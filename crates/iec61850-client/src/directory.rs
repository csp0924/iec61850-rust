//! ACSI directory services: browsing the server, its logical devices,
//! logical nodes and data objects, per IEC 61850-7-2.
//!
//! The first directory call fetches the whole object tree with GetNameList
//! over the domains and their named variables, and caches it on the
//! connection; later calls answer from that cache. [`DeviceModel`] is that
//! cache and `ensure_device_model` its lazy entry point.
//!
//! Data sets and logs are the exception and always go to the server, because
//! neither appears in the cached variable list.
//!
//! Of the ACSI classes, this implementation resolves `DataObject`, `DataSet`,
//! `Brcb`, `Urcb`, `Lcb`, `Log`, `Sgcb` and `GoCb`. `GsCb`, `Msvcb` and
//! `Usvcb` return [`ClientError::InvalidArgument`] rather than an empty list,
//! so that an unsupported class is not read as an absent one. The same
//! applies to the MMS file directory service behind
//! `get_server_directory(get_file_names = true)`, which is not implemented.

use iec61850_hal::time::Timer;
use iec61850_hal::transport::AsyncTransport;
use iec61850_mms::mms::pdu::ObjectClass;
use iec61850_mms::TypeSpecification;
use iec61850_model::FC;

use crate::connection::IedConnection;
use crate::error::ClientError;
use crate::object_io::parse_iec_object_path;
use crate::prelude::{format, Arc, String, ToString, Vec};

// Types.

/// The MMS named variables of one logical device, as cached.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IcLogicalDevice {
    /// Name of the logical device, which is also its MMS domain id.
    pub name: String,
    /// Every MMS named variable name in this logical device, in the alphabetical
    /// order the server reports.
    pub variables: Vec<String>,
}

/// Cached object tree of a whole server.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct DeviceModel {
    /// Every logical device the server reported, with its variables.
    pub logical_devices: Vec<IcLogicalDevice>,
}

impl DeviceModel {
    /// Returns the logical device with this name, if the server has one.
    pub fn find_ld(&self, name: &str) -> Option<&IcLogicalDevice> {
        self.logical_devices.iter().find(|ld| ld.name == name)
    }
}

/// ACSI class selector for [`IedConnection::get_logical_node_directory`], as
/// defined in IEC 61850-7-2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AcsiClass {
    /// Data objects, resolved from the cached variable tree.
    DataObject,
    /// Data sets, read from the server as a named variable list.
    DataSet,
    /// Buffered report control blocks (FC = BR).
    Brcb,
    /// Unbuffered report control blocks (FC = RP).
    Urcb,
    /// Log control blocks (FC = LG).
    Lcb,
    /// Logs, read from the server as domain journals.
    Log,
    /// Setting group control block, found only in LLN0 as `LLN0$SP$SGCB`.
    Sgcb,
    /// GOOSE control blocks (FC = GO).
    GoCb,
    /// GSE control blocks; not supported, returns `InvalidArgument`.
    GsCb,
    /// Multicast sampled value control blocks; not supported, returns
    /// `InvalidArgument`.
    Msvcb,
    /// Unicast sampled value control blocks; not supported, returns
    /// `InvalidArgument`.
    Usvcb,
}

// Name list retrieval, following the GetNameList continuation.

/// Default for the most names one GetNameList walk collects across its pages;
/// see [`IedConnection::with_max_name_list_names`].
pub const DEFAULT_MAX_NAME_LIST_NAMES: usize = 1_000_000;

/// Calls GetNameList repeatedly until the server reports no more names.
///
/// `domain` selects the scope: `Some(name)` is domain-specific, `None` is
/// VMD-specific. The names come in alphabetical order, so a page that
/// reports more names must end on a name ordered after the continuation it
/// was asked for. The walk stops at the connection's name limit, so a server
/// that keeps reporting more cannot hold the client in the loop.
///
/// # Errors
///
/// `NotConnected` if the association is not established, `Mms` if a page that
/// reports more names does not end past the name the previous page ended on,
/// `NameListLimit` if the walk exceeds the connection's name limit, and the
/// error the MMS layer reports.
async fn fetch_all_names<T: AsyncTransport, Tm: Timer>(
    conn: &IedConnection<T, Tm>,
    object_class: ObjectClass,
    domain: Option<&str>,
) -> Result<Vec<String>, ClientError> {
    if !conn.is_connected() {
        return Err(ClientError::NotConnected);
    }
    let limit = conn.max_name_list_names;
    let mut all: Vec<String> = Vec::new();
    let mut continue_after: Option<String> = None;
    loop {
        let mut client = conn.mms_client.lock().await;
        let (page, more) = client
            .get_name_list(object_class, domain, continue_after.as_deref())
            .await?;
        drop(client);
        if all.len().saturating_add(page.len()) > limit {
            tracing::warn!(
                ?object_class,
                domain,
                limit,
                "getnamelist walk exceeds the name limit, abandoning it"
            );
            return Err(ClientError::NameListLimit { limit });
        }
        if let Some(last) = page.last().cloned() {
            all.extend(page);
            if more {
                if continue_after
                    .as_deref()
                    .is_some_and(|previous| last.as_str() <= previous)
                {
                    tracing::warn!(
                        ?object_class,
                        domain,
                        continue_after = last.as_str(),
                        "getnamelist page does not advance past its continuation, abandoning the walk"
                    );
                    return Err(ClientError::Mms(format!(
                        "getnamelist does not advance past '{last}'"
                    )));
                }
                continue_after = Some(last);
                continue;
            }
        }
        break;
    }
    Ok(all)
}

// Lazy loading of the device model.

impl<T: AsyncTransport, Tm: Timer> IedConnection<T, Tm> {
    /// Returns the cached device model, reading the whole object tree from the
    /// server first if nothing is cached.
    ///
    /// The model read is returned directly rather than looked up again, so a
    /// concurrent `invalidate_device_model_cache` or `disconnect` cannot leave
    /// the caller without one. Internal to the directory API;
    /// [`Self::get_device_model_from_server`] is the public way to force a
    /// refresh.
    pub(crate) async fn ensure_device_model(&self) -> Result<Arc<DeviceModel>, ClientError> {
        if let Some(model) = self.device_model.lock().await.clone() {
            return Ok(model);
        }
        // The logical device names are the VMD-scope domains.
        let ld_names = fetch_all_names(self, ObjectClass::Domain, None).await?;
        let mut lds: Vec<IcLogicalDevice> = Vec::with_capacity(ld_names.len());
        for ld_name in ld_names {
            let vars =
                fetch_all_names(self, ObjectClass::NamedVariable, Some(ld_name.as_str())).await?;
            lds.push(IcLogicalDevice {
                name: ld_name,
                variables: vars,
            });
        }
        // A concurrent caller may have filled the cache meanwhile; both results
        // describe the same server, so the later write simply wins.
        let model = Arc::new(DeviceModel {
            logical_devices: lds,
        });
        *self.device_model.lock().await = Some(Arc::clone(&model));
        Ok(model)
    }

    /// Returns the variable list of one logical device from the device model,
    /// reading the model from the server first if nothing is cached.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` if the server has no logical device of that name, and
    /// the errors of reading the model.
    async fn ld_variables(&self, ld_name: &str) -> Result<Vec<String>, ClientError> {
        let model = self.ensure_device_model().await?;
        let ld = model.find_ld(ld_name).ok_or_else(|| {
            ClientError::InvalidArgument(format!("logical device `{ld_name}` not found on server"))
        })?;
        Ok(ld.variables.clone())
    }

    /// Returns a clone of the cached device model, or `None` if nothing has
    /// been cached yet.
    pub async fn cached_device_model(&self) -> Option<DeviceModel> {
        self.device_model.lock().await.as_deref().cloned()
    }

    /// Drops the cached device model, so the next directory call re-reads it.
    pub async fn invalidate_device_model_cache(&self) {
        *self.device_model.lock().await = None;
    }
}

// (1) get_server_directory

impl<T: AsyncTransport, Tm: Timer> IedConnection<T, Tm> {
    /// Returns the names of every logical device on the server.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` for `get_file_names = true`: the MMS file directory
    /// service is not implemented.
    pub async fn get_server_directory(
        &self,
        get_file_names: bool,
    ) -> Result<Vec<String>, ClientError> {
        if get_file_names {
            return Err(ClientError::InvalidArgument(
                "get_server_directory(get_file_names=true): file directory service is not implemented"
                    .to_string(),
            ));
        }
        let model = self.ensure_device_model().await?;
        Ok(model
            .logical_devices
            .iter()
            .map(|ld| ld.name.clone())
            .collect())
    }
}

// (2) get_logical_device_directory

impl<T: AsyncTransport, Tm: Timer> IedConnection<T, Tm> {
    /// Returns the names of the logical nodes in one logical device.
    ///
    /// A logical node appears in the variable list as a top-level entry without
    /// a `$`, alongside its own `LN$FC$...` variables.
    pub async fn get_logical_device_directory(
        &self,
        ld_name: &str,
    ) -> Result<Vec<String>, ClientError> {
        let vars = self.ld_variables(ld_name).await?;
        Ok(vars.into_iter().filter(|v| !v.contains('$')).collect())
    }
}

// (3) get_logical_node_directory, dispatched by ACSI class

/// Splits a logical node reference `LD/LN` into its two parts.
///
/// # Errors
///
/// `InvalidArgument` if the reference is longer than 129 bytes, has no `/`, or
/// leaves either part empty.
fn split_ln_reference(ln_ref: &str) -> Result<(&str, &str), ClientError> {
    if ln_ref.len() > 129 {
        return Err(ClientError::InvalidArgument(format!(
            "logical node reference length {} exceeds 129",
            ln_ref.len()
        )));
    }
    let (ld, ln) = ln_ref.split_once('/').ok_or_else(|| {
        ClientError::InvalidArgument(format!(
            "logical node reference `{ln_ref}` is missing the `/` of LD/LN"
        ))
    })?;
    if ld.is_empty() || ln.is_empty() {
        return Err(ClientError::InvalidArgument(format!(
            "logical node reference `{ln_ref}` has an empty LD or LN part"
        )));
    }
    Ok((ld, ln))
}

/// Appends an item unless it is already present, preserving insertion order.
///
/// A linear scan is enough: a logical node rarely holds more than a few dozen
/// data objects.
fn add_unique(set: &mut Vec<String>, item: String) {
    if !set.iter().any(|s| s == &item) {
        set.push(item);
    }
}

/// Collects the third segment of every variable named `<ln>$<fc>$<name>...`.
/// Maps one MMS variable name to the data object it names, or `None` when the
/// variable is not a data object of `ln`.
///
/// A variable is `<ln>$<FC>$<DO>` with exactly one segment after the functional
/// constraint; a deeper path names a data attribute. The control block
/// constraints RP, BR, GO and LG are excluded, because those names are control
/// blocks, which the directory reports under their own ACSI class.
fn data_object_of_variable<'a>(var: &'a str, ln: &str) -> Option<&'a str> {
    let (var_ln, rest) = var.split_once('$')?;
    if var_ln != ln {
        return None;
    }
    // `get` rather than a slice throughout: a server may answer a name whose
    // third byte falls inside a multi-byte character, which slicing panics on.
    let fc = rest.get(..2)?;
    if matches!(fc, "RP" | "BR" | "GO" | "LG") {
        return None;
    }
    let after_fc = rest.get(2..)?.strip_prefix('$')?;
    if after_fc.is_empty() || after_fc.contains('$') {
        return None;
    }
    Some(after_fc)
}

/// Appends the name of every control block of `ln` under functional constraint
/// `fc`, taking only the token after the constraint and skipping duplicates.
fn add_variables_with_fc(fc: &str, ln: &str, vars: &[String], out: &mut Vec<String>) {
    for var in vars {
        let Some((var_ln, rest)) = var.split_once('$') else {
            continue;
        };
        if var_ln != ln {
            continue;
        }
        // `rest` is `<FC>$<name>...`; check the functional constraint first.
        // `get` rather than a slice: a server may answer a name whose third
        // byte falls inside a multi-byte character, which slicing would panic on.
        if rest.get(..2) != Some(fc) {
            continue;
        }
        // What follows the functional constraint must start with `$`.
        let after_fc = match rest.get(2..) {
            Some(s) if s.starts_with('$') => &s[1..],
            _ => continue,
        };
        // Take only the token after the functional constraint.
        let name = match after_fc.split_once('$') {
            Some((head, _)) => head,
            None => after_fc,
        };
        if !name.is_empty() {
            add_unique(out, name.to_string());
        }
    }
}

impl<T: AsyncTransport, Tm: Timer> IedConnection<T, Tm> {
    /// Returns the names of one class of ACSI object inside a logical node
    /// (IEC 61850-7-2 GetLogicalNodeDirectory).
    ///
    /// # Errors
    ///
    /// `InvalidArgument` for a malformed reference, or for `GsCb`, `Msvcb` and
    /// `Usvcb`, which are not supported.
    pub async fn get_logical_node_directory(
        &self,
        ln_ref: &str,
        class: AcsiClass,
    ) -> Result<Vec<String>, ClientError> {
        let (ld_name, ln_name) = split_ln_reference(ln_ref)?;

        // Data sets and logs are read from the server; every other class is
        // answered from the cache.
        let fc = match class {
            AcsiClass::DataSet => {
                return names_in_ln(self, ObjectClass::NamedVariableList, ld_name, ln_name).await;
            }
            AcsiClass::Log => {
                return names_in_ln(self, ObjectClass::Journal, ld_name, ln_name).await;
            }
            AcsiClass::GsCb | AcsiClass::Msvcb | AcsiClass::Usvcb => {
                return Err(ClientError::InvalidArgument(format!(
                    "AcsiClass::{class:?} is not supported"
                )));
            }
            AcsiClass::DataObject => {
                let vars = self.ld_variables(ld_name).await?;
                let mut out = Vec::new();
                for var in &vars {
                    if let Some(name) = data_object_of_variable(var, ln_name) {
                        add_unique(&mut out, name.to_string());
                    }
                }
                return Ok(out);
            }
            AcsiClass::Sgcb => {
                // A logical device has at most one SGCB, and it lives in LLN0.
                let vars = self.ld_variables(ld_name).await?;
                let mut out = Vec::new();
                if ln_name == "LLN0" && vars.iter().any(|v| v == "LLN0$SP$SGCB") {
                    out.push("SGCB".to_string());
                }
                return Ok(out);
            }
            AcsiClass::Brcb => "BR",
            AcsiClass::Urcb => "RP",
            AcsiClass::GoCb => "GO",
            AcsiClass::Lcb => "LG",
        };
        let vars = self.ld_variables(ld_name).await?;
        let mut out = Vec::new();
        add_variables_with_fc(fc, ln_name, &vars, &mut out);
        Ok(out)
    }
}

/// Returns the objects of `object_class` named `<ln>$<name>` in one logical
/// device, read from the server, as their `<name>` parts.
async fn names_in_ln<T: AsyncTransport, Tm: Timer>(
    conn: &IedConnection<T, Tm>,
    object_class: ObjectClass,
    ld_name: &str,
    ln_name: &str,
) -> Result<Vec<String>, ClientError> {
    let names = fetch_all_names(conn, object_class, Some(ld_name)).await?;
    let mut out = Vec::new();
    for name in names {
        if let Some((var_ln, rest)) = name.split_once('$') {
            if var_ln == ln_name {
                out.push(rest.to_string());
            }
        }
    }
    Ok(out)
}

// Every variable of a logical node, unfiltered.

impl<T: AsyncTransport, Tm: Timer> IedConnection<T, Tm> {
    /// Returns the `<FC>$<...>` tail of every MMS variable belonging to a
    /// logical node.
    ///
    /// Neither deduplicated nor filtered by functional constraint; the order is
    /// that of the cached variable list, which the server reports alphabetically.
    pub async fn get_logical_node_variables(
        &self,
        ln_ref: &str,
    ) -> Result<Vec<String>, ClientError> {
        let (ld_name, ln_name) = split_ln_reference(ln_ref)?;
        let vars = self.ld_variables(ld_name).await?;
        let mut out = Vec::new();
        for var in vars {
            if let Some((var_ln, rest)) = var.split_once('$') {
                if var_ln == ln_name {
                    out.push(rest.to_string());
                }
            }
        }
        Ok(out)
    }
}

// (5) get_data_directory / get_data_directory_fc
// (6) get_data_directory_by_fc

/// Splits a data reference `<LD>/<LN>.<DO>[.<sub>]*` into the logical device,
/// the logical node, and the data path with `.` mapped to `$` as IEC 61850-8-1
/// requires.
///
/// # Errors
///
/// `InvalidArgument` if the reference is longer than 129 bytes, lacks a `/` or
/// a `.`, or leaves any part empty.
fn split_data_reference(data_ref: &str) -> Result<(&str, &str, String), ClientError> {
    if data_ref.len() > 129 {
        return Err(ClientError::InvalidArgument(format!(
            "data reference length {} exceeds 129",
            data_ref.len()
        )));
    }
    let (ld, rest) = data_ref.split_once('/').ok_or_else(|| {
        ClientError::InvalidArgument(format!("data reference `{data_ref}` is missing the `/`"))
    })?;
    let (ln, dot_part) = rest.split_once('.').ok_or_else(|| {
        ClientError::InvalidArgument(format!(
            "data reference `{data_ref}` is missing the `.` between LN and DO"
        ))
    })?;
    if ld.is_empty() || ln.is_empty() || dot_part.is_empty() {
        return Err(ClientError::InvalidArgument(format!(
            "data reference `{data_ref}` has an empty LD, LN or DO part"
        )));
    }
    let data_part = dot_part.replace('.', "$");
    Ok((ld, ln, data_part))
}

/// Collects the child names matching `<ln_name>$<fc>$<data_part>$<child>` in a
/// cached variable list.
///
/// `fc_filter` restricts the functional constraint when it is `Some`.
/// `with_fc_suffix` appends `[<FC>]` to each child name.
fn collect_data_children(
    vars: &[String],
    ln_name: &str,
    data_part: &str,
    fc_filter: Option<&str>,
    with_fc_suffix: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    let data_part_len = data_part.len();
    for var in vars {
        // A variable is `<ln>$<FC>$<remainder>`.
        let Some((var_ln, rest_after_ln)) = var.split_once('$') else {
            continue;
        };
        if var_ln != ln_name {
            continue;
        }
        let Some(fc) = rest_after_ln.get(..2) else {
            continue;
        };
        if let Some(want) = fc_filter {
            if fc != want {
                continue;
            }
        }
        // Skip the functional constraint; a `$` must follow it.
        let after_fc = match rest_after_ln.get(2..) {
            Some(s) if s.starts_with('$') => &s[1..],
            _ => continue,
        };
        // The remainder must start with `<data_part>$` and end in exactly one
        // further token.
        if after_fc.len() <= data_part_len {
            continue;
        }
        if !after_fc.starts_with(data_part) {
            continue;
        }
        if after_fc.as_bytes()[data_part_len] != b'$' {
            continue;
        }
        let child = &after_fc[data_part_len + 1..];
        if child.is_empty() || child.contains('$') {
            continue;
        }
        let entry = if with_fc_suffix {
            format!("{child}[{fc}]")
        } else {
            child.to_string()
        };
        add_unique(&mut out, entry);
    }
    out
}

impl<T: AsyncTransport, Tm: Timer> IedConnection<T, Tm> {
    /// Returns the immediate children of a data object or data attribute,
    /// without a functional constraint suffix.
    ///
    /// Children of the same name under different functional constraints collapse
    /// into one entry; use [`Self::get_data_directory_fc`] to keep them apart.
    pub async fn get_data_directory(&self, data_ref: &str) -> Result<Vec<String>, ClientError> {
        let (ld, ln, data_part) = split_data_reference(data_ref)?;
        let vars = self.ld_variables(ld).await?;
        Ok(collect_data_children(&vars, ln, &data_part, None, false))
    }

    /// Returns the immediate children of a data object, each suffixed with its
    /// functional constraint, as in `stVal[ST]`.
    pub async fn get_data_directory_fc(&self, data_ref: &str) -> Result<Vec<String>, ClientError> {
        let (ld, ln, data_part) = split_data_reference(data_ref)?;
        let vars = self.ld_variables(ld).await?;
        Ok(collect_data_children(&vars, ln, &data_part, None, true))
    }

    /// Returns the immediate children of a data object under one functional
    /// constraint, without a suffix.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` for `FC::None` and `FC::All`: the constraint has to name
    /// exactly one.
    pub async fn get_data_directory_by_fc(
        &self,
        data_ref: &str,
        fc: FC,
    ) -> Result<Vec<String>, ClientError> {
        if matches!(fc, FC::None | FC::All) {
            return Err(ClientError::InvalidArgument(format!(
                "FC `{fc}` cannot be used with get_data_directory_by_fc"
            )));
        }
        let fc_str = fc.as_str();
        let (ld, ln, data_part) = split_data_reference(data_ref)?;
        let vars = self.ld_variables(ld).await?;
        Ok(collect_data_children(
            &vars,
            ln,
            &data_part,
            Some(fc_str),
            false,
        ))
    }
}

// Type specification lookup and forced device model refresh.

impl<T: AsyncTransport, Tm: Timer> IedConnection<T, Tm> {
    /// Reads the MMS type specification of an object (MMS
    /// GetVariableAccessAttributes).
    ///
    /// `reference` is accepted in IEC notation (`<LD>/<LN>.<DO>[.<DA>]*`) or in
    /// MMS notation; it is resolved by [`parse_iec_object_path`].
    ///
    /// # Errors
    ///
    /// `NotConnected` if the association is not established, and
    /// `InvalidArgument` for a reference carrying an array index `(idx)`: MMS
    /// reports the type of a whole named variable, so an indexed reference has
    /// no distinct answer. Pass the container reference, such as
    /// `LD/GGIO1.Ind1`, and read the element type from the `Array` variant.
    pub async fn get_variable_specification(
        &self,
        reference: &str,
        fc: FC,
    ) -> Result<TypeSpecification, ClientError> {
        if !self.is_connected() {
            return Err(ClientError::NotConnected);
        }
        let path = parse_iec_object_path(reference, fc)?;
        if path.array.is_some() {
            return Err(ClientError::InvalidArgument(format!(
                "get_variable_specification: reference `{reference}` carries an array index `(idx)`; \
                 pass the container reference and read Array.element_type instead"
            )));
        }
        let mut client = self.mms_client.lock().await;
        let ts = client
            .get_variable_access_attributes(&path.domain, &path.item_id)
            .await?;
        Ok(ts)
    }

    /// Re-reads the whole device model from the server, replacing the cache, and
    /// returns a clone of it.
    ///
    /// Unlike the lazy path, this always goes to the wire.
    ///
    /// # Errors
    ///
    /// `NotConnected` if the association is not established.
    pub async fn get_device_model_from_server(&self) -> Result<DeviceModel, ClientError> {
        if !self.is_connected() {
            return Err(ClientError::NotConnected);
        }
        // Clearing the cache forces the lazy path to read from the server.
        *self.device_model.lock().await = None;
        let model = self.ensure_device_model().await?;
        Ok(DeviceModel::clone(&model))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_ln_ok() {
        let (ld, ln) = split_ln_reference("simpleIOGenericIO/GGIO1").unwrap();
        assert_eq!(ld, "simpleIOGenericIO");
        assert_eq!(ln, "GGIO1");
    }

    #[test]
    fn split_ln_no_slash() {
        assert!(matches!(
            split_ln_reference("noSlashHere"),
            Err(ClientError::InvalidArgument(_))
        ));
    }

    #[test]
    fn split_ln_empty_part() {
        assert!(matches!(
            split_ln_reference("LD/"),
            Err(ClientError::InvalidArgument(_))
        ));
        assert!(matches!(
            split_ln_reference("/LN"),
            Err(ClientError::InvalidArgument(_))
        ));
    }

    #[test]
    fn split_ln_too_long() {
        let s = format!("{}/{}", "x".repeat(60), "y".repeat(80));
        assert!(matches!(
            split_ln_reference(&s),
            Err(ClientError::InvalidArgument(_))
        ));
    }

    #[test]
    fn split_data_ref_ok() {
        let (ld, ln, dp) = split_data_reference("LD1/GGIO1.AnIn1.mag").unwrap();
        assert_eq!(ld, "LD1");
        assert_eq!(ln, "GGIO1");
        assert_eq!(dp, "AnIn1$mag");
    }

    #[test]
    fn split_data_ref_no_dot() {
        assert!(matches!(
            split_data_reference("LD/GGIO1"),
            Err(ClientError::InvalidArgument(_))
        ));
    }

    #[test]
    fn add_variables_with_fc_filters_ln_and_fc() {
        let vars = vec![
            "LLN0$BR$brcb01".to_string(),
            "LLN0$BR$brcb02".to_string(),
            "LLN0$RP$urcb01".to_string(), // different functional constraint
            "GGIO1$BR$brcb03".to_string(), // different logical node
            "LLN0$BR$brcb01".to_string(), // duplicate
        ];
        let mut out = Vec::new();
        add_variables_with_fc("BR", "LLN0", &vars, &mut out);
        assert_eq!(out, vec!["brcb01", "brcb02"]);
    }

    /// A server may answer a name whose byte at the functional-constraint
    /// position falls inside a multi-byte character. Every name-splitting helper
    /// must skip such a name rather than panic on a slice that is not on a
    /// character boundary.
    #[test]
    fn name_splitting_helpers_skip_a_non_ascii_name_without_panicking() {
        let malformed = "LLN0$\u{65e5}\u{672c}$stVal".to_string();

        assert_eq!(data_object_of_variable(&malformed, "LLN0"), None);
        assert_eq!(
            data_object_of_variable("LLN0$ST$Ind1", "LLN0"),
            Some("Ind1")
        );
        // A log control block is not a data object.
        assert_eq!(data_object_of_variable("LLN0$LG$evlog", "LLN0"), None);

        let vars = vec![malformed.clone(), "LLN0$BR$brcb01".to_string()];
        let mut out = Vec::new();
        add_variables_with_fc("BR", "LLN0", &vars, &mut out);
        assert_eq!(out, vec!["brcb01"]);

        assert!(collect_data_children(&vars, "LLN0", "Ind1", None, false).is_empty());
    }

    #[test]
    fn collect_data_children_basic_no_fc_filter() {
        let vars = vec![
            "GGIO1$ST$Ind1$stVal".to_string(),
            "GGIO1$ST$Ind1$q".to_string(),
            "GGIO1$ST$Ind1$t".to_string(),
            "GGIO1$ST$Ind2$stVal".to_string(), // different data object
            "GGIO1$MX$AnIn1$mag$f".to_string(), // different data object
        ];
        let out = collect_data_children(&vars, "GGIO1", "Ind1", None, false);
        assert_eq!(out, vec!["stVal", "q", "t"]);
    }

    #[test]
    fn collect_data_children_with_fc_suffix() {
        let vars = vec![
            "GGIO1$ST$Ind1$stVal".to_string(),
            "GGIO1$ST$Ind1$q".to_string(),
            "GGIO1$ST$Ind1$t".to_string(),
        ];
        let out = collect_data_children(&vars, "GGIO1", "Ind1", None, true);
        assert_eq!(out, vec!["stVal[ST]", "q[ST]", "t[ST]"]);
    }

    #[test]
    fn collect_data_children_fc_filter() {
        let vars = vec![
            "LLN0$DC$NamPlt$vendor".to_string(),
            "LLN0$DC$NamPlt$swRev".to_string(),
            "LLN0$ST$NamPlt$ldNs".to_string(), // functional constraint ST is filtered out
        ];
        let out = collect_data_children(&vars, "LLN0", "NamPlt", Some("DC"), false);
        assert_eq!(out, vec!["vendor", "swRev"]);
    }

    #[test]
    fn collect_data_children_skips_too_deep() {
        let vars = vec![
            "GGIO1$MX$AnIn1$mag$f".to_string(), // two levels below `AnIn1`
            "GGIO1$MX$AnIn1$q".to_string(),
            "GGIO1$MX$AnIn1$t".to_string(),
        ];
        let out = collect_data_children(&vars, "GGIO1", "AnIn1", None, false);
        // Only the immediate children are collected: `mag` has a child of its own
        // and its entry therefore still contains a `$`, so it is filtered out.
        assert_eq!(out, vec!["q", "t"]);
    }

    #[test]
    fn collect_data_children_deeper_data_part() {
        // `LD/GGIO1.AnIn1.mag` resolves to the children of `mag`.
        let vars = vec![
            "GGIO1$MX$AnIn1$mag$f".to_string(),
            "GGIO1$MX$AnIn1$mag$i".to_string(),
            "GGIO1$MX$AnIn1$q".to_string(), // not under `mag`
        ];
        let out = collect_data_children(&vars, "GGIO1", "AnIn1$mag", None, false);
        assert_eq!(out, vec!["f", "i"]);
    }

    /// `add_unique` deduplicates and keeps the first occurrence.
    #[test]
    fn add_unique_preserves_first_occurrence() {
        let mut v = Vec::new();
        add_unique(&mut v, "a".to_string());
        add_unique(&mut v, "b".to_string());
        add_unique(&mut v, "a".to_string());
        add_unique(&mut v, "c".to_string());
        assert_eq!(v, vec!["a", "b", "c"]);
    }

    /// `DeviceModel::find_ld` returns `None` for an unknown name rather than
    /// panicking.
    #[test]
    fn device_model_find_ld_missing() {
        let dm = DeviceModel {
            logical_devices: vec![IcLogicalDevice {
                name: "X".to_string(),
                variables: vec![],
            }],
        };
        assert!(dm.find_ld("Y").is_none());
        assert!(dm.find_ld("X").is_some());
    }
}
