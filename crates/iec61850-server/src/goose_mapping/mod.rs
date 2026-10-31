//! GoCB mapping onto MMS variables.
//!
//! Exposes a `GoosePublisher` as the MMS variable path
//! `<LD>/<LN>$GO$<gcbName>$<DA>`, so a client drives GetGoCBValues and
//! SetGoCBValues through the ordinary MMS Read and Write services.
//!
//! The GoCB is the MMS structure of IEC 61850-8-1 §18.1.1.1.1 Table 83, with
//! its components in this order:
//!
//! | Component | FC | Type | Access |
//! |---|---|---|---|
//! | GoEna | GO | BOOLEAN | read and write |
//! | GoID | GO | VisibleString | read and write |
//! | DatSet | GO | VisibleString | read |
//! | ConfRev | GO | UINT32 | read |
//! | NdsCom | GO | BOOLEAN | read |
//! | DstAddress | GO | PhyComAddress structure | read |
//! | MinTime | GO | UINT32, milliseconds | read |
//! | MaxTime | GO | UINT32, milliseconds | read |
//! | FixedOffs | GO | BOOLEAN | read |
//!
//! The GoCB reference is the name of the variable, not a component. MinTime,
//! MaxTime and FixedOffs are optional in Table 83 and always present here.
//!
//! The publisher is the only source of every value: a read takes GoEna, goID,
//! datSet, confRev, ndsCom and the destination address from the publisher, and
//! MinTime and MaxTime from its first retransmission interval and its
//! steady-state interval, so what a client reads is what the publication
//! carries (IEC 61850-8-1 §18.1.2.5.2). FixedOffs is always FALSE: the
//! publisher encodes every value in its shortest form. GoID reads as the GoCB
//! reference while the publisher has no goID of its own, which is the
//! publication's goID too.
//!
//! Writing GoEna sets the publisher's enabled flag; it does not start or stop a
//! publishing thread. A caller decides from `enabled()` whether to transmit, which
//! keeps this mapping independent of how frames reach the network.
//!
//! DstAddress is exposed as a structure of four members: the six-byte destination
//! MAC address as an OctetString, then the VLAN priority, VLAN identifier, and
//! APPID as unsigned integers.
//!
//! An unknown component name is refused with ObjectNonExistent on both read and
//! write, and a write to a read-only component with ObjectAccessDenied, rather
//! than being silently ignored.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use iec61850_goose::GoosePublisher;
use iec61850_mms::mms::pdu::common::{DataAccessError, MmsData, WriteOutcome};

use crate::mapping::{ControlBlockKind, MmsTypeSpec};

// GoCB handle

/// One server-side GoCB: where it sits in the MMS name space and the publisher
/// it controls.
///
/// A caller registers the handle once through `GoCBRegistry::register`, and MMS
/// reads and writes drive it afterwards. The handle stores no GoCB value of its
/// own: every read goes to the publisher, behind its mutex, so a change the
/// application makes on the publisher is what the next read returns.
#[non_exhaustive]
pub struct GoCBHandle {
    /// Logical device, which is the MMS domain, for example `"IED1LD0"`.
    pub ld: String,
    /// Logical node, normally `"LLN0"`.
    pub ln: String,
    /// GoCB name, without the `$GO$` prefix.
    pub name: String,
    /// The publisher this control block drives and reads its values from.
    pub publisher: Arc<Mutex<GoosePublisher>>,
}

impl std::fmt::Debug for GoCBHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoCBHandle")
            .field("ld", &self.ld)
            .field("ln", &self.ln)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl GoCBHandle {
    /// Creates a GoCB handle.
    ///
    /// The publisher's gocbRef should be the reference of this control block,
    /// `<ld>/<ln>$GO$<name>`; registration warns when it is not.
    pub fn new(
        ld: impl Into<String>,
        ln: impl Into<String>,
        name: impl Into<String>,
        publisher: Arc<Mutex<GoosePublisher>>,
    ) -> Self {
        Self {
            ld: ld.into(),
            ln: ln.into(),
            name: name.into(),
            publisher,
        }
    }

    /// Returns the GoCBRef, `<LD>/<LN>$GO$<name>`.
    pub fn go_cb_ref(&self) -> String {
        format!("{}/{}$GO${}", self.ld, self.ln, self.name)
    }

    /// Returns GoEna as the publisher holds it; `false` when the publisher's
    /// mutex is poisoned.
    pub fn enabled(&self) -> bool {
        self.publisher.lock().map(|p| p.enabled()).unwrap_or(false)
    }

    /// Returns the MMS item base, `<LN>$GO$<name>`, which the dispatcher matches a
    /// `$GO$` path against.
    pub fn mms_item_base(&self) -> String {
        format!("{}$GO${}", self.ln, self.name)
    }

    /// Qualifies a data set reference with this control block's domain, so it
    /// reads `<LD>/<LN>$<dsName>` (IEC 61850-8-1 §8.1.3.2.2).
    ///
    /// A reference that already names a domain is kept; one in the form
    /// `<LN>$<dsName>` gains the domain, and a bare data set name gains the
    /// domain and this control block's logical node.
    pub fn qualify_data_set_ref(&self, data_set_ref: &str) -> String {
        if data_set_ref.contains('/') {
            data_set_ref.to_string()
        } else if data_set_ref.contains('$') {
            format!("{}/{}", self.ld, data_set_ref)
        } else {
            format!("{}/{}${}", self.ld, self.ln, data_set_ref)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GoCBRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// Registry of every GoCB the server exposes.
///
/// `IedServer` holds an `Arc<GoCBRegistry>` and the dispatcher shares that `Arc`.
/// Entries are keyed by `(domain, item_base)`, for example
/// `("IED1LD0", "LLN0$GO$gcb01")`.
#[derive(Debug, Default)]
pub struct GoCBRegistry {
    inner: std::sync::RwLock<HashMap<(String, String), Arc<GoCBHandle>>>,
}

impl GoCBRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a GoCB. An entry with the same key is replaced, and the call then
    /// returns `false`.
    ///
    /// A publisher datSet that names no domain is qualified with the control
    /// block's domain first, so the publication and a read carry the same
    /// complete reference.
    pub fn register(&self, handle: Arc<GoCBHandle>) -> bool {
        match handle.publisher.lock() {
            Ok(mut p) => {
                if p.gocb_ref() != handle.go_cb_ref() {
                    tracing::warn!(
                        gocb = handle.go_cb_ref(),
                        publisher_gocb_ref = p.gocb_ref(),
                        "the publisher's gocbRef is not the reference of the control block it is registered under"
                    );
                }
                let qualified = handle.qualify_data_set_ref(p.data_set_ref());
                if qualified != p.data_set_ref() {
                    tracing::info!(
                        gocb = handle.go_cb_ref(),
                        dat_set = %qualified,
                        "qualified the publisher's datSet with the control block's domain"
                    );
                    if p.set_data_set_ref(qualified).is_err() {
                        tracing::warn!(
                            gocb = handle.go_cb_ref(),
                            "the publisher refused the qualified datSet"
                        );
                    }
                }
            }
            Err(_) => tracing::warn!(
                gocb = handle.go_cb_ref(),
                "gocb publisher mutex poisoned, its datSet is registered as it is"
            ),
        }
        let key = (handle.ld.clone(), handle.mms_item_base());
        let Ok(mut g) = self.inner.write() else {
            tracing::warn!("gocb registry lock poisoned, control block not registered");
            return false;
        };
        g.insert(key, handle).is_none()
    }

    /// Looks up a GoCB by name, without the `$GO$` prefix.
    pub fn find(&self, domain: &str, ln: &str, name: &str) -> Option<Arc<GoCBHandle>> {
        let key = (domain.to_string(), format!("{ln}$GO${name}"));
        self.inner.read().ok()?.get(&key).cloned()
    }

    /// Looks up a GoCB by its MMS item base, `<LN>$GO$<name>`.
    pub fn find_by_item_base(&self, domain: &str, item_base: &str) -> Option<Arc<GoCBHandle>> {
        let key = (domain.to_string(), item_base.to_string());
        self.inner.read().ok()?.get(&key).cloned()
    }

    /// Lists the MMS item bases, `<LN>$GO$<name>`, of every GoCB in a domain.
    pub fn item_bases_in_domain(&self, domain: &str) -> Vec<String> {
        let Ok(g) = self.inner.read() else {
            tracing::warn!(
                domain,
                "gocb registry lock poisoned, no control block is listed"
            );
            return vec![];
        };
        let mut out: Vec<String> = g
            .keys()
            .filter(|(d, _)| d == domain)
            .map(|(_, item_base)| item_base.clone())
            .collect();
        out.sort();
        out
    }

    /// Returns whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.read().map(|g| g.is_empty()).unwrap_or(true)
    }

    /// Returns the number of registered control blocks.
    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }
}

/// The nine components of the GoCB MMS structure, in the order of
/// IEC 61850-8-1 §18.1.1.1.1 Table 83.
pub const GOCB_DA_NAMES: &[&str] = &[
    "GoEna",
    "GoID",
    "DatSet",
    "ConfRev",
    "NdsCom",
    "DstAddress",
    "MinTime",
    "MaxTime",
    "FixedOffs",
];

// ─────────────────────────────────────────────────────────────────────────────
// Read service helper
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes a whole GoCB as an `MmsData::Structure` of nine components, in the
/// order of `GOCB_DA_NAMES`, from one consistent view of the publisher.
///
/// This answers a client read of `<LN>$GO$<name>` with no component suffix.
///
/// # Errors
///
/// `HardwareFault` when the publisher's mutex is poisoned.
pub fn encode_gocb_structure(handle: &GoCBHandle) -> Result<MmsData, DataAccessError> {
    let publisher = lock_publisher(handle)?;
    let items = GOCB_DA_NAMES
        .iter()
        .filter_map(|name| encode_component(&publisher, name))
        .collect();
    Ok(MmsData::Structure(items))
}

/// Encodes one GoCB component, or a member below one.
///
/// `da_name` is a component name such as `GoEna`, or a `$`-separated path into
/// a structured component such as `DstAddress$APPID`; members are found by the
/// names the GoCB's type description gives them.
///
/// # Errors
///
/// `ObjectNonExistent` for a path that names no component or member of
/// Table 83, and `HardwareFault` when the publisher's mutex is poisoned.
pub fn encode_gocb_da(handle: &GoCBHandle, da_name: &str) -> Result<MmsData, DataAccessError> {
    let mut segments = da_name.split('$');
    let component = segments.next().unwrap_or_default();
    let value = {
        let publisher = lock_publisher(handle)?;
        encode_component(&publisher, component)
    };
    let (Some(mut value), Some(mut spec)) = (value, component_type_spec(component)) else {
        tracing::warn!(da_name, "read of an unknown GoCB component");
        return Err(DataAccessError::ObjectNonExistent);
    };
    for member in segments {
        match select_member(value, &spec, member) {
            Some((v, s)) => {
                value = v;
                spec = s;
            }
            None => {
                tracing::warn!(da_name, member, "read of an unknown GoCB component member");
                return Err(DataAccessError::ObjectNonExistent);
            }
        }
    }
    Ok(value)
}

/// The type description of one GoCB component.
fn component_type_spec(component: &str) -> Option<MmsTypeSpec> {
    let MmsTypeSpec::Structure(members) = ControlBlockKind::Goose.type_spec() else {
        return None;
    };
    members
        .into_iter()
        .find(|m| m.name == component)
        .map(|m| m.type_spec)
}

/// Selects the member called `name` of a structured value, by the position its
/// type description gives it.
fn select_member(value: MmsData, spec: &MmsTypeSpec, name: &str) -> Option<(MmsData, MmsTypeSpec)> {
    let (MmsData::Structure(items), MmsTypeSpec::Structure(members)) = (value, spec) else {
        return None;
    };
    let index = members.iter().position(|m| m.name == name)?;
    let item = items.into_iter().nth(index)?;
    Some((item, members[index].type_spec.clone()))
}

/// Locks the publisher, reporting a poisoned mutex as a hardware fault, the
/// access error a client expects when the server cannot reach the underlying
/// object.
fn lock_publisher(
    handle: &GoCBHandle,
) -> Result<std::sync::MutexGuard<'_, GoosePublisher>, DataAccessError> {
    handle.publisher.lock().map_err(|_| {
        tracing::warn!(gocb = handle.go_cb_ref(), "gocb publisher mutex poisoned");
        DataAccessError::HardwareFault
    })
}

/// Encodes one component from the publisher; `None` for a name that is not a
/// component.
fn encode_component(p: &GoosePublisher, da_name: &str) -> Option<MmsData> {
    let millis =
        |d: std::time::Duration| u64::from(u32::try_from(d.as_millis()).unwrap_or(u32::MAX));
    let value = match da_name {
        "GoEna" => MmsData::Boolean(p.enabled()),
        "GoID" => MmsData::VisibleString(p.go_id().unwrap_or(p.gocb_ref()).to_string()),
        "DatSet" => MmsData::VisibleString(p.data_set_ref().to_string()),
        "ConfRev" => MmsData::Unsigned(u64::from(p.conf_rev())),
        "NdsCom" => MmsData::Boolean(p.needs_commission()),
        "DstAddress" => {
            let comm = p.comm_parameters();
            let vlan = comm.vlan;
            MmsData::Structure(vec![
                // Addr: the six-byte MAC address, an OctetString on the wire.
                MmsData::OctetString(comm.dst_mac.to_vec()),
                // PRIORITY: the VLAN priority, 0 when there is no VLAN tag.
                MmsData::Unsigned(vlan.map_or(0, |v| u64::from(v.priority.value()))),
                // VID: the VLAN identifier, 0 when there is no VLAN tag.
                MmsData::Unsigned(vlan.map_or(0, |v| u64::from(v.vlan_id))),
                // APPID.
                MmsData::Unsigned(u64::from(comm.app_id)),
            ])
        }
        "MinTime" => MmsData::Unsigned(millis(p.retrans_intervals().t1)),
        "MaxTime" => MmsData::Unsigned(millis(p.retrans_intervals().tmax)),
        "FixedOffs" => MmsData::Boolean(false),
        _ => return None,
    };
    Some(value)
}

// ─────────────────────────────────────────────────────────────────────────────
// Write service helper
// ─────────────────────────────────────────────────────────────────────────────

/// Applies an MMS write to one GoCB component.
///
/// GoEna, a boolean, and GoID, a visible string, are writable; GoID only while
/// the publisher is disabled, and otherwise it is refused with
/// `TemporarilyUnavailable`. The other seven components are read-only and are
/// refused with `ObjectAccessDenied`, and so is a member below a component,
/// such as `DstAddress$APPID`. An unknown component is refused with
/// `ObjectNonExistent` and a value of the wrong type with `ObjectValueInvalid`.
pub fn apply_gocb_write(handle: &GoCBHandle, da_name: &str, value: &MmsData) -> WriteOutcome {
    if da_name.contains('$') {
        return match encode_gocb_da(handle, da_name) {
            Ok(_) => {
                tracing::warn!(
                    da_name,
                    "write to a member of a read-only GoCB component refused"
                );
                WriteOutcome::Failure(DataAccessError::ObjectAccessDenied)
            }
            Err(e) => WriteOutcome::Failure(e),
        };
    }
    match da_name {
        "GoEna" => {
            let MmsData::Boolean(b) = value else {
                tracing::warn!(
                    da_name,
                    ?value,
                    "write GoEna refused: a Boolean is required"
                );
                return WriteOutcome::Failure(DataAccessError::ObjectValueInvalid);
            };
            match lock_publisher(handle) {
                Ok(p) => p.set_enabled(*b),
                Err(e) => return WriteOutcome::Failure(e),
            }
            tracing::info!(gocb = handle.go_cb_ref(), go_ena = *b, "GoCB GoEna changed");
            WriteOutcome::Success
        }
        "GoID" => {
            let MmsData::VisibleString(s) = value else {
                tracing::warn!(
                    da_name,
                    ?value,
                    "write GoID refused: a VisibleString is required"
                );
                return WriteOutcome::Failure(DataAccessError::ObjectValueInvalid);
            };
            let mut p = match lock_publisher(handle) {
                Ok(p) => p,
                Err(e) => return WriteOutcome::Failure(e),
            };
            // IEC 61850-7-2 SetGoCBValues: only GoEna may change while the
            // control block is enabled.
            if p.enabled() {
                tracing::warn!(da_name, "write GoID refused: GoEna is true");
                return WriteOutcome::Failure(DataAccessError::TemporarilyUnavailable);
            }
            p.set_go_id(Some(s.clone()));
            tracing::info!(gocb = handle.go_cb_ref(), go_id = %s, "GoCB GoID changed");
            WriteOutcome::Success
        }
        // Read-only components.
        "DatSet" | "ConfRev" | "NdsCom" | "DstAddress" | "MinTime" | "MaxTime" | "FixedOffs" => {
            tracing::warn!(da_name, "write to a read-only GoCB component refused");
            WriteOutcome::Failure(DataAccessError::ObjectAccessDenied)
        }
        _ => {
            tracing::warn!(da_name, "write to an unknown GoCB component refused");
            WriteOutcome::Failure(DataAccessError::ObjectNonExistent)
        }
    }
}

/// Splits an MMS item identifier of the form `<LN>$GO$<name>` or
/// `<LN>$GO$<name>$<da>[$<member>...]` into its item base and the optional
/// component path below it, such as `GoEna` or `DstAddress$APPID`.
///
/// Returns `None` when the identifier has fewer than three segments, an empty
/// segment, or a second segment other than `GO`.
pub fn parse_go_item_id(item_id: &str) -> Option<(&str, Option<&str>)> {
    let mut parts = item_id.splitn(4, '$');
    let (Some(ln), Some("GO"), Some(name)) = (parts.next(), parts.next(), parts.next()) else {
        return None;
    };
    if ln.is_empty() || name.is_empty() {
        return None;
    }
    match parts.next() {
        None => Some((item_id, None)),
        Some(path) if !path.is_empty() && !path.split('$').any(str::is_empty) => {
            let base_len = ln.len() + "$GO$".len() + name.len();
            Some((&item_id[..base_len], Some(path)))
        }
        Some(_) => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use iec61850_goose::frame::{VlanPriority, VlanTag};
    use iec61850_goose::publisher::{CommParameters, RetransIntervals};
    use std::time::Duration;

    fn sample_publisher(data_set_ref: &str) -> Arc<Mutex<GoosePublisher>> {
        let comm = CommParameters::new(0x1000, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01])
            .with_src_mac([0x00, 0x50, 0xc2, 0x12, 0x34, 0x56])
            .with_vlan(VlanTag {
                priority: VlanPriority::new(4).unwrap(),
                vlan_id: 100,
            });
        let p = GoosePublisher::new(comm, "IED1LD0/LLN0$GO$gcb01", None, data_set_ref, 5).unwrap();
        Arc::new(Mutex::new(p))
    }

    fn sample_handle() -> Arc<GoCBHandle> {
        Arc::new(GoCBHandle::new(
            "IED1LD0",
            "LLN0",
            "gcb01",
            sample_publisher("IED1LD0/LLN0$ds1"),
        ))
    }

    fn read(h: &GoCBHandle, da: &str) -> MmsData {
        encode_gocb_da(h, da).unwrap()
    }

    // ── Registry ───────────────────────────────────────────────────────────────

    #[test]
    fn register_and_find() {
        let reg = GoCBRegistry::new();
        let h = sample_handle();
        assert!(reg.register(h.clone()));
        let found = reg.find("IED1LD0", "LLN0", "gcb01").expect("registered");
        assert_eq!(found.go_cb_ref(), "IED1LD0/LLN0$GO$gcb01");
    }

    #[test]
    fn register_duplicate_returns_false() {
        let reg = GoCBRegistry::new();
        let h = sample_handle();
        assert!(reg.register(h.clone()));
        // Registering the same key again replaces the entry and reports false.
        assert!(!reg.register(h));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn register_qualifies_a_data_set_ref_without_a_domain() {
        for (configured, qualified) in [
            ("LLN0$ds1", "IED1LD0/LLN0$ds1"),
            ("ds1", "IED1LD0/LLN0$ds1"),
            ("OTHER/LLN0$ds1", "OTHER/LLN0$ds1"),
        ] {
            let h = Arc::new(GoCBHandle::new(
                "IED1LD0",
                "LLN0",
                "gcb01",
                sample_publisher(configured),
            ));
            GoCBRegistry::new().register(h.clone());
            assert_eq!(h.publisher.lock().unwrap().data_set_ref(), qualified);
            assert_eq!(read(&h, "DatSet"), MmsData::VisibleString(qualified.into()));
        }
    }

    #[test]
    fn find_by_item_base() {
        let reg = GoCBRegistry::new();
        let h = sample_handle();
        reg.register(h);
        let found = reg.find_by_item_base("IED1LD0", "LLN0$GO$gcb01");
        assert!(found.is_some());
        assert!(reg.find_by_item_base("IED1LD0", "LLN0$GO$nosuch").is_none());
    }

    #[test]
    fn item_bases_in_domain_lists_each_registered_block() {
        let reg = GoCBRegistry::new();
        reg.register(sample_handle());
        assert_eq!(reg.item_bases_in_domain("IED1LD0"), ["LLN0$GO$gcb01"]);
        assert!(reg.item_bases_in_domain("OTHER").is_empty());
    }

    // ── encode_gocb_da ──────────────────────────────────────────────────────────

    #[test]
    fn encode_fixed_offs_is_false() {
        let h = sample_handle();
        assert_eq!(read(&h, "FixedOffs"), MmsData::Boolean(false));
    }

    #[test]
    fn encode_go_ena_default_false() {
        let h = sample_handle();
        assert_eq!(read(&h, "GoEna"), MmsData::Boolean(false));
    }

    #[test]
    fn encode_go_id_falls_back_to_gocbref() {
        let h = sample_handle();
        assert_eq!(
            read(&h, "GoID"),
            MmsData::VisibleString("IED1LD0/LLN0$GO$gcb01".into())
        );
    }

    #[test]
    fn encode_dat_set() {
        let h = sample_handle();
        assert_eq!(
            read(&h, "DatSet"),
            MmsData::VisibleString("IED1LD0/LLN0$ds1".into())
        );
    }

    #[test]
    fn encode_conf_rev() {
        let h = sample_handle();
        assert_eq!(read(&h, "ConfRev"), MmsData::Unsigned(5));
    }

    #[test]
    fn encode_nds_com() {
        let h = sample_handle();
        assert_eq!(read(&h, "NdsCom"), MmsData::Boolean(false));
    }

    #[test]
    fn encode_dst_address_structure() {
        let h = sample_handle();
        match read(&h, "DstAddress") {
            MmsData::Structure(items) => {
                assert_eq!(items.len(), 4);
                assert_eq!(
                    items[0],
                    MmsData::OctetString(vec![0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01])
                );
                assert_eq!(items[1], MmsData::Unsigned(4)); // priority
                assert_eq!(items[2], MmsData::Unsigned(100)); // vid
                assert_eq!(items[3], MmsData::Unsigned(0x1000)); // appid
            }
            other => panic!("expected a Structure, got {:?}", other),
        }
    }

    #[test]
    fn encode_min_max_time_follow_the_retransmission_intervals() {
        let h = sample_handle();
        assert_eq!(read(&h, "MinTime"), MmsData::Unsigned(4));
        assert_eq!(read(&h, "MaxTime"), MmsData::Unsigned(1000));
    }

    #[test]
    fn encode_unknown_component_is_non_existent() {
        let h = sample_handle();
        for da in ["NoSuchDA", "GoCBRef"] {
            assert_eq!(
                encode_gocb_da(&h, da),
                Err(DataAccessError::ObjectNonExistent)
            );
        }
    }

    /// A change the application makes on the publisher is what the next read
    /// returns; the handle keeps no second copy.
    #[test]
    fn reads_follow_changes_made_on_the_publisher() {
        let h = sample_handle();
        {
            let mut p = h.publisher.lock().unwrap();
            p.set_conf_rev(9);
            p.set_needs_commission(true);
            p.set_go_id(Some("app-goid".into()));
            p.set_enabled(true);
            let mut intervals = RetransIntervals::default();
            intervals.t1 = Duration::from_millis(2);
            intervals.tmax = Duration::from_millis(5000);
            p.set_retrans_intervals(intervals);
        }
        assert_eq!(read(&h, "ConfRev"), MmsData::Unsigned(9));
        assert_eq!(read(&h, "NdsCom"), MmsData::Boolean(true));
        assert_eq!(read(&h, "GoID"), MmsData::VisibleString("app-goid".into()));
        assert_eq!(read(&h, "GoEna"), MmsData::Boolean(true));
        assert!(h.enabled());
        assert_eq!(read(&h, "MinTime"), MmsData::Unsigned(2));
        assert_eq!(read(&h, "MaxTime"), MmsData::Unsigned(5000));
    }

    #[test]
    fn encode_full_structure() {
        let h = sample_handle();
        match encode_gocb_structure(&h).unwrap() {
            MmsData::Structure(items) => {
                assert_eq!(items.len(), 9);
                assert_eq!(items[0], MmsData::Boolean(false), "GoEna leads");
                assert_eq!(items[8], MmsData::Boolean(false), "FixedOffs ends");
                for (item, name) in items.iter().zip(GOCB_DA_NAMES) {
                    assert_eq!(item, &read(&h, name), "component {name}");
                }
            }
            other => panic!("expected a Structure, got {:?}", other),
        }
    }

    // ── apply_gocb_write ────────────────────────────────────────────────────────

    #[test]
    fn write_go_ena_true_succeeds_and_publisher_enabled() {
        let h = sample_handle();
        assert!(!h.enabled());
        let r = apply_gocb_write(&h, "GoEna", &MmsData::Boolean(true));
        assert_eq!(r, WriteOutcome::Success);
        assert!(h.enabled());
        assert!(h.publisher.lock().unwrap().enabled());
    }

    #[test]
    fn write_go_ena_false_after_true_disables() {
        let h = sample_handle();
        apply_gocb_write(&h, "GoEna", &MmsData::Boolean(true));
        assert!(h.enabled());
        apply_gocb_write(&h, "GoEna", &MmsData::Boolean(false));
        assert!(!h.enabled());
        assert!(!h.publisher.lock().unwrap().enabled());
    }

    #[test]
    fn write_go_ena_wrong_type_rejects() {
        let h = sample_handle();
        let r = apply_gocb_write(&h, "GoEna", &MmsData::Unsigned(1));
        assert_eq!(
            r,
            WriteOutcome::Failure(DataAccessError::ObjectValueInvalid)
        );
    }

    #[test]
    fn write_go_id_succeeds() {
        let h = sample_handle();
        let r = apply_gocb_write(&h, "GoID", &MmsData::VisibleString("MyGoID".into()));
        assert_eq!(r, WriteOutcome::Success);
        assert_eq!(read(&h, "GoID"), MmsData::VisibleString("MyGoID".into()));
        assert_eq!(h.publisher.lock().unwrap().go_id(), Some("MyGoID"));
    }

    #[test]
    fn write_go_id_wrong_type_rejects() {
        let h = sample_handle();
        let r = apply_gocb_write(&h, "GoID", &MmsData::Boolean(true));
        assert_eq!(
            r,
            WriteOutcome::Failure(DataAccessError::ObjectValueInvalid)
        );
    }

    #[test]
    fn write_readonly_da_rejects() {
        let h = sample_handle();
        for da in [
            "DatSet",
            "ConfRev",
            "NdsCom",
            "DstAddress",
            "MinTime",
            "MaxTime",
            "FixedOffs",
        ] {
            let r = apply_gocb_write(&h, da, &MmsData::Boolean(true));
            assert_eq!(
                r,
                WriteOutcome::Failure(DataAccessError::ObjectAccessDenied),
                "{da} must be refused as read-only"
            );
        }
    }

    #[test]
    fn write_unknown_da_returns_nonexistent() {
        let h = sample_handle();
        for da in ["NoSuchDA", "GoCBRef"] {
            let r = apply_gocb_write(&h, da, &MmsData::Boolean(true));
            assert_eq!(r, WriteOutcome::Failure(DataAccessError::ObjectNonExistent));
        }
    }

    // ── parse_go_item_id ────────────────────────────────────────────────────────

    #[test]
    fn parse_go_item_id_three_parts_no_da() {
        let r = parse_go_item_id("LLN0$GO$gcb01");
        assert_eq!(r, Some(("LLN0$GO$gcb01", None)));
    }

    #[test]
    fn parse_go_item_id_four_parts_with_da() {
        let r = parse_go_item_id("LLN0$GO$gcb01$GoEna");
        assert_eq!(r, Some(("LLN0$GO$gcb01", Some("GoEna"))));
    }

    #[test]
    fn parse_go_item_id_wrong_fc_rejects() {
        assert!(parse_go_item_id("LLN0$RP$gcb01").is_none());
        assert!(parse_go_item_id("LLN0$ST$Mod").is_none());
    }

    #[test]
    fn parse_go_item_id_member_path() {
        let r = parse_go_item_id("LLN0$GO$gcb01$DstAddress$APPID");
        assert_eq!(r, Some(("LLN0$GO$gcb01", Some("DstAddress$APPID"))));
    }

    #[test]
    fn parse_go_item_id_malformed_rejects() {
        assert!(parse_go_item_id("LLN0$GO").is_none());
        assert!(parse_go_item_id("LLN0$GO$").is_none());
        assert!(parse_go_item_id("LLN0$GO$gcb01$").is_none());
        assert!(parse_go_item_id("LLN0$GO$gcb01$DstAddress$$APPID").is_none());
    }

    #[test]
    fn encode_member_of_dst_address() {
        let h = sample_handle();
        assert_eq!(read(&h, "DstAddress$APPID"), MmsData::Unsigned(0x1000));
        assert_eq!(
            read(&h, "DstAddress$Addr"),
            MmsData::OctetString(vec![0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01])
        );
        for path in ["DstAddress$Nope", "GoEna$x", "DstAddress$APPID$x"] {
            assert_eq!(
                encode_gocb_da(&h, path),
                Err(DataAccessError::ObjectNonExistent),
                "{path}"
            );
        }
    }

    #[test]
    fn write_member_of_dst_address_is_denied() {
        let h = sample_handle();
        assert_eq!(
            apply_gocb_write(&h, "DstAddress$APPID", &MmsData::Unsigned(1)),
            WriteOutcome::Failure(DataAccessError::ObjectAccessDenied)
        );
        assert_eq!(
            apply_gocb_write(&h, "DstAddress$Nope", &MmsData::Unsigned(1)),
            WriteOutcome::Failure(DataAccessError::ObjectNonExistent)
        );
    }
}
