//! Dynamic data set administration: the ACSI CreateDataSet and DeleteDataSet
//! services of IEC 61850-7-2, carried by the MMS DefineNamedVariableList and
//! DeleteNamedVariableList requests.
//!
//! A data set reference is IEC notation `<LD>/<LN>.<dsName>`, for example
//! `IED1LD0/LLN0.ds_dyn1`, which maps to the MMS domain `IED1LD0` and the list
//! name `LLN0$ds_dyn1`. A member reference is `<LD>/<LN>.<DO>[.<SDA>]*` with a
//! functional constraint, so `IED1LD0/GGIO1.Ind1.stVal` under ST maps to
//! `GGIO1$ST$Ind1$stVal`.

use crate::connection::IedConnection;
use crate::error::ClientError;
use crate::object_io::parse_iec_object_path;
use crate::prelude::{format, String, ToString, Vec};
use iec61850_hal::time::Timer;
use iec61850_hal::transport::AsyncTransport;
use iec61850_mms::mms::pdu::DefineNamedVariableEntry;
use iec61850_model::FC;

/// One member of a data set.
///
/// `reference` is accepted in IEC or MMS notation, and `fc` must match the
/// functional constraint of the data attribute on the server.
#[derive(Debug, Clone)]
pub struct DataSetMember {
    /// Object reference of the member, in IEC or MMS notation.
    pub reference: String,
    /// Functional constraint of the referenced data attribute.
    pub fc: FC,
}

impl DataSetMember {
    /// Builds a member from a reference and its functional constraint.
    pub fn new(reference: impl Into<String>, fc: FC) -> Self {
        Self {
            reference: reference.into(),
            fc,
        }
    }
}

/// Splits a data set reference `<LD>/<LN>.<dsName>` into the MMS domain and
/// list name.
///
/// # Errors
///
/// `InvalidArgument` if the reference is empty, has no `/`, has neither `.`
/// nor `$` after it, or leaves any part empty.
pub(crate) fn parse_data_set_admin_ref(reference: &str) -> Result<(String, String), ClientError> {
    let trimmed = reference.trim();
    if trimmed.is_empty() {
        return Err(ClientError::InvalidArgument(
            "data set reference is empty".to_string(),
        ));
    }
    // Both IEC ('.') and MMS ('$') notation are accepted.
    let (ld, rest) = trimmed.split_once('/').ok_or_else(|| {
        ClientError::InvalidArgument(format!(
            "data set reference '{reference}' is missing the '/' of <LD>/<LN>.<dsName>"
        ))
    })?;
    if ld.is_empty() {
        return Err(ClientError::InvalidArgument(format!(
            "data set reference '{reference}' has an empty logical device part"
        )));
    }
    // LN.<dsName> or LN$<dsName>
    let (ln, ds_name) = if let Some((a, b)) = rest.split_once('.') {
        (a, b)
    } else if let Some((a, b)) = rest.split_once('$') {
        (a, b)
    } else {
        return Err(ClientError::InvalidArgument(format!(
            "data set reference '{reference}' is missing the '.' or '$' of <LD>/<LN>.<dsName>"
        )));
    };
    if ln.is_empty() || ds_name.is_empty() {
        return Err(ClientError::InvalidArgument(format!(
            "data set reference '{reference}' has an empty logical node or data set name"
        )));
    }
    Ok((ld.to_string(), format!("{ln}${ds_name}")))
}

impl<T: AsyncTransport, Tm: Timer> IedConnection<T, Tm> {
    /// Creates a dynamic data set on the server (ACSI CreateDataSet).
    ///
    /// `reference` is IEC notation `<LD>/<LN>.<dsName>`; each member carries a
    /// reference and a functional constraint and is mapped to its MMS path.
    ///
    /// # Errors
    ///
    /// `NotConnected` if the association is not established, `InvalidArgument`
    /// for a malformed reference or a member carrying an array index, and `Mms`
    /// if the server rejects the request.
    pub async fn create_data_set(
        &self,
        reference: &str,
        members: &[DataSetMember],
    ) -> Result<(), ClientError> {
        if !self.is_connected() {
            return Err(ClientError::NotConnected);
        }
        let (domain, list_name) = parse_data_set_admin_ref(reference)?;

        // Each member reference becomes an MMS domain and item path.
        let mut entries = Vec::with_capacity(members.len());
        for m in members {
            let path = parse_iec_object_path(&m.reference, m.fc)?;
            if path.array.is_some() {
                return Err(ClientError::InvalidArgument(format!(
                    "data set member '{}' carries an array index, which a dynamic data set does not support",
                    m.reference
                )));
            }
            entries.push(DefineNamedVariableEntry::domain(path.domain, path.item_id));
        }

        let mut guard = self.mms_client.lock().await;
        guard
            .define_named_variable_list(&domain, &list_name, entries)
            .await
            .map_err(|e| ClientError::Mms(format!("{e}")))
    }

    /// Deletes a dynamic data set from the server (ACSI DeleteDataSet).
    ///
    /// Returns `true` when the server deleted the data set, and `false` when it
    /// deleted nothing, whether because the set does not exist, is static, or
    /// the request was refused.
    ///
    /// # Errors
    ///
    /// `NotConnected` if the association is not established, `InvalidArgument`
    /// for a malformed reference, and `Mms` if the server rejects the request.
    pub async fn delete_data_set(&self, reference: &str) -> Result<bool, ClientError> {
        if !self.is_connected() {
            return Err(ClientError::NotConnected);
        }
        let (domain, list_name) = parse_data_set_admin_ref(reference)?;

        let mut guard = self.mms_client.lock().await;
        let (_matched, deleted) = guard
            .delete_named_variable_list(&domain, &list_name)
            .await
            .map_err(|e| ClientError::Mms(format!("{e}")))?;
        Ok(deleted >= 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_iec_notation() {
        let (d, l) = parse_data_set_admin_ref("IED1LD0/LLN0.ds_x").unwrap();
        assert_eq!(d, "IED1LD0");
        assert_eq!(l, "LLN0$ds_x");
    }

    #[test]
    fn parse_mms_notation() {
        let (d, l) = parse_data_set_admin_ref("IED1LD0/GGIO1$ds_y").unwrap();
        assert_eq!(d, "IED1LD0");
        assert_eq!(l, "GGIO1$ds_y");
    }

    #[test]
    fn parse_no_slash_rejected() {
        assert!(matches!(
            parse_data_set_admin_ref("IED1LD0_GGIO1.ds_x"),
            Err(ClientError::InvalidArgument(_))
        ));
    }

    #[test]
    fn parse_no_separator_rejected() {
        assert!(matches!(
            parse_data_set_admin_ref("IED1LD0/GGIO1ds_x"),
            Err(ClientError::InvalidArgument(_))
        ));
    }

    #[test]
    fn parse_empty_segments_rejected() {
        assert!(matches!(
            parse_data_set_admin_ref("/.ds_x"),
            Err(ClientError::InvalidArgument(_))
        ));
        assert!(matches!(
            parse_data_set_admin_ref("IED1LD0/."),
            Err(ClientError::InvalidArgument(_))
        ));
        assert!(matches!(
            parse_data_set_admin_ref(""),
            Err(ClientError::InvalidArgument(_))
        ));
    }
}
