//! Data set directory: the ACSI GetDataSetDirectory service of
//! IEC 61850-7-2, carried by the MMS GetNamedVariableListAttributes request.
//!
//! A data set reference is IEC notation `<LD>/<LN>.<dsName>`, the same form
//! [`get_data_set_values`](crate::IedConnection::get_data_set_values) takes.
//! The response names each member as the MMS variable `<domain>` and
//! `<LN>$<FC>$<DO>[$<SDA>...]`, which this module maps back to the IEC
//! reference `<LD>/<LN>.<DO>[.<SDA>]*` and its functional constraint, the form
//! [`create_data_set`](crate::IedConnection::create_data_set) accepts.
//!
//! ## Array elements
//!
//! A member carrying an MMS `AlternateAccess` selector is rendered with the
//! index in IEC notation, `GGIO1.Ind1(2).stVal`, so that feeding the reference
//! back through `parse_iec_object_path` yields the same index and component.

use crate::connection::IedConnection;
use crate::dataset_admin::DataSetMember;
use crate::error::ClientError;
use crate::object_io::parse_data_set_ref;
use crate::prelude::{format, Vec};
use iec61850_hal::time::Timer;
use iec61850_hal::transport::AsyncTransport;
use iec61850_mms::mms::pdu::{AlternateAccessSelector, ListOfVariableEntry, ObjectName};
use iec61850_model::FC;

/// The members of a data set, together with whether the server allows it to be
/// deleted.
#[derive(Debug, Clone)]
pub struct DataSetDirectory {
    /// `mmsDeletable`: true only for a data set created at runtime through
    /// CreateDataSet. A configured data set is not deletable.
    pub deletable: bool,
    /// Members in the order the server holds them, which is the order
    /// `get_data_set_values` returns its access results in.
    pub members: Vec<DataSetMember>,
}

/// Smallest number of `$`-separated segments in an MMS member path: logical
/// node, functional constraint and data object.
const MIN_MEMBER_SEGMENTS: usize = 3;

/// Position of the logical node name within an MMS member path.
const SEG_LOGICAL_NODE: usize = 0;

/// Position of the functional constraint token within an MMS member path.
const SEG_FC: usize = 1;

/// Position of the first data object segment within an MMS member path.
const SEG_FIRST_PATH: usize = 2;

/// Maps one response member back to its IEC reference and functional
/// constraint.
///
/// The member name must be domain-specific and its item id must be
/// `<LN>$<FC>$<DO>[$<SDA>...]`. An `AlternateAccess` selector becomes an IEC
/// array index, with any component path appended as further `.` segments.
///
/// # Errors
///
/// `InvalidArgument` when the name is not domain-specific, when the item id has
/// fewer than three segments, when a segment is empty, or when the functional
/// constraint token is not one of the defined abbreviations.
pub(crate) fn member_from_entry(entry: &ListOfVariableEntry) -> Result<DataSetMember, ClientError> {
    let (domain, item_id) = match &entry.name {
        ObjectName::DomainSpecific { domain_id, item_id } => (domain_id, item_id),
        other => {
            return Err(ClientError::InvalidArgument(format!(
                "data set member {other:?} is not domain-specific"
            )))
        }
    };

    let segments: Vec<&str> = item_id.split('$').collect();
    if segments.len() < MIN_MEMBER_SEGMENTS {
        return Err(ClientError::InvalidArgument(format!(
            "data set member '{domain}/{item_id}' is not <LN>$<FC>$<DO>[$<SDA>...]"
        )));
    }
    if segments.iter().any(|s| s.is_empty()) {
        return Err(ClientError::InvalidArgument(format!(
            "data set member '{domain}/{item_id}' has an empty path segment"
        )));
    }

    let fc = FC::parse(segments[SEG_FC]).map_err(|e| {
        ClientError::InvalidArgument(format!(
            "data set member '{domain}/{item_id}' carries an unknown functional constraint: {e}"
        ))
    })?;
    if matches!(fc, FC::None | FC::All) {
        return Err(ClientError::InvalidArgument(format!(
            "data set member '{domain}/{item_id}' carries the functional constraint `{fc}`, which names no single constraint"
        )));
    }

    let mut reference = format!(
        "{domain}/{ln}.{path}",
        ln = segments[SEG_LOGICAL_NODE],
        path = segments[SEG_FIRST_PATH..].join(".")
    );

    match entry.alt_access.as_ref().map(|aa| &aa.selector) {
        None => {}
        Some(AlternateAccessSelector::Index(index)) => {
            reference.push_str(&format!("({index})"));
        }
        Some(AlternateAccessSelector::IndexComponent { index, component }) => {
            reference.push_str(&format!("({index})"));
            for seg in component.split('$') {
                if seg.is_empty() {
                    return Err(ClientError::InvalidArgument(format!(
                        "data set member '{domain}/{item_id}' has an empty component segment"
                    )));
                }
                reference.push('.');
                reference.push_str(seg);
            }
        }
    }

    Ok(DataSetMember { reference, fc })
}

impl<T: AsyncTransport, Tm: Timer> IedConnection<T, Tm> {
    /// Reads the member list of a data set (ACSI GetDataSetDirectory).
    ///
    /// `dataset_ref` is IEC notation `<LD>/<LN>.<dsName>`, as
    /// [`get_data_set_values`](Self::get_data_set_values) takes. Members come
    /// back in the order the server holds them, each with the functional
    /// constraint of its data attribute, so the result can be fed straight into
    /// [`create_data_set`](Self::create_data_set) to clone the set.
    ///
    /// Enumerating the data set names of a logical node is a different service:
    /// GetLogicalNodeDirectory, mapped onto MMS GetNameList.
    ///
    /// # Errors
    ///
    /// `NotConnected` if the association is not established, `InvalidArgument`
    /// for a malformed data set reference or a member reference the server
    /// returns in a form that cannot be mapped back, and `Mms` if the server
    /// refuses the request, which is what an unknown data set produces.
    pub async fn get_data_set_directory(
        &self,
        dataset_ref: &str,
    ) -> Result<DataSetDirectory, ClientError> {
        if !self.is_connected() {
            return Err(ClientError::NotConnected);
        }
        let ds = parse_data_set_ref(dataset_ref)?;

        let resp = {
            let mut client = self.mms_client.lock().await;
            client
                .get_named_variable_list_attributes(&ds.domain, &ds.list_name)
                .await
                .map_err(|e| ClientError::Mms(format!("{e}")))?
        };

        let mut members = Vec::with_capacity(resp.list_of_variable.len());
        for entry in &resp.list_of_variable {
            members.push(member_from_entry(entry)?);
        }
        Ok(DataSetDirectory {
            deletable: resp.mms_deletable,
            members,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_io::parse_iec_object_path;
    use crate::prelude::ToString;
    use iec61850_mms::mms::pdu::AlternateAccess;

    fn domain_entry(item: &str) -> ListOfVariableEntry {
        ListOfVariableEntry::name(ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: item.to_string(),
        })
    }

    #[test]
    fn maps_leaf_member_to_iec_reference() {
        let m = member_from_entry(&domain_entry("GGIO1$ST$Ind1$stVal")).expect("map");
        assert_eq!(m.reference, "IED1LD0/GGIO1.Ind1.stVal");
        assert_eq!(m.fc, FC::St);
    }

    #[test]
    fn maps_data_object_member_without_a_data_attribute() {
        let m = member_from_entry(&domain_entry("GGIO1$MX$AnIn1")).expect("map");
        assert_eq!(m.reference, "IED1LD0/GGIO1.AnIn1");
        assert_eq!(m.fc, FC::Mx);
    }

    #[test]
    fn maps_multi_level_sub_attribute_member() {
        let m = member_from_entry(&domain_entry("MMXU1$MX$TotW$mag$f")).expect("map");
        assert_eq!(m.reference, "IED1LD0/MMXU1.TotW.mag.f");
        assert_eq!(m.fc, FC::Mx);
    }

    #[test]
    fn round_trips_through_parse_iec_object_path() {
        let m = member_from_entry(&domain_entry("MMXU1$MX$TotW$mag$f")).expect("map");
        let path = parse_iec_object_path(&m.reference, m.fc).expect("parse back");
        assert_eq!(path.domain, "IED1LD0");
        assert_eq!(path.item_id, "MMXU1$MX$TotW$mag$f");
        assert!(path.array.is_none());
    }

    #[test]
    fn maps_index_alternate_access_to_iec_index() {
        let entry = ListOfVariableEntry::with_alt_access(
            ObjectName::DomainSpecific {
                domain_id: "IED1LD0".to_string(),
                item_id: "GGIO1$ST$Ind1".to_string(),
            },
            AlternateAccess::index(2),
        );
        let m = member_from_entry(&entry).expect("map");
        assert_eq!(m.reference, "IED1LD0/GGIO1.Ind1(2)");

        let path = parse_iec_object_path(&m.reference, m.fc).expect("parse back");
        assert_eq!(path.item_id, "GGIO1$ST$Ind1");
        let arr = path.array.expect("array element");
        assert_eq!(arr.index, 2);
        assert!(arr.component.is_none());
    }

    #[test]
    fn maps_index_component_alternate_access_to_iec_index_and_path() {
        let entry = ListOfVariableEntry::with_alt_access(
            ObjectName::DomainSpecific {
                domain_id: "IED1LD0".to_string(),
                item_id: "GGIO1$ST$Ind1".to_string(),
            },
            AlternateAccess::index_component(3, "q$stVal").expect("selector"),
        );
        let m = member_from_entry(&entry).expect("map");
        assert_eq!(m.reference, "IED1LD0/GGIO1.Ind1(3).q.stVal");

        let path = parse_iec_object_path(&m.reference, m.fc).expect("parse back");
        assert_eq!(path.item_id, "GGIO1$ST$Ind1");
        let arr = path.array.expect("array element");
        assert_eq!(arr.index, 3);
        assert_eq!(arr.component.as_deref(), Some("q$stVal"));
    }

    #[test]
    fn unknown_functional_constraint_is_an_error_not_a_panic() {
        let err = member_from_entry(&domain_entry("GGIO1$XX$Ind1$stVal")).unwrap_err();
        assert!(matches!(err, ClientError::InvalidArgument(_)));
    }

    #[test]
    fn wildcard_functional_constraint_is_rejected() {
        for token in ["ALL", "NONE"] {
            let err =
                member_from_entry(&domain_entry(&format!("GGIO1${token}$Ind1$stVal"))).unwrap_err();
            assert!(matches!(err, ClientError::InvalidArgument(_)), "{token}");
        }
    }

    #[test]
    fn too_few_segments_is_an_error() {
        let err = member_from_entry(&domain_entry("GGIO1$ST")).unwrap_err();
        assert!(matches!(err, ClientError::InvalidArgument(_)));
    }

    #[test]
    fn empty_segment_is_an_error() {
        let err = member_from_entry(&domain_entry("GGIO1$ST$")).unwrap_err();
        assert!(matches!(err, ClientError::InvalidArgument(_)));
    }

    #[test]
    fn non_domain_specific_member_is_an_error() {
        let entry = ListOfVariableEntry::name(ObjectName::VmdSpecific("plain".to_string()));
        let err = member_from_entry(&entry).unwrap_err();
        assert!(matches!(err, ClientError::InvalidArgument(_)));
    }
}
