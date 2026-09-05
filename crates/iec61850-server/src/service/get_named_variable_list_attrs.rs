//! Server handler for the MMS GetNamedVariableListAttributes service, the
//! mapping of the IEC 61850-7-2 GetDataSetDirectory request.
//!
//! The request names one data set; the response carries its members in
//! registration order, each as the MMS variable `<domain>` and
//! `<LN>$<FC>$<DO>[$<SDA>...]` the entry holds, together with `mmsDeletable`.
//!
//! ## mmsDeletable
//!
//! True exactly when the data set is in the dynamic-key set, that is when it
//! was created by DefineNamedVariableList. A configured data set is not
//! deletable, which is the same source DeleteNamedVariableList consults before
//! removing one.
//!
//! ## Scope
//!
//! Only domain-specific list names are served, matching the reporting engine
//! and the DefineNamedVariableList handler; a vmd-specific or aa-specific name
//! decodes but is answered with `ObjectAccessUnsupported`. A name absent from
//! the registry is answered with `ObjectNonExistent`.
//!
//! ## Member references
//!
//! A `DatasetEntry` holds `"<domain>/<LN>$<FC>$<DO>[$<SDA>...]"`. An entry
//! without that separator violates the registry contract and is answered with
//! an access error rather than emitted as a reference the client cannot
//! resolve.

use bytes::BytesMut;

use iec61850_mms::mms::pdu::{
    get_named_variable_list_attrs::{
        encode_confirmed_get_named_variable_list_attrs_response,
        GetNamedVariableListAttributesRequest, GetNamedVariableListAttributesResponse,
    },
    service_error::ErrorClass,
    ListOfVariableEntry, ObjectName,
};
use iec61850_mms::mms::server::dispatcher::ConfirmedResponse;

use crate::reporting::DatasetRegistry;
use crate::service::define_named_variable_list::DynamicDatasetKeys;

/// Handles a GetNamedVariableListAttributes request (confirmed service tag 0xac).
pub(crate) fn handle_get_named_variable_list_attributes(
    invoke_id: u32,
    body: &[u8],
    registry: &DatasetRegistry,
    dynamic_keys: &DynamicDatasetKeys,
) -> ConfirmedResponse {
    let req = match GetNamedVariableListAttributesRequest::decode(body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                invoke_id,
                error = %e,
                "get-named-variable-list-attributes request failed to decode, answering confirmed-error"
            );
            return crate::service::make_confirmed_error_pub(invoke_id, ErrorClass::Access(0));
        }
    };

    let (domain, list_name) = match &req.object_name {
        ObjectName::DomainSpecific { domain_id, item_id } => (domain_id.clone(), item_id.clone()),
        other => {
            tracing::warn!(
                invoke_id,
                ?other,
                "get-named-variable-list-attributes accepts only a domain-specific list name, answering object-access-unsupported"
            );
            return crate::service::make_confirmed_error_pub(invoke_id, ErrorClass::Access(9));
        }
    };

    let dataset = match registry.read() {
        Ok(guard) => guard.get(&(domain.clone(), list_name.clone())).cloned(),
        Err(_) => {
            tracing::warn!(
                invoke_id,
                "dataset registry lock is poisoned, answering resource error"
            );
            return crate::service::make_confirmed_error_pub(invoke_id, ErrorClass::Resource(0));
        }
    };

    let Some(dataset) = dataset else {
        tracing::warn!(
            invoke_id,
            domain,
            list_name,
            "get-named-variable-list-attributes names an unknown data set, answering object-non-existent"
        );
        return crate::service::make_confirmed_error_pub(invoke_id, ErrorClass::Access(10));
    };

    let mut list_of_variable = Vec::with_capacity(dataset.entries.len());
    for entry in &dataset.entries {
        match split_attr_ref(&entry.attr_ref) {
            Some((member_domain, item_id)) => {
                list_of_variable.push(ListOfVariableEntry::name(ObjectName::DomainSpecific {
                    domain_id: member_domain,
                    item_id,
                }));
            }
            None => {
                tracing::warn!(
                    invoke_id,
                    attr_ref = %entry.attr_ref,
                    "data set member reference carries no domain separator, answering access error"
                );
                return crate::service::make_confirmed_error_pub(invoke_id, ErrorClass::Access(0));
            }
        }
    }

    let mms_deletable = match dynamic_keys.lock() {
        Ok(keys) => keys.contains(&(domain.clone(), list_name.clone())),
        Err(_) => {
            tracing::warn!(
                invoke_id,
                "dynamic dataset key set is poisoned, reporting the data set as not deletable"
            );
            false
        }
    };

    let resp = GetNamedVariableListAttributesResponse {
        mms_deletable,
        list_of_variable,
    };
    let mut buf = BytesMut::new();
    encode_confirmed_get_named_variable_list_attrs_response(invoke_id, &resp, &mut buf);
    ConfirmedResponse::Response(buf.freeze())
}

/// Splits `"<domain>/<item>"` into its two parts.
///
/// Returns `None` when the separator is missing or either part is empty.
fn split_attr_ref(attr_ref: &str) -> Option<(String, String)> {
    let (domain, item) = attr_ref.split_once('/')?;
    if domain.is_empty() || item.is_empty() {
        return None;
    }
    Some((domain.to_string(), item.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attr_ref_splits_on_the_first_separator() {
        let (d, i) = split_attr_ref("IED1LD0/GGIO1$ST$Ind1$stVal").expect("split");
        assert_eq!(d, "IED1LD0");
        assert_eq!(i, "GGIO1$ST$Ind1$stVal");
    }

    #[test]
    fn attr_ref_without_separator_is_rejected() {
        assert!(split_attr_ref("GGIO1$ST$Ind1$stVal").is_none());
    }

    #[test]
    fn attr_ref_with_an_empty_part_is_rejected() {
        assert!(split_attr_ref("/GGIO1$ST$Ind1$stVal").is_none());
        assert!(split_attr_ref("IED1LD0/").is_none());
    }
}
