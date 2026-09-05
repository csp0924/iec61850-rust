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
//!
//! ## Response size
//!
//! The member list grows with the data set, so the encoded response is
//! measured against the maximum PDU size negotiated for the association. A
//! response that does not fit is replaced by a ConfirmedError of errorClass
//! resource other, as IEC 61850-8-1 requires, rather than sent to a client
//! that cannot accept it.

use bytes::BytesMut;

use iec61850_mms::mms::pdu::{
    get_named_variable_list_attrs::{
        encode_confirmed_get_named_variable_list_attrs_response,
        GetNamedVariableListAttributesRequest, GetNamedVariableListAttributesResponse,
    },
    service_error::{
        subcode::{access, resource},
        ErrorClass,
    },
    ListOfVariableEntry, ObjectName,
};
use iec61850_mms::mms::server::dispatcher::ConfirmedResponse;

use crate::reporting::DatasetRegistry;
use crate::service::define_named_variable_list::DynamicDatasetKeys;
use crate::service::pdu_budget::response_exceeds_pdu_budget;

/// Handles a GetNamedVariableListAttributes request (confirmed service tag 0xac).
///
/// `negotiated_max_pdu_size` bounds the encoded response; `None` before
/// negotiation completes leaves it unbounded.
pub(crate) fn handle_get_named_variable_list_attributes(
    invoke_id: u32,
    body: &[u8],
    registry: &DatasetRegistry,
    dynamic_keys: &DynamicDatasetKeys,
    negotiated_max_pdu_size: Option<u32>,
) -> ConfirmedResponse {
    let req = match GetNamedVariableListAttributesRequest::decode(body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                invoke_id,
                error = %e,
                "get-named-variable-list-attributes request failed to decode, answering confirmed-error"
            );
            return crate::service::make_confirmed_error_pub(
                invoke_id,
                ErrorClass::Access(access::OTHER),
            );
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
            return crate::service::make_confirmed_error_pub(
                invoke_id,
                ErrorClass::Access(access::OBJECT_ACCESS_UNSUPPORTED),
            );
        }
    };

    let dataset = match registry.read() {
        Ok(guard) => guard.get(&(domain.clone(), list_name.clone())).cloned(),
        Err(_) => {
            tracing::warn!(
                invoke_id,
                "dataset registry lock is poisoned, answering resource error"
            );
            return crate::service::make_confirmed_error_pub(
                invoke_id,
                ErrorClass::Resource(resource::OTHER),
            );
        }
    };

    let Some(dataset) = dataset else {
        tracing::warn!(
            invoke_id,
            domain,
            list_name,
            "get-named-variable-list-attributes names an unknown data set, answering object-non-existent"
        );
        return crate::service::make_confirmed_error_pub(
            invoke_id,
            ErrorClass::Access(access::OBJECT_NON_EXISTENT),
        );
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
                return crate::service::make_confirmed_error_pub(
                    invoke_id,
                    ErrorClass::Access(access::OTHER),
                );
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
    if response_exceeds_pdu_budget(buf.len(), negotiated_max_pdu_size) {
        tracing::warn!(
            invoke_id,
            domain,
            list_name,
            members = resp.list_of_variable.len(),
            encoded_len = buf.len(),
            negotiated_max_pdu_size,
            "get-named-variable-list-attributes: the response exceeds the negotiated maximum PDU size, answering a resource error"
        );
        return crate::service::make_confirmed_error_pub(
            invoke_id,
            ErrorClass::Resource(resource::OTHER),
        );
    }
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

    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};

    use iec61850_mms::mms::pdu::service_error::decode_confirmed_error_pdu;
    use iec61850_model::MmsValue;

    use crate::reporting::{Dataset, DatasetEntry};
    use crate::service::define_named_variable_list::new_dynamic_dataset_keys;
    use crate::service::read::PDU_OVERHEAD_RESERVE;

    const DOMAIN: &str = "IED1LD0";
    const LIST_NAME: &str = "GGIO1$ds1";
    const INVOKE_ID: u32 = 7;

    /// Builds a registry holding one configured data set of `members` boolean
    /// entries and returns the member item ids in registration order.
    fn registry_with_members(members: usize) -> (DatasetRegistry, Vec<String>) {
        let mut dataset = Dataset::new(LIST_NAME);
        let mut item_ids = Vec::with_capacity(members);
        for n in 0..members {
            let item_id = format!("GGIO1$ST$Ind{n}$stVal");
            dataset.push(DatasetEntry::new(
                format!("{DOMAIN}/{item_id}"),
                Arc::new(RwLock::new(MmsValue::Boolean(true))),
            ));
            item_ids.push(item_id);
        }
        let mut map = HashMap::new();
        map.insert(
            (DOMAIN.to_string(), LIST_NAME.to_string()),
            Arc::new(dataset),
        );
        (Arc::new(RwLock::new(map)), item_ids)
    }

    /// Encodes the response those members imply and returns its length, so the
    /// expected size never comes from the handler under test.
    fn encoded_response_len(item_ids: &[String]) -> usize {
        let resp = GetNamedVariableListAttributesResponse {
            mms_deletable: false,
            list_of_variable: item_ids
                .iter()
                .map(|item_id| {
                    ListOfVariableEntry::name(ObjectName::DomainSpecific {
                        domain_id: DOMAIN.to_string(),
                        item_id: item_id.clone(),
                    })
                })
                .collect(),
        };
        let mut buf = BytesMut::new();
        encode_confirmed_get_named_variable_list_attrs_response(INVOKE_ID, &resp, &mut buf);
        buf.len()
    }

    /// Encodes the request service body the handler consumes.
    fn request_body() -> BytesMut {
        let mut buf = BytesMut::new();
        GetNamedVariableListAttributesRequest::domain(DOMAIN, LIST_NAME).encode(&mut buf);
        buf
    }

    fn handle(
        registry: &DatasetRegistry,
        negotiated_max_pdu_size: Option<u32>,
    ) -> ConfirmedResponse {
        handle_get_named_variable_list_attributes(
            INVOKE_ID,
            &request_body(),
            registry,
            &new_dynamic_dataset_keys(),
            negotiated_max_pdu_size,
        )
    }

    /// Asserts the answer is a ConfirmedError of errorClass resource other.
    fn assert_resource_other(resp: ConfirmedResponse) {
        match resp {
            ConfirmedResponse::Error(bytes) => {
                let (invoke_id, service_error) =
                    decode_confirmed_error_pdu(&bytes).expect("confirmed error must decode");
                assert_eq!(invoke_id, INVOKE_ID);
                assert_eq!(
                    service_error.error_class,
                    ErrorClass::Resource(resource::OTHER),
                    "an oversized response must answer resource other"
                );
            }
            other => panic!("expected a confirmed error, got {other:?}"),
        }
    }

    #[test]
    fn a_response_over_the_negotiated_size_answers_resource_other() {
        let (registry, _) = registry_with_members(40);
        assert_resource_other(handle(&registry, Some(200)));
    }

    #[test]
    fn a_response_under_the_negotiated_size_is_sent() {
        let (registry, item_ids) = registry_with_members(3);
        let generous = (encoded_response_len(&item_ids) + PDU_OVERHEAD_RESERVE + 64) as u32;
        match handle(&registry, Some(generous)) {
            ConfirmedResponse::Response(bytes) => assert_eq!(
                bytes[0], 0xa1,
                "a response must start with the confirmed-response tag"
            ),
            other => panic!("expected a response, got {other:?}"),
        }
    }

    #[test]
    fn a_response_exactly_at_the_negotiated_size_is_sent() {
        let (registry, item_ids) = registry_with_members(6);
        let exact = (encoded_response_len(&item_ids) + PDU_OVERHEAD_RESERVE) as u32;
        match handle(&registry, Some(exact)) {
            ConfirmedResponse::Response(bytes) => assert_eq!(bytes[0], 0xa1),
            other => panic!("a response of exactly the budget must be sent, got {other:?}"),
        }
    }

    #[test]
    fn a_response_one_byte_over_the_negotiated_size_is_refused() {
        let (registry, item_ids) = registry_with_members(6);
        let one_short = (encoded_response_len(&item_ids) + PDU_OVERHEAD_RESERVE - 1) as u32;
        assert_resource_other(handle(&registry, Some(one_short)));
    }

    #[test]
    fn an_unnegotiated_association_sends_the_response() {
        let (registry, _) = registry_with_members(40);
        match handle(&registry, None) {
            ConfirmedResponse::Response(bytes) => assert_eq!(bytes[0], 0xa1),
            other => panic!("without a negotiated maximum the response is sent, got {other:?}"),
        }
    }

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
