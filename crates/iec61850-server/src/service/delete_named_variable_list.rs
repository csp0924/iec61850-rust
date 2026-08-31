//! Server handler for the MMS DeleteNamedVariableList service, the mapping of
//! the IEC 61850-7-2 DeleteDataSet request.
//!
//! Only `scopeOfDelete = Specific` is served; every other scope is answered
//! with `Access(ObjectAccessUnsupported)`. For each name in the request: a name
//! absent from the dynamic-key set denotes a configured data set, whose
//! `mmsDeletable` is false, and is not deleted; a name in the set but missing
//! from the registry counts towards neither counter; a name in both is removed
//! from registry and key set and counts towards both. An empty name list is
//! answered with 0 matched and 0 deleted.

use bytes::BytesMut;

use iec61850_mms::mms::pdu::{
    delete_named_variable_list::{
        encode_confirmed_delete_named_variable_list_response, DeleteNamedVariableListRequest,
        DeleteNamedVariableListResponse, ScopeOfDelete,
    },
    service_error::ErrorClass,
    ObjectName,
};
use iec61850_mms::mms::server::dispatcher::ConfirmedResponse;

use crate::reporting::{DatasetRegistry, DynamicDatasetOps};
use crate::service::define_named_variable_list::DynamicDatasetKeys;

pub(crate) fn handle_delete_named_variable_list(
    invoke_id: u32,
    body: &[u8],
    registry: &DatasetRegistry,
    dynamic_keys: &DynamicDatasetKeys,
) -> ConfirmedResponse {
    let req = match DeleteNamedVariableListRequest::decode(body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                invoke_id,
                error = %e,
                "delete-named-variable-list request failed to decode, answering confirmed-error"
            );
            return crate::service::make_confirmed_error_pub(invoke_id, ErrorClass::Access(0));
        }
    };

    if req.scope_of_delete != ScopeOfDelete::Specific {
        tracing::warn!(
            invoke_id,
            scope = ?req.scope_of_delete,
            "delete-named-variable-list serves only scope-of-delete specific, answering object-access-unsupported"
        );
        return crate::service::make_confirmed_error_pub(invoke_id, ErrorClass::Access(9));
    }

    let mut number_matched: u32 = 0;
    let mut number_deleted: u32 = 0;

    for name in &req.list_of_variable_list_name {
        let (domain, list_name) = match name {
            ObjectName::DomainSpecific { domain_id, item_id } => {
                (domain_id.clone(), item_id.clone())
            }
            other => {
                tracing::warn!(
                    invoke_id,
                    ?other,
                    "delete-named-variable-list serves only domain-specific entries, skipping"
                );
                continue;
            }
        };

        // numberMatched counts every name present in the registry, whether the
        // data set was configured or created at runtime.
        let exists_in_registry = DynamicDatasetOps::contains(registry, &domain, &list_name);
        if exists_in_registry {
            number_matched += 1;
        }

        let is_dynamic = match dynamic_keys.lock() {
            Ok(g) => g.contains(&(domain.clone(), list_name.clone())),
            Err(_) => {
                tracing::warn!(
                    invoke_id,
                    "dynamic dataset key set is poisoned, skipping the entry"
                );
                false
            }
        };

        if !is_dynamic {
            tracing::warn!(
                invoke_id,
                domain,
                list_name,
                "delete-named-variable-list refuses to delete a configured data set"
            );
            // A refused entry does not fail the service: it is left out of
            // numberDeleted and the response stays positive, so the client
            // decides from the counter (IEC 61850-7-2 §17).
            continue;
        }

        match DynamicDatasetOps::remove(registry, &domain, &list_name) {
            Ok(true) => {
                number_deleted += 1;
                if let Ok(mut g) = dynamic_keys.lock() {
                    g.remove(&(domain.clone(), list_name.clone()));
                }
            }
            Ok(false) => {
                tracing::warn!(
                    invoke_id,
                    domain,
                    list_name,
                    "dynamic dataset key set and registry disagree about a data set"
                );
                if let Ok(mut g) = dynamic_keys.lock() {
                    g.remove(&(domain.clone(), list_name.clone()));
                }
            }
            Err(_) => {
                tracing::warn!(
                    invoke_id,
                    "dataset registry removal failed, skipping the entry"
                );
            }
        }
    }

    let resp = DeleteNamedVariableListResponse {
        number_matched,
        number_deleted,
    };
    let mut buf = BytesMut::new();
    encode_confirmed_delete_named_variable_list_response(invoke_id, &resp, &mut buf);
    ConfirmedResponse::Response(buf.freeze())
}
