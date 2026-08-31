//! Server handler for the MMS DefineNamedVariableList service, the mapping of
//! the IEC 61850-7-2 CreateDataSet request.
//!
//! Every entry of the request is resolved against the model to the shared
//! `MmsValue` it names; the resulting data set is stored in the dataset
//! registry that the dispatcher and the Read VariableListName path share, and
//! its key is added to the dynamic-key set so that DeleteNamedVariableList can
//! tell a runtime-created data set from a configured one. Only domain-specific
//! list names are served: a vmd-specific or aa-specific name decodes but is
//! answered with `ObjectAccessUnsupported`, because the reporting engine also
//! handles only domain-specific data sets.

use std::sync::{Arc, Mutex};

use bytes::BytesMut;

use iec61850_mms::mms::pdu::{
    define_named_variable_list::{
        encode_confirmed_define_named_variable_list_response, DefineNamedVariableListRequest,
        DefineNamedVariableListResponse,
    },
    service_error::ErrorClass,
    ObjectName,
};
use iec61850_mms::mms::server::dispatcher::ConfirmedResponse;
use iec61850_model::IedModel;

use crate::reporting::{DatasetError, DatasetRegistry, DynamicDatasetOps};

/// Keys of the data sets created at runtime, shared with the dispatcher.
///
/// An entry is the `(domain, list_name)` registry key. Membership means the
/// data set was created by DefineNamedVariableList and may therefore be removed
/// by DeleteNamedVariableList.
pub type DynamicDatasetKeys = Arc<Mutex<std::collections::HashSet<(String, String)>>>;

/// Returns an empty dynamic-key set.
pub fn new_dynamic_dataset_keys() -> DynamicDatasetKeys {
    Arc::new(Mutex::new(std::collections::HashSet::new()))
}

/// Handles a DefineNamedVariableList request (confirmed service tag 0xab).
pub(crate) fn handle_define_named_variable_list(
    invoke_id: u32,
    body: &[u8],
    ied_model: &IedModel,
    registry: &DatasetRegistry,
    dynamic_keys: &DynamicDatasetKeys,
) -> ConfirmedResponse {
    let req = match DefineNamedVariableListRequest::decode(body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                invoke_id,
                error = %e,
                "define-named-variable-list request failed to decode, answering confirmed-error"
            );
            return crate::service::make_confirmed_error_pub(invoke_id, ErrorClass::Access(0));
        }
    };

    let (domain, list_name) = match &req.list_name {
        ObjectName::DomainSpecific { domain_id, item_id } => (domain_id.clone(), item_id.clone()),
        other => {
            tracing::warn!(
                invoke_id,
                ?other,
                "define-named-variable-list accepts only a domain-specific list name, answering object-access-unsupported"
            );
            return crate::service::make_confirmed_error_pub(invoke_id, ErrorClass::Access(9));
        }
    };

    // The PDU decoder guarantees every entry is domain-specific; a member whose
    // path does not resolve against the model is reported by `add_dynamic`.
    let members: Vec<(String, String)> = req
        .list_of_variable
        .iter()
        .map(|e| (e.domain_id.clone(), e.item_id.clone()))
        .collect();

    match DynamicDatasetOps::add_dynamic(registry, ied_model, &domain, &list_name, members) {
        Ok(_meta) => {
            match dynamic_keys.lock() {
                Ok(mut keys) => {
                    keys.insert((domain.clone(), list_name.clone()));
                }
                Err(_) => {
                    tracing::warn!(
                        invoke_id,
                        "dynamic dataset key set is poisoned; the data set exists but is not marked deletable"
                    );
                }
            }

            let mut buf = BytesMut::new();
            encode_confirmed_define_named_variable_list_response(
                invoke_id,
                &DefineNamedVariableListResponse,
                &mut buf,
            );
            ConfirmedResponse::Response(buf.freeze())
        }
        Err(DatasetError::NameAlreadyExists { domain, name }) => {
            tracing::warn!(
                invoke_id,
                domain,
                name,
                "define-named-variable-list name already exists, answering definition error"
            );
            // Definition class codes: 0 object-undefined, 1 invalid-attribute,
            // 2 object-attribute-inconsistent.
            crate::service::make_confirmed_error_pub(invoke_id, ErrorClass::Definition(0))
        }
        Err(DatasetError::MemberNotFound { path }) => {
            tracing::warn!(
                invoke_id,
                path,
                "define-named-variable-list member does not resolve, answering object-non-existent"
            );
            crate::service::make_confirmed_error_pub(invoke_id, ErrorClass::Access(10))
        }
        Err(DatasetError::MemberInvalidPath { path }) => {
            tracing::warn!(
                invoke_id,
                path,
                "define-named-variable-list member path is malformed, answering invalid-address"
            );
            crate::service::make_confirmed_error_pub(invoke_id, ErrorClass::Access(5))
        }
        Err(DatasetError::StaticNotDeletable { name }) => {
            // Not reachable on the add path; handled so the match stays total.
            tracing::warn!(
                invoke_id,
                name,
                "unexpected static-not-deletable while adding a data set"
            );
            crate::service::make_confirmed_error_pub(invoke_id, ErrorClass::Access(0))
        }
        Err(DatasetError::RegistryPoisoned) => {
            tracing::warn!(
                invoke_id,
                "dataset registry lock is poisoned, answering resource error"
            );
            crate::service::make_confirmed_error_pub(invoke_id, ErrorClass::Resource(0))
        }
    }
}
