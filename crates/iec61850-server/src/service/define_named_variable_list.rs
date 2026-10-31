//! Server handler for the MMS DefineNamedVariableList service, the mapping of
//! the IEC 61850-7-2 CreateDataSet request.
//!
//! Every entry of the request is resolved against the model to the node it
//! names, functional-constrained data or a functional-constrained data
//! attribute of any type, sharing the values of the leaves beneath it; the
//! resulting data set is stored in the dataset
//! registry that the dispatcher and the Read VariableListName path share, and
//! its key is added to the dynamic-key set so that DeleteNamedVariableList can
//! tell a runtime-created data set from a configured one. Only domain-specific
//! list names are served: a vmd-specific or aa-specific name decodes but is
//! answered with `ObjectAccessUnsupported`, because the reporting engine also
//! handles only domain-specific data sets.
//!
//! A domain-specific list name has the form `<LN>$<name>` that IEC 61850-8-1
//! gives a persistent data set, and the logical node must exist in the domain;
//! any other name is refused before a member is resolved. A member naming an
//! object that does not exist answers `Definition(ObjectUndefined)`, as
//! IEC 61850-8-1 §8.1.3.4.3.4 requires.
//!
//! Such a data set is persistent: it outlives the association that created it.
//! [`DynamicDatasetQuota`] bounds how many exist across the server and how many
//! of them one association has created; a request beyond either limit is
//! answered with `Resource(CapabilityUnavailable)`, as is a request whose
//! members exceed the size limits of [`DynamicDatasetOps`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::BytesMut;

use iec61850_mms::mms::pdu::{
    define_named_variable_list::{
        encode_confirmed_define_named_variable_list_response, DefineNamedVariableListRequest,
        DefineNamedVariableListResponse,
    },
    service_error::{
        subcode::{access, definition, resource},
        ErrorClass,
    },
    ObjectName,
};
use iec61850_mms::mms::server::dispatcher::ConfirmedResponse;
use iec61850_model::IedModel;

use crate::connection::ConnectionId;
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

/// Limits on the data sets clients create at run time, and the association
/// that created each one.
///
/// The total counts every data set in the dynamic-key set. The per-association
/// count covers the data sets an association created that have not been
/// deleted. A connection id is never reused, so the data sets an association
/// leaves behind when it closes count towards the total only.
#[derive(Debug)]
pub struct DynamicDatasetQuota {
    max_total: usize,
    max_per_association: usize,
    /// Creating association of each run-time data set, keyed as the registry.
    owners: Mutex<HashMap<(String, String), ConnectionId>>,
}

impl DynamicDatasetQuota {
    /// Default limit on the run-time data sets across the server.
    pub const DEFAULT_MAX_TOTAL: usize = 64;
    /// Default limit on the run-time data sets one association may create.
    pub const DEFAULT_MAX_PER_ASSOCIATION: usize = 16;

    /// Creates a quota with the given limits and no data sets.
    pub fn new(max_total: usize, max_per_association: usize) -> Self {
        Self {
            max_total,
            max_per_association,
            owners: Mutex::new(HashMap::new()),
        }
    }

    /// Returns the limit across the server.
    pub fn max_total(&self) -> usize {
        self.max_total
    }

    /// Returns the limit for one association.
    pub fn max_per_association(&self) -> usize {
        self.max_per_association
    }

    /// Stops charging a deleted data set to the association that created it.
    pub(crate) fn forget(&self, key: &(String, String)) {
        if let Ok(mut owners) = self.owners.lock() {
            owners.remove(key);
        }
    }
}

impl Default for DynamicDatasetQuota {
    fn default() -> Self {
        Self::new(Self::DEFAULT_MAX_TOTAL, Self::DEFAULT_MAX_PER_ASSOCIATION)
    }
}

/// Checks a persistent data set name, `<LN>$<name>`, against the model.
///
/// A name that is not exactly two non-empty `$`-separated parts is refused
/// with definition invalid-address; a domain or logical node that does not
/// exist, with access object-non-existent.
fn check_list_name(ied_model: &IedModel, domain: &str, list_name: &str) -> Result<(), ErrorClass> {
    let Some((ln_name, ds_name)) = list_name.split_once('$') else {
        return Err(ErrorClass::Definition(definition::INVALID_ADDRESS));
    };
    if ln_name.is_empty() || ds_name.is_empty() || ds_name.contains('$') {
        return Err(ErrorClass::Definition(definition::INVALID_ADDRESS));
    }
    let ln_exists = ied_model
        .ld_by_domain(domain)
        .is_some_and(|ld| ld.ln_by_name(ln_name).is_some());
    if !ln_exists {
        return Err(ErrorClass::Access(access::OBJECT_NON_EXISTENT));
    }
    Ok(())
}

/// Handles a DefineNamedVariableList request (confirmed service tag 0xab).
pub(crate) fn handle_define_named_variable_list(
    invoke_id: u32,
    body: &[u8],
    ied_model: &IedModel,
    registry: &DatasetRegistry,
    dynamic_keys: &DynamicDatasetKeys,
    quota: &DynamicDatasetQuota,
    conn_id: ConnectionId,
) -> ConfirmedResponse {
    let req = match DefineNamedVariableListRequest::decode(body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                invoke_id,
                error = %e,
                "define-named-variable-list request failed to decode, answering confirmed-error"
            );
            return crate::service::make_confirmed_error_pub(
                invoke_id,
                ErrorClass::Access(access::OTHER),
            );
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
            return crate::service::make_confirmed_error_pub(
                invoke_id,
                ErrorClass::Access(access::OBJECT_ACCESS_UNSUPPORTED),
            );
        }
    };

    if let Err(class) = check_list_name(ied_model, &domain, &list_name) {
        tracing::warn!(
            invoke_id,
            domain,
            list_name,
            "define-named-variable-list name is not `<LN>$<name>` of an existing logical node, refusing it"
        );
        return crate::service::make_confirmed_error_pub(invoke_id, class);
    }

    // The PDU decoder guarantees every entry is domain-specific; a member whose
    // path does not resolve against the model is reported by `add_dynamic`.
    let members: Vec<(String, String)> = req
        .list_of_variable
        .iter()
        .map(|e| (e.domain_id.clone(), e.item_id.clone()))
        .collect();

    // Held until the data set is registered, so concurrent requests cannot
    // both pass the limit check.
    let Ok(mut owners) = quota.owners.lock() else {
        tracing::warn!(
            invoke_id,
            "dynamic dataset quota is poisoned, answering resource error"
        );
        return crate::service::make_confirmed_error_pub(
            invoke_id,
            ErrorClass::Resource(resource::OTHER),
        );
    };
    let total = match dynamic_keys.lock() {
        Ok(keys) => keys.len(),
        Err(_) => quota.max_total,
    };
    let created_here = owners.values().filter(|owner| **owner == conn_id).count();
    if total >= quota.max_total || created_here >= quota.max_per_association {
        tracing::warn!(
            invoke_id,
            conn_id,
            total,
            created_here,
            max_total = quota.max_total,
            max_per_association = quota.max_per_association,
            "define-named-variable-list exceeds the run-time data set limit, answering capability-unavailable"
        );
        return crate::service::make_confirmed_error_pub(
            invoke_id,
            ErrorClass::Resource(resource::CAPABILITY_UNAVAILABLE),
        );
    }

    match DynamicDatasetOps::add_dynamic(registry, ied_model, &domain, &list_name, members) {
        Ok(_meta) => {
            owners.insert((domain.clone(), list_name.clone()), conn_id);
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
            crate::service::make_confirmed_error_pub(
                invoke_id,
                ErrorClass::Definition(definition::OBJECT_EXISTS),
            )
        }
        // A member naming an object that does not exist is an undefined
        // object of the definition (IEC 61850-8-1 §8.1.3.4.3.4, table 23).
        Err(DatasetError::MemberNotFound { path }) => {
            tracing::warn!(
                invoke_id,
                path,
                "define-named-variable-list member does not resolve, answering object-undefined"
            );
            crate::service::make_confirmed_error_pub(
                invoke_id,
                ErrorClass::Definition(definition::OBJECT_UNDEFINED),
            )
        }
        Err(DatasetError::MemberInvalidPath { path }) => {
            tracing::warn!(
                invoke_id,
                path,
                "define-named-variable-list member path is malformed, answering invalid-address"
            );
            crate::service::make_confirmed_error_pub(
                invoke_id,
                ErrorClass::Definition(definition::INVALID_ADDRESS),
            )
        }
        Err(DatasetError::StaticNotDeletable { name }) => {
            // Not reachable on the add path; handled so the match stays total.
            tracing::warn!(
                invoke_id,
                name,
                "unexpected static-not-deletable while adding a data set"
            );
            crate::service::make_confirmed_error_pub(invoke_id, ErrorClass::Access(access::OTHER))
        }
        Err(DatasetError::TooLarge { path }) => {
            tracing::warn!(
                invoke_id,
                path,
                "define-named-variable-list exceeds a data set size limit, answering capability-unavailable"
            );
            crate::service::make_confirmed_error_pub(
                invoke_id,
                ErrorClass::Resource(resource::CAPABILITY_UNAVAILABLE),
            )
        }
        Err(DatasetError::RegistryPoisoned) => {
            tracing::warn!(
                invoke_id,
                "dataset registry lock is poisoned, answering resource error"
            );
            crate::service::make_confirmed_error_pub(
                invoke_id,
                ErrorClass::Resource(resource::OTHER),
            )
        }
    }
}
