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
//!
//! A data set created at runtime that the DatSet of a report control block
//! names may not be deleted, per DeleteDataSet in IEC 61850-7-2: when any such
//! data set is named, no data set is deleted and the request is answered with
//! the negative response of IEC 61850-8-1, a ConfirmedError whose ServiceError
//! carries `Service(ObjectConstraintConflict)` and, as serviceSpecificInformation
//! `deleteNamedVariableList`, the number of data sets deleted. A configured data
//! set is never deletable, so it is answered positively as above whether or not
//! a control block uses it.

use bytes::BytesMut;

use iec61850_mms::mms::pdu::{
    delete_named_variable_list::{
        encode_confirmed_delete_named_variable_list_response, DeleteNamedVariableListRequest,
        DeleteNamedVariableListResponse, ScopeOfDelete,
    },
    service_error::{
        encode_confirmed_error_pdu,
        subcode::{access, service},
        ErrorClass, ServiceError, ServiceSpecificInfo,
    },
    ObjectName,
};
use iec61850_mms::mms::server::dispatcher::ConfirmedResponse;

use crate::reporting::{DatasetRegistry, DynamicDatasetOps, ReportingEngine};
use crate::service::define_named_variable_list::{DynamicDatasetKeys, DynamicDatasetQuota};
use std::sync::Mutex;

pub(crate) fn handle_delete_named_variable_list(
    invoke_id: u32,
    body: &[u8],
    registry: &DatasetRegistry,
    dynamic_keys: &DynamicDatasetKeys,
    quota: &DynamicDatasetQuota,
    reporting_engine: &Mutex<ReportingEngine>,
) -> ConfirmedResponse {
    let req = match DeleteNamedVariableListRequest::decode(body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                invoke_id,
                error = %e,
                "delete-named-variable-list request failed to decode, answering confirmed-error"
            );
            return crate::service::make_confirmed_error_pub(
                invoke_id,
                ErrorClass::Access(access::OTHER),
            );
        }
    };

    if req.scope_of_delete != ScopeOfDelete::Specific {
        tracing::warn!(
            invoke_id,
            scope = ?req.scope_of_delete,
            "delete-named-variable-list serves only scope-of-delete specific, answering object-access-unsupported"
        );
        return crate::service::make_confirmed_error_pub(
            invoke_id,
            ErrorClass::Access(access::OBJECT_ACCESS_UNSUPPORTED),
        );
    }

    // Held until the data sets are removed, so no DatSet write can bind one of
    // them in between.
    let Ok(engine) = reporting_engine.lock() else {
        tracing::warn!(
            invoke_id,
            "the reporting engine lock is poisoned, answering delete-named-variable-list with service-other"
        );
        return crate::service::make_confirmed_error_pub(
            invoke_id,
            ErrorClass::Service(service::OTHER),
        );
    };
    for name in &req.list_of_variable_list_name {
        if let ObjectName::DomainSpecific { domain_id, item_id } = name {
            let is_dynamic = dynamic_keys
                .lock()
                .map(|g| g.contains(&(domain_id.clone(), item_id.clone())))
                .unwrap_or(false);
            if is_dynamic && engine.dataset_in_use(domain_id, item_id) {
                tracing::warn!(
                    invoke_id,
                    domain = domain_id.as_str(),
                    list_name = item_id.as_str(),
                    "delete-named-variable-list: a report control block uses the data set, answering object-constraint-conflict"
                );
                return delete_error(
                    invoke_id,
                    ErrorClass::Service(service::OBJECT_CONSTRAINT_CONFLICT),
                    0,
                );
            }
        }
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
                quota.forget(&(domain.clone(), list_name.clone()));
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
                quota.forget(&(domain.clone(), list_name.clone()));
            }
            Err(_) => {
                tracing::warn!(
                    invoke_id,
                    "dataset registry removal failed, skipping the entry"
                );
            }
        }
    }

    drop(engine);

    let resp = DeleteNamedVariableListResponse {
        number_matched,
        number_deleted,
    };
    let mut buf = BytesMut::new();
    encode_confirmed_delete_named_variable_list_response(invoke_id, &resp, &mut buf);
    ConfirmedResponse::Response(buf.freeze())
}

/// Builds the negative DeleteNamedVariableList response: a ConfirmedError
/// whose ServiceError carries `error_class` and, as serviceSpecificInformation,
/// `number_deleted`.
fn delete_error(invoke_id: u32, error_class: ErrorClass, number_deleted: u32) -> ConfirmedResponse {
    let service_error = ServiceError::new(error_class)
        .with_service_specific(ServiceSpecificInfo::DeleteNamedVariableList(number_deleted));
    let mut buf = BytesMut::new();
    encode_confirmed_error_pdu(invoke_id, &service_error, &mut buf);
    ConfirmedResponse::Error(buf.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sends DeleteNamedVariableList for `IED1LD0/<list_name>` against a
    /// registry holding the configured data set `GGIO1$dsStatic`, and returns
    /// `(numberMatched, numberDeleted)` with whether the data set survived.
    fn delete_from_configured(list_name: &str) -> ((u32, u32), bool) {
        use crate::reporting::{Dataset, NullReportSink};
        use crate::service::define_named_variable_list::new_dynamic_dataset_keys;
        use iec61850_mms::mms::pdu::delete_named_variable_list::decode_confirmed_delete_named_variable_list_response;
        use std::sync::Arc;

        let registry: DatasetRegistry = Default::default();
        registry.write().unwrap().insert(
            ("IED1LD0".to_string(), "GGIO1$dsStatic".to_string()),
            Arc::new(Dataset::new("GGIO1$dsStatic")),
        );
        let engine = Mutex::new(ReportingEngine::new(
            Arc::new(NullReportSink),
            Default::default(),
        ));
        let mut body = BytesMut::new();
        DeleteNamedVariableListRequest::specific_domain("IED1LD0", list_name).encode(&mut body);
        let ConfirmedResponse::Response(pdu) = handle_delete_named_variable_list(
            7,
            &body,
            &registry,
            &new_dynamic_dataset_keys(),
            &DynamicDatasetQuota::default(),
            &engine,
        ) else {
            panic!("a positive response");
        };
        let (invoke_id, resp) = decode_confirmed_delete_named_variable_list_response(&pdu).unwrap();
        assert_eq!(invoke_id, 7);
        let kept = registry
            .read()
            .unwrap()
            .contains_key(&("IED1LD0".to_string(), "GGIO1$dsStatic".to_string()));
        ((resp.number_matched, resp.number_deleted), kept)
    }

    #[test]
    fn configured_data_set_is_matched_but_not_deleted() {
        assert_eq!(delete_from_configured("GGIO1$dsStatic"), ((1, 0), true));
    }

    #[test]
    fn unknown_data_set_matches_nothing() {
        assert_eq!(delete_from_configured("GGIO1$dsGhost"), ((0, 0), true));
    }
    /// Deletes `IED1LD0/GGIO1$ds` from a registry where that data set is
    /// configured, or created at runtime when `dynamic`, while the DatSet of a
    /// URCB names it.
    fn delete_in_use(dynamic: bool) -> ConfirmedResponse {
        use crate::reporting::{Dataset, NullReportSink, Rcb, ReportControl};
        use crate::service::define_named_variable_list::new_dynamic_dataset_keys;
        use std::sync::Arc;

        let key = ("IED1LD0".to_string(), "GGIO1$ds".to_string());
        let registry: DatasetRegistry = Default::default();
        registry
            .write()
            .unwrap()
            .insert(key.clone(), Arc::new(Dataset::new("GGIO1$ds")));
        let keys = new_dynamic_dataset_keys();
        if dynamic {
            keys.lock().unwrap().insert(key.clone());
        }
        let mut engine = ReportingEngine::new(Arc::new(NullReportSink), Default::default());
        engine
            .register_rcb(
                ReportControl::new("IED1LD0/GGIO1$RP$urcb01", Rcb::new("urcb01", "GGIO1$ds")),
                Dataset::new("GGIO1$ds"),
            )
            .unwrap();
        let mut body = BytesMut::new();
        DeleteNamedVariableListRequest::specific_domain("IED1LD0", "GGIO1$ds").encode(&mut body);
        let resp = handle_delete_named_variable_list(
            9,
            &body,
            &registry,
            &keys,
            &DynamicDatasetQuota::default(),
            &Mutex::new(engine),
        );
        assert!(
            registry.read().unwrap().contains_key(&key),
            "nothing is deleted"
        );
        resp
    }

    #[test]
    fn configured_data_set_in_use_is_matched_but_not_deleted() {
        use iec61850_mms::mms::pdu::delete_named_variable_list::decode_confirmed_delete_named_variable_list_response;
        let ConfirmedResponse::Response(pdu) = delete_in_use(false) else {
            panic!("a positive response");
        };
        let (_, resp) = decode_confirmed_delete_named_variable_list_response(&pdu).unwrap();
        assert_eq!((resp.number_matched, resp.number_deleted), (1, 0));
    }

    #[test]
    fn dynamic_data_set_in_use_is_refused() {
        assert!(matches!(delete_in_use(true), ConfirmedResponse::Error(_)));
    }

    #[test]
    fn in_use_response_carries_the_number_deleted() {
        let ConfirmedResponse::Error(pdu) = delete_error(
            0x0b,
            ErrorClass::Service(service::OBJECT_CONSTRAINT_CONFLICT),
            0,
        ) else {
            panic!("a confirmed error");
        };
        assert_eq!(
            pdu.as_ref(),
            [
                0xa2, 0x0f, 0x80, 0x01, 0x0b, 0xa2, 0x0a, 0xa0, 0x03, 0x84, 0x01, 0x05, 0xa3, 0x03,
                0x86, 0x01, 0x00
            ]
        );
    }

    #[test]
    fn in_use_response_decodes_to_the_number_deleted() {
        use iec61850_mms::mms::pdu::service_error::decode_confirmed_error_pdu;
        let ConfirmedResponse::Error(pdu) = delete_error(
            3,
            ErrorClass::Service(service::OBJECT_CONSTRAINT_CONFLICT),
            0x1234,
        ) else {
            panic!("a confirmed error");
        };
        let (invoke_id, se) = decode_confirmed_error_pdu(&pdu).unwrap();
        assert_eq!(invoke_id, 3);
        assert_eq!(
            se.service_specific,
            Some(ServiceSpecificInfo::DeleteNamedVariableList(0x1234))
        );
    }
}
