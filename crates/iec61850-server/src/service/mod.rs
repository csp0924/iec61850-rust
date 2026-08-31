//! MMS service dispatcher for the model-backed server.
//!
//! `MmsModelDispatcher` implements the `MmsServiceDispatcher` trait and routes
//! a ConfirmedRequest by its service tag: `0xa1` GetNameList, `0xa6`
//! GetVariableAccessAttributes, `0xa4` Read, `0xa5` Write, `0x82` Identify,
//! `0xab` DefineNamedVariableList, `0xad` DeleteNamedVariableList, and the
//! long-form `0xbf 0x41` ReadJournal.
//!
//! `ConfirmedResponse::Response` carries a complete ConfirmedResponsePdu,
//! outermost `0xa1 <len>` tag included, exactly as the
//! `encode_confirmed_*_response` functions emit it, so the connection layer
//! adds no wrapper of its own. `ConfirmedResponse::Error` carries the inner
//! bytes of a ConfirmedErrorPdu, invoke id included.
//!
//! GetNameList requests are all allowed; no directory access handler is
//! consulted.

pub mod convert;
// Data set creation and deletion belong to the reporting subsystem.
#[cfg(feature = "reporting")]
pub mod define_named_variable_list;
#[cfg(feature = "reporting")]
pub mod delete_named_variable_list;
pub mod get_name_list;
pub mod get_var_access_attrs;
pub mod read;
pub mod write;

// The compat facade selects std or embedded primitives; HashMap and Mutex are
// used only by the dataset registry and the reporting engine.
use crate::compat::Arc;
#[cfg(feature = "reporting")]
use crate::compat::{HashMap, Mutex};

#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use bytes::{Bytes, BytesMut};

use iec61850_mms::mms::pdu::{
    common::{AccessResult, DataAccessError, WriteOutcome},
    get_name_list::{
        encode_confirmed_get_name_list_response, GetNameListRequest, SERVICE_TAG_GET_NAME_LIST,
    },
    get_var_access_attrs::{
        encode_confirmed_get_var_access_attrs_response, GetVariableAccessAttributesRequest,
        SERVICE_TAG_GET_VAR_ACCESS_ATTRS,
    },
    read::{encode_confirmed_read_response, ReadRequest, ReadResponse, SERVICE_TAG_READ},
    service_error::{ErrorClass, ServiceError},
    write::{encode_confirmed_write_response, WriteRequest, WriteResponse, SERVICE_TAG_WRITE},
};
// The ReadJournal PDU types belong to the logging subsystem.
#[cfg(feature = "logging")]
use iec61850_mms::mms::pdu::read_journal::{
    encode_confirmed_read_journal_response, JournalRange, ReadJournalRequest, ReadJournalResponse,
    WireJournalEntry, WireJournalVariable, SERVICE_TAG_READ_JOURNAL,
};
use iec61850_mms::mms::server::{
    connection::MmsServerConnection,
    dispatcher::{ConfirmedRequest, ConfirmedResponse, MmsServiceDispatcher},
};
use iec61850_model::IedModel;

// Each import group is gated on the sub-feature that owns it.
#[cfg(feature = "control")]
use crate::control::ControlObjectsRegistry;
// Only `GoCBRegistry` is named by a field; the helpers are reached from the
// read and write routing paths, which carry their own gates.
#[cfg(feature = "goose-mapping")]
#[allow(unused_imports)]
use crate::goose_mapping::{
    apply_gocb_write, encode_gocb_da, encode_gocb_structure, parse_go_item_id, GoCBRegistry,
    GOCB_DA_NAMES,
};
use crate::handler::HandlerRegistry;
// These helpers serve the read and write routing paths, so they are available
// whenever any routed subsystem is enabled.
#[cfg(any(
    feature = "reporting",
    feature = "control",
    feature = "setting-groups",
    feature = "goose-mapping",
    feature = "logging"
))]
use crate::handler::{canonicalize_attr_path, fc_from_canonical_path, ReadContext, ReadOutcome};
#[cfg(feature = "logging")]
use crate::logging::{
    new_log_control_registry, storage::CollectingVisitor, LogControl, LogControlRegistry,
    LogEntryId, LogStorageError,
};
use crate::mapping::MmsDeviceModel;
use crate::policy::WriteAccessPolicies;
#[cfg(feature = "reporting")]
use crate::reporting::{NullReportSink, ReportingEngine};

use get_name_list::{handle_get_name_list_with_extras, GetNameListResult};
use get_var_access_attrs::{handle_get_var_access_attrs, GetVarAccessAttrsResult};
// `pdu_budget_for_access_results` serves the routed Read path.
#[cfg(any(
    feature = "reporting",
    feature = "control",
    feature = "setting-groups",
    feature = "goose-mapping",
    feature = "logging"
))]
use read::pdu_budget_for_access_results;
use write::handle_single_write;

// ─────────────────────────────────────────────────────────────────────────────
// MmsModelDispatcher
// ─────────────────────────────────────────────────────────────────────────────

/// The three strings an Identify-Response carries: `vendorName`, `modelName`,
/// and `revision`.
///
/// A field left unset in the server configuration falls back to the matching
/// `DEFAULT_` constant below.
#[derive(Debug, Clone)]
pub struct IdentificationStrings {
    /// Vendor name reported by the Identify service.
    pub vendor_name: String,
    /// Model name reported by the Identify service.
    pub model_name: String,
    /// Revision reported by the Identify service.
    pub revision: String,
}

impl IdentificationStrings {
    /// Vendor name reported when the configuration leaves it unset.
    pub const DEFAULT_VENDOR: &'static str = "rust61850";
    /// Model name reported when the configuration leaves it unset.
    pub const DEFAULT_MODEL: &'static str = "iec61850-rust";
    /// Revision reported when the configuration leaves it unset: the crate
    /// version.
    pub const DEFAULT_REVISION: &'static str = env!("CARGO_PKG_VERSION");
}

impl Default for IdentificationStrings {
    fn default() -> Self {
        Self {
            vendor_name: Self::DEFAULT_VENDOR.into(),
            model_name: Self::DEFAULT_MODEL.into(),
            revision: Self::DEFAULT_REVISION.into(),
        }
    }
}

/// MMS service dispatcher over a shared read-only view of the model.
///
/// It receives a ConfirmedRequest through the `MmsServiceDispatcher` trait and
/// answers with a ConfirmedResponse.
///
/// A Read or Write under functional constraint CO is routed to the control
/// object and handlers found in `control_objects`. `dispatch` is a synchronous
/// trait method whose signature cannot change, while the control flow involves
/// asynchronous handlers, so the control path awaits through
/// `tokio::task::block_in_place` and `Handle::current().block_on`. That
/// requires the server to run on a multi-threaded runtime.
///
/// A Read or Write under RP or BR is routed to `reporting_engine`, which
/// answers `ObjectNonExistent` for a control block it does not hold.
#[derive(Debug, Clone)]
pub struct MmsModelDispatcher {
    /// The live model, which Read and Write resolve against.
    pub model: Arc<IedModel>,
    /// The MMS view of the model, which GetNameList and
    /// GetVariableAccessAttributes resolve against.
    pub mms_model: Arc<MmsDeviceModel>,
    /// Which functional constraints accept a remote Write.
    pub write_policies: Arc<WriteAccessPolicies>,
    /// Strings returned by the Identify service.
    pub identification: Arc<IdentificationStrings>,
    /// Read and write handlers, keyed by canonical attribute path. Empty by
    /// default; the server builder injects the shared registry.
    pub handler_registry: Arc<HandlerRegistry>,
    /// Control objects reached by a Read or Write under functional constraint
    /// CO. Empty by default; injected through `with_control_objects`.
    #[cfg(feature = "control")]
    pub control_objects: Arc<ControlObjectsRegistry>,
    /// Reporting engine reached by a Read or Write under RP or BR. Defaults to
    /// an engine with a null sink; injected through `with_reporting_engine`.
    #[cfg(feature = "reporting")]
    pub reporting_engine: Arc<Mutex<ReportingEngine>>,
    /// Data sets, keyed by `(domain, mms_list_name)` such as
    /// (`"simpleIOGenericIO"`, `"GGIO1$ds1"`). Empty by default; the server
    /// builder injects the shared registry.
    #[cfg(feature = "reporting")]
    pub dataset_registry: crate::reporting::DatasetRegistry,
    /// Log control blocks, keyed by `(domain, item)` such as (`"IED1LD0"`,
    /// `"MMXU1$LG$lcb01"`), which ReadJournal resolves against. Empty by
    /// default; injected through `with_log_controls`.
    #[cfg(feature = "logging")]
    pub log_controls: LogControlRegistry,
    /// Setting group runtimes reached by a Read or Write of `LLN0$SP$SGCB`.
    /// Empty by default; the server builder projects it from the model.
    #[cfg(feature = "setting-groups")]
    pub setting_groups: Arc<crate::setting_groups::SettingGroupRegistry>,
    /// Keys of the data sets created at runtime, shared with the server so that
    /// both agree on which data sets may be deleted.
    #[cfg(feature = "reporting")]
    pub dynamic_dataset_keys: define_named_variable_list::DynamicDatasetKeys,
    /// GOOSE control blocks. Read and Write try the `GO$` path before the
    /// setting-group and reporting routes, and GetNameList adds
    /// `<LN>$GO$<gcb>[$<DA>]` entries from here. Empty by default.
    #[cfg(feature = "goose-mapping")]
    pub gocb_registry: Arc<GoCBRegistry>,
}

impl MmsModelDispatcher {
    /// Builds a dispatcher over a model, using the built-in identification
    /// strings and empty registries.
    pub fn new(
        model: Arc<IedModel>,
        mms_model: Arc<MmsDeviceModel>,
        write_policies: Arc<WriteAccessPolicies>,
    ) -> Self {
        Self::with_identification(
            model,
            mms_model,
            write_policies,
            Arc::new(IdentificationStrings::default()),
        )
    }

    /// Builds a dispatcher over a model with the supplied identification
    /// strings and empty registries.
    pub fn with_identification(
        model: Arc<IedModel>,
        mms_model: Arc<MmsDeviceModel>,
        write_policies: Arc<WriteAccessPolicies>,
        identification: Arc<IdentificationStrings>,
    ) -> Self {
        Self {
            model,
            mms_model,
            write_policies,
            identification,
            handler_registry: Arc::new(HandlerRegistry::new()),
            #[cfg(feature = "control")]
            control_objects: Arc::new(ControlObjectsRegistry::new()),
            #[cfg(feature = "reporting")]
            reporting_engine: Arc::new(Mutex::new(ReportingEngine::new(Arc::new(NullReportSink)))),
            #[cfg(feature = "reporting")]
            dataset_registry: Arc::new(std::sync::RwLock::new(HashMap::new())),
            #[cfg(feature = "logging")]
            log_controls: new_log_control_registry(),
            #[cfg(feature = "setting-groups")]
            setting_groups: Arc::new(crate::setting_groups::SettingGroupRegistry::new()),
            #[cfg(feature = "reporting")]
            dynamic_dataset_keys: define_named_variable_list::new_dynamic_dataset_keys(),
            #[cfg(feature = "goose-mapping")]
            gocb_registry: Arc::new(GoCBRegistry::new()),
        }
    }

    /// Installs the GOOSE control block registry, which the server builder
    /// shares with the server itself.
    #[cfg(feature = "goose-mapping")]
    pub fn with_gocb_registry(mut self, registry: Arc<GoCBRegistry>) -> Self {
        self.gocb_registry = registry;
        self
    }

    /// Installs the set of runtime-created data set keys, which the server
    /// builder shares with the server itself.
    #[cfg(feature = "reporting")]
    pub fn with_dynamic_dataset_keys(
        mut self,
        keys: define_named_variable_list::DynamicDatasetKeys,
    ) -> Self {
        self.dynamic_dataset_keys = keys;
        self
    }

    /// Installs the data set registry, which the server builder shares with the
    /// server itself.
    #[cfg(feature = "reporting")]
    pub fn with_dataset_registry(mut self, registry: crate::reporting::DatasetRegistry) -> Self {
        self.dataset_registry = registry;
        self
    }

    /// Installs the control object registry.
    #[cfg(feature = "control")]
    pub fn with_control_objects(mut self, registry: Arc<ControlObjectsRegistry>) -> Self {
        self.control_objects = registry;
        self
    }

    /// Installs the reporting engine, which the server builder shares with the
    /// server itself.
    #[cfg(feature = "reporting")]
    pub fn with_reporting_engine(mut self, engine: Arc<Mutex<ReportingEngine>>) -> Self {
        self.reporting_engine = engine;
        self
    }

    /// Installs the read and write handler registry.
    ///
    /// The server builder shares one registry so that handlers installed on the
    /// server are visible to the dispatcher.
    pub fn with_handler_registry(mut self, registry: Arc<HandlerRegistry>) -> Self {
        self.handler_registry = registry;
        self
    }

    /// Installs the log control block registry that ReadJournal resolves
    /// against.
    ///
    /// Blocks are registered under `(domain, item)`, and a ReadJournal request
    /// is looked up by the domain and item of its `journalName`.
    #[cfg(feature = "logging")]
    pub fn with_log_controls(mut self, registry: LogControlRegistry) -> Self {
        self.log_controls = registry;
        self
    }

    /// Installs the setting group registry, which the server builder projects
    /// from the setting group control blocks of the model. Application
    /// callbacks are registered on the server afterwards.
    #[cfg(feature = "setting-groups")]
    pub fn with_setting_groups(
        mut self,
        registry: Arc<crate::setting_groups::SettingGroupRegistry>,
    ) -> Self {
        self.setting_groups = registry;
        self
    }
}

/// Byte of the `servicesSupported` BIT STRING that carries the journal
/// services, `readJournal` through `deleteJournal`.
const SERVICES_JOURNAL_BYTE: usize = 8;

/// `readJournal` within [`SERVICES_JOURNAL_BYTE`].
///
/// The bit string is numbered from its most significant bit, so service 65 is
/// the second bit of byte 8. `DEFAULT_SERVICES_SUPPORTED_CLIENT` carries `0x79`
/// in that byte, the four consecutive journal services followed by
/// `getCapabilityList`, which fixes `readJournal` at `0x40`.
const SERVICES_READ_JOURNAL_BIT: u8 = 0x40;

/// Builds the `servicesSupportedCalled` bitmap of the Initiate-Response for the
/// services this build actually serves.
///
/// Starting from the baseline of the connection layer, a bit is cleared unless
/// a handler answers it: `status`, `cancel`, and
/// `getNamedVariableListAttributes` have no handler in any build, and data set
/// creation and deletion together with `informationReport` are cleared without
/// the reporting subsystem. The baseline carries no journal service, so
/// `readJournal` is set rather than cleared when the logging subsystem answers
/// it; `writeJournal` stays clear, since that request is answered with an
/// access error rather than served.
///
/// Both flags describe the compiled subsystems, not the registry contents. A
/// control block, data set or log control block is registered after the
/// dispatcher is built, while this bitmap is sent once per association, so
/// gating on what is currently registered would announce less than the server
/// goes on to serve.
///
/// A client enables its own paths from this bitmap, so advertising a service
/// that is not implemented leads it into a request that can only fail, and
/// withholding one it does implement leaves that service unreachable.
fn compute_services_supported(reporting: bool, logging: bool) -> [u8; 11] {
    use iec61850_mms::mms::server::connection::SERVER_SERVICES_SUPPORTED;
    let mut map = SERVER_SERVICES_SUPPORTED;
    map[0] &= !0x80; // status
    map[1] &= !0x08; // getNamedVariableListAttributes
    map[10] &= !0x08; // cancel: a Cancel-RequestPDU is rejected at the PDU layer
    if !reporting {
        map[1] &= !(0x10 | 0x04); // define and delete NamedVariableList
        map[9] &= !0x01; // informationReport
    }
    if logging {
        map[SERVICES_JOURNAL_BYTE] |= SERVICES_READ_JOURNAL_BIT;
    }
    map
}

impl MmsServiceDispatcher for MmsModelDispatcher {
    fn services_supported(&self) -> [u8; 11] {
        compute_services_supported(cfg!(feature = "reporting"), cfg!(feature = "logging"))
    }

    fn dispatch(&self, conn: &MmsServerConnection, req: ConfirmedRequest) -> ConfirmedResponse {
        let invoke_id = req.invoke_id;
        let body = req.service_body;
        let conn_id = conn.connection_id().unwrap_or(0);

        if body.is_empty() {
            tracing::warn!(invoke_id, "dispatcher: empty service body, rejecting");
            return ConfirmedResponse::Reject;
        }

        let service_tag = body[0];

        // A context tag number of 31 or more takes the long form: `0xbf`
        // followed by the tag value. MMS readJournal is 65 (`0xbf 0x41`) and
        // writeJournal 66 (`0xbf 0x42`).
        if service_tag == 0xbf {
            if body.len() < 2 {
                tracing::warn!(
                    invoke_id,
                    "dispatcher: long-form tag with no tag value, rejecting"
                );
                return ConfirmedResponse::Reject;
            }
            // ReadJournal is `[0xbf, 0x41]`; writeJournal, `[0xbf, 0x42]`, has
            // no handler. The journal path belongs to the logging subsystem.
            #[cfg(feature = "logging")]
            {
                return match body[1] {
                    b if b == SERVICE_TAG_READ_JOURNAL[1] => dispatch_read_journal(
                        invoke_id,
                        &body,
                        &self.log_controls,
                        conn.negotiated_max_pdu_size(),
                    ),
                    0x42 => dispatch_write_journal_unsupported(invoke_id),
                    other => {
                        tracing::warn!(
                            invoke_id,
                            long_form_tag = format!("0xbf 0x{:02X}", other),
                            "dispatcher: unknown long-form service tag, rejecting"
                        );
                        ConfirmedResponse::Reject
                    }
                };
            }
            // Without the logging subsystem no long-form tag has a handler.
            #[cfg(not(feature = "logging"))]
            {
                tracing::warn!(
                    invoke_id,
                    long_form_tag = format!("0xbf 0x{:02X}", body[1]),
                    "dispatcher: logging is not enabled, long-form service tags are not served, rejecting"
                );
                return ConfirmedResponse::Reject;
            }
        }

        match service_tag {
            SERVICE_TAG_GET_NAME_LIST => dispatch_get_name_list(
                invoke_id,
                &body,
                &self.mms_model,
                #[cfg(feature = "goose-mapping")]
                &self.gocb_registry,
                #[cfg(feature = "reporting")]
                &self.reporting_engine,
                #[cfg(feature = "reporting")]
                &self.dataset_registry,
                #[cfg(feature = "logging")]
                &self.log_controls,
            ),
            SERVICE_TAG_GET_VAR_ACCESS_ATTRS => {
                dispatch_get_var_access_attrs(invoke_id, &body, &self.mms_model)
            }
            SERVICE_TAG_IDENTIFY => dispatch_identify(invoke_id, &self.identification),
            SERVICE_TAG_READ => dispatch_read(
                invoke_id,
                &body,
                &self.model,
                &self.mms_model,
                #[cfg(feature = "control")]
                &self.control_objects,
                #[cfg(feature = "reporting")]
                &self.reporting_engine,
                &self.handler_registry,
                #[cfg(feature = "reporting")]
                &self.dataset_registry,
                #[cfg(feature = "setting-groups")]
                &self.setting_groups,
                #[cfg(feature = "goose-mapping")]
                &self.gocb_registry,
                #[cfg(feature = "logging")]
                &self.log_controls,
                conn_id,
                conn.negotiated_max_pdu_size(),
            ),
            SERVICE_TAG_WRITE => dispatch_write(
                invoke_id,
                &body,
                &self.model,
                &self.mms_model,
                &self.write_policies,
                #[cfg(feature = "control")]
                &self.control_objects,
                #[cfg(feature = "reporting")]
                &self.reporting_engine,
                &self.handler_registry,
                #[cfg(feature = "reporting")]
                &self.dataset_registry,
                #[cfg(feature = "setting-groups")]
                &self.setting_groups,
                #[cfg(feature = "goose-mapping")]
                &self.gocb_registry,
                conn_id,
            ),
            // DefineNamedVariableList, the mapping of CreateDataSet.
            #[cfg(feature = "reporting")]
            0xab => define_named_variable_list::handle_define_named_variable_list(
                invoke_id,
                &body,
                &self.model,
                &self.dataset_registry,
                &self.dynamic_dataset_keys,
            ),
            // DeleteNamedVariableList, the mapping of DeleteDataSet.
            #[cfg(feature = "reporting")]
            0xad => delete_named_variable_list::handle_delete_named_variable_list(
                invoke_id,
                &body,
                &self.dataset_registry,
                &self.dynamic_dataset_keys,
            ),
            other => {
                tracing::warn!(
                    invoke_id,
                    service_tag = format!("0x{:02X}", other),
                    "dispatcher: unknown service tag, rejecting"
                );
                ConfirmedResponse::Reject
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Identify service tag
// ─────────────────────────────────────────────────────────────────────────────

/// `Identify-Request ::= NULL`, `[2] IMPLICIT` and primitive, hence tag `0x82`.
///
/// `Identify-Response ::= SEQUENCE { ... }`, `[2] IMPLICIT` and constructed,
/// hence tag `0xa2`.
const SERVICE_TAG_IDENTIFY: u8 = 0x82;

// ─────────────────────────────────────────────────────────────────────────────
// Per-service dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Dispatches a GetNameList request (`0xa1`).
fn dispatch_get_name_list(
    invoke_id: u32,
    body: &Bytes,
    mms_model: &MmsDeviceModel,
    #[cfg(feature = "goose-mapping")] gocb_registry: &GoCBRegistry,
    #[cfg(feature = "reporting")] reporting_engine: &Arc<Mutex<ReportingEngine>>,
    #[cfg(feature = "reporting")] dataset_registry: &crate::reporting::DatasetRegistry,
    #[cfg(feature = "logging")] log_controls: &LogControlRegistry,
) -> ConfirmedResponse {
    // The service body starts at the `0xa1` tag.
    let req = match GetNameListRequest::decode(body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                invoke_id,
                error = %e,
                "get-name-list request failed to decode, answering confirmed-error"
            );
            return make_confirmed_error(invoke_id, ErrorClass::Access(0));
        }
    };

    // Objects registered after the model view was built are merged into the
    // matching domain-scope name list; every other class and scope leaves the
    // extras empty.
    #[cfg(any(feature = "goose-mapping", feature = "reporting", feature = "logging"))]
    let extras: Vec<String> = runtime_extras(
        &req,
        #[cfg(feature = "goose-mapping")]
        gocb_registry,
        #[cfg(feature = "reporting")]
        reporting_engine,
        #[cfg(feature = "reporting")]
        dataset_registry,
        #[cfg(feature = "logging")]
        log_controls,
    );
    #[cfg(not(any(feature = "goose-mapping", feature = "reporting", feature = "logging")))]
    let extras: Vec<String> = Vec::new();

    match handle_get_name_list_with_extras(mms_model, &req, &extras) {
        GetNameListResult::Response(resp) => {
            let mut buf = BytesMut::new();
            encode_confirmed_get_name_list_response(invoke_id, &resp, &mut buf);
            ConfirmedResponse::Response(buf.freeze())
        }
        GetNameListResult::NotFound => {
            tracing::warn!(
                invoke_id,
                "get-name-list: unknown domain or continueAfter, answering object-non-existent"
            );
            make_confirmed_error(invoke_id, ErrorClass::Access(10)) // object-non-existent
        }
        GetNameListResult::Unsupported => {
            tracing::warn!(
                invoke_id,
                "get-name-list: this object class and scope are not served"
            );
            make_confirmed_error(invoke_id, ErrorClass::Access(9)) // object-access-unsupported
        }
    }
}

/// Names of the registered control blocks and data sets that belong in the
/// answer to `req`, over and above the named variables of the model view.
///
/// These registries are the same ones the Read paths resolve against, so a name
/// this returns is a name a client can go on to read. The model is deliberately
/// not a second source: a control block or data set the model declares but
/// nothing registered has no Read handler, and listing it would advertise a
/// name that answers object-non-existent. A log control block resolves to the
/// attributes of [`LCB_SERVED_FIELDS`]; the rest of its attributes answer
/// object-access-unsupported, which reports the name as existing.
///
/// Only two combinations have members. Domain-scope named variables gain the
/// GOOSE control blocks of the domain, the MMS path tail of every report
/// control block the reporting engine holds, `<LN>$RP$<name>` or
/// `<LN>$BR$<name>`, and the `<LN>$LG$<name>` path of every log control block
/// the log control registry holds. Domain-scope named variable lists gain the
/// data sets of the registry, which covers both those the application
/// registered and those a client created with DefineNamedVariableList.
///
/// A poisoned registry lock yields the names it can still contribute rather
/// than failing the request: an incomplete directory is more useful to a
/// browsing client than none.
#[cfg(any(feature = "goose-mapping", feature = "reporting", feature = "logging"))]
fn runtime_extras(
    req: &GetNameListRequest,
    #[cfg(feature = "goose-mapping")] gocb_registry: &GoCBRegistry,
    #[cfg(feature = "reporting")] reporting_engine: &Arc<Mutex<ReportingEngine>>,
    #[cfg(feature = "reporting")] dataset_registry: &crate::reporting::DatasetRegistry,
    #[cfg(feature = "logging")] log_controls: &LogControlRegistry,
) -> Vec<String> {
    use iec61850_mms::mms::pdu::get_name_list::{ObjectClass, ObjectScope};
    match (&req.object_class, &req.object_scope) {
        (ObjectClass::NamedVariable, ObjectScope::DomainSpecific(domain)) => {
            let mut out = Vec::new();
            #[cfg(feature = "goose-mapping")]
            out.extend(gocb_registry.list_mms_names_in_domain(domain));
            #[cfg(feature = "reporting")]
            {
                // The engine keys a control block by `<domain>/<LN>$FC$<name>`,
                // while a name list carries the part after the domain.
                let prefix = format!("{domain}/");
                match reporting_engine.lock() {
                    Ok(engine) => out.extend(
                        engine
                            .rcb_paths()
                            .into_iter()
                            .chain(engine.brcb_paths())
                            .filter_map(|p| p.strip_prefix(&prefix).map(String::from)),
                    ),
                    Err(_) => tracing::warn!(
                        domain = %domain,
                        "get-name-list: the reporting engine lock is poisoned, no report control block is listed"
                    ),
                }
            }
            #[cfg(feature = "logging")]
            {
                match log_controls.read() {
                    Ok(registry) => out.extend(
                        registry
                            .keys()
                            .filter(|(d, item)| d == domain && is_lcb_path(item))
                            .map(|(_, item)| item.clone()),
                    ),
                    Err(_) => tracing::warn!(
                        domain = %domain,
                        "get-name-list: the log control registry lock is poisoned, no log control block is listed"
                    ),
                }
            }
            out
        }
        #[cfg(feature = "reporting")]
        (ObjectClass::NamedVariableList, ObjectScope::DomainSpecific(domain)) => {
            match dataset_registry.read() {
                Ok(registry) => registry
                    .keys()
                    .filter(|(d, _)| d == domain)
                    .map(|(_, list_name)| list_name.clone())
                    .collect(),
                Err(_) => {
                    tracing::warn!(
                        domain = %domain,
                        "get-name-list: the data set registry lock is poisoned, no data set is listed"
                    );
                    Vec::new()
                }
            }
        }
        _ => Vec::new(),
    }
}

/// Whether a log control registry item names a log control block, as opposed to
/// a log instance.
///
/// The registry accepts both forms of key. Only `<LN>$LG$<name>` is an MMS
/// named variable of the domain, and only that form is what the Read path
/// resolves. A log instance such as `MMXU1$EventLog` names a journal, which
/// belongs to the Journal object class and which this handler does not
/// enumerate; listing it as a named variable would advertise a name Read
/// cannot resolve.
#[cfg(feature = "logging")]
fn is_lcb_path(item: &str) -> bool {
    let mut segments = item.split('$');
    let ln = segments.next().unwrap_or_default();
    !ln.is_empty()
        && segments.next() == Some("LG")
        && segments.next().is_some_and(|name| !name.is_empty())
        && segments.next().is_none()
}

/// Dispatches a GetVariableAccessAttributes request (`0xa6`).
fn dispatch_get_var_access_attrs(
    invoke_id: u32,
    body: &Bytes,
    mms_model: &MmsDeviceModel,
) -> ConfirmedResponse {
    let req = match GetVariableAccessAttributesRequest::decode(body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                invoke_id,
                error = %e,
                "get-variable-access-attributes request failed to decode, answering confirmed-error"
            );
            return make_confirmed_error(invoke_id, ErrorClass::Access(0));
        }
    };

    match handle_get_var_access_attrs(mms_model, &req) {
        GetVarAccessAttrsResult::Response(resp) => {
            let mut buf = BytesMut::new();
            match encode_confirmed_get_var_access_attrs_response(invoke_id, &resp, &mut buf) {
                Ok(()) => ConfirmedResponse::Response(buf.freeze()),
                Err(e) => {
                    tracing::warn!(
                        invoke_id,
                        error = %e,
                        "get-variable-access-attributes response failed to encode, answering confirmed-error"
                    );
                    make_confirmed_error(invoke_id, ErrorClass::Access(0))
                }
            }
        }
        GetVarAccessAttrsResult::NotFound => {
            tracing::warn!(
                invoke_id,
                "get-variable-access-attributes: the path does not resolve, answering object-non-existent"
            );
            make_confirmed_error(invoke_id, ErrorClass::Access(10)) // object-non-existent
        }
        GetVarAccessAttrsResult::Unsupported => {
            tracing::warn!(
                invoke_id,
                "get-variable-access-attributes: this object name scope is not served"
            );
            make_confirmed_error(invoke_id, ErrorClass::Access(9)) // object-access-unsupported
        }
    }
}

/// Dispatches a Read request (`0xa4`) with data set, control, reporting,
/// setting group, and GOOSE control block routing.
///
/// A read that expands a logical node or a functional-constraint group tracks a
/// byte budget as it goes; exceeding the negotiated maximum PDU size replaces
/// the whole ReadResponse with `ConfirmedError(Resource(0))`, as
/// IEC 61850-8-1 requires, rather than failing individual entries.
#[cfg(any(
    feature = "reporting",
    feature = "control",
    feature = "setting-groups",
    feature = "goose-mapping",
    feature = "logging"
))]
#[allow(clippy::too_many_arguments)]
fn dispatch_read(
    invoke_id: u32,
    body: &Bytes,
    ied_model: &IedModel,
    mms_model: &MmsDeviceModel,
    #[cfg(feature = "control")] control_objects: &ControlObjectsRegistry,
    #[cfg(feature = "reporting")] reporting_engine: &Arc<Mutex<ReportingEngine>>,
    handler_registry: &HandlerRegistry,
    #[cfg(feature = "reporting")] dataset_registry: &crate::reporting::DatasetRegistry,
    #[cfg(feature = "setting-groups")] setting_groups: &crate::setting_groups::SettingGroupRegistry,
    #[cfg(feature = "goose-mapping")] gocb_registry: &GoCBRegistry,
    #[cfg(feature = "logging")] log_controls: &LogControlRegistry,
    conn_id: u64,
    negotiated_max_pdu_size: Option<u32>,
) -> ConfirmedResponse {
    let req = match ReadRequest::decode(body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                invoke_id,
                error = %e,
                "read request failed to decode, answering confirmed-error"
            );
            return make_confirmed_error(invoke_id, ErrorClass::Access(0));
        }
    };

    // A read names either a list of variables or one data set.
    let entries = match &req.variable_access_spec {
        iec61850_mms::mms::pdu::common::VariableAccessSpecification::ListOfVariable(v) => v.clone(),
        #[cfg(feature = "reporting")]
        iec61850_mms::mms::pdu::common::VariableAccessSpecification::VariableListName(name) => {
            // GetDataSetValues: the data set is looked up by domain and name.
            let key = match name {
                iec61850_mms::ObjectName::DomainSpecific { domain_id, item_id } => {
                    (domain_id.clone(), item_id.clone())
                }
                _ => {
                    tracing::warn!(
                        invoke_id,
                        "read: only a domain-specific data set name is served"
                    );
                    let resp = ReadResponse {
                        variable_access_spec: None,
                        list_of_access_result: vec![AccessResult::Failure(
                            DataAccessError::ObjectAccessUnsupported,
                        )],
                    };
                    let mut buf = BytesMut::new();
                    encode_confirmed_read_response(invoke_id, &resp, &mut buf);
                    return ConfirmedResponse::Response(buf.freeze());
                }
            };
            let dataset_arc = match dataset_registry.read() {
                Ok(g) => g.get(&key).cloned(),
                Err(_) => {
                    tracing::warn!(invoke_id, "read: the data set registry lock is poisoned");
                    None
                }
            };
            let Some(dataset) = dataset_arc else {
                tracing::warn!(
                    invoke_id,
                    domain = key.0,
                    list = key.1,
                    "read: no such data set, answering object-non-existent"
                );
                let resp = ReadResponse {
                    variable_access_spec: None,
                    list_of_access_result: vec![AccessResult::Failure(
                        DataAccessError::ObjectNonExistent,
                    )],
                };
                let mut buf = BytesMut::new();
                encode_confirmed_read_response(invoke_id, &resp, &mut buf);
                return ConfirmedResponse::Response(buf.freeze());
            };

            // Each entry snapshots its value under the shared lock and is then
            // converted to wire data.
            use crate::service::convert::mms_value_to_mms_data;
            let results: Vec<AccessResult> = dataset
                .entries
                .iter()
                .map(|entry| match entry.read_value() {
                    Some(v) => AccessResult::Success(mms_value_to_mms_data(&v)),
                    None => AccessResult::Failure(DataAccessError::HardwareFault),
                })
                .collect();
            let resp = ReadResponse {
                variable_access_spec: None,
                list_of_access_result: results,
            };
            let mut buf = BytesMut::new();
            encode_confirmed_read_response(invoke_id, &resp, &mut buf);
            return ConfirmedResponse::Response(buf.freeze());
        }
        // Data sets belong to the reporting subsystem; without it the whole PDU
        // answers object-access-unsupported.
        #[cfg(not(feature = "reporting"))]
        iec61850_mms::mms::pdu::common::VariableAccessSpecification::VariableListName(_) => {
            tracing::warn!(
                invoke_id,
                "read: data sets are not served in a build without reporting"
            );
            let resp = ReadResponse {
                variable_access_spec: None,
                list_of_access_result: vec![AccessResult::Failure(
                    DataAccessError::ObjectAccessUnsupported,
                )],
            };
            let mut buf = BytesMut::new();
            encode_confirmed_read_response(invoke_id, &resp, &mut buf);
            return ConfirmedResponse::Response(buf.freeze());
        }
    };

    // One budget covers the whole list of access results; each entry deducts
    // what it occupies.
    let mut remaining_budget = pdu_budget_for_access_results(negotiated_max_pdu_size);

    let mut results: Vec<AccessResult> = Vec::with_capacity(entries.len());
    for entry in &entries {
        let outcome = handle_read_with_routing(
            ied_model,
            mms_model,
            #[cfg(feature = "control")]
            control_objects,
            #[cfg(feature = "reporting")]
            reporting_engine,
            handler_registry,
            #[cfg(feature = "setting-groups")]
            setting_groups,
            #[cfg(feature = "goose-mapping")]
            gocb_registry,
            #[cfg(feature = "logging")]
            log_controls,
            conn_id,
            &entry.name,
            entry.alt_access.as_ref(),
            remaining_budget,
        );
        match outcome {
            ReadRoutingOutcome::Result(r) => {
                // AlternateAccess (when requested) is now resolved inside the
                // standard read lookup against the model-typed DA tree, so
                // component paths can walk a per-element Structure by name.
                // The size is recomputed from the finished access result so
                // that every routing path is charged the same way.
                if let Some(b) = remaining_budget.as_mut() {
                    let used = r.estimated_encoded_size();
                    if *b < used {
                        tracing::warn!(
                            invoke_id,
                            "read: the access results exceed the negotiated maximum PDU size, answering the whole request with a resource error"
                        );
                        return make_confirmed_error(invoke_id, ErrorClass::Resource(0));
                    }
                    *b -= used;
                }
                results.push(r);
            }
            ReadRoutingOutcome::OverBudget => {
                tracing::warn!(
                    invoke_id,
                    "read: expanding the logical node exceeds the negotiated maximum PDU size, answering a resource error per IEC 61850-8-1"
                );
                return make_confirmed_error(invoke_id, ErrorClass::Resource(0));
            }
        }
    }

    let resp = ReadResponse {
        variable_access_spec: None,
        list_of_access_result: results,
    };
    let mut buf = BytesMut::new();
    encode_confirmed_read_response(invoke_id, &resp, &mut buf);
    ConfirmedResponse::Response(buf.freeze())
}

/// Dispatches a Read request (`0xa4`) in a build with no routed subsystems.
///
/// Each entry of a variable list is read under the shared budget. A data set
/// name has no registry to resolve against, so the whole PDU answers
/// `ObjectAccessUnsupported`.
#[cfg(not(any(
    feature = "reporting",
    feature = "control",
    feature = "setting-groups",
    feature = "goose-mapping",
    feature = "logging"
)))]
fn dispatch_read(
    invoke_id: u32,
    body: &Bytes,
    ied_model: &IedModel,
    mms_model: &MmsDeviceModel,
    _handler_registry: &HandlerRegistry,
    _conn_id: u64,
    negotiated_max_pdu_size: Option<u32>,
) -> ConfirmedResponse {
    use crate::service::read::{handle_single_read_with_budget, LookupResult};
    let req = match ReadRequest::decode(body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(invoke_id, error = %e, "read request failed to decode, answering confirmed-error");
            return make_confirmed_error(invoke_id, ErrorClass::Access(0));
        }
    };
    let entries = match &req.variable_access_spec {
        iec61850_mms::mms::pdu::common::VariableAccessSpecification::ListOfVariable(v) => v.clone(),
        iec61850_mms::mms::pdu::common::VariableAccessSpecification::VariableListName(_) => {
            tracing::warn!(invoke_id, "read: data sets are not served in this build");
            let resp = ReadResponse {
                variable_access_spec: None,
                list_of_access_result: vec![AccessResult::Failure(
                    DataAccessError::ObjectAccessUnsupported,
                )],
            };
            let mut buf = BytesMut::new();
            encode_confirmed_read_response(invoke_id, &resp, &mut buf);
            return ConfirmedResponse::Response(buf.freeze());
        }
    };
    let mut remaining = negotiated_max_pdu_size.map(|n| n as usize);
    let mut results: Vec<AccessResult> = Vec::with_capacity(entries.len());
    for entry in &entries {
        match handle_single_read_with_budget(
            ied_model,
            mms_model,
            &entry.name,
            entry.alt_access.as_ref(),
            remaining,
        ) {
            LookupResult::Result(r) => {
                if let Some(b) = remaining.as_mut() {
                    let used = r.estimated_encoded_size();
                    if *b < used {
                        return make_confirmed_error(invoke_id, ErrorClass::Resource(0));
                    }
                    *b -= used;
                }
                results.push(r);
            }
            LookupResult::OverBudget => {
                return make_confirmed_error(invoke_id, ErrorClass::Resource(0));
            }
        }
    }
    let resp = ReadResponse {
        variable_access_spec: None,
        list_of_access_result: results,
    };
    let mut buf = BytesMut::new();
    encode_confirmed_read_response(invoke_id, &resp, &mut buf);
    ConfirmedResponse::Response(buf.freeze())
}

/// Outcome of routing one read entry, including the budget signal.
#[cfg(any(
    feature = "reporting",
    feature = "control",
    feature = "setting-groups",
    feature = "goose-mapping",
    feature = "logging"
))]
enum ReadRoutingOutcome {
    Result(AccessResult),
    OverBudget,
}

/// Reads an object name as a GOOSE control block path.
///
/// `Some(Success(data))` means the `GO$` path resolved to a known attribute.
/// `Some(Failure(ObjectNonExistent))` means the path is shaped like a control
/// block path but names no block or no known attribute.
/// `Some(Failure(TypeInconsistent))` means AlternateAccess was requested, which
/// a control block does not support. `None` means the name is not a control
/// block path and the caller continues with its other routes.
///
/// The read path tries this before the setting group and reporting routes.
#[cfg(feature = "goose-mapping")]
fn try_read_gocb(
    registry: &GoCBRegistry,
    name: &iec61850_mms::mms::pdu::common::ObjectName,
    alt_access: Option<&iec61850_mms::mms::pdu::common::AlternateAccess>,
) -> Option<AccessResult> {
    let (domain, item) = match name {
        iec61850_mms::ObjectName::DomainSpecific { domain_id, item_id } => {
            (domain_id.as_str(), item_id.as_str())
        }
        _ => return None,
    };
    let (base, da) = parse_go_item_id(item)?;
    if alt_access.is_some() {
        tracing::warn!(
            domain,
            item,
            "read of a GOOSE control block with alternate-access: control blocks are not arrays, rejecting"
        );
        return Some(AccessResult::Failure(DataAccessError::TypeInconsistent));
    }
    match registry.find_by_item_base(domain, base) {
        Some(handle) => match da {
            None => Some(AccessResult::Success(encode_gocb_structure(&handle))),
            Some(da_name) => {
                if !GOCB_DA_NAMES.contains(&da_name) {
                    tracing::warn!(
                        domain,
                        item,
                        da = da_name,
                        "read: unknown GOOSE control block attribute"
                    );
                    return Some(AccessResult::Failure(DataAccessError::ObjectNonExistent));
                }
                Some(AccessResult::Success(encode_gocb_da(&handle, da_name)))
            }
        },
        None => {
            tracing::warn!(
                domain,
                item,
                "read: no GOOSE control block registered under this name"
            );
            Some(AccessResult::Failure(DataAccessError::ObjectNonExistent))
        }
    }
}

/// Writes an object name as a GOOSE control block path.
///
/// `Some(Success)` means a writable attribute such as `GoEna` or `GoID` was
/// updated. `Some(Failure(ObjectAccessDenied))` means the attribute is
/// read-only. `Some(Failure(ObjectAccessUnsupported))` means the name selects
/// the whole control block rather than one attribute; a client writes the
/// attributes one at a time. `Some(Failure(ObjectNonExistent))` means the path
/// is shaped like a control block path but names no block. `None` means the
/// name is not a control block path and the caller continues with its other
/// routes.
#[cfg(feature = "goose-mapping")]
fn try_write_gocb(
    registry: &GoCBRegistry,
    name: &iec61850_mms::mms::pdu::common::ObjectName,
    data: &iec61850_mms::mms::pdu::common::MmsData,
) -> Option<WriteOutcome> {
    let (domain, item) = match name {
        iec61850_mms::ObjectName::DomainSpecific { domain_id, item_id } => {
            (domain_id.as_str(), item_id.as_str())
        }
        _ => return None,
    };
    let (base, da) = parse_go_item_id(item)?;
    match registry.find_by_item_base(domain, base) {
        Some(handle) => match da {
            None => {
                tracing::warn!(
                    domain,
                    item,
                    "write: a GOOSE control block is written one attribute at a time, answering object-access-unsupported"
                );
                Some(WriteOutcome::Failure(
                    DataAccessError::ObjectAccessUnsupported,
                ))
            }
            Some(da_name) => Some(apply_gocb_write(&handle, da_name, data)),
        },
        None => {
            tracing::warn!(
                domain,
                item,
                "write: no GOOSE control block registered under this name"
            );
            Some(WriteOutcome::Failure(DataAccessError::ObjectNonExistent))
        }
    }
}

/// Dispatches a Write request (`0xa5`) with data set, control, reporting,
/// setting group, and GOOSE control block routing.
///
/// Each route is compiled in with the sub-feature that owns it; a route whose
/// feature is off is skipped and the entry falls through to the standard write.
// Every parameter is plumbed independently by feature, so grouping them into a
// struct would not simplify the call sites.
#[cfg(any(
    feature = "reporting",
    feature = "control",
    feature = "setting-groups",
    feature = "goose-mapping"
))]
#[allow(clippy::too_many_arguments)]
fn dispatch_write(
    invoke_id: u32,
    body: &Bytes,
    ied_model: &IedModel,
    mms_model: &MmsDeviceModel,
    policies: &WriteAccessPolicies,
    #[cfg(feature = "control")] control_objects: &ControlObjectsRegistry,
    #[cfg(feature = "reporting")] reporting_engine: &Arc<Mutex<ReportingEngine>>,
    handler_registry: &HandlerRegistry,
    #[cfg(feature = "reporting")] dataset_registry: &crate::reporting::DatasetRegistry,
    #[cfg(feature = "setting-groups")] setting_groups: &crate::setting_groups::SettingGroupRegistry,
    #[cfg(feature = "goose-mapping")] gocb_registry: &GoCBRegistry,
    conn_id: u64,
) -> ConfirmedResponse {
    let req = match WriteRequest::decode(body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                invoke_id,
                error = %e,
                "write request failed to decode, answering confirmed-error"
            );
            return make_confirmed_error(invoke_id, ErrorClass::Access(0));
        }
    };

    // A write names either a list of variables or one data set.
    let entries = match &req.variable_access_spec {
        iec61850_mms::mms::pdu::common::VariableAccessSpecification::ListOfVariable(v) => v.clone(),
        iec61850_mms::mms::pdu::common::VariableAccessSpecification::VariableListName(_name) => {
            // SetDataSetValues. Data sets belong to the reporting subsystem;
            // without it there is no registry and every entry is refused.
            #[cfg(feature = "reporting")]
            {
                let name = _name;
                let key = match name {
                    iec61850_mms::ObjectName::DomainSpecific { domain_id, item_id } => {
                        (domain_id.clone(), item_id.clone())
                    }
                    _ => {
                        tracing::warn!(
                            invoke_id,
                            "write: only a domain-specific data set name is served"
                        );
                        let outcomes: Vec<WriteOutcome> = req
                            .list_of_data
                            .iter()
                            .map(|_| {
                                WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported)
                            })
                            .collect();
                        let resp = WriteResponse { outcomes };
                        let mut buf = BytesMut::new();
                        encode_confirmed_write_response(invoke_id, &resp, &mut buf);
                        return ConfirmedResponse::Response(buf.freeze());
                    }
                };
                let dataset_arc = match dataset_registry.read() {
                    Ok(g) => g.get(&key).cloned(),
                    Err(_) => {
                        tracing::warn!(invoke_id, "write: the data set registry lock is poisoned");
                        None
                    }
                };
                let Some(dataset) = dataset_arc else {
                    tracing::warn!(
                        invoke_id,
                        domain = key.0,
                        list = key.1,
                        "write: no such data set, answering object-non-existent"
                    );
                    let outcomes: Vec<WriteOutcome> = req
                        .list_of_data
                        .iter()
                        .map(|_| WriteOutcome::Failure(DataAccessError::ObjectNonExistent))
                        .collect();
                    let resp = WriteResponse { outcomes };
                    let mut buf = BytesMut::new();
                    encode_confirmed_write_response(invoke_id, &resp, &mut buf);
                    return ConfirmedResponse::Response(buf.freeze());
                };

                // One value per data set member, or the request is malformed.
                if dataset.entries.len() != req.list_of_data.len() {
                    tracing::warn!(
                        invoke_id,
                        expected = dataset.entries.len(),
                        got = req.list_of_data.len(),
                        "write: the value count does not match the data set member count"
                    );
                    let outcomes: Vec<WriteOutcome> = req
                        .list_of_data
                        .iter()
                        .map(|_| WriteOutcome::Failure(DataAccessError::TypeInconsistent))
                        .collect();
                    let resp = WriteResponse { outcomes };
                    let mut buf = BytesMut::new();
                    encode_confirmed_write_response(invoke_id, &resp, &mut buf);
                    return ConfirmedResponse::Response(buf.freeze());
                }

                use crate::service::convert::mms_data_to_mms_value;
                let outcomes: Vec<WriteOutcome> = dataset
                    .entries
                    .iter()
                    .zip(req.list_of_data.iter())
                    .map(|(entry, data)| {
                        let value = mms_data_to_mms_value(data);
                        match entry.value.write() {
                            Ok(mut g) => {
                                *g = value;
                                WriteOutcome::Success
                            }
                            Err(_) => WriteOutcome::Failure(DataAccessError::HardwareFault),
                        }
                    })
                    .collect();
                let resp = WriteResponse { outcomes };
                let mut buf = BytesMut::new();
                encode_confirmed_write_response(invoke_id, &resp, &mut buf);
                return ConfirmedResponse::Response(buf.freeze());
            }
            #[cfg(not(feature = "reporting"))]
            {
                tracing::warn!(
                    invoke_id,
                    "write: data sets are not served in a build without reporting"
                );
                let outcomes: Vec<WriteOutcome> = req
                    .list_of_data
                    .iter()
                    .map(|_| WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported))
                    .collect();
                let resp = WriteResponse { outcomes };
                let mut buf = BytesMut::new();
                encode_confirmed_write_response(invoke_id, &resp, &mut buf);
                return ConfirmedResponse::Response(buf.freeze());
            }
        }
    };

    let outcomes: Vec<WriteOutcome> = entries
        .iter()
        .zip(req.list_of_data.iter())
        .map(|(entry, data)| {
            // Writes targeting an individual array element are not supported
            // yet: the data model does not materialize per-element storage,
            // so silently overwriting the shared template would corrupt
            // every other element.
            if entry.alt_access.is_some() {
                tracing::warn!(
                    "Write with AlternateAccess targets per-element storage which is not yet \
                     materialized; rejecting with ObjectAccessUnsupported"
                );
                return WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported);
            }
            handle_write_with_routing(
                ied_model,
                mms_model,
                policies,
                #[cfg(feature = "control")]
                control_objects,
                #[cfg(feature = "reporting")]
                reporting_engine,
                handler_registry,
                #[cfg(feature = "setting-groups")]
                setting_groups,
                #[cfg(feature = "goose-mapping")]
                gocb_registry,
                conn_id,
                &entry.name,
                data,
            )
        })
        .collect();

    let resp = WriteResponse { outcomes };
    let mut buf = BytesMut::new();
    encode_confirmed_write_response(invoke_id, &resp, &mut buf);
    ConfirmedResponse::Response(buf.freeze())
}

/// Dispatches a Write request (`0xa5`) in a build with no routed subsystems.
///
/// Each entry of a variable list goes through the standard write, which refuses
/// every functional constraint that belongs to a dedicated service. A data set
/// name has no registry to resolve against, so every entry is refused with
/// `ObjectAccessUnsupported`.
#[cfg(not(any(
    feature = "reporting",
    feature = "control",
    feature = "setting-groups",
    feature = "goose-mapping"
)))]
fn dispatch_write(
    invoke_id: u32,
    body: &Bytes,
    ied_model: &IedModel,
    mms_model: &MmsDeviceModel,
    policies: &WriteAccessPolicies,
    handler_registry: &HandlerRegistry,
    conn_id: u64,
) -> ConfirmedResponse {
    let req = match WriteRequest::decode(body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(invoke_id, error = %e, "write request failed to decode, answering confirmed-error");
            return make_confirmed_error(invoke_id, ErrorClass::Access(0));
        }
    };
    let entries = match &req.variable_access_spec {
        iec61850_mms::mms::pdu::common::VariableAccessSpecification::ListOfVariable(v) => v.clone(),
        iec61850_mms::mms::pdu::common::VariableAccessSpecification::VariableListName(_) => {
            tracing::warn!(invoke_id, "write: data sets are not served in this build");
            let outcomes: Vec<WriteOutcome> = req
                .list_of_data
                .iter()
                .map(|_| WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported))
                .collect();
            let resp = WriteResponse { outcomes };
            let mut buf = BytesMut::new();
            encode_confirmed_write_response(invoke_id, &resp, &mut buf);
            return ConfirmedResponse::Response(buf.freeze());
        }
    };
    let outcomes: Vec<WriteOutcome> = entries
        .iter()
        .zip(req.list_of_data.iter())
        .map(|(entry, data)| {
            if entry.alt_access.is_some() {
                return WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported);
            }
            handle_single_write(
                ied_model,
                mms_model,
                policies,
                Some(handler_registry),
                conn_id,
                &entry.name,
                data,
            )
        })
        .collect();
    let resp = WriteResponse { outcomes };
    let mut buf = BytesMut::new();
    encode_confirmed_write_response(invoke_id, &resp, &mut buf);
    ConfirmedResponse::Response(buf.freeze())
}

/// Dispatches an Identify request (`0x82`), per IEC 61850-8-1.
///
/// The response is encoded as:
/// ```text
/// 0xa1 <len>             ConfirmedResponsePdu [1] IMPLICIT
///   0x02 <len> <id>      invokeID UNIVERSAL Integer
///   0xa2 <len>           identify [2] IMPLICIT (CONSTRUCTED)
///     0x80 <len> <vendor>    vendorName [0] IMPLICIT VisibleString
///     0x81 <len> <model>     modelName [1] IMPLICIT VisibleString
///     0x82 <len> <revision>  revision [2] IMPLICIT VisibleString
/// ```
fn dispatch_identify(invoke_id: u32, ident: &IdentificationStrings) -> ConfirmedResponse {
    let id_bytes = ber_encode_u32(invoke_id);

    let mut identify_body = BytesMut::new();
    encode_tlv_visible_string(0x80, ident.vendor_name.as_bytes(), &mut identify_body);
    encode_tlv_visible_string(0x81, ident.model_name.as_bytes(), &mut identify_body);
    encode_tlv_visible_string(0x82, ident.revision.as_bytes(), &mut identify_body);

    let mut inner = BytesMut::new();
    inner.extend_from_slice(&[0x02]);
    ber_encode_length(id_bytes.len(), &mut inner);
    inner.extend_from_slice(&id_bytes);

    inner.extend_from_slice(&[0xa2]);
    ber_encode_length(identify_body.len(), &mut inner);
    inner.extend_from_slice(&identify_body);

    let mut buf = BytesMut::new();
    buf.extend_from_slice(&[0xa1]);
    ber_encode_length(inner.len(), &mut buf);
    buf.extend_from_slice(&inner);

    ConfirmedResponse::Response(buf.freeze())
}

// ─────────────────────────────────────────────────────────────────────────────
// Report control block routing, functional constraints RP and BR
// ─────────────────────────────────────────────────────────────────────────────

/// A report control block named by an object name.
///
/// `field` is `None` when the name selects the whole control block structure
/// (`<LN>$RP$<rcb>`) and `Some` when it selects one field
/// (`<LN>$RP$<rcb>$<field>`).
///
/// `is_buffered` distinguishes a buffered control block under BR from an
/// unbuffered one under RP. The distinction matters because the buffered path
/// must first confirm that the block exists, so that a missing block answers
/// object-non-existent while an existing block whose field is not yet served
/// answers object-access-unsupported.
#[cfg(feature = "reporting")]
struct RcbTarget<'a> {
    domain: &'a str,
    mms_path: String,
    field: Option<crate::reporting::service::RcbField>,
    is_buffered: bool,
}

/// Parses a domain-specific object name as a report control block target.
///
/// Three segments (`<LN>$RP$<rcb>`) select the whole structure, which can only
/// be read; four (`<LN>$RP$<rcb>$<field>`) select one field, which can be read
/// or written. `None` means the name is not a control block path and the caller
/// continues with its other routes.
#[cfg(feature = "reporting")]
fn extract_rcb_target(name: &iec61850_mms::mms::pdu::common::ObjectName) -> Option<RcbTarget<'_>> {
    use iec61850_mms::mms::pdu::common::ObjectName;
    let (domain, item_id) = match name {
        ObjectName::DomainSpecific { domain_id, item_id } => (domain_id.as_str(), item_id.as_str()),
        _ => return None,
    };
    let parts: Vec<&str> = item_id.split('$').collect();
    if parts.len() < 3 || parts.len() > 4 {
        return None;
    }
    let fc_str = parts[1];
    if fc_str != "RP" && fc_str != "BR" {
        return None;
    }
    let ln_name = parts[0];
    let rcb_name = parts[2];
    // The path keeps the original constraint name, since the engine holds
    // buffered and unbuffered control blocks in separate tables.
    let mms_path = format!("{}/{ln_name}${fc_str}${rcb_name}", domain);
    let field = if parts.len() == 4 {
        Some(crate::reporting::service::RcbField::from_name(parts[3]))
    } else {
        None
    };
    Some(RcbTarget {
        domain,
        mms_path,
        field,
        is_buffered: fc_str == "BR",
    })
}

/// Reads every field of a report control block into one structure.
///
/// The members appear in the fixed order the control block declares in
/// IEC 61850-7-2 §15.
#[cfg(feature = "reporting")]
fn read_rcb_structure(engine: &Arc<Mutex<ReportingEngine>>, mms_path: &str) -> AccessResult {
    use crate::reporting::service::{handle_get_rcb_field, RcbField};
    use iec61850_mms::mms::pdu::common::{AccessResult, MmsData};

    // Field order of an unbuffered control block, IEC 61850-8-1 Table 30.
    let fields = [
        RcbField::RptId,
        RcbField::RptEna,
        RcbField::Resv,
        RcbField::DatSet,
        RcbField::ConfRev,
        RcbField::OptFlds,
        RcbField::BufTm,
        RcbField::SqNum,
        RcbField::TrgOps,
        RcbField::IntgPd,
        RcbField::Gi,
        RcbField::Owner,
    ];

    // Existence is checked once up front, so the structure is never returned
    // half-populated.
    {
        let eng = match engine.lock() {
            Ok(e) => e,
            Err(_) => {
                tracing::warn!(
                    mms_path,
                    "read: the reporting engine lock is unavailable, answering hardware-fault"
                );
                return AccessResult::Failure(DataAccessError::HardwareFault);
            }
        };
        if eng.get_rcb(mms_path).is_none() {
            tracing::warn!(
                mms_path,
                "read: no such report control block, answering object-non-existent"
            );
            return AccessResult::Failure(DataAccessError::ObjectNonExistent);
        }
    }

    let mut data_vec: Vec<MmsData> = Vec::with_capacity(fields.len());
    for field in &fields {
        match handle_get_rcb_field(engine, mms_path, field.clone()) {
            Some(AccessResult::Success(d)) => data_vec.push(d),
            Some(AccessResult::Failure(e)) => {
                tracing::warn!(
                    mms_path,
                    field = field.as_str(),
                    ?e,
                    "read: a report control block field could not be read"
                );
                return AccessResult::Failure(e);
            }
            None => {
                tracing::warn!(
                    mms_path,
                    field = field.as_str(),
                    "read: a report control block field has no value"
                );
                return AccessResult::Failure(DataAccessError::ObjectNonExistent);
            }
        }
    }
    AccessResult::Success(MmsData::Structure(data_vec))
}

/// The log control block attributes this server serves on a Read, in the order
/// IEC 61850-7-2 declares them.
///
/// The nine attributes of a log control block are LogEna, LogRef, DatSet,
/// OldEntrTm, NewEntrTm, OldEntr, NewEntr, TrgOps and IntgPd. The four omitted
/// here are properties of the journal behind the control block, and the
/// `LogStorage` trait exposes no accessor for them, so they answer
/// object-access-unsupported the way the unserved buffered report control block
/// fields do.
#[cfg(feature = "logging")]
const LCB_SERVED_FIELDS: [&str; 5] = ["LogEna", "LogRef", "DatSet", "TrgOps", "IntgPd"];

/// The log control block attributes IEC 61850-7-2 declares that this server
/// does not serve. They exist, so they answer object-access-unsupported rather
/// than object-non-existent.
#[cfg(feature = "logging")]
const LCB_UNSERVED_FIELDS: [&str; 4] = ["OldEntrTm", "NewEntrTm", "OldEntr", "NewEntr"];

/// Splits a Read object name into the log control registry key and the optional
/// attribute name, for an item id of `<LN>$LG$<name>` or `<LN>$LG$<name>$<attr>`.
///
/// The returned item is the key the registry holds a control block under, which
/// is also the name GetNameList reports, so a name a client browsed is a name
/// this resolves. `None` means the name is not a log control block path and the
/// caller routes it onward.
#[cfg(feature = "logging")]
fn extract_lcb_target(
    name: &iec61850_mms::mms::pdu::common::ObjectName,
) -> Option<(&str, String, Option<&str>)> {
    use iec61850_mms::mms::pdu::common::ObjectName;
    let ObjectName::DomainSpecific { domain_id, item_id } = name else {
        return None;
    };
    let parts: Vec<&str> = item_id.split('$').collect();
    if !(3..=4).contains(&parts.len())
        || parts[1] != "LG"
        || parts[0].is_empty()
        || parts[2].is_empty()
    {
        return None;
    }
    let item = format!("{}$LG${}", parts[0], parts[2]);
    Some((domain_id.as_str(), item, parts.get(3).copied()))
}

/// Reads one attribute out of the state of a log control block.
///
/// `domain` and `ln` supply the default LogRef, `<LD>/<LN>$GeneralLog`, which
/// applies when the control block configures none. The logical device is part
/// of it because a LogRef is an MMS path a client hands straight to ReadJournal,
/// which resolves it by domain and item. `None` means the attribute is not one
/// of [`LCB_SERVED_FIELDS`].
#[cfg(feature = "logging")]
fn lcb_field_value(
    state: &crate::logging::lcb::LogControlState,
    domain: &str,
    ln: &str,
    field: &str,
) -> Option<iec61850_mms::mms::pdu::common::MmsData> {
    use iec61850_mms::mms::pdu::common::MmsData;
    Some(match field {
        "LogEna" => MmsData::Boolean(matches!(state.log_ena, crate::logging::LogState::Enabled)),
        "LogRef" => MmsData::VisibleString(
            state
                .log_ref
                .clone()
                .unwrap_or_else(|| format!("{domain}/{ln}$GeneralLog")),
        ),
        "DatSet" => MmsData::VisibleString(state.data_set.clone().unwrap_or_default()),
        "TrgOps" => {
            let wire = state.trg_ops.to_ber_bit_string();
            MmsData::BitString {
                padding: wire[0],
                data: wire[1..].to_vec(),
            }
        }
        "IntgPd" => MmsData::Unsigned(state.intg_period_ms as u64),
        _ => return None,
    })
}

/// Converts a decoded wire value into a report control block write value.
///
/// A bit string is passed on with its padding byte restored at the front of the
/// buffer, which is the layout the option-flag and trigger-option decoders
/// expect. `None` means the value has no control block representation.
#[cfg(feature = "reporting")]
fn mms_data_to_rcb_write_value(
    data: &iec61850_mms::mms::pdu::common::MmsData,
) -> Option<crate::reporting::service::RcbWriteValue> {
    use crate::reporting::service::RcbWriteValue;
    use iec61850_mms::mms::pdu::common::MmsData;
    match data {
        MmsData::Boolean(b) => Some(RcbWriteValue::Bool(*b)),
        MmsData::Unsigned(u) => {
            // No unsigned control block field is wider than 32 bits.
            Some(RcbWriteValue::Unsigned(*u as u32))
        }
        MmsData::VisibleString(s) => Some(RcbWriteValue::VisibleString(s.clone())),
        MmsData::BitString { padding, data } => {
            // The decoders expect [padding_byte, data_bytes...].
            let mut bytes = Vec::with_capacity(1 + data.len());
            bytes.push(*padding);
            bytes.extend_from_slice(data);
            Some(RcbWriteValue::BitString(bytes))
        }
        MmsData::OctetString(b) => Some(RcbWriteValue::OctetString(b.clone())),
        _ => None,
    }
}

/// Routes one read entry: RP and BR to the reporting engine, CO to the control
/// objects, and everything else to the standard read.
///
/// `remaining_budget` is the shared PDU budget, which matters only to the
/// standard read: the control block and control object paths answer with single
/// short values.
#[cfg(any(
    feature = "reporting",
    feature = "control",
    feature = "setting-groups",
    feature = "goose-mapping",
    feature = "logging"
))]
#[allow(clippy::too_many_arguments)]
fn handle_read_with_routing(
    ied_model: &IedModel,
    mms_model: &MmsDeviceModel,
    #[cfg(feature = "control")] control_objects: &ControlObjectsRegistry,
    #[cfg(feature = "reporting")] reporting_engine: &Arc<Mutex<ReportingEngine>>,
    handler_registry: &HandlerRegistry,
    #[cfg(feature = "setting-groups")] setting_groups: &crate::setting_groups::SettingGroupRegistry,
    #[cfg(feature = "goose-mapping")] gocb_registry: &GoCBRegistry,
    #[cfg(feature = "logging")] log_controls: &LogControlRegistry,
    conn_id: u64,
    name: &iec61850_mms::mms::pdu::common::ObjectName,
    alt_access: Option<&iec61850_mms::mms::pdu::common::AlternateAccess>,
    remaining_budget: Option<usize>,
) -> ReadRoutingOutcome {
    #[cfg(feature = "reporting")]
    use crate::reporting::service::handle_get_rcb_field;

    // The GOOSE control block path is tried before the setting group and
    // report control block routes.
    #[cfg(feature = "goose-mapping")]
    {
        if let Some(result) = try_read_gocb(gocb_registry, name, alt_access) {
            return ReadRoutingOutcome::Result(result);
        }
    }

    // ── Setting group control block ─────────────────────────────────────
    #[cfg(feature = "setting-groups")]
    {
        if let Some((domain, ln, field)) = crate::setting_groups::extract_sgcb_target(name) {
            if alt_access.is_some() {
                tracing::warn!(
                    domain,
                    ln,
                    "read of a setting group control block with alternate-access: control blocks are not arrays, rejecting"
                );
                return ReadRoutingOutcome::Result(AccessResult::Failure(
                    DataAccessError::TypeInconsistent,
                ));
            }
            let result = crate::setting_groups::handle_sgcb_read(setting_groups, domain, ln, field);
            // A setting group control block is at most a few dozen bytes, so it
            // is not charged here; the caller still counts it into the response.
            return ReadRoutingOutcome::Result(result);
        }
    }

    // ── Report control block ────────────────────────────────────────────
    #[cfg(feature = "reporting")]
    {
        if let Some(target) = extract_rcb_target(name) {
            if alt_access.is_some() {
                tracing::warn!(
                    domain = target.domain,
                    mms_path = target.mms_path,
                    "read of a report control block with alternate-access: control blocks are not arrays, rejecting"
                );
                return ReadRoutingOutcome::Result(AccessResult::Failure(
                    DataAccessError::TypeInconsistent,
                ));
            }
            // A buffered control block is read one attribute at a time. A name
            // that selects the whole block, and the URCB-only Resv, answer
            // object-access-unsupported once the block is known to exist.
            if target.is_buffered {
                let exists = {
                    let Ok(eng) = reporting_engine.lock() else {
                        return ReadRoutingOutcome::Result(AccessResult::Failure(
                            DataAccessError::HardwareFault,
                        ));
                    };
                    eng.get_brcb(&target.mms_path).is_some()
                };
                if !exists {
                    tracing::warn!(
                        domain = target.domain,
                        mms_path = target.mms_path,
                        "read: no such buffered report control block, answering object-non-existent"
                    );
                    return ReadRoutingOutcome::Result(AccessResult::Failure(
                        DataAccessError::ObjectNonExistent,
                    ));
                }
                if let Some(field) = target.field.clone() {
                    use crate::reporting::service::handle_get_brcb_field;
                    if let Some(r) =
                        handle_get_brcb_field(reporting_engine, &target.mms_path, field)
                    {
                        return ReadRoutingOutcome::Result(r);
                    }
                }
                let field_name = target
                    .field
                    .as_ref()
                    .map(crate::reporting::service::RcbField::as_str);
                tracing::warn!(
                    domain = target.domain,
                    mms_path = target.mms_path,
                    field = ?field_name,
                    "read: a buffered report control block is read one attribute at a time, and Resv is unbuffered-only"
                );
                return ReadRoutingOutcome::Result(AccessResult::Failure(
                    DataAccessError::ObjectAccessUnsupported,
                ));
            }

            let r = match target.field {
                None => read_rcb_structure(reporting_engine, &target.mms_path),
                Some(field) => {
                    match handle_get_rcb_field(reporting_engine, &target.mms_path, field) {
                        Some(result) => result,
                        None => {
                            tracing::warn!(
                                domain = target.domain,
                                mms_path = target.mms_path,
                                "read: unknown report control block field, answering object-non-existent"
                            );
                            AccessResult::Failure(DataAccessError::ObjectNonExistent)
                        }
                    }
                }
            };
            return ReadRoutingOutcome::Result(r);
        }
    }

    // ── Log control block ───────────────────────────────────────────
    #[cfg(feature = "logging")]
    {
        if let Some((domain, item, field)) = extract_lcb_target(name) {
            if alt_access.is_some() {
                tracing::warn!(
                    domain,
                    item,
                    "read of a log control block with alternate-access: control blocks are not arrays, rejecting"
                );
                return ReadRoutingOutcome::Result(AccessResult::Failure(
                    DataAccessError::TypeInconsistent,
                ));
            }
            let lc = match log_controls.read() {
                Ok(g) => g.get(&(domain.to_string(), item.clone())).cloned(),
                Err(_) => {
                    tracing::warn!(
                        domain,
                        item,
                        "read: the log control registry lock is unavailable, answering hardware-fault"
                    );
                    return ReadRoutingOutcome::Result(AccessResult::Failure(
                        DataAccessError::HardwareFault,
                    ));
                }
            };
            let Some(lc) = lc else {
                tracing::warn!(
                    domain,
                    item,
                    "read: no such log control block, answering object-non-existent"
                );
                return ReadRoutingOutcome::Result(AccessResult::Failure(
                    DataAccessError::ObjectNonExistent,
                ));
            };
            let Ok(state) = lc.state.lock() else {
                tracing::warn!(
                    domain,
                    item,
                    "read: the log control block state is unavailable, answering hardware-fault"
                );
                return ReadRoutingOutcome::Result(AccessResult::Failure(
                    DataAccessError::HardwareFault,
                ));
            };
            let ln = item.split('$').next().unwrap_or_default();
            let r = match field {
                // A whole-block read answers the served attributes in declared
                // order, mirroring the report control block structure read.
                None => AccessResult::Success(iec61850_mms::mms::pdu::common::MmsData::Structure(
                    LCB_SERVED_FIELDS
                        .iter()
                        .filter_map(|f| lcb_field_value(&state, domain, ln, f))
                        .collect(),
                )),
                Some(f) => match lcb_field_value(&state, domain, ln, f) {
                    Some(d) => AccessResult::Success(d),
                    None if LCB_UNSERVED_FIELDS.contains(&f) => {
                        tracing::warn!(
                            domain,
                            item,
                            field = f,
                            "read: this log control block attribute is not served, answering object-access-unsupported"
                        );
                        AccessResult::Failure(DataAccessError::ObjectAccessUnsupported)
                    }
                    None => {
                        tracing::warn!(
                            domain,
                            item,
                            field = f,
                            "read: unknown log control block attribute, answering object-non-existent"
                        );
                        AccessResult::Failure(DataAccessError::ObjectNonExistent)
                    }
                },
            };
            return ReadRoutingOutcome::Result(r);
        }
    }

    // ── Control objects, then the standard read ─────────────────────────
    handle_read_with_co_routing(
        ied_model,
        mms_model,
        #[cfg(feature = "control")]
        control_objects,
        handler_registry,
        conn_id,
        name,
        alt_access,
        remaining_budget,
    )
}

/// Routes one write entry: the setting group control block, then the report
/// control block, then the control objects, and finally the standard write.
///
/// A route whose sub-feature is off is skipped, and the entry reaches the
/// control-object route, which itself falls back to the standard write.
#[cfg(any(
    feature = "reporting",
    feature = "control",
    feature = "setting-groups",
    feature = "goose-mapping"
))]
#[allow(clippy::too_many_arguments)]
fn handle_write_with_routing(
    ied_model: &IedModel,
    mms_model: &MmsDeviceModel,
    policies: &WriteAccessPolicies,
    #[cfg(feature = "control")] control_objects: &ControlObjectsRegistry,
    #[cfg(feature = "reporting")] reporting_engine: &Arc<Mutex<ReportingEngine>>,
    handler_registry: &HandlerRegistry,
    #[cfg(feature = "setting-groups")] setting_groups: &crate::setting_groups::SettingGroupRegistry,
    #[cfg(feature = "goose-mapping")] gocb_registry: &GoCBRegistry,
    conn_id: u64,
    name: &iec61850_mms::mms::pdu::common::ObjectName,
    data: &iec61850_mms::mms::pdu::common::MmsData,
) -> WriteOutcome {
    // The GOOSE control block path is tried before the setting group and
    // report control block routes.
    #[cfg(feature = "goose-mapping")]
    {
        if let Some(outcome) = try_write_gocb(gocb_registry, name, data) {
            return outcome;
        }
    }

    // ── Setting group control block ─────────────────────────────────────
    #[cfg(feature = "setting-groups")]
    {
        if let Some((domain, ln, field)) = crate::setting_groups::extract_sgcb_target(name) {
            return crate::setting_groups::handle_sgcb_write(
                setting_groups,
                domain,
                ln,
                field,
                data,
                conn_id,
            );
        }
    }

    // ── Report control block ────────────────────────────────────────────
    #[cfg(feature = "reporting")]
    {
        use crate::reporting::service::handle_set_rcb_field;
        if let Some(target) = extract_rcb_target(name) {
            // A buffered control block is written one attribute at a time. A
            // name that selects the whole block, and the URCB-only Resv, answer
            // object-access-unsupported once the block is known to exist.
            if target.is_buffered {
                let exists = {
                    let Ok(eng) = reporting_engine.lock() else {
                        return WriteOutcome::Failure(DataAccessError::HardwareFault);
                    };
                    eng.get_brcb(&target.mms_path).is_some()
                };
                if !exists {
                    tracing::warn!(
                        domain = target.domain,
                        mms_path = target.mms_path,
                        "write: no such buffered report control block, answering object-non-existent"
                    );
                    return WriteOutcome::Failure(DataAccessError::ObjectNonExistent);
                }
                if let Some(field) = target.field.clone() {
                    use crate::reporting::service::handle_set_brcb_field;
                    let rcb_value = match mms_data_to_rcb_write_value(data) {
                        Some(v) => v,
                        None => {
                            tracing::warn!(
                                domain = target.domain,
                                mms_path = target.mms_path,
                                field = field.as_str(),
                                "write: the value type has no buffered report control block representation, answering type-inconsistent"
                            );
                            return WriteOutcome::Failure(DataAccessError::TypeInconsistent);
                        }
                    };
                    if let Some(res) =
                        handle_set_brcb_field(reporting_engine, &target.mms_path, field, rcb_value)
                    {
                        return match res {
                            Ok(()) => WriteOutcome::Success,
                            Err(e) => WriteOutcome::Failure(e),
                        };
                    }
                }
                let field_name = target
                    .field
                    .as_ref()
                    .map(crate::reporting::service::RcbField::as_str);
                tracing::warn!(
                    domain = target.domain,
                    mms_path = target.mms_path,
                    field = ?field_name,
                    "write: a buffered report control block is written one attribute at a time, and Resv is unbuffered-only"
                );
                return WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported);
            }

            let field = match target.field {
                Some(f) => f,
                None => {
                    tracing::warn!(
                        domain = target.domain,
                        mms_path = target.mms_path,
                        "write: a report control block is written one field at a time, answering object-access-unsupported"
                    );
                    return WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported);
                }
            };

            let rcb_value = match mms_data_to_rcb_write_value(data) {
                Some(v) => v,
                None => {
                    tracing::warn!(
                        domain = target.domain,
                        mms_path = target.mms_path,
                        field = field.as_str(),
                        "write: the value type has no report control block representation, answering type-inconsistent"
                    );
                    return WriteOutcome::Failure(DataAccessError::TypeInconsistent);
                }
            };

            return match handle_set_rcb_field(
                reporting_engine,
                &target.mms_path,
                field,
                rcb_value,
                conn_id,
            ) {
                Ok(()) => WriteOutcome::Success,
                Err(e) => WriteOutcome::Failure(e),
            };
        }
    }

    // ── Control objects, then the standard write ────────────────────────
    handle_write_with_co_routing(
        ied_model,
        mms_model,
        policies,
        #[cfg(feature = "control")]
        control_objects,
        handler_registry,
        #[cfg(feature = "setting-groups")]
        Some(setting_groups),
        conn_id,
        name,
        data,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Control object routing, functional constraint CO
// ─────────────────────────────────────────────────────────────────────────────

/// Parses an object name of the form `LN$CO$DO$Attr` into its parts.
///
/// `None` means the name is not a control path and the caller continues with
/// the standard read or write.
#[cfg(feature = "control")]
fn extract_co_target(
    name: &iec61850_mms::mms::pdu::common::ObjectName,
) -> Option<(&str, &str, &str, crate::control::CoAttr)> {
    use iec61850_mms::mms::pdu::common::ObjectName;
    let (domain, item_id) = match name {
        ObjectName::DomainSpecific { domain_id, item_id } => (domain_id.as_str(), item_id.as_str()),
        _ => return None,
    };
    let parts: Vec<&str> = item_id.split('$').collect();
    if parts.len() != 4 || parts[1] != "CO" {
        return None;
    }
    let ln_name = parts[0];
    let do_name = parts[2];
    let attr = match parts[3] {
        "SBO" => crate::control::CoAttr::Sbo,
        "SBOw" => crate::control::CoAttr::SBOw,
        "Oper" => crate::control::CoAttr::Oper,
        "Cancel" => crate::control::CoAttr::Cancel,
        _ => return None,
    };
    Some((domain, ln_name, do_name, attr))
}

/// Routes a read: a control object attribute `SBO` performs a select, and
/// everything else goes through the standard read.
///
/// On the standard path the model is consulted first. A path that does not
/// exist answers `ObjectNonExistent` immediately, so that a registered handler
/// can never make an absent object appear to exist. Otherwise the read handler
/// registry decides: an error replaces the outcome, a cached value replaces the
/// model snapshot, and a miss or an absent handler keeps the snapshot.
///
/// With `ignore_read_access` set, the registry is skipped and the model
/// snapshot is returned as is.
///
/// The standard path reads under the shared PDU budget and answers
/// [`ReadRoutingOutcome::OverBudget`] when expansion no longer fits, which the
/// caller turns into a ServiceError for the whole request.
#[cfg(any(
    feature = "reporting",
    feature = "control",
    feature = "setting-groups",
    feature = "goose-mapping",
    feature = "logging"
))]
#[allow(clippy::too_many_arguments)]
fn handle_read_with_co_routing(
    ied_model: &IedModel,
    mms_model: &MmsDeviceModel,
    #[cfg(feature = "control")] control_objects: &ControlObjectsRegistry,
    handler_registry: &HandlerRegistry,
    conn_id: u64,
    name: &iec61850_mms::mms::pdu::common::ObjectName,
    alt_access: Option<&iec61850_mms::mms::pdu::common::AlternateAccess>,
    remaining_budget: Option<usize>,
) -> ReadRoutingOutcome {
    use crate::service::read::{handle_single_read_with_budget, LookupResult};

    #[cfg(feature = "control")]
    {
        use crate::control::{handle_read_sbo, CoAttr};
        use iec61850_mms::mms::pdu::common::MmsData;

        if let Some((domain, ln, do_name, attr)) = extract_co_target(name) {
            if alt_access.is_some() {
                tracing::warn!(
                    domain,
                    ln,
                    do_name,
                    "read of a control object with alternate-access: control attributes are scalar, rejecting"
                );
                return ReadRoutingOutcome::Result(AccessResult::Failure(
                    DataAccessError::TypeInconsistent,
                ));
            }
            let r = match attr {
                CoAttr::Sbo => {
                    let entry = match control_objects.lookup(domain, ln, do_name) {
                        Some(e) => e,
                        None => {
                            tracing::warn!(
                                domain,
                                ln,
                                do_name,
                                "read: no such control object, answering object-non-existent"
                            );
                            return ReadRoutingOutcome::Result(AccessResult::Failure(
                                DataAccessError::ObjectNonExistent,
                            ));
                        }
                    };
                    let result =
                        handle_read_sbo(&entry.object, conn_id, entry.check_handler.as_ref());
                    match result {
                        Some(obj_ref) => AccessResult::Success(MmsData::VisibleString(obj_ref)),
                        None => {
                            // A select that yields no object reference answers
                            // with an empty string, not an error.
                            AccessResult::Success(MmsData::VisibleString(String::new()))
                        }
                    }
                }
                CoAttr::SBOw | CoAttr::Oper | CoAttr::Cancel => {
                    // These attributes are issued as writes; a read of them is
                    // a client error.
                    tracing::warn!(
                        domain,
                        ln,
                        do_name,
                        ?attr,
                        "read: SBOw, Oper and Cancel are written, not read, answering object-access-unsupported"
                    );
                    AccessResult::Failure(DataAccessError::ObjectAccessUnsupported)
                }
            };
            return ReadRoutingOutcome::Result(r);
        }
    }

    let baseline = match handle_single_read_with_budget(
        ied_model,
        mms_model,
        name,
        alt_access,
        remaining_budget,
    ) {
        LookupResult::Result(r) => r,
        LookupResult::OverBudget => return ReadRoutingOutcome::OverBudget,
    };

    // A path that does not exist wins over any handler, so that a handler can
    // never make an absent object appear to exist.
    if matches!(
        baseline,
        AccessResult::Failure(DataAccessError::ObjectNonExistent)
    ) {
        return ReadRoutingOutcome::Result(baseline);
    }

    if handler_registry.ignore_read_access() {
        return ReadRoutingOutcome::Result(baseline);
    }

    // An alternate-access read bypasses the handler registry: a handler returns
    // a whole-attribute value without the model template, leaving no way to
    // apply a component path to its output. The baseline above already resolved
    // the selector against the model-typed attribute, so it is used directly.
    if alt_access.is_some() {
        return ReadRoutingOutcome::Result(baseline);
    }

    let canonical_path = match read_path_canonical_from_object_name(name) {
        Some(p) => p,
        // Not a canonicalizable domain-specific path, so out of registry scope.
        None => return ReadRoutingOutcome::Result(baseline),
    };
    let handler = match handler_registry.lookup_read(&canonical_path) {
        Some(h) => h,
        None => return ReadRoutingOutcome::Result(baseline),
    };
    let fc = match fc_from_canonical_path(&canonical_path) {
        Some(f) => f,
        None => return ReadRoutingOutcome::Result(baseline),
    };
    let ctx = ReadContext {
        path: &canonical_path,
        fc,
        conn_id,
    };
    let r = match handler.read(&ctx) {
        ReadOutcome::CacheHit(value) => {
            AccessResult::Success(crate::service::convert::mms_value_to_mms_data(&value))
        }
        ReadOutcome::CacheMiss => baseline,
        ReadOutcome::Error(e) => {
            tracing::warn!(
                path = %canonical_path,
                ?e,
                "read: the read handler replaced the model value with an error"
            );
            AccessResult::Failure(e)
        }
    };
    ReadRoutingOutcome::Result(r)
}

/// Canonicalizes a domain-specific object name into the attribute path the
/// handler registry is keyed by.
///
/// `None` means the name is not domain-specific or its item id is malformed,
/// which the caller treats as out of registry scope.
#[cfg(any(
    feature = "reporting",
    feature = "control",
    feature = "setting-groups",
    feature = "goose-mapping",
    feature = "logging"
))]
fn read_path_canonical_from_object_name(
    name: &iec61850_mms::mms::pdu::common::ObjectName,
) -> Option<String> {
    use iec61850_mms::mms::pdu::common::ObjectName;
    let item_id = match name {
        ObjectName::DomainSpecific { item_id, .. } => item_id.as_str(),
        _ => return None,
    };
    canonicalize_attr_path(item_id).ok()
}

/// Routes a write: functional constraint CO to the control service, everything
/// else to the standard write.
///
/// The control service is asynchronous while this path is synchronous, so it
/// awaits through `tokio::task::block_in_place` and
/// `Handle::current().block_on`, which requires a multi-threaded runtime.
#[cfg(any(
    feature = "reporting",
    feature = "control",
    feature = "setting-groups",
    feature = "goose-mapping"
))]
#[allow(clippy::too_many_arguments)]
fn handle_write_with_co_routing(
    ied_model: &IedModel,
    mms_model: &MmsDeviceModel,
    policies: &WriteAccessPolicies,
    #[cfg(feature = "control")] control_objects: &ControlObjectsRegistry,
    handler_registry: &HandlerRegistry,
    #[cfg(feature = "setting-groups")] setting_groups: Option<
        &crate::setting_groups::SettingGroupRegistry,
    >,
    conn_id: u64,
    name: &iec61850_mms::mms::pdu::common::ObjectName,
    data: &iec61850_mms::mms::pdu::common::MmsData,
) -> WriteOutcome {
    #[cfg(feature = "control")]
    {
        use crate::control::{handle_cancel, handle_operate, handle_sbow, CoAttr, ServiceResult};
        use crate::service::convert::mms_data_to_mms_value;

        if let Some((domain, ln, do_name, attr)) = extract_co_target(name) {
            let entry = match control_objects.lookup(domain, ln, do_name) {
                Some(e) => e,
                None => {
                    tracing::warn!(
                        domain,
                        ln,
                        do_name,
                        "write: no such control object, answering object-non-existent"
                    );
                    return WriteOutcome::Failure(DataAccessError::ObjectNonExistent);
                }
            };

            let value = mms_data_to_mms_value(data);

            let service_result = match attr {
                CoAttr::Sbo => {
                    // A select through SBO is issued as a read.
                    tracing::warn!(
                        domain,
                        ln,
                        do_name,
                        "write: SBO is read, not written, answering object-access-unsupported"
                    );
                    return WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported);
                }
                CoAttr::SBOw => block_on_async(async {
                    handle_sbow(&entry.object, conn_id, &value, entry.check_handler.as_ref()).await
                }),
                CoAttr::Oper => block_on_async(async {
                    handle_operate(
                        &entry.object,
                        conn_id,
                        &value,
                        entry.check_handler.as_ref(),
                        entry.wait_handler.as_ref(),
                        entry.operate_handler.as_ref(),
                        control_objects.ct_sink().as_ref(),
                    )
                    .await
                }),
                CoAttr::Cancel => handle_cancel(&entry.object, conn_id, &value),
            };

            return match service_result {
                ServiceResult::Success => WriteOutcome::Success,
                ServiceResult::Failure(cause) => {
                    // The failure is reported in the WriteResponse; a
                    // LastApplError report is not pushed from here.
                    tracing::warn!(
                        domain,
                        ln,
                        do_name,
                        ?attr,
                        ?cause,
                        "write: the control service refused the command"
                    );
                    let err = map_add_cause_to_data_access_error(cause);
                    WriteOutcome::Failure(err)
                }
            };
        }
    }

    handle_single_write(
        ied_model,
        mms_model,
        policies,
        Some(handler_registry),
        #[cfg(feature = "setting-groups")]
        setting_groups,
        conn_id,
        name,
        data,
    )
}

/// Maps a control add-cause onto the data access error a client receives, per
/// IEC 61850-7-2 §20.
#[cfg(feature = "control")]
fn map_add_cause_to_data_access_error(cause: crate::control::ControlAddCause) -> DataAccessError {
    use crate::control::ControlAddCause;
    match cause {
        ControlAddCause::NotSupported => DataAccessError::ObjectAccessUnsupported,
        ControlAddCause::ObjectNotSelected => DataAccessError::ObjectAccessDenied,
        ControlAddCause::ObjectAlreadySelected => DataAccessError::ObjectAccessDenied,
        ControlAddCause::LockedByOtherClient => DataAccessError::ObjectAccessDenied,
        ControlAddCause::CommandAlreadyInExecution => DataAccessError::ObjectAccessDenied,
        ControlAddCause::InconsistentParameters => DataAccessError::ObjectAccessDenied,
        ControlAddCause::NoAccessAuthority => DataAccessError::ObjectAccessDenied,
        _ => DataAccessError::ObjectAccessDenied,
    }
}

/// Awaits a future from a synchronous call path.
///
/// `block_in_place` puts the current worker thread into blocking mode, leaving
/// the remaining tasks to the other workers, and `block_on` then drives the
/// future to completion on it.
///
/// # Panics
///
/// Panics when called outside a multi-threaded tokio runtime. The connection
/// handler always runs inside one.
#[cfg(feature = "control")]
fn block_on_async<F: std::future::Future>(fut: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))
}

// ─────────────────────────────────────────────────────────────────────────────
// Encoding helpers
// ─────────────────────────────────────────────────────────────────────────────

fn encode_tlv_visible_string(tag: u8, value: &[u8], buf: &mut BytesMut) {
    buf.extend_from_slice(&[tag]);
    ber_encode_length(value.len(), buf);
    buf.extend_from_slice(value);
}

/// Encodes a BER length, delegating to the single shared implementation.
fn ber_encode_length(len: usize, buf: &mut BytesMut) {
    iec61850_asn1::encode_length(len, buf);
}

/// Encodes an unsigned value as the shortest BER INTEGER content, prefixing
/// `0x00` when the leading bit would otherwise read as a sign bit.
fn ber_encode_u32(val: u32) -> Vec<u8> {
    if val == 0 {
        return vec![0x00];
    }
    let bytes = val.to_be_bytes();
    let mut start = 0usize;
    // Leading zero bytes are dropped, except the one that keeps the value
    // unsigned.
    while start < 3 && bytes[start] == 0x00 && (bytes[start + 1] & 0x80) == 0 {
        start += 1;
    }
    bytes[start..].to_vec()
}

// ─────────────────────────────────────────────────────────────────────────────
// Journal services
// ─────────────────────────────────────────────────────────────────────────────

/// Dispatches a ReadJournal request (`0xbf 0x41`).
///
/// The request names a log control block by domain and item; the range selects
/// either a time window or a cursor position, and the matching entries are
/// encoded into a ReadJournalResponse.
///
/// # Errors
///
/// A request that fails to decode, and a storage backend that fails, both
/// answer with a ConfirmedError of class access; a log control block that is
/// not registered answers object-non-existent.
///
/// Entries are added while they fit the PDU budget. Once one does not, the
/// response stops there and sets `moreFollows`, and the client continues from
/// the entry id and occurrence time of the last entry it received. The budget
/// is the negotiated maximum PDU size less the response frame and the overhead
/// reserve; before negotiation completes it falls back to a hard cap, which
/// keeps the encoded PDU inside the 65535-byte BER length limit. `moreFollows`
/// is always set explicitly, never left absent.
#[cfg(feature = "logging")]
fn dispatch_read_journal(
    invoke_id: u32,
    body: &Bytes,
    log_controls: &LogControlRegistry,
    negotiated_max_pdu_size: Option<u32>,
) -> ConfirmedResponse {
    let req = match ReadJournalRequest::decode(body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                invoke_id,
                error = %e,
                "read-journal request failed to decode, answering confirmed-error"
            );
            return make_confirmed_error(invoke_id, ErrorClass::Access(0));
        }
    };

    let key = (req.domain_id.clone(), req.item_id.clone());
    let lc = match log_controls.read() {
        Ok(g) => g.get(&key).cloned(),
        Err(_) => {
            tracing::warn!(
                invoke_id,
                "read-journal: the log control registry lock is poisoned"
            );
            None
        }
    };
    let Some(lc) = lc else {
        tracing::warn!(
            invoke_id,
            domain = req.domain_id,
            item = req.item_id,
            "read-journal: no such log control block, answering object-non-existent"
        );
        return make_confirmed_error(invoke_id, ErrorClass::Access(10));
    };

    // A log control block with no storage attached yields an empty list.
    let mut visitor = CollectingVisitor::new();
    let query_result = match &req.range {
        JournalRange::TimeRange { start_ms, end_ms } => {
            lc.query_by_time(*start_ms, *end_ms, &mut visitor)
        }
        JournalRange::StartAfter {
            starting_time_ms,
            entry_id,
        } => {
            // An entry id travels as eight big-endian bytes.
            let id = LogEntryId::from_be_bytes(*entry_id);
            lc.query_after(*starting_time_ms, id, &mut visitor)
        }
    };
    if let Err(e) = query_result {
        tracing::warn!(
            invoke_id,
            error = %e,
            "read-journal: the log storage backend failed, answering confirmed-error"
        );
        return make_confirmed_error(invoke_id, ErrorClass::Access(0));
    }

    let budget = read_journal_budget(negotiated_max_pdu_size);
    let baseline = empty_response_baseline();
    let mut accepted: Vec<WireJournalEntry> = Vec::new();
    let mut consumed: usize = 0;
    let mut more_follows = false;

    for entry in visitor.entries.into_iter() {
        let wire = journal_entry_to_wire(entry);
        let entry_size = estimate_entry_wire_size(&wire, baseline);
        if consumed + entry_size > budget {
            // Even a first entry larger than the whole PDU stops here with
            // moreFollows set, so the client never mistakes a truncated result
            // for a complete one.
            tracing::warn!(
                invoke_id,
                budget,
                consumed,
                entry_size,
                accepted = accepted.len(),
                "read-journal: the PDU budget is spent, truncating and setting moreFollows"
            );
            more_follows = true;
            break;
        }
        consumed += entry_size;
        accepted.push(wire);
    }

    let resp = ReadJournalResponse {
        entries: accepted,
        more_follows: Some(more_follows),
    };

    let mut buf = BytesMut::new();
    encode_confirmed_read_journal_response(invoke_id, &resp, &mut buf);
    ConfirmedResponse::Response(buf.freeze())
}

/// Computes the bytes available to journal entries in a ReadJournal response.
///
/// A negotiated size gives that size less the response frame and the overhead
/// reserve. Before negotiation completes the hard cap applies instead, which
/// keeps the encoded PDU inside the 65535-byte BER length limit.
#[cfg(feature = "logging")]
fn read_journal_budget(negotiated_max_pdu_size: Option<u32>) -> usize {
    match negotiated_max_pdu_size {
        Some(n) => (n as usize)
            .saturating_sub(READ_JOURNAL_FRAME_OVERHEAD)
            .saturating_sub(read::PDU_OVERHEAD_RESERVE),
        None => READ_JOURNAL_HARD_CAP_BYTES,
    }
}

/// Bytes a ReadJournalResponse spends outside its list of entries.
///
/// The frame is the outer confirmed-response PDU (`0xa1`), the invoke id, the
/// readJournal tag (`0xbf 0x41`), the list tag (`0xa0`), and the moreFollows
/// flag (`0x81 0x01`), each length estimated in its long form. 32 leaves a
/// margin over the worst case.
#[cfg(feature = "logging")]
const READ_JOURNAL_FRAME_OVERHEAD: usize = 32;

/// Entry budget used before an association has negotiated a maximum PDU size.
///
/// 60000 stays below the 65535-byte BER length limit with about 5 KiB to spare
/// for the COTP, Session, Presentation, and ACSE frames, so the server never
/// builds a response it cannot encode.
#[cfg(feature = "logging")]
const READ_JOURNAL_HARD_CAP_BYTES: usize = 60_000;

/// Measures the encoded size of one journal entry.
///
/// An entry carries a variable-size value, so its size has no closed form; the
/// entry is encoded into a response of its own and the empty-response baseline
/// subtracted. `baseline` comes from [`empty_response_baseline`] so that it is
/// computed once rather than once per entry.
#[cfg(feature = "logging")]
fn estimate_entry_wire_size(entry: &WireJournalEntry, baseline: usize) -> usize {
    let probe = ReadJournalResponse {
        entries: vec![entry.clone()],
        more_follows: None,
    };
    let mut buf = BytesMut::new();
    probe.encode(&mut buf);
    buf.len().saturating_sub(baseline)
}

/// Measures a ReadJournalResponse with no entries and no moreFollows flag, the
/// baseline [`estimate_entry_wire_size`] subtracts.
#[cfg(feature = "logging")]
fn empty_response_baseline() -> usize {
    let empty = ReadJournalResponse {
        entries: vec![],
        more_follows: None,
    };
    let mut buf = BytesMut::new();
    empty.encode(&mut buf);
    buf.len()
}

/// Converts a stored journal entry into its wire representation.
#[cfg(feature = "logging")]
fn journal_entry_to_wire(entry: crate::logging::JournalEntry) -> WireJournalEntry {
    WireJournalEntry {
        entry_id: entry.entry_id.to_be_bytes(),
        occurence_time_ms: entry.time_ms,
        variables: entry
            .variables
            .into_iter()
            .map(|v| WireJournalVariable {
                data_ref: v.data_ref,
                value: crate::service::convert::mms_value_to_mms_data(&v.value),
                reason_code: v.reason_code,
            })
            .collect(),
    }
}

/// Dispatches a WriteJournal request (`0xbf 0x42`), which is answered with
/// `ObjectAccessUnsupported`.
///
/// An explicit access error tells the client that the server knows the service
/// and does not serve it, which is a more useful answer than rejecting the tag
/// as an unrecognized service.
#[cfg(feature = "logging")]
fn dispatch_write_journal_unsupported(invoke_id: u32) -> ConfirmedResponse {
    tracing::warn!(
        invoke_id,
        "write-journal is not served, answering object-access-unsupported"
    );
    make_confirmed_error(invoke_id, ErrorClass::Access(9))
}

/// Silences a dead-code warning: `LogControl` and `LogStorageError` are reached
/// only indirectly, through the journal query calls and through type inference
/// against the storage trait.
#[cfg(feature = "logging")]
#[allow(dead_code)]
fn _silence_log_imports(_lc: &LogControl, _e: LogStorageError) {}

/// Builds a complete ConfirmedErrorPdu, outer `0xa2 <len>` included.
///
/// The encoding follows the ConfirmedErrorPDU of IEC 61850-8-1:
///
/// ```text
/// 0xa2 <len>            -- confirmedErrorPdu [2] IMPLICIT SEQUENCE (in MMSpdu CHOICE)
///   0x80 <len> <id>     -- invokeID [0] IMPLICIT Unsigned32
///   0xa2 <len>          -- serviceError [2] IMPLICIT ServiceError (constructed)
///     0xa0 <len>        -- errorClass [0] EXPLICIT (constructed wrapper around CHOICE)
///       0x8X <len> <int>  -- access [7] / vmd-state [0] / ... IMPLICIT INTEGER
/// ```
///
/// The invoke id is `[0] IMPLICIT` (tag `0x80`) and the service error
/// `[2] IMPLICIT` (tag `0xa2`). A client that cannot find the invoke id in a
/// ConfirmedErrorPdu abandons the association, so these two tags must be exact.
///
/// This is the crate-visible wrapper around [`make_confirmed_error`], for the
/// data set handlers; the two differ only in visibility.
#[cfg(feature = "reporting")]
pub(crate) fn make_confirmed_error_pub(
    invoke_id: u32,
    error_class: ErrorClass,
) -> ConfirmedResponse {
    make_confirmed_error(invoke_id, error_class)
}

fn make_confirmed_error(invoke_id: u32, error_class: ErrorClass) -> ConfirmedResponse {
    let se = ServiceError::new(error_class);

    // invokeID [0] IMPLICIT Unsigned32 → tag 0x80
    let id_bytes = ber_encode_u32(invoke_id);
    let mut inner = BytesMut::new();
    inner.extend_from_slice(&[0x80]);
    ber_encode_length(id_bytes.len(), &mut inner);
    inner.extend_from_slice(&id_bytes);

    // serviceError [2] IMPLICIT, constructed, hence tag 0xa2.
    let mut se_body = BytesMut::new();
    se.encode_inner(&mut se_body);
    inner.extend_from_slice(&[0xa2]);
    ber_encode_length(se_body.len(), &mut inner);
    inner.extend_from_slice(&se_body);

    // confirmedErrorPdu [2] IMPLICIT SEQUENCE, hence tag 0xa2.
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&[0xa2]);
    ber_encode_length(inner.len(), &mut buf);
    buf.extend_from_slice(&inner);

    ConfirmedResponse::Error(buf.freeze())
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod services_supported_tests {
    use super::{compute_services_supported, SERVICES_JOURNAL_BYTE, SERVICES_READ_JOURNAL_BIT};

    /// The four combinations of the two subsystem flags, as
    /// `(reporting, logging)`.
    const ALL_BUILDS: [(bool, bool); 4] =
        [(true, true), (true, false), (false, true), (false, false)];

    /// No build answers getNamedVariableListAttributes (`0xac`), so no build
    /// may advertise it.
    #[test]
    fn never_advertises_get_nvl_attributes() {
        for (reporting, logging) in ALL_BUILDS {
            assert_eq!(compute_services_supported(reporting, logging)[1] & 0x08, 0);
        }
    }

    /// Data set creation and deletion and `informationReport` belong to the
    /// reporting subsystem and are advertised only when it is enabled: a client
    /// enables its own data set paths from this bitmap, and advertising a
    /// service that is not implemented leads it into a request that can only
    /// fail.
    #[test]
    fn reporting_gates_dataset_crud_and_information_report() {
        let with = compute_services_supported(true, false);
        assert_eq!(
            with[1] & 0x10,
            0x10,
            "a reporting build must advertise defineNamedVariableList"
        );
        assert_eq!(
            with[1] & 0x04,
            0x04,
            "a reporting build must advertise deleteNamedVariableList"
        );
        assert_eq!(
            with[9] & 0x01,
            0x01,
            "a reporting build must advertise informationReport"
        );

        let without = compute_services_supported(false, false);
        assert_eq!(
            without[1] & (0x10 | 0x04),
            0,
            "a build without reporting must not advertise data set services"
        );
        assert_eq!(
            without[9] & 0x01,
            0,
            "a build without reporting must not advertise informationReport"
        );
    }

    /// `readJournal` belongs to the logging subsystem, which serves
    /// QueryLogByTime and QueryLogAfter through it. Withholding the bit from a
    /// build that serves the service leaves both queries unreachable for a
    /// client that enables its own paths from this bitmap.
    #[test]
    fn logging_gates_read_journal() {
        for reporting in [true, false] {
            let with = compute_services_supported(reporting, true);
            assert_eq!(
                with[SERVICES_JOURNAL_BYTE] & SERVICES_READ_JOURNAL_BIT,
                SERVICES_READ_JOURNAL_BIT,
                "a logging build must advertise readJournal"
            );

            let without = compute_services_supported(reporting, false);
            assert_eq!(
                without[SERVICES_JOURNAL_BYTE], 0x00,
                "a build without logging must advertise no journal service"
            );
        }
    }

    /// WriteJournal is answered with an access error rather than served, so its
    /// bit stays clear in every build, logging included. The assertion covers
    /// the whole byte, which also holds `getAlarmEnrollmentSummary` and
    /// `getCapabilityList`, so any service added there has to be announced
    /// deliberately.
    #[test]
    fn never_advertises_write_journal() {
        for (reporting, logging) in ALL_BUILDS {
            let map = compute_services_supported(reporting, logging);
            assert_eq!(
                map[SERVICES_JOURNAL_BYTE] & !SERVICES_READ_JOURNAL_BIT,
                0,
                "readJournal is the only service advertised in its byte, writeJournal included"
            );
        }
    }

    /// No build answers status or cancel, so no build may advertise them.
    #[test]
    fn never_advertises_status_or_cancel() {
        for (reporting, logging) in ALL_BUILDS {
            let map = compute_services_supported(reporting, logging);
            assert_eq!(
                map[0] & 0x80,
                0,
                "status has no handler and must not be advertised"
            );
            assert_eq!(
                map[10] & 0x08,
                0,
                "cancel has no handler and must not be advertised"
            );
        }
    }

    /// The services every build answers stay advertised in every build.
    #[test]
    fn baseline_bits_stable_across_builds() {
        for (reporting, logging) in ALL_BUILDS {
            let map = compute_services_supported(reporting, logging);
            assert_eq!(
                map[0], 0x6e,
                "get-name-list, identify, read, write and get-variable-access-attributes are advertised, status is not"
            );
            assert_eq!(map[10], 0x10, "conclude is advertised, cancel is not");
        }
    }

    /// The whole bitmap, byte for byte, at both extremes, so that adding a
    /// service without adjusting the announcement fails here.
    #[test]
    fn full_bitmap_is_bit_exact() {
        assert_eq!(
            compute_services_supported(true, true),
            [0x6e, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x10],
            "a build with reporting and logging"
        );
        assert_eq!(
            compute_services_supported(false, false),
            [0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10],
            "a build with neither"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iec61850_mms::mms::pdu::common::MmsData;
    use iec61850_model::{
        DataAttribute, DataAttributeType, DataObject, DoChild, IedModelBuilder,
        LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, TrgOps, FC,
    };

    fn build_dispatcher() -> MmsModelDispatcher {
        let mag_da = DataAttribute::new(
            "mag",
            FC::Mx,
            DataAttributeType::Float32,
            TrgOps::default(),
            MmsValue::Float32(1.23),
        );
        let ctl_da = DataAttribute::new(
            "ctlModel",
            FC::Cf,
            DataAttributeType::Int32,
            TrgOps::default(),
            MmsValue::Integer(0),
        );
        let totw_do = DataObject {
            name: "TotW".into(),
            array_count: None,
            children: vec![DoChild::Da(mag_da)],
        };
        let mod_do = DataObject {
            name: "Mod".into(),
            array_count: None,
            children: vec![DoChild::Da(ctl_da)],
        };
        let mmxu_ln = iec61850_model::LogicalNode {
            prefix: String::new(),
            class: "MMXU".into(),
            inst: "1".into(),
            dos: vec![totw_do],
            datasets: vec![],
            rcbs: vec![],
            gocbs: vec![],
            svcbs: vec![],
            lcbs: vec![],
            sgcb: None,
        };
        let ggio_ln = iec61850_model::LogicalNode {
            prefix: String::new(),
            class: "GGIO".into(),
            inst: "1".into(),
            dos: vec![mod_do],
            datasets: vec![],
            rcbs: vec![],
            gocbs: vec![],
            svcbs: vec![],
            lcbs: vec![],
            sgcb: None,
        };
        let lln0 = LogicalNodeBuilder::lln0().build().unwrap();
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(lln0)
            .add_ln(mmxu_ln)
            .add_ln(ggio_ln)
            .build()
            .unwrap();
        let model = IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap();
        let mms_model = MmsDeviceModel::from_ied_model(&model).unwrap();
        let mut policies = WriteAccessPolicies::default();
        policies.set(FC::Cf, true);

        MmsModelDispatcher::new(Arc::new(model), Arc::new(mms_model), Arc::new(policies))
    }

    fn make_conn() -> MmsServerConnection {
        MmsServerConnection::new()
    }

    // ── An unknown service tag is rejected ──────────────────────────

    #[test]
    fn dispatcher_unknown_tag_returns_reject() {
        let dispatcher = build_dispatcher();
        let conn = make_conn();
        let req = ConfirmedRequest {
            invoke_id: 1,
            service_body: Bytes::from_static(&[0xff, 0x00]),
        };
        let resp = dispatcher.dispatch(&conn, req);
        assert!(
            matches!(resp, ConfirmedResponse::Reject),
            "an unknown service tag must be rejected"
        );
    }

    /// A service the bitmap does not advertise is still answered, with a
    /// Reject, when a client sends it anyway. Advertising honestly and
    /// answering everything are one pair: without the first a client walks into
    /// a dead end, without the second it waits forever.
    #[test]
    fn dispatcher_unadvertised_services_return_reject_not_silence() {
        let dispatcher = build_dispatcher();
        let conn = make_conn();
        for tag in [0x80u8, 0xac] {
            let req = ConfirmedRequest {
                invoke_id: 7,
                service_body: Bytes::copy_from_slice(&[tag, 0x00]),
            };
            let resp = dispatcher.dispatch(&conn, req);
            assert!(
                matches!(resp, ConfirmedResponse::Reject),
                "0x{tag:02x} must be rejected, neither ignored nor panicked on"
            );
        }
    }

    // ── GetNameList answers with a response ─────────────────────────

    #[test]
    fn dispatcher_gnl_returns_response() {
        use iec61850_mms::mms::pdu::get_name_list::{
            encode_confirmed_get_name_list_request, GetNameListRequest, ObjectClass, ObjectScope,
        };

        let dispatcher = build_dispatcher();
        let conn = make_conn();

        let gnl_req = GetNameListRequest {
            object_class: ObjectClass::Domain,
            object_scope: ObjectScope::VmdSpecific,
            continue_after: None,
        };
        let mut full_buf = BytesMut::new();
        encode_confirmed_get_name_list_request(1, &gnl_req, &mut full_buf);

        // The dispatcher receives the bytes after the invoke id, service tag
        // included, so the body starts at the GetNameList tag.
        let body = extract_service_body_from_confirmed_request(&full_buf);
        let req = ConfirmedRequest {
            invoke_id: 1,
            service_body: body,
        };
        let resp = dispatcher.dispatch(&conn, req);
        match resp {
            ConfirmedResponse::Response(bytes) => {
                assert_eq!(
                    bytes[0], 0xa1,
                    "a response must start with the confirmed-response tag"
                );
            }
            other => panic!("get-name-list must answer with a response, got {:?}", other),
        }
    }

    // ── Read → Response ──────────────────────────────────────────────

    #[test]
    fn dispatcher_read_returns_response_with_access_result() {
        use iec61850_mms::mms::pdu::read::{encode_confirmed_read_request, ReadRequest};

        let dispatcher = build_dispatcher();
        let conn = make_conn();

        let read_req = ReadRequest::single_domain("IED1LD0", "MMXU1$MX$TotW$mag");
        let mut full_buf = BytesMut::new();
        encode_confirmed_read_request(2, &read_req, &mut full_buf);

        let body = extract_service_body_from_confirmed_request(&full_buf);
        let req = ConfirmedRequest {
            invoke_id: 2,
            service_body: body,
        };
        let resp = dispatcher.dispatch(&conn, req);
        match resp {
            ConfirmedResponse::Response(bytes) => {
                assert_eq!(
                    bytes[0], 0xa1,
                    "a response must start with the confirmed-response tag"
                );
            }
            other => panic!("read must answer with a response, got {:?}", other),
        }
    }

    #[test]
    fn dispatcher_whole_ln_read_returns_structure_response() {
        // The association has negotiated nothing, so the read runs without a
        // budget and expands the whole logical node.
        use iec61850_mms::mms::pdu::read::{
            decode_confirmed_read_response, encode_confirmed_read_request, ReadRequest,
        };

        let dispatcher = build_dispatcher();
        let conn = make_conn();

        let read_req = ReadRequest::single_domain("IED1LD0", "MMXU1");
        let mut full_buf = BytesMut::new();
        encode_confirmed_read_request(7, &read_req, &mut full_buf);

        let body = extract_service_body_from_confirmed_request(&full_buf);
        let req = ConfirmedRequest {
            invoke_id: 7,
            service_body: body,
        };
        let resp = dispatcher.dispatch(&conn, req);
        match resp {
            ConfirmedResponse::Response(bytes) => {
                let (id, parsed) =
                    decode_confirmed_read_response(&bytes).expect("decode whole-LN response");
                assert_eq!(id, 7);
                assert_eq!(parsed.list_of_access_result.len(), 1);
                assert!(matches!(
                    &parsed.list_of_access_result[0],
                    AccessResult::Success(MmsData::Structure(_))
                ));
            }
            other => panic!(
                "a whole-LN read must answer with a response, got {:?}",
                other
            ),
        }
    }

    // With no routed subsystem the model tree is shallower and one access
    // result still fits the 32-byte budget, so the over-budget branch is only
    // reachable once routing expands the logical node further.
    #[cfg(any(
        feature = "reporting",
        feature = "control",
        feature = "setting-groups",
        feature = "goose-mapping"
    ))]
    #[test]
    fn dispatcher_whole_ln_read_over_budget_returns_service_error() {
        use iec61850_mms::mms::pdu::read::{encode_confirmed_read_request, ReadRequest};
        use iec61850_mms::mms::server::connection::NegotiatedParams;

        let dispatcher = build_dispatcher();
        let mut conn = MmsServerConnection::new();
        // A maximum below the frame overhead makes expansion overrun at once.
        conn.set_negotiated(NegotiatedParams {
            max_pdu_size: 32,
            ..NegotiatedParams::default()
        });

        let read_req = ReadRequest::single_domain("IED1LD0", "MMXU1");
        let mut full_buf = BytesMut::new();
        encode_confirmed_read_request(11, &read_req, &mut full_buf);

        let body = extract_service_body_from_confirmed_request(&full_buf);
        let req = ConfirmedRequest {
            invoke_id: 11,
            service_body: body,
        };
        let resp = dispatcher.dispatch(&conn, req);
        match resp {
            ConfirmedResponse::Error(bytes) => {
                assert_eq!(bytes[0], 0xa2, "a confirmed error must start with tag 0xa2");
                // errorClass resource carries tag 0x83 inside the explicit
                // wrapper, with sub-code 0.
                assert!(
                    bytes.windows(3).any(|w| w == [0x83, 0x01, 0x00]),
                    "the error must carry errorClass resource with sub-code 0, bytes={:?}",
                    bytes.as_ref()
                );
            }
            other => panic!(
                "an over-budget read must answer with a confirmed error, got {:?}",
                other
            ),
        }
    }

    // ── Write → Response ─────────────────────────────────────────────

    #[test]
    fn dispatcher_write_cf_allowed_returns_success_response() {
        use iec61850_mms::mms::pdu::write::{encode_confirmed_write_request, WriteRequest};

        let dispatcher = build_dispatcher();
        let conn = make_conn();

        let write_req =
            WriteRequest::single_domain("IED1LD0", "GGIO1$CF$Mod$ctlModel", MmsData::Integer(3));
        let mut full_buf = BytesMut::new();
        encode_confirmed_write_request(3, &write_req, &mut full_buf);

        let body = extract_service_body_from_confirmed_request(&full_buf);
        let req = ConfirmedRequest {
            invoke_id: 3,
            service_body: body,
        };
        let resp = dispatcher.dispatch(&conn, req);
        match resp {
            ConfirmedResponse::Response(bytes) => {
                assert_eq!(
                    bytes[0], 0xa1,
                    "a response must start with the confirmed-response tag"
                );
            }
            other => panic!("write must answer with a response, got {:?}", other),
        }
    }

    // ── GetVarAccessAttrs → Response ─────────────────────────────────

    #[test]
    fn dispatcher_gva_returns_response() {
        use iec61850_mms::mms::pdu::{
            common::ObjectName,
            get_var_access_attrs::{
                encode_confirmed_get_var_access_attrs_request, GetVariableAccessAttributesRequest,
            },
        };

        let dispatcher = build_dispatcher();
        let conn = make_conn();

        let gva_req = GetVariableAccessAttributesRequest {
            object_name: ObjectName::DomainSpecific {
                domain_id: "IED1LD0".to_string(),
                item_id: "MMXU1$MX$TotW$mag".to_string(),
            },
        };
        let mut full_buf = BytesMut::new();
        encode_confirmed_get_var_access_attrs_request(4, &gva_req, &mut full_buf);

        let body = extract_service_body_from_confirmed_request(&full_buf);
        let req = ConfirmedRequest {
            invoke_id: 4,
            service_body: body,
        };
        let resp = dispatcher.dispatch(&conn, req);
        match resp {
            ConfirmedResponse::Response(bytes) => {
                assert_eq!(
                    bytes[0], 0xa1,
                    "a response must start with the confirmed-response tag"
                );
            }
            other => panic!(
                "get-variable-access-attributes must answer with a response, got {:?}",
                other
            ),
        }
    }

    // ── Identify is byte-exact, an interoperability regression ──────

    /// The Identify-Response wire format of IEC 61850-8-1:
    /// `0xa1 ... 0x02 <id> ... 0xa2 ... 0x80 vendor 0x81 model 0x82 revision`
    #[test]
    fn identify_response_byte_exact_format() {
        let ident = IdentificationStrings {
            vendor_name: "AB".into(),
            model_name: "CD".into(),
            revision: "EF".into(),
        };
        let resp = dispatch_identify(7, &ident);
        let bytes = match resp {
            ConfirmedResponse::Response(b) => b,
            other => panic!("expected a response, got {:?}", other),
        };

        // Expected:
        //   0xa1 0x11                    ConfirmedResponsePdu, len=17
        //     0x02 0x01 0x07             invokeID = 7
        //     0xa2 0x0c                  identify body, len=12
        //       0x80 0x02 'A' 'B'        vendorName "AB"
        //       0x81 0x02 'C' 'D'        modelName "CD"
        //       0x82 0x02 'E' 'F'        revision "EF"
        let expected: &[u8] = &[
            0xa1, 0x11, 0x02, 0x01, 0x07, 0xa2, 0x0c, 0x80, 0x02, b'A', b'B', 0x81, 0x02, b'C',
            b'D', 0x82, 0x02, b'E', b'F',
        ];
        assert_eq!(
            &bytes[..],
            expected,
            "the Identify response must match the wire format of IEC 61850-8-1"
        );
    }

    /// The full dispatch path: service tag `0x82` answers with an Identify.
    #[test]
    fn dispatcher_identify_returns_response() {
        let dispatcher = build_dispatcher();
        let conn = make_conn();
        // Identify-Request is [2] IMPLICIT NULL, primitive: 0x82 0x00.
        let req = ConfirmedRequest {
            invoke_id: 0,
            service_body: Bytes::from_static(&[0x82, 0x00]),
        };
        let resp = dispatcher.dispatch(&conn, req);
        match resp {
            ConfirmedResponse::Response(bytes) => {
                assert_eq!(
                    bytes[0], 0xa1,
                    "a response must start with the confirmed-response tag"
                );
                assert!(
                    bytes.contains(&0xa2),
                    "an Identify response must carry the identify body tag"
                );
            }
            other => panic!("identify must answer with a response, got {:?}", other),
        }
    }

    // ── Long Identify strings ───────────────

    /// An Identify-Response whose `vendorName`,
    /// `modelName`, or `revision` runs past 64 bytes is encoded in full, with
    /// no fixed-size buffer anywhere on the path. Implementations that stage
    /// these strings in a 64-byte stack buffer overflow it instead.
    ///
    /// The test holds two properties: encoding strings far longer than 64 bytes
    /// does not panic, and the wire carries them whole under a long-form length
    /// (`0x82 <hi> <lo>`).
    #[test]
    fn identify_long_strings_no_stack_overflow() {
        // Distinct characters per field make a truncation easy to spot.
        let vendor: String = "V".repeat(256);
        let model: String = "M".repeat(256);
        let revision: String = "R".repeat(256);

        let ident = IdentificationStrings {
            vendor_name: vendor.clone(),
            model_name: model.clone(),
            revision: revision.clone(),
        };

        let resp = dispatch_identify(42, &ident);
        let bytes = match resp {
            ConfirmedResponse::Response(b) => b,
            other => panic!("expected a response, got {:?}", other),
        };

        assert!(
            bytes.windows(256).any(|w| w == vendor.as_bytes()),
            "the whole vendor name must reach the wire"
        );
        assert!(
            bytes.windows(256).any(|w| w == model.as_bytes()),
            "the whole model name must reach the wire"
        );
        assert!(
            bytes.windows(256).any(|w| w == revision.as_bytes()),
            "the whole revision must reach the wire"
        );

        // 256 is 0x0100, which needs the long form `0x82 0x01 0x00`.
        let mut found_long_form = 0;
        for tag in [0x80u8, 0x81, 0x82] {
            let positions: Vec<usize> = bytes
                .windows(4)
                .enumerate()
                .filter(|(_, w)| w[0] == tag && w[1] == 0x82 && w[2] == 0x01 && w[3] == 0x00)
                .map(|(i, _)| i)
                .collect();
            // 0x82 is both the revision tag and the leading byte of a long-form
            // length, so it can match either; only 0x80 and 0x81 are asserted.
            if tag != 0x82 {
                assert!(
                    !positions.is_empty(),
                    "tag {:#x} must be followed by the long-form length for 256 bytes",
                    tag
                );
                found_long_form += 1;
            }
        }
        assert_eq!(
            found_long_form, 2,
            "vendor name and model name must each use a long-form length"
        );
    }

    /// The Identify response stays correct at the boundary: a string of
    /// exactly 65 bytes, one past a 64-byte buffer boundary.
    #[test]
    fn identify_at_fixed_buffer_boundary() {
        let s = "X".repeat(65);
        let ident = IdentificationStrings {
            vendor_name: s.clone(),
            model_name: s.clone(),
            revision: s.clone(),
        };
        let resp = dispatch_identify(1, &ident);
        let bytes = match resp {
            ConfirmedResponse::Response(b) => b,
            other => panic!("expected a response, got {:?}", other),
        };
        // Only a length above 127 needs the long form, so 65 encodes as the
        // single byte 0x41.
        assert!(
            bytes
                .windows(67)
                .any(|w| w[0] == 0x80 && w[1] == 0x41 && &w[2..] == s.as_bytes()),
            "a 65-byte vendor name must encode with a single-byte length and its full payload"
        );
    }

    // ── ConfirmedError is byte-exact, an interoperability regression ─

    /// In the ConfirmedErrorPDU of IEC 61850-8-1 the invoke id is
    /// `[0] IMPLICIT` (tag `0x80`) and the service error `[2] IMPLICIT` (tag
    /// `0xa2`). A client that cannot find the invoke id abandons the
    /// association, so this test pins both tags.
    #[test]
    fn confirmed_error_byte_exact_format() {
        let resp = make_confirmed_error(3, ErrorClass::Access(10));
        let bytes = match resp {
            ConfirmedResponse::Error(b) => b,
            other => panic!("expected an error, got {:?}", other),
        };

        // Expected:
        //   0xa2 0x0a            ConfirmedErrorPDU [2] IMPLICIT, len=10
        //     0x80 0x01 0x03     invokeID [0] IMPLICIT Unsigned32 = 3
        //     0xa2 0x05          serviceError [2] IMPLICIT, len=5
        //       0xa0 0x03        errorClass [0] EXPLICIT, len=3
        //         0x87 0x01 0x0a   access [7] IMPLICIT INTEGER = 10
        let expected: &[u8] = &[
            0xa2, 0x0a, 0x80, 0x01, 0x03, 0xa2, 0x05, 0xa0, 0x03, 0x87, 0x01, 0x0a,
        ];
        assert_eq!(
            &bytes[..],
            expected,
            "the confirmed error must carry invokeID as 0x80 and serviceError as 0xa2"
        );
    }

    // ── An empty service body is rejected ───────────────────────────

    #[test]
    fn dispatcher_empty_body_returns_reject() {
        let dispatcher = build_dispatcher();
        let conn = make_conn();
        let req = ConfirmedRequest {
            invoke_id: 99,
            service_body: Bytes::new(),
        };
        let resp = dispatcher.dispatch(&conn, req);
        assert!(matches!(resp, ConfirmedResponse::Reject));
    }

    // ─────────────────────────────────────────────────────────────────
    // Test helpers
    // ─────────────────────────────────────────────────────────────────

    /// Extracts the service body the dispatcher expects, the bytes after the
    /// invoke id, from a complete ConfirmedRequestPdu.
    ///
    /// The PDU is `0xa0 <len> 0x02 <id_len> <id_bytes> <service_tag> <...>`, so
    /// the body runs from the service tag to the end.
    fn extract_service_body_from_confirmed_request(full: &BytesMut) -> Bytes {
        let (outer_len, outer_hdr) = ber_decode_length(&full[1..]);
        let inner_start = 1 + outer_hdr;
        let inner = &full[inner_start..inner_start + outer_len];

        assert_eq!(inner[0], 0x02, "the invoke id must carry tag 0x02");
        let (id_len, id_hdr) = ber_decode_length(&inner[1..]);
        let service_start = 1 + id_hdr + id_len;

        Bytes::copy_from_slice(&inner[service_start..])
    }

    /// Decodes a BER length, returning the value and the header size.
    fn ber_decode_length(data: &[u8]) -> (usize, usize) {
        if data.is_empty() {
            panic!("ber_decode_length: empty data");
        }
        if data[0] < 0x80 {
            (data[0] as usize, 1)
        } else if data[0] == 0x81 {
            (data[1] as usize, 2)
        } else if data[0] == 0x82 {
            let len = ((data[1] as usize) << 8) | (data[2] as usize);
            (len, 3)
        } else {
            panic!(
                "ber_decode_length: unsupported length form 0x{:02X}",
                data[0]
            );
        }
    }
}

#[cfg(all(test, feature = "logging"))]
mod log_control_name_tests {
    use super::{extract_lcb_target, is_lcb_path, LCB_SERVED_FIELDS, LCB_UNSERVED_FIELDS};
    use iec61850_mms::mms::pdu::common::ObjectName;

    fn domain_specific(item: &str) -> ObjectName {
        ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: item.to_string(),
        }
    }

    /// The Read path accepts the control block itself and one attribute below
    /// it, and routes everything else onward. The registry item it yields is
    /// the same string [`is_lcb_path`] admits into the name list, so a browsed
    /// name resolves.
    #[test]
    fn extract_lcb_target_splits_the_block_from_its_attribute() {
        let whole_name = domain_specific("LLN0$LG$evlog");
        let whole = extract_lcb_target(&whole_name).expect("a control block path must resolve");
        assert_eq!(whole.0, "IED1LD0");
        assert_eq!(whole.1, "LLN0$LG$evlog");
        assert_eq!(whole.2, None);
        assert!(is_lcb_path(&whole.1), "the item must be a listable name");

        let field_name = domain_specific("LLN0$LG$evlog$LogEna");
        let field = extract_lcb_target(&field_name).expect("an attribute path must resolve");
        assert_eq!(field.1, "LLN0$LG$evlog");
        assert_eq!(field.2, Some("LogEna"));

        for out_of_scope in [
            "LLN0$RP$urcbMeas",
            "LLN0$LG$evlog$LogEna$Extra",
            "LLN0$LG",
            "LLN0$LG$",
            "$LG$evlog",
        ] {
            assert!(
                extract_lcb_target(&domain_specific(out_of_scope)).is_none(),
                "`{out_of_scope}` must not route to the log control block path"
            );
        }
        assert!(extract_lcb_target(&ObjectName::VmdSpecific("LLN0$LG$evlog".into())).is_none());
    }

    /// The served and unserved attribute lists together are the nine attributes
    /// of a log control block, and they do not overlap.
    #[test]
    fn served_and_unserved_lcb_fields_are_disjoint_and_complete() {
        assert_eq!(LCB_SERVED_FIELDS.len() + LCB_UNSERVED_FIELDS.len(), 9);
        for f in LCB_SERVED_FIELDS {
            assert!(
                !LCB_UNSERVED_FIELDS.contains(&f),
                "{f} cannot be both served and unserved"
            );
        }
    }

    /// Only a three-segment `<LN>$LG$<name>` item names a log control block; a
    /// log instance key, a wrong functional constraint and a deeper path are
    /// all rejected, so none of them reaches a named variable list.
    #[test]
    fn is_lcb_path_accepts_only_a_log_control_block_item() {
        assert!(is_lcb_path("LLN0$LG$evlog"));
        assert!(is_lcb_path("MMXU1$LG$lcb01"));

        assert!(
            !is_lcb_path("MMXU1$EventLog"),
            "a log instance is not an LCB"
        );
        assert!(!is_lcb_path("LLN0$RP$urcbMeas"), "a wrong FC is not an LCB");
        assert!(
            !is_lcb_path("LLN0$LG$evlog$LogEna"),
            "an attribute below the control block is not the control block"
        );
        assert!(!is_lcb_path("LLN0$LG$"), "an empty name is not an LCB");
        assert!(
            !is_lcb_path("$LG$evlog"),
            "an empty logical node is not an LCB"
        );
        assert!(!is_lcb_path("LLN0"), "a bare logical node is not an LCB");
    }
}
