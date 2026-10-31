//! MMS service dispatcher for the model-backed server.
//!
//! `MmsModelDispatcher` implements the `MmsServiceDispatcher` trait and routes
//! a ConfirmedRequest by its service tag: `0x80` Status, `0xa1` GetNameList,
//! `0xa6` GetVariableAccessAttributes, `0xa4` Read, `0xa5` Write, `0x82` Identify,
//! `0xab` DefineNamedVariableList, `0xac` GetNamedVariableListAttributes,
//! `0xad` DeleteNamedVariableList, and the long-form `0xbf 0x41` ReadJournal.
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
#[cfg(feature = "reporting")]
pub mod get_named_variable_list_attrs;
pub mod get_var_access_attrs;
pub(crate) mod pdu_budget;
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
    identify::{
        encode_confirmed_identify_response, IdentifyResponse, SERVICE_TAG_IDENTIFY_REQUEST,
    },
    read::{encode_confirmed_read_response, ReadRequest, ReadResponse, SERVICE_TAG_READ},
    service_error::{
        subcode::{access, resource},
        ErrorClass, ServiceError,
    },
    status::{
        decode_status_request, encode_confirmed_status_response, StatusResponse, VmdLogicalStatus,
        VmdPhysicalStatus, SERVICE_TAG_STATUS_REQUEST,
    },
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
    new_log_control_registry, LogControl, LogControlRegistry, LogEntryId, LogStorageError,
};
use crate::mapping::MmsDeviceModel;
use crate::policy::WriteAccessPolicies;
#[cfg(feature = "reporting")]
use crate::reporting::{NullReportSink, ReportingEngine};

use get_name_list::{handle_get_name_list_with_extras, GetNameListResult};
use get_var_access_attrs::GetVarAccessAttrsResult;
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
#[non_exhaustive]
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
/// trait method while the control flow involves asynchronous handlers, so the
/// control path admits a request inline and executes an accepted command on a
/// task of the current tokio runtime, of either flavor.
///
/// A Read or Write under RP or BR is routed to `reporting_engine`, which
/// answers `ObjectNonExistent` for a control block it does not hold.
#[derive(Debug, Clone)]
#[non_exhaustive]
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
    /// Limits on the data sets DefineNamedVariableList creates, shared with the
    /// server.
    #[cfg(feature = "reporting")]
    pub dynamic_dataset_quota: Arc<define_named_variable_list::DynamicDatasetQuota>,
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
            #[cfg(feature = "reporting")]
            dynamic_dataset_quota: Arc::new(
                define_named_variable_list::DynamicDatasetQuota::default(),
            ),
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

    /// Installs the run-time data set limits, which the server builder shares
    /// with the server itself.
    #[cfg(feature = "reporting")]
    pub fn with_dynamic_dataset_quota(
        mut self,
        quota: Arc<define_named_variable_list::DynamicDatasetQuota>,
    ) -> Self {
        self.dynamic_dataset_quota = quota;
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
/// the second bit of byte 8, `0x40`.
const SERVICES_READ_JOURNAL_BIT: u8 = 0x40;

/// Builds the `servicesSupportedCalled` bitmap of the Initiate-Response for the
/// services this build actually serves.
///
/// Starting from the baseline of the connection layer, a bit is cleared unless
/// a handler answers it: `cancel` has no handler in any build, and data set
/// creation, deletion and directory are cleared without the reporting
/// subsystem. `informationReport` is cleared only when neither the reporting
/// nor the control subsystem is compiled in, since the control subsystem also
/// sends one, carrying `LastApplError` for a refused command or a command
/// termination for an enhanced-security model. The baseline carries no journal
/// service, so
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
fn compute_services_supported(reporting: bool, control: bool, logging: bool) -> [u8; 11] {
    use iec61850_mms::mms::server::connection::SERVER_SERVICES_SUPPORTED;
    let mut map = SERVER_SERVICES_SUPPORTED;
    map[10] &= !0x08; // cancel: a Cancel-RequestPDU is rejected at the PDU layer
    if !reporting {
        // define, getAttributes and delete NamedVariableList
        map[1] &= !(0x10 | 0x08 | 0x04);
    }
    if !reporting && !control {
        map[9] &= !0x01; // informationReport
    }
    if logging {
        map[SERVICES_JOURNAL_BYTE] |= SERVICES_READ_JOURNAL_BIT;
    }
    map
}

impl MmsServiceDispatcher for MmsModelDispatcher {
    fn services_supported(&self) -> [u8; 11] {
        compute_services_supported(
            cfg!(feature = "reporting"),
            cfg!(feature = "control"),
            cfg!(feature = "logging"),
        )
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

        // Read and Write decode their data and alternate access no deeper than
        // the nesting level the association negotiated.
        let negotiated_nesting_level = conn.negotiated().map(|p| p.data_structure_nesting_level);

        // Every answer below leaves through the outbound size guard, so a
        // service added later is bounded by the negotiated maximum PDU size
        // without having to arrange it itself.
        let response = match service_tag {
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
            SERVICE_TAG_GET_VAR_ACCESS_ATTRS => dispatch_get_var_access_attrs(
                invoke_id,
                &body,
                &self.mms_model,
                #[cfg(feature = "reporting")]
                &self.reporting_engine,
                #[cfg(feature = "logging")]
                &self.log_controls,
                #[cfg(feature = "goose-mapping")]
                &self.gocb_registry,
            ),
            SERVICE_TAG_STATUS_REQUEST => dispatch_status(invoke_id, &body),
            SERVICE_TAG_IDENTIFY_REQUEST => dispatch_identify(invoke_id, &self.identification),
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
                negotiated_nesting_level,
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
                negotiated_nesting_level,
            ),
            // DefineNamedVariableList, the mapping of CreateDataSet.
            #[cfg(feature = "reporting")]
            0xab => define_named_variable_list::handle_define_named_variable_list(
                invoke_id,
                &body,
                &self.model,
                &self.dataset_registry,
                &self.dynamic_dataset_keys,
                &self.dynamic_dataset_quota,
                conn_id,
            ),
            // GetNamedVariableListAttributes, the mapping of GetDataSetDirectory.
            #[cfg(feature = "reporting")]
            0xac => get_named_variable_list_attrs::handle_get_named_variable_list_attributes(
                invoke_id,
                &body,
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
                &self.dynamic_dataset_quota,
                &self.reporting_engine,
            ),
            other => {
                tracing::warn!(
                    invoke_id,
                    service_tag = format!("0x{:02X}", other),
                    "dispatcher: unknown service tag, rejecting"
                );
                ConfirmedResponse::Reject
            }
        };

        pdu_budget::guard_outbound_pdu_size(
            invoke_id,
            service_tag,
            response,
            conn.negotiated_max_pdu_size(),
        )
    }
}

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
            return make_confirmed_error(invoke_id, ErrorClass::Access(access::OTHER));
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
                "get-name-list: unknown domain, answering object-non-existent"
            );
            make_confirmed_error(invoke_id, ErrorClass::Access(access::OBJECT_NON_EXISTENT))
        }
        GetNameListResult::Unsupported => {
            tracing::warn!(
                invoke_id,
                "get-name-list: this object class and scope are not served"
            );
            make_confirmed_error(
                invoke_id,
                ErrorClass::Access(access::OBJECT_ACCESS_UNSUPPORTED),
            )
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
/// name that answers object-non-existent.
///
/// Only three combinations have members. Domain-scope named variables gain,
/// flattened the way the model's own names are, every report, log and GOOSE
/// control block of [`domain_control_blocks`]: the `<LN>$RP`, `<LN>$BR`,
/// `<LN>$LG` or `<LN>$GO` group, the block itself and each of its members, as
/// GetVariableAccessAttributes describes them. Domain-scope named variable lists gain the data sets of the
/// registry, which covers both those the application registered and those a
/// client created with DefineNamedVariableList.
/// Domain-scope journals gain the journals of the log control registry.
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
            for (ln, block) in domain_control_blocks(
                domain,
                None,
                #[cfg(feature = "reporting")]
                reporting_engine,
                #[cfg(feature = "logging")]
                log_controls,
                #[cfg(feature = "goose-mapping")]
                gocb_registry,
            ) {
                let group = format!("{ln}${}", block.kind.fc().as_str());
                out.extend(crate::mapping::flat_paths(
                    &format!("{group}${}", block.name),
                    &block.kind.type_spec(),
                ));
                out.push(group);
            }
            out
        }
        #[cfg(feature = "logging")]
        (ObjectClass::Journal, ObjectScope::DomainSpecific(domain)) => {
            journal_names_in_domain(log_controls, domain)
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

/// The report, log and GOOSE control blocks registered in `domain`, as the
/// logical node each belongs to and its entry, sorted by logical node, then by
/// the IEC 61850-8-1 order of their groups, then by name. `ln` limits the
/// answer to one logical node.
///
/// The reporting engine, the log control registry and the GOOSE control block
/// registry are the registries the Read paths resolve a control block against,
/// so every block this returns is one a client can go on to read. A report
/// control block counts only under the group its table serves, unbuffered
/// under RP and buffered under BR, and a log control registry key only in its
/// `<LN>$LG$<name>` form. A poisoned registry contributes nothing rather than
/// failing the caller.
#[cfg(any(feature = "reporting", feature = "logging", feature = "goose-mapping"))]
fn domain_control_blocks(
    domain: &str,
    ln: Option<&str>,
    #[cfg(feature = "reporting")] reporting_engine: &Arc<Mutex<ReportingEngine>>,
    #[cfg(feature = "logging")] log_controls: &LogControlRegistry,
    #[cfg(feature = "goose-mapping")] gocb_registry: &GoCBRegistry,
) -> Vec<(String, crate::mapping::ControlBlockEntry)> {
    use crate::mapping::{ControlBlockEntry, ControlBlockKind};
    let mut out: Vec<(String, ControlBlockEntry)> = Vec::new();
    let mut push = |item: &str, kind: ControlBlockKind| {
        let mut segments = item.split('$');
        let (Some(ln_name), Some(fc), Some(name), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return;
        };
        if ln_name.is_empty()
            || name.is_empty()
            || fc != kind.fc().as_str()
            || ln.is_some_and(|l| l != ln_name)
        {
            return;
        }
        out.push((
            ln_name.to_string(),
            ControlBlockEntry {
                kind,
                name: name.to_string(),
            },
        ));
    };
    #[cfg(feature = "reporting")]
    {
        // The engine keys a control block by `<domain>/<LN>$FC$<name>`.
        let prefix = format!("{domain}/");
        match reporting_engine.lock() {
            Ok(engine) => {
                for path in engine.rcb_paths() {
                    if let Some(item) = path.strip_prefix(&prefix) {
                        push(item, ControlBlockKind::Unbuffered);
                    }
                }
                for path in engine.brcb_paths() {
                    if let Some(item) = path.strip_prefix(&prefix) {
                        push(item, ControlBlockKind::Buffered);
                    }
                }
            }
            Err(_) => tracing::warn!(
                domain,
                "the reporting engine lock is poisoned, no report control block is listed"
            ),
        }
    }
    #[cfg(feature = "logging")]
    match log_controls.read() {
        Ok(registry) => {
            for (d, item) in registry.keys() {
                if d == domain && is_lcb_path(item) {
                    push(item, ControlBlockKind::Log);
                }
            }
        }
        Err(_) => tracing::warn!(
            domain,
            "the log control registry lock is poisoned, no log control block is listed"
        ),
    }
    #[cfg(feature = "goose-mapping")]
    for item in gocb_registry.item_bases_in_domain(domain) {
        push(&item, ControlBlockKind::Goose);
    }
    out.sort_by(|(ln_a, a), (ln_b, b)| {
        let rank = |k: ControlBlockKind| {
            iec61850_model::FC::WIRE_ORDER
                .iter()
                .position(|f| *f == k.fc())
        };
        ln_a.cmp(ln_b)
            .then(rank(a.kind).cmp(&rank(b.kind)))
            .then(a.name.cmp(&b.name))
    });
    out
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
///
/// The report, log and GOOSE control blocks of [`domain_control_blocks`] are
/// merged into the structure of their logical node, so every control block
/// name GetNameList reports has a type description.
///
/// The type specification of a logical node grows with the model, so a
/// response can outgrow the negotiated maximum PDU size; the dispatcher's
/// outbound guard bounds it.
fn dispatch_get_var_access_attrs(
    invoke_id: u32,
    body: &Bytes,
    mms_model: &MmsDeviceModel,
    #[cfg(feature = "reporting")] reporting_engine: &Arc<Mutex<ReportingEngine>>,
    #[cfg(feature = "logging")] log_controls: &LogControlRegistry,
    #[cfg(feature = "goose-mapping")] gocb_registry: &GoCBRegistry,
) -> ConfirmedResponse {
    let req = match GetVariableAccessAttributesRequest::decode(body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                invoke_id,
                error = %e,
                "get-variable-access-attributes request failed to decode, answering confirmed-error"
            );
            return make_confirmed_error(invoke_id, ErrorClass::Access(access::OTHER));
        }
    };

    #[cfg(any(feature = "reporting", feature = "logging", feature = "goose-mapping"))]
    let result = get_var_access_attrs::handle_get_var_access_attrs_with_control_blocks(
        mms_model,
        &req,
        &|domain, ln| {
            domain_control_blocks(
                domain,
                Some(ln),
                #[cfg(feature = "reporting")]
                reporting_engine,
                #[cfg(feature = "logging")]
                log_controls,
                #[cfg(feature = "goose-mapping")]
                gocb_registry,
            )
            .into_iter()
            .map(|(_, block)| block)
            .collect()
        },
    );
    #[cfg(not(any(feature = "reporting", feature = "logging", feature = "goose-mapping")))]
    let result = get_var_access_attrs::handle_get_var_access_attrs(mms_model, &req);

    match result {
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
                    make_confirmed_error(invoke_id, ErrorClass::Access(access::OTHER))
                }
            }
        }
        GetVarAccessAttrsResult::NotFound => {
            tracing::warn!(
                invoke_id,
                "get-variable-access-attributes: the path does not resolve, answering object-non-existent"
            );
            make_confirmed_error(invoke_id, ErrorClass::Access(access::OBJECT_NON_EXISTENT))
        }
        GetVarAccessAttrsResult::Unsupported => {
            tracing::warn!(
                invoke_id,
                "get-variable-access-attributes: this object name scope is not served"
            );
            make_confirmed_error(
                invoke_id,
                ErrorClass::Access(access::OBJECT_ACCESS_UNSUPPORTED),
            )
        }
    }
}

/// The access specification a ReadResponse carries: the one of the request
/// when it sets specificationWithResult, as ISO 9506-1 requires, and none
/// otherwise.
fn echoed_access_spec(
    req: &ReadRequest,
) -> Option<iec61850_mms::mms::pdu::common::VariableAccessSpecification> {
    req.specification_with_result
        .then(|| req.variable_access_spec.clone())
}

/// Bytes the list of access results of a ReadResponse may occupy: the budget
/// of [`pdu_budget_for_access_results`], less the echoed access specification
/// when the request asks for one.
fn read_results_budget(req: &ReadRequest, negotiated_max_pdu_size: Option<u32>) -> Option<usize> {
    let budget = pdu_budget_for_access_results(negotiated_max_pdu_size)?;
    if !req.specification_with_result {
        return Some(budget);
    }
    let mut spec = BytesMut::new();
    req.variable_access_spec.encode(&mut spec);
    // The echo sits inside a `[0]` wrapper whose tag and length take at most
    // four more bytes.
    Some(budget.saturating_sub(spec.len() + 4))
}

/// Dispatches a Read request (`0xa4`) with data set, control, reporting,
/// setting group, and GOOSE control block routing.
///
/// A read that expands a logical node or a functional-constraint group, and a
/// read that names a data set, track a byte budget as they go; exceeding the
/// negotiated maximum PDU size replaces the whole ReadResponse with a
/// ConfirmedError of errorClass resource other, as IEC 61850-8-1 requires,
/// rather than failing individual entries.
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
    negotiated_nesting_level: Option<u8>,
) -> ConfirmedResponse {
    let req = match ReadRequest::decode_with_negotiated_cap(body, negotiated_nesting_level) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                invoke_id,
                error = %e,
                "read request failed to decode, answering confirmed-error"
            );
            return make_confirmed_error(invoke_id, ErrorClass::Access(access::OTHER));
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
                        variable_access_spec: echoed_access_spec(&req),
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
            // A variable list name that does not resolve fails the whole
            // service rather than one access result: the list it names has no
            // members to answer for.
            let Some(dataset) = dataset_arc else {
                tracing::warn!(
                    invoke_id,
                    domain = key.0,
                    list = key.1,
                    "read: no such data set, answering object-non-existent"
                );
                return make_confirmed_error(
                    invoke_id,
                    ErrorClass::Access(access::OBJECT_NON_EXISTENT),
                );
            };

            // Each entry snapshots its value under the shared lock and is then
            // converted to wire data, after which the read handler of the member
            // applies exactly as on a direct read of it. One budget covers the
            // whole list of access results, derived from the same negotiated
            // maximum as the variable-list form of the request, so the same
            // values are refused at the same size whichever way the read names
            // them.
            use crate::service::convert::mms_value_to_mms_data;
            let mut remaining_budget = read_results_budget(&req, negotiated_max_pdu_size);
            let mut results: Vec<AccessResult> = Vec::with_capacity(dataset.entries.len());
            for entry in &dataset.entries {
                let baseline = match entry.read_value() {
                    Some(v) => AccessResult::Success(mms_value_to_mms_data(&v)),
                    None => AccessResult::Failure(DataAccessError::HardwareFault),
                };
                let result = match get_named_variable_list_attrs::split_attr_ref(&entry.attr_ref) {
                    Some((domain_id, item_id)) => apply_read_handler(
                        handler_registry,
                        mms_model,
                        conn_id,
                        &iec61850_mms::ObjectName::DomainSpecific { domain_id, item_id },
                        baseline,
                    ),
                    None => baseline,
                };
                if let Some(b) = remaining_budget.as_mut() {
                    let used = result.estimated_encoded_size();
                    if *b < used {
                        tracing::warn!(
                            invoke_id,
                            domain = key.0.as_str(),
                            list = key.1.as_str(),
                            "read: the data set values exceed the negotiated maximum PDU size, answering the whole request with a resource error"
                        );
                        return make_confirmed_error(
                            invoke_id,
                            ErrorClass::Resource(resource::OTHER),
                        );
                    }
                    *b -= used;
                }
                results.push(result);
            }
            let resp = ReadResponse {
                variable_access_spec: echoed_access_spec(&req),
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
                variable_access_spec: echoed_access_spec(&req),
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
    let mut remaining_budget = read_results_budget(&req, negotiated_max_pdu_size);

    let route = |name: &iec61850_mms::mms::pdu::common::ObjectName,
                 alt_access: Option<&iec61850_mms::mms::pdu::common::AlternateAccess>,
                 budget: Option<usize>| {
        handle_read_with_routing(
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
            name,
            alt_access,
            budget,
        )
    };

    let mut results: Vec<AccessResult> = Vec::with_capacity(entries.len());
    for entry in &entries {
        #[cfg(any(
            feature = "reporting",
            feature = "logging",
            feature = "setting-groups",
            feature = "goose-mapping"
        ))]
        let ln_read = read_ln_with_control_blocks(
            ied_model,
            #[cfg(feature = "setting-groups")]
            setting_groups,
            #[cfg(feature = "reporting")]
            reporting_engine,
            #[cfg(feature = "logging")]
            log_controls,
            #[cfg(feature = "goose-mapping")]
            gocb_registry,
            #[cfg(any(feature = "reporting", feature = "logging", feature = "goose-mapping"))]
            &route,
            &entry.name,
            entry.alt_access.as_ref(),
            remaining_budget,
        );
        #[cfg(not(any(
            feature = "reporting",
            feature = "logging",
            feature = "setting-groups",
            feature = "goose-mapping"
        )))]
        let ln_read: Option<ReadRoutingOutcome> = None;
        let outcome = match ln_read {
            Some(outcome) => outcome,
            None => route(&entry.name, entry.alt_access.as_ref(), remaining_budget),
        };
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
                        return make_confirmed_error(
                            invoke_id,
                            ErrorClass::Resource(resource::OTHER),
                        );
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
                return make_confirmed_error(invoke_id, ErrorClass::Resource(resource::OTHER));
            }
        }
    }

    let resp = ReadResponse {
        variable_access_spec: echoed_access_spec(&req),
        list_of_access_result: results,
    };
    let mut buf = BytesMut::new();
    encode_confirmed_read_response(invoke_id, &resp, &mut buf);
    ConfirmedResponse::Response(buf.freeze())
}

/// Reads one object name through the ordinary read routes, under an optional
/// alternate access and byte budget.
#[cfg(any(feature = "reporting", feature = "logging", feature = "goose-mapping"))]
type ReadRoute<'a> = dyn Fn(
        &iec61850_mms::mms::pdu::common::ObjectName,
        Option<&iec61850_mms::mms::pdu::common::AlternateAccess>,
        Option<usize>,
    ) -> ReadRoutingOutcome
    + 'a;

/// Reads a whole logical node, `LN`, or one of its functional-constraint
/// groups, `LN$FC`, with the control blocks the model view leaves out.
///
/// The setting group control block leads the SP group of a logical node that
/// declares one, and each control block of [`domain_control_blocks`] leads the
/// group of its functional constraint, in the layout
/// [`ln_spec_with_control_blocks`](crate::mapping::ln_spec_with_control_blocks)
/// gives GetVariableAccessAttributes. Each control block is read through its
/// own route, so its value is the one a read of the block alone returns, and a
/// control block that fails to read fails the whole entry.
///
/// `None` means the entry names something below a group, or carries an
/// alternate access, which the ordinary routes handle.
#[cfg(any(
    feature = "reporting",
    feature = "logging",
    feature = "setting-groups",
    feature = "goose-mapping"
))]
#[allow(clippy::too_many_arguments)]
fn read_ln_with_control_blocks(
    ied_model: &IedModel,
    #[cfg(feature = "setting-groups")] setting_groups: &crate::setting_groups::SettingGroupRegistry,
    #[cfg(feature = "reporting")] reporting_engine: &Arc<Mutex<ReportingEngine>>,
    #[cfg(feature = "logging")] log_controls: &LogControlRegistry,
    #[cfg(feature = "goose-mapping")] gocb_registry: &GoCBRegistry,
    #[cfg(any(feature = "reporting", feature = "logging", feature = "goose-mapping"))]
    route: &ReadRoute<'_>,
    name: &iec61850_mms::mms::pdu::common::ObjectName,
    alt_access: Option<&iec61850_mms::mms::pdu::common::AlternateAccess>,
    remaining_budget: Option<usize>,
) -> Option<ReadRoutingOutcome> {
    use crate::service::read::{read_ln_with_leading_members, LookupResult};
    use iec61850_mms::mms::pdu::common::{MmsData, ObjectName};

    let ObjectName::DomainSpecific { domain_id, item_id } = name else {
        return None;
    };
    if alt_access.is_some() {
        return None;
    }
    let domain = domain_id.as_str();

    let mut leading = |ln: &iec61850_model::LogicalNode,
                       fc: iec61850_model::FC|
     -> Result<Vec<MmsData>, DataAccessError> {
        let mut members = Vec::new();
        #[cfg(feature = "setting-groups")]
        if fc == iec61850_model::FC::Sp && ln.sgcb.is_some() {
            match crate::setting_groups::handle_sgcb_read(
                setting_groups,
                domain,
                "LLN0",
                crate::setting_groups::SgcbField::Whole,
            ) {
                AccessResult::Success(d) => members.push(d),
                AccessResult::Failure(e) => return Err(e),
            }
        }
        #[cfg(any(feature = "reporting", feature = "logging", feature = "goose-mapping"))]
        {
            let ln_name = format!("{}{}{}", ln.prefix, ln.class, ln.inst);
            let blocks = domain_control_blocks(
                domain,
                Some(&ln_name),
                #[cfg(feature = "reporting")]
                reporting_engine,
                #[cfg(feature = "logging")]
                log_controls,
                #[cfg(feature = "goose-mapping")]
                gocb_registry,
            );
            for (_, block) in blocks.iter().filter(|(_, b)| b.kind.fc() == fc) {
                let block_name = ObjectName::DomainSpecific {
                    domain_id: domain_id.clone(),
                    item_id: format!("{ln_name}${}${}", fc.as_str(), block.name),
                };
                match route(&block_name, None, None) {
                    ReadRoutingOutcome::Result(AccessResult::Success(d)) => members.push(d),
                    ReadRoutingOutcome::Result(AccessResult::Failure(e)) => return Err(e),
                    ReadRoutingOutcome::OverBudget => {
                        return Err(DataAccessError::ObjectAccessUnsupported)
                    }
                }
            }
        }
        Ok(members)
    };

    match read_ln_with_leading_members(ied_model, domain, item_id, &mut leading, remaining_budget)?
    {
        LookupResult::Result(r) => Some(ReadRoutingOutcome::Result(r)),
        LookupResult::OverBudget => Some(ReadRoutingOutcome::OverBudget),
    }
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
    negotiated_nesting_level: Option<u8>,
) -> ConfirmedResponse {
    use crate::service::read::{handle_single_read_with_budget, LookupResult};
    let req = match ReadRequest::decode_with_negotiated_cap(body, negotiated_nesting_level) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(invoke_id, error = %e, "read request failed to decode, answering confirmed-error");
            return make_confirmed_error(invoke_id, ErrorClass::Access(access::OTHER));
        }
    };
    let entries = match &req.variable_access_spec {
        iec61850_mms::mms::pdu::common::VariableAccessSpecification::ListOfVariable(v) => v.clone(),
        iec61850_mms::mms::pdu::common::VariableAccessSpecification::VariableListName(_) => {
            tracing::warn!(invoke_id, "read: data sets are not served in this build");
            let resp = ReadResponse {
                variable_access_spec: echoed_access_spec(&req),
                list_of_access_result: vec![AccessResult::Failure(
                    DataAccessError::ObjectAccessUnsupported,
                )],
            };
            let mut buf = BytesMut::new();
            encode_confirmed_read_response(invoke_id, &resp, &mut buf);
            return ConfirmedResponse::Response(buf.freeze());
        }
    };
    let mut remaining = read_results_budget(&req, negotiated_max_pdu_size);
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
                        return make_confirmed_error(
                            invoke_id,
                            ErrorClass::Resource(resource::OTHER),
                        );
                    }
                    *b -= used;
                }
                results.push(r);
            }
            LookupResult::OverBudget => {
                return make_confirmed_error(invoke_id, ErrorClass::Resource(resource::OTHER));
            }
        }
    }
    let resp = ReadResponse {
        variable_access_spec: echoed_access_spec(&req),
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
        Some(handle) => {
            let value = match da {
                None => encode_gocb_structure(&handle),
                Some(da_name) => encode_gocb_da(&handle, da_name),
            };
            Some(match value {
                Ok(data) => AccessResult::Success(data),
                Err(e) => AccessResult::Failure(e),
            })
        }
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
    negotiated_nesting_level: Option<u8>,
) -> ConfirmedResponse {
    let req = match WriteRequest::decode_with_negotiated_cap(body, negotiated_nesting_level) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                invoke_id,
                error = %e,
                "write request failed to decode, answering confirmed-error"
            );
            return make_confirmed_error(invoke_id, ErrorClass::Access(access::OTHER));
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

                // Each member is written exactly as if the client had named it
                // in a list of variables, so the functional constraint, the
                // write access policy, the handlers and the type check all apply
                // per member and one refused member leaves the others unaffected.
                let outcomes: Vec<WriteOutcome> = dataset
                    .entries
                    .iter()
                    .zip(req.list_of_data.iter())
                    .map(|(entry, data)| {
                        let Some((domain_id, item_id)) =
                            get_named_variable_list_attrs::split_attr_ref(&entry.attr_ref)
                        else {
                            tracing::warn!(
                                invoke_id,
                                attr_ref = %entry.attr_ref,
                                "write: data set member reference carries no domain separator, answering object-non-existent"
                            );
                            return WriteOutcome::Failure(DataAccessError::ObjectNonExistent);
                        };
                        let member = iec61850_mms::ObjectName::DomainSpecific { domain_id, item_id };
                        handle_write_with_routing(
                            ied_model,
                            mms_model,
                            policies,
                            #[cfg(feature = "control")]
                            control_objects,
                            reporting_engine,
                            handler_registry,
                            #[cfg(feature = "setting-groups")]
                            setting_groups,
                            #[cfg(feature = "goose-mapping")]
                            gocb_registry,
                            conn_id,
                            &member,
                            data,
                        )
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
    negotiated_nesting_level: Option<u8>,
) -> ConfirmedResponse {
    let req = match WriteRequest::decode_with_negotiated_cap(body, negotiated_nesting_level) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(invoke_id, error = %e, "write request failed to decode, answering confirmed-error");
            return make_confirmed_error(invoke_id, ErrorClass::Access(access::OTHER));
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
    let resp = IdentifyResponse::new(
        ident.vendor_name.as_str(),
        ident.model_name.as_str(),
        ident.revision.as_str(),
    );
    let mut buf = BytesMut::new();
    encode_confirmed_identify_response(invoke_id, &resp, &mut buf);
    ConfirmedResponse::Response(buf.freeze())
}

/// Dispatches a Status request (`0x80`), per ISO 9506-2.
///
/// The server answers `state-changes-allowed` and `operational` without
/// localDetail, whether or not extendedDerivation is requested. A request
/// whose BOOLEAN is malformed is answered with a ConfirmedError `access`
/// other.
fn dispatch_status(invoke_id: u32, body: &Bytes) -> ConfirmedResponse {
    if let Err(e) = decode_status_request(body) {
        tracing::warn!(
            invoke_id,
            error = %e,
            "status request failed to decode, answering confirmed-error"
        );
        return make_confirmed_error(invoke_id, ErrorClass::Access(access::OTHER));
    }
    let resp = StatusResponse::new(
        VmdLogicalStatus::StateChangesAllowed,
        VmdPhysicalStatus::Operational,
    );
    let mut buf = BytesMut::new();
    encode_confirmed_status_response(invoke_id, &resp, &mut buf);
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

/// Reads every attribute of a buffered report control block into one
/// structure, in the member order of
/// [`ControlBlockKind::Buffered`](crate::mapping::ControlBlockKind): RptID,
/// RptEna, DatSet, ConfRev, OptFlds, BufTm, SqNum, TrgOps, IntgPd, GI,
/// PurgeBuf, EntryID, TimeofEntry, ResvTms, and Owner.
///
/// An attribute that cannot be read fails the whole structure, so it is never
/// returned half-populated.
#[cfg(feature = "reporting")]
fn read_brcb_structure(engine: &Arc<Mutex<ReportingEngine>>, mms_path: &str) -> AccessResult {
    use crate::reporting::service::{handle_get_brcb_field, RcbField};
    use iec61850_mms::mms::pdu::common::MmsData;

    let fields = [
        RcbField::RptId,
        RcbField::RptEna,
        RcbField::DatSet,
        RcbField::ConfRev,
        RcbField::OptFlds,
        RcbField::BufTm,
        RcbField::SqNum,
        RcbField::TrgOps,
        RcbField::IntgPd,
        RcbField::Gi,
        RcbField::Unknown("PurgeBuf".into()),
        RcbField::EntryId,
        RcbField::Unknown("TimeofEntry".into()),
        RcbField::Unknown("ResvTms".into()),
        RcbField::Owner,
    ];
    let mut members: Vec<MmsData> = Vec::with_capacity(fields.len());
    for field in fields {
        let name = field.as_str().to_string();
        match handle_get_brcb_field(engine, mms_path, field) {
            Some(AccessResult::Success(d)) => members.push(d),
            Some(AccessResult::Failure(e)) => {
                tracing::warn!(
                    mms_path,
                    field = name,
                    ?e,
                    "read: a buffered report control block attribute could not be read"
                );
                return AccessResult::Failure(e);
            }
            None => {
                tracing::warn!(
                    mms_path,
                    field = name,
                    "read: a buffered report control block attribute has no value"
                );
                return AccessResult::Failure(DataAccessError::HardwareFault);
            }
        }
    }
    AccessResult::Success(MmsData::Structure(members))
}

/// The MMS components of a log control block, in the order of its MMS
/// structure (IEC 61850-8-1 log control block definition).
///
/// OldEntrTm, NewEntrTm, OldEnt and NewEnt report the oldest and newest entry
/// of the log behind the control block.
#[cfg(feature = "logging")]
const LCB_SERVED_FIELDS: [&str; 9] = [
    "LogEna",
    "LogRef",
    "DatSet",
    "OldEntrTm",
    "NewEntrTm",
    "OldEnt",
    "NewEnt",
    "TrgOps",
    "IntgPd",
];

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

/// The oldest and the newest entry of a log, as OldEntrTm, NewEntrTm, OldEnt
/// and NewEnt report them; `None` for an empty log or a control block with no
/// storage bound.
#[cfg(feature = "logging")]
type LogBounds = Option<(
    crate::logging::storage::EntryMeta,
    crate::logging::storage::EntryMeta,
)>;

/// The LogRef a log control block reports: the configured one, or the
/// default `<LD>/<LN>$GeneralLog` when none is configured.
///
/// The logical device is part of it because a LogRef is the reference a client
/// hands to ReadJournal, which resolves it by domain and item.
#[cfg(feature = "logging")]
fn effective_log_ref(
    state: &crate::logging::lcb::LogControlState,
    domain: &str,
    ln: &str,
) -> String {
    state
        .log_ref
        .clone()
        .unwrap_or_else(|| format!("{domain}/{ln}$GeneralLog"))
}

/// Reads one MMS component out of a log control block.
///
/// `domain` and `ln` supply the default LogRef. `bounds` supplies the four
/// components that describe the log: an EntryTime is a six-octet TimeOfDay,
/// and an EntryID eight octets; an empty log reports a zero time and an
/// all-zero EntryID for both its oldest and its newest entry. `None` means
/// `field` is not one of [`LCB_SERVED_FIELDS`].
#[cfg(feature = "logging")]
fn lcb_field_value(
    state: &crate::logging::lcb::LogControlState,
    bounds: LogBounds,
    domain: &str,
    ln: &str,
    field: &str,
) -> Option<iec61850_mms::mms::pdu::common::MmsData> {
    use iec61850_mms::mms::binary_time::binary_time6_from_epoch_ms;
    use iec61850_mms::mms::pdu::common::MmsData;
    let entry_time = |meta: Option<crate::logging::storage::EntryMeta>| {
        MmsData::BinaryTime(match meta {
            Some((_, time_ms)) => binary_time6_from_epoch_ms(time_ms).to_vec(),
            None => vec![0; 6],
        })
    };
    let entry_id = |meta: Option<crate::logging::storage::EntryMeta>| {
        MmsData::OctetString(meta.map_or([0; 8], |(id, _)| id.to_be_bytes()).to_vec())
    };
    Some(match field {
        "LogEna" => MmsData::Boolean(matches!(state.log_ena, crate::logging::LogState::Enabled)),
        "LogRef" => MmsData::VisibleString(effective_log_ref(state, domain, ln)),
        "DatSet" => MmsData::VisibleString(state.data_set.clone().unwrap_or_default()),
        "OldEntrTm" => entry_time(bounds.map(|(oldest, _)| oldest)),
        "NewEntrTm" => entry_time(bounds.map(|(_, newest)| newest)),
        "OldEnt" => entry_id(bounds.map(|(oldest, _)| oldest)),
        "NewEnt" => entry_id(bounds.map(|(_, newest)| newest)),
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
/// expect.
///
/// # Errors
///
/// Returns `TypeInconsistent` for a value type no control block field takes,
/// and `ObjectValueInvalid` for an unsigned value wider than 32 bits.
#[cfg(feature = "reporting")]
fn mms_data_to_rcb_write_value(
    data: &iec61850_mms::mms::pdu::common::MmsData,
) -> Result<crate::reporting::service::RcbWriteValue, DataAccessError> {
    use crate::reporting::service::RcbWriteValue;
    use iec61850_mms::mms::pdu::common::MmsData;
    match data {
        MmsData::Boolean(b) => Ok(RcbWriteValue::Bool(*b)),
        // No unsigned control block field is wider than 32 bits.
        MmsData::Unsigned(u) => u32::try_from(*u)
            .map(RcbWriteValue::Unsigned)
            .map_err(|_| DataAccessError::ObjectValueInvalid),
        MmsData::VisibleString(s) => Ok(RcbWriteValue::VisibleString(s.clone())),
        MmsData::BitString { padding, data } => {
            // The decoders expect [padding_byte, data_bytes...].
            let mut bytes = Vec::with_capacity(1 + data.len());
            bytes.push(*padding);
            bytes.extend_from_slice(data);
            Ok(RcbWriteValue::BitString(bytes))
        }
        MmsData::OctetString(b) => Ok(RcbWriteValue::OctetString(b.clone())),
        _ => Err(DataAccessError::TypeInconsistent),
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
            // A buffered control block answers the whole block or one of its
            // attributes; the URCB-only Resv answers object-access-unsupported
            // once the block is known to exist.
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
                let Some(field) = target.field.clone() else {
                    return ReadRoutingOutcome::Result(read_brcb_structure(
                        reporting_engine,
                        &target.mms_path,
                    ));
                };
                {
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
                    "read: this attribute is not served on a buffered report control block, and Resv is unbuffered-only"
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
            let field = field.map(crate::mapping::lcb_member_name);
            let describes_log = match field {
                None => true,
                Some(f) => matches!(f, "OldEntrTm" | "NewEntrTm" | "OldEnt" | "NewEnt"),
            };
            let bounds: LogBounds = match lc.storage.as_ref() {
                Some(storage) if describes_log => match storage.oldest_and_newest() {
                    Ok(bounds) => bounds,
                    Err(e) => {
                        tracing::warn!(
                            domain,
                            item,
                            error = %e,
                            "read: the log storage backend failed, answering hardware-fault"
                        );
                        return ReadRoutingOutcome::Result(AccessResult::Failure(
                            DataAccessError::HardwareFault,
                        ));
                    }
                },
                _ => None,
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
                // A whole-block read answers every component in structure order.
                None => AccessResult::Success(iec61850_mms::mms::pdu::common::MmsData::Structure(
                    LCB_SERVED_FIELDS
                        .iter()
                        .filter_map(|f| lcb_field_value(&state, bounds, domain, ln, f))
                        .collect(),
                )),
                Some(f) => match lcb_field_value(&state, bounds, domain, ln, f) {
                    Some(d) => AccessResult::Success(d),
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
            // A commit of the active group makes the edited values active.
            let commits_active_group = field == crate::setting_groups::SgcbField::CnfEdit
                && setting_groups.lookup(domain).is_some_and(|rt| {
                    let s = rt.snapshot();
                    s.edit_sg != 0 && s.edit_sg == s.act_sg
                });
            let outcome = crate::setting_groups::handle_sgcb_write(
                setting_groups,
                domain,
                ln,
                field,
                data,
                conn_id,
            );
            if commits_active_group && outcome == WriteOutcome::Success {
                crate::setting_groups::activate_edited_values(ied_model, domain);
            }
            return outcome;
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
                    use crate::reporting::service::handle_set_brcb_field_for_connection;
                    let rcb_value = match (field.as_str(), data) {
                        // ResvTms is an INT16; the field handler takes its
                        // non-negative range as an Unsigned.
                        ("ResvTms", iec61850_mms::mms::pdu::common::MmsData::Integer(i)) => {
                            i16::try_from(*i)
                                .ok()
                                .and_then(|v| u32::try_from(v).ok())
                                .map(crate::reporting::service::RcbWriteValue::Unsigned)
                                .ok_or(DataAccessError::ObjectValueInvalid)
                        }
                        _ => mms_data_to_rcb_write_value(data),
                    };
                    let rcb_value = match rcb_value {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!(
                                domain = target.domain,
                                mms_path = target.mms_path,
                                field = field.as_str(),
                                error = ?e,
                                "write: the value has no buffered report control block representation"
                            );
                            return WriteOutcome::Failure(e);
                        }
                    };
                    if let Some(res) = handle_set_brcb_field_for_connection(
                        reporting_engine,
                        &target.mms_path,
                        field,
                        rcb_value,
                        conn_id,
                    ) {
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
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        domain = target.domain,
                        mms_path = target.mms_path,
                        field = field.as_str(),
                        error = ?e,
                        "write: the value has no report control block representation"
                    );
                    return WriteOutcome::Failure(e);
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
                    // SBO exists only under the normal-security
                    // select-before-operate model, IEC 61850-8-1 Table 94, and
                    // only where the model declares it.
                    entry.object.bind_model(ied_model);
                    if crate::control::dispatch::sbo_absent(ied_model, domain, ln, do_name)
                        || entry.object.settings().ctl_model
                            != crate::control::ControlModel::SboNormal
                    {
                        tracing::warn!(
                            domain,
                            ln,
                            do_name,
                            "read: the control object has no SBO attribute, answering object-non-existent"
                        );
                        return ReadRoutingOutcome::Result(AccessResult::Failure(
                            DataAccessError::ObjectNonExistent,
                        ));
                    }
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

    // An alternate-access read bypasses the handler registry: a handler returns
    // a whole-attribute value without the model template, leaving no way to
    // apply a component path to its output. The baseline above already resolved
    // the selector against the model-typed attribute, so it is used directly.
    if alt_access.is_some() {
        return ReadRoutingOutcome::Result(baseline);
    }

    ReadRoutingOutcome::Result(apply_read_handler(
        handler_registry,
        mms_model,
        conn_id,
        name,
        baseline,
    ))
}

/// Passes the model value read for `name` through the read handler installed
/// on its attribute path, if any.
///
/// A cache hit replaces `baseline`, a miss keeps it, and an error replaces it
/// with that error. With `ignore_read_access` set, or for a name that is not a
/// handler path, `baseline` is returned unchanged. Every service that returns
/// the value of a data attribute goes through this, so an access decision a
/// handler makes holds whichever service names the attribute.
#[cfg(any(
    feature = "reporting",
    feature = "control",
    feature = "setting-groups",
    feature = "goose-mapping",
    feature = "logging"
))]
fn apply_read_handler(
    handler_registry: &HandlerRegistry,
    mms_model: &MmsDeviceModel,
    conn_id: u64,
    name: &iec61850_mms::mms::pdu::common::ObjectName,
    baseline: AccessResult,
) -> AccessResult {
    if handler_registry.ignore_read_access() {
        return baseline;
    }
    let canonical_path = match read_path_canonical_from_object_name(name) {
        Some(p) => p,
        // Not a canonicalizable domain-specific path, so out of registry scope.
        None => return baseline,
    };
    let handler = match handler_registry.lookup_read(&canonical_path) {
        Some(h) => h,
        None => return baseline,
    };
    let fc = match fc_from_canonical_path(&canonical_path) {
        Some(f) => f,
        None => return baseline,
    };
    let ctx = ReadContext {
        path: &canonical_path,
        fc,
        conn_id,
    };
    match handler.read(&ctx) {
        ReadOutcome::CacheHit(value) => {
            if handler_bit_string_fits(mms_model, name, &value) {
                AccessResult::Success(crate::service::convert::mms_value_to_mms_data(&value))
            } else {
                tracing::warn!(
                    path = %canonical_path,
                    "read: the read handler returned a bit string that does not fit the data attribute, answering object-value-invalid"
                );
                AccessResult::Failure(DataAccessError::ObjectValueInvalid)
            }
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
    }
}

/// Reports whether a value a read handler supplies may be sent for `name`: a
/// bit string must fit the declared size of a bit-string attribute, and any
/// other value passes.
#[cfg(any(
    feature = "reporting",
    feature = "control",
    feature = "setting-groups",
    feature = "goose-mapping",
    feature = "logging"
))]
fn handler_bit_string_fits(
    mms_model: &MmsDeviceModel,
    name: &iec61850_mms::mms::pdu::common::ObjectName,
    value: &iec61850_model::MmsValue,
) -> bool {
    use crate::mapping::{bit_string_fits, MmsLeafType, MmsTypeSpec};
    use iec61850_mms::mms::pdu::common::ObjectName;
    let iec61850_model::MmsValue::BitString { padding, data } = value else {
        return true;
    };
    let ObjectName::DomainSpecific { domain_id, item_id } = name else {
        return true;
    };
    match mms_model.spec_at(domain_id, item_id) {
        Some(MmsTypeSpec::Leaf(MmsLeafType::BitString(size))) => {
            bit_string_fits(*size, data.len(), *padding)
        }
        _ => true,
    }
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
/// The control service checks the value and admits the request inline and runs
/// an accepted command on its own task, so this path never blocks; see the
/// `control` module for how the outcome reaches the client.
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
        use crate::control::dispatch::{add_cause_to_data_access_error, CoTarget, CoWriteResult};
        use crate::control::CoAttr;
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

            if attr == CoAttr::Sbo {
                // A select through SBO is issued as a read.
                tracing::warn!(
                    domain,
                    ln,
                    do_name,
                    "write: SBO is read, not written, answering object-access-unsupported"
                );
                return WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported);
            }

            let value = mms_data_to_mms_value(data);
            let target = CoTarget {
                domain,
                ln_name: ln,
                do_name,
                attr: attr.clone(),
            };
            return match crate::control::dispatch::write(
                control_objects,
                ied_model,
                &entry,
                conn_id,
                &target,
                &value,
            ) {
                CoWriteResult::Accepted => WriteOutcome::Success,
                CoWriteResult::TypeInconsistent => {
                    WriteOutcome::Failure(DataAccessError::TypeInconsistent)
                }
                CoWriteResult::NonExistent => {
                    WriteOutcome::Failure(DataAccessError::ObjectNonExistent)
                }
                CoWriteResult::Refused(cause) => {
                    tracing::warn!(
                        domain,
                        ln,
                        do_name,
                        ?attr,
                        ?cause,
                        "write: the control service refused the command"
                    );
                    WriteOutcome::Failure(add_cause_to_data_access_error(cause))
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

// ─────────────────────────────────────────────────────────────────────────────
// Encoding helpers
// ─────────────────────────────────────────────────────────────────────────────

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

/// Resolves the journal a ReadJournal request names to the log control block
/// whose log it reads.
///
/// A registry key equal to `(domain, item)` wins, so a control block registered
/// under its own path, or under a log instance name, answers to that name.
/// Otherwise the journal is the log a control block's LogRef names: a LogRef
/// `<domain>/<item>` maps to the MMS journal `item` of domain `domain`. When
/// several control blocks name the same log, the first by registry key that
/// has a storage backend bound is chosen, or the first by key when none has.
#[cfg(feature = "logging")]
fn resolve_journal(
    registry: &std::collections::HashMap<(String, String), Arc<LogControl>>,
    domain: &str,
    item: &str,
) -> Option<Arc<LogControl>> {
    if let Some(lc) = registry.get(&(domain.to_string(), item.to_string())) {
        return Some(Arc::clone(lc));
    }
    let wanted = format!("{domain}/{item}");
    let mut named: Vec<(&(String, String), &Arc<LogControl>)> = registry
        .iter()
        .filter(|((d, it), lc)| {
            is_lcb_path(it) && log_ref_of(lc, d, it).as_deref() == Some(wanted.as_str())
        })
        .collect();
    named.sort_by(|a, b| a.0.cmp(b.0));
    named
        .iter()
        .find(|(_, lc)| lc.storage.is_some())
        .or_else(|| named.first())
        .map(|(_, lc)| Arc::clone(lc))
}

/// The LogRef of the control block registered under `(domain, item)`, or
/// `None` when its state is unavailable.
#[cfg(feature = "logging")]
fn log_ref_of(lc: &LogControl, domain: &str, item: &str) -> Option<String> {
    let ln = item.split('$').next().unwrap_or_default();
    lc.state
        .lock()
        .ok()
        .map(|state| effective_log_ref(&state, domain, ln))
}

/// Names of the journals of `domain`, as GetNameList reports them for the
/// Journal object class: the log each control block's LogRef names within
/// the domain, and each registry key that is a log instance name rather than
/// a control block path. Sorted, without duplicates.
///
/// A poisoned registry lock yields no name.
#[cfg(feature = "logging")]
fn journal_names_in_domain(log_controls: &LogControlRegistry, domain: &str) -> Vec<String> {
    let Ok(registry) = log_controls.read() else {
        tracing::warn!(
            domain = %domain,
            "get-name-list: the log control registry lock is poisoned, no journal is listed"
        );
        return Vec::new();
    };
    let mut names: Vec<String> = registry
        .iter()
        .filter_map(|((d, item), lc)| {
            if is_lcb_path(item) {
                let log_ref = log_ref_of(lc, d, item)?;
                let (log_domain, log_item) = log_ref.split_once('/')?;
                (log_domain == domain && !log_item.is_empty()).then(|| log_item.to_string())
            } else {
                (d == domain).then(|| item.clone())
            }
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Dispatches a ReadJournal request (`0xbf 0x41`).
///
/// The request names a journal by domain and item, which [`resolve_journal`]
/// maps to a log control block; the range selects either a time window or a
/// cursor position, and the matching entries are encoded into a
/// ReadJournalResponse.
///
/// # Errors
///
/// A request that fails to decode, and a storage backend that fails, both
/// answer with a ConfirmedError of class access; a journal that resolves to
/// no log control block answers object-non-existent.
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
            return make_confirmed_error(invoke_id, ErrorClass::Access(access::OTHER));
        }
    };

    let lc = match log_controls.read() {
        Ok(g) => resolve_journal(&g, &req.domain_id, &req.item_id),
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
            "read-journal: no such journal, answering object-non-existent"
        );
        return make_confirmed_error(invoke_id, ErrorClass::Access(access::OBJECT_NON_EXISTENT));
    };

    // A log control block with no storage attached yields an empty list.
    let mut visitor =
        BudgetedJournalVisitor::new(invoke_id, read_journal_budget(negotiated_max_pdu_size));
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
        return make_confirmed_error(invoke_id, ErrorClass::Access(access::OTHER));
    }

    let BudgetedJournalVisitor {
        accepted,
        more_follows,
        ..
    } = visitor;

    let resp = ReadJournalResponse {
        entries: accepted,
        more_follows: Some(more_follows),
    };

    let mut buf = BytesMut::new();
    encode_confirmed_read_journal_response(invoke_id, &resp, &mut buf);
    ConfirmedResponse::Response(buf.freeze())
}

/// Collects the journal entries of one ReadJournal response while they fit the
/// PDU budget.
///
/// Each entry is converted and measured as it is visited, and the walk stops
/// at the first entry that does not fit, so a query holds one response worth
/// of entries rather than every matching entry. Even a first entry larger than
/// the whole budget stops the walk with `more_follows` set, so the client never
/// mistakes a truncated result for a complete one.
#[cfg(feature = "logging")]
struct BudgetedJournalVisitor {
    invoke_id: u32,
    budget: usize,
    baseline: usize,
    consumed: usize,
    accepted: Vec<WireJournalEntry>,
    more_follows: bool,
}

#[cfg(feature = "logging")]
impl BudgetedJournalVisitor {
    fn new(invoke_id: u32, budget: usize) -> Self {
        Self {
            invoke_id,
            budget,
            baseline: empty_response_baseline(),
            consumed: 0,
            accepted: Vec::new(),
            more_follows: false,
        }
    }
}

#[cfg(feature = "logging")]
impl crate::logging::LogEntryVisitor for BudgetedJournalVisitor {
    fn visit(&mut self, entry: &crate::logging::JournalEntry) -> bool {
        let wire = journal_entry_to_wire(entry);
        let entry_size = estimate_entry_wire_size(&wire, self.baseline);
        if self.consumed + entry_size > self.budget {
            tracing::warn!(
                invoke_id = self.invoke_id,
                budget = self.budget,
                consumed = self.consumed,
                entry_size,
                accepted = self.accepted.len(),
                "read-journal: the PDU budget is spent, truncating and setting moreFollows"
            );
            self.more_follows = true;
            return false;
        }
        self.consumed += entry_size;
        self.accepted.push(wire);
        true
    }
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
fn journal_entry_to_wire(entry: &crate::logging::JournalEntry) -> WireJournalEntry {
    WireJournalEntry {
        entry_id: entry.entry_id.to_be_bytes(),
        occurence_time_ms: entry.time_ms,
        variables: entry
            .variables
            .iter()
            .map(|v| WireJournalVariable {
                data_ref: v.data_ref.clone(),
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
    make_confirmed_error(
        invoke_id,
        ErrorClass::Access(access::OBJECT_ACCESS_UNSUPPORTED),
    )
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
    use super::{
        compute_services_supported, MmsModelDispatcher, SERVICES_JOURNAL_BYTE,
        SERVICES_READ_JOURNAL_BIT,
    };
    use crate::compat::Arc;
    use crate::mapping::MmsDeviceModel;
    use crate::policy::WriteAccessPolicies;
    use iec61850_mms::mms::server::dispatcher::MmsServiceDispatcher;
    use iec61850_model::{IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder};

    /// The eight combinations of the three subsystem flags, as
    /// `(reporting, control, logging)`.
    const ALL_BUILDS: [(bool, bool, bool); 8] = [
        (true, true, true),
        (true, true, false),
        (true, false, true),
        (true, false, false),
        (false, true, true),
        (false, true, false),
        (false, false, true),
        (false, false, false),
    ];

    /// getNamedVariableListAttributes (`0xac`) is answered from the data set
    /// registry, so it is advertised exactly when the reporting subsystem is
    /// compiled in.
    #[test]
    fn reporting_gates_get_nvl_attributes() {
        for (reporting, control, logging) in ALL_BUILDS {
            assert_eq!(
                compute_services_supported(reporting, control, logging)[1] & 0x08,
                if reporting { 0x08 } else { 0 },
                "getNamedVariableListAttributes is advertised exactly in a reporting build"
            );
        }
    }

    /// Data set creation, deletion and directory belong to the reporting
    /// subsystem and are advertised only when it is enabled: a client enables
    /// its own data set paths from this bitmap, and advertising a service that
    /// is not implemented leads it into a request that can only fail.
    #[test]
    fn reporting_gates_dataset_crud() {
        for (reporting, control, logging) in ALL_BUILDS {
            let map = compute_services_supported(reporting, control, logging);
            assert_eq!(
                map[1] & 0x10,
                if reporting { 0x10 } else { 0 },
                "defineNamedVariableList is advertised exactly in a reporting build"
            );
            assert_eq!(
                map[1] & 0x04,
                if reporting { 0x04 } else { 0 },
                "deleteNamedVariableList is advertised exactly in a reporting build"
            );
        }
    }

    /// The reporting subsystem sends reports and the control subsystem sends
    /// `LastApplError` and command terminations, all as InformationReport, so
    /// the bit is advertised when either is compiled in and only then.
    #[test]
    fn information_report_follows_reporting_or_control() {
        for (reporting, control, logging) in ALL_BUILDS {
            assert_eq!(
                compute_services_supported(reporting, control, logging)[9] & 0x01,
                if reporting || control { 0x01 } else { 0 },
                "informationReport with reporting={reporting}, control={control}, logging={logging}"
            );
        }
    }

    /// The dispatcher of this build announces `informationReport` exactly
    /// when the build can send one.
    #[test]
    fn dispatcher_announces_information_report_when_it_sends_one() {
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(LogicalNodeBuilder::lln0().build().unwrap())
            .build()
            .unwrap();
        let model = IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap();
        let mms_model = MmsDeviceModel::from_ied_model(&model).unwrap();
        let dispatcher = MmsModelDispatcher::new(
            Arc::new(model),
            Arc::new(mms_model),
            Arc::new(WriteAccessPolicies::default()),
        );
        assert_eq!(
            dispatcher.services_supported()[9] & 0x01 != 0,
            cfg!(any(feature = "reporting", feature = "control")),
            "informationReport is announced exactly when reporting or control is compiled in"
        );
    }

    /// `readJournal` belongs to the logging subsystem, which serves
    /// QueryLogByTime and QueryLogAfter through it. Withholding the bit from a
    /// build that serves the service leaves both queries unreachable for a
    /// client that enables its own paths from this bitmap.
    #[test]
    fn logging_gates_read_journal() {
        for (reporting, control, _) in ALL_BUILDS {
            let with = compute_services_supported(reporting, control, true);
            assert_eq!(
                with[SERVICES_JOURNAL_BYTE] & SERVICES_READ_JOURNAL_BIT,
                SERVICES_READ_JOURNAL_BIT,
                "a logging build must advertise readJournal"
            );

            let without = compute_services_supported(reporting, control, false);
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
        for (reporting, control, logging) in ALL_BUILDS {
            let map = compute_services_supported(reporting, control, logging);
            assert_eq!(
                map[SERVICES_JOURNAL_BYTE] & !SERVICES_READ_JOURNAL_BIT,
                0,
                "readJournal is the only service advertised in its byte, writeJournal included"
            );
        }
    }

    /// Every build answers status and none answers cancel, so status is
    /// advertised and cancel is not.
    #[test]
    fn advertises_status_never_cancel() {
        for (reporting, control, logging) in ALL_BUILDS {
            let map = compute_services_supported(reporting, control, logging);
            assert_eq!(
                map[0] & 0x80,
                0x80,
                "status has a handler in every build and must be advertised"
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
        for (reporting, control, logging) in ALL_BUILDS {
            let map = compute_services_supported(reporting, control, logging);
            assert_eq!(
                map[0], 0xee,
                "status, get-name-list, identify, read, write and get-variable-access-attributes are advertised"
            );
            assert_eq!(map[10], 0x10, "conclude is advertised, cancel is not");
        }
    }

    /// The whole bitmap, byte for byte, at both extremes, so that adding a
    /// service without adjusting the announcement fails here.
    #[test]
    fn full_bitmap_is_bit_exact() {
        assert_eq!(
            compute_services_supported(true, true, true),
            [0xee, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x10],
            "a build with reporting, control and logging"
        );
        assert_eq!(
            compute_services_supported(false, true, false),
            [0xee, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x10],
            "a build with control alone"
        );
        assert_eq!(
            compute_services_supported(false, false, false),
            [0xee, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10],
            "a build with none of the three"
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
        let totw_do = DataObject::new("TotW", vec![DoChild::Da(mag_da)]);
        let mod_do = DataObject::new("Mod", vec![DoChild::Da(ctl_da)]);
        let mmxu_ln = iec61850_model::LogicalNode::new(String::new(), "MMXU", "1", vec![totw_do]);
        let ggio_ln = iec61850_model::LogicalNode::new(String::new(), "GGIO", "1", vec![mod_do]);
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
    /// a dead end, without the second it waits forever. `0xa3` is Rename,
    /// which no build serves.
    #[test]
    fn dispatcher_unadvertised_services_return_reject_not_silence() {
        let dispatcher = build_dispatcher();
        let conn = make_conn();
        let req = ConfirmedRequest {
            invoke_id: 7,
            service_body: Bytes::copy_from_slice(&[0xa3, 0x00]),
        };
        let resp = dispatcher.dispatch(&conn, req);
        assert!(
            matches!(resp, ConfirmedResponse::Reject),
            "rename must be rejected, neither ignored nor panicked on"
        );
    }

    /// Status (`0x80`) reaches its handler and answers the state the server
    /// holds, for both values of extendedDerivation.
    #[test]
    fn dispatcher_status_returns_response() {
        use iec61850_mms::mms::pdu::status::decode_confirmed_status_response;

        let dispatcher = build_dispatcher();
        let conn = make_conn();
        for flag in [0x00u8, 0xff] {
            let req = ConfirmedRequest {
                invoke_id: 9,
                service_body: Bytes::copy_from_slice(&[0x80, 0x01, flag]),
            };
            match dispatcher.dispatch(&conn, req) {
                ConfirmedResponse::Response(bytes) => {
                    assert_eq!(
                        &bytes[..],
                        &[
                            0xa1, 0x0b, 0x02, 0x01, 0x09, 0xa0, 0x06, 0x80, 0x01, 0x00, 0x81, 0x01,
                            0x00,
                        ],
                        "state-changes-allowed and operational, no localDetail"
                    );
                    let (id, resp) = decode_confirmed_status_response(&bytes).unwrap();
                    assert_eq!(id, 9);
                    assert_eq!(resp.logical_status, VmdLogicalStatus::StateChangesAllowed);
                    assert_eq!(resp.physical_status, VmdPhysicalStatus::Operational);
                    assert_eq!(resp.local_detail, None);
                }
                other => panic!("status must answer with a response, got {:?}", other),
            }
        }
    }

    /// A Status request whose BOOLEAN is not one octet is answered with a
    /// ConfirmedError rather than a status.
    #[test]
    fn dispatcher_malformed_status_returns_confirmed_error() {
        let dispatcher = build_dispatcher();
        let conn = make_conn();
        let req = ConfirmedRequest {
            invoke_id: 7,
            service_body: Bytes::copy_from_slice(&[0x80, 0x00]),
        };
        assert!(
            matches!(dispatcher.dispatch(&conn, req), ConfirmedResponse::Error(_)),
            "a malformed status request must be answered with a confirmed error"
        );
    }

    /// GetNamedVariableListAttributes (`0xac`) reaches its handler rather than
    /// the unknown-tag arm: a malformed body is answered with a
    /// ConfirmedError, and a well-formed request for a data set that is not
    /// registered with `object-non-existent` rather than an empty member list.
    #[cfg(feature = "reporting")]
    #[test]
    fn dispatcher_get_nvl_attrs_is_routed_to_its_handler() {
        use iec61850_mms::mms::pdu::get_named_variable_list_attrs::GetNamedVariableListAttributesRequest;

        let dispatcher = build_dispatcher();
        let conn = make_conn();

        let malformed = dispatcher.dispatch(
            &conn,
            ConfirmedRequest {
                invoke_id: 7,
                service_body: Bytes::copy_from_slice(&[0xac, 0x00]),
            },
        );
        assert!(
            matches!(malformed, ConfirmedResponse::Error(_)),
            "a malformed 0xac body must produce a confirmed error"
        );

        let mut body = BytesMut::new();
        GetNamedVariableListAttributesRequest::domain("IED1LD0", "GGIO1$ds_absent")
            .encode(&mut body);
        let unknown = dispatcher.dispatch(
            &conn,
            ConfirmedRequest {
                invoke_id: 8,
                service_body: body.freeze(),
            },
        );
        assert!(
            matches!(unknown, ConfirmedResponse::Error(_)),
            "an unregistered data set must produce a confirmed error"
        );
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
        conn.set_negotiated({
            let mut params = NegotiatedParams::default();
            params.max_pdu_size = 32;
            params
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

    // ── SetDataSetValues ─────────────────────────────────────────────

    /// Sends a Write and decodes its per-entry outcomes.
    #[cfg(feature = "reporting")]
    fn write_outcomes(
        dispatcher: &MmsModelDispatcher,
        req: &iec61850_mms::mms::pdu::write::WriteRequest,
    ) -> Vec<WriteOutcome> {
        use iec61850_mms::mms::pdu::write::encode_confirmed_write_request;

        let mut full_buf = BytesMut::new();
        encode_confirmed_write_request(11, req, &mut full_buf);
        let req = ConfirmedRequest {
            invoke_id: 11,
            service_body: extract_service_body_from_confirmed_request(&full_buf),
        };
        match dispatcher.dispatch(&make_conn(), req) {
            ConfirmedResponse::Response(bytes) => {
                let body = extract_service_body_from_confirmed_request(&BytesMut::from(&bytes[..]));
                WriteResponse::decode(&body)
                    .expect("the write response must decode")
                    .outcomes
            }
            other => panic!("write must answer with a response, got {:?}", other),
        }
    }

    /// Registers `IED1LD0/GGIO1$dsw` over the model's read-only `TotW.mag`
    /// (MX) and writable `Mod.ctlModel` (CF), sharing their value locks.
    #[cfg(feature = "reporting")]
    fn register_mixed_dataset(dispatcher: &MmsModelDispatcher) {
        crate::reporting::DynamicDatasetOps::add_dynamic(
            &dispatcher.dataset_registry,
            &dispatcher.model,
            "IED1LD0",
            "GGIO1$dsw",
            vec![
                ("IED1LD0".into(), "MMXU1$MX$TotW$mag".into()),
                ("IED1LD0".into(), "GGIO1$CF$Mod$ctlModel".into()),
            ],
        )
        .expect("the data set must resolve against the model");
    }

    #[cfg(feature = "reporting")]
    fn dataset_values(dispatcher: &MmsModelDispatcher) -> Vec<MmsValue> {
        let registry = dispatcher.dataset_registry.read().unwrap();
        registry
            .get(&("IED1LD0".to_string(), "GGIO1$dsw".to_string()))
            .expect("the data set is registered")
            .entries
            .iter()
            .map(|e| e.read_value().expect("the value lock is usable"))
            .collect()
    }

    #[cfg(feature = "reporting")]
    fn set_data_set_values(values: Vec<MmsData>) -> iec61850_mms::mms::pdu::write::WriteRequest {
        use iec61850_mms::mms::pdu::common::VariableAccessSpecification;
        iec61850_mms::mms::pdu::write::WriteRequest {
            variable_access_spec: VariableAccessSpecification::VariableListName(
                iec61850_mms::ObjectName::DomainSpecific {
                    domain_id: "IED1LD0".into(),
                    item_id: "GGIO1$dsw".into(),
                },
            ),
            list_of_data: values,
        }
    }

    /// SetDataSetValues writes each member through the single-write checks: a
    /// member under a functional constraint the write access policy refuses
    /// keeps its value and is answered as a Write naming it alone would be,
    /// while a writable member in the same request is updated.
    #[cfg(feature = "reporting")]
    #[test]
    fn set_data_set_values_applies_member_write_access() {
        use iec61850_mms::mms::pdu::write::WriteRequest;

        let dispatcher = build_dispatcher();
        register_mixed_dataset(&dispatcher);

        let outcomes = write_outcomes(
            &dispatcher,
            &set_data_set_values(vec![MmsData::Float32(9.5), MmsData::Integer(2)]),
        );
        let single = write_outcomes(
            &dispatcher,
            &WriteRequest::single_domain("IED1LD0", "MMXU1$MX$TotW$mag", MmsData::Float32(9.5)),
        );
        assert_eq!(outcomes.len(), 2);
        assert_eq!(
            outcomes[0], single[0],
            "a read-only member must be answered as a single write of it is"
        );
        assert!(matches!(outcomes[0], WriteOutcome::Failure(_)));
        assert_eq!(outcomes[1], WriteOutcome::Success);
        assert_eq!(
            dataset_values(&dispatcher),
            vec![MmsValue::Float32(1.23), MmsValue::Integer(2)],
            "only the writable member changes"
        );
    }

    /// A SetDataSetValues value whose type does not match its member is
    /// refused for that member and leaves the model untouched.
    #[cfg(feature = "reporting")]
    #[test]
    fn set_data_set_values_refuses_a_mistyped_member() {
        let dispatcher = build_dispatcher();
        register_mixed_dataset(&dispatcher);

        let outcomes = write_outcomes(
            &dispatcher,
            &set_data_set_values(vec![
                MmsData::Float32(1.23),
                MmsData::VisibleString("x".into()),
            ]),
        );
        assert!(
            matches!(outcomes[1], WriteOutcome::Failure(_)),
            "a string written to an integer member must fail, got {:?}",
            outcomes[1]
        );
        assert_eq!(
            dataset_values(&dispatcher)[1],
            MmsValue::Integer(0),
            "a refused member keeps its value"
        );
    }

    // ── DefineNamedVariableList limits ───────────────────────────────

    /// A dispatcher whose run-time data sets are limited to `max_total` across
    /// the server and `max_per_association` per association.
    #[cfg(feature = "reporting")]
    fn dispatcher_with_quota(max_total: usize, max_per_association: usize) -> MmsModelDispatcher {
        build_dispatcher().with_dynamic_dataset_quota(Arc::new(
            define_named_variable_list::DynamicDatasetQuota::new(max_total, max_per_association),
        ))
    }

    /// Sends DefineNamedVariableList for `IED1LD0/GGIO1$<name>` over one member
    /// on the association `conn_id`.
    #[cfg(feature = "reporting")]
    fn define_dataset(
        dispatcher: &MmsModelDispatcher,
        conn_id: u64,
        name: &str,
    ) -> ConfirmedResponse {
        use iec61850_mms::mms::pdu::define_named_variable_list::{
            encode_confirmed_define_named_variable_list_request, DefineNamedVariableEntry,
            DefineNamedVariableListRequest,
        };

        let req = DefineNamedVariableListRequest::domain(
            "IED1LD0",
            format!("GGIO1${name}"),
            vec![DefineNamedVariableEntry::domain(
                "IED1LD0",
                "GGIO1$CF$Mod$ctlModel",
            )],
        );
        let mut full = BytesMut::new();
        encode_confirmed_define_named_variable_list_request(21, &req, &mut full)
            .expect("the request encodes");
        let mut conn = make_conn();
        conn.set_connection_id(conn_id);
        dispatcher.dispatch(
            &conn,
            ConfirmedRequest {
                invoke_id: 21,
                service_body: extract_service_body_from_confirmed_request(&full),
            },
        )
    }

    #[cfg(feature = "reporting")]
    fn assert_defined(resp: ConfirmedResponse) {
        assert!(
            matches!(resp, ConfirmedResponse::Response(_)),
            "the data set must be created, got {:?}",
            resp
        );
    }

    #[cfg(feature = "reporting")]
    fn assert_capability_unavailable(resp: ConfirmedResponse) {
        use iec61850_mms::mms::pdu::service_error::decode_confirmed_error_pdu;

        match resp {
            ConfirmedResponse::Error(bytes) => {
                let (_, service_error) =
                    decode_confirmed_error_pdu(&bytes).expect("the confirmed error must decode");
                assert_eq!(
                    service_error.error_class,
                    ErrorClass::Resource(resource::CAPABILITY_UNAVAILABLE)
                );
            }
            other => panic!("expected capability-unavailable, got {:?}", other),
        }
    }

    /// One association can create only `max_per_association` data sets while
    /// another still can, and deleting one of them, from any association, lets
    /// it create another.
    #[cfg(feature = "reporting")]
    #[test]
    fn define_named_variable_list_is_bounded_per_association() {
        let dispatcher = dispatcher_with_quota(8, 2);
        assert_defined(define_dataset(&dispatcher, 1, "a1"));
        assert_defined(define_dataset(&dispatcher, 1, "a2"));
        assert_capability_unavailable(define_dataset(&dispatcher, 1, "a3"));
        assert_defined(define_dataset(&dispatcher, 2, "b1"));

        assert!(matches!(
            delete_dataset(&dispatcher, "a1"),
            ConfirmedResponse::Response(_)
        ));
        assert_defined(define_dataset(&dispatcher, 1, "a3"));
    }

    /// Sends DeleteNamedVariableList for `IED1LD0/GGIO1$<name>`.
    #[cfg(feature = "reporting")]
    fn delete_dataset(dispatcher: &MmsModelDispatcher, name: &str) -> ConfirmedResponse {
        use iec61850_mms::mms::pdu::delete_named_variable_list::{
            encode_confirmed_delete_named_variable_list_request, DeleteNamedVariableListRequest,
        };

        let mut full = BytesMut::new();
        encode_confirmed_delete_named_variable_list_request(
            22,
            &DeleteNamedVariableListRequest::specific_domain("IED1LD0", format!("GGIO1${name}")),
            &mut full,
        );
        dispatcher.dispatch(
            &make_conn(),
            ConfirmedRequest {
                invoke_id: 22,
                service_body: extract_service_body_from_confirmed_request(&full),
            },
        )
    }

    /// The run-time data sets across all associations stop at `max_total`, and
    /// deleting one makes room for another.
    #[cfg(feature = "reporting")]
    #[test]
    fn define_named_variable_list_is_bounded_in_total() {
        let dispatcher = dispatcher_with_quota(2, 8);
        assert_defined(define_dataset(&dispatcher, 1, "d1"));
        assert_defined(define_dataset(&dispatcher, 2, "d2"));
        assert_capability_unavailable(define_dataset(&dispatcher, 3, "d3"));
        assert_eq!(dispatcher.dataset_registry.read().unwrap().len(), 2);

        assert!(matches!(
            delete_dataset(&dispatcher, "d1"),
            ConfirmedResponse::Response(_)
        ));
        assert_defined(define_dataset(&dispatcher, 3, "d3"));
    }

    // ── Negotiated nesting level ─────────────────────────────────────

    /// A connection that has negotiated `level` as its
    /// dataStructureNestingLevel.
    fn conn_with_nesting(level: u8) -> MmsServerConnection {
        use iec61850_mms::mms::server::connection::NegotiatedParams;

        let mut conn = MmsServerConnection::new();
        conn.set_negotiated({
            let mut params = NegotiatedParams::default();
            params.data_structure_nesting_level = level;
            params
        });
        conn
    }

    fn is_decode_error(resp: &ConfirmedResponse) -> bool {
        use iec61850_mms::mms::pdu::service_error::decode_confirmed_error_pdu;

        match resp {
            ConfirmedResponse::Error(bytes) => {
                let (_, service_error) =
                    decode_confirmed_error_pdu(bytes).expect("the confirmed error must decode");
                service_error.error_class == ErrorClass::Access(access::OTHER)
            }
            _ => false,
        }
    }

    /// A Read whose alternate access nests deeper than the negotiated
    /// dataStructureNestingLevel is refused as undecodable, and the same
    /// request is served on an association that negotiated a deeper level.
    #[test]
    fn read_alternate_access_is_bounded_by_the_negotiated_nesting_level() {
        use iec61850_mms::mms::pdu::common::VariableAccessSpecification;
        use iec61850_mms::mms::pdu::common::{AlternateAccess, ListOfVariableEntry, ObjectName};
        use iec61850_mms::mms::pdu::read::{encode_confirmed_read_request, ReadRequest};

        let dispatcher = build_dispatcher();
        let req = ReadRequest {
            specification_with_result: false,
            variable_access_spec: VariableAccessSpecification::ListOfVariable(vec![
                ListOfVariableEntry::with_alt_access(
                    ObjectName::DomainSpecific {
                        domain_id: "IED1LD0".into(),
                        item_id: "MMXU1$MX$TotW".into(),
                    },
                    AlternateAccess::index_component(0, "a$b$c$d").unwrap(),
                ),
            ]),
        };
        let mut full = BytesMut::new();
        encode_confirmed_read_request(31, &req, &mut full);
        let request = || ConfirmedRequest {
            invoke_id: 31,
            service_body: extract_service_body_from_confirmed_request(&full),
        };

        assert!(is_decode_error(
            &dispatcher.dispatch(&conn_with_nesting(2), request())
        ));
        assert!(matches!(
            dispatcher.dispatch(&conn_with_nesting(10), request()),
            ConfirmedResponse::Response(_)
        ));
    }

    /// A Write whose data nests deeper than the negotiated
    /// dataStructureNestingLevel is refused as undecodable, and the same
    /// request is decoded on an association that negotiated a deeper level.
    #[test]
    fn write_data_is_bounded_by_the_negotiated_nesting_level() {
        use iec61850_mms::mms::pdu::write::{encode_confirmed_write_request, WriteRequest};

        let dispatcher = build_dispatcher();
        let nested = MmsData::Structure(vec![MmsData::Structure(vec![MmsData::Structure(vec![
            MmsData::Structure(vec![MmsData::Integer(1)]),
        ])])]);
        let req = WriteRequest::single_domain("IED1LD0", "GGIO1$CF$Mod$ctlModel", nested);
        let mut full = BytesMut::new();
        encode_confirmed_write_request(32, &req, &mut full);
        let request = || ConfirmedRequest {
            invoke_id: 32,
            service_body: extract_service_body_from_confirmed_request(&full),
        };

        assert!(is_decode_error(
            &dispatcher.dispatch(&conn_with_nesting(2), request())
        ));
        assert!(matches!(
            dispatcher.dispatch(&conn_with_nesting(10), request()),
            ConfirmedResponse::Response(_)
        ));
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

    /// The type specification is measured against the negotiated maximum PDU
    /// size: a response of exactly the budget is sent, one byte more is
    /// answered with errorClass resource other.
    #[test]
    fn dispatcher_gva_over_budget_returns_resource_other() {
        use iec61850_mms::mms::pdu::service_error::decode_confirmed_error_pdu;
        use iec61850_mms::mms::pdu::{
            common::ObjectName,
            get_var_access_attrs::{
                encode_confirmed_get_var_access_attrs_request, GetVariableAccessAttributesRequest,
            },
        };
        use iec61850_mms::mms::server::connection::NegotiatedParams;

        const INVOKE_ID: u32 = 21;

        let dispatcher = build_dispatcher();
        let gva_req = GetVariableAccessAttributesRequest {
            object_name: ObjectName::DomainSpecific {
                domain_id: "IED1LD0".to_string(),
                item_id: "MMXU1$MX$TotW$mag".to_string(),
            },
        };

        // The expected size comes from encoding the response the model implies,
        // not from what the dispatch path returns.
        let resp = match get_var_access_attrs::handle_get_var_access_attrs(
            &dispatcher.mms_model,
            &gva_req,
        ) {
            GetVarAccessAttrsResult::Response(r) => r,
            other => panic!("the model must resolve this path, got {:?}", other),
        };
        let mut expected = BytesMut::new();
        encode_confirmed_get_var_access_attrs_response(INVOKE_ID, &resp, &mut expected)
            .expect("the type specification must encode");
        let exact_max = (expected.len() + read::PDU_OVERHEAD_RESERVE) as u32;

        let mut full_buf = BytesMut::new();
        encode_confirmed_get_var_access_attrs_request(INVOKE_ID, &gva_req, &mut full_buf);
        let body = extract_service_body_from_confirmed_request(&full_buf);

        let dispatch_with_max = |max_pdu_size: u32| {
            let mut conn = MmsServerConnection::new();
            conn.set_negotiated({
                let mut params = NegotiatedParams::default();
                params.max_pdu_size = max_pdu_size;
                params
            });
            dispatcher.dispatch(
                &conn,
                ConfirmedRequest {
                    invoke_id: INVOKE_ID,
                    service_body: body.clone(),
                },
            )
        };

        match dispatch_with_max(exact_max) {
            ConfirmedResponse::Response(bytes) => assert_eq!(
                bytes[0], 0xa1,
                "a response of exactly the budget must be sent"
            ),
            other => panic!("expected a response, got {:?}", other),
        }

        match dispatch_with_max(exact_max - 1) {
            ConfirmedResponse::Error(bytes) => {
                let (invoke_id, service_error) =
                    decode_confirmed_error_pdu(&bytes).expect("the confirmed error must decode");
                assert_eq!(invoke_id, INVOKE_ID);
                assert_eq!(
                    service_error.error_class,
                    ErrorClass::Resource(resource::OTHER),
                    "a response one byte over the budget must answer resource other"
                );
            }
            other => panic!("expected a confirmed error, got {:?}", other),
        }
    }

    // ── GetNamedVariableListAttributes under the outbound guard ─────

    /// Registers a configured data set of `members` boolean entries and
    /// returns the member item ids in registration order.
    #[cfg(feature = "reporting")]
    fn register_dataset_of(dispatcher: &MmsModelDispatcher, members: usize) -> Vec<String> {
        use crate::reporting::{Dataset, DatasetEntry};

        let mut dataset = Dataset::new(NVL_LIST_NAME);
        let mut item_ids = Vec::with_capacity(members);
        for n in 0..members {
            let item_id = format!("GGIO1$ST$Ind{n}$stVal");
            dataset.push(DatasetEntry::new(
                format!("{NVL_DOMAIN}/{item_id}"),
                Arc::new(std::sync::RwLock::new(MmsValue::Boolean(true))),
            ));
            item_ids.push(item_id);
        }
        dispatcher
            .dataset_registry
            .write()
            .expect("the data set registry lock must be usable")
            .insert(
                (NVL_DOMAIN.to_string(), NVL_LIST_NAME.to_string()),
                Arc::new(dataset),
            );
        item_ids
    }

    /// Encodes the response those members imply, so the expected size never
    /// comes from the dispatch path under test.
    #[cfg(feature = "reporting")]
    fn nvl_response_len(item_ids: &[String], invoke_id: u32) -> usize {
        use iec61850_mms::mms::pdu::get_named_variable_list_attrs::{
            encode_confirmed_get_named_variable_list_attrs_response,
            GetNamedVariableListAttributesResponse,
        };
        use iec61850_mms::mms::pdu::{ListOfVariableEntry, ObjectName};

        let resp = GetNamedVariableListAttributesResponse {
            mms_deletable: false,
            list_of_variable: item_ids
                .iter()
                .map(|item_id| {
                    ListOfVariableEntry::name(ObjectName::DomainSpecific {
                        domain_id: NVL_DOMAIN.to_string(),
                        item_id: item_id.clone(),
                    })
                })
                .collect(),
        };
        let mut buf = BytesMut::new();
        encode_confirmed_get_named_variable_list_attrs_response(invoke_id, &resp, &mut buf);
        buf.len()
    }

    /// The GetNamedVariableListAttributes service body for the registered set.
    #[cfg(feature = "reporting")]
    fn nvl_request_body(invoke_id: u32) -> Bytes {
        use iec61850_mms::mms::pdu::get_named_variable_list_attrs::{
            encode_confirmed_get_named_variable_list_attrs_request,
            GetNamedVariableListAttributesRequest,
        };

        let req = GetNamedVariableListAttributesRequest::domain(NVL_DOMAIN, NVL_LIST_NAME);
        let mut buf = BytesMut::new();
        encode_confirmed_get_named_variable_list_attrs_request(invoke_id, &req, &mut buf);
        extract_service_body_from_confirmed_request(&buf)
    }

    /// A connection that has negotiated `max_pdu_size`.
    fn conn_with_max(max_pdu_size: u32) -> MmsServerConnection {
        use iec61850_mms::mms::server::connection::NegotiatedParams;

        let mut conn = MmsServerConnection::new();
        conn.set_negotiated({
            let mut params = NegotiatedParams::default();
            params.max_pdu_size = max_pdu_size;
            params
        });
        conn
    }

    #[cfg(feature = "reporting")]
    const NVL_DOMAIN: &str = "IED1LD0";
    #[cfg(feature = "reporting")]
    const NVL_LIST_NAME: &str = "GGIO1$ds1";

    #[cfg(feature = "reporting")]
    fn assert_resource_other(resp: ConfirmedResponse, invoke_id: u32) {
        use iec61850_mms::mms::pdu::service_error::decode_confirmed_error_pdu;

        match resp {
            ConfirmedResponse::Error(bytes) => {
                let (decoded_id, service_error) =
                    decode_confirmed_error_pdu(&bytes).expect("the confirmed error must decode");
                assert_eq!(decoded_id, invoke_id);
                assert_eq!(
                    service_error.error_class,
                    ErrorClass::Resource(resource::OTHER),
                    "an undeliverable response must answer resource other"
                );
            }
            other => panic!("expected a confirmed error, got {:?}", other),
        }
    }

    /// A data set with many members over an association that negotiated 200
    /// bytes cannot be delivered, so the guard answers resource other.
    #[cfg(feature = "reporting")]
    #[test]
    fn dispatcher_nvl_attrs_over_budget_returns_resource_other() {
        const INVOKE_ID: u32 = 31;

        let dispatcher = build_dispatcher();
        register_dataset_of(&dispatcher, 40);

        let resp = dispatcher.dispatch(
            &conn_with_max(200),
            ConfirmedRequest {
                invoke_id: INVOKE_ID,
                service_body: nvl_request_body(INVOKE_ID),
            },
        );
        assert_resource_other(resp, INVOKE_ID);
    }

    /// A response of exactly the budget is delivered and one byte more is not.
    #[cfg(feature = "reporting")]
    #[test]
    fn dispatcher_nvl_attrs_at_the_budget_boundary() {
        const INVOKE_ID: u32 = 32;

        let dispatcher = build_dispatcher();
        let item_ids = register_dataset_of(&dispatcher, 6);
        let exact_max =
            (nvl_response_len(&item_ids, INVOKE_ID) + read::PDU_OVERHEAD_RESERVE) as u32;

        let request = || ConfirmedRequest {
            invoke_id: INVOKE_ID,
            service_body: nvl_request_body(INVOKE_ID),
        };

        match dispatcher.dispatch(&conn_with_max(exact_max), request()) {
            ConfirmedResponse::Response(bytes) => assert_eq!(
                bytes[0], 0xa1,
                "a response of exactly the budget must be delivered"
            ),
            other => panic!("expected a response, got {:?}", other),
        }

        assert_resource_other(
            dispatcher.dispatch(&conn_with_max(exact_max - 1), request()),
            INVOKE_ID,
        );
    }

    /// Before negotiation completes no maximum applies, so the response goes
    /// out whatever its size.
    #[cfg(feature = "reporting")]
    #[test]
    fn dispatcher_nvl_attrs_unnegotiated_sends_the_response() {
        const INVOKE_ID: u32 = 33;

        let dispatcher = build_dispatcher();
        register_dataset_of(&dispatcher, 40);

        let resp = dispatcher.dispatch(
            &make_conn(),
            ConfirmedRequest {
                invoke_id: INVOKE_ID,
                service_body: nvl_request_body(INVOKE_ID),
            },
        );
        match resp {
            ConfirmedResponse::Response(bytes) => assert_eq!(bytes[0], 0xa1),
            other => panic!("expected a response, got {:?}", other),
        }
    }

    // ── GetDataSetValues under the read budget ──────────────────────

    /// Value every member of the data set under test holds. A visible string
    /// encodes as its tag, a single length byte, and its characters, so each
    /// member costs a predictable share of the budget.
    #[cfg(feature = "reporting")]
    const DATASET_MEMBER_VALUE: &str = "0123456789abcdef0123456789abcdef";

    /// Registers a configured data set of `members` entries, each holding
    /// [`DATASET_MEMBER_VALUE`], and returns the access results those members
    /// imply in registration order.
    #[cfg(feature = "reporting")]
    fn register_dataset_of_values(
        dispatcher: &MmsModelDispatcher,
        members: usize,
    ) -> Vec<AccessResult> {
        use crate::reporting::{Dataset, DatasetEntry};
        use crate::service::convert::mms_value_to_mms_data;

        let value = || MmsValue::VisibleString(DATASET_MEMBER_VALUE.to_string());

        let mut dataset = Dataset::new(NVL_LIST_NAME);
        for n in 0..members {
            dataset.push(DatasetEntry::new(
                format!("{NVL_DOMAIN}/GGIO1$ST$Ind{n}$stVal"),
                Arc::new(std::sync::RwLock::new(value())),
            ));
        }
        dispatcher
            .dataset_registry
            .write()
            .expect("the data set registry lock must be usable")
            .insert(
                (NVL_DOMAIN.to_string(), NVL_LIST_NAME.to_string()),
                Arc::new(dataset),
            );

        (0..members)
            .map(|_| AccessResult::Success(mms_value_to_mms_data(&value())))
            .collect()
    }

    /// The GetDataSetValues service body for the registered data set: a Read
    /// whose access specification names the variable list itself.
    #[cfg(feature = "reporting")]
    fn dataset_values_request_body(invoke_id: u32) -> Bytes {
        use iec61850_mms::mms::pdu::common::ObjectName;
        use iec61850_mms::mms::pdu::read::{encode_confirmed_read_request, ReadRequest};

        let req = ReadRequest::named_list(
            ObjectName::DomainSpecific {
                domain_id: NVL_DOMAIN.to_string(),
                item_id: NVL_LIST_NAME.to_string(),
            },
            false,
        );
        let mut buf = BytesMut::new();
        encode_confirmed_read_request(invoke_id, &req, &mut buf);
        extract_service_body_from_confirmed_request(&buf)
    }

    /// Encoded length of a list of access results, measured with the wire
    /// encoder rather than with the size estimate the budget deducts.
    #[cfg(feature = "reporting")]
    fn access_results_encoded_len(results: &[AccessResult]) -> usize {
        let mut buf = BytesMut::new();
        for result in results {
            result.encode(&mut buf);
        }
        buf.len()
    }

    /// Bytes the read budget holds back from the negotiated maximum for the
    /// ReadResponse frame and the carrying protocol frames, derived from the
    /// budget helper so that a boundary can be stated as a negotiated size.
    #[cfg(feature = "reporting")]
    fn read_budget_overhead() -> usize {
        const PROBE: u32 = 4_096;

        PROBE as usize
            - pdu_budget_for_access_results(Some(PROBE)).expect("a negotiated maximum has a budget")
    }

    /// Values that do not fit the negotiated maximum PDU size answer the whole
    /// request with errorClass resource other, not a truncated list.
    #[cfg(feature = "reporting")]
    #[test]
    fn dispatcher_dataset_values_over_budget_returns_resource_other() {
        const INVOKE_ID: u32 = 41;

        let dispatcher = build_dispatcher();
        register_dataset_of_values(&dispatcher, 40);

        let resp = dispatcher.dispatch(
            &conn_with_max(200),
            ConfirmedRequest {
                invoke_id: INVOKE_ID,
                service_body: dataset_values_request_body(INVOKE_ID),
            },
        );
        assert_resource_other(resp, INVOKE_ID);
    }

    /// A data set that fits is read in full over the same negotiated maximum,
    /// so the limit and not the data set path is what refuses the larger one.
    #[cfg(feature = "reporting")]
    #[test]
    fn dispatcher_dataset_values_within_budget_returns_the_values() {
        use iec61850_mms::mms::pdu::read::decode_confirmed_read_response;

        const INVOKE_ID: u32 = 42;

        let dispatcher = build_dispatcher();
        let expected = register_dataset_of_values(&dispatcher, 3);

        let resp = dispatcher.dispatch(
            &conn_with_max(200),
            ConfirmedRequest {
                invoke_id: INVOKE_ID,
                service_body: dataset_values_request_body(INVOKE_ID),
            },
        );
        match resp {
            ConfirmedResponse::Response(bytes) => {
                let (invoke_id, read_response) =
                    decode_confirmed_read_response(&bytes).expect("the response must decode");
                assert_eq!(invoke_id, INVOKE_ID);
                assert_eq!(
                    read_response.list_of_access_result, expected,
                    "every member value must reach the client"
                );
            }
            other => panic!("expected a response, got {:?}", other),
        }
    }

    /// Before negotiation completes no maximum bounds the read, so the same
    /// data set is served whatever its size.
    #[cfg(feature = "reporting")]
    #[test]
    fn dispatcher_dataset_values_unnegotiated_sends_the_response() {
        use iec61850_mms::mms::pdu::read::decode_confirmed_read_response;

        const INVOKE_ID: u32 = 43;
        const MEMBERS: usize = 40;

        let dispatcher = build_dispatcher();
        register_dataset_of_values(&dispatcher, MEMBERS);

        let resp = dispatcher.dispatch(
            &make_conn(),
            ConfirmedRequest {
                invoke_id: INVOKE_ID,
                service_body: dataset_values_request_body(INVOKE_ID),
            },
        );
        match resp {
            ConfirmedResponse::Response(bytes) => {
                let (_, read_response) =
                    decode_confirmed_read_response(&bytes).expect("the response must decode");
                assert_eq!(read_response.list_of_access_result.len(), MEMBERS);
            }
            other => panic!("expected a response, got {:?}", other),
        }
    }

    /// The list of access results is charged against the negotiated maximum:
    /// a list of exactly the budget is delivered, and one byte less of budget
    /// answers resource other.
    #[cfg(feature = "reporting")]
    #[test]
    fn dispatcher_dataset_values_at_the_budget_boundary() {
        const INVOKE_ID: u32 = 44;

        let dispatcher = build_dispatcher();
        let expected = register_dataset_of_values(&dispatcher, 4);
        let exact_max = (access_results_encoded_len(&expected) + read_budget_overhead()) as u32;

        let request = || ConfirmedRequest {
            invoke_id: INVOKE_ID,
            service_body: dataset_values_request_body(INVOKE_ID),
        };

        match dispatcher.dispatch(&conn_with_max(exact_max), request()) {
            ConfirmedResponse::Response(bytes) => assert_eq!(
                bytes[0], 0xa1,
                "a list of exactly the budget must be delivered"
            ),
            other => panic!("expected a response, got {:?}", other),
        }

        assert_resource_other(
            dispatcher.dispatch(&conn_with_max(exact_max - 1), request()),
            INVOKE_ID,
        );
    }

    // ── GetNameList keeps its own page under a small maximum ────────

    /// Logical devices the model needs for a domain name list to run past one
    /// page and set `moreFollows`.
    const PAGED_DOMAIN_COUNT: usize = 101;

    /// A dispatcher whose model holds [`PAGED_DOMAIN_COUNT`] logical devices.
    fn build_paged_dispatcher() -> MmsModelDispatcher {
        let mut builder = IedModelBuilder::new("IED1");
        for n in 0..PAGED_DOMAIN_COUNT {
            let ld = LogicalDeviceBuilder::new(format!("LD{n}"))
                .add_ln(LogicalNodeBuilder::lln0().build().expect("lln0"))
                .build()
                .expect("logical device");
            builder = builder.add_ld(ld).expect("add_ld");
        }
        let model = builder.build().expect("model");
        let mms_model = MmsDeviceModel::from_ied_model(&model).expect("mms model");
        MmsModelDispatcher::new(
            Arc::new(model),
            Arc::new(mms_model),
            Arc::new(WriteAccessPolicies::default()),
        )
    }

    /// GetNameList bounds its own answer by paging, so the outbound size limit
    /// leaves it alone: a page larger than the negotiated maximum is still
    /// delivered with `moreFollows` set, because replacing it with an error
    /// would lose the continuation point the client resumes browsing from.
    #[test]
    fn dispatcher_get_name_list_page_survives_a_small_negotiated_size() {
        use iec61850_mms::mms::pdu::get_name_list::{
            decode_confirmed_get_name_list_response, encode_confirmed_get_name_list_request,
            GetNameListRequest, ObjectClass, ObjectScope,
        };

        const INVOKE_ID: u32 = 51;
        const SMALL_MAX_PDU_SIZE: u32 = 128;

        let dispatcher = build_paged_dispatcher();
        let gnl_req = GetNameListRequest {
            object_class: ObjectClass::Domain,
            object_scope: ObjectScope::VmdSpecific,
            continue_after: None,
        };
        let mut full_buf = BytesMut::new();
        encode_confirmed_get_name_list_request(INVOKE_ID, &gnl_req, &mut full_buf);

        let resp = dispatcher.dispatch(
            &conn_with_max(SMALL_MAX_PDU_SIZE),
            ConfirmedRequest {
                invoke_id: INVOKE_ID,
                service_body: extract_service_body_from_confirmed_request(&full_buf),
            },
        );
        match resp {
            ConfirmedResponse::Response(bytes) => {
                assert!(
                    bytes.len() > SMALL_MAX_PDU_SIZE as usize,
                    "the page must exceed the negotiated maximum for this to test the exception"
                );
                let (invoke_id, name_list) = decode_confirmed_get_name_list_response(&bytes)
                    .expect("the name list must decode");
                assert_eq!(invoke_id, INVOKE_ID);
                assert!(
                    !name_list.identifiers.is_empty(),
                    "the page must carry names"
                );
                assert!(
                    name_list.more_follows,
                    "a name list longer than one page must set moreFollows"
                );
            }
            other => panic!("a paged name list must be delivered, got {:?}", other),
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
        let resp = make_confirmed_error(3, ErrorClass::Access(access::OBJECT_NON_EXISTENT));
        let bytes = match resp {
            ConfirmedResponse::Error(b) => b,
            other => panic!("expected an error, got {:?}", other),
        };

        // Expected:
        //   0xa2 0x0a            ConfirmedErrorPDU [2] IMPLICIT, len=10
        //     0x80 0x01 0x03     invokeID [0] IMPLICIT Unsigned32 = 3
        //     0xa2 0x05          serviceError [2] IMPLICIT, len=5
        //       0xa0 0x03        errorClass [0] EXPLICIT, len=3
        //         0x87 0x01 0x02   access [7] IMPLICIT INTEGER = 2, object-non-existent
        let expected: &[u8] = &[
            0xa2, 0x0a, 0x80, 0x01, 0x03, 0xa2, 0x05, 0xa0, 0x03, 0x87, 0x01, 0x02,
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
    use super::{extract_lcb_target, is_lcb_path, LCB_SERVED_FIELDS};
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

    /// A log control block carries its nine MMS components in structure order.
    #[test]
    fn lcb_components_follow_the_mms_structure() {
        assert_eq!(
            LCB_SERVED_FIELDS,
            [
                "LogEna",
                "LogRef",
                "DatSet",
                "OldEntrTm",
                "NewEntrTm",
                "OldEnt",
                "NewEnt",
                "TrgOps",
                "IntgPd"
            ]
        );
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
