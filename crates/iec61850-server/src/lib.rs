//! IEC 61850 server runtime: the `IedServer` object and the model-to-MMS mapping.
//!
//! The crate implements the server side of the ACSI-to-MMS mapping of
//! IEC 61850-8-1. It exposes an `IedModel` as MMS domains, named variables, and
//! type specifications, answers the confirmed services a client issues over the
//! MMS stack, and drives reporting, control, logging, GOOSE control blocks, and
//! setting groups. PDU size negotiation itself lives in `iec61850-mms`; the
//! server calls into it while the association is being established.
//!
//! Behavior a caller can rely on:
//!
//! - Associations live in an `RwLock<HashMap<_, _>>` keyed by connection id;
//!   handler and cache lookups are keyed by `AttrPath`, never by pointer
//!   identity.
//! - Values are updated through typed entry points (`update_int32`,
//!   `update_float32`, ...); there is no generic update guarded by an
//!   assertion.
//! - Negotiation clamps the MMS PDU size to at least 64 bytes and the
//!   outstanding-request count to at least 1.
//! - The data model lock is a fine-grained `RwLock` plus an `is_model_locked`
//!   flag: a reentrant `lock_data_model` returns `Err(AlreadyLocked)` instead
//!   of deadlocking.
//! - An association beyond `max_mms_connections` has its socket closed without
//!   a COTP disconnect-request.
//! - A single access point is supported.
//! - `set_write_access_policy` accepts `FC::Bl`.
//! - `servicesSupportedCalling` proposed by the client is parsed and retained
//!   in `client_proposed_services`, but is not enforced.

#![warn(missing_debug_implementations)]
#![forbid(unsafe_code)]
// `std` is a default feature, so the default build is the std build; clearing
// it selects no_std + alloc.
#![cfg_attr(not(feature = "std"), no_std)]

// `#[macro_use]` keeps `vec!` and `format!` available crate-wide in a no_std
// build; under std it is redundant but harmless.
#[macro_use]
extern crate alloc;

pub mod compat;
pub mod config;
// The bitflag types (TriggerOptions, OptFlds, InclusionFlag) sit at crate top
// level so that `reporting` and `logging` can each be enabled alone and still
// reach the same wire encoding.
pub mod flags;
// `connection` needs std for tokio and its socket types. `ConnectionId` and
// `ClientConnection` are the routing keys of every sub-feature module, so it is
// available whenever any sub-feature is on, not only under `full-server`.
#[cfg(any(
    feature = "full-server",
    feature = "reporting",
    feature = "control",
    feature = "logging",
    feature = "goose-mapping",
    feature = "setting-groups"
))]
pub mod connection;
#[cfg(feature = "control")]
pub mod control;
pub mod error;
#[cfg(feature = "goose-mapping")]
pub mod goose_mapping;
pub mod handler;
#[cfg(feature = "full-server")]
pub mod lifecycle;
// `logging` reaches TriggerOptions through `crate::flags` and therefore does
// not pull in `reporting`.
#[cfg(feature = "logging")]
pub mod logging;
pub mod mapping;
pub mod policy;
#[cfg(feature = "reporting")]
pub mod reporting;
#[cfg(feature = "full-server")]
pub mod server;
pub mod service;
#[cfg(feature = "setting-groups")]
pub mod setting_groups;

pub use config::{Edition, IedServerConfig, TimeQuality};
#[cfg(any(
    feature = "full-server",
    feature = "reporting",
    feature = "control",
    feature = "logging",
    feature = "goose-mapping",
    feature = "setting-groups"
))]
pub use connection::{ClientConnection, ConnectionId};
pub use error::{Result, ServerError};
#[cfg(feature = "goose-mapping")]
pub use goose_mapping::{
    apply_gocb_write, encode_gocb_da, encode_gocb_structure, parse_go_item_id, GoCBHandle,
    GoCBRegistry, GOCB_DA_NAMES,
};
pub use handler::{
    AttributeAccessHandler, DenyAllReadHandler, HandlerRegistry, ReadContext, ReadHandler,
    ReadOutcome, SilentReadHandler, WriteContext, WriteOutcome as HandlerWriteOutcome,
};
#[cfg(feature = "full-server")]
pub use lifecycle::ServerHandle;
#[cfg(feature = "full-server")]
pub use logging::{
    new_log_control_registry, InMemoryLogStorage, JournalEntry, JournalEntryData, LogControl,
    LogControlBlock, LogControlRegistry, LogEna, LogEntryId, LogEntryVisitor, LogState, LogStorage,
    LogStorageError,
};
pub use mapping::{
    DomainView, MmsDeviceModel, MmsLeafType, MmsTypeSpec, NamedVariableSpec, StringSize,
};
pub use policy::WriteAccessPolicies;
#[cfg(feature = "reporting")]
pub use reporting::{
    ChannelReportSink, Dataset, DatasetEntry, InclusionFlag, NullReportSink, OptFlds, Rcb,
    RcbMetrics, RcbMetricsSnapshot, ReportControl, ReportSink, ReportingEngine, SendOutcome,
    TriggerOptions, REPORT_CHANNEL_CAP,
};
#[cfg(feature = "full-server")]
pub use server::{Bound, DataModelGuard, HasModel, IedServer, IedServerBuilder, NoModel};
pub use service::{IdentificationStrings, MmsModelDispatcher};
#[cfg(feature = "setting-groups")]
pub use setting_groups::{
    DefaultSettingGroupHandler, SettingGroupHandler, SettingGroupRegistry, SettingGroupRuntime,
    SgcbSnapshot,
};
