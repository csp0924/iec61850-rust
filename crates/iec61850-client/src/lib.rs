//! IEC 61850 client API: an `IedConnection` over MMS carrying control,
//! reporting, data set and directory services.
//!
//! Wraps `iec61850-mms` into the ACSI services of IEC 61850-7-2 as mapped by
//! IEC 61850-8-1. The primary API is `async`; a synchronous caller wraps it
//! in `block_on`.
//!
//! ## Features
//!
//! - `std` (default): tokio runtime and `std::sync`; enables the async
//!   `IedConnection` API.
//! - `embedded`: `no_std` plus `alloc`, with `iec61850-mms` and
//!   `iec61850-model` on their embedded paths. Only `error` and `mms_compat`
//!   are exposed, because the async API needs a runtime.
//! - `reporting` / `control` / `datasets`: gate report dispatch together with
//!   the RCB, GoCB and journal APIs, the control API, and data set
//!   administration. Each implies `std`.
//! - `minimal`: environment-neutral marker carrying no submodule feature; the
//!   caller selects `minimal,std` or `minimal,embedded`.
//!
//! ## Reporting and RCB access
//!
//! `install_report_handler` / `uninstall_report_handler` feed a three-layer
//! parse, state and dispatch pipeline. `get_rcb_values` and
//! `refresh_rcb_values` read through `MmsClient::read`; `set_rcb_values`
//! issues one `MmsClient::write` per item, in the order
//! `build_write_sequence` returns. `trigger_grefcb` writes
//! `<rcb_ref>$GI = true`.
//!
//! `set_rcb_values` with `single_request = true` is not implemented: it would
//! need an MMS WriteMultiple request.

#![cfg_attr(not(feature = "std"), no_std)]

// Keeps `vec!` and the other alloc macros visible to every submodule in a
// no_std build, matching what the std prelude provides otherwise. No
// submodule of the `minimal` feature set uses one, hence the allow.
#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
#[macro_use]
extern crate alloc;

// Pure modules, available on every feature combination including embedded.
pub mod error;
pub mod mms_compat;

// Cross-environment alloc and collection facade (Arc, HashMap, String, Vec).
// Every module takes these from here instead of importing `std::*` directly.
pub(crate) mod prelude;

// Synchronization primitive facade: tokio::sync on std, a spin-backed facade
// with the same async shape on embedded, where a single-core caller is always
// instantly ready. Every lock held across an await point goes through it.
pub(crate) mod sync;

// The std-only constructors on `IedConnection` (`connect`, `connect_tls`,
// `new`) need tokio's TcpStream and TokioTimer and are cfg-gated out on
// embedded; the struct fields and the remaining methods stay available.
pub mod connection;
pub mod directory;
pub mod object_io;

#[cfg(feature = "control")]
pub mod control;

#[cfg(feature = "datasets")]
pub mod dataset_admin;

#[cfg(feature = "reporting")]
pub mod gocb;

#[cfg(feature = "reporting")]
pub mod journal;

#[cfg(feature = "reporting")]
pub mod rcb;

#[cfg(feature = "reporting")]
pub mod report;

pub use connection::IedConnection;
#[cfg(feature = "control")]
pub use control::{
    CommandTerminationParsed, ControlAddCause, ControlLastApplError, ControlModel,
    ControlObjectClient, ControlOutcome, LastApplError, OriginValue, SboClass,
};
#[cfg(feature = "datasets")]
pub use dataset_admin::DataSetMember;
pub use directory::{AcsiClass, DeviceModel, IcLogicalDevice};
pub use error::ClientError;
#[cfg(feature = "reporting")]
pub use gocb::{GoCBValues, GoCBValuesWrite, PhyComAddress};
// Re-exported so that the return type of
// `IedConnection::get_variable_specification` can be named without depending
// on `iec61850-mms` directly.
pub use iec61850_mms::{StructComponent, TypeSpecification};
#[cfg(feature = "reporting")]
#[allow(deprecated)]
pub use journal::{
    parse_journal_ref, wire_entry_to_client, ClientJournalEntry, ClientJournalEntryData,
    ClientJournalEntryId, JournalQuery, QueryJournalNotImplemented,
};
pub use object_io::{
    parse_data_set_ref, parse_iec_object_path, ArrayElement, DataSetRef, IecObjectPath,
};
#[cfg(feature = "reporting")]
pub use rcb::{
    create_rcb_from_mms, get_rcb_values, refresh_rcb_values, set_rcb_values, update_rcb_from_mms,
    update_values, RcbHandle, RcbWriteMask, TriggerOptions,
};
#[cfg(feature = "reporting")]
pub use report::{
    apply_report, parse_report, ClientReport, DatasetDirectory, DispatchError, ParsedReport,
    ReasonForInclusion, ReportCallback, ReportOptFlds, ReportParseError, ReportRegistry,
    Segmentation, StateError,
};
