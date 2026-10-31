//! Report control blocks and the reporting engine (IEC 61850-7-2).
//!
//! Covers unbuffered (URCB) and buffered (BRCB) report control blocks: data set
//! definition, trigger evaluation, report buffering, InformationReport PDU
//! encoding with segmentation, and the MMS routing that exposes control block
//! fields to clients. `ReportingEngine` is the entry point; it is held by
//! `IedServer` behind an `Arc<Mutex<..>>` so that reporting state stays
//! consistent across connection tasks.

pub mod brcb;
pub mod buffer;
pub mod dataset;
pub mod dynamic_ops;
pub mod engine;
pub mod pdu;
pub mod rcb;
pub mod service;
pub mod sink;
#[cfg(feature = "sqlite-backend")]
pub mod sqlite_buffer;

// Public re-exports: the minimal surface used from other crates.

pub use dataset::{DataAttributeRef, Dataset, DatasetEntry};
pub use dynamic_ops::{DatasetError, DatasetMeta, DynamicDatasetOps};

/// Shared data set registry, keyed by `(mms domain, mms list_name)`, for example
/// (`"simpleIOGenericIO"`, `"GGIO1$ds1"`).
///
/// `IedServerInner` and `MmsModelDispatcher` hold clones of the same `Arc`, so a
/// runtime `register_urcb` or `register_dataset` becomes visible to the
/// dispatcher immediately.
pub type DatasetRegistry = std::sync::Arc<
    std::sync::RwLock<std::collections::HashMap<(String, String), std::sync::Arc<Dataset>>>,
>;
pub use brcb::{
    ApplyEntryIdError, Brcb, BrcbConfigField, BrcbState, BufferedReportControl, ConfigChangeResult,
    ResvTmsState, TransmitAnchor, RESV_TMS_IMPLICIT_VALUE_S,
};
pub use buffer::{
    EnqueuedSnapshot, EntryId, InMemoryReportBuffer, OverflowStrategy, ReportBufferBackend,
    ReportEntry, SeekResult,
};
pub use engine::{NullReportSink, ReportSink, ReportingEngine};
// The flag types live in `crate::flags` so that `logging` does not have to depend
// on `reporting`; they are re-exported here for callers that reach them through
// this module.
pub use crate::flags::{InclusionFlag, OptFlds, TriggerOptions};
pub use pdu::{
    brcb_encode_snapshot, encode_brcb_report_pdus, encode_report_pdus, pending_from_brcb_entry,
    BrcbReportEncodeParams, BrcbStateSnapshot, ReportEncodeError, ReportEncodeParams,
};
pub use rcb::{PendingReport, Rcb, RcbMetrics, RcbMetricsSnapshot, RcbState, ReportControl};
pub use service::{
    handle_get_brcb_field, handle_get_rcb_field, handle_set_brcb_field, handle_set_rcb_field,
    RcbField, RcbWriteValue,
};
pub use sink::{ChannelReportSink, SendOutcome, REPORT_CHANNEL_CAP};
#[cfg(feature = "sqlite-backend")]
pub use sqlite_buffer::SqliteReportBuffer;
