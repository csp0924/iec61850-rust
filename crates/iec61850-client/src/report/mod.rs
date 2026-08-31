//! Client-side reception of IEC 61850 reports.
//!
//! Three layers: [`parse`] turns an `MmsValue` into a `ParsedReport` with no
//! side effects; [`state`] applies a parsed report to the client's copy of the
//! data set values without performing IO; [`dispatch`] owns the handler
//! registry, keyed by RCB reference, and invokes the callbacks.
//!
//! Callbacks run outside the registry lock, so a callback may install or
//! remove a handler without deadlocking.

pub mod dispatch;
pub mod parse;
pub mod state;

pub use dispatch::{DatasetDirectory, DispatchError, ReportCallback, ReportRegistry};
// Re-exported here as well; the type is defined in `crate::connection`.
pub use crate::connection::IedConnection;
pub use parse::{
    parse_report, ParsedReport, ReasonForInclusion, ReportOptFlds, ReportParseError, Segmentation,
};
pub use state::{apply_report, ClientReport, StateError};
