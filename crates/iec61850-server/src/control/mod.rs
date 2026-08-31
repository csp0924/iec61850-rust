//! Control services: Select, SelectWithValue, Operate, and Cancel of
//! IEC 61850-7-2.
//!
//! - `model`: `ControlModel`, `SboClass`, `ControlAddCause`, `ControlAction`,
//!   `OperParams`, and the related value types
//! - `state`: the `ControlState` machine and its `TransitionResult`
//! - `handler`: the `CheckHandler`, `WaitForExecutionHandler`, and `ControlHandler`
//!   traits, with test implementations
//! - `object`: `ControlObject`, the per-data-object state machine
//! - `service`: the entry points for Operate, SBO read, SBOw write, and Cancel

pub mod handler;
pub mod model;
pub mod object;
pub mod registry;
pub mod service;
pub mod state;

// Public re-exports for the rest of the crate.
pub use handler::{
    AlwaysAcceptCheckHandler, AlwaysAcceptWaitHandler, AlwaysFailOperateHandler,
    AlwaysSuccessOperateHandler, CheckHandler, ControlHandler, SelectStateChangedHandler,
    SelectStateChangedReason, WaitForExecutionHandler,
};
pub use model::{
    CancelParams, ControlAction, ControlAddCause, ControlLastApplError, ControlModel, OperParams,
    OriginValue, SboClass,
};
pub use object::{CancelResult, ControlObject, ControlObjectConfig, OperateBeginResult};
pub use registry::{ControlObjectEntry, ControlObjectKey, ControlObjectsRegistry};
pub use service::{
    handle_cancel, handle_operate, handle_read_sbo, handle_sbow, parse_co_item_id,
    ChannelCommandTermination, CoAttr, CommandTerminationSink, ConnectionTerminationEvent,
    NoOpCommandTermination, RecordingCommandTermination, ServiceResult, TerminationEvent,
};
pub use state::{ControlState, RejectionReason, TransitionResult};
