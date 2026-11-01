//! Entry points of the control services.
//!
//! | Control model | MMS operation | Entry point |
//! |---|---|---|
//! | direct with normal security | Write Oper | `handle_operate` |
//! | direct with enhanced security | Write Oper | `handle_operate` |
//! | select-before-operate, normal security: select | Read SBO | `handle_read_sbo` |
//! | select-before-operate, normal security: operate | Write Oper | `handle_operate` |
//! | select-before-operate, enhanced security: select | Write SBOw | `handle_sbow` |
//! | select-before-operate, enhanced security: operate | Write Oper | `handle_operate` |
//! | cancel | Write Cancel | `handle_cancel` |
//!
//! Enhanced security, whether direct or select-before-operate, must send a
//! CommandTermination InformationReport once the command finishes, successfully or
//! not. That is an unsolicited push rather than a confirmed response, so it is
//! routed through the `CommandTerminationSink` trait instead of the request path.

use super::handler::{
    CheckHandler, ControlHandler, SelectStateChangedReason, WaitForExecutionHandler,
};
use super::model::{
    CancelParams, ControlAction, ControlAddCause, ControlLastApplError, ControlModel, OperParams,
};
use super::object::{CancelResult, ControlObject, ControlSettings, OperateBeginResult};
use crate::connection::ConnectionId;
use bytes::{Bytes, BytesMut};
use iec61850_model::MmsValue;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::mpsc;

// ─────────────────────────────────────────────────────────────────────────────
// CommandTermination sink
// ─────────────────────────────────────────────────────────────────────────────

/// Delivers a CommandTermination to one connection.
///
/// A command termination is an unsolicited InformationReport, so it cannot travel
/// on the response path of the request that caused it. This trait keeps the
/// control services independent of how a connection is written to.
pub trait CommandTerminationSink: Send + Sync {
    /// Sends a positive CommandTermination for a command that succeeded.
    ///
    /// `oper_value` is the encoded Oper structure the client sent, which the client
    /// decodes back into the Operate parameters when it receives the report.
    fn send_positive(&self, obj_ref: &str, conn_id: u64, oper_value: Bytes);
    /// Sends a negative CommandTermination, carrying the cause of the failure
    /// and the `Error` member of its LastApplError.
    fn send_negative(
        &self,
        obj_ref: &str,
        conn_id: u64,
        add_cause: ControlAddCause,
        error: ControlLastApplError,
        oper_value: Bytes,
    );
}

/// Sink that sends nothing; normal security needs no CommandTermination.
#[derive(Debug)]
pub struct NoOpCommandTermination;

impl CommandTerminationSink for NoOpCommandTermination {
    fn send_positive(&self, _obj_ref: &str, _conn_id: u64, _oper_value: Bytes) {}
    fn send_negative(
        &self,
        _obj_ref: &str,
        _conn_id: u64,
        _add_cause: ControlAddCause,
        _error: ControlLastApplError,
        _oper_value: Bytes,
    ) {
    }
}

/// Sink that records what it was asked to send; for tests.
#[derive(Debug)]
pub struct RecordingCommandTermination {
    /// Every event the sink was asked to send, in order.
    pub events: Arc<std::sync::Mutex<Vec<TerminationEvent>>>,
}

/// One CommandTermination that `RecordingCommandTermination` captured.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TerminationEvent {
    /// The command finished successfully.
    #[non_exhaustive]
    Positive {
        /// Object reference the command targeted.
        obj_ref: String,
        /// Connection the command arrived on.
        conn_id: ConnectionId,
        /// Encoded Oper structure.
        oper_value: Bytes,
    },
    /// The command failed.
    #[non_exhaustive]
    Negative {
        /// Object reference the command targeted.
        obj_ref: String,
        /// Connection the command arrived on.
        conn_id: ConnectionId,
        /// Cause reported to the client.
        add_cause: ControlAddCause,
        /// `Error` member of the LastApplError.
        error: ControlLastApplError,
        /// Encoded Oper structure.
        oper_value: Bytes,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// ChannelCommandTermination: routing from the dispatcher to a connection task
// ─────────────────────────────────────────────────────────────────────────────

/// One CommandTermination event delivered to a connection, with the metadata
/// needed to build the PDU.
///
/// The connection task receives this and encodes the InformationReport before
/// writing it to the socket.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionTerminationEvent {
    /// The command finished successfully.
    #[non_exhaustive]
    Positive {
        /// The object reference, `<LD>/<LN>$CO$<DO>`.
        obj_ref: String,
        /// Encoded Oper structure, which becomes the second AccessResult of the
        /// InformationReport.
        oper_value: Bytes,
    },
    /// The command failed.
    #[non_exhaustive]
    Negative {
        /// The object reference, `<LD>/<LN>$CO$<DO>`.
        obj_ref: String,
        /// Cause reported to the client.
        add_cause: ControlAddCause,
        /// `Error` member of the LastApplError.
        error: ControlLastApplError,
        /// Encoded Oper structure, which becomes the second AccessResult of the
        /// InformationReport.
        oper_value: Bytes,
    },
}

/// Routes a CommandTermination to the right connection over a per-connection
/// channel.
///
/// The connection lifecycle calls `register(conn_id, sender)` when a connection is
/// established and `deregister(conn_id)` when it ends. The control services push
/// through the `CommandTerminationSink` trait and this implementation resolves the
/// connection id to its sender.
///
/// The event is queued rather than written to the socket inline, so a control task
/// and socket I/O never block one another.
#[derive(Clone, Default)]
pub struct ChannelCommandTermination {
    inner: Arc<RwLock<HashMap<u64, mpsc::UnboundedSender<ConnectionTerminationEvent>>>>,
}

impl std::fmt::Debug for ChannelCommandTermination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.inner.read().map(|g| g.len()).unwrap_or(0);
        f.debug_struct("ChannelCommandTermination")
            .field("connections", &count)
            .finish()
    }
}

impl ChannelCommandTermination {
    /// Creates a router with no connections registered.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers the channel of one connection.
    pub fn register(
        &self,
        conn_id: u64,
        sender: mpsc::UnboundedSender<ConnectionTerminationEvent>,
    ) {
        if let Ok(mut g) = self.inner.write() {
            g.insert(conn_id, sender);
        } else {
            tracing::warn!(conn_id, "command termination registry lock poisoned");
        }
    }

    /// Removes the channel of one connection, called when it closes.
    pub fn deregister(&self, conn_id: u64) {
        if let Ok(mut g) = self.inner.write() {
            g.remove(&conn_id);
        }
    }

    fn dispatch(&self, conn_id: u64, ev: ConnectionTerminationEvent) {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::warn!(conn_id, "command termination registry read lock poisoned");
                return;
            }
        };
        match g.get(&conn_id) {
            Some(tx) => {
                if let Err(e) = tx.send(ev) {
                    // The receiver is gone, so the connection task is shutting down.
                    tracing::warn!(
                        conn_id,
                        error = %e,
                        "command termination undeliverable: receiver gone"
                    );
                }
            }
            None => {
                // The connection closed or was never registered; not fatal.
                tracing::warn!(
                    conn_id,
                    "command termination dropped: no channel registered for this connection"
                );
            }
        }
    }
}

impl CommandTerminationSink for ChannelCommandTermination {
    fn send_positive(&self, obj_ref: &str, conn_id: u64, oper_value: Bytes) {
        self.dispatch(
            conn_id,
            ConnectionTerminationEvent::Positive {
                obj_ref: obj_ref.to_string(),
                oper_value,
            },
        );
    }

    fn send_negative(
        &self,
        obj_ref: &str,
        conn_id: u64,
        add_cause: ControlAddCause,
        error: ControlLastApplError,
        oper_value: Bytes,
    ) {
        self.dispatch(
            conn_id,
            ConnectionTerminationEvent::Negative {
                obj_ref: obj_ref.to_string(),
                add_cause,
                error,
                oper_value,
            },
        );
    }
}

impl CommandTerminationSink for RecordingCommandTermination {
    fn send_positive(&self, obj_ref: &str, conn_id: u64, oper_value: Bytes) {
        if let Ok(mut g) = self.events.lock() {
            g.push(TerminationEvent::Positive {
                obj_ref: obj_ref.into(),
                conn_id,
                oper_value,
            });
        }
    }
    fn send_negative(
        &self,
        obj_ref: &str,
        conn_id: u64,
        add_cause: ControlAddCause,
        error: ControlLastApplError,
        oper_value: Bytes,
    ) {
        if let Ok(mut g) = self.events.lock() {
            g.push(TerminationEvent::Negative {
                obj_ref: obj_ref.into(),
                conn_id,
                add_cause,
                error,
                oper_value,
            });
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Service results
// ─────────────────────────────────────────────────────────────────────────────

/// Result of an Operate, SBOw, or Cancel service.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServiceResult {
    /// The service succeeded.
    Success,
    /// The service failed, with the cause to report.
    Failure(ControlAddCause),
}

/// Why a control request was refused: the add cause to report, and whether the
/// refusal stems from an internal failure of the server rather than from the
/// checks of the control model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Refusal {
    /// Add cause reported to the client.
    pub(crate) cause: ControlAddCause,
    /// Whether the server failed internally.
    pub(crate) internal: bool,
}

impl Refusal {
    /// A refusal by the checks of the control model, a handler included.
    pub(crate) fn by_check(cause: ControlAddCause) -> Self {
        Self {
            cause,
            internal: false,
        }
    }

    /// A refusal caused by an internal failure of the server.
    pub(crate) fn internal() -> Self {
        Self {
            cause: ControlAddCause::Unknown,
            internal: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Select, normal security: Read SBO
// ─────────────────────────────────────────────────────────────────────────────

/// Handles a read of `$CO$<DO>$SBO`, the select of the normal-security
/// select-before-operate model.
///
/// Returns `Some(object_reference)` when the check handler admits the request and
/// the object is selected, and `None` when it is refused, which the caller answers
/// with an empty string on the wire.
pub fn handle_read_sbo(
    obj: &ControlObject,
    conn_id: u64,
    check_handler: Option<&Arc<dyn CheckHandler>>,
) -> Option<String> {
    // Every control entry point first expires a stale selection, so the object is
    // unselected again and a fresh select can succeed.
    obj.check_sbo_timeout();

    let ctl_model = obj.settings().ctl_model;

    // A status-only object never accepts a control request.
    if ctl_model == ControlModel::StatusOnly {
        tracing::warn!(
            name = %obj.config.name,
            "read SBO refused: the object is status-only"
        );
        return None;
    }

    // Only the normal-security select-before-operate model has an SBO attribute.
    if ctl_model != ControlModel::SboNormal {
        tracing::warn!(
            name = %obj.config.name,
            ?ctl_model,
            "read SBO refused: the control model is not select-before-operate with normal security"
        );
        return None;
    }

    // A select carries no control value.
    let action = ControlAction::new(
        0,
        Default::default(),
        [0u8; 8],
        false,
        false,
        false,
        true,
        conn_id,
    );

    // The check handler receives no control value on this select.
    if let Some(h) = check_handler {
        if let Err(cause) = h.check(&action, None, false, false) {
            tracing::warn!(
                name = %obj.config.name,
                ?cause,
                "read SBO refused by the check handler"
            );
            return None;
        }
    }

    match obj.try_select(conn_id) {
        Ok(true) => {
            let obj_ref = obj.object_ref();
            tracing::debug!(
                name = %obj.config.name,
                conn_id,
                obj_ref = %obj_ref,
                "select accepted"
            );
            Some(obj_ref)
        }
        Ok(false) => {
            tracing::warn!(
                name = %obj.config.name,
                "read SBO refused: the object is already selected"
            );
            None
        }
        Err(e) => {
            tracing::warn!(name = %obj.config.name, error = %e, "read SBO failed internally");
            None
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Select with value, enhanced security: Write SBOw
// ─────────────────────────────────────────────────────────────────────────────

/// Handles a write to `$CO$<DO>$SBOw`, the select of the enhanced-security
/// select-before-operate model.
///
/// A value that does not parse as an SBOw structure is refused with
/// `InconsistentParameters`, and an object of any other control model with
/// `Unknown`.
pub async fn handle_sbow(
    obj: &ControlObject,
    conn_id: u64,
    raw_value: &MmsValue,
    check_handler: Option<&Arc<dyn CheckHandler>>,
) -> ServiceResult {
    // Parse the SBOw parameters.
    let params = match OperParams::from_mms_value(raw_value) {
        Some(p) => p,
        None => {
            tracing::warn!(name = %obj.config.name, "SBOw refused: parameters did not parse");
            return ServiceResult::Failure(ControlAddCause::InconsistentParameters);
        }
    };
    match select_with_value(obj, conn_id, &params, check_handler) {
        Ok(()) => ServiceResult::Success,
        Err(refusal) => ServiceResult::Failure(refusal.cause),
    }
}

/// Runs a select with value whose parameters have been parsed.
///
/// # Errors
///
/// Returns the refusal.
pub(crate) fn select_with_value(
    obj: &ControlObject,
    conn_id: u64,
    params: &OperParams,
    check_handler: Option<&Arc<dyn CheckHandler>>,
) -> Result<(), Refusal> {
    // Expire a stale selection first.
    obj.check_sbo_timeout();

    // SelectWithValue belongs to the enhanced-security select-before-operate
    // model alone; any other model answers unknown, IEC 61850-7-2 Table 47.
    let ctl_model = obj.settings().ctl_model;
    if ctl_model != ControlModel::SboEnhanced {
        tracing::warn!(
            name = %obj.config.name,
            ?ctl_model,
            "SBOw refused: the control model is not select-before-operate with enhanced security"
        );
        return Err(Refusal::by_check(ControlAddCause::Unknown));
    }

    // The origin field must be well formed.
    if !params.origin.is_valid() {
        tracing::warn!(name = %obj.config.name, "SBOw refused: malformed origin field");
        return Err(Refusal::by_check(ControlAddCause::InconsistentParameters));
    }

    let action = ControlAction::new(
        params.ctl_num,
        params.origin.clone(),
        params.t,
        params.test,
        params.synchro_check,
        params.interlock_check,
        true, // this is a select
        conn_id,
    );

    // A select with value passes the control value to the check handler.
    if let Some(h) = check_handler {
        if let Err(cause) = h.check(
            &action,
            Some(&params.ctl_val),
            params.test,
            params.interlock_check,
        ) {
            tracing::warn!(
                name = %obj.config.name,
                ?cause,
                "SBOw refused by the check handler"
            );
            return Err(Refusal::by_check(cause));
        }
    }

    // Record the SBOw parameters so the Operate can be compared against them.
    match obj.sbow_select(conn_id, params) {
        Ok(Ok(())) => {
            tracing::debug!(name = %obj.config.name, conn_id, "select-with-value accepted");
            Ok(())
        }
        Ok(Err(cause)) => {
            tracing::warn!(name = %obj.config.name, ?cause, "SBOw refused by the state machine");
            Err(Refusal::by_check(cause))
        }
        Err(e) => {
            tracing::warn!(name = %obj.config.name, error = %e, "SBOw failed internally");
            Err(Refusal::internal())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Operate
// ─────────────────────────────────────────────────────────────────────────────

/// Handles a write to `$CO$<DO>$Oper`, for every control model, and runs the
/// command to completion.
///
/// An Operate refused by the admission checks or by the dynamic check returns
/// the cause of the refusal and sends no CommandTermination. An object without a
/// control handler, and an Operate carrying an activation time other than 0,
/// are refused with `NotSupported`. Otherwise the
/// command runs, and with enhanced security it ends with a CommandTermination,
/// positive or negative, through `ct_sink`; the result is the outcome of the
/// command.
pub async fn handle_operate(
    obj: &ControlObject,
    conn_id: u64,
    raw_value: &MmsValue,
    check_handler: Option<&Arc<dyn CheckHandler>>,
    wait_handler: Option<&Arc<dyn WaitForExecutionHandler>>,
    operate_handler: Option<&Arc<dyn ControlHandler>>,
    ct_sink: &dyn CommandTerminationSink,
) -> ServiceResult {
    // Parse the Oper parameters.
    let params = match OperParams::from_mms_value(raw_value) {
        Some(p) => p,
        None => {
            tracing::warn!(name = %obj.config.name, "operate refused: parameters did not parse");
            return ServiceResult::Failure(ControlAddCause::InconsistentParameters);
        }
    };

    let accepted = match admit_operate(
        obj,
        conn_id,
        params,
        raw_value,
        check_handler,
        wait_handler,
        operate_handler,
    ) {
        Ok(a) => a,
        Err(refusal) => return ServiceResult::Failure(refusal.cause),
    };

    if let Err(cause) = accepted.dynamic_check().await {
        return ServiceResult::Failure(cause);
    }
    accepted.mark_answered();
    let result = accepted.run().await;
    accepted.terminate(ct_sink, result);
    match result {
        Ok(()) => ServiceResult::Success,
        Err(cause) => ServiceResult::Failure(cause),
    }
}

/// An Operate that passed every admission check and awaits execution.
///
/// The object is in `WaitForExecution`. `dynamic_check` decides the Operate
/// response; after a positive response `run` carries the command out and leaves
/// the object in ready or unselected.
///
/// Dropping a command that has not finished, as when a handler panics,
/// restores the object: one not yet answered returns to unselected, and one
/// answered positively ends as a failed command, with a negative
/// CommandTermination carrying `Unknown` under enhanced security when a sink
/// is attached.
pub(crate) struct AcceptedOperate {
    obj: ControlObject,
    /// The settings in force when the Operate was admitted, which the command
    /// keeps however the configuration attributes change meanwhile.
    settings: ControlSettings,
    conn_id: u64,
    action: ControlAction,
    params: OperParams,
    oper_value: Bytes,
    wait_handler: Option<Arc<dyn WaitForExecutionHandler>>,
    operate_handler: Arc<dyn ControlHandler>,
    /// Where an unfinished command dropped after its positive response reports
    /// its end.
    ct_sink: Option<Arc<dyn CommandTerminationSink>>,
    /// How far the command has come: `ADMITTED`, `ANSWERED` or `FINISHED`.
    phase: AtomicU8,
}

/// The command awaits its dynamic check and its Operate response.
const ADMITTED: u8 = 0;
/// The command was answered positively and is to run.
const ANSWERED: u8 = 1;
/// The command finished, or was refused or abandoned.
const FINISHED: u8 = 2;

/// Admits an Operate whose parameters have been parsed: the state machine, the
/// parameter checks, and the static check handler.
///
/// An Operate carrying an activation time `operTm` other than 0, a
/// TimeActivatedOperate, is refused with `NotSupported`; an `operTm` of 0 is
/// an immediate Operate.
///
/// `raw_value` is the Oper structure as the client sent it, which a
/// CommandTermination echoes back.
///
/// # Errors
///
/// Returns the refusal; the object is then unchanged, or back in unselected
/// when the refusal ended its selection.
pub(crate) fn admit_operate(
    obj: &ControlObject,
    conn_id: u64,
    params: OperParams,
    raw_value: &MmsValue,
    check_handler: Option<&Arc<dyn CheckHandler>>,
    wait_handler: Option<&Arc<dyn WaitForExecutionHandler>>,
    operate_handler: Option<&Arc<dyn ControlHandler>>,
) -> Result<AcceptedOperate, Refusal> {
    // Expire a stale selection first; a select-before-operate object then reports
    // that it is not selected.
    obj.check_sbo_timeout();

    let Some(operate_handler) = operate_handler else {
        tracing::warn!(
            name = %obj.config.name,
            "operate refused: no control handler is installed for this object"
        );
        return Err(Refusal::by_check(ControlAddCause::NotSupported));
    };

    // TimeActivatedOperate is not supported; the object is left as it was.
    if params.oper_tm_ms != 0 {
        tracing::warn!(
            name = %obj.config.name,
            oper_tm_ms = params.oper_tm_ms,
            "operate refused: time-activated operate is not supported"
        );
        return Err(Refusal::by_check(ControlAddCause::NotSupported));
    }

    // Admit the request: state machine and parameter checks.
    match obj.begin_operate(conn_id, &params) {
        Ok(Some(OperateBeginResult::Accepted)) => {}
        Ok(Some(OperateBeginResult::Denied(cause))) => return Err(Refusal::by_check(cause)),
        Ok(None) => return Err(Refusal::internal()),
        Err(e) => {
            tracing::warn!(name = %obj.config.name, error = %e, "operate failed internally");
            return Err(Refusal::internal());
        }
    }

    let action = ControlAction::new(
        params.ctl_num,
        params.origin.clone(),
        params.t,
        params.test,
        params.synchro_check,
        params.interlock_check,
        false, // this is an operate, not a select
        conn_id,
    );

    // Static check, before the dynamic one.
    if let Some(h) = check_handler {
        if let Err(cause) = h.check(
            &action,
            Some(&params.ctl_val),
            params.test,
            params.interlock_check,
        ) {
            tracing::warn!(name = %obj.config.name, ?cause, "operate refused by the check handler");
            obj.abort_to_unselected();
            return Err(Refusal::by_check(cause));
        }
    }

    Ok(AcceptedOperate {
        obj: obj.clone(),
        settings: obj.settings(),
        conn_id,
        action,
        params,
        oper_value: encode_mms_value_to_bytes(raw_value),
        wait_handler: wait_handler.cloned(),
        operate_handler: operate_handler.clone(),
        ct_sink: None,
        phase: AtomicU8::new(ADMITTED),
    })
}

impl AcceptedOperate {
    /// Attaches the sink an unfinished command dropped after its positive
    /// response reports its end through.
    pub(crate) fn with_ct_sink(mut self, ct_sink: Arc<dyn CommandTerminationSink>) -> Self {
        self.ct_sink = Some(ct_sink);
        self
    }

    /// Records that the Operate was answered positively, so the command is to
    /// run.
    pub(crate) fn mark_answered(&self) {
        self.phase.store(ANSWERED, Ordering::Release);
    }

    /// Gives up a command whose positive response was not delivered: the
    /// command does not run and the object returns to unselected, reporting
    /// `reason`.
    pub(crate) async fn abandon(&self, reason: SelectStateChangedReason) {
        change_off_the_runtime(&self.obj, move |obj| obj.abort(reason)).await;
        self.phase.store(FINISHED, Ordering::Release);
    }

    /// Returns whether the object uses enhanced security, whose result travels
    /// in a CommandTermination rather than in the Operate response.
    pub(crate) fn is_enhanced(&self) -> bool {
        matches!(
            self.settings.ctl_model,
            ControlModel::DirectEnhanced | ControlModel::SboEnhanced
        )
    }

    /// Returns whether a dynamic check is installed, which decides the outcome
    /// of the Operate response only once it finishes.
    pub(crate) fn has_dynamic_check(&self) -> bool {
        self.wait_handler.is_some()
    }

    /// Runs the dynamic check, the WaitForExecution state of IEC 61850-7-2.
    ///
    /// The Operate response follows its outcome: a refusal returns the object to
    /// unselected and is answered negatively, a pass is answered positively and
    /// lets the command run.
    ///
    /// # Errors
    ///
    /// Returns the add cause of the dynamic check.
    pub(crate) async fn dynamic_check(&self) -> Result<(), ControlAddCause> {
        let Some(h) = &self.wait_handler else {
            return Ok(());
        };
        let outcome = h
            .wait_for_execution(
                &self.action,
                &self.params.ctl_val,
                self.params.test,
                self.params.synchro_check,
            )
            .await;
        if let Err(cause) = outcome {
            tracing::warn!(name = %self.obj.config.name, ?cause, "operate refused by the dynamic check");
            change_off_the_runtime(&self.obj, ControlObject::abort_to_unselected).await;
            self.phase.store(FINISHED, Ordering::Release);
        }
        outcome
    }

    /// Runs the command once the Operate has been answered positively, limited
    /// by the operate timeout in force when it was admitted.
    ///
    /// The object returns to ready or unselected according to the select class
    /// however the command ends.
    ///
    /// # Errors
    ///
    /// Returns the add cause of the control handler, or `TimeLimitOver` when the
    /// command outlasts the operate timeout.
    pub(crate) async fn run(&self) -> Result<(), ControlAddCause> {
        let name = &self.obj.config.name;
        self.obj.set_state_operate();
        let command =
            self.operate_handler
                .operate(&self.action, &self.params.ctl_val, self.params.test);
        let result = match self.settings.oper_timeout_ms {
            0 => command.await,
            timeout_ms => {
                match tokio::time::timeout(Duration::from_millis(u64::from(timeout_ms)), command)
                    .await
                {
                    Ok(r) => r,
                    Err(_) => {
                        tracing::warn!(
                            name = %name,
                            timeout_ms,
                            "operate ended: the command outlasted the operate timeout"
                        );
                        Err(ControlAddCause::TimeLimitOver)
                    }
                }
            }
        };
        // Return to ready or unselected according to the select class.
        change_off_the_runtime(&self.obj, ControlObject::finish_operate).await;
        self.phase.store(FINISHED, Ordering::Release);

        match result {
            Ok(()) => tracing::debug!(name = %name, "operate succeeded"),
            Err(cause) => {
                tracing::warn!(name = %name, ?cause, "operate failed in the control handler")
            }
        }
        result
    }

    /// Returns the `Error` member of the LastApplError that ends this command
    /// negatively: `Unknown` for an internal failure of the server, otherwise
    /// as `termination_error_code` decides from `Test`.
    fn termination_error(&self, internal: bool) -> ControlLastApplError {
        if internal {
            ControlLastApplError::Unknown
        } else {
            super::dispatch::termination_error_code(self.params.test)
        }
    }

    /// Returns the negative CommandTermination that ends this command with
    /// `cause` under enhanced security, or `None` under normal security;
    /// `internal` marks an internal failure of the server.
    pub(crate) fn negative_termination(
        &self,
        cause: ControlAddCause,
        internal: bool,
    ) -> Option<ConnectionTerminationEvent> {
        self.is_enhanced()
            .then(|| ConnectionTerminationEvent::Negative {
                obj_ref: self.obj.object_ref(),
                add_cause: cause,
                error: self.termination_error(internal),
                oper_value: self.oper_value.clone(),
            })
    }

    /// Sends the CommandTermination of a command that ran when the object uses
    /// enhanced security; does nothing under normal security.
    pub(crate) fn terminate(
        &self,
        ct_sink: &dyn CommandTerminationSink,
        result: Result<(), ControlAddCause>,
    ) {
        if !self.is_enhanced() {
            return;
        }
        let obj_ref = self.obj.object_ref();
        match result {
            Ok(()) => ct_sink.send_positive(&obj_ref, self.conn_id, self.oper_value.clone()),
            Err(cause) => ct_sink.send_negative(
                &obj_ref,
                self.conn_id,
                cause,
                self.termination_error(false),
                self.oper_value.clone(),
            ),
        }
    }
}

/// Applies `change` to `obj` off the runtime, since a change of the selection
/// reaches the selection change handlers; inline when the runtime is shutting
/// down.
///
/// A command marks itself finished only once this returns, so a command
/// dropped while it waits, as on a runtime shutdown, still ends through its
/// `Drop`; both changes are idempotent.
async fn change_off_the_runtime<F>(obj: &ControlObject, change: F)
where
    F: FnOnce(&ControlObject) + Clone + Send + 'static,
{
    let object = obj.clone();
    let off = change.clone();
    if crate::blocking::off_the_runtime(move || off(&object))
        .await
        .is_none()
    {
        change(obj);
    }
}

impl Drop for AcceptedOperate {
    fn drop(&mut self) {
        match *self.phase.get_mut() {
            FINISHED => {}
            ADMITTED => {
                tracing::warn!(
                    name = %self.obj.config.name,
                    "operate ended before its response, returning the object to unselected"
                );
                self.obj.abort_to_unselected();
            }
            _ => {
                tracing::warn!(
                    name = %self.obj.config.name,
                    "operate ended without its control handler finishing, ending the command"
                );
                self.obj.finish_operate();
                if let (true, Some(sink)) = (self.is_enhanced(), &self.ct_sink) {
                    sink.send_negative(
                        &self.obj.object_ref(),
                        self.conn_id,
                        ControlAddCause::Unknown,
                        self.termination_error(true),
                        self.oper_value.clone(),
                    );
                }
            }
        }
    }
}

/// Encodes an `MmsValue` into its wire bytes.
///
/// The result becomes the second AccessResult of a CommandTermination
/// InformationReport.
fn encode_mms_value_to_bytes(v: &MmsValue) -> Bytes {
    use crate::service::convert::mms_value_to_mms_data;
    let mut buf = BytesMut::new();
    mms_value_to_mms_data(v).encode(&mut buf);
    buf.freeze()
}

// ─────────────────────────────────────────────────────────────────────────────
// Cancel
// ─────────────────────────────────────────────────────────────────────────────

/// Handles a write to `$CO$<DO>$Cancel`.
///
/// A value that does not parse as a Cancel structure is refused with
/// `InconsistentParameters` and cancels nothing.
pub fn handle_cancel(obj: &ControlObject, conn_id: u64, raw_value: &MmsValue) -> ServiceResult {
    if CancelParams::from_mms_value(raw_value).is_none() {
        tracing::warn!(name = %obj.config.name, "cancel refused: parameters did not parse");
        return ServiceResult::Failure(ControlAddCause::InconsistentParameters);
    }
    match cancel(obj, conn_id) {
        Ok(()) => ServiceResult::Success,
        Err(refusal) => ServiceResult::Failure(refusal.cause),
    }
}

/// Runs a Cancel whose parameters have been parsed.
///
/// # Errors
///
/// Returns the refusal.
pub(crate) fn cancel(obj: &ControlObject, conn_id: u64) -> Result<(), Refusal> {
    match obj.try_cancel(conn_id) {
        CancelResult::Accepted => {
            tracing::debug!(name = %obj.config.name, conn_id, "cancel accepted");
            Ok(())
        }
        // The state machine reports an unknown cause only when it failed internally.
        CancelResult::Denied(ControlAddCause::Unknown) => {
            tracing::warn!(name = %obj.config.name, conn_id, "cancel failed internally");
            Err(Refusal::internal())
        }
        CancelResult::Denied(cause) => {
            tracing::warn!(name = %obj.config.name, ?cause, conn_id, "cancel refused");
            Err(Refusal::by_check(cause))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Parsing a control object path
// ─────────────────────────────────────────────────────────────────────────────

/// Which control attribute a path names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoAttr {
    /// `$CO$<DO>$SBO`: the select of the normal-security model, read by a client.
    Sbo,
    /// `$CO$<DO>$SBOw`: the select of the enhanced-security model, written by a
    /// client.
    SBOw,
    /// `$CO$<DO>$Oper`: the operate, written by a client.
    Oper,
    /// `$CO$<DO>$Cancel`: the cancel, written by a client.
    Cancel,
}

/// Parses an MMS item identifier as a control attribute path.
///
/// The path has four segments, `LN$CO$DO$Attr`, with the functional constraint
/// `CO`. Returns the data object name and the attribute, or `None` when the
/// identifier is not a control path.
pub fn parse_co_item_id(item_id: &str) -> Option<(&str, CoAttr)> {
    let parts: Vec<&str> = item_id.split('$').collect();
    if parts.len() == 4 && parts[1] == "CO" {
        let do_name = parts[2];
        let attr = match parts[3] {
            "SBO" => CoAttr::Sbo,
            "SBOw" => CoAttr::SBOw,
            "Oper" => CoAttr::Oper,
            "Cancel" => CoAttr::Cancel,
            _ => return None,
        };
        Some((do_name, attr))
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{
        handler::{AlwaysAcceptCheckHandler, AlwaysAcceptWaitHandler, AlwaysSuccessOperateHandler},
        model::SboClass,
        object::ControlObjectConfig,
        state::ControlState,
    };
    use iec61850_model::MmsValue;

    fn make_direct_obj(model: ControlModel) -> ControlObject {
        ControlObject::new(ControlObjectConfig {
            name: "SPCSO1".into(),
            ln_name: "GGIO1".into(),
            domain: "IED1LD0".into(),
            ctl_model: model,
            sbo_timeout_ms: 5000,
            sbo_class: SboClass::OperateOnce,
            oper_timeout_ms: 0,
        })
    }

    fn make_timed_obj(oper_timeout_ms: u32) -> ControlObject {
        let mut config =
            ControlObjectConfig::new("SPCSO1", "GGIO1", "IED1LD0", ControlModel::DirectEnhanced);
        config.oper_timeout_ms = oper_timeout_ms;
        ControlObject::new(config)
    }

    fn make_oper_value() -> MmsValue {
        // 6-element Oper structure
        MmsValue::Structure(vec![
            MmsValue::Boolean(true), // ctlVal
            MmsValue::Structure(vec![
                MmsValue::Integer(3),
                MmsValue::OctetString(vec![0x01]),
            ]), // origin
            MmsValue::Unsigned(1),   // ctlNum
            MmsValue::UtcTime([0u8; 8]), // T
            MmsValue::Boolean(false), // Test
            MmsValue::BitString {
                padding: 6,
                data: vec![0x40],
            }, // Check: interlockCheck
        ])
    }

    fn make_sbow_value() -> MmsValue {
        make_oper_value() // SBOw has the same structure as Oper
    }

    fn make_cancel_value() -> MmsValue {
        MmsValue::Structure(vec![
            MmsValue::Boolean(true),
            MmsValue::Structure(vec![
                MmsValue::Integer(3),
                MmsValue::OctetString(vec![0x01]),
            ]),
            MmsValue::Unsigned(1),
            MmsValue::UtcTime([0u8; 8]),
            MmsValue::Boolean(false),
        ])
    }

    // ── parse_co_item_id ────────────────────────────────────────────────

    #[test]
    fn parse_co_item_id_oper() {
        let (do_name, attr) = parse_co_item_id("GGIO1$CO$SPCSO1$Oper").unwrap();
        assert_eq!(do_name, "SPCSO1");
        assert_eq!(attr, CoAttr::Oper);
    }

    #[test]
    fn parse_co_item_id_sbo() {
        let (do_name, attr) = parse_co_item_id("GGIO1$CO$SPCSO1$SBO").unwrap();
        assert_eq!(do_name, "SPCSO1");
        assert_eq!(attr, CoAttr::Sbo);
    }

    #[test]
    fn parse_co_item_id_sbow() {
        let (_, attr) = parse_co_item_id("GGIO1$CO$SPCSO1$SBOw").unwrap();
        assert_eq!(attr, CoAttr::SBOw);
    }

    #[test]
    fn parse_co_item_id_cancel() {
        let (_, attr) = parse_co_item_id("GGIO1$CO$SPCSO1$Cancel").unwrap();
        assert_eq!(attr, CoAttr::Cancel);
    }

    #[test]
    fn parse_co_item_id_non_co_none() {
        assert!(parse_co_item_id("GGIO1$CF$Mod$ctlModel").is_none());
        assert!(parse_co_item_id("GGIO1$CO$SPCSO1$stVal").is_none());
        assert!(parse_co_item_id("GGIO1$CO").is_none());
    }

    // ── handle_read_sbo happy path ──────────────────────────────────────

    #[test]
    fn handle_read_sbo_accepted() {
        let obj = make_direct_obj(ControlModel::SboNormal);
        let h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);
        let result = handle_read_sbo(&obj, 1, Some(&h));
        assert!(result.is_some());
        assert!(result.unwrap().contains("SPCSO1"));
        assert_eq!(obj.state(), ControlState::Ready);
    }

    #[test]
    fn handle_read_sbo_status_only_rejected() {
        let obj = make_direct_obj(ControlModel::StatusOnly);
        let h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);
        let result = handle_read_sbo(&obj, 1, Some(&h));
        assert!(result.is_none());
    }

    // ── handle_cancel ────────────────────────────────────────────────────

    #[test]
    fn handle_cancel_sbo_selected_same_conn() {
        let obj = make_direct_obj(ControlModel::SboNormal);
        obj.try_select(1).unwrap();

        let cancel_val = make_cancel_value();
        let r = handle_cancel(&obj, 1, &cancel_val);
        assert_eq!(r, ServiceResult::Success);
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    #[test]
    fn handle_cancel_wrong_conn_denied() {
        let obj = make_direct_obj(ControlModel::SboNormal);
        obj.try_select(1).unwrap();

        let cancel_val = make_cancel_value();
        let r = handle_cancel(&obj, 2, &cancel_val);
        assert_eq!(
            r,
            ServiceResult::Failure(ControlAddCause::LockedByOtherClient)
        );
        assert_eq!(obj.state(), ControlState::Ready);
    }

    // ── handle_sbow happy path ────────────────────────────────────────────

    #[tokio::test]
    async fn handle_sbow_accepted() {
        let obj = make_direct_obj(ControlModel::SboEnhanced);
        let h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);
        let sbow_val = make_sbow_value();
        let r = handle_sbow(&obj, 1, &sbow_val, Some(&h)).await;
        assert_eq!(r, ServiceResult::Success);
        assert_eq!(obj.state(), ControlState::Ready);
    }

    // ── handle_operate direct-normal happy path ───────────────────────────

    #[tokio::test]
    async fn handle_operate_direct_normal_success() {
        let obj = make_direct_obj(ControlModel::DirectNormal);
        let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);
        let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
        let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
        let ct = NoOpCommandTermination;

        let oper_val = make_oper_value();
        let r = handle_operate(
            &obj,
            1,
            &oper_val,
            Some(&check_h),
            Some(&wait_h),
            Some(&oper_h),
            &ct,
        )
        .await;
        assert_eq!(r, ServiceResult::Success);
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    // ── Direct control with enhanced security sends a positive CommandTermination ──

    #[tokio::test]
    async fn handle_operate_direct_enhanced_sends_command_termination() {
        let obj = make_direct_obj(ControlModel::DirectEnhanced);
        let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);
        let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
        let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let ct = RecordingCommandTermination {
            events: events.clone(),
        };

        let oper_val = make_oper_value();
        let r = handle_operate(
            &obj,
            1,
            &oper_val,
            Some(&check_h),
            Some(&wait_h),
            Some(&oper_h),
            &ct,
        )
        .await;
        assert_eq!(r, ServiceResult::Success);

        let recorded = events.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert!(matches!(
            recorded[0],
            TerminationEvent::Positive { conn_id: 1, .. }
        ));
    }

    // ── handle_operate sbo-normal select + operate ────────────────────────

    #[tokio::test]
    async fn handle_operate_sbo_normal_flow() {
        let obj = make_direct_obj(ControlModel::SboNormal);
        // select first
        let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);
        handle_read_sbo(&obj, 1, Some(&check_h));
        assert_eq!(obj.state(), ControlState::Ready);

        let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
        let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
        let ct = NoOpCommandTermination;

        let oper_val = make_oper_value();
        let r = handle_operate(
            &obj,
            1,
            &oper_val,
            Some(&check_h),
            Some(&wait_h),
            Some(&oper_h),
            &ct,
        )
        .await;
        assert_eq!(r, ServiceResult::Success);
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    // ── handle_operate sbo-enhanced full flow ─────────────────────────────

    #[tokio::test]
    async fn handle_operate_sbo_enhanced_full_flow() {
        let obj = make_direct_obj(ControlModel::SboEnhanced);
        let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);

        // SBOw select
        let sbow_val = make_sbow_value();
        let r = handle_sbow(&obj, 1, &sbow_val, Some(&check_h)).await;
        assert_eq!(r, ServiceResult::Success);

        // Operate with the same parameters.
        let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
        let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let ct = RecordingCommandTermination {
            events: events.clone(),
        };

        let oper_val = make_oper_value();
        let r = handle_operate(
            &obj,
            1,
            &oper_val,
            Some(&check_h),
            Some(&wait_h),
            Some(&oper_h),
            &ct,
        )
        .await;
        assert_eq!(r, ServiceResult::Success);

        // Enhanced security sends a positive CommandTermination.
        let recorded = events.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert!(matches!(
            recorded[0],
            TerminationEvent::Positive { conn_id: 1, .. }
        ));
    }

    // ── handle_operate sbo-enhanced inconsistent params ───────────────────

    #[tokio::test]
    async fn handle_operate_sbo_enhanced_inconsistent_params_denied() {
        let obj = make_direct_obj(ControlModel::SboEnhanced);
        let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);

        // SBOw with Boolean(true)
        let sbow_val = make_sbow_value();
        handle_sbow(&obj, 1, &sbow_val, Some(&check_h)).await;

        // Operate with Boolean(false), which does not match the select.
        let oper_val = MmsValue::Structure(vec![
            MmsValue::Boolean(false), // a different control value
            MmsValue::Structure(vec![
                MmsValue::Integer(3),
                MmsValue::OctetString(vec![0x01]),
            ]),
            MmsValue::Unsigned(1),
            MmsValue::UtcTime([0u8; 8]),
            MmsValue::Boolean(false),
            MmsValue::BitString {
                padding: 6,
                data: vec![0x40],
            },
        ]);

        let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
        let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let ct = RecordingCommandTermination {
            events: events.clone(),
        };

        let r = handle_operate(
            &obj,
            1,
            &oper_val,
            Some(&check_h),
            Some(&wait_h),
            Some(&oper_h),
            &ct,
        )
        .await;
        assert_eq!(
            r,
            ServiceResult::Failure(ControlAddCause::InconsistentParameters)
        );
        // Differing parameters also deselect the object.
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    // ── A failed enhanced-security operate sends a negative CommandTermination ──

    #[tokio::test]
    async fn handle_operate_direct_enhanced_fail_sends_negative() {
        use crate::control::handler::AlwaysFailOperateHandler;
        let obj = make_direct_obj(ControlModel::DirectEnhanced);
        let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);
        let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
        let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysFailOperateHandler {
            cause: ControlAddCause::BlockedByProcess,
        });
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let ct = RecordingCommandTermination {
            events: events.clone(),
        };

        let oper_val = make_oper_value();
        let r = handle_operate(
            &obj,
            1,
            &oper_val,
            Some(&check_h),
            Some(&wait_h),
            Some(&oper_h),
            &ct,
        )
        .await;
        assert_eq!(r, ServiceResult::Failure(ControlAddCause::BlockedByProcess));

        let recorded = events.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert!(matches!(
            recorded[0],
            TerminationEvent::Negative {
                add_cause: ControlAddCause::BlockedByProcess,
                ..
            }
        ));
    }

    // ── An object without a control handler ───────────────────────────────

    #[tokio::test]
    async fn handle_operate_without_a_control_handler_is_not_supported() {
        let obj = make_direct_obj(ControlModel::DirectEnhanced);
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let ct = RecordingCommandTermination {
            events: events.clone(),
        };
        let r = handle_operate(&obj, 1, &make_oper_value(), None, None, None, &ct).await;
        assert_eq!(r, ServiceResult::Failure(ControlAddCause::NotSupported));
        assert_eq!(obj.state(), ControlState::Unselected);
        assert!(events.lock().unwrap().is_empty());
    }

    // ── A refused enhanced-security Operate sends no CommandTermination ────

    #[tokio::test]
    async fn handle_operate_refused_enhanced_sends_no_command_termination() {
        let obj = make_direct_obj(ControlModel::SboEnhanced);
        let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let ct = RecordingCommandTermination {
            events: events.clone(),
        };
        let r = handle_operate(&obj, 1, &make_oper_value(), None, None, Some(&oper_h), &ct).await;
        assert_eq!(
            r,
            ServiceResult::Failure(ControlAddCause::ObjectNotSelected)
        );
        assert!(events.lock().unwrap().is_empty());
    }

    // ── The dynamic check decides the response; the timeout limits the command ──

    /// Control handler that finishes after `delay`, or never when `None`.
    struct DelayedOperate(Option<std::time::Duration>);

    impl ControlHandler for DelayedOperate {
        fn operate<'a>(
            &'a self,
            _action: &'a ControlAction,
            _ctl_val: &'a MmsValue,
            _test: bool,
        ) -> crate::control::handler::OperateFuture<'a> {
            let delay = self.0;
            Box::pin(async move {
                match delay {
                    Some(d) => {
                        tokio::time::sleep(d).await;
                        Ok(())
                    }
                    None => std::future::pending().await,
                }
            })
        }
    }

    /// Dynamic check that refuses with a fixed cause.
    struct RefusingWait(ControlAddCause);

    impl WaitForExecutionHandler for RefusingWait {
        fn wait_for_execution<'a>(
            &'a self,
            _action: &'a ControlAction,
            _ctl_val: &'a MmsValue,
            _test: bool,
            _synchro_check: bool,
        ) -> crate::control::handler::WaitForExecFuture<'a> {
            let cause = self.0;
            Box::pin(async move { Err(cause) })
        }
    }

    fn accept(
        obj: &ControlObject,
        wait: Option<Arc<dyn WaitForExecutionHandler>>,
        operate: DelayedOperate,
    ) -> AcceptedOperate {
        let params = OperParams::from_mms_value(&make_oper_value()).expect("oper");
        let oper_h: Arc<dyn ControlHandler> = Arc::new(operate);
        admit_operate(
            obj,
            1,
            params,
            &make_oper_value(),
            None,
            wait.as_ref(),
            Some(&oper_h),
        )
        .unwrap_or_else(|cause| panic!("refused: {cause:?}"))
    }

    #[tokio::test]
    async fn a_refusing_dynamic_check_ends_the_operate_before_the_command() {
        let obj = make_direct_obj(ControlModel::DirectEnhanced);
        let wait: Arc<dyn WaitForExecutionHandler> =
            Arc::new(RefusingWait(ControlAddCause::BlockedBySynchrocheck));
        let accepted = accept(&obj, Some(wait), DelayedOperate(None));
        assert!(accepted.has_dynamic_check());
        assert_eq!(
            accepted.dynamic_check().await,
            Err(ControlAddCause::BlockedBySynchrocheck)
        );
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    #[tokio::test]
    async fn handle_operate_refused_by_the_dynamic_check_sends_no_command_termination() {
        let obj = make_direct_obj(ControlModel::DirectEnhanced);
        let wait_h: Arc<dyn WaitForExecutionHandler> =
            Arc::new(RefusingWait(ControlAddCause::BlockedBySynchrocheck));
        let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let ct = RecordingCommandTermination {
            events: events.clone(),
        };
        let r = handle_operate(
            &obj,
            1,
            &make_oper_value(),
            None,
            Some(&wait_h),
            Some(&oper_h),
            &ct,
        )
        .await;
        assert_eq!(
            r,
            ServiceResult::Failure(ControlAddCause::BlockedBySynchrocheck)
        );
        assert!(events.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn oper_timeout_ends_the_command_exactly_at_the_limit() {
        let obj = make_timed_obj(100);
        let accepted = accept(&obj, None, DelayedOperate(None));
        assert_eq!(accepted.dynamic_check().await, Ok(()));
        let started = tokio::time::Instant::now();
        // The outer bound only ends a run in which the operate timeout never fires.
        let result = tokio::time::timeout(std::time::Duration::from_secs(3600), accepted.run())
            .await
            .expect("the operate timeout never fired");
        assert_eq!(result, Err(ControlAddCause::TimeLimitOver));
        assert_eq!(started.elapsed(), std::time::Duration::from_millis(100));
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    #[tokio::test(start_paused = true)]
    async fn oper_timeout_lets_a_command_within_the_limit_finish() {
        let obj = make_timed_obj(100);
        let accepted = accept(
            &obj,
            None,
            DelayedOperate(Some(std::time::Duration::from_millis(99))),
        );
        assert_eq!(accepted.run().await, Ok(()));
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    #[tokio::test(start_paused = true)]
    async fn no_oper_timeout_waits_for_the_command() {
        let obj = make_direct_obj(ControlModel::DirectEnhanced);
        assert_eq!(obj.settings().oper_timeout_ms, 0);
        let accepted = accept(
            &obj,
            None,
            DelayedOperate(Some(std::time::Duration::from_secs(3600))),
        );
        let started = tokio::time::Instant::now();
        assert_eq!(accepted.run().await, Ok(()));
        assert_eq!(started.elapsed(), std::time::Duration::from_secs(3600));
    }

    // ── A command dropped at its final change still leaves the executing states ──

    /// Admits an Operate on `obj` whose command succeeds at once.
    fn admit_now(
        obj: &ControlObject,
        wait: Option<Arc<dyn WaitForExecutionHandler>>,
    ) -> AcceptedOperate {
        let params = OperParams::from_mms_value(&make_oper_value()).expect("oper");
        let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
        admit_operate(
            obj,
            1,
            params,
            &make_oper_value(),
            None,
            wait.as_ref(),
            Some(&oper_h),
        )
        .unwrap_or_else(|cause| panic!("refused: {cause:?}"))
    }

    /// Runs `step` on `accepted` in a task of a current-thread runtime whose
    /// one blocking thread is held, so the change of the object the step ends
    /// with waits in the queue, and shuts the runtime down with the task
    /// waiting there.
    fn drop_at_the_final_change<F, Fut>(accepted: AcceptedOperate, step: F)
    where
        F: FnOnce(AcceptedOperate) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .expect("runtime");
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        runtime.spawn_blocking(move || {
            held_tx.send(()).expect("held");
            let _ = release_rx.recv();
        });
        held_rx.recv().expect("the blocking thread is held");
        let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        runtime.spawn({
            let started = started.clone();
            async move {
                started.store(true, Ordering::SeqCst);
                step(accepted).await;
            }
        });
        // Nothing the step awaits before its final change is pending, so the
        // task reaches that change before this sees the flag.
        runtime.block_on(async {
            while !started.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        });
        runtime.shutdown_background();
        drop(release_tx);
    }

    #[test]
    fn a_command_dropped_as_it_finishes_leaves_the_operate_state() {
        let obj = make_direct_obj(ControlModel::DirectEnhanced);
        let accepted = admit_now(&obj, None);
        drop_at_the_final_change(accepted, |a| async move {
            let _ = a.run().await;
        });
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    #[test]
    fn a_command_dropped_as_its_dynamic_check_refuses_leaves_the_wait_state() {
        let obj = make_direct_obj(ControlModel::DirectEnhanced);
        let wait: Arc<dyn WaitForExecutionHandler> =
            Arc::new(RefusingWait(ControlAddCause::BlockedBySynchrocheck));
        let accepted = admit_now(&obj, Some(wait));
        drop_at_the_final_change(accepted, |a| async move {
            let _ = a.dynamic_check().await;
        });
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    #[test]
    fn a_command_dropped_as_it_is_abandoned_leaves_the_wait_state() {
        let obj = make_direct_obj(ControlModel::DirectEnhanced);
        let accepted = admit_now(&obj, None);
        drop_at_the_final_change(accepted, |a| async move {
            a.abandon(SelectStateChangedReason::Disconnected).await;
        });
        assert_eq!(obj.state(), ControlState::Unselected);
    }
}
