//! `ControlObject`: the per-data-object control state.
//!
//! One instance per controllable data object, holding the state machine of
//! IEC 61850-7-2 control, the application handlers, and the selection timer.
//!
//! The mutable state sits behind a `Mutex`, so several tasks may drive the same
//! object; handlers are held as `Arc<dyn Trait>`. A select timeout is driven by a
//! timer task rather than polled from a main loop.

use super::handler::{
    CheckHandler, ControlHandler, SelectStateChangedHandler, SelectStateChangedReason,
    WaitForExecutionHandler,
};
use super::model::{
    ControlAction, ControlAddCause, ControlModel, OperParams, OriginValue, SboClass,
};
use super::state::ControlState;
use crate::error::ServerError;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────
// ControlObjectConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Static configuration of one control object.
#[derive(Debug, Clone)]
pub struct ControlObjectConfig {
    /// Data object name.
    pub name: String,
    /// Logical node name.
    pub ln_name: String,
    /// Logical device domain, the IED name and LD instance, for example `IED1LD0`.
    pub domain: String,
    /// Control model, from the `ctlModel` data attribute.
    pub ctl_model: ControlModel,
    /// Select timeout in milliseconds; 0 disables it.
    ///
    /// From the `sboTimeout` attribute, defaulting to 30000 ms when absent.
    pub sbo_timeout_ms: u32,
    /// Select class, from the `sboClass` attribute: whether one selection admits a
    /// single Operate or several.
    pub sbo_class: SboClass,
}

impl ControlObjectConfig {
    /// Validates a raw `ctlModel` value.
    ///
    /// A value outside 0..=4 is refused rather than silently coerced, so a
    /// misconfigured model fails at startup instead of behaving unexpectedly at
    /// runtime.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::InvalidCtlModel` when the value is out of range.
    pub fn validate_ctl_model(val: i32) -> Result<ControlModel, ServerError> {
        match val {
            0 => Ok(ControlModel::StatusOnly),
            1 => Ok(ControlModel::DirectNormal),
            2 => Ok(ControlModel::SboNormal),
            3 => Ok(ControlModel::DirectEnhanced),
            4 => Ok(ControlModel::SboEnhanced),
            _ => {
                tracing::warn!(
                    ctl_model = val,
                    "ctlModel out of range, valid values are 0 to 4"
                );
                Err(ServerError::InvalidCtlModel { value: val })
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ControlObjectInner: the state behind the mutex
// ─────────────────────────────────────────────────────────────────────────────

struct ControlObjectInner {
    state: ControlState,

    /// Parameters of the most recent Oper or SBOw, kept to compare an Operate
    /// against the select that preceded it.
    last_oper_params: Option<OperParams>,

    /// Connection holding the selection, or 0 when none does.
    owner_conn_id: u64,

    /// When the object was selected, for the timeout.
    select_time: Option<Instant>,

    /// Activation time in milliseconds for a time-activated command; 0 when the
    /// command is not time-activated.
    #[allow(dead_code)]
    activate_time_ms: u64,

    /// Invoke id of a response deferred by a time-activated command or an
    /// asynchronous select.
    #[allow(dead_code)]
    pending_invoke_id: u32,
}

impl ControlObjectInner {
    fn new() -> Self {
        Self {
            state: ControlState::default(),
            last_oper_params: None,
            owner_conn_id: 0,
            select_time: None,
            activate_time_ms: 0,
            pending_invoke_id: 0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ControlObject: the public handle
// ─────────────────────────────────────────────────────────────────────────────

/// Control state of one controllable data object.
///
/// Implements the control object of IEC 61850-7-2 with a mutex around the mutable
/// state rather than a semaphore.
#[derive(Clone)]
pub struct ControlObject {
    /// Static configuration, shared by every clone of this handle.
    pub config: Arc<ControlObjectConfig>,
    inner: Arc<Mutex<ControlObjectInner>>,

    // Application handlers.
    /// Static check handler, installed by `set_check_handler`.
    pub check_handler: Arc<Mutex<Option<Arc<dyn CheckHandler>>>>,
    /// Dynamic check handler, installed by `set_wait_for_exec_handler`.
    pub wait_for_exec_handler: Arc<Mutex<Option<Arc<dyn WaitForExecutionHandler>>>>,
    /// Handler that carries the command out, installed by `set_operate_handler`.
    pub operate_handler: Arc<Mutex<Option<Arc<dyn ControlHandler>>>>,
    /// Selection change handler, installed by `set_select_state_handler`.
    pub select_state_handler: Arc<Mutex<Option<Arc<dyn SelectStateChangedHandler>>>>,
}

impl std::fmt::Debug for ControlObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlObject")
            .field("name", &self.config.name)
            .field("ln_name", &self.config.ln_name)
            .field("ctl_model", &self.config.ctl_model)
            .finish()
    }
}

impl ControlObject {
    /// Creates a control object in the unselected state.
    pub fn new(config: ControlObjectConfig) -> Self {
        Self {
            config: Arc::new(config),
            inner: Arc::new(Mutex::new(ControlObjectInner::new())),
            check_handler: Arc::new(Mutex::new(None)),
            wait_for_exec_handler: Arc::new(Mutex::new(None)),
            operate_handler: Arc::new(Mutex::new(None)),
            select_state_handler: Arc::new(Mutex::new(None)),
        }
    }

    /// Returns the current state.
    pub fn state(&self) -> ControlState {
        self.inner
            .lock()
            .map(|g| g.state)
            .unwrap_or(ControlState::Unselected)
    }

    /// Installs the check handler.
    pub fn set_check_handler(&self, h: Arc<dyn CheckHandler>) {
        if let Ok(mut g) = self.check_handler.lock() {
            *g = Some(h);
        }
    }

    /// Installs the wait-for-execution handler.
    pub fn set_wait_for_exec_handler(&self, h: Arc<dyn WaitForExecutionHandler>) {
        if let Ok(mut g) = self.wait_for_exec_handler.lock() {
            *g = Some(h);
        }
    }

    /// Installs the control handler.
    pub fn set_operate_handler(&self, h: Arc<dyn ControlHandler>) {
        if let Ok(mut g) = self.operate_handler.lock() {
            *g = Some(h);
        }
    }

    /// Installs the select state changed handler.
    pub fn set_select_state_handler(&self, h: Arc<dyn SelectStateChangedHandler>) {
        if let Ok(mut g) = self.select_state_handler.lock() {
            *g = Some(h);
        }
    }

    // ─── Select and deselect ─────────────────────────────────────────────

    /// Selects the object for a connection, moving it from unselected to ready.
    ///
    /// Returns `Ok(true)` when the object is now selected, `Ok(false)` when the
    /// request was refused because another connection holds it or the state does
    /// not allow a select.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::Protocol` when the state mutex is poisoned.
    pub fn try_select(&self, conn_id: u64) -> Result<bool, ServerError> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| ServerError::Protocol("ControlObject Mutex poisoned on select".into()))?;

        match g.state {
            ControlState::Unselected => {
                g.state = ControlState::Ready;
                g.owner_conn_id = conn_id;
                g.select_time = Some(Instant::now());
                tracing::debug!(
                    name = %self.config.name,
                    conn_id,
                    "select accepted, object is now ready"
                );
                Ok(true)
            }
            ControlState::Ready => {
                if g.owner_conn_id == conn_id {
                    // The same connection selecting again refreshes the timeout.
                    g.select_time = Some(Instant::now());
                    Ok(true)
                } else {
                    tracing::warn!(
                        name = %self.config.name,
                        owner = g.owner_conn_id,
                        requester = conn_id,
                        "select refused: the object is selected by another connection"
                    );
                    Ok(false)
                }
            }
            other => {
                tracing::warn!(
                    name = %self.config.name,
                    ?other,
                    "select refused: the current state does not allow it"
                );
                Ok(false)
            }
        }
    }

    /// Deselects the object, on Cancel, timeout, or a lost connection.
    ///
    /// The deselection happens only when `conn_id` holds the selection, or when
    /// `unconditional` is set. Returns whether the object was deselected.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::Protocol` when the state mutex is poisoned.
    pub fn try_unselect(
        &self,
        conn_id: u64,
        reason: SelectStateChangedReason,
        unconditional: bool,
    ) -> Result<bool, ServerError> {
        let mut g = self.inner.lock().map_err(|_| {
            ServerError::Protocol("ControlObject Mutex poisoned on unselect".into())
        })?;

        let can_unselect = unconditional || g.owner_conn_id == conn_id;
        if !can_unselect {
            tracing::warn!(
                name = %self.config.name,
                owner = g.owner_conn_id,
                requester = conn_id,
                "deselect refused: the selection is held by another connection"
            );
            return Ok(false);
        }

        g.state = ControlState::Unselected;
        g.owner_conn_id = 0;
        g.select_time = None;
        g.last_oper_params = None;
        tracing::debug!(name = %self.config.name, ?reason, "SBO unselected");
        drop(g);

        self.notify_select_state_changed(
            conn_id,
            false,
            reason,
            [0u8; 8],
            OriginValue::default(),
            0,
        );

        Ok(true)
    }

    /// Deselects the object when its select timeout has elapsed; called from a
    /// timer task.
    ///
    /// Returns whether the timeout fired. A configured timeout of 0 never fires.
    pub fn check_sbo_timeout(&self) -> bool {
        let timeout_ms = self.config.sbo_timeout_ms;
        if timeout_ms == 0 {
            return false;
        }

        let (conn_id, timed_out) = {
            let g = match self.inner.lock() {
                Ok(g) => g,
                Err(_) => return false,
            };
            if g.state != ControlState::Ready {
                return false;
            }
            let timed_out = g
                .select_time
                .map(|t| t.elapsed() > Duration::from_millis(timeout_ms as u64))
                .unwrap_or(false);
            (g.owner_conn_id, timed_out)
        };

        if timed_out {
            tracing::warn!(
                name = %self.config.name,
                timeout_ms,
                "select timeout elapsed, deselecting"
            );
            let _ = self.try_unselect(conn_id, SelectStateChangedReason::Timeout, true);
            true
        } else {
            false
        }
    }

    // ─── Operate ─────────────────────────────────────────────────────────

    /// Admits an Operate request and moves the object into the executing states.
    ///
    /// Returns `Ok(Some(Accepted))` when the command may proceed, and
    /// `Ok(Some(Denied(cause)))` when it is refused, for example because the
    /// connection does not hold the selection, the state does not allow it, or the
    /// parameters do not match the preceding select.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::Protocol` when the state mutex is poisoned.
    pub fn begin_operate(
        &self,
        conn_id: u64,
        params: &OperParams,
    ) -> Result<Option<OperateBeginResult>, ServerError> {
        let mut g = self.inner.lock().map_err(|_| {
            ServerError::Protocol("ControlObject Mutex poisoned on begin_operate".into())
        })?;

        // A status-only object never accepts a control request.
        if self.config.ctl_model == ControlModel::StatusOnly {
            tracing::warn!(name = %self.config.name, "operate refused: ctlModel is status-only");
            return Ok(Some(OperateBeginResult::Denied(
                ControlAddCause::NotSupported,
            )));
        }

        // The origin field must be well formed.
        if !params.origin.is_valid() {
            tracing::warn!(
                name = %self.config.name,
                or_cat = params.origin.or_cat,
                or_ident_len = params.origin.or_ident.len(),
                "operate refused: malformed origin field"
            );
            return Ok(Some(OperateBeginResult::Denied(
                ControlAddCause::InconsistentParameters,
            )));
        }

        match self.config.ctl_model {
            ControlModel::DirectNormal | ControlModel::DirectEnhanced => {
                // Direct control: unselected counts as ready.
                if !matches!(g.state, ControlState::Unselected | ControlState::Ready) {
                    tracing::warn!(
                        name = %self.config.name,
                        state = ?g.state,
                        "operate refused: direct control requires an idle object"
                    );
                    return Ok(Some(OperateBeginResult::Denied(
                        ControlAddCause::CommandAlreadyInExecution,
                    )));
                }
                g.state = ControlState::WaitForExecution;
                g.owner_conn_id = conn_id;
                g.last_oper_params = Some(params.clone());
                Ok(Some(OperateBeginResult::Accepted))
            }

            ControlModel::SboNormal => {
                // Select-before-operate: the object must be selected by this
                // connection.
                if g.state != ControlState::Ready {
                    tracing::warn!(
                        name = %self.config.name,
                        state = ?g.state,
                        "operate refused: the object is not selected"
                    );
                    return Ok(Some(OperateBeginResult::Denied(
                        ControlAddCause::ObjectNotSelected,
                    )));
                }
                if g.owner_conn_id != conn_id {
                    tracing::warn!(
                        name = %self.config.name,
                        owner = g.owner_conn_id,
                        requester = conn_id,
                        "operate refused: the selection is held by another connection"
                    );
                    return Ok(Some(OperateBeginResult::Denied(
                        ControlAddCause::LockedByOtherClient,
                    )));
                }
                g.state = ControlState::WaitForExecution;
                g.last_oper_params = Some(params.clone());
                Ok(Some(OperateBeginResult::Accepted))
            }

            ControlModel::SboEnhanced => {
                // Enhanced security additionally requires the parameters to match
                // those of the SBOw.
                if g.state != ControlState::Ready {
                    tracing::warn!(
                        name = %self.config.name,
                        state = ?g.state,
                        "operate refused: the object is not selected"
                    );
                    return Ok(Some(OperateBeginResult::Denied(
                        ControlAddCause::ObjectNotSelected,
                    )));
                }
                if g.owner_conn_id != conn_id {
                    tracing::warn!(
                        name = %self.config.name,
                        owner = g.owner_conn_id,
                        requester = conn_id,
                        "operate refused: the selection is held by another connection"
                    );
                    return Ok(Some(OperateBeginResult::Denied(
                        ControlAddCause::LockedByOtherClient,
                    )));
                }
                // The Operate parameters must equal those of the select.
                if let Some(ref sbow_params) = g.last_oper_params {
                    if !params_consistent(params, sbow_params) {
                        tracing::warn!(
                            name = %self.config.name,
                            "operate refused: parameters differ from the preceding SBOw"
                        );
                        g.state = ControlState::Unselected;
                        g.owner_conn_id = 0;
                        g.last_oper_params = None;
                        return Ok(Some(OperateBeginResult::Denied(
                            ControlAddCause::InconsistentParameters,
                        )));
                    }
                } else {
                    tracing::warn!(
                        name = %self.config.name,
                        "operate refused: no SBOw was recorded for this object"
                    );
                    return Ok(Some(OperateBeginResult::Denied(
                        ControlAddCause::ObjectNotSelected,
                    )));
                }
                g.state = ControlState::WaitForExecution;
                g.last_oper_params = Some(params.clone());
                Ok(Some(OperateBeginResult::Accepted))
            }

            ControlModel::StatusOnly => unreachable!(),
        }
    }

    /// Completes an Operate, returning to ready or unselected according to the
    /// select class.
    pub fn finish_operate(&self) {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let is_sbo = matches!(
            self.config.ctl_model,
            ControlModel::SboNormal | ControlModel::SboEnhanced
        );
        if is_sbo && self.config.sbo_class == SboClass::OperateMany {
            // A many-operate selection stays selected.
            g.state = ControlState::Ready;
            g.select_time = Some(Instant::now()); // refresh the select timeout
        } else {
            // A once-only selection, and direct control, return to unselected.
            g.state = ControlState::Unselected;
            g.owner_conn_id = 0;
            g.last_oper_params = None;
            g.select_time = None;
        }
    }

    /// Moves the object from awaiting the dynamic check to executing the command.
    pub fn set_state_operate(&self) {
        if let Ok(mut g) = self.inner.lock() {
            if g.state == ControlState::WaitForExecution {
                g.state = ControlState::Operate;
            }
        }
    }

    /// Returns the object to unselected after a refused check or a failed command.
    pub fn abort_to_unselected(&self) {
        if let Ok(mut g) = self.inner.lock() {
            g.state = ControlState::Unselected;
            g.owner_conn_id = 0;
            g.last_oper_params = None;
            g.select_time = None;
        }
    }

    // ─── Select with value ───────────────────────────────────────────────

    /// Selects the object with a value, recording the SBOw parameters an Operate
    /// will later be compared against.
    ///
    /// Returns whether the object was selected.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::Protocol` when the state mutex is poisoned.
    pub fn try_sbow_select(&self, conn_id: u64, params: &OperParams) -> Result<bool, ServerError> {
        let mut g = self.inner.lock().map_err(|_| {
            ServerError::Protocol("ControlObject Mutex poisoned on sbow_select".into())
        })?;

        if g.state != ControlState::Unselected {
            tracing::warn!(
                name = %self.config.name,
                state = ?g.state,
                "select-with-value refused: the object is already selected or executing"
            );
            return Ok(false);
        }

        // The origin field must be well formed.
        if !params.origin.is_valid() {
            tracing::warn!(
                name = %self.config.name,
                "select-with-value refused: malformed origin field"
            );
            return Ok(false);
        }

        g.state = ControlState::Ready;
        g.owner_conn_id = conn_id;
        g.select_time = Some(Instant::now());
        g.last_oper_params = Some(params.clone());
        tracing::debug!(name = %self.config.name, conn_id, "select-with-value accepted");
        Ok(true)
    }

    // ─── Cancel ──────────────────────────────────────────────────────────

    /// Cancels a selection or a pending time-activated command.
    ///
    /// An executing command is not cancellable and is refused with
    /// `CommandAlreadyInExecution`. A selected object is deselected when the
    /// request comes from the connection that holds it. A pending time-activated
    /// command is discarded. Canceling an unselected object succeeds and does
    /// nothing.
    pub fn try_cancel(&self, conn_id: u64) -> CancelResult {
        let g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return CancelResult::Denied(ControlAddCause::Unknown),
        };

        if g.state.is_executing() {
            tracing::warn!(
                name = %self.config.name,
                state = ?g.state,
                "cancel refused: a command is executing"
            );
            return CancelResult::Denied(ControlAddCause::CommandAlreadyInExecution);
        }

        if g.state == ControlState::WaitForActivationTime {
            drop(g);
            self.abort_to_unselected();
            return CancelResult::Accepted;
        }

        if matches!(g.state, ControlState::Ready) {
            if g.owner_conn_id != conn_id {
                tracing::warn!(
                    name = %self.config.name,
                    owner = g.owner_conn_id,
                    requester = conn_id,
                    "cancel refused: the selection is held by another connection"
                );
                return CancelResult::Denied(ControlAddCause::LockedByOtherClient);
            }
            drop(g);
            let _ = self.try_unselect(conn_id, SelectStateChangedReason::Canceled, false);
            return CancelResult::Accepted;
        }

        // Canceling an unselected object is accepted and does nothing.
        CancelResult::Accepted
    }

    // ─── Connection loss ─────────────────────────────────────────────────

    /// Deselects the object when the connection holding its selection is lost.
    ///
    /// Nothing happens unless `conn_id` holds the selection and the object is
    /// selected.
    pub fn on_connection_closed(&self, conn_id: u64) {
        let g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if g.owner_conn_id != conn_id || g.state != ControlState::Ready {
            return;
        }
        drop(g);
        let _ = self.try_unselect(conn_id, SelectStateChangedReason::Disconnected, true);
    }

    // ─── Select state notification ───────────────────────────────────────

    fn notify_select_state_changed(
        &self,
        conn_id: u64,
        is_selected: bool,
        reason: SelectStateChangedReason,
        t: [u8; 8],
        origin: OriginValue,
        ctl_num: u8,
    ) {
        let handler = self
            .select_state_handler
            .lock()
            .ok()
            .and_then(|g| g.clone());
        if let Some(h) = handler {
            let action = ControlAction::new(
                ctl_num,
                origin,
                t,
                false,
                false,
                false,
                is_selected,
                0,
                conn_id,
            );
            h.on_select_state_changed(&action, is_selected, reason);
        }
    }

    // ─── Object reference ────────────────────────────────────────────────

    /// Returns the object reference in the form `<LD>/<LN>$CO$<DO>`.
    pub fn object_ref(&self) -> String {
        format!(
            "{}/{}$CO${}",
            self.config.domain, self.config.ln_name, self.config.name
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Supporting types
// ─────────────────────────────────────────────────────────────────────────────

/// Result of `begin_operate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperateBeginResult {
    /// The command may proceed; the object is now awaiting the dynamic check.
    Accepted,
    /// The command is refused, with the cause to report.
    Denied(ControlAddCause),
}

/// Result of `try_cancel`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelResult {
    /// The cancel was accepted.
    Accepted,
    /// The cancel was refused, with the cause to report.
    Denied(ControlAddCause),
}

// ─────────────────────────────────────────────────────────────────────────────
// Parameter comparison for enhanced security
// ─────────────────────────────────────────────────────────────────────────────

/// Returns whether an Operate carries the same parameters as its SBOw, which
/// enhanced security requires per IEC 61850-7-2.
///
/// The control value is compared by its bit pattern, so a NaN float compares equal
/// to itself.
fn params_consistent(oper: &OperParams, sbow: &OperParams) -> bool {
    use super::model::mms_value_binary_equal;

    mms_value_binary_equal(&oper.ctl_val, &sbow.ctl_val)
        && oper.origin == sbow.origin
        && oper.ctl_num == sbow.ctl_num
        && oper.interlock_check == sbow.interlock_check
        && oper.synchro_check == sbow.synchro_check
        && oper.test == sbow.test
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use iec61850_model::MmsValue;

    fn make_config(model: ControlModel) -> ControlObjectConfig {
        ControlObjectConfig {
            name: "SPCSO1".into(),
            ln_name: "GGIO1".into(),
            domain: "IED1LD0".into(),
            ctl_model: model,
            sbo_timeout_ms: 5000,
            sbo_class: SboClass::OperateOnce,
        }
    }

    fn make_oper_params(ctl_val: MmsValue) -> OperParams {
        OperParams {
            ctl_val,
            oper_tm_ms: 0,
            origin: OriginValue {
                or_cat: 3,
                or_ident: vec![0x01],
            },
            ctl_num: 7,
            t: [0u8; 8],
            test: false,
            synchro_check: false,
            interlock_check: true,
        }
    }

    // ── An out-of-range ctlModel is refused ──────────────────────────────

    #[test]
    fn ctl_model_out_of_range_returns_err() {
        assert!(ControlObjectConfig::validate_ctl_model(5).is_err());
        assert!(ControlObjectConfig::validate_ctl_model(-1).is_err());
        assert!(ControlObjectConfig::validate_ctl_model(100).is_err());
    }

    #[test]
    fn ctl_model_valid_range_ok() {
        for v in 0i32..=4 {
            assert!(ControlObjectConfig::validate_ctl_model(v).is_ok());
        }
    }

    // ── A status-only object refuses Operate ─────────────────────────────

    #[test]
    fn status_only_denies_operate() {
        let obj = ControlObject::new(make_config(ControlModel::StatusOnly));
        let params = make_oper_params(MmsValue::Boolean(true));
        let result = obj.begin_operate(1, &params).unwrap();
        assert_eq!(
            result,
            Some(OperateBeginResult::Denied(ControlAddCause::NotSupported))
        );
    }

    // ── Direct control, normal security ──────────────────────────────────

    #[test]
    fn direct_normal_operate_transitions() {
        let obj = ControlObject::new(make_config(ControlModel::DirectNormal));
        assert_eq!(obj.state(), ControlState::Unselected);

        let params = make_oper_params(MmsValue::Boolean(true));
        let result = obj.begin_operate(1, &params).unwrap();
        assert_eq!(result, Some(OperateBeginResult::Accepted));
        assert_eq!(obj.state(), ControlState::WaitForExecution);

        obj.set_state_operate();
        assert_eq!(obj.state(), ControlState::Operate);

        obj.finish_operate();
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    // ── SBO-Normal select / operate / finish ───────────────────────────

    #[test]
    fn sbo_normal_select_operate_flow() {
        let obj = ControlObject::new(make_config(ControlModel::SboNormal));

        // select
        assert!(obj.try_select(1).unwrap());
        assert_eq!(obj.state(), ControlState::Ready);

        // Operate from the same connection.
        let params = make_oper_params(MmsValue::Boolean(true));
        let r = obj.begin_operate(1, &params).unwrap();
        assert_eq!(r, Some(OperateBeginResult::Accepted));
        assert_eq!(obj.state(), ControlState::WaitForExecution);

        obj.set_state_operate();
        obj.finish_operate();
        // a once-only selection returns to unselected
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    // ── Select-before-operate refuses another connection ─────────────────

    #[test]
    fn sbo_normal_wrong_conn_denied() {
        let obj = ControlObject::new(make_config(ControlModel::SboNormal));
        assert!(obj.try_select(1).unwrap());

        let params = make_oper_params(MmsValue::Boolean(true));
        let r = obj.begin_operate(2, &params).unwrap();
        assert_eq!(
            r,
            Some(OperateBeginResult::Denied(
                ControlAddCause::LockedByOtherClient
            ))
        );
    }

    // ── Enhanced security accepts matching parameters ────────────────────

    #[test]
    fn sbo_enhanced_consistent_params_accepted() {
        let obj = ControlObject::new(make_config(ControlModel::SboEnhanced));
        let params = make_oper_params(MmsValue::Boolean(true));

        assert!(obj.try_sbow_select(1, &params).unwrap());
        assert_eq!(obj.state(), ControlState::Ready);

        let r = obj.begin_operate(1, &params).unwrap();
        assert_eq!(r, Some(OperateBeginResult::Accepted));
    }

    // ── Enhanced security refuses differing parameters and deselects ─────

    #[test]
    fn sbo_enhanced_inconsistent_params_denied() {
        let obj = ControlObject::new(make_config(ControlModel::SboEnhanced));
        let sbow_params = make_oper_params(MmsValue::Boolean(true));
        let oper_params = make_oper_params(MmsValue::Boolean(false)); // a different ctlVal

        assert!(obj.try_sbow_select(1, &sbow_params).unwrap());
        let r = obj.begin_operate(1, &oper_params).unwrap();
        assert_eq!(
            r,
            Some(OperateBeginResult::Denied(
                ControlAddCause::InconsistentParameters
            ))
        );
        // Differing parameters also deselect the object.
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    // ── The select timeout deselects the object ──────────────────────────

    #[test]
    fn sbo_timeout_auto_unselect() {
        use std::thread;

        let mut config = make_config(ControlModel::SboNormal);
        config.sbo_timeout_ms = 50; // 50ms timeout
        let obj = ControlObject::new(config);

        assert!(obj.try_select(1).unwrap());
        assert_eq!(obj.state(), ControlState::Ready);

        thread::sleep(Duration::from_millis(100)); // longer than the timeout
        let timed_out = obj.check_sbo_timeout();
        assert!(timed_out, "the select timeout must fire");
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    // ── Cancel is refused while a command executes ───────────────────────

    #[test]
    fn cancel_during_execute_denied() {
        let obj = ControlObject::new(make_config(ControlModel::DirectNormal));
        let params = make_oper_params(MmsValue::Boolean(true));
        obj.begin_operate(1, &params).unwrap();
        obj.set_state_operate(); // move into the executing state

        let r = obj.try_cancel(1);
        assert_eq!(
            r,
            CancelResult::Denied(ControlAddCause::CommandAlreadyInExecution)
        );
    }

    // ── Cancel from the selecting connection succeeds ────────────────────

    #[test]
    fn cancel_selected_same_conn_ok() {
        let obj = ControlObject::new(make_config(ControlModel::SboNormal));
        assert!(obj.try_select(1).unwrap());

        let r = obj.try_cancel(1);
        assert_eq!(r, CancelResult::Accepted);
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    // ── Cancel from another connection is refused ────────────────────────

    #[test]
    fn cancel_selected_wrong_conn_denied() {
        let obj = ControlObject::new(make_config(ControlModel::SboNormal));
        assert!(obj.try_select(1).unwrap());

        let r = obj.try_cancel(2);
        assert_eq!(
            r,
            CancelResult::Denied(ControlAddCause::LockedByOtherClient)
        );
        assert_eq!(obj.state(), ControlState::Ready);
    }

    // ── Losing the connection deselects the object ───────────────────────

    #[test]
    fn connection_closed_auto_unselect() {
        let obj = ControlObject::new(make_config(ControlModel::SboNormal));
        assert!(obj.try_select(5).unwrap());

        obj.on_connection_closed(5);
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    // ── Losing another connection changes nothing ────────────────────────

    #[test]
    fn connection_closed_wrong_conn_no_effect() {
        let obj = ControlObject::new(make_config(ControlModel::SboNormal));
        assert!(obj.try_select(5).unwrap());

        obj.on_connection_closed(6); // a different connection
        assert_eq!(obj.state(), ControlState::Ready);
    }

    // ── A malformed origin is refused ────────────────────────────────────

    #[test]
    fn invalid_origin_denied() {
        let obj = ControlObject::new(make_config(ControlModel::DirectNormal));
        let mut params = make_oper_params(MmsValue::Boolean(true));
        params.origin.or_cat = 99; // outside 0 to 8

        let r = obj.begin_operate(1, &params).unwrap();
        assert_eq!(
            r,
            Some(OperateBeginResult::Denied(
                ControlAddCause::InconsistentParameters
            ))
        );
    }

    // ── The object reference has the expected form ───────────────────────

    #[test]
    fn object_ref_format() {
        let obj = ControlObject::new(make_config(ControlModel::DirectNormal));
        assert_eq!(obj.object_ref(), "IED1LD0/GGIO1$CO$SPCSO1");
    }

    // ── Very long names do not panic ─────────────

    #[test]
    fn long_names_no_panic() {
        // A logical node name and data object name that
        // together exceed a fixed-size item identifier buffer must not overflow.
        // The reference is formatted into an allocated String, so any length is safe.
        let long_name = "A".repeat(64);
        let long_ln = "B".repeat(32);
        let config = ControlObjectConfig {
            name: long_name.clone(),
            ln_name: long_ln.clone(),
            domain: "IED1LD0".into(),
            ctl_model: ControlModel::DirectNormal,
            sbo_timeout_ms: 30000,
            sbo_class: SboClass::OperateOnce,
        };
        let obj = ControlObject::new(config);
        // Formatting cannot panic, however long the names are.
        let r = obj.object_ref();
        assert!(r.contains(&long_name));
        assert!(r.contains(&long_ln));
    }

    // ── A many-operate selection stays selected after Operate ────────────

    #[test]
    fn sbo_operate_many_stays_ready() {
        let mut config = make_config(ControlModel::SboNormal);
        config.sbo_class = SboClass::OperateMany;
        let obj = ControlObject::new(config);

        assert!(obj.try_select(1).unwrap());
        let params = make_oper_params(MmsValue::Boolean(true));
        obj.begin_operate(1, &params).unwrap();
        obj.set_state_operate();
        obj.finish_operate();

        // A many-operate selection stays ready.
        assert_eq!(obj.state(), ControlState::Ready);
    }
}
