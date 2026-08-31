//! Callback traits an application implements to take part in a control sequence.
//!
//! The check handler decides whether a control request is admissible, the
//! wait-for-execution handler performs any dynamic check, and the control handler
//! carries the command out. The two handlers that may take time return a boxed
//! future, so waiting is expressed by `await` and the server never polls. An
//! application supplies its handlers as `Arc<dyn Trait + Send + Sync>`.

use super::model::{ControlAction, ControlAddCause};
use iec61850_model::MmsValue;
use std::future::Future;
use std::pin::Pin;

// ─────────────────────────────────────────────────────────────────────────────
// CheckHandler: the static check
// ─────────────────────────────────────────────────────────────────────────────

/// Static admissibility check for a control request.
///
/// Returning `Ok(())` accepts the request; returning `Err(cause)` refuses it and
/// the `ControlAddCause` is reported to the client.
///
/// On a select-before-operate select there is no control value, because
/// IEC 61850-7-2 carries none on Select, so `ctl_val` is `None`. Making that an
/// `Option` rather than a null value forces an implementation to handle the case
/// explicitly instead of dereferencing something that is not there.
pub trait CheckHandler: Send + Sync {
    /// Runs the static check.
    ///
    /// `action` is the metadata of this control request, `ctl_val` the control
    /// value or `None` on a select-before-operate select, `test` whether this is a
    /// test command, and `interlock_check` whether an interlock check was
    /// requested.
    ///
    /// # Errors
    ///
    /// Returns the `ControlAddCause` to report when the request is refused.
    fn check(
        &self,
        action: &ControlAction,
        ctl_val: Option<&MmsValue>,
        test: bool,
        interlock_check: bool,
    ) -> Result<(), ControlAddCause>;
}

// ─────────────────────────────────────────────────────────────────────────────
// WaitForExecutionHandler: the dynamic check
// ─────────────────────────────────────────────────────────────────────────────

/// Future returned by a dynamic check.
pub type WaitForExecFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), ControlAddCause>> + Send + 'a>>;

/// Dynamic check performed after the static check and before the command runs.
///
/// The check may take arbitrarily long: it returns a future and the server awaits
/// it, so no polling loop is involved.
///
/// Returning `Ok(())` lets the command proceed; returning `Err(cause)` refuses it.
pub trait WaitForExecutionHandler: Send + Sync {
    /// Runs the dynamic check, which may await for as long as it needs.
    fn wait_for_execution<'a>(
        &'a self,
        action: &'a ControlAction,
        ctl_val: &'a MmsValue,
        test: bool,
        synchro_check: bool,
    ) -> WaitForExecFuture<'a>;
}

// ─────────────────────────────────────────────────────────────────────────────
// ControlHandler: carrying out the command
// ─────────────────────────────────────────────────────────────────────────────

/// Future returned by a control command.
pub type OperateFuture<'a> = Pin<Box<dyn Future<Output = Result<(), ControlAddCause>> + Send + 'a>>;

/// Carries out a control command.
///
/// Returning `Ok(())` reports success; returning `Err(cause)` reports failure with
/// the `ControlAddCause` to send to the client.
pub trait ControlHandler: Send + Sync {
    /// Runs the command, awaiting whatever the process needs, such as the physical
    /// operation of a switch.
    fn operate<'a>(
        &'a self,
        action: &'a ControlAction,
        ctl_val: &'a MmsValue,
        test: bool,
    ) -> OperateFuture<'a>;
}

// ─────────────────────────────────────────────────────────────────────────────
// SelectStateChangedHandler
// ─────────────────────────────────────────────────────────────────────────────

/// Notified when a select-before-operate object is selected or deselected.
///
/// Implements the select state notification of IEC 61850-7-2.
pub trait SelectStateChangedHandler: Send + Sync {
    /// Reports that the selection state changed.
    fn on_select_state_changed(
        &self,
        action: &ControlAction,
        is_selected: bool,
        reason: SelectStateChangedReason,
    );
}

/// Why the selection state changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectStateChangedReason {
    /// The object was selected.
    Selected,
    /// The client canceled the selection.
    Canceled,
    /// The select timeout elapsed.
    Timeout,
    /// The client connection was lost, which deselects the object.
    Disconnected,
    /// A once-only selection was consumed by a completed Operate.
    OperateDone,
}

// ─────────────────────────────────────────────────────────────────────────────
// Test implementations
// ─────────────────────────────────────────────────────────────────────────────

/// Check handler that accepts every request; for tests.
#[derive(Debug)]
pub struct AlwaysAcceptCheckHandler;

impl CheckHandler for AlwaysAcceptCheckHandler {
    fn check(
        &self,
        _action: &ControlAction,
        _ctl_val: Option<&MmsValue>,
        _test: bool,
        _interlock_check: bool,
    ) -> Result<(), ControlAddCause> {
        Ok(())
    }
}

/// Wait-for-execution handler that accepts every request; for tests.
#[derive(Debug)]
pub struct AlwaysAcceptWaitHandler;

impl WaitForExecutionHandler for AlwaysAcceptWaitHandler {
    fn wait_for_execution<'a>(
        &'a self,
        _action: &'a ControlAction,
        _ctl_val: &'a MmsValue,
        _test: bool,
        _synchro_check: bool,
    ) -> WaitForExecFuture<'a> {
        Box::pin(async move { Ok(()) })
    }
}

/// Control handler that reports success for every command; for tests.
#[derive(Debug)]
pub struct AlwaysSuccessOperateHandler;

impl ControlHandler for AlwaysSuccessOperateHandler {
    fn operate<'a>(
        &'a self,
        _action: &'a ControlAction,
        _ctl_val: &'a MmsValue,
        _test: bool,
    ) -> OperateFuture<'a> {
        Box::pin(async move { Ok(()) })
    }
}

/// Control handler that fails every command with a fixed cause; for tests.
#[derive(Debug)]
pub struct AlwaysFailOperateHandler {
    /// Cause reported for every command this handler fails.
    pub cause: ControlAddCause,
}

impl ControlHandler for AlwaysFailOperateHandler {
    fn operate<'a>(
        &'a self,
        _action: &'a ControlAction,
        _ctl_val: &'a MmsValue,
        _test: bool,
    ) -> OperateFuture<'a> {
        let cause = self.cause;
        Box::pin(async move { Err(cause) })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::model::OriginValue;

    fn make_action() -> ControlAction {
        ControlAction::new(
            1,
            OriginValue::default(),
            [0u8; 8],
            false,
            false,
            false,
            false,
            0,
            0,
        )
    }

    #[test]
    fn always_accept_check_handler_ok() {
        let h = AlwaysAcceptCheckHandler;
        let action = make_action();
        assert!(h.check(&action, None, false, false).is_ok());
        assert!(h
            .check(&action, Some(&MmsValue::Boolean(true)), false, false)
            .is_ok());
    }

    #[tokio::test]
    async fn always_accept_wait_handler_ok() {
        let h = AlwaysAcceptWaitHandler;
        let action = make_action();
        let result = h
            .wait_for_execution(&action, &MmsValue::Boolean(true), false, false)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn always_success_operate_handler_ok() {
        let h = AlwaysSuccessOperateHandler;
        let action = make_action();
        let result = h.operate(&action, &MmsValue::Boolean(true), false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn always_fail_operate_handler_err() {
        let h = AlwaysFailOperateHandler {
            cause: ControlAddCause::BlockedByProcess,
        };
        let action = make_action();
        let result = h.operate(&action, &MmsValue::Boolean(true), false).await;
        assert_eq!(result, Err(ControlAddCause::BlockedByProcess));
    }
}
