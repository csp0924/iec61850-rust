//! The control object state machine.
//!
//! Four states cover the control models of IEC 61850-7-2:
//!
//! ```text
//! Unselected       - idle for select-before-operate; also the idle state of
//!                    direct control
//! Ready            - selected for select-before-operate, waiting for Operate
//! WaitForExecution - awaiting the wait-for-execution handler
//! Operate          - awaiting the operate handler
//! ```

// ─────────────────────────────────────────────────────────────────────────────
// ControlState
// ─────────────────────────────────────────────────────────────────────────────

/// State of one control object.
///
/// The discriminants are assigned explicitly; 2 and 3 are unused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ControlState {
    /// Idle for select-before-operate; also the initial state for direct control.
    #[default]
    Unselected = 0,

    /// Selected and awaiting Operate, for select-before-operate.
    Ready = 1,

    /// Awaiting the wait-for-execution handler.
    WaitForExecution = 4,

    /// Awaiting the operate handler.
    Operate = 5,
}

impl ControlState {
    /// Returns whether the object is selected; select-before-operate accepts an
    /// Operate only in `Ready`.
    pub fn is_selected(&self) -> bool {
        *self == ControlState::Ready
    }

    /// Returns whether a command is executing; Cancel is refused while it is.
    pub fn is_executing(&self) -> bool {
        matches!(self, ControlState::WaitForExecution | ControlState::Operate)
    }

    /// Returns whether the object is idle and can accept a new select or a direct
    /// Operate.
    pub fn is_idle(&self) -> bool {
        *self == ControlState::Unselected
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Transition results
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a state machine action, returned by `ControlObject` methods.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransitionResult {
    /// The action was accepted and the state has moved.
    Accepted,
    /// The action was refused and the state is unchanged.
    Rejected(RejectionReason),
}

/// Why a control action was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectionReason {
    /// `ctlModel` is status-only, so no control request is accepted.
    StatusOnly,
    /// The object is selected by a different connection.
    LockedByOtherClient,
    /// A command is executing, so Cancel is refused.
    CommandAlreadyInExecution,
    /// An Operate arrived for a select-before-operate object that is not selected.
    ObjectNotSelected,
    /// The Operate parameters do not match those of the preceding select.
    InconsistentParameters,
    /// The origin field is malformed.
    InvalidOrigin,
    /// The current state does not allow this action.
    InvalidState,
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_is_unselected() {
        assert_eq!(ControlState::default(), ControlState::Unselected);
    }

    #[test]
    fn ready_is_selected_only() {
        assert!(ControlState::Ready.is_selected());
        assert!(!ControlState::Unselected.is_selected());
        assert!(!ControlState::WaitForExecution.is_selected());
        assert!(!ControlState::Operate.is_selected());
    }

    #[test]
    fn executing_states() {
        assert!(ControlState::WaitForExecution.is_executing());
        assert!(ControlState::Operate.is_executing());
        assert!(!ControlState::Ready.is_executing());
        assert!(!ControlState::Unselected.is_executing());
    }

    #[test]
    fn idle_states() {
        assert!(ControlState::Unselected.is_idle());
        assert!(!ControlState::Ready.is_idle());
        assert!(!ControlState::Operate.is_idle());
    }

    #[test]
    fn transition_result_display() {
        let r = TransitionResult::Rejected(RejectionReason::StatusOnly);
        assert!(matches!(
            r,
            TransitionResult::Rejected(RejectionReason::StatusOnly)
        ));
        assert_ne!(r, TransitionResult::Accepted);
    }
}
