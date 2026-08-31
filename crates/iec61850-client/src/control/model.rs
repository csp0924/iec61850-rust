//! Types describing a control command and its outcome.
//!
//! These mirror the server-side control types. The client crate does not
//! depend on the server crate, so it owns its own copy, as `mms_compat` does.

pub use iec61850_model::ControlModel;

use crate::prelude::{String, Vec};

/// The origin data attribute: `orCat`, the operation category, and
/// `orIdent`, the operator identity.
///
/// Defined in IEC 61850-7-2 §17.2.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OriginValue {
    /// Operation category, 0 to 8, per the OrCat enumeration.
    pub or_cat: i32,
    /// Operator identity, at most 64 bytes.
    pub or_ident: Vec<u8>,
}

impl OriginValue {
    /// Returns the bay-control category (3) with an empty identity.
    pub fn bay_control() -> Self {
        Self {
            or_cat: 3,
            or_ident: Vec::new(),
        }
    }

    /// Reports whether `or_cat` is in 0 to 8 and `or_ident` fits in 64 bytes.
    pub fn is_valid(&self) -> bool {
        (0..=8).contains(&self.or_cat) && self.or_ident.len() <= 64
    }
}

/// Additional cause reported with a failed control command.
///
/// Values as defined in IEC 61850-7-2 §20.1.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum ControlAddCause {
    /// No cause was reported, or the reported value is not defined.
    #[default]
    Unknown = 0,
    /// The requested control operation is not supported by the object.
    NotSupported = 1,
    /// The switching hierarchy denies control from this originator.
    BlockedBySwitchingHierarchy = 2,
    /// The object could not be selected.
    SelectFailed = 3,
    /// The object is in a position from which the command is not valid.
    InvalidPosition = 4,
    /// The object already occupies the commanded position.
    PositionReached = 5,
    /// A parameter change is in progress on the object.
    ParameterChangeInExecution = 6,
    /// The step limit of the object has been reached.
    StepLimit = 7,
    /// The mode of the logical node blocks the command.
    BlockedByMode = 8,
    /// The process condition blocks the command.
    BlockedByProcess = 9,
    /// An interlocking condition blocks the command.
    BlockedByInterlocking = 10,
    /// The synchrocheck condition blocks the command.
    BlockedBySynchroCheck = 11,
    /// Another command on the object is still in execution.
    CommandAlreadyInExecution = 12,
    /// The health of the logical node blocks the command.
    BlockedByHealth = 13,
    /// Another object of the same one-of-n group is under control.
    OneOfNControl = 14,
    /// The command was aborted by a Cancel request.
    AbortionByCancel = 15,
    /// The command exceeded its time limit.
    TimeLimitOver = 16,
    /// The command was aborted by a trip.
    AbortionByTrip = 17,
    /// The object was not selected before the operate.
    ObjectNotSelected = 18,
    /// The object is already selected by another association.
    ObjectAlreadySelected = 19,
    /// The originator has no access authority for the object.
    NoAccessAuthority = 20,
    /// The operation ended past the commanded position.
    EndedWithOvershoot = 21,
    /// The operation was aborted because the deviation grew too large.
    AbortionDueToDeviation = 22,
    /// The operation was aborted when communication was lost.
    AbortionByCommunicationLoss = 23,
    /// The operation was aborted by a further command.
    AbortionByCommand = 24,
    /// The command failed for a reason that carries no additional cause.
    None = 25,
    /// The operate parameters do not match those of the selection.
    InconsistentParameters = 26,
    /// The object is locked by another client.
    LockedByOtherClient = 27,
}

impl ControlAddCause {
    /// Maps a wire value onto a cause; an unknown value becomes `Unknown`.
    pub fn from_i32(v: i32) -> Self {
        match v {
            1 => Self::NotSupported,
            2 => Self::BlockedBySwitchingHierarchy,
            3 => Self::SelectFailed,
            4 => Self::InvalidPosition,
            5 => Self::PositionReached,
            6 => Self::ParameterChangeInExecution,
            7 => Self::StepLimit,
            8 => Self::BlockedByMode,
            9 => Self::BlockedByProcess,
            10 => Self::BlockedByInterlocking,
            11 => Self::BlockedBySynchroCheck,
            12 => Self::CommandAlreadyInExecution,
            13 => Self::BlockedByHealth,
            14 => Self::OneOfNControl,
            15 => Self::AbortionByCancel,
            16 => Self::TimeLimitOver,
            17 => Self::AbortionByTrip,
            18 => Self::ObjectNotSelected,
            19 => Self::ObjectAlreadySelected,
            20 => Self::NoAccessAuthority,
            21 => Self::EndedWithOvershoot,
            22 => Self::AbortionDueToDeviation,
            23 => Self::AbortionByCommunicationLoss,
            24 => Self::AbortionByCommand,
            25 => Self::None,
            26 => Self::InconsistentParameters,
            27 => Self::LockedByOtherClient,
            _ => Self::Unknown,
        }
    }
}

/// The error field of a LastApplError structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum ControlLastApplError {
    /// The command completed without error.
    #[default]
    NoError = 0,
    /// The reported value is not one this implementation knows.
    Unknown = 1,
    /// The command timed out.
    TimeoutTest = 2,
    /// The operation itself failed.
    OperationFailed = 3,
}

impl ControlLastApplError {
    /// Maps a wire value onto an error; an unknown value becomes `Unknown`.
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::NoError,
            2 => Self::TimeoutTest,
            3 => Self::OperationFailed,
            _ => Self::Unknown,
        }
    }
}

/// Number of operations a selection permits, per the `sboClass` data attribute
/// of IEC 61850-7-2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SboClass {
    /// The selection ends after one operate.
    #[default]
    OperateOnce,
    /// The selection permits repeated operates.
    OperateMany,
}

/// Application-level outcome of a control command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlOutcome {
    /// The command succeeded: the confirmed response in a normal model, or a
    /// positive command termination in an enhanced one.
    Success,
    /// The command failed, with the additional cause the server reported. In an
    /// enhanced model this comes from a negative command termination; in a
    /// normal model the confirmed error carries none and `Unknown` is used.
    Failure(ControlAddCause),
}

/// A parsed command termination.
///
/// A negative termination carries a LastApplError alongside the Oper structure.
#[derive(Debug, Clone, PartialEq)]
pub struct CommandTerminationParsed {
    /// `<LD>/<LN>$CO$<DO>$Oper`, taken from the report's variable list.
    pub object_ref_oper: String,
    /// `None` for a positive termination, the error for a negative one.
    pub last_appl_error: Option<LastApplError>,
}

/// The five-element LastApplError structure of a negative command termination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastApplError {
    /// `<LD>/<LN>$CO$<DO>$Oper`.
    pub ctl_obj: String,
    /// Error the server reported for the command.
    pub error: ControlLastApplError,
    /// Originator the failed command carried.
    pub origin: OriginValue,
    /// ctlNum the failed command carried.
    pub ctl_num: u8,
    /// Additional cause of the failure.
    pub add_cause: ControlAddCause,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_cause_round_trip_wire_values() {
        assert_eq!(ControlAddCause::from_i32(0), ControlAddCause::Unknown);
        assert_eq!(
            ControlAddCause::from_i32(9),
            ControlAddCause::BlockedByProcess
        );
        assert_eq!(
            ControlAddCause::from_i32(18),
            ControlAddCause::ObjectNotSelected
        );
        assert_eq!(
            ControlAddCause::from_i32(27),
            ControlAddCause::LockedByOtherClient
        );
        assert_eq!(ControlAddCause::from_i32(99), ControlAddCause::Unknown);
        assert_eq!(ControlAddCause::default() as i32, 0);
    }

    #[test]
    fn origin_validity() {
        assert!(OriginValue::bay_control().is_valid());
        let too_long = OriginValue {
            or_cat: 3,
            or_ident: vec![0u8; 65],
        };
        assert!(!too_long.is_valid());
        let bad = OriginValue {
            or_cat: 9,
            or_ident: vec![],
        };
        assert!(!bad.is_valid());
    }

    #[test]
    fn last_appl_error_from_i32() {
        assert_eq!(
            ControlLastApplError::from_i32(0),
            ControlLastApplError::NoError
        );
        assert_eq!(
            ControlLastApplError::from_i32(3),
            ControlLastApplError::OperationFailed
        );
        assert_eq!(
            ControlLastApplError::from_i32(99),
            ControlLastApplError::Unknown
        );
    }
}
