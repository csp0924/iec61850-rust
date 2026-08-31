//! Types of the IEC 61850 control model.
//!
//! Covers the control add cause and last application error codes, the `origin`
//! data attribute, the select class, the parameter structures of Oper, SBOw, and
//! Cancel, and the `ControlAction` record handed to an application callback.
//!
//! Enum discriminants are the integer values that go on the wire, so a value here
//! may not be renumbered.

use iec61850_model::MmsValue;

// ─────────────────────────────────────────────────────────────────────────────
// ControlAddCause
// ─────────────────────────────────────────────────────────────────────────────

/// Additional cause reported for a control request.
///
/// A callback sets it, and it is carried in the LastApplError data attribute. The
/// discriminants are the wire integers of IEC 61850-7-2 and must not be
/// renumbered.
///
/// `Unknown = 0` is the default a control action starts with. `None = 25` means
/// "no additional cause", which a callback sets explicitly once an operation has
/// succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum ControlAddCause {
    /// Unknown cause; the initial value of a control action.
    #[default]
    Unknown = 0,
    /// The requested function is not supported.
    NotSupported = 1,
    /// Blocked by the switching hierarchy.
    BlockedBySwitchingHierarchy = 2,
    /// The select failed.
    SelectFailed = 3,
    /// The position is invalid.
    InvalidPosition = 4,
    /// The position has already been reached.
    PositionReached = 5,
    /// A parameter changed while the command was executing.
    ParameterChangeInExecution = 6,
    /// The step limit was reached.
    StepLimit = 7,
    /// Blocked by the current mode.
    BlockedByMode = 8,
    /// Blocked by the process.
    BlockedByProcess = 9,
    /// The interlock check failed.
    BlockedByInterlocking = 10,
    /// The synchro check failed.
    BlockedBySynchroCheck = 11,
    /// Another command is already executing.
    CommandAlreadyInExecution = 12,
    /// Blocked by the health status.
    BlockedByHealth = 13,
    /// Refused by one-of-N control.
    OneOfNControl = 14,
    /// Aborted by a Cancel.
    AbortionByCancel = 15,
    /// The time limit was exceeded.
    TimeLimitOver = 16,
    /// Aborted by a trip.
    AbortionByTrip = 17,
    /// The object is not selected.
    ObjectNotSelected = 18,
    /// The object is already selected.
    ObjectAlreadySelected = 19,
    /// The client has no access authority.
    NoAccessAuthority = 20,
    /// The operation ended with an overshoot.
    EndedWithOvershoot = 21,
    /// Aborted because of a deviation.
    AbortionDueToDeviation = 22,
    /// Aborted because communication was lost.
    AbortionByCommunicationLoss = 23,
    /// Aborted by another command.
    AbortionByCommand = 24,
    /// No additional cause; the operation succeeded.
    None = 25,
    /// The parameters are inconsistent, for example between a select and its
    /// Operate.
    InconsistentParameters = 26,
    /// The object is locked by another client.
    LockedByOtherClient = 27,
}

impl ControlAddCause {
    /// Parses the wire integer; an unrecognized value becomes `Unknown`.
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Unknown,
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

// ─────────────────────────────────────────────────────────────────────────────
// ControlLastApplError
// ─────────────────────────────────────────────────────────────────────────────

/// The `error` field of the LastApplError data attribute, per IEC 61850-7-2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum ControlLastApplError {
    /// No error.
    #[default]
    NoError = 0,
    /// Unknown error.
    Unknown = 1,
    /// The command timed out.
    TimeoutTest = 2,
    /// The operation failed.
    OperationFailed = 3,
}

// ─────────────────────────────────────────────────────────────────────────────
// SboClass
// ─────────────────────────────────────────────────────────────────────────────

/// How many Operate requests one selection admits.
///
/// Mirrors the `sboClass` data attribute of IEC 61850-7-2, where 0 is
/// operate-once and 1 is operate-many.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SboClass {
    /// The selection is consumed by one Operate, after which the object is
    /// deselected. This is the default, and also what an absent or non-zero
    /// `sboClass` attribute means.
    #[default]
    OperateOnce,
    /// The selection admits repeated Operate requests until it is canceled or
    /// times out.
    OperateMany,
}

// ─────────────────────────────────────────────────────────────────────────────
// OriginValue
// ─────────────────────────────────────────────────────────────────────────────

/// The `origin` data attribute: `orCat`, the operation category, and `orIdent`,
/// the operator identity of at most 64 bytes.
///
/// It is the first structure member of Oper and SBOw in IEC 61850-7-2. A valid
/// value has `orCat` in 0..=8 and `orIdent` no longer than 64 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OriginValue {
    /// Operation category, 0 to 8.
    pub or_cat: i32,
    /// Operator identity, at most 64 bytes.
    pub or_ident: Vec<u8>,
}

impl OriginValue {
    /// Returns whether the value is valid: `orCat` in 0..=8 and `orIdent` no
    /// longer than 64 bytes.
    pub fn is_valid(&self) -> bool {
        self.or_cat >= 0 && self.or_cat <= 8 && self.or_ident.len() <= 64
    }

    /// Parses an `origin` from a two-element MMS structure.
    ///
    /// Returns `None` when the value is not a structure, has the wrong number of
    /// elements, or its members have the wrong types.
    pub fn from_mms_value(v: &MmsValue) -> Option<Self> {
        if let MmsValue::Structure(fields) = v {
            if fields.len() == 2 {
                if let (MmsValue::Integer(cat), MmsValue::OctetString(ident)) =
                    (&fields[0], &fields[1])
                {
                    return Some(Self {
                        or_cat: *cat as i32,
                        or_ident: ident.clone(),
                    });
                }
            }
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ControlAction
// ─────────────────────────────────────────────────────────────────────────────

/// Description of one control action, handed to the application callbacks.
///
/// The fields are private with accessor methods. A callback records its outcome
/// through `set_add_cause` and `set_error`; both are read when LastApplError is
/// assembled.
#[derive(Debug, Clone)]
pub struct ControlAction {
    /// Command sequence number, the `ctlNum` attribute.
    ctl_num: u8,
    /// Operation origin, the `origin` attribute.
    origin: OriginValue,
    /// Timestamp of the Oper or SBOw, the `T` attribute in UTC_TIME form.
    t: [u8; 8],
    /// The `Test` flag.
    test: bool,
    /// The synchro check bit of `Check`.
    synchro_check: bool,
    /// The interlock check bit of `Check`.
    interlock_check: bool,
    /// Whether this is a select rather than an Operate.
    is_select: bool,
    /// Activation time in milliseconds for a time-activated command; 0 when the
    /// command is not time-activated.
    ctl_time_ms: u64,
    /// Additional cause, set by a callback.
    add_cause: ControlAddCause,
    /// Error code, set by a callback.
    error_code: ControlLastApplError,
    /// Connection that issued this control request, or 0 when there is none. Used
    /// when assembling LastApplError and CommandTermination.
    #[allow(dead_code)]
    pub(crate) conn_id: u64,
}

impl ControlAction {
    /// Creates a control action, which every request starts from afresh.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        ctl_num: u8,
        origin: OriginValue,
        t: [u8; 8],
        test: bool,
        synchro_check: bool,
        interlock_check: bool,
        is_select: bool,
        ctl_time_ms: u64,
        conn_id: u64,
    ) -> Self {
        Self {
            ctl_num,
            origin,
            t,
            test,
            synchro_check,
            interlock_check,
            is_select,
            ctl_time_ms,
            // Unknown is the initial add cause.
            add_cause: ControlAddCause::Unknown,
            error_code: ControlLastApplError::NoError,
            conn_id,
        }
    }

    /// Returns the command sequence number, `ctlNum`.
    pub fn ctl_num(&self) -> u8 {
        self.ctl_num
    }

    /// Returns the operation origin.
    pub fn origin(&self) -> &OriginValue {
        &self.origin
    }

    /// Returns the timestamp, the `T` attribute as eight UTC_TIME bytes.
    pub fn t(&self) -> [u8; 8] {
        self.t
    }

    /// Returns the `Test` flag.
    pub fn test(&self) -> bool {
        self.test
    }

    /// Returns the synchro check bit.
    pub fn synchro_check(&self) -> bool {
        self.synchro_check
    }

    /// Returns the interlock check bit.
    pub fn interlock_check(&self) -> bool {
        self.interlock_check
    }

    /// Returns whether this is a select rather than an Operate.
    pub fn is_select(&self) -> bool {
        self.is_select
    }

    /// Returns the activation time in milliseconds; 0 when the command is not
    /// time-activated.
    pub fn ctl_time_ms(&self) -> u64 {
        self.ctl_time_ms
    }

    /// Records the additional cause a callback wants reported.
    pub fn set_add_cause(&mut self, cause: ControlAddCause) {
        self.add_cause = cause;
    }

    /// Records the error code a callback wants reported.
    pub fn set_error(&mut self, error: ControlLastApplError) {
        self.error_code = error;
    }

    /// Returns the additional cause, for assembling LastApplError.
    #[allow(dead_code)]
    pub(crate) fn add_cause(&self) -> ControlAddCause {
        self.add_cause
    }

    /// Returns the error code, for assembling LastApplError.
    #[allow(dead_code)]
    pub(crate) fn error_code(&self) -> ControlLastApplError {
        self.error_code
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ControlModel, re-exported from iec61850-model
// ─────────────────────────────────────────────────────────────────────────────

pub use iec61850_model::ControlModel;

// ─────────────────────────────────────────────────────────────────────────────
// Parsing Oper, SBOw, and Cancel parameters
// ─────────────────────────────────────────────────────────────────────────────

/// Parameters of an Oper or SBOw request.
///
/// The wire structure has six elements, or seven when `operTm` is present.
#[derive(Debug, Clone)]
pub struct OperParams {
    /// Control value, element 0.
    pub ctl_val: MmsValue,
    /// Activation time in milliseconds; present only in the seven-element form,
    /// where it is element 1. Zero means the command is not time-activated.
    pub oper_tm_ms: u64,
    /// Origin, element 1 or 2.
    pub origin: OriginValue,
    /// Command sequence number, element 2 or 3.
    pub ctl_num: u8,
    /// Timestamp, element 3 or 4, as eight UTC_TIME bytes.
    pub t: [u8; 8],
    /// Test flag, element 4 or 5.
    pub test: bool,
    /// Synchro check bit of `Check`, element 5 or 6, a two-bit BIT STRING.
    pub synchro_check: bool,
    /// Interlock check bit of `Check`, element 5 or 6.
    pub interlock_check: bool,
}

impl OperParams {
    /// Parses an Oper or SBOw from its MMS structure, in either the six- or
    /// seven-element form.
    ///
    /// Returns `None` when the value is not a structure of six or seven elements,
    /// or when a member has the wrong type.
    pub fn from_mms_value(v: &MmsValue) -> Option<Self> {
        let fields = match v {
            MmsValue::Structure(f) => f,
            _ => return None,
        };

        let (has_oper_tm, base) = match fields.len() {
            6 => (false, 0usize),
            7 => (true, 1usize),
            _ => return None,
        };

        let ctl_val = fields[0].clone();

        let oper_tm_ms = if has_oper_tm {
            utc_time_to_ms(match &fields[1] {
                MmsValue::UtcTime(b) => b,
                _ => return None,
            })
        } else {
            0
        };

        let origin = OriginValue::from_mms_value(&fields[base + 1])?;

        let ctl_num = match &fields[base + 2] {
            MmsValue::Unsigned(n) => *n as u8,
            MmsValue::Integer(n) => *n as u8,
            _ => return None,
        };

        let t = match &fields[base + 3] {
            MmsValue::UtcTime(b) => *b,
            _ => [0u8; 8],
        };

        let test = match &fields[base + 4] {
            MmsValue::Boolean(b) => *b,
            _ => return None,
        };

        let (synchro_check, interlock_check) = match &fields[base + 5] {
            // Check is a two-bit BIT STRING: bit 0 is synchroCheck, bit 1 interlockCheck.
            MmsValue::BitString { data, .. } if !data.is_empty() => {
                let byte = data[0];
                (byte & 0x80 != 0, byte & 0x40 != 0)
            }
            _ => (false, false),
        };

        Some(Self {
            ctl_val,
            oper_tm_ms,
            origin,
            ctl_num,
            t,
            test,
            synchro_check,
            interlock_check,
        })
    }
}

/// Parameters of a Cancel request, a structure of five or six elements.
#[derive(Debug, Clone)]
pub struct CancelParams {
    /// Control value, element 0.
    pub ctl_val: Option<MmsValue>,
    /// Origin, element 1.
    pub origin: OriginValue,
    /// Command sequence number, element 2.
    pub ctl_num: u8,
    /// Timestamp, element 3, as eight UTC_TIME bytes.
    pub t: [u8; 8],
    /// Test flag, element 4.
    pub test: bool,
}

impl CancelParams {
    /// Parses a Cancel from its MMS structure.
    ///
    /// Returns `None` when the value is not a structure of five or six elements,
    /// or when a member has the wrong type.
    pub fn from_mms_value(v: &MmsValue) -> Option<Self> {
        let fields = match v {
            MmsValue::Structure(f) => f,
            _ => return None,
        };
        if fields.len() < 5 || fields.len() > 6 {
            return None;
        }

        let ctl_val = Some(fields[0].clone());
        let origin = OriginValue::from_mms_value(&fields[1])?;
        let ctl_num = match &fields[2] {
            MmsValue::Unsigned(n) => *n as u8,
            MmsValue::Integer(n) => *n as u8,
            _ => return None,
        };
        let t = match &fields[3] {
            MmsValue::UtcTime(b) => *b,
            _ => [0u8; 8],
        };
        let test = match &fields[4] {
            MmsValue::Boolean(b) => *b,
            _ => return None,
        };

        Some(Self {
            ctl_val,
            origin,
            ctl_num,
            t,
            test,
        })
    }
}

/// Converts a UTC_TIME value to milliseconds.
///
/// Bytes 0 to 3 are the seconds since the Unix epoch, big-endian; bytes 4 to 6 are
/// a 24-bit fraction of a second; byte 7 carries the quality flags.
pub fn utc_time_to_ms(b: &[u8; 8]) -> u64 {
    let secs = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
    // fractional = 24-bit / 2^24 * 1000 ms
    let frac24 = ((b[4] as u32) << 16 | (b[5] as u32) << 8 | b[6] as u32) as u64;
    secs * 1000 + frac24 * 1000 / (1 << 24)
}

/// Converts milliseconds to a UTC_TIME value.
pub fn ms_to_utc_time(ms: u64) -> [u8; 8] {
    let secs = (ms / 1000) as u32;
    let frac_ms = ms % 1000;
    let frac24 = (frac_ms * (1 << 24) / 1000) as u32;
    let sb = secs.to_be_bytes();
    [
        sb[0],
        sb[1],
        sb[2],
        sb[3],
        (frac24 >> 16) as u8,
        (frac24 >> 8) as u8,
        frac24 as u8,
        0,
    ]
}

/// Compares two `MmsValue`s, comparing floats by their bit patterns.
///
/// A float compared with `==` is not equal to itself when it is NaN, so the bits
/// are compared instead. Comparing the parameters of a select against those of its
/// Operate needs bit-for-bit equality.
pub fn mms_value_binary_equal(a: &MmsValue, b: &MmsValue) -> bool {
    match (a, b) {
        (MmsValue::Float32(x), MmsValue::Float32(y)) => x.to_bits() == y.to_bits(),
        (MmsValue::Float64(x), MmsValue::Float64(y)) => x.to_bits() == y.to_bits(),
        _ => a == b,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oper_params_parse_6_elements() {
        // A six-element Oper: ctlVal, origin, ctlNum, T, Test, Check.
        let origin_struct =
            MmsValue::Structure(vec![MmsValue::Integer(0), MmsValue::OctetString(vec![])]);
        let check = MmsValue::BitString {
            padding: 6,
            data: vec![0b11000000],
        };
        let v = MmsValue::Structure(vec![
            MmsValue::Boolean(true),
            origin_struct,
            MmsValue::Unsigned(5),
            MmsValue::UtcTime([0u8; 8]),
            MmsValue::Boolean(false),
            check,
        ]);
        let p = OperParams::from_mms_value(&v).expect("should parse");
        assert_eq!(p.ctl_val, MmsValue::Boolean(true));
        assert_eq!(p.ctl_num, 5);
        assert!(!p.test);
        assert!(p.synchro_check);
        assert!(p.interlock_check);
        assert_eq!(p.oper_tm_ms, 0);
    }

    #[test]
    fn oper_params_parse_7_elements_with_oper_tm() {
        let origin_struct = MmsValue::Structure(vec![
            MmsValue::Integer(3),
            MmsValue::OctetString(vec![0x01]),
        ]);
        let check = MmsValue::BitString {
            padding: 6,
            data: vec![0x00],
        };
        // Seven elements: ctlVal, operTm, origin, ctlNum, T, Test, Check.
        let v = MmsValue::Structure(vec![
            MmsValue::Boolean(false),
            MmsValue::UtcTime([0, 0, 0, 60, 0, 0, 0, 0]), // 60s
            origin_struct,
            MmsValue::Unsigned(7),
            MmsValue::UtcTime([0u8; 8]),
            MmsValue::Boolean(true),
            check,
        ]);
        let p = OperParams::from_mms_value(&v).expect("should parse 7 elements");
        assert_eq!(p.ctl_num, 7);
        assert!(p.test);
        assert_eq!(p.oper_tm_ms, 60_000);
    }

    #[test]
    fn oper_params_invalid_element_count() {
        let v = MmsValue::Structure(vec![MmsValue::Boolean(true), MmsValue::Unsigned(1)]);
        assert!(OperParams::from_mms_value(&v).is_none());
    }

    #[test]
    fn cancel_params_parse_5_elements() {
        let origin_struct =
            MmsValue::Structure(vec![MmsValue::Integer(0), MmsValue::OctetString(vec![])]);
        let v = MmsValue::Structure(vec![
            MmsValue::Boolean(false),
            origin_struct,
            MmsValue::Unsigned(2),
            MmsValue::UtcTime([0u8; 8]),
            MmsValue::Boolean(false),
        ]);
        let p = CancelParams::from_mms_value(&v).expect("should parse cancel");
        assert_eq!(p.ctl_num, 2);
        assert!(!p.test);
    }

    #[test]
    fn origin_validity_check() {
        let valid = OriginValue {
            or_cat: 3,
            or_ident: vec![0u8; 64],
        };
        assert!(valid.is_valid());

        let too_long = OriginValue {
            or_cat: 3,
            or_ident: vec![0u8; 65],
        };
        assert!(!too_long.is_valid());

        let bad_cat = OriginValue {
            or_cat: 9,
            or_ident: vec![],
        };
        assert!(!bad_cat.is_valid());
    }

    #[test]
    fn origin_from_mms_value_valid() {
        let v = MmsValue::Structure(vec![
            MmsValue::Integer(2),
            MmsValue::OctetString(vec![0xAA, 0xBB]),
        ]);
        let o = OriginValue::from_mms_value(&v).expect("should parse");
        assert_eq!(o.or_cat, 2);
        assert_eq!(o.or_ident, vec![0xAA, 0xBB]);
    }

    #[test]
    fn mms_value_binary_equal_float_nan() {
        let nan = f32::NAN;
        let a = MmsValue::Float32(nan);
        let b = MmsValue::Float32(nan);
        // the same NaN bit pattern compares equal
        assert!(mms_value_binary_equal(&a, &b));
        // NaN != 0.0
        assert!(!mms_value_binary_equal(&a, &MmsValue::Float32(0.0)));
    }

    #[test]
    fn mms_value_binary_equal_normal() {
        let a = MmsValue::Boolean(true);
        let b = MmsValue::Boolean(true);
        let c = MmsValue::Boolean(false);
        assert!(mms_value_binary_equal(&a, &b));
        assert!(!mms_value_binary_equal(&a, &c));
    }

    #[test]
    fn control_action_new_defaults_add_cause_unknown() {
        // A control action starts at Unknown(0), not None(25).
        let action = ControlAction::new(
            1,
            OriginValue::default(),
            [0u8; 8],
            false,
            false,
            false,
            false,
            0,
            0,
        );
        assert_eq!(action.add_cause(), ControlAddCause::Unknown);
        assert_eq!(action.add_cause() as i32, 0);
        assert_eq!(action.error_code(), ControlLastApplError::NoError);
    }

    #[test]
    fn control_add_cause_wire_values_match_iec61850() {
        // The wire integers of IEC 61850-7-2 must not drift.
        // Regression test for Diff #1 in docs/protocol-map/control/regressions.md
        assert_eq!(ControlAddCause::Unknown as i32, 0);
        assert_eq!(ControlAddCause::NotSupported as i32, 1);
        assert_eq!(ControlAddCause::BlockedBySwitchingHierarchy as i32, 2);
        assert_eq!(ControlAddCause::SelectFailed as i32, 3);
        assert_eq!(ControlAddCause::InvalidPosition as i32, 4);
        assert_eq!(ControlAddCause::PositionReached as i32, 5);
        assert_eq!(ControlAddCause::ParameterChangeInExecution as i32, 6);
        assert_eq!(ControlAddCause::StepLimit as i32, 7);
        assert_eq!(ControlAddCause::BlockedByMode as i32, 8);
        assert_eq!(ControlAddCause::BlockedByProcess as i32, 9);
        assert_eq!(ControlAddCause::BlockedByInterlocking as i32, 10);
        assert_eq!(ControlAddCause::BlockedBySynchroCheck as i32, 11);
        assert_eq!(ControlAddCause::CommandAlreadyInExecution as i32, 12);
        assert_eq!(ControlAddCause::BlockedByHealth as i32, 13);
        assert_eq!(ControlAddCause::OneOfNControl as i32, 14);
        assert_eq!(ControlAddCause::AbortionByCancel as i32, 15);
        assert_eq!(ControlAddCause::TimeLimitOver as i32, 16);
        assert_eq!(ControlAddCause::AbortionByTrip as i32, 17);
        assert_eq!(ControlAddCause::ObjectNotSelected as i32, 18);
        assert_eq!(ControlAddCause::ObjectAlreadySelected as i32, 19);
        assert_eq!(ControlAddCause::NoAccessAuthority as i32, 20);
        assert_eq!(ControlAddCause::EndedWithOvershoot as i32, 21);
        assert_eq!(ControlAddCause::AbortionDueToDeviation as i32, 22);
        assert_eq!(ControlAddCause::AbortionByCommunicationLoss as i32, 23);
        assert_eq!(ControlAddCause::AbortionByCommand as i32, 24);
        assert_eq!(ControlAddCause::None as i32, 25);
        assert_eq!(ControlAddCause::InconsistentParameters as i32, 26);
        assert_eq!(ControlAddCause::LockedByOtherClient as i32, 27);
        // The default add cause is Unknown(0).
        assert_eq!(ControlAddCause::default() as i32, 0);
        assert_eq!(ControlAddCause::default(), ControlAddCause::Unknown);
    }

    #[test]
    fn control_action_set_add_cause() {
        let mut action = ControlAction::new(
            2,
            OriginValue::default(),
            [0u8; 8],
            true,
            false,
            true,
            false,
            0,
            42,
        );
        action.set_add_cause(ControlAddCause::BlockedByInterlocking);
        assert_eq!(action.add_cause(), ControlAddCause::BlockedByInterlocking);
        assert_eq!(action.ctl_num(), 2);
        assert!(action.test());
        assert!(action.interlock_check());
    }

    #[test]
    fn utc_time_round_trip() {
        let ms_in = 1_000_500u64;
        let b = ms_to_utc_time(ms_in);
        let ms_out = utc_time_to_ms(&b);
        // A 1 ms tolerance covers the fractional-second resolution.
        assert!((ms_in as i64 - ms_out as i64).abs() <= 1);
    }
}
