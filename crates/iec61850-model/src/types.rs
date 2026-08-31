//! Basic model types: `DataAttributeType`, `TrgOps`, `Quality`, `Dbpos`,
//! `ControlModel`, `OrCat` and `Validity`, per IEC 61850-7-2 and 7-3.

use crate::error::ModelError;
use crate::value::MmsValue;
use core::fmt;

/// The data attribute types of IEC 61850-7-3 §5.4.
///
/// The discriminants match the numbering common IEC 61850 implementations
/// use, so a future ABI can share them; nothing here depends on the value.
///
/// A variable-length string or bit string carries its limit as a parameter,
/// rather than having one variant per length.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum DataAttributeType {
    /// BOOLEAN.
    Boolean,
    /// 8-bit signed integer.
    Int8,
    /// 16-bit signed integer.
    Int16,
    /// 32-bit signed integer.
    Int32,
    /// 64-bit signed integer.
    Int64,
    /// No native equivalent; the slot is reserved and the wire form is a plain
    /// BER INTEGER.
    Int128,
    /// 8-bit unsigned integer.
    Int8U,
    /// 16-bit unsigned integer.
    Int16U,
    /// 24-bit unsigned integer.
    Int24U,
    /// 32-bit unsigned integer.
    Int32U,
    /// 32-bit IEEE 754 floating point.
    Float32,
    /// 64-bit IEEE 754 floating point.
    Float64,
    /// Enumerated value, carried as an integer.
    Enumerated,
    /// An octet string of at most `n` bytes.
    OctetString(u16),
    /// An ASCII visible string of at most `n` bytes.
    VisibleString(u16),
    /// A Unicode string, capped at 255 bytes by IEC 61850.
    UnicodeString255,
    /// An eight-byte UTC time.
    Timestamp,
    /// A 13-bit bit string carrying the source, test, blocked and derived flags.
    Quality,
    /// A 2-bit bit string carrying the synchrocheck and interlock flags.
    Check,
    /// A 2-bit coded enumeration, such as `Dbpos`.
    CodedEnum,
    /// A bit string of at most `n` bits.
    GenericBitString(u16),
    /// A nested structure.
    Constructed,
    /// A binary time of four or six bytes.
    EntryTime,
    /// A physical communication address.
    PhyComAddr,
    /// Currency code.
    Currency,
    /// A 10-bit bit string carrying the report option fields.
    OptFlds,
    /// A 6-bit bit string carrying the trigger options.
    TrgOpsBits,
}

impl DataAttributeType {
    /// Returns a readable name, for use in error messages.
    pub fn type_name(self) -> &'static str {
        match self {
            DataAttributeType::Boolean => "Boolean",
            DataAttributeType::Int8 => "Int8",
            DataAttributeType::Int16 => "Int16",
            DataAttributeType::Int32 => "Int32",
            DataAttributeType::Int64 => "Int64",
            DataAttributeType::Int128 => "Int128",
            DataAttributeType::Int8U => "Int8U",
            DataAttributeType::Int16U => "Int16U",
            DataAttributeType::Int24U => "Int24U",
            DataAttributeType::Int32U => "Int32U",
            DataAttributeType::Float32 => "Float32",
            DataAttributeType::Float64 => "Float64",
            DataAttributeType::Enumerated => "Enumerated",
            DataAttributeType::OctetString(_) => "OctetString",
            DataAttributeType::VisibleString(_) => "VisibleString",
            DataAttributeType::UnicodeString255 => "UnicodeString255",
            DataAttributeType::Timestamp => "Timestamp",
            DataAttributeType::Quality => "Quality",
            DataAttributeType::Check => "Check",
            DataAttributeType::CodedEnum => "CodedEnum",
            DataAttributeType::GenericBitString(_) => "GenericBitString",
            DataAttributeType::Constructed => "Constructed",
            DataAttributeType::EntryTime => "EntryTime",
            DataAttributeType::PhyComAddr => "PhyComAddr",
            DataAttributeType::Currency => "Currency",
            DataAttributeType::OptFlds => "OptFlds",
            DataAttributeType::TrgOpsBits => "TrgOpsBits",
        }
    }
}

/// Trigger options: the `triggerOptions` bit field of IEC 61850-7-2 §17.2.1.
///
/// Two contexts use it. On a data attribute it marks which changes make that
/// attribute trigger a report, and only `DCHG`, `QCHG` and `DUPD` apply. On a
/// report control block it marks which trigger modes the block enables, and
/// all five bits apply; `INTEGRITY` and `GI` belong to the block itself rather
/// than to any one attribute.
///
/// The bit layout matches the trigger-option type the server runtime uses.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct TrgOps(pub u8);

impl TrgOps {
    /// No trigger option set.
    pub const NONE: Self = TrgOps(0);
    /// Data change. Valid on a data attribute and on a control block.
    pub const DCHG: Self = TrgOps(0b0000_0001);
    /// Quality change. Valid on a data attribute and on a control block.
    pub const QCHG: Self = TrgOps(0b0000_0010);
    /// Data update: the value was refreshed without changing. Valid on both.
    pub const DUPD: Self = TrgOps(0b0000_0100);
    /// Integrity: the periodic full report driven by `intgPd`. Control block
    /// only; a data attribute must not set this bit.
    pub const INTEGRITY: Self = TrgOps(0b0000_1000);
    /// General interrogation: the full snapshot a client asks for. Control
    /// block only.
    pub const GI: Self = TrgOps(0b0001_0000);
    /// All five bits: DCHG, QCHG, DUPD, INTEGRITY and GI.
    pub const ALL: Self = TrgOps(0b0001_1111);

    /// Bitwise OR, usable in a const context.
    pub const fn union(self, other: Self) -> Self {
        TrgOps(self.0 | other.0)
    }

    /// Reports whether every bit of `flag` is set.
    pub const fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) == flag.0
    }

    /// Reports whether no trigger option is set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl core::ops::BitOr for TrgOps {
    type Output = TrgOps;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

/// Validity: bits 0 and 1 of the quality bit string, per IEC 61850-7-3 §5.4.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
#[repr(u16)]
pub enum Validity {
    #[default]
    /// The value is good.
    Good = 0,
    /// Reserved by IEC 61850-7-3; treated as a distinct validity.
    Reserved = 1,
    /// The value is invalid.
    Invalid = 2,
    /// The value is questionable.
    Questionable = 3,
}

impl Validity {
    /// Recovers the validity from the low two bits of a `u16`. All four values
    /// are defined, so no input is rejected.
    pub const fn from_bits(bits: u16) -> Self {
        match bits & 0x3 {
            0 => Validity::Good,
            1 => Validity::Reserved,
            2 => Validity::Invalid,
            _ => Validity::Questionable,
        }
    }
}

/// Quality: the 13-bit bit string of IEC 61850-7-3 §5.4.
///
/// Held as a `u16` whose bits 0 to 12 each carry one flag. Conversion to and
/// from the wire form is [`Quality::to_mms_bit_string`] and
/// [`Quality::from_mms_bit_string`].
///
/// Bit 13, [`Quality::DERIVED`], lies outside the 13-bit wire encoding and is
/// never serialized, so `Quality(0x2000)` becomes `Quality(0)` after a round
/// trip. The flag therefore has no on-wire meaning and is kept only as an
/// in-memory marker.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct Quality(pub u16);

impl Quality {
    /// Good quality: every flag clear.
    pub const GOOD: Self = Quality(0);

    // Validity, bits 0 and 1, a two-bit field
    /// `validity = 1`, reserved; a single-bit mask.
    pub const VALIDITY_RESERVED: u16 = 0x0001;
    /// `validity = 2`, invalid.
    pub const VALIDITY_INVALID: u16 = 0x0002;
    /// `validity = 3`, questionable: bit 0 and bit 1 together.
    pub const VALIDITY_QUESTIONABLE: u16 = 0x0003;

    // Detail flags, bits 2 to 9
    /// The source value overflowed its range.
    pub const DETAIL_OVERFLOW: u16 = 0x0004;
    /// The source value is outside its configured range.
    pub const DETAIL_OUT_OF_RANGE: u16 = 0x0008;
    /// The reference the value derives from is bad.
    pub const DETAIL_BAD_REFERENCE: u16 = 0x0010;
    /// The source value is oscillating.
    pub const DETAIL_OSCILLATORY: u16 = 0x0020;
    /// The source device reports a failure.
    pub const DETAIL_FAILURE: u16 = 0x0040;
    /// The value has not been refreshed within its expected period.
    pub const DETAIL_OLD_DATA: u16 = 0x0080;
    /// The value is inconsistent with a redundant source.
    pub const DETAIL_INCONSISTENT: u16 = 0x0100;
    /// The value is less accurate than declared.
    pub const DETAIL_INACCURATE: u16 = 0x0200;

    // Source, test and blocked, bits 10 to 12
    /// The value was substituted rather than measured.
    pub const SOURCE_SUBSTITUTED: u16 = 0x0400;
    /// The value comes from a device in test mode.
    pub const TEST: u16 = 0x0800;
    /// The value is blocked for update by an operator.
    pub const OPERATOR_BLOCKED: u16 = 0x1000;

    /// Bit 13. Outside the 13-bit wire encoding, so it never reaches the wire
    /// and serves only as an in-memory marker.
    pub const DERIVED: u16 = 0x2000;

    /// Returns the validity field, bits 0 and 1.
    pub const fn validity(self) -> Validity {
        Validity::from_bits(self.0)
    }

    /// Returns a copy with the validity field replaced.
    pub const fn with_validity(self, v: Validity) -> Self {
        Quality((self.0 & 0xfffc) | (v as u16))
    }

    /// Returns a copy with `flag` set. `flag` is one of the single-bit
    /// constants above.
    pub const fn with_flag(self, flag: u16) -> Self {
        Quality(self.0 | flag)
    }

    /// Returns a copy with `flag` cleared.
    pub const fn without_flag(self, flag: u16) -> Self {
        Quality(self.0 & !flag)
    }

    /// Reports whether any bit of `flag` is set.
    pub const fn is_flag_set(self, flag: u16) -> bool {
        (self.0 & flag) != 0
    }

    /// Serializes to the 13-bit `MmsValue::BitString` wire form.
    ///
    /// Bit `i` of the integer becomes bit `i` of the bit string, which lands
    /// in wire byte `i / 8` at bit `7 - (i % 8)`, the big-endian bit order of
    /// ISO/IEC 8825-1. The 13 bits occupy two bytes with three padding bits.
    pub fn to_mms_bit_string(self) -> MmsValue {
        let mut data = [0u8, 0u8];
        for bit_pos in 0..13 {
            if (self.0 >> bit_pos) & 1 == 1 {
                let byte_idx = bit_pos / 8;
                let bit_in_byte = 7 - (bit_pos % 8);
                data[byte_idx] |= 1 << bit_in_byte;
            }
        }
        MmsValue::BitString {
            padding: 3,
            data: data.to_vec(),
        }
    }

    /// Recovers a quality from an `MmsValue::BitString`.
    ///
    /// Only the first 13 bits are read; any further bit is ignored.
    ///
    /// # Errors
    ///
    /// [`ModelError::TypeMismatch`] when the value is not a bit string, holds
    /// fewer than two bytes, or declares more than seven padding bits.
    pub fn from_mms_bit_string(v: &MmsValue) -> Result<Self, ModelError> {
        let MmsValue::BitString { padding, data } = v else {
            return Err(ModelError::TypeMismatch {
                path: "Quality".into(),
                expected: "BitString",
                got: v.type_name(),
            });
        };
        // 13 bits need at least two bytes. A bit string may legally declare up
        // to seven padding bits, so anything above that is malformed.
        if data.len() < 2 || *padding > 7 {
            return Err(ModelError::TypeMismatch {
                path: "Quality".into(),
                expected: "BitString>=13bit",
                got: v.type_name(),
            });
        }
        let mut q: u16 = 0;
        for bit_pos in 0..13 {
            let byte_idx = bit_pos / 8;
            let bit_in_byte = 7 - (bit_pos % 8);
            if (data[byte_idx] >> bit_in_byte) & 1 == 1 {
                q |= 1 << bit_pos;
            }
        }
        Ok(Quality(q))
    }
}

impl fmt::Display for Quality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Quality({:#06x})", self.0)
    }
}

// -----------------------------------------------------------------------------
// Dbpos
// -----------------------------------------------------------------------------

/// The double-point status position of a DPS `stVal`, per IEC 61850-7-3 §6.2.
///
/// The wire form is a 2-bit bit string in big-endian bit order: bit 0 is the
/// most significant bit of the byte and bit 1 is bit 6.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Dbpos {
    #[default]
    /// Neither contact is in its end position.
    Intermediate = 0,
    /// Off, the first end position.
    Off = 1,
    /// On, the second end position.
    On = 2,
    /// Both contacts report the same state, which is invalid.
    BadState = 3,
}

impl Dbpos {
    /// Serializes to a 2-bit `MmsValue::BitString`.
    ///
    /// In the big-endian bit order of ISO/IEC 8825-1, integer bit 0 becomes
    /// the last bit of the bit string, which is bit 6 of the wire byte, and
    /// integer bit 1 becomes the first, which is bit 7. So `Off` encodes to
    /// `0x40`, `On` to `0x80` and `BadState` to `0xC0`.
    pub fn to_mms_bit_string(self) -> MmsValue {
        let v = self as u8;
        let byte = ((v & 0x2) << 6) | ((v & 0x1) << 6);
        MmsValue::BitString {
            padding: 6,
            data: vec![byte],
        }
    }

    /// Recovers a value from a 2-bit `MmsValue::BitString`.
    pub fn from_mms_bit_string(v: &MmsValue) -> Result<Self, ModelError> {
        let MmsValue::BitString { data, .. } = v else {
            return Err(ModelError::TypeMismatch {
                path: "Dbpos".into(),
                expected: "BitString",
                got: v.type_name(),
            });
        };
        if data.is_empty() {
            return Err(ModelError::TypeMismatch {
                path: "Dbpos".into(),
                expected: "BitString>=2bit",
                got: v.type_name(),
            });
        }
        let bit0 = (data[0] >> 7) & 1;
        let bit1 = (data[0] >> 6) & 1;
        Ok(match (bit0 << 1) | bit1 {
            0 => Dbpos::Intermediate,
            1 => Dbpos::Off,
            2 => Dbpos::On,
            _ => Dbpos::BadState,
        })
    }
}

// -----------------------------------------------------------------------------
// ControlModel
// -----------------------------------------------------------------------------

/// The values of the `ctlModel` attribute, per IEC 61850-7-2 Table 67.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum ControlModel {
    #[default]
    /// Status only: the object reports but accepts no control.
    StatusOnly = 0,
    /// Direct control with normal security.
    DirectNormal = 1,
    /// Select-before-operate with normal security.
    SboNormal = 2,
    /// Direct control with enhanced security.
    DirectEnhanced = 3,
    /// Select-before-operate with enhanced security.
    SboEnhanced = 4,
}

// -----------------------------------------------------------------------------
// OrCat
// -----------------------------------------------------------------------------

/// The nine values of `origin.orCat`, per IEC 61850-7-2 §17.2.5.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum OrCat {
    #[default]
    /// The origin category is not supported.
    NotSupported = 0,
    /// Control issued at bay level.
    BayControl = 1,
    /// Control issued at station level.
    StationControl = 2,
    /// Control issued remotely.
    RemoteControl = 3,
    /// Control issued by bay-level automation.
    AutomaticBay = 4,
    /// Control issued by station-level automation.
    AutomaticStation = 5,
    /// Control issued by remote automation.
    AutomaticRemote = 6,
    /// Control issued during maintenance.
    Maintenance = 7,
    /// Control issued by the process itself.
    Process = 8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trg_ops_or() {
        let t = TrgOps::DCHG | TrgOps::QCHG;
        assert!(t.contains(TrgOps::DCHG));
        assert!(t.contains(TrgOps::QCHG));
        assert!(!t.contains(TrgOps::DUPD));
    }

    #[test]
    fn trg_ops_default_none() {
        assert_eq!(TrgOps::default(), TrgOps::NONE);
    }

    #[test]
    fn quality_default_good() {
        assert_eq!(Quality::default(), Quality::GOOD);
    }

    #[test]
    fn quality_validity_round_trip() {
        for v in [
            Validity::Good,
            Validity::Reserved,
            Validity::Invalid,
            Validity::Questionable,
        ] {
            let q = Quality::default().with_validity(v);
            assert_eq!(q.validity(), v);
        }
    }

    #[test]
    fn quality_with_validity_preserves_other_flags() {
        let q = Quality(0)
            .with_flag(Quality::TEST)
            .with_flag(Quality::DETAIL_FAILURE);
        let q2 = q.with_validity(Validity::Invalid);
        assert_eq!(q2.validity(), Validity::Invalid);
        assert!(q2.is_flag_set(Quality::TEST));
        assert!(q2.is_flag_set(Quality::DETAIL_FAILURE));
    }

    #[test]
    fn quality_flag_set_unset() {
        let q = Quality(0).with_flag(Quality::TEST);
        assert!(q.is_flag_set(Quality::TEST));
        let q2 = q.without_flag(Quality::TEST);
        assert!(!q2.is_flag_set(Quality::TEST));
    }

    #[test]
    fn quality_to_bit_string_good() {
        // GOOD is 0: every bit clear, two bytes with padding 3.
        let v = Quality::GOOD.to_mms_bit_string();
        assert_eq!(
            v,
            MmsValue::BitString {
                padding: 3,
                data: vec![0, 0]
            }
        );
    }

    #[test]
    fn quality_to_bit_string_validity_invalid() {
        // VALIDITY_INVALID is 0b10, so bit 1 lands in wire byte 0 bit 6, giving 0x40.
        let q = Quality::default().with_validity(Validity::Invalid);
        let v = q.to_mms_bit_string();
        assert_eq!(
            v,
            MmsValue::BitString {
                padding: 3,
                data: vec![0x40, 0x00]
            }
        );
    }

    #[test]
    fn quality_to_bit_string_test_flag() {
        // TEST is bit 11, which lands in wire byte 1 bit 4, giving 0x10.
        let q = Quality::default().with_flag(Quality::TEST);
        let v = q.to_mms_bit_string();
        assert_eq!(
            v,
            MmsValue::BitString {
                padding: 3,
                data: vec![0x00, 0x10]
            }
        );
    }

    #[test]
    fn quality_round_trip_through_bit_string() {
        for raw in [
            0u16,
            Quality::VALIDITY_INVALID,
            Quality::DETAIL_OVERFLOW | Quality::DETAIL_FAILURE,
            Quality::TEST | Quality::OPERATOR_BLOCKED,
            0x1FFF, // all 13 bits
        ] {
            let q = Quality(raw);
            let v = q.to_mms_bit_string();
            let q2 = Quality::from_mms_bit_string(&v).unwrap();
            assert_eq!(q, q2, "raw={raw:#06x}");
        }
    }

    #[test]
    fn quality_derived_bit_lost_in_wire_round_trip() {
        // Bit 13 lies outside the 13-bit bit string, so a wire round trip drops it.
        let q = Quality(Quality::DERIVED);
        let v = q.to_mms_bit_string();
        assert_eq!(
            v,
            MmsValue::BitString {
                padding: 3,
                data: vec![0, 0]
            }
        );
        let q2 = Quality::from_mms_bit_string(&v).unwrap();
        assert_eq!(q2, Quality::GOOD);
    }

    #[test]
    fn quality_from_bit_string_type_mismatch() {
        let r = Quality::from_mms_bit_string(&MmsValue::Boolean(true));
        assert!(matches!(r, Err(ModelError::TypeMismatch { .. })));
    }

    #[test]
    fn dbpos_to_bit_string_values() {
        // The Dbpos wire values of IEC 61850-7-3: Off is 0x40, On is 0x80 and
        // BadState is 0xC0.
        assert_eq!(
            Dbpos::Intermediate.to_mms_bit_string(),
            MmsValue::BitString {
                padding: 6,
                data: vec![0x00]
            }
        );
        assert_eq!(
            Dbpos::Off.to_mms_bit_string(),
            MmsValue::BitString {
                padding: 6,
                data: vec![0x40]
            }
        );
        assert_eq!(
            Dbpos::On.to_mms_bit_string(),
            MmsValue::BitString {
                padding: 6,
                data: vec![0x80]
            }
        );
        assert_eq!(
            Dbpos::BadState.to_mms_bit_string(),
            MmsValue::BitString {
                padding: 6,
                data: vec![0xC0]
            }
        );
    }

    #[test]
    fn dbpos_round_trip() {
        for d in [Dbpos::Intermediate, Dbpos::Off, Dbpos::On, Dbpos::BadState] {
            let v = d.to_mms_bit_string();
            assert_eq!(Dbpos::from_mms_bit_string(&v).unwrap(), d, "{d:?}");
        }
    }

    #[test]
    fn dat_type_name_smoke() {
        assert_eq!(DataAttributeType::Boolean.type_name(), "Boolean");
        assert_eq!(
            DataAttributeType::OctetString(64).type_name(),
            "OctetString"
        );
    }
}
