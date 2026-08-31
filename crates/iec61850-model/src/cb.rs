//! Control block definitions: RCB, GoCB, SvCB, LCB and SGCB.
//!
//! These types hold the static schema a logical node owns. The runtime state
//! that goes with each block lives in the server crate, so a model stays
//! immutable once built.
//!
//! A control block belongs to the logical node that owns it, not to a flat
//! list on the model root. Lookup therefore stays local and matches the
//! containment IEC 61850-7-2 defines, instead of scanning a flat list and
//! comparing each entry's parent.

use crate::compat::prelude::*;
use crate::types::TrgOps;

/// A report control block, buffered or unbuffered according to `is_buffered`.
///
/// Carries the full static schema of an SCL `<ReportControl>` element: the
/// name, the buffering flag, the referenced data set, the configuration
/// revision, the report identifier, the trigger options, the option fields,
/// the buffer time and the integrity period.
///
/// Runtime state - whether reporting is enabled, which client owns the block,
/// the current entry identifier - stays in the server crate and is not mixed
/// into this structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportControlBlock {
    /// Block name, without the `LN$RP$` or `LN$BR$` prefix; the MMS mapping
    /// adds the wire name.
    pub name: String,
    /// `true` for a buffered block, `false` for an unbuffered one.
    pub is_buffered: bool,
    /// Name of the referenced data set, as `LN$dsName` or `LD/LN$dsName`; the
    /// caller decides which form.
    pub dataset_ref: String,
    /// The `confRev` attribute.
    pub conf_rev: u32,
    /// The `RptID` attribute; an empty string means it is unset.
    pub rpt_id: String,
    /// The `trgOps` attribute: the five trigger conditions DCHG, QCHG, DUPD,
    /// INTEGRITY and GI. Maps to the SCL `<TrgOps>` element and to a
    /// `BIT_STRING(6)` on the wire.
    pub trg_ops: TrgOps,
    /// The `OptFields` attribute, nine optional report fields. Maps to the SCL
    /// `<OptFields>` element and to a `BIT_STRING(10)` on the wire; the BER
    /// conversion is [`OptFlds::to_ber_bit_string`].
    pub opt_flds: OptFlds,
    /// The `bufTime` attribute in milliseconds: how long changes accumulate
    /// after a trigger before the report is flushed. `0` flushes immediately,
    /// and there is no upper bound.
    pub buf_tm_ms: u32,
    /// The `intgPd` attribute in milliseconds: the integrity report period.
    /// `0` disables the periodic trigger, and the value only matters when
    /// `trg_ops` contains `TrgOps::INTEGRITY`.
    pub intg_pd_ms: u32,
}

/// A GOOSE control block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GooseControlBlock {
    /// Control block name.
    pub name: String,
    /// Name of the referenced data set.
    pub dataset_ref: String,
    /// The confRev attribute.
    pub conf_rev: u32,
    /// The `goID`, the protocol-level identifier.
    pub go_id: String,
}

/// A sampled values control block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvControlBlock {
    /// Control block name.
    pub name: String,
    /// Name of the referenced data set.
    pub dataset_ref: String,
    /// The confRev attribute.
    pub conf_rev: u32,
    /// The `svID`.
    pub sv_id: String,
    /// `true` for multicast, `false` for unicast.
    pub is_multicast: bool,
}

/// A log control block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogControlBlock {
    /// Control block name.
    pub name: String,
    /// Name of the referenced log.
    pub dataset_ref: String,
    /// The referenced log, as `LN$logName`.
    pub log_ref: String,
}

/// The static configuration of a setting group control block, of which a
/// logical device holds at most one, attached to LLN0.
///
/// Holds only what SCL or the builder fixes and the build then freezes: the
/// number of setting groups, the initial active group, whether `ResvTms` is
/// exposed, and the reservation time.
///
/// Runtime state - switching the active group, an edit session in progress,
/// `cnfEdit`, the editing client, the reservation timer - lives in the server
/// crate, one instance per logical device, so that a model stays immutable
/// after `build`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingGroupControlBlock {
    /// The `numOfSG` attribute: the total number of setting groups, at least 1.
    pub num_of_sg: u8,
    /// The initial `actSG`, one-based. It must lie in `[1, num_of_sg]`; once
    /// the server runs, SelectActiveSG can change it.
    pub act_sg: u8,
    /// Whether the block exposes a `ResvTms` element.
    pub has_resv_tms: bool,
    /// The default `ResvTms` in seconds: how long an edit session stays
    /// reserved before it is canceled automatically. Ignored when
    /// `has_resv_tms` is false. IEC 61850-7-2 §19 puts the default at 60 s.
    pub default_resv_tms_s: u16,
}

impl Default for SettingGroupControlBlock {
    fn default() -> Self {
        Self {
            num_of_sg: 1,
            act_sg: 1,
            has_resv_tms: false,
            default_resv_tms_s: 60,
        }
    }
}

// -----------------------------------------------------------------------------
// OptFlds, nine bits carried in an MMS BIT_STRING(10)
// -----------------------------------------------------------------------------

/// The optional report fields of a report control block.
///
/// Bit layout:
///
/// - bit 0 (0x001) SEQ_NUM, the report sequence number
/// - bit 1 (0x002) TIME_STAMP
/// - bit 2 (0x004) REASON, the reason for inclusion
/// - bit 3 (0x008) DATA_SET, the data set name
/// - bit 4 (0x010) DATA_REFERENCE, the reference of each entry
/// - bit 5 (0x020) BUFFER_OVERFLOW, buffered blocks only; forced clear on an
///   unbuffered block
/// - bit 6 (0x040) ENTRY_ID, buffered blocks only; forced clear on an
///   unbuffered block
/// - bit 7 (0x080) CONF_REV
/// - bit 8 (0x100) SEGMENTATION
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct OptFlds(pub u16);

impl OptFlds {
    /// No option field set.
    pub const NONE: Self = OptFlds(0);
    /// The report sequence number.
    pub const SEQ_NUM: Self = OptFlds(0x001);
    /// The report timestamp.
    pub const TIME_STAMP: Self = OptFlds(0x002);
    /// The reason each entry is included.
    pub const REASON: Self = OptFlds(0x004);
    /// The data set name.
    pub const DATA_SET: Self = OptFlds(0x008);
    /// The reference of each entry.
    pub const DATA_REFERENCE: Self = OptFlds(0x010);
    /// Buffered blocks only; forced clear on an unbuffered block.
    pub const BUFFER_OVERFLOW: Self = OptFlds(0x020);
    /// Buffered blocks only; forced clear on an unbuffered block.
    pub const ENTRY_ID: Self = OptFlds(0x040);
    /// The configuration revision.
    pub const CONF_REV: Self = OptFlds(0x080);
    /// Report segmentation.
    pub const SEGMENTATION: Self = OptFlds(0x100);

    /// Reports whether every bit of `flag` is set.
    pub const fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) == flag.0
    }

    /// Returns the union of two option sets.
    pub const fn union(self, other: Self) -> Self {
        OptFlds(self.0 | other.0)
    }

    /// Reports whether no option field is set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns a copy with BUFFER_OVERFLOW and ENTRY_ID cleared, as an
    /// unbuffered block requires.
    ///
    /// Call it before encoding, so a buffered-only bit never reaches the wire.
    pub fn mask_urcb(self) -> Self {
        OptFlds(self.0 & !(Self::BUFFER_OVERFLOW.0 | Self::ENTRY_ID.0))
    }

    /// Serializes to the `BIT_STRING(10)` wire bytes, padding byte included.
    ///
    /// Ten bits need two data bytes and leave six padding bits.
    ///
    /// ISO 9506-2 leaves wire bit 0 permanently unused and starts the fields at
    /// wire bit 1, so an internal bit maps to `wire bit - 1`:
    ///
    /// - SEQ_NUM (0x001) to wire bit 1, byte 0 bit 6, mask 0x40
    /// - TIME_STAMP (0x002) to wire bit 2, byte 0 bit 5, mask 0x20
    /// - REASON (0x004) to wire bit 3, byte 0 bit 4, mask 0x10
    /// - DATA_SET (0x008) to wire bit 4, byte 0 bit 3, mask 0x08
    /// - DATA_REFERENCE (0x010) to wire bit 5, byte 0 bit 2, mask 0x04
    /// - BUFFER_OVERFLOW (0x020) to wire bit 6, byte 0 bit 1, mask 0x02, cleared
    ///   on an unbuffered block
    /// - ENTRY_ID (0x040) to wire bit 7, byte 0 bit 0, mask 0x01, cleared on an
    ///   unbuffered block
    /// - CONF_REV (0x080) to wire bit 8, byte 1 bit 7, mask 0x80
    /// - SEGMENTATION (0x100) to wire bit 9, byte 1 bit 6, mask 0x40
    pub fn to_ber_bit_string(self) -> [u8; 3] {
        let v = self.mask_urcb().0; // buffered-only bits must be clear
                                    // each internal bit shifts right by one, keeping wire bit 0 clear
        let byte0: u8 = ((v & 0x001) << 6) as u8  // SEQ_NUM -> 0x40
            | ((v & 0x002) << 4) as u8             // TIME_STAMP -> 0x20
            | ((v & 0x004) << 2) as u8             // REASON -> 0x10
            | (v & 0x008) as u8                    // DATA_SET -> 0x08
            | ((v & 0x010) >> 2) as u8             // DATA_REFERENCE -> 0x04
            | ((v & 0x020) >> 4) as u8             // BUFFER_OVERFLOW -> 0x02, already clear
            | ((v & 0x040) >> 6) as u8; // ENTRY_ID -> 0x01, already clear
        let byte1: u8 = (v & 0x080) as u8          // CONF_REV -> 0x80
            | ((v & 0x100) >> 2) as u8; // SEGMENTATION -> 0x40
        [6u8, byte0, byte1] // [padding=6, byte0, byte1]
    }

    /// Parses the `BIT_STRING(10)` wire bytes, padding byte included.
    ///
    /// Wire bit N, for N of at least 1, becomes internal bit N-1: each field
    /// shifts back left by one.
    pub fn from_ber_bit_string(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 3 {
            return None;
        }
        let _padding = bytes[0];
        let byte0 = bytes[1] as u16;
        let byte1 = bytes[2] as u16;
        let v = ((byte0 & 0x40) >> 6)   // SEQ_NUM
            | ((byte0 & 0x20) >> 4)     // TIME_STAMP
            | ((byte0 & 0x10) >> 2)     // REASON
            | (byte0 & 0x08)            // DATA_SET
            | ((byte0 & 0x04) << 2)     // DATA_REFERENCE
            | ((byte0 & 0x02) << 4)     // BUFFER_OVERFLOW
            | ((byte0 & 0x01) << 6)     // ENTRY_ID
            | (byte1 & 0x80)            // CONF_REV
            | ((byte1 & 0x40) << 2); // SEGMENTATION
        Some(OptFlds(v))
    }
}

impl core::ops::BitOr for OptFlds {
    type Output = OptFlds;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl core::ops::BitOrAssign for OptFlds {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[cfg(test)]
mod opt_flds_tests {
    use super::*;

    #[test]
    fn opt_flds_bit_values_match_documented_layout() {
        // The bit layout documented on the type
        assert_eq!(OptFlds::SEQ_NUM.0, 0x001);
        assert_eq!(OptFlds::TIME_STAMP.0, 0x002);
        assert_eq!(OptFlds::REASON.0, 0x004);
        assert_eq!(OptFlds::DATA_SET.0, 0x008);
        assert_eq!(OptFlds::DATA_REFERENCE.0, 0x010);
        assert_eq!(OptFlds::BUFFER_OVERFLOW.0, 0x020);
        assert_eq!(OptFlds::ENTRY_ID.0, 0x040);
        assert_eq!(OptFlds::CONF_REV.0, 0x080);
        assert_eq!(OptFlds::SEGMENTATION.0, 0x100);
    }

    #[test]
    fn opt_flds_mask_urcb_clears_brcb_bits() {
        let all = OptFlds(0x1ff);
        let masked = all.mask_urcb();
        assert!(!masked.contains(OptFlds::BUFFER_OVERFLOW));
        assert!(!masked.contains(OptFlds::ENTRY_ID));
        assert!(masked.contains(OptFlds::SEQ_NUM));
        assert!(masked.contains(OptFlds::CONF_REV));
        assert!(masked.contains(OptFlds::SEGMENTATION));
    }

    #[test]
    fn opt_flds_to_ber_round_trip() {
        let orig = OptFlds::SEQ_NUM | OptFlds::TIME_STAMP | OptFlds::CONF_REV;
        let wire = orig.to_ber_bit_string();
        assert_eq!(wire[0], 6);
        let decoded = OptFlds::from_ber_bit_string(&wire).unwrap();
        assert_eq!(decoded, orig);
    }

    #[test]
    fn opt_flds_segmentation_round_trip() {
        let orig = OptFlds::SEGMENTATION;
        let wire = orig.to_ber_bit_string();
        let decoded = OptFlds::from_ber_bit_string(&wire).unwrap();
        assert_eq!(decoded, orig);
    }

    #[test]
    fn opt_flds_none_round_trip() {
        let orig = OptFlds::NONE;
        let wire = orig.to_ber_bit_string();
        let decoded = OptFlds::from_ber_bit_string(&wire).unwrap();
        assert_eq!(decoded, orig);
    }

    /// Golden vector: {SEQ_NUM, TIME_STAMP, REASON, DATA_SET, CONF_REV}
    /// encodes to [0x06, 0x78, 0x80].
    #[test]
    fn opt_flds_golden_encode_wire_vector() {
        let opts = OptFlds::SEQ_NUM
            | OptFlds::TIME_STAMP
            | OptFlds::REASON
            | OptFlds::DATA_SET
            | OptFlds::CONF_REV;
        let wire = opts.to_ber_bit_string();
        assert_eq!(wire, [0x06, 0x78, 0x80]);
    }

    #[test]
    fn opt_flds_golden_decode_wire_vector() {
        let decoded = OptFlds::from_ber_bit_string(&[0x06, 0x78, 0x80]).unwrap();
        let expected = OptFlds::SEQ_NUM
            | OptFlds::TIME_STAMP
            | OptFlds::REASON
            | OptFlds::DATA_SET
            | OptFlds::CONF_REV;
        assert_eq!(decoded, expected);
    }

    #[test]
    fn opt_flds_golden_segmentation_wire() {
        let wire = OptFlds::SEGMENTATION.to_ber_bit_string();
        assert_eq!(wire, [0x06, 0x00, 0x40]);
        let decoded = OptFlds::from_ber_bit_string(&[0x06, 0x00, 0x40]).unwrap();
        assert_eq!(decoded, OptFlds::SEGMENTATION);
    }
}
