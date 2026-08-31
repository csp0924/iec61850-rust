//! Report control block bit flags: trigger options, option fields, and the
//! per-entry inclusion flag, as defined in IEC 61850-7-2 §15.
//!
//! The flags are newtype wrappers over an integer with associated constants,
//! matching the style of `TrgOps` and `Quality` in `iec61850-model`, since the
//! workspace does not depend on a bit-flag crate.
//!
//! These types sit at crate top level rather than inside the reporting module:
//! the BIT_STRING encoding they define belongs to IEC 61850-7-2 rather than to
//! one subsystem, and the logging module needs it as much as the reporting
//! module does, so neither has to pull the other in.
//!
//! An unbuffered control block never advertises `BUFFER_OVERFLOW` or
//! `ENTRY_ID`; `OptFlds::mask_urcb` clears them before encoding so they cannot
//! reach the wire.

// ─────────────────────────────────────────────────────────────────────────────
// TriggerOptions: 5 flags, carried as an MMS BIT_STRING(6)
// ─────────────────────────────────────────────────────────────────────────────

/// Conditions that cause a report control block to issue a report.
///
/// Bit layout: 0x01 data-changed, 0x02 quality-changed, 0x04 data-update,
/// 0x08 integrity, 0x10 general interrogation.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct TriggerOptions(
    /// Bitmask of the trigger conditions.
    pub u8,
);

impl TriggerOptions {
    /// No trigger condition.
    pub const NONE: Self = TriggerOptions(0);
    /// The value of a data set member changed.
    pub const DATA_CHANGED: Self = TriggerOptions(0x01);
    /// The quality of a data set member changed.
    pub const QUALITY_CHANGED: Self = TriggerOptions(0x02);
    /// A data set member was written without its value changing.
    pub const DATA_UPDATE: Self = TriggerOptions(0x04);
    /// The integrity period elapsed.
    pub const INTEGRITY: Self = TriggerOptions(0x08);
    /// A general interrogation was requested.
    pub const GI: Self = TriggerOptions(0x10);
    /// Every trigger condition enabled.
    pub const ALL: Self = TriggerOptions(0x1f);

    /// Reports whether every condition set in `flag` is also set here.
    pub const fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) == flag.0
    }

    /// Returns the conditions set in either operand.
    pub const fn union(self, other: Self) -> Self {
        TriggerOptions(self.0 | other.0)
    }

    /// Reports whether the two share at least one condition.
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    /// Reports whether no condition is set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Encodes the options as BIT_STRING(6) content, padding byte first.
    ///
    /// A BIT_STRING begins with a count of unused trailing bits; six bits fit
    /// one data byte, leaving two unused, so the padding byte is 2.
    ///
    /// By the BIT_STRING convention of ISO 9506-2 wire bit 0 is permanently
    /// unused, so the fields start at wire bit 1: data-changed becomes 0x40,
    /// quality-changed 0x20, data-update 0x10, integrity 0x08, and general
    /// interrogation 0x04.
    pub fn to_ber_bit_string(self) -> [u8; 2] {
        // Each flag moves one position along, leaving wire bit 0 clear.
        let data_byte = ((self.0 & 0x01) << 6)
            | ((self.0 & 0x02) << 4)
            | ((self.0 & 0x04) << 2)
            | (self.0 & 0x08)
            | ((self.0 & 0x10) >> 2);
        [2u8, data_byte]
    }

    /// Decodes BIT_STRING(6) content, padding byte included, reversing the
    /// one-position shift of [`TriggerOptions::to_ber_bit_string`].
    ///
    /// Returns `None` for content shorter than two bytes.
    pub fn from_ber_bit_string(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 2 {
            return None;
        }
        let _padding = bytes[0];
        let data_byte = bytes[1];
        // wire bit-1(0x40) → internal bit-0; wire bit-5(0x04) → internal bit-4
        let raw = ((data_byte & 0x40) >> 6)
            | ((data_byte & 0x20) >> 4)
            | ((data_byte & 0x10) >> 2)
            | (data_byte & 0x08)
            | ((data_byte & 0x04) << 2);
        Some(TriggerOptions(raw & 0x1f))
    }
}

impl core::ops::BitOr for TriggerOptions {
    type Output = TriggerOptions;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl core::ops::BitOrAssign for TriggerOptions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OptFlds is owned by the model crate and re-exported here.
//
// The SCL `<ReportControl><OptFields>` element feeds the report control block
// schema of the model, so the type and its encoding tests live alongside it.
// ─────────────────────────────────────────────────────────────────────────────

pub use iec61850_model::cb::OptFlds;

// ─────────────────────────────────────────────────────────────────────────────
// InclusionFlag: why one data set member appears in a report
// ─────────────────────────────────────────────────────────────────────────────

/// Why one data set member is included in a report (IEC 61850-7-2 §15).
///
/// 0 means nothing is pending. 1 is a data update, 2 a data change, and 4 a
/// quality change, each matching the trigger option of the same name. 8 marks a
/// member whose copy was deferred while the data model was locked; it is not a
/// reason for inclusion and the value is copied once the lock is released.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct InclusionFlag(
    /// Bitmask of the reasons for inclusion.
    pub u8,
);

impl InclusionFlag {
    /// Nothing is pending for this member.
    pub const NONE: Self = InclusionFlag(0);
    /// The member was written without its value changing.
    pub const VALUE_UPDATE: Self = InclusionFlag(1);
    /// The value of the member changed.
    pub const VALUE_CHANGED: Self = InclusionFlag(2);
    /// The quality of the member changed.
    pub const QUALITY_CHANGED: Self = InclusionFlag(4);
    /// The copy was deferred while the data model was locked; not a reason for
    /// inclusion.
    pub const NOT_UPDATED: Self = InclusionFlag(8);

    /// Reports whether nothing at all is pending, a deferred copy included.
    pub const fn is_none(self) -> bool {
        self.0 == 0
    }

    /// Reports whether any trigger is pending, ignoring a deferred copy.
    pub const fn has_trigger(self) -> bool {
        (self.0 & 0x07) != 0
    }

    /// Reports whether every reason set in `flag` is also set here.
    pub const fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) == flag.0
    }

    /// Returns the reasons set in either operand.
    pub const fn union(self, other: Self) -> Self {
        InclusionFlag(self.0 | other.0)
    }

    /// Encodes the reason for inclusion as BIT_STRING(6) content, padding byte
    /// first.
    ///
    /// Wire bit 1 is data-change, 2 quality-change, 3 data-update, 4 integrity,
    /// and 5 general interrogation; the last two come from the arguments rather
    /// than from the flag. Wire bit numbering is one-based from the most
    /// significant bit of the data byte, so wire bit 1 is mask 0x40.
    pub fn to_reason_bit_string(self, is_integrity: bool, is_gi: bool) -> [u8; 2] {
        let mut data_byte: u8 = 0;
        if self.contains(Self::VALUE_CHANGED) {
            data_byte |= 0x40;
        }
        if self.contains(Self::QUALITY_CHANGED) {
            data_byte |= 0x20;
        }
        if self.contains(Self::VALUE_UPDATE) {
            data_byte |= 0x10;
        }
        if is_integrity {
            data_byte |= 0x08;
        }
        if is_gi {
            data_byte |= 0x04;
        }
        [2u8, data_byte]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TriggerOptions ────────────────────────────────────────────────────────

    #[test]
    fn trg_ops_bit_values_match_documented_layout() {
        assert_eq!(TriggerOptions::DATA_CHANGED.0, 0x01);
        assert_eq!(TriggerOptions::QUALITY_CHANGED.0, 0x02);
        assert_eq!(TriggerOptions::DATA_UPDATE.0, 0x04);
        assert_eq!(TriggerOptions::INTEGRITY.0, 0x08);
        assert_eq!(TriggerOptions::GI.0, 0x10);
    }

    #[test]
    fn trg_ops_contains() {
        let opts = TriggerOptions::DATA_CHANGED | TriggerOptions::GI;
        assert!(opts.contains(TriggerOptions::DATA_CHANGED));
        assert!(opts.contains(TriggerOptions::GI));
        assert!(!opts.contains(TriggerOptions::INTEGRITY));
    }

    #[test]
    fn trg_ops_to_ber_round_trip() {
        let orig = TriggerOptions::DATA_CHANGED | TriggerOptions::INTEGRITY | TriggerOptions::GI;
        let wire = orig.to_ber_bit_string();
        assert_eq!(wire[0], 2, "a BIT_STRING(6) has two unused bits");
        let decoded = TriggerOptions::from_ber_bit_string(&wire).expect("decode should succeed");
        assert_eq!(decoded, orig, "the round trip must preserve the options");
    }

    #[test]
    fn trg_ops_all_round_trip() {
        let orig = TriggerOptions::ALL;
        let wire = orig.to_ber_bit_string();
        let decoded = TriggerOptions::from_ber_bit_string(&wire).unwrap();
        assert_eq!(decoded, orig);
    }

    #[test]
    fn trg_ops_none_round_trip() {
        let orig = TriggerOptions::NONE;
        let wire = orig.to_ber_bit_string();
        let decoded = TriggerOptions::from_ber_bit_string(&wire).unwrap();
        assert_eq!(decoded, orig);
    }

    /// Golden vector for a GetURCBValues response: data-changed is wire bit 1
    /// of TrgOps and therefore encodes as `[0x02, 0x40]`.
    #[test]
    fn trg_ops_golden_data_changed() {
        let wire = TriggerOptions::DATA_CHANGED.to_ber_bit_string();
        assert_eq!(
            wire,
            [0x02, 0x40],
            "data-changed must encode as 0x40, not 0x80"
        );
        let decoded =
            TriggerOptions::from_ber_bit_string(&[0x02, 0x40]).expect("decode should succeed");
        assert_eq!(decoded, TriggerOptions::DATA_CHANGED);
    }

    /// Golden vector for the same response: integrity is wire bit 4 (0x08) and
    /// general interrogation wire bit 5 (0x04), so together they encode as
    /// `[0x02, 0x0c]`.
    #[test]
    fn trg_ops_golden_integrity_gi() {
        let opts = TriggerOptions::INTEGRITY | TriggerOptions::GI;
        let wire = opts.to_ber_bit_string();
        assert_eq!(wire, [0x02, 0x0c], "integrity with GI must encode as 0x0c");
        let decoded =
            TriggerOptions::from_ber_bit_string(&[0x02, 0x0c]).expect("decode should succeed");
        assert_eq!(decoded, opts);
    }

    // ── Option fields ───────────────────────────────────────────────────
    // The round-trip and golden-vector tests for OptFlds live with the type in
    // the model crate and are not repeated here.
    //
    // The two tests below are the exception: they pin the wire position of the
    // segmentation flag, whose internal value is zero-based bit 8 (0x100) while
    // the standard numbers it one-based bit 9, landing on bit 6 of the second
    // data byte of a BIT_STRING(10). The conversion between the two numbering
    // bases appears in several places, so a new option field added against the
    // wrong base becomes a wire defect directly; pinning the bytes here breaks
    // any such change.

    /// Segmentation must serialize to bit 6 of the second data byte (mask
    /// 0x40) and must not drift into the first byte or another bit.
    ///
    /// One-based wire bit 9 of IEC 61850-8-1 is bit 6 of data byte 1 counting
    /// from the most significant bit, so the whole content is
    /// `[padding = 6, 0x00, 0x40]`.
    #[test]
    fn optflds_segmentation_serializes_to_wire_byte1_bit6() {
        let opts = OptFlds::SEGMENTATION;
        let wire = opts.to_ber_bit_string();

        // Ten bits fill two data bytes, leaving six unused.
        assert_eq!(wire[0], 0x06, "a BIT_STRING(10) has six unused bits");

        // The first data byte holds the sequence-number through entry-id flags
        // and must stay clear.
        assert_eq!(
            wire[1], 0x00,
            "segmentation must not reach the first data byte"
        );

        assert_eq!(
            wire[2] & 0x40,
            0x40,
            "segmentation is bit 6 of the second data byte"
        );
        assert_eq!(
            wire[2] & !0x40,
            0x00,
            "no other bit of the second data byte may be set"
        );

        // Any drift in the numbering base breaks this byte-exact comparison.
        assert_eq!(
            wire,
            [0x06, 0x00, 0x40],
            "segmentation alone must encode as [6, 0x00, 0x40]"
        );
    }

    /// Encoding, decoding, and encoding again must be byte-exact, so that a
    /// numbering drift shared by both directions cannot pass unnoticed.
    #[test]
    fn optflds_segmentation_round_trips_via_ber_decode() {
        let orig = OptFlds::SEGMENTATION;
        let wire1 = orig.to_ber_bit_string();
        let decoded =
            OptFlds::from_ber_bit_string(&wire1).expect("segmentation content must decode");
        assert_eq!(
            decoded, orig,
            "decoding must yield segmentation and no other flag"
        );

        // An encoder and a decoder that drift together would pass a one-way
        // round trip while still producing the wrong bytes; this assertion and
        // the byte-exact test above together rule that out.
        let wire2 = decoded.to_ber_bit_string();
        assert_eq!(
            wire1, wire2,
            "re-encoding a decoded value must reproduce the same bytes"
        );
        assert_eq!(
            wire2,
            [0x06, 0x00, 0x40],
            "the re-encoded bytes must still be [6, 0x00, 0x40]"
        );
    }

    // ── InclusionFlag ─────────────────────────────────────────────────────────

    #[test]
    fn inclusion_flag_bit_values_match_documented_layout() {
        assert_eq!(InclusionFlag::NONE.0, 0);
        assert_eq!(InclusionFlag::VALUE_UPDATE.0, 1);
        assert_eq!(InclusionFlag::VALUE_CHANGED.0, 2);
        assert_eq!(InclusionFlag::QUALITY_CHANGED.0, 4);
        assert_eq!(InclusionFlag::NOT_UPDATED.0, 8);
    }

    #[test]
    fn inclusion_flag_has_trigger() {
        assert!(!InclusionFlag::NONE.has_trigger());
        assert!(InclusionFlag::VALUE_CHANGED.has_trigger());
        assert!(InclusionFlag::VALUE_UPDATE.has_trigger());
        assert!(InclusionFlag::QUALITY_CHANGED.has_trigger());
        // A deferred copy is not a reason for inclusion.
        assert!(!InclusionFlag::NOT_UPDATED.has_trigger());
    }

    #[test]
    fn reason_bit_string_data_change() {
        let flag = InclusionFlag::VALUE_CHANGED;
        let [pad, data] = flag.to_reason_bit_string(false, false);
        assert_eq!(pad, 2, "a BIT_STRING(6) has two unused bits");
        // Data-change is wire bit 1, which is mask 0x40.
        assert_eq!(data, 0x40);
    }

    #[test]
    fn reason_bit_string_integrity() {
        let flag = InclusionFlag::NONE;
        let [_pad, data] = flag.to_reason_bit_string(true, false);
        // integrity → bit 4 → byte bit 3 → 0x08
        assert_eq!(data, 0x08);
    }

    #[test]
    fn reason_bit_string_gi() {
        let flag = InclusionFlag::NONE;
        let [_pad, data] = flag.to_reason_bit_string(false, true);
        // GI → bit 5 → byte bit 2 → 0x04
        assert_eq!(data, 0x04);
    }
}
