//! Report parser: turns the `listOfAccessResult` of an InformationReport into
//! a `ParsedReport`.
//!
//! Pure: no state is mutated and no callback is invoked, which `state.rs` and
//! `dispatch.rs` do instead.
//!
//! The input is the decoded access result list as an `MmsValue::Array` or
//! `MmsValue::Structure`, whose elements are consumed in order. Every optional
//! field comes back owned, so the caller need not keep the source value alive.

use bitflags::bitflags;
use iec61850_mms::epoch_ms_from_binary_time6;
use iec61850_model::value::MmsValue;
use thiserror::Error;

use crate::prelude::{String, Vec};

// OptFlds, decoded on the client side.

bitflags! {
    /// Optional fields present in a report, a 10-bit BIT STRING on the wire.
    ///
    /// Wire bit 0 is reserved, so semantic bit n is wire bit n + 1:
    ///
    /// - wire bit 1: SEQUENCE_NUMBER
    /// - wire bit 2: REPORT_TIMESTAMP
    /// - wire bit 3: REASON_FOR_INCLUSION
    /// - wire bit 4: DATA_SET_NAME
    /// - wire bit 5: DATA_REFERENCE
    /// - wire bit 6: BUFFER_OVERFLOW (buffered RCBs only)
    /// - wire bit 7: ENTRY_ID (buffered RCBs only)
    /// - wire bit 8: CONF_REV
    /// - wire bit 9: SEGMENTATION
    #[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
    pub struct ReportOptFlds: u16 {
        /// The report carries a sequence number.
        const SEQUENCE_NUMBER     = 0x001;
        /// The report carries a timestamp.
        const REPORT_TIMESTAMP    = 0x002;
        /// The report carries a reason for each included member.
        const REASON_FOR_INCLUSION = 0x004;
        /// The report carries the name of the data set.
        const DATA_SET_NAME       = 0x008;
        /// The report carries the object reference of each included member.
        const DATA_REFERENCE      = 0x010;
        /// The report carries the buffer overflow flag; buffered RCBs only.
        const BUFFER_OVERFLOW     = 0x020;
        /// The report carries an entry id; buffered RCBs only.
        const ENTRY_ID            = 0x040;
        /// The report carries the configuration revision.
        const CONF_REV            = 0x080;
        /// The report carries a segmentation header.
        const SEGMENTATION        = 0x100;
    }
}

impl ReportOptFlds {
    /// Decodes OptFlds from the data bytes of a BIT STRING(10).
    ///
    /// One byte is enough; a missing second byte reads as zero.
    pub(crate) fn from_bit_string(data: &[u8]) -> Self {
        let byte0 = data.first().copied().unwrap_or(0) as u16;
        let byte1 = data.get(1).copied().unwrap_or(0) as u16;
        // Wire 0x40 of byte 0 is SEQUENCE_NUMBER, and so on down the byte.
        let v = ((byte0 & 0x40) >> 6)
            | ((byte0 & 0x20) >> 4)
            | ((byte0 & 0x10) >> 2)
            | (byte0 & 0x08)
            | ((byte0 & 0x04) << 2)
            | ((byte0 & 0x02) << 4)
            | ((byte0 & 0x01) << 6)
            | (byte1 & 0x80)
            | ((byte1 & 0x40) << 2);
        ReportOptFlds::from_bits_truncate(v)
    }
}

// ReasonForInclusion.

bitflags! {
    /// Why one data set member was included in a report, as defined in
    /// IEC 61850-7-2.
    ///
    /// A BIT STRING(6) on the wire, with the same reserved bit 0 as OptFlds.
    /// For member `i`, `reasons[i].contains(DATA_CHANGE)` answers whether that
    /// member was included because its value changed.
    #[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
    pub struct ReasonForInclusion: u8 {
        /// The value changed.
        const DATA_CHANGE     = 0b0000_0001;
        /// The quality changed.
        const QUALITY_CHANGE  = 0b0000_0010;
        /// The value was updated without changing.
        const DATA_UPDATE     = 0b0000_0100;
        /// The integrity period elapsed.
        const INTEGRITY       = 0b0000_1000;
        /// A general interrogation was requested.
        const GI              = 0b0001_0000;
    }
}

impl ReasonForInclusion {
    /// Decodes the reasons from the single data byte of a BIT STRING(6).
    ///
    /// The caller has already split off the padding count.
    pub(crate) fn from_reason_byte(byte: u8) -> Self {
        let mut v = ReasonForInclusion::empty();
        if byte & 0x40 != 0 {
            v |= ReasonForInclusion::DATA_CHANGE;
        }
        if byte & 0x20 != 0 {
            v |= ReasonForInclusion::QUALITY_CHANGE;
        }
        if byte & 0x10 != 0 {
            v |= ReasonForInclusion::DATA_UPDATE;
        }
        if byte & 0x08 != 0 {
            v |= ReasonForInclusion::INTEGRITY;
        }
        if byte & 0x04 != 0 {
            v |= ReasonForInclusion::GI;
        }
        v
    }
}

// ParsedReport: the owned output of the parser.

/// One decoded InformationReport.
///
/// Borrows nothing from the source value, so it can be held across a lock or
/// an await point.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedReport {
    /// RptId, always present; the key a handler is matched on.
    pub rpt_id: String,

    /// OptFlds, always present; decides which of the fields below are set.
    pub opt_flds: ReportOptFlds,

    /// Present with OptFlds SEQUENCE_NUMBER.
    pub seq_num: Option<u16>,

    /// Present with OptFlds REPORT_TIMESTAMP, in milliseconds since the epoch.
    pub timestamp_ms: Option<u64>,

    /// Present with OptFlds DATA_SET_NAME.
    pub data_set_name: Option<String>,

    /// Present with OptFlds BUFFER_OVERFLOW; buffered RCBs only.
    pub buf_ovfl: Option<bool>,

    /// Present with OptFlds ENTRY_ID; buffered RCBs only.
    pub entry_id: Option<Vec<u8>>,

    /// Present with OptFlds CONF_REV.
    pub conf_rev: Option<u32>,

    /// Present with OptFlds SEGMENTATION.
    pub segmentation: Option<Segmentation>,

    /// Always present; one bit per data set member.
    pub inclusion_bits: Vec<bool>,

    /// Present with OptFlds DATA_REFERENCE, in the order of the included
    /// members.
    pub data_references: Vec<String>,

    /// Always present: the values of the included members, in the order of the
    /// set bits in `inclusion_bits`.
    pub data_values: Vec<MmsValue>,

    /// Present with OptFlds REASON_FOR_INCLUSION; one entry per included
    /// member.
    pub reasons: Vec<ReasonForInclusion>,
}

/// Segmentation header of a report that is split across several PDUs.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Segmentation {
    /// Position of this PDU in the report, counted from zero.
    pub sub_seq_num: u16,
    /// Whether a further PDU of the same report follows this one.
    pub more_segments_follow: bool,
}

// Parse errors.

/// Failure reported by `parse_report`.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReportParseError {
    /// The value is neither an `MmsValue::Array` nor a `Structure`.
    #[error(
        "expected MmsValue::Array/Structure for InformationReport listOfAccessResult, got {0}"
    )]
    NotAnArray(&'static str),

    /// The PDU ends before a field the OptFlds announced.
    #[error("missing slot at index {idx}: expected {expected}")]
    MissingSlot {
        /// Index of the element the parser expected.
        idx: usize,
        /// Name of the field that should have been there.
        expected: &'static str,
    },

    /// A field has a type the report format does not allow.
    #[error("type mismatch at field {field}: expected {expected}, got {got}")]
    TypeMismatch {
        /// Name of the field that carried the wrong type.
        field: &'static str,
        /// Name of the type the field requires.
        expected: &'static str,
        /// Name of the type that was received.
        got: &'static str,
    },

    /// The segmentation header is missing or malformed; such a report is
    /// rejected rather than partially accepted.
    #[error("malformed segmentation header: {0}")]
    MalformedSegmentation(&'static str),

    /// A BINARY TIME is neither 4 nor 6 bytes long.
    #[error("invalid BinaryTime length {got} bytes (expected 4 or 6)")]
    InvalidBinaryTimeLen {
        /// Length that was received, in bytes.
        got: usize,
    },

    /// Any other wire-level defect.
    #[error("malformed report: {0}")]
    Malformed(&'static str),
}

// Parser.

/// Parses the `listOfAccessResult` of a report. Pure, with no side effects.
///
/// Fields appear in this order, the optional ones only when the corresponding
/// OptFlds bit is set:
///
/// 1. RptId (VISIBLE STRING), always
/// 2. OptFlds (BIT STRING), always
/// 3. SeqNum, 4. Timestamp, 5. DataSet, 6. BufOvfl, 7. EntryId, 8. ConfRev
/// 9. SubSeqNum and MoreSegmentsFollow
/// 10. Inclusion (BIT STRING), always
/// 11. DataReference, one per included member
/// 12. DataValue, one per included member, always
/// 13. Reason, one per included member
///
/// # Errors
///
/// `NotAnArray`, `MissingSlot`, `TypeMismatch`, `MalformedSegmentation` or
/// `InvalidBinaryTimeLen`, according to which expectation the PDU breaks.
pub fn parse_report(value: &MmsValue) -> Result<ParsedReport, ReportParseError> {
    let elements: &[MmsValue] = match value {
        MmsValue::Array(v) | MmsValue::Structure(v) => v,
        other => return Err(ReportParseError::NotAnArray(other.type_name())),
    };

    let mut idx = 0usize;

    // RptId
    let rpt_id = take_visible_string(elements, &mut idx, "RptId")?;

    // OptFlds
    let opt_flds = take_opt_flds(elements, &mut idx)?;

    // SeqNum
    let seq_num = if opt_flds.contains(ReportOptFlds::SEQUENCE_NUMBER) {
        Some(take_unsigned(elements, &mut idx, "SeqNum")? as u16)
    } else {
        None
    };

    // Timestamp
    let timestamp_ms = if opt_flds.contains(ReportOptFlds::REPORT_TIMESTAMP) {
        Some(take_binary_time_ms(elements, &mut idx)?)
    } else {
        None
    };

    // DataSet name
    let data_set_name = if opt_flds.contains(ReportOptFlds::DATA_SET_NAME) {
        Some(take_visible_string(elements, &mut idx, "DataSetName")?)
    } else {
        None
    };

    // BufOvfl (buffered RCBs only)
    let buf_ovfl = if opt_flds.contains(ReportOptFlds::BUFFER_OVERFLOW) {
        Some(take_boolean(elements, &mut idx, "BufOvfl")?)
    } else {
        None
    };

    // EntryId (buffered RCBs only)
    let entry_id = if opt_flds.contains(ReportOptFlds::ENTRY_ID) {
        Some(take_octet_string(elements, &mut idx, "EntryId")?)
    } else {
        None
    };

    // ConfRev
    let conf_rev = if opt_flds.contains(ReportOptFlds::CONF_REV) {
        Some(take_unsigned(elements, &mut idx, "ConfRev")? as u32)
    } else {
        None
    };

    // Segmentation
    //
    // The SeqNum slot is consumed strictly according to OptFlds, above; a
    // segmented report does not imply that a sequence number is present.
    let segmentation = if opt_flds.contains(ReportOptFlds::SEGMENTATION) {
        let sub_seq_num = take_unsigned(elements, &mut idx, "SubSeqNum").map_err(|_| {
            ReportParseError::MalformedSegmentation("SubSeqNum missing or wrong type")
        })? as u16;
        // A malformed MoreSegmentsFollow is an error, never a default.
        let more_segments_follow =
            take_boolean(elements, &mut idx, "MoreSegmentsFollow").map_err(|_| {
                ReportParseError::MalformedSegmentation("MoreSegmentsFollow missing or wrong type")
            })?;
        Some(Segmentation {
            sub_seq_num,
            more_segments_follow,
        })
    } else {
        None
    };

    // Inclusion BIT_STRING
    let inclusion_bits = take_inclusion(elements, &mut idx)?;
    let included_count = inclusion_bits.iter().filter(|b| **b).count();

    // DataReference[]
    let data_references = if opt_flds.contains(ReportOptFlds::DATA_REFERENCE) {
        let mut refs = Vec::with_capacity(included_count);
        for _ in 0..included_count {
            refs.push(take_visible_string(elements, &mut idx, "DataReference")?);
        }
        refs
    } else {
        Vec::new()
    };

    // DataValue[]
    let mut data_values: Vec<MmsValue> = Vec::with_capacity(included_count);
    for i in 0..included_count {
        let v = elements
            .get(idx)
            .ok_or(ReportParseError::MissingSlot {
                idx,
                expected: "DataValue",
            })?
            .clone();
        idx += 1;
        // Member types are defined by the data set, not by the report, so the
        // value is passed through as it is; the caller resolves it against the
        // data set directory.
        let _ = i;
        data_values.push(v);
    }

    // ReasonForInclusion[]
    let reasons = if opt_flds.contains(ReportOptFlds::REASON_FOR_INCLUSION) {
        let mut rs = Vec::with_capacity(included_count);
        for _ in 0..included_count {
            rs.push(take_reason(elements, &mut idx)?);
        }
        rs
    } else {
        Vec::new()
    };

    Ok(ParsedReport {
        rpt_id,
        opt_flds,
        seq_num,
        timestamp_ms,
        data_set_name,
        buf_ovfl,
        entry_id,
        conf_rev,
        segmentation,
        inclusion_bits,
        data_references,
        data_values,
        reasons,
    })
}

// Element accessors: narrow the type and advance the index.

fn take<'a>(
    elements: &'a [MmsValue],
    idx: &mut usize,
    expected: &'static str,
) -> Result<&'a MmsValue, ReportParseError> {
    let v = elements.get(*idx).ok_or(ReportParseError::MissingSlot {
        idx: *idx,
        expected,
    })?;
    *idx += 1;
    Ok(v)
}

fn take_visible_string(
    elements: &[MmsValue],
    idx: &mut usize,
    field: &'static str,
) -> Result<String, ReportParseError> {
    match take(elements, idx, field)? {
        MmsValue::VisibleString(s) | MmsValue::MmsString(s) => Ok(s.clone()),
        other => Err(ReportParseError::TypeMismatch {
            field,
            expected: "VisibleString",
            got: other.type_name(),
        }),
    }
}

fn take_unsigned(
    elements: &[MmsValue],
    idx: &mut usize,
    field: &'static str,
) -> Result<u64, ReportParseError> {
    match take(elements, idx, field)? {
        MmsValue::Unsigned(u) => Ok(*u),
        // Only UNSIGNED is accepted here; no widening from INTEGER.
        other => Err(ReportParseError::TypeMismatch {
            field,
            expected: "Unsigned",
            got: other.type_name(),
        }),
    }
}

fn take_boolean(
    elements: &[MmsValue],
    idx: &mut usize,
    field: &'static str,
) -> Result<bool, ReportParseError> {
    match take(elements, idx, field)? {
        MmsValue::Boolean(b) => Ok(*b),
        other => Err(ReportParseError::TypeMismatch {
            field,
            expected: "Boolean",
            got: other.type_name(),
        }),
    }
}

fn take_octet_string(
    elements: &[MmsValue],
    idx: &mut usize,
    field: &'static str,
) -> Result<Vec<u8>, ReportParseError> {
    match take(elements, idx, field)? {
        MmsValue::OctetString(v) => Ok(v.clone()),
        other => Err(ReportParseError::TypeMismatch {
            field,
            expected: "OctetString",
            got: other.type_name(),
        }),
    }
}

fn take_opt_flds(
    elements: &[MmsValue],
    idx: &mut usize,
) -> Result<ReportOptFlds, ReportParseError> {
    match take(elements, idx, "OptFlds")? {
        MmsValue::BitString { data, .. } => Ok(ReportOptFlds::from_bit_string(data)),
        other => Err(ReportParseError::TypeMismatch {
            field: "OptFlds",
            expected: "BitString",
            got: other.type_name(),
        }),
    }
}

fn take_inclusion(elements: &[MmsValue], idx: &mut usize) -> Result<Vec<bool>, ReportParseError> {
    match take(elements, idx, "Inclusion")? {
        MmsValue::BitString { padding, data } => {
            // The padding counts the unused bits of the last byte.
            let total_bits = data
                .len()
                .saturating_mul(8)
                .saturating_sub(*padding as usize);
            let mut bits = Vec::with_capacity(total_bits);
            // Bit 0 is the most significant bit of byte 0, and bit n selects
            // data set member n.
            for i in 0..total_bits {
                let byte = data[i / 8];
                let bit = (byte >> (7 - (i % 8))) & 0x01;
                bits.push(bit == 1);
            }
            Ok(bits)
        }
        other => Err(ReportParseError::TypeMismatch {
            field: "Inclusion",
            expected: "BitString",
            got: other.type_name(),
        }),
    }
}

fn take_reason(
    elements: &[MmsValue],
    idx: &mut usize,
) -> Result<ReasonForInclusion, ReportParseError> {
    match take(elements, idx, "Reason")? {
        MmsValue::BitString { data, .. } => {
            let byte = data.first().copied().unwrap_or(0);
            Ok(ReasonForInclusion::from_reason_byte(byte))
        }
        other => Err(ReportParseError::TypeMismatch {
            field: "Reason",
            expected: "BitString",
            got: other.type_name(),
        }),
    }
}

/// Converts a BINARY TIME into milliseconds since the UNIX epoch.
///
/// The 6-byte form holds milliseconds since midnight in bytes 0 to 3 and days
/// since 1984-01-01 in bytes 4 and 5; the 4-byte form carries only the
/// milliseconds and no date. The conversion to the 1984 epoch is shared with the
/// encoders through `iec61850_mms::epoch_ms_from_binary_time6`.
fn take_binary_time_ms(elements: &[MmsValue], idx: &mut usize) -> Result<u64, ReportParseError> {
    let v = take(elements, idx, "Timestamp")?;
    let buf = match v {
        MmsValue::BinaryTime(b) => b,
        // A report timestamp is a BINARY TIME; a UTC TIME does not belong here.
        other => {
            return Err(ReportParseError::TypeMismatch {
                field: "Timestamp",
                expected: "BinaryTime",
                got: other.type_name(),
            });
        }
    };
    binary_time_buf_to_utc_ms(buf)
}

pub(crate) fn binary_time_buf_to_utc_ms(buf: &[u8]) -> Result<u64, ReportParseError> {
    match buf.len() {
        4 => {
            let ms_since_midnight = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64;
            Ok(ms_since_midnight)
        }
        6 => Ok(epoch_ms_from_binary_time6([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5],
        ])),
        n => Err(ReportParseError::InvalidBinaryTimeLen { got: n }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vis(s: &str) -> MmsValue {
        MmsValue::VisibleString(s.to_string())
    }

    fn unsigned(u: u64) -> MmsValue {
        MmsValue::Unsigned(u)
    }

    fn bool_v(b: bool) -> MmsValue {
        MmsValue::Boolean(b)
    }

    /// Encodes an OptFlds mask into the wire bytes of a BIT STRING(10).
    fn opt_flds_bs(mask: u16) -> MmsValue {
        let byte0: u8 = (((mask & 0x001) << 6)
            | ((mask & 0x002) << 4)
            | ((mask & 0x004) << 2)
            | (mask & 0x008)
            | ((mask & 0x010) >> 2)
            | ((mask & 0x020) >> 4)
            | ((mask & 0x040) >> 6)) as u8;
        let byte1: u8 = ((mask & 0x080) | ((mask & 0x100) >> 2)) as u8;
        MmsValue::BitString {
            padding: 6,
            data: vec![byte0, byte1],
        }
    }

    /// Encodes inclusion bits, bit 0 being the most significant bit of byte 0.
    fn inclusion_bs(bits: &[bool]) -> MmsValue {
        let n = bits.len();
        let bytes_needed = n.div_ceil(8);
        let mut data = vec![0u8; bytes_needed];
        for (i, &b) in bits.iter().enumerate() {
            if b {
                data[i / 8] |= 1 << (7 - (i % 8));
            }
        }
        let padding = (bytes_needed * 8 - n) as u8;
        MmsValue::BitString { padding, data }
    }

    /// Encodes a reason mask into the wire byte of a BIT STRING(6).
    fn reason_bs(mask: u8) -> MmsValue {
        let byte = ((mask & 0x01) << 6)
            | ((mask & 0x02) << 4)
            | ((mask & 0x04) << 2)
            | (mask & 0x08)
            | ((mask & 0x10) >> 2);
        MmsValue::BitString {
            padding: 2,
            data: vec![byte],
        }
    }

    // ReportOptFlds bit decode

    #[test]
    fn opt_flds_decode_seq_num_only() {
        if let MmsValue::BitString { data, .. } = opt_flds_bs(0x001) {
            assert_eq!(
                ReportOptFlds::from_bit_string(&data),
                ReportOptFlds::SEQUENCE_NUMBER
            );
        } else {
            panic!("opt_flds_bs not BitString");
        }
    }

    #[test]
    fn opt_flds_decode_wire_golden() {
        // Wire bytes [0x78, 0x80] carry SEQ_NUM, TIMESTAMP, REASON, DATA_SET
        // and CONF_REV.
        let v = ReportOptFlds::from_bit_string(&[0x78, 0x80]);
        let expected = ReportOptFlds::SEQUENCE_NUMBER
            | ReportOptFlds::REPORT_TIMESTAMP
            | ReportOptFlds::REASON_FOR_INCLUSION
            | ReportOptFlds::DATA_SET_NAME
            | ReportOptFlds::CONF_REV;
        assert_eq!(v, expected);
    }

    #[test]
    fn opt_flds_decode_segmentation() {
        // SEGMENTATION is bit 6 of byte 1, that is 0x40.
        let v = ReportOptFlds::from_bit_string(&[0x00, 0x40]);
        assert_eq!(v, ReportOptFlds::SEGMENTATION);
    }

    // reason decode

    #[test]
    fn reason_decode_data_change_only() {
        // wire byte 0x40 → bit 1 → DATA_CHANGE
        let r = ReasonForInclusion::from_reason_byte(0x40);
        assert_eq!(r, ReasonForInclusion::DATA_CHANGE);
    }

    #[test]
    fn reason_decode_gi_plus_integrity() {
        // wire byte 0x0c = 0x08 (INTEGRITY) | 0x04 (GI)
        let r = ReasonForInclusion::from_reason_byte(0x0c);
        assert_eq!(r, ReasonForInclusion::INTEGRITY | ReasonForInclusion::GI);
    }

    // BINARY TIME conversion.

    #[test]
    fn binary_time_4byte_only_ms_since_midnight() {
        // ms = 1000
        let buf = [0u8, 0, 0x03, 0xe8];
        assert_eq!(binary_time_buf_to_utc_ms(&buf).unwrap(), 1000);
    }

    #[test]
    fn binary_time_6byte_at_1984_epoch() {
        // ms=0, days=0 → 441763200000 (1984-01-01)
        let buf = [0u8; 6];
        assert_eq!(binary_time_buf_to_utc_ms(&buf).unwrap(), 441_763_200_000u64);
    }

    #[test]
    fn binary_time_6byte_one_day_later() {
        // ms=0, days=1 → 1984-01-02
        let buf = [0u8, 0, 0, 0, 0, 1];
        assert_eq!(
            binary_time_buf_to_utc_ms(&buf).unwrap(),
            441_763_200_000u64 + 86_400_000u64
        );
    }

    #[test]
    fn binary_time_invalid_len() {
        assert!(matches!(
            binary_time_buf_to_utc_ms(&[0u8; 5]),
            Err(ReportParseError::InvalidBinaryTimeLen { got: 5 })
        ));
    }

    // parse_report.

    #[test]
    fn parse_minimal_report_no_opt_flds() {
        // RptId + OptFlds(none) + inclusion(2 bits, 1=true 0=false) + 1 data value
        let elements = vec![
            vis("simpleIOGenericIO/LLN0$RP$EventsRCB01"),
            opt_flds_bs(0),
            inclusion_bs(&[true, false]),
            unsigned(42),
        ];
        let p = parse_report(&MmsValue::Array(elements)).expect("parse should succeed");
        assert_eq!(p.rpt_id, "simpleIOGenericIO/LLN0$RP$EventsRCB01");
        assert!(p.opt_flds.is_empty());
        assert_eq!(p.seq_num, None);
        assert_eq!(p.timestamp_ms, None);
        assert_eq!(p.inclusion_bits, vec![true, false]);
        assert_eq!(p.data_values.len(), 1);
        assert_eq!(p.data_values[0], MmsValue::Unsigned(42));
        assert!(p.reasons.is_empty());
    }

    #[test]
    fn parse_report_with_seq_num_and_timestamp() {
        let opt_mask = ReportOptFlds::SEQUENCE_NUMBER | ReportOptFlds::REPORT_TIMESTAMP;
        let elements = vec![
            vis("rpt"),
            opt_flds_bs(opt_mask.bits()),
            unsigned(7),                                          // SeqNum
            MmsValue::BinaryTime(vec![0u8, 0, 0x03, 0xe8, 0, 1]), // 1984-01-02 + 1s
            inclusion_bs(&[true]),
            unsigned(99),
        ];
        let p = parse_report(&MmsValue::Array(elements)).expect("parse should succeed");
        assert_eq!(p.seq_num, Some(7));
        assert_eq!(
            p.timestamp_ms,
            Some(441_763_200_000u64 + 86_400_000u64 + 1000)
        );
    }

    #[test]
    fn parse_report_full_opt_flds_urcb_subset() {
        // A URCB general interrogation report.
        let opt_mask = ReportOptFlds::SEQUENCE_NUMBER
            | ReportOptFlds::REPORT_TIMESTAMP
            | ReportOptFlds::REASON_FOR_INCLUSION
            | ReportOptFlds::DATA_SET_NAME
            | ReportOptFlds::DATA_REFERENCE
            | ReportOptFlds::CONF_REV;
        let elements = vec![
            vis("simpleIOGenericIO/LLN0$RP$EventsRCB01"),
            opt_flds_bs(opt_mask.bits()),
            unsigned(0),                                       // SeqNum
            MmsValue::BinaryTime(vec![0u8; 6]),                // ts 1984-epoch
            vis("EventsDataset"),                              // DataSet
            unsigned(1),                                       // ConfRev
            inclusion_bs(&[true, true]),                       // 2 included
            vis("ref1"),                                       // DataRef[0]
            vis("ref2"),                                       // DataRef[1]
            MmsValue::Integer(10),                             // DataValue[0]
            MmsValue::Integer(20),                             // DataValue[1]
            reason_bs(ReasonForInclusion::GI.bits()),          // Reason[0] = GI
            reason_bs(ReasonForInclusion::DATA_CHANGE.bits()), // Reason[1] = DATA_CHANGE
        ];
        let p = parse_report(&MmsValue::Array(elements)).expect("parse should succeed");
        assert_eq!(p.rpt_id, "simpleIOGenericIO/LLN0$RP$EventsRCB01");
        assert_eq!(p.seq_num, Some(0));
        assert_eq!(p.timestamp_ms, Some(441_763_200_000u64));
        assert_eq!(p.data_set_name.as_deref(), Some("EventsDataset"));
        assert_eq!(p.conf_rev, Some(1));
        assert_eq!(p.inclusion_bits, vec![true, true]);
        assert_eq!(
            p.data_references,
            vec!["ref1".to_string(), "ref2".to_string()]
        );
        assert_eq!(p.data_values.len(), 2);
        assert_eq!(
            p.reasons,
            vec![ReasonForInclusion::GI, ReasonForInclusion::DATA_CHANGE]
        );
    }

    #[test]
    fn parse_report_with_segmentation() {
        let opt_mask = ReportOptFlds::SEGMENTATION;
        let elements = vec![
            vis("rpt"),
            opt_flds_bs(opt_mask.bits()),
            unsigned(2),  // SubSeqNum
            bool_v(true), // MoreSegmentsFollow
            inclusion_bs(&[true]),
            MmsValue::Integer(7),
        ];
        let p = parse_report(&MmsValue::Array(elements)).expect("parse should succeed");
        let seg = p.segmentation.expect("segmentation should be Some");
        assert_eq!(seg.sub_seq_num, 2);
        assert!(seg.more_segments_follow);
        // Segmentation alone does not imply a sequence number.
        assert_eq!(p.seq_num, None);
    }

    // Error paths.

    #[test]
    fn parse_report_not_an_array() {
        // A Boolean is not an access result list.
        let v = MmsValue::Boolean(true);
        assert!(matches!(
            parse_report(&v),
            Err(ReportParseError::NotAnArray("Boolean"))
        ));
    }

    #[test]
    fn parse_report_rpt_id_missing() {
        // An empty array is missing even RptId.
        let v = MmsValue::Array(vec![]);
        assert!(matches!(
            parse_report(&v),
            Err(ReportParseError::MissingSlot { idx: 0, .. })
        ));
    }

    #[test]
    fn parse_report_rpt_id_wrong_type() {
        let v = MmsValue::Array(vec![MmsValue::Integer(0)]);
        assert!(matches!(
            parse_report(&v),
            Err(ReportParseError::TypeMismatch {
                field: "RptId",
                expected: "VisibleString",
                ..
            })
        ));
    }

    #[test]
    fn parse_report_opt_flds_wrong_type() {
        let v = MmsValue::Array(vec![vis("x"), MmsValue::Integer(0)]);
        assert!(matches!(
            parse_report(&v),
            Err(ReportParseError::TypeMismatch {
                field: "OptFlds",
                ..
            })
        ));
    }

    /// A malformed MoreSegmentsFollow is rejected, not defaulted.
    #[test]
    fn parse_report_segmentation_malformed_more_follow() {
        let opt_mask = ReportOptFlds::SEGMENTATION;
        let elements = vec![
            vis("rpt"),
            opt_flds_bs(opt_mask.bits()),
            unsigned(0), // SubSeqNum
            // MoreSegmentsFollow must be a Boolean.
            MmsValue::Integer(1),
        ];
        let r = parse_report(&MmsValue::Array(elements));
        assert!(
            matches!(r, Err(ReportParseError::MalformedSegmentation(_))),
            "expected MalformedSegmentation, got {:?}",
            r
        );
    }

    #[test]
    fn parse_report_segmentation_subseq_missing() {
        let opt_mask = ReportOptFlds::SEGMENTATION;
        let elements = vec![
            vis("rpt"),
            opt_flds_bs(opt_mask.bits()),
            // SubSeqNum is missing.
        ];
        let r = parse_report(&MmsValue::Array(elements));
        assert!(matches!(r, Err(ReportParseError::MalformedSegmentation(_))));
    }

    /// A truncated value list is reported rather than silently accepted.
    #[test]
    fn parse_report_data_value_count_short() {
        // Two members are marked included but only one value follows.
        let elements = vec![
            vis("rpt"),
            opt_flds_bs(0),
            inclusion_bs(&[true, true]),
            MmsValue::Integer(1),
            // The second value is missing.
        ];
        let r = parse_report(&MmsValue::Array(elements));
        assert!(matches!(r, Err(ReportParseError::MissingSlot { .. })));
    }
}
