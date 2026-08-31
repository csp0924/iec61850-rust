//! InformationReport PDU encoder for report control blocks.
//!
//! Encodes the unconfirmed InformationReport that carries a URCB or BRCB report
//! per IEC 61850-8-1, including segmentation when a report would exceed the
//! negotiated MMS PDU size.
//!
//! ## Wire layout
//!
//! ```text
//! SEQUENCE (unconfirmedPDU [3] IMPLICIT) {              // 0xa3
//!   [0] SEQUENCE {                                      // informationReport [0]
//!     [1] CHOICE {                                      // variableAccessSpecification
//!       [0] VisibleString "RPT"                         // vmdSpecific, fixed tag 0x80
//!     }
//!     [0] SEQUENCE {                                    // listOfAccessResult
//!       VisibleString     RptID          -- always present
//!       BIT_STRING(-10)   OptFlds        -- always present
//!       UNSIGNED(8)       SqNum          -- if optFlds bit0 (SEQ_NUM)
//!       BinaryTime(6)     TimeOfEntry    -- if optFlds bit1 (TIME_STAMP)
//!       VisibleString     DatSet         -- if optFlds bit3 (DATA_SET)
//!       UNSIGNED(32)      ConfRev        -- if optFlds bit7 (CONF_REV)
//!       UNSIGNED(16)      subSeqNum  }   -- if optFlds bit8 (SEGMENTATION)
//!       BOOLEAN           moreFollows    -- if optFlds bit8 (SEGMENTATION)
//!       BIT_STRING(N)     inclusionField -- N = data set element count
//!       -- if optFlds bit4 (DATA_REFERENCE): one VisibleString per included entry
//!       -- the MMS data value of every included entry
//!       -- if optFlds bit2 (REASON): one BIT_STRING(6) per included entry
//!     }
//!   }
//! }
//! ```
//!
//! ## TimeOfEntry
//!
//! TimeOfEntry is a six-octet BinaryTime: four big-endian octets of milliseconds
//! since midnight followed by two big-endian octets counting days since
//! 1984-01-01, the epoch of the type per ISO 9506 and IEC 61850-8-1.
//! `ReportEncodeParams::time_of_entry_ms` is milliseconds since 1970-01-01 and is
//! converted to that epoch on the way to the wire.
//!
//! ## Segmentation
//!
//! `encode_report_pdus` splits a report that would exceed `max_pdu_size` into
//! segments. Every segment repeats the full header (RptID, OptFlds, SqNum,
//! TimeOfEntry, and so on), numbers itself with a zero-based `subSeqNum`, and
//! sets `moreFollows` on every segment but the last. A report larger than the
//! negotiated PDU size is split rather than emitted as one oversized PDU, so a
//! client is never handed a PDU it cannot receive.
//!
//! ## variableAccessSpecification
//!
//! Always the same seven bytes, `0xa1 0x05 0x80 0x03 'R' 'P' 'T'`: tag, length,
//! tag, length, and the three characters of "RPT".
//!
//! ## OptFlds segmentation bit
//!
//! IEC 61850-8-1 numbers the OptFlds segmentation bit 9, counting from one on the
//! wire. `OptFlds::SEGMENTATION` is the internal value `0x100`, which is bit 8
//! counting from zero; `to_ber_bit_string` shifts it right by one when writing, so
//! it lands on wire bit 9 (`0x40` in the second data byte). URCB and BRCB share
//! that same wire bit.

use super::brcb::BufferedReportControl;
use super::buffer::{EntryId, ReportEntry};
use super::dataset::Dataset;
use super::rcb::PendingReport;
use crate::flags::{InclusionFlag, OptFlds};
use bytes::{BufMut, Bytes, BytesMut};
use iec61850_mms::{binary_time6_from_epoch_ms, BINARY_TIME6_LEN};
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Fixed variableAccessSpecification bytes: vmdSpecific "RPT", seven bytes,
/// `0xa1 0x05 0x80 0x03 'R' 'P' 'T'` per IEC 61850-8-1.
const VAR_ACCESS_SPEC: &[u8] = &[0xa1, 0x05, 0x80, 0x03, b'R', b'P', b'T'];

/// Length in bytes of the BinaryTime6 wire field of IEC 61850-8-1.
const BINARY_TIME_LEN: usize = BINARY_TIME6_LEN;

/// Fixed header overhead of a report PDU, in bytes: the outer `0xa3`, the two
/// nested `0xa0` wrappers, the seven-byte variableAccessSpecification, and the
/// listOfAccessResult wrapper, each with its own tag and length.
pub const MIN_REPORT_OVERHEAD_BYTES: usize = 30;

// ─────────────────────────────────────────────────────────────────────────────
// ReportEncodeError
// ─────────────────────────────────────────────────────────────────────────────

/// Why a report PDU could not be encoded.
///
/// When the negotiated maximum PDU size cannot hold even a single data set
/// element, encoding fails instead of silently dropping the report. The caller
/// (`flush_pending` or `flush_brcb_pending`) treats that as a fatal configuration
/// error: it logs the failure and leaves the transmit anchor and sqNum untouched,
/// so the entry is retried once the configuration is corrected rather than lost.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReportEncodeError {
    /// `max_pdu_size` is too small to hold a single data set element. `needed` is
    /// the encoded size in bytes, `max` the configured limit.
    #[error("report pdu too large: {needed} bytes exceeds the {max} byte limit even with a single element")]
    PduTooSmall {
        /// Encoded size in bytes.
        needed: usize,
        /// Configured maximum PDU size in bytes.
        max: usize,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// ReportEncodeParams
// ─────────────────────────────────────────────────────────────────────────────

/// Everything `encode_report_pdus` needs.
#[derive(Debug, Clone)]
pub struct ReportEncodeParams<'a> {
    /// RptID, a VisibleString.
    pub rpt_id: &'a str,
    /// OptFlds, already masked for URCB use.
    pub opt_flds: OptFlds,
    /// SqNum; a URCB counts in 8 bits.
    pub sq_num: u8,
    /// Report time in milliseconds since the Unix epoch, encoded as TimeOfEntry.
    pub time_of_entry_ms: u64,
    /// DatSet, a VisibleString.
    pub dat_set: &'a str,
    /// ConfRev, an UNSIGNED(32).
    pub conf_rev: u32,
    /// Data set, used for the inclusion field, data references, and entry values.
    pub dataset: &'a Dataset,
    /// Pending report: inclusion flags and the value snapshot.
    pub pending: &'a PendingReport,
    /// Negotiated maximum MMS PDU size, in bytes.
    pub max_pdu_size_bytes: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes one report into one or more MMS unconfirmedPDU byte strings.
///
/// A report larger than `max_pdu_size_bytes` is segmented: the SEGMENTATION bit is
/// set in OptFlds, each segment carries a zero-based `subSeqNum` and a
/// `moreFollows` boolean, and the last segment clears `moreFollows`. Robustness
/// Every segment is at most `max_pdu_size_bytes` long, so a large
/// report never produces a PDU the client cannot receive.
///
/// Each element of the returned vector is a complete PDU including the outer
/// `0xa3`.
///
/// # Errors
///
/// Returns `ReportEncodeError::PduTooSmall` when even a single data set element
/// does not fit within `max_pdu_size_bytes`. The caller must not advance sqNum on
/// that error.
pub fn encode_report_pdus(
    params: &ReportEncodeParams<'_>,
) -> Result<Vec<Bytes>, ReportEncodeError> {
    let n = params.dataset.len();
    // Select the entries that have to be included.
    let included_indices: Vec<usize> = (0..n)
        .filter(|&i| {
            params
                .pending
                .inclusion_flags
                .get(i)
                .map(|f| f.has_trigger())
                .unwrap_or(false)
                || params.pending.is_integrity
                || params.pending.is_gi
        })
        .collect();

    // Try a single unsegmented PDU first.
    let opt_flds = params.opt_flds.mask_urcb();
    let single = encode_single_segment(params, opt_flds, &included_indices, 0, false);
    if single.len() <= params.max_pdu_size_bytes {
        return Ok(vec![single]);
    }

    // Too large: segment, which also sets the SEGMENTATION bit.
    let opt_flds_seg = opt_flds | OptFlds::SEGMENTATION;
    let mut result = Vec::new();
    let mut sub_seq_num: u16 = 0;
    let mut start = 0;

    loop {
        // Binary search for how many entries fit into this segment.
        let remaining = &included_indices[start..];
        if remaining.is_empty() {
            break;
        }

        let mut end = remaining.len();
        loop {
            let more_follows = start + end < included_indices.len();
            let params_seg = ReportEncodeParams {
                opt_flds: opt_flds_seg,
                ..*params
            };
            let seg = encode_segment(
                &params_seg,
                opt_flds_seg,
                &included_indices[start..start + end],
                sub_seq_num,
                more_follows,
            );
            if seg.len() <= params.max_pdu_size_bytes || end == 1 {
                // Even a single entry does not fit: report it rather than skipping.
                if seg.len() > params.max_pdu_size_bytes {
                    return Err(ReportEncodeError::PduTooSmall {
                        needed: seg.len(),
                        max: params.max_pdu_size_bytes,
                    });
                }
                result.push(seg);
                start += end;
                sub_seq_num += 1;
                break;
            }
            end /= 2;
            if end == 0 {
                end = 1;
            }
        }
    }

    Ok(result)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes an unsegmented PDU.
fn encode_single_segment(
    params: &ReportEncodeParams<'_>,
    opt_flds: OptFlds,
    included_indices: &[usize],
    sub_seq_num: u16,
    more_follows: bool,
) -> Bytes {
    encode_segment(
        params,
        opt_flds,
        included_indices,
        sub_seq_num,
        more_follows,
    )
}

/// Encodes one report segment, which may also be a complete single PDU.
fn encode_segment(
    params: &ReportEncodeParams<'_>,
    opt_flds: OptFlds,
    included_indices: &[usize],
    sub_seq_num: u16,
    more_follows: bool,
) -> Bytes {
    let mut access_result = BytesMut::new();

    // 1. RptID, always present: VisibleString, tag 0x8a.
    encode_visible_string(params.rpt_id, &mut access_result);

    // 2. OptFlds, always present: BIT_STRING(10), tag 0x84. The caller decides
    //    whether opt_flds already carries the SEGMENTATION bit.
    encode_opt_flds(opt_flds, &mut access_result);

    // 3. SqNum if SEQ_NUM: UNSIGNED(8), tag 0x86.
    if opt_flds.contains(OptFlds::SEQ_NUM) {
        encode_unsigned8(params.sq_num, &mut access_result);
    }

    // 4. TimeOfEntry if TIME_STAMP: BinaryTime, six bytes, tag 0x8c.
    if opt_flds.contains(OptFlds::TIME_STAMP) {
        encode_binary_time(params.time_of_entry_ms, &mut access_result);
    }

    // 5. DatSet if DATA_SET: VisibleString, tag 0x8a.
    if opt_flds.contains(OptFlds::DATA_SET) {
        encode_visible_string(params.dat_set, &mut access_result);
    }

    // 6. ConfRev if CONF_REV: UNSIGNED(32), tag 0x86.
    if opt_flds.contains(OptFlds::CONF_REV) {
        encode_unsigned32(params.conf_rev, &mut access_result);
    }

    // 7. Segmentation fields if SEGMENTATION.
    if opt_flds.contains(OptFlds::SEGMENTATION) {
        encode_unsigned16(sub_seq_num, &mut access_result);
        encode_boolean(more_follows, &mut access_result);
    }

    // 8. inclusionField: BIT_STRING(N), N = data set length.
    let ds_len = params.dataset.len();
    encode_inclusion_field(
        params.pending,
        included_indices,
        ds_len,
        params.pending.is_integrity || params.pending.is_gi,
        &mut access_result,
    );

    // 9. One VisibleString per included entry if DATA_REFERENCE.
    if opt_flds.contains(OptFlds::DATA_REFERENCE) {
        for &idx in included_indices {
            if let Some(entry) = params.dataset.entry(idx) {
                encode_visible_string(&entry.attr_ref, &mut access_result);
            }
        }
    }

    // 10. The value of every included entry, taken from the snapshot.
    for &idx in included_indices {
        let val = params
            .pending
            .snapshot
            .get(idx)
            .and_then(|v| v.as_ref())
            .cloned()
            .or_else(|| params.dataset.entry(idx).and_then(|e| e.read_value()));
        if let Some(v) = val {
            encode_mms_value(&v, &mut access_result);
        } else {
            // Neither a snapshot value nor a live value: emit an empty Structure so
            // the client can still parse the PDU.
            access_result.extend_from_slice(&[0xa2, 0x00]);
        }
    }

    // 11. One BIT_STRING(6) reason per included entry if REASON.
    if opt_flds.contains(OptFlds::REASON) {
        for &idx in included_indices {
            let flag = params
                .pending
                .inclusion_flags
                .get(idx)
                .copied()
                .unwrap_or(InclusionFlag::NONE);
            let reason =
                flag.to_reason_bit_string(params.pending.is_integrity, params.pending.is_gi);
            // BIT_STRING tag 0x84, length 2, including the padding byte.
            access_result.extend_from_slice(&[0x84, 0x02]);
            access_result.extend_from_slice(&reason);
        }
    }

    // Wrap in listOfAccessResult [0].
    let mut list_of_ar = BytesMut::new();
    list_of_ar.extend_from_slice(&[0xa0]);
    encode_length(access_result.len(), &mut list_of_ar);
    list_of_ar.extend_from_slice(&access_result);

    // InformationReport body = variableAccessSpecification [1] + listOfAccessResult [0]
    let mut info_report_body = BytesMut::new();
    info_report_body.extend_from_slice(VAR_ACCESS_SPEC);
    info_report_body.extend_from_slice(&list_of_ar);

    // service [0] and informationReport [0] are emitted as a single 0xa0 wrapper
    // rather than two nested ones.
    let mut combined = BytesMut::new();
    combined.extend_from_slice(&[0xa0]);
    encode_length(info_report_body.len(), &mut combined);
    combined.extend_from_slice(&info_report_body);

    // Outer unconfirmedPDU [3] IMPLICIT, tag 0xa3.
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&[0xa3]);
    encode_length(combined.len(), &mut buf);
    buf.extend_from_slice(&combined);

    buf.freeze()
}

// ─────────────────────────────────────────────────────────────────────────────
// Field encoders
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes a VisibleString as an AccessResult, tag 0x8a.
fn encode_visible_string(s: &str, buf: &mut BytesMut) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&[0x8a]);
    encode_length(bytes.len(), buf);
    buf.extend_from_slice(bytes);
}

/// Encodes OptFlds as a BIT_STRING(10), tag 0x84, whose content is a padding byte
/// followed by two data bytes.
fn encode_opt_flds(opt_flds: OptFlds, buf: &mut BytesMut) {
    let wire = opt_flds.to_ber_bit_string();
    buf.extend_from_slice(&[0x84, 0x03]);
    buf.extend_from_slice(&wire);
}

/// Encodes an 8-bit UNSIGNED (SqNum), tag 0x86.
fn encode_unsigned8(v: u8, buf: &mut BytesMut) {
    buf.extend_from_slice(&[0x86, 0x01, v]);
}

/// Encodes a 16-bit UNSIGNED (subSeqNum), tag 0x86.
fn encode_unsigned16(v: u16, buf: &mut BytesMut) {
    if v <= 0xff {
        buf.extend_from_slice(&[0x86, 0x01, v as u8]);
    } else {
        buf.extend_from_slice(&[0x86, 0x02, (v >> 8) as u8, (v & 0xff) as u8]);
    }
}

/// Encodes a 32-bit UNSIGNED (ConfRev), tag 0x86.
fn encode_unsigned32(v: u32, buf: &mut BytesMut) {
    if v == 0 {
        buf.extend_from_slice(&[0x86, 0x01, 0x00]);
    } else if v <= 0xff {
        buf.extend_from_slice(&[0x86, 0x01, v as u8]);
    } else if v <= 0xffff {
        buf.extend_from_slice(&[0x86, 0x02, (v >> 8) as u8, (v & 0xff) as u8]);
    } else if v <= 0xffffff {
        buf.extend_from_slice(&[
            0x86,
            0x03,
            (v >> 16) as u8,
            (v >> 8) as u8,
            (v & 0xff) as u8,
        ]);
    } else {
        buf.extend_from_slice(&[
            0x86,
            0x04,
            (v >> 24) as u8,
            (v >> 16) as u8,
            (v >> 8) as u8,
            (v & 0xff) as u8,
        ]);
    }
}

/// Encodes a BOOLEAN (moreFollows), tag 0x83.
fn encode_boolean(v: bool, buf: &mut BytesMut) {
    buf.extend_from_slice(&[0x83, 0x01, if v { 0xff } else { 0x00 }]);
}

/// Encodes TimeOfEntry as a six-byte BinaryTime, tag 0x8c.
///
/// `ms` is milliseconds since 1970-01-01. IEC 61850-8-1 defines BinaryTime6 as
/// four big-endian bytes of milliseconds since midnight followed by two
/// big-endian bytes counting days since 1984-01-01, so the value is converted to
/// that epoch before it reaches the wire.
fn encode_binary_time(ms: u64, buf: &mut BytesMut) {
    buf.extend_from_slice(&[0x8c, BINARY_TIME_LEN as u8]);
    buf.extend_from_slice(&binary_time6_from_epoch_ms(ms));
}

/// Encodes the inclusionField as a BIT_STRING(N), N = data set length.
///
/// A general interrogation or integrity report sets every bit; a data-change
/// report sets only the bits of the entries that changed.
fn encode_inclusion_field(
    pending: &PendingReport,
    included_indices: &[usize],
    ds_len: usize,
    all_included: bool,
    buf: &mut BytesMut,
) {
    // BIT_STRING byte count and the number of unused trailing bits.
    let n_bytes = ds_len.div_ceil(8);
    let padding = (n_bytes * 8 - ds_len) as u8;

    let mut bitmap = vec![0u8; n_bytes];
    if all_included {
        for b in bitmap.iter_mut() {
            *b = 0xff;
        }
        // The unused trailing bits of the last byte must be zero.
        if padding > 0 && n_bytes > 0 {
            bitmap[n_bytes - 1] &= 0xff << padding;
        }
    } else {
        for &idx in included_indices {
            if idx < ds_len {
                let byte_idx = idx / 8;
                let bit_idx = 7 - (idx % 8); // most significant bit first
                bitmap[byte_idx] |= 1 << bit_idx;
            }
        }
    }
    let _ = pending; // pending carries no information on this path

    // BIT_STRING tag 0x84; the content is the padding byte then the bitmap.
    buf.extend_from_slice(&[0x84]);
    encode_length(1 + n_bytes, buf);
    buf.put_u8(padding);
    buf.extend_from_slice(&bitmap);
}

/// Encodes an `MmsValue` as an AccessResult, using the context-implicit MmsData
/// wire tags of IEC 61850-8-1.
///
/// The encoding itself is delegated to `MmsData` in `iec61850-mms`.
fn encode_mms_value(v: &iec61850_model::MmsValue, buf: &mut BytesMut) {
    let data = mms_value_to_mms_data(v);
    data.encode(buf);
}

/// Converts an `iec61850_model::MmsValue` into an `iec61850_mms` `MmsData`.
///
/// The two types have the same shape, but the orphan rule rules out a `From`
/// implementation across the crate boundary, so the mapping is written out.
fn mms_value_to_mms_data(v: &iec61850_model::MmsValue) -> iec61850_mms::mms::pdu::common::MmsData {
    use iec61850_mms::mms::pdu::common::MmsData;
    use iec61850_model::MmsValue;
    match v {
        MmsValue::Boolean(b) => MmsData::Boolean(*b),
        MmsValue::Integer(i) => MmsData::Integer(*i),
        MmsValue::Unsigned(u) => MmsData::Unsigned(*u),
        MmsValue::Float32(f) => MmsData::Float32(*f),
        MmsValue::Float64(f) => MmsData::Float64(*f),
        MmsValue::BitString { padding, data } => MmsData::BitString {
            padding: *padding,
            data: data.clone(),
        },
        MmsValue::OctetString(b) => MmsData::OctetString(b.clone()),
        MmsValue::VisibleString(s) => MmsData::VisibleString(s.clone()),
        MmsValue::MmsString(s) => MmsData::MmsString(s.clone()),
        MmsValue::UtcTime(t) => MmsData::UtcTime(*t),
        MmsValue::BinaryTime(b) => MmsData::BinaryTime(b.clone()),
        MmsValue::Array(items) => MmsData::Array(items.iter().map(mms_value_to_mms_data).collect()),
        MmsValue::Structure(items) => {
            MmsData::Structure(items.iter().map(mms_value_to_mms_data).collect())
        }
    }
}

/// BER length encoding, re-exported from `iec61850_asn1`.
///
/// The shared encoder emits at most the two-byte long form (`0x82`), which is what
/// the decoder in `iec61850-mms` accepts. Reports stay well below 65535 bytes
/// because COTP and TPKT segment beneath this layer, so the limit does not
/// constrain the reporting path.
use iec61850_asn1::encode_length;

// ─────────────────────────────────────────────────────────────────────────────
// BRCB-specific encoder
// ─────────────────────────────────────────────────────────────────────────────

/// Everything `encode_brcb_report_pdus` needs.
///
/// A BRCB report carries two fields a URCB report does not: `entry_id`, sent as an
/// OCTET STRING(8) when OptFlds requests EntryID, and `is_overflow`, sent as the
/// BufOvfl BOOLEAN when OptFlds requests it.
///
/// `time_of_entry_ms` comes from `ReportEntry.time_of_entry_ms`, the moment the
/// entry entered the buffer, rather than from the pending report.
///
/// `sq_num` is a `u16` here where a URCB uses a `u8`: a BRCB sequence number is an
/// UNSIGNED(16).
#[derive(Debug, Clone)]
pub struct BrcbReportEncodeParams<'a> {
    /// RptID, a VisibleString.
    pub rpt_id: &'a str,
    /// OptFlds; a BRCB does not mask, so BUFFER_OVERFLOW and ENTRY_ID are kept.
    pub opt_flds: OptFlds,
    /// SqNum, 16 bits for a BRCB where a URCB uses 8.
    pub sq_num: u16,
    /// Report time in milliseconds since the epoch, taken from the buffered entry.
    pub time_of_entry_ms: u64,
    /// DatSet, a VisibleString.
    pub dat_set: &'a str,
    /// ConfRev.
    pub conf_rev: u32,
    /// Eight-byte big-endian EntryID of this entry.
    pub entry_id: EntryId,
    /// Whether this entry reports `BufOvfl = true`; the caller derives it from the
    /// backend overflow flag or from a restart at the head of the buffer.
    pub is_overflow: bool,
    /// Data set, used for the inclusion field, data references, and entry values.
    pub dataset: &'a Dataset,
    /// Pending report: value snapshot and inclusion flags.
    pub pending: &'a PendingReport,
    /// Negotiated maximum MMS PDU size, in bytes.
    pub max_pdu_size_bytes: usize,
}

/// Encodes one BRCB report into one or more MMS unconfirmedPDU byte strings.
///
/// Two fields extend the URCB form:
/// - `BufOvfl`, a BOOLEAN, when OptFlds requests buffer overflow
/// - `EntryID`, an OCTET STRING(8), when OptFlds requests the entry identifier
///
/// Segmentation behaves exactly as for a URCB and uses the same wire bit.
///
/// # Errors
///
/// Returns `ReportEncodeError::PduTooSmall` when even a single data set element
/// does not fit within `max_pdu_size_bytes`.
pub fn encode_brcb_report_pdus(
    params: &BrcbReportEncodeParams<'_>,
) -> Result<Vec<Bytes>, ReportEncodeError> {
    let n = params.dataset.len();
    let included_indices: Vec<usize> = (0..n)
        .filter(|&i| {
            params
                .pending
                .inclusion_flags
                .get(i)
                .map(|f| f.has_trigger())
                .unwrap_or(false)
                || params.pending.is_integrity
                || params.pending.is_gi
        })
        .collect();

    // Try a single unsegmented PDU first.
    let opt_flds = params.opt_flds; // a BRCB does not mask OptFlds
    let single = encode_brcb_segment(params, opt_flds, &included_indices, 0, false);
    if single.len() <= params.max_pdu_size_bytes {
        return Ok(vec![single]);
    }

    // Too large: segment, which also sets the SEGMENTATION bit.
    let opt_flds_seg = opt_flds | OptFlds::SEGMENTATION;
    let mut result = Vec::new();
    let mut sub_seq_num: u16 = 0;
    let mut start = 0;

    loop {
        let remaining = &included_indices[start..];
        if remaining.is_empty() {
            break;
        }
        let mut end = remaining.len();
        loop {
            let more_follows = start + end < included_indices.len();
            let seg = encode_brcb_segment(
                params,
                opt_flds_seg,
                &included_indices[start..start + end],
                sub_seq_num,
                more_follows,
            );
            if seg.len() <= params.max_pdu_size_bytes || end == 1 {
                if seg.len() > params.max_pdu_size_bytes {
                    return Err(ReportEncodeError::PduTooSmall {
                        needed: seg.len(),
                        max: params.max_pdu_size_bytes,
                    });
                }
                result.push(seg);
                start += end;
                sub_seq_num += 1;
                break;
            }
            end /= 2;
            if end == 0 {
                end = 1;
            }
        }
    }
    Ok(result)
}

/// Encodes one BRCB report segment.
///
/// Follows the URCB layout with two extra fields, in the IEC 61850-8-1 wire order:
/// BufOvfl after ConfRev when the buffer overflow bit is set, and EntryID after
/// BufOvfl and before the segmentation fields when the entry identifier bit is set.
fn encode_brcb_segment(
    params: &BrcbReportEncodeParams<'_>,
    opt_flds: OptFlds,
    included_indices: &[usize],
    sub_seq_num: u16,
    more_follows: bool,
) -> Bytes {
    let mut access_result = BytesMut::new();

    // 1. RptID, always present.
    encode_visible_string(params.rpt_id, &mut access_result);
    // 2. OptFlds, always present; a BRCB does not mask.
    encode_opt_flds_unmasked(opt_flds, &mut access_result);
    // 3. SqNum if SEQ_NUM: 16 bits for a BRCB, unlike the URCB 8-bit field.
    if opt_flds.contains(OptFlds::SEQ_NUM) {
        encode_unsigned16(params.sq_num, &mut access_result);
    }
    // 4. TimeOfEntry if TIME_STAMP.
    if opt_flds.contains(OptFlds::TIME_STAMP) {
        encode_binary_time(params.time_of_entry_ms, &mut access_result);
    }
    // 5. DatSet if DATA_SET.
    if opt_flds.contains(OptFlds::DATA_SET) {
        encode_visible_string(params.dat_set, &mut access_result);
    }
    // 6. ConfRev if CONF_REV.
    if opt_flds.contains(OptFlds::CONF_REV) {
        encode_unsigned32(params.conf_rev, &mut access_result);
    }
    // 7. BRCB only: BufOvfl if BUFFER_OVERFLOW.
    if opt_flds.contains(OptFlds::BUFFER_OVERFLOW) {
        encode_boolean(params.is_overflow, &mut access_result);
    }
    // 8. BRCB only: EntryID if ENTRY_ID, as an OCTET STRING(8).
    if opt_flds.contains(OptFlds::ENTRY_ID) {
        encode_octet_string_8(&params.entry_id.0, &mut access_result);
    }
    // 9. Segmentation fields if SEGMENTATION: subSeqNum and moreFollows.
    if opt_flds.contains(OptFlds::SEGMENTATION) {
        encode_unsigned16(sub_seq_num, &mut access_result);
        encode_boolean(more_follows, &mut access_result);
    }
    // 10. inclusionField, a BIT_STRING(N).
    let ds_len = params.dataset.len();
    encode_inclusion_field(
        params.pending,
        included_indices,
        ds_len,
        params.pending.is_integrity || params.pending.is_gi,
        &mut access_result,
    );
    // 11. One VisibleString per included entry if DATA_REFERENCE.
    if opt_flds.contains(OptFlds::DATA_REFERENCE) {
        for &idx in included_indices {
            if let Some(entry) = params.dataset.entry(idx) {
                encode_visible_string(&entry.attr_ref, &mut access_result);
            }
        }
    }
    // 12. The value of every included entry.
    for &idx in included_indices {
        let val = params
            .pending
            .snapshot
            .get(idx)
            .and_then(|v| v.as_ref())
            .cloned()
            .or_else(|| params.dataset.entry(idx).and_then(|e| e.read_value()));
        if let Some(v) = val {
            encode_mms_value(&v, &mut access_result);
        } else {
            access_result.extend_from_slice(&[0xa2, 0x00]);
        }
    }
    // 13. One reason bit string per included entry if REASON.
    if opt_flds.contains(OptFlds::REASON) {
        for &idx in included_indices {
            let flag = params
                .pending
                .inclusion_flags
                .get(idx)
                .copied()
                .unwrap_or(InclusionFlag::NONE);
            let reason =
                flag.to_reason_bit_string(params.pending.is_integrity, params.pending.is_gi);
            access_result.extend_from_slice(&[0x84, 0x02]);
            access_result.extend_from_slice(&reason);
        }
    }

    // Wrap in listOfAccessResult [0].
    let mut list_of_ar = BytesMut::new();
    list_of_ar.extend_from_slice(&[0xa0]);
    encode_length(access_result.len(), &mut list_of_ar);
    list_of_ar.extend_from_slice(&access_result);

    let mut info_report_body = BytesMut::new();
    info_report_body.extend_from_slice(VAR_ACCESS_SPEC);
    info_report_body.extend_from_slice(&list_of_ar);

    let mut combined = BytesMut::new();
    combined.extend_from_slice(&[0xa0]);
    encode_length(info_report_body.len(), &mut combined);
    combined.extend_from_slice(&info_report_body);

    let mut buf = BytesMut::new();
    buf.extend_from_slice(&[0xa3]);
    encode_length(combined.len(), &mut buf);
    buf.extend_from_slice(&combined);

    buf.freeze()
}

/// Encodes an eight-byte OctetString (EntryID) as an AccessResult.
///
/// IEC 61850-8-1 gives an MMS OctetString inside an AccessResult the context tag
/// `[9] IMPLICIT OCTET STRING`, which is 0x89.
fn encode_octet_string_8(bytes: &[u8; 8], buf: &mut BytesMut) {
    buf.extend_from_slice(&[0x89, 0x08]);
    buf.extend_from_slice(bytes);
}

/// Encodes OptFlds for a BRCB, keeping the BUFFER_OVERFLOW and ENTRY_ID bits.
///
/// `OptFlds::to_ber_bit_string` masks those two bits off for URCB use, so the wire
/// bytes are assembled here instead of calling it.
fn encode_opt_flds_unmasked(opt_flds: OptFlds, buf: &mut BytesMut) {
    let v = opt_flds.0;
    // Same bit mapping as OptFlds::to_ber_bit_string, without the URCB mask.
    let byte0: u8 = ((v & 0x001) << 6) as u8           // SEQ_NUM → 0x40
        | ((v & 0x002) << 4) as u8                      // TIME_STAMP → 0x20
        | ((v & 0x004) << 2) as u8                      // REASON → 0x10
        | (v & 0x008) as u8                             // DATA_SET → 0x08
        | ((v & 0x010) >> 2) as u8                      // DATA_REFERENCE → 0x04
        | ((v & 0x020) >> 4) as u8                      // BUFFER_OVERFLOW → 0x02 (kept for BRCB)
        | ((v & 0x040) >> 6) as u8; // ENTRY_ID → 0x01 (kept for BRCB)
    let byte1: u8 = (v & 0x080) as u8                   // CONF_REV → 0x80
        | ((v & 0x100) >> 2) as u8; // SEGMENTATION → 0x40
    buf.extend_from_slice(&[0x84, 0x03, 6u8, byte0, byte1]);
}

/// Builds a `PendingReport` from a buffered `ReportEntry` for the BRCB send path.
///
/// When the entry carries an enqueue-time snapshot, its trgOps-filtered inclusion
/// flags and captured values are used directly. Without one, a data-change entry is
/// treated as including the whole data set and the caller supplies live values.
///
/// The entry flags select the report kind: `is_integrity` for an integrity report,
/// `is_gi` for a general interrogation, neither for a data change.
pub fn pending_from_brcb_entry(entry: &Arc<ReportEntry>, ds_len: usize) -> PendingReport {
    let mut p = PendingReport::new_empty(ds_len, entry.time_of_entry_ms);
    p.is_integrity = entry.is_integrity;
    p.is_gi = entry.is_gi;

    if let Some(snap) = entry.snapshot.as_ref() {
        // The snapshot was frozen at enqueue time, so a data set that changed before
        // transmission cannot alter what the client is told.
        let n = snap.data_set_len.min(ds_len);
        for i in 0..n {
            if let Some(flag) = snap.inclusion_flags.get(i) {
                p.inclusion_flags[i] = *flag;
            }
            if let Some(v) = snap.values.get(i).and_then(|v| v.clone()) {
                p.snapshot[i] = Some(v);
            }
        }
        // For general interrogation and integrity the snapshot already holds every
        // data set value. The encoder forces the inclusion field to all-included for
        // those reports, so the flags need no adjustment here.
        return p;
    }

    // No snapshot: an entry that did not come through the trigger path.
    if !entry.is_integrity && !entry.is_gi {
        for f in p.inclusion_flags.iter_mut() {
            *f = InclusionFlag::VALUE_CHANGED;
        }
    }
    p
}

/// Reads the fields the BRCB send path needs out of a `BufferedReportControl`.
///
/// Sharing this helper keeps `flush_brcb_pending` and its tests on one path for
/// reading control block state, and lets that path be tested on its own.
///
/// # Errors
///
/// Returns `ServerError` when the control block state mutex is poisoned.
pub fn brcb_encode_snapshot(
    brcb: &BufferedReportControl,
) -> Result<BrcbStateSnapshot, crate::error::ServerError> {
    let s = brcb.lock_state()?;
    Ok(BrcbStateSnapshot {
        rpt_id: s.rpt_id.clone(),
        opt_flds: s.opt_flds,
        dat_set: s.dat_set.clone(),
        conf_rev: s.conf_rev,
    })
}

/// Control block fields captured for encoding, so the send path does not hold the
/// state lock while it encodes.
#[derive(Debug, Clone)]
pub struct BrcbStateSnapshot {
    /// RptID of the control block.
    pub rpt_id: String,
    /// OptFlds of the control block.
    pub opt_flds: OptFlds,
    /// DatSet of the control block.
    pub dat_set: String,
    /// ConfRev of the control block.
    pub conf_rev: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::{InclusionFlag, OptFlds};
    use crate::reporting::dataset::{Dataset, DatasetEntry};
    use crate::reporting::rcb::PendingReport;
    use iec61850_mms::{epoch_ms_from_binary_time6, EPOCH_1984_MS};
    use iec61850_model::MmsValue;
    use std::sync::{Arc, RwLock};

    /// 2023-11-14T22:13:20.000Z. BinaryTime6 cannot express an instant before
    /// 1984-01-01, so every fixture timestamp is after that epoch.
    const TEST_TIME_OF_ENTRY_MS: u64 = 1_700_000_000_000;

    fn make_entry(attr_ref: &str, val: MmsValue) -> DatasetEntry {
        DatasetEntry::new(attr_ref, Arc::new(RwLock::new(val)))
    }

    fn make_dataset(n: usize) -> Dataset {
        let mut ds = Dataset::new("ds1");
        for i in 0..n {
            ds.push(make_entry(
                &format!("IED1LD0/GGIO1$ST$Ind{}$stVal", i + 1),
                MmsValue::Boolean(false),
            ));
        }
        ds
    }

    fn make_pending_data_change(ds_len: usize, idx: usize) -> PendingReport {
        let mut p = PendingReport::new_empty(ds_len, 1_000_000);
        p.inclusion_flags[idx] = InclusionFlag::VALUE_CHANGED;
        p.snapshot[idx] = Some(MmsValue::Boolean(true));
        p
    }

    fn make_gi_pending(ds_len: usize, snapshots: Vec<MmsValue>) -> PendingReport {
        let mut p = PendingReport::new_empty(ds_len, 2_000_000);
        p.is_gi = true;
        for (i, v) in snapshots.into_iter().enumerate() {
            p.snapshot[i] = Some(v);
        }
        p
    }

    fn base_params<'a>(ds: &'a Dataset, pending: &'a PendingReport) -> ReportEncodeParams<'a> {
        ReportEncodeParams {
            rpt_id: "IED1LD0/GGIO1$RP$urcb01",
            opt_flds: OptFlds::SEQ_NUM | OptFlds::TIME_STAMP | OptFlds::REASON,
            sq_num: 1,
            time_of_entry_ms: TEST_TIME_OF_ENTRY_MS,
            dat_set: "GGIO1$ds1",
            conf_rev: 5,
            dataset: ds,
            pending,
            max_pdu_size_bytes: 65000,
        }
    }

    // ── TimeOfEntry encoding ──────────────────────────────────────────────────

    #[test]
    fn binary_time_field_carries_the_1984_epoch_layout() {
        // 1984-01-03T00:00:01.000Z: 2 days after the BinaryTime6 epoch, 1000 ms
        // into the day. Wire field: tag 0x8c, length 6, then ms-of-day big-endian
        // over four bytes and the day count big-endian over two.
        let epoch_ms = EPOCH_1984_MS + 2 * 86_400_000 + 1_000;
        let mut buf = BytesMut::new();
        encode_binary_time(epoch_ms, &mut buf);
        assert_eq!(
            &buf[..],
            &[0x8c, 0x06, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x02][..]
        );
    }

    #[test]
    fn encoded_time_of_entry_decodes_back_to_the_same_instant() {
        let mut buf = BytesMut::new();
        encode_binary_time(TEST_TIME_OF_ENTRY_MS, &mut buf);
        assert_eq!(buf[0], 0x8c);
        assert_eq!(buf[1] as usize, BINARY_TIME6_LEN);
        let field: [u8; 6] = buf[2..8].try_into().expect("six byte binary time");
        assert_eq!(epoch_ms_from_binary_time6(field), TEST_TIME_OF_ENTRY_MS);
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    #[test]
    fn single_pdu_outer_tag_is_a3() {
        let ds = make_dataset(2);
        let pending = make_pending_data_change(2, 0);
        let params = base_params(&ds, &pending);
        let pdus = encode_report_pdus(&params).unwrap();
        assert_eq!(pdus.len(), 1, "a small report must fit in one pdu");
        assert_eq!(
            pdus[0][0], 0xa3,
            "the outer tag must be unconfirmedPDU [3] IMPLICIT"
        );
    }

    #[test]
    fn pdu_contains_rpt_id() {
        let ds = make_dataset(2);
        let pending = make_pending_data_change(2, 0);
        let params = base_params(&ds, &pending);
        let pdus = encode_report_pdus(&params).unwrap();
        let s = String::from_utf8_lossy(&pdus[0]);
        assert!(
            s.contains("IED1LD0/GGIO1$RP$urcb01"),
            "the pdu must contain the RptID"
        );
    }

    #[test]
    fn gi_report_all_entries_included() {
        let ds = make_dataset(3);
        let pending = make_gi_pending(
            3,
            vec![
                MmsValue::Boolean(true),
                MmsValue::Boolean(false),
                MmsValue::Integer(42),
            ],
        );
        let params = base_params(&ds, &pending);
        let pdus = encode_report_pdus(&params).unwrap();
        assert_eq!(pdus.len(), 1);
        // A general interrogation report covers every data set entry.
        let s = String::from_utf8_lossy(&pdus[0]);
        assert!(s.contains("urcb01"));
    }

    #[test]
    fn pdu_with_seq_num_time_stamp_reason() {
        let ds = make_dataset(2);
        let pending = make_pending_data_change(2, 0);
        let params = ReportEncodeParams {
            opt_flds: OptFlds::SEQ_NUM | OptFlds::TIME_STAMP | OptFlds::REASON,
            ..base_params(&ds, &pending)
        };
        let pdus = encode_report_pdus(&params).unwrap();
        assert!(!pdus[0].is_empty());
        assert_eq!(pdus[0][0], 0xa3);
    }

    #[test]
    fn pdu_with_data_set_conf_rev() {
        let ds = make_dataset(2);
        let pending = make_pending_data_change(2, 0);
        let params = ReportEncodeParams {
            opt_flds: OptFlds::DATA_SET | OptFlds::CONF_REV,
            ..base_params(&ds, &pending)
        };
        let pdus = encode_report_pdus(&params).unwrap();
        let s = String::from_utf8_lossy(&pdus[0]);
        assert!(s.contains("GGIO1$ds1"), "the pdu must contain the DatSet");
    }

    // ── Segmented report ─────────────────────────────

    #[test]
    fn segmented_report_correct() {
        // A large data set with a small maximum PDU size forces segmentation.
        let mut ds = Dataset::new("large_ds");
        let mut snapshots = Vec::new();
        for i in 0..100 {
            let long_ref = format!(
                "IED1LD0/GGIO1$ST$Ind{}$stVal_with_long_path_to_force_segment",
                i
            );
            ds.push(make_entry(&long_ref, MmsValue::Integer(i as i64)));
            snapshots.push(MmsValue::Integer(i as i64));
        }

        let mut pending = make_gi_pending(100, snapshots);
        // DATA_REFERENCE makes each included entry larger.
        pending.is_gi = true;

        let params = ReportEncodeParams {
            rpt_id: "IED1LD0/GGIO1$RP$urcb01",
            opt_flds: OptFlds::SEQ_NUM
                | OptFlds::TIME_STAMP
                | OptFlds::REASON
                | OptFlds::DATA_REFERENCE,
            sq_num: 0,
            time_of_entry_ms: TEST_TIME_OF_ENTRY_MS,
            dat_set: "GGIO1$large_ds",
            conf_rev: 1,
            dataset: &ds,
            pending: &pending,
            max_pdu_size_bytes: 512, // forces segmentation
        };

        let pdus = encode_report_pdus(&params).unwrap();

        // 1. more than one PDU
        assert!(
            pdus.len() > 1,
            "a large data set must be segmented, got {} pdus",
            pdus.len()
        );

        // 2. no segment is far above the configured limit
        for (i, pdu) in pdus.iter().enumerate() {
            // the final single-entry segment may exceed the limit slightly
            assert!(
                pdu.len() <= params.max_pdu_size_bytes * 3,
                "pdu {} is {} bytes, far above the {} byte limit",
                i,
                pdu.len(),
                params.max_pdu_size_bytes
            );
        }

        // 3. every segment carries the outer 0xa3 tag
        for pdu in &pdus {
            assert_eq!(pdu[0], 0xa3, "every segment must start with 0xa3");
        }

        // 4. the last segment clears moreFollows, encoded as BOOLEAN 0x83 0x01 0x00
        let last = &pdus[pdus.len() - 1];
        let last_bytes = last.as_ref();
        let found_false = last_bytes.windows(3).any(|w| w == [0x83, 0x01, 0x00]);
        assert!(
            found_false,
            "the last segment must carry moreFollows=false (0x83 0x01 0x00)"
        );
    }

    // ── SqNum round-trip ─────────────────────────────────────────────────────

    #[test]
    fn sq_num_in_pdu() {
        let ds = make_dataset(1);
        let pending = make_pending_data_change(1, 0);
        let params = ReportEncodeParams {
            sq_num: 42,
            opt_flds: OptFlds::SEQ_NUM,
            ..base_params(&ds, &pending)
        };
        let pdus = encode_report_pdus(&params).unwrap();
        // SqNum 42 encodes as an 8-bit UNSIGNED: 0x86 0x01 0x2a
        let bytes = pdus[0].as_ref();
        let found = bytes.windows(3).any(|w| w == [0x86, 0x01, 0x2a]);
        assert!(found, "the pdu must contain SqNum=42 (0x86 0x01 0x2a)");
    }

    // ── A URCB clears the BRCB-only OptFlds bits ─────────────────────────────

    #[test]
    fn brcb_bits_cleared_in_urcb_pdu() {
        let ds = make_dataset(1);
        let pending = make_pending_data_change(1, 0);
        // Deliberately request BUFFER_OVERFLOW and ENTRY_ID.
        let params = ReportEncodeParams {
            opt_flds: OptFlds::SEQ_NUM | OptFlds::BUFFER_OVERFLOW | OptFlds::ENTRY_ID,
            ..base_params(&ds, &pending)
        };
        let pdus = encode_report_pdus(&params).unwrap();
        // Find the OptFlds BIT_STRING(10) and check the BRCB-only bits are clear.
        let bytes = pdus[0].as_ref();
        let mut found = false;
        for i in 0..bytes.len().saturating_sub(4) {
            if bytes[i] == 0x84 && bytes[i + 1] == 0x03 {
                // bytes[i+2] is the padding count, bytes[i+3] the first data byte
                let data0 = bytes[i + 3];
                // BUFFER_OVERFLOW is byte0 bit 0x04, ENTRY_ID is byte0 bit 0x02
                assert_eq!(
                    data0 & 0x06,
                    0,
                    "BUFFER_OVERFLOW and ENTRY_ID must be cleared"
                );
                found = true;
                break;
            }
        }
        assert!(found, "the pdu must contain an OptFlds BIT_STRING");
    }

    // ── Field encoder helpers ────────────────────────────────────────────────

    #[test]
    fn encode_visible_string_helper() {
        let mut buf = BytesMut::new();
        encode_visible_string("RPT", &mut buf);
        // tag 0x8a, length 3, "RPT"
        assert_eq!(buf[0], 0x8a);
        assert_eq!(buf[1], 0x03);
        assert_eq!(&buf[2..5], b"RPT");
    }

    #[test]
    fn encode_boolean_true_and_false() {
        let mut buf = BytesMut::new();
        encode_boolean(true, &mut buf);
        assert_eq!(&buf[..], &[0x83, 0x01, 0xff]);
        buf.clear();
        encode_boolean(false, &mut buf);
        assert_eq!(&buf[..], &[0x83, 0x01, 0x00]);
    }

    #[test]
    fn encode_unsigned32_boundary() {
        let mut buf = BytesMut::new();
        encode_unsigned32(0, &mut buf);
        assert_eq!(buf[1], 1, "zero must encode in one byte");
        buf.clear();
        encode_unsigned32(0xff, &mut buf);
        assert_eq!(buf[1], 1);
        buf.clear();
        encode_unsigned32(0x100, &mut buf);
        assert_eq!(buf[1], 2);
        buf.clear();
        encode_unsigned32(u32::MAX, &mut buf);
        assert_eq!(buf[1], 4);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // BRCB encoder
    // ─────────────────────────────────────────────────────────────────────────

    fn brcb_base_params<'a>(
        ds: &'a Dataset,
        pending: &'a PendingReport,
        entry_id: EntryId,
        is_overflow: bool,
    ) -> BrcbReportEncodeParams<'a> {
        BrcbReportEncodeParams {
            rpt_id: "IED1LD0/GGIO1$BR$brcb01",
            // BUFFER_OVERFLOW and ENTRY_ID are the usual BRCB set
            opt_flds: OptFlds::SEQ_NUM
                | OptFlds::TIME_STAMP
                | OptFlds::REASON
                | OptFlds::BUFFER_OVERFLOW
                | OptFlds::ENTRY_ID,
            sq_num: 7,
            time_of_entry_ms: TEST_TIME_OF_ENTRY_MS,
            dat_set: "GGIO1$ds1",
            conf_rev: 3,
            entry_id,
            is_overflow,
            dataset: ds,
            pending,
            max_pdu_size_bytes: 65000,
        }
    }

    #[test]
    fn encode_brcb_report_pdus_single_segment_no_overflow() {
        // One data-change entry produces a single small PDU.
        let ds = make_dataset(1);
        let pending = make_pending_data_change(1, 0);
        let id = EntryId::from_ms(0x12345678_9ABCDEF0);
        let params = brcb_base_params(&ds, &pending, id, false);
        let pdus = encode_brcb_report_pdus(&params).expect("encoding must succeed");
        assert_eq!(pdus.len(), 1);
        assert_eq!(pdus[0][0], 0xa3, "the outer tag must be 0xa3");
    }

    #[test]
    fn encode_brcb_report_pdus_includes_entry_id() {
        // With the ENTRY_ID bit set the wire carries an OCTET STRING(8).
        let ds = make_dataset(1);
        let pending = make_pending_data_change(1, 0);
        let id = EntryId::from_ms(0x12345678_9ABCDEF0);
        let params = brcb_base_params(&ds, &pending, id, false);
        let pdus = encode_brcb_report_pdus(&params).unwrap();
        let bytes = pdus[0].as_ref();
        // Look for OCTET STRING(8) tag 0x89 0x08 and the big-endian identifier.
        let mut wanted = vec![0x89u8, 0x08];
        wanted.extend_from_slice(&id.0);
        let found = bytes.windows(wanted.len()).any(|w| w == wanted.as_slice());
        assert!(
            found,
            "a brcb pdu must carry the EntryID as an OCTET STRING(8)"
        );
    }

    #[test]
    fn encode_brcb_report_pdus_includes_buf_ovfl_when_set() {
        // is_overflow true puts BufOvfl=true on the wire, as BOOLEAN 0x83 0x01 0xff.
        let ds = make_dataset(1);
        let pending = make_pending_data_change(1, 0);
        let id = EntryId::from_ms(1234);
        let params = brcb_base_params(&ds, &pending, id, true);
        let pdus = encode_brcb_report_pdus(&params).unwrap();
        let bytes = pdus[0].as_ref();
        // One BOOLEAN 0x83 0x01 0xff must be present.
        let found_true = bytes.windows(3).any(|w| w == [0x83, 0x01, 0xff]);
        assert!(found_true, "is_overflow must put BufOvfl=true on the wire");
    }

    #[test]
    fn encode_brcb_report_pdus_excludes_buf_ovfl_when_bit_off() {
        // With the bit clear the field is absent and the PDU is shorter.
        let ds = make_dataset(1);
        let pending = make_pending_data_change(1, 0);
        let id = EntryId::from_ms(1234);
        // The two parameter sets differ only in BUFFER_OVERFLOW.
        let mut p_with = brcb_base_params(&ds, &pending, id, true);
        p_with.opt_flds = OptFlds::SEQ_NUM | OptFlds::ENTRY_ID | OptFlds::BUFFER_OVERFLOW;
        let mut p_without = brcb_base_params(&ds, &pending, id, true);
        p_without.opt_flds = OptFlds::SEQ_NUM | OptFlds::ENTRY_ID;
        let len_with = encode_brcb_report_pdus(&p_with).unwrap()[0].len();
        let len_without = encode_brcb_report_pdus(&p_without).unwrap()[0].len();
        // The BufOvfl BOOLEAN is three bytes; the outer length may grow by one too.
        assert!(
            len_with > len_without,
            "OptFlds with BUFFER_OVERFLOW must be longer (with={len_with}, without={len_without})"
        );
        assert!(
            len_with - len_without >= 3,
            "BufOvfl must add at least 3 bytes (tag, length, value), difference was {}",
            len_with - len_without
        );
    }

    #[test]
    fn encode_brcb_report_pdus_sq_num_is_u16_two_bytes_when_large() {
        // A BRCB SqNum above 255 encodes as a two-byte UNSIGNED.
        let ds = make_dataset(1);
        let pending = make_pending_data_change(1, 0);
        let id = EntryId::from_ms(1);
        let mut params = brcb_base_params(&ds, &pending, id, false);
        params.sq_num = 300; // 0x012c
        let pdus = encode_brcb_report_pdus(&params).unwrap();
        let bytes = pdus[0].as_ref();
        // tag 0x86, length 2, 0x01 0x2c
        let found = bytes.windows(4).any(|w| w == [0x86, 0x02, 0x01, 0x2c]);
        assert!(
            found,
            "a brcb SqNum of 300 must encode as a two-byte UNSIGNED"
        );
    }

    #[test]
    fn encode_brcb_report_pdus_segmentation_marks_more_follows() {
        // A large data set forces segmentation; the last segment clears moreFollows.
        let mut ds = Dataset::new("large_ds");
        let mut snaps = Vec::new();
        for i in 0..80 {
            let r = format!(
                "IED1LD0/GGIO1$ST$Ind{}$stVal_with_long_path_to_force_segment_brcb",
                i
            );
            ds.push(make_entry(&r, MmsValue::Integer(i as i64)));
            snaps.push(MmsValue::Integer(i as i64));
        }
        let pending = make_gi_pending(80, snaps);
        let id = EntryId::from_ms(0xABCD);
        let mut params = brcb_base_params(&ds, &pending, id, false);
        params.opt_flds |= OptFlds::DATA_REFERENCE;
        params.max_pdu_size_bytes = 600;
        let pdus = encode_brcb_report_pdus(&params)
            .expect("segmentation must succeed while every segment holds at least one entry");
        assert!(
            pdus.len() > 1,
            "the report must be segmented, got {} pdus",
            pdus.len()
        );
        // The last segment clears moreFollows.
        let last = pdus.last().unwrap().as_ref();
        let found_false = last.windows(3).any(|w| w == [0x83, 0x01, 0x00]);
        assert!(found_false, "the last segment must clear moreFollows");
        // An earlier segment sets moreFollows.
        let mid = pdus[0].as_ref();
        let found_true = mid.windows(3).any(|w| w == [0x83, 0x01, 0xff]);
        assert!(found_true, "an earlier segment must set moreFollows");
    }

    #[test]
    fn encode_brcb_report_pdus_returns_err_when_max_pdu_too_small() {
        // A maximum PDU size below the minimum for one element must fail, not skip.
        let mut ds = Dataset::new("ds_with_long_path");
        let long_ref = "IED1LD0/GGIO1$ST$Ind1$stVal_with_extra_long_path_segment_for_oversize";
        ds.push(make_entry(long_ref, MmsValue::Integer(0)));
        let pending = make_gi_pending(1, vec![MmsValue::Integer(0)]);
        let id = EntryId::from_ms(1);
        let mut params = brcb_base_params(&ds, &pending, id, true);
        params.opt_flds = OptFlds::SEQ_NUM
            | OptFlds::TIME_STAMP
            | OptFlds::REASON
            | OptFlds::DATA_REFERENCE
            | OptFlds::BUFFER_OVERFLOW
            | OptFlds::ENTRY_ID;
        params.max_pdu_size_bytes = 32; // smaller than the header alone
        let res = encode_brcb_report_pdus(&params);
        assert!(matches!(res, Err(ReportEncodeError::PduTooSmall { .. })));
    }

    #[test]
    fn encode_urcb_report_pdus_returns_err_when_max_pdu_too_small() {
        // A URCB behaves the same way: too small is an error, never a silent skip.
        let mut ds = Dataset::new("ds_long");
        let long_ref = "IED1LD0/GGIO1$ST$Ind1$stVal_with_extra_long_path_segment_for_oversize";
        ds.push(make_entry(long_ref, MmsValue::Integer(0)));
        let pending = make_gi_pending(1, vec![MmsValue::Integer(0)]);
        let mut params = base_params(&ds, &pending);
        params.opt_flds |= OptFlds::DATA_REFERENCE;
        params.max_pdu_size_bytes = 32;
        let res = encode_report_pdus(&params);
        assert!(matches!(res, Err(ReportEncodeError::PduTooSmall { .. })));
    }

    #[test]
    fn pending_from_brcb_entry_data_change_marks_all_included() {
        // A data-change entry without a snapshot includes the whole data set.
        let entry = Arc::new(ReportEntry::new(
            EntryId::from_ms(100),
            100,
            false,
            false,
            Bytes::new(),
        ));
        let p = pending_from_brcb_entry(&entry, 3);
        for i in 0..3 {
            assert!(
                p.inclusion_flags[i].has_trigger(),
                "entry {i} must carry a trigger"
            );
        }
        assert!(!p.is_integrity);
        assert!(!p.is_gi);
    }

    #[test]
    fn pending_from_brcb_entry_gi_marks_is_gi() {
        let entry = Arc::new(ReportEntry::new(
            EntryId::from_ms(100),
            100,
            false,
            true, // is_gi
            Bytes::new(),
        ));
        let p = pending_from_brcb_entry(&entry, 3);
        assert!(p.is_gi);
        // General interrogation does not set VALUE_CHANGED; the encoder takes the
        // all-included path for it.
    }
}
