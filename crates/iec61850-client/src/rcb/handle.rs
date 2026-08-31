//! `RcbHandle`: the client's local copy of a Report Control Block.
//!
//! Absent fields are `Option<T>`, so a value the server never supplied cannot
//! be mistaken for a default.
//!
//! Invariants:
//!
//! - The object reference is validated in `new`: ASCII alphanumerics plus
//!   `/`, `.`, `$` and `_`, at most 129 bytes.
//! - Buffered or unbuffered is decided by the functional constraint in the
//!   object reference (`BR` against `RP`).
//! - `conf_rev`, `sq_num`, `owner` and `time_of_entry_ms` are read-only and
//!   have no setter.
//! - The reserved bit 0 of OptFlds and TrgOps is handled inside the codec; a
//!   caller passes and receives semantic flags without shifting.
//!
//! Element order as read back by `update_values`:
//!
//! URCB, 11 to 12 elements:
//!   0=RptId, 1=RptEna, 2=Resv, 3=DatSet, 4=ConfRev, 5=OptFlds, 6=BufTm,
//!   7=SqNum, 8=TrgOps, 9=IntgPd, 10=GI, 11=Owner (optional)
//!
//! BRCB, 13 to 15 elements:
//!   0=RptId, 1=RptEna, 2=DatSet, 3=ConfRev, 4=OptFlds, 5=BufTm, 6=SqNum,
//!   7=TrgOps, 8=IntgPd, 9=GI, 10=PurgeBuf, 11=EntryId, 12=TimeOfEntry,
//!   13=ResvTms or Owner (INTEGER selects ResvTms, OCTET STRING selects
//!   Owner), 14=Owner when 13 is ResvTms

use crate::error::ClientError;
use crate::prelude::{format, String, ToString, Vec};
use crate::rcb::mask::TriggerOptions;
use crate::report::ReportOptFlds;
use iec61850_mms::epoch_ms_from_binary_time6;
use iec61850_model::value::MmsValue;

// Object reference validation.

/// Validates the syntax of an object reference.
///
/// Permitted characters are ASCII alphanumerics plus `/`, `.`, `$` and `_`,
/// and the reference must contain at least one `.` or `$`. The length limit is
/// 129 bytes, one below the 130-byte MMS itemId limit of IEC 61850-8-1.
///
/// # Errors
///
/// `InvalidArgument` naming the offending character or length. Rejecting here
/// keeps a malformed reference from reaching the wire as an object name.
fn validate_object_reference(reference: &str) -> Result<(), ClientError> {
    if reference.is_empty() {
        return Err(ClientError::InvalidArgument(
            "object reference must not be empty".to_string(),
        ));
    }
    // One byte below the 130-byte itemId limit.
    if reference.len() > 129 {
        return Err(ClientError::InvalidArgument(format!(
            "object reference length {} exceeds the limit of 129",
            reference.len()
        )));
    }
    for ch in reference.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '/' && ch != '.' && ch != '$' && ch != '_' {
            return Err(ClientError::InvalidArgument(format!(
                "object reference contains illegal character '{ch}'; permitted: ASCII alphanumerics and / . $ _"
            )));
        }
    }
    // A reference without a separator carries no functional constraint.
    let has_separator = reference.contains('$') || reference.contains('.');
    if !has_separator {
        return Err(ClientError::InvalidArgument(
            "object reference must contain a '$' or '.' separator".to_string(),
        ));
    }
    Ok(())
}

/// Reports whether an object reference names a buffered RCB.
///
/// The functional constraint is the field between the first separator (`.` or
/// `$`) and the next one; `BR` means buffered, anything else unbuffered. Both
/// `IED1/LD0.RP.rcb01` and `IED1/LD0$BR$rcb01` are accepted.
pub(crate) fn is_buffered_rcb(reference: &str) -> bool {
    // The separator after the logical device name.
    if let Some(pos) = reference.find(['$', '.']) {
        let rest = &reference[pos + 1..];
        // The functional constraint runs to the next separator.
        let fc_end = rest.find(['$', '.']).unwrap_or(rest.len());
        let fc = &rest[..fc_end];
        fc.eq_ignore_ascii_case("br")
    } else {
        false
    }
}

// RcbHandle

/// The client's local copy of an RCB, buffered or unbuffered.
///
/// Populated from a server by `get_rcb_values` and `refresh_rcb_values`. All
/// fields are private; the read-only ones (`conf_rev`, `sq_num`, `owner`,
/// `time_of_entry_ms`) have a getter but no setter.
#[derive(Debug, Clone, PartialEq)]
pub struct RcbHandle {
    // Identity, fixed at construction.
    pub(crate) object_reference: String,
    pub(crate) is_buffered: bool,

    // Writable fields.
    pub(crate) rpt_id: Option<String>,
    pub(crate) rpt_ena: Option<bool>,
    pub(crate) resv: Option<bool>, // URCB only
    pub(crate) data_set_reference: Option<String>,
    pub(crate) opt_flds: Option<ReportOptFlds>,
    pub(crate) buf_tm_ms: Option<u32>,
    pub(crate) trg_ops: Option<TriggerOptions>,
    pub(crate) intg_pd_ms: Option<u32>,
    pub(crate) gi: Option<bool>,
    pub(crate) purge_buf: Option<bool>,   // BRCB only
    pub(crate) entry_id: Option<Vec<u8>>, // BRCB only
    pub(crate) resv_tms: Option<i16>,     // BRCB only; a server may omit it

    // Read-only fields, reported by the server.
    pub(crate) conf_rev: Option<u32>,
    pub(crate) sq_num: Option<u16>,
    pub(crate) time_of_entry_ms: Option<u64>, // BRCB only
    pub(crate) owner: Option<Vec<u8>>,
}

impl RcbHandle {
    // Construction.

    /// Creates a handle for an object reference, deriving buffered or
    /// unbuffered from its functional constraint.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` if the reference violates the character set or the
    /// 129-byte length limit.
    pub fn new(object_reference: &str) -> Result<Self, ClientError> {
        validate_object_reference(object_reference)?;
        let is_buffered = is_buffered_rcb(object_reference);
        Ok(RcbHandle {
            object_reference: object_reference.to_string(),
            is_buffered,
            rpt_id: None,
            rpt_ena: None,
            resv: None,
            data_set_reference: None,
            opt_flds: None,
            buf_tm_ms: None,
            trg_ops: None,
            intg_pd_ms: None,
            gi: None,
            purge_buf: None,
            entry_id: None,
            resv_tms: None,
            conf_rev: None,
            sq_num: None,
            time_of_entry_ms: None,
            owner: None,
        })
    }

    // Identity.

    /// Returns the object reference this handle was created for.
    pub fn object_reference(&self) -> &str {
        &self.object_reference
    }

    /// Reports whether this is a buffered RCB.
    pub fn is_buffered(&self) -> bool {
        self.is_buffered
    }

    // Writable fields.

    /// Returns RptId.
    pub fn rpt_id(&self) -> Option<&str> {
        self.rpt_id.as_deref()
    }

    /// Sets RptId. An empty string is passed through; the server defines it.
    pub fn set_rpt_id(&mut self, id: &str) {
        self.rpt_id = Some(id.to_string());
    }

    /// Returns RptEna, or false when the field has not been read.
    pub fn rpt_ena(&self) -> bool {
        self.rpt_ena.unwrap_or(false)
    }

    /// Sets RptEna.
    pub fn set_rpt_ena(&mut self, v: bool) {
        self.rpt_ena = Some(v);
    }

    /// Returns Resv (URCB only), or false when the field has not been read.
    pub fn resv(&self) -> bool {
        self.resv.unwrap_or(false)
    }

    /// Sets Resv (URCB only).
    pub fn set_resv(&mut self, v: bool) {
        self.resv = Some(v);
    }

    /// Returns the DatSet reference.
    pub fn data_set_reference(&self) -> Option<&str> {
        self.data_set_reference.as_deref()
    }

    /// Sets the DatSet reference.
    pub fn set_data_set_reference(&mut self, ds_ref: &str) {
        self.data_set_reference = Some(ds_ref.to_string());
    }

    /// Returns OptFlds, or an empty set when the field has not been read.
    pub fn opt_flds(&self) -> ReportOptFlds {
        self.opt_flds.unwrap_or(ReportOptFlds::empty())
    }

    /// Sets OptFlds. The reserved bit is added by the codec, not by the caller.
    pub fn set_opt_flds(&mut self, v: ReportOptFlds) {
        self.opt_flds = Some(v);
    }

    /// Returns BufTm in milliseconds, or 0 when the field has not been read.
    pub fn buf_tm_ms(&self) -> u32 {
        self.buf_tm_ms.unwrap_or(0)
    }

    /// Sets BufTm in milliseconds.
    pub fn set_buf_tm_ms(&mut self, ms: u32) {
        self.buf_tm_ms = Some(ms);
    }

    /// Returns TrgOps, or an empty set when the field has not been read.
    pub fn trg_ops(&self) -> TriggerOptions {
        self.trg_ops.unwrap_or(TriggerOptions::empty())
    }

    /// Sets TrgOps. The reserved bit is added by the codec, not by the caller.
    pub fn set_trg_ops(&mut self, ops: TriggerOptions) {
        self.trg_ops = Some(ops);
    }

    /// Returns IntgPd in milliseconds, or 0 when the field has not been read.
    pub fn intg_pd_ms(&self) -> u32 {
        self.intg_pd_ms.unwrap_or(0)
    }

    /// Sets IntgPd in milliseconds.
    pub fn set_intg_pd_ms(&mut self, ms: u32) {
        self.intg_pd_ms = Some(ms);
    }

    /// Returns GI (general interrogation), or false when it has not been read.
    pub fn gi(&self) -> bool {
        self.gi.unwrap_or(false)
    }

    /// Sets GI.
    pub fn set_gi(&mut self, v: bool) {
        self.gi = Some(v);
    }

    /// Returns PurgeBuf (BRCB only), or false when it has not been read.
    pub fn purge_buf(&self) -> bool {
        self.purge_buf.unwrap_or(false)
    }

    /// Sets PurgeBuf (BRCB only).
    pub fn set_purge_buf(&mut self, v: bool) {
        self.purge_buf = Some(v);
    }

    /// Returns the EntryId bytes (BRCB only).
    pub fn entry_id(&self) -> Option<&[u8]> {
        self.entry_id.as_deref()
    }

    /// Sets EntryId, where `None` clears the field.
    ///
    /// # Errors
    ///
    /// Currently infallible. The `Result` is part of the contract so that a
    /// value of an unexpected type is reported rather than dropped silently.
    pub fn set_entry_id(&mut self, id: Option<Vec<u8>>) -> Result<(), ClientError> {
        // Any byte string is a valid EntryId; `None` clears it.
        self.entry_id = id;
        Ok(())
    }

    /// Returns ResvTms (BRCB only), or 0 when the server does not report it.
    pub fn resv_tms(&self) -> i16 {
        self.resv_tms.unwrap_or(0)
    }

    /// Reports whether the server supplied a ResvTms field.
    pub fn has_resv_tms(&self) -> bool {
        self.resv_tms.is_some()
    }

    /// Sets ResvTms (BRCB only).
    pub fn set_resv_tms(&mut self, v: i16) {
        self.resv_tms = Some(v);
    }

    // Read-only fields.

    /// Returns ConfRev, or 0 when the field has not been read.
    ///
    /// ConfRev is maintained by the server; there is no setter, and the
    /// corresponding write mask bit is filtered out of `set_rcb_values`.
    pub fn conf_rev(&self) -> u32 {
        self.conf_rev.unwrap_or(0)
    }

    /// Returns SqNum, or 0 when the field has not been read.
    pub fn sq_num(&self) -> u16 {
        self.sq_num.unwrap_or(0)
    }

    /// Returns TimeOfEntry in milliseconds (BRCB only, read-only).
    pub fn time_of_entry_ms(&self) -> u64 {
        self.time_of_entry_ms.unwrap_or(0)
    }

    /// Returns the Owner bytes, if the server reported them.
    pub fn owner(&self) -> Option<&[u8]> {
        self.owner.as_deref()
    }
}

// OptFlds and TrgOps bit string codec, including the reserved bit.

/// Decodes OptFlds from the data bytes of a BIT STRING.
///
/// A BIT STRING is MSB first, so wire bit n sits at bit 7 - n of its byte.
/// Wire bit 0 is reserved, which puts the first semantic flag
/// (SEQUENCE_NUMBER) at wire bit 1, that is 0x40 of byte 0.
fn decode_opt_flds_from_bit_string(data: &[u8]) -> ReportOptFlds {
    // The same bit mapping is used when parsing a report.
    ReportOptFlds::from_bit_string(data)
}

/// Decodes TrgOps from the data bytes of a BIT STRING.
///
/// MSB first with wire bit 0 reserved, so the first semantic flag
/// (DATA_CHANGED) is wire bit 1, that is 0x40 of byte 0. The argument is the
/// data of an `MmsValue::BitString`, without the leading padding count.
fn decode_trg_ops_from_bit_string(data: &[u8]) -> TriggerOptions {
    let byte0 = data.first().copied().unwrap_or(0);
    // Wire 0x40, 0x20, 0x10, 0x08 and 0x04 map to DATA_CHANGED,
    // QUALITY_CHANGED, DATA_UPDATE, INTEGRITY and GI respectively.
    let raw = ((byte0 & 0x40) >> 6)
        | ((byte0 & 0x20) >> 4)
        | ((byte0 & 0x10) >> 2)
        | (byte0 & 0x08)
        | ((byte0 & 0x04) << 2);
    TriggerOptions::from_bits_truncate(raw & 0x1f)
}

/// Encodes OptFlds as the padding count and data bytes of a BIT STRING(10).
///
/// MSB first with wire bit 0 reserved, so semantic bit n becomes wire bit
/// n + 1: bits 0 to 6 occupy byte 0 from 0x40 down to 0x01, bits 7 and 8
/// occupy byte 1 at 0x80 and 0x40. Ten bits leave a padding of 6.
///
/// Inverse of `decode_opt_flds_from_bit_string`.
pub(crate) fn encode_opt_flds_to_bit_string(opt_flds: ReportOptFlds) -> (u8, Vec<u8>) {
    let bits = opt_flds.bits();
    let b0 = (((bits & 0x001) << 6)
        | ((bits & 0x002) << 4)
        | ((bits & 0x004) << 2)
        | (bits & 0x008)
        | ((bits & 0x010) >> 2)
        | ((bits & 0x020) >> 4)
        | ((bits & 0x040) >> 6)) as u8;
    // Semantic bits 7 and 8 land in byte 1 at 0x80 and 0x40.
    let b1 = ((bits & 0x080) | ((bits & 0x100) >> 2)) as u8;
    (6u8, vec![b0, b1])
}

/// Encodes TrgOps as the padding count and data bytes of a BIT STRING(6).
///
/// MSB first with wire bit 0 reserved, so semantic bit n becomes wire bit
/// n + 1. Six bits fit in one byte and leave a padding of 2.
pub(crate) fn encode_trg_ops_to_bit_string(trg_ops: TriggerOptions) -> (u8, Vec<u8>) {
    let bits = trg_ops.bits();
    // Semantic bits 0 to 4 map to 0x40, 0x20, 0x10, 0x08 and 0x04.
    let wire_byte = ((bits & 0x01) << 6)
        | ((bits & 0x02) << 4)
        | ((bits & 0x04) << 2)
        | (bits & 0x08)
        | ((bits & 0x10) >> 2);
    // BIT STRING(6): one data byte with a padding of 2.
    (2u8, vec![wire_byte])
}

// Decoding an RCB from the MMS structure a server returns.

/// Updates an `RcbHandle` from the structure elements returned by a
/// GetRCBValues read (IEC 61850-7-2 GetBRCBValues / GetURCBValues).
///
/// The element order differs between a URCB (11 to 12 elements) and a BRCB (13
/// to 15). In a BRCB, element 13 is either ResvTms or Owner and is resolved by
/// its type: INTEGER selects ResvTms, OCTET STRING selects Owner.
///
/// # Errors
///
/// `TypeMismatch` naming the element index together with the expected and the
/// received type, so the caller can tell which field the server disagreed on.
pub fn update_values(rcb: &mut RcbHandle, elements: &[MmsValue]) -> Result<(), ClientError> {
    if rcb.is_buffered {
        update_values_brcb(rcb, elements)
    } else {
        update_values_urcb(rcb, elements)
    }
}

/// Names the type of an `MmsValue`, for use in a `TypeMismatch`.
fn mms_type_name(v: &MmsValue) -> &'static str {
    match v {
        MmsValue::Boolean(_) => "Boolean",
        MmsValue::Integer(_) => "Integer",
        MmsValue::Unsigned(_) => "Unsigned",
        MmsValue::VisibleString(_) => "VisibleString",
        MmsValue::MmsString(_) => "MmsString",
        MmsValue::OctetString(_) => "OctetString",
        MmsValue::BitString { .. } => "BitString",
        MmsValue::BinaryTime(_) => "BinaryTime",
        MmsValue::Float32(_) => "Float32",
        MmsValue::Float64(_) => "Float64",
        MmsValue::Structure(_) => "Structure",
        MmsValue::Array(_) => "Array",
        MmsValue::UtcTime(_) => "UtcTime",
    }
}

/// Decodes the URCB element order (11 to 12 elements).
fn update_values_urcb(rcb: &mut RcbHandle, elements: &[MmsValue]) -> Result<(), ClientError> {
    if elements.len() < 11 {
        return Err(ClientError::TypeMismatch {
            index: 0,
            expected: "structure with at least 11 elements (URCB)",
            got: "element count too low",
        });
    }

    // index 0: rptId (VISIBLE_STRING)
    match &elements[0] {
        MmsValue::VisibleString(s) => rcb.rpt_id = Some(s.clone()),
        other => {
            return Err(ClientError::TypeMismatch {
                index: 0,
                expected: "VisibleString",
                got: mms_type_name(other),
            })
        }
    }
    // index 1: rptEna (BOOLEAN)
    match &elements[1] {
        MmsValue::Boolean(b) => rcb.rpt_ena = Some(*b),
        other => {
            return Err(ClientError::TypeMismatch {
                index: 1,
                expected: "Boolean",
                got: mms_type_name(other),
            })
        }
    }
    // index 2: resv (BOOLEAN) — URCB
    match &elements[2] {
        MmsValue::Boolean(b) => rcb.resv = Some(*b),
        other => {
            return Err(ClientError::TypeMismatch {
                index: 2,
                expected: "Boolean",
                got: mms_type_name(other),
            })
        }
    }
    // index 3: datSet (VISIBLE_STRING)
    match &elements[3] {
        MmsValue::VisibleString(s) => rcb.data_set_reference = Some(s.clone()),
        other => {
            return Err(ClientError::TypeMismatch {
                index: 3,
                expected: "VisibleString",
                got: mms_type_name(other),
            })
        }
    }
    // index 4: confRev (UNSIGNED)
    match &elements[4] {
        MmsValue::Unsigned(v) => rcb.conf_rev = Some(*v as u32),
        other => {
            return Err(ClientError::TypeMismatch {
                index: 4,
                expected: "Unsigned",
                got: mms_type_name(other),
            })
        }
    }
    // index 5: optFlds (BIT_STRING)
    match &elements[5] {
        MmsValue::BitString { data, .. } => {
            rcb.opt_flds = Some(decode_opt_flds_from_bit_string(data));
        }
        other => {
            return Err(ClientError::TypeMismatch {
                index: 5,
                expected: "BitString",
                got: mms_type_name(other),
            })
        }
    }
    // index 6: bufTm (UNSIGNED, ms)
    match &elements[6] {
        MmsValue::Unsigned(v) => rcb.buf_tm_ms = Some(*v as u32),
        other => {
            return Err(ClientError::TypeMismatch {
                index: 6,
                expected: "Unsigned",
                got: mms_type_name(other),
            })
        }
    }
    // index 7: sqNum (UNSIGNED)
    match &elements[7] {
        MmsValue::Unsigned(v) => rcb.sq_num = Some(*v as u16),
        other => {
            return Err(ClientError::TypeMismatch {
                index: 7,
                expected: "Unsigned",
                got: mms_type_name(other),
            })
        }
    }
    // index 8: trgOps (BIT_STRING)
    match &elements[8] {
        MmsValue::BitString { data, .. } => {
            rcb.trg_ops = Some(decode_trg_ops_from_bit_string(data));
        }
        other => {
            return Err(ClientError::TypeMismatch {
                index: 8,
                expected: "BitString",
                got: mms_type_name(other),
            })
        }
    }
    // index 9: intgPd (UNSIGNED, ms)
    match &elements[9] {
        MmsValue::Unsigned(v) => rcb.intg_pd_ms = Some(*v as u32),
        other => {
            return Err(ClientError::TypeMismatch {
                index: 9,
                expected: "Unsigned",
                got: mms_type_name(other),
            })
        }
    }
    // index 10: gi (BOOLEAN)
    match &elements[10] {
        MmsValue::Boolean(b) => rcb.gi = Some(*b),
        other => {
            return Err(ClientError::TypeMismatch {
                index: 10,
                expected: "Boolean",
                got: mms_type_name(other),
            })
        }
    }
    // index 11 (optional): owner (OCTET_STRING). A structure of 11 elements is
    // accepted, but an owner element of the wrong type is an error rather than
    // a silent skip.
    if elements.len() >= 12 {
        match &elements[11] {
            MmsValue::OctetString(bytes) => rcb.owner = Some(bytes.clone()),
            other => {
                return Err(ClientError::TypeMismatch {
                    index: 11,
                    expected: "OctetString (owner)",
                    got: mms_type_name(other),
                })
            }
        }
    }
    Ok(())
}

/// Decodes the BRCB element order (13 to 15 elements).
fn update_values_brcb(rcb: &mut RcbHandle, elements: &[MmsValue]) -> Result<(), ClientError> {
    if elements.len() < 13 {
        return Err(ClientError::TypeMismatch {
            index: 0,
            expected: "structure with at least 13 elements (BRCB)",
            got: "element count too low",
        });
    }

    // index 0: rptId (VISIBLE_STRING)
    match &elements[0] {
        MmsValue::VisibleString(s) => rcb.rpt_id = Some(s.clone()),
        other => {
            return Err(ClientError::TypeMismatch {
                index: 0,
                expected: "VisibleString",
                got: mms_type_name(other),
            })
        }
    }
    // index 1: rptEna (BOOLEAN)
    match &elements[1] {
        MmsValue::Boolean(b) => rcb.rpt_ena = Some(*b),
        other => {
            return Err(ClientError::TypeMismatch {
                index: 1,
                expected: "Boolean",
                got: mms_type_name(other),
            })
        }
    }
    // index 2: datSet (VISIBLE_STRING); a BRCB has no Resv element
    match &elements[2] {
        MmsValue::VisibleString(s) => rcb.data_set_reference = Some(s.clone()),
        other => {
            return Err(ClientError::TypeMismatch {
                index: 2,
                expected: "VisibleString",
                got: mms_type_name(other),
            })
        }
    }
    // index 3: confRev (UNSIGNED)
    match &elements[3] {
        MmsValue::Unsigned(v) => rcb.conf_rev = Some(*v as u32),
        other => {
            return Err(ClientError::TypeMismatch {
                index: 3,
                expected: "Unsigned",
                got: mms_type_name(other),
            })
        }
    }
    // index 4: optFlds (BIT_STRING)
    match &elements[4] {
        MmsValue::BitString { data, .. } => {
            rcb.opt_flds = Some(decode_opt_flds_from_bit_string(data));
        }
        other => {
            return Err(ClientError::TypeMismatch {
                index: 4,
                expected: "BitString",
                got: mms_type_name(other),
            })
        }
    }
    // index 5: bufTm (UNSIGNED, ms)
    match &elements[5] {
        MmsValue::Unsigned(v) => rcb.buf_tm_ms = Some(*v as u32),
        other => {
            return Err(ClientError::TypeMismatch {
                index: 5,
                expected: "Unsigned",
                got: mms_type_name(other),
            })
        }
    }
    // index 6: sqNum (UNSIGNED)
    match &elements[6] {
        MmsValue::Unsigned(v) => rcb.sq_num = Some(*v as u16),
        other => {
            return Err(ClientError::TypeMismatch {
                index: 6,
                expected: "Unsigned",
                got: mms_type_name(other),
            })
        }
    }
    // index 7: trgOps (BIT_STRING)
    match &elements[7] {
        MmsValue::BitString { data, .. } => {
            rcb.trg_ops = Some(decode_trg_ops_from_bit_string(data));
        }
        other => {
            return Err(ClientError::TypeMismatch {
                index: 7,
                expected: "BitString",
                got: mms_type_name(other),
            })
        }
    }
    // index 8: intgPd (UNSIGNED, ms)
    match &elements[8] {
        MmsValue::Unsigned(v) => rcb.intg_pd_ms = Some(*v as u32),
        other => {
            return Err(ClientError::TypeMismatch {
                index: 8,
                expected: "Unsigned",
                got: mms_type_name(other),
            })
        }
    }
    // index 9: gi (BOOLEAN)
    match &elements[9] {
        MmsValue::Boolean(b) => rcb.gi = Some(*b),
        other => {
            return Err(ClientError::TypeMismatch {
                index: 9,
                expected: "Boolean",
                got: mms_type_name(other),
            })
        }
    }
    // index 10: purgeBuf (BOOLEAN) — BRCB
    match &elements[10] {
        MmsValue::Boolean(b) => rcb.purge_buf = Some(*b),
        other => {
            return Err(ClientError::TypeMismatch {
                index: 10,
                expected: "Boolean",
                got: mms_type_name(other),
            })
        }
    }
    // index 11: entryId (OCTET_STRING)
    match &elements[11] {
        MmsValue::OctetString(bytes) => rcb.entry_id = Some(bytes.clone()),
        other => {
            return Err(ClientError::TypeMismatch {
                index: 11,
                expected: "OctetString",
                got: mms_type_name(other),
            })
        }
    }
    // index 12: timeOfEntry (BINARY_TIME)
    match &elements[12] {
        MmsValue::BinaryTime(bytes) => {
            rcb.time_of_entry_ms = Some(decode_binary_time_ms(bytes)?);
        }
        MmsValue::OctetString(bytes) => {
            // Some servers carry timeOfEntry as an OCTET STRING.
            let mut val = 0u64;
            for b in bytes.iter().take(8) {
                val = (val << 8) | (*b as u64);
            }
            rcb.time_of_entry_ms = Some(val);
        }
        other => {
            return Err(ClientError::TypeMismatch {
                index: 12,
                expected: "BinaryTime",
                got: mms_type_name(other),
            })
        }
    }
    // index 13 (optional): INTEGER selects resvTms, OCTET STRING selects owner.
    // Both 13 and 14 are optional, so a shorter structure is accepted; an
    // element of an unexpected type reports the index it was found at.
    if elements.len() >= 14 {
        match &elements[13] {
            MmsValue::Integer(v) => {
                rcb.resv_tms = Some(*v as i16);
                // index 14 (optional): owner (OCTET_STRING)
                if elements.len() >= 15 {
                    match &elements[14] {
                        MmsValue::OctetString(bytes) => rcb.owner = Some(bytes.clone()),
                        other => {
                            return Err(ClientError::TypeMismatch {
                                index: 14,
                                expected: "OctetString (owner)",
                                got: mms_type_name(other),
                            })
                        }
                    }
                }
            }
            MmsValue::OctetString(bytes) => {
                // Owner without resvTms.
                rcb.owner = Some(bytes.clone());
            }
            other => {
                return Err(ClientError::TypeMismatch {
                    index: 13,
                    expected: "Integer (resvTms) or OctetString (owner)",
                    got: mms_type_name(other),
                })
            }
        }
    }
    Ok(())
}

/// Decodes an MMS BINARY TIME into milliseconds since 1970-01-01.
///
/// Per ISO 9506 the 4-byte form carries only milliseconds since midnight and no
/// date; the 6-byte form adds two big-endian bytes counting days since the
/// 1984-01-01 epoch of the type. The conversion is shared with the encoders
/// through `iec61850_mms::epoch_ms_from_binary_time6`.
///
/// # Errors
///
/// `InvalidBinaryTimeLen` if the field is neither 4 nor 6 bytes long.
fn decode_binary_time_ms(bytes: &[u8]) -> Result<u64, ClientError> {
    match bytes.len() {
        4 => Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64),
        6 => Ok(epoch_ms_from_binary_time6([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
        ])),
        n => Err(ClientError::InvalidBinaryTimeLen { got: n }),
    }
}

/// Returns the elements of an `MmsValue::Structure`.
///
/// # Errors
///
/// `TypeMismatch` if the value is not a structure. `context` names the caller
/// in the warning that is logged.
pub(crate) fn unwrap_structure<'a>(
    v: &'a MmsValue,
    context: &'static str,
) -> Result<&'a Vec<MmsValue>, ClientError> {
    match v {
        MmsValue::Structure(elements) => Ok(elements),
        other => {
            tracing::warn!(
                "{context}: expected a structure, got {}",
                mms_type_name(other)
            );
            Err(ClientError::TypeMismatch {
                index: 0,
                expected: "Structure",
                got: mms_type_name(other),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rcb::mask::TriggerOptions;
    use crate::report::ReportOptFlds;

    // Buffered detection.

    #[test]
    fn is_buffered_urcb_dot_sep() {
        // Functional constraint RP: unbuffered.
        assert!(!is_buffered_rcb("IED1/LD0.RP.rcb01"));
    }

    #[test]
    fn is_buffered_brcb_dollar_sep() {
        // Functional constraint BR: buffered.
        assert!(is_buffered_rcb("IED1/LD0$BR$rcb01"));
    }

    #[test]
    fn is_buffered_rp_dollar_sep() {
        assert!(!is_buffered_rcb("IED1/LD0$RP$rcb01"));
    }

    #[test]
    fn is_buffered_br_dot_sep() {
        assert!(is_buffered_rcb("IED1/LD0.BR.rcb01"));
    }

    // Object reference validation in new().

    #[test]
    fn new_urcb_dot_sep_ok() {
        let h = RcbHandle::new("IED1/LD0.RP.rcb01").unwrap();
        assert!(!h.is_buffered());
        assert_eq!(h.object_reference(), "IED1/LD0.RP.rcb01");
    }

    #[test]
    fn new_brcb_dollar_sep_ok() {
        let h = RcbHandle::new("simpleIOGenericIO/LLN0$BR$brcb01").unwrap();
        assert!(h.is_buffered());
    }

    #[test]
    fn new_invalid_no_separator() {
        // No '$' or '.' separator.
        let err = RcbHandle::new("invalid_ref").unwrap_err();
        assert!(matches!(err, ClientError::InvalidArgument(_)));
    }

    #[test]
    fn new_invalid_illegal_char() {
        // Illegal character '@'.
        let err = RcbHandle::new("IED1@LD0$RP$rcb01").unwrap_err();
        assert!(matches!(err, ClientError::InvalidArgument(_)));
    }

    #[test]
    fn new_invalid_too_long() {
        let long = format!("A/{}$RP$rcb", "B".repeat(130));
        let err = RcbHandle::new(&long).unwrap_err();
        assert!(matches!(err, ClientError::InvalidArgument(_)));
    }

    // set_entry_id.

    #[test]
    fn set_entry_id_valid_bytes() {
        let mut h = RcbHandle::new("IED1/LD0$BR$rcb01").unwrap();
        let result = h.set_entry_id(Some(vec![0x01, 0x02, 0x03]));
        assert!(result.is_ok());
        assert_eq!(h.entry_id(), Some([0x01u8, 0x02, 0x03].as_ref()));
    }

    #[test]
    fn set_entry_id_none_clears() {
        let mut h = RcbHandle::new("IED1/LD0$BR$rcb01").unwrap();
        h.set_entry_id(Some(vec![0x01])).unwrap();
        h.set_entry_id(None).unwrap();
        assert!(h.entry_id().is_none());
    }

    // update_values URCB

    fn make_urcb_elements_11() -> Vec<MmsValue> {
        vec![
            MmsValue::VisibleString("rpt01".to_string()), // 0: rptId
            MmsValue::Boolean(false),                     // 1: rptEna
            MmsValue::Boolean(false),                     // 2: resv
            MmsValue::VisibleString("IED/DS1".to_string()), // 3: datSet
            MmsValue::Unsigned(1),                        // 4: confRev
            MmsValue::BitString {
                padding: 6,
                data: vec![0x00, 0x00],
            }, // 5: optFlds
            MmsValue::Unsigned(0),                        // 6: bufTm
            MmsValue::Unsigned(0),                        // 7: sqNum
            MmsValue::BitString {
                padding: 2,
                data: vec![0x00],
            }, // 8: trgOps
            MmsValue::Unsigned(0),                        // 9: intgPd
            MmsValue::Boolean(false),                     // 10: gi
        ]
    }

    #[test]
    fn update_values_urcb_11_elements() {
        let mut rcb = RcbHandle::new("IED1/LD0$RP$rcb01").unwrap();
        let elements = make_urcb_elements_11();
        update_values(&mut rcb, &elements).unwrap();
        assert_eq!(rcb.rpt_id(), Some("rpt01"));
        assert!(!rcb.rpt_ena());
        assert!(!rcb.resv());
        assert_eq!(rcb.data_set_reference(), Some("IED/DS1"));
        assert_eq!(rcb.conf_rev(), 1);
        assert!(rcb.opt_flds().is_empty());
        assert_eq!(rcb.buf_tm_ms(), 0);
        assert_eq!(rcb.sq_num(), 0);
        assert!(rcb.trg_ops().is_empty());
        assert_eq!(rcb.intg_pd_ms(), 0);
        assert!(!rcb.gi());
        assert!(rcb.owner().is_none());
    }

    #[test]
    fn update_values_urcb_with_owner_12_elements() {
        let mut rcb = RcbHandle::new("IED1/LD0$RP$rcb01").unwrap();
        let mut elements = make_urcb_elements_11();
        elements.push(MmsValue::OctetString(vec![0xDE, 0xAD])); // 11: owner
        update_values(&mut rcb, &elements).unwrap();
        assert_eq!(rcb.owner(), Some([0xDEu8, 0xAD].as_ref()));
    }

    #[test]
    fn update_values_urcb_type_mismatch_index0() {
        let mut rcb = RcbHandle::new("IED1/LD0$RP$rcb01").unwrap();
        let mut elements = make_urcb_elements_11();
        // A Boolean where a VisibleString is required.
        elements[0] = MmsValue::Boolean(true);
        let err = update_values(&mut rcb, &elements).unwrap_err();
        match err {
            ClientError::TypeMismatch {
                index,
                expected,
                got,
            } => {
                assert_eq!(index, 0);
                assert_eq!(expected, "VisibleString");
                assert_eq!(got, "Boolean");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    // update_values BRCB

    fn make_brcb_elements_13() -> Vec<MmsValue> {
        vec![
            MmsValue::VisibleString("brpt01".to_string()), // 0: rptId
            MmsValue::Boolean(false),                      // 1: rptEna
            MmsValue::VisibleString("IED/DS2".to_string()), // 2: datSet
            MmsValue::Unsigned(2),                         // 3: confRev
            MmsValue::BitString {
                padding: 6,
                data: vec![0x00, 0x00],
            }, // 4: optFlds
            MmsValue::Unsigned(500),                       // 5: bufTm (ms)
            MmsValue::Unsigned(1),                         // 6: sqNum
            MmsValue::BitString {
                padding: 2,
                data: vec![0x00],
            }, // 7: trgOps
            MmsValue::Unsigned(60000),                     // 8: intgPd (ms)
            MmsValue::Boolean(false),                      // 9: gi
            MmsValue::Boolean(false),                      // 10: purgeBuf
            MmsValue::OctetString(vec![0xAA, 0xBB]),       // 11: entryId
            MmsValue::BinaryTime(vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), // 12: timeOfEntry
        ]
    }

    #[test]
    fn update_values_brcb_13_elements_no_resv_tms_no_owner() {
        let mut rcb = RcbHandle::new("IED1/LD0$BR$brcb01").unwrap();
        let elements = make_brcb_elements_13();
        update_values(&mut rcb, &elements).unwrap();
        assert_eq!(rcb.rpt_id(), Some("brpt01"));
        assert_eq!(rcb.data_set_reference(), Some("IED/DS2"));
        assert_eq!(rcb.conf_rev(), 2);
        assert_eq!(rcb.buf_tm_ms(), 500);
        assert_eq!(rcb.intg_pd_ms(), 60000);
        assert_eq!(rcb.entry_id(), Some([0xAAu8, 0xBB].as_ref()));
        assert!(!rcb.has_resv_tms());
        assert!(rcb.owner().is_none());
    }

    /// A BinaryTime of any length other than 4 or 6 is reported, not absorbed.
    #[test]
    fn update_values_brcb_rejects_bad_binary_time_length() {
        for bad_len in [0usize, 1, 3, 5, 7, 8] {
            let mut rcb = RcbHandle::new("IED1/LD0$BR$brcb01").unwrap();
            let mut elements = make_brcb_elements_13();
            elements[12] = MmsValue::BinaryTime(vec![0u8; bad_len]);
            match update_values(&mut rcb, &elements) {
                Err(ClientError::InvalidBinaryTimeLen { got }) => assert_eq!(got, bad_len),
                other => panic!("expected InvalidBinaryTimeLen for {bad_len} bytes, got {other:?}"),
            }
        }
    }

    /// The 6-byte form carries the date; the 4-byte form carries milliseconds of
    /// day alone, so it decodes to a value below one day.
    #[test]
    fn update_values_brcb_accepts_both_binary_time_lengths() {
        let mut rcb = RcbHandle::new("IED1/LD0$BR$brcb01").unwrap();
        let mut elements = make_brcb_elements_13();
        // 1984-01-03T00:00:01.000Z: day count 2, 1000 ms of day.
        elements[12] = MmsValue::BinaryTime(vec![0x00, 0x00, 0x03, 0xe8, 0x00, 0x02]);
        update_values(&mut rcb, &elements).unwrap();
        assert_eq!(
            rcb.time_of_entry_ms(),
            441_763_200_000 + 2 * 86_400_000 + 1_000
        );

        let mut rcb = RcbHandle::new("IED1/LD0$BR$brcb01").unwrap();
        let mut elements = make_brcb_elements_13();
        elements[12] = MmsValue::BinaryTime(vec![0x00, 0x00, 0x03, 0xe8]);
        update_values(&mut rcb, &elements).unwrap();
        assert_eq!(rcb.time_of_entry_ms(), 1_000);
    }

    #[test]
    fn update_values_brcb_14_elements_with_resv_tms() {
        let mut rcb = RcbHandle::new("IED1/LD0$BR$brcb01").unwrap();
        let mut elements = make_brcb_elements_13();
        // index 13: resvTms (INTEGER)
        elements.push(MmsValue::Integer(30));
        update_values(&mut rcb, &elements).unwrap();
        assert!(rcb.has_resv_tms());
        assert_eq!(rcb.resv_tms(), 30);
        assert!(rcb.owner().is_none());
    }

    #[test]
    fn update_values_brcb_14_elements_owner_only() {
        let mut rcb = RcbHandle::new("IED1/LD0$BR$brcb01").unwrap();
        let mut elements = make_brcb_elements_13();
        // index 13 as an OCTET STRING selects owner and leaves resvTms unset.
        elements.push(MmsValue::OctetString(vec![0xCA, 0xFE]));
        update_values(&mut rcb, &elements).unwrap();
        assert!(!rcb.has_resv_tms());
        assert_eq!(rcb.owner(), Some([0xCAu8, 0xFE].as_ref()));
    }

    /// BRCB element 13 is type-ambiguous (Integer selects resvTms, OctetString
    /// selects owner); any other type is reported as
    /// `TypeMismatch { index: 13, .. }` rather than ignored.
    #[test]
    fn update_values_brcb_13_wrong_type_returns_err() {
        let mut rcb = RcbHandle::new("IED1/LD0$BR$brcb01").unwrap();
        let mut elements = make_brcb_elements_13();
        // index 13 is neither Integer nor OctetString.
        elements.push(MmsValue::Boolean(true));
        let err = update_values(&mut rcb, &elements).unwrap_err();
        match err {
            ClientError::TypeMismatch {
                index,
                expected,
                got,
            } => {
                assert_eq!(index, 13);
                assert_eq!(expected, "Integer (resvTms) or OctetString (owner)");
                assert_eq!(got, "Boolean");
            }
            other => panic!("unexpected error: {other:?}"),
        }
        // A failed decode must not leave resv_tms or owner partially written.
        assert!(!rcb.has_resv_tms());
        assert!(rcb.owner().is_none());
    }

    /// In a 15-element BRCB, element 14 must be an OctetString (owner); another
    /// type is reported as `TypeMismatch { index: 14, .. }`. The element is
    /// optional, so only its presence with a wrong type is an error.
    #[test]
    fn update_values_brcb_14_wrong_type_returns_err() {
        let mut rcb = RcbHandle::new("IED1/LD0$BR$brcb01").unwrap();
        let mut elements = make_brcb_elements_13();
        // index 13 as an Integer selects the resvTms branch.
        elements.push(MmsValue::Integer(45));
        // index 14 is not an OctetString.
        elements.push(MmsValue::Boolean(false));
        let err = update_values(&mut rcb, &elements).unwrap_err();
        match err {
            ClientError::TypeMismatch {
                index,
                expected,
                got,
            } => {
                assert_eq!(index, 14);
                assert_eq!(expected, "OctetString (owner)");
                assert_eq!(got, "Boolean");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    /// In a 12-element URCB, element 11 must be an OctetString (owner); another
    /// type is reported as `TypeMismatch { index: 11, .. }`. The element is
    /// optional, so only its presence with a wrong type is an error.
    #[test]
    fn update_values_urcb_11_wrong_type_returns_err() {
        let mut rcb = RcbHandle::new("IED1/LD0$RP$rcb01").unwrap();
        let mut elements = make_urcb_elements_11();
        // Element 11 present as an Integer instead of an OctetString.
        elements.push(MmsValue::Integer(0));
        let err = update_values(&mut rcb, &elements).unwrap_err();
        match err {
            ClientError::TypeMismatch {
                index,
                expected,
                got,
            } => {
                assert_eq!(index, 11);
                assert_eq!(expected, "OctetString (owner)");
                assert_eq!(got, "Integer");
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(rcb.owner().is_none());
    }

    // OptFlds and TrgOps bit mapping.

    #[test]
    fn opt_flds_bit_shift_encode_decode_roundtrip() {
        let flags = ReportOptFlds::SEQUENCE_NUMBER;
        let (padding, data) = encode_opt_flds_to_bit_string(flags);
        let decoded = decode_opt_flds_from_bit_string(&data);
        // Padding is a wire-format detail and does not affect decoding.
        let _ = padding;
        assert_eq!(decoded, flags);
    }

    #[test]
    fn trg_ops_bit_shift_encode_decode_roundtrip() {
        let ops = TriggerOptions::DATA_CHANGED;
        let (padding, data) = encode_trg_ops_to_bit_string(ops);
        let decoded = decode_trg_ops_from_bit_string(&data);
        let _ = padding;
        assert_eq!(decoded, ops);
    }
}
