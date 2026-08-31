//! BER encoding and decoding of the `IECGoosePdu` defined in IEC 61850-8-1.
//!
//! The PDU is an `[APPLICATION 1] IMPLICIT SEQUENCE` (outer tag `0x61`) whose
//! members carry context tags. Decoding is bounds-checked field by field and
//! rejects malformed input rather than repairing it; every accepted PDU has a
//! timestamp and a `numDatSetEntries` that matches the decoded `allData`.
//!
//! ## Wire format
//!
//! | Tag  | Field               |
//! |------|---------------------|
//! | 0x80 | gocbRef             |
//! | 0x81 | timeAllowedToLive   |
//! | 0x82 | datSet              |
//! | 0x83 | goID (always sent)  |
//! | 0x84 | t (8-byte UTC time) |
//! | 0x85 | stNum               |
//! | 0x86 | sqNum               |
//! | 0x87 | simulation (test)   |
//! | 0x88 | confRev             |
//! | 0x89 | ndsCom              |
//! | 0x8a | numDatSetEntries    |
//! | 0xab | allData             |
//!
//! ## Robustness cases
//!
//! - A TLV whose declared length reaches past the enclosing PDU is
//!   rejected; `pos + length <= end` is checked before any advance.
//! - BIT STRING content is taken as a bounds-checked slice of the
//!   input, never copied according to the declared length.
//! - An integer or unsigned element longer than 8 content bytes is
//!   rejected with `LengthMismatch`.
//! - An indefinite BER length (0x80) is rejected by
//!   `iec61850-asn1::decode_length`.

use bytes::BytesMut;
use iec61850_asn1::{decode_length, encode_length};
use iec61850_model::MmsValue;

use crate::error::GooseError;

/// Outer tag of the IECGoosePdu, `[APPLICATION 1] IMPLICIT SEQUENCE`.
const TAG_GOOSE_PDU: u8 = 0x61;

// PDU member tags: 0x80-0x8a are primitive, 0xab is constructed.

const TAG_GOCB_REF: u8 = 0x80;
const TAG_TIME_ALLOWED: u8 = 0x81;
const TAG_DAT_SET: u8 = 0x82;
const TAG_GO_ID: u8 = 0x83;
const TAG_T: u8 = 0x84;
const TAG_ST_NUM: u8 = 0x85;
const TAG_SQ_NUM: u8 = 0x86;
const TAG_SIMULATION: u8 = 0x87;
const TAG_CONF_REV: u8 = 0x88;
const TAG_NDS_COM: u8 = 0x89;
const TAG_NUM_DATASET_ENTRIES: u8 = 0x8a;
/// allData: constructed context tag 11, `0xa0 | 0x0b`.
const TAG_ALL_DATA: u8 = 0xab;

// Data type tags inside allData.

const TAG_DATA_ARRAY: u8 = 0xa1; // array, constructed context 1
const TAG_DATA_STRUCT: u8 = 0xa2; // structure, constructed context 2
const TAG_DATA_BOOLEAN: u8 = 0x83; // boolean, 1 byte
const TAG_DATA_BIT_STRING: u8 = 0x84; // bit string, padding byte + content
const TAG_DATA_INTEGER: u8 = 0x85; // signed integer, up to 8 content bytes
const TAG_DATA_UNSIGNED: u8 = 0x86; // unsigned integer, up to 8 payload bytes
const TAG_DATA_FLOAT: u8 = 0x87; // float, 5 or 9 bytes
const TAG_DATA_OCTET_STRING: u8 = 0x89; // octet string
const TAG_DATA_VISIBLE_STRING: u8 = 0x8a; // visible string
/// Tag for `MmsString`, a UTF-8 string.
///
/// `MmsString` carries context tag 16 (`0x90`), distinct from visible string
/// (`0x8a`); keeping the two apart preserves the value type across a decode and
/// re-encode.
const TAG_DATA_MMS_STRING: u8 = 0x90;
const TAG_DATA_BINARY_TIME: u8 = 0x8c; // binary time, 4 or 6 bytes
const TAG_DATA_UTC_TIME: u8 = 0x91; // UTC time, 8 bytes

/// Maximum length in bytes of the gocbRef, datSet, and goID string fields.
///
/// IEC 61850-8-1 §A.2 caps these object references at 129 bytes excluding
/// any terminator. A longer field is rejected rather than truncated, so a
/// subscriber never matches on a shortened reference.
const GOOSE_STRING_MAX_LEN: usize = 129;

/// Maximum nesting depth accepted inside allData.
///
/// The standard does not bound the nesting of a GOOSE data set, so decoding
/// uses a conservative cap that covers realistic data sets and keeps recursion
/// bounded on hostile input. It sits below the general
/// `iec61850_asn1::MAX_DATA_NESTING_DEPTH` of 32 because GOOSE data sets are
/// far shallower in practice than MMS structures.
const GOOSE_DATA_MAX_DEPTH: u8 = 8;

/// The IECGoosePdu of IEC 61850-8-1.
///
/// `all_data` is a `Vec` so that data set entries index in constant time on the
/// receive path.
#[derive(Debug, Clone, PartialEq)]
pub struct GoosePdu {
    /// `[0x80]` gocbRef, the GoCB object reference.
    pub gocb_ref: String,
    /// `[0x81]` timeAllowedToLive, in milliseconds.
    pub time_allowed_to_live: u32,
    /// `[0x82]` datSet, the data set object reference.
    pub dat_set: String,
    /// `[0x83]` goID. The field is always present on the wire; when this is
    /// `None`, `gocb_ref` is encoded in its place.
    pub go_id: Option<String>,
    /// `[0x84]` t, a UTC time of exactly 8 bytes.
    pub t: [u8; 8],
    /// `[0x85]` stNum, the state number; 0 is reserved and never sent.
    pub st_num: u32,
    /// `[0x86]` sqNum, the sequence number.
    ///
    /// 0 is valid here: the first frame after a reset or a state change carries
    /// sqNum 0 because the counter is incremented after encoding.
    pub sq_num: u32,
    /// `[0x87]` simulation, the ASN.1 field name for the IEC 61850-8-1 test
    /// bit.
    pub simulation: bool,
    /// `[0x88]` confRev, the configuration revision.
    pub conf_rev: u32,
    /// `[0x89]` ndsCom, needs commissioning.
    pub nds_com: bool,
    /// `[0x8a]` numDatSetEntries.
    pub num_dataset_entries: u32,
    /// `[0xab]` allData, the data set values.
    pub all_data: Vec<MmsValue>,
}

/// Appends a `tag`, its BER length, and the value bytes.
#[inline]
fn write_tlv(buf: &mut BytesMut, tag: u8, value: &[u8]) {
    buf.extend_from_slice(&[tag]);
    encode_length(value.len(), buf);
    buf.extend_from_slice(value);
}

/// Appends a string TLV; the value is the UTF-8 bytes of `s`.
#[inline]
fn write_string_tlv(buf: &mut BytesMut, tag: u8, s: &str) {
    write_tlv(buf, tag, s.as_bytes());
}

/// Appends a one-byte BOOLEAN TLV.
///
/// True is encoded as 0x01 rather than the canonical BER 0xFF, the form a
/// GOOSE subscriber decodes.
#[inline]
fn write_bool_tlv(buf: &mut BytesMut, tag: u8, v: bool) {
    write_tlv(buf, tag, &[if v { 0x01 } else { 0x00 }]);
}

/// Encodes a `u32` as a compact BER signed integer.
///
/// The value is laid out big-endian behind a 0x00 sign byte, then leading
/// bytes are dropped while at least one byte and a clear sign bit remain, so
/// the content is 1 to 5 bytes long.
fn encode_u32_integer(v: u32) -> Vec<u8> {
    // The leading 0x00 keeps the value positive; without it a u32 with bit 31
    // set would decode as a negative BER integer.
    let raw: [u8; 5] = [
        0x00,
        (v >> 24) as u8,
        (v >> 16) as u8,
        (v >> 8) as u8,
        v as u8,
    ];
    // Drop leading 0x00 bytes, but keep one as a sign byte whenever the next
    // byte has bit 7 set.
    let mut start = 0usize;
    while start < 4 && raw[start] == 0x00 && (raw[start + 1] & 0x80) == 0 {
        start += 1;
    }
    raw[start..].to_vec()
}

/// Appends a `u32` as a BER INTEGER TLV.
#[inline]
fn write_u32_tlv(buf: &mut BytesMut, tag: u8, v: u32) {
    let bytes = encode_u32_integer(v);
    write_tlv(buf, tag, &bytes);
}

/// Appends an `MmsValue` to `buf` in the GOOSE allData Data encoding.
///
/// # Errors
///
/// Returns `SubLevel(Overflow)` when nesting exceeds `GOOSE_DATA_MAX_DEPTH`.
fn encode_mms_value(v: &MmsValue, buf: &mut BytesMut, depth: u8) -> Result<(), GooseError> {
    if depth > GOOSE_DATA_MAX_DEPTH {
        return Err(GooseError::SubLevel(Box::new(GooseError::Overflow)));
    }
    match v {
        MmsValue::Boolean(b) => {
            write_bool_tlv(buf, TAG_DATA_BOOLEAN, *b);
        }
        MmsValue::Integer(i) => {
            // Big-endian i64 with redundant sign-extension bytes removed.
            let be = i.to_be_bytes();
            let start = if *i >= 0 {
                // Keep one 0x00 whenever the next byte has bit 7 set.
                let mut s = 0usize;
                while s < 7 && be[s] == 0x00 && (be[s + 1] & 0x80) == 0 {
                    s += 1;
                }
                s
            } else {
                // Keep one 0xFF whenever the next byte has bit 7 clear.
                let mut s = 0usize;
                while s < 7 && be[s] == 0xFF && (be[s + 1] & 0x80) != 0 {
                    s += 1;
                }
                s
            };
            write_tlv(buf, TAG_DATA_INTEGER, &be[start..]);
        }
        MmsValue::Unsigned(u) => {
            // A BER INTEGER is signed, so an unsigned value needs bit 7 of its
            // first content byte clear: lay it out behind a 0x00 sign byte and
            // drop leading zeros only while the next byte has bit 7 clear.
            // Values at or above 2^63 therefore occupy 9 content bytes, the
            // single over-8 form the decoder accepts.
            let raw: [u8; 9] = [
                0x00,
                (u >> 56) as u8,
                (u >> 48) as u8,
                (u >> 40) as u8,
                (u >> 32) as u8,
                (u >> 24) as u8,
                (u >> 16) as u8,
                (u >> 8) as u8,
                *u as u8,
            ];
            let mut start = 0usize;
            while start < 8 && raw[start] == 0x00 && (raw[start + 1] & 0x80) == 0 {
                start += 1;
            }
            write_tlv(buf, TAG_DATA_UNSIGNED, &raw[start..]);
        }
        MmsValue::Float32(f) => {
            // 5 bytes: exponent width 0x08 then the big-endian IEEE 754 value.
            let mut bytes = [0u8; 5];
            bytes[0] = 0x08;
            bytes[1..5].copy_from_slice(&f.to_be_bytes());
            write_tlv(buf, TAG_DATA_FLOAT, &bytes);
        }
        MmsValue::Float64(f) => {
            // 9 bytes: exponent width 0x0b then the big-endian IEEE 754 value.
            let mut bytes = [0u8; 9];
            bytes[0] = 0x0b;
            bytes[1..9].copy_from_slice(&f.to_be_bytes());
            write_tlv(buf, TAG_DATA_FLOAT, &bytes);
        }
        MmsValue::BitString { padding, data } => {
            let mut content = Vec::with_capacity(1 + data.len());
            content.push(*padding);
            content.extend_from_slice(data);
            write_tlv(buf, TAG_DATA_BIT_STRING, &content);
        }
        MmsValue::OctetString(bytes) => {
            write_tlv(buf, TAG_DATA_OCTET_STRING, bytes);
        }
        MmsValue::VisibleString(s) => {
            write_tlv(buf, TAG_DATA_VISIBLE_STRING, s.as_bytes());
        }
        MmsValue::MmsString(s) => {
            write_tlv(buf, TAG_DATA_MMS_STRING, s.as_bytes());
        }
        MmsValue::UtcTime(ts) => {
            write_tlv(buf, TAG_DATA_UTC_TIME, ts.as_ref());
        }
        MmsValue::BinaryTime(bt) => {
            write_tlv(buf, TAG_DATA_BINARY_TIME, bt);
        }
        MmsValue::Array(items) => {
            let mut inner = BytesMut::new();
            for item in items {
                encode_mms_value(item, &mut inner, depth + 1)?;
            }
            write_tlv(buf, TAG_DATA_ARRAY, &inner);
        }
        MmsValue::Structure(items) => {
            let mut inner = BytesMut::new();
            for item in items {
                encode_mms_value(item, &mut inner, depth + 1)?;
            }
            write_tlv(buf, TAG_DATA_STRUCT, &inner);
        }
    }
    Ok(())
}

/// Reads a TLV header at `data[pos..]` and returns `(tag, value_start,
/// value_end)`, where `value_end` is also the position of the next TLV.
///
/// The call checks `value_end <= end`, so a length
/// field that overstates the payload is rejected instead of producing an
/// out-of-bounds read.
///
/// # Errors
///
/// Returns `TruncatedInput` when the header or the value reaches past `end`,
/// and `Asn1` when the length field itself is malformed.
fn read_tlv_header(data: &[u8], pos: usize, end: usize) -> Result<(u8, usize, usize), GooseError> {
    if pos >= end {
        return Err(GooseError::TruncatedInput {
            needed: 1,
            available: 0,
        });
    }
    let tag = data[pos];
    let (value_len, len_bytes) = decode_length(&data[pos + 1..end]).map_err(GooseError::Asn1)?;
    let value_start = pos + 1 + len_bytes;
    let value_end = value_start + value_len;
    if value_end > end {
        tracing::warn!(
            "goose pdu tlv length out of bounds: tag=0x{:02x}, value_len={}, available={}",
            tag,
            value_len,
            end.saturating_sub(value_start),
        );
        return Err(GooseError::TruncatedInput {
            needed: value_end,
            available: end,
        });
    }
    Ok((tag, value_start, value_end))
}

/// Decodes a `u32` from a BER signed integer of at most 5 content bytes.
fn decode_u32_from_bytes(bytes: &[u8]) -> Result<u32, GooseError> {
    if bytes.is_empty() || bytes.len() > 5 {
        return Err(GooseError::LengthMismatch);
    }
    let mut result = 0u32;
    for &b in bytes {
        result = result << 8 | b as u32;
    }
    Ok(result)
}

/// Decodes one Data element of allData, recursing into arrays and structures.
///
/// `depth` bounds the recursion at `GOOSE_DATA_MAX_DEPTH`.
fn decode_data_element(
    data: &[u8],
    pos: usize,
    end: usize,
    depth: u8,
) -> Result<(MmsValue, usize), GooseError> {
    if depth > GOOSE_DATA_MAX_DEPTH {
        return Err(GooseError::SubLevel(Box::new(GooseError::Overflow)));
    }

    let (tag, value_start, value_end) = read_tlv_header(data, pos, end)?;
    let value = &data[value_start..value_end];
    let element_len = value.len();

    let mms = match tag {
        TAG_DATA_BOOLEAN => {
            let v = value.first().copied().unwrap_or(0);
            // BER treats any non-zero content byte as true.
            MmsValue::Boolean(v != 0)
        }
        TAG_DATA_BIT_STRING => {
            // One padding byte plus at least one content byte.
            if element_len < 2 {
                return Err(GooseError::LengthMismatch);
            }
            let padding = value[0];
            if padding > 7 {
                return Err(GooseError::InvalidPadding(padding));
            }
            // Content comes from the bounds-checked slice, never from
            // a copy sized by the declared length.
            MmsValue::BitString {
                padding,
                data: value[1..].to_vec(),
            }
        }
        TAG_DATA_INTEGER => {
            // An INTEGER wider than i64 is rejected.
            if element_len > 8 {
                return Err(GooseError::LengthMismatch);
            }
            if element_len == 0 {
                return Err(GooseError::LengthMismatch);
            }
            // Sign-extend into i64.
            let sign_bit = value[0] & 0x80 != 0;
            let mut result = if sign_bit { -1i64 } else { 0i64 };
            for &b in value {
                result = (result << 8) | (b as i64);
            }
            MmsValue::Integer(result)
        }
        TAG_DATA_UNSIGNED => {
            // The payload must fit a u64. A value at or above 2^63
            // needs a 0x00 sign byte to stay positive as a BER INTEGER, so a
            // 9-byte element starting with 0x00 is accepted and stripped; any
            // other 9-byte form, and anything longer, is rejected.
            if element_len == 0 {
                return Err(GooseError::LengthMismatch);
            }
            let payload: &[u8] = if element_len == 9 {
                if value[0] != 0x00 {
                    return Err(GooseError::LengthMismatch);
                }
                &value[1..]
            } else if element_len <= 8 {
                value
            } else {
                return Err(GooseError::LengthMismatch);
            };
            let mut result = 0u64;
            for &b in payload {
                result = (result << 8) | (b as u64);
            }
            MmsValue::Unsigned(result)
        }
        TAG_DATA_FLOAT => {
            // 5 bytes carry an f32, 9 bytes an f64; the first byte is the
            // exponent width.
            if element_len == 5 {
                let _exp_width = value[0]; // 0x08
                let bytes: [u8; 4] = value[1..5]
                    .try_into()
                    .map_err(|_| GooseError::LengthMismatch)?;
                MmsValue::Float32(f32::from_be_bytes(bytes))
            } else if element_len == 9 {
                let _exp_width = value[0]; // 0x0b
                let bytes: [u8; 8] = value[1..9]
                    .try_into()
                    .map_err(|_| GooseError::LengthMismatch)?;
                MmsValue::Float64(f64::from_be_bytes(bytes))
            } else {
                return Err(GooseError::LengthMismatch);
            }
        }
        TAG_DATA_OCTET_STRING => MmsValue::OctetString(value.to_vec()),
        TAG_DATA_VISIBLE_STRING => {
            let s = std::str::from_utf8(value).map_err(|_| GooseError::UnknownTag(tag))?;
            MmsValue::VisibleString(s.to_string())
        }
        TAG_DATA_MMS_STRING => {
            let s = std::str::from_utf8(value).map_err(|_| GooseError::UnknownTag(tag))?;
            MmsValue::MmsString(s.to_string())
        }
        TAG_DATA_BINARY_TIME => {
            if element_len != 4 && element_len != 6 {
                return Err(GooseError::LengthMismatch);
            }
            MmsValue::BinaryTime(value.to_vec())
        }
        TAG_DATA_UTC_TIME => {
            if element_len != 8 {
                return Err(GooseError::LengthMismatch);
            }
            let ts: [u8; 8] = value.try_into().map_err(|_| GooseError::LengthMismatch)?;
            MmsValue::UtcTime(ts)
        }
        TAG_DATA_ARRAY => {
            let mut items = Vec::new();
            let mut inner_pos = value_start;
            while inner_pos < value_end {
                let (item, next_pos) = decode_data_element(data, inner_pos, value_end, depth + 1)?;
                items.push(item);
                inner_pos = next_pos;
            }
            MmsValue::Array(items)
        }
        TAG_DATA_STRUCT => {
            let mut items = Vec::new();
            let mut inner_pos = value_start;
            while inner_pos < value_end {
                let (item, next_pos) = decode_data_element(data, inner_pos, value_end, depth + 1)?;
                items.push(item);
                inner_pos = next_pos;
            }
            MmsValue::Structure(items)
        }
        0x80 => {
            // Tag 0x80 is the reserved AccessResult member, unused by GOOSE;
            // its bytes are surfaced verbatim rather than interpreted.
            tracing::warn!("goose alldata carries reserved tag 0x80");
            MmsValue::OctetString(value.to_vec())
        }
        other => {
            tracing::warn!("goose alldata rejected unknown tag 0x{:02x}", other);
            return Err(GooseError::UnknownTag(other));
        }
    };

    Ok((mms, value_end))
}

/// Decodes every Data element inside the `0xab` allData member.
fn decode_all_data(data: &[u8], start: usize, end: usize) -> Result<Vec<MmsValue>, GooseError> {
    let mut items = Vec::new();
    let mut pos = start;
    while pos < end {
        let (item, next_pos) = decode_data_element(data, pos, end, 0)?;
        items.push(item);
        pos = next_pos;
    }
    Ok(items)
}

/// Decodes the content bytes of the allData member into data set values.
///
/// `bytes` is the content of the `0xab` member, excluding its tag and length.
///
/// # Errors
///
/// Returns the first decode error encountered, including `UnknownTag` for an
/// unrecognized Data type and `TruncatedInput` for an out-of-bounds length.
pub fn decode_all_data_bytes(bytes: &[u8]) -> Result<Vec<MmsValue>, GooseError> {
    decode_all_data(bytes, 0, bytes.len())
}

impl GoosePdu {
    /// BER encodes the PDU into `buf` and returns the number of bytes written.
    ///
    /// goID is always emitted; when `go_id` is `None` the encoder writes
    /// `gocb_ref` under tag `0x83`. `numDatSetEntries` is written as given, so
    /// an inconsistent value is only caught on decode.
    ///
    /// # Errors
    ///
    /// Returns `SubLevel(Overflow)` when an allData value nests deeper than
    /// `GOOSE_DATA_MAX_DEPTH`.
    pub fn encode_ber(&self, buf: &mut BytesMut) -> Result<usize, GooseError> {
        let start_len = buf.len();

        // The members are encoded first so the outer length is known.
        let mut pdu = BytesMut::new();

        // [0x80] gocbRef
        write_string_tlv(&mut pdu, TAG_GOCB_REF, &self.gocb_ref);

        // [0x81] timeAllowedToLive, milliseconds
        write_u32_tlv(&mut pdu, TAG_TIME_ALLOWED, self.time_allowed_to_live);

        // [0x82] datSet
        write_string_tlv(&mut pdu, TAG_DAT_SET, &self.dat_set);

        // [0x83] goID, defaulting to gocbRef
        let go_id_str = self.go_id.as_deref().unwrap_or(&self.gocb_ref);
        write_string_tlv(&mut pdu, TAG_GO_ID, go_id_str);

        // [0x84] t, 8-byte UTC time
        write_tlv(&mut pdu, TAG_T, &self.t);

        // [0x85] stNum
        write_u32_tlv(&mut pdu, TAG_ST_NUM, self.st_num);

        // [0x86] sqNum
        write_u32_tlv(&mut pdu, TAG_SQ_NUM, self.sq_num);

        // [0x87] simulation, sent even when false; IEC 61850-8-1 §A.2 requires the field
        write_bool_tlv(&mut pdu, TAG_SIMULATION, self.simulation);

        // [0x88] confRev
        write_u32_tlv(&mut pdu, TAG_CONF_REV, self.conf_rev);

        // [0x89] ndsCom, sent even when false; IEC 61850-8-1 §A.2 requires the field
        write_bool_tlv(&mut pdu, TAG_NDS_COM, self.nds_com);

        // [0x8a] numDatSetEntries
        write_u32_tlv(&mut pdu, TAG_NUM_DATASET_ENTRIES, self.num_dataset_entries);

        // [0xab] allData
        let mut all_data_buf = BytesMut::new();
        for v in &self.all_data {
            encode_mms_value(v, &mut all_data_buf, 0)?;
        }
        write_tlv(&mut pdu, TAG_ALL_DATA, &all_data_buf);

        // Outer tag, BER length, then the encoded members.
        buf.extend_from_slice(&[TAG_GOOSE_PDU]);
        encode_length(pdu.len(), buf);
        buf.extend_from_slice(&pdu);

        Ok(buf.len() - start_len)
    }

    /// BER decodes an `IECGoosePdu` from `data`, which starts at the outer
    /// `0x61` tag.
    ///
    /// Unknown member tags are skipped so that a publisher may add members;
    /// `numDatSetEntries` must equal the number of decoded allData entries.
    ///
    /// Every member is bounds-checked by
    /// `read_tlv_header`, and an indefinite length is refused by the length
    /// decoder.
    ///
    /// # Errors
    ///
    /// `TagDecode` when the outer tag is not `0x61`; `TruncatedInput` when a
    /// length reaches past the buffer; `InvalidStateNumber` for stNum 0;
    /// `InvalidTimestamp` when t is not 8 bytes; `MissingTimestamp` when t is
    /// absent; `UnknownTag` naming any other missing mandatory member; and
    /// `DataSetLengthMismatch` when numDatSetEntries disagrees with allData.
    pub fn decode_ber(data: &[u8]) -> Result<GoosePdu, GooseError> {
        let total_len = data.len();

        if total_len < 2 {
            return Err(GooseError::EthernetFrameTooShort);
        }
        if data[0] != TAG_GOOSE_PDU {
            tracing::warn!("goose pdu outer tag is 0x{:02x}, expected 0x61", data[0]);
            return Err(GooseError::TagDecode);
        }
        let (pdu_len, len_bytes) = decode_length(&data[1..]).map_err(GooseError::Asn1)?;
        let pdu_start = 1 + len_bytes;
        let pdu_end = pdu_start + pdu_len;
        if pdu_end > total_len {
            tracing::warn!(
                "goose pdu outer length {} exceeds the {} byte buffer",
                pdu_end,
                total_len
            );
            return Err(GooseError::TruncatedInput {
                needed: pdu_end,
                available: total_len,
            });
        }

        let mut pos = pdu_start;
        let end = pdu_end;

        let mut gocb_ref: Option<String> = None;
        let mut time_allowed_to_live: Option<u32> = None;
        let mut dat_set: Option<String> = None;
        let mut go_id: Option<String> = None;
        let mut t: Option<[u8; 8]> = None;
        let mut st_num: Option<u32> = None;
        let mut sq_num: Option<u32> = None;
        let mut simulation = false;
        let mut conf_rev: Option<u32> = None;
        let mut nds_com = false;
        let mut num_dataset_entries: Option<u32> = None;
        let mut all_data: Option<Vec<MmsValue>> = None;

        while pos < end {
            let (tag, value_start, value_end) = read_tlv_header(data, pos, end)?;
            let value = &data[value_start..value_end];

            match tag {
                TAG_GOCB_REF => {
                    let s = parse_string_field(value, GOOSE_STRING_MAX_LEN)?;
                    gocb_ref = Some(s);
                }
                TAG_TIME_ALLOWED => {
                    time_allowed_to_live = Some(decode_u32_from_bytes(value)?);
                }
                TAG_DAT_SET => {
                    let s = parse_string_field(value, GOOSE_STRING_MAX_LEN)?;
                    dat_set = Some(s);
                }
                TAG_GO_ID => {
                    let s = parse_string_field(value, GOOSE_STRING_MAX_LEN)?;
                    go_id = Some(s);
                }
                TAG_T => {
                    if value.len() != 8 {
                        tracing::warn!(
                            "goose timestamp field is {} bytes, expected 8",
                            value.len()
                        );
                        return Err(GooseError::InvalidTimestamp);
                    }
                    let mut ts = [0u8; 8];
                    ts.copy_from_slice(value);
                    t = Some(ts);
                }
                TAG_ST_NUM => {
                    let v = decode_u32_from_bytes(value)?;
                    if v == 0 {
                        tracing::warn!("goose stnum is 0");
                        return Err(GooseError::InvalidStateNumber);
                    }
                    st_num = Some(v);
                }
                TAG_SQ_NUM => {
                    // sqNum 0 is the valid first frame after a reset or state
                    // change; only stNum 0 is reserved as uninitialized.
                    sq_num = Some(decode_u32_from_bytes(value)?);
                }
                TAG_SIMULATION => {
                    simulation = value.first().copied().unwrap_or(0) != 0;
                }
                TAG_CONF_REV => {
                    conf_rev = Some(decode_u32_from_bytes(value)?);
                }
                TAG_NDS_COM => {
                    nds_com = value.first().copied().unwrap_or(0) != 0;
                }
                TAG_NUM_DATASET_ENTRIES => {
                    num_dataset_entries = Some(decode_u32_from_bytes(value)?);
                }
                TAG_ALL_DATA => {
                    let items = decode_all_data(data, value_start, value_end)?;
                    all_data = Some(items);
                }
                other => {
                    // Skipped for forward compatibility with future members.
                    tracing::warn!("goose pdu skipped unknown member tag 0x{:02x}", other);
                }
            }

            pos = value_end;
        }

        let gocb_ref = gocb_ref.ok_or(GooseError::UnknownTag(TAG_GOCB_REF))?;
        let time_allowed_to_live =
            time_allowed_to_live.ok_or(GooseError::UnknownTag(TAG_TIME_ALLOWED))?;
        let dat_set = dat_set.ok_or(GooseError::UnknownTag(TAG_DAT_SET))?;
        let t = t.ok_or_else(|| {
            tracing::warn!("goose pdu is missing timestamp field t");
            GooseError::MissingTimestamp
        })?;
        let st_num = st_num.ok_or(GooseError::UnknownTag(TAG_ST_NUM))?;
        let sq_num = sq_num.ok_or(GooseError::UnknownTag(TAG_SQ_NUM))?;
        let conf_rev = conf_rev.ok_or(GooseError::UnknownTag(TAG_CONF_REV))?;
        let num_dataset_entries =
            num_dataset_entries.ok_or(GooseError::UnknownTag(TAG_NUM_DATASET_ENTRIES))?;
        let all_data = all_data.ok_or(GooseError::UnknownTag(TAG_ALL_DATA))?;

        let expected = num_dataset_entries as usize;
        let actual = all_data.len();
        if expected != actual {
            tracing::warn!(
                "goose numdatsetentries {} does not match {} alldata entries",
                expected,
                actual
            );
            return Err(GooseError::DataSetLengthMismatch { expected, actual });
        }

        Ok(GoosePdu {
            gocb_ref,
            time_allowed_to_live,
            dat_set,
            go_id,
            t,
            st_num,
            sq_num,
            simulation,
            conf_rev,
            nds_com,
            num_dataset_entries,
            all_data,
        })
    }
}

/// Decodes a string field, enforcing `max_len` and UTF-8 validity.
///
/// # Errors
///
/// Returns `FieldTooLong` when the field exceeds `max_len` and `UnknownTag(0)`
/// when the bytes are not valid UTF-8.
fn parse_string_field(value: &[u8], max_len: usize) -> Result<String, GooseError> {
    if value.len() > max_len {
        tracing::warn!(
            "goose string field length {} exceeds the {} byte limit",
            value.len(),
            max_len
        );
        return Err(GooseError::FieldTooLong(value.len()));
    }
    String::from_utf8(value.to_vec()).map_err(|_| GooseError::UnknownTag(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    /// Builds the reference PDU used across these tests.
    fn sample_pdu() -> GoosePdu {
        GoosePdu {
            gocb_ref: "A/L$GO$gcb".to_string(),
            time_allowed_to_live: 2000,
            dat_set: "A/L$DS".to_string(),
            go_id: None, // encoded as gocb_ref
            t: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            st_num: 1,
            sq_num: 1,
            simulation: false,
            conf_rev: 1,
            nds_com: false,
            num_dataset_entries: 1,
            all_data: vec![MmsValue::Boolean(true)],
        }
    }

    #[test]
    fn encode_decode_round_trip_basic() {
        let pdu = sample_pdu();
        let mut buf = BytesMut::new();
        pdu.encode_ber(&mut buf).unwrap();

        let decoded = GoosePdu::decode_ber(&buf).unwrap();
        assert_eq!(decoded.gocb_ref, pdu.gocb_ref);
        assert_eq!(decoded.time_allowed_to_live, pdu.time_allowed_to_live);
        assert_eq!(decoded.dat_set, pdu.dat_set);
        // A None go_id is sent as gocbRef and decodes back as Some.
        assert_eq!(decoded.go_id, Some("A/L$GO$gcb".to_string()));
        assert_eq!(decoded.t, pdu.t);
        assert_eq!(decoded.st_num, pdu.st_num);
        assert_eq!(decoded.sq_num, pdu.sq_num);
        assert_eq!(decoded.simulation, pdu.simulation);
        assert_eq!(decoded.conf_rev, pdu.conf_rev);
        assert_eq!(decoded.nds_com, pdu.nds_com);
        assert_eq!(decoded.num_dataset_entries, pdu.num_dataset_entries);
        assert_eq!(decoded.all_data, pdu.all_data);
    }

    #[test]
    fn encode_decode_round_trip_with_go_id() {
        let mut pdu = sample_pdu();
        pdu.go_id = Some("MyGoID".to_string());
        let mut buf = BytesMut::new();
        pdu.encode_ber(&mut buf).unwrap();

        let decoded = GoosePdu::decode_ber(&buf).unwrap();
        assert_eq!(decoded.go_id, Some("MyGoID".to_string()));
    }

    #[test]
    fn encode_decode_multiple_data_types() {
        let mut pdu = sample_pdu();
        pdu.all_data = vec![
            MmsValue::Boolean(true),
            MmsValue::Integer(-42),
            MmsValue::Unsigned(12345),
            MmsValue::Float32(2.5f32),
            MmsValue::OctetString(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            MmsValue::VisibleString("hello".to_string()),
            MmsValue::UtcTime([0xAB; 8]),
        ];
        pdu.num_dataset_entries = pdu.all_data.len() as u32;

        let mut buf = BytesMut::new();
        pdu.encode_ber(&mut buf).unwrap();
        let decoded = GoosePdu::decode_ber(&buf).unwrap();

        assert_eq!(decoded.all_data.len(), pdu.all_data.len());
        assert_eq!(decoded.all_data[0], MmsValue::Boolean(true));
        assert_eq!(decoded.all_data[1], MmsValue::Integer(-42));
        assert_eq!(decoded.all_data[2], MmsValue::Unsigned(12345));
        // Compare the float within tolerance.
        if let MmsValue::Float32(f) = decoded.all_data[3] {
            assert!((f - 2.5f32).abs() < 1e-5);
        } else {
            panic!("expected float32");
        }
        assert_eq!(
            decoded.all_data[4],
            MmsValue::OctetString(vec![0xDE, 0xAD, 0xBE, 0xEF])
        );
        assert_eq!(
            decoded.all_data[5],
            MmsValue::VisibleString("hello".to_string())
        );
        assert_eq!(decoded.all_data[6], MmsValue::UtcTime([0xAB; 8]));
    }

    #[test]
    fn simulation_and_ndscom_always_encoded() {
        let mut pdu = sample_pdu();
        pdu.simulation = false;
        pdu.nds_com = false;
        let mut buf = BytesMut::new();
        pdu.encode_ber(&mut buf).unwrap();
        let bytes: &[u8] = &buf;
        assert!(
            bytes.windows(1).any(|w| w[0] == 0x87),
            "simulation tag 0x87 present on the wire"
        );
        assert!(
            bytes.windows(1).any(|w| w[0] == 0x89),
            "ndscom tag 0x89 present on the wire"
        );
    }

    #[test]
    fn go_id_none_fills_gocb_ref_on_wire() {
        let pdu = sample_pdu();
        let mut buf = BytesMut::new();
        pdu.encode_ber(&mut buf).unwrap();
        let decoded = GoosePdu::decode_ber(&buf).unwrap();
        // The decoded goID equals the gocbRef that was substituted.
        assert_eq!(decoded.go_id, Some(pdu.gocb_ref.clone()));
    }

    #[test]
    fn bit_string_round_trip() {
        let mut pdu = sample_pdu();
        pdu.all_data = vec![MmsValue::BitString {
            padding: 3,
            data: vec![0b10110000, 0b11000000],
        }];
        pdu.num_dataset_entries = 1;
        let mut buf = BytesMut::new();
        pdu.encode_ber(&mut buf).unwrap();
        let decoded = GoosePdu::decode_ber(&buf).unwrap();
        assert_eq!(
            decoded.all_data[0],
            MmsValue::BitString {
                padding: 3,
                data: vec![0b10110000, 0b11000000],
            }
        );
    }

    #[test]
    fn reject_st_num_zero() {
        let mut pdu = sample_pdu();
        pdu.st_num = 1;
        let mut buf = BytesMut::new();
        pdu.encode_ber(&mut buf).unwrap();
        let bytes: Vec<u8> = buf.to_vec();
        let mut poisoned = bytes.clone();
        // Patch the stNum TLV 0x85 0x01 0x01 to carry 0x00.
        for i in 0..poisoned.len().saturating_sub(2) {
            if poisoned[i] == 0x85 && poisoned[i + 1] == 0x01 && poisoned[i + 2] == 0x01 {
                poisoned[i + 2] = 0x00;
                break;
            }
        }
        let result = GoosePdu::decode_ber(&poisoned);
        assert!(
            matches!(result, Err(GooseError::InvalidStateNumber)),
            "stnum 0 must return invalidstatenumber, got {:?}",
            result
        );
    }

    #[test]
    fn accept_sq_num_zero_first_packet() {
        // sqNum 0 with a valid stNum must decode.
        let mut pdu = sample_pdu();
        pdu.st_num = 1;
        pdu.sq_num = 0;
        let mut buf = BytesMut::new();
        pdu.encode_ber(&mut buf).unwrap();
        let decoded = GoosePdu::decode_ber(&buf).expect("sqnum 0 is a valid first frame");
        assert_eq!(decoded.sq_num, 0);
        assert_eq!(decoded.st_num, 1);
    }

    #[test]
    fn reject_num_dataset_entries_mismatch() {
        let mut pdu = sample_pdu();
        pdu.num_dataset_entries = 3; // all_data holds one entry
        let mut buf = BytesMut::new();
        // encode writes the value as given; decode is where it is checked.
        pdu.encode_ber(&mut buf).unwrap();
        let result = GoosePdu::decode_ber(&buf);
        assert!(
            matches!(
                result,
                Err(GooseError::DataSetLengthMismatch {
                    expected: 3,
                    actual: 1
                })
            ),
            "expected datasetlengthmismatch, got {:?}",
            result
        );
    }

    #[test]
    fn reject_invalid_timestamp_length() {
        // Build the PDU rather than patching one, so the outer BER length
        // stays consistent with the shortened t field.
        let poisoned = build_pdu_with_bad_timestamp();
        let result = GoosePdu::decode_ber(&poisoned);
        assert!(
            matches!(result, Err(GooseError::InvalidTimestamp)),
            "a timestamp that is not 8 bytes must return invalidtimestamp, got {:?}",
            result
        );
    }

    /// Builds a PDU whose t field is 6 bytes instead of 8.
    fn build_pdu_with_bad_timestamp() -> Vec<u8> {
        let mut pdu_inner = BytesMut::new();
        write_string_tlv(&mut pdu_inner, TAG_GOCB_REF, "A/L$GO$gcb");
        write_u32_tlv(&mut pdu_inner, TAG_TIME_ALLOWED, 2000);
        write_string_tlv(&mut pdu_inner, TAG_DAT_SET, "A/L$DS");
        write_string_tlv(&mut pdu_inner, TAG_GO_ID, "A/L$GO$gcb");
        // t must be 8 bytes.
        write_tlv(&mut pdu_inner, TAG_T, &[0x00u8; 6]);
        write_u32_tlv(&mut pdu_inner, TAG_ST_NUM, 1);
        write_u32_tlv(&mut pdu_inner, TAG_SQ_NUM, 1);
        write_bool_tlv(&mut pdu_inner, TAG_SIMULATION, false);
        write_u32_tlv(&mut pdu_inner, TAG_CONF_REV, 1);
        write_bool_tlv(&mut pdu_inner, TAG_NDS_COM, false);
        write_u32_tlv(&mut pdu_inner, TAG_NUM_DATASET_ENTRIES, 0);
        write_tlv(&mut pdu_inner, TAG_ALL_DATA, &[]);

        let mut result = BytesMut::new();
        result.extend_from_slice(&[TAG_GOOSE_PDU]);
        encode_length(pdu_inner.len(), &mut result);
        result.extend_from_slice(&pdu_inner);
        result.to_vec()
    }

    #[test]
    fn reject_invalid_bit_string_padding() {
        let mut pdu = sample_pdu();
        pdu.all_data = vec![MmsValue::BitString {
            padding: 8, // out of range
            data: vec![0xFF],
        }];
        let mut buf = BytesMut::new();
        pdu.encode_ber(&mut buf).unwrap();
        let result = GoosePdu::decode_ber(&buf);
        assert!(
            matches!(result, Err(GooseError::InvalidPadding(8))),
            "padding 8 must return invalidpadding, got {:?}",
            result
        );
    }

    #[test]
    fn reject_integer_too_long() {
        let pdu = sample_pdu();
        let mut buf = BytesMut::new();
        pdu.encode_ber(&mut buf).unwrap();
        let poisoned = build_poison_pdu_with_long_integer();
        let result = GoosePdu::decode_ber(&poisoned);
        assert!(
            matches!(result, Err(GooseError::LengthMismatch)),
            "an integer over 8 bytes must return lengthmismatch, got {:?}",
            result
        );
    }

    /// Builds the over-long integer vector: an allData INTEGER with 9 content bytes.
    fn build_poison_pdu_with_long_integer() -> Vec<u8> {
        let mut all_data_inner = BytesMut::new();
        // tag 0x85, length 9, nine content bytes
        all_data_inner.extend_from_slice(&[
            0x85, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);

        let mut all_data = BytesMut::new();
        all_data.extend_from_slice(&[TAG_ALL_DATA]);
        encode_length(all_data_inner.len(), &mut all_data);
        all_data.extend_from_slice(&all_data_inner);

        build_minimal_pdu_with_all_data(&all_data, 1)
    }

    /// Builds a minimal valid PDU carrying the given allData bytes.
    fn build_minimal_pdu_with_all_data(all_data_bytes: &[u8], num_entries: u32) -> Vec<u8> {
        let mut pdu_inner = BytesMut::new();

        write_string_tlv(&mut pdu_inner, TAG_GOCB_REF, "A/L$GO$gcb");
        write_u32_tlv(&mut pdu_inner, TAG_TIME_ALLOWED, 2000);
        write_string_tlv(&mut pdu_inner, TAG_DAT_SET, "A/L$DS");
        write_string_tlv(&mut pdu_inner, TAG_GO_ID, "A/L$GO$gcb");
        write_tlv(&mut pdu_inner, TAG_T, &[0u8; 8]);
        write_u32_tlv(&mut pdu_inner, TAG_ST_NUM, 1);
        write_u32_tlv(&mut pdu_inner, TAG_SQ_NUM, 1);
        write_bool_tlv(&mut pdu_inner, TAG_SIMULATION, false);
        write_u32_tlv(&mut pdu_inner, TAG_CONF_REV, 1);
        write_bool_tlv(&mut pdu_inner, TAG_NDS_COM, false);
        write_u32_tlv(&mut pdu_inner, TAG_NUM_DATASET_ENTRIES, num_entries);
        pdu_inner.extend_from_slice(all_data_bytes);

        let mut result = BytesMut::new();
        result.extend_from_slice(&[TAG_GOOSE_PDU]);
        encode_length(pdu_inner.len(), &mut result);
        result.extend_from_slice(&pdu_inner);
        result.to_vec()
    }

    /// An allData element whose length exceeds the
    /// bytes present is rejected without reading past the buffer.
    #[test]
    fn element_length_overflow_rejected() {
        let mut all_data_inner = BytesMut::new();
        // tag 0x83 BOOLEAN claiming 0xFF bytes with only one byte present
        all_data_inner.extend_from_slice(&[0x83, 0xFF, 0x01]);

        let mut all_data = BytesMut::new();
        all_data.extend_from_slice(&[TAG_ALL_DATA]);
        encode_length(all_data_inner.len(), &mut all_data);
        all_data.extend_from_slice(&all_data_inner);

        let poisoned = build_minimal_pdu_with_all_data(&all_data, 1);
        let result = GoosePdu::decode_ber(&poisoned);
        assert!(
            result.is_err(),
            "out-of-bounds length returns err without panicking"
        );
    }

    /// An indefinite BER length is rejected.
    #[test]
    fn indefinite_length_rejected() {
        // Outer 0x61 followed by the indefinite length marker 0x80.
        let poisoned = vec![0x61, 0x80, 0x00, 0x00];
        let result = GoosePdu::decode_ber(&poisoned);
        assert!(result.is_err(), "indefinite length returns err");
    }

    #[test]
    fn missing_timestamp_rejected() {
        let mut pdu_inner = BytesMut::new();
        write_string_tlv(&mut pdu_inner, TAG_GOCB_REF, "A/L$GO$gcb");
        write_u32_tlv(&mut pdu_inner, TAG_TIME_ALLOWED, 2000);
        write_string_tlv(&mut pdu_inner, TAG_DAT_SET, "A/L$DS");
        write_string_tlv(&mut pdu_inner, TAG_GO_ID, "A/L$GO$gcb");
        // TAG_T is deliberately omitted.
        write_u32_tlv(&mut pdu_inner, TAG_ST_NUM, 1);
        write_u32_tlv(&mut pdu_inner, TAG_SQ_NUM, 1);
        write_bool_tlv(&mut pdu_inner, TAG_SIMULATION, false);
        write_u32_tlv(&mut pdu_inner, TAG_CONF_REV, 1);
        write_bool_tlv(&mut pdu_inner, TAG_NDS_COM, false);
        write_u32_tlv(&mut pdu_inner, TAG_NUM_DATASET_ENTRIES, 0);

        let mut all_data = BytesMut::new();
        write_tlv(&mut all_data, TAG_ALL_DATA, &[]);
        pdu_inner.extend_from_slice(&all_data);

        let mut result_buf = BytesMut::new();
        result_buf.extend_from_slice(&[TAG_GOOSE_PDU]);
        encode_length(pdu_inner.len(), &mut result_buf);
        result_buf.extend_from_slice(&pdu_inner);

        let result = GoosePdu::decode_ber(&result_buf);
        assert!(
            matches!(result, Err(GooseError::MissingTimestamp)),
            "a missing timestamp must return missingtimestamp, got {:?}",
            result
        );
    }

    #[test]
    fn reject_field_too_long() {
        let mut pdu = sample_pdu();
        // gocbRef longer than the 129-byte limit.
        pdu.gocb_ref = "A".repeat(130);
        let mut buf = BytesMut::new();
        pdu.encode_ber(&mut buf).unwrap();
        let result = GoosePdu::decode_ber(&buf);
        assert!(
            matches!(result, Err(GooseError::FieldTooLong(130))),
            "an over-long gocbref must return fieldtoolong, got {:?}",
            result
        );
    }

    #[test]
    fn nested_array_round_trip() {
        let mut pdu = sample_pdu();
        pdu.all_data = vec![MmsValue::Array(vec![
            MmsValue::Boolean(true),
            MmsValue::Integer(99),
        ])];
        pdu.num_dataset_entries = 1;
        let mut buf = BytesMut::new();
        pdu.encode_ber(&mut buf).unwrap();
        let decoded = GoosePdu::decode_ber(&buf).unwrap();
        assert_eq!(decoded.all_data[0], pdu.all_data[0]);
    }

    #[test]
    fn example_pdu_byte_level() {
        let pdu = sample_pdu();
        let mut buf = BytesMut::new();
        let encoded_len = pdu.encode_ber(&mut buf).unwrap();
        assert!(encoded_len > 10, "encoded pdu is longer than 10 bytes");
        assert_eq!(buf[0], 0x61, "outer tag is 0x61");

        let decoded = GoosePdu::decode_ber(&buf).unwrap();
        assert_eq!(decoded.gocb_ref, "A/L$GO$gcb");
        assert_eq!(decoded.all_data, vec![MmsValue::Boolean(true)]);
    }

    #[test]
    fn u32_encode_compression() {
        // Content shrinks to one byte, and gains a 0x00 sign byte whenever the
        // leading byte would otherwise set bit 7.
        assert_eq!(encode_u32_integer(0), vec![0x00]);
        assert_eq!(encode_u32_integer(1), vec![0x01]);
        assert_eq!(encode_u32_integer(127), vec![0x7F]);
        assert_eq!(encode_u32_integer(128), vec![0x00, 0x80]);
        assert_eq!(
            encode_u32_integer(u32::MAX),
            vec![0x00, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    #[test]
    fn negative_integer_round_trip() {
        for &v in &[-1i64, -128, -32768, i64::MIN] {
            let mut pdu = sample_pdu();
            pdu.all_data = vec![MmsValue::Integer(v)];
            pdu.num_dataset_entries = 1;
            let mut buf = BytesMut::new();
            pdu.encode_ber(&mut buf).unwrap();
            let decoded = GoosePdu::decode_ber(&buf).unwrap();
            assert_eq!(
                decoded.all_data[0],
                MmsValue::Integer(v),
                "negative integer {} survives a round trip",
                v
            );
        }
    }

    #[test]
    fn mms_string_uses_tag_0x90() {
        let mut buf = BytesMut::new();
        encode_mms_value(&MmsValue::MmsString("hello".to_string()), &mut buf, 0).unwrap();
        assert_eq!(
            buf[0], TAG_DATA_MMS_STRING,
            "mmsstring encodes with tag 0x90, got 0x{:02x}",
            buf[0]
        );

        // The value type must survive encode and decode inside allData.
        let mut pdu = sample_pdu();
        pdu.all_data = vec![MmsValue::MmsString("hello".to_string())];
        pdu.num_dataset_entries = 1;
        let mut pdu_buf = BytesMut::new();
        pdu.encode_ber(&mut pdu_buf).unwrap();
        let decoded = GoosePdu::decode_ber(&pdu_buf).unwrap();
        assert_eq!(
            decoded.all_data[0],
            MmsValue::MmsString("hello".to_string()),
            "round trip preserves mmsstring rather than visiblestring"
        );
    }

    #[test]
    fn unsigned_encode_sign_safe() {
        // Every value whose leading byte sets bit 7 gains a 0x00 sign byte, so
        // it never decodes as a negative BER integer.
        let cases: &[(u64, &[u8])] = &[
            (0, &[0x00]),
            (127, &[0x7F]),
            (128, &[0x00, 0x80]),
            (255, &[0x00, 0xFF]),
            (65535, &[0x00, 0xFF, 0xFF]),
            (0xFFFF_FFFF, &[0x00, 0xFF, 0xFF, 0xFF, 0xFF]),
        ];
        for &(v, expected_value_bytes) in cases {
            let mut buf = BytesMut::new();
            encode_mms_value(&MmsValue::Unsigned(v), &mut buf, 0).unwrap();
            // Layout is tag, one length byte, then the content.
            let tag = buf[0];
            assert_eq!(tag, TAG_DATA_UNSIGNED, "unsigned tag is 0x86");
            let len = buf[1] as usize;
            let value_bytes = &buf[2..2 + len];
            assert_eq!(
                value_bytes, expected_value_bytes,
                "unsigned({}) encodes to {:?}, got {:?}",
                v, expected_value_bytes, value_bytes
            );
        }
    }
}
