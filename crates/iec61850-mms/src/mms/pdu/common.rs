//! Data structures shared by the MMS Read and Write services.
//!
//! ## Depth guard
//!
//! `MmsData::decode_with_depth` carries a depth parameter bounded by
//! `MAX_DATA_NESTING_DEPTH` (32) and returns `MmsError::NestingLevelExceeded`
//! beyond it, so nesting depth never depends on the call stack.
//!
//! ## Tag assignment
//!
//! The AccessResult CHOICE tags and the Data CHOICE tags are those of the MMS
//! ASN.1 definition, and the two sets coincide.

use super::super::error::MmsError;
use super::initiate::{decode_length, encode_length};
use crate::compat::prelude::*;
use bytes::BytesMut;

// Constants

/// Default local ceiling for recursive Data and AccessResult decoding, re-exported
/// from `iec61850-asn1`.
///
/// See `iec61850_asn1::MAX_DATA_NESTING_DEPTH` for the rationale.
pub use iec61850_asn1::MAX_DATA_NESTING_DEPTH;

/// Computes the effective decode depth ceiling, re-exported from `iec61850-asn1`.
///
/// See `iec61850_asn1::effective_nesting_cap`.
pub use iec61850_asn1::effective_nesting_cap;

/// Maximum length in bytes of an ObjectName identifier.
///
/// An identifier longer than this is rejected rather than silently truncated.
pub const MAX_IDENTIFIER_LEN: usize = 64;

// DataAccessError

/// MMS DataAccessError.
///
/// The eleven standard codes 0 to 11, each encoded as a single-byte BER INTEGER.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DataAccessError {
    /// The object has been invalidated.
    ObjectInvalidated = 0,
    /// A hardware fault prevented the access.
    HardwareFault = 1,
    /// The object is temporarily unavailable.
    TemporarilyUnavailable = 2,
    /// Access to the object was denied.
    ObjectAccessDenied = 3,
    /// The object is not defined.
    ObjectUndefined = 4,
    /// The address is invalid.
    InvalidAddress = 5,
    /// The type is not supported.
    TypeUnsupported = 6,
    /// The value type does not match the type of the object.
    TypeInconsistent = 7,
    /// An object attribute is inconsistent with the request.
    ObjectAttributeInconsistent = 8,
    /// The requested kind of access is not supported for this object.
    ObjectAccessUnsupported = 9,
    /// The object does not exist.
    ObjectNonExistent = 10,
    /// The value is invalid for this object.
    ObjectValueInvalid = 11,
}

impl DataAccessError {
    /// Converts a code from the wire; a value above 11 returns an error.
    pub fn from_code(code: u8) -> Result<Self, MmsError> {
        match code {
            0 => Ok(Self::ObjectInvalidated),
            1 => Ok(Self::HardwareFault),
            2 => Ok(Self::TemporarilyUnavailable),
            3 => Ok(Self::ObjectAccessDenied),
            4 => Ok(Self::ObjectUndefined),
            5 => Ok(Self::InvalidAddress),
            6 => Ok(Self::TypeUnsupported),
            7 => Ok(Self::TypeInconsistent),
            8 => Ok(Self::ObjectAttributeInconsistent),
            9 => Ok(Self::ObjectAccessUnsupported),
            10 => Ok(Self::ObjectNonExistent),
            11 => Ok(Self::ObjectValueInvalid),
            other => {
                tracing::warn!("unknown dataaccesserror code {}, rejecting", other);
                Err(MmsError::UnknownDataAccessError(other))
            }
        }
    }

    /// Returns the INTEGER byte written on the wire.
    pub fn code(self) -> u8 {
        self as u8
    }
}

// ObjectName

/// The MMS ObjectName CHOICE, as defined in ISO 9506-2.
///
/// Wire tags:
/// - vmd-specific: `0x80`, CONTEXT `[0]` IMPLICIT primitive
/// - domain-specific: `0xa1`, CONTEXT `[1]` IMPLICIT SEQUENCE
/// - aa-specific: `0x82`, CONTEXT `[2]` IMPLICIT primitive
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectName {
    /// `0x80`: vmd-specific, a name unique across the VMD.
    VmdSpecific(String),
    /// `0xa1`: domain-specific, a domain name and an item name.
    DomainSpecific {
        /// Domain that holds the object.
        domain_id: String,
        /// Name of the object within the domain.
        item_id: String,
    },
    /// `0x82`: aa-specific, scoped to the association.
    AaSpecific(String),
}

impl ObjectName {
    /// Encodes the ObjectName into `buf`.
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            ObjectName::VmdSpecific(name) => {
                let b = name.as_bytes();
                buf.extend_from_slice(&[0x80]);
                encode_length(b.len(), buf);
                buf.extend_from_slice(b);
            }
            ObjectName::DomainSpecific { domain_id, item_id } => {
                // 0xa1 <inner_len> 0x1a <dlen> <domain> 0x1a <ilen> <item>
                let db = domain_id.as_bytes();
                let ib = item_id.as_bytes();
                let inner_len = 2 + db.len() + 2 + ib.len();
                buf.extend_from_slice(&[0xa1]);
                encode_length(inner_len, buf);
                // domainId, UNIVERSAL VisibleString (tag 26)
                buf.extend_from_slice(&[0x1a]);
                encode_length(db.len(), buf);
                buf.extend_from_slice(db);
                // itemId VisibleString
                buf.extend_from_slice(&[0x1a]);
                encode_length(ib.len(), buf);
                buf.extend_from_slice(ib);
            }
            ObjectName::AaSpecific(name) => {
                let b = name.as_bytes();
                buf.extend_from_slice(&[0x82]);
                encode_length(b.len(), buf);
                buf.extend_from_slice(b);
            }
        }
    }

    /// Decodes an ObjectName; `data` starts at the tag byte.
    ///
    /// An identifier longer than 64 bytes returns `MmsError::IdentifierTooLong`
    /// rather than being silently truncated.
    pub fn decode(data: &[u8]) -> Result<(Self, usize), MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        let tag = data[0];
        let (len, hdr) = decode_length(&data[1..])?;
        let val_start = 1 + hdr;
        if val_start + len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let val = &data[val_start..val_start + len];
        let consumed = val_start + len;

        match tag {
            0x80 => {
                // vmd-specific
                if len > MAX_IDENTIFIER_LEN {
                    tracing::warn!(
                        "vmd-specific objectname identifier of {} bytes exceeds the limit of {}",
                        len,
                        MAX_IDENTIFIER_LEN
                    );
                    return Err(MmsError::IdentifierTooLong { actual: len });
                }
                let name = core::str::from_utf8(val)
                    .map_err(|_| MmsError::InvalidUtf8)?
                    .to_owned();
                Ok((ObjectName::VmdSpecific(name), consumed))
            }
            0xa1 => {
                // domain-specific: 0x1a <len> <domain> 0x1a <len> <item>
                let (domain_id, item_id) = decode_domain_specific(val)?;
                Ok((ObjectName::DomainSpecific { domain_id, item_id }, consumed))
            }
            0x82 => {
                // aa-specific
                if len > MAX_IDENTIFIER_LEN {
                    tracing::warn!(
                        "aa-specific objectname identifier of {} bytes exceeds the limit of {}",
                        len,
                        MAX_IDENTIFIER_LEN
                    );
                    return Err(MmsError::IdentifierTooLong { actual: len });
                }
                let name = core::str::from_utf8(val)
                    .map_err(|_| MmsError::InvalidUtf8)?
                    .to_owned();
                Ok((ObjectName::AaSpecific(name), consumed))
            }
            other => {
                tracing::warn!("unknown objectname tag 0x{:02X}, rejecting", other);
                Err(MmsError::UnknownObjectNameTag(other))
            }
        }
    }

    /// Returns the encoded length in bytes without writing anything.
    pub fn encoded_len(&self) -> usize {
        match self {
            ObjectName::VmdSpecific(name) => {
                let b = name.as_bytes();
                1 + ber_len_size(b.len()) + b.len()
            }
            ObjectName::DomainSpecific { domain_id, item_id } => {
                let db = domain_id.as_bytes();
                let ib = item_id.as_bytes();
                let inner = 2 + db.len() + 2 + ib.len();
                1 + ber_len_size(inner) + inner
            }
            ObjectName::AaSpecific(name) => {
                let b = name.as_bytes();
                1 + ber_len_size(b.len()) + b.len()
            }
        }
    }
}

/// Decodes the inner content of a domain-specific name, the content of the 0xa1 wrapper.
fn decode_domain_specific(val: &[u8]) -> Result<(String, String), MmsError> {
    if val.len() < 2 {
        return Err(MmsError::TruncatedPdu);
    }
    // domainId, UNIVERSAL VisibleString tag 0x1a
    if val[0] != 0x1a {
        return Err(MmsError::InvalidTag {
            expected: 0x1a,
            actual: val[0],
        });
    }
    let (dlen, dhdr) = decode_length(&val[1..])?;
    let dstart = 1 + dhdr;
    if dstart + dlen > val.len() {
        return Err(MmsError::TruncatedPdu);
    }
    if dlen > MAX_IDENTIFIER_LEN {
        tracing::warn!(
            "domain identifier of {} bytes exceeds the limit of {}, rejecting rather than truncating",
            dlen,
            MAX_IDENTIFIER_LEN
        );
        return Err(MmsError::IdentifierTooLong { actual: dlen });
    }
    let domain_id = core::str::from_utf8(&val[dstart..dstart + dlen])
        .map_err(|_| MmsError::InvalidUtf8)?
        .to_owned();
    let item_start = dstart + dlen;

    // itemId, UNIVERSAL VisibleString tag 0x1a
    if item_start >= val.len() {
        return Err(MmsError::TruncatedPdu);
    }
    if val[item_start] != 0x1a {
        return Err(MmsError::InvalidTag {
            expected: 0x1a,
            actual: val[item_start],
        });
    }
    let (ilen, ihdr) = decode_length(&val[item_start + 1..])?;
    let istart = item_start + 1 + ihdr;
    if istart + ilen > val.len() {
        return Err(MmsError::TruncatedPdu);
    }
    if ilen > MAX_IDENTIFIER_LEN {
        tracing::warn!(
            "item identifier of {} bytes exceeds the limit of {}, rejecting rather than truncating",
            ilen,
            MAX_IDENTIFIER_LEN
        );
        return Err(MmsError::IdentifierTooLong { actual: ilen });
    }
    let item_id = core::str::from_utf8(&val[istart..istart + ilen])
        .map_err(|_| MmsError::InvalidUtf8)?
        .to_owned();
    Ok((domain_id, item_id))
}

// VariableAccessSpecification

/// The MMS VariableAccessSpecification CHOICE.
///
/// Wire tags:
/// - `listOfVariable`: `0xa0`, CONTEXT `[0]` IMPLICIT CONSTRUCTED
/// - `variableListName`: `0xa1`, CONTEXT `[1]` EXPLICIT CONSTRUCTED
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VariableAccessSpecification {
    /// `0xa0`: an explicit list of variables, a SEQUENCE OF ListOfVariableSeq.
    /// Each entry is an `ObjectName` with an optional `AlternateAccess`.
    ListOfVariable(Vec<ListOfVariableEntry>),
    /// `0xa1`: a reference to a named variable list.
    VariableListName(ObjectName),
}

/// One entry inside `listOfVariable`: an `ObjectName` plus an optional
/// `AlternateAccess` selector for array element / sub-component access.
///
/// Wire layout per entry (ASN.1 `ListOfVariableSeq`):
/// ```text
/// 0x30 <len>            -- UNIVERSAL SEQUENCE
///   0xa0 <len>          -- variableSpecification.name [0] IMPLICIT
///     <ObjectName body>
///   [<AlternateAccess>] -- OPTIONAL: 0x30 <len> ... (SEQUENCE OF)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListOfVariableEntry {
    /// Name of the variable this entry refers to.
    pub name: ObjectName,
    /// Optional selector narrowing the access to part of that variable.
    pub alt_access: Option<AlternateAccess>,
}

impl ListOfVariableEntry {
    /// Build an entry with no `AlternateAccess`.
    pub fn name(name: ObjectName) -> Self {
        Self {
            name,
            alt_access: None,
        }
    }

    /// Build an entry with an `AlternateAccess` selector attached.
    pub fn with_alt_access(name: ObjectName, alt_access: AlternateAccess) -> Self {
        Self {
            name,
            alt_access: Some(alt_access),
        }
    }
}

impl From<ObjectName> for ListOfVariableEntry {
    fn from(name: ObjectName) -> Self {
        Self::name(name)
    }
}

impl VariableAccessSpecification {
    /// Encodes the VariableAccessSpecification into `buf`.
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            VariableAccessSpecification::ListOfVariable(entries) => {
                // 0xa0 <inner_len> SEQUENCE OF ListOfVariableSeq
                // each ListOfVariableSeq is 0x30 <len> <VariableSpec> [<AlternateAccess>]
                let mut inner = BytesMut::new();
                for entry in entries {
                    encode_list_of_variable_seq(entry, &mut inner);
                }
                buf.extend_from_slice(&[0xa0]);
                encode_length(inner.len(), buf);
                buf.extend_from_slice(&inner);
            }
            VariableAccessSpecification::VariableListName(name) => {
                // 0xa1 <len> <ObjectName>
                let mut inner = BytesMut::new();
                name.encode(&mut inner);
                buf.extend_from_slice(&[0xa1]);
                encode_length(inner.len(), buf);
                buf.extend_from_slice(&inner);
            }
        }
    }

    /// Decodes a VariableAccessSpecification; `data` starts at the tag byte.
    pub fn decode(data: &[u8]) -> Result<(Self, usize), MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        let tag = data[0];
        let (len, hdr) = decode_length(&data[1..])?;
        let inner_start = 1 + hdr;
        if inner_start + len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let inner = &data[inner_start..inner_start + len];
        let consumed = inner_start + len;

        match tag {
            0xa0 => {
                // listOfVariable, a SEQUENCE OF ListOfVariableSeq
                let entries = decode_list_of_variable(inner)?;
                Ok((
                    VariableAccessSpecification::ListOfVariable(entries),
                    consumed,
                ))
            }
            0xa1 => {
                // variableListName, an EXPLICIT ObjectName
                let (name, _) = ObjectName::decode(inner)?;
                Ok((
                    VariableAccessSpecification::VariableListName(name),
                    consumed,
                ))
            }
            other => {
                tracing::warn!(
                    "unknown variableaccessspecification tag 0x{:02X}, rejecting",
                    other
                );
                Err(MmsError::UnknownVasTag(other))
            }
        }
    }

    /// Returns the encoded length in bytes.
    pub fn encoded_len(&self) -> usize {
        match self {
            VariableAccessSpecification::ListOfVariable(entries) => {
                let inner: usize = entries.iter().map(list_of_variable_seq_len).sum();
                1 + ber_len_size(inner) + inner
            }
            VariableAccessSpecification::VariableListName(name) => {
                let inner = name.encoded_len();
                1 + ber_len_size(inner) + inner
            }
        }
    }
}

/// Encode one `ListOfVariableSeq` (name + optional `AlternateAccess`).
///
/// The `alternateAccess` field of `ListOfVariableSeq` is `[5] IMPLICIT`
/// per the MMS ASN.1 module, so the wire tag is `0xa5` (CONTEXT
/// CONSTRUCTED) rather than the canonical `0x30` (universal SEQUENCE OF)
/// that [`AlternateAccess::encode`] produces. We rewrite the leading byte
/// in place after emitting the canonical form.
fn encode_list_of_variable_seq(entry: &ListOfVariableEntry, buf: &mut BytesMut) {
    let mut seq_inner = BytesMut::new();
    encode_variable_specification_name(&entry.name, &mut seq_inner);
    if let Some(aa) = &entry.alt_access {
        let aa_start = seq_inner.len();
        aa.encode(&mut seq_inner);
        debug_assert_eq!(seq_inner[aa_start], 0x30);
        seq_inner[aa_start] = 0xa5;
    }
    buf.extend_from_slice(&[0x30]);
    encode_length(seq_inner.len(), buf);
    buf.extend_from_slice(&seq_inner);
}

/// Encodes VariableSpecification.name, tag 0xa0 IMPLICIT CONSTRUCTED over an ObjectName.
fn encode_variable_specification_name(name: &ObjectName, buf: &mut BytesMut) {
    let mut obj_buf = BytesMut::new();
    name.encode(&mut obj_buf);
    buf.extend_from_slice(&[0xa0]);
    encode_length(obj_buf.len(), buf);
    buf.extend_from_slice(&obj_buf);
}

/// Decode `listOfVariable` inner (`data` is the body of the outer `0xa0`).
fn decode_list_of_variable(data: &[u8]) -> Result<Vec<ListOfVariableEntry>, MmsError> {
    let mut entries = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        if data[pos] != 0x30 {
            tracing::warn!(
                "listOfVariable expected SEQUENCE tag 0x30, got 0x{:02X}",
                data[pos]
            );
            return Err(MmsError::InvalidTag {
                expected: 0x30,
                actual: data[pos],
            });
        }
        let (seq_len, seq_hdr) = decode_length(&data[pos + 1..])?;
        let seq_start = pos + 1 + seq_hdr;
        if seq_start + seq_len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let seq_inner = &data[seq_start..seq_start + seq_len];
        pos = seq_start + seq_len;

        // VariableSpecification.name [0] IMPLICIT = 0xa0
        if seq_inner.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        if seq_inner[0] != 0xa0 {
            tracing::warn!(
                "VariableSpecification expected name tag 0xa0, got 0x{:02X}",
                seq_inner[0]
            );
            return Err(MmsError::InvalidTag {
                expected: 0xa0,
                actual: seq_inner[0],
            });
        }
        let (vs_len, vs_hdr) = decode_length(&seq_inner[1..])?;
        let vs_start = 1 + vs_hdr;
        if vs_start + vs_len > seq_inner.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let obj_data = &seq_inner[vs_start..vs_start + vs_len];
        let (name, _) = ObjectName::decode(obj_data)?;

        // Optional AlternateAccess: tail of the SEQUENCE.
        //
        // Per the MMS ASN.1 module, `alternateAccess` here is `[5] IMPLICIT`
        // so the wire tag is `0xa5`, not the canonical `0x30` that
        // `AlternateAccess::decode` expects. Substitute the leading byte
        // locally and reuse the same decoder.
        let tail_start = vs_start + vs_len;
        let alt_access = if tail_start < seq_inner.len() {
            let tail = &seq_inner[tail_start..];
            if tail[0] != 0xa5 {
                tracing::warn!(
                    "ListOfVariableSeq AlternateAccess expected tag 0xa5, got 0x{:02X}",
                    tail[0]
                );
                return Err(MmsError::InvalidTag {
                    expected: 0xa5,
                    actual: tail[0],
                });
            }
            let mut local = tail.to_vec();
            local[0] = 0x30;
            let (aa, consumed) = AlternateAccess::decode(&local)?;
            if consumed != local.len() {
                tracing::warn!(
                    "ListOfVariableSeq has trailing bytes after AlternateAccess ({} remaining)",
                    local.len() - consumed
                );
                return Err(MmsError::TruncatedPdu);
            }
            Some(aa)
        } else {
            None
        };

        entries.push(ListOfVariableEntry { name, alt_access });
    }
    Ok(entries)
}

/// Compute the encoded byte length of one `ListOfVariableSeq`.
fn list_of_variable_seq_len(entry: &ListOfVariableEntry) -> usize {
    let obj_len = entry.name.encoded_len();
    let vs_len = 1 + ber_len_size(obj_len) + obj_len;
    let aa_len = entry
        .alt_access
        .as_ref()
        .map_or(0, AlternateAccess::encoded_len);
    let seq_inner = vs_len + aa_len;
    1 + ber_len_size(seq_inner) + seq_inner
}

// MmsData, the Data CHOICE

/// The MMS Data CHOICE.
///
/// Owns its payload, so a decoded value outlives the input buffer.
///
/// ## Tag assignment, CONTEXT IMPLICIT
///
/// | variant        | primitive tag        | constructed tag        |
/// |---------------|----------------------|------------------------|
/// | failure        | `0x80`               |                        |
/// | array          |                      | `0xa1`                 |
/// | structure      |                      | `0xa2`                 |
/// | boolean        | `0x83`               |                        |
/// | bit-string     | `0x84`               |                        |
/// | integer        | `0x85`               |                        |
/// | unsigned       | `0x86`               |                        |
/// | floating-point | `0x87`               |                        |
/// | octet-string   | `0x89`               |                        |
/// | visible-string | `0x8a`               |                        |
/// | generalized-time | `0x8b`            |                        |
/// | binary-time    | `0x8c`               |                        |
/// | bcd            | `0x8d`               |                        |
/// | boolean-array  | `0x8e`               |                        |
/// | mms-string     | `0x90`               |                        |
/// | utc-time       | `0x91`               |                        |
#[derive(Debug, Clone, PartialEq)]
pub enum MmsData {
    /// `0x83`: boolean.
    Boolean(bool),
    /// `0xa1`: array, decoded recursively.
    Array(Vec<MmsData>),
    /// `0xa2`: structure, decoded recursively.
    Structure(Vec<MmsData>),
    /// `0x85`: signed integer of 1 to 8 bytes, held as an `i64`.
    Integer(i64),
    /// `0x86`: unsigned integer of 1 to 8 bytes.
    Unsigned(u64),
    /// `0x87`: single-precision float, exponent width 8, five bytes on the wire.
    Float32(f32),
    /// `0x87`: double-precision float, exponent width 11, nine bytes on the wire.
    Float64(f64),
    /// `0x89`: octet string, raw bytes.
    OctetString(Vec<u8>),
    /// `0x8a`: visible string, ASCII.
    VisibleString(String),
    /// `0x8b`: generalized time, in VisibleString form.
    GeneralizedTime(String),
    /// `0x8c`: binary time, 4 or 6 bytes.
    BinaryTime(Vec<u8>),
    /// `0x8e`: boolean array, a BIT STRING.
    BooleanArray {
        /// Number of unused bits in the final data byte.
        padding: u8,
        /// Bit string content, most significant bit first.
        data: Vec<u8>,
    },
    /// `0x84`: bit string.
    BitString {
        /// Number of unused bits in the final data byte.
        padding: u8,
        /// Bit string content, most significant bit first.
        data: Vec<u8>,
    },
    /// `0x90`: MMS string, UTF-8.
    MmsString(String),
    /// `0x91`: UTC time, a fixed 8 bytes.
    UtcTime([u8; 8]),
}

impl MmsData {
    /// Decodes an `MmsData` under the default depth ceiling; `data` starts at the tag.
    pub fn decode(data: &[u8]) -> Result<(Self, usize), MmsError> {
        Self::decode_with_depth(data, 0)
    }

    /// Decodes an `MmsData` with an explicit depth guard.
    ///
    /// `depth` starts at 0 and rises by one per level; exceeding
    /// `MAX_DATA_NESTING_DEPTH` returns an error.
    ///
    /// This entry point applies the local ceiling only.
    pub fn decode_with_depth(data: &[u8], depth: u8) -> Result<(Self, usize), MmsError> {
        Self::decode_recursive(data, depth, MAX_DATA_NESTING_DEPTH)
    }

    /// Decodes an `MmsData` under a caller-supplied ceiling; `data` starts at the tag.
    ///
    /// `max_depth` is normally `effective_nesting_cap(MAX_DATA_NESTING_DEPTH, negotiated)`,
    /// the smaller of the local ceiling and the negotiated dataStructureNestingLevel.
    pub fn decode_with_max(data: &[u8], max_depth: u8) -> Result<(Self, usize), MmsError> {
        Self::decode_recursive(data, 0, max_depth)
    }

    /// Recursive decoder. `depth` is the current level and `max_depth` the ceiling.
    fn decode_recursive(data: &[u8], depth: u8, max_depth: u8) -> Result<(Self, usize), MmsError> {
        if depth > max_depth {
            tracing::warn!(
                "mmsdata recursion depth {} exceeds the effective cap {} (local cap {})",
                depth,
                max_depth,
                MAX_DATA_NESTING_DEPTH
            );
            return Err(MmsError::NestingLevelExceeded {
                max: max_depth,
                got: depth,
            });
        }
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        let tag = data[0];
        let (len, hdr) = decode_length(&data[1..])?;
        let val_start = 1 + hdr;
        if val_start + len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let val = &data[val_start..val_start + len];
        let consumed = val_start + len;

        let result = match tag {
            0x83 => {
                // boolean, one byte
                if val.is_empty() {
                    return Err(MmsError::InvalidLength);
                }
                MmsData::Boolean(val[0] != 0)
            }
            0xa1 => {
                // array, CONSTRUCTED and decoded recursively
                let items = decode_seq_of_mmsdata(val, depth + 1, max_depth)?;
                MmsData::Array(items)
            }
            0xa2 => {
                // structure, CONSTRUCTED and decoded recursively
                let items = decode_seq_of_mmsdata(val, depth + 1, max_depth)?;
                MmsData::Structure(items)
            }
            0x85 => {
                // integer, signed big-endian, 1 to 8 bytes
                let v = decode_signed_int(val)?;
                MmsData::Integer(v)
            }
            0x86 => {
                // unsigned, big-endian, 1 to 8 bytes
                let v = decode_unsigned_int(val)?;
                MmsData::Unsigned(v)
            }
            0x87 => {
                // floating point: the first byte is the exponent width, followed by
                // IEEE 754 big-endian. A size of 5 decodes to Float32 and 9 to Float64;
                // any other size is rejected rather than ignored.
                decode_floating_point(val)?
            }
            0x89 => {
                // octet-string
                MmsData::OctetString(val.to_vec())
            }
            0x8a => {
                // visible-string
                let s = core::str::from_utf8(val)
                    .map_err(|_| MmsError::InvalidUtf8)?
                    .to_owned();
                MmsData::VisibleString(s)
            }
            0x8b => {
                // generalized-time, in VisibleString form
                let s = core::str::from_utf8(val)
                    .map_err(|_| MmsError::InvalidUtf8)?
                    .to_owned();
                MmsData::GeneralizedTime(s)
            }
            0x8c => {
                // binary-time, 4 or 6 bytes
                if val.len() != 4 && val.len() != 6 {
                    tracing::warn!("invalid binarytime length {}, expected 4 or 6", val.len());
                    return Err(MmsError::InvalidLength);
                }
                MmsData::BinaryTime(val.to_vec())
            }
            0x84 => {
                // bit-string: the first byte is the padding count, then the data
                if val.is_empty() {
                    return Err(MmsError::InvalidLength);
                }
                MmsData::BitString {
                    padding: val[0],
                    data: val[1..].to_vec(),
                }
            }
            0x8e => {
                // boolean-array, a BIT STRING whose first byte is the padding count
                if val.is_empty() {
                    return Err(MmsError::InvalidLength);
                }
                MmsData::BooleanArray {
                    padding: val[0],
                    data: val[1..].to_vec(),
                }
            }
            0x90 => {
                // mms-string, UTF-8
                let s = core::str::from_utf8(val)
                    .map_err(|_| MmsError::InvalidUtf8)?
                    .to_owned();
                MmsData::MmsString(s)
            }
            0x91 => {
                // utc-time: exactly 8 bytes, any other length is rejected
                if val.len() != 8 {
                    tracing::warn!("invalid utctime length {}, expected 8", val.len());
                    return Err(MmsError::InvalidUtcTimeLength { actual: val.len() });
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(val);
                MmsData::UtcTime(arr)
            }
            other => {
                // tags [8] and [15] are not assigned in the Data CHOICE
                tracing::warn!("unknown mmsdata tag 0x{:02X}, rejecting", other);
                return Err(MmsError::UnknownDataTag(other));
            }
        };

        Ok((result, consumed))
    }

    /// Encodes the `MmsData` into `buf`.
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            MmsData::Boolean(v) => {
                buf.extend_from_slice(&[0x83, 0x01, if *v { 0xff } else { 0x00 }]);
            }
            MmsData::Array(items) => {
                let mut inner = BytesMut::new();
                for item in items {
                    item.encode(&mut inner);
                }
                buf.extend_from_slice(&[0xa1]);
                encode_length(inner.len(), buf);
                buf.extend_from_slice(&inner);
            }
            MmsData::Structure(items) => {
                let mut inner = BytesMut::new();
                for item in items {
                    item.encode(&mut inner);
                }
                buf.extend_from_slice(&[0xa2]);
                encode_length(inner.len(), buf);
                buf.extend_from_slice(&inner);
            }
            MmsData::Integer(v) => {
                let bytes = encode_signed_int_minimal(*v);
                buf.extend_from_slice(&[0x85]);
                encode_length(bytes.len(), buf);
                buf.extend_from_slice(&bytes);
            }
            MmsData::Unsigned(v) => {
                let bytes = encode_unsigned_int_minimal(*v);
                buf.extend_from_slice(&[0x86]);
                encode_length(bytes.len(), buf);
                buf.extend_from_slice(&bytes);
            }
            MmsData::Float32(v) => {
                // FLOAT32: exponent width 8 plus a 4-byte IEEE 754 single, 5 bytes total
                buf.extend_from_slice(&[0x87, 0x05, 0x08]);
                buf.extend_from_slice(&v.to_be_bytes());
            }
            MmsData::Float64(v) => {
                // FLOAT64: exponent width 11 plus an 8-byte IEEE 754 double, 9 bytes total
                buf.extend_from_slice(&[0x87, 0x09, 0x0b]);
                buf.extend_from_slice(&v.to_be_bytes());
            }
            MmsData::OctetString(bytes) => {
                buf.extend_from_slice(&[0x89]);
                encode_length(bytes.len(), buf);
                buf.extend_from_slice(bytes);
            }
            MmsData::VisibleString(s) => {
                let b = s.as_bytes();
                buf.extend_from_slice(&[0x8a]);
                encode_length(b.len(), buf);
                buf.extend_from_slice(b);
            }
            MmsData::GeneralizedTime(s) => {
                let b = s.as_bytes();
                buf.extend_from_slice(&[0x8b]);
                encode_length(b.len(), buf);
                buf.extend_from_slice(b);
            }
            MmsData::BinaryTime(bytes) => {
                buf.extend_from_slice(&[0x8c]);
                encode_length(bytes.len(), buf);
                buf.extend_from_slice(bytes);
            }
            MmsData::BitString { padding, data } => {
                buf.extend_from_slice(&[0x84]);
                encode_length(1 + data.len(), buf);
                buf.extend_from_slice(&[*padding]);
                buf.extend_from_slice(data);
            }
            MmsData::BooleanArray { padding, data } => {
                buf.extend_from_slice(&[0x8e]);
                encode_length(1 + data.len(), buf);
                buf.extend_from_slice(&[*padding]);
                buf.extend_from_slice(data);
            }
            MmsData::MmsString(s) => {
                let b = s.as_bytes();
                buf.extend_from_slice(&[0x90]);
                encode_length(b.len(), buf);
                buf.extend_from_slice(b);
            }
            MmsData::UtcTime(arr) => {
                buf.extend_from_slice(&[0x91, 0x08]);
                buf.extend_from_slice(arr);
            }
        }
    }

    /// Returns the number of bytes `encode` would write, tag and length included.
    ///
    /// The dispatcher uses this to check a ReadResponse against the negotiated
    /// maximum PDU size before assembling it.
    ///
    /// The branches mirror `encode` exactly and the walk is linear in the value:
    /// - a scalar costs constant time
    /// - an array or structure sums its members, then adds the outer tag and length
    pub fn estimated_encoded_size(&self) -> usize {
        match self {
            MmsData::Boolean(_) => 3, // 0x83 0x01 <bool>
            MmsData::Array(items) | MmsData::Structure(items) => {
                let inner: usize = items.iter().map(|i| i.estimated_encoded_size()).sum();
                1 + length_size(inner) + inner
            }
            MmsData::Integer(v) => {
                let n = encode_signed_int_minimal(*v).len();
                1 + length_size(n) + n
            }
            MmsData::Unsigned(v) => {
                let n = encode_unsigned_int_minimal(*v).len();
                1 + length_size(n) + n
            }
            MmsData::Float32(_) => 7,  // 0x87 0x05 0x08 + 4 bytes
            MmsData::Float64(_) => 11, // 0x87 0x09 0x0b + 8 bytes
            MmsData::OctetString(b) => 1 + length_size(b.len()) + b.len(),
            MmsData::VisibleString(s) => {
                let n = s.len();
                1 + length_size(n) + n
            }
            MmsData::GeneralizedTime(s) => {
                let n = s.len();
                1 + length_size(n) + n
            }
            MmsData::BinaryTime(b) => 1 + length_size(b.len()) + b.len(),
            MmsData::BitString { data, .. } | MmsData::BooleanArray { data, .. } => {
                let n = 1 + data.len(); // padding + data
                1 + length_size(n) + n
            }
            MmsData::MmsString(s) => {
                let n = s.len();
                1 + length_size(n) + n
            }
            MmsData::UtcTime(_) => 10, // 0x91 0x08 + 8 bytes
        }
    }
}

/// Returns the number of bytes a BER definite-form length occupies, matching `encode_length`.
fn length_size(len: usize) -> usize {
    if len < 128 {
        1
    } else if len <= 0xff {
        2
    } else {
        3
    }
}

/// Decodes a SEQUENCE OF Data, used for the inner content of an array or structure.
///
/// `depth` is the current recursion level and `max_depth` the effective ceiling.
fn decode_seq_of_mmsdata(data: &[u8], depth: u8, max_depth: u8) -> Result<Vec<MmsData>, MmsError> {
    let mut items = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let (item, consumed) = MmsData::decode_recursive(&data[pos..], depth, max_depth)?;
        items.push(item);
        pos += consumed;
    }
    Ok(items)
}

// AccessResult

/// The MMS AccessResult CHOICE, one entry of a Read response.
///
/// Wire tags follow the MMS ASN.1 definition.
#[derive(Debug, Clone, PartialEq)]
pub enum AccessResult {
    /// A successful read, carrying the value.
    Success(MmsData),
    /// A failed read, carrying an error code as `0x80 <len> <code>`.
    Failure(DataAccessError),
}

impl AccessResult {
    /// Encodes the AccessResult into `buf`.
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            AccessResult::Success(data) => {
                data.encode(buf);
            }
            AccessResult::Failure(err) => {
                // 0x80 0x01 <code>
                buf.extend_from_slice(&[0x80, 0x01, err.code()]);
            }
        }
    }

    /// Returns the number of bytes `encode` would write, used for the PDU budget check.
    pub fn estimated_encoded_size(&self) -> usize {
        match self {
            AccessResult::Success(d) => d.estimated_encoded_size(),
            AccessResult::Failure(_) => 3, // 0x80 0x01 <code>
        }
    }

    /// Decodes an AccessResult; `data` starts at the tag byte.
    pub fn decode(data: &[u8]) -> Result<(Self, usize), MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        if data[0] == 0x80 {
            // failure, a DataAccessError code
            let (len, hdr) = decode_length(&data[1..])?;
            let val_start = 1 + hdr;
            if val_start + len > data.len() {
                return Err(MmsError::TruncatedPdu);
            }
            if len == 0 {
                return Err(MmsError::InvalidLength);
            }
            let code = data[val_start];
            let err = DataAccessError::from_code(code)?;
            Ok((AccessResult::Failure(err), val_start + len))
        } else {
            // success, a Data value
            let (d, consumed) = MmsData::decode(data)?;
            Ok((AccessResult::Success(d), consumed))
        }
    }
}

// WriteOutcome, one entry of a Write response

/// The result of writing one item, as carried in an MMS WriteResponse.
///
/// Wire format:
/// - success: `0x81 0x00`, CONTEXT `[1]` primitive with length 0
/// - failure: `0x80 <len> <code>`, CONTEXT `[0]` primitive
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteOutcome {
    /// The write succeeded, encoded as `0x81 0x00`.
    Success,
    /// The write failed, encoded as `0x80 0x01 <code>`.
    Failure(DataAccessError),
}

impl WriteOutcome {
    /// Encodes the WriteOutcome into `buf`.
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            WriteOutcome::Success => {
                buf.extend_from_slice(&[0x81, 0x00]);
            }
            WriteOutcome::Failure(err) => {
                // codes 0 to 11 are below 128, so this is always 0x80 0x01 <code>
                buf.extend_from_slice(&[0x80, 0x01, err.code()]);
            }
        }
    }

    /// Decodes a WriteOutcome; `data` starts at the tag byte.
    pub fn decode(data: &[u8]) -> Result<(Self, usize), MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        match data[0] {
            0x81 => {
                // success
                let (len, hdr) = decode_length(&data[1..])?;
                Ok((WriteOutcome::Success, 1 + hdr + len))
            }
            0x80 => {
                // failure
                let (len, hdr) = decode_length(&data[1..])?;
                let val_start = 1 + hdr;
                if val_start + len > data.len() {
                    return Err(MmsError::TruncatedPdu);
                }
                // the declared length must be 1 to 4 bytes
                if len == 0 || len > 4 {
                    tracing::warn!(
                        "invalid writeresponse failure length {}, expected 1 to 4",
                        len
                    );
                    return Err(MmsError::InvalidLength);
                }
                let code = data[val_start];
                let err = DataAccessError::from_code(code)?;
                Ok((WriteOutcome::Failure(err), val_start + len))
            }
            other => {
                tracing::warn!("unknown writeoutcome tag 0x{:02X}, rejecting", other);
                Err(MmsError::UnknownWriteOutcomeTag(other))
            }
        }
    }
}

// AlternateAccess (array element / component selection)

/// Selector inside an [`AlternateAccess`] sequence.
///
/// Two access patterns are supported in this scope:
/// `indexRange`, `allElements`, component-only, named, and multi-member
/// selections fall outside this scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlternateAccessSelector {
    /// Single array element, no sub-component.
    /// Wire: `0x82 <ulen> <index>` - `selectAccess.index`,
    /// CONTEXT \[2\] IMPLICIT primitive Unsigned32.
    Index(u32),
    /// Array element followed by a sub-component path (`$`-separated).
    /// Wire: `0xa0 <len> { 0x81 <ulen> <index>, 0x30 <len> <component-chain> }`,
    /// i.e. `selectAlternateAccess` with `accessSelection.index` and a nested
    /// `AlternateAccess` carrying the component chain.
    IndexComponent {
        /// Zero-based index of the array element.
        index: u32,
        /// Name of the component selected inside that element.
        component: String,
    },
}

/// MMS `AlternateAccess` `SEQUENCE OF` carrying a single member.
///
/// ASN.1 grammar (IEC 61850-8-1 / ISO 9506-2):
///
/// ```text
/// AlternateAccess ::= SEQUENCE OF CHOICE {
///   unnamed AlternateAccessSelection,
///   named [5] IMPLICIT SEQUENCE { componentName Identifier, access AlternateAccessSelection }
/// }
///
/// AlternateAccessSelection ::= CHOICE {
///   selectAlternateAccess [0] IMPLICIT SEQUENCE {
///       accessSelection CHOICE {
///           component   [0] IMPLICIT Identifier,
///           index       [1] IMPLICIT Unsigned32,
///           indexRange  [2] IMPLICIT SEQUENCE { ... },
///           allElements [3] IMPLICIT NULL
///       },
///       alternateAccess AlternateAccess
///   },
///   selectAccess CHOICE {
///       component   [1] IMPLICIT Identifier,
///       index       [2] IMPLICIT Unsigned32,
///       indexRange  [3] IMPLICIT SEQUENCE { ... },
///       allElements [4] IMPLICIT NULL
///   }
/// }
/// ```
///
/// Note that `accessSelection` (inside `selectAlternateAccess`) uses tags
/// \[0\]-\[3\] while `selectAccess` uses \[1\]-\[4\].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlternateAccess {
    /// Selector applied at this level of the access path.
    pub selector: AlternateAccessSelector,
}

impl AlternateAccess {
    /// Build a selector for a single array element with no sub-component.
    pub fn index(index: u32) -> Self {
        Self {
            selector: AlternateAccessSelector::Index(index),
        }
    }

    /// Build a selector for an array element with a sub-component path.
    ///
    /// `component` is `$`-separated. Each segment is bounded by
    /// [`MAX_IDENTIFIER_LEN`]. Empty input and empty segments are rejected.
    pub fn index_component(index: u32, component: impl Into<String>) -> Result<Self, MmsError> {
        let component = component.into();
        if component.is_empty() {
            return Err(MmsError::AlternateAccessUnsupported("component is empty"));
        }
        for seg in component.split('$') {
            if seg.is_empty() {
                return Err(MmsError::AlternateAccessUnsupported(
                    "component path contains an empty segment",
                ));
            }
            if seg.len() > MAX_IDENTIFIER_LEN {
                return Err(MmsError::IdentifierTooLong { actual: seg.len() });
            }
        }
        Ok(Self {
            selector: AlternateAccessSelector::IndexComponent { index, component },
        })
    }

    /// Encode the value into `buf`, including the outer `0x30 <len>` SEQUENCE OF wrapper.
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut member = BytesMut::new();
        encode_alt_access_member(&self.selector, &mut member);
        buf.extend_from_slice(&[0x30]);
        encode_length(member.len(), buf);
        buf.extend_from_slice(&member);
    }

    /// Number of bytes the encoded form occupies, including the outer wrapper.
    pub fn encoded_len(&self) -> usize {
        let inner = alt_access_member_len(&self.selector);
        1 + ber_len_size(inner) + inner
    }

    /// Decode an `AlternateAccess` from `data`, starting at the outer
    /// `0x30 <len>` SEQUENCE OF wrapper. Returns the decoded value and the
    /// total number of bytes consumed (header + content).
    ///
    /// Only the two selector forms produced by [`AlternateAccess::index`] and
    /// [`AlternateAccess::index_component`] are accepted. Any other
    /// `accessSelection` branch (`indexRange`, `allElements`, `named`,
    /// component-only, multi-member) yields [`MmsError::AlternateAccessUnsupported`].
    pub fn decode(data: &[u8]) -> Result<(Self, usize), MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        if data[0] != 0x30 {
            return Err(MmsError::InvalidTag {
                expected: 0x30,
                actual: data[0],
            });
        }
        let (inner_len, hdr) = decode_length(&data[1..])?;
        let inner_start = 1 + hdr;
        let total = inner_start + inner_len;
        if total > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let inner = &data[inner_start..total];
        if inner.is_empty() {
            return Err(MmsError::AlternateAccessUnsupported(
                "empty AlternateAccess sequence",
            ));
        }
        let (selector, consumed) = decode_alt_access_member(inner)?;
        if consumed != inner.len() {
            return Err(MmsError::AlternateAccessUnsupported(
                "multi-member AlternateAccess",
            ));
        }
        Ok((Self { selector }, total))
    }
}

/// Decode one `AlternateAccess__Member.unnamed` body. Returns the selector and
/// the number of bytes consumed from `data`.
fn decode_alt_access_member(data: &[u8]) -> Result<(AlternateAccessSelector, usize), MmsError> {
    if data.is_empty() {
        return Err(MmsError::TruncatedPdu);
    }
    let tag = data[0];
    let (len, hdr) = decode_length(&data[1..])?;
    let val_start = 1 + hdr;
    let total = val_start + len;
    if total > data.len() {
        return Err(MmsError::TruncatedPdu);
    }
    let val = &data[val_start..total];

    match tag {
        // selectAccess.index - CONTEXT [2] IMPLICIT Unsigned32
        0x82 => {
            let idx = decode_unsigned_int(val)? as u32;
            Ok((AlternateAccessSelector::Index(idx), total))
        }
        // selectAlternateAccess - CONTEXT [0] IMPLICIT SEQUENCE
        0xa0 => {
            let (index, component) = decode_select_alternate_access(val)?;
            Ok((
                AlternateAccessSelector::IndexComponent { index, component },
                total,
            ))
        }
        // selectAccess.component / indexRange / allElements not in scope
        0x81 => Err(MmsError::AlternateAccessUnsupported(
            "selectAccess.component (component-only) is not supported",
        )),
        0xa3 => Err(MmsError::AlternateAccessUnsupported(
            "selectAccess.indexRange is not supported",
        )),
        0x84 => Err(MmsError::AlternateAccessUnsupported(
            "selectAccess.allElements is not supported",
        )),
        0xa5 => Err(MmsError::AlternateAccessUnsupported(
            "named AlternateAccess member is not supported",
        )),
        _ => Err(MmsError::AlternateAccessUnsupported(
            "unknown AlternateAccess selector tag",
        )),
    }
}

/// Decode the body of `selectAlternateAccess `[0]` IMPLICIT SEQUENCE`.
/// Expects exactly two members: `accessSelection.index` (`[1]` IMPLICIT
/// Unsigned32) followed by a nested `AlternateAccess` carrying the
/// component chain.
fn decode_select_alternate_access(data: &[u8]) -> Result<(u32, String), MmsError> {
    // accessSelection.index [1] IMPLICIT Unsigned32
    if data.is_empty() {
        return Err(MmsError::TruncatedPdu);
    }
    if data[0] != 0x81 {
        return Err(MmsError::AlternateAccessUnsupported(
            "selectAlternateAccess: only accessSelection.index is supported",
        ));
    }
    let (idx_len, idx_hdr) = decode_length(&data[1..])?;
    let idx_start = 1 + idx_hdr;
    let idx_end = idx_start + idx_len;
    if idx_end > data.len() {
        return Err(MmsError::TruncatedPdu);
    }
    let index = decode_unsigned_int(&data[idx_start..idx_end])? as u32;

    // Nested AlternateAccess carrying the component chain (SEQUENCE OF, 0x30).
    let tail = &data[idx_end..];
    let component = decode_component_chain_sequence(tail)?;
    Ok((index, component))
}

/// Decode a component chain wrapped in `0x30 <len>` SEQUENCE OF.
/// The body is a single `AlternateAccess__Member.unnamed` whose selector is
/// either `selectAccess.component` (`0x81`, terminal segment) or
/// `selectAlternateAccess` (`0xa0`) recursing through the chain.
fn decode_component_chain_sequence(data: &[u8]) -> Result<String, MmsError> {
    if data.is_empty() {
        return Err(MmsError::TruncatedPdu);
    }
    if data[0] != 0x30 {
        return Err(MmsError::InvalidTag {
            expected: 0x30,
            actual: data[0],
        });
    }
    let (inner_len, hdr) = decode_length(&data[1..])?;
    let inner_start = 1 + hdr;
    if inner_start + inner_len > data.len() {
        return Err(MmsError::TruncatedPdu);
    }
    let inner = &data[inner_start..inner_start + inner_len];
    decode_component_chain_member(inner)
}

fn decode_component_chain_member(data: &[u8]) -> Result<String, MmsError> {
    if data.is_empty() {
        return Err(MmsError::TruncatedPdu);
    }
    let tag = data[0];
    let (len, hdr) = decode_length(&data[1..])?;
    let val_start = 1 + hdr;
    if val_start + len > data.len() {
        return Err(MmsError::TruncatedPdu);
    }
    let val = &data[val_start..val_start + len];
    match tag {
        // selectAccess.component - terminal Identifier
        0x81 => {
            let s = core::str::from_utf8(val).map_err(|_| MmsError::InvalidUtf8)?;
            if s.is_empty() {
                return Err(MmsError::AlternateAccessUnsupported(
                    "component segment is empty",
                ));
            }
            if s.len() > MAX_IDENTIFIER_LEN {
                return Err(MmsError::IdentifierTooLong { actual: s.len() });
            }
            Ok(s.to_owned())
        }
        // selectAlternateAccess - recurse
        0xa0 => {
            // val = accessSelection.component (0x80) + nested AlternateAccess (0x30)
            if val.is_empty() {
                return Err(MmsError::TruncatedPdu);
            }
            if val[0] != 0x80 {
                return Err(MmsError::AlternateAccessUnsupported(
                    "nested selectAlternateAccess: only accessSelection.component is supported",
                ));
            }
            let (head_len, head_hdr) = decode_length(&val[1..])?;
            let head_start = 1 + head_hdr;
            let head_end = head_start + head_len;
            if head_end > val.len() {
                return Err(MmsError::TruncatedPdu);
            }
            let head_bytes = &val[head_start..head_end];
            let head = core::str::from_utf8(head_bytes).map_err(|_| MmsError::InvalidUtf8)?;
            if head.is_empty() {
                return Err(MmsError::AlternateAccessUnsupported(
                    "component segment is empty",
                ));
            }
            if head.len() > MAX_IDENTIFIER_LEN {
                return Err(MmsError::IdentifierTooLong { actual: head.len() });
            }
            let rest = decode_component_chain_sequence(&val[head_end..])?;
            Ok(format!("{head}${rest}"))
        }
        _ => Err(MmsError::AlternateAccessUnsupported(
            "unknown component chain selector tag",
        )),
    }
}

/// Encode a single `AlternateAccess__Member.unnamed` body (no outer SEQUENCE OF wrapper).
fn encode_alt_access_member(selector: &AlternateAccessSelector, buf: &mut BytesMut) {
    match selector {
        AlternateAccessSelector::Index(idx) => {
            let bytes = encode_unsigned_int_minimal(*idx as u64);
            buf.extend_from_slice(&[0x82]);
            encode_length(bytes.len(), buf);
            buf.extend_from_slice(&bytes);
        }
        AlternateAccessSelector::IndexComponent { index, component } => {
            let idx_bytes = encode_unsigned_int_minimal(*index as u64);
            let mut chain = BytesMut::new();
            encode_component_chain(component, &mut chain);

            let mut sel = BytesMut::new();
            sel.extend_from_slice(&[0x81]);
            encode_length(idx_bytes.len(), &mut sel);
            sel.extend_from_slice(&idx_bytes);
            sel.extend_from_slice(&[0x30]);
            encode_length(chain.len(), &mut sel);
            sel.extend_from_slice(&chain);

            buf.extend_from_slice(&[0xa0]);
            encode_length(sel.len(), buf);
            buf.extend_from_slice(&sel);
        }
    }
}

fn alt_access_member_len(selector: &AlternateAccessSelector) -> usize {
    match selector {
        AlternateAccessSelector::Index(idx) => {
            let n = encode_unsigned_int_minimal(*idx as u64).len();
            1 + ber_len_size(n) + n
        }
        AlternateAccessSelector::IndexComponent { index, component } => {
            let idx_n = encode_unsigned_int_minimal(*index as u64).len();
            let chain_n = component_chain_len(component);
            let inner = (1 + ber_len_size(idx_n) + idx_n) + (1 + ber_len_size(chain_n) + chain_n);
            1 + ber_len_size(inner) + inner
        }
    }
}

/// Encode a `$`-separated sub-component path as an `AlternateAccess__Member.unnamed`
/// body. The last segment is emitted as `selectAccess.component` (tag `0x81`);
/// preceding segments are wrapped as `selectAlternateAccess` with
/// `accessSelection.component` (tag `0x80`) and a nested `AlternateAccess`.
fn encode_component_chain(component_path: &str, buf: &mut BytesMut) {
    let mut parts = component_path.splitn(2, '$');
    let head = parts.next().expect("non-empty: guaranteed by caller");
    match parts.next() {
        None => {
            buf.extend_from_slice(&[0x81]);
            encode_length(head.len(), buf);
            buf.extend_from_slice(head.as_bytes());
        }
        Some(rest) => {
            let mut nested = BytesMut::new();
            encode_component_chain(rest, &mut nested);

            let mut sel = BytesMut::new();
            sel.extend_from_slice(&[0x80]);
            encode_length(head.len(), &mut sel);
            sel.extend_from_slice(head.as_bytes());
            sel.extend_from_slice(&[0x30]);
            encode_length(nested.len(), &mut sel);
            sel.extend_from_slice(&nested);

            buf.extend_from_slice(&[0xa0]);
            encode_length(sel.len(), buf);
            buf.extend_from_slice(&sel);
        }
    }
}

fn component_chain_len(component_path: &str) -> usize {
    let mut parts = component_path.splitn(2, '$');
    let head = parts.next().expect("non-empty: guaranteed by caller");
    match parts.next() {
        None => 1 + ber_len_size(head.len()) + head.len(),
        Some(rest) => {
            let nested = component_chain_len(rest);
            let inner =
                (1 + ber_len_size(head.len()) + head.len()) + (1 + ber_len_size(nested) + nested);
            1 + ber_len_size(inner) + inner
        }
    }
}

// BER encoding helpers, private to this module

/// Returns the number of bytes a BER length field needs.
pub(super) fn ber_len_size(len: usize) -> usize {
    if len < 128 {
        1
    } else if len <= 0xff {
        2
    } else {
        3
    }
}

/// Decodes a signed big-endian integer of 1 to 8 bytes.
fn decode_signed_int(data: &[u8]) -> Result<i64, MmsError> {
    if data.is_empty() || data.len() > 8 {
        return Err(MmsError::InvalidLength);
    }
    // sign extension
    let sign_bit = (data[0] & 0x80) != 0;
    let mut val: i64 = if sign_bit { -1 } else { 0 };
    for &b in data {
        val = (val << 8) | (b as i64);
    }
    Ok(val)
}

/// Encodes a signed integer as the shortest BER INTEGER.
pub(crate) fn encode_signed_int_minimal(val: i64) -> Vec<u8> {
    if val == 0 {
        return vec![0x00];
    }
    let bytes = val.to_be_bytes();
    let mut start = 0usize;
    while start < 7 {
        // drop a leading byte only when the sign stays the same
        if (bytes[start] == 0x00 && (bytes[start + 1] & 0x80) == 0)
            || (bytes[start] == 0xff && (bytes[start + 1] & 0x80) != 0)
        {
            start += 1;
        } else {
            break;
        }
    }
    bytes[start..].to_vec()
}

/// Decodes an unsigned big-endian integer of 1 to 8 bytes.
fn decode_unsigned_int(data: &[u8]) -> Result<u64, MmsError> {
    if data.is_empty() || data.len() > 8 {
        return Err(MmsError::InvalidLength);
    }
    let mut val = 0u64;
    for &b in data {
        val = (val << 8) | (b as u64);
    }
    Ok(val)
}

/// Encodes an unsigned integer as the shortest BER INTEGER.
pub(crate) fn encode_unsigned_int_minimal(val: u64) -> Vec<u8> {
    if val == 0 {
        return vec![0x00];
    }
    // BER INTEGER is signed, so a leading 0x00 is needed when the top bit is set
    let bytes = val.to_be_bytes();
    let mut start = 0usize;
    while start < 7 && bytes[start] == 0x00 && (bytes[start + 1] & 0x80) == 0 {
        start += 1;
    }
    bytes[start..].to_vec()
}

/// Decodes a floating point value: the first byte is the exponent width, followed
/// by an IEEE 754 big-endian value.
///
/// A size other than 5 or 9 is rejected rather than ignored.
///
/// Returns `MmsData::Float32` or `MmsData::Float64` so the original precision is
/// preserved and re-encoding reproduces the wire bytes exactly.
fn decode_floating_point(data: &[u8]) -> Result<MmsData, MmsError> {
    match data.len() {
        5 => {
            // FLOAT32: exponent width byte (8) plus a 4-byte IEEE 754 single
            let mut arr = [0u8; 4];
            arr.copy_from_slice(&data[1..5]);
            Ok(MmsData::Float32(f32::from_be_bytes(arr)))
        }
        9 => {
            // FLOAT64: exponent width byte (11) plus an 8-byte IEEE 754 double
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&data[1..9]);
            Ok(MmsData::Float64(f64::from_be_bytes(arr)))
        }
        other => {
            tracing::warn!("invalid floatingpoint length {}, expected 5 or 9", other);
            Err(MmsError::InvalidFloatSize { actual: other })
        }
    }
}

// Unit tests

#[cfg(test)]
mod tests {
    use super::*;

    // ObjectName encode and decode round trips

    #[test]
    fn object_name_vmd_roundtrip() {
        let name = ObjectName::VmdSpecific("GGIO1".to_owned());
        let mut buf = BytesMut::new();
        name.encode(&mut buf);
        assert_eq!(buf[0], 0x80);
        let (decoded, consumed) = ObjectName::decode(&buf).unwrap();
        assert_eq!(decoded, name);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn object_name_domain_roundtrip() {
        let name = ObjectName::DomainSpecific {
            domain_id: "TESTLD".to_owned(),
            item_id: "GGIO1$ST$Ind$stVal".to_owned(),
        };
        let mut buf = BytesMut::new();
        name.encode(&mut buf);
        assert_eq!(buf[0], 0xa1);
        let (decoded, consumed) = ObjectName::decode(&buf).unwrap();
        assert_eq!(decoded, name);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn object_name_aa_roundtrip() {
        let name = ObjectName::AaSpecific("AA_VAR".to_owned());
        let mut buf = BytesMut::new();
        name.encode(&mut buf);
        assert_eq!(buf[0], 0x82);
        let (decoded, _) = ObjectName::decode(&buf).unwrap();
        assert_eq!(decoded, name);
    }

    #[test]
    fn object_name_identifier_too_long_err() {
        // a 65-byte identifier exceeds MAX_IDENTIFIER_LEN of 64
        let long_name: String = "A".repeat(65);
        // built by hand as 0x80 <65> <65 bytes>
        let mut buf = vec![0x80u8, 65u8];
        buf.extend(long_name.as_bytes());
        let result = ObjectName::decode(&buf);
        assert!(matches!(result, Err(MmsError::IdentifierTooLong { .. })));
    }

    // VariableAccessSpecification round trips

    #[test]
    fn vas_list_of_variable_roundtrip() {
        let entries: Vec<ListOfVariableEntry> = vec![
            ObjectName::DomainSpecific {
                domain_id: "LD1".to_owned(),
                item_id: "LLN0$ST".to_owned(),
            }
            .into(),
            ObjectName::VmdSpecific("VMD_VAR".to_owned()).into(),
        ];
        let vas = VariableAccessSpecification::ListOfVariable(entries);
        let mut buf = BytesMut::new();
        vas.encode(&mut buf);
        assert_eq!(buf[0], 0xa0);
        let (decoded, consumed) = VariableAccessSpecification::decode(&buf).unwrap();
        assert_eq!(decoded, vas);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn vas_list_of_variable_with_alt_access_roundtrip() {
        let entries = vec![
            ListOfVariableEntry::with_alt_access(
                ObjectName::DomainSpecific {
                    domain_id: "LD".to_owned(),
                    item_id: "GGIO1$ST$Ind".to_owned(),
                },
                AlternateAccess::index(2),
            ),
            ListOfVariableEntry::with_alt_access(
                ObjectName::DomainSpecific {
                    domain_id: "LD".to_owned(),
                    item_id: "GGIO1$ST$Ind1".to_owned(),
                },
                AlternateAccess::index_component(0, "stVal").unwrap(),
            ),
        ];
        let vas = VariableAccessSpecification::ListOfVariable(entries);
        let mut buf = BytesMut::new();
        vas.encode(&mut buf);
        assert_eq!(buf.len(), vas.encoded_len());
        let (decoded, consumed) = VariableAccessSpecification::decode(&buf).unwrap();
        assert_eq!(decoded, vas);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn alt_access_decode_rejects_unsupported_selector() {
        // selectAccess.allElements [4] IMPLICIT NULL - out of scope
        let bytes = [0x30u8, 0x02, 0x84, 0x00];
        let err = AlternateAccess::decode(&bytes).unwrap_err();
        assert!(matches!(err, MmsError::AlternateAccessUnsupported(_)));
    }

    #[test]
    fn alt_access_decode_rejects_multi_member() {
        // Two Index members back-to-back inside the SEQUENCE OF
        let bytes = [0x30u8, 0x06, 0x82, 0x01, 0x00, 0x82, 0x01, 0x01];
        let err = AlternateAccess::decode(&bytes).unwrap_err();
        assert!(matches!(err, MmsError::AlternateAccessUnsupported(_)));
    }

    #[test]
    fn vas_variable_list_name_roundtrip() {
        let name = ObjectName::DomainSpecific {
            domain_id: "TESTLD".to_owned(),
            item_id: "DataSet1".to_owned(),
        };
        let vas = VariableAccessSpecification::VariableListName(name);
        let mut buf = BytesMut::new();
        vas.encode(&mut buf);
        assert_eq!(buf[0], 0xa1);
        let (decoded, consumed) = VariableAccessSpecification::decode(&buf).unwrap();
        assert_eq!(decoded, vas);
        assert_eq!(consumed, buf.len());
    }

    // AccessResult round trips

    #[test]
    fn access_result_success_boolean_roundtrip() {
        let ar = AccessResult::Success(MmsData::Boolean(true));
        let mut buf = BytesMut::new();
        ar.encode(&mut buf);
        let (decoded, _) = AccessResult::decode(&buf).unwrap();
        assert_eq!(decoded, ar);
    }

    #[test]
    fn access_result_failure_roundtrip() {
        let ar = AccessResult::Failure(DataAccessError::ObjectNonExistent);
        let mut buf = BytesMut::new();
        ar.encode(&mut buf);
        assert_eq!(&buf[..], &[0x80, 0x01, 10]);
        let (decoded, _) = AccessResult::decode(&buf).unwrap();
        assert_eq!(decoded, ar);
    }

    // MmsData round trips for each primitive variant

    #[test]
    fn mmsdata_integer_roundtrip() {
        let data = MmsData::Integer(-12345);
        let mut buf = BytesMut::new();
        data.encode(&mut buf);
        let (decoded, consumed) = MmsData::decode(&buf).unwrap();
        assert_eq!(decoded, data);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn mmsdata_unsigned_roundtrip() {
        let data = MmsData::Unsigned(65000);
        let mut buf = BytesMut::new();
        data.encode(&mut buf);
        let (decoded, _) = MmsData::decode(&buf).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    #[allow(clippy::approx_constant)] // 3.14 is a test sentinel, not an approximation of pi
    fn mmsdata_float32_roundtrip() {
        // Float32 encodes to 5 bytes, exponent width 8 plus a single, and decodes back
        let data = MmsData::Float32(3.14f32);
        let mut buf = BytesMut::new();
        data.encode(&mut buf);
        // wire: 0x87 0x05 0x08 <4 bytes IEEE 754 single>
        assert_eq!(buf[0], 0x87);
        assert_eq!(buf[1], 0x05);
        assert_eq!(buf[2], 0x08);
        assert_eq!(buf.len(), 7);
        let (decoded, consumed) = MmsData::decode(&buf).unwrap();
        assert_eq!(consumed, 7);
        assert_eq!(decoded, data);
    }

    #[test]
    #[allow(clippy::approx_constant)] // 3.141592... is a test sentinel, not an approximation of pi
    fn mmsdata_float64_roundtrip() {
        // Float64 encodes to 9 bytes, exponent width 11 plus a double, and decodes back
        let data = MmsData::Float64(3.141592653589793f64);
        let mut buf = BytesMut::new();
        data.encode(&mut buf);
        // wire: 0x87 0x09 0x0b <8 bytes IEEE 754 double>
        assert_eq!(buf[0], 0x87);
        assert_eq!(buf[1], 0x09);
        assert_eq!(buf[2], 0x0b);
        assert_eq!(buf.len(), 11);
        let (decoded, consumed) = MmsData::decode(&buf).unwrap();
        assert_eq!(consumed, 11);
        assert_eq!(decoded, data);
    }

    #[test]
    fn mmsdata_float32_wire_regression() {
        // FLOAT32 bytes as they appear in a ReadResponse: 0x87 0x05 0x08 0x3f 0x5c 0xfb 0x49
        // decoding must yield Float32 and re-encoding must be byte exact
        let wire = [0x87u8, 0x05, 0x08, 0x3f, 0x5c, 0xfb, 0x49];
        let (data, consumed) = MmsData::decode(&wire).unwrap();
        assert_eq!(consumed, 7);
        match data {
            MmsData::Float32(v) => {
                // 0x3f5cfb49 about 0.8625...
                assert!((v - f32::from_be_bytes([0x3f, 0x5c, 0xfb, 0x49])).abs() < f32::EPSILON);
            }
            other => panic!("expected Float32, got {:?}", other),
        }
        // re-encoding must be byte exact
        let mut out = BytesMut::new();
        MmsData::Float32(f32::from_be_bytes([0x3f, 0x5c, 0xfb, 0x49])).encode(&mut out);
        assert_eq!(out.as_ref(), &wire[..]);
    }

    #[test]
    fn mmsdata_visible_string_roundtrip() {
        let data = MmsData::VisibleString("Hello".to_owned());
        let mut buf = BytesMut::new();
        data.encode(&mut buf);
        let (decoded, _) = MmsData::decode(&buf).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn mmsdata_utctime_roundtrip() {
        let data = MmsData::UtcTime([0x5e, 0x1a, 0x2b, 0x3c, 0x01, 0x02, 0x03, 0x04]);
        let mut buf = BytesMut::new();
        data.encode(&mut buf);
        let (decoded, _) = MmsData::decode(&buf).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn mmsdata_utctime_wrong_length_err() {
        // 0x91 0x07 <7 bytes>, where 8 are required
        let bytes = [0x91u8, 0x07, 1, 2, 3, 4, 5, 6, 7];
        let result = MmsData::decode(&bytes);
        assert!(matches!(
            result,
            Err(MmsError::InvalidUtcTimeLength { actual: 7 })
        ));
    }

    #[test]
    fn mmsdata_float_wrong_size_err() {
        // 0x87 0x04 <4 bytes>, where 5 or 9 are required
        let bytes = [0x87u8, 0x04, 0x08, 0x40, 0x48, 0xf5];
        let result = MmsData::decode(&bytes);
        assert!(matches!(
            result,
            Err(MmsError::InvalidFloatSize { actual: 4 })
        ));
    }

    #[test]
    fn mmsdata_octet_string_roundtrip() {
        let data = MmsData::OctetString(vec![0xde, 0xad, 0xbe, 0xef]);
        let mut buf = BytesMut::new();
        data.encode(&mut buf);
        let (decoded, _) = MmsData::decode(&buf).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn mmsdata_bit_string_roundtrip() {
        let data = MmsData::BitString {
            padding: 3,
            data: vec![0xf8],
        };
        let mut buf = BytesMut::new();
        data.encode(&mut buf);
        let (decoded, _) = MmsData::decode(&buf).unwrap();
        assert_eq!(decoded, data);
    }

    // Structure and Array round trips, including nesting

    #[test]
    fn mmsdata_structure_nested_roundtrip() {
        let data = MmsData::Structure(vec![
            MmsData::Boolean(true),
            MmsData::Integer(42),
            MmsData::Structure(vec![MmsData::Unsigned(100)]),
        ]);
        let mut buf = BytesMut::new();
        data.encode(&mut buf);
        let (decoded, _) = MmsData::decode(&buf).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn mmsdata_array_roundtrip() {
        let data = MmsData::Array(vec![
            MmsData::Integer(1),
            MmsData::Integer(2),
            MmsData::Integer(3),
        ]);
        let mut buf = BytesMut::new();
        data.encode(&mut buf);
        let (decoded, _) = MmsData::decode(&buf).unwrap();
        assert_eq!(decoded, data);
    }

    // A nesting depth bomb

    #[test]
    fn depth_bomb_err() {
        // build 33 nested structures, one past MAX_DATA_NESTING_DEPTH of 32
        // each level is 0xa2 0x03 with a 3-byte inner value
        // the innermost level is 0xa2 0x00, an empty structure
        fn make_nested(depth: usize) -> Vec<u8> {
            if depth == 0 {
                return vec![0xa2, 0x00]; // empty structure
            }
            let inner = make_nested(depth - 1);
            let mut result = vec![0xa2u8];
            // encode length
            if inner.len() < 128 {
                result.push(inner.len() as u8);
            } else {
                result.push(0x81);
                result.push(inner.len() as u8);
            }
            result.extend_from_slice(&inner);
            result
        }

        // 33 levels, past MAX_DATA_NESTING_DEPTH of 32
        let bomb = make_nested(33);
        let result = MmsData::decode(&bomb);
        assert!(
            matches!(result, Err(MmsError::NestingLevelExceeded { .. })),
            "a depth bomb must return NestingLevelExceeded, got {:?}",
            result
        );
    }

    #[test]
    fn depth_at_limit_ok() {
        // 32 levels, exactly at the ceiling, must still succeed
        fn make_nested(depth: usize) -> Vec<u8> {
            if depth == 0 {
                return vec![0x83, 0x01, 0x01]; // boolean true
            }
            let inner = make_nested(depth - 1);
            let mut result = vec![0xa2u8, inner.len() as u8];
            result.extend_from_slice(&inner);
            result
        }
        // decode_with_depth(.., 0) reaches depth 32 at the deepest level, which equals
        // MAX_DATA_NESTING_DEPTH; the guard trips only past it, so this is accepted
        let data = make_nested(31); // 31 structures plus a boolean is 32 levels
        let result = MmsData::decode(&data);
        assert!(result.is_ok(), "32 levels must succeed, got {:?}", result);
    }

    // Oversized length fields

    #[test]
    fn oversized_length_returns_err() {
        // 0x85 0x82 0xff 0xff declares 65535 bytes with far fewer present
        let bytes = [0x85u8, 0x82, 0xff, 0xff, 0x00, 0x01];
        let result = MmsData::decode(&bytes);
        assert!(
            result.is_err(),
            "an oversized length must return an error, not panic"
        );
    }

    #[test]
    fn truncated_length_returns_err() {
        // 0x85 0x81 promises another length byte that is missing
        let bytes = [0x85u8, 0x81];
        let result = MmsData::decode(&bytes);
        assert!(matches!(result, Err(MmsError::TruncatedPdu)));
    }

    // WriteOutcome round trips

    #[test]
    fn write_outcome_success_roundtrip() {
        let outcome = WriteOutcome::Success;
        let mut buf = BytesMut::new();
        outcome.encode(&mut buf);
        assert_eq!(&buf[..], &[0x81, 0x00]);
        let (decoded, consumed) = WriteOutcome::decode(&buf).unwrap();
        assert_eq!(decoded, WriteOutcome::Success);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn write_outcome_failure_roundtrip() {
        let outcome = WriteOutcome::Failure(DataAccessError::TypeInconsistent);
        let mut buf = BytesMut::new();
        outcome.encode(&mut buf);
        assert_eq!(&buf[..], &[0x80, 0x01, 7]);
        let (decoded, _) = WriteOutcome::decode(&buf).unwrap();
        assert_eq!(decoded, outcome);
    }

    // DataAccessError::from_code

    #[test]
    fn data_access_error_all_codes_valid() {
        for code in 0u8..=11u8 {
            DataAccessError::from_code(code).unwrap();
        }
    }

    #[test]
    fn data_access_error_invalid_code_err() {
        let result = DataAccessError::from_code(12);
        assert!(matches!(result, Err(MmsError::UnknownDataAccessError(12))));
    }

    // effective_nesting_cap

    #[test]
    fn effective_nesting_cap_none_falls_back_to_local() {
        // no negotiated value falls back to the local ceiling
        assert_eq!(effective_nesting_cap(32, None), 32);
        assert_eq!(effective_nesting_cap(25, None), 25);
    }

    #[test]
    fn effective_nesting_cap_negotiated_lower_clamps() {
        // a negotiated value below the local ceiling wins, being stricter
        assert_eq!(effective_nesting_cap(32, Some(5)), 5);
        assert_eq!(effective_nesting_cap(32, Some(0)), 0);
    }

    #[test]
    fn effective_nesting_cap_negotiated_higher_clamps_to_local() {
        // a negotiated value above the local ceiling is clamped, so a peer cannot
        // raise the limit by proposing a large value
        assert_eq!(effective_nesting_cap(32, Some(100)), 32);
        assert_eq!(effective_nesting_cap(32, Some(255)), 32);
    }

    #[test]
    fn effective_nesting_cap_negotiated_equal_to_local() {
        // a negotiated value equal to the local ceiling keeps that value
        assert_eq!(effective_nesting_cap(32, Some(32)), 32);
    }

    // decode_with_max honors the negotiated nesting level

    /// With a negotiated ceiling below the local one, exceeding it returns an error.
    #[test]
    fn negotiated_lower_than_local_cap_clamps() {
        // local=32, negotiated=Some(5) -> effective=5
        // build 6 nested structures: the sixth is reached at depth 5, which equals
        // the effective cap of 5 and trips the guard
        fn make_nested(depth: usize) -> Vec<u8> {
            if depth == 0 {
                return vec![0xa2, 0x00]; // empty structure
            }
            let inner = make_nested(depth - 1);
            let mut result = vec![0xa2u8];
            if inner.len() < 128 {
                result.push(inner.len() as u8);
            } else {
                result.push(0x81);
                result.push(inner.len() as u8);
            }
            result.extend_from_slice(&inner);
            result
        }
        // 6 levels: the outer structure decodes at depth 0 and depth 5 trips the guard
        let data = make_nested(6);
        let result = MmsData::decode_with_max(&data, 5);
        assert!(
            matches!(result, Err(MmsError::NestingLevelExceeded { .. })),
            "with a negotiated cap of 5, six levels must fail, got {:?}",
            result
        );
    }

    /// With a negotiated ceiling above the local one, the local ceiling still applies.
    #[test]
    fn negotiated_higher_than_local_still_clamps_to_local() {
        // local=32, negotiated=Some(100) -> effective_nesting_cap -> 32
        // 33 levels must fail because the local cap of 32 applies
        fn make_nested(depth: usize) -> Vec<u8> {
            if depth == 0 {
                return vec![0xa2, 0x00];
            }
            let inner = make_nested(depth - 1);
            let mut result = vec![0xa2u8];
            if inner.len() < 128 {
                result.push(inner.len() as u8);
            } else {
                result.push(0x81);
                result.push(inner.len() as u8);
            }
            result.extend_from_slice(&inner);
            result
        }
        let effective = effective_nesting_cap(MAX_DATA_NESTING_DEPTH, Some(100));
        assert_eq!(
            effective, 32,
            "a negotiated 100 above the local 32 must clamp to 32"
        );
        let data = make_nested(33); // 33 levels, past 32
        let result = MmsData::decode_with_max(&data, effective);
        assert!(
            matches!(result, Err(MmsError::NestingLevelExceeded { .. })),
            "33 levels must fail because the local cap of 32 applies, got {:?}",
            result
        );
    }

    /// With no negotiated value the local ceiling applies: 33 levels fail, 32 succeed.
    #[test]
    fn negotiated_none_falls_back_to_local() {
        fn make_nested(depth: usize) -> Vec<u8> {
            if depth == 0 {
                return vec![0x83, 0x01, 0x01]; // boolean
            }
            let inner = make_nested(depth - 1);
            let mut result = vec![0xa2u8, inner.len() as u8];
            result.extend_from_slice(&inner);
            result
        }
        let effective = effective_nesting_cap(MAX_DATA_NESTING_DEPTH, None);
        assert_eq!(effective, 32);
        // 33 levels exceed the ceiling of 32
        let deep_data = make_nested(33);
        let result = MmsData::decode_with_max(&deep_data, effective);
        assert!(
            matches!(result, Err(MmsError::NestingLevelExceeded { .. })),
            "without a negotiated value, 33 levels must fail, got {:?}",
            result
        );
        // 32 levels or fewer stay inside the ceiling
        let ok_data = make_nested(31);
        let result = MmsData::decode_with_max(&ok_data, effective);
        assert!(
            result.is_ok(),
            "without a negotiated value, up to 32 levels must succeed, got {:?}",
            result
        );
    }

    // estimated_encoded_size must match the real encoded length

    fn assert_size_matches_encode(d: &MmsData) {
        let mut buf = BytesMut::new();
        d.encode(&mut buf);
        assert_eq!(
            d.estimated_encoded_size(),
            buf.len(),
            "estimated_encoded_size must match the encoded length, data={:?}",
            d
        );
    }

    #[test]
    fn estimated_size_matches_encode_scalars() {
        assert_size_matches_encode(&MmsData::Boolean(true));
        assert_size_matches_encode(&MmsData::Integer(0));
        assert_size_matches_encode(&MmsData::Integer(i64::MAX));
        assert_size_matches_encode(&MmsData::Integer(-1));
        assert_size_matches_encode(&MmsData::Unsigned(0));
        assert_size_matches_encode(&MmsData::Unsigned(u64::MAX));
        assert_size_matches_encode(&MmsData::Float32(1.5));
        assert_size_matches_encode(&MmsData::Float64(1.5));
        assert_size_matches_encode(&MmsData::OctetString(vec![1, 2, 3]));
        assert_size_matches_encode(&MmsData::VisibleString("hello".to_owned()));
        assert_size_matches_encode(&MmsData::MmsString("naïve-ünïcödé".to_owned()));
        assert_size_matches_encode(&MmsData::UtcTime([0u8; 8]));
        assert_size_matches_encode(&MmsData::BinaryTime(vec![0u8; 6]));
        assert_size_matches_encode(&MmsData::BitString {
            padding: 3,
            data: vec![0xff],
        });
    }

    #[test]
    fn estimated_size_matches_encode_long_strings() {
        // lengths that straddle the short-form and long-form length boundary
        assert_size_matches_encode(&MmsData::OctetString(vec![0u8; 127]));
        assert_size_matches_encode(&MmsData::OctetString(vec![0u8; 128]));
        assert_size_matches_encode(&MmsData::OctetString(vec![0u8; 256]));
    }

    #[test]
    fn estimated_size_matches_encode_nested() {
        let st = MmsData::Structure(vec![
            MmsData::Boolean(false),
            MmsData::Integer(42),
            MmsData::Structure(vec![
                MmsData::Float32(1.5),
                MmsData::VisibleString("nested".to_owned()),
            ]),
        ]);
        assert_size_matches_encode(&st);

        let arr = MmsData::Array(vec![MmsData::Integer(1), MmsData::Integer(2)]);
        assert_size_matches_encode(&arr);
    }

    #[test]
    fn access_result_estimated_size_matches_encode() {
        let s = AccessResult::Success(MmsData::Float32(1.0));
        let mut buf = BytesMut::new();
        s.encode(&mut buf);
        assert_eq!(s.estimated_encoded_size(), buf.len());

        let f = AccessResult::Failure(DataAccessError::ObjectNonExistent);
        let mut buf = BytesMut::new();
        f.encode(&mut buf);
        assert_eq!(f.estimated_encoded_size(), buf.len());
    }

    // AlternateAccess encoding, byte exact

    #[test]
    fn alt_access_index_small_byte_exact() {
        // index=5 -> 0x30 0x03 0x82 0x01 0x05
        let aa = AlternateAccess::index(5);
        let mut buf = BytesMut::new();
        aa.encode(&mut buf);
        assert_eq!(&buf[..], &[0x30, 0x03, 0x82, 0x01, 0x05]);
        assert_eq!(aa.encoded_len(), buf.len());
    }

    #[test]
    fn alt_access_index_zero_byte_exact() {
        // index 0 encodes as [0x00], giving 0x30 0x03 0x82 0x01 0x00
        let aa = AlternateAccess::index(0);
        let mut buf = BytesMut::new();
        aa.encode(&mut buf);
        assert_eq!(&buf[..], &[0x30, 0x03, 0x82, 0x01, 0x00]);
        assert_eq!(aa.encoded_len(), buf.len());
    }

    #[test]
    fn alt_access_index_large_needs_two_bytes() {
        // index 300 is 0x012C, whose minimal unsigned BER form is [0x01, 0x2C]
        // -> 0x30 0x04 0x82 0x02 0x01 0x2C
        let aa = AlternateAccess::index(300);
        let mut buf = BytesMut::new();
        aa.encode(&mut buf);
        assert_eq!(&buf[..], &[0x30, 0x04, 0x82, 0x02, 0x01, 0x2C]);
        assert_eq!(aa.encoded_len(), buf.len());
    }

    #[test]
    fn alt_access_index_with_sign_pad() {
        // index 0x80 is 128: the top bit is set, so BER prefixes 0x00, giving [0x00, 0x80]
        let aa = AlternateAccess::index(128);
        let mut buf = BytesMut::new();
        aa.encode(&mut buf);
        assert_eq!(&buf[..], &[0x30, 0x04, 0x82, 0x02, 0x00, 0x80]);
        assert_eq!(aa.encoded_len(), buf.len());
    }

    #[test]
    fn alt_access_index_component_single_segment_byte_exact() {
        // index=2, component="stVal"
        // chain = selectAccess.component = 0x81 0x05 's' 't' 'V' 'a' 'l'  (7 bytes)
        // sel = 0x81 0x01 0x02   (accessSelection.index)
        //     + 0x30 0x07 <chain>
        // -> 0xa0 <len(sel)> <sel>
        // sel_len = 3 + 9 = 12
        // outer member = 0xa0 0x0c <12 bytes>  -> 14 bytes
        // SEQUENCE OF wrap = 0x30 0x0e <14 bytes>
        let aa = AlternateAccess::index_component(2, "stVal").unwrap();
        let mut buf = BytesMut::new();
        aa.encode(&mut buf);
        assert_eq!(
            &buf[..],
            &[
                0x30, 0x0e, // AlternateAccess SEQUENCE OF, len=14
                0xa0, 0x0c, // selectAlternateAccess, len=12
                0x81, 0x01, 0x02, // accessSelection.index = 2
                0x30, 0x07, // nested AlternateAccess, len=7
                0x81, 0x05, b's', b't', b'V', b'a', b'l', // selectAccess.component
            ]
        );
        assert_eq!(aa.encoded_len(), buf.len());
    }

    #[test]
    fn alt_access_index_component_two_segments_byte_exact() {
        // index=0, component="inner$f"
        // the final link is selectAccess.component "f", 0x81 0x01 'f', 3 bytes
        // the preceding link is 0x80 0x05 'inner' plus 0x30 0x03 <final>, 12 bytes
        //         -> 0xa0 0x0c <12 bytes>  (14 bytes)
        // member = 14 bytes
        // outer sel(IndexComp) = 0x81 0x01 0x00 + 0x30 0x0e <14 bytes>
        //   = 3 + 16 = 19 bytes
        // -> 0xa0 0x13 <19 bytes>  (21 bytes)
        // SEQUENCE OF = 0x30 0x15 <21 bytes>
        let aa = AlternateAccess::index_component(0, "inner$f").unwrap();
        let mut buf = BytesMut::new();
        aa.encode(&mut buf);
        assert_eq!(
            &buf[..],
            &[
                0x30, 0x15, // AlternateAccess SEQUENCE OF, len=21
                0xa0, 0x13, // selectAlternateAccess(outer), len=19
                0x81, 0x01, 0x00, // accessSelection.index = 0
                0x30, 0x0e, // nested AlternateAccess, len=14
                0xa0, 0x0c, // selectAlternateAccess(inner), len=12
                0x80, 0x05, b'i', b'n', b'n', b'e', b'r', // accessSelection.component
                0x30, 0x03, // nested AlternateAccess, len=3
                0x81, 0x01, b'f', // selectAccess.component
            ]
        );
        assert_eq!(aa.encoded_len(), buf.len());
    }

    #[test]
    fn alt_access_index_component_empty_rejected() {
        assert!(matches!(
            AlternateAccess::index_component(0, ""),
            Err(MmsError::AlternateAccessUnsupported(_))
        ));
    }

    #[test]
    fn alt_access_index_component_double_dollar_rejected() {
        assert!(matches!(
            AlternateAccess::index_component(0, "a$$b"),
            Err(MmsError::AlternateAccessUnsupported(_))
        ));
    }

    #[test]
    fn alt_access_index_component_segment_too_long_rejected() {
        let long = "x".repeat(MAX_IDENTIFIER_LEN + 1);
        assert!(matches!(
            AlternateAccess::index_component(0, long),
            Err(MmsError::IdentifierTooLong { .. })
        ));
    }
}
