//! MMS TypeSpecification CHOICE, BER encoded and decoded per ISO 9506-2.
//!
//! ## Wire tags
//!
//! | CONTEXT tag | Name            | Underlying encoding |
//! |-------------|---------------|-------------------|
//! | `[0]` EXP.  | typeName        | ObjectName, decode only |
//! | `[1]` IMP.  | array         | SEQUENCE{packed?,count,`[2]`EXP typespec} |
//! | `[2]` IMP.  | structure     | SEQUENCE{packed?,`[1]`IMP SEQOF StructComp} |
//! | `[3]` IMP.  | boolean         | NULL, empty content |
//! | `[4]` IMP.  | bitstring       | INTEGER, may be negative |
//! | `[5]` IMP.  | integer       | INTEGER Unsigned8 |
//! | `[6]` IMP.  | unsigned      | INTEGER Unsigned8 |
//! | `[7]` IMP.  | floatingpoint | SEQUENCE{formatwidth, exponentwidth} |
//! | `[9]` IMP.  | octetstring     | INTEGER, may be negative |
//! | `[10]` IMP. | visiblestring   | INTEGER, may be negative |
//! | `[11]` IMP. | generalizedtime | NULL, decode only |
//! | `[12]` IMP. | binarytime    | BOOLEAN           |
//! | `[13]` IMP. | bcd             | INTEGER, decode only |
//! | `[15]` IMP. | objId           | NULL, decode only |
//! | `[16]` IMP. | mMSString       | INTEGER, may be negative |
//! | `[17]` IMP. | utctime         | NULL, empty content |
//!
//! Tag `[8]` is reserved by the standard and unused.
//!
//! ## Recursion depth guard
//!
//! Decoding returns an error once the recursion depth reaches
//! `MAX_TYPE_SPEC_DEPTH` (32), so deeply nested input cannot exhaust the stack.
//!
//! ## Unknown and unsupported variants
//!
//! Decoding an unsupported tag (typeName `[0xa0]`, generalizedtime `[0x8b]`,
//! bcd `[0x8d]`, objId `[0x8f]`, and any tag the standard does not define) yields
//! `TypeSpecification::Unknown(tag)`, leaving the caller to log, forward or reject it.
//!
//! Encoding an `Unknown` returns `MmsError::UnknownTypeSpecTag`, because the
//! original bytes cannot be reconstructed.
//!
//! ## floatingpoint field order
//!
//! On the wire `formatwidth` precedes `exponentwidth`.
//! float32: formatwidth 32 (0x20), exponentwidth 8 (0x08).
//! float64: formatwidth 64 (0x40), exponentwidth 11 (0x0b).
//!
//! ## Negative bitString values
//!
//! `bits: i32` may be negative, which denotes a variable-length bit string; the
//! signed type preserves that meaning.

use super::super::error::MmsError;
use super::initiate::{decode_length, encode_length};
use crate::compat::prelude::*;
use bytes::BytesMut;

// Constants

/// Local ceiling on TypeSpecification recursion during decode.
///
/// This is not the only bound. The effective ceiling comes from
/// `effective_nesting_cap` and is the smaller of this constant and the negotiated
/// dataStructureNestingLevel.
pub const MAX_TYPE_SPEC_DEPTH: u8 = 32;

// TypeSpecification CHOICE context tags; IMPLICIT unless marked EXPLICIT.
const TAG_TYPE_NAME: u8 = 0xa0; // [0] EXPLICIT
const TAG_ARRAY: u8 = 0xa1; // [1] IMPLICIT CONSTRUCTED
const TAG_STRUCTURE: u8 = 0xa2; // [2] IMPLICIT CONSTRUCTED
const TAG_BOOLEAN: u8 = 0x83; // [3] IMPLICIT primitive NULL
const TAG_BITSTRING: u8 = 0x84; // [4] IMPLICIT primitive INTEGER
const TAG_INTEGER: u8 = 0x85; // [5] IMPLICIT primitive INTEGER
const TAG_UNSIGNED: u8 = 0x86; // [6] IMPLICIT primitive INTEGER
const TAG_FLOATINGPOINT: u8 = 0xa7; // [7] IMPLICIT CONSTRUCTED SEQUENCE
const TAG_OCTETSTRING: u8 = 0x89; // [9] IMPLICIT primitive INTEGER
const TAG_VISIBLESTRING: u8 = 0x8a; // [10] IMPLICIT primitive INTEGER
const TAG_GENERALIZEDTIME: u8 = 0x8b; // [11] IMPLICIT primitive NULL, decode only
const TAG_BINARYTIME: u8 = 0x8c; // [12] IMPLICIT primitive BOOLEAN
const TAG_BCD: u8 = 0x8d; // [13] IMPLICIT primitive INTEGER, decode only
const TAG_OBJ_ID: u8 = 0x8f; // [15] IMPLICIT primitive NULL, decode only
const TAG_MMS_STRING: u8 = 0x90; // [16] IMPLICIT primitive INTEGER
const TAG_UTCTIME: u8 = 0x91; // [17] IMPLICIT primitive NULL

// StructComponent

/// One member of an MMS structure, the StructComponent SEQUENCE.
///
/// Wire format:
/// ```text
/// SEQUENCE (UNIVERSAL 16 = 0x30) {
///   [0] IMPLICIT VisibleString    -- componentName, OPTIONAL but normally present
///   [1] EXPLICIT TypeSpecification -- componentType, recursive
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructComponent {
    /// Component name, a VisibleString.
    pub name: String,
    /// Component type, itself a TypeSpecification.
    pub type_spec: TypeSpecification,
}

impl StructComponent {
    /// Returns the encoded length in bytes.
    fn encoded_len(&self) -> usize {
        let name_bytes = self.name.as_bytes();
        // [0] IMPLICIT VisibleString: tag 0x80, length field, content
        let name_part = 1 + len_size(name_bytes.len()) + name_bytes.len();
        // [1] EXPLICIT TypeSpecification: tag 0xa1, length field, content
        let ts_len = self.type_spec.encoded_len();
        let ts_part = 1 + len_size(ts_len) + ts_len;
        let inner = name_part + ts_part;
        // UNIVERSAL SEQUENCE: tag 0x30, length field, content
        1 + len_size(inner) + inner
    }
}

// TypeSpecification

/// The MMS TypeSpecification CHOICE.
///
/// Variants that both encode and decode: Boolean, BitString, Integer, Unsigned,
/// FloatingPoint, OctetString, VisibleString, MmsString, UtcTime, BinaryTime,
/// Array and Structure.
///
/// ## Negative bitString values
///
/// `bits: i32` may be negative, which denotes a variable-length bit string.
///
/// ## Unknown and unsupported variants
///
/// Decoding an unsupported tag (typeName `[0xa0]`, generalizedtime `[0x8b]`,
/// bcd `[0x8d]`, objId `[0x8f]`, and any tag the standard does not define) yields
/// `Unknown(tag)`, leaving the caller to log, forward or reject it.
///
/// Surfacing the tag explicitly keeps the value from being partially initialized.
///
/// `encode` returns `Err(UnknownTypeSpecTag)` for `Unknown`, since the original
/// bytes cannot be reconstructed; `encoded_len` returns 0 as a placeholder the
/// encode path never reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeSpecification {
    /// `[3]` boolean, encoded as NULL with empty content.
    Boolean,
    /// `[4]` bitstring; a negative value denotes variable length.
    BitString {
        /// Bit count; a negative value denotes variable length.
        bits: i32,
    },
    /// `[5]` integer, with the width in bits.
    Integer {
        /// Width of the integer in bits.
        width_bits: u8,
    },
    /// `[6]` unsigned, with the width in bits.
    Unsigned {
        /// Width of the unsigned integer in bits.
        width_bits: u8,
    },
    /// `[7]` floatingpoint, a SEQUENCE with formatwidth before exponentwidth.
    FloatingPoint {
        /// Total width in bits: 32 for float32, 64 for float64.
        format_width: u8,
        /// Exponent width in bits: 8 for float32, 11 for float64.
        exponent_width: u8,
    },
    /// `[9]` octetstring; a negative value denotes variable length.
    OctetString {
        /// Maximum octet count; a negative value denotes variable length.
        max_octets: i32,
    },
    /// `[10]` visiblestring; a negative value denotes variable length.
    VisibleString {
        /// Maximum character count; a negative value denotes variable length.
        max_chars: i32,
    },
    /// `[16]` mMSString; a negative value denotes variable length.
    MmsString {
        /// Maximum character count; a negative value denotes variable length.
        max_chars: i32,
    },
    /// `[17]` utctime, encoded as NULL with empty content.
    UtcTime,
    /// `[12]` binarytime; false selects the 4-byte form, true the 6-byte form.
    BinaryTime {
        /// False selects the 4-byte form, true the 6-byte form.
        use_long_form: bool,
    },
    /// `[1]` array, a SEQUENCE.
    Array {
        /// Number of elements.
        element_count: u32,
        /// Type shared by every element.
        element_type: Box<TypeSpecification>,
    },
    /// `[2]` structure, a SEQUENCE OF StructComponent.
    Structure {
        /// Component list.
        components: Vec<StructComponent>,
    },
    /// An unsupported or standard-undefined TypeSpecification tag, passed through.
    ///
    /// The tag is surfaced rather than dropped so the caller can log it, forward it,
    /// or reject the PDU. Encoding is not supported: `encode` returns
    /// `Err(UnknownTypeSpecTag)`, because re-encoding cannot reproduce the original
    /// bytes.
    Unknown(u8),
}

impl TypeSpecification {
    /// Returns the encoded length in bytes, including the outer tag and length.
    pub fn encoded_len(&self) -> usize {
        match self {
            TypeSpecification::Boolean => 2, // 0x83 0x00
            TypeSpecification::UtcTime => 2, // 0x91 0x00
            TypeSpecification::BitString { bits } => {
                let int_bytes = encode_signed_i32_minimal(*bits);
                1 + len_size(int_bytes.len()) + int_bytes.len()
            }
            TypeSpecification::Integer { .. } | TypeSpecification::Unsigned { .. } => {
                3 // 0x8x 0x01 <byte>
            }
            TypeSpecification::OctetString { max_octets } => {
                let int_bytes = encode_signed_i32_minimal(*max_octets);
                1 + len_size(int_bytes.len()) + int_bytes.len()
            }
            TypeSpecification::VisibleString { max_chars } => {
                let int_bytes = encode_signed_i32_minimal(*max_chars);
                1 + len_size(int_bytes.len()) + int_bytes.len()
            }
            TypeSpecification::MmsString { max_chars } => {
                let int_bytes = encode_signed_i32_minimal(*max_chars);
                1 + len_size(int_bytes.len()) + int_bytes.len()
            }
            TypeSpecification::BinaryTime { .. } => 3, // 0x8c 0x01 0x00/0x01
            TypeSpecification::FloatingPoint { .. } => {
                // 0xa7 <inner_len> 0x02 0x01 <format> 0x02 0x01 <exponent>
                // inner = 3 + 3 = 6 bytes
                1 + 1 + 6
            }
            TypeSpecification::Array {
                element_count,
                element_type,
            } => {
                let count_bytes = encode_unsigned_u32_minimal(*element_count);
                // [1] inner = [1] count INTEGER + [2] EXPLICIT ts
                let ts_len = element_type.encoded_len();
                // [1] numberOfElements: tag 0x81, length field, content
                let count_part = 1 + len_size(count_bytes.len()) + count_bytes.len();
                // [2] elementType EXPLICIT: tag 0xa2, length field, content
                let ts_part = 1 + len_size(ts_len) + ts_len;
                let inner = count_part + ts_part;
                1 + len_size(inner) + inner
            }
            TypeSpecification::Structure { components } => {
                let comp_list_len: usize = components.iter().map(|c| c.encoded_len()).sum();
                // [1] IMPLICIT SEQUENCE OF: tag 0xa1, length field, content
                let list_part = 1 + len_size(comp_list_len) + comp_list_len;
                let inner = list_part;
                1 + len_size(inner) + inner
            }
            // Unknown cannot be encoded; this placeholder is never used, encode() errors.
            TypeSpecification::Unknown(_) => 0,
        }
    }

    /// Encodes the TypeSpecification into `buf`, including the outer tag and length.
    ///
    /// # Errors
    ///
    /// Returns `MmsError::UnknownTypeSpecTag` for an `Unknown` variant rather than
    /// emitting an invalid PDU. Errors from nested values propagate unchanged.
    pub fn encode(&self, buf: &mut BytesMut) -> Result<(), MmsError> {
        match self {
            TypeSpecification::Boolean => {
                buf.extend_from_slice(&[TAG_BOOLEAN, 0x00]);
            }
            TypeSpecification::UtcTime => {
                buf.extend_from_slice(&[TAG_UTCTIME, 0x00]);
            }
            TypeSpecification::BitString { bits } => {
                let int_bytes = encode_signed_i32_minimal(*bits);
                buf.extend_from_slice(&[TAG_BITSTRING]);
                encode_length(int_bytes.len(), buf);
                buf.extend_from_slice(&int_bytes);
            }
            TypeSpecification::Integer { width_bits } => {
                buf.extend_from_slice(&[TAG_INTEGER, 0x01, *width_bits]);
            }
            TypeSpecification::Unsigned { width_bits } => {
                buf.extend_from_slice(&[TAG_UNSIGNED, 0x01, *width_bits]);
            }
            TypeSpecification::FloatingPoint {
                format_width,
                exponent_width,
            } => {
                // Two UNIVERSAL INTEGERs in fixed order: formatwidth first,
                // exponentwidth second.
                let inner: [u8; 6] = [
                    0x02,
                    0x01,
                    *format_width, // formatwidth
                    0x02,
                    0x01,
                    *exponent_width, // exponentwidth
                ];
                buf.extend_from_slice(&[TAG_FLOATINGPOINT]);
                encode_length(inner.len(), buf);
                buf.extend_from_slice(&inner);
            }
            TypeSpecification::OctetString { max_octets } => {
                let int_bytes = encode_signed_i32_minimal(*max_octets);
                buf.extend_from_slice(&[TAG_OCTETSTRING]);
                encode_length(int_bytes.len(), buf);
                buf.extend_from_slice(&int_bytes);
            }
            TypeSpecification::VisibleString { max_chars } => {
                let int_bytes = encode_signed_i32_minimal(*max_chars);
                buf.extend_from_slice(&[TAG_VISIBLESTRING]);
                encode_length(int_bytes.len(), buf);
                buf.extend_from_slice(&int_bytes);
            }
            TypeSpecification::MmsString { max_chars } => {
                let int_bytes = encode_signed_i32_minimal(*max_chars);
                buf.extend_from_slice(&[TAG_MMS_STRING]);
                encode_length(int_bytes.len(), buf);
                buf.extend_from_slice(&int_bytes);
            }
            TypeSpecification::BinaryTime { use_long_form } => {
                // BOOLEAN: 0x00 selects the 4-byte form, 0xff the 6-byte form
                let bool_byte: u8 = if *use_long_form { 0xff } else { 0x00 };
                buf.extend_from_slice(&[TAG_BINARYTIME, 0x01, bool_byte]);
            }
            TypeSpecification::Array {
                element_count,
                element_type,
            } => {
                let mut inner = BytesMut::new();
                // [1] numberOfElements, CONTEXT [1] IMPLICIT INTEGER
                let count_bytes = encode_unsigned_u32_minimal(*element_count);
                inner.extend_from_slice(&[0x81]);
                encode_length(count_bytes.len(), &mut inner);
                inner.extend_from_slice(&count_bytes);
                // [2] elementType, CONTEXT [2] EXPLICIT TypeSpecification
                let mut ts_buf = BytesMut::new();
                element_type.encode(&mut ts_buf)?;
                inner.extend_from_slice(&[0xa2]);
                encode_length(ts_buf.len(), &mut inner);
                inner.extend_from_slice(&ts_buf);

                buf.extend_from_slice(&[TAG_ARRAY]);
                encode_length(inner.len(), buf);
                buf.extend_from_slice(&inner);
            }
            TypeSpecification::Structure { components } => {
                let mut comp_list = BytesMut::new();
                for comp in components {
                    encode_struct_component(comp, &mut comp_list)?;
                }
                // [1] IMPLICIT SEQUENCE OF StructComponent
                let mut inner = BytesMut::new();
                inner.extend_from_slice(&[0xa1]);
                encode_length(comp_list.len(), &mut inner);
                inner.extend_from_slice(&comp_list);

                buf.extend_from_slice(&[TAG_STRUCTURE]);
                encode_length(inner.len(), buf);
                buf.extend_from_slice(&inner);
            }
            // Unknown comes from a decode pass-through; re-encoding cannot reproduce
            // the original bytes, so it is rejected explicitly.
            TypeSpecification::Unknown(tag) => {
                tracing::warn!("cannot encode typespecification unknown(0x{:02X})", tag);
                return Err(MmsError::UnknownTypeSpecTag(*tag));
            }
        }
        Ok(())
    }

    /// Decodes a TypeSpecification; `data` starts at the tag byte.
    ///
    /// `depth` starts at 0 and increases by one for each nested array or structure.
    /// Reaching `MAX_TYPE_SPEC_DEPTH` (32) returns `MmsError::NestingLevelExceeded`.
    ///
    /// Returns the value together with the number of bytes consumed.
    ///
    /// This entry point applies the local ceiling only. Use `decode_with_max` to
    /// apply a negotiated dataStructureNestingLevel as well.
    ///
    /// # Errors
    ///
    /// Returns `NestingLevelExceeded` past 32 levels, `TruncatedPdu` for a short
    /// buffer and `InvalidLength` for a malformed INTEGER. An unknown or unsupported
    /// tag is not an error: it decodes to `Ok(Unknown(tag))`.
    pub fn decode(data: &[u8], depth: u8) -> Result<(Self, usize), MmsError> {
        Self::decode_recursive(data, depth, MAX_TYPE_SPEC_DEPTH)
    }

    /// Decodes a TypeSpecification under a caller-supplied depth ceiling.
    ///
    /// `max_depth` is normally `effective_nesting_cap(MAX_TYPE_SPEC_DEPTH, negotiated)`,
    /// the smaller of the local ceiling and the negotiated dataStructureNestingLevel.
    pub fn decode_with_max(data: &[u8], max_depth: u8) -> Result<(Self, usize), MmsError> {
        Self::decode_recursive(data, 0, max_depth)
    }

    /// Recursive decoder. `depth` is the current level and `max_depth` the ceiling.
    ///
    /// The guard rejects `depth >= max_depth`, so levels 0..max_depth-1 are allowed.
    pub(crate) fn decode_recursive(
        data: &[u8],
        depth: u8,
        max_depth: u8,
    ) -> Result<(Self, usize), MmsError> {
        // Reject at the ceiling so deeply nested input cannot exhaust the stack.
        if depth >= max_depth {
            tracing::warn!(
                "typespecification recursion depth {} reached the effective cap {} (local cap {})",
                depth,
                max_depth,
                MAX_TYPE_SPEC_DEPTH
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
        let (val_len, hdr_size) = decode_length(&data[1..])?;
        let val_start = 1 + hdr_size;
        if val_start + val_len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let val = &data[val_start..val_start + val_len];
        let consumed = val_start + val_len;

        let ts = match tag {
            TAG_BOOLEAN => {
                // NULL, empty content
                TypeSpecification::Boolean
            }
            TAG_UTCTIME => {
                // NULL, empty content
                TypeSpecification::UtcTime
            }
            TAG_BITSTRING => {
                // INTEGER, signed and possibly negative
                let bits = decode_signed_i32(val)?;
                TypeSpecification::BitString { bits }
            }
            TAG_INTEGER => {
                // Unsigned8
                if val.is_empty() {
                    return Err(MmsError::InvalidLength);
                }
                TypeSpecification::Integer { width_bits: val[0] }
            }
            TAG_UNSIGNED => {
                // Unsigned8
                if val.is_empty() {
                    return Err(MmsError::InvalidLength);
                }
                TypeSpecification::Unsigned { width_bits: val[0] }
            }
            TAG_FLOATINGPOINT => {
                // SEQUENCE: 0x02 0x01 <format> 0x02 0x01 <exponent>,
                // formatwidth before exponentwidth
                decode_floatingpoint(val)?
            }
            TAG_OCTETSTRING => {
                let max_octets = decode_signed_i32(val)?;
                TypeSpecification::OctetString { max_octets }
            }
            TAG_VISIBLESTRING => {
                let max_chars = decode_signed_i32(val)?;
                TypeSpecification::VisibleString { max_chars }
            }
            TAG_MMS_STRING => {
                let max_chars = decode_signed_i32(val)?;
                TypeSpecification::MmsString { max_chars }
            }
            TAG_BINARYTIME => {
                // BOOLEAN: 0x00 is the 4-byte form, anything else the 6-byte form
                if val.is_empty() {
                    return Err(MmsError::InvalidLength);
                }
                TypeSpecification::BinaryTime {
                    use_long_form: val[0] != 0,
                }
            }
            TAG_ARRAY => {
                // SEQUENCE: [1] count, then [2] EXPLICIT elementType
                decode_array_inner(val, depth + 1, max_depth)?
            }
            TAG_STRUCTURE => {
                // SEQUENCE: [1] IMPLICIT SEQUENCE OF StructComponent
                decode_structure_inner(val, depth + 1, max_depth)?
            }
            // Unsupported and unknown variants pass through as Unknown(tag) so the
            // caller can log, forward or reject them.
            TAG_TYPE_NAME => {
                tracing::warn!(
                    "typespecification tag typename [0] (0xa0) is unsupported, passing through as unknown"
                );
                TypeSpecification::Unknown(TAG_TYPE_NAME)
            }
            TAG_GENERALIZEDTIME => {
                tracing::warn!(
                    "typespecification tag generalizedtime [11] (0x8b) is unsupported, passing through as unknown"
                );
                TypeSpecification::Unknown(TAG_GENERALIZEDTIME)
            }
            TAG_BCD => {
                tracing::warn!(
                    "typespecification tag bcd [13] (0x8d) is unsupported, passing through as unknown"
                );
                TypeSpecification::Unknown(TAG_BCD)
            }
            TAG_OBJ_ID => {
                tracing::warn!(
                    "typespecification tag objid [15] (0x8f) is unsupported, passing through as unknown"
                );
                TypeSpecification::Unknown(TAG_OBJ_ID)
            }
            other => {
                tracing::warn!(
                    "unknown typespecification tag 0x{:02X}, passing through as unknown",
                    other
                );
                TypeSpecification::Unknown(other)
            }
        };

        Ok((ts, consumed))
    }
}

// StructComponent encode/decode

/// Encodes one StructComponent: a UNIVERSAL SEQUENCE wrapping both fields.
fn encode_struct_component(comp: &StructComponent, buf: &mut BytesMut) -> Result<(), MmsError> {
    let mut inner = BytesMut::new();

    // [0] IMPLICIT VisibleString, componentName
    let name_bytes = comp.name.as_bytes();
    inner.extend_from_slice(&[0x80]);
    encode_length(name_bytes.len(), &mut inner);
    inner.extend_from_slice(name_bytes);

    // [1] EXPLICIT TypeSpecification, componentType
    let mut ts_buf = BytesMut::new();
    comp.type_spec.encode(&mut ts_buf)?;
    inner.extend_from_slice(&[0xa1]);
    encode_length(ts_buf.len(), &mut inner);
    inner.extend_from_slice(&ts_buf);

    // UNIVERSAL SEQUENCE wrapper, tag 0x30
    buf.extend_from_slice(&[0x30]);
    encode_length(inner.len(), buf);
    buf.extend_from_slice(&inner);
    Ok(())
}

/// Decodes one StructComponent; `data` starts at the UNIVERSAL SEQUENCE tag 0x30.
///
/// `depth` is the current recursion level and `max_depth` the ceiling.
fn decode_struct_component(
    data: &[u8],
    depth: u8,
    max_depth: u8,
) -> Result<(StructComponent, usize), MmsError> {
    if data.is_empty() {
        return Err(MmsError::TruncatedPdu);
    }
    if data[0] != 0x30 {
        tracing::warn!(
            "structcomponent expected universal sequence tag 0x30, got 0x{:02X}, rejecting",
            data[0]
        );
        return Err(MmsError::InvalidTag {
            expected: 0x30,
            actual: data[0],
        });
    }
    let (seq_len, seq_hdr) = decode_length(&data[1..])?;
    let seq_start = 1 + seq_hdr;
    if seq_start + seq_len > data.len() {
        return Err(MmsError::TruncatedPdu);
    }
    let seq_inner = &data[seq_start..seq_start + seq_len];
    let consumed = seq_start + seq_len;

    let mut pos = 0usize;
    let mut name: Option<String> = None;
    let mut type_spec: Option<TypeSpecification> = None;

    while pos < seq_inner.len() {
        let field_tag = seq_inner[pos];
        let (flen, fhdr) = decode_length(&seq_inner[pos + 1..])?;
        let fval_start = pos + 1 + fhdr;
        if fval_start + flen > seq_inner.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let fval = &seq_inner[fval_start..fval_start + flen];
        pos = fval_start + flen;

        match field_tag {
            // [0] IMPLICIT VisibleString, componentName
            0x80 => {
                let s = core::str::from_utf8(fval)
                    .map_err(|_| MmsError::InvalidUtf8)?
                    .to_owned();
                name = Some(s);
            }
            // [1] EXPLICIT TypeSpecification, componentType
            0xa1 => {
                let (ts, _) = TypeSpecification::decode_recursive(fval, depth, max_depth)?;
                type_spec = Some(ts);
            }
            other => {
                tracing::debug!("skipping unknown structcomponent field tag 0x{:02X}", other);
            }
        }
    }

    let name = name.ok_or(MmsError::TruncatedPdu)?;
    let type_spec = type_spec.ok_or(MmsError::TruncatedPdu)?;
    Ok((StructComponent { name, type_spec }, consumed))
}

// array / structure inner decode

/// Decodes the inner content of an array, the content of the 0xa1 wrapper.
///
/// Wire format:
/// ```text
/// [0] IMPLICIT BOOLEAN         -- packed, OPTIONAL DEFAULT FALSE, usually omitted
/// [1] IMPLICIT INTEGER         -- numberOfElements, Unsigned32
/// [2] EXPLICIT TypeSpecification -- elementType
/// ```
fn decode_array_inner(val: &[u8], depth: u8, max_depth: u8) -> Result<TypeSpecification, MmsError> {
    let mut pos = 0usize;
    let mut element_count: Option<u32> = None;
    let mut element_type: Option<TypeSpecification> = None;

    while pos < val.len() {
        let field_tag = val[pos];
        let (flen, fhdr) = decode_length(&val[pos + 1..])?;
        let fval_start = pos + 1 + fhdr;
        if fval_start + flen > val.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let fval = &val[fval_start..fval_start + flen];
        pos = fval_start + flen;

        match field_tag {
            // [0] IMPLICIT BOOLEAN, packed, DEFAULT FALSE and usually omitted
            0x80 => {
                // the packed flag is ignored
            }
            // [1] IMPLICIT INTEGER, numberOfElements
            0x81 => {
                let count = decode_unsigned_u32(fval)?;
                element_count = Some(count);
            }
            // [2] EXPLICIT TypeSpecification, elementType
            0xa2 => {
                let (ts, _) = TypeSpecification::decode_recursive(fval, depth, max_depth)?;
                element_type = Some(ts);
            }
            other => {
                tracing::debug!("skipping unknown array field tag 0x{:02X}", other);
            }
        }
    }

    let element_count = element_count.ok_or(MmsError::TruncatedPdu)?;
    let element_type = element_type.ok_or(MmsError::TruncatedPdu)?;
    Ok(TypeSpecification::Array {
        element_count,
        element_type: Box::new(element_type),
    })
}

/// Decodes the inner content of a structure, the content of the 0xa2 wrapper.
///
/// Wire format:
/// ```text
/// [0] IMPLICIT BOOLEAN         -- packed, OPTIONAL DEFAULT FALSE, usually omitted
/// [1] IMPLICIT SEQUENCE OF StructComponent -- components
/// ```
fn decode_structure_inner(
    val: &[u8],
    depth: u8,
    max_depth: u8,
) -> Result<TypeSpecification, MmsError> {
    let mut pos = 0usize;
    let mut components: Option<Vec<StructComponent>> = None;

    while pos < val.len() {
        let field_tag = val[pos];
        let (flen, fhdr) = decode_length(&val[pos + 1..])?;
        let fval_start = pos + 1 + fhdr;
        if fval_start + flen > val.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let fval = &val[fval_start..fval_start + flen];
        pos = fval_start + flen;

        match field_tag {
            // [0] IMPLICIT BOOLEAN, packed, DEFAULT FALSE and usually omitted
            0x80 => {
                // the packed flag is ignored
            }
            // [1] IMPLICIT SEQUENCE OF StructComponent
            0xa1 => {
                let comps = decode_struct_component_list(fval, depth, max_depth)?;
                components = Some(comps);
            }
            other => {
                tracing::debug!("skipping unknown structure field tag 0x{:02X}", other);
            }
        }
    }

    // an empty component list is legal
    let components = components.unwrap_or_default();
    Ok(TypeSpecification::Structure { components })
}

/// Decodes a SEQUENCE OF StructComponent; `data` is the content of the 0xa1 field.
fn decode_struct_component_list(
    data: &[u8],
    depth: u8,
    max_depth: u8,
) -> Result<Vec<StructComponent>, MmsError> {
    let mut comps = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let (comp, consumed) = decode_struct_component(&data[pos..], depth, max_depth)?;
        comps.push(comp);
        pos += consumed;
    }
    Ok(comps)
}

/// Decodes the inner content of a floatingpoint, the content of the 0xa7 wrapper.
///
/// Wire format:
/// ```text
/// 0x02 0x01 <formatwidth>   -- UNIVERSAL INTEGER, formatwidth first
/// 0x02 0x01 <exponentwidth> -- UNIVERSAL INTEGER, exponentwidth second
/// ```
/// Both fields are UNIVERSAL INTEGERs, so position rather than tag carries meaning.
fn decode_floatingpoint(val: &[u8]) -> Result<TypeSpecification, MmsError> {
    // minimum 6 bytes: 0x02 0x01 <fw> 0x02 0x01 <ew>
    if val.len() < 6 {
        tracing::warn!(
            "floatingpoint inner length {} is below the 6-byte minimum of two universal integers",
            val.len()
        );
        return Err(MmsError::TruncatedPdu);
    }
    if val[0] != 0x02 || val[3] != 0x02 {
        tracing::warn!(
            "floatingpoint inner expected two universal integer tags 0x02, got 0x{:02X} 0x{:02X}, rejecting",
            val[0],
            val[3]
        );
        return Err(MmsError::InvalidTag {
            expected: 0x02,
            actual: val[0],
        });
    }
    // length of the first INTEGER
    let fw_len = val[1] as usize;
    if 2 + fw_len > val.len() {
        return Err(MmsError::TruncatedPdu);
    }
    let format_width = if fw_len == 1 {
        val[2]
    } else {
        // a multi-byte width is not expected and is rejected
        return Err(MmsError::InvalidLength);
    };

    let second_start = 2 + fw_len;
    if second_start + 2 > val.len() || val[second_start] != 0x02 {
        return Err(MmsError::TruncatedPdu);
    }
    let ew_len = val[second_start + 1] as usize;
    if second_start + 2 + ew_len > val.len() {
        return Err(MmsError::TruncatedPdu);
    }
    let exponent_width = if ew_len == 1 {
        val[second_start + 2]
    } else {
        return Err(MmsError::InvalidLength);
    };

    Ok(TypeSpecification::FloatingPoint {
        format_width,
        exponent_width,
    })
}

// BER integer helpers, private to this module

/// Returns the number of bytes a BER length field needs for `len`.
pub(crate) fn len_size(len: usize) -> usize {
    if len < 128 {
        1
    } else if len <= 0xff {
        2
    } else {
        3
    }
}

/// Encodes a signed `i32` as the shortest BER INTEGER.
///
/// Negative values are allowed: they carry the variable-length meaning used by
/// bitString, octetString, visibleString and mMSString.
pub(crate) fn encode_signed_i32_minimal(val: i32) -> Vec<u8> {
    if val == 0 {
        return vec![0x00];
    }
    let bytes = val.to_be_bytes();
    let mut start = 0usize;
    while start < 3 {
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

/// Decodes a signed big-endian INTEGER of 1 to 4 bytes into an `i32`.
fn decode_signed_i32(data: &[u8]) -> Result<i32, MmsError> {
    if data.is_empty() || data.len() > 4 {
        return Err(MmsError::InvalidLength);
    }
    // sign extension
    let sign_bit = (data[0] & 0x80) != 0;
    let mut val: i32 = if sign_bit { -1 } else { 0 };
    for &b in data {
        val = (val << 8) | (b as i32);
    }
    Ok(val)
}

/// Encodes an unsigned `u32` as the shortest BER INTEGER; BER INTEGER is signed,
/// so the most significant bit needs care.
pub(crate) fn encode_unsigned_u32_minimal(val: u32) -> Vec<u8> {
    if val == 0 {
        return vec![0x00];
    }
    let bytes = val.to_be_bytes();
    let mut start = 0usize;
    // strip leading zero bytes while keeping the value non-negative
    while start < 3 && bytes[start] == 0x00 && (bytes[start + 1] & 0x80) == 0 {
        start += 1;
    }
    // a leading 0x00 is prepended when the top bit is set, so the value stays positive
    let slice = &bytes[start..];
    if slice[0] & 0x80 != 0 {
        let mut v = vec![0x00];
        v.extend_from_slice(slice);
        v
    } else {
        slice.to_vec()
    }
}

/// Decodes an unsigned big-endian INTEGER of 1 to 4 bytes into a `u32`.
fn decode_unsigned_u32(data: &[u8]) -> Result<u32, MmsError> {
    if data.is_empty() || data.len() > 5 {
        // up to 5 bytes, allowing one leading 0x00
        return Err(MmsError::InvalidLength);
    }
    let mut val = 0u32;
    // skip a leading 0x00 inserted to keep the BER INTEGER non-negative
    let start = if data[0] == 0x00 && data.len() > 1 {
        1
    } else {
        0
    };
    if data.len() - start > 4 {
        return Err(MmsError::InvalidLength);
    }
    for &b in &data[start..] {
        val = (val << 8) | (b as u32);
    }
    Ok(val)
}

// Unit tests

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodes, decodes, and asserts the result equals the input.
    fn roundtrip(ts: TypeSpecification) {
        let mut buf = BytesMut::new();
        ts.encode(&mut buf).expect("encode failed");
        let (decoded, consumed) = TypeSpecification::decode(&buf, 0).expect("decode failed");
        assert_eq!(
            consumed,
            buf.len(),
            "consumed bytes differ from the encoded length"
        );
        assert_eq!(decoded, ts, "the round trip changed the value");
    }

    // Boolean and UtcTime, the NULL variants

    #[test]
    fn boolean_roundtrip() {
        roundtrip(TypeSpecification::Boolean);
    }

    #[test]
    fn utctime_roundtrip() {
        roundtrip(TypeSpecification::UtcTime);
    }

    #[test]
    fn boolean_byte_exact() {
        let mut buf = BytesMut::new();
        TypeSpecification::Boolean.encode(&mut buf).unwrap();
        assert_eq!(&buf[..], &[0x83, 0x00], "unexpected boolean wire bytes");
    }

    #[test]
    fn utctime_byte_exact() {
        let mut buf = BytesMut::new();
        TypeSpecification::UtcTime.encode(&mut buf).unwrap();
        assert_eq!(&buf[..], &[0x91, 0x00], "unexpected utctime wire bytes");
    }

    // Integer and Unsigned

    #[test]
    fn integer_width_8_roundtrip() {
        roundtrip(TypeSpecification::Integer { width_bits: 8 });
    }

    #[test]
    fn integer_width_32_roundtrip() {
        roundtrip(TypeSpecification::Integer { width_bits: 32 });
    }

    #[test]
    fn unsigned_width_8_roundtrip() {
        roundtrip(TypeSpecification::Unsigned { width_bits: 8 });
    }

    #[test]
    fn unsigned_width_32_roundtrip() {
        roundtrip(TypeSpecification::Unsigned { width_bits: 32 });
    }

    // FloatingPoint

    #[test]
    fn float32_roundtrip() {
        // float32: formatwidth 32, exponentwidth 8
        roundtrip(TypeSpecification::FloatingPoint {
            format_width: 32,
            exponent_width: 8,
        });
    }

    #[test]
    fn float64_roundtrip() {
        // float64: formatwidth 64, exponentwidth 11
        roundtrip(TypeSpecification::FloatingPoint {
            format_width: 64,
            exponent_width: 11,
        });
    }

    /// Checks the float32 wire bytes, with formatwidth before exponentwidth.
    ///
    /// ```text
    /// 0xa7 0x06           -- floatingpoint [7] IMPLICIT SEQUENCE, len=6
    ///   0x02 0x01 0x20    -- formatwidth INTEGER 32 (0x20)
    ///   0x02 0x01 0x08    -- exponentwidth INTEGER 8
    /// ```
    #[test]
    fn float32_byte_exact() {
        let mut buf = BytesMut::new();
        TypeSpecification::FloatingPoint {
            format_width: 32,
            exponent_width: 8,
        }
        .encode(&mut buf)
        .unwrap();
        let expected: &[u8] = &[0xa7, 0x06, 0x02, 0x01, 0x20, 0x02, 0x01, 0x08];
        assert_eq!(
            &buf[..],
            expected,
            "unexpected float32 wire bytes: got {:02X?}, expected {:02X?}",
            &buf[..],
            expected
        );
    }

    // Negative bitString values

    #[test]
    fn bitstring_positive_roundtrip() {
        roundtrip(TypeSpecification::BitString { bits: 64 });
    }

    #[test]
    fn bitstring_negative_variable_length_roundtrip() {
        // bits = -1 denotes a variable-length bit string
        roundtrip(TypeSpecification::BitString { bits: -1 });
    }

    #[test]
    fn bitstring_negative_preserves_sign() {
        let ts = TypeSpecification::BitString { bits: -1 };
        let mut buf = BytesMut::new();
        ts.encode(&mut buf).unwrap();
        let (decoded, _) = TypeSpecification::decode(&buf, 0).unwrap();
        match decoded {
            TypeSpecification::BitString { bits } => {
                assert_eq!(bits, -1, "bitString -1 changed in the round trip");
            }
            other => panic!("expected BitString, got {:?}", other),
        }
    }

    // OctetString, VisibleString and MmsString

    #[test]
    fn octet_string_positive_roundtrip() {
        roundtrip(TypeSpecification::OctetString { max_octets: 128 });
    }

    #[test]
    fn octet_string_negative_roundtrip() {
        // -1 denotes variable length
        roundtrip(TypeSpecification::OctetString { max_octets: -1 });
    }

    #[test]
    fn visible_string_roundtrip() {
        roundtrip(TypeSpecification::VisibleString { max_chars: 255 });
    }

    #[test]
    fn mms_string_roundtrip() {
        roundtrip(TypeSpecification::MmsString { max_chars: 255 });
    }

    // BinaryTime

    #[test]
    fn binary_time_short_roundtrip() {
        // false = 4-byte form
        roundtrip(TypeSpecification::BinaryTime {
            use_long_form: false,
        });
    }

    #[test]
    fn binary_time_long_roundtrip() {
        // true = 6-byte form
        roundtrip(TypeSpecification::BinaryTime {
            use_long_form: true,
        });
    }

    // Array

    #[test]
    fn array_of_boolean_roundtrip() {
        roundtrip(TypeSpecification::Array {
            element_count: 10,
            element_type: Box::new(TypeSpecification::Boolean),
        });
    }

    #[test]
    fn array_of_integer_roundtrip() {
        roundtrip(TypeSpecification::Array {
            element_count: 100,
            element_type: Box::new(TypeSpecification::Integer { width_bits: 32 }),
        });
    }

    // Structure

    #[test]
    fn structure_simple_roundtrip() {
        roundtrip(TypeSpecification::Structure {
            components: vec![
                StructComponent {
                    name: "stVal".to_owned(),
                    type_spec: TypeSpecification::Boolean,
                },
                StructComponent {
                    name: "q".to_owned(),
                    type_spec: TypeSpecification::BitString { bits: 13 },
                },
                StructComponent {
                    name: "t".to_owned(),
                    type_spec: TypeSpecification::UtcTime,
                },
            ],
        });
    }

    // Nested Array and Structure round trips

    #[test]
    fn array_of_structure_roundtrip() {
        roundtrip(TypeSpecification::Array {
            element_count: 5,
            element_type: Box::new(TypeSpecification::Structure {
                components: vec![
                    StructComponent {
                        name: "val".to_owned(),
                        type_spec: TypeSpecification::FloatingPoint {
                            format_width: 32,
                            exponent_width: 8,
                        },
                    },
                    StructComponent {
                        name: "ts".to_owned(),
                        type_spec: TypeSpecification::UtcTime,
                    },
                ],
            }),
        });
    }

    #[test]
    fn structure_three_level_nested_roundtrip() {
        // three nested levels: structure inside structure inside structure
        let inner_inner = TypeSpecification::Structure {
            components: vec![StructComponent {
                name: "leaf".to_owned(),
                type_spec: TypeSpecification::Integer { width_bits: 32 },
            }],
        };
        let inner = TypeSpecification::Structure {
            components: vec![StructComponent {
                name: "mid".to_owned(),
                type_spec: inner_inner,
            }],
        };
        let outer = TypeSpecification::Structure {
            components: vec![StructComponent {
                name: "outer".to_owned(),
                type_spec: inner,
            }],
        };
        roundtrip(outer);
    }

    // Recursion depth guard

    /// A nested array PDU deeper than 32 levels must decode to an error, not crash.
    /// Robustness case: unbounded TypeSpecification recursion.
    ///
    /// Guard semantics: `depth >= MAX_TYPE_SPEC_DEPTH` (32) returns an error.
    /// The entry point starts at depth 0 for the outermost TypeSpecification and
    /// adds one per level, so the 33rd level reaches 32 and trips the guard.
    #[test]
    fn depth_limit_exceeded_returns_err() {
        // BER definite length: short form below 128, otherwise 0x80 | n followed by
        // n big-endian bytes.
        fn push_ber_length(out: &mut Vec<u8>, len: usize) {
            if len < 128 {
                out.push(len as u8);
            } else if len <= 0xff {
                out.push(0x81);
                out.push(len as u8);
            } else if len <= 0xffff {
                out.push(0x82);
                out.push((len >> 8) as u8);
                out.push((len & 0xff) as u8);
            } else {
                unreachable!("test fixture length should fit in 2 bytes");
            }
        }

        // Build N nested array TypeSpecs; each level is
        // 0xa1 len [0x81 0x01 0x01 0xa2 innerlen inner], with a boolean innermost.
        fn make_nested_array_bytes(depth: usize) -> Vec<u8> {
            if depth == 0 {
                return vec![0x83, 0x00];
            }
            let inner = make_nested_array_bytes(depth - 1);
            // 0xa2 + innerlen + inner
            let mut element_type_tlv = vec![0xa2u8];
            push_ber_length(&mut element_type_tlv, inner.len());
            element_type_tlv.extend_from_slice(&inner);
            // count_part = 0x81 0x01 0x01
            let count_part: &[u8] = &[0x81, 0x01, 0x01];
            let total_inner = count_part.len() + element_type_tlv.len();
            let mut result = vec![0xa1u8];
            push_ber_length(&mut result, total_inner);
            result.extend_from_slice(count_part);
            result.extend_from_slice(&element_type_tlv);
            result
        }

        // 33 array levels plus the innermost boolean: the 33rd decodes at depth 32.
        let bomb = make_nested_array_bytes(33);
        let result = TypeSpecification::decode(&bomb, 0);
        assert!(
            matches!(result, Err(MmsError::NestingLevelExceeded { .. })),
            "nesting beyond 32 levels must return NestingLevelExceeded, got {:?}",
            result
        );
    }

    #[test]
    fn depth_at_limit_ok() {
        // depth 31 is the deepest the guard allows: it rejects at 32, leaving the
        // 32 slots 0..31. A primitive TypeSpec entered at depth 31 must decode.
        let ts = TypeSpecification::Boolean;
        let mut buf = BytesMut::new();
        ts.encode(&mut buf).unwrap();
        let result = TypeSpecification::decode(&buf, 31);
        assert!(
            result.is_ok(),
            "depth 31 is inside the guard and must succeed, got {:?}",
            result
        );
    }

    // Unknown and unsupported tags pass through as Ok(Unknown(...))

    /// An unknown tag passes through as `Unknown(tag)` instead of failing.
    #[test]
    fn unknown_tag_decodes_as_unknown() {
        // tag 0x88 is not in the table
        let data = [0x88u8, 0x00];
        let result = TypeSpecification::decode(&data, 0);
        assert!(
            matches!(result, Ok((TypeSpecification::Unknown(0x88), 2))),
            "an unknown tag must pass through as Unknown(0x88), got {:?}",
            result
        );
    }

    /// generalizedtime passes through as `Unknown` instead of failing.
    #[test]
    fn generalizedtime_tag_decodes_as_unknown() {
        // tag 0x8b is generalizedtime, unsupported and passed through
        let data = [TAG_GENERALIZEDTIME, 0x00];
        let result = TypeSpecification::decode(&data, 0);
        assert!(
            matches!(result, Ok((TypeSpecification::Unknown(0x8b), 2))),
            "generalizedtime must pass through as Unknown(0x8b), got {:?}",
            result
        );
    }

    /// bcd passes through as `Unknown` instead of failing.
    #[test]
    fn bcd_tag_decodes_as_unknown() {
        let data = [TAG_BCD, 0x01, 0x04];
        let result = TypeSpecification::decode(&data, 0);
        assert!(
            matches!(result, Ok((TypeSpecification::Unknown(0x8d), 3))),
            "bcd must pass through as Unknown(0x8d), got {:?}",
            result
        );
    }

    /// typeName passes through as `Unknown` instead of failing.
    #[test]
    fn type_name_tag_decodes_as_unknown() {
        // tag 0xa0 is typeName [0] EXPLICIT, unsupported and passed through
        let data = [TAG_TYPE_NAME, 0x00];
        let result = TypeSpecification::decode(&data, 0);
        assert!(
            matches!(result, Ok((TypeSpecification::Unknown(0xa0), 2))),
            "typeName must pass through as Unknown(0xa0), got {:?}",
            result
        );
    }

    // Unknown variant coverage

    #[test]
    fn unknown_type_name_tag_decodes_as_unknown() {
        // typeName with empty content: 0xa0 0x00 decodes to Unknown(0xa0), consuming 2
        let data = [0xa0u8, 0x00];
        let (ts, consumed) = TypeSpecification::decode(&data, 0).expect("decode must succeed");
        assert_eq!(
            ts,
            TypeSpecification::Unknown(0xa0),
            "expected Unknown(0xa0)"
        );
        assert_eq!(consumed, 2, "expected 2 consumed bytes");
    }

    #[test]
    fn unknown_generalizedtime_decodes_as_unknown() {
        // generalizedtime with empty content: 0x8b 0x00 decodes to Unknown(0x8b), consuming 2
        let data = [0x8bu8, 0x00];
        let (ts, consumed) = TypeSpecification::decode(&data, 0).expect("decode must succeed");
        assert_eq!(
            ts,
            TypeSpecification::Unknown(0x8b),
            "expected Unknown(0x8b)"
        );
        assert_eq!(consumed, 2, "expected 2 consumed bytes");
    }

    #[test]
    fn unknown_bcd_decodes_as_unknown() {
        // bcd with one content byte: 0x8d 0x01 0x10 decodes to Unknown(0x8d), consuming 3
        let data = [0x8du8, 0x01, 0x10];
        let (ts, consumed) = TypeSpecification::decode(&data, 0).expect("decode must succeed");
        assert_eq!(
            ts,
            TypeSpecification::Unknown(0x8d),
            "expected Unknown(0x8d)"
        );
        assert_eq!(consumed, 3, "expected 3 consumed bytes");
    }

    #[test]
    fn unknown_obj_id_decodes_as_unknown() {
        // objId with empty content: 0x8f 0x00 decodes to Unknown(0x8f), consuming 2
        let data = [0x8fu8, 0x00];
        let (ts, consumed) = TypeSpecification::decode(&data, 0).expect("decode must succeed");
        assert_eq!(
            ts,
            TypeSpecification::Unknown(0x8f),
            "expected Unknown(0x8f)"
        );
        assert_eq!(consumed, 2, "expected 2 consumed bytes");
    }

    #[test]
    fn truly_unknown_tag_passes_through() {
        // undefined tag 0xb0 with 2 content bytes decodes to Unknown(0xb0), consuming 4
        let data = [0xb0u8, 0x02, 0x00, 0x00];
        let (ts, consumed) = TypeSpecification::decode(&data, 0).expect("decode must succeed");
        assert_eq!(
            ts,
            TypeSpecification::Unknown(0xb0),
            "expected Unknown(0xb0)"
        );
        assert_eq!(consumed, 4, "expected 4 consumed bytes");
    }

    #[test]
    fn unknown_inside_array_propagates() {
        // an array whose elementType decodes to an Unknown variant
        // wire: 0xa1 <len> [0x81 0x01 0x01] [0xa2 <ts_len> [0xa0 0x00]]
        // count = 1, elementType = typeName, which decodes to Unknown(0xa0)
        let element_ts: &[u8] = &[0xa0, 0x00]; // Unknown(0xa0) TLV
        let mut inner = Vec::new();
        // [1] numberOfElements = 1
        inner.extend_from_slice(&[0x81, 0x01, 0x01]);
        // [2] EXPLICIT elementType
        inner.push(0xa2);
        inner.push(element_ts.len() as u8);
        inner.extend_from_slice(element_ts);

        let mut data = Vec::new();
        data.push(0xa1); // TAG_ARRAY
        data.push(inner.len() as u8);
        data.extend_from_slice(&inner);

        let (ts, consumed) = TypeSpecification::decode(&data, 0).expect("decode must succeed");
        assert_eq!(consumed, data.len(), "consumed must cover the whole TLV");
        match ts {
            TypeSpecification::Array {
                element_count,
                element_type,
            } => {
                assert_eq!(element_count, 1);
                assert_eq!(*element_type, TypeSpecification::Unknown(0xa0));
            }
            other => panic!("expected Array, got {:?}", other),
        }
    }

    #[test]
    fn unknown_inside_structure_component_propagates() {
        // a structure whose single component has type Unknown(0x8b), generalizedtime
        // StructComponent = 0x30 <inner>
        //   0x80 0x03 b"val"    (componentName)
        //   0xa1 <ts_len> [0x8b 0x00]  ([1] EXPLICIT componentType)
        let comp_name = b"val";
        let ts_bytes: &[u8] = &[0x8b, 0x00]; // generalizedtime Unknown(0x8b)
        let mut comp_inner = Vec::new();
        comp_inner.push(0x80);
        comp_inner.push(comp_name.len() as u8);
        comp_inner.extend_from_slice(comp_name);
        comp_inner.push(0xa1);
        comp_inner.push(ts_bytes.len() as u8);
        comp_inner.extend_from_slice(ts_bytes);

        let mut comp_tlv = Vec::new();
        comp_tlv.push(0x30);
        comp_tlv.push(comp_inner.len() as u8);
        comp_tlv.extend_from_slice(&comp_inner);

        // [1] IMPLICIT SEQUENCE OF StructComponent
        let mut list_inner = Vec::new();
        list_inner.extend_from_slice(&comp_tlv);
        let mut struct_inner = Vec::new();
        struct_inner.push(0xa1);
        struct_inner.push(list_inner.len() as u8);
        struct_inner.extend_from_slice(&list_inner);

        let mut data = Vec::new();
        data.push(0xa2); // TAG_STRUCTURE
        data.push(struct_inner.len() as u8);
        data.extend_from_slice(&struct_inner);

        let (ts, consumed) = TypeSpecification::decode(&data, 0).expect("decode must succeed");
        assert_eq!(consumed, data.len(), "consumed must cover the whole TLV");
        match ts {
            TypeSpecification::Structure { components } => {
                assert_eq!(components.len(), 1);
                assert_eq!(components[0].name, "val");
                assert_eq!(components[0].type_spec, TypeSpecification::Unknown(0x8b));
            }
            other => panic!("expected Structure, got {:?}", other),
        }
    }

    #[test]
    fn unknown_encode_returns_err() {
        let mut buf = BytesMut::new();
        let result = TypeSpecification::Unknown(0xa0).encode(&mut buf);
        assert!(
            matches!(result, Err(MmsError::UnknownTypeSpecTag(0xa0))),
            "encoding Unknown must return Err(UnknownTypeSpecTag(0xa0)), got {:?}",
            result
        );
        assert!(buf.is_empty(), "buf must stay empty when encoding fails");
    }

    // Malformed input must be rejected

    #[test]
    fn truncated_floatingpoint_returns_err() {
        // a floatingpoint whose inner content is truncated after formatwidth:
        // 0xa7 0x03 0x02 0x01 0x20, with exponentwidth missing
        let data = [0xa7u8, 0x03, 0x02, 0x01, 0x20];
        let result = TypeSpecification::decode(&data, 0);
        assert!(
            result.is_err(),
            "a truncated floatingpoint must return an error, got {:?}",
            result
        );
    }

    #[test]
    fn empty_input_returns_truncated() {
        let result = TypeSpecification::decode(&[], 0);
        assert!(matches!(result, Err(MmsError::TruncatedPdu)));
    }

    #[test]
    fn truncated_pdu_returns_err() {
        // 0x85 0x02 0x20: length 2 with only one byte following
        let data = [0x85u8, 0x02, 0x20];
        let result = TypeSpecification::decode(&data, 0);
        assert!(
            result.is_err(),
            "a truncated pdu must return an error, got {:?}",
            result
        );
    }

    // Robustness case: unbounded structure recursion

    #[test]
    fn unbounded_structure_recursion_returns_err() {
        // 100 nested structure levels must return an error rather than crash
        // each level: 0xa2 <len> 0xa1 <comp_list_len> 0x30 <seq_len> 0x80 <name_len> "x" 0xa1 <ts_len> <inner>
        fn make_nested_structure_bytes(depth: usize) -> Vec<u8> {
            if depth == 0 {
                return vec![0x83, 0x00]; // boolean NULL
            }
            // structure [2] holding one StructComponent
            // StructComponent = 0x30 <inner_len>
            //   0x80 0x01 b'x'   (componentName "x")
            //   0xa1 <ts_len> <inner_ts>  ([1] EXPLICIT componentType)
            let inner_ts = make_nested_structure_bytes(depth - 1);
            // [1] EXPLICIT TypeSpecification wrapper
            let comp_type_part_len = 1 + 1 + inner_ts.len(); // 0xa1 len content
                                                             // componentName = 0x80 0x01 b'x' (3 bytes)
            let seq_inner_len = 3 + comp_type_part_len;
            // UNIVERSAL SEQUENCE 0x30
            let seq_total = 1 + 1 + seq_inner_len; // 0x30 len content
                                                   // [1] IMPLICIT SEQUENCE OF wrapper: 0xa1 len seq_total
            let list_inner_len = seq_total;
            let list_total = 1 + 1 + list_inner_len;
            // structure outer: 0xa2 len list_total
            let outer_inner_len = list_total;

            let mut result = vec![0xa2u8]; // TAG_STRUCTURE
            if outer_inner_len < 128 {
                result.push(outer_inner_len as u8);
            } else {
                result.push(0x81);
                result.push(outer_inner_len as u8);
            }
            // [1] IMPLICIT SEQUENCE OF
            result.push(0xa1);
            if list_inner_len < 128 {
                result.push(list_inner_len as u8);
            } else {
                result.push(0x81);
                result.push(list_inner_len as u8);
            }
            // UNIVERSAL SEQUENCE 0x30
            result.push(0x30);
            if seq_inner_len < 128 {
                result.push(seq_inner_len as u8);
            } else {
                result.push(0x81);
                result.push(seq_inner_len as u8);
            }
            // componentName
            result.extend_from_slice(&[0x80, 0x01, b'x']);
            // componentType [1] EXPLICIT
            result.push(0xa1);
            if inner_ts.len() < 128 {
                result.push(inner_ts.len() as u8);
            } else {
                result.push(0x81);
                result.push(inner_ts.len() as u8);
            }
            result.extend_from_slice(&inner_ts);
            result
        }

        let bomb = make_nested_structure_bytes(100);
        let result = TypeSpecification::decode(&bomb, 0);
        assert!(
            result.is_err(),
            "100 nested structure levels must return an error, got {:?}",
            result
        );
    }

    // decode_with_max honors the negotiated nesting level

    /// With a local cap of 32 and a negotiated 5 the effective cap is 5, so the
    /// sixth level must fail.
    #[test]
    fn type_spec_negotiated_lower_than_local_cap_clamps() {
        // builds N nested array TypeSpec bytes
        fn push_len(out: &mut Vec<u8>, len: usize) {
            if len < 128 {
                out.push(len as u8);
            } else if len <= 0xff {
                out.push(0x81);
                out.push(len as u8);
            } else {
                out.push(0x82);
                out.push((len >> 8) as u8);
                out.push((len & 0xff) as u8);
            }
        }
        fn make_nested(depth: usize) -> Vec<u8> {
            if depth == 0 {
                return vec![0x83, 0x00]; // boolean
            }
            let inner = make_nested(depth - 1);
            let mut et_tlv = vec![0xa2u8];
            push_len(&mut et_tlv, inner.len());
            et_tlv.extend_from_slice(&inner);
            let count_part: &[u8] = &[0x81, 0x01, 0x01];
            let total_inner = count_part.len() + et_tlv.len();
            let mut result = vec![0xa1u8];
            push_len(&mut result, total_inner);
            result.extend_from_slice(count_part);
            result.extend_from_slice(&et_tlv);
            result
        }
        // the effective cap is min(32, 5) = 5, so 6 levels must fail
        let data = make_nested(6);
        let result = TypeSpecification::decode_with_max(&data, 5);
        assert!(
            matches!(result, Err(MmsError::NestingLevelExceeded { .. })),
            "with a negotiated cap of 5, six levels must fail, got {:?}",
            result
        );
    }

    /// With a local cap of 32 and a negotiated 100 the effective cap stays 32, so
    /// the 33rd level still fails.
    #[test]
    fn type_spec_negotiated_higher_than_local_still_clamps_to_local() {
        use crate::mms::pdu::common::effective_nesting_cap;
        let effective = effective_nesting_cap(MAX_TYPE_SPEC_DEPTH, Some(100));
        assert_eq!(effective, 32);
        // decode 33 levels with an effective cap of 32, which must fail
        fn push_len(out: &mut Vec<u8>, len: usize) {
            if len < 128 {
                out.push(len as u8);
            } else if len <= 0xff {
                out.push(0x81);
                out.push(len as u8);
            } else {
                out.push(0x82);
                out.push((len >> 8) as u8);
                out.push((len & 0xff) as u8);
            }
        }
        fn make_nested(depth: usize) -> Vec<u8> {
            if depth == 0 {
                return vec![0x83, 0x00];
            }
            let inner = make_nested(depth - 1);
            let mut et_tlv = vec![0xa2u8];
            push_len(&mut et_tlv, inner.len());
            et_tlv.extend_from_slice(&inner);
            let count_part: &[u8] = &[0x81, 0x01, 0x01];
            let total_inner = count_part.len() + et_tlv.len();
            let mut result = vec![0xa1u8];
            push_len(&mut result, total_inner);
            result.extend_from_slice(count_part);
            result.extend_from_slice(&et_tlv);
            result
        }
        let data = make_nested(33);
        let result = TypeSpecification::decode_with_max(&data, effective);
        assert!(
            matches!(result, Err(MmsError::NestingLevelExceeded { .. })),
            "a negotiated cap of 100 above the local 32 must still fail at 33 levels, got {:?}",
            result
        );
    }
}
