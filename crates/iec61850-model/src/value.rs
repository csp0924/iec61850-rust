//! `MmsValue`, the authoritative value type of the model.
//!
//! The Rust representation of an MMS value as used by IEC 61850-8-1. This type
//! covers construction, comparison and reading; BER encoding and decoding live
//! in `iec61850-asn1` and in the layers that own the wire format.
//!
//! A value owns its data outright, so no borrow escapes the model. `Float32`
//! and `Float64` are separate variants, because ISO 9506-2 distinguishes them
//! only by the exponent width and one shared variant would invite a wire-width
//! mistake. `BinaryTime` keeps its bytes in a `Vec`, so a single variant
//! carries both the 4-byte and the 6-byte form and the caller decides which
//! applies.

use crate::compat::prelude::*;

/// An MMS value.
///
/// The tag bytes named on each variant are the CONTEXT IMPLICIT tags of
/// `AccessResult` in ISO 9506-2, matching the encoding the MMS layer uses.
#[derive(Debug, Clone, PartialEq)]
pub enum MmsValue {
    /// `0x83` BOOLEAN.
    Boolean(bool),
    /// `0x85` INTEGER; the encoder picks the wire width from the value.
    Integer(i64),
    /// `0x86` UNSIGNED.
    Unsigned(u64),
    /// `0x87` FLOAT with exponent width 8, five bytes on the wire.
    Float32(f32),
    /// `0x87` FLOAT with exponent width 11, nine bytes on the wire.
    Float64(f64),
    /// `0x84` BIT_STRING; `padding` counts the unused bits of the last byte.
    BitString {
        /// Number of unused bits in the last byte.
        padding: u8,
        /// The bit string bytes, most significant bit first.
        data: Vec<u8>,
    },
    /// `0x89` OCTET_STRING.
    OctetString(Vec<u8>),
    /// `0x8a` VISIBLE_STRING, ASCII.
    VisibleString(String),
    /// `0x90` MMS_STRING, UTF-8.
    MmsString(String),
    /// `0x91` UTC_TIME, always eight bytes.
    UtcTime([u8; 8]),
    /// `0x8c` BINARY_TIME, four or six bytes.
    ///
    /// Four big-endian bytes of milliseconds since midnight, and in the
    /// six-byte form two further big-endian bytes counting days since the
    /// 1984-01-01 epoch of the type.
    BinaryTime(Vec<u8>),
    /// `0xa1` ARRAY OF MmsValue.
    Array(Vec<MmsValue>),
    /// `0xa2` STRUCTURE OF MmsValue.
    Structure(Vec<MmsValue>),
}

impl MmsValue {
    /// Builds the default zero value for a data attribute type.
    ///
    /// The zero value is materialized rather than left absent, so no reader
    /// has to handle a missing value.
    pub fn default_for(ty: crate::types::DataAttributeType) -> MmsValue {
        use crate::types::DataAttributeType as T;
        match ty {
            T::Boolean => MmsValue::Boolean(false),
            T::Int8 | T::Int16 | T::Int32 | T::Int64 | T::Int128 => MmsValue::Integer(0),
            T::Int8U | T::Int16U | T::Int24U | T::Int32U => MmsValue::Unsigned(0),
            T::Float32 => MmsValue::Float32(0.0),
            T::Float64 => MmsValue::Float64(0.0),
            T::Enumerated => MmsValue::Integer(0),
            T::OctetString(_) => MmsValue::OctetString(Vec::new()),
            T::VisibleString(_) | T::Currency => MmsValue::VisibleString(String::new()),
            T::UnicodeString255 => MmsValue::MmsString(String::new()),
            T::Timestamp => MmsValue::UtcTime([0u8; 8]),
            // 13-bit bit string, padding 3
            T::Quality => MmsValue::BitString {
                padding: 3,
                data: vec![0, 0],
            },
            // 2-bit bit string, padding 6
            T::CodedEnum | T::Check => MmsValue::BitString {
                padding: 6,
                data: vec![0],
            },
            T::GenericBitString(n) => {
                let bytes = n.div_ceil(8) as usize;
                let used_bits = n as usize;
                let padding = (bytes * 8 - used_bits) as u8;
                MmsValue::BitString {
                    padding,
                    data: vec![0; bytes],
                }
            }
            // OptFlds is 10 bits wide and TrgOps 6; each gets its own width.
            T::OptFlds => MmsValue::BitString {
                padding: 6,
                data: vec![0, 0],
            },
            T::TrgOpsBits => MmsValue::BitString {
                padding: 2,
                data: vec![0],
            },
            T::Constructed | T::PhyComAddr => MmsValue::Structure(Vec::new()),
            T::EntryTime => MmsValue::BinaryTime(vec![0u8; 6]),
        }
    }

    /// Returns a readable name for this variant, for use in error messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            MmsValue::Boolean(_) => "Boolean",
            MmsValue::Integer(_) => "Integer",
            MmsValue::Unsigned(_) => "Unsigned",
            MmsValue::Float32(_) => "Float32",
            MmsValue::Float64(_) => "Float64",
            MmsValue::BitString { .. } => "BitString",
            MmsValue::OctetString(_) => "OctetString",
            MmsValue::VisibleString(_) => "VisibleString",
            MmsValue::MmsString(_) => "MmsString",
            MmsValue::UtcTime(_) => "UtcTime",
            MmsValue::BinaryTime(_) => "BinaryTime",
            MmsValue::Array(_) => "Array",
            MmsValue::Structure(_) => "Structure",
        }
    }

    /// Reports whether two values are the same variant, without comparing
    /// their contents. Used by the Write service to check types.
    pub fn same_variant(&self, other: &MmsValue) -> bool {
        core::mem::discriminant(self) == core::mem::discriminant(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_name_covers_all_variants() {
        let cases: &[MmsValue] = &[
            MmsValue::Boolean(true),
            MmsValue::Integer(0),
            MmsValue::Unsigned(0),
            MmsValue::Float32(0.0),
            MmsValue::Float64(0.0),
            MmsValue::BitString {
                padding: 0,
                data: vec![],
            },
            MmsValue::OctetString(vec![]),
            MmsValue::VisibleString(String::new()),
            MmsValue::MmsString(String::new()),
            MmsValue::UtcTime([0; 8]),
            MmsValue::BinaryTime(vec![0; 4]),
            MmsValue::Array(vec![]),
            MmsValue::Structure(vec![]),
        ];
        for v in cases {
            assert!(!v.type_name().is_empty());
        }
    }

    #[test]
    fn same_variant_distinguishes_floats() {
        let a = MmsValue::Float32(1.0);
        let b = MmsValue::Float64(1.0);
        assert!(!a.same_variant(&b));
        assert!(a.same_variant(&MmsValue::Float32(2.0)));
    }

    #[test]
    fn same_variant_distinguishes_array_vs_structure() {
        let a = MmsValue::Array(vec![]);
        let b = MmsValue::Structure(vec![]);
        assert!(!a.same_variant(&b));
    }
}
