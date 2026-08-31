//! Conversions between the model value type and the MMS wire types, following
//! the type mapping of IEC 61850-8-1.
//!
//! `MmsValue` and `MmsData` are near-parallel enums and convert variant by
//! variant in both directions: the Read path turns a model value into wire
//! data, and the Write path turns decoded wire data back into a model value.
//! `MmsTypeSpec` converts to `TypeSpecification` in one direction only, for
//! GetVariableAccessAttributes. A generic bit string carries no declared size,
//! so its type specification encodes `bitString = 0` per IEC 61850-8-1 §9.7.

// These names are in the std prelude, so the import is only needed in a no_std
// build. Which subset is used depends on the enabled features, hence the blanket
// allow rather than one cfg per name.
#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};

use crate::mapping::{MmsLeafType, MmsTypeSpec, NamedVariableSpec, StringSize};
use iec61850_mms::mms::pdu::{
    common::MmsData,
    type_specification::{StructComponent, TypeSpecification},
};
use iec61850_model::MmsValue;

// ─────────────────────────────────────────────────────────────────────────────
// MmsTypeSpec to TypeSpecification, for GetVariableAccessAttributes
// ─────────────────────────────────────────────────────────────────────────────

/// Converts a mapped type specification into the wire-level
/// `TypeSpecification` carried by a GetVariableAccessAttributes response.
///
/// `StringSize::Generic` becomes `TypeSpecification::BitString { bits: 0 }`: a
/// generic bit string declares no size, so the response encodes zero rather
/// than a bound (IEC 61850-8-1 §9.7).
pub fn mms_type_spec_to_type_spec(ts: &MmsTypeSpec) -> TypeSpecification {
    match ts {
        MmsTypeSpec::Leaf(leaf) => leaf_to_type_spec(leaf),
        MmsTypeSpec::Structure(children) => {
            let components = children
                .iter()
                .map(named_variable_spec_to_struct_component)
                .collect();
            TypeSpecification::Structure { components }
        }
        MmsTypeSpec::Array { count, inner } => TypeSpecification::Array {
            element_count: *count,
            element_type: Box::new(mms_type_spec_to_type_spec(inner)),
        },
    }
}

fn named_variable_spec_to_struct_component(nv: &NamedVariableSpec) -> StructComponent {
    StructComponent {
        name: nv.name.clone(),
        type_spec: mms_type_spec_to_type_spec(&nv.type_spec),
    }
}

fn leaf_to_type_spec(leaf: &MmsLeafType) -> TypeSpecification {
    match leaf {
        MmsLeafType::Boolean => TypeSpecification::Boolean,
        MmsLeafType::Integer(bits) => TypeSpecification::Integer {
            width_bits: *bits as u8,
        },
        MmsLeafType::Unsigned(bits) => TypeSpecification::Unsigned {
            width_bits: *bits as u8,
        },
        MmsLeafType::Float {
            format_width,
            exponent_width,
        } => TypeSpecification::FloatingPoint {
            format_width: *format_width as u8,
            exponent_width: *exponent_width as u8,
        },
        MmsLeafType::BitString(size) => {
            let bits = string_size_to_signed(*size);
            TypeSpecification::BitString { bits }
        }
        MmsLeafType::OctetString(size) => {
            let max_octets = string_size_to_signed(*size);
            TypeSpecification::OctetString { max_octets }
        }
        MmsLeafType::VisibleString(size) => {
            let max_chars = string_size_to_signed(*size);
            TypeSpecification::VisibleString { max_chars }
        }
        MmsLeafType::UnicodeString(size) => {
            let max_chars = string_size_to_signed(*size);
            TypeSpecification::MmsString { max_chars }
        }
        MmsLeafType::UtcTime => TypeSpecification::UtcTime,
        MmsLeafType::BinaryTime { size } => {
            // A 6-octet BinaryTime uses the long form; 4 octets use the short form.
            TypeSpecification::BinaryTime {
                use_long_form: *size == 6,
            }
        }
    }
}

/// Encodes a string size with the sign convention of the MMS type
/// specification: `Max(n)` becomes `-n`, `Fixed(n)` becomes `n`, and `Generic`
/// becomes 0 rather than a negative bound (IEC 61850-8-1 §9.7).
fn string_size_to_signed(size: StringSize) -> i32 {
    match size {
        StringSize::Max(n) => -(n as i32),
        StringSize::Fixed(n) => n as i32,
        StringSize::Generic => 0,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MmsValue to MmsData, for the Read path
// ─────────────────────────────────────────────────────────────────────────────

/// Converts a model value into the wire value carried by an MMS PDU.
///
/// Arrays and structures are converted recursively.
pub fn mms_value_to_mms_data(v: &MmsValue) -> MmsData {
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
        MmsValue::OctetString(bytes) => MmsData::OctetString(bytes.clone()),
        MmsValue::VisibleString(s) => MmsData::VisibleString(s.clone()),
        MmsValue::MmsString(s) => MmsData::MmsString(s.clone()),
        MmsValue::UtcTime(arr) => MmsData::UtcTime(*arr),
        MmsValue::BinaryTime(bytes) => MmsData::BinaryTime(bytes.clone()),
        MmsValue::Array(items) => MmsData::Array(items.iter().map(mms_value_to_mms_data).collect()),
        MmsValue::Structure(items) => {
            MmsData::Structure(items.iter().map(mms_value_to_mms_data).collect())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MmsData to MmsValue, for the Write path
// ─────────────────────────────────────────────────────────────────────────────

/// Converts a decoded wire value into a model value.
///
/// The Write path calls this once the variant check has passed.
pub fn mms_data_to_mms_value(d: &MmsData) -> MmsValue {
    match d {
        MmsData::Boolean(b) => MmsValue::Boolean(*b),
        MmsData::Integer(i) => MmsValue::Integer(*i),
        MmsData::Unsigned(u) => MmsValue::Unsigned(*u),
        MmsData::Float32(f) => MmsValue::Float32(*f),
        MmsData::Float64(f) => MmsValue::Float64(*f),
        MmsData::BitString { padding, data } => MmsValue::BitString {
            padding: *padding,
            data: data.clone(),
        },
        MmsData::OctetString(bytes) => MmsValue::OctetString(bytes.clone()),
        MmsData::VisibleString(s) => MmsValue::VisibleString(s.clone()),
        MmsData::MmsString(s) => MmsValue::MmsString(s.clone()),
        MmsData::UtcTime(arr) => MmsValue::UtcTime(*arr),
        MmsData::BinaryTime(bytes) => MmsValue::BinaryTime(bytes.clone()),
        MmsData::Array(items) => MmsValue::Array(items.iter().map(mms_data_to_mms_value).collect()),
        MmsData::Structure(items) => {
            MmsValue::Structure(items.iter().map(mms_data_to_mms_value).collect())
        }
        // A BooleanArray on the wire maps onto a model bit string.
        MmsData::BooleanArray { padding, data } => MmsValue::BitString {
            padding: *padding,
            data: data.clone(),
        },
        MmsData::GeneralizedTime(s) => MmsValue::VisibleString(s.clone()),
    }
}

/// Reports whether a wire value and a model value share the same variant.
///
/// The Write path rejects a mismatch, as the Write service of IEC 61850-8-1
/// requires. This compares variants, not values, and an array or structure is
/// compared only at the top level.
pub fn same_data_variant(data: &MmsData, value: &MmsValue) -> bool {
    matches!(
        (data, value),
        (MmsData::Boolean(_), MmsValue::Boolean(_))
            | (MmsData::Integer(_), MmsValue::Integer(_))
            | (MmsData::Unsigned(_), MmsValue::Unsigned(_))
            | (MmsData::Float32(_), MmsValue::Float32(_))
            | (MmsData::Float64(_), MmsValue::Float64(_))
            | (MmsData::BitString { .. }, MmsValue::BitString { .. })
            | (MmsData::BooleanArray { .. }, MmsValue::BitString { .. })
            | (MmsData::OctetString(_), MmsValue::OctetString(_))
            | (MmsData::VisibleString(_), MmsValue::VisibleString(_))
            | (MmsData::MmsString(_), MmsValue::MmsString(_))
            | (MmsData::UtcTime(_), MmsValue::UtcTime(_))
            | (MmsData::BinaryTime(_), MmsValue::BinaryTime(_))
            | (MmsData::Array(_), MmsValue::Array(_))
            | (MmsData::Structure(_), MmsValue::Structure(_))
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapping::{MmsLeafType, MmsTypeSpec, NamedVariableSpec, StringSize};

    #[test]
    fn mms_leaf_boolean_converts_to_type_spec_boolean() {
        let ts = MmsTypeSpec::Leaf(MmsLeafType::Boolean);
        let result = mms_type_spec_to_type_spec(&ts);
        assert_eq!(result, TypeSpecification::Boolean);
    }

    #[test]
    fn mms_leaf_integer_converts_correctly() {
        let ts = MmsTypeSpec::Leaf(MmsLeafType::Integer(32));
        let result = mms_type_spec_to_type_spec(&ts);
        assert_eq!(result, TypeSpecification::Integer { width_bits: 32 });
    }

    #[test]
    fn mms_leaf_float32_converts_correctly() {
        let ts = MmsTypeSpec::Leaf(MmsLeafType::Float {
            format_width: 32,
            exponent_width: 8,
        });
        let result = mms_type_spec_to_type_spec(&ts);
        assert_eq!(
            result,
            TypeSpecification::FloatingPoint {
                format_width: 32,
                exponent_width: 8,
            }
        );
    }

    #[test]
    fn mms_leaf_generic_bitstring_converts_to_bits_zero() {
        // A generic bit string declares no size, so bits encodes as 0.
        let ts = MmsTypeSpec::Leaf(MmsLeafType::BitString(StringSize::Generic));
        let result = mms_type_spec_to_type_spec(&ts);
        assert_eq!(
            result,
            TypeSpecification::BitString { bits: 0 },
            "a generic bit string must encode bits = 0"
        );
    }

    #[test]
    fn mms_leaf_quality_converts_to_bits_neg13() {
        // Quality is a 13-bit maximum, so bits encodes as -13.
        let ts = MmsTypeSpec::Leaf(MmsLeafType::BitString(StringSize::Max(13)));
        let result = mms_type_spec_to_type_spec(&ts);
        assert_eq!(result, TypeSpecification::BitString { bits: -13 });
    }

    #[test]
    fn mms_leaf_visible_string_max_converts_to_neg() {
        // A 64-character maximum encodes as -64.
        let ts = MmsTypeSpec::Leaf(MmsLeafType::VisibleString(StringSize::Max(64)));
        let result = mms_type_spec_to_type_spec(&ts);
        assert_eq!(result, TypeSpecification::VisibleString { max_chars: -64 });
    }

    #[test]
    fn mms_leaf_octet_string_fixed_converts_to_pos() {
        // A fixed 8-octet size encodes as 8.
        let ts = MmsTypeSpec::Leaf(MmsLeafType::OctetString(StringSize::Fixed(8)));
        let result = mms_type_spec_to_type_spec(&ts);
        assert_eq!(result, TypeSpecification::OctetString { max_octets: 8 });
    }

    #[test]
    fn mms_type_spec_structure_converts_with_children() {
        let ts = MmsTypeSpec::Structure(vec![
            NamedVariableSpec {
                name: "stVal".into(),
                type_spec: MmsTypeSpec::Leaf(MmsLeafType::Boolean),
            },
            NamedVariableSpec {
                name: "q".into(),
                type_spec: MmsTypeSpec::Leaf(MmsLeafType::BitString(StringSize::Max(13))),
            },
        ]);
        let result = mms_type_spec_to_type_spec(&ts);
        match result {
            TypeSpecification::Structure { components } => {
                assert_eq!(components.len(), 2);
                assert_eq!(components[0].name, "stVal");
                assert_eq!(components[0].type_spec, TypeSpecification::Boolean);
                assert_eq!(components[1].name, "q");
                assert_eq!(
                    components[1].type_spec,
                    TypeSpecification::BitString { bits: -13 }
                );
            }
            other => panic!("expected a structure, got {:?}", other),
        }
    }

    #[test]
    fn mms_type_spec_array_converts() {
        let ts = MmsTypeSpec::Array {
            count: 3,
            inner: Box::new(MmsTypeSpec::Leaf(MmsLeafType::Integer(32))),
        };
        let result = mms_type_spec_to_type_spec(&ts);
        match result {
            TypeSpecification::Array {
                element_count,
                element_type,
            } => {
                assert_eq!(element_count, 3);
                assert_eq!(*element_type, TypeSpecification::Integer { width_bits: 32 });
            }
            other => panic!("expected an array, got {:?}", other),
        }
    }

    // MmsValue and MmsData conversions

    #[test]
    fn mms_value_boolean_roundtrip() {
        let v = MmsValue::Boolean(true);
        let d = mms_value_to_mms_data(&v);
        assert_eq!(d, MmsData::Boolean(true));
        let v2 = mms_data_to_mms_value(&d);
        assert!(matches!(v2, MmsValue::Boolean(true)));
    }

    #[test]
    fn mms_value_float32_roundtrip() {
        let v = MmsValue::Float32(1.23_f32);
        let d = mms_value_to_mms_data(&v);
        assert!(matches!(d, MmsData::Float32(_)));
        let v2 = mms_data_to_mms_value(&d);
        assert!(matches!(v2, MmsValue::Float32(_)));
    }

    #[test]
    fn mms_value_utctime_roundtrip() {
        let arr = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let v = MmsValue::UtcTime(arr);
        let d = mms_value_to_mms_data(&v);
        assert!(matches!(d, MmsData::UtcTime(_)));
        let v2 = mms_data_to_mms_value(&d);
        assert!(matches!(v2, MmsValue::UtcTime(_)));
    }

    #[test]
    fn mms_value_structure_roundtrip() {
        let v = MmsValue::Structure(vec![MmsValue::Boolean(true), MmsValue::Integer(42)]);
        let d = mms_value_to_mms_data(&v);
        match &d {
            MmsData::Structure(items) => {
                assert_eq!(items.len(), 2);
            }
            other => panic!("expected a structure, got {:?}", other),
        }
        let v2 = mms_data_to_mms_value(&d);
        assert!(matches!(v2, MmsValue::Structure(_)));
    }

    // same_data_variant checks

    #[test]
    fn same_data_variant_matching_types() {
        assert!(same_data_variant(
            &MmsData::Boolean(true),
            &MmsValue::Boolean(false)
        ));
        assert!(same_data_variant(
            &MmsData::Integer(0),
            &MmsValue::Integer(99)
        ));
        assert!(same_data_variant(
            &MmsData::Float32(0.0),
            &MmsValue::Float32(1.0)
        ));
    }

    #[test]
    fn same_data_variant_mismatching_types() {
        assert!(!same_data_variant(
            &MmsData::Boolean(true),
            &MmsValue::Integer(1)
        ));
        assert!(!same_data_variant(
            &MmsData::Integer(0),
            &MmsValue::Boolean(false)
        ));
        assert!(!same_data_variant(
            &MmsData::Float32(0.0),
            &MmsValue::Float64(0.0)
        ));
    }

    #[test]
    fn mms_leaf_utc_time_converts() {
        let ts = MmsTypeSpec::Leaf(MmsLeafType::UtcTime);
        let result = mms_type_spec_to_type_spec(&ts);
        assert_eq!(result, TypeSpecification::UtcTime);
    }

    #[test]
    fn mms_leaf_binary_time_6_is_long_form() {
        let ts = MmsTypeSpec::Leaf(MmsLeafType::BinaryTime { size: 6 });
        let result = mms_type_spec_to_type_spec(&ts);
        assert_eq!(
            result,
            TypeSpecification::BinaryTime {
                use_long_form: true
            }
        );
    }

    #[test]
    fn mms_leaf_binary_time_4_is_short_form() {
        let ts = MmsTypeSpec::Leaf(MmsLeafType::BinaryTime { size: 4 });
        let result = mms_type_spec_to_type_spec(&ts);
        assert_eq!(
            result,
            TypeSpecification::BinaryTime {
                use_long_form: false
            }
        );
    }
}
