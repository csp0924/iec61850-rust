//! Conversion between the wire value type `MmsData` and the model value type
//! `iec61850-model::MmsValue`.
//!
//! `MmsClient::read` yields `MmsData`, while the RCB and report decoding paths
//! work on `MmsValue`. Both directions are pure and recurse through arrays and
//! structures.
//!
//! Two variants do not map one to one:
//!
//! - `MmsData::BooleanArray { padding, data }` becomes
//!   `MmsValue::BitString { padding, data }`, because a boolean array is
//!   carried as a BIT STRING on the wire and the model has only that variant.
//! - `MmsData::GeneralizedTime(s)` becomes `MmsValue::VisibleString(s)`, as the
//!   model has no GeneralizedTime variant.

use iec61850_mms::mms::pdu::common::MmsData;
use iec61850_model::value::MmsValue;

/// Converts a model value into its wire representation.
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

/// Converts a wire value into its model representation.
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
        MmsData::BooleanArray { padding, data } => MmsValue::BitString {
            padding: *padding,
            data: data.clone(),
        },
        MmsData::OctetString(bytes) => MmsValue::OctetString(bytes.clone()),
        MmsData::VisibleString(s) => MmsValue::VisibleString(s.clone()),
        MmsData::MmsString(s) => MmsValue::MmsString(s.clone()),
        MmsData::UtcTime(arr) => MmsValue::UtcTime(*arr),
        MmsData::BinaryTime(bytes) => MmsValue::BinaryTime(bytes.clone()),
        MmsData::GeneralizedTime(s) => MmsValue::VisibleString(s.clone()),
        MmsData::Array(items) => MmsValue::Array(items.iter().map(mms_data_to_mms_value).collect()),
        MmsData::Structure(items) => {
            MmsValue::Structure(items.iter().map(mms_data_to_mms_value).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boolean_roundtrip() {
        let v = MmsValue::Boolean(true);
        let d = mms_value_to_mms_data(&v);
        assert!(matches!(d, MmsData::Boolean(true)));
        let v2 = mms_data_to_mms_value(&d);
        assert!(matches!(v2, MmsValue::Boolean(true)));
    }

    #[test]
    fn structure_roundtrip() {
        let v = MmsValue::Structure(vec![
            MmsValue::VisibleString("rpt".to_string()),
            MmsValue::Boolean(false),
            MmsValue::Unsigned(42),
        ]);
        let d = mms_value_to_mms_data(&v);
        let v2 = mms_data_to_mms_value(&d);
        match (&v, &v2) {
            (MmsValue::Structure(a), MmsValue::Structure(b)) => assert_eq!(a, b),
            _ => panic!("structure round trip did not yield a structure"),
        }
    }

    #[test]
    fn boolean_array_maps_to_bit_string() {
        let d = MmsData::BooleanArray {
            padding: 5,
            data: vec![0xa0],
        };
        let v = mms_data_to_mms_value(&d);
        assert!(matches!(
            v,
            MmsValue::BitString { padding: 5, ref data } if data == &vec![0xa0u8]
        ));
    }
}
