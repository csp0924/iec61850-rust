//! Checks the value of a control service write against the type the model
//! declares for it.
//!
//! A write of `Oper`, `SBOw`, or `Cancel` must carry a value of the type of that
//! attribute, per the type consistency rule of the MMS Write service. The
//! structure of each attribute follows the common data class of the object in
//! IEC 61850-7-3.

use super::model::bit_string_len;
use iec61850_model::{DataAttribute, DataAttributeType, DoChild, IedModel, MmsValue, FC};

/// Returns the control attribute `attr` of `<domain>/<ln>$CO$<do_name>` as the
/// model declares it, or `None` when the model does not declare it.
pub(crate) fn declared_co_attribute<'a>(
    model: &'a IedModel,
    domain: &str,
    ln_name: &str,
    do_name: &str,
    attr: &str,
) -> Option<&'a DataAttribute> {
    let data_object = model
        .ld_by_domain(domain)?
        .ln_by_name(ln_name)?
        .do_by_name(do_name)?;
    data_object.children.iter().find_map(|child| match child {
        DoChild::Da(da) if da.name == attr && da.fc == FC::Co => Some(da),
        _ => None,
    })
}

/// Returns whether `value` has the type of `da`, member by member.
///
/// A structure must have exactly one member per child attribute, an integer must
/// fit the range of its declared width, a string or octet string its declared
/// maximum length, and a bit string of fixed size exactly that many bits.
pub(crate) fn conforms(da: &DataAttribute, value: &MmsValue) -> bool {
    use DataAttributeType as T;
    match (da.ty, value) {
        (T::Constructed, MmsValue::Structure(members)) => {
            members.len() == da.children.len()
                && da
                    .children
                    .iter()
                    .zip(members)
                    .all(|(child, member)| conforms(child, member))
        }
        (T::Boolean, MmsValue::Boolean(_)) => true,
        (T::Int8, MmsValue::Integer(n)) => i8::try_from(*n).is_ok(),
        (T::Int16, MmsValue::Integer(n)) => i16::try_from(*n).is_ok(),
        (T::Int32 | T::Enumerated, MmsValue::Integer(n)) => i32::try_from(*n).is_ok(),
        (T::Int64 | T::Int128, MmsValue::Integer(_)) => true,
        (T::Int8U, MmsValue::Unsigned(n)) => u8::try_from(*n).is_ok(),
        (T::Int16U, MmsValue::Unsigned(n)) => u16::try_from(*n).is_ok(),
        (T::Int24U, MmsValue::Unsigned(n)) => *n <= 0x00ff_ffff,
        (T::Int32U, MmsValue::Unsigned(n)) => u32::try_from(*n).is_ok(),
        (T::Float32, MmsValue::Float32(_)) => true,
        (T::Float64, MmsValue::Float64(_)) => true,
        (T::OctetString(max), MmsValue::OctetString(b)) => b.len() <= max as usize,
        (T::VisibleString(max), MmsValue::VisibleString(s)) => s.len() <= max as usize,
        (T::UnicodeString255, MmsValue::MmsString(s)) => s.len() <= 255,
        (T::Timestamp, MmsValue::UtcTime(_)) => true,
        (T::EntryTime, MmsValue::BinaryTime(b)) => b.len() == 4 || b.len() == 6,
        (ty, MmsValue::BitString { padding, data }) => match bit_string_len(*padding, data) {
            Some(bits) => match ty {
                T::Check | T::CodedEnum => bits == 2,
                T::Quality => bits == 13,
                T::OptFlds => bits == 10,
                T::TrgOpsBits => bits == 6,
                T::GenericBitString(max) => bits <= max as usize,
                _ => false,
            },
            None => false,
        },
        (ty, v) => {
            !matches!(v, MmsValue::Structure(_) | MmsValue::Array(_))
                && core::mem::discriminant(&MmsValue::default_for(ty)) == core::mem::discriminant(v)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iec61850_model::cdc::{self, CdcOptions, ControlOptions};
    use iec61850_model::ControlModel;

    fn spc_oper(model: ControlModel) -> DataAttribute {
        let data_object = cdc::spc(
            "SPCSO1",
            CdcOptions::NONE,
            ControlOptions::NONE
                .with_model(model)
                .union(ControlOptions::HAS_CANCEL),
        );
        data_object
            .children
            .into_iter()
            .find_map(|c| match c {
                DoChild::Da(da) if da.name == "Oper" => Some(da),
                _ => None,
            })
            .expect("Oper")
    }

    fn oper_value(ctl_val: MmsValue, ctl_num: MmsValue, check_bits: u8) -> MmsValue {
        MmsValue::Structure(vec![
            ctl_val,
            MmsValue::Structure(vec![
                MmsValue::Integer(3),
                MmsValue::OctetString(b"op".to_vec()),
            ]),
            ctl_num,
            MmsValue::UtcTime([0; 8]),
            MmsValue::Boolean(false),
            MmsValue::BitString {
                padding: 8 - check_bits,
                data: vec![0],
            },
        ])
    }

    #[test]
    fn well_typed_oper_conforms() {
        let da = spc_oper(ControlModel::DirectNormal);
        let v = oper_value(MmsValue::Boolean(true), MmsValue::Unsigned(7), 2);
        assert!(conforms(&da, &v));
    }

    #[test]
    fn wrong_ctl_val_type_does_not_conform() {
        let da = spc_oper(ControlModel::DirectNormal);
        let v = oper_value(MmsValue::Integer(5), MmsValue::Unsigned(7), 2);
        assert!(!conforms(&da, &v));
    }

    #[test]
    fn ctl_num_outside_int8u_does_not_conform() {
        let da = spc_oper(ControlModel::DirectNormal);
        assert!(!conforms(
            &da,
            &oper_value(MmsValue::Boolean(true), MmsValue::Unsigned(300), 2)
        ));
        assert!(!conforms(
            &da,
            &oper_value(MmsValue::Boolean(true), MmsValue::Integer(7), 2)
        ));
    }

    #[test]
    fn check_of_other_width_does_not_conform() {
        let da = spc_oper(ControlModel::DirectNormal);
        let v = oper_value(MmsValue::Boolean(true), MmsValue::Unsigned(7), 3);
        assert!(!conforms(&da, &v));
    }

    #[test]
    fn missing_member_does_not_conform() {
        let da = spc_oper(ControlModel::DirectNormal);
        let MmsValue::Structure(mut members) =
            oper_value(MmsValue::Boolean(true), MmsValue::Unsigned(7), 2)
        else {
            unreachable!()
        };
        members.pop();
        assert!(!conforms(&da, &MmsValue::Structure(members)));
    }
}
