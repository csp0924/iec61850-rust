//! The basic types of IEC 61850-6 §9.5.4.2 `tPredefinedBasicTypeEnum` that a
//! `<DA>` may declare, and the model type and value each one becomes.

use iec61850_model::tree::{DoChild, IedModel};
use iec61850_model::types::DataAttributeType;
use iec61850_model::MmsValue;

fn try_build(xml: &str) -> Result<IedModel, String> {
    let raw = iec61850_scl::parse_scl(xml).map_err(|e| format!("parse: {e}"))?;
    let resolved = raw.resolve().map_err(|e| format!("resolve: {e}"))?;
    resolved
        .build_model("IED1")
        .map_err(|e| format!("build: {e}"))
}

/// One IED whose LLN0 data object `X` has a single attribute `v` of bType
/// `b_type`, carrying the template `<Val>` `val` when given.
fn one_attribute(b_type: &str, val: Option<&str>) -> String {
    let val = val.map(|v| format!("<Val>{v}</Val>")).unwrap_or_default();
    format!(
        r#"<SCL>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnClass="LLN0" lnType="LLN0_T"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="X" type="X_T"/>
    </LNodeType>
    <DOType id="X_T" cdc="SPS">
      <DA name="v" fc="ST" bType="{b_type}">{val}</DA>
    </DOType>
  </DataTypeTemplates>
</SCL>"#
    )
}

fn attribute(model: &IedModel) -> (DataAttributeType, MmsValue) {
    let ln = &model.lds[0].lns[0];
    match ln.do_by_name("X").unwrap().child_by_name("v", None) {
        Some(DoChild::Da(d)) => (d.ty, d.snapshot()),
        other => panic!("X.v: {other:?}"),
    }
}

fn build_attribute(b_type: &str, val: Option<&str>) -> (DataAttributeType, MmsValue) {
    attribute(&try_build(&one_attribute(b_type, val)).unwrap_or_else(|e| panic!("{b_type}: {e}")))
}

/// INT24, Octet6, Octet16, SvOptFlds and LogOptFlds are basic types of
/// IEC 61850-6 §9.5.4.2 and load with their model type and zero value.
#[test]
fn schema_basic_types_are_accepted() {
    for (b_type, ty, zero) in [
        ("INT24", DataAttributeType::Int24, MmsValue::Integer(0)),
        (
            "Octet6",
            DataAttributeType::OctetString(6),
            MmsValue::OctetString(vec![]),
        ),
        (
            "Octet16",
            DataAttributeType::OctetString(16),
            MmsValue::OctetString(vec![]),
        ),
        (
            "SvOptFlds",
            DataAttributeType::SvOptFlds,
            MmsValue::BitString {
                padding: 3,
                data: vec![0],
            },
        ),
        (
            "LogOptFlds",
            DataAttributeType::LogOptFlds,
            MmsValue::BitString {
                padding: 7,
                data: vec![0],
            },
        ),
    ] {
        assert_eq!(build_attribute(b_type, None), (ty, zero), "{b_type}");
    }
}

/// An INT24 `<Val>` is an integer within -2^23..=2^23-1.
#[test]
fn int24_val_is_range_checked() {
    assert_eq!(
        build_attribute("INT24", Some("-8388608")).1,
        MmsValue::Integer(-8_388_608)
    );
    assert_eq!(
        build_attribute("INT24", Some("8388607")).1,
        MmsValue::Integer(8_388_607)
    );
    for v in ["8388608", "-8388609"] {
        assert!(
            try_build(&one_attribute("INT24", Some(v))).is_err(),
            "{v} accepted"
        );
    }
}

/// An Octet6 or Octet16 `<Val>` is base64Binary holding at most 6 or 16
/// octets.
#[test]
fn octet_vals_are_base64_within_their_length() {
    assert_eq!(
        build_attribute("Octet6", Some("AQIDBAUG")).1,
        MmsValue::OctetString(vec![1, 2, 3, 4, 5, 6])
    );
    assert!(try_build(&one_attribute("Octet6", Some("AQIDBAUGBw=="))).is_err());
    assert_eq!(
        build_attribute("Octet16", Some("AAECAwQFBgcICQoLDA0ODw==")).1,
        MmsValue::OctetString((0..16).collect())
    );
    assert!(try_build(&one_attribute("Octet16", Some("AAECAwQFBgcICQoLDA0ODxA="))).is_err());
}

/// IEC 61850-6 gives SvOptFlds and LogOptFlds no value representation, so a
/// `<Val>` on one leaves the zero value.
#[test]
fn option_field_vals_keep_the_default() {
    assert_eq!(
        build_attribute("SvOptFlds", Some("10100")).1,
        MmsValue::BitString {
            padding: 3,
            data: vec![0],
        }
    );
}

/// Control: a bType outside the schema is still rejected.
#[test]
fn unknown_basic_type_is_rejected() {
    assert!(try_build(&one_attribute("INT40", None)).is_err());
}
