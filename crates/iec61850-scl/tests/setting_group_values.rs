//! The setting group values of an SCL instance: every `<Val sGroup="n">` of a
//! `<DAI>` belongs to setting group `n` (IEC 61850-6 §9.5.4.4), and a `<DAI>`
//! reaches both the FC=SE and the FC=SG attribute of a setting.

use iec61850_model::tree::{DataAttribute, DoChild, IedModel};
use iec61850_model::{MmsValue, FC};

fn try_build(xml: &str) -> Result<IedModel, String> {
    let raw = iec61850_scl::parse_scl(xml).map_err(|e| format!("parse: {e}"))?;
    let resolved = raw.resolve().map_err(|e| format!("resolve: {e}"))?;
    resolved
        .build_model("IED1")
        .map_err(|e| format!("build: {e}"))
}

fn build(xml: &str) -> IedModel {
    try_build(xml).unwrap_or_else(|e| panic!("{e}"))
}

/// One IED whose LLN0 holds `setting_control` and whose PTOC1 carries
/// `doi`. `Spt` declares `setVal` under FC=SE only, so its FC=SG attribute is
/// derived; `Both` declares it under FC=SE and FC=SG.
fn scl(setting_control: &str, doi: &str) -> String {
    format!(
        r#"<SCL>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnClass="LLN0" lnType="LLN0_T">{setting_control}</LN0>
          <LN lnClass="PTOC" inst="1" lnType="PTOC_T">{doi}</LN>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <LNodeType id="PTOC_T" lnClass="PTOC">
      <DO name="Spt" type="ING_SE"/>
      <DO name="Both" type="ING_BOTH"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="BOOLEAN"/>
    </DOType>
    <DOType id="ING_SE" cdc="ING">
      <DA name="setVal" fc="SE" bType="INT32"/>
    </DOType>
    <DOType id="ING_BOTH" cdc="ING">
      <DA name="setVal" fc="SG" bType="INT32"/>
      <DA name="setVal" fc="SE" bType="INT32"/>
    </DOType>
  </DataTypeTemplates>
</SCL>"#
    )
}

const THREE_GROUPS: &str = r#"<SettingControl numOfSGs="3" actSG="1"/>"#;

fn setting<'a>(model: &'a IedModel, do_name: &str, fc: FC) -> &'a DataAttribute {
    let ln = model.lds[0].ln_by_name("PTOC1").expect("PTOC1");
    match ln
        .do_by_name(do_name)
        .unwrap()
        .child_by_name("setVal", Some(fc))
    {
        Some(DoChild::Da(d)) => d,
        other => panic!("{do_name}.setVal[{fc}]: {other:?}"),
    }
}

fn ints(values: &[(u8, MmsValue)]) -> Vec<(u8, i64)> {
    values
        .iter()
        .map(|(g, v)| match v {
            MmsValue::Integer(i) => (*g, *i),
            other => panic!("{other:?}"),
        })
        .collect()
}

/// Every group's value is kept, in group order, on both attributes of the
/// setting; the value without a group is the attribute's value.
#[test]
fn every_setting_group_value_is_kept() {
    let m = build(&scl(
        THREE_GROUPS,
        r#"<DOI name="Spt"><DAI name="setVal">
             <Val sGroup="3">30</Val><Val>5</Val><Val sGroup="1">10</Val><Val sGroup="2">20</Val>
           </DAI></DOI>"#,
    ));
    for fc in [FC::Se, FC::Sg] {
        let sv = setting(&m, "Spt", fc);
        assert_eq!(ints(&sv.sgroup_values), [(1, 10), (2, 20), (3, 30)], "{fc}");
        assert_eq!(sv.snapshot(), MmsValue::Integer(5), "{fc}");
        assert_eq!(sv.sgroup_value(2), Some(&MmsValue::Integer(20)), "{fc}");
    }
}

/// When every value names a group, the attribute's value starts at the first
/// one, as before.
#[test]
fn value_without_a_group_falls_back_to_the_first() {
    let m = build(&scl(
        THREE_GROUPS,
        r#"<DOI name="Spt"><DAI name="setVal"><Val sGroup="2">20</Val><Val sGroup="1">10</Val></DAI></DOI>"#,
    ));
    let sv = setting(&m, "Spt", FC::Sg);
    assert_eq!(sv.snapshot(), MmsValue::Integer(20));
    assert_eq!(ints(&sv.sgroup_values), [(1, 10), (2, 20)]);
}

/// A group of 0, one above `numOfSGs`, and two values for one group are
/// rejected.
#[test]
fn impossible_setting_groups_are_rejected() {
    for vals in [
        r#"<Val sGroup="0">1</Val>"#,
        r#"<Val sGroup="4">1</Val>"#,
        r#"<Val sGroup="1">1</Val><Val sGroup="1">2</Val>"#,
    ] {
        let doi = format!(r#"<DOI name="Spt"><DAI name="setVal">{vals}</DAI></DOI>"#);
        assert!(
            try_build(&scl(THREE_GROUPS, &doi)).is_err(),
            "{vals} accepted"
        );
    }
    // Without a SettingControl only the u8 range applies.
    let m = build(&scl(
        "",
        r#"<DOI name="Spt"><DAI name="setVal"><Val sGroup="7">1</Val></DAI></DOI>"#,
    ));
    assert_eq!(ints(&setting(&m, "Spt", FC::Sg).sgroup_values), [(7, 1)]);
    let doi = r#"<DOI name="Spt"><DAI name="setVal"><Val sGroup="256">1</Val></DAI></DOI>"#;
    assert!(try_build(&scl("", doi)).is_err());
}

/// A DOType declaring a setting under both FC=SE and FC=SG has both
/// attributes take the `<DAI>` value and setting group values.
#[test]
fn dai_reaches_both_declared_setting_attributes() {
    let m = build(&scl(
        THREE_GROUPS,
        r#"<DOI name="Both"><DAI name="setVal"><Val>7</Val><Val sGroup="2">70</Val></DAI></DOI>"#,
    ));
    for fc in [FC::Se, FC::Sg] {
        let sv = setting(&m, "Both", fc);
        assert_eq!(sv.snapshot(), MmsValue::Integer(7), "{fc}");
        assert_eq!(ints(&sv.sgroup_values), [(2, 70)], "{fc}");
    }
}

/// Control: a `<DAI>` with a single plain value sets no group values.
#[test]
fn plain_value_sets_no_group_values() {
    let m = build(&scl(
        THREE_GROUPS,
        r#"<DOI name="Spt"><DAI name="setVal"><Val>9</Val></DAI></DOI>"#,
    ));
    let sv = setting(&m, "Spt", FC::Se);
    assert_eq!(sv.snapshot(), MmsValue::Integer(9));
    assert!(sv.sgroup_values.is_empty());
}

/// `numOfSGs` is an INT8U (IEC 61850-7-2), so the parser already rejects one
/// above 255 and accepts 255.
#[test]
fn num_of_sgs_above_255_is_rejected_by_the_parser() {
    let sc = |n: u32| format!(r#"<SettingControl numOfSGs="{n}" actSG="1"/>"#);
    assert!(iec61850_scl::parse_scl(&scl(&sc(256), "")).is_err());
    assert!(iec61850_scl::parse_scl(&scl(&sc(255), "")).is_ok());
}
