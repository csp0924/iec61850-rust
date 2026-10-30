//! A BOOLEAN `<Val>` is an xs:boolean (IEC 61850-6), so `1` and `0` stand
//! next to `true` and `false`, on a DataTypeTemplates declaration and on a
//! `<DAI>` alike.

use iec61850_model::tree::{DoChild, IedModel};
use iec61850_model::MmsValue;

fn scl(da_vals: &str, dai_vals: &str) -> String {
    format!(
        r#"<SCL>
  <IED name="IED1"><AccessPoint name="AP1"><Server><LDevice inst="LD0">
    <LN0 inst="" lnClass="LLN0" lnType="LLN0_T"><DOI name="B">{dai_vals}</DOI></LN0>
  </LDevice></Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="B" type="B_T"/></LNodeType>
    <DOType id="B_T" cdc="SPC">{da_vals}</DOType>
  </DataTypeTemplates>
</SCL>"#
    )
}

fn try_build(xml: &str) -> Result<IedModel, String> {
    iec61850_scl::parse_scl(xml)
        .and_then(|r| r.resolve())
        .and_then(|r| r.build_model("IED1"))
        .map_err(|e| e.to_string())
}

fn value(m: &IedModel, name: &str) -> MmsValue {
    let ln = m.ld_by_inst("LD0").unwrap().ln_by_name("LLN0").unwrap();
    match ln.do_by_name("B").unwrap().child_by_name(name) {
        Some(DoChild::Da(d)) => d.snapshot(),
        other => panic!("{name}: {other:?}"),
    }
}

#[test]
fn boolean_val_accepts_one_and_zero() {
    let m = try_build(&scl(
        r#"<DA name="tmpl" fc="CF" bType="BOOLEAN"><Val>1</Val></DA>
           <DA name="inst" fc="CF" bType="BOOLEAN"><Val>1</Val></DA>
           <DA name="upper" fc="CF" bType="BOOLEAN"/>"#,
        r#"<DAI name="inst"><Val>0</Val></DAI><DAI name="upper"><Val>TRUE</Val></DAI>"#,
    ))
    .unwrap();
    assert_eq!(value(&m, "tmpl"), MmsValue::Boolean(true));
    assert_eq!(value(&m, "inst"), MmsValue::Boolean(false));
    assert_eq!(value(&m, "upper"), MmsValue::Boolean(true));
}

/// Control: a text that is not an xs:boolean still fails the build.
#[test]
fn boolean_val_rejects_other_text() {
    let r = try_build(&scl(
        r#"<DA name="v" fc="CF" bType="BOOLEAN"/>"#,
        r#"<DAI name="v"><Val>yes</Val></DAI>"#,
    ));
    assert!(r.is_err());
}
