//! What the SCL-to-model path accepts, rejects and carries over, each case
//! stated as the outcome IEC 61850-6 requires for an inline SCL file.

use iec61850_model::tree::IedModel;

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

/// One IED with LD0, whose LLN0 body and further logical nodes are given, and
/// the extra DataTypeTemplates entries they reference.
fn wrap(templates: &str, ln0_body: &str, extra_lns: &str) -> String {
    format!(
        r#"<SCL>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnClass="LLN0" lnType="LLN0_T">{ln0_body}</LN0>
          {extra_lns}
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="BOOLEAN"/>
    </DOType>
    {templates}
  </DataTypeTemplates>
</SCL>"#
    )
}

/// A DOType whose sub-object refers back to it is a type cycle, rejected in
/// stage 2 instead of recursing without bound in the model builder.
#[test]
fn dotype_sdo_self_cycle_is_rejected() {
    let t = r#"
    <LNodeType id="X_T" lnClass="GGIO"><DO name="Loop" type="A"/></LNodeType>
    <DOType id="A" cdc="WYE"><SDO name="phsA" type="A"/></DOType>"#;
    let raw = iec61850_scl::parse_scl(&wrap(t, "", "")).expect("stage 1");
    let err = raw
        .resolve()
        .expect_err("a self-referencing DOType must be rejected");
    assert!(err.to_string().contains("A -> A"), "{err}");
}

/// A cycle through two DOTypes is rejected the same way, and is reported even
/// when no logical node instantiates the types.
#[test]
fn dotype_sdo_indirect_cycle_is_rejected() {
    let t = r#"
    <DOType id="A" cdc="WYE"><SDO name="phsA" type="B"/></DOType>
    <DOType id="B" cdc="CMV"><DA name="q" fc="MX" bType="Quality"/><SDO name="back" type="A"/></DOType>"#;
    let raw = iec61850_scl::parse_scl(&wrap(t, "", "")).expect("stage 1");
    let err = raw
        .resolve()
        .expect_err("an indirect DOType cycle must be rejected");
    assert!(err.to_string().contains("A -> B -> A"), "{err}");
}

/// Control: a DOType reached through two sub-objects, a shared type rather
/// than a cycle, resolves and builds.
#[test]
fn dotype_shared_sdo_type_builds() {
    let t = r#"
    <LNodeType id="MMXU_T" lnClass="MMXU"><DO name="A" type="WYE_T"/></LNodeType>
    <DOType id="WYE_T" cdc="WYE">
      <SDO name="phsA" type="CMV_T"/>
      <SDO name="phsB" type="CMV_T"/>
    </DOType>
    <DOType id="CMV_T" cdc="CMV"><DA name="q" fc="MX" bType="Quality"/></DOType>"#;
    let m = build(&wrap(
        t,
        "",
        r#"<LN lnClass="MMXU" inst="1" lnType="MMXU_T"/>"#,
    ));
    let ln = m.ld_by_inst("LD0").unwrap().ln_by_name("MMXU1").unwrap();
    assert_eq!(ln.do_by_name("A").unwrap().children.len(), 2);
}
