//! What the SCL-to-model path accepts, rejects and carries over, each case
//! stated as the outcome IEC 61850-6 requires for an inline SCL file.

use iec61850_model::tree::{DataAttribute, DoChild, IedModel};
use iec61850_model::MmsValue;

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

fn da<'a>(model: &'a IedModel, ln: &str, do_name: &str, da_name: &str) -> &'a DataAttribute {
    let ln = model.ld_by_inst("LD0").unwrap().ln_by_name(ln).unwrap();
    match ln.do_by_name(do_name).unwrap().child_by_name(da_name) {
        Some(DoChild::Da(d)) => d,
        other => panic!("{do_name}.{da_name}: {other:?}"),
    }
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

const CSWI: &str = r#"
    <LNodeType id="CSWI_T" lnClass="CSWI">
      <DO name="Pos" type="DPC_T"/>
    </LNodeType>
    <DOType id="DPC_T" cdc="DPC">
      <DA name="stVal" fc="ST" bType="Dbpos" dchg="true"/>
      <DA name="ctlModel" fc="CF" bType="Enum" type="CtlModels"><Val>sbo-with-normal-security</Val></DA>
      <DA name="sboTimeout" fc="CF" bType="INT32U"><Val>30000</Val></DA>
      <DA name="pulseConfig" fc="CF" bType="Struct" type="PulseConfig"/>
    </DOType>
    <DAType id="PulseConfig">
      <BDA name="onDur" bType="INT32U"><Val>500</Val></BDA>
      <BDA name="offDur" bType="INT32U"/>
    </DAType>
    <EnumType id="CtlModels">
      <EnumVal ord="0">status-only</EnumVal>
      <EnumVal ord="1">direct-with-normal-security</EnumVal>
      <EnumVal ord="2">sbo-with-normal-security</EnumVal>
      <EnumVal ord="3">direct-with-enhanced-security</EnumVal>
      <EnumVal ord="4">sbo-with-enhanced-security</EnumVal>
    </EnumType>"#;

/// A `<Val>` on a DataTypeTemplates `<DA>` is the initial value of every
/// instance without a `<DAI>` override.
#[test]
fn template_da_val_is_the_initial_value() {
    let m = build(&wrap(
        CSWI,
        "",
        r#"<LN lnClass="CSWI" inst="1" lnType="CSWI_T"/>"#,
    ));
    assert_eq!(
        da(&m, "CSWI1", "Pos", "ctlModel").snapshot(),
        MmsValue::Integer(2)
    );
    assert_eq!(
        da(&m, "CSWI1", "Pos", "sboTimeout").snapshot(),
        MmsValue::Unsigned(30000)
    );
}

/// The same rule for a `<BDA>` inside a DAType; a BDA without a `<Val>` keeps
/// the zero value of its type.
#[test]
fn template_bda_val_is_the_initial_value() {
    let m = build(&wrap(
        CSWI,
        "",
        r#"<LN lnClass="CSWI" inst="1" lnType="CSWI_T"/>"#,
    ));
    let pulse = da(&m, "CSWI1", "Pos", "pulseConfig");
    assert_eq!(
        pulse.child_by_name("onDur").unwrap().snapshot(),
        MmsValue::Unsigned(500)
    );
    assert_eq!(
        pulse.child_by_name("offDur").unwrap().snapshot(),
        MmsValue::Unsigned(0)
    );
}

/// A `<DAI>` on the instance overrides the template value.
#[test]
fn dai_overrides_the_template_val() {
    let ln = r#"<LN lnClass="CSWI" inst="1" lnType="CSWI_T">
            <DOI name="Pos">
              <DAI name="ctlModel"><Val>direct-with-normal-security</Val></DAI>
              <SDI name="pulseConfig"><DAI name="onDur"><Val>250</Val></DAI></SDI>
            </DOI></LN>"#;
    let m = build(&wrap(CSWI, "", ln));
    assert_eq!(
        da(&m, "CSWI1", "Pos", "ctlModel").snapshot(),
        MmsValue::Integer(1)
    );
    let pulse = da(&m, "CSWI1", "Pos", "pulseConfig");
    assert_eq!(
        pulse.child_by_name("onDur").unwrap().snapshot(),
        MmsValue::Unsigned(250)
    );
}

/// A template `<Val>` that does not parse as its bType fails the build, as a
/// `<DAI>` value does.
#[test]
fn template_val_of_the_wrong_type_fails_the_build() {
    let t = r#"
    <LNodeType id="GGIO_T" lnClass="GGIO"><DO name="X" type="X_T"/></LNodeType>
    <DOType id="X_T" cdc="SPS"><DA name="v" fc="CF" bType="INT32U"><Val>many</Val></DA></DOType>"#;
    let err = try_build(&wrap(
        t,
        "",
        r#"<LN lnClass="GGIO" inst="1" lnType="GGIO_T"/>"#,
    ))
    .expect_err("an INT32U default of `many` must be rejected");
    assert!(err.contains("many"), "{err}");
}

const GGIO_SPS: &str = r#"
    <LNodeType id="GGIO_T" lnClass="GGIO">
      <DO name="Ind1" type="SPS_T"/>
    </LNodeType>
    <DOType id="SPS_T" cdc="SPS">
      <DA name="stVal" fc="ST" bType="BOOLEAN" dchg="true"/>
    </DOType>"#;

const GGIO1: &str = r#"<LN lnClass="GGIO" inst="1" lnType="GGIO_T"/>"#;

/// The `appID` of a `<GSEControl>` is its GoID; the control block keeps its
/// own name.
#[test]
fn gse_control_app_id_is_the_go_id() {
    let ln0 = r#"
            <DataSet name="DSGoose">
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
            </DataSet>
            <GSEControl name="gcb1" appID="IED1_GOOSE_PROT" datSet="DSGoose" confRev="1" type="GOOSE"/>
            <GSEControl name="gcbEvents" appID="events" datSet="DSGoose" confRev="1"/>"#;
    let m = build(&wrap(GGIO_SPS, ln0, GGIO1));
    let ln0 = m.ld_by_inst("LD0").unwrap().ln_by_name("LLN0").unwrap();
    let ids: Vec<(&str, &str)> = ln0
        .gocbs
        .iter()
        .map(|g| (g.name.as_str(), g.go_id.as_str()))
        .collect();
    assert_eq!(
        ids,
        vec![("gcb1", "IED1_GOOSE_PROT"), ("gcbEvents", "events")]
    );
}
