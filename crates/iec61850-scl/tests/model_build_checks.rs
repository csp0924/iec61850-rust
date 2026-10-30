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

/// One GGIO whose `Lim` data object has one attribute of each integer bType,
/// with the given DOI body.
fn integer_scl(doi: &str) -> String {
    let t = r#"
    <LNodeType id="GGIO_T" lnClass="GGIO"><DO name="Lim" type="INT_T"/></LNodeType>
    <DOType id="INT_T" cdc="ING">
      <DA name="i8" fc="SP" bType="INT8"/>
      <DA name="i16" fc="SP" bType="INT16"/>
      <DA name="i32" fc="SP" bType="INT32"/>
      <DA name="u8" fc="CF" bType="INT8U"/>
      <DA name="u16" fc="CF" bType="INT16U"/>
      <DA name="u24" fc="CF" bType="INT24U"/>
      <DA name="u32" fc="CF" bType="INT32U"/>
    </DOType>"#;
    let ln =
        format!(r#"<LN lnClass="GGIO" inst="1" lnType="GGIO_T"><DOI name="Lim">{doi}</DOI></LN>"#);
    wrap(t, "", &ln)
}

/// A `<DAI>` value outside the range of its integer bType is rejected rather
/// than stored, so an INT8 never holds 300.
#[test]
fn dai_integer_out_of_range_is_rejected() {
    for (name, value) in [
        ("i8", "300"),
        ("i8", "-129"),
        ("i16", "32768"),
        ("i32", "2147483648"),
        ("u8", "256"),
        ("u16", "65536"),
        ("u24", "16777216"),
        ("u32", "4294967296"),
    ] {
        let doi = format!(r#"<DAI name="{name}"><Val>{value}</Val></DAI>"#);
        let r = try_build(&integer_scl(&doi));
        assert!(r.is_err(), "{name} = {value} must be rejected");
    }
}

/// Control: the bounds of each integer bType are accepted.
#[test]
fn dai_integer_at_the_bounds_is_accepted() {
    let doi = r#"
        <DAI name="i8"><Val>-128</Val></DAI>
        <DAI name="i16"><Val>32767</Val></DAI>
        <DAI name="i32"><Val>-2147483648</Val></DAI>
        <DAI name="u8"><Val>255</Val></DAI>
        <DAI name="u16"><Val>65535</Val></DAI>
        <DAI name="u24"><Val>16777215</Val></DAI>
        <DAI name="u32"><Val>4294967295</Val></DAI>"#;
    let m = build(&integer_scl(doi));
    let v = |n: &str| da(&m, "GGIO1", "Lim", n).snapshot();
    assert_eq!(v("i8"), MmsValue::Integer(-128));
    assert_eq!(v("i16"), MmsValue::Integer(32767));
    assert_eq!(v("i32"), MmsValue::Integer(-2147483648));
    assert_eq!(v("u8"), MmsValue::Unsigned(255));
    assert_eq!(v("u16"), MmsValue::Unsigned(65535));
    assert_eq!(v("u24"), MmsValue::Unsigned(16777215));
    assert_eq!(v("u32"), MmsValue::Unsigned(4294967295));
}

/// The range check applies to a DataTypeTemplates `<Val>` as well.
#[test]
fn template_integer_out_of_range_is_rejected() {
    let t = r#"
    <LNodeType id="GGIO_T" lnClass="GGIO"><DO name="X" type="X_T"/></LNodeType>
    <DOType id="X_T" cdc="ING"><DA name="v" fc="SP" bType="INT8"><Val>128</Val></DA></DOType>"#;
    assert!(try_build(&wrap(
        t,
        "",
        r#"<LN lnClass="GGIO" inst="1" lnType="GGIO_T"/>"#
    ))
    .is_err());
}

fn da_with_fc(fc: &str) -> String {
    let t = format!(
        r#"
    <LNodeType id="GGIO_T" lnClass="GGIO"><DO name="X" type="X_T"/></LNodeType>
    <DOType id="X_T" cdc="SPS"><DA name="v" fc="{fc}" bType="BOOLEAN"/></DOType>"#
    );
    wrap(&t, "", GGIO1)
}

/// A `<DA>` whose `fc` is the ALL or NONE selector or a control block
/// constraint is rejected, since no MMS view of the logical node lists it.
#[test]
fn da_fc_outside_the_data_constraints_is_rejected() {
    for fc in ["ALL", "NONE", "BR", "RP", "LG", "GO", "MS", "US"] {
        let r = iec61850_scl::parse_scl(&da_with_fc(fc));
        assert!(r.is_err(), "fc={fc} accepted on a DA");
    }
}

/// Control: every data functional constraint is accepted on a `<DA>`.
#[test]
fn da_fc_data_constraints_are_accepted() {
    for fc in [
        "ST", "MX", "CO", "SP", "SG", "SE", "SV", "CF", "DC", "EX", "SR", "BL", "OR",
    ] {
        build(&da_with_fc(fc));
    }
}

/// The same restriction holds for an `<FCDA>`.
#[test]
fn fcda_fc_outside_the_data_constraints_is_rejected() {
    for fc in ["ALL", "BR", "GO"] {
        let ln0 = format!(
            r#"<DataSet name="DS1"><FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind1" fc="{fc}"/></DataSet>"#
        );
        let r = iec61850_scl::parse_scl(&wrap(GGIO_SPS, &ln0, GGIO1));
        assert!(r.is_err(), "fc={fc} accepted on an FCDA");
    }
}

/// `numOfSGs` and `actSG` count setting groups from 1, and `actSG` cannot
/// exceed `numOfSGs`.
#[test]
fn setting_control_out_of_range_is_rejected() {
    for attrs in [
        r#"numOfSGs="0""#,
        r#"numOfSGs="0" actSG="0""#,
        r#"numOfSGs="2" actSG="0""#,
        r#"numOfSGs="2" actSG="3""#,
    ] {
        let ln0 = format!("<SettingControl {attrs}/>");
        let r = iec61850_scl::parse_scl(&wrap("", &ln0, ""));
        assert!(r.is_err(), "SettingControl {attrs} accepted");
    }
}

/// Control: an active group equal to the group count, and the default
/// active group of 1, are accepted.
#[test]
fn setting_control_in_range_is_accepted() {
    for (attrs, act) in [(r#"numOfSGs="3" actSG="3""#, 3), (r#"numOfSGs="1""#, 1)] {
        let ln0 = format!("<SettingControl {attrs}/>");
        let m = build(&wrap("", &ln0, ""));
        let ln0 = m.ld_by_inst("LD0").unwrap().ln_by_name("LLN0").unwrap();
        assert_eq!(ln0.sgcb.as_ref().unwrap().act_sg, act);
    }
}

const MMXU_MV: &str = r#"
    <LNodeType id="MMXU_T" lnClass="MMXU">
      <DO name="TotW" type="MV_T"/>
      <DO name="Har" type="HAR_T"/>
    </LNodeType>
    <DOType id="MV_T" cdc="MV">
      <DA name="mag" fc="MX" bType="Struct" type="AV"/>
      <DA name="q" fc="MX" bType="Quality"/>
    </DOType>
    <DOType id="HAR_T" cdc="HWYE">
      <SDO name="phsAHar" type="CMV_T"/>
    </DOType>
    <DOType id="CMV_T" cdc="CMV">
      <DA name="cVal" fc="MX" bType="Struct" type="VEC"/>
    </DOType>
    <DAType id="AV"><BDA name="f" bType="FLOAT32"/></DAType>
    <DAType id="VEC"><BDA name="mag" bType="Struct" type="AV"/></DAType>"#;

const MMXU1: &str = r#"<LN lnClass="MMXU" inst="1" lnType="MMXU_T"/>"#;

fn first_entry(m: &IedModel) -> iec61850_model::tree::DataSetEntry {
    let ln0 = m.ld_by_inst("LD0").unwrap().ln_by_name("LLN0").unwrap();
    ln0.datasets[0].entries[0].clone()
}

fn fcda(attrs: &str) -> String {
    format!(
        r#"<DataSet name="DS1"><FCDA ldInst="LD0" lnClass="MMXU" lnInst="1" fc="MX" {attrs}/></DataSet>"#
    )
}

/// An FCDA `daName` names nested attributes joined with `.`, so `mag.f` is
/// two path segments, matching the `["DO", "DA", "SDA", ...]` contract of
/// `DataSetEntry::do_path`.
#[test]
fn fcda_dotted_da_name_splits_into_segments() {
    let m = build(&wrap(
        MMXU_MV,
        &fcda(r#"doName="TotW" daName="mag.f""#),
        MMXU1,
    ));
    assert_eq!(first_entry(&m).do_path, vec!["TotW", "mag", "f"]);
}

/// An element index written into a name, as in `phsAHar(9).cVal`, is taken
/// off the segment and becomes the array index when `ix` is absent.
#[test]
fn fcda_indexed_segment_yields_the_array_index() {
    let m = build(&wrap(
        MMXU_MV,
        &fcda(r#"doName="Har" daName="phsAHar(9).cVal.mag.f" ix="9""#),
        MMXU1,
    ));
    let e = first_entry(&m);
    assert_eq!(e.do_path, vec!["Har", "phsAHar", "cVal", "mag", "f"]);
    assert_eq!(e.array_index, Some(9));
    let m = build(&wrap(MMXU_MV, &fcda(r#"doName="Har.phsAHar(3)""#), MMXU1));
    let e = first_entry(&m);
    assert_eq!(e.do_path, vec!["Har", "phsAHar"]);
    assert_eq!(e.array_index, Some(3));
}

/// A malformed or contradictory index, and an empty name segment, are
/// rejected.
#[test]
fn fcda_malformed_name_is_rejected() {
    for attrs in [
        r#"doName="Har" daName="phsAHar(9.cVal""#,
        r#"doName="Har" daName="phsAHar(x)""#,
        r#"doName="Har" daName="phsAHar(9)" ix="8""#,
        r#"doName="Har" daName="phsAHar(1).cVal(2)""#,
        r#"doName="TotW" daName="mag..f""#,
    ] {
        assert!(
            try_build(&wrap(MMXU_MV, &fcda(attrs), MMXU1)).is_err(),
            "{attrs} accepted"
        );
    }
}

/// An FCDA naming an attribute the model does not have, or naming one under
/// another functional constraint than its own, fails the build.
#[test]
fn fcda_unresolvable_attribute_fails_the_build() {
    for (fc, attrs) in [
        ("MX", r#"doName="TotW" daName="noSuchDa""#),
        ("MX", r#"doName="TotW" daName="mag.i""#),
        ("ST", r#"doName="TotW" daName="mag.f""#),
        ("ST", r#"doName="TotW""#),
    ] {
        let ln0 = format!(
            r#"<DataSet name="DS1"><FCDA ldInst="LD0" lnClass="MMXU" lnInst="1" fc="{fc}" {attrs}/></DataSet>"#
        );
        let err = try_build(&wrap(MMXU_MV, &ln0, MMXU1)).expect_err(attrs);
        assert!(err.contains("DS1"), "{err}");
    }
}

/// Control: the same members under their own functional constraint build.
#[test]
fn fcda_resolvable_members_build() {
    for attrs in [
        r#"doName="TotW" daName="mag.f""#,
        r#"doName="TotW" daName="q""#,
        r#"doName="TotW""#,
        r#"doName="Har" daName="phsAHar(2).cVal""#,
    ] {
        build(&wrap(MMXU_MV, &fcda(attrs), MMXU1));
    }
}
