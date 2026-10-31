//! What the SCL-to-model path accepts, rejects and carries over, each case
//! stated as the outcome IEC 61850-6 requires for an inline SCL file.

use iec61850_model::tree::{DataAttribute, DoChild, IedModel};
use iec61850_model::types::DataAttributeType;
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
    match ln.do_by_name(do_name).unwrap().child_by_name(da_name, None) {
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

fn coded_enum_scl(doi: &str) -> String {
    let t = r#"
    <LNodeType id="GGIO_T" lnClass="GGIO"><DO name="C" type="C_T"/></LNodeType>
    <DOType id="C_T" cdc="DPC">
      <DA name="pos" fc="ST" bType="Dbpos"/>
      <DA name="step" fc="ST" bType="Tcmd"/>
    </DOType>"#;
    let ln =
        format!(r#"<LN lnClass="GGIO" inst="1" lnType="GGIO_T"><DOI name="C">{doi}</DOI></LN>"#);
    wrap(t, "", &ln)
}

fn two_bits(ord: u8) -> MmsValue {
    MmsValue::BitString {
        padding: 6,
        data: vec![ord << 6],
    }
}

/// A Dbpos or Tcmd `<Val>` written as an IEC 61850-7-3 value name becomes the
/// two-bit string of its ordinal.
#[test]
fn coded_enum_val_names_are_applied() {
    for (pos, pos_ord, step, step_ord) in [
        ("intermediate-state", 0, "stop", 0),
        ("off", 1, "lower", 1),
        ("on", 2, "higher", 2),
        ("bad-state", 3, "reserved", 3),
    ] {
        let doi = format!(
            r#"<DAI name="pos"><Val>{pos}</Val></DAI><DAI name="step"><Val>{step}</Val></DAI>"#
        );
        let m = build(&coded_enum_scl(&doi));
        assert_eq!(
            da(&m, "GGIO1", "C", "pos").snapshot(),
            two_bits(pos_ord),
            "{pos}"
        );
        assert_eq!(
            da(&m, "GGIO1", "C", "step").snapshot(),
            two_bits(step_ord),
            "{step}"
        );
    }
}

/// Control: a text that is not a value name leaves the default in place.
#[test]
fn coded_enum_unknown_val_keeps_the_default() {
    let m = build(&coded_enum_scl(
        r#"<DAI name="pos"><Val>closed</Val></DAI>"#,
    ));
    assert_eq!(da(&m, "GGIO1", "C", "pos").snapshot(), two_bits(0));
}

/// A `<DAI>` or `<SDI>` with an `ix` addresses an array element, which the
/// model does not hold, so its value is not written into the single element
/// the model keeps; the same instance without `ix` is applied.
#[test]
fn indexed_dai_and_sdi_are_skipped() {
    let t = r#"
    <LNodeType id="GGIO_T" lnClass="GGIO"><DO name="Lim" type="L_T"/></LNodeType>
    <DOType id="L_T" cdc="ING">
      <DA name="v" fc="SP" bType="INT32"/>
      <DA name="w" fc="SP" bType="INT32"/>
      <DA name="pulse" fc="CF" bType="Struct" type="P"/>
    </DOType>
    <DAType id="P"><BDA name="onDur" bType="INT32U"/></DAType>"#;
    let ln = r#"<LN lnClass="GGIO" inst="1" lnType="GGIO_T"><DOI name="Lim">
            <DAI name="v" ix="2"><Val>7</Val></DAI>
            <DAI name="w"><Val>9</Val></DAI>
            <SDI name="pulse" ix="1"><DAI name="onDur"><Val>5</Val></DAI></SDI>
          </DOI></LN>"#;
    let m = build(&wrap(t, "", ln));
    assert_eq!(da(&m, "GGIO1", "Lim", "v").snapshot(), MmsValue::Integer(0));
    assert_eq!(da(&m, "GGIO1", "Lim", "w").snapshot(), MmsValue::Integer(9));
    let pulse = da(&m, "GGIO1", "Lim", "pulse");
    assert_eq!(
        pulse.child_by_name("onDur").unwrap().snapshot(),
        MmsValue::Unsigned(0)
    );
}

/// Counts the WARN events whose fields mention `count`.
struct CountWarnings(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl tracing::Subscriber for CountWarnings {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Text(String);
        impl tracing::field::Visit for Text {
            fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                self.0.push_str(&format!("{}={:?} ", f.name(), v));
            }
        }
        if *event.metadata().level() == tracing::Level::WARN {
            let mut text = Text(String::new());
            event.record(&mut text);
            if text.0.contains("count") {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// An array declared with `count` on a `<DA>`, an `<SDO>` or a `<BDA>` is
/// built as a single element, and each such declaration is warned about
/// rather than dropped silently.
#[test]
fn count_is_warned_about() {
    let t = r#"
    <LNodeType id="GGIO_T" lnClass="GGIO"><DO name="Hst" type="HST_T"/></LNodeType>
    <DOType id="HST_T" cdc="HST">
      <DA name="hstVal" fc="ST" bType="INT32" count="4"/>
      <DA name="cfg" fc="CF" bType="Struct" type="CFG_T"/>
      <SDO name="har" type="CMV_T" count="16"/>
    </DOType>
    <DOType id="CMV_T" cdc="CMV"><DA name="q" fc="MX" bType="Quality"/></DOType>
    <DAType id="CFG_T"><BDA name="pts" bType="INT32" count="8"/></DAType>"#;
    let xml = wrap(t, "", r#"<LN lnClass="GGIO" inst="1" lnType="GGIO_T"/>"#);
    let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let m = tracing::subscriber::with_default(CountWarnings(seen.clone()), || build(&xml));
    assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert_eq!(
        da(&m, "GGIO1", "Hst", "hstVal").snapshot(),
        MmsValue::Integer(0)
    );
}

/// An EnumType with the given ordinals, referenced by `GGIO1.E.stVal`, with
/// the DAI value `val`.
fn enum_scl(ords: &[i32], val: &str) -> String {
    let vals: String = ords
        .iter()
        .map(|o| format!(r#"<EnumVal ord="{o}">v{o}</EnumVal>"#))
        .collect();
    let t = format!(
        r#"
    <LNodeType id="GGIO_T" lnClass="GGIO"><DO name="E" type="ENS_T"/></LNodeType>
    <DOType id="ENS_T" cdc="ENS"><DA name="stVal" fc="ST" bType="Enum" type="Big"/></DOType>
    <EnumType id="Big">{vals}</EnumType>"#
    );
    let ln = format!(
        r#"<LN lnClass="GGIO" inst="1" lnType="GGIO_T"><DOI name="E"><DAI name="stVal"><Val>{val}</Val></DAI></DOI></LN>"#
    );
    wrap(&t, "", &ln)
}

/// An Enum whose ordinals exceed integer(8) is declared with the smallest
/// integer that holds them all, so the value it carries fits its type.
#[test]
fn enum_with_wide_ordinals_widens_its_type() {
    for (ords, val, ty, v) in [
        (&[1, 300][..], "v300", DataAttributeType::Int16, 300),
        (&[-129, 0][..], "v-129", DataAttributeType::Int16, -129),
        (&[0, 70000][..], "v70000", DataAttributeType::Int32, 70000),
    ] {
        let m = build(&enum_scl(ords, val));
        let d = da(&m, "GGIO1", "E", "stVal");
        assert_eq!((d.ty, d.snapshot()), (ty, MmsValue::Integer(v)), "{ords:?}");
    }
}

/// Control: ordinals within −128..=127 keep the integer(8) Enumerated type.
#[test]
fn enum_within_integer8_keeps_its_type() {
    for val in ["v127", "v-128"] {
        let m = build(&enum_scl(&[-128, 127], val));
        assert_eq!(
            da(&m, "GGIO1", "E", "stVal").ty,
            DataAttributeType::Enumerated
        );
    }
}

/// A `<GSEControl>` with an empty `appID` gets the default GoID, its GoCBRef
/// `<domain>/LLN0$GO$<name>`, where the domain is the `ldName` when the
/// logical device sets one.
#[test]
fn gse_control_empty_app_id_defaults_to_the_gocb_ref() {
    let ln0 = r#"
            <DataSet name="DSGoose">
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
            </DataSet>
            <GSEControl name="gcb1" appID="" datSet="DSGoose" confRev="1"/>"#;
    let xml = wrap(GGIO_SPS, ln0, GGIO1);
    let m = build(&xml);
    let ln = m.ld_by_inst("LD0").unwrap().ln_by_name("LLN0").unwrap();
    assert_eq!(ln.gocbs[0].go_id, "IED1LD0/LLN0$GO$gcb1");
    let m = build(&xml.replace(
        r#"<LDevice inst="LD0">"#,
        r#"<LDevice inst="LD0" ldName="Bay1">"#,
    ));
    let ln = m.ld_by_inst("LD0").unwrap().ln_by_name("LLN0").unwrap();
    assert_eq!(ln.gocbs[0].go_id, "Bay1/LLN0$GO$gcb1");
}

fn octet_time_scl(doi: &str) -> String {
    let t = r#"
    <LNodeType id="GGIO_T" lnClass="GGIO"><DO name="R" type="R_T"/></LNodeType>
    <DOType id="R_T" cdc="SPS">
      <DA name="raw" fc="CF" bType="Octet64"/>
      <DA name="t" fc="ST" bType="Timestamp"/>
    </DOType>"#;
    let ln =
        format!(r#"<LN lnClass="GGIO" inst="1" lnType="GGIO_T"><DOI name="R">{doi}</DOI></LN>"#);
    wrap(t, "", &ln)
}

/// An Octet64 `<Val>` is base64Binary and a Timestamp `<Val>` an xs:dateTime
/// without a time zone, both applied to the attribute.
#[test]
fn octet_string_and_timestamp_vals_are_applied() {
    let m = build(&octet_time_scl(
        r#"<DAI name="raw"><Val>3q2+7w==</Val></DAI><DAI name="t"><Val>2007-12-31T21:01:12.345</Val></DAI>"#,
    ));
    assert_eq!(
        da(&m, "GGIO1", "R", "raw").snapshot(),
        MmsValue::OctetString(vec![0xDE, 0xAD, 0xBE, 0xEF])
    );
    match da(&m, "GGIO1", "R", "t").snapshot() {
        MmsValue::UtcTime(b) => assert_eq!(b[..4], 1_199_134_872u32.to_be_bytes()),
        other => panic!("{other:?}"),
    }
}

/// A `<Val>` that is not base64Binary or not an xs:dateTime fails the build.
#[test]
fn malformed_octet_string_or_timestamp_val_fails_the_build() {
    for doi in [
        r#"<DAI name="raw"><Val>DEADBEEF!</Val></DAI>"#,
        r#"<DAI name="t"><Val>31.12.2007 21:01</Val></DAI>"#,
    ] {
        assert!(try_build(&octet_time_scl(doi)).is_err(), "{doi} accepted");
    }
}

const SETTINGS: &str = r#"
    <LNodeType id="PTOC_T" lnClass="PTOC">
      <DO name="OpDlTmms" type="ING_SE_T"/>
      <DO name="StrVal" type="ASG_SE_T"/>
      <DO name="TmMult" type="ING_SG_T"/>
      <DO name="MinOpTmms" type="ING_BOTH_T"/>
    </LNodeType>
    <DOType id="ING_SE_T" cdc="ING">
      <DA name="setVal" fc="SE" bType="INT32"><Val>100</Val></DA>
      <DA name="minVal" fc="CF" bType="INT32"/>
    </DOType>
    <DOType id="ASG_SE_T" cdc="ASG">
      <DA name="setMag" fc="SE" bType="Struct" type="AnVal_T"/>
    </DOType>
    <DOType id="ING_SG_T" cdc="ING">
      <DA name="setVal" fc="SG" bType="INT32"><Val>7</Val></DA>
    </DOType>
    <DOType id="ING_BOTH_T" cdc="ING">
      <DA name="setVal" fc="SG" bType="INT32"><Val>3</Val></DA>
      <DA name="setVal" fc="SE" bType="INT32"><Val>4</Val></DA>
    </DOType>
    <DAType id="AnVal_T"><BDA name="f" bType="FLOAT32"/></DAType>"#;

fn settings_model(doi: &str) -> IedModel {
    let ln = format!(r#"<LN lnClass="PTOC" inst="1" lnType="PTOC_T">{doi}</LN>"#);
    build(&wrap(SETTINGS, "", &ln))
}

/// The data attributes of `do_name` under `fc`, by name.
fn under_fc<'a>(model: &'a IedModel, do_name: &str, fc: FC) -> Vec<&'a DataAttribute> {
    let ln = model
        .ld_by_inst("LD0")
        .unwrap()
        .ln_by_name("PTOC1")
        .unwrap();
    ln.do_by_name(do_name)
        .unwrap()
        .children_with_fc(fc)
        .collect()
}

/// A `<DA>` with `fc="SE"` is also an FC=SG data attribute of the same name and
/// type, starting at the same value, with a value of its own.
#[test]
fn se_attribute_is_also_an_sg_attribute() {
    let m = settings_model("");
    let se = under_fc(&m, "OpDlTmms", FC::Se);
    let sg = under_fc(&m, "OpDlTmms", FC::Sg);
    assert_eq!(se.len(), 1);
    assert_eq!(sg.len(), 1);
    assert_eq!(sg[0].name, "setVal");
    assert_eq!(sg[0].ty, DataAttributeType::Int32);
    assert_eq!(sg[0].snapshot(), MmsValue::Integer(100));
    assert_eq!(under_fc(&m, "OpDlTmms", FC::Cf).len(), 1);

    se[0].store(MmsValue::Integer(5));
    assert_eq!(sg[0].snapshot(), MmsValue::Integer(100));

    let sg_mag = under_fc(&m, "StrVal", FC::Sg);
    assert_eq!(sg_mag.len(), 1);
    let f = sg_mag[0].child_by_name("f").unwrap();
    assert_eq!(f.fc, FC::Sg);
    assert_eq!(f.snapshot(), MmsValue::Float32(0.0));
}

/// A `<DAI>` value of an FC=SE attribute is the initial value under FC=SG too,
/// for a leaf and for a member of a constructed attribute.
#[test]
fn dai_value_of_an_se_attribute_reaches_the_sg_attribute() {
    let m = settings_model(
        r#"<DOI name="OpDlTmms"><DAI name="setVal"><Val>250</Val></DAI></DOI>
           <DOI name="StrVal"><SDI name="setMag"><DAI name="f"><Val>1.5</Val></DAI></SDI></DOI>"#,
    );
    for fc in [FC::Se, FC::Sg] {
        assert_eq!(
            under_fc(&m, "OpDlTmms", fc)[0].snapshot(),
            MmsValue::Integer(250),
            "{fc:?}"
        );
        let mag = under_fc(&m, "StrVal", fc)[0];
        assert_eq!(
            mag.child_by_name("f").unwrap().snapshot(),
            MmsValue::Float32(1.5),
            "{fc:?}"
        );
    }
}

/// A `<DA>` with `fc="SG"` stays a view only, and a DOType that declares a
/// setting under both constraints keeps exactly those two attributes.
#[test]
fn sg_attribute_does_not_yield_an_se_attribute() {
    let m = settings_model("");
    assert!(under_fc(&m, "TmMult", FC::Se).is_empty());
    let sg = under_fc(&m, "TmMult", FC::Sg);
    assert_eq!(sg.len(), 1);
    assert_eq!(sg[0].snapshot(), MmsValue::Integer(7));

    let se = under_fc(&m, "MinOpTmms", FC::Se);
    let sg = under_fc(&m, "MinOpTmms", FC::Sg);
    assert_eq!((se.len(), sg.len()), (1, 1));
    assert_eq!(se[0].snapshot(), MmsValue::Integer(4));
    assert_eq!(sg[0].snapshot(), MmsValue::Integer(3));
}

fn settings_model_with_data_set(fcda: &str) -> Result<IedModel, String> {
    let ln0 = format!(r#"<DataSet name="ds">{fcda}</DataSet>"#);
    let ln = r#"<LN lnClass="PTOC" inst="1" lnType="PTOC_T"/>"#;
    try_build(&wrap(SETTINGS, &ln0, ln))
}

/// An `<FCDA>` resolves the setting under the constraint it names, at the data
/// attribute level as well as the data object level, whichever of the two
/// attributes the DOType declares first.
#[test]
fn fcda_resolves_a_setting_under_se_and_sg() {
    for fcda in [
        r#"<FCDA ldInst="LD0" lnClass="PTOC" lnInst="1" doName="OpDlTmms" daName="setVal" fc="SG"/>"#,
        r#"<FCDA ldInst="LD0" lnClass="PTOC" lnInst="1" doName="OpDlTmms" daName="setVal" fc="SE"/>"#,
        r#"<FCDA ldInst="LD0" lnClass="PTOC" lnInst="1" doName="OpDlTmms" fc="SG"/>"#,
        r#"<FCDA ldInst="LD0" lnClass="PTOC" lnInst="1" doName="MinOpTmms" daName="setVal" fc="SE"/>"#,
        r#"<FCDA ldInst="LD0" lnClass="PTOC" lnInst="1" doName="MinOpTmms" daName="setVal" fc="SG"/>"#,
    ] {
        settings_model_with_data_set(fcda).unwrap_or_else(|e| panic!("{fcda}: {e}"));
    }
    let err = settings_model_with_data_set(
        r#"<FCDA ldInst="LD0" lnClass="PTOC" lnInst="1" doName="TmMult" daName="setVal" fc="SE"/>"#,
    )
    .expect_err("a setting declared under FC=SG only has no FC=SE attribute");
    assert!(err.contains("does not exist"), "{err}");
}

/// A setting declared under FC=SG and FC=SE with two different types is
/// refused.
#[test]
fn setting_declared_with_two_types_is_rejected() {
    let t = r#"
    <LNodeType id="X_T" lnClass="PTOC"><DO name="Spt" type="X_DO"/></LNodeType>
    <DOType id="X_DO" cdc="ING">
      <DA name="setVal" fc="SG" bType="INT32"/>
      <DA name="setVal" fc="SE" bType="INT64"/>
    </DOType>"#;
    let ln = r#"<LN lnClass="PTOC" inst="1" lnType="X_T"/>"#;
    let err = try_build(&wrap(t, "", ln)).expect_err("two types for one setting");
    assert!(err.contains("setVal"), "{err}");
}

/// An `fc="SE"` attribute below a sub-object is also an FC=SG attribute there.
#[test]
fn se_attribute_below_a_sub_object_is_also_an_sg_attribute() {
    let t = r#"
    <LNodeType id="X_T" lnClass="PTOC"><DO name="TmSet" type="X_DO"/></LNodeType>
    <DOType id="X_DO" cdc="ING"><SDO name="tm" type="X_SUB"/></DOType>
    <DOType id="X_SUB" cdc="ING"><DA name="setVal" fc="SE" bType="INT32"><Val>8</Val></DA></DOType>"#;
    let ln = r#"<LN lnClass="PTOC" inst="1" lnType="X_T">
      <DOI name="TmSet"><SDI name="tm"><DAI name="setVal"><Val>9</Val></DAI></SDI></DOI></LN>"#;
    let m = build(&wrap(t, "", ln));
    let ln = m.ld_by_inst("LD0").unwrap().ln_by_name("PTOC1").unwrap();
    let sub = match ln.do_by_name("TmSet").unwrap().child_by_name("tm", None) {
        Some(DoChild::SubDo(s)) => s,
        other => panic!("tm: {other:?}"),
    };
    for fc in [FC::Se, FC::Sg] {
        let da: Vec<_> = sub.children_with_fc(fc).collect();
        assert_eq!(da.len(), 1, "{fc:?}");
        assert_eq!(da[0].snapshot(), MmsValue::Integer(9), "{fc:?}");
    }
}
