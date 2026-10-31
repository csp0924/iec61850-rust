//! What the model carries over from the control block elements of an SCL
//! file: `<LogControl>` and `<ReportControl>`, with the defaults IEC 61850-6
//! gives each omitted attribute.

use iec61850_model::cb::{LogControlBlock, ReportControlBlock};
use iec61850_model::tree::IedModel;
use iec61850_model::types::TrgOps;

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

/// One IED whose LLN0 carries `ln0_body` and a data set `ds1`.
fn wrap(ln0_body: &str) -> String {
    format!(
        r#"<SCL>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnClass="LLN0" lnType="LLN0_T">
            <DataSet name="ds1">
              <FCDA ldInst="LD0" lnClass="LLN0" doName="Mod" daName="stVal" fc="ST"/>
            </DataSet>
            {ln0_body}
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="BOOLEAN" dchg="true"/>
    </DOType>
  </DataTypeTemplates>
</SCL>"#
    )
}

fn lcbs(model: &IedModel) -> &[LogControlBlock] {
    &model.lds[0].lns[0].lcbs
}

fn rcbs(model: &IedModel) -> &[ReportControlBlock] {
    &model.lds[0].lns[0].rcbs
}

/// Every attribute of a `<LogControl>` and its `<TrgOps>` reaches the model.
#[test]
fn log_control_attributes_reach_the_model() {
    let m = build(&wrap(
        r#"<LogControl name="lcb1" datSet="ds1" logName="Log" logEna="false"
               reasonCode="false" bufTime="250" intgPd="5000">
             <TrgOps dchg="true" qchg="true" period="true" gi="true"/>
           </LogControl>"#,
    ));
    let lcb = &lcbs(&m)[0];
    assert_eq!(lcb.name, "lcb1");
    assert_eq!(lcb.dataset_ref, "ds1");
    assert_eq!(lcb.log_ref, "Log");
    assert!(!lcb.log_ena);
    assert!(!lcb.reason_code);
    assert_eq!(lcb.buf_tm_ms, 250);
    assert_eq!(lcb.intg_pd_ms, 5000);
    // GI does not apply to a log and is dropped.
    assert_eq!(lcb.trg_ops, TrgOps::DCHG | TrgOps::QCHG | TrgOps::INTEGRITY);
}

/// An omitted attribute takes its `tLogControl` default: logEna and
/// reasonCode true, bufTime and intgPd 0.
#[test]
fn log_control_defaults_follow_the_schema() {
    let m = build(&wrap(r#"<LogControl name="lcb1" logName="Log"/>"#));
    let lcb = &lcbs(&m)[0];
    assert!(lcb.log_ena);
    assert!(lcb.reason_code);
    assert_eq!(lcb.buf_tm_ms, 0);
    assert_eq!(lcb.intg_pd_ms, 0);
    assert_eq!(lcb.dataset_ref, "");
    assert_eq!(lcb, &LogControlBlock::new("lcb1", "Log"));
}

/// Control: a `<ReportControl>` keeps carrying its existing schema.
#[test]
fn report_control_schema_is_unchanged() {
    let m = build(&wrap(
        r#"<ReportControl name="brcb" datSet="ds1" confRev="1" buffered="true" bufTime="50" intgPd="1000">
             <TrgOps dchg="true" period="true"/>
           </ReportControl>"#,
    ));
    let rcb = &rcbs(&m)[0];
    assert!(rcb.is_buffered);
    assert_eq!(rcb.buf_tm_ms, 50);
    assert_eq!(rcb.intg_pd_ms, 1000);
    assert_eq!(rcb.trg_ops, TrgOps::DCHG | TrgOps::INTEGRITY | TrgOps::GI);
}

/// A `<TrgOps>` that leaves `gi` out enables general interrogation on a
/// report control block, buffered or not, as IEC 61850-6 §9.3.8 defaults it;
/// `gi="false"` disables it.
#[test]
fn report_trg_ops_default_gi_to_true() {
    let m = build(&wrap(
        r#"<ReportControl name="urcb" datSet="ds1" confRev="1"><TrgOps dchg="true"/></ReportControl>
           <ReportControl name="brcb" datSet="ds1" confRev="1" buffered="true"><TrgOps dchg="true"/></ReportControl>
           <ReportControl name="noGi" datSet="ds1" confRev="1"><TrgOps dchg="true" gi="false"/></ReportControl>
           <ReportControl name="bare" datSet="ds1" confRev="1"><TrgOps/></ReportControl>"#,
    ));
    let rcbs = rcbs(&m);
    assert_eq!(rcbs[0].trg_ops, TrgOps::DCHG | TrgOps::GI);
    assert_eq!(rcbs[1].trg_ops, TrgOps::DCHG | TrgOps::GI);
    assert_eq!(rcbs[2].trg_ops, TrgOps::DCHG);
    assert_eq!(rcbs[3].trg_ops, TrgOps::GI);
}

/// A report or log control block without a `<TrgOps>` element has no
/// trigger option at all.
#[test]
fn absent_trg_ops_element_enables_nothing() {
    let m = build(&wrap(
        r#"<ReportControl name="urcb" datSet="ds1" confRev="1"/>
           <LogControl name="lcb1" datSet="ds1" logName="Log"/>"#,
    ));
    assert_eq!(rcbs(&m)[0].trg_ops, TrgOps::NONE);
    assert_eq!(lcbs(&m)[0].trg_ops, TrgOps::NONE);
}

/// The `gi` default does not reach a log control block, to which general
/// interrogation does not apply.
#[test]
fn log_trg_ops_drop_the_gi_default() {
    let m = build(&wrap(
        r#"<LogControl name="lcb1" datSet="ds1" logName="Log"><TrgOps dchg="true"/></LogControl>"#,
    ));
    assert_eq!(lcbs(&m)[0].trg_ops, TrgOps::DCHG);
}

/// The summary line of a report control block carries every setting the
/// model holds, so two models that differ in any of them summarize apart.
#[test]
fn report_control_summary_carries_every_setting() {
    let m = build(&wrap(
        r#"<ReportControl name="brcb" datSet="ds1" rptID="R1" confRev="3" buffered="true" bufTime="50" intgPd="1000">
             <TrgOps dchg="true" period="true"/>
             <OptFields seqNum="true"/>
           </ReportControl>"#,
    ));
    let summary = iec61850_scl::summarize::summarize_model(&m);
    let line = summary
        .lines()
        .find(|l| l.trim_start().starts_with("RCB name=brcb "))
        .unwrap_or_else(|| panic!("no RCB line in:\n{summary}"));
    let rcb = &rcbs(&m)[0];
    for field in [
        format!("trg=0x{:02x}", rcb.trg_ops.0),
        format!("optFlds=0x{:04x}", rcb.opt_flds.0),
        "bufTm=50".to_string(),
        "intgPd=1000".to_string(),
    ] {
        assert!(line.contains(&field), "{field} missing from {line}");
    }
}

/// The raw `<TrgOps>` of a report and a log control block both carry the
/// `gi` default.
#[test]
fn raw_trg_ops_carry_the_gi_default() {
    let raw = iec61850_scl::parse_scl(&wrap(
        r#"<ReportControl name="urcb" datSet="ds1"><TrgOps dchg="true"/></ReportControl>
           <LogControl name="lcb1" datSet="ds1" logName="Log"><TrgOps qchg="true"/></LogControl>"#,
    ))
    .expect("parse");
    let ln0 = &raw.ieds[0].access_points[0]
        .server
        .as_ref()
        .expect("server")
        .logical_devices[0]
        .logical_nodes[0];
    assert!(ln0.report_controls[0].trg_ops.gi);
    assert!(ln0.log_controls[0].trg_ops.gi);
}

/// The raw `<LogControl>` already applies the schema default of
/// `reasonCode`, true, when the attribute is omitted.
#[test]
fn raw_log_control_reason_code_defaults_to_true() {
    let raw = iec61850_scl::parse_scl(&wrap(r#"<LogControl name="lcb1" logName="Log"/>"#))
        .expect("parse");
    let ln0 = &raw.ieds[0].access_points[0]
        .server
        .as_ref()
        .expect("server")
        .logical_devices[0]
        .logical_nodes[0];
    assert!(ln0.log_controls[0].reason_code);
    assert!(ln0.log_controls[0].log_ena);
}

/// `indexed` and the `max` of `<RptEnabled>` reach the model, and the model
/// names the instances `name01` to `nameNN`.
#[test]
fn rpt_enabled_max_and_indexed_reach_the_model() {
    let m = build(&wrap(
        r#"<ReportControl name="EventsBRCB" datSet="ds1" buffered="true">
             <RptEnabled max="3"><ClientLN iedName="C1" ldInst="LD0" lnClass="IHMI" lnInst="1"/></RptEnabled>
           </ReportControl>
           <ReportControl name="urcbA" datSet="ds1" indexed="false"/>"#,
    ));
    let rcbs = rcbs(&m);
    assert!(rcbs[0].indexed);
    assert_eq!(rcbs[0].max_instances, 3);
    assert_eq!(
        rcbs[0].instance_names(),
        ["EventsBRCB01", "EventsBRCB02", "EventsBRCB03"]
    );
    assert!(!rcbs[1].indexed);
    assert_eq!(rcbs[1].max_instances, 1);
    assert_eq!(rcbs[1].instance_names(), ["urcbA"]);
}

/// The raw `<ReportControl>` reads `max` from the `<RptEnabled>` child,
/// leaves it unset without one, and defaults `indexed` to true.
#[test]
fn raw_report_control_reads_the_rpt_enabled_child() {
    let raw = iec61850_scl::parse_scl(&wrap(
        r#"<ReportControl name="a" datSet="ds1"><RptEnabled max="5"/></ReportControl>
           <ReportControl name="b" datSet="ds1"/>
           <ReportControl name="c" datSet="ds1"><RptEnabled/></ReportControl>"#,
    ))
    .expect("parse");
    let ln0 = &raw.ieds[0].access_points[0]
        .server
        .as_ref()
        .expect("server")
        .logical_devices[0]
        .logical_nodes[0];
    let rc = &ln0.report_controls;
    assert_eq!(rc[0].rpt_enabled_max, Some(5));
    assert_eq!(rc[1].rpt_enabled_max, None);
    assert_eq!(rc[2].rpt_enabled_max, Some(1));
    assert!(rc.iter().all(|r| r.indexed));
}

/// `max="0"` is rejected, and so are more than 99 indexed instances, which a
/// two-digit suffix cannot name.
#[test]
fn impossible_instance_counts_are_rejected() {
    for body in [
        r#"<ReportControl name="a" datSet="ds1"><RptEnabled max="0"/></ReportControl>"#,
        r#"<ReportControl name="a" datSet="ds1"><RptEnabled max="100"/></ReportControl>"#,
    ] {
        assert!(try_build(&wrap(body)).is_err(), "{body} accepted");
    }
    // Control: the bounds themselves are accepted.
    for body in [
        r#"<ReportControl name="a" datSet="ds1"><RptEnabled max="99"/></ReportControl>"#,
        r#"<ReportControl name="a" datSet="ds1" indexed="false"><RptEnabled max="1"/></ReportControl>"#,
    ] {
        assert!(try_build(&wrap(body)).is_ok(), "{body} rejected");
    }
}

/// A block that is not indexed has a single instance, however large the
/// `max` it declares.
#[test]
fn unindexed_block_counts_one_instance() {
    let m = build(&wrap(
        r#"<ReportControl name="a" datSet="ds1" indexed="false"><RptEnabled max="2"/></ReportControl>"#,
    ));
    assert_eq!(rcbs(&m)[0].max_instances, 1);
    assert_eq!(rcbs(&m)[0].instance_names(), ["a"]);
}

/// The attribute `rptEnabledMax` does not exist in IEC 61850-6 and no longer
/// sets the instance count.
#[test]
fn rpt_enabled_max_attribute_is_not_read() {
    let m = build(&wrap(
        r#"<ReportControl name="a" datSet="ds1" rptEnabledMax="7"/>"#,
    ));
    assert_eq!(rcbs(&m)[0].max_instances, 1);
}

/// An empty `smvID` is filled with the control block reference, as an empty
/// GoID is (IEC 61850-6 Annex I.3.2.7); a given one is kept.
#[test]
fn empty_smv_id_takes_the_control_block_reference() {
    let m = build(&wrap(
        r#"<SampledValueControl name="msv" smvID="" datSet="ds1" smpRate="80" nofASDU="1"/>
           <SampledValueControl name="usv" smvID="" datSet="ds1" smpRate="80" nofASDU="1" multicast="false"/>
           <SampledValueControl name="named" smvID="SV1" datSet="ds1" smpRate="80" nofASDU="1"/>"#,
    ));
    let svcbs = &m.lds[0].lns[0].svcbs;
    assert_eq!(svcbs[0].sv_id, "IED1LD0/LLN0$MS$msv");
    assert_eq!(svcbs[1].sv_id, "IED1LD0/LLN0$US$usv");
    assert_eq!(svcbs[2].sv_id, "SV1");
}
