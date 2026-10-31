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
    assert_eq!(rcb.trg_ops, TrgOps::DCHG | TrgOps::INTEGRITY);
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
