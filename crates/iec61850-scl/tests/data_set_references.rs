//! Stage 2 checks the `datSet` of every control block against the data sets
//! of its logical node, as the keys of the SCL schema require
//! (IEC 61850-6 Annex A.4): a report, log, GOOSE or sampled value control
//! block naming a data set its logical node does not declare is rejected at
//! the control block.

use iec61850_scl::{ErrorKind, SclParseError};

/// One IED whose LLN0 declares the data set `ds0` and holds `ln0_body`, and
/// whose GGIO1 declares the data set `ds1` and holds `ggio_body`.
fn scl(ln0_body: &str, ggio_body: &str) -> String {
    format!(
        r#"<SCL>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnClass="LLN0" lnType="LLN0_T">
            <DataSet name="ds0">
              <FCDA ldInst="LD0" lnClass="LLN0" doName="Mod" daName="stVal" fc="ST"/>
            </DataSet>
{ln0_body}
          </LN0>
          <LN lnClass="GGIO" inst="1" lnType="LLN0_T">
            <DataSet name="ds1">
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Mod" daName="stVal" fc="ST"/>
            </DataSet>
{ggio_body}
          </LN>
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

fn resolve(xml: &str) -> Result<iec61850_scl::ResolvedScl, SclParseError> {
    iec61850_scl::parse_scl(xml).expect("parse").resolve()
}

/// The one-based line of the first line of `xml` holding `needle`.
fn line_of(xml: &str, needle: &str) -> u32 {
    let index = xml
        .lines()
        .position(|l| l.contains(needle))
        .unwrap_or_else(|| panic!("{needle} not in the file"));
    u32::try_from(index + 1).unwrap()
}

/// Asserts that `xml` fails stage 2 on the `datSet` `missing` of the control
/// block element `element` named `name`, in the logical node whose path
/// segment is `ln`, at the line of that element.
fn assert_rejected(xml: &str, ln: &str, element: &str, name: &str, missing: &str) {
    let err = match resolve(xml) {
        Ok(_) => panic!("{element} {name}: the file resolved"),
        Err(e) => e,
    };
    match err.kind.as_ref() {
        ErrorKind::UnresolvedDataSetReference { data_set, .. } => {
            assert_eq!(data_set, missing, "{err}")
        }
        other => panic!("{element} {name}: unexpected error {other:?}"),
    }
    assert_eq!(
        err.element_path,
        format!(
            "SCL/IED[name=\"IED1\"]/AccessPoint[name=\"AP1\"]/Server/LDevice[inst=\"LD0\"]/{ln}/{element}[name=\"{name}\"]"
        )
    );
    assert_eq!(err.attribute.as_deref(), Some("datSet"));
    assert_eq!(
        err.span.line,
        line_of(xml, &format!("<{element} name=\"{name}\"")),
        "{err}"
    );
}

const LLN0: &str = r#"LN[lnClass="LLN0",inst=""]"#;
const GGIO1: &str = r#"LN[lnClass="GGIO",inst="1"]"#;

/// Each kind of control block of LLN0 naming a data set LLN0 does not
/// declare is rejected at that control block.
#[test]
fn a_control_block_of_lln0_naming_a_missing_data_set_is_rejected() {
    for (element, body) in [
        (
            "ReportControl",
            r#"            <ReportControl name="rcb" datSet="nope" rptID="r"/>"#,
        ),
        (
            "LogControl",
            r#"            <LogControl name="lcb" datSet="nope" logName="log"/>"#,
        ),
        (
            "GSEControl",
            r#"            <GSEControl name="gcb" appID="app" datSet="nope"/>"#,
        ),
        (
            "SampledValueControl",
            r#"            <SampledValueControl name="svcb" smvID="sv" datSet="nope" smpRate="80" nofASDU="1"/>"#,
        ),
    ] {
        let name = body.split('"').nth(1).unwrap();
        assert_rejected(&scl(body, ""), LLN0, element, name, "nope");
    }
}

/// A report or log control block of another logical node is checked against
/// the data sets of its own logical node: one naming a data set of LLN0 is
/// rejected.
#[test]
fn a_control_block_names_a_data_set_of_its_own_logical_node() {
    assert_rejected(
        &scl(
            "",
            r#"            <ReportControl name="rcb" datSet="ds0" rptID="r"/>"#,
        ),
        GGIO1,
        "ReportControl",
        "rcb",
        "ds0",
    );
    assert_rejected(
        &scl(
            "",
            r#"            <LogControl name="lcb" datSet="ds0" logName="log"/>"#,
        ),
        GGIO1,
        "LogControl",
        "lcb",
        "ds0",
    );
}

/// The first control block of a logical node naming a missing data set is
/// the one reported, after those that resolve.
#[test]
fn the_first_unresolved_control_block_is_reported() {
    let xml = scl(
        r#"            <ReportControl name="ok" datSet="ds0" rptID="r"/>
            <ReportControl name="bad" datSet="ds1" rptID="r"/>"#,
        "",
    );
    assert_rejected(&xml, LLN0, "ReportControl", "bad", "ds1");
}

/// Control: control blocks naming a data set of their own logical node
/// resolve and reach the model, and a report or log control block naming no
/// data set, by an absent or an empty `datSet`, resolves.
#[test]
fn control_blocks_naming_their_own_data_sets_resolve() {
    let xml = scl(
        r#"            <ReportControl name="rcb" datSet="ds0" rptID="r"/>
            <ReportControl name="rcbNone" rptID="r"/>
            <ReportControl name="rcbEmpty" datSet="" rptID="r"/>
            <LogControl name="lcb" datSet="ds0" logName="log"/>
            <LogControl name="lcbNone" logName="log"/>
            <GSEControl name="gcb" appID="app" datSet="ds0"/>
            <SampledValueControl name="svcb" smvID="sv" datSet="ds0" smpRate="80" nofASDU="1"/>"#,
        r#"            <ReportControl name="rcb1" datSet="ds1" rptID="r"/>
            <LogControl name="lcb1" datSet="ds1" logName="log"/>"#,
    );
    let model = resolve(&xml)
        .expect("every data set resolves")
        .build_model("IED1")
        .expect("build");
    let lln0 = &model.lds[0].lns[0];
    assert_eq!(lln0.rcbs.len(), 3);
    assert_eq!(lln0.lcbs.len(), 2);
    assert_eq!(lln0.gocbs.len(), 1);
    let ggio = &model.lds[0].lns[1];
    assert_eq!(ggio.rcbs[0].dataset_ref, "ds1");
    assert_eq!(ggio.lcbs[0].dataset_ref, "ds1");
}

/// Every IED of a file is checked: in a substation configuration of two
/// IEDs, a control block of the second naming a data set its logical node
/// does not declare is rejected, though the first resolves.
#[test]
fn a_control_block_of_a_later_ied_is_checked() {
    let ied = |name: &str, data_set: &str| {
        format!(
            r#"  <IED name="{name}">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnClass="LLN0" lnType="LLN0_T">
            <DataSet name="ds0">
              <FCDA ldInst="LD0" lnClass="LLN0" doName="Mod" daName="stVal" fc="ST"/>
            </DataSet>
            <ReportControl name="rcb" datSet="{data_set}" rptID="r"/>
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
"#
        )
    };
    let xml = format!(
        r#"<SCL>
{}{}  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="BOOLEAN" dchg="true"/>
    </DOType>
  </DataTypeTemplates>
</SCL>"#,
        ied("IED1", "ds0"),
        ied("IED2", "nope")
    );
    let err = match resolve(&xml) {
        Ok(_) => panic!("the file resolved"),
        Err(e) => e,
    };
    match err.kind.as_ref() {
        ErrorKind::UnresolvedDataSetReference { data_set, .. } => assert_eq!(data_set, "nope"),
        other => panic!("unexpected error {other:?}"),
    }
    assert_eq!(
        err.element_path,
        r#"SCL/IED[name="IED2"]/AccessPoint[name="AP1"]/Server/LDevice[inst="LD0"]/LN[lnClass="LLN0",inst=""]/ReportControl[name="rcb"]"#
    );
    assert_eq!(err.attribute.as_deref(), Some("datSet"));

    // Control: with the data set declared in both, the file resolves.
    let xml = xml.replace(r#"datSet="nope""#, r#"datSet="ds0""#);
    assert!(resolve(&xml).is_ok());
}
