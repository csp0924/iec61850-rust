//! Every service of the client against one instance of the server of this
//! repository, started from an SCL model with every control block the model
//! declares registered in one call.
//!
//! The steps run in order on the same server and, where they can, the same
//! association: association services, directories and variable access
//! attributes, reads of every functional constraint and of an array element,
//! writes of a data attribute and a whole data object, data sets with data
//! object and constructed members, the four control models and a refusal,
//! unbuffered and buffered reports with several instances, segmented reports
//! on an association with a small PDU, the GOOSE control block, the log and
//! its journal, the setting groups, and release, abort and a refused
//! association. Each step checks what the standard has the server answer;
//! the details of each service are covered by the tests of that service.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use iec61850_client::control::{ControlAddCause, ControlOutcome, OriginValue};
use iec61850_client::dataset_admin::DataSetMember;
use iec61850_client::directory::AcsiClass;
use iec61850_client::gocb::GoCBValuesWrite;
use iec61850_client::journal::JournalQuery;
use iec61850_client::rcb::{RcbHandle, RcbWriteMask};
use iec61850_client::report::{ClientReport, ReasonForInclusion, ReportCallback};
use iec61850_client::{ClientError, IedConnection, TypeSpecification};
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_mms::{AccessResult, DataAccessError};
use iec61850_model::{ControlModel, DataAttribute, DoChild, IedModel, MmsValue, FC};
use iec61850_server::control::{
    AlwaysAcceptCheckHandler, AlwaysAcceptWaitHandler, AlwaysSuccessOperateHandler, CheckHandler,
    ControlAction, ControlAddCause as ServerAddCause, ControlHandler, WaitForExecutionHandler,
};
use iec61850_server::{FromModelSummary, IedServer, IedServerConfig, ServerHandle};

const LD: &str = "MxLD0";

/// A visible string long enough that the members of `dsBig` do not fit one
/// PDU of 1024 octets together, while each fits one alone.
fn long_text(tag: &str) -> String {
    format!("{tag}-{}", "0123456789".repeat(9))
}

/// The model: LLN0 with three data sets, report control blocks of both kinds
/// (one indexed with two instances), a GOOSE control block, a log control
/// block and two setting groups; GGIO1 with status points, five controllable
/// points, a writable structure, a measured value and an array; LPHD1 and
/// PTOC1 with a name plate and a setting.
fn matrix_scl() -> String {
    let scl = r#"<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B">
  <Header id="matrix"/>
  <IED name="Mx">
    <AccessPoint name="AP1">
      <Server>
        <Authentication/>
        <LDevice inst="LD0">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <DataSet name="dsStatus">
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind2" fc="ST"/>
            </DataSet>
            <DataSet name="dsBig">
              <FCDA ldInst="LD0" lnClass="LLN0" doName="NamPlt" fc="DC"/>
              <FCDA ldInst="LD0" lnClass="LPHD" lnInst="1" doName="PhyNam" fc="DC"/>
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Nam" fc="DC"/>
            </DataSet>
            <DataSet name="dsLog">
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind3" daName="stVal" fc="ST"/>
            </DataSet>
            <ReportControl name="urcbSt" datSet="dsStatus" confRev="1" bufTime="0">
              <TrgOps dchg="true" qchg="true" gi="true"/>
              <OptFields seqNum="true" dataSet="true" reasonCode="true" dataRef="true" configRef="true"/>
              <RptEnabled max="2"/>
            </ReportControl>
            <ReportControl name="brcbSt" datSet="dsStatus" buffered="true" indexed="false" confRev="1" bufTime="0">
              <TrgOps dchg="true" qchg="true" gi="true"/>
              <OptFields seqNum="true" entryID="true" reasonCode="true" dataSet="true"/>
              <RptEnabled max="1"/>
            </ReportControl>
            <ReportControl name="urcbBig" datSet="dsBig" indexed="false" confRev="1" bufTime="0">
              <TrgOps dchg="true" gi="true"/>
              <OptFields seqNum="true" dataSet="true"/>
              <RptEnabled max="1"/>
            </ReportControl>
            <ReportControl name="brcbBig" datSet="dsBig" buffered="true" indexed="false" confRev="1" bufTime="0">
              <TrgOps dchg="true" gi="true"/>
              <OptFields seqNum="true" entryID="true"/>
              <RptEnabled max="1"/>
            </ReportControl>
            <LogControl name="lcbLog" datSet="dsLog" logName="MxLog" logEna="true">
              <TrgOps dchg="true"/>
            </LogControl>
            <GSEControl name="gcbStatus" datSet="dsStatus" appID="MxStatus" confRev="1"/>
            <SettingControl numOfSGs="2" actSG="1"/>
            <DOI name="NamPlt">
              <DAI name="vendor"><Val>{LONG_A}</Val></DAI>
              <DAI name="swRev"><Val>{LONG_B}</Val></DAI>
              <DAI name="d"><Val>{LONG_C}</Val></DAI>
              <DAI name="configRev"><Val>{LONG_D}</Val></DAI>
            </DOI>
          </LN0>
          <LN lnClass="LPHD" inst="1" lnType="LPHD_T">
            <DOI name="PhyNam">
              <DAI name="vendor"><Val>{LONG_E}</Val></DAI>
              <DAI name="hwRev"><Val>{LONG_F}</Val></DAI>
              <DAI name="swRev"><Val>{LONG_G}</Val></DAI>
              <DAI name="serNum"><Val>{LONG_H}</Val></DAI>
              <DAI name="model"><Val>{LONG_I}</Val></DAI>
            </DOI>
          </LN>
          <LN lnClass="GGIO" inst="1" lnType="GGIO_T">
            <DOI name="SPCSO1"><DAI name="ctlModel"><Val>direct-with-normal-security</Val></DAI></DOI>
            <DOI name="SPCSO2"><DAI name="ctlModel"><Val>sbo-with-normal-security</Val></DAI></DOI>
            <DOI name="SPCSO3"><DAI name="ctlModel"><Val>direct-with-enhanced-security</Val></DAI></DOI>
            <DOI name="SPCSO4"><DAI name="ctlModel"><Val>sbo-with-enhanced-security</Val></DAI></DOI>
            <DOI name="SPCSO5"><DAI name="ctlModel"><Val>direct-with-normal-security</Val></DAI></DOI>
            <DOI name="Nam">
              <DAI name="vendor"><Val>{LONG_J}</Val></DAI>
              <DAI name="hwRev"><Val>{LONG_K}</Val></DAI>
              <DAI name="swRev"><Val>{LONG_L}</Val></DAI>
              <DAI name="serNum"><Val>{LONG_M}</Val></DAI>
              <DAI name="model"><Val>{LONG_N}</Val></DAI>
            </DOI>
            <DOI name="Hst">
              <DAI name="hstVal" ix="1"><Val>5</Val></DAI>
            </DOI>
          </LN>
          <LN lnClass="PTOC" inst="1" lnType="PTOC_T">
            <DOI name="OpDlTmms">
              <DAI name="setVal"><Val sGroup="1">100</Val><Val sGroup="2">200</Val></DAI>
            </DOI>
          </LN>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
      <DO name="NamPlt" type="LPL_T"/>
    </LNodeType>
    <LNodeType id="LPHD_T" lnClass="LPHD">
      <DO name="PhyNam" type="DPL_T"/>
    </LNodeType>
    <LNodeType id="GGIO_T" lnClass="GGIO">
      <DO name="Ind1" type="SPS_T"/>
      <DO name="Ind2" type="SPS_T"/>
      <DO name="Ind3" type="SPS_T"/>
      <DO name="SPCSO1" type="SPC_T"/>
      <DO name="SPCSO2" type="SPC_T"/>
      <DO name="SPCSO3" type="SPC_T"/>
      <DO name="SPCSO4" type="SPC_T"/>
      <DO name="SPCSO5" type="SPC_T"/>
      <DO name="Lim" type="LIM_T"/>
      <DO name="AnIn1" type="MV_T"/>
      <DO name="Hst" type="HST_T"/>
      <DO name="Nam" type="DPL_T"/>
    </LNodeType>
    <LNodeType id="PTOC_T" lnClass="PTOC">
      <DO name="OpDlTmms" type="ING_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="BOOLEAN"/>
    </DOType>
    <DOType id="LPL_T" cdc="LPL">
      <DA name="vendor" fc="DC" bType="VisString255"/>
      <DA name="swRev" fc="DC" bType="VisString255"/>
      <DA name="d" fc="DC" bType="VisString255"/>
      <DA name="configRev" fc="DC" bType="VisString255"/>
    </DOType>
    <DOType id="DPL_T" cdc="DPL">
      <DA name="vendor" fc="DC" bType="VisString255"/>
      <DA name="hwRev" fc="DC" bType="VisString255"/>
      <DA name="swRev" fc="DC" bType="VisString255"/>
      <DA name="serNum" fc="DC" bType="VisString255"/>
      <DA name="model" fc="DC" bType="VisString255"/>
    </DOType>
    <DOType id="SPS_T" cdc="SPS">
      <DA name="stVal" fc="ST" bType="BOOLEAN" dchg="true"/>
      <DA name="q" fc="ST" bType="Quality" qchg="true"/>
      <DA name="t" fc="ST" bType="Timestamp"/>
    </DOType>
    <DOType id="SPC_T" cdc="SPC">
      <DA name="SBO" fc="CO" bType="ObjRef"/>
      <DA name="SBOw" fc="CO" bType="Struct" type="SPCCmd_T"/>
      <DA name="Oper" fc="CO" bType="Struct" type="SPCCmd_T"/>
      <DA name="Cancel" fc="CO" bType="Struct" type="Cancel_T"/>
      <DA name="origin" fc="ST" bType="Struct" type="Originator_T"/>
      <DA name="ctlNum" fc="ST" bType="INT8U"/>
      <DA name="stVal" fc="ST" bType="BOOLEAN" dchg="true"/>
      <DA name="q" fc="ST" bType="Quality" qchg="true"/>
      <DA name="t" fc="ST" bType="Timestamp"/>
      <DA name="ctlModel" fc="CF" bType="Enum" type="CtlModelKind"/>
    </DOType>
    <DOType id="LIM_T" cdc="ASG">
      <DA name="lo" fc="SP" bType="INT8"/>
      <DA name="hi" fc="SP" bType="INT8"/>
    </DOType>
    <DOType id="MV_T" cdc="MV">
      <DA name="mag" fc="MX" bType="Struct" type="AnalogValue_T" dchg="true"/>
      <DA name="q" fc="MX" bType="Quality" qchg="true"/>
    </DOType>
    <DOType id="HST_T" cdc="HST">
      <DA name="hstVal" fc="ST" bType="INT32" count="3" dchg="true"/>
    </DOType>
    <DOType id="ING_T" cdc="ING">
      <DA name="setVal" fc="SG" bType="INT32"/>
      <DA name="setVal" fc="SE" bType="INT32"/>
    </DOType>
    <DAType id="AnalogValue_T">
      <BDA name="f" bType="FLOAT32"/>
    </DAType>
    <DAType id="Originator_T">
      <BDA name="orCat" bType="Enum" type="OrCatKind"/>
      <BDA name="orIdent" bType="Octet64"/>
    </DAType>
    <DAType id="SPCCmd_T">
      <BDA name="ctlVal" bType="BOOLEAN"/>
      <BDA name="origin" bType="Struct" type="Originator_T"/>
      <BDA name="ctlNum" bType="INT8U"/>
      <BDA name="T" bType="Timestamp"/>
      <BDA name="Test" bType="BOOLEAN"/>
      <BDA name="Check" bType="Check"/>
    </DAType>
    <DAType id="Cancel_T">
      <BDA name="ctlVal" bType="BOOLEAN"/>
      <BDA name="origin" bType="Struct" type="Originator_T"/>
      <BDA name="ctlNum" bType="INT8U"/>
      <BDA name="T" bType="Timestamp"/>
      <BDA name="Test" bType="BOOLEAN"/>
    </DAType>
    <EnumType id="CtlModelKind">
      <EnumVal ord="0">status-only</EnumVal>
      <EnumVal ord="1">direct-with-normal-security</EnumVal>
      <EnumVal ord="2">sbo-with-normal-security</EnumVal>
      <EnumVal ord="3">direct-with-enhanced-security</EnumVal>
      <EnumVal ord="4">sbo-with-enhanced-security</EnumVal>
    </EnumType>
    <EnumType id="OrCatKind">
      <EnumVal ord="0">not-supported</EnumVal>
      <EnumVal ord="1">bay-control</EnumVal>
      <EnumVal ord="2">station-control</EnumVal>
      <EnumVal ord="3">remote-control</EnumVal>
    </EnumType>
  </DataTypeTemplates>
</SCL>"#;
    let mut scl = scl.to_string();
    for tag in "ABCDEFGHIJKLMN".chars() {
        scl = scl.replace(&format!("{{LONG_{tag}}}"), &long_text(&tag.to_string()));
    }
    scl
}

fn build_model() -> Arc<IedModel> {
    let raw = iec61850_scl::parse_scl(&matrix_scl()).expect("parse the SCL");
    Arc::new(
        raw.resolve()
            .expect("resolve the SCL")
            .build_model("Mx")
            .expect("build the model"),
    )
}

/// A check handler refusing every command as blocked by interlocking.
struct Interlocked;

impl CheckHandler for Interlocked {
    fn check(
        &self,
        _action: &ControlAction,
        _ctl_val: Option<&MmsValue>,
        _test: bool,
        _interlock_check: bool,
    ) -> Result<(), ServerAddCause> {
        Err(ServerAddCause::BlockedByInterlocking)
    }
}

/// Builds the server from the model, registers what the model declares and
/// installs the control handlers: SPCSO1 to SPCSO4 accept, SPCSO5 is
/// refused by its check.
fn build_server(model: Arc<IedModel>) -> IedServer {
    let mut config = IedServerConfig::default();
    config.max_mms_connections = 3;
    let server = IedServer::builder()
        .model(model)
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(config)
        .build()
        .expect("build the server");
    let summary = server.register_from_model().expect("register_from_model");
    let mut expected = FromModelSummary::default();
    expected.data_sets = 3;
    expected.urcbs = 3;
    expected.brcbs = 2;
    expected.gocbs = 1;
    expected.lcbs = 1;
    expected.sgcbs = 1;
    expected.control_objects = 5;
    assert_eq!(summary, expected);

    let registry = server.control_objects();
    for name in ["SPCSO1", "SPCSO2", "SPCSO3", "SPCSO4", "SPCSO5"] {
        let entry = registry
            .lookup(LD, "GGIO1", name)
            .unwrap_or_else(|| panic!("{name} is registered from the model"));
        let check: Arc<dyn CheckHandler> = if name == "SPCSO5" {
            Arc::new(Interlocked)
        } else {
            Arc::new(AlwaysAcceptCheckHandler)
        };
        registry.register(
            entry
                .with_check(check)
                .with_wait(Arc::new(AlwaysAcceptWaitHandler) as Arc<dyn WaitForExecutionHandler>)
                .with_operate(Arc::new(AlwaysSuccessOperateHandler) as Arc<dyn ControlHandler>),
        );
    }
    server
}

async fn connect(handle: &ServerHandle, max_pdu: Option<u32>) -> IedConnection {
    let mut builder = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000);
    if let Some(max) = max_pdu {
        builder = builder.local_max_pdu_size(max);
    }
    let conn = IedConnection::with_mms_client(builder.build());
    conn.connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    conn
}

/// The attribute `<LD>/<path>` of the model, `path` in dot notation.
fn attribute<'m>(model: &'m IedModel, path: &str, fc: FC) -> &'m DataAttribute {
    let (ln, rest) = path.split_once('.').expect("<LN>.<DO>.<DA>");
    let (dobj, da) = rest.split_once('.').expect("<DO>.<DA>");
    let dobj = model
        .ld_by_domain(LD)
        .and_then(|ld| ld.ln_by_name(ln))
        .and_then(|ln| ln.do_by_name(dobj))
        .unwrap_or_else(|| panic!("{path}: no such data object"));
    match dobj.child_by_name(da, Some(fc)) {
        Some(DoChild::Da(da)) => da,
        other => panic!("{path}: {other:?}"),
    }
}

/// The reports one handler received, in order.
#[derive(Clone, Default)]
struct Received(Arc<Mutex<Vec<Arc<ClientReport>>>>);

impl Received {
    fn callback(&self) -> ReportCallback {
        let sink = Arc::clone(&self.0);
        Arc::new(move |report: Arc<ClientReport>| sink.lock().unwrap().push(report))
    }

    fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    /// Polls `conn` until `count` reports have arrived and returns them;
    /// fails after ten seconds.
    async fn wait(&self, conn: &IedConnection, count: usize) -> Vec<Arc<ClientReport>> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            {
                let seen = self.0.lock().unwrap();
                if seen.len() >= count {
                    return seen[..count].to_vec();
                }
            }
            assert!(
                Instant::now() < deadline,
                "{count} reports expected, {} arrived",
                self.len()
            );
            conn.poll_reports(Duration::from_millis(100))
                .await
                .expect("poll reports");
        }
    }
}

/// Installs a handler for the report control block `rcb` and returns where
/// its reports go.
async fn subscribe(conn: &IedConnection, rcb: &str) -> Received {
    let received = Received::default();
    conn.install_report_handler(None, rcb, None, received.callback())
        .await
        .expect("install the report handler");
    received
}

async fn enable(conn: &IedConnection, rcb: &str, gi: bool) {
    let mut handle = RcbHandle::new(rcb).expect("rcb reference");
    handle.set_rpt_ena(true);
    let mut mask = RcbWriteMask::RPT_ENA;
    if gi {
        handle.set_gi(true);
        mask |= RcbWriteMask::GI;
    }
    conn.set_rcb_values(&handle, mask, false)
        .await
        .unwrap_or_else(|e| panic!("enable {rcb}: {e:?}"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_service_runs_on_one_server() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let model = build_model();
        let server = build_server(Arc::clone(&model));
        let handle = server.start().await.expect("start");
        let conn = connect(&handle, None).await;

        association(&conn).await;
        directories(&conn).await;
        reads(&conn).await;
        writes(&conn).await;
        data_sets(&conn).await;
        controls(&conn).await;
        reports(&server, &model, &conn).await;
        segmented_reports(&handle).await;
        goose_control_block(&conn).await;
        log_and_journal(&server, &model, &conn).await;
        setting_groups(&conn).await;
        release_abort_and_refusal(&server, &handle, &conn).await;

        handle.stop().await;
    })
    .await
    .expect("the matrix finishes within 60 s");
}

/// Identify and Status answer on the association.
async fn association(conn: &IedConnection) {
    let identity = conn.get_server_identity().await.expect("Identify");
    assert!(!identity.vendor.is_empty(), "{identity:?}");
    assert!(!identity.model.is_empty(), "{identity:?}");
    conn.get_server_status(false).await.expect("Status");
}

/// The server, logical device and logical node directories list what the
/// model declares, and the variable access attributes follow it.
async fn directories(conn: &IedConnection) {
    assert_eq!(
        conn.get_server_directory(false)
            .await
            .expect("server directory"),
        vec![LD.to_string()]
    );
    let lns = conn
        .get_logical_device_directory(LD)
        .await
        .expect("logical device directory");
    for ln in ["LLN0", "LPHD1", "GGIO1", "PTOC1"] {
        assert!(lns.iter().any(|l| l == ln), "{ln} in {lns:?}");
    }
    let listed = |class| async move {
        let mut names = conn
            .get_logical_node_directory(&format!("{LD}/LLN0"), class)
            .await
            .unwrap_or_else(|e| panic!("{class:?}: {e:?}"));
        names.sort();
        names
    };
    assert_eq!(
        listed(AcsiClass::DataSet).await,
        ["dsBig", "dsLog", "dsStatus"]
    );
    assert_eq!(
        listed(AcsiClass::Urcb).await,
        ["urcbBig", "urcbSt01", "urcbSt02"]
    );
    assert_eq!(listed(AcsiClass::Brcb).await, ["brcbBig", "brcbSt"]);
    assert_eq!(listed(AcsiClass::GoCb).await, ["gcbStatus"]);
    assert_eq!(listed(AcsiClass::Lcb).await, ["lcbLog"]);
    assert_eq!(listed(AcsiClass::Log).await, ["MxLog"]);
    assert_eq!(listed(AcsiClass::Sgcb).await, ["SGCB"]);

    // The members of a data object follow the order of its type.
    let TypeSpecification::Structure { components } = conn
        .get_variable_specification(&format!("{LD}/GGIO1.Ind2"), FC::St)
        .await
        .expect("Ind2 attributes")
    else {
        panic!("a data object is a structure");
    };
    let names: Vec<&str> = components.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["stVal", "q", "t"]);

    // An array keeps its element count.
    let TypeSpecification::Structure { components } = conn
        .get_variable_specification(&format!("{LD}/GGIO1.Hst"), FC::St)
        .await
        .expect("Hst attributes")
    else {
        panic!("a data object is a structure");
    };
    assert!(matches!(
        &components[0].type_spec,
        TypeSpecification::Array {
            element_count: 3,
            ..
        }
    ));

    // A GOOSE control block has the nine attributes of IEC 61850-8-1.
    let TypeSpecification::Structure { components } = conn
        .get_variable_specification(&format!("{LD}/LLN0.gcbStatus"), FC::Go)
        .await
        .expect("GoCB attributes")
    else {
        panic!("a GoCB is a structure");
    };
    let names: Vec<&str> = components.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "GoEna",
            "GoID",
            "DatSet",
            "ConfRev",
            "NdsCom",
            "DstAddress",
            "MinTime",
            "MaxTime",
            "FixedOffs"
        ]
    );
}

/// A read under each functional constraint the model uses, and of one array
/// element.
async fn reads(conn: &IedConnection) {
    for (reference, fc) in [
        ("GGIO1.Ind1", FC::St),
        ("GGIO1.AnIn1", FC::Mx),
        ("GGIO1.SPCSO1", FC::Cf),
        ("GGIO1.SPCSO1", FC::Co),
        ("GGIO1.Lim", FC::Sp),
        ("LLN0.NamPlt", FC::Dc),
        ("PTOC1.OpDlTmms", FC::Sg),
        ("LLN0.urcbSt01", FC::Rp),
        ("LLN0.brcbSt", FC::Br),
        ("LLN0.gcbStatus", FC::Go),
        ("LLN0.lcbLog", FC::Lg),
        ("LLN0.SGCB", FC::Sp),
    ] {
        let value = conn
            .read_object(&format!("{LD}/{reference}"), fc)
            .await
            .unwrap_or_else(|e| panic!("read {reference} [{fc:?}]: {e:?}"));
        assert!(
            matches!(value, MmsValue::Structure(_)),
            "{reference} [{fc:?}] is read whole: {value:?}"
        );
    }
    assert_eq!(
        conn.read_object(&format!("{LD}/GGIO1.Hst.hstVal(1)"), FC::St)
            .await
            .expect("read an array element"),
        MmsValue::Integer(5)
    );
    assert_eq!(
        conn.read_object(&format!("{LD}/GGIO1.SPCSO2.ctlModel"), FC::Cf)
            .await
            .expect("read ctlModel"),
        MmsValue::Integer(2),
        "the control model of the SCL"
    );
}

/// A whole data object and one attribute are written; a value outside the
/// range of the attribute is refused.
async fn writes(conn: &IedConnection) {
    let lim = format!("{LD}/GGIO1.Lim");
    conn.write_object(
        &lim,
        FC::Sp,
        MmsValue::Structure(vec![MmsValue::Integer(5), MmsValue::Integer(9)]),
    )
    .await
    .expect("write a data object");
    assert_eq!(
        conn.read_object(&lim, FC::Sp).await.expect("read back"),
        MmsValue::Structure(vec![MmsValue::Integer(5), MmsValue::Integer(9)])
    );
    conn.write_object(&format!("{lim}.lo"), FC::Sp, MmsValue::Integer(7))
        .await
        .expect("write an attribute");
    assert_eq!(
        conn.write_object(&format!("{lim}.hi"), FC::Sp, MmsValue::Integer(300))
            .await,
        Err(ClientError::DataAccessError(
            DataAccessError::ObjectValueInvalid
        )),
        "an INT8 does not take 300"
    );
    assert_eq!(
        conn.read_object(&lim, FC::Sp).await.expect("read back"),
        MmsValue::Structure(vec![MmsValue::Integer(7), MmsValue::Integer(9)])
    );
}

/// The configured data sets list their members, a data set with a data
/// object, a constructed attribute and a data attribute is created, read and
/// deleted, and a configured data set cannot be deleted.
async fn data_sets(conn: &IedConnection) {
    let status = conn
        .get_data_set_directory(&format!("{LD}/LLN0.dsStatus"))
        .await
        .expect("dsStatus directory");
    assert!(!status.deletable);
    assert_eq!(status.members.len(), 2);
    let values = conn
        .get_data_set_values(&format!("{LD}/LLN0.dsStatus"))
        .await
        .expect("dsStatus values");
    assert_eq!(values.len(), 2);
    assert!(
        values.iter().all(|r| matches!(r, AccessResult::Success(_))),
        "{values:?}"
    );

    let dynamic = format!("{LD}/LLN0.dsDyn");
    conn.create_data_set(
        &dynamic,
        &[
            DataSetMember::new(format!("{LD}/GGIO1.Ind3"), FC::St),
            DataSetMember::new(format!("{LD}/GGIO1.AnIn1.mag"), FC::Mx),
            DataSetMember::new(format!("{LD}/GGIO1.Lim.lo"), FC::Sp),
        ],
    )
    .await
    .expect("create a data set");
    let directory = conn
        .get_data_set_directory(&dynamic)
        .await
        .expect("dsDyn directory");
    assert!(directory.deletable);
    assert_eq!(directory.members.len(), 3);
    let values = conn
        .get_data_set_values(&dynamic)
        .await
        .expect("dsDyn values");
    assert_eq!(values.len(), 3);
    assert_eq!(
        values[2],
        AccessResult::Success(iec61850_mms::MmsData::Integer(7))
    );
    assert_eq!(conn.delete_data_set(&dynamic).await, Ok(true));
    assert_eq!(
        conn.delete_data_set(&format!("{LD}/LLN0.dsStatus")).await,
        Ok(false),
        "a configured data set is not deleted"
    );
    assert_eq!(
        conn.get_logical_node_directory(&format!("{LD}/LLN0"), AcsiClass::DataSet)
            .await
            .map(|names| names.contains(&"dsStatus".to_string())),
        Ok(true)
    );
}

fn operator() -> OriginValue {
    OriginValue {
        or_cat: 3,
        or_ident: b"matrix".to_vec(),
    }
}

/// Each control model concludes a command, and a refused command carries its
/// LastApplError.
async fn controls(conn: &IedConnection) {
    let object = |name: &str, model| {
        let mut object = conn
            .create_control_object(&format!("{LD}/GGIO1.{name}"), model)
            .expect("control object");
        object.set_origin(operator());
        object
    };
    let on = MmsValue::Boolean(true);

    let direct = object("SPCSO1", ControlModel::DirectNormal);
    assert_eq!(
        direct.operate(on.clone()).await,
        Ok(ControlOutcome::Success)
    );

    let sbo = object("SPCSO2", ControlModel::SboNormal);
    assert_eq!(sbo.select().await, Ok(ControlOutcome::Success));
    assert_eq!(sbo.operate(on.clone()).await, Ok(ControlOutcome::Success));
    let unselected = sbo.operate(on.clone()).await.expect("operate");
    assert_eq!(
        unselected.add_cause(),
        Some(ControlAddCause::ObjectNotSelected),
        "an operate after the selection was used is refused: {unselected:?}"
    );

    let enhanced = object("SPCSO3", ControlModel::DirectEnhanced);
    assert_eq!(
        enhanced.operate(on.clone()).await,
        Ok(ControlOutcome::Success),
        "a positive command termination"
    );

    let sbo_enhanced = object("SPCSO4", ControlModel::SboEnhanced);
    assert_eq!(
        sbo_enhanced.select_with_value(on.clone()).await,
        Ok(ControlOutcome::Success)
    );
    assert_eq!(
        sbo_enhanced.operate(on.clone()).await,
        Ok(ControlOutcome::Success)
    );

    let refused = object("SPCSO5", ControlModel::DirectNormal);
    let outcome = refused.operate(on.clone()).await.expect("operate");
    let error = outcome
        .last_appl_error()
        .unwrap_or_else(|| panic!("a LastApplError: {outcome:?}"));
    assert_eq!(error.add_cause, ControlAddCause::BlockedByInterlocking);
    assert_eq!(error.ctl_obj, format!("{LD}/GGIO1$CO$SPCSO5$Oper"));
    assert_eq!(error.origin, operator());
    assert_eq!(outcome.add_cause(), Some(error.add_cause));
}

/// Both instances of an indexed URCB and a BRCB report a change of a data
/// attribute member and of a data object member, and not an update that
/// leaves a value as it was; a general interrogation reports every member; a
/// BRCB refuses PurgeBuf while enabled and resumes after the last entry a
/// client received; the updates of a locked data model go out as one report;
/// a disabled URCB stays reserved.
async fn reports(server: &IedServer, model: &IedModel, conn: &IedConnection) {
    let urcb1 = format!("{LD}/LLN0$RP$urcbSt01");
    let urcb2 = format!("{LD}/LLN0$RP$urcbSt02");
    let brcb = format!("{LD}/LLN0$BR$brcbSt");
    let first = subscribe(conn, &urcb1).await;
    let second = subscribe(conn, &urcb2).await;
    let buffered = subscribe(conn, &brcb).await;
    enable(conn, &urcb1, false).await;
    enable(conn, &urcb2, false).await;
    enable(conn, &brcb, false).await;

    // Enabling a URCB reserves it for the association.
    let read = conn.get_rcb_values(&urcb1).await.expect("read urcbSt01");
    assert!(read.rpt_ena() && read.resv(), "RptEna and Resv are set");

    let ind1 = attribute(model, "GGIO1.Ind1.stVal", FC::St);
    server.update_boolean(ind1, true).expect("update Ind1");
    for received in [&first, &second, &buffered] {
        let report = received.wait(conn, 1).await.remove(0);
        assert_eq!(report.included, vec![true, false]);
        assert_eq!(report.reasons[0], ReasonForInclusion::DATA_CHANGE);
        assert_eq!(report.data_set_values[0], Some(MmsValue::Boolean(true)));
    }

    // An update to the value already held raises no data change, so the next
    // report is that of the quality change beneath the data object member,
    // which reports the whole data object.
    server
        .update_boolean(ind1, true)
        .expect("update Ind1 to the same value");
    let q = attribute(model, "GGIO1.Ind2.q", FC::St);
    server
        .update_bit_string(q, &[0x40, 0x00], 3)
        .expect("update Ind2.q");
    let report = first.wait(conn, 2).await.remove(1);
    assert_eq!(report.included, vec![false, true]);
    assert_eq!(report.reasons[1], ReasonForInclusion::QUALITY_CHANGE);
    assert!(
        matches!(&report.data_set_values[1], Some(MmsValue::Structure(m)) if m.len() == 3),
        "{:?}",
        report.data_set_values[1]
    );
    let last_entry = buffered.wait(conn, 2).await[1]
        .entry_id
        .clone()
        .expect("a buffered report carries its EntryID");
    second.wait(conn, 2).await;

    conn.trigger_grefcb(&urcb1).await.expect("GI");
    let gi = first.wait(conn, 3).await.remove(2);
    assert_eq!(gi.included, vec![true, true]);
    assert!(gi.reasons.iter().all(|r| *r == ReasonForInclusion::GI));

    let mut purge = RcbHandle::new(&brcb).unwrap();
    purge.set_purge_buf(true);
    assert_eq!(
        conn.set_rcb_values(&purge, RcbWriteMask::PURGE_BUF, false)
            .await,
        Err(ClientError::DataAccessError(
            DataAccessError::TemporarilyUnavailable
        )),
        "PurgeBuf is refused while the BRCB is enabled"
    );

    // Disabled, the BRCB keeps buffering; enabled again after the last entry
    // received, it sends what it buffered meanwhile.
    let mut disable = RcbHandle::new(&brcb).unwrap();
    disable.set_rpt_ena(false);
    conn.set_rcb_values(&disable, RcbWriteMask::RPT_ENA, false)
        .await
        .expect("disable the BRCB");
    server.update_boolean(ind1, false).expect("update Ind1");
    first.wait(conn, 4).await;
    let mut resume = RcbHandle::new(&brcb).unwrap();
    resume.set_entry_id(Some(last_entry)).expect("EntryID");
    resume.set_rpt_ena(true);
    conn.set_rcb_values(
        &resume,
        RcbWriteMask::ENTRY_ID | RcbWriteMask::RPT_ENA,
        false,
    )
    .await
    .expect("resume the BRCB");
    let resumed = buffered.wait(conn, 3).await.remove(2);
    assert_eq!(resumed.included, vec![true, false]);
    assert_eq!(resumed.data_set_values[0], Some(MmsValue::Boolean(false)));

    {
        let _batch = server.lock_data_model().expect("lock the data model");
        server.update_boolean(ind1, true).expect("update Ind1");
        server
            .update_bit_string(q, &[0x00, 0x00], 3)
            .expect("update Ind2.q");
    }
    let batch = first.wait(conn, 5).await.remove(4);
    assert_eq!(batch.included, vec![true, true], "one report for the batch");
    assert_eq!(batch.reasons[0], ReasonForInclusion::DATA_CHANGE);
    assert_eq!(batch.reasons[1], ReasonForInclusion::QUALITY_CHANGE);

    for rcb in [&urcb1, &urcb2, &brcb] {
        let mut off = RcbHandle::new(rcb).unwrap();
        off.set_rpt_ena(false);
        conn.set_rcb_values(&off, RcbWriteMask::RPT_ENA, false)
            .await
            .expect("disable");
        conn.uninstall_report_handler(rcb).await.expect("uninstall");
    }
    let read = conn.get_rcb_values(&urcb1).await.expect("read urcbSt01");
    assert!(
        !read.rpt_ena() && read.resv(),
        "a disabled URCB stays reserved for the association"
    );
}

/// On an association with a PDU of 1024 octets, a general interrogation of a
/// URCB and of a BRCB whose data set does not fit one PDU arrives in segments
/// of one sequence number, numbered from zero, the last without
/// MoreSegmentsFollow, whose inclusions together cover every member once.
async fn segmented_reports(handle: &ServerHandle) {
    let small = connect(handle, Some(1024)).await;
    for rcb in [
        format!("{LD}/LLN0$RP$urcbBig"),
        format!("{LD}/LLN0$BR$brcbBig"),
    ] {
        let received = subscribe(&small, &rcb).await;
        enable(&small, &rcb, true).await;
        let deadline = Instant::now() + Duration::from_secs(10);
        let segments = loop {
            let seen = received.0.lock().unwrap().clone();
            if seen
                .last()
                .and_then(|r| r.segmentation)
                .is_some_and(|s| !s.more_segments_follow)
            {
                break seen;
            }
            assert!(
                Instant::now() < deadline,
                "{rcb}: no last segment among {} reports",
                seen.len()
            );
            small
                .poll_reports(Duration::from_millis(100))
                .await
                .expect("poll reports");
        };
        assert!(segments.len() >= 2, "{rcb}: {} segments", segments.len());
        let seq_num = segments[0].seq_num;
        let mut covered = [false; 3];
        for (i, segment) in segments.iter().enumerate() {
            let s = segment
                .segmentation
                .unwrap_or_else(|| panic!("{rcb}: segment {i} carries the segmentation"));
            assert_eq!(usize::from(s.sub_seq_num), i, "{rcb}");
            assert_eq!(s.more_segments_follow, i + 1 < segments.len(), "{rcb}");
            assert_eq!(segment.seq_num, seq_num, "{rcb}: one sequence number");
            for (m, included) in segment.included.iter().enumerate() {
                if *included {
                    assert!(!covered[m], "{rcb}: member {m} is sent once");
                    covered[m] = true;
                }
            }
        }
        assert_eq!(covered, [true; 3], "{rcb}: every member is sent");
        let mut off = RcbHandle::new(&rcb).unwrap();
        off.set_rpt_ena(false);
        small
            .set_rcb_values(&off, RcbWriteMask::RPT_ENA, false)
            .await
            .expect("disable");
    }
    small.disconnect().await.expect("release");
}

/// The GOOSE control block is read whole and written as a block; one write
/// disables an enabled block and changes its DatSet, another changes DatSet
/// and enables it.
async fn goose_control_block(conn: &IedConnection) {
    let gocb = format!("{LD}/LLN0$GO$gcbStatus");
    let values = conn.get_gocb_values(&gocb).await.expect("GoCB values");
    assert!(!values.go_ena);
    assert_eq!(values.go_id, "MxStatus");
    assert_eq!(values.dat_set, format!("{LD}/LLN0$dsStatus"));
    assert_eq!(values.conf_rev, 1);
    conn.set_gocb_values(&gocb, GoCBValuesWrite::new().with_go_ena(true))
        .await
        .expect("enable the GoCB");
    assert!(
        conn.get_gocb_values(&gocb)
            .await
            .expect("GoCB values")
            .go_ena
    );
    conn.set_gocb_values(
        &gocb,
        GoCBValuesWrite::new()
            .with_go_ena(false)
            .with_dat_set(format!("{LD}/LLN0$dsLog")),
    )
    .await
    .expect("disable the GoCB and change its DatSet");
    let values = conn.get_gocb_values(&gocb).await.expect("GoCB values");
    assert!(!values.go_ena);
    assert_eq!(values.dat_set, format!("{LD}/LLN0$dsLog"));
    assert_eq!(values.conf_rev, 2);
    // Enabling follows the DatSet write.
    conn.set_gocb_values(
        &gocb,
        GoCBValuesWrite::new()
            .with_dat_set(format!("{LD}/LLN0$dsStatus"))
            .with_go_ena(true),
    )
    .await
    .expect("restore the DatSet and enable");
    conn.set_gocb_values(&gocb, GoCBValuesWrite::new().with_go_ena(false))
        .await
        .expect("disable the GoCB");
}

/// A change of the logged member writes an entry the journal returns.
async fn log_and_journal(server: &IedServer, model: &IedModel, conn: &IedConnection) {
    let lcb = conn
        .read_object(&format!("{LD}/LLN0.lcbLog.LogEna"), FC::Lg)
        .await
        .expect("read LogEna");
    assert_eq!(lcb, MmsValue::Boolean(true));
    let ind3 = attribute(model, "GGIO1.Ind3.stVal", FC::St);
    server.update_boolean(ind3, true).expect("update Ind3");
    let entries = conn
        .query_journal_all(&format!("{LD}/LLN0$MxLog"), &JournalQuery::new())
        .await
        .expect("ReadJournal");
    assert_eq!(entries.len(), 1, "{entries:?}");
    let variables = &entries[0].variables;
    assert_eq!(variables.len(), 1, "{variables:?}");
    assert_eq!(variables[0].data_ref, format!("{LD}/GGIO1$ST$Ind3$stVal"));
    assert_eq!(variables[0].value, MmsValue::Boolean(true));
}

/// A setting group is edited, confirmed and activated, and the active group
/// then reads the edited value.
async fn setting_groups(conn: &IedConnection) {
    let sgcb = |attr: &str| format!("{LD}/LLN0.SGCB.{attr}");
    let set_val = format!("{LD}/PTOC1.OpDlTmms.setVal");
    assert_eq!(
        conn.read_object(&set_val, FC::Sg).await.expect("read SG"),
        MmsValue::Integer(100),
        "group 1 is active"
    );
    conn.write_object(&sgcb("EditSG"), FC::Sp, MmsValue::Unsigned(2))
        .await
        .expect("SelectEditSG");
    assert_eq!(
        conn.read_object(&set_val, FC::Se).await.expect("read SE"),
        MmsValue::Integer(200),
        "the edit buffer holds group 2"
    );
    conn.write_object(&set_val, FC::Se, MmsValue::Integer(250))
        .await
        .expect("SetEditSGValue");
    conn.write_object(&sgcb("CnfEdit"), FC::Sp, MmsValue::Boolean(true))
        .await
        .expect("ConfirmEditSGValues");
    conn.write_object(&sgcb("ActSG"), FC::Sp, MmsValue::Unsigned(2))
        .await
        .expect("SelectActiveSG");
    assert_eq!(
        conn.read_object(&sgcb("ActSG"), FC::Sp)
            .await
            .expect("ActSG"),
        MmsValue::Unsigned(2)
    );
    assert_eq!(
        conn.read_object(&set_val, FC::Sg).await.expect("read SG"),
        MmsValue::Integer(250)
    );
}

/// With the connection limit at three, a third association is accepted and a
/// fourth refused; the third is released and the second aborted, after which
/// the server holds the first alone, which still answers, and accepts a new
/// association in a freed slot.
async fn release_abort_and_refusal(
    server: &IedServer,
    handle: &ServerHandle,
    conn: &IedConnection,
) {
    let second = connect(handle, None).await;
    let third = connect(handle, None).await;
    let fourth = IedConnection::with_mms_client(
        MmsClientBuilder::new()
            .connect_timeout_ms(3_000)
            .request_timeout_ms(3_000)
            .build(),
    );
    assert!(
        fourth
            .connect("127.0.0.1", handle.bound_addr.port())
            .await
            .is_err(),
        "a fourth association is refused"
    );
    third.disconnect().await.expect("release");
    second.abort().await.expect("abort");
    assert!(!second.is_connected() && !third.is_connected());
    let deadline = Instant::now() + Duration::from_secs(10);
    while server.connection_count() != 1 {
        assert!(
            Instant::now() < deadline,
            "the server still holds {} associations",
            server.connection_count()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    conn.get_server_status(false)
        .await
        .expect("the first association still answers");
    let next = connect(handle, None).await;
    next.disconnect().await.expect("release");
    conn.disconnect().await.expect("release");
}

/// The same server behind TLS, which allows TLS 1.3 only: an association over
/// TLS runs the services, and a failed handshake names its kind: a server
/// certificate the client does not trust, a client limited to TLS 1.2 that
/// the server refuses with an alert, and a server that never answers.
#[cfg(feature = "tls")]
mod over_tls {
    use super::*;
    use iec61850_client::TlsFailureKind;
    use iec61850_tls::{TlsAcceptor, TlsConfigBuilder, TlsConnector, TlsVersion};
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    /// A CA certificate, and a server certificate for `localhost` it signed,
    /// PEM encoded.
    fn certificates() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).expect("ca certificate");
        let key = KeyPair::generate().expect("server key");
        let cert = CertificateParams::new(vec!["localhost".to_string()])
            .expect("server params")
            .signed_by(&key, &ca, &ca_key)
            .expect("server certificate");
        (
            ca.pem().into_bytes(),
            cert.pem().into_bytes(),
            key.serialize_pem().into_bytes(),
        )
    }

    fn connector(ca: &[u8], max_version: TlsVersion) -> TlsConnector {
        TlsConnector::new(
            TlsConfigBuilder::new()
                .add_ca_pem(ca)
                .expect("ca")
                .max_version(max_version)
                .build_client()
                .expect("client config"),
        )
    }

    /// The kind of a failed handshake; fails on any other outcome.
    async fn handshake_failure(
        conn: &IedConnection,
        addr: SocketAddr,
        connector: &TlsConnector,
    ) -> TlsFailureKind {
        let result = conn
            .connect_tls(
                addr,
                connector,
                "localhost".try_into().expect("server name"),
            )
            .await;
        assert!(!conn.is_connected());
        match result {
            Err(ClientError::TlsHandshake { kind, message, .. }) => {
                assert!(!message.is_empty(), "the TLS error is carried");
                kind
            }
            other => panic!("expected a failed TLS handshake, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_services_run_over_tls() {
        tokio::time::timeout(Duration::from_secs(60), async {
            let (ca, cert, key) = certificates();
            let model = build_model();
            let mut config = IedServerConfig::default();
            config.max_mms_connections = 3;
            let server = IedServer::builder()
                .model(Arc::clone(&model))
                .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
                .config(config)
                .with_tls(TlsAcceptor::new(
                    TlsConfigBuilder::new()
                        .with_cert_pem(&cert, &key)
                        .expect("server certificate")
                        .min_version(TlsVersion::Tls13)
                        .build_server()
                        .expect("server config"),
                ))
                .build()
                .expect("build the server");
            server.register_from_model().expect("register_from_model");
            let handle = server.start().await.expect("start");

            let conn = IedConnection::new();
            conn.connect_tls(
                handle.bound_addr,
                &connector(&ca, TlsVersion::Tls13),
                "localhost".try_into().expect("server name"),
            )
            .await
            .expect("connect over TLS");
            association(&conn).await;
            directories(&conn).await;
            reads(&conn).await;
            writes(&conn).await;

            let rcb = format!("{LD}/LLN0$RP$urcbSt01");
            let received = subscribe(&conn, &rcb).await;
            enable(&conn, &rcb, true).await;
            let gi = received.wait(&conn, 1).await.remove(0);
            assert_eq!(gi.included, vec![true, true]);
            conn.disconnect().await.expect("release");

            let (other_ca, _, _) = certificates();
            assert_eq!(
                handshake_failure(
                    &IedConnection::new(),
                    handle.bound_addr,
                    &connector(&other_ca, TlsVersion::Tls13),
                )
                .await,
                TlsFailureKind::Verification
            );
            assert_eq!(
                handshake_failure(
                    &IedConnection::new(),
                    handle.bound_addr,
                    &connector(&ca, TlsVersion::Tls12),
                )
                .await,
                TlsFailureKind::AlertReceived,
                "the server refuses TLS 1.2 with an alert"
            );

            handle.stop().await;
        })
        .await
        .expect("the TLS matrix finishes within 60 s");
    }

    /// Accepts one connection and runs `then` on it, holding it open after.
    async fn accept_once<F, Fut>(then: F) -> (SocketAddr, tokio::task::JoinHandle<()>)
    where
        F: FnOnce(tokio::net::TcpStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("address");
        let peer = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            then(socket).await;
        });
        (addr, peer)
    }

    /// A client whose connection establishment is bounded by 2 s.
    fn client_bounded_by_two_seconds() -> IedConnection {
        IedConnection::with_mms_client(
            MmsClientBuilder::new()
                .connect_timeout_ms(2_000)
                .request_timeout_ms(2_000)
                .build(),
        )
    }

    /// A handshake the server never answers ends at the connect deadline as a
    /// TLS failure of the timeout kind. The peer accepts and then neither
    /// reads nor writes, so only the deadline can end the handshake.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_unanswered_handshake_ends_at_the_connect_deadline() {
        let (ca, _, _) = certificates();
        let (addr, peer) = accept_once(|socket| async move {
            std::future::pending::<()>().await;
            drop(socket);
        })
        .await;
        let conn = client_bounded_by_two_seconds();
        let kind = tokio::time::timeout(
            Duration::from_secs(30),
            handshake_failure(&conn, addr, &connector(&ca, TlsVersion::Tls13)),
        )
        .await
        .expect("the connect ends");
        assert_eq!(kind, TlsFailureKind::Timeout);
        peer.abort();
    }

    /// A peer that completes the TLS handshake and never answers the COTP
    /// connection request ends the connect at the same deadline, as a connect
    /// timeout rather than a TLS failure. Only the deadline can end it; the
    /// handshake, which takes a small fraction of a second on loopback, has
    /// to complete within the deadline, so the deadline is ten seconds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_unanswered_cotp_request_over_tls_ends_at_the_connect_deadline() {
        let (ca, cert, key) = certificates();
        let acceptor = TlsAcceptor::new(
            TlsConfigBuilder::new()
                .with_cert_pem(&cert, &key)
                .expect("server certificate")
                .build_server()
                .expect("server config"),
        );
        let (addr, peer) = accept_once(move |socket| async move {
            let stream = acceptor.accept(socket).await.expect("TLS handshake");
            std::future::pending::<()>().await;
            drop(stream);
        })
        .await;
        let conn = IedConnection::with_mms_client(
            MmsClientBuilder::new()
                .connect_timeout_ms(10_000)
                .request_timeout_ms(10_000)
                .build(),
        );
        let result = tokio::time::timeout(
            Duration::from_secs(60),
            conn.connect_tls(
                addr,
                &connector(&ca, TlsVersion::Tls13),
                "localhost".try_into().expect("server name"),
            ),
        )
        .await
        .expect("the connect ends");
        assert!(
            matches!(
                result,
                Err(ClientError::ConnectTimeout {
                    after_ms: 10_000,
                    ..
                })
            ),
            "got {result:?}"
        );
        assert!(!conn.is_connected());
        peer.abort();
    }
}

/// A peer that accepts the TCP connection and never answers the COTP
/// connection request ends the connect at the connect deadline. Only the
/// deadline can end it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unanswered_cotp_request_ends_at_the_connect_deadline() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("address").port();
    let peer = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        std::future::pending::<()>().await;
        drop(socket);
    });
    let conn = IedConnection::with_mms_client(
        MmsClientBuilder::new()
            .connect_timeout_ms(2_000)
            .request_timeout_ms(2_000)
            .build(),
    );
    let result = tokio::time::timeout(Duration::from_secs(30), conn.connect("127.0.0.1", port))
        .await
        .expect("the connect ends");
    assert!(
        matches!(
            result,
            Err(ClientError::ConnectTimeout {
                after_ms: 2_000,
                ..
            })
        ),
        "got {result:?}"
    );
    assert!(!conn.is_connected());
    peer.abort();
}
