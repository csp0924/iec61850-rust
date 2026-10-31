//! Control blocks registered from the model in one call.
//!
//! `IedServer::register_from_model` registers what an SCL file declares: the
//! data sets, every instance of each report control block (`EventsRCB01` and
//! `EventsRCB02` for `<RptEnabled max="2">`), the GOOSE and log control
//! blocks and the control objects. A client then lists, reads and enables them
//! as if the application had registered each one by hand.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use iec61850_client::IedConnection;
use iec61850_mms::mms::client::{ClientError, MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::common::ObjectName;
use iec61850_mms::mms::pdu::get_name_list::ObjectClass;
use iec61850_mms::mms::pdu::information_report::{decode_information_report, VariableAccessSpec};
use iec61850_mms::mms::pdu::DataAccessError;
use iec61850_mms::mms::MmsData;
use iec61850_model::{DoChild, IedModel, FC};
use iec61850_server::control::{
    AlwaysSuccessOperateHandler, ControlHandler, ControlObject, ControlObjectConfig,
    ControlObjectEntry,
};
use iec61850_server::{
    Dataset, FromModelSummary, IedServer, IedServerConfig, ServerError, ServerHandle,
};

const DOMAIN: &str = "FmLD0";

const FM_SCL: &str = r#"<SCL>
  <IED name="Fm">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <DataSet name="Events">
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind2" fc="ST"/>
            </DataSet>
            <ReportControl name="EventsRCB" datSet="Events" rptID="Events" confRev="2">
              <TrgOps dchg="true" gi="true"/>
              <OptFields seqNum="true" dataSet="true" reasonCode="true"/>
              <RptEnabled max="2"/>
            </ReportControl>
            <ReportControl name="EventsBRCB" datSet="Events" buffered="true" indexed="false" confRev="1">
              <TrgOps dchg="true"/>
              <RptEnabled max="1"/>
            </ReportControl>
            <LogControl name="EventLog" datSet="Events" logName="EventLog">
              <TrgOps dchg="true"/>
            </LogControl>
            <GSEControl name="gcbEvents" datSet="Events" appID="FmEvents" confRev="3"/>
            <SettingControl numOfSGs="2" actSG="1"/>
          </LN0>
          <LN lnClass="GGIO" inst="1" lnType="GGIO_T">
            <DOI name="SPCSO1"><DAI name="ctlModel"><Val>direct-with-normal-security</Val></DAI></DOI>
          </LN>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="Mod" type="ENC_T"/></LNodeType>
    <LNodeType id="GGIO_T" lnClass="GGIO">
      <DO name="Ind1" type="SPS_T"/>
      <DO name="Ind2" type="SPS_T"/>
      <DO name="SPCSO1" type="SPC_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC"><DA name="stVal" fc="ST" bType="BOOLEAN"/></DOType>
    <DOType id="SPS_T" cdc="SPS">
      <DA name="stVal" fc="ST" bType="BOOLEAN" dchg="true"/>
      <DA name="q" fc="ST" bType="Quality" qchg="true"/>
      <DA name="t" fc="ST" bType="Timestamp"/>
    </DOType>
    <DOType id="SPC_T" cdc="SPC">
      <DA name="stVal" fc="ST" bType="BOOLEAN" dchg="true"/>
      <DA name="ctlModel" fc="CF" bType="Enum" type="CtlModelKind"/>
    </DOType>
    <EnumType id="CtlModelKind">
      <EnumVal ord="0">status-only</EnumVal>
      <EnumVal ord="1">direct-with-normal-security</EnumVal>
      <EnumVal ord="2">sbo-with-normal-security</EnumVal>
      <EnumVal ord="3">direct-with-enhanced-security</EnumVal>
      <EnumVal ord="4">sbo-with-enhanced-security</EnumVal>
    </EnumType>
  </DataTypeTemplates>
</SCL>"#;

fn build_model() -> Arc<IedModel> {
    build_model_from(FM_SCL)
}

fn build_model_from(scl: &str) -> Arc<IedModel> {
    let raw = iec61850_scl::parse_scl(scl).expect("parse");
    Arc::new(
        raw.resolve()
            .expect("resolve")
            .build_model("Fm")
            .expect("build"),
    )
}

/// `FM_SCL` with `extra` added to LLN0 after the data set.
fn fm_scl_with(extra: &str) -> String {
    let anchor = "            </DataSet>\n";
    assert!(FM_SCL.contains(anchor));
    FM_SCL.replacen(anchor, &format!("{anchor}{extra}\n"), 1)
}

fn build_server(model: Arc<IedModel>) -> IedServer {
    let mut cfg = IedServerConfig::default();
    cfg.max_mms_connections = 4;
    IedServer::builder()
        .model(model)
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(cfg)
        .build()
        .expect("build server")
}

async fn connect(handle: &ServerHandle) -> MmsClient {
    let mut c = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    c.connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    c
}

async fn names(c: &mut MmsClient, class: ObjectClass) -> Vec<String> {
    let mut all = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let (page, more) = c
            .get_name_list(class, Some(DOMAIN), after.as_deref())
            .await
            .expect("get_name_list");
        after = page.last().cloned();
        all.extend(page);
        if !more {
            return all;
        }
    }
}

async fn enable(c: &mut MmsClient, rcb: &str) -> Result<(), ClientError> {
    c.write(DOMAIN, &format!("{rcb}$Resv"), MmsData::Boolean(true))
        .await?;
    c.write(DOMAIN, &format!("{rcb}$RptEna"), MmsData::Boolean(true))
        .await
}

/// Receives the next report and returns its RptID; fails after four seconds.
async fn next_rpt_id(c: &mut MmsClient) -> String {
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "no report arrived");
        let Some(inner) = c
            .recv_unconfirmed_pdu_with_timeout(remaining)
            .await
            .expect("receive")
        else {
            continue;
        };
        let report = decode_information_report(&inner).expect("decode information report");
        let is_rpt = matches!(
            &report.variable_access_spec,
            VariableAccessSpec::VariableListName(ObjectName::VmdSpecific(s)) if s == "RPT"
        );
        if !is_rpt {
            continue;
        }
        match report.list_of_access_result.first() {
            Some(MmsData::VisibleString(id)) => return id.clone(),
            other => panic!("a report starts with its RptID, got {other:?}"),
        }
    }
}

fn ind1_st_val(model: &IedModel) -> &iec61850_model::DataAttribute {
    let dobj = model
        .ld_by_domain(DOMAIN)
        .and_then(|ld| ld.ln_by_name("GGIO1"))
        .and_then(|ln| ln.do_by_name("Ind1"))
        .expect("Ind1");
    match dobj.child_by_name("stVal", Some(FC::St)) {
        Some(DoChild::Da(da)) => da,
        other => panic!("stVal: {other:?}"),
    }
}

/// Everything the SCL file declares is registered, with the counts of the
/// model, and the server serves each control block under its name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_declared_control_block_is_served() {
    let server = build_server(build_model());
    let summary = server.register_from_model().expect("register_from_model");
    let mut expected = FromModelSummary::default();
    expected.data_sets = 1;
    expected.urcbs = 2;
    expected.brcbs = 1;
    expected.gocbs = 1;
    expected.lcbs = 1;
    expected.sgcbs = 1;
    expected.control_objects = 1;
    assert_eq!(summary, expected);

    let handle = server.start().await.expect("start");
    let mut a = connect(&handle).await;
    let variables = names(&mut a, ObjectClass::NamedVariable).await;
    for name in [
        "LLN0$RP$EventsRCB01",
        "LLN0$RP$EventsRCB02",
        "LLN0$BR$EventsBRCB",
        "LLN0$GO$gcbEvents",
        "LLN0$LG$EventLog",
    ] {
        assert!(
            variables.iter().any(|n| n == name),
            "{name} in {variables:?}"
        );
    }
    assert!(
        !variables.iter().any(|n| n == "LLN0$RP$EventsRCB"),
        "an indexed block has no instance without a suffix: {variables:?}"
    );
    let lists = names(&mut a, ObjectClass::NamedVariableList).await;
    assert_eq!(lists, vec!["LLN0$Events".to_string()]);

    // The client reads the instance by its indexed name, with the settings of
    // the model.
    let conn = IedConnection::with_mms_client(
        MmsClientBuilder::new()
            .connect_timeout_ms(3_000)
            .request_timeout_ms(3_000)
            .build(),
    );
    conn.connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    let rcb = conn
        .get_rcb_values(&format!("{DOMAIN}/LLN0$RP$EventsRCB01"))
        .await
        .expect("GetURCBValues");
    assert_eq!(rcb.rpt_id(), Some("Events"));
    assert_eq!(rcb.conf_rev(), 2);
    assert!(rcb
        .data_set_reference()
        .is_some_and(|ds| ds.ends_with("LLN0$Events")));
    let brcb = conn
        .get_rcb_values(&format!("{DOMAIN}/LLN0$BR$EventsBRCB"))
        .await
        .expect("GetBRCBValues");
    assert_eq!(
        brcb.rpt_id(),
        Some(format!("{DOMAIN}/LLN0$BR$EventsBRCB").as_str())
    );

    let gocb = conn
        .get_gocb_values(&format!("{DOMAIN}/LLN0$GO$gcbEvents"))
        .await
        .expect("GetGoCBValues");
    assert_eq!(gocb.go_id, "FmEvents");
    assert_eq!(gocb.dat_set, format!("{DOMAIN}/LLN0$Events"));
    assert_eq!(gocb.conf_rev, 3);
    assert!(!gocb.go_ena);

    assert_eq!(
        a.read(DOMAIN, "LLN0$LG$EventLog$LogEna")
            .await
            .expect("LogEna"),
        MmsData::Boolean(true)
    );
    assert_eq!(
        a.read(DOMAIN, "LLN0$LG$EventLog$LogRef")
            .await
            .expect("LogRef"),
        MmsData::VisibleString(format!("{DOMAIN}/LLN0$EventLog"))
    );
    handle.stop().await;
}

/// The two instances of an indexed block are independent: each client
/// reserves and enables its own, a reserved one refuses the other client, and
/// a change of a member is reported on both.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_instance_is_reserved_and_reports_on_its_own() {
    let server = build_server(build_model());
    server.register_from_model().expect("register_from_model");
    let handle = server.start().await.expect("start");
    let mut a = connect(&handle).await;
    let mut b = connect(&handle).await;

    enable(&mut a, "LLN0$RP$EventsRCB01")
        .await
        .expect("client A enables instance 01");
    match b
        .write(DOMAIN, "LLN0$RP$EventsRCB01$Resv", MmsData::Boolean(true))
        .await
    {
        Err(ClientError::DataAccessError(DataAccessError::TemporarilyUnavailable)) => {}
        other => panic!("instance 01 is reserved by client A, got {other:?}"),
    }
    enable(&mut b, "LLN0$RP$EventsRCB02")
        .await
        .expect("client B enables instance 02");

    let model = server.model();
    server
        .update_boolean(ind1_st_val(&model), true)
        .expect("update");
    assert_eq!(next_rpt_id(&mut a).await, "Events");
    assert_eq!(next_rpt_id(&mut b).await, "Events");
    handle.stop().await;
}

/// A data set already registered under a name the model uses makes the call
/// fail before anything is registered; a second call fails the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_name_already_registered_fails_the_whole_call() {
    let server = build_server(build_model());
    server.register_dataset(DOMAIN, Dataset::new("LLN0$Events"));
    match server.register_from_model() {
        Err(ServerError::AlreadyRegistered { reference }) => {
            assert_eq!(reference, format!("{DOMAIN}/LLN0$Events"))
        }
        other => panic!("expected AlreadyRegistered, got {other:?}"),
    }
    assert!(server
        .reporting_engine()
        .lock()
        .unwrap()
        .rcb_paths()
        .is_empty());
    assert!(server.gocb_registry().is_empty());
    assert!(server.log_controls().read().unwrap().is_empty());
    assert!(server.control_objects().is_empty());

    let server = build_server(build_model());
    server.register_from_model().expect("first call");
    match server.register_from_model() {
        Err(ServerError::AlreadyRegistered { reference }) => {
            assert_eq!(reference, format!("{DOMAIN}/LLN0$Events"))
        }
        other => panic!("expected AlreadyRegistered, got {other:?}"),
    }
}

/// A control object registered before the call keeps its handler.
#[test]
fn a_control_object_registered_by_hand_is_kept() {
    let server = build_server(build_model());
    let registry = server.control_objects();
    let object = ControlObject::new(ControlObjectConfig::new(
        "SPCSO1",
        "GGIO1",
        DOMAIN,
        iec61850_server::control::ControlModel::DirectNormal,
    ));
    registry.register(
        ControlObjectEntry::new(object)
            .with_operate(Arc::new(AlwaysSuccessOperateHandler) as Arc<dyn ControlHandler>),
    );
    let summary = server.register_from_model().expect("register_from_model");
    assert_eq!(summary.control_objects, 0);
    let entry = registry.lookup(DOMAIN, "GGIO1", "SPCSO1").expect("kept");
    assert!(entry.operate_handler.is_some());
}

/// The sample configuration of this crate registers what it declares: an
/// unbuffered and a buffered block, each `indexed="false"` and so one
/// instance, its two data sets, its GOOSE control block and its control
/// object.
#[test]
fn the_sample_configuration_registers_what_it_declares() {
    let xml = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/models/demo.cid"
    ))
    .expect("demo.cid");
    let model = iec61850_scl::parse_scl(&xml)
        .expect("parse")
        .resolve()
        .expect("resolve")
        .build_model("DemoIED")
        .expect("build");
    let server = build_server(Arc::new(model));
    let summary = server.register_from_model().expect("register_from_model");
    let mut expected = FromModelSummary::default();
    expected.data_sets = 2;
    expected.urcbs = 1;
    expected.brcbs = 1;
    expected.gocbs = 1;
    expected.control_objects = 1;
    assert_eq!(summary, expected);
    let engine = server.reporting_engine();
    let g = engine.lock().unwrap();
    assert_eq!(g.rcb_paths(), vec!["DemoIEDLD0/LLN0$RP$urcbMeas"]);
    assert_eq!(g.brcb_paths(), vec!["DemoIEDLD0/LLN0$BR$brcbMeas"]);
}

/// A report control block that names no data set registers none: the data
/// set names list no empty name, its `DatSet` reads empty, and a client that
/// reserves it and writes a data set to it enables it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_report_control_block_without_a_data_set_registers_none() {
    let scl = fm_scl_with(
        r#"            <ReportControl name="NoDs" rptID="NoDs" indexed="false"><TrgOps dchg="true"/></ReportControl>"#,
    );
    let server = build_server(build_model_from(&scl));
    let summary = server.register_from_model().expect("register_from_model");
    assert_eq!(summary.urcbs, 3);
    assert_eq!(summary.data_sets, 1);
    let handle = server.start().await.expect("start");
    let mut c = connect(&handle).await;

    let lists = names(&mut c, ObjectClass::NamedVariableList).await;
    assert_eq!(lists, vec!["LLN0$Events".to_string()]);
    assert_eq!(
        c.read(DOMAIN, "LLN0$RP$NoDs$DatSet").await.expect("DatSet"),
        MmsData::VisibleString(String::new())
    );
    c.write(DOMAIN, "LLN0$RP$NoDs$Resv", MmsData::Boolean(true))
        .await
        .expect("reserve");
    c.write(
        DOMAIN,
        "LLN0$RP$NoDs$DatSet",
        MmsData::VisibleString(format!("{DOMAIN}/LLN0$Events")),
    )
    .await
    .expect("write DatSet");
    c.write(DOMAIN, "LLN0$RP$NoDs$RptEna", MmsData::Boolean(true))
        .await
        .expect("enable once a data set is set");
    handle.stop().await;
}

/// Two report control block instances of the model with one name, here the
/// first instance of the indexed `EventsRCB` and a block named `EventsRCB01`,
/// fail the call before anything is registered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_instances_with_one_name_fail_the_call() {
    let scl = fm_scl_with(
        r#"            <ReportControl name="EventsRCB01" datSet="Events" indexed="false" confRev="7"/>"#,
    );
    let server = build_server(build_model_from(&scl));
    match server.register_from_model() {
        Err(ServerError::InvalidModel(why)) => {
            assert!(why.contains("LLN0$RP$EventsRCB01"), "{why}")
        }
        other => panic!("expected InvalidModel, got {other:?}"),
    }
    assert!(server
        .reporting_engine()
        .lock()
        .unwrap()
        .rcb_paths()
        .is_empty());
    assert!(server.gocb_registry().is_empty());
    let handle = server.start().await.expect("start");
    let mut c = connect(&handle).await;
    assert!(names(&mut c, ObjectClass::NamedVariableList)
        .await
        .is_empty());
    handle.stop().await;
}
