//! The values of every setting group, kept by the server, on the wire.
//!
//! An SCL model gives each setting one value per group (`<Val sGroup="n">`).
//! SelectActiveSG loads the values of the selected group into FC=SG,
//! SelectEditSG loads them into FC=SE, and ConfirmEditSGValues stores the
//! edited values into their group, so a group selected again reads what was
//! committed to it. Values the server loads go through its update path: a data
//! set member under FC=SG with `dchg` is reported when the active group changes
//! it.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use iec61850_client::mms_compat::mms_data_to_mms_value;
use iec61850_client::report::parse::{parse_report, ParsedReport};
use iec61850_mms::mms::client::{ClientError, MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::common::ObjectName;
use iec61850_mms::mms::pdu::information_report::{decode_information_report, VariableAccessSpec};
use iec61850_mms::mms::pdu::DataAccessError;
use iec61850_mms::mms::MmsData;
use iec61850_model::{DataAttribute, DoChild, IedModel, MmsValue, FC};
use iec61850_server::connection::ConnectionId;
use iec61850_server::{
    Dataset, DatasetEntry, IedServer, IedServerConfig, OptFlds, Rcb, ReportControl, ServerHandle,
    SettingGroupHandler, TriggerOptions, WriteAccessPolicies,
};

const DOMAIN: &str = "ProtLD0";

const PROT_SCL: &str = r#"<SCL>
  <IED name="Prot">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <SettingControl numOfSGs="3" actSG="1"/>
          </LN0>
          <LN lnClass="PTOC" inst="1" lnType="PTOC_T">
            <DOI name="OpDlTmms">
              <DAI name="setVal"><Val sGroup="1">100</Val><Val sGroup="2">200</Val><Val sGroup="3">500</Val></DAI>
            </DOI>
            <DOI name="StrVal">
              <SDI name="setMag"><DAI name="f"><Val sGroup="1">1.5</Val><Val sGroup="2">2.5</Val></DAI></SDI>
            </DOI>
          </LN>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="Mod" type="ENC_T"/></LNodeType>
    <LNodeType id="PTOC_T" lnClass="PTOC">
      <DO name="OpDlTmms" type="ING_SE_T"/>
      <DO name="StrVal" type="ASG_SE_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC"><DA name="stVal" fc="ST" bType="BOOLEAN"/></DOType>
    <DOType id="ING_SE_T" cdc="ING">
      <DA name="setVal" fc="SE" bType="INT32" dchg="true"/>
    </DOType>
    <DOType id="ASG_SE_T" cdc="ASG">
      <DA name="setMag" fc="SE" bType="Struct" type="AnVal_T"/>
    </DOType>
    <DAType id="AnVal_T"><BDA name="f" bType="FLOAT32"/></DAType>
  </DataTypeTemplates>
</SCL>"#;

const OP_DL_SG: &str = "PTOC1$SG$OpDlTmms$setVal";
const OP_DL_SE: &str = "PTOC1$SE$OpDlTmms$setVal";
const STR_VAL_SG: &str = "PTOC1$SG$StrVal$setMag$f";

fn build_model() -> Arc<IedModel> {
    let raw = iec61850_scl::parse_scl(PROT_SCL).expect("parse");
    Arc::new(
        raw.resolve()
            .expect("resolve")
            .build_model("Prot")
            .expect("build"),
    )
}

fn build_server() -> IedServer {
    let mut policies = WriteAccessPolicies::default();
    policies.set(FC::Sp, true);
    policies.set(FC::Se, true);
    let mut cfg = IedServerConfig::default();
    cfg.write_access_policies = policies;
    IedServer::builder()
        .model(build_model())
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

async fn read(c: &mut MmsClient, item: &str) -> MmsData {
    c.read(DOMAIN, item)
        .await
        .unwrap_or_else(|e| panic!("read {item}: {e:?}"))
}

async fn write(c: &mut MmsClient, item: &str, value: MmsData) -> Result<(), ClientError> {
    c.write(DOMAIN, item, value).await
}

async fn sgcb(c: &mut MmsClient, field: &str, value: u64) {
    write(
        c,
        &format!("LLN0$SP$SGCB${field}"),
        MmsData::Unsigned(value),
    )
    .await
    .unwrap_or_else(|e| panic!("{field}={value}: {e:?}"));
}

async fn commit(c: &mut MmsClient) {
    write(c, "LLN0$SP$SGCB$CnfEdit", MmsData::Boolean(true))
        .await
        .expect("CnfEdit");
}

fn setting_sg(model: &IedModel) -> &DataAttribute {
    let dobj = model
        .ld_by_domain(DOMAIN)
        .and_then(|ld| ld.ln_by_name("PTOC1"))
        .and_then(|ln| ln.do_by_name("OpDlTmms"))
        .expect("OpDlTmms");
    match dobj.child_by_name("setVal", Some(FC::Sg)) {
        Some(DoChild::Da(da)) => da,
        other => panic!("setVal under SG: {other:?}"),
    }
}

/// A group edited and committed while another group is active reads its
/// committed value once it is selected, and keeps it across later selections.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_committed_group_reads_its_values_once_selected() {
    let handle = build_server().start().await.expect("start");
    let mut c = connect(&handle).await;

    assert_eq!(read(&mut c, OP_DL_SG).await, MmsData::Integer(100));
    assert_eq!(read(&mut c, STR_VAL_SG).await, MmsData::Float32(1.5));

    sgcb(&mut c, "ActSG", 2).await;
    assert_eq!(read(&mut c, OP_DL_SG).await, MmsData::Integer(200));
    assert_eq!(read(&mut c, STR_VAL_SG).await, MmsData::Float32(2.5));

    sgcb(&mut c, "EditSG", 3).await;
    assert_eq!(read(&mut c, OP_DL_SE).await, MmsData::Integer(500));
    write(&mut c, OP_DL_SE, MmsData::Integer(777))
        .await
        .expect("SetEditSGValue");
    write(&mut c, "PTOC1$SE$StrVal$setMag$f", MmsData::Float32(12.5))
        .await
        .expect("SetEditSGValue on a structured setting");
    commit(&mut c).await;
    assert_eq!(
        read(&mut c, OP_DL_SG).await,
        MmsData::Integer(200),
        "group 3 is not active"
    );

    sgcb(&mut c, "ActSG", 3).await;
    assert_eq!(read(&mut c, OP_DL_SG).await, MmsData::Integer(777));
    assert_eq!(read(&mut c, STR_VAL_SG).await, MmsData::Float32(12.5));

    sgcb(&mut c, "ActSG", 1).await;
    assert_eq!(read(&mut c, OP_DL_SG).await, MmsData::Integer(100));
    sgcb(&mut c, "ActSG", 3).await;
    assert_eq!(read(&mut c, OP_DL_SG).await, MmsData::Integer(777));

    sgcb(&mut c, "EditSG", 3).await;
    assert_eq!(read(&mut c, OP_DL_SE).await, MmsData::Integer(777));
    sgcb(&mut c, "EditSG", 0).await;
    handle.stop().await;
}

/// Committing the active group changes FC=SG at once; an edit that is
/// cancelled changes no group.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_commit_of_the_active_group_takes_effect_and_a_cancel_does_not() {
    let handle = build_server().start().await.expect("start");
    let mut c = connect(&handle).await;

    sgcb(&mut c, "EditSG", 1).await;
    write(&mut c, OP_DL_SE, MmsData::Integer(150))
        .await
        .expect("SetEditSGValue");
    assert_eq!(read(&mut c, OP_DL_SG).await, MmsData::Integer(100));
    commit(&mut c).await;
    assert_eq!(read(&mut c, OP_DL_SG).await, MmsData::Integer(150));

    sgcb(&mut c, "EditSG", 2).await;
    write(&mut c, OP_DL_SE, MmsData::Integer(250))
        .await
        .expect("SetEditSGValue");
    sgcb(&mut c, "EditSG", 0).await;
    sgcb(&mut c, "ActSG", 2).await;
    assert_eq!(read(&mut c, OP_DL_SG).await, MmsData::Integer(200));
    handle.stop().await;
}

/// Selects group 2 while the commit of group 1 is under way, as another
/// association can between the check of the commit and its completion.
struct SwitchDuringCommit(OnceLock<IedServer>);

impl SettingGroupHandler for SwitchDuringCommit {
    fn confirm_edit_sg(&self, _edit_sg: u8, _conn_id: ConnectionId) -> bool {
        let server = self.0.get().expect("server");
        server
            .force_active_setting_group(DOMAIN, 2)
            .expect("select group 2");
        true
    }
}

/// The edited values reach FC=SG only when their group is still active once
/// the commit completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_commit_does_not_load_a_group_that_is_no_longer_active() {
    let server = build_server();
    let handler = Arc::new(SwitchDuringCommit(OnceLock::new()));
    assert!(handler.0.set(server.clone()).is_ok());
    server
        .register_setting_group_handler(DOMAIN, handler)
        .expect("handler");
    let handle = server.start().await.expect("start");
    let mut c = connect(&handle).await;

    sgcb(&mut c, "EditSG", 1).await;
    write(&mut c, OP_DL_SE, MmsData::Integer(150))
        .await
        .expect("SetEditSGValue");
    commit(&mut c).await;
    assert_eq!(
        read(&mut c, OP_DL_SG).await,
        MmsData::Integer(200),
        "group 2 became active during the commit"
    );
    sgcb(&mut c, "ActSG", 1).await;
    assert_eq!(read(&mut c, OP_DL_SG).await, MmsData::Integer(150));
    handle.stop().await;
}

/// A commit the handler refuses answers object-access-denied and leaves the
/// group and the edit session as they were.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_commit_the_handler_refuses_changes_nothing() {
    struct Refuse;
    impl SettingGroupHandler for Refuse {
        fn confirm_edit_sg(&self, _edit_sg: u8, _conn_id: ConnectionId) -> bool {
            false
        }
    }
    let server = build_server();
    server
        .register_setting_group_handler(DOMAIN, Arc::new(Refuse))
        .expect("handler");
    let handle = server.start().await.expect("start");
    let mut c = connect(&handle).await;

    sgcb(&mut c, "EditSG", 1).await;
    write(&mut c, OP_DL_SE, MmsData::Integer(150))
        .await
        .expect("SetEditSGValue");
    match write(&mut c, "LLN0$SP$SGCB$CnfEdit", MmsData::Boolean(true)).await {
        Err(ClientError::DataAccessError(DataAccessError::ObjectAccessDenied)) => {}
        other => panic!("expected object-access-denied, got {other:?}"),
    }
    assert_eq!(read(&mut c, OP_DL_SG).await, MmsData::Integer(100));
    assert_eq!(
        read(&mut c, "LLN0$SP$SGCB$EditSG").await,
        MmsData::Unsigned(1),
        "the edit session stays open"
    );
    handle.stop().await;
}

// ── Reports of the values the server loads ──────────────────────────────────

/// Decodes an InformationReport, given the bytes after the outer
/// unconfirmed-PDU tag and length; `None` for a report other than `RPT`.
fn parse_information_report(inner: &[u8]) -> Option<ParsedReport> {
    let report = decode_information_report(inner).expect("decode information report");
    let is_rpt = matches!(
        &report.variable_access_spec,
        VariableAccessSpec::VariableListName(ObjectName::VmdSpecific(s)) if s == "RPT"
    );
    if !is_rpt {
        return None;
    }
    let elements: Vec<MmsValue> = report
        .list_of_access_result
        .iter()
        .map(mms_data_to_mms_value)
        .collect();
    Some(parse_report(&MmsValue::Array(elements)).expect("parse report"))
}

/// Receives the next report; fails after four seconds.
async fn next_report(c: &mut MmsClient) -> ParsedReport {
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
        if let Some(report) = parse_information_report(&inner) {
            return report;
        }
    }
}

/// A data set member under FC=SG with `dchg` is reported when SelectActiveSG
/// changes it and when a commit of the active group does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_values_the_server_loads_trigger_reports() {
    let server = build_server();
    let model = server.model();
    let sg = setting_sg(&model);
    let mut ds = Dataset::new("LLN0$dsSettings");
    ds.push(DatasetEntry::new(
        format!("{DOMAIN}/{OP_DL_SG}"),
        Arc::clone(&sg.value),
    ));
    let rcb = Rcb::new("urcbSettings", "LLN0$dsSettings")
        .with_trg_ops(TriggerOptions::DATA_CHANGED)
        .with_opt_flds(OptFlds::DATA_REFERENCE);
    server
        .register_urcb(
            ReportControl::new(format!("{DOMAIN}/LLN0$RP$urcbSettings"), rcb),
            ds,
        )
        .expect("register_urcb");
    let handle = server.start().await.expect("start");
    let mut c = connect(&handle).await;
    for item in ["LLN0$RP$urcbSettings$Resv", "LLN0$RP$urcbSettings$RptEna"] {
        write(&mut c, item, MmsData::Boolean(true))
            .await
            .expect("enable the control block");
    }

    sgcb(&mut c, "ActSG", 2).await;
    let report = next_report(&mut c).await;
    assert_eq!(report.data_values, vec![MmsValue::Integer(200)]);
    assert_eq!(report.data_references, vec![format!("{DOMAIN}/{OP_DL_SG}")]);

    sgcb(&mut c, "EditSG", 2).await;
    write(&mut c, OP_DL_SE, MmsData::Integer(222))
        .await
        .expect("SetEditSGValue");
    commit(&mut c).await;
    let report = next_report(&mut c).await;
    assert_eq!(report.data_values, vec![MmsValue::Integer(222)]);
    handle.stop().await;
}

/// The application keeps no group values of its own: a handler that only
/// records the calls sees every operation, and the values come from the
/// server.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_handler_sees_each_operation_without_storing_values() {
    #[derive(Default)]
    struct Record(Mutex<Vec<(&'static str, u8)>>);
    impl SettingGroupHandler for Record {
        fn act_sg_changed(&self, sg: u8, _: ConnectionId) -> bool {
            self.0.lock().unwrap().push(("act", sg));
            true
        }
        fn edit_sg_changed(&self, sg: u8, _: ConnectionId) -> bool {
            self.0.lock().unwrap().push(("edit", sg));
            true
        }
        fn confirm_edit_sg(&self, sg: u8, _: ConnectionId) -> bool {
            self.0.lock().unwrap().push(("confirm", sg));
            true
        }
    }
    let server = build_server();
    let record = Arc::new(Record::default());
    server
        .register_setting_group_handler(DOMAIN, record.clone())
        .expect("handler");
    let handle = server.start().await.expect("start");
    let mut c = connect(&handle).await;

    sgcb(&mut c, "EditSG", 2).await;
    write(&mut c, OP_DL_SE, MmsData::Integer(201))
        .await
        .expect("SetEditSGValue");
    commit(&mut c).await;
    sgcb(&mut c, "ActSG", 2).await;
    assert_eq!(read(&mut c, OP_DL_SG).await, MmsData::Integer(201));
    assert_eq!(
        *record.0.lock().unwrap(),
        vec![("edit", 2), ("confirm", 2), ("act", 2)]
    );
    handle.stop().await;
}

/// SelectActiveSG while the application holds the data model lock completes,
/// and the group's values are in FC=SG once the lock is released.
#[test]
fn a_selection_under_the_data_model_lock_completes() {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let server = build_server();
        let outcome = {
            let _guard = server.lock_data_model().expect("lock");
            server.force_active_setting_group(DOMAIN, 2)
        };
        let model = server.model();
        let _ = tx.send((outcome.is_ok(), setting_sg(&model).snapshot()));
    });
    let (selected, value) = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the selection completes under the lock");
    assert!(selected);
    assert_eq!(value, MmsValue::Integer(200));
}
