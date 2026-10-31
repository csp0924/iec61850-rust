//! `stSeld` kept by the server.
//!
//! IEC 61850-7-3 defines `stSeld` as the selected state of a controllable data
//! object. The server writes it on every change of the selection of a
//! select-before-operate object, through its update path: a select sets it,
//! and the end of an operate-once command and the select timeout clear it. A
//! data set member `stSeld` with `dchg` is reported on each change, and the
//! application's selection change handler still hears of each one.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use iec61850_client::mms_compat::mms_data_to_mms_value;
use iec61850_client::report::parse::{parse_report, ParsedReport};
use iec61850_mms::mms::client::{MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::common::ObjectName;
use iec61850_mms::mms::pdu::information_report::{decode_information_report, VariableAccessSpec};
use iec61850_mms::mms::MmsData;
use iec61850_model::cdc::{self, CdcOptions, ControlOptions};
use iec61850_model::{
    ControlModel, DataAttribute, DataAttributeType, DataObject, DoChild, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::control::{
    AlwaysSuccessOperateHandler, ControlAction, ControlHandler, SelectStateChangedHandler,
    SelectStateChangedReason,
};
use iec61850_server::{
    Dataset, DatasetEntry, IedServer, OptFlds, Rcb, ReportControl, ServerHandle, TriggerOptions,
};

const DOMAIN: &str = "ctlLD0";
const ST_SELD: &str = "GGIO1$ST$SPCSO2$stSeld";

/// `GGIO1.SPCSO2`, an SPC under normal-security select-before-operate with
/// `stSeld` and the select timeout `sbo_timeout_ms`.
fn build_model(sbo_timeout_ms: u64) -> Arc<IedModel> {
    let mut spc: DataObject = cdc::spc(
        "SPCSO2",
        CdcOptions::NONE,
        ControlOptions::NONE
            .with_model(ControlModel::SboNormal)
            .union(ControlOptions::ST_SELD),
    );
    spc.children.push(DoChild::Da(DataAttribute::new(
        "sboTimeout",
        FC::Cf,
        DataAttributeType::Int32U,
        TrgOps::NONE,
        MmsValue::Unsigned(sbo_timeout_ms),
    )));
    let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
    let ggio = LogicalNodeBuilder::new("", "GGIO", "1")
        .add_do(spc)
        .build()
        .expect("ggio");
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .add_ln(ggio)
        .build()
        .expect("ld");
    Arc::new(
        IedModelBuilder::new("ctl")
            .add_ld(ld)
            .expect("add_ld")
            .build()
            .expect("model"),
    )
}

/// Every change of the selection the application's handler hears of.
#[derive(Default)]
struct Changes(Mutex<Vec<(bool, SelectStateChangedReason)>>);

impl SelectStateChangedHandler for Changes {
    fn on_select_state_changed(
        &self,
        _action: &ControlAction,
        is_selected: bool,
        reason: SelectStateChangedReason,
    ) {
        self.0.lock().unwrap().push((is_selected, reason));
    }
}

struct Fixture {
    _server: IedServer,
    _handle: ServerHandle,
    client: MmsClient,
    changes: Arc<Changes>,
}

/// Starts the server with `SPCSO2` registered from the model, a control
/// handler that succeeds and a recording selection handler, and enables a URCB
/// over `stSeld` on the client's association.
async fn start(sbo_timeout_ms: u64) -> Fixture {
    let server = IedServer::builder()
        .model(build_model(sbo_timeout_ms))
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()
        .expect("server");
    let registry = server.control_objects();
    assert_eq!(registry.register_from_model(&server.model()), 1);
    let entry = registry
        .lookup(DOMAIN, "GGIO1", "SPCSO2")
        .expect("registered");
    let changes = Arc::new(Changes::default());
    entry.object.set_select_state_handler(changes.clone());
    registry.register(
        entry.with_operate(Arc::new(AlwaysSuccessOperateHandler) as Arc<dyn ControlHandler>),
    );

    let model = server.model();
    let st_seld = model
        .ld_by_domain(DOMAIN)
        .and_then(|ld| ld.ln_by_name("GGIO1"))
        .and_then(|ln| ln.do_by_name("SPCSO2"))
        .and_then(|d| match d.child_by_name("stSeld", Some(FC::St)) {
            Some(DoChild::Da(da)) => Some(Arc::clone(&da.value)),
            _ => None,
        })
        .expect("stSeld");
    let mut ds = Dataset::new("LLN0$dsSel");
    ds.push(DatasetEntry::new(format!("{DOMAIN}/{ST_SELD}"), st_seld));
    let rcb = Rcb::new("urcbSel", "LLN0$dsSel")
        .with_trg_ops(TriggerOptions::DATA_CHANGED)
        .with_opt_flds(OptFlds::DATA_REFERENCE);
    server
        .register_urcb(
            ReportControl::new(format!("{DOMAIN}/LLN0$RP$urcbSel"), rcb),
            ds,
        )
        .expect("register_urcb");

    let handle = server.start().await.expect("start");
    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    client
        .connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    for item in ["LLN0$RP$urcbSel$Resv", "LLN0$RP$urcbSel$RptEna"] {
        client
            .write(DOMAIN, item, MmsData::Boolean(true))
            .await
            .expect("enable the control block");
    }
    Fixture {
        _server: server,
        _handle: handle,
        client,
        changes,
    }
}

fn oper(ctl_num: u64) -> MmsData {
    MmsData::Structure(vec![
        MmsData::Boolean(true),
        MmsData::Structure(vec![
            MmsData::Integer(3),
            MmsData::OctetString(b"probe".to_vec()),
        ]),
        MmsData::Unsigned(ctl_num),
        MmsData::UtcTime([0; 8]),
        MmsData::Boolean(false),
        MmsData::BitString {
            padding: 6,
            data: vec![0],
        },
    ])
}

async fn select(c: &mut MmsClient) {
    match c.read(DOMAIN, "GGIO1$CO$SPCSO2$SBO").await {
        Ok(MmsData::VisibleString(s)) if !s.is_empty() => {}
        other => panic!("select refused: {other:?}"),
    }
}

async fn st_seld(c: &mut MmsClient) -> MmsData {
    c.read(DOMAIN, ST_SELD).await.expect("read stSeld")
}

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

/// Receives the next report of `stSeld` and returns its value; fails after
/// four seconds.
async fn next_st_seld_report(c: &mut MmsClient) -> MmsValue {
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
            assert_eq!(report.data_references, vec![format!("{DOMAIN}/{ST_SELD}")]);
            return report.data_values.into_iter().next().expect("a value");
        }
    }
}

/// A select sets `stSeld` and the end of the operate-once command clears it,
/// each change reported.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_select_sets_st_seld_and_the_operate_clears_it() {
    let mut f = start(30_000).await;
    assert_eq!(st_seld(&mut f.client).await, MmsData::Boolean(false));

    select(&mut f.client).await;
    assert_eq!(st_seld(&mut f.client).await, MmsData::Boolean(true));
    assert_eq!(
        next_st_seld_report(&mut f.client).await,
        MmsValue::Boolean(true)
    );

    f.client
        .write(DOMAIN, "GGIO1$CO$SPCSO2$Oper", oper(1))
        .await
        .expect("operate");
    assert_eq!(
        next_st_seld_report(&mut f.client).await,
        MmsValue::Boolean(false)
    );
    assert_eq!(st_seld(&mut f.client).await, MmsData::Boolean(false));
    assert_eq!(
        *f.changes.0.lock().unwrap(),
        vec![
            (true, SelectStateChangedReason::Selected),
            (false, SelectStateChangedReason::OperateDone),
        ],
        "the application's handler hears of every change"
    );
}

/// The select timeout clears `stSeld`, reported like any other change.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_select_timeout_clears_st_seld() {
    let mut f = start(50).await;
    select(&mut f.client).await;
    assert_eq!(
        next_st_seld_report(&mut f.client).await,
        MmsValue::Boolean(true)
    );
    assert_eq!(
        next_st_seld_report(&mut f.client).await,
        MmsValue::Boolean(false)
    );
    assert_eq!(st_seld(&mut f.client).await, MmsData::Boolean(false));
    assert_eq!(
        f.changes.0.lock().unwrap().last(),
        Some(&(false, SelectStateChangedReason::Timeout))
    );
}
