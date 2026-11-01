//! Control services over the wire: real TCP and the full ISO stack between the
//! server and the MMS client.
//!
//! The model declares four SPC objects, one per control model, so a write is
//! checked against the declared `Oper`, `SBOw`, and `Cancel` types. Waits are
//! driven by events; a timeout only bounds a wait whose event never comes.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use iec61850_mms::mms::client::connection::MmsConnection;
use iec61850_mms::mms::client::invoke_id::InvokeIdAllocator;
use iec61850_mms::mms::client::services::write_variable;
use iec61850_mms::mms::client::{ClientError, MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::common::VariableAccessSpecification;
use iec61850_mms::mms::pdu::common::{DataAccessError, MmsData, ObjectName};
use iec61850_mms::mms::pdu::information_report::{decode_information_report, VariableAccessSpec};
use iec61850_mms::mms::pdu::write::{encode_confirmed_write_request, WriteRequest};
use iec61850_mms::mms::pdu::MmsPdu;
use iec61850_model::cdc::{self, CdcOptions, ControlOptions};
use iec61850_model::{
    ControlModel, IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue,
};
use iec61850_server::control::handler::{OperateFuture, WaitForExecFuture};
use iec61850_server::control::{
    AlwaysAcceptCheckHandler, AlwaysFailOperateHandler, AlwaysSuccessOperateHandler, CheckHandler,
    ControlAction, ControlAddCause, ControlHandler, ControlObject, ControlObjectConfig,
    ControlObjectEntry, ControlState, SelectStateChangedHandler, SelectStateChangedReason,
    WaitForExecutionHandler,
};
use iec61850_server::{IedServer, IedServerConfig, ServerHandle};
use tokio::sync::Notify;

const DOMAIN: &str = "simpleIOGenericIO";
const WAIT: Duration = Duration::from_secs(5);

// ── Model and server ────────────────────────────────────────────────────────

fn build_model() -> Arc<IedModel> {
    let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
    let mut ggio = LogicalNodeBuilder::new("", "GGIO", "1");
    for (name, model) in [
        ("SPCSO1", ControlModel::DirectNormal),
        ("SPCSO2", ControlModel::SboNormal),
        ("SPCSO3", ControlModel::DirectEnhanced),
        ("SPCSO4", ControlModel::SboEnhanced),
        ("SPCSO5", ControlModel::DirectEnhanced),
    ] {
        let mut opts = ControlOptions::NONE
            .with_model(model)
            .union(ControlOptions::HAS_CANCEL);
        if name == "SPCSO5" {
            opts = opts.union(ControlOptions::IS_TIME_ACTIVATED);
        }
        ggio = ggio.add_do(cdc::spc(name, CdcOptions::NONE, opts));
    }
    let ld = LogicalDeviceBuilder::new("GenericIO")
        .add_ln(lln0)
        .add_ln(ggio.build().expect("ggio"))
        .build()
        .expect("ld");
    Arc::new(
        IedModelBuilder::new("simpleIO")
            .add_ld(ld)
            .expect("add_ld")
            .build()
            .expect("model"),
    )
}

fn server() -> IedServer {
    IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config({
            let mut config = IedServerConfig::default();
            config.max_mms_connections = 4;
            config
        })
        .build()
        .expect("server")
}

fn object(name: &str, ctl_model: ControlModel) -> ControlObject {
    ControlObject::new(ControlObjectConfig::new(name, "GGIO1", DOMAIN, ctl_model))
}

fn register(server: &IedServer, obj: ControlObject, op: Arc<dyn ControlHandler>) {
    server.control_objects().register(
        ControlObjectEntry::new(obj)
            .with_check(Arc::new(AlwaysAcceptCheckHandler) as Arc<dyn CheckHandler>)
            .with_operate(op),
    );
}

async fn start(server: &IedServer) -> ServerHandle {
    server.start().await.expect("start")
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

// ── Values ──────────────────────────────────────────────────────────────────

fn origin() -> MmsData {
    MmsData::Structure(vec![
        MmsData::Integer(3),
        MmsData::OctetString(b"probe".to_vec()),
    ])
}

fn check_bits() -> MmsData {
    MmsData::BitString {
        padding: 6,
        data: vec![0],
    }
}

fn oper(ctl_val: MmsData, ctl_num: u64) -> MmsData {
    MmsData::Structure(vec![
        ctl_val,
        origin(),
        MmsData::Unsigned(ctl_num),
        MmsData::UtcTime([0; 8]),
        MmsData::Boolean(false),
        check_bits(),
    ])
}

fn cancel(ctl_num: u64) -> MmsData {
    MmsData::Structure(vec![
        MmsData::Boolean(true),
        origin(),
        MmsData::Unsigned(ctl_num),
        MmsData::UtcTime([0; 8]),
        MmsData::Boolean(false),
    ])
}

fn on() -> MmsData {
    MmsData::Boolean(true)
}

// ── Reports ─────────────────────────────────────────────────────────────────

/// An InformationReport: its variable names and values.
type Report = (Vec<ObjectName>, Vec<MmsData>);

/// Returns the next InformationReport, waiting at most `wait`.
async fn next_report(c: &mut MmsClient, wait: Duration) -> Option<Report> {
    let inner = c.recv_unconfirmed_pdu_with_timeout(wait).await.ok()??;
    let r = decode_information_report(&inner).expect("information report");
    let names = match r.variable_access_spec {
        VariableAccessSpec::ListOfVariable(n) => n,
        other => panic!("unexpected variable access specification {other:?}"),
    };
    Some((names, r.list_of_access_result))
}

/// Returns the report already queued by the client, without waiting.
async fn queued_report(c: &mut MmsClient) -> Option<Report> {
    next_report(c, Duration::ZERO).await
}

fn is_last_appl_error(name: &ObjectName) -> bool {
    matches!(name, ObjectName::VmdSpecific(s) if s == "LastApplError")
}

/// Asserts a report carrying only LastApplError and returns its five members.
fn last_appl_error_only(report: Option<Report>) -> Vec<MmsData> {
    let (names, values) = report.expect("a LastApplError report");
    assert!(
        names.len() == 1 && is_last_appl_error(&names[0]),
        "expected a report of LastApplError alone, got {names:?}"
    );
    match values.into_iter().next() {
        Some(MmsData::Structure(members)) => {
            assert_eq!(members.len(), 5, "LastApplError has five members");
            members
        }
        other => panic!("LastApplError is not a structure: {other:?}"),
    }
}

fn assert_last_appl_error(members: &[MmsData], cntrl_obj: &str, ctl_num: u64, add_cause: i64) {
    assert_eq!(members[0], MmsData::VisibleString(cntrl_obj.to_string()));
    assert_eq!(members[1], MmsData::Integer(0), "Error is No Error");
    assert_eq!(members[2], origin(), "origin echoes the command");
    assert_eq!(
        members[3],
        MmsData::Unsigned(ctl_num),
        "ctlNum echoes the command"
    );
    assert_eq!(members[4], MmsData::Integer(add_cause), "AddCause");
}

fn denied(r: Result<(), ClientError>) -> DataAccessError {
    match r {
        Err(ClientError::DataAccessError(e)) => e,
        other => panic!("expected a data access error, got {other:?}"),
    }
}

// ── Handlers ────────────────────────────────────────────────────────────────

/// Control handler that signals entry and finishes when released.
struct Gate {
    entered: Arc<Notify>,
    release: Arc<Notify>,
    result: Result<(), ControlAddCause>,
}

impl ControlHandler for Gate {
    fn operate<'a>(
        &'a self,
        _a: &'a ControlAction,
        _v: &'a MmsValue,
        _t: bool,
    ) -> OperateFuture<'a> {
        let entered = self.entered.clone();
        let release = self.release.clone();
        let result = self.result;
        Box::pin(async move {
            entered.notify_one();
            release.notified().await;
            result
        })
    }
}

/// Control handler that records every control value it receives and signals
/// each run.
struct Recorder(Arc<Mutex<Vec<MmsValue>>>, Arc<Notify>);

impl Recorder {
    fn new(seen: &Arc<Mutex<Vec<MmsValue>>>) -> Self {
        Self(seen.clone(), Arc::new(Notify::new()))
    }
}

impl ControlHandler for Recorder {
    fn operate<'a>(
        &'a self,
        _a: &'a ControlAction,
        v: &'a MmsValue,
        _t: bool,
    ) -> OperateFuture<'a> {
        self.0.lock().unwrap().push(v.clone());
        self.1.notify_one();
        Box::pin(async { Ok(()) })
    }
}

/// Dynamic check that signals entry and finishes with `result` when released.
struct GatedCheck {
    entered: Arc<Notify>,
    release: Arc<Notify>,
    result: Result<(), ControlAddCause>,
}

impl GatedCheck {
    /// A check that finishes with `result` as soon as it is entered.
    fn open(result: Result<(), ControlAddCause>) -> Self {
        let release = Arc::new(Notify::new());
        release.notify_one();
        Self {
            entered: Arc::new(Notify::new()),
            release,
            result,
        }
    }
}

impl WaitForExecutionHandler for GatedCheck {
    fn wait_for_execution<'a>(
        &'a self,
        _a: &'a ControlAction,
        _v: &'a MmsValue,
        _t: bool,
        _s: bool,
    ) -> WaitForExecFuture<'a> {
        let entered = self.entered.clone();
        let release = self.release.clone();
        let result = self.result;
        Box::pin(async move {
            entered.notify_one();
            release.notified().await;
            result
        })
    }
}

/// Control handler that never finishes.
struct NeverDone;

impl ControlHandler for NeverDone {
    fn operate<'a>(
        &'a self,
        _a: &'a ControlAction,
        _v: &'a MmsValue,
        _t: bool,
    ) -> OperateFuture<'a> {
        Box::pin(std::future::pending())
    }
}

// ── LastApplError before a negative response ────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_normal_operate_sends_last_appl_error_before_the_response() {
    let s = server();
    register(
        &s,
        object("SPCSO2", ControlModel::SboNormal),
        Arc::new(AlwaysSuccessOperateHandler),
    );
    let h = start(&s).await;
    let mut a = connect(&h).await;

    let r = a.write(DOMAIN, "GGIO1$CO$SPCSO2$Oper", oper(on(), 1)).await;
    assert_eq!(denied(r), DataAccessError::ObjectAccessDenied);
    // The report arrived ahead of the response, so it is already queued.
    let lae = last_appl_error_only(queued_report(&mut a).await);
    assert_last_appl_error(&lae, &format!("{DOMAIN}/GGIO1$CO$SPCSO2$Oper"), 1, 18);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_enhanced_operate_sends_last_appl_error_and_no_command_termination() {
    let s = server();
    register(
        &s,
        object("SPCSO4", ControlModel::SboEnhanced),
        Arc::new(AlwaysSuccessOperateHandler),
    );
    let h = start(&s).await;
    let mut a = connect(&h).await;

    let r = a.write(DOMAIN, "GGIO1$CO$SPCSO4$Oper", oper(on(), 2)).await;
    assert_eq!(denied(r), DataAccessError::ObjectAccessDenied);
    let lae = last_appl_error_only(queued_report(&mut a).await);
    assert_last_appl_error(&lae, &format!("{DOMAIN}/GGIO1$CO$SPCSO4$Oper"), 2, 18);

    // A command termination would be served ahead of the next request, so by
    // the time this read is answered it would be queued.
    a.read(DOMAIN, "GGIO1$ST$SPCSO4$stVal").await.expect("read");
    assert_eq!(
        queued_report(&mut a).await,
        None,
        "a refused Operate has no CommandTermination"
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_sbow_and_cancel_of_another_client_send_last_appl_error() {
    let s = server();
    let obj = object("SPCSO4", ControlModel::SboEnhanced);
    register(&s, obj.clone(), Arc::new(AlwaysSuccessOperateHandler));
    let h = start(&s).await;
    let mut a = connect(&h).await;
    let mut b = connect(&h).await;

    a.write(DOMAIN, "GGIO1$CO$SPCSO4$SBOw", oper(on(), 9))
        .await
        .expect("A selects");

    let r = b
        .write(DOMAIN, "GGIO1$CO$SPCSO4$SBOw", oper(on(), 10))
        .await;
    assert_eq!(denied(r), DataAccessError::TemporarilyUnavailable);
    let lae = last_appl_error_only(queued_report(&mut b).await);
    assert_last_appl_error(&lae, &format!("{DOMAIN}/GGIO1$CO$SPCSO4$SBOw"), 10, 19);

    let r = b.write(DOMAIN, "GGIO1$CO$SPCSO4$Cancel", cancel(11)).await;
    assert_eq!(denied(r), DataAccessError::TemporarilyUnavailable);
    let lae = last_appl_error_only(queued_report(&mut b).await);
    assert_last_appl_error(&lae, &format!("{DOMAIN}/GGIO1$CO$SPCSO4$Cancel"), 11, 27);

    assert_eq!(
        obj.state(),
        ControlState::Ready,
        "A still holds the selection"
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sbow_on_a_selected_object_reports_object_already_selected() {
    let s = server();
    register(
        &s,
        object("SPCSO4", ControlModel::SboEnhanced),
        Arc::new(AlwaysSuccessOperateHandler),
    );
    let h = start(&s).await;
    let mut a = connect(&h).await;

    a.write(DOMAIN, "GGIO1$CO$SPCSO4$SBOw", oper(on(), 1))
        .await
        .expect("select");
    let r = a.write(DOMAIN, "GGIO1$CO$SPCSO4$SBOw", oper(on(), 2)).await;
    assert_eq!(denied(r), DataAccessError::TemporarilyUnavailable);
    let lae = last_appl_error_only(queued_report(&mut a).await);
    assert_last_appl_error(&lae, &format!("{DOMAIN}/GGIO1$CO$SPCSO4$SBOw"), 2, 19);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_select_by_the_same_client_is_refused() {
    let s = server();
    let obj = object("SPCSO2", ControlModel::SboNormal);
    register(&s, obj.clone(), Arc::new(AlwaysSuccessOperateHandler));
    let h = start(&s).await;
    let mut a = connect(&h).await;

    let sel = a.read(DOMAIN, "GGIO1$CO$SPCSO2$SBO").await.expect("select");
    assert_eq!(
        sel,
        MmsData::VisibleString(format!("{DOMAIN}/GGIO1$CO$SPCSO2"))
    );
    // A refused select answers an empty string, IEC 61850-8-1 Table 95.
    let again = a.read(DOMAIN, "GGIO1$CO$SPCSO2$SBO").await.expect("read");
    assert_eq!(again, MmsData::VisibleString(String::new()));
    assert_eq!(obj.state(), ControlState::Ready, "the selection is kept");
    a.write(DOMAIN, "GGIO1$CO$SPCSO2$Oper", oper(on(), 1))
        .await
        .expect("operate under the first selection");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepted_requests_send_no_last_appl_error() {
    let s = server();
    let obj = object("SPCSO2", ControlModel::SboNormal);
    let mut changes = observe(&obj);
    register(&s, obj.clone(), Arc::new(AlwaysSuccessOperateHandler));
    let h = start(&s).await;
    let mut a = connect(&h).await;

    let sel = a.read(DOMAIN, "GGIO1$CO$SPCSO2$SBO").await.expect("select");
    assert_eq!(
        sel,
        MmsData::VisibleString(format!("{DOMAIN}/GGIO1$CO$SPCSO2"))
    );
    a.write(DOMAIN, "GGIO1$CO$SPCSO2$Oper", oper(on(), 1))
        .await
        .expect("operate");
    assert_eq!(queued_report(&mut a).await, None);
    // The command runs on its own task after the response.
    assert_eq!(
        next_change(&mut changes).await,
        SelectStateChangedReason::Selected
    );
    assert_eq!(
        next_change(&mut changes).await,
        SelectStateChangedReason::OperateDone
    );
    assert_eq!(obj.state(), ControlState::Unselected);
    h.stop().await;
}

// ── Execution off the dispatch path ─────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enhanced_execution_failure_answers_positively_then_terminates_negatively() {
    let s = server();
    register(
        &s,
        object("SPCSO3", ControlModel::DirectEnhanced),
        Arc::new(AlwaysFailOperateHandler {
            cause: ControlAddCause::BlockedByProcess,
        }),
    );
    let h = start(&s).await;
    let mut a = connect(&h).await;

    let r = a
        .write(DOMAIN, "GGIO1$CO$SPCSO3$Oper", oper(on(), 42))
        .await;
    assert!(
        r.is_ok(),
        "an accepted command is answered positively, got {r:?}"
    );
    let (names, values) = next_report(&mut a, WAIT).await.expect("CommandTermination");
    assert_eq!(
        names.len(),
        2,
        "a negative termination names LastApplError and Oper"
    );
    assert!(is_last_appl_error(&names[0]));
    assert_eq!(
        names[1],
        ObjectName::DomainSpecific {
            domain_id: DOMAIN.into(),
            item_id: "GGIO1$CO$SPCSO3$Oper".into()
        }
    );
    let MmsData::Structure(lae) = &values[0] else {
        panic!("LastApplError is not a structure")
    };
    assert_last_appl_error(lae, &format!("{DOMAIN}/GGIO1$CO$SPCSO3$Oper"), 42, 9);
    assert_eq!(values[1], oper(on(), 42), "the termination echoes the Oper");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enhanced_operate_is_answered_while_the_command_executes() {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let s = server();
    let obj = object("SPCSO3", ControlModel::DirectEnhanced);
    register(
        &s,
        obj.clone(),
        Arc::new(Gate {
            entered: entered.clone(),
            release: release.clone(),
            result: Ok(()),
        }),
    );
    let h = start(&s).await;
    let mut a = connect(&h).await;

    // The handler is not released until after the response, so a response held
    // until the end of execution never arrives and the request times out.
    let r = a.write(DOMAIN, "GGIO1$CO$SPCSO3$Oper", oper(on(), 5)).await;
    if r.is_err() {
        // Lets a command that held the response finish, so the server can stop.
        release.notify_one();
    }
    assert!(
        r.is_ok(),
        "no Operate response while the command executes: {r:?}"
    );
    entered.notified().await;
    assert_eq!(obj.state(), ControlState::Operate);

    // The association keeps serving requests meanwhile; a Cancel cannot stop an
    // executing command.
    a.read(DOMAIN, "GGIO1$ST$SPCSO3$stVal").await.expect("read");
    let r = a.write(DOMAIN, "GGIO1$CO$SPCSO3$Cancel", cancel(5)).await;
    assert_eq!(denied(r), DataAccessError::TemporarilyUnavailable);
    let lae = last_appl_error_only(queued_report(&mut a).await);
    assert_last_appl_error(&lae, &format!("{DOMAIN}/GGIO1$CO$SPCSO3$Cancel"), 5, 12);

    release.notify_one();
    let (names, _) = next_report(&mut a, WAIT).await.expect("CommandTermination");
    assert_eq!(names.len(), 1, "a positive termination names Oper alone");
    assert_eq!(obj.state(), ControlState::Unselected);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operate_with_a_dynamic_check_is_answered_by_its_outcome() {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let s = server();
    s.control_objects().register(
        ControlObjectEntry::new(object("SPCSO1", ControlModel::DirectNormal))
            .with_wait(Arc::new(GatedCheck {
                entered: entered.clone(),
                release: release.clone(),
                result: Err(ControlAddCause::BlockedBySynchrocheck),
            }) as Arc<dyn WaitForExecutionHandler>)
            .with_operate(Arc::new(AlwaysSuccessOperateHandler) as Arc<dyn ControlHandler>),
    );
    let h = start(&s).await;
    let mut a = connect(&h).await;

    // The check finishes only after it has been entered, so the response cannot
    // precede it.
    let releaser = tokio::spawn(async move {
        entered.notified().await;
        release.notify_one();
    });
    let r = a.write(DOMAIN, "GGIO1$CO$SPCSO1$Oper", oper(on(), 7)).await;
    releaser.await.expect("releaser");
    assert_eq!(denied(r), DataAccessError::ObjectAccessDenied);
    let lae = last_appl_error_only(queued_report(&mut a).await);
    assert_last_appl_error(&lae, &format!("{DOMAIN}/GGIO1$CO$SPCSO1$Oper"), 7, 11);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enhanced_operate_refused_by_the_dynamic_check_has_no_command_termination() {
    let s = server();
    let obj = object("SPCSO3", ControlModel::DirectEnhanced);
    s.control_objects().register(
        ControlObjectEntry::new(obj.clone())
            .with_wait(Arc::new(GatedCheck::open(Err(
                ControlAddCause::BlockedBySynchrocheck,
            ))) as Arc<dyn WaitForExecutionHandler>)
            .with_operate(Arc::new(AlwaysSuccessOperateHandler) as Arc<dyn ControlHandler>),
    );
    let h = start(&s).await;
    let mut a = connect(&h).await;

    let r = a.write(DOMAIN, "GGIO1$CO$SPCSO3$Oper", oper(on(), 8)).await;
    assert_eq!(denied(r), DataAccessError::ObjectAccessDenied);
    let lae = last_appl_error_only(queued_report(&mut a).await);
    assert_last_appl_error(&lae, &format!("{DOMAIN}/GGIO1$CO$SPCSO3$Oper"), 8, 11);
    a.read(DOMAIN, "GGIO1$ST$SPCSO3$stVal").await.expect("read");
    assert_eq!(
        queued_report(&mut a).await,
        None,
        "a refused Operate has no CommandTermination"
    );
    assert_eq!(obj.state(), ControlState::Unselected);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enhanced_operate_passing_the_dynamic_check_is_answered_then_terminated() {
    let s = server();
    s.control_objects().register(
        ControlObjectEntry::new(object("SPCSO3", ControlModel::DirectEnhanced))
            .with_wait(Arc::new(GatedCheck::open(Ok(()))) as Arc<dyn WaitForExecutionHandler>)
            .with_operate(Arc::new(AlwaysSuccessOperateHandler) as Arc<dyn ControlHandler>),
    );
    let h = start(&s).await;
    let mut a = connect(&h).await;

    a.write(DOMAIN, "GGIO1$CO$SPCSO3$Oper", oper(on(), 9))
        .await
        .expect("answered positively");
    let (names, values) = next_report(&mut a, WAIT).await.expect("CommandTermination");
    assert_eq!(names.len(), 1, "a positive termination names Oper alone");
    assert_eq!(values[0], oper(on(), 9));
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn normal_operate_failing_after_a_positive_response_is_not_reported() {
    let s = server();
    register(
        &s,
        object("SPCSO1", ControlModel::DirectNormal),
        Arc::new(AlwaysFailOperateHandler {
            cause: ControlAddCause::BlockedByProcess,
        }),
    );
    let h = start(&s).await;
    let mut a = connect(&h).await;

    a.write(DOMAIN, "GGIO1$CO$SPCSO1$Oper", oper(on(), 6))
        .await
        .expect("normal security answers when the checks pass");
    a.read(DOMAIN, "GGIO1$ST$SPCSO1$stVal").await.expect("read");
    assert_eq!(queued_report(&mut a).await, None);
    h.stop().await;
}

#[tokio::test]
async fn operate_on_a_current_thread_runtime() {
    let s = server();
    register(
        &s,
        object("SPCSO1", ControlModel::DirectNormal),
        Arc::new(AlwaysSuccessOperateHandler),
    );
    register(
        &s,
        object("SPCSO3", ControlModel::DirectEnhanced),
        Arc::new(AlwaysSuccessOperateHandler),
    );
    let h = start(&s).await;
    let mut a = connect(&h).await;

    a.write(DOMAIN, "GGIO1$CO$SPCSO1$Oper", oper(on(), 1))
        .await
        .expect("direct-normal operate");
    a.write(DOMAIN, "GGIO1$CO$SPCSO3$Oper", oper(on(), 2))
        .await
        .expect("direct-enhanced operate");
    let (names, _) = next_report(&mut a, WAIT).await.expect("CommandTermination");
    assert_eq!(names.len(), 1);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oper_timeout_ends_the_command_with_time_limit_over() {
    let s = server();
    let obj = ControlObject::new({
        let mut config =
            ControlObjectConfig::new("SPCSO3", "GGIO1", DOMAIN, ControlModel::DirectEnhanced);
        config.oper_timeout_ms = 20;
        config
    });
    register(&s, obj.clone(), Arc::new(NeverDone));
    let h = start(&s).await;
    let mut a = connect(&h).await;

    a.write(DOMAIN, "GGIO1$CO$SPCSO3$Oper", oper(on(), 3))
        .await
        .expect("accepted");
    let (names, values) = next_report(&mut a, WAIT).await.expect("CommandTermination");
    assert_eq!(names.len(), 2, "the timeout ends in a negative termination");
    let MmsData::Structure(lae) = &values[0] else {
        panic!("LastApplError is not a structure")
    };
    assert_last_appl_error(lae, &format!("{DOMAIN}/GGIO1$CO$SPCSO3$Oper"), 3, 16);
    assert_eq!(obj.state(), ControlState::Unselected);
    h.stop().await;
}

/// A test command, its `Test` set, that outlasts the operate timeout ends with
/// the same negative termination, whose Error is Operator Test Not OK instead
/// of No Error (IEC 61850-8-1 §20.11).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oper_timeout_of_a_test_command_carries_operator_test_not_ok() {
    let s = server();
    let obj = ControlObject::new({
        let mut config =
            ControlObjectConfig::new("SPCSO3", "GGIO1", DOMAIN, ControlModel::DirectEnhanced);
        config.oper_timeout_ms = 20;
        config
    });
    register(&s, obj.clone(), Arc::new(NeverDone));
    let h = start(&s).await;
    let mut a = connect(&h).await;

    let MmsData::Structure(mut test_oper) = oper(on(), 4) else {
        unreachable!()
    };
    test_oper[4] = MmsData::Boolean(true);
    a.write(
        DOMAIN,
        "GGIO1$CO$SPCSO3$Oper",
        MmsData::Structure(test_oper),
    )
    .await
    .expect("accepted");
    let (names, values) = next_report(&mut a, WAIT).await.expect("CommandTermination");
    assert_eq!(names.len(), 2, "the timeout ends in a negative termination");
    let MmsData::Structure(lae) = &values[0] else {
        panic!("LastApplError is not a structure")
    };
    assert_eq!(
        lae[0],
        MmsData::VisibleString(format!("{DOMAIN}/GGIO1$CO$SPCSO3$Oper"))
    );
    assert_eq!(lae[1], MmsData::Integer(3), "Error is Operator Test Not OK");
    assert_eq!(lae[3], MmsData::Unsigned(4), "ctlNum echoes the command");
    assert_eq!(lae[4], MmsData::Integer(16), "AddCause is Time-limit-over");
    assert_eq!(obj.state(), ControlState::Unselected);
    h.stop().await;
}

// ── Type of the written value ───────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operate_with_a_ctl_val_of_the_wrong_type_is_type_inconsistent() {
    let seen: Arc<Mutex<Vec<MmsValue>>> = Arc::default();
    let recorder = Recorder::new(&seen);
    let ran = recorder.1.clone();
    let s = server();
    register(
        &s,
        object("SPCSO1", ControlModel::DirectNormal),
        Arc::new(recorder),
    );
    let h = start(&s).await;
    let mut a = connect(&h).await;

    // The ctlVal of an SPC is BOOLEAN.
    let r = a
        .write(DOMAIN, "GGIO1$CO$SPCSO1$Oper", oper(MmsData::Integer(5), 1))
        .await;
    assert_eq!(denied(r), DataAccessError::TypeInconsistent);
    let r = a
        .write(DOMAIN, "GGIO1$CO$SPCSO1$Oper", oper(on(), 300))
        .await;
    assert_eq!(
        denied(r),
        DataAccessError::TypeInconsistent,
        "ctlNum is INT8U"
    );
    let MmsData::Structure(mut short) = oper(on(), 1) else {
        unreachable!()
    };
    short.pop();
    let r = a
        .write(DOMAIN, "GGIO1$CO$SPCSO1$Oper", MmsData::Structure(short))
        .await;
    assert_eq!(
        denied(r),
        DataAccessError::TypeInconsistent,
        "Check is missing"
    );
    assert!(
        seen.lock().unwrap().is_empty(),
        "the handler saw an ill-typed command"
    );

    a.write(DOMAIN, "GGIO1$CO$SPCSO1$Oper", oper(on(), 1))
        .await
        .expect("a well-typed Oper");
    // The command runs on its own task after the response.
    tokio::time::timeout(WAIT, ran.notified())
        .await
        .expect("the control handler runs");
    assert_eq!(*seen.lock().unwrap(), vec![MmsValue::Boolean(true)]);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_cancel_is_type_inconsistent_and_keeps_the_selection() {
    let s = server();
    let obj = object("SPCSO4", ControlModel::SboEnhanced);
    register(&s, obj.clone(), Arc::new(AlwaysSuccessOperateHandler));
    let h = start(&s).await;
    let mut a = connect(&h).await;

    a.write(DOMAIN, "GGIO1$CO$SPCSO4$SBOw", oper(on(), 1))
        .await
        .expect("select");
    let bad = MmsData::Structure(vec![MmsData::Integer(1), MmsData::Boolean(true)]);
    let r = a.write(DOMAIN, "GGIO1$CO$SPCSO4$Cancel", bad).await;
    assert_eq!(denied(r), DataAccessError::TypeInconsistent);
    assert_eq!(
        obj.state(),
        ControlState::Ready,
        "a malformed Cancel cancels nothing"
    );

    a.write(DOMAIN, "GGIO1$CO$SPCSO4$Cancel", cancel(1))
        .await
        .expect("cancel");
    assert_eq!(obj.state(), ControlState::Unselected);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_object_the_model_does_not_declare_is_checked_against_the_service_structure() {
    let s = server();
    let obj = object("SPCSO9", ControlModel::SboEnhanced);
    register(&s, obj.clone(), Arc::new(AlwaysSuccessOperateHandler));
    let h = start(&s).await;
    let mut a = connect(&h).await;

    let r = a
        .write(DOMAIN, "GGIO1$CO$SPCSO9$SBOw", oper(on(), 300))
        .await;
    assert_eq!(
        denied(r),
        DataAccessError::TypeInconsistent,
        "ctlNum is INT8U"
    );
    a.write(DOMAIN, "GGIO1$CO$SPCSO9$SBOw", oper(on(), 1))
        .await
        .expect("select");
    let bad = MmsData::Structure(vec![MmsData::Integer(1), MmsData::Boolean(true)]);
    let r = a.write(DOMAIN, "GGIO1$CO$SPCSO9$Cancel", bad).await;
    assert_eq!(denied(r), DataAccessError::TypeInconsistent);
    assert_eq!(
        obj.state(),
        ControlState::Ready,
        "a malformed Cancel cancels nothing"
    );
    h.stop().await;
}

// ── An object without a control handler ────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn object_without_a_control_handler_refuses_operate_with_not_supported() {
    let s = server();
    s.control_objects().register(ControlObjectEntry::new(object(
        "SPCSO1",
        ControlModel::DirectNormal,
    )));
    let h = start(&s).await;
    let mut a = connect(&h).await;

    let r = a.write(DOMAIN, "GGIO1$CO$SPCSO1$Oper", oper(on(), 4)).await;
    assert_eq!(denied(r), DataAccessError::ObjectAccessDenied);
    let lae = last_appl_error_only(queued_report(&mut a).await);
    assert_last_appl_error(&lae, &format!("{DOMAIN}/GGIO1$CO$SPCSO1$Oper"), 4, 1);
    h.stop().await;
}

// ── Writes the client stack does not issue on its own ──────────────────────

/// Connects an MMS association without the request API, so a test can send a
/// PDU of its own and see exactly what arrived before each response.
async fn raw_connect(handle: &ServerHandle) -> MmsConnection {
    let mut conn: MmsConnection = MmsConnection::new();
    conn.connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    conn
}

/// Returns the content of a ConfirmedRequest PDU encoded by the PDU encoders,
/// which include the outer tag and length.
fn request_content(full: BytesMut) -> Bytes {
    let pdu = full.freeze();
    let start = if pdu[1] <= 0x7f {
        2
    } else {
        2 + (pdu[1] & 0x7f) as usize
    };
    pdu.slice(start..)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_enhanced_operate_in_a_multi_variable_write_is_terminated() {
    let s = server();
    s.control_objects().register(
        ControlObjectEntry::new(object("SPCSO3", ControlModel::DirectEnhanced))
            .with_wait(Arc::new(GatedCheck::open(Err(
                ControlAddCause::BlockedBySynchrocheck,
            ))) as Arc<dyn WaitForExecutionHandler>)
            .with_operate(Arc::new(AlwaysSuccessOperateHandler) as Arc<dyn ControlHandler>),
    );
    register(
        &s,
        object("SPCSO1", ControlModel::DirectNormal),
        Arc::new(AlwaysSuccessOperateHandler),
    );
    let h = start(&s).await;
    let mut conn = raw_connect(&h).await;

    let name = |item: &str| ObjectName::DomainSpecific {
        domain_id: DOMAIN.into(),
        item_id: item.into(),
    };
    let req = WriteRequest {
        variable_access_spec: VariableAccessSpecification::ListOfVariable(vec![
            name("GGIO1$CO$SPCSO3$Oper").into(),
            name("GGIO1$CO$SPCSO1$Oper").into(),
        ]),
        list_of_data: vec![oper(on(), 21), oper(on(), 22)],
    };
    let mut full = BytesMut::new();
    encode_confirmed_write_request(1, &req, &mut full);
    conn.send_mms_pdu(&MmsPdu::ConfirmedRequest(request_content(full)))
        .await
        .expect("send");

    // A write of two variables cannot wait for the dynamic check, so both
    // variables are answered positively.
    match conn.recv_mms_pdu_confirmed().await.expect("response") {
        MmsPdu::ConfirmedResponse(content) => assert!(
            content.ends_with(&[0xa5, 0x04, 0x81, 0x00, 0x81, 0x00]),
            "expected two successes, got {content:02x?}"
        ),
        other => panic!("expected a confirmed response, got {other:?}"),
    }
    // The refused enhanced command still ends its sequence, negatively.
    let inner = match conn.pop_pending_unconfirmed() {
        Some(inner) => inner,
        None => match conn
            .recv_mms_pdu_with_timeout(Some(WAIT))
            .await
            .expect("receive")
        {
            Some(MmsPdu::Unconfirmed(inner)) => inner,
            other => panic!("expected a CommandTermination, got {other:?}"),
        },
    };
    let report = decode_information_report(&inner).expect("information report");
    let VariableAccessSpec::ListOfVariable(names) = report.variable_access_spec else {
        panic!("unexpected variable access specification")
    };
    assert_eq!(
        names.len(),
        2,
        "a negative termination names LastApplError and Oper"
    );
    assert!(is_last_appl_error(&names[0]));
    let MmsData::Structure(lae) = &report.list_of_access_result[0] else {
        panic!("LastApplError is not a structure")
    };
    assert_last_appl_error(lae, &format!("{DOMAIN}/GGIO1$CO$SPCSO3$Oper"), 21, 11);
    h.stop().await;
}

// ── Error of a failed test command ─────────────────────────────────────────

/// An Oper with `Test` set, carrying `operTm` when `oper_tm` is given.
fn test_oper(ctl_num: u64, oper_tm: Option<[u8; 8]>) -> MmsData {
    let MmsData::Structure(mut members) = oper(on(), ctl_num) else {
        unreachable!()
    };
    members[4] = MmsData::Boolean(true);
    if let Some(t) = oper_tm {
        members.insert(1, MmsData::UtcTime(t));
    }
    MmsData::Structure(members)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_test_commands_terminate_with_the_test_error_codes() {
    let s = server();
    register(
        &s,
        object("SPCSO3", ControlModel::DirectEnhanced),
        Arc::new(AlwaysFailOperateHandler {
            cause: ControlAddCause::BlockedByProcess,
        }),
    );
    let h = start(&s).await;
    let mut a = connect(&h).await;

    for (item, value, error) in [
        ("GGIO1$CO$SPCSO3$Oper", test_oper(31, None), 3),
        ("GGIO1$CO$SPCSO3$Oper", oper(on(), 33), 0),
    ] {
        a.write(DOMAIN, item, value).await.expect("accepted");
        let (names, values) = next_report(&mut a, WAIT).await.expect("CommandTermination");
        assert_eq!(names.len(), 2, "a negative termination");
        let MmsData::Structure(lae) = &values[0] else {
            panic!("LastApplError is not a structure")
        };
        assert_eq!(lae[1], MmsData::Integer(error), "Error of {item}");
        assert_eq!(lae[4], MmsData::Integer(9), "AddCause");
    }
    h.stop().await;
}

// ── Services outside the control model ─────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sbow_outside_the_enhanced_select_model_is_refused() {
    let s = server();
    let declared = object("SPCSO1", ControlModel::DirectNormal);
    let undeclared = object("SPCSO9", ControlModel::DirectNormal);
    register(&s, declared.clone(), Arc::new(AlwaysSuccessOperateHandler));
    register(
        &s,
        undeclared.clone(),
        Arc::new(AlwaysSuccessOperateHandler),
    );
    let h = start(&s).await;
    let mut a = connect(&h).await;

    // The model declares SPCSO1 without SBOw, so the attribute does not exist.
    let r = a
        .write(DOMAIN, "GGIO1$CO$SPCSO1$SBOw", oper(on(), 81))
        .await;
    assert_eq!(denied(r), DataAccessError::ObjectNonExistent);
    assert_eq!(queued_report(&mut a).await, None);
    assert_eq!(declared.state(), ControlState::Unselected);

    // An object the model does not declare answers unknown.
    let r = a
        .write(DOMAIN, "GGIO1$CO$SPCSO9$SBOw", oper(on(), 82))
        .await;
    assert_eq!(denied(r), DataAccessError::ObjectAccessDenied);
    let lae = last_appl_error_only(queued_report(&mut a).await);
    assert_last_appl_error(&lae, &format!("{DOMAIN}/GGIO1$CO$SPCSO9$SBOw"), 82, 0);
    assert_eq!(undeclared.state(), ControlState::Unselected);
    h.stop().await;
}

/// Returns the data access error a read answers with.
fn read_denied(r: Result<MmsData, ClientError>) -> DataAccessError {
    match r {
        Err(ClientError::DataAccessError(e)) => e,
        other => panic!("expected a data access error, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_of_sbo_outside_the_normal_select_model_does_not_exist() {
    let s = server();
    for (name, model) in [
        ("SPCSO1", ControlModel::DirectNormal),
        ("SPCSO2", ControlModel::SboNormal),
        ("SPCSO4", ControlModel::SboEnhanced),
        ("SPCSO9", ControlModel::DirectNormal),
    ] {
        register(
            &s,
            object(name, model),
            Arc::new(AlwaysSuccessOperateHandler),
        );
    }
    let h = start(&s).await;
    let mut a = connect(&h).await;

    for item in [
        "GGIO1$CO$SPCSO1$SBO",
        "GGIO1$CO$SPCSO4$SBO",
        "GGIO1$CO$SPCSO9$SBO",
    ] {
        let r = a.read(DOMAIN, item).await;
        assert_eq!(read_denied(r), DataAccessError::ObjectNonExistent, "{item}");
    }
    let sel = a.read(DOMAIN, "GGIO1$CO$SPCSO2$SBO").await.expect("select");
    assert_eq!(
        sel,
        MmsData::VisibleString(format!("{DOMAIN}/GGIO1$CO$SPCSO2"))
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_of_an_idle_direct_object_is_not_supported() {
    let s = server();
    for (name, model) in [
        ("SPCSO1", ControlModel::DirectNormal),
        ("SPCSO3", ControlModel::DirectEnhanced),
    ] {
        register(
            &s,
            object(name, model),
            Arc::new(AlwaysSuccessOperateHandler),
        );
    }
    let h = start(&s).await;
    let mut a = connect(&h).await;

    for (item, ctl_num) in [
        ("GGIO1$CO$SPCSO1$Cancel", 83),
        ("GGIO1$CO$SPCSO3$Cancel", 84),
    ] {
        let r = a.write(DOMAIN, item, cancel(ctl_num)).await;
        assert_eq!(denied(r), DataAccessError::ObjectAccessDenied, "{item}");
        let lae = last_appl_error_only(queued_report(&mut a).await);
        assert_last_appl_error(&lae, &format!("{DOMAIN}/{item}"), ctl_num, 1);
    }
    h.stop().await;
}

// ── End of a selection ─────────────────────────────────────────────────────

/// Forwards every selection change reason to a channel.
struct Selections(tokio::sync::mpsc::UnboundedSender<SelectStateChangedReason>);

impl SelectStateChangedHandler for Selections {
    fn on_select_state_changed(
        &self,
        _a: &ControlAction,
        _selected: bool,
        reason: SelectStateChangedReason,
    ) {
        let _ = self.0.send(reason);
    }
}

fn observe(obj: &ControlObject) -> tokio::sync::mpsc::UnboundedReceiver<SelectStateChangedReason> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    obj.set_select_state_handler(Arc::new(Selections(tx)));
    rx
}

async fn next_change(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<SelectStateChangedReason>,
) -> SelectStateChangedReason {
    tokio::time::timeout(WAIT, rx.recv())
        .await
        .expect("a selection change")
        .expect("the handler is installed")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operate_after_the_select_timeout_is_refused() {
    let s = server();
    let obj = ControlObject::new({
        let mut config =
            ControlObjectConfig::new("SPCSO2", "GGIO1", DOMAIN, ControlModel::SboNormal);
        config.sbo_timeout_ms = 20;
        config
    });
    let mut changes = observe(&obj);
    register(&s, obj.clone(), Arc::new(AlwaysSuccessOperateHandler));
    let h = start(&s).await;
    let mut a = connect(&h).await;

    a.read(DOMAIN, "GGIO1$CO$SPCSO2$SBO").await.expect("select");
    assert_eq!(
        next_change(&mut changes).await,
        SelectStateChangedReason::Selected
    );
    // The timer ends the selection with no request arriving.
    assert_eq!(
        next_change(&mut changes).await,
        SelectStateChangedReason::Timeout
    );
    assert_eq!(obj.state(), ControlState::Unselected);

    let r = a
        .write(DOMAIN, "GGIO1$CO$SPCSO2$Oper", oper(on(), 91))
        .await;
    assert_eq!(denied(r), DataAccessError::ObjectAccessDenied);
    let lae = last_appl_error_only(queued_report(&mut a).await);
    assert_last_appl_error(&lae, &format!("{DOMAIN}/GGIO1$CO$SPCSO2$Oper"), 91, 18);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closing_the_association_ends_its_selection() {
    let s = server();
    let obj = object("SPCSO4", ControlModel::SboEnhanced);
    let mut changes = observe(&obj);
    register(&s, obj.clone(), Arc::new(AlwaysSuccessOperateHandler));
    let h = start(&s).await;
    let mut a = connect(&h).await;

    a.write(DOMAIN, "GGIO1$CO$SPCSO4$SBOw", oper(on(), 92))
        .await
        .expect("select");
    assert_eq!(
        next_change(&mut changes).await,
        SelectStateChangedReason::Selected
    );
    a.abort().await.expect("abort");
    assert_eq!(
        next_change(&mut changes).await,
        SelectStateChangedReason::Disconnected
    );
    assert_eq!(obj.state(), ControlState::Unselected);
    h.stop().await;
}

// ── An association lost while the response waits ───────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_operate_whose_association_closes_before_its_response_does_not_run() {
    let seen: Arc<Mutex<Vec<MmsValue>>> = Arc::default();
    let check = GatedCheck {
        entered: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
        result: Ok(()),
    };
    let (entered, release) = (check.entered.clone(), check.release.clone());
    let s = server();
    let obj = object("SPCSO2", ControlModel::SboNormal);
    let mut changes = observe(&obj);
    s.control_objects().register(
        ControlObjectEntry::new(obj.clone())
            .with_wait(Arc::new(check) as Arc<dyn WaitForExecutionHandler>)
            .with_operate(Arc::new(Recorder::new(&seen)) as Arc<dyn ControlHandler>),
    );
    let h = start(&s).await;
    let mut conn = raw_connect(&h).await;

    let mut alloc = InvokeIdAllocator::new(8);
    let select = iec61850_mms::mms::client::services::read_variable(
        &mut conn,
        &mut alloc,
        DOMAIN,
        "GGIO1$CO$SPCSO2$SBO",
    )
    .await
    .expect("select");
    assert_eq!(
        select,
        MmsData::VisibleString(format!("{DOMAIN}/GGIO1$CO$SPCSO2"))
    );
    assert_eq!(
        next_change(&mut changes).await,
        SelectStateChangedReason::Selected
    );

    let req = WriteRequest::single_domain(DOMAIN, "GGIO1$CO$SPCSO2$Oper", oper(on(), 95));
    let mut full = BytesMut::new();
    encode_confirmed_write_request(9, &req, &mut full);
    conn.send_mms_pdu(&MmsPdu::ConfirmedRequest(request_content(full)))
        .await
        .expect("send");
    entered.notified().await;
    conn.abort().await.expect("abort");
    tokio::time::timeout(WAIT, async {
        while s.connection_count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the association is released");

    // The dynamic check passes after the association is gone.
    release.notify_one();
    assert_eq!(
        next_change(&mut changes).await,
        SelectStateChangedReason::Disconnected
    );
    assert_eq!(obj.state(), ControlState::Unselected);
    assert!(seen.lock().unwrap().is_empty(), "the command ran");
    h.stop().await;
}

// ── A handler that panics ──────────────────────────────────────────────────

/// Control handler that panics while it executes.
struct PanickingOperate;

impl ControlHandler for PanickingOperate {
    fn operate<'a>(
        &'a self,
        _a: &'a ControlAction,
        _v: &'a MmsValue,
        _t: bool,
    ) -> OperateFuture<'a> {
        Box::pin(async { panic!("control handler failure") })
    }
}

/// Dynamic check that panics.
struct PanickingCheck;

impl WaitForExecutionHandler for PanickingCheck {
    fn wait_for_execution<'a>(
        &'a self,
        _a: &'a ControlAction,
        _v: &'a MmsValue,
        _t: bool,
        _s: bool,
    ) -> WaitForExecFuture<'a> {
        Box::pin(async { panic!("dynamic check failure") })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panicking_control_handler_ends_the_command_negatively() {
    let s = server();
    let obj = object("SPCSO3", ControlModel::DirectEnhanced);
    register(&s, obj.clone(), Arc::new(PanickingOperate));
    let h = start(&s).await;
    let mut a = connect(&h).await;

    a.write(DOMAIN, "GGIO1$CO$SPCSO3$Oper", oper(on(), 101))
        .await
        .expect("answered positively");
    let (names, values) = next_report(&mut a, WAIT).await.expect("CommandTermination");
    assert_eq!(names.len(), 2, "a negative termination");
    let MmsData::Structure(lae) = &values[0] else {
        panic!("LastApplError is not a structure")
    };
    assert_eq!(lae[1], MmsData::Integer(1), "Error Unknown");
    assert_eq!(lae[3], MmsData::Unsigned(101));
    assert_eq!(lae[4], MmsData::Integer(0), "AddCause Unknown");
    assert_eq!(obj.state(), ControlState::Unselected);

    // The object accepts the next command instead of answering 12.
    a.write(DOMAIN, "GGIO1$CO$SPCSO3$Oper", oper(on(), 102))
        .await
        .expect("answered positively");
    next_report(&mut a, WAIT).await.expect("CommandTermination");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panicking_handler_under_normal_security_ends_the_selection() {
    let s = server();
    let obj = object("SPCSO2", ControlModel::SboNormal);
    let mut changes = observe(&obj);
    register(&s, obj.clone(), Arc::new(PanickingOperate));
    let h = start(&s).await;
    let mut a = connect(&h).await;

    a.read(DOMAIN, "GGIO1$CO$SPCSO2$SBO").await.expect("select");
    a.write(DOMAIN, "GGIO1$CO$SPCSO2$Oper", oper(on(), 103))
        .await
        .expect("answered positively");
    assert_eq!(
        next_change(&mut changes).await,
        SelectStateChangedReason::Selected
    );
    assert_eq!(
        next_change(&mut changes).await,
        SelectStateChangedReason::OperateDone
    );
    assert_eq!(obj.state(), ControlState::Unselected);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panicking_dynamic_check_answers_the_operate_negatively() {
    let s = server();
    let obj = object("SPCSO1", ControlModel::DirectNormal);
    s.control_objects().register(
        ControlObjectEntry::new(obj.clone())
            .with_wait(Arc::new(PanickingCheck) as Arc<dyn WaitForExecutionHandler>)
            .with_operate(Arc::new(AlwaysSuccessOperateHandler) as Arc<dyn ControlHandler>),
    );
    let h = start(&s).await;
    let mut a = connect(&h).await;

    let r = a
        .write(DOMAIN, "GGIO1$CO$SPCSO1$Oper", oper(on(), 104))
        .await;
    assert_eq!(denied(r), DataAccessError::ObjectAccessDenied);
    let lae = last_appl_error_only(queued_report(&mut a).await);
    assert_eq!(lae[1], MmsData::Integer(1), "Error Unknown");
    assert_eq!(lae[4], MmsData::Integer(0), "AddCause Unknown");
    assert_eq!(obj.state(), ControlState::Unselected);
    h.stop().await;
}

// ── TimeActivatedOperate ───────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operate_with_an_activation_time_is_refused_with_not_supported() {
    let seen: Arc<Mutex<Vec<MmsValue>>> = Arc::default();
    let s = server();
    let obj = object("SPCSO5", ControlModel::DirectEnhanced);
    register(&s, obj.clone(), Arc::new(Recorder::new(&seen)));
    let h = start(&s).await;
    let mut a = connect(&h).await;

    let mut timed = test_oper(71, Some([0, 0, 0, 60, 0, 0, 0, 0]));
    if let MmsData::Structure(m) = &mut timed {
        m[5] = MmsData::Boolean(false);
    }
    let r = a.write(DOMAIN, "GGIO1$CO$SPCSO5$Oper", timed).await;
    assert_eq!(denied(r), DataAccessError::ObjectAccessDenied);
    let lae = last_appl_error_only(queued_report(&mut a).await);
    assert_last_appl_error(&lae, &format!("{DOMAIN}/GGIO1$CO$SPCSO5$Oper"), 71, 1);
    assert_eq!(obj.state(), ControlState::Unselected);
    assert!(seen.lock().unwrap().is_empty(), "the command ran");

    // An operTm of 0 is an immediate Operate.
    let mut immediate = test_oper(72, Some([0; 8]));
    if let MmsData::Structure(m) = &mut immediate {
        m[5] = MmsData::Boolean(false);
    }
    a.write(DOMAIN, "GGIO1$CO$SPCSO5$Oper", immediate)
        .await
        .expect("an Operate without an activation time");
    let (names, _) = next_report(&mut a, WAIT).await.expect("CommandTermination");
    assert_eq!(names.len(), 1, "a positive termination names Oper alone");
    assert_eq!(*seen.lock().unwrap(), vec![MmsValue::Boolean(true)]);
    h.stop().await;
}

// ── Error of a refusal whose cause is unknown ──────────────────────────────

/// Check handler that refuses with a fixed cause.
struct RefusingCheck(ControlAddCause);

impl CheckHandler for RefusingCheck {
    fn check(
        &self,
        _a: &ControlAction,
        _v: Option<&MmsValue>,
        _t: bool,
        _i: bool,
    ) -> Result<(), ControlAddCause> {
        Err(self.0)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_handler_refusal_with_an_unknown_cause_carries_no_error() {
    let s = server();
    s.control_objects().register(
        ControlObjectEntry::new(object("SPCSO1", ControlModel::DirectNormal))
            .with_check(Arc::new(RefusingCheck(ControlAddCause::Unknown)) as Arc<dyn CheckHandler>)
            .with_operate(Arc::new(AlwaysSuccessOperateHandler) as Arc<dyn ControlHandler>),
    );
    let h = start(&s).await;
    let mut a = connect(&h).await;

    let r = a
        .write(DOMAIN, "GGIO1$CO$SPCSO1$Oper", oper(on(), 51))
        .await;
    assert_eq!(denied(r), DataAccessError::ObjectAccessDenied);
    // Error is No Error: the refusal came from a check, not from the server.
    let lae = last_appl_error_only(queued_report(&mut a).await);
    assert_last_appl_error(&lae, &format!("{DOMAIN}/GGIO1$CO$SPCSO1$Oper"), 51, 0);
    h.stop().await;
}

// ── LastApplError ahead of the negative response ───────────────────────────

/// Writes one variable and returns the outcome together with the reports that
/// arrived before the response; nothing reads the socket after it.
async fn write_and_take_earlier_reports(
    conn: &mut MmsConnection,
    alloc: &mut InvokeIdAllocator,
    item: &str,
    value: MmsData,
) -> (Result<(), ClientError>, Vec<Report>) {
    let r = write_variable(conn, alloc, DOMAIN, item, value).await;
    let mut earlier = Vec::new();
    while let Some(inner) = conn.pop_pending_unconfirmed() {
        let report = decode_information_report(&inner).expect("information report");
        let VariableAccessSpec::ListOfVariable(names) = report.variable_access_spec else {
            panic!("unexpected variable access specification")
        };
        earlier.push((names, report.list_of_access_result));
    }
    (r, earlier)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn last_appl_error_arrives_before_the_negative_response() {
    let s = server();
    register(
        &s,
        object("SPCSO2", ControlModel::SboNormal),
        Arc::new(AlwaysSuccessOperateHandler),
    );
    register(
        &s,
        object("SPCSO4", ControlModel::SboEnhanced),
        Arc::new(AlwaysSuccessOperateHandler),
    );
    s.control_objects().register(
        ControlObjectEntry::new(object("SPCSO1", ControlModel::DirectNormal))
            .with_wait(Arc::new(GatedCheck::open(Err(
                ControlAddCause::BlockedBySynchrocheck,
            ))) as Arc<dyn WaitForExecutionHandler>)
            .with_operate(Arc::new(AlwaysSuccessOperateHandler) as Arc<dyn ControlHandler>),
    );
    let h = start(&s).await;
    let mut holder = connect(&h).await;
    holder
        .write(DOMAIN, "GGIO1$CO$SPCSO4$SBOw", oper(on(), 40))
        .await
        .expect("select");
    let mut conn = raw_connect(&h).await;
    let mut alloc = InvokeIdAllocator::new(8);

    for (item, value, ctl_num, add_cause) in [
        ("GGIO1$CO$SPCSO2$Oper", oper(on(), 41), 41, 18),
        ("GGIO1$CO$SPCSO4$SBOw", oper(on(), 42), 42, 19),
        ("GGIO1$CO$SPCSO4$Cancel", cancel(43), 43, 27),
        // Refused by the dynamic check, so the response was deferred.
        ("GGIO1$CO$SPCSO1$Oper", oper(on(), 44), 44, 11),
    ] {
        let (r, earlier) = write_and_take_earlier_reports(&mut conn, &mut alloc, item, value).await;
        assert!(r.is_err(), "{item} is refused, got {r:?}");
        let lae = last_appl_error_only(earlier.into_iter().next());
        assert_last_appl_error(&lae, &format!("{DOMAIN}/{item}"), ctl_num, add_cause);
    }
    h.stop().await;
}

// ── SelectWithValue on an executing object ─────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sbow_on_an_executing_object_reports_command_already_in_execution() {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let s = server();
    let obj = object("SPCSO4", ControlModel::SboEnhanced);
    register(
        &s,
        obj.clone(),
        Arc::new(Gate {
            entered: entered.clone(),
            release: release.clone(),
            result: Ok(()),
        }),
    );
    let h = start(&s).await;
    let mut a = connect(&h).await;

    a.write(DOMAIN, "GGIO1$CO$SPCSO4$SBOw", oper(on(), 61))
        .await
        .expect("select");
    let r = a
        .write(DOMAIN, "GGIO1$CO$SPCSO4$Oper", oper(on(), 61))
        .await;
    if r.is_err() {
        release.notify_one();
    }
    r.expect("answered positively");
    entered.notified().await;
    assert_eq!(obj.state(), ControlState::Operate);

    let r = a
        .write(DOMAIN, "GGIO1$CO$SPCSO4$SBOw", oper(on(), 62))
        .await;
    release.notify_one();
    assert_eq!(denied(r), DataAccessError::TemporarilyUnavailable);
    let lae = last_appl_error_only(queued_report(&mut a).await);
    assert_last_appl_error(&lae, &format!("{DOMAIN}/GGIO1$CO$SPCSO4$SBOw"), 62, 12);
    h.stop().await;
}
