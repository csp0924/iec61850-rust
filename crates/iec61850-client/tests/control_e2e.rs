//! End-to-end control tests over a loopback association, covering all four
//! control models.
//!
//! Each test drives the whole chain: the client issues an MMS Write or Read,
//! the server dispatches it to its control object registry, and the registry
//! invokes the select, operate, cancel or check handler.
//!
//! Covered: direct-normal accepted and refused by the check handler;
//! direct-enhanced accepted with a positive command termination and refused
//! with a negative one; sbo-normal selected then operated, and operated
//! without a selection; sbo-enhanced selected with a value then operated, and
//! operated with a value the selection did not carry.

use std::net::SocketAddr;
use std::sync::Arc;

use iec61850_client::control::{ControlAddCause, ControlObjectClient, ControlOutcome};
use iec61850_client::IedConnection;
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_model::{
    ControlModel, IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue,
};
use iec61850_server::control::{
    AlwaysAcceptCheckHandler, AlwaysAcceptWaitHandler, AlwaysFailOperateHandler,
    AlwaysSuccessOperateHandler, CheckHandler, ControlAddCause as ServerControlAddCause,
    ControlHandler, ControlObject, ControlObjectConfig, ControlObjectEntry, SboClass,
    WaitForExecutionHandler,
};
use iec61850_server::{IedServer, IedServerConfig};

// Server fixture: one SPC per control model.

const DOMAIN: &str = "IED1LD0";
const LN: &str = "GGIO1";

fn build_model() -> Arc<IedModel> {
    let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .build()
        .expect("ld");
    Arc::new(
        IedModelBuilder::new("IED1")
            .add_ld(ld)
            .expect("add_ld")
            .build()
            .expect("model"),
    )
}

fn build_server() -> IedServer {
    IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig {
            max_mms_connections: 4,
            ..Default::default()
        })
        .build()
        .expect("build server")
}

/// Registers a control object with its handlers on the server.
fn register_control_object(
    server: &IedServer,
    do_name: &str,
    ctl_model: ControlModel,
    operate_handler: Arc<dyn ControlHandler>,
) {
    register_control_object_with_timeout(server, do_name, ctl_model, operate_handler, 30_000);
}

/// Registers a control object with an explicit select-before-operate timeout.
fn register_control_object_with_timeout(
    server: &IedServer,
    do_name: &str,
    ctl_model: ControlModel,
    operate_handler: Arc<dyn ControlHandler>,
    sbo_timeout_ms: u32,
) {
    let obj = ControlObject::new(ControlObjectConfig {
        name: do_name.into(),
        ln_name: LN.into(),
        domain: DOMAIN.into(),
        ctl_model,
        sbo_timeout_ms,
        sbo_class: SboClass::OperateOnce,
    });
    let entry = ControlObjectEntry::new(obj)
        .with_check(Arc::new(AlwaysAcceptCheckHandler) as Arc<dyn CheckHandler>)
        .with_wait(Arc::new(AlwaysAcceptWaitHandler) as Arc<dyn WaitForExecutionHandler>)
        .with_operate(operate_handler);
    server.control_objects().register(entry);
}

/// Registers a control object with a check handler that always refuses.
fn register_control_object_with_check(
    server: &IedServer,
    do_name: &str,
    ctl_model: ControlModel,
    check_handler: Arc<dyn CheckHandler>,
) {
    let obj = ControlObject::new(ControlObjectConfig {
        name: do_name.into(),
        ln_name: LN.into(),
        domain: DOMAIN.into(),
        ctl_model,
        sbo_timeout_ms: 30_000,
        sbo_class: SboClass::OperateOnce,
    });
    let entry = ControlObjectEntry::new(obj)
        .with_check(check_handler)
        .with_wait(Arc::new(AlwaysAcceptWaitHandler) as Arc<dyn WaitForExecutionHandler>)
        .with_operate(Arc::new(AlwaysSuccessOperateHandler) as Arc<dyn ControlHandler>);
    server.control_objects().register(entry);
}

/// A check handler that always answers BlockedByInterlocking.
struct AlwaysBlockedCheck;
impl CheckHandler for AlwaysBlockedCheck {
    fn check(
        &self,
        _action: &iec61850_server::control::ControlAction,
        _ctl_val: Option<&MmsValue>,
        _test: bool,
        _interlock_check: bool,
    ) -> Result<(), ServerControlAddCause> {
        Err(ServerControlAddCause::BlockedByInterlocking)
    }
}

// Client fixture

async fn make_connected_client(port: u16) -> IedConnection {
    let mms = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    let conn = IedConnection::with_mms_client(mms);
    conn.connect("127.0.0.1", port)
        .await
        .expect("client connect");
    conn
}

fn make_control_handle(
    conn: &IedConnection,
    do_name: &str,
    ctl_model: ControlModel,
) -> ControlObjectClient {
    conn.create_control_object(&format!("{DOMAIN}/{LN}.{do_name}"), ctl_model)
        .expect("create_control_object")
}

// direct-normal, accepted.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_normal_operate_success() {
    let server = build_server();
    register_control_object(
        &server,
        "SPCDN",
        ControlModel::DirectNormal,
        Arc::new(AlwaysSuccessOperateHandler),
    );

    let handle = server.start().await.expect("start");
    let port = handle.bound_addr.port();

    let conn = make_connected_client(port).await;
    let spc = make_control_handle(&conn, "SPCDN", ControlModel::DirectNormal);

    let outcome = spc.operate(MmsValue::Boolean(true)).await.expect("operate");
    assert_eq!(
        outcome,
        ControlOutcome::Success,
        "direct-normal operate should succeed"
    );

    let _ = conn.disconnect().await;
    handle.stop().await;
}

// direct-normal, refused by the check handler.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_normal_operate_check_rejects() {
    let server = build_server();
    register_control_object_with_check(
        &server,
        "SPCDN_BLK",
        ControlModel::DirectNormal,
        Arc::new(AlwaysBlockedCheck),
    );

    let handle = server.start().await.expect("start");
    let port = handle.bound_addr.port();

    let conn = make_connected_client(port).await;
    let spc = make_control_handle(&conn, "SPCDN_BLK", ControlModel::DirectNormal);

    let outcome = spc.operate(MmsValue::Boolean(true)).await.expect("operate");
    // A refused direct-normal command comes back as a confirmed error, which
    // carries no additional cause, so the client reports Failure(Unknown).
    assert!(
        matches!(outcome, ControlOutcome::Failure(_)),
        "direct-normal with a blocking check should fail, got {outcome:?}"
    );

    let _ = conn.disconnect().await;
    handle.stop().await;
}

// direct-enhanced, accepted with a positive command termination.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_enhanced_operate_success_with_ct_positive() {
    let server = build_server();
    register_control_object(
        &server,
        "SPCDE",
        ControlModel::DirectEnhanced,
        Arc::new(AlwaysSuccessOperateHandler),
    );

    let handle = server.start().await.expect("start");
    let port = handle.bound_addr.port();

    let conn = make_connected_client(port).await;
    let spc = make_control_handle(&conn, "SPCDE", ControlModel::DirectEnhanced);

    let outcome = spc.operate(MmsValue::Boolean(true)).await.expect("operate");
    assert_eq!(
        outcome,
        ControlOutcome::Success,
        "direct-enhanced should receive CT+ and report success"
    );

    let _ = conn.disconnect().await;
    handle.stop().await;
}

// direct-enhanced, operate handler fails and the server sends CT-.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_enhanced_operate_failure_with_ct_negative() {
    let server = build_server();
    register_control_object(
        &server,
        "SPCDE_FAIL",
        ControlModel::DirectEnhanced,
        Arc::new(AlwaysFailOperateHandler {
            cause: ServerControlAddCause::BlockedByProcess,
        }),
    );

    let handle = server.start().await.expect("start");
    let port = handle.bound_addr.port();

    let conn = make_connected_client(port).await;
    let spc = make_control_handle(&conn, "SPCDE_FAIL", ControlModel::DirectEnhanced);

    let outcome = spc.operate(MmsValue::Boolean(true)).await.expect("operate");
    // The write itself is answered, so the failure arrives as the negative
    // command termination that follows; the client reads it and reports the
    // additional cause it carries.
    match outcome {
        ControlOutcome::Failure(c) => {
            assert!(
                matches!(
                    c,
                    ControlAddCause::BlockedByProcess | ControlAddCause::Unknown
                ),
                "direct-enhanced failure should report BlockedByProcess, or Unknown as a fallback, got {c:?}"
            );
        }
        ControlOutcome::Success => panic!("direct-enhanced operate failed but reported success"),
    }

    let _ = conn.disconnect().await;
    handle.stop().await;
}

// sbo-normal, select then operate.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sbo_normal_select_then_operate_success() {
    let server = build_server();
    register_control_object(
        &server,
        "SPCSN",
        ControlModel::SboNormal,
        Arc::new(AlwaysSuccessOperateHandler),
    );

    let handle = server.start().await.expect("start");
    let port = handle.bound_addr.port();

    let conn = make_connected_client(port).await;
    let spc = make_control_handle(&conn, "SPCSN", ControlModel::SboNormal);

    let selected = spc.select().await.expect("select");
    assert!(selected, "sbo-normal select should be accepted");

    let outcome = spc.operate(MmsValue::Boolean(true)).await.expect("operate");
    assert_eq!(outcome, ControlOutcome::Success);

    let _ = conn.disconnect().await;
    handle.stop().await;
}

// sbo-normal, operate without a selection.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sbo_normal_operate_without_select_rejects() {
    let server = build_server();
    register_control_object(
        &server,
        "SPCSN_NS",
        ControlModel::SboNormal,
        Arc::new(AlwaysSuccessOperateHandler),
    );

    let handle = server.start().await.expect("start");
    let port = handle.bound_addr.port();

    let conn = make_connected_client(port).await;
    let spc = make_control_handle(&conn, "SPCSN_NS", ControlModel::SboNormal);

    // Operate without selecting first.
    let outcome = spc.operate(MmsValue::Boolean(true)).await.expect("operate");
    assert!(
        matches!(outcome, ControlOutcome::Failure(_)),
        "sbo-normal operate without a selection should fail, got {outcome:?}"
    );

    let _ = conn.disconnect().await;
    handle.stop().await;
}

// sbo-enhanced, select with value then operate.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sbo_enhanced_full_flow_success() {
    let server = build_server();
    register_control_object(
        &server,
        "SPCSE",
        ControlModel::SboEnhanced,
        Arc::new(AlwaysSuccessOperateHandler),
    );

    let handle = server.start().await.expect("start");
    let port = handle.bound_addr.port();

    let conn = make_connected_client(port).await;
    let spc = make_control_handle(&conn, "SPCSE", ControlModel::SboEnhanced);

    // Select with the value the operate will carry.
    let sbow_outcome = spc
        .select_with_value(MmsValue::Boolean(true))
        .await
        .expect("select_with_value");
    assert_eq!(
        sbow_outcome,
        ControlOutcome::Success,
        "select with value should succeed"
    );

    // Operate with the same value; sbo-enhanced reuses the ctlNum of the selection.
    let outcome = spc.operate(MmsValue::Boolean(true)).await.expect("operate");
    assert_eq!(
        outcome,
        ControlOutcome::Success,
        "sbo-enhanced operate should receive CT+ and report success"
    );

    let _ = conn.disconnect().await;
    handle.stop().await;
}

// sbo-enhanced, operate with a value the selection did not carry.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sbo_enhanced_inconsistent_params_rejects_with_ct_negative() {
    let server = build_server();
    register_control_object(
        &server,
        "SPCSE_INC",
        ControlModel::SboEnhanced,
        Arc::new(AlwaysSuccessOperateHandler),
    );

    let handle = server.start().await.expect("start");
    let port = handle.bound_addr.port();

    let conn = make_connected_client(port).await;
    let spc = make_control_handle(&conn, "SPCSE_INC", ControlModel::SboEnhanced);

    // Select with true.
    let _ = spc
        .select_with_value(MmsValue::Boolean(true))
        .await
        .expect("select_with_value");

    // Operate with false, which the server rejects as inconsistent, with a CT-.
    let outcome = spc
        .operate(MmsValue::Boolean(false))
        .await
        .expect("operate");
    match outcome {
        ControlOutcome::Failure(c) => {
            assert!(
                matches!(
                    c,
                    ControlAddCause::InconsistentParameters | ControlAddCause::Unknown
                ),
                "an inconsistent sbo-enhanced operate should report InconsistentParameters, or Unknown as a fallback, got {c:?}"
            );
        }
        ControlOutcome::Success => panic!("an inconsistent sbo-enhanced operate must not succeed"),
    }

    let _ = conn.disconnect().await;
    handle.stop().await;
}

// sbo-normal, cancel releases the selection.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sbo_normal_cancel_after_select() {
    let server = build_server();
    register_control_object(
        &server,
        "SPCSN_CXL",
        ControlModel::SboNormal,
        Arc::new(AlwaysSuccessOperateHandler),
    );

    let handle = server.start().await.expect("start");
    let port = handle.bound_addr.port();

    let conn = make_connected_client(port).await;
    let spc = make_control_handle(&conn, "SPCSN_CXL", ControlModel::SboNormal);

    assert!(spc.select().await.expect("select"));

    let cancel_outcome = spc.cancel(MmsValue::Boolean(true)).await.expect("cancel");
    assert_eq!(cancel_outcome, ControlOutcome::Success);

    // After a cancel the object is unselected, so an operate is refused.
    let after = spc.operate(MmsValue::Boolean(true)).await.expect("operate");
    assert!(
        matches!(after, ControlOutcome::Failure(_)),
        "operate after cancel should fail, got {after:?}"
    );

    let _ = conn.disconnect().await;
    handle.stop().await;
}

// sbo-normal, the selection expires and can be taken again.
//
// The whole sequence runs over the wire: the client selects, the server enters
// the ready state, the selection timeout elapses, and the next operate finds
// the object unselected because the server checks the timeout on entry.
// Selecting again succeeds and the following operate is accepted.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sbo_normal_timeout_releases_then_reselect_succeeds() {
    use std::time::Duration;
    use tokio::time::sleep;

    let server = build_server();
    register_control_object_with_timeout(
        &server,
        "SPCSN_TO",
        ControlModel::SboNormal,
        Arc::new(AlwaysSuccessOperateHandler),
        100, // selection timeout, short enough to keep the test quick
    );

    let handle = server.start().await.expect("start");
    let port = handle.bound_addr.port();

    let conn = make_connected_client(port).await;
    let spc = make_control_handle(&conn, "SPCSN_TO", ControlModel::SboNormal);

    // The first selection is accepted.
    let selected_1 = spc.select().await.expect("select #1");
    assert!(selected_1, "the first select should succeed");

    // Wait well past the selection timeout.
    sleep(Duration::from_millis(450)).await;

    // The server releases the expired selection when the operate arrives, so
    // the object is unselected and the command is refused.
    let after_timeout = spc
        .operate(MmsValue::Boolean(true))
        .await
        .expect("operate after timeout");
    assert!(
        matches!(after_timeout, ControlOutcome::Failure(_)),
        "operate after the selection expired should fail, got {after_timeout:?}"
    );

    // The object can be selected again once the selection has been released.
    let selected_2 = spc.select().await.expect("select #2");
    assert!(
        selected_2,
        "select after the timeout should succeed; a failure means the server did not release the expired selection"
    );

    // The operate after the new selection is accepted.
    let final_outcome = spc
        .operate(MmsValue::Boolean(true))
        .await
        .expect("operate after reselect");
    assert_eq!(
        final_outcome,
        ControlOutcome::Success,
        "operate after selecting again should succeed"
    );

    let _ = conn.disconnect().await;
    handle.stop().await;
}
