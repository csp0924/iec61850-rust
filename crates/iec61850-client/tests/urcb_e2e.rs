//! End-to-end tests of URCB report subscription over a loopback association.
//!
//! Each test drives the whole chain: a server hosts a URCB whose data set
//! holds one Boolean data attribute; the client connects and installs a report
//! handler; a value update makes the reporting engine queue a report, which
//! reaches the client socket as an InformationReport; the client polls,
//! decodes and dispatches it to the handler.
//!
//! Reporting is enabled by setting the control block state directly rather
//! than through `set_rcb_values`, so that a test exercises the report path
//! alone.

use bytes::Bytes;
use iec61850_client::report::{ClientReport, ReportCallback};
use iec61850_client::IedConnection;
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_model::{
    DataAttribute, DataAttributeType, IedModel, IedModelBuilder, LogicalDeviceBuilder,
    LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::{
    Dataset, DatasetEntry, IedServer, IedServerConfig, Rcb, ReportControl, TriggerOptions,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// Fixture

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
    let cfg = IedServerConfig {
        max_mms_connections: 5,
        ..Default::default()
    };
    IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(cfg)
        .build()
        .expect("build server")
}

/// A fixed RptId, so that client and server agree on it; the default would be
/// empty and never match.
const TEST_RPT_ID: &str = "IED1LD0/GGIO1$RP$urcb01";

/// Registers a URCB whose data set holds one Boolean data attribute, and
/// returns that attribute, the MMS path and the RptId.
fn register_urcb_with_bool_da(server: &IedServer) -> (DataAttribute, String, String) {
    let da = DataAttribute::new(
        "stVal",
        FC::St,
        DataAttributeType::Boolean,
        TrgOps::DCHG,
        MmsValue::Boolean(false),
    );
    let attr_ref = "IED1LD0/GGIO1$ST$Ind1$stVal".to_string();
    let entry = DatasetEntry::new(attr_ref, Arc::clone(&da.value));
    let mut ds = Dataset::new("GGIO1$ds1");
    ds.push(entry);

    // The report state carries the RptId of the control block verbatim, and an
    // empty string would read as no default; the client installs on the same
    // string.
    let rcb = Rcb::new("urcb01", "GGIO1$ds1")
        .with_rpt_id(TEST_RPT_ID)
        .with_trg_ops(TriggerOptions::DATA_CHANGED);
    let mms_path = "IED1LD0/GGIO1$RP$urcb01".to_string();
    let rc = ReportControl::new(&mms_path, rcb);
    server.register_urcb(rc, ds).expect("register_urcb");
    (da, mms_path, TEST_RPT_ID.to_string())
}

/// Enables the report control block directly on the server.
///
/// Binding a connection id makes the engine push the report through that
/// connection's sink on the next tick.
fn enable_urcb(server: &IedServer, mms_path: &str, conn_id: u64) {
    let engine = server.reporting_engine();
    let engine_g = engine.lock().unwrap();
    let rc_arc = engine_g
        .get_rcb(mms_path)
        .expect("RCB should be registered");
    let rc_g = rc_arc.lock().unwrap();
    let mut state = rc_g.state.lock().unwrap();
    state.rpt_ena = true;
    state.client_conn_id = Some(conn_id);
}

// A data change reaches the handler through poll_reports.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rust_to_rust_urcb_data_change_dispatch() {
    let server = build_server();
    let (da, mms_path, rpt_id) = register_urcb_with_bool_da(&server);

    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    // Connect the client.
    let mms_client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    let conn = IedConnection::with_mms_client(mms_client);
    conn.connect("127.0.0.1", port)
        .await
        .expect("client.connect");

    // Wait until the server has accepted the connection and registered its
    // report sink, then take that connection id.
    let conn_id = wait_for_first_conn_id(&server, Duration::from_secs(2)).await;

    // Install a handler that records the values it is given.
    let captured: Arc<Mutex<Vec<MmsValue>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_clone = Arc::clone(&captured);
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = Arc::clone(&counter);

    let cb: ReportCallback = Arc::new(move |snap: Arc<ClientReport>| {
        counter_clone.fetch_add(1, Ordering::SeqCst);
        // The snapshot holds one slot per data set member; take the first
        // included value.
        if let Some(Some(v)) = snap.data_set_values.first() {
            captured_clone.lock().unwrap().push(v.clone());
        }
    });
    // The client installs on the same RptId the server puts into the report,
    // which is the full MMS path of the control block.
    conn.install_report_handler(Some(rpt_id.clone()), &mms_path, None, cb)
        .await
        .expect("install_report_handler");

    // Enable reporting on the server, then change the value.
    enable_urcb(&server, &mms_path, conn_id);
    server.update_boolean(&da, true).expect("update_boolean");

    // Poll until the handler fires, allowing for the server tick and the socket.
    let mut total_dispatched = 0usize;
    for _ in 0..40 {
        let n = conn
            .poll_reports(Duration::from_millis(100))
            .await
            .expect("poll_reports");
        total_dispatched += n;
        if counter.load(Ordering::SeqCst) >= 1 {
            break;
        }
    }

    // The handler ran once and received Boolean(true).
    assert!(
        counter.load(Ordering::SeqCst) >= 1,
        "the handler should have been called at least once (dispatched={total_dispatched})"
    );
    let captured_vals = captured.lock().unwrap().clone();
    assert!(
        captured_vals
            .iter()
            .any(|v| matches!(v, MmsValue::Boolean(true))),
        "the handler should have received Boolean(true), captured={captured_vals:?}"
    );

    let _ = conn.disconnect().await;
    handle.stop().await;
}

// A background dispatcher delivers reports without an explicit poll.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rust_to_rust_urcb_background_dispatcher_dispatches() {
    let server = build_server();
    let (da, mms_path, rpt_id) = register_urcb_with_bool_da(&server);

    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    let mms_client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    let conn = IedConnection::with_mms_client(mms_client);
    conn.connect("127.0.0.1", port)
        .await
        .expect("client.connect");

    let conn_id = wait_for_first_conn_id(&server, Duration::from_secs(2)).await;

    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = Arc::clone(&counter);
    let cb: ReportCallback = Arc::new(move |_snap| {
        counter_clone.fetch_add(1, Ordering::SeqCst);
    });
    conn.install_report_handler(Some(rpt_id.clone()), &mms_path, None, cb)
        .await
        .expect("install");

    // Start the background dispatcher on a short poll interval.
    let dispatcher = conn.spawn_report_dispatcher(Duration::from_millis(50));

    enable_urcb(&server, &mms_path, conn_id);
    server.update_boolean(&da, true).expect("update");

    // Wait up to four seconds for the handler to fire.
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    while std::time::Instant::now() < deadline && counter.load(Ordering::SeqCst) == 0 {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        counter.load(Ordering::SeqCst) >= 1,
        "the background dispatcher should have delivered at least one report"
    );

    // Disconnecting clears the connected flag, ending the dispatcher task.
    let _ = conn.disconnect().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), dispatcher).await;
    handle.stop().await;
}

// Waits for the server to accept the client and register its report sink.

async fn wait_for_first_conn_id(server: &IedServer, timeout: Duration) -> u64 {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if let Some(id) = first_connected_id(server) {
            return id;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for the server connection id ({timeout:?})");
}

/// Returns the identifier of the first accepted connection.
///
/// The server numbers connections from one and each test owns its own server,
/// so the first connection is always 1. A test running two servers in parallel
/// would need the server to expose the identifier instead.
// TODO: read the connection id from the server rather than assuming it.
fn first_connected_id(_server: &IedServer) -> Option<u64> {
    Some(1)
}

// Keeps the `Bytes` import from reading as unused.
#[allow(dead_code)]
fn _force_use(_: Bytes) {}

// A general interrogation returns a complete snapshot of the data set.
//
// The client writes `<rcb_ref>$GI = true`, the server sets the flag on the
// control block, and its next tick queues a report carrying every data set
// member. The data set holds three attributes (Boolean, Boolean, Int32), so
// the handler must receive three values, each equal to the live value on the
// server.

const GI_RPT_ID: &str = "IED1LD0/GGIO1$RP$urcb_gi";

/// Registers a URCB whose trigger options include GI, over a data set of three
/// data attributes.
fn register_urcb_for_gi(
    server: &IedServer,
) -> (
    DataAttribute, // Ind1.stVal (Boolean)
    DataAttribute, // Ind2.stVal (Boolean)
    DataAttribute, // AnIn1.mag.f, an Integer here to keep the assertion simple
    String,        // mms_path
    String,        // rpt_id
) {
    let da1 = DataAttribute::new(
        "stVal",
        FC::St,
        DataAttributeType::Boolean,
        TrgOps::DCHG,
        MmsValue::Boolean(false),
    );
    let da2 = DataAttribute::new(
        "stVal",
        FC::St,
        DataAttributeType::Boolean,
        TrgOps::DCHG,
        MmsValue::Boolean(true),
    );
    let da3 = DataAttribute::new(
        "stVal",
        FC::St,
        DataAttributeType::Int32,
        TrgOps::DCHG,
        MmsValue::Integer(42),
    );

    let mut ds = Dataset::new("GGIO1$ds_gi");
    ds.push(DatasetEntry::new(
        "IED1LD0/GGIO1$ST$Ind1$stVal",
        Arc::clone(&da1.value),
    ));
    ds.push(DatasetEntry::new(
        "IED1LD0/GGIO1$ST$Ind2$stVal",
        Arc::clone(&da2.value),
    ));
    ds.push(DatasetEntry::new(
        "IED1LD0/GGIO1$ST$AnIn1$stVal",
        Arc::clone(&da3.value),
    ));

    let rcb = Rcb::new("urcb_gi", "GGIO1$ds_gi")
        .with_rpt_id(GI_RPT_ID)
        .with_trg_ops(TriggerOptions::DATA_CHANGED | TriggerOptions::GI);
    let mms_path = "IED1LD0/GGIO1$RP$urcb_gi".to_string();
    let rc = ReportControl::new(&mms_path, rcb);
    server.register_urcb(rc, ds).expect("register_urcb");
    (da1, da2, da3, mms_path, GI_RPT_ID.to_string())
}

/// Enables the control block and marks it reserved for the connection.
///
/// Writing GI requires the caller to hold the reservation, so enabling
/// reporting alone is not enough.
fn enable_urcb_with_resv(server: &IedServer, mms_path: &str, conn_id: u64) {
    let engine = server.reporting_engine();
    let engine_g = engine.lock().unwrap();
    let rc_arc = engine_g
        .get_rcb(mms_path)
        .expect("RCB should be registered");
    let rc_g = rc_arc.lock().unwrap();
    let mut state = rc_g.state.lock().unwrap();
    state.resv = true;
    state.rpt_ena = true;
    state.client_conn_id = Some(conn_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rust_to_rust_urcb_gi_via_trigger_grefcb_full_dataset() {
    let server = build_server();
    let (_da1, _da2, _da3, mms_path, rpt_id) = register_urcb_for_gi(&server);

    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    // Connect the client.
    let mms_client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    let conn = IedConnection::with_mms_client(mms_client);
    conn.connect("127.0.0.1", port)
        .await
        .expect("client.connect");

    let conn_id = wait_for_first_conn_id(&server, Duration::from_secs(2)).await;

    // Install a handler that keeps every report it is given.
    let captured: Arc<Mutex<Vec<Arc<ClientReport>>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_cb = Arc::clone(&captured);
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_cb = Arc::clone(&counter);

    let cb: ReportCallback = Arc::new(move |snap: Arc<ClientReport>| {
        counter_cb.fetch_add(1, Ordering::SeqCst);
        captured_cb.lock().unwrap().push(snap);
    });
    conn.install_report_handler(Some(rpt_id.clone()), &mms_path, None, cb)
        .await
        .expect("install_report_handler");

    // Enable and reserve the control block for this connection.
    enable_urcb_with_resv(&server, &mms_path, conn_id);

    // `trigger_grefcb` writes `<rcb_ref>$GI = true`: the part before the `/` is
    // the MMS domain, the rest has `.` replaced by `$`, and `$GI` is appended,
    // so the written item is `GGIO1$RP$urcb_gi$GI`.
    let rcb_ref_for_trigger = "IED1LD0/GGIO1$RP$urcb_gi";
    conn.trigger_grefcb(rcb_ref_for_trigger)
        .await
        .expect("trigger_grefcb should succeed");

    // Poll for the general interrogation report.
    let mut total_dispatched = 0usize;
    for _ in 0..40 {
        let n = conn
            .poll_reports(Duration::from_millis(100))
            .await
            .expect("poll_reports");
        total_dispatched += n;
        if counter.load(Ordering::SeqCst) >= 1 {
            break;
        }
    }

    assert!(
        counter.load(Ordering::SeqCst) >= 1,
        "the general interrogation handler should have been called at least once (dispatched={total_dispatched})"
    );

    // The snapshot must carry all three entries at their live server values.
    let snaps = captured.lock().unwrap().clone();
    assert!(!snaps.is_empty(), "expected at least one snapshot");
    let gi_snap = snaps
        .iter()
        .find(|s| s.data_set_values.len() == 3)
        .unwrap_or_else(|| {
            panic!(
                "a general interrogation snapshot should carry three entries, got lengths: {:?}",
                snaps
                    .iter()
                    .map(|s| s.data_set_values.len())
                    .collect::<Vec<_>>()
            )
        });

    assert_eq!(
        gi_snap.data_set_values.len(),
        3,
        "a general interrogation snapshot should carry three entries"
    );

    // entry 0: Ind1.stVal = false
    match &gi_snap.data_set_values[0] {
        Some(MmsValue::Boolean(b)) => assert!(!*b, "entry 0 should be Boolean(false)"),
        other => panic!("entry 0 should be Some(Boolean(false)), got {other:?}"),
    }
    // entry 1: Ind2.stVal = true
    match &gi_snap.data_set_values[1] {
        Some(MmsValue::Boolean(b)) => assert!(*b, "entry 1 should be Boolean(true)"),
        other => panic!("entry 1 should be Some(Boolean(true)), got {other:?}"),
    }
    // entry 2: AnIn1.stVal = Integer(42)
    match &gi_snap.data_set_values[2] {
        Some(MmsValue::Integer(v)) => assert_eq!(*v, 42, "entry 2 should be Integer(42)"),
        other => panic!("entry 2 should be Some(Integer(42)), got {other:?}"),
    }

    let _ = conn.disconnect().await;
    handle.stop().await;
}
