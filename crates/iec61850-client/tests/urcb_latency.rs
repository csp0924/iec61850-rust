//! Measures the latency from a data change to the report reaching a handler.
//!
//! A server hosts a URCB whose data set holds one Boolean data attribute, with
//! the buffer time set to zero. The client connects, installs a handler and
//! runs a background dispatcher. Each sample takes a timestamp, flips the
//! value, waits for the handler and records the difference; samples do not
//! overlap. The test reports p50, p95, p99 and the maximum, and requires p95
//! to stay under the budget below.
//!
//! The buffer time is zero because a non-zero one batches the triggers of a
//! member within its window, which would be measured as latency rather than
//! the dispatch path itself.
//!
//! Reporting is enabled by setting the control block state directly rather
//! than over the wire: enabling it through `set_rcb_values` adds a reservation
//! and an enable round trip, and makes the server's dispatcher lock contend
//! with the report path. The wire path is covered by the other end-to-end
//! tests.

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
use std::sync::Arc;
use std::time::{Duration, Instant};

// Fixture, as in the other URCB tests but with the buffer time set to zero.

const TEST_RPT_ID: &str = "IED1LD0/GGIO1$RP$urcb_latency";

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

fn register_urcb(server: &IedServer) -> (DataAttribute, String) {
    let da = DataAttribute::new(
        "stVal",
        FC::St,
        DataAttributeType::Boolean,
        TrgOps::DCHG,
        MmsValue::Boolean(false),
    );
    let entry = DatasetEntry::new(
        "IED1LD0/GGIO1$ST$Ind1$stVal".to_string(),
        Arc::clone(&da.value),
    );
    let mut ds = Dataset::new("GGIO1$ds_lat");
    ds.push(entry);

    let rcb = Rcb::new("urcb_latency", "GGIO1$ds_lat")
        .with_rpt_id(TEST_RPT_ID)
        .with_trg_ops(TriggerOptions::DATA_CHANGED)
        .with_buf_tm_ms(0);
    let mms_path = "IED1LD0/GGIO1$RP$urcb_latency".to_string();
    let rc = ReportControl::new(&mms_path, rcb);
    server.register_urcb(rc, ds).expect("register_urcb");
    (da, mms_path)
}

fn enable_urcb_direct(server: &IedServer, mms_path: &str, conn_id: u64) {
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

// Measurement.

const N_SAMPLES: usize = 50;
const PER_SAMPLE_TIMEOUT: Duration = Duration::from_secs(2);
const P95_BUDGET_MS: u128 = 100;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn urcb_data_change_latency_p95_under_100ms() {
    let server = build_server();
    let (da, mms_path) = register_urcb(&server);
    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    let mms = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    let conn = IedConnection::with_mms_client(mms);
    conn.connect("127.0.0.1", port)
        .await
        .expect("client.connect");

    // The handler sends a timestamp; the main task computes the difference.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Instant>();
    let tx_for_cb = tx.clone();
    let cb: ReportCallback = Arc::new(move |_snap: Arc<ClientReport>| {
        // Do no work in the handler beyond taking the timestamp.
        let _ = tx_for_cb.send(Instant::now());
    });
    conn.install_report_handler(Some(TEST_RPT_ID.to_string()), &mms_path, None, cb)
        .await
        .expect("install");

    // A short poll interval keeps the measured latency close to the dispatch
    // cost itself; too short and it contends with the update path.
    let dispatcher = conn.spawn_report_dispatcher(Duration::from_millis(20));

    enable_urcb_direct(&server, &mms_path, conn_id_first());

    // One warm-up round, excluded from the samples, to settle lazy setup.
    server
        .update_boolean(&da, true)
        .expect("update_boolean warmup");
    let _warm = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("warmup callback timeout")
        .expect("warmup channel closed");

    // The measured samples.
    let mut samples: Vec<Duration> = Vec::with_capacity(N_SAMPLES);
    let mut state = true;
    for i in 0..N_SAMPLES {
        state = !state;
        let t0 = Instant::now();
        server.update_boolean(&da, state).expect("update");
        let t1 = tokio::time::timeout(PER_SAMPLE_TIMEOUT, rx.recv())
            .await
            .unwrap_or_else(|_| panic!("sample #{i} timed out waiting for the handler"))
            .unwrap_or_else(|| panic!("sample #{i} channel closed"));
        samples.push(t1.saturating_duration_since(t0));
    }

    let _ = conn.disconnect().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), dispatcher).await;
    handle.stop().await;
    drop(tx);

    samples.sort();
    let p50 = samples[N_SAMPLES / 2];
    let p95 = samples[(N_SAMPLES * 95) / 100];
    let p99 = samples[(N_SAMPLES * 99) / 100];
    let max = *samples.last().unwrap();

    println!(
        "URCB latency over N={N_SAMPLES}: p50={:?} p95={:?} p99={:?} max={:?}",
        p50, p95, p99, max
    );

    assert!(
        p95.as_millis() < P95_BUDGET_MS,
        "p95 latency {}ms should be below {} ms (max={:?})",
        p95.as_millis(),
        P95_BUDGET_MS,
        max
    );
}

/// The identifier of the first accepted connection. The server numbers them
/// from one and this test owns its server.
fn conn_id_first() -> u64 {
    1
}
