//! End-to-end test of the URCB reservation contest between two clients.
//!
//! The whole sequence runs over the wire:
//!
//! 1. Client A writes `Resv = true` and takes the reservation, so the control
//!    block records A as its owner.
//! 2. Client B writes `Resv = true` on the same control block and receives
//!    `DataAccessError::TemporarilyUnavailable`; the server state is unchanged.
//! 3. Client A writes `Resv = false` and releases the reservation.
//! 4. Client B retries and succeeds, and the owner becomes B.
//!
//! Per IEC 61850-7-2, a reserved unbuffered control block may only be written
//! by the association holding the reservation. The unit tests cover the server
//! side; this test covers the whole path from the client write through the
//! dispatcher to the access error encoded back to the client.

use iec61850_client::rcb::{RcbHandle, RcbWriteMask};
use iec61850_client::{ClientError, IedConnection};
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
use std::time::Duration;

const RPT_MMS_PATH: &str = "IED1LD0/GGIO1$RP$urcb_compete";

fn build_model() -> Arc<IedModel> {
    let lln0 = LogicalNodeBuilder::lln0().build().unwrap();
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .build()
        .unwrap();
    Arc::new(
        IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap(),
    )
}

fn build_server() -> IedServer {
    IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig {
            max_mms_connections: 5,
            ..Default::default()
        })
        .build()
        .unwrap()
}

fn register_urcb(server: &IedServer) -> DataAttribute {
    let da = DataAttribute::new(
        "stVal",
        FC::St,
        DataAttributeType::Boolean,
        TrgOps::DCHG,
        MmsValue::Boolean(false),
    );
    let mut ds = Dataset::new("GGIO1$ds_compete");
    ds.push(DatasetEntry::new(
        "IED1LD0/GGIO1$ST$Ind1$stVal".to_string(),
        Arc::clone(&da.value),
    ));
    let rcb = Rcb::new("urcb_compete", "GGIO1$ds_compete")
        .with_rpt_id(RPT_MMS_PATH)
        .with_trg_ops(TriggerOptions::DATA_CHANGED);
    server
        .register_urcb(ReportControl::new(RPT_MMS_PATH, rcb), ds)
        .unwrap();
    da
}

/// Waits until the server reports at least `target` connections.
async fn wait_for_connections(server: &IedServer, target: usize, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if server.connection_count() >= target {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!(
        "timed out waiting for connection_count >= {target} (current = {})",
        server.connection_count()
    );
}

/// Reads the reservation flag and owner of a report control block.
fn read_resv_state(server: &IedServer, mms_path: &str) -> (bool, Option<u64>) {
    let engine = server.reporting_engine();
    let engine_g = engine.lock().unwrap();
    let rc_arc = engine_g
        .get_rcb(mms_path)
        .expect("RCB should be registered");
    let rc = rc_arc.lock().unwrap();
    let s = rc.state.lock().unwrap();
    (s.resv, s.client_conn_id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dual_client_urcb_resv_competition_then_handover() {
    let server = build_server();
    let _da = register_urcb(&server);
    let handle = server.start().await.unwrap();
    let port = handle.bound_addr.port();

    // Connect client A.
    let mms_a = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    let conn_a = IedConnection::with_mms_client(mms_a);
    conn_a.connect("127.0.0.1", port).await.unwrap();

    // Wait until the server has completed A's association.
    wait_for_connections(&server, 1, Duration::from_secs(3)).await;

    // Connect client B.
    let mms_b = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    let conn_b = IedConnection::with_mms_client(mms_b);
    conn_b.connect("127.0.0.1", port).await.unwrap();
    wait_for_connections(&server, 2, Duration::from_secs(3)).await;

    // Connections are numbered from one in order of acceptance.
    let id_a: u64 = 1;
    let id_b: u64 = 2;

    // A takes the reservation.
    let mut rcb_a = RcbHandle::new(RPT_MMS_PATH).unwrap();
    rcb_a.set_resv(true);
    let res_a = tokio::time::timeout(
        Duration::from_secs(3),
        conn_a.set_rcb_values(&rcb_a, RcbWriteMask::RESV, false),
    )
    .await
    .expect("A set_rcb_values should finish within 3s");
    res_a.expect("A should reserve the control block");

    let (resv, owner) = read_resv_state(&server, RPT_MMS_PATH);
    assert!(resv, "Resv should be true after A reserved");
    assert_eq!(owner, Some(id_a), "the owner should be A after A reserved");

    // B attempts the reservation and is refused.
    let mut rcb_b = RcbHandle::new(RPT_MMS_PATH).unwrap();
    rcb_b.set_resv(true);
    let res_b = tokio::time::timeout(
        Duration::from_secs(3),
        conn_b.set_rcb_values(&rcb_b, RcbWriteMask::RESV, false),
    )
    .await
    .expect("B set_rcb_values should finish within 3s");
    let err_b = res_b.expect_err("B should be refused the reservation");
    match &err_b {
        ClientError::DataAccessError(iec61850_mms::DataAccessError::TemporarilyUnavailable) => {}
        other => {
            panic!("B should receive DataAccessError(TemporarilyUnavailable), got {other:?}")
        }
    }

    // A failed contest must leave the owner unchanged.
    let (resv2, owner2) = read_resv_state(&server, RPT_MMS_PATH);
    assert!(resv2, "Resv should still be true after B was refused");
    assert_eq!(
        owner2,
        Some(id_a),
        "the owner should not change when a contest fails"
    );

    // A releases the reservation; with reporting disabled the owner is cleared.
    rcb_a.set_resv(false);
    let res_release = tokio::time::timeout(
        Duration::from_secs(3),
        conn_a.set_rcb_values(&rcb_a, RcbWriteMask::RESV, false),
    )
    .await
    .expect("A release should finish within 3s");
    res_release.expect("A should release the reservation");

    let (resv3, owner3) = read_resv_state(&server, RPT_MMS_PATH);
    assert!(!resv3, "Resv should be false after A released");
    assert_eq!(owner3, None, "the owner should be cleared after A released");

    // B retries and succeeds.
    let res_b_retry = tokio::time::timeout(
        Duration::from_secs(3),
        conn_b.set_rcb_values(&rcb_b, RcbWriteMask::RESV, false),
    )
    .await
    .expect("B retry should finish within 3s");
    res_b_retry.expect("B should reserve once A has released");

    let (resv4, owner4) = read_resv_state(&server, RPT_MMS_PATH);
    assert!(resv4, "Resv should be true after B reserved");
    assert_eq!(
        owner4,
        Some(id_b),
        "the owner should become B after its retry succeeded"
    );

    let _ = conn_a.disconnect().await;
    let _ = conn_b.disconnect().await;
    handle.stop().await;
}
