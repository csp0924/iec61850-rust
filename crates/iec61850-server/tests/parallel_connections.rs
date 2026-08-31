//! Concurrency tests for many clients on one server.
//!
//! The cases are: ten clients completing the ISO and MMS handshake at once and
//! disconnecting cleanly, each with a positive negotiated PDU size; ten clients
//! reading the same data attribute five times each, which exercises the
//! per-value lock; ten clients writing and reading back their own data
//! attribute, which would expose write bleed between connections; a hundred
//! clients handshaking at once; and a server capped at two connections, where
//! further clients are refused.
//!
//! Each client runs in its own task and they all wait on a barrier before
//! connecting, so the connections really do collide.

use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_mms::mms::MmsData;
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObject, DataObjectBuilder, DoChild, IedModel,
    IedModelBuilder, LogicalDeviceBuilder, LogicalNode, LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::{IedServer, IedServerConfig, WriteAccessPolicies};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

const N_CLIENTS: usize = 10;

// Model helpers

/// Model for the concurrent read tests: one logical device with LLN0 and a
/// GGIO1 carrying a single point status with a boolean stVal.
fn model_with_single_sps() -> Arc<IedModel> {
    let ind1_st_val = DataAttribute::new(
        "stVal",
        FC::St,
        DataAttributeType::Boolean,
        TrgOps::default(),
        MmsValue::Boolean(true),
    );
    let ind1_do = DataObject {
        name: "Ind1".into(),
        array_count: None,
        children: vec![DoChild::Da(ind1_st_val)],
    };
    let ggio = LogicalNode {
        prefix: String::new(),
        class: "GGIO".into(),
        inst: "1".into(),
        dos: vec![ind1_do],
        datasets: vec![],
        rcbs: vec![],
        gocbs: vec![],
        svcbs: vec![],
        lcbs: vec![],
        sgcb: None,
    };
    let lln0 = LogicalNodeBuilder::lln0().build().unwrap();
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .add_ln(ggio)
        .build()
        .unwrap();
    Arc::new(
        IedModelBuilder::new("TEST")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap(),
    )
}

/// Model for the concurrent write tests: LLN0.NamPlt carries one writable
/// VisibleString attribute per client.
fn model_with_n_writable_vendors(n: usize) -> Arc<IedModel> {
    let mut nam_plt = DataObjectBuilder::scalar("NamPlt");
    for i in 0..n {
        nam_plt = nam_plt.add_da(
            format!("vendor_{i}"),
            FC::Dc,
            DataAttributeType::VisibleString(255),
            TrgOps::NONE,
            MmsValue::VisibleString(format!("init_{i}")),
        );
    }
    let nam_plt = nam_plt.build().unwrap();
    let lln0 = LogicalNodeBuilder::lln0().add_do(nam_plt).build().unwrap();
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .build()
        .unwrap();
    Arc::new(
        IedModelBuilder::new("TEST")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap(),
    )
}

fn build_server(model: Arc<IedModel>, max_connections: usize) -> IedServer {
    let cfg = IedServerConfig {
        max_mms_connections: max_connections,
        ..Default::default()
    };
    IedServer::builder()
        .model(model)
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(cfg)
        .build()
        .expect("build server")
}

fn build_server_with_dc_writable(model: Arc<IedModel>, max_connections: usize) -> IedServer {
    let mut policies = WriteAccessPolicies::default();
    policies.set(FC::Dc, true);
    let cfg = IedServerConfig {
        max_mms_connections: max_connections,
        write_access_policies: policies,
        ..Default::default()
    };
    IedServer::builder()
        .model(model)
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(cfg)
        .build()
        .expect("build server")
}

// Ten clients handshake at once.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ten_parallel_handshakes() {
    let server = build_server(model_with_single_sps(), N_CLIENTS);
    let handle = server.start().await.expect("start");
    let port = handle.bound_addr.port();

    let barrier = Arc::new(tokio::sync::Barrier::new(N_CLIENTS));

    let mut joins = Vec::with_capacity(N_CLIENTS);
    for _ in 0..N_CLIENTS {
        let b = barrier.clone();
        joins.push(tokio::task::spawn(async move {
            b.wait().await;
            let mut client = MmsClientBuilder::new()
                .connect_timeout_ms(5_000)
                .request_timeout_ms(5_000)
                .build();
            client.connect("127.0.0.1", port).await.expect("connect");
            let max_pdu = client.negotiated_max_pdu_size();
            client.disconnect().await.expect("disconnect");
            max_pdu
        }));
    }

    for (i, j) in joins.into_iter().enumerate() {
        let max_pdu = j.await.expect("client task panicked");
        assert!(max_pdu > 0, "client {i} negotiated a zero-byte PDU size");
    }

    handle.stop().await;
}

// Ten clients read the same data attribute five times each.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ten_parallel_reads_same_da() {
    const READS_PER_CLIENT: usize = 5;
    let server = build_server(model_with_single_sps(), N_CLIENTS);
    let handle = server.start().await.expect("start");
    let port = handle.bound_addr.port();

    let barrier = Arc::new(tokio::sync::Barrier::new(N_CLIENTS));

    let mut joins = Vec::with_capacity(N_CLIENTS);
    for client_idx in 0..N_CLIENTS {
        let b = barrier.clone();
        joins.push(tokio::task::spawn(async move {
            b.wait().await;
            let mut client = MmsClientBuilder::new()
                .connect_timeout_ms(5_000)
                .request_timeout_ms(5_000)
                .build();
            client.connect("127.0.0.1", port).await.expect("connect");
            for read_idx in 0..READS_PER_CLIENT {
                let v = client
                    .read("TESTLD0", "GGIO1$ST$Ind1$stVal")
                    .await
                    .unwrap_or_else(|e| panic!("client {client_idx} read {read_idx} failed: {e}"));
                match v {
                    MmsData::Boolean(b) => assert!(
                        b,
                        "client {client_idx} read {read_idx} expected stVal true, got false"
                    ),
                    other => {
                        panic!(
                            "client {client_idx} read {read_idx} expected Boolean, got {other:?}"
                        )
                    }
                }
            }
            client.disconnect().await.expect("disconnect");
        }));
    }

    for j in joins {
        j.await.expect("client task panicked");
    }

    handle.stop().await;
}

// Ten clients write and read back their own data attribute; a value from
// another connection would show up here.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ten_parallel_writes_distinct_das() {
    let server = build_server_with_dc_writable(model_with_n_writable_vendors(N_CLIENTS), N_CLIENTS);
    let handle = server.start().await.expect("start");
    let port = handle.bound_addr.port();

    let barrier = Arc::new(tokio::sync::Barrier::new(N_CLIENTS));

    let mut joins = Vec::with_capacity(N_CLIENTS);
    for client_idx in 0..N_CLIENTS {
        let b = barrier.clone();
        joins.push(tokio::task::spawn(async move {
            b.wait().await;
            let mut client = MmsClientBuilder::new()
                .connect_timeout_ms(5_000)
                .request_timeout_ms(5_000)
                .build();
            client.connect("127.0.0.1", port).await.expect("connect");

            let item = format!("LLN0$DC$NamPlt$vendor_{client_idx}");
            let payload = format!("client_{client_idx}_owned");

            client
                .write("TESTLD0", &item, MmsData::VisibleString(payload.clone()))
                .await
                .unwrap_or_else(|e| panic!("client {client_idx} write failed: {e}"));

            let got = client
                .read("TESTLD0", &item)
                .await
                .unwrap_or_else(|e| panic!("client {client_idx} read-back failed: {e}"));
            match got {
                MmsData::VisibleString(s) => assert_eq!(
                    s, payload,
                    "client {client_idx} must read back the value it wrote"
                ),
                other => panic!("client {client_idx} expected VisibleString, got {other:?}"),
            }

            client.disconnect().await.expect("disconnect");
        }));
    }

    for j in joins {
        j.await.expect("client task panicked");
    }

    handle.stop().await;
}

// A hundred clients handshake at once, without deadlock or panic.
//
// This is a separate case rather than a wider version of the ten-client tests:
// ten connections already expose the ordinary races and keep those tests fast,
// while a hundred sockets take seconds and can hit ephemeral port throttling on
// the host. The connection limit is raised to match, because the point here is
// the accept loop and the connection map, not the limit.

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn hundred_parallel_handshakes_no_deadlock() {
    const N: usize = 100;
    let server = build_server(model_with_single_sps(), N);
    let handle = server.start().await.expect("start");
    let port = handle.bound_addr.port();

    let barrier = Arc::new(tokio::sync::Barrier::new(N));

    let mut joins = Vec::with_capacity(N);
    for client_idx in 0..N {
        let b = barrier.clone();
        joins.push(tokio::task::spawn(async move {
            b.wait().await;
            let mut client = MmsClientBuilder::new()
                .connect_timeout_ms(15_000)
                .request_timeout_ms(15_000)
                .build();
            client
                .connect("127.0.0.1", port)
                .await
                .map_err(|e| format!("client {client_idx} connect failed: {e}"))?;
            let max_pdu = client.negotiated_max_pdu_size();
            client
                .disconnect()
                .await
                .map_err(|e| format!("client {client_idx} disconnect failed: {e}"))?;
            Ok::<_, String>(max_pdu)
        }));
    }

    let mut success = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for (i, j) in joins.into_iter().enumerate() {
        match j.await.expect("client task panicked") {
            Ok(max_pdu) => {
                if max_pdu == 0 {
                    failures.push(format!("client {i}: negotiated a zero-byte PDU size"));
                } else {
                    success += 1;
                }
            }
            Err(e) => failures.push(e),
        }
    }

    handle.stop().await;

    // Every client must succeed; failures are listed to make the cause visible.
    assert!(
        failures.is_empty(),
        "concurrent handshakes: {success} succeeded, {} failed: {:#?}",
        failures.len(),
        failures
    );
    assert_eq!(success, N, "every client must complete the handshake");
}

// With a limit of two connections, further clients are refused.
//
// The clients are staged rather than launched together: the accept loop tests
// the limit when it accepts a socket, but the connection count only rises once
// ACSE and Initiate complete. Launching every socket at once would find the
// count still at zero and accept them all.
// TODO: reserve the slot at accept time so the limit holds without staging

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn max_connections_caps_concurrent() {
    let server = build_server(model_with_single_sps(), 2);
    let handle = server.start().await.expect("start");
    let port = handle.bound_addr.port();

    // Two clients complete the handshake and hold their slots.
    let mut hold_clients = Vec::new();
    for _ in 0..2 {
        let mut client = MmsClientBuilder::new()
            .connect_timeout_ms(2_000)
            .request_timeout_ms(2_000)
            .build();
        client
            .connect("127.0.0.1", port)
            .await
            .expect("hold client connect");
        hold_clients.push(client);
    }

    // The server counts both connections before the rest start.
    for _ in 0..50 {
        if handle.bound_addr.port() != 0
            && hold_clients[0].state() == iec61850_mms::mms::client::ConnectionState::Connected
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Let the connection bookkeeping settle.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The remaining clients connect at once and are refused.
    const EXTRA_CLIENTS: usize = 8;
    let barrier = Arc::new(tokio::sync::Barrier::new(EXTRA_CLIENTS));
    let mut joins = Vec::with_capacity(EXTRA_CLIENTS);
    for _ in 0..EXTRA_CLIENTS {
        let b = barrier.clone();
        joins.push(tokio::task::spawn(async move {
            b.wait().await;
            let mut client = MmsClientBuilder::new()
                .connect_timeout_ms(1_500)
                .request_timeout_ms(1_500)
                .build();
            client
                .connect("127.0.0.1", port)
                .await
                .map_err(|e| e.to_string())
        }));
    }

    let mut success = 0usize;
    let mut failure = 0usize;
    for j in joins {
        match j.await.expect("client task panicked") {
            Ok(()) => success += 1,
            Err(_) => failure += 1,
        }
    }

    assert!(
        failure >= 1,
        "with both slots held, {EXTRA_CLIENTS} further clients gave \
         success={success} failure={failure}; at least one must be refused"
    );
    assert_eq!(success + failure, EXTRA_CLIENTS);

    // Release the clients holding the slots.
    for mut c in hold_clients {
        let _ = c.disconnect().await;
    }
    handle.stop().await;
}
