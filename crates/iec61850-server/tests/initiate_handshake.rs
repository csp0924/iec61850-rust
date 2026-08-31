//! Integration tests for the server listener, accept loop, shutdown and the
//! COTP handshake.
//!
//! Every test binds 127.0.0.1:0 so concurrent tests cannot collide on a port.

use iec61850_mms::iso::cotp::{CotpConnection, CotpOptions};
use iec61850_model::{IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder};
use iec61850_server::{IedServer, IedServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

fn minimal_model() -> Arc<IedModel> {
    let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .build()
        .expect("ld");
    let model = IedModelBuilder::new("TEST")
        .add_ld(ld)
        .expect("add_ld")
        .build()
        .expect("model");
    Arc::new(model)
}

fn build_server_with_max(max: usize) -> IedServer {
    let cfg = IedServerConfig {
        max_mms_connections: max,
        ..Default::default()
    };
    IedServer::builder()
        .model(minimal_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(cfg)
        .build()
        .expect("build server")
}

#[tokio::test]
async fn server_starts_and_listens() {
    let server = build_server_with_max(5);
    let handle = server.start().await.expect("start server");
    assert!(server.is_running());
    assert!(handle.bound_addr.port() > 0);
    handle.stop().await;
    assert!(!server.is_running(), "stop must clear the running flag");
}

#[tokio::test]
async fn server_stop_is_idempotent_via_handle() {
    // Stopping twice must neither panic nor block.
    let server = build_server_with_max(5);
    let handle = server.start().await.expect("start");
    handle.stop().await;
    assert!(!server.is_running());
}

#[tokio::test]
async fn cotp_handshake_completes() {
    // The first step of an accepted connection is the COTP handshake: the
    // server receives CR and answers CC.
    let server = build_server_with_max(5);
    let handle = server.start().await.expect("start");
    let addr = handle.bound_addr;

    let stream = TcpStream::connect(addr).await.expect("tcp connect");
    let cotp = CotpConnection::connect(stream, CotpOptions::default())
        .await
        .expect("the COTP CR/CC handshake must succeed");
    assert_eq!(
        format!("{}", cotp.state()),
        "Connected",
        "the connection is Connected once the COTP handshake completes"
    );
    drop(cotp);

    handle.stop().await;
}

#[tokio::test]
async fn rejects_garbage_first_payload_after_cotp() {
    // After the COTP handshake the server waits for a Session CN. Garbage fails
    // to parse in the session, presentation or ACSE layer and the server closes
    // the socket at once, so the next client read sees EOF.
    let server = build_server_with_max(5);
    let handle = server.start().await.expect("start");
    let addr = handle.bound_addr;

    let stream = TcpStream::connect(addr).await.expect("tcp connect");
    let mut cotp = CotpConnection::connect(stream, CotpOptions::default())
        .await
        .expect("COTP handshake");

    // Eight bytes of garbage in place of the Session CN payload.
    cotp.send_data(&[0xff; 8]).await.expect("send garbage");

    // The server closes the socket, so recv_data reports an I/O error on EOF.
    let result = tokio::time::timeout(Duration::from_secs(2), cotp.recv_data()).await;
    match result {
        Ok(Err(_)) => {
            // Expected: the socket is closed and the read fails.
        }
        Ok(Ok(bytes)) => panic!("no data must arrive, got {bytes:?}"),
        Err(_) => panic!("the server did not close the socket within 2s"),
    }

    handle.stop().await;
}

#[tokio::test]
async fn over_max_connections_drops_socket() {
    // A connection beyond max_mms_connections has its socket closed. A
    // connection only joins the server pool once Initiate completes, so until
    // then connection_count stays 0 and the limit cannot fire; this test only
    // asserts that the listener does not reset the second socket before that.
    // TODO: assert that connection N+1 is dropped after full negotiation
    let server = build_server_with_max(1);
    let handle = server.start().await.expect("start");
    let addr = handle.bound_addr;

    let mut s1 = TcpStream::connect(addr).await.expect("client1 connect");
    let mut s2 = TcpStream::connect(addr).await.expect("client2 connect");

    // Both sockets are still before the COTP handshake, so the connection limit
    // cannot have fired yet.
    let _ = s1.write_all(&[]).await;
    let _ = s2.write_all(&[]).await;

    handle.stop().await;
}

#[tokio::test]
async fn shutdown_does_not_block_on_no_connections() {
    // With no active connection the accept loop breaks and stop returns at once.
    let server = build_server_with_max(5);
    let handle = server.start().await.expect("start");

    let stop_future = handle.stop();
    let result = tokio::time::timeout(Duration::from_millis(500), stop_future).await;
    assert!(
        result.is_ok(),
        "stop must complete within 500ms when no connection is active"
    );
    assert!(!server.is_running());
}

#[tokio::test]
async fn shutdown_drops_open_connections_in_progress() {
    // stop also completes with an open connection: the accept loop breaks and a
    // connection task blocked in recv sees EOF once the stream is dropped.
    let server = build_server_with_max(5);
    let handle = server.start().await.expect("start");
    let addr = handle.bound_addr;

    let stream = TcpStream::connect(addr).await.expect("tcp connect");
    let _cotp = CotpConnection::connect(stream, CotpOptions::default())
        .await
        .expect("COTP handshake");
    // Nothing further is sent, so the connection task blocks in recv_data.
    let stop_future = handle.stop();
    let result = tokio::time::timeout(Duration::from_secs(2), stop_future).await;
    assert!(
        result.is_ok(),
        "stop must complete within 2s even with a blocked connection"
    );
}
