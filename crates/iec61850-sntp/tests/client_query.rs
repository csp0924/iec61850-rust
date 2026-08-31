//! Integration test: query a locally hosted server with `SntpClient` and
//! check that the offset and the round-trip time are plausible.

use std::time::Duration;

use iec61850_sntp::{LeapIndicator, SntpClient, SntpServer};

#[tokio::test]
async fn client_query_against_local_server() {
    let server = SntpServer::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("local_addr");

    let _handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let client = SntpClient::new(server_addr);
    let resp = client
        .query(Duration::from_secs(3))
        .await
        .expect("query ok");

    assert_eq!(resp.stratum, 1, "default server config is stratum 1");
    assert_eq!(resp.version, 4);
    assert_eq!(resp.leap_indicator, LeapIndicator::NoWarning);
    assert_eq!(&resp.reference_id, b"LOCL");

    // Client and server share one machine, so the offset and round trip are
    // tiny. The 1 s bound leaves room for a busy CI machine.
    assert!(
        resp.offset_seconds.abs() < 1.0,
        "offset too large: {} s",
        resp.offset_seconds
    );
    assert!(
        resp.round_trip_seconds.abs() < 1.0,
        "rtt too large: {} s",
        resp.round_trip_seconds
    );
    // Neither derived timestamp may come back as NaN.
    assert!(resp.server_time_unix_s.is_finite());
    assert!(resp.client_receive_unix_s.is_finite());
}

#[tokio::test]
async fn client_query_times_out_when_no_server() {
    // The socket is bound but never served, so the client must time out.
    let dead = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind dead socket");
    let dead_addr = dead.local_addr().expect("local_addr");

    let client = SntpClient::new(dead_addr);
    let err = client
        .query(Duration::from_millis(200))
        .await
        .expect_err("expected timeout");
    let msg = format!("{err}");
    assert!(
        msg.contains("timed out") || msg.contains("I/O"),
        "msg={msg}"
    );
}
