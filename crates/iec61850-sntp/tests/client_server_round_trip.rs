//! Integration test: host a server, send a client packet and check the reply.

use std::time::Duration;

use iec61850_sntp::{Mode, NtpTimestamp, SntpPacket, SntpServer, SNTP_PACKET_LEN};
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[tokio::test]
async fn server_replies_to_client_request() {
    let server = SntpServer::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("local_addr");

    // Spawn the server task; it is dropped when the test ends.
    let _handle = tokio::spawn(async move {
        // The run result is ignored on purpose; the test ends on its own timeout.
        let _ = server.run().await;
    });

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");

    // The magic transmit timestamp proves the server echoed it into originate.
    let magic_xmit = NtpTimestamp {
        seconds: 0xDEAD_BEEF,
        fraction: 0xCAFE_BABE,
    };
    let mut req = SntpPacket::client_request();
    req.transmit_ts = magic_xmit;
    let req_bytes = req.encode();

    client
        .send_to(&req_bytes, server_addr)
        .await
        .expect("send req");

    let mut reply_buf = [0u8; SNTP_PACKET_LEN];
    let (len, _peer) = timeout(Duration::from_secs(5), client.recv_from(&mut reply_buf))
        .await
        .expect("reply within 5s")
        .expect("recv ok");
    assert_eq!(len, SNTP_PACKET_LEN);

    let reply = SntpPacket::decode(&reply_buf).expect("decode reply");
    assert_eq!(reply.mode, Mode::Server);
    assert_eq!(reply.version, 4);
    assert_eq!(
        reply.originate_ts, magic_xmit,
        "must echo client transmit_ts"
    );
    assert_ne!(reply.transmit_ts, NtpTimestamp::ZERO);
    assert_ne!(reply.receive_ts, NtpTimestamp::ZERO);
    assert_eq!(reply.stratum, 1);
}

#[tokio::test]
async fn server_drops_short_packet() {
    let server = SntpServer::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind");
    let server_addr = server.local_addr().expect("local_addr");

    let _handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    // Deliberately too short: the server warns and drops it, so no reply arrives.
    client
        .send_to(&[0u8; 10], server_addr)
        .await
        .expect("send short");

    let mut buf = [0u8; SNTP_PACKET_LEN];
    let res = timeout(Duration::from_millis(500), client.recv_from(&mut buf)).await;
    assert!(res.is_err(), "expected no reply for short packet");
}
