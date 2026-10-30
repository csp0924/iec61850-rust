//! Integration test: datagrams outside the plain 48-octet client exchange,
//! over a real UDP socket.

use std::net::SocketAddr;
use std::time::Duration;

use iec61850_sntp::{Mode, NtpTimestamp, SntpClient, SntpPacket, SntpServer};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const REPLY_TIMEOUT: Duration = Duration::from_secs(3);

async fn spawn_server() -> (SocketAddr, JoinHandle<std::io::Result<()>>) {
    let server = SntpServer::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind server");
    let addr = server.local_addr().expect("local_addr");
    (addr, tokio::spawn(server.run()))
}

async fn assert_still_serving(addr: SocketAddr, task: &JoinHandle<std::io::Result<()>>) {
    let r = SntpClient::new(addr).query(REPLY_TIMEOUT).await;
    assert!(!task.is_finished(), "the receive loop ended");
    assert!(r.is_ok(), "query failed: {r:?}");
}

async fn exchange(sock: &UdpSocket, addr: SocketAddr, wire: &[u8]) -> SntpPacket {
    sock.send_to(wire, addr).await.expect("send");
    let mut buf = [0u8; 1024];
    let (len, _) = timeout(REPLY_TIMEOUT, sock.recv_from(&mut buf))
        .await
        .expect("reply in time")
        .expect("recv");
    SntpPacket::decode(&buf[..len]).expect("decode reply")
}

#[tokio::test]
async fn request_with_an_authenticator_is_answered() {
    let (addr, task) = spawn_server().await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let mut req = SntpPacket::client_request();
    req.transmit_ts = NtpTimestamp {
        seconds: 0xDEAD_BEEF,
        fraction: 1,
    };
    // Key identifier and a 128-bit digest (RFC 4330 section 3): 68 octets.
    let mut wire = req.encode().to_vec();
    wire.extend_from_slice(&[0u8; 20]);

    let reply = exchange(&sock, addr, &wire).await;
    assert_eq!(reply.mode, Mode::Server);
    assert_eq!(reply.originate_ts, req.transmit_ts);
    assert_still_serving(addr, &task).await;
}

#[tokio::test]
async fn datagram_longer_than_the_buffer_does_not_stop_the_server() {
    let (addr, task) = spawn_server().await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let mut wire = SntpPacket::client_request().encode().to_vec();
    wire.resize(4096, 0);
    sock.send_to(&wire, addr).await.expect("send");
    assert_still_serving(addr, &task).await;
}

#[tokio::test]
async fn reply_to_a_closed_port_does_not_stop_the_server() {
    let (addr, task) = spawn_server().await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let req = SntpPacket::client_request().encode();
    exchange(&sock, addr, &req).await;
    // The reply to this request reaches a port that no longer exists, which
    // makes some platforms report an ICMP port unreachable on a later
    // receive.
    sock.send_to(&req, addr).await.expect("send");
    drop(sock);

    for _ in 0..3 {
        assert_still_serving(addr, &task).await;
    }
}

#[tokio::test]
async fn symmetric_active_request_gets_a_symmetric_passive_reply() {
    let (addr, _task) = spawn_server().await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let mut req = SntpPacket::client_request();
    req.mode = Mode::SymmetricActive;
    req.poll = 10;

    let reply = exchange(&sock, addr, &req.encode()).await;
    assert_eq!(reply.mode, Mode::SymmetricPassive);
    assert_eq!(reply.poll, 10);
}

#[tokio::test]
async fn client_request_gets_a_server_reply_with_its_poll() {
    let (addr, _task) = spawn_server().await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let mut req = SntpPacket::client_request();
    req.poll = 4;

    let reply = exchange(&sock, addr, &req.encode()).await;
    assert_eq!(reply.mode, Mode::Server);
    assert_eq!(reply.poll, 4);
}
