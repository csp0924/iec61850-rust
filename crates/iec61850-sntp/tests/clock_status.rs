//! Integration test: the synchronization state of the served clock, as a
//! reply over a real UDP socket reports it.

use std::net::SocketAddr;
use std::time::Duration;

use iec61850_sntp::{
    LeapIndicator, NtpTimestamp, SntpClock, SntpClockStatus, SntpPacket, SntpServer,
    SntpServerConfig, UNSYNCHRONIZED_STRATUM,
};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const REPLY_TIMEOUT: Duration = Duration::from_secs(3);
const LAST_SET: NtpTimestamp = NtpTimestamp {
    seconds: 0xE000_0000,
    fraction: 0x8000_0000,
};

async fn spawn_server(clock: SntpClock) -> SocketAddr {
    let mut config = SntpServerConfig::default();
    config.clock = clock;
    let server = SntpServer::bind_with("127.0.0.1:0".parse().unwrap(), config)
        .await
        .expect("bind server");
    let addr = server.local_addr().expect("local_addr");
    tokio::spawn(server.run());
    addr
}

async fn ask(addr: SocketAddr) -> SntpPacket {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    sock.send_to(&SntpPacket::client_request().encode(), addr)
        .await
        .expect("send");
    let mut buf = [0u8; 1024];
    let (len, _) = timeout(REPLY_TIMEOUT, sock.recv_from(&mut buf))
        .await
        .expect("reply in time")
        .expect("recv");
    SntpPacket::decode(&buf[..len]).expect("decode reply")
}

#[tokio::test]
async fn unsynchronized_clock_is_reported_with_leap_indicator_3() {
    let clock = SntpClock::new(SntpClockStatus::unsynchronized(Some(LAST_SET)));
    let addr = spawn_server(clock).await;

    let reply = ask(addr).await;
    assert_eq!(reply.leap, LeapIndicator::AlarmUnsynchronized);
    assert_eq!(reply.stratum, UNSYNCHRONIZED_STRATUM);
    assert_eq!(reply.reference_ts, LAST_SET);
}

#[tokio::test]
async fn a_running_server_reports_each_change_of_state() {
    let clock = SntpClock::new(SntpClockStatus::unsynchronized(None));
    let addr = spawn_server(clock.clone()).await;
    let reply = ask(addr).await;
    assert_eq!(reply.leap, LeapIndicator::AlarmUnsynchronized);
    assert_eq!(reply.reference_ts, NtpTimestamp::ZERO);

    clock.set(SntpClockStatus::synchronized(Some(LAST_SET)));
    let reply = ask(addr).await;
    assert_eq!(reply.leap, LeapIndicator::NoWarning);
    assert_eq!(reply.stratum, 1);
    assert_eq!(reply.reference_ts, LAST_SET);
}
