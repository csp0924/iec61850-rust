//! pcap backend receive timeouts on a quiet veth interface.
//!
//! The test needs libpcap, `CAP_NET_RAW` and a veth pair that is up, named in
//! `IEC61850_VETH` as `<sender>,<receiver>`, so it is ignored by default:
//!
//! ```sh
//! ip link add vf0 type veth peer name vf1
//! ip link set vf0 up && ip link set vf1 up
//! IEC61850_VETH=vf0,vf1 cargo test -p iec61850-hal --features ethernet-pcap \
//!     --test pcap_veth -- --ignored
//! ```

#![cfg(all(target_os = "linux", feature = "ethernet-pcap"))]

use std::sync::mpsc;
use std::time::{Duration, Instant};

use iec61850_hal::ethernet::pcap::PcapSocket;
use iec61850_hal::ethernet::{EthernetConfig, EthernetError, EthernetSource};

/// Receives once on the receiving end of the veth pair with `timeout`, from a
/// socket opened with `cfg_timeout`, and returns the result and how long the
/// call took. A call that never returns fails the test after 10 s.
fn recv_once(
    cfg_timeout: Option<Duration>,
    timeout: Option<Duration>,
) -> (Result<usize, EthernetError>, Duration) {
    let names = std::env::var("IEC61850_VETH").expect("IEC61850_VETH=<sender>,<receiver>");
    let (_, b) = names.split_once(',').expect("two interface names");
    let mut cfg = EthernetConfig::new(b);
    if let Some(d) = cfg_timeout {
        cfg = cfg.with_recv_timeout(d);
    }
    let (done, result) = mpsc::channel();
    std::thread::spawn(move || {
        let mut sock = PcapSocket::open(&cfg).expect("open pcap on the receiver");
        let mut buf = [0u8; 1522];
        let started = Instant::now();
        let r = sock.recv(&mut buf, timeout);
        let _ = done.send((r, started.elapsed()));
    });
    result
        .recv_timeout(Duration::from_secs(10))
        .expect("recv did not return")
}

#[test]
#[ignore = "needs libpcap, CAP_NET_RAW and a veth pair named in IEC61850_VETH"]
fn per_call_timeout_is_honored_without_a_configured_one() {
    let (r, took) = recv_once(None, Some(Duration::from_millis(300)));
    assert_eq!(r, Err(EthernetError::Timeout));
    assert!(
        took >= Duration::from_millis(300),
        "returned after {took:?}"
    );
}

#[test]
#[ignore = "needs libpcap, CAP_NET_RAW and a veth pair named in IEC61850_VETH"]
fn per_call_timeout_overrides_a_longer_configured_one() {
    let (r, took) = recv_once(
        Some(Duration::from_secs(30)),
        Some(Duration::from_millis(200)),
    );
    assert_eq!(r, Err(EthernetError::Timeout));
    assert!(
        took >= Duration::from_millis(200),
        "returned after {took:?}"
    );
}

#[test]
#[ignore = "needs libpcap, CAP_NET_RAW and a veth pair named in IEC61850_VETH"]
fn configured_timeout_applies_when_the_call_gives_none() {
    let (r, took) = recv_once(Some(Duration::from_millis(250)), None);
    assert_eq!(r, Err(EthernetError::Timeout));
    assert!(
        took >= Duration::from_millis(250),
        "returned after {took:?}"
    );
}
