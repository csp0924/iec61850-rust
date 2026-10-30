//! AF_PACKET backend over a veth pair.
//!
//! These tests need `CAP_NET_RAW` and a veth pair that is up, named in
//! `IEC61850_VETH` as `<sender>,<receiver>`, so they are ignored by default.
//! IPv6 is turned off on the pair so that no other frame reaches the receiver:
//!
//! ```sh
//! ip link add vf0 type veth peer name vf1
//! sysctl -w net.ipv6.conf.vf0.disable_ipv6=1 net.ipv6.conf.vf1.disable_ipv6=1
//! ip link set vf0 up && ip link set vf1 up
//! IEC61850_VETH=vf0,vf1 cargo test -p iec61850-hal \
//!     --features ethernet-linux-afpacket --test afpacket_veth -- --ignored
//! ```

#![cfg(all(target_os = "linux", feature = "ethernet-linux-afpacket"))]

use std::time::{Duration, Instant};

use iec61850_hal::ethernet::linux::AfPacketSocket;
use iec61850_hal::ethernet::{EthernetConfig, EthernetError, EthernetSink, EthernetSource};

const DST: [u8; 6] = [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01];
/// EtherType reserved for local experiments by IEEE 802, so no other traffic
/// on the pair is mistaken for a test frame.
const TEST_ETHER_TYPE: [u8; 2] = [0x88, 0xb5];

fn pair() -> (AfPacketSocket, AfPacketSocket) {
    let names = std::env::var("IEC61850_VETH").expect("IEC61850_VETH=<sender>,<receiver>");
    let (a, b) = names.split_once(',').expect("two interface names");
    let tx = AfPacketSocket::open(&EthernetConfig::new(a)).expect("open sender");
    let rx = AfPacketSocket::open(
        &EthernetConfig::new(b)
            .with_promiscuous(true)
            .with_recv_timeout(Duration::from_millis(200)),
    )
    .expect("open receiver");
    (tx, rx)
}

/// Builds a frame with `src`, an optional 802.1Q tag, the test EtherType, a
/// marker, and padding up to `len` bytes.
fn frame(src: [u8; 6], tci: Option<u16>, marker: u8, len: usize) -> Vec<u8> {
    let mut f = Vec::with_capacity(len);
    f.extend_from_slice(&DST);
    f.extend_from_slice(&src);
    if let Some(tci) = tci {
        f.extend_from_slice(&[0x81, 0x00]);
        f.extend_from_slice(&tci.to_be_bytes());
    }
    f.extend_from_slice(&TEST_ETHER_TYPE);
    f.push(marker);
    f.resize(len, 0xa5);
    f
}

/// Receives until a test frame carrying `marker` arrives, returning it or the
/// first error, within two seconds.
fn recv_marked(
    rx: &mut AfPacketSocket,
    marker: u8,
    buf_len: usize,
) -> Result<Vec<u8>, EthernetError> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut buf = vec![0u8; buf_len];
    while Instant::now() < deadline {
        match rx.recv(&mut buf, None) {
            Ok(n) => {
                let f = &buf[..n];
                let at = if f.get(12..14) == Some(&[0x81, 0x00]) {
                    16
                } else {
                    12
                };
                if f.get(at..at + 2) == Some(&TEST_ETHER_TYPE) && f.get(at + 2) == Some(&marker) {
                    return Ok(f.to_vec());
                }
            }
            Err(EthernetError::Timeout) => {}
            Err(e) => return Err(e),
        }
    }
    panic!("no test frame with marker {marker} arrived");
}

#[test]
#[ignore = "needs CAP_NET_RAW and a veth pair named in IEC61850_VETH"]
fn zero_source_is_sent_as_the_interface_address() {
    let (mut tx, mut rx) = pair();
    let hw = tx.hw_addr().expect("veth has an ethernet address");
    tx.send(&frame([0; 6], None, 1, 64)).expect("send");
    let got = recv_marked(&mut rx, 1, 1522).expect("recv");
    assert_eq!(&got[6..12], &hw.0);
}

#[test]
#[ignore = "needs CAP_NET_RAW and a veth pair named in IEC61850_VETH"]
fn given_source_is_sent_unchanged() {
    let (mut tx, mut rx) = pair();
    let src = [0x02, 0x00, 0x00, 0x00, 0x00, 0x07];
    tx.send(&frame(src, None, 2, 64)).expect("send");
    let got = recv_marked(&mut rx, 2, 1522).expect("recv");
    assert_eq!(&got[6..12], &src);
}
