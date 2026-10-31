//! Sampled Values publish and receive over an AF_PACKET veth pair.
//!
//! The test needs `CAP_NET_RAW` and a veth pair that is up, named in
//! `IEC61850_VETH` as `<sender>,<receiver>`, so it is ignored by default:
//!
//! ```sh
//! ip link add vf0 type veth peer name vf1
//! ip link set vf0 up && ip link set vf1 up
//! IEC61850_VETH=vf0,vf1 cargo test -p iec61850-sv --test afpacket_veth -- --ignored
//! ```

#![cfg(target_os = "linux")]

use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use iec61850_hal::ethernet::linux::AfPacketSocket;
use iec61850_hal::ethernet::{EthernetConfig, EthernetSink};
use iec61850_sv::{SvPublisherBuilder, SvReceiver, SvSubscriberBuilder};

#[test]
#[ignore = "needs CAP_NET_RAW and a veth pair named in IEC61850_VETH"]
fn simulate_bit_crosses_the_wire() {
    let names = std::env::var("IEC61850_VETH").expect("IEC61850_VETH=<sender>,<receiver>");
    let (a, b) = names.split_once(',').expect("two interface names");
    let mut tx = AfPacketSocket::open(&EthernetConfig::new(a)).expect("open sender");
    let rx = AfPacketSocket::open(&EthernetConfig::new(b).with_promiscuous(true))
        .expect("open receiver");

    let (send_seen, seen) = mpsc::channel::<(u16, bool)>();
    let sub = SvSubscriberBuilder::new()
        .sv_id("vethSV")
        .listener(move |a| {
            let _ = send_seen.send((a.smp_cnt, a.simulate));
        })
        .build();
    let mut receiver = SvReceiver::new();
    receiver.add_subscriber(Arc::new(sub));
    let handle = receiver.start_thread(Box::new(rx));

    let mut builder = SvPublisherBuilder::new([0x02, 0, 0, 0, 0, 0x51]);
    let h = builder.add_asdu("vethSV", None::<&str>, 1, 8).unwrap();
    let mut publisher = builder.setup_complete().unwrap();
    tx.send(publisher.frame_bytes()).expect("send original");
    publisher.set_simulate(true);
    publisher.increase_smp_cnt(h).unwrap();
    tx.send(publisher.frame_bytes()).expect("send simulated");

    let first = seen
        .recv_timeout(Duration::from_secs(2))
        .expect("the original frame was not received");
    let second = seen
        .recv_timeout(Duration::from_secs(2))
        .expect("the simulated frame was not received");
    handle.stop_and_join();
    assert_eq!(first, (0, false));
    assert_eq!(second, (1, true));
}
