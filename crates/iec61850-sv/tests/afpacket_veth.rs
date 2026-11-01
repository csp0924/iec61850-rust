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
use iec61850_hal::ethernet::{EthernetConfig, EthernetSink, EthernetSource};
use iec61850_model::comm::Address;
use iec61850_sv::{SvFrame, SvPublisherBuilder, SvReceiver, SvSubscriberBuilder};

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

#[test]
#[ignore = "needs CAP_NET_RAW and a veth pair named in IEC61850_VETH"]
fn default_tagged_frame_arrives_with_its_tag() {
    let names = std::env::var("IEC61850_VETH").expect("IEC61850_VETH=<sender>,<receiver>");
    let (a, b) = names.split_once(',').expect("two interface names");
    let mut tx = AfPacketSocket::open(&EthernetConfig::new(a)).expect("open sender");
    let mut rx = AfPacketSocket::open(
        &EthernetConfig::new(b)
            .with_promiscuous(true)
            .with_recv_timeout(Duration::from_millis(200)),
    )
    .expect("open receiver");

    let mut builder = SvPublisherBuilder::new([0x02, 0, 0, 0, 0, 0x52]);
    builder.add_asdu("vethTag", None::<&str>, 1, 8).unwrap();
    let publisher = builder.setup_complete().unwrap();
    tx.send(publisher.frame_bytes()).expect("send");

    // Other traffic may share the link; wait for the SV frame.
    let mut buf = [0u8; 1522];
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let frame = loop {
        assert!(
            std::time::Instant::now() < deadline,
            "the frame was not received"
        );
        let Ok(n) = rx.recv(&mut buf, None) else {
            continue;
        };
        if let Ok(f) = SvFrame::decode(&buf[..n]) {
            break f;
        }
    };
    let tag = frame.header.vlan.expect("the default 802.1q tag was lost");
    assert_eq!(tag.priority.value(), 4);
    assert_eq!(tag.vlan_id, 0);
}

#[test]
#[ignore = "needs CAP_NET_RAW and a veth pair named in IEC61850_VETH"]
fn scl_address_reaches_the_wire() {
    let names = std::env::var("IEC61850_VETH").expect("IEC61850_VETH=<sender>,<receiver>");
    let (a, b) = names.split_once(',').expect("two interface names");
    let mut tx = AfPacketSocket::open(&EthernetConfig::new(a)).expect("open sender");
    let mut rx = AfPacketSocket::open(
        &EthernetConfig::new(b)
            .with_promiscuous(true)
            .with_recv_timeout(Duration::from_millis(200)),
    )
    .expect("open receiver");

    let mut address = Address::new();
    for (t, v) in [
        ("MAC-Address", "01-0C-CD-04-00-07"),
        ("APPID", "4007"),
        ("VLAN-ID", "005"),
        ("VLAN-PRIORITY", "6"),
    ] {
        address.push(t, v).expect("valid parameter");
    }
    let mut builder = SvPublisherBuilder::new([0x02, 0, 0, 0, 0, 0x53])
        .with_address(&address)
        .expect("readable address");
    builder.add_asdu("vethAddr", None::<&str>, 1, 8).unwrap();
    let publisher = builder.setup_complete().unwrap();
    tx.send(publisher.frame_bytes()).expect("send");

    // Other traffic may share the link; wait for this stream.
    let mut buf = [0u8; 1522];
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let frame = loop {
        assert!(
            std::time::Instant::now() < deadline,
            "the frame was not received"
        );
        let Ok(n) = rx.recv(&mut buf, None) else {
            continue;
        };
        if let Ok(f) = SvFrame::decode(&buf[..n]) {
            if f.header.app_id == 0x4007 {
                break f;
            }
        }
    };
    assert_eq!(frame.header.dst_mac, [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x07]);
    let tag = frame.header.vlan.expect("the 802.1q tag was lost");
    assert_eq!(tag.priority.value(), 6);
    assert_eq!(tag.vlan_id, 5);
}
