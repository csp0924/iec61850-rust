//! GOOSE publish and receive over an AF_PACKET veth pair.
//!
//! The test needs `CAP_NET_RAW` and a veth pair that is up, named in
//! `IEC61850_VETH` as `<sender>,<receiver>`, so it is ignored by default:
//!
//! ```sh
//! ip link add vf0 type veth peer name vf1
//! ip link set vf0 up && ip link set vf1 up
//! IEC61850_VETH=vf0,vf1 cargo test -p iec61850-goose --test afpacket_veth -- --ignored
//! ```

#![cfg(target_os = "linux")]

use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use iec61850_goose::frame::{VlanPriority, VlanTag};
use iec61850_goose::publisher::{CommParameters, GoosePublisher};
use iec61850_goose::{GooseEvent, GooseReceiver, GooseSubscriberBuilder, GooseSubscriberState};
use iec61850_hal::ethernet::linux::AfPacketSocket;
use iec61850_hal::ethernet::{EthernetConfig, EthernetSink};
use iec61850_model::MmsValue;

/// Opens the sending and the receiving end of the veth pair.
fn veth_pair() -> (AfPacketSocket, AfPacketSocket) {
    let names = std::env::var("IEC61850_VETH").expect("IEC61850_VETH=<sender>,<receiver>");
    let (a, b) = names.split_once(',').expect("two interface names");
    let tx = AfPacketSocket::open(&EthernetConfig::new(a)).expect("open sender");
    let rx = AfPacketSocket::open(&EthernetConfig::new(b).with_promiscuous(true))
        .expect("open receiver");
    (tx, rx)
}

/// Starts a receiver with `sub` on `rx` and returns the states its first
/// publication of each state delivers.
fn listen(
    rx: AfPacketSocket,
    sub: GooseSubscriberBuilder,
) -> (
    iec61850_goose::GooseReceiverHandle,
    mpsc::Receiver<Arc<GooseSubscriberState>>,
) {
    let (send_state, states) = mpsc::channel::<Arc<GooseSubscriberState>>();
    let sub = sub
        .listener(move |e: GooseEvent| {
            if let GooseEvent::NewState { state, .. } | GooseEvent::Retransmission { state, .. } = e
            {
                let _ = send_state.send(state);
            }
        })
        .build();
    let mut receiver = GooseReceiver::new();
    receiver.add_subscriber(sub);
    (receiver.start_thread(Box::new(rx)), states)
}

#[test]
#[ignore = "needs CAP_NET_RAW and a veth pair named in IEC61850_VETH"]
fn simulation_flag_crosses_the_wire_in_pdu_and_header() {
    let (mut tx, rx) = veth_pair();
    let (handle, states) = listen(
        rx,
        GooseSubscriberBuilder::new()
            .gocb_ref("LD/LLN0$GO$vsim")
            .app_id(0x1002),
    );

    let comm = CommParameters::new(0x1002, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x02]);
    let mut publisher =
        GoosePublisher::new(comm, "LD/LLN0$GO$vsim", None, "LD/LLN0$ds", 1).unwrap();
    publisher.set_simulation(true);
    let frame = publisher.publish(&[MmsValue::Boolean(true)]).unwrap();
    tx.send(&frame).expect("send");

    let state = states
        .recv_timeout(Duration::from_secs(2))
        .expect("the simulated publication was not received");
    handle.stop_and_join();
    assert!(state.simulation, "pdu simulation member");
    assert!(state.frame_simulation, "reserved1 s bit");
}

#[test]
#[ignore = "needs CAP_NET_RAW and a veth pair named in IEC61850_VETH"]
fn appid_only_subscription_drops_other_appids_on_the_wire() {
    let (mut tx, rx) = veth_pair();
    let (handle, states) = listen(rx, GooseSubscriberBuilder::new().app_id(0x1003));

    let dst = [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x03];
    let mut other = GoosePublisher::new(
        CommParameters::new(0x1004, dst),
        "LD/LLN0$GO$other",
        None,
        "LD/LLN0$ds",
        1,
    )
    .unwrap();
    let mut wanted = GoosePublisher::new(
        CommParameters::new(0x1003, dst),
        "LD/LLN0$GO$wanted",
        None,
        "LD/LLN0$ds",
        1,
    )
    .unwrap();
    // The unwanted APPID goes first, so it would be the first delivery if
    // the filter let it through.
    tx.send(&other.publish(&[MmsValue::Boolean(true)]).unwrap())
        .expect("send other");
    tx.send(&wanted.publish(&[MmsValue::Boolean(true)]).unwrap())
        .expect("send wanted");

    let state = states
        .recv_timeout(Duration::from_secs(2))
        .expect("the matching publication was not received");
    handle.stop_and_join();
    assert_eq!(state.gocb_ref, "LD/LLN0$GO$wanted");
    assert!(states.try_recv().is_err(), "nothing else was delivered");
}

#[test]
#[ignore = "needs CAP_NET_RAW and a veth pair named in IEC61850_VETH"]
fn published_frame_arrives_with_vlan_tag_and_interface_source() {
    let (mut tx, rx) = veth_pair();
    let hw = tx.hw_addr().expect("veth has an ethernet address");

    let (send_state, states) = mpsc::channel::<Arc<GooseSubscriberState>>();
    let sub = GooseSubscriberBuilder::new()
        .gocb_ref("LD/LLN0$GO$veth")
        .app_id(0x1001)
        .listener(move |e: GooseEvent| {
            if let GooseEvent::NewState { state, .. } = e {
                let _ = send_state.send(state);
            }
        })
        .build();
    let mut receiver = GooseReceiver::new();
    receiver.add_subscriber(sub);
    let handle = receiver.start_thread(Box::new(rx));

    let tag = VlanTag {
        priority: VlanPriority::new(4).unwrap(),
        vlan_id: 100,
    };
    let comm = CommParameters::new(0x1001, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01]).with_vlan(tag);
    let mut publisher =
        GoosePublisher::new(comm, "LD/LLN0$GO$veth", None, "LD/LLN0$ds", 1).unwrap();
    let frame = publisher.publish(&[MmsValue::Boolean(true)]).unwrap();
    tx.send(&frame).expect("send");

    let state = states
        .recv_timeout(Duration::from_secs(2))
        .expect("the publication was not received");
    handle.stop_and_join();

    assert_eq!(
        state.src_mac, hw.0,
        "the frame left with a zero source address"
    );
    let got = state.vlan.expect("the vlan tag was lost on receive");
    assert_eq!(got.vlan_id, 100);
    assert_eq!(got.priority.value(), 4);
}
