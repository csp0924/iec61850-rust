//! Integration tests for `ChannelReportSink` registration, dispatch and
//! deregistration.
//!
//! No socket is opened; the tests cover the channel routing semantics alone.

use bytes::Bytes;
use iec61850_server::{ChannelReportSink, ReportSink};

// Registration, dispatch and deregistration.

#[tokio::test]
async fn channel_report_sink_basic_register_dispatch_deregister() {
    let sink = ChannelReportSink::new();
    let (tx, mut rx) = ChannelReportSink::create_channel();

    // Before registration send_pdu reports failure.
    let pdu = Bytes::from_static(b"\xa3\x00");
    assert!(
        !sink.send_pdu(1, pdu.clone()),
        "send_pdu must report failure before the connection is registered"
    );

    // register
    sink.register(1, tx);

    // Send a PDU.
    assert!(
        sink.send_pdu(1, pdu.clone()),
        "send_pdu must report success once the connection is registered"
    );

    // The receiver gets the PDU unchanged.
    let received = rx.recv().await.expect("a PDU must arrive");
    assert_eq!(received, pdu, "the received PDU must match the one sent");

    // After deregistration a send fails again.
    sink.deregister(1);
    assert!(
        !sink.send_pdu(1, pdu.clone()),
        "send_pdu must report failure after deregistration"
    );
}

// Sending to an unregistered connection reports failure.

#[tokio::test]
async fn channel_report_sink_unregistered_conn_returns_false() {
    let sink = ChannelReportSink::new();
    let pdu = Bytes::from_static(b"\xa3\x05hello");

    let result = sink.send_pdu(9999, pdu);
    assert!(!result, "a send to an unregistered connection must fail");
}

// Each connection receives only its own PDUs.

#[tokio::test]
async fn channel_report_sink_routes_to_correct_connection() {
    let sink = ChannelReportSink::new();

    let (tx1, mut rx1) = ChannelReportSink::create_channel();
    let (tx2, mut rx2) = ChannelReportSink::create_channel();
    sink.register(1, tx1);
    sink.register(2, tx2);

    let pdu_for_1 = Bytes::from_static(b"\xa3\x01\x01");
    let pdu_for_2 = Bytes::from_static(b"\xa3\x01\x02");

    assert!(sink.send_pdu(1, pdu_for_1.clone()));
    assert!(sink.send_pdu(2, pdu_for_2.clone()));

    let got1 = rx1.recv().await.unwrap();
    let got2 = rx2.recv().await.unwrap();

    assert_eq!(got1, pdu_for_1, "connection 1 must receive its own PDU");
    assert_eq!(got2, pdu_for_2, "connection 2 must receive its own PDU");
}

// A dropped receiver makes send_pdu report failure.

#[tokio::test]
async fn channel_report_sink_dropped_receiver_returns_false() {
    let sink = ChannelReportSink::new();
    let (tx, rx) = ChannelReportSink::create_channel();
    sink.register(3, tx);
    drop(rx); // as if the connection task had ended

    let pdu = Bytes::from_static(b"\xa3\x00");
    let result = sink.send_pdu(3, pdu);
    assert!(!result, "send_pdu must fail once the receiver is dropped");
}

// Deregistering an unknown connection is a no-op.

#[test]
fn channel_report_sink_deregister_nonexistent_no_panic() {
    let sink = ChannelReportSink::new();
    // Must not panic.
    sink.deregister(12345);
}

// Several PDUs arrive in the order they were sent.

#[tokio::test]
async fn channel_report_sink_multiple_pdus_ordered() {
    let sink = ChannelReportSink::new();
    let (tx, mut rx) = ChannelReportSink::create_channel();
    sink.register(7, tx);

    let pdus: Vec<Bytes> = (0u8..5)
        .map(|i| Bytes::copy_from_slice(&[0xa3, 0x01, i]))
        .collect();

    for pdu in &pdus {
        assert!(sink.send_pdu(7, pdu.clone()), "every send must succeed");
    }

    for expected in &pdus {
        let got = rx.recv().await.unwrap();
        assert_eq!(
            &got, expected,
            "PDUs must arrive in the order they were sent"
        );
    }
}
