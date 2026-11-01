//! The GOOSE `t` member as a UtcTime: a publisher timestamp travels through
//! the receiver to a listener unchanged, a `t` that is not a valid UtcTime
//! drops its frame, and values the encoding allows are delivered whatever
//! their quality flags.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use iec61850_goose::frame::GooseFrame;
use iec61850_goose::publisher::{CommParameters, GoosePublisher};
use iec61850_goose::{
    GooseError, GooseEvent, GoosePdu, GooseReceiver, GooseSubscriberBuilder, TimeAccuracy,
    TimeQuality, UtcTime, UtcTimeError,
};
use iec61850_model::MmsValue;

mod log_capture;
use log_capture::warnings_containing;

const DST: [u8; 6] = [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01];
const GOCB: &str = "LD/LLN0$GO$g";

/// A timestamp whose octets do not occur elsewhere in the frame.
const MARKER: [u8; 8] = [0x65, 0x4A, 0x3B, 0x2C, 0xD1, 0xE2, 0xF3, 0x8A];

/// Publishes one frame of `GOCB` stamped with `t`.
fn publisher_frame(t: UtcTime) -> Vec<u8> {
    let comm = CommParameters::new(0x1000, DST)
        .without_vlan()
        .with_src_mac([0, 0x50, 0xc2, 0, 0, 1]);
    let mut p = GoosePublisher::new(comm, GOCB, None, "LD/LLN0$ds", 1).unwrap();
    p.set_timestamp(t);
    p.publish(&[MmsValue::Boolean(true)]).unwrap().to_vec()
}

/// Returns a publisher frame whose `t` octets are `raw`, written over the
/// frame bytes after encoding so that values no `UtcTime` can hold reach the
/// wire.
fn frame_with_raw_t(raw: [u8; 8]) -> Vec<u8> {
    let mut frame = publisher_frame(UtcTime::from_bytes(MARKER).unwrap());
    let at = frame
        .windows(10)
        .position(|w| w[..2] == [0x84, 0x08] && w[2..] == MARKER)
        .expect("t member in the frame");
    frame[at + 2..at + 10].copy_from_slice(&raw);
    frame
}

/// The timestamps a listener has been handed, in order.
type Seen = Arc<Mutex<Vec<UtcTime>>>;

/// Feeds `frame` to a receiver with one subscription on `GOCB` and returns the
/// timestamps of the states it delivered.
fn deliver(frame: &[u8]) -> Vec<UtcTime> {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let seen_cb = seen.clone();
    let sub = GooseSubscriberBuilder::new()
        .gocb_ref(GOCB)
        .listener(move |e| {
            if let GooseEvent::NewState { state, .. } | GooseEvent::Retransmission { state, .. } = e
            {
                seen_cb.lock().unwrap().push(state.timestamp);
            }
        })
        .build();
    let mut rx = GooseReceiver::new();
    rx.add_subscriber(sub);
    let mut rx = rx.start();
    rx.handle_message(frame);
    let got = seen.lock().unwrap().clone();
    got
}

fn pdu_of(frame: &[u8]) -> Result<GoosePdu, GooseError> {
    GoosePdu::decode_ber(&GooseFrame::decode(frame).unwrap().pdu_bytes)
}

#[test]
fn publisher_timestamp_reaches_listener_unchanged() {
    let tq = TimeQuality::new(true, false, false, TimeAccuracy::bits(18).unwrap());
    let sent =
        UtcTime::from_duration_since_epoch(Duration::new(1_761_955_200, 750_000_000), tq).unwrap();

    let got = deliver(&publisher_frame(sent));

    assert_eq!(got, vec![sent]);
    assert_eq!(
        got[0].duration_since_epoch(),
        Duration::new(1_761_955_200, 750_000_000)
    );
    assert_eq!(got[0].time_quality(), tq);
}

#[test]
fn every_publishable_quality_round_trips() {
    let accuracies = (0..=TimeAccuracy::MAX_BITS)
        .map(|n| TimeAccuracy::bits(n).unwrap())
        .chain([TimeAccuracy::UNSPECIFIED]);
    for accuracy in accuracies {
        for flags in 0..8u8 {
            let tq = TimeQuality::new(flags & 4 != 0, flags & 2 != 0, flags & 1 != 0, accuracy);
            let sent = UtcTime::new(0x6543_2100, 0x00FF_FFFF, tq).unwrap();
            assert_eq!(pdu_of(&publisher_frame(sent)).unwrap().t, sent, "{tq:?}");
        }
    }
}

#[test]
fn unset_publisher_timestamp_is_null() {
    let comm = CommParameters::new(0x1000, DST).without_vlan();
    let mut p = GoosePublisher::new(comm, GOCB, None, "LD/LLN0$ds", 1).unwrap();
    let frame = p.publish(&[MmsValue::Boolean(true)]).unwrap();
    assert!(pdu_of(&frame).unwrap().t.is_null());
}

#[test]
fn invalid_time_accuracy_drops_the_frame() {
    for code in 25..=30u8 {
        let frame = frame_with_raw_t([0x65, 0x4A, 0x3B, 0x2C, 0x00, 0x00, 0x00, 0x80 | code]);

        assert_eq!(
            pdu_of(&frame),
            Err(GooseError::InvalidTimestampQuality(
                UtcTimeError::InvalidTimeAccuracy(code)
            )),
            "code {code}"
        );
        let mut got = Vec::new();
        let logged = warnings_containing("not a valid utctime", || got = deliver(&frame));
        assert!(got.is_empty(), "code {code} reached the listener");
        assert_eq!(logged, 1, "code {code}");
    }
}

#[test]
fn valid_time_accuracy_codes_on_the_wire_are_delivered() {
    for code in (0..=24u8).chain([31]) {
        let raw = [0x65, 0x4A, 0x3B, 0x2C, 0x00, 0x00, 0x00, 0x80 | code];
        let got = deliver(&frame_with_raw_t(raw));
        assert_eq!(got.len(), 1, "code {code}");
        assert_eq!(got[0].to_bytes(), raw);
        assert_eq!(got[0].time_quality().time_accuracy.code(), code);
    }
}

#[test]
fn clock_flags_and_null_time_are_delivered_not_judged() {
    let cases = [
        // ClockFailure: the value is to be ignored by the application.
        [0x65, 0x4A, 0x3B, 0x2C, 0x12, 0x34, 0x56, 0x40 | 0x0A],
        // ClockNotSynchronized and LeapSecondsKnown cleared.
        [0x65, 0x4A, 0x3B, 0x2C, 0x12, 0x34, 0x56, 0x20 | 0x1F],
        // The NULL TimeStamp.
        [0; 8],
        // The largest SecondSinceEpoch and FractionOfSecond.
        [0xFF; 8],
    ];
    for raw in cases {
        let got = deliver(&frame_with_raw_t(raw));
        assert_eq!(got.len(), 1, "{raw:02x?}");
        assert_eq!(got[0].to_bytes(), raw);
    }
    let failed = deliver(&frame_with_raw_t(cases[0]))[0].time_quality();
    assert!(failed.clock_failure);
    assert!(!failed.leap_seconds_known);
}
