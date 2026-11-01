//! Integration tests for refrTm validation: a publisher frame carrying refrTm
//! travels through the receiver to a listener unchanged, a refrTm that is not
//! a valid UtcTime drops its frame, and values the encoding allows are
//! delivered whatever their quality flags.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use iec61850_sv::pdu::decode_sav_pdu;
use iec61850_sv::receiver::{Idle, Running, SvReceiver};
use iec61850_sv::subscriber::SvSubscriberBuilder;
use iec61850_sv::{
    SvError, SvPublisherBuilder, TimeAccuracy, TimeQuality, UtcTime, UtcTimeError,
    SV_HEADER_NO_VLAN,
};

const SRC_MAC: [u8; 6] = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];

/// A refrTm whose first seven octets do not occur elsewhere in the frame.
const MARKER: [u8; 8] = [0x65, 0x4A, 0x3B, 0x2C, 0xD1, 0xE2, 0xF3, 0x8A];

/// Builds a one-ASDU publisher frame of the stream `sv1` carrying `refr_tm`.
fn publisher_frame(refr_tm: UtcTime) -> Vec<u8> {
    let mut b = SvPublisherBuilder::new(SRC_MAC).without_vlan();
    let h = b.add_asdu("sv1", None::<String>, 1, 8).unwrap();
    b.enable_refr_tm(h).unwrap();
    let mut p = b.setup_complete().unwrap();
    p.set_sample(h, &[0x11; 8]).unwrap();
    p.set_refr_tm(h, refr_tm).unwrap();
    p.frame_bytes().to_vec()
}

/// Returns a publisher frame whose refrTm octets are `raw`, written over the
/// frame bytes after encoding so that values no `UtcTime` can hold reach the
/// wire.
fn frame_with_raw_refr_tm(raw: [u8; 8]) -> Vec<u8> {
    let mut frame = publisher_frame(UtcTime::from_bytes(MARKER).unwrap());
    let at = frame
        .windows(10)
        .position(|w| w[..2] == [0x84, 0x08] && w[2..] == MARKER)
        .expect("refrTm field in the frame");
    frame[at + 2..at + 10].copy_from_slice(&raw);
    frame
}

/// Builds a raw savPdu of one ASDU of the stream `sv1` whose refrTm value is
/// `refr_tm`, of any length.
fn raw_pdu_with_refr_tm(refr_tm: &[u8]) -> Vec<u8> {
    let mut asdu = vec![0x80, 0x03, b's', b'v', b'1'];
    asdu.extend_from_slice(&[0x82, 0x02, 0x00, 0x01]);
    asdu.extend_from_slice(&[0x83, 0x04, 0x00, 0x00, 0x00, 0x01]);
    asdu.push(0x84);
    asdu.push(refr_tm.len() as u8);
    asdu.extend_from_slice(refr_tm);
    asdu.extend_from_slice(&[0x85, 0x01, 0x02]);
    asdu.extend_from_slice(&[0x87, 0x02, 0x00, 0x00]);

    let mut seq = vec![0x30, asdu.len() as u8];
    seq.extend_from_slice(&asdu);

    let mut body = vec![0x80, 0x01, 0x01, 0xA2, seq.len() as u8];
    body.extend_from_slice(&seq);

    let mut pdu = vec![0x60, body.len() as u8];
    pdu.extend_from_slice(&body);
    pdu
}

/// The refrTm values a listener has been handed, in order.
type Seen = Arc<Mutex<Vec<Option<UtcTime>>>>;

/// A running receiver with one subscription to `sv1` that records every
/// refrTm it is handed.
fn receiver() -> (SvReceiver<Running>, Seen) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_cb = seen.clone();
    let sub = SvSubscriberBuilder::new()
        .sv_id("sv1")
        .listener(move |asdu| seen_cb.lock().unwrap().push(asdu.refr_tm))
        .build();
    let mut rx = SvReceiver::<Idle>::new();
    rx.add_subscriber(Arc::new(sub));
    (rx.into_threadless(), seen)
}

fn quality(leap: bool, failure: bool, not_synced: bool, accuracy: TimeAccuracy) -> TimeQuality {
    TimeQuality::new(leap, failure, not_synced, accuracy)
}

#[test]
fn publisher_refr_tm_reaches_listener_unchanged() {
    let tq = quality(true, false, false, TimeAccuracy::bits(20).unwrap());
    let sent =
        UtcTime::from_duration_since_epoch(Duration::new(1_761_955_200, 125_000_000), tq).unwrap();
    let (mut rx, seen) = receiver();

    assert_eq!(rx.tick(&publisher_frame(sent)), Ok(1));

    let got = seen.lock().unwrap()[0].expect("refrTm delivered");
    assert_eq!(got, sent);
    assert_eq!(got.seconds_since_epoch(), 1_761_955_200);
    assert_eq!(got.fraction_of_second(), 0x0020_0000);
    assert_eq!(
        got.duration_since_epoch(),
        Duration::new(1_761_955_200, 125_000_000)
    );
    assert_eq!(got.time_quality(), tq);
}

#[test]
fn every_publishable_quality_round_trips() {
    let accuracies = (0..=TimeAccuracy::MAX_BITS)
        .map(|n| TimeAccuracy::bits(n).unwrap())
        .chain([TimeAccuracy::UNSPECIFIED]);
    for accuracy in accuracies {
        for flags in 0..8u8 {
            let tq = quality(flags & 4 != 0, flags & 2 != 0, flags & 1 != 0, accuracy);
            let sent = UtcTime::new(0x6543_2100, 0x00FF_FFFF, tq).unwrap();
            let frame = publisher_frame(sent);
            let pdu = decode_sav_pdu(&frame[SV_HEADER_NO_VLAN..]).unwrap();
            assert_eq!(pdu.asdus[0].refr_tm, Some(sent), "{tq:?}");
        }
    }
}

#[test]
fn invalid_time_accuracy_drops_the_frame() {
    for code in 25..=30u8 {
        let frame = frame_with_raw_refr_tm([0x65, 0x4A, 0x3B, 0x2C, 0x00, 0x00, 0x00, 0x80 | code]);
        let (mut rx, seen) = receiver();

        assert_eq!(
            rx.tick(&frame),
            Err(SvError::InvalidRefrTm(UtcTimeError::InvalidTimeAccuracy(
                code
            ))),
            "code {code}"
        );
        assert!(
            seen.lock().unwrap().is_empty(),
            "code {code} reached the listener"
        );
    }
}

#[test]
fn valid_time_accuracy_codes_on_the_wire_are_delivered() {
    for code in (0..=24u8).chain([31]) {
        let raw = [0x65, 0x4A, 0x3B, 0x2C, 0x00, 0x00, 0x00, 0x80 | code];
        let (mut rx, seen) = receiver();

        assert_eq!(rx.tick(&frame_with_raw_refr_tm(raw)), Ok(1), "code {code}");
        let got = seen.lock().unwrap()[0].expect("refrTm delivered");
        assert_eq!(got.to_bytes(), raw);
        assert_eq!(got.time_quality().time_accuracy.code(), code);
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
        [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
    ];
    for raw in cases {
        let (mut rx, seen) = receiver();
        assert_eq!(rx.tick(&frame_with_raw_refr_tm(raw)), Ok(1), "{raw:02x?}");
        let got = seen.lock().unwrap()[0].expect("refrTm delivered");
        assert_eq!(got.to_bytes(), raw);
    }

    let (mut rx, seen) = receiver();
    rx.tick(&frame_with_raw_refr_tm(cases[0])).unwrap();
    let failed = seen.lock().unwrap()[0].unwrap();
    assert!(failed.time_quality().clock_failure);
    assert!(!failed.time_quality().leap_seconds_known);

    let (mut rx, seen) = receiver();
    rx.tick(&frame_with_raw_refr_tm([0; 8])).unwrap();
    assert!(seen.lock().unwrap()[0].unwrap().is_null());
}

#[test]
fn refr_tm_length_other_than_eight_is_rejected() {
    for len in [0usize, 7, 9] {
        let pdu = raw_pdu_with_refr_tm(&vec![0u8; len]);
        let r = decode_sav_pdu(&pdu);
        assert!(
            matches!(
                r,
                Err(SvError::InvalidFieldLength { tag: 0x84, expected: 8, actual, .. }) if actual == len
            ),
            "length {len}: {r:?}"
        );
    }
    let ok = raw_pdu_with_refr_tm(&[0x65, 0x4A, 0x3B, 0x2C, 0x00, 0x00, 0x00, 0x8A]);
    assert!(decode_sav_pdu(&ok).is_ok());
}

#[test]
fn invalid_time_accuracy_in_raw_pdu_is_rejected() {
    let pdu = raw_pdu_with_refr_tm(&[0x65, 0x4A, 0x3B, 0x2C, 0x00, 0x00, 0x00, 0x19]);
    assert_eq!(
        decode_sav_pdu(&pdu),
        Err(SvError::InvalidRefrTm(UtcTimeError::InvalidTimeAccuracy(
            25
        )))
    );
}
