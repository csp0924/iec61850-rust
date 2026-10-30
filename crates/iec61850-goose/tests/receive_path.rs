//! Receive-path behavior of the GOOSE decoder, receiver, and subscriber.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use iec61850_goose::frame::{GooseFrame, GooseFrameHeader};
use iec61850_goose::publisher::{CommParameters, GoosePublisher};
use iec61850_goose::GoosePdu;
use iec61850_goose::{GooseEvent, GooseReceiver, GooseSubscriber, GooseSubscriberBuilder};
use iec61850_model::MmsValue;

const DST: [u8; 6] = [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01];

fn pdu(gocb: &str, st: u32, sq: u32) -> GoosePdu {
    GoosePdu {
        gocb_ref: gocb.into(),
        time_allowed_to_live: 2000,
        dat_set: "LD/LLN0$ds".into(),
        go_id: Some("id".into()),
        t: [0; 8],
        st_num: st,
        sq_num: sq,
        simulation: false,
        conf_rev: 1,
        nds_com: false,
        num_dataset_entries: 1,
        all_data: vec![MmsValue::Boolean(true)],
    }
}

fn pdu_bytes(p: &GoosePdu) -> Vec<u8> {
    let mut b = BytesMut::new();
    p.encode_ber(&mut b).unwrap();
    b.to_vec()
}

fn frame_from_pdu_bytes(pdu_bytes: Vec<u8>, app_id: u16) -> Vec<u8> {
    let header = GooseFrameHeader {
        dst_mac: DST,
        src_mac: [0, 0x50, 0xc2, 0, 0, 1],
        vlan: None,
        app_id,
        length: 0,
    };
    let mut out = BytesMut::new();
    GooseFrame::new(header, pdu_bytes).encode(&mut out).unwrap();
    out.to_vec()
}

fn frame_of(p: &GoosePdu, app_id: u16) -> Vec<u8> {
    frame_from_pdu_bytes(pdu_bytes(p), app_id)
}

/// Builds a subscriber that counts the events it receives.
fn counting(gocb: Option<&str>, app_id: Option<u16>) -> (GooseSubscriber, Arc<Mutex<u32>>) {
    let hits = Arc::new(Mutex::new(0u32));
    let h = hits.clone();
    let mut b = GooseSubscriberBuilder::new().listener(move |_e: GooseEvent| {
        *h.lock().unwrap() += 1;
    });
    if let Some(g) = gocb {
        b = b.gocb_ref(g);
    }
    if let Some(a) = app_id {
        b = b.app_id(a);
    }
    (b.build(), hits)
}

/// Feeds `frame` to a receiver holding one subscriber on `LD/LLN0$GO$g` and
/// returns the number of events it raised.
fn hits_for(frame: &[u8]) -> u32 {
    let (sub, hits) = counting(Some("LD/LLN0$GO$g"), None);
    let mut rx = GooseReceiver::new();
    rx.add_subscriber(sub);
    let mut rx = rx.start();
    rx.handle_message(frame);
    let n = *hits.lock().unwrap();
    n
}

/// Replaces the confRev member (`88 01 01`) of a PDU encoded by `pdu` with
/// `content`, fixing the outer length, which stays in the short form.
fn with_conf_rev_content(p: &GoosePdu, content: &[u8]) -> Vec<u8> {
    let mut b = pdu_bytes(p);
    let pos = b
        .windows(3)
        .position(|w| w == [0x88, 0x01, 0x01])
        .expect("confrev member");
    let mut member = vec![0x88, content.len() as u8];
    member.extend_from_slice(content);
    b.splice(pos..pos + 3, member);
    assert!(b.len() - 2 < 0x80, "outer length stays in the short form");
    b[1] = (b.len() - 2) as u8;
    b
}

#[test]
fn five_byte_integer_with_nonzero_lead_is_rejected() {
    let b = with_conf_rev_content(&pdu("LD/LLN0$GO$g", 1, 0), &[0x01, 0, 0, 0, 0x01]);
    let r = GoosePdu::decode_ber(&b);
    assert!(r.is_err(), "a value above u32::MAX decoded as {r:?}");
}

#[test]
fn five_byte_integer_with_sign_octet_is_accepted() {
    let b = with_conf_rev_content(&pdu("LD/LLN0$GO$g", 1, 0), &[0x00, 0x80, 0, 0, 0x01]);
    let p = GoosePdu::decode_ber(&b).expect("sign-prefixed u32");
    assert_eq!(p.conf_rev, 0x8000_0001);
}

#[test]
fn six_byte_integer_is_rejected() {
    let b = with_conf_rev_content(&pdu("LD/LLN0$GO$g", 1, 0), &[0, 0, 0, 0, 0, 0x01]);
    assert!(GoosePdu::decode_ber(&b).is_err());
}

#[test]
fn own_frame_with_conf_rev_above_i32_is_received() {
    let comm = CommParameters::new(0x1000, DST).with_src_mac([0, 0x50, 0xc2, 0, 0, 1]);
    let mut p = GoosePublisher::new(comm, "LD/LLN0$GO$g", None, "LD/LLN0$ds", 0x8000_0000).unwrap();
    let frame = p.publish(&[MmsValue::Boolean(true)]).unwrap();
    assert_eq!(hits_for(&frame), 1, "a confrev of 2^31 was not delivered");
}

#[test]
fn well_formed_frame_is_received() {
    assert_eq!(hits_for(&frame_of(&pdu("LD/LLN0$GO$g", 1, 0), 0x1000)), 1);
}

#[test]
fn num_dat_set_entries_mismatch_is_dropped() {
    let mut bad = pdu("LD/LLN0$GO$g", 1, 0);
    bad.num_dataset_entries = 3;
    assert_eq!(hits_for(&frame_of(&bad, 0x1000)), 0);
}

#[test]
fn st_num_zero_is_dropped() {
    assert_eq!(hits_for(&frame_of(&pdu("LD/LLN0$GO$g", 0, 0), 0x1000)), 0);
}

/// Removes the member with `tag` from an encoded PDU whose lengths are all in
/// the short form.
fn without_member(p: &GoosePdu, tag: u8) -> Vec<u8> {
    strip_member(pdu_bytes(p), tag)
}

/// Removes the member with `tag` from encoded PDU bytes whose lengths are all
/// in the short form.
fn strip_member(b: Vec<u8>, tag: u8) -> Vec<u8> {
    assert!(b[1] < 0x80);
    let mut out = vec![0x61, 0];
    let mut pos = 2;
    while pos < b.len() {
        let len = b[pos + 1] as usize;
        assert!(len < 0x80);
        if b[pos] != tag {
            out.extend_from_slice(&b[pos..pos + 2 + len]);
        }
        pos += 2 + len;
    }
    out[1] = (out.len() - 2) as u8;
    out
}

#[test]
fn frame_missing_a_mandatory_member_is_dropped() {
    let p = pdu("LD/LLN0$GO$g", 1, 0);
    for tag in [0x80u8, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x88, 0x8a, 0xab] {
        let frame = frame_from_pdu_bytes(without_member(&p, tag), 0x1000);
        assert_eq!(
            hits_for(&frame),
            0,
            "a pdu without tag 0x{tag:02x} was delivered"
        );
    }
}

#[test]
fn frame_missing_only_defaulted_members_is_received() {
    let p = pdu("LD/LLN0$GO$g", 1, 0);
    let without_both = without_member(&p, 0x87);
    let frame = frame_from_pdu_bytes(strip_member(without_both, 0x89), 0x1000);
    assert_eq!(
        hits_for(&frame),
        1,
        "simulation and ndscom default to false"
    );
}

/// Event kinds recorded by `recording`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    New(String, u32, bool),
    Retx(String, u32, bool),
    Expired(String),
}

/// Builds a subscriber that records every event it receives.
fn recording(builder: GooseSubscriberBuilder) -> (GooseSubscriber, Arc<Mutex<Vec<Seen>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = seen.clone();
    let sub = builder
        .listener(move |e: GooseEvent| {
            let item = match e {
                GooseEvent::NewState { state, .. } => {
                    Seen::New(state.gocb_ref.clone(), state.st_num, state.state_valid)
                }
                GooseEvent::Retransmission { state, .. } => {
                    Seen::Retx(state.gocb_ref.clone(), state.st_num, state.state_valid)
                }
                GooseEvent::Expired { last_state } => Seen::Expired(last_state.gocb_ref.clone()),
            };
            s.lock().unwrap().push(item);
        })
        .build();
    (sub, seen)
}

fn expired_count(seen: &Arc<Mutex<Vec<Seen>>>) -> usize {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|s| matches!(s, Seen::Expired(_)))
        .count()
}

#[test]
fn expiry_follows_the_injected_clock() {
    let (sub, seen) = recording(GooseSubscriberBuilder::new().gocb_ref("LD/LLN0$GO$g"));
    let mut rx = GooseReceiver::new();
    let idx = rx.add_subscriber(sub);
    let mut rx = rx.start();
    let t0 = Instant::now();
    rx.handle_message_at(&frame_of(&pdu("LD/LLN0$GO$g", 1, 0), 0x1000), t0);

    let at_tal = t0 + Duration::from_millis(2000);
    rx.tick_at(None, at_tal);
    assert_eq!(
        expired_count(&seen),
        0,
        "expired before timeallowedtolive elapsed"
    );
    assert!(rx.subscriber(idx).unwrap().is_valid_at(at_tal));

    let past_tal = t0 + Duration::from_millis(2001);
    rx.tick_at(None, past_tal);
    assert_eq!(expired_count(&seen), 1);
    assert!(!rx.subscriber(idx).unwrap().is_valid_at(past_tal));
}

/// Delivers `frames` at 10 ms steps from `t0` to one subscriber on
/// `LD/LLN0$GO$g`, then sweeps at `sweep_after_ms` past the last frame.
fn expired_after(frames: &[(u32, u32)], sweep_after_ms: u64) -> (usize, Vec<Seen>) {
    let (sub, seen) = recording(GooseSubscriberBuilder::new().gocb_ref("LD/LLN0$GO$g"));
    let mut rx = GooseReceiver::new();
    rx.add_subscriber(sub);
    let mut rx = rx.start();
    let t0 = Instant::now();
    let mut last = t0;
    for (i, (st, sq)) in frames.iter().enumerate() {
        last = t0 + Duration::from_millis(10 * i as u64);
        rx.handle_message_at(&frame_of(&pdu("LD/LLN0$GO$g", *st, *sq), 0x1000), last);
    }
    rx.tick_at(None, last + Duration::from_millis(sweep_after_ms));
    let all = seen.lock().unwrap().clone();
    (expired_count(&seen), all)
}

#[test]
fn expired_is_raised_after_a_duplicate_frame() {
    let (n, seen) = expired_after(&[(1, 0), (1, 1), (1, 1)], 2001);
    assert!(seen.contains(&Seen::Retx("LD/LLN0$GO$g".into(), 1, false)));
    assert_eq!(n, 1, "no expiry after a repeated sqnum: {seen:?}");
}

#[test]
fn expired_is_raised_after_an_st_num_rollback() {
    let (n, seen) = expired_after(&[(5, 0), (1, 0)], 2001);
    assert!(seen.contains(&Seen::New("LD/LLN0$GO$g".into(), 1, false)));
    assert_eq!(n, 1, "no expiry after stnum went backwards: {seen:?}");
}

#[test]
fn out_of_sequence_frame_does_not_expire_early() {
    let (n, _) = expired_after(&[(1, 0), (1, 1), (1, 1)], 2000);
    assert_eq!(n, 0);
}

/// Adds `subs` in order and returns the event count of each after one frame.
fn hits_each(subs: Vec<(GooseSubscriber, Arc<Mutex<u32>>)>, frame: &[u8]) -> Vec<u32> {
    let mut rx = GooseReceiver::new();
    let mut counters = Vec::new();
    for (sub, hits) in subs {
        rx.add_subscriber(sub);
        counters.push(hits);
    }
    let mut rx = rx.start();
    rx.handle_message(frame);
    counters.iter().map(|h| *h.lock().unwrap()).collect()
}

#[test]
fn observer_added_first_does_not_starve_a_specific_subscriber() {
    let frame = frame_of(&pdu("LD/LLN0$GO$g", 1, 0), 0x1000);
    let hits = hits_each(
        vec![counting(None, None), counting(Some("LD/LLN0$GO$g"), None)],
        &frame,
    );
    assert_eq!(hits, vec![1, 1]);
}

#[test]
fn specific_subscriber_added_first_does_not_starve_an_observer() {
    let frame = frame_of(&pdu("LD/LLN0$GO$g", 1, 0), 0x1000);
    let hits = hits_each(
        vec![counting(Some("LD/LLN0$GO$g"), None), counting(None, None)],
        &frame,
    );
    assert_eq!(hits, vec![1, 1]);
}

#[test]
fn appid_filter_is_not_bypassed_by_a_gocb_ref_match() {
    let frame = frame_of(&pdu("LD/LLN0$GO$g", 1, 0), 0x1000);
    let hits = hits_each(
        vec![
            counting(Some("LD/LLN0$GO$other"), Some(0x1000)),
            counting(Some("LD/LLN0$GO$g"), Some(0x2000)),
        ],
        &frame,
    );
    assert_eq!(
        hits,
        vec![0, 0],
        "a subscriber on another appid received the frame"
    );
}

#[test]
fn only_subscribers_on_the_frame_gocb_ref_receive_it() {
    let frame = frame_of(&pdu("LD/LLN0$GO$g", 1, 0), 0x1000);
    let hits = hits_each(
        vec![
            counting(Some("LD/LLN0$GO$other"), None),
            counting(Some("LD/LLN0$GO$g"), Some(0x1000)),
            counting(Some("LD/LLN0$GO$g"), None),
        ],
        &frame,
    );
    assert_eq!(hits, vec![0, 1, 1]);
}

#[test]
fn dst_mac_filter_holds_alongside_an_observer() {
    let frame = frame_of(&pdu("LD/LLN0$GO$g", 1, 0), 0x1000);
    let (other_mac, other_hits) = {
        let hits = Arc::new(Mutex::new(0u32));
        let h = hits.clone();
        let sub = GooseSubscriberBuilder::new()
            .gocb_ref("LD/LLN0$GO$g")
            .dst_mac([0x01, 0x0c, 0xcd, 0x01, 0x00, 0x02])
            .listener(move |_e: GooseEvent| *h.lock().unwrap() += 1)
            .build();
        (sub, hits)
    };
    let hits = hits_each(vec![counting(None, None), (other_mac, other_hits)], &frame);
    assert_eq!(
        hits,
        vec![1, 0],
        "a subscriber on another destination received the frame"
    );
}
