//! Integration tests for `SvSubscriber` dispatch: stream filters, delivery to
//! every matching subscription, the sample length lock, smpCnt gap counting,
//! the ASDU view accessors, and 9-2 LE sample decoding.

use std::sync::{Arc, Mutex};

use iec61850_model::Quality;
use iec61850_sv::pdu::{Asdu, SmpMod, SmpSynch};
use iec61850_sv::subscriber::{SvSubscriberAsdu, SvSubscriberBuilder};
use iec61850_sv::{ChannelSample, NineTwoLE};

fn make_asdu(sv_id: &str, smp_cnt: u16, sample: Vec<u8>) -> Asdu {
    Asdu {
        sv_id: sv_id.to_owned(),
        dat_set: None,
        smp_cnt,
        conf_rev: 1,
        refr_tm: None,
        smp_synch: SmpSynch::GlobalClock,
        smp_rate: None,
        sample,
        smp_mod: None,
        gm_identity: None,
    }
}

fn make_full_asdu(sv_id: &str, smp_cnt: u16) -> Asdu {
    Asdu {
        sv_id: sv_id.to_owned(),
        dat_set: Some("IED1/LLN0$SV$ds".to_owned()),
        smp_cnt,
        conf_rev: 0x12345678,
        refr_tm: Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11]),
        smp_synch: SmpSynch::LocalIdentified(7),
        smp_rate: Some(4000),
        sample: vec![0x5Au8; 64],
        smp_mod: Some(SmpMod::SamplesPerSecond),
        gm_identity: Some([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
    }
}

#[test]
fn single_subscriber_matching_fires_once() {
    let counter: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let c = counter.clone();
    let sub = SvSubscriberBuilder::new()
        .sv_id("sv1")
        .listener(move |_| {
            *c.lock().unwrap() += 1;
        })
        .build();

    let asdu = make_asdu("sv1", 0, vec![0u8; 8]);
    sub.dispatch(&SvSubscriberAsdu::from_asdu(&asdu));
    assert_eq!(*counter.lock().unwrap(), 1);
}

#[test]
fn single_subscriber_non_matching_app_id_no_callback() {
    let called: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let c = called.clone();
    let sub = SvSubscriberBuilder::new()
        .app_id(0x4001)
        .listener(move |_| {
            *c.lock().unwrap() = true;
        })
        .build();

    let asdu = make_asdu("sv1", 0, vec![0u8; 8]);
    // Filtering happens in the receiver, so this checks `matches` rather than
    // dispatch.
    assert!(!sub.matches(0x4000, &[0u8; 6], &asdu));
}

#[test]
fn single_subscriber_non_matching_sv_id_no_callback() {
    let sub = SvSubscriberBuilder::new().sv_id("sv99").build();
    let asdu = make_asdu("sv1", 0, vec![0u8; 8]);
    assert!(!sub.matches(0x4000, &[0u8; 6], &asdu));
}

#[test]
fn dst_mac_filter_on_matches_correct_mac() {
    let mac = [0x01, 0x0C, 0xCD, 0x04, 0x00, 0x01];
    let sub = SvSubscriberBuilder::new().dst_mac(mac).build();
    let asdu = make_asdu("sv1", 0, vec![0u8; 8]);
    assert!(sub.matches(0x4000, &mac, &asdu));
    assert!(!sub.matches(0x4000, &[0x01, 0x0C, 0xCD, 0x04, 0x00, 0x02], &asdu));
}

#[test]
fn no_dst_mac_filter_accepts_any_mac() {
    let sub = SvSubscriberBuilder::new().build();
    let asdu = make_asdu("sv1", 0, vec![0u8; 8]);
    assert!(sub.matches(0x4000, &[0xFF; 6], &asdu));
    assert!(sub.matches(0x4000, &[0u8; 6], &asdu));
}

#[test]
fn two_subscribers_same_app_id_different_sv_id_each_dispatched() {
    // The end-to-end receiver path is covered in sv_receiver_typestate.
    let sub1 = SvSubscriberBuilder::new().sv_id("sv1").build();
    let sub2 = SvSubscriberBuilder::new().sv_id("sv2").build();

    let asdu1 = make_asdu("sv1", 0, vec![0u8; 8]);
    let asdu2 = make_asdu("sv2", 0, vec![0u8; 8]);

    assert!(sub1.matches(0x4000, &[0u8; 6], &asdu1));
    assert!(!sub1.matches(0x4000, &[0u8; 6], &asdu2));
    assert!(!sub2.matches(0x4000, &[0u8; 6], &asdu1));
    assert!(sub2.matches(0x4000, &[0u8; 6], &asdu2));
}

#[test]
fn two_subscribers_identical_filter_both_callback() {
    let cnt1: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let cnt2: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let c1 = cnt1.clone();
    let c2 = cnt2.clone();

    let sub1 = SvSubscriberBuilder::new()
        .sv_id("sv1")
        .listener(move |_| {
            *c1.lock().unwrap() += 1;
        })
        .build();
    let sub2 = SvSubscriberBuilder::new()
        .sv_id("sv1")
        .listener(move |_| {
            *c2.lock().unwrap() += 1;
        })
        .build();

    let asdu = make_asdu("sv1", 0, vec![0u8; 64]);
    sub1.dispatch(&SvSubscriberAsdu::from_asdu(&asdu));
    sub2.dispatch(&SvSubscriberAsdu::from_asdu(&asdu));

    assert_eq!(*cnt1.lock().unwrap(), 1);
    assert_eq!(*cnt2.lock().unwrap(), 1);
}

#[test]
fn dispatch_called_twice_for_two_asdus() {
    let counter: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let c = counter.clone();
    let sub = SvSubscriberBuilder::new()
        .sv_id("sv1")
        .listener(move |_| {
            *c.lock().unwrap() += 1;
        })
        .build();

    let asdu1 = make_asdu("sv1", 0, vec![0u8; 64]);
    let asdu2 = make_asdu("sv1", 1, vec![0u8; 64]);
    sub.dispatch(&SvSubscriberAsdu::from_asdu(&asdu1));
    sub.dispatch(&SvSubscriberAsdu::from_asdu(&asdu2));

    assert_eq!(*counter.lock().unwrap(), 2);
}

#[test]
fn asdu_view_all_getters_correct() {
    let asdu = make_full_asdu("IED1/LLN0$SV$sv1", 77);
    let view = SvSubscriberAsdu::from_asdu(&asdu);

    assert_eq!(view.sv_id, "IED1/LLN0$SV$sv1");
    assert_eq!(view.dat_set, Some("IED1/LLN0$SV$ds"));
    assert_eq!(view.smp_cnt, 77);
    assert_eq!(view.conf_rev, 0x12345678);
    assert_eq!(
        view.refr_tm,
        Some(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11])
    );
    assert_eq!(view.smp_synch, SmpSynch::LocalIdentified(7));
    assert_eq!(view.smp_rate, Some(4000));
    assert_eq!(view.smp_mod, Some(SmpMod::SamplesPerSecond));
    assert_eq!(
        view.gm_identity,
        Some(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    );
    assert_eq!(view.sample.len(), 64);
}

#[test]
fn parse_9_2_le_from_subscriber_asdu() {
    let channels = [
        ChannelSample::new(1000, Quality(0x0001)),
        ChannelSample::new(-500, Quality(0x0002)),
        ChannelSample::new(750, Quality(0x0004)),
        ChannelSample::new(0, Quality(0)),
        ChannelSample::new(220000, Quality(0)),
        ChannelSample::new(220000, Quality(0)),
        ChannelSample::new(220000, Quality(0)),
        ChannelSample::new(0, Quality(0)),
    ];
    let sv = NineTwoLE { channels };
    let raw = sv.to_sample();

    let asdu = make_asdu("sv1", 0, raw.to_vec());
    let view = SvSubscriberAsdu::from_asdu(&asdu);
    let decoded = view.parse_9_2_le().unwrap();

    for (i, expected) in channels.iter().enumerate() {
        assert_eq!(&decoded.channels[i], expected, "channel {} mismatch", i);
    }
}

#[test]
fn get_i32_out_of_range_returns_none() {
    let asdu = make_asdu("sv1", 0, vec![0u8; 8]);
    let view = SvSubscriberAsdu::from_asdu(&asdu);
    // Reading 4 bytes at offset 5 would need 9 bytes.
    assert_eq!(view.get_i32(5), None);
    assert_eq!(view.get_i32(0), Some(0i32));
}

#[test]
fn q4_sample_size_mismatch_skips_callback() {
    let counter: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let c = counter.clone();
    let sub = SvSubscriberBuilder::new()
        .listener(move |_| {
            *c.lock().unwrap() += 1;
        })
        .build();

    // The first ASDU locks the sample length at 64.
    let a1 = make_asdu("sv1", 0, vec![0u8; 64]);
    sub.dispatch(&SvSubscriberAsdu::from_asdu(&a1));
    assert_eq!(sub.expected_sample_size(), 64);
    assert_eq!(*counter.lock().unwrap(), 1);

    // A different length is dropped.
    let a2 = make_asdu("sv1", 1, vec![0u8; 80]);
    sub.dispatch(&SvSubscriberAsdu::from_asdu(&a2));
    assert_eq!(
        *counter.lock().unwrap(),
        1,
        "a differing sample length is not delivered"
    );
}

#[test]
fn smp_cnt_gap_detection_missed_count() {
    let sub = SvSubscriberBuilder::new().build();

    // The first ASDU sets the baseline.
    let a1 = make_asdu("sv1", 1, vec![0u8; 8]);
    sub.dispatch(&SvSubscriberAsdu::from_asdu(&a1));
    assert_eq!(sub.missed_count(), 0);

    // The next counter follows on.
    let a2 = make_asdu("sv1", 2, vec![0u8; 8]);
    sub.dispatch(&SvSubscriberAsdu::from_asdu(&a2));
    assert_eq!(sub.missed_count(), 0);

    // Counter 3 is missing, so one sample is counted as missed.
    let a4 = make_asdu("sv1", 4, vec![0u8; 8]);
    sub.dispatch(&SvSubscriberAsdu::from_asdu(&a4));
    assert_eq!(sub.missed_count(), 1, "one missed sample is counted");
}

#[test]
fn too_many_asdus_tick_returns_err() {
    use bytes::BytesMut;
    use iec61850_asn1::encode_length;
    use iec61850_sv::frame::{SvFrame, SvFrameHeader, SV_APP_HEADER_SIZE, SV_DEFAULT_APPID};
    use iec61850_sv::receiver::{Idle, SvReceiver};
    use iec61850_sv::SvError;

    let mut pdu_buf = BytesMut::new();
    let inner = vec![0x80u8, 0x01, 11u8, 0xA2, 0x00]; // noASDU = 11
    pdu_buf.extend_from_slice(&[0x60u8]);
    encode_length(inner.len(), &mut pdu_buf);
    pdu_buf.extend_from_slice(&inner);
    let pdu_bytes = pdu_buf.to_vec();

    let frame = SvFrame {
        header: SvFrameHeader {
            dst_mac: iec61850_sv::SV_DEFAULT_DST_MAC,
            src_mac: [0u8; 6],
            vlan: None,
            app_id: SV_DEFAULT_APPID,
            length: (SV_APP_HEADER_SIZE + pdu_bytes.len()) as u16,
        },
        pdu_bytes,
    };
    let mut buf = BytesMut::new();
    frame.encode(&mut buf).unwrap();

    let mut rx = SvReceiver::<Idle>::new().into_threadless();
    assert!(matches!(rx.tick(&buf), Err(SvError::TooManyAsdus(11))));
}

#[test]
fn corrupt_frame_incomplete_asdu_returns_err() {
    use bytes::BytesMut;
    use iec61850_asn1::encode_length;
    use iec61850_sv::frame::{SvFrame, SvFrameHeader, SV_APP_HEADER_SIZE, SV_DEFAULT_APPID};
    use iec61850_sv::receiver::{Idle, SvReceiver};

    // One ASDU carrying only svID; the mandatory fields are missing.
    let mut inner_asdu = Vec::new();
    inner_asdu.extend_from_slice(&[0x80u8, 0x03]);
    inner_asdu.extend_from_slice(b"sv1");

    let asdu_tlv = {
        let mut v = vec![0x30u8];
        let mut tbuf = BytesMut::new();
        encode_length(inner_asdu.len(), &mut tbuf);
        v.extend_from_slice(&tbuf);
        v.extend_from_slice(&inner_asdu);
        v
    };

    let seq_tlv = {
        let mut v = vec![0xA2u8];
        let mut tbuf = BytesMut::new();
        encode_length(asdu_tlv.len(), &mut tbuf);
        v.extend_from_slice(&tbuf);
        v.extend_from_slice(&asdu_tlv);
        v
    };

    let no_asdu_bytes = vec![0x80u8, 0x01, 0x01];
    let contents = [no_asdu_bytes.as_slice(), seq_tlv.as_slice()].concat();
    let mut pdu_buf = BytesMut::new();
    pdu_buf.extend_from_slice(&[0x60u8]);
    encode_length(contents.len(), &mut pdu_buf);
    pdu_buf.extend_from_slice(&contents);
    let pdu_bytes = pdu_buf.to_vec();

    let frame = SvFrame {
        header: SvFrameHeader {
            dst_mac: iec61850_sv::SV_DEFAULT_DST_MAC,
            src_mac: [0u8; 6],
            vlan: None,
            app_id: SV_DEFAULT_APPID,
            length: (SV_APP_HEADER_SIZE + pdu_bytes.len()) as u16,
        },
        pdu_bytes,
    };
    let mut buf = BytesMut::new();
    frame.encode(&mut buf).unwrap();

    let mut rx = SvReceiver::<Idle>::new().into_threadless();
    assert!(rx.tick(&buf).is_err(), "an incomplete asdu returns err");
}
