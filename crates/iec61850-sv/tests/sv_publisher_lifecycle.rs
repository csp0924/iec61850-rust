//! Integration tests for the publisher lifecycle: configuring a builder,
//! completing setup, writing fields, and decoding the resulting frame.

use iec61850_sv::{
    decode_sav_pdu, AsduHandle, SmpSynch, SvError, SvPublisher, SvPublisherBuilder, VlanPriority,
    VlanTag, SV_HEADER_NO_VLAN, SV_HEADER_WITH_VLAN, SV_STRING_MAX_LEN,
};
use std::num::NonZeroU16;

const SRC_MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

fn make_simple(sample_size: usize) -> (SvPublisher, AsduHandle) {
    let mut b = SvPublisherBuilder::new(SRC_MAC);
    let h = b
        .add_asdu("IED1/LLN0$SV$sv1", None::<String>, 1, sample_size)
        .unwrap();
    let p = b.setup_complete().unwrap();
    (p, h)
}

fn decode_pdu(pub_: &SvPublisher) -> iec61850_sv::SavPdu {
    let bytes = pub_.frame_bytes();
    decode_sav_pdu(&bytes[SV_HEADER_NO_VLAN..]).unwrap()
}

#[test]
fn add_1_asdu_setup_ok() {
    let (p, _) = make_simple(64);
    assert_eq!(p.no_asdu(), 1);
    assert_eq!(p.asdu_count(), 1);
}

#[test]
fn add_2_asdus_setup_ok() {
    let mut b = SvPublisherBuilder::new(SRC_MAC);
    b.add_asdu("sv1", None::<String>, 1, 64).unwrap();
    b.add_asdu("sv2", None::<String>, 1, 64).unwrap();
    let p = b.setup_complete().unwrap();
    assert_eq!(p.no_asdu(), 2);
}

#[test]
fn add_4_asdus_setup_ok() {
    let mut b = SvPublisherBuilder::new(SRC_MAC);
    for i in 0..4 {
        b.add_asdu(format!("sv{i}"), None::<String>, 1, 64).unwrap();
    }
    let p = b.setup_complete().unwrap();
    assert_eq!(p.no_asdu(), 4);
}

#[test]
fn add_10_asdus_setup_ok() {
    let mut b = SvPublisherBuilder::new(SRC_MAC);
    for i in 0..10 {
        b.add_asdu(format!("sv{i}"), None::<String>, 1, 8).unwrap();
    }
    let p = b.setup_complete().unwrap();
    assert_eq!(p.no_asdu(), 10);
    let bytes = p.frame_bytes();
    let pdu = decode_sav_pdu(&bytes[SV_HEADER_NO_VLAN..]).unwrap();
    assert_eq!(pdu.asdus.len(), 10);
}

#[test]
fn add_11_asdus_err() {
    let mut b = SvPublisherBuilder::new(SRC_MAC);
    for i in 0..10 {
        b.add_asdu(format!("sv{i}"), None::<String>, 1, 8).unwrap();
    }
    let result = b.add_asdu("sv10", None::<String>, 1, 8);
    assert!(result.is_err(), "the eleventh add_asdu is refused");
}

#[test]
fn set_sample_and_decode_byte_exact() {
    let sample_data: Vec<u8> = (0..64).collect();
    let (mut p, h) = make_simple(64);
    p.set_sample(h, &sample_data).unwrap();
    p.set_smp_cnt(h, 99).unwrap();

    let pdu = decode_pdu(&p);
    assert_eq!(pdu.asdus[0].sample, sample_data);
    assert_eq!(pdu.asdus[0].smp_cnt, 99);
}

#[test]
fn increase_smp_cnt_and_decode() {
    let (mut p, h) = make_simple(8);
    for _ in 0..10 {
        p.increase_smp_cnt(h).unwrap();
    }
    let pdu = decode_pdu(&p);
    assert_eq!(pdu.asdus[0].smp_cnt, 10);
}

#[test]
fn smp_cnt_limit_none_wrap_at_65535() {
    // With no limit the counter wraps at the full u16 range.
    let (mut p, h) = make_simple(8);
    p.set_smp_cnt(h, 65535).unwrap();
    p.increase_smp_cnt(h).unwrap();
    assert_eq!(p.get_smp_cnt(h).unwrap(), 0);

    let pdu = decode_pdu(&p);
    assert_eq!(pdu.asdus[0].smp_cnt, 0);
}

#[test]
fn smp_cnt_limit_80_wrap() {
    // A limit of 80 counts 0 through 79.
    let mut b = SvPublisherBuilder::new(SRC_MAC);
    let h = b.add_asdu("sv1", None::<String>, 1, 8).unwrap();
    b.set_smp_cnt_limit(h, Some(NonZeroU16::new(80).unwrap()))
        .unwrap();
    let mut p = b.setup_complete().unwrap();

    p.set_smp_cnt(h, 79).unwrap();
    p.increase_smp_cnt(h).unwrap();
    assert_eq!(p.get_smp_cnt(h).unwrap(), 0);
}

#[test]
fn smp_cnt_limit_4000_wrap() {
    // A limit of 4000 matches 4000 samples per second at 50 Hz.
    let mut b = SvPublisherBuilder::new(SRC_MAC);
    let h = b.add_asdu("sv1", None::<String>, 1, 8).unwrap();
    b.set_smp_cnt_limit(h, Some(NonZeroU16::new(4000).unwrap()))
        .unwrap();
    let mut p = b.setup_complete().unwrap();

    p.set_smp_cnt(h, 3999).unwrap();
    p.increase_smp_cnt(h).unwrap();
    assert_eq!(p.get_smp_cnt(h).unwrap(), 0);

    // A mid-range value must not wrap.
    p.set_smp_cnt(h, 1000).unwrap();
    p.increase_smp_cnt(h).unwrap();
    assert_eq!(p.get_smp_cnt(h).unwrap(), 1001);
}

#[test]
fn gm_identity_initial_and_post_setup_update() {
    let gm_init = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let gm_new = [0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02];

    let mut b = SvPublisherBuilder::new(SRC_MAC);
    let h = b.add_asdu("sv1", None::<String>, 1, 8).unwrap();
    b.set_gm_identity(h, gm_init).unwrap();
    let mut p = b.setup_complete().unwrap();

    let pdu1 = decode_pdu(&p);
    assert_eq!(pdu1.asdus[0].gm_identity, Some(gm_init));

    // The field is written straight into the frame after setup.
    p.set_gm_identity(h, gm_new).unwrap();
    let pdu2 = decode_pdu(&p);
    assert_eq!(pdu2.asdus[0].gm_identity, Some(gm_new));
}

#[test]
fn hundred_consecutive_smp_cnt_increase() {
    let (mut p, h) = make_simple(64);
    let sample = vec![0u8; 64];
    p.set_sample(h, &sample).unwrap();

    for expected in 1u16..=100 {
        p.increase_smp_cnt(h).unwrap();
        let cnt = p.get_smp_cnt(h).unwrap();
        assert_eq!(
            cnt, expected,
            "smpcnt is {expected} after {expected} increments"
        );
    }

    let pdu = decode_pdu(&p);
    assert_eq!(pdu.asdus[0].smp_cnt, 100);
    assert_eq!(pdu.asdus[0].sample, sample);
}

#[test]
fn refr_tm_enable_and_set() {
    let mut b = SvPublisherBuilder::new(SRC_MAC);
    let h = b.add_asdu("sv1", None::<String>, 1, 8).unwrap();
    b.enable_refr_tm(h).unwrap();
    let mut p = b.setup_complete().unwrap();

    let ts = [0x01u8, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
    p.set_refr_tm(h, ts).unwrap();

    let pdu = decode_pdu(&p);
    assert_eq!(pdu.asdus[0].refr_tm, Some(ts));
}

#[test]
fn multi_asdu_no_asdu_2_byte_exact_decode() {
    let mut b = SvPublisherBuilder::new(SRC_MAC);
    let h0 = b.add_asdu("sv0", None::<String>, 1, 64).unwrap();
    let h1 = b.add_asdu("sv1", None::<String>, 1, 64).unwrap();
    let mut p = b.setup_complete().unwrap();

    let s0: Vec<u8> = (0..64u8).collect();
    let s1: Vec<u8> = (64..128u8).collect();
    p.set_sample(h0, &s0).unwrap();
    p.set_sample(h1, &s1).unwrap();
    p.set_smp_cnt(h0, 10).unwrap();
    p.set_smp_cnt(h1, 20).unwrap();

    let bytes = p.frame_bytes();
    let pdu = decode_sav_pdu(&bytes[SV_HEADER_NO_VLAN..]).unwrap();

    assert_eq!(pdu.asdus.len(), 2);
    assert_eq!(pdu.asdus[0].sample, s0);
    assert_eq!(pdu.asdus[1].sample, s1);
    assert_eq!(pdu.asdus[0].smp_cnt, 10);
    assert_eq!(pdu.asdus[1].smp_cnt, 20);
}

#[test]
fn vlan_frame_decode_header_offset_correct() {
    let vlan = VlanTag {
        priority: VlanPriority::new(4).unwrap(),
        vlan_id: 100,
    };
    let mut b = SvPublisherBuilder::new(SRC_MAC);
    b = b.with_vlan(vlan);
    let h = b.add_asdu("sv1", None::<String>, 1, 8).unwrap();
    let p = b.setup_complete().unwrap();

    let bytes = p.frame_bytes();
    // With a VLAN tag the PDU starts at offset 26.
    let pdu = decode_sav_pdu(&bytes[SV_HEADER_WITH_VLAN..]).unwrap();
    assert_eq!(pdu.asdus.len(), 1);

    assert_eq!(
        u16::from_be_bytes([bytes[12], bytes[13]]),
        0x8100,
        "tpid at offset 12"
    );
    let _ = h;
}

#[test]
fn set_smp_synch_global_clock() {
    let (mut p, h) = make_simple(8);
    p.set_smp_synch(h, SmpSynch::GlobalClock).unwrap();
    let pdu = decode_pdu(&p);
    assert_eq!(pdu.asdus[0].smp_synch, SmpSynch::GlobalClock);
}

#[test]
fn sample_size_mismatch_err() {
    let (mut p, h) = make_simple(64);
    let result = p.set_sample(h, &[0u8; 8]);
    assert!(result.is_err());
}

#[test]
fn gm_identity_not_enabled_returns_err() {
    let (mut p, h) = make_simple(8);
    let result = p.set_gm_identity(h, [0u8; 8]);
    assert!(result.is_err());
}

#[test]
fn refr_tm_not_enabled_returns_err() {
    let (mut p, h) = make_simple(8);
    let result = p.set_refr_tm(h, [0u8; 8]);
    assert!(result.is_err());
}

/// The svID bound is inclusive: an identifier of exactly `SV_STRING_MAX_LEN` bytes
/// is accepted and reaches the published frame.
#[test]
fn add_asdu_sv_id_at_the_limit_ok() {
    let sv_id = "A".repeat(SV_STRING_MAX_LEN);
    let mut b = SvPublisherBuilder::new(SRC_MAC);
    b.add_asdu(sv_id.clone(), None::<String>, 1, 64)
        .expect("an svid at the limit is accepted");
    let p = b.setup_complete().unwrap();
    assert_eq!(decode_pdu(&p).asdus[0].sv_id, sv_id);
}

/// An svID past `SV_STRING_MAX_LEN` is refused at configuration time, so a
/// publisher never emits a stream identifier a subscriber must reject.
#[test]
fn add_asdu_sv_id_too_long_err() {
    let mut b = SvPublisherBuilder::new(SRC_MAC);
    let result = b.add_asdu("A".repeat(SV_STRING_MAX_LEN + 1), None::<String>, 1, 64);
    assert!(
        matches!(result, Err(SvError::SvIdTooLong(130))),
        "an over-long svid returns svidtoolong, got {:?}",
        result
    );
}

/// The datSet bound is inclusive: a reference of exactly `SV_STRING_MAX_LEN`
/// bytes is accepted and reaches the published frame.
#[test]
fn add_asdu_dat_set_at_the_limit_ok() {
    let dat_set = "D".repeat(SV_STRING_MAX_LEN);
    let mut b = SvPublisherBuilder::new(SRC_MAC);
    b.add_asdu("sv1", Some(dat_set.clone()), 1, 64)
        .expect("a datset at the limit is accepted");
    let p = b.setup_complete().unwrap();
    assert_eq!(
        decode_pdu(&p).asdus[0].dat_set.as_deref(),
        Some(dat_set.as_str())
    );
}

/// A datSet past `SV_STRING_MAX_LEN` is refused at configuration time, so a
/// publisher never emits a reference a subscriber must reject.
#[test]
fn add_asdu_dat_set_too_long_err() {
    let mut b = SvPublisherBuilder::new(SRC_MAC);
    let result = b.add_asdu("sv1", Some("D".repeat(SV_STRING_MAX_LEN + 1)), 1, 64);
    assert!(
        matches!(result, Err(SvError::DatSetTooLong(130))),
        "an over-long datset returns datsettoolong, got {:?}",
        result
    );
}
