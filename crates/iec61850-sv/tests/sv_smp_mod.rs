//! smpMod travels as an INT16U in two octets, per IEC 61850-9-2 §8.5.2
//! Table 14.

use bytes::BytesMut;
use iec61850_sv::{
    decode_sav_pdu, encode_sav_pdu, Asdu, SavPdu, SmpMod, SmpSynch, SvPublisherBuilder,
    SV_HEADER_NO_VLAN,
};

mod log_capture;
use log_capture::warnings_containing;

#[test]
fn publisher_encodes_smp_mod_in_two_octets() {
    let mut b = SvPublisherBuilder::new([0x02, 0, 0, 0, 0, 1]);
    let h = b.add_asdu("MU01", None::<String>, 1, 8).unwrap();
    b.set_smp_mod(h, 1).unwrap();
    let p = b.setup_complete().unwrap();
    let frame = p.frame_bytes();
    let tail = &frame[frame.len() - 4..];
    assert_eq!(tail, &[0x88, 0x02, 0x00, 0x01], "smpmod is the last member");
    let pdu = decode_sav_pdu(&frame[SV_HEADER_NO_VLAN..]).unwrap();
    assert_eq!(pdu.asdus[0].smp_mod, Some(SmpMod::SamplesPerSecond));
}

#[test]
fn publisher_without_smp_mod_sends_none() {
    let mut b = SvPublisherBuilder::new([0x02, 0, 0, 0, 0, 1]);
    b.add_asdu("MU01", None::<String>, 1, 8).unwrap();
    let p = b.setup_complete().unwrap();
    let pdu = decode_sav_pdu(&p.frame_bytes()[SV_HEADER_NO_VLAN..]).unwrap();
    assert_eq!(pdu.asdus[0].smp_mod, None);
}

/// Encodes a one-ASDU savPdu whose smpMod member carries `smp_mod`.
fn pdu_with_smp_mod(smp_mod: &[u8]) -> Vec<u8> {
    let pdu = SavPdu {
        asdus: vec![Asdu {
            sv_id: "MU01".into(),
            dat_set: None,
            smp_cnt: 0,
            conf_rev: 1,
            refr_tm: None,
            smp_synch: SmpSynch::GlobalClock,
            smp_rate: None,
            sample: vec![0; 8],
            smp_mod: Some(SmpMod::SamplesPerSecond),
            gm_identity: None,
        }],
    };
    let mut buf = BytesMut::new();
    encode_sav_pdu(&pdu, &mut buf).unwrap();
    let mut b = buf.to_vec();
    // smpMod is the last member: 88 02 00 01.
    let n = b.len();
    assert_eq!(&b[n - 4..], &[0x88, 0x02, 0x00, 0x01]);
    b.truncate(n - 4);
    b.push(0x88);
    b.push(smp_mod.len() as u8);
    b.extend_from_slice(smp_mod);
    let delta = smp_mod.len() as u8;
    // Every enclosing length is in the short form; patch savPdu, the ASDU
    // sequence, and the ASDU, which sit at fixed offsets.
    for at in [1usize, 6, 8] {
        b[at] = b[at] + delta - 2;
    }
    b
}

#[test]
fn unassigned_smp_mod_is_dropped_and_logged_once() {
    let frame = pdu_with_smp_mod(&[0x01, 0x00]);
    let logged = warnings_containing("smpmod value", || {
        for _ in 0..10 {
            let pdu = decode_sav_pdu(&frame).unwrap();
            assert_eq!(pdu.asdus[0].smp_mod, None);
        }
    });
    assert_eq!(logged, 1);
}

#[test]
fn one_octet_smp_mod_is_logged_once() {
    let frame = pdu_with_smp_mod(&[0x01]);
    let logged = warnings_containing("smpmod is 1 octet", || {
        for _ in 0..10 {
            let pdu = decode_sav_pdu(&frame).unwrap();
            assert_eq!(pdu.asdus[0].smp_mod, Some(SmpMod::SamplesPerSecond));
        }
    });
    assert_eq!(logged, 1);
}
