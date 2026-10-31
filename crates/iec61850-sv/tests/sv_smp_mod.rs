//! smpMod travels as an INT16U in two octets, per IEC 61850-9-2 §8.5.2
//! Table 14.
//!
//! The once-per-process report of a one-octet smpMod is tested in its own
//! binary, `sv_smp_mod_report`.

use bytes::BytesMut;
use iec61850_sv::{
    decode_sav_pdu, encode_sav_pdu, Asdu, SavPdu, SmpMod, SmpSynch, SvPublisherBuilder,
    SV_HEADER_NO_VLAN,
};

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
fn publisher_encodes_an_smp_mod_above_255() {
    let mut b = SvPublisherBuilder::new([0x02, 0, 0, 0, 0, 1]);
    let h = b.add_asdu("MU01", None::<String>, 1, 8).unwrap();
    b.set_smp_mod(h, 0x0102).unwrap();
    let p = b.setup_complete().unwrap();
    let frame = p.frame_bytes();
    assert_eq!(&frame[frame.len() - 4..], &[0x88, 0x02, 0x01, 0x02]);
    let pdu = decode_sav_pdu(&frame[SV_HEADER_NO_VLAN..]).unwrap();
    assert_eq!(pdu.asdus[0].smp_mod, Some(SmpMod::Unknown(0x0102)));
}

#[test]
fn publisher_without_smp_mod_sends_none() {
    let mut b = SvPublisherBuilder::new([0x02, 0, 0, 0, 0, 1]);
    b.add_asdu("MU01", None::<String>, 1, 8).unwrap();
    let p = b.setup_complete().unwrap();
    let pdu = decode_sav_pdu(&p.frame_bytes()[SV_HEADER_NO_VLAN..]).unwrap();
    assert_eq!(pdu.asdus[0].smp_mod, None);
}

#[test]
fn unassigned_smp_mod_round_trips() {
    let pdu = SavPdu::new(vec![{
        let mut asdu = Asdu::new("MU01", 0, vec![0; 8]);
        asdu.smp_synch = SmpSynch::GlobalClock;
        asdu.smp_mod = Some(SmpMod::Unknown(256));
        asdu
    }]);
    let mut buf = BytesMut::new();
    encode_sav_pdu(&pdu, &mut buf).unwrap();
    let n = buf.len();
    assert_eq!(&buf[n - 4..], &[0x88, 0x02, 0x01, 0x00]);
    let decoded = decode_sav_pdu(&buf).unwrap();
    assert_eq!(decoded.asdus[0].smp_mod, Some(SmpMod::Unknown(256)));
}
