//! The one-time report of a one-octet smpMod.
//!
//! The decoder reports a one-octet smpMod once per process, so this binary
//! holds only the test that observes the report: any other test that decodes
//! such a value in the same process would make the count depend on test
//! order.

use bytes::BytesMut;
use iec61850_sv::{decode_sav_pdu, encode_sav_pdu, Asdu, SavPdu, SmpMod, SmpSynch};

mod log_capture;
use log_capture::warnings_containing;

/// Encodes a one-ASDU savPdu whose smpMod member carries `smp_mod`.
fn pdu_with_smp_mod(smp_mod: &[u8]) -> Vec<u8> {
    let pdu = SavPdu::new(vec![{
        let mut asdu = Asdu::new("MU01", 0, vec![0; 8]);
        asdu.smp_synch = SmpSynch::GlobalClock;
        asdu.smp_mod = Some(SmpMod::SamplesPerSecond);
        asdu
    }]);
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
