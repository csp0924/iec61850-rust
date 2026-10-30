//! Receive-path behavior of the GOOSE decoder, receiver, and subscriber.

use bytes::BytesMut;
use iec61850_goose::GoosePdu;
use iec61850_model::MmsValue;

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
