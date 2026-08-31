//! Integration tests for savPdu BER encoding and decoding.

use bytes::BytesMut;
use iec61850_model::Quality;
use iec61850_sv::nine_two_le::{ChannelSample, NineTwoLE, SAMPLE_SIZE};
use iec61850_sv::pdu::{
    decode_sav_pdu, encode_sav_pdu, Asdu, SavPdu, SmpMod, SmpSynch, MAX_ASDU_PER_FRAME,
    SV_STRING_MAX_LEN,
};
use iec61850_sv::SvError;

fn minimal_asdu(sv_id: &str, smp_cnt: u16) -> Asdu {
    Asdu {
        sv_id: sv_id.to_owned(),
        dat_set: None,
        smp_cnt,
        conf_rev: 1,
        refr_tm: None,
        smp_synch: SmpSynch::NotSynced,
        smp_rate: None,
        sample: vec![0u8; 8],
        smp_mod: None,
        gm_identity: None,
    }
}

fn encode_decode(pdu: &SavPdu) -> SavPdu {
    let mut buf = BytesMut::new();
    encode_sav_pdu(pdu, &mut buf).expect("encode the pdu");
    decode_sav_pdu(&buf).expect("decode the encoded pdu")
}

#[test]
fn minimal_asdu_byte_exact_roundtrip() {
    let pdu = SavPdu {
        asdus: vec![minimal_asdu("TESTLD/LLN0$SV$sv1", 0)],
    };
    let mut buf1 = BytesMut::new();
    encode_sav_pdu(&pdu, &mut buf1).unwrap();

    let decoded = decode_sav_pdu(&buf1).unwrap();
    assert_eq!(decoded, pdu);

    let mut buf2 = BytesMut::new();
    encode_sav_pdu(&decoded, &mut buf2).unwrap();

    assert_eq!(
        &buf1[..],
        &buf2[..],
        "the second encode reproduces the first"
    );
}

#[test]
fn minimal_asdu_roundtrip_2() {
    let pdu = SavPdu {
        asdus: vec![minimal_asdu("IED2/LLN0$SV$myStream", 4000)],
    };
    let decoded = encode_decode(&pdu);
    assert_eq!(decoded, pdu);
}

#[test]
fn full_optional_fields_roundtrip() {
    let pdu = SavPdu {
        asdus: vec![Asdu {
            sv_id: "IED1/LLN0$SV$fullSV".to_owned(),
            dat_set: Some("IED1/LLN0$SV$testDS".to_owned()),
            smp_cnt: 100,
            conf_rev: 0xABCDEF01,
            refr_tm: Some([0x5F, 0xA1, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD]),
            smp_synch: SmpSynch::GlobalClock,
            smp_rate: Some(4000),
            sample: vec![0xABu8; 64],
            smp_mod: Some(SmpMod::SamplesPerSecond),
            gm_identity: Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
        }],
    };
    let decoded = encode_decode(&pdu);
    assert_eq!(decoded, pdu);
    let a = &decoded.asdus[0];
    assert_eq!(a.dat_set, Some("IED1/LLN0$SV$testDS".to_owned()));
    assert_eq!(
        a.refr_tm,
        Some([0x5F, 0xA1, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD])
    );
    assert_eq!(a.smp_rate, Some(4000));
    assert_eq!(a.smp_mod, Some(SmpMod::SamplesPerSecond));
    assert_eq!(
        a.gm_identity,
        Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
    );
}

#[test]
fn no_asdu_1_roundtrip() {
    let pdu = SavPdu {
        asdus: vec![minimal_asdu("sv1", 1)],
    };
    let decoded = encode_decode(&pdu);
    assert_eq!(decoded.asdus.len(), 1);
    assert_eq!(decoded, pdu);
}

#[test]
fn no_asdu_2_roundtrip() {
    let pdu = SavPdu {
        asdus: vec![minimal_asdu("sv1", 10), minimal_asdu("sv2", 20)],
    };
    let decoded = encode_decode(&pdu);
    assert_eq!(decoded.asdus.len(), 2);
    assert_eq!(decoded.asdus[0].sv_id, "sv1");
    assert_eq!(decoded.asdus[1].sv_id, "sv2");
    assert_eq!(decoded, pdu);
}

#[test]
fn no_asdu_4_roundtrip() {
    let pdu = SavPdu {
        asdus: (0..4)
            .map(|i| minimal_asdu(&format!("sv{}", i), i as u16 * 100))
            .collect(),
    };
    let decoded = encode_decode(&pdu);
    assert_eq!(decoded.asdus.len(), 4);
    assert_eq!(decoded, pdu);
}

#[test]
fn no_asdu_10_boundary_ok() {
    assert_eq!(MAX_ASDU_PER_FRAME, 10, "the frame limit is 10 asdus");
    let pdu = SavPdu {
        asdus: (0..10)
            .map(|i| minimal_asdu(&format!("sv{}", i), i as u16))
            .collect(),
    };
    let decoded = encode_decode(&pdu);
    assert_eq!(decoded.asdus.len(), 10);
}

#[test]
fn no_asdu_11_rejected() {
    use iec61850_asn1::encode_length;

    // A savPdu announcing 11 ASDUs, one past the limit.
    let inner = vec![0x80u8, 0x01, 11u8, 0xA2, 0x00];
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&[0x60u8]);
    encode_length(inner.len(), &mut buf);
    buf.extend_from_slice(&inner);

    let result = decode_sav_pdu(&buf);
    assert!(
        matches!(result, Err(SvError::TooManyAsdus(11))),
        "an noasdu of 11 returns toomanyasdus, got {:?}",
        result
    );
}

/// A publisher that sends smpMod in two bytes must still be decoded, taking the
/// last byte as the value.
#[test]
fn smp_mod_legacy_2byte_tolerant() {
    use iec61850_asn1::encode_length;

    let mut inner_asdu = BytesMut::new();
    inner_asdu.extend_from_slice(&[0x80u8, 0x03, b's', b'v', b'1']); // svID
    inner_asdu.extend_from_slice(&[0x82u8, 0x02, 0x00, 0x00]); // smpCnt
    inner_asdu.extend_from_slice(&[0x83u8, 0x04, 0x00, 0x00, 0x00, 0x01]); // confRev
    inner_asdu.extend_from_slice(&[0x85u8, 0x01, 0x00]); // smpSynch
    inner_asdu.extend_from_slice(&[0x87u8, 0x04, 0x00, 0x00, 0x00, 0x00]); // sample
    inner_asdu.extend_from_slice(&[0x88u8, 0x02, 0x00, 0x01]); // smpMod, 2 bytes

    let mut asdu_tlv = BytesMut::new();
    asdu_tlv.extend_from_slice(&[0x30u8]);
    encode_length(inner_asdu.len(), &mut asdu_tlv);
    asdu_tlv.extend_from_slice(&inner_asdu);

    let mut seq_tlv = BytesMut::new();
    seq_tlv.extend_from_slice(&[0xA2u8]);
    encode_length(asdu_tlv.len(), &mut seq_tlv);
    seq_tlv.extend_from_slice(&asdu_tlv);

    let no_asdu_bytes = vec![0x80u8, 0x01, 0x01];
    let contents_len = no_asdu_bytes.len() + seq_tlv.len();
    let mut final_buf = BytesMut::new();
    final_buf.extend_from_slice(&[0x60u8]);
    encode_length(contents_len, &mut final_buf);
    final_buf.extend_from_slice(&no_asdu_bytes);
    final_buf.extend_from_slice(&seq_tlv);

    let decoded = decode_sav_pdu(&final_buf).unwrap();
    assert_eq!(decoded.asdus.len(), 1);
    // The last byte, 0x01, is the value.
    assert_eq!(decoded.asdus[0].smp_mod, Some(SmpMod::SamplesPerSecond));
}

#[test]
fn smp_synch_local_identified_roundtrip() {
    let pdu = SavPdu {
        asdus: vec![Asdu {
            sv_id: "svLocal".to_owned(),
            dat_set: None,
            smp_cnt: 0,
            conf_rev: 1,
            refr_tm: None,
            smp_synch: SmpSynch::LocalIdentified(100),
            smp_rate: None,
            sample: vec![0u8; 8],
            smp_mod: None,
            gm_identity: None,
        }],
    };
    let decoded = encode_decode(&pdu);
    assert_eq!(decoded.asdus[0].smp_synch, SmpSynch::LocalIdentified(100));
}

#[test]
fn nine_two_le_64_byte_sample_roundtrip() {
    let sv = NineTwoLE {
        channels: [
            ChannelSample::new(500, Quality::GOOD),
            ChannelSample::new(-500, Quality(0x0001)),
            ChannelSample::new(750, Quality(0x0004)),
            ChannelSample::new(0, Quality(0x0008)),
            ChannelSample::new(220000, Quality(0x0010)),
            ChannelSample::new(-220000, Quality(0x0020)),
            ChannelSample::new(220000, Quality(0x0040)),
            ChannelSample::new(0, Quality(0x0080)),
        ],
    };
    let sample_bytes = sv.to_sample();
    assert_eq!(sample_bytes.len(), SAMPLE_SIZE);

    // Carry the sample through a full PDU round trip.
    let pdu = SavPdu {
        asdus: vec![Asdu {
            sv_id: "IED1/LLN0$SV$sv9_2LE".to_owned(),
            dat_set: None,
            smp_cnt: 0,
            conf_rev: 1,
            refr_tm: None,
            smp_synch: SmpSynch::GlobalClock,
            smp_rate: Some(4000),
            sample: sample_bytes.to_vec(),
            smp_mod: None,
            gm_identity: None,
        }],
    };
    let decoded = encode_decode(&pdu);
    let decoded_bytes: [u8; SAMPLE_SIZE] = decoded.asdus[0].sample[..].try_into().unwrap();
    let decoded_sv = NineTwoLE::from_sample(&decoded_bytes);
    assert_eq!(decoded_sv, sv);
}

/// Robustness regression: smpMod is always encoded in exactly one byte.
#[test]
fn smp_mod_encodes_one_byte() {
    let pdu = SavPdu {
        asdus: vec![Asdu {
            sv_id: "sv1".to_owned(),
            dat_set: None,
            smp_cnt: 0,
            conf_rev: 1,
            refr_tm: None,
            smp_synch: SmpSynch::NotSynced,
            smp_rate: None,
            sample: vec![0u8; 4],
            smp_mod: Some(SmpMod::SamplesPerSecond),
            gm_identity: None,
        }],
    };
    let mut buf = BytesMut::new();
    encode_sav_pdu(&pdu, &mut buf).unwrap();
    let bytes = &buf[..];
    let mut found = false;
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i] == 0x88 {
            assert_eq!(
                bytes[i + 1],
                0x01,
                "smpmod ber length is 1, got {}",
                bytes[i + 1]
            );
            found = true;
            break;
        }
    }
    assert!(found, "smpmod tag 0x88 is present in the encoding");
}

/// Robustness regression: a sample longer than 127 bytes uses a
/// multi-byte BER length instead of being truncated.
#[test]
fn large_sample_ber_length() {
    let large_sample = vec![0xABu8; 200];
    let pdu = SavPdu {
        asdus: vec![Asdu {
            sv_id: "sv1".to_owned(),
            dat_set: None,
            smp_cnt: 0,
            conf_rev: 1,
            refr_tm: None,
            smp_synch: SmpSynch::NotSynced,
            smp_rate: None,
            sample: large_sample,
            smp_mod: None,
            gm_identity: None,
        }],
    };
    let mut buf = BytesMut::new();
    encode_sav_pdu(&pdu, &mut buf).unwrap();
    let bytes = &buf[..];
    // The sample tag 0x87 must be followed by the long-form length 0x81.
    let mut found = false;
    for i in 0..bytes.len().saturating_sub(2) {
        if bytes[i] == 0x87 && bytes[i + 1] == 0x81 {
            assert_eq!(bytes[i + 2], 200u8, "the length byte carries 200");
            found = true;
            break;
        }
    }
    assert!(found, "sample tag 0x87 uses the long-form length 0x81");
    let decoded = decode_sav_pdu(&buf).unwrap();
    assert_eq!(decoded.asdus[0].sample.len(), 200);
}

/// Robustness regression: a corrupt BER length returns an error instead of
/// panicking or looping.
#[test]
fn corrupt_ber_length_rejected() {
    // 0x83 announces a 3-byte long-form length, which is not supported.
    let corrupt = vec![0x60u8, 0x83, 0x00, 0x00, 0x10];
    let result = decode_sav_pdu(&corrupt);
    assert!(result.is_err(), "a corrupt ber length returns err");
}

/// The svID bound is inclusive: an identifier of exactly `SV_STRING_MAX_LEN` bytes
/// survives a round trip.
#[test]
fn sv_id_at_the_limit_accepted() {
    let sv_id = "A".repeat(SV_STRING_MAX_LEN);
    let pdu = SavPdu {
        asdus: vec![minimal_asdu(&sv_id, 0)],
    };
    assert_eq!(encode_decode(&pdu).asdus[0].sv_id, sv_id);
}

/// Robustness regression: an svID past `SV_STRING_MAX_LEN` is rejected rather than
/// truncated, and without reading past the enclosing ASDU.
#[test]
fn sv_id_too_long_rejected() {
    let pdu = SavPdu {
        asdus: vec![minimal_asdu(&"A".repeat(SV_STRING_MAX_LEN + 1), 0)],
    };
    let mut buf = BytesMut::new();
    encode_sav_pdu(&pdu, &mut buf).expect("encode the pdu");
    let result = decode_sav_pdu(&buf);
    assert!(
        matches!(result, Err(SvError::SvIdTooLong(130))),
        "an over-long svid returns svidtoolong, got {:?}",
        result
    );
}

/// The datSet bound is inclusive: a reference of exactly `SV_STRING_MAX_LEN`
/// bytes survives a round trip.
#[test]
fn dat_set_at_the_limit_accepted() {
    let dat_set = "D".repeat(SV_STRING_MAX_LEN);
    let mut asdu = minimal_asdu("sv1", 0);
    asdu.dat_set = Some(dat_set.clone());
    let pdu = SavPdu { asdus: vec![asdu] };
    assert_eq!(
        encode_decode(&pdu).asdus[0].dat_set.as_deref(),
        Some(dat_set.as_str())
    );
}

/// Robustness regression: a datSet past `SV_STRING_MAX_LEN` is rejected rather
/// than truncated, and without reading past the enclosing ASDU.
#[test]
fn dat_set_too_long_rejected() {
    let mut asdu = minimal_asdu("sv1", 0);
    asdu.dat_set = Some("D".repeat(SV_STRING_MAX_LEN + 1));
    let pdu = SavPdu { asdus: vec![asdu] };
    let mut buf = BytesMut::new();
    encode_sav_pdu(&pdu, &mut buf).expect("encode the pdu");
    let result = decode_sav_pdu(&buf);
    assert!(
        matches!(result, Err(SvError::DatSetTooLong(130))),
        "an over-long datset returns datsettoolong, got {:?}",
        result
    );
}
