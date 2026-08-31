//! Regenerates the seed corpus of the Sampled Values fuzz targets.
//!
//! A libFuzzer mutator starts from the bytes under `corpus/<target>/`; seeds
//! that already resemble real traffic reach interesting states sooner. This
//! binary writes two kinds of seed:
//!
//! 1. Valid PDUs and frames produced by `encode_sav_pdu` and `SvFrame::encode`,
//!    including the IEC 61850-9-2 LE profile shape.
//! 2. Malformed inputs for the robustness cases the decoder must survive (a
//!    long-form sample length, a zero-length sample, an inner length overflow,
//!    an indefinite length, an over-long svID, an over-long datSet), plus two
//!    length-encoding cases a decoder meets on a live network.
//!
//! Seeds land in `corpus/sv_pdu_parse/` and `corpus/sv_frame_parse/`. Each seed
//! has a fixed file name, so a corpus grown by the mutator is not overwritten.
//!
//! Run from `crates/iec61850-sv/fuzz` on a nightly toolchain:
//!
//! ```sh
//! cargo run --bin gen_corpus
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use bytes::BytesMut;
use iec61850_sv::frame::{SvFrame, SvFrameHeader, VlanPriority, VlanTag};
use iec61850_sv::pdu::{encode_sav_pdu, Asdu, SavPdu, SmpMod, SmpSynch};
use iec61850_sv::SV_DEFAULT_DST_MAC;

fn pdu_corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus/sv_pdu_parse")
}

fn frame_corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus/sv_frame_parse")
}

fn write_seed(dir: &Path, name: &str, bytes: &[u8]) {
    fs::create_dir_all(dir).expect("mkdir corpus");
    let path = dir.join(name);
    fs::write(&path, bytes).expect("write seed");
    println!("  {} ({} bytes)", path.display(), bytes.len());
}

// -- PDU encoder helper --

fn encode_pdu(pdu: &SavPdu) -> Vec<u8> {
    let mut buf = BytesMut::new();
    encode_sav_pdu(pdu, &mut buf).expect("encode_sav_pdu");
    buf.to_vec()
}

fn make_minimal_asdu(sv_id: &str, sample_size: usize) -> Asdu {
    Asdu {
        sv_id: sv_id.to_string(),
        dat_set: None,
        smp_cnt: 0,
        conf_rev: 1,
        refr_tm: None,
        smp_synch: SmpSynch::GlobalClock,
        smp_rate: None,
        sample: vec![0u8; sample_size],
        smp_mod: None,
        gm_identity: None,
    }
}

fn make_pdu_minimal() -> SavPdu {
    SavPdu {
        asdus: vec![make_minimal_asdu("svMin", 8)],
    }
}

fn make_pdu_two_asdu() -> SavPdu {
    SavPdu {
        asdus: vec![make_minimal_asdu("sv01", 8), make_minimal_asdu("sv02", 8)],
    }
}

fn make_pdu_9_2_le() -> SavPdu {
    // IEC 61850-9-2 LE: a 64-byte sample, eight channels of eight bytes.
    SavPdu {
        asdus: vec![Asdu {
            sv_id: "MUnn01".to_string(),
            dat_set: Some("MUnn01/LLN0$dataset".to_string()),
            smp_cnt: 1234,
            conf_rev: 1,
            refr_tm: Some([0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0xA0]),
            smp_synch: SmpSynch::GlobalClock,
            smp_rate: Some(4000),
            sample: vec![0x55u8; 64],
            smp_mod: Some(SmpMod::PerNominalPeriod),
            gm_identity: Some([0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED, 0xFA, 0xCE]),
        }],
    }
}

fn make_pdu_all_optional() -> SavPdu {
    // Every optional field is present, so the full decode path is exercised.
    let mut pdu = make_pdu_9_2_le();
    pdu.asdus.push(Asdu {
        sv_id: "MUnn02".to_string(),
        dat_set: Some("ds2".to_string()),
        smp_cnt: 65534,
        conf_rev: 0xCAFEBABE,
        refr_tm: Some([0xFF; 8]),
        smp_synch: SmpSynch::LocalIdentified(100),
        smp_rate: Some(0xFFFF),
        sample: vec![0xAA; 128], // over 127 bytes, forcing long-form length
        smp_mod: Some(SmpMod::SamplesPerSecond),
        gm_identity: Some([0u8; 8]),
    });
    pdu
}

// -- Malformed PDU builders: the BER attack surface --

/// A two-byte smpMod inside an otherwise valid ASDU. Some publishers in the
/// field encode the field this way, so the decoder stays tolerant of it.
fn poison_smp_mod_2_byte() -> Vec<u8> {
    // Hand-built BER so the smpMod length is exactly two bytes:
    // savPdu 0x60 { noASDU 0x80, asdu_seq 0xA2 { asdu 0x30 { ... } } }.
    let inner = vec![
        // svID 0x80 len=4 "test"
        0x80, 0x04, b't', b'e', b's', b't', // smpCnt 0x82 len=2 0x0001
        0x82, 0x02, 0x00, 0x01, // confRev 0x83 len=4 0x00000001
        0x83, 0x04, 0x00, 0x00, 0x00, 0x01, // smpSynch 0x85 len=1 0x02
        0x85, 0x01, 0x02, // sample 0x87 len=4
        0x87, 0x04, 0xDE, 0xAD, 0xBE, 0xEF,
        // smpMod 0x88 with length 2 where the field is one byte
        0x88, 0x02, 0x00, 0x00,
    ];
    let mut asdu = vec![0x30, inner.len() as u8];
    asdu.extend(&inner);
    let mut asdu_seq = vec![0xA2, asdu.len() as u8];
    asdu_seq.extend(&asdu);
    let mut body = vec![0x80, 0x01, 0x01]; // noASDU=1
    body.extend(&asdu_seq);
    let mut pdu = vec![0x60, body.len() as u8];
    pdu.extend(&body);
    pdu
}

/// A sample over 127 bytes carries a long-form BER
/// length, which the decoder must honor without reading past the buffer.
fn poison_large_sample_long_form_length() -> Vec<u8> {
    // The length declares 200 sample bytes; the buffer stops after 50.
    let inner_prefix = vec![
        0x80, 0x04, b'b', b'i', b'g', b'!', // svID
        0x82, 0x02, 0x00, 0x02, // smpCnt
        0x83, 0x04, 0x00, 0x00, 0x00, 0x01, // confRev
        0x85, 0x01, 0x02, // smpSynch
        0x87, 0x81, 0xC8, // sample 0x87 long-form length=200
    ];
    // Only 50 of the declared 200 bytes follow, so the decoder must error.
    let mut inner = inner_prefix.clone();
    inner.extend(vec![0x42u8; 50]);
    let mut asdu = vec![0x30, 0x81, inner.len() as u8];
    asdu.extend(&inner);
    let mut asdu_seq = vec![0xA2, 0x81, asdu.len() as u8];
    asdu_seq.extend(&asdu);
    let mut body = vec![0x80, 0x01, 0x01];
    body.extend(&asdu_seq);
    let mut pdu = vec![0x60, 0x81, body.len() as u8];
    pdu.extend(&body);
    pdu
}

/// A zero-length sample OCTET STRING, which the
/// decoder must reject rather than panic on.
fn poison_sample_size_zero() -> Vec<u8> {
    let inner = vec![
        0x80, 0x03, b'z', b'r', b'o', // svID
        0x82, 0x02, 0x00, 0x00, // smpCnt
        0x83, 0x04, 0x00, 0x00, 0x00, 0x01, // confRev
        0x85, 0x01, 0x02, // smpSynch
        0x87, 0x00, // sample length=0
    ];
    let mut asdu = vec![0x30, inner.len() as u8];
    asdu.extend(&inner);
    let mut asdu_seq = vec![0xA2, asdu.len() as u8];
    asdu_seq.extend(&asdu);
    let mut body = vec![0x80, 0x01, 0x01];
    body.extend(&asdu_seq);
    let mut pdu = vec![0x60, body.len() as u8];
    pdu.extend(&body);
    pdu
}

/// An svID one byte past the 129-byte bound, which the decoder must reject
/// without reading past the enclosing ASDU.
fn poison_sv_id_too_long() -> Vec<u8> {
    let mut inner = vec![0x80, 0x81, 0x82]; // svID long-form length=130
    inner.extend(vec![b'A'; 130]);
    inner.extend_from_slice(&[0x82, 0x02, 0x00, 0x00]); // smpCnt
    inner.extend_from_slice(&[0x83, 0x04, 0x00, 0x00, 0x00, 0x01]); // confRev
    inner.extend_from_slice(&[0x85, 0x01, 0x02]); // smpSynch
    inner.extend_from_slice(&[0x87, 0x04, 0x00, 0x00, 0x00, 0x00]); // sample
    let mut asdu = vec![0x30, 0x81, inner.len() as u8];
    asdu.extend(&inner);
    let mut asdu_seq = vec![0xA2, 0x81, asdu.len() as u8];
    asdu_seq.extend(&asdu);
    let mut body = vec![0x80, 0x01, 0x01];
    body.extend(&asdu_seq);
    let mut pdu = vec![0x60, 0x81, body.len() as u8];
    pdu.extend(&body);
    pdu
}

/// A datSet one byte past the 129-byte bound, which the decoder must reject
/// without reading past the enclosing ASDU.
fn poison_dat_set_too_long() -> Vec<u8> {
    let mut inner = vec![0x80, 0x03, b's', b'v', b'1']; // svID
    inner.extend_from_slice(&[0x81, 0x81, 0x82]); // datSet long-form length=130
    inner.extend(vec![b'D'; 130]);
    inner.extend_from_slice(&[0x82, 0x02, 0x00, 0x00]); // smpCnt
    inner.extend_from_slice(&[0x83, 0x04, 0x00, 0x00, 0x00, 0x01]); // confRev
    inner.extend_from_slice(&[0x85, 0x01, 0x02]); // smpSynch
    inner.extend_from_slice(&[0x87, 0x04, 0x00, 0x00, 0x00, 0x00]); // sample
    let mut asdu = vec![0x30, 0x81, inner.len() as u8];
    asdu.extend(&inner);
    let mut asdu_seq = vec![0xA2, 0x81, asdu.len() as u8];
    asdu_seq.extend(&asdu);
    let mut body = vec![0x80, 0x01, 0x01];
    body.extend(&asdu_seq);
    let mut pdu = vec![0x60, 0x81, body.len() as u8];
    pdu.extend(&body);
    pdu
}

/// The outer BER length declares far more bytes than the buffer holds.
fn poison_corrupt_ber_length() -> Vec<u8> {
    // savPdu 0x60 declaring 65535 content bytes over five.
    vec![0x60, 0x82, 0xFF, 0xFF, 0x80, 0x01, 0x01]
}

/// The outer SavPdu length is consistent but an inner
/// ASDU declares a length beyond what the outer element leaves.
fn poison_inner_length_overflow() -> Vec<u8> {
    // Outer length 10, inner SEQUENCE OF ASDU length 20.
    vec![
        0x60, 0x0A, // SavPdu length=10
        0x80, 0x01, 0x01, // noASDU=1
        0xA2, 0x14, // SEQUENCE OF ASDU length=20 (> 10-3)
        0x30, 0x10, // ASDU length=16
        b'X', b'Y', b'Z', // three content bytes remain
    ]
}

/// Indefinite length (0x80). BER permits it, the
/// IEC 61850 encoding rules do not, so the decoder must reject it.
fn poison_indefinite_length() -> Vec<u8> {
    vec![0x60, 0x80, 0x80, 0x01, 0x01, 0x00, 0x00]
}

/// noASDU above MAX_ASDU_PER_FRAME, which must raise TooManyAsdus.
fn poison_too_many_asdus() -> Vec<u8> {
    // noASDU is 20 over an empty ASDU list, so the bound is checked first.
    vec![
        0x60, 0x07, 0x80, 0x01, 0x14, // noASDU=20
        0xA2, 0x02, 0x30, 0x00, // empty ASDU list
    ]
}

// -- Frame builders --

fn make_frame(pdu_bytes: Vec<u8>, vlan: Option<VlanTag>) -> Vec<u8> {
    let header = SvFrameHeader {
        dst_mac: SV_DEFAULT_DST_MAC,
        src_mac: [0x02, 0, 0, 0, 0, 1],
        vlan,
        app_id: 0x4000,
        length: (pdu_bytes.len() + 8) as u16,
    };
    let frame = SvFrame { header, pdu_bytes };
    let mut buf = BytesMut::new();
    frame.encode(&mut buf).expect("frame encode");
    buf.to_vec()
}

fn poison_frame_wrong_ethertype() -> Vec<u8> {
    // The GOOSE EtherType over an SV-shaped payload, which the frame decoder
    // must reject.
    vec![
        0x01, 0x0C, 0xCD, 0x04, 0x00, 0x00, // dst
        0x02, 0, 0, 0, 0, 1, // src
        0x88, 0xB8, // wrong ethertype (GOOSE not SV)
        0x40, 0x00, // appid
        0x00, 0x10, // length
        0x00, 0x00, 0x00, 0x00, // reserved
        0x60, 0x05, 0x80, 0x01, 0x01, 0xA2, 0x00, // tiny pdu
    ]
}

fn poison_frame_too_short() -> Vec<u8> {
    // Ten bytes, below SV_MIN_FRAME_SIZE.
    vec![0x01, 0x0C, 0xCD, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]
}

// -- main --

fn main() {
    let pdu_dir = pdu_corpus_dir();
    let frame_dir = frame_corpus_dir();

    println!("== sv_pdu_parse seeds =>  {}", pdu_dir.display());

    // valid seeds
    write_seed(
        &pdu_dir,
        "valid_minimal.bin",
        &encode_pdu(&make_pdu_minimal()),
    );
    write_seed(
        &pdu_dir,
        "valid_two_asdu.bin",
        &encode_pdu(&make_pdu_two_asdu()),
    );
    write_seed(
        &pdu_dir,
        "valid_9_2_le.bin",
        &encode_pdu(&make_pdu_9_2_le()),
    );
    write_seed(
        &pdu_dir,
        "valid_all_optional.bin",
        &encode_pdu(&make_pdu_all_optional()),
    );

    // poison seeds
    write_seed(&pdu_dir, "smp_mod_2_byte.bin", &poison_smp_mod_2_byte());
    write_seed(
        &pdu_dir,
        "large_sample_long_form_length.bin",
        &poison_large_sample_long_form_length(),
    );
    write_seed(
        &pdu_dir,
        "sample_size_zero.bin",
        &poison_sample_size_zero(),
    );
    write_seed(&pdu_dir, "sv_id_too_long.bin", &poison_sv_id_too_long());
    write_seed(&pdu_dir, "dat_set_too_long.bin", &poison_dat_set_too_long());
    write_seed(
        &pdu_dir,
        "corrupt_ber_length.bin",
        &poison_corrupt_ber_length(),
    );
    write_seed(
        &pdu_dir,
        "inner_length_overflow.bin",
        &poison_inner_length_overflow(),
    );
    write_seed(
        &pdu_dir,
        "indefinite_length.bin",
        &poison_indefinite_length(),
    );
    write_seed(
        &pdu_dir,
        "poison_too_many_asdus.bin",
        &poison_too_many_asdus(),
    );

    println!();
    println!("== sv_frame_parse seeds =>  {}", frame_dir.display());

    // valid frames
    let pdu_bytes = encode_pdu(&make_pdu_minimal());
    write_seed(
        &frame_dir,
        "valid_minimal.bin",
        &make_frame(pdu_bytes.clone(), None),
    );
    write_seed(
        &frame_dir,
        "valid_vlan.bin",
        &make_frame(
            pdu_bytes.clone(),
            Some(VlanTag {
                priority: VlanPriority::new(4).unwrap(),
                vlan_id: 0,
            }),
        ),
    );
    let pdu_9_2_le = encode_pdu(&make_pdu_9_2_le());
    write_seed(
        &frame_dir,
        "valid_9_2_le.bin",
        &make_frame(pdu_9_2_le, None),
    );

    // poison frames
    write_seed(
        &frame_dir,
        "poison_wrong_ethertype.bin",
        &poison_frame_wrong_ethertype(),
    );
    write_seed(
        &frame_dir,
        "poison_too_short.bin",
        &poison_frame_too_short(),
    );

    // The PDU-level seeds also reach the frame target, wrapped in an SV header.
    let too_many = poison_too_many_asdus();
    write_seed(
        &frame_dir,
        "poison_pdu_too_many_asdus.bin",
        &make_frame(too_many, None),
    );
    let bad_length = poison_corrupt_ber_length();
    write_seed(
        &frame_dir,
        "poison_pdu_corrupt_length.bin",
        &make_frame(bad_length, None),
    );

    println!();
    println!("seed corpus written");
}
