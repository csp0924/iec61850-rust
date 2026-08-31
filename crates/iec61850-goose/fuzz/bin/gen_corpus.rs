//! Regenerates the seed corpus of the GOOSE fuzz targets.
//!
//! A libFuzzer mutator starts from the bytes under `corpus/<target>/`; seeds
//! that already resemble real traffic reach interesting states sooner. This
//! binary writes two kinds of seed:
//!
//! 1. Valid PDUs and frames produced by `GoosePdu::encode_ber` and
//!    `GooseFrame::encode`, covering the dataset shapes the decoder handles.
//! 2. Malformed inputs for the robustness cases the decoder must survive.
//!
//! Seeds land in `corpus/goose_pdu_parse/` and `corpus/goose_frame_parse/`.
//! Each seed has a fixed file name, so a corpus grown by the mutator is not
//! overwritten.
//!
//! Run from `crates/iec61850-goose/fuzz` on a nightly toolchain:
//!
//! ```sh
//! cargo run --bin gen_corpus
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use bytes::BytesMut;
use iec61850_goose::frame::{GooseFrame, GooseFrameHeader, VlanPriority, VlanTag};
use iec61850_goose::pdu::GoosePdu;
use iec61850_model::MmsValue;

fn pdu_corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus/goose_pdu_parse")
}

fn frame_corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus/goose_frame_parse")
}

fn write_seed(dir: &Path, name: &str, bytes: &[u8]) {
    fs::create_dir_all(dir).expect("mkdir corpus");
    let path = dir.join(name);
    fs::write(&path, bytes).expect("write seed");
    println!("  {} ({} bytes)", path.display(), bytes.len());
}

// -- PDU encoder helper --

fn encode_pdu(pdu: &GoosePdu) -> Vec<u8> {
    let mut buf = BytesMut::new();
    pdu.encode_ber(&mut buf).expect("encode_ber");
    buf.to_vec()
}

fn make_pdu_basic() -> GoosePdu {
    GoosePdu {
        gocb_ref: "demoIED/LLN0$GO$gcb".to_string(),
        time_allowed_to_live: 1000,
        dat_set: "demoIED/LLN0$DS".to_string(),
        go_id: Some("gid".to_string()),
        t: [0u8; 8],
        st_num: 1,
        sq_num: 0,
        simulation: false,
        conf_rev: 1,
        nds_com: false,
        num_dataset_entries: 1,
        all_data: vec![MmsValue::Boolean(true)],
    }
}

fn make_pdu_mixed_types() -> GoosePdu {
    let mut pdu = make_pdu_basic();
    pdu.all_data = vec![
        MmsValue::Boolean(true),
        MmsValue::Integer(-12345),
        MmsValue::Unsigned(0xCAFEBABE),
        MmsValue::Float32(1.5),
        MmsValue::Float64(2.5),
        MmsValue::BitString {
            padding: 3,
            data: vec![0xA5, 0x5A],
        },
        MmsValue::OctetString(vec![0x00, 0x11, 0x22, 0x33]),
        MmsValue::VisibleString("hello".to_string()),
        MmsValue::MmsString("caf\u{e9}-\u{2713}".to_string()),
        MmsValue::UtcTime([1, 2, 3, 4, 5, 6, 7, 8]),
        MmsValue::BinaryTime(vec![0u8; 6]),
    ];
    pdu.num_dataset_entries = pdu.all_data.len() as u32;
    pdu
}

fn make_pdu_empty_dataset() -> GoosePdu {
    let mut pdu = make_pdu_basic();
    pdu.all_data = vec![];
    pdu.num_dataset_entries = 0;
    pdu
}

fn make_pdu_long_strings() -> GoosePdu {
    // A single string of 128 bytes or more forces BER long-form length.
    let mut pdu = make_pdu_basic();
    pdu.gocb_ref = "A".repeat(120);
    pdu.dat_set = "B".repeat(120);
    pdu.go_id = Some("C".repeat(120));
    pdu
}

fn make_pdu_large_dataset() -> GoosePdu {
    // A dataset this size pushes the [11] allData length into long form.
    let mut pdu = make_pdu_basic();
    pdu.all_data = (0..50).map(MmsValue::Integer).collect();
    pdu.num_dataset_entries = pdu.all_data.len() as u32;
    pdu
}

fn make_pdu_simulation_true() -> GoosePdu {
    let mut pdu = make_pdu_basic();
    pdu.simulation = true;
    pdu.nds_com = true;
    pdu
}

// -- Frame builders --

fn make_frame(pdu_bytes: Vec<u8>, vlan: Option<VlanTag>) -> Vec<u8> {
    let header = GooseFrameHeader {
        dst_mac: [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01],
        src_mac: [0x02, 0, 0, 0, 0, 1],
        vlan,
        app_id: 0x1000,
        length: (pdu_bytes.len() + 8) as u16,
    };
    let frame = GooseFrame::new(header, pdu_bytes);
    let mut buf = BytesMut::new();
    frame.encode(&mut buf).expect("frame encode");
    buf.to_vec()
}

// -- Malformed PDU builders --

/// The outer SEQUENCE declares length 255 over a
/// buffer of a few bytes.
fn poison_outer_length_overflow() -> Vec<u8> {
    // 0x61 outer tag, 0x81 0xFF long-form length 255, five content bytes.
    vec![0x61, 0x81, 0xFF, 0x80, 0x03, b'a', b'b', b'c']
}

/// The outer length is consistent but an inner TLV
/// declares a length beyond what the outer element leaves.
fn poison_inner_length_overflow() -> Vec<u8> {
    // The first inner TLV (0x80 gocbRef) claims 127 bytes while the outer
    // element leaves 8.
    vec![
        0x61, 0x0A, // outer SEQ length=10
        0x80, 0x7F, // gocbRef length 127, past the 8 remaining bytes
        b'X', b'Y', b'Z', b'W', b'V', b'U', b'T', b'S',
    ]
}

/// A truncated buffer holding only the outer tag and
/// a large declared length.
fn poison_truncated_outer_tlv() -> Vec<u8> {
    vec![0x61, 0x82, 0xFF, 0xFF] // declares 65535 content bytes, carries none
}

/// Indefinite length (0x80). BER permits it, the
/// IEC 61850 encoding rules do not, so the decoder must reject it.
fn poison_indefinite_length() -> Vec<u8> {
    vec![0x61, 0x80, 0x80, 0x03, b'a', b'b', b'c', 0x00, 0x00]
}

/// An INTEGER inside allData declares 16 content
/// bytes, past the 8 an MMS integer can hold, inside an otherwise valid PDU.
fn poison_integer_overlength() -> Vec<u8> {
    // A skeleton, not a complete PDU: it carries the 0x85 0x10 pattern into
    // the corpus so the mutator explores around it.
    let int16 = [
        0x85, 0x10, // INTEGER, length=16
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF,
    ];
    let mut all_data = vec![0xAB, int16.len() as u8];
    all_data.extend_from_slice(&int16);
    let mut outer = vec![0x61, all_data.len() as u8];
    outer.extend_from_slice(&all_data);
    outer
}

/// A BIT STRING needs at least the padding-count
/// byte, so a zero-length element must be rejected.
fn poison_bit_string_zero_length() -> Vec<u8> {
    // A zero-length BIT STRING (0x84 0x00) inside allData.
    let bs = [0x84, 0x00];
    let mut all_data = vec![0xAB, bs.len() as u8];
    all_data.extend_from_slice(&bs);
    let mut outer = vec![0x61, all_data.len() as u8];
    outer.extend_from_slice(&all_data);
    outer
}

/// numDatSetEntries disagrees with the number of allData members, which the
/// decoder must reject.
fn poison_num_entries_mismatch(basic_pdu_bytes: &[u8]) -> Vec<u8> {
    // Patches the numDatSetEntries byte of a valid PDU, so the corpus holds a
    // matched pair that differs in one field.
    let mut bytes = basic_pdu_bytes.to_vec();
    if let Some(pos) = bytes.windows(2).position(|w| w[0] == 0x8a && w[1] == 0x01) {
        bytes[pos + 2] = 0xFF; // numDatSetEntries becomes 255
    }
    bytes
}

// -- Malformed frame builders --

/// The frame Length field declares more bytes than the buffer holds.
fn poison_frame_length_overflow() -> Vec<u8> {
    // dst (6) + src (6) + EtherType 0x88B8 + APPID 0x1000 + Length=0xFFFF + Reserved 0 0 + 2 byte payload
    vec![
        0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01, // dst
        0x02, 0, 0, 0, 0, 0x01, // src
        0x88, 0xB8, // EtherType GOOSE
        0x10, 0x00, // APPID
        0xFF, 0xFF, // Length declares 65535
        0x00, 0x00, // Reserved 1+2
        0x61, 0x00, // outer 0x61 length=0
    ]
}

/// The frame is shorter than an Ethernet header.
fn poison_frame_too_short() -> Vec<u8> {
    vec![0x01, 0x0c, 0xcd, 0x01]
}

/// The EtherType is neither 0x88B8 (GOOSE) nor 0x8100 (VLAN tag).
fn poison_frame_wrong_ether_type() -> Vec<u8> {
    let mut f = vec![
        0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01, 0x02, 0, 0, 0, 0, 0x01, 0x08,
        0x00, // EtherType IPv4
        0x10, 0x00, 0x00, 0x08, 0x00, 0x00, 0x61, 0x00,
    ];
    f.resize(64, 0);
    f
}

// -- main --

fn main() {
    let pdu_dir = pdu_corpus_dir();
    let frame_dir = frame_corpus_dir();

    println!("PDU seeds -> {}", pdu_dir.display());

    // -- Valid PDU seeds --
    let basic = encode_pdu(&make_pdu_basic());
    write_seed(&pdu_dir, "valid_basic.bin", &basic);
    write_seed(
        &pdu_dir,
        "valid_mixed_types.bin",
        &encode_pdu(&make_pdu_mixed_types()),
    );
    write_seed(
        &pdu_dir,
        "valid_empty_dataset.bin",
        &encode_pdu(&make_pdu_empty_dataset()),
    );
    write_seed(
        &pdu_dir,
        "valid_long_strings.bin",
        &encode_pdu(&make_pdu_long_strings()),
    );
    write_seed(
        &pdu_dir,
        "valid_large_dataset.bin",
        &encode_pdu(&make_pdu_large_dataset()),
    );
    write_seed(
        &pdu_dir,
        "valid_simulation_true.bin",
        &encode_pdu(&make_pdu_simulation_true()),
    );

    // -- Malformed PDU seeds --
    write_seed(
        &pdu_dir,
        "outer_length_overflow.bin",
        &poison_outer_length_overflow(),
    );
    write_seed(
        &pdu_dir,
        "inner_length_overflow.bin",
        &poison_inner_length_overflow(),
    );
    write_seed(&pdu_dir, "truncated_outer_tlv.bin", &poison_truncated_outer_tlv());
    write_seed(
        &pdu_dir,
        "indefinite_length.bin",
        &poison_indefinite_length(),
    );
    write_seed(
        &pdu_dir,
        "integer_overlength.bin",
        &poison_integer_overlength(),
    );
    write_seed(
        &pdu_dir,
        "bit_string_zero_length.bin",
        &poison_bit_string_zero_length(),
    );
    write_seed(
        &pdu_dir,
        "num_entries_mismatch.bin",
        &poison_num_entries_mismatch(&basic),
    );

    println!("\nframe seeds -> {}", frame_dir.display());

    // -- Valid frame seeds --
    write_seed(
        &frame_dir,
        "valid_basic.bin",
        &make_frame(basic.clone(), None),
    );
    write_seed(
        &frame_dir,
        "valid_vlan_priority4.bin",
        &make_frame(
            basic.clone(),
            Some(VlanTag {
                priority: VlanPriority::new(4).unwrap(),
                vlan_id: 100,
            }),
        ),
    );
    write_seed(
        &frame_dir,
        "valid_vlan_priority7.bin",
        &make_frame(
            basic.clone(),
            Some(VlanTag {
                priority: VlanPriority::new(7).unwrap(),
                vlan_id: 4094,
            }),
        ),
    );
    write_seed(
        &frame_dir,
        "valid_mixed_types_vlan.bin",
        &make_frame(
            encode_pdu(&make_pdu_mixed_types()),
            Some(VlanTag {
                priority: VlanPriority::new(4).unwrap(),
                vlan_id: 1,
            }),
        ),
    );
    // -- Malformed frame seeds --
    write_seed(
        &frame_dir,
        "frame_length_overflow.bin",
        &poison_frame_length_overflow(),
    );
    write_seed(
        &frame_dir,
        "frame_too_short.bin",
        &poison_frame_too_short(),
    );
    write_seed(
        &frame_dir,
        "frame_wrong_ether_type.bin",
        &poison_frame_wrong_ether_type(),
    );

    println!("\nseed corpus written");
}
