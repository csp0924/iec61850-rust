//! Fuzz target for GOOSE PDU decoding.
//!
//! Feeds arbitrary bytes to `GoosePdu::decode_ber` and holds it to three
//! contracts:
//!
//! 1. Decoding never panics; returning an error is the expected outcome for
//!    malformed input.
//! 2. Decoding and encoding reach a byte-exact fixed point, so no input has two
//!    canonical wire forms.
//! 3. Malformed input returns an error rather than reading out of bounds,
//!    overflowing, or looping forever.
//!
//! ## Running
//!
//! ```sh
//! cd crates/iec61850-goose/fuzz
//! cargo +nightly fuzz run goose_pdu_parse
//! cargo +nightly fuzz run goose_pdu_parse -- -max_total_time=86400
//! ```
//!
//! ## Seeds
//!
//! `corpus/goose_pdu_parse/` holds valid PDUs alongside hand-built malformed
//! ones: a member length that exceeds the buffer, an INTEGER or UNSIGNED
//! element wider than 8 bytes, a BIT STRING with no padding byte, and an
//! indefinite BER length.

#![no_main]

use bytes::BytesMut;
use iec61850_goose::GoosePdu;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Primary contract: decoding arbitrary bytes never panics.
    let Ok(pdu1) = GoosePdu::decode_ber(data) else {
        return;
    };

    // Secondary contract: the wire form reaches a fixed point after the second
    // encode.
    //
    // The comparison is deliberately over bytes rather than `pdu1 == pdu2`:
    // `go_id: Option<String>` is lossy by design, because `None` is encoded as
    // gocbRef and decodes back as `Some(gocb_ref)`. That happens exactly once;
    // everything already on the wire is canonical, so the second encode must
    // reproduce the first byte for byte.
    //
    // Any drift would mean the encoder is not deterministic, that decode and
    // encode fail to normalize arbitrary input, or that one PDU has two valid
    // wire representations.
    let mut buf1 = BytesMut::new();
    pdu1.encode_ber(&mut buf1)
        .expect("encoding a decoded pdu cannot fail");

    let pdu2 = GoosePdu::decode_ber(&buf1).expect("re-encoded pdu bytes must decode");

    let mut buf2 = BytesMut::new();
    pdu2.encode_ber(&mut buf2)
        .expect("encoding a decoded pdu cannot fail");

    assert_eq!(
        buf1.as_ref(),
        buf2.as_ref(),
        "pdu wire form does not reach a fixed point: buf1.len={} buf2.len={} pdu1={:?} pdu2={:?}",
        buf1.len(),
        buf2.len(),
        pdu1,
        pdu2
    );
});
