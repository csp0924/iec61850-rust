//! Fuzz target for savPdu decoding.
//!
//! Feeds arbitrary bytes to `decode_sav_pdu` and holds it to three contracts:
//!
//! 1. Decoding never panics; returning an error is the expected outcome for
//!    malformed input.
//! 2. Decoding and encoding reach a byte-exact fixed point.
//! 3. The malformed-input classes below return an error rather than reading out
//!    of bounds, overflowing, or looping forever:
//!    - A sample longer than 127 bytes, whose total length must be
//!      encoded as a multi-byte BER length.
//!    - A member length that reaches past the enclosing PDU.
//!    - An indefinite BER length.
//!    - A corrupt BER length field, and a smpMod field of more than one byte.
//!
//! ## Running
//!
//! ```sh
//! cd crates/iec61850-sv/fuzz
//! cargo +nightly fuzz run sv_pdu_parse
//! cargo +nightly fuzz run sv_pdu_parse -- -max_total_time=86400
//! ```
//!
//! ## Seeds
//!
//! `corpus/sv_pdu_parse/` holds valid PDUs alongside the malformed cases above.

#![no_main]

use bytes::BytesMut;
use iec61850_sv::pdu::{decode_sav_pdu, encode_sav_pdu};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(pdu1) = decode_sav_pdu(data) else {
        return;
    };

    // The comparison is over bytes rather than `pdu1 == pdu2`, so that adding
    // an optional field later cannot turn a lossy structural round trip into a
    // false failure. The wire form must still be identical.
    let mut buf1 = BytesMut::new();
    encode_sav_pdu(&pdu1, &mut buf1).expect("encoding a decoded pdu cannot fail");

    let pdu2 = decode_sav_pdu(&buf1).expect("re-encoded pdu bytes must decode");

    let mut buf2 = BytesMut::new();
    encode_sav_pdu(&pdu2, &mut buf2).expect("encoding a decoded pdu cannot fail");

    assert_eq!(
        buf1.as_ref(),
        buf2.as_ref(),
        "pdu wire form does not reach a fixed point: buf1.len={} buf2.len={}",
        buf1.len(),
        buf2.len()
    );
});
