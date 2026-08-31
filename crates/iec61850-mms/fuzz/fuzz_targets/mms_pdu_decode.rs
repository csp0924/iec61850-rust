//! Fuzz target for MMS PDU decoding.
//!
//! Feeds arbitrary bytes to `MmsPdu::decode` and checks that:
//! 1. it never panics, as library code must not;
//! 2. once a PDU decodes, encoding it and decoding the result again yields the same
//!    value, so a mutated input cannot expose a canonical-form ambiguity.
//!
//! ## Running
//!
//! ```sh
//! cd crates/iec61850-mms/fuzz
//! cargo +nightly fuzz run mms_pdu_decode
//! # long run, 24 hours
//! cargo +nightly fuzz run mms_pdu_decode -- -max_total_time=86400
//! ```
//!
//! ## Corpus
//!
//! `corpus/mms_pdu_decode/` holds well-formed PDUs as seeds, such as conclude, reject
//! and initiate, from which the fuzzer mutates boundary cases.

#![no_main]

use libfuzzer_sys::fuzz_target;

use bytes::BytesMut;
use iec61850_mms::MmsPdu;

fuzz_target!(|data: &[u8]| {
    // Primary contract: no input may make decode panic; returning an error is fine.
    let Ok(pdu) = MmsPdu::decode(data) else {
        return;
    };

    // Secondary contract: encoding a decoded PDU and decoding it again reproduces it.
    // This catches an encoder that omits a tag or length for some variant, and a
    // decoder that is not deterministic for the same bytes.
    let mut buf = BytesMut::new();
    pdu.encode(&mut buf);

    let redecoded = MmsPdu::decode(&buf).expect("encoded bytes must decode again");

    assert_eq!(
        pdu, redecoded,
        "MmsPdu round trip is not idempotent: original={:?} vs redecoded={:?}",
        pdu, redecoded
    );
});
