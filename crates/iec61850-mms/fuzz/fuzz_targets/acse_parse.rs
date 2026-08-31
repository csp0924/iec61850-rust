//! Fuzz target for ACSE parsing.
//!
//! Feeds arbitrary bytes to `AcseConnection::parse_message` and checks that:
//! 1. it never panics, as library code must not;
//! 2. the too-short and length-overrun guards always take the error path
//!    instead of slicing past the end of the buffer.
//!
//! Parsing is fuzzed one way, without an encode round trip: an AARQ or AARE carries
//! many optional TLVs and `parse_message` keeps only the user-data slice, so the
//! original bytes cannot be reconstructed from what it returns.
//!
//! ## Running
//!
//! ```sh
//! cd crates/iec61850-mms/fuzz
//! cargo +nightly fuzz run acse_parse
//! # long run, 24 hours
//! cargo +nightly fuzz run acse_parse -- -max_total_time=86400
//! ```
//!
//! ## Corpus
//!
//! `corpus/acse_parse/` holds well-formed AARQ, AARE, RLRQ, RLRE and ABRT PDUs as
//! seeds. The malformed vectors in `tests/acse_robustness.rs` belong there as well.

#![no_main]

use libfuzzer_sys::fuzz_target;

use iec61850_mms::AcseConnection;

fuzz_target!(|data: &[u8]| {
    let mut conn = AcseConnection::new(None);

    // Primary contract: no input may make parse_message panic; Ok and Err are both fine.
    match conn.parse_message(data) {
        Ok((_indication, user_data)) => {
            // user_data is a subslice of the input, which the borrow checker already
            // guarantees. The length check keeps that true if the code is ever
            // refactored to return an owned copy.
            assert!(
                user_data.len() <= data.len(),
                "user_data slice ({} bytes) is larger than the input ({} bytes)",
                user_data.len(),
                data.len()
            );
        }
        Err(_) => {
            // Rejection is a valid outcome; only a panic would be a failure.
        }
    }
});
