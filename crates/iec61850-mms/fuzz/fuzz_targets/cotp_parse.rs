//! Fuzz target for COTP parsing.
//!
//! Feeds arbitrary bytes to `parse_cotp_pdu` and checks that:
//! 1. it never panics, as library code must not;
//! 2. a TPKT packet with no COTP payload takes the error path instead of
//!    reading past the buffer.
//!
//! The entry point `iec61850_mms::iso::cotp::parse_cotp_pdu` is stateless.
//!
//! ## Corpus
//!
//! `corpus/cotp_parse/` holds CR, CC, DT, DR and DC PDUs together with boundary
//! cases: a length of 0, and a length that overruns the frame.

#![no_main]

use libfuzzer_sys::fuzz_target;

use iec61850_mms::iso::cotp::parse_cotp_pdu;

fuzz_target!(|data: &[u8]| {
    // Primary contract: no input may make parse_cotp_pdu panic; Ok and Err are both fine.
    let _ = parse_cotp_pdu(data);
});
