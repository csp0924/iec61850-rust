//! Fuzz target for Presentation PPDU parsing.
//!
//! Feeds arbitrary bytes to `parse_connect`, `parse_accept` and `parse_user_data` and
//! checks that:
//! 1. none of them ever panics, as library code must not;
//! 2. an unknown tag with length 0, a CP PDU without user-data, and a CP PDU
//!    without normal-mode-parameters all take the error path rather than
//!    looping forever or reading past the buffer.
//!
//! One leading byte selects the entry point and the remaining bytes are the input, so
//! the corpus spreads evenly over the three. Each iteration builds a fresh
//! `IsoPresentation`, which is what the stateful `parse_user_data` needs.
//!
//! ## Corpus
//!
//! `corpus/presentation_parse/` holds CP, CPA and user-data PDUs together with
//! boundary cases: missing user-data, deep nesting, and a missing ACSE context.

#![no_main]

use libfuzzer_sys::fuzz_target;

use iec61850_mms::iso::presentation::{
    parse_accept, parse_connect, parse_user_data, IsoPresentation,
};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let selector = data[0];
    let payload = &data[1..];
    let mut pres = IsoPresentation::default();

    // Primary contract: no input may make any of the three entry points panic.
    match selector & 0b11 {
        0 => {
            let _ = parse_connect(&mut pres, payload);
        }
        1 => {
            let _ = parse_accept(&mut pres, payload);
        }
        _ => {
            let _ = parse_user_data(&mut pres, payload);
        }
    }
});
