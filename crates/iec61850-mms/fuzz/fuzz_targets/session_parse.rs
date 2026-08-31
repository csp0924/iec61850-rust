//! Fuzz target for Session SPDU parsing.
//!
//! Feeds arbitrary bytes to `IsoSession::parse_message` and checks that:
//! 1. it never panics, as library code must not;
//! 2. a message below the minimum size takes the error path.
//!
//! Each iteration starts from a fresh `IsoSession`, so state never carries across
//! inputs and the corpus does not have to search for a reachable sequence.
//!
//! ## Corpus
//!
//! `corpus/session_parse/` holds CONNECT, ACCEPT, FINISH, DISCONNECT, ABORT and
//! NOT-FINISHED SPDUs together with boundary cases: a length below 2, an LI that
//! overruns the frame, and an unknown SPDU ID.

#![no_main]

use libfuzzer_sys::fuzz_target;

use iec61850_mms::iso::session::IsoSession;

fuzz_target!(|data: &[u8]| {
    let mut sess = IsoSession::new();
    // Primary contract: no input may make parse_message panic.
    let _ = sess.parse_message(data);
});
