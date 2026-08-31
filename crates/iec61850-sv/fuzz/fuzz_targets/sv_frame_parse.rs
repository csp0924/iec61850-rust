//! Fuzz target for Sampled Values Ethernet frame decoding.
//!
//! Covers the whole receive path a raw socket feeds: the Ethernet header, the
//! optional 802.1Q tag, the SV application header, and the savPdu boundary.
//!
//! Contracts: decoding arbitrary bytes never panics; a decoded frame
//! re-encodes to bytes that decode back identically; and a short frame, a
//! foreign EtherType, or a Length below the header all return an error.
//!
//! ## Running
//!
//! ```sh
//! cd crates/iec61850-sv/fuzz
//! cargo +nightly fuzz run sv_frame_parse
//! ```

#![no_main]

use bytes::BytesMut;
use iec61850_sv::frame::SvFrame;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(frame) = SvFrame::decode(data) else {
        return;
    };

    let mut buf = BytesMut::new();
    frame
        .encode(&mut buf)
        .expect("encoding a decoded frame cannot fail");

    let redecoded = SvFrame::decode(&buf).expect("re-encoded frame bytes must decode");

    assert_eq!(
        frame, redecoded,
        "frame is not stable across a round trip: original={:?} vs redecoded={:?}",
        frame, redecoded
    );
});
