//! Fuzz target for GOOSE Ethernet frame decoding.
//!
//! Covers the frame-level attack surface that `GooseReceiver::handle_message`
//! sees from a raw socket: the Ethernet header, the optional 802.1Q tag, the
//! EtherType, the APPID, Length and reserved fields, and a Length field that
//! disagrees with the bytes actually present.
//!
//! ## Running
//!
//! ```sh
//! cd crates/iec61850-goose/fuzz
//! cargo +nightly fuzz run goose_frame_parse
//! ```

#![no_main]

use bytes::BytesMut;
use iec61850_goose::{GooseFrame, GoosePdu};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Primary contract: decoding arbitrary bytes never panics.
    let Ok(frame) = GooseFrame::decode(data) else {
        return;
    };

    // Secondary contract: re-encoding a decoded frame reproduces it.
    let mut buf = BytesMut::new();
    frame
        .encode(&mut buf)
        .expect("encoding a decoded frame cannot fail");
    let redecoded = GooseFrame::decode(&buf).expect("re-encoded frame bytes must decode");
    assert_eq!(
        frame.header, redecoded.header,
        "frame header is not stable across a round trip: {:?} vs {:?}",
        frame.header, redecoded.header
    );
    assert_eq!(
        frame.pdu_bytes, redecoded.pdu_bytes,
        "frame pdu bytes are not stable across a round trip"
    );

    // The payload also runs the receive path's decode and encode chain, checked
    // at the wire level for the reason described in `goose_pdu_parse`.
    if let Ok(pdu1) = GoosePdu::decode_ber(&frame.pdu_bytes) {
        let mut pdu_buf1 = BytesMut::new();
        pdu1.encode_ber(&mut pdu_buf1)
            .expect("encoding a decoded pdu cannot fail");
        let pdu2 = GoosePdu::decode_ber(&pdu_buf1).expect("re-encoded pdu bytes must decode");
        let mut pdu_buf2 = BytesMut::new();
        pdu2.encode_ber(&mut pdu_buf2)
            .expect("encoding a decoded pdu cannot fail");
        assert_eq!(
            pdu_buf1.as_ref(),
            pdu_buf2.as_ref(),
            "pdu wire form does not reach a fixed point"
        );
    }
});
