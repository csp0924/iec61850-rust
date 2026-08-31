//! Robustness regression tests for the ACSE layer.
//!
//! Each test feeds a malformed PDU and asserts that it is rejected with an error,
//! without reading past the buffer and without panicking.

use iec61850_mms::iso::acse::{AcseConnection, AcseError};

// A PDU shorter than a tag plus one length byte

/// An empty buffer must return TooShort, without panicking or reading past the end.
///
/// A tag byte and at least one length byte are required, so a buffer shorter than
/// two bytes is rejected before any field is read.
#[test]
fn empty_buf_too_short() {
    let mut conn = AcseConnection::new(None);
    let result = conn.parse_message(&[]);
    assert!(
        matches!(result, Err(AcseError::TooShort { .. })),
        "an empty buffer must return TooShort"
    );
}

/// A single byte, a tag with no length, must return TooShort.
#[test]
fn one_byte_aarq_too_short() {
    let mut conn = AcseConnection::new(None);
    // only the AARQ tag, with no length byte
    let result = conn.parse_message(&[0x60]);
    assert!(
        matches!(result, Err(AcseError::TooShort { .. })),
        "a single-byte pdu must return TooShort"
    );
}

/// A single RLRQ tag must return TooShort, since even an RLRQ needs a length byte.
#[test]
fn one_byte_rlrq_too_short() {
    let mut conn = AcseConnection::new(None);
    let result = conn.parse_message(&[0x62]);
    assert!(
        matches!(result, Err(AcseError::TooShort { .. })),
        "a single-byte rlrq must return TooShort"
    );
}

// An AARQ whose declared length overruns the buffer

/// The outer AARQ length declares more bytes than the buffer holds.
///
/// The decoder must bound the declared length against what remains rather than
/// trusting it, so the attack shape `len > remaining` is rejected.
#[test]
fn aarq_outer_length_overflow() {
    let mut conn = AcseConnection::new(None);
    // AARQ tag 0x60 with length 0x7f, 127 bytes, but only 5 bytes follow
    let poison: &[u8] = &[
        0x60, 0x7f, // AARQ declaring 127 bytes with only 5 present
        0xa1, 0x07, 0x06, 0x05, 0x28, // a truncated app-context
    ];
    let result = conn.parse_message(poison);
    assert!(
        result.is_err(),
        "an outer aarq length overrun must return an error, got: {:?}",
        result
    );
}

/// An inner AARQ TLV, app-context-name, declares a length past the outer end.
#[test]
fn aarq_inner_length_overflow() {
    let mut conn = AcseConnection::new(None);
    // AARQ tag 0x60 with a valid outer length of 5
    // the inner tag 0xa1 declares 80 bytes while only 3 remain
    let poison: &[u8] = &[
        0x60, 0x05, // AARQ with 5 bytes of content
        0xa1, 0x50, // app-context-name declaring 80 bytes, past the outer end
        0x06, 0x05, 0x28, // truncated, and already past the outer end
    ];
    let result = conn.parse_message(poison);
    assert!(
        result.is_err(),
        "an inner aarq length overrun must return an error, got: {:?}",
        result
    );
}

/// A multi-byte AARQ length, 0x82 hi lo, declares more than the buffer holds.
#[test]
fn aarq_multibyte_length_overflow() {
    let mut conn = AcseConnection::new(None);
    // AARQ tag 0x60 with the multi-byte length 0x82 0xff 0xff, that is 65535 bytes
    let poison: &[u8] = &[
        0x60, 0x82, 0xff, 0xff, // AARQ declaring 65535 bytes
        0xa1, 0x07, 0x06, 0x05, 0x28, 0xca, 0x22, 0x02, 0x03, // only 9 bytes present
    ];
    let result = conn.parse_message(poison);
    assert!(
        result.is_err(),
        "a multi-byte aarq length overrun must return an error, got: {:?}",
        result
    );
}

// An AARE whose declared length overruns the buffer

/// The outer AARE length declares more bytes than the buffer holds.
///
/// The same bound applies as for an AARQ.
#[test]
fn aare_outer_length_overflow() {
    let mut conn = AcseConnection::new(None);
    // AARE tag 0x61 with length 0x7f, 127 bytes, but only 5 bytes follow
    let poison: &[u8] = &[
        0x61, 0x7f, // AARE declaring 127 bytes
        0xa1, 0x07, 0x06, 0x05, 0x28, // truncated
    ];
    let result = conn.parse_message(poison);
    assert!(
        result.is_err(),
        "an outer aare length overrun must return an error, got: {:?}",
        result
    );
}

/// The AARE result field, 0xa2, declares a length past the AARE content.
///
/// The nested result field is bounds checked against the enclosing PDU.
#[test]
fn aare_result_inner_length_overflow() {
    let mut conn = AcseConnection::new(None);
    // a valid AARE outer length of 10, whose inner 0xa2 declares 50 bytes
    let poison: &[u8] = &[
        0x61, 0x0a, // AARE with 10 bytes of content
        0xa1, 0x07, 0x06, 0x05, 0x28, 0xca, 0x22, 0x02,
        0x03, // app-context, 9 bytes, filling the outer content
        0xa2, 0x32, // result declaring 50 bytes, past the outer end
        0x02, 0x01, 0x00,
    ];
    let result = conn.parse_message(poison);
    assert!(
        result.is_err(),
        "an aare result length overrun must return an error, got: {:?}",
        result
    );
}

/// The AARE user-information field, 0xbe, declares a length past the content.
///
/// The nested user-information field is bounds checked as well.
#[test]
fn aare_user_info_length_overflow() {
    let mut conn = AcseConnection::new(None);
    // an AARE of 20 bytes: app-context 9, result 5, then 0xbe declaring 50 with 6 left
    let body: &[u8] = &[
        0xa1, 0x07, 0x06, 0x05, 0x28, 0xca, 0x22, 0x02, 0x03, // app-context, 9 bytes
        0xa2, 0x03, 0x02, 0x01, 0x00, // result 0, 5 bytes
        0xbe, 0x32, // user-information declaring 50 bytes, past the end
        0x28, 0x04, 0x02, 0x01, 0x03, // association-data, 5 bytes, while 0xbe declared 50
    ];
    let mut pdu = vec![0x61u8, body.len() as u8];
    pdu.extend_from_slice(body);
    let result = conn.parse_message(&pdu);
    assert!(
        result.is_err(),
        "an aare user-information length overrun must return an error, got: {:?}",
        result
    );
}

// Fuzz-style sweeps: a malformed PDU must never panic

/// Truncating a well-formed AARQ at every length must never panic.
#[test]
fn no_panic_on_truncated_aarq_vectors() {
    // truncate a minimal AARQ at every possible length
    let full_aarq: &[u8] = &[
        0x60, 0x1f, 0xa1, 0x07, 0x06, 0x05, 0x28, 0xca, 0x22, 0x02, 0x03, 0xbe, 0x14, 0x28, 0x12,
        0x02, 0x01, 0x03, 0xa0, 0x0d, 0xde, 0xad, 0xde, 0xad, 0xde, 0xad, 0xde, 0xad, 0xde, 0xad,
        0xde, 0xad, 0xde,
    ];
    for len in 0..full_aarq.len() {
        let mut conn = AcseConnection::new(None);
        // the only requirement is that it does not panic; Ok and Err are both fine
        let _ = conn.parse_message(&full_aarq[..len]);
    }
}

/// Truncating a well-formed AARE at every length must never panic.
#[test]
fn no_panic_on_truncated_aare_vectors() {
    let full_aare: &[u8] = &[
        0x61, 0x26, 0xa1, 0x07, 0x06, 0x05, 0x28, 0xca, 0x22, 0x02, 0x03, 0xa2, 0x03, 0x02, 0x01,
        0x00, 0xa3, 0x05, 0xa1, 0x03, 0x02, 0x01, 0x00, 0xbe, 0x11, 0x28, 0x0f, 0x02, 0x01, 0x03,
        0xa0, 0x0a, 0xde, 0xad, 0xde, 0xad, 0xde, 0xad, 0xde, 0xad,
    ];
    for len in 0..full_aare.len() {
        let mut conn = AcseConnection::new(None);
        let _ = conn.parse_message(&full_aare[..len]);
    }
}
