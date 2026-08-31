//! The shared error type for BER length coding.
//!
//! Every variant describes what is wrong with the BER bytes and nothing
//! else: no PDU, IED or IEC 61850 semantics. Layer error types wrap it with
//! `#[from]` and expose it under their own name.

use thiserror::Error;

/// An error raised while decoding a BER length field.
///
/// Produced by `decode_length`; `encode_length` cannot fail.
#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum Asn1Error {
    /// The input ends before the length field is complete: an empty slice in
    /// the short form, or missing bytes after a long-form prefix.
    #[error("truncated BER length field")]
    TruncatedInput,

    /// The long form declares more than two length bytes (`0x83` or above).
    ///
    /// An unbounded length is an attack vector: it invites out-of-bounds
    /// reads and oversized allocations. MMS, GOOSE and SV PDUs stay below
    /// 65535 bytes, where two length bytes suffice; anything larger is
    /// segmented by the COTP/TPKT layer.
    #[error(
        "BER length field too long (first byte 0x{first_byte:02X}, at most 0x82 is supported)"
    )]
    LengthTooLong {
        /// The first length byte, which selects the form and the byte count.
        first_byte: u8,
    },
}
