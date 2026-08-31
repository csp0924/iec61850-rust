//! Shared BER codec core for the MMS, GOOSE and Sampled Values layers.
//!
//! Holds only what all three layers use with identical semantics:
//! definite-length encoding and decoding per ISO/IEC 8825-1 §8.1.3 (short
//! form, plus a long form of at most two length bytes), the recursion-depth
//! guards for nested MMS `Data` structures, and [`Asn1Error`], which each
//! layer converts into its own error type. PDU-level tag dispatch stays in
//! the layer that owns the PDU.
//!
//! Guarantees a caller relies on: the indefinite length form `0x80` is
//! rejected rather than scanned for an end-of-contents marker; decoding depth
//! is capped by the smaller of the local and the negotiated limit; and
//! `decode_length` returns a `Result`, so a malformed length field cannot be
//! ignored.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod depth;
mod error;
mod length;

pub use depth::{effective_nesting_cap, MAX_DATA_NESTING_DEPTH};
pub use error::Asn1Error;
pub use length::{decode_length, encode_length};
