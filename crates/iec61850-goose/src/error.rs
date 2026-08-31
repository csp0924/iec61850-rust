//! `GooseError` — error type for the GOOSE PDU and frame layers.
//!
//! Covers BER decoding of the IECGoosePdu, the Ethernet/VLAN frame layer, and
//! the strict validation this implementation applies to malformed publications.

use thiserror::Error;

/// GOOSE encode and decode errors.
///
/// Decoding is strict: an out-of-range string length, a missing timestamp, and
/// a `numDatSetEntries` that disagrees with the number of decoded `allData`
/// entries are all reported as errors instead of being repaired silently, so a
/// subscriber never acts on a partially reconstructed data set.
#[derive(Debug, Error, PartialEq, Clone)]
pub enum GooseError {
    /// Unknown Data tag byte.
    #[error("unknown data tag 0x{0:02x}")]
    UnknownTag(u8),

    /// Malformed BER length field, including indefinite length (0x80).
    #[error("malformed ber length field")]
    TagDecode,

    /// A nested structure failed to decode.
    #[error("nested decode error: {0}")]
    SubLevel(Box<GooseError>),

    /// More `allData` elements than `numDatSetEntries` announces.
    #[error("more alldata elements than expected")]
    Overflow,

    /// Fewer `allData` elements than `numDatSetEntries` announces.
    #[error("fewer alldata elements than expected")]
    Underflow,

    /// Decoded element type differs from the expected type at this index.
    #[error("type mismatch at index {0}")]
    TypeMismatch(usize),

    /// Field length out of range, such as an integer longer than 8 bytes or a
    /// UTC time that is not 8 bytes.
    #[error("length mismatch")]
    LengthMismatch,

    /// BIT STRING padding byte greater than 7.
    #[error("invalid bit-string padding {0}")]
    InvalidPadding(u8),

    /// A string field exceeds the 129-byte limit.
    ///
    /// Truncating an over-long field silently would hand the application a
    /// different reference than the publisher sent; the frame is rejected.
    #[error("string field length {0} exceeds the 129 byte limit")]
    FieldTooLong(usize),

    /// The PDU carries no timestamp (`t`) field.
    ///
    /// Substituting zero for a missing timestamp would make an undated
    /// publication indistinguishable from one stamped at the epoch.
    #[error("missing timestamp field t")]
    MissingTimestamp,

    /// `stNum` or `sqNum` decoded as 0, a reserved value meaning uninitialized.
    #[error("stnum / sqnum is 0")]
    InvalidStateNumber,

    /// The timestamp field is not 8 bytes long.
    #[error("timestamp field is not 8 bytes")]
    InvalidTimestamp,

    /// Ethernet frame shorter than 14 bytes, or shorter than 18 bytes when a
    /// VLAN tag is present.
    #[error("ethernet frame too short")]
    EthernetFrameTooShort,

    /// EtherType is not 0x88B8 (GOOSE).
    #[error("wrong ethertype 0x{0:04x}, expected 0x88b8")]
    WrongEtherType(u16),

    /// VLAN priority greater than 7; the PCP field holds only 3 bits.
    #[error("vlan priority {0} out of range 0-7")]
    VlanPriorityOutOfRange(u8),

    /// The encode buffer cannot hold the PDU.
    #[error("pdu buffer overflow")]
    PduOverflow,

    /// `numDatSetEntries` disagrees with the number of `allData` entries.
    ///
    /// Accepting the mismatch would let a publisher and a subscriber disagree
    /// about the data set layout without either side noticing.
    #[error("numdatsetentries ({expected}) does not match alldata length ({actual})")]
    DataSetLengthMismatch { expected: usize, actual: usize },

    /// BER length error from `iec61850-asn1`.
    #[error("ber length decode error: {0}")]
    Asn1(#[from] iec61850_asn1::Asn1Error),

    /// Input truncated: the slice is shorter than the field requires.
    #[error("truncated input, need {needed} bytes but {available} available")]
    TruncatedInput { needed: usize, available: usize },

    /// `confRev` differs from the configured revision.
    ///
    /// The mismatch is reported rather than resolved by discarding the data set
    /// values, so the application decides whether to act on the publication;
    /// the listener is still invoked.
    #[error("confrev mismatch, expected {expected} but got {actual}")]
    ConfRevMismatch { expected: u32, actual: u32 },

    /// The receiver is running and its subscriber list cannot be modified.
    ///
    /// The list is shared with the receive thread, so mutation is refused at
    /// run time rather than left to a documentation warning.
    #[error("goose receiver is running, subscriber list is locked")]
    ReceiverRunning,

    /// The timestamp field (tag 0x84) has an element length other than 8.
    #[error("timestamp tag 0x84 field length {0} is not 8 bytes")]
    TimestampBadLength(usize),
}
