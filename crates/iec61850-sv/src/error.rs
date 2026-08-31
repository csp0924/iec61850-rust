//! `SvError` — error type for the Sampled Values PDU and frame layers.

use thiserror::Error;

/// Sampled Values encode and decode errors.
///
/// Decoding is strict: a malformed header length, an implausible ASDU count, a
/// field whose length does not match its definition, and a value that reaches
/// past its enclosing ASDU are all rejected instead of skipped, so a subscriber
/// never publishes samples reconstructed from a damaged frame.
#[derive(Debug, Error, PartialEq, Clone)]
pub enum SvError {
    /// Ethernet frame shorter than the 22-byte minimum.
    #[error("sv ethernet frame too short, {0} bytes")]
    EthernetFrameTooShort(usize),

    /// EtherType is not 0x88BA (Sampled Values).
    #[error("wrong ethertype 0x{0:04x}, expected 0x88ba")]
    WrongEtherType(u16),

    /// The SV header Length field is below 8, which would make the APDU length
    /// negative.
    #[error("sv header length field {0} is below the 8 byte header")]
    InvalidHeaderLength(u16),

    /// noASDU exceeds `MAX_ASDU_PER_FRAME`.
    ///
    /// The bound keeps a single frame from steering the decoder into a large
    /// number of ASDU parses.
    #[error("noasdu {0} exceeds the maximum of {max}", max = crate::pdu::MAX_ASDU_PER_FRAME)]
    TooManyAsdus(u8),

    /// BER length error from `iec61850-asn1`.
    #[error("ber length decode error: {0}")]
    Asn1(#[from] iec61850_asn1::Asn1Error),

    /// Input truncated: the slice is shorter than the field requires.
    #[error("truncated input, need {needed} bytes but {available} available")]
    TruncatedInput { needed: usize, available: usize },

    /// The outer PDU tag is not 0x60, the savPdu.
    #[error("outer pdu tag 0x{0:02x} is not the expected 0x60 savpdu")]
    WrongPduTag(u8),

    /// The SEQUENCE OF ASDU tag is not 0xA2.
    #[error("sequence of asdu tag 0x{0:02x} is not the expected 0xa2")]
    WrongAsduSeqTag(u8),

    /// An ASDU does not start with the SEQUENCE tag 0x30.
    #[error("asdu tag 0x{0:02x} is not the expected 0x30 sequence")]
    WrongAsduTag(u8),

    /// A field length differs from its definition, such as a smpCnt that is not
    /// 2 bytes or a confRev that is not 4 bytes.
    #[error("field tag 0x{tag:02x} length is {actual}, expected {expected}")]
    InvalidFieldLength {
        tag: u8,
        expected: usize,
        actual: usize,
    },

    /// A mandatory field is absent: svID, smpCnt, confRev, smpSynch, or the
    /// sample data.
    #[error("missing required field tag 0x{tag:02x} ({name})")]
    MissingRequiredField { tag: u8, name: &'static str },

    /// A string field is not valid UTF-8.
    #[error("svid / datset is not valid utf-8")]
    InvalidUtf8,

    /// The svID exceeds `SV_STRING_MAX_LEN`.
    ///
    /// Truncating an over-long identifier silently would let a subscriber
    /// match a stream on a shortened svID; the ASDU is rejected instead.
    #[error("svid length {0} exceeds the maximum of {max} bytes", max = crate::pdu::SV_STRING_MAX_LEN)]
    SvIdTooLong(usize),

    /// The datSet exceeds `SV_STRING_MAX_LEN`.
    ///
    /// A shortened data set reference would name a different data set; the
    /// ASDU is rejected rather than truncated.
    #[error("datset length {0} exceeds the maximum of {max} bytes", max = crate::pdu::SV_STRING_MAX_LEN)]
    DatSetTooLong(usize),

    /// The encode buffer cannot hold the PDU.
    #[error("pdu buffer overflow")]
    PduOverflow,

    /// The gmIdentity field is not 8 bytes long.
    #[error("gmidentity field length {0} is not 8 bytes")]
    InvalidGmIdentityLength(usize),

    /// VLAN priority greater than 7; the PCP field holds only 3 bits.
    #[error("vlan priority {0} out of range 0-7")]
    VlanPriorityOutOfRange(u8),

    /// An ASDU field reaches past the length its ASDU declared.
    #[error("asdu field tag 0x{tag:02x} ends at {value_end}, past the asdu end {asdu_end}")]
    AsduFieldOutOfBounds {
        tag: u8,
        value_end: usize,
        asdu_end: usize,
    },

    /// `setup_complete` was called with no ASDU configured.
    #[error("sv publisher has no asdu to build a frame from")]
    NoAsdus,

    /// The frame would exceed the 1518-byte Ethernet limit.
    #[error("sv publisher frame size {0} exceeds the 1518 byte limit")]
    FrameTooLarge(usize),

    /// An `AsduHandle` does not refer to a configured ASDU.
    #[error("invalid asduhandle({0}), out of range")]
    InvalidAsduHandle(usize),

    /// The sample data length differs from the size declared by `add_asdu`.
    #[error("sample data length {actual} does not match the expected {expected}")]
    SampleSizeMismatch { expected: usize, actual: usize },

    /// `set_refr_tm` was called on an ASDU without a refrTm field; enable it
    /// with `enable_refr_tm` before `setup_complete`.
    #[error("asdu has no refrtm field, call enable_refr_tm before setup_complete")]
    RefrTmNotEnabled,

    /// `set_gm_identity` was called on an ASDU without a gmIdentity field; set
    /// it before `setup_complete`.
    #[error("asdu has no gmidentity field, call set_gm_identity before setup_complete")]
    GmIdentityNotEnabled,

    /// Platform error surfaced by an `EthernetSink` or `EthernetSource`, such as
    /// a failed raw socket send or receive. It maps no Sampled Values clause.
    #[error("sv platform error: {0}")]
    Other(String),
}
