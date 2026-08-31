//! Error types of the MMS PDU layer.
//!
//! Covers PDU parsing, association negotiation and service invocation. `IsoError`,
//! defined in `crate::error`, covers the layers below; `MmsError` sits above them.

use crate::compat::prelude::*;
use iec61850_asn1::Asn1Error;
use thiserror::Error;

/// Errors raised while encoding or decoding MMS PDUs.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MmsError {
    /// A BER tag differs from the expected one.
    #[error("ber tag mismatch: expected=0x{expected:02X}, actual=0x{actual:02X}")]
    InvalidTag {
        /// Tag the decoder expected.
        expected: u8,
        /// Tag actually present.
        actual: u8,
    },

    /// The BER length field is malformed, for instance a long form that overruns the
    /// remaining buffer.
    #[error("malformed ber length field")]
    InvalidLength,

    /// The PDU ends before a field it declares.
    #[error("mms pdu is truncated")]
    TruncatedPdu,

    /// The parameterCBB BIT STRING is not 3 bytes, padding byte included.
    ///
    /// Rejected rather than ignored, so a peer with a different capability encoding
    /// is reported instead of silently mis-parsed.
    #[error("invalid parametercbb bit string length (expected 3, got {actual})")]
    InvalidParameterCbbLength {
        /// Length received; it must be 3.
        actual: usize,
    },

    /// dataStructureNestingLevel exceeds the ceiling this implementation accepts.
    ///
    /// The ceiling bounds recursion depth during decoding.
    #[error("datastructurenestinglevel {got} exceeds the limit of {max}")]
    NestingLevelExceeded {
        /// Ceiling in force.
        max: u8,
        /// Depth or level that exceeded it.
        got: u8,
    },

    /// The outermost MmsPdu tag is not one of the defined alternatives.
    #[error("unknown mms pdu tag 0x{0:02X}")]
    UnknownMmsPduTag(u8),

    /// A VisibleString or UTF-8 string field is not valid UTF-8.
    #[error("invalid utf-8 in a string field")]
    InvalidUtf8,

    /// The servicesSupported BIT STRING is not 12 bytes, 11 of data plus one of padding.
    #[error("invalid servicessupportedcalling bit string length (expected 12, got {actual})")]
    InvalidServicesSupportedLength {
        /// Length received; it must be 12.
        actual: usize,
    },

    /// An ObjectName identifier exceeds the 64-byte maximum.
    ///
    /// An oversized identifier is rejected rather than silently truncated.
    #[error("objectname identifier length {actual} exceeds the limit of 64 bytes")]
    IdentifierTooLong {
        /// Identifier length received.
        actual: usize,
    },

    /// The ObjectName tag is none of 0x80, 0xa1 or 0x82.
    #[error("unknown objectname tag 0x{0:02X}")]
    UnknownObjectNameTag(u8),

    /// The VariableAccessSpecification tag is neither 0xa0 nor 0xa1.
    #[error("unknown variableaccessspecification tag 0x{0:02X}")]
    UnknownVasTag(u8),

    /// The Data CHOICE tag is not one of the defined alternatives.
    #[error("unknown mmsdata tag 0x{0:02X}")]
    UnknownDataTag(u8),

    /// The DataAccessError code is above 11.
    #[error("unknown dataaccesserror code {0}")]
    UnknownDataAccessError(u8),

    /// A UtcTime value is not exactly 8 bytes.
    ///
    /// A different length is rejected rather than reinterpreted.
    #[error("invalid utctime length {actual}, expected 8")]
    InvalidUtcTimeLength {
        /// Length received; it must be 8.
        actual: usize,
    },

    /// A FloatingPoint value is neither 5 bytes, float32, nor 9 bytes, float64.
    ///
    /// A different length is rejected rather than reinterpreted.
    #[error("invalid floatingpoint length {actual}, expected 5 or 9")]
    InvalidFloatSize {
        /// Length received; it must be 5 or 9.
        actual: usize,
    },

    /// The WriteOutcome tag is neither 0x80 nor 0x81.
    #[error("unknown writeoutcome tag 0x{0:02X}")]
    UnknownWriteOutcomeTag(u8),

    /// A WriteRequest names a different number of variables than it carries values.
    #[error("write item count mismatch: expected={expected}, actual={actual}")]
    WriteCountMismatch {
        /// Number of variables named.
        expected: usize,
        /// Number of values supplied.
        actual: usize,
    },

    /// A WriteRequest carries more than the 100 items accepted.
    #[error("write item count {count} exceeds the limit of 100")]
    TooManyWriteItems {
        /// Number of items requested.
        count: usize,
    },

    /// The PDU is malformed and must be answered with an invalid-PDU reject.
    ///
    /// Raised for parse-level rejections such as an objectClass inner tag other than
    /// 0x80, a continueAfter of 130 bytes or more, or a domainName longer than 64
    /// bytes.
    #[error("malformed mms pdu")]
    InvalidPdu,

    /// The GetNameList objectClass value is not one of 0, 2, 8 or 9.
    ///
    /// The value is rejected while decoding, leaving the service layer to choose the
    /// response rather than parsing on with an unusable class.
    #[error("unsupported objectclass value {0}")]
    UnsupportedObjectClass(u32),

    /// The TypeSpecification CHOICE tag is unknown or unsupported.
    ///
    /// Decoding stops rather than returning a partially initialized value. This
    /// covers typeName `[0xa0]`, generalizedtime `[0x8b]`, bcd `[0x8d]` and objId `[0x8f]`.
    #[error("unknown or unsupported typespecification tag 0x{0:02X}")]
    UnknownTypeSpecTag(u8),

    /// A reject of confirmedRequest with unrecognizedService, type 1 reason 1.
    #[error("mms reject: unrecognized service")]
    RejectUnrecognizedService,

    /// A reject of confirmedRequest with invalidArgument, type 1 reason 4.
    #[error("mms reject: request invalid argument")]
    RejectRequestInvalidArgument,

    /// A reject of pduError with unknownPduType, type 5 reason 0.
    #[error("mms reject: unknown pdu type")]
    RejectUnknownPduType,

    /// A reject of pduError with invalidPdu, type 5 reason 1.
    #[error("mms reject: invalid pdu")]
    RejectInvalidPdu,

    /// Any reject whose type and reason are not one of the four mapped above.
    ///
    /// The type and reason are not carried in this variant.
    #[error("mms reject: other")]
    RejectOther,

    /// An InformationReport or variableAccessSpecification failed to decode.
    /// Covers a wrong tag, a length overrun, and bytes left over after the flat value
    /// sequence. A dedicated variant is used rather than `InvalidTag` or
    /// `TruncatedPdu` because the decoder walks a CHOICE through several `0xa0`
    /// layers, and a bare tag or length message cannot say which layer failed.
    #[error("informationreport decode failed: {0}")]
    InformationReportDecode(String),

    /// A DefineNamedVariableList request is missing a required field.
    /// The payload names the missing field or carries a fixed diagnostic string.
    #[error("definenamedvariablelist is missing a field: {0}")]
    DefineNamedVariableListMissingField(&'static str),

    /// A DefineNamedVariableList request carries more than the 100 entries accepted.
    #[error("definenamedvariablelist entry count {count} exceeds the limit of 100")]
    TooManyDefineEntries {
        /// Number of entries requested.
        count: usize,
    },

    // AlternateAccess
    /// The requested `AlternateAccess` form is not supported.
    ///
    /// Supported forms are `selectAccess.index` and
    /// `selectAlternateAccess { index, nested component }`. Other branches
    /// (component-only, `indexRange`, `allElements`, `named`, multi-member)
    /// surface this error instead of silently producing an undefined PDU.
    #[error("alternateaccess form is not supported: {0}")]
    AlternateAccessUnsupported(&'static str),
}

impl MmsError {
    /// Builds an [`MmsError::InformationReportDecode`] from a message.
    ///
    /// The shorter name keeps the call sites in the InformationReport decoder
    /// readable while the public variant stays unchanged.
    pub fn decode<S: Into<String>>(msg: S) -> Self {
        Self::InformationReportDecode(msg.into())
    }
}

/// Converts an `Asn1Error` into an `MmsError` so `?` works over the shared BER helpers.
///
/// - `TruncatedInput` -> `TruncatedPdu`
/// - `LengthTooLong { .. }` -> `InvalidLength`
impl From<Asn1Error> for MmsError {
    fn from(err: Asn1Error) -> Self {
        match err {
            Asn1Error::TruncatedInput => MmsError::TruncatedPdu,
            Asn1Error::LengthTooLong { .. } => MmsError::InvalidLength,
        }
    }
}
