//! RejectPDU encoding and decoding, per ISO 9506-2.
//!
//! ## Wire format
//!
//! ```text
//! 0xa4 <total_len>               -- [4] IMPLICIT SEQUENCE, constructed
//!   [0x80 <invokeId_len> <...>]  -- originalInvokeID [0] OPTIONAL
//!   0x8<N> 0x01 <reason>         -- rejectReason, where N is the rejectType 1..11
//! ```
//!
//! ## Encoding and decoding rules
//!
//! - The encoder always writes a one-byte rejectReason.
//! - The decoder tolerates a multi-byte BER INTEGER; a value outside the defined
//!   range is clamped to `other(0)` and logged.
//! - The NULL-bodied tags 0x86, 0x87 and 0x88 carry no INTEGER, so the decoder
//!   returns `CancelRequest`, `CancelResponse` or `CancelError` without decoding one.
//!   Peers emit these with an empty body, and rejecting them would break the exchange.
//! - An unknown rejectReason sub-value is clamped to `Other(0)`, so a round trip
//!   does not preserve the original value.
//! - A PDU carrying no rejectReason tag in the range 0x81 to 0x8b returns
//!   `MmsError::InvalidPdu` rather than an unspecified reason.

use super::super::error::MmsError;
use super::initiate::{decode_length, encode_length};
use bytes::BytesMut;

// Public types

/// An MMS RejectPDU, per ISO 9506-2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectPdu {
    /// originalInvokeID `[0]` OPTIONAL, encoded as `0x80 <len> <big-endian u32>`.
    pub invoke_id: Option<u32>,
    /// The rejectReason CHOICE, tags 0x81 to 0x8b.
    pub reason: RejectReason,
}

/// The rejectReason CHOICE, whose alternatives are numbered 1 to 11.
///
/// The Cancel alternatives carry no value; every other one carries a sub-enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// rejectType 1, tag 0x81.
    ConfirmedRequest(ConfirmedRequestRejectReason),
    /// rejectType 2, tag 0x82.
    ConfirmedResponse(ConfirmedResponseRejectReason),
    /// rejectType 3, tag 0x83.
    ConfirmedError(ConfirmedErrorRejectReason),
    /// rejectType 4, tag 0x84.
    UnconfirmedPdu(UnconfirmedPduRejectReason),
    /// rejectType 5, tag 0x85.
    PduError(PduErrorRejectReason),
    /// rejectType 6, tag 0x86, with a NULL body.
    CancelRequest,
    /// rejectType 7, tag 0x87, with a NULL body.
    CancelResponse,
    /// rejectType 8, tag 0x88, with a NULL body.
    CancelError,
    /// rejectType 9, tag 0x89.
    ConcludeRequest(ConcludeRequestRejectReason),
    /// rejectType 10, tag 0x8a.
    ConcludeResponse(ConcludeResponseRejectReason),
    /// rejectType 11, tag 0x8b.
    ConcludeError(ConcludeErrorRejectReason),
}

// ConfirmedRequest, rejectType 1

/// rejectReason values for confirmedRequest, 0 to 9, where 7 is not defined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmedRequestRejectReason {
    /// No more specific reason applies.
    Other = 0,
    /// The service named in the request is not recognized.
    UnrecognizedService = 1,
    /// A modifier in the request is not recognized.
    UnrecognizedModifier = 2,
    /// The invokeID is invalid, for instance because it is already in use.
    InvalidInvokeId = 3,
    /// A service argument is invalid.
    InvalidArgument = 4,
    /// A modifier is invalid.
    InvalidModifier = 5,
    /// The peer has more requests outstanding than were negotiated.
    MaxServOutstandingExceeded = 6,
    /// Value 7 is not defined by the standard, so numbering resumes at 8.
    MaxRecursionExceeded = 8,
    /// An argument value lies outside its permitted range.
    ValueOutOfRange = 9,
}

impl ConfirmedRequestRejectReason {
    fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Other,
            1 => Self::UnrecognizedService,
            2 => Self::UnrecognizedModifier,
            3 => Self::InvalidInvokeId,
            4 => Self::InvalidArgument,
            5 => Self::InvalidModifier,
            6 => Self::MaxServOutstandingExceeded,
            8 => Self::MaxRecursionExceeded,
            9 => Self::ValueOutOfRange,
            other => {
                tracing::warn!(
                    "confirmedrequest reject reason {} is outside the defined range, using other(0)",
                    other
                );
                Self::Other
            }
        }
    }

    fn as_u8(&self) -> u8 {
        match self {
            Self::Other => 0,
            Self::UnrecognizedService => 1,
            Self::UnrecognizedModifier => 2,
            Self::InvalidInvokeId => 3,
            Self::InvalidArgument => 4,
            Self::InvalidModifier => 5,
            Self::MaxServOutstandingExceeded => 6,
            Self::MaxRecursionExceeded => 8,
            Self::ValueOutOfRange => 9,
        }
    }
}

// ConfirmedResponse, rejectType 2

/// rejectReason values for confirmedResponse, 0 to 6, where 4 is not defined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmedResponseRejectReason {
    /// No more specific reason applies.
    Other = 0,
    /// The service named in the response is not recognized.
    UnrecognizedService = 1,
    /// The invokeID does not match an outstanding request.
    InvalidInvokeId = 2,
    /// The result field is invalid.
    InvalidResult = 3,
    /// Value 4 is not defined by the standard.
    MaxRecursionExceeded = 5,
    /// A result value lies outside its permitted range.
    ValueOutOfRange = 6,
}

impl ConfirmedResponseRejectReason {
    fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Other,
            1 => Self::UnrecognizedService,
            2 => Self::InvalidInvokeId,
            3 => Self::InvalidResult,
            5 => Self::MaxRecursionExceeded,
            6 => Self::ValueOutOfRange,
            other => {
                tracing::warn!(
                    "confirmedresponse reject reason {} is outside the defined range, using other(0)",
                    other
                );
                Self::Other
            }
        }
    }

    fn as_u8(&self) -> u8 {
        match self {
            Self::Other => 0,
            Self::UnrecognizedService => 1,
            Self::InvalidInvokeId => 2,
            Self::InvalidResult => 3,
            Self::MaxRecursionExceeded => 5,
            Self::ValueOutOfRange => 6,
        }
    }
}

// ConfirmedError, rejectType 3

/// rejectReason values for confirmedError, 0 to 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmedErrorRejectReason {
    /// No more specific reason applies.
    Other = 0,
    /// The service named in the error is not recognized.
    UnrecognizedService = 1,
    /// The invokeID does not match an outstanding request.
    InvalidInvokeId = 2,
    /// The serviceError field is invalid.
    InvalidServiceError = 3,
    /// A value in the error lies outside its permitted range.
    ValueOutOfRange = 4,
}

impl ConfirmedErrorRejectReason {
    fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Other,
            1 => Self::UnrecognizedService,
            2 => Self::InvalidInvokeId,
            3 => Self::InvalidServiceError,
            4 => Self::ValueOutOfRange,
            other => {
                tracing::warn!(
                    "confirmederror reject reason {} is outside the defined range, using other(0)",
                    other
                );
                Self::Other
            }
        }
    }

    fn as_u8(&self) -> u8 {
        match self {
            Self::Other => 0,
            Self::UnrecognizedService => 1,
            Self::InvalidInvokeId => 2,
            Self::InvalidServiceError => 3,
            Self::ValueOutOfRange => 4,
        }
    }
}

// UnconfirmedPdu, rejectType 4

/// rejectReason values for unconfirmedPDU, 0 to 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnconfirmedPduRejectReason {
    /// No more specific reason applies.
    Other = 0,
    /// The service named in the unconfirmed PDU is not recognized.
    UnrecognizedService = 1,
    /// A service argument is invalid.
    InvalidArgument = 2,
    /// The PDU nests more deeply than the negotiated limit allows.
    MaxRecursionExceeded = 3,
    /// An argument value lies outside its permitted range.
    ValueOutOfRange = 4,
}

impl UnconfirmedPduRejectReason {
    fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Other,
            1 => Self::UnrecognizedService,
            2 => Self::InvalidArgument,
            3 => Self::MaxRecursionExceeded,
            4 => Self::ValueOutOfRange,
            other => {
                tracing::warn!(
                    "unconfirmedpdu reject reason {} is outside the defined range, using other(0)",
                    other
                );
                Self::Other
            }
        }
    }

    fn as_u8(&self) -> u8 {
        match self {
            Self::Other => 0,
            Self::UnrecognizedService => 1,
            Self::InvalidArgument => 2,
            Self::MaxRecursionExceeded => 3,
            Self::ValueOutOfRange => 4,
        }
    }
}

// PduError, rejectType 5

/// rejectReason values for pduError, 0 to 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PduErrorRejectReason {
    /// The outermost PDU tag is not recognized.
    UnknownPduType = 0,
    /// The PDU is malformed.
    InvalidPdu = 1,
    /// The PDU is not legal for the ACSE mapping in use.
    IllegalAcseMapping = 2,
}

impl PduErrorRejectReason {
    fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::UnknownPduType,
            1 => Self::InvalidPdu,
            2 => Self::IllegalAcseMapping,
            other => {
                tracing::warn!(
                    "pduerror reject reason {} is outside the defined range, using unknownpdutype(0)",
                    other
                );
                Self::UnknownPduType
            }
        }
    }

    fn as_u8(&self) -> u8 {
        match self {
            Self::UnknownPduType => 0,
            Self::InvalidPdu => 1,
            Self::IllegalAcseMapping => 2,
        }
    }
}

// ConcludeRequest, rejectType 9

/// rejectReason values for concludeRequestPDU, 0 to 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConcludeRequestRejectReason {
    /// No more specific reason applies.
    Other = 0,
    /// The conclude request carries an invalid argument.
    InvalidArgument = 1,
}

impl ConcludeRequestRejectReason {
    fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Other,
            1 => Self::InvalidArgument,
            other => {
                tracing::warn!(
                    "concluderequest reject reason {} is outside the defined range, using other(0)",
                    other
                );
                Self::Other
            }
        }
    }

    fn as_u8(&self) -> u8 {
        match self {
            Self::Other => 0,
            Self::InvalidArgument => 1,
        }
    }
}

// ConcludeResponse, rejectType 10

/// rejectReason values for concludeResponsePDU, 0 to 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConcludeResponseRejectReason {
    /// No more specific reason applies.
    Other = 0,
    /// The conclude response carries an invalid result.
    InvalidResult = 1,
}

impl ConcludeResponseRejectReason {
    fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Other,
            1 => Self::InvalidResult,
            other => {
                tracing::warn!(
                    "concluderesponse reject reason {} is outside the defined range, using other(0)",
                    other
                );
                Self::Other
            }
        }
    }

    fn as_u8(&self) -> u8 {
        match self {
            Self::Other => 0,
            Self::InvalidResult => 1,
        }
    }
}

// ConcludeError, rejectType 11

/// rejectReason values for concludeErrorPDU, 0 to 2.
///
/// Tag `0x8b` inside a Reject PDU means concludeErrorPDU, rejectType 11, while the
/// same tag at the top level of an MmsPdu means ConcludeRequest, `[11]` primitive
/// NULL. The two live in different contexts: the decoder identifies a Reject by its
/// outer `0xa4` before reading any inner tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConcludeErrorRejectReason {
    /// No more specific reason applies.
    Other = 0,
    /// The conclude error carries an invalid serviceError.
    InvalidServiceError = 1,
    /// A value in the conclude error lies outside its permitted range.
    ValueOutOfRange = 2,
}

impl ConcludeErrorRejectReason {
    fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Other,
            1 => Self::InvalidServiceError,
            2 => Self::ValueOutOfRange,
            other => {
                tracing::warn!(
                    "concludeerror reject reason {} is outside the defined range, using other(0)",
                    other
                );
                Self::Other
            }
        }
    }

    fn as_u8(&self) -> u8 {
        match self {
            Self::Other => 0,
            Self::InvalidServiceError => 1,
            Self::ValueOutOfRange => 2,
        }
    }
}

// RejectReason helpers

impl RejectReason {
    /// Returns the rejectType, 1 to 11, which the wire tag encodes as `0x80 + N`.
    pub fn reject_type(&self) -> u8 {
        match self {
            Self::ConfirmedRequest(_) => 1,
            Self::ConfirmedResponse(_) => 2,
            Self::ConfirmedError(_) => 3,
            Self::UnconfirmedPdu(_) => 4,
            Self::PduError(_) => 5,
            Self::CancelRequest => 6,
            Self::CancelResponse => 7,
            Self::CancelError => 8,
            Self::ConcludeRequest(_) => 9,
            Self::ConcludeResponse(_) => 10,
            Self::ConcludeError(_) => 11,
        }
    }

    /// Returns the rejectReason value to encode; the NULL-bodied variants return 0.
    fn reason_value(&self) -> u8 {
        match self {
            Self::ConfirmedRequest(r) => r.as_u8(),
            Self::ConfirmedResponse(r) => r.as_u8(),
            Self::ConfirmedError(r) => r.as_u8(),
            Self::UnconfirmedPdu(r) => r.as_u8(),
            Self::PduError(r) => r.as_u8(),
            Self::CancelRequest | Self::CancelResponse | Self::CancelError => 0,
            Self::ConcludeRequest(r) => r.as_u8(),
            Self::ConcludeResponse(r) => r.as_u8(),
            Self::ConcludeError(r) => r.as_u8(),
        }
    }

    /// Returns whether the variant has a NULL body, so it carries only a tag and a
    /// length of 0.
    fn is_null_type(&self) -> bool {
        matches!(
            self,
            Self::CancelRequest | Self::CancelResponse | Self::CancelError
        )
    }
}

// RejectPdu encode / decode

impl RejectPdu {
    /// Encodes the RejectPdu into `buf`, outer `0xa4 <len>` included.
    ///
    /// The rejectReason is always one byte; a NULL-bodied variant encodes as
    /// `0x8<N> 0x00` with an empty body.
    pub fn encode(&self, buf: &mut BytesMut) {
        // content length
        let invoke_id_len: usize = if let Some(id) = self.invoke_id {
            // tag and length plus the big-endian value, at most 5 bytes
            let v_len = uint32_encoded_size(id) as usize;
            2 + v_len
        } else {
            0
        };

        let reason_payload_len: usize = if self.reason.is_null_type() {
            // 0x8<N> 0x00
            2
        } else {
            // 0x8<N> 0x01 <reason>
            3
        };

        let inner_len = invoke_id_len + reason_payload_len;

        // outer tag and length
        buf.extend_from_slice(&[0xa4]);
        encode_length(inner_len, buf);

        // optional invokeID
        if let Some(id) = self.invoke_id {
            let v_len = uint32_encoded_size(id) as usize;
            buf.extend_from_slice(&[0x80]);
            encode_length(v_len, buf);
            encode_uint32(id, buf);
        }

        // rejectReason
        let wire_tag = 0x80u8 + self.reason.reject_type();
        if self.reason.is_null_type() {
            buf.extend_from_slice(&[wire_tag, 0x00]);
        } else {
            buf.extend_from_slice(&[wire_tag, 0x01, self.reason.reason_value()]);
        }
    }

    /// Decodes a RejectPdu; `data` starts at the `0xa4` tag byte.
    ///
    /// A PDU carrying no rejectReason tag in the range 0x81 to 0x8b returns
    /// `MmsError::InvalidPdu` rather than an unspecified reason.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }

        // outer tag
        let tag = *data.first().ok_or(MmsError::TruncatedPdu)?;
        if tag != 0xa4 {
            tracing::warn!("reject pdu outer tag 0x{:02X} is not 0xa4, rejecting", tag);
            return Err(MmsError::InvalidTag {
                expected: 0xa4,
                actual: tag,
            });
        }

        // outer length
        if data.len() < 2 {
            return Err(MmsError::TruncatedPdu);
        }
        let (inner_len, hdr_size) = decode_length(&data[1..])?;
        let inner_start = 1 + hdr_size;
        if inner_start + inner_len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let inner = &data[inner_start..inner_start + inner_len];

        // inner TLVs
        let mut pos = 0usize;
        let mut invoke_id: Option<u32> = None;
        let mut parsed_reason: Option<RejectReason> = None;

        while pos < inner.len() {
            // tag
            let t = *inner.get(pos).ok_or(MmsError::TruncatedPdu)?;
            pos += 1;

            // length, short form or long form
            if pos >= inner.len() {
                return Err(MmsError::TruncatedPdu);
            }
            let (vlen, lhdr) = decode_length(&inner[pos..])?;
            pos += lhdr;

            // value
            let v_end = pos + vlen;
            if v_end > inner.len() {
                return Err(MmsError::TruncatedPdu);
            }
            let v = &inner[pos..v_end];

            match t {
                0x80 => {
                    // originalInvokeID [0]
                    invoke_id = Some(decode_uint32(v));
                }
                0x81 => {
                    let r = decode_int32(v);
                    parsed_reason = Some(RejectReason::ConfirmedRequest(
                        ConfirmedRequestRejectReason::from_i32(r),
                    ));
                }
                0x82 => {
                    let r = decode_int32(v);
                    parsed_reason = Some(RejectReason::ConfirmedResponse(
                        ConfirmedResponseRejectReason::from_i32(r),
                    ));
                }
                0x83 => {
                    let r = decode_int32(v);
                    parsed_reason = Some(RejectReason::ConfirmedError(
                        ConfirmedErrorRejectReason::from_i32(r),
                    ));
                }
                0x84 => {
                    let r = decode_int32(v);
                    parsed_reason = Some(RejectReason::UnconfirmedPdu(
                        UnconfirmedPduRejectReason::from_i32(r),
                    ));
                }
                0x85 => {
                    let r = decode_int32(v);
                    parsed_reason = Some(RejectReason::PduError(PduErrorRejectReason::from_i32(r)));
                }
                // Tags 0x86, 0x87 and 0x88 carry a NULL body, so no INTEGER is decoded.
                // Peers send them with an empty body and rejecting them would break the
                // exchange.
                0x86 => {
                    parsed_reason = Some(RejectReason::CancelRequest);
                }
                0x87 => {
                    parsed_reason = Some(RejectReason::CancelResponse);
                }
                0x88 => {
                    parsed_reason = Some(RejectReason::CancelError);
                }
                0x89 => {
                    let r = decode_int32(v);
                    parsed_reason = Some(RejectReason::ConcludeRequest(
                        ConcludeRequestRejectReason::from_i32(r),
                    ));
                }
                0x8a => {
                    let r = decode_int32(v);
                    parsed_reason = Some(RejectReason::ConcludeResponse(
                        ConcludeResponseRejectReason::from_i32(r),
                    ));
                }
                0x8b => {
                    let r = decode_int32(v);
                    parsed_reason = Some(RejectReason::ConcludeError(
                        ConcludeErrorRejectReason::from_i32(r),
                    ));
                }
                unknown => {
                    // an unknown inner tag is skipped, and traced for diagnosis
                    tracing::trace!(
                        "skipping unknown reject pdu inner tag 0x{:02X} with length {}",
                        unknown,
                        vlen
                    );
                }
            }

            pos = v_end;
        }

        // without a valid rejectReason the PDU is rejected
        let reason = parsed_reason.ok_or_else(|| {
            tracing::warn!(
                "reject pdu carries no valid rejectreason tag (0x81 to 0x8b), rejecting"
            );
            MmsError::InvalidPdu
        })?;

        Ok(RejectPdu { invoke_id, reason })
    }

    /// Maps the reject reason to an `MmsError`.
    ///
    /// Four reasons map to a specific variant; every other one maps to
    /// `MmsError::RejectOther`.
    pub fn to_mms_error(&self) -> MmsError {
        match &self.reason {
            RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::UnrecognizedService) => {
                MmsError::RejectUnrecognizedService
            }
            RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::InvalidArgument) => {
                MmsError::RejectRequestInvalidArgument
            }
            RejectReason::PduError(PduErrorRejectReason::UnknownPduType) => {
                MmsError::RejectUnknownPduType
            }
            RejectReason::PduError(PduErrorRejectReason::InvalidPdu) => MmsError::RejectInvalidPdu,
            _ => MmsError::RejectOther,
        }
    }
}

// BER helpers

/// Returns the number of bytes a `u32` needs in BER.
///
/// A BER integer is signed, so a value whose top bit is set needs a leading 0x00;
/// 0xFFFFFFFF therefore takes five bytes.
fn uint32_encoded_size(v: u32) -> u8 {
    if v <= 0x7f {
        1
    } else if v <= 0x7fff {
        2
    } else if v <= 0x7fffff {
        3
    } else if v <= 0x7fffffff {
        4
    } else {
        5 // a leading 0x00 keeps the value positive
    }
}

/// Encodes a `u32` as a minimal-length big-endian BER INTEGER.
fn encode_uint32(v: u32, buf: &mut BytesMut) {
    let size = uint32_encoded_size(v);
    match size {
        1 => buf.extend_from_slice(&[v as u8]),
        2 => buf.extend_from_slice(&[(v >> 8) as u8, v as u8]),
        3 => buf.extend_from_slice(&[(v >> 16) as u8, (v >> 8) as u8, v as u8]),
        4 => buf.extend_from_slice(&[(v >> 24) as u8, (v >> 16) as u8, (v >> 8) as u8, v as u8]),
        _ => buf.extend_from_slice(&[
            0x00,
            (v >> 24) as u8,
            (v >> 16) as u8,
            (v >> 8) as u8,
            v as u8,
        ]),
    }
}

/// Decodes a BER `u32`: an empty slice yields 0, and only the last 4 bytes are used.
fn decode_uint32(v: &[u8]) -> u32 {
    let mut result = 0u32;
    for &b in v.iter().take(5) {
        result = result.wrapping_shl(8) | b as u32;
    }
    result
}

/// Decodes a BER INTEGER into an `i32`.
///
/// Lengths of 1 to 4 bytes are accepted, an empty slice yields 0, and a longer slice
/// contributes only its last 4 bytes.
fn decode_int32(v: &[u8]) -> i32 {
    if v.is_empty() {
        return 0;
    }
    // in a BER signed integer the top bit of the first byte is the sign
    let mut result = if v[0] & 0x80 != 0 {
        -1i32 // sign extend
    } else {
        0i32
    };
    for &b in v.iter().take(4) {
        result = result.wrapping_shl(8) | (b as i32 & 0xff);
    }
    result
}

// Unit tests

#[cfg(test)]
mod tests {
    use super::*;

    // helpers

    fn encode_to_vec(pdu: &RejectPdu) -> Vec<u8> {
        let mut buf = BytesMut::new();
        pdu.encode(&mut buf);
        buf.to_vec()
    }

    fn roundtrip(pdu: &RejectPdu) -> RejectPdu {
        let bytes = encode_to_vec(pdu);
        RejectPdu::decode(&bytes).expect("round trip decode failed")
    }

    // round trips without an invokeId

    #[test]
    fn encode_confirmed_request_other_no_invoke_id() {
        // confirmedRequest/other, no invokeId -> rejectType=1, rejectReason=0
        let pdu = RejectPdu {
            invoke_id: None,
            reason: RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::Other),
        };
        let bytes = encode_to_vec(&pdu);
        // a4 03 81 01 00
        assert_eq!(bytes, &[0xa4, 0x03, 0x81, 0x01, 0x00]);
    }

    #[test]
    fn encode_pdu_error_unknown_pdu_type_no_invoke_id() {
        // pduError/unknownPduType -> rejectType=5, rejectReason=0
        let pdu = RejectPdu {
            invoke_id: None,
            reason: RejectReason::PduError(PduErrorRejectReason::UnknownPduType),
        };
        let bytes = encode_to_vec(&pdu);
        // a4 03 85 01 00
        assert_eq!(bytes, &[0xa4, 0x03, 0x85, 0x01, 0x00]);
    }

    // round trips with an invokeId

    #[test]
    fn encode_unrecognized_service_with_invoke_id_1() {
        // invokeId=1, confirmedRequest/unrecognizedService
        // inner bytes: 80 01 01 81 01 01 = 6 bytes -> outer length = 6
        // a4 06 80 01 01 81 01 01
        // the content is 6 bytes, so the outer length is 6
        let pdu = RejectPdu {
            invoke_id: Some(1),
            reason: RejectReason::ConfirmedRequest(
                ConfirmedRequestRejectReason::UnrecognizedService,
            ),
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes, &[0xa4, 0x06, 0x80, 0x01, 0x01, 0x81, 0x01, 0x01]);
    }

    #[test]
    fn encode_invalid_argument_with_invoke_id_42() {
        // confirmedRequest/invalidArgument, invokeId=42 -> rejectType=1, reason=4
        // inner bytes: 80 01 2a 81 01 04 = 6 bytes -> outer length = 6
        let pdu = RejectPdu {
            invoke_id: Some(42),
            reason: RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::InvalidArgument),
        };
        let bytes = encode_to_vec(&pdu);
        // a4 06 80 01 2a 81 01 04
        assert_eq!(bytes, &[0xa4, 0x06, 0x80, 0x01, 0x2a, 0x81, 0x01, 0x04]);
    }

    // one round trip per rejectType

    #[test]
    fn roundtrip_all_reject_types_no_invoke_id() {
        let cases: &[RejectReason] = &[
            RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::Other),
            RejectReason::ConfirmedResponse(ConfirmedResponseRejectReason::Other),
            RejectReason::ConfirmedError(ConfirmedErrorRejectReason::Other),
            RejectReason::UnconfirmedPdu(UnconfirmedPduRejectReason::Other),
            RejectReason::PduError(PduErrorRejectReason::UnknownPduType),
            RejectReason::CancelRequest,
            RejectReason::CancelResponse,
            RejectReason::CancelError,
            RejectReason::ConcludeRequest(ConcludeRequestRejectReason::Other),
            RejectReason::ConcludeResponse(ConcludeResponseRejectReason::Other),
            RejectReason::ConcludeError(ConcludeErrorRejectReason::Other),
        ];
        for reason in cases {
            let pdu = RejectPdu {
                invoke_id: None,
                reason: reason.clone(),
            };
            let got = roundtrip(&pdu);
            assert_eq!(got, pdu, "round trip failed for {:?}", reason);
        }
    }

    #[test]
    fn roundtrip_all_reject_types_with_invoke_id() {
        let cases: &[RejectReason] = &[
            RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::UnrecognizedService),
            RejectReason::ConfirmedResponse(ConfirmedResponseRejectReason::InvalidResult),
            RejectReason::ConfirmedError(ConfirmedErrorRejectReason::ValueOutOfRange),
            RejectReason::UnconfirmedPdu(UnconfirmedPduRejectReason::MaxRecursionExceeded),
            RejectReason::PduError(PduErrorRejectReason::IllegalAcseMapping),
            RejectReason::CancelRequest,
            RejectReason::ConcludeRequest(ConcludeRequestRejectReason::InvalidArgument),
            RejectReason::ConcludeResponse(ConcludeResponseRejectReason::InvalidResult),
            RejectReason::ConcludeError(ConcludeErrorRejectReason::ValueOutOfRange),
        ];
        for reason in cases {
            let pdu = RejectPdu {
                invoke_id: Some(99),
                reason: reason.clone(),
            };
            let got = roundtrip(&pdu);
            assert_eq!(
                got, pdu,
                "round trip with invokeId 99 failed for {:?}",
                reason
            );
        }
    }

    // four byte-exact encodings

    #[test]
    fn c_produced_unrecognized_service_no_invoke() {
        // confirmedRequest/unrecognizedService, no invokeId
        let pdu = RejectPdu {
            invoke_id: None,
            reason: RejectReason::ConfirmedRequest(
                ConfirmedRequestRejectReason::UnrecognizedService,
            ),
        };
        assert_eq!(encode_to_vec(&pdu), &[0xa4, 0x03, 0x81, 0x01, 0x01]);
    }

    #[test]
    fn c_produced_unknown_pdu_type_no_invoke() {
        // pduError/unknownPduType, no invokeId
        let pdu = RejectPdu {
            invoke_id: None,
            reason: RejectReason::PduError(PduErrorRejectReason::UnknownPduType),
        };
        assert_eq!(encode_to_vec(&pdu), &[0xa4, 0x03, 0x85, 0x01, 0x00]);
    }

    #[test]
    fn c_produced_invalid_argument_with_invoke_1() {
        // confirmedRequest/invalidArgument, invokeId=1
        // the content is 3 + 2 + 1 bytes with a one-byte invokeId, so 6 in all:
        // a4 06 80 01 01 81 01 04
        let pdu = RejectPdu {
            invoke_id: Some(1),
            reason: RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::InvalidArgument),
        };
        assert_eq!(
            encode_to_vec(&pdu),
            &[0xa4, 0x06, 0x80, 0x01, 0x01, 0x81, 0x01, 0x04]
        );
    }

    #[test]
    fn c_produced_invalid_pdu_no_invoke() {
        // pduError/invalidPdu, no invokeId
        let pdu = RejectPdu {
            invoke_id: None,
            reason: RejectReason::PduError(PduErrorRejectReason::InvalidPdu),
        };
        assert_eq!(encode_to_vec(&pdu), &[0xa4, 0x03, 0x85, 0x01, 0x01]);
    }

    // invoke_id absent versus present

    #[test]
    fn invoke_id_none_omits_field() {
        let pdu = RejectPdu {
            invoke_id: None,
            reason: RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::Other),
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes.len(), 5); // a4 03 81 01 00
        assert!(!bytes.contains(&0x80)); // the invokeId tag must be absent
    }

    #[test]
    fn invoke_id_some_42_present() {
        let pdu = RejectPdu {
            invoke_id: Some(42),
            reason: RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::Other),
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes.len(), 8); // a4 06 80 01 2a 81 01 00
        let decoded = RejectPdu::decode(&bytes).unwrap();
        assert_eq!(decoded.invoke_id, Some(42));
    }

    // a multi-byte invoke_id

    #[test]
    fn multi_byte_invoke_id_roundtrip() {
        let pdu = RejectPdu {
            invoke_id: Some(0x1234_5678),
            reason: RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::Other),
        };
        let got = roundtrip(&pdu);
        assert_eq!(got.invoke_id, Some(0x1234_5678));
    }

    // the decoder tolerates a multi-byte reason

    #[test]
    fn decoder_multi_byte_reason_accepted() {
        // 0x81 0x02 0x00 0x05 is confirmedRequest reason 5, InvalidModifier,
        // written as a multi-byte BER INTEGER the decoder must accept
        // inner = [0x81, 0x02, 0x00, 0x05] = 4 bytes -> outer length = 4
        let data = &[0xa4u8, 0x04, 0x81, 0x02, 0x00, 0x05];
        let pdu = RejectPdu::decode(data).unwrap();
        assert_eq!(
            pdu.reason,
            RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::InvalidModifier)
        );
    }

    #[test]
    fn decoder_single_byte_reason_5() {
        // confirmedRequest reason = 5 -> InvalidModifier
        let data = &[0xa4u8, 0x03, 0x81, 0x01, 0x05];
        let pdu = RejectPdu::decode(data).unwrap();
        assert_eq!(
            pdu.reason,
            RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::InvalidModifier)
        );
    }

    // an unknown reason value clamps to Other

    #[test]
    fn unknown_confirmed_request_reason_clamps_to_other() {
        // reason 99 lies outside the defined range and clamps to Other(0)
        let data = &[0xa4u8, 0x03, 0x81, 0x01, 0x63]; // 0x63 is 99
        let pdu = RejectPdu::decode(data).unwrap();
        assert_eq!(
            pdu.reason,
            RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::Other)
        );
    }

    // an unknown rejectType is skipped

    #[test]
    fn unknown_reject_type_0x8f_ignored_no_reason_returns_err() {
        // tag 0x8f is rejectType 15, above 0x8b, so it is skipped and no reason remains
        let data = &[0xa4u8, 0x03, 0x8f, 0x01, 0x00];
        let result = RejectPdu::decode(data);
        assert!(
            matches!(result, Err(MmsError::InvalidPdu)),
            "expected InvalidPdu, got {:?}",
            result
        );
    }

    #[test]
    fn unknown_reject_type_12_with_valid_before_it() {
        // a valid reason followed by an unknown tag still decodes
        let data = &[0xa4u8, 0x06, 0x81, 0x01, 0x01, 0x8f, 0x01, 0x00];
        let pdu = RejectPdu::decode(data).unwrap();
        assert_eq!(
            pdu.reason,
            RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::UnrecognizedService)
        );
    }

    // a truncated PDU yields TruncatedPdu

    #[test]
    fn truncated_empty_returns_err() {
        assert!(matches!(
            RejectPdu::decode(&[]),
            Err(MmsError::TruncatedPdu)
        ));
    }

    #[test]
    fn truncated_only_outer_tag() {
        assert!(matches!(
            RejectPdu::decode(&[0xa4]),
            Err(MmsError::TruncatedPdu)
        ));
    }

    #[test]
    fn truncated_inner_content() {
        // the outer length claims 7 bytes with only 2 present
        let data = &[0xa4u8, 0x07, 0x81, 0x01];
        assert!(matches!(
            RejectPdu::decode(data),
            Err(MmsError::TruncatedPdu)
        ));
    }

    #[test]
    fn truncated_no_length_byte() {
        // 0xa4 with no length byte
        let data = &[0xa4u8];
        assert!(matches!(
            RejectPdu::decode(data),
            Err(MmsError::TruncatedPdu)
        ));
    }

    // a PDU with only an invokeId and no reason is rejected

    #[test]
    fn pdu_with_only_invoke_id_no_reason_returns_err() {
        // a4 03 80 01 01 carries an invokeId and no rejectReason
        let data = &[0xa4u8, 0x03, 0x80, 0x01, 0x01];
        let result = RejectPdu::decode(data);
        assert!(
            matches!(result, Err(MmsError::InvalidPdu)),
            "expected InvalidPdu, got {:?}",
            result
        );
    }

    // a wrong outer tag yields InvalidTag

    #[test]
    fn wrong_outer_tag_returns_err() {
        let data = &[0xa8u8, 0x03, 0x81, 0x01, 0x01];
        let result = RejectPdu::decode(data);
        assert!(matches!(
            result,
            Err(MmsError::InvalidTag {
                expected: 0xa4,
                actual: 0xa8
            })
        ));
    }

    // the NULL-bodied rejectTypes

    #[test]
    fn cancel_request_encode_decode() {
        let pdu = RejectPdu {
            invoke_id: None,
            reason: RejectReason::CancelRequest,
        };
        let bytes = encode_to_vec(&pdu);
        // a4 02 86 00
        assert_eq!(bytes, &[0xa4, 0x02, 0x86, 0x00]);
        let got = RejectPdu::decode(&bytes).unwrap();
        assert_eq!(got.reason, RejectReason::CancelRequest);
    }

    #[test]
    fn cancel_response_encode_decode() {
        let pdu = RejectPdu {
            invoke_id: None,
            reason: RejectReason::CancelResponse,
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes, &[0xa4, 0x02, 0x87, 0x00]);
        let got = RejectPdu::decode(&bytes).unwrap();
        assert_eq!(got.reason, RejectReason::CancelResponse);
    }

    #[test]
    fn cancel_error_encode_decode() {
        let pdu = RejectPdu {
            invoke_id: None,
            reason: RejectReason::CancelError,
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes, &[0xa4, 0x02, 0x88, 0x00]);
        let got = RejectPdu::decode(&bytes).unwrap();
        assert_eq!(got.reason, RejectReason::CancelError);
    }

    // the four specific to_mms_error mappings

    #[test]
    fn to_mms_error_unrecognized_service() {
        let pdu = RejectPdu {
            invoke_id: None,
            reason: RejectReason::ConfirmedRequest(
                ConfirmedRequestRejectReason::UnrecognizedService,
            ),
        };
        assert_eq!(pdu.to_mms_error(), MmsError::RejectUnrecognizedService);
    }

    #[test]
    fn to_mms_error_invalid_argument() {
        let pdu = RejectPdu {
            invoke_id: None,
            reason: RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::InvalidArgument),
        };
        assert_eq!(pdu.to_mms_error(), MmsError::RejectRequestInvalidArgument);
    }

    #[test]
    fn to_mms_error_unknown_pdu_type() {
        let pdu = RejectPdu {
            invoke_id: None,
            reason: RejectReason::PduError(PduErrorRejectReason::UnknownPduType),
        };
        assert_eq!(pdu.to_mms_error(), MmsError::RejectUnknownPduType);
    }

    #[test]
    fn to_mms_error_invalid_pdu() {
        let pdu = RejectPdu {
            invoke_id: None,
            reason: RejectReason::PduError(PduErrorRejectReason::InvalidPdu),
        };
        assert_eq!(pdu.to_mms_error(), MmsError::RejectInvalidPdu);
    }

    #[test]
    fn to_mms_error_other_cases() {
        let pdu = RejectPdu {
            invoke_id: None,
            reason: RejectReason::ConfirmedError(ConfirmedErrorRejectReason::Other),
        };
        assert_eq!(pdu.to_mms_error(), MmsError::RejectOther);
    }

    // round trips over every sub-enum value

    #[test]
    fn confirmed_request_all_values_roundtrip() {
        use ConfirmedRequestRejectReason::*;
        for r in [
            Other,
            UnrecognizedService,
            UnrecognizedModifier,
            InvalidInvokeId,
            InvalidArgument,
            InvalidModifier,
            MaxServOutstandingExceeded,
            MaxRecursionExceeded,
            ValueOutOfRange,
        ] {
            let pdu = RejectPdu {
                invoke_id: None,
                reason: RejectReason::ConfirmedRequest(r),
            };
            let got = roundtrip(&pdu);
            assert_eq!(got, pdu);
        }
    }

    #[test]
    fn conclude_error_all_values_roundtrip() {
        use ConcludeErrorRejectReason::*;
        for r in [Other, InvalidServiceError, ValueOutOfRange] {
            let pdu = RejectPdu {
                invoke_id: None,
                reason: RejectReason::ConcludeError(r),
            };
            let got = roundtrip(&pdu);
            assert_eq!(got, pdu);
        }
    }
}
