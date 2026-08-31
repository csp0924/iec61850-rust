//! The outermost MmsPdu CHOICE and its tag dispatch.
//!
//! ## Tag assignment
//!
//! | Variant                | BER tag  | Notes                       |
//! |------------------------|----------|-----------------------------|
//! | ConfirmedRequest       | `0xa0`   | `[0]` IMPLICIT SEQUENCE       |
//! | ConfirmedResponse      | `0xa1`   | `[1]` IMPLICIT SEQUENCE       |
//! | ConfirmedError         | `0xa2`   | `[2]` IMPLICIT SEQUENCE       |
//! | Unconfirmed            | `0xa3`   | `[3]` IMPLICIT SEQUENCE       |
//! | Reject                 | `0xa4`   | `[4]` IMPLICIT SEQUENCE       |
//! | InitiateRequest        | `0xa8`   | `[8]` IMPLICIT SEQUENCE       |
//! | InitiateResponse       | `0xa9`   | `[9]` IMPLICIT SEQUENCE       |
//! | InitiateError          | `0xaa`   | `[10]` IMPLICIT SEQUENCE      |
//! | ConcludeRequest        | `0x8b`   | `[11]` IMPLICIT primitive NULL |
//! | ConcludeResponse       | `0x8c`   | `[12]` IMPLICIT primitive NULL |
//!
//! Tags `[5]`, `[6]` and `[7]`, the cancel services, exist in the standard but are not
//! implemented: decoding one returns `UnknownMmsPduTag` and logs a warning.
//!
//! `ConfirmedRequest`, `ConfirmedResponse`, `ConfirmedError` and `Unconfirmed` are
//! decoded only as far as their content bytes; the service layer parses those.
//! `Reject` is decoded in full into a `RejectPdu`.

use bytes::{Bytes, BytesMut};

pub mod common;
pub mod conclude;
pub mod define_named_variable_list;
pub mod delete_named_variable_list;
pub mod get_name_list;
pub mod get_var_access_attrs;
pub mod information_report;
pub mod initiate;
pub mod read;
pub mod read_journal;
pub mod reject;
pub mod service_error;
pub mod type_specification;
pub mod write;

use super::error::MmsError;
pub use common::{
    AccessResult, AlternateAccess, AlternateAccessSelector, DataAccessError, ListOfVariableEntry,
    MmsData, ObjectName, VariableAccessSpecification, WriteOutcome, MAX_DATA_NESTING_DEPTH,
    MAX_IDENTIFIER_LEN,
};
pub use conclude::{ConcludeRequestPdu, ConcludeResponsePdu};
pub use define_named_variable_list::{
    decode_confirmed_define_named_variable_list_request,
    decode_confirmed_define_named_variable_list_response,
    encode_confirmed_define_named_variable_list_request,
    encode_confirmed_define_named_variable_list_response, DefineNamedVariableEntry,
    DefineNamedVariableListRequest, DefineNamedVariableListResponse, MAX_DEFINE_ENTRIES,
    SERVICE_TAG_DEFINE_NAMED_VARIABLE_LIST,
};
pub use delete_named_variable_list::{
    decode_confirmed_delete_named_variable_list_request,
    decode_confirmed_delete_named_variable_list_response,
    encode_confirmed_delete_named_variable_list_request,
    encode_confirmed_delete_named_variable_list_response, DeleteNamedVariableListRequest,
    DeleteNamedVariableListResponse, ScopeOfDelete, SERVICE_TAG_DELETE_NAMED_VARIABLE_LIST,
};
pub use get_name_list::{
    decode_confirmed_get_name_list_request, decode_confirmed_get_name_list_response,
    encode_confirmed_get_name_list_request, encode_confirmed_get_name_list_response,
    GetNameListRequest, GetNameListResponse, ObjectClass, ObjectScope, SERVICE_TAG_GET_NAME_LIST,
};
pub use get_var_access_attrs::{
    decode_confirmed_get_var_access_attrs_request, decode_confirmed_get_var_access_attrs_response,
    encode_confirmed_get_var_access_attrs_request, encode_confirmed_get_var_access_attrs_response,
    GetVariableAccessAttributesRequest, GetVariableAccessAttributesResponse,
    SERVICE_TAG_GET_VAR_ACCESS_ATTRS,
};
pub use information_report::{
    encode_command_termination_negative, encode_command_termination_positive,
    encode_information_report, encode_last_appl_error_struct, LastApplErrorRef, OriginRef,
};
pub use initiate::{
    InitRequestDetail, InitResponseDetail, InitiateErrorPdu, InitiateRequestPdu,
    InitiateResponsePdu, DEFAULT_MAX_PDU_SIZE, DEFAULT_MAX_SERV_OUTSTANDING_CALLED,
    DEFAULT_MAX_SERV_OUTSTANDING_CALLING, DEFAULT_PARAMETER_CBB_CLIENT,
    DEFAULT_SERVICES_SUPPORTED_CLIENT,
};
pub use read::{
    decode_confirmed_read_request, decode_confirmed_read_response, encode_confirmed_read_request,
    encode_confirmed_read_response, ReadRequest, ReadResponse, SERVICE_TAG_READ,
};
pub use read_journal::{
    decode_confirmed_read_journal_request, decode_confirmed_read_journal_response,
    encode_confirmed_read_journal_request, encode_confirmed_read_journal_response, JournalRange,
    ReadJournalRequest, ReadJournalResponse, WireJournalEntry, WireJournalVariable, ENTRY_ID_SIZE,
    SERVICE_TAG_READ_JOURNAL,
};
pub use reject::{
    ConcludeErrorRejectReason, ConcludeRequestRejectReason, ConcludeResponseRejectReason,
    ConfirmedErrorRejectReason, ConfirmedRequestRejectReason, ConfirmedResponseRejectReason,
    PduErrorRejectReason, RejectPdu, RejectReason, UnconfirmedPduRejectReason,
};
pub use service_error::{encode_confirmed_error_pdu, ErrorClass, ServiceError};
pub use type_specification::{StructComponent, TypeSpecification, MAX_TYPE_SPEC_DEPTH};
pub use write::{
    decode_confirmed_write_request, decode_confirmed_write_response,
    encode_confirmed_write_request, encode_confirmed_write_response, WriteRequest, WriteResponse,
    MAX_WRITE_ITEMS, SERVICE_TAG_WRITE,
};

// Outermost tag constants

/// Outermost tag of a ConfirmedRequestPdu, MmsPdu `[0]`.
pub const TAG_CONFIRMED_REQUEST: u8 = 0xa0;
/// Outermost tag of a ConfirmedResponsePdu, MmsPdu `[1]`.
pub const TAG_CONFIRMED_RESPONSE: u8 = 0xa1;
/// Outermost tag of a ConfirmedErrorPDU, MmsPdu `[2]`.
pub const TAG_CONFIRMED_ERROR: u8 = 0xa2;
/// Outermost tag of an UnconfirmedPDU, MmsPdu `[3]`.
pub const TAG_UNCONFIRMED: u8 = 0xa3;
/// Outermost tag of a RejectPDU, MmsPdu `[4]`.
pub const TAG_REJECT: u8 = 0xa4;
/// Outermost tag of an InitiateRequestPdu, MmsPdu `[8]`.
pub const TAG_INITIATE_REQUEST: u8 = 0xa8;
/// Outermost tag of an InitiateResponsePdu, MmsPdu `[9]`.
pub const TAG_INITIATE_RESPONSE: u8 = 0xa9;
/// Outermost tag of an InitiateErrorPdu, MmsPdu `[10]`.
pub const TAG_INITIATE_ERROR: u8 = 0xaa;
/// Outermost tag of a ConcludeRequestPDU, MmsPdu `[11]`.
pub const TAG_CONCLUDE_REQUEST: u8 = 0x8b;
/// Outermost tag of a ConcludeResponsePDU, MmsPdu `[12]`.
pub const TAG_CONCLUDE_RESPONSE: u8 = 0x8c;

// MmsPdu enum

/// The outermost MMS PDU CHOICE, per ISO 9506-2.
///
/// `ConfirmedRequest`, `ConfirmedResponse`, `ConfirmedError` and `Unconfirmed` carry
/// their content as raw bytes for the service layer to parse. `Reject` is decoded in
/// full into a `RejectPdu`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MmsPdu {
    /// `[0]` `0xa0`: ConfirmedRequestPdu, as raw content bytes.
    ConfirmedRequest(Bytes),
    /// `[1]` `0xa1`: ConfirmedResponsePdu, as raw content bytes.
    ConfirmedResponse(Bytes),
    /// `[2]` `0xa2`: ConfirmedErrorPDU, as raw content bytes.
    ConfirmedError(Bytes),
    /// `[3]` `0xa3`: UnconfirmedPDU, as raw content bytes.
    Unconfirmed(Bytes),
    /// `[4]` `0xa4`: RejectPDU, decoded in full.
    Reject(RejectPdu),
    /// `[8]` `0xa8`: InitiateRequestPdu, decoded in full.
    InitiateRequest(InitiateRequestPdu),
    /// `[9]` `0xa9`: InitiateResponsePdu, decoded in full.
    InitiateResponse(InitiateResponsePdu),
    /// `[10]` `0xaa`: InitiateErrorPdu, decoded in full.
    InitiateError(InitiateErrorPdu),
    /// `[11]` `0x8b`: ConcludeRequestPDU, with an empty body.
    ConcludeRequest,
    /// `[12]` `0x8c`: ConcludeResponsePDU, with an empty body.
    ConcludeResponse,
}

impl MmsPdu {
    /// Returns the outermost tag byte of this variant.
    pub fn tag_byte(&self) -> u8 {
        match self {
            MmsPdu::ConfirmedRequest(_) => TAG_CONFIRMED_REQUEST,
            MmsPdu::ConfirmedResponse(_) => TAG_CONFIRMED_RESPONSE,
            MmsPdu::ConfirmedError(_) => TAG_CONFIRMED_ERROR,
            MmsPdu::Unconfirmed(_) => TAG_UNCONFIRMED,
            MmsPdu::Reject(_) => TAG_REJECT,
            MmsPdu::InitiateRequest(_) => TAG_INITIATE_REQUEST,
            MmsPdu::InitiateResponse(_) => TAG_INITIATE_RESPONSE,
            MmsPdu::InitiateError(_) => TAG_INITIATE_ERROR,
            MmsPdu::ConcludeRequest => TAG_CONCLUDE_REQUEST,
            MmsPdu::ConcludeResponse => TAG_CONCLUDE_RESPONSE,
        }
    }

    /// Encodes the PDU into `buf`.
    ///
    /// The Initiate variants delegate to their own encoders, the Conclude variants
    /// write their fixed two bytes, `Reject` delegates to `RejectPdu::encode`, which
    /// already writes the outer `0xa4`, and the raw-content variants are wrapped in
    /// their tag and length again.
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            MmsPdu::ConfirmedRequest(inner)
            | MmsPdu::ConfirmedResponse(inner)
            | MmsPdu::ConfirmedError(inner)
            | MmsPdu::Unconfirmed(inner) => {
                buf.extend_from_slice(&[self.tag_byte()]);
                initiate::encode_length(inner.len(), buf);
                buf.extend_from_slice(inner);
            }
            MmsPdu::Reject(pdu) => pdu.encode(buf),
            MmsPdu::InitiateRequest(pdu) => pdu.encode(buf),
            MmsPdu::InitiateResponse(pdu) => pdu.encode(buf),
            MmsPdu::InitiateError(pdu) => pdu.encode(buf),
            MmsPdu::ConcludeRequest => {
                buf.extend_from_slice(&conclude::CONCLUDE_REQUEST_BYTES);
            }
            MmsPdu::ConcludeResponse => {
                buf.extend_from_slice(&conclude::CONCLUDE_RESPONSE_BYTES);
            }
        }
    }

    /// Decodes a PDU; `data` starts at the first tag byte.
    ///
    /// The Confirmed and Unconfirmed variants keep their content as raw bytes, `Reject`
    /// is decoded into a `RejectPdu`, and the Initiate and Conclude variants are
    /// decoded in full.
    ///
    /// An unrecognized tag returns `MmsError::UnknownMmsPduTag`.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        let tag = data[0];
        match tag {
            TAG_CONFIRMED_REQUEST => {
                let inner = extract_inner_bytes(data)?;
                Ok(MmsPdu::ConfirmedRequest(inner))
            }
            TAG_CONFIRMED_RESPONSE => {
                let inner = extract_inner_bytes(data)?;
                Ok(MmsPdu::ConfirmedResponse(inner))
            }
            TAG_CONFIRMED_ERROR => {
                let inner = extract_inner_bytes(data)?;
                Ok(MmsPdu::ConfirmedError(inner))
            }
            TAG_UNCONFIRMED => {
                let inner = extract_inner_bytes(data)?;
                Ok(MmsPdu::Unconfirmed(inner))
            }
            TAG_REJECT => {
                // decoded in full
                let pdu = RejectPdu::decode(data)?;
                Ok(MmsPdu::Reject(pdu))
            }
            TAG_INITIATE_REQUEST => {
                let pdu = InitiateRequestPdu::decode(data)?;
                Ok(MmsPdu::InitiateRequest(pdu))
            }
            TAG_INITIATE_RESPONSE => {
                let pdu = InitiateResponsePdu::decode(data)?;
                Ok(MmsPdu::InitiateResponse(pdu))
            }
            TAG_INITIATE_ERROR => {
                let pdu = InitiateErrorPdu::decode(data)?;
                Ok(MmsPdu::InitiateError(pdu))
            }
            TAG_CONCLUDE_REQUEST => {
                // 0x8b 0x00, two bytes
                Ok(MmsPdu::ConcludeRequest)
            }
            TAG_CONCLUDE_RESPONSE => {
                // 0x8c 0x00, two bytes
                Ok(MmsPdu::ConcludeResponse)
            }
            // tags [5], [6] and [7] are the cancel services, which are not implemented
            unknown => {
                tracing::warn!("unknown mms pdu tag 0x{:02X}, rejecting", unknown);
                Err(MmsError::UnknownMmsPduTag(unknown))
            }
        }
    }
}

// Helpers

/// Returns the content of a TLV as `Bytes`; `data` starts at the tag byte.
fn extract_inner_bytes(data: &[u8]) -> Result<Bytes, MmsError> {
    if data.len() < 2 {
        return Err(MmsError::TruncatedPdu);
    }
    let (inner_len, hdr_size) = initiate::decode_length(&data[1..])?;
    let inner_start = 1 + hdr_size;
    if inner_start + inner_len > data.len() {
        return Err(MmsError::TruncatedPdu);
    }
    Ok(Bytes::copy_from_slice(
        &data[inner_start..inner_start + inner_len],
    ))
}

// Unit tests

#[cfg(test)]
mod tests {
    use super::*;

    // one dispatch test per variant

    #[test]
    fn dispatch_confirmed_request() {
        // 0xa0 0x01 0x00 with one content byte
        let data = &[0xa0u8, 0x01, 0x42];
        let pdu = MmsPdu::decode(data).unwrap();
        assert!(matches!(pdu, MmsPdu::ConfirmedRequest(_)));
        assert_eq!(pdu.tag_byte(), 0xa0);
    }

    #[test]
    fn dispatch_confirmed_response() {
        let data = &[0xa1u8, 0x01, 0x42];
        let pdu = MmsPdu::decode(data).unwrap();
        assert!(matches!(pdu, MmsPdu::ConfirmedResponse(_)));
        assert_eq!(pdu.tag_byte(), 0xa1);
    }

    #[test]
    fn dispatch_confirmed_error() {
        let data = &[0xa2u8, 0x01, 0x42];
        let pdu = MmsPdu::decode(data).unwrap();
        assert!(matches!(pdu, MmsPdu::ConfirmedError(_)));
        assert_eq!(pdu.tag_byte(), 0xa2);
    }

    #[test]
    fn dispatch_unconfirmed() {
        let data = &[0xa3u8, 0x01, 0x42];
        let pdu = MmsPdu::decode(data).unwrap();
        assert!(matches!(pdu, MmsPdu::Unconfirmed(_)));
        assert_eq!(pdu.tag_byte(), 0xa3);
    }

    #[test]
    fn dispatch_reject() {
        // a valid reject: confirmedRequest with unrecognizedService and invokeId 1,
        // whose content is 80 01 01 81 01 01, six bytes, giving a4 06 ...
        let data = &[0xa4u8, 0x06, 0x80, 0x01, 0x01, 0x81, 0x01, 0x01];
        let pdu = MmsPdu::decode(data).unwrap();
        assert!(matches!(pdu, MmsPdu::Reject(_)));
        assert_eq!(pdu.tag_byte(), 0xa4);
        if let MmsPdu::Reject(r) = &pdu {
            assert_eq!(r.invoke_id, Some(1));
            assert_eq!(
                r.reason,
                RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::UnrecognizedService)
            );
        } else {
            panic!("expected the Reject variant");
        }
    }

    #[test]
    fn reject_mmspdu_encode_decode_roundtrip() {
        // a full encode and decode round trip of a Reject at the MmsPdu layer
        let reject = RejectPdu {
            invoke_id: Some(5),
            reason: RejectReason::PduError(PduErrorRejectReason::InvalidPdu),
        };
        let pdu = MmsPdu::Reject(reject.clone());
        let mut buf = BytesMut::new();
        pdu.encode(&mut buf);
        let decoded = MmsPdu::decode(&buf).unwrap();
        assert_eq!(decoded, MmsPdu::Reject(reject));
    }

    #[test]
    fn dispatch_initiate_request() {
        // encode a default request and check the decoded variant
        let req = InitiateRequestPdu::default();
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let pdu = MmsPdu::decode(&buf).unwrap();
        assert!(matches!(pdu, MmsPdu::InitiateRequest(_)));
        assert_eq!(pdu.tag_byte(), 0xa8);
    }

    #[test]
    fn dispatch_initiate_response() {
        let resp = InitiateResponsePdu::default();
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        let pdu = MmsPdu::decode(&buf).unwrap();
        assert!(matches!(pdu, MmsPdu::InitiateResponse(_)));
        assert_eq!(pdu.tag_byte(), 0xa9);
    }

    #[test]
    fn dispatch_initiate_error() {
        let err_pdu = InitiateErrorPdu::new(0);
        let mut buf = BytesMut::new();
        err_pdu.encode(&mut buf);
        let pdu = MmsPdu::decode(&buf).unwrap();
        assert!(matches!(pdu, MmsPdu::InitiateError(_)));
        assert_eq!(pdu.tag_byte(), 0xaa);
    }

    #[test]
    fn dispatch_conclude_request() {
        let data = &[0x8bu8, 0x00];
        let pdu = MmsPdu::decode(data).unwrap();
        assert_eq!(pdu, MmsPdu::ConcludeRequest);
        assert_eq!(pdu.tag_byte(), 0x8b);
    }

    #[test]
    fn dispatch_conclude_response() {
        let data = &[0x8cu8, 0x00];
        let pdu = MmsPdu::decode(data).unwrap();
        assert_eq!(pdu, MmsPdu::ConcludeResponse);
        assert_eq!(pdu.tag_byte(), 0x8c);
    }

    // unknown tags

    #[test]
    fn unknown_tag_returns_err() {
        // tag [5], 0xa5, is cancel-request and is not implemented
        let data = &[0xa5u8, 0x01, 0x00];
        let result = MmsPdu::decode(data);
        assert!(matches!(result, Err(MmsError::UnknownMmsPduTag(0xa5))));
    }

    #[test]
    fn cancel_tags_56_7_all_unknown() {
        for tag in [0xa5u8, 0xa6, 0xa7] {
            let data = &[tag, 0x01, 0x00];
            let result = MmsPdu::decode(data);
            assert!(
                matches!(result, Err(MmsError::UnknownMmsPduTag(_))),
                "tag 0x{:02X} must return UnknownMmsPduTag",
                tag
            );
        }
    }

    // encode round trips for the raw-content variants

    #[test]
    fn confirmed_request_encode_roundtrip() {
        let inner = Bytes::from_static(&[0x01, 0x02, 0x03]);
        let pdu = MmsPdu::ConfirmedRequest(inner.clone());
        let mut buf = BytesMut::new();
        pdu.encode(&mut buf);
        assert_eq!(buf[0], 0xa0);
        let decoded = MmsPdu::decode(&buf).unwrap();
        if let MmsPdu::ConfirmedRequest(got) = decoded {
            assert_eq!(got, inner);
        } else {
            panic!("the decoded pdu is not a ConfirmedRequest");
        }
    }

    // byte-exact Conclude encoding

    #[test]
    fn conclude_request_encode_via_mmspdu() {
        let pdu = MmsPdu::ConcludeRequest;
        let mut buf = BytesMut::new();
        pdu.encode(&mut buf);
        assert_eq!(&buf[..], &[0x8b, 0x00]);
    }

    #[test]
    fn conclude_response_encode_via_mmspdu() {
        let pdu = MmsPdu::ConcludeResponse;
        let mut buf = BytesMut::new();
        pdu.encode(&mut buf);
        assert_eq!(&buf[..], &[0x8c, 0x00]);
    }

    // boundary conditions

    #[test]
    fn empty_input_returns_truncated() {
        let result = MmsPdu::decode(&[]);
        assert!(matches!(result, Err(MmsError::TruncatedPdu)));
    }

    #[test]
    fn initiate_error_byte_exact_via_mmspdu() {
        let err_pdu = InitiateErrorPdu::new(0);
        let pdu = MmsPdu::InitiateError(err_pdu);
        let mut buf = BytesMut::new();
        pdu.encode(&mut buf);
        assert_eq!(&buf[..], &[0xaa, 0x05, 0xa0, 0x03, 0x88, 0x01, 0x00]);
    }
}
