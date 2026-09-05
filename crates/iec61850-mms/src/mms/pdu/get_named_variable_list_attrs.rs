//! MMS GetNamedVariableListAttributes request and response PDUs, per ISO 9506-2.
//!
//! ## Wire format
//!
//! `GetNamedVariableListAttributesRequest ::= ObjectName`. An `ObjectName` is a
//! CHOICE, so the ConfirmedServiceRequest tag `[12]` is EXPLICIT and wraps the
//! `ObjectName` unchanged:
//!
//! ```text
//! 0xa0 <len>          -- confirmedRequestPdu [0] IMPLICIT SEQUENCE
//!   0x02 <len> <id>   -- invokeID INTEGER
//!   0xac <len>        -- getNamedVariableListAttributes [12] EXPLICIT
//!     <ObjectName>    -- domain-specific, vmd-specific or aa-specific
//! ```
//!
//! The response tag `[12]` is IMPLICIT over a SEQUENCE, so the two wrappers are
//! not symmetric:
//!
//! ```text
//! 0xa1 <len>            -- confirmedResponsePdu [1] IMPLICIT SEQUENCE
//!   0x02 <len> <id>     -- invokeID INTEGER
//!   0xac <len>          -- getNamedVariableListAttributes [12] IMPLICIT SEQUENCE
//!     0x80 <1> <bool>   -- mmsDeletable [0] IMPLICIT BOOLEAN
//!     0xa1 <len>        -- listOfVariable [1] IMPLICIT SEQUENCE OF
//!       0x30 <len>      -- ListOfVariableSeq, UNIVERSAL SEQUENCE
//!         0xa0 <len>    -- variableSpecification.name [0] IMPLICIT
//!           <ObjectName>
//!         [0xa5 <len>]  -- alternateAccess [5] IMPLICIT, OPTIONAL
//!     [0x82 <len> <s>]  -- accessControlList [2] IMPLICIT Identifier, OPTIONAL
//! ```
//!
//! ## listOfVariable elements
//!
//! An element has the same shape as an element of
//! `VariableAccessSpecification::ListOfVariable`, so [`ListOfVariableEntry`] and
//! its codec are reused unchanged, `alternateAccess` on the `[5]` IMPLICIT tag
//! included.
//!
//! ## accessControlList
//!
//! Decoding accepts and discards the `[2]` field; encoding never emits it.
//!
//! ## Response size
//!
//! The number of decoded elements is bounded by the length of the input, since
//! every element consumes at least two bytes. The transport layer caps that
//! length at the negotiated maximum PDU size.

use super::super::error::MmsError;
use super::common::{decode_list_of_variable, encode_list_of_variable_seq, ObjectName};
use super::initiate::{decode_length, encode_length};
use super::ListOfVariableEntry;
use crate::compat::prelude::*;
use bytes::BytesMut;

// Tag constants

/// Service tag of GetNamedVariableListAttributes in the ConfirmedService CHOICE.
///
/// In a request `0xac` is CONTEXT `[12]` EXPLICIT CONSTRUCTED over an
/// `ObjectName`; in a response it is CONTEXT `[12]` IMPLICIT CONSTRUCTED
/// SEQUENCE.
pub const SERVICE_TAG_GET_NAMED_VARIABLE_LIST_ATTRS: u8 = 0xac;

/// mmsDeletable `[0]` IMPLICIT BOOLEAN.
const TAG_MMS_DELETABLE: u8 = 0x80;

/// listOfVariable `[1]` IMPLICIT SEQUENCE OF ListOfVariableSeq.
const TAG_LIST_OF_VARIABLE: u8 = 0xa1;

/// accessControlList `[2]` IMPLICIT Identifier, OPTIONAL.
const TAG_ACCESS_CONTROL_LIST: u8 = 0x82;

/// DER encoding of BOOLEAN TRUE.
const BOOLEAN_TRUE: u8 = 0xff;

/// DER encoding of BOOLEAN FALSE.
const BOOLEAN_FALSE: u8 = 0x00;

// GetNamedVariableListAttributesRequest

/// An MMS GetNamedVariableListAttributesRequest.
///
/// The request body is an `ObjectName` naming the variable list to describe:
/// domain-specific, vmd-specific or aa-specific.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetNamedVariableListAttributesRequest {
    /// Name of the variable list to describe.
    pub object_name: ObjectName,
}

impl GetNamedVariableListAttributesRequest {
    /// Builds a request for a domain-specific variable list.
    pub fn domain(domain_id: impl Into<String>, list_name: impl Into<String>) -> Self {
        Self {
            object_name: ObjectName::DomainSpecific {
                domain_id: domain_id.into(),
                item_id: list_name.into(),
            },
        }
    }

    /// Encodes the request, including the `0xac <len>` service wrapper.
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut inner = BytesMut::new();
        self.object_name.encode(&mut inner);

        buf.extend_from_slice(&[SERVICE_TAG_GET_NAMED_VARIABLE_LIST_ATTRS]);
        encode_length(inner.len(), buf);
        buf.extend_from_slice(&inner);
    }

    /// Decodes a request; `data` starts at the `0xac` byte.
    ///
    /// Bytes after the `ObjectName` are rejected rather than ignored, so a
    /// malformed request never resolves to a plausible list name.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        let inner = service_body(data)?;
        let (object_name, consumed) = ObjectName::decode(inner)?;
        if consumed != inner.len() {
            tracing::warn!(
                "getnamedvariablelistattributesrequest has {} trailing bytes after the objectname",
                inner.len() - consumed
            );
            return Err(MmsError::InvalidPdu);
        }
        Ok(Self { object_name })
    }
}

// GetNamedVariableListAttributesResponse

/// An MMS GetNamedVariableListAttributesResponse.
///
/// `list_of_variable` is in the order the server holds the members in, which is
/// the order a Read of the same list returns its access results in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetNamedVariableListAttributesResponse {
    /// mmsDeletable `[0]` IMPLICIT BOOLEAN: whether DeleteNamedVariableList may
    /// remove this list.
    pub mms_deletable: bool,
    /// listOfVariable `[1]`: the members, in order.
    pub list_of_variable: Vec<ListOfVariableEntry>,
}

impl GetNamedVariableListAttributesResponse {
    /// Encodes the response, including the `0xac <len>` service wrapper.
    ///
    /// The optional `accessControlList` field is never emitted.
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut inner = BytesMut::new();

        // mmsDeletable [0] IMPLICIT BOOLEAN
        let bool_byte = if self.mms_deletable {
            BOOLEAN_TRUE
        } else {
            BOOLEAN_FALSE
        };
        inner.extend_from_slice(&[TAG_MMS_DELETABLE, 0x01, bool_byte]);

        // listOfVariable [1] IMPLICIT SEQUENCE OF ListOfVariableSeq
        let mut list = BytesMut::new();
        for entry in &self.list_of_variable {
            encode_list_of_variable_seq(entry, &mut list);
        }
        inner.extend_from_slice(&[TAG_LIST_OF_VARIABLE]);
        encode_length(list.len(), &mut inner);
        inner.extend_from_slice(&list);

        buf.extend_from_slice(&[SERVICE_TAG_GET_NAMED_VARIABLE_LIST_ATTRS]);
        encode_length(inner.len(), buf);
        buf.extend_from_slice(&inner);
    }

    /// Decodes a response; `data` starts at the `0xac` byte.
    ///
    /// A missing `mmsDeletable` or `listOfVariable` is a truncated PDU; an
    /// `accessControlList` is accepted and discarded.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        let inner = service_body(data)?;
        decode_response_inner(inner)
    }
}

/// Decodes the response content: mmsDeletable, listOfVariable and the optional
/// accessControlList.
fn decode_response_inner(data: &[u8]) -> Result<GetNamedVariableListAttributesResponse, MmsError> {
    let mut pos = 0usize;
    let mut mms_deletable: Option<bool> = None;
    let mut list_of_variable: Option<Vec<ListOfVariableEntry>> = None;

    while pos < data.len() {
        let tag = data[pos];
        if pos + 1 >= data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let (len, hdr) = decode_length(&data[pos + 1..])?;
        let val_start = pos + 1 + hdr;
        if val_start + len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let val = &data[val_start..val_start + len];
        pos = val_start + len;

        match tag {
            TAG_MMS_DELETABLE => {
                if val.is_empty() {
                    return Err(MmsError::InvalidLength);
                }
                mms_deletable = Some(val[0] != 0);
            }
            TAG_LIST_OF_VARIABLE => {
                list_of_variable = Some(decode_list_of_variable(val)?);
            }
            TAG_ACCESS_CONTROL_LIST => {
                tracing::debug!(
                    "ignoring the getnamedvariablelistattributesresponse accesscontrollist field"
                );
            }
            other => {
                tracing::debug!(
                    "skipping unknown getnamedvariablelistattributesresponse tag 0x{:02X}",
                    other
                );
            }
        }
    }

    let mms_deletable = mms_deletable.ok_or(MmsError::TruncatedPdu)?;
    let list_of_variable = list_of_variable.ok_or(MmsError::TruncatedPdu)?;
    Ok(GetNamedVariableListAttributesResponse {
        mms_deletable,
        list_of_variable,
    })
}

/// Returns the content of the `0xac` service TLV; `data` starts at its tag.
fn service_body(data: &[u8]) -> Result<&[u8], MmsError> {
    if data.is_empty() {
        return Err(MmsError::TruncatedPdu);
    }
    if data[0] != SERVICE_TAG_GET_NAMED_VARIABLE_LIST_ATTRS {
        return Err(MmsError::InvalidTag {
            expected: SERVICE_TAG_GET_NAMED_VARIABLE_LIST_ATTRS,
            actual: data[0],
        });
    }
    let (len, hdr) = decode_length(&data[1..])?;
    let start = 1 + hdr;
    if start + len > data.len() {
        return Err(MmsError::TruncatedPdu);
    }
    Ok(&data[start..start + len])
}

// ConfirmedRequestPdu and ConfirmedResponsePdu wrappers

/// Encodes the request as a complete ConfirmedRequestPdu, outer `0xa0` tag
/// included.
pub fn encode_confirmed_get_named_variable_list_attrs_request(
    invoke_id: u32,
    req: &GetNamedVariableListAttributesRequest,
    buf: &mut BytesMut,
) {
    let mut inner = BytesMut::new();
    encode_invoke_id(invoke_id, &mut inner);
    req.encode(&mut inner);

    buf.extend_from_slice(&[0xa0]);
    encode_length(inner.len(), buf);
    buf.extend_from_slice(&inner);
}

/// Encodes the response as a complete ConfirmedResponsePdu, outer `0xa1` tag
/// included.
pub fn encode_confirmed_get_named_variable_list_attrs_response(
    invoke_id: u32,
    resp: &GetNamedVariableListAttributesResponse,
    buf: &mut BytesMut,
) {
    let mut inner = BytesMut::new();
    encode_invoke_id(invoke_id, &mut inner);
    resp.encode(&mut inner);

    buf.extend_from_slice(&[0xa1]);
    encode_length(inner.len(), buf);
    buf.extend_from_slice(&inner);
}

/// Decodes the request inside a ConfirmedRequestPdu; `data` starts at `0xa0`.
pub fn decode_confirmed_get_named_variable_list_attrs_request(
    data: &[u8],
) -> Result<(u32, GetNamedVariableListAttributesRequest), MmsError> {
    let (invoke_id, service_data) = decode_confirmed_pdu_inner(data, 0xa0)?;
    let req = GetNamedVariableListAttributesRequest::decode(service_data)?;
    Ok((invoke_id, req))
}

/// Decodes the response inside a ConfirmedResponsePdu; `data` starts at `0xa1`.
pub fn decode_confirmed_get_named_variable_list_attrs_response(
    data: &[u8],
) -> Result<(u32, GetNamedVariableListAttributesResponse), MmsError> {
    let (invoke_id, service_data) = decode_confirmed_pdu_inner(data, 0xa1)?;
    let resp = GetNamedVariableListAttributesResponse::decode(service_data)?;
    Ok((invoke_id, resp))
}

// Private helpers

/// Encodes an invokeID as a UNIVERSAL INTEGER, tag `0x02`.
fn encode_invoke_id(invoke_id: u32, buf: &mut BytesMut) {
    use super::common::encode_unsigned_int_minimal;
    let bytes = encode_unsigned_int_minimal(invoke_id as u64);
    buf.extend_from_slice(&[0x02]);
    encode_length(bytes.len(), buf);
    buf.extend_from_slice(&bytes);
}

/// Extracts the invokeID and service content of a ConfirmedRequest or
/// ConfirmedResponse PDU; `data` starts at the outer tag.
fn decode_confirmed_pdu_inner(data: &[u8], outer_tag: u8) -> Result<(u32, &[u8]), MmsError> {
    if data.is_empty() {
        return Err(MmsError::TruncatedPdu);
    }
    if data[0] != outer_tag {
        return Err(MmsError::InvalidTag {
            expected: outer_tag,
            actual: data[0],
        });
    }
    let (outer_len, outer_hdr) = decode_length(&data[1..])?;
    let inner_start = 1 + outer_hdr;
    if inner_start + outer_len > data.len() {
        return Err(MmsError::TruncatedPdu);
    }
    let inner = &data[inner_start..inner_start + outer_len];

    if inner.is_empty() || inner[0] != 0x02 {
        return Err(MmsError::TruncatedPdu);
    }
    let (id_len, id_hdr) = decode_length(&inner[1..])?;
    let id_start = 1 + id_hdr;
    if id_start + id_len > inner.len() {
        return Err(MmsError::TruncatedPdu);
    }
    let invoke_id = decode_u32_from_bytes(&inner[id_start..id_start + id_len])?;

    Ok((invoke_id, &inner[id_start + id_len..]))
}

/// Decodes 1 to 4 big-endian bytes into a `u32`.
fn decode_u32_from_bytes(data: &[u8]) -> Result<u32, MmsError> {
    if data.is_empty() || data.len() > 4 {
        return Err(MmsError::InvalidLength);
    }
    let mut val = 0u32;
    for &b in data {
        val = (val << 8) | (b as u32);
    }
    Ok(val)
}

// Unit tests
//
// Every expected byte string below is written by hand from the ASN.1 of
// ISO 9506-2, cross-checked against the tag assignment the asn1c-generated
// `GetNamedVariableListAttributesResponse` descriptor of the reference C
// implementation carries: mmsDeletable CONTEXT [0] IMPLICIT, listOfVariable
// CONTEXT [1] IMPLICIT SEQUENCE OF UNIVERSAL SEQUENCE, member
// variableSpecification.name CONTEXT [0] and alternateAccess CONTEXT [5]
// IMPLICIT, and the ConfirmedServiceRequest tag [12] EXPLICIT against the
// ConfirmedServiceResponse tag [12] IMPLICIT. No vector is produced by the
// encoder under test.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mms::pdu::common::AlternateAccess;

    // Request

    /// `0xac 0x16` over ObjectName domain-specific "IED1LD0" / "GGIO1$ds1":
    /// `0xa1 0x14 0x1a 0x07 <domain> 0x1a 0x09 <item>`.
    const REQUEST_DOMAIN_BYTES: &[u8] = &[
        0xac, 0x16, // getNamedVariableListAttributes [12] EXPLICIT, 22 bytes
        0xa1, 0x14, // ObjectName domain-specific, 20 bytes
        0x1a, 0x07, b'I', b'E', b'D', b'1', b'L', b'D', b'0', // domainId
        0x1a, 0x09, b'G', b'G', b'I', b'O', b'1', b'$', b'd', b's', b'1', // itemId
    ];

    #[test]
    fn request_encodes_byte_exact() {
        let req = GetNamedVariableListAttributesRequest::domain("IED1LD0", "GGIO1$ds1");
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        assert_eq!(&buf[..], REQUEST_DOMAIN_BYTES);
    }

    #[test]
    fn request_decodes_from_bytes() {
        let req = GetNamedVariableListAttributesRequest::decode(REQUEST_DOMAIN_BYTES).unwrap();
        assert_eq!(
            req.object_name,
            ObjectName::DomainSpecific {
                domain_id: "IED1LD0".to_string(),
                item_id: "GGIO1$ds1".to_string(),
            }
        );
    }

    #[test]
    fn request_wrong_service_tag_rejected() {
        let mut data = REQUEST_DOMAIN_BYTES.to_vec();
        data[0] = 0xad;
        assert!(matches!(
            GetNamedVariableListAttributesRequest::decode(&data),
            Err(MmsError::InvalidTag {
                expected: 0xac,
                actual: 0xad
            })
        ));
    }

    #[test]
    fn request_truncated_returns_err_without_panic() {
        for cut in 0..REQUEST_DOMAIN_BYTES.len() {
            let res = GetNamedVariableListAttributesRequest::decode(&REQUEST_DOMAIN_BYTES[..cut]);
            assert!(res.is_err(), "prefix of {cut} bytes must not decode");
        }
    }

    #[test]
    fn request_vmd_specific_round_trip() {
        let req = GetNamedVariableListAttributesRequest {
            object_name: ObjectName::VmdSpecific("vmdlist".to_string()),
        };
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        // 0xac <len> 0x80 0x07 "vmdlist"
        assert_eq!(
            &buf[..],
            &[0xac, 0x09, 0x80, 0x07, b'v', b'm', b'd', b'l', b'i', b's', b't']
        );
        let back = GetNamedVariableListAttributesRequest::decode(&buf).unwrap();
        assert_eq!(back, req);
    }

    // Response: one member, no alternateAccess, mmsDeletable false

    const RESPONSE_ONE_MEMBER_BYTES: &[u8] = &[
        0xac, 0x13, // getNamedVariableListAttributes [12] IMPLICIT SEQUENCE, 19 bytes
        0x80, 0x01, 0x00, // mmsDeletable [0] = FALSE
        0xa1, 0x0e, // listOfVariable [1], 14 bytes
        0x30, 0x0c, // ListOfVariableSeq, 12 bytes
        0xa0, 0x0a, // variableSpecification.name [0], 10 bytes
        0xa1, 0x08, // ObjectName domain-specific, 8 bytes
        0x1a, 0x02, b'D', b'1', // domainId
        0x1a, 0x02, b'V', b'1', // itemId
    ];

    fn member(domain: &str, item: &str) -> ListOfVariableEntry {
        ListOfVariableEntry::name(ObjectName::DomainSpecific {
            domain_id: domain.to_string(),
            item_id: item.to_string(),
        })
    }

    #[test]
    fn response_one_member_encodes_byte_exact() {
        let resp = GetNamedVariableListAttributesResponse {
            mms_deletable: false,
            list_of_variable: vec![member("D1", "V1")],
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        assert_eq!(&buf[..], RESPONSE_ONE_MEMBER_BYTES);
    }

    #[test]
    fn response_one_member_decodes_from_bytes() {
        let resp = GetNamedVariableListAttributesResponse::decode(RESPONSE_ONE_MEMBER_BYTES)
            .expect("decode");
        assert!(!resp.mms_deletable);
        assert_eq!(resp.list_of_variable.len(), 1);
        assert_eq!(resp.list_of_variable[0], member("D1", "V1"));
    }

    // Response: two members, the second with an index alternateAccess,
    // mmsDeletable true

    const RESPONSE_TWO_MEMBERS_BYTES: &[u8] = &[
        0xac, 0x26, // [12] IMPLICIT SEQUENCE, 38 bytes
        0x80, 0x01, 0xff, // mmsDeletable [0] = TRUE
        0xa1, 0x21, // listOfVariable [1], 33 bytes
        // member 1: D1 / V1, no alternateAccess
        0x30, 0x0c, 0xa0, 0x0a, 0xa1, 0x08, 0x1a, 0x02, b'D', b'1', 0x1a, 0x02, b'V', b'1',
        // member 2: D1 / V2 with selectAccess.index 3
        0x30, 0x11, // ListOfVariableSeq, 17 bytes
        0xa0, 0x0a, 0xa1, 0x08, 0x1a, 0x02, b'D', b'1', 0x1a, 0x02, b'V', b'2', 0xa5,
        0x03, // alternateAccess [5] IMPLICIT SEQUENCE OF, 3 bytes
        0x82, 0x01, 0x03, // selectAccess.index [2] IMPLICIT Unsigned32 = 3
    ];

    fn two_member_response() -> GetNamedVariableListAttributesResponse {
        GetNamedVariableListAttributesResponse {
            mms_deletable: true,
            list_of_variable: vec![
                member("D1", "V1"),
                ListOfVariableEntry::with_alt_access(
                    ObjectName::DomainSpecific {
                        domain_id: "D1".to_string(),
                        item_id: "V2".to_string(),
                    },
                    AlternateAccess::index(3),
                ),
            ],
        }
    }

    #[test]
    fn response_two_members_encodes_byte_exact() {
        let mut buf = BytesMut::new();
        two_member_response().encode(&mut buf);
        assert_eq!(&buf[..], RESPONSE_TWO_MEMBERS_BYTES);
    }

    #[test]
    fn response_two_members_decodes_from_bytes() {
        let resp = GetNamedVariableListAttributesResponse::decode(RESPONSE_TWO_MEMBERS_BYTES)
            .expect("decode");
        assert_eq!(resp, two_member_response());
        // Order is part of the contract: member order equals data set order.
        assert_eq!(
            resp.list_of_variable[0].name,
            ObjectName::DomainSpecific {
                domain_id: "D1".to_string(),
                item_id: "V1".to_string(),
            }
        );
        assert!(resp.list_of_variable[0].alt_access.is_none());
        assert_eq!(
            resp.list_of_variable[1].alt_access,
            Some(AlternateAccess::index(3))
        );
    }

    #[test]
    fn response_mms_deletable_true_and_false_differ_by_one_byte() {
        let mut deletable = BytesMut::new();
        GetNamedVariableListAttributesResponse {
            mms_deletable: true,
            list_of_variable: vec![member("D1", "V1")],
        }
        .encode(&mut deletable);

        let mut fixed = BytesMut::new();
        GetNamedVariableListAttributesResponse {
            mms_deletable: false,
            list_of_variable: vec![member("D1", "V1")],
        }
        .encode(&mut fixed);

        assert_eq!(deletable.len(), fixed.len());
        assert_eq!(deletable[4], BOOLEAN_TRUE);
        assert_eq!(fixed[4], BOOLEAN_FALSE);
        assert_eq!(&deletable[..4], &fixed[..4]);
        assert_eq!(&deletable[5..], &fixed[5..]);
    }

    #[test]
    fn response_with_access_control_list_is_accepted_and_ignored() {
        // RESPONSE_ONE_MEMBER_BYTES with `0x82 0x03 "ACL"` appended inside the
        // service TLV, whose length grows from 0x13 to 0x18.
        let mut data = RESPONSE_ONE_MEMBER_BYTES.to_vec();
        data[1] = 0x18;
        data.extend_from_slice(&[0x82, 0x03, b'A', b'C', b'L']);

        let resp = GetNamedVariableListAttributesResponse::decode(&data).expect("decode");
        assert!(!resp.mms_deletable);
        assert_eq!(resp.list_of_variable, vec![member("D1", "V1")]);

        // Re-encoding drops the field.
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        assert_eq!(&buf[..], RESPONSE_ONE_MEMBER_BYTES);
    }

    #[test]
    fn response_missing_list_of_variable_is_truncated() {
        // Only mmsDeletable, no listOfVariable.
        let data = &[0xac, 0x03, 0x80, 0x01, 0x00];
        assert!(matches!(
            GetNamedVariableListAttributesResponse::decode(data),
            Err(MmsError::TruncatedPdu)
        ));
    }

    #[test]
    fn response_empty_list_of_variable_decodes_to_no_members() {
        let data = &[0xac, 0x05, 0x80, 0x01, 0x00, 0xa1, 0x00];
        let resp = GetNamedVariableListAttributesResponse::decode(data).expect("decode");
        assert!(resp.list_of_variable.is_empty());
    }

    #[test]
    fn response_truncated_returns_err_without_panic() {
        for cut in 0..RESPONSE_TWO_MEMBERS_BYTES.len() {
            let res =
                GetNamedVariableListAttributesResponse::decode(&RESPONSE_TWO_MEMBERS_BYTES[..cut]);
            assert!(res.is_err(), "prefix of {cut} bytes must not decode");
        }
    }

    #[test]
    fn response_member_with_wrong_sequence_tag_rejected() {
        let mut data = RESPONSE_ONE_MEMBER_BYTES.to_vec();
        // The ListOfVariableSeq tag must be UNIVERSAL SEQUENCE.
        data[7] = 0x31;
        assert!(matches!(
            GetNamedVariableListAttributesResponse::decode(&data),
            Err(MmsError::InvalidTag {
                expected: 0x30,
                actual: 0x31
            })
        ));
    }

    // Confirmed PDU wrappers

    #[test]
    fn confirmed_request_wrapper_byte_exact() {
        let req = GetNamedVariableListAttributesRequest::domain("IED1LD0", "GGIO1$ds1");
        let mut buf = BytesMut::new();
        encode_confirmed_get_named_variable_list_attrs_request(1, &req, &mut buf);

        let mut expected = vec![0xa0, 0x1b, 0x02, 0x01, 0x01];
        expected.extend_from_slice(REQUEST_DOMAIN_BYTES);
        assert_eq!(&buf[..], &expected[..]);

        let (id, back) = decode_confirmed_get_named_variable_list_attrs_request(&buf).unwrap();
        assert_eq!(id, 1);
        assert_eq!(back, req);
    }

    #[test]
    fn confirmed_response_wrapper_byte_exact() {
        let resp = GetNamedVariableListAttributesResponse {
            mms_deletable: false,
            list_of_variable: vec![member("D1", "V1")],
        };
        let mut buf = BytesMut::new();
        encode_confirmed_get_named_variable_list_attrs_response(7, &resp, &mut buf);

        let mut expected = vec![0xa1, 0x18, 0x02, 0x01, 0x07];
        expected.extend_from_slice(RESPONSE_ONE_MEMBER_BYTES);
        assert_eq!(&buf[..], &expected[..]);

        let (id, back) = decode_confirmed_get_named_variable_list_attrs_response(&buf).unwrap();
        assert_eq!(id, 7);
        assert_eq!(back, resp);
    }

    #[test]
    fn confirmed_response_with_request_outer_tag_rejected() {
        let resp = GetNamedVariableListAttributesResponse {
            mms_deletable: false,
            list_of_variable: vec![member("D1", "V1")],
        };
        let mut buf = BytesMut::new();
        encode_confirmed_get_named_variable_list_attrs_response(7, &resp, &mut buf);
        assert!(matches!(
            decode_confirmed_get_named_variable_list_attrs_request(&buf),
            Err(MmsError::InvalidTag { .. })
        ));
    }
}
