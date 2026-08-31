//! MMS GetVariableAccessAttributes request and response PDUs, per ISO 9506-2.
//!
//! ## Wire format
//!
//! Request, ConfirmedServiceRequest CHOICE `[6]` EXPLICIT:
//! ```text
//! 0xa0 <len>          -- confirmedRequestPdu [0] IMPLICIT SEQUENCE
//!   0x02 <len> <id>   -- invokeID INTEGER
//!   0xa6 <len>        -- getVariableAccessAttributes [6] EXPLICIT
//!     0xa0 <len>      -- name [0] EXPLICIT, the request CHOICE
//!       <ObjectName>  -- domain-specific, vmd-specific or aa-specific
//! ```
//!
//! Response, ConfirmedServiceResponse CHOICE `[6]` IMPLICIT:
//! ```text
//! 0xa1 <len>          -- confirmedResponsePdu [1] IMPLICIT SEQUENCE
//!   0x02 <len> <id>   -- invokeID INTEGER
//!   0xa6 <len>        -- getVariableAccessAttributes [6] IMPLICIT SEQUENCE
//!     0x80 <1> 0x00   -- mmsDeletable [0] IMPLICIT BOOLEAN
//!     (0xa1 ... )     -- address [1] OPTIONAL, unused and skipped when decoding
//!     0xa2 <len>      -- typeSpecification [2] EXPLICIT
//!       <TypeSpec>    -- TypeSpecification CHOICE
//! ```
//!
//! The `[6]` tag is EXPLICIT in the request and IMPLICIT in the response, so the two
//! wrappers are not symmetric.
//!
//! ## Supported alternatives
//!
//! - The request CHOICE has a name `[0]` and an address `[1]` alternative. Only name is
//!   supported; an address request returns an error.
//! - mmsDeletable is decoded from the wire and encoded from the field value.

use super::super::error::MmsError;
use super::common::{effective_nesting_cap, ObjectName};
use super::initiate::{decode_length, encode_length};
use super::type_specification::{TypeSpecification, MAX_TYPE_SPEC_DEPTH};
use bytes::BytesMut;

// Tag constants

/// Service tag of GetVariableAccessAttributes in the ConfirmedService CHOICE.
///
/// In a request `0xa6` is CONTEXT `[6]` EXPLICIT CONSTRUCTED, with the wrapper added
/// by the caller; in a response it is CONTEXT `[6]` IMPLICIT CONSTRUCTED SEQUENCE.
pub const SERVICE_TAG_GET_VAR_ACCESS_ATTRS: u8 = 0xa6;

// GetVariableAccessAttributesRequest

/// An MMS GetVariableAccessAttributesRequest.
///
/// Only the name `[0]` alternative is supported, naming a domain-specific,
/// vmd-specific or aa-specific object; an address `[1]` request returns an error.
///
/// ## VMD scope
///
/// `ObjectName::VmdSpecific(item_id)` selects the VMD scope, with no domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetVariableAccessAttributesRequest {
    /// Name of the object to query.
    pub object_name: ObjectName,
}

impl GetVariableAccessAttributesRequest {
    /// Encodes the request, including the `0xa6 <len>` service wrapper.
    ///
    /// Wire format, where `[6]` is EXPLICIT on the request side:
    /// ```text
    /// 0xa6 <len>    -- [6] EXPLICIT service wrapper
    ///   0xa0 <len>  -- name [0] EXPLICIT, the CHOICE name alternative
    ///     <ObjectName>
    /// ```
    pub fn encode(&self, buf: &mut BytesMut) {
        // name [0] EXPLICIT: 0xa0 <len> <ObjectName>
        let mut obj_buf = BytesMut::new();
        self.object_name.encode(&mut obj_buf);
        let mut name_wrapper = BytesMut::new();
        name_wrapper.extend_from_slice(&[0xa0]);
        encode_length(obj_buf.len(), &mut name_wrapper);
        name_wrapper.extend_from_slice(&obj_buf);

        // service tag [6] EXPLICIT wrapper
        buf.extend_from_slice(&[SERVICE_TAG_GET_VAR_ACCESS_ATTRS]);
        encode_length(name_wrapper.len(), buf);
        buf.extend_from_slice(&name_wrapper);
    }

    /// Decodes a request; `data` starts at the `0xa6` byte.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        if data[0] != SERVICE_TAG_GET_VAR_ACCESS_ATTRS {
            return Err(MmsError::InvalidTag {
                expected: SERVICE_TAG_GET_VAR_ACCESS_ATTRS,
                actual: data[0],
            });
        }
        let (outer_len, outer_hdr) = decode_length(&data[1..])?;
        let inner_start = 1 + outer_hdr;
        if inner_start + outer_len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let inner = &data[inner_start..inner_start + outer_len];
        decode_request_inner(inner)
    }
}

/// Decodes the request content, the name `[0]` or address `[1]` CHOICE.
fn decode_request_inner(data: &[u8]) -> Result<GetVariableAccessAttributesRequest, MmsError> {
    if data.is_empty() {
        return Err(MmsError::TruncatedPdu);
    }
    let choice_tag = data[0];
    let (choice_len, choice_hdr) = decode_length(&data[1..])?;
    let choice_val_start = 1 + choice_hdr;
    if choice_val_start + choice_len > data.len() {
        return Err(MmsError::TruncatedPdu);
    }
    let choice_val = &data[choice_val_start..choice_val_start + choice_len];

    match choice_tag {
        // name [0] EXPLICIT, whose content is an ObjectName
        0xa0 => {
            let (object_name, _) = ObjectName::decode(choice_val)?;
            Ok(GetVariableAccessAttributesRequest { object_name })
        }
        // address [1] is not supported
        0xa1 => {
            tracing::warn!("getvariableaccessattributes address [1] requests are not supported");
            Err(MmsError::InvalidPdu)
        }
        other => {
            tracing::warn!(
                "unknown getvariableaccessattributesrequest choice tag 0x{:02X}, rejecting",
                other
            );
            Err(MmsError::InvalidPdu)
        }
    }
}

// GetVariableAccessAttributesResponse

/// An MMS GetVariableAccessAttributesResponse.
///
/// ## mmsDeletable
///
/// Decoded from the wire and encoded from the field value.
///
/// ## address
///
/// The `[1]` address field is skipped when decoding and not retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetVariableAccessAttributesResponse {
    /// mmsDeletable `[0]` IMPLICIT BOOLEAN.
    pub mms_deletable: bool,
    /// typeSpecification `[2]` EXPLICIT TypeSpecification.
    pub type_specification: TypeSpecification,
}

impl GetVariableAccessAttributesResponse {
    /// Encodes the response, including the `0xa6 <len>` service wrapper.
    ///
    /// Wire format, where `[6]` is an IMPLICIT SEQUENCE on the response side:
    /// ```text
    /// 0xa6 <len>          -- [6] IMPLICIT SEQUENCE
    ///   0x80 0x01 0x00    -- mmsDeletable [0] IMPLICIT BOOLEAN
    ///   0xa2 <len>        -- typeSpecification [2] EXPLICIT
    ///     <TypeSpec>
    /// ```
    pub fn encode(&self, buf: &mut BytesMut) -> Result<(), MmsError> {
        let mut inner = BytesMut::new();

        // mmsDeletable [0] IMPLICIT BOOLEAN
        let bool_byte: u8 = if self.mms_deletable { 0xff } else { 0x00 };
        inner.extend_from_slice(&[0x80, 0x01, bool_byte]);

        // typeSpecification [2] EXPLICIT TypeSpecification
        let mut ts_buf = BytesMut::new();
        self.type_specification.encode(&mut ts_buf)?;
        inner.extend_from_slice(&[0xa2]);
        encode_length(ts_buf.len(), &mut inner);
        inner.extend_from_slice(&ts_buf);

        buf.extend_from_slice(&[SERVICE_TAG_GET_VAR_ACCESS_ATTRS]);
        encode_length(inner.len(), buf);
        buf.extend_from_slice(&inner);
        Ok(())
    }

    /// Decodes a response; `data` starts at the `0xa6` byte.
    ///
    /// The local ceiling `MAX_TYPE_SPEC_DEPTH` bounds TypeSpecification recursion.
    /// Use `decode_with_negotiated_cap` to apply a negotiated nesting level as well.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        Self::decode_inner_from_service_tag(data, MAX_TYPE_SPEC_DEPTH)
    }

    /// Decodes a response under the negotiated `dataStructureNestingLevel`.
    ///
    /// The effective ceiling is the smaller of `MAX_TYPE_SPEC_DEPTH` and the
    /// negotiated value; `None` falls back to the local ceiling, which is the case
    /// before negotiation completes.
    pub fn decode_with_negotiated_cap(
        data: &[u8],
        negotiated: Option<u8>,
    ) -> Result<Self, MmsError> {
        let max_depth = effective_nesting_cap(MAX_TYPE_SPEC_DEPTH, negotiated);
        Self::decode_inner_from_service_tag(data, max_depth)
    }

    fn decode_inner_from_service_tag(data: &[u8], max_depth: u8) -> Result<Self, MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        if data[0] != SERVICE_TAG_GET_VAR_ACCESS_ATTRS {
            return Err(MmsError::InvalidTag {
                expected: SERVICE_TAG_GET_VAR_ACCESS_ATTRS,
                actual: data[0],
            });
        }
        let (outer_len, outer_hdr) = decode_length(&data[1..])?;
        let inner_start = 1 + outer_hdr;
        if inner_start + outer_len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let inner = &data[inner_start..inner_start + outer_len];
        decode_response_inner(inner, max_depth)
    }
}

/// Decodes the response content: mmsDeletable and typeSpecification.
///
/// `max_depth` is the effective ceiling for TypeSpecification recursion.
fn decode_response_inner(
    data: &[u8],
    max_depth: u8,
) -> Result<GetVariableAccessAttributesResponse, MmsError> {
    let mut pos = 0usize;
    let mut mms_deletable: Option<bool> = None;
    let mut type_specification: Option<TypeSpecification> = None;

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
            // mmsDeletable [0] IMPLICIT BOOLEAN
            0x80 => {
                if val.is_empty() {
                    return Err(MmsError::InvalidLength);
                }
                mms_deletable = Some(val[0] != 0);
            }
            // address [1] OPTIONAL, unused and skipped
            0xa1 => {
                tracing::debug!(
                    "ignoring the getvariableaccessattributesresponse address [1] field"
                );
            }
            // typeSpecification [2] EXPLICIT TypeSpecification
            // typeSpecification, decoded under the effective ceiling
            0xa2 => {
                let (ts, _) = TypeSpecification::decode_with_max(val, max_depth)?;
                type_specification = Some(ts);
            }
            other => {
                tracing::debug!(
                    "skipping unknown getvariableaccessattributesresponse tag 0x{:02X}",
                    other
                );
            }
        }
    }

    let mms_deletable = mms_deletable.ok_or(MmsError::TruncatedPdu)?;
    let type_specification = type_specification.ok_or(MmsError::TruncatedPdu)?;
    Ok(GetVariableAccessAttributesResponse {
        mms_deletable,
        type_specification,
    })
}

// ConfirmedRequestPdu and ConfirmedResponsePdu wrappers

/// Encodes the request as a complete ConfirmedRequestPdu, outer `0xa0` tag included.
///
/// Wire format:
/// ```text
/// 0xa0 <len>          -- confirmedRequestPdu [0]
///   0x02 <len> <id>   -- invokeID
///   0xa6 <len>        -- GetVariableAccessAttributesRequest, [6] EXPLICIT
/// ```
pub fn encode_confirmed_get_var_access_attrs_request(
    invoke_id: u32,
    req: &GetVariableAccessAttributesRequest,
    buf: &mut BytesMut,
) {
    let mut inner = BytesMut::new();
    encode_invoke_id(invoke_id, &mut inner);
    req.encode(&mut inner);

    buf.extend_from_slice(&[0xa0]);
    encode_length(inner.len(), buf);
    buf.extend_from_slice(&inner);
}

/// Encodes the response as a complete ConfirmedResponsePdu, outer `0xa1` tag included.
pub fn encode_confirmed_get_var_access_attrs_response(
    invoke_id: u32,
    resp: &GetVariableAccessAttributesResponse,
    buf: &mut BytesMut,
) -> Result<(), MmsError> {
    let mut inner = BytesMut::new();
    encode_invoke_id(invoke_id, &mut inner);
    resp.encode(&mut inner)?;

    buf.extend_from_slice(&[0xa1]);
    encode_length(inner.len(), buf);
    buf.extend_from_slice(&inner);
    Ok(())
}

/// Decodes the request inside a ConfirmedRequestPdu; `data` starts at `0xa0`.
pub fn decode_confirmed_get_var_access_attrs_request(
    data: &[u8],
) -> Result<(u32, GetVariableAccessAttributesRequest), MmsError> {
    let (invoke_id, service_data) = decode_confirmed_pdu_inner(data, 0xa0)?;
    let req = GetVariableAccessAttributesRequest::decode(service_data)?;
    Ok((invoke_id, req))
}

/// Decodes the response inside a ConfirmedResponsePdu; `data` starts at `0xa1`.
///
/// The local ceiling bounds TypeSpecification recursion.
pub fn decode_confirmed_get_var_access_attrs_response(
    data: &[u8],
) -> Result<(u32, GetVariableAccessAttributesResponse), MmsError> {
    let (invoke_id, service_data) = decode_confirmed_pdu_inner(data, 0xa1)?;
    let resp = GetVariableAccessAttributesResponse::decode(service_data)?;
    Ok((invoke_id, resp))
}

/// Decodes the response inside a ConfirmedResponsePdu under the negotiated ceiling.
///
/// The effective ceiling is the smaller of `MAX_TYPE_SPEC_DEPTH` and the negotiated
/// value.
pub fn decode_confirmed_get_var_access_attrs_response_with_negotiated_cap(
    data: &[u8],
    negotiated: Option<u8>,
) -> Result<(u32, GetVariableAccessAttributesResponse), MmsError> {
    let (invoke_id, service_data) = decode_confirmed_pdu_inner(data, 0xa1)?;
    let resp =
        GetVariableAccessAttributesResponse::decode_with_negotiated_cap(service_data, negotiated)?;
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

/// Extracts the invokeID and content of a ConfirmedRequest or ConfirmedResponse
/// PDU; `data` starts at the outer tag.
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
    let id_val = &inner[id_start..id_start + id_len];
    let invoke_id = decode_u32_from_bytes(id_val)?;

    let service_start = id_start + id_len;
    Ok((invoke_id, &inner[service_start..]))
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

#[cfg(test)]
mod tests {
    use super::super::type_specification::{StructComponent, TypeSpecification};
    use super::*;

    // GetVariableAccessAttributesRequest round trips

    #[test]
    fn request_domain_specific_roundtrip() {
        let req = GetVariableAccessAttributesRequest {
            object_name: ObjectName::DomainSpecific {
                domain_id: "LDCB".to_owned(),
                item_id: "CSWI1$ST$Pos".to_owned(),
            },
        };
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let decoded = GetVariableAccessAttributesRequest::decode(&buf).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_vmd_specific_roundtrip() {
        // VMD scope, so no domain is named
        let req = GetVariableAccessAttributesRequest {
            object_name: ObjectName::VmdSpecific("VAR".to_owned()),
        };
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let decoded = GetVariableAccessAttributesRequest::decode(&buf).unwrap();
        assert_eq!(decoded, req);
    }

    // GetVariableAccessAttributesResponse round trips

    #[test]
    fn response_simple_boolean_type_roundtrip() {
        let resp = GetVariableAccessAttributesResponse {
            mms_deletable: false,
            type_specification: TypeSpecification::Boolean,
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf).unwrap();
        let decoded = GetVariableAccessAttributesResponse::decode(&buf).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn response_float32_type_roundtrip() {
        // float32: formatwidth 32, exponentwidth 8
        let resp = GetVariableAccessAttributesResponse {
            mms_deletable: false,
            type_specification: TypeSpecification::FloatingPoint {
                format_width: 32,
                exponent_width: 8,
            },
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf).unwrap();
        let decoded = GetVariableAccessAttributesResponse::decode(&buf).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn response_complex_structure_roundtrip() {
        // a typical IEC 61850 single point status: stVal, q and t
        let resp = GetVariableAccessAttributesResponse {
            mms_deletable: false,
            type_specification: TypeSpecification::Structure {
                components: vec![
                    StructComponent {
                        name: "stVal".to_owned(),
                        type_spec: TypeSpecification::Boolean,
                    },
                    StructComponent {
                        name: "q".to_owned(),
                        type_spec: TypeSpecification::BitString { bits: 13 },
                    },
                    StructComponent {
                        name: "t".to_owned(),
                        type_spec: TypeSpecification::UtcTime,
                    },
                ],
            },
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf).unwrap();
        let decoded = GetVariableAccessAttributesResponse::decode(&buf).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn response_mms_deletable_true_roundtrip() {
        // mmsDeletable true must survive decoding
        let resp = GetVariableAccessAttributesResponse {
            mms_deletable: true,
            type_specification: TypeSpecification::Integer { width_bits: 32 },
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf).unwrap();
        let decoded = GetVariableAccessAttributesResponse::decode(&buf).unwrap();
        assert!(decoded.mms_deletable);
        assert_eq!(decoded.type_specification, resp.type_specification);
    }

    // ConfirmedRequestPdu and ConfirmedResponsePdu wrappers

    #[test]
    fn confirmed_request_domain_specific_roundtrip() {
        let req = GetVariableAccessAttributesRequest {
            object_name: ObjectName::DomainSpecific {
                domain_id: "TESTLD".to_owned(),
                item_id: "GGIO1$ST$Ind$stVal".to_owned(),
            },
        };
        let mut buf = BytesMut::new();
        encode_confirmed_get_var_access_attrs_request(7, &req, &mut buf);
        assert_eq!(
            buf[0], 0xa0,
            "the outer tag must be 0xa0, a ConfirmedRequestPdu"
        );
        let (invoke_id, decoded_req) = decode_confirmed_get_var_access_attrs_request(&buf).unwrap();
        assert_eq!(invoke_id, 7);
        assert_eq!(decoded_req, req);
    }

    #[test]
    fn confirmed_response_complex_type_spec_roundtrip() {
        // a response carrying an array of structures
        let resp = GetVariableAccessAttributesResponse {
            mms_deletable: false,
            type_specification: TypeSpecification::Array {
                element_count: 3,
                element_type: Box::new(TypeSpecification::Structure {
                    components: vec![
                        StructComponent {
                            name: "val".to_owned(),
                            type_spec: TypeSpecification::FloatingPoint {
                                format_width: 32,
                                exponent_width: 8,
                            },
                        },
                        StructComponent {
                            name: "t".to_owned(),
                            type_spec: TypeSpecification::UtcTime,
                        },
                    ],
                }),
            },
        };
        let mut buf = BytesMut::new();
        encode_confirmed_get_var_access_attrs_response(42, &resp, &mut buf).unwrap();
        assert_eq!(
            buf[0], 0xa1,
            "the outer tag must be 0xa1, a ConfirmedResponsePdu"
        );
        let (invoke_id, decoded_resp) =
            decode_confirmed_get_var_access_attrs_response(&buf).unwrap();
        assert_eq!(invoke_id, 42);
        assert_eq!(decoded_resp, resp);
    }

    // byte-exact encoding

    /// A response with mmsDeletable false and a Boolean typeSpecification.
    ///
    /// ```text
    /// 0xa6 0x07             -- [6] IMPLICIT SEQUENCE, len=7
    ///   0x80 0x01 0x00      -- mmsDeletable [0] IMPLICIT BOOLEAN false
    ///   0xa2 0x02           -- typeSpecification [2] EXPLICIT, len=2
    ///     0x83 0x00         -- TypeSpec::Boolean
    /// ```
    ///
    /// The content is 7 bytes: 3 for mmsDeletable plus 4 for typeSpecification.
    #[test]
    fn response_boolean_type_byte_exact() {
        let resp = GetVariableAccessAttributesResponse {
            mms_deletable: false,
            type_specification: TypeSpecification::Boolean,
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf).unwrap();
        let expected: &[u8] = &[
            0xa6, 0x07, // [6] IMPLICIT SEQUENCE, len=7
            0x80, 0x01, 0x00, // mmsDeletable false
            0xa2, 0x02, // typeSpecification [2] EXPLICIT, len=2
            0x83, 0x00, // TypeSpec::Boolean
        ];
        assert_eq!(
            &buf[..],
            expected,
            "encoding is not byte exact: got {:02X?}, expected {:02X?}",
            &buf[..],
            expected
        );
    }

    // malformed input and error paths

    #[test]
    fn request_wrong_tag_err() {
        // 0xa5 instead of 0xa6
        let data = [0xa5u8, 0x00];
        let result = GetVariableAccessAttributesRequest::decode(&data);
        assert!(matches!(
            result,
            Err(MmsError::InvalidTag {
                expected: 0xa6,
                actual: 0xa5
            })
        ));
    }

    #[test]
    fn request_address_variant_err() {
        // the address [1] alternative, tag 0xa1, is not supported
        // wire: 0xa6 <len> 0xa1 <len> <address bytes>
        let inner: &[u8] = &[0xa1, 0x00]; // an empty address [1]
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0xa6]);
        buf.extend_from_slice(&[inner.len() as u8]);
        buf.extend_from_slice(inner);
        let result = GetVariableAccessAttributesRequest::decode(&buf);
        assert!(
            matches!(result, Err(MmsError::InvalidPdu)),
            "an address request must return Err(InvalidPdu), got: {:?}",
            result
        );
    }

    #[test]
    fn response_missing_type_spec_err() {
        // mmsDeletable alone, with no typeSpecification
        // wire: 0xa6 0x03 0x80 0x01 0x00
        let data: &[u8] = &[0xa6, 0x03, 0x80, 0x01, 0x00];
        let result = GetVariableAccessAttributesResponse::decode(data);
        assert!(
            result.is_err(),
            "a missing typeSpecification must return an error, got: {:?}",
            result
        );
    }

    #[test]
    fn request_empty_returns_truncated() {
        let result = GetVariableAccessAttributesRequest::decode(&[]);
        assert!(matches!(result, Err(MmsError::TruncatedPdu)));
    }

    #[test]
    fn response_empty_returns_truncated() {
        let result = GetVariableAccessAttributesResponse::decode(&[]);
        assert!(matches!(result, Err(MmsError::TruncatedPdu)));
    }

    #[test]
    fn request_truncated_pdu_err() {
        // 0xa6 0x10 declares 16 bytes with none present
        let data = [0xa6u8, 0x10];
        let result = GetVariableAccessAttributesRequest::decode(&data);
        assert!(matches!(result, Err(MmsError::TruncatedPdu)));
    }

    // decode_with_negotiated_cap

    /// Builds a response whose typeSpecification nests `nest_depth` arrays.
    fn build_response_with_nested_typespec(nest_depth: usize) -> BytesMut {
        fn push_len(out: &mut Vec<u8>, len: usize) {
            if len < 128 {
                out.push(len as u8);
            } else if len <= 0xff {
                out.push(0x81);
                out.push(len as u8);
            } else {
                out.push(0x82);
                out.push((len >> 8) as u8);
                out.push((len & 0xff) as u8);
            }
        }
        fn make_nested(depth: usize) -> Vec<u8> {
            if depth == 0 {
                return vec![0x83, 0x00]; // TypeSpec::Boolean
            }
            let inner = make_nested(depth - 1);
            // array elementType TLV
            let mut et_tlv = vec![0xa2u8];
            push_len(&mut et_tlv, inner.len());
            et_tlv.extend_from_slice(&inner);
            let count_part: &[u8] = &[0x81, 0x01, 0x01];
            let total_inner = count_part.len() + et_tlv.len();
            let mut result = vec![0xa1u8]; // array tag
            push_len(&mut result, total_inner);
            result.extend_from_slice(count_part);
            result.extend_from_slice(&et_tlv);
            result
        }
        let ts_bytes = make_nested(nest_depth);
        // Response body = 0x80 0x01 0x00 (mmsDeletable) + 0xa2 <len> <ts>
        let mut inner = Vec::new();
        inner.extend_from_slice(&[0x80, 0x01, 0x00]); // mmsDeletable=false
        inner.push(0xa2u8); // typeSpecification [2] EXPLICIT
        push_len(&mut inner, ts_bytes.len());
        inner.extend_from_slice(&ts_bytes);
        // 0xa6 <len> <inner>, using the length writer that handles long forms
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[SERVICE_TAG_GET_VAR_ACCESS_ATTRS]);
        let mut len_bytes = Vec::new();
        push_len(&mut len_bytes, inner.len());
        buf.extend_from_slice(&len_bytes);
        buf.extend_from_slice(&inner);
        buf
    }

    /// With a negotiated ceiling of 5, six nested levels must fail.
    #[test]
    fn response_negotiated_cap_lower_clamps_typespec_depth() {
        let buf = build_response_with_nested_typespec(6);
        let result = GetVariableAccessAttributesResponse::decode_with_negotiated_cap(&buf, Some(5));
        assert!(
            matches!(result, Err(MmsError::NestingLevelExceeded { .. })),
            "with a negotiated cap of 5, six levels must fail, got: {:?}",
            result
        );
    }

    /// A negotiated ceiling of 100 clamps to the local 32.
    ///
    /// The clamp itself is checked through `effective_nesting_cap`, and the depth
    /// guard through a six-level response, since a 33-level response exceeds the
    /// short-form length this helper builds.
    #[test]
    fn response_negotiated_higher_than_local_still_clamps() {
        use crate::mms::pdu::common::effective_nesting_cap;
        use crate::mms::pdu::type_specification::MAX_TYPE_SPEC_DEPTH;
        // the effective cap itself
        let effective = effective_nesting_cap(MAX_TYPE_SPEC_DEPTH, Some(100));
        assert_eq!(
            effective, 32,
            "a negotiated 100 above the local 32 must clamp to 32"
        );
        // six levels against a negotiated cap of 5 exercise the clamp to the smaller
        // value
        let buf = build_response_with_nested_typespec(6);
        // negotiated 5 gives an effective cap of 5, so six levels must fail
        let result = GetVariableAccessAttributesResponse::decode_with_negotiated_cap(&buf, Some(5));
        assert!(
            matches!(result, Err(MmsError::NestingLevelExceeded { .. })),
            "with a negotiated cap of 5 below the local 32, six levels must fail, got: {:?}",
            result
        );
        // the clamp to the local ceiling is checked once more through the helper;
        // the depth guard itself is covered by the type_specification tests
        assert_eq!(
            effective_nesting_cap(MAX_TYPE_SPEC_DEPTH, Some(255)),
            32,
            "a negotiated 255 must still clamp to the local 32"
        );
    }

    /// Without a negotiated value the local ceiling applies, so one level decodes.
    #[test]
    fn response_negotiated_none_ok_for_shallow() {
        let buf = build_response_with_nested_typespec(1);
        let result = GetVariableAccessAttributesResponse::decode_with_negotiated_cap(&buf, None);
        assert!(
            result.is_ok(),
            "without a negotiated value, one level must decode, got: {:?}",
            result
        );
    }

    /// The negotiated-cap entry point wires through to the response decoder.
    #[test]
    fn confirmed_response_with_negotiated_cap_roundtrip() {
        let resp = GetVariableAccessAttributesResponse {
            mms_deletable: false,
            type_specification: TypeSpecification::Boolean,
        };
        let mut buf = BytesMut::new();
        encode_confirmed_get_var_access_attrs_response(10, &resp, &mut buf).unwrap();
        let (invoke_id, decoded) =
            decode_confirmed_get_var_access_attrs_response_with_negotiated_cap(&buf, None).unwrap();
        assert_eq!(invoke_id, 10);
        assert_eq!(decoded, resp);
    }
}
