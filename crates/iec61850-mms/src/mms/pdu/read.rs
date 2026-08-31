//! MMS Read request and response PDUs.
//!
//! ## Wire format
//!
//! Inside the `ConfirmedServiceRequest` CHOICE:
//! - read is CONTEXT `[4]` IMPLICIT CONSTRUCTED, tag `0xa4`
//!
//! A ReadRequest inside a ConfirmedRequestPdu:
//! ```text
//! 0xa0 <len>           -- MmsPdu [0] confirmedRequestPdu
//!   0x02 <len> <id>    -- invokeID INTEGER
//!   0xa4 <len>         -- read [4] IMPLICIT, a ReadRequest SEQUENCE
//!     [0x80 0x01 0x01] -- specificationWithResult [0] = TRUE, OPTIONAL
//!     0xa1 <len>       -- variableAccessSpecification [1] EXPLICIT
//!       <VAS CHOICE>   -- 0xa0 listOfVariable or 0xa1 variableListName
//! ```
//!
//! A ReadResponse inside a ConfirmedResponsePdu:
//! ```text
//! 0xa1 <len>           -- MmsPdu [1] confirmedResponsePdu
//!   0x02 <len> <id>    -- invokeID INTEGER
//!   0xa4 <len>         -- read [4] IMPLICIT, a ReadResponse SEQUENCE
//!     [0xa0 <len> ...] -- variableAccessSpecification [0] EXPLICIT, OPTIONAL
//!     0xa1 <len>       -- listOfAccessResult [1] IMPLICIT SEQUENCE OF
//!       <AccessResult> -- repeated once per variable
//! ```
//!
//! ## Interoperability
//!
//! `specificationWithResult = true` is encoded faithfully on the listOfVariable path,
//! but a response that does not echo the access specification is still accepted:
//! `variableAccessSpecification` is OPTIONAL in the ReadResponse, unlike the
//! ReadRequest, where it is required.

use super::super::error::MmsError;
use super::common::{AccessResult, VariableAccessSpecification};
use super::initiate::{decode_length, encode_length};
use crate::compat::prelude::*;
use bytes::BytesMut;

// Tag constants

/// Tag of Read inside the ConfirmedService CHOICE.
pub const SERVICE_TAG_READ: u8 = 0xa4;

// ReadRequest

/// An MMS ReadRequest.
///
/// - `specificationWithResult`: `[0]` IMPLICIT BOOLEAN, OPTIONAL with DEFAULT FALSE
/// - `variableAccessSpecification`: `[1]` EXPLICIT CHOICE of listOfVariable or
///   variableListName
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRequest {
    /// When true the server echoes the access specification in its response.
    /// OPTIONAL on the wire, with DEFAULT FALSE.
    pub specification_with_result: bool,
    /// Which variables to read.
    pub variable_access_spec: VariableAccessSpecification,
}

impl ReadRequest {
    /// Builds a request that reads one domain-specific variable.
    pub fn single_domain(domain_id: impl Into<String>, item_id: impl Into<String>) -> Self {
        use super::common::ObjectName;
        Self {
            specification_with_result: false,
            variable_access_spec: VariableAccessSpecification::ListOfVariable(vec![
                ObjectName::DomainSpecific {
                    domain_id: domain_id.into(),
                    item_id: item_id.into(),
                }
                .into(),
            ]),
        }
    }

    /// Builds a request that reads a named variable list.
    pub fn named_list(name: super::common::ObjectName, specification_with_result: bool) -> Self {
        Self {
            specification_with_result,
            variable_access_spec: VariableAccessSpecification::VariableListName(name),
        }
    }

    /// Encodes the request, including the `0xa4 <len>` service wrapper.
    ///
    /// The caller adds the ConfirmedRequestPdu invokeID and its outer `0xa0` wrapper.
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut inner = BytesMut::new();

        // specificationWithResult [0], written only when true since FALSE is the default
        if self.specification_with_result {
            inner.extend_from_slice(&[0x80, 0x01, 0x01]);
        }

        // [1] variableAccessSpecification - EXPLICIT [1] wrapper
        let mut vas_buf = BytesMut::new();
        self.variable_access_spec.encode(&mut vas_buf);
        inner.extend_from_slice(&[0xa1]);
        encode_length(vas_buf.len(), &mut inner);
        inner.extend_from_slice(&vas_buf);

        buf.extend_from_slice(&[SERVICE_TAG_READ]);
        encode_length(inner.len(), buf);
        buf.extend_from_slice(&inner);
    }

    /// Decodes a request; `data` starts at the `0xa4` byte.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        if data[0] != SERVICE_TAG_READ {
            return Err(MmsError::InvalidTag {
                expected: SERVICE_TAG_READ,
                actual: data[0],
            });
        }
        let (inner_len, hdr) = decode_length(&data[1..])?;
        let inner_start = 1 + hdr;
        if inner_start + inner_len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let inner = &data[inner_start..inner_start + inner_len];
        decode_read_request_inner(inner)
    }
}

fn decode_read_request_inner(data: &[u8]) -> Result<ReadRequest, MmsError> {
    let mut pos = 0usize;
    let mut spec_with_result = false;
    let mut vas: Option<VariableAccessSpecification> = None;

    while pos < data.len() {
        if pos >= data.len() {
            break;
        }
        let tag = data[pos];
        let (len, hdr) = decode_length(&data[pos + 1..])?;
        let val_start = pos + 1 + hdr;
        if val_start + len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let val = &data[val_start..val_start + len];
        pos = val_start + len;

        match tag {
            0x80 => {
                // specificationWithResult [0] IMPLICIT BOOLEAN
                if val.is_empty() {
                    return Err(MmsError::InvalidLength);
                }
                spec_with_result = val[0] != 0;
            }
            0xa1 => {
                // variableAccessSpecification [1] EXPLICIT, whose content is the CHOICE
                let (decoded_vas, _) = VariableAccessSpecification::decode(val)?;
                vas = Some(decoded_vas);
            }
            other => {
                tracing::debug!("skipping unknown readrequest tag 0x{:02X}", other);
            }
        }
    }

    let variable_access_spec = vas.ok_or(MmsError::TruncatedPdu)?;
    Ok(ReadRequest {
        specification_with_result: spec_with_result,
        variable_access_spec,
    })
}

// ReadResponse

/// An MMS ReadResponse.
///
/// - `variableAccessSpecification`: `[0]` EXPLICIT and OPTIONAL, echoed only when the
///   request asked for it on the variableListName path
/// - `listOfAccessResult`: `[1]` IMPLICIT SEQUENCE OF AccessResult
#[derive(Debug, Clone, PartialEq)]
pub struct ReadResponse {
    /// The echoed access specification, when the server sent one.
    pub variable_access_spec: Option<VariableAccessSpecification>,
    /// One result per variable read.
    pub list_of_access_result: Vec<AccessResult>,
}

impl ReadResponse {
    /// Encodes the response, including the `0xa4 <len>` service wrapper.
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut inner = BytesMut::new();

        // variableAccessSpecification [0] EXPLICIT, OPTIONAL
        if let Some(ref vas) = self.variable_access_spec {
            let mut vas_buf = BytesMut::new();
            vas.encode(&mut vas_buf);
            inner.extend_from_slice(&[0xa0]);
            encode_length(vas_buf.len(), &mut inner);
            inner.extend_from_slice(&vas_buf);
        }

        // [1] listOfAccessResult - IMPLICIT [1] SEQUENCE OF
        let mut ar_buf = BytesMut::new();
        for ar in &self.list_of_access_result {
            ar.encode(&mut ar_buf);
        }
        inner.extend_from_slice(&[0xa1]);
        encode_length(ar_buf.len(), &mut inner);
        inner.extend_from_slice(&ar_buf);

        buf.extend_from_slice(&[SERVICE_TAG_READ]);
        encode_length(inner.len(), buf);
        buf.extend_from_slice(&inner);
    }

    /// Decodes a response; `data` starts at the `0xa4` byte.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        if data[0] != SERVICE_TAG_READ {
            return Err(MmsError::InvalidTag {
                expected: SERVICE_TAG_READ,
                actual: data[0],
            });
        }
        let (inner_len, hdr) = decode_length(&data[1..])?;
        let inner_start = 1 + hdr;
        if inner_start + inner_len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let inner = &data[inner_start..inner_start + inner_len];
        decode_read_response_inner(inner)
    }
}

fn decode_read_response_inner(data: &[u8]) -> Result<ReadResponse, MmsError> {
    let mut pos = 0usize;
    let mut vas: Option<VariableAccessSpecification> = None;
    let mut results: Option<Vec<AccessResult>> = None;

    while pos < data.len() {
        let tag = data[pos];
        let (len, hdr) = decode_length(&data[pos + 1..])?;
        let val_start = pos + 1 + hdr;
        if val_start + len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let val = &data[val_start..val_start + len];
        pos = val_start + len;

        match tag {
            0xa0 => {
                // variableAccessSpecification [0] EXPLICIT
                let (decoded_vas, _) = VariableAccessSpecification::decode(val)?;
                vas = Some(decoded_vas);
            }
            0xa1 => {
                // listOfAccessResult [1] IMPLICIT SEQUENCE OF
                let list = decode_list_of_access_result(val)?;
                results = Some(list);
            }
            other => {
                tracing::debug!("skipping unknown readresponse tag 0x{:02X}", other);
            }
        }
    }

    let list_of_access_result = results.ok_or(MmsError::TruncatedPdu)?;
    Ok(ReadResponse {
        variable_access_spec: vas,
        list_of_access_result,
    })
}

/// Decodes listOfAccessResult; `data` is the content of the `0xa1` field.
fn decode_list_of_access_result(data: &[u8]) -> Result<Vec<AccessResult>, MmsError> {
    let mut results = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let (ar, consumed) = AccessResult::decode(&data[pos..])?;
        results.push(ar);
        pos += consumed;
    }
    Ok(results)
}

// ConfirmedRequestPdu and ConfirmedResponsePdu wrappers

/// Encodes a ReadRequest as a complete ConfirmedRequestPdu, outer `0xa0` included.
///
/// Wire format:
/// ```text
/// 0xa0 <len>           -- confirmedRequestPdu [0]
///   0x02 <len> <id>    -- invokeID
///   0xa4 <len>         -- ReadRequest
/// ```
pub fn encode_confirmed_read_request(invoke_id: u32, req: &ReadRequest, buf: &mut BytesMut) {
    let mut inner = BytesMut::new();
    // invokeID INTEGER
    encode_invoke_id(invoke_id, &mut inner);
    // ReadRequest
    req.encode(&mut inner);

    buf.extend_from_slice(&[0xa0]);
    encode_length(inner.len(), buf);
    buf.extend_from_slice(&inner);
}

/// Encodes a ReadResponse as a complete ConfirmedResponsePdu, outer `0xa1` included.
pub fn encode_confirmed_read_response(invoke_id: u32, resp: &ReadResponse, buf: &mut BytesMut) {
    let mut inner = BytesMut::new();
    encode_invoke_id(invoke_id, &mut inner);
    resp.encode(&mut inner);

    buf.extend_from_slice(&[0xa1]);
    encode_length(inner.len(), buf);
    buf.extend_from_slice(&inner);
}

/// Decodes the ReadRequest inside a ConfirmedRequestPdu; `data` starts at `0xa0`.
pub fn decode_confirmed_read_request(data: &[u8]) -> Result<(u32, ReadRequest), MmsError> {
    let (invoke_id, service_data) = decode_confirmed_pdu_inner(data, 0xa0)?;
    let req = ReadRequest::decode(service_data)?;
    Ok((invoke_id, req))
}

/// Decodes the ReadResponse inside a ConfirmedResponsePdu; `data` starts at `0xa1`.
pub fn decode_confirmed_read_response(data: &[u8]) -> Result<(u32, ReadResponse), MmsError> {
    let (invoke_id, service_data) = decode_confirmed_pdu_inner(data, 0xa1)?;
    let resp = ReadResponse::decode(service_data)?;
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

/// Extracts the invokeID and content of a ConfirmedRequest or ConfirmedResponse PDU;
/// `data` starts at the outer tag.
///
/// The returned slice starts at the service tag, such as `0xa4` or `0xa5`.
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

    // the invokeID is the first element, a UNIVERSAL INTEGER with tag 0x02
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
    use super::super::common::{DataAccessError, MmsData, ObjectName};
    use super::*;

    // ReadRequest round trips

    #[test]
    fn read_request_domain_specific_roundtrip() {
        let req = ReadRequest::single_domain("TESTLD", "GGIO1$ST$Ind$stVal");
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        assert_eq!(buf[0], SERVICE_TAG_READ);
        let decoded = ReadRequest::decode(&buf).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn read_request_named_list_roundtrip() {
        let name = ObjectName::DomainSpecific {
            domain_id: "LD1".to_owned(),
            item_id: "DataSet1".to_owned(),
        };
        let req = ReadRequest::named_list(name, false);
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let decoded = ReadRequest::decode(&buf).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn read_request_spec_with_result_true_roundtrip() {
        let name = ObjectName::DomainSpecific {
            domain_id: "LD1".to_owned(),
            item_id: "DataSet1".to_owned(),
        };
        let req = ReadRequest::named_list(name, true);
        let mut buf = BytesMut::new();
        req.encode(&mut buf);

        // 0x80 0x01 0x01 marks specificationWithResult TRUE
        let bytes = &buf[..];
        let has_spec = bytes.windows(3).any(|w| w == [0x80, 0x01, 0x01]);
        assert!(
            has_spec,
            "specificationWithResult true must produce 0x80 0x01 0x01"
        );

        let decoded = ReadRequest::decode(&buf).unwrap();
        assert!(decoded.specification_with_result);
    }

    #[test]
    fn read_request_spec_with_result_false_no_byte() {
        let req = ReadRequest::single_domain("LD", "VAR");
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        // FALSE is the default and is omitted, so 0x80 0x01 0x01 must be absent
        let bytes = &buf[..];
        let has_spec = bytes.windows(3).any(|w| w == [0x80, 0x01, 0x01]);
        assert!(
            !has_spec,
            "specificationWithResult false must not produce 0x80 0x01 0x01"
        );
    }

    #[test]
    fn read_request_multiple_variables_roundtrip() {
        use crate::mms::pdu::common::VariableAccessSpecification;
        let vars: Vec<super::super::common::ListOfVariableEntry> = vec![
            ObjectName::DomainSpecific {
                domain_id: "LD1".to_owned(),
                item_id: "A".to_owned(),
            }
            .into(),
            ObjectName::DomainSpecific {
                domain_id: "LD1".to_owned(),
                item_id: "B".to_owned(),
            }
            .into(),
            ObjectName::VmdSpecific("VMD_C".to_owned()).into(),
        ];
        let req = ReadRequest {
            specification_with_result: false,
            variable_access_spec: VariableAccessSpecification::ListOfVariable(vars),
        };
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let decoded = ReadRequest::decode(&buf).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn read_request_vmd_specific_roundtrip() {
        use crate::mms::pdu::common::VariableAccessSpecification;
        let req = ReadRequest {
            specification_with_result: false,
            variable_access_spec: VariableAccessSpecification::ListOfVariable(vec![
                ObjectName::VmdSpecific("VMD_VAR".to_owned()).into(),
            ]),
        };
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let decoded = ReadRequest::decode(&buf).unwrap();
        assert_eq!(decoded, req);
    }

    // ReadResponse round trips

    #[test]
    fn read_response_basic_roundtrip() {
        let resp = ReadResponse {
            variable_access_spec: None,
            list_of_access_result: vec![
                AccessResult::Success(MmsData::Boolean(true)),
                AccessResult::Success(MmsData::Integer(42)),
            ],
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        let decoded = ReadResponse::decode(&buf).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn read_response_with_vas_echo_roundtrip() {
        use crate::mms::pdu::common::VariableAccessSpecification;
        let vas = VariableAccessSpecification::VariableListName(ObjectName::DomainSpecific {
            domain_id: "LD".to_owned(),
            item_id: "DS".to_owned(),
        });
        let resp = ReadResponse {
            variable_access_spec: Some(vas),
            list_of_access_result: vec![AccessResult::Success(MmsData::Unsigned(100))],
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        let decoded = ReadResponse::decode(&buf).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn read_response_mixed_success_failure_roundtrip() {
        let resp = ReadResponse {
            variable_access_spec: None,
            list_of_access_result: vec![
                AccessResult::Success(MmsData::Boolean(false)),
                AccessResult::Failure(DataAccessError::ObjectNonExistent),
                AccessResult::Success(MmsData::VisibleString("OK".to_owned())),
                AccessResult::Failure(DataAccessError::ObjectAccessDenied),
            ],
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        let decoded = ReadResponse::decode(&buf).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn read_response_empty_list_ok() {
        // an empty listOfAccessResult is legal
        let resp = ReadResponse {
            variable_access_spec: None,
            list_of_access_result: vec![],
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        // the encoding must contain 0xa1 0x00
        let bytes = &buf[..];
        let has_empty = bytes.windows(2).any(|w| w == [0xa1, 0x00]);
        assert!(
            has_empty,
            "an empty listOfAccessResult must encode as 0xa1 0x00"
        );
        let decoded = ReadResponse::decode(&buf).unwrap();
        assert!(decoded.list_of_access_result.is_empty());
    }

    // ConfirmedRequestPdu and ConfirmedResponsePdu wrappers

    #[test]
    fn confirmed_read_request_roundtrip() {
        let req = ReadRequest::single_domain("LD1", "VAR1");
        let mut buf = BytesMut::new();
        encode_confirmed_read_request(42, &req, &mut buf);
        assert_eq!(buf[0], 0xa0);
        let (invoke_id, decoded_req) = decode_confirmed_read_request(&buf).unwrap();
        assert_eq!(invoke_id, 42);
        assert_eq!(decoded_req, req);
    }

    #[test]
    fn confirmed_read_response_roundtrip() {
        let resp = ReadResponse {
            variable_access_spec: None,
            list_of_access_result: vec![AccessResult::Success(MmsData::Integer(777))],
        };
        let mut buf = BytesMut::new();
        encode_confirmed_read_response(99, &resp, &mut buf);
        assert_eq!(buf[0], 0xa1);
        let (invoke_id, decoded_resp) = decode_confirmed_read_response(&buf).unwrap();
        assert_eq!(invoke_id, 99);
        assert_eq!(decoded_resp, resp);
    }

    // every AccessResult value type

    #[test]
    fn access_result_all_primitive_types() {
        let cases: Vec<MmsData> = vec![
            MmsData::Boolean(true),
            MmsData::Boolean(false),
            MmsData::Integer(-1),
            MmsData::Integer(0),
            MmsData::Integer(255),
            MmsData::Unsigned(0),
            MmsData::Unsigned(65535),
            MmsData::Float64(1.0),
            MmsData::OctetString(vec![0xde, 0xad]),
            MmsData::VisibleString("TEST".to_owned()),
            MmsData::MmsString("UTF8".to_owned()),
            MmsData::UtcTime([0x5e, 0x1a, 0x2b, 0x3c, 0x00, 0x00, 0x00, 0x00]),
            MmsData::BitString {
                padding: 3,
                data: vec![0xf8],
            },
            MmsData::BooleanArray {
                padding: 0,
                data: vec![0xff],
            },
            MmsData::BinaryTime(vec![0x00, 0x00, 0x00, 0x00]),
        ];
        for data in cases {
            let ar = AccessResult::Success(data.clone());
            let mut buf = BytesMut::new();
            ar.encode(&mut buf);
            let (decoded, _) = AccessResult::decode(&buf).unwrap();
            assert_eq!(decoded, ar, "AccessResult for {:?} must round trip", data);
        }
    }

    // malformed input

    #[test]
    fn read_request_wrong_tag_err() {
        let data = [0xa5u8, 0x00]; // write tag
        let result = ReadRequest::decode(&data);
        assert!(matches!(
            result,
            Err(MmsError::InvalidTag {
                expected: 0xa4,
                actual: 0xa5
            })
        ));
    }

    #[test]
    fn read_response_missing_list_err() {
        // 0xa4 with a length but no 0xa1 listOfAccessResult
        let data = [0xa4u8, 0x00]; // empty content
        let result = ReadResponse::decode(&data);
        assert!(
            result.is_err(),
            "a missing listOfAccessResult must return an error"
        );
    }

    #[test]
    fn read_request_truncated_err() {
        // a tag with no length byte
        let data = [0xa4u8];
        let result = ReadRequest::decode(&data);
        assert!(result.is_err());
    }

    // ReadRequest with an AlternateAccess

    use super::super::common::{AlternateAccess, ListOfVariableEntry};

    fn build_alt_access_request(invoke_id: u32, item: &str, aa: AlternateAccess) -> BytesMut {
        let entry = ListOfVariableEntry::with_alt_access(
            ObjectName::DomainSpecific {
                domain_id: "TESTLD".to_owned(),
                item_id: item.to_owned(),
            },
            aa,
        );
        let req = ReadRequest {
            specification_with_result: false,
            variable_access_spec: VariableAccessSpecification::ListOfVariable(vec![entry]),
        };
        let mut buf = BytesMut::new();
        encode_confirmed_read_request(invoke_id, &req, &mut buf);
        buf
    }

    #[test]
    fn read_request_alt_access_index_roundtrip() {
        let buf = build_alt_access_request(7, "GGIO1$ST$Ind", AlternateAccess::index(2));
        assert_eq!(buf[0], 0xa0);
        let (invoke_id, decoded) = decode_confirmed_read_request(&buf).unwrap();
        assert_eq!(invoke_id, 7);
        match decoded.variable_access_spec {
            VariableAccessSpecification::ListOfVariable(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(
                    entries[0].name,
                    ObjectName::DomainSpecific {
                        domain_id: "TESTLD".to_owned(),
                        item_id: "GGIO1$ST$Ind".to_owned(),
                    }
                );
                assert_eq!(entries[0].alt_access, Some(AlternateAccess::index(2)));
            }
            _ => panic!("expected ListOfVariable"),
        }
    }

    #[test]
    fn read_request_alt_access_index_component_wire_contains_alt_bytes() {
        let buf = build_alt_access_request(
            1,
            "GGIO1$ST$Ind1",
            AlternateAccess::index_component(0, "stVal").unwrap(),
        );
        let bytes = &buf[..];
        let has_alt = bytes.windows(4).any(|w| w == [0xa0, 0x0c, 0x81, 0x01]);
        assert!(
            has_alt,
            "wire bytes should contain the IndexComponent header"
        );
    }
}
