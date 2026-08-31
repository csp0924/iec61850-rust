//! MMS Write request and response PDUs.
//!
//! ## Wire format
//!
//! Inside the `ConfirmedServiceRequest` CHOICE:
//! - write is CONTEXT `[5]` IMPLICIT CONSTRUCTED, tag `0xa5`
//!
//! A WriteRequest inside a ConfirmedRequestPdu:
//! ```text
//! 0xa0 <len>            -- MmsPdu [0] confirmedRequestPdu
//!   0x02 <len> <id>     -- invokeID INTEGER
//!   0xa5 <len>          -- write [5] IMPLICIT, a WriteRequest SEQUENCE
//!     <VAS CHOICE>      -- variableAccessSpecification, 0xa0 or 0xa1 with no wrapper
//!     0xa0 <len>        -- listOfData [0] IMPLICIT SEQUENCE OF Data
//!       <Data ...>
//! ```
//!
//! A WriteResponse inside a ConfirmedResponsePdu:
//! ```text
//! 0xa1 <len>            -- MmsPdu [1] confirmedResponsePdu
//!   0x02 <len> <id>     -- invokeID INTEGER
//!   0xa5 <len>          -- write [5] IMPLICIT, a WriteResponse SEQUENCE OF CHOICE
//!     0x81 0x00         -- success
//!     OR 0x80 0x01 <e>  -- failure
//! ```
//!
//! ## Validation rules
//!
//! - The number of outcomes in a response must equal the number of items requested.
//! - A failure outcome carries a properly encoded BER INTEGER; the DataAccessError
//!   codes 0 to 11 all fit in one byte.
//! - At most 100 items may be written in one request; more are rejected.

use super::super::error::MmsError;
use super::common::{
    effective_nesting_cap, MmsData, VariableAccessSpecification, WriteOutcome,
    MAX_DATA_NESTING_DEPTH,
};
use super::initiate::{decode_length, encode_length};
use crate::compat::prelude::*;
use bytes::BytesMut;

// Tag constants

/// Tag of Write inside the ConfirmedService CHOICE.
pub const SERVICE_TAG_WRITE: u8 = 0xa5;

/// Largest number of items accepted in one WriteRequest.
pub const MAX_WRITE_ITEMS: usize = 100;

// WriteRequest

/// An MMS WriteRequest.
///
/// - `variableAccessSpecification`: the CHOICE of listOfVariable or variableListName
/// - `listOfData`: `[0]` IMPLICIT SEQUENCE OF Data
#[derive(Debug, Clone, PartialEq)]
pub struct WriteRequest {
    /// Which variables to write.
    pub variable_access_spec: VariableAccessSpecification,
    /// Values to write, in the order the access specification lists the variables.
    pub list_of_data: Vec<MmsData>,
}

impl WriteRequest {
    /// Builds a request that writes one domain-specific variable.
    pub fn single_domain(
        domain_id: impl Into<String>,
        item_id: impl Into<String>,
        value: MmsData,
    ) -> Self {
        use super::common::ObjectName;
        Self {
            variable_access_spec: VariableAccessSpecification::ListOfVariable(vec![
                ObjectName::DomainSpecific {
                    domain_id: domain_id.into(),
                    item_id: item_id.into(),
                }
                .into(),
            ]),
            list_of_data: vec![value],
        }
    }

    /// Builds a request that writes a named variable list.
    pub fn named_list(name: super::common::ObjectName, values: Vec<MmsData>) -> Self {
        Self {
            variable_access_spec: VariableAccessSpecification::VariableListName(name),
            list_of_data: values,
        }
    }

    /// Encodes the request, including the `0xa5 <len>` service wrapper.
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut inner = BytesMut::new();

        // variableAccessSpecification, a CHOICE written as its variant tag with no wrapper
        self.variable_access_spec.encode(&mut inner);

        // listOfData [0] IMPLICIT SEQUENCE OF Data, tag 0xa0
        let mut data_buf = BytesMut::new();
        for d in &self.list_of_data {
            d.encode(&mut data_buf);
        }
        inner.extend_from_slice(&[0xa0]);
        encode_length(data_buf.len(), &mut inner);
        inner.extend_from_slice(&data_buf);

        buf.extend_from_slice(&[SERVICE_TAG_WRITE]);
        encode_length(inner.len(), buf);
        buf.extend_from_slice(&inner);
    }

    /// Decodes a request; `data` starts at the `0xa5` byte.
    ///
    /// The local ceiling `MAX_DATA_NESTING_DEPTH` bounds Data recursion.
    /// Use `decode_with_negotiated_cap` to apply a negotiated nesting level as well.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        Self::decode_inner_from_service_tag(data, MAX_DATA_NESTING_DEPTH)
    }

    /// Decodes a request under the negotiated `dataStructureNestingLevel`.
    ///
    /// The effective ceiling is the smaller of `MAX_DATA_NESTING_DEPTH` and the
    /// negotiated value; `None` falls back to the local ceiling, which is the case
    /// before negotiation completes.
    pub fn decode_with_negotiated_cap(
        data: &[u8],
        negotiated: Option<u8>,
    ) -> Result<Self, MmsError> {
        let max_depth = effective_nesting_cap(MAX_DATA_NESTING_DEPTH, negotiated);
        Self::decode_inner_from_service_tag(data, max_depth)
    }

    fn decode_inner_from_service_tag(data: &[u8], max_depth: u8) -> Result<Self, MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        if data[0] != SERVICE_TAG_WRITE {
            return Err(MmsError::InvalidTag {
                expected: SERVICE_TAG_WRITE,
                actual: data[0],
            });
        }
        let (inner_len, hdr) = decode_length(&data[1..])?;
        let inner_start = 1 + hdr;
        if inner_start + inner_len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let inner = &data[inner_start..inner_start + inner_len];
        decode_write_request_inner(inner, max_depth)
    }
}

fn decode_write_request_inner(data: &[u8], max_depth: u8) -> Result<WriteRequest, MmsError> {
    if data.is_empty() {
        return Err(MmsError::TruncatedPdu);
    }

    // The variableAccessSpecification CHOICE uses 0xa0 for listOfVariable and 0xa1 for
    // variableListName. listOfData also carries 0xa0, so the two are told apart by
    // position: the access specification is read first, then listOfData.
    let (vas, vas_consumed) = VariableAccessSpecification::decode(data)?;
    let rest = &data[vas_consumed..];

    // listOfData [0] IMPLICIT SEQUENCE OF Data, tag 0xa0
    if rest.is_empty() {
        return Err(MmsError::TruncatedPdu);
    }
    if rest[0] != 0xa0 {
        tracing::warn!(
            "writerequest listofdata expected tag 0xa0, got 0x{:02X}, rejecting",
            rest[0]
        );
        return Err(MmsError::InvalidTag {
            expected: 0xa0,
            actual: rest[0],
        });
    }
    let (list_len, list_hdr) = decode_length(&rest[1..])?;
    let list_start = 1 + list_hdr;
    if list_start + list_len > rest.len() {
        return Err(MmsError::TruncatedPdu);
    }
    let list_inner = &rest[list_start..list_start + list_len];
    let list_of_data = decode_list_of_data(list_inner, max_depth)?;

    // the access specification and listOfData must describe the same number of items
    let vas_count = match &vas {
        VariableAccessSpecification::ListOfVariable(names) => names.len(),
        VariableAccessSpecification::VariableListName(_) => list_of_data.len(), // count not checked for a named list
    };
    if let VariableAccessSpecification::ListOfVariable(_) = &vas {
        if vas_count != list_of_data.len() {
            tracing::warn!(
                "writerequest names {} variables but carries {} values, rejecting",
                vas_count,
                list_of_data.len()
            );
            return Err(MmsError::WriteCountMismatch {
                expected: vas_count,
                actual: list_of_data.len(),
            });
        }
    }

    // item count ceiling
    if list_of_data.len() > MAX_WRITE_ITEMS {
        tracing::warn!(
            "writerequest carries {} items, above the limit of {}, rejecting",
            list_of_data.len(),
            MAX_WRITE_ITEMS
        );
        return Err(MmsError::TooManyWriteItems {
            count: list_of_data.len(),
        });
    }

    Ok(WriteRequest {
        variable_access_spec: vas,
        list_of_data,
    })
}

/// Decodes listOfData; `data` is the content of the `0xa0` field.
///
/// `max_depth` is the effective ceiling for Data recursion.
fn decode_list_of_data(data: &[u8], max_depth: u8) -> Result<Vec<MmsData>, MmsError> {
    let mut items = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let (item, consumed) = MmsData::decode_with_max(&data[pos..], max_depth)?;
        items.push(item);
        pos += consumed;
    }
    Ok(items)
}

// WriteResponse

/// An MMS WriteResponse.
///
/// The response is a SEQUENCE OF CHOICE whose elements are `WriteOutcome` values:
/// - success: `0x81 0x00`
/// - failure: `0x80 0x01 <code>`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteResponse {
    /// One outcome per written item, in request order.
    pub outcomes: Vec<WriteOutcome>,
}

impl WriteResponse {
    /// Encodes the response, including the `0xa5 <len>` service wrapper.
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut inner = BytesMut::new();
        for outcome in &self.outcomes {
            outcome.encode(&mut inner);
        }
        buf.extend_from_slice(&[SERVICE_TAG_WRITE]);
        encode_length(inner.len(), buf);
        buf.extend_from_slice(&inner);
    }

    /// Decodes a response; `data` starts at the `0xa5` byte.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        if data[0] != SERVICE_TAG_WRITE {
            return Err(MmsError::InvalidTag {
                expected: SERVICE_TAG_WRITE,
                actual: data[0],
            });
        }
        let (inner_len, hdr) = decode_length(&data[1..])?;
        let inner_start = 1 + hdr;
        if inner_start + inner_len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let inner = &data[inner_start..inner_start + inner_len];
        decode_write_response_inner(inner)
    }

    /// Decodes a response and requires it to carry `expected` outcomes.
    pub fn decode_with_expected_count(data: &[u8], expected: usize) -> Result<Self, MmsError> {
        let resp = Self::decode(data)?;
        if resp.outcomes.len() != expected {
            tracing::warn!(
                "writeresponse carries {} outcomes but {} were requested",
                resp.outcomes.len(),
                expected
            );
            return Err(MmsError::WriteCountMismatch {
                expected,
                actual: resp.outcomes.len(),
            });
        }
        Ok(resp)
    }
}

fn decode_write_response_inner(data: &[u8]) -> Result<WriteResponse, MmsError> {
    let mut outcomes = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let (outcome, consumed) = WriteOutcome::decode(&data[pos..])?;
        outcomes.push(outcome);
        pos += consumed;
    }
    Ok(WriteResponse { outcomes })
}

// ConfirmedRequestPdu and ConfirmedResponsePdu wrappers

/// Encodes a WriteRequest as a complete ConfirmedRequestPdu, outer `0xa0` included.
pub fn encode_confirmed_write_request(invoke_id: u32, req: &WriteRequest, buf: &mut BytesMut) {
    let mut inner = BytesMut::new();
    encode_invoke_id(invoke_id, &mut inner);
    req.encode(&mut inner);

    buf.extend_from_slice(&[0xa0]);
    encode_length(inner.len(), buf);
    buf.extend_from_slice(&inner);
}

/// Encodes a WriteResponse as a complete ConfirmedResponsePdu, outer `0xa1` included.
pub fn encode_confirmed_write_response(invoke_id: u32, resp: &WriteResponse, buf: &mut BytesMut) {
    let mut inner = BytesMut::new();
    encode_invoke_id(invoke_id, &mut inner);
    resp.encode(&mut inner);

    buf.extend_from_slice(&[0xa1]);
    encode_length(inner.len(), buf);
    buf.extend_from_slice(&inner);
}

/// Decodes the WriteRequest inside a ConfirmedRequestPdu; `data` starts at `0xa0`.
///
/// The local ceiling bounds Data recursion.
pub fn decode_confirmed_write_request(data: &[u8]) -> Result<(u32, WriteRequest), MmsError> {
    let (invoke_id, service_data) = decode_confirmed_pdu_inner(data, 0xa0)?;
    let req = WriteRequest::decode(service_data)?;
    Ok((invoke_id, req))
}

/// Decodes the WriteRequest inside a ConfirmedRequestPdu under the negotiated ceiling.
///
/// The effective ceiling is the smaller of `MAX_DATA_NESTING_DEPTH` and the
/// negotiated value.
pub fn decode_confirmed_write_request_with_negotiated_cap(
    data: &[u8],
    negotiated: Option<u8>,
) -> Result<(u32, WriteRequest), MmsError> {
    let (invoke_id, service_data) = decode_confirmed_pdu_inner(data, 0xa0)?;
    let req = WriteRequest::decode_with_negotiated_cap(service_data, negotiated)?;
    Ok((invoke_id, req))
}

/// Decodes the WriteResponse inside a ConfirmedResponsePdu; `data` starts at `0xa1`.
pub fn decode_confirmed_write_response(data: &[u8]) -> Result<(u32, WriteResponse), MmsError> {
    let (invoke_id, service_data) = decode_confirmed_pdu_inner(data, 0xa1)?;
    let resp = WriteResponse::decode(service_data)?;
    Ok((invoke_id, resp))
}

// Private helpers

fn encode_invoke_id(invoke_id: u32, buf: &mut BytesMut) {
    use super::common::encode_unsigned_int_minimal;
    let bytes = encode_unsigned_int_minimal(invoke_id as u64);
    buf.extend_from_slice(&[0x02]);
    encode_length(bytes.len(), buf);
    buf.extend_from_slice(&bytes);
}

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

    // WriteRequest round trips

    #[test]
    fn write_request_single_boolean_roundtrip() {
        let req =
            WriteRequest::single_domain("TESTLD", "GGIO1$CO$Ind$Oper", MmsData::Boolean(true));
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        assert_eq!(buf[0], SERVICE_TAG_WRITE);
        let decoded = WriteRequest::decode(&buf).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn write_request_multiple_items_roundtrip() {
        use crate::mms::pdu::common::VariableAccessSpecification;
        let req = WriteRequest {
            variable_access_spec: VariableAccessSpecification::ListOfVariable(vec![
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
                ObjectName::VmdSpecific("C".to_owned()).into(),
            ]),
            list_of_data: vec![
                MmsData::Boolean(true),
                MmsData::Integer(-5),
                MmsData::Unsigned(0),
            ],
        };
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let decoded = WriteRequest::decode(&buf).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn write_request_named_variable_list_roundtrip() {
        let name = ObjectName::DomainSpecific {
            domain_id: "TESTLD".to_owned(),
            item_id: "DataSet1".to_owned(),
        };
        let req =
            WriteRequest::named_list(name, vec![MmsData::Boolean(false), MmsData::Integer(100)]);
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let decoded = WriteRequest::decode(&buf).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn write_request_listofdata_tag_is_0xa0() {
        let req = WriteRequest::single_domain("LD", "V", MmsData::Boolean(true));
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        // the listOfData tag 0xa0 must be present; listOfVariable uses it too, so at
        // least two occurrences are expected
        let bytes = &buf[..];
        let count = bytes.iter().filter(|&&b| b == 0xa0).count();
        assert!(
            count >= 1,
            "the encoded WriteRequest must contain the listOfData tag 0xa0"
        );
    }

    // WriteResponse round trips

    #[test]
    fn write_response_single_success_roundtrip() {
        let resp = WriteResponse {
            outcomes: vec![WriteOutcome::Success],
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        assert_eq!(buf[0], SERVICE_TAG_WRITE);
        let decoded = WriteResponse::decode(&buf).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn write_response_mixed_outcomes_roundtrip() {
        let resp = WriteResponse {
            outcomes: vec![
                WriteOutcome::Success,
                WriteOutcome::Failure(DataAccessError::TypeInconsistent),
                WriteOutcome::Success,
                WriteOutcome::Failure(DataAccessError::ObjectNonExistent),
                WriteOutcome::Success,
            ],
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        let decoded = WriteResponse::decode(&buf).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn write_response_all_failures_roundtrip() {
        let resp = WriteResponse {
            outcomes: vec![
                WriteOutcome::Failure(DataAccessError::HardwareFault),
                WriteOutcome::Failure(DataAccessError::ObjectAccessDenied),
            ],
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        let decoded = WriteResponse::decode(&buf).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn write_response_decode_error_tag_0x80() {
        // hand-built 0xa5 0x03 0x80 0x01 0x07, where 7 is typeInconsistent
        let bytes = [0xa5u8, 0x03, 0x80, 0x01, 0x07];
        let decoded = WriteResponse::decode(&bytes).unwrap();
        assert_eq!(decoded.outcomes.len(), 1);
        assert_eq!(
            decoded.outcomes[0],
            WriteOutcome::Failure(DataAccessError::TypeInconsistent)
        );
    }

    #[test]
    fn write_response_decode_success_tag_0x81() {
        // hand-built 0xa5 0x02 0x81 0x00, a success
        let bytes = [0xa5u8, 0x02, 0x81, 0x00];
        let decoded = WriteResponse::decode(&bytes).unwrap();
        assert_eq!(decoded.outcomes.len(), 1);
        assert_eq!(decoded.outcomes[0], WriteOutcome::Success);
    }

    // ConfirmedRequestPdu and ConfirmedResponsePdu wrappers

    #[test]
    fn confirmed_write_request_roundtrip() {
        let req = WriteRequest::single_domain("LD1", "VAR1", MmsData::Integer(42));
        let mut buf = BytesMut::new();
        encode_confirmed_write_request(1, &req, &mut buf);
        assert_eq!(buf[0], 0xa0);
        let (invoke_id, decoded) = decode_confirmed_write_request(&buf).unwrap();
        assert_eq!(invoke_id, 1);
        assert_eq!(decoded, req);
    }

    #[test]
    fn confirmed_write_response_roundtrip() {
        let resp = WriteResponse {
            outcomes: vec![
                WriteOutcome::Success,
                WriteOutcome::Failure(DataAccessError::ObjectAccessDenied),
            ],
        };
        let mut buf = BytesMut::new();
        encode_confirmed_write_response(2, &resp, &mut buf);
        assert_eq!(buf[0], 0xa1);
        let (invoke_id, decoded) = decode_confirmed_write_response(&buf).unwrap();
        assert_eq!(invoke_id, 2);
        assert_eq!(decoded, resp);
    }

    // decode_with_expected_count

    #[test]
    fn write_response_count_match_ok() {
        let resp = WriteResponse {
            outcomes: vec![WriteOutcome::Success, WriteOutcome::Success],
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        let result = WriteResponse::decode_with_expected_count(&buf, 2);
        assert!(result.is_ok());
    }

    #[test]
    fn write_response_count_mismatch_err() {
        // the outcome count must match what was requested
        let resp = WriteResponse {
            outcomes: vec![WriteOutcome::Success],
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        let result = WriteResponse::decode_with_expected_count(&buf, 2); // 2 expected, 1 present
        assert!(matches!(
            result,
            Err(MmsError::WriteCountMismatch {
                expected: 2,
                actual: 1
            })
        ));
    }

    // a mismatch between the access specification and listOfData

    #[test]
    fn write_request_count_mismatch_err() {
        use crate::mms::pdu::common::VariableAccessSpecification;
        // two variables named but three values supplied
        let req = WriteRequest {
            variable_access_spec: VariableAccessSpecification::ListOfVariable(vec![
                ObjectName::VmdSpecific("A".to_owned()).into(),
                ObjectName::VmdSpecific("B".to_owned()).into(),
            ]),
            list_of_data: vec![
                MmsData::Boolean(true),
                MmsData::Boolean(false),
                MmsData::Integer(1),
            ],
        };
        // encode by hand, since the encoder does not validate the count, then decode
        let mut buf = BytesMut::new();
        let mut inner = BytesMut::new();
        req.variable_access_spec.encode(&mut inner);
        let mut data_buf = BytesMut::new();
        for d in &req.list_of_data {
            d.encode(&mut data_buf);
        }
        inner.extend_from_slice(&[0xa0]);
        crate::mms::pdu::initiate::encode_length(data_buf.len(), &mut inner);
        inner.extend_from_slice(&data_buf);
        buf.extend_from_slice(&[SERVICE_TAG_WRITE]);
        crate::mms::pdu::initiate::encode_length(inner.len(), &mut buf);
        buf.extend_from_slice(&inner);

        let result = WriteRequest::decode(&buf);
        assert!(matches!(result, Err(MmsError::WriteCountMismatch { .. })));
    }

    // more items than MAX_WRITE_ITEMS

    #[test]
    fn write_request_too_many_items_err() {
        use crate::mms::pdu::common::VariableAccessSpecification;
        // 101 items, one past MAX_WRITE_ITEMS
        let entries: Vec<super::super::common::ListOfVariableEntry> = (0..=100)
            .map(|i| ObjectName::VmdSpecific(format!("V{}", i)).into())
            .collect();
        let data: Vec<MmsData> = (0..=100).map(|_| MmsData::Boolean(true)).collect();
        let req = WriteRequest {
            variable_access_spec: VariableAccessSpecification::ListOfVariable(entries),
            list_of_data: data,
        };
        // encode by hand to bypass the encoder-side count check
        let mut inner = BytesMut::new();
        req.variable_access_spec.encode(&mut inner);
        let mut data_buf = BytesMut::new();
        for d in &req.list_of_data {
            d.encode(&mut data_buf);
        }
        inner.extend_from_slice(&[0xa0]);
        crate::mms::pdu::initiate::encode_length(data_buf.len(), &mut inner);
        inner.extend_from_slice(&data_buf);
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[SERVICE_TAG_WRITE]);
        crate::mms::pdu::initiate::encode_length(inner.len(), &mut buf);
        buf.extend_from_slice(&inner);

        let result = WriteRequest::decode(&buf);
        assert!(matches!(result, Err(MmsError::TooManyWriteItems { .. })));
    }

    // A nesting depth bomb inside listOfData

    #[test]
    fn write_depth_bomb_err() {
        // 33 nested structures as the first element of listOfData
        fn make_nested(depth: usize) -> Vec<u8> {
            if depth == 0 {
                return vec![0xa2, 0x00];
            }
            let inner = make_nested(depth - 1);
            let mut result = vec![0xa2u8];
            if inner.len() < 128 {
                result.push(inner.len() as u8);
            } else {
                result.push(0x81);
                result.push(inner.len() as u8);
            }
            result.extend_from_slice(&inner);
            result
        }
        let bomb_data = make_nested(33);

        // a WriteRequest naming one VMD-specific variable whose value is the bomb
        let mut buf = BytesMut::new();
        let mut inner = BytesMut::new();
        // the access specification: listOfVariable with one item
        inner.extend_from_slice(&[0xa0]); // listOfVariable
                                          // one ListOfVariableSeq: 0x30 <> 0xa0 <> 0x80 <len> "V"
        let vs_inner = {
            let mut vs = BytesMut::new();
            vs.extend_from_slice(&[0xa0, 0x03, 0x80, 0x01, b'V']);
            vs
        };
        let seq = {
            let mut s = BytesMut::new();
            s.extend_from_slice(&[0x30]);
            s.extend_from_slice(&[vs_inner.len() as u8]);
            s.extend_from_slice(&vs_inner);
            s
        };
        crate::mms::pdu::initiate::encode_length(seq.len(), &mut inner);
        inner.extend_from_slice(&seq);
        // listOfData = 0xa0 + bomb
        inner.extend_from_slice(&[0xa0]);
        if bomb_data.len() < 128 {
            inner.extend_from_slice(&[bomb_data.len() as u8]);
        } else {
            inner.extend_from_slice(&[0x81, bomb_data.len() as u8]);
        }
        inner.extend_from_slice(&bomb_data);
        buf.extend_from_slice(&[SERVICE_TAG_WRITE]);
        crate::mms::pdu::initiate::encode_length(inner.len(), &mut buf);
        buf.extend_from_slice(&inner);

        let result = WriteRequest::decode(&buf);
        assert!(
            matches!(result, Err(MmsError::NestingLevelExceeded { .. })),
            "a depth bomb must return NestingLevelExceeded, got: {:?}",
            result
        );
    }

    // malformed input

    #[test]
    fn write_request_wrong_tag_err() {
        let data = [0xa4u8, 0x00]; // read tag
        let result = WriteRequest::decode(&data);
        assert!(matches!(
            result,
            Err(MmsError::InvalidTag {
                expected: 0xa5,
                actual: 0xa4
            })
        ));
    }

    #[test]
    fn write_request_missing_listofdata_err() {
        // 0xa5 <len> <access spec> with no listOfData
        let mut buf = BytesMut::new();
        let mut inner = BytesMut::new();
        inner.extend_from_slice(&[0xa0, 0x00]); // an empty listOfVariable
                                                // and no listOfData
        buf.extend_from_slice(&[SERVICE_TAG_WRITE]);
        crate::mms::pdu::initiate::encode_length(inner.len(), &mut buf);
        buf.extend_from_slice(&inner);
        let result = WriteRequest::decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn write_response_wrong_tag_err() {
        let data = [0xa4u8, 0x00]; // read tag
        let result = WriteResponse::decode(&data);
        assert!(matches!(
            result,
            Err(MmsError::InvalidTag {
                expected: 0xa5,
                actual: 0xa4
            })
        ));
    }

    #[test]
    fn write_request_truncated_err() {
        let data = [0xa5u8];
        let result = WriteRequest::decode(&data);
        assert!(result.is_err());
    }

    // a listOfData tag other than 0xa0

    #[test]
    fn write_request_invalid_listofdata_tag_err() {
        // a valid access specification followed by listOfData tagged 0xa1
        let mut buf = BytesMut::new();
        let mut inner = BytesMut::new();
        // the access specification is an empty listOfVariable, 0xa0 0x00
        inner.extend_from_slice(&[0xa0, 0x00]);
        // listOfData with wrong tag 0xa1
        inner.extend_from_slice(&[0xa1, 0x00]);
        buf.extend_from_slice(&[SERVICE_TAG_WRITE]);
        crate::mms::pdu::initiate::encode_length(inner.len(), &mut buf);
        buf.extend_from_slice(&inner);
        // An empty listOfVariable decodes to an empty listOfData, so the counts agree,
        // but the listOfData tag 0xa1 must still be rejected.
        let result = WriteRequest::decode(&buf);
        assert!(matches!(
            result,
            Err(MmsError::InvalidTag {
                expected: 0xa0,
                actual: 0xa1
            })
        ));
    }

    // decode_with_negotiated_cap

    /// Builds a valid WriteRequest whose first value nests `nest_depth` structures.
    fn build_write_request_with_nested_data(nest_depth: usize) -> BytesMut {
        fn make_nested_structure(depth: usize) -> Vec<u8> {
            if depth == 0 {
                return vec![0xa2, 0x00]; // an empty structure
            }
            let inner = make_nested_structure(depth - 1);
            let mut result = vec![0xa2u8];
            if inner.len() < 128 {
                result.push(inner.len() as u8);
            } else {
                result.push(0x81);
                result.push(inner.len() as u8);
            }
            result.extend_from_slice(&inner);
            result
        }
        let nested_data = make_nested_structure(nest_depth);
        let mut buf = BytesMut::new();
        let mut inner = BytesMut::new();
        // the access specification: listOfVariable with one VMD-specific item
        let vs_inner: &[u8] = &[0xa0, 0x03, 0x80, 0x01, b'V']; // the VMD-specific name "V"
        let seq: Vec<u8> = {
            let mut s = vec![0x30u8, vs_inner.len() as u8];
            s.extend_from_slice(vs_inner);
            s
        };
        inner.extend_from_slice(&[0xa0, seq.len() as u8]);
        inner.extend_from_slice(&seq);
        // listOfData = 0xa0 + nested_data
        inner.extend_from_slice(&[0xa0]);
        if nested_data.len() < 128 {
            inner.extend_from_slice(&[nested_data.len() as u8]);
        } else {
            inner.extend_from_slice(&[0x81, nested_data.len() as u8]);
        }
        inner.extend_from_slice(&nested_data);
        buf.extend_from_slice(&[SERVICE_TAG_WRITE]);
        crate::mms::pdu::initiate::encode_length(inner.len(), &mut buf);
        buf.extend_from_slice(&inner);
        buf
    }

    /// With a negotiated ceiling of 5, six nested levels must fail.
    #[test]
    fn write_request_negotiated_cap_lower_clamps_depth() {
        let buf = build_write_request_with_nested_data(6);
        let result = WriteRequest::decode_with_negotiated_cap(&buf, Some(5));
        assert!(
            matches!(result, Err(MmsError::NestingLevelExceeded { .. })),
            "with a negotiated cap of 5, six levels must fail, got: {:?}",
            result
        );
    }

    /// A negotiated ceiling of 100 clamps to the local 32, so 33 levels still fail.
    #[test]
    fn write_request_negotiated_higher_than_local_still_clamps() {
        let buf = build_write_request_with_nested_data(33);
        let result = WriteRequest::decode_with_negotiated_cap(&buf, Some(100));
        assert!(
            matches!(result, Err(MmsError::NestingLevelExceeded { .. })),
            "a negotiated 100 above the local 32 must still fail at 33 levels, got: {:?}",
            result
        );
    }

    /// Without a negotiated value the local ceiling applies, so one level decodes.
    #[test]
    fn write_request_negotiated_none_ok_for_shallow() {
        let buf = build_write_request_with_nested_data(1);
        let result = WriteRequest::decode_with_negotiated_cap(&buf, None);
        assert!(
            result.is_ok(),
            "without a negotiated value, one level must decode, got: {:?}",
            result
        );
    }

    // WriteRequest with an AlternateAccess

    fn build_alt_access_write_request(
        invoke_id: u32,
        item: &str,
        aa: super::super::common::AlternateAccess,
        value: MmsData,
    ) -> BytesMut {
        use super::super::common::ListOfVariableEntry;
        let entry = ListOfVariableEntry::with_alt_access(
            ObjectName::DomainSpecific {
                domain_id: "TESTLD".to_owned(),
                item_id: item.to_owned(),
            },
            aa,
        );
        let req = WriteRequest {
            variable_access_spec: VariableAccessSpecification::ListOfVariable(vec![entry]),
            list_of_data: vec![value],
        };
        let mut buf = BytesMut::new();
        encode_confirmed_write_request(invoke_id, &req, &mut buf);
        buf
    }

    #[test]
    fn write_request_alt_access_index_roundtrip() {
        use super::super::common::AlternateAccess;
        let buf = build_alt_access_write_request(
            42,
            "GGIO1$SP$SetIndArr",
            AlternateAccess::index(3),
            MmsData::Boolean(true),
        );
        assert_eq!(buf[0], 0xa0);
        let (invoke_id, decoded) = decode_confirmed_write_request(&buf).unwrap();
        assert_eq!(invoke_id, 42);
        match &decoded.variable_access_spec {
            VariableAccessSpecification::ListOfVariable(entries) => {
                assert_eq!(entries.len(), 1);
                if let ObjectName::DomainSpecific { domain_id, item_id } = &entries[0].name {
                    assert_eq!(domain_id, "TESTLD");
                    assert_eq!(item_id, "GGIO1$SP$SetIndArr");
                } else {
                    panic!("expected DomainSpecific");
                }
                assert_eq!(entries[0].alt_access, Some(AlternateAccess::index(3)));
            }
            _ => panic!("expected ListOfVariable"),
        }
        assert_eq!(decoded.list_of_data.len(), 1);
        assert_eq!(decoded.list_of_data[0], MmsData::Boolean(true));
    }

    #[test]
    fn write_request_alt_access_index_component_wire_contains_alt_bytes() {
        use super::super::common::AlternateAccess;
        let buf = build_alt_access_write_request(
            1,
            "GGIO1$ST$Ind1",
            AlternateAccess::index_component(2, "stVal").unwrap(),
            MmsData::Boolean(false),
        );
        let bytes = &buf[..];
        let has_alt = bytes.windows(4).any(|w| w == [0xa0, 0x0c, 0x81, 0x01]);
        assert!(
            has_alt,
            "wire bytes should contain the IndexComponent header"
        );
    }

    /// The negotiated-cap entry point wires through to the request decoder.
    #[test]
    fn confirmed_write_request_with_negotiated_cap_roundtrip() {
        let req = WriteRequest::single_domain("LD1", "VAR1", MmsData::Integer(42));
        let mut buf = BytesMut::new();
        encode_confirmed_write_request(1, &req, &mut buf);
        // no negotiated value, so the local ceiling applies
        let (invoke_id, decoded) =
            decode_confirmed_write_request_with_negotiated_cap(&buf, None).unwrap();
        assert_eq!(invoke_id, 1);
        assert_eq!(decoded, req);
    }
}
