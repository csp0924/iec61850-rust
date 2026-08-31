//! MMS DeleteNamedVariableList request and response PDUs.
//!
//! ## Wire format
//!
//! `ConfirmedServiceRequest.deleteNamedVariableList` is CONTEXT `[13]` IMPLICIT
//! SEQUENCE, so the outermost tag is `0x80 | 0x20 | 13`, that is `0xad`.
//!
//! ```text
//! 0xa0 <len>           -- MmsPdu [0] confirmedRequestPdu
//!   0x02 <len> <id>    -- invokeID
//!   0xad <len>         -- deleteNamedVariableList [13] IMPLICIT SEQUENCE
//!     [0x80 <int>]     -- scopeOfDelete [0] IMPLICIT INTEGER (DEFAULT 0=specific)
//!     [0xa1 <len>]     -- listOfVariableListName [1] IMPLICIT SEQUENCE OF ObjectName
//!     [0x82 <len> <s>] -- domainName [2] IMPLICIT VisibleString OPTIONAL
//! ```
//!
//! The response is CONTEXT `[13]` IMPLICIT SEQUENCE:
//!
//! ```text
//! 0xa1 <len>           -- MmsPdu [1] confirmedResponsePdu
//!   0x02 <len> <id>    -- invokeID
//!   0xad <len>         -- deleteNamedVariableList [13] IMPLICIT SEQUENCE
//!     0x80 <int>       -- numberMatched [0] IMPLICIT Unsigned32
//!     0x81 <int>       -- numberDeleted [1] IMPLICIT Unsigned32
//! ```

use super::super::error::MmsError;
use super::common::ObjectName;
use super::initiate::{decode_length, encode_length};
use crate::compat::prelude::*;
use bytes::BytesMut;

// Tag constants

/// Tag of DeleteNamedVariableList inside the ConfirmedService CHOICE.
/// CONTEXT `[13]` IMPLICIT CONSTRUCTED, that is `0xad`.
pub const SERVICE_TAG_DELETE_NAMED_VARIABLE_LIST: u8 = 0xad;

/// Outer tag of listOfVariableListName `[1]` IMPLICIT.
const TAG_LIST_OF_NAMES: u8 = 0xa1;

/// Tag of scopeOfDelete `[0]` IMPLICIT INTEGER.
const TAG_SCOPE_OF_DELETE: u8 = 0x80;

/// Tag of domainName `[2]` IMPLICIT VisibleString.
const TAG_DOMAIN_NAME: u8 = 0x82;

// ScopeOfDelete enum

/// The scopeOfDelete alternatives.
///
/// `Specific` is the common case and names the data sets to delete. The broader
/// scopes, `AaSpecific`, `Domain` and `Vmd`, are served on a best-effort basis: the
/// server enumerates every dynamic data set, and a request carrying no
/// listOfVariableListName is legal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ScopeOfDelete {
    /// 0, specific: the data sets to delete are listed in listOfVariableListName.
    #[default]
    Specific = 0,
    /// 1 = aa-specific
    AaSpecific = 1,
    /// 2 = domain
    Domain = 2,
    /// 3 = vmd
    Vmd = 3,
}

impl ScopeOfDelete {
    /// Returns the INTEGER value written on the wire.
    pub fn wire_value(self) -> u8 {
        self as u8
    }

    /// Converts a scope value from the wire, rejecting an undefined one.
    pub fn from_wire(v: u8) -> Result<Self, MmsError> {
        match v {
            0 => Ok(Self::Specific),
            1 => Ok(Self::AaSpecific),
            2 => Ok(Self::Domain),
            3 => Ok(Self::Vmd),
            other => {
                tracing::warn!(
                    "unknown deletenamedvariablelist scopeofdelete value {}",
                    other
                );
                // reuse the existing variant; an out-of-range wire value shares its message
                Err(MmsError::DefineNamedVariableListMissingField(
                    "scopeOfDelete out of range",
                ))
            }
        }
    }
}

// Request

#[derive(Debug, Clone, PartialEq, Eq, Default)]
/// An MMS DeleteNamedVariableListRequest.
pub struct DeleteNamedVariableListRequest {
    /// scopeOfDelete, OPTIONAL with DEFAULT specific.
    pub scope_of_delete: ScopeOfDelete,
    /// Data sets to delete, OPTIONAL; an empty vector omits listOfVariableListName.
    pub list_of_variable_list_name: Vec<ObjectName>,
    /// Optional domain filter, used when the scope is Domain.
    pub domain_name: Option<String>,
}

impl DeleteNamedVariableListRequest {
    /// Builds a specific-scope request deleting one domain-specific data set.
    pub fn specific_domain(domain_id: impl Into<String>, list_name: impl Into<String>) -> Self {
        Self {
            scope_of_delete: ScopeOfDelete::Specific,
            list_of_variable_list_name: vec![ObjectName::DomainSpecific {
                domain_id: domain_id.into(),
                item_id: list_name.into(),
            }],
            domain_name: None,
        }
    }

    /// Encodes the request, including the `0xad <len>` service wrapper.
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut inner = BytesMut::new();

        // scopeOfDelete [0] IMPLICIT INTEGER. The default value 0 is still written,
        // because a BER INTEGER 0 is one byte in minimal form and peers expect the field.
        let scope = self.scope_of_delete.wire_value();
        inner.extend_from_slice(&[TAG_SCOPE_OF_DELETE, 0x01, scope]);

        // listOfVariableListName [1] IMPLICIT SEQUENCE OF ObjectName, OPTIONAL
        if !self.list_of_variable_list_name.is_empty() {
            let mut names_buf = BytesMut::new();
            for name in &self.list_of_variable_list_name {
                name.encode(&mut names_buf);
            }
            inner.extend_from_slice(&[TAG_LIST_OF_NAMES]);
            encode_length(names_buf.len(), &mut inner);
            inner.extend_from_slice(&names_buf);
        }

        // domainName [2] IMPLICIT VisibleString OPTIONAL
        if let Some(d) = self.domain_name.as_deref() {
            let b = d.as_bytes();
            inner.extend_from_slice(&[TAG_DOMAIN_NAME]);
            encode_length(b.len(), &mut inner);
            inner.extend_from_slice(b);
        }

        buf.extend_from_slice(&[SERVICE_TAG_DELETE_NAMED_VARIABLE_LIST]);
        encode_length(inner.len(), buf);
        buf.extend_from_slice(&inner);
    }

    /// Decodes a request; `data` starts at the `0xad` byte.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        if data[0] != SERVICE_TAG_DELETE_NAMED_VARIABLE_LIST {
            return Err(MmsError::InvalidTag {
                expected: SERVICE_TAG_DELETE_NAMED_VARIABLE_LIST,
                actual: data[0],
            });
        }
        let (inner_len, hdr) = decode_length(&data[1..])?;
        let inner_start = 1 + hdr;
        if inner_start + inner_len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let inner = &data[inner_start..inner_start + inner_len];
        decode_request_inner(inner)
    }
}

fn decode_request_inner(data: &[u8]) -> Result<DeleteNamedVariableListRequest, MmsError> {
    let mut req = DeleteNamedVariableListRequest::default();
    let mut pos = 0usize;
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
            TAG_SCOPE_OF_DELETE => {
                if val.is_empty() {
                    return Err(MmsError::InvalidLength);
                }
                req.scope_of_delete = ScopeOfDelete::from_wire(val[0])?;
            }
            TAG_LIST_OF_NAMES => {
                let mut names = Vec::new();
                let mut p = 0usize;
                while p < val.len() {
                    let (n, used) = ObjectName::decode(&val[p..])?;
                    names.push(n);
                    p += used;
                }
                req.list_of_variable_list_name = names;
            }
            TAG_DOMAIN_NAME => {
                let s = core::str::from_utf8(val)
                    .map_err(|_| MmsError::InvalidUtf8)?
                    .to_owned();
                req.domain_name = Some(s);
            }
            other => {
                tracing::debug!(
                    "skipping unknown deletenamedvariablelist tag 0x{:02X}",
                    other
                );
            }
        }
    }
    Ok(req)
}

// Response

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
/// An MMS DeleteNamedVariableListResponse.
pub struct DeleteNamedVariableListResponse {
    /// Number of data sets that matched the request.
    pub number_matched: u32,
    /// Number of data sets actually deleted.
    pub number_deleted: u32,
}

impl DeleteNamedVariableListResponse {
    /// Encodes the complete response, including `0xad <len>`.
    pub fn encode(&self, buf: &mut BytesMut) {
        use super::common::encode_unsigned_int_minimal;
        let mut inner = BytesMut::new();

        let mb = encode_unsigned_int_minimal(self.number_matched as u64);
        inner.extend_from_slice(&[0x80]);
        encode_length(mb.len(), &mut inner);
        inner.extend_from_slice(&mb);

        let db = encode_unsigned_int_minimal(self.number_deleted as u64);
        inner.extend_from_slice(&[0x81]);
        encode_length(db.len(), &mut inner);
        inner.extend_from_slice(&db);

        buf.extend_from_slice(&[SERVICE_TAG_DELETE_NAMED_VARIABLE_LIST]);
        encode_length(inner.len(), buf);
        buf.extend_from_slice(&inner);
    }

    /// Decodes a response; `data` starts at the `0xad` byte.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        if data[0] != SERVICE_TAG_DELETE_NAMED_VARIABLE_LIST {
            return Err(MmsError::InvalidTag {
                expected: SERVICE_TAG_DELETE_NAMED_VARIABLE_LIST,
                actual: data[0],
            });
        }
        let (inner_len, hdr) = decode_length(&data[1..])?;
        let inner_start = 1 + hdr;
        if inner_start + inner_len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let inner = &data[inner_start..inner_start + inner_len];

        let mut number_matched = 0u32;
        let mut number_deleted = 0u32;
        let mut pos = 0usize;
        while pos < inner.len() {
            let tag = inner[pos];
            let (len, hdr) = decode_length(&inner[pos + 1..])?;
            let val_start = pos + 1 + hdr;
            if val_start + len > inner.len() {
                return Err(MmsError::TruncatedPdu);
            }
            let val = &inner[val_start..val_start + len];
            pos = val_start + len;

            match tag {
                0x80 => number_matched = decode_u32(val)?,
                0x81 => number_deleted = decode_u32(val)?,
                _ => {}
            }
        }

        Ok(Self {
            number_matched,
            number_deleted,
        })
    }
}

fn decode_u32(data: &[u8]) -> Result<u32, MmsError> {
    if data.is_empty() || data.len() > 4 {
        return Err(MmsError::InvalidLength);
    }
    let mut v = 0u32;
    for &b in data {
        v = (v << 8) | (b as u32);
    }
    Ok(v)
}

// ConfirmedRequest and ConfirmedResponse wrappers

/// Encodes the request as a complete ConfirmedRequestPdu, outer `0xa0` included.
pub fn encode_confirmed_delete_named_variable_list_request(
    invoke_id: u32,
    req: &DeleteNamedVariableListRequest,
    buf: &mut BytesMut,
) {
    let mut inner = BytesMut::new();
    encode_invoke_id(invoke_id, &mut inner);
    req.encode(&mut inner);

    buf.extend_from_slice(&[0xa0]);
    encode_length(inner.len(), buf);
    buf.extend_from_slice(&inner);
}

/// Encodes the response as a complete ConfirmedResponsePdu, outer `0xa1` included.
pub fn encode_confirmed_delete_named_variable_list_response(
    invoke_id: u32,
    resp: &DeleteNamedVariableListResponse,
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
pub fn decode_confirmed_delete_named_variable_list_request(
    data: &[u8],
) -> Result<(u32, DeleteNamedVariableListRequest), MmsError> {
    let (invoke_id, service_data) = decode_confirmed_pdu_inner(data, 0xa0)?;
    let req = DeleteNamedVariableListRequest::decode(service_data)?;
    Ok((invoke_id, req))
}

/// Decodes the response inside a ConfirmedResponsePdu; `data` starts at `0xa1`.
pub fn decode_confirmed_delete_named_variable_list_response(
    data: &[u8],
) -> Result<(u32, DeleteNamedVariableListResponse), MmsError> {
    let (invoke_id, service_data) = decode_confirmed_pdu_inner(data, 0xa1)?;
    let resp = DeleteNamedVariableListResponse::decode(service_data)?;
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
    if id_val.is_empty() || id_val.len() > 4 {
        return Err(MmsError::InvalidLength);
    }
    let mut invoke_id = 0u32;
    for &b in id_val {
        invoke_id = (invoke_id << 8) | (b as u32);
    }
    let service_start = id_start + id_len;
    Ok((invoke_id, &inner[service_start..]))
}

// Unit tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_specific_round_trip() {
        let req = DeleteNamedVariableListRequest::specific_domain("IED1LD0", "GGIO1$ds1");
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        assert_eq!(buf[0], SERVICE_TAG_DELETE_NAMED_VARIABLE_LIST);

        let decoded = DeleteNamedVariableListRequest::decode(&buf).unwrap();
        assert_eq!(decoded, req);
        assert_eq!(decoded.scope_of_delete, ScopeOfDelete::Specific);
        assert_eq!(decoded.list_of_variable_list_name.len(), 1);
    }

    #[test]
    fn confirmed_request_round_trip_via_pdu_wrapper() {
        let req = DeleteNamedVariableListRequest::specific_domain("IED1LD0", "GGIO1$ds1");
        let mut buf = BytesMut::new();
        encode_confirmed_delete_named_variable_list_request(99, &req, &mut buf);
        assert_eq!(buf[0], 0xa0);

        let (invoke_id, decoded) =
            decode_confirmed_delete_named_variable_list_request(&buf).unwrap();
        assert_eq!(invoke_id, 99);
        assert_eq!(decoded, req);
    }

    #[test]
    fn response_round_trip() {
        let resp = DeleteNamedVariableListResponse {
            number_matched: 3,
            number_deleted: 2,
        };
        let mut buf = BytesMut::new();
        encode_confirmed_delete_named_variable_list_response(7, &resp, &mut buf);
        assert_eq!(buf[0], 0xa1);
        let (invoke_id, decoded) =
            decode_confirmed_delete_named_variable_list_response(&buf).unwrap();
        assert_eq!(invoke_id, 7);
        assert_eq!(decoded, resp);
    }

    #[test]
    fn empty_buffer_rejected() {
        assert!(matches!(
            DeleteNamedVariableListRequest::decode(&[]),
            Err(MmsError::TruncatedPdu)
        ));
    }

    #[test]
    fn wrong_tag_rejected() {
        let bad = [0xab, 0x00];
        assert!(matches!(
            DeleteNamedVariableListRequest::decode(&bad),
            Err(MmsError::InvalidTag { .. })
        ));
    }

    #[test]
    fn truncated_inner_rejected() {
        let bad = [SERVICE_TAG_DELETE_NAMED_VARIABLE_LIST, 0x10, 0x00];
        assert!(matches!(
            DeleteNamedVariableListRequest::decode(&bad),
            Err(MmsError::TruncatedPdu)
        ));
    }

    #[test]
    fn batch_delete_two_names() {
        let req = DeleteNamedVariableListRequest {
            scope_of_delete: ScopeOfDelete::Specific,
            list_of_variable_list_name: vec![
                ObjectName::DomainSpecific {
                    domain_id: "D1".into(),
                    item_id: "ds1".into(),
                },
                ObjectName::DomainSpecific {
                    domain_id: "D1".into(),
                    item_id: "ds2".into(),
                },
            ],
            domain_name: None,
        };
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let decoded = DeleteNamedVariableListRequest::decode(&buf).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn response_zero_numbers_round_trip() {
        let resp = DeleteNamedVariableListResponse {
            number_matched: 0,
            number_deleted: 0,
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        let decoded = DeleteNamedVariableListResponse::decode(&buf).unwrap();
        assert_eq!(decoded, resp);
    }
}
