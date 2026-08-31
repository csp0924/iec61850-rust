//! MMS GetNameList request and response PDUs, per ISO 9506-2.
//!
//! ## Wire format
//!
//! Inside the `ConfirmedServiceRequest` CHOICE:
//! - getNameList is CONTEXT `[1]` IMPLICIT CONSTRUCTED, tag `0xa1`
//!
//! A GetNameListRequest inside a ConfirmedRequestPdu:
//! ```text
//! 0xa0 <len>           -- MmsPdu [0] confirmedRequestPdu
//!   0x02 <len> <id>    -- invokeID INTEGER
//!   0xa1 <len>         -- getNameList [1] IMPLICIT, a GetNameListRequest SEQUENCE
//!     0xa0 <len>       -- objectClass [0] EXPLICIT
//!       0x80 0x01 <v>  -- basicObjectClass [0] IMPLICIT INTEGER
//!     0xa1 <len>       -- objectScope [1] EXPLICIT CHOICE
//!       0x80 0x00      -- vmdSpecific [0] IMPLICIT NULL
//!       OR 0x81 <len> <bytes>  -- domainSpecific [1] IMPLICIT VisibleString
//!       OR 0x82 0x00   -- aaSpecific [2] IMPLICIT NULL
//!     [0x82 <len> <s>] -- continueAfter [2] IMPLICIT VisibleString OPTIONAL
//! ```
//!
//! A GetNameListResponse inside a ConfirmedResponsePdu:
//! ```text
//! 0xa1 <len>           -- MmsPdu [1] confirmedResponsePdu
//!   0x02 <len> <id>    -- invokeID INTEGER
//!   0xa1 <len>         -- getNameList [1] IMPLICIT, a GetNameListResponse SEQUENCE
//!     0xa0 <len>       -- listOfIdentifier [0] IMPLICIT SEQUENCE OF
//!       [0x1a <l> <s>] -- Identifier (UNIVERSAL VisibleString) x N
//!     [0x81 0x01 0x00] -- moreFollows [1] IMPLICIT BOOLEAN OPTIONAL, written only when false
//! ```
//!
//! ## Validation
//!
//! Inside the objectClass `0xa0` wrapper the inner tag must be `0x80`,
//! basicObjectClass; any other tag returns `MmsError::InvalidPdu` rather than being
//! accepted.

use super::super::error::MmsError;
use super::initiate::{decode_length, encode_length};
use crate::compat::prelude::*;
use bytes::BytesMut;

// Tag constants

/// Tag of GetNameList inside the ConfirmedService CHOICE.
/// getNameList is CONTEXT `[1]`, that is `0xa1`, per the ISO 9506-2 CHOICE.
pub const SERVICE_TAG_GET_NAME_LIST: u8 = 0xa1;

/// Largest accepted continueAfter length in bytes; 129 bytes are still valid and
/// anything longer is rejected as an invalid PDU.
pub const MAX_CONTINUE_AFTER_LEN: usize = 129;

/// Largest accepted domainName length in bytes.
pub const MAX_DOMAIN_NAME_LEN: usize = 64;

// ObjectClass enum

/// MMS ObjectClass, per ISO 9506-2.
///
/// Only the four classes this implementation serves are listed. The other defined
/// values, 1, 3 to 7 and 10 to 13, decode at the PDU layer but the server answers
/// them with object-access-unsupported; a value outside the standard returns
/// `MmsError::UnsupportedObjectClass`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectClass {
    /// 0 = namedVariable
    NamedVariable = 0,
    /// 2 = namedVariableList
    NamedVariableList = 2,
    /// 8 = journal
    Journal = 8,
    /// 9 = domain
    Domain = 9,
}

impl ObjectClass {
    /// Returns the INTEGER byte written on the wire.
    pub fn wire_value(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u32> for ObjectClass {
    type Error = MmsError;

    /// Converts an INTEGER value from the wire.
    ///
    /// Values that are defined by the standard but not served here also return an
    /// error, which the service layer turns into object-access-unsupported.
    fn try_from(v: u32) -> Result<Self, MmsError> {
        match v {
            0 => Ok(ObjectClass::NamedVariable),
            2 => Ok(ObjectClass::NamedVariableList),
            8 => Ok(ObjectClass::Journal),
            9 => Ok(ObjectClass::Domain),
            other => {
                tracing::warn!("getnamelist objectclass {} is not supported", other);
                Err(MmsError::UnsupportedObjectClass(other))
            }
        }
    }
}

// ObjectScope enum

/// The GetNameList objectScope CHOICE.
///
/// Wire tags:
/// - `0x80`: vmdSpecific, CONTEXT `[0]` IMPLICIT NULL with length 0
/// - `0x81`: domainSpecific, CONTEXT `[1]` IMPLICIT VisibleString
/// - `0x82`: aaSpecific, CONTEXT `[2]` IMPLICIT NULL with length 0
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectScope {
    /// vmd-specific: the whole VMD.
    VmdSpecific,
    /// domain-specific: one domain, named by a VisibleString.
    DomainSpecific(String),
    /// aa-specific: the scope of this association.
    AaSpecific,
}

// GetNameListRequest

/// An MMS GetNameListRequest, per ISO 9506-2.
///
/// - `objectClass`: `[0]` EXPLICIT wrapping basicObjectClass `[0]` IMPLICIT INTEGER
/// - `objectScope`: `[1]` EXPLICIT CHOICE of vmdSpecific, domainSpecific or aaSpecific
/// - `continueAfter`: `[2]` IMPLICIT VisibleString, OPTIONAL, the paging cursor
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetNameListRequest {
    /// Class of object to enumerate.
    pub object_class: ObjectClass,
    /// Scope to enumerate: the VMD, one domain, or the association.
    pub object_scope: ObjectScope,
    /// Paging cursor: enumeration resumes after this name.
    pub continue_after: Option<String>,
}

impl GetNameListRequest {
    /// Encodes the request, including the `0xa1 <len>` service wrapper.
    ///
    /// The caller adds the ConfirmedRequestPdu invokeID and its outer `0xa0` wrapper.
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut inner = BytesMut::new();

        // objectClass [0] EXPLICIT SEQUENCE
        //   basicObjectClass [0] IMPLICIT INTEGER
        let class_val = self.object_class.wire_value();
        // inner TLV: 0x80 0x01 <class>
        let class_inner = [0x80u8, 0x01, class_val];
        // outer wrapper: 0xa0 0x03
        inner.extend_from_slice(&[0xa0, class_inner.len() as u8]);
        inner.extend_from_slice(&class_inner);

        // objectScope [1] EXPLICIT SEQUENCE
        let mut scope_inner = BytesMut::new();
        match &self.object_scope {
            ObjectScope::VmdSpecific => {
                // vmdSpecific [0] IMPLICIT NULL: 0x80 0x00
                scope_inner.extend_from_slice(&[0x80, 0x00]);
            }
            ObjectScope::DomainSpecific(domain) => {
                // domainSpecific [1] IMPLICIT VisibleString: 0x81 <len> <bytes>
                let db = domain.as_bytes();
                scope_inner.extend_from_slice(&[0x81]);
                encode_length(db.len(), &mut scope_inner);
                scope_inner.extend_from_slice(db);
            }
            ObjectScope::AaSpecific => {
                // aaSpecific [2] IMPLICIT NULL: 0x82 0x00
                scope_inner.extend_from_slice(&[0x82, 0x00]);
            }
        }
        inner.extend_from_slice(&[0xa1]);
        encode_length(scope_inner.len(), &mut inner);
        inner.extend_from_slice(&scope_inner);

        // continueAfter [2] IMPLICIT VisibleString, OPTIONAL
        if let Some(ref ca) = self.continue_after {
            let cb = ca.as_bytes();
            inner.extend_from_slice(&[0x82]);
            encode_length(cb.len(), &mut inner);
            inner.extend_from_slice(cb);
        }

        buf.extend_from_slice(&[SERVICE_TAG_GET_NAME_LIST]);
        encode_length(inner.len(), buf);
        buf.extend_from_slice(&inner);
    }

    /// Decodes a request; `data` starts at the `0xa1` service tag.
    ///
    /// The objectClass inner tag must be `0x80`; any other value returns
    /// `MmsError::InvalidPdu`.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        if data[0] != SERVICE_TAG_GET_NAME_LIST {
            return Err(MmsError::InvalidTag {
                expected: SERVICE_TAG_GET_NAME_LIST,
                actual: data[0],
            });
        }
        let (inner_len, hdr) = decode_length(&data[1..])?;
        let inner_start = 1 + hdr;
        if inner_start + inner_len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let inner = &data[inner_start..inner_start + inner_len];
        decode_get_name_list_request_inner(inner)
    }
}

/// Decodes the request content: objectClass, objectScope and continueAfter.
fn decode_get_name_list_request_inner(data: &[u8]) -> Result<GetNameListRequest, MmsError> {
    let mut pos = 0usize;
    let mut object_class: Option<ObjectClass> = None;
    let mut object_scope: Option<ObjectScope> = None;
    let mut continue_after: Option<String> = None;

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
            // objectClass [0] EXPLICIT
            0xa0 => {
                // the inner value must be basicObjectClass [0] IMPLICIT INTEGER,
                // so an inner tag other than 0x80 is rejected
                if val.len() < 2 {
                    tracing::warn!("getnamelist objectclass inner value is too short");
                    return Err(MmsError::TruncatedPdu);
                }
                let inner_tag = val[0];
                if inner_tag != 0x80 {
                    tracing::warn!(
                        "getnamelist objectclass inner tag 0x{:02X} is not 0x80 (basicobjectclass)",
                        inner_tag
                    );
                    return Err(MmsError::InvalidPdu);
                }
                let (class_val_len, class_hdr) = decode_length(&val[1..])?;
                let class_val_start = 1 + class_hdr;
                if class_val_start + class_val_len > val.len() {
                    return Err(MmsError::TruncatedPdu);
                }
                let class_bytes = &val[class_val_start..class_val_start + class_val_len];
                // decode the value as a BER INTEGER of 1 to 4 bytes
                let class_int = decode_u32_from_bytes(class_bytes)?;
                let oc = ObjectClass::try_from(class_int)?;
                object_class = Some(oc);
            }
            // objectScope [1] EXPLICIT CHOICE
            0xa1 => {
                let scope = decode_object_scope(val)?;
                object_scope = Some(scope);
            }
            // continueAfter [2] IMPLICIT VisibleString, OPTIONAL
            0x82 => {
                // 130 bytes or more is rejected as an invalid PDU
                if len >= 130 {
                    tracing::warn!(
                        "getnamelist continueafter length {} reaches 130, rejecting",
                        len
                    );
                    return Err(MmsError::InvalidPdu);
                }
                let s = core::str::from_utf8(val)
                    .map_err(|_| MmsError::InvalidUtf8)?
                    .to_owned();
                continue_after = Some(s);
            }
            other => {
                tracing::debug!("skipping unknown getnamelistrequest tag 0x{:02X}", other);
            }
        }
    }

    let object_class = object_class.ok_or(MmsError::TruncatedPdu)?;
    let object_scope = object_scope.ok_or(MmsError::TruncatedPdu)?;

    Ok(GetNameListRequest {
        object_class,
        object_scope,
        continue_after,
    })
}

/// Decodes the objectScope CHOICE; `val` is the content of the `0xa1` wrapper.
fn decode_object_scope(val: &[u8]) -> Result<ObjectScope, MmsError> {
    if val.is_empty() {
        return Err(MmsError::TruncatedPdu);
    }
    let scope_tag = val[0];
    let (scope_len, scope_hdr) = decode_length(&val[1..])?;
    let scope_val_start = 1 + scope_hdr;
    if scope_val_start + scope_len > val.len() {
        return Err(MmsError::TruncatedPdu);
    }
    let scope_val = &val[scope_val_start..scope_val_start + scope_len];

    match scope_tag {
        // vmdSpecific [0] IMPLICIT NULL, length 0
        0x80 => Ok(ObjectScope::VmdSpecific),
        // domainSpecific [1] IMPLICIT VisibleString
        0x81 => {
            // a domain name longer than 64 bytes is rejected as an invalid PDU
            if scope_len > MAX_DOMAIN_NAME_LEN {
                tracing::warn!(
                    "getnamelist domainname length {} exceeds 64, rejecting",
                    scope_len
                );
                return Err(MmsError::InvalidPdu);
            }
            let domain = core::str::from_utf8(scope_val)
                .map_err(|_| MmsError::InvalidUtf8)?
                .to_owned();
            Ok(ObjectScope::DomainSpecific(domain))
        }
        // aaSpecific [2] IMPLICIT NULL, length 0
        0x82 => Ok(ObjectScope::AaSpecific),
        other => {
            tracing::warn!(
                "unknown getnamelist objectscope tag 0x{:02X}, rejecting",
                other
            );
            Err(MmsError::InvalidPdu)
        }
    }
}

// GetNameListResponse

/// An MMS GetNameListResponse, per ISO 9506-2.
///
/// - `listOfIdentifier`: `[0]` IMPLICIT SEQUENCE OF VisibleString, tag `0xa0`
/// - `moreFollows`: `[1]` IMPLICIT BOOLEAN, OPTIONAL with DEFAULT TRUE
///
/// ## moreFollows
///
/// - `true` omits the field, since TRUE is the default
/// - `false` writes `0x81 0x01 0x00`
/// - an absent field decodes as `true`
/// - any non-zero byte decodes as `true`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetNameListResponse {
    /// The identifiers returned, possibly empty.
    pub identifiers: Vec<String>,
    /// Whether more names remain; DEFAULT TRUE, and false marks the last page.
    pub more_follows: bool,
}

impl GetNameListResponse {
    /// Encodes the response, including the `0xa1 <len>` service wrapper.
    ///
    /// moreFollows is written only when false, since TRUE is the default.
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut inner = BytesMut::new();

        // listOfIdentifier [0] IMPLICIT SEQUENCE OF VisibleString
        let mut id_list = BytesMut::new();
        for id in &self.identifiers {
            let ib = id.as_bytes();
            // Identifier tag 0x1a, UNIVERSAL 26 VisibleString, primitive
            id_list.extend_from_slice(&[0x1a]);
            encode_length(ib.len(), &mut id_list);
            id_list.extend_from_slice(ib);
        }
        inner.extend_from_slice(&[0xa0]);
        encode_length(id_list.len(), &mut inner);
        inner.extend_from_slice(&id_list);

        // moreFollows [1] IMPLICIT BOOLEAN, omitted when true
        if !self.more_follows {
            // false is 0x00; 0x81 is CONTEXT [1] IMPLICIT primitive
            inner.extend_from_slice(&[0x81, 0x01, 0x00]);
        }

        buf.extend_from_slice(&[SERVICE_TAG_GET_NAME_LIST]);
        encode_length(inner.len(), buf);
        buf.extend_from_slice(&inner);
    }

    /// Decodes a response; `data` starts at the `0xa1` service tag.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        if data[0] != SERVICE_TAG_GET_NAME_LIST {
            return Err(MmsError::InvalidTag {
                expected: SERVICE_TAG_GET_NAME_LIST,
                actual: data[0],
            });
        }
        let (inner_len, hdr) = decode_length(&data[1..])?;
        let inner_start = 1 + hdr;
        if inner_start + inner_len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let inner = &data[inner_start..inner_start + inner_len];
        decode_get_name_list_response_inner(inner)
    }
}

/// Decodes the response content: listOfIdentifier and moreFollows.
fn decode_get_name_list_response_inner(data: &[u8]) -> Result<GetNameListResponse, MmsError> {
    let mut pos = 0usize;
    let mut identifiers: Option<Vec<String>> = None;
    // moreFollows defaults to true when the field is absent
    let mut more_follows = true;

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
            // listOfIdentifier [0] IMPLICIT SEQUENCE OF VisibleString
            0xa0 => {
                let ids = decode_list_of_identifiers(val)?;
                identifiers = Some(ids);
            }
            // moreFollows [1] IMPLICIT BOOLEAN, DEFAULT TRUE
            0x81 => {
                if val.is_empty() {
                    return Err(MmsError::TruncatedPdu);
                }
                // BER BOOLEAN: any non-zero byte is true
                more_follows = val[0] != 0;
            }
            other => {
                tracing::debug!("skipping unknown getnamelistresponse tag 0x{:02X}", other);
            }
        }
    }

    let identifiers = identifiers.ok_or(MmsError::TruncatedPdu)?;
    Ok(GetNameListResponse {
        identifiers,
        more_follows,
    })
}

/// Decodes listOfIdentifier; `data` is the content of the `0xa0` field.
fn decode_list_of_identifiers(data: &[u8]) -> Result<Vec<String>, MmsError> {
    let mut ids = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let tag = data[pos];
        if tag != 0x1a {
            tracing::warn!(
                "getnamelist listofidentifier expected 0x1a, got 0x{:02X}, skipping",
                tag
            );
            // skip the element and keep parsing the rest of the list
            if pos + 1 >= data.len() {
                break;
            }
            let (skip_len, skip_hdr) = decode_length(&data[pos + 1..])?;
            pos += 1 + skip_hdr + skip_len;
            continue;
        }
        let (id_len, id_hdr) = decode_length(&data[pos + 1..])?;
        let id_start = pos + 1 + id_hdr;
        if id_start + id_len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let id_bytes = &data[id_start..id_start + id_len];
        let id = core::str::from_utf8(id_bytes)
            .map_err(|_| MmsError::InvalidUtf8)?
            .to_owned();
        ids.push(id);
        pos = id_start + id_len;
    }
    Ok(ids)
}

// ConfirmedRequestPdu and ConfirmedResponsePdu wrappers

/// Encodes a GetNameListRequest as a complete ConfirmedRequestPdu, outer `0xa0`
/// tag included.
///
/// Wire format:
/// ```text
/// 0xa0 <len>           -- confirmedRequestPdu [0]
///   0x02 <len> <id>    -- invokeID
///   0xa1 <len>         -- GetNameListRequest
/// ```
pub fn encode_confirmed_get_name_list_request(
    invoke_id: u32,
    req: &GetNameListRequest,
    buf: &mut BytesMut,
) {
    let mut inner = BytesMut::new();
    encode_invoke_id(invoke_id, &mut inner);
    req.encode(&mut inner);

    buf.extend_from_slice(&[0xa0]);
    encode_length(inner.len(), buf);
    buf.extend_from_slice(&inner);
}

/// Encodes a GetNameListResponse as a complete ConfirmedResponsePdu, outer `0xa1`
/// tag included.
pub fn encode_confirmed_get_name_list_response(
    invoke_id: u32,
    resp: &GetNameListResponse,
    buf: &mut BytesMut,
) {
    let mut inner = BytesMut::new();
    encode_invoke_id(invoke_id, &mut inner);
    resp.encode(&mut inner);

    buf.extend_from_slice(&[0xa1]);
    encode_length(inner.len(), buf);
    buf.extend_from_slice(&inner);
}

/// Decodes the GetNameListRequest inside a ConfirmedRequestPdu; `data` starts at
/// the `0xa0` byte.
pub fn decode_confirmed_get_name_list_request(
    data: &[u8],
) -> Result<(u32, GetNameListRequest), MmsError> {
    let (invoke_id, service_data) = decode_confirmed_pdu_inner(data, 0xa0)?;
    let req = GetNameListRequest::decode(service_data)?;
    Ok((invoke_id, req))
}

/// Decodes the GetNameListResponse inside a ConfirmedResponsePdu; `data` starts at
/// the `0xa1` byte.
pub fn decode_confirmed_get_name_list_response(
    data: &[u8],
) -> Result<(u32, GetNameListResponse), MmsError> {
    let (invoke_id, service_data) = decode_confirmed_pdu_inner(data, 0xa1)?;
    let resp = GetNameListResponse::decode(service_data)?;
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
    use super::*;

    // ObjectClass conversion

    #[test]
    fn object_class_try_from_supported_values() {
        assert_eq!(
            ObjectClass::try_from(0u32).unwrap(),
            ObjectClass::NamedVariable
        );
        assert_eq!(
            ObjectClass::try_from(2u32).unwrap(),
            ObjectClass::NamedVariableList
        );
        assert_eq!(ObjectClass::try_from(8u32).unwrap(), ObjectClass::Journal);
        assert_eq!(ObjectClass::try_from(9u32).unwrap(), ObjectClass::Domain);
    }

    #[test]
    fn object_class_try_from_unsupported_returns_err() {
        // values that are defined but not served here
        for v in [1u32, 3, 4, 5, 6, 7, 10] {
            assert!(
                matches!(
                    ObjectClass::try_from(v),
                    Err(MmsError::UnsupportedObjectClass(_))
                ),
                "objectclass {} must return an error",
                v
            );
        }
    }

    // GetNameListRequest encode and decode round trips

    #[test]
    fn request_vmd_named_variable_no_continue_after_roundtrip() {
        let req = GetNameListRequest {
            object_class: ObjectClass::NamedVariable,
            object_scope: ObjectScope::VmdSpecific,
            continue_after: None,
        };
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let decoded = GetNameListRequest::decode(&buf).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_domain_named_variable_with_continue_after_roundtrip() {
        let req = GetNameListRequest {
            object_class: ObjectClass::NamedVariable,
            object_scope: ObjectScope::DomainSpecific("TESTLD".to_string()),
            continue_after: Some("GGIO1".to_string()),
        };
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let decoded = GetNameListRequest::decode(&buf).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_aa_specific_nvl_no_continue_after_roundtrip() {
        let req = GetNameListRequest {
            object_class: ObjectClass::NamedVariableList,
            object_scope: ObjectScope::AaSpecific,
            continue_after: None,
        };
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let decoded = GetNameListRequest::decode(&buf).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_vmd_domain_class_roundtrip() {
        let req = GetNameListRequest {
            object_class: ObjectClass::Domain,
            object_scope: ObjectScope::VmdSpecific,
            continue_after: None,
        };
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let decoded = GetNameListRequest::decode(&buf).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_vmd_journal_with_continue_after_roundtrip() {
        let req = GetNameListRequest {
            object_class: ObjectClass::Journal,
            object_scope: ObjectScope::VmdSpecific,
            continue_after: Some("JournalA".to_string()),
        };
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let decoded = GetNameListRequest::decode(&buf).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_domain_nvl_no_continue_after_roundtrip() {
        let req = GetNameListRequest {
            object_class: ObjectClass::NamedVariableList,
            object_scope: ObjectScope::DomainSpecific("LD1".to_string()),
            continue_after: None,
        };
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let decoded = GetNameListRequest::decode(&buf).unwrap();
        assert_eq!(decoded, req);
    }

    // GetNameListResponse encode and decode round trips

    #[test]
    fn response_empty_identifiers_more_follows_true_roundtrip() {
        let resp = GetNameListResponse {
            identifiers: vec![],
            more_follows: true,
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        let decoded = GetNameListResponse::decode(&buf).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn response_multiple_identifiers_more_follows_false_roundtrip() {
        let resp = GetNameListResponse {
            identifiers: vec![
                "GGIO1".to_string(),
                "GGIO2".to_string(),
                "GGIO3".to_string(),
            ],
            more_follows: false,
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        let decoded = GetNameListResponse::decode(&buf).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn response_single_identifier_more_follows_true_roundtrip() {
        let resp = GetNameListResponse {
            identifiers: vec!["XCBR1".to_string()],
            more_follows: true,
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        let decoded = GetNameListResponse::decode(&buf).unwrap();
        assert_eq!(decoded, resp);
    }

    // moreFollows DEFAULT TRUE semantics

    #[test]
    fn response_more_follows_true_is_omitted_in_wire() {
        // a true moreFollows omits the field, since TRUE is the default
        let resp = GetNameListResponse {
            identifiers: vec!["A".to_string()],
            more_follows: true,
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        // no 0x81 tag must be present, as it is written only for false
        let has_more_follows_byte = buf.contains(&0x81);
        assert!(
            !has_more_follows_byte,
            "moreFollows true must not write the 0x81 tag"
        );
    }

    #[test]
    fn response_more_follows_false_writes_0x81_0x01_0x00() {
        // a false moreFollows writes 0x81 0x01 0x00
        let resp = GetNameListResponse {
            identifiers: vec![],
            more_follows: false,
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        let bytes = &buf[..];
        let found = bytes.windows(3).any(|w| w == [0x81, 0x01, 0x00]);
        assert!(
            found,
            "moreFollows false must produce 0x81 0x01 0x00, got: {:02X?}",
            bytes
        );
    }

    #[test]
    fn decode_response_missing_more_follows_defaults_to_true() {
        // a hand-built response with only listOfIdentifier and no moreFollows field
        // wire: 0xa1 <len> 0xa0 <id_list_len> [identifiers...]
        let id_bytes = b"A";
        // inner of 0xa0: 0x1a 0x01 b'A'
        let id_list_inner: &[u8] = &[0x1a, 0x01, b'A'];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0xa1]); // service tag
                                        // inner = 0xa0 <len> <id_list_inner>
        let inner_len = 1 + 1 + id_list_inner.len(); // 0xa0 len content
        encode_length(inner_len, &mut buf);
        buf.extend_from_slice(&[0xa0]);
        encode_length(id_list_inner.len(), &mut buf);
        buf.extend_from_slice(id_list_inner);

        let decoded = GetNameListResponse::decode(&buf).unwrap();
        assert_eq!(decoded.identifiers, vec!["A".to_string()]);
        assert!(
            decoded.more_follows,
            "an absent moreFollows must default to true"
        );
        let _ = id_bytes;
    }

    #[test]
    fn decode_response_more_follows_nonzero_bytes_are_true() {
        // any non-zero moreFollows byte decodes as true
        for &byte_val in &[0x01u8, 0x0f, 0xffu8] {
            // a hand-built response carrying moreFollows = byte_val
            // wire: 0xa1 <len> 0xa0 0x00 0x81 0x01 <byte_val>
            let mut buf = BytesMut::new();
            buf.extend_from_slice(&[0xa1]);
            // content is 0xa0 0x00, an empty list, plus 0x81 0x01 <byte_val>
            let inner: &[u8] = &[0xa0, 0x00, 0x81, 0x01, byte_val];
            encode_length(inner.len(), &mut buf);
            buf.extend_from_slice(inner);
            let decoded = GetNameListResponse::decode(&buf).unwrap();
            assert!(
                decoded.more_follows,
                "moreFollows byte 0x{:02X} must decode as true",
                byte_val
            );
        }
    }

    #[test]
    fn decode_response_more_follows_zero_is_false() {
        // a moreFollows byte of 0x00 decodes as false
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0xa1]);
        let inner: &[u8] = &[0xa0, 0x00, 0x81, 0x01, 0x00];
        encode_length(inner.len(), &mut buf);
        buf.extend_from_slice(inner);
        let decoded = GetNameListResponse::decode(&buf).unwrap();
        assert!(
            !decoded.more_follows,
            "moreFollows byte 0x00 must decode as false"
        );
    }

    // objectClass inner tag validation

    #[test]
    fn decode_request_invalid_object_class_inner_tag_returns_err() {
        // an objectClass 0xa0 wrapper whose inner tag is 0x81 instead of 0x80
        // wire: 0xa1 <len>
        //   0xa0 0x03 0x81 0x01 0x09   inner tag 0x81, which is wrong
        //   0xa1 0x02 0x80 0x00        objectScope vmdSpecific
        let inner: &[u8] = &[
            0xa0, 0x03, 0x81, 0x01, 0x09, // objectClass with the wrong inner tag 0x81
            0xa1, 0x02, 0x80, 0x00, // objectScope vmdSpecific
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0xa1]);
        encode_length(inner.len(), &mut buf);
        buf.extend_from_slice(inner);

        let result = GetNameListRequest::decode(&buf);
        assert!(
            matches!(result, Err(MmsError::InvalidPdu)),
            "an objectClass inner tag other than 0x80 must return Err(InvalidPdu), got: {:?}",
            result
        );
    }

    // boundary: continueAfter length of 130 or more

    #[test]
    fn decode_request_continue_after_130_bytes_returns_err() {
        // a continueAfter of 130 bytes
        let long_ca = "X".repeat(130);
        let req = GetNameListRequest {
            object_class: ObjectClass::NamedVariable,
            object_scope: ObjectScope::VmdSpecific,
            continue_after: Some(long_ca.clone()),
        };
        // encoding is allowed, since the encoder does not validate the length
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        // decoding must reject it
        let result = GetNameListRequest::decode(&buf);
        assert!(
            matches!(result, Err(MmsError::InvalidPdu)),
            "a 130-byte continueAfter must return Err(InvalidPdu), got: {:?}",
            result
        );
    }

    #[test]
    fn decode_request_continue_after_129_bytes_ok() {
        // 129 bytes is the largest accepted length
        let ca = "X".repeat(129);
        let req = GetNameListRequest {
            object_class: ObjectClass::NamedVariable,
            object_scope: ObjectScope::VmdSpecific,
            continue_after: Some(ca),
        };
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let result = GetNameListRequest::decode(&buf);
        assert!(
            result.is_ok(),
            "a 129-byte continueAfter must decode, got: {:?}",
            result
        );
    }

    // boundary: domainName longer than 64 bytes

    #[test]
    fn decode_request_domain_name_65_bytes_returns_err() {
        let long_domain = "D".repeat(65);
        let req = GetNameListRequest {
            object_class: ObjectClass::NamedVariable,
            object_scope: ObjectScope::DomainSpecific(long_domain),
            continue_after: None,
        };
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let result = GetNameListRequest::decode(&buf);
        assert!(
            matches!(result, Err(MmsError::InvalidPdu)),
            "a 65-byte domainName must return Err(InvalidPdu), got: {:?}",
            result
        );
    }

    #[test]
    fn decode_request_domain_name_64_bytes_ok() {
        // 64 bytes is the largest accepted length
        let domain = "D".repeat(64);
        let req = GetNameListRequest {
            object_class: ObjectClass::NamedVariable,
            object_scope: ObjectScope::DomainSpecific(domain),
            continue_after: None,
        };
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let result = GetNameListRequest::decode(&buf);
        assert!(
            result.is_ok(),
            "a 64-byte domainName must decode, got: {:?}",
            result
        );
    }

    // byte-exact encoding

    /// objectClass Domain(9), scope vmdSpecific, no continueAfter.
    /// Expected wire bytes:
    ///
    /// ```text
    /// 0xa1 0x09                    -- service tag + len(9)
    ///   0xa0 0x03                  -- objectClass [0] EXPLICIT len=3
    ///     0x80 0x01 0x09           -- basicObjectClass INTEGER 9
    ///   0xa1 0x02                  -- objectScope [1] EXPLICIT len=2
    ///     0x80 0x00                -- vmdSpecific NULL
    /// ```
    /// The content is 5 + 4 = 9 bytes.
    #[test]
    fn request_byte_exact_domain_class_vmd_scope() {
        let req = GetNameListRequest {
            object_class: ObjectClass::Domain,
            object_scope: ObjectScope::VmdSpecific,
            continue_after: None,
        };
        let mut buf = BytesMut::new();
        req.encode(&mut buf);

        let expected: &[u8] = &[
            0xa1, 0x09, // service tag + len=9
            0xa0, 0x03, // objectClass [0] EXPLICIT
            0x80, 0x01, 0x09, // basicObjectClass INTEGER 9 (Domain)
            0xa1, 0x02, // objectScope [1] EXPLICIT
            0x80, 0x00, // vmdSpecific NULL
        ];
        assert_eq!(
            &buf[..],
            expected,
            "encoding is not byte exact: got={:02X?}, expected={:02X?}",
            &buf[..],
            expected
        );
    }

    /// A response with the identifiers "A" and "B" and moreFollows false.
    /// ```text
    /// 0xa1 0x0b                    -- service tag + len(11)
    ///   0xa0 0x06                  -- listOfIdentifier [0] len=6
    ///     0x1a 0x01 0x41           -- "A"
    ///     0x1a 0x01 0x42           -- "B"
    ///   0x81 0x01 0x00             -- moreFollows false
    /// ```
    /// The content is 8 bytes, 0xa0 0x06 plus 6, and 3 more for 0x81 0x01 0x00, so 11.
    #[test]
    fn response_byte_exact_two_ids_more_follows_false() {
        let resp = GetNameListResponse {
            identifiers: vec!["A".to_string(), "B".to_string()],
            more_follows: false,
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);

        let expected: &[u8] = &[
            0xa1, 0x0b, // service tag + len=11
            0xa0, 0x06, // listOfIdentifier [0] len=6
            0x1a, 0x01, 0x41, // "A"
            0x1a, 0x01, 0x42, // "B"
            0x81, 0x01, 0x00, // moreFollows false
        ];
        assert_eq!(
            &buf[..],
            expected,
            "encoding is not byte exact: got={:02X?}, expected={:02X?}",
            &buf[..],
            expected
        );
    }

    /// A response with the identifier "Hello" and moreFollows true, which omits the
    /// moreFollows field.
    /// ```text
    /// 0xa1 0x09                    -- service tag + len(9)
    ///   0xa0 0x07                  -- listOfIdentifier [0] len=7
    ///     0x1a 0x05 <Hello>        -- "Hello"
    /// ```
    #[test]
    fn response_byte_exact_one_id_more_follows_true_omitted() {
        let resp = GetNameListResponse {
            identifiers: vec!["Hello".to_string()],
            more_follows: true,
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);

        let expected: &[u8] = &[
            0xa1, 0x09, // service tag + len=9
            0xa0, 0x07, // listOfIdentifier [0] len=7
            0x1a, 0x05, b'H', b'e', b'l', b'l', b'o',
        ];
        assert_eq!(
            &buf[..],
            expected,
            "encoding is not byte exact: got={:02X?}, expected={:02X?}",
            &buf[..],
            expected
        );
    }

    // ConfirmedRequestPdu and ConfirmedResponsePdu wrappers

    #[test]
    fn confirmed_get_name_list_request_roundtrip() {
        let req = GetNameListRequest {
            object_class: ObjectClass::NamedVariable,
            object_scope: ObjectScope::DomainSpecific("TESTLD".to_string()),
            continue_after: None,
        };
        let mut buf = BytesMut::new();
        encode_confirmed_get_name_list_request(42, &req, &mut buf);
        assert_eq!(buf[0], 0xa0);
        let (invoke_id, decoded_req) = decode_confirmed_get_name_list_request(&buf).unwrap();
        assert_eq!(invoke_id, 42);
        assert_eq!(decoded_req, req);
    }

    #[test]
    fn confirmed_get_name_list_response_roundtrip() {
        let resp = GetNameListResponse {
            identifiers: vec!["XCBR1".to_string(), "GGIO1".to_string()],
            more_follows: false,
        };
        let mut buf = BytesMut::new();
        encode_confirmed_get_name_list_response(99, &resp, &mut buf);
        assert_eq!(buf[0], 0xa1);
        let (invoke_id, decoded_resp) = decode_confirmed_get_name_list_response(&buf).unwrap();
        assert_eq!(invoke_id, 99);
        assert_eq!(decoded_resp, resp);
    }

    // Malformed input must be rejected

    #[test]
    fn decode_request_wrong_tag_err() {
        // 0xa4, the Read service tag, instead of 0xa1
        let data = [0xa4u8, 0x00];
        let result = GetNameListRequest::decode(&data);
        assert!(matches!(
            result,
            Err(MmsError::InvalidTag {
                expected: 0xa1,
                actual: 0xa4
            })
        ));
    }

    #[test]
    fn decode_request_empty_returns_truncated() {
        let result = GetNameListRequest::decode(&[]);
        assert!(matches!(result, Err(MmsError::TruncatedPdu)));
    }

    #[test]
    fn decode_response_wrong_tag_err() {
        let data = [0xa4u8, 0x00];
        let result = GetNameListResponse::decode(&data);
        assert!(matches!(
            result,
            Err(MmsError::InvalidTag {
                expected: 0xa1,
                actual: 0xa4
            })
        ));
    }

    #[test]
    fn decode_response_missing_identifier_list_err() {
        // 0xa1 with a length but no 0xa0 listOfIdentifier
        let data = [0xa1u8, 0x00];
        let result = GetNameListResponse::decode(&data);
        assert!(
            result.is_err(),
            "a missing listOfIdentifier must return an error, got: {:?}",
            result
        );
    }

    #[test]
    fn decode_request_truncated_returns_err() {
        let data = [0xa1u8]; // a tag with no length byte
        let result = GetNameListRequest::decode(&data);
        assert!(result.is_err());
    }
}
