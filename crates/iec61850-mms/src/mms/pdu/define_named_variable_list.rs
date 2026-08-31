//! MMS DefineNamedVariableList request and response PDUs.
//!
//! ## Wire format
//!
//! `ConfirmedServiceRequest.defineNamedVariableList` is CONTEXT `[11]` IMPLICIT
//! SEQUENCE, so the outermost tag is `0xab`, that is `0x80 | 0x20 | 11`.
//!
//! ```text
//! 0xa0 <len>           -- MmsPdu [0] confirmedRequestPdu
//!   0x02 <len> <id>    -- invokeID
//!   0xab <len>         -- defineNamedVariableList [11] IMPLICIT SEQUENCE
//!     <ObjectName>     -- variableListName CHOICE, which carries its own tag
//!     0xa0 <len>       -- listOfVariable [0] IMPLICIT SEQUENCE OF Member
//!       0x30 <len>     -- Member SEQUENCE
//!         0xa0 <len>   -- variableSpecification.name [0] IMPLICIT
//!           <ObjectName>
//!         [0xa5 <AlternateAccess>]  -- alternateAccess [5] IMPLICIT OPTIONAL
//!       ... repeated once per member
//! ```
//!
//! The response is CONTEXT `[11]` IMPLICIT with an empty body: tag `0xab`, length 0.
//!
//! ```text
//! 0xa1 <len>           -- MmsPdu [1] confirmedResponsePdu
//!   0x02 <len> <id>    -- invokeID
//!   0xab 0x00          -- defineNamedVariableList [11] IMPLICIT empty SEQUENCE
//! ```

use super::super::error::MmsError;
use super::common::ObjectName;
use super::initiate::{decode_length, encode_length};
use crate::compat::prelude::*;
use bytes::BytesMut;

// Tag constants

/// Tag of DefineNamedVariableList inside the ConfirmedService CHOICE.
/// CONTEXT `[11]` IMPLICIT CONSTRUCTED, that is `0x80 | 0x20 | 11`.
pub const SERVICE_TAG_DEFINE_NAMED_VARIABLE_LIST: u8 = 0xab;

/// Outer tag of listOfVariable `[0]` IMPLICIT SEQUENCE OF Member.
const TAG_LIST_OF_VARIABLE: u8 = 0xa0;

/// Tag of variableSpecification.name `[0]` IMPLICIT inside a Member.
const TAG_VAR_SPEC_NAME: u8 = 0xa0;

/// The UNIVERSAL 16 CONSTRUCTED SEQUENCE tag.
const TAG_SEQUENCE: u8 = 0x30;

/// Largest number of entries accepted, matching the WriteRequest limit.
pub const MAX_DEFINE_ENTRIES: usize = 100;

// Request

/// One entry of a DefineNamedVariableList request.
///
/// Only a plain domain-specific named variable is supported; an AlternateAccess,
/// which would select an array element or a component path, is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefineNamedVariableEntry {
    /// Domain that holds the variable.
    pub domain_id: String,
    /// Name of the variable within the domain.
    pub item_id: String,
}

impl DefineNamedVariableEntry {
    /// Builds a plain domain-specific entry.
    pub fn domain(domain_id: impl Into<String>, item_id: impl Into<String>) -> Self {
        Self {
            domain_id: domain_id.into(),
            item_id: item_id.into(),
        }
    }

    /// Returns the entry as an `ObjectName`.
    fn object_name(&self) -> ObjectName {
        ObjectName::DomainSpecific {
            domain_id: self.domain_id.clone(),
            item_id: self.item_id.clone(),
        }
    }
}

/// An MMS DefineNamedVariableListRequest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefineNamedVariableListRequest {
    /// Name of the data set itself. Domain-specific, vmd-specific and aa-specific
    /// names are all accepted, through the shared ObjectName encoding.
    pub list_name: ObjectName,
    /// Data set entries, stored in the order given.
    pub list_of_variable: Vec<DefineNamedVariableEntry>,
}

impl DefineNamedVariableListRequest {
    /// Builds a request naming a domain-specific data set.
    pub fn domain(
        domain_id: impl Into<String>,
        list_name: impl Into<String>,
        entries: Vec<DefineNamedVariableEntry>,
    ) -> Self {
        Self {
            list_name: ObjectName::DomainSpecific {
                domain_id: domain_id.into(),
                item_id: list_name.into(),
            },
            list_of_variable: entries,
        }
    }

    /// Encodes the request, including the `0xab <len>` service wrapper.
    pub fn encode(&self, buf: &mut BytesMut) -> Result<(), MmsError> {
        if self.list_of_variable.len() > MAX_DEFINE_ENTRIES {
            return Err(MmsError::TooManyDefineEntries {
                count: self.list_of_variable.len(),
            });
        }
        let mut inner = BytesMut::new();

        // variableListName CHOICE: ObjectName carries its own tag, so it needs no wrapper
        self.list_name.encode(&mut inner);

        // 2. listOfVariable [0] IMPLICIT SEQUENCE OF Member
        let mut list_buf = BytesMut::new();
        for entry in &self.list_of_variable {
            encode_member(entry, &mut list_buf);
        }
        inner.extend_from_slice(&[TAG_LIST_OF_VARIABLE]);
        encode_length(list_buf.len(), &mut inner);
        inner.extend_from_slice(&list_buf);

        buf.extend_from_slice(&[SERVICE_TAG_DEFINE_NAMED_VARIABLE_LIST]);
        encode_length(inner.len(), buf);
        buf.extend_from_slice(&inner);
        Ok(())
    }

    /// Decodes a request; `data` starts at the `0xab` byte.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        if data[0] != SERVICE_TAG_DEFINE_NAMED_VARIABLE_LIST {
            return Err(MmsError::InvalidTag {
                expected: SERVICE_TAG_DEFINE_NAMED_VARIABLE_LIST,
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

/// Encodes one Member: a SEQUENCE holding variableSpecification.name and, optionally,
/// an alternateAccess.
fn encode_member(entry: &DefineNamedVariableEntry, buf: &mut BytesMut) {
    let mut member = BytesMut::new();

    // variableSpecification.name [0] IMPLICIT: a 0xa0 wrapper around the ObjectName
    let mut name_inner = BytesMut::new();
    entry.object_name().encode(&mut name_inner);
    member.extend_from_slice(&[TAG_VAR_SPEC_NAME]);
    encode_length(name_inner.len(), &mut member);
    member.extend_from_slice(&name_inner);

    // alternateAccess [5] IMPLICIT OPTIONAL is never emitted
    buf.extend_from_slice(&[TAG_SEQUENCE]);
    encode_length(member.len(), buf);
    buf.extend_from_slice(&member);
}

fn decode_request_inner(data: &[u8]) -> Result<DefineNamedVariableListRequest, MmsError> {
    if data.is_empty() {
        return Err(MmsError::DefineNamedVariableListMissingField(
            "variableListName",
        ));
    }

    // variableListName CHOICE: the ObjectName carries its own tag, 0x80, 0xa1 or 0x82
    let (list_name, consumed) = ObjectName::decode(data)?;

    if consumed >= data.len() {
        return Err(MmsError::DefineNamedVariableListMissingField(
            "listOfVariable",
        ));
    }

    // 2. listOfVariable [0] IMPLICIT
    let rest = &data[consumed..];
    if rest[0] != TAG_LIST_OF_VARIABLE {
        return Err(MmsError::InvalidTag {
            expected: TAG_LIST_OF_VARIABLE,
            actual: rest[0],
        });
    }
    let (list_len, list_hdr) = decode_length(&rest[1..])?;
    let list_start = 1 + list_hdr;
    if list_start + list_len > rest.len() {
        return Err(MmsError::TruncatedPdu);
    }
    let list_inner = &rest[list_start..list_start + list_len];

    let entries = decode_member_list(list_inner)?;
    if entries.len() > MAX_DEFINE_ENTRIES {
        return Err(MmsError::TooManyDefineEntries {
            count: entries.len(),
        });
    }

    Ok(DefineNamedVariableListRequest {
        list_name,
        list_of_variable: entries,
    })
}

fn decode_member_list(data: &[u8]) -> Result<Vec<DefineNamedVariableEntry>, MmsError> {
    let mut entries = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        if data[pos] != TAG_SEQUENCE {
            tracing::warn!(
                "definenamedvariablelist member expected sequence 0x30, got 0x{:02X}, rejecting",
                data[pos]
            );
            return Err(MmsError::InvalidTag {
                expected: TAG_SEQUENCE,
                actual: data[pos],
            });
        }
        let (seq_len, seq_hdr) = decode_length(&data[pos + 1..])?;
        let seq_start = pos + 1 + seq_hdr;
        if seq_start + seq_len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let seq_inner = &data[seq_start..seq_start + seq_len];
        pos = seq_start + seq_len;

        entries.push(decode_member(seq_inner)?);
    }
    Ok(entries)
}

fn decode_member(data: &[u8]) -> Result<DefineNamedVariableEntry, MmsError> {
    if data.is_empty() {
        return Err(MmsError::TruncatedPdu);
    }
    // the first element is variableSpecification.name [0] IMPLICIT, a 0xa0 over ObjectName
    if data[0] != TAG_VAR_SPEC_NAME {
        return Err(MmsError::InvalidTag {
            expected: TAG_VAR_SPEC_NAME,
            actual: data[0],
        });
    }
    let (name_len, name_hdr) = decode_length(&data[1..])?;
    let name_start = 1 + name_hdr;
    if name_start + name_len > data.len() {
        return Err(MmsError::TruncatedPdu);
    }
    let name_inner = &data[name_start..name_start + name_len];
    let (object_name, _) = ObjectName::decode(name_inner)?;

    let (domain_id, item_id) = match object_name {
        ObjectName::DomainSpecific { domain_id, item_id } => (domain_id, item_id),
        // vmd-specific and aa-specific entries are not supported and are rejected
        _ => {
            tracing::warn!("definenamedvariablelist members must be domain-specific, rejecting");
            return Err(MmsError::DefineNamedVariableListMissingField(
                "domain-specific entry",
            ));
        }
    };

    // An alternateAccess [5], tag 0xa5, may follow. It is rejected rather than ignored,
    // because it means the caller needs an array or component path the server would
    // not preserve.
    let after_name = name_start + name_len;
    if after_name < data.len() && data[after_name] == 0xa5 {
        return Err(MmsError::DefineNamedVariableListMissingField(
            "alternateAccess not supported in MVP",
        ));
    }

    Ok(DefineNamedVariableEntry { domain_id, item_id })
}

// Response

/// An MMS DefineNamedVariableListResponse: an empty body encoded as `0xab 0x00`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DefineNamedVariableListResponse;

impl DefineNamedVariableListResponse {
    /// Encodes the complete response, `0xab 0x00`.
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&[SERVICE_TAG_DEFINE_NAMED_VARIABLE_LIST, 0x00]);
    }

    /// Decodes a response; `data` starts at the `0xab` byte.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        if data.len() < 2 {
            return Err(MmsError::TruncatedPdu);
        }
        if data[0] != SERVICE_TAG_DEFINE_NAMED_VARIABLE_LIST {
            return Err(MmsError::InvalidTag {
                expected: SERVICE_TAG_DEFINE_NAMED_VARIABLE_LIST,
                actual: data[0],
            });
        }
        // A non-empty body carries no meaning here: the tag alone signals success, and
        // some servers append filler.
        Ok(Self)
    }
}

// ConfirmedRequest and ConfirmedResponse wrappers

/// Encodes a complete ConfirmedRequestPdu, outer `0xa0` included.
pub fn encode_confirmed_define_named_variable_list_request(
    invoke_id: u32,
    req: &DefineNamedVariableListRequest,
    buf: &mut BytesMut,
) -> Result<(), MmsError> {
    let mut inner = BytesMut::new();
    encode_invoke_id(invoke_id, &mut inner);
    req.encode(&mut inner)?;

    buf.extend_from_slice(&[0xa0]);
    encode_length(inner.len(), buf);
    buf.extend_from_slice(&inner);
    Ok(())
}

/// Encodes a complete ConfirmedResponsePdu, outer `0xa1` included.
pub fn encode_confirmed_define_named_variable_list_response(
    invoke_id: u32,
    resp: &DefineNamedVariableListResponse,
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
pub fn decode_confirmed_define_named_variable_list_request(
    data: &[u8],
) -> Result<(u32, DefineNamedVariableListRequest), MmsError> {
    let (invoke_id, service_data) = decode_confirmed_pdu_inner(data, 0xa0)?;
    let req = DefineNamedVariableListRequest::decode(service_data)?;
    Ok((invoke_id, req))
}

/// Decodes the response inside a ConfirmedResponsePdu; `data` starts at `0xa1`.
pub fn decode_confirmed_define_named_variable_list_response(
    data: &[u8],
) -> Result<(u32, DefineNamedVariableListResponse), MmsError> {
    let (invoke_id, service_data) = decode_confirmed_pdu_inner(data, 0xa1)?;
    let resp = DefineNamedVariableListResponse::decode(service_data)?;
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
    let mut invoke_id = 0u32;
    if id_val.is_empty() || id_val.len() > 4 {
        return Err(MmsError::InvalidLength);
    }
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

    fn sample_entries() -> Vec<DefineNamedVariableEntry> {
        vec![
            DefineNamedVariableEntry::domain("IED1LD0", "GGIO1$ST$Ind1$stVal"),
            DefineNamedVariableEntry::domain("IED1LD0", "GGIO1$ST$Ind2$stVal"),
        ]
    }

    #[test]
    fn request_encode_then_decode_is_identity() {
        let req = DefineNamedVariableListRequest::domain("IED1LD0", "GGIO1$ds1", sample_entries());
        let mut buf = BytesMut::new();
        req.encode(&mut buf).unwrap();
        // the first byte must be the service tag
        assert_eq!(buf[0], SERVICE_TAG_DEFINE_NAMED_VARIABLE_LIST);

        let decoded = DefineNamedVariableListRequest::decode(&buf).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn confirmed_request_round_trip_via_pdu_wrapper() {
        let req = DefineNamedVariableListRequest::domain("IED1LD0", "GGIO1$ds1", sample_entries());
        let mut buf = BytesMut::new();
        encode_confirmed_define_named_variable_list_request(42, &req, &mut buf).unwrap();
        assert_eq!(buf[0], 0xa0);

        let (invoke_id, decoded) =
            decode_confirmed_define_named_variable_list_request(&buf).unwrap();
        assert_eq!(invoke_id, 42);
        assert_eq!(decoded, req);
    }

    #[test]
    fn response_byte_exact_minimal() {
        let resp = DefineNamedVariableListResponse;
        let mut buf = BytesMut::new();
        encode_confirmed_define_named_variable_list_response(7, &resp, &mut buf);
        // 0xa1 0x05 0x02 0x01 0x07 0xab 0x00
        assert_eq!(&buf[..], &[0xa1, 0x05, 0x02, 0x01, 0x07, 0xab, 0x00]);

        let (invoke_id, _) = decode_confirmed_define_named_variable_list_response(&buf).unwrap();
        assert_eq!(invoke_id, 7);
    }

    #[test]
    fn empty_buffer_returns_err() {
        assert!(matches!(
            DefineNamedVariableListRequest::decode(&[]),
            Err(MmsError::TruncatedPdu)
        ));
    }

    #[test]
    fn wrong_outer_tag_rejected() {
        // 0xac is getNamedVariableListAttributes, a valid tag but a different service
        let bad = [0xac, 0x00];
        assert!(matches!(
            DefineNamedVariableListRequest::decode(&bad),
            Err(MmsError::InvalidTag { .. })
        ));
    }

    #[test]
    fn truncated_inner_length_rejected() {
        // a declared length of 10 with only 2 bytes present
        let bad = [SERVICE_TAG_DEFINE_NAMED_VARIABLE_LIST, 0x0a, 0x00, 0x00];
        assert!(matches!(
            DefineNamedVariableListRequest::decode(&bad),
            Err(MmsError::TruncatedPdu)
        ));
    }

    #[test]
    fn empty_entries_list_round_trips() {
        // a valid data set name with no entries, which is allowed
        let req = DefineNamedVariableListRequest::domain("D", "ds_empty", vec![]);
        let mut buf = BytesMut::new();
        req.encode(&mut buf).unwrap();
        let decoded = DefineNamedVariableListRequest::decode(&buf).unwrap();
        assert_eq!(decoded, req);
        assert!(decoded.list_of_variable.is_empty());
    }

    #[test]
    fn too_many_entries_rejected_at_encode() {
        let entries: Vec<_> = (0..MAX_DEFINE_ENTRIES + 1)
            .map(|i| DefineNamedVariableEntry::domain("D", format!("item{i}")))
            .collect();
        let req = DefineNamedVariableListRequest::domain("D", "ds_overflow", entries);
        let mut buf = BytesMut::new();
        let err = req.encode(&mut buf).unwrap_err();
        assert!(matches!(err, MmsError::TooManyDefineEntries { .. }));
    }

    #[test]
    fn alternate_access_rejected_in_mvp() {
        // A hand-built Member carrying a 0xa5 alternateAccess must be rejected.
        // Member SEQUENCE: 0x30 <len>
        //   0xa0 <len> ObjectName
        //   0xa5 0x00       -- alternateAccess with an empty body
        use super::super::common::ObjectName;
        let mut name_inner = BytesMut::new();
        ObjectName::DomainSpecific {
            domain_id: "IED1LD0".into(),
            item_id: "GGIO1$ST$Ind1".into(),
        }
        .encode(&mut name_inner);
        let mut member = BytesMut::new();
        member.extend_from_slice(&[TAG_VAR_SPEC_NAME]);
        encode_length(name_inner.len(), &mut member);
        member.extend_from_slice(&name_inner);
        member.extend_from_slice(&[0xa5, 0x00]);

        let mut list = BytesMut::new();
        list.extend_from_slice(&[TAG_SEQUENCE]);
        encode_length(member.len(), &mut list);
        list.extend_from_slice(&member);

        let mut inner = BytesMut::new();
        ObjectName::DomainSpecific {
            domain_id: "IED1LD0".into(),
            item_id: "ds_with_alt".into(),
        }
        .encode(&mut inner);
        inner.extend_from_slice(&[TAG_LIST_OF_VARIABLE]);
        encode_length(list.len(), &mut inner);
        inner.extend_from_slice(&list);

        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[SERVICE_TAG_DEFINE_NAMED_VARIABLE_LIST]);
        encode_length(inner.len(), &mut buf);
        buf.extend_from_slice(&inner);

        let err = DefineNamedVariableListRequest::decode(&buf).unwrap_err();
        assert!(matches!(
            err,
            MmsError::DefineNamedVariableListMissingField("alternateAccess not supported in MVP")
        ));
    }

    #[test]
    fn missing_list_of_variable_field_rejected() {
        // an ObjectName with no 0xa0 listOfVariable after it
        let mut bad = BytesMut::new();
        let mut inner = BytesMut::new();
        ObjectName::DomainSpecific {
            domain_id: "D".into(),
            item_id: "ds".into(),
        }
        .encode(&mut inner);
        bad.extend_from_slice(&[SERVICE_TAG_DEFINE_NAMED_VARIABLE_LIST]);
        encode_length(inner.len(), &mut bad);
        bad.extend_from_slice(&inner);

        let err = DefineNamedVariableListRequest::decode(&bad).unwrap_err();
        assert!(matches!(
            err,
            MmsError::DefineNamedVariableListMissingField("listOfVariable")
        ));
    }
}
