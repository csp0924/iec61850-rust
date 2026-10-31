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
//!         0xa0 <len>   -- variableSpecification.name [0] EXPLICIT
//!           <ObjectName>
//!         [0xa5 <AlternateAccess>]  -- alternateAccess [5] IMPLICIT OPTIONAL,
//!                                   -- an array element and its components
//!       ... repeated once per member
//! ```
//!
//! The response is `defineNamedVariableList [11] IMPLICIT
//! DefineNamedVariableList-Response`, and `DefineNamedVariableList-Response ::=
//! NULL` (ISO 9506-2), so it is the primitive tag `0x8b` with length 0.
//!
//! ```text
//! 0xa1 <len>           -- MmsPdu [1] confirmedResponsePdu
//!   0x02 <len> <id>    -- invokeID
//!   0x8b 0x00          -- defineNamedVariableList [11] IMPLICIT NULL
//! ```
//!
//! The decoder also accepts the constructed form `0xab 0x00`, which some
//! implementations send.

use super::super::error::MmsError;
use super::common::{
    decode_list_of_variable, encode_list_of_variable_seq, AlternateAccess, ListOfVariableEntry,
    ObjectName, MAX_DATA_NESTING_DEPTH,
};
use super::initiate::{decode_length, encode_length};
use crate::compat::prelude::*;
use bytes::BytesMut;

// Tag constants

/// Tag of DefineNamedVariableList inside the ConfirmedServiceRequest CHOICE.
/// CONTEXT `[11]` IMPLICIT CONSTRUCTED, that is `0x80 | 0x20 | 11`.
pub const SERVICE_TAG_DEFINE_NAMED_VARIABLE_LIST: u8 = 0xab;

/// Tag of DefineNamedVariableList inside the ConfirmedServiceResponse CHOICE.
/// CONTEXT `[11]` IMPLICIT NULL, a primitive encoding, that is `0x80 | 11`.
pub const SERVICE_TAG_DEFINE_NAMED_VARIABLE_LIST_RESPONSE: u8 = 0x8b;

/// Outer tag of listOfVariable `[0]` IMPLICIT SEQUENCE OF Member.
const TAG_LIST_OF_VARIABLE: u8 = 0xa0;

/// Largest number of entries a request may carry, in either direction.
///
/// The bound keeps a decoded request from growing without limit. A server
/// enforces its own limit on the members of a data set, which is never above
/// this one; a request beyond either is a request for more variables than the
/// server allows, answered with `resource` `capability-unavailable`
/// (IEC 61850-8-1 §8.1.3.4.3.4). The decoder reports this bound as
/// [`MmsError::TooManyDefineEntries`] so the service can answer that error.
pub const MAX_DEFINE_ENTRIES: usize = 4096;

// Request

/// One entry of a DefineNamedVariableList request: a domain-specific named
/// variable, and optionally an alternate access selecting an array element of
/// it and components inside that element (IEC 61850-8-1 §7.3.3, §7.3.4,
/// Table 151).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DefineNamedVariableEntry {
    /// Domain that holds the variable.
    pub domain_id: String,
    /// Name of the variable within the domain.
    pub item_id: String,
    /// Selection of part of the variable, such as an array element.
    pub alt_access: Option<AlternateAccess>,
}

impl DefineNamedVariableEntry {
    /// Builds a plain domain-specific entry.
    pub fn domain(domain_id: impl Into<String>, item_id: impl Into<String>) -> Self {
        Self {
            domain_id: domain_id.into(),
            item_id: item_id.into(),
            alt_access: None,
        }
    }

    /// Returns the entry with `alt_access` selecting part of the variable.
    pub fn with_alt_access(mut self, alt_access: AlternateAccess) -> Self {
        self.alt_access = Some(alt_access);
        self
    }

    /// Returns the entry as a `listOfVariable` element.
    fn list_entry(&self) -> ListOfVariableEntry {
        ListOfVariableEntry {
            name: ObjectName::DomainSpecific {
                domain_id: self.domain_id.clone(),
                item_id: self.item_id.clone(),
            },
            alt_access: self.alt_access.clone(),
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
            encode_list_of_variable_seq(&entry.list_entry(), &mut list_buf);
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

/// Decodes the members of listOfVariable; `data` is its content.
///
/// Every member names a domain-specific variable; an alternate access nests
/// at most [`MAX_DATA_NESTING_DEPTH`] levels.
fn decode_member_list(data: &[u8]) -> Result<Vec<DefineNamedVariableEntry>, MmsError> {
    decode_list_of_variable(data, MAX_DATA_NESTING_DEPTH)?
        .into_iter()
        .map(|entry| match entry.name {
            ObjectName::DomainSpecific { domain_id, item_id } => Ok(DefineNamedVariableEntry {
                domain_id,
                item_id,
                alt_access: entry.alt_access,
            }),
            _ => {
                tracing::warn!(
                    "definenamedvariablelist members must be domain-specific, rejecting"
                );
                Err(MmsError::DefineNamedVariableListMissingField(
                    "domain-specific entry",
                ))
            }
        })
        .collect()
}

// Response

/// An MMS DefineNamedVariableListResponse: a NULL encoded as `0x8b 0x00`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DefineNamedVariableListResponse;

impl DefineNamedVariableListResponse {
    /// Encodes the complete response, `0x8b 0x00`.
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&[SERVICE_TAG_DEFINE_NAMED_VARIABLE_LIST_RESPONSE, 0x00]);
    }

    /// Decodes a response; `data` starts at the service tag, `0x8b`, or `0xab`
    /// for the constructed form.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        if data.len() < 2 {
            return Err(MmsError::TruncatedPdu);
        }
        if data[0] != SERVICE_TAG_DEFINE_NAMED_VARIABLE_LIST_RESPONSE
            && data[0] != SERVICE_TAG_DEFINE_NAMED_VARIABLE_LIST
        {
            return Err(MmsError::InvalidTag {
                expected: SERVICE_TAG_DEFINE_NAMED_VARIABLE_LIST_RESPONSE,
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
        // 0xa1 0x05 0x02 0x01 0x07 0x8b 0x00: the response body is a primitive NULL
        assert_eq!(&buf[..], &[0xa1, 0x05, 0x02, 0x01, 0x07, 0x8b, 0x00]);

        let (invoke_id, _) = decode_confirmed_define_named_variable_list_response(&buf).unwrap();
        assert_eq!(invoke_id, 7);
    }

    #[test]
    fn response_in_constructed_form_is_accepted() {
        let buf = [0xa1, 0x05, 0x02, 0x01, 0x09, 0xab, 0x00];
        let (invoke_id, _) = decode_confirmed_define_named_variable_list_response(&buf).unwrap();
        assert_eq!(invoke_id, 9);
    }

    #[test]
    fn response_with_another_service_tag_is_rejected() {
        // a context tag other than [11] belongs to another service
        let buf = [0xa1, 0x05, 0x02, 0x01, 0x09, 0x8c, 0x00];
        assert!(matches!(
            decode_confirmed_define_named_variable_list_response(&buf),
            Err(MmsError::InvalidTag { .. })
        ));
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
    fn entries_up_to_the_limit_round_trip() {
        let entries: Vec<_> = (0..MAX_DEFINE_ENTRIES)
            .map(|i| DefineNamedVariableEntry::domain("D", format!("i{i}")))
            .collect();
        let req = DefineNamedVariableListRequest::domain("D", "LLN0$ds", entries);
        let mut buf = BytesMut::new();
        req.encode(&mut buf).unwrap();
        let decoded = DefineNamedVariableListRequest::decode(&buf).unwrap();
        assert_eq!(decoded.list_of_variable.len(), MAX_DEFINE_ENTRIES);
    }

    #[test]
    fn too_many_entries_rejected_at_decode() {
        let mut list = BytesMut::new();
        for i in 0..=MAX_DEFINE_ENTRIES {
            encode_list_of_variable_seq(
                &DefineNamedVariableEntry::domain("D", format!("i{i}")).list_entry(),
                &mut list,
            );
        }
        let mut inner = BytesMut::new();
        ObjectName::DomainSpecific {
            domain_id: "D".into(),
            item_id: "LLN0$ds".into(),
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
            MmsError::TooManyDefineEntries { count } if count == MAX_DEFINE_ENTRIES + 1
        ));
    }

    /// A member selecting an array element, and components inside it, carries
    /// the selection as alternateAccess `[5]` and decodes back to it.
    #[test]
    fn alternate_access_round_trips() {
        let element = DefineNamedVariableEntry::domain("IED1LD0", "MHAI1$MX$HA$phsAHar")
            .with_alt_access(AlternateAccess::index_component(3, "cVal$mag$f").unwrap());
        let whole = DefineNamedVariableEntry::domain("IED1LD0", "GGIO1$ST$Arr$hstVal")
            .with_alt_access(AlternateAccess::index(1));
        let plain = DefineNamedVariableEntry::domain("IED1LD0", "GGIO1$ST$Ind1$stVal");
        let req = DefineNamedVariableListRequest::domain(
            "IED1LD0",
            "LLN0$dyn",
            vec![element.clone(), whole, plain],
        );
        let mut buf = BytesMut::new();
        req.encode(&mut buf).unwrap();
        assert_eq!(DefineNamedVariableListRequest::decode(&buf).unwrap(), req);

        let mut member = BytesMut::new();
        encode_list_of_variable_seq(&element.list_entry(), &mut member);
        let name_len = usize::from(member[3]);
        assert_eq!(member[4 + name_len], 0xa5, "{member:02x?}");
    }

    #[test]
    fn member_not_domain_specific_rejected() {
        let mut list = BytesMut::new();
        encode_list_of_variable_seq(
            &ListOfVariableEntry::name(ObjectName::VmdSpecific("v".into())),
            &mut list,
        );
        let mut inner = BytesMut::new();
        ObjectName::DomainSpecific {
            domain_id: "D".into(),
            item_id: "LLN0$ds".into(),
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
            MmsError::DefineNamedVariableListMissingField("domain-specific entry")
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
