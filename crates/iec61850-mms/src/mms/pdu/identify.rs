//! MMS Identify request and response PDUs, per ISO 9506-2.
//!
//! ## Wire format
//!
//! `ConfirmedServiceRequest.identify` is CONTEXT `[2]` IMPLICIT NULL, so the
//! request carries the primitive service tag `0x82` with no content:
//!
//! ```text
//! 0xa0 <len>           -- MmsPdu [0] confirmedRequestPdu
//!   0x02 <len> <id>    -- invokeID
//!   0x82 0x00          -- identify [2] IMPLICIT NULL
//! ```
//!
//! The response is CONTEXT `[2]` IMPLICIT SEQUENCE:
//!
//! ```text
//! 0xa1 <len>               -- MmsPdu [1] confirmedResponsePdu
//!   0x02 <len> <id>        -- invokeID
//!   0xa2 <len>             -- identify [2] IMPLICIT SEQUENCE
//!     0x80 <len> <vendor>  -- vendorName [0] IMPLICIT MMSString
//!     0x81 <len> <model>   -- modelName [1] IMPLICIT MMSString
//!     0x82 <len> <rev>     -- revision [2] IMPLICIT MMSString
//!     [0xa3 <len>          -- listOfAbstractSyntaxes [3] IMPLICIT
//!        0x06 <len> <oid>  --   SEQUENCE OF OBJECT IDENTIFIER, OPTIONAL
//!        ...]
//! ```

use super::super::error::MmsError;
use super::initiate::{decode_length, encode_length};
use crate::compat::prelude::*;
use crate::iso::params::ApTitle;
use bytes::BytesMut;

// Tag constants

/// Tag of the Identify request inside the ConfirmedService CHOICE.
/// CONTEXT `[2]` IMPLICIT primitive NULL, that is `0x82`.
pub const SERVICE_TAG_IDENTIFY_REQUEST: u8 = 0x82;

/// Tag of the Identify response inside the ConfirmedService CHOICE.
/// CONTEXT `[2]` IMPLICIT CONSTRUCTED, that is `0xa2`.
pub const SERVICE_TAG_IDENTIFY_RESPONSE: u8 = 0xa2;

/// Tag of vendorName `[0]` IMPLICIT MMSString.
const TAG_VENDOR_NAME: u8 = 0x80;

/// Tag of modelName `[1]` IMPLICIT MMSString.
const TAG_MODEL_NAME: u8 = 0x81;

/// Tag of revision `[2]` IMPLICIT MMSString.
const TAG_REVISION: u8 = 0x82;

/// Tag of listOfAbstractSyntaxes `[3]` IMPLICIT SEQUENCE OF.
const TAG_LIST_OF_ABSTRACT_SYNTAXES: u8 = 0xa3;

/// UNIVERSAL tag of an OBJECT IDENTIFIER.
const TAG_OBJECT_IDENTIFIER: u8 = 0x06;

// Response

/// An MMS Identify-Response: the vendor, model and revision of the responding
/// implementation, and optionally the abstract syntaxes it supports.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct IdentifyResponse {
    /// vendorName.
    pub vendor_name: String,
    /// modelName.
    pub model_name: String,
    /// revision.
    pub revision: String,
    /// listOfAbstractSyntaxes, each OBJECT IDENTIFIER held as its arcs. An
    /// empty vector stands for the absent OPTIONAL field.
    pub list_of_abstract_syntaxes: Vec<Vec<u32>>,
}

impl IdentifyResponse {
    /// Builds a response carrying the three mandatory strings and no
    /// listOfAbstractSyntaxes.
    pub fn new(
        vendor_name: impl Into<String>,
        model_name: impl Into<String>,
        revision: impl Into<String>,
    ) -> Self {
        Self {
            vendor_name: vendor_name.into(),
            model_name: model_name.into(),
            revision: revision.into(),
            list_of_abstract_syntaxes: Vec::new(),
        }
    }

    /// Encodes the response, including the `0xa2 <len>` service wrapper.
    ///
    /// An abstract syntax that is not an encodable OBJECT IDENTIFIER, with
    /// fewer than two arcs or an out-of-range first pair, is omitted.
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut inner = BytesMut::new();
        encode_string(TAG_VENDOR_NAME, &self.vendor_name, &mut inner);
        encode_string(TAG_MODEL_NAME, &self.model_name, &mut inner);
        encode_string(TAG_REVISION, &self.revision, &mut inner);

        if !self.list_of_abstract_syntaxes.is_empty() {
            let mut oids = BytesMut::new();
            for arcs in &self.list_of_abstract_syntaxes {
                match ApTitle::from_arcs(arcs) {
                    Ok(oid) => {
                        let content = oid.to_ber_content();
                        oids.extend_from_slice(&[TAG_OBJECT_IDENTIFIER]);
                        encode_length(content.len(), &mut oids);
                        oids.extend_from_slice(&content);
                    }
                    Err(e) => {
                        tracing::warn!("identify: omitting abstract syntax {:?}: {e}", arcs);
                    }
                }
            }
            inner.extend_from_slice(&[TAG_LIST_OF_ABSTRACT_SYNTAXES]);
            encode_length(oids.len(), &mut inner);
            inner.extend_from_slice(&oids);
        }

        buf.extend_from_slice(&[SERVICE_TAG_IDENTIFY_RESPONSE]);
        encode_length(inner.len(), buf);
        buf.extend_from_slice(&inner);
    }

    /// Decodes a response; `data` starts at the `0xa2` byte.
    ///
    /// # Errors
    ///
    /// - `InvalidTag` when `data` does not start with `0xa2`.
    /// - `TruncatedPdu` when a length runs past the end of the input.
    /// - `InvalidPdu` when vendorName, modelName or revision is missing, or
    ///   when listOfAbstractSyntaxes holds anything but well-formed OBJECT
    ///   IDENTIFIERs.
    /// - `InvalidUtf8` when a string field is not valid UTF-8.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        if data[0] != SERVICE_TAG_IDENTIFY_RESPONSE {
            return Err(MmsError::InvalidTag {
                expected: SERVICE_TAG_IDENTIFY_RESPONSE,
                actual: data[0],
            });
        }
        let (inner_len, hdr) = decode_length(&data[1..])?;
        let inner_start = 1 + hdr;
        if inner_start + inner_len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        decode_response_inner(&data[inner_start..inner_start + inner_len])
    }
}

fn decode_response_inner(data: &[u8]) -> Result<IdentifyResponse, MmsError> {
    let mut vendor_name = None;
    let mut model_name = None;
    let mut revision = None;
    let mut list_of_abstract_syntaxes = Vec::new();

    let mut pos = 0usize;
    while pos < data.len() {
        let (tag, val, next) = next_tlv(data, pos)?;
        pos = next;
        match tag {
            TAG_VENDOR_NAME => vendor_name = Some(decode_string(val)?),
            TAG_MODEL_NAME => model_name = Some(decode_string(val)?),
            TAG_REVISION => revision = Some(decode_string(val)?),
            TAG_LIST_OF_ABSTRACT_SYNTAXES => {
                list_of_abstract_syntaxes = decode_abstract_syntaxes(val)?;
            }
            other => {
                tracing::debug!("skipping unknown identify response tag 0x{:02X}", other);
            }
        }
    }

    match (vendor_name, model_name, revision) {
        (Some(vendor_name), Some(model_name), Some(revision)) => Ok(IdentifyResponse {
            vendor_name,
            model_name,
            revision,
            list_of_abstract_syntaxes,
        }),
        _ => {
            tracing::warn!("identify response lacks vendorName, modelName or revision");
            Err(MmsError::InvalidPdu)
        }
    }
}

fn decode_abstract_syntaxes(data: &[u8]) -> Result<Vec<Vec<u32>>, MmsError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let (tag, val, next) = next_tlv(data, pos)?;
        pos = next;
        if tag != TAG_OBJECT_IDENTIFIER {
            tracing::warn!(
                "identify listOfAbstractSyntaxes holds tag 0x{:02X}, not an object identifier",
                tag
            );
            return Err(MmsError::InvalidPdu);
        }
        let oid = ApTitle::from_ber_content(val).map_err(|e| {
            tracing::warn!("identify listOfAbstractSyntaxes holds a malformed oid: {e}");
            MmsError::InvalidPdu
        })?;
        out.push(oid.arcs().to_vec());
    }
    Ok(out)
}

/// Splits the TLV starting at `pos` into its tag, value and the position just
/// past it.
fn next_tlv(data: &[u8], pos: usize) -> Result<(u8, &[u8], usize), MmsError> {
    let tag = data[pos];
    let (len, hdr) = decode_length(&data[pos + 1..])?;
    let val_start = pos + 1 + hdr;
    if val_start + len > data.len() {
        return Err(MmsError::TruncatedPdu);
    }
    Ok((tag, &data[val_start..val_start + len], val_start + len))
}

fn encode_string(tag: u8, value: &str, buf: &mut BytesMut) {
    let b = value.as_bytes();
    buf.extend_from_slice(&[tag]);
    encode_length(b.len(), buf);
    buf.extend_from_slice(b);
}

fn decode_string(val: &[u8]) -> Result<String, MmsError> {
    core::str::from_utf8(val)
        .map(ToOwned::to_owned)
        .map_err(|_| MmsError::InvalidUtf8)
}

// ConfirmedRequest and ConfirmedResponse wrappers

/// Encodes an Identify request as a complete ConfirmedRequestPdu, outer `0xa0`
/// included.
pub fn encode_confirmed_identify_request(invoke_id: u32, buf: &mut BytesMut) {
    let mut inner = BytesMut::new();
    encode_invoke_id(invoke_id, &mut inner);
    inner.extend_from_slice(&[SERVICE_TAG_IDENTIFY_REQUEST, 0x00]);

    buf.extend_from_slice(&[0xa0]);
    encode_length(inner.len(), buf);
    buf.extend_from_slice(&inner);
}

/// Encodes the response as a complete ConfirmedResponsePdu, outer `0xa1`
/// included.
pub fn encode_confirmed_identify_response(
    invoke_id: u32,
    resp: &IdentifyResponse,
    buf: &mut BytesMut,
) {
    let mut inner = BytesMut::new();
    encode_invoke_id(invoke_id, &mut inner);
    resp.encode(&mut inner);

    buf.extend_from_slice(&[0xa1]);
    encode_length(inner.len(), buf);
    buf.extend_from_slice(&inner);
}

/// Decodes an Identify request inside a ConfirmedRequestPdu and returns its
/// invokeID; `data` starts at `0xa0`.
///
/// # Errors
///
/// `InvalidTag` when the service is not `0x82`, and `InvalidLength` when the
/// NULL carries content.
pub fn decode_confirmed_identify_request(data: &[u8]) -> Result<u32, MmsError> {
    let (invoke_id, service_data) = decode_confirmed_pdu_inner(data, 0xa0)?;
    let Some(&tag) = service_data.first() else {
        return Err(MmsError::TruncatedPdu);
    };
    if tag != SERVICE_TAG_IDENTIFY_REQUEST {
        return Err(MmsError::InvalidTag {
            expected: SERVICE_TAG_IDENTIFY_REQUEST,
            actual: tag,
        });
    }
    let (len, _) = decode_length(&service_data[1..])?;
    if len != 0 {
        return Err(MmsError::InvalidLength);
    }
    Ok(invoke_id)
}

/// Decodes the response inside a ConfirmedResponsePdu; `data` starts at
/// `0xa1`.
pub fn decode_confirmed_identify_response(
    data: &[u8],
) -> Result<(u32, IdentifyResponse), MmsError> {
    let (invoke_id, service_data) = decode_confirmed_pdu_inner(data, 0xa1)?;
    let resp = IdentifyResponse::decode(service_data)?;
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
    // an unsigned value with its top bit set carries a leading 0x00
    let id_val = match id_val {
        [0x00, rest @ ..] if !rest.is_empty() => rest,
        other => other,
    };
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

    /// `1.0.9506.2.1`, the MMS abstract syntax.
    const MMS_ABSTRACT_SYNTAX: [u32; 5] = [1, 0, 9506, 2, 1];

    #[test]
    fn request_is_invoke_id_and_primitive_null() {
        let mut buf = BytesMut::new();
        encode_confirmed_identify_request(5, &mut buf);
        assert_eq!(&buf[..], &[0xa0, 0x05, 0x02, 0x01, 0x05, 0x82, 0x00]);
    }

    #[test]
    fn request_with_wide_invoke_id_round_trips() {
        let mut buf = BytesMut::new();
        encode_confirmed_identify_request(0x8000_0001, &mut buf);
        assert_eq!(
            &buf[..],
            &[0xa0, 0x09, 0x02, 0x05, 0x00, 0x80, 0x00, 0x00, 0x01, 0x82, 0x00]
        );
        assert_eq!(
            decode_confirmed_identify_request(&buf).unwrap(),
            0x8000_0001
        );
    }

    #[test]
    fn request_decode_rejects_other_service() {
        // read [4] in place of identify [2]
        let data = [0xa0, 0x05, 0x02, 0x01, 0x01, 0xa4, 0x00];
        assert_eq!(
            decode_confirmed_identify_request(&data),
            Err(MmsError::InvalidTag {
                expected: SERVICE_TAG_IDENTIFY_REQUEST,
                actual: 0xa4,
            })
        );
    }

    #[test]
    fn request_decode_rejects_null_with_content() {
        let data = [0xa0, 0x06, 0x02, 0x01, 0x01, 0x82, 0x01, 0x00];
        assert_eq!(
            decode_confirmed_identify_request(&data),
            Err(MmsError::InvalidLength)
        );
    }

    #[test]
    fn response_without_abstract_syntaxes_is_byte_exact() {
        let resp = IdentifyResponse::new("V", "M", "1");
        let mut buf = BytesMut::new();
        encode_confirmed_identify_response(7, &resp, &mut buf);
        assert_eq!(
            &buf[..],
            &[
                0xa1, 0x0e, 0x02, 0x01, 0x07, 0xa2, 0x09, 0x80, 0x01, b'V', 0x81, 0x01, b'M', 0x82,
                0x01, b'1',
            ]
        );
        let (id, decoded) = decode_confirmed_identify_response(&buf).unwrap();
        assert_eq!(id, 7);
        assert_eq!(decoded, resp);
        assert!(decoded.list_of_abstract_syntaxes.is_empty());
    }

    #[test]
    fn response_with_abstract_syntaxes_round_trips() {
        let mut resp = IdentifyResponse::new("vendor", "model", "1.2.3");
        resp.list_of_abstract_syntaxes = vec![MMS_ABSTRACT_SYNTAX.to_vec(), vec![2, 999, 3]];
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);

        // 1.0.9506.2.1 is 28 ca 22 02 01; 2.999.3 is 88 37 03
        let tail = [
            0xa3, 0x0c, 0x06, 0x05, 0x28, 0xca, 0x22, 0x02, 0x01, 0x06, 0x03, 0x88, 0x37, 0x03,
        ];
        assert!(buf.ends_with(&tail), "got {:02x?}", &buf[..]);
        assert_eq!(IdentifyResponse::decode(&buf).unwrap(), resp);
    }

    #[test]
    fn response_decode_reads_abstract_syntaxes_from_wire() {
        let data = [
            0xa2, 0x12, 0x80, 0x01, b'a', 0x81, 0x01, b'b', 0x82, 0x01, b'c', 0xa3, 0x07, 0x06,
            0x05, 0x28, 0xca, 0x22, 0x02, 0x01,
        ];
        let resp = IdentifyResponse::decode(&data).unwrap();
        assert_eq!(resp.vendor_name, "a");
        assert_eq!(resp.model_name, "b");
        assert_eq!(resp.revision, "c");
        assert_eq!(
            resp.list_of_abstract_syntaxes,
            vec![MMS_ABSTRACT_SYNTAX.to_vec()]
        );
    }

    #[test]
    fn response_accepts_empty_strings_and_long_form_length() {
        let vendor = "v".repeat(200);
        let resp = IdentifyResponse::new(vendor.clone(), "", "");
        let mut buf = BytesMut::new();
        encode_confirmed_identify_response(1, &resp, &mut buf);
        let (_, decoded) = decode_confirmed_identify_response(&buf).unwrap();
        assert_eq!(decoded.vendor_name, vendor);
        assert_eq!(decoded.model_name, "");
        assert_eq!(decoded.revision, "");
    }

    #[test]
    fn response_missing_revision_is_invalid() {
        let data = [0xa2, 0x06, 0x80, 0x01, b'a', 0x81, 0x01, b'b'];
        assert_eq!(IdentifyResponse::decode(&data), Err(MmsError::InvalidPdu));
    }

    #[test]
    fn response_with_non_oid_abstract_syntax_is_invalid() {
        let data = [
            0xa2, 0x0e, 0x80, 0x01, b'a', 0x81, 0x01, b'b', 0x82, 0x01, b'c', 0xa3, 0x03, 0x04,
            0x01, 0x00,
        ];
        assert_eq!(IdentifyResponse::decode(&data), Err(MmsError::InvalidPdu));
    }

    #[test]
    fn response_with_truncated_field_is_rejected() {
        let data = [0xa2, 0x05, 0x80, 0x05, b'a', b'b', b'c'];
        assert_eq!(IdentifyResponse::decode(&data), Err(MmsError::TruncatedPdu));
    }

    #[test]
    fn response_with_invalid_utf8_is_rejected() {
        let data = [
            0xa2, 0x09, 0x80, 0x01, 0xff, 0x81, 0x01, b'b', 0x82, 0x01, b'c',
        ];
        assert_eq!(IdentifyResponse::decode(&data), Err(MmsError::InvalidUtf8));
    }

    #[test]
    fn response_decode_rejects_wrong_service_tag() {
        let data = [0xad, 0x00];
        assert_eq!(
            IdentifyResponse::decode(&data),
            Err(MmsError::InvalidTag {
                expected: SERVICE_TAG_IDENTIFY_RESPONSE,
                actual: 0xad,
            })
        );
    }

    #[test]
    fn unencodable_abstract_syntax_is_omitted() {
        let mut resp = IdentifyResponse::new("a", "b", "c");
        resp.list_of_abstract_syntaxes = vec![vec![1], MMS_ABSTRACT_SYNTAX.to_vec()];
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        let decoded = IdentifyResponse::decode(&buf).unwrap();
        assert_eq!(
            decoded.list_of_abstract_syntaxes,
            vec![MMS_ABSTRACT_SYNTAX.to_vec()]
        );
    }
}
