//! MMS Status request and response PDUs, per ISO 9506-2.
//!
//! ## Wire format
//!
//! `ConfirmedServiceRequest.status` is CONTEXT `[0]` IMPLICIT BOOLEAN, the
//! extendedDerivation flag, so the request carries the primitive service tag
//! `0x80` with one content octet:
//!
//! ```text
//! 0xa0 <len>           -- MmsPdu [0] confirmedRequestPdu
//!   0x02 <len> <id>    -- invokeID
//!   0x80 0x01 <flag>   -- status [0] IMPLICIT BOOLEAN, extendedDerivation
//! ```
//!
//! The response is CONTEXT `[0]` IMPLICIT SEQUENCE:
//!
//! ```text
//! 0xa1 <len>               -- MmsPdu [1] confirmedResponsePdu
//!   0x02 <len> <id>        -- invokeID
//!   0xa0 <len>             -- status [0] IMPLICIT SEQUENCE
//!     0x80 <len> <int>     -- vmdLogicalStatus [0] IMPLICIT INTEGER
//!     0x81 <len> <int>     -- vmdPhysicalStatus [1] IMPLICIT INTEGER
//!     [0x82 <len> <pad> <bits>]  -- localDetail [2] IMPLICIT BIT STRING
//!                                --   (SIZE(0..128)), OPTIONAL
//! ```

use super::super::error::MmsError;
use super::common::{decode_bit_string, decode_signed_int, encode_signed_int_minimal};
use super::initiate::{decode_length, encode_length};
use crate::compat::prelude::*;
use bytes::BytesMut;

// Tag constants

/// Tag of the Status request inside the ConfirmedService CHOICE.
/// CONTEXT `[0]` IMPLICIT primitive BOOLEAN, that is `0x80`.
pub const SERVICE_TAG_STATUS_REQUEST: u8 = 0x80;

/// Tag of the Status response inside the ConfirmedService CHOICE.
/// CONTEXT `[0]` IMPLICIT CONSTRUCTED, that is `0xa0`.
pub const SERVICE_TAG_STATUS_RESPONSE: u8 = 0xa0;

/// Largest number of bits localDetail may carry.
pub const MAX_LOCAL_DETAIL_BITS: usize = 128;

/// Tag of vmdLogicalStatus `[0]` IMPLICIT INTEGER.
const TAG_LOGICAL_STATUS: u8 = 0x80;

/// Tag of vmdPhysicalStatus `[1]` IMPLICIT INTEGER.
const TAG_PHYSICAL_STATUS: u8 = 0x81;

/// Tag of localDetail `[2]` IMPLICIT BIT STRING.
const TAG_LOCAL_DETAIL: u8 = 0x82;

// Status values

/// vmdLogicalStatus: which services the VMD currently permits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum VmdLogicalStatus {
    /// `state-changes-allowed (0)`.
    StateChangesAllowed,
    /// `no-state-changes-allowed (1)`.
    NoStateChangesAllowed,
    /// `limited-services-permitted (2)`.
    LimitedServicesPermitted,
    /// `support-services-allowed (3)`.
    SupportServicesAllowed,
    /// A value outside the named ones, kept as received.
    Other(i64),
}

impl VmdLogicalStatus {
    /// Maps a wire value to its named state, or to `Other` when it has none.
    pub fn from_code(code: i64) -> Self {
        match code {
            0 => Self::StateChangesAllowed,
            1 => Self::NoStateChangesAllowed,
            2 => Self::LimitedServicesPermitted,
            3 => Self::SupportServicesAllowed,
            other => Self::Other(other),
        }
    }

    /// The wire value.
    pub fn code(self) -> i64 {
        match self {
            Self::StateChangesAllowed => 0,
            Self::NoStateChangesAllowed => 1,
            Self::LimitedServicesPermitted => 2,
            Self::SupportServicesAllowed => 3,
            Self::Other(code) => code,
        }
    }
}

/// vmdPhysicalStatus: the operational condition of the real device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum VmdPhysicalStatus {
    /// `operational (0)`.
    Operational,
    /// `partially-operational (1)`.
    PartiallyOperational,
    /// `inoperable (2)`.
    Inoperable,
    /// `needs-commissioning (3)`.
    NeedsCommissioning,
    /// A value outside the named ones, kept as received.
    Other(i64),
}

impl VmdPhysicalStatus {
    /// Maps a wire value to its named state, or to `Other` when it has none.
    pub fn from_code(code: i64) -> Self {
        match code {
            0 => Self::Operational,
            1 => Self::PartiallyOperational,
            2 => Self::Inoperable,
            3 => Self::NeedsCommissioning,
            other => Self::Other(other),
        }
    }

    /// The wire value.
    pub fn code(self) -> i64 {
        match self {
            Self::Operational => 0,
            Self::PartiallyOperational => 1,
            Self::Inoperable => 2,
            Self::NeedsCommissioning => 3,
            Self::Other(code) => code,
        }
    }
}

// Response

/// An MMS Status-Response: the logical and physical status of the VMD, and
/// optionally implementation-specific detail bits.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StatusResponse {
    /// vmdLogicalStatus.
    pub logical_status: VmdLogicalStatus,
    /// vmdPhysicalStatus.
    pub physical_status: VmdPhysicalStatus,
    /// localDetail, one entry per bit in transmission order; `None` stands for
    /// the absent OPTIONAL field and `Some` of an empty vector for an empty bit
    /// string.
    pub local_detail: Option<Vec<bool>>,
}

impl StatusResponse {
    /// Builds a response carrying the two status values and no localDetail.
    pub fn new(logical_status: VmdLogicalStatus, physical_status: VmdPhysicalStatus) -> Self {
        Self {
            logical_status,
            physical_status,
            local_detail: None,
        }
    }

    /// Encodes the response, including the `0xa0 <len>` service wrapper.
    ///
    /// localDetail bits past [`MAX_LOCAL_DETAIL_BITS`] are not encoded.
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut inner = BytesMut::new();
        encode_integer(TAG_LOGICAL_STATUS, self.logical_status.code(), &mut inner);
        encode_integer(TAG_PHYSICAL_STATUS, self.physical_status.code(), &mut inner);

        if let Some(bits) = &self.local_detail {
            let bits = if bits.len() > MAX_LOCAL_DETAIL_BITS {
                tracing::warn!(
                    "status: local detail of {} bits is cut to {}",
                    bits.len(),
                    MAX_LOCAL_DETAIL_BITS
                );
                &bits[..MAX_LOCAL_DETAIL_BITS]
            } else {
                &bits[..]
            };
            let content = pack_bits(bits);
            inner.extend_from_slice(&[TAG_LOCAL_DETAIL]);
            encode_length(content.len(), &mut inner);
            inner.extend_from_slice(&content);
        }

        buf.extend_from_slice(&[SERVICE_TAG_STATUS_RESPONSE]);
        encode_length(inner.len(), buf);
        buf.extend_from_slice(&inner);
    }

    /// Decodes a response; `data` starts at the `0xa0` byte.
    ///
    /// A status value outside the named ones decodes to the `Other` variant.
    ///
    /// # Errors
    ///
    /// - `InvalidTag` when `data` does not start with `0xa0`.
    /// - `TruncatedPdu` when a length runs past the end of the input.
    /// - `InvalidPdu` when vmdLogicalStatus or vmdPhysicalStatus is missing, or
    ///   when localDetail is a malformed bit string or exceeds
    ///   [`MAX_LOCAL_DETAIL_BITS`].
    /// - `InvalidLength` when a status INTEGER is empty or longer than 8 octets.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        if data[0] != SERVICE_TAG_STATUS_RESPONSE {
            return Err(MmsError::InvalidTag {
                expected: SERVICE_TAG_STATUS_RESPONSE,
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

fn decode_response_inner(data: &[u8]) -> Result<StatusResponse, MmsError> {
    let mut logical_status = None;
    let mut physical_status = None;
    let mut local_detail = None;

    let mut pos = 0usize;
    while pos < data.len() {
        let (tag, val, next) = next_tlv(data, pos)?;
        pos = next;
        match tag {
            TAG_LOGICAL_STATUS => {
                logical_status = Some(VmdLogicalStatus::from_code(decode_signed_int(val)?));
            }
            TAG_PHYSICAL_STATUS => {
                physical_status = Some(VmdPhysicalStatus::from_code(decode_signed_int(val)?));
            }
            TAG_LOCAL_DETAIL => local_detail = Some(decode_local_detail(val)?),
            other => {
                tracing::debug!("skipping unknown status response tag 0x{:02X}", other);
            }
        }
    }

    match (logical_status, physical_status) {
        (Some(logical_status), Some(physical_status)) => Ok(StatusResponse {
            logical_status,
            physical_status,
            local_detail,
        }),
        _ => {
            tracing::warn!("status response lacks vmdLogicalStatus or vmdPhysicalStatus");
            Err(MmsError::InvalidPdu)
        }
    }
}

fn decode_local_detail(val: &[u8]) -> Result<Vec<bool>, MmsError> {
    let (padding, bytes) = decode_bit_string(TAG_LOCAL_DETAIL, val)?;
    let bit_len = bytes.len() * 8 - padding as usize;
    if bit_len > MAX_LOCAL_DETAIL_BITS {
        tracing::warn!(
            "status local detail carries {} bits, more than {}",
            bit_len,
            MAX_LOCAL_DETAIL_BITS
        );
        return Err(MmsError::InvalidPdu);
    }
    Ok((0..bit_len)
        .map(|i| bytes[i / 8] & (0x80 >> (i % 8)) != 0)
        .collect())
}

/// Packs bits, most significant first, into BIT STRING content: the count of
/// unused bits followed by the data octets.
fn pack_bits(bits: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; 1 + bits.len().div_ceil(8)];
    out[0] = ((8 - bits.len() % 8) % 8) as u8;
    for (i, &bit) in bits.iter().enumerate() {
        if bit {
            out[1 + i / 8] |= 0x80 >> (i % 8);
        }
    }
    out
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

fn encode_integer(tag: u8, value: i64, buf: &mut BytesMut) {
    let bytes = encode_signed_int_minimal(value);
    buf.extend_from_slice(&[tag]);
    encode_length(bytes.len(), buf);
    buf.extend_from_slice(&bytes);
}

// ConfirmedRequest and ConfirmedResponse wrappers

/// Encodes a Status request as a complete ConfirmedRequestPdu, outer `0xa0`
/// included. `extended_derivation` asks the server to derive the status by
/// executing its own checks rather than report the status it holds.
pub fn encode_confirmed_status_request(
    invoke_id: u32,
    extended_derivation: bool,
    buf: &mut BytesMut,
) {
    let mut inner = BytesMut::new();
    encode_invoke_id(invoke_id, &mut inner);
    let flag = if extended_derivation { 0xff } else { 0x00 };
    inner.extend_from_slice(&[SERVICE_TAG_STATUS_REQUEST, 0x01, flag]);

    buf.extend_from_slice(&[0xa0]);
    encode_length(inner.len(), buf);
    buf.extend_from_slice(&inner);
}

/// Encodes the response as a complete ConfirmedResponsePdu, outer `0xa1`
/// included.
pub fn encode_confirmed_status_response(invoke_id: u32, resp: &StatusResponse, buf: &mut BytesMut) {
    let mut inner = BytesMut::new();
    encode_invoke_id(invoke_id, &mut inner);
    resp.encode(&mut inner);

    buf.extend_from_slice(&[0xa1]);
    encode_length(inner.len(), buf);
    buf.extend_from_slice(&inner);
}

/// Decodes the service body of a Status request, starting at the `0x80` tag,
/// into its extendedDerivation flag. Any non-zero content octet is TRUE.
///
/// # Errors
///
/// `InvalidTag` when the service is not `0x80`, `TruncatedPdu` when the body
/// ends early, and `InvalidLength` when the BOOLEAN is not exactly one octet.
pub fn decode_status_request(body: &[u8]) -> Result<bool, MmsError> {
    let Some(&tag) = body.first() else {
        return Err(MmsError::TruncatedPdu);
    };
    if tag != SERVICE_TAG_STATUS_REQUEST {
        return Err(MmsError::InvalidTag {
            expected: SERVICE_TAG_STATUS_REQUEST,
            actual: tag,
        });
    }
    let (len, hdr) = decode_length(&body[1..])?;
    if len != 1 {
        return Err(MmsError::InvalidLength);
    }
    let Some(&flag) = body.get(1 + hdr) else {
        return Err(MmsError::TruncatedPdu);
    };
    Ok(flag != 0)
}

/// Decodes a Status request inside a ConfirmedRequestPdu and returns its
/// invokeID and extendedDerivation flag; `data` starts at `0xa0`.
///
/// # Errors
///
/// As [`decode_status_request`], plus the errors of the outer PDU.
pub fn decode_confirmed_status_request(data: &[u8]) -> Result<(u32, bool), MmsError> {
    let (invoke_id, service_data) = decode_confirmed_pdu_inner(data, 0xa0)?;
    let extended_derivation = decode_status_request(service_data)?;
    Ok((invoke_id, extended_derivation))
}

/// Decodes the response inside a ConfirmedResponsePdu; `data` starts at
/// `0xa1`.
pub fn decode_confirmed_status_response(data: &[u8]) -> Result<(u32, StatusResponse), MmsError> {
    let (invoke_id, service_data) = decode_confirmed_pdu_inner(data, 0xa1)?;
    let resp = StatusResponse::decode(service_data)?;
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

    #[test]
    fn request_carries_one_boolean_octet() {
        let mut buf = BytesMut::new();
        encode_confirmed_status_request(5, false, &mut buf);
        assert_eq!(&buf[..], &[0xa0, 0x06, 0x02, 0x01, 0x05, 0x80, 0x01, 0x00]);

        let mut buf = BytesMut::new();
        encode_confirmed_status_request(5, true, &mut buf);
        assert_eq!(&buf[..], &[0xa0, 0x06, 0x02, 0x01, 0x05, 0x80, 0x01, 0xff]);
    }

    #[test]
    fn request_round_trips_both_flags() {
        for flag in [false, true] {
            let mut buf = BytesMut::new();
            encode_confirmed_status_request(0x8000_0001, flag, &mut buf);
            assert_eq!(
                decode_confirmed_status_request(&buf).unwrap(),
                (0x8000_0001, flag)
            );
        }
    }

    #[test]
    fn request_any_non_zero_octet_is_true() {
        assert_eq!(decode_status_request(&[0x80, 0x01, 0x01]), Ok(true));
        assert_eq!(decode_status_request(&[0x80, 0x01, 0x00]), Ok(false));
    }

    #[test]
    fn request_boolean_of_wrong_length_is_rejected() {
        assert_eq!(
            decode_status_request(&[0x80, 0x00]),
            Err(MmsError::InvalidLength)
        );
        assert_eq!(
            decode_status_request(&[0x80, 0x02, 0x00, 0x00]),
            Err(MmsError::InvalidLength)
        );
        assert_eq!(
            decode_status_request(&[0x80, 0x01]),
            Err(MmsError::TruncatedPdu)
        );
    }

    #[test]
    fn request_decode_rejects_other_service() {
        // identify [2] in place of status [0]
        assert_eq!(
            decode_status_request(&[0x82, 0x00]),
            Err(MmsError::InvalidTag {
                expected: SERVICE_TAG_STATUS_REQUEST,
                actual: 0x82,
            })
        );
    }

    #[test]
    fn response_without_local_detail_is_byte_exact() {
        let resp = StatusResponse::new(
            VmdLogicalStatus::StateChangesAllowed,
            VmdPhysicalStatus::Operational,
        );
        let mut buf = BytesMut::new();
        encode_confirmed_status_response(7, &resp, &mut buf);
        assert_eq!(
            &buf[..],
            &[0xa1, 0x0b, 0x02, 0x01, 0x07, 0xa0, 0x06, 0x80, 0x01, 0x00, 0x81, 0x01, 0x00]
        );
        let (id, decoded) = decode_confirmed_status_response(&buf).unwrap();
        assert_eq!(id, 7);
        assert_eq!(decoded, resp);
    }

    #[test]
    fn response_with_local_detail_round_trips() {
        let mut resp = StatusResponse::new(
            VmdLogicalStatus::LimitedServicesPermitted,
            VmdPhysicalStatus::NeedsCommissioning,
        );
        // 1010 0000 01, ten bits, six unused
        let mut bits = vec![false; 10];
        bits[0] = true;
        bits[2] = true;
        bits[9] = true;
        resp.local_detail = Some(bits);
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        assert_eq!(
            &buf[..],
            &[0xa0, 0x0b, 0x80, 0x01, 0x02, 0x81, 0x01, 0x03, 0x82, 0x03, 0x06, 0xa0, 0x40]
        );
        assert_eq!(StatusResponse::decode(&buf).unwrap(), resp);
    }

    #[test]
    fn response_with_empty_local_detail_differs_from_absent() {
        let mut resp = StatusResponse::new(
            VmdLogicalStatus::NoStateChangesAllowed,
            VmdPhysicalStatus::Inoperable,
        );
        resp.local_detail = Some(Vec::new());
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        assert!(buf.ends_with(&[0x82, 0x01, 0x00]), "got {:02x?}", &buf[..]);
        let decoded = StatusResponse::decode(&buf).unwrap();
        assert_eq!(decoded.local_detail, Some(Vec::new()));
    }

    #[test]
    fn response_with_unknown_values_keeps_them() {
        // logical 7, and physical 300 as a two-octet INTEGER
        let data = [0xa0, 0x07, 0x80, 0x01, 0x07, 0x81, 0x02, 0x01, 0x2c];
        let resp = StatusResponse::decode(&data).unwrap();
        assert_eq!(resp.logical_status, VmdLogicalStatus::Other(7));
        assert_eq!(resp.physical_status, VmdPhysicalStatus::Other(300));

        // logical -1 as a one-octet INTEGER
        let data = [0xa0, 0x06, 0x80, 0x01, 0xff, 0x81, 0x01, 0x01];
        let resp = StatusResponse::decode(&data).unwrap();
        assert_eq!(resp.logical_status, VmdLogicalStatus::Other(-1));
        assert_eq!(
            resp.physical_status,
            VmdPhysicalStatus::PartiallyOperational
        );

        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        assert_eq!(
            &buf[..],
            &data[..],
            "an unknown value re-encodes as received"
        );
    }

    #[test]
    fn status_codes_map_both_ways() {
        for code in 0..4 {
            assert_eq!(VmdLogicalStatus::from_code(code).code(), code);
            assert_eq!(VmdPhysicalStatus::from_code(code).code(), code);
            assert!(!matches!(
                VmdLogicalStatus::from_code(code),
                VmdLogicalStatus::Other(_)
            ));
            assert!(!matches!(
                VmdPhysicalStatus::from_code(code),
                VmdPhysicalStatus::Other(_)
            ));
        }
        assert_eq!(VmdLogicalStatus::from_code(4), VmdLogicalStatus::Other(4));
        assert_eq!(VmdPhysicalStatus::from_code(4), VmdPhysicalStatus::Other(4));
    }

    #[test]
    fn response_missing_physical_status_is_invalid() {
        let data = [0xa0, 0x03, 0x80, 0x01, 0x00];
        assert_eq!(StatusResponse::decode(&data), Err(MmsError::InvalidPdu));
    }

    #[test]
    fn response_with_empty_integer_is_rejected() {
        let data = [0xa0, 0x05, 0x80, 0x00, 0x81, 0x01, 0x00];
        assert_eq!(StatusResponse::decode(&data), Err(MmsError::InvalidLength));
    }

    #[test]
    fn response_with_oversized_local_detail_is_invalid() {
        // 136 bits: padding 0 and 17 data octets
        let mut data = vec![
            0xa0, 0x1a, 0x80, 0x01, 0x00, 0x81, 0x01, 0x00, 0x82, 0x12, 0x00,
        ];
        data.extend_from_slice(&[0u8; 17]);
        assert_eq!(StatusResponse::decode(&data), Err(MmsError::InvalidPdu));
    }

    #[test]
    fn response_with_local_detail_of_exactly_128_bits_is_accepted() {
        let mut data = vec![
            0xa0, 0x19, 0x80, 0x01, 0x00, 0x81, 0x01, 0x00, 0x82, 0x11, 0x00,
        ];
        data.extend_from_slice(&[0xffu8; 16]);
        let resp = StatusResponse::decode(&data).unwrap();
        assert_eq!(resp.local_detail, Some(vec![true; MAX_LOCAL_DETAIL_BITS]));
    }

    #[test]
    fn response_with_bad_padding_is_invalid() {
        let data = [
            0xa0, 0x0a, 0x80, 0x01, 0x00, 0x81, 0x01, 0x00, 0x82, 0x02, 0x08, 0x00,
        ];
        assert_eq!(StatusResponse::decode(&data), Err(MmsError::InvalidPdu));
    }

    #[test]
    fn local_detail_past_the_limit_is_cut_when_encoding() {
        let mut resp = StatusResponse::new(
            VmdLogicalStatus::StateChangesAllowed,
            VmdPhysicalStatus::Operational,
        );
        resp.local_detail = Some(vec![true; MAX_LOCAL_DETAIL_BITS + 3]);
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        let decoded = StatusResponse::decode(&buf).unwrap();
        assert_eq!(
            decoded.local_detail,
            Some(vec![true; MAX_LOCAL_DETAIL_BITS])
        );
    }

    #[test]
    fn response_with_truncated_field_is_rejected() {
        let data = [0xa0, 0x04, 0x80, 0x03, 0x00, 0x00];
        assert_eq!(StatusResponse::decode(&data), Err(MmsError::TruncatedPdu));
    }

    #[test]
    fn response_decode_rejects_wrong_service_tag() {
        let data = [0xa2, 0x00];
        assert_eq!(
            StatusResponse::decode(&data),
            Err(MmsError::InvalidTag {
                expected: SERVICE_TAG_STATUS_RESPONSE,
                actual: 0xa2,
            })
        );
    }

    #[test]
    fn response_skips_unknown_tags() {
        let data = [
            0xa0, 0x09, 0x80, 0x01, 0x00, 0x85, 0x01, 0x07, 0x81, 0x01, 0x00,
        ];
        let resp = StatusResponse::decode(&data).unwrap();
        assert_eq!(resp.logical_status, VmdLogicalStatus::StateChangesAllowed);
        assert_eq!(resp.physical_status, VmdPhysicalStatus::Operational);
    }
}
