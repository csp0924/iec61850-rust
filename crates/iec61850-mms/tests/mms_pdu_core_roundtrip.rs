#![allow(clippy::field_reassign_with_default)] // readability first in tests

//! Integration tests for the MmsPdu dispatch and the three Initiate PDUs.
//!
//! Covered here:
//! - `MmsPdu` tag dispatch across all ten variants
//! - `InitiateRequestPdu` encode / decode roundtrip
//! - `InitiateResponsePdu` encode / decode roundtrip
//! - byte-exact `InitiateErrorPdu` encoding, `0xaa 0x05 0xa0 0x03 0x88 0x01 0x00`
//! - byte-exact `ConcludeRequestPdu` encoding, `0x8b 0x00`
//! - byte-exact `ConcludeResponsePdu` encoding, `0x8c 0x00`
//! - a parameterCBB length other than 3, which yields `InvalidParameterCbbLength`
//! - the BIT STRING padding byte, which must be skipped
//! - an oversized length field, which must return an error rather than panic
//! - a malformed PDU missing a mandatory field, which must be rejected

use bytes::{Bytes, BytesMut};
use iec61850_mms::mms::{
    InitiateErrorPdu, InitiateRequestPdu, InitiateResponsePdu, MmsError, MmsPdu,
    DEFAULT_SERVICES_SUPPORTED_CLIENT,
};
use iec61850_mms::{ConcludeRequestPdu, ConcludeResponsePdu};

// MmsPdu tag dispatch, one test per variant

#[test]
fn dispatch_tag_0xa0_confirmed_request() {
    let pdu = MmsPdu::decode(&[0xa0, 0x01, 0x00]).unwrap();
    assert!(matches!(pdu, MmsPdu::ConfirmedRequest(_)));
    assert_eq!(pdu.tag_byte(), 0xa0);
}

#[test]
fn dispatch_tag_0xa1_confirmed_response() {
    let pdu = MmsPdu::decode(&[0xa1, 0x01, 0x00]).unwrap();
    assert!(matches!(pdu, MmsPdu::ConfirmedResponse(_)));
    assert_eq!(pdu.tag_byte(), 0xa1);
}

#[test]
fn dispatch_tag_0xa2_confirmed_error() {
    let pdu = MmsPdu::decode(&[0xa2, 0x01, 0x00]).unwrap();
    assert!(matches!(pdu, MmsPdu::ConfirmedError(_)));
    assert_eq!(pdu.tag_byte(), 0xa2);
}

#[test]
fn dispatch_tag_0xa3_unconfirmed() {
    let pdu = MmsPdu::decode(&[0xa3, 0x01, 0x00]).unwrap();
    assert!(matches!(pdu, MmsPdu::Unconfirmed(_)));
    assert_eq!(pdu.tag_byte(), 0xa3);
}

#[test]
fn dispatch_tag_0xa4_reject() {
    // the smallest legal RejectPdu: no invokeId and ConfirmedRequest::Other(0),
    // whose content 81 01 00 is 3 bytes, giving a4 03 81 01 00
    let pdu = MmsPdu::decode(&[0xa4, 0x03, 0x81, 0x01, 0x00]).unwrap();
    assert!(matches!(pdu, MmsPdu::Reject(_)));
    assert_eq!(pdu.tag_byte(), 0xa4);
}

#[test]
fn dispatch_tag_0xa8_initiate_request() {
    let req = InitiateRequestPdu::default();
    let mut buf = BytesMut::new();
    req.encode(&mut buf);
    let pdu = MmsPdu::decode(&buf).unwrap();
    assert!(matches!(pdu, MmsPdu::InitiateRequest(_)));
    assert_eq!(pdu.tag_byte(), 0xa8);
}

#[test]
fn dispatch_tag_0xa9_initiate_response() {
    let resp = InitiateResponsePdu::default();
    let mut buf = BytesMut::new();
    resp.encode(&mut buf);
    let pdu = MmsPdu::decode(&buf).unwrap();
    assert!(matches!(pdu, MmsPdu::InitiateResponse(_)));
    assert_eq!(pdu.tag_byte(), 0xa9);
}

#[test]
fn dispatch_tag_0xaa_initiate_error() {
    let err_pdu = InitiateErrorPdu::new(0);
    let mut buf = BytesMut::new();
    err_pdu.encode(&mut buf);
    let pdu = MmsPdu::decode(&buf).unwrap();
    assert!(matches!(pdu, MmsPdu::InitiateError(_)));
    assert_eq!(pdu.tag_byte(), 0xaa);
}

#[test]
fn dispatch_tag_0x8b_conclude_request() {
    let pdu = MmsPdu::decode(&[0x8b, 0x00]).unwrap();
    assert_eq!(pdu, MmsPdu::ConcludeRequest);
    assert_eq!(pdu.tag_byte(), 0x8b);
}

#[test]
fn dispatch_tag_0x8c_conclude_response() {
    let pdu = MmsPdu::decode(&[0x8c, 0x00]).unwrap();
    assert_eq!(pdu, MmsPdu::ConcludeResponse);
    assert_eq!(pdu.tag_byte(), 0x8c);
}

// InitiateRequestPdu encode roundtrip

#[test]
fn initiate_request_roundtrip_default() {
    let req = InitiateRequestPdu::default();
    let mut buf = BytesMut::new();
    req.encode(&mut buf);
    let decoded = InitiateRequestPdu::decode(&buf).unwrap();
    assert_eq!(decoded, req);
}

#[test]
fn initiate_request_roundtrip_custom_values() {
    let mut req = InitiateRequestPdu::default();
    req.local_detail_calling = Some(4096);
    req.proposed_max_serv_outstanding_calling = 10;
    req.proposed_max_serv_outstanding_called = 3;
    req.proposed_data_structure_nesting_level = Some(5);

    let mut buf = BytesMut::new();
    req.encode(&mut buf);
    let decoded = InitiateRequestPdu::decode(&buf).unwrap();
    assert_eq!(decoded, req);
}

// InitiateResponsePdu encode roundtrip

#[test]
fn initiate_response_roundtrip_default() {
    let resp = InitiateResponsePdu::default();
    let mut buf = BytesMut::new();
    resp.encode(&mut buf);
    let decoded = InitiateResponsePdu::decode(&buf).unwrap();
    assert_eq!(decoded, resp);
}

#[test]
fn initiate_response_roundtrip_small_pdu_size() {
    let mut resp = InitiateResponsePdu::default();
    resp.local_detail_called = Some(1024);
    resp.negotiated_max_serv_outstanding_calling = 2;
    resp.negotiated_max_serv_outstanding_called = 2;
    resp.negotiated_data_structure_nesting_level = Some(4);

    let mut buf = BytesMut::new();
    resp.encode(&mut buf);
    let decoded = InitiateResponsePdu::decode(&buf).unwrap();
    assert_eq!(decoded, resp);
}

// InitiateErrorPdu byte-exact encode

/// Byte exact: `0xaa 0x05 0xa0 0x03 0x88 0x01 0x00`.
#[test]
fn initiate_error_encode_byte_exact() {
    let err_pdu = InitiateErrorPdu::new(0);
    let mut buf = BytesMut::new();
    err_pdu.encode(&mut buf);
    assert_eq!(
        &buf[..],
        &[0xaa, 0x05, 0xa0, 0x03, 0x88, 0x01, 0x00],
        "the InitiateErrorPdu encoding is not byte exact"
    );
}

#[test]
fn initiate_error_roundtrip() {
    let err_pdu = InitiateErrorPdu::new(1); // version-incompatible
    let mut buf = BytesMut::new();
    err_pdu.encode(&mut buf);
    let decoded = InitiateErrorPdu::decode(&buf).unwrap();
    assert_eq!(decoded, err_pdu);
}

// ConcludeRequest / Response byte-exact encode

/// Byte exact: `0x8b 0x00`.
#[test]
fn conclude_request_encode_byte_exact() {
    let mut buf = BytesMut::new();
    ConcludeRequestPdu.encode(&mut buf);
    assert_eq!(&buf[..], &[0x8b, 0x00]);
}

/// Byte exact: `0x8c 0x00`.
#[test]
fn conclude_response_encode_byte_exact() {
    let mut buf = BytesMut::new();
    ConcludeResponsePdu.encode(&mut buf);
    assert_eq!(&buf[..], &[0x8c, 0x00]);
}

// A parameterCBB length other than 3 is rejected

/// A parameterCBB length other than 3 yields `InvalidParameterCbbLength`.
#[test]
fn parameter_cbb_wrong_length_returns_err() {
    // encode a valid PDU, then patch the parameterCBB length
    let req = InitiateRequestPdu::default();
    let mut buf = BytesMut::new();
    req.encode(&mut buf);

    // find 0x81 0x03, the parameterCBB tag and length, and set the length to 2
    let bytes = buf.as_mut();
    let mut found = false;
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i] == 0x81 && bytes[i + 1] == 0x03 {
            bytes[i + 1] = 0x02;
            found = true;
            break;
        }
    }
    assert!(found, "the parameterCBB TLV to mutate was not found");

    let result = InitiateRequestPdu::decode(bytes);
    assert!(
        matches!(
            result,
            Err(MmsError::InvalidParameterCbbLength { actual: 2 })
        ),
        "a parameterCBB length of 2 must return InvalidParameterCbbLength(2), got: {:?}",
        result
    );
}

// The BIT STRING padding byte must be skipped

/// BIT STRING decoding must skip the leading padding count before reading the data.
///
/// A decoder that forgets to skip it shifts the services bitmap by one byte, so this
/// test requires `services_supported_calling[0]` to be 0xee rather than 0x03.
#[test]
fn bit_string_padding_byte_not_treated_as_data() {
    let req = InitiateRequestPdu::default();
    let mut buf = BytesMut::new();
    req.encode(&mut buf);
    let decoded = InitiateRequestPdu::decode(&buf).unwrap();

    let services = decoded.init_request_detail.services_supported_calling;
    assert_ne!(
        services[0], 0x03,
        "the first services byte must not be the padding count 0x03"
    );
    assert_eq!(
        services[0], 0xee,
        "services[0] must be 0xee, the first default client byte"
    );
    assert_eq!(
        services, DEFAULT_SERVICES_SUPPORTED_CLIENT,
        "the whole services array must match the client default"
    );
}

// An oversized length field must not panic

/// An oversized length, 0xff 0xff, must return an error rather than panic.
#[test]
fn oversized_length_does_not_panic() {
    let cases: &[&[u8]] = &[
        &[0xa8, 0x82, 0xff, 0xff], // InitiateRequest tag + long-form 65535
        &[0xa9, 0x82, 0xff, 0xff], // InitiateResponse tag
        &[0xaa, 0x82, 0xff, 0xff], // InitiateError tag
        &[0xa0, 0x82, 0xff, 0xff], // ConfirmedRequest tag
    ];
    for case in cases {
        let result = MmsPdu::decode(case);
        assert!(
            result.is_err(),
            "an oversized length must return an error, not panic: {:02x?}",
            case
        );
    }
}

// A malformed PDU missing a mandatory field

/// An InitiateRequestPdu without `proposedMaxServOutstandingCalling` is rejected.
#[test]
fn malformed_initiate_request_missing_mandatory_field() {
    // only the optional localDetailCalling, without the mandatory outstanding fields:
    // 0xa8 <len> 0x80 0x01 0x05
    let inner: &[u8] = &[0x80, 0x01, 0x05]; // localDetailCalling = 5
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&[0xa8, inner.len() as u8]);
    buf.extend_from_slice(inner);

    let result = InitiateRequestPdu::decode(&buf);
    assert!(
        result.is_err(),
        "a missing proposedMaxServOutstandingCalling must return an error"
    );
}

/// An empty PDU returns TruncatedPdu.
#[test]
fn empty_pdu_returns_truncated() {
    let result = MmsPdu::decode(&[]);
    assert!(matches!(result, Err(MmsError::TruncatedPdu)));
}

/// An unknown tag, such as 0xa5 for cancel-request, returns UnknownMmsPduTag.
#[test]
fn unknown_tag_returns_err() {
    let result = MmsPdu::decode(&[0xa5, 0x01, 0x00]);
    assert!(matches!(result, Err(MmsError::UnknownMmsPduTag(0xa5))));
}

// MmsPdu encode via top-level enum

#[test]
fn mmspdu_initiate_error_byte_exact_via_enum() {
    let pdu = MmsPdu::InitiateError(InitiateErrorPdu::new(0));
    let mut buf = BytesMut::new();
    pdu.encode(&mut buf);
    assert_eq!(&buf[..], &[0xaa, 0x05, 0xa0, 0x03, 0x88, 0x01, 0x00]);
}

#[test]
fn mmspdu_conclude_request_byte_exact_via_enum() {
    let pdu = MmsPdu::ConcludeRequest;
    let mut buf = BytesMut::new();
    pdu.encode(&mut buf);
    assert_eq!(&buf[..], &[0x8b, 0x00]);
}

#[test]
fn mmspdu_conclude_response_byte_exact_via_enum() {
    let pdu = MmsPdu::ConcludeResponse;
    let mut buf = BytesMut::new();
    pdu.encode(&mut buf);
    assert_eq!(&buf[..], &[0x8c, 0x00]);
}

#[test]
fn raw_bytes_variant_roundtrip() {
    let inner = Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]);
    let pdu = MmsPdu::ConfirmedRequest(inner.clone());
    let mut buf = BytesMut::new();
    pdu.encode(&mut buf);

    let decoded = MmsPdu::decode(&buf).unwrap();
    if let MmsPdu::ConfirmedRequest(got) = decoded {
        assert_eq!(got, inner);
    } else {
        panic!("the decoded pdu is not a ConfirmedRequest");
    }
}

// A dataStructureNestingLevel above MAX_NESTING_LEVEL is rejected

/// A dataStructureNestingLevel above `MAX_NESTING_LEVEL`, 32, yields NestingLevelExceeded.
#[test]
fn nesting_level_255_returns_err() {
    let req = InitiateRequestPdu::default();
    let mut buf = BytesMut::new();
    req.encode(&mut buf);

    // find 0x83 0x01 <level>, the nesting level field, and set it to 255
    let bytes = buf.as_mut();
    let mut found = false;
    for i in 0..bytes.len().saturating_sub(2) {
        if bytes[i] == 0x83 && bytes[i + 1] == 0x01 {
            bytes[i + 2] = 255;
            found = true;
            break;
        }
    }
    assert!(found, "the nesting level TLV was not found");

    let result = InitiateRequestPdu::decode(bytes);
    assert!(
        matches!(
            result,
            Err(MmsError::NestingLevelExceeded { max: 32, got: 255 })
        ),
        "a nesting level of 255 must return NestingLevelExceeded(max=32, got=255), got: {:?}",
        result
    );
}

// An indefinite BER length must be rejected

/// An indefinite BER length, `0x80`, must be rejected with an error.
///
/// A decoder that accepts the indefinite form loops forever while parsing the
/// content. `decode_length` returns `InvalidLength` for `0x80` instead.
#[test]
fn indefinite_length_returns_err() {
    // 0xa8 is the InitiateRequest tag and 0x80 the indefinite length marker
    let malformed: &[u8] = &[0xa8, 0x80, 0x01, 0x00, 0x00, 0x00];
    let result = MmsPdu::decode(malformed);
    assert!(
        result.is_err(),
        "an indefinite length 0x80 must return an error, not loop, got: {:?}",
        result
    );
    // and 0x80 must not be read as a two-byte long form
    assert!(
        !matches!(result, Err(MmsError::UnknownMmsPduTag(_))),
        "the failure must be a length error, not an unknown tag"
    );
}

/// The same check against the InitiateResponse tag.
#[test]
fn indefinite_length_response_tag_returns_err() {
    let malformed: &[u8] = &[0xa9, 0x80, 0x00, 0x00];
    let result = MmsPdu::decode(malformed);
    assert!(
        result.is_err(),
        "0xa9 with an indefinite length must return an error"
    );
}

// Tags [5], [6] and [7], the cancel services, are unknown

/// Tags [5], [6] and [7], the cancel services, return `UnknownMmsPduTag`.
#[test]
fn cancel_tags_5_6_7_unknown() {
    for tag in [0xa5u8, 0xa6, 0xa7] {
        let data = &[tag, 0x01, 0x00];
        let result = MmsPdu::decode(data);
        assert!(
            matches!(result, Err(MmsError::UnknownMmsPduTag(_))),
            "tag 0x{:02X} must return UnknownMmsPduTag, got: {:?}",
            tag,
            result
        );
    }
}
