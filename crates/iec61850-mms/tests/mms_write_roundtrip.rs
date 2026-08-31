#![allow(clippy::approx_constant)] // 3.14 is a test sentinel, not an approximation of pi

//! Integration tests for the MMS Write request and response.
//!
//! Covered here:
//! - a single domain-specific variable round trip
//! - a multi-variable batch round trip
//! - the variableListName path
//! - WriteResponse outcomes: success, failure and a mixture
//! - a mismatch between the access specification and listOfData, which is rejected
//! - more than MAX_WRITE_ITEMS, that is 100, which is rejected
//! - a nesting depth bomb inside listOfData
//! - decode_with_expected_count, which requires the outcome count to match

use bytes::BytesMut;
use iec61850_mms::{
    decode_confirmed_write_request, decode_confirmed_write_response,
    encode_confirmed_write_request, encode_confirmed_write_response, DataAccessError, MmsData,
    MmsError, ObjectName, VariableAccessSpecification, WriteOutcome, WriteRequest, WriteResponse,
    MAX_WRITE_ITEMS, SERVICE_TAG_WRITE,
};

// WriteRequest round trips

#[test]
fn write_request_single_domain_boolean_roundtrip() {
    let req = WriteRequest::single_domain("TESTLD", "GGIO1$CO$Ind$Oper", MmsData::Boolean(true));
    let mut buf = BytesMut::new();
    req.encode(&mut buf);
    assert_eq!(buf[0], SERVICE_TAG_WRITE);
    let decoded = WriteRequest::decode(&buf).unwrap();
    assert_eq!(decoded, req);
    assert_eq!(decoded.list_of_data.len(), 1);
    assert_eq!(decoded.list_of_data[0], MmsData::Boolean(true));
}

#[test]
fn write_request_single_domain_integer_roundtrip() {
    let req = WriteRequest::single_domain("LD1", "MV1$MX$mag$f", MmsData::Integer(-9999));
    let mut buf = BytesMut::new();
    req.encode(&mut buf);
    let decoded = WriteRequest::decode(&buf).unwrap();
    assert_eq!(decoded, req);
}

#[test]
fn write_request_multiple_items_roundtrip() {
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
            ObjectName::DomainSpecific {
                domain_id: "LD1".to_owned(),
                item_id: "C".to_owned(),
            }
            .into(),
        ]),
        list_of_data: vec![
            MmsData::Boolean(false),
            MmsData::Integer(42),
            MmsData::Unsigned(0),
        ],
    };
    let mut buf = BytesMut::new();
    req.encode(&mut buf);
    let decoded = WriteRequest::decode(&buf).unwrap();
    assert_eq!(decoded, req);
    assert_eq!(decoded.list_of_data.len(), 3);
}

#[test]
fn write_request_named_variable_list_domain_specific_roundtrip() {
    let name = ObjectName::DomainSpecific {
        domain_id: "TESTLD".to_owned(),
        item_id: "DataSet1".to_owned(),
    };
    let req = WriteRequest::named_list(
        name,
        vec![
            MmsData::Boolean(true),
            MmsData::Integer(100),
            MmsData::VisibleString("status".to_owned()),
        ],
    );
    let mut buf = BytesMut::new();
    req.encode(&mut buf);
    let decoded = WriteRequest::decode(&buf).unwrap();
    assert_eq!(decoded, req);
    assert!(matches!(
        &decoded.variable_access_spec,
        VariableAccessSpecification::VariableListName(_)
    ));
}

#[test]
fn write_request_all_data_types_roundtrip() {
    // every MmsData variant must encode and decode on the write path
    let data_list = vec![
        MmsData::Boolean(true),
        MmsData::Integer(-12345),
        MmsData::Unsigned(65535),
        MmsData::Float64(3.14),
        MmsData::OctetString(vec![0xde, 0xad, 0xbe, 0xef]),
        MmsData::VisibleString("test".to_owned()),
        MmsData::UtcTime([0x5e, 0x1a, 0x2b, 0x3c, 0x00, 0x00, 0x00, 0x00]),
        MmsData::BitString {
            padding: 3,
            data: vec![0xf8],
        },
    ];
    let entries: Vec<iec61850_mms::ListOfVariableEntry> = (0..data_list.len())
        .map(|i| ObjectName::VmdSpecific(format!("V{}", i)).into())
        .collect();
    let req = WriteRequest {
        variable_access_spec: VariableAccessSpecification::ListOfVariable(entries),
        list_of_data: data_list,
    };
    let mut buf = BytesMut::new();
    req.encode(&mut buf);
    let decoded = WriteRequest::decode(&buf).unwrap();
    assert_eq!(decoded, req);
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
    assert_eq!(&buf[2..], &[0x81, 0x00]); // success body
    let decoded = WriteResponse::decode(&buf).unwrap();
    assert_eq!(decoded, resp);
}

#[test]
fn write_response_single_failure_roundtrip() {
    let resp = WriteResponse {
        outcomes: vec![WriteOutcome::Failure(DataAccessError::TypeInconsistent)],
    };
    let mut buf = BytesMut::new();
    resp.encode(&mut buf);
    // 0xa5 <len> 0x80 0x01 0x07
    assert_eq!(&buf[2..], &[0x80, 0x01, 7]);
    let decoded = WriteResponse::decode(&buf).unwrap();
    assert_eq!(decoded, resp);
}

#[test]
fn write_response_five_mixed_outcomes_roundtrip() {
    let resp = WriteResponse {
        outcomes: vec![
            WriteOutcome::Success,
            WriteOutcome::Success,
            WriteOutcome::Failure(DataAccessError::ObjectAccessDenied),
            WriteOutcome::Success,
            WriteOutcome::Failure(DataAccessError::HardwareFault),
        ],
    };
    let mut buf = BytesMut::new();
    resp.encode(&mut buf);
    let decoded = WriteResponse::decode(&buf).unwrap();
    assert_eq!(decoded.outcomes.len(), 5);
    assert_eq!(decoded, resp);
}

#[test]
fn write_response_all_data_access_errors() {
    // all eleven DataAccessError codes must encode and decode
    for code in 0u8..=11u8 {
        let err = DataAccessError::from_code(code).unwrap();
        let resp = WriteResponse {
            outcomes: vec![WriteOutcome::Failure(err)],
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        let decoded = WriteResponse::decode(&buf).unwrap();
        assert_eq!(
            decoded, resp,
            "DataAccessError code {} failed to round trip",
            code
        );
    }
}

// ConfirmedRequestPdu and ConfirmedResponsePdu wrappers

#[test]
fn confirmed_write_request_invoke_id_preserved() {
    let req = WriteRequest::single_domain("LD1", "V1", MmsData::Integer(1));
    let mut buf = BytesMut::new();
    encode_confirmed_write_request(42, &req, &mut buf);
    assert_eq!(buf[0], 0xa0);
    let (id, decoded) = decode_confirmed_write_request(&buf).unwrap();
    assert_eq!(id, 42);
    assert_eq!(decoded, req);
}

#[test]
fn confirmed_write_response_invoke_id_preserved() {
    let resp = WriteResponse {
        outcomes: vec![WriteOutcome::Success],
    };
    let mut buf = BytesMut::new();
    encode_confirmed_write_response(77, &resp, &mut buf);
    assert_eq!(buf[0], 0xa1);
    let (id, decoded) = decode_confirmed_write_response(&buf).unwrap();
    assert_eq!(id, 77);
    assert_eq!(decoded, resp);
}

// decode_with_expected_count

#[test]
fn write_response_decode_with_expected_count_match_ok() {
    let resp = WriteResponse {
        outcomes: vec![
            WriteOutcome::Success,
            WriteOutcome::Failure(DataAccessError::ObjectNonExistent),
        ],
    };
    let mut buf = BytesMut::new();
    resp.encode(&mut buf);
    let result = WriteResponse::decode_with_expected_count(&buf, 2);
    assert!(result.is_ok());
}

#[test]
fn write_response_decode_with_expected_count_mismatch_err() {
    // the outcome count is always compared; there is no mode that skips the check
    let resp = WriteResponse {
        outcomes: vec![WriteOutcome::Success],
    };
    let mut buf = BytesMut::new();
    resp.encode(&mut buf);
    // two outcomes are expected while the response carries one
    let result = WriteResponse::decode_with_expected_count(&buf, 2);
    assert!(
        matches!(
            result,
            Err(MmsError::WriteCountMismatch {
                expected: 2,
                actual: 1
            })
        ),
        "got: {:?}",
        result
    );
}

// a mismatch between the access specification and listOfData

#[test]
fn write_request_vaspec_data_count_mismatch_err() {
    // encode by hand: two variables named and three values, bypassing the encoder check
    let mut buf = BytesMut::new();
    let mut inner = BytesMut::new();

    // vaSpec = listOfVariable with 2 items
    let mut vas_inner = BytesMut::new();
    for name in &["A", "B"] {
        // ListOfVariableSeq = 0x30 <len> 0xa0 <len> 0x80 <len> <name>
        let nb = name.as_bytes();
        let vs = [0xa0u8, (2 + nb.len()) as u8, 0x80, nb.len() as u8];
        let seq_inner: Vec<u8> = [vs.as_ref(), nb].concat();
        let seq_len = seq_inner.len();
        inner.extend_from_slice(&[0x30, seq_len as u8]);
        inner.extend_from_slice(&seq_inner);
        vas_inner.extend_from_slice(&[0x30, seq_len as u8]);
        vas_inner.extend_from_slice(&seq_inner);
    }
    let mut tmp = BytesMut::new();
    tmp.extend_from_slice(&[0xa0]);
    tmp.extend_from_slice(&[vas_inner.len() as u8]);
    tmp.extend_from_slice(&vas_inner);

    // listOfData = 0xa0 + 3 items
    let mut data_buf = BytesMut::new();
    for _ in 0..3 {
        data_buf.extend_from_slice(&[0x83, 0x01, 0x01]); // boolean true
    }
    tmp.extend_from_slice(&[0xa0, data_buf.len() as u8]);
    tmp.extend_from_slice(&data_buf);

    buf.extend_from_slice(&[SERVICE_TAG_WRITE, tmp.len() as u8]);
    buf.extend_from_slice(&tmp);

    let result = WriteRequest::decode(&buf);
    assert!(
        matches!(result, Err(MmsError::WriteCountMismatch { .. })),
        "two variables with three values must return WriteCountMismatch, got: {:?}",
        result
    );
}

// more than MAX_WRITE_ITEMS, that is 100

#[test]
fn write_request_101_items_too_many_err() {
    const N: usize = MAX_WRITE_ITEMS + 1; // 101
    let names: Vec<ObjectName> = (0..N)
        .map(|i| ObjectName::VmdSpecific(format!("V{:03}", i)))
        .collect();
    let data: Vec<MmsData> = (0..N).map(|_| MmsData::Boolean(true)).collect();

    // encode by hand to bypass the encoder-side check
    let mut inner = BytesMut::new();
    // vaSpec
    let mut vas_inner = BytesMut::new();
    for name in &names {
        match name {
            ObjectName::VmdSpecific(s) => {
                let nb = s.as_bytes();
                // VariableSpec.name 0xa0 <> ObjectName.vmdspecific 0x80 <> name
                let obj: Vec<u8> = [&[0x80u8, nb.len() as u8], nb].concat();
                let vs: Vec<u8> = [&[0xa0u8, obj.len() as u8], obj.as_slice()].concat();
                let seq: Vec<u8> = [&[0x30u8, vs.len() as u8], vs.as_slice()].concat();
                vas_inner.extend_from_slice(&seq);
            }
            _ => unreachable!(),
        }
    }
    inner.extend_from_slice(&[0xa0]);
    if vas_inner.len() < 128 {
        inner.extend_from_slice(&[vas_inner.len() as u8]);
    } else if vas_inner.len() <= 0xff {
        inner.extend_from_slice(&[0x81, vas_inner.len() as u8]);
    } else {
        inner.extend_from_slice(&[
            0x82,
            (vas_inner.len() >> 8) as u8,
            (vas_inner.len() & 0xff) as u8,
        ]);
    }
    inner.extend_from_slice(&vas_inner);

    // listOfData
    let mut data_buf = BytesMut::new();
    for _ in &data {
        data_buf.extend_from_slice(&[0x83, 0x01, 0x01]);
    }
    inner.extend_from_slice(&[0xa0]);
    if data_buf.len() < 128 {
        inner.extend_from_slice(&[data_buf.len() as u8]);
    } else if data_buf.len() <= 0xff {
        inner.extend_from_slice(&[0x81, data_buf.len() as u8]);
    } else {
        inner.extend_from_slice(&[
            0x82,
            (data_buf.len() >> 8) as u8,
            (data_buf.len() & 0xff) as u8,
        ]);
    }
    inner.extend_from_slice(&data_buf);

    let mut buf = BytesMut::new();
    buf.extend_from_slice(&[SERVICE_TAG_WRITE]);
    if inner.len() < 128 {
        buf.extend_from_slice(&[inner.len() as u8]);
    } else if inner.len() <= 0xff {
        buf.extend_from_slice(&[0x81, inner.len() as u8]);
    } else {
        buf.extend_from_slice(&[0x82, (inner.len() >> 8) as u8, (inner.len() & 0xff) as u8]);
    }
    buf.extend_from_slice(&inner);

    let result = WriteRequest::decode(&buf);
    assert!(
        matches!(result, Err(MmsError::TooManyWriteItems { count: 101 })),
        "101 items must return TooManyWriteItems, got: {:?}",
        result
    );
}

/// A listOfData nesting 33 structures must be rejected, not overflow the stack.
#[test]
fn write_listofdata_depth_bomb_err() {
    fn make_nested(depth: usize) -> Vec<u8> {
        if depth == 0 {
            return vec![0xa2, 0x00]; // an empty structure
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

    let bomb = make_nested(33);

    // vaSpec = listOfVariable with 1 VmdSpecific "V"
    let vs_inner: Vec<u8> = vec![0xa0, 0x03, 0x80, 0x01, b'V'];
    let seq: Vec<u8> = [&[0x30u8, vs_inner.len() as u8], vs_inner.as_slice()].concat();
    let vas: Vec<u8> = [&[0xa0u8, seq.len() as u8], seq.as_slice()].concat();

    // listOfData = 0xa0 + bomb
    let mut list_data = vec![0xa0u8];
    if bomb.len() < 128 {
        list_data.push(bomb.len() as u8);
    } else {
        list_data.push(0x81);
        list_data.push(bomb.len() as u8);
    }
    list_data.extend_from_slice(&bomb);

    let mut inner: Vec<u8> = vas;
    inner.extend_from_slice(&list_data);

    let mut buf: Vec<u8> = vec![SERVICE_TAG_WRITE];
    if inner.len() < 128 {
        buf.push(inner.len() as u8);
    } else {
        buf.push(0x81);
        buf.push(inner.len() as u8);
    }
    buf.extend_from_slice(&inner);

    let result = WriteRequest::decode(&buf);
    assert!(
        matches!(result, Err(MmsError::NestingLevelExceeded { .. })),
        "a listOfData depth bomb must return NestingLevelExceeded, got: {:?}",
        result
    );
}

// an oversized length field must not panic

#[test]
fn write_request_oversized_length_no_panic() {
    // 0xa5 0x82 0xff 0xff: a WriteRequest tag with a length of 65535 and far less data
    let poison = [0xa5u8, 0x82, 0xff, 0xff, 0x00, 0x01];
    let result = WriteRequest::decode(&poison);
    assert!(
        result.is_err(),
        "an oversized length must return an error, not panic"
    );
}

#[test]
fn write_response_oversized_length_no_panic() {
    let poison = [0xa5u8, 0x82, 0xff, 0xff, 0x00, 0x01];
    let result = WriteResponse::decode(&poison);
    assert!(
        result.is_err(),
        "an oversized length must return an error, not panic"
    );
}

// malformed input

#[test]
fn write_request_wrong_service_tag_err() {
    // 0xa4 is the read tag, not the write tag
    let data = [0xa4u8, 0x00];
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
fn write_response_wrong_service_tag_err() {
    let data = [0xa4u8, 0x00];
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
fn write_request_empty_buf_err() {
    let result = WriteRequest::decode(&[]);
    assert!(matches!(result, Err(MmsError::TruncatedPdu)));
}

#[test]
fn write_response_empty_buf_err() {
    let result = WriteResponse::decode(&[]);
    assert!(matches!(result, Err(MmsError::TruncatedPdu)));
}
