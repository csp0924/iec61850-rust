//! Integration tests for the MMS Read request and response.
//!
//! Covered here:
//! - listOfVariable round trips, both domain-specific and vmd-specific
//! - variableListName round trips, both domain-specific and vmd-specific
//! - the three states of the OPTIONAL specificationWithResult: true, false, absent
//! - a listOfAccessResult mixing Success and Failure entries
//! - a nesting depth bomb
//! - an oversized length field, which must return an error rather than panic
//! - a 65-byte domainId, which must be rejected
//! - an invalid floatingpoint size, which must be rejected
//! - an invalid utctime size, which must be rejected
//! - an empty listOfAccessResult, which is legal

use bytes::BytesMut;
use iec61850_mms::{
    decode_confirmed_read_request, decode_confirmed_read_response, encode_confirmed_read_request,
    encode_confirmed_read_response, AccessResult, DataAccessError, MmsData, MmsError, ObjectName,
    ReadRequest, ReadResponse, VariableAccessSpecification,
};

// listOfVariable round trips

#[test]
fn read_request_list_of_variable_domain_specific_roundtrip() {
    let req = ReadRequest::single_domain("TESTLD", "GGIO1$ST$Ind$stVal");
    let mut buf = BytesMut::new();
    req.encode(&mut buf);
    let decoded = ReadRequest::decode(&buf).unwrap();
    assert_eq!(decoded, req);
    assert!(!decoded.specification_with_result);
    match &decoded.variable_access_spec {
        VariableAccessSpecification::ListOfVariable(entries) => {
            assert_eq!(entries.len(), 1);
            assert!(matches!(entries[0].name, ObjectName::DomainSpecific { .. }));
        }
        _ => panic!("expected ListOfVariable"),
    }
}

#[test]
fn read_request_list_of_variable_vmd_specific_roundtrip() {
    let req = ReadRequest {
        specification_with_result: false,
        variable_access_spec: VariableAccessSpecification::ListOfVariable(vec![
            ObjectName::VmdSpecific("MY_VAR".to_owned()).into(),
        ]),
    };
    let mut buf = BytesMut::new();
    req.encode(&mut buf);
    let decoded = ReadRequest::decode(&buf).unwrap();
    assert_eq!(decoded, req);
}

#[test]
fn read_request_multiple_variables_roundtrip() {
    let req = ReadRequest {
        specification_with_result: false,
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
    };
    let mut buf = BytesMut::new();
    req.encode(&mut buf);
    let decoded = ReadRequest::decode(&buf).unwrap();
    assert_eq!(decoded, req);
    match &decoded.variable_access_spec {
        VariableAccessSpecification::ListOfVariable(v) => assert_eq!(v.len(), 3),
        _ => panic!("expected ListOfVariable"),
    }
}

// variableListName round trips

#[test]
fn read_request_variable_list_name_domain_specific_roundtrip() {
    let name = ObjectName::DomainSpecific {
        domain_id: "TESTLD".to_owned(),
        item_id: "DataSet1".to_owned(),
    };
    let req = ReadRequest::named_list(name, false);
    let mut buf = BytesMut::new();
    req.encode(&mut buf);
    let decoded = ReadRequest::decode(&buf).unwrap();
    assert_eq!(decoded, req);
    assert!(matches!(
        &decoded.variable_access_spec,
        VariableAccessSpecification::VariableListName(_)
    ));
}

#[test]
fn read_request_variable_list_name_vmd_specific_roundtrip() {
    let name = ObjectName::VmdSpecific("GLOBAL_DS".to_owned());
    let req = ReadRequest::named_list(name, false);
    let mut buf = BytesMut::new();
    req.encode(&mut buf);
    let decoded = ReadRequest::decode(&buf).unwrap();
    assert_eq!(decoded, req);
}

// the three states of specificationWithResult

#[test]
fn read_request_spec_with_result_true_contains_0x80_01_01() {
    let name = ObjectName::DomainSpecific {
        domain_id: "LD".to_owned(),
        item_id: "DS".to_owned(),
    };
    let req = ReadRequest::named_list(name, true);
    let mut buf = BytesMut::new();
    req.encode(&mut buf);
    // the encoding must contain 0x80 0x01 0x01
    let has = buf.windows(3).any(|w| w == [0x80, 0x01, 0x01]);
    assert!(
        has,
        "specificationWithResult true must produce 0x80 0x01 0x01"
    );
    let decoded = ReadRequest::decode(&buf).unwrap();
    assert!(decoded.specification_with_result);
}

#[test]
fn read_request_spec_with_result_false_omits_0x80_01() {
    let req = ReadRequest::single_domain("LD", "VAR");
    let mut buf = BytesMut::new();
    req.encode(&mut buf);
    // FALSE is the default and is omitted, so 0x80 0x01 0x01 must be absent
    let has = buf.windows(3).any(|w| w == [0x80, 0x01, 0x01]);
    assert!(
        !has,
        "specificationWithResult false must not produce 0x80 0x01 0x01"
    );
    let decoded = ReadRequest::decode(&buf).unwrap();
    assert!(!decoded.specification_with_result);
}

// ReadResponse round trips

#[test]
fn read_response_list_of_access_result_success_failure_mixed() {
    let resp = ReadResponse {
        variable_access_spec: None,
        list_of_access_result: vec![
            AccessResult::Success(MmsData::Boolean(true)),
            AccessResult::Failure(DataAccessError::ObjectNonExistent),
            AccessResult::Success(MmsData::Integer(-100)),
            AccessResult::Failure(DataAccessError::ObjectAccessDenied),
            AccessResult::Success(MmsData::VisibleString("val".to_owned())),
        ],
    };
    let mut buf = BytesMut::new();
    resp.encode(&mut buf);
    let decoded = ReadResponse::decode(&buf).unwrap();
    assert_eq!(decoded, resp);
    assert_eq!(decoded.list_of_access_result.len(), 5);
}

#[test]
fn read_response_with_spec_echo_roundtrip() {
    let vas = VariableAccessSpecification::VariableListName(ObjectName::DomainSpecific {
        domain_id: "LD".to_owned(),
        item_id: "DS".to_owned(),
    });
    let resp = ReadResponse {
        variable_access_spec: Some(vas),
        list_of_access_result: vec![AccessResult::Success(MmsData::Unsigned(42))],
    };
    let mut buf = BytesMut::new();
    resp.encode(&mut buf);
    let decoded = ReadResponse::decode(&buf).unwrap();
    assert_eq!(decoded, resp);
    assert!(decoded.variable_access_spec.is_some());
}

#[test]
fn read_response_without_spec_echo_roundtrip() {
    let resp = ReadResponse {
        variable_access_spec: None,
        list_of_access_result: vec![AccessResult::Success(MmsData::Integer(0))],
    };
    let mut buf = BytesMut::new();
    resp.encode(&mut buf);
    let decoded = ReadResponse::decode(&buf).unwrap();
    assert_eq!(decoded, resp);
    assert!(decoded.variable_access_spec.is_none());
}

#[test]
fn read_response_empty_list_of_access_result_ok() {
    // an empty SEQUENCE OF is legal
    let resp = ReadResponse {
        variable_access_spec: None,
        list_of_access_result: vec![],
    };
    let mut buf = BytesMut::new();
    resp.encode(&mut buf);
    let decoded = ReadResponse::decode(&buf).unwrap();
    assert!(decoded.list_of_access_result.is_empty());
}

// ConfirmedRequestPdu and ConfirmedResponsePdu wrappers

#[test]
fn confirmed_read_request_invoke_id_preserved() {
    let req = ReadRequest::single_domain("LD1", "VAR");
    let mut buf = BytesMut::new();
    encode_confirmed_read_request(1234, &req, &mut buf);
    let (id, decoded) = decode_confirmed_read_request(&buf).unwrap();
    assert_eq!(id, 1234);
    assert_eq!(decoded, req);
}

#[test]
fn confirmed_read_response_invoke_id_preserved() {
    let resp = ReadResponse {
        variable_access_spec: None,
        list_of_access_result: vec![AccessResult::Success(MmsData::Boolean(false))],
    };
    let mut buf = BytesMut::new();
    encode_confirmed_read_response(9999, &resp, &mut buf);
    let (id, decoded) = decode_confirmed_read_response(&buf).unwrap();
    assert_eq!(id, 9999);
    assert_eq!(decoded, resp);
}

// robustness regressions

/// An AccessResult nesting more than 32 structures must be rejected.
#[test]
fn access_result_depth_bomb_err() {
    // build 33 nested structures
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

    // wrap the bomb in a ReadResponse
    let bomb = make_nested(33);
    // layers: 0xa1 <len> for the response, 0xa1 <len> for listOfAccessResult, then the bomb
    let list_content = bomb;
    let mut list_buf = vec![0xa1u8];
    if list_content.len() < 128 {
        list_buf.push(list_content.len() as u8);
    } else {
        list_buf.push(0x81);
        list_buf.push(list_content.len() as u8);
    }
    list_buf.extend_from_slice(&list_content);

    // wrap in 0xa4, the read service tag
    let mut read_buf = vec![0xa4u8];
    if list_buf.len() < 128 {
        read_buf.push(list_buf.len() as u8);
    } else {
        read_buf.push(0x81);
        read_buf.push(list_buf.len() as u8);
    }
    read_buf.extend_from_slice(&list_buf);

    let result = ReadResponse::decode(&read_buf);
    assert!(
        matches!(result, Err(MmsError::NestingLevelExceeded { .. })),
        "a depth bomb must return NestingLevelExceeded, got: {:?}",
        result
    );
}

/// An oversized length field returns an error, not a panic.
#[test]
fn oversized_length_no_panic() {
    // 0x85 0x82 0xff 0xff: an integer tag with a long-form length of 65535 and no data
    let poison = [0x85u8, 0x82, 0xff, 0xff, 0x00, 0x01];
    let result = MmsData::decode(&poison);
    assert!(
        result.is_err(),
        "an oversized length must return an error, not panic"
    );
}

#[test]
fn truncated_length_no_panic() {
    // 0x85 0x81: a long form whose following length byte is missing
    let poison = [0x85u8, 0x81];
    let result = MmsData::decode(&poison);
    assert!(matches!(result, Err(MmsError::TruncatedPdu)));
}

// boundary conditions

#[test]
fn read_request_domain_id_65_bytes_err() {
    // a 65-byte identifier exceeds MAX_IDENTIFIER_LEN of 64
    let long_name: String = "A".repeat(65);
    let mut inner = vec![0x80u8, 65u8]; // vmd-specific with 65 byte name
    inner.extend(long_name.as_bytes());
    let result = ObjectName::decode(&inner);
    assert!(matches!(
        result,
        Err(MmsError::IdentifierTooLong { actual: 65 })
    ));
}

#[test]
fn access_result_floatingpoint_invalid_size_err() {
    // 0x87 0x04 <4 bytes>, where 5 or 9 are required
    let bytes = [0x87u8, 0x04, 0x08, 0x40, 0x48, 0xf5];
    let result = MmsData::decode(&bytes);
    assert!(matches!(
        result,
        Err(MmsError::InvalidFloatSize { actual: 4 })
    ));
}

#[test]
fn access_result_utctime_wrong_size_err() {
    // 0x91 0x07 <7 bytes>, where 8 are required
    let bytes = [0x91u8, 0x07, 1, 2, 3, 4, 5, 6, 7];
    let result = MmsData::decode(&bytes);
    assert!(matches!(
        result,
        Err(MmsError::InvalidUtcTimeLength { actual: 7 })
    ));
}

#[test]
fn access_result_utctime_8_bytes_ok() {
    let bytes = [0x91u8, 0x08, 0x5e, 0x1a, 0x2b, 0x3c, 0x00, 0x00, 0x00, 0x04];
    let (data, consumed) = MmsData::decode(&bytes).unwrap();
    assert_eq!(consumed, 10);
    assert!(matches!(data, MmsData::UtcTime(_)));
}

#[test]
fn access_result_all_data_access_errors_decode_correctly() {
    // all eleven DataAccessError codes, 0 to 11, must decode
    for code in 0u8..=11u8 {
        let bytes = [0x80u8, 0x01, code];
        let (ar, _) = AccessResult::decode(&bytes).unwrap();
        assert!(
            matches!(ar, AccessResult::Failure(_)),
            "code {} must decode as a Failure",
            code
        );
    }
}

#[test]
fn access_result_unknown_data_access_error_code_err() {
    // code 12 yields UnknownDataAccessError
    let bytes = [0x80u8, 0x01, 12];
    let result = AccessResult::decode(&bytes);
    assert!(matches!(result, Err(MmsError::UnknownDataAccessError(12))));
}
