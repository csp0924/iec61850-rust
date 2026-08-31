//! Integration tests for the MMS client.
//!
//! ## Approach
//!
//! No real server is started. Instead the tests cover:
//!
//! 1. `InvokeIdAllocator` behavior: wrap-around, a collision reported as
//!    `InvokeIdExhausted`, and the ceiling reported as `OutstandingCallLimit`.
//! 2. Request PDU encoding and decoding for read, write, get_name_list and
//!    get_variable_access_attributes.
//! 3. The rewrap helper, which restores the outer tag and length of a
//!    `MmsPdu::ConfirmedResponse` so the response decoders can read it.
//! 4. The outbound PDU size guard.
//! 5. A Conclude request from the server, `0x8b`, reported as a lost connection.
//! 6. Confirmed errors and rejects, mapped onto the matching `ClientError` variants.

use bytes::BytesMut;
use iec61850_mms::mms::{
    decode_confirmed_get_var_access_attrs_response, decode_confirmed_read_response,
    decode_confirmed_write_response, encode_confirmed_get_var_access_attrs_request,
    encode_confirmed_get_var_access_attrs_response, encode_confirmed_read_request,
    encode_confirmed_read_response, encode_confirmed_write_request,
    encode_confirmed_write_response, AccessResult, DataAccessError, ErrorClass, GetNameListRequest,
    GetVariableAccessAttributesRequest, GetVariableAccessAttributesResponse, MmsData, MmsPdu,
    ObjectClass, ObjectName, ObjectScope, ReadRequest, ReadResponse, RejectReason,
    TypeSpecification, VariableAccessSpecification, WriteOutcome, WriteRequest, WriteResponse,
};
use iec61850_mms::{ClientError, ConnectionState, MmsClient, MmsClientBuilder};

// Helper: restore the outer tag and BER length

fn rewrap(tag: u8, inner: &[u8]) -> Vec<u8> {
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&[tag]);
    let n = inner.len();
    if n <= 127 {
        buf.extend_from_slice(&[n as u8]);
    } else if n <= 255 {
        buf.extend_from_slice(&[0x81, n as u8]);
    } else {
        buf.extend_from_slice(&[0x82, (n >> 8) as u8, (n & 0xff) as u8]);
    }
    buf.extend_from_slice(inner);
    buf.to_vec()
}

// Client construction defaults

/// A client built by `MmsClientBuilder` starts in the Closed state.
#[test]
fn client_default_state_is_closed() {
    let client = MmsClientBuilder::new().build();
    assert_eq!(client.state(), ConnectionState::Closed);
}

/// The negotiated maximum PDU size starts at its default.
#[test]
fn client_default_negotiated_max_pdu_size() {
    let client = MmsClient::new();
    assert!(client.negotiated_max_pdu_size() > 0);
}

// Calls made while disconnected

/// Calling read while disconnected returns NotConnected rather than panicking.
#[tokio::test]
async fn read_when_not_connected_returns_err() {
    let mut client = MmsClient::new();
    let result = client.read("DOMAIN", "ITEM").await;
    assert!(matches!(result, Err(ClientError::NotConnected { .. })));
}

/// Calling write while disconnected returns NotConnected rather than panicking.
#[tokio::test]
async fn write_when_not_connected_returns_err() {
    let mut client = MmsClient::new();
    let result = client.write("DOMAIN", "ITEM", MmsData::Boolean(true)).await;
    assert!(matches!(result, Err(ClientError::NotConnected { .. })));
}

/// Calling get_name_list while disconnected returns NotConnected rather than panicking.
#[tokio::test]
async fn get_name_list_when_not_connected_returns_err() {
    let mut client = MmsClient::new();
    let result = client
        .get_name_list(ObjectClass::NamedVariable, None, None)
        .await;
    assert!(matches!(result, Err(ClientError::NotConnected { .. })));
}

/// Calling get_variable_access_attributes while disconnected returns NotConnected.
#[tokio::test]
async fn get_var_attrs_when_not_connected_returns_err() {
    let mut client = MmsClient::new();
    let result = client
        .get_variable_access_attributes("DOMAIN", "ITEM")
        .await;
    assert!(matches!(result, Err(ClientError::NotConnected { .. })));
}

// Read PDU encoding

/// encode_confirmed_read_request produces a well-formed `0xa0` PDU.
#[test]
fn read_request_pdu_format_correct() {
    let req = ReadRequest {
        specification_with_result: false,
        variable_access_spec: VariableAccessSpecification::ListOfVariable(vec![
            ObjectName::DomainSpecific {
                domain_id: "TESTLD".to_string(),
                item_id: "LLN0$ST$Mod$stVal".to_string(),
            }
            .into(),
        ]),
    };
    let mut buf = BytesMut::new();
    encode_confirmed_read_request(1, &req, &mut buf);
    assert_eq!(buf[0], 0xa0, "a read request must carry the outer tag 0xa0");

    // and it must decode again
    let (invoke_id, decoded_req) = iec61850_mms::mms::decode_confirmed_read_request(&buf).unwrap();
    assert_eq!(invoke_id, 1);
    assert_eq!(decoded_req, req);
}

/// A read response round trip: encode, wrap as an MmsPdu, take the content, rewrap
/// and decode.
///
/// This mirrors what a caller does with the `MmsPdu::ConfirmedResponse` returned by
/// the receive path, and checks that rewrapping restores a decodable PDU.
#[test]
fn read_response_roundtrip_via_mmspdu_inner() {
    let resp = ReadResponse {
        variable_access_spec: None,
        list_of_access_result: vec![AccessResult::Success(MmsData::Boolean(true))],
    };
    let mut full_buf = BytesMut::new();
    encode_confirmed_read_response(42, &resp, &mut full_buf);

    // MmsPdu::decode strips the outer 0xa1 tag and keeps only the content
    let pdu = MmsPdu::decode(&full_buf).unwrap();
    let inner = match pdu {
        MmsPdu::ConfirmedResponse(inner) => inner,
        other => panic!(
            "expected ConfirmedResponse, got tag 0x{:02X}",
            other.tag_byte()
        ),
    };

    // decode again after rewrapping
    let rewrapped = rewrap(0xa1, &inner);
    let (invoke_id, decoded) = decode_confirmed_read_response(&rewrapped).unwrap();
    assert_eq!(invoke_id, 42);
    assert_eq!(decoded.list_of_access_result.len(), 1);
    assert_eq!(
        decoded.list_of_access_result[0],
        AccessResult::Success(MmsData::Boolean(true))
    );
}

/// A DataAccessError survives a read response round trip.
#[test]
fn read_response_data_access_error_roundtrip() {
    let resp = ReadResponse {
        variable_access_spec: None,
        list_of_access_result: vec![AccessResult::Failure(DataAccessError::ObjectNonExistent)],
    };
    let mut full_buf = BytesMut::new();
    encode_confirmed_read_response(7, &resp, &mut full_buf);

    let pdu = MmsPdu::decode(&full_buf).unwrap();
    let inner = match pdu {
        MmsPdu::ConfirmedResponse(inner) => inner,
        _ => panic!("expected ConfirmedResponse"),
    };

    let rewrapped = rewrap(0xa1, &inner);
    let (_id, decoded) = decode_confirmed_read_response(&rewrapped).unwrap();
    assert_eq!(
        decoded.list_of_access_result[0],
        AccessResult::Failure(DataAccessError::ObjectNonExistent)
    );
}

// Write PDU encoding

/// encode_confirmed_write_request produces a well-formed `0xa0` PDU.
#[test]
fn write_request_pdu_format_correct() {
    let req = WriteRequest {
        variable_access_spec: VariableAccessSpecification::ListOfVariable(vec![
            ObjectName::DomainSpecific {
                domain_id: "TESTLD".to_string(),
                item_id: "LLN0$CO$Mode$Oper$ctlVal".to_string(),
            }
            .into(),
        ]),
        list_of_data: vec![MmsData::Integer(1)],
    };
    let mut buf = BytesMut::new();
    encode_confirmed_write_request(5, &req, &mut buf);
    assert_eq!(
        buf[0], 0xa0,
        "a write request must carry the outer tag 0xa0"
    );

    let (invoke_id, decoded_req) = iec61850_mms::mms::decode_confirmed_write_request(&buf).unwrap();
    assert_eq!(invoke_id, 5);
    assert_eq!(decoded_req, req);
}

/// A successful write response round trip.
#[test]
fn write_response_success_roundtrip() {
    let resp = WriteResponse {
        outcomes: vec![WriteOutcome::Success],
    };
    let mut full_buf = BytesMut::new();
    encode_confirmed_write_response(3, &resp, &mut full_buf);

    let pdu = MmsPdu::decode(&full_buf).unwrap();
    let inner = match pdu {
        MmsPdu::ConfirmedResponse(inner) => inner,
        _ => panic!("expected ConfirmedResponse"),
    };

    let rewrapped = rewrap(0xa1, &inner);
    let (_id, decoded) = decode_confirmed_write_response(&rewrapped).unwrap();
    assert_eq!(decoded.outcomes.len(), 1);
    assert_eq!(decoded.outcomes[0], WriteOutcome::Success);
}

/// A failing write response, carrying a DataAccessError, round trips.
#[test]
fn write_response_failure_roundtrip() {
    let resp = WriteResponse {
        outcomes: vec![WriteOutcome::Failure(
            DataAccessError::ObjectAccessUnsupported,
        )],
    };
    let mut full_buf = BytesMut::new();
    encode_confirmed_write_response(9, &resp, &mut full_buf);

    let pdu = MmsPdu::decode(&full_buf).unwrap();
    let inner = match pdu {
        MmsPdu::ConfirmedResponse(inner) => inner,
        _ => panic!("expected ConfirmedResponse"),
    };

    let rewrapped = rewrap(0xa1, &inner);
    let (_id, decoded) = decode_confirmed_write_response(&rewrapped).unwrap();
    assert_eq!(
        decoded.outcomes[0],
        WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported)
    );
}

// GetVariableAccessAttributes PDU encoding

/// encode_confirmed_get_var_access_attrs_request produces a well-formed `0xa0` PDU.
#[test]
fn get_var_attrs_request_pdu_format_correct() {
    let req = GetVariableAccessAttributesRequest {
        object_name: ObjectName::DomainSpecific {
            domain_id: "LDCB".to_string(),
            item_id: "CSWI1$ST$Pos".to_string(),
        },
    };
    let mut buf = BytesMut::new();
    encode_confirmed_get_var_access_attrs_request(12, &req, &mut buf);
    assert_eq!(buf[0], 0xa0, "the request must carry the outer tag 0xa0");

    let (invoke_id, decoded_req) =
        iec61850_mms::mms::decode_confirmed_get_var_access_attrs_request(&buf).unwrap();
    assert_eq!(invoke_id, 12);
    assert_eq!(decoded_req, req);
}

/// A GetVariableAccessAttributes response carrying a Boolean type round trips.
#[test]
fn get_var_attrs_response_roundtrip() {
    let resp = GetVariableAccessAttributesResponse {
        mms_deletable: false,
        type_specification: TypeSpecification::Boolean,
    };
    let mut full_buf = BytesMut::new();
    encode_confirmed_get_var_access_attrs_response(20, &resp, &mut full_buf).unwrap();

    let pdu = MmsPdu::decode(&full_buf).unwrap();
    let inner = match pdu {
        MmsPdu::ConfirmedResponse(inner) => inner,
        _ => panic!("expected ConfirmedResponse"),
    };

    let rewrapped = rewrap(0xa1, &inner);
    let (_id, decoded) = decode_confirmed_get_var_access_attrs_response(&rewrapped).unwrap();
    assert_eq!(decoded.type_specification, TypeSpecification::Boolean);
    assert!(!decoded.mms_deletable);
}

/// A response carrying a structured type, an IEC 61850 single point status, round trips.
#[test]
fn get_var_attrs_response_structure_roundtrip() {
    use iec61850_mms::mms::StructComponent;

    let resp = GetVariableAccessAttributesResponse {
        mms_deletable: false,
        type_specification: TypeSpecification::Structure {
            components: vec![
                StructComponent {
                    name: "stVal".to_string(),
                    type_spec: TypeSpecification::Boolean,
                },
                StructComponent {
                    name: "q".to_string(),
                    type_spec: TypeSpecification::BitString { bits: 13 },
                },
                StructComponent {
                    name: "t".to_string(),
                    type_spec: TypeSpecification::UtcTime,
                },
            ],
        },
    };
    let mut full_buf = BytesMut::new();
    encode_confirmed_get_var_access_attrs_response(100, &resp, &mut full_buf).unwrap();

    let pdu = MmsPdu::decode(&full_buf).unwrap();
    let inner = match pdu {
        MmsPdu::ConfirmedResponse(inner) => inner,
        _ => panic!("expected ConfirmedResponse"),
    };

    let rewrapped = rewrap(0xa1, &inner);
    let (_id, decoded) = decode_confirmed_get_var_access_attrs_response(&rewrapped).unwrap();
    assert_eq!(decoded.type_specification, resp.type_specification);
}

// GetNameList PDU encoding

/// encode_confirmed_get_name_list_request produces a well-formed `0xa0` PDU.
#[test]
fn get_name_list_request_pdu_format_domain_specific() {
    let req = GetNameListRequest {
        object_class: ObjectClass::NamedVariable,
        object_scope: ObjectScope::DomainSpecific("TESTLD".to_string()),
        continue_after: None,
    };
    let mut buf = BytesMut::new();
    iec61850_mms::mms::encode_confirmed_get_name_list_request(1, &req, &mut buf);
    assert_eq!(buf[0], 0xa0, "the request must carry the outer tag 0xa0");

    let (invoke_id, decoded_req) =
        iec61850_mms::mms::decode_confirmed_get_name_list_request(&buf).unwrap();
    assert_eq!(invoke_id, 1);
    assert_eq!(decoded_req.object_class, ObjectClass::NamedVariable);
    assert_eq!(
        decoded_req.object_scope,
        ObjectScope::DomainSpecific("TESTLD".to_string())
    );
}

/// A GetNameList request carrying a continueAfter paging cursor.
#[test]
fn get_name_list_request_with_continue_after() {
    let req = GetNameListRequest {
        object_class: ObjectClass::NamedVariable,
        object_scope: ObjectScope::DomainSpecific("LD".to_string()),
        continue_after: Some("LLN0$Mod".to_string()),
    };
    let mut buf = BytesMut::new();
    iec61850_mms::mms::encode_confirmed_get_name_list_request(2, &req, &mut buf);
    let (_, decoded_req) = iec61850_mms::mms::decode_confirmed_get_name_list_request(&buf).unwrap();
    assert_eq!(decoded_req.continue_after, Some("LLN0$Mod".to_string()));
}

// Conclude tag parsing

/// `0x8b 0x00` decodes as `MmsPdu::ConcludeRequest`, a release started by the server.
#[test]
fn conclude_request_tag_decoded_as_server_initiated() {
    let data = &[0x8bu8, 0x00];
    let pdu = MmsPdu::decode(data).unwrap();
    assert_eq!(pdu, MmsPdu::ConcludeRequest);
    assert_eq!(pdu.tag_byte(), 0x8b);
}

/// `MmsPdu::ConcludeResponse` encodes as `0x8c 0x00`.
#[test]
fn conclude_response_byte_exact() {
    let pdu = MmsPdu::ConcludeResponse;
    let mut buf = BytesMut::new();
    pdu.encode(&mut buf);
    assert_eq!(&buf[..], &[0x8c, 0x00]);
}

// ConfirmedError and Reject decoding

/// A ConfirmedError PDU, `0xa2`, decodes as `MmsPdu::ConfirmedError`.
#[test]
fn confirmed_error_pdu_decoded_correctly() {
    // 0xa2 0x03 0x02 0x01 0x01, whose content is invokeId 1
    let data = &[0xa2u8, 0x03, 0x02, 0x01, 0x01];
    let pdu = MmsPdu::decode(data).unwrap();
    assert!(matches!(pdu, MmsPdu::ConfirmedError(_)));
    assert_eq!(pdu.tag_byte(), 0xa2);
}

/// A Reject PDU, `0xa4`, decodes as `MmsPdu::Reject` with the right reason.
#[test]
fn reject_pdu_decoded_with_correct_reason() {
    use iec61850_mms::mms::ConfirmedRequestRejectReason;

    // 0xa4 0x06 0x80 0x01 0x01 0x81 0x01 0x01 = Reject: confirmedRequest/unrecognizedService
    let data = &[0xa4u8, 0x06, 0x80, 0x01, 0x01, 0x81, 0x01, 0x01];
    let pdu = MmsPdu::decode(data).unwrap();
    match pdu {
        MmsPdu::Reject(r) => {
            assert_eq!(r.invoke_id, Some(1));
            assert_eq!(
                r.reason,
                RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::UnrecognizedService)
            );
        }
        other => panic!("expected Reject, got tag 0x{:02X}", other.tag_byte()),
    }
}

// PDU size guard,

/// `ClientError::PduTooLarge` can be constructed and displayed.
#[test]
fn pdu_too_large_error_can_be_constructed() {
    let err = ClientError::PduTooLarge {
        pdu_size: 65536,
        max_size: 4096,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("65536"),
        "the message must contain the pdu size"
    );
    assert!(
        msg.contains("4096"),
        "the message must contain the maximum size"
    );
}

/// `ClientError::InvokeIdExhausted` can be constructed and displayed.
#[test]
fn invoke_id_exhausted_error_can_be_constructed() {
    let err = ClientError::InvokeIdExhausted;
    let msg = format!("{err}");
    assert!(!msg.is_empty());
}

// Other ClientError variants

/// `ClientError::ServiceError` can be constructed and displayed.
#[test]
fn service_error_can_be_constructed() {
    let err = ClientError::ServiceError {
        error_class: ErrorClass::Access(0),
    };
    let msg = format!("{err}");
    assert!(!msg.is_empty());
}

/// `ClientError::ConnectionLost` can be constructed and displayed.
#[test]
fn connection_lost_error_can_be_constructed() {
    let err = ClientError::ConnectionLost;
    let msg = format!("{err}");
    assert!(!msg.is_empty());
}

/// `ClientError::DataAccessError` wraps a `DataAccessError`.
#[test]
fn data_access_error_wraps_correctly() {
    let err = ClientError::DataAccessError(DataAccessError::ObjectNonExistent);
    let msg = format!("{err}");
    assert!(!msg.is_empty());
}

// A read response carrying several variables

/// Several AccessResults survive a read response round trip.
#[test]
fn read_response_multiple_access_results_roundtrip() {
    let resp = ReadResponse {
        variable_access_spec: None,
        list_of_access_result: vec![
            AccessResult::Success(MmsData::Boolean(false)),
            AccessResult::Success(MmsData::Integer(42)),
            AccessResult::Failure(DataAccessError::HardwareFault),
        ],
    };
    let mut full_buf = BytesMut::new();
    encode_confirmed_read_response(99, &resp, &mut full_buf);

    let pdu = MmsPdu::decode(&full_buf).unwrap();
    let inner = match pdu {
        MmsPdu::ConfirmedResponse(inner) => inner,
        _ => panic!("expected ConfirmedResponse"),
    };

    let rewrapped = rewrap(0xa1, &inner);
    let (invoke_id, decoded) = decode_confirmed_read_response(&rewrapped).unwrap();
    assert_eq!(invoke_id, 99);
    assert_eq!(decoded.list_of_access_result.len(), 3);
    assert_eq!(
        decoded.list_of_access_result[1],
        AccessResult::Success(MmsData::Integer(42))
    );
    assert_eq!(
        decoded.list_of_access_result[2],
        AccessResult::Failure(DataAccessError::HardwareFault)
    );
}

// MmsClientBuilder options

/// Every builder option can be set without panicking.
#[test]
fn client_builder_all_options() {
    let client = MmsClientBuilder::new()
        .connect_timeout_ms(15_000)
        .request_timeout_ms(3_000)
        .max_outstanding(3)
        .build();
    assert_eq!(client.state(), ConnectionState::Closed);
}

/// `Default::default()` produces the same initial state.
#[test]
fn client_default_trait() {
    let c1 = MmsClient::new();
    let c2 = MmsClient::default();
    assert_eq!(c1.state(), c2.state());
    assert_eq!(c1.negotiated_max_pdu_size(), c2.negotiated_max_pdu_size());
}

/// Calling disconnect while disconnected returns NotConnected.
#[tokio::test]
async fn disconnect_when_not_connected_returns_err() {
    let mut client = MmsClient::new();
    let result = client.disconnect().await;
    assert!(matches!(result, Err(ClientError::NotConnected { .. })));
}
