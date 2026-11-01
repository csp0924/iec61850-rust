//! End-to-end tests of ConfirmedError decoding over real TCP and the full ISO
//! stack.
//!
//! A scripted server answers each Status request with a ConfirmedError written
//! byte by byte, so every legal BER shape of the PDU reaches the client: long
//! form lengths with one and two length octets at every level, a two-octet
//! subcode, every errorClass alternative and the optional ServiceError fields.
//! Each one must surface as a typed service error; a malformed one surfaces as
//! a parse error and leaves the association usable.

mod support;

use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use iec61850_client::{ClientError, ErrorClass, IedConnection, ServerStatus, ServiceSpecificInfo};
use iec61850_mms::mms::pdu::{
    decode_confirmed_status_request, encode_confirmed_status_response, StatusResponse,
    VmdLogicalStatus, VmdPhysicalStatus,
};
use iec61850_mms::MmsClientBuilder;
use support::{tlv, Plan};

/// The content octets of `id` as a minimal non-negative INTEGER.
fn invoke_id_content(id: u32) -> Vec<u8> {
    let bytes = id.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(3);
    let mut out = bytes[first..].to_vec();
    if out[0] & 0x80 != 0 {
        out.insert(0, 0x00);
    }
    out
}

/// A ConfirmedError under `invoke_id` carrying `service_error`, every length
/// in the short or long form the encoder picks for its size.
fn confirmed_error(invoke_id: u32, service_error: &[u8]) -> Bytes {
    let mut inner = BytesMut::new();
    tlv(0x80, &invoke_id_content(invoke_id), &mut inner);
    tlv(0xa2, service_error, &mut inner);
    let mut pdu = BytesMut::new();
    tlv(0xa2, &inner, &mut pdu);
    pdu.freeze()
}

/// A ConfirmedError under `invoke_id` with every length in a long form: the
/// outer SEQUENCE and the serviceError with two length octets, the invokeID,
/// the errorClass wrapper and the subcode with one.
fn confirmed_error_long_lengths(invoke_id: u32, class_tag: u8, code: u8) -> Bytes {
    let id = invoke_id_content(invoke_id);
    let mut service_error = vec![0xa0, 0x81, 0x04, class_tag, 0x81, 0x01, code];
    let mut inner = vec![0x80, 0x81, id.len() as u8];
    inner.extend_from_slice(&id);
    inner.extend_from_slice(&[0xa2, 0x82, 0x00, service_error.len() as u8]);
    inner.append(&mut service_error);
    let mut pdu = vec![0xa2, 0x82, 0x00, inner.len() as u8];
    pdu.extend_from_slice(&inner);
    Bytes::from(pdu)
}

async fn connect(port: u16) -> IedConnection {
    let mms_client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    let conn = IedConnection::with_mms_client(mms_client);
    conn.connect("127.0.0.1", port)
        .await
        .expect("client.connect");
    conn
}

async fn status(conn: &IedConnection) -> Result<ServerStatus, ClientError> {
    tokio::time::timeout(Duration::from_secs(5), conn.get_server_status(false))
        .await
        .expect("status timed out")
}

/// Starts a scripted server answering the n-th Status request with
/// `answers[n - 1]`, built for the request's invokeID, and every later one
/// with a Status response.
async fn scripted(answers: Vec<fn(u32) -> Bytes>) -> u16 {
    support::start(Arc::new(move |mms: &[u8], seq: u32| {
        let (invoke_id, _) = decode_confirmed_status_request(mms).ok()?;
        if let Some(answer) = answers.get(seq as usize - 1) {
            return Some(Plan::reply(answer(invoke_id)));
        }
        let mut buf = BytesMut::new();
        encode_confirmed_status_response(
            invoke_id,
            &StatusResponse::new(
                VmdLogicalStatus::StateChangesAllowed,
                VmdPhysicalStatus::Operational,
            ),
            &mut buf,
        );
        Some(Plan::reply(buf.freeze()))
    }))
    .await
}

/// Asserts that `r` is a service error carrying `want`, and returns its
/// serviceSpecificInformation.
fn expect_service_error(
    r: Result<ServerStatus, ClientError>,
    want: ErrorClass,
) -> Option<ServiceSpecificInfo> {
    match r {
        Err(ClientError::Service {
            error_class,
            service_specific,
            ..
        }) => {
            assert_eq!(error_class, want);
            service_specific
        }
        other => panic!("expected a service error carrying {want:?}, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn long_form_lengths_decode_to_the_error_class() {
    let port = scripted(vec![
        // the errorClass wrapper length with one length octet
        |id| confirmed_error(id, &[0xa0, 0x81, 0x03, 0x87, 0x01, 0x02]),
        // the errorClass wrapper length with two length octets
        |id| confirmed_error(id, &[0xa0, 0x82, 0x00, 0x03, 0x87, 0x01, 0x02]),
        // the subcode length with one length octet
        |id| confirmed_error(id, &[0xa0, 0x04, 0x87, 0x81, 0x01, 0x02]),
        // every length in a long form
        |id| confirmed_error_long_lengths(id, 0x87, 0x02),
    ])
    .await;
    let conn = connect(port).await;

    for _ in 0..4 {
        expect_service_error(status(&conn).await, ErrorClass::Access(2));
    }
    assert!(status(&conn).await.is_ok(), "the association stays usable");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_error_class_alternative_decodes() {
    let port = scripted(vec![
        |id| confirmed_error(id, &[0xa0, 0x03, 0x80, 0x01, 0x01]),
        |id| confirmed_error(id, &[0xa0, 0x03, 0x81, 0x01, 0x02]),
        |id| confirmed_error(id, &[0xa0, 0x03, 0x82, 0x01, 0x03]),
        |id| confirmed_error(id, &[0xa0, 0x03, 0x83, 0x01, 0x04]),
        |id| confirmed_error(id, &[0xa0, 0x03, 0x84, 0x01, 0x05]),
        |id| confirmed_error(id, &[0xa0, 0x03, 0x85, 0x01, 0x01]),
        |id| confirmed_error(id, &[0xa0, 0x03, 0x86, 0x01, 0x01]),
        |id| confirmed_error(id, &[0xa0, 0x03, 0x87, 0x01, 0x03]),
        |id| confirmed_error(id, &[0xa0, 0x03, 0x88, 0x01, 0x07]),
        |id| confirmed_error(id, &[0xa0, 0x03, 0x89, 0x01, 0x01]),
        |id| confirmed_error(id, &[0xa0, 0x03, 0x8a, 0x01, 0x02]),
        |id| confirmed_error(id, &[0xa0, 0x03, 0x8b, 0x01, 0x09]),
        // others, with a subcode that needs a leading zero octet
        |id| confirmed_error(id, &[0xa0, 0x04, 0x8c, 0x02, 0x00, 0xc8]),
    ])
    .await;
    let conn = connect(port).await;

    let want = [
        ErrorClass::VmdState(1),
        ErrorClass::ApplicationReference(2),
        ErrorClass::Definition(3),
        ErrorClass::Resource(4),
        ErrorClass::Service(5),
        ErrorClass::ServicePreempt(1),
        ErrorClass::TimeResolution(1),
        ErrorClass::Access(3),
        ErrorClass::Initiate(7),
        ErrorClass::Conclude(1),
        ErrorClass::Cancel(2),
        ErrorClass::File(9),
        ErrorClass::Others(200),
    ];
    for class in want {
        expect_service_error(status(&conn).await, class);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn optional_fields_keep_the_error_class() {
    let port = scripted(vec![
        // a 200-byte additionalDescription, its length with one length octet
        |id| {
            let mut se = vec![0xa0, 0x03, 0x87, 0x01, 0x03, 0x81, 0x01, 0x07];
            let mut desc = BytesMut::new();
            tlv(0x82, &[b'x'; 200], &mut desc);
            se.extend_from_slice(&desc);
            se.extend_from_slice(&[0xa3, 0x03, 0x86, 0x01, 0x02]);
            confirmed_error(id, &se)
        },
        // an additionalCode wider than 32 bits
        |id| {
            confirmed_error(
                id,
                &[
                    0xa0, 0x03, 0x87, 0x01, 0x03, 0x81, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
                ],
            )
        },
    ])
    .await;
    let conn = connect(port).await;

    assert_eq!(
        expect_service_error(status(&conn).await, ErrorClass::Access(3)),
        Some(ServiceSpecificInfo::DeleteNamedVariableList(2))
    );
    assert_eq!(
        expect_service_error(status(&conn).await, ErrorClass::Access(3)),
        None
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_error_class_is_a_parse_error_and_keeps_the_association() {
    let port = scripted(vec![
        // a negative subcode
        |id| confirmed_error(id, &[0xa0, 0x03, 0x87, 0x01, 0xff]),
        // a wrapper carrying a second alternative
        |id| confirmed_error(id, &[0xa0, 0x06, 0x87, 0x01, 0x02, 0x87, 0x01, 0x02]),
    ])
    .await;
    let conn = connect(port).await;

    for _ in 0..2 {
        let r = status(&conn).await;
        assert!(
            matches!(&r, Err(ClientError::Mms(m)) if m.contains("ConfirmedError decode failed")),
            "expected a ConfirmedError parse error, got {r:?}"
        );
    }
    assert!(conn.is_connected());
    assert!(status(&conn).await.is_ok(), "the association stays usable");
}
