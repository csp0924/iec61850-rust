//! End-to-end tests of GetGoCBValues against a scripted server.
//!
//! A GoCB that the configuration leaves disabled may reveal an empty octet
//! string as `DstAddress.Addr` (IEC 61850-8-1 §25.3.2); the client reads it as
//! the all-zero address, which means no destination. An `Addr` of any other
//! length than zero or six bytes is still refused.

mod support;

use bytes::BytesMut;
use iec61850_client::{ClientError, IedConnection};
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_mms::{
    decode_confirmed_read_request, encode_confirmed_read_response, AccessResult, MmsData,
    ReadResponse,
};
use std::sync::Arc;
use support::Plan;

/// A GoCB structure with the given `DstAddress.Addr`.
fn gocb(addr: Vec<u8>) -> MmsData {
    MmsData::Structure(vec![
        MmsData::Boolean(false),
        MmsData::VisibleString("goid01".into()),
        MmsData::VisibleString("IED1LD0/LLN0$ds1".into()),
        MmsData::Unsigned(1),
        MmsData::Boolean(false),
        MmsData::Structure(vec![
            MmsData::OctetString(addr),
            MmsData::Unsigned(0),
            MmsData::Unsigned(0),
            MmsData::Unsigned(0),
        ]),
    ])
}

/// Starts a scripted server that answers every Read with `value`.
async fn serving(value: MmsData) -> IedConnection {
    let port = support::start(Arc::new(move |mms: &[u8], _seq: u32| {
        let (invoke_id, _) = decode_confirmed_read_request(mms).ok()?;
        let mut buf = BytesMut::new();
        encode_confirmed_read_response(
            invoke_id,
            &ReadResponse {
                variable_access_spec: None,
                list_of_access_result: vec![AccessResult::Success(value.clone())],
            },
            &mut buf,
        );
        Some(Plan::reply(buf.freeze()))
    }))
    .await;
    let conn = IedConnection::with_mms_client(
        MmsClientBuilder::new()
            .connect_timeout_ms(3_000)
            .request_timeout_ms(3_000)
            .build(),
    );
    conn.connect("127.0.0.1", port).await.expect("connect");
    conn
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_gocb_has_no_destination() {
    let conn = serving(gocb(Vec::new())).await;
    let v = conn
        .get_gocb_values("IED1LD0/LLN0.gcb01")
        .await
        .expect("GoCB values");
    assert!(!v.go_ena);
    assert_eq!(v.dst_address.addr, [0; 6]);
    assert_eq!(v.go_id, "goid01");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn destination_of_another_length_is_refused() {
    for len in [5, 7] {
        let conn = serving(gocb(vec![0x01; len])).await;
        let r = conn.get_gocb_values("IED1LD0/LLN0.gcb01").await;
        assert!(
            matches!(r, Err(ClientError::InvalidArgument(_))),
            "{len} bytes: {r:?}"
        );
    }
}
