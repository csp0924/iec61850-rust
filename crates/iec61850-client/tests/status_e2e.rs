//! End-to-end tests of the MMS Status service over real TCP and the full ISO
//! stack.
//!
//! Covered: the crate's own server answering both values of
//! extendedDerivation; a scripted server that answers according to the flag it
//! receives, with localDetail and with a status value outside the named ones;
//! a scripted server rejecting the request, after which the association still
//! serves a second request; and a call before connecting.

mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use iec61850_client::{
    ClientError, IedConnection, ServerStatus, VmdLogicalStatus, VmdPhysicalStatus,
};
use iec61850_mms::mms::pdu::{
    decode_confirmed_status_request, encode_confirmed_status_response, StatusResponse,
};
use iec61850_mms::MmsClientBuilder;
use iec61850_model::{IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder};
use iec61850_server::{IedServer, IedServerConfig};
use support::Plan;

fn build_model() -> Arc<IedModel> {
    let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .build()
        .expect("ld");
    Arc::new(
        IedModelBuilder::new("IED1")
            .add_ld(ld)
            .expect("add_ld")
            .build()
            .expect("model"),
    )
}

async fn fresh_client(port: u16) -> IedConnection {
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

async fn status(conn: &IedConnection, extended: bool) -> Result<ServerStatus, ClientError> {
    tokio::time::timeout(Duration::from_secs(5), conn.get_server_status(extended))
        .await
        .expect("status timed out")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn own_server_reports_operational_status() {
    let handle = IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig::default())
        .build()
        .expect("build server")
        .start()
        .await
        .expect("server start");
    let conn = fresh_client(handle.bound_addr.port()).await;

    for extended in [false, true] {
        let st = status(&conn, extended).await.expect("status");
        assert_eq!(st.logical, VmdLogicalStatus::StateChangesAllowed);
        assert_eq!(st.physical, VmdPhysicalStatus::Operational);
        assert_eq!(st.local_detail, None);
    }

    // the association still serves the data model afterwards
    let lds = conn
        .get_server_directory(false)
        .await
        .expect("server directory");
    assert_eq!(lds, vec!["IED1LD0".to_string()]);

    conn.disconnect().await.expect("disconnect");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn extended_derivation_reaches_the_server_and_detail_reaches_the_caller() {
    // the scripted server answers according to the flag it decodes
    let port = support::start(Arc::new(|mms: &[u8], _seq: u32| {
        let (invoke_id, extended) = decode_confirmed_status_request(mms).ok()?;
        let resp = if extended {
            let mut r = StatusResponse::new(
                VmdLogicalStatus::LimitedServicesPermitted,
                VmdPhysicalStatus::NeedsCommissioning,
            );
            r.local_detail = Some(vec![true, false, false, true, true]);
            r
        } else {
            StatusResponse::new(
                VmdLogicalStatus::from_code(9),
                VmdPhysicalStatus::PartiallyOperational,
            )
        };
        let mut buf = BytesMut::new();
        encode_confirmed_status_response(invoke_id, &resp, &mut buf);
        Some(Plan::reply(buf.freeze()))
    }))
    .await;
    let conn = fresh_client(port).await;

    let plain = status(&conn, false).await.expect("status");
    assert_eq!(plain.logical, VmdLogicalStatus::Other(9));
    assert_eq!(plain.physical, VmdPhysicalStatus::PartiallyOperational);
    assert_eq!(plain.local_detail, None);

    let extended = status(&conn, true).await.expect("extended status");
    assert_eq!(extended.logical, VmdLogicalStatus::LimitedServicesPermitted);
    assert_eq!(extended.physical, VmdPhysicalStatus::NeedsCommissioning);
    assert_eq!(
        extended.local_detail,
        Some(vec![true, false, false, true, true])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejected_status_fails_and_keeps_the_association() {
    // the first request is rejected, the second answered
    let port = support::start(Arc::new(|mms: &[u8], seq: u32| {
        let (invoke_id, _) = decode_confirmed_status_request(mms).ok()?;
        if seq == 1 {
            return None;
        }
        let mut buf = BytesMut::new();
        encode_confirmed_status_response(
            invoke_id,
            &StatusResponse::new(
                VmdLogicalStatus::NoStateChangesAllowed,
                VmdPhysicalStatus::Inoperable,
            ),
            &mut buf,
        );
        Some(Plan::reply(buf.freeze()))
    }))
    .await;
    let conn = fresh_client(port).await;

    let err = status(&conn, false).await.expect_err("a rejected status");
    match &err {
        ClientError::Reject { reason, .. } => assert_eq!(
            reason.reject_type(),
            1,
            "a confirmed-request reject, got {reason:?}"
        ),
        other => panic!("expected the MMS reject error, got {other:?}"),
    }
    assert!(conn.is_connected());

    let st = status(&conn, false).await.expect("second status");
    assert_eq!(st.logical, VmdLogicalStatus::NoStateChangesAllowed);
    assert_eq!(st.physical, VmdPhysicalStatus::Inoperable);
}

#[tokio::test]
async fn status_before_connect_is_not_connected() {
    let conn = IedConnection::new();
    assert_eq!(
        conn.get_server_status(false).await,
        Err(ClientError::NotConnected)
    );
}
