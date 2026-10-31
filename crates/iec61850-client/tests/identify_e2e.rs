//! End-to-end tests of the MMS Identify service over real TCP and the full ISO
//! stack.
//!
//! Covered: the crate's own server answering with its built-in identity and
//! with the strings set in its configuration; a scripted server listing
//! abstract syntaxes; a scripted server rejecting the request, after which the
//! association still serves a second request; and a call before connecting.

mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use iec61850_client::{ClientError, IedConnection, ServerIdentity};
use iec61850_mms::mms::pdu::{
    decode_confirmed_identify_request, encode_confirmed_identify_response, IdentifyResponse,
};
use iec61850_mms::MmsClientBuilder;
use iec61850_model::{IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder};
use iec61850_server::{IdentificationStrings, IedServer, IedServerConfig};
use support::Plan;

/// `1.0.9506.2.1`, the MMS abstract syntax.
const MMS_ABSTRACT_SYNTAX: [u32; 5] = [1, 0, 9506, 2, 1];

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

fn build_server(cfg: IedServerConfig) -> IedServer {
    IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(cfg)
        .build()
        .expect("build server")
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

async fn identify(conn: &IedConnection) -> Result<ServerIdentity, ClientError> {
    tokio::time::timeout(Duration::from_secs(5), conn.get_server_identity())
        .await
        .expect("identify timed out")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn own_server_reports_its_built_in_identity() {
    let handle = build_server(IedServerConfig::default())
        .start()
        .await
        .expect("server start");
    let conn = fresh_client(handle.bound_addr.port()).await;

    let id = identify(&conn).await.expect("identify");
    assert_eq!(id.vendor, IdentificationStrings::DEFAULT_VENDOR);
    assert_eq!(id.model, IdentificationStrings::DEFAULT_MODEL);
    assert_eq!(id.revision, IdentificationStrings::DEFAULT_REVISION);
    assert!(id.abstract_syntaxes.is_empty());

    conn.disconnect().await.expect("disconnect");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn own_server_reports_configured_identity() {
    let cfg = IedServerConfig {
        vendor_name: Some("Example Vendor".into()),
        model_name: Some("Bay Controller 7".into()),
        revision: Some("4.2.0-rc1".into()),
        ..Default::default()
    };
    let handle = build_server(cfg).start().await.expect("server start");
    let conn = fresh_client(handle.bound_addr.port()).await;

    let id = identify(&conn).await.expect("identify");
    assert_eq!(id.vendor, "Example Vendor");
    assert_eq!(id.model, "Bay Controller 7");
    assert_eq!(id.revision, "4.2.0-rc1");

    // the call is repeatable on the same association
    let again = identify(&conn).await.expect("second identify");
    assert_eq!(again, id);

    conn.disconnect().await.expect("disconnect");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn listed_abstract_syntaxes_reach_the_caller() {
    let port = support::start(Arc::new(|mms: &[u8], _seq: u32| {
        let invoke_id = decode_confirmed_identify_request(mms).ok()?;
        let mut resp = IdentifyResponse::new("scripted", "peer", "9");
        resp.list_of_abstract_syntaxes = vec![MMS_ABSTRACT_SYNTAX.to_vec()];
        let mut buf = BytesMut::new();
        encode_confirmed_identify_response(invoke_id, &resp, &mut buf);
        Some(Plan::reply(buf.freeze()))
    }))
    .await;
    let conn = fresh_client(port).await;

    let id = identify(&conn).await.expect("identify");
    assert_eq!(id.vendor, "scripted");
    assert_eq!(id.model, "peer");
    assert_eq!(id.revision, "9");
    assert_eq!(id.abstract_syntaxes, vec![MMS_ABSTRACT_SYNTAX.to_vec()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejected_identify_fails_and_keeps_the_association() {
    // the first request is rejected, the second answered
    let port = support::start(Arc::new(|mms: &[u8], seq: u32| {
        let invoke_id = decode_confirmed_identify_request(mms).ok()?;
        if seq == 1 {
            return None;
        }
        let mut buf = BytesMut::new();
        encode_confirmed_identify_response(
            invoke_id,
            &IdentifyResponse::new("v", "m", "r"),
            &mut buf,
        );
        Some(Plan::reply(buf.freeze()))
    }))
    .await;
    let conn = fresh_client(port).await;

    let err = identify(&conn).await.expect_err("a rejected identify");
    match &err {
        ClientError::Mms(msg) => assert!(msg.contains("reject"), "got {msg}"),
        other => panic!("expected the MMS reject error, got {other:?}"),
    }
    assert!(conn.is_connected());

    let id = identify(&conn).await.expect("second identify");
    assert_eq!((id.vendor.as_str(), id.model.as_str()), ("v", "m"));
}

#[tokio::test]
async fn identify_before_connect_is_not_connected() {
    let conn = IedConnection::new();
    assert_eq!(
        conn.get_server_identity().await,
        Err(ClientError::NotConnected)
    );
}
