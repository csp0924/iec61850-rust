//! A connection reused for a new association, over real TCP and the full ISO
//! stack.
//!
//! Covered: connecting to a plaintext server while a TLS or plaintext
//! association to another server is still established, after which every
//! service reaches the new server; and connecting to another server after the
//! first one ended the association, after which the directory describes the
//! new server rather than the cached model of the old one.

mod support;

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use iec61850_client::{ClientError, IedConnection};
use iec61850_mms::mms::pdu::get_name_list::{
    decode_confirmed_get_name_list_request, encode_confirmed_get_name_list_response,
    GetNameListResponse, ObjectScope,
};
use iec61850_model::{IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder};
use iec61850_server::{IedServer, IedServerConfig};

/// A model of one logical device `<ied_name>LD0` holding only LLN0.
fn build_model(ied_name: &str) -> Arc<IedModel> {
    let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .build()
        .expect("ld");
    Arc::new(
        IedModelBuilder::new(ied_name)
            .add_ld(ld)
            .expect("add_ld")
            .build()
            .expect("model"),
    )
}

/// The configuration of a server identifying itself with `vendor`.
fn config(vendor: &str) -> IedServerConfig {
    let mut cfg = IedServerConfig::default();
    cfg.vendor_name = Some(vendor.into());
    cfg
}

/// A plaintext server of `build_model(ied_name)` identifying itself as `vendor`.
fn plain_server(ied_name: &str, vendor: &str) -> IedServer {
    IedServer::builder()
        .model(build_model(ied_name))
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(config(vendor))
        .build()
        .expect("build the server")
}

/// A scripted server whose directory is the one logical device `ld` holding
/// LLN0, and which closes the connection on any request other than
/// GetNameList.
fn directory_then_close(ld: &'static str) -> Arc<support::Script> {
    Arc::new(move |mms: &[u8], _seq: u32| {
        let Ok((invoke_id, req)) = decode_confirmed_get_name_list_request(mms) else {
            return Some(support::Plan {
                close: true,
                ..support::Plan::default()
            });
        };
        let identifiers = match req.object_scope {
            ObjectScope::VmdSpecific => vec![ld.to_string()],
            _ => vec!["LLN0".to_string()],
        };
        let mut buf = BytesMut::new();
        encode_confirmed_get_name_list_response(
            invoke_id,
            &GetNameListResponse {
                identifiers,
                more_follows: false,
            },
            &mut buf,
        );
        Some(support::Plan::reply(buf.freeze()))
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_association_reads_the_directory_of_its_own_server() {
    let a = support::start(directory_then_close("ALD0")).await;
    let b = support::start(directory_then_close("BLD0")).await;
    let conn = IedConnection::new();

    conn.connect("127.0.0.1", a).await.expect("connect A");
    let lds = conn
        .get_server_directory(false)
        .await
        .expect("directory of A");
    assert_eq!(lds, vec!["ALD0".to_string()]);

    // server A ends the association
    let ended = conn.get_server_identity().await;
    assert!(
        matches!(ended, Err(ClientError::ConnectionLost)),
        "got {ended:?}"
    );
    assert!(!conn.is_connected());

    conn.connect("127.0.0.1", b).await.expect("connect B");
    assert!(
        conn.cached_device_model().await.is_none(),
        "the model of A does not describe B"
    );
    let lds = conn
        .get_server_directory(false)
        .await
        .expect("directory of B");
    assert_eq!(lds, vec!["BLD0".to_string()]);
}

#[cfg(feature = "tls")]
mod over_tls {
    use super::*;
    use iec61850_tls::{TlsAcceptor, TlsConfigBuilder, TlsConnector};
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    /// A CA certificate, and a server certificate for `localhost` it signed,
    /// PEM encoded.
    fn certificates() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).expect("ca certificate");
        let key = KeyPair::generate().expect("server key");
        let cert = CertificateParams::new(vec!["localhost".to_string()])
            .expect("server params")
            .signed_by(&key, &ca, &ca_key)
            .expect("server certificate");
        (
            ca.pem().into_bytes(),
            cert.pem().into_bytes(),
            key.serialize_pem().into_bytes(),
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn connecting_over_an_established_tls_association_reaches_the_new_server() {
        let (ca, cert, key) = certificates();
        let tls_server = IedServer::builder()
            .model(build_model("A"))
            .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .config(config("vendor A"))
            .with_tls(TlsAcceptor::new(
                TlsConfigBuilder::new()
                    .with_cert_pem(&cert, &key)
                    .expect("server certificate")
                    .build_server()
                    .expect("server config"),
            ))
            .build()
            .expect("build the TLS server");
        let a = tls_server.start().await.expect("start A");
        let b = plain_server("B", "vendor B")
            .start()
            .await
            .expect("start B");
        let connector = TlsConnector::new(
            TlsConfigBuilder::new()
                .add_ca_pem(&ca)
                .expect("ca")
                .build_client()
                .expect("client config"),
        );

        let conn = IedConnection::new();
        conn.connect_tls(
            a.bound_addr,
            &connector,
            "localhost".try_into().expect("server name"),
        )
        .await
        .expect("connect A over TLS");
        let first = conn.get_server_identity().await.expect("Identify A");
        assert_eq!(first.vendor, "vendor A");

        // no release in between: the new association replaces the old one
        conn.connect("127.0.0.1", b.bound_addr.port())
            .await
            .expect("connect B");
        let second = conn.get_server_identity().await.expect("Identify B");
        assert_eq!(second.vendor, "vendor B");
        let lds = conn
            .get_server_directory(false)
            .await
            .expect("directory of B");
        assert_eq!(lds, vec!["BLD0".to_string()]);

        conn.disconnect().await.expect("release B");
        a.stop().await;
        b.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connecting_over_an_established_association_reaches_the_new_server() {
    let a = plain_server("A", "vendor A")
        .start()
        .await
        .expect("start A");
    let b = plain_server("B", "vendor B")
        .start()
        .await
        .expect("start B");

    let conn = IedConnection::new();
    conn.connect("127.0.0.1", a.bound_addr.port())
        .await
        .expect("connect A");
    let first = conn.get_server_identity().await.expect("Identify A");
    assert_eq!(first.vendor, "vendor A");

    conn.connect("127.0.0.1", b.bound_addr.port())
        .await
        .expect("connect B");
    let second = conn.get_server_identity().await.expect("Identify B");
    assert_eq!(second.vendor, "vendor B");

    conn.disconnect().await.expect("release B");
    a.stop().await;
    b.stop().await;
}
