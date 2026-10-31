//! Transport failures over TLS.
//!
//! A server that requires a client certificate refuses a client that presents
//! none. Under TLS 1.3 the client completes its side of the handshake first
//! and only learns of the refusal from the fatal alert that follows, so the
//! refusal reaches the client as a failed read; the error must carry that
//! alert rather than a bare "transport IO error".
//!
//! The refusing peer is driven by hand over `rustls::ServerConnection`, so
//! that it sends the alert and then reads until the client closes. Closing
//! with the client's COTP request still unread would reset the connection,
//! and a reset may discard the alert before the client reads it.

#![cfg(feature = "tls")]

use std::sync::Arc;
use std::time::Duration;

use iec61850_client::{ClientError, IedConnection, IoErrorKind};
use iec61850_tls::{TlsConfigBuilder, TlsConnector};
use rcgen::{CertificateParams, IsCa, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A CA certificate, and a server certificate for `localhost` it signed, all
/// PEM encoded.
fn certificates() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).expect("ca certificate");

    let server_key = KeyPair::generate().expect("server key");
    let server_params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
    let server = server_params
        .signed_by(&server_key, &ca, &ca_key)
        .expect("server certificate");
    (
        ca.pem().into_bytes(),
        server.pem().into_bytes(),
        server_key.serialize_pem().into_bytes(),
    )
}

/// Accepts one connection, runs the TLS handshake under `config` until it
/// fails, sends the alert rustls queued, and reads until the client closes.
async fn refuse_once(listener: TcpListener, config: Arc<rustls::ServerConfig>) {
    let (mut tcp, _) = listener.accept().await.expect("accept");
    let mut tls = rustls::ServerConnection::new(config).expect("server connection");
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        while tls.wants_write() {
            let mut out = Vec::new();
            tls.write_tls(&mut out).expect("write tls");
            tcp.write_all(&out).await.expect("send tls");
        }
        let n = tcp.read(&mut buf).await.unwrap_or(0);
        if n == 0 {
            return;
        }
        let mut input = &buf[..n];
        while !input.is_empty() {
            tls.read_tls(&mut input).expect("read tls");
            if tls.process_new_packets().is_err() {
                while tls.wants_write() {
                    let mut out = Vec::new();
                    tls.write_tls(&mut out).expect("write alert");
                    tcp.write_all(&out).await.expect("send alert");
                }
                while tcp.read(&mut buf).await.map(|n| n > 0).unwrap_or(false) {}
                return;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refused_client_certificate_reaches_the_client_with_its_cause() {
    let (ca, server_cert, server_key) = certificates();
    let server_tls = TlsConfigBuilder::new()
        .with_cert_pem(&server_cert, &server_key)
        .expect("server certificate")
        .add_ca_pem(&ca)
        .expect("ca")
        .require_client_auth(true)
        .build_server()
        .expect("server config");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let peer = tokio::spawn(refuse_once(listener, server_tls.inner()));

    let client_tls = TlsConfigBuilder::new()
        .add_ca_pem(&ca)
        .expect("ca")
        .build_client()
        .expect("client config");
    let connector = TlsConnector::new(client_tls);
    let conn = IedConnection::new();
    let r = tokio::time::timeout(
        Duration::from_secs(10),
        conn.connect_tls(
            addr,
            &connector,
            "localhost".try_into().expect("server name"),
        ),
    )
    .await
    .expect("connect does not hang");

    match r {
        Err(ClientError::Transport(cause)) => {
            assert_eq!(cause.kind(), IoErrorKind::InvalidData, "{cause}");
            let detail = cause.detail().unwrap_or_default();
            assert!(
                detail.contains("CertificateRequired"),
                "the alert is carried: {cause}"
            );
        }
        other => panic!("expected a transport error carrying the alert, got {other:?}"),
    }
    assert!(!conn.is_connected());
    peer.await.expect("peer");
}
