//! TLS failures while a connection is being established.
//!
//! A server that requires a client certificate refuses a client that presents
//! none. Under TLS 1.3 the client completes its side of the handshake first
//! and only learns of the refusal from the fatal alert that follows, which it
//! reads during the COTP exchange. Until the association is established such
//! a TLS error is reported as `TlsHandshake`, classified like a failed
//! handshake; a transport failure with no TLS error behind it is not.
//!
//! The misbehaving peers are driven by hand over `rustls::ServerConnection`,
//! so that they send what they send and then read until the client closes.
//! Closing with the client's COTP request still unread would reset the
//! connection, and a reset may discard the alert before the client reads it.

#![cfg(feature = "tls")]

use std::sync::Arc;
use std::time::Duration;

use iec61850_client::{ClientError, IedConnection, TlsFailureKind};
use iec61850_tls::{TlsConfigBuilder, TlsConnector, TlsVersion};
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

/// What a peer does once its TLS 1.3 handshake with the client completed.
enum AfterHandshake {
    /// Sends these bytes as they are, then reads until the client closes.
    Send(Vec<u8>),
    /// Waits for the client's first bytes after the handshake and resets the
    /// TCP connection.
    Reset,
}

/// Accepts one connection, completes the TLS handshake under `config`, sends
/// whatever rustls queued, and then acts as `after` says.
async fn misbehave_once(
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    after: AfterHandshake,
) {
    let (mut tcp, _) = listener.accept().await.expect("accept");
    let mut tls = rustls::ServerConnection::new(config).expect("server connection");
    let mut buf = vec![0u8; 16 * 1024];
    while tls.is_handshaking() {
        while tls.wants_write() {
            let mut out = Vec::new();
            tls.write_tls(&mut out).expect("write tls");
            tcp.write_all(&out).await.expect("send tls");
        }
        let n = tcp.read(&mut buf).await.expect("read tls");
        assert!(n > 0, "the client closed during the handshake");
        let mut input = &buf[..n];
        while !input.is_empty() {
            tls.read_tls(&mut input).expect("read tls");
            tls.process_new_packets().expect("handshake");
        }
    }
    while tls.wants_write() {
        let mut out = Vec::new();
        tls.write_tls(&mut out).expect("write tls");
        tcp.write_all(&out).await.expect("send tls");
    }
    match after {
        AfterHandshake::Send(bytes) => {
            tcp.write_all(&bytes).await.expect("send");
            while tcp.read(&mut buf).await.map(|n| n > 0).unwrap_or(false) {}
        }
        AfterHandshake::Reset => {
            // The client's first bytes may have come with its Finished and been
            // decrypted already; otherwise they are read until they decrypt.
            let mut io = tls.process_new_packets().expect("records");
            while io.plaintext_bytes_to_read() == 0 {
                let n = tcp.read(&mut buf).await.expect("read");
                assert!(n > 0, "the client closed before sending");
                let mut input = &buf[..n];
                while !input.is_empty() {
                    tls.read_tls(&mut input).expect("read tls");
                    io = tls.process_new_packets().expect("records");
                }
            }
            // A zero linger time turns the close into a reset.
            tcp.set_zero_linger().expect("zero linger");
            drop(tcp);
        }
    }
}

/// A server configuration for `localhost` that only speaks TLS 1.3.
fn tls13_server(
    server_cert: &[u8],
    server_key: &[u8],
    ca: &[u8],
    client_auth: bool,
) -> Arc<rustls::ServerConfig> {
    TlsConfigBuilder::new()
        .with_cert_pem(server_cert, server_key)
        .expect("server certificate")
        .add_ca_pem(ca)
        .expect("ca")
        .require_client_auth(client_auth)
        .min_version(TlsVersion::Tls13)
        .build_server()
        .expect("server config")
        .inner()
}

/// Connects a client that trusts `ca` and presents no certificate.
async fn connect_without_certificate(
    addr: std::net::SocketAddr,
    ca: &[u8],
) -> (IedConnection, Result<(), ClientError>) {
    let client_tls = TlsConfigBuilder::new()
        .add_ca_pem(ca)
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
    (conn, r)
}

/// The fatal alert of a TLS 1.3 server that refuses the missing client
/// certificate, read during the COTP exchange, is a failed TLS handshake of
/// the `AlertReceived` kind that names the alert.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refused_client_certificate_reaches_the_client_with_its_cause() {
    let (ca, server_cert, server_key) = certificates();
    let server_tls = tls13_server(&server_cert, &server_key, &ca, true);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let peer = tokio::spawn(refuse_once(listener, server_tls));

    let (conn, r) = connect_without_certificate(addr, &ca).await;
    assert_alert_received(r);
    assert!(!conn.is_connected());
    peer.await.expect("peer");
}

/// A record that does not decrypt after the handshake is a failed TLS
/// handshake too, of the kind the TLS error has.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_undecryptable_record_before_the_association_is_a_tls_failure() {
    let (ca, server_cert, server_key) = certificates();
    let server_tls = tls13_server(&server_cert, &server_key, &ca, false);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    // An application data record whose 32 bytes of zeros are no valid
    // ciphertext under the session keys.
    let mut record = vec![0x17, 0x03, 0x03, 0x00, 0x20];
    record.extend_from_slice(&[0u8; 32]);
    let peer = tokio::spawn(misbehave_once(
        listener,
        server_tls,
        AfterHandshake::Send(record),
    ));

    let (conn, r) = connect_without_certificate(addr, &ca).await;
    match r {
        Err(ClientError::TlsHandshake { kind, message, .. }) => {
            assert_eq!(kind, TlsFailureKind::Other, "{message}");
            assert!(message.contains("decrypt"), "{message}");
        }
        other => panic!("expected a TLS failure, got {other:?}"),
    }
    assert!(!conn.is_connected());
    peer.await.expect("peer");
}

/// A peer that completes the handshake and then resets the TCP connection
/// raises no TLS error, so the failure is a transport one, not a TLS one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reset_after_the_handshake_is_not_a_tls_failure() {
    let (ca, server_cert, server_key) = certificates();
    let server_tls = tls13_server(&server_cert, &server_key, &ca, false);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let peer = tokio::spawn(misbehave_once(listener, server_tls, AfterHandshake::Reset));

    let (conn, r) = connect_without_certificate(addr, &ca).await;
    match r {
        Err(ClientError::ConnectionLost | ClientError::Transport(_)) => {}
        other => panic!("expected a transport failure, got {other:?}"),
    }
    assert!(!conn.is_connected());
    peer.await.expect("peer");
}

fn assert_alert_received(r: Result<(), ClientError>) {
    match r {
        Err(ClientError::TlsHandshake { kind, message, .. }) => {
            assert_eq!(kind, TlsFailureKind::AlertReceived, "{message}");
            assert!(
                message.contains("CertificateRequired"),
                "the alert is named: {message}"
            );
        }
        other => panic!("expected a TLS failure naming the alert, got {other:?}"),
    }
}

/// The same refusal by our own TLS 1.3 server: it sends the alert and reads
/// past the client's COTP request before closing, so the client reports the
/// alert as a failed TLS handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refusal_by_the_iec61850_server_reaches_the_client_with_its_cause() {
    let (ca, server_cert, server_key) = certificates();
    let server_tls = TlsConfigBuilder::new()
        .with_cert_pem(&server_cert, &server_key)
        .expect("server certificate")
        .add_ca_pem(&ca)
        .expect("ca")
        .require_client_auth(true)
        .min_version(TlsVersion::Tls13)
        .build_server()
        .expect("server config");
    let lln0 = iec61850_model::LogicalNodeBuilder::lln0()
        .build()
        .expect("lln0");
    let ld = iec61850_model::LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .build()
        .expect("ld");
    let model = iec61850_model::IedModelBuilder::new("TEST")
        .add_ld(ld)
        .expect("add ld")
        .build()
        .expect("model");
    let server = iec61850_server::IedServer::builder()
        .model(Arc::new(model))
        .bind(
            "127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .expect("bind address"),
        )
        .with_tls(iec61850_tls::TlsAcceptor::new(server_tls))
        .build()
        .expect("server");
    let handle = server.start().await.expect("start");

    let (conn, r) = connect_without_certificate(handle.bound_addr, &ca).await;
    assert_alert_received(r);
    assert!(!conn.is_connected());
    handle.stop().await;
}
