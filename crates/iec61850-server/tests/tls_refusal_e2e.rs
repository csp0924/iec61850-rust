//! A client the TLS server refuses learns why: the server sends its alert
//! and closes the connection without resetting it, so the alert reaches the
//! client over a real TCP connection.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iec61850_model::{IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder};
use iec61850_server::IedServer;
use iec61850_tls::{TlsAcceptor, TlsConfigBuilder, TlsConnector, TlsVersion};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, SanType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn minimal_model() -> Arc<IedModel> {
    let lln0 = LogicalNodeBuilder::lln0().build().unwrap();
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .build()
        .unwrap();
    Arc::new(
        IedModelBuilder::new("TEST")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap(),
    )
}

/// A CA and a server certificate for `localhost` it issued: the CA PEM, the
/// server certificate PEM and the server key PEM.
fn certificates() -> (String, String, String) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
    let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
    (ca.pem(), cert.pem(), key.serialize_pem())
}

/// A server that requires a client certificate refuses a client without one,
/// and the client reads the alert the server sent rather than a reset
/// connection.
///
/// Under TLS 1.3 the client finishes its side of the handshake before the
/// server checks the client certificate, so the client has already sent its
/// first data, here the 22 octets of a COTP connection request, when the
/// refusal comes; the server must read past that data to close cleanly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_client_reads_the_alert_of_the_server() {
    let (ca, cert, key) = certificates();
    let server_tls = TlsConfigBuilder::new()
        .with_cert_pem(cert.as_bytes(), key.as_bytes())
        .unwrap()
        .add_ca_pem(ca.as_bytes())
        .unwrap()
        .require_client_auth(true)
        .build_server()
        .unwrap();
    let server = IedServer::builder()
        .model(minimal_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .with_tls(TlsAcceptor::new(server_tls))
        .build()
        .unwrap();
    let handle = server.start().await.unwrap();

    let client_tls = TlsConfigBuilder::new()
        .add_ca_pem(ca.as_bytes())
        .unwrap()
        .build_client()
        .unwrap();
    let tcp = TcpStream::connect(handle.bound_addr).await.unwrap();
    let mut stream = TlsConnector::new(client_tls)
        .connect("localhost".try_into().unwrap(), tcp)
        .await
        .expect("the client side of a TLS 1.3 handshake completes");
    assert_eq!(stream.protocol_version(), Some(TlsVersion::Tls13));
    let cotp_cr = [
        0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc0, 0x01, 0x0d, 0xc2,
        0x02, 0x00, 0x01, 0xc1, 0x02, 0x00, 0x01,
    ];
    stream.write_all(&cotp_cr).await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = [0u8; 64];
    let err = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
        .await
        .expect("the read ends")
        .expect_err("the server refuses the client");
    let alert = err
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .cloned();
    assert_eq!(
        alert,
        Some(rustls::Error::AlertReceived(
            rustls::AlertDescription::CertificateRequired
        )),
        "the client must read the alert of the server, got {err:?}"
    );
    handle.stop().await;
}
