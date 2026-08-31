//! Integration tests for the server-side TLS transport.
//!
//! A self-signed CA and server certificate are generated with rcgen; the tests
//! then check that the TLS handshake completes, that the ISO stack (COTP,
//! session, presentation, ACSE) and MMS Initiate run over it, and that the
//! `with_tls` builder path works. Every await is wrapped in a five-second
//! timeout so a stalled handshake cannot hang the run.

use iec61850_model::{IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder};
use iec61850_server::IedServer;
use iec61850_tls::{TlsAcceptor, TlsConfigBuilder};
use rcgen::{CertificateParams, IsCa, KeyPair};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

// Test helpers.

/// Builds the smallest usable model.
fn minimal_model() -> Arc<IedModel> {
    let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .build()
        .expect("ld");
    Arc::new(
        IedModelBuilder::new("TEST")
            .add_ld(ld)
            .expect("add_ld")
            .build()
            .expect("model"),
    )
}

/// Generates a self-signed CA and a server certificate.
///
/// Returns the CA certificate, the server certificate and the server key, all
/// PEM encoded.
fn gen_certs() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    // CA
    let ca_key = KeyPair::generate().expect("ca key gen");
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
    let ca_cert_pem = ca_cert.pem().into_bytes();

    // Server leaf certificate with localhost as its subject alternative name.
    let server_key = KeyPair::generate().expect("server key gen");
    let mut server_params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
    server_params.subject_alt_names = vec![rcgen::SanType::DnsName(
        "localhost".to_string().try_into().expect("san"),
    )];
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("server cert");
    let server_cert_pem = server_cert.pem().into_bytes();
    let server_key_pem = server_key.serialize_pem().into_bytes();

    (ca_cert_pem, server_cert_pem, server_key_pem)
}

// Integration tests.

/// A TLS client completes Initiate against a TLS server.
///
/// Only the handshake and the ISO stack up to MMS Initiate are exercised; no
/// data services are called.
#[tokio::test]
async fn server_tls_handshake_succeeds() {
    let result = tokio::time::timeout(Duration::from_secs(5), run_server_tls_handshake()).await;

    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("TLS handshake failed: {}", e),
        Err(_) => panic!("TLS handshake timed out after 5s"),
    }
}

async fn run_server_tls_handshake() -> Result<(), Box<dyn std::error::Error>> {
    let (ca_cert_pem, server_cert_pem, server_key_pem) = gen_certs();

    // TLS server configuration.
    let server_tls_config = TlsConfigBuilder::new()
        .with_cert_pem(&server_cert_pem, &server_key_pem)?
        .add_ca_pem(&ca_cert_pem)?
        // A client certificate is optional; when one is presented the chain is
        // validated.
        .build_server()?;
    let tls_acceptor = TlsAcceptor::new(server_tls_config);

    // Server bound to the TLS acceptor.
    let server = IedServer::builder()
        .model(minimal_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .with_tls(tls_acceptor)
        .build()?;

    let handle = server.start().await?;
    let bound_addr = handle.bound_addr;

    // TLS client configuration.
    let client_tls_config = TlsConfigBuilder::new()
        .add_ca_pem(&ca_cert_pem)?
        .build_client()?;
    let connector = iec61850_tls::TlsConnector::new(client_tls_config);

    // Connect over TLS.
    let server_name: rustls::pki_types::ServerName<'static> =
        "localhost".try_into().expect("server name");

    let mut client = iec61850_mms::mms::client::MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .build();

    client
        .connect_tls(bound_addr, &connector, server_name)
        .await
        .map_err(|e| format!("MMS connect over TLS failed: {}", e))?;

    // Initiate completed; disconnect.
    let _ = client.disconnect().await; // the server may have closed first

    handle.stop().await;
    Ok(())
}

/// Without a TLS acceptor the server still serves plain TCP unchanged.
#[tokio::test]
async fn server_plain_tcp_still_works_after_tls_api_added() {
    let result = tokio::time::timeout(Duration::from_secs(5), run_plain_tcp_sanity()).await;

    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("plain TCP path failed: {}", e),
        Err(_) => panic!("plain TCP path timed out"),
    }
}

async fn run_plain_tcp_sanity() -> Result<(), Box<dyn std::error::Error>> {
    // No with_tls call, so the listener stays plain TCP.
    let server = IedServer::builder()
        .model(minimal_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()?;

    let handle = server.start().await?;
    let bound_addr = handle.bound_addr;
    assert!(bound_addr.port() > 0);

    let mut client = iec61850_mms::mms::client::MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .build();

    client
        .connect("127.0.0.1", bound_addr.port())
        .await
        .map_err(|e| format!("plain TCP connect failed: {}", e))?;

    let _ = client.disconnect().await;
    handle.stop().await;
    Ok(())
}
