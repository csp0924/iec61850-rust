//! The IEC 62351-3 event `AlmHandshakeTimeout` on a TLS server: raised when
//! the TLS handshake, or the association setup after it, exceeds the
//! association setup timeout, and not raised for an association that
//! completes.
//!
//! The setup timeout is 60 s. Where a test waits for it to expire, the tokio
//! clock is paused, so the runtime advances to the deadline as soon as every
//! task is waiting and the expiry does not depend on wall-clock time.

use iec61850_model::{IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder};
use iec61850_server::{IedServer, IedServerConfig, ServerHandle};
use iec61850_tls::{
    TlsAcceptor, TlsConfigBuilder, TlsConnector, TlsEventCode, TlsEventHandler, TlsEventLevel,
};
use rcgen::{CertificateParams, IsCa, KeyPair};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncReadExt;
use tokio::sync::Notify;

/// Association setup timeout of the servers under test.
const SETUP_TIMEOUT_MS: u64 = 60_000;

#[derive(Default)]
struct Recorder {
    events: Mutex<Vec<(TlsEventLevel, TlsEventCode, String)>>,
    raised: Notify,
}

impl TlsEventHandler for Recorder {
    fn on_event(&self, level: TlsEventLevel, code: TlsEventCode, message: &str) {
        self.events
            .lock()
            .unwrap()
            .push((level, code, message.to_string()));
        self.raised.notify_waiters();
    }
}

impl Recorder {
    /// Waits until the event handler has received `code`.
    async fn wait_for(&self, code: TlsEventCode) {
        loop {
            let raised = self.raised.notified();
            if self
                .events
                .lock()
                .unwrap()
                .iter()
                .any(|(_, c, _)| *c == code)
            {
                return;
            }
            raised.await;
        }
    }

    /// The messages of the `AlmHandshakeTimeout` incidents raised so far.
    fn timeouts(&self) -> Vec<String> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|(level, code, _)| {
                *level == TlsEventLevel::Incident && *code == TlsEventCode::AlmHandshakeTimeout
            })
            .map(|(_, _, message)| message.clone())
            .collect()
    }
}

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

/// A CA certificate, and a server certificate for `localhost` with its key,
/// all PEM encoded.
fn gen_certs() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let server_key = KeyPair::generate().unwrap();
    let server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();
    (
        ca_cert.pem().into_bytes(),
        server_cert.pem().into_bytes(),
        server_key.serialize_pem().into_bytes(),
    )
}

/// Starts a TLS server with the 60 s association setup timeout whose events go
/// to the returned recorder, and returns a connector trusting it.
async fn start_tls_server() -> (ServerHandle, Arc<Recorder>, TlsConnector) {
    let (ca, cert, key) = gen_certs();
    let recorder = Arc::new(Recorder::default());
    let server_tls = TlsConfigBuilder::new()
        .with_cert_pem(&cert, &key)
        .unwrap()
        .add_ca_pem(&ca)
        .unwrap()
        .with_event_handler(recorder.clone())
        .build_server()
        .unwrap();
    let mut config = IedServerConfig::default();
    config.association_setup_timeout_ms = SETUP_TIMEOUT_MS;
    let handle = IedServer::builder()
        .model(minimal_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(config)
        .with_tls(TlsAcceptor::new(server_tls))
        .build()
        .unwrap()
        .start()
        .await
        .unwrap();
    let client_tls = TlsConfigBuilder::new()
        .add_ca_pem(&ca)
        .unwrap()
        .build_client()
        .unwrap();
    (handle, recorder, TlsConnector::new(client_tls))
}

/// Reads until the server closes the connection.
///
/// No timer of its own competes with the server's deadline: on the paused
/// clock the deadline is the next timer the runtime advances to.
async fn until_closed(stream: &mut (impl tokio::io::AsyncRead + Unpin)) {
    let mut buf = [0u8; 64];
    while let Ok(n) = stream.read(&mut buf).await {
        if n == 0 {
            break;
        }
    }
}

/// A TCP connection that never starts the TLS handshake raises one
/// `AlmHandshakeTimeout`, for the handshake, when the server closes it.
#[tokio::test(start_paused = true)]
async fn stalled_tls_handshake_raises_a_handshake_timeout() {
    let (handle, recorder, _) = start_tls_server().await;
    let mut silent = tokio::net::TcpStream::connect(handle.bound_addr)
        .await
        .unwrap();
    until_closed(&mut silent).await;
    let timeouts = recorder.timeouts();
    assert_eq!(timeouts.len(), 1, "{timeouts:?}");
    assert!(
        !timeouts[0].contains("after the TLS handshake"),
        "{timeouts:?}"
    );
    handle.stop().await;
}

/// A connection that completes the TLS handshake but never sends the
/// association request raises one `AlmHandshakeTimeout`, for the association
/// setup, when the server closes it.
///
/// The handshake runs on the wall clock against the 60 s deadline; the clock
/// is paused once the server has completed it, which it reports as
/// `SessionEstablished`.
#[tokio::test]
async fn stalled_association_setup_over_tls_raises_a_handshake_timeout() {
    let (handle, recorder, connector) = start_tls_server().await;
    let tcp = tokio::net::TcpStream::connect(handle.bound_addr)
        .await
        .unwrap();
    let mut tls = connector
        .connect("localhost".try_into().unwrap(), tcp)
        .await
        .expect("the TLS handshake completes");
    recorder.wait_for(TlsEventCode::SessionEstablished).await;
    assert!(recorder.timeouts().is_empty());

    tokio::time::pause();
    until_closed(&mut tls).await;
    let timeouts = recorder.timeouts();
    assert_eq!(timeouts.len(), 1, "{timeouts:?}");
    assert!(
        timeouts[0].contains("after the TLS handshake"),
        "{timeouts:?}"
    );
    handle.stop().await;
}

/// An association that completes over TLS raises no `AlmHandshakeTimeout`.
#[tokio::test]
async fn completed_association_raises_no_handshake_timeout() {
    let (handle, recorder, connector) = start_tls_server().await;
    let mut client = iec61850_mms::mms::client::MmsClientBuilder::new()
        .connect_timeout_ms(SETUP_TIMEOUT_MS)
        .build();
    client
        .connect_tls(
            handle.bound_addr,
            &connector,
            "localhost".try_into().unwrap(),
        )
        .await
        .expect("connect over TLS");
    client.disconnect().await.expect("release");
    assert!(recorder.timeouts().is_empty());
    handle.stop().await;
}
