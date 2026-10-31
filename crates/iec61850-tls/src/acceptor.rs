//! Server side of the TLS handshake, producing a stream that plugs into COTP.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor as RustlsTlsAcceptor;

use crate::config::TlsServerConfig;
use crate::error::TlsError;
use crate::event::{
    report_established, report_handshake_failure, DefaultTracingHandler, TlsEventCode,
    TlsEventHandler, TlsEventLevel,
};
use crate::stream::TlsStream;

/// TLS acceptor for the server side.
///
/// Cloning is cheap, because the configuration sits behind an `Arc`. The
/// returned [`TlsStream<TcpStream>`] implements
/// `AsyncRead + AsyncWrite + Unpin`, so it can be handed to
/// `CotpConnection::new()` with no change inside COTP.
///
/// Each handshake raises events on the configuration's event handler:
/// `SessionEstablished` on success, `WrnNoPeerCert` when a client presents no
/// certificate to a server that requests one without requiring it, and an
/// alarm when the handshake fails for a reason with a matching code.
///
/// A refused connection is closed so that the client reads the alert that
/// says why: after the alert, the write side is shut down and whatever the
/// client still sends is read and discarded until it closes, for at most two
/// seconds and 16 KiB. Closing at once with unread data would reset the
/// connection and could discard the alert. At most 64 refused connections
/// are drained at a time across the clones of one acceptor; a refusal beyond
/// them is closed at once, so a peer that keeps failing handshakes cannot
/// make the server hold more sockets than that.
#[derive(Clone)]
pub struct TlsAcceptor {
    inner: RustlsTlsAcceptor,
    event_handler: Arc<dyn TlsEventHandler>,
    client_auth_optional: bool,
    refusal_drains: Arc<Semaphore>,
}

/// Refused connections drained at a time; a refusal beyond them is closed at
/// once.
const REFUSAL_DRAINS: usize = 64;

/// Longest time a refused connection stays open, waiting for the client to
/// close it after reading the alert.
const REFUSAL_LINGER: Duration = Duration::from_secs(2);

/// Most octets read and discarded from a refused connection before it is
/// closed.
const REFUSAL_DRAIN_LIMIT: usize = 16 * 1024;

impl std::fmt::Debug for TlsAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsAcceptor").finish_non_exhaustive()
    }
}

impl TlsAcceptor {
    /// Builds an acceptor from a [`TlsServerConfig`], reporting events to the
    /// configuration's event handler.
    pub fn new(config: TlsServerConfig) -> Self {
        Self {
            inner: RustlsTlsAcceptor::from(config.inner()),
            event_handler: config.event_handler,
            client_auth_optional: config.client_auth_optional,
            refusal_drains: Arc::new(Semaphore::new(REFUSAL_DRAINS)),
        }
    }

    /// Builds an acceptor directly from an `Arc<rustls::ServerConfig>`.
    ///
    /// Events go to [`DefaultTracingHandler`]; `WrnNoPeerCert` is never
    /// raised, because the client authentication policy of a foreign
    /// configuration is unknown.
    pub fn from_rustls(config: Arc<rustls::ServerConfig>) -> Self {
        Self {
            inner: RustlsTlsAcceptor::from(config),
            event_handler: Arc::new(DefaultTracingHandler),
            client_auth_optional: false,
            refusal_drains: Arc::new(Semaphore::new(REFUSAL_DRAINS)),
        }
    }

    /// Accepts one TCP connection and runs the TLS handshake.
    ///
    /// The returned `TlsStream<TcpStream>` is the generic argument of
    /// `CotpConnection<T>`.
    ///
    /// The close of a refused connection, described on the type, runs on a
    /// task of its own, so the error is returned without waiting for it; that
    /// task needs a runtime with the time driver enabled.
    ///
    /// # Errors
    ///
    /// The [`TlsError`] variant that classifies the failure, as described
    /// there, when the handshake fails.
    pub async fn accept(&self, tcp: TcpStream) -> Result<TlsStream<TcpStream>, TlsError> {
        match self.inner.accept(tcp).into_fallible().await {
            Ok(stream) => {
                let stream = TlsStream::new(stream);
                let conn = stream.state();
                report_established(self.event_handler.as_ref(), "server", conn);
                if self.client_auth_optional && conn.peer_certificates().is_none() {
                    let msg = "client presented no certificate; client authentication is optional";
                    self.event_handler.on_event(
                        TlsEventLevel::Warning,
                        TlsEventCode::WrnNoPeerCert,
                        msg,
                    );
                    tracing::warn!("{}", msg);
                }
                Ok(stream)
            }
            Err((e, tcp)) => {
                tracing::warn!("TLS server handshake failed: {}", e);
                report_handshake_failure(self.event_handler.as_ref(), "server", &e);
                match Arc::clone(&self.refusal_drains).try_acquire_owned() {
                    Ok(permit) => {
                        tokio::spawn(async move {
                            close_refused(tcp).await;
                            drop(permit);
                        });
                    }
                    Err(_) => {
                        tracing::debug!(
                            "refused TLS connection closed at once: {} refusals are draining",
                            REFUSAL_DRAINS
                        );
                    }
                }
                Err(TlsError::from_handshake(e))
            }
        }
    }

    /// Raises `AlmHandshakeTimeout` at the `Incident` level on the event
    /// handler, with `message`, and logs it as a warning.
    ///
    /// [`accept`](Self::accept) applies no timeout of its own; the caller that
    /// bounds the handshake, or the association setup that follows it, reports
    /// the expiry through this method.
    pub fn report_handshake_timeout(&self, message: &str) {
        self.event_handler.on_event(
            TlsEventLevel::Incident,
            TlsEventCode::AlmHandshakeTimeout,
            message,
        );
        tracing::warn!("{}", message);
    }
}

/// Closes a connection whose handshake failed, after the alert went out:
/// shuts down the write side, then reads and discards until the client
/// closes, for at most [`REFUSAL_LINGER`] and [`REFUSAL_DRAIN_LIMIT`] octets.
async fn close_refused(mut tcp: TcpStream) {
    if let Err(e) = tcp.shutdown().await {
        tracing::debug!(
            "refused TLS connection: shutting down the write side failed: {}",
            e
        );
        return;
    }
    let mut buf = [0u8; 1024];
    let mut drained = 0usize;
    let drain = async {
        while drained < REFUSAL_DRAIN_LIMIT {
            match tcp.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => drained += n,
            }
        }
    };
    if tokio::time::timeout(REFUSAL_LINGER, drain).await.is_err() {
        tracing::debug!("refused TLS connection: the client did not close it in time");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recorder(Mutex<Vec<(TlsEventLevel, TlsEventCode, String)>>);

    impl TlsEventHandler for Recorder {
        fn on_event(&self, level: TlsEventLevel, code: TlsEventCode, message: &str) {
            self.0
                .lock()
                .unwrap()
                .push((level, code, message.to_string()));
        }
    }

    #[test]
    fn handshake_timeout_is_reported_as_an_incident() {
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));
        let recorder = Arc::new(Recorder::default());
        let acceptor = TlsAcceptor {
            inner: RustlsTlsAcceptor::from(Arc::new(config)),
            event_handler: recorder.clone(),
            client_auth_optional: false,
            refusal_drains: Arc::new(Semaphore::new(REFUSAL_DRAINS)),
        };

        acceptor.report_handshake_timeout("setup timed out");

        assert_eq!(
            *recorder.0.lock().unwrap(),
            vec![(
                TlsEventLevel::Incident,
                TlsEventCode::AlmHandshakeTimeout,
                "setup timed out".to_string()
            )]
        );
    }

    /// A server that requires a client certificate, the matching client
    /// configuration without one, and the acceptor.
    fn refusing_pair() -> (TlsAcceptor, crate::TlsConnector) {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .signed_by(&key, &ca, &ca_key)
            .unwrap();
        let server = crate::TlsConfigBuilder::new()
            .with_cert_pem(cert.pem().as_bytes(), key.serialize_pem().as_bytes())
            .unwrap()
            .add_ca_pem(ca.pem().as_bytes())
            .unwrap()
            .require_client_auth(true)
            .build_server()
            .unwrap();
        let client = crate::TlsConfigBuilder::new()
            .add_ca_pem(ca.pem().as_bytes())
            .unwrap()
            .build_client()
            .unwrap();
        (TlsAcceptor::new(server), crate::TlsConnector::new(client))
    }

    /// Runs one refused handshake. The client completes its side under TLS
    /// 1.3 and then neither sends nor closes; its stream is returned so the
    /// connection stays open.
    async fn refuse(
        acceptor: &TlsAcceptor,
        connector: &crate::TlsConnector,
    ) -> crate::TlsStream<TcpStream> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn({
            let connector = connector.clone();
            async move {
                let tcp = TcpStream::connect(addr).await.unwrap();
                connector
                    .connect("localhost".try_into().unwrap(), tcp)
                    .await
                    .unwrap()
            }
        });
        let (tcp, _) = listener.accept().await.unwrap();
        let (accepted, client) = tokio::join!(acceptor.accept(tcp), client);
        assert!(matches!(accepted, Err(TlsError::Verification(_))));
        client.unwrap()
    }

    #[tokio::test]
    async fn a_refused_connection_is_drained_for_at_most_the_linger_time() {
        let (acceptor, connector) = refusing_pair();
        let _client = refuse(&acceptor, &connector).await;
        tokio::time::pause();
        // Lets the drain task start its wait on the paused clock.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            acceptor.refusal_drains.available_permits(),
            REFUSAL_DRAINS - 1,
            "the refused connection is draining"
        );
        tokio::time::advance(REFUSAL_LINGER - Duration::from_millis(1)).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            acceptor.refusal_drains.available_permits(),
            REFUSAL_DRAINS - 1,
            "still draining just before the linger time"
        );
        // One more millisecond of timer granularity on top of the linger time.
        tokio::time::advance(Duration::from_millis(2)).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            acceptor.refusal_drains.available_permits(),
            REFUSAL_DRAINS,
            "the drain ends at the linger time"
        );
    }

    #[tokio::test]
    async fn a_refusal_beyond_the_drain_limit_is_closed_at_once() {
        let (acceptor, connector) = refusing_pair();
        let held = Arc::clone(&acceptor.refusal_drains)
            .try_acquire_many_owned(REFUSAL_DRAINS as u32)
            .unwrap();
        let tasks = tokio::runtime::Handle::current().metrics();
        let before = tasks.num_alive_tasks();
        let _client = refuse(&acceptor, &connector).await;
        assert_eq!(
            tasks.num_alive_tasks(),
            before,
            "no task drains the refused connection"
        );
        drop(held);
        assert_eq!(
            acceptor.refusal_drains.available_permits(),
            REFUSAL_DRAINS,
            "no drain took a permit"
        );
    }
}
