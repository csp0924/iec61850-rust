//! Server side of the TLS handshake, producing a stream that plugs into COTP.

use std::sync::Arc;

use tokio::net::TcpStream;
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
#[derive(Clone)]
pub struct TlsAcceptor {
    inner: RustlsTlsAcceptor,
    event_handler: Arc<dyn TlsEventHandler>,
    client_auth_optional: bool,
}

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
        }
    }

    /// Accepts one TCP connection and runs the TLS handshake.
    ///
    /// The returned `TlsStream<TcpStream>` is the generic argument of
    /// `CotpConnection<T>`.
    ///
    /// # Errors
    ///
    /// The [`TlsError`] variant that classifies the failure, as described
    /// there, when the handshake fails.
    pub async fn accept(&self, tcp: TcpStream) -> Result<TlsStream<TcpStream>, TlsError> {
        match self.inner.accept(tcp).await {
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
            Err(e) => {
                tracing::warn!("TLS server handshake failed: {}", e);
                report_handshake_failure(self.event_handler.as_ref(), "server", &e);
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
}
