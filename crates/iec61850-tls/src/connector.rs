//! Client side of the TLS handshake, producing a stream that plugs into COTP.

use std::sync::Arc;

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector as RustlsTlsConnector;

use crate::config::TlsClientConfig;
use crate::error::TlsError;
use crate::event::{
    report_established, report_handshake_failure, DefaultTracingHandler, TlsEventHandler,
};
use crate::stream::TlsStream;

/// TLS connector for the client side.
///
/// Cloning is cheap, because the configuration sits behind an `Arc`. The
/// returned [`TlsStream<TcpStream>`] implements
/// `AsyncRead + AsyncWrite + Unpin`, so it can be handed to
/// `CotpConnection::new()` with no change inside COTP.
///
/// Each handshake raises events on the configuration's event handler:
/// `SessionEstablished` on success, and an alarm when the handshake fails for
/// a reason with a matching code.
#[derive(Clone)]
pub struct TlsConnector {
    inner: RustlsTlsConnector,
    event_handler: Arc<dyn TlsEventHandler>,
}

impl std::fmt::Debug for TlsConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConnector").finish_non_exhaustive()
    }
}

impl TlsConnector {
    /// Builds a connector from a [`TlsClientConfig`], reporting events to the
    /// configuration's event handler.
    pub fn new(config: TlsClientConfig) -> Self {
        Self {
            inner: RustlsTlsConnector::from(config.inner()),
            event_handler: config.event_handler,
        }
    }

    /// Builds a connector directly from an `Arc<rustls::ClientConfig>`.
    ///
    /// Events go to [`DefaultTracingHandler`].
    pub fn from_rustls(config: Arc<rustls::ClientConfig>) -> Self {
        Self {
            inner: RustlsTlsConnector::from(config),
            event_handler: Arc::new(DefaultTracingHandler),
        }
    }

    /// Runs the TLS handshake over an already connected TCP stream.
    ///
    /// `server_name` is presented in SNI and checked against the server
    /// certificate, unless the configuration was built with
    /// `with_dangerous_no_sni_verify()`. The returned `TlsStream<TcpStream>` is
    /// the generic argument of `CotpConnection<T>`.
    ///
    /// # Errors
    ///
    /// The [`TlsError`] variant that classifies the failure, as described
    /// there, when the handshake fails.
    pub async fn connect(
        &self,
        server_name: ServerName<'static>,
        tcp: TcpStream,
    ) -> Result<TlsStream<TcpStream>, TlsError> {
        match self.inner.connect(server_name, tcp).await {
            Ok(stream) => {
                let stream = TlsStream::new(stream);
                report_established(self.event_handler.as_ref(), "client", stream.state());
                Ok(stream)
            }
            Err(e) => {
                tracing::warn!("TLS client handshake failed: {}", e);
                report_handshake_failure(self.event_handler.as_ref(), "client", &e);
                Err(TlsError::from_handshake(e))
            }
        }
    }
}
