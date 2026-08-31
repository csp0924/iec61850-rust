//! Client side of the TLS handshake, producing a stream that plugs into COTP.

use std::sync::Arc;

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector as RustlsTlsConnector};

use crate::config::TlsClientConfig;
use crate::error::TlsError;

/// TLS connector for the client side.
///
/// A thin wrapper over `tokio_rustls::TlsConnector`; cloning is cheap, because
/// the configuration sits behind an `Arc`. The returned
/// `tokio_rustls::client::TlsStream<TcpStream>` implements
/// `AsyncRead + AsyncWrite + Unpin`, so it can be handed to
/// `CotpConnection::new()` with no change inside COTP.
#[derive(Clone)]
pub struct TlsConnector {
    inner: RustlsTlsConnector,
}

impl std::fmt::Debug for TlsConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConnector").finish_non_exhaustive()
    }
}

impl TlsConnector {
    /// Builds a connector from a [`TlsClientConfig`].
    pub fn new(config: TlsClientConfig) -> Self {
        Self {
            inner: RustlsTlsConnector::from(config.inner()),
        }
    }

    /// Builds a connector directly from an `Arc<rustls::ClientConfig>`.
    pub fn from_rustls(config: Arc<rustls::ClientConfig>) -> Self {
        Self {
            inner: RustlsTlsConnector::from(config),
        }
    }

    /// Runs the TLS handshake over an already connected TCP stream.
    ///
    /// `server_name` is presented in SNI and checked against the server
    /// certificate. The returned `TlsStream<TcpStream>` is the generic
    /// argument of `CotpConnection<T>`.
    ///
    /// # Errors
    ///
    /// [`TlsError::Io`] if the handshake fails.
    pub async fn connect(
        &self,
        server_name: ServerName<'static>,
        tcp: TcpStream,
    ) -> Result<TlsStream<TcpStream>, TlsError> {
        self.inner.connect(server_name, tcp).await.map_err(|e| {
            tracing::warn!("TLS client handshake failed: {}", e);
            TlsError::Io(e)
        })
    }
}
