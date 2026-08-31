//! Server side of the TLS handshake, producing a stream that plugs into COTP.

use std::sync::Arc;

use tokio::net::TcpStream;
use tokio_rustls::{server::TlsStream, TlsAcceptor as RustlsTlsAcceptor};

use crate::config::TlsServerConfig;
use crate::error::TlsError;

/// TLS acceptor for the server side.
///
/// A thin wrapper over `tokio_rustls::TlsAcceptor`; cloning is cheap, because
/// the configuration sits behind an `Arc`. The returned
/// `tokio_rustls::server::TlsStream<TcpStream>` implements
/// `AsyncRead + AsyncWrite + Unpin`, so it can be handed to
/// `CotpConnection::new()` with no change inside COTP.
#[derive(Clone)]
pub struct TlsAcceptor {
    inner: RustlsTlsAcceptor,
}

impl std::fmt::Debug for TlsAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsAcceptor").finish_non_exhaustive()
    }
}

impl TlsAcceptor {
    /// Builds an acceptor from a [`TlsServerConfig`].
    pub fn new(config: TlsServerConfig) -> Self {
        Self {
            inner: RustlsTlsAcceptor::from(config.inner()),
        }
    }

    /// Builds an acceptor directly from an `Arc<rustls::ServerConfig>`.
    pub fn from_rustls(config: Arc<rustls::ServerConfig>) -> Self {
        Self {
            inner: RustlsTlsAcceptor::from(config),
        }
    }

    /// Accepts one TCP connection and runs the TLS handshake.
    ///
    /// The returned `TlsStream<TcpStream>` is the generic argument of
    /// `CotpConnection<T>`.
    ///
    /// # Errors
    ///
    /// [`TlsError::Io`] if the handshake fails.
    pub async fn accept(&self, tcp: TcpStream) -> Result<TlsStream<TcpStream>, TlsError> {
        self.inner.accept(tcp).await.map_err(|e| {
            tracing::warn!("TLS server handshake failed: {}", e);
            TlsError::Io(e)
        })
    }
}
