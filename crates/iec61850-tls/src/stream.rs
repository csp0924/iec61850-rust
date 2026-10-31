//! The TLS stream a completed handshake hands back.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rustls_pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::config::TlsVersion;

/// A TLS session over the transport `S`, as returned by
/// [`crate::TlsAcceptor::accept`] and [`crate::TlsConnector::connect`].
///
/// It reads and writes application data through `AsyncRead` and
/// `AsyncWrite`, so it can be handed to `CotpConnection::new()` like the bare
/// transport, and it exposes what the handshake negotiated: the peer
/// certificate chain, the protocol version, the cipher suite and whether the
/// session was resumed.
pub struct TlsStream<S> {
    inner: tokio_rustls::TlsStream<S>,
}

impl<S> TlsStream<S> {
    pub(crate) fn new(inner: impl Into<tokio_rustls::TlsStream<S>>) -> Self {
        Self {
            inner: inner.into(),
        }
    }

    /// The transport the session runs over, for example to read the peer
    /// address of a TCP stream. Bytes must not be read from or written to it
    /// directly.
    pub fn get_ref(&self) -> &S {
        self.inner.get_ref().0
    }

    /// The certificate chain the peer presented, leaf first, or `None` when
    /// it presented none.
    pub fn peer_certificates(&self) -> Option<&[CertificateDer<'static>]> {
        self.state().peer_certificates()
    }

    /// The negotiated protocol version.
    pub fn protocol_version(&self) -> Option<TlsVersion> {
        match self.state().protocol_version()? {
            rustls::ProtocolVersion::TLSv1_2 => Some(TlsVersion::Tls12),
            rustls::ProtocolVersion::TLSv1_3 => Some(TlsVersion::Tls13),
            _ => None,
        }
    }

    /// The negotiated cipher suite, by its IANA code point.
    pub fn negotiated_cipher_suite(&self) -> Option<rustls::CipherSuite> {
        self.state().negotiated_cipher_suite().map(|s| s.suite())
    }

    /// Whether the handshake resumed an earlier session rather than running
    /// in full.
    pub fn is_resumed(&self) -> bool {
        self.state().handshake_kind() == Some(rustls::HandshakeKind::Resumed)
    }

    pub(crate) fn state(&self) -> &rustls::CommonState {
        self.inner.get_ref().1
    }
}

impl<S> std::fmt::Debug for TlsStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsStream")
            .field("protocol_version", &self.protocol_version())
            .field("cipher_suite", &self.negotiated_cipher_suite())
            .finish_non_exhaustive()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
