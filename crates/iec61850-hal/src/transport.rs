//! `AsyncTransport`, the async byte-stream trait the MMS layer is written
//! against.
//!
//! Taking `T: AsyncTransport` instead of binding to `tokio::net::TcpStream`
//! keeps changes in an external ecosystem trait out of the layers above.
//! Under feature `transport-tokio` a blanket implementation covers every
//! `tokio::io::AsyncRead + AsyncWrite + Unpin + Send`, so existing tokio
//! types satisfy the trait unchanged.
//!
//! The methods are `async fn` in a trait, stable since Rust 1.75. The trait
//! is therefore not object safe; every caller is generic over
//! `T: AsyncTransport`, and dynamic dispatch would need an adapter.

use crate::compat::prelude::*;
use core::fmt;

/// Category of an I/O failure, available without `std`.
///
/// Mirrors the `std::io::ErrorKind` categories a byte-stream transport
/// produces, so a no_std backend can classify its own errors the same way a
/// std backend does. Under `std` the two convert into each other; a std kind
/// with no counterpart here becomes `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IoErrorKind {
    /// An entity was not found, such as a host name with no address.
    NotFound,
    /// The operation lacked the necessary privileges.
    PermissionDenied,
    /// The remote host refused the connection.
    ConnectionRefused,
    /// The remote host reset the connection.
    ConnectionReset,
    /// The remote host is not reachable.
    HostUnreachable,
    /// The network containing the remote host is not reachable.
    NetworkUnreachable,
    /// The connection was aborted by the local side or the network.
    ConnectionAborted,
    /// The operation needs a connection that does not exist.
    NotConnected,
    /// The local address is already in use.
    AddrInUse,
    /// The requested local address is not available.
    AddrNotAvailable,
    /// The local network is down.
    NetworkDown,
    /// The write half was closed by the peer.
    BrokenPipe,
    /// The operation would block on a non-blocking stream.
    WouldBlock,
    /// An argument passed to the backend was invalid.
    InvalidInput,
    /// The data read was not valid for the operation, such as a TLS record
    /// that fails to decrypt or a fatal TLS alert.
    InvalidData,
    /// The operation timed out.
    TimedOut,
    /// A write returned zero bytes written.
    WriteZero,
    /// The operation was interrupted.
    Interrupted,
    /// The operation is not supported by the backend.
    Unsupported,
    /// The stream ended before the expected number of bytes was read.
    UnexpectedEof,
    /// The backend ran out of memory.
    OutOfMemory,
    /// Any failure no other category describes.
    Other,
}

impl IoErrorKind {
    /// Returns a short lowercase description, as used by `Display`.
    pub fn as_str(self) -> &'static str {
        match self {
            IoErrorKind::NotFound => "entity not found",
            IoErrorKind::PermissionDenied => "permission denied",
            IoErrorKind::ConnectionRefused => "connection refused",
            IoErrorKind::ConnectionReset => "connection reset",
            IoErrorKind::HostUnreachable => "host unreachable",
            IoErrorKind::NetworkUnreachable => "network unreachable",
            IoErrorKind::ConnectionAborted => "connection aborted",
            IoErrorKind::NotConnected => "not connected",
            IoErrorKind::AddrInUse => "address in use",
            IoErrorKind::AddrNotAvailable => "address not available",
            IoErrorKind::NetworkDown => "network down",
            IoErrorKind::BrokenPipe => "broken pipe",
            IoErrorKind::WouldBlock => "operation would block",
            IoErrorKind::InvalidInput => "invalid input parameter",
            IoErrorKind::InvalidData => "invalid data",
            IoErrorKind::TimedOut => "timed out",
            IoErrorKind::WriteZero => "write zero",
            IoErrorKind::Interrupted => "operation interrupted",
            IoErrorKind::Unsupported => "unsupported",
            IoErrorKind::UnexpectedEof => "unexpected end of file",
            IoErrorKind::OutOfMemory => "out of memory",
            IoErrorKind::Other => "other error",
        }
    }
}

impl fmt::Display for IoErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(feature = "std")]
impl From<std::io::ErrorKind> for IoErrorKind {
    fn from(kind: std::io::ErrorKind) -> Self {
        use std::io::ErrorKind as K;
        match kind {
            K::NotFound => IoErrorKind::NotFound,
            K::PermissionDenied => IoErrorKind::PermissionDenied,
            K::ConnectionRefused => IoErrorKind::ConnectionRefused,
            K::ConnectionReset => IoErrorKind::ConnectionReset,
            K::HostUnreachable => IoErrorKind::HostUnreachable,
            K::NetworkUnreachable => IoErrorKind::NetworkUnreachable,
            K::ConnectionAborted => IoErrorKind::ConnectionAborted,
            K::NotConnected => IoErrorKind::NotConnected,
            K::AddrInUse => IoErrorKind::AddrInUse,
            K::AddrNotAvailable => IoErrorKind::AddrNotAvailable,
            K::NetworkDown => IoErrorKind::NetworkDown,
            K::BrokenPipe => IoErrorKind::BrokenPipe,
            K::WouldBlock => IoErrorKind::WouldBlock,
            K::InvalidInput => IoErrorKind::InvalidInput,
            K::InvalidData => IoErrorKind::InvalidData,
            K::TimedOut => IoErrorKind::TimedOut,
            K::WriteZero => IoErrorKind::WriteZero,
            K::Interrupted => IoErrorKind::Interrupted,
            K::Unsupported => IoErrorKind::Unsupported,
            K::UnexpectedEof => IoErrorKind::UnexpectedEof,
            K::OutOfMemory => IoErrorKind::OutOfMemory,
            _ => IoErrorKind::Other,
        }
    }
}

#[cfg(feature = "std")]
impl From<IoErrorKind> for std::io::ErrorKind {
    fn from(kind: IoErrorKind) -> Self {
        use std::io::ErrorKind as K;
        match kind {
            IoErrorKind::NotFound => K::NotFound,
            IoErrorKind::PermissionDenied => K::PermissionDenied,
            IoErrorKind::ConnectionRefused => K::ConnectionRefused,
            IoErrorKind::ConnectionReset => K::ConnectionReset,
            IoErrorKind::HostUnreachable => K::HostUnreachable,
            IoErrorKind::NetworkUnreachable => K::NetworkUnreachable,
            IoErrorKind::ConnectionAborted => K::ConnectionAborted,
            IoErrorKind::NotConnected => K::NotConnected,
            IoErrorKind::AddrInUse => K::AddrInUse,
            IoErrorKind::AddrNotAvailable => K::AddrNotAvailable,
            IoErrorKind::NetworkDown => K::NetworkDown,
            IoErrorKind::BrokenPipe => K::BrokenPipe,
            IoErrorKind::WouldBlock => K::WouldBlock,
            IoErrorKind::InvalidInput => K::InvalidInput,
            IoErrorKind::InvalidData => K::InvalidData,
            IoErrorKind::TimedOut => K::TimedOut,
            IoErrorKind::WriteZero => K::WriteZero,
            IoErrorKind::Interrupted => K::Interrupted,
            IoErrorKind::Unsupported => K::Unsupported,
            IoErrorKind::UnexpectedEof => K::UnexpectedEof,
            IoErrorKind::OutOfMemory => K::OutOfMemory,
            IoErrorKind::Other => K::Other,
        }
    }
}

/// An error raised by the transport layer.
///
/// Free of `std::io::Error`, so a no_std backend can produce it, yet it keeps
/// the cause: the [`IoErrorKind`] of the failure and, when the backend has one,
/// the text of the underlying error, such as the fatal alert a TLS peer sent.
/// Under `std`, `From<std::io::Error>` fills both in.
///
/// The `Io` and `Closed` variants are `#[non_exhaustive]`: a backend builds
/// them with [`TransportError::io`], [`TransportError::closed`] and
/// [`TransportError::with_detail`], and a match names the fields it reads
/// followed by `..`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportError {
    /// A read or a write failed.
    #[non_exhaustive]
    Io {
        /// Category of the failure.
        kind: IoErrorKind,
        /// Text of the underlying error, when the backend has one.
        detail: Option<String>,
    },
    /// The peer closed the connection, or an unexpected EOF was reached.
    #[non_exhaustive]
    Closed {
        /// How the close was observed: `UnexpectedEof` for an end of stream,
        /// `ConnectionReset`, `ConnectionAborted` or `BrokenPipe` otherwise.
        kind: IoErrorKind,
    },
    /// The operation timed out.
    Timeout,
}

impl TransportError {
    /// Builds a failed read or write of the given category, with no detail.
    pub fn io(kind: IoErrorKind) -> Self {
        TransportError::Io { kind, detail: None }
    }

    /// Builds a closed connection observed as `kind`.
    pub fn closed(kind: IoErrorKind) -> Self {
        TransportError::Closed { kind }
    }

    /// Attaches the text of the underlying error to an `Io` failure.
    ///
    /// The other variants carry no detail and are returned unchanged.
    pub fn with_detail(self, text: impl Into<String>) -> Self {
        match self {
            TransportError::Io { kind, .. } => TransportError::Io {
                kind,
                detail: Some(text.into()),
            },
            other => other,
        }
    }

    /// Returns the category of the failure; `Timeout` reports `TimedOut`.
    pub fn kind(&self) -> IoErrorKind {
        match self {
            TransportError::Io { kind, .. } | TransportError::Closed { kind } => *kind,
            TransportError::Timeout => IoErrorKind::TimedOut,
        }
    }

    /// Returns the text of the underlying error, if the backend supplied one.
    pub fn detail(&self) -> Option<&str> {
        match self {
            TransportError::Io { detail, .. } => detail.as_deref(),
            _ => None,
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Io { kind, detail } => {
                write!(f, "transport IO error ({kind})")?;
                if let Some(detail) = detail {
                    write!(f, ": {detail}")?;
                }
                Ok(())
            }
            TransportError::Closed { kind } => write!(f, "transport closed ({kind})"),
            TransportError::Timeout => f.write_str("transport timeout"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TransportError {}

#[cfg(feature = "std")]
impl From<std::io::Error> for TransportError {
    fn from(e: std::io::Error) -> Self {
        use std::io::ErrorKind;
        let kind = IoErrorKind::from(e.kind());
        match e.kind() {
            ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::BrokenPipe => TransportError::closed(kind),
            ErrorKind::TimedOut => TransportError::Timeout,
            _ => TransportError::io(kind).with_detail(e.to_string()),
        }
    }
}

/// Async byte-stream transport for the layers above.
///
/// Semantics follow `tokio::io::AsyncRead` and `AsyncWrite`: `read` returns
/// the number of bytes read and 0 means EOF, `write_all` returns only once
/// the whole buffer is written, and `close` is a graceful shutdown.
///
/// ```ignore
/// async fn handshake<T: AsyncTransport>(transport: &mut T) -> Result<(), TransportError> {
///     transport.write_all(b"INIT\n").await?;
///     let mut buf = [0u8; 64];
///     let n = transport.read(&mut buf).await?;
///     if n == 0 { return Err(TransportError::Closed); }
///     Ok(())
/// }
/// ```
///
/// The trait is defined twice, once per environment, differing only in
/// `Send`. This definition applies under `std` and requires `Send` on the
/// supertrait and on all three returned futures: a multi-threaded runtime
/// moves futures between workers, and code that spawns a task from a generic
/// context cannot restore the guarantee at the call site, because `T: Send`
/// does not imply that `T`'s methods return `Send` futures and stable Rust
/// has no return-type notation to say so. The no_std definition below has no
/// `Send` anywhere: an embedded target runs a single executor on one core and
/// its only usable backend is not `Send` by construction, so the bound would
/// make that path unimplementable. Method signatures and semantics are
/// identical either way, so caller code never branches on the environment.
#[cfg(feature = "std")]
pub trait AsyncTransport: Send {
    /// Reads at most `buf.len()` bytes into `buf` and returns how many were
    /// read. `Ok(0)` means EOF, that is the peer closed the connection.
    fn read(
        &mut self,
        buf: &mut [u8],
    ) -> impl core::future::Future<Output = Result<usize, TransportError>> + Send;

    /// Writes all of `buf`; the implementation loops over partial writes.
    fn write_all(
        &mut self,
        buf: &[u8],
    ) -> impl core::future::Future<Output = Result<(), TransportError>> + Send;

    /// Graceful shutdown of the write half; a read may still observe the
    /// peer's close.
    fn close(&mut self) -> impl core::future::Future<Output = Result<(), TransportError>> + Send;
}

/// The no_std form: same names and signatures as the `std` definition, with
/// no `Send` guarantee. See that definition for the reasoning.
#[cfg(not(feature = "std"))]
pub trait AsyncTransport {
    /// Reads at most `buf.len()` bytes into `buf` and returns how many were
    /// read. `Ok(0)` means EOF, that is the peer closed the connection.
    fn read(
        &mut self,
        buf: &mut [u8],
    ) -> impl core::future::Future<Output = Result<usize, TransportError>>;

    /// Writes all of `buf`; the implementation loops over partial writes.
    fn write_all(
        &mut self,
        buf: &[u8],
    ) -> impl core::future::Future<Output = Result<(), TransportError>>;

    /// Graceful shutdown of the write half; a read may still observe the
    /// peer's close.
    fn close(&mut self) -> impl core::future::Future<Output = Result<(), TransportError>>;
}

// --- std backend --------------------------------------------------------------
//
// Blanket impl over tokio AsyncRead + AsyncWrite, so `tokio::net::TcpStream`
// and similar types satisfy `AsyncTransport` without an adapter.

#[cfg(feature = "transport-tokio")]
impl<T> AsyncTransport for T
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        use tokio::io::AsyncReadExt;
        AsyncReadExt::read(self, buf)
            .await
            .map_err(TransportError::from)
    }

    async fn write_all(&mut self, buf: &[u8]) -> Result<(), TransportError> {
        use tokio::io::AsyncWriteExt;
        AsyncWriteExt::write_all(self, buf)
            .await
            .map_err(TransportError::from)
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        use tokio::io::AsyncWriteExt;
        AsyncWriteExt::shutdown(self)
            .await
            .map_err(TransportError::from)
    }
}

// --- embassy / embedded-io-async backend -------------------------------------
//
// There is deliberately no blanket impl for `T: embedded_io_async::Read +
// Write`. Its trait methods are `async fn`, so the trait does not promise the
// returned futures are `Send`, and stable Rust has no return-type notation to
// add that at the bound. A blanket impl would be possible for the no_std
// `AsyncTransport`, which carries no `Send`, but it would take the mapping of
// backend errors onto `TransportError` out of the user's hands, and embedded
// backends classify errors very differently.
//
// embassy-net sockets are not `Send`: `Stack<'d>` holds `&'d RefCell<Inner>`,
// `&T: Send` requires `T: Sync`, and `RefCell` is never `Sync`. That follows
// from the single-executor design and no feature switches it, which is why
// `AsyncTransport` has a separate no_std definition with no `Send` bound; a
// `!Send` future is perfectly legal under a single-core executor.
//
// Sketch of an embedded implementation, against the no_std signatures; note
// the absence of `+ Send`:
//
// ```ignore
// pub struct MySocket(embassy_net::tcp::TcpSocket<'static>);
//
// impl iec61850_hal::transport::AsyncTransport for MySocket {
//     fn read(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<usize, TransportError>> {
//         async move {
//             embedded_io_async::Read::read(&mut self.0, buf)
//                 .await
//                 .map_err(|_| TransportError::io(IoErrorKind::Other))
//         }
//     }
//     // write_all and close follow the same shape
// }
// ```

#[cfg(all(test, feature = "transport-tokio"))]
mod tests_tokio {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn duplex_round_trip() {
        let (mut a, mut b) = duplex(64);
        AsyncTransport::write_all(&mut a, b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        let n = AsyncTransport::read(&mut b, &mut buf).await.unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test]
    async fn read_eof_returns_zero() {
        let (a, mut b) = duplex(64);
        drop(a);
        let mut buf = [0u8; 8];
        let n = AsyncTransport::read(&mut b, &mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn io_error_maps_closed() {
        let e = std::io::Error::from(std::io::ErrorKind::UnexpectedEof);
        assert_eq!(
            TransportError::from(e),
            TransportError::closed(IoErrorKind::UnexpectedEof)
        );
    }

    #[test]
    fn a_reset_keeps_its_kind() {
        let e = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
        let t = TransportError::from(e);
        assert_eq!(t, TransportError::closed(IoErrorKind::ConnectionReset));
        assert_eq!(t.kind(), IoErrorKind::ConnectionReset);
    }

    #[test]
    fn an_io_error_keeps_its_kind_and_text() {
        let e = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "received fatal alert: CertificateRequired",
        );
        let t = TransportError::from(e);
        assert_eq!(t.kind(), IoErrorKind::InvalidData);
        assert_eq!(
            t.detail(),
            Some("received fatal alert: CertificateRequired")
        );
        assert_eq!(
            t.to_string(),
            "transport IO error (invalid data): received fatal alert: CertificateRequired"
        );
    }

    #[test]
    fn a_kind_without_counterpart_becomes_other() {
        let e = std::io::Error::from(std::io::ErrorKind::QuotaExceeded);
        assert_eq!(TransportError::from(e).kind(), IoErrorKind::Other);
    }

    #[test]
    fn kinds_convert_both_ways() {
        for kind in [
            IoErrorKind::ConnectionRefused,
            IoErrorKind::InvalidData,
            IoErrorKind::UnexpectedEof,
            IoErrorKind::NetworkDown,
        ] {
            assert_eq!(IoErrorKind::from(std::io::ErrorKind::from(kind)), kind);
        }
    }

    #[test]
    fn detail_attaches_only_to_io_failures() {
        let t = TransportError::closed(IoErrorKind::BrokenPipe).with_detail("ignored");
        assert_eq!(t.detail(), None);
        let t = TransportError::io(IoErrorKind::Other).with_detail("x");
        assert_eq!(t.detail(), Some("x"));
    }

    #[test]
    fn io_error_maps_timeout() {
        let e = std::io::Error::from(std::io::ErrorKind::TimedOut);
        assert_eq!(TransportError::from(e), TransportError::Timeout);
    }
}
