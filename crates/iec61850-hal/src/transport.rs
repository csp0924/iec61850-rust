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

use core::fmt;

/// An error raised by the transport layer.
///
/// Deliberately coarse and free of `std::io::Error`, so a no_std backend can
/// produce it. Under `std`, `From<std::io::Error>` maps an I/O error onto
/// these categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// A read or a write failed.
    Io,
    /// The peer closed the connection, or an unexpected EOF was reached.
    Closed,
    /// The operation timed out.
    Timeout,
    /// Any other failure. Reserved so that adding a variant later is not a
    /// breaking change.
    Other,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            TransportError::Io => "transport IO error",
            TransportError::Closed => "transport closed",
            TransportError::Timeout => "transport timeout",
            TransportError::Other => "transport other error",
        };
        f.write_str(msg)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TransportError {}

#[cfg(feature = "std")]
impl From<std::io::Error> for TransportError {
    fn from(e: std::io::Error) -> Self {
        use std::io::ErrorKind;
        match e.kind() {
            ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::BrokenPipe => TransportError::Closed,
            ErrorKind::TimedOut => TransportError::Timeout,
            _ => TransportError::Io,
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
//             embedded_io_async::Read::read(&mut self.0, buf).await.map_err(|_| TransportError::Io)
//         }
//     }
//     // write_all and close follow the same shape
// }
// ```

// Keeps the dependency type-resolved in an embedded build, so enabling the
// feature without otherwise naming the crate is not a warning.
#[cfg(feature = "transport-embassy")]
#[allow(unused_imports)]
use embedded_io_async as _used;

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
        assert_eq!(TransportError::from(e), TransportError::Closed);
    }

    #[test]
    fn io_error_maps_timeout() {
        let e = std::io::Error::from(std::io::ErrorKind::TimedOut);
        assert_eq!(TransportError::from(e), TransportError::Timeout);
    }
}
