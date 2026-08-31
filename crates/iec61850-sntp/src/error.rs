//! Errors raised by the SNTP client and server.

use std::io;

/// An error raised by the SNTP client or server.
#[derive(Debug, thiserror::Error)]
pub enum SntpError {
    /// The datagram is shorter than the 48 bytes RFC 4330 defines, excluding
    /// the optional authenticator.
    #[error("invalid SNTP packet length: got {got}, expected at least {expected}")]
    InvalidLength {
        /// Length actually received.
        got: usize,
        /// Minimum length required.
        expected: usize,
    },

    /// The LI, VN or Mode field carries a value the decoder rejects.
    #[error("invalid SNTP header field: {0}")]
    InvalidHeader(&'static str),

    /// The request mode is neither client (3) nor symmetric active (1); the
    /// server answers only those two.
    #[error("unexpected SNTP mode in request: {0}")]
    UnexpectedMode(u8),

    /// No NTP timestamp can be formed from the system clock: it reads before
    /// the Unix epoch (1970-01-01), or adding the 2208988800 s offset that
    /// separates the NTP epoch (1900-01-01) from it would overflow.
    #[error("system time cannot be expressed as an NTP timestamp")]
    TimeBeforeEpoch,

    /// A socket bind, receive or send failed.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}
