//! The error type of the IEC 62351-3 TLS integration layer.

use thiserror::Error;

/// An error raised by the TLS layer.
///
/// Library code does not panic; every failure path returns
/// `Result<_, TlsError>`.
#[derive(Debug, Error)]
pub enum TlsError {
    /// The TLS handshake failed inside rustls.
    #[error("TLS handshake failed: {0}")]
    Handshake(#[from] rustls::Error),

    /// A certificate or key could not be loaded; PEM or DER parsing failed.
    #[error("certificate/key load error: {0}")]
    CertLoad(String),

    /// The requested cipher suite is not in the IEC 62351-3 whitelist.
    #[error("cipher suite not in IEC 62351-3 whitelist: {0}")]
    CipherUnsupported(String),

    /// The requested TLS version is not supported; the floor is TLS 1.2.
    #[error("TLS version not supported: {0}")]
    VersionUnsupported(String),

    /// A TCP connect, read or write failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Certificate verification failed, either in chain validation or in the
    /// allow-only-known check.
    #[error("certificate verification failed: {0}")]
    Verification(String),

    /// A builder argument failed the validation performed by `build_client`
    /// or `build_server`.
    #[error("TLS config validation error: {0}")]
    Validation(String),

    /// A CRL operation failed.
    #[error("CRL error: {0}")]
    CrlError(String),
}
