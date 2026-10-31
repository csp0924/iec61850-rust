//! The error type of the IEC 62351-3 TLS integration layer.

use thiserror::Error;

/// An error raised by the TLS layer.
///
/// Library code does not panic; every failure path returns
/// `Result<_, TlsError>`. A failed handshake is classified by the rustls
/// error behind it: [`Self::Verification`], [`Self::CipherUnsupported`] and
/// [`Self::VersionUnsupported`] for the three causes they name,
/// [`Self::Handshake`] for any other TLS error, such as an alert from the
/// peer, and [`Self::Io`] when the transport failed with no TLS error.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TlsError {
    /// The handshake failed for a TLS reason the other variants do not name,
    /// for example a fatal alert the peer sent.
    #[error("TLS handshake failed: {0}")]
    Handshake(rustls::Error),

    /// A certificate or key could not be loaded; PEM or DER parsing failed.
    #[error("certificate/key load error: {0}")]
    CertLoad(String),

    /// The handshake found no cipher suite or key exchange group that both
    /// sides allow.
    #[error("no cipher suite in common with the peer: {0}")]
    CipherUnsupported(rustls::Error),

    /// The handshake found no TLS version that both sides allow.
    #[error("no TLS version in common with the peer: {0}")]
    VersionUnsupported(rustls::Error),

    /// The transport failed with no TLS error behind it, for example a TCP
    /// connection closed during the handshake.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The peer certificate was rejected, by chain validation, by the
    /// allow-only-known check or by any other verification step, or the peer
    /// presented no certificate where one is required.
    #[error("certificate verification failed: {0}")]
    Verification(rustls::Error),

    /// A builder argument failed the validation performed by `build_client`
    /// or `build_server`.
    #[error("TLS config validation error: {0}")]
    Validation(String),

    /// A CRL operation failed.
    #[error("CRL error: {0}")]
    CrlError(String),
}

/// The cause a rustls handshake error names, shared by the classification of
/// [`TlsError`] and the events a failed handshake raises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HandshakeCause {
    /// The peer certificate was rejected, or none was presented where one is
    /// required.
    Verification,
    /// No cipher suite or key exchange group in common.
    Cipher,
    /// No TLS version in common.
    Version,
    /// Any other TLS error.
    Other,
}

/// Names the cause of a rustls handshake error.
pub(crate) fn handshake_cause(err: &rustls::Error) -> HandshakeCause {
    use rustls::{Error as E, PeerIncompatible as P};
    match err {
        E::InvalidCertificate(_) | E::NoCertificatesPresented => HandshakeCause::Verification,
        E::PeerIncompatible(P::NoCipherSuitesInCommon | P::NoKxGroupsInCommon) => {
            HandshakeCause::Cipher
        }
        E::PeerIncompatible(
            P::Tls12NotOffered
            | P::Tls12NotOfferedOrEnabled
            | P::SignatureAlgorithmsExtensionRequired
            | P::SupportedVersionsExtensionRequired
            | P::ServerDoesNotSupportTls12Or13
            | P::ServerTlsVersionIsDisabledByOurConfig,
        ) => HandshakeCause::Version,
        _ => HandshakeCause::Other,
    }
}

impl From<rustls::Error> for TlsError {
    /// Classifies a rustls error as the variant naming its cause.
    fn from(err: rustls::Error) -> Self {
        match handshake_cause(&err) {
            HandshakeCause::Verification => Self::Verification(err),
            HandshakeCause::Cipher => Self::CipherUnsupported(err),
            HandshakeCause::Version => Self::VersionUnsupported(err),
            HandshakeCause::Other => Self::Handshake(err),
        }
    }
}

impl TlsError {
    /// Classifies the error a failed handshake returned: the rustls error
    /// it carries, through `From<rustls::Error>`, or [`Self::Io`] when it
    /// carries none.
    pub(crate) fn from_handshake(err: std::io::Error) -> Self {
        match err
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        {
            Some(tls_err) => Self::from(tls_err.clone()),
            None => Self::Io(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{CertificateError, Error as E, PeerIncompatible as P};

    #[test]
    fn rustls_errors_are_classified_by_cause() {
        assert!(matches!(
            TlsError::from(E::InvalidCertificate(CertificateError::Expired)),
            TlsError::Verification(_)
        ));
        assert!(matches!(
            TlsError::from(E::NoCertificatesPresented),
            TlsError::Verification(_)
        ));
        assert!(matches!(
            TlsError::from(E::PeerIncompatible(P::NoCipherSuitesInCommon)),
            TlsError::CipherUnsupported(_)
        ));
        assert!(matches!(
            TlsError::from(E::PeerIncompatible(P::ServerDoesNotSupportTls12Or13)),
            TlsError::VersionUnsupported(_)
        ));
        assert!(matches!(
            TlsError::from(E::AlertReceived(rustls::AlertDescription::HandshakeFailure)),
            TlsError::Handshake(_)
        ));
    }

    #[test]
    fn a_handshake_error_without_a_tls_cause_stays_an_io_error() {
        let err = TlsError::from_handshake(std::io::ErrorKind::UnexpectedEof.into());
        assert!(matches!(err, TlsError::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof));
    }

    #[test]
    fn a_handshake_error_with_a_tls_cause_is_classified_by_it() {
        let io = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            E::PeerIncompatible(P::NoKxGroupsInCommon),
        );
        assert!(matches!(
            TlsError::from_handshake(io),
            TlsError::CipherUnsupported(_)
        ));
    }
}
