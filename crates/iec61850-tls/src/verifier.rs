//! Certificate verifier wrappers that add the IEC 62351-3 rules on top of the
//! rustls chain validators.
//!
//! Allow-only-known certificates: once the inner verifier accepts the chain,
//! the leaf certificate DER is compared against the configured list. An empty
//! list rejects rather than accepts, because a whitelist that matches nothing
//! must not mean "match everything".
//!
//! Ignore validity time: `Expired`, `NotValidYet` and their `*Context`
//! variants are downgraded to a warning event when validity-time checking is
//! off. Every other chain error still propagates.

use std::sync::Arc;

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
    DigitallySignedStruct, DistinguishedName, Error as RustlsError, SignatureScheme,
};

use crate::event::{TlsEventCode, TlsEventHandler, TlsEventLevel};

// -----------------------------------------------------------------------------
// AllowOnlyKnownCertsServerVerifier
// -----------------------------------------------------------------------------

/// Server-side allow-only-known-certificates wrapper.
///
/// Runs the inner chain validation first. When `allow_only_known` is set, the
/// leaf certificate DER must then appear in `known_peer_certs`: an empty list
/// rejects, and an absent leaf rejects and raises an incident event.
pub struct AllowOnlyKnownCertsServerVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    allow_only_known: bool,
    /// DER bytes of the certificates a peer is allowed to present.
    known_peer_certs: Vec<CertificateDer<'static>>,
    event_handler: Arc<dyn TlsEventHandler>,
}

impl AllowOnlyKnownCertsServerVerifier {
    /// Wraps `inner` with the allow-only-known check.
    pub fn new(
        inner: Arc<dyn ServerCertVerifier>,
        allow_only_known: bool,
        known_peer_certs: Vec<CertificateDer<'static>>,
        event_handler: Arc<dyn TlsEventHandler>,
    ) -> Self {
        Self {
            inner,
            allow_only_known,
            known_peer_certs,
            event_handler,
        }
    }

    /// Compares the leaf against the list in constant time, so the check
    /// leaks no timing signal.
    fn cert_in_list(&self, leaf: &CertificateDer<'_>) -> bool {
        self.known_peer_certs
            .iter()
            .any(|known| subtle_eq(known.as_ref(), leaf.as_ref()))
    }
}

impl std::fmt::Debug for AllowOnlyKnownCertsServerVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AllowOnlyKnownCertsServerVerifier")
            .field("allow_only_known", &self.allow_only_known)
            .field("known_peer_certs_count", &self.known_peer_certs.len())
            .finish()
    }
}

impl ServerCertVerifier for AllowOnlyKnownCertsServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // Strict chain validation runs first.
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        if self.allow_only_known
            && (self.known_peer_certs.is_empty() || !self.cert_in_list(end_entity))
        {
            // An empty list rejects: a whitelist that matches nothing is not
            // the same as allowing every peer.
            self.event_handler.on_event(
                TlsEventLevel::Incident,
                TlsEventCode::AlmCertNotConfigured,
                "server cert not in allow-only-known list; connection rejected",
            );
            tracing::warn!(
                "rejecting server leaf cert, not in the known list (known_count={})",
                self.known_peer_certs.len()
            );
            return Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// -----------------------------------------------------------------------------
// AllowOnlyKnownCertsClientVerifier
// -----------------------------------------------------------------------------

/// Client-side allow-only-known-certificates wrapper.
///
/// Behaves exactly like the server-side wrapper, on the client certificate.
pub struct AllowOnlyKnownCertsClientVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    allow_only_known: bool,
    known_peer_certs: Vec<CertificateDer<'static>>,
    event_handler: Arc<dyn TlsEventHandler>,
}

impl AllowOnlyKnownCertsClientVerifier {
    /// Wraps `inner` with the allow-only-known check.
    pub fn new(
        inner: Arc<dyn ClientCertVerifier>,
        allow_only_known: bool,
        known_peer_certs: Vec<CertificateDer<'static>>,
        event_handler: Arc<dyn TlsEventHandler>,
    ) -> Self {
        Self {
            inner,
            allow_only_known,
            known_peer_certs,
            event_handler,
        }
    }

    fn cert_in_list(&self, leaf: &CertificateDer<'_>) -> bool {
        self.known_peer_certs
            .iter()
            .any(|known| subtle_eq(known.as_ref(), leaf.as_ref()))
    }
}

impl std::fmt::Debug for AllowOnlyKnownCertsClientVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AllowOnlyKnownCertsClientVerifier")
            .field("allow_only_known", &self.allow_only_known)
            .field("known_peer_certs_count", &self.known_peer_certs.len())
            .finish()
    }
}

impl ClientCertVerifier for AllowOnlyKnownCertsClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    /// Delegates to the inner verifier. When that one was built with
    /// `allow_unauthenticated()`, client authentication is offered but not
    /// mandatory, so a peer without a client certificate can still connect.
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    /// Delegates to the inner verifier; `allow_unauthenticated()` makes this
    /// return false.
    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        // Strict chain validation runs first.
        self.inner
            .verify_client_cert(end_entity, intermediates, now)?;

        if self.allow_only_known
            && (self.known_peer_certs.is_empty() || !self.cert_in_list(end_entity))
        {
            self.event_handler.on_event(
                TlsEventLevel::Incident,
                TlsEventCode::AlmCertNotConfigured,
                "client cert not in allow-only-known list; connection rejected",
            );
            tracing::warn!(
                "rejecting client leaf cert, not in the known list (known_count={})",
                self.known_peer_certs.len()
            );
            return Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }

        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// -----------------------------------------------------------------------------
// IgnoreValidityTimeServerVerifier
// -----------------------------------------------------------------------------

/// Server verifier that can ignore certificate validity time.
///
/// Only `Expired` and `NotValidYet`, including their `*Context` variants, are
/// downgraded to a warning event. Every other chain error, such as a bad
/// signature, a revoked certificate or an unknown CA, still rejects. That is
/// what IEC 62351-3 requires: switching validity-time checking off relaxes the
/// expiry check and nothing else.
pub struct IgnoreValidityTimeServerVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    /// `false` keeps the strict default; `true` ignores validity time and is
    /// intended for development only.
    ignore_validity_time: bool,
    event_handler: Arc<dyn TlsEventHandler>,
}

impl IgnoreValidityTimeServerVerifier {
    /// Wraps `inner` with the validity-time downgrade.
    pub fn new(
        inner: Arc<dyn ServerCertVerifier>,
        ignore_validity_time: bool,
        event_handler: Arc<dyn TlsEventHandler>,
    ) -> Self {
        Self {
            inner,
            ignore_validity_time,
            event_handler,
        }
    }
}

impl std::fmt::Debug for IgnoreValidityTimeServerVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IgnoreValidityTimeServerVerifier")
            .field("ignore_validity_time", &self.ignore_validity_time)
            .finish()
    }
}

/// Reports whether a rustls error is validity-time related, and may therefore
/// be downgraded when validity-time checking is off.
fn is_validity_time_error(err: &RustlsError) -> bool {
    matches!(
        err,
        RustlsError::InvalidCertificate(rustls::CertificateError::Expired)
            | RustlsError::InvalidCertificate(rustls::CertificateError::ExpiredContext { .. })
            | RustlsError::InvalidCertificate(rustls::CertificateError::NotValidYet)
            | RustlsError::InvalidCertificate(rustls::CertificateError::NotValidYetContext { .. })
    )
}

impl ServerCertVerifier for IgnoreValidityTimeServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(v) => Ok(v),
            Err(ref e) if self.ignore_validity_time && is_validity_time_error(e) => {
                // Downgrade to a warning and let the connection through.
                let (code, msg) = if matches!(
                    e,
                    RustlsError::InvalidCertificate(rustls::CertificateError::NotValidYet)
                        | RustlsError::InvalidCertificate(
                            rustls::CertificateError::NotValidYetContext { .. }
                        )
                ) {
                    (
                        TlsEventCode::WrnCertNotYetValid,
                        "server cert not yet valid; time_validation=false, allowing",
                    )
                } else {
                    (
                        TlsEventCode::WrnCertExpired,
                        "server cert expired; time_validation=false, allowing",
                    )
                };
                self.event_handler
                    .on_event(TlsEventLevel::Warning, code, msg);
                tracing::warn!("{}", msg);
                Ok(ServerCertVerified::assertion())
            }
            Err(e) => Err(e),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// -----------------------------------------------------------------------------
// Constant-time byte comparison
// -----------------------------------------------------------------------------

/// Compares byte slices in constant time.
///
/// Certificate DER comparison is not a high-value timing target, but the
/// constant-time form matches the convention of the surrounding crypto code.
fn subtle_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // XOR fold, so the comparison never short-circuits.
    let diff: u8 = a
        .iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y));
    diff == 0
}
