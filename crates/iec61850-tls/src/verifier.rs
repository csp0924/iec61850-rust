//! Certificate verifier wrappers that add the IEC 62351-3 rules on top of the
//! rustls chain validators.
//!
//! Allow-only-known certificates: once the inner verifier accepts the chain,
//! the leaf certificate DER is compared against the configured list. An empty
//! list rejects rather than accepts, because a whitelist that matches nothing
//! must not mean "match everything".
//!
//! Ignore validity time: when validity-time checking is off, a certificate
//! that has expired or is not valid yet is verified again at a time inside its
//! validity period, and the outcome of that verification decides. Every other
//! chain error, the allow-only-known check included, still applies.

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
// Validity-time override
// -----------------------------------------------------------------------------

/// Upper bound on the verifications one validity-time override may run.
///
/// Each run moves the validation time into the validity period of one more
/// certificate of the chain, so the bound caps the chain length the override
/// can cover.
const MAX_VALIDITY_TIME_RUNS: usize = 8;

/// The validity-time errors one override encountered.
#[derive(Debug, Default, Clone, Copy)]
struct ValidityTimeFindings {
    expired: bool,
    not_yet_valid: bool,
}

/// Runs `verify` at `now`, and again at a time inside the validity period of
/// any certificate the previous run found expired or not yet valid.
///
/// The result is the outcome of the last run, so every check other than
/// validity time, such as the signature chain, revocation, the name and the
/// allow-only-known list, still decides. An expiry error without its
/// `*Context` data carries no usable time and is returned unchanged.
fn verify_ignoring_validity_time<T>(
    now: UnixTime,
    mut verify: impl FnMut(UnixTime) -> Result<T, RustlsError>,
) -> Result<(T, ValidityTimeFindings), RustlsError> {
    let mut findings = ValidityTimeFindings::default();
    let mut at = now;
    let mut runs = 0;
    loop {
        runs += 1;
        let err = match verify(at) {
            Ok(v) => return Ok((v, findings)),
            Err(e) => e,
        };
        let retry_at = match &err {
            RustlsError::InvalidCertificate(rustls::CertificateError::ExpiredContext {
                not_after,
                ..
            }) => {
                findings.expired = true;
                *not_after
            }
            RustlsError::InvalidCertificate(rustls::CertificateError::NotValidYetContext {
                not_before,
                ..
            }) => {
                findings.not_yet_valid = true;
                *not_before
            }
            _ => return Err(err),
        };
        if runs >= MAX_VALIDITY_TIME_RUNS || retry_at == at {
            return Err(err);
        }
        at = retry_at;
    }
}

/// Raises the warning events for the validity-time errors an accepted
/// certificate carried.
fn report_validity_time_findings(
    handler: &dyn TlsEventHandler,
    peer: &str,
    findings: ValidityTimeFindings,
) {
    if findings.expired {
        let msg = format!("{peer} cert expired; time_validation=false, allowing");
        handler.on_event(TlsEventLevel::Warning, TlsEventCode::WrnCertExpired, &msg);
        tracing::warn!("{}", msg);
    }
    if findings.not_yet_valid {
        let msg = format!("{peer} cert not yet valid; time_validation=false, allowing");
        handler.on_event(
            TlsEventLevel::Warning,
            TlsEventCode::WrnCertNotYetValid,
            &msg,
        );
        tracing::warn!("{}", msg);
    }
}

// -----------------------------------------------------------------------------
// IgnoreValidityTimeServerVerifier
// -----------------------------------------------------------------------------

/// Server verifier that can ignore certificate validity time.
///
/// With `ignore_validity_time` set, a certificate that has expired or is not
/// valid yet is verified again at a time inside its validity period. It is
/// accepted, with a warning event, only when that verification passes, so a
/// bad signature, a revoked certificate, an unknown CA or a peer outside the
/// allow-only-known list still rejects. That is what IEC 62351-3 requires:
/// switching validity-time checking off relaxes the expiry check and nothing
/// else. An inner verifier that reports expiry without the `*Context`
/// variants gives no validity period to verify in, so its error rejects.
pub struct IgnoreValidityTimeServerVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    /// `false` keeps the strict default; `true` ignores validity time and is
    /// intended for development only.
    ignore_validity_time: bool,
    event_handler: Arc<dyn TlsEventHandler>,
}

impl IgnoreValidityTimeServerVerifier {
    /// Wraps `inner` with the validity-time override.
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

impl ServerCertVerifier for IgnoreValidityTimeServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if !self.ignore_validity_time {
            return self.inner.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            );
        }
        let (verified, findings) = verify_ignoring_validity_time(now, |at| {
            self.inner
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, at)
        })?;
        report_validity_time_findings(self.event_handler.as_ref(), "server", findings);
        Ok(verified)
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
