//! The TLS event handler trait and its default implementations.
//!
//! Carries the 19 event codes defined in IEC 62351-3 §5. Events are
//! informational, such as session establishment or a warning; they do not
//! replace the `Result<_, TlsError>` error path.
//!
//! The verifiers of a configuration built by [`crate::TlsConfigBuilder`]
//! raise the certificate events; [`crate::TlsAcceptor`] and
//! [`crate::TlsConnector`] raise the handshake events. Each code's
//! documentation names where it is raised; codes marked "not raised by this
//! crate" are defined for callers that detect the condition themselves.

/// Severity of a TLS event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TlsEventLevel {
    /// Informational: a normal-flow notification.
    Info,
    /// Non-fatal but worth attention, such as an expired certificate accepted
    /// because validity-time checking is off.
    Warning,
    /// A security incident affecting the safety of the connection, such as a
    /// certificate outside the allowed list.
    Incident,
}

/// TLS event codes, as defined in IEC 62351-3 §5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
pub enum TlsEventCode {
    // Informational events
    /// The TLS session was established. Raised by the acceptor and the
    /// connector on every completed handshake.
    SessionEstablished = 1,
    /// The TLS session closed with a normal close_notify. Not raised by this
    /// crate: the stream belongs to the caller once the handshake completes.
    SessionClosed = 2,
    /// A renegotiation or key update was triggered. Not raised by this crate,
    /// which never initiates either.
    SessionRenegotiation = 3,

    // Warning events
    /// The certificate has expired, and was accepted because validity-time
    /// checking is off and every other check passed.
    WrnCertExpired = 100,
    /// The certificate is not valid yet, and was accepted because
    /// validity-time checking is off and every other check passed.
    WrnCertNotYetValid = 101,
    /// The certificate expires within 30 days. Not raised by this crate.
    WrnCertExpiringSoon = 102,
    /// The CRL has expired. Not raised by this crate; an expired CRL is still
    /// used for the revocation check.
    WrnCrlExpired = 103,
    /// The client presented no certificate to a server that requests one
    /// without requiring it. Raised by the acceptor.
    WrnNoPeerCert = 104,

    // Security alarm events
    /// The peer certificate is not on the configured allow list, or a client
    /// presented no certificate to a server that requires one.
    AlmCertNotConfigured = 200,
    /// Chain validation failed: an untrusted CA, a bad signature, a validity
    /// time outside the certificate's period with validity-time checking on,
    /// or similar.
    AlmCertChainInvalid = 201,
    /// The certificate has been revoked, according to a configured CRL.
    AlmCertRevoked = 202,
    /// The certificate common name or SAN does not match.
    AlmCertSanMismatch = 203,
    /// The peer offered no cipher suite of the IEC 62351-3 whitelist, or no
    /// key exchange group a whitelisted suite can use, as a client offering
    /// only RSA key exchange or DHE suites does. Raised by the acceptor and
    /// the connector.
    AlmCipherNotAllowed = 204,
    /// The peer offered no TLS version this end accepts, or a client sent a
    /// ClientHello without the signature_algorithms extension, as TLS 1.1 and
    /// older clients do. Raised by the acceptor and the connector.
    AlmVersionTooOld = 205,
    /// A connection was attempted from an unauthorized address or port. Not
    /// raised by this crate.
    AlmUnauthorizedAccess = 206,
    /// The TLS handshake timed out. The acceptor and the connector apply no
    /// timeout of their own; [`TlsAcceptor::report_handshake_timeout`] raises
    /// it for the caller that bounds the handshake, as the IEC 61850 server
    /// does when the handshake or the association setup after it exceeds its
    /// setup timeout.
    ///
    /// [`TlsAcceptor::report_handshake_timeout`]: crate::TlsAcceptor::report_handshake_timeout
    AlmHandshakeTimeout = 207,
    /// The peer aborted the handshake with a TLS alert. Raised by the acceptor
    /// and the connector.
    AlmUnexpectedAlert = 208,
    /// The certificate could not be parsed.
    AlmCertBadEncoding = 209,
    /// The local end closed the connection because a security policy fired.
    /// Not raised by this crate.
    AlmConnectionAborted = 210,
}

/// Callback interface for TLS events.
///
/// An implementation may log, raise an alarm or count. It must not panic; a
/// failure inside the handler belongs in a log line.
pub trait TlsEventHandler: Send + Sync {
    /// Reports one event with its severity, code and message.
    fn on_event(&self, level: TlsEventLevel, code: TlsEventCode, message: &str);
}

/// Default handler: `Info` goes to `tracing::debug!`, `Warning` to
/// `tracing::warn!`, and `Incident` to `tracing::error!`.
#[derive(Debug, Default)]
pub struct DefaultTracingHandler;

impl TlsEventHandler for DefaultTracingHandler {
    fn on_event(&self, level: TlsEventLevel, code: TlsEventCode, message: &str) {
        match level {
            TlsEventLevel::Info => {
                tracing::debug!(event_code = ?code, "{}", message);
            }
            TlsEventLevel::Warning => {
                tracing::warn!(event_code = ?code, "{}", message);
            }
            TlsEventLevel::Incident => {
                tracing::error!(event_code = ?code, "{}", message);
            }
        }
    }
}

/// Handler that discards every event, for tests.
#[derive(Debug, Default)]
pub struct NullEventHandler;

impl TlsEventHandler for NullEventHandler {
    fn on_event(&self, _level: TlsEventLevel, _code: TlsEventCode, _message: &str) {}
}

/// Raises `SessionEstablished` for a completed handshake.
pub(crate) fn report_established(
    handler: &dyn TlsEventHandler,
    side: &str,
    conn: &rustls::CommonState,
) {
    let msg = format!(
        "{side} TLS session established: version={:?} suite={:?}",
        conn.protocol_version(),
        conn.negotiated_cipher_suite().map(|s| s.suite())
    );
    handler.on_event(TlsEventLevel::Info, TlsEventCode::SessionEstablished, &msg);
}

/// Raises the event matching a failed handshake.
///
/// Certificate rejections raise nothing here: the verifiers of a built
/// configuration have already reported them. Failures with no matching code,
/// such as I/O errors, raise nothing either.
pub(crate) fn report_handshake_failure(
    handler: &dyn TlsEventHandler,
    side: &str,
    err: &std::io::Error,
) {
    use rustls::{Error as E, PeerIncompatible as P};
    let Some(tls_err) = err
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    else {
        return;
    };
    let code = match tls_err {
        E::NoCertificatesPresented => TlsEventCode::AlmCertNotConfigured,
        E::PeerIncompatible(P::NoCipherSuitesInCommon | P::NoKxGroupsInCommon) => {
            TlsEventCode::AlmCipherNotAllowed
        }
        E::PeerIncompatible(
            P::Tls12NotOffered
            | P::Tls12NotOfferedOrEnabled
            | P::SupportedVersionsExtensionRequired
            | P::SignatureAlgorithmsExtensionRequired
            | P::ServerDoesNotSupportTls12Or13
            | P::ServerTlsVersionIsDisabledByOurConfig,
        ) => TlsEventCode::AlmVersionTooOld,
        E::AlertReceived(_) => TlsEventCode::AlmUnexpectedAlert,
        _ => return,
    };
    let msg = format!("{side} TLS handshake failed: {tls_err}");
    handler.on_event(TlsEventLevel::Incident, code, &msg);
}
