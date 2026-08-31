//! The TLS event handler trait and its default implementations.
//!
//! Carries the 20 event codes defined in IEC 62351-3 §5. Events are
//! informational, such as session establishment or a warning; they do not
//! replace the `Result<_, TlsError>` error path.

/// Severity of a TLS event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
pub enum TlsEventCode {
    // Informational events
    /// The TLS session was established.
    SessionEstablished = 1,
    /// The TLS session closed with a normal close_notify.
    SessionClosed = 2,
    /// A renegotiation or key update was triggered.
    SessionRenegotiation = 3,

    // Warning events
    /// The certificate has expired, downgraded to a warning because
    /// validity-time checking is off.
    WrnCertExpired = 100,
    /// The certificate is not valid yet, downgraded to a warning because
    /// validity-time checking is off.
    WrnCertNotYetValid = 101,
    /// The certificate expires within 30 days.
    WrnCertExpiringSoon = 102,
    /// The CRL has expired, downgraded to a warning because validity-time
    /// checking is off.
    WrnCrlExpired = 103,
    /// The peer offered no certificate; a client certificate is optional
    /// under TLS 1.2.
    WrnNoPeerCert = 104,

    // Security alarm events
    /// The peer certificate is not on the configured allow list.
    AlmCertNotConfigured = 200,
    /// Chain validation failed: an untrusted CA, a bad signature or similar.
    AlmCertChainInvalid = 201,
    /// The certificate has been revoked.
    AlmCertRevoked = 202,
    /// The certificate common name or SAN does not match.
    AlmCertSanMismatch = 203,
    /// The connection negotiated a cipher outside the IEC 62351-3 whitelist.
    AlmCipherNotAllowed = 204,
    /// The TLS version is below the required minimum.
    AlmVersionTooOld = 205,
    /// A connection was attempted from an unauthorized address or port.
    AlmUnauthorizedAccess = 206,
    /// The TLS handshake timed out.
    AlmHandshakeTimeout = 207,
    /// An unexpected TLS alert arrived.
    AlmUnexpectedAlert = 208,
    /// The certificate could not be parsed.
    AlmCertBadEncoding = 209,
    /// The local end closed the connection because a security policy fired.
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
