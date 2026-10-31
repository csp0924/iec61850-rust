//! Builder for the IEC 62351-3 compatible TLS configuration.
//!
//! [`TlsConfigBuilder`] collects every setting; `build_client` and
//! `build_server` validate them and produce a [`TlsClientConfig`] or a
//! [`TlsServerConfig`].
//!
//! Defaults: validity-time validation on, allow-only-known peers off, client
//! authentication requested but not required when trust anchors are set,
//! session resumption on with no TLS 1.3 session ticket sent, so only TLS 1.2
//! sessions resume, and TLS 1.2 as the minimum version, which IEC 62351-3
//! mandates. Chain validation always runs.
//!
//! Client authentication on the server is mandatory when
//! [`TlsConfigBuilder::require_client_auth`] or
//! [`TlsConfigBuilder::allow_only_known_peers`] is set; such a server needs at
//! least one trust anchor. Otherwise a server with trust anchors requests a
//! client certificate and validates it when one is presented, and a server
//! without trust anchors does not request one.

use std::sync::Arc;
use std::time::Duration;

use rustls::server::{NoServerSessionStorage, WebPkiClientVerifier};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::pem::{Error as PemError, PemObject};
use rustls_pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};

use crate::ciphers::IEC62351_3_ALL_CIPHERS;
use crate::error::TlsError;
use crate::event::{DefaultTracingHandler, TlsEventHandler};
use crate::session::{system_clock, ExpiringSessionStore, SessionClock, SESSION_CACHE_CAPACITY};
use crate::verifier::{
    AllowOnlyKnownCertsClientVerifier, AllowOnlyKnownCertsServerVerifier,
    IgnoreValidityTimeClientVerifier, IgnoreValidityTimeServerVerifier, ReportingClientVerifier,
    ReportingServerVerifier,
};

// -----------------------------------------------------------------------------
// TlsVersion
// -----------------------------------------------------------------------------

/// The TLS versions this layer supports.
///
/// Only 1.2 and 1.3 exist as variants, so TLS 1.0 and 1.1 are excluded at
/// compile time. IEC 62351-3 Annex A sets TLS 1.2 as the floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    /// TLS 1.2.
    Tls12,
    /// TLS 1.3.
    Tls13,
}

impl TlsVersion {
    fn to_rustls(self) -> &'static rustls::SupportedProtocolVersion {
        match self {
            TlsVersion::Tls12 => &rustls::version::TLS12,
            TlsVersion::Tls13 => &rustls::version::TLS13,
        }
    }
}

// -----------------------------------------------------------------------------
// TlsClientConfig / TlsServerConfig
// -----------------------------------------------------------------------------

/// Client-side TLS configuration. Cloning is cheap; the rustls configuration
/// sits behind an `Arc`.
#[derive(Clone)]
pub struct TlsClientConfig {
    pub(crate) inner: Arc<ClientConfig>,
    /// Receives the session events raised by [`crate::TlsConnector`].
    pub(crate) event_handler: Arc<dyn TlsEventHandler>,
}

impl TlsClientConfig {
    /// Returns the underlying `Arc<rustls::ClientConfig>`.
    pub fn inner(&self) -> Arc<ClientConfig> {
        Arc::clone(&self.inner)
    }
}

impl std::fmt::Debug for TlsClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsClientConfig")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

/// Server-side TLS configuration. Cloning is cheap; the rustls configuration
/// sits behind an `Arc`.
#[derive(Clone)]
pub struct TlsServerConfig {
    pub(crate) inner: Arc<ServerConfig>,
    /// Receives the session events raised by [`crate::TlsAcceptor`].
    pub(crate) event_handler: Arc<dyn TlsEventHandler>,
    /// Whether the server requests a client certificate without requiring
    /// one, so that a client presenting none is worth a warning.
    pub(crate) client_auth_optional: bool,
}

impl TlsServerConfig {
    /// Returns the underlying `Arc<rustls::ServerConfig>`.
    pub fn inner(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.inner)
    }
}

impl std::fmt::Debug for TlsServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsServerConfig")
            .field("inner", &self.inner)
            .field("client_auth_optional", &self.client_auth_optional)
            .finish_non_exhaustive()
    }
}

// -----------------------------------------------------------------------------
// TlsConfigBuilder
// -----------------------------------------------------------------------------

/// Builder for a client or a server TLS configuration.
///
/// One builder serves both sides: `build_client` and `build_server` read the
/// same settings.
pub struct TlsConfigBuilder {
    // Certificates and keys
    /// Local certificate chain in DER, leaf first.
    cert_chain: Vec<CertificateDer<'static>>,
    /// Local private key.
    private_key: Option<PrivateKeyDer<'static>>,
    /// Trust anchors used for chain validation.
    ca_certs: Vec<CertificateDer<'static>>,

    // Allow-only-known peers
    /// Certificates a peer may present in allow-only-known mode.
    known_peer_certs: Vec<CertificateDer<'static>>,
    /// Restricts peers to `known_peer_certs`. Defaults to false.
    allow_only_known_peers: bool,
    /// Makes a client certificate mandatory on the server. Defaults to false.
    require_client_auth: bool,

    // Verification settings
    /// Requested chain validation setting. Not applied: chain validation
    /// always runs.
    chain_validation: bool,
    /// Checks certificate validity time. Defaults to true; false accepts an
    /// expired or not yet valid certificate whose chain is otherwise valid.
    time_validation: bool,

    // TLS versions
    /// Lowest accepted version. TLS 1.2 by default, as IEC 62351-3 requires.
    min_version: TlsVersion,
    /// Highest accepted version. TLS 1.3 by default.
    max_version: TlsVersion,

    // Hostname verification
    /// Skips matching the server certificate against the server name.
    /// Dangerous; defaults to false.
    dangerous_no_sni_verify: bool,

    // -- CRL ------------------------------------------------------------------
    /// Certificate revocation lists in DER, used by the WebPKI revocation check.
    crls: Vec<CertificateRevocationListDer<'static>>,

    // -- Session resumption --------------------------------------------------
    /// Enables session resumption: a session cache on both sides. Defaults to
    /// true.
    session_resumption: bool,
    /// How long the server keeps a session resumable; `None` keeps the rustls
    /// cache, which bounds the entry count only.
    session_resumption_lifetime: Option<Duration>,
    /// Time source of the server session store.
    session_clock: SessionClock,
    /// TLS 1.3 tickets the server sends per handshake. Defaults to 0.
    tls13_session_tickets: usize,

    // Renegotiation
    /// Requested renegotiation interval in milliseconds. Not applied: no
    /// renegotiation is ever initiated.
    renegotiation_interval_ms: u64,

    // -- Event handler -------------------------------------------------------
    /// Event callback; `DefaultTracingHandler` by default.
    event_handler: Arc<dyn TlsEventHandler>,
}

impl Default for TlsConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsConfigBuilder {
    /// Creates a builder carrying the defaults listed in the module header.
    pub fn new() -> Self {
        Self {
            cert_chain: Vec::new(),
            private_key: None,
            ca_certs: Vec::new(),
            known_peer_certs: Vec::new(),
            allow_only_known_peers: false,
            require_client_auth: false,
            chain_validation: true,
            time_validation: true,
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls13,
            dangerous_no_sni_verify: false,
            crls: Vec::new(),
            session_resumption: true,
            session_resumption_lifetime: None,
            session_clock: system_clock(),
            tls13_session_tickets: 0,
            renegotiation_interval_ms: 0,
            event_handler: Arc::new(DefaultTracingHandler),
        }
    }

    // Certificate and key setters

    /// Loads the local certificate chain and private key from PEM bytes.
    ///
    /// # Errors
    ///
    /// [`TlsError::CertLoad`] if the PEM holds no certificate or no key, or
    /// fails to parse.
    pub fn with_cert_pem(mut self, cert_pem: &[u8], key_pem: &[u8]) -> Result<Self, TlsError> {
        let cert_chain = load_cert_chain_pem(cert_pem)?;
        let key = load_private_key_pem(key_pem)?;
        self.cert_chain = cert_chain;
        self.private_key = Some(key);
        Ok(self)
    }

    /// Loads the local certificate chain and private key from PEM files.
    ///
    /// # Errors
    ///
    /// [`TlsError::CertLoad`] if either file cannot be read or parsed.
    pub fn with_cert_pem_file(self, cert_path: &str, key_path: &str) -> Result<Self, TlsError> {
        let cert_bytes = std::fs::read(cert_path)
            .map_err(|e| TlsError::CertLoad(format!("read cert file {cert_path}: {e}")))?;
        let key_bytes = std::fs::read(key_path)
            .map_err(|e| TlsError::CertLoad(format!("read key file {key_path}: {e}")))?;
        self.with_cert_pem(&cert_bytes, &key_bytes)
    }

    /// Sets the local certificate chain and private key from DER.
    pub fn with_cert_der(
        mut self,
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Self {
        self.cert_chain = cert_chain;
        self.private_key = Some(key);
        self
    }

    /// Adds trust anchors from PEM bytes. May be called repeatedly.
    ///
    /// # Errors
    ///
    /// [`TlsError::CertLoad`] if the PEM holds no certificate or fails to parse.
    pub fn add_ca_pem(mut self, pem: &[u8]) -> Result<Self, TlsError> {
        let certs = load_cert_chain_pem(pem)?;
        self.ca_certs.extend(certs);
        Ok(self)
    }

    /// Adds trust anchors from a PEM file.
    ///
    /// # Errors
    ///
    /// [`TlsError::CertLoad`] if the file cannot be read or parsed.
    pub fn add_ca_pem_file(self, path: &str) -> Result<Self, TlsError> {
        let bytes = std::fs::read(path)
            .map_err(|e| TlsError::CertLoad(format!("read CA file {path}: {e}")))?;
        self.add_ca_pem(&bytes)
    }

    /// Adds a certificate a peer may present in allow-only-known mode, from
    /// PEM bytes.
    ///
    /// # Errors
    ///
    /// [`TlsError::CertLoad`] if the PEM holds no certificate or fails to parse.
    pub fn add_known_peer_pem(mut self, pem: &[u8]) -> Result<Self, TlsError> {
        let certs = load_cert_chain_pem(pem)?;
        self.known_peer_certs.extend(certs);
        Ok(self)
    }

    /// Adds a certificate a peer may present in allow-only-known mode, in DER
    /// form.
    pub fn add_known_peer_der(mut self, cert: CertificateDer<'static>) -> Self {
        self.known_peer_certs.push(cert);
        self
    }

    // Behavior setters

    /// Enables or disables allow-only-known-certificates mode. Defaults to false.
    ///
    /// When enabled, the peer must present a certificate that passes chain
    /// validation and appears on the known-peer list. On the server this makes
    /// client authentication mandatory, so a client presenting no certificate
    /// is refused.
    pub fn allow_only_known_peers(mut self, v: bool) -> Self {
        self.allow_only_known_peers = v;
        self
    }

    /// Makes a client certificate mandatory on the server. Defaults to false.
    ///
    /// When enabled, a client presenting no certificate is refused and raises
    /// `AlmCertNotConfigured`. When disabled, a server with trust anchors
    /// still requests a certificate and validates one when presented, and a
    /// server without trust anchors does not request one. Has no effect on
    /// `build_client`.
    pub fn require_client_auth(mut self, v: bool) -> Self {
        self.require_client_auth = v;
        self
    }

    /// Records a chain validation setting. Not applied: chain validation
    /// against the trust anchors always runs, and `false` only logs a warning
    /// when the configuration is built.
    pub fn chain_validation(mut self, v: bool) -> Self {
        self.chain_validation = v;
        self
    }

    /// Enables or disables certificate validity-time checking on both sides.
    /// Defaults to true.
    ///
    /// When disabled, an expired or not yet valid peer certificate is
    /// accepted, with a `WrnCertExpired` or `WrnCertNotYetValid` event, only if
    /// it passes every other check at a time inside its validity period.
    pub fn time_validation(mut self, v: bool) -> Self {
        self.time_validation = v;
        self
    }

    /// Sets the lowest accepted TLS version.
    pub fn min_version(mut self, v: TlsVersion) -> Self {
        self.min_version = v;
        self
    }

    /// Sets the highest accepted TLS version.
    pub fn max_version(mut self, v: TlsVersion) -> Self {
        self.max_version = v;
        self
    }

    /// Skips matching the server certificate against the server name passed
    /// to [`crate::TlsConnector::connect`].
    ///
    /// Dangerous, and off by default; intended for IEDs whose certificates
    /// carry no matching DNS or IP subject alternative name. Chain validation,
    /// revocation, validity time and the allow-only-known list still apply.
    /// Has no effect on `build_server`.
    pub fn with_dangerous_no_sni_verify(mut self) -> Self {
        self.dangerous_no_sni_verify = true;
        self
    }

    /// Adds CRLs from PEM bytes. May be called repeatedly.
    ///
    /// # Errors
    ///
    /// [`TlsError::CrlError`] if the PEM fails to parse.
    pub fn add_crl_pem(mut self, pem: &[u8]) -> Result<Self, TlsError> {
        let crls = load_crls_pem(pem)?;
        self.crls.extend(crls);
        Ok(self)
    }

    /// Removes every CRL added so far.
    pub fn clear_crls(mut self) -> Self {
        self.crls.clear();
        self
    }

    /// Enables or disables session resumption. Defaults to true.
    ///
    /// When enabled, TLS 1.2 sessions resume through session IDs; TLS 1.3
    /// sessions resume only when the server sends tickets, which it does
    /// not unless [`Self::tls13_session_tickets`] is set.
    ///
    /// When disabled, the server keeps no session state and issues no TLS 1.3
    /// ticket, so neither TLS 1.2 nor TLS 1.3 sessions resume, and the client
    /// offers no session to resume. This takes precedence over
    /// [`Self::session_resumption_lifetime`] and
    /// [`Self::tls13_session_tickets`].
    pub fn session_resumption(mut self, v: bool) -> Self {
        self.session_resumption = v;
        self
    }

    /// Sets how long the server keeps a session resumable after storing it.
    ///
    /// Applies to TLS 1.2 session IDs and TLS 1.3 tickets alike; resuming an
    /// older session falls back to a full handshake. A zero lifetime disables
    /// resumption on the server. Without this setting the server keeps up to
    /// 256 sessions with no time limit. Has no effect on `build_client`.
    pub fn session_resumption_lifetime(mut self, d: Duration) -> Self {
        self.session_resumption_lifetime = Some(d);
        self
    }

    /// Sets how many TLS 1.3 session tickets the server sends after each
    /// handshake.
    ///
    /// Defaults to 0: the server sends no TLS 1.3 ticket, so TLS 1.3 sessions
    /// do not resume, while TLS 1.2 session ID resumption keeps working. Keep
    /// it at 0 when serving TLS 1.3 clients that close the connection on
    /// receiving a ticket. `session_resumption(false)` and a zero
    /// [`Self::session_resumption_lifetime`] take precedence: either sends no
    /// ticket whatever this value. Has no effect on `build_client`.
    pub fn tls13_session_tickets(mut self, n: usize) -> Self {
        self.tls13_session_tickets = n;
        self
    }

    /// Replaces the time source of the server session store.
    #[cfg(test)]
    pub(crate) fn with_session_clock(mut self, clock: SessionClock) -> Self {
        self.session_clock = clock;
        self
    }

    /// Records a renegotiation interval in milliseconds. Not applied.
    ///
    /// rustls supports no TLS 1.2 renegotiation, so no HelloRequest is ever
    /// sent; a non-zero value only logs a warning when the configuration is
    /// built.
    pub fn renegotiation_interval(mut self, ms: u64) -> Self {
        self.renegotiation_interval_ms = ms;
        self
    }

    /// Replaces the event callback.
    pub fn with_event_handler(mut self, handler: Arc<dyn TlsEventHandler>) -> Self {
        self.event_handler = handler;
        self
    }

    // -- build ----------------------------------------------------------------

    /// Builds the client configuration.
    ///
    /// # Errors
    ///
    /// [`TlsError::Validation`] when `min_version` exceeds `max_version`, when
    /// the protocol version list is rejected, or when the certificate verifier
    /// cannot be built; [`TlsError::CertLoad`] when the client authentication
    /// certificate is rejected.
    pub fn build_client(self) -> Result<TlsClientConfig, TlsError> {
        if self.min_version > self.max_version {
            return Err(TlsError::Validation(format!(
                "min_version ({:?}) > max_version ({:?})",
                self.min_version, self.max_version
            )));
        }
        self.warn_unapplied_settings();

        let versions = build_version_list(self.min_version, self.max_version);
        // cipher_suites is a public field of CryptoProvider and is overwritten
        // directly; the provider exposes no builder for it.
        let provider = Arc::new(rustls::crypto::CryptoProvider {
            cipher_suites: IEC62351_3_ALL_CIPHERS.to_vec(),
            ..rustls::crypto::ring::default_provider()
        });

        let root_store = build_root_store(&self.ca_certs)?;

        // build() already yields an Arc<WebPkiServerVerifier>, usable directly
        // as an Arc<dyn ServerCertVerifier>.
        let webpki_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
            rustls::client::WebPkiServerVerifier::builder_with_provider(
                Arc::new(root_store),
                Arc::clone(&provider),
            )
            .with_crls(self.crls)
            .build()
            .map_err(|e| TlsError::Validation(format!("verifier build: {e}")))?;

        // Verifier chain, outermost first:
        // Reporting(IgnoreValidityTime(AllowOnlyKnownCerts(WebPki or NoSni wrapper))).
        let base_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
            if self.dangerous_no_sni_verify {
                Arc::new(NoSniServerVerifier::new(webpki_verifier))
            } else {
                webpki_verifier
            };

        // Allow-only-known wrapper.
        let known_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
            Arc::new(AllowOnlyKnownCertsServerVerifier::new(
                base_verifier,
                self.allow_only_known_peers,
                self.known_peer_certs,
                Arc::clone(&self.event_handler),
            ));

        // Validity-time wrapper.
        let timed_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
            Arc::new(IgnoreValidityTimeServerVerifier::new(
                known_verifier,
                !self.time_validation, // time_validation off means ignore_validity_time on
                Arc::clone(&self.event_handler),
            ));

        // Event-reporting wrapper.
        let final_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> = Arc::new(
            ReportingServerVerifier::new(timed_verifier, Arc::clone(&self.event_handler)),
        );

        let cfg_builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&versions)
            .map_err(|e| TlsError::Validation(format!("protocol versions: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(final_verifier);

        let mut cfg = if let (Some(key), certs) = (self.private_key, self.cert_chain) {
            if certs.is_empty() {
                cfg_builder.with_no_client_auth()
            } else {
                cfg_builder
                    .with_client_auth_cert(certs, key)
                    .map_err(|e| TlsError::CertLoad(format!("client auth cert: {e}")))?
            }
        } else {
            cfg_builder.with_no_client_auth()
        };

        if !self.session_resumption {
            cfg.resumption = rustls::client::Resumption::disabled();
        }

        Ok(TlsClientConfig {
            inner: Arc::new(cfg),
            event_handler: self.event_handler,
        })
    }

    /// Builds the server configuration.
    ///
    /// # Errors
    ///
    /// [`TlsError::Validation`] when `min_version` exceeds `max_version`, when
    /// no private key or certificate chain was supplied, when client
    /// authentication is mandatory but no trust anchor was supplied, when the
    /// protocol version list is rejected, or when the client verifier cannot
    /// be built; [`TlsError::CertLoad`] when the server certificate is
    /// rejected.
    pub fn build_server(self) -> Result<TlsServerConfig, TlsError> {
        if self.min_version > self.max_version {
            return Err(TlsError::Validation(format!(
                "min_version ({:?}) > max_version ({:?})",
                self.min_version, self.max_version
            )));
        }
        self.warn_unapplied_settings();
        // A server must present a certificate and a key.
        let key = self
            .private_key
            .ok_or_else(|| TlsError::Validation("server requires private key".into()))?;
        if self.cert_chain.is_empty() {
            return Err(TlsError::Validation(
                "server requires at least one certificate in chain".into(),
            ));
        }
        let client_auth_mandatory = self.require_client_auth || self.allow_only_known_peers;
        if client_auth_mandatory && self.ca_certs.is_empty() {
            return Err(TlsError::Validation(
                "mandatory client authentication requires at least one trust anchor".into(),
            ));
        }

        let versions = build_version_list(self.min_version, self.max_version);
        let provider = Arc::new(rustls::crypto::CryptoProvider {
            cipher_suites: IEC62351_3_ALL_CIPHERS.to_vec(),
            ..rustls::crypto::ring::default_provider()
        });

        // Client certificate verifier, outermost first:
        // Reporting(IgnoreValidityTime(AllowOnlyKnownCerts(WebPki))).
        let client_auth_optional = !client_auth_mandatory && !self.ca_certs.is_empty();
        let client_verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
            if self.ca_certs.is_empty() {
                WebPkiClientVerifier::no_client_auth()
            } else {
                let root_store = build_root_store(&self.ca_certs)?;
                let mut webpki_builder = WebPkiClientVerifier::builder_with_provider(
                    Arc::new(root_store),
                    Arc::clone(&provider),
                )
                .with_crls(self.crls);
                if client_auth_optional {
                    webpki_builder = webpki_builder.allow_unauthenticated();
                }
                let webpki_verifier = webpki_builder
                    .build()
                    .map_err(|e| TlsError::Validation(format!("client verifier build: {e}")))?;

                let known_verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
                    Arc::new(AllowOnlyKnownCertsClientVerifier::new(
                        webpki_verifier,
                        self.allow_only_known_peers,
                        self.known_peer_certs,
                        Arc::clone(&self.event_handler),
                    ));
                let timed_verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
                    Arc::new(IgnoreValidityTimeClientVerifier::new(
                        known_verifier,
                        !self.time_validation,
                        Arc::clone(&self.event_handler),
                    ));
                Arc::new(ReportingClientVerifier::new(
                    timed_verifier,
                    Arc::clone(&self.event_handler),
                ))
            };

        let mut cfg = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&versions)
            .map_err(|e| TlsError::Validation(format!("protocol versions: {e}")))?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(self.cert_chain, key)
            .map_err(|e| TlsError::CertLoad(format!("server cert: {e}")))?;

        // TLS 1.2 session IDs and TLS 1.3 stateful tickets both live in
        // session_storage; the default ticketer issues no stateless ticket.
        let lifetime = self.session_resumption_lifetime;
        if !self.session_resumption || lifetime.is_some_and(|d| d.is_zero()) {
            cfg.session_storage = Arc::new(NoServerSessionStorage {});
            cfg.send_tls13_tickets = 0;
        } else {
            if let Some(lifetime) = lifetime {
                cfg.session_storage = Arc::new(ExpiringSessionStore::new(
                    lifetime,
                    SESSION_CACHE_CAPACITY,
                    self.session_clock,
                ));
            }
            cfg.send_tls13_tickets = self.tls13_session_tickets;
        }

        Ok(TlsServerConfig {
            inner: Arc::new(cfg),
            event_handler: self.event_handler,
            client_auth_optional,
        })
    }

    /// Logs the settings the builder records but does not apply.
    fn warn_unapplied_settings(&self) {
        if !self.chain_validation {
            tracing::warn!("chain_validation(false) is not applied; chain validation still runs");
        }
        if self.renegotiation_interval_ms != 0 {
            tracing::warn!(
                "renegotiation_interval ({} ms) is not applied; no renegotiation is initiated",
                self.renegotiation_interval_ms
            );
        }
    }
}

// -----------------------------------------------------------------------------
// NoSniServerVerifier
// -----------------------------------------------------------------------------

/// Server verifier that skips matching the certificate against the server
/// name.
///
/// IEC 62351-3 does not require the SAN to match the server hostname, unlike
/// Web PKI. Reached only through `with_dangerous_no_sni_verify()`. The inner
/// verifier must be a `WebPkiServerVerifier`, which checks the name after the
/// chain, revocation and validity time; a name mismatch therefore means every
/// other check has passed, and only that error is turned into acceptance.
struct NoSniServerVerifier {
    inner: Arc<dyn rustls::client::danger::ServerCertVerifier>,
}

impl NoSniServerVerifier {
    fn new(inner: Arc<dyn rustls::client::danger::ServerCertVerifier>) -> Self {
        Self { inner }
    }
}

impl std::fmt::Debug for NoSniServerVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoSniServerVerifier").finish()
    }
}

impl rustls::client::danger::ServerCertVerifier for NoSniServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName
                | rustls::CertificateError::NotValidForNameContext { .. },
            )) => Ok(rustls::client::danger::ServerCertVerified::assertion()),
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Parses a certificate chain from PEM bytes into DER.
///
/// Every `CERTIFICATE` section is returned in file order; sections of any
/// other kind are skipped.
///
/// # Errors
///
/// [`TlsError::CertLoad`] if the PEM fails to parse or holds no certificate.
pub(crate) fn load_cert_chain_pem(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::CertLoad(format!("parse cert PEM: {e}")))?;
    if certs.is_empty() {
        return Err(TlsError::CertLoad("no certificates found in PEM".into()));
    }
    Ok(certs)
}

/// Parses a private key from PEM bytes.
///
/// `PRIVATE KEY` (PKCS#8), `RSA PRIVATE KEY` (PKCS#1) and `EC PRIVATE KEY`
/// (SEC1) sections are all accepted. The first key section wins; certificate,
/// CRL and other sections ahead of it are skipped.
///
/// # Errors
///
/// [`TlsError::CertLoad`] if the PEM fails to parse or holds no key.
pub(crate) fn load_private_key_pem(pem: &[u8]) -> Result<PrivateKeyDer<'static>, TlsError> {
    PrivateKeyDer::from_pem_slice(pem).map_err(|e| match e {
        PemError::NoItemsFound => TlsError::CertLoad("no private key found in PEM".into()),
        other => TlsError::CertLoad(format!("parse key PEM: {other}")),
    })
}

/// Parses CRLs from PEM bytes.
///
/// Every `X509 CRL` section is returned in file order; sections of any other
/// kind are skipped, so a PEM holding none yields an empty vector.
///
/// # Errors
///
/// [`TlsError::CrlError`] if the PEM fails to parse.
pub(crate) fn load_crls_pem(
    pem: &[u8],
) -> Result<Vec<CertificateRevocationListDer<'static>>, TlsError> {
    CertificateRevocationListDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::CrlError(format!("parse CRL PEM: {e}")))
}

/// Builds a `RootCertStore` from DER certificates.
fn build_root_store(ca_certs: &[CertificateDer<'static>]) -> Result<RootCertStore, TlsError> {
    let mut store = RootCertStore::empty();
    for cert in ca_certs {
        store
            .add(cert.clone())
            .map_err(|e| TlsError::CertLoad(format!("add CA cert: {e}")))?;
    }
    Ok(store)
}

/// Builds the rustls protocol version list from a minimum and a maximum.
fn build_version_list(
    min: TlsVersion,
    max: TlsVersion,
) -> Vec<&'static rustls::SupportedProtocolVersion> {
    let mut versions = Vec::new();
    if min <= TlsVersion::Tls12 && max >= TlsVersion::Tls12 {
        versions.push(TlsVersion::Tls12.to_rustls());
    }
    if min <= TlsVersion::Tls13 && max >= TlsVersion::Tls13 {
        versions.push(TlsVersion::Tls13.to_rustls());
    }
    versions
}
