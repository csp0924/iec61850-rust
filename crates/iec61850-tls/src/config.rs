//! Builder for the IEC 62351-3 compatible TLS configuration.
//!
//! [`TlsConfigBuilder`] collects every setting; `build_client` and
//! `build_server` validate them and produce a [`TlsClientConfig`] or a
//! [`TlsServerConfig`].
//!
//! Defaults: chain validation on, validity-time validation on,
//! allow-only-known peers off, session resumption on, and TLS 1.2 as the
//! minimum version, which IEC 62351-3 mandates.

use std::sync::Arc;
use std::time::Duration;

use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::pem::{Error as PemError, PemObject};
use rustls_pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};

use crate::ciphers::IEC62351_3_ALL_CIPHERS;
use crate::error::TlsError;
use crate::event::{DefaultTracingHandler, TlsEventHandler};
use crate::verifier::{
    AllowOnlyKnownCertsClientVerifier, AllowOnlyKnownCertsServerVerifier,
    IgnoreValidityTimeServerVerifier,
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
#[derive(Clone, Debug)]
pub struct TlsClientConfig {
    pub(crate) inner: Arc<ClientConfig>,
}

impl TlsClientConfig {
    /// Returns the underlying `Arc<rustls::ClientConfig>`.
    pub fn inner(&self) -> Arc<ClientConfig> {
        Arc::clone(&self.inner)
    }
}

/// Server-side TLS configuration. Cloning is cheap; the rustls configuration
/// sits behind an `Arc`.
#[derive(Clone, Debug)]
pub struct TlsServerConfig {
    pub(crate) inner: Arc<ServerConfig>,
}

impl TlsServerConfig {
    /// Returns the underlying `Arc<rustls::ServerConfig>`.
    pub fn inner(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.inner)
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

    // Verification settings
    /// Runs chain validation against the trust anchors. Defaults to true.
    chain_validation: bool,
    /// Checks certificate validity time. Defaults to true; false downgrades
    /// expiry errors to warnings.
    time_validation: bool,

    // TLS versions
    /// Lowest accepted version. TLS 1.2 by default, as IEC 62351-3 requires.
    min_version: TlsVersion,
    /// Highest accepted version. TLS 1.3 by default.
    max_version: TlsVersion,

    // Hostname verification
    /// Records the intent to skip SNI hostname verification. Dangerous;
    /// defaults to false.
    dangerous_no_sni_verify: bool,

    // -- CRL ------------------------------------------------------------------
    /// Certificate revocation lists in DER, used by the WebPKI revocation check.
    crls: Vec<CertificateRevocationListDer<'static>>,

    // -- Session resumption --------------------------------------------------
    /// Enables session resumption: tickets on the server, a cache on the
    /// client. Defaults to true.
    session_resumption: bool,
    /// Session resumption lifetime; `None` keeps the rustls default.
    session_resumption_lifetime: Option<Duration>,

    // Renegotiation
    /// Renegotiation interval in milliseconds; 0 disables it. Not applicable
    /// to TLS 1.3.
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
            chain_validation: true,
            time_validation: true,
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls13,
            dangerous_no_sni_verify: false,
            crls: Vec::new(),
            session_resumption: true,
            session_resumption_lifetime: None,
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
    pub fn allow_only_known_peers(mut self, v: bool) -> Self {
        self.allow_only_known_peers = v;
        self
    }

    /// Enables or disables chain validation against the trust anchors.
    /// Defaults to true.
    pub fn chain_validation(mut self, v: bool) -> Self {
        self.chain_validation = v;
        self
    }

    /// Enables or disables certificate validity-time checking. Defaults to
    /// true; switching it off downgrades expiry errors to warnings.
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

    /// Records the intent to skip SNI hostname verification.
    ///
    /// Dangerous, and off by default; intended for development and interop
    /// testing. See `NoSniServerVerifier` for what is currently enforced.
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
    pub fn session_resumption(mut self, v: bool) -> Self {
        self.session_resumption = v;
        self
    }

    /// Sets the session resumption lifetime.
    pub fn session_resumption_lifetime(mut self, d: Duration) -> Self {
        self.session_resumption_lifetime = Some(d);
        self
    }

    /// Sets the renegotiation interval in milliseconds; 0 disables it. TLS 1.2
    /// only.
    ///
    /// A session that runs indefinitely without rekeying
    /// is bounded by this interval. rustls does not support server-initiated
    /// renegotiation, so the value is recorded but no HelloRequest is sent.
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
        // IgnoreValidityTime(AllowOnlyKnownCerts(WebPki or NoSni wrapper)).
        let base_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
            if self.dangerous_no_sni_verify {
                // Wrapped to record the no-SNI intent; see NoSniServerVerifier.
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
        let final_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
            Arc::new(IgnoreValidityTimeServerVerifier::new(
                known_verifier,
                !self.time_validation, // time_validation off means ignore_validity_time on
                Arc::clone(&self.event_handler),
            ));

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
        })
    }

    /// Builds the server configuration.
    ///
    /// # Errors
    ///
    /// [`TlsError::Validation`] when `min_version` exceeds `max_version`, when
    /// no private key or certificate chain was supplied, when the protocol
    /// version list is rejected, or when the client verifier cannot be built;
    /// [`TlsError::CertLoad`] when the server certificate is rejected.
    pub fn build_server(self) -> Result<TlsServerConfig, TlsError> {
        if self.min_version > self.max_version {
            return Err(TlsError::Validation(format!(
                "min_version ({:?}) > max_version ({:?})",
                self.min_version, self.max_version
            )));
        }
        // A server must present a certificate and a key.
        let key = self
            .private_key
            .ok_or_else(|| TlsError::Validation("server requires private key".into()))?;
        if self.cert_chain.is_empty() {
            return Err(TlsError::Validation(
                "server requires at least one certificate in chain".into(),
            ));
        }

        let versions = build_version_list(self.min_version, self.max_version);
        let provider = Arc::new(rustls::crypto::CryptoProvider {
            cipher_suites: IEC62351_3_ALL_CIPHERS.to_vec(),
            ..rustls::crypto::ring::default_provider()
        });

        // Client certificate verifier, for mutual TLS.
        let root_store = build_root_store(&self.ca_certs)?;
        let base_client_verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(root_store),
            Arc::clone(&provider),
        )
        .with_crls(self.crls)
        .allow_unauthenticated() // clients without a certificate are gated by allow_only_known
        .build()
        .map_err(|e| TlsError::Validation(format!("client verifier build: {e}")))?;

        // Allow-only-known wrapper.
        let final_client_verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
            Arc::new(AllowOnlyKnownCertsClientVerifier::new(
                base_client_verifier,
                self.allow_only_known_peers,
                self.known_peer_certs,
                Arc::clone(&self.event_handler),
            ));

        let mut cfg = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&versions)
            .map_err(|e| TlsError::Validation(format!("protocol versions: {e}")))?
            .with_client_cert_verifier(final_client_verifier)
            .with_single_cert(self.cert_chain, key)
            .map_err(|e| TlsError::CertLoad(format!("server cert: {e}")))?;

        if !self.session_resumption {
            cfg.send_tls13_tickets = 0;
        }
        if let Some(lifetime) = self.session_resumption_lifetime {
            cfg.send_tls13_tickets = (lifetime.as_secs() / 3600).max(1) as usize;
        }

        Ok(TlsServerConfig {
            inner: Arc::new(cfg),
        })
    }
}

// -----------------------------------------------------------------------------
// NoSniServerVerifier
// -----------------------------------------------------------------------------

/// Verifier wrapper that records the intent to skip SNI hostname checking.
///
/// IEC 62351-3 does not require the SAN to match the server hostname, unlike
/// Web PKI. Reached only through `with_dangerous_no_sni_verify()`.
///
/// TODO: implement genuine SAN-free verification; this wrapper still forwards
/// to the inner verifier, which does check the SAN.
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
        // The inner verifier still performs chain validation, and its SAN
        // check with it. Skipping the SAN would mean reimplementing chain
        // validation against the webpki API; see the TODO on this type.
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
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
