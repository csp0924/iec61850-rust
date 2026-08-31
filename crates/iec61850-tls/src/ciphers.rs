//! The IEC 62351-3 cipher suite whitelist, as const slices.
//!
//! Annex B of IEC 62351-3 fixes the permitted suites. The builder installs
//! [`IEC62351_3_ALL_CIPHERS`] and exposes no API to add or remove a suite at
//! runtime, so a deployment cannot weaken the profile.
//!
//! Annex B also lists the `TLS_DHE_RSA_WITH_AES_*_GCM_SHA*` suites. The
//! rustls ring provider implements no finite-field Diffie-Hellman, only
//! ECDHE, so a peer that offers DHE alone fails to negotiate.

use rustls::SupportedCipherSuite;

/// TLS 1.2 suites permitted by IEC 62351-3, narrowed to what the rustls ring
/// provider implements.
///
/// Annex B also names the DHE_RSA suites; ring provides no finite-field
/// Diffie-Hellman, so only the ECDHE suites appear here.
pub const IEC62351_3_TLS12_CIPHERS: &[SupportedCipherSuite] = &[
    rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
];

/// TLS 1.3 suites permitted by IEC 62351-3.
pub const IEC62351_3_TLS13_CIPHERS: &[SupportedCipherSuite] = &[
    rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
    rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
];

/// The combined TLS 1.2 and TLS 1.3 whitelist, as installed by the builder.
pub const IEC62351_3_ALL_CIPHERS: &[SupportedCipherSuite] = &[
    rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
    rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
];
