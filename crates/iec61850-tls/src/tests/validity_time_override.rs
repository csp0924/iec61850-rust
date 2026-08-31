//! Regression tests for ignoring certificate validity time.
//!
//! The malformed-input class: a peer presents a certificate that has expired
//! or is not valid yet. Required outcome: with `time_validation=false` only
//! those two errors are downgraded to a warning, while every other chain
//! error, such as a bad signature, a revoked certificate or an unknown CA,
//! still rejects.
//!
//! Covered here: expiry rejects with validity-time checking on; expiry is
//! allowed with it off; and an unknown CA still rejects with it off.

use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair};
use rustls::{
    client::danger::ServerCertVerifier,
    pki_types::{CertificateDer, ServerName, UnixTime},
    RootCertStore,
};
// The time helpers come from rcgen, which depends on the time crate.
use rcgen::date_time_ymd;

use crate::{event::NullEventHandler, verifier::IgnoreValidityTimeServerVerifier};

// -----------------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------------

/// Builds an already expired self-signed CA and a matching server leaf
/// certificate, both valid only until 1971-01-01.
fn make_expired_ca_and_leaf(dns_name: &str) -> (CertificateDer<'static>, CertificateDer<'static>) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    // Fixed far in the past, so the certificate is expired under any clock.
    ca_params.not_before = date_time_ymd(1970, 1, 2);
    ca_params.not_after = date_time_ymd(1971, 1, 1);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_der = CertificateDer::from(ca_cert.der().to_vec()).into_owned();

    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::new(vec![dns_name.to_string()]).unwrap();
    leaf_params.not_before = date_time_ymd(1970, 1, 2);
    leaf_params.not_after = date_time_ymd(1971, 1, 1);
    leaf_params.subject_alt_names = vec![rcgen::SanType::DnsName(dns_name.try_into().unwrap())];
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
    let leaf_der = CertificateDer::from(leaf_cert.der().to_vec()).into_owned();

    (ca_der, leaf_der)
}

/// Builds a valid self-signed CA and a matching server leaf certificate.
fn make_valid_ca_and_leaf(dns_name: &str) -> (CertificateDer<'static>, CertificateDer<'static>) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_der = CertificateDer::from(ca_cert.der().to_vec()).into_owned();

    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::new(vec![dns_name.to_string()]).unwrap();
    leaf_params.subject_alt_names = vec![rcgen::SanType::DnsName(dns_name.try_into().unwrap())];
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
    let leaf_der = CertificateDer::from(leaf_cert.der().to_vec()).into_owned();

    (ca_der, leaf_der)
}

/// Builds a `WebPkiServerVerifier` that trusts `ca_cert` and checks validity time.
fn make_webpki_verifier(
    ca_cert: CertificateDer<'static>,
) -> Arc<dyn rustls::client::danger::ServerCertVerifier> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut root_store = RootCertStore::empty();
    root_store.add(ca_cert).unwrap();
    rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(root_store), provider)
        .build()
        .unwrap()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

/// With validity-time checking on, an expired
/// certificate is rejected.
#[test]
fn expired_cert_with_time_validation_rejects() {
    let (ca_der, leaf_der) = make_expired_ca_and_leaf("server.test");
    let inner = make_webpki_verifier(ca_der);

    // ignore_validity_time = false, that is time_validation = true
    let verifier = IgnoreValidityTimeServerVerifier::new(inner, false, Arc::new(NullEventHandler));

    let now = UnixTime::now(); // well past the certificate's not_after
    let server_name: ServerName<'static> = "server.test".try_into().unwrap();
    let result = verifier.verify_server_cert(&leaf_der, &[], &server_name, &[], now);

    assert!(
        result.is_err(),
        "with time_validation on an expired cert must reject, but verification returned Ok"
    );
}

/// With validity-time checking off, an expired
/// certificate is downgraded to a warning and accepted.
#[test]
fn expired_cert_with_time_validation_off_passes_with_warning() {
    let (ca_der, leaf_der) = make_expired_ca_and_leaf("server.test");
    let inner = make_webpki_verifier(ca_der);

    // ignore_validity_time = true, that is time_validation = false
    let verifier = IgnoreValidityTimeServerVerifier::new(inner, true, Arc::new(NullEventHandler));

    let now = UnixTime::now();
    let server_name: ServerName<'static> = "server.test".try_into().unwrap();
    let result = verifier.verify_server_cert(&leaf_der, &[], &server_name, &[], now);

    assert!(
        result.is_ok(),
        "with time_validation off an expired cert must be downgraded and accepted, but verification returned Err: {:?}",
        result
    );
}

/// Guard: with validity-time checking off, an unknown CA still rejects.
///
/// `ignore_validity_time` downgrades validity-time errors only; a bad
/// signature or an unknown CA remains a rejection.
#[test]
fn bad_signature_with_time_validation_off_still_rejects() {
    // The leaf is signed by CA-A while the verifier trusts only CA-B, so the
    // chain is invalid for a reason unrelated to time.
    let (ca_a_der, leaf_der) = make_valid_ca_and_leaf("server.test");
    let (ca_b_der, _) = make_valid_ca_and_leaf("other.test");

    // The verifier trusts CA-B; the leaf was signed by CA-A.
    let inner = make_webpki_verifier(ca_b_der);

    // ignore_validity_time = true, that is time_validation = false
    let verifier = IgnoreValidityTimeServerVerifier::new(inner, true, Arc::new(NullEventHandler));

    let now = UnixTime::now();
    let server_name: ServerName<'static> = "server.test".try_into().unwrap();
    let result = verifier.verify_server_cert(&leaf_der, &[], &server_name, &[], now);

    // An unknown CA is not a validity-time problem, so it must reject.
    assert!(
        result.is_err(),
        "with time_validation off an unknown CA must still reject, but verification returned Ok"
    );

    // Consume ca_a_der so it is not reported as unused.
    let _ = ca_a_der;
}
