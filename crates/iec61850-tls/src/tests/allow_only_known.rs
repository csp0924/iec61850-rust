//! Regression tests for allow-only-known certificates.
//!
//! The malformed-configuration class: a peer presents a leaf certificate that
//! is not on the configured allow list, or the allow list is empty. Required
//! outcome: the handshake is rejected. An empty list must not be read as
//! "allow every peer".
//!
//! Covered here: an empty list rejects; a leaf on the list is accepted once
//! chain validation passes; a leaf absent from the list is rejected; and with
//! the mode disabled only chain validation runs.

use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::{
    client::danger::ServerCertVerifier,
    pki_types::{CertificateDer, ServerName, UnixTime},
    CertificateError, Error as RustlsError, RootCertStore,
};

use crate::{event::NullEventHandler, verifier::AllowOnlyKnownCertsServerVerifier};

// -----------------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------------

/// Builds a self-signed CA and one server leaf certificate, returning
/// (ca_cert_der, leaf_cert_der, ca_cert, ca_key).
fn make_ca_and_leaf(
    dns_name: &str,
) -> (
    CertificateDer<'static>,
    CertificateDer<'static>,
    rcgen::Certificate,
    KeyPair,
) {
    // Certificate authority
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec()).into_owned();

    // Leaf certificate
    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::new(vec![dns_name.to_string()]).unwrap();
    leaf_params.subject_alt_names = vec![SanType::DnsName(dns_name.try_into().unwrap())];
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
    let leaf_cert_der = CertificateDer::from(leaf_cert.der().to_vec()).into_owned();

    (ca_cert_der, leaf_cert_der, ca_cert, ca_key)
}

/// Builds a `WebPkiServerVerifier` that trusts `ca_cert`.
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

/// `allow_only_known` with an empty list rejects.
///
/// An empty list means no peer is allowed, never that every peer is.
#[test]
fn allow_only_known_empty_list_rejects() {
    let (ca_der, leaf_der, _, _) = make_ca_and_leaf("server.test");
    let inner = make_webpki_verifier(ca_der);

    let verifier = AllowOnlyKnownCertsServerVerifier::new(
        inner,
        true,   // allow_only_known = true
        vec![], // empty list
        Arc::new(NullEventHandler),
    );

    let now = UnixTime::now();
    let server_name: ServerName<'static> = "server.test".try_into().unwrap();
    let result = verifier.verify_server_cert(&leaf_der, &[], &server_name, &[], now);

    assert!(
        result.is_err(),
        "an empty known list must reject, but verification returned Ok"
    );
    assert!(
        matches!(
            result.unwrap_err(),
            RustlsError::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
        ),
        "the error must be ApplicationVerificationFailure"
    );
}

/// `allow_only_known` with the leaf on the list accepts.
#[test]
fn allow_only_known_peer_in_list_accepts() {
    let (ca_der, leaf_der, _, _) = make_ca_and_leaf("server.test");
    let inner = make_webpki_verifier(ca_der);

    // Put the leaf on the known list.
    let known_list = vec![leaf_der.clone()];
    let verifier =
        AllowOnlyKnownCertsServerVerifier::new(inner, true, known_list, Arc::new(NullEventHandler));

    let now = UnixTime::now();
    let server_name: ServerName<'static> = "server.test".try_into().unwrap();
    let result = verifier.verify_server_cert(&leaf_der, &[], &server_name, &[], now);

    assert!(
        result.is_ok(),
        "a leaf on the known list must be accepted, but verification returned Err: {:?}",
        result
    );
}

/// `allow_only_known` with the leaf absent rejects.
#[test]
fn allow_only_known_peer_not_in_list_rejects() {
    let (ca_der, leaf_der, ca_cert, ca_key) = make_ca_and_leaf("server.test");

    // A second certificate, different from the leaf, goes on the known list.
    let other_key = KeyPair::generate().unwrap();
    let other_params = CertificateParams::new(vec!["other.test".to_string()]).unwrap();
    let other_cert = other_params
        .signed_by(&other_key, &ca_cert, &ca_key)
        .unwrap();
    let other_der = CertificateDer::from(other_cert.der().to_vec()).into_owned();

    let inner = make_webpki_verifier(ca_der);

    // The known list holds only the other certificate, not the leaf.
    let known_list = vec![other_der];
    let verifier =
        AllowOnlyKnownCertsServerVerifier::new(inner, true, known_list, Arc::new(NullEventHandler));

    let now = UnixTime::now();
    let server_name: ServerName<'static> = "server.test".try_into().unwrap();
    let result = verifier.verify_server_cert(&leaf_der, &[], &server_name, &[], now);

    assert!(
        result.is_err(),
        "a leaf absent from the known list must reject, but verification returned Ok"
    );
}

/// With allow_only_known disabled, only chain validation runs.
#[test]
fn allow_only_known_disabled_passes_chain_only() {
    let (ca_der, leaf_der, _, _) = make_ca_and_leaf("server.test");
    let inner = make_webpki_verifier(ca_der);

    // allow_only_known is false, so the empty list must not cause a rejection.
    let verifier = AllowOnlyKnownCertsServerVerifier::new(
        inner,
        false, // allow_only_known = false
        vec![],
        Arc::new(NullEventHandler),
    );

    let now = UnixTime::now();
    let server_name: ServerName<'static> = "server.test".try_into().unwrap();
    let result = verifier.verify_server_cert(&leaf_der, &[], &server_name, &[], now);

    assert!(
        result.is_ok(),
        "with allow_only_known off only chain validation applies, but verification returned Err: {:?}",
        result
    );
}
