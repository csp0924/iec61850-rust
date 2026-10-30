//! Regression tests for ignoring certificate validity time.
//!
//! The malformed-input class: a peer presents a certificate that has expired
//! or is not valid yet. Required outcome: with `time_validation=false` such a
//! certificate is accepted only when it passes every other check at a time
//! inside its validity period, so a bad signature, a revoked certificate or an
//! unknown CA still rejects.
//!
//! Covered here, for the server and the client certificate: expiry rejects
//! with validity-time checking on; expiry is allowed with it off; an unknown
//! CA still rejects with it off, also when the certificate has expired; a
//! certificate not valid yet is allowed with it off; and an expiry error
//! without a validity period rejects.

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

/// With validity-time checking off, an expired leaf from an untrusted CA still
/// rejects: the expiry is checked before the signature chain, so accepting the
/// expiry error alone would skip chain validation.
#[test]
fn expired_cert_from_an_untrusted_ca_with_time_validation_off_rejects() {
    let (_, rogue_leaf_der) = make_expired_ca_and_leaf("server.test");
    let (trusted_ca_der, _) = make_valid_ca_and_leaf("server.test");
    let inner = make_webpki_verifier(trusted_ca_der);

    let verifier = IgnoreValidityTimeServerVerifier::new(inner, true, Arc::new(NullEventHandler));

    let server_name: ServerName<'static> = "server.test".try_into().unwrap();
    let result =
        verifier.verify_server_cert(&rogue_leaf_der, &[], &server_name, &[], UnixTime::now());

    assert!(
        matches!(
            result,
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer | rustls::CertificateError::BadSignature
            ))
        ),
        "an expired leaf from an untrusted CA must reject as untrusted, got {:?}",
        result
    );
}

/// With validity-time checking off, a certificate that is not valid yet is
/// accepted once its chain verifies.
#[test]
fn not_yet_valid_cert_with_time_validation_off_passes() {
    let (ca_der, leaf_der) = make_valid_ca_and_leaf("server.test");
    let inner = make_webpki_verifier(ca_der);

    let verifier = IgnoreValidityTimeServerVerifier::new(inner, true, Arc::new(NullEventHandler));

    // Before the rcgen default not_before of 1975-01-01.
    let before_validity = UnixTime::since_unix_epoch(std::time::Duration::from_secs(86_400));
    let server_name: ServerName<'static> = "server.test".try_into().unwrap();
    let result = verifier.verify_server_cert(&leaf_der, &[], &server_name, &[], before_validity);

    assert!(result.is_ok(), "got {:?}", result);
}

/// Builds a CA signed by `root` and valid from `not_before` to `not_after`.
fn make_intermediate(
    root: &rcgen::Certificate,
    root_key: &KeyPair,
    not_before: (i32, u8, u8),
    not_after: (i32, u8, u8),
) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "intermediate");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.not_before = date_time_ymd(not_before.0, not_before.1, not_before.2);
    params.not_after = date_time_ymd(not_after.0, not_after.1, not_after.2);
    let cert = params.signed_by(&key, root, root_key).unwrap();
    (cert, key)
}

/// With validity-time checking off, a chain whose leaf and intermediate have
/// both expired, at different times, is accepted: the leaf expiry moves the
/// validation time to its not_after, where the intermediate has expired, and
/// that moves it to the intermediate's not_after, where both are valid. With
/// validity-time checking on, the same chain rejects.
#[test]
fn chain_needing_three_verifications_with_time_validation_off_passes() {
    let root_key = KeyPair::generate().unwrap();
    let mut root_params = CertificateParams::default();
    root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let root = root_params.self_signed(&root_key).unwrap();
    let root_der = CertificateDer::from(root.der().to_vec()).into_owned();

    let (inter, inter_key) = make_intermediate(&root, &root_key, (1999, 1, 1), (2002, 1, 1));
    let inter_der = CertificateDer::from(inter.der().to_vec()).into_owned();

    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::new(vec!["server.test".to_string()]).unwrap();
    leaf_params.not_before = date_time_ymd(2000, 1, 1);
    leaf_params.not_after = date_time_ymd(2003, 1, 1);
    let leaf = leaf_params
        .signed_by(&leaf_key, &inter, &inter_key)
        .unwrap();
    let leaf_der = CertificateDer::from(leaf.der().to_vec()).into_owned();

    let server_name: ServerName<'static> = "server.test".try_into().unwrap();
    let relaxed = IgnoreValidityTimeServerVerifier::new(
        make_webpki_verifier(root_der.clone()),
        true,
        Arc::new(NullEventHandler),
    );
    let strict = IgnoreValidityTimeServerVerifier::new(
        make_webpki_verifier(root_der),
        false,
        Arc::new(NullEventHandler),
    );
    let intermediates = [inter_der];

    let result = relaxed.verify_server_cert(
        &leaf_der,
        &intermediates,
        &server_name,
        &[],
        UnixTime::now(),
    );
    assert!(result.is_ok(), "got {:?}", result);
    assert!(strict
        .verify_server_cert(
            &leaf_der,
            &intermediates,
            &server_name,
            &[],
            UnixTime::now()
        )
        .is_err());
}

/// An inner verifier that reports expiry with no validity period cannot be
/// verified again, so its error rejects.
#[test]
fn expiry_without_context_with_time_validation_off_rejects() {
    #[derive(Debug)]
    struct AlwaysExpired;

    impl ServerCertVerifier for AlwaysExpired {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Expired,
            ))
        }

        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::General("unused".into()))
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::General("unused".into()))
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            Vec::new()
        }
    }

    let (_, leaf_der) = make_valid_ca_and_leaf("server.test");
    let verifier = IgnoreValidityTimeServerVerifier::new(
        Arc::new(AlwaysExpired),
        true,
        Arc::new(NullEventHandler),
    );

    let server_name: ServerName<'static> = "server.test".try_into().unwrap();
    let result = verifier.verify_server_cert(&leaf_der, &[], &server_name, &[], UnixTime::now());

    assert!(result.is_err());
}

/// Builds a `WebPkiClientVerifier` that trusts `ca_cert` and requires a
/// client certificate.
fn make_client_verifier(
    ca_cert: CertificateDer<'static>,
) -> Arc<dyn rustls::server::danger::ClientCertVerifier> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut root_store = RootCertStore::empty();
    root_store.add(ca_cert).unwrap();
    rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(root_store), provider)
        .build()
        .unwrap()
}

/// The client-certificate counterpart accepts an expired certificate from a
/// trusted CA with validity-time checking off.
#[test]
fn expired_client_cert_with_time_validation_off_passes() {
    use rustls::server::danger::ClientCertVerifier;

    let (ca_der, leaf_der) = make_expired_ca_and_leaf("client.test");
    let verifier = crate::verifier::IgnoreValidityTimeClientVerifier::new(
        make_client_verifier(ca_der),
        true,
        Arc::new(NullEventHandler),
    );

    let result = verifier.verify_client_cert(&leaf_der, &[], UnixTime::now());

    assert!(result.is_ok(), "got {:?}", result);
    assert!(verifier.client_auth_mandatory());
}

/// The client-certificate counterpart still rejects an expired certificate
/// from an untrusted CA with validity-time checking off.
#[test]
fn expired_client_cert_from_an_untrusted_ca_with_time_validation_off_rejects() {
    use rustls::server::danger::ClientCertVerifier;

    let (_, rogue_leaf_der) = make_expired_ca_and_leaf("client.test");
    let (trusted_ca_der, _) = make_valid_ca_and_leaf("client.test");
    let verifier = crate::verifier::IgnoreValidityTimeClientVerifier::new(
        make_client_verifier(trusted_ca_der),
        true,
        Arc::new(NullEventHandler),
    );

    let result = verifier.verify_client_cert(&rogue_leaf_der, &[], UnixTime::now());

    assert!(result.is_err());
}

/// The client-certificate counterpart rejects an expired certificate with
/// validity-time checking on.
#[test]
fn expired_client_cert_with_time_validation_on_rejects() {
    use rustls::server::danger::ClientCertVerifier;

    let (ca_der, leaf_der) = make_expired_ca_and_leaf("client.test");
    let verifier = crate::verifier::IgnoreValidityTimeClientVerifier::new(
        make_client_verifier(ca_der),
        false,
        Arc::new(NullEventHandler),
    );

    let result = verifier.verify_client_cert(&leaf_der, &[], UnixTime::now());

    assert!(result.is_err());
}
