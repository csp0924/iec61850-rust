//! Tests for the PEM loaders behind the `*_pem` builder methods.
//!
//! They pin the accepted input classes: a bundle holding several
//! `CERTIFICATE` sections, the three private-key encodings the loader takes
//! (PKCS#8, PKCS#1, SEC1), and the rule that a section of an unrelated kind is
//! skipped rather than rejected. The error branches are pinned by their
//! `TlsError` variant and message.
//!
//! Key and CRL bodies are synthetic: the loaders classify a section and
//! base64-decode it, and leave DER validation to rustls, so a short body
//! exercises the same path a real key does.

use rcgen::{CertificateParams, DnType, KeyPair};
use rustls_pki_types::PrivateKeyDer;

use crate::config::{load_cert_chain_pem, load_crls_pem, load_private_key_pem, TlsConfigBuilder};
use crate::error::TlsError;

// -----------------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------------

/// A PKCS#1 body and its base64 form.
const PKCS1_DER: &[u8] = &[0x30, 0x82, 0x01, 0x00, 0x0a, 0x0b];
const PKCS1_B64: &str = "MIIBAAoL";

/// A SEC1 body and its base64 form.
const SEC1_DER: &[u8] = &[0x30, 0x77, 0x02, 0x01, 0x01];
const SEC1_B64: &str = "MHcCAQE=";

/// A second SEC1 body, used to check which key section wins.
const SEC1_ALT_DER: &[u8] = &[0x30, 0x2e, 0x02, 0x01, 0x00];
const SEC1_ALT_B64: &str = "MC4CAQA=";

/// Two CRL bodies and their base64 forms.
const CRL_A_DER: &[u8] = &[0x30, 0x10, 0x11, 0x12];
const CRL_A_B64: &str = "MBAREg==";
const CRL_B_DER: &[u8] = &[0x30, 0x20, 0x21, 0x22];
const CRL_B_B64: &str = "MCAhIg==";

/// Generates one self-signed certificate, returning its PEM and DER forms.
fn self_signed(common_name: &str) -> (String, Vec<u8>) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![common_name.to_string()]).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    let cert = params.self_signed(&key).unwrap();
    (cert.pem(), cert.der().to_vec())
}

/// Wraps an already base64-encoded body in a PEM section with `label`.
fn pem_section(label: &str, body_b64: &str) -> String {
    format!("-----BEGIN {label}-----\n{body_b64}\n-----END {label}-----\n")
}

// -----------------------------------------------------------------------------
// Certificate chains
// -----------------------------------------------------------------------------

#[test]
fn cert_bundle_yields_every_certificate_in_file_order() {
    let (pem_a, der_a) = self_signed("leaf.example");
    let (pem_b, der_b) = self_signed("issuer.example");
    let bundle = format!("{pem_a}{pem_b}");

    let certs = load_cert_chain_pem(bundle.as_bytes()).unwrap();

    assert_eq!(certs.len(), 2);
    assert_eq!(certs[0].as_ref(), der_a.as_slice());
    assert_eq!(certs[1].as_ref(), der_b.as_slice());
}

#[test]
fn cert_loader_skips_sections_of_other_kinds() {
    let (cert_pem, der) = self_signed("leaf.example");
    let bundle = format!(
        "{}{}{}",
        pem_section("PRIVATE KEY", SEC1_B64),
        cert_pem,
        pem_section("X509 CRL", CRL_A_B64)
    );

    let certs = load_cert_chain_pem(bundle.as_bytes()).unwrap();

    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].as_ref(), der.as_slice());
}

#[test]
fn cert_loader_rejects_pem_without_a_certificate() {
    let key_only = pem_section("PRIVATE KEY", SEC1_B64);

    let err = load_cert_chain_pem(key_only.as_bytes()).unwrap_err();

    assert!(
        matches!(&err, TlsError::CertLoad(m) if m == "no certificates found in PEM"),
        "unexpected error: {err}"
    );
}

#[test]
fn cert_loader_reports_a_truncated_section_as_a_parse_failure() {
    let truncated = "-----BEGIN CERTIFICATE-----\nMBAREg==\n";

    let err = load_cert_chain_pem(truncated.as_bytes()).unwrap_err();

    assert!(
        matches!(&err, TlsError::CertLoad(m) if m.starts_with("parse cert PEM: ")),
        "unexpected error: {err}"
    );
}

// -----------------------------------------------------------------------------
// Private keys
// -----------------------------------------------------------------------------

#[test]
fn key_loader_accepts_a_pkcs8_section() {
    let key = KeyPair::generate().unwrap();

    let loaded = load_private_key_pem(key.serialize_pem().as_bytes()).unwrap();

    assert!(matches!(loaded, PrivateKeyDer::Pkcs8(_)));
    assert_eq!(loaded.secret_der(), key.serialized_der());
}

#[test]
fn key_loader_accepts_a_pkcs1_section() {
    let pem = pem_section("RSA PRIVATE KEY", PKCS1_B64);

    let loaded = load_private_key_pem(pem.as_bytes()).unwrap();

    assert!(matches!(loaded, PrivateKeyDer::Pkcs1(_)));
    assert_eq!(loaded.secret_der(), PKCS1_DER);
}

#[test]
fn key_loader_accepts_a_sec1_section() {
    let pem = pem_section("EC PRIVATE KEY", SEC1_B64);

    let loaded = load_private_key_pem(pem.as_bytes()).unwrap();

    assert!(matches!(loaded, PrivateKeyDer::Sec1(_)));
    assert_eq!(loaded.secret_der(), SEC1_DER);
}

#[test]
fn key_loader_takes_the_first_key_after_skipping_a_certificate() {
    let (cert_pem, _) = self_signed("leaf.example");
    let bundle = format!(
        "{}{}{}",
        cert_pem,
        pem_section("EC PRIVATE KEY", SEC1_ALT_B64),
        pem_section("RSA PRIVATE KEY", PKCS1_B64)
    );

    let loaded = load_private_key_pem(bundle.as_bytes()).unwrap();

    assert!(matches!(loaded, PrivateKeyDer::Sec1(_)));
    assert_eq!(loaded.secret_der(), SEC1_ALT_DER);
}

#[test]
fn key_loader_rejects_pem_without_a_key() {
    let (cert_pem, _) = self_signed("leaf.example");

    let err = load_private_key_pem(cert_pem.as_bytes()).unwrap_err();

    assert!(
        matches!(&err, TlsError::CertLoad(m) if m == "no private key found in PEM"),
        "unexpected error: {err}"
    );
}

#[test]
fn key_loader_reports_a_truncated_section_as_a_parse_failure() {
    let truncated = "-----BEGIN PRIVATE KEY-----\nMBAREg==\n";

    let err = load_private_key_pem(truncated.as_bytes()).unwrap_err();

    assert!(
        matches!(&err, TlsError::CertLoad(m) if m.starts_with("parse key PEM: ")),
        "unexpected error: {err}"
    );
}

#[test]
fn cert_and_key_load_together_through_the_builder() {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["leaf.example".to_string()]).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "leaf.example");
    let cert = params.self_signed(&key).unwrap();

    TlsConfigBuilder::new()
        .with_cert_pem(cert.pem().as_bytes(), key.serialize_pem().as_bytes())
        .unwrap();
}

// -----------------------------------------------------------------------------
// Certificate revocation lists
// -----------------------------------------------------------------------------

#[test]
fn crl_bundle_yields_every_crl_in_file_order() {
    let (cert_pem, _) = self_signed("leaf.example");
    let bundle = format!(
        "{}{}{}",
        cert_pem,
        pem_section("X509 CRL", CRL_A_B64),
        pem_section("X509 CRL", CRL_B_B64)
    );

    let crls = load_crls_pem(bundle.as_bytes()).unwrap();

    assert_eq!(crls.len(), 2);
    assert_eq!(crls[0].as_ref(), CRL_A_DER);
    assert_eq!(crls[1].as_ref(), CRL_B_DER);
}

#[test]
fn crl_loader_skips_sections_of_other_kinds() {
    let (cert_pem, _) = self_signed("leaf.example");
    let key_section = pem_section("PRIVATE KEY", SEC1_B64);
    let no_crls = format!("{cert_pem}{key_section}");

    let crls = load_crls_pem(no_crls.as_bytes()).unwrap();

    // A PEM carrying no CRL is accepted and contributes nothing, rather than
    // being rejected.
    assert!(crls.is_empty());
    TlsConfigBuilder::new()
        .add_crl_pem(no_crls.as_bytes())
        .unwrap();
}

#[test]
fn crl_loader_reports_a_truncated_section_as_a_crl_error() {
    let truncated = "-----BEGIN X509 CRL-----\nMBAREg==\n";

    let err = load_crls_pem(truncated.as_bytes()).unwrap_err();

    assert!(
        matches!(&err, TlsError::CrlError(m) if m.starts_with("parse CRL PEM: ")),
        "unexpected error: {err}"
    );
}
