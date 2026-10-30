//! End-to-end handshakes over TCP between configurations built by
//! `TlsConfigBuilder`.
//!
//! Covered here: the cipher whitelist, validity time, client authentication
//! modes, session resumption, name checking, revocation and the events each
//! outcome raises.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use iec61850_tls::{
    TlsAcceptor, TlsConfigBuilder, TlsConnector, TlsError, TlsEventCode, TlsEventHandler,
    TlsEventLevel, TlsVersion, IEC62351_3_TLS12_CIPHERS,
};
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose, SanType,
    SerialNumber,
};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// -----------------------------------------------------------------------------
// PKI helpers
// -----------------------------------------------------------------------------

/// RSA 2048 key; ring cannot generate RSA keys.
const RSA_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDkbAV8LZqTrC1s
BlffbRZxLcmN6zzuL8fmpEFEi2mOVfAQnkZZh88nS32Tj8KrMVG/1EAljATOPXez
DukEU/UFna+xk1TP+HjqPhfDLIJdZKmTSQYLJpQz2R2eR2RPGir6MSSgguRynXwF
3BzcmOfxkapyipQBMkCahV83P7YQFE6drRiQojLX9wAW6I1bLzgyLjD/c1EmnQ0B
ZYQL6ZHa1NbgxCOCojqLVtgjBwgPW5zF4yHrmY+yTYxdwiQqxwi0TlgAbY2AJu2k
qDQMwOEGglTsX/M96OqkUfGf5fs8tf82NJgxITX5glQOQ5TP9B+3KpIcYUEu6VOZ
V6oxwHqFAgMBAAECggEADBEAwSyPi9l+lMRJBA55LwViLlMM5vAzOSXYJMzQiKpV
gis6QCSCdurv+UmQ2QZD8UQ/FzysTFDG7/iLqqTcvq0zyMelpU7U5FrfWnoRcOmO
Y69p2FDzZ0HC5MeUrvEM8CaEbs47TyqukIiuJaEWL5aoUGCtrNqAuyjsfLiq33J5
l7DIKXndpI9La5BtJDi1OclISI+VObHPsJjRPZ1zRmV+y2mxmbeCXqU7kG65UQtS
AymzCtZjHzIzvMLocyxhN8u3czTQA18jojG4F3o6XQVLjzriKzKfLEyPcL/d7LEh
r9O2GzvuGMukbWtv7yKgHnwr3rxjIugdqxMZ+IckiQKBgQD+g/zKlcS3DNUBTlN3
rBD9VNDaW/l5hd6aUrOutmGznH1At5GQBizqXptV+A4YD65kIqYQnC16T0KvpkSP
Crj1SccBFsg1u7dbqijjqqjYgMLYf130Wo84F8/5zFDtWndLiDJIDh4blsCl+4JM
ULbwK15jROxg1cc1rf3CrMEVBwKBgQDlwRL1hZXSR0rQk/HCq0i3NG9gQ1s+nR4t
4fm4dpt4zSX0cs+1sVJBq4E5SDvNjqP5Te0w61eHlwCWsWEZCc9XSQk+cT4sIDDw
FjNssJm+7ZfO6Q5QqoBq5r28Rv0es7qbWspqPl6MpvQrHGDCBXumqhgGZnLQuVFm
TE+fYDz9EwKBgEWZzo2P+2Wbirx6sPSvB05f3WV5dXW4GDHXn++NTJaTmuURziq2
pZ3KFWyjEyedUjFsEEHGk+E4v6HNND5xzja14Ef59PJMzU2x8NChoN7kB2SxH/5s
rXHHgUZsi0z9SlZLfoSZ573fsfsyFmXMRNrU4VEATiwFCh8x341XNM4NAoGAEevV
hsE8xoI5G7vuh7jEm0XDykZ2v5OR3xJZYEIgLnQSGdc6zHlgaS7vjYBM6ePOdovV
jJNO6Iymxxpe8I0LV0ujJPPAXcDFEHUq3beIxpPR25niO/iQu8Xz1tPSuqpaS/Px
BgiHZ4E+Wn6ELZ4v3vg1l4o2OoG6D7i0HUJsf3ECgYEAktf4+rXaJ5VTtVDBq93E
Zwsl9xI1RIneJcvmAAq2vxKVggHctd7LoyKv8+xreBTkA8nkeenkwBlFDlVbR92Q
WX803Btd4S1rdtDQ0+EVuPkAtDg1Y5LW7daGVM641wE2xQG8TbQUfJsBBPAR1OSk
W/za9+XssFmMrTy9l8TLvII=
-----END PRIVATE KEY-----";

const SERVER_NAME: &str = "server.test";

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

impl Ca {
    fn new() -> Self {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let cert = params.self_signed(&key).unwrap();
        Self { cert, key }
    }

    fn pem(&self) -> String {
        self.cert.pem()
    }

    /// Issues a leaf for `name` with the given serial number.
    fn leaf(&self, name: &str, serial: u64) -> Leaf {
        self.issue(name, serial, LeafKind::default())
    }

    fn issue(&self, name: &str, serial: u64, kind: LeafKind) -> Leaf {
        let key = if kind.rsa {
            KeyPair::from_pem(RSA_KEY).unwrap()
        } else {
            KeyPair::generate().unwrap()
        };
        let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
        params.subject_alt_names = vec![SanType::DnsName(name.try_into().unwrap())];
        params.serial_number = Some(SerialNumber::from(serial));
        if kind.expired {
            params.not_before = date_time_ymd(2000, 1, 1);
            params.not_after = date_time_ymd(2001, 1, 1);
        }
        let cert = params.signed_by(&key, &self.cert, &self.key).unwrap();
        Leaf {
            pem: cert.pem(),
            key_pem: key.serialize_pem(),
            der: CertificateDer::from(cert.der().to_vec()),
        }
    }
}

#[derive(Default, Clone, Copy)]
struct LeafKind {
    rsa: bool,
    expired: bool,
}

struct Leaf {
    pem: String,
    key_pem: String,
    der: CertificateDer<'static>,
}

/// A server builder presenting `leaf`.
fn server_with(leaf: &Leaf) -> TlsConfigBuilder {
    TlsConfigBuilder::new()
        .with_cert_pem(leaf.pem.as_bytes(), leaf.key_pem.as_bytes())
        .unwrap()
}

/// A client builder trusting `ca`.
fn client_trusting(ca: &Ca) -> TlsConfigBuilder {
    TlsConfigBuilder::new()
        .add_ca_pem(ca.pem().as_bytes())
        .unwrap()
}

/// An RSA leaf for `name`, so TLS 1.2 handshakes do not depend on the ECDSA
/// suites.
fn rsa_leaf(ca: &Ca, name: &str) -> Leaf {
    ca.issue(
        name,
        1,
        LeafKind {
            rsa: true,
            ..LeafKind::default()
        },
    )
}

fn expired() -> LeafKind {
    LeafKind {
        expired: true,
        ..LeafKind::default()
    }
}

// -----------------------------------------------------------------------------
// Event recording
// -----------------------------------------------------------------------------

#[derive(Default)]
struct Recorder(Mutex<Vec<(TlsEventLevel, TlsEventCode)>>);

impl TlsEventHandler for Recorder {
    fn on_event(&self, level: TlsEventLevel, code: TlsEventCode, _message: &str) {
        self.0.lock().unwrap().push((level, code));
    }
}

impl Recorder {
    fn codes(&self) -> Vec<TlsEventCode> {
        self.0.lock().unwrap().iter().map(|(_, c)| *c).collect()
    }

    fn has(&self, level: TlsEventLevel, code: TlsEventCode) -> bool {
        self.0.lock().unwrap().contains(&(level, code))
    }
}

// -----------------------------------------------------------------------------
// Handshake driver
// -----------------------------------------------------------------------------

#[derive(Debug)]
struct ServerSide {
    peer_cert_presented: bool,
}

#[derive(Debug)]
struct ClientSide {
    version: Option<rustls::ProtocolVersion>,
}

/// Runs one handshake over loopback TCP, presenting `name` to the server, and
/// exchanges one byte each way.
async fn handshake_as(
    acceptor: TlsAcceptor,
    connector: &TlsConnector,
    name: &str,
) -> (Result<ServerSide, String>, Result<ClientSide, String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(tcp).await.map_err(|e| e.to_string())?;
        let peer_cert_presented = stream.get_ref().1.peer_certificates().is_some();
        let mut byte = [0u8; 1];
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| e.to_string())?;
        stream.write_all(&byte).await.map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;
        Ok(ServerSide {
            peer_cert_presented,
        })
    });
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from(name.to_string()).unwrap();
    let client = match connector.connect(name, tcp).await {
        Ok(mut stream) => {
            let conn = stream.get_ref().1;
            let version = conn.protocol_version();
            async {
                stream.write_all(&[7]).await?;
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).await?;
                Ok::<_, std::io::Error>(())
            }
            .await
            .map(|_| ClientSide { version })
            .map_err(|e| e.to_string())
        }
        Err(e) => Err(e.to_string()),
    };
    let server = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("server task finishes")
        .unwrap();
    (server, client)
}

async fn handshake(
    acceptor: TlsAcceptor,
    connector: &TlsConnector,
) -> (Result<ServerSide, String>, Result<ClientSide, String>) {
    handshake_as(acceptor, connector, SERVER_NAME).await
}

// -----------------------------------------------------------------------------
// Cipher whitelist
// -----------------------------------------------------------------------------

#[test]
fn tls12_whitelist_holds_ecdhe_rsa_and_ecdhe_ecdsa_with_aes_gcm() {
    use rustls::CipherSuite as S;
    let suites: Vec<S> = IEC62351_3_TLS12_CIPHERS.iter().map(|s| s.suite()).collect();
    assert_eq!(
        suites,
        vec![
            S::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            S::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            S::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            S::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        ]
    );
}

#[tokio::test]
async fn ecdsa_certificate_negotiates_tls12() {
    let ca = Ca::new();
    let leaf = ca.leaf(SERVER_NAME, 1);
    let server = server_with(&leaf)
        .max_version(TlsVersion::Tls12)
        .build_server()
        .unwrap();
    let client = client_trusting(&ca)
        .max_version(TlsVersion::Tls12)
        .build_client()
        .unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(srv.is_ok(), "server side: {srv:?}");
    assert_eq!(
        cli.expect("client side").version,
        Some(rustls::ProtocolVersion::TLSv1_2)
    );
}

#[tokio::test]
async fn rsa_certificate_negotiates_tls12() {
    let ca = Ca::new();
    let leaf = rsa_leaf(&ca, SERVER_NAME);
    let server = server_with(&leaf)
        .max_version(TlsVersion::Tls12)
        .build_server()
        .unwrap();
    let client = client_trusting(&ca)
        .max_version(TlsVersion::Tls12)
        .build_client()
        .unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(srv.is_ok(), "server side: {srv:?}");
    assert_eq!(
        cli.expect("client side").version,
        Some(rustls::ProtocolVersion::TLSv1_2)
    );
}

// -----------------------------------------------------------------------------
// Validity time
// -----------------------------------------------------------------------------

#[tokio::test]
async fn client_with_time_validation_off_accepts_an_expired_certificate_from_its_ca() {
    let ca = Ca::new();
    let leaf = ca.issue(SERVER_NAME, 1, expired());
    let events = Arc::new(Recorder::default());
    let server = server_with(&leaf).build_server().unwrap();
    let client = client_trusting(&ca)
        .time_validation(false)
        .with_event_handler(events.clone())
        .build_client()
        .unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(srv.is_ok() && cli.is_ok(), "server={srv:?} client={cli:?}");
    assert!(
        events.has(TlsEventLevel::Warning, TlsEventCode::WrnCertExpired),
        "events: {:?}",
        events.codes()
    );
}

#[tokio::test]
async fn client_with_time_validation_off_rejects_an_expired_certificate_from_an_untrusted_ca() {
    let trusted_ca = Ca::new();
    let rogue_ca = Ca::new();
    let rogue_leaf = rogue_ca.issue(SERVER_NAME, 1, expired());
    let events = Arc::new(Recorder::default());
    let server = server_with(&rogue_leaf).build_server().unwrap();
    let client = client_trusting(&trusted_ca)
        .time_validation(false)
        .with_event_handler(events.clone())
        .build_client()
        .unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(
        srv.is_err() && cli.is_err(),
        "server={srv:?} client={cli:?}"
    );
    assert!(
        !events.codes().contains(&TlsEventCode::WrnCertExpired),
        "events: {:?}",
        events.codes()
    );
}

#[tokio::test]
async fn expired_unknown_server_is_refused_in_allow_only_known_mode_with_time_validation_off() {
    let ca = Ca::new();
    let known = ca.leaf(SERVER_NAME, 1);
    let expired_other = ca.issue(SERVER_NAME, 2, expired());
    let events = Arc::new(Recorder::default());
    let server = server_with(&expired_other).build_server().unwrap();
    let client = client_trusting(&ca)
        .add_known_peer_der(known.der.clone())
        .allow_only_known_peers(true)
        .time_validation(false)
        .with_event_handler(events.clone())
        .build_client()
        .unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(
        srv.is_err() && cli.is_err(),
        "server={srv:?} client={cli:?}"
    );
    assert!(
        events.has(TlsEventLevel::Incident, TlsEventCode::AlmCertNotConfigured),
        "events: {:?}",
        events.codes()
    );
}

#[tokio::test]
async fn server_with_time_validation_off_accepts_an_expired_client_certificate() {
    let server_ca = Ca::new();
    let client_ca = Ca::new();
    let server_leaf = server_ca.leaf(SERVER_NAME, 1);
    let client_leaf = client_ca.issue("client.test", 2, expired());
    let events = Arc::new(Recorder::default());
    let server = server_with(&server_leaf)
        .add_ca_pem(client_ca.pem().as_bytes())
        .unwrap()
        .time_validation(false)
        .with_event_handler(events.clone())
        .build_server()
        .unwrap();
    let client = client_trusting(&server_ca)
        .with_cert_pem(client_leaf.pem.as_bytes(), client_leaf.key_pem.as_bytes())
        .unwrap()
        .build_client()
        .unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(srv.expect("server side").peer_cert_presented);
    assert!(cli.is_ok(), "client side: {cli:?}");
    assert!(
        events.has(TlsEventLevel::Warning, TlsEventCode::WrnCertExpired),
        "events: {:?}",
        events.codes()
    );
}

#[tokio::test]
async fn server_with_time_validation_on_rejects_an_expired_client_certificate() {
    let server_ca = Ca::new();
    let client_ca = Ca::new();
    let server_leaf = server_ca.leaf(SERVER_NAME, 1);
    let client_leaf = client_ca.issue("client.test", 2, expired());
    let server = server_with(&server_leaf)
        .add_ca_pem(client_ca.pem().as_bytes())
        .unwrap()
        .build_server()
        .unwrap();
    let client = client_trusting(&server_ca)
        .with_cert_pem(client_leaf.pem.as_bytes(), client_leaf.key_pem.as_bytes())
        .unwrap()
        .build_client()
        .unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(
        srv.is_err() && cli.is_err(),
        "server={srv:?} client={cli:?}"
    );
}

#[tokio::test]
async fn server_with_time_validation_off_rejects_an_expired_client_certificate_from_an_untrusted_ca(
) {
    let server_ca = Ca::new();
    let client_ca = Ca::new();
    let rogue_ca = Ca::new();
    let server_leaf = server_ca.leaf(SERVER_NAME, 1);
    let rogue_leaf = rogue_ca.issue("client.test", 2, expired());
    let server = server_with(&server_leaf)
        .add_ca_pem(client_ca.pem().as_bytes())
        .unwrap()
        .time_validation(false)
        .build_server()
        .unwrap();
    let client = client_trusting(&server_ca)
        .with_cert_pem(rogue_leaf.pem.as_bytes(), rogue_leaf.key_pem.as_bytes())
        .unwrap()
        .build_client()
        .unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(
        srv.is_err() && cli.is_err(),
        "server={srv:?} client={cli:?}"
    );
}

// -----------------------------------------------------------------------------
// Client authentication
// -----------------------------------------------------------------------------

#[tokio::test]
async fn client_without_certificate_is_refused_when_only_known_peers_are_allowed() {
    let server_ca = Ca::new();
    let client_ca = Ca::new();
    let server_leaf = server_ca.leaf(SERVER_NAME, 1);
    let known_client = client_ca.leaf("client.test", 2);
    let server = server_with(&server_leaf)
        .add_ca_pem(client_ca.pem().as_bytes())
        .unwrap()
        .add_known_peer_der(known_client.der.clone())
        .allow_only_known_peers(true)
        .build_server()
        .unwrap();
    let client = client_trusting(&server_ca).build_client().unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(
        srv.is_err() && cli.is_err(),
        "a client without a certificate got through: server={srv:?} client={cli:?}"
    );
}

#[tokio::test]
async fn known_client_certificate_is_accepted_when_only_known_peers_are_allowed() {
    let server_ca = Ca::new();
    let client_ca = Ca::new();
    let server_leaf = server_ca.leaf(SERVER_NAME, 1);
    let known_client = client_ca.leaf("client.test", 2);
    let server = server_with(&server_leaf)
        .add_ca_pem(client_ca.pem().as_bytes())
        .unwrap()
        .add_known_peer_der(known_client.der.clone())
        .allow_only_known_peers(true)
        .build_server()
        .unwrap();
    let client = client_trusting(&server_ca)
        .with_cert_pem(known_client.pem.as_bytes(), known_client.key_pem.as_bytes())
        .unwrap()
        .build_client()
        .unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(srv.expect("server side").peer_cert_presented);
    assert!(cli.is_ok(), "client side: {cli:?}");
}

#[tokio::test]
async fn unknown_client_certificate_is_refused_when_only_known_peers_are_allowed() {
    let server_ca = Ca::new();
    let client_ca = Ca::new();
    let server_leaf = server_ca.leaf(SERVER_NAME, 1);
    let known_client = client_ca.leaf("client.test", 2);
    let other_client = client_ca.leaf("other.test", 3);
    let server = server_with(&server_leaf)
        .add_ca_pem(client_ca.pem().as_bytes())
        .unwrap()
        .add_known_peer_der(known_client.der.clone())
        .allow_only_known_peers(true)
        .build_server()
        .unwrap();
    let client = client_trusting(&server_ca)
        .with_cert_pem(other_client.pem.as_bytes(), other_client.key_pem.as_bytes())
        .unwrap()
        .build_client()
        .unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(
        srv.is_err() && cli.is_err(),
        "server={srv:?} client={cli:?}"
    );
}

#[tokio::test]
async fn client_without_certificate_is_refused_when_client_auth_is_required() {
    let server_ca = Ca::new();
    let client_ca = Ca::new();
    let server_leaf = server_ca.leaf(SERVER_NAME, 1);
    let server = server_with(&server_leaf)
        .add_ca_pem(client_ca.pem().as_bytes())
        .unwrap()
        .require_client_auth(true)
        .build_server()
        .unwrap();
    let client = client_trusting(&server_ca).build_client().unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(
        srv.is_err() && cli.is_err(),
        "server={srv:?} client={cli:?}"
    );
}

#[tokio::test]
async fn client_with_certificate_is_accepted_when_client_auth_is_required() {
    let server_ca = Ca::new();
    let client_ca = Ca::new();
    let server_leaf = server_ca.leaf(SERVER_NAME, 1);
    let client_leaf = client_ca.leaf("client.test", 2);
    let server = server_with(&server_leaf)
        .add_ca_pem(client_ca.pem().as_bytes())
        .unwrap()
        .require_client_auth(true)
        .build_server()
        .unwrap();
    let client = client_trusting(&server_ca)
        .with_cert_pem(client_leaf.pem.as_bytes(), client_leaf.key_pem.as_bytes())
        .unwrap()
        .build_client()
        .unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(srv.expect("server side").peer_cert_presented);
    assert!(cli.is_ok(), "client side: {cli:?}");
}

#[tokio::test]
async fn client_without_certificate_is_accepted_when_client_auth_is_optional() {
    let server_ca = Ca::new();
    let client_ca = Ca::new();
    let server_leaf = server_ca.leaf(SERVER_NAME, 1);
    let server = server_with(&server_leaf)
        .add_ca_pem(client_ca.pem().as_bytes())
        .unwrap()
        .build_server()
        .unwrap();
    let client = client_trusting(&server_ca).build_client().unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(!srv.expect("server side").peer_cert_presented);
    assert!(cli.is_ok(), "client side: {cli:?}");
}

#[tokio::test]
async fn server_without_trust_anchors_requests_no_client_certificate() {
    let server_ca = Ca::new();
    let client_ca = Ca::new();
    let server_leaf = server_ca.leaf(SERVER_NAME, 1);
    let client_leaf = client_ca.leaf("client.test", 2);
    let server = server_with(&server_leaf)
        .build_server()
        .expect("a server without trust anchors builds");
    let client = client_trusting(&server_ca)
        .with_cert_pem(client_leaf.pem.as_bytes(), client_leaf.key_pem.as_bytes())
        .unwrap()
        .build_client()
        .unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(!srv.expect("server side").peer_cert_presented);
    assert!(cli.is_ok(), "client side: {cli:?}");
}

#[test]
fn mandatory_client_auth_without_trust_anchors_fails_to_build() {
    let server_ca = Ca::new();
    let server_leaf = server_ca.leaf(SERVER_NAME, 1);
    let required = server_with(&server_leaf)
        .require_client_auth(true)
        .build_server();
    let known_only = server_with(&server_leaf)
        .add_known_peer_der(server_leaf.der.clone())
        .allow_only_known_peers(true)
        .build_server();
    assert!(matches!(required, Err(TlsError::Validation(_))));
    assert!(matches!(known_only, Err(TlsError::Validation(_))));
}
