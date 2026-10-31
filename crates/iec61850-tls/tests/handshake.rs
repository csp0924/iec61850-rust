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
    date_time_ymd, BasicConstraints, CertificateParams, CertificateRevocationListParams, IsCa,
    KeyIdMethod, KeyPair, KeyUsagePurpose, RevokedCertParams, SanType, SerialNumber,
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

    /// A CRL revoking the given serial numbers, valid until 2099.
    fn crl(&self, revoked: &[u64]) -> String {
        let params = CertificateRevocationListParams {
            this_update: date_time_ymd(2020, 1, 1),
            next_update: date_time_ymd(2099, 1, 1),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: revoked
                .iter()
                .map(|serial| RevokedCertParams {
                    serial_number: SerialNumber::from(*serial),
                    revocation_time: date_time_ymd(2020, 1, 1),
                    reason_code: None,
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: KeyIdMethod::Sha256,
        };
        params
            .signed_by(&self.cert, &self.key)
            .unwrap()
            .pem()
            .unwrap()
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
    resumed: bool,
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
            let resumed = conn.handshake_kind() == Some(rustls::HandshakeKind::Resumed);
            let version = conn.protocol_version();
            async {
                stream.write_all(&[7]).await?;
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).await?;
                Ok::<_, std::io::Error>(())
            }
            .await
            .map(|_| ClientSide { resumed, version })
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

// -----------------------------------------------------------------------------
// Session resumption
// -----------------------------------------------------------------------------

/// Runs two handshakes with one connector against an RSA server, so TLS 1.2
/// is available whatever the suites, and reports whether the second one
/// resumed.
async fn second_handshake_resumed(
    server: impl Fn(&Leaf) -> TlsConfigBuilder,
    max: TlsVersion,
) -> bool {
    let ca = Ca::new();
    let leaf = rsa_leaf(&ca, SERVER_NAME);
    let acceptor = TlsAcceptor::new(server(&leaf).build_server().unwrap());
    let client = client_trusting(&ca).max_version(max);
    let connector = TlsConnector::new(client.build_client().unwrap());
    let (s1, c1) = handshake(acceptor.clone(), &connector).await;
    assert!(
        s1.is_ok() && c1.is_ok(),
        "first: server={s1:?} client={c1:?}"
    );
    let (s2, c2) = handshake(acceptor, &connector).await;
    assert!(s2.is_ok(), "second: server={s2:?}");
    c2.expect("second client side").resumed
}

const BOTH_VERSIONS: [TlsVersion; 2] = [TlsVersion::Tls12, TlsVersion::Tls13];

#[tokio::test]
async fn enabled_resumption_resumes_tls12_and_tls13_sessions() {
    for max in BOTH_VERSIONS {
        let resumed = second_handshake_resumed(server_with, max).await;
        assert!(resumed, "{max:?} session did not resume");
    }
}

#[tokio::test]
async fn disabled_resumption_disables_tls12_and_tls13_resumption() {
    for max in BOTH_VERSIONS {
        let resumed =
            second_handshake_resumed(|leaf| server_with(leaf).session_resumption(false), max).await;
        assert!(!resumed, "{max:?} session resumed");
    }
}

#[tokio::test]
async fn resumption_lifetime_keeps_disabled_resumption_off() {
    let server = |leaf: &Leaf| {
        server_with(leaf)
            .session_resumption(false)
            .session_resumption_lifetime(Duration::from_secs(7200))
    };
    for max in BOTH_VERSIONS {
        let resumed = second_handshake_resumed(server, max).await;
        assert!(!resumed, "{max:?} session resumed");
    }
}

#[tokio::test]
async fn resumption_lifetime_keeps_sessions_resumable_within_it() {
    let server =
        |leaf: &Leaf| server_with(leaf).session_resumption_lifetime(Duration::from_secs(3600));
    for max in BOTH_VERSIONS {
        let resumed = second_handshake_resumed(server, max).await;
        assert!(resumed, "{max:?} session did not resume");
    }
}

#[tokio::test]
async fn zero_resumption_lifetime_disables_resumption() {
    let server = |leaf: &Leaf| server_with(leaf).session_resumption_lifetime(Duration::ZERO);
    for max in BOTH_VERSIONS {
        let resumed = second_handshake_resumed(server, max).await;
        assert!(!resumed, "{max:?} session resumed");
    }
}

#[test]
fn resumption_lifetime_leaves_the_ticket_count_unchanged() {
    let ca = Ca::new();
    let leaf = ca.leaf(SERVER_NAME, 1);
    let default_count = server_with(&leaf)
        .build_server()
        .unwrap()
        .inner()
        .send_tls13_tickets;
    let with_lifetime = server_with(&leaf)
        .session_resumption_lifetime(Duration::from_secs(36_000))
        .build_server()
        .unwrap()
        .inner()
        .send_tls13_tickets;
    assert_eq!(with_lifetime, default_count);
}

// -----------------------------------------------------------------------------
// Name checking
// -----------------------------------------------------------------------------

#[tokio::test]
async fn no_sni_verify_accepts_a_certificate_without_a_matching_name() {
    let ca = Ca::new();
    let leaf = ca.leaf(SERVER_NAME, 1);
    let server = server_with(&leaf).build_server().unwrap();
    let client = client_trusting(&ca)
        .with_dangerous_no_sni_verify()
        .build_client()
        .unwrap();

    let (srv, cli) = handshake_as(
        TlsAcceptor::new(server),
        &TlsConnector::new(client),
        "ied.example",
    )
    .await;

    assert!(srv.is_ok() && cli.is_ok(), "server={srv:?} client={cli:?}");
}

#[tokio::test]
async fn name_mismatch_is_rejected_without_no_sni_verify() {
    let ca = Ca::new();
    let leaf = ca.leaf(SERVER_NAME, 1);
    let server = server_with(&leaf).build_server().unwrap();
    let client = client_trusting(&ca).build_client().unwrap();

    let (srv, cli) = handshake_as(
        TlsAcceptor::new(server),
        &TlsConnector::new(client),
        "ied.example",
    )
    .await;

    assert!(
        srv.is_err() && cli.is_err(),
        "server={srv:?} client={cli:?}"
    );
}

#[tokio::test]
async fn no_sni_verify_still_rejects_an_untrusted_chain() {
    let trusted_ca = Ca::new();
    let rogue_ca = Ca::new();
    let rogue_leaf = rogue_ca.leaf(SERVER_NAME, 1);
    let server = server_with(&rogue_leaf).build_server().unwrap();
    let client = client_trusting(&trusted_ca)
        .with_dangerous_no_sni_verify()
        .build_client()
        .unwrap();

    let (srv, cli) = handshake_as(
        TlsAcceptor::new(server),
        &TlsConnector::new(client),
        "ied.example",
    )
    .await;

    assert!(
        srv.is_err() && cli.is_err(),
        "server={srv:?} client={cli:?}"
    );
}

#[tokio::test]
async fn no_sni_verify_still_rejects_an_expired_certificate() {
    let ca = Ca::new();
    let leaf = ca.issue(SERVER_NAME, 1, expired());
    let server = server_with(&leaf).build_server().unwrap();
    let client = client_trusting(&ca)
        .with_dangerous_no_sni_verify()
        .build_client()
        .unwrap();

    let (srv, cli) = handshake_as(
        TlsAcceptor::new(server),
        &TlsConnector::new(client),
        "ied.example",
    )
    .await;

    assert!(
        srv.is_err() && cli.is_err(),
        "server={srv:?} client={cli:?}"
    );
}

// -----------------------------------------------------------------------------
// Settings that are not applied
// -----------------------------------------------------------------------------

#[tokio::test]
async fn chain_validation_off_still_validates_the_chain() {
    let trusted_ca = Ca::new();
    let rogue_ca = Ca::new();
    let rogue_leaf = rogue_ca.leaf(SERVER_NAME, 1);
    let server = server_with(&rogue_leaf).build_server().unwrap();
    let client = client_trusting(&trusted_ca)
        .chain_validation(false)
        .build_client()
        .unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(
        srv.is_err() && cli.is_err(),
        "server={srv:?} client={cli:?}"
    );
}

// -----------------------------------------------------------------------------
// Events
// -----------------------------------------------------------------------------

#[tokio::test]
async fn completed_handshake_raises_session_established_on_both_sides() {
    let ca = Ca::new();
    let leaf = ca.leaf(SERVER_NAME, 1);
    let server_events = Arc::new(Recorder::default());
    let client_events = Arc::new(Recorder::default());
    let server = server_with(&leaf)
        .with_event_handler(server_events.clone())
        .build_server()
        .unwrap();
    let client = client_trusting(&ca)
        .with_event_handler(client_events.clone())
        .build_client()
        .unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(srv.is_ok() && cli.is_ok(), "server={srv:?} client={cli:?}");
    assert_eq!(
        server_events.codes(),
        vec![TlsEventCode::SessionEstablished]
    );
    assert_eq!(
        client_events.codes(),
        vec![TlsEventCode::SessionEstablished]
    );
}

#[tokio::test]
async fn refused_client_without_certificate_raises_cert_not_configured() {
    let server_ca = Ca::new();
    let client_ca = Ca::new();
    let server_leaf = server_ca.leaf(SERVER_NAME, 1);
    let known_client = client_ca.leaf("client.test", 2);
    let modes: [fn(TlsConfigBuilder) -> TlsConfigBuilder; 2] = [
        |b| b.require_client_auth(true),
        |b| b.allow_only_known_peers(true),
    ];
    for mode in modes {
        let events = Arc::new(Recorder::default());
        let server = mode(server_with(&server_leaf))
            .add_ca_pem(client_ca.pem().as_bytes())
            .unwrap()
            .add_known_peer_der(known_client.der.clone())
            .with_event_handler(events.clone())
            .build_server()
            .unwrap();
        let client = client_trusting(&server_ca).build_client().unwrap();

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
}

#[tokio::test]
async fn client_without_certificate_raises_no_peer_cert_when_client_auth_is_optional() {
    let server_ca = Ca::new();
    let client_ca = Ca::new();
    let server_leaf = server_ca.leaf(SERVER_NAME, 1);
    let events = Arc::new(Recorder::default());
    let server = server_with(&server_leaf)
        .add_ca_pem(client_ca.pem().as_bytes())
        .unwrap()
        .with_event_handler(events.clone())
        .build_server()
        .unwrap();
    let client = client_trusting(&server_ca).build_client().unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(srv.is_ok() && cli.is_ok(), "server={srv:?} client={cli:?}");
    assert!(
        events.has(TlsEventLevel::Warning, TlsEventCode::WrnNoPeerCert),
        "events: {:?}",
        events.codes()
    );
}

#[tokio::test]
async fn server_without_trust_anchors_raises_no_missing_certificate_warning() {
    let ca = Ca::new();
    let leaf = ca.leaf(SERVER_NAME, 1);
    let events = Arc::new(Recorder::default());
    let server = server_with(&leaf)
        .with_event_handler(events.clone())
        .build_server()
        .unwrap();
    let client = client_trusting(&ca).build_client().unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(srv.is_ok() && cli.is_ok(), "server={srv:?} client={cli:?}");
    assert_eq!(events.codes(), vec![TlsEventCode::SessionEstablished]);
}

#[tokio::test]
async fn untrusted_server_certificate_raises_one_chain_event() {
    let trusted_ca = Ca::new();
    let rogue_ca = Ca::new();
    let rogue_leaf = rogue_ca.leaf(SERVER_NAME, 1);
    let events = Arc::new(Recorder::default());
    let server = server_with(&rogue_leaf).build_server().unwrap();
    let client = client_trusting(&trusted_ca)
        .with_event_handler(events.clone())
        .build_client()
        .unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(
        srv.is_err() && cli.is_err(),
        "server={srv:?} client={cli:?}"
    );
    assert_eq!(events.codes(), vec![TlsEventCode::AlmCertChainInvalid]);
}

#[tokio::test]
async fn expired_server_certificate_from_an_untrusted_ca_raises_a_chain_event() {
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
    assert_eq!(events.codes(), vec![TlsEventCode::AlmCertChainInvalid]);
}

#[tokio::test]
async fn expired_client_certificate_rejection_raises_a_chain_event() {
    let server_ca = Ca::new();
    let client_ca = Ca::new();
    let server_leaf = server_ca.leaf(SERVER_NAME, 1);
    let client_leaf = client_ca.issue("client.test", 2, expired());
    let events = Arc::new(Recorder::default());
    let server = server_with(&server_leaf)
        .add_ca_pem(client_ca.pem().as_bytes())
        .unwrap()
        .with_event_handler(events.clone())
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
    assert!(
        events.has(TlsEventLevel::Incident, TlsEventCode::AlmCertChainInvalid),
        "events: {:?}",
        events.codes()
    );
}

#[tokio::test]
async fn name_mismatch_raises_a_san_event() {
    let ca = Ca::new();
    let leaf = ca.leaf(SERVER_NAME, 1);
    let events = Arc::new(Recorder::default());
    let server = server_with(&leaf).build_server().unwrap();
    let client = client_trusting(&ca)
        .with_event_handler(events.clone())
        .build_client()
        .unwrap();

    let (srv, cli) = handshake_as(
        TlsAcceptor::new(server),
        &TlsConnector::new(client),
        "ied.example",
    )
    .await;

    assert!(
        srv.is_err() && cli.is_err(),
        "server={srv:?} client={cli:?}"
    );
    assert_eq!(events.codes(), vec![TlsEventCode::AlmCertSanMismatch]);
}

#[tokio::test]
async fn revoked_server_certificate_raises_a_revocation_event() {
    let ca = Ca::new();
    let leaf = ca.leaf(SERVER_NAME, 41);
    let events = Arc::new(Recorder::default());
    let server = server_with(&leaf).build_server().unwrap();
    let client = client_trusting(&ca)
        .add_crl_pem(ca.crl(&[41]).as_bytes())
        .unwrap()
        .with_event_handler(events.clone())
        .build_client()
        .unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(
        srv.is_err() && cli.is_err(),
        "server={srv:?} client={cli:?}"
    );
    assert_eq!(events.codes(), vec![TlsEventCode::AlmCertRevoked]);
}

#[tokio::test]
async fn revoked_client_certificate_raises_a_revocation_event() {
    let server_ca = Ca::new();
    let client_ca = Ca::new();
    let server_leaf = server_ca.leaf(SERVER_NAME, 1);
    let client_leaf = client_ca.leaf("client.test", 42);
    let events = Arc::new(Recorder::default());
    let server = server_with(&server_leaf)
        .add_ca_pem(client_ca.pem().as_bytes())
        .unwrap()
        .add_crl_pem(client_ca.crl(&[42]).as_bytes())
        .unwrap()
        .with_event_handler(events.clone())
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
    assert!(
        events.has(TlsEventLevel::Incident, TlsEventCode::AlmCertRevoked),
        "events: {:?}",
        events.codes()
    );
}

#[tokio::test]
async fn crl_not_listing_the_peer_lets_the_handshake_through() {
    let ca = Ca::new();
    let leaf = ca.leaf(SERVER_NAME, 43);
    let events = Arc::new(Recorder::default());
    let server = server_with(&leaf).build_server().unwrap();
    let client = client_trusting(&ca)
        .add_crl_pem(ca.crl(&[44]).as_bytes())
        .unwrap()
        .with_event_handler(events.clone())
        .build_client()
        .unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(srv.is_ok() && cli.is_ok(), "server={srv:?} client={cli:?}");
    assert_eq!(events.codes(), vec![TlsEventCode::SessionEstablished]);
}

#[tokio::test]
async fn no_common_cipher_suite_raises_a_cipher_event() {
    let ca = Ca::new();
    let leaf = ca.leaf(SERVER_NAME, 1);
    let events = Arc::new(Recorder::default());
    let server = server_with(&leaf)
        .with_event_handler(events.clone())
        .build_server()
        .unwrap();
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: vec![
            rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        ],
        ..rustls::crypto::ring::default_provider()
    };
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca.cert.der().to_vec()))
        .unwrap();
    let foreign = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let (srv, cli) = handshake(
        TlsAcceptor::new(server),
        &TlsConnector::from_rustls(Arc::new(foreign)),
    )
    .await;

    assert!(
        srv.is_err() && cli.is_err(),
        "server={srv:?} client={cli:?}"
    );
    assert!(
        events.has(TlsEventLevel::Incident, TlsEventCode::AlmCipherNotAllowed),
        "events: {:?}",
        events.codes()
    );
}

#[tokio::test]
async fn refused_tls12_client_raises_an_alert_event() {
    let server_ca = Ca::new();
    let client_ca = Ca::new();
    let server_leaf = server_ca.leaf(SERVER_NAME, 1);
    let client_events = Arc::new(Recorder::default());
    let server = server_with(&server_leaf)
        .add_ca_pem(client_ca.pem().as_bytes())
        .unwrap()
        .require_client_auth(true)
        .build_server()
        .unwrap();
    let client = client_trusting(&server_ca)
        .max_version(TlsVersion::Tls12)
        .with_event_handler(client_events.clone())
        .build_client()
        .unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(
        srv.is_err() && cli.is_err(),
        "server={srv:?} client={cli:?}"
    );
    assert!(
        client_events.has(TlsEventLevel::Incident, TlsEventCode::AlmUnexpectedAlert),
        "events: {:?}",
        client_events.codes()
    );
}

#[tokio::test]
async fn version_mismatch_raises_a_version_event_on_the_server() {
    let ca = Ca::new();
    let leaf = ca.leaf(SERVER_NAME, 1);
    let events = Arc::new(Recorder::default());
    let server = server_with(&leaf)
        .min_version(TlsVersion::Tls13)
        .with_event_handler(events.clone())
        .build_server()
        .unwrap();
    let client = client_trusting(&ca)
        .max_version(TlsVersion::Tls12)
        .build_client()
        .unwrap();

    let (srv, cli) = handshake(TlsAcceptor::new(server), &TlsConnector::new(client)).await;

    assert!(
        srv.is_err() && cli.is_err(),
        "server={srv:?} client={cli:?}"
    );
    assert!(
        events.has(TlsEventLevel::Incident, TlsEventCode::AlmVersionTooOld),
        "events: {:?}",
        events.codes()
    );
}

// -----------------------------------------------------------------------------
// Hand-built ClientHello
// -----------------------------------------------------------------------------

const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;

/// A u16 length-prefixed list of u16 values.
fn u16_list(values: &[u16]) -> Vec<u8> {
    let mut out = ((values.len() * 2) as u16).to_be_bytes().to_vec();
    for v in values {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out
}

/// A ClientHello record at `legacy_version` offering `suites`, with the
/// given extensions.
fn client_hello(legacy_version: u16, suites: &[u16], extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut body = legacy_version.to_be_bytes().to_vec();
    body.extend_from_slice(&[0x5a; 32]);
    body.push(0);
    body.extend_from_slice(&u16_list(suites));
    body.extend_from_slice(&[1, 0]);
    let mut exts = Vec::new();
    for (ty, data) in extensions {
        exts.extend_from_slice(&ty.to_be_bytes());
        exts.extend_from_slice(&(data.len() as u16).to_be_bytes());
        exts.extend_from_slice(data);
    }
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut handshake = vec![1];
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// The signature_algorithms extension of a TLS 1.2 client.
fn tls12_signature_algorithms() -> (u16, Vec<u8>) {
    (
        EXT_SIGNATURE_ALGORITHMS,
        u16_list(&[0x0804, 0x0401, 0x0403]),
    )
}

/// An acceptor presenting an RSA certificate, reporting to `events`.
fn rsa_acceptor(events: Arc<Recorder>) -> TlsAcceptor {
    let ca = Ca::new();
    let leaf = rsa_leaf(&ca, SERVER_NAME);
    TlsAcceptor::new(
        server_with(&leaf)
            .with_event_handler(events)
            .build_server()
            .unwrap(),
    )
}

/// Sends `hello` to an RSA server and returns the events the server raised
/// while refusing it.
async fn server_events_for_refused_hello(hello: Vec<u8>) -> Vec<TlsEventCode> {
    let events = Arc::new(Recorder::default());
    let acceptor = rsa_acceptor(events.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        acceptor.accept(tcp).await.map(|_| ())
    });
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(&hello).await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("server task finishes")
        .unwrap();
    assert!(result.is_err(), "handshake accepted");
    events.codes()
}

#[tokio::test]
async fn rsa_key_exchange_only_hello_raises_a_cipher_event() {
    // TLS_RSA_WITH_AES_128_GCM_SHA256 without supported_groups.
    let hello = client_hello(0x0303, &[0x009c], &[tls12_signature_algorithms()]);
    let codes = server_events_for_refused_hello(hello).await;
    assert_eq!(codes, vec![TlsEventCode::AlmCipherNotAllowed]);
}

#[tokio::test]
async fn dhe_only_hello_raises_a_cipher_event() {
    // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 with the ffdhe2048 group.
    let hello = client_hello(
        0x0303,
        &[0x009e],
        &[
            (EXT_SUPPORTED_GROUPS, u16_list(&[0x0100])),
            tls12_signature_algorithms(),
        ],
    );
    let codes = server_events_for_refused_hello(hello).await;
    assert_eq!(codes, vec![TlsEventCode::AlmCipherNotAllowed]);
}

#[tokio::test]
async fn tls11_hello_raises_a_version_event() {
    // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA and TLS_RSA_WITH_AES_128_CBC_SHA,
    // without signature_algorithms, as a TLS 1.1 client sends them.
    let hello = client_hello(
        0x0302,
        &[0xc013, 0x002f],
        &[
            (EXT_SUPPORTED_GROUPS, u16_list(&[0x001d, 0x0017])),
            (EXT_EC_POINT_FORMATS, vec![1, 0]),
        ],
    );
    let codes = server_events_for_refused_hello(hello).await;
    assert_eq!(codes, vec![TlsEventCode::AlmVersionTooOld]);
}

#[tokio::test]
async fn hand_built_hello_with_a_whitelisted_suite_gets_a_server_hello() {
    let events = Arc::new(Recorder::default());
    let acceptor = rsa_acceptor(events.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        acceptor.accept(tcp).await.map(|_| ())
    });
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 with x25519.
    let hello = client_hello(
        0x0303,
        &[0xc02f],
        &[
            (EXT_SUPPORTED_GROUPS, u16_list(&[0x001d])),
            (EXT_EC_POINT_FORMATS, vec![1, 0]),
            tls12_signature_algorithms(),
        ],
    );
    tcp.write_all(&hello).await.unwrap();
    let mut header = [0u8; 6];
    tokio::time::timeout(Duration::from_secs(10), tcp.read_exact(&mut header))
        .await
        .expect("server answers")
        .unwrap();
    assert_eq!(header[0], 0x16, "not a handshake record");
    assert_eq!(header[5], 2, "not a ServerHello");
    drop(tcp);
    let result = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("server task finishes")
        .unwrap();
    assert!(result.is_err(), "handshake completed");
    assert!(events.codes().is_empty(), "events: {:?}", events.codes());
}
