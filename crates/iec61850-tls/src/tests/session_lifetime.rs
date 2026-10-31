//! Regression tests for the server session lifetime.
//!
//! A session stored longer ago than the configured lifetime must not resume,
//! for TLS 1.2 session IDs and TLS 1.3 tickets alike; a younger one must. The
//! store bounds its entry count and evicts the oldest entry first. Time comes
//! from an injected clock, so no test depends on wall-clock time.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::pki_types::ServerName;
use rustls::server::StoresServerSessions;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::session::{ExpiringSessionStore, SessionClock};
use crate::{TlsAcceptor, TlsConfigBuilder, TlsConnector, TlsVersion};

// -----------------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------------

/// A clock that advances only when told to.
#[derive(Clone)]
struct ManualClock {
    base: Instant,
    offset_secs: Arc<AtomicU64>,
}

impl ManualClock {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            offset_secs: Arc::new(AtomicU64::new(0)),
        }
    }

    fn advance(&self, d: Duration) {
        self.offset_secs.fetch_add(d.as_secs(), Ordering::SeqCst);
    }

    fn clock(&self) -> SessionClock {
        let base = self.base;
        let offset = Arc::clone(&self.offset_secs);
        Arc::new(move || base + Duration::from_secs(offset.load(Ordering::SeqCst)))
    }
}

struct Pki {
    ca_pem: String,
    leaf_pem: String,
    leaf_key_pem: String,
}

fn pki() -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::new(vec!["server.test".to_string()]).unwrap();
    leaf_params.subject_alt_names = vec![SanType::DnsName("server.test".try_into().unwrap())];
    let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    Pki {
        ca_pem: ca.pem(),
        leaf_pem: leaf.pem(),
        leaf_key_pem: leaf_key.serialize_pem(),
    }
}

/// Runs one handshake and one byte each way; returns whether the client
/// resumed.
async fn handshake(acceptor: TlsAcceptor, connector: &TlsConnector) -> bool {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(tcp).await.unwrap();
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        stream.write_all(&byte).await.unwrap();
        stream.flush().await.unwrap();
    });
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("server.test").unwrap().to_owned();
    let mut stream = connector.connect(name, tcp).await.unwrap();
    let resumed = stream.is_resumed();
    stream.write_all(&[7]).await.unwrap();
    let mut byte = [0u8; 1];
    stream.read_exact(&mut byte).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("server task finishes")
        .unwrap();
    resumed
}

/// Two handshakes with `advance` passing on the server clock in between;
/// returns whether the second one resumed.
async fn resumed_after(max: TlsVersion, lifetime: Duration, advance: Duration) -> bool {
    let p = pki();
    let clock = ManualClock::new();
    let server = TlsConfigBuilder::new()
        .with_cert_pem(p.leaf_pem.as_bytes(), p.leaf_key_pem.as_bytes())
        .unwrap()
        .session_resumption_lifetime(lifetime)
        .tls13_session_tickets(2)
        .with_session_clock(clock.clock())
        .build_server()
        .unwrap();
    let client = TlsConfigBuilder::new()
        .add_ca_pem(p.ca_pem.as_bytes())
        .unwrap()
        .max_version(max)
        .build_client()
        .unwrap();
    let acceptor = TlsAcceptor::new(server);
    let connector = TlsConnector::new(client);
    assert!(!handshake(acceptor.clone(), &connector).await);
    clock.advance(advance);
    handshake(acceptor, &connector).await
}

// -----------------------------------------------------------------------------
// Handshake tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn tls12_session_resumes_before_its_lifetime_ends() {
    let resumed = resumed_after(
        TlsVersion::Tls12,
        Duration::from_secs(600),
        Duration::from_secs(599),
    )
    .await;
    assert!(resumed);
}

#[tokio::test]
async fn tls12_session_does_not_resume_once_its_lifetime_ends() {
    let resumed = resumed_after(
        TlsVersion::Tls12,
        Duration::from_secs(600),
        Duration::from_secs(600),
    )
    .await;
    assert!(!resumed);
}

#[tokio::test]
async fn tls13_session_resumes_before_its_lifetime_ends() {
    let resumed = resumed_after(
        TlsVersion::Tls13,
        Duration::from_secs(600),
        Duration::from_secs(599),
    )
    .await;
    assert!(resumed);
}

#[tokio::test]
async fn tls13_session_does_not_resume_once_its_lifetime_ends() {
    let resumed = resumed_after(
        TlsVersion::Tls13,
        Duration::from_secs(600),
        Duration::from_secs(600),
    )
    .await;
    assert!(!resumed);
}

// -----------------------------------------------------------------------------
// Store tests
// -----------------------------------------------------------------------------

fn store(lifetime_secs: u64, capacity: usize, clock: &ManualClock) -> ExpiringSessionStore {
    ExpiringSessionStore::new(Duration::from_secs(lifetime_secs), capacity, clock.clock())
}

#[test]
fn entry_is_returned_until_its_lifetime_ends() {
    let clock = ManualClock::new();
    let s = store(10, 4, &clock);
    assert!(s.put(b"a".to_vec(), b"1".to_vec()));
    clock.advance(Duration::from_secs(9));
    assert_eq!(s.get(b"a"), Some(b"1".to_vec()));
    clock.advance(Duration::from_secs(1));
    assert_eq!(s.get(b"a"), None);
}

#[test]
fn take_removes_the_entry() {
    let clock = ManualClock::new();
    let s = store(10, 4, &clock);
    s.put(b"a".to_vec(), b"1".to_vec());
    assert_eq!(s.take(b"a"), Some(b"1".to_vec()));
    assert_eq!(s.take(b"a"), None);
    assert_eq!(s.get(b"a"), None);
}

#[test]
fn take_of_an_expired_entry_returns_nothing() {
    let clock = ManualClock::new();
    let s = store(10, 4, &clock);
    s.put(b"a".to_vec(), b"1".to_vec());
    clock.advance(Duration::from_secs(10));
    assert_eq!(s.take(b"a"), None);
}

#[test]
fn full_store_evicts_the_oldest_entry() {
    let clock = ManualClock::new();
    let s = store(100, 2, &clock);
    s.put(b"a".to_vec(), b"1".to_vec());
    clock.advance(Duration::from_secs(1));
    s.put(b"b".to_vec(), b"2".to_vec());
    clock.advance(Duration::from_secs(1));
    s.put(b"c".to_vec(), b"3".to_vec());
    assert_eq!(s.get(b"a"), None);
    assert_eq!(s.get(b"b"), Some(b"2".to_vec()));
    assert_eq!(s.get(b"c"), Some(b"3".to_vec()));
}

#[test]
fn overwritten_key_counts_once_and_restarts_its_lifetime() {
    let clock = ManualClock::new();
    let s = store(10, 2, &clock);
    s.put(b"a".to_vec(), b"1".to_vec());
    s.put(b"b".to_vec(), b"2".to_vec());
    clock.advance(Duration::from_secs(5));
    s.put(b"a".to_vec(), b"3".to_vec());
    assert_eq!(s.get(b"b"), Some(b"2".to_vec()));
    clock.advance(Duration::from_secs(5));
    assert_eq!(s.get(b"b"), None);
    assert_eq!(s.get(b"a"), Some(b"3".to_vec()));
}

#[test]
fn zero_capacity_store_caches_nothing() {
    let clock = ManualClock::new();
    let s = store(10, 0, &clock);
    assert!(!s.can_cache());
    assert!(!s.put(b"a".to_vec(), b"1".to_vec()));
    assert_eq!(s.get(b"a"), None);
}
