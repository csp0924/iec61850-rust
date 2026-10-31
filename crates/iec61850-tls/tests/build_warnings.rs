//! The warnings `TlsConfigBuilder::build_server` logs about a configuration
//! that builds but is likely incomplete.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use iec61850_tls::TlsConfigBuilder;
use rcgen::{CertificateParams, KeyPair};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::Interest;
use tracing::{Event, Level, Metadata, Subscriber};

/// Counts the warning and error events whose message contains `needle`.
struct Counter {
    needle: &'static str,
    hits: Arc<AtomicUsize>,
}

struct Message(String);

impl Visit for Message {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

impl Subscriber for Counter {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        if *event.metadata().level() > Level::WARN {
            return;
        }
        let mut m = Message(String::new());
        event.record(&mut m);
        if m.0.contains(self.needle) {
            self.hits.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

fn warnings_containing(needle: &'static str, f: impl FnOnce()) -> usize {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Counter {
        needle,
        hits: hits.clone(),
    };
    tracing::subscriber::with_default(counter, f);
    hits.load(Ordering::Relaxed)
}

/// A self-signed certificate for `server.test`: its PEM and its key's PEM.
fn self_signed() -> (String, String) {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["server.test".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    (cert.pem(), key.serialize_pem())
}

fn server_builder() -> TlsConfigBuilder {
    let (cert, key) = self_signed();
    TlsConfigBuilder::new()
        .with_cert_pem(cert.as_bytes(), key.as_bytes())
        .unwrap()
}

#[test]
fn a_server_without_trust_anchors_warns_that_it_accepts_any_client() {
    let warnings = warnings_containing("no trust anchor", || {
        server_builder().build_server().expect("builds");
    });
    assert_eq!(warnings, 1);
}

#[test]
fn a_server_with_trust_anchors_does_not_warn_about_them() {
    let (ca, _) = self_signed();
    let warnings = warnings_containing("no trust anchor", || {
        server_builder()
            .add_ca_pem(ca.as_bytes())
            .unwrap()
            .build_server()
            .expect("builds");
    });
    assert_eq!(warnings, 0);
}
