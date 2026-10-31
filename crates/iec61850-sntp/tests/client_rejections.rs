//! Integration test: each reply the client rejects, over a real UDP socket,
//! is returned as an error and reported with one `tracing` warning.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use iec61850_sntp::{LeapIndicator, Mode, NtpTimestamp, SntpClient, SntpError, SntpPacket};
use tokio::net::UdpSocket;
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

/// Queries a one-shot server that answers the request with `reply` after
/// `tamper` has changed it, and returns the query result together with the
/// number of "rejected SNTP reply" warnings the client emitted.
fn query_with(tamper: fn(&mut SntpPacket)) -> (Result<(), SntpError>, usize) {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Counter {
        needle: "rejected SNTP reply",
        hits: hits.clone(),
    };
    let result = tracing::subscriber::with_default(counter, || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
            let addr = server.local_addr().expect("local_addr");
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let (len, peer) = server.recv_from(&mut buf).await.expect("recv");
                let req = SntpPacket::decode(&buf[..len]).expect("decode request");
                let mut reply = SntpPacket::client_request();
                reply.mode = Mode::Server;
                reply.stratum = 1;
                reply.originate_ts = req.transmit_ts;
                reply.receive_ts = req.transmit_ts;
                reply.transmit_ts = req.transmit_ts;
                tamper(&mut reply);
                server.send_to(&reply.encode(), peer).await.expect("send");
            });
            SntpClient::new(addr)
                .query(Duration::from_secs(3))
                .await
                .map(|_| ())
        })
    });
    (result, hits.load(Ordering::Relaxed))
}

#[test]
fn an_acceptable_reply_raises_no_warning() {
    let (result, warnings) = query_with(|_| {});
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(warnings, 0);
}

#[test]
fn a_reply_in_the_wrong_mode_is_rejected_with_a_warning() {
    let (result, warnings) = query_with(|r| r.mode = Mode::Client);
    assert!(
        matches!(result, Err(SntpError::UnexpectedMode(3))),
        "{result:?}"
    );
    assert_eq!(warnings, 1);
}

#[test]
fn a_reply_to_another_request_is_rejected_with_a_warning() {
    let (result, warnings) = query_with(|r| r.originate_ts.fraction ^= 1);
    assert!(
        matches!(result, Err(SntpError::InvalidHeader(_))),
        "{result:?}"
    );
    assert_eq!(warnings, 1);
}

#[test]
fn a_reply_with_a_zero_transmit_time_is_rejected_with_a_warning() {
    let (result, warnings) = query_with(|r| r.transmit_ts = NtpTimestamp::ZERO);
    assert!(
        matches!(result, Err(SntpError::InvalidHeader(_))),
        "{result:?}"
    );
    assert_eq!(warnings, 1);
}

#[test]
fn a_reply_from_an_unsynchronized_clock_is_rejected_with_a_warning() {
    let (result, warnings) = query_with(|r| r.leap = LeapIndicator::AlarmUnsynchronized);
    assert!(
        matches!(result, Err(SntpError::InvalidHeader(_))),
        "{result:?}"
    );
    assert_eq!(warnings, 1);
}
