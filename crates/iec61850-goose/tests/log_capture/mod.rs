//! Counts the warning and error `tracing` events a closure emits on the
//! current thread.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::Interest;
use tracing::{Event, Level, Metadata, Subscriber};

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

/// Runs `f` and returns how many warning or error events whose message
/// contains `needle` it emitted on this thread.
pub fn warnings_containing(needle: &'static str, f: impl FnOnce()) -> usize {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Counter {
        needle,
        hits: hits.clone(),
    };
    tracing::subscriber::with_default(counter, f);
    hits.load(Ordering::Relaxed)
}
