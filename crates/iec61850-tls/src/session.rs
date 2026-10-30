//! Server session storage that bounds how long a session can be resumed.
//!
//! [`ExpiringSessionStore`] serves both TLS 1.2 session IDs and TLS 1.3
//! stateful tickets. An entry older than the configured lifetime is never
//! handed back, so resuming it falls back to a full handshake. The store holds
//! at most [`SESSION_CACHE_CAPACITY`] entries and evicts the oldest first.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use rustls::server::StoresServerSessions;

/// Maximum number of sessions the store keeps, the same as the rustls default
/// cache.
pub(crate) const SESSION_CACHE_CAPACITY: usize = 256;

/// Monotonic time source of the store.
pub(crate) type SessionClock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// The clock used outside tests: [`Instant::now`].
pub(crate) fn system_clock() -> SessionClock {
    Arc::new(Instant::now)
}

/// Stored sessions, keyed by session ID or ticket, with their insertion order.
#[derive(Default)]
struct Entries {
    map: HashMap<Vec<u8>, (Instant, Vec<u8>)>,
    /// Keys from oldest to newest insertion; every key of `map` appears once.
    order: VecDeque<Vec<u8>>,
}

impl Entries {
    fn remove(&mut self, key: &[u8]) -> Option<(Instant, Vec<u8>)> {
        let entry = self.map.remove(key)?;
        self.order.retain(|k| k.as_slice() != key);
        Some(entry)
    }
}

/// Session store whose entries expire after a fixed lifetime.
pub(crate) struct ExpiringSessionStore {
    lifetime: Duration,
    capacity: usize,
    clock: SessionClock,
    entries: Mutex<Entries>,
}

impl ExpiringSessionStore {
    /// Creates a store whose sessions can be resumed for `lifetime` after
    /// they were stored, holding at most `capacity` entries.
    pub(crate) fn new(lifetime: Duration, capacity: usize, clock: SessionClock) -> Self {
        Self {
            lifetime,
            capacity,
            clock,
            entries: Mutex::new(Entries::default()),
        }
    }

    fn is_expired(&self, stored_at: Instant, now: Instant) -> bool {
        now.saturating_duration_since(stored_at) >= self.lifetime
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Entries> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl std::fmt::Debug for ExpiringSessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExpiringSessionStore")
            .field("lifetime", &self.lifetime)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl StoresServerSessions for ExpiringSessionStore {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        if self.capacity == 0 {
            return false;
        }
        let now = (self.clock)();
        let mut entries = self.lock();
        entries.remove(&key);
        // Insertion order is time order, so expired entries sit at the front.
        while let Some(oldest) = entries.order.front() {
            let expired = entries
                .map
                .get(oldest)
                .is_none_or(|(stored_at, _)| self.is_expired(*stored_at, now));
            if !expired && entries.order.len() < self.capacity {
                break;
            }
            if let Some(k) = entries.order.pop_front() {
                entries.map.remove(&k);
            }
        }
        entries.order.push_back(key.clone());
        entries.map.insert(key, (now, value));
        true
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let now = (self.clock)();
        let mut entries = self.lock();
        let stored_at = entries.map.get(key)?.0;
        if self.is_expired(stored_at, now) {
            entries.remove(key);
            return None;
        }
        entries.map.get(key).map(|(_, value)| value.clone())
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        let now = (self.clock)();
        let (stored_at, value) = self.lock().remove(key)?;
        (!self.is_expired(stored_at, now)).then_some(value)
    }

    fn can_cache(&self) -> bool {
        self.capacity > 0
    }
}
