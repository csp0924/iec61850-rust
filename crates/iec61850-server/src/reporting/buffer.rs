//! BRCB report buffer: the multi-entry queue behind a buffered report control
//! block.
//!
//! Implements the enqueue, purge, and EntryID lookup behavior that
//! IEC 61850-7-2 defines for buffered reporting. Capacity is counted in entries
//! rather than in bytes, so an entry is never rejected for its size. Entries are
//! stored as `Arc<ReportEntry>` carrying an owned value snapshot, so the send
//! path can re-encode and re-segment the same entry without reading live data.
//! An EntryID index maps each identifier to a monotonic sequence number, which
//! makes a resynchronization lookup constant time rather than a linear scan.
//!
//! Invariants a caller relies on: a fresh buffer has `isOverflow` set, so the
//! first report a reconnecting client receives carries `BufOvfl = true`; a full
//! buffer evicts its oldest entry unless the configured strategy rejects the new
//! one instead; and `purge` clears the entries, the identifier index, and the
//! entry count together. Storage is reached only through `ReportBufferBackend`,
//! so another backend can be substituted without touching the callers.

use bytes::Bytes;
use iec61850_model::MmsValue;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::flags::InclusionFlag;

// ─────────────────────────────────────────────────────────────────────────────
// Overflow strategy
// ─────────────────────────────────────────────────────────────────────────────

/// What a report buffer does when it is full.
///
/// `DropOldest` is the default and is the behavior IEC 61850-7-2 describes for
/// enqueueReport. `DropNewest` and `Reject` are additional options for
/// deployments that would rather keep the buffered history than accept the
/// newest event.
///
/// All three increment `dropped_buffer_full` when the buffer is full, if a
/// counter has been injected, and all three set `is_overflow`. They differ in
/// which entry is lost:
/// - `DropOldest`: the oldest entry is evicted and the new one is stored
/// - `DropNewest`: the stored entries are kept and the new entry is rejected
/// - `Reject`: same behavior as `DropNewest`, kept separate so the two can be
///   told apart by a future metric label
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OverflowStrategy {
    /// Default: evict the oldest entry and store the new one.
    #[default]
    DropOldest,
    /// Reject the new entry and keep every stored one; `dropped_buffer_full`
    /// still increments.
    DropNewest,
    /// Same behavior as `DropNewest`, kept separate for future metric labeling.
    Reject,
}

/// BRCB EntryID: eight bytes, big-endian on the wire.
///
/// `EntryId::from_ms` encodes through `u64::to_be_bytes`, so the result is the
/// same on every host byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct EntryId(pub [u8; 8]);

impl EntryId {
    /// The all-zero EntryID, which a client writes to ask for the buffer from its
    /// head.
    pub const ZERO: Self = EntryId([0; 8]);

    /// Builds a big-endian EntryID from a millisecond timestamp.
    pub fn from_ms(ms: u64) -> Self {
        EntryId(ms.to_be_bytes())
    }

    /// Returns the identifier as a host-order `u64`, for comparison and logging.
    /// This is not the wire form.
    pub fn as_u64(&self) -> u64 {
        u64::from_be_bytes(self.0)
    }

    /// Returns whether this is the all-zero identifier.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 8]
    }
}

/// Data set values and inclusion flags frozen at the moment an entry was
/// enqueued.
///
/// This is the principal behavioral difference between a BRCB and a URCB: a URCB
/// reads the live data set on the send path, whereas a BRCB captures the values
/// at enqueue time, so a data set that changes between enqueue and transmission
/// cannot make a client see a value the event never had.
///
/// `inclusion_flags` records, per data set position, which trigger fired after
/// the trgOps filter (value change, quality change, and so on). General
/// interrogation and integrity reports carry their own flags on the entry but
/// still fill this vector to the data set length. `values` holds the value
/// captured at each triggered position. `data_set_len` duplicates the vector
/// length but saves the caller from having to infer the inclusion bitstring
/// length.
#[derive(Debug, Clone)]
pub struct EnqueuedSnapshot {
    /// One flag per data set position; `NONE` means this position did not trigger.
    pub inclusion_flags: Vec<InclusionFlag>,
    /// One slot per data set position: the value captured when it triggered,
    /// `None` where nothing was captured.
    pub values: Vec<Option<MmsValue>>,
    /// Data set length, used to size the inclusion bitstring.
    pub data_set_len: usize,
}

impl EnqueuedSnapshot {
    /// Creates an empty snapshot for the trigger path to fill in.
    pub fn new(ds_len: usize) -> Self {
        Self {
            inclusion_flags: vec![InclusionFlag::NONE; ds_len],
            values: vec![None; ds_len],
            data_set_len: ds_len,
        }
    }
}

/// One buffered report entry: a value snapshot and its metadata.
///
/// `snapshot` carries the data set values and the trgOps-filtered inclusion flags
/// captured at enqueue time, and the send path reads them from there rather than
/// from the live data set. `encoded_payload` is retained so a byte-arena backend
/// storing encoded BER directly could reuse the type; entries built with a
/// snapshot leave it empty.
#[derive(Debug, Clone)]
pub struct ReportEntry {
    /// Eight-byte big-endian EntryID, carried on the wire unchanged.
    pub entry_id: EntryId,
    /// Host-order millisecond timestamp, encoded as the `TimeOfEntry` BinaryTime6
    /// field.
    pub time_of_entry_ms: u64,
    /// Integrity report flag.
    pub is_integrity: bool,
    /// General interrogation flag.
    pub is_gi: bool,
    /// Pre-encoded BER payload; empty for an entry that carries a `snapshot`. Kept
    /// for a future byte-arena backend that stores encoded bytes directly.
    pub encoded_payload: Bytes,
    /// Data set values and inclusion flags captured at enqueue time. `None` means
    /// the entry has no snapshot and the send path falls back to live values.
    /// Wrapped in an `Arc` so the send path never clones the vectors.
    pub snapshot: Option<Arc<EnqueuedSnapshot>>,
}

impl ReportEntry {
    /// Creates an entry without an enqueue-time snapshot.
    pub fn new(
        entry_id: EntryId,
        time_of_entry_ms: u64,
        is_integrity: bool,
        is_gi: bool,
        encoded_payload: Bytes,
    ) -> Self {
        Self {
            entry_id,
            time_of_entry_ms,
            is_integrity,
            is_gi,
            encoded_payload,
            snapshot: None,
        }
    }

    /// Creates an entry carrying an enqueue-time snapshot, for the trigger path.
    pub fn with_snapshot(
        entry_id: EntryId,
        time_of_entry_ms: u64,
        is_integrity: bool,
        is_gi: bool,
        snapshot: Arc<EnqueuedSnapshot>,
    ) -> Self {
        Self {
            entry_id,
            time_of_entry_ms,
            is_integrity,
            is_gi,
            encoded_payload: Bytes::new(),
            snapshot: Some(snapshot),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Backend trait
// ─────────────────────────────────────────────────────────────────────────────

/// Result of `seek_to_after_entry_id`.
///
/// Three states are needed because "found, and a later entry exists" and "found,
/// and it is the newest entry" lead to different resynchronization handling.
#[derive(Debug, Clone)]
pub enum SeekResult {
    /// The identifier was found and a later entry exists; `next` is where
    /// transmission resumes.
    FoundWithNext(Arc<ReportEntry>),
    /// The identifier was found but is the newest entry in the buffer. The caller
    /// must arrange for transmission to resume at the next entry enqueued.
    FoundLast,
    /// The identifier is not in the buffer, having been evicted or never stored.
    /// The caller answers the client with an invalid-value error and sets
    /// `is_overflow`.
    NotFound,
}

/// Storage backend for a BRCB report buffer.
///
/// The trait deliberately talks only about entries and never about the container
/// holding them, so another backend can implement it unchanged.
///
/// # Invariants
///
/// - `purge()` must clear the stored entries and the EntryID index together, so
///   no counter survives a purge and misreports the buffer contents.
/// - `push()` on a full buffer applies the configured `OverflowStrategy` and must
///   set `is_overflow`, so the next report carries `BufOvfl = true`.
/// - `find_entry(id)` gives `EntryId::ZERO` no special meaning; the caller tests
///   `is_zero()` first.
/// - `find_entry` returns an owned `Arc` rather than a borrow, so a backend whose
///   lookup materializes an entry can implement it.
///
/// # Concurrency
///
/// The trait takes `&mut self`; the caller owns the lock that serializes access.
pub trait ReportBufferBackend: std::fmt::Debug + Send + Sync {
    /// Stores an entry.
    ///
    /// The return value depends on the configured `OverflowStrategy`:
    /// - `DropOldest`: `true` when the buffer was full and the oldest entry was
    ///   evicted to make room, `false` when it was not full
    /// - `DropNewest` and `Reject`: `true` when the buffer was full and this entry
    ///   was rejected, `false` when it was stored
    ///
    /// Either way a full buffer sets `is_overflow`. A caller that has to tell
    /// eviction from rejection reads `overflow_strategy()`.
    fn push(&mut self, entry: Arc<ReportEntry>) -> bool;

    /// Returns the entry with this EntryID, for resynchronization.
    ///
    /// The result is owned rather than borrowed so a backend that materializes an
    /// entry on lookup can implement it; an in-memory backend only clones an `Arc`.
    fn find_entry(&self, id: &EntryId) -> Option<Arc<ReportEntry>>;

    /// Locates an EntryID and reports where transmission should resume.
    ///
    /// - `EntryId::ZERO` is not handled here: the caller tests `EntryId::is_zero()`
    ///   first and starts from the head of the buffer.
    /// - Found with a later entry: `FoundWithNext(next_entry)`.
    /// - Found as the newest entry: `FoundLast`; the caller must resume at the next
    ///   entry enqueued.
    /// - Absent: `NotFound`.
    ///
    /// No backend state is modified; the caller decides what to do with the result.
    fn seek_to_after_entry_id(&self, id: &EntryId) -> SeekResult;

    /// Clears every entry and the EntryID index, returning how many entries were
    /// removed. `is_overflow` is left untouched.
    fn purge(&mut self) -> usize;

    /// Returns the number of stored entries.
    fn len(&self) -> usize;

    /// Returns whether the buffer holds no entries.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the `BufOvfl` flag, set when the buffer overflows and cleared by the
    /// caller once an entry has been transmitted.
    fn is_overflow(&self) -> bool;

    /// Clears the `BufOvfl` flag, once an entry has been transmitted.
    fn clear_overflow(&mut self);

    /// Returns every stored entry in insertion order.
    fn iter_entries(&self) -> Vec<Arc<ReportEntry>>;

    /// Returns every entry whose EntryID is strictly greater than `after`, in
    /// insertion order.
    ///
    /// When `after` is not in the buffer, every entry is returned and the caller
    /// decides whether resynchronization failed. The default implementation filters
    /// `iter_entries` on `entry_id.as_u64()`.
    fn iter_from(&self, after: &EntryId) -> Vec<Arc<ReportEntry>> {
        let cutoff = after.as_u64();
        self.iter_entries()
            .into_iter()
            .filter(|e| e.entry_id.as_u64() > cutoff)
            .collect()
    }

    /// Returns the overflow strategy this backend applies; `DropOldest` by default.
    fn overflow_strategy(&self) -> OverflowStrategy {
        OverflowStrategy::DropOldest
    }

    /// Injects the engine-level `dropped_buffer_full` counter.
    ///
    /// `register_brcb` calls this when a BRCB is attached to the engine, so the
    /// backend can increment the shared counter itself whenever a push drops an
    /// entry, whether by eviction or by rejection. The default is a no-op.
    fn set_dropped_counter(&mut self, _counter: Arc<AtomicU64>) {
        // A backend that counts dropped entries overrides this.
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// In-memory implementation
// ─────────────────────────────────────────────────────────────────────────────

/// In-memory BRCB report buffer.
///
/// Entries live in a `VecDeque`, oldest at the front, and eviction removes from
/// the front. `entry_index` maps an EntryID to an absolute, monotonically
/// increasing sequence number, and `front_seq` records the sequence number of the
/// entry at the front, so an entry sits at position `seq - front_seq`. Storing
/// absolute sequence numbers rather than positions means an eviction does not have
/// to renumber the index. The sequence number is internal and unrelated to
/// `EntryId`.
#[derive(Debug)]
pub struct InMemoryReportBuffer {
    /// Maximum number of entries; zero rejects every push.
    capacity: usize,
    /// Stored entries: front is the oldest, back the newest.
    entries: VecDeque<Arc<ReportEntry>>,
    /// EntryID to absolute sequence number.
    entry_index: HashMap<[u8; 8], u64>,
    /// Sequence number the next push will take; monotonic and never reset.
    next_seq: u64,
    /// Sequence number of the entry currently at the front of the queue.
    front_seq: u64,
    /// Entries ever stored, including evicted ones; a purge does not reset it.
    enqueue_count: u64,
    /// `BufOvfl` flag: set on overflow, cleared once an entry has been
    /// transmitted. A fresh buffer starts with it set.
    overflow: bool,
    /// Behavior when the buffer is full.
    strategy: OverflowStrategy,
    /// Engine-level `dropped_buffer_full` counter, injected by `register_brcb`.
    /// `None` when the backend runs without an engine.
    dropped_counter: Option<Arc<AtomicU64>>,
}

impl InMemoryReportBuffer {
    /// Creates a buffer that evicts its oldest entry when full.
    ///
    /// `capacity` is a number of entries, not a number of bytes.
    pub fn new(capacity: usize) -> Self {
        Self::with_strategy(capacity, OverflowStrategy::DropOldest)
    }

    /// Creates a buffer with an explicit overflow strategy.
    pub fn with_strategy(capacity: usize, strategy: OverflowStrategy) -> Self {
        Self {
            capacity,
            entries: VecDeque::with_capacity(capacity),
            entry_index: HashMap::with_capacity(capacity),
            next_seq: 0,
            front_seq: 0,
            enqueue_count: 0,
            // IEC 61850-7-2: a report buffer starts with isOverflow set.
            overflow: true,
            strategy,
            dropped_counter: None,
        }
    }

    /// Returns how many entries have ever been stored, including evicted ones.
    pub fn enqueue_count(&self) -> u64 {
        self.enqueue_count
    }

    /// Increments the injected drop counter, when one has been injected.
    fn bump_dropped_counter(&self) {
        if let Some(c) = &self.dropped_counter {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl ReportBufferBackend for InMemoryReportBuffer {
    fn push(&mut self, entry: Arc<ReportEntry>) -> bool {
        if self.capacity == 0 {
            // A capacity of zero is a misconfiguration: warn rather than panic.
            tracing::warn!("brcb buffer capacity is 0, entry not stored");
            return false;
        }

        let mut evicted = false;
        // Full: apply the configured strategy.
        if self.entries.len() >= self.capacity {
            match self.strategy {
                OverflowStrategy::DropOldest => {
                    // IEC 61850-7-2 enqueueReport: evict until there is room.
                    while self.entries.len() >= self.capacity {
                        if let Some(old) = self.entries.pop_front() {
                            self.entry_index.remove(&old.entry_id.0);
                            self.front_seq = self.front_seq.saturating_add(1);
                            // Every eviction counts as one dropped entry.
                            self.bump_dropped_counter();
                            evicted = true;
                        } else {
                            break;
                        }
                    }
                    // Falls through to the store path below.
                }
                OverflowStrategy::DropNewest | OverflowStrategy::Reject => {
                    // Full: keep the stored entries and reject this one.
                    self.bump_dropped_counter();
                    self.overflow = true;
                    tracing::warn!(
                        strategy = ?self.strategy,
                        capacity = self.capacity,
                        "brcb buffer full, rejecting the new entry"
                    );
                    // A true return here means rejected, not evicted.
                    return true;
                }
            }
        }

        // Store: the buffer was either not full or has just been made room in.
        let seq = self.next_seq;
        self.entry_index.insert(entry.entry_id.0, seq);
        self.entries.push_back(entry);
        self.next_seq = self.next_seq.saturating_add(1);
        self.enqueue_count = self.enqueue_count.saturating_add(1);

        if evicted {
            // IEC 61850-7-2 enqueueReport: an eviction sets isOverflow.
            self.overflow = true;
        }
        evicted
    }

    fn find_entry(&self, id: &EntryId) -> Option<Arc<ReportEntry>> {
        let seq = *self.entry_index.get(&id.0)?;
        // Position = absolute sequence number - front_seq; front_seq <= seq holds
        // for any entry still in the index.
        let rel = seq.checked_sub(self.front_seq)?;
        self.entries.get(rel as usize).cloned()
    }

    fn seek_to_after_entry_id(&self, id: &EntryId) -> SeekResult {
        let Some(&seq) = self.entry_index.get(&id.0) else {
            return SeekResult::NotFound;
        };
        let Some(rel) = seq.checked_sub(self.front_seq) else {
            // entry_index and front_seq are maintained together by push and evict,
            // so this cannot normally happen; report it instead of panicking.
            tracing::warn!(
                seq = seq,
                front_seq = self.front_seq,
                "report buffer entry index and front sequence number disagree"
            );
            return SeekResult::NotFound;
        };
        let rel = rel as usize;
        if rel + 1 >= self.entries.len() {
            // Found, but it is the newest entry: the caller resumes at the next
            // enqueue.
            SeekResult::FoundLast
        } else {
            match self.entries.get(rel + 1).cloned() {
                Some(next) => SeekResult::FoundWithNext(next),
                // Unreachable while rel + 1 < len; answer NotFound rather than panic.
                None => SeekResult::NotFound,
            }
        }
    }

    fn purge(&mut self) -> usize {
        let n = self.entries.len();
        self.entries.clear();
        self.entry_index.clear();
        // Keep front_seq aligned with next_seq so the next push cannot compute a
        // negative position.
        self.front_seq = self.next_seq;
        // The entry count is derived from entries.len(), so clearing the queue
        // clears it too. enqueue_count is cumulative and deliberately survives a
        // purge.
        n
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn is_overflow(&self) -> bool {
        self.overflow
    }

    fn clear_overflow(&mut self) {
        self.overflow = false;
    }

    fn iter_entries(&self) -> Vec<Arc<ReportEntry>> {
        self.entries.iter().cloned().collect()
    }

    fn iter_from(&self, after: &EntryId) -> Vec<Arc<ReportEntry>> {
        // Insertion order and EntryId::as_u64() increase together, so filtering the
        // queue in order is enough and no sort is needed.
        let cutoff = after.as_u64();
        self.entries
            .iter()
            .filter(|e| e.entry_id.as_u64() > cutoff)
            .cloned()
            .collect()
    }

    fn overflow_strategy(&self) -> OverflowStrategy {
        self.strategy
    }

    fn set_dropped_counter(&mut self, counter: Arc<AtomicU64>) {
        self.dropped_counter = Some(counter);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(id_ms: u64, payload_byte: u8) -> Arc<ReportEntry> {
        Arc::new(ReportEntry::new(
            EntryId::from_ms(id_ms),
            id_ms,
            false,
            false,
            Bytes::from(vec![payload_byte; 4]),
        ))
    }

    #[test]
    fn entry_id_zero_detection() {
        assert!(EntryId::ZERO.is_zero());
        assert!(EntryId([0; 8]).is_zero());
        assert!(!EntryId::from_ms(1).is_zero());
    }

    #[test]
    fn entry_id_big_endian_round_trip() {
        let id = EntryId::from_ms(0x1234_5678_9ABC_DEF0);
        // Big-endian: the most significant byte comes first.
        assert_eq!(id.0, [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]);
        assert_eq!(id.as_u64(), 0x1234_5678_9ABC_DEF0);
    }

    #[test]
    fn buffer_initial_overflow_is_true() {
        // IEC 61850-7-2: a report buffer starts with isOverflow set.
        let buf = InMemoryReportBuffer::new(8);
        assert!(
            buf.is_overflow(),
            "a new buffer must start with isOverflow set"
        );
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn push_and_find_entry_id() {
        let mut buf = InMemoryReportBuffer::new(4);
        let e1 = make_entry(100, 0xAA);
        let e2 = make_entry(200, 0xBB);
        let e3 = make_entry(300, 0xCC);
        assert!(!buf.push(e1.clone()));
        assert!(!buf.push(e2.clone()));
        assert!(!buf.push(e3.clone()));
        assert_eq!(buf.len(), 3);
        assert!(buf.find_entry(&e1.entry_id).is_some());
        assert!(buf.find_entry(&e2.entry_id).is_some());
        assert!(buf.find_entry(&e3.entry_id).is_some());
        assert!(buf.find_entry(&EntryId::from_ms(999)).is_none());
    }

    #[test]
    fn evict_oldest_on_overflow() {
        // A full buffer evicts its oldest entry and sets is_overflow.
        let mut buf = InMemoryReportBuffer::new(2);
        let e1 = make_entry(100, 0x01);
        let e2 = make_entry(200, 0x02);
        let e3 = make_entry(300, 0x03);
        buf.clear_overflow(); // clear the initial flag so the eviction is visible
        assert!(!buf.is_overflow());
        assert!(!buf.push(e1.clone()));
        assert!(!buf.push(e2.clone()));
        let evicted = buf.push(e3.clone());
        assert!(evicted, "a push into a full buffer must report an eviction");
        assert!(buf.is_overflow(), "an eviction must set is_overflow");
        assert_eq!(buf.len(), 2);
        // The evicted entry is gone from the index as well.
        assert!(buf.find_entry(&e1.entry_id).is_none());
        assert!(buf.find_entry(&e2.entry_id).is_some());
        assert!(buf.find_entry(&e3.entry_id).is_some());
    }

    #[test]
    fn purge_resets_count_and_index() {
        let mut buf = InMemoryReportBuffer::new(8);
        for i in 0..5u64 {
            buf.push(make_entry(100 + i, i as u8));
        }
        assert_eq!(buf.len(), 5);
        let purged_n = buf.purge();
        assert_eq!(purged_n, 5);
        assert_eq!(buf.len(), 0, "purge must leave the buffer empty");
        assert!(buf.find_entry(&EntryId::from_ms(100)).is_none());
        assert!(buf.find_entry(&EntryId::from_ms(104)).is_none());
        // purge leaves is_overflow alone; only the send path clears it.
        assert!(buf.is_overflow());
    }

    #[test]
    fn purge_then_push_continues_correctly() {
        // After a purge the sequence numbers stay aligned, so new entries are found.
        let mut buf = InMemoryReportBuffer::new(4);
        buf.push(make_entry(100, 0x01));
        buf.push(make_entry(200, 0x02));
        buf.purge();
        let e3 = make_entry(300, 0x03);
        buf.push(e3.clone());
        assert_eq!(buf.len(), 1);
        assert!(buf.find_entry(&e3.entry_id).is_some());
        assert!(buf.find_entry(&EntryId::from_ms(100)).is_none());
    }

    #[test]
    fn capacity_zero_rejects_push() {
        let mut buf = InMemoryReportBuffer::new(0);
        let e = make_entry(100, 0xFF);
        assert!(!buf.push(e));
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn enqueue_count_accumulates_through_evict() {
        let mut buf = InMemoryReportBuffer::new(2);
        for i in 0..10u64 {
            buf.push(make_entry(100 + i, i as u8));
        }
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.enqueue_count(), 10);
    }

    // ─── Overflow strategy and the drop counter ──────────────────────────────

    #[test]
    fn in_memory_drop_oldest_increments_counter() {
        // DropOldest increments the counter on every eviction.
        let mut buf = InMemoryReportBuffer::new(2);
        let counter = Arc::new(AtomicU64::new(0));
        buf.set_dropped_counter(counter.clone());

        buf.push(make_entry(100, 1));
        buf.push(make_entry(101, 2));
        for i in 0..5u64 {
            buf.push(make_entry(102 + i, i as u8));
        }
        assert_eq!(
            counter.load(Ordering::Relaxed),
            5,
            "five evictions must increment the counter five times"
        );
        assert_eq!(buf.len(), 2, "the buffer must stay at its capacity");
    }

    #[test]
    fn in_memory_drop_newest_rejects_when_full() {
        // DropNewest rejects the new entry and keeps the stored ones.
        let mut buf = InMemoryReportBuffer::with_strategy(2, OverflowStrategy::DropNewest);
        let counter = Arc::new(AtomicU64::new(0));
        buf.set_dropped_counter(counter.clone());

        let e1 = make_entry(100, 1);
        let e2 = make_entry(101, 2);
        let e3 = make_entry(102, 3);
        assert!(!buf.push(e1.clone()));
        assert!(!buf.push(e2.clone()));
        let rejected = buf.push(e3.clone());
        assert!(
            rejected,
            "a push into a full drop-newest buffer must report a rejection"
        );
        assert_eq!(buf.len(), 2);
        assert!(
            buf.find_entry(&e1.entry_id).is_some(),
            "drop-newest must not evict a stored entry"
        );
        assert!(buf.find_entry(&e2.entry_id).is_some());
        assert!(buf.find_entry(&e3.entry_id).is_none());
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        assert!(buf.is_overflow());
    }

    #[test]
    fn in_memory_reject_strategy_same_behavior_as_drop_newest() {
        // Reject behaves exactly like DropNewest.
        let mut buf = InMemoryReportBuffer::with_strategy(2, OverflowStrategy::Reject);
        let counter = Arc::new(AtomicU64::new(0));
        buf.set_dropped_counter(counter.clone());

        buf.push(make_entry(100, 1));
        buf.push(make_entry(101, 2));
        let rejected = buf.push(make_entry(102, 3));
        assert!(rejected);
        assert_eq!(buf.len(), 2);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn in_memory_overflow_strategy_reports_correctly() {
        let buf1 = InMemoryReportBuffer::new(4);
        assert_eq!(buf1.overflow_strategy(), OverflowStrategy::DropOldest);
        let buf2 = InMemoryReportBuffer::with_strategy(4, OverflowStrategy::DropNewest);
        assert_eq!(buf2.overflow_strategy(), OverflowStrategy::DropNewest);
        let buf3 = InMemoryReportBuffer::with_strategy(4, OverflowStrategy::Reject);
        assert_eq!(buf3.overflow_strategy(), OverflowStrategy::Reject);
    }

    #[test]
    fn iter_from_returns_strictly_after() {
        // iter_from returns the entries whose id is strictly greater than the cutoff.
        let mut buf = InMemoryReportBuffer::new(8);
        for i in 0..5u64 {
            buf.push(make_entry(100 + i, i as u8));
        }
        let after = EntryId::from_ms(101);
        let v = buf.iter_from(&after);
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].entry_id.as_u64(), 102);
        assert_eq!(v[2].entry_id.as_u64(), 104);
    }

    // ─── seek_to_after_entry_id ──────────────────────────────────────────────

    #[test]
    fn seek_to_after_entry_id_returns_found_with_next() {
        // Found with a later entry present.
        let mut buf = InMemoryReportBuffer::new(8);
        let e1 = make_entry(100, 0xAA);
        let e2 = make_entry(200, 0xBB);
        let e3 = make_entry(300, 0xCC);
        buf.push(e1.clone());
        buf.push(e2.clone());
        buf.push(e3.clone());

        match buf.seek_to_after_entry_id(&e1.entry_id) {
            SeekResult::FoundWithNext(next) => {
                assert_eq!(next.entry_id, e2.entry_id, "the entry after e1 must be e2");
            }
            other => panic!("expected FoundWithNext, got {:?}", other),
        }
        match buf.seek_to_after_entry_id(&e2.entry_id) {
            SeekResult::FoundWithNext(next) => {
                assert_eq!(next.entry_id, e3.entry_id);
            }
            other => panic!("expected FoundWithNext, got {:?}", other),
        }
    }

    #[test]
    fn seek_to_after_entry_id_returns_found_last_when_id_is_newest() {
        // Found as the newest entry: the caller resumes at the next enqueue.
        let mut buf = InMemoryReportBuffer::new(8);
        let e1 = make_entry(100, 0xAA);
        let e2 = make_entry(200, 0xBB);
        buf.push(e1);
        buf.push(e2.clone());

        match buf.seek_to_after_entry_id(&e2.entry_id) {
            SeekResult::FoundLast => {}
            other => panic!("expected FoundLast, got {:?}", other),
        }
    }

    #[test]
    fn seek_to_after_entry_id_returns_not_found() {
        let mut buf = InMemoryReportBuffer::new(8);
        buf.push(make_entry(100, 0xAA));
        buf.push(make_entry(200, 0xBB));

        match buf.seek_to_after_entry_id(&EntryId::from_ms(999)) {
            SeekResult::NotFound => {}
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    #[test]
    fn seek_to_after_entry_id_after_evict_returns_not_found() {
        // An evicted identifier must report NotFound.
        let mut buf = InMemoryReportBuffer::new(2);
        let e1 = make_entry(100, 1);
        let e2 = make_entry(200, 2);
        let e3 = make_entry(300, 3);
        buf.push(e1.clone());
        buf.push(e2);
        buf.push(e3); // evicts e1
        match buf.seek_to_after_entry_id(&e1.entry_id) {
            SeekResult::NotFound => {}
            other => panic!("expected NotFound after evict, got {:?}", other),
        }
    }

    #[test]
    fn find_entry_returns_owned_arc() {
        let mut buf = InMemoryReportBuffer::new(4);
        let e1 = make_entry(100, 0xAA);
        buf.push(e1.clone());
        let got: Option<Arc<ReportEntry>> = buf.find_entry(&e1.entry_id);
        let got = got.expect("find_entry must locate the stored entry");
        assert_eq!(got.entry_id, e1.entry_id);
        // The result is an owned Arc clone, so the reference count is above one.
        assert!(Arc::strong_count(&got) >= 2);
    }

    #[test]
    fn iter_entries_returns_in_order() {
        let mut buf = InMemoryReportBuffer::new(4);
        let e1 = make_entry(100, 0x01);
        let e2 = make_entry(200, 0x02);
        buf.push(e1.clone());
        buf.push(e2.clone());
        let v = buf.iter_entries();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].entry_id, e1.entry_id);
        assert_eq!(v[1].entry_id, e2.entry_id);
    }
}
