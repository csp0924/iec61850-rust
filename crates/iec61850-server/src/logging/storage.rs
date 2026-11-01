//! The `LogStorage` trait and an in-memory implementation.
//!
//! Storage sits behind a trait object, so a persistent backend can replace the
//! in-memory one without touching the log control block. Entries are read back
//! through `LogEntryVisitor`, which is called once per entry, rather than through
//! interleaved entry-level and data-level callbacks.

use iec61850_model::MmsValue;
use std::collections::VecDeque;
use std::sync::RwLock;

/// Identifier of one log entry.
///
/// On the wire it is an `OCTET STRING(8)` in big-endian order. The host-order
/// `u64` is wrapped in a newtype so the two forms cannot be confused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct EntryId(pub u64);

impl EntryId {
    /// Builds an identifier from a millisecond timestamp.
    pub fn from_ms(ms: u64) -> Self {
        EntryId(ms)
    }

    /// Encodes the identifier as eight big-endian bytes for the wire.
    pub fn to_be_bytes(&self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Decodes the identifier from eight big-endian wire bytes.
    pub fn from_be_bytes(b: [u8; 8]) -> Self {
        EntryId(u64::from_be_bytes(b))
    }
}

/// One journal entry: its metadata and the data points it carries.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct JournalEntry {
    /// EntryID, sent as eight big-endian bytes.
    pub entry_id: EntryId,
    /// Time of the entry in milliseconds since the epoch, sent as a BinaryTime6.
    pub time_ms: u64,
    /// Data points, one `JournalEntryData` each.
    pub variables: Vec<JournalEntryData>,
}

impl JournalEntry {
    /// Creates an entry with the identifier `entry_id`, the time `time_ms` in
    /// milliseconds since the epoch, and the data points `variables`.
    pub fn new(entry_id: EntryId, time_ms: u64, variables: Vec<JournalEntryData>) -> Self {
        Self {
            entry_id,
            time_ms,
            variables,
        }
    }
}

/// One data point of a journal entry: its reference, value, and reason code.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct JournalEntryData {
    /// Data attribute reference.
    pub data_ref: String,
    /// The value recorded.
    pub value: MmsValue,
    /// Reason code (ReasonForInclusionInLog): mask `1 << n` holds bit `n` of
    /// the BIT STRING sent on the wire, so data change is 0x02, quality change
    /// 0x04, data update 0x08, integrity 0x10, general interrogation 0x20 and
    /// application trigger 0x40.
    pub reason_code: u8,
}

impl JournalEntryData {
    /// Creates a data point recording `value` for the reference `data_ref`
    /// with the reason code `reason_code`.
    pub fn new(data_ref: impl Into<String>, value: MmsValue, reason_code: u8) -> Self {
        Self {
            data_ref: data_ref.into(),
            value,
            reason_code,
        }
    }
}

/// An entry identifier with its time, as `oldest_and_newest` returns.
pub type EntryMeta = (EntryId, u64);

/// Why a `LogStorage` operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LogStorageError {
    /// The entry identifier is not in the log.
    #[error("entry id {0:?} is not in the log")]
    EntryIdNotFound(EntryId),
    /// The backend failed internally, for example on a poisoned lock or an I/O error.
    #[error("log storage backend failed: {0}")]
    Backend(String),
}

/// Visitor over journal entries.
///
/// It is called once per entry; returning `false` stops the walk.
pub trait LogEntryVisitor {
    /// Receives one entry. Returning `false` stops the walk.
    fn visit(&mut self, entry: &JournalEntry) -> bool;
}

/// Backend that stores log entries.
///
/// # Invariants
///
/// - An `add_entry` and the `add_entry_data` calls that follow belong to the same
///   entry; the caller keeps them together.
/// - `query_by_time` and `query_after` must visit entries in ascending order of
///   entry identifier.
/// - `oldest_and_newest` answers from cached metadata rather than scanning, and
///   returns `None` for an empty log.
///
/// # Calling context
///
/// A started server writes and queries the log from client requests and from
/// its periodic triggers on the blocking thread pool of the runtime, never on
/// a worker thread. A backend that blocks still holds up whatever waits for
/// it: the request it serves and every update whose triggers queue behind the
/// batch under way, which takes in the writes other associations make to
/// attributes that raise a trigger and `IedServer::update_*` calls on any
/// thread. An update called on a runtime worker stalls that worker until the
/// backend returns, and on a current-thread runtime the whole server. An
/// update made through `IedServer::update_*` writes on the caller's thread. An
/// integrity entry is written while the periodic triggers hold off
/// `IedServer::lock_data_model`, so a backend does not call it.
///
/// # Calls from the update path
///
/// An `IedServer` writes the entries of value updates while it raises their
/// triggers, one batch at a time in the order the values were stored, and
/// holds none of its locks while it calls the backend. The backend may update
/// the server from the thread it is called on: that update is raised after the
/// batch under way, and the call returns at once. It must not wait for an
/// update made on another thread, which waits in turn for the batch under way
/// and so for the backend.
pub trait LogStorage: std::fmt::Debug + Send + Sync {
    /// Writes a new entry header with its time and a fresh entry identifier.
    ///
    /// # Errors
    ///
    /// Returns `LogStorageError::Backend` when the backend fails.
    fn add_entry(&self, time_ms: u64) -> Result<EntryId, LogStorageError>;

    /// Appends one data point to an entry that already exists.
    ///
    /// # Errors
    ///
    /// Returns `LogStorageError::EntryIdNotFound` when the entry is unknown, or
    /// `LogStorageError::Backend` when the backend fails.
    fn add_entry_data(
        &self,
        entry_id: EntryId,
        data_ref: &str,
        value: MmsValue,
        reason_code: u8,
    ) -> Result<(), LogStorageError>;

    /// Writes a whole entry, its time and every data point, as one unit, and
    /// returns its identifier.
    ///
    /// The default implementation writes the header with `add_entry` and then
    /// each data point with `add_entry_data`, so it can leave part of an entry
    /// behind when a later call fails. A backend that can fail between those
    /// calls overrides it to write the entry at once; the in-memory backend
    /// does, and leaves nothing behind on failure.
    ///
    /// # Errors
    ///
    /// Returns `LogStorageError::Backend` when the backend fails.
    fn add_entry_with_data(
        &self,
        time_ms: u64,
        data: &[JournalEntryData],
    ) -> Result<EntryId, LogStorageError> {
        let id = self.add_entry(time_ms)?;
        for d in data {
            self.add_entry_data(id, &d.data_ref, d.value.clone(), d.reason_code)?;
        }
        Ok(id)
    }

    /// Visits the entries in a time range, both endpoints included.
    ///
    /// # Errors
    ///
    /// Returns `LogStorageError::Backend` when the backend fails.
    fn query_by_time(
        &self,
        start_ms: u64,
        end_ms: u64,
        visitor: &mut dyn LogEntryVisitor,
    ) -> Result<(), LogStorageError>;

    /// Visits the entries after a given entry identifier whose time is at least
    /// `starting_time_ms`. Both conditions apply.
    ///
    /// # Errors
    ///
    /// Returns `LogStorageError::Backend` when the backend fails.
    fn query_after(
        &self,
        starting_time_ms: u64,
        entry_id: EntryId,
        visitor: &mut dyn LogEntryVisitor,
    ) -> Result<(), LogStorageError>;

    /// Returns the metadata of the oldest and newest entries, for the OldEntr and
    /// NewEntr attributes of a log control block, or `None` for an empty log.
    ///
    /// # Errors
    ///
    /// Returns `LogStorageError::Backend` when the backend fails.
    fn oldest_and_newest(&self) -> Result<Option<(EntryMeta, EntryMeta)>, LogStorageError>;

    /// Returns the number of stored entries.
    fn count(&self) -> usize;
}

// ─────────────────────────────────────────────────────────────────────────────
// In-memory implementation
// ─────────────────────────────────────────────────────────────────────────────

/// In-memory `LogStorage` backed by a `VecDeque<JournalEntry>`.
///
/// Suited to tests, demonstrations, and embedded use; a deployment that must keep
/// its log across a restart needs a persistent backend.
///
/// The capacity is optional; a full log evicts its oldest entry, as a buffered
/// report control block does.
#[derive(Debug)]
pub struct InMemoryLogStorage {
    inner: RwLock<InMemoryInner>,
}

#[derive(Debug)]
struct InMemoryInner {
    entries: VecDeque<JournalEntry>,
    next_id: u64,
    /// Maximum number of entries; `None` means unbounded.
    capacity: Option<usize>,
}

impl InMemoryLogStorage {
    /// Creates an in-memory log with no capacity limit.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(InMemoryInner {
                entries: VecDeque::new(),
                next_id: 1,
                capacity: None,
            }),
        }
    }

    /// Creates an in-memory log that evicts its oldest entry once `cap` entries are
    /// stored.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            inner: RwLock::new(InMemoryInner {
                entries: VecDeque::new(),
                next_id: 1,
                capacity: Some(cap),
            }),
        }
    }
}

impl Default for InMemoryLogStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl LogStorage for InMemoryLogStorage {
    fn add_entry(&self, time_ms: u64) -> Result<EntryId, LogStorageError> {
        self.add_entry_with_data(time_ms, &[])
    }

    fn add_entry_with_data(
        &self,
        time_ms: u64,
        data: &[JournalEntryData],
    ) -> Result<EntryId, LogStorageError> {
        let mut g = self
            .inner
            .write()
            .map_err(|e| LogStorageError::Backend(format!("RwLock poisoned: {e}")))?;
        let id = EntryId(g.next_id);
        g.next_id = g.next_id.saturating_add(1);
        // A full log evicts its oldest entry.
        if let Some(cap) = g.capacity {
            while g.entries.len() >= cap {
                if g.entries.pop_front().is_none() {
                    break;
                }
            }
        }
        g.entries.push_back(JournalEntry {
            entry_id: id,
            time_ms,
            variables: data.to_vec(),
        });
        Ok(id)
    }

    fn add_entry_data(
        &self,
        entry_id: EntryId,
        data_ref: &str,
        value: MmsValue,
        reason_code: u8,
    ) -> Result<(), LogStorageError> {
        let mut g = self
            .inner
            .write()
            .map_err(|e| LogStorageError::Backend(format!("RwLock poisoned: {e}")))?;
        let entry = g
            .entries
            .iter_mut()
            .find(|e| e.entry_id == entry_id)
            .ok_or(LogStorageError::EntryIdNotFound(entry_id))?;
        entry.variables.push(JournalEntryData {
            data_ref: data_ref.to_string(),
            value,
            reason_code,
        });
        Ok(())
    }

    fn query_by_time(
        &self,
        start_ms: u64,
        end_ms: u64,
        visitor: &mut dyn LogEntryVisitor,
    ) -> Result<(), LogStorageError> {
        let g = self
            .inner
            .read()
            .map_err(|e| LogStorageError::Backend(format!("RwLock poisoned: {e}")))?;
        for entry in g.entries.iter() {
            if entry.time_ms >= start_ms && entry.time_ms <= end_ms && !visitor.visit(entry) {
                break;
            }
        }
        Ok(())
    }

    fn query_after(
        &self,
        starting_time_ms: u64,
        entry_id: EntryId,
        visitor: &mut dyn LogEntryVisitor,
    ) -> Result<(), LogStorageError> {
        // Both conditions apply: the entry identifier must be strictly greater than
        // the one given, and the time at least `starting_time_ms`.
        let g = self
            .inner
            .read()
            .map_err(|e| LogStorageError::Backend(format!("RwLock poisoned: {e}")))?;
        for entry in g.entries.iter() {
            if entry.entry_id > entry_id
                && entry.time_ms >= starting_time_ms
                && !visitor.visit(entry)
            {
                break;
            }
        }
        Ok(())
    }

    fn oldest_and_newest(&self) -> Result<Option<(EntryMeta, EntryMeta)>, LogStorageError> {
        let g = self
            .inner
            .read()
            .map_err(|e| LogStorageError::Backend(format!("RwLock poisoned: {e}")))?;
        let oldest = g.entries.front().map(|e| (e.entry_id, e.time_ms));
        let newest = g.entries.back().map(|e| (e.entry_id, e.time_ms));
        Ok(match (oldest, newest) {
            (Some(o), Some(n)) => Some((o, n)),
            _ => None,
        })
    }

    fn count(&self) -> usize {
        self.inner.read().map(|g| g.entries.len()).unwrap_or(0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Collecting visitor
// ─────────────────────────────────────────────────────────────────────────────

/// Visitor that clones every entry it is given into a `Vec`, for tests and simple
/// queries.
#[derive(Debug, Default)]
pub struct CollectingVisitor {
    /// Every entry the visitor was given, in visit order.
    pub entries: Vec<JournalEntry>,
}

impl CollectingVisitor {
    /// Creates a visitor holding no entries.
    pub fn new() -> Self {
        Self::default()
    }
}

impl LogEntryVisitor for CollectingVisitor {
    fn visit(&mut self, entry: &JournalEntry) -> bool {
        self.entries.push(entry.clone());
        true // never stops early
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_whole_entry_is_stored_at_once() {
        let s = InMemoryLogStorage::with_capacity(1);
        s.add_entry(1).unwrap();
        let id = s
            .add_entry_with_data(
                2,
                &[
                    JournalEntryData::new("a", MmsValue::Boolean(true), 0x10),
                    JournalEntryData::new("b", MmsValue::Integer(7), 0x10),
                ],
            )
            .unwrap();
        let mut v = CollectingVisitor::new();
        s.query_by_time(0, 9999, &mut v).unwrap();
        assert_eq!(v.entries.len(), 1, "the full log evicts its oldest entry");
        assert_eq!(v.entries[0].entry_id, id);
        let refs: Vec<_> = v.entries[0]
            .variables
            .iter()
            .map(|d| d.data_ref.as_str())
            .collect();
        assert_eq!(refs, ["a", "b"]);
    }

    #[test]
    fn add_entry_and_query_round_trip() {
        let s = InMemoryLogStorage::new();
        let id = s.add_entry(1000).unwrap();
        s.add_entry_data(id, "ref1", MmsValue::Boolean(true), 0x02)
            .unwrap();

        let mut v = CollectingVisitor::new();
        s.query_by_time(0, 9999, &mut v).unwrap();
        assert_eq!(v.entries.len(), 1);
        assert_eq!(v.entries[0].entry_id, id);
        assert_eq!(v.entries[0].time_ms, 1000);
        assert_eq!(v.entries[0].variables.len(), 1);
        assert_eq!(v.entries[0].variables[0].data_ref, "ref1");
        assert_eq!(v.entries[0].variables[0].reason_code, 0x02);
    }

    #[test]
    fn add_entry_data_to_unknown_entry_id_fails() {
        let s = InMemoryLogStorage::new();
        let r = s.add_entry_data(EntryId(99), "ref", MmsValue::Boolean(true), 0);
        assert!(matches!(r, Err(LogStorageError::EntryIdNotFound(_))));
    }

    #[test]
    fn query_by_time_filters_range() {
        let s = InMemoryLogStorage::new();
        s.add_entry(100).unwrap();
        s.add_entry(200).unwrap();
        s.add_entry(300).unwrap();

        let mut v = CollectingVisitor::new();
        s.query_by_time(150, 250, &mut v).unwrap();
        assert_eq!(v.entries.len(), 1);
        assert_eq!(v.entries[0].time_ms, 200);
    }

    #[test]
    fn query_after_uses_both_starting_time_and_entry_id() {
        // Both conditions apply.
        let s = InMemoryLogStorage::new();
        let id1 = s.add_entry(100).unwrap();
        let _id2 = s.add_entry(200).unwrap();
        let _id3 = s.add_entry(300).unwrap();

        // After id1 and at time 250 or later, only id3 at time 300 remains.
        let mut v = CollectingVisitor::new();
        s.query_after(250, id1, &mut v).unwrap();
        assert_eq!(v.entries.len(), 1);
        assert_eq!(v.entries[0].time_ms, 300);
    }

    #[test]
    fn oldest_and_newest_returns_pair() {
        let s = InMemoryLogStorage::new();
        let id1 = s.add_entry(100).unwrap();
        let id3 = s.add_entry(300).unwrap();
        let pair = s.oldest_and_newest().unwrap();
        assert!(pair.is_some());
        let ((oid, ot), (nid, nt)) = pair.unwrap();
        assert_eq!(oid, id1);
        assert_eq!(ot, 100);
        assert_eq!(nid, id3);
        assert_eq!(nt, 300);
    }

    #[test]
    fn oldest_and_newest_empty_returns_none() {
        let s = InMemoryLogStorage::new();
        assert!(s.oldest_and_newest().unwrap().is_none());
    }

    #[test]
    fn capacity_evicts_oldest() {
        let s = InMemoryLogStorage::with_capacity(2);
        s.add_entry(100).unwrap();
        s.add_entry(200).unwrap();
        s.add_entry(300).unwrap(); // evicts the entry at time 100
        assert_eq!(s.count(), 2);
        let pair = s.oldest_and_newest().unwrap().unwrap();
        assert_eq!(pair.0 .1, 200);
        assert_eq!(pair.1 .1, 300);
    }

    #[test]
    fn entry_id_be_bytes_round_trip() {
        let id = EntryId(0x0102030405060708);
        let b = id.to_be_bytes();
        assert_eq!(b, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(EntryId::from_be_bytes(b), id);
    }

    #[test]
    fn visitor_can_break_iteration() {
        struct OnlyFirst {
            count: usize,
        }
        impl LogEntryVisitor for OnlyFirst {
            fn visit(&mut self, _: &JournalEntry) -> bool {
                self.count += 1;
                false
            }
        }
        let s = InMemoryLogStorage::new();
        s.add_entry(100).unwrap();
        s.add_entry(200).unwrap();
        s.add_entry(300).unwrap();
        let mut v = OnlyFirst { count: 0 };
        s.query_by_time(0, 9999, &mut v).unwrap();
        assert_eq!(v.count, 1, "returning false must stop the walk at once");
    }
}
