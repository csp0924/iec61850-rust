//! SQLite report buffer backend for a BRCB, behind the `sqlite-backend` feature.
//!
//! Implements `ReportBufferBackend` on top of a single SQLite file, so entries
//! that have not been sent survive a restart of the server process.
//!
//! The database runs in WAL mode with `synchronous = NORMAL`, which stays
//! crash-safe while doing fewer fsyncs than `FULL`. Several control blocks may
//! share one file; rows are separated by a `brcb_id` column.
//! `seq INTEGER PRIMARY KEY AUTOINCREMENT` preserves insertion order, so eviction
//! deletes the row with the smallest `seq`. An index on `(brcb_id, entry_id)`
//! serves the resynchronization lookup. Eviction costs a `SELECT MIN(seq)` plus a
//! `DELETE` on every push into a full buffer.
//!
//! `rusqlite::Connection` is neither `Send` nor `Sync`, so the connection is held
//! in a `Mutex`; because `ReportBufferBackend` also requires `Send + Sync`, the
//! caller's own lock sits outside it.
//!
//! Behavior matches the in-memory backend exactly: `is_overflow` starts true,
//! `purge()` removes the entries without touching `is_overflow`, `DropOldest`
//! evicts while `DropNewest` and `Reject` refuse the new entry, and the shared
//! `dropped_buffer_full` counter injected through `set_dropped_counter` is
//! incremented on every dropped entry.

use super::buffer::{EntryId, OverflowStrategy, ReportBufferBackend, ReportEntry, SeekResult};
use bytes::Bytes;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// SQLite-backed BRCB report buffer.
///
/// One connection is shared across every trait method behind a `Mutex`. The
/// schema is:
/// ```sql
/// CREATE TABLE IF NOT EXISTS report_entries (
///     seq              INTEGER PRIMARY KEY AUTOINCREMENT,
///     brcb_id          TEXT    NOT NULL,
///     entry_id         BLOB    NOT NULL,
///     time_of_entry_ms INTEGER NOT NULL,
///     is_integrity     INTEGER NOT NULL,
///     is_gi            INTEGER NOT NULL,
///     payload          BLOB    NOT NULL
/// );
/// CREATE INDEX IF NOT EXISTS idx_brcb_entry
///     ON report_entries (brcb_id, entry_id);
/// ```
pub struct SqliteReportBuffer {
    inner: Mutex<SqliteInner>,
}

struct SqliteInner {
    conn: Connection,
    capacity: usize,
    strategy: OverflowStrategy,
    brcb_id: String,
    overflow: bool,
    dropped_counter: Option<Arc<AtomicU64>>,
}

impl std::fmt::Debug for SqliteReportBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.inner.lock() {
            Ok(g) => f
                .debug_struct("SqliteReportBuffer")
                .field("brcb_id", &g.brcb_id)
                .field("capacity", &g.capacity)
                .field("strategy", &g.strategy)
                .field("overflow", &g.overflow)
                .finish(),
            Err(_) => f
                .debug_struct("SqliteReportBuffer")
                .field("state", &"<poisoned>")
                .finish(),
        }
    }
}

impl SqliteReportBuffer {
    /// Opens or creates the database file and initializes the schema.
    ///
    /// `path` may be a file path or `:memory:`, which gives an isolated in-memory
    /// database per call. `brcb_id` separates the rows of control blocks that share
    /// one file.
    ///
    /// # Errors
    ///
    /// Returns the `rusqlite` error when the database cannot be opened or the
    /// schema cannot be created.
    pub fn open(
        path: &Path,
        brcb_id: &str,
        capacity: usize,
        strategy: OverflowStrategy,
    ) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        Self::init_schema(&conn)?;
        Ok(Self {
            inner: Mutex::new(SqliteInner {
                conn,
                capacity,
                strategy,
                brcb_id: brcb_id.to_string(),
                // A report buffer starts with isOverflow set, as the in-memory
                // backend does.
                overflow: true,
                dropped_counter: None,
            }),
        })
    }

    /// Opens a purely in-memory database, for tests.
    #[cfg(test)]
    pub fn open_memory(
        brcb_id: &str,
        capacity: usize,
        strategy: OverflowStrategy,
    ) -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init_schema(&conn)?;
        Ok(Self {
            inner: Mutex::new(SqliteInner {
                conn,
                capacity,
                strategy,
                brcb_id: brcb_id.to_string(),
                overflow: true,
                dropped_counter: None,
            }),
        })
    }

    fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
        // WAL improves concurrent reads and stays crash-safe; synchronous = NORMAL
        // is still ACID under WAL and does fewer fsyncs than FULL, which suits a
        // buffer written in bursts and read later. The PRAGMA result is consumed
        // through query_row because some SQLite versions otherwise buffer it.
        let _: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        conn.execute_batch(
            "PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS report_entries (
                 seq              INTEGER PRIMARY KEY AUTOINCREMENT,
                 brcb_id          TEXT    NOT NULL,
                 entry_id         BLOB    NOT NULL,
                 time_of_entry_ms INTEGER NOT NULL,
                 is_integrity     INTEGER NOT NULL,
                 is_gi            INTEGER NOT NULL,
                 payload          BLOB    NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_brcb_entry
                 ON report_entries (brcb_id, entry_id);",
        )?;
        Ok(())
    }

    /// Returns how many entries are stored for one `brcb_id`.
    ///
    /// A failed query reports 0 rather than propagating; the caller decides whether
    /// to treat that as an error.
    pub fn count_for(&self, brcb_id: &str) -> usize {
        let Ok(g) = self.inner.lock() else {
            return 0;
        };
        let res: rusqlite::Result<i64> = g.conn.query_row(
            "SELECT COUNT(*) FROM report_entries WHERE brcb_id = ?",
            params![brcb_id],
            |row| row.get(0),
        );
        res.map(|n| n as usize).unwrap_or(0)
    }
}

impl SqliteInner {
    /// Converts an EntryID BLOB back into `[u8; 8]`.
    ///
    /// External input is converted rather than sliced blindly.
    fn entry_id_from_blob(blob: &[u8]) -> rusqlite::Result<[u8; 8]> {
        <[u8; 8]>::try_from(blob).map_err(|_| {
            rusqlite::Error::FromSqlConversionFailure(
                blob.len(),
                rusqlite::types::Type::Blob,
                Box::<dyn std::error::Error + Send + Sync>::from(format!(
                    "EntryID BLOB must be exactly 8 bytes, was {} bytes",
                    blob.len()
                )),
            )
        })
    }

    /// Counts the entries stored for this control block.
    fn count(&self) -> rusqlite::Result<i64> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM report_entries WHERE brcb_id = ?",
            params![&self.brcb_id],
            |row| row.get(0),
        )
    }

    /// Evicts the oldest entry, for the `DropOldest` strategy. Returns whether a
    /// row was actually deleted.
    fn evict_oldest(&self) -> rusqlite::Result<bool> {
        let oldest_seq: Option<i64> = self
            .conn
            .query_row(
                "SELECT seq FROM report_entries WHERE brcb_id = ? ORDER BY seq ASC LIMIT 1",
                params![&self.brcb_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(seq) = oldest_seq else {
            return Ok(false);
        };
        let n = self
            .conn
            .execute("DELETE FROM report_entries WHERE seq = ?", params![seq])?;
        Ok(n > 0)
    }

    /// Increments the injected drop counter, when one has been injected.
    fn bump_dropped_counter(&self) {
        if let Some(c) = &self.dropped_counter {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Inserts one entry. Capacity is the caller's concern: eviction or rejection
    /// has already been decided.
    fn insert(&self, entry: &Arc<ReportEntry>) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO report_entries
                (brcb_id, entry_id, time_of_entry_ms, is_integrity, is_gi, payload)
             VALUES (?, ?, ?, ?, ?, ?)",
            params![
                &self.brcb_id,
                &entry.entry_id.0[..],
                entry.time_of_entry_ms as i64,
                entry.is_integrity as i32,
                entry.is_gi as i32,
                entry.encoded_payload.as_ref(),
            ],
        )?;
        Ok(())
    }

    /// Builds a `ReportEntry` from a SQL row. `rusqlite` rows cannot be borrowed
    /// past the statement, so every value is copied out.
    fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<Arc<ReportEntry>> {
        let entry_id_blob: Vec<u8> = row.get(0)?;
        let entry_id = Self::entry_id_from_blob(&entry_id_blob)?;
        let time_of_entry_ms: i64 = row.get(1)?;
        let is_integrity: i32 = row.get(2)?;
        let is_gi: i32 = row.get(3)?;
        let payload: Vec<u8> = row.get(4)?;
        Ok(Arc::new(ReportEntry::new(
            EntryId(entry_id),
            time_of_entry_ms as u64,
            is_integrity != 0,
            is_gi != 0,
            Bytes::from(payload),
        )))
    }
}

impl ReportBufferBackend for SqliteReportBuffer {
    fn push(&mut self, entry: Arc<ReportEntry>) -> bool {
        // A poisoned mutex must not panic, so the entry is dropped with a warning.
        let Ok(mut g) = self.inner.lock() else {
            tracing::warn!("sqlite report buffer mutex poisoned, entry dropped");
            return false;
        };
        if g.capacity == 0 {
            tracing::warn!("brcb sqlite buffer capacity is 0, entry not stored");
            return false;
        }

        let count = match g.count() {
            Ok(n) => n as usize,
            Err(e) => {
                tracing::warn!(error = %e, "sqlite report buffer count failed, entry dropped");
                return false;
            }
        };

        let mut evicted = false;
        if count >= g.capacity {
            match g.strategy {
                OverflowStrategy::DropOldest => {
                    // Evict until there is room; one round suffices for a positive
                    // capacity.
                    while {
                        let c = g.count().unwrap_or(0) as usize;
                        c >= g.capacity
                    } {
                        match g.evict_oldest() {
                            Ok(true) => {
                                g.bump_dropped_counter();
                                evicted = true;
                            }
                            Ok(false) => break,
                            Err(e) => {
                                tracing::warn!(error = %e, "sqlite report buffer eviction failed");
                                break;
                            }
                        }
                    }
                }
                OverflowStrategy::DropNewest | OverflowStrategy::Reject => {
                    g.bump_dropped_counter();
                    g.overflow = true;
                    tracing::warn!(
                        strategy = ?g.strategy,
                        capacity = g.capacity,
                        "brcb sqlite buffer full, rejecting the new entry"
                    );
                    return true; // a true return here means rejected, not evicted
                }
            }
        }

        if let Err(e) = g.insert(&entry) {
            tracing::warn!(error = %e, "sqlite report buffer insert failed, entry dropped");
            return false;
        }

        if evicted {
            g.overflow = true;
        }
        evicted
    }

    fn find_entry(&self, id: &EntryId) -> Option<Arc<ReportEntry>> {
        // The (brcb_id, entry_id) index answers this with a single row lookup.
        let g = self.inner.lock().ok()?;
        let mut stmt = g
            .conn
            .prepare(
                "SELECT entry_id, time_of_entry_ms, is_integrity, is_gi, payload
                 FROM report_entries
                 WHERE brcb_id = ? AND entry_id = ?
                 LIMIT 1",
            )
            .ok()?;
        let mut rows = stmt
            .query_map(params![&g.brcb_id, &id.0[..]], SqliteInner::row_to_entry)
            .ok()?;
        match rows.next() {
            Some(Ok(entry)) => Some(entry),
            Some(Err(e)) => {
                tracing::warn!(error = %e, "sqlite report buffer find_entry row decode failed");
                None
            }
            None => None,
        }
    }

    fn seek_to_after_entry_id(&self, id: &EntryId) -> SeekResult {
        // First resolve the EntryID to its seq through the (brcb_id, entry_id)
        // index, then look for the first row with a greater seq: none means this was
        // the newest entry, one means transmission resumes there.
        let Ok(g) = self.inner.lock() else {
            tracing::warn!("sqlite report buffer seek mutex poisoned, answering NotFound");
            return SeekResult::NotFound;
        };
        let target_seq: Option<i64> = match g
            .conn
            .query_row(
                "SELECT seq FROM report_entries WHERE brcb_id = ? AND entry_id = ? LIMIT 1",
                params![&g.brcb_id, &id.0[..]],
                |row| row.get(0),
            )
            .optional()
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "sqlite report buffer seek failed to read seq");
                return SeekResult::NotFound;
            }
        };
        let Some(seq) = target_seq else {
            return SeekResult::NotFound;
        };
        // The next row for the same control block, by strictly greater seq.
        let next_row = g
            .conn
            .query_row(
                "SELECT entry_id, time_of_entry_ms, is_integrity, is_gi, payload
                 FROM report_entries
                 WHERE brcb_id = ? AND seq > ?
                 ORDER BY seq ASC
                 LIMIT 1",
                params![&g.brcb_id, seq],
                SqliteInner::row_to_entry,
            )
            .optional();
        match next_row {
            Ok(Some(next)) => SeekResult::FoundWithNext(next),
            Ok(None) => SeekResult::FoundLast,
            Err(e) => {
                tracing::warn!(error = %e, "sqlite report buffer seek failed to read the next row");
                // The query failed but the target row does exist, so this is neither
                // NotFound nor FoundWithNext. FoundLast sends the caller down the
                // WaitingForNext path without falsely setting is_overflow.
                SeekResult::FoundLast
            }
        }
    }

    fn purge(&mut self) -> usize {
        let Ok(g) = self.inner.lock() else {
            return 0;
        };
        match g.conn.execute(
            "DELETE FROM report_entries WHERE brcb_id = ?",
            params![&g.brcb_id],
        ) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(error = %e, "sqlite report buffer purge failed");
                0
            }
        }
    }

    fn len(&self) -> usize {
        let Ok(g) = self.inner.lock() else {
            return 0;
        };
        g.count().unwrap_or(0) as usize
    }

    fn is_overflow(&self) -> bool {
        let Ok(g) = self.inner.lock() else {
            return false;
        };
        g.overflow
    }

    fn clear_overflow(&mut self) {
        if let Ok(mut g) = self.inner.lock() {
            g.overflow = false;
        }
    }

    fn iter_entries(&self) -> Vec<Arc<ReportEntry>> {
        let Ok(g) = self.inner.lock() else {
            return Vec::new();
        };
        let Ok(mut stmt) = g.conn.prepare(
            "SELECT entry_id, time_of_entry_ms, is_integrity, is_gi, payload
             FROM report_entries
             WHERE brcb_id = ?
             ORDER BY seq ASC",
        ) else {
            return Vec::new();
        };
        let rows = stmt.query_map(params![&g.brcb_id], SqliteInner::row_to_entry);
        match rows {
            Ok(iter) => iter.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                tracing::warn!(error = %e, "sqlite report buffer iter_entries failed");
                Vec::new()
            }
        }
    }

    fn iter_from(&self, after: &EntryId) -> Vec<Arc<ReportEntry>> {
        let Ok(g) = self.inner.lock() else {
            return Vec::new();
        };
        // Ordering by the entry_id BLOB is a lexicographic order, which for a
        // big-endian u64 is the numeric order. The comparison uses the
        // (brcb_id, entry_id) index.
        let Ok(mut stmt) = g.conn.prepare(
            "SELECT entry_id, time_of_entry_ms, is_integrity, is_gi, payload
             FROM report_entries
             WHERE brcb_id = ? AND entry_id > ?
             ORDER BY entry_id ASC",
        ) else {
            return Vec::new();
        };
        let rows = stmt.query_map(params![&g.brcb_id, &after.0[..]], SqliteInner::row_to_entry);
        match rows {
            Ok(iter) => iter.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                tracing::warn!(error = %e, "sqlite report buffer iter_from failed");
                Vec::new()
            }
        }
    }

    fn overflow_strategy(&self) -> OverflowStrategy {
        match self.inner.lock() {
            Ok(g) => g.strategy,
            Err(_) => OverflowStrategy::DropOldest,
        }
    }

    fn set_dropped_counter(&mut self, counter: Arc<AtomicU64>) {
        if let Ok(mut g) = self.inner.lock() {
            g.dropped_counter = Some(counter);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use tempfile::TempDir;

    fn make_entry(id_ms: u64, payload_byte: u8) -> Arc<ReportEntry> {
        Arc::new(ReportEntry::new(
            EntryId::from_ms(id_ms),
            id_ms,
            false,
            false,
            Bytes::from(vec![payload_byte; 4]),
        ))
    }

    /// Entries written before the process ends are still there after reopening the
    /// same database file.
    #[test]
    fn roundtrip_persists_entries() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("brcb.db");

        // Open the file, store five entries, then close it.
        {
            let mut buf =
                SqliteReportBuffer::open(&path, "brcb01", 16, OverflowStrategy::DropOldest)
                    .unwrap();
            for i in 0..5u64 {
                buf.push(make_entry(1000 + i, i as u8));
            }
            assert_eq!(buf.len(), 5);
        } // drop here

        // Reopen the same file; every entry must still be present.
        {
            let buf = SqliteReportBuffer::open(&path, "brcb01", 16, OverflowStrategy::DropOldest)
                .unwrap();
            assert_eq!(buf.len(), 5, "entries must survive a reopen");
            let entries = buf.iter_entries();
            assert_eq!(entries.len(), 5);
            // Insertion order is preserved.
            for (i, e) in entries.iter().enumerate() {
                assert_eq!(e.entry_id.as_u64(), 1000 + i as u64);
            }
        }
    }

    /// Every eviction under `DropOldest` increments `dropped_buffer_full`.
    #[test]
    fn evict_increments_dropped_counter() {
        let mut buf =
            SqliteReportBuffer::open_memory("brcb01", 4, OverflowStrategy::DropOldest).unwrap();
        let counter = Arc::new(AtomicU64::new(0));
        buf.set_dropped_counter(counter.clone());

        // A capacity of 4 with 14 pushes evicts 10 entries.
        for i in 0..14u64 {
            buf.push(make_entry(1000 + i, i as u8));
        }
        assert_eq!(buf.len(), 4, "the buffer must stay at a capacity of 4");
        assert_eq!(
            counter.load(Ordering::Relaxed),
            10,
            "14 pushes into a capacity of 4 must evict 10 entries"
        );
    }

    /// `DropNewest` refuses the new entry and keeps the stored ones.
    #[test]
    fn overflow_strategy_drop_newest_rejects_new() {
        let mut buf =
            SqliteReportBuffer::open_memory("brcb01", 2, OverflowStrategy::DropNewest).unwrap();
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
            "a full drop-newest buffer must report a rejection"
        );
        assert_eq!(buf.len(), 2);
        // The stored entries are still there.
        let v = buf.iter_entries();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].entry_id.as_u64(), 100);
        assert_eq!(v[1].entry_id.as_u64(), 101);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        assert!(buf.is_overflow());
    }

    /// `Reject` behaves exactly like `DropNewest`.
    #[test]
    fn overflow_strategy_reject_same_as_drop_newest() {
        let mut buf =
            SqliteReportBuffer::open_memory("brcb01", 2, OverflowStrategy::Reject).unwrap();
        let counter = Arc::new(AtomicU64::new(0));
        buf.set_dropped_counter(counter.clone());

        buf.push(make_entry(100, 1));
        buf.push(make_entry(101, 2));
        let rejected = buf.push(make_entry(102, 3));
        assert!(rejected);
        assert_eq!(buf.len(), 2);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        assert_eq!(buf.overflow_strategy(), OverflowStrategy::Reject);
    }

    /// The database really is in WAL mode.
    #[test]
    fn wal_mode_enabled() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.db");
        let buf =
            SqliteReportBuffer::open(&path, "brcb01", 4, OverflowStrategy::DropOldest).unwrap();
        let g = buf.inner.lock().unwrap();
        let mode: String = g
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal", "journal_mode must be wal");
    }

    /// Control blocks sharing one file are separated by `brcb_id`.
    #[test]
    fn multi_brcb_isolation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("multi.db");

        let mut buf_a =
            SqliteReportBuffer::open(&path, "brcbA", 16, OverflowStrategy::DropOldest).unwrap();
        let mut buf_b =
            SqliteReportBuffer::open(&path, "brcbB", 16, OverflowStrategy::DropOldest).unwrap();

        for i in 0..5u64 {
            buf_a.push(make_entry(1000 + i, i as u8));
        }
        for i in 0..3u64 {
            buf_b.push(make_entry(2000 + i, i as u8));
        }

        assert_eq!(buf_a.len(), 5);
        assert_eq!(buf_b.len(), 3);

        // Purging B leaves A alone.
        let purged = buf_b.purge();
        assert_eq!(purged, 3);
        assert_eq!(buf_b.len(), 0);
        assert_eq!(buf_a.len(), 5, "purging B must not affect A");
    }

    /// `iter_from` returns the entries whose EntryID is strictly greater than the
    /// cutoff, in ascending order.
    #[test]
    fn iter_from_returns_strictly_after() {
        let mut buf =
            SqliteReportBuffer::open_memory("brcb01", 16, OverflowStrategy::DropOldest).unwrap();
        for i in 0..5u64 {
            buf.push(make_entry(100 + i, i as u8));
        }
        let v = buf.iter_from(&EntryId::from_ms(101));
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].entry_id.as_u64(), 102);
        assert_eq!(v[2].entry_id.as_u64(), 104);
    }

    /// A thousand entries with continuous eviction neither panics nor deadlocks.
    #[test]
    fn stress_thousand_entries_evicts_without_panic() {
        let mut buf =
            SqliteReportBuffer::open_memory("brcb01", 50, OverflowStrategy::DropOldest).unwrap();
        let counter = Arc::new(AtomicU64::new(0));
        buf.set_dropped_counter(counter.clone());

        for i in 0..1000u64 {
            buf.push(make_entry(10_000 + i, (i % 256) as u8));
        }
        assert_eq!(buf.len(), 50, "the buffer must stay at a capacity of 50");
        // 1000 pushes into a capacity of 50 evict 950 entries.
        assert_eq!(counter.load(Ordering::Relaxed), 950);
    }

    // ─── find_entry and seek_to_after_entry_id ────────────────────

    /// `find_entry` returns the stored entry.
    #[test]
    fn find_entry_returns_the_stored_entry_or_none() {
        let mut buf =
            SqliteReportBuffer::open_memory("brcb01", 8, OverflowStrategy::DropOldest).unwrap();
        let e1 = make_entry(100, 0xAA);
        let e2 = make_entry(200, 0xBB);
        buf.push(e1.clone());
        buf.push(e2.clone());
        let got = buf.find_entry(&e1.entry_id).expect("e1 must be found");
        assert_eq!(got.entry_id, e1.entry_id);
        assert_eq!(got.time_of_entry_ms, 100);
        let got2 = buf.find_entry(&e2.entry_id).expect("e2 must be found");
        assert_eq!(got2.entry_id, e2.entry_id);
        // An identifier that was never stored.
        assert!(buf.find_entry(&EntryId::from_ms(999)).is_none());
    }

    #[test]
    fn seek_to_after_entry_id_sqlite_found_with_next() {
        let mut buf =
            SqliteReportBuffer::open_memory("brcb01", 8, OverflowStrategy::DropOldest).unwrap();
        let e1 = make_entry(100, 1);
        let e2 = make_entry(200, 2);
        let e3 = make_entry(300, 3);
        buf.push(e1.clone());
        buf.push(e2.clone());
        buf.push(e3);
        match buf.seek_to_after_entry_id(&e1.entry_id) {
            SeekResult::FoundWithNext(next) => {
                assert_eq!(next.entry_id, e2.entry_id);
            }
            other => panic!("expected FoundWithNext, got {:?}", other),
        }
    }

    #[test]
    fn seek_to_after_entry_id_sqlite_found_last() {
        let mut buf =
            SqliteReportBuffer::open_memory("brcb01", 8, OverflowStrategy::DropOldest).unwrap();
        let e1 = make_entry(100, 1);
        let e2 = make_entry(200, 2);
        buf.push(e1);
        buf.push(e2.clone());
        match buf.seek_to_after_entry_id(&e2.entry_id) {
            SeekResult::FoundLast => {}
            other => panic!("expected FoundLast, got {:?}", other),
        }
    }

    #[test]
    fn seek_to_after_entry_id_sqlite_not_found() {
        let mut buf =
            SqliteReportBuffer::open_memory("brcb01", 8, OverflowStrategy::DropOldest).unwrap();
        buf.push(make_entry(100, 1));
        match buf.seek_to_after_entry_id(&EntryId::from_ms(999)) {
            SeekResult::NotFound => {}
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    /// A purge empties the buffer and leaves `is_overflow` alone; only the send
    /// path clears it.
    #[test]
    fn purge_clears_entries_but_not_overflow() {
        let mut buf =
            SqliteReportBuffer::open_memory("brcb01", 16, OverflowStrategy::DropOldest).unwrap();
        for i in 0..5u64 {
            buf.push(make_entry(100 + i, i as u8));
        }
        assert!(buf.is_overflow(), "a new buffer starts with overflow set");
        let n = buf.purge();
        assert_eq!(n, 5);
        assert_eq!(buf.len(), 0);
        // purge does not touch the overflow flag.
        assert!(buf.is_overflow());
    }
}
