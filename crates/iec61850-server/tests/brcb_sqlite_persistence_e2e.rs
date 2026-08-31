//! End-to-end test that a buffered report control block backed by SQLite keeps
//! its unsent reports across a server restart.
//!
//! One engine writes a hundred entries into a database file and is then dropped
//! outright, standing in for a server that was killed. A second engine reopens
//! the same file, must find all hundred entries, and, once its transmit anchor
//! is set past the fiftieth one as a reconnecting client would set it, flushes
//! exactly the fifty that follow.
//!
//! The entries are enqueued on the backend directly rather than raised through
//! the trigger path: what is under test is persistence across the drop and the
//! resynchronization that follows, and the trigger path is covered elsewhere.
//!
//! The temporary file is held for the whole test, because it is deleted when
//! its handle is dropped and the second engine still has to read it.

#![cfg(feature = "sqlite-backend")]

use bytes::Bytes;
use iec61850_server::reporting::{
    Brcb, BufferedReportControl, OverflowStrategy, ReportBufferBackend, ReportSink,
    ReportingEngine, SqliteReportBuffer, TransmitAnchor,
};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iec61850_server::ConnectionId;

/// A sink that keeps the PDU bytes it is handed. The one inside the crate is
/// compiled only for its own unit tests.
#[derive(Debug, Default)]
struct CollectSink {
    pdus: Mutex<Vec<(ConnectionId, Bytes)>>,
}

impl ReportSink for CollectSink {
    fn send_pdu(&self, conn_id: ConnectionId, pdu: Bytes) -> bool {
        // A poisoned lock cannot happen in this test, so the send is simply
        // dropped rather than handled.
        if let Ok(mut g) = self.pdus.lock() {
            g.push((conn_id, pdu));
        }
        true
    }
}

/// Writes a hundred entries, drops the engine as an abrupt restart would,
/// reopens the same database, checks that every entry survived, and flushes the
/// fifty that follow the cursor.
#[test]
fn brcb_sqlite_buffer_survives_engine_drop_and_resyncs_after_entry() {
    // The temporary file is created empty and handed over as a path that is
    // deleted on drop; opening the database overwrites the empty file. The path
    // is held for the whole test so the file outlives the first engine.
    let tmp_file = tempfile::NamedTempFile::new().expect("create a temporary file");
    let _db_path: tempfile::TempPath = tmp_file.into_temp_path();
    let db_path: PathBuf = _db_path.to_path_buf();

    let cursor;
    let total_pushed: usize = 100;

    // The first engine writes its entries and is then dropped.
    {
        let backend =
            SqliteReportBuffer::open(&db_path, "brcb01", 200, OverflowStrategy::DropOldest)
                .expect("open the SQLite backend");

        // The capacity is deliberately larger than what is written, so no entry
        // is evicted here.
        let brcb = Brcb::new("brcb01", "GGIO1$ds1").with_buffer_capacity(200);
        let brc =
            BufferedReportControl::with_backend("IED1LD0/GGIO1$BR$brcb01", brcb, Box::new(backend));

        let sink_a = Arc::new(CollectSink::default());
        let mut eng_a = ReportingEngine::new(sink_a.clone() as Arc<dyn ReportSink>);
        eng_a
            .register_brcb(brc)
            .expect("register the control block");

        let path = "IED1LD0/GGIO1$BR$brcb01";
        let brcb_arc = eng_a.get_brcb(path).expect("read the control block back");

        // The timestamps increase, so the entry identifiers do too.
        let mut ids = Vec::with_capacity(total_pushed);
        for i in 0..total_pushed as u64 {
            // The payload carries the index, so an entry can be identified in
            // the flushed PDU bytes.
            let payload = Bytes::from(vec![
                (i >> 24) as u8,
                (i >> 16) as u8,
                (i >> 8) as u8,
                i as u8,
            ]);
            let (id, evicted) = brcb_arc
                .enqueue_entry(1_000 + i, false, false, payload)
                .expect("enqueue an entry");
            assert!(!evicted, "the capacity must hold every entry, at i={i}");
            ids.push(id);
        }

        // The fiftieth entry identifier becomes the cursor, so half the entries
        // follow it.
        cursor = ids[49];

        assert_eq!(
            brcb_arc.lock_buffer().expect("lock buffer A").len(),
            total_pushed,
            "the buffer must hold all {total_pushed} entries"
        );

        // Dropping the engine releases the last reference to the control block,
        // which closes the backend and its database connection, flushing the
        // write-ahead log to disk.
        drop(brcb_arc);
        drop(eng_a);
        drop(sink_a);
    }

    // The second engine reopens the same database and resynchronizes.
    let backend_b = SqliteReportBuffer::open(&db_path, "brcb01", 200, OverflowStrategy::DropOldest)
        .expect("reopen the SQLite backend");

    // Every entry written before the drop is still there.
    let len_after_reopen = backend_b.len();
    assert_eq!(
        len_after_reopen, total_pushed,
        "reopening must find all {total_pushed} entries, found {len_after_reopen}"
    );

    // Reading from the cursor on the backend yields the entries after it.
    let from_cursor = backend_b.iter_from(&cursor);
    assert_eq!(
        from_cursor.len(),
        total_pushed - 50,
        "reading from the cursor must yield {} entries",
        total_pushed - 50
    );
    // The first of them comes after the cursor.
    assert!(
        from_cursor[0].entry_id.as_u64() > cursor.as_u64(),
        "the first entry read must come after the cursor"
    );

    // Only the buffer is persistent; the control block state is rebuilt, so the
    // sequence number starts from zero again.
    let brcb = Brcb::new("brcb01", "GGIO1$ds1").with_buffer_capacity(200);
    let brc =
        BufferedReportControl::with_backend("IED1LD0/GGIO1$BR$brcb01", brcb, Box::new(backend_b));

    let sink_b = Arc::new(CollectSink::default());
    let mut eng_b = ReportingEngine::new(sink_b.clone() as Arc<dyn ReportSink>);
    eng_b
        .register_brcb(brc)
        .expect("register the control block");

    let path = "IED1LD0/GGIO1$BR$brcb01";
    let brcb_arc = eng_b.get_brcb(path).expect("read the control block back");

    // As if a reconnecting client had written EntryID equal to the cursor. The
    // connection id on the state matters only to the trigger path, which this
    // test does not use; the flush takes its own connection id.
    {
        let mut s = brcb_arc.state.lock().expect("lock state B");
        s.transmit_anchor = TransmitAnchor::AfterEntryId(cursor);
        s.client_conn_id = Some(7);
    }

    // The flush is timed rather than guarded by a watchdog thread; a single
    // flush must not take anywhere near this long.
    let flush_start = std::time::Instant::now();
    let sent_count = eng_b.flush_brcb_pending(&brcb_arc, 7, 2_000_000);
    let flush_elapsed = flush_start.elapsed();
    assert!(
        flush_elapsed < Duration::from_secs(5),
        "the flush must not hang, it took {flush_elapsed:?}"
    );

    // The flush sends exactly the entries after the cursor.
    assert_eq!(
        sent_count,
        total_pushed - 50,
        "the flush must send the entries after the cursor, sent {sent_count}"
    );

    let pdus = sink_b.pdus.lock().expect("lock sink");
    assert_eq!(
        pdus.len(),
        total_pushed - 50,
        "the sink must receive one PDU per entry sent"
    );
    for (cid, _pdu) in pdus.iter() {
        assert_eq!(*cid, 7, "every PDU must go to the flushing connection");
    }
    drop(pdus);

    // The anchor ends up past the last entry sent.
    {
        let s = brcb_arc.state.lock().expect("lock state B post-flush");
        match &s.transmit_anchor {
            TransmitAnchor::AfterEntryId(id) => {
                // The last entry sent is the last one written.
                assert!(
                    id.as_u64() > cursor.as_u64(),
                    "the anchor must advance to the last entry sent"
                );
            }
            other => panic!("the anchor must point past an entry, got {other:?}"),
        }
    }

    // The second engine is dropped; the temporary file goes with it.
    drop(brcb_arc);
    drop(eng_b);
    drop(sink_b);
    // The path is still held here and is unlinked when the test returns.
}
