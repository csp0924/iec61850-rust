//! End-to-end test that buffered reporting loses nothing across reconnects.
//!
//! Five clients each receive a thousand events over five rounds, disconnecting
//! and resynchronizing between rounds; all five thousand reports must arrive
//! and their entry identifiers must increase strictly.
//!
//! No socket is opened; the resynchronization semantics are driven on the
//! engine. Each client gets its own control block, because a buffered control
//! block serves one client at a time.
//!
//! Two behaviors are singled out. When the client writes back the identifier of
//! the last entry in the buffer there is nothing to send yet, so the anchor
//! waits for the next entry; enqueueing one must move the anchor past that last
//! identifier so the new entry is sent. And after every flush the anchor must
//! sit past the last entry sent, with the sequence number advanced.

use bytes::Bytes;
use iec61850_model::MmsValue;
use iec61850_server::connection::ConnectionId;
use iec61850_server::reporting::{
    Brcb, BufferedReportControl, Dataset, DatasetEntry, EntryId, InclusionFlag, OptFlds,
    ReportSink, ReportingEngine, TransmitAnchor, TriggerOptions,
};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

/// A sink that keeps the PDU bytes it is handed. The one inside the crate is
/// compiled only for its own unit tests.
#[derive(Debug, Default)]
struct BucketSink {
    pdus: Mutex<Vec<(ConnectionId, Bytes)>>,
}

impl BucketSink {
    fn new() -> Self {
        Self::default()
    }

    /// Takes everything collected so far and clears the buffer, as a client
    /// losing its connection would.
    fn drain(&self) -> Vec<(ConnectionId, Bytes)> {
        let mut g = self.pdus.lock().expect("BucketSink poisoned");
        std::mem::take(&mut *g)
    }
}

impl ReportSink for BucketSink {
    fn send_pdu(&self, conn_id: ConnectionId, pdu: Bytes) -> bool {
        self.pdus
            .lock()
            .expect("BucketSink poisoned")
            .push((conn_id, pdu));
        true
    }
}

/// Reads the EntryID out of a report PDU by finding the first eight-byte octet
/// string, which the report carries under an implicit context tag.
///
/// A data set member could in principle be an eight-byte octet string too, so
/// the first match is taken as the EntryID; the data set used here holds a
/// boolean, so there is no ambiguity.
fn extract_entry_id_be(pdu: &[u8]) -> Option<u64> {
    pdu.windows(10)
        .find(|w| w[0] == 0x89 && w[1] == 0x08)
        .map(|w| {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&w[2..10]);
            u64::from_be_bytes(buf)
        })
}

// Fixture for one buffered control block; the caller owns the connection id.

const BRCB_CAP: usize = 6000; // well past the events per client, so nothing is evicted
const EVENTS_PER_ROUND: usize = 200;
const ROUNDS_PER_CLIENT: usize = 5;
const TOTAL_EVENTS_PER_CLIENT: usize = EVENTS_PER_ROUND * ROUNDS_PER_CLIENT; // 1000

/// Registers one buffered control block over a single-member data set.
///
/// Each client gets its own control block, keyed by its index in the path.
fn register_one_brcb(
    eng: &mut ReportingEngine,
    client_idx: usize,
) -> (String, Arc<RwLock<MmsValue>>, String) {
    let mms_path = format!("IED1LD0/GGIO{client_idx}$BR$brcb01");
    let attr_ref = format!("IED1LD0/GGIO{client_idx}$ST$Ind1$stVal");
    let val = Arc::new(RwLock::new(MmsValue::Boolean(false)));

    let mut ds = Dataset::new(format!("GGIO{client_idx}$ds1"));
    ds.push(DatasetEntry::new(&attr_ref, val.clone()));

    let brcb = Brcb::new("brcb01", format!("GGIO{client_idx}$ds1"))
        .with_buffer_capacity(BRCB_CAP)
        .with_trg_ops(TriggerOptions::DATA_CHANGED)
        // The entryID option field has to be set or the reports carry no
        // EntryID for the assertions to read.
        .with_opt_flds(OptFlds::SEQ_NUM | OptFlds::ENTRY_ID | OptFlds::BUFFER_OVERFLOW);
    let brc = BufferedReportControl::new(&mms_path, brcb);
    eng.register_brcb_with_dataset(brc, ds)
        .expect("register_brcb_with_dataset");

    (mms_path, val, attr_ref)
}

/// Runs one resynchronization round on a control block: write the EntryID to
/// set the anchor, raise `count` triggers, flush, and return the PDUs the sink
/// collected. The caller sets the connection id beforehand.
///
/// The attribute reference is taken by `&String` to match the engine signature.
#[allow(clippy::ptr_arg)]
#[allow(clippy::too_many_arguments)]
fn run_round_default(
    eng: &ReportingEngine,
    brcb_path: &str,
    attr_ref: &String,
    val: &Arc<RwLock<MmsValue>>,
    sink: &Arc<BucketSink>,
    conn_id: ConnectionId,
    start_id: EntryId,
    count: usize,
    base_now_ms: u64,
) -> Vec<(ConnectionId, Bytes)> {
    let brcb_arc = eng
        .get_brcb(brcb_path)
        .expect("the control block must be registered");

    // Set the anchor: an all-zero identifier means from the head, anything else
    // seeks in the buffer.
    {
        let outcome = brcb_arc
            .apply_entry_id_write(start_id)
            .expect("apply_entry_id_write infrastructure");
        // The buffer is large enough that no entry has been evicted, so every
        // identifier the client can write is still found.
        outcome.expect("the EntryID must still be in the buffer");
    }

    // Raise the triggers; a zero buffer time enqueues each one immediately.
    for i in 0..count {
        // Flip the value on every trigger so each one is a real data change.
        let new_v = i % 2 == 0;
        {
            *val.write().expect("val poisoned") = MmsValue::Boolean(new_v);
        }
        eng.on_brcb_value_updated(
            attr_ref,
            MmsValue::Boolean(new_v),
            InclusionFlag::VALUE_CHANGED,
            base_now_ms + i as u64,
        );
    }

    // (3) flush
    let now_ms = base_now_ms + count as u64;
    let sent = eng.flush_brcb_pending(&brcb_arc, conn_id, now_ms);
    assert_eq!(
        sent,
        count,
        "the round must flush {count} entries for conn_id={conn_id}, start_id={:#x}",
        start_id.as_u64()
    );

    // Take the PDUs this round produced.
    let pdus = sink.drain();
    assert_eq!(
        pdus.len(),
        count,
        "the sink must receive {count} PDUs for conn_id={conn_id}"
    );
    pdus
}

// Five clients, five rounds of two hundred events each: every report arrives,
// identifiers increase strictly, and the waiting-for-next path is exercised.

#[tokio::test(flavor = "current_thread")]
async fn brcb_reconnect_resync_5clients_5rounds_no_loss_strict_increasing_entry_id() {
    tokio::time::timeout(Duration::from_secs(30), async {
        // Engine and sink.
        let sink: Arc<BucketSink> = Arc::new(BucketSink::new());
        let mut eng = ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>);

        // One control block per client.
        let conn_ids: [ConnectionId; 5] = [10, 20, 30, 40, 50];
        let mut brcbs: Vec<(String, Arc<RwLock<MmsValue>>, String)> = Vec::with_capacity(5);
        for (i, _cid) in conn_ids.iter().enumerate() {
            brcbs.push(register_one_brcb(&mut eng, i + 1));
        }

        // Total PDUs across all clients.
        let mut grand_total: usize = 0;
        // The identifiers each client received, in order.
        let mut per_client_ids: Vec<Vec<u64>> = (0..5)
            .map(|_| Vec::with_capacity(TOTAL_EVENTS_PER_CLIENT))
            .collect();

        // The waiting-for-next path only has to be exercised once.
        let mut waiting_for_next_path_verified = false;

        // five clients, five rounds
        for (ci, &conn_id) in conn_ids.iter().enumerate() {
            let (brcb_path, val, attr_ref) = &brcbs[ci];
            let brcb_arc = eng.get_brcb(brcb_path).expect("BRCB");

            // The client connects for the first time.
            {
                let mut s = brcb_arc.state.lock().expect("state");
                s.client_conn_id = Some(conn_id);
            }

            // The first round starts from the head; later rounds start from the
            // last identifier the client saw.
            let mut next_start_id = EntryId::ZERO;
            let mut last_seen_id: u64 = 0;

            for round in 0..ROUNDS_PER_CLIENT {
                let base_now_ms = 1_000_000 + (ci * 100_000 + round * 1_000) as u64;

                // One round is split in two by hand to reach the waiting-for-next
                // path: the written EntryID lands on the last entry in the
                // buffer, and the following trigger has to move the anchor on.
                // It needs an earlier round to have produced that identifier.
                let force_waiting_for_next_path =
                    !waiting_for_next_path_verified && ci == 0 && round == 2;

                if force_waiting_for_next_path {
                    // Write back the identifier of the last entry in the buffer.
                    let last_id = EntryId::from_ms(last_seen_id);
                    let outcome = brcb_arc.apply_entry_id_write(last_id).expect("apply infra");
                    outcome.expect("the entry must still be in the buffer");

                    // The anchor waits for the next entry.
                    {
                        let s = brcb_arc.state.lock().expect("state");
                        assert_eq!(
                            s.transmit_anchor,
                            TransmitAnchor::WaitingForNext,
                            "an identifier at the end of the buffer must leave the anchor waiting"
                        );
                    }

                    // Nothing is sent while the anchor is waiting.
                    let n_zero = eng.flush_brcb_pending(&brcb_arc, conn_id, base_now_ms);
                    assert_eq!(n_zero, 0, "a waiting anchor must send nothing");
                    let drained_zero = sink.drain();
                    assert!(
                        drained_zero.is_empty(),
                        "a flush on a waiting anchor must produce no PDU"
                    );

                    // A new entry moves the anchor past the identifier it was
                    // waiting on.
                    {
                        *val.write().expect("val") = MmsValue::Boolean(true);
                    }
                    eng.on_brcb_value_updated(
                        attr_ref,
                        MmsValue::Boolean(true),
                        InclusionFlag::VALUE_CHANGED,
                        base_now_ms + 1,
                    );

                    // The anchor has moved.
                    {
                        let s = brcb_arc.state.lock().expect("state");
                        assert_eq!(
                            s.transmit_anchor,
                            TransmitAnchor::AfterEntryId(last_id),
                            "enqueueing must move a waiting anchor past the identifier it waited on"
                        );
                    }

                    // The flush now sends that new entry.
                    let n_one = eng.flush_brcb_pending(&brcb_arc, conn_id, base_now_ms + 2);
                    assert_eq!(
                        n_one, 1,
                        "the flush must send the entry that released the anchor"
                    );

                    // Its identifier must still increase.
                    let drained_one = sink.drain();
                    assert_eq!(drained_one.len(), 1);
                    let (cid, pdu) = &drained_one[0];
                    assert_eq!(*cid, conn_id);
                    let eid = extract_entry_id_be(pdu).expect("the PDU must carry an EntryID");
                    assert!(
                        eid > last_seen_id,
                        "the released entry must come after the one the client saw"
                    );
                    last_seen_id = eid;
                    per_client_ids[ci].push(eid);
                    grand_total += 1;

                    // The rest of the round runs normally so the totals hold.
                    let remain = EVENTS_PER_ROUND - 1;
                    let pdus = run_round_default(
                        &eng,
                        brcb_path,
                        attr_ref,
                        val,
                        &sink,
                        conn_id,
                        // The identifier is no longer the last in the buffer, so
                        // the write finds an entry after it.
                        EntryId::from_ms(last_seen_id),
                        remain,
                        base_now_ms + 100,
                    );
                    for (cid, pdu) in &pdus {
                        assert_eq!(*cid, conn_id);
                        let eid = extract_entry_id_be(pdu).expect("EntryID");
                        assert!(
                            eid > last_seen_id,
                            "the remaining entries must keep increasing"
                        );
                        last_seen_id = eid;
                        per_client_ids[ci].push(eid);
                    }
                    grand_total += pdus.len();

                    waiting_for_next_path_verified = true;
                } else {
                    // An ordinary round.
                    let pdus = run_round_default(
                        &eng,
                        brcb_path,
                        attr_ref,
                        val,
                        &sink,
                        conn_id,
                        next_start_id,
                        EVENTS_PER_ROUND,
                        base_now_ms,
                    );
                    for (cid, pdu) in &pdus {
                        assert_eq!(*cid, conn_id, "every PDU must go to its own connection");
                        let eid = extract_entry_id_be(pdu).expect("the PDU must carry an EntryID");
                        assert!(
                            eid > last_seen_id,
                            "client {ci} round {round}: EntryIDs must increase strictly \
                             (got {eid:#x}, prev {last_seen_id:#x})"
                        );
                        last_seen_id = eid;
                        per_client_ids[ci].push(eid);
                    }
                    grand_total += pdus.len();
                }

                // The round ends with the anchor past its last entry.
                {
                    let s = brcb_arc.state.lock().expect("state");
                    assert_eq!(
                        s.transmit_anchor,
                        TransmitAnchor::AfterEntryId(EntryId::from_ms(last_seen_id)),
                        "client {ci} round {round}: after the flush the anchor must be \
                         AfterEntryId(last)"
                    );
                    assert_eq!(
                        s.last_sent_entry_id.as_u64(),
                        last_seen_id,
                        "the last sent identifier must be the last entry of the round"
                    );
                }

                // The client disconnects; the buffer and the anchor stay.
                {
                    let mut s = brcb_arc.state.lock().expect("state");
                    s.client_conn_id = None;
                }

                // It reconnects on the same connection id, so the control block
                // cannot rely on the id changing to notice the reconnect.
                {
                    let mut s = brcb_arc.state.lock().expect("state");
                    s.client_conn_id = Some(conn_id);
                }

                // The next round starts from the last identifier the client
                // reported, which the engine either sends on from or waits on.
                next_start_id = EntryId::from_ms(last_seen_id);
            }

            // The client received every event.
            assert_eq!(
                per_client_ids[ci].len(),
                TOTAL_EVENTS_PER_CLIENT,
                "client {ci} must receive all {TOTAL_EVENTS_PER_CLIENT} entries"
            );

            // Strictly increasing across the whole stream, released entry
            // included.
            for w in per_client_ids[ci].windows(2) {
                assert!(
                    w[1] > w[0],
                    "client {ci} EntryIDs must increase strictly across the stream: \
                     {:#x} followed by {:#x}",
                    w[0],
                    w[1]
                );
            }
        }

        // Totals.
        assert_eq!(
            grand_total,
            5 * TOTAL_EVENTS_PER_CLIENT,
            "the sink must receive every report from every client"
        );
        assert!(
            waiting_for_next_path_verified,
            "the waiting-for-next path must have been exercised in some round"
        );
    })
    .await
    .expect("the test did not finish within 30s");
}
