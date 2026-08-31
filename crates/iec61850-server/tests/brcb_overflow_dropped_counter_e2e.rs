//! End-to-end test for the buffer-full drop counter of a buffered report
//! control block.
//!
//! The whole path is exercised, from a value update through the engine into the
//! backend: with a zero buffer time every trigger enqueues at once, and once
//! the buffer is full the drop-oldest strategy evicts one entry per trigger and
//! counts it. The test also checks the wire result: the first PDU of a flush
//! from the head carries BufOvfl set, and the following ones carry it clear.
//!
//! The collecting sink is defined here because the one inside the crate is
//! compiled only for its own unit tests.

use bytes::Bytes;
use iec61850_model::MmsValue;
use iec61850_server::connection::ConnectionId;
use iec61850_server::reporting::{
    Brcb, BufferedReportControl, Dataset, DatasetEntry, InMemoryReportBuffer, InclusionFlag,
    OptFlds, OverflowStrategy, ReportBufferBackend, ReportSink, ReportingEngine, TransmitAnchor,
    TriggerOptions,
};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

/// A sink that keeps the PDU bytes it is handed.
#[derive(Default)]
struct CollectingSink {
    pdus: Mutex<Vec<(ConnectionId, Bytes)>>,
}

impl ReportSink for CollectingSink {
    fn send_pdu(&self, conn_id: ConnectionId, pdu: Bytes) -> bool {
        self.pdus
            .lock()
            .expect("CollectingSink mutex poisoned")
            .push((conn_id, pdu));
        true
    }
}

/// Locates the BufOvfl boolean inside a buffered report PDU.
///
/// Returns the index at which `0x83 0x01 <flag>` starts, where the flag byte is
/// 0xff for true and 0x00 for false.
///
/// Scanning for that three-byte sequence alone would be ambiguous, because a
/// boolean data set member encodes with the same implicit tag. The field order
/// of a report segment is fixed - RptID, OptFlds, SqNum, BufOvfl, EntryID, the
/// inclusion field, then the values - so the search starts after the five bytes
/// of OptFlds and skips SqNum, and the first boolean after that is BufOvfl.
fn locate_buf_ovfl(pdu: &[u8]) -> Option<usize> {
    // OptFlds is a bit string of ten bits, so it always encodes as the tag, a
    // length of three, six unused bits and two content bytes.
    let opt_flds_start = pdu
        .windows(5)
        .position(|w| w[0] == 0x84 && w[1] == 0x03 && w[2] == 0x06)?;
    let after_opt_flds = opt_flds_start + 5;

    // SqNum is an unsigned 16-bit integer, so tag, length and one or two
    // content bytes separate it from the BufOvfl tag.
    if after_opt_flds + 2 > pdu.len() {
        return None;
    }
    if pdu[after_opt_flds] != 0x86 {
        return None;
    }
    let sqnum_len = pdu[after_opt_flds + 1] as usize;
    let after_sqnum = after_opt_flds + 2 + sqnum_len;
    if after_sqnum + 3 > pdu.len() {
        return None;
    }
    // What follows is BufOvfl.
    if pdu[after_sqnum] == 0x83 && pdu[after_sqnum + 1] == 0x01 {
        Some(after_sqnum)
    } else {
        None
    }
}

#[tokio::test(flavor = "current_thread")]
async fn brcb_overflow_dropped_counter_e2e() {
    // The whole test runs under a five-second timeout.
    tokio::time::timeout(Duration::from_secs(5), async {
        // A data set with a single boolean member.
        let attr_ref = "IED1LD0/GGIO1$ST$Ind1$stVal".to_string();
        let val = Arc::new(RwLock::new(MmsValue::Boolean(false)));
        let mut ds = Dataset::new("GGIO1$ds1");
        ds.push(DatasetEntry::new(&attr_ref, val.clone()));

        // The control block triggers on data change with a zero buffer time, so
        // every trigger enqueues immediately. OptFlds must carry buffer-overflow
        // and entryID for the flag to appear on the wire.
        let brcb = Brcb::new("brcb01", "GGIO1$ds1")
            .with_trg_ops(TriggerOptions::DATA_CHANGED)
            .with_opt_flds(OptFlds::SEQ_NUM | OptFlds::BUFFER_OVERFLOW | OptFlds::ENTRY_ID);

        // A backend holding four entries that drops the oldest on overflow.
        // Registering the control block with its data set also hands the
        // backend the engine-level drop counter.
        let backend: Box<dyn ReportBufferBackend> = Box::new(InMemoryReportBuffer::with_strategy(
            4,
            OverflowStrategy::DropOldest,
        ));
        let mms_path = "IED1LD0/GGIO1$BR$brcb01";
        let brc = BufferedReportControl::with_backend(mms_path, brcb, backend);

        // The engine sends into the collecting sink.
        let sink = Arc::new(CollectingSink::default());
        let mut eng = ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>);
        eng.register_brcb_with_dataset(brc, ds)
            .expect("register_brcb_with_dataset");

        let brcb_arc = eng.get_brcb(mms_path).expect("get_brcb");

        // A buffered control block with a valid data set buffers triggers even
        // while RptEna is false, so buffering is already on here.
        {
            let mut state = brcb_arc.state.lock().expect("BrcbState lock");
            state.client_conn_id = Some(7);
            assert!(
                state.is_buffering,
                "a control block with a data set must be buffering"
            );
        }

        // Ten triggers into a buffer of four: the first four fill it and the
        // remaining six each evict the oldest entry and count a drop. The value
        // is flipped every time so each trigger is a real data change.
        for i in 0..10u64 {
            // Flip the member value.
            *val.write().expect("val write") = MmsValue::Boolean(i % 2 == 1);
            eng.on_brcb_value_updated(
                &attr_ref,
                MmsValue::Boolean(i % 2 == 1),
                InclusionFlag::VALUE_CHANGED,
                1_000_000 + i,
            );
        }

        // The drop counter and the buffer state.
        let metrics = eng.engine_metrics();
        assert_eq!(
            metrics.dropped_buffer_full(),
            6,
            "ten triggers into a buffer of four must evict six entries"
        );

        let buf_len = brcb_arc.lock_buffer().expect("lock_buffer").len();
        assert_eq!(buf_len, 4, "the buffer must be full");

        let is_overflow_before_flush = brcb_arc.lock_buffer().expect("lock_buffer").is_overflow();
        assert!(
            is_overflow_before_flush,
            "the backend must report an overflow after evicting"
        );

        // Flush from the head of the buffer.
        {
            let mut state = brcb_arc.state.lock().expect("BrcbState lock");
            state.transmit_anchor = TransmitAnchor::FromHead;
        }

        let sent = eng.flush_brcb_pending(&brcb_arc, 7, 1_000_100);
        assert_eq!(sent, 4, "a flush from the head must send all four entries");

        // The sink received one PDU per entry.
        let pdus = sink.pdus.lock().expect("sink pdus lock");
        assert_eq!(pdus.len(), 4, "the sink must receive four PDUs");
        for (cid, pdu) in pdus.iter() {
            assert_eq!(*cid, 7);
            assert_eq!(pdu[0], 0xa3, "a report PDU must carry the 0xa3 tag");
        }

        // A flush from the head sets BufOvfl on the first entry only; sending it
        // clears the overflow, so the entries after it carry the flag clear.
        let first_pdu: &[u8] = &pdus[0].1;
        let first_buf_ovfl =
            locate_buf_ovfl(first_pdu).expect("the first PDU must carry a BufOvfl field");
        assert_eq!(
            first_pdu[first_buf_ovfl + 2],
            0xff,
            "the first PDU must carry BufOvfl set at offset {}. \
             PDU bytes: {:02x?}",
            first_buf_ovfl + 2,
            first_pdu
        );

        // The following PDUs carry BufOvfl clear.
        let second_pdu: &[u8] = &pdus[1].1;
        let second_buf_ovfl =
            locate_buf_ovfl(second_pdu).expect("the second PDU must carry a BufOvfl field");
        assert_eq!(
            second_pdu[second_buf_ovfl + 2],
            0x00,
            "the second PDU must carry BufOvfl clear at offset {}. \
             PDU bytes: {:02x?}",
            second_buf_ovfl + 2,
            second_pdu
        );

        // The remaining PDUs must not set the flag again.
        for (i, (_, pdu)) in pdus.iter().enumerate().skip(1) {
            let off = locate_buf_ovfl(pdu)
                .unwrap_or_else(|| panic!("PDU {i} must carry a BufOvfl field"));
            assert_eq!(
                pdu[off + 2],
                0x00,
                "PDU {i} must still carry BufOvfl clear, bytes: {:02x?}",
                pdu
            );
        }

        // The counter accumulates rather than resetting per flush: the buffer is
        // full again, so one more trigger evicts one more entry.
        *val.write().expect("val write") = MmsValue::Boolean(true);
        eng.on_brcb_value_updated(
            &attr_ref,
            MmsValue::Boolean(true),
            InclusionFlag::VALUE_CHANGED,
            2_000_000,
        );
        assert_eq!(
            metrics.dropped_buffer_full(),
            7,
            "a further eviction must add to the running count"
        );
    })
    .await
    .expect("the test did not finish within 5s");
}
