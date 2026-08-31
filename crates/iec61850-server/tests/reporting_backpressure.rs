//! Integration tests for reporting backpressure and the per-control-block
//! metrics.
//!
//! A bounded channel sink whose receiver never reads stands in for a slow
//! client: once the channel is full further reports raise the socket-full drop
//! counter, and after enough consecutive would-block results the engine treats
//! the connection as gone and clears RptEna. The metrics tests drive each
//! counter path by hand and read the values back from the snapshot.

use bytes::Bytes;
use iec61850_model::MmsValue;
use iec61850_server::reporting::engine::BACKPRESSURE_CLOSE_THRESHOLD;
use iec61850_server::{
    ChannelReportSink, Dataset, DatasetEntry, InclusionFlag, NullReportSink, Rcb,
    RcbMetricsSnapshot, ReportControl, ReportingEngine, SendOutcome, TriggerOptions,
    REPORT_CHANNEL_CAP,
};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

// helpers

fn make_entry(attr_ref: &str, val: MmsValue) -> DatasetEntry {
    DatasetEntry::new(attr_ref, Arc::new(RwLock::new(val)))
}

fn make_ds_one(attr_ref: &str) -> Dataset {
    let mut ds = Dataset::new("ds1");
    ds.push(make_entry(attr_ref, MmsValue::Boolean(false)));
    ds
}

fn make_rc(rcb_name: &str, trg_ops: TriggerOptions) -> ReportControl {
    let rcb = Rcb::new(rcb_name, "GGIO1$ds1").with_trg_ops(trg_ops);
    let mms_path = format!("IED1LD0/GGIO1$RP${}", rcb_name);
    ReportControl::new(&mms_path, rcb)
}

fn enable_rcb(rc_arc: &Arc<Mutex<ReportControl>>, conn_id: u64) {
    let rc = rc_arc.lock().unwrap();
    let mut state = rc.state.lock().unwrap();
    state.rpt_ena = true;
    state.resv = true;
    state.client_conn_id = Some(conn_id);
}

// A receiver that keeps up loses nothing.

#[tokio::test]
async fn backpressure_normal_receiver_no_drops() {
    let ch_sink = Arc::new(ChannelReportSink::new());
    let mut engine = ReportingEngine::new_with_channel_sink(ch_sink.clone());

    let attr = "IED1LD0/GGIO1$ST$Ind1$stVal";
    let rc = make_rc("urcb01", TriggerOptions::DATA_CHANGED);
    let ds = make_ds_one(attr);
    let path = rc.mms_path.clone();
    engine.register_rcb(rc, ds).unwrap();

    let rc_arc = engine.get_rcb(&path).unwrap();
    enable_rcb(&rc_arc, 42);

    // A receiver that drains the channel.
    let (tx, mut rx) = ChannelReportSink::create_channel();
    ch_sink.register(42, tx);

    // Drain the channel from a task.
    let consume_task = tokio::spawn(async move {
        let mut count = 0u32;
        while let Some(_pdu) = rx.recv().await {
            count += 1;
            if count >= 100 {
                break;
            }
        }
        count
    });

    // Raise a hundred events.
    for i in 0u8..100 {
        let val = MmsValue::Boolean(i % 2 == 0);
        engine.on_value_updated(
            &attr.to_string(),
            val,
            InclusionFlag::VALUE_CHANGED,
            1000 + i as u64,
        );
        // Expire the report deadline and tick.
        {
            let rc_l = rc_arc.lock().unwrap();
            let mut s = rc_l.state.lock().unwrap();
            if let Some(ref mut due) = s.report_due {
                *due = Instant::now() - Duration::from_millis(10);
            }
        }
        engine.tick();
        // Give the consumer a chance to drain.
        tokio::task::yield_now().await;
    }

    // Wait for the consumer to finish.
    let received = tokio::time::timeout(std::time::Duration::from_secs(2), consume_task)
        .await
        .expect("the consumer did not finish within 2s")
        .expect("consumer task join");

    // Nothing was dropped.
    let rc_l = rc_arc.lock().unwrap();
    let snap = rc_l.metrics_snapshot();
    assert_eq!(
        snap.dropped_socket_full, 0,
        "a receiver that keeps up must drop nothing, got {}",
        snap.dropped_socket_full
    );
    assert!(
        received > 0,
        "the receiver must get some PDUs, got {}",
        received
    );
}

// A slow receiver raises the drop counter and eventually loses the connection.

// The body is synchronous, so it runs on its own thread with a receive timeout:
// a reentrant-lock regression inside the engine would otherwise hang the whole
// test binary instead of failing this one test.
#[test]
fn backpressure_slow_receiver_dropped_counter_and_conn_dropped() {
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let handle = std::thread::spawn(move || {
        let ch_sink = Arc::new(ChannelReportSink::new());
        let mut engine = ReportingEngine::new_with_channel_sink(ch_sink.clone());

        let attr = "IED1LD0/GGIO1$ST$Ind1$stVal";
        let rc = make_rc("urcb01", TriggerOptions::DATA_CHANGED);
        let ds = make_ds_one(attr);
        let path = rc.mms_path.clone();
        engine.register_rcb(rc, ds).unwrap();

        let rc_arc = engine.get_rcb(&path).unwrap();
        enable_rcb(&rc_arc, 7);

        // The receiver never reads, standing in for a slow client.
        let (tx, _rx) = ChannelReportSink::create_channel();
        ch_sink.register(7, tx);

        // Fill the channel.
        let dummy = Bytes::from_static(b"\xa3\x00");
        for _ in 0..REPORT_CHANNEL_CAP {
            let outcome = ch_sink.try_send_pdu(7, dummy.clone());
            assert_eq!(
                outcome,
                SendOutcome::Sent,
                "sends must succeed until the channel is full"
            );
        }

        // The channel is full now.
        assert_eq!(
            ch_sink.try_send_pdu(7, dummy.clone()),
            SendOutcome::WouldBlock,
            "a send into a full channel must report would-block"
        );

        // Each tick flushes once and hits would-block once, so enough ticks
        // cross the threshold at which the connection is dropped.
        use iec61850_server::reporting::rcb::PendingReport;

        for i in 0..(BACKPRESSURE_CLOSE_THRESHOLD + 5) {
            // Put a pending report in place and expire its deadline.
            {
                let rc_l = rc_arc.lock().unwrap();
                let mut s = rc_l.state.lock().unwrap();
                // Stop once the connection has been dropped.
                if !s.rpt_ena {
                    break;
                }
                let ds_len = s.dataset.as_ref().map(|d| d.len()).unwrap_or(1);
                let mut pending = PendingReport::new_empty(ds_len, 1_000_000 + i as u64);
                pending.inclusion_flags[0] = InclusionFlag::VALUE_CHANGED;
                pending.snapshot[0] = Some(MmsValue::Boolean(true));
                s.pending = Some(pending);
                s.triggered = true;
                s.report_due = Some(Instant::now() - Duration::from_millis(10));
            }
            engine.tick();
        }

        // Reports were dropped.
        let rc_l = rc_arc.lock().unwrap();
        let snap = rc_l.metrics_snapshot();
        assert!(
            snap.dropped_socket_full > 0,
            "a slow receiver must drop reports, got {}",
            snap.dropped_socket_full
        );

        // The connection was dropped, which clears RptEna.
        let state = rc_l.state.lock().unwrap();
        assert!(
            !state.rpt_ena,
            "repeated would-block must drop the connection and clear RptEna"
        );

        let _ = done_tx.send(());
    });

    match done_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(()) => {
            handle.join().expect("worker thread panic");
        }
        Err(_) => {
            panic!(
                "the slow-receiver test did not finish within 5s, which points at a \
                 reentrant lock in the flush path taking the control block lock twice"
            );
        }
    }
}

// A fresh control block starts with every counter at zero.

#[test]
fn metrics_snapshot_default_all_zero() {
    let rc = make_rc("urcb01", TriggerOptions::DATA_CHANGED);
    let snap = rc.metrics_snapshot();
    assert_eq!(
        snap,
        RcbMetricsSnapshot::default(),
        "a fresh control block must report all counters at zero"
    );
}

// An event that no trigger option covers is counted as skipped.

#[test]
fn metrics_skipped_trgops_incremented_on_mismatch() {
    let mut engine = ReportingEngine::new(Arc::new(NullReportSink));
    // The control block triggers on quality change only, so a value change is
    // skipped.
    let attr = "IED1LD0/GGIO1$ST$Ind1$stVal";
    let rc = make_rc("urcb01", TriggerOptions::QUALITY_CHANGED);
    let ds = make_ds_one(attr);
    let path = rc.mms_path.clone();
    engine.register_rcb(rc, ds).unwrap();

    let rc_arc = engine.get_rcb(&path).unwrap();
    enable_rcb(&rc_arc, 1);

    engine.on_value_updated(
        &attr.to_string(),
        MmsValue::Boolean(true),
        InclusionFlag::VALUE_CHANGED,
        1000,
    );

    let rc_l = rc_arc.lock().unwrap();
    let snap = rc_l.metrics_snapshot();
    assert_eq!(
        snap.skipped_trgops, 1,
        "an event outside the trigger options must count as skipped"
    );
}

// A second trigger on the same entry within the buffer time is coalesced.

#[test]
fn metrics_coalesced_buftm_incremented_on_buftm_bypass() {
    let mut engine = ReportingEngine::new(Arc::new(NullReportSink));
    let attr = "IED1LD0/GGIO1$ST$Ind1$stVal";
    let rc = make_rc("urcb01", TriggerOptions::DATA_CHANGED);
    let ds = make_ds_one(attr);
    let path = rc.mms_path.clone();
    engine.register_rcb(rc, ds).unwrap();

    let rc_arc = engine.get_rcb(&path).unwrap();
    // A 100 ms buffer time holds the first trigger back.
    {
        let rc_l = rc_arc.lock().unwrap();
        let mut s = rc_l.state.lock().unwrap();
        s.rpt_ena = true;
        s.resv = true;
        s.client_conn_id = Some(2);
        s.buf_tm_ms = 100;
    }

    // The first trigger creates the pending report.
    engine.on_value_updated(
        &attr.to_string(),
        MmsValue::Boolean(true),
        InclusionFlag::VALUE_CHANGED,
        1000,
    );
    // The second trigger on the same entry is coalesced into it.
    engine.on_value_updated(
        &attr.to_string(),
        MmsValue::Boolean(false),
        InclusionFlag::VALUE_CHANGED,
        1010,
    );

    let rc_l = rc_arc.lock().unwrap();
    let snap = rc_l.metrics_snapshot();
    assert_eq!(
        snap.coalesced_buftm, 1,
        "a coalesced trigger must be counted once"
    );
}

// Unbuffered reporting never drops on a full buffer.

#[test]
fn metrics_dropped_buffer_full_always_zero_in_urcb() {
    // An unbuffered control block flushes rather than drops when a second
    // trigger arrives, so this counter stays at zero; it exists for buffered
    // reporting.
    let rc = make_rc("urcb01", TriggerOptions::DATA_CHANGED);
    let snap = rc.metrics_snapshot();
    assert_eq!(
        snap.dropped_buffer_full, 0,
        "unbuffered reporting must never count a buffer-full drop"
    );
}

// A successful flush counts as sent.

#[test]
fn metrics_sent_counter_incremented_on_successful_flush() {
    let ch_sink = Arc::new(ChannelReportSink::new());
    let mut engine = ReportingEngine::new_with_channel_sink(ch_sink.clone());

    let attr = "IED1LD0/GGIO1$ST$Ind1$stVal";
    let rc = make_rc("urcb01", TriggerOptions::DATA_CHANGED);
    let ds = make_ds_one(attr);
    let path = rc.mms_path.clone();
    engine.register_rcb(rc, ds).unwrap();

    let rc_arc = engine.get_rcb(&path).unwrap();
    enable_rcb(&rc_arc, 5);

    // The channel has room, so sends succeed even with an idle receiver.
    let (tx, _rx) = ChannelReportSink::create_channel();
    ch_sink.register(5, tx);

    // Put a pending report in place and expire its deadline.
    {
        use iec61850_server::reporting::rcb::PendingReport;
        let rc_l = rc_arc.lock().unwrap();
        let mut s = rc_l.state.lock().unwrap();
        let ds_len = s.dataset.as_ref().map(|d| d.len()).unwrap_or(1);
        let mut pending = PendingReport::new_empty(ds_len, 1_000_000);
        pending.inclusion_flags[0] = InclusionFlag::VALUE_CHANGED;
        pending.snapshot[0] = Some(MmsValue::Boolean(true));
        s.pending = Some(pending);
        s.triggered = true;
        s.report_due = Some(Instant::now() - Duration::from_millis(10));
    }

    engine.tick();

    let rc_l = rc_arc.lock().unwrap();
    let snap = rc_l.metrics_snapshot();
    assert!(
        snap.sent >= 1,
        "a successful flush must count at least one send, got {}",
        snap.sent
    );
    assert_eq!(
        snap.dropped_socket_full, 0,
        "a successful flush must drop nothing"
    );
}

// The socket-full counter follows the would-block path.

#[test]
fn metrics_dropped_socket_full_incremented_per_would_block() {
    let ch_sink = Arc::new(ChannelReportSink::new());
    let mut engine = ReportingEngine::new_with_channel_sink(ch_sink.clone());

    let attr = "IED1LD0/GGIO1$ST$Ind1$stVal";
    let rc = make_rc("urcb01", TriggerOptions::DATA_CHANGED);
    let ds = make_ds_one(attr);
    let path = rc.mms_path.clone();
    engine.register_rcb(rc, ds).unwrap();

    let rc_arc = engine.get_rcb(&path).unwrap();
    enable_rcb(&rc_arc, 99);

    // An idle receiver.
    let (tx, _rx) = ChannelReportSink::create_channel();
    ch_sink.register(99, tx);

    // Fill the channel.
    let dummy = Bytes::from_static(b"\xa3\x00");
    for _ in 0..REPORT_CHANNEL_CAP {
        ch_sink.try_send_pdu(99, dummy.clone());
    }

    // One flush hits would-block and counts one drop.
    {
        use iec61850_server::reporting::rcb::PendingReport;
        let rc_l = rc_arc.lock().unwrap();
        let mut s = rc_l.state.lock().unwrap();
        let ds_len = s.dataset.as_ref().map(|d| d.len()).unwrap_or(1);
        let mut pending = PendingReport::new_empty(ds_len, 1_000_000);
        pending.inclusion_flags[0] = InclusionFlag::VALUE_CHANGED;
        pending.snapshot[0] = Some(MmsValue::Boolean(true));
        s.pending = Some(pending);
        s.triggered = true;
        s.report_due = Some(Instant::now() - Duration::from_millis(10));
    }
    engine.tick();

    let rc_l = rc_arc.lock().unwrap();
    let snap = rc_l.metrics_snapshot();
    assert!(
        snap.dropped_socket_full >= 1,
        "a would-block must count at least one drop, got {}",
        snap.dropped_socket_full
    );
}
