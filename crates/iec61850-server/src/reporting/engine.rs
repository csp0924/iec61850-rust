//! `ReportingEngine`: the central registry for report control blocks.
//!
//! Owns every URCB and BRCB the server exposes and drives them per
//! IEC 61850-7-2: value-update triggers, buffer-time coalescing, integrity
//! periods, general interrogation, and report PDU delivery. An inverted index
//! from data attribute reference to the control blocks watching it keeps the
//! update path proportional to the number of interested control blocks rather
//! than to the total number of control blocks and data set entries. `tick()`
//! must be called periodically by the caller; a 1 ms interval keeps
//! `BufTm = 0` reports effectively immediate.

use super::brcb::{BufferedReportControl, TransmitAnchor};
use super::buffer::EnqueuedSnapshot;
use super::dataset::{DataAttributeRef, Dataset};
use super::pdu::{
    brcb_encode_snapshot, encode_brcb_report_pdus, encode_report_pdus, pending_from_brcb_entry,
    BrcbReportEncodeParams, ReportEncodeParams,
};
use super::rcb::{PendingReport, ReportControl};
use super::sink::{ChannelReportSink, SendOutcome};
use crate::connection::ConnectionId;
use crate::error::{Result, ServerError};
use crate::flags::{InclusionFlag, TriggerOptions};
use bytes::Bytes;
use iec61850_model::MmsValue;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────
// Backpressure constants
// ─────────────────────────────────────────────────────────────────────────────

/// Number of consecutive `WouldBlock` results after which a connection counts as
/// stalled and `on_connection_dropped` is called.
///
/// The value is 10: raise it when bursty traffic causes false positives, lower it
/// to close unresponsive connections sooner.
pub const BACKPRESSURE_CLOSE_THRESHOLD: u32 = 10;

// ─────────────────────────────────────────────────────────────────────────────
// ReportSink: the caller implements this trait to deliver PDU bytes to a client
// ─────────────────────────────────────────────────────────────────────────────

/// Sink for outgoing report PDUs.
///
/// After `ReportingEngine::tick` encodes a report, it hands the bytes to this
/// trait; the connection lifecycle layer implements it by writing them to the
/// client transport.
pub trait ReportSink: Send + Sync {
    /// Sends one PDU to the given connection.
    ///
    /// Returns `false` when the connection is already gone; the engine then calls
    /// `on_connection_dropped`.
    fn send_pdu(&self, conn_id: ConnectionId, pdu: Bytes) -> bool;
}

/// Test sink that discards every PDU and always reports success.
#[derive(Debug, Default)]
pub struct NullReportSink;

impl ReportSink for NullReportSink {
    fn send_pdu(&self, _conn_id: ConnectionId, _pdu: Bytes) -> bool {
        true
    }
}

/// Test sink that collects the PDU bytes it is handed.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct CollectReportSink {
    pub pdus: std::sync::Mutex<Vec<(ConnectionId, Bytes)>>,
}

#[cfg(test)]
impl ReportSink for CollectReportSink {
    fn send_pdu(&self, conn_id: ConnectionId, pdu: Bytes) -> bool {
        self.pdus.lock().unwrap().push((conn_id, pdu));
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReportingEngine
// ─────────────────────────────────────────────────────────────────────────────

/// Central registry for report control blocks.
///
/// - `rcbs`: runtime handle for every URCB, keyed by MMS path
/// - `watch_map`: inverted index from data attribute reference to the URCBs that
///   watch it
/// - `sink`: report PDU delivery, injected by the connection lifecycle layer
/// - `channel_sink`: optional backpressure-aware sink
///
/// The consecutive-`WouldBlock` count lives per control block in
/// `rc.metrics.consecutive_socket_full`, so `flush_pending` needs only `&self`.
///
/// `Arc<dyn ReportSink>` is not `Debug`, so `Debug` is implemented by hand.
pub struct ReportingEngine {
    rcbs: HashMap<String, Arc<Mutex<ReportControl>>>,
    /// BRCBs share this engine with the URCBs but live in their own table, keyed by
    /// `<domain>/<LN>$BR$<rcb>` (URCBs use `$RP$`). Their trigger path and their
    /// BufTm, IntgPd, and GI timing are driven from the same `tick()`.
    brcbs: HashMap<String, Arc<BufferedReportControl>>,
    /// Inverted index: attribute reference to every URCB watching it. The handles
    /// are weak so a control block is not kept alive by the index.
    watch_map: HashMap<DataAttributeRef, Vec<Weak<Mutex<ReportControl>>>>,
    /// BRCB inverted index, symmetric with `watch_map`: built by
    /// `register_brcb_with_dataset` and read by `on_brcb_value_updated`.
    brcb_watch_map: HashMap<DataAttributeRef, Vec<Weak<BufferedReportControl>>>,
    /// Data set bound to each BRCB, keyed by MMS path. A `BufferedReportControl`
    /// stores only the `dat_set` name, so the engine holds the `Dataset` itself.
    brcb_datasets: HashMap<String, Dataset>,
    /// Per-BRCB buffer-time accumulation state, keyed by MMS path. BufTm timing
    /// follows the same rules as for a URCB.
    brcb_buftm_pending: Mutex<HashMap<String, BrcbBufTmPending>>,
    /// Instant of the next integrity scan per BRCB, keyed by MMS path.
    brcb_next_intg: Mutex<HashMap<String, Instant>>,
    sink: Arc<dyn ReportSink>,
    /// Backpressure-aware sink. When present, `flush_pending` uses `try_send_pdu`.
    channel_sink: Option<Arc<ChannelReportSink>>,
    /// Engine-level metrics. `dropped_buffer_full` is incremented by the buffer
    /// backends themselves when an entry has to be discarded.
    metrics: Arc<ReportingEngineMetrics>,
}

/// Buffer-time accumulation state for one BRCB.
///
/// Follows the URCB `RcbState.report_due` timing model: the first trigger sets
/// `due_at = now + buf_tm_ms`, and later triggers inside the same window only
/// update the inclusion bitmap and the value snapshot. When the buffer time
/// expires, the accumulated inclusion flags and snapshot are frozen into one
/// buffer entry, which is then flushed.
#[derive(Debug)]
struct BrcbBufTmPending {
    /// Millisecond timestamp of the first trigger, used as the entry time.
    first_trigger_ms: u64,
    /// Instant at which the buffer time expires, compared against in `tick`.
    due_at: Instant,
    /// Accumulated inclusion flags and values, one slot per data set entry.
    snapshot: super::buffer::EnqueuedSnapshot,
}

/// Engine-level reporting metrics; per-control-block counters live in `RcbMetrics`.
///
/// `dropped_buffer_full` counts report buffer overflow and must not be confused
/// with `RcbMetrics::dropped_socket_full`, which counts socket backpressure.
///
/// `register_brcb` injects this counter into every BRCB buffer backend through
/// `ReportBufferBackend::set_dropped_counter`. The in-memory `DropOldest` strategy
/// increments it on each eviction, `DropNewest` and `Reject` on each rejected
/// entry; the SQLite backend behaves the same way.
#[derive(Debug)]
pub struct ReportingEngineMetrics {
    /// Entries dropped because a BRCB buffer was full.
    ///
    /// Shared as an `Arc` so every BRCB backend increments the same counter
    /// directly instead of reporting back to the engine.
    pub dropped_buffer_full: Arc<AtomicU64>,
}

impl Default for ReportingEngineMetrics {
    fn default() -> Self {
        Self {
            dropped_buffer_full: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl ReportingEngineMetrics {
    /// Creates a metrics block with every counter at zero.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Returns the current `dropped_buffer_full` value.
    pub fn dropped_buffer_full(&self) -> u64 {
        self.dropped_buffer_full.load(Ordering::Relaxed)
    }
}

impl std::fmt::Debug for ReportingEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReportingEngine")
            .field("rcb_count", &self.rcbs.len())
            .field("watch_keys", &self.watch_map.len())
            .finish()
    }
}

impl ReportingEngine {
    /// Creates an empty engine; `sink` is injected by the connection lifecycle layer.
    ///
    /// Use `new_with_channel_sink` instead when the sink is an
    /// `Arc<ChannelReportSink>`, to enable backpressure handling.
    pub fn new(sink: Arc<dyn ReportSink>) -> Self {
        Self {
            rcbs: HashMap::new(),
            brcbs: HashMap::new(),
            watch_map: HashMap::new(),
            brcb_watch_map: HashMap::new(),
            brcb_datasets: HashMap::new(),
            brcb_buftm_pending: Mutex::new(HashMap::new()),
            brcb_next_intg: Mutex::new(HashMap::new()),
            sink,
            channel_sink: None,
            metrics: ReportingEngineMetrics::new(),
        }
    }

    /// Creates an engine backed by a backpressure-aware `ChannelReportSink`.
    ///
    /// `flush_pending` then sends through `try_send_pdu`, evaluates the
    /// `SendOutcome`, and asks for the connection to be closed after
    /// `BACKPRESSURE_CLOSE_THRESHOLD` consecutive failures. The consecutive count
    /// is kept per control block in `rc.metrics.consecutive_socket_full`.
    pub fn new_with_channel_sink(sink: Arc<ChannelReportSink>) -> Self {
        let trait_sink = sink.clone() as Arc<dyn ReportSink>;
        Self {
            rcbs: HashMap::new(),
            brcbs: HashMap::new(),
            watch_map: HashMap::new(),
            brcb_watch_map: HashMap::new(),
            brcb_datasets: HashMap::new(),
            brcb_buftm_pending: Mutex::new(HashMap::new()),
            brcb_next_intg: Mutex::new(HashMap::new()),
            sink: trait_sink,
            channel_sink: Some(sink),
            metrics: ReportingEngineMetrics::new(),
        }
    }

    /// Creates an engine with a `NullReportSink`, for tests.
    #[cfg(test)]
    pub fn new_null() -> Self {
        Self::new(Arc::new(NullReportSink))
    }

    // ─── RCB management ───────────────────────────────────────────────────────

    /// Registers a URCB, binds its data set, and adds it to the inverted index.
    ///
    /// `rc.mms_path` has the form `"<domain>/<LN>$RP$<rcb_name>"`; `dataset` must
    /// already be resolved to live attribute handles.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::InvalidModel` when a control block mutex is poisoned.
    pub fn register_rcb(&mut self, rc: ReportControl, dataset: Dataset) -> Result<()> {
        let mms_path = rc.mms_path.clone();
        let rc = Arc::new(Mutex::new(rc));

        // Lock order: the ReportControl mutex is taken before the RcbState mutex.
        {
            let rc_guard = rc
                .lock()
                .map_err(|_| ServerError::InvalidModel("ReportControl Mutex poisoned".into()))?;
            let mut state = rc_guard
                .state
                .lock()
                .map_err(|_| ServerError::InvalidModel("RcbState Mutex poisoned".into()))?;
            state.dataset = Some(dataset.clone());
        }

        // Inverted index: one weak handle per data set entry attribute.
        for entry in &dataset.entries {
            let weak = Arc::downgrade(&rc);
            self.watch_map
                .entry(entry.attr_ref.clone())
                .or_default()
                .push(weak);
        }

        self.rcbs.insert(mms_path, rc);
        Ok(())
    }

    /// Returns the URCB registered under `mms_path`, for the service layer.
    pub fn get_rcb(&self, mms_path: &str) -> Option<Arc<Mutex<ReportControl>>> {
        self.rcbs.get(mms_path).cloned()
    }

    /// Lists the MMS path of every registered URCB.
    pub fn rcb_paths(&self) -> Vec<String> {
        self.rcbs.keys().cloned().collect()
    }

    // ─── BRCB registration and lookup ─────────────────────────────────────────

    /// Registers a BRCB under the key `<domain>/<LN>$BR$<rcb>`.
    ///
    /// This only places the control block in the BRCB table, so the dispatcher can
    /// find it when routing a `$BR$` path. Binding a data set and building the
    /// inverted index is the job of `register_brcb_with_dataset`.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::InvalidModel` when the MMS path is already registered.
    pub fn register_brcb(&mut self, brcb: BufferedReportControl) -> Result<()> {
        let mms_path = brcb.mms_path.clone();
        if self.brcbs.contains_key(&mms_path) {
            return Err(ServerError::InvalidModel(format!(
                "BRCB already registered: {mms_path}"
            )));
        }
        // Hand the engine-level dropped_buffer_full counter to the backend so it can
        // increment on a full push without going back through the engine. A poisoned
        // lock only warns: the counter stays at zero, which costs observability but
        // not correctness.
        match brcb.report_buffer.lock() {
            Ok(mut backend) => {
                backend.set_dropped_counter(self.metrics.dropped_buffer_full.clone());
            }
            Err(_) => {
                tracing::warn!(
                    mms_path = %mms_path,
                    "brcb report buffer mutex poisoned, dropped_buffer_full counter not injected"
                );
            }
        }
        self.brcbs.insert(mms_path, Arc::new(brcb));
        Ok(())
    }

    /// Registers a BRCB, binds its data set, and builds the BRCB inverted index.
    ///
    /// Mirrors `register_rcb`: every data set attribute reference is added to
    /// `brcb_watch_map`, so `on_brcb_value_updated` is a table lookup. The data set
    /// is also cloned into `brcb_datasets` for the send path, because a
    /// `BufferedReportControl` stores only the `dat_set` name.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::InvalidModel` when the MMS path is already registered.
    pub fn register_brcb_with_dataset(
        &mut self,
        brcb: BufferedReportControl,
        dataset: Dataset,
    ) -> Result<()> {
        let mms_path = brcb.mms_path.clone();
        if self.brcbs.contains_key(&mms_path) {
            return Err(ServerError::InvalidModel(format!(
                "BRCB already registered: {mms_path}"
            )));
        }
        // Inject the engine-level counter, as in register_brcb.
        match brcb.report_buffer.lock() {
            Ok(mut backend) => {
                backend.set_dropped_counter(self.metrics.dropped_buffer_full.clone());
            }
            Err(_) => {
                tracing::warn!(
                    mms_path = %mms_path,
                    "brcb report buffer mutex poisoned, dropped_buffer_full counter not injected"
                );
            }
        }
        let brcb_arc = Arc::new(brcb);
        // BRCB inverted index: one weak handle per data set entry attribute.
        for entry in &dataset.entries {
            let weak = Arc::downgrade(&brcb_arc);
            self.brcb_watch_map
                .entry(entry.attr_ref.clone())
                .or_default()
                .push(weak);
        }
        self.brcb_datasets.insert(mms_path.clone(), dataset);
        self.brcbs.insert(mms_path, brcb_arc);
        Ok(())
    }

    /// Returns the BRCB registered under `mms_path`, for dispatcher routing.
    pub fn get_brcb(&self, mms_path: &str) -> Option<Arc<BufferedReportControl>> {
        self.brcbs.get(mms_path).cloned()
    }

    /// Returns the data set bound to a BRCB.
    pub fn brcb_dataset(&self, mms_path: &str) -> Option<&Dataset> {
        self.brcb_datasets.get(mms_path)
    }

    /// Lists the MMS path of every registered BRCB.
    pub fn brcb_paths(&self) -> Vec<String> {
        self.brcbs.keys().cloned().collect()
    }

    /// Returns the engine-level metrics block.
    pub fn engine_metrics(&self) -> Arc<ReportingEngineMetrics> {
        self.metrics.clone()
    }

    /// Releases every BRCB reservation whose timeout has elapsed.
    ///
    /// Returns how many reservations fired. Driven from the `tick` path, where once
    /// per second is enough resolution.
    pub fn tick_brcb_reservations(&self) -> usize {
        let now = Instant::now();
        let mut fired = 0;
        for brcb in self.brcbs.values() {
            let Ok(mut state) = brcb.state.lock() else {
                continue;
            };
            if state.tick_reservation(now) {
                fired += 1;
            }
        }
        fired
    }

    // ─── Value-update triggers ────────────────────────────────────────────────

    /// Reports that a data attribute value changed.
    ///
    /// Looks the attribute up in the inverted index and triggers every enabled URCB
    /// watching it, so the cost is proportional to the number of watchers rather
    /// than to the number of registered control blocks.
    ///
    /// `attr_ref` has the form `"<domain>/<LN>$<FC>$<DO>$<DA>"`. `new_value` is
    /// cloned into the pending snapshot. `flag` selects the trigger class (data
    /// change, quality change, or data update). `now_ms` is the current time in
    /// milliseconds and seeds the buffer-time deadline.
    pub fn on_value_updated(
        &self,
        attr_ref: &DataAttributeRef,
        new_value: MmsValue,
        flag: InclusionFlag,
        now_ms: u64,
    ) {
        let Some(weak_list) = self.watch_map.get(attr_ref) else {
            return;
        };

        for weak in weak_list {
            let Some(rc_arc) = weak.upgrade() else {
                continue;
            };
            let Ok(rc_guard) = rc_arc.lock() else {
                tracing::warn!(attr_ref = %attr_ref, "report control mutex poisoned, skipping");
                continue;
            };
            let Ok(mut state) = rc_guard.state.lock() else {
                tracing::warn!(attr_ref = %attr_ref, "rcb state mutex poisoned, skipping");
                continue;
            };

            if !state.rpt_ena {
                continue;
            }

            let trg = if flag.contains(InclusionFlag::VALUE_CHANGED) {
                TriggerOptions::DATA_CHANGED
            } else if flag.contains(InclusionFlag::QUALITY_CHANGED) {
                TriggerOptions::QUALITY_CHANGED
            } else if flag.contains(InclusionFlag::VALUE_UPDATE) {
                TriggerOptions::DATA_UPDATE
            } else {
                continue;
            };

            if !state.trg_ops.contains(trg) {
                rc_guard
                    .metrics
                    .skipped_trgops
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }

            // Resolve the index first so the shared borrow of the data set ends
            // before state is mutated below.
            let idx = {
                let Some(ref ds) = state.dataset else {
                    continue;
                };
                match ds.entries.iter().position(|e| &e.attr_ref == attr_ref) {
                    Some(i) => i,
                    None => continue,
                }
            };

            // Buffer-time bypass: if this entry already carries a trigger flag, the
            // pending report is sent at once instead of absorbing a second change,
            // per IEC 61850-7-2.
            let already_triggered = state
                .pending
                .as_ref()
                .and_then(|p| p.inclusion_flags.get(idx))
                .map(|f| f.has_trigger())
                .unwrap_or(false);

            if already_triggered {
                state.report_due = Some(Instant::now());
                rc_guard
                    .metrics
                    .coalesced_buftm
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    attr_ref = %attr_ref,
                    idx,
                    "buffer-time bypass: entry retriggered inside the buffer window, sending the pending report now"
                );
            }

            let ds_len = state.dataset.as_ref().map(|d| d.len()).unwrap_or(0);
            let pending = state
                .pending
                .get_or_insert_with(|| PendingReport::new_empty(ds_len, now_ms));

            if let Some(f) = pending.inclusion_flags.get_mut(idx) {
                *f = flag;
            }
            if let Some(slot) = pending.snapshot.get_mut(idx) {
                *slot = Some(new_value.clone());
            }

            if !state.triggered {
                state.triggered = true;
                let buf_tm = Duration::from_millis(state.buf_tm_ms as u64);
                state.report_due = Some(Instant::now() + buf_tm);
                if let Some(ref mut p) = state.pending {
                    p.time_of_entry_ms = now_ms;
                }
            }
        }
    }

    // ─── BRCB trigger path ────────────────────────────────────────────────────

    /// Reports that a data attribute value changed, for BRCBs.
    ///
    /// Mirrors `on_value_updated`:
    /// 1. look the attribute up in `brcb_watch_map`;
    /// 2. apply the trgOps filter and skip control blocks that do not subscribe to
    ///    this trigger class;
    /// 3. honor the `is_buffering` gate: a BRCB buffers whenever its data set is
    ///    valid, even while `RptEna` is false, which is the principal behavioral
    ///    difference between a BRCB and a URCB;
    /// 4. coalesce by buffer time: `buf_tm_ms == 0` enqueues an entry immediately,
    ///    otherwise the trigger accumulates in `brcb_buftm_pending` until `tick`
    ///    finds it due;
    /// 5. enqueue through `enqueue_entry_with_snapshot`, which freezes the data set
    ///    values and inclusion flags into the entry, so the send path never reads
    ///    live values.
    ///
    /// `attr_ref`, `new_value`, `flag`, and `now_ms` mean the same as in
    /// `on_value_updated`.
    pub fn on_brcb_value_updated(
        &self,
        attr_ref: &DataAttributeRef,
        new_value: MmsValue,
        flag: InclusionFlag,
        now_ms: u64,
    ) {
        let Some(weak_list) = self.brcb_watch_map.get(attr_ref) else {
            return;
        };

        for weak in weak_list {
            let Some(brcb_arc) = weak.upgrade() else {
                continue;
            };

            // trgOps filter
            let trg = if flag.contains(InclusionFlag::VALUE_CHANGED) {
                TriggerOptions::DATA_CHANGED
            } else if flag.contains(InclusionFlag::QUALITY_CHANGED) {
                TriggerOptions::QUALITY_CHANGED
            } else if flag.contains(InclusionFlag::VALUE_UPDATE) {
                TriggerOptions::DATA_UPDATE
            } else {
                continue;
            };

            // Copy the fields needed, then release the state lock.
            let (is_buffering, buf_tm_ms, trg_ops, mms_path, ds_len) = {
                let Ok(state) = brcb_arc.state.lock() else {
                    tracing::warn!(attr_ref = %attr_ref, "brcb state mutex poisoned, skipping trigger");
                    continue;
                };
                let mms_path = brcb_arc.mms_path.clone();
                let ds = match self.brcb_datasets.get(&mms_path) {
                    Some(ds) => ds,
                    None => continue,
                };
                (
                    state.is_buffering,
                    state.buf_tm_ms,
                    state.trg_ops,
                    mms_path,
                    ds.len(),
                )
            };

            // A BRCB with no valid data set does not buffer, so it takes no triggers.
            if !is_buffering {
                continue;
            }
            if !trg_ops.contains(trg) {
                tracing::trace!(
                    mms_path = %mms_path,
                    attr_ref = %attr_ref,
                    "brcb trigger skipped: trgops does not cover this trigger class"
                );
                continue;
            }

            let idx = match self
                .brcb_datasets
                .get(&mms_path)
                .and_then(|ds| ds.entries.iter().position(|e| &e.attr_ref == attr_ref))
            {
                Some(i) => i,
                None => continue,
            };

            if buf_tm_ms == 0 {
                // Single-trigger snapshot: the other data set slots stay `None`, so
                // the encoded inclusion bitmap marks only this index.
                let mut snap = EnqueuedSnapshot::new(ds_len);
                if let Some(slot) = snap.inclusion_flags.get_mut(idx) {
                    *slot = flag;
                }
                if let Some(slot) = snap.values.get_mut(idx) {
                    *slot = Some(new_value.clone());
                }
                if let Err(e) = brcb_arc.enqueue_entry_with_snapshot(now_ms, false, false, snap) {
                    tracing::warn!(
                        mms_path = %mms_path,
                        attr_ref = %attr_ref,
                        error = ?e,
                        "brcb enqueue failed on the immediate path"
                    );
                }
                continue;
            }

            // Buffer time set: accumulate until tick finds the window expired.
            let Ok(mut pending) = self.brcb_buftm_pending.lock() else {
                tracing::warn!(mms_path = %mms_path, "brcb buffer-time pending mutex poisoned");
                continue;
            };
            let entry = pending
                .entry(mms_path.clone())
                .or_insert_with(|| BrcbBufTmPending {
                    first_trigger_ms: now_ms,
                    due_at: Instant::now() + Duration::from_millis(buf_tm_ms as u64),
                    snapshot: EnqueuedSnapshot::new(ds_len),
                });
            // A later trigger in the same window merges its inclusion flag and
            // overwrites the value with the newest one.
            if let Some(slot) = entry.snapshot.inclusion_flags.get_mut(idx) {
                *slot = flag;
            }
            if let Some(slot) = entry.snapshot.values.get_mut(idx) {
                *slot = Some(new_value.clone());
            }
        }
    }

    /// Enqueues and flushes every BRCB whose buffer time, integrity period, or
    /// general interrogation is due.
    ///
    /// Called from `tick()`; exposed separately so it can be driven directly.
    pub fn tick_brcb(&self, now: Instant, now_ms: u64) {
        let due_paths: Vec<(String, BrcbBufTmPending)> = {
            let Ok(mut pending) = self.brcb_buftm_pending.lock() else {
                return;
            };
            let due_keys: Vec<String> = pending
                .iter()
                .filter(|(_, v)| now >= v.due_at)
                .map(|(k, _)| k.clone())
                .collect();
            due_keys
                .into_iter()
                .filter_map(|k| pending.remove(&k).map(|v| (k, v)))
                .collect()
        };
        for (mms_path, p) in due_paths {
            if let Some(brcb_arc) = self.brcbs.get(&mms_path) {
                if let Err(e) = brcb_arc.enqueue_entry_with_snapshot(
                    p.first_trigger_ms,
                    false,
                    false,
                    p.snapshot,
                ) {
                    tracing::warn!(
                        mms_path = %mms_path,
                        error = ?e,
                        "brcb buffer-time enqueue failed"
                    );
                }
            }
        }

        // General interrogation, integrity period, then flush.
        for (mms_path, brcb_arc) in self.brcbs.iter() {
            // Copy the fields needed, then release the state lock.
            let (rpt_ena, conn_id, gi_pending, intg_pd_ms, trg_ops) = {
                let Ok(state) = brcb_arc.state.lock() else {
                    continue;
                };
                (
                    state.rpt_ena,
                    state.client_conn_id,
                    state.gi,
                    state.intg_pd_ms,
                    state.trg_ops,
                )
            };

            // General interrogation: enqueue the whole data set as one entry and
            // clear the request flag.
            if rpt_ena && trg_ops.contains(TriggerOptions::GI) && gi_pending {
                if let Some(snap) = self.snapshot_full_dataset(mms_path.as_str()) {
                    if let Err(e) = brcb_arc.enqueue_entry_with_snapshot(now_ms, false, true, snap)
                    {
                        tracing::warn!(
                            mms_path = %mms_path,
                            error = ?e,
                            "brcb general interrogation enqueue failed"
                        );
                    } else if let Ok(mut s) = brcb_arc.state.lock() {
                        s.gi = false;
                    }
                }
            }

            // Integrity period elapsed: enqueue the whole data set as one entry.
            if rpt_ena && trg_ops.contains(TriggerOptions::INTEGRITY) && intg_pd_ms > 0 {
                let due = {
                    let Ok(map) = self.brcb_next_intg.lock() else {
                        continue;
                    };
                    map.get(mms_path)
                        .copied()
                        .map(|t| now >= t)
                        .unwrap_or(false)
                };
                if due {
                    if let Some(snap) = self.snapshot_full_dataset(mms_path.as_str()) {
                        if let Err(e) =
                            brcb_arc.enqueue_entry_with_snapshot(now_ms, true, false, snap)
                        {
                            tracing::warn!(
                                mms_path = %mms_path,
                                error = ?e,
                                "brcb integrity enqueue failed"
                            );
                        }
                        if let Ok(mut map) = self.brcb_next_intg.lock() {
                            map.insert(
                                mms_path.to_string(),
                                now + Duration::from_millis(intg_pd_ms as u64),
                            );
                        }
                    }
                }
            }

            if rpt_ena {
                if let Some(cid) = conn_id {
                    self.flush_brcb_pending(brcb_arc, cid, now_ms);
                }
            }
        }
    }

    /// Takes a live snapshot of a BRCB data set, for integrity and general
    /// interrogation reports.
    fn snapshot_full_dataset(&self, mms_path: &str) -> Option<EnqueuedSnapshot> {
        let ds = self.brcb_datasets.get(mms_path)?;
        let n = ds.len();
        let mut snap = EnqueuedSnapshot::new(n);
        for (i, entry) in ds.entries.iter().enumerate() {
            snap.values[i] = entry.read_value();
            snap.inclusion_flags[i] = InclusionFlag::VALUE_CHANGED;
        }
        Some(snap)
    }

    /// Restarts a BRCB integrity period timer; called when the BRCB is enabled.
    pub fn refresh_brcb_integrity_period(&self, mms_path: &str) {
        let intg_pd_ms = match self.brcbs.get(mms_path) {
            Some(b) => match b.state.lock() {
                Ok(s) => s.intg_pd_ms,
                Err(_) => return,
            },
            None => return,
        };
        let Ok(mut map) = self.brcb_next_intg.lock() else {
            return;
        };
        if intg_pd_ms > 0 {
            map.insert(
                mms_path.to_string(),
                Instant::now() + Duration::from_millis(intg_pd_ms as u64),
            );
        } else {
            map.remove(mms_path);
        }
    }

    // ─── Periodic tick (buffer time, integrity period, GI) ────────────────────

    /// Scans every URCB and sends the reports whose buffer time, integrity period,
    /// or general interrogation is due.
    ///
    /// Implements the report event processing of IEC 61850-7-2. A 1 ms interval
    /// keeps `BufTm = 0` reports effectively immediate.
    pub fn tick(&self) {
        let now = Instant::now();
        let now_ms = current_time_ms();

        // Connections to drop are collected and handled after the per-control-block
        // locks are released: flush_pending cannot call on_connection_dropped itself
        // because std mutexes are not reentrant.
        let mut to_drop: Vec<ConnectionId> = Vec::new();

        for rc_arc in self.rcbs.values() {
            let Ok(rc_guard) = rc_arc.lock() else {
                continue;
            };

            // Decide what to send while the state lock is held, then flush after it
            // is released.
            let action = {
                let Ok(mut state) = rc_guard.state.lock() else {
                    continue;
                };

                if !state.rpt_ena {
                    continue;
                }
                let conn_id = match state.client_conn_id {
                    Some(id) => id,
                    None => continue,
                };

                // General interrogation takes priority.
                if state.trg_ops.contains(TriggerOptions::GI) && state.gi {
                    let pending_dc = if state.triggered {
                        state.triggered = false;
                        state.report_due = None;
                        state.pending.take()
                    } else {
                        None
                    };
                    let ds_len = state.dataset.as_ref().map(|d| d.len()).unwrap_or(0);
                    let gi_pending = make_gi_pending(ds_len, now_ms, &state);
                    state.gi = false;
                    TickAction::Gi {
                        conn_id,
                        pending_dc,
                        gi_pending,
                    }
                }
                // Integrity report, once the period has elapsed.
                else if state.trg_ops.contains(TriggerOptions::INTEGRITY)
                    && state.intg_pd_ms > 0
                    && state.next_intg_report.map(|t| now >= t).unwrap_or(false)
                {
                    let pending_dc = if state.triggered {
                        state.triggered = false;
                        state.report_due = None;
                        state.pending.take()
                    } else {
                        None
                    };
                    let ds_len = state.dataset.as_ref().map(|d| d.len()).unwrap_or(0);
                    let intg_pending = make_integrity_pending(ds_len, now_ms, &state);
                    let intg_pd = Duration::from_millis(state.intg_pd_ms as u64);
                    state.next_intg_report = Some(now + intg_pd);
                    TickAction::Integrity {
                        conn_id,
                        pending_dc,
                        intg_pending,
                    }
                }
                // Buffer time elapsed: send the accumulated data-change report.
                else if state.triggered && state.report_due.map(|t| now >= t).unwrap_or(false) {
                    if let Some(pending) = state.pending.take() {
                        state.triggered = false;
                        state.report_due = None;
                        TickAction::DataChange { conn_id, pending }
                    } else {
                        TickAction::None
                    }
                } else {
                    TickAction::None
                }
            };
            // The state lock is released here; a Some result asks for the connection
            // to be dropped.
            let drop_after: Option<ConnectionId> = match action {
                TickAction::None => None,
                TickAction::DataChange { conn_id, pending } => {
                    self.flush_pending(&rc_guard, conn_id, pending, now_ms)
                }
                TickAction::Gi {
                    conn_id,
                    pending_dc,
                    gi_pending,
                } => {
                    let r1 = if let Some(dc) = pending_dc {
                        self.flush_pending(&rc_guard, conn_id, dc, now_ms)
                    } else {
                        None
                    };
                    // The connection is already treated as gone, so the second report
                    // is not attempted.
                    if r1.is_some() {
                        r1
                    } else {
                        self.flush_pending(&rc_guard, conn_id, gi_pending, now_ms)
                    }
                }
                TickAction::Integrity {
                    conn_id,
                    pending_dc,
                    intg_pending,
                } => {
                    let r1 = if let Some(dc) = pending_dc {
                        self.flush_pending(&rc_guard, conn_id, dc, now_ms)
                    } else {
                        None
                    };
                    if r1.is_some() {
                        r1
                    } else {
                        self.flush_pending(&rc_guard, conn_id, intg_pending, now_ms)
                    }
                }
            };
            drop(rc_guard); // released explicitly so on_connection_dropped can relock the same handle
            if let Some(c) = drop_after {
                to_drop.push(c);
            }
        }

        // Every control block lock is released by now.
        for c in to_drop {
            self.on_connection_dropped(c);
        }
    }

    /// Fills in the values of entries still marked NOT_UPDATED once the model is
    /// unlocked, and marks the affected control blocks due.
    ///
    /// Implements the post-unlock value fill-in of IEC 61850-7-2.
    pub fn flush_after_unlock(&self, now_ms: u64) {
        for rc_arc in self.rcbs.values() {
            let Ok(rc_guard) = rc_arc.lock() else {
                continue;
            };
            let Ok(mut state) = rc_guard.state.lock() else {
                continue;
            };
            if !state.rpt_ena {
                continue;
            }
            if state.pending.is_none() {
                continue;
            }

            // Collect the indices first: state cannot be borrowed mutably while the
            // pending report is borrowed shared.
            let not_updated_indices: Vec<usize> = state
                .pending
                .as_ref()
                .map(|p| {
                    p.inclusion_flags
                        .iter()
                        .enumerate()
                        .filter(|(_, f)| f.contains(InclusionFlag::NOT_UPDATED))
                        .map(|(i, _)| i)
                        .collect()
                })
                .unwrap_or_default();

            for i in not_updated_indices {
                let live_val = state
                    .dataset
                    .as_ref()
                    .and_then(|ds| ds.entries.get(i))
                    .and_then(|e| e.read_value());

                if let Some(ref mut p) = state.pending {
                    if let Some(snap_slot) = p.snapshot.get_mut(i) {
                        *snap_slot = live_val;
                    }
                    if let Some(flag_slot) = p.inclusion_flags.get_mut(i) {
                        *flag_slot = InclusionFlag::VALUE_CHANGED;
                    }
                }
            }

            // Mark the report due so the next tick picks it up.
            if !state.triggered {
                state.triggered = true;
                state.report_due = Some(Instant::now());
                if let Some(ref mut p) = state.pending {
                    p.time_of_entry_ms = now_ms;
                }
            }
        }
    }

    // ─── Connection loss ──────────────────────────────────────────────────────

    /// Releases every RCB held by a connection that has gone away: the control block
    /// is disabled and its reservation cleared.
    ///
    /// Implements the RCB release on connection loss of IEC 61850-7-2.
    pub fn on_connection_dropped(&self, conn_id: ConnectionId) {
        for rc_arc in self.rcbs.values() {
            let Ok(rc_guard) = rc_arc.lock() else {
                continue;
            };
            let Ok(mut state) = rc_guard.state.lock() else {
                continue;
            };
            if state.client_conn_id != Some(conn_id) {
                continue;
            }
            tracing::warn!(
                conn_id,
                mms_path = %rc_guard.mms_path,
                "connection lost, disabling urcb and clearing its reservation"
            );
            state.rpt_ena = false;
            state.client_conn_id = None;
            state.pending = None;
            state.triggered = false;
            state.report_due = None;
            // A lost connection always clears Resv.
            state.resv = false;
            state.gi = false;
        }
    }

    // ─── Internal: sending a pending report ───────────────────────────────────

    /// Sends every PDU segment of one pending report, honoring backpressure.
    ///
    /// With a `ChannelReportSink` injected, each PDU goes through `try_send_pdu` and
    /// the `SendOutcome` decides what happens:
    ///
    /// - `Sent`: the `sent` counter is incremented and the consecutive-failure count
    ///   is reset to zero
    /// - `WouldBlock`: `dropped_socket_full` is incremented, a warning is logged, and
    ///   the consecutive count grows; on reaching `BACKPRESSURE_CLOSE_THRESHOLD` the
    ///   function returns `Some(conn_id)`
    /// - `ReceiverDropped` or `NotFound`: the connection is treated as gone and
    ///   `Some(conn_id)` is returned
    ///
    /// With any other sink the plain boolean path is used and no counter moves.
    ///
    /// A `Some(conn_id)` return means the caller must call
    /// `self.on_connection_dropped(conn_id)` after releasing the outer control block
    /// lock. It is not called here because `tick` holds `rc_arc.lock()` while
    /// `on_connection_dropped` relocks every control block, and `std::sync::Mutex`
    /// is not reentrant, so an inline call would deadlock.
    #[must_use]
    fn flush_pending(
        &self,
        rc: &ReportControl,
        conn_id: ConnectionId,
        pending: PendingReport,
        now_ms: u64,
    ) -> Option<ConnectionId> {
        let (rpt_id, opt_flds, sq_num, dat_set, conf_rev, dataset_clone, max_pdu) = {
            let Ok(mut state) = rc.state.lock() else {
                return None;
            };
            let sq_num = state.next_sq_num();
            let dataset_clone = match state.dataset.clone() {
                Some(d) => d,
                None => {
                    tracing::warn!(
                        mms_path = %rc.mms_path,
                        "flush_pending: no data set bound, skipping"
                    );
                    return None;
                }
            };
            (
                state.rpt_id.clone(),
                state.opt_flds,
                sq_num,
                state.dat_set.clone(),
                state.conf_rev,
                dataset_clone,
                65000usize, // TODO: take this from the connection negotiated max PDU size
            )
        };

        let params = ReportEncodeParams {
            rpt_id: &rpt_id,
            opt_flds,
            sq_num,
            time_of_entry_ms: pending.time_of_entry_ms.max(now_ms),
            dat_set: &dat_set,
            conf_rev,
            dataset: &dataset_clone,
            pending: &pending,
            max_pdu_size_bytes: max_pdu,
        };

        // A PduTooSmall result is a fatal configuration error: the report is dropped
        // and sqNum is rolled back to the value taken above, so the client sees no
        // gap. The failure is reported rather than silently skipped.
        let pdus = match encode_report_pdus(&params) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(
                    mms_path = %rc.mms_path,
                    sq_num,
                    error = %e,
                    "urcb report encode failed, dropping the pending report"
                );
                if let Ok(mut state) = rc.state.lock() {
                    state.sq_num = sq_num;
                }
                return None;
            }
        };

        if let Some(ref ch_sink) = self.channel_sink {
            // Backpressure-aware path.
            for pdu in pdus {
                let outcome = ch_sink.try_send_pdu(conn_id, pdu);
                match outcome {
                    SendOutcome::Sent => {
                        rc.metrics.sent.fetch_add(1, Ordering::Relaxed);
                        rc.metrics
                            .consecutive_socket_full
                            .store(0, Ordering::Relaxed);
                    }
                    SendOutcome::WouldBlock => {
                        rc.metrics
                            .dropped_socket_full
                            .fetch_add(1, Ordering::Relaxed);
                        let consec = rc
                            .metrics
                            .consecutive_socket_full
                            .fetch_add(1, Ordering::Relaxed)
                            + 1;
                        tracing::warn!(
                            conn_id,
                            mms_path = %rc.mms_path,
                            consecutive = consec,
                            threshold = BACKPRESSURE_CLOSE_THRESHOLD,
                            "report pdu dropped: channel full"
                        );
                        if consec >= BACKPRESSURE_CLOSE_THRESHOLD {
                            tracing::warn!(
                                conn_id,
                                mms_path = %rc.mms_path,
                                consecutive = consec,
                                "consecutive would-block threshold reached, connection treated as stalled"
                            );
                            // Reset for the next connection.
                            rc.metrics
                                .consecutive_socket_full
                                .store(0, Ordering::Relaxed);
                            return Some(conn_id);
                        }
                        // Below the threshold: the rest of this report is dropped and
                        // the connection stays open.
                        return None;
                    }
                    SendOutcome::ReceiverDropped | SendOutcome::NotFound => {
                        tracing::warn!(
                            conn_id,
                            mms_path = %rc.mms_path,
                            ?outcome,
                            "send failed, client is presumed disconnected"
                        );
                        return Some(conn_id);
                    }
                }
            }
        } else {
            // Plain trait path, used by test sinks.
            for pdu in pdus {
                if !self.sink.send_pdu(conn_id, pdu) {
                    tracing::warn!(
                        conn_id,
                        mms_path = %rc.mms_path,
                        "send failed, client is presumed disconnected"
                    );
                    return Some(conn_id);
                }
            }
        }
        None
    }

    // ─── BRCB send path ───────────────────────────────────────────────────────

    /// Sends the entries a BRCB has buffered, to one client connection.
    ///
    /// The transmit anchor decides where sending starts:
    /// - `None`: the buffer has not been resynchronized yet and nothing is sent
    /// - `FromHead`: every buffered entry is sent and the first one implies
    ///   `BufOvfl = true`
    /// - `AfterEntryId(id)`: sending resumes after `id`, and `BufOvfl` comes from the
    ///   backend
    /// - `WaitingForNext`: the trigger path failed to run the `on_enqueue` hook; this
    ///   is logged as an error and nothing is sent
    ///
    /// Each entry is encoded, then sent segment by segment. `sq_num`, the transmit
    /// anchor, and the overflow flag advance only once the last segment of an entry
    /// has been accepted, so a partial send is retried from the same entry. A
    /// `WouldBlock` leaves the anchor untouched for the next attempt; a closed or
    /// unknown receiver drops the connection; an encoding failure also leaves the
    /// anchor untouched.
    ///
    /// Returns the number of entries sent.
    pub fn flush_brcb_pending(
        &self,
        brcb: &Arc<BufferedReportControl>,
        conn_id: ConnectionId,
        now_ms: u64,
    ) -> usize {
        // Read the anchor and release the state lock before calling
        // brcb_encode_snapshot, which takes the same lock; std mutexes are not
        // reentrant.
        let anchor = {
            let Ok(state) = brcb.state.lock() else {
                tracing::warn!(mms_path = %brcb.mms_path, "brcb state mutex poisoned");
                return 0;
            };
            state.transmit_anchor.clone()
        };
        let snap = match brcb_encode_snapshot(brcb) {
            Ok(s) => s,
            Err(_) => return 0,
        };

        let (entries, mut imply_overflow) = match anchor {
            TransmitAnchor::None => {
                // Not resynchronized yet: the client has not written EntryID.
                return 0;
            }
            TransmitAnchor::FromHead => {
                // An all-zero EntryID means send from the head, and the first entry
                // implies BufOvfl = true.
                let buf = match brcb.lock_buffer() {
                    Ok(b) => b,
                    Err(_) => return 0,
                };
                let entries = buf.iter_entries();
                drop(buf);
                (entries, true)
            }
            TransmitAnchor::AfterEntryId(after) => {
                let buf = match brcb.lock_buffer() {
                    Ok(b) => b,
                    Err(_) => return 0,
                };
                let entries = buf.iter_from(&after);
                let ovfl = buf.is_overflow();
                drop(buf);
                (entries, ovfl)
            }
            TransmitAnchor::WaitingForNext => {
                // on_enqueue should have moved this state on to AfterEntryId; seeing
                // it here means the trigger path skipped that hook.
                tracing::error!(
                    mms_path = %brcb.mms_path,
                    "brcb transmit anchor stuck at waiting-for-next: the trigger path skipped the on_enqueue hook"
                );
                return 0;
            }
        };

        if entries.is_empty() {
            return 0;
        }

        // Prefer the data set bound by register_brcb_with_dataset; fall back to an
        // empty data set when the BRCB was registered without one.
        let dataset_clone: Dataset = match self.brcb_datasets.get(&brcb.mms_path) {
            Some(ds) => ds.clone(),
            None => self.brcb_dataset_or_empty(&snap.dat_set),
        };
        let dataset = &dataset_clone;
        let max_pdu = 65000usize;
        let mut sent_count: usize = 0;

        for entry in entries.iter() {
            // Read sqNum without advancing it: it moves only after the last segment.
            let sq_num = match brcb.state.lock() {
                Ok(s) => s.sq_num,
                Err(_) => return sent_count,
            };

            let pending = pending_from_brcb_entry(entry, dataset.len());
            let params = BrcbReportEncodeParams {
                rpt_id: &snap.rpt_id,
                opt_flds: snap.opt_flds,
                sq_num,
                time_of_entry_ms: entry.time_of_entry_ms.max(now_ms),
                dat_set: &snap.dat_set,
                conf_rev: snap.conf_rev,
                entry_id: entry.entry_id,
                is_overflow: imply_overflow,
                dataset,
                pending: &pending,
                max_pdu_size_bytes: max_pdu,
            };

            let pdus = match encode_brcb_report_pdus(&params) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(
                        mms_path = %brcb.mms_path,
                        entry_id = entry.entry_id.as_u64(),
                        error = %e,
                        "brcb report encode failed, entry dropped and the anchor left in place"
                    );
                    // The anchor and sqNum stay put, so the entry is retried once the
                    // configuration is corrected.
                    return sent_count;
                }
            };

            let mut all_segments_sent = true;
            if let Some(ref ch_sink) = self.channel_sink {
                for pdu in pdus {
                    let outcome = ch_sink.try_send_pdu(conn_id, pdu);
                    match outcome {
                        SendOutcome::Sent => {}
                        SendOutcome::WouldBlock => {
                            tracing::warn!(
                                conn_id,
                                mms_path = %brcb.mms_path,
                                entry_id = entry.entry_id.as_u64(),
                                "brcb report pdu dropped: channel full, anchor left in place for the next tick"
                            );
                            all_segments_sent = false;
                            break;
                        }
                        SendOutcome::ReceiverDropped | SendOutcome::NotFound => {
                            tracing::warn!(
                                conn_id,
                                mms_path = %brcb.mms_path,
                                ?outcome,
                                "brcb send failed, connection treated as closed"
                            );
                            self.on_connection_dropped(conn_id);
                            return sent_count;
                        }
                    }
                }
            } else {
                for pdu in pdus {
                    if !self.sink.send_pdu(conn_id, pdu) {
                        tracing::warn!(
                            conn_id,
                            mms_path = %brcb.mms_path,
                            "brcb send failed, connection treated as closed"
                        );
                        self.on_connection_dropped(conn_id);
                        return sent_count;
                    }
                }
            }

            if !all_segments_sent {
                // A segment failed part way through: leave the anchor in place and
                // retry on the next pass.
                return sent_count;
            }

            // Every segment was accepted: advance the anchor and sqNum, clear overflow.
            if let Ok(mut state) = brcb.state.lock() {
                state.sq_num = state.sq_num.wrapping_add(1);
                state.transmit_anchor = TransmitAnchor::AfterEntryId(entry.entry_id);
                state.last_sent_entry_id = entry.entry_id;
                state.last_sent_time_of_entry_ms = entry.time_of_entry_ms;
            }
            if let Ok(mut buf) = brcb.lock_buffer() {
                buf.clear_overflow();
            }
            // Overflow was just cleared, so later entries in this pass do not imply it.
            imply_overflow = false;
            sent_count += 1;
        }

        sent_count
    }

    /// Flushes every BRCB that is enabled and has a client connection.
    ///
    /// Returns the total number of entries sent.
    pub fn flush_all_brcb_pending(&self, now_ms: u64) -> usize {
        let mut total = 0;
        for brcb_arc in self.brcbs.values() {
            // The state guard must be dropped before flush_brcb_pending, which takes
            // the same lock; std mutexes are not reentrant.
            let conn_id = {
                let Ok(s) = brcb_arc.state.lock() else {
                    continue;
                };
                if !s.rpt_ena {
                    continue;
                }
                match s.client_conn_id {
                    Some(id) => id,
                    None => continue,
                }
            };
            total += self.flush_brcb_pending(brcb_arc, conn_id, now_ms);
        }
        total
    }

    /// Returns an empty `Dataset` named after `dat_set`.
    ///
    /// Used when a BRCB was registered without a bound data set: the encoder then
    /// takes the empty-inclusion path and still produces a valid PDU carrying
    /// EntryID and BufOvfl.
    fn brcb_dataset_or_empty(&self, dat_set: &str) -> Dataset {
        Dataset::new(dat_set)
    }

    // ─── Integrity period setup ───────────────────────────────────────────────

    /// Restarts a URCB integrity period timer; called when the URCB is enabled.
    pub fn refresh_integrity_period(&self, mms_path: &str) {
        if let Some(rc_arc) = self.rcbs.get(mms_path) {
            if let Ok(rc_guard) = rc_arc.lock() {
                if let Ok(mut state) = rc_guard.state.lock() {
                    if state.intg_pd_ms > 0 {
                        let dur = Duration::from_millis(state.intg_pd_ms as u64);
                        state.next_intg_report = Some(Instant::now() + dur);
                    } else {
                        state.next_intg_report = None;
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tick action: what one tick decided to send for a control block
// ─────────────────────────────────────────────────────────────────────────────

enum TickAction {
    None,
    DataChange {
        conn_id: ConnectionId,
        pending: PendingReport,
    },
    Gi {
        conn_id: ConnectionId,
        pending_dc: Option<PendingReport>,
        gi_pending: PendingReport,
    },
    Integrity {
        conn_id: ConnectionId,
        pending_dc: Option<PendingReport>,
        intg_pending: PendingReport,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the current wall-clock time in milliseconds since the Unix epoch.
fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Builds a general interrogation report from a live snapshot of the data set.
fn make_gi_pending(ds_len: usize, now_ms: u64, state: &super::rcb::RcbState) -> PendingReport {
    let mut p = PendingReport::new_empty(ds_len, now_ms);
    p.is_gi = true;
    if let Some(ref ds) = state.dataset {
        for (i, entry) in ds.entries.iter().enumerate() {
            p.snapshot[i] = entry.read_value();
        }
    }
    p
}

/// Builds an integrity report from a live snapshot of the data set.
fn make_integrity_pending(
    ds_len: usize,
    now_ms: u64,
    state: &super::rcb::RcbState,
) -> PendingReport {
    let mut p = PendingReport::new_empty(ds_len, now_ms);
    p.is_integrity = true;
    if let Some(ref ds) = state.dataset {
        for (i, entry) in ds.entries.iter().enumerate() {
            p.snapshot[i] = entry.read_value();
        }
    }
    p
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::{InclusionFlag, OptFlds, TriggerOptions};
    use crate::reporting::dataset::{Dataset, DatasetEntry};
    use crate::reporting::rcb::Rcb;
    use iec61850_model::MmsValue;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, RwLock};

    fn make_entry(attr_ref: &str, val: MmsValue) -> DatasetEntry {
        DatasetEntry::new(attr_ref, Arc::new(RwLock::new(val)))
    }

    fn make_ds(entries: Vec<(&str, MmsValue)>) -> Dataset {
        let mut ds = Dataset::new("ds1");
        for (r, v) in entries {
            ds.push(make_entry(r, v));
        }
        ds
    }

    fn make_rcb_and_ds(
        name: &str,
        attr_ref: &str,
        trg_ops: TriggerOptions,
    ) -> (ReportControl, Dataset) {
        let rcb = Rcb::new(name, "GGIO1$ds1")
            .with_trg_ops(trg_ops)
            .with_opt_flds(OptFlds::SEQ_NUM | OptFlds::REASON);
        let ds = make_ds(vec![(attr_ref, MmsValue::Boolean(false))]);
        let mms_path = format!("IED1LD0/GGIO1$RP${}", name);
        let rc = ReportControl::new(&mms_path, rcb);
        (rc, ds)
    }

    fn enable_rcb(rc_arc: &Arc<Mutex<ReportControl>>, conn_id: ConnectionId) {
        let rc = rc_arc.lock().unwrap();
        let mut state = rc.state.lock().unwrap();
        state.rpt_ena = true;
        state.resv = true;
        state.client_conn_id = Some(conn_id);
    }

    // ── register / get ────────────────────────────────────────────────────────

    #[test]
    fn register_rcb_and_get() {
        let mut engine = ReportingEngine::new_null();
        let (rc, ds) = make_rcb_and_ds(
            "urcb01",
            "IED1LD0/GGIO1$ST$Ind1$stVal",
            TriggerOptions::DATA_CHANGED,
        );
        let path = rc.mms_path.clone();
        engine.register_rcb(rc, ds).unwrap();
        assert!(engine.get_rcb(&path).is_some());
    }

    #[test]
    fn register_builds_inverted_index() {
        let mut engine = ReportingEngine::new_null();
        let (rc, ds) = make_rcb_and_ds(
            "urcb01",
            "IED1LD0/GGIO1$ST$Ind1$stVal",
            TriggerOptions::DATA_CHANGED,
        );
        engine.register_rcb(rc, ds).unwrap();
        assert!(
            engine.watch_map.contains_key("IED1LD0/GGIO1$ST$Ind1$stVal"),
            "the inverted index must contain this attribute reference"
        );
    }

    // ── on_value_updated, the inverted index path ──────────────────────────────

    #[test]
    fn on_value_updated_sets_triggered() {
        let mut engine = ReportingEngine::new_null();
        let (rc, ds) = make_rcb_and_ds(
            "urcb01",
            "IED1LD0/GGIO1$ST$Ind1$stVal",
            TriggerOptions::DATA_CHANGED,
        );
        let path = rc.mms_path.clone();
        engine.register_rcb(rc, ds).unwrap();

        // enable RCB
        let rc_arc = engine.get_rcb(&path).unwrap();
        enable_rcb(&rc_arc, 42);

        let now_ms = 1_000_000u64;
        engine.on_value_updated(
            &"IED1LD0/GGIO1$ST$Ind1$stVal".to_string(),
            MmsValue::Boolean(true),
            InclusionFlag::VALUE_CHANGED,
            now_ms,
        );

        let rc = rc_arc.lock().unwrap();
        let state = rc.state.lock().unwrap();
        assert!(
            state.triggered,
            "triggered must be set after on_value_updated"
        );
        assert!(
            state.pending.is_some(),
            "a pending report must exist after on_value_updated"
        );
        let p = state.pending.as_ref().unwrap();
        assert!(
            p.inclusion_flags[0].has_trigger(),
            "entry 0 must carry a trigger flag"
        );
        assert_eq!(p.snapshot[0], Some(MmsValue::Boolean(true)));
    }

    #[test]
    fn on_value_updated_disabled_rcb_ignored() {
        let mut engine = ReportingEngine::new_null();
        let (rc, ds) = make_rcb_and_ds(
            "urcb01",
            "IED1LD0/GGIO1$ST$Ind1$stVal",
            TriggerOptions::DATA_CHANGED,
        );
        let path = rc.mms_path.clone();
        engine.register_rcb(rc, ds).unwrap();
        // The control block is left disabled.

        engine.on_value_updated(
            &"IED1LD0/GGIO1$ST$Ind1$stVal".to_string(),
            MmsValue::Boolean(true),
            InclusionFlag::VALUE_CHANGED,
            1_000_000,
        );

        let rc_arc = engine.get_rcb(&path).unwrap();
        let rc = rc_arc.lock().unwrap();
        let state = rc.state.lock().unwrap();
        assert!(
            !state.triggered,
            "a disabled control block must not be triggered"
        );
    }

    #[test]
    fn on_value_updated_wrong_trg_ops_ignored() {
        let mut engine = ReportingEngine::new_null();
        // trgOps allows only quality changes, but a value change is reported.
        let (rc, ds) = make_rcb_and_ds(
            "urcb01",
            "IED1LD0/GGIO1$ST$Ind1$stVal",
            TriggerOptions::QUALITY_CHANGED,
        );
        let path = rc.mms_path.clone();
        engine.register_rcb(rc, ds).unwrap();
        let rc_arc = engine.get_rcb(&path).unwrap();
        enable_rcb(&rc_arc, 42);

        engine.on_value_updated(
            &"IED1LD0/GGIO1$ST$Ind1$stVal".to_string(),
            MmsValue::Boolean(true),
            InclusionFlag::VALUE_CHANGED, // not covered by trgOps
            1_000_000,
        );

        let rc = rc_arc.lock().unwrap();
        let state = rc.state.lock().unwrap();
        assert!(
            !state.triggered,
            "a trigger class outside trgops must not fire"
        );
    }

    /// A trigger class outside trgOps increments `skipped_trgops`.
    #[test]
    fn on_value_updated_wrong_trg_ops_increments_skipped_trgops() {
        let mut engine = ReportingEngine::new_null();
        let (rc, ds) = make_rcb_and_ds(
            "urcb01",
            "IED1LD0/GGIO1$ST$Ind1$stVal",
            TriggerOptions::QUALITY_CHANGED,
        );
        let path = rc.mms_path.clone();
        engine.register_rcb(rc, ds).unwrap();
        let rc_arc = engine.get_rcb(&path).unwrap();
        enable_rcb(&rc_arc, 42);

        engine.on_value_updated(
            &"IED1LD0/GGIO1$ST$Ind1$stVal".to_string(),
            MmsValue::Boolean(true),
            InclusionFlag::VALUE_CHANGED, // not covered by trgOps
            1_000_000,
        );

        let rc = rc_arc.lock().unwrap();
        let snap = rc.metrics_snapshot();
        assert_eq!(
            snap.skipped_trgops, 1,
            "a trigger outside trgops must set skipped_trgops to 1"
        );
    }

    /// A second trigger on the same entry inside the buffer time increments `coalesced_buftm`.
    #[test]
    fn on_value_updated_buftm_bypass_increments_coalesced_buftm() {
        let mut engine = ReportingEngine::new_null();
        let (rc, ds) = make_rcb_and_ds(
            "urcb01",
            "IED1LD0/GGIO1$ST$Ind1$stVal",
            TriggerOptions::DATA_CHANGED,
        );
        let path = rc.mms_path.clone();
        engine.register_rcb(rc, ds).unwrap();
        let rc_arc = engine.get_rcb(&path).unwrap();
        // A buffer time of 100 ms keeps the first trigger from flushing immediately.
        {
            let rc_l = rc_arc.lock().unwrap();
            let mut s = rc_l.state.lock().unwrap();
            s.rpt_ena = true;
            s.resv = true;
            s.client_conn_id = Some(10);
            s.buf_tm_ms = 100;
        }

        let attr = "IED1LD0/GGIO1$ST$Ind1$stVal".to_string();
        // First trigger: creates the pending report.
        engine.on_value_updated(
            &attr,
            MmsValue::Boolean(true),
            InclusionFlag::VALUE_CHANGED,
            1000,
        );
        // Second trigger on the same entry takes the buffer-time bypass.
        engine.on_value_updated(
            &attr,
            MmsValue::Boolean(false),
            InclusionFlag::VALUE_CHANGED,
            1010,
        );

        let rc = rc_arc.lock().unwrap();
        let snap = rc.metrics_snapshot();
        assert_eq!(
            snap.coalesced_buftm, 1,
            "the buffer-time bypass must set coalesced_buftm to 1"
        );
    }

    // ── metrics_snapshot starts at zero ───────────────────────────────────────

    #[test]
    fn metrics_snapshot_default_all_zero() {
        let (rc, _ds) = make_rcb_and_ds("urcb01", "A", TriggerOptions::DATA_CHANGED);
        let snap = rc.metrics_snapshot();
        assert_eq!(snap.sent, 0);
        assert_eq!(snap.dropped_socket_full, 0);
        assert_eq!(snap.dropped_buffer_full, 0);
        assert_eq!(snap.coalesced_buftm, 0);
        assert_eq!(snap.skipped_trgops, 0);
    }

    // ── sent counter on the channel sink path ─────────────────────────────────

    #[test]
    fn flush_pending_sent_counter_increments_with_channel_sink() {
        use crate::reporting::sink::ChannelReportSink;

        let ch_sink = Arc::new(ChannelReportSink::new());
        let mut engine = ReportingEngine::new_with_channel_sink(ch_sink.clone());

        let (rc, ds) = make_rcb_and_ds(
            "urcb01",
            "IED1LD0/GGIO1$ST$Ind1$stVal",
            TriggerOptions::DATA_CHANGED,
        );
        let path = rc.mms_path.clone();
        engine.register_rcb(rc, ds).unwrap();
        let rc_arc = engine.get_rcb(&path).unwrap();
        enable_rcb(&rc_arc, 7);

        // Register a bounded channel for the connection.
        let (tx, _rx) = ChannelReportSink::create_channel();
        ch_sink.register(7, tx);

        // Stage a pending report whose buffer time has already elapsed.
        {
            let rc_l = rc_arc.lock().unwrap();
            let mut state = rc_l.state.lock().unwrap();
            let ds_len = state.dataset.as_ref().map(|d| d.len()).unwrap_or(1);
            let mut pending = PendingReport::new_empty(ds_len, 1_000_000);
            pending.inclusion_flags[0] = InclusionFlag::VALUE_CHANGED;
            pending.snapshot[0] = Some(MmsValue::Boolean(true));
            state.pending = Some(pending);
            state.triggered = true;
            state.report_due = Some(Instant::now() - Duration::from_millis(10));
        }

        engine.tick();

        let rc_l = rc_arc.lock().unwrap();
        let snap = rc_l.metrics_snapshot();
        assert!(
            snap.sent >= 1,
            "sent must be at least 1 after tick, was {}",
            snap.sent
        );
    }

    // ── on_connection_dropped ─────────────────────────────────────────────────

    #[test]
    fn on_connection_dropped_disables_rcb() {
        let mut engine = ReportingEngine::new_null();
        let (rc, ds) = make_rcb_and_ds("urcb01", "A", TriggerOptions::DATA_CHANGED);
        let path = rc.mms_path.clone();
        engine.register_rcb(rc, ds).unwrap();
        let rc_arc = engine.get_rcb(&path).unwrap();
        enable_rcb(&rc_arc, 99);

        engine.on_connection_dropped(99);

        let rc = rc_arc.lock().unwrap();
        let state = rc.state.lock().unwrap();
        assert!(
            !state.rpt_ena,
            "rpt_ena must be false after the connection is lost"
        );
        assert!(
            !state.resv,
            "resv must be cleared after the connection is lost"
        );
        assert!(
            state.client_conn_id.is_none(),
            "client_conn_id must be cleared"
        );
    }

    #[test]
    fn on_connection_dropped_only_affects_matching_conn() {
        let mut engine = ReportingEngine::new_null();
        let (rc1, ds1) = make_rcb_and_ds("urcb01", "A1", TriggerOptions::DATA_CHANGED);
        let (rc2, ds2) = make_rcb_and_ds("urcb02", "A2", TriggerOptions::DATA_CHANGED);
        let path1 = rc1.mms_path.clone();
        let path2 = rc2.mms_path.clone();
        engine.register_rcb(rc1, ds1).unwrap();
        engine.register_rcb(rc2, ds2).unwrap();

        let rc1_arc = engine.get_rcb(&path1).unwrap();
        let rc2_arc = engine.get_rcb(&path2).unwrap();
        enable_rcb(&rc1_arc, 1);
        enable_rcb(&rc2_arc, 2);

        engine.on_connection_dropped(1); // only connection 1 is lost

        let rc1_l = rc1_arc.lock().unwrap();
        let s1 = rc1_l.state.lock().unwrap();
        assert!(
            !s1.rpt_ena,
            "the control block on connection 1 must be disabled"
        );

        let rc2_l = rc2_arc.lock().unwrap();
        let s2 = rc2_l.state.lock().unwrap();
        assert!(
            s2.rpt_ena,
            "the control block on connection 2 must be unaffected"
        );
    }

    // ── tick + collect sink ───────────────────────────────────────────────────

    #[test]
    fn tick_sends_pdu_when_buf_tm_expired() {
        let sink = Arc::new(CollectReportSink::default());
        let mut engine = ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>);

        let (rc, ds) = make_rcb_and_ds(
            "urcb01",
            "IED1LD0/GGIO1$ST$Ind1$stVal",
            TriggerOptions::DATA_CHANGED,
        );
        let path = rc.mms_path.clone();
        engine.register_rcb(rc, ds).unwrap();
        let rc_arc = engine.get_rcb(&path).unwrap();
        enable_rcb(&rc_arc, 7);

        // Stage a pending report whose buffer time has already elapsed.
        {
            let rc = rc_arc.lock().unwrap();
            let mut state = rc.state.lock().unwrap();
            let ds_len = state.dataset.as_ref().map(|d| d.len()).unwrap_or(1);
            let mut pending = PendingReport::new_empty(ds_len, 1_000_000);
            pending.inclusion_flags[0] = InclusionFlag::VALUE_CHANGED;
            pending.snapshot[0] = Some(MmsValue::Boolean(true));
            state.pending = Some(pending);
            state.triggered = true;
            state.report_due = Some(Instant::now() - Duration::from_millis(10));
        }

        engine.tick();

        let sent = sink.pdus.lock().unwrap();
        assert!(!sent.is_empty(), "tick must send a pdu");
        assert_eq!(sent[0].0, 7, "the pdu must go to connection 7");
        assert_eq!(sent[0].1[0], 0xa3, "the outer pdu tag must be 0xa3");
    }

    // ── WouldBlock increments dropped_socket_full and drops the connection ────

    #[test]
    fn flush_pending_would_block_increments_dropped_and_drops_conn() {
        use crate::reporting::sink::ChannelReportSink;

        let ch_sink = Arc::new(ChannelReportSink::new());
        let mut engine = ReportingEngine::new_with_channel_sink(ch_sink.clone());

        let (rc, ds) = make_rcb_and_ds(
            "urcb01",
            "IED1LD0/GGIO1$ST$Ind1$stVal",
            TriggerOptions::DATA_CHANGED,
        );
        let path = rc.mms_path.clone();
        engine.register_rcb(rc, ds).unwrap();
        let rc_arc = engine.get_rcb(&path).unwrap();
        enable_rcb(&rc_arc, 7);

        // Register a channel whose receiver never reads, simulating a slow client.
        let (tx, _rx) = ChannelReportSink::create_channel();
        ch_sink.register(7, tx);

        // Fill the channel.
        {
            let pdu = bytes::Bytes::from_static(b"\xa3\x00");
            use crate::reporting::sink::REPORT_CHANNEL_CAP;
            for _ in 0..REPORT_CHANNEL_CAP {
                ch_sink.try_send_pdu(7, pdu.clone());
            }
        }

        // Tick past the threshold, staging a pending report each time.
        for i in 0..(BACKPRESSURE_CLOSE_THRESHOLD as usize + 2) {
            {
                let rc_l = rc_arc.lock().unwrap();
                let mut state = rc_l.state.lock().unwrap();
                if !state.rpt_ena {
                    break;
                }
                let ds_len = state.dataset.as_ref().map(|d| d.len()).unwrap_or(1);
                let mut pending = PendingReport::new_empty(ds_len, 1_000_000 + i as u64);
                pending.inclusion_flags[0] = InclusionFlag::VALUE_CHANGED;
                pending.snapshot[0] = Some(MmsValue::Boolean(true));
                state.pending = Some(pending);
                state.triggered = true;
                state.report_due = Some(Instant::now() - Duration::from_millis(10));
            }
            engine.tick();
        }

        let rc_l = rc_arc.lock().unwrap();
        let snap = rc_l.metrics_snapshot();
        assert!(
            snap.dropped_socket_full >= BACKPRESSURE_CLOSE_THRESHOLD as u64,
            "dropped_socket_full must be at least {}, was {}",
            BACKPRESSURE_CLOSE_THRESHOLD,
            snap.dropped_socket_full
        );

        let state = rc_l.state.lock().unwrap();
        assert!(
            !state.rpt_ena,
            "rpt_ena must be false after {} consecutive would-block results",
            BACKPRESSURE_CLOSE_THRESHOLD
        );
    }

    // ── refresh_integrity_period ──────────────────────────────────────────────

    #[test]
    fn refresh_integrity_period_sets_next_intg_report() {
        let mut engine = ReportingEngine::new_null();
        let (rc, ds) = make_rcb_and_ds("urcb01", "A", TriggerOptions::INTEGRITY);
        let path = rc.mms_path.clone();
        engine.register_rcb(rc, ds).unwrap();

        let rc_arc = engine.get_rcb(&path).unwrap();
        {
            let rc = rc_arc.lock().unwrap();
            let mut s = rc.state.lock().unwrap();
            s.intg_pd_ms = 500;
        }

        engine.refresh_integrity_period(&path);

        let rc = rc_arc.lock().unwrap();
        let s = rc.state.lock().unwrap();
        assert!(
            s.next_intg_report.is_some(),
            "next_intg_report must be set when the integrity period is greater than zero"
        );
    }

    // ── dropped_buffer_full stays zero for a URCB ─────────────────────────────

    #[test]
    fn dropped_buffer_full_never_incremented_in_urcb() {
        // A URCB pending report is flushed by the buffer-time bypass rather than
        // dropped, so this counter never moves; see the RcbMetrics documentation.
        let (rc, _ds) = make_rcb_and_ds("urcb01", "A", TriggerOptions::DATA_CHANGED);
        let snap = rc.metrics_snapshot();
        assert_eq!(
            snap.dropped_buffer_full, 0,
            "dropped_buffer_full must stay zero for a urcb"
        );
        // The counter staying at zero is the expected behavior, not a defect.
        let _ = rc
            .metrics
            .dropped_buffer_full
            .fetch_add(0, Ordering::Relaxed);
    }

    // ─── BRCB engine integration tests ────────────────────────────────────────

    fn make_brcb(name: &str) -> crate::reporting::brcb::BufferedReportControl {
        use crate::reporting::brcb::{Brcb, BufferedReportControl};
        let brcb = Brcb::new(name, "GGIO1$ds1");
        let mms_path = format!("IED1LD0/GGIO1$BR${}", name);
        BufferedReportControl::new(mms_path, brcb)
    }

    #[test]
    fn engine_register_brcb_then_lookup() {
        let mut eng = ReportingEngine::new_null();
        let brc = make_brcb("brcb01");
        eng.register_brcb(brc).unwrap();
        let path = "IED1LD0/GGIO1$BR$brcb01";
        assert!(
            eng.get_brcb(path).is_some(),
            "get_brcb must find a registered control block"
        );
        assert!(eng.brcb_paths().contains(&path.to_string()));
        assert!(
            eng.get_rcb(path).is_none(),
            "the urcb table must not contain a brcb"
        );
    }

    #[test]
    fn engine_register_brcb_duplicate_returns_err() {
        let mut eng = ReportingEngine::new_null();
        let brc = make_brcb("brcb01");
        eng.register_brcb(brc).unwrap();
        let dup = make_brcb("brcb01");
        assert!(eng.register_brcb(dup).is_err());
    }

    #[test]
    fn engine_tick_brcb_reservations_fires_on_expiry() {
        use crate::reporting::brcb::ResvTmsState;
        use std::num::NonZeroU16;
        let mut eng = ReportingEngine::new_null();
        let brc = make_brcb("brcb01");
        eng.register_brcb(brc).unwrap();
        // Make the reservation already expired.
        let path = "IED1LD0/GGIO1$BR$brcb01";
        {
            let brcb = eng.get_brcb(path).unwrap();
            let mut state = brcb.state.lock().unwrap();
            state.resv_tms = ResvTmsState::WithTimeout(NonZeroU16::new(1).unwrap());
            state.reservation_timeout = Some(Instant::now() - Duration::from_secs(60));
        }
        let fired = eng.tick_brcb_reservations();
        assert_eq!(
            fired, 1,
            "an expired brcb reservation must be released once"
        );
        let brcb = eng.get_brcb(path).unwrap();
        let state = brcb.state.lock().unwrap();
        assert_eq!(state.resv_tms, ResvTmsState::NotReserved);
        assert!(state.reservation_timeout.is_none());
    }

    #[test]
    fn engine_tick_brcb_reservations_no_op_when_not_expired() {
        use crate::reporting::brcb::ResvTmsState;
        use std::num::NonZeroU16;
        let mut eng = ReportingEngine::new_null();
        let brc = make_brcb("brcb01");
        eng.register_brcb(brc).unwrap();
        let path = "IED1LD0/GGIO1$BR$brcb01";
        {
            let brcb = eng.get_brcb(path).unwrap();
            let mut state = brcb.state.lock().unwrap();
            state.resv_tms = ResvTmsState::WithTimeout(NonZeroU16::new(60).unwrap());
            state.reservation_timeout = Some(Instant::now() + Duration::from_secs(60));
        }
        let fired = eng.tick_brcb_reservations();
        assert_eq!(fired, 0);
    }

    #[test]
    fn engine_metrics_dropped_buffer_full_initially_zero() {
        let eng = ReportingEngine::new_null();
        let m = eng.engine_metrics();
        assert_eq!(m.dropped_buffer_full(), 0);
    }

    /// Eviction in a registered BRCB backend increments the engine-level counter.
    #[test]
    fn engine_brcb_evict_increments_engine_dropped_buffer_full() {
        use crate::reporting::brcb::Brcb;

        let mut eng = ReportingEngine::new_null();
        // A capacity of 2 with five pushes evicts three entries.
        let brcb = Brcb::new("brcb01", "GGIO1$ds1").with_buffer_capacity(2);
        let brc =
            crate::reporting::brcb::BufferedReportControl::new("IED1LD0/GGIO1$BR$brcb01", brcb);
        eng.register_brcb(brc).unwrap();

        let path = "IED1LD0/GGIO1$BR$brcb01";
        let brcb_arc = eng.get_brcb(path).unwrap();
        for i in 0..5u64 {
            brcb_arc
                .enqueue_entry(1000 + i, false, false, bytes::Bytes::from_static(b"x"))
                .unwrap();
        }
        let m = eng.engine_metrics();
        assert_eq!(
            m.dropped_buffer_full(),
            3,
            "five pushes into a capacity of 2 must evict three entries"
        );
    }

    // ─── flush_brcb_pending send path ─────────────────────────────────────────

    /// A `FromHead` anchor sends every buffered entry.
    #[test]
    fn flush_brcb_pending_sends_from_head_when_anchor_is_from_head() {
        use crate::reporting::brcb::{Brcb, BufferedReportControl, TransmitAnchor};
        let sink = Arc::new(CollectReportSink::default());
        let mut eng = ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>);

        let brcb = Brcb::new("brcb01", "GGIO1$ds1").with_buffer_capacity(8);
        let brc = BufferedReportControl::new("IED1LD0/GGIO1$BR$brcb01", brcb);
        eng.register_brcb(brc).unwrap();
        let path = "IED1LD0/GGIO1$BR$brcb01";
        let brcb_arc = eng.get_brcb(path).unwrap();

        for i in 0..3u64 {
            brcb_arc
                .enqueue_entry(1000 + i, false, false, bytes::Bytes::from_static(b"e"))
                .unwrap();
        }

        // flush_brcb_pending does not check RptEna, so only the anchor is set.
        {
            let mut s = brcb_arc.state.lock().unwrap();
            s.transmit_anchor = TransmitAnchor::FromHead;
        }

        let n = eng.flush_brcb_pending(&brcb_arc, 42, 1_000_000);
        assert_eq!(n, 3, "a from-head anchor must send all three entries");

        let pdus = sink.pdus.lock().unwrap();
        assert_eq!(pdus.len(), 3, "the sink must receive three pdus");
        for (cid, pdu) in pdus.iter() {
            assert_eq!(*cid, 42);
            assert_eq!(pdu[0], 0xa3);
        }
    }

    #[test]
    fn flush_brcb_pending_sends_from_iter_from_when_anchor_is_after() {
        // An AfterEntryId anchor resumes with the entries that follow that id.
        use crate::reporting::brcb::{Brcb, BufferedReportControl, TransmitAnchor};
        let sink = Arc::new(CollectReportSink::default());
        let mut eng = ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>);

        let brcb = Brcb::new("brcb01", "GGIO1$ds1").with_buffer_capacity(8);
        let brc = BufferedReportControl::new("IED1LD0/GGIO1$BR$brcb01", brcb);
        eng.register_brcb(brc).unwrap();
        let path = "IED1LD0/GGIO1$BR$brcb01";
        let brcb_arc = eng.get_brcb(path).unwrap();

        let (id1, _) = brcb_arc
            .enqueue_entry(1000, false, false, bytes::Bytes::from_static(b"e1"))
            .unwrap();
        brcb_arc
            .enqueue_entry(1001, false, false, bytes::Bytes::from_static(b"e2"))
            .unwrap();
        brcb_arc
            .enqueue_entry(1002, false, false, bytes::Bytes::from_static(b"e3"))
            .unwrap();

        {
            let mut s = brcb_arc.state.lock().unwrap();
            s.transmit_anchor = TransmitAnchor::AfterEntryId(id1);
        }

        let n = eng.flush_brcb_pending(&brcb_arc, 7, 1_000_000);
        assert_eq!(
            n, 2,
            "an after-entry-id anchor must send the two later entries"
        );
        assert_eq!(sink.pdus.lock().unwrap().len(), 2);
    }

    #[test]
    fn flush_brcb_pending_advances_anchor_after_full_segment_send() {
        // The anchor advances to AfterEntryId only once an entry is fully sent.
        use crate::reporting::brcb::{Brcb, BufferedReportControl, TransmitAnchor};
        let sink = Arc::new(CollectReportSink::default());
        let mut eng = ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>);

        let brcb = Brcb::new("brcb01", "GGIO1$ds1").with_buffer_capacity(8);
        let brc = BufferedReportControl::new("IED1LD0/GGIO1$BR$brcb01", brcb);
        eng.register_brcb(brc).unwrap();
        let path = "IED1LD0/GGIO1$BR$brcb01";
        let brcb_arc = eng.get_brcb(path).unwrap();

        brcb_arc
            .enqueue_entry(1000, false, false, bytes::Bytes::from_static(b"e1"))
            .unwrap();
        let (id_last, _) = brcb_arc
            .enqueue_entry(1001, false, false, bytes::Bytes::from_static(b"e2"))
            .unwrap();
        {
            let mut s = brcb_arc.state.lock().unwrap();
            s.transmit_anchor = TransmitAnchor::FromHead;
        }

        let pre_sq = brcb_arc.state.lock().unwrap().sq_num;
        eng.flush_brcb_pending(&brcb_arc, 1, 1_000_000);

        let s = brcb_arc.state.lock().unwrap();
        assert_eq!(s.transmit_anchor, TransmitAnchor::AfterEntryId(id_last));
        // sqNum advances once per entry.
        assert_eq!(s.sq_num, pre_sq.wrapping_add(2));
        assert_eq!(s.last_sent_entry_id, id_last);
    }

    #[test]
    fn flush_brcb_pending_does_not_advance_when_buffer_empty() {
        // A from-head anchor over an empty buffer sends nothing and leaves the anchor
        // in place.
        use crate::reporting::brcb::{Brcb, BufferedReportControl, TransmitAnchor};
        let sink = Arc::new(CollectReportSink::default());
        let mut eng = ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>);

        let brcb = Brcb::new("brcb01", "GGIO1$ds1").with_buffer_capacity(8);
        let brc = BufferedReportControl::new("IED1LD0/GGIO1$BR$brcb01", brcb);
        eng.register_brcb(brc).unwrap();
        let path = "IED1LD0/GGIO1$BR$brcb01";
        let brcb_arc = eng.get_brcb(path).unwrap();
        {
            let mut s = brcb_arc.state.lock().unwrap();
            s.transmit_anchor = TransmitAnchor::FromHead;
        }
        let n = eng.flush_brcb_pending(&brcb_arc, 1, 1_000_000);
        assert_eq!(n, 0);
        assert!(sink.pdus.lock().unwrap().is_empty());
        let s = brcb_arc.state.lock().unwrap();
        assert_eq!(s.transmit_anchor, TransmitAnchor::FromHead);
    }

    #[test]
    fn flush_brcb_pending_anchor_none_returns_zero() {
        // A None anchor means the buffer has not been resynchronized yet.
        use crate::reporting::brcb::{Brcb, BufferedReportControl};
        let sink = Arc::new(CollectReportSink::default());
        let mut eng = ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>);

        let brcb = Brcb::new("brcb01", "GGIO1$ds1").with_buffer_capacity(8);
        let brc = BufferedReportControl::new("IED1LD0/GGIO1$BR$brcb01", brcb);
        eng.register_brcb(brc).unwrap();
        let path = "IED1LD0/GGIO1$BR$brcb01";
        let brcb_arc = eng.get_brcb(path).unwrap();
        brcb_arc
            .enqueue_entry(1000, false, false, bytes::Bytes::from_static(b"e"))
            .unwrap();
        let n = eng.flush_brcb_pending(&brcb_arc, 1, 1_000_000);
        assert_eq!(n, 0, "a none anchor must not send any pdu");
        assert!(sink.pdus.lock().unwrap().is_empty());
    }

    #[test]
    fn flush_brcb_pending_logs_error_on_waiting_for_next_anchor() {
        // on_enqueue should have cleared WaitingForNext; seeing it on the send path is
        // logged as an error and must not panic.
        use crate::reporting::brcb::{Brcb, BufferedReportControl, TransmitAnchor};
        let sink = Arc::new(CollectReportSink::default());
        let mut eng = ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>);

        let brcb = Brcb::new("brcb01", "GGIO1$ds1").with_buffer_capacity(8);
        let brc = BufferedReportControl::new("IED1LD0/GGIO1$BR$brcb01", brcb);
        eng.register_brcb(brc).unwrap();
        let path = "IED1LD0/GGIO1$BR$brcb01";
        let brcb_arc = eng.get_brcb(path).unwrap();
        brcb_arc
            .enqueue_entry(1000, false, false, bytes::Bytes::from_static(b"e"))
            .unwrap();
        {
            let mut s = brcb_arc.state.lock().unwrap();
            s.transmit_anchor = TransmitAnchor::WaitingForNext;
        }
        let n = eng.flush_brcb_pending(&brcb_arc, 1, 1_000_000);
        assert_eq!(
            n, 0,
            "a waiting-for-next anchor must send nothing and return 0"
        );
    }

    #[test]
    fn flush_brcb_pending_clears_overflow_after_send() {
        use crate::reporting::brcb::{Brcb, BufferedReportControl, TransmitAnchor};
        let sink = Arc::new(CollectReportSink::default());
        let mut eng = ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>);
        let brcb = Brcb::new("brcb01", "GGIO1$ds1").with_buffer_capacity(8);
        let brc = BufferedReportControl::new("IED1LD0/GGIO1$BR$brcb01", brcb);
        eng.register_brcb(brc).unwrap();
        let path = "IED1LD0/GGIO1$BR$brcb01";
        let brcb_arc = eng.get_brcb(path).unwrap();

        brcb_arc
            .enqueue_entry(1000, false, false, bytes::Bytes::from_static(b"e"))
            .unwrap();
        // A fresh report buffer starts with overflow set.
        assert!(brcb_arc.lock_buffer().unwrap().is_overflow());
        {
            let mut s = brcb_arc.state.lock().unwrap();
            s.transmit_anchor = TransmitAnchor::FromHead;
        }
        eng.flush_brcb_pending(&brcb_arc, 1, 1_000_000);
        assert!(
            !brcb_arc.lock_buffer().unwrap().is_overflow(),
            "overflow must be cleared once the entry is sent"
        );
    }

    // ─── Enqueue-time snapshot pins the reported value ────────────────────────

    /// Values are frozen at enqueue time, not at flush time.
    ///
    /// The data set attribute is changed between enqueue and flush; the encoded PDU
    /// must still carry the value the attribute had when the entry was enqueued.
    #[test]
    fn brcb_enqueue_snapshot_locks_value_against_dataset_mutation() {
        use crate::flags::OptFlds;
        use crate::reporting::brcb::{Brcb, BufferedReportControl, TransmitAnchor};
        use crate::reporting::dataset::DatasetEntry;
        use std::sync::RwLock;

        let sink = Arc::new(CollectReportSink::default());
        let mut eng = ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>);

        let val = Arc::new(RwLock::new(MmsValue::Boolean(false)));
        let mut ds = Dataset::new("GGIO1$ds1");
        let attr_ref = "IED1LD0/GGIO1$ST$Ind1$stVal".to_string();
        ds.push(DatasetEntry::new(&attr_ref, val.clone()));

        let brcb = Brcb::new("brcb01", "GGIO1$ds1")
            .with_buffer_capacity(8)
            .with_trg_ops(TriggerOptions::DATA_CHANGED)
            .with_opt_flds(OptFlds::SEQ_NUM | OptFlds::ENTRY_ID);
        let mms_path = "IED1LD0/GGIO1$BR$brcb01";
        let brc = BufferedReportControl::new(mms_path, brcb);

        eng.register_brcb_with_dataset(brc, ds).unwrap();

        // is_buffering is already true because the data set name is not empty.
        let brcb_arc = eng.get_brcb(mms_path).unwrap();
        {
            let mut s = brcb_arc.state.lock().unwrap();
            s.client_conn_id = Some(7);
        }

        // Trigger with the value changing from false to true.
        {
            *val.write().unwrap() = MmsValue::Boolean(true);
        }
        eng.on_brcb_value_updated(
            &attr_ref,
            MmsValue::Boolean(true),
            InclusionFlag::VALUE_CHANGED,
            1_000_000,
        );

        assert_eq!(
            brcb_arc.lock_buffer().unwrap().len(),
            1,
            "a buffer time of 0 must enqueue the entry immediately"
        );

        // The data set changes again between enqueue and send.
        {
            *val.write().unwrap() = MmsValue::Boolean(false);
        }

        {
            let mut s = brcb_arc.state.lock().unwrap();
            s.transmit_anchor = TransmitAnchor::FromHead;
        }
        let sent = eng.flush_brcb_pending(&brcb_arc, 7, 1_000_001);
        assert_eq!(sent, 1, "exactly one entry must be sent");

        // A BER boolean is encoded as tag 0x83, length 1, content 0xff for true.
        let pdus = sink.pdus.lock().unwrap();
        assert_eq!(pdus.len(), 1);
        let (_, pdu) = &pdus[0];
        let pdu_slice: &[u8] = pdu;
        let has_true = pdu_slice
            .windows(3)
            .any(|w| w[0] == 0x83 && w[1] == 0x01 && w[2] == 0xff);
        assert!(
            has_true,
            "the pdu must carry the value present at enqueue time (boolean true, \
             0x83 0x01 0xff) even though the data set was changed back to false. pdu bytes: {:?}",
            pdu_slice
        );
    }

    /// A trigger class outside trgOps enqueues nothing.
    #[test]
    fn brcb_trigger_filtered_by_trg_ops() {
        use crate::reporting::brcb::{Brcb, BufferedReportControl};
        use crate::reporting::dataset::DatasetEntry;
        use std::sync::RwLock;

        let mut eng = ReportingEngine::new_null();

        let val = Arc::new(RwLock::new(MmsValue::Boolean(false)));
        let mut ds = Dataset::new("GGIO1$ds1");
        let attr_ref = "IED1LD0/GGIO1$ST$Ind1$stVal".to_string();
        ds.push(DatasetEntry::new(&attr_ref, val.clone()));

        let brcb = Brcb::new("brcb01", "GGIO1$ds1")
            .with_buffer_capacity(8)
            .with_trg_ops(TriggerOptions::QUALITY_CHANGED);
        let mms_path = "IED1LD0/GGIO1$BR$brcb01";
        let brc = BufferedReportControl::new(mms_path, brcb);
        eng.register_brcb_with_dataset(brc, ds).unwrap();

        eng.on_brcb_value_updated(
            &attr_ref,
            MmsValue::Boolean(true),
            InclusionFlag::VALUE_CHANGED,
            1_000_000,
        );

        let brcb_arc = eng.get_brcb(mms_path).unwrap();
        assert_eq!(
            brcb_arc.lock_buffer().unwrap().len(),
            0,
            "a trigger outside trgops must not be buffered"
        );
    }

    /// A BRCB whose `is_buffering` is false takes no triggers.
    #[test]
    fn brcb_trigger_skipped_when_not_buffering() {
        use crate::reporting::brcb::{Brcb, BufferedReportControl};
        use crate::reporting::dataset::DatasetEntry;
        use std::sync::RwLock;

        let mut eng = ReportingEngine::new_null();
        let val = Arc::new(RwLock::new(MmsValue::Boolean(false)));
        let mut ds = Dataset::new("GGIO1$ds1");
        let attr_ref = "IED1LD0/GGIO1$ST$Ind1$stVal".to_string();
        ds.push(DatasetEntry::new(&attr_ref, val.clone()));

        let brcb = Brcb::new("brcb01", "GGIO1$ds1").with_trg_ops(TriggerOptions::DATA_CHANGED);
        let mms_path = "IED1LD0/GGIO1$BR$brcb01";
        let brc = BufferedReportControl::new(mms_path, brcb);
        eng.register_brcb_with_dataset(brc, ds).unwrap();

        {
            let brcb_arc = eng.get_brcb(mms_path).unwrap();
            let mut s = brcb_arc.state.lock().unwrap();
            s.is_buffering = false;
        }

        eng.on_brcb_value_updated(
            &attr_ref,
            MmsValue::Boolean(true),
            InclusionFlag::VALUE_CHANGED,
            1_000_000,
        );

        let brcb_arc = eng.get_brcb(mms_path).unwrap();
        assert_eq!(
            brcb_arc.lock_buffer().unwrap().len(),
            0,
            "no entry must be buffered while is_buffering is false"
        );
    }

    /// With a buffer time greater than zero a trigger accumulates until `tick_brcb`
    /// finds the window expired.
    #[test]
    fn brcb_trigger_with_buf_tm_pends_until_tick() {
        use crate::reporting::brcb::{Brcb, BufferedReportControl};
        use crate::reporting::dataset::DatasetEntry;
        use std::sync::RwLock;

        let mut eng = ReportingEngine::new_null();
        let val = Arc::new(RwLock::new(MmsValue::Boolean(false)));
        let mut ds = Dataset::new("GGIO1$ds1");
        let attr_ref = "IED1LD0/GGIO1$ST$Ind1$stVal".to_string();
        ds.push(DatasetEntry::new(&attr_ref, val.clone()));

        let brcb = Brcb::new("brcb01", "GGIO1$ds1")
            .with_trg_ops(TriggerOptions::DATA_CHANGED)
            .with_buf_tm_ms(50);
        let mms_path = "IED1LD0/GGIO1$BR$brcb01";
        let brc = BufferedReportControl::new(mms_path, brcb);
        eng.register_brcb_with_dataset(brc, ds).unwrap();

        eng.on_brcb_value_updated(
            &attr_ref,
            MmsValue::Boolean(true),
            InclusionFlag::VALUE_CHANGED,
            1_000_000,
        );

        let brcb_arc = eng.get_brcb(mms_path).unwrap();
        assert_eq!(
            brcb_arc.lock_buffer().unwrap().len(),
            0,
            "a trigger must stay pending while the buffer time has not elapsed"
        );

        std::thread::sleep(std::time::Duration::from_millis(60));
        eng.tick_brcb(Instant::now(), 1_000_100);
        assert_eq!(
            brcb_arc.lock_buffer().unwrap().len(),
            1,
            "tick_brcb must enqueue one entry once the buffer time has elapsed"
        );
    }
}
