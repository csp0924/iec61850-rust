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

use super::brcb::{BufferedReportControl, ResvTmsState, TransmitAnchor};
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
use iec61850_mms::mms::server::connection::SERVER_MAX_PDU_SIZE;
use iec61850_model::MmsValue;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

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
/// The number of report PDUs a URCB has dropped since its channel last took one
/// lives per control block in `rc.metrics.consecutive_socket_full`, so
/// `flush_pending` needs only `&self`.
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
    /// MMS paths of the BRCBs whose last send found the channel full; a BRCB
    /// logs when it enters and when it leaves this set, not on every retry.
    brcb_blocked: Mutex<HashSet<String>>,
    /// Engine-level metrics. `dropped_buffer_full` is incremented by the buffer
    /// backends themselves when an entry has to be discarded.
    metrics: Arc<ReportingEngineMetrics>,
    /// Every open association: its peer address, which identifies the owner of
    /// a BRCB reservation across connections, and its negotiated PDU size.
    peers: HashMap<ConnectionId, Peer>,
    /// Data sets a DatSet write may name, shared with the server.
    dataset_registry: super::DatasetRegistry,
    /// Attribute reference of every member a DatSet write bound a control
    /// block to.
    value_index: ValueIndex,
}

/// Attribute reference of every data set member a DatSet write bound a control
/// block to, keyed by the address of the member's value lock.
///
/// Members of the data sets registered with a control block are indexed by the
/// server; this index holds the ones a client binds later. The server holds a
/// clone and looks an updated value up without taking the engine lock, and an
/// index nothing was ever added to costs a single atomic load. The weak handle
/// confirms that an address still belongs to the same value.
#[derive(Debug, Clone, Default)]
pub(crate) struct ValueIndex(Arc<ValueIndexInner>);

#[derive(Debug, Default)]
struct ValueIndexInner {
    /// Set once the first member is added; the map is not read before.
    populated: std::sync::atomic::AtomicBool,
    members: RwLock<MemberMap>,
}

/// Value lock address to the weak handle of that lock and its attribute
/// reference.
type MemberMap = HashMap<usize, (Weak<RwLock<MmsValue>>, DataAttributeRef)>;

impl ValueIndex {
    /// Records the attribute reference of every member of `dataset`.
    fn insert_members(&self, dataset: &Dataset) {
        let Ok(mut index) = self.0.members.write() else {
            tracing::warn!("the member value index lock is poisoned; the members were not indexed");
            return;
        };
        for entry in &dataset.entries {
            index.insert(
                Arc::as_ptr(&entry.value) as usize,
                (Arc::downgrade(&entry.value), entry.attr_ref.clone()),
            );
        }
        if !dataset.entries.is_empty() {
            self.0.populated.store(true, Ordering::Release);
        }
    }

    /// Returns the attribute reference a control block knows the value lock
    /// `value` by, when a data set bound by a DatSet write has it as a member.
    #[cfg(any(feature = "full-server", test))]
    pub(crate) fn attr_ref_for(&self, value: &Arc<RwLock<MmsValue>>) -> Option<DataAttributeRef> {
        if !self.0.populated.load(Ordering::Acquire) {
            return None;
        }
        let index = self.0.members.read().ok()?;
        let (weak, attr_ref) = index.get(&(Arc::as_ptr(value) as usize))?;
        (weak.strong_count() > 0 && std::ptr::eq(weak.as_ptr(), Arc::as_ptr(value)))
            .then(|| attr_ref.clone())
    }
}

/// Largest report PDU sent to a connection whose association is not
/// registered, in bytes: the largest MMS PDU size the server negotiates.
const UNREGISTERED_MAX_PDU_SIZE_BYTES: usize = SERVER_MAX_PDU_SIZE as usize;

/// What the engine keeps about one open association.
#[derive(Debug, Clone, Copy)]
struct Peer {
    /// Address of the remote end.
    ip: IpAddr,
    /// max_mms_pdu_size negotiated by Initiate, in bytes.
    max_pdu_size_bytes: usize,
}

/// Buffer-time accumulation state for one BRCB.
///
/// Follows the URCB `RcbState.report_due` timing model: the first trigger sets
/// `due_at = now + buf_tm_ms`, and triggers of other members inside the same
/// window only update the inclusion bitmap and the value snapshot. When the
/// buffer time expires, or a member already in the window triggers again, the
/// accumulated inclusion flags and snapshot are frozen into one buffer entry,
/// which is then flushed.
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
#[non_exhaustive]
pub struct ReportingEngineMetrics {
    /// Entries dropped because a BRCB buffer was full.
    ///
    /// Shared as an `Arc` so every BRCB backend increments the same counter
    /// directly instead of reporting back to the engine.
    pub dropped_buffer_full: Arc<AtomicU64>,
    /// URCB reports and BRCB entries dropped because they cannot be encoded
    /// within the PDU size the association negotiated.
    pub dropped_oversized: Arc<AtomicU64>,
}

impl Default for ReportingEngineMetrics {
    fn default() -> Self {
        Self {
            dropped_buffer_full: Arc::new(AtomicU64::new(0)),
            dropped_oversized: Arc::new(AtomicU64::new(0)),
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

    /// Returns the current `dropped_oversized` value.
    pub fn dropped_oversized(&self) -> u64 {
        self.dropped_oversized.load(Ordering::Relaxed)
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
    /// A DatSet write must name a data set in `registry`, keyed by
    /// `(domain, <LN>$<name>)`; a value without a domain names one in the
    /// domain of the control block. The server passes the registry its
    /// dispatcher serves, so both resolve the same data sets.
    ///
    /// Use `new_with_channel_sink` instead when the sink is an
    /// `Arc<ChannelReportSink>`, to enable backpressure handling.
    pub fn new(sink: Arc<dyn ReportSink>, registry: super::DatasetRegistry) -> Self {
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
            brcb_blocked: Mutex::new(HashSet::new()),
            metrics: ReportingEngineMetrics::new(),
            peers: HashMap::new(),
            dataset_registry: registry,
            value_index: ValueIndex::default(),
        }
    }

    /// Creates an engine backed by a backpressure-aware `ChannelReportSink`.
    ///
    /// Reports are then sent through `try_send_pdu`. A full channel drops the
    /// rest of a URCB report and keeps a BRCB entry buffered for the next tick;
    /// neither changes RptEna or Resv. Only a channel whose receiver is gone
    /// releases the control blocks of the connection.
    ///
    /// `registry` is the data set registry DatSet writes resolve against, as
    /// for `new`.
    pub fn new_with_channel_sink(
        sink: Arc<ChannelReportSink>,
        registry: super::DatasetRegistry,
    ) -> Self {
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
            brcb_blocked: Mutex::new(HashSet::new()),
            metrics: ReportingEngineMetrics::new(),
            peers: HashMap::new(),
            dataset_registry: registry,
            value_index: ValueIndex::default(),
        }
    }

    /// Creates an engine with a `NullReportSink` and an empty data set
    /// registry, for tests.
    #[cfg(test)]
    pub fn new_null() -> Self {
        Self::new(Arc::new(NullReportSink), Default::default())
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

    // ─── Data set binding ─────────────────────────────────────────────────────

    /// Returns the data set registry DatSet writes resolve against.
    #[cfg(test)]
    pub(crate) fn dataset_registry(&self) -> &super::DatasetRegistry {
        &self.dataset_registry
    }

    /// Returns the index of the members bound to a control block, which the
    /// caller queries without the engine lock.
    #[cfg(any(feature = "full-server", test))]
    pub(crate) fn value_index(&self) -> ValueIndex {
        self.value_index.clone()
    }

    /// Records the attribute reference of every member of `dataset`, which a
    /// DatSet write bound a control block to.
    fn index_values(&mut self, dataset: &Dataset) {
        self.value_index.insert_members(dataset);
    }

    /// Looks up the data set a DatSet value names, for the control block at
    /// `rcb_mms_path`.
    pub(crate) fn resolve_dataset(&self, rcb_mms_path: &str, dat_set: &str) -> Option<Dataset> {
        let key = dataset_key(rcb_mms_path, dat_set)?;
        let registry = self.dataset_registry.read().ok()?;
        registry.get(&key).map(|ds| Dataset::clone(ds))
    }

    /// Moves the URCB `rc` from the members of `old` to those of `new` in the
    /// inverted index.
    pub(crate) fn rebind_rcb_watches(
        &mut self,
        rc: &Arc<Mutex<ReportControl>>,
        old: Option<&Dataset>,
        new: Option<&Dataset>,
    ) {
        for entry in old.map(|d| d.entries.as_slice()).unwrap_or_default() {
            if let Some(list) = self.watch_map.get_mut(&entry.attr_ref) {
                list.retain(|w| !std::ptr::eq(w.as_ptr(), Arc::as_ptr(rc)));
                if list.is_empty() {
                    self.watch_map.remove(&entry.attr_ref);
                }
            }
        }
        if let Some(ds) = new {
            for entry in &ds.entries {
                self.watch_map
                    .entry(entry.attr_ref.clone())
                    .or_default()
                    .push(Arc::downgrade(rc));
            }
            self.index_values(ds);
        }
    }

    /// Binds the BRCB at `mms_path` to `dataset`, or unbinds it for `None`.
    ///
    /// Rebuilds its inverted index entries and drops any buffer-time window
    /// accumulated against the previous data set.
    pub(crate) fn rebind_brcb_dataset(&mut self, mms_path: &str, dataset: Option<Dataset>) {
        let Some(brcb) = self.brcbs.get(mms_path).cloned() else {
            return;
        };
        if let Some(old) = self.brcb_datasets.remove(mms_path) {
            for entry in &old.entries {
                if let Some(list) = self.brcb_watch_map.get_mut(&entry.attr_ref) {
                    list.retain(|w| !std::ptr::eq(w.as_ptr(), Arc::as_ptr(&brcb)));
                    if list.is_empty() {
                        self.brcb_watch_map.remove(&entry.attr_ref);
                    }
                }
            }
        }
        if let Ok(mut pending) = self.brcb_buftm_pending.lock() {
            pending.remove(mms_path);
        }
        if let Some(ds) = dataset {
            for entry in &ds.entries {
                self.brcb_watch_map
                    .entry(entry.attr_ref.clone())
                    .or_default()
                    .push(Arc::downgrade(&brcb));
            }
            self.index_values(&ds);
            self.brcb_datasets.insert(mms_path.to_string(), ds);
        }
    }

    /// Reports whether the DatSet of a control block names the data set
    /// `(domain, list_name)`.
    pub(crate) fn dataset_in_use(&self, domain: &str, list_name: &str) -> bool {
        let names = |path: &str, dat_set: &str| {
            dataset_key(path, dat_set).is_some_and(|(d, l)| d == domain && l == list_name)
        };
        let urcb = self.rcbs.iter().any(|(path, rc)| {
            rc.lock()
                .ok()
                .and_then(|rc| rc.state.lock().ok().map(|s| names(path, &s.dat_set)))
                .unwrap_or(true)
        });
        urcb || self.brcbs.iter().any(|(path, b)| {
            b.state
                .lock()
                .map(|s| names(path, &s.dat_set))
                .unwrap_or(true)
        })
    }

    /// Releases every BRCB reservation whose timeout has elapsed.
    ///
    /// Returns how many reservations fired. Driven from the `tick` path, where once
    /// per second is enough resolution.
    pub fn tick_brcb_reservations(&self) -> usize {
        self.tick_brcb_reservations_at(Instant::now())
    }

    /// Runs `tick_brcb_reservations` against the clock reading `now`.
    pub(crate) fn tick_brcb_reservations_at(&self, now: Instant) -> usize {
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
    /// A control block takes the reasons of `flag` its TrgOps enable and no
    /// other, so a report carries only enabled reasons for inclusion; a control
    /// block that enables none of them is not triggered.
    ///
    /// A member that triggers again while it is already part of the pending report
    /// sends that report immediately, and the new trigger opens the next buffer
    /// time, so no value is overwritten before it is reported.
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

        // Connections whose send failed are dropped once every lock is released.
        let mut to_drop: Vec<ConnectionId> = Vec::new();
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

            let flag = enabled_triggers(flag, state.trg_ops);
            if !flag.has_trigger() {
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

            // Buffer-time bypass, per the BufTm rules of IEC 61850-7-2: a second
            // trigger of a member already in the pending report sends that report
            // at once, and the new trigger starts the next buffer time.
            let already_triggered = state
                .pending
                .as_ref()
                .and_then(|p| p.inclusion_flags.get(idx))
                .map(|f| f.has_trigger())
                .unwrap_or(false);

            if let (true, Some(conn_id)) = (already_triggered, state.client_conn_id) {
                if let Some(pending) = state.pending.take() {
                    state.triggered = false;
                    state.report_due = None;
                    rc_guard
                        .metrics
                        .coalesced_buftm
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(
                        attr_ref = %attr_ref,
                        idx,
                        "buffer-time bypass: member retriggered inside the buffer window, sending the pending report now"
                    );
                    // flush_pending takes the state lock itself.
                    drop(state);
                    if let Some(c) = self.flush_pending(&rc_guard, conn_id, pending, now_ms) {
                        to_drop.push(c);
                    }
                    state = match rc_guard.state.lock() {
                        Ok(s) => s,
                        Err(_) => {
                            tracing::warn!(attr_ref = %attr_ref, "rcb state mutex poisoned, skipping");
                            continue;
                        }
                    };
                    if !state.rpt_ena {
                        continue;
                    }
                }
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
        for c in to_drop {
            self.on_connection_dropped(c);
        }
    }

    // ─── BRCB trigger path ────────────────────────────────────────────────────

    /// Reports that a data attribute value changed, for BRCBs.
    ///
    /// Mirrors `on_value_updated`:
    /// 1. look the attribute up in `brcb_watch_map`;
    /// 2. keep the reasons of `flag` the TrgOps enable, skipping a control block
    ///    that enables none of them;
    /// 3. honor the `is_buffering` gate: a BRCB buffers whenever its data set is
    ///    valid, even while `RptEna` is false, which is the principal behavioral
    ///    difference between a BRCB and a URCB;
    /// 4. coalesce by buffer time: `buf_tm_ms == 0` enqueues an entry immediately,
    ///    otherwise the trigger accumulates in `brcb_buftm_pending` until `tick`
    ///    finds it due; a member that triggers again inside the window enqueues
    ///    the accumulated entry at once and opens the next window;
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
            if let Some(brcb_arc) = weak.upgrade() {
                self.trigger_brcb(&brcb_arc, attr_ref, &new_value, flag, now_ms);
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
                    self.flush_brcb_pending(brcb_arc, cid);
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
        // The entry is flagged as integrity or general interrogation, which
        // includes every member; no member carries a data-change reason.
        for (i, entry) in ds.entries.iter().enumerate() {
            snap.values[i] = entry.read_value();
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
        self.tick_at(Instant::now(), current_time_ms());
    }

    /// Runs one `tick` against the clock readings `now` and `now_ms`.
    pub(crate) fn tick_at(&self, now: Instant, now_ms: u64) {
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

    // ─── Association peers ────────────────────────────────────────────────────

    /// Records the peer address of association `conn_id` and the
    /// max_mms_pdu_size it negotiated, in bytes.
    ///
    /// Every report PDU sent to the association stays within that size, per
    /// IEC 61850-8-1 §6.2.2.2 (b): the whole MMSpdu counts, the Session and
    /// Presentation envelope does not.
    #[cfg(any(feature = "full-server", test))]
    pub(crate) fn register_peer(
        &mut self,
        conn_id: ConnectionId,
        peer: IpAddr,
        max_pdu_size_bytes: usize,
    ) {
        self.peers.insert(
            conn_id,
            Peer {
                ip: peer,
                max_pdu_size_bytes,
            },
        );
    }

    /// Forgets the peer address of association `conn_id`.
    #[cfg(any(feature = "full-server", test))]
    pub(crate) fn deregister_peer(&mut self, conn_id: ConnectionId) {
        self.peers.remove(&conn_id);
    }

    /// Returns the peer address of association `conn_id`, when it is known.
    pub(crate) fn peer(&self, conn_id: ConnectionId) -> Option<IpAddr> {
        self.peers.get(&conn_id).map(|p| p.ip)
    }

    /// Returns the largest report PDU association `conn_id` accepts, in bytes.
    ///
    /// An association that was never registered gets the largest size the
    /// server negotiates.
    fn max_pdu_size_bytes(&self, conn_id: ConnectionId) -> usize {
        self.peers
            .get(&conn_id)
            .map_or(UNREGISTERED_MAX_PDU_SIZE_BYTES, |p| p.max_pdu_size_bytes)
    }

    // ─── Connection loss ──────────────────────────────────────────────────────

    /// Releases every RCB held by a connection that has gone away.
    ///
    /// Implements the RCB release on connection loss of IEC 61850-7-2. A URCB is
    /// disabled and its reservation cleared. A BRCB is disabled and unbound from
    /// the connection but keeps its buffer and its transmit anchor, so a client
    /// that enables it again resumes after the last entry sent. A BRCB reserved
    /// with a positive ResvTms stays reserved for its owner for ResvTms seconds
    /// from now; an unreserved one forgets its owner.
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
            rc_guard
                .metrics
                .consecutive_socket_full
                .store(0, Ordering::Relaxed);
        }
        for brcb in self.brcbs.values() {
            let Ok(mut state) = brcb.state.lock() else {
                continue;
            };
            if state.client_conn_id != Some(conn_id) {
                continue;
            }
            tracing::warn!(
                conn_id,
                mms_path = %brcb.mms_path,
                "connection lost, disabling brcb and keeping its buffer"
            );
            state.rpt_ena = false;
            state.client_conn_id = None;
            state.gi = false;
            self.set_brcb_blocked(&brcb.mms_path, false);
            match state.resv_tms {
                ResvTmsState::WithTimeout(secs) => {
                    state.reservation_timeout =
                        Some(Instant::now() + Duration::from_secs(u64::from(secs.get())));
                }
                ResvTmsState::NotReserved => state.owner = None,
                ResvTmsState::Preconfigured => {}
            }
        }
    }

    // ─── Internal: sending a pending report ───────────────────────────────────

    /// Sends every PDU segment of one pending report, honoring backpressure.
    ///
    /// The report is segmented at the PDU size the association negotiated.
    ///
    /// With a `ChannelReportSink` injected, each PDU goes through `try_send_pdu` and
    /// the `SendOutcome` decides what happens:
    ///
    /// - `Sent`: the `sent` counter is incremented
    /// - `WouldBlock`: this PDU and the remaining segments of the report are
    ///   dropped and counted in `dropped_socket_full`; RptEna and Resv are left as
    ///   they are, since only the loss of the association disables a URCB
    ///   (IEC 61850-7-2 §17.2.4.4, §17.2.4.5)
    /// - `ReceiverDropped` or `NotFound`: the connection is treated as gone and
    ///   `Some(conn_id)` is returned
    ///
    /// A run of drops logs one warning when it starts and one, with the number
    /// of PDUs dropped, when the channel takes a PDU again. An association that
    /// stops reading altogether is closed by the idle and send timeouts of the
    /// connection lifecycle.
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
        let (rpt_id, opt_flds, sq_num, dat_set, conf_rev, dataset_clone) = {
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
            max_pdu_size_bytes: self.max_pdu_size_bytes(conn_id),
        };

        // A report that does not fit the negotiated PDU size is dropped, logged
        // and counted once, and sqNum is rolled back to the value taken above,
        // so the client sees no gap.
        let pdus = match encode_report_pdus(&params) {
            Ok(v) => v,
            Err(e) => {
                self.report_oversized(&rc.mms_path, None, &dataset_clone, &e);
                if let Ok(mut state) = rc.state.lock() {
                    state.sq_num = sq_num;
                }
                return None;
            }
        };

        if let Some(ref ch_sink) = self.channel_sink {
            // Backpressure-aware path.
            let segments = pdus.len();
            for (n, pdu) in pdus.into_iter().enumerate() {
                let outcome = ch_sink.try_send_pdu(conn_id, pdu);
                match outcome {
                    SendOutcome::Sent => {
                        rc.metrics.sent.fetch_add(1, Ordering::Relaxed);
                        let dropped = rc
                            .metrics
                            .consecutive_socket_full
                            .swap(0, Ordering::Relaxed);
                        if dropped > 0 {
                            tracing::warn!(
                                conn_id,
                                mms_path = %rc.mms_path,
                                dropped,
                                "report delivery resumed after the report channel was full"
                            );
                        }
                    }
                    SendOutcome::WouldBlock => {
                        // This segment and the ones after it are dropped.
                        self.count_urcb_drop(rc, conn_id, segments - n);
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

    /// Counts `dropped` report PDUs of a URCB lost to a full channel, and logs
    /// when a run of drops starts.
    fn count_urcb_drop(&self, rc: &ReportControl, conn_id: ConnectionId, dropped: usize) {
        let dropped = dropped as u64;
        rc.metrics
            .dropped_socket_full
            .fetch_add(dropped, Ordering::Relaxed);
        let before = rc.metrics.consecutive_socket_full.fetch_add(
            u32::try_from(dropped).unwrap_or(u32::MAX),
            Ordering::Relaxed,
        );
        if before == 0 {
            tracing::warn!(
                conn_id,
                mms_path = %rc.mms_path,
                "report channel full, dropping urcb reports until it drains; RptEna and Resv are kept"
            );
        }
    }

    /// Logs and counts a URCB report or BRCB entry that cannot be encoded within
    /// the negotiated PDU size; the caller drops it.
    fn report_oversized(
        &self,
        mms_path: &str,
        entry_id: Option<super::buffer::EntryId>,
        dataset: &Dataset,
        error: &super::pdu::ReportEncodeError,
    ) {
        self.metrics
            .dropped_oversized
            .fetch_add(1, Ordering::Relaxed);
        let member = match error {
            super::pdu::ReportEncodeError::MemberTooLarge { index, .. } => dataset
                .entry(*index)
                .map(|e| e.attr_ref.as_str())
                .unwrap_or_default(),
            _ => "",
        };
        tracing::error!(
            mms_path = %mms_path,
            entry_id = entry_id.map(|id| id.as_u64()),
            member,
            error = %error,
            "report does not fit the negotiated pdu size, dropping it"
        );
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
    /// - `WaitingForNext`: the client resynchronized on the newest entry and
    ///   nothing is sent until a newer one is buffered; this is a normal state
    ///   and is not logged. Should a newer entry be buffered without `on_enqueue`
    ///   having resolved the anchor, the anchor is resolved here, once, with an
    ///   error logged, and sending resumes after the resynchronized entry
    ///
    /// Each entry is encoded, segmented at the PDU size the association
    /// negotiated, then sent segment by segment. Every segment of an entry
    /// carries the EntryID of that entry. `sq_num`, the transmit anchor, and the
    /// overflow flag advance only once the last segment of an entry has been
    /// accepted, so a partial send is retried from the same entry. A
    /// `WouldBlock` leaves the anchor untouched for the next attempt; a closed or
    /// unknown receiver drops the connection. An entry that cannot be encoded within the negotiated PDU size is dropped: it is
    /// logged and counted once, and the anchor moves past it.
    ///
    /// Every report carries, as TimeOfEntry, the time its entry entered the
    /// buffer, which is also what GetBRCBValues reads back as `TimeofEntry`; the
    /// send time does not appear on the wire.
    ///
    /// Returns the number of entries sent.
    pub fn flush_brcb_pending(
        &self,
        brcb: &Arc<BufferedReportControl>,
        conn_id: ConnectionId,
    ) -> usize {
        // Read the anchor and release the state lock before calling
        // brcb_encode_snapshot, which takes the same lock; std mutexes are not
        // reentrant.
        let (anchor, resynced_on) = {
            let Ok(state) = brcb.state.lock() else {
                tracing::warn!(mms_path = %brcb.mms_path, "brcb state mutex poisoned");
                return 0;
            };
            (state.transmit_anchor.clone(), state.last_committed_entry_id)
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
                // The client resynchronized on the newest entry, and nothing has
                // been buffered since: an ordinary wait for the next entry.
                let buf = match brcb.lock_buffer() {
                    Ok(b) => b,
                    Err(_) => return 0,
                };
                let entries = buf.iter_from(&resynced_on);
                let ovfl = buf.is_overflow();
                drop(buf);
                if entries.is_empty() {
                    return 0;
                }
                // A newer entry is buffered, yet on_enqueue never resolved the
                // anchor. Resolving it here logs this once and resumes after the
                // entry the client resynchronized on.
                tracing::error!(
                    mms_path = %brcb.mms_path,
                    entry_id = resynced_on.as_u64(),
                    "brcb transmit anchor still waiting for the next entry although a newer one is buffered, resuming after the resynchronized entry"
                );
                if let Ok(mut state) = brcb.state.lock() {
                    if state.transmit_anchor == TransmitAnchor::WaitingForNext {
                        state.transmit_anchor = TransmitAnchor::AfterEntryId(resynced_on);
                    }
                }
                (entries, ovfl)
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
        let max_pdu = self.max_pdu_size_bytes(conn_id);
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
                time_of_entry_ms: entry.time_of_entry_ms,
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
                    // The entry is dropped once: the anchor moves past it, so no
                    // later flush tries it again. sqNum stays put, since nothing
                    // was sent.
                    self.report_oversized(&brcb.mms_path, Some(entry.entry_id), dataset, &e);
                    if let Ok(mut state) = brcb.state.lock() {
                        state.transmit_anchor = TransmitAnchor::AfterEntryId(entry.entry_id);
                    }
                    continue;
                }
            };

            let mut all_segments_sent = true;
            if let Some(ref ch_sink) = self.channel_sink {
                for pdu in pdus {
                    let outcome = ch_sink.try_send_pdu(conn_id, pdu);
                    match outcome {
                        SendOutcome::Sent => {}
                        SendOutcome::WouldBlock => {
                            if self.set_brcb_blocked(&brcb.mms_path, true) {
                                tracing::warn!(
                                    conn_id,
                                    mms_path = %brcb.mms_path,
                                    entry_id = entry.entry_id.as_u64(),
                                    "report channel full, brcb entries stay buffered until it drains"
                                );
                            }
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
            if self.set_brcb_blocked(&brcb.mms_path, false) {
                tracing::debug!(
                    conn_id,
                    mms_path = %brcb.mms_path,
                    "report channel drained, brcb transmission resumed"
                );
            }
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

    /// Marks the BRCB at `mms_path` as blocked by a full channel, or as no
    /// longer blocked, and reports whether that changed its state.
    fn set_brcb_blocked(&self, mms_path: &str, blocked: bool) -> bool {
        let Ok(mut set) = self.brcb_blocked.lock() else {
            return blocked;
        };
        if blocked {
            set.insert(mms_path.to_string())
        } else {
            set.remove(mms_path)
        }
    }

    /// Flushes every BRCB that is enabled and has a client connection.
    ///
    /// Returns the total number of entries sent.
    pub fn flush_all_brcb_pending(&self) -> usize {
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
            total += self.flush_brcb_pending(brcb_arc, conn_id);
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

    // ─── Batched triggers ─────────────────────────────────────────────────────

    /// Reports several data attribute updates as one batch.
    ///
    /// Each element is an attribute reference, its new value, and the reasons
    /// for inclusion the update raised, as `on_value_updated` takes them. A
    /// reference given more than once counts once, with its last value and the
    /// reasons of all its elements. Every URCB and every BRCB watching any of
    /// the references takes all of them together: a URCB adds them to one
    /// pending report, a BRCB with no buffer time buffers one entry holding all
    /// of them, and a BRCB with a buffer time adds them to its open window.
    /// When a member of the batch is already part of a control block's pending
    /// report or open window, that report or window is closed first, once, so
    /// it keeps only the values from before the batch and the batch stays
    /// whole. Each control block keeps only the reasons its TrgOps enable.
    pub fn on_values_updated(
        &self,
        updates: &[(DataAttributeRef, MmsValue, InclusionFlag)],
        now_ms: u64,
    ) {
        let updates = merge_updates(updates);
        let mut to_drop: Vec<ConnectionId> = Vec::new();
        for (rc_arc, members) in group_by_watcher(&updates, &self.watch_map) {
            if let Some(c) = self.trigger_urcb_batch(&rc_arc, &updates, &members, now_ms) {
                to_drop.push(c);
            }
        }
        for (brcb_arc, members) in group_by_watcher(&updates, &self.brcb_watch_map) {
            self.trigger_brcb_batch(&brcb_arc, &updates, &members, now_ms);
        }
        for c in to_drop {
            self.on_connection_dropped(c);
        }
    }

    /// Adds the batch members `members` of `updates` to one URCB; returns a
    /// connection to drop when sending its earlier pending report failed.
    fn trigger_urcb_batch(
        &self,
        rc_arc: &Arc<Mutex<ReportControl>>,
        updates: &[(DataAttributeRef, MmsValue, InclusionFlag)],
        members: &[usize],
        now_ms: u64,
    ) -> Option<ConnectionId> {
        let Ok(rc_guard) = rc_arc.lock() else {
            tracing::warn!("report control mutex poisoned, skipping a batch of updates");
            return None;
        };
        let Ok(mut state) = rc_guard.state.lock() else {
            tracing::warn!(mms_path = %rc_guard.mms_path, "rcb state mutex poisoned, skipping a batch of updates");
            return None;
        };
        if !state.rpt_ena {
            return None;
        }
        let mut slots: Vec<(usize, InclusionFlag, &MmsValue)> = Vec::new();
        for &u in members {
            let (attr_ref, value, flag) = &updates[u];
            let flag = enabled_triggers(*flag, state.trg_ops);
            if !flag.has_trigger() {
                rc_guard
                    .metrics
                    .skipped_trgops
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let idx = state
                .dataset
                .as_ref()
                .and_then(|ds| ds.entries.iter().position(|e| &e.attr_ref == attr_ref));
            if let Some(idx) = idx {
                slots.push((idx, flag, value));
            }
        }
        if slots.is_empty() {
            return None;
        }

        // A batch member already in the pending report closes that report
        // first, so the report keeps the values from before the batch.
        let mut dropped = None;
        let retriggered = state.pending.as_ref().is_some_and(|p| {
            slots
                .iter()
                .any(|(idx, _, _)| p.inclusion_flags.get(*idx).is_some_and(|f| f.has_trigger()))
        });
        if let (true, Some(conn_id)) = (retriggered, state.client_conn_id) {
            if let Some(pending) = state.pending.take() {
                state.triggered = false;
                state.report_due = None;
                rc_guard
                    .metrics
                    .coalesced_buftm
                    .fetch_add(1, Ordering::Relaxed);
                // flush_pending takes the state lock itself.
                drop(state);
                dropped = self.flush_pending(&rc_guard, conn_id, pending, now_ms);
                state = match rc_guard.state.lock() {
                    Ok(s) => s,
                    Err(_) => {
                        tracing::warn!(mms_path = %rc_guard.mms_path, "rcb state mutex poisoned, skipping a batch of updates");
                        return dropped;
                    }
                };
                if !state.rpt_ena {
                    return dropped;
                }
            }
        }

        let ds_len = state.dataset.as_ref().map(|d| d.len()).unwrap_or(0);
        let pending = state
            .pending
            .get_or_insert_with(|| PendingReport::new_empty(ds_len, now_ms));
        for (idx, flag, value) in slots {
            if let Some(f) = pending.inclusion_flags.get_mut(idx) {
                *f = flag;
            }
            if let Some(slot) = pending.snapshot.get_mut(idx) {
                *slot = Some(value.clone());
            }
        }
        if !state.triggered {
            state.triggered = true;
            let buf_tm = Duration::from_millis(state.buf_tm_ms as u64);
            state.report_due = Some(Instant::now() + buf_tm);
            if let Some(ref mut p) = state.pending {
                p.time_of_entry_ms = now_ms;
            }
        }
        dropped
    }

    /// Adds the batch members `members` of `updates` to one BRCB: one entry
    /// with no buffer time, the open window otherwise.
    fn trigger_brcb_batch(
        &self,
        brcb_arc: &Arc<BufferedReportControl>,
        updates: &[(DataAttributeRef, MmsValue, InclusionFlag)],
        members: &[usize],
        now_ms: u64,
    ) {
        let mms_path = &brcb_arc.mms_path;
        let (is_buffering, buf_tm_ms, trg_ops) = {
            let Ok(state) = brcb_arc.state.lock() else {
                tracing::warn!(mms_path = %mms_path, "brcb state mutex poisoned, skipping a batch of updates");
                return;
            };
            (state.is_buffering, state.buf_tm_ms, state.trg_ops)
        };
        // A BRCB with no valid data set does not buffer, so it takes no triggers.
        if !is_buffering {
            return;
        }
        let Some(ds) = self.brcb_datasets.get(mms_path) else {
            return;
        };
        let slots: Vec<(usize, InclusionFlag, &MmsValue)> = members
            .iter()
            .filter_map(|&u| {
                let (attr_ref, value, flag) = &updates[u];
                let flag = enabled_triggers(*flag, trg_ops);
                if !flag.has_trigger() {
                    return None;
                }
                let idx = ds.entries.iter().position(|e| &e.attr_ref == attr_ref)?;
                Some((idx, flag, value))
            })
            .collect();
        if slots.is_empty() {
            return;
        }
        let fill = |snap: &mut EnqueuedSnapshot| {
            for (idx, flag, value) in &slots {
                if let Some(slot) = snap.inclusion_flags.get_mut(*idx) {
                    *slot = *flag;
                }
                if let Some(slot) = snap.values.get_mut(*idx) {
                    *slot = Some((*value).clone());
                }
            }
        };

        if buf_tm_ms == 0 {
            let mut snap = EnqueuedSnapshot::new(ds.len());
            fill(&mut snap);
            if let Err(e) = brcb_arc.enqueue_entry_with_snapshot(now_ms, false, false, snap) {
                tracing::warn!(
                    mms_path = %mms_path,
                    error = ?e,
                    "brcb enqueue of a batch of updates failed"
                );
            }
            return;
        }

        let completed = {
            let Ok(mut pending) = self.brcb_buftm_pending.lock() else {
                tracing::warn!(mms_path = %mms_path, "brcb buffer-time pending mutex poisoned");
                return;
            };
            // A batch member already in the open window closes it first, so the
            // window keeps the values from before the batch.
            let retriggered = pending.get(mms_path).is_some_and(|p| {
                slots.iter().any(|(idx, _, _)| {
                    p.snapshot
                        .inclusion_flags
                        .get(*idx)
                        .is_some_and(|f| f.has_trigger())
                })
            });
            let completed = if retriggered {
                pending.remove(mms_path)
            } else {
                None
            };
            let entry = pending
                .entry(mms_path.clone())
                .or_insert_with(|| BrcbBufTmPending {
                    first_trigger_ms: now_ms,
                    due_at: Instant::now() + Duration::from_millis(buf_tm_ms as u64),
                    snapshot: EnqueuedSnapshot::new(ds.len()),
                });
            fill(&mut entry.snapshot);
            completed
        };
        if let Some(p) = completed {
            if let Err(e) =
                brcb_arc.enqueue_entry_with_snapshot(p.first_trigger_ms, false, false, p.snapshot)
            {
                tracing::warn!(
                    mms_path = %mms_path,
                    error = ?e,
                    "brcb buffer-time enqueue failed"
                );
            }
        }
    }

    /// Raises one trigger on one buffered report control block: the per-block
    /// half of `on_brcb_value_updated`, which describes the steps.
    fn trigger_brcb(
        &self,
        brcb_arc: &Arc<BufferedReportControl>,
        attr_ref: &DataAttributeRef,
        new_value: &MmsValue,
        flag: InclusionFlag,
        now_ms: u64,
    ) {
        // Copy the fields needed, then release the state lock.
        let (is_buffering, buf_tm_ms, trg_ops, mms_path, ds_len) = {
            let Ok(state) = brcb_arc.state.lock() else {
                tracing::warn!(attr_ref = %attr_ref, "brcb state mutex poisoned, skipping trigger");
                return;
            };
            let mms_path = brcb_arc.mms_path.clone();
            let ds = match self.brcb_datasets.get(&mms_path) {
                Some(ds) => ds,
                None => return,
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
            return;
        }
        let flag = enabled_triggers(flag, trg_ops);
        if !flag.has_trigger() {
            tracing::trace!(
                mms_path = %mms_path,
                attr_ref = %attr_ref,
                "brcb trigger skipped: trgops does not cover this trigger class"
            );
            return;
        }

        let idx = match self
            .brcb_datasets
            .get(&mms_path)
            .and_then(|ds| ds.entries.iter().position(|e| &e.attr_ref == attr_ref))
        {
            Some(i) => i,
            None => return,
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
            return;
        }

        // Buffer time set: accumulate until tick finds the window expired.
        let completed = {
            let Ok(mut pending) = self.brcb_buftm_pending.lock() else {
                tracing::warn!(mms_path = %mms_path, "brcb buffer-time pending mutex poisoned");
                return;
            };
            // A member that triggers again inside the window closes it: the
            // accumulated entry is buffered at once and the new trigger opens
            // the next window, per the BufTm rules of IEC 61850-7-2.
            let retriggered = pending.get(&mms_path).is_some_and(|p| {
                p.snapshot
                    .inclusion_flags
                    .get(idx)
                    .is_some_and(|f| f.has_trigger())
            });
            let completed = if retriggered {
                pending.remove(&mms_path)
            } else {
                None
            };
            let entry = pending
                .entry(mms_path.clone())
                .or_insert_with(|| BrcbBufTmPending {
                    first_trigger_ms: now_ms,
                    due_at: Instant::now() + Duration::from_millis(buf_tm_ms as u64),
                    snapshot: EnqueuedSnapshot::new(ds_len),
                });
            if let Some(slot) = entry.snapshot.inclusion_flags.get_mut(idx) {
                *slot = flag;
            }
            if let Some(slot) = entry.snapshot.values.get_mut(idx) {
                *slot = Some(new_value.clone());
            }
            completed
        };
        if let Some(p) = completed {
            tracing::debug!(
                mms_path = %mms_path,
                attr_ref = %attr_ref,
                "buffer-time bypass: member retriggered inside the buffer window, buffering the entry now"
            );
            if let Err(e) =
                brcb_arc.enqueue_entry_with_snapshot(p.first_trigger_ms, false, false, p.snapshot)
            {
                tracing::warn!(
                    mms_path = %mms_path,
                    error = ?e,
                    "brcb buffer-time enqueue failed"
                );
            }
        }
    }
}

/// Merges the elements of a batch that name the same reference: the last
/// value and the reasons of all of them, in the order references first appear.
fn merge_updates(
    updates: &[(DataAttributeRef, MmsValue, InclusionFlag)],
) -> Vec<(DataAttributeRef, MmsValue, InclusionFlag)> {
    let mut merged: Vec<(DataAttributeRef, MmsValue, InclusionFlag)> =
        Vec::with_capacity(updates.len());
    let mut index: HashMap<&str, usize> = HashMap::new();
    for (attr_ref, value, flag) in updates {
        match index.get(attr_ref.as_str()) {
            Some(&i) => {
                merged[i].1 = value.clone();
                merged[i].2 = merged[i].2.union(*flag);
            }
            None => {
                index.insert(attr_ref.as_str(), merged.len());
                merged.push((attr_ref.clone(), value.clone(), *flag));
            }
        }
    }
    merged
}

/// Groups the positions in `updates` by the control block watching them, in
/// the order the control blocks are first met.
fn group_by_watcher<T>(
    updates: &[(DataAttributeRef, MmsValue, InclusionFlag)],
    watch_map: &HashMap<DataAttributeRef, Vec<Weak<T>>>,
) -> Vec<(Arc<T>, Vec<usize>)> {
    let mut groups: Vec<(Arc<T>, Vec<usize>)> = Vec::new();
    let mut index: HashMap<*const T, usize> = HashMap::new();
    for (u, (attr_ref, _, _)) in updates.iter().enumerate() {
        let Some(watchers) = watch_map.get(attr_ref) else {
            continue;
        };
        for weak in watchers {
            let Some(watcher) = weak.upgrade() else {
                continue;
            };
            match index.get(&Arc::as_ptr(&watcher)) {
                Some(&g) => {
                    if !groups[g].1.contains(&u) {
                        groups[g].1.push(u);
                    }
                }
                None => {
                    index.insert(Arc::as_ptr(&watcher), groups.len());
                    groups.push((watcher, vec![u]));
                }
            }
        }
    }
    groups
}

/// Returns the reasons of `flag` that `trg_ops` enable: data-change for
/// `dchg`, quality-change for `qchg`, and data-update for `dupd`.
fn enabled_triggers(flag: InclusionFlag, trg_ops: TriggerOptions) -> InclusionFlag {
    let mut out = InclusionFlag::NONE;
    for (reason, trigger) in [
        (InclusionFlag::VALUE_CHANGED, TriggerOptions::DATA_CHANGED),
        (
            InclusionFlag::QUALITY_CHANGED,
            TriggerOptions::QUALITY_CHANGED,
        ),
        (InclusionFlag::VALUE_UPDATE, TriggerOptions::DATA_UPDATE),
    ] {
        if flag.contains(reason) && trg_ops.contains(trigger) {
            out = out.union(reason);
        }
    }
    out
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

/// Returns the data set registry key `(domain, list_name)` a DatSet value names.
///
/// A value of the form `<domain>/<LN>$<name>` carries its domain; a value without
/// one names a data set in the domain of the control block at `rcb_mms_path`. An
/// empty value names no data set.
fn dataset_key(rcb_mms_path: &str, dat_set: &str) -> Option<(String, String)> {
    if dat_set.is_empty() {
        return None;
    }
    match dat_set.split_once('/') {
        Some((domain, item)) => Some((domain.to_string(), item.to_string())),
        None => rcb_mms_path
            .split_once('/')
            .map(|(domain, _)| (domain.to_string(), dat_set.to_string())),
    }
}

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
        let mut engine =
            ReportingEngine::new_with_channel_sink(ch_sink.clone(), Default::default());

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
        let mut engine =
            ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>, Default::default());

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

    // ── WouldBlock drops the report and keeps the control block ───────────────

    /// Counts the warning and error events emitted on the current thread.
    #[derive(Clone, Default)]
    struct LogCount {
        warn: Arc<std::sync::atomic::AtomicUsize>,
        error: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl tracing::Subscriber for LogCount {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let counter = match *event.metadata().level() {
                tracing::Level::WARN => &self.warn,
                tracing::Level::ERROR => &self.error,
                _ => return,
            };
            counter.fetch_add(1, Ordering::Relaxed);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    impl LogCount {
        fn warns(&self) -> usize {
            self.warn.load(Ordering::Relaxed)
        }
        fn errors(&self) -> usize {
            self.error.load(Ordering::Relaxed)
        }
    }

    /// Stages a due data-change report on the single member of a URCB.
    fn stage_due_report(rc_arc: &Arc<Mutex<ReportControl>>, now_ms: u64) {
        let rc_l = rc_arc.lock().unwrap();
        let mut state = rc_l.state.lock().unwrap();
        let ds_len = state.dataset.as_ref().map(|d| d.len()).unwrap_or(1);
        let mut pending = PendingReport::new_empty(ds_len, now_ms);
        pending.inclusion_flags[0] = InclusionFlag::VALUE_CHANGED;
        pending.snapshot[0] = Some(MmsValue::Boolean(true));
        state.pending = Some(pending);
        state.triggered = true;
        state.report_due = Some(Instant::now() - Duration::from_millis(10));
    }

    #[test]
    fn full_report_channel_drops_reports_and_keeps_the_urcb_enabled() {
        use crate::reporting::sink::{ChannelReportSink, REPORT_CHANNEL_CAP};

        let ch_sink = Arc::new(ChannelReportSink::new());
        let mut engine =
            ReportingEngine::new_with_channel_sink(ch_sink.clone(), Default::default());
        let (rc, ds) = make_rcb_and_ds(
            "urcb01",
            "IED1LD0/GGIO1$ST$Ind1$stVal",
            TriggerOptions::DATA_CHANGED,
        );
        let path = rc.mms_path.clone();
        engine.register_rcb(rc, ds).unwrap();
        let rc_arc = engine.get_rcb(&path).unwrap();
        enable_rcb(&rc_arc, 7);

        // A receiver that reads nothing until the channel is full.
        let (tx, mut rx) = ChannelReportSink::create_channel();
        ch_sink.register(7, tx);
        let filler = bytes::Bytes::from_static(b"\xa3\x00");
        for _ in 0..REPORT_CHANNEL_CAP {
            ch_sink.try_send_pdu(7, filler.clone());
        }

        let logs = LogCount::default();
        tracing::subscriber::with_default(logs.clone(), || {
            for i in 0..40 {
                stage_due_report(&rc_arc, 1_000_000 + i);
                engine.tick();
            }
        });
        {
            let rc_l = rc_arc.lock().unwrap();
            assert_eq!(rc_l.metrics_snapshot().dropped_socket_full, 40);
            let state = rc_l.state.lock().unwrap();
            assert!(state.rpt_ena, "RptEna stays TRUE");
            assert!(state.resv, "Resv stays TRUE");
            assert_eq!(state.client_conn_id, Some(7));
        }
        assert_eq!(logs.warns(), 1, "one warning for the whole run of drops");

        // The client reads again: the next report is delivered.
        while rx.try_recv().is_ok() {}
        tracing::subscriber::with_default(logs.clone(), || {
            stage_due_report(&rc_arc, 2_000_000);
            engine.tick();
        });
        let delivered = rx.try_recv().expect("the next report is delivered");
        assert_eq!(delivered[0], 0xa3);
        assert_eq!(logs.warns(), 2, "one more warning when delivery resumes");
        assert_eq!(logs.errors(), 0);
        let rc_l = rc_arc.lock().unwrap();
        assert_eq!(rc_l.metrics_snapshot().sent, 1);
        assert!(rc_l.state.lock().unwrap().rpt_ena);
    }

    /// Control: a receiver that is gone still releases the URCB.
    #[test]
    fn dropped_report_receiver_releases_the_urcb() {
        use crate::reporting::sink::ChannelReportSink;

        let ch_sink = Arc::new(ChannelReportSink::new());
        let mut engine =
            ReportingEngine::new_with_channel_sink(ch_sink.clone(), Default::default());
        let (rc, ds) = make_rcb_and_ds(
            "urcb01",
            "IED1LD0/GGIO1$ST$Ind1$stVal",
            TriggerOptions::DATA_CHANGED,
        );
        let path = rc.mms_path.clone();
        engine.register_rcb(rc, ds).unwrap();
        let rc_arc = engine.get_rcb(&path).unwrap();
        enable_rcb(&rc_arc, 7);
        let (tx, rx) = ChannelReportSink::create_channel();
        ch_sink.register(7, tx);
        drop(rx);
        stage_due_report(&rc_arc, 1_000_000);
        engine.tick();
        let rc_l = rc_arc.lock().unwrap();
        let state = rc_l.state.lock().unwrap();
        assert!(!state.rpt_ena);
        assert!(!state.resv);
    }

    #[test]
    fn full_report_channel_keeps_brcb_entries_and_logs_once() {
        use crate::reporting::brcb::{Brcb, BufferedReportControl, TransmitAnchor};
        use crate::reporting::sink::{ChannelReportSink, REPORT_CHANNEL_CAP};

        let ch_sink = Arc::new(ChannelReportSink::new());
        let mut eng = ReportingEngine::new_with_channel_sink(ch_sink.clone(), Default::default());
        let attr = "IED1LD0/GGIO1$ST$Ind1$stVal";
        let brcb = Brcb::new("brcb01", "GGIO1$ds1")
            .with_trg_ops(TriggerOptions::DATA_CHANGED)
            .with_opt_flds(OptFlds::SEQ_NUM);
        let path = "IED1LD0/GGIO1$BR$brcb01";
        eng.register_brcb_with_dataset(
            BufferedReportControl::new(path, brcb),
            make_ds(vec![(attr, MmsValue::Integer(0))]),
        )
        .unwrap();
        let brcb_arc = eng.get_brcb(path).unwrap();
        {
            let mut s = brcb_arc.state.lock().unwrap();
            s.rpt_ena = true;
            s.client_conn_id = Some(5);
            s.transmit_anchor = TransmitAnchor::FromHead;
        }
        let (tx, mut rx) = ChannelReportSink::create_channel();
        ch_sink.register(5, tx);
        let filler = bytes::Bytes::from_static(b"\xa3\x00");
        for _ in 0..REPORT_CHANNEL_CAP {
            ch_sink.try_send_pdu(5, filler.clone());
        }
        eng.on_brcb_value_updated(
            &attr.to_string(),
            MmsValue::Integer(1),
            InclusionFlag::VALUE_CHANGED,
            1_000,
        );

        let logs = LogCount::default();
        tracing::subscriber::with_default(logs.clone(), || {
            for _ in 0..40 {
                assert_eq!(eng.flush_brcb_pending(&brcb_arc, 5), 0);
            }
        });
        assert_eq!(logs.warns(), 1, "one warning while the channel stays full");
        assert!(brcb_arc.state.lock().unwrap().rpt_ena);

        while rx.try_recv().is_ok() {}
        assert_eq!(eng.flush_brcb_pending(&brcb_arc, 5), 1);
        assert!(rx.try_recv().is_ok(), "the buffered entry is delivered");
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
    fn on_connection_dropped_disables_brcb_and_holds_its_reservation() {
        use crate::reporting::brcb::ResvTmsState;
        use std::num::NonZeroU16;
        let mut eng = ReportingEngine::new_null();
        eng.register_brcb(make_brcb("brcb01")).unwrap();
        eng.register_brcb(make_brcb("brcb02")).unwrap();
        let dropped = eng.get_brcb("IED1LD0/GGIO1$BR$brcb01").unwrap();
        let kept = eng.get_brcb("IED1LD0/GGIO1$BR$brcb02").unwrap();
        let (entry_id, _) = dropped
            .enqueue_entry(1_000, false, false, Bytes::from_static(b"a"))
            .unwrap();
        for (brcb, conn_id) in [(&dropped, 5), (&kept, 6)] {
            let mut s = brcb.state.lock().unwrap();
            s.rpt_ena = true;
            s.gi = true;
            s.client_conn_id = Some(conn_id);
            s.resv_tms = ResvTmsState::WithTimeout(NonZeroU16::new(30).unwrap());
            s.reservation_timeout = None;
            s.transmit_anchor = TransmitAnchor::AfterEntryId(entry_id);
        }

        let before = Instant::now();
        eng.on_connection_dropped(5);
        let after = Instant::now();
        let resv = Duration::from_secs(30);

        {
            let s = dropped.state.lock().unwrap();
            assert!(!s.rpt_ena);
            assert!(!s.gi);
            assert_eq!(s.client_conn_id, None);
            assert_eq!(
                s.resv_tms,
                ResvTmsState::WithTimeout(NonZeroU16::new(30).unwrap())
            );
            let restarted = s.reservation_timeout.unwrap();
            assert!(before + resv <= restarted && restarted <= after + resv);
            assert_eq!(s.transmit_anchor, TransmitAnchor::AfterEntryId(entry_id));
        }
        assert_eq!(dropped.lock_buffer().unwrap().len(), 1);
        let s = kept.state.lock().unwrap();
        assert!(s.rpt_ena);
        assert!(s.gi);
        assert_eq!(s.client_conn_id, Some(6));
        assert_eq!(s.reservation_timeout, None);
    }

    #[test]
    fn on_connection_dropped_forgets_the_owner_of_an_unreserved_brcb() {
        let mut eng = ReportingEngine::new_null();
        eng.register_brcb(make_brcb("brcb01")).unwrap();
        let brcb = eng.get_brcb("IED1LD0/GGIO1$BR$brcb01").unwrap();
        {
            let mut s = brcb.state.lock().unwrap();
            s.rpt_ena = true;
            s.client_conn_id = Some(5);
            s.owner = Some("10.0.0.1".parse().unwrap());
        }
        eng.on_connection_dropped(5);
        let s = brcb.state.lock().unwrap();
        assert_eq!(s.owner, None);
        assert_eq!(s.reservation_timeout, None);
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
        let mut eng = ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>, Default::default());

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

        let n = eng.flush_brcb_pending(&brcb_arc, 42);
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
        let mut eng = ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>, Default::default());

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

        let n = eng.flush_brcb_pending(&brcb_arc, 7);
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
        let mut eng = ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>, Default::default());

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
        eng.flush_brcb_pending(&brcb_arc, 1);

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
        let mut eng = ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>, Default::default());

        let brcb = Brcb::new("brcb01", "GGIO1$ds1").with_buffer_capacity(8);
        let brc = BufferedReportControl::new("IED1LD0/GGIO1$BR$brcb01", brcb);
        eng.register_brcb(brc).unwrap();
        let path = "IED1LD0/GGIO1$BR$brcb01";
        let brcb_arc = eng.get_brcb(path).unwrap();
        {
            let mut s = brcb_arc.state.lock().unwrap();
            s.transmit_anchor = TransmitAnchor::FromHead;
        }
        let n = eng.flush_brcb_pending(&brcb_arc, 1);
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
        let mut eng = ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>, Default::default());

        let brcb = Brcb::new("brcb01", "GGIO1$ds1").with_buffer_capacity(8);
        let brc = BufferedReportControl::new("IED1LD0/GGIO1$BR$brcb01", brcb);
        eng.register_brcb(brc).unwrap();
        let path = "IED1LD0/GGIO1$BR$brcb01";
        let brcb_arc = eng.get_brcb(path).unwrap();
        brcb_arc
            .enqueue_entry(1000, false, false, bytes::Bytes::from_static(b"e"))
            .unwrap();
        let n = eng.flush_brcb_pending(&brcb_arc, 1);
        assert_eq!(n, 0, "a none anchor must not send any pdu");
        assert!(sink.pdus.lock().unwrap().is_empty());
    }

    /// A BRCB the client resynchronized on its newest entry, which is buffered.
    fn brcb_resynced_on_the_newest_entry() -> (
        ReportingEngine,
        Arc<CollectReportSink>,
        Arc<crate::reporting::brcb::BufferedReportControl>,
    ) {
        use crate::reporting::brcb::{Brcb, BufferedReportControl, TransmitAnchor};
        let sink = Arc::new(CollectReportSink::default());
        let mut eng = ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>, Default::default());
        let brcb = Brcb::new("brcb01", "GGIO1$ds1").with_buffer_capacity(8);
        let brc = BufferedReportControl::new("IED1LD0/GGIO1$BR$brcb01", brcb);
        eng.register_brcb(brc).unwrap();
        let brcb_arc = eng.get_brcb("IED1LD0/GGIO1$BR$brcb01").unwrap();
        let (newest, _) = brcb_arc
            .enqueue_entry(1000, false, false, bytes::Bytes::from_static(b"e"))
            .unwrap();
        brcb_arc.apply_entry_id_write(newest).unwrap().unwrap();
        {
            let mut s = brcb_arc.state.lock().unwrap();
            assert_eq!(s.transmit_anchor, TransmitAnchor::WaitingForNext);
            s.rpt_ena = true;
            s.client_conn_id = Some(1);
        }
        (eng, sink, brcb_arc)
    }

    #[test]
    fn brcb_waiting_for_the_next_entry_logs_nothing() {
        let (eng, sink, brcb_arc) = brcb_resynced_on_the_newest_entry();
        let logs = LogCount::default();
        tracing::subscriber::with_default(logs.clone(), || {
            for _ in 0..200 {
                assert_eq!(eng.flush_brcb_pending(&brcb_arc, 1), 0);
            }
        });
        assert_eq!(logs.errors(), 0, "waiting for the next entry is no error");
        assert_eq!(logs.warns(), 0);
        assert!(sink.pdus.lock().unwrap().is_empty());

        // The next entry is sent.
        brcb_arc
            .enqueue_entry(2000, false, false, bytes::Bytes::from_static(b"f"))
            .unwrap();
        assert_eq!(eng.flush_brcb_pending(&brcb_arc, 1), 1);
        assert_eq!(sink.pdus.lock().unwrap().len(), 1);
    }

    /// A newer entry buffered without `on_enqueue` resolving the anchor is
    /// logged once and sent.
    #[test]
    fn brcb_anchor_left_waiting_behind_a_newer_entry_is_resolved_once() {
        use crate::reporting::brcb::TransmitAnchor;
        let (eng, sink, brcb_arc) = brcb_resynced_on_the_newest_entry();
        brcb_arc
            .enqueue_entry(2000, false, false, bytes::Bytes::from_static(b"f"))
            .unwrap();
        // Undo what on_enqueue did, standing in for a path that skipped it.
        brcb_arc.state.lock().unwrap().transmit_anchor = TransmitAnchor::WaitingForNext;
        let logs = LogCount::default();
        tracing::subscriber::with_default(logs.clone(), || {
            assert_eq!(eng.flush_brcb_pending(&brcb_arc, 1), 1);
            for _ in 0..50 {
                assert_eq!(eng.flush_brcb_pending(&brcb_arc, 1), 0);
            }
        });
        assert_eq!(logs.errors(), 1, "logged once, when the anchor is resolved");
        assert_eq!(sink.pdus.lock().unwrap().len(), 1, "only the newer entry");
    }

    #[test]
    fn flush_brcb_pending_clears_overflow_after_send() {
        use crate::reporting::brcb::{Brcb, BufferedReportControl, TransmitAnchor};
        let sink = Arc::new(CollectReportSink::default());
        let mut eng = ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>, Default::default());
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
        eng.flush_brcb_pending(&brcb_arc, 1);
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
        let mut eng = ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>, Default::default());

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
        let sent = eng.flush_brcb_pending(&brcb_arc, 7);
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

    // ── Buffer time, reasons, and TimeOfEntry on the send path ────────────────

    /// Returns whether `pdu` contains `needle`.
    fn contains(pdu: &[u8], needle: &[u8]) -> bool {
        pdu.windows(needle.len()).any(|w| w == needle)
    }

    /// An INTEGER value as the report encoder writes it.
    const INT_2: [u8; 3] = [0x85, 0x01, 0x02];
    const INT_1: [u8; 3] = [0x85, 0x01, 0x01];

    #[test]
    fn urcb_retrigger_inside_buf_tm_sends_the_first_value_at_once() {
        let sink = Arc::new(CollectReportSink::default());
        let mut engine =
            ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>, Default::default());
        let attr = "IED1LD0/GGIO1$ST$Ind1$stVal".to_string();
        let (rc, ds) = make_rcb_and_ds("urcb01", &attr, TriggerOptions::DATA_CHANGED);
        let path = rc.mms_path.clone();
        engine.register_rcb(rc, ds).unwrap();
        let rc_arc = engine.get_rcb(&path).unwrap();
        enable_rcb(&rc_arc, 7);
        rc_arc.lock().unwrap().state.lock().unwrap().buf_tm_ms = 10_000;

        let flag = InclusionFlag::VALUE_CHANGED;
        engine.on_value_updated(&attr, MmsValue::Integer(2), flag, 1_000);
        assert!(
            sink.pdus.lock().unwrap().is_empty(),
            "the first trigger waits"
        );
        engine.on_value_updated(&attr, MmsValue::Integer(1), flag, 1_010);
        {
            let pdus = sink.pdus.lock().unwrap();
            assert_eq!(pdus.len(), 1, "the retrigger sends the pending report");
            assert!(contains(&pdus[0].1, &INT_2), "with the first value");
            assert!(!contains(&pdus[0].1, &INT_1));
        }

        // The second value waits for its own buffer time.
        engine.tick_at(Instant::now(), 1_020);
        assert_eq!(sink.pdus.lock().unwrap().len(), 1);
        engine.tick_at(Instant::now() + Duration::from_secs(11), 11_010);
        let pdus = sink.pdus.lock().unwrap();
        assert_eq!(
            pdus.len(),
            2,
            "the second value follows after its buffer time"
        );
        assert!(contains(&pdus[1].1, &INT_1));
    }

    #[test]
    fn urcb_trigger_of_another_member_inside_buf_tm_is_merged() {
        let sink = Arc::new(CollectReportSink::default());
        let mut engine =
            ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>, Default::default());
        let a = "IED1LD0/GGIO1$ST$Ind1$stVal".to_string();
        let b = "IED1LD0/GGIO1$ST$Ind2$stVal".to_string();
        let rcb = Rcb::new("urcb01", "GGIO1$ds1")
            .with_trg_ops(TriggerOptions::DATA_CHANGED)
            .with_opt_flds(OptFlds::SEQ_NUM)
            .with_buf_tm_ms(10_000);
        let ds = make_ds(vec![
            (a.as_str(), MmsValue::Integer(0)),
            (b.as_str(), MmsValue::Integer(0)),
        ]);
        engine
            .register_rcb(ReportControl::new("IED1LD0/GGIO1$RP$urcb01", rcb), ds)
            .unwrap();
        let rc_arc = engine.get_rcb("IED1LD0/GGIO1$RP$urcb01").unwrap();
        enable_rcb(&rc_arc, 7);

        let flag = InclusionFlag::VALUE_CHANGED;
        engine.on_value_updated(&a, MmsValue::Integer(2), flag, 1_000);
        engine.on_value_updated(&b, MmsValue::Integer(1), flag, 1_010);
        assert!(sink.pdus.lock().unwrap().is_empty());
        engine.tick_at(Instant::now() + Duration::from_secs(11), 11_000);
        let pdus = sink.pdus.lock().unwrap();
        assert_eq!(pdus.len(), 1, "one report for both members");
        assert!(contains(&pdus[0].1, &INT_2) && contains(&pdus[0].1, &INT_1));
    }

    /// A BRCB over one INTEGER member, with the given buffer time and options.
    fn brcb_engine(
        buf_tm_ms: u32,
        trg_ops: TriggerOptions,
        opt_flds: OptFlds,
    ) -> (
        ReportingEngine,
        Arc<CollectReportSink>,
        Arc<crate::reporting::brcb::BufferedReportControl>,
        String,
    ) {
        use crate::reporting::brcb::{Brcb, BufferedReportControl, TransmitAnchor};
        let sink = Arc::new(CollectReportSink::default());
        let mut eng = ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>, Default::default());
        let attr = "IED1LD0/GGIO1$ST$Ind1$stVal".to_string();
        let ds = make_ds(vec![(attr.as_str(), MmsValue::Integer(0))]);
        let brcb = Brcb::new("brcb01", "GGIO1$ds1")
            .with_trg_ops(trg_ops)
            .with_opt_flds(opt_flds)
            .with_buf_tm_ms(buf_tm_ms);
        let path = "IED1LD0/GGIO1$BR$brcb01";
        eng.register_brcb_with_dataset(BufferedReportControl::new(path, brcb), ds)
            .unwrap();
        let brcb_arc = eng.get_brcb(path).unwrap();
        {
            let mut s = brcb_arc.state.lock().unwrap();
            s.rpt_ena = true;
            s.client_conn_id = Some(5);
            s.transmit_anchor = TransmitAnchor::FromHead;
        }
        (eng, sink, brcb_arc, attr)
    }

    #[test]
    fn brcb_retrigger_inside_buf_tm_buffers_the_first_value_at_once() {
        let (eng, _sink, brcb, attr) =
            brcb_engine(10_000, TriggerOptions::DATA_CHANGED, OptFlds::SEQ_NUM);
        let flag = InclusionFlag::VALUE_CHANGED;
        eng.on_brcb_value_updated(&attr, MmsValue::Integer(2), flag, 1_000);
        assert_eq!(
            brcb.lock_buffer().unwrap().len(),
            0,
            "the first trigger waits"
        );
        eng.on_brcb_value_updated(&attr, MmsValue::Integer(1), flag, 1_010);
        {
            let entries = brcb.lock_buffer().unwrap().iter_entries();
            assert_eq!(entries.len(), 1, "the retrigger buffers the open window");
            let snap = entries[0].snapshot.as_ref().expect("snapshot");
            assert_eq!(snap.values[0], Some(MmsValue::Integer(2)));
            assert_eq!(entries[0].time_of_entry_ms, 1_000);
        }
        eng.tick_brcb(Instant::now(), 1_020);
        assert_eq!(brcb.lock_buffer().unwrap().len(), 1);
        eng.tick_brcb(Instant::now() + Duration::from_secs(11), 11_010);
        let entries = brcb.lock_buffer().unwrap().iter_entries();
        assert_eq!(entries.len(), 2, "the second value gets its own entry");
        let snap = entries[1].snapshot.as_ref().expect("snapshot");
        assert_eq!(snap.values[0], Some(MmsValue::Integer(1)));
        assert_eq!(entries[1].time_of_entry_ms, 1_010);
    }

    /// The reason-for-inclusion BIT_STRING(6) of one member.
    fn reason(bits: u8) -> [u8; 4] {
        [0x84, 0x02, 0x02, bits]
    }

    #[test]
    fn brcb_gi_report_reason_is_general_interrogation_only() {
        let (eng, sink, brcb, _attr) = brcb_engine(
            0,
            TriggerOptions::DATA_CHANGED | TriggerOptions::GI,
            OptFlds::REASON,
        );
        brcb.state.lock().unwrap().gi = true;
        eng.tick_brcb(Instant::now(), 2_000);
        let entries = brcb.lock_buffer().unwrap().iter_entries();
        assert_eq!(entries.len(), 1);
        let snap = entries[0].snapshot.as_ref().expect("snapshot");
        assert!(snap.inclusion_flags.iter().all(|f| !f.has_trigger()));
        let pdus = sink.pdus.lock().unwrap();
        assert_eq!(pdus.len(), 1);
        assert!(contains(&pdus[0].1, &reason(0x04)), "general-interrogation");
        assert!(!contains(&pdus[0].1, &reason(0x44)), "no data-change");
    }

    #[test]
    fn brcb_integrity_report_reason_is_integrity_only() {
        let (eng, sink, brcb, _attr) = brcb_engine(0, TriggerOptions::INTEGRITY, OptFlds::REASON);
        brcb.state.lock().unwrap().intg_pd_ms = 1_000;
        eng.refresh_brcb_integrity_period(&brcb.mms_path);
        eng.tick_brcb(Instant::now() + Duration::from_secs(2), 3_000);
        let pdus = sink.pdus.lock().unwrap();
        assert_eq!(pdus.len(), 1);
        assert!(contains(&pdus[0].1, &reason(0x08)), "integrity");
        assert!(!contains(&pdus[0].1, &reason(0x48)), "no data-change");
    }

    #[test]
    fn brcb_report_time_of_entry_is_the_buffering_time() {
        let (eng, sink, brcb, attr) =
            brcb_engine(0, TriggerOptions::DATA_CHANGED, OptFlds::TIME_STAMP);
        let buffered_at = 1_700_000_000_000u64;
        let sent_at = buffered_at + 3_600_000;
        brcb.state.lock().unwrap().rpt_ena = false;
        eng.on_brcb_value_updated(
            &attr,
            MmsValue::Integer(2),
            InclusionFlag::VALUE_CHANGED,
            buffered_at,
        );
        assert_eq!(eng.flush_brcb_pending(&brcb, 5), 1);
        let pdus = sink.pdus.lock().unwrap();
        let toe = iec61850_mms::binary_time6_from_epoch_ms(buffered_at);
        assert!(
            contains(&pdus[0].1, &toe),
            "TimeOfEntry is the buffering time"
        );
        assert!(!contains(
            &pdus[0].1,
            &iec61850_mms::binary_time6_from_epoch_ms(sent_at)
        ));
        assert_eq!(
            brcb.state.lock().unwrap().last_sent_time_of_entry_ms,
            buffered_at,
            "the same instant TimeofEntry reads back"
        );
    }

    /// A data set of `n` members with long references, so a general
    /// interrogation report over it takes several segments of a small PDU.
    fn wide_ds(n: usize) -> Dataset {
        let tail = "x".repeat(60);
        let mut ds = Dataset::new("ds1");
        for i in 0..n {
            ds.push(make_entry(
                &format!("IED1LD0/GGIO1$ST$Ind{i:03}$stVal_{tail}"),
                MmsValue::Integer(i as i64),
            ));
        }
        ds
    }

    /// Runs one URCB general interrogation for association 3 and returns the
    /// PDUs it produced; `max_pdu` registers the association with that size.
    fn urcb_gi_pdus(max_pdu: Option<usize>) -> Vec<Bytes> {
        let sink = Arc::new(CollectReportSink::default());
        let mut engine =
            ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>, Default::default());
        let rcb = Rcb::new("urcb01", "GGIO1$ds1")
            .with_trg_ops(TriggerOptions::GI)
            .with_opt_flds(OptFlds::SEQ_NUM | OptFlds::DATA_REFERENCE);
        let rc = ReportControl::new("IED1LD0/GGIO1$RP$urcb01", rcb);
        engine.register_rcb(rc, wide_ds(30)).unwrap();
        if let Some(size) = max_pdu {
            engine.register_peer(3, "10.0.0.3".parse().unwrap(), size);
        }
        let rc_arc = engine.get_rcb("IED1LD0/GGIO1$RP$urcb01").unwrap();
        enable_rcb(&rc_arc, 3);
        rc_arc.lock().unwrap().state.lock().unwrap().gi = true;
        engine.tick_at(Instant::now(), 1_000_000);
        let pdus = sink.pdus.lock().unwrap();
        pdus.iter().map(|(_, p)| p.clone()).collect()
    }

    #[test]
    fn urcb_report_is_segmented_at_the_negotiated_pdu_size() {
        let pdus = urcb_gi_pdus(Some(400));
        assert!(pdus.len() >= 3, "{} pdus", pdus.len());
        for pdu in &pdus {
            assert!(pdu.len() <= 400, "a {} byte pdu", pdu.len());
        }
        // The same report fits one PDU for an association that is not
        // registered.
        let whole = urcb_gi_pdus(None);
        assert_eq!(whole.len(), 1);
        assert!(whole[0].len() > 400);
    }

    /// Flushes one BRCB general interrogation entry to association 5 and
    /// returns the PDUs it produced.
    fn brcb_gi_pdus(max_pdu: Option<usize>) -> Vec<Bytes> {
        use crate::reporting::brcb::{Brcb, BufferedReportControl, TransmitAnchor};
        let sink = Arc::new(CollectReportSink::default());
        let mut eng = ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>, Default::default());
        let brcb = Brcb::new("brcb01", "GGIO1$ds1")
            .with_trg_ops(TriggerOptions::GI)
            .with_opt_flds(OptFlds::SEQ_NUM | OptFlds::DATA_REFERENCE | OptFlds::ENTRY_ID);
        let path = "IED1LD0/GGIO1$BR$brcb01";
        eng.register_brcb_with_dataset(BufferedReportControl::new(path, brcb), wide_ds(30))
            .unwrap();
        if let Some(size) = max_pdu {
            eng.register_peer(5, "10.0.0.5".parse().unwrap(), size);
        }
        let brcb_arc = eng.get_brcb(path).unwrap();
        {
            let mut s = brcb_arc.state.lock().unwrap();
            s.rpt_ena = true;
            s.client_conn_id = Some(5);
            s.transmit_anchor = TransmitAnchor::FromHead;
            s.gi = true;
        }
        eng.tick_brcb(Instant::now(), 1_000_000);
        let pdus = sink.pdus.lock().unwrap();
        pdus.iter().map(|(_, p)| p.clone()).collect()
    }

    #[test]
    fn brcb_report_is_segmented_at_the_negotiated_pdu_size() {
        let pdus = brcb_gi_pdus(Some(400));
        assert!(pdus.len() >= 3, "{} pdus", pdus.len());
        for pdu in &pdus {
            assert!(pdu.len() <= 400, "a {} byte pdu", pdu.len());
        }
        // Every segment of the entry carries its EntryID.
        let entry_id = {
            let first = &pdus[0];
            let at = first
                .windows(2)
                .position(|w| w == [0x89, 0x08])
                .expect("EntryID");
            first[at..at + 10].to_vec()
        };
        assert!(pdus.iter().all(|p| contains(p, &entry_id)));
        let whole = brcb_gi_pdus(None);
        assert_eq!(whole.len(), 1);
        assert!(whole[0].len() > 400);
    }

    #[test]
    fn deregistered_association_no_longer_limits_its_reports() {
        let mut engine = ReportingEngine::new_null();
        engine.register_peer(9, "10.0.0.9".parse().unwrap(), 512);
        assert_eq!(engine.max_pdu_size_bytes(9), 512);
        assert_eq!(engine.peer(9), Some("10.0.0.9".parse().unwrap()));
        engine.deregister_peer(9);
        assert_eq!(
            engine.max_pdu_size_bytes(9),
            UNREGISTERED_MAX_PDU_SIZE_BYTES
        );
        assert_eq!(engine.peer(9), None);
    }

    /// A member that triggers again inside the buffer time restarts the buffer
    /// time from the retrigger, not from the first trigger (IEC 61850-7-2
    /// §17.2.2.9).
    #[test]
    fn urcb_retrigger_restarts_the_buffer_time() {
        let sink = Arc::new(CollectReportSink::default());
        let mut engine =
            ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>, Default::default());
        let attr = "IED1LD0/GGIO1$ST$Ind1$stVal".to_string();
        let (rc, ds) = make_rcb_and_ds("urcb01", &attr, TriggerOptions::DATA_CHANGED);
        let path = rc.mms_path.clone();
        engine.register_rcb(rc, ds).unwrap();
        let rc_arc = engine.get_rcb(&path).unwrap();
        enable_rcb(&rc_arc, 4);
        rc_arc.lock().unwrap().state.lock().unwrap().buf_tm_ms = 60_000;

        let flag = InclusionFlag::VALUE_CHANGED;
        engine.on_value_updated(&attr, MmsValue::Boolean(true), flag, 1_000);
        // The buffer time of the first trigger has run out by the time the
        // member triggers again.
        let first_due = Instant::now() - Duration::from_secs(1);
        rc_arc.lock().unwrap().state.lock().unwrap().report_due = Some(first_due);
        engine.on_value_updated(&attr, MmsValue::Boolean(false), flag, 2_000);
        assert_eq!(
            sink.pdus.lock().unwrap().len(),
            1,
            "the first value at once"
        );

        // Due by the first trigger, not by the retrigger: nothing is sent.
        engine.tick_at(Instant::now(), 3_000);
        assert_eq!(
            sink.pdus.lock().unwrap().len(),
            1,
            "the retrigger waits BufTm"
        );
        // A full buffer time after the retrigger, the second value goes out.
        engine.tick_at(Instant::now() + Duration::from_secs(61), 63_000);
        assert_eq!(sink.pdus.lock().unwrap().len(), 2);
    }

    /// A data set whose first member holds a 100-byte string and whose second
    /// holds an integer; only the second fits a 64-byte PDU.
    fn big_and_small_ds() -> (Dataset, String, String) {
        let big = "IED1LD0/GGIO1$ST$Big$stVal".to_string();
        let small = "IED1LD0/GGIO1$ST$Small$stVal".to_string();
        let ds = make_ds(vec![
            (big.as_str(), MmsValue::VisibleString(String::new())),
            (small.as_str(), MmsValue::Integer(0)),
        ]);
        (ds, big, small)
    }

    #[test]
    fn oversized_urcb_report_is_dropped_once_and_the_next_one_is_sent() {
        let sink = Arc::new(CollectReportSink::default());
        let mut engine =
            ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>, Default::default());
        let (ds, big, small) = big_and_small_ds();
        let rcb = Rcb::new("urcb01", "GGIO1$ds1")
            .with_rpt_id("r")
            .with_trg_ops(TriggerOptions::DATA_CHANGED)
            .with_opt_flds(OptFlds::SEQ_NUM);
        engine
            .register_rcb(ReportControl::new("IED1LD0/GGIO1$RP$urcb01", rcb), ds)
            .unwrap();
        engine.register_peer(3, "10.0.0.3".parse().unwrap(), 64);
        let rc_arc = engine.get_rcb("IED1LD0/GGIO1$RP$urcb01").unwrap();
        enable_rcb(&rc_arc, 3);

        let flag = InclusionFlag::VALUE_CHANGED;
        let logs = LogCount::default();
        tracing::subscriber::with_default(logs.clone(), || {
            engine.on_value_updated(&big, MmsValue::VisibleString("x".repeat(100)), flag, 1);
            engine.tick_at(Instant::now(), 2);
            engine.tick_at(Instant::now(), 3);
            assert!(
                sink.pdus.lock().unwrap().is_empty(),
                "nothing over 64 bytes"
            );
            engine.on_value_updated(&small, MmsValue::Integer(5), flag, 4);
            engine.tick_at(Instant::now(), 5);
        });
        assert_eq!(logs.errors(), 1, "the oversized report is logged once");
        assert_eq!(engine.engine_metrics().dropped_oversized(), 1);
        let pdus = sink.pdus.lock().unwrap();
        assert_eq!(pdus.len(), 1, "the next report goes out");
        assert!(pdus[0].1.len() <= 64);
        // The dropped report used no sequence number: the sent one is SqNum 0.
        assert!(contains(&pdus[0].1, &[0x86, 0x01, 0x00]));
        assert!(rc_arc.lock().unwrap().state.lock().unwrap().rpt_ena);
    }

    #[test]
    fn oversized_brcb_entry_is_dropped_once_and_the_next_one_is_sent() {
        use crate::reporting::brcb::{Brcb, BufferedReportControl, TransmitAnchor};
        let sink = Arc::new(CollectReportSink::default());
        let mut eng = ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>, Default::default());
        let (ds, big, small) = big_and_small_ds();
        let brcb = Brcb::new("brcb01", "GGIO1$ds1")
            .with_rpt_id("b")
            .with_trg_ops(TriggerOptions::DATA_CHANGED)
            .with_opt_flds(OptFlds::SEQ_NUM | OptFlds::ENTRY_ID);
        let path = "IED1LD0/GGIO1$BR$brcb01";
        eng.register_brcb_with_dataset(BufferedReportControl::new(path, brcb), ds)
            .unwrap();
        eng.register_peer(5, "10.0.0.5".parse().unwrap(), 64);
        let brcb_arc = eng.get_brcb(path).unwrap();
        let flag = InclusionFlag::VALUE_CHANGED;
        eng.on_brcb_value_updated(&big, MmsValue::VisibleString("x".repeat(100)), flag, 1);
        eng.on_brcb_value_updated(&small, MmsValue::Integer(5), flag, 2);
        {
            let mut s = brcb_arc.state.lock().unwrap();
            s.rpt_ena = true;
            s.client_conn_id = Some(5);
            s.transmit_anchor = TransmitAnchor::FromHead;
        }
        let entries = brcb_arc.lock_buffer().unwrap().iter_entries();
        assert_eq!(entries.len(), 2);

        let logs = LogCount::default();
        tracing::subscriber::with_default(logs.clone(), || {
            assert_eq!(eng.flush_brcb_pending(&brcb_arc, 5), 1, "the next entry");
            for _ in 0..50 {
                assert_eq!(eng.flush_brcb_pending(&brcb_arc, 5), 0);
            }
        });
        assert_eq!(logs.errors(), 1, "the oversized entry is logged once");
        assert_eq!(eng.engine_metrics().dropped_oversized(), 1);
        let pdus = sink.pdus.lock().unwrap();
        assert_eq!(pdus.len(), 1);
        assert!(pdus[0].1.len() <= 64);
        assert!(
            contains(&pdus[0].1, &entries[1].entry_id.0),
            "the second entry"
        );
        let s = brcb_arc.state.lock().unwrap();
        assert_eq!(
            s.transmit_anchor,
            TransmitAnchor::AfterEntryId(entries[1].entry_id)
        );
        assert_eq!(s.sq_num, 1, "only the sent entry used a sequence number");
    }
}
