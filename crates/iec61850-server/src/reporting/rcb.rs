//! `Rcb`, `RcbState`, and `ReportControl`: the URCB runtime state machine.
//!
//! Implements the unbuffered report control block state and its transitions per
//! IEC 61850-7-2. Static configuration (`Rcb`) is read-only after construction and
//! is kept separate from the mutable runtime state (`RcbState`), which lives
//! behind a single mutex covering both the control block fields and the pending
//! report. A URCB holds exactly one pending report slot rather than a queue.
//!
//! ```text
//! IDLE ──(Resv=true)──► RESERVED ──(RptEna=true)──► ENABLED
//!         ◄──(conn drop)──           ◄──(RptEna=false / conn drop)──
//! ```
//!
//! A URCB reservation has no timeout: it is released only when the owning
//! connection goes away.

use super::dataset::Dataset;
use crate::connection::ConnectionId;
use crate::flags::{InclusionFlag, OptFlds, TriggerOptions};
use iec61850_model::MmsValue;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────
// Static configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Static URCB configuration, read-only once built.
///
/// Holds the configured values of IEC 61850-7-2 report control block fields; the
/// runtime copies live in `RcbState`.
#[derive(Debug, Clone)]
pub struct Rcb {
    /// Control block name without a prefix, for example `"urcb01"`.
    pub name: String,
    /// Initial RptID; when empty, `"<LD>/<LN>$RP$<name>"` is used.
    pub rpt_id: String,
    /// Referenced data set name, `"<LN>$<dsName>"` or an absolute reference.
    pub dataset_name: String,
    /// Initial ConfRev.
    pub conf_rev: u32,
    /// Initial trigger options.
    pub trg_ops: TriggerOptions,
    /// Initial optional fields.
    pub opt_flds: OptFlds,
    /// Initial BufTm, in milliseconds.
    pub buf_tm_ms: u32,
    /// Initial IntgPd, in milliseconds.
    pub intg_pd_ms: u32,
    /// Pre-configured owner address; when set, only a client at this address may
    /// use the control block.
    pub client_reservation: Option<IpAddr>,
}

impl Rcb {
    /// Creates a URCB configuration with default field values.
    pub fn new(name: impl Into<String>, dataset_name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            rpt_id: String::new(), // empty selects the default RptID
            dataset_name: dataset_name.into(),
            conf_rev: 1,
            trg_ops: TriggerOptions::DATA_CHANGED,
            opt_flds: OptFlds::SEQ_NUM | OptFlds::TIME_STAMP | OptFlds::REASON,
            buf_tm_ms: 0,
            intg_pd_ms: 0,
            client_reservation: None,
            name,
        }
    }

    /// Sets RptID.
    pub fn with_rpt_id(mut self, rpt_id: impl Into<String>) -> Self {
        self.rpt_id = rpt_id.into();
        self
    }

    /// Sets ConfRev.
    pub fn with_conf_rev(mut self, v: u32) -> Self {
        self.conf_rev = v;
        self
    }

    /// Sets the trigger options.
    pub fn with_trg_ops(mut self, ops: TriggerOptions) -> Self {
        self.trg_ops = ops;
        self
    }

    /// Sets the optional fields.
    pub fn with_opt_flds(mut self, flds: OptFlds) -> Self {
        self.opt_flds = flds;
        self
    }

    /// Sets BufTm, in milliseconds.
    pub fn with_buf_tm_ms(mut self, ms: u32) -> Self {
        self.buf_tm_ms = ms;
        self
    }

    /// Sets IntgPd, in milliseconds.
    pub fn with_intg_pd_ms(mut self, ms: u32) -> Self {
        self.intg_pd_ms = ms;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-control-block observability counters
// ─────────────────────────────────────────────────────────────────────────────

/// Five per-control-block counters, all atomic so no mutex is needed.
///
/// | Counter | Incremented when |
/// |---|---|
/// | `sent` | `flush_pending` successfully sends a PDU segment |
/// | `dropped_socket_full` | a send hits a full channel, that is, backpressure |
/// | `dropped_buffer_full` | a BRCB report buffer is full; a URCB never increments it |
/// | `coalesced_buftm` | `on_value_updated` merges a second trigger on the same entry inside the buffer time |
/// | `skipped_trgops` | `on_value_updated` returns early because trgOps does not cover the trigger |
///
/// A URCB has a single pending slot, and IEC 61850-7-2 answers a second trigger
/// on the same entry inside the buffer time by flushing the pending report and
/// starting a new one rather than by dropping anything. `dropped_buffer_full`
/// therefore stays at zero for a URCB; reading zero is expected, not a defect.
/// The counter exists so a BRCB can reuse this type unchanged.
///
/// `consecutive_socket_full` is internal state, not a published metric, and does
/// not appear in `RcbMetricsSnapshot`. It tracks how many `WouldBlock` results a
/// flush has seen in a row, for the `BACKPRESSURE_CLOSE_THRESHOLD` decision. It is
/// an `AtomicU32` so `flush_pending` needs only `&self`; a successful send stores
/// zero and a `WouldBlock` increments it.
#[derive(Debug, Default)]
pub struct RcbMetrics {
    /// PDU segments sent successfully, segmented reports included.
    pub sent: AtomicU64,
    /// PDUs dropped because the delivery channel was full.
    pub dropped_socket_full: AtomicU64,
    /// Reports dropped because a BRCB buffer was full; never incremented for a URCB.
    pub dropped_buffer_full: AtomicU64,
    /// Times a second trigger on the same entry was merged inside the buffer time.
    pub coalesced_buftm: AtomicU64,
    /// Triggers skipped because trgOps did not cover them.
    pub skipped_trgops: AtomicU64,
    /// Consecutive `WouldBlock` results; internal backpressure state.
    pub(crate) consecutive_socket_full: AtomicU32,
}

impl RcbMetrics {
    /// Creates a metrics block with every counter at zero.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Reads every counter once. The reads are not atomic as a group, so the
    /// snapshot is for observation rather than for arithmetic invariants.
    pub fn snapshot(&self) -> RcbMetricsSnapshot {
        RcbMetricsSnapshot {
            sent: self.sent.load(Ordering::Relaxed),
            dropped_socket_full: self.dropped_socket_full.load(Ordering::Relaxed),
            dropped_buffer_full: self.dropped_buffer_full.load(Ordering::Relaxed),
            coalesced_buftm: self.coalesced_buftm.load(Ordering::Relaxed),
            skipped_trgops: self.skipped_trgops.load(Ordering::Relaxed),
        }
    }
}

/// A one-shot read of `RcbMetrics`; plain `u64` fields, freely copyable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RcbMetricsSnapshot {
    /// PDU segments sent successfully.
    pub sent: u64,
    /// PDUs dropped because the delivery channel was full.
    pub dropped_socket_full: u64,
    /// Reports dropped because a BRCB buffer was full; always zero for a URCB.
    pub dropped_buffer_full: u64,
    /// Entries merged inside the buffer time.
    pub coalesced_buftm: u64,
    /// Triggers skipped because trgOps did not cover them.
    pub skipped_trgops: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Pending report
// ─────────────────────────────────────────────────────────────────────────────

/// One report waiting to be sent.
///
/// A URCB has a single pending slot: when an entry triggers again inside the
/// buffer time, the pending report is flushed at once and a new one started,
/// bypassing the buffer time per IEC 61850-7-2.
#[derive(Debug, Clone)]
pub struct PendingReport {
    /// Trigger flag per data set entry; the vector is as long as the data set.
    pub inclusion_flags: Vec<InclusionFlag>,
    /// Values captured when each entry triggered.
    pub snapshot: Vec<Option<MmsValue>>,
    /// Timestamp recorded when this report was first triggered.
    pub time_of_entry_ms: u64,
    /// Whether this is an integrity report.
    pub is_integrity: bool,
    /// Whether this is a general interrogation report.
    pub is_gi: bool,
}

impl PendingReport {
    /// Creates an empty pending report sized to the data set.
    pub fn new_empty(dataset_len: usize, now_ms: u64) -> Self {
        Self {
            inclusion_flags: vec![InclusionFlag::NONE; dataset_len],
            snapshot: vec![None; dataset_len],
            time_of_entry_ms: now_ms,
            is_integrity: false,
            is_gi: false,
        }
    }

    /// Returns whether any entry is flagged; meaningful outside integrity and
    /// general interrogation reports, which include everything.
    pub fn has_pending(&self) -> bool {
        self.inclusion_flags.iter().any(|f| f.has_trigger())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime state
// ─────────────────────────────────────────────────────────────────────────────

/// The mutable runtime state of a URCB, held behind a single mutex that covers
/// both the control block fields and the pending report.
#[derive(Debug)]
pub struct RcbState {
    // ── Control block fields readable and writable by a client ───────────────
    /// RptID; a client may overwrite it.
    pub rpt_id: String,
    /// RptEna: whether reporting is enabled.
    pub rpt_ena: bool,
    /// Resv: the client reservation flag, which only a URCB has.
    pub resv: bool,
    /// DatSet: the name of the data set in use.
    pub dat_set: String,
    /// ConfRev; not writable by a client.
    pub conf_rev: u32,
    /// OptFlds.
    pub opt_flds: OptFlds,
    /// BufTm, in milliseconds.
    pub buf_tm_ms: u32,
    /// SqNum. A URCB sequence number is an `UNSIGNED(8)` in the MMS structure and
    /// wraps to zero on overflow, per IEC 61850-7-2, so it is held as a `u8`.
    pub sq_num: u8,
    /// TrgOps.
    pub trg_ops: TriggerOptions,
    /// IntgPd, in milliseconds.
    pub intg_pd_ms: u32,
    /// General interrogation trigger; a client sets it and the engine clears it
    /// once the report has been sent.
    pub gi: bool,
    /// Owner; `None` when unset.
    pub owner: Option<IpAddr>,

    // ── Runtime state, not directly readable or writable by a client ─────────
    /// Connection currently holding this control block.
    pub client_conn_id: Option<ConnectionId>,
    /// Resolved data set; `None` when DatSet is empty or not yet resolved.
    pub dataset: Option<Dataset>,
    /// The single pending report slot.
    pub pending: Option<PendingReport>,
    /// Whether an event is waiting for the buffer time to elapse.
    pub triggered: bool,
    /// When the buffer time expires. An `Instant`, so a wall-clock jump cannot
    /// move the deadline.
    pub report_due: Option<Instant>,
    /// When the next integrity report is due.
    pub next_intg_report: Option<Instant>,
    /// Segmented report: the data set index the next segment starts at.
    pub start_index_for_next_segment: usize,
    /// Segmented report: the sub-sequence number, a 16-bit value.
    pub sub_seq_num: u16,
    /// Timestamp shared by every segment of one report, so the segments agree.
    pub segmented_report_timestamp_ms: u64,
}

impl RcbState {
    /// Builds the runtime state from a static configuration.
    pub fn from_rcb(rcb: &Rcb) -> Self {
        let rpt_id = if rcb.rpt_id.is_empty() {
            // Empty: the caller fills in the default at registration time.
            String::new()
        } else {
            rcb.rpt_id.clone()
        };
        Self {
            rpt_id,
            rpt_ena: false,
            resv: false,
            dat_set: rcb.dataset_name.clone(),
            conf_rev: rcb.conf_rev,
            opt_flds: rcb.opt_flds,
            buf_tm_ms: rcb.buf_tm_ms,
            sq_num: 0,
            trg_ops: rcb.trg_ops,
            intg_pd_ms: rcb.intg_pd_ms,
            gi: false,
            owner: None,
            client_conn_id: None,
            dataset: None,
            pending: None,
            triggered: false,
            report_due: None,
            next_intg_report: None,
            start_index_for_next_segment: 0,
            sub_seq_num: 0,
            segmented_report_timestamp_ms: 0,
        }
    }

    /// Returns the current SqNum and advances it, wrapping at 8 bits per
    /// IEC 61850-7-2.
    pub fn next_sq_num(&mut self) -> u8 {
        let n = self.sq_num;
        self.sq_num = self.sq_num.wrapping_add(1);
        n
    }

    /// Clears every pending state; called on disable and on a buffer purge.
    pub fn purge(&mut self) {
        self.pending = None;
        self.triggered = false;
        self.report_due = None;
        self.start_index_for_next_segment = 0;
        self.sub_seq_num = 0;
        if let Some(ref mut p) = self.pending {
            for f in p.inclusion_flags.iter_mut() {
                *f = InclusionFlag::NONE;
            }
        }
    }

    /// Increments ConfRev. Zero means "unset", so the counter skips it on
    /// overflow and continues at one, per IEC 61850-7-2.
    pub fn increase_conf_rev(&mut self) {
        self.conf_rev = self.conf_rev.wrapping_add(1);
        if self.conf_rev == 0 {
            self.conf_rev = 1;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReportControl: the public runtime handle
// ─────────────────────────────────────────────────────────────────────────────

/// Runtime handle for a URCB: static configuration, lockable runtime state, and
/// counters.
///
/// The counters sit outside the state mutex, so incrementing one never has to take
/// that lock. `AtomicU64` is `Sync` on its own and plain counting needs no ordering
/// guarantees, so every access uses `Ordering::Relaxed`.
#[derive(Debug)]
pub struct ReportControl {
    /// Full key in the MMS namespace, for example `"IED1LD0/GGIO1$RP$urcb01"`.
    pub mms_path: String,
    /// Static configuration, read-only.
    pub rcb: Rcb,
    /// Mutable runtime state behind a single mutex.
    pub state: std::sync::Mutex<RcbState>,
    /// Per-control-block observability counters.
    pub metrics: Arc<RcbMetrics>,
}

impl ReportControl {
    /// Creates a report control handle.
    ///
    /// `mms_path` has the form `"<domain>/<LN>$RP$<rcb_name>"`, without a field name.
    pub fn new(mms_path: impl Into<String>, rcb: Rcb) -> Self {
        let state = RcbState::from_rcb(&rcb);
        Self {
            mms_path: mms_path.into(),
            state: std::sync::Mutex::new(state),
            metrics: RcbMetrics::new(),
            rcb,
        }
    }

    /// Returns a one-shot read of the counters.
    pub fn metrics_snapshot(&self) -> RcbMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Locks the runtime state.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::InvalidModel` when the state mutex is poisoned; this
    /// never panics.
    pub fn lock_state(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, RcbState>, crate::error::ServerError> {
        self.state
            .lock()
            .map_err(|_| crate::error::ServerError::InvalidModel("RcbState Mutex poisoned".into()))
    }

    /// Returns BufTm as a `Duration`, so no bare integer crosses the boundary.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::InvalidModel` when the state mutex is poisoned.
    pub fn buf_tm(&self) -> Result<Duration, crate::error::ServerError> {
        let s = self.lock_state()?;
        Ok(Duration::from_millis(s.buf_tm_ms as u64))
    }

    /// Returns IntgPd as a `Duration`.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::InvalidModel` when the state mutex is poisoned.
    pub fn intg_pd(&self) -> Result<Duration, crate::error::ServerError> {
        let s = self.lock_state()?;
        Ok(Duration::from_millis(s.intg_pd_ms as u64))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rcb() -> Rcb {
        Rcb::new("urcb01", "GGIO1$ds1")
            .with_conf_rev(5)
            .with_buf_tm_ms(100)
            .with_intg_pd_ms(1000)
            .with_trg_ops(TriggerOptions::DATA_CHANGED | TriggerOptions::GI)
            .with_opt_flds(OptFlds::SEQ_NUM | OptFlds::TIME_STAMP | OptFlds::REASON)
    }

    #[test]
    fn rcb_fields_set_correctly() {
        let rcb = make_rcb();
        assert_eq!(rcb.name, "urcb01");
        assert_eq!(rcb.dataset_name, "GGIO1$ds1");
        assert_eq!(rcb.conf_rev, 5);
        assert_eq!(rcb.buf_tm_ms, 100);
        assert_eq!(rcb.intg_pd_ms, 1000);
        assert!(rcb.trg_ops.contains(TriggerOptions::DATA_CHANGED));
        assert!(rcb.trg_ops.contains(TriggerOptions::GI));
    }

    #[test]
    fn rcb_state_initial_values() {
        let rcb = make_rcb();
        let state = RcbState::from_rcb(&rcb);
        assert!(!state.rpt_ena);
        assert!(!state.resv);
        assert_eq!(state.sq_num, 0);
        assert_eq!(state.conf_rev, 5);
        assert_eq!(state.buf_tm_ms, 100);
        assert_eq!(state.intg_pd_ms, 1000);
        assert!(state.client_conn_id.is_none());
        assert!(state.pending.is_none());
        assert!(!state.triggered);
    }

    #[test]
    fn sq_num_wraps_at_256() {
        let rcb = make_rcb();
        let mut state = RcbState::from_rcb(&rcb);
        state.sq_num = 255;
        let n = state.next_sq_num();
        assert_eq!(n, 255);
        assert_eq!(state.sq_num, 0, "SqNum must wrap to 0 after 255");
    }

    #[test]
    fn sq_num_sequential_increment() {
        let rcb = make_rcb();
        let mut state = RcbState::from_rcb(&rcb);
        assert_eq!(state.next_sq_num(), 0);
        assert_eq!(state.next_sq_num(), 1);
        assert_eq!(state.next_sq_num(), 2);
    }

    #[test]
    fn conf_rev_overflow_skips_zero() {
        let rcb = make_rcb();
        let mut state = RcbState::from_rcb(&rcb);
        state.conf_rev = u32::MAX;
        state.increase_conf_rev();
        assert_eq!(
            state.conf_rev, 1,
            "ConfRev must skip 0 and continue at 1 on overflow, per IEC 61850-7-2"
        );
    }

    #[test]
    fn conf_rev_normal_increment() {
        let rcb = make_rcb();
        let mut state = RcbState::from_rcb(&rcb);
        state.conf_rev = 42;
        state.increase_conf_rev();
        assert_eq!(state.conf_rev, 43);
    }

    #[test]
    fn report_control_new_mms_path() {
        let rcb = make_rcb();
        let rc = ReportControl::new("IED1LD0/GGIO1$RP$urcb01", rcb);
        assert_eq!(rc.mms_path, "IED1LD0/GGIO1$RP$urcb01");
    }

    #[test]
    fn report_control_lock_state_ok() {
        let rcb = make_rcb();
        let rc = ReportControl::new("IED1LD0/GGIO1$RP$urcb01", rcb);
        let state = rc.lock_state().expect("lock_state must succeed");
        assert!(!state.rpt_ena);
    }

    #[test]
    fn pending_report_new_empty() {
        let p = PendingReport::new_empty(3, 1000);
        assert_eq!(p.inclusion_flags.len(), 3);
        assert_eq!(p.snapshot.len(), 3);
        assert!(p.inclusion_flags.iter().all(|f| f.is_none()));
        assert!(p.snapshot.iter().all(|v| v.is_none()));
        assert_eq!(p.time_of_entry_ms, 1000);
        assert!(!p.is_integrity);
        assert!(!p.is_gi);
    }

    #[test]
    fn pending_report_has_pending() {
        let mut p = PendingReport::new_empty(2, 0);
        assert!(!p.has_pending());
        p.inclusion_flags[0] = InclusionFlag::VALUE_CHANGED;
        assert!(p.has_pending());
    }
}
