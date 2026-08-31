//! BRCB: the buffered report control block.
//!
//! Implements the buffered reporting branch of IEC 61850-7-2. Compared with the
//! unbuffered control block in `rcb.rs`, a BRCB keeps a multi-entry report buffer
//! instead of one pending slot, carries an EntryID, counts sequence numbers in 16
//! bits rather than 8, and keeps its buffer when reporting is disabled.
//!
//! The behavior that most distinguishes a BRCB is `is_buffering`: while DatSet
//! names a valid data set, entries keep being enqueued even with `RptEna` false,
//! so a client that reconnects can resynchronize from an EntryID it already holds.
//!
//! Buffer capacity is counted in entries rather than bytes, a reservation timeout
//! is expired by an active tick rather than checked lazily on the next access, and
//! a configuration change that purges the buffer logs a warning rather than
//! discarding entries silently.

use super::buffer::{
    EnqueuedSnapshot, EntryId, InMemoryReportBuffer, ReportBufferBackend, ReportEntry, SeekResult,
};
use crate::connection::ConnectionId;
use crate::flags::{OptFlds, TriggerOptions};
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────
// ResvTms state
// ─────────────────────────────────────────────────────────────────────────────

/// State of the BRCB ResvTms field.
///
/// On the wire ResvTms is an `INT16` carrying three meanings in one number: a
/// negative value marks a pre-configured owner that never times out, zero means
/// unreserved, and a positive value is the number of seconds left on the
/// reservation. Splitting them into variants makes the compiler force every case
/// to be handled. The wire format is unchanged; the conversion happens at the
/// encoding boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResvTmsState {
    /// Pre-configured owner: never times out, and only a client whose address
    /// matches may take the control block.
    Preconfigured,
    /// Unreserved: any client write reserves the control block implicitly for ten
    /// seconds.
    NotReserved,
    /// Reserved with a timeout; the value is the number of seconds remaining.
    WithTimeout(NonZeroU16),
}

impl ResvTmsState {
    /// Builds the state from the wire `INT16`.
    ///
    /// Any negative value is `Preconfigured`; only -1 is defined and no other
    /// negative value carries a distinct meaning. Zero is `NotReserved` and a
    /// positive value is `WithTimeout`.
    pub fn from_wire(v: i16) -> Self {
        if v < 0 {
            Self::Preconfigured
        } else if v == 0 {
            Self::NotReserved
        } else {
            // v is positive here, so the cast cannot overflow: the positive range
            // of an i16 is 1..=32767.
            match NonZeroU16::new(v as u16) {
                Some(nz) => Self::WithTimeout(nz),
                // Unreachable while v is positive; answered as NotReserved rather
                // than panicking.
                None => Self::NotReserved,
            }
        }
    }

    /// Converts back to the wire `INT16`, for encoding the MMS field.
    pub fn to_wire(self) -> i16 {
        match self {
            Self::Preconfigured => -1,
            Self::NotReserved => 0,
            Self::WithTimeout(s) => s.get() as i16,
        }
    }

    /// Returns whether the control block is reserved, that is `Preconfigured` or
    /// `WithTimeout`.
    pub fn is_reserved(self) -> bool {
        !matches!(self, Self::NotReserved)
    }
}

/// Seconds of the implicit reservation defined by IEC 61850-7-2: a successful RCB
/// write other than one to ResvTms reserves the control block for this long.
///
/// Nothing consumes this constant yet — no write path applies the implicit
/// reservation — so it records the value the standard specifies rather than
/// behavior this crate implements.
// TODO: apply the implicit reservation on a successful RCB write.
pub const RESV_TMS_IMPLICIT_VALUE_S: u16 = 10;

// ─────────────────────────────────────────────────────────────────────────────
// Configuration writes: BrcbConfigField and ConfigChangeResult
// ─────────────────────────────────────────────────────────────────────────────

/// Which configuration field a BRCB write targets.
///
/// Every configuration write funnels through `set_config_field`, so a field added
/// later cannot accidentally skip the buffer purge the change requires.
#[derive(Debug, Clone)]
pub enum BrcbConfigField {
    /// The referenced data set name.
    DatSet(String),
    /// The trigger options.
    TrgOps(TriggerOptions),
    /// The integrity period, in milliseconds.
    IntgPdMs(u32),
    /// The buffer time, in milliseconds.
    BufTmMs(u32),
    /// The report identifier.
    RptId(String),
}

impl BrcbConfigField {
    /// Returns the field name, for logging and metrics.
    pub fn field_name(&self) -> &'static str {
        match self {
            Self::DatSet(_) => "DatSet",
            Self::TrgOps(_) => "TrgOps",
            Self::IntgPdMs(_) => "IntgPd",
            Self::BufTmMs(_) => "BufTm",
            Self::RptId(_) => "RptID",
        }
    }
}

/// Result of `set_config_field`.
///
/// The purge that `RequiresPurge` reports is performed inside `set_config_field`
/// itself, not by the caller; the variant only tells the caller that this change
/// emptied the buffer, so it can be logged or counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigChangeResult {
    /// The value written was already in place: nothing changed and nothing was
    /// purged.
    NoChange,
    /// The change was applied without a purge. No field takes this path today; it
    /// is kept for fields added later.
    Applied,
    /// The change was applied and the buffer was purged; the count is how many
    /// entries were removed.
    RequiresPurge {
        /// Number of entries the purge removed.
        purged_entries: usize,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Transmit anchor and the EntryID write path
// ─────────────────────────────────────────────────────────────────────────────

/// Where transmission resumes for a BRCB.
///
/// Four situations have to be told apart: nothing is set yet, transmission starts
/// at the head of the buffer, it resumes after a known entry, or the client
/// selected the newest entry and transmission must resume at whatever is enqueued
/// next. Keeping them as separate variants forces a caller to handle
/// `WaitingForNext` instead of confusing it with "not set".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum TransmitAnchor {
    /// No starting point is set: the buffer is empty, or the client has not
    /// resynchronized.
    #[default]
    None,
    /// Send from the head of the buffer; a client selects this by writing an
    /// all-zero EntryID.
    FromHead,
    /// Send the entries that follow this one; set when a client writes a non-zero
    /// EntryID that is found in the buffer.
    AfterEntryId(EntryId),
    /// The client selected the newest entry, so transmission waits for the next
    /// entry enqueued. `BrcbState::on_enqueue` then turns this into
    /// `AfterEntryId(prev_last)`.
    WaitingForNext,
}

/// Why `apply_entry_id_write` failed.
///
/// Only one case exists today; it is an enum rather than a unit struct so a later
/// case does not force every caller to change the shape of its match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyEntryIdError {
    /// The EntryID is not in the buffer, having been evicted or never stored. The
    /// dispatcher answers `DataAccessError::ObjectValueInvalid`.
    InvalidEntryId,
}

// ─────────────────────────────────────────────────────────────────────────────
// Static configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Static BRCB configuration, read-only once built.
///
/// Differs from the URCB `Rcb` in three ways: there is no `Resv` field, which only
/// a URCB has; `with_resv_tms` and `with_owner` decide whether the Edition 2 fields
/// are exposed; and the sequence number is 16 bits rather than 8.
#[derive(Debug, Clone)]
pub struct Brcb {
    /// Control block name without a prefix, for example `"brcb01"`.
    pub name: String,
    /// Initial RptID; when empty, `"<LD>/<LN>$BR$<name>"` is used.
    pub rpt_id: String,
    /// Referenced data set name.
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
    /// Maximum number of buffered entries; capacity counts entries, not bytes.
    pub buffer_capacity: usize,
    /// Pre-configured owner address; when set, ResvTms starts as `Preconfigured`.
    pub client_reservation: Option<IpAddr>,
    /// Whether the Edition 2 ResvTms MMS field is exposed.
    pub with_resv_tms: bool,
    /// Whether the Edition 2 Owner MMS field is exposed.
    pub with_owner: bool,
}

impl Brcb {
    /// Creates a BRCB configuration with default field values.
    pub fn new(name: impl Into<String>, dataset_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            rpt_id: String::new(),
            dataset_name: dataset_name.into(),
            conf_rev: 1,
            trg_ops: TriggerOptions::DATA_CHANGED,
            opt_flds: OptFlds::SEQ_NUM
                | OptFlds::TIME_STAMP
                | OptFlds::REASON
                | OptFlds::BUFFER_OVERFLOW
                | OptFlds::ENTRY_ID,
            buf_tm_ms: 0,
            intg_pd_ms: 0,
            buffer_capacity: 64, // 64 buffered entries by default
            client_reservation: None,
            with_resv_tms: true,
            with_owner: false,
        }
    }

    /// Sets the buffer capacity, in entries.
    pub fn with_buffer_capacity(mut self, n: usize) -> Self {
        self.buffer_capacity = n;
        self
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

    /// Sets the pre-configured owner address.
    pub fn with_preconfigured_owner(mut self, ip: IpAddr) -> Self {
        self.client_reservation = Some(ip);
        self
    }

    /// Sets whether the ResvTms field is exposed.
    pub fn with_resv_tms(mut self, on: bool) -> Self {
        self.with_resv_tms = on;
        self
    }

    /// Sets whether the Owner field is exposed.
    pub fn with_owner(mut self, on: bool) -> Self {
        self.with_owner = on;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime state
// ─────────────────────────────────────────────────────────────────────────────

/// The mutable runtime state of a BRCB, held behind a mutex.
///
/// Carries both the fields a BRCB shares with a URCB and the ones only a buffered
/// control block has, per IEC 61850-7-2.
#[derive(Debug)]
pub struct BrcbState {
    // ── Control block fields readable and writable by a client ───────────────
    /// RptID.
    pub rpt_id: String,
    /// RptEna: whether reporting is enabled.
    pub rpt_ena: bool,
    /// DatSet: the name of the data set in use.
    pub dat_set: String,
    /// ConfRev; not writable by a client.
    pub conf_rev: u32,
    /// OptFlds.
    pub opt_flds: OptFlds,
    /// BufTm, in milliseconds.
    pub buf_tm_ms: u32,
    /// SqNum. A BRCB sequence number is 16 bits where a URCB uses 8, and it wraps
    /// naturally rather than being reset.
    pub sq_num: u16,
    /// TrgOps.
    pub trg_ops: TriggerOptions,
    /// IntgPd, in milliseconds.
    pub intg_pd_ms: u32,
    /// General interrogation trigger; a client sets it and it is cleared once the
    /// report has been sent.
    pub gi: bool,
    /// PurgeBuf, which only a BRCB has: writing true purges the report buffer,
    /// writing false has no effect.
    pub purge_buf_pending: bool,
    /// EntryID of the entry sent most recently, eight bytes big-endian; BRCB only.
    pub last_sent_entry_id: EntryId,
    /// Millisecond timestamp of the entry sent most recently; BRCB only.
    pub last_sent_time_of_entry_ms: u64,
    /// ResvTms, introduced in Edition 2.
    pub resv_tms: ResvTmsState,
    /// Owner, introduced in Edition 2; `None` when unset.
    pub owner: Option<IpAddr>,

    // ── Runtime state, not directly readable or writable by a client ─────────
    /// Connection currently holding this control block.
    pub client_conn_id: Option<ConnectionId>,
    /// `is_buffering`, which only a BRCB has: while DatSet is valid, entries are
    /// enqueued even with RptEna false.
    pub is_buffering: bool,
    /// `is_resync`: set once a client has written EntryID, so the next
    /// `RptEna = true` does not reset the transmit anchor.
    pub is_resync: bool,
    /// EntryID assigned most recently, as a host-order `u64` for the monotonic
    /// bump; it becomes big-endian when written into the buffer.
    pub last_entry_id_ms: u64,
    /// Where transmission resumes. `apply_entry_id_write` sets it and `on_enqueue`
    /// resolves it when it is `WaitingForNext`; the send path reads it to decide
    /// where to start.
    pub transmit_anchor: TransmitAnchor,
    /// EntryID the client wrote most recently. GetBRCBValues reads it back, so a
    /// read after a write returns the same value.
    pub last_committed_entry_id: EntryId,
    /// When the reservation expires. The tick path scans this and releases the
    /// reservation once it has passed. `None` when no timer is needed, that is for
    /// a pre-configured or unreserved control block.
    pub reservation_timeout: Option<Instant>,

    // ── Segmentation ─────────────────────────────────────────────────────────
    /// Segmented report: the data set index the next segment starts at.
    pub start_index_for_next_segment: usize,
    /// Segmented report: the sub-sequence number.
    pub sub_seq_num: u16,
    /// Whether an entry is currently being sent in segments.
    pub segmented: bool,
}

impl BrcbState {
    /// Builds the runtime state from a static configuration.
    pub fn from_brcb(brcb: &Brcb) -> Self {
        let resv_tms = if brcb.client_reservation.is_some() {
            ResvTmsState::Preconfigured
        } else {
            ResvTmsState::NotReserved
        };
        Self {
            rpt_id: brcb.rpt_id.clone(),
            rpt_ena: false,
            dat_set: brcb.dataset_name.clone(),
            conf_rev: brcb.conf_rev,
            opt_flds: brcb.opt_flds,
            buf_tm_ms: brcb.buf_tm_ms,
            sq_num: 0,
            trg_ops: brcb.trg_ops,
            intg_pd_ms: brcb.intg_pd_ms,
            gi: false,
            purge_buf_pending: false,
            last_sent_entry_id: EntryId::ZERO,
            last_sent_time_of_entry_ms: 0,
            resv_tms,
            owner: None,
            client_conn_id: None,
            // A non-empty DatSet starts buffering, so entries accumulate even
            // before a client enables reporting.
            is_buffering: !brcb.dataset_name.is_empty(),
            is_resync: false,
            last_entry_id_ms: 0,
            transmit_anchor: TransmitAnchor::None,
            last_committed_entry_id: EntryId::ZERO,
            reservation_timeout: None,
            start_index_for_next_segment: 0,
            sub_seq_num: 0,
            segmented: false,
        }
    }

    /// Returns the current SqNum and advances it; the 16-bit counter wraps
    /// naturally.
    pub fn next_sq_num(&mut self) -> u16 {
        let n = self.sq_num;
        self.sq_num = self.sq_num.wrapping_add(1);
        n
    }

    /// Increments ConfRev, skipping zero on overflow as a URCB does.
    pub fn increase_conf_rev(&mut self) {
        self.conf_rev = self.conf_rev.wrapping_add(1);
        if self.conf_rev == 0 {
            self.conf_rev = 1;
        }
    }

    /// Allocates the next EntryID.
    ///
    /// The identifier is `max(now_ms, last_entry_id + 1)`, so it increases strictly
    /// even when several entries fall in the same millisecond or the wall clock
    /// steps backwards. It is still derived from the timestamp rather than being a
    /// pure sequence number.
    pub fn allocate_entry_id(&mut self, now_ms: u64) -> EntryId {
        let candidate = if self.last_entry_id_ms == 0 {
            now_ms
        } else {
            now_ms.max(self.last_entry_id_ms.saturating_add(1))
        };
        self.last_entry_id_ms = candidate;
        EntryId::from_ms(candidate)
    }

    /// Releases the reservation when its timer has elapsed.
    ///
    /// Called once per second from `ReportingEngine::tick()`. When
    /// `reservation_timeout` has passed, the reservation is released: the client
    /// connection is forgotten and ResvTms returns to `NotReserved`.
    ///
    /// Returns `true` when this call actually released a reservation.
    pub fn tick_reservation(&mut self, now: Instant) -> bool {
        // A pre-configured owner never times out.
        if matches!(self.resv_tms, ResvTmsState::Preconfigured) {
            return false;
        }
        let Some(deadline) = self.reservation_timeout else {
            return false;
        };
        if now < deadline {
            return false;
        }
        // Expired: release the reservation.
        tracing::warn!("brcb reservation timed out and was released");
        self.resv_tms = ResvTmsState::NotReserved;
        self.reservation_timeout = None;
        // Disabling a BRCB does not purge the buffer, so only the connection is
        // cleared here; the buffer and is_buffering are kept.
        if !self.rpt_ena {
            self.client_conn_id = None;
        }
        true
    }

    /// Applies a client write to the EntryID field.
    ///
    /// The caller supplies the buffer backend to query and must already hold the
    /// buffer lock; this method takes no lock of its own and updates only
    /// `BrcbState`.
    ///
    /// Four outcomes, following the resynchronization rules of IEC 61850-7-2:
    ///
    /// 1. an all-zero EntryID sets `transmit_anchor = FromHead`, clears
    ///    `is_resync`, and implies `is_overflow = true`, meaning "send everything
    ///    from the head";
    /// 2. an EntryID found with a later entry sets
    ///    `transmit_anchor = AfterEntryId(found)`, sets `is_resync`, and leaves
    ///    `is_overflow = false`;
    /// 3. an EntryID found as the newest entry sets
    ///    `transmit_anchor = WaitingForNext`, sets `is_resync`, and leaves
    ///    `is_overflow = false`; the next `on_enqueue` resolves it;
    /// 4. an EntryID that is not in the buffer implies `is_overflow = true` and is
    ///    refused, and the dispatcher answers
    ///    `DataAccessError::ObjectValueInvalid`.
    ///
    /// This method does not set the overflow flag itself. The caller owns it, and
    /// the send path infers it — see `BufferedReportControl::apply_entry_id_write`.
    ///
    /// # Errors
    ///
    /// Returns `ApplyEntryIdError::InvalidEntryId` for the fourth case.
    pub fn apply_entry_id_write(
        &mut self,
        id: EntryId,
        backend: &dyn ReportBufferBackend,
    ) -> Result<(), ApplyEntryIdError> {
        // A read of EntryID after this write returns the value just written.
        self.last_committed_entry_id = id;

        if id.is_zero() {
            // An all-zero EntryID sends from the head. The overflow indication is a
            // marker here and does not mean anything was actually dropped.
            self.transmit_anchor = TransmitAnchor::FromHead;
            self.is_resync = false;
            return Ok(());
        }

        match backend.seek_to_after_entry_id(&id) {
            SeekResult::FoundWithNext(_next) => {
                // Record the identifier rather than an Arc to the next entry:
                // holding a reference here would keep that entry alive against
                // eviction. The send path re-reads the buffer for current state.
                self.transmit_anchor = TransmitAnchor::AfterEntryId(id);
                self.is_resync = true;
                Ok(())
            }
            SeekResult::FoundLast => {
                // Found as the newest entry: transmission waits for the next
                // enqueue.
                self.transmit_anchor = TransmitAnchor::WaitingForNext;
                self.is_resync = true;
                Ok(())
            }
            SeekResult::NotFound => {
                // Not in the buffer: the client is answered with an invalid value.
                tracing::warn!(
                    entry_id = id.as_u64(),
                    "SetBRCBValues EntryID: not found in the buffer, answering InvalidEntryId"
                );
                Err(ApplyEntryIdError::InvalidEntryId)
            }
        }
    }

    /// Hook run after an entry has been enqueued.
    ///
    /// When the transmit anchor is `WaitingForNext` it becomes
    /// `AfterEntryId(prev_last)`, so the send path knows to start with this new
    /// entry. Every other anchor state is already self-consistent and is left
    /// alone.
    ///
    /// `entry` is the entry that was just enqueued.
    pub fn on_enqueue(&mut self, entry: &ReportEntry) {
        if matches!(self.transmit_anchor, TransmitAnchor::WaitingForNext) {
            // Turn "the next one" into a concrete anchor. The anchor names the
            // EntryID the client last wrote, not the new entry, so the send path
            // walks forward from it and emits this entry and everything after it.
            self.transmit_anchor = TransmitAnchor::AfterEntryId(self.last_committed_entry_id);
            tracing::debug!(
                resolved_after = self.last_committed_entry_id.as_u64(),
                new_entry = entry.entry_id.as_u64(),
                "brcb on_enqueue resolved WaitingForNext to AfterEntryId"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BufferedReportControl: the public runtime handle
// ─────────────────────────────────────────────────────────────────────────────

/// Runtime handle for a BRCB, the counterpart of the URCB `ReportControl`.
///
/// - `brcb`: static configuration, read-only
/// - `state`: mutable runtime state behind a mutex
/// - `report_buffer`: the buffer backend behind its own mutex, held as a trait
///   object so another backend can be substituted without touching `BrcbState`
#[derive(Debug)]
pub struct BufferedReportControl {
    /// Full key in the MMS namespace, for example `"IED1LD0/GGIO1$BR$brcb01"`. A
    /// BRCB uses `$BR$` where a URCB uses `$RP$`.
    pub mms_path: String,
    /// Static configuration, read-only.
    pub brcb: Brcb,
    /// Mutable runtime state.
    pub state: std::sync::Mutex<BrcbState>,
    /// Report buffer backend.
    pub report_buffer: std::sync::Mutex<Box<dyn ReportBufferBackend>>,
}

impl BufferedReportControl {
    /// Creates a BRCB backed by an in-memory report buffer.
    pub fn new(mms_path: impl Into<String>, brcb: Brcb) -> Self {
        let state = BrcbState::from_brcb(&brcb);
        let backend: Box<dyn ReportBufferBackend> =
            Box::new(InMemoryReportBuffer::new(brcb.buffer_capacity));
        Self {
            mms_path: mms_path.into(),
            state: std::sync::Mutex::new(state),
            report_buffer: std::sync::Mutex::new(backend),
            brcb,
        }
    }

    /// Creates a BRCB with a caller-supplied buffer backend.
    pub fn with_backend(
        mms_path: impl Into<String>,
        brcb: Brcb,
        backend: Box<dyn ReportBufferBackend>,
    ) -> Self {
        let state = BrcbState::from_brcb(&brcb);
        Self {
            mms_path: mms_path.into(),
            state: std::sync::Mutex::new(state),
            report_buffer: std::sync::Mutex::new(backend),
            brcb,
        }
    }

    /// Locks the runtime state.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::InvalidModel` when the state mutex is poisoned; this
    /// never panics.
    pub fn lock_state(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, BrcbState>, crate::error::ServerError> {
        self.state
            .lock()
            .map_err(|_| crate::error::ServerError::InvalidModel("BrcbState Mutex poisoned".into()))
    }

    /// Locks the report buffer.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::InvalidModel` when the buffer mutex is poisoned.
    pub fn lock_buffer(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Box<dyn ReportBufferBackend>>, crate::error::ServerError>
    {
        self.report_buffer.lock().map_err(|_| {
            crate::error::ServerError::InvalidModel("ReportBuffer Mutex poisoned".into())
        })
    }

    /// Returns BufTm as a `Duration`.
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

    // ─── Configuration writes ────────────────────────────────────────────────

    /// The single entry point for changing BRCB configuration.
    ///
    /// Changing DatSet, TrgOps, IntgPd, BufTm, or RptID to a different value purges
    /// the report buffer and logs a warning naming the control block, the field,
    /// and how many entries were discarded. Writing the value already in place
    /// changes nothing and purges nothing.
    ///
    /// Configuration may only be changed while `RptEna` is false.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::InvalidModel` when reporting is enabled, or when the
    /// state or buffer mutex is poisoned.
    pub fn set_config_field(
        &self,
        field: BrcbConfigField,
    ) -> Result<ConfigChangeResult, crate::error::ServerError> {
        let mut state = self.lock_state()?;
        if state.rpt_ena {
            return Err(crate::error::ServerError::InvalidModel(
                "brcb config cannot be modified while RptEna=true".into(),
            ));
        }

        let field_name = field.field_name();

        // Purge only when the value actually changes.
        let changed = match &field {
            BrcbConfigField::DatSet(v) => {
                let c = state.dat_set != *v;
                if c {
                    state.dat_set = v.clone();
                    // An empty DatSet stops buffering.
                    state.is_buffering = !v.is_empty();
                }
                c
            }
            BrcbConfigField::TrgOps(v) => {
                let c = state.trg_ops != *v;
                if c {
                    state.trg_ops = *v;
                }
                c
            }
            BrcbConfigField::IntgPdMs(v) => {
                let c = state.intg_pd_ms != *v;
                if c {
                    state.intg_pd_ms = *v;
                }
                c
            }
            BrcbConfigField::BufTmMs(v) => {
                let c = state.buf_tm_ms != *v;
                if c {
                    state.buf_tm_ms = *v;
                }
                c
            }
            BrcbConfigField::RptId(v) => {
                let c = state.rpt_id != *v;
                if c {
                    state.rpt_id = v.clone();
                }
                c
            }
        };

        if !changed {
            return Ok(ConfigChangeResult::NoChange);
        }

        // A configuration change bumps ConfRev.
        state.increase_conf_rev();

        // Release the state lock before taking the buffer lock; the two are never
        // held at the same time.
        drop(state);

        let purged = {
            let mut buf = self.lock_buffer()?;
            buf.purge()
        };

        // The purge is reported rather than performed silently.
        tracing::warn!(
            mms_path = %self.mms_path,
            field = field_name,
            purged_entries = purged,
            "brcb config change purged the report buffer"
        );

        Ok(ConfigChangeResult::RequiresPurge {
            purged_entries: purged,
        })
    }

    /// Applies a client write to the PurgeBuf field.
    ///
    /// Writing false has no effect. Writing true purges the report buffer, but only
    /// while `RptEna` is false; while reporting is enabled the write is ignored.
    /// Returns the number of entries removed.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::InvalidModel` when the state or buffer mutex is
    /// poisoned.
    pub fn handle_purge_buf_write(&self, value: bool) -> Result<usize, crate::error::ServerError> {
        if !value {
            // Writing false is not an error; nothing is purged.
            return Ok(0);
        }
        let state = self.lock_state()?;
        if state.rpt_ena {
            // PurgeBuf is effective only while reporting is disabled.
            tracing::warn!(
                mms_path = %self.mms_path,
                "PurgeBuf write ignored while RptEna is true"
            );
            return Ok(0);
        }
        drop(state);
        let purged = {
            let mut buf = self.lock_buffer()?;
            buf.purge()
        };
        tracing::warn!(
            mms_path = %self.mms_path,
            purged_entries = purged,
            "client wrote PurgeBuf=true, report buffer purged"
        );
        Ok(purged)
    }

    /// Enqueues one entry carrying a pre-encoded payload.
    ///
    /// Returns the assigned EntryID and whether the push evicted an older entry.
    /// After the push, `state.on_enqueue` runs, so a transmit anchor left at
    /// `WaitingForNext` by an earlier EntryID write advances to
    /// `AfterEntryId(prev_last)`.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::InvalidModel` when the state or buffer mutex is
    /// poisoned.
    pub fn enqueue_entry(
        &self,
        now_ms: u64,
        is_integrity: bool,
        is_gi: bool,
        encoded_payload: bytes::Bytes,
    ) -> Result<(EntryId, bool), crate::error::ServerError> {
        // The state lock and the buffer lock are taken one at a time, never together.
        let entry_id = {
            let mut state = self.lock_state()?;
            state.allocate_entry_id(now_ms)
        };
        let entry = Arc::new(ReportEntry::new(
            entry_id,
            now_ms,
            is_integrity,
            is_gi,
            encoded_payload,
        ));
        let evicted = {
            let mut buf = self.lock_buffer()?;
            buf.push(entry.clone())
        };
        // Resolve a WaitingForNext anchor now that a new entry is in the buffer.
        {
            let mut state = self.lock_state()?;
            state.on_enqueue(&entry);
        }
        Ok((entry_id, evicted))
    }

    /// Enqueues one entry carrying an enqueue-time snapshot.
    ///
    /// Differs from `enqueue_entry` in taking an `EnqueuedSnapshot` instead of
    /// encoded bytes: the trigger path has already applied the trgOps filter and
    /// frozen the data set values, so the send path reads the snapshot rather than
    /// live values and a data set that changes before transmission cannot alter
    /// what the client is told.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::InvalidModel` when the state or buffer mutex is
    /// poisoned.
    pub fn enqueue_entry_with_snapshot(
        &self,
        now_ms: u64,
        is_integrity: bool,
        is_gi: bool,
        snapshot: EnqueuedSnapshot,
    ) -> Result<(EntryId, bool), crate::error::ServerError> {
        let entry_id = {
            let mut state = self.lock_state()?;
            state.allocate_entry_id(now_ms)
        };
        let entry = Arc::new(ReportEntry::with_snapshot(
            entry_id,
            now_ms,
            is_integrity,
            is_gi,
            Arc::new(snapshot),
        ));
        let evicted = {
            let mut buf = self.lock_buffer()?;
            buf.push(entry.clone())
        };
        {
            let mut state = self.lock_state()?;
            state.on_enqueue(&entry);
        }
        Ok((entry_id, evicted))
    }

    // ─── EntryID resynchronization ───────────────────────────────────────────

    /// The single entry point for a client write to the EntryID field, per the
    /// resynchronization rules of IEC 61850-7-2.
    ///
    /// The buffer lock is taken for the lookup and released before the state lock
    /// is taken, so the two are never held at once.
    ///
    /// Outcomes:
    /// - `Ok(())` with `transmit_anchor = FromHead` for an all-zero EntryID
    /// - `Ok(())` with `transmit_anchor = AfterEntryId(id)` when the entry is found
    ///   and is not the newest
    /// - `Ok(())` with `transmit_anchor = WaitingForNext` when the entry is found
    ///   and is the newest; the next enqueue resolves it
    /// - `Err(InvalidEntryId)` when the entry is not in the buffer, which the
    ///   dispatcher answers with `DataAccessError::ObjectValueInvalid`
    ///
    /// The buffer overflow flag is not set here. The send path implies
    /// `BufOvfl = true` whenever the anchor is `FromHead` or unset, which covers the
    /// not-found case as well, so a resynchronizing client still sees
    /// `BufOvfl = true` on its first report without widening the
    /// `ReportBufferBackend` trait.
    ///
    /// # Errors
    ///
    /// The outer `Result` carries infrastructure failures such as a poisoned mutex;
    /// the inner one carries the client-visible `ApplyEntryIdError`.
    pub fn apply_entry_id_write(
        &self,
        id: EntryId,
    ) -> Result<Result<(), ApplyEntryIdError>, crate::error::ServerError> {
        // Query the backend first; the buffer lock is released at the end of this scope.
        let seek = if id.is_zero() {
            None
        } else {
            Some(self.lock_buffer()?.seek_to_after_entry_id(&id))
        };

        // Then apply the result to the state.
        let mut state = self.lock_state()?;
        state.last_committed_entry_id = id;
        let outcome = if id.is_zero() {
            state.transmit_anchor = TransmitAnchor::FromHead;
            state.is_resync = false;
            Ok(())
        } else {
            // The non-zero path always took the Some branch above.
            match seek.expect("a non-zero entry id always has a seek result") {
                SeekResult::FoundWithNext(_) => {
                    state.transmit_anchor = TransmitAnchor::AfterEntryId(id);
                    state.is_resync = true;
                    Ok(())
                }
                SeekResult::FoundLast => {
                    state.transmit_anchor = TransmitAnchor::WaitingForNext;
                    state.is_resync = true;
                    Ok(())
                }
                SeekResult::NotFound => {
                    tracing::warn!(
                        mms_path = %self.mms_path,
                        entry_id = id.as_u64(),
                        "SetBRCBValues EntryID: not found in the buffer, answering InvalidEntryId"
                    );
                    Err(ApplyEntryIdError::InvalidEntryId)
                }
            }
        };
        Ok(outcome)
    }

    /// Returns the EntryID the client wrote most recently, for GetBRCBValues. It is
    /// the all-zero identifier until a client writes one.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::InvalidModel` when the state mutex is poisoned.
    pub fn last_committed_entry_id(&self) -> Result<EntryId, crate::error::ServerError> {
        let s = self.lock_state()?;
        Ok(s.last_committed_entry_id)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::time::Duration;

    fn make_brcb() -> Brcb {
        Brcb::new("brcb01", "GGIO1$ds1")
            .with_buf_tm_ms(100)
            .with_intg_pd_ms(1000)
            .with_buffer_capacity(8)
            .with_trg_ops(TriggerOptions::DATA_CHANGED | TriggerOptions::GI)
    }

    // ─── ResvTmsState ────────────────────────────────────────────────────────

    #[test]
    fn resv_tms_state_three_variants() {
        // Three variants stand in for the wire values -1, 0, and greater than zero.
        let pre = ResvTmsState::from_wire(-1);
        assert_eq!(pre, ResvTmsState::Preconfigured);
        let none = ResvTmsState::from_wire(0);
        assert_eq!(none, ResvTmsState::NotReserved);
        let with = ResvTmsState::from_wire(10);
        match with {
            ResvTmsState::WithTimeout(s) => assert_eq!(s.get(), 10),
            _ => panic!("expected WithTimeout"),
        }
    }

    #[test]
    fn resv_tms_state_wire_round_trip() {
        // The wire form is unchanged: a value must survive a round trip.
        for v in &[-32768i16, -1, 0, 1, 10, 32767] {
            let s = ResvTmsState::from_wire(*v);
            let w = s.to_wire();
            // Every negative value normalizes to -1.
            if *v < 0 {
                assert_eq!(w, -1, "a negative value normalizes to -1");
            } else {
                assert_eq!(w, *v);
            }
        }
    }

    #[test]
    fn resv_tms_state_is_reserved() {
        assert!(ResvTmsState::Preconfigured.is_reserved());
        assert!(!ResvTmsState::NotReserved.is_reserved());
        assert!(ResvTmsState::WithTimeout(NonZeroU16::new(5).unwrap()).is_reserved());
    }

    // ─── Initialization and state machine ────────────────────────────────────

    #[test]
    fn brcb_state_initial_is_buffering_when_dataset_set() {
        // A valid DatSet starts buffering.
        let brcb = make_brcb();
        let state = BrcbState::from_brcb(&brcb);
        assert!(
            state.is_buffering,
            "a non-empty DatSet must start buffering"
        );
        assert!(!state.rpt_ena);
        assert!(!state.is_resync);
    }

    #[test]
    fn brcb_state_initial_no_buffering_when_dataset_empty() {
        let brcb = Brcb::new("brcb02", ""); // empty data set
        let state = BrcbState::from_brcb(&brcb);
        assert!(
            !state.is_buffering,
            "an empty DatSet must not start buffering"
        );
    }

    #[test]
    fn brcb_state_preconfigured_owner() {
        let brcb = make_brcb().with_preconfigured_owner("192.168.1.10".parse::<IpAddr>().unwrap());
        let state = BrcbState::from_brcb(&brcb);
        assert_eq!(state.resv_tms, ResvTmsState::Preconfigured);
    }

    #[test]
    fn sq_num_is_u16_natural_wrap() {
        // A BRCB sequence number is 16 bits where a URCB uses 8.
        let brcb = make_brcb();
        let mut state = BrcbState::from_brcb(&brcb);
        state.sq_num = u16::MAX;
        let n = state.next_sq_num();
        assert_eq!(n, u16::MAX);
        assert_eq!(state.sq_num, 0, "a 16-bit sequence number wraps to 0");
    }

    #[test]
    fn entry_id_monotone_bump() {
        // Several triggers in one millisecond still get increasing identifiers.
        let brcb = make_brcb();
        let mut state = BrcbState::from_brcb(&brcb);
        let id1 = state.allocate_entry_id(1000);
        let id2 = state.allocate_entry_id(1000); // same millisecond
        let id3 = state.allocate_entry_id(999); // clock steps backwards
        assert_eq!(id1.as_u64(), 1000);
        assert_eq!(
            id2.as_u64(),
            1001,
            "a second call in the same millisecond must add 1"
        );
        assert_eq!(id3.as_u64(), 1002, "a backwards clock must stay monotonic");
    }

    #[test]
    fn entry_id_advances_with_time() {
        let brcb = make_brcb();
        let mut state = BrcbState::from_brcb(&brcb);
        let id1 = state.allocate_entry_id(1000);
        let id2 = state.allocate_entry_id(2000);
        assert_eq!(id1.as_u64(), 1000);
        assert_eq!(id2.as_u64(), 2000);
    }

    // ─── Reservation timer ───────────────────────────────────────────────────

    #[test]
    fn tick_reservation_preconfigured_never_times_out() {
        // A pre-configured owner never times out.
        let brcb = make_brcb().with_preconfigured_owner("10.0.0.1".parse::<IpAddr>().unwrap());
        let mut state = BrcbState::from_brcb(&brcb);
        state.reservation_timeout = Some(Instant::now() - Duration::from_secs(60));
        let fired = state.tick_reservation(Instant::now());
        assert!(!fired, "a preconfigured owner must not time out");
        assert_eq!(state.resv_tms, ResvTmsState::Preconfigured);
    }

    #[test]
    fn tick_reservation_with_timeout_fires_when_expired() {
        // An elapsed timer releases the reservation.
        let brcb = make_brcb();
        let mut state = BrcbState::from_brcb(&brcb);
        state.resv_tms = ResvTmsState::WithTimeout(NonZeroU16::new(5).unwrap());
        state.reservation_timeout = Some(Instant::now() - Duration::from_millis(10));
        let fired = state.tick_reservation(Instant::now());
        assert!(fired, "an elapsed timer must release the reservation");
        assert_eq!(state.resv_tms, ResvTmsState::NotReserved);
        assert!(state.reservation_timeout.is_none());
    }

    #[test]
    fn tick_reservation_not_yet_expired_no_op() {
        let brcb = make_brcb();
        let mut state = BrcbState::from_brcb(&brcb);
        state.resv_tms = ResvTmsState::WithTimeout(NonZeroU16::new(5).unwrap());
        state.reservation_timeout = Some(Instant::now() + Duration::from_secs(60));
        let fired = state.tick_reservation(Instant::now());
        assert!(!fired);
        assert!(matches!(state.resv_tms, ResvTmsState::WithTimeout(_)));
    }

    // ─── set_config_field ────────────────────────────────────────────────────

    #[test]
    fn set_config_field_dat_set_triggers_purge() {
        // Changing DatSet purges the buffer.
        let brcb = make_brcb();
        let rc = BufferedReportControl::new("IED1/LN0$BR$brcb01", brcb);
        // Put a couple of entries in the buffer first.
        rc.enqueue_entry(1000, false, false, Bytes::from_static(b"abc"))
            .unwrap();
        rc.enqueue_entry(1001, false, false, Bytes::from_static(b"def"))
            .unwrap();
        assert_eq!(rc.lock_buffer().unwrap().len(), 2);

        let result = rc
            .set_config_field(BrcbConfigField::DatSet("OtherLN$ds2".into()))
            .unwrap();
        match result {
            ConfigChangeResult::RequiresPurge { purged_entries } => {
                assert_eq!(purged_entries, 2, "changing DatSet must empty the buffer");
            }
            other => panic!("expected RequiresPurge, got {:?}", other),
        }
        assert_eq!(rc.lock_buffer().unwrap().len(), 0);
    }

    #[test]
    fn set_config_field_no_change_returns_no_change() {
        // Writing the value already in place purges nothing.
        let brcb = make_brcb();
        let rc = BufferedReportControl::new("IED1/LN0$BR$brcb01", brcb);
        rc.enqueue_entry(1000, false, false, Bytes::from_static(b"abc"))
            .unwrap();
        let result = rc
            .set_config_field(BrcbConfigField::DatSet("GGIO1$ds1".into())) // same value
            .unwrap();
        assert_eq!(result, ConfigChangeResult::NoChange);
        assert_eq!(rc.lock_buffer().unwrap().len(), 1);
    }

    #[test]
    fn set_config_field_all_fields_purge() {
        // All five fields funnel through the same entry point.
        for field_factory in [
            (|| BrcbConfigField::TrgOps(TriggerOptions::INTEGRITY)) as fn() -> BrcbConfigField,
            || BrcbConfigField::IntgPdMs(5000),
            || BrcbConfigField::BufTmMs(250),
            || BrcbConfigField::RptId("renamed".into()),
        ] {
            let brcb = make_brcb();
            let rc = BufferedReportControl::new("IED1/LN0$BR$brcb01", brcb);
            rc.enqueue_entry(1000, false, false, Bytes::from_static(b"x"))
                .unwrap();
            let result = rc.set_config_field(field_factory()).unwrap();
            assert!(
                matches!(result, ConfigChangeResult::RequiresPurge { .. }),
                "{:?} must trigger a purge",
                field_factory()
            );
            assert_eq!(rc.lock_buffer().unwrap().len(), 0);
        }
    }

    #[test]
    fn set_config_field_blocked_when_enabled() {
        // Configuration may not change while reporting is enabled.
        let brcb = make_brcb();
        let rc = BufferedReportControl::new("IED1/LN0$BR$brcb01", brcb);
        rc.lock_state().unwrap().rpt_ena = true;
        let result = rc.set_config_field(BrcbConfigField::BufTmMs(999));
        assert!(result.is_err());
    }

    // ─── PurgeBuf writes ─────────────────────────────────────────────────────

    #[test]
    fn handle_purge_buf_write_true_purges() {
        let brcb = make_brcb();
        let rc = BufferedReportControl::new("IED1/LN0$BR$brcb01", brcb);
        rc.enqueue_entry(1000, false, false, Bytes::from_static(b"a"))
            .unwrap();
        rc.enqueue_entry(1001, false, false, Bytes::from_static(b"b"))
            .unwrap();
        let purged = rc.handle_purge_buf_write(true).unwrap();
        assert_eq!(purged, 2);
        assert_eq!(rc.lock_buffer().unwrap().len(), 0);
    }

    #[test]
    fn handle_purge_buf_write_false_is_noop() {
        // Writing false has no effect.
        let brcb = make_brcb();
        let rc = BufferedReportControl::new("IED1/LN0$BR$brcb01", brcb);
        rc.enqueue_entry(1000, false, false, Bytes::from_static(b"a"))
            .unwrap();
        let purged = rc.handle_purge_buf_write(false).unwrap();
        assert_eq!(purged, 0);
        assert_eq!(rc.lock_buffer().unwrap().len(), 1);
    }

    #[test]
    fn handle_purge_buf_write_ignored_when_enabled() {
        // A PurgeBuf write is ignored while reporting is enabled.
        let brcb = make_brcb();
        let rc = BufferedReportControl::new("IED1/LN0$BR$brcb01", brcb);
        rc.enqueue_entry(1000, false, false, Bytes::from_static(b"a"))
            .unwrap();
        rc.lock_state().unwrap().rpt_ena = true;
        let purged = rc.handle_purge_buf_write(true).unwrap();
        assert_eq!(purged, 0);
        assert_eq!(rc.lock_buffer().unwrap().len(), 1);
    }

    // ─── enqueue_entry ───────────────────────────────────────────────────────

    #[test]
    fn enqueue_entry_returns_increasing_ids() {
        let brcb = make_brcb();
        let rc = BufferedReportControl::new("IED1/LN0$BR$brcb01", brcb);
        let (id1, evict1) = rc
            .enqueue_entry(1000, false, false, Bytes::from_static(b"a"))
            .unwrap();
        let (id2, evict2) = rc
            .enqueue_entry(1000, false, false, Bytes::from_static(b"b"))
            .unwrap();
        let (id3, evict3) = rc
            .enqueue_entry(1500, false, false, Bytes::from_static(b"c"))
            .unwrap();
        assert!(!evict1 && !evict2 && !evict3);
        assert_eq!(id1.as_u64(), 1000);
        assert_eq!(
            id2.as_u64(),
            1001,
            "the same millisecond bumps the identifier"
        );
        assert_eq!(id3.as_u64(), 1500);
    }

    #[test]
    fn enqueue_entry_evict_oldest_when_full() {
        // A full buffer evicts its oldest entry.
        let brcb = make_brcb().with_buffer_capacity(2);
        let rc = BufferedReportControl::new("IED1/LN0$BR$brcb01", brcb);
        // Clear the initial overflow flag so the eviction is visible.
        rc.lock_buffer().unwrap().clear_overflow();
        rc.enqueue_entry(1000, false, false, Bytes::from_static(b"a"))
            .unwrap();
        rc.enqueue_entry(1001, false, false, Bytes::from_static(b"b"))
            .unwrap();
        let (_id3, evicted) = rc
            .enqueue_entry(1002, false, false, Bytes::from_static(b"c"))
            .unwrap();
        assert!(evicted, "a full buffer must evict on push");
        assert!(
            rc.lock_buffer().unwrap().is_overflow(),
            "an eviction must set overflow"
        );
        assert_eq!(rc.lock_buffer().unwrap().len(), 2);
    }

    // ─── EntryID writes and the on_enqueue hook ──────────────────────────────

    #[test]
    fn apply_entry_id_write_zero_sets_from_head() {
        // An all-zero EntryID selects the head of the buffer and clears is_resync.
        let brcb = make_brcb();
        let rc = BufferedReportControl::new("IED1/LN0$BR$brcb01", brcb);
        rc.enqueue_entry(1000, false, false, Bytes::from_static(b"a"))
            .unwrap();

        let outer = rc.apply_entry_id_write(EntryId::ZERO).unwrap();
        assert_eq!(outer, Ok(()));
        let state = rc.lock_state().unwrap();
        assert_eq!(state.transmit_anchor, TransmitAnchor::FromHead);
        assert!(
            !state.is_resync,
            "the all-zero path must leave is_resync clear"
        );
        assert_eq!(state.last_committed_entry_id, EntryId::ZERO);
    }

    #[test]
    fn apply_entry_id_write_found_with_next_sets_after_entry_id() {
        // An EntryID found with a later entry anchors after it and sets is_resync.
        let brcb = make_brcb();
        let rc = BufferedReportControl::new("IED1/LN0$BR$brcb01", brcb);
        let (id1, _) = rc
            .enqueue_entry(1000, false, false, Bytes::from_static(b"a"))
            .unwrap();
        rc.enqueue_entry(1100, false, false, Bytes::from_static(b"b"))
            .unwrap();

        let outer = rc.apply_entry_id_write(id1).unwrap();
        assert_eq!(outer, Ok(()));
        let state = rc.lock_state().unwrap();
        assert_eq!(state.transmit_anchor, TransmitAnchor::AfterEntryId(id1));
        assert!(state.is_resync);
        assert_eq!(state.last_committed_entry_id, id1);
    }

    #[test]
    fn apply_entry_id_write_found_last_sets_waiting_for_next() {
        // An EntryID found as the newest entry waits for the next enqueue.
        let brcb = make_brcb();
        let rc = BufferedReportControl::new("IED1/LN0$BR$brcb01", brcb);
        rc.enqueue_entry(1000, false, false, Bytes::from_static(b"a"))
            .unwrap();
        let (id_last, _) = rc
            .enqueue_entry(1100, false, false, Bytes::from_static(b"b"))
            .unwrap();

        let outer = rc.apply_entry_id_write(id_last).unwrap();
        assert_eq!(outer, Ok(()));
        let state = rc.lock_state().unwrap();
        assert_eq!(state.transmit_anchor, TransmitAnchor::WaitingForNext);
        assert!(state.is_resync);
    }

    #[test]
    fn apply_entry_id_write_not_found_returns_err() {
        // An EntryID that is not in the buffer is refused.
        let brcb = make_brcb();
        let rc = BufferedReportControl::new("IED1/LN0$BR$brcb01", brcb);
        rc.enqueue_entry(1000, false, false, Bytes::from_static(b"a"))
            .unwrap();
        let bogus = EntryId::from_ms(999_999);

        let outer = rc.apply_entry_id_write(bogus).unwrap();
        assert_eq!(outer, Err(ApplyEntryIdError::InvalidEntryId));
        let state = rc.lock_state().unwrap();
        // The written value is still recorded, so a client reads back what it wrote
        // even though no such entry exists.
        assert_eq!(state.last_committed_entry_id, bogus);
    }

    #[test]
    fn on_enqueue_resolves_waiting_for_next() {
        // A new entry after a WaitingForNext anchor resolves it to
        // AfterEntryId(prev_last).
        let brcb = make_brcb();
        let rc = BufferedReportControl::new("IED1/LN0$BR$brcb01", brcb);
        rc.enqueue_entry(1000, false, false, Bytes::from_static(b"a"))
            .unwrap();
        let (id_last, _) = rc
            .enqueue_entry(1100, false, false, Bytes::from_static(b"b"))
            .unwrap();

        // The client writes EntryID = id_last, giving WaitingForNext.
        let _ = rc.apply_entry_id_write(id_last).unwrap();
        assert_eq!(
            rc.lock_state().unwrap().transmit_anchor,
            TransmitAnchor::WaitingForNext
        );

        // The new entry makes on_enqueue advance the anchor to AfterEntryId(id_last).
        rc.enqueue_entry(1200, false, false, Bytes::from_static(b"c"))
            .unwrap();
        assert_eq!(
            rc.lock_state().unwrap().transmit_anchor,
            TransmitAnchor::AfterEntryId(id_last),
            "on_enqueue must resolve WaitingForNext to AfterEntryId(prev_last)"
        );
    }

    #[test]
    fn on_enqueue_no_op_when_anchor_is_not_waiting() {
        // Any other anchor state is left alone by on_enqueue.
        let brcb = make_brcb();
        let rc = BufferedReportControl::new("IED1/LN0$BR$brcb01", brcb);
        rc.lock_state().unwrap().transmit_anchor = TransmitAnchor::FromHead;
        rc.enqueue_entry(1000, false, false, Bytes::from_static(b"a"))
            .unwrap();
        assert_eq!(
            rc.lock_state().unwrap().transmit_anchor,
            TransmitAnchor::FromHead,
            "FromHead must not be changed by on_enqueue"
        );
    }

    #[test]
    fn last_committed_entry_id_initial_zero() {
        // EntryID reads back as all-zero until a client writes one.
        let brcb = make_brcb();
        let rc = BufferedReportControl::new("IED1/LN0$BR$brcb01", brcb);
        assert_eq!(rc.last_committed_entry_id().unwrap(), EntryId::ZERO);
    }
}
