//! `LogControlBlock` and the runtime `LogControl` of IEC 61850-7-2.
//!
//! `LogControlBlock` is the static definition and `LogControl` the runtime object.
//! The nine MMS attributes of a log control block are LogEna, LogRef, DatSet,
//! OldEntrTm, NewEntrTm, OldEntr, NewEntr, TrgOps, and IntgPd.
//!
//! A log control block is pull-based: a trigger writes an entry into persistent
//! storage and a client fetches entries with ReadJournal. Nothing is pushed, there
//! is no report sink, and there is no server-side buffer with resynchronization or
//! segmentation, which is what distinguishes it from a buffered report control
//! block.
//!
//! ```text
//!     [NOT_ENABLED]                          [ENABLED]
//!         |                                    |
//!         |  Write LogEna=true                 |  Write LogEna=false
//!         |  (dataSet != None &&               |
//!         |   storage != None)                 |
//!         +------------ → ENABLED              +-- → NOT_ENABLED
//! ```
//!
//! A control block whose definition sets LogEna starts in ENABLED as soon as
//! it has both a data set and a storage backend.

use super::storage::{EntryId, LogEntryVisitor, LogStorage, LogStorageError};
use crate::flags::TriggerOptions;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// The LogEna attribute of a log control block.
///
/// An enum rather than a boolean, so a third state such as a pre-configured owner
/// could be added without changing the type, as the buffered report control block
/// does for its reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogEna {
    /// Logging is disabled.
    #[default]
    Disabled,
    /// Logging is enabled.
    Enabled,
}

/// State of a log control block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogState {
    /// LogEna is false, the default: a trigger writes nothing.
    #[default]
    NotEnabled,
    /// LogEna is true: a trigger writes to storage.
    Enabled,
}

/// Static definition of a log control block.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LogControlBlock {
    /// Control block name, for example `"lcb01"`.
    pub name: String,
    /// Referenced data set; `None` when none is configured.
    pub dataset_name: Option<String>,
    /// Configured LogRef; `None` selects the default `<LN>$GeneralLog`.
    pub log_ref: Option<String>,
    /// Configured trigger options.
    pub trg_ops: TriggerOptions,
    /// Integrity period, in milliseconds.
    pub intg_period_ms: u32,
    /// Configured LogEna; defaults to true, as the `logEna` attribute of an SCL
    /// `LogControl` does.
    ///
    /// When true, the runtime control block starts enabled once it has both a
    /// data set and a storage backend, which `LogControl::with_storage`
    /// completes; when false, it starts disabled until LogEna is written.
    pub default_enabled: bool,
    /// Whether an entry carries its reason code.
    pub include_reason_code: bool,
}

impl LogControlBlock {
    /// Creates a log control block definition with default field values.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            dataset_name: None,
            log_ref: None,
            trg_ops: TriggerOptions::DATA_CHANGED,
            intg_period_ms: 0,
            default_enabled: true,
            include_reason_code: true,
        }
    }

    /// Sets the referenced data set.
    pub fn with_dataset(mut self, ds: impl Into<String>) -> Self {
        self.dataset_name = Some(ds.into());
        self
    }

    /// Sets LogRef.
    pub fn with_log_ref(mut self, lr: impl Into<String>) -> Self {
        self.log_ref = Some(lr.into());
        self
    }

    /// Sets the trigger options.
    pub fn with_trg_ops(mut self, ops: TriggerOptions) -> Self {
        self.trg_ops = ops;
        self
    }

    /// Sets the integrity period, in milliseconds.
    pub fn with_intg_pd_ms(mut self, ms: u32) -> Self {
        self.intg_period_ms = ms;
        self
    }

    /// Sets the configured LogEna.
    pub fn with_default_enabled(mut self, on: bool) -> Self {
        self.default_enabled = on;
        self
    }
}

/// Runtime log control block.
///
/// The storage backend is shared through an `Arc`, so several control blocks may
/// write into the same log.
#[non_exhaustive]
pub struct LogControl {
    /// Full key in the MMS namespace, for example `"IED1LD0/MMXU1$LG$lcb01"`.
    pub mms_path: String,
    /// Static definition, read-only after construction.
    pub lcb: LogControlBlock,
    /// Mutable runtime state.
    pub state: Mutex<LogControlState>,
    /// Storage backend. When it is `None` a trigger writes nothing and logs a
    /// warning.
    pub storage: Option<Arc<dyn LogStorage>>,
}

impl std::fmt::Debug for LogControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogControl")
            .field("mms_path", &self.mms_path)
            .field("lcb_name", &self.lcb.name)
            .field("has_storage", &self.storage.is_some())
            .finish()
    }
}

/// Mutable runtime state of a log control block.
#[derive(Debug)]
#[non_exhaustive]
pub struct LogControlState {
    /// Current LogEna state.
    pub log_ena: LogState,
    /// Current LogRef; `None` selects the default.
    pub log_ref: Option<String>,
    /// Referenced data set; `None` when none is configured.
    pub data_set: Option<String>,
    /// Current trigger options.
    pub trg_ops: TriggerOptions,
    /// Current integrity period, in milliseconds.
    pub intg_period_ms: u32,
    /// Start of the current integrity period: when the control block was
    /// enabled or last wrote an integrity entry.
    intg_since: Option<Instant>,
}

impl LogControl {
    /// Creates a runtime control block with no storage bound. It starts
    /// disabled, since enabling requires a storage backend; `with_storage`
    /// enables it when the definition sets LogEna and names a data set.
    pub fn new(mms_path: impl Into<String>, lcb: LogControlBlock) -> Self {
        let state = LogControlState {
            log_ena: LogState::NotEnabled,
            log_ref: lcb.log_ref.clone(),
            data_set: lcb.dataset_name.clone(),
            trg_ops: lcb.trg_ops,
            intg_period_ms: lcb.intg_period_ms,
            intg_since: None,
        };
        Self {
            mms_path: mms_path.into(),
            lcb,
            state: Mutex::new(state),
            storage: None,
        }
    }

    /// Binds the storage backend.
    ///
    /// A control block whose definition sets LogEna and that names a data set is
    /// enabled here, as a server enables such a control block at start-up
    /// (IEC 61850-7-2 LogEna; IEC 61850-6 `LogControl`).
    pub fn with_storage(mut self, storage: Arc<dyn LogStorage>) -> Self {
        self.storage = Some(storage);
        let default_enabled = self.lcb.default_enabled;
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if default_enabled && state.data_set.is_some() {
            state.log_ena = LogState::Enabled;
            state.intg_since = Some(Instant::now());
        }
        self
    }

    /// Sets LogEna.
    ///
    /// Enabling requires both a data set and a storage backend; disabling is always
    /// accepted.
    ///
    /// # Errors
    ///
    /// Returns a message describing what is missing, which the caller answers with
    /// `DataAccessError::ObjectAttributeInconsistent`, or that the state mutex is
    /// poisoned.
    pub fn set_log_ena(&self, on: bool) -> Result<(), &'static str> {
        let mut s = self
            .state
            .lock()
            .map_err(|_| "log control state mutex poisoned")?;
        if on {
            if s.data_set.is_none() {
                return Err("LogEna cannot be set while no data set is configured");
            }
            if self.storage.is_none() {
                return Err("LogEna cannot be set while no storage backend is bound");
            }
            if s.log_ena != LogState::Enabled {
                s.log_ena = LogState::Enabled;
                s.intg_since = Some(Instant::now());
            }
        } else {
            s.log_ena = LogState::NotEnabled;
            s.intg_since = None;
        }
        Ok(())
    }

    /// Returns whether logging is enabled, which the trigger path checks.
    pub fn is_enabled(&self) -> bool {
        self.state
            .lock()
            .map(|s| matches!(s.log_ena, LogState::Enabled))
            .unwrap_or(false)
    }

    /// Writes one entry holding `data`, each value with `reason_code`; the
    /// trigger paths of the server are its only callers.
    ///
    /// A disabled control block writes nothing and returns `Ok(None)`. A control
    /// block with no storage bound logs a warning and returns `Ok(None)` rather
    /// than failing. Otherwise the entry is written with
    /// `LogStorage::add_entry_with_data`, as one unit, and its identifier is
    /// returned.
    ///
    /// # Errors
    ///
    /// Returns the `LogStorageError` the backend reports.
    #[cfg(any(feature = "full-server", test))]
    pub(crate) fn write_entry(
        &self,
        time_ms: u64,
        data: &[(String, iec61850_model::MmsValue)],
        reason_code: u8,
    ) -> Result<Option<EntryId>, LogStorageError> {
        if !self.is_enabled() {
            return Ok(None);
        }
        let Some(storage) = self.storage.clone() else {
            tracing::warn!(
                mms_path = %self.mms_path,
                "log control has no storage bound, trigger skipped"
            );
            return Ok(None);
        };
        let data: Vec<super::storage::JournalEntryData> = data
            .iter()
            .map(|(data_ref, value)| {
                super::storage::JournalEntryData::new(data_ref.clone(), value.clone(), reason_code)
            })
            .collect();
        storage.add_entry_with_data(time_ms, &data).map(Some)
    }

    /// Writes one entry holding `data`, each data set member with its own
    /// reason code, when the control block is enabled and has a storage bound;
    /// otherwise writes nothing and returns `Ok(None)`.
    #[cfg(feature = "full-server")]
    pub(crate) fn write_members(
        &self,
        time_ms: u64,
        data: &[(String, iec61850_model::MmsValue, u8)],
    ) -> Result<Option<EntryId>, LogStorageError> {
        if !self.is_enabled() {
            return Ok(None);
        }
        let Some(storage) = self.storage.clone() else {
            tracing::warn!(
                mms_path = %self.mms_path,
                "log control has no storage bound, trigger skipped"
            );
            return Ok(None);
        };
        let data: Vec<super::storage::JournalEntryData> = data
            .iter()
            .map(|(data_ref, value, reason_code)| {
                super::storage::JournalEntryData::new(data_ref.clone(), value.clone(), *reason_code)
            })
            .collect();
        storage.add_entry_with_data(time_ms, &data).map(Some)
    }

    /// Reports whether an integrity entry is due at `now`; when it is, returns
    /// the data set to log and starts the next integrity period from `now`.
    ///
    /// An entry is due when the control block is enabled, its TrgOps hold
    /// integrity, its IntgPd is above zero, and IntgPd milliseconds have passed
    /// since it was enabled or last wrote an integrity entry. While it is
    /// enabled but not set up for integrity, its period keeps restarting from
    /// `now`, so the first entry comes one IntgPd after integrity is set up.
    #[cfg(any(feature = "full-server", test))]
    pub(crate) fn integrity_due(&self, now: Instant) -> Option<String> {
        let mut s = self.state.lock().ok()?;
        if s.log_ena != LogState::Enabled {
            return None;
        }
        if !s.trg_ops.contains(TriggerOptions::INTEGRITY) || s.intg_period_ms == 0 {
            s.intg_since = Some(now);
            return None;
        }
        let period = std::time::Duration::from_millis(u64::from(s.intg_period_ms));
        match s.intg_since {
            Some(since) if now >= since + period => {
                s.intg_since = Some(now);
                s.data_set.clone()
            }
            Some(_) => None,
            None => {
                s.intg_since = Some(now);
                None
            }
        }
    }

    /// Visits the entries within a time range.
    ///
    /// A control block with no storage bound visits nothing. This is the path a
    /// ReadJournal request takes on the server side.
    ///
    /// # Errors
    ///
    /// Returns the `LogStorageError` the backend reports.
    pub fn query_by_time(
        &self,
        start_ms: u64,
        end_ms: u64,
        visitor: &mut dyn LogEntryVisitor,
    ) -> Result<(), LogStorageError> {
        let Some(storage) = self.storage.as_ref() else {
            return Ok(());
        };
        storage.query_by_time(start_ms, end_ms, visitor)
    }

    /// Visits the entries after a given time and entry identifier.
    ///
    /// A control block with no storage bound visits nothing.
    ///
    /// # Errors
    ///
    /// Returns the `LogStorageError` the backend reports.
    pub fn query_after(
        &self,
        starting_time_ms: u64,
        entry_id: EntryId,
        visitor: &mut dyn LogEntryVisitor,
    ) -> Result<(), LogStorageError> {
        let Some(storage) = self.storage.as_ref() else {
            return Ok(());
        };
        storage.query_after(starting_time_ms, entry_id, visitor)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::storage::{CollectingVisitor, InMemoryLogStorage, JournalEntryData};
    use iec61850_model::MmsValue;
    use std::time::Duration;

    /// A control block with a data set and storage whose definition clears
    /// LogEna, so it starts disabled.
    fn make_lcb_with_storage() -> LogControl {
        let storage = Arc::new(InMemoryLogStorage::new()) as Arc<dyn LogStorage>;
        let lcb = LogControlBlock::new("lcb01")
            .with_dataset("MMXU1$ds1")
            .with_log_ref("IED1LD0/MMXU1$GeneralLog")
            .with_trg_ops(TriggerOptions::DATA_CHANGED)
            .with_default_enabled(false);
        LogControl::new("IED1LD0/MMXU1$LG$lcb01", lcb).with_storage(storage)
    }

    fn write_one(lc: &LogControl, time_ms: u64, value: MmsValue) -> Option<EntryId> {
        lc.write_entry(time_ms, &[("ref1".to_string(), value)], 0x02)
            .unwrap()
    }

    #[test]
    fn configured_log_ena_enables_once_data_set_and_storage_are_bound() {
        let storage = Arc::new(InMemoryLogStorage::new()) as Arc<dyn LogStorage>;
        let lcb = LogControlBlock::new("lcb01").with_dataset("MMXU1$ds1");
        assert!(lcb.default_enabled, "LogEna defaults to true, as in SCL");
        let lc = LogControl::new("IED1LD0/MMXU1$LG$lcb01", lcb);
        assert!(!lc.is_enabled(), "no storage is bound yet");
        let lc = lc.with_storage(storage);
        assert!(lc.is_enabled());
    }

    #[test]
    fn configured_log_ena_needs_a_data_set() {
        let storage = Arc::new(InMemoryLogStorage::new()) as Arc<dyn LogStorage>;
        let lc = LogControl::new("IED1LD0/MMXU1$LG$lcb01", LogControlBlock::new("lcb01"))
            .with_storage(storage);
        assert!(!lc.is_enabled());
    }

    #[test]
    fn cleared_log_ena_starts_disabled() {
        assert!(!make_lcb_with_storage().is_enabled());
    }

    fn integrity_lcb(intg_pd_ms: u32) -> LogControl {
        let storage = Arc::new(InMemoryLogStorage::new()) as Arc<dyn LogStorage>;
        let lcb = LogControlBlock::new("lcb01")
            .with_dataset("MMXU1$ds1")
            .with_trg_ops(TriggerOptions::INTEGRITY)
            .with_intg_pd_ms(intg_pd_ms);
        LogControl::new("IED1LD0/MMXU1$LG$lcb01", lcb).with_storage(storage)
    }

    #[test]
    fn integrity_is_due_once_per_period_from_enabling() {
        let lc = integrity_lcb(1_000);
        let t0 = Instant::now();
        assert_eq!(lc.integrity_due(t0), None);
        let due = t0 + Duration::from_millis(1_000);
        assert_eq!(lc.integrity_due(due), Some("MMXU1$ds1".to_string()));
        assert_eq!(
            lc.integrity_due(due),
            None,
            "the next period starts at once"
        );
        assert_eq!(lc.integrity_due(due + Duration::from_millis(999)), None);
        assert_eq!(
            lc.integrity_due(due + Duration::from_millis(1_000)),
            Some("MMXU1$ds1".to_string())
        );
    }

    #[test]
    fn integrity_is_never_due_without_the_trigger_or_a_period() {
        let later = Instant::now() + Duration::from_secs(3_600);
        assert_eq!(integrity_lcb(0).integrity_due(later), None);

        let storage = Arc::new(InMemoryLogStorage::new()) as Arc<dyn LogStorage>;
        let lcb = LogControlBlock::new("lcb01")
            .with_dataset("MMXU1$ds1")
            .with_trg_ops(TriggerOptions::DATA_CHANGED | TriggerOptions::GI)
            .with_intg_pd_ms(1_000);
        let lc = LogControl::new("IED1LD0/MMXU1$LG$lcb01", lcb).with_storage(storage);
        assert_eq!(lc.integrity_due(later), None);
    }

    #[test]
    fn integrity_period_restarts_when_logging_is_enabled_again() {
        let lc = integrity_lcb(1_000);
        lc.set_log_ena(false).unwrap();
        let later = Instant::now() + Duration::from_secs(3_600);
        assert_eq!(
            lc.integrity_due(later),
            None,
            "a disabled block logs nothing"
        );
        lc.set_log_ena(true).unwrap();
        let t1 = Instant::now();
        assert_eq!(lc.integrity_due(t1 + Duration::from_millis(500)), None);
        assert!(lc
            .integrity_due(t1 + Duration::from_millis(1_000))
            .is_some());
    }

    #[test]
    fn an_entry_holds_every_value_given() {
        let lc = make_lcb_with_storage();
        lc.set_log_ena(true).unwrap();
        lc.write_entry(
            10,
            &[
                ("a".to_string(), MmsValue::Boolean(true)),
                ("b".to_string(), MmsValue::Integer(7)),
            ],
            0x10,
        )
        .unwrap()
        .expect("an entry");
        let mut v = CollectingVisitor::new();
        lc.query_by_time(0, 9999, &mut v).unwrap();
        assert_eq!(v.entries.len(), 1);
        let refs: Vec<_> = v.entries[0]
            .variables
            .iter()
            .map(|d| (d.data_ref.as_str(), d.reason_code))
            .collect();
        assert_eq!(refs, vec![("a", 0x10), ("b", 0x10)]);
    }

    #[test]
    fn enable_with_dataset_and_storage_succeeds() {
        let lc = make_lcb_with_storage();
        assert!(lc.set_log_ena(true).is_ok());
        assert!(lc.is_enabled());
    }

    #[test]
    fn enable_without_storage_fails() {
        let lcb = LogControlBlock::new("lcb01").with_dataset("MMXU1$ds1");
        let lc = LogControl::new("IED1LD0/MMXU1$LG$lcb01", lcb);
        let r = lc.set_log_ena(true);
        assert!(
            r.is_err(),
            "LogEna=true must fail while no storage is bound"
        );
    }

    #[test]
    fn enable_without_dataset_fails() {
        let storage = Arc::new(InMemoryLogStorage::new()) as Arc<dyn LogStorage>;
        let lcb = LogControlBlock::new("lcb01"); // no dataset
        let lc = LogControl::new("IED1LD0/MMXU1$LG$lcb01", lcb).with_storage(storage);
        let r = lc.set_log_ena(true);
        assert!(
            r.is_err(),
            "LogEna=true must fail while no data set is configured"
        );
    }

    #[test]
    fn disable_always_allowed() {
        let lc = make_lcb_with_storage();
        lc.set_log_ena(true).unwrap();
        assert!(lc.set_log_ena(false).is_ok());
        assert!(!lc.is_enabled());
    }

    #[test]
    fn log_value_when_disabled_returns_none() {
        let lc = make_lcb_with_storage();
        // The control block starts disabled.
        let r = write_one(&lc, 1000, MmsValue::Boolean(true));
        assert!(
            r.is_none(),
            "a disabled control block must not write an entry"
        );
    }

    #[test]
    fn log_value_when_enabled_writes_entry() {
        let lc = make_lcb_with_storage();
        lc.set_log_ena(true).unwrap();
        let id = write_one(&lc, 1000, MmsValue::Boolean(true));
        assert!(id.is_some());

        let mut v = CollectingVisitor::new();
        lc.query_by_time(0, 9999, &mut v).unwrap();
        assert_eq!(v.entries.len(), 1);
        assert_eq!(v.entries[0].variables[0].data_ref, "ref1");
    }

    #[test]
    fn query_after_round_trip() {
        let lc = make_lcb_with_storage();
        lc.set_log_ena(true).unwrap();
        let id1 = write_one(&lc, 100, MmsValue::Integer(1)).unwrap();
        let id2 = write_one(&lc, 200, MmsValue::Integer(2)).unwrap();
        let id3 = write_one(&lc, 300, MmsValue::Integer(3)).unwrap();
        let _ = (id2, id3);

        // Everything after id1, which is id2 and id3.
        let mut v = CollectingVisitor::new();
        lc.query_after(0, id1, &mut v).unwrap();
        assert_eq!(v.entries.len(), 2);
    }

    /// An entry is written through the whole-entry method of the backend, so
    /// a backend that writes it at once never leaves part of it behind.
    #[test]
    fn an_entry_is_written_as_one_unit() {
        #[derive(Debug, Default)]
        struct WholeOnly {
            written: Mutex<Vec<(u64, usize)>>,
        }
        impl LogStorage for WholeOnly {
            fn add_entry(&self, _: u64) -> Result<EntryId, LogStorageError> {
                Err(LogStorageError::Backend("piecewise write".into()))
            }
            fn add_entry_data(
                &self,
                _: EntryId,
                _: &str,
                _: MmsValue,
                _: u8,
            ) -> Result<(), LogStorageError> {
                Err(LogStorageError::Backend("piecewise write".into()))
            }
            fn add_entry_with_data(
                &self,
                time_ms: u64,
                data: &[JournalEntryData],
            ) -> Result<EntryId, LogStorageError> {
                self.written.lock().unwrap().push((time_ms, data.len()));
                Ok(EntryId(1))
            }
            fn query_by_time(
                &self,
                _: u64,
                _: u64,
                _: &mut dyn LogEntryVisitor,
            ) -> Result<(), LogStorageError> {
                Ok(())
            }
            fn query_after(
                &self,
                _: u64,
                _: EntryId,
                _: &mut dyn LogEntryVisitor,
            ) -> Result<(), LogStorageError> {
                Ok(())
            }
            fn oldest_and_newest(
                &self,
            ) -> Result<
                Option<(
                    super::super::storage::EntryMeta,
                    super::super::storage::EntryMeta,
                )>,
                LogStorageError,
            > {
                Ok(None)
            }
            fn count(&self) -> usize {
                0
            }
        }
        let storage = Arc::new(WholeOnly::default());
        let lcb = LogControlBlock::new("lcb01").with_dataset("MMXU1$ds1");
        let lc = LogControl::new("IED1LD0/MMXU1$LG$lcb01", lcb)
            .with_storage(storage.clone() as Arc<dyn LogStorage>);
        lc.write_entry(
            5,
            &[
                ("a".to_string(), MmsValue::Boolean(true)),
                ("b".to_string(), MmsValue::Integer(7)),
            ],
            0x10,
        )
        .expect("the whole-entry write succeeds");
        assert_eq!(*storage.written.lock().unwrap(), [(5, 2)]);
    }

    /// An error part way through writing an entry is
    /// propagated instead of leaving a partially written entry behind.
    #[test]
    fn error_is_propagated_not_partial_state() {
        // A storage backend that always fails.
        #[derive(Debug)]
        struct FailStorage;
        impl LogStorage for FailStorage {
            fn add_entry(&self, _: u64) -> Result<EntryId, LogStorageError> {
                Err(LogStorageError::Backend("simulated".into()))
            }
            fn add_entry_data(
                &self,
                _: EntryId,
                _: &str,
                _: MmsValue,
                _: u8,
            ) -> Result<(), LogStorageError> {
                Err(LogStorageError::Backend("simulated".into()))
            }
            fn query_by_time(
                &self,
                _: u64,
                _: u64,
                _: &mut dyn LogEntryVisitor,
            ) -> Result<(), LogStorageError> {
                Ok(())
            }
            fn query_after(
                &self,
                _: u64,
                _: EntryId,
                _: &mut dyn LogEntryVisitor,
            ) -> Result<(), LogStorageError> {
                Ok(())
            }
            fn oldest_and_newest(
                &self,
            ) -> Result<
                Option<(
                    super::super::storage::EntryMeta,
                    super::super::storage::EntryMeta,
                )>,
                LogStorageError,
            > {
                Ok(None)
            }
            fn count(&self) -> usize {
                0
            }
        }
        let storage = Arc::new(FailStorage) as Arc<dyn LogStorage>;
        let lcb = LogControlBlock::new("lcb01").with_dataset("MMXU1$ds1");
        let lc = LogControl::new("IED1LD0/MMXU1$LG$lcb01", lcb).with_storage(storage);
        lc.set_log_ena(true).unwrap();
        let r = lc.write_entry(1000, &[("ref1".to_string(), MmsValue::Boolean(true))], 0x02);
        assert!(
            r.is_err(),
            "a storage failure must be propagated, with no partial state"
        );
    }
}
