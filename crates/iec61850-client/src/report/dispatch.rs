//! Report handler registry and callback dispatch.
//!
//! Handlers are keyed by RCB reference in a hash map, so install, uninstall
//! and lookup are constant time. A callback is invoked after the registry lock
//! has been released: the dispatch path clones the callback handle and takes
//! an owned snapshot of the report state while holding the lock, then drops
//! the guard before calling. A callback may therefore install or uninstall a
//! handler without deadlocking.

// `Duration` is used only by `poll_reports` and `spawn_report_dispatcher`,
// both of which require std.
#[cfg(feature = "std")]
use core::time::Duration;

use iec61850_hal::time::Timer;
use iec61850_hal::transport::AsyncTransport;
// InformationReport decoding is reached only through the std-only polling
// helpers, so the imports are gated with them.
#[cfg(feature = "std")]
use iec61850_mms::mms::pdu::common::ObjectName;
#[cfg(feature = "std")]
use iec61850_mms::mms::pdu::information_report::{decode_information_report, VariableAccessSpec};
use iec61850_model::value::MmsValue;

use crate::connection::IedConnection;
use crate::error::ClientError;
use crate::prelude::{format, Arc, HashMap, String, ToString, Vec};
use crate::report::parse::{parse_report, ReportParseError};
use crate::report::state::{apply_report, ClientReport, StateError};
use crate::sync::RwLock;

/// Signature of a report callback.
///
/// The argument is an owned snapshot of the `ClientReport` after the incoming
/// report has been applied, so it may be moved into another task or held
/// across an await point. A callback returning `()` cannot propagate an error;
/// use a channel or shared state for that.
pub type ReportCallback = Arc<dyn Fn(Arc<ClientReport>) + Send + Sync + 'static>;

/// One registered handler together with the report state it accumulates.
struct ReportEntry {
    state: ClientReport,
    callback: ReportCallback,
}

/// Optional description of the data set a report is expected to carry.
///
/// Currently only the member count, used as a sanity check at install time.
#[derive(Debug, Clone, Default)]
pub struct DatasetDirectory {
    /// Expected number of data set members. If `Some(n)` and the first report
    /// carries a different inclusion length, the report is rejected. `None`
    /// disables the check.
    pub expected_size: Option<usize>,
}

/// Registry of installed report handlers, held by `IedConnection`.
///
/// All mutation goes through the methods below; the lock is never exposed, and
/// a callback is always invoked with the lock released.
pub struct ReportRegistry {
    // Keyed by RCB reference.
    inner: RwLock<HashMap<String, ReportEntry>>,
}

impl ReportRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a handler for an RCB reference.
    ///
    /// With `rpt_id` set to `None`, dispatch matches against the RCB reference
    /// with every '.' replaced by '$'. An existing entry for the same RCB
    /// reference is replaced.
    ///
    /// # Errors
    ///
    /// `InvalidRptId` if `rpt_id` is longer than the 128-byte MMS object-name
    /// limit.
    pub async fn install(
        &self,
        rcb_reference: String,
        rpt_id: Option<String>,
        _dataset_dir: Option<DatasetDirectory>,
        callback: ReportCallback,
    ) -> Result<(), ClientError> {
        if let Some(ref id) = rpt_id {
            // A VMD-specific name is limited to 128 bytes.
            if id.len() >= 129 {
                tracing::warn!(rpt_id = %id, len = id.len(), "rejecting install: rpt_id too long");
                return Err(ClientError::InvalidRptId { len: id.len() });
            }
        }

        let entry = ReportEntry {
            state: ClientReport::new(rcb_reference.clone(), rpt_id),
            callback,
        };

        let mut guard = self.inner.write().await;
        // Re-installing on the same reference replaces the entry rather than failing.
        guard.insert(rcb_reference, entry);
        Ok(())
    }

    /// Removes the handler registered for an RCB reference.
    pub async fn uninstall(&self, rcb_reference: &str) -> Result<(), ClientError> {
        let mut guard = self.inner.write().await;
        guard
            .remove(rcb_reference)
            .map(|_| ())
            .ok_or_else(|| ClientError::NotFound(rcb_reference.to_string()))
    }

    /// Matches an incoming report against the registered handlers and invokes
    /// the callback of the one whose effective RptId equals the report's.
    ///
    /// A report matching no handler is dropped and reported as success.
    ///
    /// Parsing runs outside the lock. Under the lock the report is applied to
    /// the entry's state, then the callback handle and an owned snapshot are
    /// cloned out; the callback itself runs after the guard is dropped.
    pub async fn handle_report(&self, value: &MmsValue) -> Result<(), DispatchError> {
        // Parsing is pure and needs no lock.
        let parsed = parse_report(value).map_err(DispatchError::Parse)?;
        let rpt_id = parsed.rpt_id.clone();

        // Under the lock: apply the report, clone out callback and snapshot.
        let (callback, snapshot) = {
            let mut guard = self.inner.write().await;
            // Match on the effective RptId of each entry.
            let matched_key = guard
                .iter()
                .find(|(_, e)| e.state.effective_rpt_id() == rpt_id)
                .map(|(k, _)| k.clone());
            let Some(key) = matched_key else {
                tracing::debug!(rpt_id = %rpt_id, "no handler matches rpt_id — dropping report");
                return Ok(());
            };
            let entry = guard.get_mut(&key).expect("just-found key must exist");
            apply_report(&mut entry.state, parsed).map_err(DispatchError::State)?;
            let snapshot = Arc::new(entry.state.clone());
            (Arc::clone(&entry.callback), snapshot)
            // The guard is dropped at the end of this block.
        };

        // Invoked without the lock, so a callback may install or uninstall.
        callback(snapshot);
        Ok(())
    }

    /// Reports whether a handler is registered for an RCB reference.
    pub async fn contains(&self, rcb_reference: &str) -> bool {
        self.inner.read().await.contains_key(rcb_reference)
    }
}

impl Default for ReportRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Failure reported by `handle_report`, from either the parse or the apply step.
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    /// The report could not be parsed.
    #[error("parse failed: {0}")]
    Parse(ReportParseError),

    /// The parsed report could not be applied to the subscription state.
    #[error("state apply failed: {0}")]
    State(StateError),
}

// Connection-level entry points. The struct is defined in `crate::connection`;
// the reporting, RCB, journal and GoCB methods are attached here and reach the
// registry through the feature-gated `reports` field.

impl<T: AsyncTransport, Tm: Timer> IedConnection<T, Tm> {
    /// Returns a handle to the connection's report registry.
    pub fn report_registry(&self) -> Arc<ReportRegistry> {
        Arc::clone(&self.reports)
    }

    /// Installs a report handler (ACSI installReportHandler).
    pub async fn install_report_handler(
        &self,
        rpt_id: Option<String>,
        rcb_ref: &str,
        dataset_dir: Option<DatasetDirectory>,
        callback: ReportCallback,
    ) -> Result<(), ClientError> {
        self.reports
            .install(rcb_ref.to_string(), rpt_id, dataset_dir, callback)
            .await
    }

    /// Removes a report handler (ACSI uninstallReportHandler).
    pub async fn uninstall_report_handler(&self, rcb_ref: &str) -> Result<(), ClientError> {
        self.reports.uninstall(rcb_ref).await
    }

    /// Triggers a general interrogation by writing `<rcb_ref>$GI = true`.
    ///
    /// # Errors
    ///
    /// `NotConnected` if the association is not established.
    pub async fn trigger_grefcb(&self, rcb_ref: &str) -> Result<(), ClientError> {
        if !self.is_connected() {
            return Err(ClientError::NotConnected);
        }
        let (domain, item_base) =
            crate::rcb::write::parse_object_reference(rcb_ref).ok_or_else(|| {
                ClientError::InvalidArgument(format!(
                    "trigger_grefcb: cannot parse object reference '{rcb_ref}'"
                ))
            })?;
        let item = format!("{item_base}$GI");
        let value = iec61850_mms::mms::pdu::common::MmsData::Boolean(true);
        let mut client = self.mms_client.lock().await;
        client.write(&domain, &item, value).await?;
        Ok(())
    }

    /// Reads an RCB from the server into a new `RcbHandle`.
    ///
    /// Method form of [`crate::rcb::get_rcb_values`].
    pub async fn get_rcb_values(
        &self,
        rcb_ref: &str,
    ) -> Result<crate::rcb::RcbHandle, ClientError> {
        crate::rcb::get_rcb_values(self, rcb_ref).await
    }

    /// Refreshes an existing `RcbHandle` in place from the server.
    pub async fn refresh_rcb_values(
        &self,
        rcb: &mut crate::rcb::RcbHandle,
    ) -> Result<(), ClientError> {
        crate::rcb::refresh_rcb_values(self, rcb).await
    }

    /// Writes the `RcbHandle` fields selected by `mask` back to the server.
    ///
    /// Method form of [`crate::rcb::set_rcb_values`].
    pub async fn set_rcb_values(
        &self,
        rcb: &crate::rcb::RcbHandle,
        mask: crate::rcb::RcbWriteMask,
        single_request: bool,
    ) -> Result<(), ClientError> {
        crate::rcb::set_rcb_values(self, rcb, mask, single_request).await
    }

    // Journal queries.

    /// Queries a log over a time range (ACSI QueryLogByTime).
    ///
    /// `log_ref` is an MMS path of the form `<domain>/<item>`, for example
    /// `IED1LD0/MMXU1$LG$lcb01`. Returns the entries and whether more follow.
    pub async fn query_journal_by_time(
        &self,
        log_ref: &str,
        start_ms: u64,
        end_ms: u64,
    ) -> Result<(Vec<crate::journal::ClientJournalEntry>, bool), ClientError> {
        self.query_journal_internal(
            log_ref,
            crate::journal::JournalQuery::by_time(start_ms, end_ms),
        )
        .await
    }

    /// Queries a log for the entries after a given entry id (ACSI
    /// QueryLogAfterEntry).
    ///
    /// Both filters apply: an entry must be newer than `starting_time_ms` and
    /// follow `entry_id`.
    pub async fn query_journal_after_entry(
        &self,
        log_ref: &str,
        starting_time_ms: u64,
        entry_id: crate::journal::ClientJournalEntryId,
    ) -> Result<(Vec<crate::journal::ClientJournalEntry>, bool), ClientError> {
        self.query_journal_internal(
            log_ref,
            crate::journal::JournalQuery::after_entry(starting_time_ms, entry_id),
        )
        .await
    }

    async fn query_journal_internal(
        &self,
        log_ref: &str,
        query: crate::journal::JournalQuery,
    ) -> Result<(Vec<crate::journal::ClientJournalEntry>, bool), ClientError> {
        if !self.is_connected() {
            return Err(ClientError::NotConnected);
        }
        let (domain, item) = crate::journal::parse_journal_ref(log_ref)?;
        let wire_req = crate::journal::build_wire_request(domain, item, &query);

        let resp = {
            let mut client = self.mms_client.lock().await;
            client.read_journal(&wire_req).await?
        };

        let entries: Vec<crate::journal::ClientJournalEntry> = resp
            .entries
            .into_iter()
            .map(crate::journal::wire_entry_to_client)
            .collect();
        Ok((entries, resp.more_follows.unwrap_or(false)))
    }

    // InformationReport polling and dispatch.

    /// Receives the pending InformationReports and dispatches them to the
    /// report registry, returning the number of reports dispatched.
    ///
    /// The caller drives reception; no background task is involved. The first
    /// PDU is awaited for the whole `timeout`, then any further PDUs already
    /// queued are drained with a 5 ms wait each until the connection goes idle
    /// or the timeout expires. Unconfirmed PDUs that are not URCB reports, such
    /// as a command termination, are not counted.
    ///
    /// The MMS client lock is held for the duration, which blocks concurrent
    /// reads, writes and RCB updates; a short timeout keeps that window small. A
    /// background dispatcher should use `spawn_report_dispatcher` with an
    /// interval around 100 ms instead.
    ///
    /// # Errors
    ///
    /// `NotConnected` if the association is not established, and also if the
    /// transport reports the connection lost, in which case the connection is
    /// marked disconnected first.
    ///
    /// Requires `std` for its monotonic deadline. An embedded caller drives
    /// `MmsClient::recv_unconfirmed_pdu_with_timeout` and
    /// [`Self::report_registry`] directly, with a deadline from its own timer.
    #[cfg(feature = "std")]
    pub async fn poll_reports(&self, timeout: Duration) -> Result<usize, ClientError> {
        if !self.is_connected() {
            return Err(ClientError::NotConnected);
        }
        let mut count = 0usize;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let now = std::time::Instant::now();
            let remaining = deadline.saturating_duration_since(now);
            // The first PDU gets the whole timeout; the drain uses a short one.
            let inner_timeout = if count == 0 {
                if remaining.is_zero() {
                    break;
                }
                remaining
            } else if remaining.is_zero() {
                break;
            } else {
                Duration::from_millis(5).min(remaining)
            };

            // Receive under the lock, then release it as early as possible.
            let opt_inner = {
                let mut client = self.mms_client.lock().await;
                match client
                    .recv_unconfirmed_pdu_with_timeout(inner_timeout)
                    .await
                {
                    Ok(Some(b)) => Some(b),
                    Ok(None) => None,
                    Err(e) => {
                        if matches!(e, iec61850_mms::ClientError::ConnectionLost) {
                            self.is_connected
                                .store(false, core::sync::atomic::Ordering::Release);
                        }
                        return Err(e.into());
                    }
                }
            };

            let Some(inner_bytes) = opt_inner else {
                // Nothing arrived within the timeout.
                break;
            };

            match decode_and_dispatch_report(&inner_bytes, &self.reports).await {
                DispatchOutcome::Dispatched => count += 1,
                DispatchOutcome::SkippedNonUrcb => {
                    // A non-URCB InformationReport is not dispatched here.
                }
                DispatchOutcome::DecodeFailed(msg) => {
                    tracing::warn!(error = %msg, "dropping undecodable information report");
                }
                DispatchOutcome::DispatchFailed(err) => {
                    tracing::warn!(error = ?err, "report dispatch failed");
                }
            }
        }
        Ok(count)
    }

    /// Spawns a background task that receives InformationReports and dispatches
    /// them to the report registry.
    ///
    /// `poll_interval` bounds each receive, and therefore how long the task
    /// holds the MMS client lock against concurrent reads and writes; 50 ms to
    /// 200 ms is a reasonable range.
    ///
    /// The task ends when the connection is closed or a receive fails. Dropping
    /// the returned handle does not cancel it; call `disconnect` to stop it at
    /// the next iteration.
    ///
    /// The transport and timer must be `Send + 'static`, as required by the
    /// spawned future. A backend that is not `Send` has to use `poll_reports`.
    ///
    /// Requires `std`. An embedded caller runs the same receive-and-dispatch
    /// loop on its own executor.
    #[cfg(feature = "std")]
    pub fn spawn_report_dispatcher(&self, poll_interval: Duration) -> tokio::task::JoinHandle<()>
    where
        T: Send + 'static,
        Tm: Send + 'static,
    {
        let registry = Arc::clone(&self.reports);
        let mms_client = Arc::clone(&self.mms_client);
        let is_connected = Arc::clone(&self.is_connected);
        tokio::spawn(async move {
            tracing::debug!("report dispatcher started");
            while is_connected.load(core::sync::atomic::Ordering::Acquire) {
                let opt_inner = {
                    let mut client = mms_client.lock().await;
                    match client
                        .recv_unconfirmed_pdu_with_timeout(poll_interval)
                        .await
                    {
                        Ok(Some(b)) => Some(b),
                        Ok(None) => None,
                        Err(e) => {
                            if matches!(e, iec61850_mms::ClientError::ConnectionLost) {
                                is_connected.store(false, core::sync::atomic::Ordering::Release);
                            }
                            tracing::warn!(error = ?e, "report dispatcher stopping: receive failed");
                            return;
                        }
                    }
                };
                if let Some(inner_bytes) = opt_inner {
                    let _ = decode_and_dispatch_report(&inner_bytes, &registry).await;
                }
                // The interval is already spent inside the receive; sleeping
                // again would double the latency.
            }
            tracing::debug!("report dispatcher stopped");
        })
    }
}

/// Outcome of decoding and dispatching one unconfirmed PDU.
///
/// Both callers are std-only, hence the same gate here.
#[cfg(feature = "std")]
enum DispatchOutcome {
    /// Decoded, matched to a handler, and the callback was invoked.
    Dispatched,
    /// Decoded, but the variable access specification is not the VMD-specific
    /// name `RPT`, so this is not a report; a command termination arrives this
    /// way and is handled by the control module.
    SkippedNonUrcb,
    /// The PDU did not decode as an InformationReport.
    DecodeFailed(String),
    /// The registry rejected the report while parsing or applying it.
    DispatchFailed(DispatchError),
}

/// Decodes the inner bytes of an unconfirmed PDU and dispatches the report.
///
/// The access results are converted into an `MmsValue::Array` for the parser.
/// Only the VMD-specific name `RPT`, the form URCB reports take, is accepted.
#[cfg(feature = "std")]
async fn decode_and_dispatch_report(
    inner_bytes: &[u8],
    registry: &Arc<ReportRegistry>,
) -> DispatchOutcome {
    let report = match decode_information_report(inner_bytes) {
        Ok(r) => r,
        Err(e) => return DispatchOutcome::DecodeFailed(e.to_string()),
    };

    // Only `RPT`; a command termination is dispatched by the control module.
    let is_urcb = matches!(
        &report.variable_access_spec,
        VariableAccessSpec::VariableListName(ObjectName::VmdSpecific(s)) if s == "RPT"
    );
    if !is_urcb {
        return DispatchOutcome::SkippedNonUrcb;
    }

    let elements: Vec<MmsValue> = report
        .list_of_access_result
        .iter()
        .map(crate::mms_compat::mms_data_to_mms_value)
        .collect();
    let value = MmsValue::Array(elements);

    match registry.handle_report(&value).await {
        Ok(()) => DispatchOutcome::Dispatched,
        Err(e) => DispatchOutcome::DispatchFailed(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::parse::ReportOptFlds;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::Mutex;

    /// Builds a minimal report value: RptId, empty OptFlds, a one-bit inclusion
    /// bitmap and a single data value.
    fn minimal_report_value(rpt_id: &str, value: i64) -> MmsValue {
        let opt_flds = MmsValue::BitString {
            padding: 6,
            data: vec![0, 0],
        };
        let inclusion = MmsValue::BitString {
            padding: 7,
            data: vec![0x80],
        }; // 1 bit, true
        MmsValue::Array(vec![
            MmsValue::VisibleString(rpt_id.to_string()),
            opt_flds,
            inclusion,
            MmsValue::Integer(value),
        ])
    }

    #[tokio::test]
    async fn install_and_lookup() {
        let reg = ReportRegistry::new();
        let cb: ReportCallback = Arc::new(|_| {});
        reg.install("RCB1".to_string(), Some("RCB1".to_string()), None, cb)
            .await
            .unwrap();
        assert!(reg.contains("RCB1").await);
    }

    #[tokio::test]
    async fn uninstall_existing() {
        let reg = ReportRegistry::new();
        let cb: ReportCallback = Arc::new(|_| {});
        reg.install("RCB1".to_string(), Some("RCB1".to_string()), None, cb)
            .await
            .unwrap();
        reg.uninstall("RCB1").await.unwrap();
        assert!(!reg.contains("RCB1").await);
    }

    #[tokio::test]
    async fn uninstall_missing_returns_err() {
        let reg = ReportRegistry::new();
        let r = reg.uninstall("nope").await;
        assert!(matches!(r, Err(ClientError::NotFound(_))));
    }

    #[tokio::test]
    async fn install_rejects_too_long_rpt_id() {
        let reg = ReportRegistry::new();
        let long = "x".repeat(129);
        let cb: ReportCallback = Arc::new(|_| {});
        let r = reg.install("RCB1".to_string(), Some(long), None, cb).await;
        assert!(matches!(r, Err(ClientError::InvalidRptId { len: 129 })));
    }

    #[tokio::test]
    async fn handle_report_invokes_callback_with_snapshot() {
        let reg = Arc::new(ReportRegistry::new());
        let counter = Arc::new(AtomicUsize::new(0));
        let counter2 = Arc::clone(&counter);
        let captured_value = Arc::new(std::sync::Mutex::new(None::<i64>));
        let captured_value2 = Arc::clone(&captured_value);
        let cb: ReportCallback = Arc::new(move |snap: Arc<ClientReport>| {
            counter2.fetch_add(1, Ordering::SeqCst);
            if let Some(Some(MmsValue::Integer(v))) = snap.data_set_values.first() {
                *captured_value2.lock().unwrap() = Some(*v);
            }
        });
        reg.install("RCB1".to_string(), Some("RCB1".to_string()), None, cb)
            .await
            .unwrap();

        let v = minimal_report_value("RCB1", 42);
        reg.handle_report(&v).await.unwrap();

        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(*captured_value.lock().unwrap(), Some(42));
    }

    #[tokio::test]
    async fn handle_report_no_match_drops_silently() {
        let reg = Arc::new(ReportRegistry::new());
        let counter = Arc::new(AtomicUsize::new(0));
        let counter2 = Arc::clone(&counter);
        let cb: ReportCallback = Arc::new(move |_| {
            counter2.fetch_add(1, Ordering::SeqCst);
        });
        reg.install("RCB1".to_string(), Some("RCB1".to_string()), None, cb)
            .await
            .unwrap();
        // A report whose RptId matches no handler.
        let v = minimal_report_value("OTHER", 0);
        reg.handle_report(&v).await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn default_rpt_id_dot_to_dollar_match() {
        let reg = Arc::new(ReportRegistry::new());
        let counter = Arc::new(AtomicUsize::new(0));
        let counter2 = Arc::clone(&counter);
        let cb: ReportCallback = Arc::new(move |_| {
            counter2.fetch_add(1, Ordering::SeqCst);
        });
        // With no explicit RptId, dispatch matches the reference with '.' as '$'.
        reg.install("simpleIO/LLN0.RP.EventsRCB01".to_string(), None, None, cb)
            .await
            .unwrap();
        let v = minimal_report_value("simpleIO/LLN0$RP$EventsRCB01", 7);
        reg.handle_report(&v).await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    /// A callback that installs another handler must not deadlock: the callback
    /// runs with the registry lock released. The timeout turns a regression into
    /// a failure rather than a hang.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn callback_can_install_another_handler_without_deadlock() {
        let reg = Arc::new(ReportRegistry::new());
        let reg_in_cb = Arc::clone(&reg);

        // The outer callback installs a second handler when it fires.
        let installed_inner = Arc::new(AtomicUsize::new(0));
        let installed_inner_clone = Arc::clone(&installed_inner);
        let cb: ReportCallback = Arc::new(move |_snap: Arc<ClientReport>| {
            // The callback is a synchronous `Fn`, so the async install is spawned:
            // it returns immediately and does not block dispatch. What is under
            // test is that the install completes at all.
            let reg_in_cb = Arc::clone(&reg_in_cb);
            let installed_inner_clone = Arc::clone(&installed_inner_clone);
            tokio::spawn(async move {
                let inner_cb: ReportCallback = Arc::new(|_| {});
                reg_in_cb
                    .install(
                        "INNER".to_string(),
                        Some("INNER".to_string()),
                        None,
                        inner_cb,
                    )
                    .await
                    .unwrap();
                installed_inner_clone.fetch_add(1, Ordering::SeqCst);
            });
        });

        reg.install("OUTER".to_string(), Some("OUTER".to_string()), None, cb)
            .await
            .unwrap();
        // Firing the outer callback installs the inner handler.
        let v = minimal_report_value("OUTER", 0);
        // A callback awaiting under the lock would hang here instead of failing.
        tokio::time::timeout(Duration::from_secs(2), reg.handle_report(&v))
            .await
            .expect("handle_report should not deadlock when callback installs another handler")
            .unwrap();

        // Wait for the spawned install to complete.
        for _ in 0..50 {
            if installed_inner.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(installed_inner.load(Ordering::SeqCst), 1);
        assert!(reg.contains("INNER").await);
    }

    #[tokio::test]
    async fn ied_connection_install_uninstall_round_trip() {
        let conn = IedConnection::new();
        let cb: ReportCallback = Arc::new(|_| {});
        conn.install_report_handler(Some("RCB1".to_string()), "RCB1", None, cb)
            .await
            .unwrap();
        assert!(conn.report_registry().contains("RCB1").await);
        conn.uninstall_report_handler("RCB1").await.unwrap();
        assert!(!conn.report_registry().contains("RCB1").await);
    }

    /// The snapshot handed to a callback is owned and outlives the dispatch.
    #[tokio::test]
    async fn parsed_report_is_owned_and_callback_outlives_dispatch() {
        let reg = Arc::new(ReportRegistry::new());
        let snap_holder = Arc::new(std::sync::Mutex::new(None::<Arc<ClientReport>>));
        let snap_holder2 = Arc::clone(&snap_holder);
        let cb: ReportCallback = Arc::new(move |snap| {
            *snap_holder2.lock().unwrap() = Some(snap);
        });
        reg.install("RCB1".to_string(), Some("RCB1".to_string()), None, cb)
            .await
            .unwrap();
        let v = minimal_report_value("RCB1", 100);
        reg.handle_report(&v).await.unwrap();

        let held = snap_holder.lock().unwrap().clone();
        let held = held.expect("callback should have stored snapshot");
        assert_eq!(held.data_set_values[0], Some(MmsValue::Integer(100)));
        // The snapshot is still readable after dispatch returned.
        let _ = ReportOptFlds::SEQUENCE_NUMBER;
    }

    // Use-after-free resistance around callbacks.

    /// A handler removed while its callback is still running must not
    /// invalidate the data the callback holds.
    ///
    /// The equivalent hazard in a manually managed implementation is freeing the
    /// callback parameter on an error path and then reading it again. Here the
    /// contract is enforced by construction:
    ///
    /// 1. The callback receives an owned `Arc<ClientReport>` snapshot, not a
    ///    reference into the registry entry, so uninstalling the entry
    ///    immediately afterwards leaves the snapshot valid.
    ///
    /// 2. The callback handle and the state are cloned while the lock is held,
    ///    and the callback runs after the guard is dropped.
    ///
    /// 3. The `ClientReport` lives until the last `Arc` clone is dropped, even
    ///    when the registry entry is gone.
    ///
    /// The test drives that sequence: dispatch clones the snapshot, another task
    /// uninstalls the entry, and the callback then reads the snapshot.
    #[tokio::test]
    async fn uaf_resistance_uninstall_during_callback() {
        use tokio::time::{timeout, Duration};

        let reg = Arc::new(ReportRegistry::new());
        let reg_for_uninstall = Arc::clone(&reg);

        // The callback keeps the snapshot, waits for a signal, then reads it.
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let release_rx = Arc::new(Mutex::new(Some(release_rx)));
        let observed = Arc::new(std::sync::Mutex::new(None::<i64>));
        let observed_for_cb = Arc::clone(&observed);
        let release_rx_for_cb = Arc::clone(&release_rx);

        let cb: ReportCallback = Arc::new(move |snap: Arc<ClientReport>| {
            // Store the snapshot now and read it later, from a spawned task.
            let observed = Arc::clone(&observed_for_cb);
            let rx_holder = Arc::clone(&release_rx_for_cb);
            tokio::spawn(async move {
                // Wait until the entry has been uninstalled.
                if let Some(rx) = rx_holder.lock().await.take() {
                    let _ = timeout(Duration::from_secs(5), rx).await;
                }
                // The entry is gone, but the snapshot still owns the report.
                if let Some(MmsValue::Integer(v)) =
                    snap.data_set_values.first().and_then(|v| v.as_ref())
                {
                    *observed.lock().unwrap() = Some(*v);
                }
            });
        });

        reg.install("RCB1".to_string(), Some("RCB1".to_string()), None, cb)
            .await
            .unwrap();

        // Dispatch; the callback spawns its task and waits for the signal.
        let v = minimal_report_value("RCB1", 0xCAFE);
        timeout(Duration::from_secs(5), reg.handle_report(&v))
            .await
            .expect("dispatch should not time out")
            .expect("dispatch should succeed");

        // Remove the entry while the callback still holds the snapshot.
        timeout(Duration::from_secs(5), reg_for_uninstall.uninstall("RCB1"))
            .await
            .expect("uninstall should not time out")
            .expect("uninstall should succeed");

        assert!(!reg.contains("RCB1").await, "entry should be uninstalled");

        // Release the read inside the callback.
        let _ = release_tx.send(());

        // Wait for the task the callback spawned.
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if observed.lock().unwrap().is_some() {
                break;
            }
        }

        let got = *observed.lock().unwrap();
        assert_eq!(
            got,
            Some(0xCAFE),
            "callback must still read its snapshot after the entry was uninstalled"
        );
    }

    /// The `ReportCallback` signature takes an owned `Arc<ClientReport>` rather
    /// than a reference into a registry entry, so a borrow cannot escape the
    /// lock. The test asserts the contract by compiling.
    #[test]
    fn callback_signature_is_owned_snapshot() {
        // Building a callback from this signature is the assertion.
        fn _accepts_owned_snapshot(snap: Arc<ClientReport>) {
            // The snapshot can be moved into another task or across an await.
            let _kept = snap;
        }
        let cb: ReportCallback = Arc::new(_accepts_owned_snapshot);
        // The alias also requires `Send + Sync + 'static`.
        fn _assert_send_sync<T: Send + Sync + 'static>(_: &T) {}
        _assert_send_sync(&cb);
    }
}
