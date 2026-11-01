//! The order in which the updates of one attribute reach a buffered report
//! control block, over a real MMS association.
//!
//! The triggers of an update are raised in the order the values were stored,
//! whether the updates come from two threads while a log storage is slow,
//! from a log storage that updates the attribute while it writes an entry, or
//! from a write handler that updates an attribute an earlier item of the same
//! write request stored. The last report a subscriber receives for the
//! attribute therefore carries the value the model holds. Reports are received
//! on a raw MMS association and decoded without client-side report state.

use std::net::SocketAddr;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use iec61850_client::mms_compat::mms_data_to_mms_value;
use iec61850_client::report::parse::{parse_report, ParsedReport};
use iec61850_mms::mms::client::{MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::common::ObjectName;
use iec61850_mms::mms::pdu::information_report::{decode_information_report, VariableAccessSpec};
use iec61850_mms::mms::MmsData;
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObject, DoChild, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::logging::storage::EntryMeta;
use iec61850_server::logging::{
    InMemoryLogStorage, JournalEntryData, LogControl, LogControlBlock, LogEntryId, LogEntryVisitor,
    LogStorage, LogStorageError,
};
use iec61850_server::reporting::{Brcb, BufferedReportControl};
use iec61850_server::{
    AttributeAccessHandler, Dataset, DatasetEntry, HandlerWriteOutcome, IedServer, OptFlds,
    ServerHandle, TriggerOptions, WriteContext,
};

const DOM: &str = "TESTLD0";
const IND: &str = "TESTLD0/GGIO1$ST$Ind$stVal";
const SET1: &str = "TESTLD0/GGIO1$SP$Set1$setVal";
const SET2: &str = "TESTLD0/GGIO1$SP$Set2$setVal";
const DATA_SET: &str = "LLN0$dsAll";
const BRCB: &str = "LLN0$BR$brcb01";
const LCB: &str = "LLN0$LG$evlog";

/// GGIO1 with three booleans that declare `dchg`: `Ind.stVal` under FC=ST and
/// `Set1.setVal` and `Set2.setVal` under FC=SP, which a client may write.
fn model() -> Arc<IedModel> {
    let boolean = |data_object: &str, name: &str, fc: FC| {
        DataObject::new(
            data_object,
            vec![DoChild::Da(DataAttribute::new(
                name,
                fc,
                DataAttributeType::Boolean,
                TrgOps::DCHG,
                MmsValue::Boolean(false),
            ))],
        )
    };
    let ggio = LogicalNodeBuilder::new("", "GGIO", "1")
        .add_do(boolean("Ind", "stVal", FC::St))
        .add_do(boolean("Set1", "setVal", FC::Sp))
        .add_do(boolean("Set2", "setVal", FC::Sp))
        .build()
        .unwrap();
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(LogicalNodeBuilder::lln0().build().unwrap())
        .add_ln(ggio)
        .build()
        .unwrap();
    Arc::new(
        IedModelBuilder::new("TEST")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap(),
    )
}

/// The single attribute of data object `index` of GGIO1: Ind, Set1, then
/// Set2.
fn da(m: &IedModel, index: usize) -> &DataAttribute {
    let DoChild::Da(da) = &m.lds[0].lns[1].dos[index].children[0] else {
        panic!("fixture shape")
    };
    da
}

/// The data set `[Ind.stVal, Set1.setVal, Set2.setVal]`.
fn data_set(m: &IedModel) -> Dataset {
    let mut ds = Dataset::new(DATA_SET);
    for (i, r) in [IND, SET1, SET2].into_iter().enumerate() {
        ds.push(DatasetEntry::new(r, da(m, i).value.clone()));
    }
    ds
}

/// A built server with an enabled log control block over the data set,
/// writing to `storage`, and a BRCB with no buffer time over the same data
/// set.
fn server(m: &Arc<IedModel>, storage: Arc<dyn LogStorage>) -> IedServer {
    let srv = IedServer::builder()
        .model(m.clone())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()
        .expect("build server");
    srv.register_dataset(DOM, data_set(m));
    let block = LogControlBlock::new("evlog")
        .with_dataset(DATA_SET)
        .with_trg_ops(TriggerOptions::DATA_CHANGED)
        .with_log_ref(format!("{DOM}/LLN0$EventLog"));
    let lc = LogControl::new(format!("{DOM}/{LCB}"), block).with_storage(storage);
    srv.register_log_control(DOM, LCB, Arc::new(lc));
    let brcb = Brcb::new("brcb01", DATA_SET)
        .with_trg_ops(TriggerOptions::DATA_CHANGED)
        .with_opt_flds(OptFlds::SEQ_NUM | OptFlds::DATA_SET | OptFlds::DATA_REFERENCE)
        .with_buf_tm_ms(0);
    srv.register_brcb(
        BufferedReportControl::new(format!("{DOM}/{BRCB}"), brcb),
        data_set(m),
    )
    .expect("register_brcb");
    srv
}

/// Starts the server and opens an association, leaving the BRCB disabled.
async fn start_disabled(srv: &IedServer) -> (ServerHandle, MmsClient) {
    let handle = srv.start().await.expect("start");
    let mut mms = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    mms.connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    (handle, mms)
}

/// Starts the server and enables the BRCB from a new association.
async fn start(srv: &IedServer) -> (ServerHandle, MmsClient) {
    let (handle, mut mms) = start_disabled(srv).await;
    mms.write(DOM, &format!("{BRCB}$RptEna"), MmsData::Boolean(true))
        .await
        .expect("enable the BRCB");
    (handle, mms)
}

/// Decodes an InformationReport, given the bytes after the outer
/// unconfirmed-PDU tag and length; `None` for a report other than `RPT`.
fn parse_information_report(inner: &[u8]) -> Option<ParsedReport> {
    let report = decode_information_report(inner).expect("decode information report");
    let is_rpt = matches!(
        &report.variable_access_spec,
        VariableAccessSpec::VariableListName(ObjectName::VmdSpecific(s)) if s == "RPT"
    );
    if !is_rpt {
        return None;
    }
    let elements: Vec<MmsValue> = report
        .list_of_access_result
        .iter()
        .map(mms_data_to_mms_value)
        .collect();
    Some(parse_report(&MmsValue::Array(elements)).expect("parse report"))
}

/// Receives the next report; fails after ten seconds.
async fn next_report(mms: &mut MmsClient) -> ParsedReport {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "no report arrived");
        let Some(inner) = mms
            .recv_unconfirmed_pdu_with_timeout(remaining)
            .await
            .expect("receive")
        else {
            continue;
        };
        if let Some(report) = parse_information_report(&inner) {
            return report;
        }
    }
}

/// The members a report carries, each with its value.
fn members(r: &ParsedReport) -> Vec<(&str, MmsValue)> {
    r.data_references
        .iter()
        .zip(&r.data_values)
        .map(|(d, v)| (d.as_str(), v.clone()))
        .collect()
}

/// A log storage that runs `on_first` before it writes its first entry, and
/// writes every entry to memory.
struct HookedStorage {
    inner: InMemoryLogStorage,
    on_first: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl std::fmt::Debug for HookedStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookedStorage")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl HookedStorage {
    fn new(on_first: impl FnOnce() + Send + 'static) -> Self {
        Self {
            inner: InMemoryLogStorage::new(),
            on_first: Mutex::new(Some(Box::new(on_first))),
        }
    }

    /// The value of the only member of each entry, oldest first.
    fn logged(&self) -> Vec<MmsValue> {
        #[derive(Default)]
        struct Values(Vec<MmsValue>);
        impl LogEntryVisitor for Values {
            fn visit(&mut self, entry: &iec61850_server::JournalEntry) -> bool {
                self.0.push(entry.variables[0].value.clone());
                true
            }
        }
        let mut values = Values::default();
        self.inner
            .query_by_time(0, u64::MAX / 2, &mut values)
            .unwrap();
        values.0
    }
}

impl LogStorage for HookedStorage {
    fn add_entry(&self, time_ms: u64) -> Result<LogEntryId, LogStorageError> {
        self.inner.add_entry(time_ms)
    }

    fn add_entry_data(
        &self,
        entry_id: LogEntryId,
        data_ref: &str,
        value: MmsValue,
        reason_code: u8,
    ) -> Result<(), LogStorageError> {
        self.inner
            .add_entry_data(entry_id, data_ref, value, reason_code)
    }

    fn add_entry_with_data(
        &self,
        time_ms: u64,
        data: &[JournalEntryData],
    ) -> Result<LogEntryId, LogStorageError> {
        let hook = self.on_first.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
        self.inner.add_entry_with_data(time_ms, data)
    }

    fn query_by_time(
        &self,
        start_ms: u64,
        end_ms: u64,
        visitor: &mut dyn LogEntryVisitor,
    ) -> Result<(), LogStorageError> {
        self.inner.query_by_time(start_ms, end_ms, visitor)
    }

    fn query_after(
        &self,
        starting_time_ms: u64,
        entry_id: LogEntryId,
        visitor: &mut dyn LogEntryVisitor,
    ) -> Result<(), LogStorageError> {
        self.inner.query_after(starting_time_ms, entry_id, visitor)
    }

    fn oldest_and_newest(&self) -> Result<Option<(EntryMeta, EntryMeta)>, LogStorageError> {
        self.inner.oldest_and_newest()
    }

    fn count(&self) -> usize {
        self.inner.count()
    }
}

/// Checks that the next two reports carry `Ind` as true and then as false.
async fn assert_true_then_false(mms: &mut MmsClient) {
    let first = next_report(mms).await;
    assert_eq!(members(&first), [(IND, MmsValue::Boolean(true))]);
    let second = next_report(mms).await;
    assert_eq!(
        members(&second),
        [(IND, MmsValue::Boolean(false))],
        "the last report carries the value the model holds"
    );
}

/// Two threads update `Ind`, true and then false, while the log entry of the
/// first is still being written: the subscriber receives true and then
/// false, and the log holds them in the same order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_updates_are_reported_in_commit_order() {
    let m = model();
    let (started_tx, started_rx) = mpsc::channel::<()>();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let storage = Arc::new(HookedStorage::new(move || {
        started_tx.send(()).unwrap();
        go_rx.recv().unwrap();
    }));
    let srv = server(&m, storage.clone());
    let (_handle, mut mms) = start(&srv).await;

    let first = std::thread::spawn({
        let (srv, m) = (srv.clone(), m.clone());
        move || srv.update_boolean(da(&m, 0), true).unwrap()
    });
    started_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the first update writes its log entry");
    let second = std::thread::spawn({
        let (srv, m) = (srv.clone(), m.clone());
        move || srv.update_boolean(da(&m, 0), false).unwrap()
    });
    // Once the second value is stored, its triggers are queued behind those
    // of the first.
    let deadline = Instant::now() + Duration::from_secs(30);
    while *da(&m, 0).value.read().unwrap() != MmsValue::Boolean(false) {
        assert!(Instant::now() < deadline, "the second update never stores");
        std::thread::yield_now();
    }
    go_tx.send(()).unwrap();
    first.join().unwrap();
    second.join().unwrap();

    assert_true_then_false(&mut mms).await;
    assert_eq!(
        storage.logged(),
        [MmsValue::Boolean(true), MmsValue::Boolean(false)]
    );
}

/// A log storage that updates `Ind` to false while it writes the entry of the
/// update to true: the update it makes is reported after the one being
/// logged, so the subscriber receives true and then false.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_update_made_while_logging_is_reported_after_the_logged_one() {
    let m = model();
    let server_cell: Arc<OnceLock<IedServer>> = Arc::new(OnceLock::new());
    let storage = Arc::new(HookedStorage::new({
        let (server_cell, m) = (Arc::clone(&server_cell), m.clone());
        move || {
            let srv = server_cell.get().expect("the server is built");
            srv.update_boolean(da(&m, 0), false).unwrap();
        }
    }));
    let srv = server(&m, storage.clone());
    server_cell.set(srv.clone()).unwrap();
    let (_handle, mut mms) = start(&srv).await;

    std::thread::spawn({
        let (srv, m) = (srv.clone(), m.clone());
        move || srv.update_boolean(da(&m, 0), true).unwrap()
    })
    .join()
    .unwrap();

    assert_eq!(*da(&m, 0).value.read().unwrap(), MmsValue::Boolean(false));
    assert_true_then_false(&mut mms).await;
    assert_eq!(
        storage.logged(),
        [MmsValue::Boolean(true), MmsValue::Boolean(false)]
    );
}

/// A write handler on `Set2` that updates `Set1` to false.
#[derive(Debug)]
struct ClearSet1 {
    srv: OnceLock<IedServer>,
    m: Arc<IedModel>,
}

impl AttributeAccessHandler for ClearSet1 {
    fn on_write(&self, _ctx: &WriteContext<'_>, _value: &MmsValue) -> HandlerWriteOutcome {
        let srv = self.srv.get().expect("the server is built");
        srv.update_boolean(da(&self.m, 1), false).unwrap();
        HandlerWriteOutcome::Accept
    }
}

/// SetDataSetValues of `[Set1, Set2]` stores `Set1` = true, then the write
/// handler of `Set2` updates `Set1` back to false before `Set2` is stored.
/// The update of the handler is reported at once; the batch of the request,
/// raised when it ends, leaves out `Set1`, whose stored value was replaced, so
/// the last report holding `Set1` carries false, the value the model holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_written_value_replaced_before_the_request_ends_is_not_reported_after() {
    let m = model();
    let srv = server(&m, Arc::new(InMemoryLogStorage::new()));
    let mut written = Dataset::new("LLN0$dsSet");
    for (i, r) in [(1, SET1), (2, SET2)] {
        written.push(DatasetEntry::new(r, da(&m, i).value.clone()));
    }
    srv.register_dataset(DOM, written);
    let handler = Arc::new(ClearSet1 {
        srv: OnceLock::new(),
        m: m.clone(),
    });
    handler.srv.set(srv.clone()).unwrap();
    srv.install_write_access_handler("GGIO1$SP$Set2$setVal", handler)
        .unwrap();
    let (_handle, mut mms) = start(&srv).await;

    let outcomes = mms
        .write_named_variable_list_values(
            DOM,
            "LLN0$dsSet",
            vec![MmsData::Boolean(true), MmsData::Boolean(true)],
        )
        .await
        .expect("SetDataSetValues");
    assert!(outcomes
        .iter()
        .all(|o| matches!(o, iec61850_mms::mms::pdu::WriteOutcome::Success)));
    assert_eq!(*da(&m, 1).value.read().unwrap(), MmsValue::Boolean(false));
    assert_eq!(*da(&m, 2).value.read().unwrap(), MmsValue::Boolean(true));

    let first = next_report(&mut mms).await;
    assert_eq!(members(&first), [(SET1, MmsValue::Boolean(false))]);
    let second = next_report(&mut mms).await;
    assert_eq!(
        members(&second),
        [(SET2, MmsValue::Boolean(true))],
        "the request reports only the value still held"
    );
}

/// A client purges the disabled BRCB while the log entry of `Ind` = true is
/// still being written, so the value was stored before the purge but its
/// triggers reach the reporting engine after it. The purge discarded that
/// event (IEC 61850-7-2 17.2.2.14): once the client enables the BRCB, the
/// first report it receives is the one of `Ind` = false, stored after the
/// purge.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_value_stored_before_a_purge_is_not_reported_after_it() {
    let m = model();
    let (started_tx, started_rx) = mpsc::channel::<()>();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let storage = Arc::new(HookedStorage::new(move || {
        started_tx.send(()).unwrap();
        go_rx.recv().unwrap();
    }));
    let srv = server(&m, storage.clone());
    let (_handle, mut mms) = start_disabled(&srv).await;

    let stored_before = std::thread::spawn({
        let (srv, m) = (srv.clone(), m.clone());
        move || srv.update_boolean(da(&m, 0), true).unwrap()
    });
    started_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the update writes its log entry");
    mms.write(DOM, &format!("{BRCB}$PurgeBuf"), MmsData::Boolean(true))
        .await
        .expect("purge the BRCB");
    go_tx.send(()).unwrap();
    stored_before.join().unwrap();

    srv.update_boolean(da(&m, 0), false).unwrap();
    mms.write(DOM, &format!("{BRCB}$RptEna"), MmsData::Boolean(true))
        .await
        .expect("enable the BRCB");
    let first = next_report(&mut mms).await;
    assert_eq!(members(&first), [(IND, MmsValue::Boolean(false))]);
}
