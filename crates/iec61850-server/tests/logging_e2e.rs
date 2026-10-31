//! End-to-end tests of the log model over a real MMS association: implicit
//! logging on a data set member update, the log control block structure, and
//! the journal a LogRef names.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use iec61850_mms::mms::client::{MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::get_name_list::ObjectClass;
use iec61850_mms::mms::pdu::{ReadJournalRequest, ReadJournalResponse};
use iec61850_mms::mms::MmsData;
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObject, DoChild, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::logging::{
    InMemoryLogStorage, JournalEntry, LogControl, LogControlBlock, LogEntryId, LogEntryVisitor,
    LogStorage, LogStorageError,
};
use iec61850_server::reporting::{Dataset, DatasetEntry, TriggerOptions};
use iec61850_server::{IedServer, IedServerConfig};

const DOM: &str = "TESTLD0";
const LCB_ITEM: &str = "LLN0$LG$evlog";
const DATA_SET: &str = "LLN0$dsLog";
const ST_VAL_REF: &str = "TESTLD0/GGIO1$ST$Ind1$stVal";
const Q_REF: &str = "TESTLD0/GGIO1$ST$Ind1$q";
const EVENT_LOG: &str = "LLN0$EventLog";

fn model() -> Arc<IedModel> {
    let st_val = DataAttribute::new(
        "stVal",
        FC::St,
        DataAttributeType::Boolean,
        TrgOps::DCHG,
        MmsValue::Boolean(false),
    );
    let q = DataAttribute::new(
        "q",
        FC::St,
        DataAttributeType::Boolean,
        TrgOps::QCHG,
        MmsValue::Boolean(false),
    );
    let other = DataAttribute::new(
        "stVal",
        FC::St,
        DataAttributeType::Boolean,
        TrgOps::DCHG,
        MmsValue::Boolean(false),
    );
    let ind1 = DataObject::new("Ind1", vec![DoChild::Da(st_val), DoChild::Da(q)]);
    let ind2 = DataObject::new("Ind2", vec![DoChild::Da(other)]);
    let ggio = LogicalNodeBuilder::new("", "GGIO", "1")
        .add_do(ind1)
        .add_do(ind2)
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

/// The attribute `index` of data object `do_index` of GGIO1.
fn ggio_da(m: &IedModel, do_index: usize, index: usize) -> &DataAttribute {
    let DoChild::Da(da) = &m.lds[0].lns[1].dos[do_index].children[index] else {
        panic!("fixture shape")
    };
    da
}

fn server(m: Arc<IedModel>) -> IedServer {
    IedServer::builder()
        .model(m)
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig::default())
        .build()
        .expect("build server")
}

/// Registers the data set `LLN0$dsLog` holding GGIO1.Ind1.stVal and
/// GGIO1.Ind1.q.
fn register_data_set(srv: &IedServer, m: &IedModel) {
    let mut ds = Dataset::new(DATA_SET);
    ds.push(DatasetEntry::new(
        ST_VAL_REF,
        ggio_da(m, 0, 0).value.clone(),
    ));
    ds.push(DatasetEntry::new(Q_REF, ggio_da(m, 0, 1).value.clone()));
    srv.register_dataset(DOM, ds);
}

fn lcb(trg_ops: TriggerOptions) -> LogControlBlock {
    LogControlBlock::new("evlog")
        .with_dataset(DATA_SET)
        .with_log_ref(format!("{DOM}/{EVENT_LOG}"))
        .with_trg_ops(trg_ops)
        .with_intg_pd_ms(2_000)
}

fn register_lcb(
    srv: &IedServer,
    block: LogControlBlock,
    storage: Arc<dyn LogStorage>,
    enable: bool,
) {
    let lc = LogControl::new(format!("{DOM}/{LCB_ITEM}"), block).with_storage(storage);
    lc.set_log_ena(enable).unwrap();
    srv.register_log_control(DOM, LCB_ITEM, Arc::new(lc));
}

async fn client(port: u16) -> MmsClient {
    client_with(MmsClientBuilder::new(), port).await
}

async fn client_with(builder: MmsClientBuilder, port: u16) -> MmsClient {
    let mut c = builder
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    c.connect("127.0.0.1", port).await.expect("connect");
    c
}

async fn read_all(c: &mut MmsClient, item: &str) -> ReadJournalResponse {
    c.read_journal(&ReadJournalRequest::time_range(DOM, item, 0, u64::MAX / 2))
        .await
        .expect("read journal")
}

fn members(v: MmsData) -> Vec<MmsData> {
    match v {
        MmsData::Structure(m) => m,
        other => panic!("expected a structure, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enabled_lcb_logs_each_data_change_of_a_data_set_member() {
    let m = model();
    let srv = server(m.clone());
    register_data_set(&srv, &m);
    let storage: Arc<dyn LogStorage> = Arc::new(InMemoryLogStorage::new());
    register_lcb(
        &srv,
        lcb(TriggerOptions::DATA_CHANGED),
        storage.clone(),
        true,
    );
    let h = srv.start().await.unwrap();

    srv.update_boolean(ggio_da(&m, 0, 0), true).unwrap();
    srv.update_boolean(ggio_da(&m, 0, 0), false).unwrap();
    assert_eq!(storage.count(), 2);

    let mut c = client(h.bound_addr.port()).await;
    let resp = read_all(&mut c, EVENT_LOG).await;
    assert_eq!(resp.entries.len(), 2);
    let values: Vec<_> = resp
        .entries
        .iter()
        .map(|e| {
            assert_eq!(e.variables.len(), 1);
            let v = &e.variables[0];
            assert_eq!(v.data_ref, ST_VAL_REF);
            assert_eq!(v.reason_code, 0x02, "data-change");
            v.value.clone()
        })
        .collect();
    assert_eq!(
        values,
        vec![MmsData::Boolean(true), MmsData::Boolean(false)]
    );
    c.disconnect().await.ok();
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quality_change_is_logged_with_its_reason_code() {
    let m = model();
    let srv = server(m.clone());
    register_data_set(&srv, &m);
    let storage: Arc<dyn LogStorage> = Arc::new(InMemoryLogStorage::new());
    register_lcb(
        &srv,
        lcb(TriggerOptions::QUALITY_CHANGED),
        storage.clone(),
        true,
    );
    let h = srv.start().await.unwrap();

    srv.update_boolean(ggio_da(&m, 0, 1), true).unwrap();
    // A data change is not among the TrgOps, so stVal is not logged.
    srv.update_boolean(ggio_da(&m, 0, 0), true).unwrap();

    let mut c = client(h.bound_addr.port()).await;
    let resp = read_all(&mut c, EVENT_LOG).await;
    assert_eq!(resp.entries.len(), 1);
    assert_eq!(resp.entries[0].variables[0].data_ref, Q_REF);
    assert_eq!(
        resp.entries[0].variables[0].reason_code, 0x04,
        "quality-change"
    );
    c.disconnect().await.ok();
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nothing_is_logged_by_a_disabled_lcb_or_for_a_non_member() {
    let m = model();
    let srv = server(m.clone());
    register_data_set(&srv, &m);
    let disabled: Arc<dyn LogStorage> = Arc::new(InMemoryLogStorage::new());
    register_lcb(
        &srv,
        lcb(TriggerOptions::DATA_CHANGED),
        disabled.clone(),
        false,
    );
    let enabled: Arc<dyn LogStorage> = Arc::new(InMemoryLogStorage::new());
    let lc = LogControl::new(
        format!("{DOM}/LLN0$LG$other"),
        lcb(TriggerOptions::DATA_CHANGED),
    )
    .with_storage(enabled.clone());
    lc.set_log_ena(true).unwrap();
    srv.register_log_control(DOM, "LLN0$LG$other", Arc::new(lc));

    srv.update_boolean(ggio_da(&m, 0, 0), true).unwrap();
    // GGIO1.Ind2.stVal is in no data set.
    srv.update_boolean(ggio_da(&m, 1, 0), true).unwrap();

    assert_eq!(disabled.count(), 0, "a disabled control block logs nothing");
    assert_eq!(enabled.count(), 1, "only the data set member is logged");
}

/// A control block registered under its own path and under the name of its
/// log writes one entry per update, not one per key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_lcb_registered_under_two_keys_logs_each_update_once() {
    let m = model();
    let srv = server(m.clone());
    register_data_set(&srv, &m);
    let storage: Arc<dyn LogStorage> = Arc::new(InMemoryLogStorage::new());
    let lc = LogControl::new(
        format!("{DOM}/{LCB_ITEM}"),
        lcb(TriggerOptions::DATA_CHANGED),
    )
    .with_storage(storage.clone());
    lc.set_log_ena(true).unwrap();
    let lc = Arc::new(lc);
    srv.register_log_control(DOM, LCB_ITEM, Arc::clone(&lc));
    srv.register_log_control(DOM, EVENT_LOG, lc);
    let h = srv.start().await.unwrap();

    srv.update_boolean(ggio_da(&m, 0, 0), true).unwrap();
    assert_eq!(storage.count(), 1);

    let mut c = client(h.bound_addr.port()).await;
    assert_eq!(read_all(&mut c, EVENT_LOG).await.entries.len(), 1);
    c.disconnect().await.ok();
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_lcb_with_an_unregistered_data_set_logs_nothing() {
    let m = model();
    let srv = server(m.clone());
    let storage: Arc<dyn LogStorage> = Arc::new(InMemoryLogStorage::new());
    register_lcb(
        &srv,
        lcb(TriggerOptions::DATA_CHANGED),
        storage.clone(),
        true,
    );

    srv.update_boolean(ggio_da(&m, 0, 0), true).unwrap();
    assert_eq!(storage.count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn whole_lcb_read_carries_the_nine_components() {
    let m = model();
    let srv = server(m.clone());
    register_data_set(&srv, &m);
    let storage: Arc<dyn LogStorage> = Arc::new(InMemoryLogStorage::new());
    register_lcb(
        &srv,
        lcb(TriggerOptions::DATA_CHANGED),
        storage.clone(),
        true,
    );
    let h = srv.start().await.unwrap();
    let mut c = client(h.bound_addr.port()).await;

    // An empty log reports a zero time and an all-zero EntryID.
    let empty = members(c.read(DOM, LCB_ITEM).await.expect("read LCB"));
    assert_eq!(empty.len(), 9);
    assert_eq!(empty[0], MmsData::Boolean(true));
    assert_eq!(
        empty[1],
        MmsData::VisibleString(format!("{DOM}/{EVENT_LOG}"))
    );
    assert_eq!(
        empty[2],
        MmsData::VisibleString(format!("{DOM}/{DATA_SET}"))
    );
    assert_eq!(empty[3], MmsData::BinaryTime(vec![0; 6]));
    assert_eq!(empty[4], MmsData::BinaryTime(vec![0; 6]));
    assert_eq!(empty[5], MmsData::OctetString(vec![0; 8]));
    assert_eq!(empty[6], MmsData::OctetString(vec![0; 8]));
    assert!(matches!(empty[7], MmsData::BitString { .. }), "TrgOps");
    assert_eq!(empty[8], MmsData::Unsigned(2_000));

    srv.update_boolean(ggio_da(&m, 0, 0), true).unwrap();
    srv.update_boolean(ggio_da(&m, 0, 0), false).unwrap();
    let journal = read_all(&mut c, EVENT_LOG).await;
    let (oldest, newest) = (&journal.entries[0], &journal.entries[1]);

    let full = members(c.read(DOM, LCB_ITEM).await.expect("read LCB"));
    let time = |ms| {
        MmsData::BinaryTime(iec61850_mms::mms::binary_time::binary_time6_from_epoch_ms(ms).to_vec())
    };
    assert_eq!(full[3], time(oldest.occurence_time_ms));
    assert_eq!(full[4], time(newest.occurence_time_ms));
    assert_eq!(full[5], MmsData::OctetString(oldest.entry_id.to_vec()));
    assert_eq!(full[6], MmsData::OctetString(newest.entry_id.to_vec()));

    // Each component reads alone by its component name, and OldEnt and
    // NewEnt also by the attribute names OldEntr and NewEntr.
    for (name, expected) in [
        ("OldEntrTm", &full[3]),
        ("NewEntrTm", &full[4]),
        ("OldEnt", &full[5]),
        ("NewEnt", &full[6]),
        ("OldEntr", &full[5]),
        ("NewEntr", &full[6]),
        ("IntgPd", &full[8]),
    ] {
        let v = c
            .read(DOM, &format!("{LCB_ITEM}${name}"))
            .await
            .unwrap_or_else(|e| panic!("read {name}: {e:?}"));
        assert_eq!(&v, expected, "{name}");
    }
    assert!(
        c.read(DOM, &format!("{LCB_ITEM}$NoSuchAttr"))
            .await
            .is_err(),
        "an unknown attribute is absent"
    );
    c.disconnect().await.ok();
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_journal_a_logref_names_is_readable() {
    let m = model();
    let srv = server(m.clone());
    register_data_set(&srv, &m);
    let storage: Arc<dyn LogStorage> = Arc::new(InMemoryLogStorage::new());
    register_lcb(
        &srv,
        lcb(TriggerOptions::DATA_CHANGED),
        storage.clone(),
        true,
    );
    // No LogRef configured: the default `<LD>/<LN>$GeneralLog` applies. The
    // block stays disabled, so its journal is readable and empty.
    let general = LogControl::new(
        format!("{DOM}/GGIO1$LG$gen"),
        LogControlBlock::new("gen")
            .with_dataset(DATA_SET)
            .with_default_enabled(false),
    )
    .with_storage(Arc::new(InMemoryLogStorage::new()));
    srv.register_log_control(DOM, "GGIO1$LG$gen", Arc::new(general));
    let h = srv.start().await.unwrap();
    srv.update_boolean(ggio_da(&m, 0, 0), true).unwrap();

    let mut c = client(h.bound_addr.port()).await;
    let log_ref = c.read(DOM, &format!("{LCB_ITEM}$LogRef")).await.unwrap();
    assert_eq!(
        log_ref,
        MmsData::VisibleString(format!("{DOM}/{EVENT_LOG}"))
    );

    let by_log_ref = read_all(&mut c, EVENT_LOG).await;
    assert_eq!(by_log_ref.entries.len(), 1);
    assert_eq!(by_log_ref.entries[0].variables[0].data_ref, ST_VAL_REF);
    // The control block path names no journal.
    let by_path = c
        .read_journal(&ReadJournalRequest::time_range(DOM, LCB_ITEM, 0, 1))
        .await;
    assert!(
        by_path.is_err(),
        "a control block path is not a journal name"
    );
    assert!(read_all(&mut c, "GGIO1$GeneralLog")
        .await
        .entries
        .is_empty());

    let missing = c
        .read_journal(&ReadJournalRequest::time_range(DOM, "LLN0$NoLog", 0, 1))
        .await;
    assert!(missing.is_err(), "a journal no LogRef names is absent");
    c.disconnect().await.ok();
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_name_list_lists_the_journals_of_a_domain() {
    let m = model();
    let srv = server(m.clone());
    let storage: Arc<dyn LogStorage> = Arc::new(InMemoryLogStorage::new());
    register_lcb(
        &srv,
        lcb(TriggerOptions::DATA_CHANGED),
        storage.clone(),
        true,
    );
    // No LogRef configured: the default `<LD>/<LN>$GeneralLog` applies.
    let general = LogControl::new(
        format!("{DOM}/GGIO1$LG$gen"),
        LogControlBlock::new("gen").with_dataset(DATA_SET),
    );
    srv.register_log_control(DOM, "GGIO1$LG$gen", Arc::new(general));
    // A second control block writing to the same log adds no name.
    let shared = LogControl::new(
        format!("{DOM}/LLN0$LG$second"),
        lcb(TriggerOptions::DATA_CHANGED),
    );
    srv.register_log_control(DOM, "LLN0$LG$second", Arc::new(shared));
    let h = srv.start().await.unwrap();

    let mut c = client(h.bound_addr.port()).await;
    let (journals, more) = c
        .get_name_list(ObjectClass::Journal, Some(DOM), None)
        .await
        .expect("journal names");
    assert_eq!(
        journals,
        vec!["GGIO1$GeneralLog".to_string(), EVENT_LOG.to_string()]
    );
    assert!(!more);
    let (variables, _) = c
        .get_name_list(ObjectClass::NamedVariable, Some(DOM), None)
        .await
        .expect("variable names");
    assert!(
        !variables.iter().any(|n| n == EVENT_LOG),
        "a journal is not a named variable"
    );
    c.disconnect().await.ok();
    h.stop().await;
}

/// A control block whose definition leaves LogEna at its default and names a
/// data set is enabled once its storage is bound, and logs from the start.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_lcb_left_at_its_configured_log_ena_logs_from_the_start() {
    let m = model();
    let srv = server(m.clone());
    register_data_set(&srv, &m);
    let storage: Arc<dyn LogStorage> = Arc::new(InMemoryLogStorage::new());
    let block = lcb(TriggerOptions::DATA_CHANGED);
    assert!(block.default_enabled);
    let lc = LogControl::new(format!("{DOM}/{LCB_ITEM}"), block).with_storage(storage.clone());
    srv.register_log_control(DOM, LCB_ITEM, Arc::new(lc));
    let h = srv.start().await.unwrap();

    srv.update_boolean(ggio_da(&m, 0, 0), true).unwrap();

    let mut c = client(h.bound_addr.port()).await;
    let log_ena = c.read(DOM, &format!("{LCB_ITEM}$LogEna")).await.unwrap();
    assert_eq!(log_ena, MmsData::Boolean(true));
    let resp = read_all(&mut c, EVENT_LOG).await;
    assert_eq!(resp.entries.len(), 1);
    assert_eq!(resp.entries[0].variables[0].data_ref, ST_VAL_REF);
    c.disconnect().await.ok();
    h.stop().await;
}

/// A storage backend that counts the entries it hands to a visitor.
#[derive(Debug)]
struct CountingStorage {
    inner: InMemoryLogStorage,
    visited: AtomicUsize,
}

struct CountingVisitor<'a> {
    inner: &'a mut dyn LogEntryVisitor,
    visited: &'a AtomicUsize,
}

impl LogEntryVisitor for CountingVisitor<'_> {
    fn visit(&mut self, entry: &JournalEntry) -> bool {
        self.visited.fetch_add(1, Ordering::Relaxed);
        self.inner.visit(entry)
    }
}

impl LogStorage for CountingStorage {
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
    fn query_by_time(
        &self,
        start_ms: u64,
        end_ms: u64,
        visitor: &mut dyn LogEntryVisitor,
    ) -> Result<(), LogStorageError> {
        let mut v = CountingVisitor {
            inner: visitor,
            visited: &self.visited,
        };
        self.inner.query_by_time(start_ms, end_ms, &mut v)
    }
    fn query_after(
        &self,
        starting_time_ms: u64,
        entry_id: LogEntryId,
        visitor: &mut dyn LogEntryVisitor,
    ) -> Result<(), LogStorageError> {
        let mut v = CountingVisitor {
            inner: visitor,
            visited: &self.visited,
        };
        self.inner.query_after(starting_time_ms, entry_id, &mut v)
    }
    fn oldest_and_newest(
        &self,
    ) -> Result<
        Option<(
            iec61850_server::logging::storage::EntryMeta,
            iec61850_server::logging::storage::EntryMeta,
        )>,
        LogStorageError,
    > {
        self.inner.oldest_and_newest()
    }
    fn count(&self) -> usize {
        self.inner.count()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_journal_page_stops_visiting_once_the_pdu_is_full() {
    let m = model();
    let srv = server(m.clone());
    let storage = Arc::new(CountingStorage {
        inner: InMemoryLogStorage::new(),
        visited: AtomicUsize::new(0),
    });
    let lc = LogControl::new(
        format!("{DOM}/{LCB_ITEM}"),
        lcb(TriggerOptions::DATA_CHANGED),
    )
    .with_storage(storage.clone());
    lc.set_log_ena(true).unwrap();
    for i in 0..1_000u64 {
        let id = storage.add_entry(1_700_000_000_000 + i).unwrap();
        storage
            .add_entry_data(id, ST_VAL_REF, MmsValue::Boolean(i % 2 == 0), 0x02)
            .unwrap();
    }
    srv.register_log_control(DOM, LCB_ITEM, Arc::new(lc));
    let h = srv.start().await.unwrap();

    let mut c = client_with(
        MmsClientBuilder::new().local_max_pdu_size(2_000),
        h.bound_addr.port(),
    )
    .await;
    let page = read_all(&mut c, EVENT_LOG).await;
    assert_eq!(page.more_follows, Some(true));
    assert!(!page.entries.is_empty());
    let visited = storage.visited.load(Ordering::Relaxed);
    assert_eq!(
        visited,
        page.entries.len() + 1,
        "the walk stops at the first entry that does not fit"
    );
    c.disconnect().await.ok();
    h.stop().await;
}
