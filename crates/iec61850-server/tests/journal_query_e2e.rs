//! End-to-end tests of ReadJournal over a real MMS association: how a journal
//! is named and what a request selects from it.

use std::net::SocketAddr;
use std::sync::Arc;

use iec61850_mms::mms::client::{MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::get_name_list::ObjectClass;
use iec61850_mms::mms::pdu::{
    JournalRangeStart, JournalRangeStop, ReadJournalRequest, ReadJournalResponse,
};
use iec61850_model::{
    IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue,
};
use iec61850_server::logging::{
    InMemoryLogStorage, LogControl, LogControlBlock, LogEntryId, LogStorage,
};
use iec61850_server::{IedServer, IedServerConfig, ServerHandle};

const DOM: &str = "TESTLD0";

fn model() -> Arc<IedModel> {
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(LogicalNodeBuilder::lln0().build().unwrap())
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

fn server() -> IedServer {
    IedServer::builder()
        .model(model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig::default())
        .build()
        .expect("build server")
}

async fn client(h: &ServerHandle) -> MmsClient {
    let mut c = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    c.connect("127.0.0.1", h.bound_addr.port())
        .await
        .expect("connect");
    c
}

async fn readable(c: &mut MmsClient, item: &str) -> bool {
    c.read_journal(&ReadJournalRequest::new(DOM, item))
        .await
        .is_ok()
}

/// A journal answers to the name its LogRef gives it, and only to that name:
/// neither the path a control block is registered under nor any other key
/// reads it, and GetNameList lists exactly the names that read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_journal_answers_only_to_its_log_ref() {
    let srv = server();
    let with_log_ref = LogControl::new(
        format!("{DOM}/LLN0$LG$evlog"),
        LogControlBlock::new("evlog").with_log_ref(format!("{DOM}/LLN0$EventLog")),
    )
    .with_storage(Arc::new(InMemoryLogStorage::new()));
    srv.register_log_control(DOM, "LLN0$LG$evlog", Arc::new(with_log_ref));
    // No LogRef: the default `<LD>/<LN>$GeneralLog` names the journal.
    let by_instance_key = LogControl::new(
        format!("{DOM}/GGIO1$Instance"),
        LogControlBlock::new("inst"),
    )
    .with_storage(Arc::new(InMemoryLogStorage::new()));
    srv.register_log_control(DOM, "GGIO1$Instance", Arc::new(by_instance_key));
    let h = srv.start().await.unwrap();
    let mut c = client(&h).await;

    let (journals, more) = c
        .get_name_list(ObjectClass::Journal, Some(DOM), None)
        .await
        .expect("journal names");
    assert!(!more);
    assert_eq!(journals, vec!["GGIO1$GeneralLog", "LLN0$EventLog"]);
    for name in &journals {
        assert!(readable(&mut c, name).await, "listed journal {name} reads");
    }
    for key in ["LLN0$LG$evlog", "GGIO1$Instance"] {
        assert!(
            !readable(&mut c, key).await,
            "registry key {key} names no journal"
        );
    }
    c.disconnect().await.ok();
    h.stop().await;
}

const JOURNAL: &str = "LLN0$GeneralLog";
const BASE: u64 = 1_700_000_000_000;
const STEP: u64 = 1_000;
const COUNT: usize = 10;
const A: &str = "TESTLD0/GGIO1$ST$Ind1$stVal";
const B: &str = "TESTLD0/GGIO1$ST$Ind2$stVal";

/// Serves a journal of ten entries, one every second from `BASE`. Entry `i`
/// carries data point `A` with value `i`, and the even entries carry `B` as
/// well. Returns the handle and the EntryIDs in entry order.
async fn serve_journal() -> (ServerHandle, Vec<LogEntryId>) {
    let srv = server();
    let storage = Arc::new(InMemoryLogStorage::new());
    let mut ids = Vec::new();
    for i in 0..COUNT {
        let id = storage.add_entry(BASE + i as u64 * STEP).unwrap();
        storage
            .add_entry_data(id, A, MmsValue::Integer(i as i64), 0x02)
            .unwrap();
        if i % 2 == 0 {
            storage
                .add_entry_data(id, B, MmsValue::Boolean(true), 0x04)
                .unwrap();
        }
        ids.push(id);
    }
    let lc = LogControl::new(
        format!("{DOM}/LLN0$LG$evlog"),
        LogControlBlock::new("evlog"),
    )
    .with_storage(storage);
    srv.register_log_control(DOM, "LLN0$LG$evlog", Arc::new(lc));
    (srv.start().await.unwrap(), ids)
}

/// The indices of the entries a response carries.
fn indices(resp: &ReadJournalResponse) -> Vec<u64> {
    resp.entries
        .iter()
        .map(|e| (e.occurence_time_ms - BASE) / STEP)
        .collect()
}

async fn query(req: ReadJournalRequest) -> ReadJournalResponse {
    let (h, _) = serve_journal().await;
    let mut c = client(&h).await;
    let resp = c.read_journal(&req).await.expect("read journal");
    c.disconnect().await.ok();
    h.stop().await;
    resp
}

/// QueryLogByTime with a RangeStartTime alone selects through the newest
/// entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_time_alone_selects_through_the_newest_entry() {
    let resp = query(
        ReadJournalRequest::new(DOM, JOURNAL)
            .with_range_start(JournalRangeStart::StartingTime(BASE + 5 * STEP)),
    )
    .await;
    assert_eq!(indices(&resp), vec![5, 6, 7, 8, 9]);
    assert_eq!(resp.more_follows, Some(false));
}

/// QueryLogByTime with both times selects the entries between them, both
/// included, with every data point and its reason code.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_and_an_end_time_bound_the_selection() {
    let resp = query(ReadJournalRequest::time_range(
        DOM,
        JOURNAL,
        BASE + 2 * STEP,
        BASE + 4 * STEP,
    ))
    .await;
    assert_eq!(indices(&resp), vec![2, 3, 4]);
    let refs: Vec<Vec<&str>> = resp
        .entries
        .iter()
        .map(|e| e.variables.iter().map(|v| v.data_ref.as_str()).collect())
        .collect();
    assert_eq!(refs, vec![vec![A, B], vec![A], vec![A, B]]);
    assert_eq!(resp.entries[1].variables[0].reason_code, 0x02);
}

/// QueryLogAfter with an endingTime resumes after the entry and still stops
/// at the end time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_log_after_with_an_end_time_stops_at_it() {
    let (h, ids) = serve_journal().await;
    let mut c = client(&h).await;
    let req = ReadJournalRequest::start_after(DOM, JOURNAL, BASE + 3 * STEP, ids[3].to_be_bytes())
        .with_range_stop(JournalRangeStop::EndingTime(BASE + 6 * STEP));
    let resp = c.read_journal(&req).await.expect("read journal");
    assert_eq!(indices(&resp), vec![4, 5, 6]);
    assert_eq!(resp.more_follows, Some(false));
    c.disconnect().await.ok();
    h.stop().await;
}

/// A listOfVariables keeps only the listed data points, and an entry left
/// with none is not returned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_list_of_variables_keeps_only_the_listed_data_points() {
    let resp = query(ReadJournalRequest::new(DOM, JOURNAL).with_list_of_variables([B])).await;
    assert_eq!(indices(&resp), vec![0, 2, 4, 6, 8]);
    for e in &resp.entries {
        assert_eq!(e.variables.len(), 1);
        assert_eq!(e.variables[0].data_ref, B);
        assert_eq!(e.variables[0].reason_code, 0x04);
    }
}

/// A startingEntry includes that entry, and numberOfEntries ends the request
/// with moreFollows clear once that many entries are returned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_starting_entry_and_a_number_of_entries_bound_the_selection() {
    let (h, ids) = serve_journal().await;
    let mut c = client(&h).await;
    let req = ReadJournalRequest::new(DOM, JOURNAL)
        .with_range_start(JournalRangeStart::StartingEntry(ids[4].to_be_bytes()))
        .with_range_stop(JournalRangeStop::NumberOfEntries(3));
    let resp = c.read_journal(&req).await.expect("read journal");
    assert_eq!(indices(&resp), vec![4, 5, 6]);
    assert_eq!(resp.more_follows, Some(false));
    c.disconnect().await.ok();
    h.stop().await;
}

/// The start time and the entryToStartAfter of one request both apply, as do
/// a numberOfEntries and a listOfVariables.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_present_field_narrows_the_selection() {
    let (h, ids) = serve_journal().await;
    let mut c = client(&h).await;
    let req = ReadJournalRequest::new(DOM, JOURNAL)
        .with_range_start(JournalRangeStart::StartingTime(BASE + 5 * STEP))
        .with_range_stop(JournalRangeStop::NumberOfEntries(2))
        .with_list_of_variables([B])
        .with_entry_to_start_after(BASE, ids[0].to_be_bytes());
    let resp = c.read_journal(&req).await.expect("read journal");
    assert_eq!(indices(&resp), vec![6, 8]);
    assert_eq!(resp.more_follows, Some(false));
    c.disconnect().await.ok();
    h.stop().await;
}
