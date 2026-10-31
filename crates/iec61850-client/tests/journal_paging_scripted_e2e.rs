//! `IedConnection::query_journal_all` against scripted servers that page a
//! journal in ways the crate's own server does not, over real TCP and the full
//! ISO stack.
//!
//! The journal holds `TOTAL` entries; entry `i` has the EntryID `i + 1` and
//! the time `BASE + (i / PER_TIME) * STEP`, so `PER_TIME` entries share each
//! time. Each response carries at most `PAGE` entries, which is not a multiple
//! of `PER_TIME`, so a page ends at different places within a time.

mod support;

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use bytes::BytesMut;
use iec61850_client::{ClientError, ClientJournalEntryId, IedConnection, JournalQuery};
use iec61850_mms::mms::pdu::common::MmsData;
use iec61850_mms::mms::pdu::{
    decode_confirmed_read_journal_request, encode_confirmed_read_journal_response,
    JournalRangeStart, JournalRangeStop, ReadJournalRequest, ReadJournalResponse, WireJournalEntry,
    WireJournalVariable,
};
use iec61850_mms::MmsClientBuilder;
use support::Plan;

const LOG_REF: &str = "IED1LD0/LLN0$GeneralLog";
const BASE: u64 = 1_700_000_000_000;
const STEP: u64 = 10;
const TOTAL: usize = 2_100;
const PER_TIME: usize = 4;
const PAGE: usize = 50;
/// Requests after which a server that does not advance stops reporting more
/// entries.
const STUCK_REQUESTS: u32 = 50;

/// How a scripted server pages the journal.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Paging {
    /// Resumes after the entry of entryToStartAfter and honours every bound.
    Exact,
    /// Resumes at the entry of entryToStartAfter, sending it again.
    CursorIncluded,
    /// Resumes at the first entry of the time of entryToStartAfter, sending
    /// again the entries of that time up to and including that entry.
    CursorTime,
    /// Resumes at the first entry of the time of entryToStartAfter but leaves
    /// that entry out, sending again the other entries of that time ahead of
    /// it.
    CursorTimeWithoutCursor,
    /// Resumes after the entry of entryToStartAfter, but ignores endingTime
    /// unless startingTime is present.
    EndTimeIgnored,
    /// Answers the first request with the first three entries and every
    /// continuation with the entry it resumes after, always with moreFollows.
    Stuck,
    /// Ignores entryToStartAfter, answering every request with the first
    /// page, always with moreFollows.
    CursorIgnored,
    /// Answers every continuation with the first page short of its last five
    /// entries, older than the entry it resumes after, always with
    /// moreFollows.
    GoesBack,
    /// Pages like `Exact` a journal whose clock steps back after the first
    /// page: every entry from `PAGE` on is `CLOCK_STEP_BACK` older than its
    /// time.
    ClockBack,
}

/// How far the clock of the `ClockBack` journal steps back.
const CLOCK_STEP_BACK: u64 = 100 * STEP;

/// The time of entry `i` in the journal `paging` serves.
fn entry_time(paging: Paging, i: usize) -> u64 {
    if paging == Paging::ClockBack && i >= PAGE {
        time(i) - CLOCK_STEP_BACK
    } else {
        time(i)
    }
}

fn time(i: usize) -> u64 {
    BASE + (i / PER_TIME) as u64 * STEP
}

fn entry_id(i: usize) -> [u8; 8] {
    (i as u64 + 1).to_be_bytes()
}

fn index(id: ClientJournalEntryId) -> usize {
    (id.as_u64() - 1) as usize
}

/// The indices from `from` on whose time lies between `start_ms` and
/// `end_ms`, both included.
fn expected(from: usize, start_ms: u64, end_ms: u64) -> Vec<usize> {
    (from..TOTAL)
        .filter(|&i| time(i) >= start_ms && time(i) <= end_ms)
        .collect()
}

/// The entries of `req` as `paging` selects them, and whether more follow.
fn select(paging: Paging, req: &ReadJournalRequest, requests: u32) -> (Vec<usize>, bool) {
    let cursor = req
        .entry_to_start_after
        .map(|a| (a.time_ms, (u64::from_be_bytes(a.entry_id) - 1) as usize));
    let more = requests < STUCK_REQUESTS;
    match (paging, cursor) {
        (Paging::Stuck, None) => return ((0..3).collect(), true),
        (Paging::Stuck, Some((_, i))) => return (vec![i], more),
        (Paging::CursorIgnored, _) | (Paging::GoesBack, None) => {
            return ((0..PAGE).collect(), more)
        }
        (Paging::GoesBack, Some(_)) => return ((0..PAGE - 5).collect(), more),
        _ => {}
    }
    let start = match req.range_start {
        Some(JournalRangeStart::StartingTime(ms)) => ms,
        _ => 0,
    };
    let end = match req.range_stop {
        Some(JournalRangeStop::EndingTime(_))
            if paging == Paging::EndTimeIgnored && req.range_start.is_none() =>
        {
            u64::MAX
        }
        Some(JournalRangeStop::EndingTime(ms)) => ms,
        _ => u64::MAX,
    };
    let (first, skip) = match cursor {
        None => (0, None),
        Some((time_ms, i)) => match paging {
            Paging::CursorIncluded => (i, None),
            Paging::CursorTime => ((0..TOTAL).find(|&j| time(j) >= time_ms).unwrap(), None),
            Paging::CursorTimeWithoutCursor => {
                ((0..TOTAL).find(|&j| time(j) >= time_ms).unwrap(), Some(i))
            }
            _ => (i + 1, None),
        },
    };
    let selected: Vec<usize> = (first..TOTAL)
        .filter(|&i| Some(i) != skip && time(i) >= start && time(i) <= end)
        .collect();
    let more = selected.len() > PAGE;
    (selected.into_iter().take(PAGE).collect(), more)
}

fn journal_page(paging: Paging, invoke_id: u32, indices: &[usize], more: bool) -> Plan {
    let entries = indices
        .iter()
        .map(|&i| {
            WireJournalEntry::new(
                entry_id(i),
                entry_time(paging, i),
                vec![WireJournalVariable::new(
                    "IED1LD0/GGIO1$ST$Ind1$stVal",
                    MmsData::Boolean(i % 2 == 0),
                    0x02,
                )],
            )
        })
        .collect();
    let mut buf = BytesMut::new();
    encode_confirmed_read_journal_response(
        invoke_id,
        &ReadJournalResponse {
            entries,
            more_follows: more.then_some(true),
        },
        &mut buf,
    );
    Plan::reply(buf.freeze())
}

/// What a read from a scripted server gave and what the server saw.
struct Read {
    /// The entries read, as indices.
    result: Result<Vec<usize>, ClientError>,
    /// ReadJournal requests the server answered.
    requests: u32,
    /// Requests that arrived after the server had sent an entry later than
    /// their endingTime.
    past_end_requests: u32,
}

/// Reads `query` to the end from a server that pages as `paging` says.
async fn read_all(paging: Paging, query: &JournalQuery) -> Read {
    let requests = Arc::new(AtomicU32::new(0));
    let past_end_requests = Arc::new(AtomicU32::new(0));
    let latest_sent = Arc::new(AtomicU64::new(0));
    let (counter, past_end, latest) = (
        Arc::clone(&requests),
        Arc::clone(&past_end_requests),
        Arc::clone(&latest_sent),
    );
    let port = support::start(Arc::new(move |mms: &[u8], _seq: u32| {
        let (invoke_id, req) = decode_confirmed_read_journal_request(mms).ok()?;
        let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
        if let Some(JournalRangeStop::EndingTime(end)) = req.range_stop {
            if latest.load(Ordering::SeqCst) > end {
                past_end.fetch_add(1, Ordering::SeqCst);
            }
        }
        let (indices, more) = select(paging, &req, n);
        if let Some(latest_time) = indices.iter().map(|&i| time(i)).max() {
            latest.fetch_max(latest_time, Ordering::SeqCst);
        }
        Some(journal_page(paging, invoke_id, &indices, more))
    }))
    .await;
    let conn = IedConnection::with_mms_client(
        MmsClientBuilder::new()
            .connect_timeout_ms(3_000)
            .request_timeout_ms(3_000)
            .build(),
    );
    conn.connect("127.0.0.1", port).await.expect("connect");
    let result = conn
        .query_journal_all(LOG_REF, query)
        .await
        .map(|all| all.iter().map(|e| index(e.entry_id)).collect());
    Read {
        result,
        requests: requests.load(Ordering::SeqCst),
        past_end_requests: past_end_requests.load(Ordering::SeqCst),
    }
}

/// QueryLogByTime from the time of entry 10 to the time of entry 2000.
fn by_time() -> JournalQuery {
    JournalQuery::by_time(time(10), time(2_000))
}

fn by_time_expected() -> Vec<usize> {
    expected(0, time(10), time(2_000))
}

/// QueryLogAfter entry 5, which has entries of its time on both sides, with
/// the end time of entry 1500.
fn after_with_end_time() -> JournalQuery {
    JournalQuery::after_entry(time(5), ClientJournalEntryId(entry_id(5))).with_end_time(time(1_500))
}

fn after_with_end_time_expected() -> Vec<usize> {
    expected(6, 0, time(1_500))
}

/// The whole journal, through a query that sets only an end time.
fn whole_journal() -> JournalQuery {
    JournalQuery::new().with_end_time(time(TOTAL - 1))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_exact_server_pages_to_the_selection() {
    let read = read_all(Paging::Exact, &by_time()).await;
    assert_eq!(read.result.unwrap(), by_time_expected());
    let read = read_all(Paging::Exact, &after_with_end_time()).await;
    assert_eq!(read.result.unwrap(), after_with_end_time_expected());
    assert_eq!(read.past_end_requests, 0);
}

/// A server that sends the cursor entry again at the head of each
/// continuation still yields every entry once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_that_includes_the_cursor_yields_each_entry_once() {
    let read = read_all(Paging::CursorIncluded, &by_time()).await;
    assert_eq!(read.result.unwrap(), by_time_expected());
    let read = read_all(Paging::CursorIncluded, &after_with_end_time()).await;
    assert_eq!(read.result.unwrap(), after_with_end_time_expected());
}

/// A server that resumes at the time of the cursor sends again the entries of
/// that time up to the cursor entry; they are dropped, also ahead of the
/// first page of QueryLogAfter, and the whole journal reads as `TOTAL`
/// distinct entries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_that_resumes_at_the_cursor_time_yields_each_entry_once() {
    let read = read_all(Paging::CursorTime, &whole_journal()).await;
    assert_eq!(read.result.unwrap(), (0..TOTAL).collect::<Vec<_>>());
    let read = read_all(Paging::CursorTime, &by_time()).await;
    assert_eq!(read.result.unwrap(), by_time_expected());
    let read = read_all(Paging::CursorTime, &after_with_end_time()).await;
    assert_eq!(read.result.unwrap(), after_with_end_time_expected());
}

/// A server that resumes at the time of the cursor without the cursor entry
/// sends again the entries of that time already received; they are dropped,
/// and the entries of that time not yet received are kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_that_resends_received_entries_of_the_cursor_time_yields_each_once() {
    let read = read_all(Paging::CursorTimeWithoutCursor, &whole_journal()).await;
    assert_eq!(read.result.unwrap(), (0..TOTAL).collect::<Vec<_>>());
    let read = read_all(Paging::CursorTimeWithoutCursor, &by_time()).await;
    assert_eq!(read.result.unwrap(), by_time_expected());
}

/// A server that ignores the end time of QueryLogAfter: the entries past it
/// are dropped and no request follows the page that reached past it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_that_ignores_the_end_time_is_cut_at_it() {
    let read = read_all(Paging::EndTimeIgnored, &after_with_end_time()).await;
    assert_eq!(read.result.unwrap(), after_with_end_time_expected());
    assert_eq!(read.past_end_requests, 0);
    assert!(read.requests > 1);
    let read = read_all(Paging::EndTimeIgnored, &by_time()).await;
    assert_eq!(read.result.unwrap(), by_time_expected());
}

/// A server that reports more entries but sends only the cursor entry again
/// ends the read with `JournalNotAdvancing` after one continuation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_that_does_not_advance_is_an_error() {
    let read = read_all(Paging::Stuck, &by_time()).await;
    assert_eq!(read.result, Err(ClientError::JournalNotAdvancing));
    assert_eq!(read.requests, 2);
}

/// A server that ignores entryToStartAfter, sending the first page again or
/// entries older than the cursor, ends the read with `JournalNotAdvancing`
/// after one continuation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_that_ignores_the_cursor_is_an_error() {
    for paging in [Paging::CursorIgnored, Paging::GoesBack] {
        let read = read_all(paging, &JournalQuery::new()).await;
        assert_eq!(read.result, Err(ClientError::JournalNotAdvancing));
        assert_eq!(read.requests, 2);
    }
}

/// A journal whose clock steps back between two pages reads to the end: the
/// entries are new, although older than the entry the page resumes after.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_journal_whose_clock_steps_back_reads_to_the_end() {
    let read = read_all(Paging::ClockBack, &JournalQuery::new()).await;
    assert_eq!(read.result.unwrap(), (0..TOTAL).collect::<Vec<_>>());
}

/// An entry count ends the read once that many entries are received, from a
/// server that ignores numberOfEntries and sends the cursor entry again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_entry_count_ends_the_read_once_received() {
    let read = read_all(
        Paging::CursorIncluded,
        &JournalQuery::new().with_max_entries(120),
    )
    .await;
    assert_eq!(read.result.unwrap(), (0..120).collect::<Vec<_>>());
    assert_eq!(read.requests, 3);
}
