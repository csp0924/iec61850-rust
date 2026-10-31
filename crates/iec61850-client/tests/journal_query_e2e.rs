//! Journal queries through `IedConnection` over a real association, including
//! the continuation pages a server sends when the selection outgrows one PDU.

use std::net::SocketAddr;
use std::sync::Arc;

use iec61850_client::{ClientJournalEntry, IedConnection, JournalQuery};
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_model::{IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue};
use iec61850_server::logging::{InMemoryLogStorage, LogControl, LogControlBlock, LogStorage};
use iec61850_server::{IedServer, IedServerConfig, ServerHandle};

const DOMAIN: &str = "IED1LD0";
const LOG_REF: &str = "IED1LD0/LLN0$GeneralLog";
const BASE: u64 = 1_700_000_000_000;
const STEP: u64 = 10;
const TOTAL: u64 = 2_500;
const VALUE: &str = "IED1LD0/MMXU1$MX$A$mag$f";
const FLAG: &str = "IED1LD0/GGIO1$ST$Ind1$stVal";

/// Serves a journal of `TOTAL` entries, one every `STEP` ms from `BASE`.
/// Entry `i` carries `VALUE`, and every tenth entry carries `FLAG` as well.
async fn serve() -> ServerHandle {
    let lln0 = LogicalNodeBuilder::lln0().build().unwrap();
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .build()
        .unwrap();
    let model = Arc::new(
        IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap(),
    );
    let server = IedServer::builder()
        .model(model)
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig::default())
        .build()
        .unwrap();
    let storage = Arc::new(InMemoryLogStorage::new());
    for i in 0..TOTAL {
        let id = storage.add_entry(BASE + i * STEP).unwrap();
        storage
            .add_entry_data(id, VALUE, MmsValue::Float32(i as f32), 0x02)
            .unwrap();
        if i % 10 == 0 {
            storage
                .add_entry_data(id, FLAG, MmsValue::Boolean(true), 0x02)
                .unwrap();
        }
    }
    let lc = LogControl::new(
        format!("{DOMAIN}/LLN0$LG$evlog"),
        LogControlBlock::new("evlog"),
    )
    .with_storage(storage);
    server.register_log_control(DOMAIN, "LLN0$LG$evlog", Arc::new(lc));
    server.start().await.unwrap()
}

/// Connects with a 2 000-octet PDU size, so a response holds a few dozen
/// entries and a large selection takes many pages.
async fn connect(h: &ServerHandle) -> IedConnection {
    let conn = IedConnection::with_mms_client(
        MmsClientBuilder::new()
            .local_max_pdu_size(2_000)
            .connect_timeout_ms(3_000)
            .request_timeout_ms(3_000)
            .build(),
    );
    conn.connect("127.0.0.1", h.bound_addr.port())
        .await
        .unwrap();
    conn
}

fn index(e: &ClientJournalEntry) -> u64 {
    (e.time_ms - BASE) / STEP
}

/// A time-range query read page by page never runs past its end time: every
/// continuation keeps it, so the result is exactly the entries in range.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paging_a_time_range_keeps_its_end_time() {
    let h = serve().await;
    let conn = connect(&h).await;
    let end = 2_200;
    let query = JournalQuery::by_time(BASE + 100 * STEP, BASE + end * STEP);

    let (first, more) = conn.query_journal(LOG_REF, &query).await.unwrap();
    assert!(more, "the selection must outgrow one response");
    assert!(first.len() < 200);

    let all = conn.query_journal_all(LOG_REF, &query).await.unwrap();
    let got: Vec<u64> = all.iter().map(index).collect();
    assert_eq!(got, (100..=end).collect::<Vec<_>>());
    h.stop().await;
}

/// QueryLogAfter with an end time pages to the end time and no further.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paging_query_log_after_with_an_end_time_stops_at_it() {
    let h = serve().await;
    let conn = connect(&h).await;
    let (head, _) = conn
        .query_journal(LOG_REF, &JournalQuery::by_time(BASE, BASE + 5 * STEP))
        .await
        .unwrap();
    let cursor = &head[5];
    let query = JournalQuery::after_entry(cursor.time_ms, cursor.entry_id)
        .with_end_time(BASE + 1_500 * STEP);
    let all = conn.query_journal_all(LOG_REF, &query).await.unwrap();
    let got: Vec<u64> = all.iter().map(index).collect();
    assert_eq!(got, (6..=1_500).collect::<Vec<_>>());
    h.stop().await;
}

/// A variable list returns only the listed data points, across pages.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_variable_list_returns_only_the_listed_data_points() {
    let h = serve().await;
    let conn = connect(&h).await;
    let all = conn
        .query_journal_all(LOG_REF, &JournalQuery::new().with_variables([FLAG]))
        .await
        .unwrap();
    let got: Vec<u64> = all.iter().map(index).collect();
    assert_eq!(got, (0..TOTAL).step_by(10).collect::<Vec<_>>());
    assert!(all
        .iter()
        .all(|e| e.variables.len() == 1 && e.variables[0].data_ref == FLAG));
    h.stop().await;
}

/// An entry count bounds the total across pages, and the last continuation
/// asks only for the remainder.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_entry_count_bounds_the_total_across_pages() {
    let h = serve().await;
    let conn = connect(&h).await;
    let query = JournalQuery::new()
        .with_start_time(BASE + 300 * STEP)
        .with_max_entries(1_000);
    let all = conn.query_journal_all(LOG_REF, &query).await.unwrap();
    let got: Vec<u64> = all.iter().map(index).collect();
    assert_eq!(got, (300..1_300).collect::<Vec<_>>());
    h.stop().await;
}
