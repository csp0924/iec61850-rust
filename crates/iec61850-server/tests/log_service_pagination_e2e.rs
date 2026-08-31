//! End-to-end tests that ten thousand log entries can be read out page by page
//! with ReadJournal.
//!
//! A probe measures the wire size of a single entry, which is what the chunk
//! size is derived from. One test reads five hundred entries in a single
//! time-range query, checking that the decoder handles a large response with
//! strictly increasing entry identifiers and intact first and last entries. The
//! other pages through all ten thousand entries with successive time windows.
//!
//! A single query cannot carry them all: a BER length is capped at 65535 bytes
//! per PDU, segmentation being the transport's job, and at roughly 83 bytes per
//! entry ten thousand entries are an order of magnitude past that. The client
//! therefore slices the range into windows.

use bytes::{Bytes, BytesMut};
use iec61850_mms::mms::pdu::{
    decode_confirmed_read_journal_response, encode_confirmed_read_journal_request,
    ReadJournalRequest,
};
use iec61850_mms::mms::server::dispatcher::{
    ConfirmedRequest, ConfirmedResponse, MmsServiceDispatcher,
};
use iec61850_mms::mms::server::MmsServerConnection;
use iec61850_model::{IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue};
use iec61850_server::logging::{InMemoryLogStorage, LogControl, LogControlBlock, LogStorage};
use iec61850_server::mapping::MmsDeviceModel;
use iec61850_server::policy::WriteAccessPolicies;
use iec61850_server::reporting::TriggerOptions;
use iec61850_server::service::MmsModelDispatcher;
use std::sync::Arc;

const DOMAIN: &str = "IED1LD0";
const ITEM: &str = "MMXU1$LG$lcb01";
const BASE_TIME_MS: u64 = 1_700_000_000_000;
const TIME_STEP_MS: u64 = 10;
const TOTAL_ENTRIES: usize = 10_000;
const DATA_REF: &str = "LD0/MMXU1$MX$A$mag$f";

/// Entries per round, derived from the wire-size budget: at roughly 83 bytes
/// per entry the 65535-byte BER limit holds about 789, and this leaves around
/// ten percent of margin. Recompute it when the fixture changes shape.
const CHUNK_ENTRIES_PER_ROUND: usize = 700;

// These helpers mirror the journal routing test fixture; integration test
// binaries share no modules, so the code is duplicated on purpose.

fn build_min_model() -> iec61850_model::IedModel {
    let lln0 = LogicalNodeBuilder::lln0().build().unwrap();
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .build()
        .unwrap();
    IedModelBuilder::new("IED1")
        .add_ld(ld)
        .unwrap()
        .build()
        .unwrap()
}

/// Builds a dispatcher with a log control block over unbounded in-memory
/// storage, prefilled with `prefill` entries spaced 10 ms apart, each carrying
/// one Float32 data point logged on data change.
fn build_dispatcher_with_prefilled_lcb(
    prefill: usize,
) -> (MmsModelDispatcher, Arc<dyn LogStorage>) {
    let model = build_min_model();
    let mms_model = MmsDeviceModel::from_ied_model(&model).unwrap();
    let policies = WriteAccessPolicies::default();

    // The in-memory storage is unbounded, so ten thousand entries fit.
    let storage: Arc<dyn LogStorage> = Arc::new(InMemoryLogStorage::new());
    let lcb_block = LogControlBlock::new("lcb01")
        .with_dataset("MMXU1$ds1")
        .with_log_ref("IED1LD0/MMXU1$GeneralLog")
        .with_trg_ops(TriggerOptions::DATA_CHANGED);
    let lc = LogControl::new(format!("{DOMAIN}/{ITEM}"), lcb_block).with_storage(storage.clone());
    lc.set_log_ena(true).unwrap();

    for i in 0..prefill {
        let time_ms = BASE_TIME_MS + (i as u64) * TIME_STEP_MS;
        // The reason code is the trigger option shifted left by one, so a data
        // change becomes 0x02.
        lc.log_single_value(time_ms, DATA_REF, MmsValue::Float32(i as f32), 0x02)
            .unwrap();
    }

    let registry = iec61850_server::logging::new_log_control_registry();
    {
        let mut g = registry.write().unwrap();
        g.insert((DOMAIN.to_string(), ITEM.to_string()), Arc::new(lc));
    }

    let dispatcher =
        MmsModelDispatcher::new(Arc::new(model), Arc::new(mms_model), Arc::new(policies))
            .with_log_controls(registry);
    (dispatcher, storage)
}

fn make_conn() -> MmsServerConnection {
    let mut c = MmsServerConnection::new();
    c.set_connection_id(1);
    c
}

fn extract_service_body(full: &BytesMut) -> Bytes {
    let (outer_len, outer_hdr) = ber_decode_length(&full[1..]);
    let inner_start = 1 + outer_hdr;
    let inner = &full[inner_start..inner_start + outer_len];
    assert_eq!(inner[0], 0x02, "the invokeID tag must be 0x02");
    let (id_len, id_hdr) = ber_decode_length(&inner[1..]);
    let service_start = 1 + id_hdr + id_len;
    Bytes::copy_from_slice(&inner[service_start..])
}

fn ber_decode_length(data: &[u8]) -> (usize, usize) {
    if data[0] < 0x80 {
        (data[0] as usize, 1)
    } else if data[0] == 0x81 {
        (data[1] as usize, 2)
    } else if data[0] == 0x82 {
        (((data[1] as usize) << 8) | (data[2] as usize), 3)
    } else {
        panic!("unsupported length form 0x{:02X}", data[0]);
    }
}

// Measures the wire size of a single entry, which the chunk size is derived
// from.

#[test]
fn probe_entry_wire_size() {
    // Averaged over a hundred entries so the fixed response overhead does not
    // distort it. The measurement is printed with --nocapture; nothing asserts
    // on the value itself.
    let n = 100usize;
    let (dispatcher, _) = build_dispatcher_with_prefilled_lcb(n);
    let conn = make_conn();
    let req = ReadJournalRequest::time_range(
        DOMAIN,
        ITEM,
        BASE_TIME_MS,
        BASE_TIME_MS + (n as u64) * TIME_STEP_MS,
    );
    let mut full = BytesMut::new();
    encode_confirmed_read_journal_request(1, &req, &mut full);
    let body = extract_service_body(&full);
    let resp = dispatcher.dispatch(
        &conn,
        ConfirmedRequest {
            invoke_id: 1,
            service_body: body,
        },
    );
    let bytes = match resp {
        ConfirmedResponse::Response(b) => b,
        other => panic!("the probe query must answer with a Response, got {other:?}"),
    };
    let per_entry = bytes.len() / n;
    eprintln!(
        "probe: {n} entries -> {} bytes wire (~{per_entry} bytes/entry)",
        bytes.len()
    );
    // The chunk must still fit inside the 65535-byte BER length cap.
    assert!(
        CHUNK_ENTRIES_PER_ROUND * per_entry < 60_000,
        "a chunk of {CHUNK_ENTRIES_PER_ROUND} entries is about {} bytes, too close to the 65535-byte cap",
        CHUNK_ENTRIES_PER_ROUND * per_entry
    );
}

// A large but wire-safe single time-range query.

#[test]
fn read_journal_full_time_range_returns_all_entries_within_pdu_cap() {
    // Five hundred entries are around 41 kB, safely inside the cap.
    const N: usize = 500;
    let (dispatcher, _storage) = build_dispatcher_with_prefilled_lcb(N);
    let conn = make_conn();

    let end_time = BASE_TIME_MS + (N as u64) * TIME_STEP_MS;
    let req = ReadJournalRequest::time_range(DOMAIN, ITEM, BASE_TIME_MS, end_time);

    let mut full = BytesMut::new();
    encode_confirmed_read_journal_request(7, &req, &mut full);
    let body = extract_service_body(&full);

    let resp = dispatcher.dispatch(
        &conn,
        ConfirmedRequest {
            invoke_id: 7,
            service_body: body,
        },
    );
    let bytes = match resp {
        ConfirmedResponse::Response(b) => b,
        other => panic!("expected a Response, got {other:?}"),
    };

    // The assertions go through the decoder rather than over raw bytes.
    let (id, parsed) = decode_confirmed_read_journal_response(&bytes).unwrap();
    assert_eq!(id, 7);
    assert_eq!(
        parsed.entries.len(),
        N,
        "the query must return all {N} entries"
    );

    // Entry identifiers increase strictly; the backend counts up.
    let mut prev = 0u64;
    for (idx, e) in parsed.entries.iter().enumerate() {
        let cur = u64::from_be_bytes(e.entry_id);
        assert!(
            cur > prev,
            "entry identifiers must increase strictly: idx={idx} prev={prev} cur={cur}"
        );
        prev = cur;
    }

    // The first entry decodes back to the data-change reason.
    assert_eq!(parsed.entries[0].variables.len(), 1);
    assert_eq!(parsed.entries[0].variables[0].reason_code, 0x02);

    // The last entry matches the fixture, so nothing was truncated.
    assert_eq!(
        parsed.entries.last().unwrap().variables[0].data_ref,
        DATA_REF
    );
}

// Paging through every entry with successive time windows.

#[test]
fn read_journal_time_window_pagination_iterates_all_10000() {
    let (dispatcher, _storage) = build_dispatcher_with_prefilled_lcb(TOTAL_ENTRIES);
    let conn = make_conn();

    // Each round asks for one window of chunk_entries times the entry spacing.
    // A time range is used rather than a start cursor because a start cursor
    // has no upper bound and would ask for every entry at once.
    let window_ms: u64 = (CHUNK_ENTRIES_PER_ROUND as u64) * TIME_STEP_MS;
    let mut t_cursor: u64 = BASE_TIME_MS;
    let t_end_global: u64 = BASE_TIME_MS + (TOTAL_ENTRIES as u64) * TIME_STEP_MS;
    let mut collected_ids: Vec<u64> = Vec::with_capacity(TOTAL_ENTRIES);
    let mut rounds = 0usize;
    let max_rounds = 64; // safety stop; around fifteen rounds are expected

    while t_cursor < t_end_global && rounds < max_rounds {
        // The time range includes both bounds, so the next window starts one
        // millisecond later to avoid repeating an entry.
        let t_window_end = (t_cursor + window_ms).min(t_end_global);
        let req = ReadJournalRequest::time_range(DOMAIN, ITEM, t_cursor, t_window_end);

        let mut full = BytesMut::new();
        let invoke_id = 100u32 + rounds as u32;
        encode_confirmed_read_journal_request(invoke_id, &req, &mut full);
        let body = extract_service_body(&full);

        let resp = dispatcher.dispatch(
            &conn,
            ConfirmedRequest {
                invoke_id,
                service_body: body,
            },
        );
        let bytes = match resp {
            ConfirmedResponse::Response(b) => b,
            other => panic!("round {rounds} must answer with a Response, got {other:?}"),
        };
        let (_id, parsed) = decode_confirmed_read_journal_response(&bytes).unwrap();

        // Every entry is collected; the identifier check below would catch a
        // duplicate if the windows ever overlapped.
        for e in parsed.entries.iter() {
            let id = u64::from_be_bytes(e.entry_id);
            collected_ids.push(id);
        }

        // Advance past the upper bound of the window just read.
        t_cursor = t_window_end.saturating_add(1);
        rounds += 1;
    }

    assert_eq!(
        collected_ids.len(),
        TOTAL_ENTRIES,
        "expected {TOTAL_ENTRIES} entries in total, got {} over {rounds} rounds",
        collected_ids.len()
    );

    // Strictly increasing across rounds, so paging never went back, skipped or
    // repeated an entry.
    for (i, w) in collected_ids.windows(2).enumerate() {
        assert!(
            w[1] > w[0],
            "entry identifiers must increase strictly: idx={i} prev={} cur={}",
            w[0],
            w[1]
        );
    }

    // With this chunk size the full set takes about fifteen rounds; the bounds
    // below leave room for the entry size to drift.
    eprintln!("paging took {rounds} rounds");
    assert!(
        (12..=20).contains(&rounds),
        "expected between 12 and 20 rounds, got {rounds}"
    );
}
