//! End-to-end tests for server-side ReadJournal segmentation and the
//! moreFollows flag.
//!
//! Two thousand entries are logged, roughly 83 bytes each on the wire, so the
//! result is far larger than a single PDU. A client queries from the start, is
//! served a partial answer with moreFollows set, and repeats the query using
//! the occurrence time and entry identifier of the last entry as a cursor until
//! moreFollows is clear. The totals must add up to every entry, with strictly
//! increasing identifiers and no duplicates.
//!
//! The server, not the test, decides where to cut each round: the truncation
//! point follows the negotiated maximum PDU size.

use bytes::{Bytes, BytesMut};
use iec61850_mms::mms::pdu::{
    decode_confirmed_read_journal_response, encode_confirmed_read_journal_request,
    ReadJournalRequest,
};
use iec61850_mms::mms::server::connection::NegotiatedParams;
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
const TOTAL_ENTRIES: usize = 2_000;
const DATA_REF: &str = "LD0/MMXU1$MX$A$mag$f";

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

fn build_dispatcher_with_prefilled_lcb(
    prefill: usize,
) -> (MmsModelDispatcher, Arc<dyn LogStorage>) {
    let model = build_min_model();
    let mms_model = MmsDeviceModel::from_ied_model(&model).unwrap();
    let policies = WriteAccessPolicies::default();

    let storage: Arc<dyn LogStorage> = Arc::new(InMemoryLogStorage::new());
    let lcb_block = LogControlBlock::new("lcb01")
        .with_dataset("MMXU1$ds1")
        .with_log_ref("IED1LD0/MMXU1$GeneralLog")
        .with_trg_ops(TriggerOptions::DATA_CHANGED);
    let lc = LogControl::new(format!("{DOMAIN}/{ITEM}"), lcb_block).with_storage(storage.clone());
    lc.set_log_ena(true).unwrap();

    for i in 0..prefill {
        let time_ms = BASE_TIME_MS + (i as u64) * TIME_STEP_MS;
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

/// Builds a connection that has negotiated a 65000-byte maximum PDU size, just
/// under the BER length limit, so the dispatcher truncates against it.
fn make_negotiated_conn(max_pdu_size: u32) -> MmsServerConnection {
    let mut c = MmsServerConnection::new();
    c.set_connection_id(1);
    c.set_negotiated(NegotiatedParams {
        max_pdu_size,
        ..Default::default()
    });
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

// A connection that has not negotiated a PDU size falls back to the hard cap.

#[test]
fn read_journal_unnegotiated_conn_uses_hard_cap_and_sets_more_follows() {
    let (dispatcher, _storage) = build_dispatcher_with_prefilled_lcb(TOTAL_ENTRIES);

    // No negotiated size, so the dispatcher applies its 60000-byte hard cap;
    // the full result is far larger and must be truncated.
    let mut c = MmsServerConnection::new();
    c.set_connection_id(1);

    let req = ReadJournalRequest::start_after(DOMAIN, ITEM, 0, [0u8; 8]);
    let mut full = BytesMut::new();
    encode_confirmed_read_journal_request(7, &req, &mut full);
    let body = extract_service_body(&full);

    let resp = dispatcher.dispatch(
        &c,
        ConfirmedRequest {
            invoke_id: 7,
            service_body: body,
        },
    );
    let bytes = match resp {
        ConfirmedResponse::Response(b) => b,
        other => panic!("expected a Response rather than a rejection, got {other:?}"),
    };
    let (_id, parsed) = decode_confirmed_read_journal_response(&bytes).unwrap();

    assert!(
        parsed.entries.len() < TOTAL_ENTRIES,
        "the hard cap must truncate the answer, accepted={} of {TOTAL_ENTRIES}",
        parsed.entries.len()
    );
    assert!(
        parsed.entries.len() > 100,
        "a 60 KB cap must still carry several hundred entries, accepted={}",
        parsed.entries.len()
    );
    assert_eq!(
        parsed.more_follows,
        Some(true),
        "a truncated answer must set moreFollows"
    );
}

// Paging with the occurrence time and entry identifier as a cursor terminates
// and returns every entry exactly once.

#[test]
fn read_journal_server_segmentation_cursor_iterates_all_entries() {
    let (dispatcher, _storage) = build_dispatcher_with_prefilled_lcb(TOTAL_ENTRIES);
    // With a 65000-byte PDU size the per-round budget is a little under that
    // once the headers are subtracted, so the full result takes a few rounds.
    let conn = make_negotiated_conn(65_000);

    let mut collected_ids: Vec<u64> = Vec::with_capacity(TOTAL_ENTRIES);
    let mut cursor_time: u64 = 0;
    let mut cursor_id: [u8; 8] = [0u8; 8];
    let mut rounds = 0usize;
    let max_rounds = 32usize;
    loop {
        if rounds >= max_rounds {
            panic!("paging did not converge within {max_rounds} rounds");
        }
        let req = ReadJournalRequest::start_after(DOMAIN, ITEM, cursor_time, cursor_id);
        let mut full = BytesMut::new();
        let invoke_id = 200u32 + rounds as u32;
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

        // The flag is always present; the dispatcher never omits it.
        let more = parsed
            .more_follows
            .expect("the dispatcher must always report moreFollows explicitly");

        assert!(
            !parsed.entries.is_empty() || !more,
            "round {rounds} returned no entry while claiming more follow"
        );

        let last_entry_opt = parsed.entries.last().cloned();
        for e in parsed.entries.iter() {
            collected_ids.push(u64::from_be_bytes(e.entry_id));
        }

        if !more {
            break;
        }
        // Advance the cursor to the occurrence time and identifier of the last
        // entry received.
        let last = last_entry_opt.expect("a round claiming more follow must carry entries");
        cursor_time = last.occurence_time_ms;
        cursor_id = last.entry_id;
        rounds += 1;
    }
    rounds += 1; // count the final round that cleared the flag

    eprintln!(
        "paging finished in {rounds} rounds with {} entries",
        collected_ids.len()
    );

    assert_eq!(
        collected_ids.len(),
        TOTAL_ENTRIES,
        "expected {TOTAL_ENTRIES} entries in total, got {} over {rounds} rounds",
        collected_ids.len()
    );

    // Strictly increasing, so nothing is lost or repeated.
    for (i, w) in collected_ids.windows(2).enumerate() {
        assert!(
            w[1] > w[0],
            "entry identifiers must increase strictly: idx={i} prev={} cur={}",
            w[0],
            w[1]
        );
    }

    // At roughly 83 bytes per entry the budget carries several hundred entries
    // per round, so the whole set takes a handful of rounds including the final
    // one that clears the flag.
    assert!(
        (2..=6).contains(&rounds),
        "expected between 2 and 6 rounds, got {rounds}"
    );
}

// When everything fits, moreFollows is present and clear.

#[test]
fn read_journal_fits_in_budget_returns_more_follows_false() {
    // Thirty entries fit in one round.
    let (dispatcher, _storage) = build_dispatcher_with_prefilled_lcb(30);
    let conn = make_negotiated_conn(65_000);

    let req = ReadJournalRequest::start_after(DOMAIN, ITEM, 0, [0u8; 8]);
    let mut full = BytesMut::new();
    encode_confirmed_read_journal_request(11, &req, &mut full);
    let body = extract_service_body(&full);

    let resp = dispatcher.dispatch(
        &conn,
        ConfirmedRequest {
            invoke_id: 11,
            service_body: body,
        },
    );
    let bytes = match resp {
        ConfirmedResponse::Response(b) => b,
        other => panic!("expected a Response, got {other:?}"),
    };
    let (_id, parsed) = decode_confirmed_read_journal_response(&bytes).unwrap();
    assert_eq!(parsed.entries.len(), 30);
    assert_eq!(
        parsed.more_follows,
        Some(false),
        "a complete answer must report moreFollows as present and false"
    );
}
