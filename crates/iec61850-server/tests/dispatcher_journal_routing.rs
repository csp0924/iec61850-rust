//! Integration tests for ReadJournal routing through the model dispatcher.
//!
//! A log control block backed by in-memory storage is registered and filled
//! with entries; the tests then encode complete ReadJournal request bytes, call
//! the dispatcher, decode the response and check that the entries and their
//! reason codes come back intact. An unregistered control block must answer
//! ConfirmedError(ObjectNonExistent), and WriteJournal must answer
//! ConfirmedError(ObjectAccessUnsupported).

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
use iec61850_server::logging::{
    storage::CollectingVisitor, InMemoryLogStorage, LogControl, LogControlBlock, LogStorage,
};
use iec61850_server::mapping::MmsDeviceModel;
use iec61850_server::policy::WriteAccessPolicies;
use iec61850_server::reporting::TriggerOptions;
use iec61850_server::service::MmsModelDispatcher;
use std::sync::Arc;

const DOMAIN: &str = "IED1LD0";
const ITEM: &str = "MMXU1$LG$lcb01";

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

fn build_dispatcher_with_lcb(prefill_entries: usize) -> (MmsModelDispatcher, Arc<dyn LogStorage>) {
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

    // Prefill entries through the storage handle the trigger path also uses.
    for i in 0..prefill_entries {
        let time_ms = 1_700_000_000_000u64 + (i as u64) * 1_000;
        // The reason code is the trigger option shifted left by one, so a data
        // change becomes 0x02.
        lc.log_single_value(
            time_ms,
            "LD0/MMXU1$MX$A$mag$f",
            MmsValue::Float32(1.0 + i as f32),
            0x02,
        )
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

#[test]
fn read_journal_time_range_returns_all_entries() {
    let (dispatcher, _storage) = build_dispatcher_with_lcb(3);
    let conn = make_conn();

    let req = ReadJournalRequest::time_range(
        DOMAIN,
        ITEM,
        // BinaryTime6 counts from 1984, so the test values are past that epoch.
        1_700_000_000_000,
        1_700_000_010_000,
    );
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

    let (id, parsed) = decode_confirmed_read_journal_response(&bytes).unwrap();
    assert_eq!(id, 7);
    assert_eq!(parsed.entries.len(), 3, "all three entries must come back");

    // Each entry carries one logical data point plus its reason code, encoded
    // as two variable elements on the wire; the decoder folds them back into a
    // single journal variable.
    let first = &parsed.entries[0];
    assert_eq!(first.variables.len(), 1);
    assert_eq!(first.variables[0].data_ref, "LD0/MMXU1$MX$A$mag$f");
    assert_eq!(first.variables[0].reason_code, 0x02);

    // Entry identifiers increase strictly; the in-memory backend counts up.
    let id1 = u64::from_be_bytes(parsed.entries[0].entry_id);
    let id2 = u64::from_be_bytes(parsed.entries[1].entry_id);
    let id3 = u64::from_be_bytes(parsed.entries[2].entry_id);
    assert!(
        id1 < id2 && id2 < id3,
        "entry identifiers must increase strictly"
    );
}

#[test]
fn read_journal_start_after_skips_first_entry() {
    let (dispatcher, storage) = build_dispatcher_with_lcb(3);
    let conn = make_conn();

    // Using the first entry identifier as the cursor must return the other two.
    let mut visitor = CollectingVisitor::new();
    storage.query_by_time(0, u64::MAX, &mut visitor).unwrap();
    let first_id = visitor.entries[0].entry_id;

    let req =
        ReadJournalRequest::start_after(DOMAIN, ITEM, 1_700_000_000_000, first_id.to_be_bytes());
    let mut full = BytesMut::new();
    encode_confirmed_read_journal_request(8, &req, &mut full);
    let body = extract_service_body(&full);

    let resp = dispatcher.dispatch(
        &conn,
        ConfirmedRequest {
            invoke_id: 8,
            service_body: body,
        },
    );
    let bytes = match resp {
        ConfirmedResponse::Response(b) => b,
        other => panic!("expected a Response, got {other:?}"),
    };

    let (_id, parsed) = decode_confirmed_read_journal_response(&bytes).unwrap();
    assert_eq!(
        parsed.entries.len(),
        2,
        "a query after the first entry must return the remaining two"
    );
}

#[test]
fn read_journal_unknown_lcb_returns_object_nonexistent() {
    let (dispatcher, _storage) = build_dispatcher_with_lcb(0);
    let conn = make_conn();

    let req = ReadJournalRequest::time_range(
        DOMAIN,
        "MMXU99$LG$lcb_unknown",
        1_700_000_000_000,
        1_700_000_001_000,
    );
    let mut full = BytesMut::new();
    encode_confirmed_read_journal_request(9, &req, &mut full);
    let body = extract_service_body(&full);

    let resp = dispatcher.dispatch(
        &conn,
        ConfirmedRequest {
            invoke_id: 9,
            service_body: body,
        },
    );
    match resp {
        ConfirmedResponse::Error(bytes) => {
            assert_eq!(bytes[0], 0xa2, "the ConfirmedError tag must be 0xa2");
            // ObjectNonExistent = access(7) sub-code 10
            // The serviceError carries an explicit errorClass, so the access
            // class with ObjectNonExistent encodes as 0x87 0x01 0x0a.
            assert!(
                bytes.windows(3).any(|w| w == [0x87, 0x01, 0x0a]),
                "an unregistered log control block must answer object-nonexistent, bytes={:?}",
                bytes.as_ref()
            );
        }
        other => {
            panic!("an unregistered log control block must answer ConfirmedError, got {other:?}")
        }
    }
}

#[test]
fn write_journal_returns_object_access_unsupported() {
    let (dispatcher, _storage) = build_dispatcher_with_lcb(0);
    let conn = make_conn();

    // A well-formed WriteJournal; its content does not matter because the
    // dispatcher rejects the service outright.
    let body = Bytes::from_static(&[0xbf, 0x42, 0x00]);
    let resp = dispatcher.dispatch(
        &conn,
        ConfirmedRequest {
            invoke_id: 11,
            service_body: body,
        },
    );
    match resp {
        ConfirmedResponse::Error(bytes) => {
            assert_eq!(bytes[0], 0xa2);
            // ObjectAccessUnsupported = access(7) sub-code 9
            assert!(
                bytes.windows(3).any(|w| w == [0x87, 0x01, 0x09]),
                "WriteJournal must answer object-access-unsupported, bytes={:?}",
                bytes.as_ref()
            );
        }
        other => panic!("WriteJournal must answer ConfirmedError, got {other:?}"),
    }
}

#[test]
fn read_journal_empty_storage_returns_empty_list() {
    let (dispatcher, _storage) = build_dispatcher_with_lcb(0);
    let conn = make_conn();

    let req = ReadJournalRequest::time_range(DOMAIN, ITEM, 1_700_000_000_000, 1_700_000_009_000);
    let mut full = BytesMut::new();
    encode_confirmed_read_journal_request(13, &req, &mut full);
    let body = extract_service_body(&full);

    let resp = dispatcher.dispatch(
        &conn,
        ConfirmedRequest {
            invoke_id: 13,
            service_body: body,
        },
    );
    let bytes = match resp {
        ConfirmedResponse::Response(b) => b,
        other => panic!("expected a Response, got {other:?}"),
    };
    let (_id, parsed) = decode_confirmed_read_journal_response(&bytes).unwrap();
    assert!(
        parsed.entries.is_empty(),
        "empty storage must answer with an empty journal entry list"
    );
    // The dispatcher always reports the more-follows flag explicitly rather
    // than omitting it; with empty storage everything has been sent, so the
    // flag is present and false.
    assert_eq!(parsed.more_follows, Some(false));
}

#[test]
fn read_journal_round_trip_carries_timestamp_and_value() {
    let (dispatcher, _storage) = build_dispatcher_with_lcb(2);
    let conn = make_conn();

    let req = ReadJournalRequest::time_range(DOMAIN, ITEM, 1_700_000_000_000, 1_700_000_010_000);
    let mut full = BytesMut::new();
    encode_confirmed_read_journal_request(15, &req, &mut full);
    let body = extract_service_body(&full);

    let resp = dispatcher.dispatch(
        &conn,
        ConfirmedRequest {
            invoke_id: 15,
            service_body: body,
        },
    );
    let bytes = match resp {
        ConfirmedResponse::Response(b) => b,
        other => panic!("expected a Response, got {other:?}"),
    };
    let (_id, parsed) = decode_confirmed_read_journal_response(&bytes).unwrap();
    assert_eq!(parsed.entries.len(), 2);
    // The fixture timestamps the first entry one second before the second.
    assert_eq!(parsed.entries[0].occurence_time_ms, 1_700_000_000_000);
    assert_eq!(parsed.entries[1].occurence_time_ms, 1_700_000_001_000);
    // The first entry carries a Float32 of 1.0.
    use iec61850_mms::mms::pdu::common::MmsData;
    match &parsed.entries[0].variables[0].value {
        MmsData::Float32(f) => assert!((f - 1.0).abs() < 1e-6),
        other => panic!("expected Float32, got {other:?}"),
    }
}
