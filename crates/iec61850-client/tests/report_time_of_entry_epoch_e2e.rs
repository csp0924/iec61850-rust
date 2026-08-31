//! End-to-end check that TimeOfEntry survives the server-to-client path exactly.
//!
//! The server encodes a report PDU with an injected timestamp, the MMS layer
//! decodes the InformationReport, and the client report parser recovers the
//! instant. Server and client must agree that the BinaryTime6 wire epoch is
//! 1984-01-01, per ISO 9506 and IEC 61850-8-1; a mismatch shifts every reported
//! timestamp by the 14 years between 1970-01-01 and that epoch.
//!
//! Run with `cargo test -p iec61850-client --test report_time_of_entry_epoch_e2e`.

use iec61850_client::mms_compat::mms_data_to_mms_value;
use iec61850_client::report::parse_report;
use iec61850_mms::mms::pdu::information_report::decode_information_report;
use iec61850_mms::EPOCH_1984_MS;
use iec61850_model::MmsValue;
use iec61850_server::reporting::{
    encode_report_pdus, Dataset, DatasetEntry, InclusionFlag, OptFlds, PendingReport,
    ReportEncodeParams,
};
use std::sync::{Arc, RwLock};

/// 2023-11-14T22:13:20.000Z, an instant the six-octet BinaryTime form can hold.
const INJECTED_TIME_OF_ENTRY_MS: u64 = 1_700_000_000_000;

fn single_entry_dataset() -> Dataset {
    let mut ds = Dataset::new("ds1");
    ds.push(DatasetEntry::new(
        "IED1LD0/GGIO1$ST$Ind1$stVal",
        Arc::new(RwLock::new(MmsValue::Boolean(false))),
    ));
    ds
}

fn data_change_pending(time_of_entry_ms: u64) -> PendingReport {
    let mut p = PendingReport::new_empty(1, time_of_entry_ms);
    p.inclusion_flags[0] = InclusionFlag::VALUE_CHANGED;
    p.snapshot[0] = Some(MmsValue::Boolean(true));
    p
}

/// Encodes one report PDU on the server side and parses it on the client side.
fn round_trip_time_of_entry(time_of_entry_ms: u64) -> u64 {
    let ds = single_entry_dataset();
    let pending = data_change_pending(time_of_entry_ms);
    let params = ReportEncodeParams {
        rpt_id: "IED1LD0/GGIO1$RP$urcb01",
        opt_flds: OptFlds::SEQ_NUM | OptFlds::TIME_STAMP | OptFlds::REASON,
        sq_num: 1,
        time_of_entry_ms,
        dat_set: "GGIO1$ds1",
        conf_rev: 1,
        dataset: &ds,
        pending: &pending,
        max_pdu_size_bytes: 65000,
    };

    let pdus = encode_report_pdus(&params).expect("report encoding must succeed");
    assert_eq!(pdus.len(), 1, "a one-entry report fits in a single pdu");

    // Strip the unconfirmedPDU [3] tag and its length to reach the inner bytes
    // the InformationReport decoder expects.
    let pdu = &pdus[0];
    assert_eq!(pdu[0], 0xa3, "the outer tag must be unconfirmedPDU [3]");
    let inner = strip_definite_length_header(pdu);

    let report = decode_information_report(inner).expect("information report must decode");
    let elements: Vec<MmsValue> = report
        .list_of_access_result
        .iter()
        .map(mms_data_to_mms_value)
        .collect();
    let parsed = parse_report(&MmsValue::Array(elements)).expect("report must parse");

    parsed
        .timestamp_ms
        .expect("the TIME_STAMP option field was set, so TimeOfEntry must be present")
}

/// Returns the value bytes of a BER TLV whose tag occupies one byte.
fn strip_definite_length_header(tlv: &[u8]) -> &[u8] {
    let first = tlv[1];
    if first & 0x80 == 0 {
        &tlv[2..]
    } else {
        let n = (first & 0x7f) as usize;
        &tlv[2 + n..]
    }
}

#[test]
fn time_of_entry_survives_the_round_trip_exactly() {
    assert_eq!(
        round_trip_time_of_entry(INJECTED_TIME_OF_ENTRY_MS),
        INJECTED_TIME_OF_ENTRY_MS
    );
}

#[test]
fn time_of_entry_round_trips_at_the_binary_time_epoch() {
    assert_eq!(round_trip_time_of_entry(EPOCH_1984_MS), EPOCH_1984_MS);
}

#[test]
fn time_of_entry_round_trips_at_the_last_millisecond_of_a_day() {
    let ms = EPOCH_1984_MS + 86_400_000 - 1;
    assert_eq!(round_trip_time_of_entry(ms), ms);
}

/// Checks the wire field itself, so that an encoder and a decoder sharing the
/// same wrong epoch cannot pass by agreeing with each other.
#[test]
fn wire_field_holds_the_1984_day_count_and_milliseconds_of_day() {
    let ds = single_entry_dataset();
    let pending = data_change_pending(INJECTED_TIME_OF_ENTRY_MS);
    let params = ReportEncodeParams {
        rpt_id: "IED1LD0/GGIO1$RP$urcb01",
        opt_flds: OptFlds::SEQ_NUM | OptFlds::TIME_STAMP | OptFlds::REASON,
        sq_num: 1,
        time_of_entry_ms: INJECTED_TIME_OF_ENTRY_MS,
        dat_set: "GGIO1$ds1",
        conf_rev: 1,
        dataset: &ds,
        pending: &pending,
        max_pdu_size_bytes: 65000,
    };
    let pdus = encode_report_pdus(&params).expect("report encoding must succeed");

    // Locate the BinaryTime6 TLV: tag 0x8c, length 6.
    let pdu = &pdus[0];
    let at = pdu
        .windows(2)
        .position(|w| w == [0x8c, 0x06])
        .expect("the TIME_STAMP option field puts a six-octet BinaryTime on the wire");
    let field = &pdu[at + 2..at + 8];

    let since_1984 = INJECTED_TIME_OF_ENTRY_MS - EPOCH_1984_MS;
    let expected_days = (since_1984 / 86_400_000) as u16;
    let expected_ms_of_day = (since_1984 % 86_400_000) as u32;
    assert_eq!(
        u32::from_be_bytes([field[0], field[1], field[2], field[3]]),
        expected_ms_of_day
    );
    assert_eq!(u16::from_be_bytes([field[4], field[5]]), expected_days);
}

// GetBRCBValues TimeofEntry: the second encode site, and the client RCB
// read-back that consumes it.

/// Drives the server's GetBRCBValues TimeofEntry encoder and the client's RCB
/// structure decoder over one instant, returning what the client recovered.
fn round_trip_brcb_time_of_entry(time_of_entry_ms: u64) -> u64 {
    use iec61850_client::rcb::{update_values, RcbHandle};
    use iec61850_mms::mms::pdu::common::{AccessResult, MmsData};
    use iec61850_server::reporting::{
        handle_get_brcb_field, Brcb, BufferedReportControl, NullReportSink, RcbField,
        ReportingEngine, TriggerOptions,
    };
    use std::sync::Mutex;

    // Server: a BRCB whose last sent report carries the instant under test.
    let mut engine = ReportingEngine::new(Arc::new(NullReportSink));
    let brcb = Brcb::new("01", "MMXU1$ds1").with_trg_ops(TriggerOptions::DATA_CHANGED);
    let path = "IED1LD0/MMXU1$BR$brcb01".to_string();
    engine
        .register_brcb(BufferedReportControl::new(&path, brcb))
        .expect("brcb registration must succeed");
    let engine = Arc::new(Mutex::new(engine));
    {
        let guard = engine.lock().expect("engine lock");
        let brcb = guard.get_brcb(&path).expect("registered brcb");
        drop(guard);
        brcb.state
            .lock()
            .expect("brcb state lock")
            .last_sent_time_of_entry_ms = time_of_entry_ms;
    }

    let field = handle_get_brcb_field(&engine, &path, RcbField::Unknown("TimeofEntry".to_string()));
    let wire = match field {
        Some(AccessResult::Success(MmsData::BinaryTime(b))) => b,
        other => panic!("expected a BinaryTime for TimeofEntry, got {other:?}"),
    };
    assert_eq!(wire.len(), 6, "TimeofEntry is encoded as a BinaryTime6");

    // Client: the BRCB structure read-back, with the server bytes at index 12.
    let mut rcb = RcbHandle::new("IED1/LD0$BR$brcb01").expect("rcb handle");
    let mut elements = vec![
        MmsValue::VisibleString("brpt01".to_string()), // 0: rptId
        MmsValue::Boolean(false),                      // 1: rptEna
        MmsValue::VisibleString("IED/DS2".to_string()), // 2: datSet
        MmsValue::Unsigned(2),                         // 3: confRev
        MmsValue::BitString {
            padding: 6,
            data: vec![0x00, 0x00],
        }, // 4: optFlds
        MmsValue::Unsigned(500),                       // 5: bufTm
        MmsValue::Unsigned(1),                         // 6: sqNum
        MmsValue::BitString {
            padding: 2,
            data: vec![0x00],
        }, // 7: trgOps
        MmsValue::Unsigned(60000),                     // 8: intgPd
        MmsValue::Boolean(false),                      // 9: gi
        MmsValue::Boolean(false),                      // 10: purgeBuf
        MmsValue::OctetString(vec![0xAA, 0xBB]),       // 11: entryId
        MmsValue::BinaryTime(vec![]),                  // 12: timeOfEntry, filled below
    ];
    elements[12] = MmsValue::BinaryTime(wire);
    update_values(&mut rcb, &elements).expect("brcb read-back must parse");
    rcb.time_of_entry_ms()
}

#[test]
fn brcb_time_of_entry_survives_the_round_trip_exactly() {
    assert_eq!(
        round_trip_brcb_time_of_entry(INJECTED_TIME_OF_ENTRY_MS),
        INJECTED_TIME_OF_ENTRY_MS
    );
}

#[test]
fn brcb_time_of_entry_round_trips_at_the_binary_time_epoch() {
    assert_eq!(round_trip_brcb_time_of_entry(EPOCH_1984_MS), EPOCH_1984_MS);
}

#[test]
fn brcb_time_of_entry_round_trips_at_the_last_millisecond_of_a_day() {
    let ms = EPOCH_1984_MS + 86_400_000 - 1;
    assert_eq!(round_trip_brcb_time_of_entry(ms), ms);
}
