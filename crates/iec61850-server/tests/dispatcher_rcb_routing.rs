//! Integration tests for routing report control block access (FC=RP and FC=BR)
//! through the model dispatcher.
//!
//! The tests encode complete confirmed request bytes and call the dispatcher
//! directly, covering a read of the whole control block, a read of a single
//! field and a write of a field, and requiring an unknown control block to
//! answer ObjectNonExistent.

use bytes::{Bytes, BytesMut};
use iec61850_mms::mms::pdu::common::{AccessResult, DataAccessError, MmsData, WriteOutcome};
use iec61850_mms::mms::pdu::read::{encode_confirmed_read_request, ReadRequest, ReadResponse};
use iec61850_mms::mms::pdu::write::{encode_confirmed_write_request, WriteRequest, WriteResponse};
use iec61850_mms::mms::server::dispatcher::{
    ConfirmedRequest, ConfirmedResponse, MmsServiceDispatcher,
};
use iec61850_mms::mms::server::MmsServerConnection;
use iec61850_model::{IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue};
use iec61850_server::mapping::MmsDeviceModel;
use iec61850_server::policy::WriteAccessPolicies;
use iec61850_server::reporting::{
    Brcb, BufferedReportControl, Dataset, DatasetEntry, NullReportSink, Rcb, ReportControl,
    ReportingEngine,
};
use iec61850_server::service::MmsModelDispatcher;
use std::sync::{Arc, Mutex, RwLock};

// Shared fixture.

/// Builds the smallest model: MMXU1 alongside LLN0.
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

/// Builds a dispatcher carrying one unbuffered control block.
fn build_dispatcher_with_urcb() -> (MmsModelDispatcher, Arc<Mutex<ReportingEngine>>) {
    let model = build_min_model();
    let mms_model = MmsDeviceModel::from_ied_model(&model).unwrap();
    let policies = WriteAccessPolicies::default();

    // Register the control block on a fresh engine.
    let engine: Arc<Mutex<ReportingEngine>> =
        Arc::new(Mutex::new(ReportingEngine::new(Arc::new(NullReportSink))));

    {
        let mut eng = engine.lock().unwrap();
        let rcb = Rcb::new("urcb01", "MMXU1$ds1");
        let mms_path = "IED1LD0/MMXU1$RP$urcb01";
        let rc = ReportControl::new(mms_path, rcb);
        // The data set is left empty. Enabling reporting fails in that state,
        // which is intended; reads are unaffected.
        let ds = Dataset::new("MMXU1$ds1");
        eng.register_rcb(rc, ds).unwrap();
    }

    let dispatcher =
        MmsModelDispatcher::new(Arc::new(model), Arc::new(mms_model), Arc::new(policies))
            .with_reporting_engine(engine.clone());

    (dispatcher, engine)
}

/// Builds a server connection with connection id 1.
fn make_conn() -> MmsServerConnection {
    let mut c = MmsServerConnection::new();
    c.set_connection_id(1);
    c
}

/// Extracts the service body the dispatcher expects, from the service tag to
/// the end, out of a complete encoded confirmed request.
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

/// Reads through the dispatcher and returns the decoded read response.
fn do_read(dispatcher: &MmsModelDispatcher, domain: &str, item_id: &str) -> ReadResponse {
    let req = ReadRequest::single_domain(domain, item_id);
    let mut full = BytesMut::new();
    encode_confirmed_read_request(1, &req, &mut full);
    let conf_req = ConfirmedRequest {
        invoke_id: 1,
        service_body: extract_service_body(&full),
    };
    let conn = make_conn();
    let resp = dispatcher.dispatch(&conn, conf_req);
    let bytes = match resp {
        ConfirmedResponse::Response(b) => b,
        other => panic!("expected a Response, got {:?}", other),
    };
    let (_id, parsed) =
        iec61850_mms::mms::pdu::read::decode_confirmed_read_response(&bytes).unwrap();
    parsed
}

/// Writes through the dispatcher and returns the decoded write response.
fn do_write(
    dispatcher: &MmsModelDispatcher,
    domain: &str,
    item_id: &str,
    data: MmsData,
) -> WriteResponse {
    let req = WriteRequest::single_domain(domain, item_id, data);
    let mut full = BytesMut::new();
    encode_confirmed_write_request(2, &req, &mut full);
    let conf_req = ConfirmedRequest {
        invoke_id: 2,
        service_body: extract_service_body(&full),
    };
    let conn = make_conn();
    let resp = dispatcher.dispatch(&conn, conf_req);
    let bytes = match resp {
        ConfirmedResponse::Response(b) => b,
        other => panic!("expected a Response, got {:?}", other),
    };
    let (_id, parsed) =
        iec61850_mms::mms::pdu::write::decode_confirmed_write_response(&bytes).unwrap();
    parsed
}

// Reading the whole control block returns a successful structure.

#[test]
fn dispatcher_read_rcb_structure_returns_success() {
    let (dispatcher, _engine) = build_dispatcher_with_urcb();
    let resp = do_read(&dispatcher, "IED1LD0", "MMXU1$RP$urcb01");

    assert_eq!(resp.list_of_access_result.len(), 1);
    match &resp.list_of_access_result[0] {
        AccessResult::Success(MmsData::Structure(fields)) => {
            // An unbuffered control block has twelve fields per
            // IEC 61850-8-1 table 30.
            assert_eq!(
                fields.len(),
                12,
                "an unbuffered control block must expose 12 fields, got {}",
                fields.len()
            );
        }
        other => panic!("expected a successful Structure, got {:?}", other),
    }
}

// Reading the single field RptEna returns its initial value.

#[test]
fn dispatcher_read_rcb_field_rptenable_returns_false() {
    let (dispatcher, _engine) = build_dispatcher_with_urcb();
    let resp = do_read(&dispatcher, "IED1LD0", "MMXU1$RP$urcb01$RptEna");

    assert_eq!(resp.list_of_access_result.len(), 1);
    assert_eq!(
        resp.list_of_access_result[0],
        AccessResult::Success(MmsData::Boolean(false)),
        "RptEna starts out false"
    );
}

// Writing Resv succeeds.

#[test]
fn dispatcher_write_rcb_resv_true_returns_success() {
    let (dispatcher, _engine) = build_dispatcher_with_urcb();
    let resp = do_write(
        &dispatcher,
        "IED1LD0",
        "MMXU1$RP$urcb01$Resv",
        MmsData::Boolean(true),
    );

    assert_eq!(resp.outcomes.len(), 1);
    assert_eq!(
        resp.outcomes[0],
        WriteOutcome::Success,
        "writing Resv true must succeed"
    );

    // The engine state carries the reservation.
    let engine = _engine.lock().unwrap();
    let rc_arc = engine.get_rcb("IED1LD0/MMXU1$RP$urcb01").unwrap();
    drop(engine);
    let rc = rc_arc.lock().unwrap();
    let state = rc.state.lock().unwrap();
    assert!(state.resv, "the engine must record the reservation");
}

// ConfRev is read-only, so writing it is denied.

#[test]
fn dispatcher_write_rcb_confrev_returns_access_denied() {
    let (dispatcher, _engine) = build_dispatcher_with_urcb();
    let resp = do_write(
        &dispatcher,
        "IED1LD0",
        "MMXU1$RP$urcb01$ConfRev",
        MmsData::Unsigned(999),
    );

    assert_eq!(resp.outcomes.len(), 1);
    assert_eq!(
        resp.outcomes[0],
        WriteOutcome::Failure(DataAccessError::ObjectAccessDenied),
        "a write to the read-only ConfRev must answer ObjectAccessDenied"
    );
}

// Reading an unregistered control block answers ObjectNonExistent.

#[test]
fn dispatcher_read_unregistered_rcb_returns_not_existent() {
    let (dispatcher, _engine) = build_dispatcher_with_urcb();
    let resp = do_read(&dispatcher, "IED1LD0", "MMXU1$RP$nosuchurcb");

    assert_eq!(resp.list_of_access_result.len(), 1);
    assert_eq!(
        resp.list_of_access_result[0],
        AccessResult::Failure(DataAccessError::ObjectNonExistent),
        "an unknown control block must answer ObjectNonExistent"
    );
}

// A write to a buffered control block the engine does not carry answers
// ObjectNonExistent.

#[test]
fn dispatcher_write_br_rcb_returns_not_existent() {
    let (dispatcher, _engine) = build_dispatcher_with_urcb();
    // The dispatcher routes the buffered path to the engine, which only holds
    // the unbuffered control block here.
    let resp = do_write(
        &dispatcher,
        "IED1LD0",
        "MMXU1$BR$brcb01$Resv",
        MmsData::Boolean(true),
    );

    assert_eq!(resp.outcomes.len(), 1);
    assert_eq!(
        resp.outcomes[0],
        WriteOutcome::Failure(DataAccessError::ObjectNonExistent),
        "an unregistered buffered control block must answer ObjectNonExistent"
    );
}

// Registration through the server is visible on the reporting engine.

#[test]
fn ied_server_register_urcb_api_works() {
    use iec61850_server::IedServer;
    use std::net::SocketAddr;

    let model = build_min_model();
    let server = IedServer::builder()
        .model(Arc::new(model))
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()
        .expect("server build");

    // The engine is reachable from the server.
    let engine_arc = server.reporting_engine();

    // Registration succeeds.
    let rcb = Rcb::new("urcb01", "MMXU1$ds1");
    let mms_path = "IED1LD0/MMXU1$RP$urcb01";
    let rc = ReportControl::new(mms_path, rcb);
    let ds = Dataset::new("MMXU1$ds1");
    server.register_urcb(rc, ds).expect("register_urcb");

    // The engine now knows the control block.
    let engine = engine_arc.lock().unwrap();
    let paths = engine.rcb_paths();
    assert!(
        paths.contains(&mms_path.to_string()),
        "the engine must carry {mms_path}, got {:?}",
        paths
    );
}

// Reading the single field Resv returns its initial value.

#[test]
fn dispatcher_read_rcb_field_resv_returns_false() {
    let (dispatcher, _engine) = build_dispatcher_with_urcb();
    let resp = do_read(&dispatcher, "IED1LD0", "MMXU1$RP$urcb01$Resv");

    assert_eq!(resp.list_of_access_result.len(), 1);
    assert_eq!(
        resp.list_of_access_result[0],
        AccessResult::Success(MmsData::Boolean(false)),
        "Resv starts out false"
    );
}

// Writing an unregistered control block answers ObjectNonExistent.

#[test]
fn dispatcher_write_unregistered_rcb_returns_not_existent() {
    let (dispatcher, _engine) = build_dispatcher_with_urcb();
    let resp = do_write(
        &dispatcher,
        "IED1LD0",
        "MMXU1$RP$nosuchurcb$Resv",
        MmsData::Boolean(true),
    );

    assert_eq!(resp.outcomes.len(), 1);
    assert_eq!(
        resp.outcomes[0],
        WriteOutcome::Failure(DataAccessError::ObjectNonExistent),
        "a write to an unknown control block must answer ObjectNonExistent"
    );
}

// While a control block is enabled, writing RptID, DatSet, OptFlds, TrgOps,
// BufTm or IntgPd must answer TemporarilyUnavailable: an enabled control block
// cannot be reconfigured.
//
// The fixture pushes the engine state to enabled and reserved directly instead
// of enabling over the wire, because an empty data set would refuse RptEna, and
// then drives the writes through the full MMS path. The connection id has to
// match the one the requests carry, or the reservation check would refuse them
// with ObjectAccessDenied before the enabled check is reached.

/// Builds a dispatcher whose control block is already enabled over a non-empty
/// data set.
fn build_dispatcher_with_enabled_urcb() -> (MmsModelDispatcher, Arc<Mutex<ReportingEngine>>) {
    let model = build_min_model();
    let mms_model = MmsDeviceModel::from_ied_model(&model).unwrap();
    let policies = WriteAccessPolicies::default();

    let engine: Arc<Mutex<ReportingEngine>> =
        Arc::new(Mutex::new(ReportingEngine::new(Arc::new(NullReportSink))));

    {
        let mut eng = engine.lock().unwrap();
        let rcb = Rcb::new("urcb01", "MMXU1$ds1");
        let mms_path = "IED1LD0/MMXU1$RP$urcb01";
        let rc = ReportControl::new(mms_path, rcb);
        // One member, so enabling is not refused for an empty data set.
        let mut ds = Dataset::new("MMXU1$ds1");
        ds.push(DatasetEntry::new(
            "IED1LD0/MMXU1$ST$Ind1$stVal",
            Arc::new(RwLock::new(MmsValue::Boolean(false))),
        ));
        eng.register_rcb(rc, ds).unwrap();

        // Push the state to enabled and reserved for the connection the
        // requests come from.
        let rc_arc = eng
            .get_rcb("IED1LD0/MMXU1$RP$urcb01")
            .expect("the control block was just registered");
        let rc_g = rc_arc.lock().unwrap();
        let mut state = rc_g.state.lock().unwrap();
        state.resv = true;
        state.client_conn_id = Some(1);
        state.rpt_ena = true;
    }

    let dispatcher =
        MmsModelDispatcher::new(Arc::new(model), Arc::new(mms_model), Arc::new(policies))
            .with_reporting_engine(engine.clone());

    (dispatcher, engine)
}

#[test]
fn dispatcher_write_rcb_enabled_rejects_reconfiguration_fields() {
    let (dispatcher, _engine) = build_dispatcher_with_enabled_urcb();

    // Each of the six configuration fields is written with a value of its own
    // type; all must be refused.
    let cases: Vec<(&str, MmsData)> = vec![
        ("RptID", MmsData::VisibleString("new_rpt_id".into())),
        ("DatSet", MmsData::VisibleString("MMXU1$ds_new".into())),
        // OptFlds is a ten-bit string; all zeros is enough to test the refusal.
        (
            "OptFlds",
            MmsData::BitString {
                padding: 6,
                data: vec![0x00, 0x00],
            },
        ),
        ("BufTm", MmsData::Unsigned(500)),
        // TrgOps: BIT_STRING(6) — DCHG=wire bit-1=0x40
        (
            "TrgOps",
            MmsData::BitString {
                padding: 2,
                data: vec![0x40],
            },
        ),
        ("IntgPd", MmsData::Unsigned(1000)),
    ];

    for (field, data) in cases {
        let item = format!("MMXU1$RP$urcb01${field}");
        let resp = do_write(&dispatcher, "IED1LD0", &item, data);
        assert_eq!(
            resp.outcomes.len(),
            1,
            "field={field} must answer with one outcome"
        );
        assert_eq!(
            resp.outcomes[0],
            WriteOutcome::Failure(DataAccessError::TemporarilyUnavailable),
            "field={field} must answer TemporarilyUnavailable while enabled"
        );
    }
}

// Writing RptEna false still succeeds while the control block is enabled; the
// reconfiguration rule must not block disabling it.

#[test]
fn dispatcher_write_rcb_enabled_can_disable() {
    let (dispatcher, engine) = build_dispatcher_with_enabled_urcb();

    let resp = do_write(
        &dispatcher,
        "IED1LD0",
        "MMXU1$RP$urcb01$RptEna",
        MmsData::Boolean(false),
    );
    assert_eq!(resp.outcomes.len(), 1);
    assert_eq!(
        resp.outcomes[0],
        WriteOutcome::Success,
        "disabling an enabled control block must succeed"
    );

    let eng = engine.lock().unwrap();
    let rc_arc = eng.get_rcb("IED1LD0/MMXU1$RP$urcb01").unwrap();
    drop(eng);
    let rc = rc_arc.lock().unwrap();
    let state = rc.state.lock().unwrap();
    assert!(!state.rpt_ena, "RptEna must be false after disabling");
}

// Buffered report control block routing (FC=BR).

/// Builds a dispatcher carrying one buffered control block.
fn build_dispatcher_with_brcb() -> (MmsModelDispatcher, Arc<Mutex<ReportingEngine>>) {
    let model = build_min_model();
    let mms_model = MmsDeviceModel::from_ied_model(&model).unwrap();
    let policies = WriteAccessPolicies::default();

    let engine: Arc<Mutex<ReportingEngine>> =
        Arc::new(Mutex::new(ReportingEngine::new(Arc::new(NullReportSink))));

    {
        let mut eng = engine.lock().unwrap();
        let brcb = Brcb::new("brcb01", "MMXU1$ds1");
        let mms_path = "IED1LD0/MMXU1$BR$brcb01";
        let brc = BufferedReportControl::new(mms_path, brcb);
        eng.register_brcb(brc).unwrap();
    }

    let dispatcher =
        MmsModelDispatcher::new(Arc::new(model), Arc::new(mms_model), Arc::new(policies))
            .with_reporting_engine(engine.clone());

    (dispatcher, engine)
}

/// Field-level access to a buffered control block follows the same rules as an
/// unbuffered one, so enabling reporting over an empty data set is refused with
/// TemporarilyUnavailable.
#[test]
fn dispatcher_write_registered_brcb_rpt_ena_with_empty_dataset_is_temporarily_unavailable() {
    let (dispatcher, _engine) = build_dispatcher_with_brcb();
    // The fixture control block names a data set, so enabling succeeds even
    // though no data set was registered with the engine.
    let resp = do_write(
        &dispatcher,
        "IED1LD0",
        "MMXU1$BR$brcb01$RptEna",
        MmsData::Boolean(true),
    );

    assert_eq!(resp.outcomes.len(), 1);
    assert_eq!(
        resp.outcomes[0],
        WriteOutcome::Success,
        "enabling a buffered control block with a named data set must succeed"
    );
}

#[test]
fn dispatcher_read_registered_brcb_rpt_ena_returns_boolean() {
    let (dispatcher, _engine) = build_dispatcher_with_brcb();
    let resp = do_read(&dispatcher, "IED1LD0", "MMXU1$BR$brcb01$RptEna");

    assert_eq!(resp.list_of_access_result.len(), 1);
    assert_eq!(
        resp.list_of_access_result[0],
        AccessResult::Success(MmsData::Boolean(false)),
        "RptEna of a buffered control block starts out false"
    );
}

/// Writing an all-zero EntryID asks for retransmission from the head of the
/// buffer: the write succeeds, the transmit anchor moves to the head, and the
/// control block is not marked as resynchronizing.
#[test]
fn dispatcher_write_brcb_entry_id_zero_sets_from_head() {
    use iec61850_server::reporting::TransmitAnchor;
    let (dispatcher, engine) = build_dispatcher_with_brcb();

    // An eight-byte all-zero EntryID means start from the head.
    let resp = do_write(
        &dispatcher,
        "IED1LD0",
        "MMXU1$BR$brcb01$EntryID",
        MmsData::OctetString(vec![0u8; 8]),
    );

    assert_eq!(resp.outcomes.len(), 1);
    assert_eq!(
        resp.outcomes[0],
        WriteOutcome::Success,
        "writing an all-zero EntryID must succeed"
    );

    // The engine state follows the write.
    let eng = engine.lock().unwrap();
    let brcb_arc = eng.get_brcb("IED1LD0/MMXU1$BR$brcb01").unwrap();
    drop(eng);
    let state = brcb_arc.lock_state().unwrap();
    assert_eq!(
        state.transmit_anchor,
        TransmitAnchor::FromHead,
        "an all-zero EntryID must set the transmit anchor to the head"
    );
    assert!(
        !state.is_resync,
        "the all-zero path must not mark a resynchronization"
    );
}

/// An EntryID that is not eight bytes long is refused with ObjectValueInvalid.
#[test]
fn dispatcher_write_brcb_entry_id_wrong_length_returns_invalid() {
    let (dispatcher, _engine) = build_dispatcher_with_brcb();
    let resp = do_write(
        &dispatcher,
        "IED1LD0",
        "MMXU1$BR$brcb01$EntryID",
        MmsData::OctetString(vec![0u8; 4]), // wrong length
    );
    assert_eq!(resp.outcomes.len(), 1);
    assert_eq!(
        resp.outcomes[0],
        WriteOutcome::Failure(DataAccessError::ObjectValueInvalid),
        "an EntryID other than eight bytes long must answer ObjectValueInvalid"
    );
}

/// EntryID reads back as eight zero bytes before anything is transmitted.
#[test]
fn dispatcher_read_brcb_entry_id_initial_zero() {
    let (dispatcher, _engine) = build_dispatcher_with_brcb();
    let resp = do_read(&dispatcher, "IED1LD0", "MMXU1$BR$brcb01$EntryID");

    assert_eq!(resp.list_of_access_result.len(), 1);
    assert_eq!(
        resp.list_of_access_result[0],
        AccessResult::Success(MmsData::OctetString(vec![0u8; 8])),
        "EntryID starts out as eight zero bytes"
    );
}

/// End-to-end send path: an all-zero EntryID sets the anchor to the head, four
/// entries are buffered, and the flush hands the sink one PDU per entry with
/// the sequence number and the anchor advanced accordingly.
///
/// The collecting sink is defined here because the one inside the crate is
/// compiled only for its own unit tests.
#[test]
fn brcb_send_path_after_entry_id_zero_e2e_w3b() {
    use bytes::Bytes;
    use iec61850_server::connection::ConnectionId;
    use iec61850_server::reporting::{ReportSink, TransmitAnchor};

    /// A sink that keeps the PDU bytes it is handed.
    #[derive(Default)]
    struct CollectingSink {
        pdus: std::sync::Mutex<Vec<(ConnectionId, bytes::Bytes)>>,
    }
    impl ReportSink for CollectingSink {
        fn send_pdu(&self, conn_id: ConnectionId, pdu: bytes::Bytes) -> bool {
            self.pdus.lock().unwrap().push((conn_id, pdu));
            true
        }
    }

    // The engine and control block are built directly; this test is about the
    // send path rather than about routing.
    let sink = Arc::new(CollectingSink::default());
    let mut eng = ReportingEngine::new(sink.clone() as Arc<dyn ReportSink>);

    let brcb = Brcb::new("brcb01", "MMXU1$ds1").with_buffer_capacity(8);
    let mms_path = "IED1LD0/MMXU1$BR$brcb01";
    let brc = BufferedReportControl::new(mms_path, brcb);
    eng.register_brcb(brc).unwrap();
    let brcb_arc = eng.get_brcb(mms_path).unwrap();

    // Buffer four entries. The timestamps are host-order milliseconds; the
    // entry identifier is byte-swapped where it is allocated.
    for i in 0..4u64 {
        brcb_arc
            .enqueue_entry(2_000 + i, false, false, Bytes::from_static(b"e"))
            .unwrap();
    }

    // The equivalent of a client writing an all-zero EntryID.
    use iec61850_server::reporting::EntryId;
    let outcome = brcb_arc.apply_entry_id_write(EntryId::ZERO).unwrap();
    assert_eq!(outcome, Ok(()));
    assert_eq!(
        brcb_arc.lock_state().unwrap().transmit_anchor,
        TransmitAnchor::FromHead
    );

    // The flush sends one PDU per entry.
    let n = eng.flush_brcb_pending(&brcb_arc, 99, 5_000_000);
    assert_eq!(n, 4, "a flush from the head must send all four entries");

    let pdus = sink.pdus.lock().unwrap();
    assert_eq!(pdus.len(), 4, "the sink must receive four PDUs");
    for (cid, pdu) in pdus.iter() {
        assert_eq!(*cid, 99);
        assert_eq!(pdu[0], 0xa3, "a report PDU must carry the 0xa3 tag");
    }

    // The anchor moves to the last entry and the sequence number counts four.
    let s = brcb_arc.lock_state().unwrap();
    match &s.transmit_anchor {
        TransmitAnchor::AfterEntryId(_) => {}
        other => panic!(
            "the anchor must advance past the last entry, got {:?}",
            other
        ),
    }
    assert_eq!(
        s.sq_num, 4,
        "four entries advance the sequence number to four"
    );
    assert!(
        !s.last_sent_entry_id.is_zero(),
        "the last sent entry identifier must be recorded"
    );
}

/// A buffered control block that was never registered still answers
/// ObjectNonExistent.
#[test]
fn dispatcher_write_unregistered_brcb_still_not_existent() {
    let (dispatcher, _engine) = build_dispatcher_with_brcb();
    // A control block name the engine does not carry.
    let resp = do_write(
        &dispatcher,
        "IED1LD0",
        "MMXU1$BR$nosuchbrcb$RptEna",
        MmsData::Boolean(true),
    );

    assert_eq!(resp.outcomes.len(), 1);
    assert_eq!(
        resp.outcomes[0],
        WriteOutcome::Failure(DataAccessError::ObjectNonExistent),
        "an unregistered buffered control block must answer ObjectNonExistent"
    );
}
