//! Integration tests for routing control services (FC=CO) through the model
//! dispatcher.
//!
//! The tests encode complete confirmed request bytes and call the dispatcher
//! directly, checking that a read of SBO and writes of Oper, SBOw and Cancel
//! reach the control service and that the command termination sink is called
//! where the control model requires it.

use bytes::{Bytes, BytesMut};
use iec61850_mms::mms::pdu::common::{MmsData, ObjectName};
use iec61850_mms::mms::pdu::read::{encode_confirmed_read_request, ReadRequest, ReadResponse};
use iec61850_mms::mms::pdu::write::{encode_confirmed_write_request, WriteRequest, WriteResponse};
use iec61850_mms::mms::server::dispatcher::{
    ConfirmedRequest, ConfirmedResponse, MmsServiceDispatcher,
};
use iec61850_mms::mms::server::MmsServerConnection;
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObject, DoChild, IedModelBuilder, LogicalDeviceBuilder,
    LogicalNode, LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::control::{
    AlwaysAcceptCheckHandler, AlwaysAcceptWaitHandler, AlwaysSuccessOperateHandler, CheckHandler,
    ControlHandler, ControlModel, ControlObject, ControlObjectConfig, ControlObjectEntry,
    ControlObjectsRegistry, RecordingCommandTermination, SboClass, TerminationEvent,
    WaitForExecutionHandler,
};
use iec61850_server::mapping::MmsDeviceModel;
use iec61850_server::policy::WriteAccessPolicies;
use iec61850_server::service::MmsModelDispatcher;
use std::sync::Arc;

// Shared fixture.

fn build_min_model() -> iec61850_model::IedModel {
    // GGIO1.SPCSO1 needs no data attribute: the control path resolves objects
    // through the control registry, not through the model tree.
    let mod_da = DataAttribute::new(
        "ctlModel",
        FC::Cf,
        DataAttributeType::Int32,
        TrgOps::default(),
        MmsValue::Integer(1),
    );
    let mod_do = DataObject {
        name: "Mod".into(),
        array_count: None,
        children: vec![DoChild::Da(mod_da)],
    };
    let ggio_ln = LogicalNode {
        prefix: String::new(),
        class: "GGIO".into(),
        inst: "1".into(),
        dos: vec![mod_do],
        datasets: vec![],
        rcbs: vec![],
        gocbs: vec![],
        svcbs: vec![],
        lcbs: vec![],
        sgcb: None,
    };
    let lln0 = LogicalNodeBuilder::lln0().build().unwrap();
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .add_ln(ggio_ln)
        .build()
        .unwrap();
    IedModelBuilder::new("IED1")
        .add_ld(ld)
        .unwrap()
        .build()
        .unwrap()
}

fn make_control_object(model: ControlModel) -> ControlObject {
    ControlObject::new(ControlObjectConfig {
        name: "SPCSO1".into(),
        ln_name: "GGIO1".into(),
        domain: "IED1LD0".into(),
        ctl_model: model,
        sbo_timeout_ms: 5000,
        sbo_class: SboClass::OperateOnce,
    })
}

/// Builds a dispatcher holding one control object with accepting handlers and
/// a recording command termination sink, and returns both.
fn build_dispatcher_with_recording_sink(
    ctl_model: ControlModel,
) -> (
    MmsModelDispatcher,
    Arc<std::sync::Mutex<Vec<TerminationEvent>>>,
) {
    let model = build_min_model();
    let mms_model = MmsDeviceModel::from_ied_model(&model).unwrap();
    let policies = WriteAccessPolicies::default();

    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Arc::new(RecordingCommandTermination {
        events: events.clone(),
    });

    let registry = Arc::new(ControlObjectsRegistry::with_sink(
        sink as Arc<dyn iec61850_server::control::CommandTerminationSink>,
    ));
    let entry = ControlObjectEntry::new(make_control_object(ctl_model))
        .with_check(Arc::new(AlwaysAcceptCheckHandler) as Arc<dyn CheckHandler>)
        .with_wait(Arc::new(AlwaysAcceptWaitHandler) as Arc<dyn WaitForExecutionHandler>)
        .with_operate(Arc::new(AlwaysSuccessOperateHandler) as Arc<dyn ControlHandler>);
    registry.register(entry);

    let dispatcher =
        MmsModelDispatcher::new(Arc::new(model), Arc::new(mms_model), Arc::new(policies))
            .with_control_objects(registry);
    (dispatcher, events)
}

/// Builds a server connection with connection id 1.
fn make_conn() -> MmsServerConnection {
    let mut c = MmsServerConnection::new();
    c.set_connection_id(1);
    c
}

/// Builds the six-element Oper structure.
fn oper_data(ctl_val: bool, ctl_num: u8) -> MmsData {
    MmsData::Structure(vec![
        MmsData::Boolean(ctl_val),
        MmsData::Structure(vec![MmsData::Integer(3), MmsData::OctetString(vec![0x01])]),
        MmsData::Unsigned(ctl_num as u64),
        MmsData::UtcTime([0u8; 8]),
        MmsData::Boolean(false),
        MmsData::BitString {
            padding: 6,
            data: vec![0x40],
        },
    ])
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

// Direct control with normal security answers an Oper with a successful write
// response.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dispatcher_direct_normal_oper_returns_success() {
    let (dispatcher, events) = build_dispatcher_with_recording_sink(ControlModel::DirectNormal);
    let conn = make_conn();

    let req = WriteRequest::single_domain("IED1LD0", "GGIO1$CO$SPCSO1$Oper", oper_data(true, 1));
    let mut full = BytesMut::new();
    encode_confirmed_write_request(10, &req, &mut full);

    let conf_req = ConfirmedRequest {
        invoke_id: 10,
        service_body: extract_service_body(&full),
    };
    let resp = dispatcher.dispatch(&conn, conf_req);
    let bytes = match resp {
        ConfirmedResponse::Response(b) => b,
        other => panic!("expected a Response, got {:?}", other),
    };
    // The outer tag of a confirmed response PDU is 0xa1.
    assert_eq!(bytes[0], 0xa1);

    // Decode the write response and confirm it is a success.
    let (_id, parsed) =
        iec61850_mms::mms::pdu::write::decode_confirmed_write_response(&bytes).unwrap();
    assert_eq!(parsed.outcomes.len(), 1);
    assert!(matches!(
        parsed.outcomes[0],
        iec61850_mms::mms::pdu::common::WriteOutcome::Success
    ));

    // Normal security sends no CommandTermination.
    assert!(
        events.lock().unwrap().is_empty(),
        "normal security must send no CommandTermination"
    );
}

// Direct control with enhanced security also sends a positive
// CommandTermination.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dispatcher_direct_enhanced_oper_sends_command_termination_positive() {
    let (dispatcher, events) = build_dispatcher_with_recording_sink(ControlModel::DirectEnhanced);
    let conn = make_conn();

    let req = WriteRequest::single_domain("IED1LD0", "GGIO1$CO$SPCSO1$Oper", oper_data(true, 1));
    let mut full = BytesMut::new();
    encode_confirmed_write_request(20, &req, &mut full);

    let conf_req = ConfirmedRequest {
        invoke_id: 20,
        service_body: extract_service_body(&full),
    };
    let resp = dispatcher.dispatch(&conn, conf_req);
    let bytes = match resp {
        ConfirmedResponse::Response(b) => b,
        other => panic!("expected a Response, got {:?}", other),
    };
    let (_id, parsed) =
        iec61850_mms::mms::pdu::write::decode_confirmed_write_response(&bytes).unwrap();
    assert_eq!(parsed.outcomes.len(), 1);
    assert!(matches!(
        parsed.outcomes[0],
        iec61850_mms::mms::pdu::common::WriteOutcome::Success
    ));

    // Enhanced security sends a positive CommandTermination.
    let recorded = events.lock().unwrap();
    assert_eq!(
        recorded.len(),
        1,
        "enhanced security must send one CommandTermination"
    );
    match &recorded[0] {
        TerminationEvent::Positive {
            conn_id,
            obj_ref,
            oper_value,
        } => {
            assert_eq!(*conn_id, 1);
            assert!(obj_ref.contains("SPCSO1"));
            // The termination carries the real Oper structure, not an empty
            // placeholder: an Oper with a boolean control value encodes to more
            // than the two bytes of an empty structure.
            assert!(
                oper_value.len() > 2,
                "the Oper value must be the real structure, not a placeholder (len={})",
                oper_value.len()
            );
            assert_eq!(
                oper_value[0], 0xa2,
                "the Oper value must start with the structure tag 0xa2"
            );
        }
        other => panic!("expected a positive termination, got {:?}", other),
    }
}

// A read of SBO under normal security answers with the object reference.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dispatcher_sbo_normal_read_sbo_returns_object_reference() {
    let (dispatcher, _) = build_dispatcher_with_recording_sink(ControlModel::SboNormal);
    let conn = make_conn();

    let req = ReadRequest::single_domain("IED1LD0", "GGIO1$CO$SPCSO1$SBO");
    let mut full = BytesMut::new();
    encode_confirmed_read_request(30, &req, &mut full);

    let conf_req = ConfirmedRequest {
        invoke_id: 30,
        service_body: extract_service_body(&full),
    };
    let resp = dispatcher.dispatch(&conn, conf_req);
    let bytes = match resp {
        ConfirmedResponse::Response(b) => b,
        other => panic!("expected a Response, got {:?}", other),
    };
    let (_id, parsed) = decode_confirmed_read_response(&bytes);
    assert_eq!(parsed.list_of_access_result.len(), 1);
    let ar = &parsed.list_of_access_result[0];
    let s = match ar {
        iec61850_mms::mms::pdu::common::AccessResult::Success(MmsData::VisibleString(s)) => s,
        other => panic!("expected a successful VisibleString, got {:?}", other),
    };
    assert!(
        s.contains("SPCSO1"),
        "the SBO read must return the object reference"
    );
}

// SBOw followed by a matching Oper under enhanced security.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dispatcher_sbo_enhanced_sbow_then_oper_succeeds_and_sends_ct() {
    let (dispatcher, events) = build_dispatcher_with_recording_sink(ControlModel::SboEnhanced);
    let conn = make_conn();

    // Write SBOw.
    let sbow_req =
        WriteRequest::single_domain("IED1LD0", "GGIO1$CO$SPCSO1$SBOw", oper_data(true, 1));
    let mut full = BytesMut::new();
    encode_confirmed_write_request(40, &sbow_req, &mut full);
    let conf_req = ConfirmedRequest {
        invoke_id: 40,
        service_body: extract_service_body(&full),
    };
    let resp = dispatcher.dispatch(&conn, conf_req);
    let bytes = match resp {
        ConfirmedResponse::Response(b) => b,
        other => panic!("SBOw must answer with a Response, got {:?}", other),
    };
    let (_id, parsed) =
        iec61850_mms::mms::pdu::write::decode_confirmed_write_response(&bytes).unwrap();
    assert!(matches!(
        parsed.outcomes[0],
        iec61850_mms::mms::pdu::common::WriteOutcome::Success
    ));
    // SBOw sends no CommandTermination; only the Oper does.
    assert!(
        events.lock().unwrap().is_empty(),
        "SBOw must send no CommandTermination"
    );

    // Write Oper with the same control value and control number.
    let oper_req =
        WriteRequest::single_domain("IED1LD0", "GGIO1$CO$SPCSO1$Oper", oper_data(true, 1));
    let mut full = BytesMut::new();
    encode_confirmed_write_request(41, &oper_req, &mut full);
    let conf_req = ConfirmedRequest {
        invoke_id: 41,
        service_body: extract_service_body(&full),
    };
    let resp = dispatcher.dispatch(&conn, conf_req);
    let bytes = match resp {
        ConfirmedResponse::Response(b) => b,
        other => panic!("Oper must answer with a Response, got {:?}", other),
    };
    let (_id, parsed) =
        iec61850_mms::mms::pdu::write::decode_confirmed_write_response(&bytes).unwrap();
    assert!(matches!(
        parsed.outcomes[0],
        iec61850_mms::mms::pdu::common::WriteOutcome::Success
    ));

    // SBO-enhanced operate → CommandTermination+
    let recorded = events.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    assert!(matches!(recorded[0], TerminationEvent::Positive { .. }));
}

// An Operate without a preceding SBOw fails and still terminates.
//
// Per IEC 61850-7-2 clause 20.2.1 every denied Operate under enhanced security
// is reported with a negative CommandTermination, ObjectNotSelected included.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dispatcher_sbo_enhanced_oper_without_select_fails() {
    let (dispatcher, events) = build_dispatcher_with_recording_sink(ControlModel::SboEnhanced);
    let conn = make_conn();

    // Write Oper without selecting first.
    let oper_req =
        WriteRequest::single_domain("IED1LD0", "GGIO1$CO$SPCSO1$Oper", oper_data(true, 1));
    let mut full = BytesMut::new();
    encode_confirmed_write_request(50, &oper_req, &mut full);
    let conf_req = ConfirmedRequest {
        invoke_id: 50,
        service_body: extract_service_body(&full),
    };
    let resp = dispatcher.dispatch(&conn, conf_req);
    let bytes = match resp {
        ConfirmedResponse::Response(b) => b,
        other => panic!("expected a Response, got {:?}", other),
    };
    let (_id, parsed) =
        iec61850_mms::mms::pdu::write::decode_confirmed_write_response(&bytes).unwrap();
    assert!(matches!(
        parsed.outcomes[0],
        iec61850_mms::mms::pdu::common::WriteOutcome::Failure(_)
    ));

    // Every denied Operate sends a negative CommandTermination.
    let recorded = events.lock().unwrap();
    assert_eq!(
        recorded.len(),
        1,
        "a failed Operate must send a negative CommandTermination"
    );
    assert!(matches!(recorded[0], TerminationEvent::Negative { .. }));
}

// A status-only control model refuses the service.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dispatcher_status_only_oper_fails() {
    let (dispatcher, _) = build_dispatcher_with_recording_sink(ControlModel::StatusOnly);
    let conn = make_conn();

    let req = WriteRequest::single_domain("IED1LD0", "GGIO1$CO$SPCSO1$Oper", oper_data(true, 1));
    let mut full = BytesMut::new();
    encode_confirmed_write_request(60, &req, &mut full);
    let conf_req = ConfirmedRequest {
        invoke_id: 60,
        service_body: extract_service_body(&full),
    };
    let resp = dispatcher.dispatch(&conn, conf_req);
    let bytes = match resp {
        ConfirmedResponse::Response(b) => b,
        other => panic!("expected a Response, got {:?}", other),
    };
    let (_id, parsed) =
        iec61850_mms::mms::pdu::write::decode_confirmed_write_response(&bytes).unwrap();
    assert!(matches!(
        parsed.outcomes[0],
        iec61850_mms::mms::pdu::common::WriteOutcome::Failure(_)
    ));
}

// An unregistered control object answers ObjectNonExistent.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dispatcher_unregistered_co_returns_non_existent() {
    let model = build_min_model();
    let mms_model = MmsDeviceModel::from_ied_model(&model).unwrap();
    let policies = WriteAccessPolicies::default();
    let registry = Arc::new(ControlObjectsRegistry::new()); // empty registry
    let dispatcher =
        MmsModelDispatcher::new(Arc::new(model), Arc::new(mms_model), Arc::new(policies))
            .with_control_objects(registry);
    let conn = make_conn();

    let req =
        WriteRequest::single_domain("IED1LD0", "GGIO1$CO$NotRegistered$Oper", oper_data(true, 1));
    let mut full = BytesMut::new();
    encode_confirmed_write_request(70, &req, &mut full);
    let conf_req = ConfirmedRequest {
        invoke_id: 70,
        service_body: extract_service_body(&full),
    };
    let resp = dispatcher.dispatch(&conn, conf_req);
    let bytes = match resp {
        ConfirmedResponse::Response(b) => b,
        other => panic!("expected a Response, got {:?}", other),
    };
    let (_id, parsed) =
        iec61850_mms::mms::pdu::write::decode_confirmed_write_response(&bytes).unwrap();
    assert!(matches!(
        parsed.outcomes[0],
        iec61850_mms::mms::pdu::common::WriteOutcome::Failure(
            iec61850_mms::mms::pdu::common::DataAccessError::ObjectNonExistent
        )
    ));
}

// Local read response decoder; the client crate exports no complete one.

fn decode_confirmed_read_response(data: &[u8]) -> (u32, ReadResponse) {
    iec61850_mms::mms::pdu::read::decode_confirmed_read_response(data).unwrap()
}

// Keeps otherwise unused helpers from tripping the dead-code lint.
#[allow(dead_code)]
fn _silence_unused() {
    let _: ObjectName = ObjectName::VmdSpecific(String::new());
    let _: WriteResponse = WriteResponse { outcomes: vec![] };
}
