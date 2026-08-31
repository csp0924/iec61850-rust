//! Integration tests for the read and attribute access handlers on the read and
//! write paths of the model dispatcher.
//!
//! The tests encode complete confirmed request bytes and call the dispatcher
//! directly. They cover the three read handler outcomes (cache hit, cache miss
//! and error), the switch that bypasses the handler registry on reads, the fact
//! that a read handler cannot override the object-nonexistent guard, the
//! deny-all and silent helpers, the three write handler outcomes (accept,
//! accept without update and reject), the order in which the dispatcher applies
//! functional constraint classification, type check, write policy, handler and
//! cache update, and that installing a handler twice on one path replaces the
//! first.

use bytes::{Bytes, BytesMut};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use iec61850_mms::mms::pdu::common::{AccessResult, DataAccessError, MmsData, WriteOutcome};
use iec61850_mms::mms::pdu::read::{
    decode_confirmed_read_response, encode_confirmed_read_request, ReadRequest,
};
use iec61850_mms::mms::pdu::write::{
    decode_confirmed_write_response, encode_confirmed_write_request, WriteRequest,
};
use iec61850_mms::mms::server::dispatcher::{
    ConfirmedRequest, ConfirmedResponse, MmsServiceDispatcher,
};
use iec61850_mms::mms::server::MmsServerConnection;
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObject, DoChild, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::handler::{
    AttributeAccessHandler, DenyAllReadHandler, HandlerRegistry, ReadContext, ReadHandler,
    ReadOutcome, SilentReadHandler, WriteContext, WriteOutcome as HandlerWriteOutcome,
};
use iec61850_server::mapping::MmsDeviceModel;
use iec61850_server::policy::WriteAccessPolicies;
use iec61850_server::service::MmsModelDispatcher;

// Shared fixture: MMXU1.MX.TotW.mag as Float32 and GGIO1.CF.Mod.ctlModel as
// Int32.

fn build_test_model() -> IedModel {
    let mag_da = DataAttribute::new(
        "mag",
        FC::Mx,
        DataAttributeType::Float32,
        TrgOps::default(),
        MmsValue::Float32(1.23),
    );
    let ctl_model_da = DataAttribute::new(
        "ctlModel",
        FC::Cf,
        DataAttributeType::Int32,
        TrgOps::default(),
        MmsValue::Integer(0),
    );

    let totw_do = DataObject {
        name: "TotW".into(),
        array_count: None,
        children: vec![DoChild::Da(mag_da)],
    };
    let mod_do = DataObject {
        name: "Mod".into(),
        array_count: None,
        children: vec![DoChild::Da(ctl_model_da)],
    };

    let mmxu_ln = iec61850_model::LogicalNode {
        prefix: String::new(),
        class: "MMXU".into(),
        inst: "1".into(),
        dos: vec![totw_do],
        datasets: vec![],
        rcbs: vec![],
        gocbs: vec![],
        svcbs: vec![],
        lcbs: vec![],
        sgcb: None,
    };
    let ggio_ln = iec61850_model::LogicalNode {
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
        .add_ln(mmxu_ln)
        .add_ln(ggio_ln)
        .build()
        .unwrap();
    IedModelBuilder::new("IED1")
        .add_ld(ld)
        .unwrap()
        .build()
        .unwrap()
}

/// Builds a dispatcher and its handler registry; the registry is shared, so an
/// installed handler takes effect immediately.
fn build_dispatcher() -> (MmsModelDispatcher, Arc<HandlerRegistry>) {
    let model = build_test_model();
    let mms_model = MmsDeviceModel::from_ied_model(&model).unwrap();
    let mut policies = WriteAccessPolicies::default();
    policies.set(FC::Cf, true);

    let registry = Arc::new(HandlerRegistry::new());
    let dispatcher =
        MmsModelDispatcher::new(Arc::new(model), Arc::new(mms_model), Arc::new(policies))
            .with_handler_registry(registry.clone());
    (dispatcher, registry)
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
        let len = ((data[1] as usize) << 8) | (data[2] as usize);
        (len, 3)
    } else {
        panic!(
            "ber_decode_length: unsupported length form 0x{:02X}",
            data[0]
        );
    }
}

/// Reads one object name through the dispatcher and returns the first access
/// result.
fn dispatch_single_read(
    dispatcher: &MmsModelDispatcher,
    domain: &str,
    item_id: &str,
) -> AccessResult {
    let conn = make_conn();
    let req = ReadRequest::single_domain(domain, item_id);
    let mut full_buf = BytesMut::new();
    encode_confirmed_read_request(11, &req, &mut full_buf);
    let body = extract_service_body(&full_buf);
    let resp = dispatcher.dispatch(
        &conn,
        ConfirmedRequest {
            invoke_id: 11,
            service_body: body,
        },
    );
    let bytes = match resp {
        ConfirmedResponse::Response(b) => b,
        other => panic!("Read must answer with a Response, got {other:?}"),
    };
    let (_id, parsed) = decode_confirmed_read_response(&bytes).expect("decode read response");
    parsed
        .list_of_access_result
        .into_iter()
        .next()
        .expect("at least one access result")
}

/// Writes one object name through the dispatcher and returns the first outcome.
fn dispatch_single_write(
    dispatcher: &MmsModelDispatcher,
    domain: &str,
    item_id: &str,
    data: MmsData,
) -> WriteOutcome {
    let conn = make_conn();
    let req = WriteRequest::single_domain(domain, item_id, data);
    let mut full_buf = BytesMut::new();
    encode_confirmed_write_request(22, &req, &mut full_buf);
    let body = extract_service_body(&full_buf);
    let resp = dispatcher.dispatch(
        &conn,
        ConfirmedRequest {
            invoke_id: 22,
            service_body: body,
        },
    );
    let bytes = match resp {
        ConfirmedResponse::Response(b) => b,
        other => panic!("Write must answer with a Response, got {other:?}"),
    };
    let (_id, parsed) = decode_confirmed_write_response(&bytes).expect("decode write response");
    parsed
        .outcomes
        .into_iter()
        .next()
        .expect("at least one write outcome")
}

// Read handler tests.

/// A read handler that always answers with a fixed value.
#[derive(Debug)]
struct CannedReadHandler {
    value: MmsValue,
    calls: AtomicU32,
}

impl ReadHandler for CannedReadHandler {
    fn read(&self, _ctx: &ReadContext<'_>) -> ReadOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        ReadOutcome::CacheHit(self.value.clone())
    }
}

#[test]
fn read_handler_cache_hit_returns_value() {
    let (dispatcher, registry) = build_dispatcher();

    let canned = Arc::new(CannedReadHandler {
        value: MmsValue::Float32(99.5),
        calls: AtomicU32::new(0),
    });
    registry
        .install_read_handler("MMXU1$MX$TotW$mag", canned.clone())
        .unwrap();

    let result = dispatch_single_read(&dispatcher, "IED1LD0", "MMXU1$MX$TotW$mag");
    match result {
        AccessResult::Success(MmsData::Float32(v)) => {
            assert!(
                (v - 99.5).abs() < f32::EPSILON,
                "the handler value must replace the model value"
            );
        }
        other => panic!("expected Float32(99.5), got {other:?}"),
    }
    assert_eq!(canned.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn read_handler_cache_miss_falls_back_to_model() {
    let (dispatcher, registry) = build_dispatcher();

    let silent = Arc::new(SilentReadHandler);
    registry
        .install_read_handler("MMXU1$MX$TotW$mag", silent)
        .unwrap();

    let result = dispatch_single_read(&dispatcher, "IED1LD0", "MMXU1$MX$TotW$mag");
    // Without a handler value the model snapshot of 1.23 is returned.
    match result {
        AccessResult::Success(MmsData::Float32(v)) => {
            assert!(
                (v - 1.23).abs() < f32::EPSILON,
                "a cache miss falls back to the model snapshot"
            );
        }
        other => panic!("expected Float32(1.23), got {other:?}"),
    }
}

#[test]
fn silent_read_handler_equivalent_to_no_handler() {
    let (d_no_handler, _r1) = build_dispatcher();
    let r1 = dispatch_single_read(&d_no_handler, "IED1LD0", "MMXU1$MX$TotW$mag");

    let (d_silent, registry2) = build_dispatcher();
    registry2
        .install_read_handler("MMXU1$MX$TotW$mag", Arc::new(SilentReadHandler))
        .unwrap();
    let r2 = dispatch_single_read(&d_silent, "IED1LD0", "MMXU1$MX$TotW$mag");

    // Both paths return the model snapshot of 1.23.
    let v1 = match r1 {
        AccessResult::Success(MmsData::Float32(v)) => v,
        other => panic!("first read: expected Float32, got {other:?}"),
    };
    let v2 = match r2 {
        AccessResult::Success(MmsData::Float32(v)) => v,
        other => panic!("second read: expected Float32, got {other:?}"),
    };
    assert!(
        (v1 - v2).abs() < f32::EPSILON,
        "the silent handler must behave like no handler at all"
    );
}

#[test]
fn read_handler_error_returned_as_data_access_error() {
    let (dispatcher, registry) = build_dispatcher();

    #[derive(Debug)]
    struct AlwaysErr;
    impl ReadHandler for AlwaysErr {
        fn read(&self, _ctx: &ReadContext<'_>) -> ReadOutcome {
            ReadOutcome::Error(DataAccessError::HardwareFault)
        }
    }
    registry
        .install_read_handler("MMXU1$MX$TotW$mag", Arc::new(AlwaysErr))
        .unwrap();

    let result = dispatch_single_read(&dispatcher, "IED1LD0", "MMXU1$MX$TotW$mag");
    match result {
        AccessResult::Failure(DataAccessError::HardwareFault) => {}
        other => panic!("expected a HardwareFault failure, got {other:?}"),
    }
}

#[test]
fn deny_all_read_handler_blocks_path() {
    let (dispatcher, registry) = build_dispatcher();

    registry
        .install_read_handler(
            "MMXU1$MX$TotW$mag",
            Arc::new(DenyAllReadHandler {
                error: DataAccessError::ObjectAccessDenied,
            }),
        )
        .unwrap();

    let result = dispatch_single_read(&dispatcher, "IED1LD0", "MMXU1$MX$TotW$mag");
    match result {
        AccessResult::Failure(DataAccessError::ObjectAccessDenied) => {}
        other => panic!("the deny-all handler must answer ObjectAccessDenied, got {other:?}"),
    }
}

#[test]
fn set_ignore_read_access_short_circuits_registry() {
    let (dispatcher, registry) = build_dispatcher();

    // Install a handler that fails every read.
    registry
        .install_read_handler(
            "MMXU1$MX$TotW$mag",
            Arc::new(DenyAllReadHandler {
                error: DataAccessError::ObjectAccessDenied,
            }),
        )
        .unwrap();

    // With read access checks ignored the handler is bypassed.
    registry.set_ignore_read_access(true);

    let result = dispatch_single_read(&dispatcher, "IED1LD0", "MMXU1$MX$TotW$mag");
    match result {
        AccessResult::Success(MmsData::Float32(v)) => {
            assert!((v - 1.23).abs() < f32::EPSILON);
        }
        other => panic!("a bypassed handler must fall back to the model snapshot, got {other:?}"),
    }

    // Turning the bypass off makes the handler effective again.
    registry.set_ignore_read_access(false);
    let result2 = dispatch_single_read(&dispatcher, "IED1LD0", "MMXU1$MX$TotW$mag");
    match result2 {
        AccessResult::Failure(DataAccessError::ObjectAccessDenied) => {}
        other => panic!("the deny-all handler must apply again, got {other:?}"),
    }
}

#[test]
fn read_handler_does_not_override_object_nonexistent_guard() {
    // A handler cannot resurrect a path the model does not carry.
    let (dispatcher, registry) = build_dispatcher();

    // Install a value-returning handler on a path that does not exist.
    registry
        .install_read_handler(
            "MMXU1$MX$TotW$nosuchda",
            Arc::new(CannedReadHandler {
                value: MmsValue::Float32(42.0),
                calls: AtomicU32::new(0),
            }),
        )
        .unwrap();

    let result = dispatch_single_read(&dispatcher, "IED1LD0", "MMXU1$MX$TotW$nosuchda");
    // The read answers ObjectNonExistent and the handler is never called.
    match result {
        AccessResult::Failure(DataAccessError::ObjectNonExistent) => {}
        other => panic!("the object-nonexistent guard must win over the handler, got {other:?}"),
    }
}

// Attribute access handler tests.

/// A write handler that counts its calls and returns a preset outcome.
#[derive(Debug)]
struct RecordingWriteHandler {
    outcome: HandlerWriteOutcome,
    calls: AtomicU32,
}

impl RecordingWriteHandler {
    fn new(outcome: HandlerWriteOutcome) -> Arc<Self> {
        Arc::new(Self {
            outcome,
            calls: AtomicU32::new(0),
        })
    }
}

impl AttributeAccessHandler for RecordingWriteHandler {
    fn on_write(&self, _ctx: &WriteContext<'_>, _v: &MmsValue) -> HandlerWriteOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.outcome.clone()
    }
}

fn read_ctl_model(model: &IedModel) -> MmsValue {
    let ld = model.ld_by_domain("IED1LD0").unwrap();
    let ln = ld.ln_by_name("GGIO1").unwrap();
    let do_node = ln.do_by_name("Mod").unwrap();
    let da = do_node
        .children
        .iter()
        .find_map(|c| match c {
            DoChild::Da(da) if da.name == "ctlModel" => Some(da),
            _ => None,
        })
        .unwrap();
    da.snapshot()
}

#[test]
fn write_handler_accept_updates_cache() {
    let (dispatcher, registry) = build_dispatcher();
    let handler = RecordingWriteHandler::new(HandlerWriteOutcome::Accept);
    registry
        .install_write_access_handler("GGIO1$CF$Mod$ctlModel", handler.clone())
        .unwrap();

    let outcome = dispatch_single_write(
        &dispatcher,
        "IED1LD0",
        "GGIO1$CF$Mod$ctlModel",
        MmsData::Integer(2),
    );
    assert_eq!(outcome, WriteOutcome::Success);
    assert_eq!(handler.calls.load(Ordering::SeqCst), 1);

    // The cache carries the new value.
    let model = dispatcher.model.clone();
    assert_eq!(read_ctl_model(&model), MmsValue::Integer(2));
}

#[test]
fn write_handler_accept_no_update_skips_cache() {
    let (dispatcher, registry) = build_dispatcher();
    let handler = RecordingWriteHandler::new(HandlerWriteOutcome::AcceptNoUpdate);
    registry
        .install_write_access_handler("GGIO1$CF$Mod$ctlModel", handler.clone())
        .unwrap();

    let model = dispatcher.model.clone();
    let before = read_ctl_model(&model);

    let outcome = dispatch_single_write(
        &dispatcher,
        "IED1LD0",
        "GGIO1$CF$Mod$ctlModel",
        MmsData::Integer(2),
    );
    assert_eq!(outcome, WriteOutcome::Success);
    assert_eq!(handler.calls.load(Ordering::SeqCst), 1);

    // The cache is unchanged.
    let after = read_ctl_model(&model);
    assert_eq!(
        before, after,
        "accept-without-update must not touch the cache"
    );
}

#[test]
fn write_handler_reject_returns_error() {
    let (dispatcher, registry) = build_dispatcher();
    let handler = RecordingWriteHandler::new(HandlerWriteOutcome::Reject(
        DataAccessError::ObjectAccessDenied,
    ));
    registry
        .install_write_access_handler("GGIO1$CF$Mod$ctlModel", handler.clone())
        .unwrap();

    let model = dispatcher.model.clone();
    let before = read_ctl_model(&model);

    let outcome = dispatch_single_write(
        &dispatcher,
        "IED1LD0",
        "GGIO1$CF$Mod$ctlModel",
        MmsData::Integer(2),
    );
    assert_eq!(
        outcome,
        WriteOutcome::Failure(DataAccessError::ObjectAccessDenied)
    );
    assert_eq!(handler.calls.load(Ordering::SeqCst), 1);

    // The cache is unchanged.
    assert_eq!(
        before,
        read_ctl_model(&model),
        "a rejected write must not touch the cache"
    );
}

#[test]
fn write_handler_called_after_policy_passes() {
    // The write policy is checked before the handler runs.
    let model = build_test_model();
    let mms_model = MmsDeviceModel::from_ied_model(&model).unwrap();
    // CF is not writable by default.
    let policies = WriteAccessPolicies::default();
    let registry = Arc::new(HandlerRegistry::new());
    let dispatcher =
        MmsModelDispatcher::new(Arc::new(model), Arc::new(mms_model), Arc::new(policies))
            .with_handler_registry(registry.clone());

    let handler = RecordingWriteHandler::new(HandlerWriteOutcome::Accept);
    registry
        .install_write_access_handler("GGIO1$CF$Mod$ctlModel", handler.clone())
        .unwrap();

    let outcome = dispatch_single_write(
        &dispatcher,
        "IED1LD0",
        "GGIO1$CF$Mod$ctlModel",
        MmsData::Integer(2),
    );
    // The policy refuses the write.
    assert_eq!(
        outcome,
        WriteOutcome::Failure(DataAccessError::ObjectAccessDenied)
    );
    // The handler is never reached.
    assert_eq!(
        handler.calls.load(Ordering::SeqCst),
        0,
        "a policy refusal must keep the handler from running"
    );
}

#[test]
fn write_handler_called_after_type_check() {
    // The type check also runs before the handler.
    let (dispatcher, registry) = build_dispatcher();
    let handler = RecordingWriteHandler::new(HandlerWriteOutcome::Accept);
    registry
        .install_write_access_handler("GGIO1$CF$Mod$ctlModel", handler.clone())
        .unwrap();

    // ctlModel is an integer, so writing a boolean is a type mismatch.
    let outcome = dispatch_single_write(
        &dispatcher,
        "IED1LD0",
        "GGIO1$CF$Mod$ctlModel",
        MmsData::Boolean(true),
    );
    assert_eq!(
        outcome,
        WriteOutcome::Failure(DataAccessError::ObjectValueInvalid)
    );
    assert_eq!(
        handler.calls.load(Ordering::SeqCst),
        0,
        "a type mismatch must keep the handler from running"
    );
}

// Handler replacement and path canonicalization.

#[test]
fn install_handler_replaces_with_warn() {
    // Installing twice on one path keeps the later handler.
    let (dispatcher, registry) = build_dispatcher();

    let h1 =
        RecordingWriteHandler::new(HandlerWriteOutcome::Reject(DataAccessError::HardwareFault));
    let h2 = RecordingWriteHandler::new(HandlerWriteOutcome::Accept);

    registry
        .install_write_access_handler("GGIO1$CF$Mod$ctlModel", h1.clone())
        .unwrap();
    registry
        .install_write_access_handler("GGIO1$CF$Mod$ctlModel", h2.clone())
        .unwrap();

    let outcome = dispatch_single_write(
        &dispatcher,
        "IED1LD0",
        "GGIO1$CF$Mod$ctlModel",
        MmsData::Integer(2),
    );
    // The second handler is the one that runs.
    assert_eq!(outcome, WriteOutcome::Success);
    assert_eq!(
        h1.calls.load(Ordering::SeqCst),
        0,
        "the replaced handler must not run"
    );
    assert_eq!(
        h2.calls.load(Ordering::SeqCst),
        1,
        "the later handler must run"
    );
}

#[test]
fn path_canonicalization_dot_to_dollar_works_in_dispatch() {
    // A path installed in dotted form and dispatched in dollar form canonicalize
    // to the same key.
    let (dispatcher, registry) = build_dispatcher();

    let handler = RecordingWriteHandler::new(HandlerWriteOutcome::Reject(
        DataAccessError::ObjectAccessDenied,
    ));
    registry
        .install_write_access_handler("GGIO1.CF.Mod.ctlModel", handler.clone())
        .unwrap();

    // Dispatched item identifiers always use the dollar form.
    let outcome = dispatch_single_write(
        &dispatcher,
        "IED1LD0",
        "GGIO1$CF$Mod$ctlModel",
        MmsData::Integer(2),
    );
    assert_eq!(
        outcome,
        WriteOutcome::Failure(DataAccessError::ObjectAccessDenied)
    );
    assert_eq!(handler.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn path_canonicalization_fc_uppercase_works_in_dispatch() {
    // The functional constraint in a path is case-insensitive after
    // canonicalization.
    let (dispatcher, registry) = build_dispatcher();

    let handler = RecordingWriteHandler::new(HandlerWriteOutcome::Reject(
        DataAccessError::ObjectAccessDenied,
    ));
    registry
        .install_write_access_handler("GGIO1$cf$Mod$ctlModel", handler.clone())
        .unwrap();

    let outcome = dispatch_single_write(
        &dispatcher,
        "IED1LD0",
        "GGIO1$CF$Mod$ctlModel",
        MmsData::Integer(2),
    );
    assert_eq!(
        outcome,
        WriteOutcome::Failure(DataAccessError::ObjectAccessDenied)
    );
    assert_eq!(handler.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn path_canonicalization_rejects_short_at_install() {
    let registry = HandlerRegistry::new();
    // Fewer than three path segments.
    assert!(
        registry
            .install_read_handler("MMXU1", Arc::new(SilentReadHandler))
            .is_err(),
        "a path with fewer than three segments must be rejected at install time"
    );
    assert!(
        registry
            .install_write_access_handler(
                "MMXU1$MX",
                Arc::new(RecordingWriteHandler {
                    outcome: HandlerWriteOutcome::Accept,
                    calls: AtomicU32::new(0),
                })
            )
            .is_err(),
        "a path with fewer than three segments must be rejected at install time"
    );
}
