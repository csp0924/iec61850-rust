//! Integration tests for the direct control model with enhanced security
//! (ctlModel 3).
//!
//! They exercise the Operate to CommandTermination path, where the termination
//! reaches the client as an unsolicited InformationReport: a write of Oper runs
//! the check handler, the wait-for-execution handler and the operate handler,
//! and a successful operate ends in a positive CommandTermination while a
//! failing one ends in a negative CommandTermination.

use iec61850_model::MmsValue;
use iec61850_server::control::{
    handle_operate, state::ControlState, AlwaysAcceptCheckHandler, AlwaysAcceptWaitHandler,
    AlwaysFailOperateHandler, AlwaysSuccessOperateHandler, CheckHandler, ControlAddCause,
    ControlHandler, ControlModel, ControlObject, ControlObjectConfig, RecordingCommandTermination,
    SboClass, ServiceResult, TerminationEvent, WaitForExecutionHandler,
};
use std::sync::Arc;

fn make_obj() -> ControlObject {
    ControlObject::new(ControlObjectConfig {
        name: "SPCSO1".into(),
        ln_name: "GGIO1".into(),
        domain: "IED1LD0".into(),
        ctl_model: ControlModel::DirectEnhanced,
        sbo_timeout_ms: 5000,
        sbo_class: SboClass::OperateOnce,
    })
}

fn make_oper_value(ctl_val: bool) -> MmsValue {
    MmsValue::Structure(vec![
        MmsValue::Boolean(ctl_val),
        MmsValue::Structure(vec![
            MmsValue::Integer(2),
            MmsValue::OctetString(vec![0xAA]),
        ]),
        MmsValue::Unsigned(3),
        MmsValue::UtcTime([0u8; 8]),
        MmsValue::Boolean(false),
        MmsValue::BitString {
            padding: 6,
            data: vec![0x00],
        },
    ])
}

fn make_recorder() -> (
    RecordingCommandTermination,
    Arc<std::sync::Mutex<Vec<TerminationEvent>>>,
) {
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let rec = RecordingCommandTermination {
        events: events.clone(),
    };
    (rec, events)
}

// Happy path: Operate → CommandTermination+

#[tokio::test]
async fn direct_enhanced_operate_sends_command_termination_positive() {
    let obj = make_obj();
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);
    let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
    let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
    let (ct, events) = make_recorder();

    let oper_val = make_oper_value(true);
    let result = handle_operate(
        &obj,
        42, // conn_id
        &oper_val,
        Some(&check_h),
        Some(&wait_h),
        Some(&oper_h),
        &ct,
    )
    .await;

    assert_eq!(result, ServiceResult::Success);
    assert_eq!(obj.state(), ControlState::Unselected);

    let recorded = events.lock().unwrap();
    assert_eq!(recorded.len(), 1, "expected exactly one CommandTermination");
    assert!(
        matches!(recorded[0], TerminationEvent::Positive { conn_id: 42, .. }),
        "expected a positive CommandTermination on conn_id 42"
    );
    assert!(
        recorded[0].obj_ref_contains("SPCSO1"),
        "obj_ref must contain the data object name"
    );
}

// A failing operate handler ends in a negative CommandTermination.

#[tokio::test]
async fn direct_enhanced_operate_failure_sends_command_termination_negative() {
    let obj = make_obj();
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);
    let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
    let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysFailOperateHandler {
        cause: ControlAddCause::BlockedByProcess,
    });
    let (ct, events) = make_recorder();

    let oper_val = make_oper_value(false);
    let result = handle_operate(
        &obj,
        7,
        &oper_val,
        Some(&check_h),
        Some(&wait_h),
        Some(&oper_h),
        &ct,
    )
    .await;

    assert_eq!(
        result,
        ServiceResult::Failure(ControlAddCause::BlockedByProcess)
    );

    let recorded = events.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    assert!(
        matches!(
            recorded[0],
            TerminationEvent::Negative {
                add_cause: ControlAddCause::BlockedByProcess,
                conn_id: 7,
                ..
            }
        ),
        "expected a negative CommandTermination with BlockedByProcess on conn_id 7"
    );
}

// A rejecting check handler ends in a negative CommandTermination.

#[tokio::test]
async fn direct_enhanced_check_rejected_sends_command_termination_negative() {
    use iec61850_server::control::handler::CheckHandler as CheckHandlerTrait;

    struct RejectHandler;
    impl CheckHandlerTrait for RejectHandler {
        fn check(
            &self,
            _action: &iec61850_server::control::ControlAction,
            _ctl_val: Option<&MmsValue>,
            _test: bool,
            _interlock_check: bool,
        ) -> Result<(), ControlAddCause> {
            Err(ControlAddCause::BlockedBySynchroCheck)
        }
    }

    let obj = make_obj();
    let check_h: Arc<dyn CheckHandler> = Arc::new(RejectHandler);
    let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
    let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
    let (ct, events) = make_recorder();

    let oper_val = make_oper_value(true);
    let result = handle_operate(
        &obj,
        5,
        &oper_val,
        Some(&check_h),
        Some(&wait_h),
        Some(&oper_h),
        &ct,
    )
    .await;

    assert_eq!(
        result,
        ServiceResult::Failure(ControlAddCause::BlockedBySynchroCheck)
    );

    let recorded = events.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    assert!(matches!(
        recorded[0],
        TerminationEvent::Negative {
            add_cause: ControlAddCause::BlockedBySynchroCheck,
            ..
        }
    ));
}

// Direct control with enhanced security sends a CommandTermination for every
// Operate, so two operations produce two of them.

#[tokio::test]
async fn direct_enhanced_two_consecutive_operates_each_sends_ct() {
    let obj = make_obj();
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);
    let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
    let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
    let (ct, events) = make_recorder();

    for _ in 0..2 {
        handle_operate(
            &obj,
            1,
            &make_oper_value(true),
            Some(&check_h),
            Some(&wait_h),
            Some(&oper_h),
            &ct,
        )
        .await;
    }

    let recorded = events.lock().unwrap();
    assert_eq!(
        recorded.len(),
        2,
        "each Operate must produce one CommandTermination"
    );
    assert!(recorded
        .iter()
        .all(|e| matches!(e, TerminationEvent::Positive { .. })));
}

// Helper trait that extracts obj_ref from a TerminationEvent.

trait ObjRefCheck {
    fn obj_ref_contains(&self, sub: &str) -> bool;
}

impl ObjRefCheck for TerminationEvent {
    fn obj_ref_contains(&self, sub: &str) -> bool {
        match self {
            TerminationEvent::Positive { obj_ref, .. } => obj_ref.contains(sub),
            TerminationEvent::Negative { obj_ref, .. } => obj_ref.contains(sub),
        }
    }
}
