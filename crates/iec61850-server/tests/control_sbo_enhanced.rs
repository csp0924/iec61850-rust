//! Integration tests for select-before-operate with enhanced security
//! (ctlModel 4).
//!
//! A write of SBOw carrying the control value selects the object; a following
//! Oper with the same parameters succeeds and produces a positive
//! CommandTermination, while one with a different control value or control
//! number fails with InconsistentParameters and unselects. The tests also cover
//! Oper after the select timeout, cancel from the owning and from a foreign
//! connection, and the unselect that follows a lost connection.

use iec61850_model::MmsValue;
use iec61850_server::control::{
    handle_cancel, handle_operate, handle_sbow, state::ControlState, AlwaysAcceptCheckHandler,
    AlwaysAcceptWaitHandler, AlwaysFailOperateHandler, AlwaysSuccessOperateHandler, CheckHandler,
    ControlAddCause, ControlHandler, ControlModel, ControlObject, ControlObjectConfig,
    RecordingCommandTermination, SboClass, ServiceResult, TerminationEvent,
    WaitForExecutionHandler,
};
use std::sync::Arc;
use std::time::Duration;

fn make_obj(sbo_timeout_ms: u32) -> ControlObject {
    ControlObject::new(ControlObjectConfig {
        name: "SPCSO1".into(),
        ln_name: "GGIO1".into(),
        domain: "IED1LD0".into(),
        ctl_model: ControlModel::SboEnhanced,
        sbo_timeout_ms,
        sbo_class: SboClass::OperateOnce,
    })
}

/// Builds the six-element SBOw or Oper structure.
fn make_oper_value(ctl_val: bool, ctl_num: u8) -> MmsValue {
    MmsValue::Structure(vec![
        MmsValue::Boolean(ctl_val),
        MmsValue::Structure(vec![
            MmsValue::Integer(3),
            MmsValue::OctetString(vec![0x01]),
        ]),
        MmsValue::Unsigned(ctl_num as u64),
        MmsValue::UtcTime([0u8; 8]),
        MmsValue::Boolean(false),
        MmsValue::BitString {
            padding: 6,
            data: vec![0x40],
        },
    ])
}

fn make_cancel_value() -> MmsValue {
    MmsValue::Structure(vec![
        MmsValue::Boolean(true),
        MmsValue::Structure(vec![
            MmsValue::Integer(3),
            MmsValue::OctetString(vec![0x01]),
        ]),
        MmsValue::Unsigned(1),
        MmsValue::UtcTime([0u8; 8]),
        MmsValue::Boolean(false),
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

// SBOw followed by a matching Oper succeeds and terminates positively.

#[tokio::test]
async fn sbo_enhanced_select_then_operate_succeeds() {
    let obj = make_obj(5000);
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);

    // SBOw select
    let sbow_val = make_oper_value(true, 1);
    let sbow_r = handle_sbow(&obj, 42, &sbow_val, Some(&check_h)).await;
    assert_eq!(
        sbow_r,
        ServiceResult::Success,
        "SBOw must select the object"
    );
    assert_eq!(
        obj.state(),
        ControlState::Ready,
        "SBOw leaves the object Ready"
    );

    // Oper from the same connection with the same parameters.
    let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
    let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
    let (ct, events) = make_recorder();

    let oper_val = make_oper_value(true, 1); // same parameters as the SBOw
    let result = handle_operate(
        &obj,
        42,
        &oper_val,
        Some(&check_h),
        Some(&wait_h),
        Some(&oper_h),
        &ct,
    )
    .await;

    assert_eq!(
        result,
        ServiceResult::Success,
        "Operate after a matching select must succeed"
    );
    // operate-once → Unselected
    assert_eq!(
        obj.state(),
        ControlState::Unselected,
        "operate-once unselects the object afterwards"
    );

    // CommandTermination+
    let recorded = events.lock().unwrap();
    assert_eq!(recorded.len(), 1, "expected exactly one CommandTermination");
    assert!(
        matches!(recorded[0], TerminationEvent::Positive { conn_id: 42, .. }),
        "expected a positive CommandTermination on conn_id 42"
    );
    assert!(
        obj_ref_contains(&recorded[0], "SPCSO1"),
        "obj_ref must contain the data object name"
    );
}

// A mismatched control value fails with InconsistentParameters and unselects.

#[tokio::test]
async fn sbo_enhanced_inconsistent_ctl_val_denied() {
    let obj = make_obj(5000);
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);

    // SBOw with true
    let sbow_val = make_oper_value(true, 1);
    handle_sbow(&obj, 1, &sbow_val, Some(&check_h)).await;
    assert_eq!(obj.state(), ControlState::Ready);

    // Oper with the opposite control value.
    let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
    let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
    let (ct, events) = make_recorder();

    let oper_val = make_oper_value(false, 1); // different control value
    let result = handle_operate(
        &obj,
        1,
        &oper_val,
        Some(&check_h),
        Some(&wait_h),
        Some(&oper_h),
        &ct,
    )
    .await;

    assert_eq!(
        result,
        ServiceResult::Failure(ControlAddCause::InconsistentParameters),
        "a mismatched control value must fail with InconsistentParameters"
    );
    assert_eq!(
        obj.state(),
        ControlState::Unselected,
        "a mismatch unselects the object"
    );

    // Per IEC 61850-7-2 clause 20.2.1 every denied Operate under enhanced
    // security is reported, so a rejection in begin_operate - a parameter
    // mismatch or an unselected object - still sends a negative
    // CommandTermination rather than failing silently.
    let recorded = events.lock().unwrap();
    assert_eq!(
        recorded.len(),
        1,
        "a denied Operate must send a negative CommandTermination"
    );
    assert!(matches!(
        recorded[0],
        iec61850_server::control::TerminationEvent::Negative { .. }
    ));
}

// After the select times out an Oper fails with ObjectNotSelected.

#[tokio::test]
async fn sbo_enhanced_timeout_then_oper_fails() {
    let obj = make_obj(50); // 50ms timeout
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);

    let sbow_val = make_oper_value(true, 1);
    handle_sbow(&obj, 1, &sbow_val, Some(&check_h)).await;
    assert_eq!(obj.state(), ControlState::Ready);

    // Wait past the select timeout.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let timed_out = obj.check_sbo_timeout();
    assert!(timed_out, "the select must time out");
    assert_eq!(
        obj.state(),
        ControlState::Unselected,
        "the object is Unselected once the select times out"
    );

    // Oper on unselected → ObjectNotSelected
    let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
    let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
    let (ct, _events) = make_recorder();

    let oper_val = make_oper_value(true, 1);
    let result = handle_operate(
        &obj,
        1,
        &oper_val,
        Some(&check_h),
        Some(&wait_h),
        Some(&oper_h),
        &ct,
    )
    .await;

    assert_eq!(
        result,
        ServiceResult::Failure(ControlAddCause::ObjectNotSelected),
        "an Oper after the timeout must fail with ObjectNotSelected"
    );
}

// Cancel from the owning connection succeeds and unselects the object.

#[tokio::test]
async fn sbo_enhanced_cancel_same_conn_succeeds() {
    let obj = make_obj(5000);
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);

    let sbow_val = make_oper_value(true, 1);
    handle_sbow(&obj, 1, &sbow_val, Some(&check_h)).await;
    assert_eq!(obj.state(), ControlState::Ready);

    let cancel_val = make_cancel_value();
    let result = handle_cancel(&obj, 1, &cancel_val);
    assert_eq!(
        result,
        ServiceResult::Success,
        "Cancel from the owner must succeed"
    );
    assert_eq!(
        obj.state(),
        ControlState::Unselected,
        "the object is Unselected after a Cancel"
    );
}

// Cancel from another connection fails with LockedByOtherClient.

#[tokio::test]
async fn sbo_enhanced_cancel_wrong_conn_fails() {
    let obj = make_obj(5000);
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);

    let sbow_val = make_oper_value(true, 1);
    handle_sbow(&obj, 1, &sbow_val, Some(&check_h)).await;

    let cancel_val = make_cancel_value();
    let result = handle_cancel(&obj, 2, &cancel_val);
    assert!(
        matches!(
            result,
            ServiceResult::Failure(ControlAddCause::LockedByOtherClient)
        ),
        "Cancel from another connection must fail with LockedByOtherClient"
    );
    assert_eq!(
        obj.state(),
        ControlState::Ready,
        "the object stays Ready after a refused Cancel"
    );
}

// Losing the connection unselects the object.

#[tokio::test]
async fn sbo_enhanced_connection_closed_unselects() {
    let obj = make_obj(5000);
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);

    let sbow_val = make_oper_value(true, 1);
    handle_sbow(&obj, 77, &sbow_val, Some(&check_h)).await;
    assert_eq!(obj.state(), ControlState::Ready);

    obj.on_connection_closed(77);
    assert_eq!(
        obj.state(),
        ControlState::Unselected,
        "a lost connection must unselect the object"
    );
}

// A failing operate handler ends in a negative CommandTermination.

#[tokio::test]
async fn sbo_enhanced_operate_failure_sends_ct_negative() {
    let obj = make_obj(5000);
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);

    // SBOw select
    let sbow_val = make_oper_value(true, 1);
    handle_sbow(&obj, 5, &sbow_val, Some(&check_h)).await;

    let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
    let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysFailOperateHandler {
        cause: ControlAddCause::BlockedByProcess,
    });
    let (ct, events) = make_recorder();

    let oper_val = make_oper_value(true, 1); // matching parameters
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
        ServiceResult::Failure(ControlAddCause::BlockedByProcess),
        "a failing operate handler must fail with BlockedByProcess"
    );

    // Enhanced security reports the failure as a negative CommandTermination.
    let recorded = events.lock().unwrap();
    assert_eq!(recorded.len(), 1, "expected exactly one CommandTermination");
    assert!(
        matches!(
            recorded[0],
            TerminationEvent::Negative {
                add_cause: ControlAddCause::BlockedByProcess,
                conn_id: 5,
                ..
            }
        ),
        "expected a negative CommandTermination with BlockedByProcess on conn_id 5"
    );
}

// A matching control value with a different control number also fails.

#[tokio::test]
async fn sbo_enhanced_inconsistent_ctl_num_denied() {
    let obj = make_obj(5000);
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);

    // SBOw with ctl_num=1
    let sbow_val = make_oper_value(true, 1);
    handle_sbow(&obj, 1, &sbow_val, Some(&check_h)).await;

    // Oper with a different control number.
    let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
    let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
    let (ct, _events) = make_recorder();

    let oper_val = make_oper_value(true, 2); // different control number
    let result = handle_operate(
        &obj,
        1,
        &oper_val,
        Some(&check_h),
        Some(&wait_h),
        Some(&oper_h),
        &ct,
    )
    .await;

    assert_eq!(
        result,
        ServiceResult::Failure(ControlAddCause::InconsistentParameters),
        "a mismatched control number must fail with InconsistentParameters"
    );
    assert_eq!(obj.state(), ControlState::Unselected);
}

// An Oper from another connection while the object is held fails with
// LockedByOtherClient.

#[tokio::test]
async fn sbo_enhanced_wrong_conn_oper_fails() {
    let obj = make_obj(5000);
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);

    // conn 1 select
    let sbow_val = make_oper_value(true, 1);
    handle_sbow(&obj, 1, &sbow_val, Some(&check_h)).await;
    assert_eq!(obj.state(), ControlState::Ready);

    // conn 2 Oper
    let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
    let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
    let (ct, _events) = make_recorder();

    let oper_val = make_oper_value(true, 1);
    let result = handle_operate(
        &obj,
        2, // a different connection
        &oper_val,
        Some(&check_h),
        Some(&wait_h),
        Some(&oper_h),
        &ct,
    )
    .await;

    assert_eq!(
        result,
        ServiceResult::Failure(ControlAddCause::LockedByOtherClient),
        "an Oper from another connection must fail with LockedByOtherClient"
    );
    // The first connection still holds the selection.
    assert_eq!(obj.state(), ControlState::Ready);
}

// A second SBOw from another connection fails while the object is held.

#[tokio::test]
async fn sbo_enhanced_double_sbow_different_conn_fails() {
    let obj = make_obj(5000);
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);

    // conn 1 SBOw
    let sbow_val = make_oper_value(true, 1);
    let r1 = handle_sbow(&obj, 1, &sbow_val, Some(&check_h)).await;
    assert_eq!(r1, ServiceResult::Success);

    // The SBOw from the second connection fails.
    let sbow_val2 = make_oper_value(true, 1);
    let r2 = handle_sbow(&obj, 2, &sbow_val2, Some(&check_h)).await;
    assert!(
        matches!(r2, ServiceResult::Failure(_)),
        "a second SBOw from another connection must fail"
    );
    // The first connection keeps the selection.
    assert_eq!(obj.state(), ControlState::Ready);
}

// With operate-many the object stays Ready after an Oper.

#[tokio::test]
async fn sbo_enhanced_operate_many_stays_selected() {
    let obj = ControlObject::new(ControlObjectConfig {
        name: "SPCSO1".into(),
        ln_name: "GGIO1".into(),
        domain: "IED1LD0".into(),
        ctl_model: ControlModel::SboEnhanced,
        sbo_timeout_ms: 5000,
        sbo_class: SboClass::OperateMany,
    });
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);

    // SBOw select
    let sbow_val = make_oper_value(true, 1);
    handle_sbow(&obj, 1, &sbow_val, Some(&check_h)).await;

    let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
    let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
    let (ct, _events) = make_recorder();

    let oper_val = make_oper_value(true, 1);
    let result = handle_operate(
        &obj,
        1,
        &oper_val,
        Some(&check_h),
        Some(&wait_h),
        Some(&oper_h),
        &ct,
    )
    .await;

    assert_eq!(result, ServiceResult::Success);
    // operate-many does not unselect.
    assert_eq!(
        obj.state(),
        ControlState::Ready,
        "the object stays Ready after an operate-many Oper"
    );
}

// Helpers.

fn obj_ref_contains(event: &TerminationEvent, sub: &str) -> bool {
    match event {
        TerminationEvent::Positive { obj_ref, .. } => obj_ref.contains(sub),
        TerminationEvent::Negative { obj_ref, .. } => obj_ref.contains(sub),
    }
}
