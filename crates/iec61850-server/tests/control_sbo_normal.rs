//! Integration tests for select-before-operate with normal security
//! (ctlModel 2).
//!
//! They cover a read of SBO followed by a write of Oper, a second select from
//! another connection while the object is held, the automatic unselect on the
//! select timeout, and cancel from the owning and from a foreign connection.

use iec61850_model::MmsValue;
use iec61850_server::control::{
    handle_cancel, handle_operate, handle_read_sbo, state::ControlState, AlwaysAcceptCheckHandler,
    AlwaysAcceptWaitHandler, AlwaysSuccessOperateHandler, CheckHandler, ControlHandler,
    ControlModel, ControlObject, ControlObjectConfig, NoOpCommandTermination, SboClass,
    ServiceResult, WaitForExecutionHandler,
};
use std::sync::Arc;
use std::time::Duration;

fn make_obj(sbo_timeout_ms: u32) -> ControlObject {
    ControlObject::new(ControlObjectConfig {
        name: "SPCSO1".into(),
        ln_name: "GGIO1".into(),
        domain: "IED1LD0".into(),
        ctl_model: ControlModel::SboNormal,
        sbo_timeout_ms,
        sbo_class: SboClass::OperateOnce,
    })
}

fn make_oper_value() -> MmsValue {
    MmsValue::Structure(vec![
        MmsValue::Boolean(true),
        MmsValue::Structure(vec![
            MmsValue::Integer(1),
            MmsValue::OctetString(vec![0x01]),
        ]),
        MmsValue::Unsigned(1),
        MmsValue::UtcTime([0u8; 8]),
        MmsValue::Boolean(false),
        MmsValue::BitString {
            padding: 6,
            data: vec![0x00],
        },
    ])
}

fn make_cancel_value() -> MmsValue {
    MmsValue::Structure(vec![
        MmsValue::Boolean(true),
        MmsValue::Structure(vec![
            MmsValue::Integer(1),
            MmsValue::OctetString(vec![0x01]),
        ]),
        MmsValue::Unsigned(1),
        MmsValue::UtcTime([0u8; 8]),
        MmsValue::Boolean(false),
    ])
}

// Happy path: Select → Operate → SUCCESS

#[tokio::test]
async fn sbo_normal_select_then_operate_succeeds() {
    let obj = make_obj(5000);
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);

    // Select, that is a read of SBO.
    let sbo_ref = handle_read_sbo(&obj, 1, Some(&check_h));
    assert!(
        sbo_ref.is_some(),
        "a successful select returns the object reference"
    );
    assert!(
        sbo_ref.unwrap().contains("SPCSO1"),
        "the object reference must contain the data object name"
    );
    assert_eq!(obj.state(), ControlState::Ready);

    // Operate from the connection that holds the selection.
    let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
    let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
    let ct = NoOpCommandTermination;

    let result = handle_operate(
        &obj,
        1,
        &make_oper_value(),
        Some(&check_h),
        Some(&wait_h),
        Some(&oper_h),
        &ct,
    )
    .await;

    assert_eq!(
        result,
        ServiceResult::Success,
        "Operate after select must succeed"
    );
    // operate-once → unselect
    assert_eq!(obj.state(), ControlState::Unselected);
}

// Re-selecting from the owning connection succeeds and refreshes the select
// timer.

#[tokio::test]
async fn sbo_normal_double_select_same_conn_ok() {
    let obj = make_obj(5000);
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);

    let r1 = handle_read_sbo(&obj, 1, Some(&check_h));
    assert!(r1.is_some());

    let r2 = handle_read_sbo(&obj, 1, Some(&check_h));
    assert!(
        r2.is_some(),
        "a repeated select from the owner must succeed"
    );
    assert_eq!(obj.state(), ControlState::Ready);
}

// Selecting from another connection fails while the object is held.

#[tokio::test]
async fn sbo_normal_double_select_different_conn_fails() {
    let obj = make_obj(5000);
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);

    handle_read_sbo(&obj, 1, Some(&check_h));

    let r2 = handle_read_sbo(&obj, 2, Some(&check_h));
    assert!(
        r2.is_none(),
        "a select from another connection must fail and return an empty string"
    );
    // The first connection still holds the selection.
    assert_eq!(obj.state(), ControlState::Ready);
}

// The select timeout unselects the object on its own.

#[tokio::test]
async fn sbo_normal_timeout_auto_unselect() {
    let obj = make_obj(50); // 50ms timeout
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);

    handle_read_sbo(&obj, 1, Some(&check_h));
    assert_eq!(obj.state(), ControlState::Ready);

    tokio::time::sleep(Duration::from_millis(100)).await;

    let timed_out = obj.check_sbo_timeout();
    assert!(timed_out, "the select must time out after 50ms");
    assert_eq!(
        obj.state(),
        ControlState::Unselected,
        "the object is Unselected once the select times out"
    );
}

// Cancel from the owning connection succeeds and unselects the object.

#[tokio::test]
async fn sbo_normal_cancel_same_conn_succeeds() {
    let obj = make_obj(5000);
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);

    handle_read_sbo(&obj, 1, Some(&check_h));
    assert_eq!(obj.state(), ControlState::Ready);

    let cancel_val = make_cancel_value();
    let result = handle_cancel(&obj, 1, &cancel_val);
    assert_eq!(
        result,
        ServiceResult::Success,
        "Cancel from the owner must succeed"
    );
    assert_eq!(obj.state(), ControlState::Unselected);
}

// Cancel from another connection fails.

#[tokio::test]
async fn sbo_normal_cancel_wrong_conn_fails() {
    let obj = make_obj(5000);
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);

    handle_read_sbo(&obj, 1, Some(&check_h));

    let cancel_val = make_cancel_value();
    let result = handle_cancel(&obj, 2, &cancel_val);
    assert!(
        matches!(result, ServiceResult::Failure(_)),
        "Cancel from another connection must fail"
    );
    // The object stays Ready.
    assert_eq!(obj.state(), ControlState::Ready);
}

// With operate-many the object stays Ready after an Operate.

#[tokio::test]
async fn sbo_normal_operate_many_stays_selected() {
    let obj = ControlObject::new(ControlObjectConfig {
        name: "SPCSO1".into(),
        ln_name: "GGIO1".into(),
        domain: "IED1LD0".into(),
        ctl_model: ControlModel::SboNormal,
        sbo_timeout_ms: 5000,
        sbo_class: SboClass::OperateMany,
    });
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);
    handle_read_sbo(&obj, 1, Some(&check_h));

    let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
    let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
    let ct = NoOpCommandTermination;

    let result = handle_operate(
        &obj,
        1,
        &make_oper_value(),
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
        "the object stays Ready after an operate-many Operate"
    );
}

// Losing the connection unselects the object.

#[tokio::test]
async fn sbo_normal_connection_closed_unselects() {
    let obj = make_obj(5000);
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);

    handle_read_sbo(&obj, 99, Some(&check_h));
    assert_eq!(obj.state(), ControlState::Ready);

    obj.on_connection_closed(99);
    assert_eq!(
        obj.state(),
        ControlState::Unselected,
        "a lost connection must unselect the object"
    );
}
