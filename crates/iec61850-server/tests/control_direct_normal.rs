//! Integration tests for the direct control model with normal security
//! (ctlModel 1).
//!
//! A write of Oper runs the check handler, the wait-for-execution handler and
//! the operate handler, and answers the write with success. The tests call the
//! control services on a `ControlObject` directly, without a TCP connection.

use iec61850_model::MmsValue;
use iec61850_server::control::{
    handle_operate, state::ControlState, AlwaysAcceptCheckHandler, AlwaysAcceptWaitHandler,
    AlwaysFailOperateHandler, AlwaysSuccessOperateHandler, CheckHandler, ControlAddCause,
    ControlHandler, ControlModel, ControlObject, ControlObjectConfig, NoOpCommandTermination,
    SboClass, ServiceResult, WaitForExecutionHandler,
};
use std::sync::Arc;

fn make_obj(model: ControlModel) -> ControlObject {
    ControlObject::new(ControlObjectConfig {
        name: "SPCSO1".into(),
        ln_name: "GGIO1".into(),
        domain: "IED1LD0".into(),
        ctl_model: model,
        sbo_timeout_ms: 5000,
        sbo_class: SboClass::OperateOnce,
    })
}

/// Builds the six-element Oper structure.
fn make_oper_value(ctl_val: bool, ctl_num: u8, interlock: bool) -> MmsValue {
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
            data: vec![if interlock { 0x40 } else { 0x00 }],
        },
    ])
}

// Happy path: Operate → SUCCESS

#[tokio::test]
async fn direct_normal_operate_happy_path() {
    let obj = make_obj(ControlModel::DirectNormal);

    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);
    let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
    let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
    let ct = NoOpCommandTermination;

    let oper_val = make_oper_value(true, 1, true);
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
        ServiceResult::Success,
        "Operate under direct control with normal security must succeed"
    );
    assert_eq!(
        obj.state(),
        ControlState::Unselected,
        "the object returns to Unselected once the Operate completes"
    );
}

// Direct control has no select step, so every Operate executes on its own.

#[tokio::test]
async fn direct_normal_operate_twice_succeeds() {
    let obj = make_obj(ControlModel::DirectNormal);

    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);
    let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
    let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
    let ct = NoOpCommandTermination;

    for i in 1u8..=2 {
        let oper_val = make_oper_value(true, i, false);
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
        assert_eq!(result, ServiceResult::Success, "Operate {} must succeed", i);
        assert_eq!(obj.state(), ControlState::Unselected);
    }
}

// A rejecting check handler fails the write and never reaches the operate
// handler.

#[tokio::test]
async fn direct_normal_check_rejected_no_operate() {
    use iec61850_server::control::handler::CheckHandler;

    struct RejectCheckHandler;
    impl CheckHandler for RejectCheckHandler {
        fn check(
            &self,
            _action: &iec61850_server::control::ControlAction,
            _ctl_val: Option<&MmsValue>,
            _test: bool,
            _interlock_check: bool,
        ) -> Result<(), ControlAddCause> {
            Err(ControlAddCause::BlockedByInterlocking)
        }
    }

    let obj = make_obj(ControlModel::DirectNormal);
    let check_h: Arc<dyn CheckHandler> = Arc::new(RejectCheckHandler);
    let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
    let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
    let ct = NoOpCommandTermination;

    let oper_val = make_oper_value(true, 1, false);
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
        ServiceResult::Failure(ControlAddCause::BlockedByInterlocking),
        "a rejected check must fail the service"
    );
    assert_eq!(
        obj.state(),
        ControlState::Unselected,
        "the object stays Unselected after a rejection"
    );
}

// A failing operate handler fails the write.

#[tokio::test]
async fn direct_normal_operate_failure() {
    let obj = make_obj(ControlModel::DirectNormal);
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);
    let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
    let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysFailOperateHandler {
        cause: ControlAddCause::BlockedByProcess,
    });
    let ct = NoOpCommandTermination;

    let oper_val = make_oper_value(true, 1, false);
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
        ServiceResult::Failure(ControlAddCause::BlockedByProcess),
        "a failing operate handler must fail with BlockedByProcess"
    );
    assert_eq!(obj.state(), ControlState::Unselected);
}

// A status-only object refuses control.

#[tokio::test]
async fn status_only_denies_operate() {
    let obj = make_obj(ControlModel::StatusOnly);
    let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);
    let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
    let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
    let ct = NoOpCommandTermination;

    let oper_val = make_oper_value(true, 1, false);
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

    assert!(
        matches!(result, ServiceResult::Failure(_)),
        "a status-only object must refuse Operate"
    );
}
