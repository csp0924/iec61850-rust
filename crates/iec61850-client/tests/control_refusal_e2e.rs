//! End-to-end tests of how a control command concludes when the server refuses
//! it, times out or loses the connection, over real TCP and the full ISO stack.
//!
//! The peer is a scripted server assembled from the ISO and MMS building blocks
//! of `iec61850-mms`. Per IEC 61850-8-1 it answers a refused Select,
//! SelectWithValue, Operate or Cancel with an InformationReport carrying only
//! `LastApplError`, followed by the negative response, and sends no command
//! termination for it. The data object named in a request selects the script,
//! so every case is deterministic.

mod support;

use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use iec61850_client::control::{
    ControlAddCause, ControlLastApplError, ControlObjectClient, ControlOutcome, OriginValue,
};
use iec61850_client::{ClientError, IedConnection};
use iec61850_mms::mms::pdu::information_report::{
    encode_command_termination_negative, encode_command_termination_positive,
    encode_information_report, encode_last_appl_error_struct, LastApplErrorRef, OriginRef,
};
use iec61850_mms::mms::pdu::reject::{ConfirmedRequestRejectReason, RejectReason};
use iec61850_mms::mms::server::encode_reject_pdu;
use iec61850_mms::{
    decode_confirmed_read_request, decode_confirmed_write_request, encode_confirmed_error_pdu,
    encode_confirmed_read_response, encode_confirmed_write_response, AccessResult, DataAccessError,
    ErrorClass, MmsClientBuilder, MmsData, ObjectName, ReadResponse, ServiceError, WriteOutcome,
    WriteResponse,
};
use iec61850_model::{ControlModel, MmsValue};
use support::{single_item, Plan};

const DOMAIN: &str = "IED1LD0";
const LN: &str = "GGIO1";

// Scripts, chosen by the data object a request names.

/// Answers a Write or a Read of a control attribute; `seq` counts the
/// requests on the association.
fn script(mms: &[u8], seq: u32) -> Option<Plan> {
    if let Ok((invoke_id, req)) = decode_confirmed_write_request(mms) {
        let item = single_item(&req.variable_access_spec)?;
        let value = req.list_of_data.first()?;
        return Some(script_write(invoke_id, &item, value, seq));
    }
    if let Ok((invoke_id, req)) = decode_confirmed_read_request(mms) {
        let item = single_item(&req.variable_access_spec)?;
        return Some(script_read(invoke_id, &item, seq));
    }
    None
}

async fn start_server() -> u16 {
    support::start(Arc::new(script)).await
}

/// Splits `GGIO1$CO$<DO>$<attribute>` into the data object and the attribute.
fn split_item(item: &str) -> (String, String) {
    let rest = item.strip_prefix(&format!("{LN}$CO$")).unwrap_or_default();
    match rest.split_once('$') {
        Some((dobj, attr)) => (dobj.to_string(), attr.to_string()),
        None => (rest.to_string(), String::new()),
    }
}

/// Returns an Oper structure with ctlNum replaced.
fn with_ctl_num(value: &MmsData, ctl_num: u8) -> MmsData {
    match value {
        MmsData::Structure(items) if items.len() >= 4 => {
            let mut items = items.clone();
            let idx = items.len() - 4;
            items[idx] = MmsData::Unsigned(u64::from(ctl_num));
            MmsData::Structure(items)
        }
        other => other.clone(),
    }
}

/// Reads ctlNum and origin from an Oper, SBOw or Cancel structure.
///
/// Oper and SBOw end with origin, ctlNum, T, Test and Check; Cancel ends with
/// origin, ctlNum, T and Test.
fn command_of(value: &MmsData, attr: &str) -> (u8, OriginRef) {
    let tail = if attr == "Cancel" { 3 } else { 4 };
    let MmsData::Structure(items) = value else {
        return (0, OriginRef::default());
    };
    let Some(idx) = items.len().checked_sub(tail) else {
        return (0, OriginRef::default());
    };
    let ctl_num = match &items[idx] {
        MmsData::Unsigned(n) => *n as u8,
        _ => 0,
    };
    let origin = match idx.checked_sub(1).map(|i| &items[i]) {
        Some(MmsData::Structure(fields)) => match fields.as_slice() {
            [MmsData::Integer(or_cat), MmsData::OctetString(or_ident)] => OriginRef {
                or_cat: *or_cat as i32,
                or_ident: or_ident.clone(),
            },
            _ => OriginRef::default(),
        },
        _ => OriginRef::default(),
    };
    (ctl_num, origin)
}

fn encoded(value: &MmsData) -> Bytes {
    let mut buf = BytesMut::new();
    value.encode(&mut buf);
    buf.freeze()
}

fn last_appl_error_ref(
    ctl_obj: &str,
    origin: &OriginRef,
    ctl_num: u8,
    add_cause: i32,
) -> LastApplErrorRef {
    LastApplErrorRef {
        ctl_obj: ctl_obj.to_string(),
        error: 0,
        origin: origin.clone(),
        ctl_num,
        add_cause,
    }
}

/// An InformationReport carrying only `LastApplError`.
fn last_appl_error_report(ctl_obj: &str, origin: &OriginRef, ctl_num: u8, add_cause: i32) -> Bytes {
    let e = last_appl_error_ref(ctl_obj, origin, ctl_num, add_cause);
    encode_information_report(&[(
        ObjectName::VmdSpecific("LastApplError".to_string()),
        encode_last_appl_error_struct(&e),
    )])
}

fn ct_positive(dobj: &str, oper: &MmsData) -> Bytes {
    encode_command_termination_positive(DOMAIN, &format!("{LN}$CO${dobj}$Oper"), encoded(oper))
}

fn ct_negative(dobj: &str, oper: &MmsData, add_cause: i32) -> Bytes {
    let item = format!("{LN}$CO${dobj}$Oper");
    let (ctl_num, origin) = command_of(oper, "Oper");
    let e = last_appl_error_ref(&format!("{DOMAIN}/{item}"), &origin, ctl_num, add_cause);
    encode_command_termination_negative(&e, DOMAIN, &item, encoded(oper))
}

fn write_response(invoke_id: u32, outcome: WriteOutcome) -> Bytes {
    let mut buf = BytesMut::new();
    encode_confirmed_write_response(
        invoke_id,
        &WriteResponse {
            outcomes: vec![outcome],
        },
        &mut buf,
    );
    buf.freeze()
}

fn write_refused(invoke_id: u32) -> Bytes {
    write_response(
        invoke_id,
        WriteOutcome::Failure(DataAccessError::ObjectAccessDenied),
    )
}

/// The scripts of a Write, chosen by the data object it names.
fn script_write(invoke_id: u32, item: &str, value: &MmsData, seq: u32) -> Plan {
    let (dobj, attr) = split_item(item);
    let ctl_obj = format!("{DOMAIN}/{item}");
    let (ctl_num, origin) = command_of(value, &attr);
    // A LastApplError carrying the origin of the command.
    let lae = |ctl_obj: &str, ctl_num: u8, add_cause: i32| {
        last_appl_error_report(ctl_obj, &origin, ctl_num, add_cause)
    };
    match dobj.as_str() {
        // Refused with BlockedByInterlocking.
        "SPCREFUSE" => Plan {
            before: vec![lae(&ctl_obj, ctl_num, 10)],
            reply: Some(write_refused(invoke_id)),
            ..Plan::default()
        },
        // Refused with a confirmed error and ObjectNotSelected.
        "SPCCONFERR" => {
            let mut buf = BytesMut::new();
            encode_confirmed_error_pdu(
                invoke_id,
                &ServiceError {
                    error_class: ErrorClass::Access(3),
                    additional_code: None,
                    additional_description: None,
                },
                &mut buf,
            );
            Plan {
                before: vec![lae(&ctl_obj, ctl_num, 18)],
                reply: Some(buf.freeze()),
                ..Plan::default()
            }
        }
        // Refused, with the LastApplError naming a different object.
        "SPCOTHERLAE" => Plan {
            before: vec![lae(&format!("{DOMAIN}/{LN}$CO$SPCELSE$Oper"), ctl_num, 19)],
            reply: Some(write_refused(invoke_id)),
            ..Plan::default()
        },
        // Refused, with the LastApplError naming the same object in another
        // logical device.
        "SPCOTHERLD" => Plan {
            before: vec![lae(
                &format!("OTHERLD/{LN}$CO$SPCOTHERLD$Oper"),
                ctl_num,
                19,
            )],
            reply: Some(write_refused(invoke_id)),
            ..Plan::default()
        },
        // Refused, with the LastApplError carrying another originator.
        "SPCOTHERORIGIN" => Plan {
            before: vec![last_appl_error_report(
                &ctl_obj,
                &OriginRef {
                    or_cat: 1,
                    or_ident: b"someone else".to_vec(),
                },
                ctl_num,
                19,
            )],
            reply: Some(write_refused(invoke_id)),
            ..Plan::default()
        },
        // The first command is left unanswered. The next one is refused with
        // no LastApplError of its own, the late one of the first command
        // arriving ahead of the response.
        "SPCLATELAE" if seq == 1 => Plan::default(),
        "SPCLATELAE" => Plan {
            before: vec![lae(&ctl_obj, ctl_num.wrapping_sub(1), 10)],
            reply: Some(write_refused(invoke_id)),
            ..Plan::default()
        },
        // Refused with BlockedByInterlocking, an empty InformationReport
        // preceding the LastApplError.
        "SPCEMPTYIR" => Plan {
            before: vec![
                Bytes::from_static(&[0xa3, 0x00]),
                lae(&ctl_obj, ctl_num, 10),
            ],
            reply: Some(write_refused(invoke_id)),
            ..Plan::default()
        },
        // Refused with BlockedByInterlocking and a stray CT- with
        // InconsistentParameters after the response; accepted afterwards.
        "SPCSTRAYCT" if seq == 1 => Plan {
            before: vec![lae(&ctl_obj, ctl_num, 10)],
            reply: Some(write_refused(invoke_id)),
            after: vec![ct_negative("SPCSTRAYCT", value, 26)],
            ..Plan::default()
        },
        "SPCSTRAYCT" => Plan {
            reply: Some(write_response(invoke_id, WriteOutcome::Success)),
            after: vec![ct_positive("SPCSTRAYCT", value)],
            ..Plan::default()
        },
        // Accepted; a CT+ of another object precedes this object's CT- with
        // BlockedByProcess.
        "SPCOTHERCT" => Plan {
            reply: Some(write_response(invoke_id, WriteOutcome::Success)),
            after: vec![
                ct_positive("SPCELSE", value),
                ct_negative("SPCOTHERCT", value, 9),
            ],
            ..Plan::default()
        },
        // Accepted; a CT- of the previous ctlNum with TimeLimitOver precedes
        // this command's CT+.
        "SPCLATECT" => Plan {
            reply: Some(write_response(invoke_id, WriteOutcome::Success)),
            after: vec![
                ct_negative(
                    "SPCLATECT",
                    &with_ctl_num(value, ctl_num.wrapping_sub(1)),
                    16,
                ),
                ct_positive("SPCLATECT", value),
            ],
            ..Plan::default()
        },
        // Accepted, with a CT+ for an enhanced model.
        "SPCACCEPT" => Plan {
            reply: Some(write_response(invoke_id, WriteOutcome::Success)),
            after: vec![ct_positive("SPCACCEPT", value)],
            ..Plan::default()
        },
        // Answered with a Reject PDU.
        "SPCREJECT" => Plan::reply(encode_reject_pdu(
            Some(invoke_id),
            RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::InvalidArgument),
        )),
        // Left unanswered.
        "SPCSILENT" => Plan::default(),
        // The connection is closed instead of answering.
        "SPCDROP" => Plan {
            close: true,
            ..Plan::default()
        },
        _ => Plan {
            reply: Some(write_response(
                invoke_id,
                WriteOutcome::Failure(DataAccessError::ObjectNonExistent),
            )),
            ..Plan::default()
        },
    }
}

/// The scripts of a Read of `SBO`, chosen by the data object it names.
fn script_read(invoke_id: u32, item: &str, seq: u32) -> Plan {
    let (dobj, _) = split_item(item);
    let (before, answer) = match dobj.as_str() {
        // Denied with ObjectAlreadySelected; for SPCSELFLIP only the first time.
        "SPCSELDENY" => (
            vec![last_appl_error_report(
                &format!("{DOMAIN}/{item}"),
                &OriginRef::default(),
                0,
                19,
            )],
            String::new(),
        ),
        "SPCSELFLIP" if seq == 1 => (
            vec![last_appl_error_report(
                &format!("{DOMAIN}/{item}"),
                &OriginRef::default(),
                0,
                19,
            )],
            String::new(),
        ),
        _ => (Vec::new(), format!("{DOMAIN}/{LN}$CO${dobj}")),
    };
    let mut buf = BytesMut::new();
    encode_confirmed_read_response(
        invoke_id,
        &ReadResponse {
            variable_access_spec: None,
            list_of_access_result: vec![AccessResult::Success(MmsData::VisibleString(answer))],
        },
        &mut buf,
    );
    Plan {
        before,
        reply: Some(buf.freeze()),
        ..Plan::default()
    }
}

// Client fixture.

async fn connect(port: u16, request_timeout_ms: u64) -> IedConnection {
    let mms = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(request_timeout_ms)
        .build();
    let conn = IedConnection::with_mms_client(mms);
    conn.connect("127.0.0.1", port).await.expect("connect");
    conn
}

fn handle(conn: &IedConnection, dobj: &str, ctl_model: ControlModel) -> ControlObjectClient {
    conn.create_control_object(&format!("{DOMAIN}/{LN}.{dobj}"), ctl_model)
        .expect("create_control_object")
}

// A refused command reports the AddCause of the LastApplError ahead of the
// negative response.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_normal_operate_reports_the_last_appl_error_cause() {
    let conn = connect(start_server().await, 3_000).await;
    let mut spc = handle(&conn, "SPCREFUSE", ControlModel::DirectNormal);
    let origin = OriginValue {
        or_cat: 2,
        or_ident: b"operator 1".to_vec(),
    };
    spc.set_origin(origin.clone());
    let outcome = spc.operate(MmsValue::Boolean(true)).await.expect("operate");
    assert_eq!(
        outcome,
        ControlOutcome::Failure(ControlAddCause::BlockedByInterlocking)
    );
    let e = spc.last_appl_error().expect("last appl error");
    assert_eq!(e.ctl_obj, format!("{DOMAIN}/{LN}$CO$SPCREFUSE$Oper"));
    assert_eq!(e.error, ControlLastApplError::NoError);
    assert_eq!(e.origin, origin);
    assert_eq!(e.ctl_num, 1);
    assert_eq!(e.add_cause, ControlAddCause::BlockedByInterlocking);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_operate_with_a_confirmed_error_reports_the_last_appl_error_cause() {
    let conn = connect(start_server().await, 3_000).await;
    let spc = handle(&conn, "SPCCONFERR", ControlModel::SboNormal);
    let outcome = spc.operate(MmsValue::Boolean(true)).await.expect("operate");
    assert_eq!(
        outcome,
        ControlOutcome::Failure(ControlAddCause::ObjectNotSelected)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_select_with_value_reports_the_last_appl_error_cause() {
    let conn = connect(start_server().await, 3_000).await;
    let spc = handle(&conn, "SPCREFUSE", ControlModel::SboEnhanced);
    let outcome = spc
        .select_with_value(MmsValue::Boolean(true))
        .await
        .expect("select_with_value");
    assert_eq!(
        outcome,
        ControlOutcome::Failure(ControlAddCause::BlockedByInterlocking)
    );
    let e = spc.last_appl_error().expect("last appl error");
    assert_eq!(e.ctl_obj, format!("{DOMAIN}/{LN}$CO$SPCREFUSE$SBOw"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_cancel_reports_the_last_appl_error_cause() {
    let conn = connect(start_server().await, 3_000).await;
    let spc = handle(&conn, "SPCREFUSE", ControlModel::SboNormal);
    let outcome = spc.cancel(MmsValue::Boolean(true)).await.expect("cancel");
    assert_eq!(
        outcome,
        ControlOutcome::Failure(ControlAddCause::BlockedByInterlocking)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn denied_select_keeps_the_last_appl_error() {
    let conn = connect(start_server().await, 3_000).await;
    let spc = handle(&conn, "SPCSELDENY", ControlModel::SboNormal);
    assert!(!spc.select().await.expect("select"));
    let e = spc.last_appl_error().expect("last appl error");
    assert_eq!(e.add_cause, ControlAddCause::ObjectAlreadySelected);

    let granted = handle(&conn, "SPCSELOK", ControlModel::SboNormal);
    assert!(granted.select().await.expect("select"));
    assert_eq!(granted.last_appl_error(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn last_appl_error_of_another_object_is_not_taken() {
    let conn = connect(start_server().await, 3_000).await;
    let spc = handle(&conn, "SPCOTHERLAE", ControlModel::DirectNormal);
    let outcome = spc.operate(MmsValue::Boolean(true)).await.expect("operate");
    assert_eq!(outcome, ControlOutcome::Failure(ControlAddCause::Unknown));
    assert_eq!(spc.last_appl_error(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn last_appl_error_of_another_logical_device_is_not_taken() {
    let conn = connect(start_server().await, 3_000).await;
    let spc = handle(&conn, "SPCOTHERLD", ControlModel::DirectNormal);
    let outcome = spc.operate(MmsValue::Boolean(true)).await.expect("operate");
    assert_eq!(outcome, ControlOutcome::Failure(ControlAddCause::Unknown));
    assert_eq!(spc.last_appl_error(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn last_appl_error_of_another_originator_is_not_taken() {
    let conn = connect(start_server().await, 3_000).await;
    let spc = handle(&conn, "SPCOTHERORIGIN", ControlModel::DirectNormal);
    let outcome = spc.operate(MmsValue::Boolean(true)).await.expect("operate");
    assert_eq!(outcome, ControlOutcome::Failure(ControlAddCause::Unknown));
    assert_eq!(spc.last_appl_error(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_last_appl_error_of_an_earlier_command_is_not_taken() {
    let conn = connect(start_server().await, 300).await;
    let spc = handle(&conn, "SPCLATELAE", ControlModel::DirectNormal);
    let first = spc.operate(MmsValue::Boolean(true)).await;
    assert!(matches!(first, Err(ClientError::Mms(_))), "got {first:?}");
    // The LastApplError ahead of this response carries the previous ctlNum.
    let outcome = spc.operate(MmsValue::Boolean(true)).await.expect("operate");
    assert_eq!(outcome, ControlOutcome::Failure(ControlAddCause::Unknown));
    assert_eq!(spc.last_appl_error(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_information_report_does_not_hide_the_last_appl_error() {
    let conn = connect(start_server().await, 3_000).await;
    let spc = handle(&conn, "SPCEMPTYIR", ControlModel::DirectNormal);
    let outcome = spc.operate(MmsValue::Boolean(true)).await.expect("operate");
    assert_eq!(
        outcome,
        ControlOutcome::Failure(ControlAddCause::BlockedByInterlocking)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_command_clears_the_previous_last_appl_error() {
    // Each object is refused the first time and accepted afterwards.
    let conn = connect(start_server().await, 3_000).await;
    let spc = handle(&conn, "SPCSTRAYCT", ControlModel::SboEnhanced);
    let _ = spc.select_with_value(MmsValue::Boolean(true)).await;
    assert!(spc.last_appl_error().is_some());
    assert_eq!(
        spc.select_with_value(MmsValue::Boolean(true))
            .await
            .expect("select_with_value"),
        ControlOutcome::Success
    );
    assert_eq!(spc.last_appl_error(), None);

    let conn = connect(start_server().await, 3_000).await;
    let spc = handle(&conn, "SPCSTRAYCT", ControlModel::SboNormal);
    let _ = spc.cancel(MmsValue::Boolean(true)).await;
    assert!(spc.last_appl_error().is_some());
    assert_eq!(
        spc.cancel(MmsValue::Boolean(true)).await.expect("cancel"),
        ControlOutcome::Success
    );
    assert_eq!(spc.last_appl_error(), None);

    let conn = connect(start_server().await, 3_000).await;
    let spc = handle(&conn, "SPCSELFLIP", ControlModel::SboNormal);
    assert!(!spc.select().await.expect("select"));
    assert!(spc.last_appl_error().is_some());
    assert!(spc.select().await.expect("select"));
    assert_eq!(spc.last_appl_error(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_command_clears_the_previous_last_appl_error() {
    let conn = connect(start_server().await, 3_000).await;
    // Refused the first time, accepted afterwards.
    let spc = handle(&conn, "SPCSTRAYCT", ControlModel::DirectNormal);
    let _ = spc.operate(MmsValue::Boolean(true)).await.expect("operate");
    assert!(spc.last_appl_error().is_some());
    assert_eq!(
        spc.operate(MmsValue::Boolean(true)).await.expect("operate"),
        ControlOutcome::Success
    );
    assert_eq!(spc.last_appl_error(), None);
}

// A refused enhanced command concludes at the negative response.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_enhanced_operate_does_not_wait_for_a_command_termination() {
    let conn = connect(start_server().await, 3_000).await;
    let spc = handle(&conn, "SPCSTRAYCT", ControlModel::DirectEnhanced);
    // The CT- the server sends after the negative response is not this
    // command's conclusion: the cause comes from the LastApplError.
    let outcome = spc.operate(MmsValue::Boolean(true)).await.expect("operate");
    assert_eq!(
        outcome,
        ControlOutcome::Failure(ControlAddCause::BlockedByInterlocking)
    );
    // The stray CT- carries the previous ctlNum, so the next command's
    // termination is the CT+ that follows its own response.
    let outcome = spc.operate(MmsValue::Boolean(true)).await.expect("operate");
    assert_eq!(outcome, ControlOutcome::Success);
}

// An enhanced command concludes at its own command termination.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enhanced_operate_reports_a_negative_command_termination() {
    let conn = connect(start_server().await, 3_000).await;
    let spc = handle(&conn, "SPCOTHERCT", ControlModel::DirectEnhanced);
    let outcome = spc.operate(MmsValue::Boolean(true)).await.expect("operate");
    // The CT+ of another object ahead of it is not this command's.
    assert_eq!(
        outcome,
        ControlOutcome::Failure(ControlAddCause::BlockedByProcess)
    );
    let e = spc.last_appl_error().expect("last appl error");
    assert_eq!(e.add_cause, ControlAddCause::BlockedByProcess);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enhanced_operate_skips_a_late_termination_of_an_earlier_command() {
    let conn = connect(start_server().await, 3_000).await;
    let spc = handle(&conn, "SPCLATECT", ControlModel::DirectEnhanced);
    let outcome = spc.operate(MmsValue::Boolean(true)).await.expect("operate");
    assert_eq!(outcome, ControlOutcome::Success);
    assert_eq!(spc.last_appl_error(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepted_sbo_enhanced_flow_succeeds() {
    let conn = connect(start_server().await, 3_000).await;
    let spc = handle(&conn, "SPCACCEPT", ControlModel::SboEnhanced);
    assert_eq!(
        spc.select_with_value(MmsValue::Boolean(true))
            .await
            .expect("select_with_value"),
        ControlOutcome::Success
    );
    assert_eq!(
        spc.operate(MmsValue::Boolean(true)).await.expect("operate"),
        ControlOutcome::Success
    );
}

// Without an answer from the server the fate of a command is unknown, so the
// call fails instead of reporting a refusal.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unanswered_operate_is_an_error() {
    let conn = connect(start_server().await, 300).await;
    let spc = handle(&conn, "SPCSILENT", ControlModel::DirectNormal);
    let r = spc.operate(MmsValue::Boolean(true)).await;
    assert!(matches!(r, Err(ClientError::Mms(_))), "got {r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unanswered_cancel_is_an_error() {
    let conn = connect(start_server().await, 300).await;
    let spc = handle(&conn, "SPCSILENT", ControlModel::SboNormal);
    let r = spc.cancel(MmsValue::Boolean(true)).await;
    assert!(matches!(r, Err(ClientError::Mms(_))), "got {r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_operate_is_an_error() {
    let conn = connect(start_server().await, 3_000).await;
    let spc = handle(&conn, "SPCREJECT", ControlModel::DirectNormal);
    let r = spc.operate(MmsValue::Boolean(true)).await;
    assert!(matches!(r, Err(ClientError::Mms(_))), "got {r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn select_with_value_on_a_lost_connection_is_an_error() {
    let conn = connect(start_server().await, 3_000).await;
    let spc = handle(&conn, "SPCDROP", ControlModel::SboEnhanced);
    let r = spc.select_with_value(MmsValue::Boolean(true)).await;
    assert!(matches!(r, Err(ClientError::Mms(_))), "got {r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enhanced_operate_on_a_lost_connection_is_an_error() {
    let conn = connect(start_server().await, 3_000).await;
    let spc = handle(&conn, "SPCDROP", ControlModel::DirectEnhanced);
    let r = spc.operate(MmsValue::Boolean(true)).await;
    assert!(matches!(r, Err(ClientError::Mms(_))), "got {r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scripted_server_answers_within_the_request_timeout() {
    // Control for the timeout cases above: an answered command completes well
    // inside the same short request timeout.
    let conn = connect(start_server().await, 300).await;
    let spc = handle(&conn, "SPCACCEPT", ControlModel::DirectNormal);
    let r = spc.operate(MmsValue::Boolean(true)).await;
    assert_eq!(r.expect("operate"), ControlOutcome::Success);
}
