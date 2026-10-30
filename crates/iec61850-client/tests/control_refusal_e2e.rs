//! End-to-end tests of how a control command concludes when the server does
//! not answer it or the connection is lost, over real TCP and the full ISO
//! stack.
//!
//! The peer is a scripted server assembled from the ISO and MMS building blocks
//! of `iec61850-mms`. The data object named in a request selects the script,
//! so every case is deterministic.

mod support;

use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use iec61850_client::control::{ControlObjectClient, ControlOutcome};
use iec61850_client::{ClientError, IedConnection};
use iec61850_mms::mms::pdu::information_report::encode_command_termination_positive;
use iec61850_mms::mms::pdu::reject::{ConfirmedRequestRejectReason, RejectReason};
use iec61850_mms::mms::server::encode_reject_pdu;
use iec61850_mms::{
    decode_confirmed_write_request, encode_confirmed_write_response, DataAccessError,
    MmsClientBuilder, MmsData, WriteOutcome, WriteResponse,
};
use iec61850_model::{ControlModel, MmsValue};
use support::{single_item, Plan};

const DOMAIN: &str = "IED1LD0";
const LN: &str = "GGIO1";

// Scripts, chosen by the data object a request names.

/// Answers a Write of a control attribute.
fn script(mms: &[u8], _seq: u32) -> Option<Plan> {
    let (invoke_id, req) = decode_confirmed_write_request(mms).ok()?;
    let item = single_item(&req.variable_access_spec)?;
    let value = req.list_of_data.first()?;
    Some(script_write(invoke_id, &item, value))
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

fn encoded(value: &MmsData) -> Bytes {
    let mut buf = BytesMut::new();
    value.encode(&mut buf);
    buf.freeze()
}

fn ct_positive(dobj: &str, oper: &MmsData) -> Bytes {
    encode_command_termination_positive(DOMAIN, &format!("{LN}$CO${dobj}$Oper"), encoded(oper))
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

/// The scripts of a Write, chosen by the data object it names.
fn script_write(invoke_id: u32, item: &str, value: &MmsData) -> Plan {
    let (dobj, _) = split_item(item);
    match dobj.as_str() {
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
