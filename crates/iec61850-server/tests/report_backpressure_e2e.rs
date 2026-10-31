//! A URCB whose client stops reading for a while.
//!
//! The test drives a started `IedServer` from a raw `MmsClient` over TCP and the
//! full ISO stack. While the client reads nothing, the server keeps producing
//! reports until its report channel to the association is full and reports are
//! dropped. The association is still there, so IEC 61850-7-2 §17.2.4.4 and
//! §17.2.4.5 keep the control block enabled and reserved, and reporting goes on
//! once the client reads again.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use iec61850_client::mms_compat::mms_data_to_mms_value;
use iec61850_client::report::parse::{parse_report, ParsedReport};
use iec61850_mms::mms::client::{MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::common::ObjectName;
use iec61850_mms::mms::pdu::information_report::{decode_information_report, VariableAccessSpec};
use iec61850_mms::mms::MmsData;
use iec61850_model::{
    DataAttribute, DataAttributeType, IedModel, IedModelBuilder, LogicalDeviceBuilder,
    LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::{
    Dataset, DatasetEntry, IedServer, OptFlds, Rcb, ReportControl, TriggerOptions,
};

const DOMAIN: &str = "IED1LD0";
const URCB_ITEM: &str = "LLN0$RP$urcbFlood";

fn build_model() -> Arc<IedModel> {
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(LogicalNodeBuilder::lln0().build().expect("lln0"))
        .build()
        .expect("ld");
    Arc::new(
        IedModelBuilder::new("IED1")
            .add_ld(ld)
            .expect("add_ld")
            .build()
            .expect("model"),
    )
}

/// Reference of the only data set member. Its length makes each report a few
/// kilobytes, so the transport and the report channel fill after a few
/// hundred reports.
fn member_ref() -> String {
    format!("{DOMAIN}/GGIO1$MX$AnIn1$mag$i_{}", "x".repeat(4_000))
}

fn dropped_socket_full(server: &IedServer) -> u64 {
    let engine = server.reporting_engine();
    let engine = engine.lock().expect("engine");
    let rc = engine
        .get_rcb(&format!("{DOMAIN}/{URCB_ITEM}"))
        .expect("urcb");
    let rc = rc.lock().expect("urcb lock");
    rc.metrics_snapshot().dropped_socket_full
}

/// RptEna of the URCB as the server holds it.
fn server_rpt_ena(server: &IedServer) -> bool {
    let engine = server.reporting_engine();
    let engine = engine.lock().expect("engine");
    let rc = engine
        .get_rcb(&format!("{DOMAIN}/{URCB_ITEM}"))
        .expect("urcb");
    let rc = rc.lock().expect("urcb lock");
    let enabled = rc.state.lock().expect("state").rpt_ena;
    enabled
}

async fn read_bool(mms: &mut MmsClient, item: &str) -> bool {
    match mms.read(DOMAIN, item).await.expect("read") {
        MmsData::Boolean(b) => b,
        other => panic!("{item}: BOOLEAN expected, got {other:?}"),
    }
}

async fn next_report(mms: &mut MmsClient) -> ParsedReport {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "no report arrived");
        let Some(inner) = mms
            .recv_unconfirmed_pdu_with_timeout(remaining)
            .await
            .expect("receive")
        else {
            continue;
        };
        let decoded = decode_information_report(&inner).expect("decode information report");
        let is_rpt = matches!(
            &decoded.variable_access_spec,
            VariableAccessSpec::VariableListName(ObjectName::VmdSpecific(s)) if s == "RPT"
        );
        if !is_rpt {
            continue;
        }
        let elements: Vec<MmsValue> = decoded
            .list_of_access_result
            .iter()
            .map(mms_data_to_mms_value)
            .collect();
        return parse_report(&MmsValue::Array(elements)).expect("parse report");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn urcb_stays_enabled_and_reserved_when_its_report_channel_fills() {
    let server = IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()
        .expect("server build");
    let member = DataAttribute::with_shared_value(
        "i",
        FC::Mx,
        DataAttributeType::Int32,
        TrgOps::DCHG,
        Arc::new(RwLock::new(MmsValue::Integer(0))),
    );
    let mut ds = Dataset::new("LLN0$dsFlood");
    ds.push(DatasetEntry::new(member_ref(), Arc::clone(&member.value)));
    let rcb = Rcb::new("urcbFlood", "LLN0$dsFlood")
        .with_trg_ops(TriggerOptions::DATA_CHANGED)
        .with_opt_flds(OptFlds::SEQ_NUM | OptFlds::DATA_REFERENCE);
    server
        .register_urcb(ReportControl::new(format!("{DOMAIN}/{URCB_ITEM}"), rcb), ds)
        .expect("register_urcb");
    let handle = server.start().await.expect("server start");

    let mut mms = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(10_000)
        .build();
    mms.connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    mms.write(DOMAIN, &format!("{URCB_ITEM}$Resv"), MmsData::Boolean(true))
        .await
        .expect("Resv");
    mms.write(
        DOMAIN,
        &format!("{URCB_ITEM}$RptEna"),
        MmsData::Boolean(true),
    )
    .await
    .expect("RptEna");

    // The client reads nothing while every update produces a report, until
    // the server has dropped 32 reports for a full channel, or has disabled
    // the URCB.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut value = 0;
    while dropped_socket_full(&server) < 32 && server_rpt_ena(&server) {
        assert!(Instant::now() < deadline, "the report channel never filled");
        value += 1;
        server.update_int32(&member, value).expect("update");
        tokio::task::yield_now().await;
    }

    // The client reads again: the control block is still enabled and
    // reserved for it.
    assert!(
        read_bool(&mut mms, &format!("{URCB_ITEM}$RptEna")).await,
        "RptEna stays TRUE"
    );
    assert!(
        read_bool(&mut mms, &format!("{URCB_ITEM}$Resv")).await,
        "Resv stays TRUE"
    );

    assert!(dropped_socket_full(&server) >= 32);

    // A later update is reported.
    server.update_int32(&member, -1).expect("update");
    loop {
        let r = next_report(&mut mms).await;
        if r.data_values == [MmsValue::Integer(-1)] {
            break;
        }
    }

    // The client still owns the control block.
    mms.write(
        DOMAIN,
        &format!("{URCB_ITEM}$RptEna"),
        MmsData::Boolean(false),
    )
    .await
    .expect("disabling succeeds for the owner");
}
