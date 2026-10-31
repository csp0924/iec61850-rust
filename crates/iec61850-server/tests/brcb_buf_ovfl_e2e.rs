//! BufOvfl of a buffered report control block that is enabled again.
//!
//! IEC 61850-7-2 §17.2.3.2.2.8: the report handler sets `BufOvfl = TRUE` in
//! the first report it sends after the transition from disabled to enabled,
//! and `FALSE` in the reports after it. A client of this crate drives the
//! server over TCP and decodes the reports itself.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use iec61850_client::mms_compat::mms_data_to_mms_value;
use iec61850_client::report::parse::{parse_report, ParsedReport};
use iec61850_mms::mms::client::{MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::common::ObjectName;
use iec61850_mms::mms::pdu::information_report::{decode_information_report, VariableAccessSpec};
use iec61850_mms::mms::MmsData;
use iec61850_model::{
    cdc, DataAttribute, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue,
    NodeRef, ObjectRef,
};
use iec61850_server::reporting::{Brcb, BufferedReportControl};
use iec61850_server::{Dataset, DatasetEntry, IedServer, OptFlds, TriggerOptions};

const DOM: &str = "IED1LD0";
const RPT_ENA: &str = "LLN0$BR$brcbA$RptEna";

/// A server whose BRCB reports `GGIO1.Ind1.stVal` on a data change, with
/// BufOvfl and EntryID among its option fields and no buffer time.
fn server() -> IedServer {
    let ggio = LogicalNodeBuilder::new("", "GGIO", "1")
        .add_do(cdc::sps("Ind1", cdc::CdcOptions::NONE))
        .build()
        .unwrap();
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(LogicalNodeBuilder::lln0().build().unwrap())
        .add_ln(ggio)
        .build()
        .unwrap();
    let model = IedModelBuilder::new("IED1")
        .add_ld(ld)
        .unwrap()
        .build()
        .unwrap();
    let server = IedServer::builder()
        .model(model.into())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()
        .expect("server build");
    let m = server.model();
    let mut ds = Dataset::new("LLN0$dsA");
    ds.push(DatasetEntry::from_model(&m, DOM, "GGIO1$ST$Ind1$stVal").unwrap());
    let brcb = Brcb::new("brcbA", "LLN0$dsA")
        .with_trg_ops(TriggerOptions::DATA_CHANGED)
        .with_opt_flds(OptFlds::SEQ_NUM | OptFlds::BUFFER_OVERFLOW | OptFlds::ENTRY_ID);
    server
        .register_brcb(
            BufferedReportControl::new(format!("{DOM}/LLN0$BR$brcbA"), brcb),
            ds,
        )
        .expect("register_brcb");
    server
}

fn st_val(server: &IedServer) -> DataAttribute {
    let model = server.model();
    let r = ObjectRef::parse_iec(&format!("{DOM}/GGIO1.Ind1.stVal")).unwrap();
    match model.node_by_object_ref(&r).expect("node") {
        NodeRef::Da(da) => DataAttribute::with_shared_value(
            da.name.clone(),
            da.fc,
            da.ty,
            da.trg_ops,
            std::sync::Arc::clone(&da.value),
        ),
        _ => panic!("stVal is a data attribute"),
    }
}

/// Receives the next report; fails after four seconds.
async fn next_report(mms: &mut MmsClient) -> ParsedReport {
    let deadline = Instant::now() + Duration::from_secs(4);
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
        let report = decode_information_report(&inner).expect("decode information report");
        if !matches!(
            &report.variable_access_spec,
            VariableAccessSpec::VariableListName(ObjectName::VmdSpecific(s)) if s == "RPT"
        ) {
            continue;
        }
        let elements: Vec<MmsValue> = report
            .list_of_access_result
            .iter()
            .map(mms_data_to_mms_value)
            .collect();
        return parse_report(&MmsValue::Array(elements)).expect("parse report");
    }
}

async fn set_rpt_ena(mms: &mut MmsClient, on: bool) {
    mms.write(DOM, RPT_ENA, MmsData::Boolean(on))
        .await
        .unwrap_or_else(|e| panic!("RptEna={on}: {e:?}"));
}

/// Each enable, the first one and one after a disable alike, makes the first
/// report sent afterwards carry `BufOvfl = TRUE` and the next one `FALSE`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_report_after_each_enable_indicates_an_overflow() {
    let server = server();
    let st_val = st_val(&server);
    let handle = server.start().await.unwrap();
    let mut mms = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    mms.connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");

    let mut value = false;
    let mut change = |server: &IedServer| {
        value = !value;
        server.update_boolean(&st_val, value).unwrap();
    };
    for round in 0..2 {
        set_rpt_ena(&mut mms, true).await;
        change(&server);
        let first = next_report(&mut mms).await;
        assert_eq!(first.buf_ovfl, Some(true), "round {round}: first report");
        change(&server);
        let second = next_report(&mut mms).await;
        assert_eq!(second.buf_ovfl, Some(false), "round {round}: second report");
        set_rpt_ena(&mut mms, false).await;
    }
    handle.stop().await;
}
