//! End-to-end test that enabling a URCB over the wire actually starts
//! reporting.
//!
//! The other report tests enable the control block by setting the server state
//! directly. Here the client writes `Resv = true` and `RptEna = true` through
//! `set_rcb_values`, so the request travels the dispatcher and the control
//! block service before a later value change produces a report.
//!
//! This guards the path the reporting example relies on: the example can still
//! compile while the wire path is broken, and a user would then see no reports.

use iec61850_client::rcb::{RcbHandle, RcbWriteMask};
use iec61850_client::report::{ClientReport, ReportCallback};
use iec61850_client::IedConnection;
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_model::{
    DataAttribute, DataAttributeType, IedModel, IedModelBuilder, LogicalDeviceBuilder,
    LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::{
    Dataset, DatasetEntry, IedServer, IedServerConfig, Rcb, ReportControl, TriggerOptions,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const RPT_MMS_PATH: &str = "IED1LD0/GGIO1$RP$urcb_wire";

fn build_model() -> Arc<IedModel> {
    let lln0 = LogicalNodeBuilder::lln0().build().unwrap();
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .build()
        .unwrap();
    Arc::new(
        IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap(),
    )
}

fn build_server() -> IedServer {
    IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig {
            max_mms_connections: 5,
            ..Default::default()
        })
        .build()
        .unwrap()
}

fn register_urcb(server: &IedServer) -> DataAttribute {
    let da = DataAttribute::new(
        "stVal",
        FC::St,
        DataAttributeType::Boolean,
        TrgOps::DCHG,
        MmsValue::Boolean(false),
    );
    let mut ds = Dataset::new("GGIO1$ds_wire");
    ds.push(DatasetEntry::new(
        "IED1LD0/GGIO1$ST$Ind1$stVal".to_string(),
        Arc::clone(&da.value),
    ));

    let rcb = Rcb::new("urcb_wire", "GGIO1$ds_wire")
        .with_rpt_id(RPT_MMS_PATH)
        .with_trg_ops(TriggerOptions::DATA_CHANGED)
        .with_buf_tm_ms(50);
    server
        .register_urcb(ReportControl::new(RPT_MMS_PATH, rcb), ds)
        .unwrap();
    da
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_set_rcb_values_enables_and_receives_report() {
    let server = build_server();
    let da = register_urcb(&server);
    let handle = server.start().await.unwrap();
    let port = handle.bound_addr.port();

    let mms = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    let conn = IedConnection::with_mms_client(mms);
    conn.connect("127.0.0.1", port).await.unwrap();

    let counter = Arc::new(AtomicUsize::new(0));
    let counter_for_cb = Arc::clone(&counter);
    let cb: ReportCallback = Arc::new(move |_snap: Arc<ClientReport>| {
        counter_for_cb.fetch_add(1, Ordering::SeqCst);
    });
    conn.install_report_handler(Some(RPT_MMS_PATH.to_string()), RPT_MMS_PATH, None, cb)
        .await
        .unwrap();

    // Enable over the wire: Resv first, then RptEna.
    let mut rcb = RcbHandle::new(RPT_MMS_PATH).unwrap();
    rcb.set_resv(true);
    rcb.set_rpt_ena(true);
    let mask = RcbWriteMask::RESV | RcbWriteMask::RPT_ENA;
    conn.set_rcb_values(&rcb, mask, false)
        .await
        .expect("set_rcb_values should enable the control block");

    // Run the background dispatcher to receive the reports.
    let dispatcher = conn.spawn_report_dispatcher(Duration::from_millis(50));

    // Change the value.
    server.update_boolean(&da, true).unwrap();

    // Wait up to four seconds, which covers the buffer time and the dispatch.
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    while std::time::Instant::now() < deadline && counter.load(Ordering::SeqCst) == 0 {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        counter.load(Ordering::SeqCst) >= 1,
        "no report arrived after enabling over the wire, so set_rcb_values did not reach the control block"
    );

    // A second change reports as well.
    server.update_boolean(&da, false).unwrap();
    let deadline2 = std::time::Instant::now() + Duration::from_secs(4);
    while std::time::Instant::now() < deadline2 && counter.load(Ordering::SeqCst) < 2 {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        counter.load(Ordering::SeqCst) >= 2,
        "the second change produced no report (counter={})",
        counter.load(Ordering::SeqCst)
    );

    let _ = conn.disconnect().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), dispatcher).await;
    handle.stop().await;
}
