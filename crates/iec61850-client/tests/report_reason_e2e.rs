//! End-to-end test of the reasons a report subscription exposes.
//!
//! A URCB reports a data set of `Pos.stVal` (`dchg`) and `Pos.q` (`qchg`). A
//! `stVal` change is reported first, then a `q` change alone. The second
//! report carries only `q`, so the subscription state keeps the previous
//! `stVal` value but gives `stVal` no reason for inclusion.

use iec61850_client::rcb::{RcbHandle, RcbWriteMask};
use iec61850_client::report::{ClientReport, ReasonForInclusion, ReportCallback};
use iec61850_client::IedConnection;
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_model::{
    cdc, DataAttribute, IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder,
    MmsValue, NodeRef, ObjectRef,
};
use iec61850_server::{
    Dataset, DatasetEntry, IedServer, OptFlds, Rcb, ReportControl, TriggerOptions,
};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const RCB_PATH: &str = "IED1LD0/LLN0$RP$urcbPos";

fn build_model() -> Arc<IedModel> {
    let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
    let cswi = LogicalNodeBuilder::new("", "CSWI", "1")
        .add_do(cdc::dps("Pos", cdc::CdcOptions::NONE))
        .build()
        .expect("cswi");
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .add_ln(cswi)
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

fn resolve_da(model: &IedModel, path: &str) -> DataAttribute {
    let r = ObjectRef::parse_iec(path).expect("parse_iec");
    match model.node_by_object_ref(&r).expect("node lookup") {
        NodeRef::Da(da) => DataAttribute {
            name: da.name.clone(),
            fc: da.fc,
            ty: da.ty,
            trg_ops: da.trg_ops,
            value: Arc::clone(&da.value),
            children: Vec::new(),
        },
        _ => panic!("expected a data attribute at {path}"),
    }
}

/// Polls until the handler has seen `count` reports; fails after four seconds.
async fn wait_for_reports(
    conn: &IedConnection,
    seen: &Mutex<Vec<Arc<ClientReport>>>,
    count: usize,
) -> Arc<ClientReport> {
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        conn.poll_reports(Duration::from_millis(200))
            .await
            .expect("poll reports");
        let seen = seen.lock().unwrap();
        if seen.len() >= count {
            return Arc::clone(&seen[count - 1]);
        }
    }
    panic!("report {count} did not arrive");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn member_omitted_from_a_report_has_no_reason() {
    let server = IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()
        .expect("server build");
    let model = server.model();
    let st_val = resolve_da(&model, "IED1LD0/CSWI1.Pos.stVal");
    let q = resolve_da(&model, "IED1LD0/CSWI1.Pos.q");
    let mut ds = Dataset::new("LLN0$dsPos");
    ds.push(DatasetEntry::new(
        "IED1LD0/CSWI1$ST$Pos$stVal",
        Arc::clone(&st_val.value),
    ));
    ds.push(DatasetEntry::new(
        "IED1LD0/CSWI1$ST$Pos$q",
        Arc::clone(&q.value),
    ));
    let rcb = Rcb::new("urcbPos", "LLN0$dsPos")
        .with_trg_ops(TriggerOptions::DATA_CHANGED | TriggerOptions::QUALITY_CHANGED)
        .with_opt_flds(
            OptFlds::SEQ_NUM | OptFlds::REASON | OptFlds::DATA_SET | OptFlds::DATA_REFERENCE,
        )
        .with_buf_tm_ms(10);
    server
        .register_urcb(ReportControl::new(RCB_PATH, rcb), ds)
        .expect("register_urcb");
    let handle = server.start().await.expect("server start");

    let mms = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    let conn = IedConnection::with_mms_client(mms);
    conn.connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    let seen: Arc<Mutex<Vec<Arc<ClientReport>>>> = Arc::default();
    let sink = Arc::clone(&seen);
    let cb: ReportCallback = Arc::new(move |snap: Arc<ClientReport>| {
        sink.lock().unwrap().push(snap);
    });
    conn.install_report_handler(Some(RCB_PATH.to_string()), RCB_PATH, None, cb)
        .await
        .expect("install handler");
    let mut rcb = RcbHandle::new(RCB_PATH).unwrap();
    rcb.set_resv(true);
    rcb.set_rpt_ena(true);
    conn.set_rcb_values(&rcb, RcbWriteMask::RESV | RcbWriteMask::RPT_ENA, false)
        .await
        .expect("enable the control block");

    let dbpos_on = MmsValue::BitString {
        padding: 6,
        data: vec![0x80],
    };
    server.update_bit_string_from_int(&st_val, 2).unwrap();
    let first = wait_for_reports(&conn, &seen, 1).await;
    assert_eq!(first.data_set_values[0], Some(dbpos_on.clone()));
    assert_eq!(first.reasons[0], ReasonForInclusion::DATA_CHANGE);
    assert_eq!(first.reasons[1], ReasonForInclusion::empty());

    server.update_bit_string(&q, &[0x60, 0x00], 3).unwrap();
    let second = wait_for_reports(&conn, &seen, 2).await;
    assert_eq!(second.reasons[1], ReasonForInclusion::QUALITY_CHANGE);
    assert_eq!(
        second.data_set_values[1],
        Some(MmsValue::BitString {
            padding: 3,
            data: vec![0x60, 0x00],
        })
    );
    // `stVal` keeps the value of the first report but is not part of this one.
    assert_eq!(second.data_set_values[0], Some(dbpos_on));
    assert_eq!(
        second.data_references[0].as_deref(),
        Some("IED1LD0/CSWI1$ST$Pos$stVal")
    );
    assert_eq!(second.reasons[0], ReasonForInclusion::empty());

    conn.disconnect().await.expect("disconnect");
}
