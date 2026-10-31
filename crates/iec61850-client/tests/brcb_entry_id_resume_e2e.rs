//! End-to-end resynchronization of a BRCB through `set_rcb_values`.
//!
//! A client receives buffered reports, loses its association, and on a new
//! association writes back the EntryID of an entry it received together with
//! `RptEna`. The server must resume after that entry, so the client receives
//! the later entries again, including the one buffered while it was away. The
//! client and the server run over real TCP and the full ISO stack.

use iec61850_client::rcb::RcbWriteMask;
use iec61850_client::report::{ClientReport, ReportCallback};
use iec61850_client::IedConnection;
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_model::{
    cdc, DataAttribute, IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder,
    MmsValue, NodeRef, ObjectRef,
};
use iec61850_server::reporting::{Brcb, BufferedReportControl};
use iec61850_server::{Dataset, DatasetEntry, IedServer, OptFlds, ServerHandle, TriggerOptions};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const ST_VAL_REF: &str = "IED1LD0/CSWI1$ST$Pos$stVal";
const BRCB_PATH: &str = "IED1LD0/LLN0$BR$brcbPos";

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

/// The `stVal` a Dbpos of `n` reads as.
fn dbpos(n: u8) -> MmsValue {
    MmsValue::BitString {
        padding: 6,
        data: vec![n << 6],
    }
}

struct Fixture {
    server: IedServer,
    handle: ServerHandle,
    st_val: DataAttribute,
}

async fn start() -> Fixture {
    let server = IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()
        .expect("server build");
    let model = server.model();
    let st_val = resolve_da(&model, "IED1LD0/CSWI1.Pos.stVal");
    let mut ds = Dataset::new("LLN0$dsPos");
    ds.push(DatasetEntry::new(ST_VAL_REF, Arc::clone(&st_val.value)));
    let brcb = Brcb::new("brcbPos", "LLN0$dsPos")
        .with_trg_ops(TriggerOptions::DATA_CHANGED)
        .with_opt_flds(OptFlds::SEQ_NUM | OptFlds::ENTRY_ID | OptFlds::BUFFER_OVERFLOW);
    server
        .register_brcb(BufferedReportControl::new(BRCB_PATH, brcb), ds)
        .expect("register_brcb");
    let handle = server.start().await.expect("server start");
    Fixture {
        server,
        handle,
        st_val,
    }
}

/// The EntryID and first data value of each report a subscription received.
type Received = Arc<Mutex<Vec<(Vec<u8>, MmsValue)>>>;

impl Fixture {
    /// Connects a client with a report handler on the BRCB.
    async fn subscribe(&self) -> (IedConnection, Received) {
        let mms = MmsClientBuilder::new()
            .connect_timeout_ms(3_000)
            .request_timeout_ms(3_000)
            .build();
        let conn = IedConnection::with_mms_client(mms);
        conn.connect("127.0.0.1", self.handle.bound_addr.port())
            .await
            .expect("connect");
        let received: Received = Arc::default();
        let sink = Arc::clone(&received);
        let cb: ReportCallback = Arc::new(move |report: Arc<ClientReport>| {
            let entry_id = report
                .entry_id
                .clone()
                .expect("a BRCB report carries EntryID");
            let value = report
                .data_set_values
                .first()
                .cloned()
                .flatten()
                .expect("the report carries the member");
            sink.lock().unwrap().push((entry_id, value));
        });
        conn.install_report_handler(Some(BRCB_PATH.to_string()), BRCB_PATH, None, cb)
            .await
            .expect("install_report_handler");
        (conn, received)
    }

    fn set_st_val(&self, n: u32) {
        self.server
            .update_bit_string_from_int(&self.st_val, n)
            .expect("update stVal");
    }

    async fn wait_for_no_connection(&self) {
        let deadline = Instant::now() + Duration::from_secs(4);
        while self.server.connection_count() > 0 {
            assert!(
                Instant::now() < deadline,
                "the association was not released"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

/// Polls until `count` reports have been received; fails after four seconds.
async fn wait_for_reports(
    conn: &IedConnection,
    received: &Received,
    count: usize,
) -> Vec<(Vec<u8>, MmsValue)> {
    let deadline = Instant::now() + Duration::from_secs(4);
    while received.lock().unwrap().len() < count {
        assert!(
            Instant::now() < deadline,
            "expected {count} reports, received {:?}",
            received.lock().unwrap()
        );
        conn.poll_reports(Duration::from_millis(50))
            .await
            .expect("poll_reports");
    }
    received.lock().unwrap().clone()
}

/// A client that writes back an EntryID it received, with `RptEna`, receives
/// every entry after it on its new association.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brcb_resumes_after_the_entry_id_the_client_writes() {
    let f = start().await;

    let (first, first_received) = f.subscribe().await;
    let mut rcb = first
        .get_rcb_values(BRCB_PATH)
        .await
        .expect("get_rcb_values");
    rcb.set_rpt_ena(true);
    first
        .set_rcb_values(&rcb, RcbWriteMask::RPT_ENA, false)
        .await
        .expect("enable the brcb");
    f.set_st_val(2);
    f.set_st_val(1);
    let before = wait_for_reports(&first, &first_received, 2).await;
    assert_eq!(before[0].1, dbpos(2));
    assert_eq!(before[1].1, dbpos(1));

    first.disconnect().await.expect("disconnect");
    f.wait_for_no_connection().await;
    f.set_st_val(2);

    let (second, second_received) = f.subscribe().await;
    let mut rcb = second
        .get_rcb_values(BRCB_PATH)
        .await
        .expect("get_rcb_values");
    assert!(!rcb.rpt_ena(), "the brcb was disabled with the association");
    rcb.set_entry_id(Some(before[0].0.clone()))
        .expect("set_entry_id");
    rcb.set_rpt_ena(true);
    second
        .set_rcb_values(&rcb, RcbWriteMask::ENTRY_ID | RcbWriteMask::RPT_ENA, false)
        .await
        .expect("write EntryID and enable the brcb");

    let after = wait_for_reports(&second, &second_received, 2).await;
    assert_eq!(after[0], before[1], "the entry after the written EntryID");
    assert_eq!(after[1].1, dbpos(2), "the entry buffered while away");
    assert!(after[1].0 > before[1].0, "entry ids increase");

    second.disconnect().await.expect("disconnect");
    f.handle.stop().await;
}
