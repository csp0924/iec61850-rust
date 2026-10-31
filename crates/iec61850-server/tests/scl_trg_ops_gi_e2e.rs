//! General interrogation of report control blocks whose SCL `<TrgOps>`
//! leaves the `gi` attribute out.
//!
//! IEC 61850-6 §9.3.8 defaults `gi` to true, so a block declared with
//! `<TrgOps dchg="true"/>` and registered with
//! `IedServer::register_from_model` serves a TrgOps that includes GI, and a
//! client that keeps it, enables the block and writes GI receives a general
//! interrogation report. `gi="false"` leaves GI out.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use iec61850_client::rcb::{RcbHandle, RcbWriteMask, TriggerOptions};
use iec61850_client::report::{ClientReport, ReasonForInclusion, ReportCallback};
use iec61850_client::IedConnection;
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_model::IedModel;
use iec61850_server::{FromModelSummary, IedServer, IedServerConfig, ServerHandle};

const DOMAIN: &str = "GiLD0";

const GI_SCL: &str = r#"<SCL>
  <IED name="Gi">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <DataSet name="Events">
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind2" daName="stVal" fc="ST"/>
            </DataSet>
            <ReportControl name="urcbDchg" datSet="Events" rptID="UrcbDchg" indexed="false" confRev="1">
              <TrgOps dchg="true"/>
              <OptFields reasonCode="true"/>
            </ReportControl>
            <ReportControl name="brcbDchg" datSet="Events" rptID="BrcbDchg" buffered="true" indexed="false" confRev="1">
              <TrgOps dchg="true"/>
              <OptFields reasonCode="true"/>
            </ReportControl>
            <ReportControl name="urcbNoGi" datSet="Events" rptID="UrcbNoGi" indexed="false" confRev="1">
              <TrgOps dchg="true" gi="false"/>
              <OptFields reasonCode="true"/>
            </ReportControl>
          </LN0>
          <LN lnClass="GGIO" inst="1" lnType="GGIO_T"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="Mod" type="ENC_T"/></LNodeType>
    <LNodeType id="GGIO_T" lnClass="GGIO">
      <DO name="Ind1" type="SPS_T"/>
      <DO name="Ind2" type="SPS_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC"><DA name="stVal" fc="ST" bType="BOOLEAN"/></DOType>
    <DOType id="SPS_T" cdc="SPS">
      <DA name="stVal" fc="ST" bType="BOOLEAN" dchg="true"/>
      <DA name="q" fc="ST" bType="Quality" qchg="true"/>
    </DOType>
  </DataTypeTemplates>
</SCL>"#;

fn build_model() -> Arc<IedModel> {
    let raw = iec61850_scl::parse_scl(GI_SCL).expect("parse");
    Arc::new(
        raw.resolve()
            .expect("resolve")
            .build_model("Gi")
            .expect("build"),
    )
}

/// Builds the server from the model and registers what the model declares.
fn build_server() -> IedServer {
    let mut cfg = IedServerConfig::default();
    cfg.max_mms_connections = 2;
    let server = IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(cfg)
        .build()
        .expect("build server");
    let summary = server.register_from_model().expect("register_from_model");
    let mut expected = FromModelSummary::default();
    expected.data_sets = 1;
    expected.urcbs = 2;
    expected.brcbs = 1;
    assert_eq!(summary, expected);
    server
}

async fn connect(handle: &ServerHandle) -> IedConnection {
    let builder = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000);
    let conn = IedConnection::with_mms_client(builder.build());
    conn.connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    conn
}

/// The reports one handler received, in order.
#[derive(Clone, Default)]
struct Received(Arc<Mutex<Vec<Arc<ClientReport>>>>);

impl Received {
    fn callback(&self) -> ReportCallback {
        let sink = Arc::clone(&self.0);
        Arc::new(move |report: Arc<ClientReport>| sink.lock().unwrap().push(report))
    }

    /// Polls `conn` until a report has arrived and returns the first one;
    /// fails after ten seconds.
    async fn first(&self, conn: &IedConnection) -> Arc<ClientReport> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(report) = self.0.lock().unwrap().first() {
                return Arc::clone(report);
            }
            assert!(Instant::now() < deadline, "no report arrived");
            conn.poll_reports(Duration::from_millis(100))
                .await
                .expect("poll reports");
        }
    }
}

fn rcb_ref(name: &str, fc: &str) -> String {
    format!("{DOMAIN}/LLN0${fc}${name}")
}

/// The TrgOps a client reads back carries GI for a block whose `<TrgOps>`
/// leaves `gi` out, unbuffered or buffered, and not for one declaring
/// `gi="false"`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trg_ops_read_by_a_client_default_gi_to_true() {
    let server = build_server();
    let handle = server.start().await.expect("start");
    let conn = connect(&handle).await;

    for rcb in [rcb_ref("urcbDchg", "RP"), rcb_ref("brcbDchg", "BR")] {
        let read = conn.get_rcb_values(&rcb).await.expect("read the RCB");
        assert_eq!(
            read.trg_ops(),
            TriggerOptions::DATA_CHANGED | TriggerOptions::GI,
            "{rcb}"
        );
    }
    let read = conn
        .get_rcb_values(&rcb_ref("urcbNoGi", "RP"))
        .await
        .expect("read urcbNoGi");
    assert_eq!(read.trg_ops(), TriggerOptions::DATA_CHANGED);

    handle.stop().await;
}

/// A client that keeps the TrgOps of the SCL file, reserves and enables the
/// block and writes GI receives a report of every member with reason GI,
/// from an unbuffered and from a buffered block.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn writing_gi_reports_on_a_block_declaring_only_dchg() {
    let server = build_server();
    let handle = server.start().await.expect("start");
    let conn = connect(&handle).await;

    for (rcb, rpt_id, buffered) in [
        (rcb_ref("urcbDchg", "RP"), "UrcbDchg", false),
        (rcb_ref("brcbDchg", "BR"), "BrcbDchg", true),
    ] {
        let received = Received::default();
        conn.install_report_handler(Some(rpt_id.to_string()), &rcb, None, received.callback())
            .await
            .expect("install the report handler");

        if !buffered {
            let mut resv = RcbHandle::new(&rcb).expect("rcb reference");
            resv.set_resv(true);
            conn.set_rcb_values(&resv, RcbWriteMask::RESV, false)
                .await
                .unwrap_or_else(|e| panic!("reserve {rcb}: {e:?}"));
        }
        let mut ena = RcbHandle::new(&rcb).expect("rcb reference");
        ena.set_rpt_ena(true);
        conn.set_rcb_values(&ena, RcbWriteMask::RPT_ENA, false)
            .await
            .unwrap_or_else(|e| panic!("enable {rcb}: {e:?}"));

        let mut gi = RcbHandle::new(&rcb).expect("rcb reference");
        gi.set_gi(true);
        conn.set_rcb_values(&gi, RcbWriteMask::GI, false)
            .await
            .unwrap_or_else(|e| panic!("write GI to {rcb}: {e:?}"));

        let report = received.first(&conn).await;
        assert_eq!(report.included, vec![true, true], "{rcb}");
        assert!(
            report.reasons.iter().all(|r| *r == ReasonForInclusion::GI),
            "{rcb}: {:?}",
            report.reasons
        );
    }

    handle.stop().await;
}
