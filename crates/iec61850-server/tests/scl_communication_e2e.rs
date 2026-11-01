//! GOOSE control blocks registered from a model whose SCL addresses them.
//!
//! `IedServer::register_from_model` gives each publisher the destination of
//! the `<GSE>` that names its control block, and `MinTime` and `MaxTime` from
//! the same element. A client reads them back as `DstAddress`, `MinTime` and
//! `MaxTime` (IEC 61850-8-1 §18.1.1.1.1 Table 83).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iec61850_client::IedConnection;
use iec61850_goose::{CommParameters, RetransIntervals};
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_model::IedModel;
use iec61850_server::{FromModelOptions, IedServer, IedServerConfig, ServerError};

const DOMAIN: &str = "CommLD0";

/// An IED with two GOOSE control blocks, `gcbTrip` addressed by `gse` and
/// `gcbSpare` addressed by nothing.
fn scl(gse: &str) -> String {
    format!(
        r#"<SCL>
  <Communication>
    <SubNetwork name="W01" type="8-MMS">
      <ConnectedAP iedName="Comm" apName="AP1">
        <Address><P type="IP">127.0.0.1</P></Address>
        {gse}
      </ConnectedAP>
    </SubNetwork>
  </Communication>
  <IED name="Comm">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <DataSet name="Trip">
              <FCDA ldInst="LD0" lnClass="LLN0" doName="Mod" daName="stVal" fc="ST"/>
            </DataSet>
            <GSEControl name="gcbTrip" datSet="Trip" appID="Trip" confRev="1"/>
            <GSEControl name="gcbSpare" datSet="Trip" appID="Spare" confRev="1"/>
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="Mod" type="ENC_T"/></LNodeType>
    <DOType id="ENC_T" cdc="ENC"><DA name="stVal" fc="ST" bType="BOOLEAN" dchg="true"/></DOType>
  </DataTypeTemplates>
</SCL>"#
    )
}

const TRIP_GSE: &str = r#"<GSE ldInst="LD0" cbName="gcbTrip">
          <Address>
            <P type="MAC-Address">01-0C-CD-01-00-05</P>
            <P type="APPID">3A01</P>
            <P type="VLAN-ID">07B</P>
            <P type="VLAN-PRIORITY">6</P>
          </Address>
          <MinTime unit="s" multiplier="m">8</MinTime>
          <MaxTime unit="s" multiplier="m">2000</MaxTime>
        </GSE>"#;

fn model(gse: &str) -> Arc<IedModel> {
    let raw = iec61850_scl::parse_scl(&scl(gse)).expect("parse");
    Arc::new(
        raw.resolve()
            .expect("resolve")
            .build_model("Comm")
            .expect("build"),
    )
}

fn server(model: Arc<IedModel>) -> IedServer {
    let mut cfg = IedServerConfig::default();
    cfg.max_mms_connections = 2;
    IedServer::builder()
        .model(model)
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(cfg)
        .build()
        .expect("build server")
}

/// The communication parameters and the intervals of the publisher of
/// `name`.
fn publisher_settings(server: &IedServer, name: &str) -> (CommParameters, RetransIntervals) {
    let handle = server
        .gocb_registry()
        .find(DOMAIN, "LLN0", name)
        .unwrap_or_else(|| panic!("{name} is not registered"));
    let publisher = handle.publisher.lock().unwrap();
    (
        publisher.comm_parameters().clone(),
        *publisher.retrans_intervals(),
    )
}

/// The publisher of a control block the SCL addresses sends to the `<GSE>`
/// address, repeats after `MinTime` and settles at `MaxTime`; one the SCL
/// does not address keeps the defaults.
#[test]
fn the_publisher_takes_the_gse_of_its_control_block() {
    let model = model(TRIP_GSE);
    let server = server(model.clone());
    server.register_from_model().expect("register_from_model");

    let gse = model.gse_address("LD0", "gcbTrip").expect("GSE");
    let (comm, intervals) = publisher_settings(&server, "gcbTrip");
    assert_eq!(comm, CommParameters::from_address(&gse.address).unwrap());
    assert_eq!(comm.app_id, 0x3a01);
    assert_eq!(comm.dst_mac, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x05]);
    let vlan = comm.vlan.expect("tagged");
    assert_eq!((vlan.priority.value(), vlan.vlan_id), (6, 0x07b));
    assert_eq!(intervals.t1, Duration::from_millis(8));
    assert_eq!(intervals.tmax, Duration::from_millis(2000));

    let (comm, intervals) = publisher_settings(&server, "gcbSpare");
    assert_eq!(
        comm,
        CommParameters::new(0, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x00])
    );
    assert_eq!(intervals, RetransIntervals::default());
}

/// A client reads `DstAddress`, `MinTime` and `MaxTime` of the control block
/// as the SCL declares them, over TCP from our own server.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_reads_the_scl_addressing_of_the_gocb() {
    let server = server(model(TRIP_GSE));
    server.register_from_model().expect("register_from_model");
    let handle = server.start().await.expect("start");

    let conn = IedConnection::with_mms_client(
        MmsClientBuilder::new()
            .connect_timeout_ms(3_000)
            .request_timeout_ms(3_000)
            .build(),
    );
    conn.connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");

    let trip = conn
        .get_gocb_values(&format!("{DOMAIN}/LLN0$GO$gcbTrip"))
        .await
        .expect("GetGoCBValues gcbTrip");
    assert_eq!(trip.dst_address.addr, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x05]);
    assert_eq!(trip.dst_address.app_id, 0x3a01);
    assert_eq!(trip.dst_address.vlan_id, 0x07b);
    assert_eq!(trip.dst_address.priority, 6);
    assert_eq!(trip.min_time_ms, Some(8));
    assert_eq!(trip.max_time_ms, Some(2000));

    let spare = conn
        .get_gocb_values(&format!("{DOMAIN}/LLN0$GO$gcbSpare"))
        .await
        .expect("GetGoCBValues gcbSpare");
    assert_eq!(spare.dst_address.addr, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x00]);
    assert_eq!(spare.dst_address.app_id, 0);
    assert_eq!(spare.min_time_ms, Some(4));
    assert_eq!(spare.max_time_ms, Some(1000));
    handle.stop().await;
}

/// The application's factory chooses the destination of every publisher,
/// the addressed one included, while `MinTime` and `MaxTime` stay those of the
/// `<GSE>`.
#[test]
fn the_comm_factory_takes_precedence_over_the_gse() {
    let server = server(model(TRIP_GSE));
    let options = FromModelOptions::new().with_goose_comm(Arc::new(|_reference: &str| {
        CommParameters::new(0x0042, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x42])
    }));
    server
        .register_from_model_with(&options)
        .expect("register_from_model_with");

    let (comm, intervals) = publisher_settings(&server, "gcbTrip");
    assert_eq!(comm.app_id, 0x0042);
    assert_eq!(intervals.t1, Duration::from_millis(8));
    assert_eq!(intervals.tmax, Duration::from_millis(2000));
    assert_eq!(publisher_settings(&server, "gcbSpare").0.app_id, 0x0042);
}

/// A `<GSE>` address without `MAC-Address` cannot give a layer 2 destination:
/// the call fails and registers nothing.
#[test]
fn a_gse_without_mac_address_fails_the_registration() {
    let server = server(model(
        r#"<GSE ldInst="LD0" cbName="gcbTrip"><Address><P type="APPID">3A01</P></Address></GSE>"#,
    ));
    match server.register_from_model() {
        Err(ServerError::InvalidModel(why)) => {
            assert!(
                why.contains("gcbTrip") && why.contains("MAC-Address"),
                "{why}"
            )
        }
        other => panic!("{other:?}"),
    }
    assert!(server.gocb_registry().is_empty());
}
