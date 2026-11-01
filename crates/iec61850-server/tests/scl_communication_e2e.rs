//! GOOSE control blocks registered from a model whose SCL addresses them.
//!
//! `IedServer::register_from_model` gives each publisher the destination of
//! the `<GSE>` that names its control block, and `MinTime` and `MaxTime` from
//! the same element. A client reads them back as `DstAddress`, `MinTime` and
//! `MaxTime` (IEC 61850-8-1 §18.1.1.1.1 Table 83).
//!
//! In a system configuration, an SCL whose Communication section connects the
//! IED, a control block without `<GSE>` is disabled (IEC 61850-8-1 §25.3.2):
//! its `DstAddress$Addr` reads as the NULL address, six zero octets, and GoEna
//! cannot be set TRUE. An SCL without Communication section keeps the default destination.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iec61850_client::IedConnection;
use iec61850_goose::{CommParameters, RetransIntervals};
use iec61850_mms::mms::client::{ClientError, MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::common::DataAccessError;
use iec61850_mms::mms::pdu::type_specification::TypeSpecification;
use iec61850_mms::mms::MmsData;
use iec61850_model::IedModel;
use iec61850_server::{FromModelOptions, IedServer, IedServerConfig};

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

/// The IED of [`scl`] without Communication section, as an ICD describes it.
fn icd() -> String {
    let full = scl("");
    let start = full.find("  <Communication>").expect("Communication");
    let end = full
        .find("</Communication>\n")
        .expect("end of Communication")
        + "</Communication>\n".len();
    format!("{}{}", &full[..start], &full[end..])
}

fn model(gse: &str) -> Arc<IedModel> {
    model_of(&scl(gse))
}

fn model_of(xml: &str) -> Arc<IedModel> {
    let raw = iec61850_scl::parse_scl(xml).expect("parse");
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
/// address, repeats after `MinTime` and settles at `MaxTime`; the publisher of
/// one the SCL does not address keeps the defaults.
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
    handle.stop().await;
}

/// Reads the GoCB `name` with the client's GetGoCBValues.
async fn gocb_values(port: u16, name: &str) -> iec61850_client::GoCBValues {
    let conn = IedConnection::with_mms_client(
        MmsClientBuilder::new()
            .connect_timeout_ms(3_000)
            .request_timeout_ms(3_000)
            .build(),
    );
    conn.connect("127.0.0.1", port).await.expect("connect");
    conn.get_gocb_values(&format!("{DOMAIN}/LLN0$GO${name}"))
        .await
        .unwrap_or_else(|e| panic!("GetGoCBValues {name}: {e:?}"))
}

async fn connect(port: u16) -> MmsClient {
    let mut c = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    c.connect("127.0.0.1", port).await.expect("connect");
    c
}

/// Reads `DstAddress$Addr` of `name`, then writes its GoEna TRUE.
async fn addr_and_enable(c: &mut MmsClient, name: &str) -> (MmsData, Result<(), ClientError>) {
    let addr = c
        .read(DOMAIN, &format!("LLN0$GO${name}$DstAddress$Addr"))
        .await
        .expect("read DstAddress$Addr");
    let enable = c
        .write(
            DOMAIN,
            &format!("LLN0$GO${name}$GoEna"),
            MmsData::Boolean(true),
        )
        .await;
    (addr, enable)
}

/// In a system configuration, the control block the SCL gives no `<GSE>` is
/// registered disabled: no destination address, GoEna FALSE and refused TRUE,
/// so its publisher never becomes enabled. The addressed one beside it is the
/// control group.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_control_block_without_gse_in_an_scd_is_disabled() {
    let server = server(model(TRIP_GSE));
    server.register_from_model().expect("register_from_model");
    let handle = server.start().await.expect("start");
    let mut c = connect(handle.bound_addr.port()).await;

    assert_eq!(
        c.read(DOMAIN, "LLN0$GO$gcbSpare$GoEna")
            .await
            .expect("GoEna"),
        MmsData::Boolean(false)
    );
    let (addr, enable) = addr_and_enable(&mut c, "gcbSpare").await;
    assert_eq!(addr, MmsData::OctetString(vec![0; 6]));
    match enable {
        Err(ClientError::DataAccessError(DataAccessError::TemporarilyUnavailable)) => {}
        other => panic!("GoEna=TRUE on a disabled control block: {other:?}"),
    }
    // The type description keeps Addr a fixed six-octet OctetString.
    match c
        .get_variable_access_attributes(DOMAIN, "LLN0$GO$gcbSpare$DstAddress")
        .await
        .expect("GetVariableAccessAttributes DstAddress")
    {
        TypeSpecification::Structure { components } => assert!(
            matches!(
                components[0].type_spec,
                TypeSpecification::OctetString { max_octets: 6, .. }
            ),
            "{:?}",
            components[0]
        ),
        other => panic!("DstAddress: {other:?}"),
    }
    // The client reads the disabled control block with its NULL address.
    let disabled = gocb_values(handle.bound_addr.port(), "gcbSpare").await;
    assert_eq!(disabled.dst_address.addr, [0; 6]);
    assert!(!disabled.go_ena);
    let spare = server
        .gocb_registry()
        .find(DOMAIN, "LLN0", "gcbSpare")
        .expect("gcbSpare is registered");
    assert!(!spare.has_destination);
    assert!(!spare.enabled(), "the publisher stays disabled");
    match c.read(DOMAIN, "LLN0$GO$gcbSpare$DstAddress").await {
        Ok(MmsData::Structure(items)) => assert_eq!(items[0], MmsData::OctetString(vec![0; 6])),
        other => panic!("DstAddress: {other:?}"),
    }

    let (addr, enable) = addr_and_enable(&mut c, "gcbTrip").await;
    assert_eq!(
        addr,
        MmsData::OctetString(vec![0x01, 0x0c, 0xcd, 0x01, 0x00, 0x05])
    );
    enable.expect("GoEna=TRUE on the addressed control block");
    assert!(server
        .gocb_registry()
        .find(DOMAIN, "LLN0", "gcbTrip")
        .expect("gcbTrip")
        .enabled());
    handle.stop().await;
}

/// A disabled control block is stamped like any other: its publisher carries
/// the timestamp source and starts from the wall clock reading.
#[test]
fn a_disabled_control_block_still_stamps_t() {
    let server = server(model(TRIP_GSE));
    let clock: iec61850_server::WallClock = Arc::new(|| Duration::from_secs(1_700_000_000));
    server
        .register_from_model_with(&FromModelOptions::new().with_wall_clock(clock))
        .expect("register_from_model_with");
    for name in ["gcbSpare", "gcbTrip"] {
        let handle = server
            .gocb_registry()
            .find(DOMAIN, "LLN0", name)
            .unwrap_or_else(|| panic!("{name} is registered"));
        assert_eq!(handle.has_destination, name == "gcbTrip");
        let publisher = handle.publisher.lock().unwrap();
        assert!(publisher.has_timestamp_source(), "{name}");
        assert_eq!(
            publisher.timestamp().seconds_since_epoch(),
            1_700_000_000,
            "{name}"
        );
    }
}

/// A destination the application supplies replaces the missing `<GSE>`: the
/// control block has an address and can be enabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_comm_factory_gives_a_destination_to_a_control_block_without_gse() {
    let server = server(model(TRIP_GSE));
    let options = FromModelOptions::new().with_goose_comm(Arc::new(|_reference: &str| {
        CommParameters::new(0x0042, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x42])
    }));
    server
        .register_from_model_with(&options)
        .expect("register_from_model_with");
    let handle = server.start().await.expect("start");
    let mut c = connect(handle.bound_addr.port()).await;

    let (addr, enable) = addr_and_enable(&mut c, "gcbSpare").await;
    assert_eq!(
        addr,
        MmsData::OctetString(vec![0x01, 0x0c, 0xcd, 0x01, 0x00, 0x42])
    );
    enable.expect("GoEna=TRUE with a destination from the factory");
    handle.stop().await;
}

/// An SCL without Communication section, as an ICD, disables nothing: the
/// control block keeps the default destination and can be enabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_control_block_of_an_icd_keeps_the_default_destination() {
    let model = model_of(&icd());
    assert!(model.connected_aps.is_empty());
    let server = server(model);
    server.register_from_model().expect("register_from_model");
    let handle = server.start().await.expect("start");
    let mut c = connect(handle.bound_addr.port()).await;

    let (addr, enable) = addr_and_enable(&mut c, "gcbSpare").await;
    assert_eq!(
        addr,
        MmsData::OctetString(vec![0x01, 0x0c, 0xcd, 0x01, 0x00, 0x00])
    );
    enable.expect("GoEna=TRUE on a control block of an ICD");
    let conn = IedConnection::with_mms_client(
        MmsClientBuilder::new()
            .connect_timeout_ms(3_000)
            .request_timeout_ms(3_000)
            .build(),
    );
    conn.connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    let spare = conn
        .get_gocb_values(&format!("{DOMAIN}/LLN0$GO$gcbSpare"))
        .await
        .expect("GetGoCBValues gcbSpare");
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

/// A `<GSE>` address without `MAC-Address`, as one for GOOSE over UDP/IP,
/// gives no layer 2 destination: its control block is registered disabled,
/// and every other control block is registered as usual.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_gse_without_mac_address_disables_its_control_block() {
    let server = server(model(
        r#"<GSE ldInst="LD0" cbName="gcbTrip"><Address><P type="APPID">3A01</P><P type="IP">239.0.0.1</P></Address><MinTime>8</MinTime></GSE>"#,
    ));
    let summary = server.register_from_model().expect("register_from_model");
    assert_eq!(summary.gocbs, 2);
    assert_eq!(summary.data_sets, 1);
    let trip = server
        .gocb_registry()
        .find(DOMAIN, "LLN0", "gcbTrip")
        .expect("gcbTrip is registered");
    assert!(!trip.has_destination);
    assert_eq!(
        publisher_settings(&server, "gcbTrip").1.t1,
        Duration::from_millis(8)
    );

    let handle = server.start().await.expect("start");
    let mut c = connect(handle.bound_addr.port()).await;
    let (addr, enable) = addr_and_enable(&mut c, "gcbTrip").await;
    assert_eq!(addr, MmsData::OctetString(vec![0; 6]));
    match enable {
        Err(ClientError::DataAccessError(DataAccessError::TemporarilyUnavailable)) => {}
        other => panic!("GoEna=TRUE without a layer 2 destination: {other:?}"),
    }
    let disabled = gocb_values(handle.bound_addr.port(), "gcbTrip").await;
    assert_eq!(disabled.dst_address.addr, [0; 6]);
    assert_eq!(disabled.min_time_ms, Some(8));
    handle.stop().await;
}

/// A `<GSE>` whose values are written another way than the schema form, but
/// read without ambiguity, gives its destination as read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_gse_written_another_way_gives_its_destination() {
    let server = server(model(
        r#"<GSE ldInst="LD0" cbName="gcbTrip"><Address><P type="MAC-Address">01:0c:cd:01:00:07</P><P type="APPID">3a1</P><P type="VLAN-ID">1</P><P type="VLAN-PRIORITY">05</P></Address></GSE>"#,
    ));
    server.register_from_model().expect("register_from_model");
    let trip = server
        .gocb_registry()
        .find(DOMAIN, "LLN0", "gcbTrip")
        .expect("gcbTrip is registered");
    assert!(trip.has_destination);
    drop(trip);
    let handle = server.start().await.expect("start");
    let values = gocb_values(handle.bound_addr.port(), "gcbTrip").await;
    assert_eq!(
        values.dst_address.addr,
        [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x07]
    );
    assert_eq!(values.dst_address.app_id, 0x3a1);
    assert_eq!(values.dst_address.vlan_id, 1);
    assert_eq!(values.dst_address.priority, 5);
    handle.stop().await;
}

/// A `<GSE>` whose MAC address cannot be read loads, and its control block
/// is registered disabled, as one without a layer 2 destination; every other
/// control block is registered as usual.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_gse_with_an_unreadable_mac_address_disables_its_control_block() {
    let server = server(model(
        r#"<GSE ldInst="LD0" cbName="gcbTrip"><Address><P type="MAC-Address">01-0C-CD-01-00</P></Address></GSE>"#,
    ));
    let summary = server.register_from_model().expect("register_from_model");
    assert_eq!(summary.gocbs, 2);
    let trip = server
        .gocb_registry()
        .find(DOMAIN, "LLN0", "gcbTrip")
        .expect("gcbTrip is registered");
    assert!(!trip.has_destination);
    drop(trip);
    let handle = server.start().await.expect("start");
    let values = gocb_values(handle.bound_addr.port(), "gcbTrip").await;
    assert_eq!(values.dst_address.addr, [0; 6]);
    assert!(!values.go_ena);
    handle.stop().await;
}
