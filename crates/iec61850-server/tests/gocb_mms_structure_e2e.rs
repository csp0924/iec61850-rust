//! End-to-end tests for the GoCB MMS structure of IEC 61850-8-1 §18.1.1.1.1
//! Table 83, over real TCP and the full ISO stack.
//!
//! A server publishes one GoCB; the client reads it whole and by component
//! and checks the component order, the component types and that every value
//! is the one the publisher sends.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iec61850_goose::frame::{VlanPriority, VlanTag};
use iec61850_goose::publisher::CommParameters;
use iec61850_goose::GoosePublisher;
use iec61850_mms::mms::client::{MmsClient, MmsClientBuilder};
use iec61850_mms::mms::MmsData;
use iec61850_model::{IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder};
use iec61850_server::goose_mapping::GoCBHandle;
use iec61850_server::lifecycle::ServerHandle;
use iec61850_server::{IedServer, IedServerConfig};

const DOMAIN: &str = "TESTLD0";
const GOCB_ITEM: &str = "LLN0$GO$gcb01";

fn build_model() -> Arc<IedModel> {
    let lln0 = LogicalNodeBuilder::lln0().build().unwrap();
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .build()
        .unwrap();
    Arc::new(
        IedModelBuilder::new("TEST")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap(),
    )
}

fn comm() -> CommParameters {
    CommParameters::new(0x1000, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01])
        .with_src_mac([0x00, 0x50, 0xc2, 0x12, 0x34, 0x56])
        .with_vlan(VlanTag {
            priority: VlanPriority::new(4).unwrap(),
            vlan_id: 100,
        })
}

fn build_publisher() -> Arc<Mutex<GoosePublisher>> {
    build_publisher_with_data_set("TESTLD0/LLN0$ds1")
}

fn build_publisher_with_data_set(data_set_ref: &str) -> Arc<Mutex<GoosePublisher>> {
    let p = GoosePublisher::new(
        comm(),
        "TESTLD0/LLN0$GO$gcb01",
        Some("goid01".into()),
        data_set_ref,
        7,
    )
    .unwrap();
    Arc::new(Mutex::new(p))
}

fn build_handle(publisher: Arc<Mutex<GoosePublisher>>) -> Arc<GoCBHandle> {
    Arc::new(GoCBHandle::new(DOMAIN, "LLN0", "gcb01", publisher))
}

async fn start_server(config: IedServerConfig) -> (ServerHandle, Arc<Mutex<GoosePublisher>>) {
    start_server_with(config, build_publisher()).await
}

async fn start_server_with(
    config: IedServerConfig,
    publisher: Arc<Mutex<GoosePublisher>>,
) -> (ServerHandle, Arc<Mutex<GoosePublisher>>) {
    let server = IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(config)
        .build()
        .expect("build server");
    server.register_gocb(build_handle(publisher.clone()));
    (server.start().await.expect("start"), publisher)
}

async fn connect(handle: &ServerHandle) -> MmsClient {
    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    client
        .connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    client
}

async fn read(client: &mut MmsClient, item: &str) -> MmsData {
    tokio::time::timeout(Duration::from_secs(5), client.read(DOMAIN, item))
        .await
        .expect("timeout")
        .unwrap_or_else(|e| panic!("read {item}: {e:?}"))
}

/// The components of Table 83 with the values the publisher sends.
fn expected_components() -> Vec<(&'static str, MmsData)> {
    vec![
        ("GoEna", MmsData::Boolean(false)),
        ("GoID", MmsData::VisibleString("goid01".into())),
        ("DatSet", MmsData::VisibleString("TESTLD0/LLN0$ds1".into())),
        ("ConfRev", MmsData::Unsigned(7)),
        ("NdsCom", MmsData::Boolean(false)),
        (
            "DstAddress",
            MmsData::Structure(vec![
                MmsData::OctetString(vec![0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01]),
                MmsData::Unsigned(4),
                MmsData::Unsigned(100),
                MmsData::Unsigned(0x1000),
            ]),
        ),
        ("MinTime", MmsData::Unsigned(4)),
        ("MaxTime", MmsData::Unsigned(1000)),
        ("FixedOffs", MmsData::Boolean(false)),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn whole_gocb_read_follows_table_83() {
    let (handle, _publisher) = start_server(IedServerConfig::default()).await;
    let mut client = connect(&handle).await;

    let whole = read(&mut client, GOCB_ITEM).await;
    let MmsData::Structure(items) = whole else {
        panic!("a GoCB reads as a structure, got {whole:?}");
    };
    let expected = expected_components();
    assert_eq!(items.len(), expected.len(), "Table 83 has nine components");
    for (item, (name, value)) in items.iter().zip(&expected) {
        assert_eq!(item, value, "component {name}");
    }

    client.disconnect().await.expect("disconnect");
    handle.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_component_reads_alone_as_in_the_whole_block() {
    let (handle, _publisher) = start_server(IedServerConfig::default()).await;
    let mut client = connect(&handle).await;

    for (name, value) in expected_components() {
        let got = read(&mut client, &format!("{GOCB_ITEM}${name}")).await;
        assert_eq!(got, value, "component {name}");
    }

    client.disconnect().await.expect("disconnect");
    handle.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_get_gocb_values_decodes_table_83() {
    use iec61850_client::connection::IedConnection;

    let (handle, _publisher) = start_server(IedServerConfig::default()).await;
    let conn = IedConnection::new();
    conn.connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");

    let v = tokio::time::timeout(
        Duration::from_secs(5),
        conn.get_gocb_values("TESTLD0/LLN0.gcb01"),
    )
    .await
    .expect("timeout")
    .expect("get_gocb_values");
    assert!(!v.go_ena);
    assert_eq!(v.go_id, "goid01");
    assert_eq!(v.dat_set, "TESTLD0/LLN0$ds1");
    assert_eq!(v.conf_rev, 7);
    assert!(!v.nds_com);
    assert_eq!(v.dst_address.addr, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01]);
    assert_eq!(v.dst_address.priority, 4);
    assert_eq!(v.dst_address.vlan_id, 100);
    assert_eq!(v.dst_address.app_id, 0x1000);
    assert_eq!(v.min_time_ms, Some(4));
    assert_eq!(v.max_time_ms, Some(1000));
    assert_eq!(v.fixed_offs, Some(false));

    conn.disconnect().await.expect("disconnect");
    handle.stop().await;
}

/// A change the application makes on the publisher after the GoCB is
/// registered is what a client reads next: the publication and the GoCB carry
/// the same goID, datSet, confRev and ndsCom (IEC 61850-8-1 §18.1.2.5.2).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reads_follow_changes_made_on_the_publisher() {
    use iec61850_goose::publisher::RetransIntervals;

    let (handle, publisher) = start_server(IedServerConfig::default()).await;
    let mut client = connect(&handle).await;
    {
        let mut p = publisher.lock().unwrap();
        p.set_conf_rev(8);
        p.set_needs_commission(true);
        p.set_go_id(Some("goid02".into()));
        let mut intervals = RetransIntervals::default();
        intervals.t1 = Duration::from_millis(2);
        intervals.tmax = Duration::from_millis(3000);
        p.set_retrans_intervals(intervals);
        p.set_enabled(true);
    }

    assert_eq!(
        read(&mut client, "LLN0$GO$gcb01$ConfRev").await,
        MmsData::Unsigned(8)
    );
    assert_eq!(
        read(&mut client, "LLN0$GO$gcb01$NdsCom").await,
        MmsData::Boolean(true)
    );
    assert_eq!(
        read(&mut client, "LLN0$GO$gcb01$GoID").await,
        MmsData::VisibleString("goid02".into())
    );
    assert_eq!(
        read(&mut client, "LLN0$GO$gcb01$GoEna").await,
        MmsData::Boolean(true)
    );
    assert_eq!(
        read(&mut client, "LLN0$GO$gcb01$MinTime").await,
        MmsData::Unsigned(2)
    );
    assert_eq!(
        read(&mut client, "LLN0$GO$gcb01$MaxTime").await,
        MmsData::Unsigned(3000)
    );

    client.disconnect().await.expect("disconnect");
    handle.stop().await;
}

/// DatSet reads as a complete reference, `<LD>/LLN0$<dsName>`, even when the
/// publisher was configured with the data set name relative to its domain
/// (IEC 61850-8-1 §8.1.3.2.2); the publication carries the same reference.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dat_set_reads_with_its_domain() {
    let (handle, publisher) = start_server_with(
        IedServerConfig::default(),
        build_publisher_with_data_set("LLN0$ds1"),
    )
    .await;
    let mut client = connect(&handle).await;

    assert_eq!(
        read(&mut client, "LLN0$GO$gcb01$DatSet").await,
        MmsData::VisibleString("TESTLD0/LLN0$ds1".into())
    );
    assert_eq!(publisher.lock().unwrap().data_set_ref(), "TESTLD0/LLN0$ds1");

    client.disconnect().await.expect("disconnect");
    handle.stop().await;
}
