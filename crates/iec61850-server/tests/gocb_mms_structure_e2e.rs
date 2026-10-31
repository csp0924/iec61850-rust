//! End-to-end tests for the GoCB MMS structure of IEC 61850-8-1 §18.1.1.1.1
//! Table 83, over real TCP and the full ISO stack.
//!
//! A server publishes one GoCB; the client reads it whole and by component
//! and checks the component order, the component types and that every value
//! is the one the publisher sends.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use iec61850_goose::frame::{VlanPriority, VlanTag};
use iec61850_goose::publisher::CommParameters;
use iec61850_goose::GoosePublisher;
use iec61850_mms::mms::client::{MmsClient, MmsClientBuilder, MmsConnection};
use iec61850_mms::mms::pdu::common::{
    AccessResult, AlternateAccess, DataAccessError, ListOfVariableEntry, ObjectName,
    VariableAccessSpecification,
};
use iec61850_mms::mms::pdu::get_name_list::ObjectClass;
use iec61850_mms::mms::pdu::read::{encode_confirmed_read_request, ReadRequest, ReadResponse};
use iec61850_mms::mms::pdu::type_specification::TypeSpecification;
use iec61850_mms::mms::pdu::MmsPdu;
use iec61850_mms::mms::MmsData;
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObjectBuilder, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::goose_mapping::GoCBHandle;
use iec61850_server::lifecycle::ServerHandle;
use iec61850_server::reporting::Dataset;
use iec61850_server::{IedServer, IedServerConfig};

const DOMAIN: &str = "TESTLD0";
const GOCB_ITEM: &str = "LLN0$GO$gcb01";

/// LD0 with LLN0 holding `Mod.stVal`.
fn build_model() -> Arc<IedModel> {
    let lln0 = LogicalNodeBuilder::lln0()
        .add_do(
            DataObjectBuilder::scalar("Mod")
                .add_da_node(DataAttribute::new(
                    "stVal",
                    FC::St,
                    DataAttributeType::Enumerated,
                    TrgOps::default(),
                    MmsValue::Integer(1),
                ))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
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
    for name in ["LLN0$ds1", "LLN0$ds2"] {
        server.register_dataset(DOMAIN, Dataset::new(name));
    }
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

// ── Type descriptions, name list and logical node reads ─────────────────

fn member_names(spec: &TypeSpecification) -> Vec<String> {
    match spec {
        TypeSpecification::Structure { components } => {
            components.iter().map(|c| c.name.clone()).collect()
        }
        other => panic!("expected a structure, got {other:?}"),
    }
}

/// Reports whether `value` has the shape `spec` describes: the same structure
/// nesting and member counts, and leaves of the matching kind.
fn fits(spec: &TypeSpecification, value: &MmsData) -> bool {
    use TypeSpecification as T;
    match (spec, value) {
        (T::Structure { components }, MmsData::Structure(members)) => {
            components.len() == members.len()
                && components
                    .iter()
                    .zip(members)
                    .all(|(c, m)| fits(&c.type_spec, m))
        }
        (T::Array { element_type, .. }, MmsData::Array(items)) => {
            items.iter().all(|i| fits(element_type, i))
        }
        (T::Boolean, MmsData::Boolean(_))
        | (T::Integer { .. }, MmsData::Integer(_))
        | (T::Unsigned { .. }, MmsData::Unsigned(_))
        | (T::FloatingPoint { .. }, MmsData::Float32(_) | MmsData::Float64(_))
        | (T::BitString { .. }, MmsData::BitString { .. })
        | (T::OctetString { .. }, MmsData::OctetString(_))
        | (T::VisibleString { .. }, MmsData::VisibleString(_))
        | (T::MmsString { .. }, MmsData::MmsString(_))
        | (T::UtcTime, MmsData::UtcTime(_))
        | (T::BinaryTime { .. }, MmsData::BinaryTime(_)) => true,
        _ => false,
    }
}

async fn gvaa(client: &mut MmsClient, item: &str) -> TypeSpecification {
    tokio::time::timeout(
        Duration::from_secs(5),
        client.get_variable_access_attributes(DOMAIN, item),
    )
    .await
    .expect("timeout")
    .unwrap_or_else(|e| panic!("{item} has no type description: {e:?}"))
}

async fn all_names(client: &mut MmsClient) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let (page, more) = tokio::time::timeout(
            Duration::from_secs(5),
            client.get_name_list(ObjectClass::NamedVariable, Some(DOMAIN), cursor.as_deref()),
        )
        .await
        .expect("timeout")
        .expect("GetNameList");
        cursor = page.last().cloned();
        out.extend(page);
        if !more {
            return out;
        }
    }
}

const TABLE_83: [&str; 9] = [
    "GoEna",
    "GoID",
    "DatSet",
    "ConfRev",
    "NdsCom",
    "DstAddress",
    "MinTime",
    "MaxTime",
    "FixedOffs",
];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_variable_access_attributes_describes_table_83() {
    use TypeSpecification as T;

    let (handle, _publisher) = start_server(IedServerConfig::default()).await;
    let mut client = connect(&handle).await;

    let spec = gvaa(&mut client, GOCB_ITEM).await;
    assert_eq!(member_names(&spec), TABLE_83);
    let T::Structure { components } = &spec else {
        unreachable!()
    };
    let kinds: Vec<&str> = components
        .iter()
        .map(|c| match &c.type_spec {
            T::Boolean => "Boolean",
            T::VisibleString { .. } => "VisibleString",
            T::Unsigned { .. } => "Unsigned",
            T::Structure { .. } => "Structure",
            other => panic!("{}: unexpected type {other:?}", c.name),
        })
        .collect();
    assert_eq!(
        kinds,
        [
            "Boolean",
            "VisibleString",
            "VisibleString",
            "Unsigned",
            "Boolean",
            "Structure",
            "Unsigned",
            "Unsigned",
            "Boolean"
        ]
    );
    assert_eq!(
        member_names(&components[5].type_spec),
        ["Addr", "PRIORITY", "VID", "APPID"]
    );

    assert_eq!(member_names(&gvaa(&mut client, "LLN0$GO").await), ["gcb01"]);
    assert!(matches!(
        gvaa(&mut client, "LLN0$GO$gcb01$GoEna").await,
        T::Boolean
    ));
    assert!(matches!(
        gvaa(&mut client, "LLN0$GO$gcb01$DstAddress$APPID").await,
        T::Unsigned { .. }
    ));
    assert!(member_names(&gvaa(&mut client, "LLN0").await).contains(&"GO".to_string()));

    client.disconnect().await.expect("disconnect");
    handle.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_name_list_lists_the_go_group_and_every_component() {
    let (handle, _publisher) = start_server(IedServerConfig::default()).await;
    let mut client = connect(&handle).await;

    let names = all_names(&mut client).await;
    let expected = ["LLN0$GO".to_string(), GOCB_ITEM.to_string()]
        .into_iter()
        .chain(TABLE_83.iter().map(|c| format!("{GOCB_ITEM}${c}")))
        .chain(
            ["Addr", "PRIORITY", "VID", "APPID"]
                .iter()
                .map(|m| format!("{GOCB_ITEM}$DstAddress${m}")),
        );
    for name in expected {
        assert!(names.contains(&name), "{name} is not listed in {names:?}");
    }
    assert!(!names.iter().any(|n| n.ends_with("$GoCBRef")));

    client.disconnect().await.expect("disconnect");
    handle.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logical_node_and_go_group_reads_hold_the_gocb() {
    let (handle, _publisher) = start_server(IedServerConfig::default()).await;
    let mut client = connect(&handle).await;

    let whole = read(&mut client, GOCB_ITEM).await;
    assert_eq!(
        read(&mut client, "LLN0$GO").await,
        MmsData::Structure(vec![whole.clone()])
    );

    let lln0_spec = gvaa(&mut client, "LLN0").await;
    let lln0 = read(&mut client, "LLN0").await;
    let (TypeSpecification::Structure { components }, MmsData::Structure(groups)) =
        (&lln0_spec, &lln0)
    else {
        panic!("LLN0 is a structure: {lln0:?}");
    };
    assert_eq!(components.len(), groups.len());
    let go = components
        .iter()
        .position(|c| c.name == "GO")
        .expect("LLN0 has a GO group");
    assert_eq!(groups[go], MmsData::Structure(vec![whole]));

    client.disconnect().await.expect("disconnect");
    handle.stop().await;
}

/// Every listed name under a GO group, for every GoCB of the server, reads a
/// value of the type GetVariableAccessAttributes describes for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_gocb_name_reads_the_type_it_is_described_with() {
    let server = IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig::default())
        .build()
        .expect("build server");
    for name in ["gcb01", "gcb02"] {
        let publisher = GoosePublisher::new(
            comm(),
            format!("TESTLD0/LLN0$GO${name}"),
            None,
            "TESTLD0/LLN0$ds1",
            3,
        )
        .unwrap();
        server.register_gocb(Arc::new(GoCBHandle::new(
            DOMAIN,
            "LLN0",
            name,
            Arc::new(Mutex::new(publisher)),
        )));
    }
    let handle = server.start().await.expect("start");
    let mut client = connect(&handle).await;

    let names: Vec<String> = all_names(&mut client)
        .await
        .into_iter()
        .filter(|n| n.starts_with("LLN0$GO"))
        .collect();
    assert_eq!(names.len(), 1 + 2 * (1 + TABLE_83.len() + 4));
    for name in names.iter().map(String::as_str).chain(["LLN0"]) {
        let spec = gvaa(&mut client, name).await;
        let value = read(&mut client, name).await;
        assert!(
            fits(&spec, &value),
            "{name}: {value:?} does not fit {spec:?}"
        );
    }

    client.disconnect().await.expect("disconnect");
    handle.stop().await;
}

// ── SetGoCBValues ───────────────────────────────────────────────────────

/// Under the default edition, a DatSet write while the GoCB is disabled
/// replaces the publication's datSet and increments ConfRev, also when the
/// value is unchanged (IEC 61850-7-2 §18.2.1.6); while it is enabled the write
/// is refused (7-2 §18.2.2.6.3).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dat_set_write_increments_conf_rev_even_when_unchanged() {
    use iec61850_client::connection::IedConnection;
    use iec61850_client::gocb::GoCBValuesWrite;
    use iec61850_client::ClientError;

    let (handle, publisher) = start_server(IedServerConfig::default()).await;
    let conn = IedConnection::new();
    conn.connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");

    for (written, conf_rev) in [("LLN0$ds2", 8), ("TESTLD0/LLN0$ds2", 9)] {
        tokio::time::timeout(
            Duration::from_secs(5),
            conn.set_gocb_values(
                "TESTLD0/LLN0.gcb01",
                GoCBValuesWrite::new().with_dat_set(written),
            ),
        )
        .await
        .expect("timeout")
        .expect("set DatSet");
        let v = conn.get_gocb_values("TESTLD0/LLN0.gcb01").await.unwrap();
        assert_eq!(v.dat_set, "TESTLD0/LLN0$ds2");
        assert_eq!(v.conf_rev, conf_rev, "after writing {written}");
    }
    {
        let p = publisher.lock().unwrap();
        assert_eq!(p.data_set_ref(), "TESTLD0/LLN0$ds2");
        assert_eq!(p.conf_rev(), 9);
    }

    conn.set_gocb_values(
        "TESTLD0/LLN0.gcb01",
        GoCBValuesWrite::new().with_go_ena(true),
    )
    .await
    .expect("enable");
    let refused = conn
        .set_gocb_values(
            "TESTLD0/LLN0.gcb01",
            GoCBValuesWrite::new().with_dat_set("LLN0$ds1"),
        )
        .await;
    assert!(
        matches!(
            refused,
            Err(ClientError::DataAccessError(
                DataAccessError::TemporarilyUnavailable
            ))
        ),
        "a DatSet write while enabled is refused, got {refused:?}"
    );
    assert_eq!(publisher.lock().unwrap().conf_rev(), 9);

    conn.set_gocb_values(
        "TESTLD0/LLN0.gcb01",
        GoCBValuesWrite::new().with_go_ena(false),
    )
    .await
    .expect("disable");
    // A data set the server does not hold, and an association-scope one, are
    // refused without touching the publication (IEC 61850-8-1 Table 83).
    for refused in ["LLN0$nosuch", "@ds2"] {
        let r = conn
            .set_gocb_values(
                "TESTLD0/LLN0.gcb01",
                GoCBValuesWrite::new().with_dat_set(refused),
            )
            .await;
        assert!(
            matches!(
                r,
                Err(ClientError::DataAccessError(
                    DataAccessError::ObjectValueInvalid
                ))
            ),
            "{refused}: expected object-value-invalid, got {r:?}"
        );
    }
    {
        let p = publisher.lock().unwrap();
        assert_eq!(p.data_set_ref(), "TESTLD0/LLN0$ds2");
        assert_eq!(p.conf_rev(), 9);
    }

    conn.disconnect().await.expect("disconnect");
    handle.stop().await;
}

/// A server configured for Ed2.1 refuses GoID and DatSet writes with
/// object-access-denied, as IEC 61850-8-1 §18.1.1.1.1 Table 83 makes both
/// read-only, and leaves the publisher untouched; GoEna stays writable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ed2_1_server_refuses_go_id_and_dat_set_writes() {
    use iec61850_mms::mms::client::error::ClientError;
    use iec61850_server::Edition;

    let mut config = IedServerConfig::default();
    config.edition = Edition::Ed2_1;
    let (handle, publisher) = start_server(config).await;
    let mut client = connect(&handle).await;

    for (component, value) in [
        ("GoID", MmsData::VisibleString("changed".into())),
        ("DatSet", MmsData::VisibleString("TESTLD0/LLN0$ds2".into())),
    ] {
        let r = tokio::time::timeout(
            Duration::from_secs(5),
            client.write(DOMAIN, &format!("{GOCB_ITEM}${component}"), value),
        )
        .await
        .expect("timeout");
        assert!(
            matches!(
                r,
                Err(ClientError::DataAccessError(
                    DataAccessError::ObjectAccessDenied
                ))
            ),
            "{component}: expected object-access-denied, got {r:?}"
        );
    }
    {
        let p = publisher.lock().unwrap();
        assert_eq!(p.go_id(), Some("goid01"));
        assert_eq!(p.data_set_ref(), "TESTLD0/LLN0$ds1");
        assert_eq!(p.conf_rev(), 7);
    }
    tokio::time::timeout(
        Duration::from_secs(5),
        client.write(
            DOMAIN,
            &format!("{GOCB_ITEM}$GoEna"),
            MmsData::Boolean(true),
        ),
    )
    .await
    .expect("timeout")
    .expect("GoEna stays writable");
    assert!(publisher.lock().unwrap().enabled());

    client.disconnect().await.expect("disconnect");
    handle.stop().await;
}

/// The default edition, Ed2, accepts a GoID write while the GoCB is disabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ed2_server_accepts_go_id_writes_while_disabled() {
    let (handle, publisher) = start_server(IedServerConfig::default()).await;
    let mut client = connect(&handle).await;

    tokio::time::timeout(
        Duration::from_secs(5),
        client.write(
            DOMAIN,
            &format!("{GOCB_ITEM}$GoID"),
            MmsData::VisibleString("changed".into()),
        ),
    )
    .await
    .expect("timeout")
    .expect("GoID write");
    assert_eq!(publisher.lock().unwrap().go_id(), Some("changed"));

    client.disconnect().await.expect("disconnect");
    handle.stop().await;
}

// ── Alternate access ────────────────────────────────────────────────────

/// Sends one Read of `item` under `access` over a bare MMS association and
/// returns its single access result.
async fn read_with_access(
    conn: &mut MmsConnection,
    invoke_id: u32,
    item: &str,
    access: AlternateAccess,
) -> AccessResult {
    let req = ReadRequest {
        specification_with_result: false,
        variable_access_spec: VariableAccessSpecification::ListOfVariable(vec![
            ListOfVariableEntry::with_alt_access(
                ObjectName::DomainSpecific {
                    domain_id: DOMAIN.to_string(),
                    item_id: item.to_string(),
                },
                access,
            ),
        ]),
    };
    let mut full = BytesMut::new();
    encode_confirmed_read_request(invoke_id, &req, &mut full);
    let content = Bytes::from(tlv_content(&full).to_vec());
    tokio::time::timeout(
        Duration::from_secs(5),
        conn.send_mms_pdu(&MmsPdu::ConfirmedRequest(content)),
    )
    .await
    .expect("timeout")
    .expect("send");
    let pdu = tokio::time::timeout(Duration::from_secs(5), conn.recv_mms_pdu_confirmed())
        .await
        .expect("timeout")
        .expect("recv");
    let MmsPdu::ConfirmedResponse(body) = pdu else {
        panic!("a confirmed response, got {pdu:?}");
    };
    // The body is the invoke id followed by the ReadResponse.
    let (header, len) = tlv_header(&body);
    let mut resp = ReadResponse::decode(&body[header + len..]).expect("decode ReadResponse");
    assert_eq!(resp.list_of_access_result.len(), 1);
    resp.list_of_access_result.remove(0)
}

fn tlv_content(tlv: &[u8]) -> &[u8] {
    let (header, len) = tlv_header(tlv);
    &tlv[header..header + len]
}

fn tlv_header(tlv: &[u8]) -> (usize, usize) {
    let first = tlv[1];
    if first < 0x80 {
        return (2, usize::from(first));
    }
    let n = usize::from(first & 0x7f);
    let len = tlv[2..2 + n]
        .iter()
        .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
    (2 + n, len)
}

/// A component selection reads the same value as the flattened name it
/// stands for (IEC 61850-8-1 §7.3.1), for a GoCB component, for a chain that
/// starts at the logical node, and for model data.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn component_alternate_access_reads_like_the_flattened_name() {
    let (handle, _publisher) = start_server(IedServerConfig::default()).await;
    let mut conn = MmsConnection::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        conn.connect("127.0.0.1", handle.bound_addr.port()),
    )
    .await
    .expect("timeout")
    .expect("connect");

    let go_ena = read_with_access(
        &mut conn,
        1,
        GOCB_ITEM,
        AlternateAccess::component("GoEna").unwrap(),
    )
    .await;
    assert_eq!(go_ena, AccessResult::Success(MmsData::Boolean(false)));

    let app_id = read_with_access(
        &mut conn,
        2,
        "LLN0",
        AlternateAccess::component("GO$gcb01$DstAddress$APPID").unwrap(),
    )
    .await;
    assert_eq!(app_id, AccessResult::Success(MmsData::Unsigned(0x1000)));

    let st_val = read_with_access(
        &mut conn,
        3,
        "LLN0$ST",
        AlternateAccess::component("Mod$stVal").unwrap(),
    )
    .await;
    assert_eq!(st_val, AccessResult::Success(MmsData::Integer(1)));

    let unknown = read_with_access(
        &mut conn,
        4,
        GOCB_ITEM,
        AlternateAccess::component("NoSuch").unwrap(),
    )
    .await;
    assert_eq!(
        unknown,
        AccessResult::Failure(DataAccessError::ObjectNonExistent)
    );

    // No GoCB component is an array.
    let indexed = read_with_access(
        &mut conn,
        5,
        GOCB_ITEM,
        AlternateAccess::component_then("GoEna", AlternateAccess::index(0)).unwrap(),
    )
    .await;
    assert_eq!(
        indexed,
        AccessResult::Failure(DataAccessError::TypeInconsistent)
    );

    handle.stop().await;
}

/// Enabling a GoCB whose ConfRev is 0 is refused with object-value-invalid,
/// since IEC 61850-7-2 §18.2.1.3 treats it as an inconsistent configuration,
/// and the publisher stays disabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enabling_a_gocb_with_conf_rev_zero_is_refused() {
    use iec61850_mms::mms::client::error::ClientError;

    let publisher = build_publisher();
    publisher.lock().unwrap().set_conf_rev(0);
    let (handle, publisher) = start_server_with(IedServerConfig::default(), publisher).await;
    let mut client = connect(&handle).await;

    let r = tokio::time::timeout(
        Duration::from_secs(5),
        client.write(
            DOMAIN,
            &format!("{GOCB_ITEM}$GoEna"),
            MmsData::Boolean(true),
        ),
    )
    .await
    .expect("timeout");
    assert!(
        matches!(
            r,
            Err(ClientError::DataAccessError(
                DataAccessError::ObjectValueInvalid
            ))
        ),
        "expected object-value-invalid, got {r:?}"
    );
    assert!(!publisher.lock().unwrap().enabled());
    assert_eq!(
        read(&mut client, &format!("{GOCB_ITEM}$GoEna")).await,
        MmsData::Boolean(false)
    );

    client.disconnect().await.expect("disconnect");
    handle.stop().await;
}
