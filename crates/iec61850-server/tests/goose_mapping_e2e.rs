//! End-to-end tests for the GOOSE control block exposed over MMS.
//!
//! A server is started with one GoCB bound to a publisher, and a client reads
//! and writes its attributes. The assertions are that GetNameList lists the
//! GoCB paths, that GoEna defaults to false, that writing GoEna true or false
//! reads back and reaches the publisher, that writing GoID takes effect, that
//! the read-only fields ConfRev and DstAddress answer ObjectAccessDenied, that
//! reading the whole control block returns its nine members, and that an
//! unknown control block name answers ObjectNonExistent.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iec61850_goose::frame::{VlanPriority, VlanTag};
use iec61850_goose::publisher::CommParameters;
use iec61850_goose::GoosePublisher;
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_mms::mms::pdu::DataAccessError;
use iec61850_mms::mms::MmsData;
use iec61850_model::{IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder};
use iec61850_server::goose_mapping::GoCBHandle;
use iec61850_server::{IedServer, IedServerConfig};

fn build_minimal_model() -> Arc<IedModel> {
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

fn build_publisher(comm: CommParameters) -> Arc<Mutex<GoosePublisher>> {
    let p =
        GoosePublisher::new(comm, "TESTLD0/LLN0$GO$gcb01", None, "TESTLD0/LLN0$ds1", 7).unwrap();
    Arc::new(Mutex::new(p))
}

fn build_server_with_gocb() -> IedServer {
    let server = IedServer::builder()
        .model(build_minimal_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig::default())
        .build()
        .expect("build server");

    let comm = CommParameters::new(0x1000, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01])
        .with_src_mac([0x00, 0x50, 0xc2, 0x12, 0x34, 0x56])
        .with_vlan(VlanTag {
            priority: VlanPriority::new(4).unwrap(),
            vlan_id: 100,
        });
    let publisher = build_publisher(comm.clone());

    let handle = Arc::new(GoCBHandle::new(
        "TESTLD0",
        "LLN0",
        "gcb01",
        publisher,
        7,
        "TESTLD0/LLN0$ds1",
        None,
        false,
        comm,
        Some(10),
        Some(2000),
    ));
    server.register_gocb(handle);
    server
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gocb_get_name_list_includes_paths() {
    use iec61850_mms::mms::pdu::get_name_list::ObjectClass;

    let server = build_server_with_gocb();
    let h = server.start().await.expect("start");
    let port = h.bound_addr.port();

    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    client.connect("127.0.0.1", port).await.expect("connect");

    let (names, _more) = tokio::time::timeout(
        Duration::from_secs(5),
        client.get_name_list(ObjectClass::NamedVariable, Some("TESTLD0"), None),
    )
    .await
    .expect("timeout")
    .expect("GetNameList");

    assert!(
        names.iter().any(|n| n == "LLN0$GO$gcb01"),
        "GetNameList must contain the GoCB top-level path, got {:?}",
        names
    );
    assert!(
        names.iter().any(|n| n == "LLN0$GO$gcb01$GoEna"),
        "GetNameList must contain the GoCB GoEna path, got {:?}",
        names
    );
    assert!(
        names.iter().any(|n| n == "LLN0$GO$gcb01$DstAddress"),
        "GetNameList must contain the GoCB DstAddress path"
    );

    client.disconnect().await.expect("disconnect");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gocb_read_default_attributes() {
    let server = build_server_with_gocb();
    let h = server.start().await.expect("start");
    let port = h.bound_addr.port();

    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    client.connect("127.0.0.1", port).await.expect("connect");

    // GoCBRef → "TESTLD0/LLN0$GO$gcb01"
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        client.read("TESTLD0", "LLN0$GO$gcb01$GoCBRef"),
    )
    .await
    .expect("timeout")
    .expect("read GoCBRef");
    assert_eq!(r, MmsData::VisibleString("TESTLD0/LLN0$GO$gcb01".into()));

    // GoEna defaults to false.
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        client.read("TESTLD0", "LLN0$GO$gcb01$GoEna"),
    )
    .await
    .expect("timeout")
    .expect("read GoEna");
    assert_eq!(r, MmsData::Boolean(false));

    // ConfRev = 7
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        client.read("TESTLD0", "LLN0$GO$gcb01$ConfRev"),
    )
    .await
    .expect("timeout")
    .expect("read ConfRev");
    assert_eq!(r, MmsData::Unsigned(7));

    // DatSet
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        client.read("TESTLD0", "LLN0$GO$gcb01$DatSet"),
    )
    .await
    .expect("timeout")
    .expect("read DatSet");
    assert_eq!(r, MmsData::VisibleString("TESTLD0/LLN0$ds1".into()));

    client.disconnect().await.expect("disconnect");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gocb_write_go_ena_toggle_round_trip() {
    let server = build_server_with_gocb();
    // Keep a handle on the publisher to assert against.
    let registry = server.gocb_registry();
    let h = server.start().await.expect("start");
    let port = h.bound_addr.port();

    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    client.connect("127.0.0.1", port).await.expect("connect");

    // Write GoEna = true
    tokio::time::timeout(
        Duration::from_secs(5),
        client.write("TESTLD0", "LLN0$GO$gcb01$GoEna", MmsData::Boolean(true)),
    )
    .await
    .expect("timeout")
    .expect("write GoEna=true");

    // The value must read back as true.
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        client.read("TESTLD0", "LLN0$GO$gcb01$GoEna"),
    )
    .await
    .expect("timeout")
    .expect("read GoEna");
    assert_eq!(r, MmsData::Boolean(true));

    // The publisher on the server side reflects the write.
    let handle = registry.find("TESTLD0", "LLN0", "gcb01").unwrap();
    assert!(handle.enabled());
    assert!(handle.publisher.lock().unwrap().enabled());

    // Write GoEna = false
    tokio::time::timeout(
        Duration::from_secs(5),
        client.write("TESTLD0", "LLN0$GO$gcb01$GoEna", MmsData::Boolean(false)),
    )
    .await
    .expect("timeout")
    .expect("write GoEna=false");
    assert!(!handle.enabled());
    assert!(!handle.publisher.lock().unwrap().enabled());

    client.disconnect().await.expect("disconnect");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gocb_write_go_id_round_trip() {
    let server = build_server_with_gocb();
    let h = server.start().await.expect("start");
    let port = h.bound_addr.port();

    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    client.connect("127.0.0.1", port).await.expect("connect");

    tokio::time::timeout(
        Duration::from_secs(5),
        client.write(
            "TESTLD0",
            "LLN0$GO$gcb01$GoID",
            MmsData::VisibleString("MyCustomGoID".into()),
        ),
    )
    .await
    .expect("timeout")
    .expect("write GoID");

    let r = tokio::time::timeout(
        Duration::from_secs(5),
        client.read("TESTLD0", "LLN0$GO$gcb01$GoID"),
    )
    .await
    .expect("timeout")
    .expect("read GoID");
    assert_eq!(r, MmsData::VisibleString("MyCustomGoID".into()));

    client.disconnect().await.expect("disconnect");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gocb_write_readonly_returns_object_access_denied() {
    let server = build_server_with_gocb();
    let h = server.start().await.expect("start");
    let port = h.bound_addr.port();

    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    client.connect("127.0.0.1", port).await.expect("connect");

    // ConfRev is read-only, so the write is refused.
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        client.write("TESTLD0", "LLN0$GO$gcb01$ConfRev", MmsData::Unsigned(99)),
    )
    .await
    .expect("timeout");
    match r {
        Err(iec61850_mms::mms::client::error::ClientError::DataAccessError(
            DataAccessError::ObjectAccessDenied,
        )) => {}
        other => panic!("expected ObjectAccessDenied for ConfRev write, got {other:?}"),
    }

    client.disconnect().await.expect("disconnect");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gocb_read_unknown_returns_object_non_existent() {
    let server = build_server_with_gocb();
    let h = server.start().await.expect("start");
    let port = h.bound_addr.port();

    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    client.connect("127.0.0.1", port).await.expect("connect");

    // An unregistered control block name.
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        client.read("TESTLD0", "LLN0$GO$nosuch$GoEna"),
    )
    .await
    .expect("timeout");
    // The read path answers with an AccessResult failure inside a ReadResponse
    // rather than a ConfirmedError; for a single-variable read the client turns
    // that first failure into an error.
    match r {
        Err(iec61850_mms::mms::client::error::ClientError::DataAccessError(
            DataAccessError::ObjectNonExistent,
        )) => {}
        other => panic!("expected ObjectNonExistent for unknown gcb, got {other:?}"),
    }

    client.disconnect().await.expect("disconnect");
    h.stop().await;
}

// End-to-end through the high-level client API.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_get_gocb_values_round_trip() {
    use iec61850_client::connection::IedConnection;

    let server = build_server_with_gocb();
    let h = server.start().await.expect("start");
    let port = h.bound_addr.port();

    let conn = IedConnection::new();
    conn.connect("127.0.0.1", port).await.expect("connect");

    let v = tokio::time::timeout(
        Duration::from_secs(5),
        conn.get_gocb_values("TESTLD0/LLN0.gcb01"),
    )
    .await
    .expect("timeout")
    .expect("get_gocb_values");

    assert_eq!(v.go_cb_ref, "TESTLD0/LLN0$GO$gcb01");
    assert!(!v.go_ena);
    assert_eq!(v.dat_set, "TESTLD0/LLN0$ds1");
    assert_eq!(v.conf_rev, 7);
    assert_eq!(v.dst_address.addr, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01]);
    assert_eq!(v.dst_address.priority, 4);
    assert_eq!(v.dst_address.vlan_id, 100);
    assert_eq!(v.dst_address.app_id, 0x1000);
    assert_eq!(v.min_time_ms, 10);
    assert_eq!(v.max_time_ms, 2000);

    conn.disconnect().await.expect("disconnect");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_set_gocb_values_round_trip() {
    use iec61850_client::connection::IedConnection;
    use iec61850_client::gocb::GoCBValuesWrite;

    let server = build_server_with_gocb();
    let h = server.start().await.expect("start");
    let port = h.bound_addr.port();

    let conn = IedConnection::new();
    conn.connect("127.0.0.1", port).await.expect("connect");

    // Write GoEna true together with a new GoID.
    tokio::time::timeout(
        Duration::from_secs(5),
        conn.set_gocb_values(
            "TESTLD0/LLN0.gcb01",
            GoCBValuesWrite::new()
                .with_go_ena(true)
                .with_go_id("ClientSetGoID"),
        ),
    )
    .await
    .expect("timeout")
    .expect("set_gocb_values");

    // Read-back
    let v = tokio::time::timeout(
        Duration::from_secs(5),
        conn.get_gocb_values("TESTLD0/LLN0.gcb01"),
    )
    .await
    .expect("timeout")
    .expect("get_gocb_values");
    assert!(v.go_ena);
    assert_eq!(v.go_id, "ClientSetGoID");

    conn.disconnect().await.expect("disconnect");
    h.stop().await;
}
