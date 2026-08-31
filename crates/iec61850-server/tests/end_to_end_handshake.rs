//! End-to-end tests of the MMS client against the server over a real socket.
//!
//! One test drives the whole stack: TCP, COTP CR/CC, Session CN/AC,
//! Presentation CP/CPA, ACSE AARQ/AARE, MMS Initiate, a dispatched confirmed
//! request (GetNameList or Read) and finally MMS Conclude. The assertions are
//! that the Initiate handshake completes, that GetNameList(Domain) lists the
//! configured domain, that a boolean data attribute reads back, and that
//! disconnect takes the Conclude path.

use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_mms::mms::pdu::ObjectClass;
use iec61850_mms::mms::MmsData;
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObject, DataObjectBuilder, DoChild, IedModel,
    IedModelBuilder, LogicalDeviceBuilder, LogicalNode, LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::{IedServer, IedServerConfig, WriteAccessPolicies};
use std::net::SocketAddr;
use std::sync::Arc;

fn model_with_ggio() -> Arc<IedModel> {
    // One logical device LD0 with LLN0 and GGIO1, where GGIO1 carries a single
    // point status with a boolean stVal.
    let ind1_st_val = DataAttribute::new(
        "stVal",
        FC::St,
        DataAttributeType::Boolean,
        TrgOps::default(),
        MmsValue::Boolean(false),
    );
    let ind1_do = DataObject {
        name: "Ind1".into(),
        array_count: None,
        children: vec![DoChild::Da(ind1_st_val)],
    };
    let ggio = LogicalNode {
        prefix: String::new(),
        class: "GGIO".into(),
        inst: "1".into(),
        dos: vec![ind1_do],
        datasets: vec![],
        rcbs: vec![],
        gocbs: vec![],
        svcbs: vec![],
        lcbs: vec![],
        sgcb: None,
    };
    let lln0 = LogicalNodeBuilder::lln0().build().unwrap();
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .add_ln(ggio)
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

fn build_server() -> IedServer {
    let cfg = IedServerConfig {
        max_mms_connections: 5,
        ..Default::default()
    };
    IedServer::builder()
        .model(model_with_ggio())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(cfg)
        .build()
        .expect("build server")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_client_completes_full_handshake() {
    let server = build_server();
    let handle = server.start().await.expect("start");
    let port = handle.bound_addr.port();

    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    client
        .connect("127.0.0.1", port)
        .await
        .expect("client.connect");
    let max_pdu = client.negotiated_max_pdu_size();
    client.disconnect().await.expect("client.disconnect");

    assert!(max_pdu > 0, "the negotiated max PDU size must be positive");

    handle.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_client_get_name_list_returns_domain() {
    let server = build_server();
    let handle = server.start().await.expect("start");
    let port = handle.bound_addr.port();

    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    client
        .connect("127.0.0.1", port)
        .await
        .expect("client.connect");

    // A VMD-specific GetNameList(Domain) lists the configured domain.
    let (names, _more) = client
        .get_name_list(ObjectClass::Domain, None, None)
        .await
        .expect("get_name_list");
    assert!(
        names.iter().any(|n| n == "TESTLD0"),
        "GetNameList(Domain) must contain TESTLD0, got names={:?}",
        names
    );

    client.disconnect().await.expect("disconnect");
    handle.stop().await;
}

/// Write round-trip: the model carries a VisibleString data attribute with
/// FC=Dc (LLN0.NamPlt.vendor); with Dc writable the value the client writes
/// reads back unchanged.
fn model_with_writable_vendor() -> Arc<IedModel> {
    let nam_plt = DataObjectBuilder::scalar("NamPlt")
        .add_da(
            "vendor",
            FC::Dc,
            DataAttributeType::VisibleString(255),
            TrgOps::NONE,
            MmsValue::VisibleString("init".into()),
        )
        .build()
        .unwrap();
    let lln0 = LogicalNodeBuilder::lln0().add_do(nam_plt).build().unwrap();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_client_write_round_trip() {
    let mut policies = WriteAccessPolicies::default();
    policies.set(FC::Dc, true);
    let cfg = IedServerConfig {
        max_mms_connections: 5,
        write_access_policies: policies,
        ..Default::default()
    };
    let server = IedServer::builder()
        .model(model_with_writable_vendor())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(cfg)
        .build()
        .expect("build server");
    let handle = server.start().await.expect("start");
    let port = handle.bound_addr.port();

    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    client
        .connect("127.0.0.1", port)
        .await
        .expect("client.connect");

    let new_vendor = "vendor-write-probe";
    client
        .write(
            "TESTLD0",
            "LLN0$DC$NamPlt$vendor",
            MmsData::VisibleString(new_vendor.into()),
        )
        .await
        .expect("write vendor");

    let got = client
        .read("TESTLD0", "LLN0$DC$NamPlt$vendor")
        .await
        .expect("read-back vendor");
    match got {
        MmsData::VisibleString(s) => assert_eq!(s, new_vendor, "read-back must match the write"),
        other => panic!("expected VisibleString, got {other:?}"),
    }

    client.disconnect().await.expect("disconnect");
    handle.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_client_read_returns_value() {
    let server = build_server();
    let handle = server.start().await.expect("start");
    let port = handle.bound_addr.port();

    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    client
        .connect("127.0.0.1", port)
        .await
        .expect("client.connect");

    let val = client
        .read("TESTLD0", "GGIO1$ST$Ind1$stVal")
        .await
        .expect("read GGIO1.Ind1.stVal");
    // Defaults to false.
    match val {
        iec61850_mms::mms::client::MmsValue::Boolean(b) => {
            assert!(!b, "Ind1.stVal defaults to false, got {b}");
        }
        other => panic!("expected Boolean, got {other:?}"),
    }

    client.disconnect().await.expect("disconnect");
    handle.stop().await;
}
