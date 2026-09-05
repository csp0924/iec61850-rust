//! End-to-end tests of GetDataSetDirectory over a loopback association.
//!
//! Covered: a configured data set of three members across two functional
//! constraints, whose directory keeps the registration order and reports
//! `deletable == false`; a data set created at runtime, whose directory matches
//! what was created and reports `deletable == true`, and which is gone after
//! DeleteDataSet; and a name the server does not hold, which fails rather than
//! returning an empty member list.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iec61850_client::dataset_admin::DataSetMember;
use iec61850_client::IedConnection;
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObject, DoChild, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::{Dataset, DatasetEntry, IedServer, IedServerConfig};

const DOMAIN: &str = "IED1LD0";
const STATIC_DS_NAME: &str = "GGIO1$ds_static";

/// Model: GGIO1 with `Ind1.stVal` and `Ind2.stVal` under ST and `AnIn1.mag`
/// under MX, so a data set can mix functional constraints.
fn build_model() -> Arc<IedModel> {
    fn bool_do(name: &str, init: bool) -> DataObject {
        let da = DataAttribute::new(
            "stVal",
            FC::St,
            DataAttributeType::Boolean,
            TrgOps::DCHG,
            MmsValue::Boolean(init),
        );
        DataObject {
            name: name.into(),
            array_count: None,
            children: vec![DoChild::Da(da)],
        }
    }
    let analog_do = {
        let da = DataAttribute::new(
            "mag",
            FC::Mx,
            DataAttributeType::Float32,
            TrgOps::DCHG,
            MmsValue::Float32(1.5),
        );
        DataObject {
            name: "AnIn1".into(),
            array_count: None,
            children: vec![DoChild::Da(da)],
        }
    };

    let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
    let ggio = LogicalNodeBuilder::new("", "GGIO", "1")
        .add_do(bool_do("Ind1", true))
        .add_do(bool_do("Ind2", false))
        .add_do(analog_do)
        .build()
        .expect("GGIO1");
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .add_ln(ggio)
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

fn build_server() -> IedServer {
    let cfg = IedServerConfig {
        max_mms_connections: 5,
        ..Default::default()
    };
    IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(cfg)
        .build()
        .expect("build server")
}

/// Registers a configured data set of three members, in this order:
/// `Ind1.stVal` (ST), `AnIn1.mag` (MX), `Ind2.stVal` (ST). The order differs
/// from the model declaration order so that a directory that sorts rather than
/// preserves order is visible.
fn register_static_dataset(server: &IedServer) -> Vec<DataAttribute> {
    let da_b1 = DataAttribute::new(
        "stVal",
        FC::St,
        DataAttributeType::Boolean,
        TrgOps::DCHG,
        MmsValue::Boolean(true),
    );
    let da_f = DataAttribute::new(
        "mag",
        FC::Mx,
        DataAttributeType::Float32,
        TrgOps::DCHG,
        MmsValue::Float32(1.5),
    );
    let da_b2 = DataAttribute::new(
        "stVal",
        FC::St,
        DataAttributeType::Boolean,
        TrgOps::DCHG,
        MmsValue::Boolean(false),
    );

    let mut ds = Dataset::new(STATIC_DS_NAME);
    ds.push(DatasetEntry::new(
        "IED1LD0/GGIO1$ST$Ind1$stVal".to_string(),
        Arc::clone(&da_b1.value),
    ));
    ds.push(DatasetEntry::new(
        "IED1LD0/GGIO1$MX$AnIn1$mag".to_string(),
        Arc::clone(&da_f.value),
    ));
    ds.push(DatasetEntry::new(
        "IED1LD0/GGIO1$ST$Ind2$stVal".to_string(),
        Arc::clone(&da_b2.value),
    ));
    server.register_dataset(DOMAIN, ds);

    vec![da_b1, da_f, da_b2]
}

async fn fresh_client(port: u16) -> IedConnection {
    let mms_client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    let conn = IedConnection::with_mms_client(mms_client);
    conn.connect("127.0.0.1", port)
        .await
        .expect("client.connect");
    conn
}

fn dynamic_members() -> Vec<DataSetMember> {
    vec![
        DataSetMember::new("IED1LD0/GGIO1.Ind2.stVal", FC::St),
        DataSetMember::new("IED1LD0/GGIO1.AnIn1.mag", FC::Mx),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn static_dataset_directory_keeps_order_and_is_not_deletable() {
    let server = build_server();
    let _das = register_static_dataset(&server);
    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    let conn = fresh_client(port).await;

    let dir = tokio::time::timeout(
        Duration::from_secs(5),
        conn.get_data_set_directory("IED1LD0/GGIO1.ds_static"),
    )
    .await
    .expect("timeout")
    .expect("get_data_set_directory");

    assert!(
        !dir.deletable,
        "a configured data set must report mmsDeletable false"
    );
    assert_eq!(dir.members.len(), 3, "expected three members");

    let refs: Vec<&str> = dir.members.iter().map(|m| m.reference.as_str()).collect();
    assert_eq!(
        refs,
        vec![
            "IED1LD0/GGIO1.Ind1.stVal",
            "IED1LD0/GGIO1.AnIn1.mag",
            "IED1LD0/GGIO1.Ind2.stVal",
        ],
        "members must come back in registration order"
    );

    let fcs: Vec<FC> = dir.members.iter().map(|m| m.fc).collect();
    assert_eq!(fcs, vec![FC::St, FC::Mx, FC::St]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dynamic_dataset_directory_matches_creation_and_is_deletable() {
    let server = build_server();
    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    let conn = fresh_client(port).await;

    tokio::time::timeout(
        Duration::from_secs(5),
        conn.create_data_set("IED1LD0/GGIO1.ds_dyn", &dynamic_members()),
    )
    .await
    .expect("create timeout")
    .expect("create OK");
    assert_eq!(server.dynamic_dataset_count(), 1);

    let dir = tokio::time::timeout(
        Duration::from_secs(5),
        conn.get_data_set_directory("IED1LD0/GGIO1.ds_dyn"),
    )
    .await
    .expect("timeout")
    .expect("get_data_set_directory");

    assert!(
        dir.deletable,
        "a data set created at runtime must report mmsDeletable true"
    );
    let got: Vec<(String, FC)> = dir
        .members
        .iter()
        .map(|m| (m.reference.clone(), m.fc))
        .collect();
    let expected: Vec<(String, FC)> = dynamic_members()
        .iter()
        .map(|m| (m.reference.clone(), m.fc))
        .collect();
    assert_eq!(got, expected, "directory must match what was created");

    // After deletion the directory request fails rather than returning an
    // empty member list.
    let deleted = tokio::time::timeout(
        Duration::from_secs(5),
        conn.delete_data_set("IED1LD0/GGIO1.ds_dyn"),
    )
    .await
    .expect("delete timeout")
    .expect("delete call OK");
    assert!(deleted, "the dynamic data set must be deleted");

    let after = tokio::time::timeout(
        Duration::from_secs(5),
        conn.get_data_set_directory("IED1LD0/GGIO1.ds_dyn"),
    )
    .await
    .expect("timeout");
    assert!(
        after.is_err(),
        "a deleted data set must not answer a directory request: {after:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_dataset_directory_is_an_error_not_an_empty_list() {
    let server = build_server();
    let _das = register_static_dataset(&server);
    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    let conn = fresh_client(port).await;

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        conn.get_data_set_directory("IED1LD0/GGIO1.ds_absent"),
    )
    .await
    .expect("timeout");

    assert!(result.is_err(), "an unknown data set must fail: {result:?}");

    // The association survives the refusal and still serves the data set that
    // does exist.
    let dir = tokio::time::timeout(
        Duration::from_secs(5),
        conn.get_data_set_directory("IED1LD0/GGIO1.ds_static"),
    )
    .await
    .expect("timeout")
    .expect("get_data_set_directory");
    assert_eq!(dir.members.len(), 3);
}
