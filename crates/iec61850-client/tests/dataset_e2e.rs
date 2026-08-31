//! End-to-end tests of GetDataSetValues and SetDataSetValues over a loopback
//! association.
//!
//! Covered: reading a data set of three entries (Boolean, Boolean, Int32) as a
//! named variable list; writing it back and reading the new values; a data set
//! that does not exist, which reports `ObjectNonExistent` per entry; and a
//! write whose value count differs from the entry count, which reports
//! `TypeInconsistent` per entry.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iec61850_client::IedConnection;
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_mms::{AccessResult, MmsData, WriteOutcome};
use iec61850_model::{
    DataAttribute, DataAttributeType, IedModel, IedModelBuilder, LogicalDeviceBuilder,
    LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::{Dataset, DatasetEntry, IedServer, IedServerConfig};

const DOMAIN: &str = "IED1LD0";
const DS_NAME: &str = "GGIO1$ds1";

fn build_model() -> Arc<IedModel> {
    let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
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

/// Registers a data set, not bound to any RCB, with three entries:
/// Boolean(true), Boolean(false) and Integer.
/// - 2: Integer(42)
fn register_three_entry_dataset(server: &IedServer) -> Vec<DataAttribute> {
    let da_b1 = DataAttribute::new(
        "stVal",
        FC::St,
        DataAttributeType::Boolean,
        TrgOps::DCHG,
        MmsValue::Boolean(true),
    );
    let da_b2 = DataAttribute::new(
        "stVal",
        FC::St,
        DataAttributeType::Boolean,
        TrgOps::DCHG,
        MmsValue::Boolean(false),
    );
    let da_i = DataAttribute::new(
        "stVal",
        FC::St,
        DataAttributeType::Int32,
        TrgOps::DCHG,
        MmsValue::Integer(42),
    );

    let mut ds = Dataset::new(DS_NAME);
    ds.push(DatasetEntry::new(
        "IED1LD0/GGIO1$ST$Ind1$stVal".to_string(),
        Arc::clone(&da_b1.value),
    ));
    ds.push(DatasetEntry::new(
        "IED1LD0/GGIO1$ST$Ind2$stVal".to_string(),
        Arc::clone(&da_b2.value),
    ));
    ds.push(DatasetEntry::new(
        "IED1LD0/GGIO1$ST$IntIn1$stVal".to_string(),
        Arc::clone(&da_i.value),
    ));
    server.register_dataset(DOMAIN, ds);

    vec![da_b1, da_b2, da_i]
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dataset_get_values_three_entries() {
    let server = build_server();
    let _das = register_three_entry_dataset(&server);
    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    let conn = fresh_client(port).await;

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        conn.get_data_set_values("IED1LD0/GGIO1.ds1"),
    )
    .await
    .expect("timeout")
    .expect("get_data_set_values");

    assert_eq!(result.len(), 3, "expected three entries");
    assert!(matches!(
        result[0],
        AccessResult::Success(MmsData::Boolean(true))
    ));
    assert!(matches!(
        result[1],
        AccessResult::Success(MmsData::Boolean(false))
    ));
    assert!(matches!(
        result[2],
        AccessResult::Success(MmsData::Integer(42))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dataset_set_then_get_round_trip() {
    let server = build_server();
    let _das = register_three_entry_dataset(&server);
    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    let conn = fresh_client(port).await;

    // Write a new value for each of the three entries.
    let new_values = vec![
        MmsValue::Boolean(false),
        MmsValue::Boolean(true),
        MmsValue::Integer(99),
    ];
    let outcomes = tokio::time::timeout(
        Duration::from_secs(5),
        conn.set_data_set_values("IED1LD0/GGIO1.ds1", new_values),
    )
    .await
    .expect("timeout")
    .expect("set_data_set_values");
    assert_eq!(outcomes.len(), 3);
    for o in &outcomes {
        assert!(matches!(o, WriteOutcome::Success));
    }

    // Read them back.
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        conn.get_data_set_values("IED1LD0/GGIO1.ds1"),
    )
    .await
    .expect("timeout")
    .expect("get_data_set_values");
    assert!(matches!(
        result[0],
        AccessResult::Success(MmsData::Boolean(false))
    ));
    assert!(matches!(
        result[1],
        AccessResult::Success(MmsData::Boolean(true))
    ));
    assert!(matches!(
        result[2],
        AccessResult::Success(MmsData::Integer(99))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dataset_not_registered_returns_object_nonexistent() {
    let server = build_server();
    // Deliberately register no data set.
    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    let conn = fresh_client(port).await;

    // An unknown data set is reported per entry: the read itself succeeds on
    // the wire and every access result is a failure, which the client passes on.
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        conn.get_data_set_values("IED1LD0/GGIO1.ds_unknown"),
    )
    .await
    .expect("timeout")
    .expect("get_data_set_values");
    assert_eq!(result.len(), 1);
    assert!(matches!(
        result[0],
        AccessResult::Failure(iec61850_mms::DataAccessError::ObjectNonExistent)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dataset_set_wrong_count_returns_type_inconsistent() {
    let server = build_server();
    let _das = register_three_entry_dataset(&server);
    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    let conn = fresh_client(port).await;

    // The data set has three entries; the client supplies two.
    let outcomes = tokio::time::timeout(
        Duration::from_secs(5),
        conn.set_data_set_values(
            "IED1LD0/GGIO1.ds1",
            vec![MmsValue::Boolean(false), MmsValue::Boolean(true)],
        ),
    )
    .await
    .expect("timeout")
    .expect("set_data_set_values");
    // A length mismatch fails every entry.
    assert_eq!(outcomes.len(), 2);
    for o in &outcomes {
        assert!(matches!(
            o,
            WriteOutcome::Failure(iec61850_mms::DataAccessError::TypeInconsistent)
        ));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dataset_get_not_connected_rejected_locally() {
    let mms_client = MmsClientBuilder::new().build();
    let conn = IedConnection::with_mms_client(mms_client);
    let r = conn.get_data_set_values("IED1LD0/GGIO1.ds1").await;
    assert!(matches!(r, Err(iec61850_client::ClientError::NotConnected)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dataset_mms_notation_also_accepted() {
    let server = build_server();
    let _das = register_three_entry_dataset(&server);
    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    let conn = fresh_client(port).await;

    // The same data set, addressed in MMS notation.
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        conn.get_data_set_values("IED1LD0/GGIO1$ds1"),
    )
    .await
    .expect("timeout")
    .expect("get_data_set_values");
    assert_eq!(result.len(), 3);
}
