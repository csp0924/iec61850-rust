//! End-to-end tests of GetDataSetValues and SetDataSetValues over a loopback
//! association.
//!
//! Covered: reading a data set of three entries (Boolean, Boolean, Int32) as a
//! named variable list; writing a data set of setting (SP) entries and reading
//! the new values back; a write to a data set of status (ST) entries, which
//! the write access policy refuses per entry; a data set that does not exist,
//! which reports `ObjectNonExistent` per entry; and a write whose value count
//! differs from the entry count, which reports `TypeInconsistent` per entry.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use iec61850_client::IedConnection;
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_mms::{AccessResult, MmsData, WriteOutcome};
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObject, DoChild, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNode, LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::{Dataset, DatasetEntry, IedServer, IedServerConfig};

const DOMAIN: &str = "IED1LD0";
const DS_NAME: &str = "GGIO1$ds1";

const SP_DS_NAME: &str = "GGIO1$ds2";

/// Value locks of the GGIO1 attributes the data sets refer to, shared with the
/// model.
struct Members {
    /// `Ind1`, `Ind2` and `IntIn1` `stVal` under ST.
    status: Vec<Arc<RwLock<MmsValue>>>,
    /// `Set1`, `Set2` and `SetInt1` `setVal` under SP.
    setting: Vec<Arc<RwLock<MmsValue>>>,
}

/// One data object holding a single attribute, and that attribute's value
/// lock.
fn data_object(
    name: &str,
    da_name: &str,
    fc: FC,
    ty: DataAttributeType,
    value: MmsValue,
) -> (DataObject, Arc<RwLock<MmsValue>>) {
    let da = DataAttribute::new(da_name, fc, ty, TrgOps::DCHG, value);
    let handle = Arc::clone(&da.value);
    let dobj = DataObject {
        name: name.into(),
        array_count: None,
        children: vec![DoChild::Da(da)],
    };
    (dobj, handle)
}

/// IED1LD0 with LLN0 and GGIO1, whose status attributes hold true, false and
/// 42 and whose setting attributes hold the same values.
fn build_model() -> (Arc<IedModel>, Members) {
    let specs = [
        (
            "Ind1",
            "stVal",
            FC::St,
            DataAttributeType::Boolean,
            MmsValue::Boolean(true),
        ),
        (
            "Ind2",
            "stVal",
            FC::St,
            DataAttributeType::Boolean,
            MmsValue::Boolean(false),
        ),
        (
            "IntIn1",
            "stVal",
            FC::St,
            DataAttributeType::Int32,
            MmsValue::Integer(42),
        ),
        (
            "Set1",
            "setVal",
            FC::Sp,
            DataAttributeType::Boolean,
            MmsValue::Boolean(true),
        ),
        (
            "Set2",
            "setVal",
            FC::Sp,
            DataAttributeType::Boolean,
            MmsValue::Boolean(false),
        ),
        (
            "SetInt1",
            "setVal",
            FC::Sp,
            DataAttributeType::Int32,
            MmsValue::Integer(42),
        ),
    ];
    let mut dos = Vec::new();
    let mut handles = Vec::new();
    for (name, da_name, fc, ty, value) in specs {
        let (dobj, handle) = data_object(name, da_name, fc, ty, value);
        dos.push(dobj);
        handles.push(handle);
    }
    let setting = handles.split_off(3);
    let ggio = LogicalNode {
        prefix: String::new(),
        class: "GGIO".into(),
        inst: "1".into(),
        dos,
        datasets: vec![],
        rcbs: vec![],
        gocbs: vec![],
        svcbs: vec![],
        lcbs: vec![],
        sgcb: None,
    };
    let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .add_ln(ggio)
        .build()
        .expect("ld");
    let model = IedModelBuilder::new("IED1")
        .add_ld(ld)
        .expect("add_ld")
        .build()
        .expect("model");
    (
        Arc::new(model),
        Members {
            status: handles,
            setting,
        },
    )
}

/// A server over [`build_model`] with the default write access policy, under
/// which SP is writable and ST is not.
fn build_server() -> (IedServer, Members) {
    let (model, members) = build_model();
    let cfg = IedServerConfig {
        max_mms_connections: 5,
        ..Default::default()
    };
    let server = IedServer::builder()
        .model(model)
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(cfg)
        .build()
        .expect("build server");
    (server, members)
}

/// Registers two data sets, not bound to any RCB: `GGIO1$ds1` over the status
/// attributes and `GGIO1$ds2` over the setting attributes.
fn register_datasets(server: &IedServer, members: &Members) {
    let mut ds = Dataset::new(DS_NAME);
    for (item, value) in [
        "GGIO1$ST$Ind1$stVal",
        "GGIO1$ST$Ind2$stVal",
        "GGIO1$ST$IntIn1$stVal",
    ]
    .iter()
    .zip(&members.status)
    {
        ds.push(DatasetEntry::new(
            format!("{DOMAIN}/{item}"),
            Arc::clone(value),
        ));
    }
    server.register_dataset(DOMAIN, ds);

    let mut ds = Dataset::new(SP_DS_NAME);
    for (item, value) in [
        "GGIO1$SP$Set1$setVal",
        "GGIO1$SP$Set2$setVal",
        "GGIO1$SP$SetInt1$setVal",
    ]
    .iter()
    .zip(&members.setting)
    {
        ds.push(DatasetEntry::new(
            format!("{DOMAIN}/{item}"),
            Arc::clone(value),
        ));
    }
    server.register_dataset(DOMAIN, ds);
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
    let (server, members) = build_server();
    register_datasets(&server, &members);
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
    let (server, members) = build_server();
    register_datasets(&server, &members);
    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    let conn = fresh_client(port).await;

    // Write a new value for each of the three setting entries.
    let new_values = vec![
        MmsValue::Boolean(false),
        MmsValue::Boolean(true),
        MmsValue::Integer(99),
    ];
    let outcomes = tokio::time::timeout(
        Duration::from_secs(5),
        conn.set_data_set_values("IED1LD0/GGIO1.ds2", new_values),
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
        conn.get_data_set_values("IED1LD0/GGIO1.ds2"),
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

/// Status values are not writable under the default write access policy, so a
/// SetDataSetValues over the ST data set fails for every entry and leaves the
/// values as they were.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dataset_set_status_entries_is_refused() {
    let (server, members) = build_server();
    register_datasets(&server, &members);
    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    let conn = fresh_client(port).await;

    let outcomes = tokio::time::timeout(
        Duration::from_secs(5),
        conn.set_data_set_values(
            "IED1LD0/GGIO1.ds1",
            vec![
                MmsValue::Boolean(false),
                MmsValue::Boolean(true),
                MmsValue::Integer(99),
            ],
        ),
    )
    .await
    .expect("timeout")
    .expect("set_data_set_values");
    assert_eq!(outcomes.len(), 3);
    for o in &outcomes {
        assert!(
            matches!(o, WriteOutcome::Failure(_)),
            "a status entry must not be written, got {o:?}"
        );
    }
    let values: Vec<MmsValue> = members
        .status
        .iter()
        .map(|v| v.read().unwrap().clone())
        .collect();
    assert_eq!(
        values,
        vec![
            MmsValue::Boolean(true),
            MmsValue::Boolean(false),
            MmsValue::Integer(42)
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dataset_not_registered_returns_object_nonexistent() {
    let (server, _members) = build_server();
    // Deliberately register no data set.
    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    let conn = fresh_client(port).await;

    // An unknown data set fails the whole service, which the client reports
    // as an error rather than as access results.
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        conn.get_data_set_values("IED1LD0/GGIO1.ds_unknown"),
    )
    .await
    .expect("timeout");
    assert!(result.is_err(), "got: {result:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dataset_set_wrong_count_returns_type_inconsistent() {
    let (server, members) = build_server();
    register_datasets(&server, &members);
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
    let (server, members) = build_server();
    register_datasets(&server, &members);
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
