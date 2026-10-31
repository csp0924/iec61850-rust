//! End-to-end tests of CreateDataSet and DeleteDataSet over a loopback
//! association.
//!
//! Covered: creating a data set and reading its entries back; creating one
//! under a name already taken, which the server refuses; naming a member that
//! does not exist, which the server refuses; deleting a data set, after which
//! reading it reports `ObjectNonExistent`; deleting one that was never created,
//! which reports that nothing was deleted rather than an error; deleting a
//! static data set, which is not deletable; and deleting a data set a report
//! control block refers to, which the server refuses while reporting how many
//! data sets it deleted.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iec61850_client::dataset_admin::DataSetMember;
use iec61850_client::{ClientError, ErrorClass, IedConnection, ServiceSpecificInfo};
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_mms::mms::pdu::service_error::subcode::service;
use iec61850_mms::AccessResult;
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObject, DoChild, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::{Dataset, DatasetEntry, IedServer, IedServerConfig, Rcb, ReportControl};

const DOMAIN: &str = "IED1LD0";

/// Model: GGIO1.Ind1.stVal and Ind2.stVal as Booleans, IntIn1.stVal as an
/// Integer.
fn build_model() -> Arc<IedModel> {
    fn make_bool_do(name: &str, init: bool) -> DataObject {
        let da = DataAttribute::new(
            "stVal",
            FC::St,
            DataAttributeType::Boolean,
            TrgOps::DCHG,
            MmsValue::Boolean(init),
        );
        DataObject::new(name, vec![DoChild::Da(da)])
    }
    let int_do = {
        let da = DataAttribute::new(
            "stVal",
            FC::St,
            DataAttributeType::Int32,
            TrgOps::DCHG,
            MmsValue::Integer(42),
        );
        DataObject::new("IntIn1", vec![DoChild::Da(da)])
    };
    let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
    let ggio = LogicalNodeBuilder::new("", "GGIO", "1")
        .add_do(make_bool_do("Ind1", true))
        .add_do(make_bool_do("Ind2", false))
        .add_do(int_do)
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
    let mut cfg = IedServerConfig::default();
    cfg.max_mms_connections = 5;
    IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(cfg)
        .build()
        .expect("build server")
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

fn members_two() -> Vec<DataSetMember> {
    vec![
        DataSetMember::new("IED1LD0/GGIO1.Ind1.stVal", FC::St),
        DataSetMember::new("IED1LD0/GGIO1.Ind2.stVal", FC::St),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_then_read_then_delete_round_trip() {
    let server = build_server();
    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    let conn = fresh_client(port).await;

    // 1. create
    tokio::time::timeout(
        Duration::from_secs(5),
        conn.create_data_set("IED1LD0/GGIO1.ds_dyn1", &members_two()),
    )
    .await
    .expect("create timeout")
    .expect("create OK");

    assert_eq!(server.dynamic_dataset_count(), 1);

    // The new data set reads back its two Boolean entries.
    let results = tokio::time::timeout(
        Duration::from_secs(5),
        conn.get_data_set_values("IED1LD0/GGIO1.ds_dyn1"),
    )
    .await
    .expect("read timeout")
    .expect("read OK");
    assert_eq!(results.len(), 2);
    for r in &results {
        assert!(matches!(r, AccessResult::Success(_)), "got: {:?}", r);
    }

    // 3. delete
    let deleted = tokio::time::timeout(
        Duration::from_secs(5),
        conn.delete_data_set("IED1LD0/GGIO1.ds_dyn1"),
    )
    .await
    .expect("delete timeout")
    .expect("delete call OK");
    assert!(deleted, "the server should report the data set as deleted");
    assert_eq!(server.dynamic_dataset_count(), 0);

    // Reading it again fails the service: the data set no longer exists.
    let results2 = tokio::time::timeout(
        Duration::from_secs(5),
        conn.get_data_set_values("IED1LD0/GGIO1.ds_dyn1"),
    )
    .await
    .expect("read2 timeout");
    assert!(results2.is_err(), "got: {results2:?}");

    let _ = conn.disconnect().await;
    let _ = handle.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_duplicate_name_returns_err() {
    let server = build_server();
    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    let conn = fresh_client(port).await;

    conn.create_data_set("IED1LD0/GGIO1.ds_dup", &members_two())
        .await
        .expect("first create OK");

    let err = tokio::time::timeout(
        Duration::from_secs(5),
        conn.create_data_set("IED1LD0/GGIO1.ds_dup", &members_two()),
    )
    .await
    .expect("dup create timeout")
    .expect_err("the second create should fail");
    // The exact service error class is not asserted; only that the call failed.
    let msg = format!("{err:?}");
    assert!(msg.contains("Mms") || msg.contains("Definition"), "{msg}");

    assert_eq!(
        server.dynamic_dataset_count(),
        1,
        "the registry must not gain a duplicate"
    );

    let _ = conn.disconnect().await;
    let _ = handle.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_with_bad_member_returns_err() {
    let server = build_server();
    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    let conn = fresh_client(port).await;

    let bad = vec![DataSetMember::new("IED1LD0/BogusLN.X.Y", FC::St)];

    let err = tokio::time::timeout(
        Duration::from_secs(5),
        conn.create_data_set("IED1LD0/GGIO1.ds_bad", &bad),
    )
    .await
    .expect("create timeout")
    .expect_err("a member that does not exist should fail");
    let _ = err; // the precise error mapping is left to the server

    assert_eq!(server.dynamic_dataset_count(), 0);

    let _ = conn.disconnect().await;
    let _ = handle.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_nonexistent_returns_false_not_err() {
    let server = build_server();
    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    let conn = fresh_client(port).await;

    // Nothing was ever created, so the server deletes nothing and reports false.
    let deleted = tokio::time::timeout(
        Duration::from_secs(5),
        conn.delete_data_set("IED1LD0/GGIO1.ds_ghost"),
    )
    .await
    .expect("timeout")
    .expect("call returns Ok");
    assert!(!deleted);

    let _ = conn.disconnect().await;
    let _ = handle.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_static_dataset_rejected_returns_false() {
    let server = build_server();

    // Register a static data set directly on the server.
    let bool_da = DataAttribute::new(
        "stVal",
        FC::St,
        DataAttributeType::Boolean,
        TrgOps::DCHG,
        MmsValue::Boolean(true),
    );
    let mut ds = Dataset::new("GGIO1$ds_static");
    ds.push(DatasetEntry::new(
        "IED1LD0/GGIO1$ST$Ind1$stVal".to_string(),
        Arc::clone(&bool_da.value),
    ));
    server.register_dataset(DOMAIN, ds);

    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    let conn = fresh_client(port).await;

    // A static data set is not deletable, so the server reports nothing deleted.
    let deleted = tokio::time::timeout(
        Duration::from_secs(5),
        conn.delete_data_set("IED1LD0/GGIO1.ds_static"),
    )
    .await
    .expect("timeout")
    .expect("call returns Ok");
    assert!(!deleted, "a static data set must not be deletable");

    // It is still readable.
    let results = conn
        .get_data_set_values("IED1LD0/GGIO1.ds_static")
        .await
        .expect("read static dataset OK");
    assert_eq!(results.len(), 1);

    let _ = conn.disconnect().await;
    let _ = handle.stop().await;
}

/// A data set a report control block refers to is not deleted: the server
/// answers the DeleteNamedVariableList with object-constraint-conflict and
/// reports, as its serviceSpecificInformation, that it deleted none
/// (ISO 9506-2). Once the control block refers to another data set, the same
/// delete succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deleting_a_data_set_in_use_reports_how_many_were_deleted() {
    let server = build_server();
    let bool_da = DataAttribute::new(
        "stVal",
        FC::St,
        DataAttributeType::Boolean,
        TrgOps::DCHG,
        MmsValue::Boolean(true),
    );
    let mut ds = Dataset::new("GGIO1$ds_urcb");
    ds.push(DatasetEntry::new(
        "IED1LD0/GGIO1$ST$Ind1$stVal".to_string(),
        Arc::clone(&bool_da.value),
    ));
    let rc = ReportControl::new(
        "IED1LD0/GGIO1$RP$urcb01",
        Rcb::new("urcb01", "GGIO1$ds_urcb"),
    );
    server.register_urcb(rc, ds).expect("register_urcb");
    let handle = server.start().await.expect("server start");
    let conn = fresh_client(handle.bound_addr.port()).await;

    within(conn.create_data_set("IED1LD0/GGIO1.ds_dyn1", &members_two()))
        .await
        .expect("create OK");
    within(conn.write_boolean("IED1LD0/GGIO1.urcb01.Resv", FC::Rp, true))
        .await
        .expect("the client reserves the URCB");
    within(conn.write_visible_string(
        "IED1LD0/GGIO1.urcb01.DatSet",
        FC::Rp,
        "IED1LD0/GGIO1$ds_dyn1",
    ))
    .await
    .expect("the URCB takes the new data set");

    let refused = within(conn.delete_data_set("IED1LD0/GGIO1.ds_dyn1")).await;
    match refused {
        Err(ClientError::Service {
            error_class,
            service_specific,
            ..
        }) => {
            assert_eq!(
                error_class,
                ErrorClass::Service(service::OBJECT_CONSTRAINT_CONFLICT)
            );
            assert_eq!(
                service_specific,
                Some(ServiceSpecificInfo::DeleteNamedVariableList(0)),
                "the refusal reports that no data set was deleted"
            );
        }
        other => panic!("expected a service error, got {other:?}"),
    }
    assert_eq!(server.dynamic_dataset_count(), 1, "the data set survives");

    within(conn.write_visible_string(
        "IED1LD0/GGIO1.urcb01.DatSet",
        FC::Rp,
        "IED1LD0/GGIO1$ds_urcb",
    ))
    .await
    .expect("the URCB takes its own data set back");
    let deleted = within(conn.delete_data_set("IED1LD0/GGIO1.ds_dyn1"))
        .await
        .expect("a data set no control block refers to is deleted");
    assert!(deleted);

    let _ = conn.disconnect().await;
    let _ = handle.stop().await;
}

/// Awaits `f` for at most five seconds.
async fn within<F: std::future::Future>(f: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(5), f)
        .await
        .expect("the call finishes within five seconds")
}
