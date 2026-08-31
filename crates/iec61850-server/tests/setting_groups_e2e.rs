//! End-to-end tests for setting group control and for the access rules on the
//! SE and SG functional constraints.
//!
//! A hand-built model drives a real client against a real server, so the tests
//! cover the wire path, the setting group state machine and the access checks
//! together. The assertions are that SelectActiveSG switches the active group
//! and reads back, that an SE write without an edit session is denied, that
//! SelectEditSG opens a session in which the owning connection can write SE
//! values and read them back, that ConfirmEditSGValues closes the session so a
//! second confirm is denied, and that a write with FC=SG is refused even when
//! the write policy allows that functional constraint.

use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_mms::mms::pdu::DataAccessError;
use iec61850_mms::mms::MmsData;
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObject, DoChild, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNode, LogicalNodeBuilder, MmsValue, SettingGroupControlBlock,
    TrgOps, FC,
};
use iec61850_server::{IedServer, IedServerConfig, WriteAccessPolicies};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Builds the setting group demonstration model:
/// - LD0/LLN0 with an SGCB carrying three groups and group 1 active.
/// - LD0/GGIO1.Setpoint.setVal (FC=SE), the staging buffer written during an
///   edit session.
/// - LD0/GGIO1.Setpoint.curVal (FC=SG), the value of the active group.
fn build_sg_demo_model() -> Arc<IedModel> {
    let set_val = DataAttribute::new(
        "setVal",
        FC::Se,
        DataAttributeType::Int32,
        TrgOps::default(),
        MmsValue::Integer(0),
    );
    let cur_val = DataAttribute::new(
        "curVal",
        FC::Sg,
        DataAttributeType::Int32,
        TrgOps::default(),
        MmsValue::Integer(0),
    );
    let setpoint = DataObject {
        name: "Setpoint".into(),
        array_count: None,
        children: vec![DoChild::Da(set_val), DoChild::Da(cur_val)],
    };
    let ggio = LogicalNode {
        prefix: String::new(),
        class: "GGIO".into(),
        inst: "1".into(),
        dos: vec![setpoint],
        datasets: vec![],
        rcbs: vec![],
        gocbs: vec![],
        svcbs: vec![],
        lcbs: vec![],
        sgcb: None,
    };
    let lln0 = LogicalNodeBuilder::lln0()
        .set_sgcb(SettingGroupControlBlock {
            num_of_sg: 3,
            act_sg: 1,
            has_resv_tms: false,
            default_resv_tms_s: 60,
        })
        .build()
        .unwrap();
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

fn build_sg_demo_server() -> IedServer {
    // SP and SE are writable so the edit session can be exercised, and CF is
    // writable so the client can drive the SGCB control attributes directly.
    let mut policies = WriteAccessPolicies::default();
    policies.set(FC::Sp, true);
    policies.set(FC::Se, true);
    policies.set(FC::Sg, true); // allowed on purpose; SG writes are refused anyway
    policies.set(FC::Cf, true);
    let cfg = IedServerConfig {
        max_mms_connections: 5,
        write_access_policies: policies,
        ..Default::default()
    };
    IedServer::builder()
        .model(build_sg_demo_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(cfg)
        .build()
        .expect("build server")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn select_active_sg_round_trip() {
    let server = build_sg_demo_server();
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

    // Switch the active setting group to 2.
    tokio::time::timeout(
        Duration::from_secs(5),
        client.write("TESTLD0", "LLN0$SP$SGCB$ActSG", MmsData::Unsigned(2)),
    )
    .await
    .expect("write timeout")
    .expect("SelectActiveSG should succeed");

    // Read ActSG back.
    let val = tokio::time::timeout(
        Duration::from_secs(5),
        client.read("TESTLD0", "LLN0$SP$SGCB$ActSG"),
    )
    .await
    .expect("read timeout")
    .expect("read ActSG");
    match val {
        MmsData::Unsigned(n) => assert_eq!(n, 2, "ActSG should reflect new value"),
        other => panic!("expected Unsigned, got {other:?}"),
    }

    client.disconnect().await.expect("disconnect");
    handle.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn edit_sg_confirm_round_trip_persists_se_fc_value() {
    let server = build_sg_demo_server();
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

    // An SE write without an edit session is denied.
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        client.write("TESTLD0", "GGIO1$SE$Setpoint$setVal", MmsData::Integer(11)),
    )
    .await
    .expect("write timeout");
    match r {
        Err(iec61850_mms::mms::client::error::ClientError::DataAccessError(
            DataAccessError::ObjectAccessDenied,
        )) => {}
        other => panic!("expected ObjectAccessDenied for SE without session, got {other:?}"),
    }

    // 2. EditSG = 2
    tokio::time::timeout(
        Duration::from_secs(5),
        client.write("TESTLD0", "LLN0$SP$SGCB$EditSG", MmsData::Unsigned(2)),
    )
    .await
    .expect("write timeout")
    .expect("EditSG=2 should succeed");

    // An SE write from the connection that owns the session succeeds.
    tokio::time::timeout(
        Duration::from_secs(5),
        client.write("TESTLD0", "GGIO1$SE$Setpoint$setVal", MmsData::Integer(42)),
    )
    .await
    .expect("write timeout")
    .expect("SE write by edit owner should succeed");

    // The new value reads back.
    let val = tokio::time::timeout(
        Duration::from_secs(5),
        client.read("TESTLD0", "GGIO1$SE$Setpoint$setVal"),
    )
    .await
    .expect("read timeout")
    .expect("read SE");
    match val {
        MmsData::Integer(n) => assert_eq!(n, 42, "SE value should persist after write"),
        other => panic!("expected Integer, got {other:?}"),
    }

    // 5. CnfEdit = true
    tokio::time::timeout(
        Duration::from_secs(5),
        client.write("TESTLD0", "LLN0$SP$SGCB$CnfEdit", MmsData::Boolean(true)),
    )
    .await
    .expect("write timeout")
    .expect("CnfEdit should succeed");

    // The session is closed, so a second confirm is refused.
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        client.write("TESTLD0", "LLN0$SP$SGCB$CnfEdit", MmsData::Boolean(true)),
    )
    .await
    .expect("write timeout");
    match r {
        Err(iec61850_mms::mms::client::error::ClientError::DataAccessError(
            DataAccessError::ObjectAccessDenied,
        )) => {}
        other => panic!("expected ObjectAccessDenied after session cleared, got {other:?}"),
    }

    // An SE write after the session closed is refused as well.
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        client.write("TESTLD0", "GGIO1$SE$Setpoint$setVal", MmsData::Integer(99)),
    )
    .await
    .expect("write timeout");
    match r {
        Err(iec61850_mms::mms::client::error::ClientError::DataAccessError(
            DataAccessError::ObjectAccessDenied,
        )) => {}
        other => panic!("expected ObjectAccessDenied for SE after CnfEdit, got {other:?}"),
    }

    client.disconnect().await.expect("disconnect");
    handle.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sg_fc_write_always_denied_even_with_policy() {
    let server = build_sg_demo_server();
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

    // A write with FC=SG is always refused, whatever the write policy allows;
    // setting group values are only changed through an SE edit session.
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        client.write("TESTLD0", "GGIO1$SG$Setpoint$curVal", MmsData::Integer(7)),
    )
    .await
    .expect("write timeout");
    match r {
        Err(iec61850_mms::mms::client::error::ClientError::DataAccessError(
            DataAccessError::ObjectAccessDenied,
        )) => {}
        other => panic!("expected ObjectAccessDenied for SG-FC write, got {other:?}"),
    }

    client.disconnect().await.expect("disconnect");
    handle.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_client_cannot_steal_edit_session() {
    let server = build_sg_demo_server();
    let handle = server.start().await.expect("start");
    let port = handle.bound_addr.port();

    // Client A opens the edit session.
    let mut client_a = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    client_a
        .connect("127.0.0.1", port)
        .await
        .expect("A connect");
    tokio::time::timeout(
        Duration::from_secs(5),
        client_a.write("TESTLD0", "LLN0$SP$SGCB$EditSG", MmsData::Unsigned(2)),
    )
    .await
    .expect("A timeout")
    .expect("A EditSG=2");

    // Client B cannot take the session over and gets TemporarilyUnavailable.
    let mut client_b = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    client_b
        .connect("127.0.0.1", port)
        .await
        .expect("B connect");
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        client_b.write("TESTLD0", "LLN0$SP$SGCB$EditSG", MmsData::Unsigned(3)),
    )
    .await
    .expect("B timeout");
    match r {
        Err(iec61850_mms::mms::client::error::ClientError::DataAccessError(
            DataAccessError::TemporarilyUnavailable,
        )) => {}
        other => panic!("expected TemporarilyUnavailable for B, got {other:?}"),
    }

    // Client B cannot write SE values either; it does not own the session.
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        client_b.write("TESTLD0", "GGIO1$SE$Setpoint$setVal", MmsData::Integer(77)),
    )
    .await
    .expect("B SE timeout");
    match r {
        Err(iec61850_mms::mms::client::error::ClientError::DataAccessError(
            DataAccessError::ObjectAccessDenied,
        )) => {}
        other => panic!("expected ObjectAccessDenied for B SE write, got {other:?}"),
    }

    client_a.disconnect().await.expect("A disconnect");
    client_b.disconnect().await.expect("B disconnect");
    handle.stop().await;
}
