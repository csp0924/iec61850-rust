//! The write access policy changed while the server runs: our client writes
//! to our server through the full ISO stack, and each change of the policy
//! applies to the next Write.

use std::net::SocketAddr;
use std::sync::Arc;

use iec61850_mms::mms::client::{ClientError, MmsClient, MmsClientBuilder};
use iec61850_mms::mms::MmsData;
use iec61850_mms::DataAccessError;
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObject, DoChild, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNode, LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::{IedServer, IedServerConfig, ServerHandle, WriteAccessPolicies};

const DOMAIN: &str = "IED1LD0";
const SP_ITEM: &str = "GGIO1$SP$Set$setVal";
const CF_ITEM: &str = "GGIO1$CF$Set$cfgVal";

fn model() -> Arc<IedModel> {
    let set = DataObject::new(
        "Set",
        vec![
            DoChild::Da(DataAttribute::new(
                "setVal",
                FC::Sp,
                DataAttributeType::Int32,
                TrgOps::default(),
                MmsValue::Integer(0),
            )),
            DoChild::Da(DataAttribute::new(
                "cfgVal",
                FC::Cf,
                DataAttributeType::Int32,
                TrgOps::default(),
                MmsValue::Integer(0),
            )),
        ],
    );
    let ggio = LogicalNode::new(String::new(), "GGIO", "1", vec![set]);
    let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
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

/// Starts a server with `policies` and connects our client to it.
async fn start(policies: WriteAccessPolicies) -> (IedServer, ServerHandle, MmsClient) {
    let mut config = IedServerConfig::default();
    config.write_access_policies = policies;
    let server = IedServer::builder()
        .model(model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(config)
        .build()
        .expect("build server");
    let handle = server.start().await.expect("start server");
    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(5_000)
        .request_timeout_ms(5_000)
        .build();
    client
        .connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    (server, handle, client)
}

async fn write(client: &mut MmsClient, item: &str, value: i32) -> Result<(), ClientError> {
    client
        .write(DOMAIN, item, MmsData::Integer(value.into()))
        .await
}

async fn read(client: &mut MmsClient, item: &str) -> MmsData {
    client.read(DOMAIN, item).await.expect("read")
}

fn assert_denied(result: Result<(), ClientError>) {
    match result {
        Err(ClientError::DataAccessError(DataAccessError::ObjectAccessDenied)) => {}
        other => panic!("expected object-access-denied, got {other:?}"),
    }
}

#[tokio::test]
async fn closing_and_reopening_a_constraint_while_running_applies_to_the_next_write() {
    let (server, handle, mut client) = start(WriteAccessPolicies::default()).await;

    // control: SP is writable under the default policy, and allowing it
    // again keeps it writable
    server.set_write_access_policy(FC::Sp, true).unwrap();
    write(&mut client, SP_ITEM, 1)
        .await
        .expect("SP is writable");
    assert_eq!(read(&mut client, SP_ITEM).await, MmsData::Integer(1));

    server.set_write_access_policy(FC::Sp, false).unwrap();
    assert!(!server.write_access_allowed(FC::Sp));
    assert_denied(write(&mut client, SP_ITEM, 2).await);
    assert_eq!(
        read(&mut client, SP_ITEM).await,
        MmsData::Integer(1),
        "a denied write leaves the value"
    );

    server.set_write_access_policy(FC::Sp, true).unwrap();
    write(&mut client, SP_ITEM, 3)
        .await
        .expect("SP writable again");
    assert_eq!(read(&mut client, SP_ITEM).await, MmsData::Integer(3));

    client.disconnect().await.expect("release");
    handle.stop().await;
}

#[tokio::test]
async fn opening_a_constraint_while_running_applies_to_the_next_write() {
    let (server, handle, mut client) = start(WriteAccessPolicies::default()).await;

    // control: CF is not writable under the default policy
    assert_denied(write(&mut client, CF_ITEM, 5).await);

    server.set_write_access_policy(FC::Cf, true).unwrap();
    write(&mut client, CF_ITEM, 5).await.expect("CF opened");
    assert_eq!(read(&mut client, CF_ITEM).await, MmsData::Integer(5));

    let shared = server.write_access_policies();
    shared.set(FC::Cf, false);
    assert!(!server.write_access_allowed(FC::Cf));
    assert_denied(write(&mut client, CF_ITEM, 6).await);

    client.disconnect().await.expect("release");
    handle.stop().await;
}

#[tokio::test]
async fn a_change_reaches_an_association_opened_before_it() {
    let (server, handle, mut first) = start(WriteAccessPolicies::default()).await;
    let mut second = MmsClientBuilder::new()
        .connect_timeout_ms(5_000)
        .request_timeout_ms(5_000)
        .build();
    second
        .connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");

    server.set_write_access_policy(FC::Sp, false).unwrap();
    assert_denied(write(&mut first, SP_ITEM, 7).await);
    assert_denied(write(&mut second, SP_ITEM, 7).await);

    first.disconnect().await.expect("release");
    second.disconnect().await.expect("release");
    handle.stop().await;
}
