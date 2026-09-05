//! End-to-end tests of the Confirmed-ErrorPDU round trip over a loopback
//! association.
//!
//! A server that refuses a request answers with a Confirmed-ErrorPDU. These
//! tests assert that the client reads it back as a typed `ServiceError` with
//! the errorClass the server chose, rather than as a parse failure: a decoder
//! that cannot read the PDU turns every refusal into the same opaque error and
//! hides which object was missing and why.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iec61850_mms::mms::pdu::service_error::subcode::{access, definition};
use iec61850_mms::mms::pdu::{DefineNamedVariableEntry, ErrorClass};
use iec61850_mms::{ClientError, MmsClient, MmsClientBuilder};
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObject, DoChild, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::{IedServer, IedServerConfig};

const DOMAIN: &str = "IED1LD0";

/// Model: GGIO1 with one boolean under ST, enough to name a real member when
/// defining a data set.
fn build_model() -> Arc<IedModel> {
    let da = DataAttribute::new(
        "stVal",
        FC::St,
        DataAttributeType::Boolean,
        TrgOps::DCHG,
        MmsValue::Boolean(true),
    );
    let ind = DataObject {
        name: "Ind1".into(),
        array_count: None,
        children: vec![DoChild::Da(da)],
    };
    let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
    let ggio = LogicalNodeBuilder::new("", "GGIO", "1")
        .add_do(ind)
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

async fn fresh_mms_client(port: u16) -> MmsClient {
    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    client.connect("127.0.0.1", port).await.expect("connect");
    client
}

fn member(reference: &str) -> DefineNamedVariableEntry {
    DefineNamedVariableEntry {
        domain_id: DOMAIN.to_string(),
        item_id: reference.to_string(),
    }
}

/// A data set the server does not hold is answered with errorClass access
/// object-non-existent, and the client reads that class back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_data_set_yields_a_typed_service_error() {
    let server = build_server();
    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    let mut client = fresh_mms_client(port).await;
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        client.get_named_variable_list_attributes(DOMAIN, "GGIO1$no_such_set"),
    )
    .await
    .expect("timeout");

    match result {
        Err(ClientError::ServiceError { error_class }) => assert_eq!(
            error_class,
            ErrorClass::Access(access::OBJECT_NON_EXISTENT),
            "an unknown data set must answer object-non-existent"
        ),
        other => panic!("expected a service error carrying an errorClass, got {other:?}"),
    }
}

/// Defining a data set whose name is already taken is answered with errorClass
/// definition object-exists, which is a different alternative of the same
/// CHOICE and must survive the round trip as such.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duplicate_data_set_name_yields_the_definition_error_class() {
    let server = build_server();
    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    let mut client = fresh_mms_client(port).await;
    let entries = vec![member("GGIO1$ST$Ind1$stVal")];

    tokio::time::timeout(
        Duration::from_secs(5),
        client.define_named_variable_list(DOMAIN, "GGIO1$ds_twice", entries.clone()),
    )
    .await
    .expect("timeout")
    .expect("the first definition must succeed");

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        client.define_named_variable_list(DOMAIN, "GGIO1$ds_twice", entries),
    )
    .await
    .expect("timeout");

    match result {
        Err(ClientError::ServiceError { error_class }) => assert_eq!(
            error_class,
            ErrorClass::Definition(definition::OBJECT_EXISTS),
            "a duplicate data set name must answer definition object-exists"
        ),
        other => panic!("expected a service error carrying an errorClass, got {other:?}"),
    }
}

/// A member reference that does not resolve against the model is answered with
/// errorClass access object-non-existent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_member_yields_a_typed_service_error() {
    let server = build_server();
    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    let mut client = fresh_mms_client(port).await;
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        client.define_named_variable_list(
            DOMAIN,
            "GGIO1$ds_bad_member",
            vec![member("GGIO1$ST$NoSuchDo$stVal")],
        ),
    )
    .await
    .expect("timeout");

    match result {
        Err(ClientError::ServiceError { error_class }) => assert_eq!(
            error_class,
            ErrorClass::Access(access::OBJECT_NON_EXISTENT),
            "an unresolvable member must answer object-non-existent"
        ),
        other => panic!("expected a service error carrying an errorClass, got {other:?}"),
    }
}

/// The refusal reaches the client as a service error and not as a parse
/// failure. Pinned separately from the errorClass so that a decoder regression
/// is visible even if the class the server picks ever changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_is_never_reported_as_a_parse_failure() {
    let server = build_server();
    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();

    let mut client = fresh_mms_client(port).await;
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        client.get_named_variable_list_attributes(DOMAIN, "GGIO1$still_missing"),
    )
    .await
    .expect("timeout");

    let err = result.expect_err("an unknown data set must fail");
    assert!(
        !matches!(err, ClientError::PduParse(_)),
        "a Confirmed-ErrorPDU the server sent must be decodable, got {err:?}"
    );
    assert!(
        matches!(err, ClientError::ServiceError { .. }),
        "expected a service error, got {err:?}"
    );
}
