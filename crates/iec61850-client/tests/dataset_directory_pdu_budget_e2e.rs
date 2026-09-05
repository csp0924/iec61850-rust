//! End-to-end coverage of the outbound size limit on the data set services.
//!
//! A client that negotiates a small maximum PDU size cannot accept the
//! directory, nor the values, of a data set with many members. The server
//! measures what it is about to send against the negotiated maximum and
//! answers a ConfirmedError of errorClass resource other instead of sending a
//! PDU the peer must drop.
//!
//! Covered: the same data set succeeds over an association that negotiates the
//! default maximum and fails over one that negotiates 256 bytes, so the limit
//! and not the data set is what refuses it; a data set that fits still
//! succeeds over the small association; the error class survives the round
//! trip as a typed `ServiceError`; and GetDataSetValues is bounded the same
//! way as GetDataSetDirectory.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iec61850_client::IedConnection;
use iec61850_mms::mms::pdu::service_error::subcode::resource;
use iec61850_mms::mms::pdu::ErrorClass;
use iec61850_mms::{ClientError, MmsClient, MmsClientBuilder};
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObject, DoChild, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::{Dataset, DatasetEntry, IedServer, IedServerConfig};

const DOMAIN: &str = "IED1LD0";
const BIG_DS_NAME: &str = "GGIO1$ds_big";
const SMALL_DS_NAME: &str = "GGIO1$ds_small";

/// Members of the oversized data set. Each reference costs about forty bytes
/// on the wire, so this many members overrun a 256-byte association by an
/// order of magnitude while staying well inside the default one.
const BIG_DS_MEMBERS: usize = 40;

/// Maximum PDU size the constrained association negotiates, in bytes. The
/// server floors negotiation at 64 bytes, and a real client typically proposes
/// 1024 to 4096.
const SMALL_MAX_PDU_SIZE: u32 = 256;

/// Model: GGIO1 with one boolean under ST, enough for a valid association. The
/// directory service answers from the data set registry, so the members below
/// need no counterpart in the model.
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

/// Name of the data set read for its values. Its members carry visible
/// strings rather than booleans, so the list of access results, and not only
/// the list of member names, runs past a small association.
const WIDE_DS_NAME: &str = "GGIO1$ds_wide";

/// Members of that data set, and the visible string each member holds.
/// Together they encode to about a kilobyte of access results, well past a
/// 256-byte association and well inside the default one.
const WIDE_DS_MEMBERS: usize = 40;
const WIDE_DS_VALUE: &str = "0123456789abcdef0123456789abcdef";

/// Builds a configured data set of `members` boolean entries.
fn boolean_dataset(name: &str, members: usize) -> Dataset {
    let mut ds = Dataset::new(name);
    for n in 0..members {
        let da = DataAttribute::new(
            "stVal",
            FC::St,
            DataAttributeType::Boolean,
            TrgOps::DCHG,
            MmsValue::Boolean(true),
        );
        ds.push(DatasetEntry::new(
            format!("{DOMAIN}/GGIO1$ST$Ind{n}$stVal"),
            Arc::clone(&da.value),
        ));
    }
    ds
}

/// Builds a configured data set of `members` entries, each holding
/// [`WIDE_DS_VALUE`].
fn string_dataset(name: &str, members: usize) -> Dataset {
    let mut ds = Dataset::new(name);
    for n in 0..members {
        ds.push(DatasetEntry::new(
            format!("{DOMAIN}/GGIO1$ST$Ind{n}$stVal"),
            Arc::new(std::sync::RwLock::new(MmsValue::VisibleString(
                WIDE_DS_VALUE.to_string(),
            ))),
        ));
    }
    ds
}

/// Starts a server holding one oversized and one small configured data set.
async fn start_server() -> (IedServer, u16) {
    let cfg = IedServerConfig {
        max_mms_connections: 5,
        ..Default::default()
    };
    let server = IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(cfg)
        .build()
        .expect("build server");
    server.register_dataset(DOMAIN, boolean_dataset(BIG_DS_NAME, BIG_DS_MEMBERS));
    server.register_dataset(DOMAIN, boolean_dataset(SMALL_DS_NAME, 1));
    server.register_dataset(DOMAIN, string_dataset(WIDE_DS_NAME, WIDE_DS_MEMBERS));
    let handle = server.start().await.expect("server start");
    let port = handle.bound_addr.port();
    (server, port)
}

/// Connects with the given proposed maximum PDU size; `None` leaves the client
/// default in place.
async fn connect(port: u16, local_max_pdu_size: Option<u32>) -> IedConnection {
    let mut builder = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000);
    if let Some(size) = local_max_pdu_size {
        builder = builder.local_max_pdu_size(size);
    }
    let conn = IedConnection::with_mms_client(builder.build());
    conn.connect("127.0.0.1", port)
        .await
        .expect("client.connect");
    conn
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_directory_over_the_negotiated_pdu_size_is_refused() {
    let (_server, port) = start_server().await;

    // Control: the default association carries the same directory.
    let roomy = connect(port, None).await;
    let dir = tokio::time::timeout(
        Duration::from_secs(5),
        roomy.get_data_set_directory("IED1LD0/GGIO1.ds_big"),
    )
    .await
    .expect("timeout")
    .expect("the default association must carry the directory");
    assert_eq!(dir.members.len(), BIG_DS_MEMBERS);

    // The same request over a 256-byte association is refused.
    let constrained = connect(port, Some(SMALL_MAX_PDU_SIZE)).await;
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        constrained.get_data_set_directory("IED1LD0/GGIO1.ds_big"),
    )
    .await
    .expect("timeout")
    .expect_err("a directory larger than the negotiated maximum must be refused");
    assert!(
        err.to_string().contains("Resource(0)"),
        "the refusal must carry errorClass resource other, got {err}"
    );

    // A data set that fits still succeeds over the same association.
    let small = tokio::time::timeout(
        Duration::from_secs(5),
        constrained.get_data_set_directory("IED1LD0/GGIO1.ds_small"),
    )
    .await
    .expect("timeout")
    .expect("a directory within the negotiated maximum must still be served");
    assert_eq!(small.members.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_refusal_arrives_as_a_typed_service_error() {
    let (_server, port) = start_server().await;

    let mut client: MmsClient = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .local_max_pdu_size(SMALL_MAX_PDU_SIZE)
        .build();
    client.connect("127.0.0.1", port).await.expect("connect");

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        client.get_named_variable_list_attributes(DOMAIN, BIG_DS_NAME),
    )
    .await
    .expect("timeout");

    match result {
        Err(ClientError::ServiceError { error_class }) => assert_eq!(
            error_class,
            ErrorClass::Resource(resource::OTHER),
            "an oversized directory must answer resource other"
        ),
        other => panic!("expected a service error carrying an errorClass, got {other:?}"),
    }
}

/// GetDataSetValues carries the same limit as the directory service: the
/// values of a data set that does not fit the negotiated maximum are refused
/// as a whole, rather than truncated into a list the client would read as
/// complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn data_set_values_over_the_negotiated_pdu_size_are_refused() {
    let (_server, port) = start_server().await;

    // Control: the default association carries every value.
    let roomy = connect(port, None).await;
    let values = tokio::time::timeout(
        Duration::from_secs(5),
        roomy.get_data_set_values("IED1LD0/GGIO1.ds_wide"),
    )
    .await
    .expect("timeout")
    .expect("the default association must carry the values");
    assert_eq!(values.len(), WIDE_DS_MEMBERS);

    // The same request over a 256-byte association is refused.
    let constrained = connect(port, Some(SMALL_MAX_PDU_SIZE)).await;
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        constrained.get_data_set_values("IED1LD0/GGIO1.ds_wide"),
    )
    .await
    .expect("timeout")
    .expect_err("values larger than the negotiated maximum must be refused");
    assert!(
        err.to_string().contains("Resource(0)"),
        "the refusal must carry errorClass resource other, got {err}"
    );

    // A data set that fits is still read over the same association.
    let small = tokio::time::timeout(
        Duration::from_secs(5),
        constrained.get_data_set_values("IED1LD0/GGIO1.ds_small"),
    )
    .await
    .expect("timeout")
    .expect("values within the negotiated maximum must still be served");
    assert_eq!(small.len(), 1);
}

/// The values refusal reaches the MMS client as a typed `ServiceError`, so a
/// caller can branch on the errorClass without parsing the message.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_values_refusal_arrives_as_a_typed_service_error() {
    let (_server, port) = start_server().await;

    let mut client: MmsClient = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .local_max_pdu_size(SMALL_MAX_PDU_SIZE)
        .build();
    client.connect("127.0.0.1", port).await.expect("connect");

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        client.read_named_variable_list_values(DOMAIN, WIDE_DS_NAME),
    )
    .await
    .expect("timeout");

    match result {
        Err(ClientError::ServiceError { error_class }) => assert_eq!(
            error_class,
            ErrorClass::Resource(resource::OTHER),
            "oversized data set values must answer resource other"
        ),
        other => panic!("expected a service error carrying an errorClass, got {other:?}"),
    }
}
