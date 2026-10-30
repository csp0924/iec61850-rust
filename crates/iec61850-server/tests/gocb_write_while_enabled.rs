//! SetGoCBValues while a GoCB is enabled, over a real TCP association.
//!
//! IEC 61850-7-2 lets only GoEna change while GoEna is true: a GoID write is
//! refused with temporarily-unavailable and leaves the publisher untouched,
//! GoEna itself stays writable, and GoID becomes writable again once GoEna is
//! false.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iec61850_goose::publisher::CommParameters;
use iec61850_goose::GoosePublisher;
use iec61850_mms::mms::client::error::ClientError;
use iec61850_mms::mms::client::{MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::DataAccessError;
use iec61850_mms::mms::MmsData;
use iec61850_model::{IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder};
use iec61850_server::goose_mapping::GoCBHandle;
use iec61850_server::{IedServer, IedServerConfig, ServerHandle};

fn model() -> Arc<IedModel> {
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

async fn start() -> (ServerHandle, MmsClient, Arc<Mutex<GoosePublisher>>) {
    let server = IedServer::builder()
        .model(model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig::default())
        .build()
        .expect("build server");
    let comm = CommParameters::new(0x1000, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01])
        .with_src_mac([0x00, 0x50, 0xc2, 0x12, 0x34, 0x56]);
    let publisher = Arc::new(Mutex::new(
        GoosePublisher::new(
            comm.clone(),
            "TESTLD0/LLN0$GO$gcb01",
            Some("before".into()),
            "TESTLD0/LLN0$ds1",
            7,
        )
        .unwrap(),
    ));
    server.register_gocb(Arc::new(GoCBHandle::new(
        "TESTLD0",
        "LLN0",
        "gcb01",
        publisher.clone(),
        7,
        "TESTLD0/LLN0$ds1",
        Some("before".into()),
        false,
        comm,
        None,
        None,
    )));
    let h = server.start().await.expect("start");
    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    client
        .connect("127.0.0.1", h.bound_addr.port())
        .await
        .expect("connect");
    (h, client, publisher)
}

async fn write(client: &mut MmsClient, da: &str, v: MmsData) -> Result<(), ClientError> {
    tokio::time::timeout(
        Duration::from_secs(5),
        client.write("TESTLD0", &format!("LLN0$GO$gcb01${da}"), v),
    )
    .await
    .expect("timeout")
}

async fn read_go_id(client: &mut MmsClient) -> MmsData {
    tokio::time::timeout(
        Duration::from_secs(5),
        client.read("TESTLD0", "LLN0$GO$gcb01$GoID"),
    )
    .await
    .expect("timeout")
    .expect("read GoID")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn go_id_write_is_refused_while_enabled() {
    let (h, mut client, publisher) = start().await;
    write(&mut client, "GoEna", MmsData::Boolean(true))
        .await
        .expect("enable");

    let r = write(&mut client, "GoID", MmsData::VisibleString("after".into())).await;
    assert!(
        matches!(
            r,
            Err(ClientError::DataAccessError(
                DataAccessError::TemporarilyUnavailable
            ))
        ),
        "expected temporarily-unavailable, got {r:?}"
    );
    assert_eq!(
        read_go_id(&mut client).await,
        MmsData::VisibleString("before".into())
    );
    assert_eq!(publisher.lock().unwrap().go_id(), Some("before"));

    client.disconnect().await.ok();
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn go_ena_stays_writable_while_enabled() {
    let (h, mut client, publisher) = start().await;
    write(&mut client, "GoEna", MmsData::Boolean(true))
        .await
        .expect("enable");
    write(&mut client, "GoEna", MmsData::Boolean(true))
        .await
        .expect("enable again");
    write(&mut client, "GoEna", MmsData::Boolean(false))
        .await
        .expect("disable");
    assert!(!publisher.lock().unwrap().enabled());

    client.disconnect().await.ok();
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn go_id_write_is_accepted_once_disabled() {
    let (h, mut client, publisher) = start().await;
    write(&mut client, "GoEna", MmsData::Boolean(true))
        .await
        .expect("enable");
    write(&mut client, "GoEna", MmsData::Boolean(false))
        .await
        .expect("disable");
    write(&mut client, "GoID", MmsData::VisibleString("after".into()))
        .await
        .expect("write GoID while disabled");
    assert_eq!(
        read_go_id(&mut client).await,
        MmsData::VisibleString("after".into())
    );
    assert_eq!(publisher.lock().unwrap().go_id(), Some("after"));

    client.disconnect().await.ok();
    h.stop().await;
}
