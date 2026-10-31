//! End-to-end round trip of `write_bit_string` over a loopback association.
//!
//! The model carries one writable `BIT STRING(13)` under FC CF. A write reads
//! back with the unused low-order bits of the last byte cleared, and a write
//! with invalid padding fails before any request is sent.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iec61850_client::{ClientError, IedConnection};
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_model::{
    DataAttributeType, DataObjectBuilder, IedModel, IedModelBuilder, LogicalDeviceBuilder,
    LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::{IedServer, IedServerConfig, WriteAccessPolicies};

const REFERENCE: &str = "IED1LD0/GGIO1.Mask.bits";

fn build_model() -> Arc<IedModel> {
    let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
    let mask = DataObjectBuilder::scalar("Mask")
        .add_da(
            "bits",
            FC::Cf,
            DataAttributeType::GenericBitString(13),
            TrgOps::NONE,
            MmsValue::default_for(DataAttributeType::GenericBitString(13)),
        )
        .build()
        .expect("mask");
    let ggio = LogicalNodeBuilder::new("", "GGIO", "1")
        .add_do(mask)
        .build()
        .expect("ggio");
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
    let mut policies = WriteAccessPolicies::default();
    policies.set(FC::Cf, true);
    IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config({
            let mut config = IedServerConfig::default();
            config.max_mms_connections = 4;
            config.write_access_policies = policies;
            config
        })
        .build()
        .expect("build server")
}

async fn make_client(port: u16) -> IedConnection {
    let mms = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    let conn = IedConnection::with_mms_client(mms);
    conn.connect("127.0.0.1", port).await.expect("connect");
    conn
}

/// A 13-bit write reads back with padding 3 and the unused bits cleared.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_bit_string_round_trip() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let conn = make_client(handle.bound_addr.port()).await;

        conn.write_bit_string(REFERENCE, FC::Cf, vec![0xa5, 0xff], 3)
            .await
            .expect("write_bit_string");
        let read = conn
            .read_object(REFERENCE, FC::Cf)
            .await
            .expect("read_object");
        assert_eq!(
            read,
            MmsValue::BitString {
                padding: 3,
                data: vec![0xa5, 0xf8],
            }
        );

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// Invalid padding is rejected with `InvalidArgument` and the attribute keeps
/// its value.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_bit_string_invalid_padding_rejected() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let conn = make_client(handle.bound_addr.port()).await;

        for (data, padding) in [(vec![0xffu8, 0xff], 8u8), (vec![], 1)] {
            let err = conn
                .write_bit_string(REFERENCE, FC::Cf, data, padding)
                .await
                .expect_err("invalid padding");
            assert!(matches!(err, ClientError::InvalidArgument(_)), "{err:?}");
        }
        let read = conn
            .read_object(REFERENCE, FC::Cf)
            .await
            .expect("read_object");
        assert_eq!(
            read,
            MmsValue::BitString {
                padding: 3,
                data: vec![0x00, 0x00],
            }
        );

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// The padding check runs before the connection is consulted, so an invalid
/// write on an unconnected client never reaches the transport.
#[tokio::test]
async fn write_bit_string_checks_padding_before_sending() {
    let conn = IedConnection::with_mms_client(MmsClientBuilder::new().build());
    let err = conn
        .write_bit_string(REFERENCE, FC::Cf, vec![0x80], 9)
        .await
        .expect_err("invalid padding");
    assert!(matches!(err, ClientError::InvalidArgument(_)), "{err:?}");

    let err = conn
        .write_bit_string(REFERENCE, FC::Cf, vec![0x80], 6)
        .await
        .expect_err("not connected");
    assert!(matches!(err, ClientError::NotConnected), "{err:?}");
}
