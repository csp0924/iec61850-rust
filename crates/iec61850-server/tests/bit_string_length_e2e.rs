//! Bit-string length checks on the Write, SetDataSetValues and Read paths.
//!
//! A written bit string must fit the declared size of the attribute: exactly
//! two bits for a `Dbpos`, 1 to 13 for a `Quality`, any length for a bit string
//! that declares no size. One that does not
//! fit answers `type-inconsistent` and leaves the model unchanged. A read
//! handler value that does not fit is not sent, and the read answers
//! `object-value-invalid`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iec61850_client::{ClientError, DataSetMember, IedConnection};
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_mms::{DataAccessError, WriteOutcome};
use iec61850_model::{
    DataAttributeType, DataObjectBuilder, IedModel, IedModelBuilder, LogicalDeviceBuilder,
    LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::{
    IedServer, IedServerConfig, ReadContext, ReadHandler, ReadOutcome, WriteAccessPolicies,
};

const POS: &str = "IED1LD0/GGIO1.Cfg.pos";
const QUAL: &str = "IED1LD0/GGIO1.Cfg.qual";
const FREE: &str = "IED1LD0/GGIO1.Cfg.free";

fn build_model() -> Arc<IedModel> {
    let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
    let cfg = DataObjectBuilder::scalar("Cfg")
        .add_da(
            "pos",
            FC::Cf,
            DataAttributeType::CodedEnum,
            TrgOps::NONE,
            MmsValue::BitString {
                padding: 6,
                data: vec![0x40],
            },
        )
        .add_da(
            "qual",
            FC::Cf,
            DataAttributeType::Quality,
            TrgOps::NONE,
            MmsValue::default_for(DataAttributeType::Quality),
        )
        .add_da(
            "free",
            FC::Cf,
            DataAttributeType::GenericBitString(0),
            TrgOps::NONE,
            MmsValue::default_for(DataAttributeType::GenericBitString(0)),
        )
        .build()
        .expect("cfg");
    let ggio = LogicalNodeBuilder::new("", "GGIO", "1")
        .add_do(cfg)
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
        .config(IedServerConfig {
            max_mms_connections: 4,
            write_access_policies: policies,
            ..Default::default()
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

fn bit_string(padding: u8, data: &[u8]) -> MmsValue {
    MmsValue::BitString {
        padding,
        data: data.to_vec(),
    }
}

/// A read handler that answers every read with one fixed value.
#[derive(Debug)]
struct FixedRead(MmsValue);

impl ReadHandler for FixedRead {
    fn read(&self, _ctx: &ReadContext<'_>) -> ReadOutcome {
        ReadOutcome::CacheHit(self.0.clone())
    }
}

/// A bit string of 13, 0 or 1 bits written to a two-bit `Dbpos` answers
/// `type-inconsistent` and the attribute keeps its value; two bits succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_to_fixed_size_bit_string_checks_length() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let conn = make_client(handle.bound_addr.port()).await;

        for (data, padding) in [(vec![0x00u8, 0x00], 3u8), (vec![], 0), (vec![0x80], 7)] {
            let err = conn
                .write_object(POS, FC::Cf, bit_string(padding, &data))
                .await
                .expect_err("a bit string of another length is refused");
            assert!(
                matches!(
                    err,
                    ClientError::DataAccessError(DataAccessError::TypeInconsistent)
                ),
                "{err:?}"
            );
            let read = conn.read_object(POS, FC::Cf).await.expect("read_object");
            assert_eq!(read, bit_string(6, &[0x40]));
        }

        conn.write_object(POS, FC::Cf, bit_string(6, &[0x80]))
            .await
            .expect("a two-bit write succeeds");
        let read = conn.read_object(POS, FC::Cf).await.expect("read_object");
        assert_eq!(read, bit_string(6, &[0x80]));

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// A `Quality`, declared as at most 13 bits, takes 13 bits and refuses 16
/// bits and an empty bit string.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_to_bounded_bit_string_checks_upper_bound() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let conn = make_client(handle.bound_addr.port()).await;

        for (data, padding) in [(vec![0xffu8, 0xff], 0u8), (vec![], 0)] {
            let err = conn
                .write_object(QUAL, FC::Cf, bit_string(padding, &data))
                .await
                .expect_err("16 bits exceed the bound and no bits fall short of it");
            assert!(
                matches!(
                    err,
                    ClientError::DataAccessError(DataAccessError::TypeInconsistent)
                ),
                "{err:?}"
            );
            let read = conn.read_object(QUAL, FC::Cf).await.expect("read_object");
            assert_eq!(read, bit_string(3, &[0x00, 0x00]));
        }

        conn.write_object(QUAL, FC::Cf, bit_string(3, &[0xc0, 0x08]))
            .await
            .expect("13 bits fit");
        let read = conn.read_object(QUAL, FC::Cf).await.expect("read_object");
        assert_eq!(read, bit_string(3, &[0xc0, 0x08]));

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// A bit string that declares no size takes a write of any length.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_to_unsized_bit_string_takes_any_length() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let conn = make_client(handle.bound_addr.port()).await;

        for value in [bit_string(5, &[0xa0]), bit_string(3, &[0xff, 0xf8])] {
            conn.write_object(FREE, FC::Cf, value.clone())
                .await
                .expect("any length fits");
            let read = conn.read_object(FREE, FC::Cf).await.expect("read_object");
            assert_eq!(read, value);
        }

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// SetDataSetValues applies the same check per member: the member of another
/// length answers `type-inconsistent` and the other member is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn set_data_set_values_checks_member_length() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let conn = make_client(handle.bound_addr.port()).await;

        conn.create_data_set(
            "IED1LD0/GGIO1.dsBits",
            &[
                DataSetMember::new(POS, FC::Cf),
                DataSetMember::new(QUAL, FC::Cf),
            ],
        )
        .await
        .expect("create_data_set");
        let outcomes = conn
            .set_data_set_values(
                "IED1LD0/GGIO1.dsBits",
                vec![bit_string(3, &[0x00, 0x00]), bit_string(3, &[0x40, 0x00])],
            )
            .await
            .expect("set_data_set_values");
        assert!(
            matches!(
                outcomes.as_slice(),
                [
                    WriteOutcome::Failure(DataAccessError::TypeInconsistent),
                    WriteOutcome::Success
                ]
            ),
            "{outcomes:?}"
        );
        let pos = conn.read_object(POS, FC::Cf).await.expect("read pos");
        assert_eq!(pos, bit_string(6, &[0x40]));
        let qual = conn.read_object(QUAL, FC::Cf).await.expect("read qual");
        assert_eq!(qual, bit_string(3, &[0x40, 0x00]));

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// A read handler value of another length is not sent: the read answers
/// `object-value-invalid`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_handler_bit_string_of_other_length_refused() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let server = build_server();
        server
            .install_read_handler(
                "GGIO1$CF$Cfg$pos",
                Arc::new(FixedRead(bit_string(3, &[0x00, 0x00]))),
            )
            .expect("install_read_handler");
        let handle = server.start().await.expect("start");
        let conn = make_client(handle.bound_addr.port()).await;

        let err = conn
            .read_object(POS, FC::Cf)
            .await
            .expect_err("a 13-bit value for a Dbpos is not sent");
        assert!(
            matches!(
                err,
                ClientError::DataAccessError(DataAccessError::ObjectValueInvalid)
            ),
            "{err:?}"
        );

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// A read handler value for a `Quality` is held to 1 to 13 bits: 16 bits and
/// an empty bit string answer `object-value-invalid`, 13 bits are sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_handler_bit_string_checks_upper_bound() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for (value, sent) in [
            (bit_string(0, &[0xff, 0xff]), false),
            (bit_string(0, &[]), false),
            (bit_string(3, &[0xc0, 0x08]), true),
        ] {
            let server = build_server();
            server
                .install_read_handler("GGIO1$CF$Cfg$qual", Arc::new(FixedRead(value.clone())))
                .expect("install_read_handler");
            let handle = server.start().await.expect("start");
            let conn = make_client(handle.bound_addr.port()).await;

            let read = conn.read_object(QUAL, FC::Cf).await;
            if sent {
                assert_eq!(read.expect("read_object"), value);
            } else {
                assert!(
                    matches!(
                        read,
                        Err(ClientError::DataAccessError(
                            DataAccessError::ObjectValueInvalid
                        ))
                    ),
                    "{read:?}"
                );
            }

            let _ = conn.disconnect().await;
            handle.stop().await;
        }
    })
    .await
    .expect("timed out");
}

/// A read handler value of the declared length is sent as it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_handler_bit_string_of_declared_length_sent() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let server = build_server();
        server
            .install_read_handler(
                "GGIO1$CF$Cfg$pos",
                Arc::new(FixedRead(bit_string(6, &[0xc0]))),
            )
            .expect("install_read_handler");
        let handle = server.start().await.expect("start");
        let conn = make_client(handle.bound_addr.port()).await;

        let read = conn.read_object(POS, FC::Cf).await.expect("read_object");
        assert_eq!(read, bit_string(6, &[0xc0]));

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}
