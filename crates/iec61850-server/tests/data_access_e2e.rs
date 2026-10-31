//! Data read and write rules over the wire: our client against our server
//! through the full ISO stack.
//!
//! A write is held to the type each attribute declares, its integer range and
//! its string length.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iec61850_mms::mms::client::{ClientError, MmsClient, MmsClientBuilder};
use iec61850_mms::mms::MmsData;
use iec61850_mms::DataAccessError;
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObject, DoChild, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNode, LogicalNodeBuilder, MmsValue, SettingGroupControlBlock,
    TrgOps, FC,
};
use iec61850_server::{IedServer, IedServerConfig, ServerHandle};

const DOMAIN: &str = "IED1LD0";

fn da(name: &str, fc: FC, ty: DataAttributeType, value: MmsValue) -> DoChild {
    DoChild::Da(DataAttribute::new(name, fc, ty, TrgOps::default(), value))
}

/// `GGIO1.Lim` holds SP attributes with a declared range or length.
fn build_model() -> Arc<IedModel> {
    let lim = DataObject::new(
        "Lim",
        vec![
            da(
                "u8",
                FC::Sp,
                DataAttributeType::Int8U,
                MmsValue::Unsigned(0),
            ),
            da("i8", FC::Sp, DataAttributeType::Int8, MmsValue::Integer(0)),
            da(
                "vis",
                FC::Sp,
                DataAttributeType::VisibleString(4),
                MmsValue::VisibleString(String::new()),
            ),
            da(
                "oct",
                FC::Sp,
                DataAttributeType::OctetString(4),
                MmsValue::OctetString(Vec::new()),
            ),
            da(
                "qual",
                FC::Sp,
                DataAttributeType::Quality,
                MmsValue::default_for(DataAttributeType::Quality),
            ),
        ],
    );
    let ggio = LogicalNode::new(String::new(), "GGIO", "1", vec![lim]);
    let lln0 = LogicalNodeBuilder::lln0()
        .set_sgcb({
            let mut sgcb = SettingGroupControlBlock::default();
            sgcb.num_of_sg = 2;
            sgcb.act_sg = 1;
            sgcb
        })
        .build()
        .expect("lln0");
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

/// Starts a server on the model; SP and SE are writable under the default
/// policy. Handlers go into `server.handler_registry()`.
async fn start() -> (IedServer, ServerHandle) {
    let server = IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config({
            let mut config = IedServerConfig::default();
            config.max_mms_connections = 4;
            config
        })
        .build()
        .expect("build server");
    let handle = server.start().await.expect("start");
    (server, handle)
}

async fn connect(handle: &ServerHandle) -> MmsClient {
    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    client
        .connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    client
}

fn data_access_error(result: Result<(), ClientError>) -> DataAccessError {
    match result {
        Err(ClientError::DataAccessError(e)) => e,
        other => panic!("expected a data access error, got {other:?}"),
    }
}

/// Values outside the declared range or length of an attribute answer
/// object-value-invalid and leave the attribute as it was; the bounds succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_outside_the_declared_type_is_refused() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (_server, handle) = start().await;
        let mut client = connect(&handle).await;

        let refused = [
            ("GGIO1$SP$Lim$u8", MmsData::Unsigned(256)),
            ("GGIO1$SP$Lim$i8", MmsData::Integer(-129)),
            ("GGIO1$SP$Lim$vis", MmsData::VisibleString("abcde".into())),
            ("GGIO1$SP$Lim$oct", MmsData::OctetString(vec![0; 5])),
        ];
        for (item, data) in refused {
            assert_eq!(
                data_access_error(client.write(DOMAIN, item, data).await),
                DataAccessError::ObjectValueInvalid,
                "{item}"
            );
        }
        assert_eq!(
            client.read(DOMAIN, "GGIO1$SP$Lim$u8").await.unwrap(),
            MmsData::Unsigned(0)
        );

        client
            .write(DOMAIN, "GGIO1$SP$Lim$u8", MmsData::Unsigned(255))
            .await
            .expect("255 fits an INT8U");
        client
            .write(
                DOMAIN,
                "GGIO1$SP$Lim$vis",
                MmsData::VisibleString("abcd".into()),
            )
            .await
            .expect("four characters fit");
        assert_eq!(
            client.read(DOMAIN, "GGIO1$SP$Lim$u8").await.unwrap(),
            MmsData::Unsigned(255)
        );

        handle.stop().await;
    })
    .await
    .expect("timed out");
}
