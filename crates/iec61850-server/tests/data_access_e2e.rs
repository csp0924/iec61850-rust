//! Data read and write rules over the wire: our client against our server
//! through the full ISO stack.
//!
//! A write is held to the type each attribute declares: its integer range
//! (object-value-invalid) and its string length (type-inconsistent); a bit
//! string shorter than its declared maximum is padded to it. A write may name
//! a whole data object under one functional constraint (FCD): every leaf is
//! checked, and every handler asked, before any of them changes.
//!
//! A read of the setting group edit buffer, FC SE, answers
//! temporarily-unavailable until a setting group is selected for editing.
//!
//! A read handler decides every read that covers its node, from above or from
//! below, and a refused read carries no part of the value.
//!
//! A data set created at run time may take a member beneath a sub-data-object.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iec61850_mms::mms::client::{ClientError, MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::define_named_variable_list::DefineNamedVariableEntry;
use iec61850_mms::mms::MmsData;
use iec61850_mms::{AccessResult, DataAccessError};
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObject, DoChild, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNode, LogicalNodeBuilder, MmsValue, SettingGroupControlBlock,
    TrgOps, FC,
};
use iec61850_server::{
    AttributeAccessHandler, HandlerWriteOutcome, IedServer, IedServerConfig, ReadContext,
    ReadHandler, ReadOutcome, ServerHandle, WriteContext,
};

const DOMAIN: &str = "IED1LD0";

fn da(name: &str, fc: FC, ty: DataAttributeType, value: MmsValue) -> DoChild {
    DoChild::Da(DataAttribute::new(name, fc, ty, TrgOps::default(), value))
}

/// `GGIO1.Lim` holds SP attributes with a declared range or length; `GGIO1.Pt`
/// holds, under SP, a leaf, a constructed attribute and a sub-object, plus a
/// status and a configuration attribute outside SP.
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
    let pt = DataObject::new(
        "Pt",
        vec![
            da(
                "stVal",
                FC::St,
                DataAttributeType::Boolean,
                MmsValue::Boolean(false),
            ),
            da(
                "setVal",
                FC::Sp,
                DataAttributeType::Int32,
                MmsValue::Integer(0),
            ),
            DoChild::Da(DataAttribute::constructed(
                "setMag",
                FC::Sp,
                vec![DataAttribute::new(
                    "f",
                    FC::Sp,
                    DataAttributeType::Float32,
                    TrgOps::default(),
                    MmsValue::Float32(0.0),
                )],
            )),
            DoChild::SubDo(DataObject::new(
                "phsA",
                vec![da(
                    "lim",
                    FC::Sp,
                    DataAttributeType::Int8U,
                    MmsValue::Unsigned(0),
                )],
            )),
            da(
                "cfgVal",
                FC::Cf,
                DataAttributeType::Int32,
                MmsValue::Integer(0),
            ),
        ],
    );
    let set = DataObject::new(
        "Set",
        vec![
            da(
                "setVal",
                FC::Se,
                DataAttributeType::Int32,
                MmsValue::Integer(5),
            ),
            da(
                "setVal",
                FC::Sg,
                DataAttributeType::Int32,
                MmsValue::Integer(5),
            ),
        ],
    );
    let ind = DataObject::new(
        "Ind",
        vec![
            da(
                "stVal",
                FC::St,
                DataAttributeType::Boolean,
                MmsValue::Boolean(true),
            ),
            da(
                "q",
                FC::St,
                DataAttributeType::Quality,
                MmsValue::default_for(DataAttributeType::Quality),
            ),
        ],
    );
    let ggio = LogicalNode::new(String::new(), "GGIO", "1", vec![lim, pt, set, ind]);
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

/// An integer outside its declared range answers object-value-invalid and a
/// string longer than its declared maximum answers type-inconsistent; either
/// leaves the attribute as it was, and the bounds succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_outside_the_declared_type_is_refused() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (_server, handle) = start().await;
        let mut client = connect(&handle).await;

        let refused = [
            (
                "GGIO1$SP$Lim$u8",
                MmsData::Unsigned(256),
                DataAccessError::ObjectValueInvalid,
            ),
            (
                "GGIO1$SP$Lim$i8",
                MmsData::Integer(-129),
                DataAccessError::ObjectValueInvalid,
            ),
            (
                "GGIO1$SP$Lim$vis",
                MmsData::VisibleString("abcde".into()),
                DataAccessError::TypeInconsistent,
            ),
            (
                "GGIO1$SP$Lim$oct",
                MmsData::OctetString(vec![0; 5]),
                DataAccessError::TypeInconsistent,
            ),
        ];
        for (item, data, expected) in refused {
            assert_eq!(
                data_access_error(client.write(DOMAIN, item, data).await),
                expected,
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

/// The SP value of `GGIO1.Pt`: `setVal`, `setMag`, then `phsA`.
fn pt_value(set_val: i64, f: f32, lim: u64) -> MmsData {
    MmsData::Structure(vec![
        MmsData::Integer(set_val),
        MmsData::Structure(vec![MmsData::Float32(f)]),
        MmsData::Structure(vec![MmsData::Unsigned(lim)]),
    ])
}

async fn pt_leaves(client: &mut MmsClient) -> (MmsData, MmsData, MmsData) {
    (
        client.read(DOMAIN, "GGIO1$SP$Pt$setVal").await.unwrap(),
        client.read(DOMAIN, "GGIO1$SP$Pt$setMag$f").await.unwrap(),
        client.read(DOMAIN, "GGIO1$SP$Pt$phsA$lim").await.unwrap(),
    )
}

/// Refuses every write of the attribute it is installed on.
#[derive(Debug)]
struct Refuse;

impl AttributeAccessHandler for Refuse {
    fn on_write(&self, _ctx: &WriteContext<'_>, _value: &MmsValue) -> HandlerWriteOutcome {
        HandlerWriteOutcome::Reject(DataAccessError::ObjectAccessDenied)
    }
}

/// An FCD write stores every leaf the data object holds under the constraint,
/// across its constructed attributes and sub-objects, and the whole data object
/// reads back as written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_of_a_data_object_updates_every_leaf() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (_server, handle) = start().await;
        let mut client = connect(&handle).await;

        client
            .write(DOMAIN, "GGIO1$SP$Pt", pt_value(7, 1.5, 200))
            .await
            .expect("an FCD write succeeds");
        assert_eq!(
            pt_leaves(&mut client).await,
            (
                MmsData::Integer(7),
                MmsData::Float32(1.5),
                MmsData::Unsigned(200)
            )
        );
        assert_eq!(
            client.read(DOMAIN, "GGIO1$SP$Pt").await.unwrap(),
            pt_value(7, 1.5, 200)
        );

        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// An FCD write fails whole when one leaf fails: a value outside its type, a
/// handler that refuses, a shape that does not follow the data object, or a
/// functional constraint the policy refuses; no leaf changes in any case.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_of_a_data_object_is_refused_whole() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (server, handle) = start().await;
        let mut client = connect(&handle).await;
        let unchanged = (
            MmsData::Integer(0),
            MmsData::Float32(0.0),
            MmsData::Unsigned(0),
        );

        assert_eq!(
            data_access_error(
                client
                    .write(DOMAIN, "GGIO1$SP$Pt", pt_value(7, 1.5, 256))
                    .await
            ),
            DataAccessError::ObjectValueInvalid
        );
        assert_eq!(pt_leaves(&mut client).await, unchanged);

        let short = MmsData::Structure(vec![MmsData::Integer(7)]);
        assert_eq!(
            data_access_error(client.write(DOMAIN, "GGIO1$SP$Pt", short).await),
            DataAccessError::TypeInconsistent
        );
        assert_eq!(pt_leaves(&mut client).await, unchanged);

        let MmsData::Structure(mut long) = pt_value(7, 1.5, 200) else {
            unreachable!()
        };
        long.push(MmsData::Integer(1));
        assert_eq!(
            data_access_error(
                client
                    .write(DOMAIN, "GGIO1$SP$Pt", MmsData::Structure(long))
                    .await
            ),
            DataAccessError::TypeInconsistent
        );
        assert_eq!(pt_leaves(&mut client).await, unchanged);

        assert_eq!(
            data_access_error(
                client
                    .write(
                        DOMAIN,
                        "GGIO1$CF$Pt",
                        MmsData::Structure(vec![MmsData::Integer(1)]),
                    )
                    .await
            ),
            DataAccessError::ObjectAccessDenied
        );

        server
            .handler_registry()
            .install_write_access_handler("GGIO1$SP$Pt$phsA$lim", Arc::new(Refuse))
            .unwrap();
        assert_eq!(
            data_access_error(
                client
                    .write(DOMAIN, "GGIO1$SP$Pt", pt_value(7, 1.5, 200))
                    .await
            ),
            DataAccessError::ObjectAccessDenied
        );
        assert_eq!(pt_leaves(&mut client).await, unchanged);

        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// A Quality written with 9 bits reads back with the 13 bits it declares: the
/// written bits, then zero bits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn short_quality_reads_back_at_its_declared_length() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (_server, handle) = start().await;
        let mut client = connect(&handle).await;

        client
            .write(
                DOMAIN,
                "GGIO1$SP$Lim$qual",
                MmsData::BitString {
                    padding: 7,
                    data: vec![0x41, 0x80],
                },
            )
            .await
            .expect("9 bits fit a Quality");
        assert_eq!(
            client.read(DOMAIN, "GGIO1$SP$Lim$qual").await.unwrap(),
            MmsData::BitString {
                padding: 3,
                data: vec![0x41, 0x80],
            }
        );

        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// A write handler on a data object decides a write of a leaf beneath it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_handler_on_a_data_object_decides_a_leaf_write() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (server, handle) = start().await;
        let mut client = connect(&handle).await;
        server
            .handler_registry()
            .install_write_access_handler("GGIO1$SP$Pt", Arc::new(Refuse))
            .unwrap();

        assert_eq!(
            data_access_error(
                client
                    .write(DOMAIN, "GGIO1$SP$Pt$phsA$lim", MmsData::Unsigned(3))
                    .await
            ),
            DataAccessError::ObjectAccessDenied
        );
        assert_eq!(
            client.read(DOMAIN, "GGIO1$SP$Pt$phsA$lim").await.unwrap(),
            MmsData::Unsigned(0)
        );

        handle.stop().await;
    })
    .await
    .expect("timed out");
}

fn access_error(result: Result<MmsData, ClientError>) -> DataAccessError {
    match result {
        Err(ClientError::DataAccessError(e)) => e,
        other => panic!("expected a data access error, got {other:?}"),
    }
}

/// While EditSG is 0, a read of FC SE answers temporarily-unavailable whether
/// it names an attribute, a data object or the whole SE group, and a read of
/// the active group under SG still answers. Once a group is selected for
/// editing, SE reads answer from the edit buffer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn edit_buffer_reads_wait_for_a_selected_edit_group() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (_server, handle) = start().await;
        let mut client = connect(&handle).await;

        for item in ["GGIO1$SE$Set$setVal", "GGIO1$SE$Set", "GGIO1$SE"] {
            assert_eq!(
                access_error(client.read(DOMAIN, item).await),
                DataAccessError::TemporarilyUnavailable,
                "{item}"
            );
        }
        assert_eq!(
            client.read(DOMAIN, "GGIO1$SG$Set$setVal").await.unwrap(),
            MmsData::Integer(5)
        );

        client
            .write(DOMAIN, "LLN0$SP$SGCB$EditSG", MmsData::Unsigned(1))
            .await
            .expect("select the edit group");
        assert_eq!(
            client.read(DOMAIN, "GGIO1$SE$Set$setVal").await.unwrap(),
            MmsData::Integer(5)
        );

        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// Answers every read with one outcome and counts how often it is asked.
#[derive(Debug)]
struct FixedRead {
    outcome: ReadOutcome,
    asked: std::sync::atomic::AtomicUsize,
}

impl FixedRead {
    fn new(outcome: ReadOutcome) -> Arc<Self> {
        Arc::new(Self {
            outcome,
            asked: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn asked(&self) -> usize {
        self.asked.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl ReadHandler for FixedRead {
    fn read(&self, _ctx: &ReadContext<'_>) -> ReadOutcome {
        self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.outcome.clone()
    }
}

/// A handler on a leaf is asked by a read of the whole data object: its value
/// replaces the leaf, and its refusal refuses the read with no value in the
/// answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leaf_read_handler_decides_a_read_of_its_data_object() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (server, handle) = start().await;
        let mut client = connect(&handle).await;
        let quality = MmsData::BitString {
            padding: 3,
            data: vec![0, 0],
        };

        let hit = FixedRead::new(ReadOutcome::CacheHit(MmsValue::Boolean(false)));
        server
            .handler_registry()
            .install_read_handler("GGIO1$ST$Ind$stVal", hit.clone())
            .unwrap();
        assert_eq!(
            client.read(DOMAIN, "GGIO1$ST$Ind").await.unwrap(),
            MmsData::Structure(vec![MmsData::Boolean(false), quality.clone()])
        );
        assert_eq!(hit.asked(), 1);

        server
            .handler_registry()
            .install_read_handler(
                "GGIO1$ST$Ind$stVal",
                FixedRead::new(ReadOutcome::Error(DataAccessError::ObjectAccessDenied)),
            )
            .unwrap();
        assert_eq!(
            access_error(client.read(DOMAIN, "GGIO1$ST$Ind").await),
            DataAccessError::ObjectAccessDenied
        );
        assert_eq!(
            client.read(DOMAIN, "GGIO1$ST$Ind$q").await.unwrap(),
            quality
        );

        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// A handler on a data object decides a read of an attribute beneath it, on
/// its own and as a data set member.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn data_object_read_handler_decides_reads_beneath_it() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (server, handle) = start().await;
        let mut client = connect(&handle).await;
        server
            .handler_registry()
            .install_read_handler(
                "GGIO1$ST$Ind",
                FixedRead::new(ReadOutcome::Error(DataAccessError::ObjectAccessDenied)),
            )
            .unwrap();

        assert_eq!(
            access_error(client.read(DOMAIN, "GGIO1$ST$Ind$stVal").await),
            DataAccessError::ObjectAccessDenied
        );

        client
            .define_named_variable_list(
                DOMAIN,
                "GGIO1$dsInd",
                vec![
                    DefineNamedVariableEntry::domain(DOMAIN, "GGIO1$ST$Ind$stVal"),
                    DefineNamedVariableEntry::domain(DOMAIN, "GGIO1$SP$Lim$u8"),
                ],
            )
            .await
            .expect("CreateDataSet");
        assert_eq!(
            client
                .read_named_variable_list_values(DOMAIN, "GGIO1$dsInd")
                .await
                .expect("GetDataSetValues"),
            vec![
                AccessResult::Failure(DataAccessError::ObjectAccessDenied),
                AccessResult::Success(MmsData::Unsigned(0)),
            ]
        );

        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// A read of a whole logical node or of one of its functional-constraint
/// groups asks the handlers of the data objects in it: a value replaces its
/// node, a refusal refuses the read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn logical_node_and_group_reads_ask_the_read_handlers() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (server, handle) = start().await;
        let mut client = connect(&handle).await;
        let quality = MmsData::BitString {
            padding: 3,
            data: vec![0, 0],
        };

        let hit = FixedRead::new(ReadOutcome::CacheHit(MmsValue::Boolean(false)));
        server
            .handler_registry()
            .install_read_handler("GGIO1$ST$Ind$stVal", hit.clone())
            .unwrap();
        let st_group = client.read(DOMAIN, "GGIO1$ST").await.unwrap();
        let MmsData::Structure(objects) = &st_group else {
            panic!("a structure, got {st_group:?}");
        };
        assert_eq!(
            objects.last(),
            Some(&MmsData::Structure(vec![MmsData::Boolean(false), quality]))
        );
        client
            .read(DOMAIN, "GGIO1")
            .await
            .expect("whole logical node");
        assert_eq!(hit.asked(), 2);

        server
            .handler_registry()
            .install_read_handler(
                "GGIO1$ST$Ind$q",
                FixedRead::new(ReadOutcome::Error(DataAccessError::ObjectAccessDenied)),
            )
            .unwrap();
        for item in ["GGIO1$ST", "GGIO1"] {
            assert_eq!(
                access_error(client.read(DOMAIN, item).await),
                DataAccessError::ObjectAccessDenied,
                "{item}"
            );
        }
        client
            .read(DOMAIN, "GGIO1$SP")
            .await
            .expect("another group");

        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// CreateDataSet takes a member beneath a sub-data-object, and
/// GetDataSetValues reads its value.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn data_set_member_beneath_a_sub_data_object() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (_server, handle) = start().await;
        let mut client = connect(&handle).await;

        client
            .write(DOMAIN, "GGIO1$SP$Pt$phsA$lim", MmsData::Unsigned(42))
            .await
            .expect("write the member");
        client
            .define_named_variable_list(
                DOMAIN,
                "GGIO1$dsSdo",
                vec![DefineNamedVariableEntry::domain(
                    DOMAIN,
                    "GGIO1$SP$Pt$phsA$lim",
                )],
            )
            .await
            .expect("CreateDataSet with a member beneath a sub-data-object");
        assert_eq!(
            client
                .read_named_variable_list_values(DOMAIN, "GGIO1$dsSdo")
                .await
                .expect("GetDataSetValues"),
            vec![AccessResult::Success(MmsData::Unsigned(42))]
        );

        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// Refuses a read of its own path and lets every read that covers it pass, by
/// comparing the path the client named with its own.
#[derive(Debug)]
struct OwnPathOnly;

impl ReadHandler for OwnPathOnly {
    fn read(&self, ctx: &ReadContext<'_>) -> ReadOutcome {
        if ctx.requested != ctx.path {
            return ReadOutcome::CacheMiss;
        }
        ReadOutcome::Error(DataAccessError::ObjectAccessDenied)
    }
}

/// A handler that compares the requested path with its own guards only its
/// own path: the data object and the logical node above it still read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_handler_can_guard_its_own_path_only() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (server, handle) = start().await;
        let mut client = connect(&handle).await;
        server
            .handler_registry()
            .install_read_handler("GGIO1$ST$Ind$stVal", Arc::new(OwnPathOnly))
            .unwrap();

        assert_eq!(
            access_error(client.read(DOMAIN, "GGIO1$ST$Ind$stVal").await),
            DataAccessError::ObjectAccessDenied
        );
        client
            .read(DOMAIN, "GGIO1$ST$Ind")
            .await
            .expect("the data object reads");
        client
            .read(DOMAIN, "GGIO1")
            .await
            .expect("the logical node reads");

        handle.stop().await;
    })
    .await
    .expect("timed out");
}
