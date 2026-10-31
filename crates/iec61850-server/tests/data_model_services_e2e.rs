//! Data model services over a real association: loopback TCP and the full ISO
//! stack.
//!
//! Covers name resolution under a functional constraint, the type description
//! and the value layout of control blocks and setting group control blocks,
//! data set members and their read access, writes below constructed
//! attributes, paging, and the echo of an access specification.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use iec61850_client::{DataSetMember, IedConnection};
use iec61850_mms::mms::client::{ClientError, MmsClient, MmsClientBuilder, MmsConnection};
use iec61850_mms::mms::pdu::common::{
    AccessResult, DataAccessError, ObjectName, VariableAccessSpecification,
};
use iec61850_mms::mms::pdu::get_name_list::ObjectClass;
use iec61850_mms::mms::pdu::read::{encode_confirmed_read_request, ReadRequest, ReadResponse};
use iec61850_mms::mms::pdu::service_error::{
    decode_confirmed_error_inner,
    subcode::{access, resource},
    ErrorClass,
};
use iec61850_mms::mms::pdu::type_specification::TypeSpecification;
use iec61850_mms::mms::pdu::{DefineNamedVariableEntry, MmsPdu};
use iec61850_mms::mms::MmsData;
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObjectBuilder, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, NodeRef, ObjectRef,
    SettingGroupControlBlock, TrgOps, FC,
};
use iec61850_server::handler::{
    AttributeAccessHandler, ReadContext, ReadHandler, ReadOutcome, WriteContext, WriteOutcome,
};
use iec61850_server::logging::{LogControl, LogControlBlock};
use iec61850_server::reporting::{Brcb, BufferedReportControl};
use iec61850_server::{
    Dataset, DatasetEntry, IedServer, IedServerConfig, Rcb, ReportControl, ServerHandle,
    TimeQuality,
};

const DOM: &str = "IED1LD0";

/// The nine MMS components of a log control block, in IEC 61850-8-1 order.
const LCB_MEMBERS: [&str; 9] = [
    "LogEna",
    "LogRef",
    "DatSet",
    "OldEntrTm",
    "NewEntrTm",
    "OldEnt",
    "NewEnt",
    "TrgOps",
    "IntgPd",
];

const URCB_MEMBERS: [&str; 12] = [
    "RptID", "RptEna", "Resv", "DatSet", "ConfRev", "OptFlds", "BufTm", "SqNum", "TrgOps",
    "IntgPd", "GI", "Owner",
];

const BRCB_MEMBERS: [&str; 15] = [
    "RptID",
    "RptEna",
    "DatSet",
    "ConfRev",
    "OptFlds",
    "BufTm",
    "SqNum",
    "TrgOps",
    "IntgPd",
    "GI",
    "PurgeBuf",
    "EntryID",
    "TimeofEntry",
    "ResvTms",
    "Owner",
];

macro_rules! t {
    ($e:expr) => {
        tokio::time::timeout(Duration::from_secs(5), $e)
            .await
            .expect("timed out")
    };
}

fn leaf(name: &str, fc: FC, ty: DataAttributeType, value: MmsValue) -> DataAttribute {
    DataAttribute::new(name, fc, ty, TrgOps::default(), value)
}

fn float_struct(name: &str, fc: FC, value: f32) -> DataAttribute {
    DataAttribute::constructed(
        name,
        fc,
        vec![leaf(
            "f",
            fc,
            DataAttributeType::Float32,
            MmsValue::Float32(value),
        )],
    )
}

/// LLN0 with a setting group control block, GGIO1 with a status and a
/// measurement, MMXU1 with a constructed measurement, and PTOC1 with a
/// constructed setting under SP and SE.
fn model(resv_tms: bool) -> Arc<IedModel> {
    let lln0 = LogicalNodeBuilder::lln0()
        .add_do(
            DataObjectBuilder::scalar("Mod")
                .add_da_node(leaf(
                    "stVal",
                    FC::St,
                    DataAttributeType::Enumerated,
                    MmsValue::Integer(1),
                ))
                .build()
                .unwrap(),
        )
        .set_sgcb({
            let mut sgcb = SettingGroupControlBlock::default();
            sgcb.num_of_sg = 3;
            sgcb.act_sg = 1;
            sgcb.has_resv_tms = resv_tms;
            sgcb.default_resv_tms_s = 30;
            sgcb
        })
        .build()
        .unwrap();
    let ggio = LogicalNodeBuilder::new("", "GGIO", "1")
        .add_do(
            DataObjectBuilder::scalar("Ind1")
                .add_da_node(leaf(
                    "stVal",
                    FC::St,
                    DataAttributeType::Boolean,
                    MmsValue::Boolean(true),
                ))
                .build()
                .unwrap(),
        )
        .add_do(
            DataObjectBuilder::scalar("Ind2")
                .add_da_node(leaf(
                    "stVal",
                    FC::St,
                    DataAttributeType::Boolean,
                    MmsValue::Boolean(false),
                ))
                .build()
                .unwrap(),
        )
        .add_do(
            DataObjectBuilder::scalar("AnIn1")
                .add_da_node(float_struct("mag", FC::Mx, 7.0))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let ptoc = LogicalNodeBuilder::new("", "PTOC", "1")
        .add_do(
            DataObjectBuilder::scalar("StrVal")
                .add_da_node(float_struct("setMag", FC::Sp, 1.0))
                .build()
                .unwrap(),
        )
        .add_do(
            DataObjectBuilder::scalar("OpDlTmms")
                .add_da_node(float_struct("setMag", FC::Se, 1.0))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .add_ln(ggio)
        .add_ln(ptoc)
        .build()
        .unwrap();
    Arc::new(
        IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap(),
    )
}

fn shared_value(model: &IedModel, iec: &str, fc: FC) -> Arc<std::sync::RwLock<MmsValue>> {
    let mut r = ObjectRef::parse_iec(iec).expect("parse");
    r.fc = Some(fc);
    match model.node_by_object_ref(&r) {
        Some(NodeRef::Da(da)) => Arc::clone(&da.value),
        other => panic!("{iec} is not a data attribute: {other:?}"),
    }
}

fn status_data_set(model: &IedModel) -> Dataset {
    let mut ds = Dataset::new("LLN0$dsStatus");
    ds.push(DatasetEntry::new(
        format!("{DOM}/GGIO1$ST$Ind1$stVal"),
        shared_value(model, "IED1LD0/GGIO1.Ind1.stVal", FC::St),
    ));
    ds.push(DatasetEntry::new(
        format!("{DOM}/GGIO1$ST$Ind2$stVal"),
        shared_value(model, "IED1LD0/GGIO1.Ind2.stVal", FC::St),
    ));
    ds
}

fn server_with(model: Arc<IedModel>, config: IedServerConfig) -> IedServer {
    IedServer::builder()
        .model(model)
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(config)
        .build()
        .expect("build server")
}

/// A server with a data set, an unbuffered and a buffered report control
/// block, and a log control block, all in LLN0.
fn server_with_control_blocks() -> IedServer {
    let m = model(true);
    let server = server_with(m.clone(), IedServerConfig::default());
    server.register_dataset(DOM, status_data_set(&m));
    server
        .register_urcb(
            ReportControl::new(
                format!("{DOM}/LLN0$RP$urcbA"),
                Rcb::new("urcbA", format!("{DOM}/LLN0$dsStatus")),
            ),
            status_data_set(&m),
        )
        .expect("register urcb");
    server
        .register_brcb(
            BufferedReportControl::new(
                format!("{DOM}/LLN0$BR$brcbA"),
                Brcb::new("brcbA", format!("{DOM}/LLN0$dsStatus")),
            ),
            status_data_set(&m),
        )
        .expect("register brcb");
    let block = LogControlBlock::new("evlog")
        .with_dataset("LLN0$dsStatus")
        .with_log_ref(format!("{DOM}/LLN0$EventLog"));
    server.register_log_control(
        DOM,
        "LLN0$LG$evlog",
        Arc::new(LogControl::new(format!("{DOM}/LLN0$LG$evlog"), block)),
    );
    server
}

async fn mms(handle: &ServerHandle) -> MmsClient {
    let mut c = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    t!(c.connect("127.0.0.1", handle.bound_addr.port())).expect("connect");
    c
}

async fn ied(handle: &ServerHandle) -> IedConnection {
    let mms = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    let conn = IedConnection::with_mms_client(mms);
    t!(conn.connect("127.0.0.1", handle.bound_addr.port())).expect("connect");
    conn
}

fn member_names(spec: &TypeSpecification) -> Vec<String> {
    match spec {
        TypeSpecification::Structure { components } => {
            components.iter().map(|c| c.name.clone()).collect()
        }
        other => panic!("expected a structure, got {other:?}"),
    }
}

/// Reports whether `value` has the shape `spec` describes: the same structure
/// nesting and member counts, and leaves of the matching kind.
fn fits(spec: &TypeSpecification, value: &MmsData) -> bool {
    use TypeSpecification as T;
    match (spec, value) {
        (T::Structure { components }, MmsData::Structure(members)) => {
            components.len() == members.len()
                && components
                    .iter()
                    .zip(members)
                    .all(|(c, m)| fits(&c.type_spec, m))
        }
        (T::Array { element_type, .. }, MmsData::Array(items)) => {
            items.iter().all(|i| fits(element_type, i))
        }
        (T::Boolean, MmsData::Boolean(_))
        | (T::Integer { .. }, MmsData::Integer(_))
        | (T::Unsigned { .. }, MmsData::Unsigned(_))
        | (T::FloatingPoint { .. }, MmsData::Float32(_) | MmsData::Float64(_))
        | (T::BitString { .. }, MmsData::BitString { .. })
        | (T::OctetString { .. }, MmsData::OctetString(_))
        | (T::VisibleString { .. }, MmsData::VisibleString(_))
        | (T::MmsString { .. }, MmsData::MmsString(_))
        | (T::UtcTime, MmsData::UtcTime(_))
        | (T::BinaryTime { .. }, MmsData::BinaryTime(_)) => true,
        _ => false,
    }
}

async fn names(c: &mut MmsClient, continue_after: Option<&str>) -> (Vec<String>, bool) {
    t!(c.get_name_list(ObjectClass::NamedVariable, Some(DOM), continue_after)).expect("names")
}

async fn all_names(c: &mut MmsClient) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let (page, more) = names(c, cursor.as_deref()).await;
        cursor = page.last().cloned();
        out.extend(page);
        if !more {
            return out;
        }
    }
}

// ── Functional constraint on the read path ──────────────────────────────

/// A data attribute exists only under its own functional constraint, so a read
/// naming it under another one answers object-non-existent, as
/// GetVariableAccessAttributes does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_resolves_an_attribute_only_under_its_own_fc() {
    let server = server_with(model(false), IedServerConfig::default());
    let handle = server.start().await.unwrap();
    let mut c = mms(&handle).await;

    assert_eq!(
        t!(c.read(DOM, "GGIO1$ST$Ind1$stVal")).expect("own constraint"),
        MmsData::Boolean(true)
    );
    for item in ["GGIO1$MX$Ind1$stVal", "GGIO1$CF$Ind1$stVal"] {
        let read = t!(c.read(DOM, item));
        assert!(
            matches!(
                read,
                Err(ClientError::DataAccessError(
                    DataAccessError::ObjectNonExistent
                ))
            ),
            "{item}: {read:?}"
        );
        assert!(t!(c.get_variable_access_attributes(DOM, item)).is_err());
    }
    handle.stop().await;
}

// ── Report and log control blocks ───────────────────────────────────────

/// Every report and log control block GetNameList lists has a type
/// description, its members in IEC 61850-8-1 order, and the list carries the
/// group, the block, and each member.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listed_control_blocks_have_type_descriptions() {
    let server = server_with_control_blocks();
    let handle = server.start().await.unwrap();
    let mut c = mms(&handle).await;

    let listed = all_names(&mut c).await;
    for (group, block, members) in [
        ("LLN0$RP", "urcbA", &URCB_MEMBERS[..]),
        ("LLN0$BR", "brcbA", &BRCB_MEMBERS[..]),
        ("LLN0$LG", "evlog", &LCB_MEMBERS[..]),
    ] {
        let item = format!("{group}${block}");
        let spec = t!(c.get_variable_access_attributes(DOM, &item))
            .unwrap_or_else(|e| panic!("{item} has no type description: {e:?}"));
        assert_eq!(member_names(&spec), members, "{item}");
        for name in [group.to_string(), item.clone()]
            .into_iter()
            .chain(members.iter().map(|m| format!("{item}${m}")))
        {
            assert!(listed.contains(&name), "{name} is not listed");
            assert!(
                t!(c.get_variable_access_attributes(DOM, &name)).is_ok(),
                "{name} is listed but has no type description"
            );
        }
    }
    let lln0 = t!(c.get_variable_access_attributes(DOM, "LLN0")).unwrap();
    assert_eq!(member_names(&lln0), ["ST", "SP", "RP", "LG", "BR"]);
    handle.stop().await;
}

/// The member types of a log control block follow the IEC 61850-8-1 mapping,
/// and the ACSI names of OldEnt and NewEnt resolve to the same components
/// without being listed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn log_control_block_member_types() {
    let server = server_with_control_blocks();
    let handle = server.start().await.unwrap();
    let mut c = mms(&handle).await;

    let listed = all_names(&mut c).await;
    for (acsi, mms_name) in [("OldEntr", "OldEnt"), ("NewEntr", "NewEnt")] {
        let by_acsi = t!(c.get_variable_access_attributes(DOM, &format!("LLN0$LG$evlog${acsi}")))
            .unwrap_or_else(|e| panic!("{acsi}: {e:?}"));
        let by_mms =
            t!(c.get_variable_access_attributes(DOM, &format!("LLN0$LG$evlog${mms_name}")))
                .unwrap();
        assert_eq!(by_acsi, by_mms);
        assert!(!listed.contains(&format!("LLN0$LG$evlog${acsi}")));
    }

    let TypeSpecification::Structure { components } =
        t!(c.get_variable_access_attributes(DOM, "LLN0$LG$evlog")).unwrap()
    else {
        panic!("a log control block is a structure");
    };
    use TypeSpecification as T;
    let types: Vec<_> = components.into_iter().map(|c| c.type_spec).collect();
    assert_eq!(
        types,
        [
            T::Boolean,
            T::VisibleString { max_chars: -129 },
            T::VisibleString { max_chars: -129 },
            T::BinaryTime {
                use_long_form: true
            },
            T::BinaryTime {
                use_long_form: true
            },
            T::OctetString { max_octets: 8 },
            T::OctetString { max_octets: 8 },
            T::BitString { bits: -6 },
            T::Unsigned { width_bits: 32 },
        ]
    );
    handle.stop().await;
}

/// A read of a report or log control block, of its group, and of the whole
/// logical node returns the layout the type description gives the same name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_block_reads_follow_their_type_description() {
    let server = server_with_control_blocks();
    let handle = server.start().await.unwrap();
    let mut c = mms(&handle).await;

    for item in [
        "LLN0$RP$urcbA",
        "LLN0$BR$brcbA",
        "LLN0$LG$evlog",
        "LLN0$RP",
        "LLN0$BR",
        "LLN0$LG",
    ] {
        let spec = t!(c.get_variable_access_attributes(DOM, item)).unwrap();
        let value = t!(c.read(DOM, item)).unwrap_or_else(|e| panic!("{item}: {e:?}"));
        assert!(
            fits(&spec, &value),
            "{item}: {value:?} does not fit {spec:?}"
        );
    }
    let spec = t!(c.get_variable_access_attributes(DOM, "LLN0")).unwrap();
    let value = t!(c.read(DOM, "LLN0")).unwrap();
    let (TypeSpecification::Structure { components }, MmsData::Structure(groups)) = (&spec, &value)
    else {
        panic!("LLN0 is a structure");
    };
    assert_eq!(components.len(), groups.len());
    for (c, g) in components.iter().zip(groups) {
        assert!(fits(&c.type_spec, g), "LLN0${}: {g:?}", c.name);
    }
    handle.stop().await;
}

// ── Setting group control block ─────────────────────────────────────────

/// The type description of a setting group control block carries ResvTms
/// when the block exposes it, and every read of the block, of the SP group,
/// and of LLN0 returns the layout the type description gives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setting_group_control_block_reads_follow_their_type_description() {
    for resv_tms in [true, false] {
        let server = server_with(model(resv_tms), IedServerConfig::default());
        let handle = server.start().await.unwrap();
        let mut c = mms(&handle).await;

        let spec = t!(c.get_variable_access_attributes(DOM, "LLN0$SP$SGCB")).unwrap();
        let mut expected = vec!["NumOfSG", "ActSG", "EditSG", "CnfEdit", "LActTm"];
        if resv_tms {
            expected.push("ResvTms");
        }
        assert_eq!(member_names(&spec), expected);
        assert_eq!(
            t!(c.get_variable_access_attributes(DOM, "LLN0$SP$SGCB$ResvTms")).is_ok(),
            resv_tms
        );
        assert_eq!(
            all_names(&mut c)
                .await
                .contains(&"LLN0$SP$SGCB$ResvTms".to_string()),
            resv_tms
        );
        for item in ["LLN0$SP$SGCB", "LLN0$SP", "LLN0"] {
            let spec = t!(c.get_variable_access_attributes(DOM, item)).unwrap();
            let value = t!(c.read(DOM, item)).unwrap_or_else(|e| panic!("{item}: {e:?}"));
            assert!(
                fits(&spec, &value),
                "{item}: {value:?} does not fit {spec:?}"
            );
        }
        handle.stop().await;
    }
}

/// A setting group control block exists only in LLN0: the same path under
/// another logical node neither reads nor writes, and the control block of
/// LLN0 keeps its value.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setting_group_control_block_is_only_in_lln0() {
    let server = server_with(model(false), IedServerConfig::default());
    let handle = server.start().await.unwrap();
    let mut c = mms(&handle).await;

    let read = t!(c.read(DOM, "GGIO1$SP$SGCB$ActSG"));
    assert!(
        matches!(
            read,
            Err(ClientError::DataAccessError(
                DataAccessError::ObjectNonExistent
            ))
        ),
        "{read:?}"
    );
    assert!(t!(c.write(DOM, "GGIO1$SP$SGCB$ActSG", MmsData::Unsigned(2))).is_err());
    assert_eq!(
        t!(c.read(DOM, "LLN0$SP$SGCB$ActSG")).unwrap(),
        MmsData::Unsigned(1)
    );
    t!(c.write(DOM, "LLN0$SP$SGCB$ActSG", MmsData::Unsigned(2))).expect("LLN0 is served");
    assert_eq!(
        t!(c.read(DOM, "LLN0$SP$SGCB$ActSG")).unwrap(),
        MmsData::Unsigned(2)
    );
    handle.stop().await;
}

/// LActTm carries the time quality the server is configured with.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn last_activation_time_carries_the_configured_time_quality() {
    let quality = TimeQuality {
        leap_seconds_known: false,
        clock_failure: true,
        clock_not_synchronized: true,
        time_accuracy: 3,
    };
    for (config, expected) in [
        (IedServerConfig::default(), TimeQuality::default().to_byte()),
        (
            {
                let mut config = IedServerConfig::default();
                config.time_quality = quality;
                config
            },
            quality.to_byte(),
        ),
    ] {
        let server = server_with(model(false), config);
        let handle = server.start().await.unwrap();
        let mut c = mms(&handle).await;
        let MmsData::UtcTime(t) = t!(c.read(DOM, "LLN0$SP$SGCB$LActTm")).unwrap() else {
            panic!("LActTm is a UTC time");
        };
        assert_eq!(t[7], expected);
        handle.stop().await;
    }
}

// ── Data set members ────────────────────────────────────────────────────

/// A data set member naming a constructed attribute reads as the structure of
/// its leaves, and a member naming one of its leaves as the leaf value
/// (IEC 61850-7-2 §13.2.2.3).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_data_set_takes_a_constructed_member() {
    let server = server_with(model(false), IedServerConfig::default());
    let handle = server.start().await.unwrap();
    let conn = ied(&handle).await;

    t!(conn.create_data_set(
        "IED1LD0/LLN0.dynCons",
        &[DataSetMember::new("IED1LD0/GGIO1.AnIn1.mag", FC::Mx)]
    ))
    .expect("a constructed member is accepted");
    let values = t!(conn.get_data_set_values("IED1LD0/LLN0.dynCons")).unwrap();
    assert_eq!(
        values,
        [AccessResult::Success(MmsData::Structure(vec![
            MmsData::Float32(7.0)
        ]))]
    );
    t!(conn.create_data_set(
        "IED1LD0/LLN0.dynLeaf",
        &[DataSetMember::new("IED1LD0/GGIO1.AnIn1.mag.f", FC::Mx)]
    ))
    .expect("a leaf member is accepted");
    let values = t!(conn.get_data_set_values("IED1LD0/LLN0.dynLeaf")).unwrap();
    assert_eq!(values, [AccessResult::Success(MmsData::Float32(7.0))]);
    handle.stop().await;
}

/// A persistent data set name is `<LN>$<name>` of a logical node that exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_data_set_checks_the_list_name() {
    let server = server_with(model(false), IedServerConfig::default());
    let handle = server.start().await.unwrap();
    let mut c = mms(&handle).await;
    let member = || {
        vec![DefineNamedVariableEntry {
            domain_id: DOM.into(),
            item_id: "GGIO1$ST$Ind1$stVal".into(),
        }]
    };

    for name in ["noLogicalNode", "LLN0$", "$ds", "LLN0$a$b", "NOSUCH1$ds"] {
        let r = t!(c.define_named_variable_list(DOM, name, member()));
        assert!(r.is_err(), "{name}: {r:?}");
    }
    let (lists, _) = t!(c.get_name_list(ObjectClass::NamedVariableList, Some(DOM), None)).unwrap();
    assert!(lists.is_empty(), "{lists:?}");
    t!(c.define_named_variable_list(DOM, "GGIO1$ds", member())).expect("a well-formed name");
    handle.stop().await;
}

#[derive(Debug)]
struct Deny;
impl ReadHandler for Deny {
    fn read(&self, _ctx: &ReadContext<'_>) -> ReadOutcome {
        ReadOutcome::Error(DataAccessError::ObjectAccessDenied)
    }
}

/// A read handler applies to a data set member exactly as to a direct read of
/// it, whether the application or a client defined the data set; the other
/// members keep their values.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn data_set_values_go_through_the_read_handler() {
    let m = model(false);
    let server = server_with(m.clone(), IedServerConfig::default());
    server.register_dataset(DOM, status_data_set(&m));
    server
        .install_read_handler("GGIO1$ST$Ind1$stVal", Arc::new(Deny))
        .unwrap();
    let handle = server.start().await.unwrap();
    let conn = ied(&handle).await;

    assert!(t!(conn.read_object("IED1LD0/GGIO1.Ind1.stVal", FC::St)).is_err());
    t!(conn.create_data_set(
        "IED1LD0/LLN0.dynLeak",
        &[
            DataSetMember::new("IED1LD0/GGIO1.Ind1.stVal", FC::St),
            DataSetMember::new("IED1LD0/GGIO1.Ind2.stVal", FC::St),
        ]
    ))
    .unwrap();
    for ds in ["IED1LD0/LLN0.dsStatus", "IED1LD0/LLN0.dynLeak"] {
        let values = t!(conn.get_data_set_values(ds)).unwrap();
        assert_eq!(
            values,
            [
                AccessResult::Failure(DataAccessError::ObjectAccessDenied),
                AccessResult::Success(MmsData::Boolean(false)),
            ],
            "{ds}"
        );
    }
    handle.stop().await;
}

/// GetDataSetValues of a data set that does not exist fails the service, as
/// GetDataSetDirectory does, rather than answering one failed member.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn data_set_values_of_an_unknown_data_set_fail_the_service() {
    let m = model(false);
    let server = server_with(m.clone(), IedServerConfig::default());
    server.register_dataset(DOM, status_data_set(&m));
    let handle = server.start().await.unwrap();
    let mut c = mms(&handle).await;

    let unknown = t!(c.read_named_variable_list_values(DOM, "LLN0$noSuch"));
    assert!(
        matches!(
            unknown,
            Err(ClientError::ServiceError {
                error_class: ErrorClass::Access(access::OBJECT_NON_EXISTENT),
                ..
            })
        ),
        "{unknown:?}"
    );
    assert_eq!(
        t!(c.read_named_variable_list_values(DOM, "LLN0$dsStatus"))
            .unwrap()
            .len(),
        2
    );
    handle.stop().await;
}

// ── Writes below a constructed attribute ────────────────────────────────

/// A leaf below a constructed SP setting is written by its own path, and the
/// whole setting by a structure with one member per leaf.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn constructed_setting_is_writable_leaf_by_leaf_and_whole() {
    let server = server_with(model(false), IedServerConfig::default());
    let handle = server.start().await.unwrap();
    let mut c = mms(&handle).await;

    t!(c.write(DOM, "PTOC1$SP$StrVal$setMag$f", MmsData::Float32(2.5))).expect("leaf");
    assert_eq!(
        t!(c.read(DOM, "PTOC1$SP$StrVal$setMag$f")).unwrap(),
        MmsData::Float32(2.5)
    );
    t!(c.write(
        DOM,
        "PTOC1$SP$StrVal$setMag",
        MmsData::Structure(vec![MmsData::Float32(3.5)])
    ))
    .expect("whole");
    assert_eq!(
        t!(c.read(DOM, "PTOC1$SP$StrVal$setMag")).unwrap(),
        MmsData::Structure(vec![MmsData::Float32(3.5)])
    );
    let mismatched = t!(c.write(
        DOM,
        "PTOC1$SP$StrVal$setMag",
        MmsData::Structure(vec![MmsData::Float32(4.5), MmsData::Float32(5.5)])
    ));
    assert!(mismatched.is_err());
    assert_eq!(
        t!(c.read(DOM, "PTOC1$SP$StrVal$setMag$f")).unwrap(),
        MmsData::Float32(3.5)
    );
    handle.stop().await;
}

/// SetEditSGValue reaches a leaf below a constructed SE setting once the
/// association holds the edit session, and only then.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn constructed_edit_setting_is_writable_in_an_edit_session() {
    let server = server_with(model(false), IedServerConfig::default());
    let handle = server.start().await.unwrap();
    let mut c = mms(&handle).await;

    let item = "PTOC1$SE$OpDlTmms$setMag$f";
    assert!(t!(c.write(DOM, item, MmsData::Float32(9.0))).is_err());
    t!(c.write(DOM, "LLN0$SP$SGCB$EditSG", MmsData::Unsigned(2))).expect("edit session");
    t!(c.write(DOM, item, MmsData::Float32(9.0))).expect("leaf in the edit session");
    assert_eq!(t!(c.read(DOM, item)).unwrap(), MmsData::Float32(9.0));
    handle.stop().await;
}

#[derive(Debug)]
struct RefuseWrites;
impl AttributeAccessHandler for RefuseWrites {
    fn on_write(&self, _ctx: &WriteContext<'_>, _value: &MmsValue) -> WriteOutcome {
        WriteOutcome::Reject(DataAccessError::ObjectAccessDenied)
    }
}

/// A write handler on a constructed setting refuses a write of a leaf below
/// it as it refuses a write of the whole setting, under SP and under SE in an
/// edit session; a setting without the handler stays writable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leaf_write_is_decided_by_the_handler_of_its_constructed_attribute() {
    let server = server_with(model(false), IedServerConfig::default());
    for path in ["PTOC1$SP$StrVal$setMag", "PTOC1$SE$OpDlTmms$setMag"] {
        server
            .install_write_access_handler(path, Arc::new(RefuseWrites))
            .unwrap();
    }
    let handle = server.start().await.unwrap();
    let mut c = mms(&handle).await;
    t!(c.write(DOM, "LLN0$SP$SGCB$EditSG", MmsData::Unsigned(2))).expect("edit session");

    for item in ["PTOC1$SP$StrVal$setMag$f", "PTOC1$SE$OpDlTmms$setMag$f"] {
        let r = t!(c.write(DOM, item, MmsData::Float32(5.0)));
        assert!(
            matches!(
                r,
                Err(ClientError::DataAccessError(
                    DataAccessError::ObjectAccessDenied
                ))
            ),
            "{item}: {r:?}"
        );
        assert_eq!(
            t!(c.read(DOM, item)).unwrap(),
            MmsData::Float32(1.0),
            "{item}"
        );
    }
    t!(c.write(DOM, "GGIO1$MX$AnIn1$mag$f", MmsData::Float32(5.0)))
        .expect_err("MX stays read-only");
    handle.stop().await;
}

// ── GetNameList paging ──────────────────────────────────────────────────

/// A continueAfter name that is not in the list resumes at the next name in
/// order instead of failing the enumeration.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_name_list_resumes_after_an_absent_name() {
    let server = server_with(model(false), IedServerConfig::default());
    let handle = server.start().await.unwrap();
    let mut c = mms(&handle).await;

    let all = all_names(&mut c).await;
    let (page, _) = names(&mut c, Some("GGIO1$ST$Ind1$zz")).await;
    let expected: Vec<String> = all
        .iter()
        .filter(|n| n.as_str() > "GGIO1$ST$Ind1$zz")
        .cloned()
        .collect();
    assert_eq!(page.first(), expected.first());
    assert!(!page.is_empty());
    let (control, _) = names(&mut c, Some("GGIO1$ST$Ind1$stVal")).await;
    assert_eq!(control.first(), expected.first());
    handle.stop().await;
}

// ── specificationWithResult ─────────────────────────────────────────────

fn read_request(spec: VariableAccessSpecification, with_result: bool) -> ReadRequest {
    ReadRequest {
        specification_with_result: with_result,
        variable_access_spec: spec,
    }
}

/// Sends one Read over a bare MMS association and decodes the ReadResponse.
async fn raw_read(conn: &mut MmsConnection, invoke_id: u32, req: &ReadRequest) -> ReadResponse {
    let mut full = BytesMut::new();
    encode_confirmed_read_request(invoke_id, req, &mut full);
    let content = Bytes::from(strip_tag_and_length(&full).to_vec());
    t!(conn.send_mms_pdu(&MmsPdu::ConfirmedRequest(content))).expect("send");
    let MmsPdu::ConfirmedResponse(body) = t!(conn.recv_mms_pdu_confirmed()).expect("recv") else {
        panic!("a confirmed response");
    };
    // The body is the invoke id followed by the ReadResponse.
    let after_invoke_id = strip_tag_and_length_prefix(&body);
    ReadResponse::decode(after_invoke_id).expect("decode ReadResponse")
}

/// The content of the BER TLV at the start of `tlv`.
fn strip_tag_and_length(tlv: &[u8]) -> &[u8] {
    let (header, len) = ber_header(tlv);
    &tlv[header..header + len]
}

/// What follows the BER TLV at the start of `tlv`.
fn strip_tag_and_length_prefix(tlv: &[u8]) -> &[u8] {
    let (header, len) = ber_header(tlv);
    &tlv[header + len..]
}

fn ber_header(tlv: &[u8]) -> (usize, usize) {
    let first = tlv[1];
    if first < 0x80 {
        return (2, usize::from(first));
    }
    let n = usize::from(first & 0x7f);
    let len = tlv[2..2 + n]
        .iter()
        .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
    (2 + n, len)
}

/// Sends one Read over a bare MMS association and returns the answering PDU.
async fn raw_read_pdu(conn: &mut MmsConnection, invoke_id: u32, req: &ReadRequest) -> MmsPdu {
    let mut full = BytesMut::new();
    encode_confirmed_read_request(invoke_id, req, &mut full);
    let content = Bytes::from(strip_tag_and_length(&full).to_vec());
    t!(conn.send_mms_pdu(&MmsPdu::ConfirmedRequest(content))).expect("send");
    t!(conn.recv_mms_pdu_confirmed()).expect("recv")
}

/// The echoed access specification counts against the negotiated maximum
/// PDU size: results that fit on their own but not together with the echo
/// answer resource other instead of an oversized response.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn echoed_access_specification_counts_against_the_pdu_size() {
    let server = server_with(model(false), IedServerConfig::default());
    let handle = server.start().await.unwrap();
    let mut conn: MmsConnection = MmsConnection::new();
    conn.local_max_pdu_size = Some(1024);
    t!(conn.connect("127.0.0.1", handle.bound_addr.port())).expect("connect");

    // Twenty-seven booleans fit in 1024 bytes, and so does a request naming
    // them, but not a response carrying both.
    let VariableAccessSpecification::ListOfVariable(one) =
        ReadRequest::single_domain(DOM, "GGIO1$ST$Ind1$stVal").variable_access_spec
    else {
        unreachable!("single_domain builds a list of variables");
    };
    let spec = VariableAccessSpecification::ListOfVariable(vec![one[0].clone(); 27]);
    let plain = raw_read_pdu(&mut conn, 1, &read_request(spec.clone(), false)).await;
    assert!(matches!(plain, MmsPdu::ConfirmedResponse(_)), "{plain:?}");
    let echoed = raw_read_pdu(&mut conn, 2, &read_request(spec, true)).await;
    let MmsPdu::ConfirmedError(body) = echoed else {
        panic!("an echo that does not fit must answer an error: {echoed:?}");
    };
    let (_, error) = decode_confirmed_error_inner(&body).expect("decode ConfirmedError");
    assert_eq!(error.error_class, ErrorClass::Resource(resource::OTHER));
    handle.stop().await;
}

/// A Read that sets specificationWithResult gets its access specification
/// back, for a list of variables and for a data set; one that does not set it
/// gets none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_echoes_the_access_specification_on_request() {
    let m = model(false);
    let server = server_with(m.clone(), IedServerConfig::default());
    server.register_dataset(DOM, status_data_set(&m));
    let handle = server.start().await.unwrap();
    let mut conn: MmsConnection = MmsConnection::new();
    t!(conn.connect("127.0.0.1", handle.bound_addr.port())).expect("connect");

    let list = ReadRequest::single_domain(DOM, "GGIO1$ST$Ind1$stVal").variable_access_spec;
    let named = VariableAccessSpecification::VariableListName(ObjectName::DomainSpecific {
        domain_id: DOM.into(),
        item_id: "LLN0$dsStatus".into(),
    });
    for (invoke_id, spec) in [(1, list), (2, named)] {
        let echoed = raw_read(&mut conn, invoke_id, &read_request(spec.clone(), true)).await;
        assert_eq!(echoed.variable_access_spec.as_ref(), Some(&spec));
        assert!(!echoed.list_of_access_result.is_empty());
        let plain = raw_read(&mut conn, invoke_id + 10, &read_request(spec, false)).await;
        assert_eq!(plain.variable_access_spec, None);
    }
    handle.stop().await;
}
