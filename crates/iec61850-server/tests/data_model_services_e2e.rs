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
use iec61850_mms::mms::pdu::type_specification::TypeSpecification;
use iec61850_mms::mms::pdu::{DefineNamedVariableEntry, MmsPdu};
use iec61850_mms::mms::MmsData;
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObjectBuilder, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, NodeRef, ObjectRef,
    SettingGroupControlBlock, TrgOps, FC,
};
use iec61850_server::handler::{ReadContext, ReadHandler, ReadOutcome};
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
        .set_sgcb(SettingGroupControlBlock {
            num_of_sg: 3,
            act_sg: 1,
            has_resv_tms: resv_tms,
            default_resv_tms_s: 30,
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

// ── Setting group control block ─────────────────────────────────────────

// ── Data set members ────────────────────────────────────────────────────

#[derive(Debug)]
struct Deny;
impl ReadHandler for Deny {
    fn read(&self, _ctx: &ReadContext<'_>) -> ReadOutcome {
        ReadOutcome::Error(DataAccessError::ObjectAccessDenied)
    }
}

// ── Writes below a constructed attribute ────────────────────────────────

// ── GetNameList paging ──────────────────────────────────────────────────

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
