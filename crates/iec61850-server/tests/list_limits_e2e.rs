//! The number of variables a request may name, over a real association:
//! loopback TCP and the full ISO stack.
//!
//! A request naming more variables than the server handles is answered with
//! `resource` `capability-unavailable` (IEC 61850-8-1 §8.1.3.4.3.4), whether
//! the data set member limit or the limit of the request decoder refuses it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use iec61850_mms::mms::client::{ClientError, MmsClient, MmsClientBuilder, MmsConnection};
use iec61850_mms::mms::pdu::get_name_list::ObjectClass;
use iec61850_mms::mms::pdu::service_error::{
    decode_confirmed_error_inner,
    subcode::{access, resource},
    ErrorClass,
};
use iec61850_mms::mms::pdu::{DefineNamedVariableEntry, MmsPdu, MAX_DEFINE_ENTRIES};
use iec61850_mms::mms::MmsData;
use iec61850_mms::MAX_WRITE_ITEMS;
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObjectBuilder, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::reporting::DynamicDatasetOps;
use iec61850_server::{IedServer, IedServerConfig, ServerHandle};

const DOM: &str = "IED1LD0";

macro_rules! t {
    ($e:expr) => {
        tokio::time::timeout(Duration::from_secs(10), $e)
            .await
            .expect("timed out")
    };
}

fn model() -> Arc<IedModel> {
    let leaf = |name: &str| {
        DataAttribute::new(
            name,
            FC::St,
            DataAttributeType::Boolean,
            TrgOps::default(),
            MmsValue::Boolean(false),
        )
    };
    let lln0 = LogicalNodeBuilder::lln0()
        .add_do(
            DataObjectBuilder::scalar("Mod")
                .add_da_node(leaf("stVal"))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let ggio = LogicalNodeBuilder::new("", "GGIO", "1")
        .add_do(
            DataObjectBuilder::scalar("Ind1")
                .add_da_node(leaf("stVal"))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .add_ln(ggio)
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

async fn start() -> ServerHandle {
    IedServer::builder()
        .model(model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig::default())
        .build()
        .expect("build server")
        .start()
        .await
        .expect("start server")
}

async fn mms(handle: &ServerHandle) -> MmsClient {
    let mut c = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(5_000)
        .build();
    t!(c.connect("127.0.0.1", handle.bound_addr.port())).expect("connect");
    c
}

fn members(n: usize) -> Vec<DefineNamedVariableEntry> {
    vec![DefineNamedVariableEntry::domain(DOM, "GGIO1$ST$Ind1$stVal"); n]
}

fn is_capability_unavailable<T: std::fmt::Debug>(r: &Result<T, ClientError>) -> bool {
    matches!(
        r,
        Err(ClientError::ServiceError {
            error_class: ErrorClass::Resource(resource::CAPABILITY_UNAVAILABLE),
            ..
        })
    )
}

async fn data_sets(c: &mut MmsClient) -> Vec<String> {
    t!(c.get_name_list(ObjectClass::NamedVariableList, Some(DOM), None))
        .expect("names")
        .0
}

/// A data set takes as many members as the run-time member limit, and one more
/// is answered `resource` `capability-unavailable` without creating anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_data_set_holds_up_to_the_member_limit() {
    let handle = start().await;
    let mut c = mms(&handle).await;

    t!(c.define_named_variable_list(DOM, "LLN0$small", members(2))).expect("two members");
    t!(c.define_named_variable_list(DOM, "LLN0$full", members(DynamicDatasetOps::MAX_MEMBERS)))
        .expect("a data set at the member limit");
    let over = t!(c.define_named_variable_list(
        DOM,
        "LLN0$over",
        members(DynamicDatasetOps::MAX_MEMBERS + 1)
    ));
    assert!(is_capability_unavailable(&over), "{over:?}");

    let mut lists = data_sets(&mut c).await;
    lists.sort();
    assert_eq!(lists, ["LLN0$full", "LLN0$small"]);
    let values = t!(c.read_named_variable_list_values(DOM, "LLN0$full")).unwrap();
    assert_eq!(values.len(), DynamicDatasetOps::MAX_MEMBERS);
    handle.stop().await;
}

/// The BER TLV of `tag` around `content`.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match content.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n <= 0xff => out.extend_from_slice(&[0x81, n as u8]),
        n => out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(content);
    out
}

/// A domain-specific ObjectName.
fn domain_name(domain: &str, item: &str) -> Vec<u8> {
    let mut inner = tlv(0x1a, domain.as_bytes());
    inner.extend(tlv(0x1a, item.as_bytes()));
    tlv(0xa1, &inner)
}

/// A DefineNamedVariableList request with more members than the decoder
/// accepts is answered `resource` `capability-unavailable` too, and the
/// association stays usable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_data_set_beyond_the_decoder_limit_is_capability_unavailable() {
    let handle = start().await;
    let mut conn = MmsConnection::new();
    t!(conn.connect("127.0.0.1", handle.bound_addr.port())).expect("connect");

    // Short names keep the request within the negotiated PDU size.
    let member = tlv(0x30, &tlv(0xa0, &domain_name("D", "x")));
    let list: Vec<u8> = member.repeat(MAX_DEFINE_ENTRIES + 1);
    let mut service = domain_name(DOM, "LLN0$huge");
    service.extend(tlv(0xa0, &list));
    let mut content = tlv(0x02, &[0x01]);
    content.extend(tlv(0xab, &service));
    assert!(content.len() < 65_000, "{}", content.len());

    t!(conn.send_mms_pdu(&MmsPdu::ConfirmedRequest(Bytes::from(content)))).expect("send");
    let MmsPdu::ConfirmedError(body) = t!(conn.recv_mms_pdu_confirmed()).expect("recv") else {
        panic!("a confirmed error");
    };
    let (invoke_id, error) = decode_confirmed_error_inner(&body).expect("decode ConfirmedError");
    assert_eq!(invoke_id, 1);
    assert_eq!(
        error.error_class,
        ErrorClass::Resource(resource::CAPABILITY_UNAVAILABLE)
    );

    // A request that is merely malformed keeps its own answer.
    let mut bad = tlv(0x02, &[0x02]);
    bad.extend(tlv(0xab, &domain_name(DOM, "LLN0$bad")));
    t!(conn.send_mms_pdu(&MmsPdu::ConfirmedRequest(Bytes::from(bad)))).expect("send");
    let MmsPdu::ConfirmedError(body) = t!(conn.recv_mms_pdu_confirmed()).expect("recv") else {
        panic!("a confirmed error");
    };
    let (_, error) = decode_confirmed_error_inner(&body).expect("decode ConfirmedError");
    assert_eq!(error.error_class, ErrorClass::Access(access::OTHER));
    handle.stop().await;
}

/// SetDataSetValues reaches every member of the largest data set a client can
/// create, and a Write with more items than the server writes in one request
/// is answered `resource` `capability-unavailable`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_holds_up_to_the_item_limit() {
    let handle = start().await;
    let mut c = mms(&handle).await;
    t!(c.define_named_variable_list(DOM, "LLN0$full", members(DynamicDatasetOps::MAX_MEMBERS)))
        .expect("a data set at the member limit");

    let small =
        t!(c.write_named_variable_list_values(DOM, "LLN0$full", vec![MmsData::Boolean(true); 2]));
    assert!(small.is_ok(), "{small:?}");
    let outcomes = t!(c.write_named_variable_list_values(
        DOM,
        "LLN0$full",
        vec![MmsData::Boolean(true); DynamicDatasetOps::MAX_MEMBERS]
    ))
    .expect("one outcome per member");
    assert_eq!(outcomes.len(), DynamicDatasetOps::MAX_MEMBERS);

    let over = t!(c.write_named_variable_list_values(
        DOM,
        "LLN0$full",
        vec![MmsData::Boolean(true); MAX_WRITE_ITEMS + 1]
    ));
    assert!(is_capability_unavailable(&over), "{over:?}");
    let outcomes =
        t!(c.write_named_variable_list_values(DOM, "LLN0$full", vec![MmsData::Boolean(true); 1]));
    assert!(outcomes.is_ok(), "the association survives: {outcomes:?}");
    handle.stop().await;
}
