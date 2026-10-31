//! End-to-end tests of single array element access through `read_object` and
//! `write_object` over real TCP and the full ISO stack.
//!
//! Covered: the exact Write request a reference with an index produces, with
//! and without a component below the element, against a scripted server
//! (IEC 61850-8-1 §24.2.2.4.1.2 Table 138, ISO 9506-2 AlternateAccess); and
//! element reads and writes against the crate's own server, for an array of a
//! basic type, an array of structures and an array of sub-data-objects.

mod support;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::BytesMut;
use iec61850_client::IedConnection;
use iec61850_mms::{
    decode_confirmed_write_request, encode_confirmed_write_response, MmsClientBuilder,
    WriteOutcome, WriteResponse,
};
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObject, DataObjectBuilder, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::IedServer;
use support::Plan;

async fn fresh_client(port: u16) -> IedConnection {
    let mms_client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    let conn = IedConnection::with_mms_client(mms_client);
    conn.connect("127.0.0.1", port)
        .await
        .expect("client.connect");
    conn
}

/// Starts a scripted server that keeps the first Write request it receives
/// and answers it with success.
async fn recording_server() -> (u16, Arc<Mutex<Vec<u8>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let keep = Arc::clone(&seen);
    let port = support::start(Arc::new(move |mms: &[u8], _seq: u32| {
        let (invoke_id, _) = decode_confirmed_write_request(mms).ok()?;
        keep.lock().unwrap().extend_from_slice(mms);
        let mut buf = BytesMut::new();
        encode_confirmed_write_response(
            invoke_id,
            &WriteResponse {
                outcomes: vec![WriteOutcome::Success],
            },
            &mut buf,
        );
        Some(Plan::reply(buf.freeze()))
    }))
    .await;
    (port, seen)
}

/// Replaces the one-octet invoke id of a confirmed request, the fifth octet,
/// with 0, so a request compares with a vector whatever id the client chose.
fn without_invoke_id(mut pdu: Vec<u8>) -> Vec<u8> {
    assert_eq!(&pdu[2..4], &[0x02, 0x01], "a one-octet invoke id");
    pdu[4] = 0;
    pdu
}

/// An index in the reference writes the element through an alternate access
/// that selects it, `[5] { selectAccess index }` on the variable the reference
/// names up to the array.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn element_write_sends_an_index_alternate_access() {
    let (port, seen) = recording_server().await;
    let conn = fresh_client(port).await;
    tokio::time::timeout(
        Duration::from_secs(5),
        conn.write_object("IED1LD0/GGIO1.Vals(2)", FC::Sp, MmsValue::Integer(7)),
    )
    .await
    .expect("timeout")
    .expect("write");
    conn.disconnect().await.ok();

    #[rustfmt::skip]
    let expected: Vec<u8> = vec![
        0xa0, 0x2f,                         // Confirmed-RequestPDU
        0x02, 0x01, 0x00,                   // invokeID
        0xa5, 0x2a,                         // write
        0xa0, 0x23,                         // listOfVariable
        0x30, 0x21,                         // one entry
        0xa0, 0x1a,                         // variableSpecification name
        0xa1, 0x18,                         // domain-specific
        0x1a, 0x07, b'I', b'E', b'D', b'1', b'L', b'D', b'0',
        0x1a, 0x0d, b'G', b'G', b'I', b'O', b'1', b'$', b'S', b'P', b'$', b'V', b'a', b'l', b's',
        0xa5, 0x03,                         // alternateAccess
        0x82, 0x01, 0x02,                   // selectAccess index 2
        0xa0, 0x03,                         // listOfData
        0x85, 0x01, 0x07,                   // integer 7
    ];
    assert_eq!(without_invoke_id(seen.lock().unwrap().clone()), expected);
}

/// A component after the index selects the member of the element through a
/// nested alternate access: `selectAlternateAccess { index, { selectAccess
/// component } }`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn element_member_write_sends_an_index_then_a_component() {
    let (port, seen) = recording_server().await;
    let conn = fresh_client(port).await;
    tokio::time::timeout(
        Duration::from_secs(5),
        conn.write_object("IED1LD0/GGIO1.Pts(1).x", FC::Sp, MmsValue::Float32(2.5)),
    )
    .await
    .expect("timeout")
    .expect("write");
    conn.disconnect().await.ok();

    #[rustfmt::skip]
    let expected: Vec<u8> = vec![
        0xa0, 0x39,                         // Confirmed-RequestPDU
        0x02, 0x01, 0x00,                   // invokeID
        0xa5, 0x34,                         // write
        0xa0, 0x29,                         // listOfVariable
        0x30, 0x27,                         // one entry
        0xa0, 0x19,                         // variableSpecification name
        0xa1, 0x17,                         // domain-specific
        0x1a, 0x07, b'I', b'E', b'D', b'1', b'L', b'D', b'0',
        0x1a, 0x0c, b'G', b'G', b'I', b'O', b'1', b'$', b'S', b'P', b'$', b'P', b't', b's',
        0xa5, 0x0a,                         // alternateAccess
        0xa0, 0x08,                         // selectAlternateAccess
        0x81, 0x01, 0x01,                   // accessSelection index 1
        0x30, 0x03,                         // alternateAccess
        0x81, 0x01, b'x',                   // selectAccess component x
        0xa0, 0x07,                         // listOfData
        0x87, 0x05, 0x08, 0x40, 0x20, 0x00, 0x00, // floating-point 2.5
    ];
    assert_eq!(without_invoke_id(seen.lock().unwrap().clone()), expected);
}

/// `GGIO1` of `IED1LD0` holds `Vals`, an SP array of four INT32, `Pts`, an SP
/// array of two structures of `x` and `y`, and `Har`, an SP array of three
/// sub-data-objects holding `setVal`.
fn array_model() -> Arc<IedModel> {
    let leaf = |name: &str, ty, value| DataAttribute::new(name, FC::Sp, ty, TrgOps::NONE, value);
    let vals = DataAttribute::array(
        leaf("vals", DataAttributeType::Int32, MmsValue::Integer(0)),
        4,
    )
    .unwrap();
    let point = DataAttribute::constructed(
        "pts",
        FC::Sp,
        vec![
            leaf("x", DataAttributeType::Float32, MmsValue::Float32(0.0)),
            leaf("y", DataAttributeType::Float32, MmsValue::Float32(0.0)),
        ],
    );
    let arr = DataObjectBuilder::scalar("Arr")
        .add_da_node(vals)
        .add_da_node(DataAttribute::array(point, 2).unwrap())
        .build()
        .unwrap();
    let ing = DataObjectBuilder::scalar("Har")
        .add_da_node(leaf(
            "setVal",
            DataAttributeType::Int32,
            MmsValue::Integer(0),
        ))
        .build()
        .unwrap();
    let spt = DataObjectBuilder::scalar("Spt")
        .add_sub_do(DataObject::array(ing, 3).unwrap())
        .build()
        .unwrap();
    let ggio = LogicalNodeBuilder::new("", "GGIO", "1")
        .add_do(arr)
        .add_do(spt)
        .build()
        .unwrap();
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(LogicalNodeBuilder::lln0().build().unwrap())
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

/// Against the crate's own server, an element written through `write_object`
/// reads back through `read_object`, by element and as part of the whole
/// array, and the other elements keep their values.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn elements_written_to_our_server_read_back() {
    let server = IedServer::builder()
        .model(array_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()
        .expect("build server");
    let handle = server.start().await.expect("start");
    let conn = fresh_client(handle.bound_addr.port()).await;
    let io = |r: &'static str, v: MmsValue| {
        let conn = &conn;
        async move {
            tokio::time::timeout(Duration::from_secs(5), conn.write_object(r, FC::Sp, v))
                .await
                .expect("timeout")
                .unwrap_or_else(|e| panic!("write {r}: {e}"))
        }
    };
    io("IED1LD0/GGIO1.Arr.vals(2)", MmsValue::Integer(-9)).await;
    io("IED1LD0/GGIO1.Arr.pts(1).y", MmsValue::Float32(4.5)).await;
    io("IED1LD0/GGIO1.Spt.Har(2).setVal", MmsValue::Integer(3)).await;
    let read = |r: &'static str| {
        let conn = &conn;
        async move {
            tokio::time::timeout(Duration::from_secs(5), conn.read_object(r, FC::Sp))
                .await
                .expect("timeout")
                .unwrap_or_else(|e| panic!("read {r}: {e}"))
        }
    };
    let element = read("IED1LD0/GGIO1.Arr.vals(2)").await;
    let whole = read("IED1LD0/GGIO1.Arr.vals").await;
    let point = read("IED1LD0/GGIO1.Arr.pts(1)").await;
    let set_val = read("IED1LD0/GGIO1.Spt.Har(2).setVal").await;
    let har = read("IED1LD0/GGIO1.Spt.Har").await;
    conn.disconnect().await.ok();
    handle.stop().await;

    assert_eq!(element, MmsValue::Integer(-9));
    assert_eq!(
        whole,
        MmsValue::Array(vec![
            MmsValue::Integer(0),
            MmsValue::Integer(0),
            MmsValue::Integer(-9),
            MmsValue::Integer(0),
        ])
    );
    assert_eq!(
        point,
        MmsValue::Structure(vec![MmsValue::Float32(0.0), MmsValue::Float32(4.5)])
    );
    assert_eq!(set_val, MmsValue::Integer(3));
    let one = |v| MmsValue::Structure(vec![MmsValue::Integer(v)]);
    assert_eq!(har, MmsValue::Array(vec![one(0), one(0), one(3)]));
}
