//! End-to-end round trips of `read_objects`, the multi-variable read, over a
//! loopback association.
//!
//! The model is a `simpleIOGenericIO` logical device with LLN0, LPHD1 and
//! GGIO1, carrying NamPlt, Ind, AnIn and SPCSO, matching the model of the
//! single-object tests. The cases cover mixed value types in one request, the
//! position of a failing entry, request order, an `AlternateAccess` entry
//! travelling inside the list, and the number of PDUs a call costs.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use iec61850_client::{ClientError, IedConnection};
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_mms::{AccessResult, DataAccessError, MmsData};
use iec61850_model::{
    cdc, ControlModel, ControlOptions, DataAttribute, DataAttributeType, DataObjectBuilder,
    IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNode, LogicalNodeBuilder, MmsValue,
    NodeRef, ObjectRef, TrgOps, FC,
};
use iec61850_server::{IedServer, IedServerConfig, WriteAccessPolicies};

const DOMAIN: &str = "simpleIOGenericIO";

fn build_lln0() -> LogicalNode {
    let mod_do = cdc::ens("Mod", cdc::CdcOptions::NONE);
    let beh_do = cdc::ens("Beh", cdc::CdcOptions::NONE);
    let health_do = cdc::ens("Health", cdc::CdcOptions::NONE);
    let nam_plt = DataObjectBuilder::scalar("NamPlt")
        .add_da(
            "vendor",
            FC::Dc,
            DataAttributeType::VisibleString(255),
            TrgOps::NONE,
            MmsValue::VisibleString("rust61850".into()),
        )
        .add_da(
            "swRev",
            FC::Dc,
            DataAttributeType::VisibleString(255),
            TrgOps::NONE,
            MmsValue::VisibleString("0.1.0".into()),
        )
        .build()
        .expect("nam_plt build");
    LogicalNodeBuilder::lln0()
        .add_do(mod_do)
        .add_do(beh_do)
        .add_do(health_do)
        .add_do(nam_plt)
        .build()
        .expect("lln0 build")
}

fn build_ggio1() -> LogicalNode {
    let mut b = LogicalNodeBuilder::new("", "GGIO", "1");
    for i in 1..=3 {
        b = b.add_do(cdc::sps(format!("Ind{i}"), cdc::CdcOptions::NONE));
    }
    for i in 1..=2 {
        b = b.add_do(cdc::mv(
            format!("AnIn{i}"),
            cdc::CdcOptions::NONE,
            /* is_integer_not_float */ false,
        ));
    }
    let spc_opts = ControlOptions::NONE.with_model(ControlModel::DirectNormal);
    b = b.add_do(cdc::spc("SPCSO1", cdc::CdcOptions::NONE, spc_opts));
    b.build().expect("ggio1 build")
}

fn build_model() -> Arc<IedModel> {
    let ld = LogicalDeviceBuilder::new("GenericIO")
        .add_ln(build_lln0())
        .add_ln(build_ggio1())
        .build()
        .expect("ld");
    Arc::new(
        IedModelBuilder::new("simpleIO")
            .add_ld(ld)
            .expect("add_ld")
            .build()
            .expect("model"),
    )
}

fn build_server() -> IedServer {
    let mut policies = WriteAccessPolicies::default();
    policies.set(FC::Dc, true);
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

fn resolve_da(model: &IedModel, path: &str) -> DataAttribute {
    let r = ObjectRef::parse_iec(path).expect("parse_iec");
    match model.node_by_object_ref(&r).expect("node lookup") {
        NodeRef::Da(da) => DataAttribute {
            name: da.name.clone(),
            fc: da.fc,
            ty: da.ty,
            trg_ops: da.trg_ops,
            value: Arc::clone(&da.value),
            children: Vec::new(),
        },
        _ => panic!("expected DA, got non-DA at {path}"),
    }
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

/// Seeds the values the read cases assert on: a boolean, a visible string and
/// a float, one per value type.
fn seed_values(server: &IedServer) {
    let model = server.model();
    let ind1 = resolve_da(&model, "simpleIOGenericIO/GGIO1.Ind1.stVal");
    server.update_boolean(&ind1, true).expect("update Ind1");
    let an_in1_f = resolve_da(&model, "simpleIOGenericIO/GGIO1.AnIn1.mag.f");
    server
        .update_float32(&an_in1_f, 12.5)
        .expect("update AnIn1");
}

// TPKT / COTP frame counter
//
// A counting relay between the client and the server, used to assert how many
// PDUs one call costs. It forwards bytes unchanged and counts the COTP DT
// frames (RFC 1006 TPKT carrying TPDU code `0xf0`) that flow from the client
// to the server. Every MMS PDU of the size used here occupies exactly one such
// frame, so the count is the number of requests issued.

const TPKT_VERSION: u8 = 0x03;
const TPKT_HEADER_LEN: usize = 4;
/// Offset of the COTP TPDU code inside a TPKT frame: 4 header bytes then the
/// COTP length indicator.
const COTP_CODE_OFFSET: usize = 5;
/// COTP DT (data) TPDU code, the only frame type carrying an MMS PDU.
const COTP_CODE_DT: u8 = 0xf0;

/// Consumes whole TPKT frames from `pending` and counts the DT ones.
///
/// A trailing partial frame stays in `pending` for the next call.
fn count_dt_frames(pending: &mut Vec<u8>, counter: &AtomicUsize) {
    loop {
        if pending.len() < TPKT_HEADER_LEN || pending[0] != TPKT_VERSION {
            return;
        }
        let frame_len = u16::from_be_bytes([pending[2], pending[3]]) as usize;
        if frame_len < TPKT_HEADER_LEN || pending.len() < frame_len {
            return;
        }
        if frame_len > COTP_CODE_OFFSET && pending[COTP_CODE_OFFSET] == COTP_CODE_DT {
            counter.fetch_add(1, Ordering::SeqCst);
        }
        pending.drain(..frame_len);
    }
}

/// Pumps `from` into `to`, counting client-side DT frames when `counter` is set.
fn pump(mut from: TcpStream, mut to: TcpStream, counter: Option<Arc<AtomicUsize>>) {
    let mut buf = [0u8; 4096];
    let mut pending: Vec<u8> = Vec::new();
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if let Some(c) = counter.as_ref() {
            pending.extend_from_slice(&buf[..n]);
            count_dt_frames(&mut pending, c);
        }
        if to.write_all(&buf[..n]).is_err() {
            break;
        }
    }
    let _ = to.shutdown(std::net::Shutdown::Both);
}

/// A relay in front of the server, exposing the port the client connects to
/// and the number of requests seen so far.
struct CountingRelay {
    port: u16,
    requests: Arc<AtomicUsize>,
}

impl CountingRelay {
    /// Binds the relay and serves connections on background threads.
    fn start(upstream: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind relay");
        let port = listener.local_addr().expect("relay addr").port();
        let requests = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&requests);
        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(downstream) = incoming else { break };
                let Ok(up) = TcpStream::connect(upstream) else {
                    break;
                };
                let (Ok(down_rx), Ok(up_rx)) = (downstream.try_clone(), up.try_clone()) else {
                    break;
                };
                let c = Arc::clone(&counter);
                std::thread::spawn(move || pump(down_rx, up, Some(c)));
                std::thread::spawn(move || pump(up_rx, downstream, None));
            }
        });
        Self { port, requests }
    }

    /// Number of MMS-carrying frames sent by the client so far.
    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

fn expect_boolean(result: &AccessResult, expected: bool) {
    match result {
        AccessResult::Success(MmsData::Boolean(b)) => assert_eq!(*b, expected),
        other => panic!("expected Boolean({expected}), got {other:?}"),
    }
}

fn expect_visible_string(result: &AccessResult, expected: &str) {
    match result {
        AccessResult::Success(MmsData::VisibleString(s)) => assert_eq!(s, expected),
        other => panic!("expected VisibleString({expected:?}), got {other:?}"),
    }
}

fn expect_float32(result: &AccessResult, expected: f32) {
    match result {
        AccessResult::Success(MmsData::Float32(f)) => assert_eq!(*f, expected),
        other => panic!("expected Float32({expected}), got {other:?}"),
    }
}

fn expect_failure(result: &AccessResult, expected: DataAccessError) {
    match result {
        AccessResult::Failure(e) => assert_eq!(*e, expected),
        other => panic!("expected Failure({expected:?}), got {other:?}"),
    }
}

// Three existing variables of different types plus one reference that does not
// resolve. Every entry keeps its position, and the missing one fails alone.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_objects_mixed_types_with_one_missing_reference() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        seed_values(&server);
        let handle = server.start().await.expect("start");
        let conn = make_client(handle.bound_addr.port()).await;

        let targets = [
            (format!("{DOMAIN}/GGIO1.Ind1.stVal"), FC::St),
            (format!("{DOMAIN}/LLN0.NamPlt.vendor"), FC::Dc),
            (format!("{DOMAIN}/GGIO1.AnIn1.mag.f"), FC::Mx),
            (format!("{DOMAIN}/GGIO1.NoSuchDo.stVal"), FC::St),
        ];
        let refs: Vec<(&str, FC)> = targets.iter().map(|(r, fc)| (r.as_str(), *fc)).collect();

        let results = conn.read_objects(&refs).await.expect("read_objects");
        assert_eq!(results.len(), 4, "one access result per requested variable");
        expect_boolean(&results[0], true);
        expect_visible_string(&results[1], "rust61850");
        expect_float32(&results[2], 12.5);
        expect_failure(&results[3], DataAccessError::ObjectNonExistent);

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

// The same references in reverse order come back in reverse order: position is
// what binds a result to its request.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_objects_preserves_request_order() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        seed_values(&server);
        let handle = server.start().await.expect("start");
        let conn = make_client(handle.bound_addr.port()).await;

        let forward = [
            (format!("{DOMAIN}/GGIO1.Ind1.stVal"), FC::St),
            (format!("{DOMAIN}/LLN0.NamPlt.vendor"), FC::Dc),
            (format!("{DOMAIN}/GGIO1.AnIn1.mag.f"), FC::Mx),
            (format!("{DOMAIN}/GGIO1.NoSuchDo.stVal"), FC::St),
        ];
        let forward_refs: Vec<(&str, FC)> =
            forward.iter().map(|(r, fc)| (r.as_str(), *fc)).collect();
        let mut reversed_refs = forward_refs.clone();
        reversed_refs.reverse();

        let forward_results = conn.read_objects(&forward_refs).await.expect("forward");
        let reversed_results = conn.read_objects(&reversed_refs).await.expect("reversed");

        assert_eq!(reversed_results.len(), 4);
        expect_failure(&reversed_results[0], DataAccessError::ObjectNonExistent);
        expect_float32(&reversed_results[1], 12.5);
        expect_visible_string(&reversed_results[2], "rust61850");
        expect_boolean(&reversed_results[3], true);

        let mut mirrored = reversed_results.clone();
        mirrored.reverse();
        assert_eq!(
            mirrored, forward_results,
            "reversing the request must reverse the results"
        );

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

// An entry carrying an array index rides in the list as an `AlternateAccess`
// selector. `GGIO1.Ind1.stVal` is a scalar Boolean rather than an array, so the
// server applies the selector to a non-array value and answers
// `TypeInconsistent` for that entry alone, which proves the selector reached
// the server and that its neighbours are unaffected.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_objects_carries_an_array_element_entry() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        seed_values(&server);
        let handle = server.start().await.expect("start");
        let conn = make_client(handle.bound_addr.port()).await;

        let targets = [
            (format!("{DOMAIN}/GGIO1.Ind1.stVal"), FC::St),
            (format!("{DOMAIN}/GGIO1.Ind1(0).stVal"), FC::St),
            (format!("{DOMAIN}/LLN0.NamPlt.vendor"), FC::Dc),
        ];
        let refs: Vec<(&str, FC)> = targets.iter().map(|(r, fc)| (r.as_str(), *fc)).collect();

        let results = conn.read_objects(&refs).await.expect("read_objects");
        assert_eq!(results.len(), 3);
        expect_boolean(&results[0], true);
        expect_failure(&results[1], DataAccessError::TypeInconsistent);
        expect_visible_string(&results[2], "rust61850");

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

// Four variables cost one request; a refused call costs none.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_objects_uses_a_single_round_trip() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let server = build_server();
        seed_values(&server);
        let handle = server.start().await.expect("start");
        let relay = CountingRelay::start(handle.bound_addr);
        let conn = make_client(relay.port).await;

        let targets = [
            (format!("{DOMAIN}/GGIO1.Ind1.stVal"), FC::St),
            (format!("{DOMAIN}/LLN0.NamPlt.vendor"), FC::Dc),
            (format!("{DOMAIN}/GGIO1.AnIn1.mag.f"), FC::Mx),
            (format!("{DOMAIN}/LLN0.NamPlt.swRev"), FC::Dc),
        ];
        let refs: Vec<(&str, FC)> = targets.iter().map(|(r, fc)| (r.as_str(), *fc)).collect();

        // One reference at a time, as a baseline: four calls, four requests.
        let before_single = relay.requests();
        for (reference, fc) in &refs {
            conn.read_object(reference, *fc).await.expect("read_object");
        }
        let single_cost = relay.requests() - before_single;
        assert_eq!(single_cost, 4, "one request per read_object call");

        // The same four variables in one call: one request.
        let before_multi = relay.requests();
        let results = conn.read_objects(&refs).await.expect("read_objects");
        let multi_cost = relay.requests() - before_multi;
        assert_eq!(results.len(), 4);
        assert_eq!(multi_cost, 1, "four variables must cost one request");

        // An empty target list is refused before anything is sent.
        let before_empty = relay.requests();
        let err = conn.read_objects(&[]).await.expect_err("empty targets");
        assert!(
            matches!(err, ClientError::InvalidArgument(_)),
            "got {err:?}"
        );
        assert_eq!(relay.requests() - before_empty, 0, "nothing may be sent");

        // A reference that does not parse refuses the whole call, likewise
        // without sending anything.
        let before_bad = relay.requests();
        let bad = [
            (format!("{DOMAIN}/GGIO1.Ind1.stVal"), FC::St),
            ("missing-the-slash".to_string(), FC::St),
        ];
        let bad_refs: Vec<(&str, FC)> = bad.iter().map(|(r, fc)| (r.as_str(), *fc)).collect();
        let err = conn
            .read_objects(&bad_refs)
            .await
            .expect_err("unparsable reference");
        assert!(
            matches!(err, ClientError::InvalidArgument(_)),
            "got {err:?}"
        );
        assert_eq!(relay.requests() - before_bad, 0, "nothing may be sent");

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

// Without an association the call is refused locally.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_objects_not_connected() {
    let conn = IedConnection::new();
    let reference = format!("{DOMAIN}/GGIO1.Ind1.stVal");
    let err = conn
        .read_objects(&[(reference.as_str(), FC::St)])
        .await
        .expect_err("not connected");
    assert!(matches!(err, ClientError::NotConnected), "got {err:?}");
}
