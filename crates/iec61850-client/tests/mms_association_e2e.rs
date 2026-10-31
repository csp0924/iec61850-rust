//! Association-level behavior of the client against a real server over TCP.
//!
//! A TPKT-level proxy between client and server can hold a server answer,
//! release it, or cut the transport at a chosen point, and records every frame
//! in both directions. A held answer never arrives on its own, so a request
//! timeout is reached deterministically rather than through a sleep margin.
//! A test that needs a frame to have passed waits for the proxy to record it.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::BytesMut;
use iec61850_client::dataset_admin::DataSetMember;
use iec61850_client::{ClientError, IedConnection};
use iec61850_mms::mms::client::{ConnectionState, MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::{
    encode_confirmed_write_request, VariableAccessSpecification, WriteRequest,
};
use iec61850_mms::{ClientError as MmsClientError, MmsData};
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObject, DoChild, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::{IedServer, IedServerConfig, ServerHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Notify};

const DOMAIN: &str = "IED1LD0";

fn bool_do(name: &str, v: bool) -> DataObject {
    DataObject::new(
        name,
        vec![DoChild::Da(DataAttribute::new(
            "stVal",
            FC::St,
            DataAttributeType::Boolean,
            TrgOps::DCHG,
            MmsValue::Boolean(v),
        ))],
    )
}

fn build_model() -> Arc<IedModel> {
    let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
    let ggio = LogicalNodeBuilder::new("", "GGIO", "1")
        .add_do(bool_do("Ind1", true))
        .add_do(bool_do("Ind2", false))
        .build()
        .expect("GGIO1");
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

async fn start_server(bind: &str) -> ServerHandle {
    IedServer::builder()
        .model(build_model())
        .bind(bind.parse::<SocketAddr>().unwrap())
        .config({
            let mut config = IedServerConfig::default();
            config.max_mms_connections = 4;
            config
        })
        .build()
        .expect("build server")
        .start()
        .await
        .expect("server start")
}

fn mms_client(request_timeout_ms: u64) -> MmsClient {
    MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(request_timeout_ms)
        .build()
}

/// Commands steering the server-to-client direction of the proxy.
enum Cmd {
    /// Hold the next server-to-client TPKT until `Release`.
    HoldNext,
    /// Write the held TPKT and forward normally again.
    Release,
    /// Close both sockets.
    Cut,
    /// Write a TPKT to the client as if the server had sent it.
    Inject(Vec<u8>),
}

/// Every TPKT the proxy forwarded, in each direction.
#[derive(Default)]
struct Frames {
    to_server: Vec<Vec<u8>>,
    to_client: Vec<Vec<u8>>,
}

impl Frames {
    /// SPDUs, the TSDU after TPKT and the three-octet COTP DT header.
    fn spdus(frames: &[Vec<u8>]) -> Vec<Vec<u8>> {
        frames
            .iter()
            .filter(|f| f.len() > 7 && f[5] == 0xf0)
            .map(|f| f[7..].to_vec())
            .collect()
    }
}

struct Proxy {
    port: u16,
    cmd: mpsc::UnboundedSender<Cmd>,
    ack: mpsc::UnboundedReceiver<&'static str>,
    frames: Arc<Mutex<Frames>>,
    /// Notified whenever a frame is recorded or a side closes.
    changed: Arc<Notify>,
}

impl Proxy {
    async fn send(&mut self, cmd: Cmd, expect: &'static str) {
        self.cmd.send(cmd).unwrap();
        assert_eq!(self.ack.recv().await, Some(expect));
    }

    fn spdus_to_server(&self) -> Vec<Vec<u8>> {
        Frames::spdus(&self.frames.lock().unwrap().to_server)
    }

    fn spdus_to_client(&self) -> Vec<Vec<u8>> {
        Frames::spdus(&self.frames.lock().unwrap().to_client)
    }
}

async fn read_tpkt(s: &mut tokio::net::tcp::OwnedReadHalf) -> Option<Vec<u8>> {
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await.ok()?;
    let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    let mut body = vec![0u8; len.saturating_sub(4)];
    s.read_exact(&mut body).await.ok()?;
    let mut out = hdr.to_vec();
    out.extend_from_slice(&body);
    Some(out)
}

/// Starts a one-shot proxy to `upstream`. Every command is acknowledged once
/// applied; a held frame is acknowledged with "held" when it arrives.
async fn start_proxy(upstream: SocketAddr) -> Proxy {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, mut rx) = mpsc::unbounded_channel::<Cmd>();
    let (ack_tx, ack_rx) = mpsc::unbounded_channel::<&'static str>();
    let frames = Arc::new(Mutex::new(Frames::default()));
    let changed = Arc::new(Notify::new());
    let rec = Arc::clone(&frames);
    let notify = Arc::clone(&changed);
    tokio::spawn(async move {
        let (client, _) = listener.accept().await.unwrap();
        let server = TcpStream::connect(upstream).await.unwrap();
        let (mut cr, mut cw) = client.into_split();
        let (mut sr, mut sw) = server.into_split();
        let rec_c2s = Arc::clone(&rec);
        let notify_c2s = Arc::clone(&notify);
        let c2s = tokio::spawn(async move {
            while let Some(f) = read_tpkt(&mut cr).await {
                rec_c2s.lock().unwrap().to_server.push(f.clone());
                notify_c2s.notify_waiters();
                if sw.write_all(&f).await.is_err() {
                    break;
                }
            }
            notify_c2s.notify_waiters();
            let _ = sw.shutdown().await;
        });
        let mut hold_next = false;
        let mut held: Option<Vec<u8>> = None;
        loop {
            tokio::select! {
                cmd = rx.recv() => match cmd {
                    Some(Cmd::HoldNext) => { hold_next = true; let _ = ack_tx.send("hold"); }
                    Some(Cmd::Release) => {
                        if let Some(f) = held.take() { let _ = cw.write_all(&f).await; }
                        let _ = ack_tx.send("released");
                    }
                    Some(Cmd::Inject(f)) => {
                        let _ = cw.write_all(&f).await;
                        let _ = ack_tx.send("injected");
                    }
                    Some(Cmd::Cut) => {
                        c2s.abort();
                        let _ = cw.shutdown().await;
                        drop(cw);
                        let _ = ack_tx.send("cut");
                        return;
                    }
                    None => return,
                },
                f = read_tpkt(&mut sr) => {
                    let Some(f) = f else {
                        notify.notify_waiters();
                        let _ = cw.shutdown().await;
                        return;
                    };
                    rec.lock().unwrap().to_client.push(f.clone());
                    notify.notify_waiters();
                    if hold_next {
                        hold_next = false;
                        held = Some(f);
                        let _ = ack_tx.send("held");
                    } else if cw.write_all(&f).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    Proxy {
        port,
        cmd: tx,
        ack: ack_rx,
        frames,
        changed,
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Session FN carrying an ACSE RLRQ (normal) on the ACSE presentation context.
fn is_finish_with_rlrq(spdu: &[u8]) -> bool {
    spdu.first() == Some(&0x09) && contains(spdu, &[0x62, 0x03, 0x80, 0x01, 0x00])
}

/// Session DN carrying an ACSE RLRE.
fn is_disconnect_with_rlre(spdu: &[u8]) -> bool {
    spdu.first() == Some(&0x0a) && contains(spdu, &[0xa0, 0x02, 0x63, 0x00])
}

/// Session AB carrying an ACSE ABRT with abort-source acse-service-user.
fn is_abort_with_user_abrt(spdu: &[u8]) -> bool {
    spdu.first() == Some(&0x19) && contains(spdu, &[0x64, 0x03, 0x80, 0x01, 0x00])
}

/// Waits until `done` holds over the frames the proxy recorded, checking again
/// each time it records a frame. The bound only keeps a broken run from
/// hanging; the wait ends on the recorded frame.
async fn settle(proxy: &Proxy, done: impl Fn(&Proxy) -> bool) {
    let waited = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let changed = proxy.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if done(proxy) {
                return;
            }
            changed.await;
        }
    })
    .await;
    assert!(
        waited.is_ok(),
        "the proxy never recorded the expected frame"
    );
}

// Request timeout and late answers

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_after_a_timeout_returns_its_own_value() {
    let handle = start_server("127.0.0.1:0").await;
    let mut proxy = start_proxy(handle.bound_addr).await;
    let mut client = mms_client(300);
    client
        .connect("127.0.0.1", proxy.port)
        .await
        .expect("connect");

    proxy.send(Cmd::HoldNext, "hold").await;
    let first = client.read(DOMAIN, "GGIO1$ST$Ind1$stVal").await;
    assert!(
        matches!(
            first,
            Err(MmsClientError::ServiceTimeout {
                timeout_ms: 300,
                ..
            })
        ),
        "got {first:?}"
    );
    assert_eq!(proxy.ack.recv().await, Some("held"));
    assert_eq!(client.state(), ConnectionState::Connected);
    proxy.send(Cmd::Release, "released").await;

    // Ind2 is false and Ind1 true on the server
    assert_eq!(
        client.read(DOMAIN, "GGIO1$ST$Ind2$stVal").await.unwrap(),
        MmsData::Boolean(false)
    );
    assert_eq!(
        client.read(DOMAIN, "GGIO1$ST$Ind1$stVal").await.unwrap(),
        MmsData::Boolean(true)
    );
    handle.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ied_connection_read_after_a_timeout_returns_its_own_object() {
    let handle = start_server("127.0.0.1:0").await;
    let mut proxy = start_proxy(handle.bound_addr).await;
    let conn = IedConnection::with_mms_client(mms_client(300));
    conn.connect("127.0.0.1", proxy.port)
        .await
        .expect("connect");

    proxy.send(Cmd::HoldNext, "hold").await;
    let first = conn.read_object("IED1LD0/GGIO1.Ind1.stVal", FC::St).await;
    assert!(
        matches!(first, Err(ClientError::Timeout { after_ms: 300, .. })),
        "the held read times out: {first:?}"
    );
    assert_eq!(proxy.ack.recv().await, Some("held"));
    assert!(conn.is_connected(), "a timeout keeps the association");
    proxy.send(Cmd::Release, "released").await;

    let second = conn.read_object("IED1LD0/GGIO1.Ind2.stVal", FC::St).await;
    assert_eq!(second.unwrap(), MmsValue::Boolean(false));
    handle.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn late_answer_is_discarded_while_polling_reports() {
    let handle = start_server("127.0.0.1:0").await;
    let mut proxy = start_proxy(handle.bound_addr).await;
    let conn = IedConnection::with_mms_client(mms_client(300));
    conn.connect("127.0.0.1", proxy.port)
        .await
        .expect("connect");

    proxy.send(Cmd::HoldNext, "hold").await;
    assert!(conn
        .read_object("IED1LD0/GGIO1.Ind1.stVal", FC::St)
        .await
        .is_err());
    assert_eq!(proxy.ack.recv().await, Some("held"));
    proxy.send(Cmd::Release, "released").await;

    let polled = conn.poll_reports(Duration::from_millis(200)).await;
    assert_eq!(polled, Ok(0));
    assert!(conn.is_connected());
    handle.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn poll_longer_than_the_request_timeout_returns_zero() {
    let handle = start_server("127.0.0.1:0").await;
    let conn = IedConnection::with_mms_client(mms_client(100));
    conn.connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    let r = conn.poll_reports(Duration::from_millis(600)).await;
    assert_eq!(r, Ok(0));
    handle.stop().await;
}

// Report dispatcher

/// Frames `mms` as the server would: Presentation user data, Session DT, COTP
/// DT and TPKT.
fn server_frame(mms: &[u8]) -> Vec<u8> {
    let mut pres = BytesMut::new();
    iec61850_mms::iso::presentation::encode_user_data(
        &iec61850_mms::iso::presentation::IsoPresentation::new(),
        mms,
        &mut pres,
    );
    let mut spdu = BytesMut::new();
    iec61850_mms::iso::session::encode_data(&pres, &mut spdu);
    let len = 4 + 3 + spdu.len();
    let mut frame = vec![0x03, 0x00, (len >> 8) as u8, len as u8, 0x02, 0xf0, 0x80];
    frame.extend_from_slice(&spdu);
    frame
}

/// Wraps `inner` in `tag` and a definite length.
fn tlv(tag: u8, inner: &[u8]) -> Vec<u8> {
    assert!(inner.len() < 0x80, "short-form lengths only");
    let mut out = vec![tag, inner.len() as u8];
    out.extend_from_slice(inner);
    out
}

/// An InformationReport on `RPT` carrying RptID `rpt_id`, no optional fields
/// and one included Integer member.
fn report_pdu(rpt_id: &str, value: i64) -> Vec<u8> {
    let mut name = BytesMut::new();
    iec61850_mms::mms::pdu::ObjectName::VmdSpecific("RPT".into()).encode(&mut name);
    let mut results = BytesMut::new();
    for data in [
        MmsData::VisibleString(rpt_id.into()),
        MmsData::BitString {
            padding: 6,
            data: vec![0, 0],
        },
        MmsData::BitString {
            padding: 7,
            data: vec![0x80],
        },
        MmsData::Integer(value),
    ] {
        data.encode(&mut results);
    }
    let mut body = tlv(0xa1, &name);
    body.extend_from_slice(&tlv(0xa0, &results));
    tlv(0xa3, &tlv(0xa0, &body))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn report_dispatcher_survives_an_answer_that_matches_no_request() {
    let handle = start_server("127.0.0.1:0").await;
    let mut proxy = start_proxy(handle.bound_addr).await;
    let conn = IedConnection::with_mms_client(mms_client(3_000));
    conn.connect("127.0.0.1", proxy.port)
        .await
        .expect("connect");
    let (tx, mut rx) = mpsc::unbounded_channel::<()>();
    let cb: iec61850_client::ReportCallback = Arc::new(move |_report| {
        let _ = tx.send(());
    });
    conn.install_report_handler(Some("R1".into()), "IED1LD0/LLN0$RP$R1", None, cb)
        .await
        .expect("install");
    let dispatcher = conn.spawn_report_dispatcher(Duration::from_millis(50));

    // a Read answer under invokeID 0x7f, which no request carries
    let stray = [0xa1, 0x05, 0x02, 0x01, 0x7f, 0xa4, 0x00];
    proxy
        .send(Cmd::Inject(server_frame(&stray)), "injected")
        .await;
    proxy
        .send(Cmd::Inject(server_frame(&report_pdu("R1", 7))), "injected")
        .await;

    let delivered = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await;
    assert!(
        matches!(delivered, Ok(Some(_))),
        "the report after the stray answer reaches the callback"
    );
    assert!(!dispatcher.is_finished());
    assert!(conn.is_connected());
    conn.disconnect().await.expect("disconnect");
    handle.stop().await;
}

// Transport loss

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transport_loss_clears_is_connected() {
    let handle = start_server("127.0.0.1:0").await;
    let mut proxy = start_proxy(handle.bound_addr).await;
    let conn = IedConnection::with_mms_client(mms_client(3_000));
    conn.connect("127.0.0.1", proxy.port)
        .await
        .expect("connect");
    assert!(conn
        .read_object("IED1LD0/GGIO1.Ind1.stVal", FC::St)
        .await
        .is_ok());

    proxy.send(Cmd::Cut, "cut").await;
    let r = conn.read_object("IED1LD0/GGIO1.Ind1.stVal", FC::St).await;
    assert_eq!(r, Err(ClientError::ConnectionLost));
    assert!(!conn.is_connected(), "a lost transport clears is_connected");
    assert_eq!(
        conn.read_object("IED1LD0/GGIO1.Ind1.stVal", FC::St).await,
        Err(ClientError::NotConnected)
    );
    assert_eq!(
        conn.poll_reports(Duration::from_millis(50)).await,
        Err(ClientError::NotConnected)
    );
    handle.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transport_loss_while_polling_is_not_connected() {
    let handle = start_server("127.0.0.1:0").await;
    let mut proxy = start_proxy(handle.bound_addr).await;
    let conn = IedConnection::with_mms_client(mms_client(3_000));
    conn.connect("127.0.0.1", proxy.port)
        .await
        .expect("connect");

    proxy.send(Cmd::Cut, "cut").await;
    let r = conn.poll_reports(Duration::from_millis(2_000)).await;
    assert_eq!(r, Err(ClientError::NotConnected));
    assert!(!conn.is_connected());
    handle.stop().await;
}

// Release by the server

/// A Session FN carrying an ACSE RLRQ, as a server releasing the association
/// sends it.
fn server_finish_frame() -> Vec<u8> {
    let mut rlrq = [0u8; 5];
    iec61850_mms::iso::acse::encode_rlrq(&mut rlrq);
    let mut pres = BytesMut::new();
    iec61850_mms::iso::presentation::encode_user_data_acse(
        &iec61850_mms::iso::presentation::IsoPresentation::new(),
        &rlrq,
        &mut pres,
    );
    let mut spdu = BytesMut::new();
    iec61850_mms::iso::session::encode_finish(&pres, &mut spdu).unwrap();
    let len = 4 + 3 + spdu.len();
    let mut frame = vec![0x03, 0x00, (len >> 8) as u8, len as u8, 0x02, 0xf0, 0x80];
    frame.extend_from_slice(&spdu);
    frame
}

/// The client meets the release only when it next receives, after it has sent
/// the Read; the server's answer to that Read is held in the proxy, so the
/// client closes with nothing unread and its Session DN cannot be lost to a
/// reset of the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn release_by_the_server_is_answered_and_reported() {
    let handle = start_server("127.0.0.1:0").await;
    let mut proxy = start_proxy(handle.bound_addr).await;
    let conn = IedConnection::with_mms_client(mms_client(3_000));
    conn.connect("127.0.0.1", proxy.port)
        .await
        .expect("connect");

    proxy
        .send(Cmd::Inject(server_finish_frame()), "injected")
        .await;
    proxy.send(Cmd::HoldNext, "hold").await;
    let r = conn.read_object("IED1LD0/GGIO1.Ind1.stVal", FC::St).await;
    assert_eq!(r, Err(ClientError::ReleasedByPeer));
    assert!(!conn.is_connected(), "a release clears is_connected");

    settle(&proxy, |p| {
        p.spdus_to_server()
            .iter()
            .any(|s| is_disconnect_with_rlre(s))
    })
    .await;
    assert!(
        proxy
            .spdus_to_server()
            .iter()
            .any(|s| is_disconnect_with_rlre(s)),
        "the release is answered with an rlre in a session dn: {:02x?}",
        proxy.spdus_to_server()
    );
    handle.stop().await;
}

// Host names

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_accepts_ipv6_literals_with_and_without_brackets() {
    let handle = start_server("[::1]:0").await;
    let port = handle.bound_addr.port();
    for host in ["::1", "[::1]"] {
        let mut client = mms_client(3_000);
        client
            .connect(host, port)
            .await
            .unwrap_or_else(|e| panic!("{host}: {e}"));
        assert_eq!(client.state(), ConnectionState::Connected);
        client.disconnect().await.expect("disconnect");
    }
    handle.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_resolves_a_host_name() {
    let handle = start_server("127.0.0.1:0").await;
    let mut client = mms_client(3_000);
    client
        .connect("localhost", handle.bound_addr.port())
        .await
        .expect("connect localhost");
    assert_eq!(client.state(), ConnectionState::Connected);
    client.disconnect().await.expect("disconnect");
    handle.stop().await;
}

// Outbound PDU size

/// Encodes the Write request `client` would send under `invoke_id` and
/// returns its MMS PDU length.
fn write_pdu_len(invoke_id: u32, item: &str) -> usize {
    let req = WriteRequest {
        variable_access_spec: VariableAccessSpecification::ListOfVariable(vec![
            iec61850_mms::mms::pdu::ObjectName::DomainSpecific {
                domain_id: DOMAIN.to_string(),
                item_id: item.to_string(),
            }
            .into(),
        ]),
        list_of_data: vec![MmsData::Boolean(true)],
    };
    let mut buf = BytesMut::new();
    encode_confirmed_write_request(invoke_id, &req, &mut buf);
    buf.len()
}

/// Returns an item name whose Write request under `invoke_id` is exactly `len`
/// octets long.
fn item_for_pdu_len(invoke_id: u32, len: usize) -> String {
    let mut item = String::from("GGIO1$ST$X");
    while write_pdu_len(invoke_id, &item) < len {
        item.push('x');
    }
    assert_eq!(write_pdu_len(invoke_id, &item), len);
    item
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pdu_at_the_negotiated_size_is_sent_and_one_above_is_refused() {
    let handle = start_server("127.0.0.1:0").await;
    let mut client = MmsClientBuilder::new()
        .request_timeout_ms(3_000)
        .local_max_pdu_size(100)
        .build();
    client
        .connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    let max = client.negotiated_max_pdu_size();
    assert_eq!(max, 100, "the local proposal bounds the negotiated size");

    // the first request carries invokeID 1, the second 2
    let at_limit = client
        .write(DOMAIN, &item_for_pdu_len(1, max), MmsData::Boolean(true))
        .await;
    assert!(
        !matches!(at_limit, Err(MmsClientError::PduTooLarge { .. })),
        "a pdu of exactly the negotiated size is sent: {at_limit:?}"
    );
    let above = client
        .write(
            DOMAIN,
            &item_for_pdu_len(2, max + 1),
            MmsData::Boolean(true),
        )
        .await;
    assert!(
        matches!(above, Err(MmsClientError::PduTooLarge { pdu_size, max_size, .. }) if pdu_size == max + 1 && max_size == max),
        "got {above:?}"
    );
    handle.stop().await;
}

// Release and abort

/// The client releases with an RLRQ in a Session FN and the server answers
/// with an RLRE in a Session DN, which the client has received by the time
/// the release returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn release_is_a_finish_answered_by_a_disconnect() {
    let handle = start_server("127.0.0.1:0").await;
    let proxy = start_proxy(handle.bound_addr).await;
    let mut client = mms_client(1_000);
    client
        .connect("127.0.0.1", proxy.port)
        .await
        .expect("connect");
    client.disconnect().await.expect("disconnect");
    assert_eq!(client.state(), ConnectionState::Closed);
    let sent = proxy.spdus_to_server();
    assert!(
        sent.iter().any(|s| is_finish_with_rlrq(s)),
        "no session finish with an rlrq among {sent:02x?}"
    );
    let answers = proxy.spdus_to_client();
    assert!(
        answers.iter().any(|s| is_disconnect_with_rlre(s)),
        "no session disconnect with an rlre among {answers:02x?}"
    );
    handle.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn abort_sends_a_user_abrt_in_a_session_abort() {
    let handle = start_server("127.0.0.1:0").await;
    let proxy = start_proxy(handle.bound_addr).await;
    let conn = IedConnection::with_mms_client(mms_client(1_000));
    conn.connect("127.0.0.1", proxy.port)
        .await
        .expect("connect");
    conn.abort().await.expect("abort");
    assert!(!conn.is_connected());
    settle(&proxy, |p| {
        p.spdus_to_server().iter().any(|s| s.first() == Some(&0x19))
    })
    .await;
    let sent = proxy.spdus_to_server();
    assert!(
        sent.iter().any(|s| is_abort_with_user_abrt(s)),
        "no session abort with a user abrt among {sent:02x?}"
    );
    handle.stop().await;
}

// DefineNamedVariableList response

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_data_set_answer_is_a_primitive_null() {
    let handle = start_server("127.0.0.1:0").await;
    let proxy = start_proxy(handle.bound_addr).await;
    let conn = IedConnection::with_mms_client(mms_client(3_000));
    conn.connect("127.0.0.1", proxy.port)
        .await
        .expect("connect");
    conn.create_data_set(
        "IED1LD0/GGIO1.ds_dyn",
        &[DataSetMember::new("IED1LD0/GGIO1.Ind1.stVal", FC::St)],
    )
    .await
    .expect("create_data_set");
    let answers = proxy.spdus_to_client();
    // ... 02 01 <invokeID> 8b 00: confirmed-response of defineNamedVariableList
    assert!(
        answers
            .iter()
            .any(|s| s.len() > 4 && s.ends_with(&[0x8b, 0x00]) && s[s.len() - 5] == 0x02),
        "no defineNamedVariableList response encoded as 8b 00 among {answers:02x?}"
    );
    handle.stop().await;
}

/// A data set whose member names a data object, under its functional
/// constraint, is created and then deleted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_data_set_with_a_data_object_member_succeeds() {
    let handle = start_server("127.0.0.1:0").await;
    let conn = IedConnection::with_mms_client(mms_client(3_000));
    conn.connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    let name = "IED1LD0/LLN0.dynF1";
    let created = conn
        .create_data_set(name, &[DataSetMember::new("IED1LD0/GGIO1.Ind1", FC::St)])
        .await;
    assert_eq!(created, Ok(()));
    assert_eq!(
        conn.get_data_set_values(name).await.map(|v| v.len()),
        Ok(1),
        "the data set holds its one member"
    );
    assert_eq!(conn.delete_data_set(name).await, Ok(true));
    conn.disconnect().await.expect("disconnect");
    handle.stop().await;
}
