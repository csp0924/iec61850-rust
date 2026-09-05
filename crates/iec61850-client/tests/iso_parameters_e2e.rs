//! End-to-end coverage of the ISO connection parameters an association offers.
//!
//! Every case runs against the workspace `IedServer` over loopback. A relay in
//! front of the server keeps the first session CONNECT SPDU the client sends,
//! so the selectors and the ACSE addressing can be read back off the wire
//! rather than inferred from the encoder.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iec61850_client::{ApTitle, IedConnection, IsoConnectionParameters};
use iec61850_mms::iso::acse::{AcseConnection, AcseIndication};
use iec61850_mms::iso::presentation::{parse_connect, IsoPresentation, PSelector};
use iec61850_mms::iso::session::{IsoSession, SSelector, SessionIndication};
use iec61850_model::{
    cdc, DataAttributeType, DataObjectBuilder, IedModel, IedModelBuilder, LogicalDeviceBuilder,
    LogicalNode, LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::{IedServer, IedServerConfig};

const DOMAIN: &str = "simpleIOGenericIO";

// Model

fn build_lln0() -> LogicalNode {
    let nam_plt = DataObjectBuilder::scalar("NamPlt")
        .add_da(
            "vendor",
            FC::Dc,
            DataAttributeType::VisibleString(255),
            TrgOps::NONE,
            MmsValue::VisibleString("rust61850".into()),
        )
        .build()
        .expect("nam_plt build");
    LogicalNodeBuilder::lln0()
        .add_do(cdc::ens("Mod", cdc::CdcOptions::NONE))
        .add_do(cdc::ens("Beh", cdc::CdcOptions::NONE))
        .add_do(cdc::ens("Health", cdc::CdcOptions::NONE))
        .add_do(nam_plt)
        .build()
        .expect("lln0 build")
}

fn build_model() -> Arc<IedModel> {
    let ld = LogicalDeviceBuilder::new("GenericIO")
        .add_ln(build_lln0())
        .add_ln(
            LogicalNodeBuilder::new("", "GGIO", "1")
                .add_do(cdc::sps("Ind1", cdc::CdcOptions::NONE))
                .build()
                .expect("ggio1 build"),
        )
        .build()
        .expect("ld build");
    Arc::new(
        IedModelBuilder::new("simpleIO")
            .add_ld(ld)
            .expect("add_ld")
            .build()
            .expect("model build"),
    )
}

fn build_server() -> IedServer {
    IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig {
            max_mms_connections: 4,
            ..Default::default()
        })
        .build()
        .expect("build server")
}

// Capturing relay

/// TPKT version byte of RFC 1006.
const TPKT_VERSION: u8 = 0x03;

/// Length of the TPKT header.
const TPKT_HEADER_LEN: usize = 4;

/// Offset of the COTP TPDU code inside a TPKT frame.
const COTP_CODE_OFFSET: usize = 5;

/// COTP DT code; the session CONNECT travels inside such a frame.
const COTP_CODE_DT: u8 = 0xf0;

/// Offset at which the session SPDU starts inside a COTP DT frame: the TPKT
/// header, then the COTP length indicator, code and EOT bytes.
const SESSION_SPDU_OFFSET: usize = 7;

/// A relay in front of the server that keeps the first session SPDU the client
/// sends, which is the CONNECT.
struct CapturingRelay {
    port: u16,
    first_spdu: Arc<Mutex<Option<Vec<u8>>>>,
}

impl CapturingRelay {
    /// Binds the relay and serves connections on background threads.
    fn start(upstream: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind relay");
        let port = listener.local_addr().expect("relay addr").port();
        let first_spdu: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let captured = Arc::clone(&first_spdu);
        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(downstream) = incoming else { break };
                let Ok(up) = TcpStream::connect(upstream) else {
                    break;
                };
                let (Ok(down_rx), Ok(up_rx)) = (downstream.try_clone(), up.try_clone()) else {
                    break;
                };
                let sink = Arc::clone(&captured);
                std::thread::spawn(move || pump(down_rx, up, Some(sink)));
                std::thread::spawn(move || pump(up_rx, downstream, None));
            }
        });
        Self { port, first_spdu }
    }

    /// Returns the first session SPDU the client sent, panicking when none was
    /// seen; an empty capture would otherwise pass an assertion vacuously.
    fn first_session_spdu(&self) -> Vec<u8> {
        self.first_spdu
            .lock()
            .expect("capture lock")
            .clone()
            .expect("no session spdu was captured")
    }
}

/// Consumes whole TPKT frames from `pending` and keeps the first session SPDU.
fn capture_first_spdu(pending: &mut Vec<u8>, sink: &Mutex<Option<Vec<u8>>>) {
    loop {
        if pending.len() < TPKT_HEADER_LEN || pending[0] != TPKT_VERSION {
            return;
        }
        let frame_len = u16::from_be_bytes([pending[2], pending[3]]) as usize;
        if frame_len < TPKT_HEADER_LEN || pending.len() < frame_len {
            return;
        }
        if frame_len > SESSION_SPDU_OFFSET && pending[COTP_CODE_OFFSET] == COTP_CODE_DT {
            let mut slot = sink.lock().expect("capture lock");
            if slot.is_none() {
                *slot = Some(pending[SESSION_SPDU_OFFSET..frame_len].to_vec());
            }
        }
        pending.drain(..frame_len);
    }
}

/// Pumps `from` into `to`, capturing the first client-side session SPDU when
/// `sink` is set.
fn pump(mut from: TcpStream, mut to: TcpStream, sink: Option<Arc<Mutex<Option<Vec<u8>>>>>) {
    let mut buf = [0u8; 4096];
    let mut pending: Vec<u8> = Vec::new();
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if let Some(slot) = sink.as_ref() {
            pending.extend_from_slice(&buf[..n]);
            capture_first_spdu(&mut pending, slot);
        }
        if to.write_all(&buf[..n]).is_err() {
            break;
        }
    }
    let _ = to.shutdown(std::net::Shutdown::Both);
}

// Wire inspection

/// The ACSE addressing and the presentation selectors carried by one session
/// CONNECT SPDU.
struct ConnectRequestFields {
    calling_p_sel: PSelector,
    called_p_sel: PSelector,
    calling_ap_title: Vec<u8>,
    calling_ae_qualifier: i32,
}

/// Decodes a session CONNECT SPDU down to the ACSE AARQ inside it.
///
/// The decoders are the ones the server itself runs, so a field this reads back
/// is a field the peer receives.
fn decode_connect_request(spdu: &[u8]) -> ConnectRequestFields {
    let mut session = IsoSession::new();
    let indication = session.parse_message(spdu).expect("session cn must parse");
    assert_eq!(indication, SessionIndication::Connect);
    let session_payload = session.user_data(spdu).to_vec();

    let mut presentation = IsoPresentation::new();
    let cp = parse_connect(&mut presentation, &session_payload).expect("cp must parse");
    let acse_payload = cp.payload(&session_payload).to_vec();

    let mut acse = AcseConnection::new(None);
    let (acse_indication, _) = acse.parse_message(&acse_payload).expect("aarq must parse");
    assert_eq!(acse_indication, AcseIndication::Associate);

    ConnectRequestFields {
        calling_p_sel: presentation.calling_p_sel.clone(),
        called_p_sel: presentation.called_p_sel.clone(),
        calling_ap_title: acse.application_reference.ap_title.clone(),
        calling_ae_qualifier: acse.application_reference.ae_qualifier,
    }
}

/// Reads one variable, proving the association carries traffic.
async fn read_a_variable(conn: &IedConnection) {
    conn.read_object(&format!("{DOMAIN}/LLN0.NamPlt.vendor"), FC::Dc)
        .await
        .expect("read_object");
}

// The default parameters associate with the workspace server.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn default_iso_parameters_associate() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let handle = server.start().await.expect("start");

        let conn = IedConnection::new();
        conn.connect("127.0.0.1", handle.bound_addr.port())
            .await
            .expect("connect with default iso parameters");
        assert!(conn.is_connected());
        read_a_variable(&conn).await;
        conn.disconnect().await.expect("disconnect");
    })
    .await
    .expect("test timed out");
}

// Custom selectors and a custom AP-title associate, and the peer receives them.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn custom_iso_parameters_reach_the_peer() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let relay = CapturingRelay::start(handle.bound_addr);

        let title: ApTitle = "1.3.9999.13".parse().expect("ap-title");
        let params = IsoConnectionParameters {
            local_p_sel: PSelector::from_slice(&[0x00, 0x00, 0x00, 0x02]).expect("p-sel"),
            remote_p_sel: PSelector::from_slice(&[0x00, 0x00, 0x00, 0x02]).expect("p-sel"),
            local_s_sel: SSelector::from_slice(&[0x00, 0x02]).expect("s-sel"),
            remote_s_sel: SSelector::from_slice(&[0x00, 0x02]).expect("s-sel"),
            local_ap_title: Some(title.clone()),
            remote_ap_title: Some(title.clone()),
            local_ae_qualifier: Some(1),
            remote_ae_qualifier: Some(1),
            ..IsoConnectionParameters::default()
        };

        let conn = IedConnection::with_iso_parameters(params);
        conn.connect("127.0.0.1", relay.port)
            .await
            .expect("connect with custom iso parameters");
        assert!(conn.is_connected());
        read_a_variable(&conn).await;
        conn.disconnect().await.expect("disconnect");

        // the peer's own decoders read back what was configured
        let fields = decode_connect_request(&relay.first_session_spdu());
        assert_eq!(fields.calling_p_sel.as_slice(), &[0x00, 0x00, 0x00, 0x02]);
        assert_eq!(fields.called_p_sel.as_slice(), &[0x00, 0x00, 0x00, 0x02]);
        assert_eq!(
            ApTitle::from_ber_content(&fields.calling_ap_title).expect("ap-title decode"),
            title
        );
        assert_eq!(fields.calling_ae_qualifier, 1);
    })
    .await
    .expect("test timed out");
}

// The default P-Selector on the wire is 00 00 00 01, on both sides of the CP.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_default_connect_carries_the_documented_p_selector() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let relay = CapturingRelay::start(handle.bound_addr);

        let conn = IedConnection::new();
        conn.connect("127.0.0.1", relay.port)
            .await
            .expect("connect through the relay");
        read_a_variable(&conn).await;
        conn.disconnect().await.expect("disconnect");

        let spdu = relay.first_session_spdu();
        assert!(!spdu.is_empty(), "the captured spdu must not be empty");
        let calling: &[u8] = &[0x81, 0x04, 0x00, 0x00, 0x00, 0x01];
        assert!(
            spdu.windows(calling.len()).any(|w| w == calling),
            "the calling-presentation-selector must be 00 00 00 01"
        );

        let fields = decode_connect_request(&spdu);
        assert_eq!(fields.calling_p_sel.as_slice(), &[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(fields.called_p_sel.as_slice(), &[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(
            ApTitle::from_ber_content(&fields.calling_ap_title).expect("ap-title decode"),
            "1.1.1.999".parse::<ApTitle>().expect("ap-title")
        );
        assert_eq!(fields.calling_ae_qualifier, 12);
    })
    .await
    .expect("test timed out");
}
