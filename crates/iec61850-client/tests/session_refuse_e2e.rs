//! End-to-end behavior of `IedConnection::connect` when the peer refuses the
//! association at the session layer.
//!
//! The peer here is a plain `TcpListener` that completes the COTP handshake and
//! then answers the session CONNECT with a hand-written SPDU: an RF carrying a
//! reason code, with and without the CPR PPDU that names a presentation
//! provider-reason, and an SPDU identifier the layer does not know.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use iec61850_client::{ClientError, IedConnection};
use iec61850_mms::{encode_cc, parse_cr};

/// TPKT version byte of RFC 1006.
const TPKT_VERSION: u8 = 0x03;

/// Length of the TPKT header.
const TPKT_HEADER_LEN: usize = 4;

/// COTP DT header carrying a session SPDU: LI 2, code 0xF0, EOT set.
const COTP_DT_HEADER: [u8; 3] = [0x02, 0xf0, 0x80];

/// Source reference the fake peer answers the CR with.
const PEER_SOURCE_REFERENCE: u16 = 0x0001;

/// How long the peer keeps the socket open after answering.
const PEER_LINGER: Duration = Duration::from_secs(2);

/// Reads one whole TPKT frame and returns the TPDU inside it.
fn read_tpkt(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; TPKT_HEADER_LEN];
    stream.read_exact(&mut header)?;
    assert_eq!(header[0], TPKT_VERSION, "tpkt version");
    let total = u16::from_be_bytes([header[2], header[3]]) as usize;
    let mut body = vec![0u8; total - TPKT_HEADER_LEN];
    stream.read_exact(&mut body)?;
    Ok(body)
}

/// Writes one TPDU inside a TPKT frame.
fn write_tpkt(stream: &mut TcpStream, tpdu: &[u8]) -> std::io::Result<()> {
    let total = (TPKT_HEADER_LEN + tpdu.len()) as u16;
    let mut frame = vec![TPKT_VERSION, 0x00];
    frame.extend_from_slice(&total.to_be_bytes());
    frame.extend_from_slice(tpdu);
    stream.write_all(&frame)
}

/// Starts a peer that completes the COTP handshake, reads the session CONNECT
/// and answers it with `answer`, a raw session SPDU.
///
/// Returns the port it listens on.
fn spawn_refusing_peer(answer: Vec<u8>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind peer");
    let port = listener.local_addr().expect("peer addr").port();
    thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");

        // COTP CR, answered with a CC that echoes the caller reference
        let cr = read_tpkt(&mut sock).expect("read cr");
        let (src_ref, options) = parse_cr(&cr).expect("parse cr");
        let cc = encode_cc(&options, PEER_SOURCE_REFERENCE, src_ref);
        write_tpkt(&mut sock, &cc).expect("write cc");

        // the session CONNECT, answered with the prepared SPDU
        let _cn = read_tpkt(&mut sock).expect("read cn");
        let mut dt = COTP_DT_HEADER.to_vec();
        dt.extend_from_slice(&answer);
        write_tpkt(&mut sock, &dt).expect("write answer");

        // hold the socket open until the client drops it
        sock.set_read_timeout(Some(PEER_LINGER)).expect("timeout");
        let mut sink = [0u8; 1];
        let _ = sock.read(&mut sink);
    });
    port
}

/// Connects to `port` and returns the error the association fails with.
async fn connect_error(port: u16) -> ClientError {
    let conn = IedConnection::new();
    let err = conn
        .connect("127.0.0.1", port)
        .await
        .expect_err("the association must fail");
    assert!(
        !conn.is_connected(),
        "a refused association is not connected"
    );
    err
}

// An RF SPDU with reason code 129, session selector unknown, carrying a CPR
// PPDU whose provider-reason is 3, called-presentation-address-unknown.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuse_with_reason_and_provider_reason() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let refusal = vec![
            0x0C, 0x0A, // RF, LI 10
            0x32, 0x01, 0x81, // PI 50, reason code 129
            0xC1, 0x05, // PGI 193, user data of 5 bytes
            0x30, 0x03, 0x8A, 0x01, 0x03, // CPR with provider-reason 3
        ];
        let port = spawn_refusing_peer(refusal);
        let err = connect_error(port).await;

        assert_eq!(
            err,
            ClientError::SessionRefused {
                reason_code: Some(129),
                transport_disconnect: None,
                provider_reason: Some(3),
            }
        );
        let text = err.to_string();
        assert!(
            text.contains("session selector unknown"),
            "the reason code must be named: {text}"
        );
        assert!(
            text.contains("called-presentation-address-unknown"),
            "the provider reason must be named: {text}"
        );
    })
    .await
    .expect("test timed out");
}

// An RF SPDU with reason code 2 and no user data: no provider-reason to report.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuse_without_user_data_has_no_provider_reason() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let refusal = vec![
            0x0C, 0x06, // RF, LI 6
            0x11, 0x01, 0x01, // PI 17, transport disconnect
            0x32, 0x01, 0x02, // PI 50, reason code 2
        ];
        let port = spawn_refusing_peer(refusal);
        let err = connect_error(port).await;

        assert_eq!(
            err,
            ClientError::SessionRefused {
                reason_code: Some(2),
                transport_disconnect: Some(1),
                provider_reason: None,
            }
        );
        let text = err.to_string();
        assert!(
            text.contains("rejection by called SS-user, user data"),
            "the reason code must be named: {text}"
        );
        assert!(
            !text.contains("provider reason"),
            "no provider reason may be reported: {text}"
        );
    })
    .await
    .expect("test timed out");
}

// An SPDU identifier the session layer does not know keeps its own error; the
// refuse branch must not swallow every unrecognized identifier.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_spdu_is_not_reported_as_a_refusal() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let port = spawn_refusing_peer(vec![0x0B, 0x00]);
        let err = connect_error(port).await;

        assert!(
            !matches!(err, ClientError::SessionRefused { .. }),
            "an unknown spdu is not a refusal: {err:?}"
        );
        let text = err.to_string();
        assert!(
            text.contains("unknown spdu id 0x0B"),
            "the unknown identifier must be reported: {text}"
        );
    })
    .await
    .expect("test timed out");
}
