//! Wire tests of `MmsClient` against a scripted peer.
//!
//! The peer runs the full ISO stack over real TCP (COTP, Session, Presentation,
//! ACSE, MMS) and answers each request with exactly the bytes a test chooses,
//! which a conforming server cannot be made to send: an answer under another
//! invokeID, a Read answer with two access results, an AARE without a result,
//! a Conclude-ErrorPDU or a Session abort.

use bytes::BytesMut;
use iec61850_hal::time::{Timer, TokioTimer};
use iec61850_hal::transport::{AsyncTransport, IoErrorKind, TransportError};
use iec61850_mms::iso::acse::{encode_aare, AcseConnection, AcseIndication};
use iec61850_mms::iso::cotp::{CotpConnection, CotpOptions};
use iec61850_mms::iso::presentation::{
    encode_abort as pres_encode_abort, encode_cpa, encode_user_data, encode_user_data_acse,
    parse_connect, parse_user_data, IsoPresentation,
};
use iec61850_mms::iso::session::{
    encode_abort as sess_encode_abort, encode_accept, encode_data, encode_disconnect,
    encode_finish, IsoSession, SessionIndication,
};
use iec61850_mms::mms::client::invoke_id::InvokeIdAllocator;
use iec61850_mms::mms::client::services::read_variable;
use iec61850_mms::mms::client::{
    ClientError, ConnectionState, MmsClient, MmsClientBuilder, MmsConnection,
};
use iec61850_mms::mms::pdu::initiate::InitiateResponsePdu;
use iec61850_mms::mms::pdu::{
    decode_confirmed_read_request, encode_confirmed_read_response, AccessResult, MmsData,
    ReadResponse,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

/// The peer side of one association.
struct Peer {
    cotp: CotpConnection<TcpStream>,
    session: IsoSession,
    pres: IsoPresentation,
}

/// What the peer answers to the AARQ.
enum Aare {
    /// result 0 with an Initiate response.
    Accept,
    /// result 0 with an Initiate response negotiating this outstanding
    /// calling limit.
    AcceptWithMaxCalling(u16),
    /// An AARE whose result field is left out.
    WithoutResult,
}

/// Binds a listener on the loopback interface.
async fn listener() -> (TcpListener, u16) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    (l, port)
}

/// Accepts one association and answers the AARQ as `aare` says.
async fn accept(listener: &TcpListener, aare: Aare) -> Peer {
    let (tcp, _) = listener.accept().await.unwrap();
    let mut cotp = CotpConnection::accept(tcp, CotpOptions::default())
        .await
        .unwrap();
    let mut session = IsoSession::new();
    let mut pres = IsoPresentation::new();

    let raw = cotp.recv_data().await.unwrap();
    assert_eq!(
        session.parse_message(&raw).unwrap(),
        SessionIndication::Connect
    );
    let cp = session.user_data(&raw).to_vec();
    let connect = parse_connect(&mut pres, &cp).unwrap();
    let aarq = connect.payload(&cp).to_vec();
    let mut acse = AcseConnection::new(None);
    let (ind, _) = acse.parse_message(&aarq).unwrap();
    assert_eq!(ind, AcseIndication::Associate);

    let mut init = BytesMut::new();
    let mut init_resp = InitiateResponsePdu::default();
    if let Aare::AcceptWithMaxCalling(n) = aare {
        init_resp.negotiated_max_serv_outstanding_calling = n;
    }
    init_resp.encode(&mut init);
    let mut aare_buf = BytesMut::new();
    encode_aare(0, Some(&init), 3, &mut aare_buf);
    let aare_bytes = match aare {
        Aare::Accept | Aare::AcceptWithMaxCalling(_) => aare_buf.to_vec(),
        Aare::WithoutResult => without_element(&aare_buf, 0xa2),
    };
    let mut cpa = BytesMut::new();
    encode_cpa(&pres, &aare_bytes, &mut cpa);
    let mut ac = BytesMut::new();
    encode_accept(&session, &cpa, &mut ac).unwrap();
    cotp.send_data(&ac).await.unwrap();
    Peer {
        cotp,
        session,
        pres,
    }
}

/// Removes the top-level element with `tag` from an ACSE APDU.
fn without_element(apdu: &[u8], tag: u8) -> Vec<u8> {
    let (len, hdr) = iec61850_asn1::decode_length(&apdu[1..]).unwrap();
    let content = &apdu[1 + hdr..1 + hdr + len];
    let mut body = Vec::new();
    let mut pos = 0;
    while pos < content.len() {
        let (l, h) = iec61850_asn1::decode_length(&content[pos + 1..]).unwrap();
        let end = pos + 1 + h + l;
        if content[pos] != tag {
            body.extend_from_slice(&content[pos..end]);
        }
        pos = end;
    }
    let mut out = BytesMut::new();
    out.extend_from_slice(&apdu[..1]);
    iec61850_asn1::encode_length(body.len(), &mut out);
    out.extend_from_slice(&body);
    out.to_vec()
}

impl Peer {
    /// Receives one SPDU and returns its indication with its user data.
    async fn recv_spdu(&mut self) -> Option<(SessionIndication, Vec<u8>)> {
        let raw = self.cotp.recv_data().await.ok()?;
        let ind = self.session.parse_message(&raw).unwrap();
        Some((ind, self.session.user_data(&raw).to_vec()))
    }

    /// Receives one MMS PDU carried in a Session DT.
    async fn recv_mms(&mut self) -> Vec<u8> {
        let (ind, ud) = self.recv_spdu().await.expect("an spdu");
        assert_eq!(ind, SessionIndication::Data);
        let r = parse_user_data(&mut self.pres, &ud).unwrap();
        r.payload(&ud).to_vec()
    }

    /// Sends one MMS PDU in a Session DT.
    async fn send_mms(&mut self, mms: &[u8]) {
        let mut p = BytesMut::new();
        encode_user_data(&self.pres, mms, &mut p);
        let mut s = BytesMut::new();
        encode_data(&p, &mut s);
        self.cotp.send_data(&s).await.unwrap();
    }

    /// Receives a Read request and returns its invokeID.
    async fn recv_read(&mut self) -> u32 {
        let mms = self.recv_mms().await;
        decode_confirmed_read_request(&mms).unwrap().0
    }

    /// Sends a Read answer under `invoke_id`.
    async fn send_read_response(&mut self, invoke_id: u32, results: Vec<AccessResult>) {
        let resp = ReadResponse {
            variable_access_spec: None,
            list_of_access_result: results,
        };
        let mut buf = BytesMut::new();
        encode_confirmed_read_response(invoke_id, &resp, &mut buf);
        self.send_mms(&buf).await;
    }
}

fn client(request_timeout_ms: u64) -> MmsClient {
    MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(request_timeout_ms)
        .build()
}

async fn connected_with(request_timeout_ms: u64) -> (MmsClient, Peer) {
    let (l, port) = listener().await;
    let mut c = client(request_timeout_ms);
    let (r, peer) = tokio::join!(c.connect("127.0.0.1", port), accept(&l, Aare::Accept));
    r.expect("connect");
    (c, peer)
}

async fn connected() -> (MmsClient, Peer) {
    connected_with(3_000).await
}

fn boolean(v: bool) -> AccessResult {
    AccessResult::Success(MmsData::Boolean(v))
}

#[tokio::test]
async fn answer_under_another_invoke_id_is_discarded() {
    let (mut c, mut peer) = connected().await;
    let server = async {
        let id = peer.recv_read().await;
        // a stray answer first, then the answer to the request
        peer.send_read_response(id.wrapping_add(100), vec![boolean(true)])
            .await;
        peer.send_read_response(id, vec![boolean(false)]).await;
        peer
    };
    let (value, _peer) = tokio::join!(c.read("LD0", "GGIO1$ST$Ind1$stVal"), server);
    assert_eq!(value.unwrap(), MmsData::Boolean(false));
}

#[tokio::test]
async fn answer_under_the_request_invoke_id_is_returned() {
    let (mut c, mut peer) = connected().await;
    let server = async {
        let id = peer.recv_read().await;
        peer.send_read_response(id, vec![boolean(true)]).await;
        peer
    };
    let (value, _peer) = tokio::join!(c.read("LD0", "GGIO1$ST$Ind1$stVal"), server);
    assert_eq!(value.unwrap(), MmsData::Boolean(true));
}

#[tokio::test]
async fn read_answer_with_two_access_results_is_rejected() {
    let (mut c, mut peer) = connected().await;
    let server = async {
        let id = peer.recv_read().await;
        peer.send_read_response(id, vec![boolean(true), boolean(false)])
            .await;
        peer
    };
    let (value, _peer) = tokio::join!(c.read("LD0", "GGIO1$ST$Ind1$stVal"), server);
    assert!(
        matches!(value, Err(ClientError::PduParse(_))),
        "got {value:?}"
    );
}

#[tokio::test]
async fn unanswered_request_times_out_and_leaves_the_association_usable() {
    let (mut c, mut peer) = connected_with(300).await;

    // the first request is never answered in time
    let (first, held_id) = tokio::join!(c.read("LD0", "GGIO1$ST$Ind1$stVal"), peer.recv_read());
    assert!(
        matches!(
            first,
            Err(ClientError::ServiceTimeout {
                timeout_ms: 300,
                ..
            })
        ),
        "got {first:?}"
    );
    assert_eq!(c.state(), ConnectionState::Connected);

    // its late answer precedes the answer to the next request
    let server = async {
        let id = peer.recv_read().await;
        peer.send_read_response(held_id, vec![boolean(true)]).await;
        peer.send_read_response(id, vec![boolean(false)]).await;
        peer
    };
    let (second, _peer) = tokio::join!(c.read("LD0", "GGIO1$ST$Ind2$stVal"), server);
    assert_eq!(second.unwrap(), MmsData::Boolean(false));
}

#[tokio::test]
async fn aare_without_result_is_refused() {
    let (l, port) = listener().await;
    let mut c = client(3_000);
    let (r, _peer) = tokio::join!(
        c.connect("127.0.0.1", port),
        accept(&l, Aare::WithoutResult)
    );
    assert!(matches!(r, Err(ClientError::AssociateFailed)), "got {r:?}");
    assert_eq!(c.state(), ConnectionState::Closed);
}

#[tokio::test]
async fn session_abort_from_the_peer_is_connection_lost() {
    let (mut c, mut peer) = connected().await;
    let server = async {
        let _ = peer.recv_read().await;
        let mut abrt = [0u8; 5];
        iec61850_mms::iso::acse::encode_abrt(false, &mut abrt);
        let mut p = BytesMut::new();
        pres_encode_abort(&peer.pres, &abrt, &mut p);
        let mut s = BytesMut::new();
        sess_encode_abort(&p, &mut s).unwrap();
        peer.cotp.send_data(&s).await.unwrap();
        peer
    };
    let (r, _peer) = tokio::join!(c.read("LD0", "GGIO1$ST$Ind1$stVal"), server);
    assert!(matches!(r, Err(ClientError::ConnectionLost)), "got {r:?}");
    assert_eq!(c.state(), ConnectionState::Closed);
}

#[tokio::test]
async fn transport_end_is_connection_lost() {
    let (mut c, mut peer) = connected().await;
    let server = async {
        let _ = peer.recv_read().await;
        drop(peer);
    };
    let (r, ()) = tokio::join!(c.read("LD0", "GGIO1$ST$Ind1$stVal"), server);
    assert!(matches!(r, Err(ClientError::ConnectionLost)), "got {r:?}");
    assert_eq!(c.state(), ConnectionState::Closed);
    let next = c.read("LD0", "GGIO1$ST$Ind1$stVal").await;
    assert!(
        matches!(next, Err(ClientError::NotConnected { .. })),
        "got {next:?}"
    );
}

impl Peer {
    /// Sends a Session FN carrying an ACSE RLRQ on the ACSE context.
    async fn send_release_request(&mut self) {
        let mut rlrq = [0u8; 5];
        iec61850_mms::iso::acse::encode_rlrq(&mut rlrq);
        let mut p = BytesMut::new();
        encode_user_data_acse(&self.pres, &rlrq, &mut p);
        let mut s = BytesMut::new();
        encode_finish(&p, &mut s).unwrap();
        self.cotp.send_data(&s).await.unwrap();
    }

    /// Receives the answer to a release request and returns its session
    /// indication and the ACSE APDU it carries.
    async fn recv_release_response(&mut self) -> (SessionIndication, Vec<u8>) {
        let (ind, ud) = self.recv_spdu().await.expect("release response");
        let mut pres = IsoPresentation::new();
        let parsed = parse_user_data(&mut pres, &ud).expect("release response user data");
        assert_eq!(parsed.context_id, 1, "rlre travels on the acse context");
        (ind, parsed.payload(&ud).to_vec())
    }
}

#[tokio::test]
async fn conclude_request_from_the_server_closes_the_client() {
    let (mut c, mut peer) = connected().await;
    let server = async {
        let _ = peer.recv_read().await;
        peer.send_mms(&[0x8b, 0x00]).await;
        let answer = peer.recv_mms().await;
        (peer, answer)
    };
    let (r, (_peer, answer)) = tokio::join!(c.read("LD0", "GGIO1$ST$Ind1$stVal"), server);
    assert!(matches!(r, Err(ClientError::ReleasedByPeer)), "got {r:?}");
    assert_eq!(answer, vec![0x8c, 0x00]);
    assert_eq!(c.state(), ConnectionState::Closed);
}

#[tokio::test]
async fn release_request_from_the_peer_is_answered_with_rlre_in_a_disconnect() {
    let (mut c, mut peer) = connected().await;
    let server = async {
        let _ = peer.recv_read().await;
        peer.send_release_request().await;
        let release = peer.recv_release_response().await;
        (peer, release)
    };
    let (r, (_peer, (ind, apdu))) = tokio::join!(c.read("LD0", "GGIO1$ST$Ind1$stVal"), server);
    assert!(matches!(r, Err(ClientError::ReleasedByPeer)), "got {r:?}");
    assert_eq!(ind, SessionIndication::Disconnect);
    assert_eq!(apdu.first(), Some(&0x63), "an rlre: {apdu:02x?}");
    assert_eq!(c.state(), ConnectionState::Closed);
}

#[tokio::test]
async fn release_request_while_polling_reports_is_answered() {
    let (mut c, mut peer) = connected().await;
    let server = async {
        peer.send_release_request().await;
        let release = peer.recv_release_response().await;
        (peer, release)
    };
    let (r, (_peer, (ind, _))) = tokio::join!(
        c.recv_unconfirmed_pdu_with_timeout(Duration::from_secs(3)),
        server
    );
    assert!(matches!(r, Err(ClientError::ReleasedByPeer)), "got {r:?}");
    assert_eq!(ind, SessionIndication::Disconnect);
    assert_eq!(c.state(), ConnectionState::Closed);
}

#[tokio::test]
async fn refused_conclude_keeps_the_association() {
    let (mut c, mut peer) = connected().await;
    let server = async {
        assert_eq!(peer.recv_mms().await, vec![0x8b, 0x00]);
        // Conclude-ErrorPDU [13] IMPLICIT ServiceError: errorClass conclude [9],
        // further-communication-required(1)
        peer.send_mms(&[0xad, 0x05, 0xa0, 0x03, 0x89, 0x01, 0x01])
            .await;
        peer
    };
    let (r, mut peer) = tokio::join!(c.disconnect(), server);
    assert!(matches!(r, Err(ClientError::ConcludeRejected)), "got {r:?}");
    assert_eq!(c.state(), ConnectionState::Connected);

    // the association still serves requests
    let server = async {
        let id = peer.recv_read().await;
        peer.send_read_response(id, vec![boolean(true)]).await;
        peer
    };
    let (value, _peer) = tokio::join!(c.read("LD0", "GGIO1$ST$Ind1$stVal"), server);
    assert_eq!(value.unwrap(), MmsData::Boolean(true));
}

#[tokio::test]
async fn release_sends_rlrq_in_a_finish_and_accepts_rlre_in_the_disconnect() {
    let (mut c, mut peer) = connected().await;
    let server = async {
        assert_eq!(peer.recv_mms().await, vec![0x8b, 0x00]);
        // an InformationReport ahead of the conclude response is not taken for it
        peer.send_mms(&[0xa3, 0x02, 0xa0, 0x00]).await;
        peer.send_mms(&[0x8c, 0x00]).await;
        let (ind, ud) = peer.recv_spdu().await.expect("finish");
        let mut rlre = [0u8; 2];
        iec61850_mms::iso::acse::encode_rlre(&mut rlre);
        let mut p = BytesMut::new();
        encode_user_data_acse(&peer.pres, &rlre, &mut p);
        let mut dn = BytesMut::new();
        encode_disconnect(&p, &mut dn).unwrap();
        peer.cotp.send_data(&dn).await.unwrap();
        (ind, ud)
    };
    let (r, (ind, ud)) = tokio::join!(c.disconnect(), server);
    r.expect("disconnect");
    assert_eq!(ind, SessionIndication::Finish);
    let mut pres = IsoPresentation::new();
    let parsed = parse_user_data(&mut pres, &ud).expect("finish user data");
    assert_eq!(parsed.context_id, 1, "rlrq travels on the acse context");
    assert_eq!(parsed.payload(&ud), &[0x62, 0x03, 0x80, 0x01, 0x00]);
    assert_eq!(c.state(), ConnectionState::Closed);
}

#[tokio::test]
async fn release_without_an_answer_still_closes() {
    let (mut c, mut peer) = connected_with(300).await;
    let server = async {
        assert_eq!(peer.recv_mms().await, vec![0x8b, 0x00]);
        peer.send_mms(&[0x8c, 0x00]).await;
        let finish = peer.recv_spdu().await.expect("finish");
        (peer, finish.0)
    };
    let (r, (_peer, ind)) = tokio::join!(c.disconnect(), server);
    r.expect("disconnect");
    assert_eq!(ind, SessionIndication::Finish);
    assert_eq!(c.state(), ConnectionState::Closed);
}

#[tokio::test]
async fn abort_sends_a_user_abrt_in_a_session_abort() {
    let (mut c, mut peer) = connected().await;
    let (r, raw) = tokio::join!(c.abort(), peer.cotp.recv_data());
    r.expect("abort");
    let raw = raw.expect("abort spdu");
    assert_eq!(raw[0], 0x19, "session ab spdu");
    let abrt_user = [0x64, 0x03, 0x80, 0x01, 0x00];
    assert!(
        raw.windows(abrt_user.len()).any(|w| w == abrt_user),
        "an abrt with abort-source acse-service-user: {raw:02x?}"
    );
    assert_eq!(c.state(), ConnectionState::Closed);
}

#[tokio::test]
async fn unconfirmed_pdu_without_content_is_discarded() {
    let (mut c, mut peer) = connected().await;
    let server = async {
        let id = peer.recv_read().await;
        // a3 00 carries no unconfirmedService, which is mandatory
        peer.send_mms(&[0xa3, 0x00]).await;
        peer.send_mms(&[0xa3, 0x03, 0xa0, 0x01, 0x07]).await;
        peer.send_read_response(id, vec![boolean(true)]).await;
        // and once more while no request is outstanding
        peer.send_mms(&[0xa3, 0x00]).await;
        peer
    };
    let (value, _peer) = tokio::join!(c.read("LD0", "GGIO1$ST$Ind1$stVal"), server);
    assert_eq!(value.unwrap(), MmsData::Boolean(true));
    let first = c
        .recv_unconfirmed_pdu_with_timeout(Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(first.as_deref(), Some(&[0xa0, 0x01, 0x07][..]));
    let second = c
        .recv_unconfirmed_pdu_with_timeout(Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(second, None, "the empty pdu is not handed out");
}

#[tokio::test]
async fn pending_unconfirmed_pdus_are_bounded() {
    let (l, port) = listener().await;
    let mut c = MmsClientBuilder::new()
        .request_timeout_ms(3_000)
        .max_pending_unconfirmed(2)
        .build();
    let (r, mut peer) = tokio::join!(c.connect("127.0.0.1", port), accept(&l, Aare::Accept));
    r.expect("connect");
    let server = async {
        let id = peer.recv_read().await;
        for tag in [0x01u8, 0x02, 0x03] {
            // three InformationReports with distinguishable bodies
            peer.send_mms(&[0xa3, 0x03, 0xa0, 0x01, tag]).await;
        }
        peer.send_read_response(id, vec![boolean(true)]).await;
        peer
    };
    let (value, _peer) = tokio::join!(c.read("LD0", "GGIO1$ST$Ind1$stVal"), server);
    assert_eq!(value.unwrap(), MmsData::Boolean(true));
    let mut kept = Vec::new();
    while let Some(inner) = c
        .recv_unconfirmed_pdu_with_timeout(Duration::from_millis(1))
        .await
        .unwrap()
    {
        kept.push(inner.to_vec());
        if kept.len() > 3 {
            break;
        }
    }
    // the oldest report is the one dropped
    assert_eq!(
        kept,
        vec![vec![0xa0, 0x01, 0x02], vec![0xa0, 0x01, 0x03]],
        "kept {kept:02x?}"
    );
}

/// A TCP transport whose reads fail with a chosen error once `fail` is set.
struct FailingReads {
    tcp: TcpStream,
    fail: std::sync::Arc<std::sync::atomic::AtomicBool>,
    error: TransportError,
}

impl AsyncTransport for FailingReads {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        if self.fail.load(std::sync::atomic::Ordering::Acquire) {
            return Err(self.error.clone());
        }
        AsyncTransport::read(&mut self.tcp, buf).await
    }

    async fn write_all(&mut self, buf: &[u8]) -> Result<(), TransportError> {
        AsyncTransport::write_all(&mut self.tcp, buf).await
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        AsyncTransport::close(&mut self.tcp).await
    }
}

#[tokio::test]
async fn transport_failure_keeps_its_cause() {
    let (l, port) = listener().await;
    let fail = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let alert = TransportError::io(IoErrorKind::InvalidData)
        .with_detail("received fatal alert: CertificateRequired");
    let transport = FailingReads {
        tcp: TcpStream::connect(("127.0.0.1", port)).await.unwrap(),
        fail: fail.clone(),
        error: alert.clone(),
    };
    let (c, mut peer) = tokio::join!(
        MmsClient::<FailingReads, TokioTimer>::from_transport(transport),
        accept(&l, Aare::Accept)
    );
    let mut c = c.expect("association");

    fail.store(true, std::sync::atomic::Ordering::Release);
    let (r, _) = tokio::join!(c.read("LD0", "GGIO1$ST$Ind1$stVal"), peer.recv_read());
    match r {
        Err(ClientError::Transport(cause)) => {
            assert_eq!(cause, alert);
            assert_eq!(cause.kind(), IoErrorKind::InvalidData);
        }
        other => panic!("expected a transport error, got {other:?}"),
    }
    assert_eq!(c.state(), ConnectionState::Closed);
}

#[tokio::test]
async fn refused_tcp_connection_reports_its_kind() {
    // a port that was just released refuses the connection
    let (l, port) = listener().await;
    drop(l);
    // Windows retries a refused loopback connect for about two seconds
    let mut c = MmsClientBuilder::new().connect_timeout_ms(30_000).build();
    let r = c.connect("127.0.0.1", port).await;
    match r {
        Err(ClientError::Transport(cause)) => {
            assert_eq!(cause.kind(), IoErrorKind::ConnectionRefused, "{cause}");
            assert!(cause.detail().is_some(), "{cause}");
        }
        other => panic!("expected a transport error, got {other:?}"),
    }
}

async fn connected_with_max_calling(
    request_timeout_ms: u64,
    max_calling: u16,
) -> (MmsClient, Peer) {
    let (l, port) = listener().await;
    let mut c = client(request_timeout_ms);
    let (r, peer) = tokio::join!(
        c.connect("127.0.0.1", port),
        accept(&l, Aare::AcceptWithMaxCalling(max_calling))
    );
    r.expect("connect");
    (c, peer)
}

#[tokio::test]
async fn outstanding_limit_waits_for_the_late_answer() {
    let (mut c, mut peer) = connected_with_max_calling(300, 1).await;
    let (first, held_id) = tokio::join!(c.read("LD0", "GGIO1$ST$Ind1$stVal"), peer.recv_read());
    assert!(
        matches!(
            first,
            Err(ClientError::ServiceTimeout {
                timeout_ms: 300,
                ..
            })
        ),
        "got {first:?}"
    );

    // the late answer frees the one slot, and only then is the next request sent
    let server = async {
        peer.send_read_response(held_id, vec![boolean(true)]).await;
        let id = peer.recv_read().await;
        peer.send_read_response(id, vec![boolean(false)]).await;
        peer
    };
    let (second, _peer) = tokio::join!(c.read("LD0", "GGIO1$ST$Ind2$stVal"), server);
    assert_eq!(second.unwrap(), MmsData::Boolean(false));
}

#[tokio::test]
async fn outstanding_limit_without_a_late_answer_refuses_to_send() {
    let (mut c, mut peer) = connected_with_max_calling(300, 1).await;
    let (first, _) = tokio::join!(c.read("LD0", "GGIO1$ST$Ind1$stVal"), peer.recv_read());
    assert!(
        matches!(
            first,
            Err(ClientError::ServiceTimeout {
                timeout_ms: 300,
                ..
            })
        ),
        "got {first:?}"
    );

    let second = c.read("LD0", "GGIO1$ST$Ind2$stVal").await;
    assert!(
        matches!(second, Err(ClientError::OutstandingCallLimit)),
        "got {second:?}"
    );
    assert_eq!(c.state(), ConnectionState::Connected);

    // the next spdu the peer sees is the abort, so the refused read never left
    let (r, next) = tokio::join!(c.abort(), peer.recv_spdu());
    r.expect("abort");
    let (ind, _) = next.expect("an spdu");
    assert_eq!(ind, SessionIndication::Abort);
}

#[tokio::test]
async fn outstanding_limit_with_a_free_slot_sends_at_once() {
    let (mut c, mut peer) = connected_with_max_calling(300, 2).await;
    let (first, held_id) = tokio::join!(c.read("LD0", "GGIO1$ST$Ind1$stVal"), peer.recv_read());
    assert!(
        matches!(
            first,
            Err(ClientError::ServiceTimeout {
                timeout_ms: 300,
                ..
            })
        ),
        "got {first:?}"
    );

    // the second slot is free, so the request goes out before the late answer
    let server = async {
        let id = peer.recv_read().await;
        peer.send_read_response(id, vec![boolean(false)]).await;
        peer.send_read_response(held_id, vec![boolean(true)]).await;
        peer
    };
    let (second, _peer) = tokio::join!(c.read("LD0", "GGIO1$ST$Ind2$stVal"), server);
    assert_eq!(second.unwrap(), MmsData::Boolean(false));
}

#[tokio::test]
async fn initiate_request_proposes_the_configured_outstanding_limit() {
    let (l, port) = listener().await;
    let mut c = MmsClientBuilder::new().max_outstanding(3).build();
    let probe = async {
        let (tcp, _) = l.accept().await.unwrap();
        let mut cotp = CotpConnection::accept(tcp, CotpOptions::default())
            .await
            .unwrap();
        let raw = cotp.recv_data().await.unwrap();
        let mut session = IsoSession::new();
        let mut pres = IsoPresentation::new();
        session.parse_message(&raw).unwrap();
        let cp = session.user_data(&raw).to_vec();
        let connect = parse_connect(&mut pres, &cp).unwrap();
        let aarq = connect.payload(&cp).to_vec();
        let mut acse = AcseConnection::new(None);
        let (_, init) = acse.parse_message(&aarq).unwrap();
        iec61850_mms::mms::pdu::initiate::InitiateRequestPdu::decode(init).unwrap()
    };
    let (_, init) = tokio::join!(c.connect("127.0.0.1", port), probe);
    assert_eq!(init.proposed_max_serv_outstanding_calling, 3);
}

/// Real time after which a test driven by a granted timer gives up. It only
/// turns a client stuck on a sleep that no grant ends into a failure; the
/// outcome of a passing test never depends on it.
const HANG_GUARD: Duration = Duration::from_secs(30);

/// A timer whose sleeps end only when the test grants an expiry.
///
/// Each granted permit ends exactly one sleep, whichever is waiting or starts
/// next, so a timeout fires at the point the test chooses.
#[derive(Clone)]
struct GrantedTimer(Arc<Semaphore>);

impl Timer for GrantedTimer {
    async fn sleep(&self, _duration: Duration) {
        self.0.acquire().await.expect("semaphore open").forget();
    }
}

/// Associates a connection driven by a granted timer that proposes
/// `max_calling`, with a peer that negotiates the same value.
async fn associated_with_granted_timer(
    max_calling: u16,
) -> (MmsConnection<TcpStream, GrantedTimer>, Peer, Arc<Semaphore>) {
    let (l, port) = listener().await;
    let expiries = Arc::new(Semaphore::new(0));
    let mut conn = MmsConnection::with_timer(GrantedTimer(expiries.clone()));
    conn.local_max_outstanding = Some(max_calling);
    let client = async {
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        conn.connect_via(tcp).await
    };
    let (r, peer) = tokio::join!(client, accept(&l, Aare::AcceptWithMaxCalling(max_calling)));
    r.expect("associate");
    assert_eq!(conn.negotiated_max_calling, max_calling);
    (conn, peer, expiries)
}

/// Sends `count` Reads the peer holds unanswered until each times out, and
/// returns their invokeIDs in order.
async fn hold_unanswered_reads(
    conn: &mut MmsConnection<TcpStream, GrantedTimer>,
    alloc: &mut InvokeIdAllocator,
    peer: &mut Peer,
    expiries: &Semaphore,
    count: u16,
) -> Vec<u32> {
    let mut held = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let server = async {
            let id = peer.recv_read().await;
            expiries.add_permits(1);
            id
        };
        let (r, id) = tokio::join!(
            read_variable(conn, alloc, "LD0", "GGIO1$ST$Ind1$stVal"),
            server
        );
        assert!(
            matches!(r, Err(ClientError::ServiceTimeout { .. })),
            "got {r:?}"
        );
        held.push(id);
    }
    held
}

#[tokio::test]
async fn outstanding_limit_above_64_refuses_to_send_past_the_limit() {
    const LIMIT: u16 = 65;
    let (mut conn, mut peer, expiries) = associated_with_granted_timer(LIMIT).await;
    let mut alloc = InvokeIdAllocator::new(5);
    let held = hold_unanswered_reads(&mut conn, &mut alloc, &mut peer, &expiries, LIMIT).await;
    assert_eq!(held, (1..=u32::from(LIMIT)).collect::<Vec<_>>());

    // every slot is held, and no late answer arrives before the wait expires
    expiries.add_permits(1);
    let refused = read_variable(&mut conn, &mut alloc, "LD0", "GGIO1$ST$Ind2$stVal").await;
    assert!(
        matches!(refused, Err(ClientError::OutstandingCallLimit)),
        "got {refused:?}"
    );
    assert_eq!(conn.state, ConnectionState::Connected);

    // the next spdu the peer sees is the abort, so the refused read never left
    let (r, next) = tokio::join!(conn.abort(), peer.recv_spdu());
    r.expect("abort");
    let (ind, _) = next.expect("an spdu");
    assert_eq!(ind, SessionIndication::Abort);
}

#[tokio::test]
async fn outstanding_limit_above_64_frees_a_slot_on_the_oldest_late_answer() {
    const LIMIT: u16 = 65;
    let (mut conn, mut peer, expiries) = associated_with_granted_timer(LIMIT).await;
    let mut alloc = InvokeIdAllocator::new(5);
    let held = hold_unanswered_reads(&mut conn, &mut alloc, &mut peer, &expiries, LIMIT).await;

    // the late answer to the first request frees its slot for the next one
    let server = async {
        peer.send_read_response(held[0], vec![boolean(true)]).await;
        let id = peer.recv_read().await;
        peer.send_read_response(id, vec![boolean(false)]).await;
        id
    };
    let exchange = async {
        tokio::join!(
            read_variable(&mut conn, &mut alloc, "LD0", "GGIO1$ST$Ind2$stVal"),
            server
        )
    };
    let (value, id) = tokio::time::timeout(HANG_GUARD, exchange)
        .await
        .expect("the client is still waiting for a slot the late answer should have freed");
    assert_eq!(value.unwrap(), MmsData::Boolean(false));
    assert_eq!(id, u32::from(LIMIT) + 1);
}

/// Runs a client call together with the peer side of its exchange and returns
/// both results.
///
/// The peer side sends the answer last, so it finishes first; a call that ends
/// while the peer side still waits fails the test with its result instead of
/// leaving the peer waiting forever.
async fn exchange<C, P>(call: C, peer_side: P) -> (C::Output, P::Output)
where
    C: std::future::Future,
    C::Output: std::fmt::Debug,
    P: std::future::Future,
{
    let mut call = std::pin::pin!(call);
    let mut peer_side = std::pin::pin!(peer_side);
    tokio::select! {
        biased;
        p = &mut peer_side => (call.await, p),
        c = &mut call => panic!("the call ended before the peer side: {c:?}"),
    }
}

/// Starts a Read and drops it once the peer has received its request, the way
/// an outer timeout cancels a call; returns the invokeID the peer saw.
async fn read_dropped_after_sending(c: &mut MmsClient, peer: &mut Peer) -> u32 {
    tokio::select! {
        biased;
        r = c.read("LD0", "GGIO1$ST$Ind1$stVal") => panic!("the read ended first: {r:?}"),
        id = peer.recv_read() => id,
    }
}

#[tokio::test]
async fn calls_dropped_after_sending_leave_the_client_usable() {
    let (mut c, mut peer) = connected().await;
    let mut held = Vec::new();
    for _ in 0..5 {
        held.push(read_dropped_after_sending(&mut c, &mut peer).await);
    }
    assert_eq!(held, vec![1, 2, 3, 4, 5]);

    // the dropped requests hold every slot until their late answers arrive
    let server = async {
        for &id in &held {
            peer.send_read_response(id, vec![boolean(true)]).await;
        }
        let id = peer.recv_read().await;
        peer.send_read_response(id, vec![boolean(false)]).await;
        id
    };
    let (value, id) = exchange(c.read("LD0", "GGIO1$ST$Ind2$stVal"), server).await;
    assert_eq!(value.unwrap(), MmsData::Boolean(false));
    assert_eq!(id, 6);
}

#[tokio::test]
async fn a_new_association_starts_with_every_slot_free() {
    let (mut c, mut peer) = connected().await;
    for _ in 0..5 {
        read_dropped_after_sending(&mut c, &mut peer).await;
    }

    let (l, port) = listener().await;
    let (r, mut fresh) = tokio::join!(c.connect("127.0.0.1", port), accept(&l, Aare::Accept));
    r.expect("reconnect");
    let server = async {
        let id = fresh.recv_read().await;
        fresh.send_read_response(id, vec![boolean(true)]).await;
    };
    let (value, ()) = exchange(c.read("LD0", "GGIO1$ST$Ind1$stVal"), server).await;
    assert_eq!(value.unwrap(), MmsData::Boolean(true));
}

#[tokio::test]
async fn a_call_dropped_before_sending_sends_nothing() {
    let (mut c, mut peer) = connected_with_max_calling(3_000, 1).await;
    let held = read_dropped_after_sending(&mut c, &mut peer).await;

    // the one slot is held, so this read waits for a slot and is dropped unsent
    tokio::select! {
        biased;
        r = c.read("LD0", "GGIO1$ST$Ind2$stVal") => panic!("the read ended first: {r:?}"),
        () = std::future::ready(()) => {}
    }

    let server = async {
        peer.send_read_response(held, vec![boolean(true)]).await;
        let id = peer.recv_read().await;
        peer.send_read_response(id, vec![boolean(false)]).await;
        id
    };
    let (value, id) = exchange(c.read("LD0", "GGIO1$ST$Ind3$stVal"), server).await;
    assert_eq!(value.unwrap(), MmsData::Boolean(false));
    assert_eq!(id, held + 2, "the dropped read never reached the peer");
}

#[tokio::test]
async fn refused_oversized_writes_hold_no_slot() {
    let (l, port) = listener().await;
    let mut c = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .local_max_pdu_size(128)
        .build();
    let (r, mut peer) = tokio::join!(c.connect("127.0.0.1", port), accept(&l, Aare::Accept));
    r.expect("connect");

    // more refused sends than the outstanding limit of 5
    for _ in 0..6 {
        let refused = c
            .write(
                "LD0",
                "GGIO1$ST$Ind1$stVal",
                MmsData::VisibleString("x".repeat(512)),
            )
            .await;
        assert!(
            matches!(refused, Err(ClientError::PduTooLarge { .. })),
            "got {refused:?}"
        );
    }

    let server = async {
        let id = peer.recv_read().await;
        peer.send_read_response(id, vec![boolean(true)]).await;
        id
    };
    let (value, id) = exchange(c.read("LD0", "GGIO1$ST$Ind2$stVal"), server).await;
    assert_eq!(value.unwrap(), MmsData::Boolean(true));
    assert_eq!(id, 7);
}

/// A transport over TCP whose writes stop making progress once `stall` is set.
struct StalledWrites {
    tcp: TcpStream,
    stall: Arc<std::sync::atomic::AtomicBool>,
}

impl AsyncTransport for StalledWrites {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        AsyncTransport::read(&mut self.tcp, buf).await
    }

    async fn write_all(&mut self, buf: &[u8]) -> Result<(), TransportError> {
        if self.stall.load(std::sync::atomic::Ordering::Acquire) {
            std::future::pending::<()>().await;
        }
        AsyncTransport::write_all(&mut self.tcp, buf).await
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        AsyncTransport::close(&mut self.tcp).await
    }
}

#[tokio::test]
async fn a_call_dropped_while_sending_closes_the_connection() {
    let (l, port) = listener().await;
    let stall = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let transport = StalledWrites {
        tcp: TcpStream::connect(("127.0.0.1", port)).await.unwrap(),
        stall: stall.clone(),
    };
    let (c, _peer) = tokio::join!(
        MmsClient::<StalledWrites, TokioTimer>::from_transport(transport),
        accept(&l, Aare::Accept)
    );
    let mut c = c.expect("association");

    // the request is stuck in the transport when the call is dropped
    stall.store(true, std::sync::atomic::Ordering::Release);
    tokio::select! {
        biased;
        r = c.read("LD0", "GGIO1$ST$Ind1$stVal") => panic!("the read ended first: {r:?}"),
        () = std::future::ready(()) => {}
    }
    assert_eq!(c.state(), ConnectionState::Closed);
    let next = c.read("LD0", "GGIO1$ST$Ind1$stVal").await;
    assert!(
        matches!(next, Err(ClientError::NotConnected { .. })),
        "got {next:?}"
    );
}

#[tokio::test]
async fn each_association_gets_a_new_number() {
    let mut c = client(3_000);
    assert_eq!(c.association_id(), 0);

    let (l, port) = listener().await;
    let (r, first) = tokio::join!(c.connect("127.0.0.1", port), accept(&l, Aare::Accept));
    r.expect("connect");
    assert_eq!(c.association_id(), 1);

    // the number stays with the association after it ends
    drop(first);
    let lost = c.read("LD0", "GGIO1$ST$Ind1$stVal").await;
    assert!(
        matches!(lost, Err(ClientError::ConnectionLost)),
        "got {lost:?}"
    );
    assert_eq!(c.association_id(), 1);

    let (r, _second) = tokio::join!(c.connect("127.0.0.1", port), accept(&l, Aare::Accept));
    r.expect("reconnect");
    assert_eq!(c.association_id(), 2);
}

fn list_entry(item: &str) -> iec61850_mms::mms::pdu::ListOfVariableEntry {
    iec61850_mms::mms::pdu::ObjectName::DomainSpecific {
        domain_id: "LD0".to_string(),
        item_id: item.to_string(),
    }
    .into()
}

#[test]
fn blocking_client_covers_list_reads_reports_and_abort() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let (l, port) = rt.block_on(listener());
    let peer = rt.spawn(async move {
        let mut peer = accept(&l, Aare::Accept).await;
        let id = peer.recv_read().await;
        peer.send_read_response(id, vec![boolean(true), boolean(false)])
            .await;
        peer.send_mms(&[0xa3, 0x03, 0xa0, 0x01, 0x07]).await;
        let (ind, _) = peer.recv_spdu().await.expect("abort");
        ind
    });

    let mut c = iec61850_mms::mms::client::BlockingMmsClient::from_builder(
        MmsClientBuilder::new().request_timeout_ms(3_000),
    )
    .unwrap();
    c.connect("127.0.0.1", port).unwrap();
    let results = c
        .read_list(vec![
            list_entry("GGIO1$ST$Ind1$stVal"),
            list_entry("GGIO1$ST$Ind2$stVal"),
        ])
        .unwrap();
    assert_eq!(results, vec![boolean(true), boolean(false)]);
    let report = c
        .recv_unconfirmed_pdu_with_timeout(Duration::from_secs(3))
        .unwrap();
    assert_eq!(report.as_deref(), Some(&[0xa0, 0x01, 0x07][..]));
    c.abort().unwrap();
    assert_eq!(c.state(), ConnectionState::Closed);
    assert_eq!(rt.block_on(peer).unwrap(), SessionIndication::Abort);
}

#[test]
fn async_client_taken_from_a_blocking_client_keeps_its_association() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let (l, port) = rt.block_on(listener());
    let peer = rt.spawn(async move {
        let mut peer = accept(&l, Aare::Accept).await;
        let id = peer.recv_read().await;
        peer.send_read_response(id, vec![boolean(true)]).await;
        let id = peer.recv_read().await;
        peer.send_read_response(id, vec![boolean(false)]).await;
        peer
    });

    let mut c = iec61850_mms::mms::client::BlockingMmsClient::from_builder(
        MmsClientBuilder::new().request_timeout_ms(3_000),
    )
    .unwrap();
    c.connect("127.0.0.1", port).unwrap();
    assert!(matches!(
        c.read("LD0", "GGIO1$ST$Ind1$stVal").unwrap(),
        iec61850_mms::mms::client::MmsValue::Boolean(true)
    ));
    let (mut client, client_rt) = c.into_parts();
    assert_eq!(client.state(), ConnectionState::Connected);
    let value = client_rt
        .block_on(client.read("LD0", "GGIO1$ST$Ind2$stVal"))
        .expect("read on the runtime the association was built on");
    assert!(matches!(
        value,
        iec61850_mms::mms::client::MmsValue::Boolean(false)
    ));
    drop(rt.block_on(peer).unwrap());
}
