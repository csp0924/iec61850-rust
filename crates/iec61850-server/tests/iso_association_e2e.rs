//! The ISO upper layers of an association over real TCP: raw COTP, Session,
//! Presentation and ACSE PDUs against the server, checking the presentation
//! context identifiers it answers on, the PDUs that refuse an association, and
//! the release of an association.

use bytes::BytesMut;
use iec61850_mms::iso::acse::{encode_aarq, encode_rlrq, AcseConnection, AcseIndication};
use iec61850_mms::iso::cotp::{CotpConnection, CotpOptions};
use iec61850_mms::iso::presentation::{
    encode_connect as pres_encode_connect, encode_user_data, encode_user_data_acse, parse_reject,
    parse_user_data, IsoPresentation, PresentationConnectionParameters,
};
use iec61850_mms::iso::session::{
    encode_connect as sess_encode_connect, encode_data, encode_finish, IsoParameters, IsoSession,
    SessionIndication,
};
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_mms::mms::pdu::initiate::InitiateRequestPdu;
use iec61850_mms::mms::pdu::read::{
    decode_confirmed_read_response, encode_confirmed_read_request, ReadRequest,
};
use iec61850_mms::{AarqAddressing, MmsData};
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObjectBuilder, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::{IedServer, IedServerConfig, ServerHandle};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// ACSE presentation context item of the CP `encode_connect` writes: context
/// identifier 1 and the ACSE abstract syntax.
const ACSE_ITEM: [u8; 9] = [0x02, 0x01, 0x01, 0x06, 0x04, 0x52, 0x01, 0x00, 0x01];

/// MMS presentation context item of the same CP: context identifier 3 and the
/// MMS abstract syntax.
const MMS_ITEM: [u8; 10] = [0x02, 0x01, 0x03, 0x06, 0x05, 0x28, 0xca, 0x22, 0x02, 0x01];

/// Start of the PDV that carries the AARQ in the same CP: context identifier 1
/// followed by the presentation-data tag.
const AARQ_PDV: [u8; 4] = [0x02, 0x01, 0x01, 0xa0];

fn model() -> Arc<IedModel> {
    let vendor = DataAttribute::new(
        "vendor",
        FC::Dc,
        DataAttributeType::VisibleString(255),
        TrgOps::NONE,
        MmsValue::VisibleString("acme".into()),
    );
    let nam_plt = DataObjectBuilder::scalar("NamPlt")
        .add_da_node(vendor)
        .build()
        .unwrap();
    let lln0 = LogicalNodeBuilder::lln0().add_do(nam_plt).build().unwrap();
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .build()
        .unwrap();
    Arc::new(
        IedModelBuilder::new("TEST")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap(),
    )
}

async fn start_server() -> ServerHandle {
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

/// Encodes the default CP carrying an AARQ whose user information is `mms`.
fn cp_carrying(mms: &[u8]) -> Vec<u8> {
    let mut aarq = BytesMut::new();
    encode_aarq(mms, None, 3, &AarqAddressing::default(), &mut aarq);
    let mut cp = BytesMut::new();
    pres_encode_connect(&PresentationConnectionParameters::default(), &aarq, &mut cp);
    cp.to_vec()
}

fn initiate(req: &InitiateRequestPdu) -> Vec<u8> {
    let mut initiate = BytesMut::new();
    req.encode(&mut initiate);
    initiate.to_vec()
}

/// Encodes the default CP carrying an AARQ with the default Initiate request.
fn cp() -> Vec<u8> {
    cp_carrying(&initiate(&InitiateRequestPdu::default()))
}

/// Replaces the single occurrence of `pattern` in `buf`, writing `value` at
/// `offset` inside it.
fn patch(buf: &mut [u8], pattern: &[u8], offset: usize, value: u8) {
    let at = buf
        .windows(pattern.len())
        .position(|w| w == pattern)
        .expect("the pattern is present");
    buf[at + offset] = value;
}

/// Encodes a CP whose ACSE and MMS contexts carry the identifiers `acse` and
/// `mms`, the AARQ travelling on the ACSE one.
fn cp_with_context_ids(acse: u8, mms: u8) -> Vec<u8> {
    let mut cp = cp();
    patch(&mut cp, &ACSE_ITEM, 2, acse);
    patch(&mut cp, &MMS_ITEM, 2, mms);
    patch(&mut cp, &AARQ_PDV, 2, acse);
    cp
}

fn cn(cp: &[u8]) -> Vec<u8> {
    let mut cn = BytesMut::new();
    sess_encode_connect(&IsoParameters::default(), &IsoSession::new(), cp, &mut cn).unwrap();
    cn.to_vec()
}

async fn connect_cotp(handle: &ServerHandle) -> CotpConnection<TcpStream> {
    let tcp = TcpStream::connect(handle.bound_addr).await.unwrap();
    CotpConnection::connect(tcp, CotpOptions::default())
        .await
        .unwrap()
}

/// Reads one TSDU and parses its SPDU, returning the indication and the user
/// data; `None` once the server has closed the connection.
async fn recv_spdu(cotp: &mut CotpConnection<TcpStream>) -> Option<(SessionIndication, Vec<u8>)> {
    let raw = tokio::time::timeout(Duration::from_secs(5), cotp.recv_data())
        .await
        .expect("the server answers or closes in time")
        .ok()?;
    let mut s = IsoSession::new();
    let ind = s.parse_message(&raw).expect("the SPDU parses");
    Some((ind, s.user_data(&raw).to_vec()))
}

/// Splits a Fully-Encoded-Data PPDU into its context identifier and payload.
fn pdv(ud: &[u8]) -> (u8, Vec<u8>) {
    let mut p = IsoPresentation::new();
    let r = parse_user_data(&mut p, ud).expect("a fully-encoded-data PPDU");
    (r.context_id, r.payload(ud).to_vec())
}

/// Reads a BER length at `buf[*pos]`, short form or `0x81`/`0x82` long form.
fn ber_len(buf: &[u8], pos: &mut usize) -> usize {
    let first = buf[*pos];
    *pos += 1;
    match first {
        0x81 => {
            *pos += 1;
            buf[*pos - 1] as usize
        }
        0x82 => {
            *pos += 2;
            u16::from_be_bytes([buf[*pos - 2], buf[*pos - 1]]) as usize
        }
        short => short as usize,
    }
}

/// Returns the indirect-reference of the user-information of an AARE: the
/// presentation context identifier its MMS PDU travels on.
fn aare_indirect_reference(aare: &[u8]) -> Option<u8> {
    let mut pos = 1;
    let end = ber_len(aare, &mut pos) + pos;
    while pos < end {
        let tag = aare[pos];
        pos += 1;
        let len = ber_len(aare, &mut pos);
        if tag == 0xbe {
            // association-data 28 <L>, then indirect-reference 02 01 <id>
            let mut inner = pos + 1;
            ber_len(aare, &mut inner);
            return (aare[inner..inner + 2] == [0x02, 0x01]).then(|| aare[inner + 2]);
        }
        pos += len;
    }
    None
}

/// Returns the AARE inside the CPA user data of an AC.
fn aare_of_cpa(cpa: &[u8]) -> Vec<u8> {
    let mut p = IsoPresentation::new();
    let r = iec61850_mms::iso::presentation::parse_accept(&mut p, cpa).expect("a CPA");
    r.payload(cpa).to_vec()
}

/// Sends `mms` in a Session data SPDU on presentation context `context_id`.
async fn send_on_context(cotp: &mut CotpConnection<TcpStream>, context_id: u8, mms: &[u8]) {
    let mut pres = IsoPresentation::new();
    pres.mms_context_id = context_id;
    let mut ppdu = BytesMut::new();
    encode_user_data(&pres, mms, &mut ppdu);
    let mut spdu = BytesMut::new();
    encode_data(&ppdu, &mut spdu);
    cotp.send_data(&spdu).await.unwrap();
}

/// The server answers on the presentation context identifiers the client chose
/// in its CP, including identifiers other than 1 and 3 and a pair that swaps
/// them: the AC completes the association, and an Identify and a Read are
/// answered on the client's MMS context.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn context_ids_chosen_by_the_client_are_used_for_every_pdu() {
    let handle = start_server().await;
    for (acse, mms) in [(5u8, 7u8), (3, 1), (1, 3)] {
        let mut cotp = connect_cotp(&handle).await;
        cotp.send_data(&cn(&cp_with_context_ids(acse, mms)))
            .await
            .unwrap();
        let (ind, cpa) = recv_spdu(&mut cotp).await.expect("an AC");
        assert_eq!(ind, SessionIndication::Accept, "contexts {acse}/{mms}");
        assert_eq!(
            aare_indirect_reference(&aare_of_cpa(&cpa)),
            Some(mms),
            "the AARE names the client's MMS context, contexts {acse}/{mms}"
        );

        // Identify, invokeID 1
        send_on_context(&mut cotp, mms, &[0xa0, 0x05, 0x02, 0x01, 0x01, 0x82, 0x00]).await;
        let (ind, ud) = recv_spdu(&mut cotp).await.expect("an identify response");
        assert_eq!(ind, SessionIndication::Data);
        let (ctx, body) = pdv(&ud);
        assert_eq!(ctx, mms, "contexts {acse}/{mms}");
        assert_eq!(
            body.first(),
            Some(&0xa1),
            "a confirmed response: {body:02x?}"
        );

        let mut read = BytesMut::new();
        encode_confirmed_read_request(
            2,
            &ReadRequest::single_domain("TESTLD0", "LLN0$DC$NamPlt$vendor"),
            &mut read,
        );
        send_on_context(&mut cotp, mms, &read).await;
        let (_, ud) = recv_spdu(&mut cotp).await.expect("a read response");
        let (ctx, body) = pdv(&ud);
        assert_eq!(ctx, mms, "contexts {acse}/{mms}");
        let (invoke_id, resp) = decode_confirmed_read_response(&body).expect("a read response");
        assert_eq!(invoke_id, 2);
        assert_eq!(
            resp.list_of_access_result,
            vec![iec61850_mms::AccessResult::Success(MmsData::VisibleString(
                "acme".into()
            ))]
        );
    }
    handle.stop().await;
}

/// What a Session REFUSE carried: its reason code, the provider-reason and
/// context results of the CPR inside it, and the context identifier and
/// payload of the CPR user data.
#[derive(Debug)]
struct Refusal {
    reason_code: Option<u8>,
    provider_reason: Option<u8>,
    results: Vec<u8>,
    user_data: Option<(u8, Vec<u8>)>,
}

/// Wraps the content of a CPR user-data field, its PDV list, back into a
/// Fully-Encoded-Data PPDU.
fn fully_encoded_data(pdv_list: &[u8]) -> Vec<u8> {
    let len = pdv_list.len();
    let mut out = vec![0x61];
    if len < 0x80 {
        out.push(len as u8);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(pdv_list);
    out
}

/// Reads the server's answer to a CN, expecting a Session REFUSE with a CPR as
/// its user data, and then the end of the connection.
async fn expect_refusal(cotp: &mut CotpConnection<TcpStream>) -> Refusal {
    let raw = tokio::time::timeout(Duration::from_secs(5), cotp.recv_data())
        .await
        .expect("the server answers in time")
        .expect("an answer to the CN");
    let mut s = IsoSession::new();
    let info = match s.parse_message(&raw).expect("the SPDU parses") {
        SessionIndication::Refuse(info) => info,
        other => panic!("expected a session REFUSE, got {other:?}: {raw:02x?}"),
    };
    let cpr_bytes = info.user_data(&raw).to_vec();
    let cpr = parse_reject(&cpr_bytes).expect("the REFUSE carries a CPR");
    let ud = cpr.user_data(&cpr_bytes);
    let refusal = Refusal {
        reason_code: info.reason_code,
        provider_reason: cpr.provider_reason,
        results: cpr.context_result_list.clone(),
        user_data: (!ud.is_empty()).then(|| pdv(&fully_encoded_data(ud))),
    };
    assert!(
        recv_spdu(cotp).await.is_none(),
        "the server closes the connection after the REFUSE"
    );
    refusal
}

/// An Initiate the server refuses, here proposing a 32-octet maximum PDU, is
/// answered with a Session REFUSE carrying a CPR, user rejection, whose user
/// data is an AARE with a rejected result and the Initiate-ErrorPDU as its user
/// information. The same CN proposing 64 octets is accepted with an AC.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_initiate_travels_in_an_aare_inside_a_cpr_and_a_refuse() {
    let handle = start_server().await;
    let refused = InitiateRequestPdu {
        local_detail_calling: Some(32),
        ..InitiateRequestPdu::default()
    };
    for mms in [3u8, 7] {
        let mut cp = cp_carrying(&initiate(&refused));
        patch(&mut cp, &MMS_ITEM, 2, mms);
        let mut cotp = connect_cotp(&handle).await;
        cotp.send_data(&cn(&cp)).await.unwrap();
        let refusal = expect_refusal(&mut cotp).await;
        assert_eq!(refusal.reason_code, Some(2), "{refusal:?}");
        assert_eq!(
            refusal.provider_reason, None,
            "a user rejection: {refusal:?}"
        );
        let (ctx, aare) = refusal.user_data.expect("the CPR carries the AARE");
        assert_eq!(ctx, 1, "the AARE travels on the ACSE context");
        assert_eq!(
            aare_indirect_reference(&aare),
            Some(mms),
            "the Initiate-ErrorPDU is named on the client's MMS context"
        );
        let mut acse = AcseConnection::new(None);
        let (ind, user_info) = acse.parse_message(&aare).expect("an AARE");
        assert_eq!(ind, AcseIndication::AssociateFailed);
        assert_eq!(user_info, [0xaa, 0x05, 0xa0, 0x03, 0x88, 0x01, 0x00]);
    }

    let accepted = InitiateRequestPdu {
        local_detail_calling: Some(64),
        ..InitiateRequestPdu::default()
    };
    let mut cotp = connect_cotp(&handle).await;
    cotp.send_data(&cn(&cp_carrying(&initiate(&accepted))))
        .await
        .unwrap();
    let (ind, _) = recv_spdu(&mut cotp).await.expect("an AC");
    assert_eq!(ind, SessionIndication::Accept);
    handle.stop().await;
}

/// An AARQ whose user information is not an Initiate request is refused the
/// same way, with an AARE that carries no user information.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aarq_without_an_initiate_is_refused_in_a_cpr_and_a_refuse() {
    let handle = start_server().await;
    // Identify, invokeID 1, in place of the Initiate request
    let mut cotp = connect_cotp(&handle).await;
    cotp.send_data(&cn(&cp_carrying(&[
        0xa0, 0x05, 0x02, 0x01, 0x01, 0x82, 0x00,
    ])))
    .await
    .unwrap();
    let refusal = expect_refusal(&mut cotp).await;
    assert_eq!(refusal.provider_reason, None, "{refusal:?}");
    let (ctx, aare) = refusal.user_data.expect("the CPR carries the AARE");
    assert_eq!(ctx, 1);
    let mut acse = AcseConnection::new(None);
    let (ind, user_info) = acse.parse_message(&aare).expect("an AARE");
    assert_eq!(ind, AcseIndication::AssociateFailed);
    assert!(user_info.is_empty());
    handle.stop().await;
}

const ACSE_OID: &[u8] = &[0x52, 0x01, 0x00, 0x01];
const MMS_OID: &[u8] = &[0x28, 0xca, 0x22, 0x02, 0x01];
const UNKNOWN_OID: &[u8] = &[0x2b, 0x06, 0x01];

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(content);
    out
}

/// Builds a CP proposing `contexts`, each a context identifier and an abstract
/// syntax offered with BER, and carrying the default AARQ on context 1.
fn cp_with_contexts(contexts: &[(u8, &[u8])]) -> Vec<u8> {
    let mut pcdl = Vec::new();
    for (id, oid) in contexts {
        let mut item = vec![0x02, 0x01, *id];
        item.extend(tlv(0x06, oid));
        item.extend(tlv(0x30, &tlv(0x06, &[0x51, 0x01])));
        pcdl.extend(tlv(0x30, &item));
    }
    let mut aarq = BytesMut::new();
    encode_aarq(
        &initiate(&InitiateRequestPdu::default()),
        None,
        3,
        &AarqAddressing::default(),
        &mut aarq,
    );
    let mut pdv = vec![0x02, 0x01, 0x01];
    pdv.extend(tlv(0xa0, &aarq));
    let mut nmp = vec![0x81, 0x00, 0x82, 0x00];
    nmp.extend(tlv(0xa4, &pcdl));
    nmp.extend(tlv(0x61, &tlv(0x30, &pdv)));
    let mut cp = vec![0xa0, 0x03, 0x80, 0x01, 0x01];
    cp.extend(tlv(0xa2, &nmp));
    tlv(0x31, &cp)
}

/// A context with an abstract syntax the server does not support is rejected
/// in its own result of the CPA, in the order of the CP, and the association
/// goes ahead on the ACSE and MMS contexts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsupported_context_is_rejected_in_the_cpa_alone() {
    let handle = start_server().await;
    let mut cotp = connect_cotp(&handle).await;
    cotp.send_data(&cn(&cp_with_contexts(&[
        (1, ACSE_OID),
        (5, UNKNOWN_OID),
        (3, MMS_OID),
    ])))
    .await
    .unwrap();
    let (ind, cpa) = recv_spdu(&mut cotp).await.expect("an AC");
    assert_eq!(ind, SessionIndication::Accept);
    let accept = [0x30, 0x07, 0x80, 0x01, 0x00, 0x81, 0x02, 0x51, 0x01];
    let mut results = vec![0xa5, 0x1a];
    results.extend_from_slice(&accept);
    results.extend_from_slice(&[0x30, 0x06, 0x80, 0x01, 0x02, 0x82, 0x01, 0x01]);
    results.extend_from_slice(&accept);
    assert!(
        cpa.windows(results.len()).any(|w| w == results),
        "the CPA answers each context in order: {cpa:02x?}"
    );

    send_on_context(&mut cotp, 3, &[0xa0, 0x05, 0x02, 0x01, 0x01, 0x82, 0x00]).await;
    let (_, ud) = recv_spdu(&mut cotp).await.expect("an identify response");
    assert_eq!(pdv(&ud).0, 3);
    handle.stop().await;
}

/// A CP without an MMS context is refused by the presentation provider: a
/// Session REFUSE carrying a CPR with provider-reason 0 and the result of the
/// one context proposed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cp_without_an_mms_context_is_refused_by_the_provider() {
    let handle = start_server().await;
    let mut cotp = connect_cotp(&handle).await;
    cotp.send_data(&cn(&cp_with_contexts(&[(1, ACSE_OID), (5, UNKNOWN_OID)])))
        .await
        .unwrap();
    let refusal = expect_refusal(&mut cotp).await;
    assert_eq!(refusal.reason_code, Some(2), "{refusal:?}");
    assert_eq!(refusal.provider_reason, Some(0), "{refusal:?}");
    assert_eq!(refusal.results, vec![0, 2], "{refusal:?}");
    assert!(refusal.user_data.is_none(), "{refusal:?}");
    handle.stop().await;
}

// ── Release ─────────────────────────────────────────────────────────────

/// An ACSE RLRQ on presentation context `acse` inside a session FINISH.
fn finish_with_rlrq(acse: u8) -> Vec<u8> {
    let mut rlrq = [0u8; 5];
    encode_rlrq(&mut rlrq);
    let mut pres = IsoPresentation::new();
    pres.acse_context_id = acse;
    let mut ppdu = BytesMut::new();
    encode_user_data_acse(&pres, &rlrq, &mut ppdu);
    let mut spdu = BytesMut::new();
    encode_finish(&ppdu, &mut spdu).unwrap();
    spdu.to_vec()
}

/// Concludes an association opened with `cotp`, MMS on context `mms`, and
/// checks the Conclude response.
async fn conclude(cotp: &mut CotpConnection<TcpStream>, mms: u8) {
    send_on_context(cotp, mms, &[0x8b, 0x00]).await;
    let (ind, ud) = recv_spdu(cotp).await.expect("a conclude response");
    assert_eq!(ind, SessionIndication::Data);
    assert_eq!(pdv(&ud), (mms, vec![0x8c, 0x00]));
}

/// Reads every SPDU until the server closes the connection.
async fn drain(cotp: &mut CotpConnection<TcpStream>) -> Vec<(SessionIndication, Vec<u8>)> {
    let mut seen = Vec::new();
    while let Some(spdu) = recv_spdu(cotp).await {
        seen.push(spdu);
    }
    seen
}

/// After a Conclude the server sends nothing of its own; a FINISH carrying an
/// RLRQ on the client's ACSE context is answered with a DISCONNECT carrying an
/// RLRE on that context, and the server closes the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finish_with_rlrq_is_answered_with_rlre_in_a_disconnect() {
    let handle = start_server().await;
    for (acse, mms) in [(1u8, 3u8), (5, 7)] {
        let mut cotp = connect_cotp(&handle).await;
        cotp.send_data(&cn(&cp_with_context_ids(acse, mms)))
            .await
            .unwrap();
        recv_spdu(&mut cotp).await.expect("an AC");
        conclude(&mut cotp, mms).await;

        cotp.send_data(&finish_with_rlrq(acse)).await.unwrap();
        let seen = drain(&mut cotp).await;
        assert_eq!(seen.len(), 1, "one SPDU answers the FINISH: {seen:02x?}");
        let (ind, ud) = &seen[0];
        assert_eq!(*ind, SessionIndication::Disconnect);
        assert_eq!(
            pdv(ud),
            (acse, vec![0x63, 0x00]),
            "an RLRE on the ACSE context"
        );
    }
    handle.stop().await;
}

/// An RLRQ in a data transfer is a protocol error: the server answers with a
/// session ABORT and closes the connection, sending no RLRE.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rlrq_in_a_data_transfer_is_aborted() {
    let handle = start_server().await;
    let mut cotp = connect_cotp(&handle).await;
    cotp.send_data(&cn(&cp())).await.unwrap();
    recv_spdu(&mut cotp).await.expect("an AC");
    conclude(&mut cotp, 3).await;

    let mut rlrq = [0u8; 5];
    encode_rlrq(&mut rlrq);
    let mut ppdu = BytesMut::new();
    encode_user_data_acse(&IsoPresentation::new(), &rlrq, &mut ppdu);
    let mut spdu = BytesMut::new();
    encode_data(&ppdu, &mut spdu);
    cotp.send_data(&spdu).await.unwrap();

    let seen = drain_raw(&mut cotp).await;
    assert_eq!(seen.len(), 1, "{seen:02x?}");
    assert_eq!(seen[0][0], 0x19, "a session ABORT: {seen:02x?}");
    assert_eq!(abrt_source(&seen[0]), Some(1), "a provider abort");
    handle.stop().await;
}

/// A FINISH without an RLRQ is a protocol error answered with a session ABORT.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finish_without_rlrq_is_aborted() {
    let handle = start_server().await;
    let mut cotp = connect_cotp(&handle).await;
    cotp.send_data(&cn(&cp())).await.unwrap();
    recv_spdu(&mut cotp).await.expect("an AC");
    conclude(&mut cotp, 3).await;

    let mut spdu = BytesMut::new();
    encode_finish(&[], &mut spdu).unwrap();
    cotp.send_data(&spdu).await.unwrap();

    let seen = drain_raw(&mut cotp).await;
    assert_eq!(seen.len(), 1, "{seen:02x?}");
    assert_eq!(seen[0][0], 0x19, "a session ABORT: {seen:02x?}");
    assert_eq!(abrt_source(&seen[0]), Some(1), "a provider abort");
    handle.stop().await;
}

/// Returns the abort-source of the ACSE ABRT inside a session ABORT.
fn abrt_source(spdu: &[u8]) -> Option<u8> {
    let at = spdu
        .windows(4)
        .position(|w| w == [0x64, 0x03, 0x80, 0x01])?;
    spdu.get(at + 4).copied()
}

/// Reads every TSDU, unparsed, until the server closes the connection.
async fn drain_raw(cotp: &mut CotpConnection<TcpStream>) -> Vec<Vec<u8>> {
    let mut seen = Vec::new();
    loop {
        let r = tokio::time::timeout(Duration::from_secs(5), cotp.recv_data())
            .await
            .expect("the server answers or closes in time");
        match r {
            Ok(raw) => seen.push(raw.to_vec()),
            Err(_) => return seen,
        }
    }
}

/// An abort the server application requests names the ACSE service user as
/// its source; the protocol errors above name the service provider.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requested_abort_names_the_user_as_its_source() {
    let server = IedServer::builder()
        .model(model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig::default())
        .build()
        .expect("build server");
    let handle = server.start().await.expect("start server");
    let mut cotp = connect_cotp(&handle).await;
    cotp.send_data(&cn(&cp())).await.unwrap();
    recv_spdu(&mut cotp).await.expect("an AC");
    // An answered request means the association is registered with the server.
    send_on_context(&mut cotp, 3, &[0xa0, 0x05, 0x02, 0x01, 0x01, 0x82, 0x00]).await;
    recv_spdu(&mut cotp).await.expect("an identify response");
    assert_eq!(server.abort_all_connections(), 1);

    let seen = drain_raw(&mut cotp).await;
    assert_eq!(seen.len(), 1, "{seen:02x?}");
    assert_eq!(seen[0][0], 0x19, "a session ABORT: {seen:02x?}");
    assert_eq!(abrt_source(&seen[0]), Some(0), "a user abort");
    handle.stop().await;
}

/// Every TPKT a proxy forwarded, in each direction, and whether the server
/// side has closed.
#[derive(Default)]
struct Recorded {
    to_server: Vec<Vec<u8>>,
    to_client: Vec<Vec<u8>>,
    server_closed: bool,
}

async fn read_tpkt(s: &mut tokio::net::tcp::OwnedReadHalf) -> Option<Vec<u8>> {
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await.ok()?;
    let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    let mut frame = hdr.to_vec();
    frame.resize(len.max(4), 0);
    s.read_exact(&mut frame[4..]).await.ok()?;
    Some(frame)
}

/// Starts a one-shot TPKT proxy to `upstream` that records every frame.
async fn start_recording_proxy(upstream: SocketAddr) -> (u16, Arc<Mutex<Recorded>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let rec = Arc::new(Mutex::new(Recorded::default()));
    let rec_task = Arc::clone(&rec);
    tokio::spawn(async move {
        let (client, _) = listener.accept().await.unwrap();
        let server = TcpStream::connect(upstream).await.unwrap();
        let (mut cr, mut cw) = client.into_split();
        let (mut sr, mut sw) = server.into_split();
        let rec_c2s = Arc::clone(&rec_task);
        tokio::spawn(async move {
            while let Some(f) = read_tpkt(&mut cr).await {
                rec_c2s.lock().unwrap().to_server.push(f.clone());
                if sw.write_all(&f).await.is_err() {
                    break;
                }
            }
            let _ = sw.shutdown().await;
        });
        while let Some(f) = read_tpkt(&mut sr).await {
            rec_task.lock().unwrap().to_client.push(f.clone());
            if cw.write_all(&f).await.is_err() {
                break;
            }
        }
        rec_task.lock().unwrap().server_closed = true;
        let _ = cw.shutdown().await;
    });
    (port, rec)
}

/// The SPDUs of the COTP data TPDUs among `frames`, each with its user data.
fn spdus(frames: &[Vec<u8>]) -> Vec<(SessionIndication, Vec<u8>)> {
    frames
        .iter()
        .filter(|f| f.len() > 7 && f[5] == 0xf0)
        .map(|f| {
            let mut s = IsoSession::new();
            let ind = s.parse_message(&f[7..]).expect("the SPDU parses");
            (ind, s.user_data(&f[7..]).to_vec())
        })
        .collect()
}

/// The iec61850-mms client releasing an association with the server, recorded
/// at the TPKT level: Conclude request, Conclude response, FINISH with RLRQ,
/// DISCONNECT with RLRE, and the server closes the connection. The server
/// sends no FINISH of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_release_is_conclude_then_finish_and_disconnect() {
    let handle = start_server().await;
    let (port, rec) = start_recording_proxy(handle.bound_addr).await;
    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(2_000)
        .request_timeout_ms(2_000)
        .build();
    client.connect("127.0.0.1", port).await.expect("connect");
    client.disconnect().await.expect("release");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !rec.lock().unwrap().server_closed && tokio::time::Instant::now() < deadline {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let (up, down) = {
        let rec = rec.lock().unwrap();
        assert!(rec.server_closed, "the server closes after the release");
        (spdus(&rec.to_server), spdus(&rec.to_client))
    };
    let up_tail = &up[up.len() - 2..];
    let down_tail = &down[down.len() - 2..];

    assert_eq!(up_tail[0].0, SessionIndication::Data);
    assert_eq!(
        pdv(&up_tail[0].1),
        (3, vec![0x8b, 0x00]),
        "conclude request"
    );
    assert_eq!(up_tail[1].0, SessionIndication::Finish);
    let (ctx, rlrq) = pdv(&up_tail[1].1);
    assert_eq!((ctx, rlrq.first()), (1, Some(&0x62)), "RLRQ: {rlrq:02x?}");

    assert_eq!(down_tail[0].0, SessionIndication::Data);
    assert_eq!(
        pdv(&down_tail[0].1),
        (3, vec![0x8c, 0x00]),
        "conclude response"
    );
    assert_eq!(down_tail[1].0, SessionIndication::Disconnect);
    assert_eq!(pdv(&down_tail[1].1), (1, vec![0x63, 0x00]), "RLRE");
    assert!(
        !down
            .iter()
            .any(|(ind, _)| *ind == SessionIndication::Finish),
        "the server sent a FINISH: {down:02x?}"
    );
    handle.stop().await;
}
