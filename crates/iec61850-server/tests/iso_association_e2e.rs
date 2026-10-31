//! The ISO upper layers of an association over real TCP: raw COTP, Session,
//! Presentation and ACSE PDUs against the server, checking the presentation
//! context identifiers it answers on.

use bytes::BytesMut;
use iec61850_mms::iso::acse::encode_aarq;
use iec61850_mms::iso::cotp::{CotpConnection, CotpOptions};
use iec61850_mms::iso::presentation::{
    encode_connect as pres_encode_connect, encode_user_data, parse_user_data, IsoPresentation,
    PresentationConnectionParameters,
};
use iec61850_mms::iso::session::{
    encode_connect as sess_encode_connect, encode_data, IsoParameters, IsoSession,
    SessionIndication,
};
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
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

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

/// Encodes the default CP carrying an AARQ with the default Initiate request.
fn cp() -> Vec<u8> {
    let mut initiate = BytesMut::new();
    InitiateRequestPdu::default().encode(&mut initiate);
    let mut aarq = BytesMut::new();
    encode_aarq(&initiate, None, 3, &AarqAddressing::default(), &mut aarq);
    let mut cp = BytesMut::new();
    pres_encode_connect(&PresentationConnectionParameters::default(), &aarq, &mut cp);
    cp.to_vec()
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
