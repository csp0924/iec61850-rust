//! A scripted MMS server over real TCP and the full ISO stack, for end-to-end
//! tests that need a peer to answer in a way the crate's own server does not.
//!
//! The association is accepted with the ISO and MMS building blocks of
//! `iec61850-mms`. Each later request goes to a script, which returns the PDUs
//! to send ahead of the response, the response, and the PDUs to send after it.
//! A request the script does not handle is answered with a Reject.

#![allow(dead_code)]

use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use iec61850_mms::iso::acse::{encode_aare, AcseConnection, AcseIndication};
use iec61850_mms::iso::cotp::{CotpConnection, CotpOptions};
use iec61850_mms::iso::presentation::{
    encode_cpa, encode_user_data, parse_connect, parse_user_data, IsoPresentation,
};
use iec61850_mms::iso::session::{encode_accept, encode_data, IsoSession, SessionIndication};
use iec61850_mms::mms::server::{
    parse_message, MessageOutcome, MmsServerConnection, RejectAllDispatcher,
};
use iec61850_mms::{ObjectName, VariableAccessSpecification};
use tokio::net::{TcpListener, TcpStream};

/// What the scripted server sends for one request, in order.
#[derive(Default)]
pub struct Plan {
    /// PDUs sent ahead of the response.
    pub before: Vec<Bytes>,
    /// The response, or `None` to leave the request unanswered.
    pub reply: Option<Bytes>,
    /// PDUs sent after the response.
    pub after: Vec<Bytes>,
    /// Close the connection instead of answering.
    pub close: bool,
}

impl Plan {
    /// A plan that sends only `reply`.
    pub fn reply(reply: Bytes) -> Self {
        Self {
            reply: Some(reply),
            ..Self::default()
        }
    }
}

/// Answers one request: the raw MMS PDU and its 1-based position on the
/// association. `None` leaves the request to the default Reject.
pub type Script = dyn Fn(&[u8], u32) -> Option<Plan> + Send + Sync;

/// Starts a scripted server on 127.0.0.1 and returns its port.
pub async fn start(script: Arc<Script>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(serve(stream, Arc::clone(&script)));
        }
    });
    port
}

/// Returns the item id of a request that names one domain-specific variable.
pub fn single_item(spec: &VariableAccessSpecification) -> Option<String> {
    match spec {
        VariableAccessSpecification::ListOfVariable(entries) => match entries.as_slice() {
            [entry] => match &entry.name {
                ObjectName::DomainSpecific { item_id, .. } => Some(item_id.clone()),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

/// Appends a BER tag and definite length followed by `content`.
pub fn tlv(tag: u8, content: &[u8], out: &mut BytesMut) {
    out.extend_from_slice(&[tag]);
    let n = content.len();
    if n < 0x80 {
        out.extend_from_slice(&[n as u8]);
    } else if n <= 0xff {
        out.extend_from_slice(&[0x81, n as u8]);
    } else {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(content);
}

/// Wraps an MMS PDU in Presentation user data and a Session data SPDU, and
/// sends it as one COTP data TPDU.
async fn send_mms(
    cotp: &mut CotpConnection<TcpStream>,
    pres: &IsoPresentation,
    pdu: &[u8],
) -> bool {
    let mut pres_buf = BytesMut::new();
    encode_user_data(pres, pdu, &mut pres_buf);
    let mut sess_buf = BytesMut::new();
    encode_data(&pres_buf, &mut sess_buf);
    cotp.send_data(&sess_buf).await.is_ok()
}

/// Accepts one association: COTP, Session, Presentation, ACSE and the MMS
/// Initiate, all answered positively.
async fn accept_association(
    stream: TcpStream,
) -> Option<(
    CotpConnection<TcpStream>,
    IsoSession,
    IsoPresentation,
    MmsServerConnection,
)> {
    let mut cotp = CotpConnection::accept(stream, CotpOptions::default())
        .await
        .ok()?;
    let first = cotp.recv_data().await.ok()?;
    let mut session = IsoSession::new();
    if !matches!(
        session.parse_message(&first).ok()?,
        SessionIndication::Connect
    ) {
        return None;
    }
    let cp_bytes = session.user_data(&first).to_vec();
    let mut pres = IsoPresentation::new();
    let cp = parse_connect(&mut pres, &cp_bytes).ok()?;
    let aarq = cp.payload(&cp_bytes).to_vec();
    let mut acse = AcseConnection::new(None);
    let (ind, initiate) = acse.parse_message(&aarq).ok()?;
    if !matches!(ind, AcseIndication::Associate) {
        return None;
    }
    let initiate = initiate.to_vec();
    let mut mms_conn = MmsServerConnection::new();
    let MessageOutcome::SendInitiateResponse {
        response_bytes,
        params,
        ..
    } = parse_message(&mms_conn, &RejectAllDispatcher, &initiate)
    else {
        return None;
    };
    mms_conn.set_negotiated(params);
    let mut aare = BytesMut::new();
    encode_aare(0, Some(&response_bytes), 3, &mut aare);
    let mut cpa = BytesMut::new();
    encode_cpa(&pres, &aare, &mut cpa);
    let mut sess = BytesMut::new();
    encode_accept(&session, &cpa, &mut sess).ok()?;
    cotp.send_data(&sess).await.ok()?;
    Some((cotp, session, pres, mms_conn))
}

/// Serves one association, answering each request from `script`.
async fn serve(stream: TcpStream, script: Arc<Script>) {
    let Some((mut cotp, session, mut pres, mms_conn)) = accept_association(stream).await else {
        return;
    };
    let mut seq: u32 = 0;
    loop {
        let Ok(payload) = cotp.recv_data().await else {
            return;
        };
        let mut local_session = session.clone();
        if !matches!(
            local_session.parse_message(&payload),
            Ok(SessionIndication::Data)
        ) {
            return;
        }
        let user_data = local_session.user_data(&payload).to_vec();
        let Ok(pres_result) = parse_user_data(&mut pres, &user_data) else {
            return;
        };
        let mms = pres_result.payload(&user_data).to_vec();
        seq += 1;

        let plan = match script(&mms, seq) {
            Some(plan) => plan,
            None => match parse_message(&mms_conn, &RejectAllDispatcher, &mms) {
                MessageOutcome::SendBytes(b) => Plan::reply(b),
                MessageOutcome::SendConcludeResponse { response_bytes, .. } => {
                    Plan::reply(response_bytes)
                }
                _ => Plan::default(),
            },
        };
        if plan.close {
            return;
        }
        for pdu in plan
            .before
            .iter()
            .chain(plan.reply.iter())
            .chain(plan.after.iter())
        {
            if !send_mms(&mut cotp, &pres, pdu).await {
                return;
            }
        }
    }
}
