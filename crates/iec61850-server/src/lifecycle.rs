//! TCP listener, accept loop, and the per-association ISO and MMS state
//! machine.
//!
//! `IedServer::start` binds a listener and spawns the accept loop and the
//! periodic tick loop; `ServerHandle::stop` signals both to exit and marks
//! every open association for abort.
//!
//! Each accepted connection runs COTP CR/CC, Session CN/AC, Presentation
//! CP/CPA, ACSE AARQ/AARE, and MMS Initiate negotiation, and then dispatches
//! confirmed requests until the peer concludes, the server aborts, or a layer
//! fails to parse.
//!
//! Behavior a peer can rely on:
//!
//! - A connection beyond `max_mms_connections` has its socket closed with no
//!   COTP disconnect-request.
//! - An Initiate the server refuses is answered with an ACSE AARE reject before
//!   the socket closes, so the client learns why rather than seeing a bare
//!   disconnect.
//! - An abort sends an ACSE A-ABORT, wrapped in a Session abort and a COTP data
//!   TPDU, before the socket closes.
//! - After answering a Conclude the server waits for the Session finish for a
//!   bounded time, 10 seconds by default, and then closes the socket itself.
//! - An AARQ that fails authentication is answered with an AARE carrying a
//!   rejected result.

use crate::control::{ConnectionTerminationEvent, ControlAddCause, ControlLastApplError};
use crate::error::Result;
use crate::server::IedServer;
use crate::ConnectionId;
use bytes::{Bytes, BytesMut};
use iec61850_mms::error::CotpError;
use iec61850_mms::iso::acse::{
    encode_aare, encode_abrt, encode_associate_failed, encode_rlre, AcseConnection, AcseError,
    AcseIndication,
};
use iec61850_mms::iso::cotp::{CotpConnection, CotpOptions};
use iec61850_mms::iso::presentation::{
    encode_abort as pres_encode_abort, encode_cpa, encode_user_data, encode_user_data_acse,
    parse_connect as pres_parse_connect, parse_user_data, IsoPresentation, PresentationError,
    ACSE_CONTEXT_ID, MMS_CONTEXT_ID,
};
use iec61850_mms::iso::session::{
    encode_abort as sess_encode_abort, encode_accept as sess_encode_accept, encode_data,
    encode_finish, IsoSession, SessionError, SessionIndication,
};
use iec61850_mms::mms::pdu::information_report::{
    encode_command_termination_negative, encode_command_termination_positive, LastApplErrorRef,
    OriginRef,
};
use iec61850_mms::mms::server::{parse_message, MessageOutcome, MmsServerConnection};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};

use crate::connection::ClientConnection;

/// Handle to a running server, returned by `IedServer::start`.
#[derive(Debug)]
pub struct ServerHandle {
    shutdown_tx: watch::Sender<bool>,
    accept_join: tokio::task::JoinHandle<()>,
    /// The loop that drives the reporting engine.
    tick_join: tokio::task::JoinHandle<()>,
    /// Address the listener is actually bound to, which is the assigned port
    /// when the caller asked for port 0.
    pub bound_addr: std::net::SocketAddr,
    /// Kept so that `stop` can mark the open associations for abort.
    server: IedServer,
}

impl ServerHandle {
    /// Shuts the server down: the accept and tick loops are told to exit, every
    /// open association is marked for abort so its task sends an A-ABORT and
    /// closes its socket, and both loops are awaited.
    pub async fn stop(self) {
        let _ = self.shutdown_tx.send(true);
        self.server.abort_all_connections();
        let _ = self.accept_join.await;
        let _ = self.tick_join.await;
    }
}

impl IedServer {
    /// Binds the listener and starts the accept and tick loops.
    ///
    /// One access point is supported.
    ///
    /// # Errors
    ///
    /// Returns the socket error when the address cannot be bound.
    pub async fn start(&self) -> Result<ServerHandle> {
        let listener = TcpListener::bind(self.bind_addr()).await?;
        let bound_addr = listener.local_addr()?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let shutdown_rx2 = shutdown_tx.subscribe();

        let server_for_loop = self.clone();
        let server_for_tick = self.clone();
        self.set_running(true);

        let accept_join = tokio::spawn(async move {
            run_accept_loop(server_for_loop, listener, shutdown_rx).await;
        });

        let tick_join = tokio::spawn(async move {
            run_tick_loop(server_for_tick, shutdown_rx2).await;
        });

        Ok(ServerHandle {
            shutdown_tx,
            accept_join,
            tick_join,
            bound_addr,
            server: self.clone(),
        })
    }
}

/// Drives the reporting engine on a 1 ms interval.
///
/// Every tick advances the buffer time, integrity period, and general
/// interrogation timers of both the unbuffered and the buffered report control
/// blocks. Once per second it also releases expired buffered-report and setting
/// group reservations; an accumulated millisecond count carries that period, so
/// jitter in the 1 ms interval cannot skip a sweep.
///
/// A poisoned lock is logged and the loop continues: reporting stops working
/// but the rest of the server keeps serving.
async fn run_tick_loop(server: IedServer, mut shutdown_rx: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(1));
    let mut reservation_accum_ms: u32 = 0;
    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    tracing::debug!("tick loop received the shutdown signal");
                    break;
                }
            }
            _ = interval.tick() => {
                match server.reporting_engine().lock() {
                    Ok(engine) => {
                        let now = std::time::Instant::now();
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        engine.tick();
                        engine.tick_brcb(now, now_ms);
                        reservation_accum_ms = reservation_accum_ms.saturating_add(1);
                        if reservation_accum_ms >= 1000 {
                            reservation_accum_ms = 0;
                            engine.tick_brcb_reservations();
                            // The setting group registry takes its own write
                            // lock, so the engine lock is released first rather
                            // than nesting the two.
                            drop(engine);
                            let released = server.setting_groups().tick_reservations();
                            for (domain, owner) in released {
                                tracing::info!(
                                    domain,
                                    conn_id = owner,
                                    "setting group reservation expired, releasing the edit session"
                                );
                            }
                        }
                    }
                    Err(_) => {
                        tracing::warn!("tick loop: the reporting engine lock is poisoned, skipping this tick");
                    }
                }
            }
        }
    }
}

async fn run_accept_loop(
    server: IedServer,
    listener: TcpListener,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    tracing::debug!("accept loop received the shutdown signal");
                    break;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        if !server.can_accept_new() {
                            // D1 carry C [DECIDED 2026-04-25]
                            tracing::warn!(
                                ?peer,
                                count = server.connection_count(),
                                "connection limit reached, closing the socket without a disconnect-request"
                            );
                            drop(stream);
                            continue;
                        }
                        tracing::info!(?peer, "accepted a client connection");
                        let server_for_conn = server.clone();
                        // With a TLS acceptor configured, the handshake runs
                        // before COTP; otherwise the connection is plain TCP.
                        #[cfg(feature = "tls")]
                        {
                            if let Some(acceptor) = server.tls_acceptor().cloned() {
                                tokio::spawn(async move {
                                    match acceptor.accept(stream).await {
                                        Ok(tls_stream) => {
                                            handle_connection_inner(
                                                server_for_conn, tls_stream, peer,
                                            ).await;
                                        }
                                        Err(e) => {
                                            tracing::warn!(?peer, error = %e, "TLS handshake failed, closing the connection");
                                        }
                                    }
                                });
                            } else {
                                tokio::spawn(async move {
                                    handle_connection_inner(server_for_conn, stream, peer).await;
                                });
                            }
                        }
                        #[cfg(not(feature = "tls"))]
                        {
                            tokio::spawn(async move {
                                handle_connection_inner(server_for_conn, stream, peer).await;
                            });
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed");
                    }
                }
            }
        }
    }
    server.set_running(false);
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-connection state machine
// ─────────────────────────────────────────────────────────────────────────────

/// Failures from any layer of the stack, collected so the connection task can
/// propagate and log them in one place.
#[derive(Debug, thiserror::Error)]
enum ConnError {
    #[error("cotp error: {0}")]
    Cotp(#[from] CotpError),
    #[error("session error: {0}")]
    Session(#[from] SessionError),
    #[error("presentation error: {0}")]
    Presentation(#[from] PresentationError),
    #[error("acse error: {0}")]
    Acse(#[from] AcseError),
    #[error("acse association failed: authentication was refused or the result was non-zero")]
    AcseAssociationFailed,
    #[error("unexpected acse indication {0:?}: only associate is accepted while associating")]
    UnexpectedAcseIndication(AcseIndication),
    #[error("initiate-request was refused; the association was rejected and the socket closed")]
    InitiateRejected,
    #[error("unexpected session indication {0:?}")]
    UnexpectedSessionIndication(SessionIndication),
}

/// Runs one association from accept to close.
///
/// The stream is generic so that a plain TCP connection and a TLS connection
/// take the same path.
async fn handle_connection_inner<S>(server: IedServer, stream: S, peer: std::net::SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let conn_id = server.next_connection_id();
    tracing::debug!(conn_id, ?peer, "connection task started");

    match run_connection(server.clone(), stream, peer, conn_id).await {
        Ok(()) => {
            tracing::debug!(conn_id, ?peer, "connection closed normally");
        }
        Err(e) => {
            tracing::warn!(conn_id, ?peer, error = %e, "connection closed after an error");
        }
    }

    let _ = server.remove_connection(conn_id);
}

async fn run_connection<S>(
    server: IedServer,
    stream: S,
    peer: std::net::SocketAddr,
    conn_id: ConnectionId,
) -> std::result::Result<(), ConnError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // ── COTP: receive the connection request, send the confirm ──────────
    let cotp_opts = CotpOptions::default();
    let mut cotp = CotpConnection::accept(stream, cotp_opts).await?;
    tracing::debug!(
        conn_id,
        "COTP established with tpdu_size={}",
        cotp.tpdu_size()
    );

    // ── The first data TPDU carries Session CN, Presentation CP, ACSE
    //    AARQ, and the MMS Initiate all at once ────────────────────────
    let first_payload = cotp.recv_data().await?;
    let dispatcher = server.dispatcher();

    let mut session = IsoSession::new();
    match session.parse_message(&first_payload)? {
        SessionIndication::Connect => {}
        other => {
            tracing::warn!(
                conn_id,
                ?other,
                "the first PDU is not a session connect, refusing"
            );
            return Err(ConnError::UnexpectedSessionIndication(other));
        }
    }
    let cp_payload_range =
        session.user_data(&first_payload).as_ptr() as usize - first_payload.as_ptr() as usize;
    let cp_payload_len = session.user_data(&first_payload).len();
    let cp_bytes = &first_payload[cp_payload_range..cp_payload_range + cp_payload_len];

    let mut pres = IsoPresentation::new();
    let cp_result = pres_parse_connect(&mut pres, cp_bytes)?;
    // Copied out so that the presentation state can be borrowed mutably below.
    let aarq_bytes = cp_result.payload(cp_bytes).to_vec();

    let mut acse = AcseConnection::new(None);
    let (acse_ind, acse_user_data) = acse.parse_message(&aarq_bytes)?;
    match acse_ind {
        AcseIndication::Associate => {}
        AcseIndication::AssociateFailed => {
            tracing::warn!(
                conn_id,
                "acse authentication failed, sending a reject and closing the socket"
            );
            send_acse_only(&mut cotp, &mut session, &mut pres, encode_associate_failed).await?;
            return Err(ConnError::AcseAssociationFailed);
        }
        other => {
            tracing::warn!(
                conn_id,
                ?other,
                "the first acse PDU is not an associate request, refusing"
            );
            return Err(ConnError::UnexpectedAcseIndication(other));
        }
    }

    // The ACSE user information is the MMS Initiate PDU, tag 0xa8.
    let initiate_bytes: bytes::Bytes = bytes::Bytes::copy_from_slice(acse_user_data);
    let mut mms_conn = MmsServerConnection::new();
    let outcome = parse_message(&mms_conn, dispatcher.as_ref(), &initiate_bytes);

    match outcome {
        MessageOutcome::SendInitiateResponse {
            response_bytes,
            params,
        } => {
            mms_conn.set_negotiated(params);
            mms_conn.set_block_requests(server.connection_block_requests_default());
            // The dispatcher routes command terminations by this id.
            mms_conn.set_connection_id(conn_id);

            // The response is wrapped outwards: MMS, ACSE AARE, Presentation
            // CPA, Session AC, COTP data.
            let mut aare_buf = BytesMut::new();
            encode_aare(0, Some(&response_bytes), 3, &mut aare_buf);

            let mut cpa_buf = BytesMut::new();
            encode_cpa(&pres, &aare_buf, &mut cpa_buf);

            let mut sess_buf = BytesMut::new();
            sess_encode_accept(&session, &cpa_buf, &mut sess_buf)?;

            cotp.send_data(&sess_buf).await?;
            tracing::debug!(conn_id, "initiate negotiation complete");
        }
        MessageOutcome::SendInitiateErrorAndClose { error_bytes } => {
            // The association never completed, so a Session accept would be out
            // of order and the MMS InitiateError has no carrier. An ACSE AARE
            // reject without user information is sent instead, which tells the
            // client the association was refused rather than dropping it silently.
            tracing::warn!(
                conn_id,
                initiate_error_len = error_bytes.len(),
                "initiate refused, sending an associate reject and closing the socket"
            );
            send_acse_only(&mut cotp, &mut session, &mut pres, encode_associate_failed).await?;
            return Err(ConnError::InitiateRejected);
        }
        other => {
            tracing::warn!(
                conn_id,
                ?other,
                "unexpected outcome while establishing the association"
            );
            return Err(ConnError::InitiateRejected);
        }
    }

    // ── Register the association with the server ────────────────────────
    let client_conn = ClientConnection::new(conn_id, peer, mms_conn);
    server.add_connection(client_conn.clone());

    // ── Command terminations ────────────────────────────────────────────
    //
    // The control service posts a termination event to the sender registered
    // here; the loop below encodes it as an InformationReport and writes it.
    let ct_sink = server.ct_sink();
    let (ct_tx, mut ct_rx) = mpsc::unbounded_channel::<ConnectionTerminationEvent>();
    ct_sink.register(conn_id, ct_tx);

    // ── Reports ─────────────────────────────────────────────────────────
    //
    // The reporting engine posts an encoded report to the sender registered
    // here and the loop below writes it. The channel is bounded, so a slow
    // reader fills it and the engine sees the backpressure rather than growing
    // an unbounded queue.
    let report_sink = server.report_sink();
    let (rpt_tx, mut rpt_rx) = crate::reporting::sink::ChannelReportSink::create_channel();
    report_sink.register(conn_id, rpt_tx);

    // ── Dispatch loop ───────────────────────────────────────────────────
    //
    // Each iteration aborts when the association is marked for abort, gives up
    // when a concluded association has waited too long for the session finish,
    // and otherwise waits for a request, a command termination, or a report.
    let conclude_timeout = client_conn
        .with_mms(|m| m.conclude_timeout_ms())
        .unwrap_or(10_000);

    loop {
        // Polled rather than awaited, so no future is built per iteration.
        if client_conn.abort_requested() {
            tracing::warn!(
                conn_id,
                "association marked for abort, sending an abort and closing the socket"
            );
            send_acse_abort(&mut cotp, &mut session, &mut pres).await?;
            break;
        }

        let concluded = client_conn.with_mms(|m| m.is_concluded()).unwrap_or(false);
        let tick = if concluded {
            Duration::from_millis(conclude_timeout)
        } else {
            Duration::from_millis(200)
        };

        // The select is biased: a command termination is served first because a
        // control operation is already waiting on it, then a report, then a new
        // request from the socket.
        enum Step {
            Payload(Bytes),
            Continue,
            Break,
        }
        let step = tokio::select! {
            biased;
            ev = ct_rx.recv() => {
                match ev {
                    Some(event) => {
                        if let Err(e) = send_command_termination(
                            &mut cotp, &session, &pres, &event,
                        ).await {
                            tracing::warn!(conn_id, error = %e, "failed to send a command termination");
                            return Err(e);
                        }
                        Step::Continue
                    }
                    None => {
                        tracing::warn!(conn_id, "the command termination channel has closed");
                        Step::Continue
                    }
                }
            }
            ev = rpt_rx.recv() => {
                match ev {
                    Some(pdu) => {
                        if let Err(e) = send_user_data_mms(&mut cotp, &session, &pres, &pdu).await {
                            tracing::warn!(conn_id, error = %e, "failed to send a report");
                            return Err(e);
                        }
                        Step::Continue
                    }
                    None => {
                        tracing::warn!(conn_id, "the report channel has closed");
                        Step::Continue
                    }
                }
            }
            r = tokio::time::timeout(tick, cotp.recv_data()) => {
                match r {
                    Ok(Ok(payload)) => Step::Payload(payload),
                    Ok(Err(e)) => return Err(ConnError::from(e)),
                    Err(_) => {
                        if concluded {
                            tracing::warn!(
                                conn_id,
                                timeout_ms = conclude_timeout,
                                "no session finish arrived after the conclude, closing the socket"
                            );
                            Step::Break
                        } else {
                            Step::Continue
                        }
                    }
                }
            }
        };
        let payload = match step {
            Step::Payload(p) => p,
            Step::Continue => continue,
            Step::Break => break,
        };

        let mut local_session = session.clone();
        let sess_ind = match local_session.parse_message(&payload) {
            Ok(ind) => ind,
            Err(e) => {
                tracing::warn!(conn_id, error = %e, "session parse failed, closing the socket");
                break;
            }
        };
        match sess_ind {
            SessionIndication::Data => {
                // An ordinary MMS or ACSE PDU.
            }
            SessionIndication::Finish => {
                // The peer wants to finish; answer with a disconnect and close.
                tracing::debug!(
                    conn_id,
                    "session finish received, answering with a disconnect"
                );
                let mut dn = BytesMut::new();
                use iec61850_mms::iso::session::encode_disconnect;
                encode_disconnect(&[], &mut dn)?;
                cotp.send_data(&dn).await?;
                break;
            }
            SessionIndication::Abort => {
                tracing::debug!(conn_id, "session abort received, closing the socket");
                break;
            }
            SessionIndication::Disconnect => {
                tracing::debug!(conn_id, "session disconnect received, closing the socket");
                break;
            }
            other => {
                tracing::warn!(
                    conn_id,
                    ?other,
                    "unexpected session indication, closing the socket"
                );
                break;
            }
        }

        let mms_or_acse_payload = local_session.user_data(&payload).to_vec();

        let mut local_pres = pres.clone();
        let pres_result = match parse_user_data(&mut local_pres, &mms_or_acse_payload) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(conn_id, error = %e, "presentation parse failed, closing the socket");
                break;
            }
        };
        let inner_payload = pres_result.payload(&mms_or_acse_payload).to_vec();

        match pres_result.context_id {
            id if id == ACSE_CONTEXT_ID => {
                // On the ACSE context the peer is releasing or aborting.
                let mut local_acse = AcseConnection::new(None);
                let (acse_ind, _) = match local_acse.parse_message(&inner_payload) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(conn_id, error = %e, "acse parse failed, closing the socket");
                        break;
                    }
                };
                match acse_ind {
                    AcseIndication::ReleaseRequest => {
                        // The release response is followed by a session finish
                        // from the peer.
                        tracing::debug!(
                            conn_id,
                            "acse release request received, answering with a release response"
                        );
                        let mut rlre = [0u8; 2];
                        encode_rlre(&mut rlre);
                        send_user_data_acse(&mut cotp, &session, &pres, &rlre).await?;
                    }
                    AcseIndication::Abort => {
                        tracing::debug!(conn_id, "acse abort received, closing the socket");
                        break;
                    }
                    other => {
                        tracing::warn!(
                            conn_id,
                            ?other,
                            "unexpected indication on the acse context"
                        );
                        break;
                    }
                }
            }
            id if id == MMS_CONTEXT_ID => {
                let outcome = client_conn
                    .with_mms(|m| parse_message(m, dispatcher.as_ref(), &inner_payload))
                    .unwrap_or(MessageOutcome::Silent);

                match outcome {
                    MessageOutcome::SendBytes(bytes) => {
                        send_user_data_mms(&mut cotp, &session, &pres, &bytes).await?;
                    }
                    MessageOutcome::SendConcludeResponse { response_bytes } => {
                        send_user_data_mms(&mut cotp, &session, &pres, &response_bytes).await?;
                        // Starts the bounded wait for the session finish.
                        client_conn.with_mms_mut(|m| m.mark_concluded());
                        // The session finish tells the peer to close as well.
                        let mut fn_bytes = BytesMut::new();
                        encode_finish(&[], &mut fn_bytes)?;
                        cotp.send_data(&fn_bytes).await?;
                    }
                    MessageOutcome::SendInitiateErrorAndClose { error_bytes: _ } => {
                        tracing::warn!(conn_id, "a second initiate arrived on an established association, closing the socket");
                        break;
                    }
                    MessageOutcome::SendInitiateResponse { .. } => {
                        // Unreachable on an established association.
                        tracing::warn!(conn_id, "an initiate response was produced on an established association, closing the socket");
                        break;
                    }
                    MessageOutcome::Silent => {
                        // Nothing to send, as for a received Reject PDU.
                    }
                }
            }
            other => {
                tracing::warn!(
                    conn_id,
                    context_id = other,
                    "unknown presentation context id"
                );
                break;
            }
        }
    }

    let _ = (session, pres);

    // Release the command termination sender and any select this association
    // still holds.
    ct_sink.deregister(conn_id);
    server.control_objects().release_connection(conn_id);

    // Release the report sender and tell the engine the association is gone.
    report_sink.deregister(conn_id);
    if let Ok(engine) = server.reporting_engine().lock() {
        engine.on_connection_dropped(conn_id);
    } else {
        tracing::warn!(
            conn_id,
            "the reporting engine lock is poisoned, the association could not be deregistered from it"
        );
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Writing a PDU down through the stack
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes an ACSE PDU with the supplied callback and wraps it outwards through
/// Presentation CPA, Session accept, and a COTP data TPDU.
///
/// This is the path a refused Initiate and a failed authentication take, both
/// of which answer while the association is still being established.
async fn send_acse_only<S>(
    cotp: &mut CotpConnection<S>,
    session: &mut IsoSession,
    pres: &mut IsoPresentation,
    encode_acse: impl FnOnce(&mut BytesMut),
) -> std::result::Result<(), ConnError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut acse_buf = BytesMut::new();
    encode_acse(&mut acse_buf);

    let mut cpa_buf = BytesMut::new();
    encode_cpa(pres, &acse_buf, &mut cpa_buf);

    let mut sess_buf = BytesMut::new();
    sess_encode_accept(session, &cpa_buf, &mut sess_buf)?;

    cotp.send_data(&sess_buf).await?;
    Ok(())
}

/// Wraps an MMS PDU as presentation user data, a session data TPDU, and a COTP
/// data TPDU, and writes it.
async fn send_user_data_mms<S>(
    cotp: &mut CotpConnection<S>,
    session: &IsoSession,
    pres: &IsoPresentation,
    mms_bytes: &[u8],
) -> std::result::Result<(), ConnError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut pres_buf = BytesMut::new();
    encode_user_data(pres, mms_bytes, &mut pres_buf);

    let mut sess_buf = BytesMut::new();
    encode_data(&pres_buf, &mut sess_buf);
    // Sending user data leaves the session state unchanged.
    let _ = session;

    cotp.send_data(&sess_buf).await?;
    Ok(())
}

/// Wraps an ACSE PDU as presentation user data on the ACSE context, a session
/// data TPDU, and a COTP data TPDU, and writes it.
async fn send_user_data_acse<S>(
    cotp: &mut CotpConnection<S>,
    session: &IsoSession,
    pres: &IsoPresentation,
    acse_bytes: &[u8],
) -> std::result::Result<(), ConnError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut pres_buf = BytesMut::new();
    encode_user_data_acse(pres, acse_bytes, &mut pres_buf);

    let mut sess_buf = BytesMut::new();
    encode_data(&pres_buf, &mut sess_buf);
    let _ = session;

    cotp.send_data(&sess_buf).await?;
    Ok(())
}

/// Encodes a command termination as an InformationReport and writes it.
///
/// The event carries the object reference `<LD>/<LN>$CO$<DO>` and the encoded
/// Oper structure the client sent. A positive termination reports one variable,
/// `<LN>$CO$<DO>$Oper`, carrying that structure; a negative one reports
/// `LastApplError` first and the structure second.
async fn send_command_termination<S>(
    cotp: &mut CotpConnection<S>,
    session: &IsoSession,
    pres: &IsoPresentation,
    event: &ConnectionTerminationEvent,
) -> std::result::Result<(), ConnError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (domain_id, item_id) = match event {
        ConnectionTerminationEvent::Positive { obj_ref, .. } => parse_obj_ref_to_oper(obj_ref),
        ConnectionTerminationEvent::Negative { obj_ref, .. } => parse_obj_ref_to_oper(obj_ref),
    };

    let pdu_bytes = match event {
        ConnectionTerminationEvent::Positive {
            obj_ref,
            oper_value,
        } => {
            tracing::debug!(
                obj_ref,
                oper_len = oper_value.len(),
                "sending a positive command termination"
            );
            encode_command_termination_positive(&domain_id, &item_id, oper_value.clone())
        }
        ConnectionTerminationEvent::Negative {
            obj_ref,
            add_cause,
            oper_value,
        } => {
            tracing::debug!(
                obj_ref,
                ?add_cause,
                oper_len = oper_value.len(),
                "sending a negative command termination"
            );
            let last_err = LastApplErrorRef {
                ctl_obj: format!("{}/{}", domain_id, item_id),
                error: ControlLastApplError::OperationFailed as i32,
                origin: OriginRef::default(),
                ctl_num: 0,
                add_cause: cause_to_i32(*add_cause),
            };
            encode_command_termination_negative(&last_err, &domain_id, &item_id, oper_value.clone())
        }
    };

    send_user_data_mms(cotp, session, pres, &pdu_bytes).await
}

/// Splits an object reference into an MMS domain and item, naming the `Oper`
/// attribute: `IED1LD0/GGIO1$CO$SPCSO1` becomes `("IED1LD0",
/// "GGIO1$CO$SPCSO1$Oper")`.
fn parse_obj_ref_to_oper(obj_ref: &str) -> (String, String) {
    let mut parts = obj_ref.splitn(2, '/');
    let domain = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let item = if path.is_empty() {
        "Oper".to_string()
    } else {
        format!("{}$Oper", path)
    };
    (domain, item)
}

/// Returns the wire value of a control add-cause.
fn cause_to_i32(c: ControlAddCause) -> i32 {
    c as i32
}

/// Sends an ACSE A-ABORT with the provider as its source, wrapped outwards
/// through a presentation abort, a session abort, and a COTP data TPDU.
async fn send_acse_abort<S>(
    cotp: &mut CotpConnection<S>,
    _session: &mut IsoSession,
    pres: &mut IsoPresentation,
) -> std::result::Result<(), ConnError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut abrt = [0u8; 5];
    encode_abrt(true, &mut abrt);

    let mut pres_buf = BytesMut::new();
    pres_encode_abort(pres, &abrt, &mut pres_buf);

    let mut sess_buf = BytesMut::new();
    sess_encode_abort(&pres_buf, &mut sess_buf)?;

    cotp.send_data(&sess_buf).await?;
    Ok(())
}
