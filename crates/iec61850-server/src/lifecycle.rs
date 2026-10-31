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
//!   COTP disconnect-request. A connection counts from accept, before it has
//!   associated, until its socket closes.
//! - A connection that has not completed the TLS handshake, if TLS is
//!   configured, and association setup through the MMS Initiate response within
//!   `association_setup_timeout_ms` is closed.
//! - An Initiate the server refuses is answered with an ACSE AARE reject before
//!   the socket closes, so the client learns why rather than seeing a bare
//!   disconnect.
//! - An abort sends an ACSE A-ABORT, wrapped in a Session abort and a COTP data
//!   TPDU, before the socket closes.
//! - Once the Initiate exchange completes, a TSDU larger than the negotiated
//!   maximum PDU size plus 8192 bytes of envelope closes the connection.
//! - An association that neither receives nor sends a PDU for
//!   `association_idle_timeout_ms`, 300 000 ms by default, is aborted.
//! - A PDU the peer does not accept within `association_send_timeout_ms`,
//!   10 000 ms by default, ends the connection without a further write.
//! - After answering a Conclude the server waits for the Session finish for a
//!   bounded time, 10 seconds by default, and then closes the socket itself.
//! - An AARQ that fails authentication is answered with an AARE carrying a
//!   rejected result.
//! - However the connection ends, including a transport error, the
//!   association's URCB reservations, control selects and setting group edit
//!   session are released as the connection task ends. A BRCB the association
//!   enabled is disabled and keeps buffering; a BRCB it reserved stays reserved
//!   for the same client address until its ResvTms expires.

use crate::control::{ConnectionTerminationEvent, ControlAddCause};
use crate::error::Result;
use crate::server::IedServer;
use crate::ConnectionId;
use bytes::{Bytes, BytesMut};
use iec61850_mms::error::CotpError;
use iec61850_mms::iso::acse::{
    encode_aare, encode_abrt, encode_associate_failed, encode_rlre, AcseConnection, AcseError,
    AcseIndication,
};
use iec61850_mms::iso::cotp::{CotpConnection, CotpOptions, DEFAULT_MAX_TSDU_SIZE};
use iec61850_mms::iso::presentation::{
    encode_abort as pres_encode_abort, encode_cpa, encode_user_data, encode_user_data_acse,
    parse_connect as pres_parse_connect, parse_user_data, IsoPresentation, PresentationError,
};
use iec61850_mms::iso::session::{
    encode_abort as sess_encode_abort, encode_accept as sess_encode_accept, encode_data,
    encode_finish, IsoSession, SessionError, SessionIndication,
};
use iec61850_mms::mms::pdu::common::WriteOutcome;
use iec61850_mms::mms::pdu::information_report::{
    encode_command_termination_negative, encode_command_termination_positive, LastApplErrorRef,
    OriginRef,
};
use iec61850_mms::mms::pdu::write::{
    decode_confirmed_write_response, encode_confirmed_write_response, WriteResponse,
};
use iec61850_mms::mms::server::{
    parse_message, MessageOutcome, MmsServerConnection, MmsServiceDispatcher,
};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};

use crate::connection::ClientConnection;

/// Tag of the MMS Initiate-RequestPDU, the only PDU an AARQ may carry.
const MMS_INITIATE_REQUEST_TAG: u8 = 0xa8;

/// Room a TSDU leaves around one MMS PDU for its Session, Presentation and
/// ACSE envelope: the margin `DEFAULT_MAX_TSDU_SIZE` adds to the default
/// maximum PDU size.
const TSDU_ENVELOPE_SIZE: usize =
    DEFAULT_MAX_TSDU_SIZE - iec61850_mms::DEFAULT_MAX_PDU_SIZE as usize;

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
                        // The slot is taken before anything is read from the
                        // socket, so connections that never associate count
                        // against the limit as well.
                        let Some(slot) = server.try_acquire_connection_slot() else {
                            tracing::warn!(
                                ?peer,
                                count = server.open_socket_count(),
                                "connection limit reached, closing the socket without a disconnect-request"
                            );
                            drop(stream);
                            continue;
                        };
                        tracing::info!(?peer, "accepted a client connection");
                        let setup_deadline = tokio::time::Instant::now()
                            + Duration::from_millis(server.config().association_setup_timeout_ms);
                        let server_for_conn = server.clone();
                        // With a TLS acceptor configured, the handshake runs
                        // before COTP; otherwise the connection is plain TCP.
                        #[cfg(feature = "tls")]
                        {
                            if let Some(acceptor) = server.tls_acceptor().cloned() {
                                tokio::spawn(async move {
                                    let _slot = slot;
                                    match tokio::time::timeout_at(setup_deadline, acceptor.accept(stream)).await {
                                        Ok(Ok(tls_stream)) => {
                                            handle_connection_inner(
                                                server_for_conn, tls_stream, peer, setup_deadline,
                                            ).await;
                                        }
                                        Ok(Err(e)) => {
                                            tracing::warn!(?peer, error = %e, "TLS handshake failed, closing the connection");
                                        }
                                        Err(_) => {
                                            tracing::warn!(?peer, "TLS handshake did not complete within the association setup timeout, closing the connection");
                                        }
                                    }
                                });
                            } else {
                                tokio::spawn(async move {
                                    let _slot = slot;
                                    handle_connection_inner(server_for_conn, stream, peer, setup_deadline).await;
                                });
                            }
                        }
                        #[cfg(not(feature = "tls"))]
                        {
                            tokio::spawn(async move {
                                let _slot = slot;
                                handle_connection_inner(server_for_conn, stream, peer, setup_deadline).await;
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
    #[error("association setup did not complete within the setup timeout")]
    SetupTimedOut,
    #[error("a PDU could not be written within the send timeout")]
    SendTimedOut,
}

/// Runs one association from accept to close.
///
/// The stream is generic so that a plain TCP connection and a TLS connection
/// take the same path. Setup through the Initiate response must finish by
/// `setup_deadline`.
async fn handle_connection_inner<S>(
    server: IedServer,
    stream: S,
    peer: std::net::SocketAddr,
    setup_deadline: tokio::time::Instant,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let conn_id = server.next_connection_id();
    let _teardown = AssociationTeardown {
        server: server.clone(),
        conn_id,
    };
    tracing::debug!(conn_id, ?peer, "connection task started");

    match run_connection(server.clone(), stream, peer, conn_id, setup_deadline).await {
        Ok(()) => {
            tracing::debug!(conn_id, ?peer, "connection closed normally");
        }
        Err(e) => {
            tracing::warn!(conn_id, ?peer, error = %e, "connection closed after an error");
        }
    }
}

/// Releases everything an association holds when its connection task ends,
/// whichever way it ends: an orderly close, an error from any layer, or the
/// task being dropped.
///
/// Every release is idempotent and tolerates a connection id that never
/// registered, so the guard is armed before the association is established.
struct AssociationTeardown {
    server: IedServer,
    conn_id: ConnectionId,
}

impl Drop for AssociationTeardown {
    fn drop(&mut self) {
        let conn_id = self.conn_id;
        // The command termination and report senders go first, so nothing new
        // is queued for the association while its state is being released.
        self.server.ct_sink().deregister(conn_id);
        self.server.control_objects().outbox().deregister(conn_id);
        self.server.report_sink().deregister(conn_id);
        self.server.control_objects().release_connection(conn_id);
        if let Ok(mut engine) = self.server.reporting_engine().lock() {
            engine.on_connection_dropped(conn_id);
            engine.deregister_peer(conn_id);
        } else {
            tracing::warn!(
                conn_id,
                "the reporting engine lock is poisoned, the association could not be deregistered from it"
            );
        }
        self.server.setting_groups().release_all_for_conn(conn_id);
        let _ = self.server.remove_connection(conn_id);
    }
}

async fn run_connection<S>(
    server: IedServer,
    stream: S,
    peer: std::net::SocketAddr,
    conn_id: ConnectionId,
    setup_deadline: tokio::time::Instant,
) -> std::result::Result<(), ConnError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let dispatcher = server.dispatcher();
    let setup = establish_association(&server, stream, conn_id, dispatcher.as_ref());
    let established = match tokio::time::timeout_at(setup_deadline, setup).await {
        Ok(established) => established?,
        Err(_) => {
            tracing::warn!(
                conn_id,
                "association setup did not complete within the setup timeout, closing the socket"
            );
            return Err(ConnError::SetupTimedOut);
        }
    };
    serve_association(server, peer, conn_id, dispatcher, established).await
}

/// The protocol state of an association once the Initiate response is sent.
struct Established<S> {
    cotp: CotpConnection<S>,
    session: IsoSession,
    pres: IsoPresentation,
    mms_conn: MmsServerConnection,
}

/// Runs COTP CR/CC through the MMS Initiate exchange and sends the Initiate
/// response.
async fn establish_association<S>(
    server: &IedServer,
    stream: S,
    conn_id: ConnectionId,
    dispatcher: &dyn MmsServiceDispatcher,
) -> std::result::Result<Established<S>, ConnError>
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
    // Any other MMS PDU in the AARQ is refused before it reaches the dispatcher,
    // so no confirmed service runs on an association that has not negotiated.
    if initiate_bytes.first() != Some(&MMS_INITIATE_REQUEST_TAG) {
        tracing::warn!(
            conn_id,
            first_byte = ?initiate_bytes.first(),
            "the acse user information is not an initiate-request, sending an associate reject and closing the socket"
        );
        send_acse_only(&mut cotp, &mut session, &mut pres, encode_associate_failed).await?;
        return Err(ConnError::InitiateRejected);
    }
    let mut mms_conn = MmsServerConnection::new();
    let outcome = parse_message(&mms_conn, dispatcher, &initiate_bytes);

    match outcome {
        MessageOutcome::SendInitiateResponse {
            response_bytes,
            params,
        } => {
            // From here on a TSDU carries at most one MMS PDU of the
            // negotiated size inside its Session and Presentation envelope.
            cotp.set_max_tsdu_size(Some(
                (params.max_pdu_size as usize).saturating_add(TSDU_ENVELOPE_SIZE),
            ));
            mms_conn.set_negotiated(params);
            mms_conn.set_block_requests(server.connection_block_requests_default());
            // The dispatcher routes command terminations by this id.
            mms_conn.set_connection_id(conn_id);

            // The response is wrapped outwards: MMS, ACSE AARE, Presentation
            // CPA, Session AC, COTP data.
            let mut aare_buf = BytesMut::new();
            encode_aare(
                0,
                Some(&response_bytes),
                pres.mms_context_id.into(),
                &mut aare_buf,
            );

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
    Ok(Established {
        cotp,
        session,
        pres,
        mms_conn,
    })
}

/// Registers an established association and dispatches its requests until it
/// closes.
async fn serve_association<S>(
    server: IedServer,
    peer: std::net::SocketAddr,
    conn_id: ConnectionId,
    dispatcher: std::sync::Arc<dyn MmsServiceDispatcher>,
    established: Established<S>,
) -> std::result::Result<(), ConnError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let Established {
        mut cotp,
        mut session,
        mut pres,
        mms_conn,
    } = established;

    // ── Register the association with the server ────────────────────────
    let client_conn = ClientConnection::new(conn_id, peer, mms_conn);
    server.add_connection(client_conn.clone());
    if let Ok(mut engine) = server.reporting_engine().lock() {
        engine.register_peer(conn_id, peer.ip());
    }

    // ── Command terminations ────────────────────────────────────────────
    //
    // The control service posts a termination event to the sender registered
    // here; the loop below encodes it as an InformationReport and writes it.
    let ct_sink = server.ct_sink();
    let (ct_tx, mut ct_rx) = mpsc::unbounded_channel::<ConnectionTerminationEvent>();
    ct_sink.register(conn_id, ct_tx);

    // ── Control outbox ──────────────────────────────────────────────────
    //
    // A refused control request queues its LastApplError report here, which is
    // sent ahead of the response of that request. An Operate under normal
    // security defers its write response; the loop holds the invoke id and
    // answers when the execution task posts the outcome.
    let control_outbox = server.control_objects().outbox().clone();
    let mut deferred_rx = control_outbox.register(conn_id);
    let mut deferred_writes: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
    // A closed channel is dropped from the select below rather than polled
    // again, which would keep it ready forever and starve the socket.
    let mut deferred_open = true;
    let mut ct_open = true;

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
    let idle_timeout = server
        .config()
        .association_idle_timeout_ms
        .map(Duration::from_millis);
    let send_timeout = Duration::from_millis(server.config().association_send_timeout_ms);
    let mut last_activity = tokio::time::Instant::now();

    loop {
        // Polled rather than awaited, so no future is built per iteration.
        if client_conn.abort_requested() {
            tracing::warn!(
                conn_id,
                "association marked for abort, sending an abort and closing the socket"
            );
            send_bounded(
                conn_id,
                send_timeout,
                &mut last_activity,
                send_acse_abort(&mut cotp, &mut session, &mut pres),
            )
            .await?;
            break;
        }

        let concluded = client_conn.with_mms(|m| m.is_concluded()).unwrap_or(false);
        // Checked here rather than on the receive timeout, which a steady
        // stream of reports or command terminations would never let expire.
        if let Some(idle) = idle_timeout {
            if !concluded && last_activity.elapsed() >= idle {
                tracing::warn!(
                    conn_id,
                    idle_timeout_ms = idle.as_millis() as u64,
                    "no PDU received or sent within the idle timeout, sending an abort and closing the socket"
                );
                send_bounded(
                    conn_id,
                    send_timeout,
                    &mut last_activity,
                    send_acse_abort(&mut cotp, &mut session, &mut pres),
                )
                .await?;
                break;
            }
        }
        let tick = if concluded {
            Duration::from_millis(conclude_timeout)
        } else {
            Duration::from_millis(200)
        };

        // The select is biased: the response of a deferred write is served
        // first, ahead of the command termination its command may already have
        // posted, then a command termination, then a report, then a new request
        // from the socket.
        enum Step {
            Payload(Bytes),
            Continue,
            Break,
        }
        let step = tokio::select! {
            biased;
            done = deferred_rx.recv(), if deferred_open => {
                match done {
                    Some(done) => {
                        if let Some(invoke_id) = deferred_writes.remove(&done.id) {
                            if let Some(report) = &done.last_appl_error {
                                send_bounded(
                                    conn_id,
                                    send_timeout,
                                    &mut last_activity,
                                    send_user_data_mms(&mut cotp, &session, &pres, report),
                                )
                                .await?;
                            }
                            let mut buf = BytesMut::new();
                            encode_confirmed_write_response(
                                invoke_id,
                                &WriteResponse { outcomes: vec![done.outcome] },
                                &mut buf,
                            );
                            send_bounded(
                                conn_id,
                                send_timeout,
                                &mut last_activity,
                                send_user_data_mms(&mut cotp, &session, &pres, &buf),
                            )
                            .await?;
                            if let Some(released) = done.released {
                                let _ = released.send(());
                            }
                        } else if let Some(event) = &done.termination {
                            tracing::warn!(
                                conn_id,
                                "the dynamic check refused an operate whose write was answered at acceptance, terminating it negatively"
                            );
                            send_bounded(
                                conn_id,
                                send_timeout,
                                &mut last_activity,
                                send_command_termination(&mut cotp, &session, &pres, event),
                            )
                            .await?;
                        } else if let Some(released) = done.released {
                            // The write was answered positively at acceptance.
                            let _ = released.send(());
                        } else {
                            tracing::warn!(
                                conn_id,
                                "a deferred operate finished after its write was answered, dropping its outcome"
                            );
                        }
                        Step::Continue
                    }
                    None => {
                        tracing::warn!(conn_id, "the control outbox channel has closed");
                        deferred_open = false;
                        Step::Continue
                    }
                }
            }
            ev = ct_rx.recv(), if ct_open => {
                match ev {
                    Some(event) => {
                        if let Err(e) = send_bounded(
                            conn_id,
                            send_timeout,
                            &mut last_activity,
                            send_command_termination(&mut cotp, &session, &pres, &event),
                        ).await {
                            tracing::warn!(conn_id, error = %e, "failed to send a command termination");
                            return Err(e);
                        }
                        Step::Continue
                    }
                    None => {
                        tracing::warn!(conn_id, "the command termination channel has closed");
                        ct_open = false;
                        Step::Continue
                    }
                }
            }
            ev = rpt_rx.recv() => {
                match ev {
                    Some(pdu) => {
                        if let Err(e) = send_bounded(
                            conn_id,
                            send_timeout,
                            &mut last_activity,
                            send_user_data_mms(&mut cotp, &session, &pres, &pdu),
                        ).await {
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
            Step::Payload(p) => {
                last_activity = tokio::time::Instant::now();
                p
            }
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
                send_bounded(conn_id, send_timeout, &mut last_activity, async {
                    cotp.send_data(&dn).await.map_err(ConnError::from)
                })
                .await?;
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

        // The context identifiers are the ones the client chose in its CP.
        match pres_result.context_id {
            id if id == pres.acse_context_id => {
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
                        send_bounded(
                            conn_id,
                            send_timeout,
                            &mut last_activity,
                            send_user_data_acse(&mut cotp, &session, &pres, &rlre),
                        )
                        .await?;
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
            id if id == pres.mms_context_id => {
                let outcome = client_conn
                    .with_mms(|m| parse_message(m, dispatcher.as_ref(), &inner_payload))
                    .unwrap_or(MessageOutcome::Silent);

                // Reports the request produced go ahead of its response.
                for report in control_outbox.take_before_response(conn_id) {
                    send_bounded(
                        conn_id,
                        send_timeout,
                        &mut last_activity,
                        send_user_data_mms(&mut cotp, &session, &pres, &report),
                    )
                    .await?;
                }
                let deferred = control_outbox.take_deferred(conn_id);
                let outcome = match outcome {
                    MessageOutcome::SendBytes(bytes) if !deferred.is_empty() => {
                        match deferrable_write(&bytes, &deferred) {
                            Some(invoke_id) => {
                                deferred_writes.insert(deferred[0], invoke_id);
                                MessageOutcome::Silent
                            }
                            None => {
                                tracing::warn!(
                                    conn_id,
                                    "a write of several variables cannot wait for its operate, answering at acceptance"
                                );
                                MessageOutcome::SendBytes(bytes)
                            }
                        }
                    }
                    other => other,
                };

                match outcome {
                    MessageOutcome::SendBytes(bytes) => {
                        send_bounded(
                            conn_id,
                            send_timeout,
                            &mut last_activity,
                            send_user_data_mms(&mut cotp, &session, &pres, &bytes),
                        )
                        .await?;
                    }
                    MessageOutcome::SendConcludeResponse { response_bytes } => {
                        send_bounded(
                            conn_id,
                            send_timeout,
                            &mut last_activity,
                            send_user_data_mms(&mut cotp, &session, &pres, &response_bytes),
                        )
                        .await?;
                        // Starts the bounded wait for the session finish.
                        client_conn.with_mms_mut(|m| m.mark_concluded());
                        // The session finish tells the peer to close as well.
                        let mut fn_bytes = BytesMut::new();
                        encode_finish(&[], &mut fn_bytes)?;
                        send_bounded(conn_id, send_timeout, &mut last_activity, async {
                            cotp.send_data(&fn_bytes).await.map_err(ConnError::from)
                        })
                        .await?;
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
                    _ => {
                        tracing::warn!(conn_id, "unhandled message outcome on an established association, closing the socket");
                        break;
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
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Writing a PDU down through the stack
// ─────────────────────────────────────────────────────────────────────────────

/// Runs one write of an established association within `send_timeout`, and
/// records its completion as activity for the idle timeout.
///
/// # Errors
///
/// Returns the write's own error, or `ConnError::SendTimedOut` when the peer
/// has stopped reading and the write does not complete in time; the caller then
/// ends the connection without attempting any further write.
async fn send_bounded<F>(
    conn_id: ConnectionId,
    send_timeout: Duration,
    last_activity: &mut tokio::time::Instant,
    send: F,
) -> std::result::Result<(), ConnError>
where
    F: core::future::Future<Output = std::result::Result<(), ConnError>>,
{
    match tokio::time::timeout(send_timeout, send).await {
        Ok(Ok(())) => {
            *last_activity = tokio::time::Instant::now();
            Ok(())
        }
        Ok(Err(e)) => Err(e),
        Err(_) => {
            tracing::warn!(
                conn_id,
                send_timeout_ms = send_timeout.as_millis() as u64,
                "the peer did not accept a PDU within the send timeout, closing the socket"
            );
            Err(ConnError::SendTimedOut)
        }
    }
}

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
            error,
            oper_value,
        } => {
            tracing::debug!(
                obj_ref,
                ?add_cause,
                oper_len = oper_value.len(),
                "sending a negative command termination"
            );
            let echoed = echoed_oper(oper_value);
            let last_err = LastApplErrorRef {
                ctl_obj: format!("{}/{}", domain_id, item_id),
                error: *error as i32,
                origin: echoed.origin,
                ctl_num: echoed.ctl_num,
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

/// Returns the invoke id of a write response that can wait for the one Operate
/// it carries: a single deferral, and a positive response of one variable.
fn deferrable_write(response: &[u8], deferred: &[u64]) -> Option<u32> {
    if deferred.len() != 1 {
        return None;
    }
    let (invoke_id, resp) = decode_confirmed_write_response(response).ok()?;
    match resp.outcomes.as_slice() {
        [WriteOutcome::Success] => Some(invoke_id),
        _ => None,
    }
}

/// The members of an echoed Oper structure the LastApplError of a negative
/// command termination carries.
#[derive(Default)]
struct EchoedOper {
    origin: OriginRef,
    ctl_num: u8,
}

/// Decodes the Oper structure a command termination echoes; a structure that
/// does not decode yields the defaults.
fn echoed_oper(oper_value: &[u8]) -> EchoedOper {
    use crate::control::OperParams;
    use crate::service::convert::mms_data_to_mms_value;
    use iec61850_mms::mms::pdu::common::MmsData;

    let params = MmsData::decode(oper_value)
        .ok()
        .and_then(|(data, _)| OperParams::from_mms_value(&mms_data_to_mms_value(&data)));
    match params {
        Some(p) => EchoedOper {
            origin: OriginRef {
                or_cat: p.origin.or_cat,
                or_ident: p.origin.or_ident,
            },
            ctl_num: p.ctl_num,
        },
        None => {
            tracing::warn!("command termination: the echoed Oper structure did not decode");
            EchoedOper::default()
        }
    }
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

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

/// The association timers, run against an in-memory stream on a paused clock:
/// the runtime advances time only when every task is waiting, so each
/// assertion about a timeout holds regardless of machine load.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IedServerConfig;
    use crate::reporting::rcb::Rcb;
    use crate::reporting::{Dataset, ReportControl};
    use iec61850_mms::iso::acse::encode_aarq;
    use iec61850_mms::iso::presentation::{encode_connect, PresentationConnectionParameters};
    use iec61850_mms::iso::session::{encode_connect as sess_encode_connect, IsoParameters};
    use iec61850_mms::mms::pdu::initiate::InitiateRequestPdu;
    use iec61850_mms::AarqAddressing;
    use iec61850_model::{IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder};
    use std::sync::Arc;
    use tokio::io::DuplexStream;
    use tokio::task::JoinHandle;
    use tokio::time::Instant;

    const URCB_PATH: &str = "TESTLD0/LLN0$RP$urcb01";

    fn build_server(cfg: IedServerConfig) -> IedServer {
        let lln0 = LogicalNodeBuilder::lln0().build().unwrap();
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(lln0)
            .build()
            .unwrap();
        let model = IedModelBuilder::new("TEST")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap();
        let server = IedServer::builder()
            .model(Arc::new(model))
            .bind("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .config(cfg)
            .build()
            .unwrap();
        server
            .register_urcb(
                ReportControl::new(URCB_PATH, Rcb::new("urcb01", "LLN0$ds1")),
                Dataset::new("LLN0$ds1"),
            )
            .unwrap();
        server
    }

    /// Runs one connection task, holding a connection slot as the accept loop
    /// does, over an in-memory stream that buffers `buf` bytes per direction.
    fn spawn_connection(server: &IedServer, buf: usize) -> (DuplexStream, JoinHandle<()>) {
        let (client, server_end) = tokio::io::duplex(buf);
        let slot = server.try_acquire_connection_slot().expect("a free slot");
        let server = server.clone();
        let deadline = Instant::now() + Duration::from_secs(10);
        let task = tokio::spawn(async move {
            let _slot = slot;
            handle_connection_inner(
                server,
                server_end,
                "127.0.0.1:102".parse().unwrap(),
                deadline,
            )
            .await;
        });
        (client, task)
    }

    /// Completes the association and waits for the Initiate response.
    async fn associate(client: DuplexStream) -> CotpConnection<DuplexStream> {
        let mut initiate = BytesMut::new();
        InitiateRequestPdu::default().encode(&mut initiate);
        let mut aarq = BytesMut::new();
        encode_aarq(&initiate, None, 3, &AarqAddressing::default(), &mut aarq);
        let mut cp = BytesMut::new();
        encode_connect(&PresentationConnectionParameters::default(), &aarq, &mut cp);
        let mut cn = BytesMut::new();
        sess_encode_connect(&IsoParameters::default(), &IsoSession::new(), &cp, &mut cn).unwrap();

        let mut cotp = CotpConnection::connect(client, CotpOptions::default())
            .await
            .unwrap();
        cotp.send_data(&cn).await.unwrap();
        cotp.recv_data().await.expect("the initiate response");
        cotp
    }

    /// Reads and discards everything the server sends until it closes.
    fn drain(mut cotp: CotpConnection<DuplexStream>) -> JoinHandle<()> {
        tokio::spawn(async move { while cotp.recv_data().await.is_ok() {} })
    }

    /// Posts one report-sized PDU to connection 1, the first id a server hands out.
    fn post_report(server: &IedServer) {
        let _ = server
            .report_sink()
            .try_send_pdu(1, Bytes::from(vec![0xa3; 200]));
    }

    fn urcb_reserved(server: &IedServer) -> bool {
        let engine = server.reporting_engine();
        let engine = engine.lock().unwrap();
        let rc = engine.get_rcb(URCB_PATH).unwrap();
        let rc = rc.lock().unwrap();
        let reserved = rc.state.lock().unwrap().resv;
        reserved
    }

    fn reserve_urcb_for_connection_1(server: &IedServer) {
        let engine = server.reporting_engine();
        let engine = engine.lock().unwrap();
        let rc = engine.get_rcb(URCB_PATH).unwrap();
        let rc = rc.lock().unwrap();
        let mut state = rc.state.lock().unwrap();
        state.resv = true;
        state.client_conn_id = Some(1);
    }

    /// A peer that stops reading while the server has reports to send has its
    /// connection closed once a write exceeds the send timeout; the slot and
    /// the URCB reservation are released with it.
    #[tokio::test(start_paused = true)]
    async fn peer_that_stops_reading_is_closed_after_the_send_timeout() {
        let server = build_server(IedServerConfig {
            association_send_timeout_ms: 1_000,
            association_idle_timeout_ms: None,
            ..Default::default()
        });
        let (client, task) = spawn_connection(&server, 512);
        let _stalled = associate(client).await;
        reserve_urcb_for_connection_1(&server);

        let start = Instant::now();
        for _ in 0..8 {
            post_report(&server);
        }
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the connection must end once a write exceeds the send timeout")
            .unwrap();
        assert!(start.elapsed() >= Duration::from_secs(1));
        assert_eq!(server.connection_count(), 0);
        assert_eq!(server.open_socket_count(), 0);
        assert!(!urcb_reserved(&server));
    }

    /// A peer that keeps reading receives reports for well past the send
    /// timeout and stays connected.
    #[tokio::test(start_paused = true)]
    async fn reading_peer_outlasts_the_send_timeout() {
        let server = build_server(IedServerConfig {
            association_send_timeout_ms: 1_000,
            association_idle_timeout_ms: None,
            ..Default::default()
        });
        let (client, task) = spawn_connection(&server, 512);
        let _reader = drain(associate(client).await);

        for _ in 0..20 {
            for _ in 0..8 {
                post_report(&server);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        assert!(!task.is_finished());
        assert_eq!(server.connection_count(), 1);
    }

    /// A client that only receives reports, never sending a request, stays
    /// open through three idle timeouts, because each completed send counts as
    /// activity.
    #[tokio::test(start_paused = true)]
    async fn report_only_client_outlives_the_idle_timeout() {
        let server = build_server(IedServerConfig::default());
        let (client, task) = spawn_connection(&server, 4096);
        let _reader = drain(associate(client).await);

        for _ in 0..15 {
            post_report(&server);
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
        assert!(
            !task.is_finished(),
            "a report-only client must not be aborted"
        );
        assert_eq!(server.connection_count(), 1);
    }

    /// A client that neither sends nor receives anything is aborted once the
    /// default idle timeout of 300 s has passed, and not before.
    #[tokio::test(start_paused = true)]
    async fn silent_client_is_aborted_at_the_idle_timeout() {
        let server = build_server(IedServerConfig::default());
        let (client, task) = spawn_connection(&server, 4096);
        let _silent = associate(client).await;

        let start = Instant::now();
        tokio::time::timeout(Duration::from_secs(301), task)
            .await
            .expect("a silent association must be aborted at the idle timeout")
            .unwrap();
        assert!(start.elapsed() >= Duration::from_secs(300));
        assert_eq!(server.connection_count(), 0);
    }

    /// Completes the association offering `max_pdu_size` and waits for the
    /// Initiate response.
    async fn associate_with_max_pdu(
        client: DuplexStream,
        max_pdu_size: u32,
    ) -> CotpConnection<DuplexStream> {
        let mut initiate = BytesMut::new();
        InitiateRequestPdu {
            local_detail_calling: Some(max_pdu_size),
            ..InitiateRequestPdu::default()
        }
        .encode(&mut initiate);
        let mut aarq = BytesMut::new();
        encode_aarq(&initiate, None, 3, &AarqAddressing::default(), &mut aarq);
        let mut cp = BytesMut::new();
        encode_connect(&PresentationConnectionParameters::default(), &aarq, &mut cp);
        let mut cn = BytesMut::new();
        sess_encode_connect(&IsoParameters::default(), &IsoSession::new(), &cp, &mut cn).unwrap();

        let mut cotp = CotpConnection::connect(client, CotpOptions::default())
            .await
            .unwrap();
        cotp.send_data(&cn).await.unwrap();
        cotp.recv_data().await.expect("the initiate response");
        cotp
    }

    /// Sends a GetNameList request padded to about `size` bytes by its
    /// continue-after name, wrapped in Presentation and Session user data, and
    /// returns whether any answer arrives before the server closes.
    async fn oversized_request_is_answered(
        cotp: &mut CotpConnection<DuplexStream>,
        size: usize,
    ) -> bool {
        use iec61850_mms::mms::pdu::get_name_list::{
            encode_confirmed_get_name_list_request, GetNameListRequest, ObjectScope,
        };
        use iec61850_mms::mms::pdu::ObjectClass;

        let req = GetNameListRequest {
            object_class: ObjectClass::Domain,
            object_scope: ObjectScope::VmdSpecific,
            continue_after: Some("x".repeat(size)),
        };
        let mut mms = BytesMut::new();
        encode_confirmed_get_name_list_request(41, &req, &mut mms);
        let mut ppdu = BytesMut::new();
        encode_user_data(&IsoPresentation::new(), &mms, &mut ppdu);
        let mut spdu = BytesMut::new();
        encode_data(&ppdu, &mut spdu);
        if cotp.send_data(&spdu).await.is_err() {
            return false;
        }
        cotp.recv_data().await.is_ok()
    }

    /// Once an association has negotiated a 1000-byte maximum PDU, a TSDU
    /// larger than that plus the 8192-byte envelope closes the connection
    /// unanswered; the same request is answered on an association that kept
    /// the default maximum.
    #[tokio::test(start_paused = true)]
    async fn tsdu_is_bounded_by_the_negotiated_pdu_size() {
        let server = build_server(IedServerConfig::default());
        let (client, task) = spawn_connection(&server, 64 * 1024);
        let mut small = associate_with_max_pdu(client, 1_000).await;
        assert!(!oversized_request_is_answered(&mut small, 12_000).await);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("the connection must end on an oversized TSDU")
            .unwrap();

        let (client, task) = spawn_connection(&server, 64 * 1024);
        let mut default = associate(client).await;
        assert!(oversized_request_is_answered(&mut default, 12_000).await);
        assert!(!task.is_finished());
    }

    /// A client that sends a request every 100 s stays open through three
    /// idle timeouts.
    #[tokio::test(start_paused = true)]
    async fn requesting_client_outlives_the_idle_timeout() {
        use iec61850_mms::mms::client::MmsClient;
        use iec61850_mms::mms::pdu::ObjectClass;

        let server = build_server(IedServerConfig::default());
        let (client, task) = spawn_connection(&server, 4096);
        let mut client = MmsClient::<DuplexStream>::from_transport(client)
            .await
            .expect("associate");
        for _ in 0..9 {
            tokio::time::sleep(Duration::from_secs(100)).await;
            client
                .get_name_list(ObjectClass::Domain, None, None)
                .await
                .expect("an active association keeps serving");
        }
        assert!(!task.is_finished());
        assert_eq!(server.connection_count(), 1);
    }
}

#[cfg(test)]
mod control_channel_tests {
    use super::*;
    use iec61850_mms::mms::client::MmsClient;
    use iec61850_mms::mms::pdu::ObjectClass;
    use iec61850_model::{IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Counts the events whose message mentions `needle`.
    struct EventCounter {
        needle: &'static str,
        count: Arc<AtomicUsize>,
    }

    struct MessageVisitor<'a>(&'a mut String);

    impl tracing::field::Visit for MessageVisitor<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                *self.0 = format!("{value:?}");
            }
        }
    }

    impl tracing::Subscriber for EventCounter {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut message = String::new();
            event.record(&mut MessageVisitor(&mut message));
            if message.contains(self.needle) {
                self.count.fetch_add(1, Ordering::Relaxed);
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// An association whose deferred-outcome and command-termination channels
    /// have closed notices each closure once and keeps serving its requests.
    #[tokio::test]
    async fn closed_control_channels_are_not_polled_again() {
        let closed = Arc::new(AtomicUsize::new(0));
        let _guard = tracing::subscriber::set_default(EventCounter {
            needle: "channel has closed",
            count: closed.clone(),
        });
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(LogicalNodeBuilder::lln0().build().unwrap())
            .build()
            .unwrap();
        let model = IedModelBuilder::new("TEST")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap();
        let server = IedServer::builder()
            .model(Arc::new(model))
            .bind("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .build()
            .unwrap();
        let (client, server_end) = tokio::io::duplex(4096);
        let slot = server.try_acquire_connection_slot().expect("a free slot");
        let task_server = server.clone();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let task = tokio::spawn(async move {
            let _slot = slot;
            handle_connection_inner(
                task_server,
                server_end,
                "127.0.0.1:102".parse().unwrap(),
                deadline,
            )
            .await;
        });
        let mut client = MmsClient::<tokio::io::DuplexStream>::from_transport(client)
            .await
            .expect("associate");

        // Connection 1 is the first id the server hands out.
        server.control_objects().outbox().deregister(1);
        server.ct_sink().deregister(1);
        for _ in 0..3 {
            client
                .get_name_list(ObjectClass::Domain, None, None)
                .await
                .expect("the association keeps serving");
        }
        assert!(!task.is_finished());
        assert_eq!(
            closed.load(Ordering::Relaxed),
            2,
            "each closed channel is noticed once"
        );
    }
}
