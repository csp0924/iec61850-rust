//! Low-level MMS client connection management over an async transport.
//!
//! ## Responsibilities
//!
//! 1. Owning the transport and its I/O.
//! 2. Running the association sequence: COTP CR and CC, then Session CN with
//!    Presentation CP, ACSE AARQ and the MMS Initiate request in one message, and
//!    the matching Session AC with Presentation CPA, ACSE AARE and the MMS Initiate
//!    response.
//! 3. Running the release sequence: MMS Conclude request and response, then the
//!    ACSE A-RELEASE (RLRQ carried by a Session FN, RLRE by the DN), then close.
//!    The abort sequence sends an ACSE ABRT inside a Session AB and closes.
//! 4. Sending and receiving MMS PDUs inside TPKT and COTP framing, through
//!    [`crate::iso::cotp::CotpConnection`].
//! 5. An encoded MMS PDU larger than `negotiated_max_pdu_size` is rejected
//!    instead of being sent.
//! 6. A confirmed response is bound to its request by invokeID (ISO 9506-2). The
//!    invokeID of a request that timed out is remembered, so its late answer is
//!    discarded instead of being taken for the answer to a later request.
//!
//! ## Design
//!
//! - The API is async throughout, and all framing goes through
//!   `CotpConnection`, which is transport generic.
//! - Synchronous callers use the `BlockingMmsClient` wrapper.
//! - `connect_timeout_ms` and `request_timeout_ms` are applied with
//!   `iec61850_hal::time::with_timeout`, so the runtime stays pluggable. Each
//!   receive is bounded by exactly one timeout.
//!
//! ## Behavior
//!
//! - A Session FN from the peer, which carries its ACSE release request, is
//!   answered with a Session DN carrying the release response (ISO 8327-1,
//!   ISO 8650-1); the transport is then closed and the caller sees
//!   `ReleasedByPeer`.
//! - A Conclude request arriving from the server (`0x8b`) is answered with
//!   `0x8c`, the transport is closed and the caller sees `ReleasedByPeer`.
//! - The end of the transport, a COTP DR, and a Session AB or DN close the
//!   connection and surface as `ConnectionLost`.
//! - An I/O error of the transport closes the connection and surfaces as
//!   `Transport`, carrying the category and text the transport reported; a TLS
//!   alert received once the association is established arrives this way.
//! - Establishing the connection, the TCP connection, the TLS handshake and
//!   the COTP CR and CC, is bounded by one `connect_timeout_ms` deadline for
//!   all of these steps together. Running out of it during the TLS handshake
//!   is a `TlsHandshake` of the `Timeout` kind, and during any other of these
//!   steps `ConnectTimeout`.
//! - A failed TLS handshake surfaces as `TlsHandshake`, carrying the kind of
//!   failure. So does a TLS error, such as a fatal alert or a record that does
//!   not decrypt, while the connection is being established: from the TCP
//!   connection until the MMS Initiate response has been accepted. Under
//!   TLS 1.3 a server that refuses the client certificate does so after the
//!   client has completed its side of the handshake, and the client reads its
//!   alert only during the COTP exchange that follows.

use super::error::ClientError;
use crate::compat::prelude::*;
use crate::compat::{Arc, VecDeque};
use crate::error::CotpError;
use crate::iso::acse::{self, AcseConnection, AcseIndication};
use crate::iso::cotp::{CotpConnection, CotpOptions};
use crate::iso::params::IsoConnectionParameters;
use crate::iso::presentation::{self, IsoPresentation, PresentationConnectionParameters};
use crate::iso::session::{self, IsoParameters, IsoSession, SessionIndication};
use crate::mms::pdu::{
    InitiateRequestPdu, MmsPdu, DEFAULT_MAX_PDU_SIZE, DEFAULT_MAX_SERV_OUTSTANDING_CALLED,
    DEFAULT_MAX_SERV_OUTSTANDING_CALLING,
};
use bytes::{Bytes, BytesMut};
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use iec61850_hal::time::{with_timeout, Timer};
use iec61850_hal::transport::AsyncTransport;
#[cfg(feature = "std")]
use iec61850_hal::transport::{IoErrorKind, TransportError};
use tracing::{debug, warn};

// std only: the tokio TcpStream and TokioTimer defaults, plus the TLS connector.
#[cfg(feature = "std")]
use iec61850_hal::time::TokioTimer;
#[cfg(feature = "std")]
use tokio::net::TcpStream;

#[cfg(feature = "tls")]
use super::error::TlsFailureKind;
#[cfg(feature = "tls")]
use iec61850_tls::{TlsConnector, TlsError, TlsStream};
#[cfg(feature = "tls")]
use rustls::pki_types::ServerName;

/// The text of a failed client handshake, without the prefix of
/// `TlsError::Handshake`, which the error carrying it already has.
#[cfg(feature = "tls")]
fn tls_failure_message(e: &TlsError) -> String {
    match e {
        TlsError::Handshake(inner) => inner.to_string(),
        other => other.to_string(),
    }
}

/// The failure of a TLS association that `error` interrupted after the
/// handshake, while the association was being established.
///
/// A transport failure behind which the session recorded `tls_error` is that
/// TLS error, classified like a failed handshake; any other failure is
/// returned unchanged.
#[cfg(feature = "tls")]
fn tls_setup_failure(error: ClientError, tls_error: Option<&rustls::Error>) -> ClientError {
    match (error, tls_error) {
        (ClientError::Transport(_), Some(err)) => {
            let e = TlsError::from(err.clone());
            ClientError::TlsHandshake {
                kind: tls_failure_kind(&e),
                message: tls_failure_message(&e),
            }
        }
        (error, _) => error,
    }
}

/// The client TLS session of an association, recording the first TLS error a
/// read or a write of it failed with.
///
/// The transport layer reduces a failed read to a category and a text, which
/// is what an established association reports; the record keeps the TLS
/// error itself for the classification of a failure while the association is
/// being established.
#[cfg(feature = "tls")]
struct ClientTlsStream {
    inner: TlsStream<TcpStream>,
    tls_error: Arc<std::sync::OnceLock<rustls::Error>>,
}

#[cfg(feature = "tls")]
impl ClientTlsStream {
    /// Records the TLS error behind `result`, if it is a failure carrying one.
    fn record<R>(
        &self,
        result: core::task::Poll<std::io::Result<R>>,
    ) -> core::task::Poll<std::io::Result<R>> {
        if let core::task::Poll::Ready(Err(e)) = &result {
            if let Some(err) = e
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<rustls::Error>())
            {
                let _ = self.tls_error.set(err.clone());
            }
        }
        result
    }
}

#[cfg(feature = "tls")]
impl tokio::io::AsyncRead for ClientTlsStream {
    fn poll_read(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        let result = core::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        self.record(result)
    }
}

#[cfg(feature = "tls")]
impl tokio::io::AsyncWrite for ClientTlsStream {
    fn poll_write(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &[u8],
    ) -> core::task::Poll<std::io::Result<usize>> {
        let result = core::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        self.record(result)
    }

    fn poll_write_vectored(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> core::task::Poll<std::io::Result<usize>> {
        let result = core::pin::Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        self.record(result)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        let result = core::pin::Pin::new(&mut self.inner).poll_flush(cx);
        self.record(result)
    }

    fn poll_shutdown(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        let result = core::pin::Pin::new(&mut self.inner).poll_shutdown(cx);
        self.record(result)
    }
}

/// Steps of a TLS connection establishment, as recorded while it runs.
#[cfg(feature = "tls")]
const STEP_TCP: u8 = 0;
#[cfg(feature = "tls")]
const STEP_TLS_HANDSHAKE: u8 = 1;
#[cfg(feature = "tls")]
const STEP_COTP: u8 = 2;

/// Classifies a failed client handshake.
#[cfg(feature = "tls")]
fn tls_failure_kind(e: &TlsError) -> TlsFailureKind {
    match e {
        TlsError::Verification(_) => TlsFailureKind::Verification,
        TlsError::VersionUnsupported(_) => TlsFailureKind::VersionUnsupported,
        TlsError::CipherUnsupported(_) => TlsFailureKind::CipherUnsupported,
        TlsError::Handshake(rustls::Error::AlertReceived(_)) => TlsFailureKind::AlertReceived,
        TlsError::Io(_) => TlsFailureKind::Io,
        _ => TlsFailureKind::Other,
    }
}

// Constants

/// Default connect timeout in milliseconds.
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10_000;

/// Default request timeout in milliseconds.
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 5_000;

/// Default ceiling on the Unconfirmed PDUs stashed while a confirmed call is in
/// flight; see [`MmsConnection::max_pending_unconfirmed`].
pub const DEFAULT_MAX_PENDING_UNCONFIRMED: usize = 1024;

/// Minimum number of timed-out invokeIDs remembered so that their late answers
/// are recognized and discarded; the oldest is forgotten first. A negotiated
/// outstanding calling limit above it raises the ceiling to that limit, so every
/// request that holds a slot stays counted.
const MAX_ABANDONED_INVOKE_IDS: usize = 64;

/// indirect-reference written into the AARQ user-information; MMS uses 3.
const ACSE_INDIRECT_REFERENCE: u32 = 3;

/// Tag of the Conclude-ErrorPDU, `[13] IMPLICIT ServiceError` (ISO 9506-2).
const TAG_CONCLUDE_ERROR: u8 = 0xad;

/// Tag of the ACSE RLRQ APDU (ISO 8650-1).
const TAG_ACSE_RLRQ: u8 = 0x62;

/// Tag of the ACSE RLRE APDU (ISO 8650-1).
const TAG_ACSE_RLRE: u8 = 0x63;

// ConnectionState

/// MMS connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// No association; the transport is not connected.
    Closed,
    /// The association sequence is in progress.
    Connecting,
    /// The association is established and services may be issued.
    Connected,
    /// A Conclude request has been sent and the release is in progress.
    Closing,
}

// MmsConnection

/// A low-level MMS client connection: an async transport plus ISO stack state.
///
/// `T` is the transport and `Tm` the timer. On std they default to `TcpStream`
/// and `TokioTimer`; an embedded caller supplies both, constructing the connection
/// with `MmsConnection::<MyTransport, MyTimer>::with_timer` and associating it with
/// `connect_via`.
///
/// The connection holds a `CotpConnection<T>` for plaintext, and with the `tls`
/// feature an additional TLS one, usable only when `T = TcpStream`. All framing
/// goes through `CotpConnection`.
///
/// The std build gives both type parameters defaults; the no_std build requires
/// them. To keep the defaults from naming types that no_std lacks, the struct is
/// defined twice with identical fields.
#[cfg(feature = "std")]
pub struct MmsConnection<T = TcpStream, Tm = TokioTimer> {
    /// COTP connection over the generic transport; `None` while disconnected.
    cotp: Option<CotpConnection<T>>,
    /// COTP connection over TLS; `None` while disconnected.
    #[cfg(feature = "tls")]
    cotp_tls: Option<CotpConnection<ClientTlsStream>>,
    /// Session layer state, including selector negotiation.
    session: IsoSession,
    /// Presentation layer state, including context identifier negotiation.
    presentation: IsoPresentation,
    /// ACSE association state, including the indirect reference.
    acse: AcseConnection,
    /// Timer backend; every timeout and sleep in this layer goes through it.
    timer: Tm,
    /// Connection state.
    pub state: ConnectionState,
    /// Negotiated maximum PDU size in bytes.
    pub negotiated_max_pdu_size: usize,
    /// Negotiated ceiling on the confirmed requests this client may have
    /// outstanding at once; see [`Self::local_max_outstanding`].
    pub negotiated_max_calling: u16,
    /// Negotiated ceiling on outstanding called requests.
    pub negotiated_max_called: u16,
    /// Connect timeout in milliseconds.
    pub connect_timeout_ms: u64,
    /// Request timeout in milliseconds.
    pub request_timeout_ms: u64,
    /// proposedMaxServOutstandingCalling of the Initiate request. `None`
    /// proposes `DEFAULT_MAX_SERV_OUTSTANDING_CALLING`, that is 5, and 0 is
    /// proposed as 1.
    ///
    /// The negotiated value never exceeds this proposal, whatever the server
    /// answers. A request that timed out counts as outstanding until its late
    /// answer arrives, so once that many requests have timed out unanswered, the
    /// next request first waits for a late answer; see
    /// [`ClientError::OutstandingCallLimit`]. A request the peer discarded
    /// holds its slot until a new association is established.
    pub local_max_outstanding: Option<u16>,
    /// `localDetail` proposed in the Initiate request, the proposedMaxPduSize.
    /// `None` uses `DEFAULT_MAX_PDU_SIZE`, that is 65000. The negotiated size never
    /// exceeds this proposal, whatever the server answers.
    pub local_max_pdu_size: Option<u32>,
    /// ISO addressing offered by the next association: the T, S and P selectors
    /// and the AP-title and AE-qualifier of both sides.
    pub iso_parameters: IsoConnectionParameters,
    /// Ceiling on the number of stashed Unconfirmed PDUs. When it is reached the
    /// oldest stashed PDU is dropped with a warning. Defaults to
    /// [`DEFAULT_MAX_PENDING_UNCONFIRMED`].
    pub max_pending_unconfirmed: usize,
    /// Inner bytes of Unconfirmed PDUs, such as InformationReport, that arrived while
    /// a confirmed service was awaiting its response.
    ///
    /// A server may push an InformationReport, for a report control block or a
    /// command termination, in the middle of a confirmed exchange. Such a PDU is
    /// stashed here and drained by `recv_unconfirmed_pdu_with_timeout`, which keeps
    /// the caller from mistaking it for the response. The queue preserves arrival order.
    pending_unconfirmed: VecDeque<Bytes>,
    /// invokeIDs of requests that timed out, oldest first.
    abandoned_invoke_ids: VecDeque<u32>,
    /// Flag mirroring whether the state is `Connected`, shared with observers.
    connected_flag: Option<Arc<AtomicBool>>,
}

/// The no_std form of `MmsConnection`, without type parameter defaults. Its fields
/// match the std form exactly.
#[cfg(not(feature = "std"))]
pub struct MmsConnection<T, Tm> {
    cotp: Option<CotpConnection<T>>,
    session: IsoSession,
    presentation: IsoPresentation,
    acse: AcseConnection,
    timer: Tm,
    /// Connection state.
    pub state: ConnectionState,
    /// Negotiated maximum PDU size in bytes.
    pub negotiated_max_pdu_size: usize,
    /// Negotiated ceiling on outstanding calling requests.
    pub negotiated_max_calling: u16,
    /// Negotiated ceiling on outstanding called requests.
    pub negotiated_max_called: u16,
    /// Connect timeout in milliseconds.
    pub connect_timeout_ms: u64,
    /// Request timeout in milliseconds.
    pub request_timeout_ms: u64,
    /// proposedMaxServOutstandingCalling of the Initiate request; `None` uses
    /// the default.
    pub local_max_outstanding: Option<u16>,
    /// `localDetail` proposed in the Initiate request; `None` uses the default.
    pub local_max_pdu_size: Option<u32>,
    /// ISO addressing offered by the next association.
    pub iso_parameters: IsoConnectionParameters,
    /// Ceiling on the number of stashed Unconfirmed PDUs.
    pub max_pending_unconfirmed: usize,
    pending_unconfirmed: VecDeque<Bytes>,
    abandoned_invoke_ids: VecDeque<u32>,
    connected_flag: Option<Arc<AtomicBool>>,
}

impl<T, Tm: Default> MmsConnection<T, Tm> {
    /// Creates a disconnected connection whose timer is `Tm::default()`.
    pub fn new() -> Self {
        Self::with_timer(Tm::default())
    }
}

impl<T, Tm> MmsConnection<T, Tm> {
    /// Creates a disconnected connection from a caller-supplied timer.
    ///
    /// An embedded timer is often not `Default`, for instance when the driver instance
    /// has to be injected; use this instead of `new` in that case.
    pub fn with_timer(timer: Tm) -> Self {
        Self {
            cotp: None,
            #[cfg(feature = "tls")]
            cotp_tls: None,
            session: IsoSession::new(),
            presentation: IsoPresentation::new(),
            acse: AcseConnection::new(None),
            timer,
            state: ConnectionState::Closed,
            negotiated_max_pdu_size: DEFAULT_MAX_PDU_SIZE as usize,
            negotiated_max_calling: DEFAULT_MAX_SERV_OUTSTANDING_CALLING,
            negotiated_max_called: DEFAULT_MAX_SERV_OUTSTANDING_CALLED,
            connect_timeout_ms: DEFAULT_CONNECT_TIMEOUT_MS,
            request_timeout_ms: DEFAULT_REQUEST_TIMEOUT_MS,
            local_max_outstanding: None,
            local_max_pdu_size: None,
            iso_parameters: IsoConnectionParameters::default(),
            max_pending_unconfirmed: DEFAULT_MAX_PENDING_UNCONFIRMED,
            pending_unconfirmed: VecDeque::new(),
            abandoned_invoke_ids: VecDeque::new(),
            connected_flag: None,
        }
    }

    /// Replaces the ISO addressing offered by the next association.
    ///
    /// The entry point for a caller that owns its transport and therefore never
    /// goes through `MmsClientBuilder`.
    pub fn set_iso_parameters(&mut self, params: IsoConnectionParameters) {
        self.iso_parameters = params;
    }

    /// Returns a flag that is `true` exactly while the state is `Connected`.
    ///
    /// Every later call returns the same flag. The connection updates it on each
    /// state change, including a transport loss detected inside a service call,
    /// so an observer can test liveness without taking the connection.
    pub fn connected_flag(&mut self) -> Arc<AtomicBool> {
        let connected = self.state == ConnectionState::Connected;
        Arc::clone(
            self.connected_flag
                .get_or_insert_with(|| Arc::new(AtomicBool::new(connected))),
        )
    }

    /// Removes the oldest stashed Unconfirmed PDU, if any.
    ///
    /// `recv_mms_pdu_confirmed` pushes the inner bytes of an InformationReport onto
    /// `pending_unconfirmed` while a confirmed call is in flight;
    /// `MmsClient::recv_unconfirmed_pdu_with_timeout` drains the queue before reading
    /// from the transport.
    pub fn pop_pending_unconfirmed(&mut self) -> Option<Bytes> {
        self.pending_unconfirmed.pop_front()
    }

    /// Returns a set of Unconfirmed PDU inner bytes to the back of the stash.
    ///
    /// A command-termination wait that takes an InformationReport and finds it is a
    /// different kind of report puts it back here for the report dispatcher. The
    /// stash is bounded by `max_pending_unconfirmed`, dropping the oldest entry.
    pub fn push_pending_unconfirmed(&mut self, inner: Bytes) {
        if self.max_pending_unconfirmed == 0 {
            warn!(
                len = inner.len(),
                "unconfirmed pdu stash has a limit of 0, dropping the pdu"
            );
            return;
        }
        while self.pending_unconfirmed.len() >= self.max_pending_unconfirmed {
            let Some(dropped) = self.pending_unconfirmed.pop_front() else {
                break;
            };
            warn!(
                dropped_len = dropped.len(),
                limit = self.max_pending_unconfirmed,
                "unconfirmed pdu stash is full, dropping the oldest entry"
            );
        }
        self.pending_unconfirmed.push_back(inner);
    }

    /// Moves to `state` and updates the shared connected flag.
    fn set_state(&mut self, state: ConnectionState) {
        self.state = state;
        if let Some(flag) = self.connected_flag.as_ref() {
            flag.store(state == ConnectionState::Connected, Ordering::Release);
        }
    }

    /// Remembers the invokeID of a request whose answer did not arrive in time.
    ///
    /// At most the larger of `MAX_ABANDONED_INVOKE_IDS` and
    /// `negotiated_max_calling` invokeIDs are kept, so the count never falls
    /// below the outstanding limit it is checked against.
    fn abandon_invoke_id(&mut self, invoke_id: u32) {
        let ceiling = MAX_ABANDONED_INVOKE_IDS.max(usize::from(self.negotiated_max_calling));
        while self.abandoned_invoke_ids.len() >= ceiling {
            self.abandoned_invoke_ids.pop_front();
        }
        self.abandoned_invoke_ids.push_back(invoke_id);
    }

    /// Forgets `invoke_id` and reports whether it was an abandoned request.
    fn take_abandoned(&mut self, invoke_id: u32) -> bool {
        match self
            .abandoned_invoke_ids
            .iter()
            .position(|&id| id == invoke_id)
        {
            Some(pos) => {
                self.abandoned_invoke_ids.remove(pos);
                true
            }
            None => false,
        }
    }
}

// TCP-specific constructors, std only

#[cfg(feature = "std")]
impl MmsConnection<TcpStream, TokioTimer> {
    /// Runs the full ISO and MMS association sequence over a new TCP connection.
    ///
    /// `host` is an IP literal, with or without the brackets of an IPv6 literal,
    /// or a host name, which is resolved and whose addresses are tried in turn.
    /// The sequence is TCP, COTP CR and CC, then Session CN with Presentation CP,
    /// ACSE AARQ and the MMS Initiate request, and the matching Session AC with
    /// Presentation CPA, ACSE AARE and the MMS Initiate response.
    ///
    /// The TCP connection and the COTP CR and CC share one deadline of
    /// `connect_timeout_ms`. An association still established, over TCP or
    /// TLS, is closed first without a release; every later service reaches the
    /// new peer.
    ///
    /// # Errors
    ///
    /// - `ConnectTimeout` when the TCP connection and the COTP handshake do not
    ///   complete within `connect_timeout_ms`.
    /// - `Transport` when the name does not resolve or every address refuses.
    /// - `ServiceTimeout` when the Initiate response does not arrive within
    ///   `request_timeout_ms`.
    /// - `SessionRefused`, `AssociateFailed` or `InitiateFailed` when the peer
    ///   refuses at the Session, ACSE or MMS level.
    /// - `IsoError` or `PduParse` for a malformed answer.
    pub async fn connect(&mut self, host: &str, port: u16) -> Result<(), ClientError> {
        self.reset_association_state();
        self.set_state(ConnectionState::Connecting);
        let timeout_ms = self.connect_timeout_ms;
        let opts = cotp_options(&self.iso_parameters);
        let established = with_timeout(&self.timer, Duration::from_millis(timeout_ms), async {
            let tcp = connect_tcp(host, port).await?;
            // disable Nagle to keep the latency of small PDUs down
            let _ = tcp.set_nodelay(true);
            CotpConnection::connect(tcp, opts)
                .await
                .map_err(|e| association_failed("cotp", e))
        })
        .await;
        let cotp = match established {
            Ok(Ok(cotp)) => cotp,
            Ok(Err(e)) => {
                self.set_state(ConnectionState::Closed);
                return Err(e);
            }
            Err(_) => {
                warn!(
                    host,
                    port, timeout_ms, "the connection was not established in time"
                );
                self.set_state(ConnectionState::Closed);
                return Err(ClientError::ConnectTimeout { timeout_ms });
            }
        };
        debug!("cotp connection established");
        self.finish_association(cotp).await
    }

    /// Runs the association sequence over TLS.
    ///
    /// The TLS handshake is inserted after the TCP connection, and every later step
    /// is identical to the plaintext path. The TCP connection, the handshake and
    /// the COTP CR and CC share one deadline of `connect_timeout_ms`. An
    /// association still established, over TCP or TLS, is closed first without
    /// a release. On failure the connection is left `Closed`. A failed handshake returns
    /// `ClientError::TlsHandshake`, and so does running out of the deadline
    /// during the handshake, with the `Timeout` kind; running out of it during
    /// the TCP connection or the COTP handshake returns `ConnectTimeout`.
    ///
    /// A TLS error after the handshake and before the MMS Initiate response has
    /// been accepted, such as the fatal alert of a TLS 1.3 server refusing the
    /// client certificate, also returns `ClientError::TlsHandshake`, classified
    /// like a failed handshake: `AlertReceived` for a fatal alert and the kind
    /// of the TLS error otherwise. A transport failure with no TLS error behind
    /// it returns the error of the step it interrupted, as on the plaintext
    /// path.
    #[cfg(feature = "tls")]
    pub async fn connect_tls(
        &mut self,
        addr: std::net::SocketAddr,
        connector: &TlsConnector,
        server_name: ServerName<'static>,
    ) -> Result<(), ClientError> {
        let tls_error = Arc::new(std::sync::OnceLock::new());
        let result = self
            .associate_tls(addr, connector, server_name, &tls_error)
            .await
            .map_err(|e| tls_setup_failure(e, tls_error.get()));
        if result.is_err() {
            self.close_raw();
        }
        result
    }

    /// Runs the association sequence over TLS, recording in `tls_error` the
    /// first TLS error the session fails with after the handshake.
    #[cfg(feature = "tls")]
    async fn associate_tls(
        &mut self,
        addr: std::net::SocketAddr,
        connector: &TlsConnector,
        server_name: ServerName<'static>,
        tls_error: &Arc<std::sync::OnceLock<rustls::Error>>,
    ) -> Result<(), ClientError> {
        self.reset_association_state();
        self.set_state(ConnectionState::Connecting);
        let timeout_ms = self.connect_timeout_ms;
        let opts = cotp_options(&self.iso_parameters);

        // Steps 0 to 2: TCP connect, TLS handshake and COTP CR/CC, under one
        // deadline.
        let step = core::sync::atomic::AtomicU8::new(STEP_TCP);
        let established = with_timeout(&self.timer, Duration::from_millis(timeout_ms), async {
            let tcp = TcpStream::connect(addr)
                .await
                .map_err(|e| ClientError::Transport(TransportError::from(e)))?;
            let _ = tcp.set_nodelay(true);
            step.store(STEP_TLS_HANDSHAKE, Ordering::Relaxed);
            let tls_stream = connector
                .connect(server_name, tcp)
                .await
                .map_err(|e: TlsError| ClientError::TlsHandshake {
                    kind: tls_failure_kind(&e),
                    message: tls_failure_message(&e),
                })?;
            debug!("tls handshake complete");
            step.store(STEP_COTP, Ordering::Relaxed);
            let tls_stream = ClientTlsStream {
                inner: tls_stream,
                tls_error: Arc::clone(tls_error),
            };
            CotpConnection::connect(tls_stream, opts)
                .await
                .map_err(|e| association_failed("cotp tls", e))
        })
        .await;
        let mut cotp = match established {
            Ok(result) => result?,
            Err(_) if step.load(Ordering::Relaxed) == STEP_TLS_HANDSHAKE => {
                return Err(ClientError::TlsHandshake {
                    kind: TlsFailureKind::Timeout,
                    message: format!("the handshake did not complete within {timeout_ms} ms"),
                });
            }
            Err(_) => return Err(ClientError::ConnectTimeout { timeout_ms }),
        };
        debug!("cotp connection over tls established");

        // Step 3: Session CN + Presentation CP + ACSE AARQ + MMS Initiate-Request
        {
            let sess_buf = self
                .build_connect_request()
                .map_err(|e| ClientError::IsoError(format!("session cn tls: {e}")))?;

            cotp.send_data(&sess_buf)
                .await
                .map_err(|e| association_failed("cotp tls send", e))?;
        }

        // Step 4: Session AC + Presentation CPA + ACSE AARE + MMS Initiate-Response
        {
            let request_timeout_ms = self.request_timeout_ms;
            let req_dur = Duration::from_millis(request_timeout_ms);
            let raw = with_timeout(&self.timer, req_dur, cotp.recv_data())
                .await
                .map_err(|_| ClientError::ServiceTimeout {
                    timeout_ms: request_timeout_ms,
                })?
                .map_err(|e| association_failed("cotp tls recv", e))?;

            let sess_ind = self
                .session
                .parse_message(&raw)
                .map_err(|e| ClientError::IsoError(format!("session ac tls: {e}")))?;
            check_session_accept(&raw, sess_ind)?;
            let sess_payload: Vec<u8> = self.session.user_data(&raw).to_vec();

            let cpa_result = presentation::parse_accept(&mut self.presentation, &sess_payload)
                .map_err(|e| ClientError::IsoError(format!("pres cpa tls: {e}")))?;
            let acse_payload: Vec<u8> = cpa_result.payload(&sess_payload).to_vec();

            let (acse_ind, mms_init_bytes_ref) = self
                .acse
                .parse_message(&acse_payload)
                .map_err(|e| ClientError::IsoError(format!("acse aare tls: {e}")))?;
            if acse_ind != AcseIndication::Associate {
                warn!("acse association over tls was rejected: {:?}", acse_ind);
                return Err(ClientError::AssociateFailed);
            }
            let mms_init_bytes: Vec<u8> = mms_init_bytes_ref.to_vec();

            let init_pdu = MmsPdu::decode(&mms_init_bytes).map_err(|e| {
                warn!("mms initiate response over tls failed to decode: {e}");
                ClientError::PduParse(format!("{e}"))
            })?;

            match init_pdu {
                MmsPdu::InitiateResponse(resp) => {
                    self.negotiated_max_pdu_size =
                        negotiate_max_pdu_size(self.local_max_pdu_size, resp.local_detail_called);
                    self.negotiated_max_calling = negotiate_max_calling(
                        self.proposed_max_calling(),
                        resp.negotiated_max_serv_outstanding_calling,
                    );
                    self.negotiated_max_called = resp.negotiated_max_serv_outstanding_called;
                    debug!(
                        max_pdu = self.negotiated_max_pdu_size,
                        "mms initiate over tls negotiated"
                    );
                }
                MmsPdu::InitiateError(err_pdu) => {
                    warn!(
                        "mms initiate over tls failed: errorCode={}",
                        err_pdu.service_error.error_class.code()
                    );
                    return Err(ClientError::InitiateFailed {
                        error_code: err_pdu.service_error.error_class.code(),
                    });
                }
                other => {
                    warn!(
                        "expected an mms initiate response over tls, got tag=0x{:02X}",
                        other.tag_byte()
                    );
                    return Err(ClientError::PduParse(format!(
                        "expected InitiateResponse (tls), got tag=0x{:02X}",
                        other.tag_byte()
                    )));
                }
            }
        }

        self.cotp_tls = Some(cotp);
        self.set_state(ConnectionState::Connected);
        Ok(())
    }
}

/// Resolves `host` and connects to the first of its addresses that accepts.
///
/// A bracketed IPv6 literal such as `[::1]` is accepted as well as the bare form.
#[cfg(feature = "std")]
async fn connect_tcp(host: &str, port: u16) -> Result<TcpStream, ClientError> {
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let addrs = tokio::net::lookup_host((host, port)).await.map_err(|e| {
        warn!(host, port, error = %e, "address resolution failed");
        ClientError::Transport(TransportError::from(e))
    })?;
    let mut last_error: Option<std::io::Error> = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(tcp) => return Ok(tcp),
            Err(e) => {
                debug!(%addr, error = %e, "tcp connect attempt failed");
                last_error = Some(e);
            }
        }
    }
    Err(match last_error {
        Some(e) => ClientError::Transport(TransportError::from(e)),
        None => {
            warn!(host, port, "address resolution returned no address");
            ClientError::Transport(
                TransportError::io(IoErrorKind::NotFound)
                    .with_detail(format!("no address for {host}")),
            )
        }
    })
}

// Transport-generic association handling

impl<T: AsyncTransport, Tm: Timer> MmsConnection<T, Tm> {
    /// Runs the ISO and MMS Initiate sequence over an already connected transport.
    ///
    /// This is the entry point for callers that own the transport themselves, an
    /// embedded IP stack for instance. Only the COTP handshake and the
    /// Session, Presentation, ACSE and MMS Initiate negotiation happen here.
    ///
    /// `connect` and `connect_tls` establish their own transport and COTP
    /// connection under one deadline and then run the same negotiation. An
    /// association still established, over any transport, is closed first
    /// without a release. On failure the connection is left `Closed`.
    ///
    /// The COTP CR and CC are bounded by `connect_timeout_ms`.
    ///
    /// # Errors
    ///
    /// - `ConnectTimeout` when the COTP handshake does not complete within
    ///   `connect_timeout_ms`.
    /// - `ServiceTimeout` when the Initiate response does not arrive within
    ///   `request_timeout_ms`.
    /// - `SessionRefused`, `AssociateFailed` or `InitiateFailed` when the peer
    ///   refuses at the Session, ACSE or MMS level.
    /// - `IsoError` or `PduParse` for a malformed answer.
    pub async fn connect_via(&mut self, transport: T) -> Result<(), ClientError> {
        self.reset_association_state();
        self.set_state(ConnectionState::Connecting);

        // Step 1+2: COTP CR/CC handshake
        let opts = cotp_options(&self.iso_parameters);
        let timeout_ms = self.connect_timeout_ms;
        let established = with_timeout(
            &self.timer,
            Duration::from_millis(timeout_ms),
            CotpConnection::connect(transport, opts),
        )
        .await;
        let cotp = match established {
            Ok(Ok(cotp)) => cotp,
            Ok(Err(e)) => {
                self.set_state(ConnectionState::Closed);
                return Err(association_failed("cotp", e));
            }
            Err(_) => {
                self.set_state(ConnectionState::Closed);
                return Err(ClientError::ConnectTimeout { timeout_ms });
            }
        };
        debug!("cotp connection established over the supplied transport");
        self.finish_association(cotp).await
    }

    /// Runs the Session, Presentation, ACSE and MMS Initiate negotiation over
    /// an established COTP connection, leaving the connection `Closed` on
    /// failure.
    async fn finish_association(&mut self, mut cotp: CotpConnection<T>) -> Result<(), ClientError> {
        // ISO negotiation and the MMS Initiate exchange
        if let Err(e) = self.run_initiate_handshake(&mut cotp).await {
            self.set_state(ConnectionState::Closed);
            return Err(e);
        }

        self.cotp = Some(cotp);
        self.set_state(ConnectionState::Connected);
        Ok(())
    }

    /// Returns the proposedMaxServOutstandingCalling of the next Initiate
    /// request, at least 1.
    fn proposed_max_calling(&self) -> u16 {
        self.local_max_outstanding
            .unwrap_or(DEFAULT_MAX_SERV_OUTSTANDING_CALLING)
            .max(1)
    }

    /// Waits until another confirmed request may be sent without exceeding
    /// `negotiated_max_calling`.
    ///
    /// A request that timed out stays outstanding at the server until its late
    /// answer arrives, so it counts against the limit together with the request
    /// about to be sent. While the limit is reached, the connection reads on
    /// within `request_timeout_ms`, discarding late answers and stashing
    /// Unconfirmed PDUs, until a late answer frees a slot. With no request
    /// timed out, it returns at once.
    ///
    /// # Errors
    ///
    /// - `OutstandingCallLimit` when no late answer frees a slot in time; the
    ///   association stays established, but a slot held by a request the peer
    ///   discarded is freed only by a new association.
    /// - The receive errors of [`Self::recv_mms_pdu`].
    pub(crate) async fn reserve_outstanding_slot(&mut self) -> Result<(), ClientError> {
        let limit = usize::from(self.negotiated_max_calling.max(1));
        if self.abandoned_invoke_ids.len() < limit {
            return Ok(());
        }
        let timeout_ms = self.request_timeout_ms;
        let timer = self.timer.clone();
        match with_timeout(
            &timer,
            Duration::from_millis(timeout_ms),
            self.await_outstanding_slot(limit),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                warn!(
                    limit,
                    timeout_ms,
                    "every outstanding request slot is held by a request that timed out"
                );
                Err(ClientError::OutstandingCallLimit)
            }
        }
    }

    /// Drops everything an earlier association left behind before a new one
    /// starts: both transports, the Session, Presentation and ACSE states, the
    /// negotiated parameters and the per-association queues.
    ///
    /// An association still established is closed without a release, as by
    /// [`Self::close_raw`], so nothing of it can carry over to the new one.
    fn reset_association_state(&mut self) {
        if self.state == ConnectionState::Connected {
            warn!("a new association replaces an established one, closing it without a release");
        }
        self.cotp = None;
        #[cfg(feature = "tls")]
        {
            self.cotp_tls = None;
        }
        self.session = IsoSession::new();
        self.presentation = IsoPresentation::new();
        self.acse = AcseConnection::new(None);
        self.negotiated_max_pdu_size = DEFAULT_MAX_PDU_SIZE as usize;
        self.negotiated_max_calling = DEFAULT_MAX_SERV_OUTSTANDING_CALLING;
        self.negotiated_max_called = DEFAULT_MAX_SERV_OUTSTANDING_CALLED;
        self.pending_unconfirmed.clear();
        self.abandoned_invoke_ids.clear();
    }

    /// Builds the Session CN SPDU carrying the Presentation CP, the ACSE AARQ and
    /// the MMS Initiate request.
    ///
    /// Every address written here comes from `iso_parameters`: the session
    /// selectors, the presentation selectors and the AARQ AP-title and
    /// AE-qualifier fields. The T-Selectors reach the wire through the COTP
    /// options instead, as the CR TPDU carries them.
    fn build_connect_request(&self) -> Result<BytesMut, session::SessionError> {
        let mut mms_buf = BytesMut::new();
        let mut init_req = InitiateRequestPdu::default();
        if let Some(size) = self.local_max_pdu_size {
            init_req.local_detail_calling = Some(size);
        }
        init_req.proposed_max_serv_outstanding_calling = self.proposed_max_calling();
        init_req.encode(&mut mms_buf);

        let mut acse_buf = BytesMut::new();
        acse::encode_aarq(
            &mms_buf,
            None,
            ACSE_INDIRECT_REFERENCE,
            &self.iso_parameters.aarq_addressing(),
            &mut acse_buf,
        );

        let pres_params = PresentationConnectionParameters {
            local_p_sel: self.iso_parameters.local_p_sel.clone(),
            remote_p_sel: self.iso_parameters.remote_p_sel.clone(),
        };
        let mut pres_buf = BytesMut::new();
        presentation::encode_connect(&pres_params, &acse_buf, &mut pres_buf);

        let sess_params = IsoParameters {
            local_selector: self.iso_parameters.local_s_sel.clone(),
            remote_selector: self.iso_parameters.remote_s_sel.clone(),
        };
        let mut sess_buf = BytesMut::new();
        session::encode_connect(&sess_params, &self.session, &pres_buf, &mut sess_buf)?;
        Ok(sess_buf)
    }

    /// Sends Session CN, Presentation CP, ACSE AARQ and the MMS Initiate request, then
    /// awaits Session AC, Presentation CPA, ACSE AARE and the Initiate response.
    ///
    /// Shared by the TCP, TLS and transport-generic entry points so the sequence lives
    /// in one place.
    async fn run_initiate_handshake(
        &mut self,
        cotp: &mut CotpConnection<T>,
    ) -> Result<(), ClientError> {
        // Step 3
        {
            let sess_buf = self
                .build_connect_request()
                .map_err(|e| ClientError::IsoError(format!("session cn: {e}")))?;

            cotp.send_data(&sess_buf)
                .await
                .map_err(|e| association_failed("cotp send", e))?;
        }

        // Step 4
        let request_timeout_ms = self.request_timeout_ms;
        let req_dur = Duration::from_millis(request_timeout_ms);
        let raw = with_timeout(&self.timer, req_dur, cotp.recv_data())
            .await
            .map_err(|_| ClientError::ServiceTimeout {
                timeout_ms: request_timeout_ms,
            })?
            .map_err(|e| association_failed("cotp recv", e))?;

        let sess_ind = self
            .session
            .parse_message(&raw)
            .map_err(|e| ClientError::IsoError(format!("session ac: {e}")))?;
        check_session_accept(&raw, sess_ind)?;
        let sess_payload: Vec<u8> = self.session.user_data(&raw).to_vec();

        let cpa_result = presentation::parse_accept(&mut self.presentation, &sess_payload)
            .map_err(|e| ClientError::IsoError(format!("pres cpa: {e}")))?;
        let acse_payload: Vec<u8> = cpa_result.payload(&sess_payload).to_vec();

        let (acse_ind, mms_init_bytes_ref) = self
            .acse
            .parse_message(&acse_payload)
            .map_err(|e| ClientError::IsoError(format!("acse aare: {e}")))?;
        if acse_ind != AcseIndication::Associate {
            warn!("acse association was rejected: {:?}", acse_ind);
            return Err(ClientError::AssociateFailed);
        }
        let mms_init_bytes: Vec<u8> = mms_init_bytes_ref.to_vec();

        let init_pdu = MmsPdu::decode(&mms_init_bytes).map_err(|e| {
            warn!("mms initiate response failed to decode: {e}");
            ClientError::PduParse(format!("{e}"))
        })?;

        match init_pdu {
            MmsPdu::InitiateResponse(resp) => {
                self.negotiated_max_pdu_size =
                    negotiate_max_pdu_size(self.local_max_pdu_size, resp.local_detail_called);
                self.negotiated_max_calling = negotiate_max_calling(
                    self.proposed_max_calling(),
                    resp.negotiated_max_serv_outstanding_calling,
                );
                self.negotiated_max_called = resp.negotiated_max_serv_outstanding_called;
                debug!(
                    max_pdu = self.negotiated_max_pdu_size,
                    "mms initiate negotiated"
                );
                Ok(())
            }
            MmsPdu::InitiateError(err_pdu) => {
                warn!(
                    "mms initiate failed: errorCode={}",
                    err_pdu.service_error.error_class.code()
                );
                Err(ClientError::InitiateFailed {
                    error_code: err_pdu.service_error.error_class.code(),
                })
            }
            other => {
                warn!(
                    "expected an mms initiate response, got tag=0x{:02X}",
                    other.tag_byte()
                );
                Err(ClientError::PduParse(format!(
                    "expected InitiateResponse, got tag=0x{:02X}",
                    other.tag_byte()
                )))
            }
        }
    }

    /// Releases the association and closes the connection.
    ///
    /// The sequence is the MMS Conclude exchange, then the ACSE A-RELEASE: an RLRQ
    /// carried by a Session FN, answered by an RLRE carried by the Session DN
    /// (ISO 8650-1, ISO 8327-1). The release response is awaited for at most
    /// `request_timeout_ms`; a peer that closes the transport instead, or does
    /// not answer, still ends with the connection closed. InformationReports
    /// arriving before the Conclude response are stashed, not taken for it.
    ///
    /// A caller-initiated disconnect does not invoke the connection-lost handler.
    ///
    /// # Errors
    ///
    /// - `NotConnected` when no association is established.
    /// - `ConcludeRejected` when the peer answers with a Conclude-ErrorPDU; the
    ///   association then stays `Connected`.
    /// - The transport error when the Conclude request cannot be sent; the
    ///   connection is closed.
    pub async fn disconnect(&mut self) -> Result<(), ClientError> {
        if self.state != ConnectionState::Connected {
            return Err(ClientError::NotConnected {
                state: format!("{:?}", self.state),
            });
        }
        self.set_state(ConnectionState::Closing);

        if let Err(e) = self.send_mms_pdu(&MmsPdu::ConcludeRequest).await {
            self.close_raw();
            return Err(e);
        }

        let timeout_ms = self.request_timeout_ms;
        let timer = self.timer.clone();
        match with_timeout(
            &timer,
            Duration::from_millis(timeout_ms),
            self.await_conclude_response(),
        )
        .await
        {
            Ok(Ok(())) => {
                debug!("received a conclude response, releasing the association");
                self.release_association().await;
            }
            Ok(Err(ClientError::ConcludeRejected)) => {
                self.set_state(ConnectionState::Connected);
                return Err(ClientError::ConcludeRejected);
            }
            Ok(Err(e)) => {
                warn!("failed to receive a conclude response: {e}, closing anyway");
            }
            Err(_) => {
                warn!(timeout_ms, "no conclude response arrived, closing anyway");
            }
        }

        self.close_raw();
        Ok(())
    }

    /// Aborts the association and closes the connection.
    ///
    /// Sends an ACSE ABRT with abort-source acse-service-user inside a Session
    /// AB (ISO 8650-1 A-ABORT), then closes the transport without waiting for any
    /// answer. A connection that is already closed is left as it is.
    ///
    /// # Errors
    ///
    /// The transport error when the abort cannot be sent; the connection is
    /// closed either way.
    pub async fn abort(&mut self) -> Result<(), ClientError> {
        if self.state == ConnectionState::Closed {
            return Ok(());
        }
        let mut abrt = [0u8; 5];
        acse::encode_abrt(false, &mut abrt);
        let mut pres_buf = BytesMut::new();
        presentation::encode_abort(&self.presentation, &abrt, &mut pres_buf);
        let mut sess_buf = BytesMut::new();
        let result = match session::encode_abort(&pres_buf, &mut sess_buf) {
            Ok(()) => self.send_tsdu(&sess_buf, "abort").await,
            Err(e) => Err(ClientError::IsoError(format!("session ab: {e}"))),
        };
        self.close_raw();
        result
    }

    /// Closes the transport immediately, without any release handshake.
    ///
    /// The connection-lost handler is not invoked. Dropping the `CotpConnection`
    /// closes the underlying transport.
    pub fn close_raw(&mut self) {
        self.cotp = None;
        #[cfg(feature = "tls")]
        {
            self.cotp_tls = None;
        }
        self.abandoned_invoke_ids.clear();
        self.set_state(ConnectionState::Closed);
    }

    /// Sends an MMS PDU wrapped in the full ISO stack.
    ///
    /// An encoded MMS PDU larger than `negotiated_max_pdu_size` returns
    /// `PduTooLarge` instead of being sent; the Presentation and Session
    /// wrappers do not count toward the limit.
    ///
    /// # Errors
    ///
    /// - `PduTooLarge` as above.
    /// - `NotConnected` when there is no transport.
    /// - `ConnectionLost` when the peer has closed the transport, and
    ///   `Transport` when the transport reports an I/O error; either way the
    ///   connection is closed.
    pub async fn send_mms_pdu(&mut self, pdu: &MmsPdu) -> Result<(), ClientError> {
        // MMS PDU encode
        let mut mms_buf = BytesMut::new();
        pdu.encode(&mut mms_buf);

        // outbound PDU size guard
        if mms_buf.len() > self.negotiated_max_pdu_size {
            warn!(
                pdu_size = mms_buf.len(),
                max_size = self.negotiated_max_pdu_size,
                "pdu exceeds the negotiated maximum size, refusing to send"
            );
            return Err(ClientError::PduTooLarge {
                pdu_size: mms_buf.len(),
                max_size: self.negotiated_max_pdu_size,
            });
        }

        // wrap in Presentation Fully-Encoded-Data
        let mut pres_buf = BytesMut::new();
        presentation::encode_user_data(&self.presentation, &mms_buf, &mut pres_buf);

        // wrap in a Session data SPDU
        let mut session_buf = BytesMut::new();
        session::encode_data(&pres_buf, &mut session_buf);

        self.send_tsdu(&session_buf, "send").await
    }

    /// Receives one MMS PDU, parsing the full ISO stack, under a timeout.
    ///
    /// A `timeout_dur` of `None` uses `request_timeout_ms`, and `Some(d)` uses `d`;
    /// no other timeout applies.
    ///
    /// Cancel safety: `cotp.recv_data` and `read_tpkt` keep their partial state inside
    /// the COTP connection, so a timeout loses no bytes and the next call resumes from
    /// the same point.
    ///
    /// Returns:
    /// - `Ok(Some(pdu))` when a PDU arrived.
    /// - `Ok(None)` when no complete PDU arrived within the timeout.
    /// - `Err(_)` on an I/O failure or a parse failure; `ConnectionLost` when the
    ///   peer ended the connection.
    pub async fn recv_mms_pdu_with_timeout(
        &mut self,
        timeout_dur: Option<Duration>,
    ) -> Result<Option<MmsPdu>, ClientError> {
        let dur = timeout_dur.unwrap_or_else(|| Duration::from_millis(self.request_timeout_ms));
        // The timer is cloned so borrowing it does not conflict with the mutable
        // borrow of self. Timer requires Clone and is cheap to clone in every backend.
        let timer = self.timer.clone();
        match with_timeout(&timer, dur, self.recv_pdu()).await {
            Ok(Ok(pdu)) => Ok(Some(pdu)),
            Ok(Err(e)) => Err(e),
            // the partial read state stays in the COTP connection
            Err(_) => Ok(None),
        }
    }

    /// Receives one PDU for a confirmed call, stashing any Unconfirmed PDU in
    /// `pending_unconfirmed` and reading on until a non-Unconfirmed PDU arrives.
    ///
    /// The invokeID of the answer is not examined; [`Self::recv_confirmed_response`]
    /// binds the answer to its request. The whole wait is bounded by
    /// `request_timeout_ms`.
    ///
    /// # Errors
    ///
    /// `ServiceTimeout` when nothing but Unconfirmed PDUs arrives in time, and the
    /// receive errors of [`Self::recv_mms_pdu`].
    pub async fn recv_mms_pdu_confirmed(&mut self) -> Result<MmsPdu, ClientError> {
        let timeout_ms = self.request_timeout_ms;
        let timer = self.timer.clone();
        match with_timeout(
            &timer,
            Duration::from_millis(timeout_ms),
            self.await_non_unconfirmed(),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(ClientError::ServiceTimeout { timeout_ms }),
        }
    }

    /// Receives the answer to the confirmed request sent with `invoke_id`.
    ///
    /// Unconfirmed PDUs arriving meanwhile are stashed in `pending_unconfirmed`. A
    /// Confirmed-Response, Confirmed-Error or Reject PDU carrying another invokeID
    /// is discarded with a warning; when that invokeID belongs to a request that
    /// timed out earlier, it is forgotten at the same time. A Reject without an
    /// originalInvokeID is taken as the answer. The whole wait is bounded by
    /// `request_timeout_ms`.
    ///
    /// # Errors
    ///
    /// - `ServiceTimeout` when no answer arrives in time. `invoke_id` is then
    ///   remembered as abandoned and the association stays usable.
    /// - `PduParse` when the invokeID of an answer does not decode.
    /// - The receive errors of [`Self::recv_mms_pdu`].
    pub async fn recv_confirmed_response(&mut self, invoke_id: u32) -> Result<MmsPdu, ClientError> {
        let timeout_ms = self.request_timeout_ms;
        let timer = self.timer.clone();
        match with_timeout(
            &timer,
            Duration::from_millis(timeout_ms),
            self.await_response(invoke_id),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                warn!(
                    invoke_id,
                    timeout_ms, "no answer within the request timeout, abandoning the request"
                );
                if self.state == ConnectionState::Connected {
                    self.abandon_invoke_id(invoke_id);
                }
                Err(ClientError::ServiceTimeout { timeout_ms })
            }
        }
    }

    /// Receives one MMS PDU, parsing the full ISO stack, within `request_timeout_ms`.
    ///
    /// A Conclude request from the server (`0x8b`) is answered with `0x8c`, the
    /// transport is closed, and the call returns `Err(ReleasedByPeer)`.
    ///
    /// # Errors
    ///
    /// - `ServiceTimeout` when no complete PDU arrives in time.
    /// - `ReleasedByPeer` when the peer releases the association with a Session
    ///   FN or a Conclude request; the release is answered and the connection
    ///   is closed.
    /// - `ConnectionLost` when the transport ends, a COTP DR arrives, or the peer
    ///   sends a Session AB or DN; the connection is closed.
    /// - `Transport` when the transport reports an I/O error; the connection is
    ///   closed.
    /// - `NotConnected` when there is no transport.
    /// - `IsoError` or `PduParse` for a PDU that does not decode.
    pub async fn recv_mms_pdu(&mut self) -> Result<MmsPdu, ClientError> {
        let timeout_ms = self.request_timeout_ms;
        let timer = self.timer.clone();
        match with_timeout(&timer, Duration::from_millis(timeout_ms), self.recv_pdu()).await {
            Ok(result) => result,
            Err(_) => Err(ClientError::ServiceTimeout { timeout_ms }),
        }
    }

    /// Receives the next Unconfirmed PDU within `timeout_dur`.
    ///
    /// The late answer to an abandoned request is discarded on the way. Returns
    /// `Ok(None)` when no Unconfirmed PDU arrives in time.
    pub(crate) async fn recv_unconfirmed(
        &mut self,
        timeout_dur: Duration,
    ) -> Result<Option<Bytes>, ClientError> {
        let timer = self.timer.clone();
        match with_timeout(&timer, timeout_dur, self.await_unconfirmed()).await {
            Ok(result) => result.map(Some),
            Err(_) => Ok(None),
        }
    }

    // Receive loops; each caller bounds one with a single timeout.

    async fn await_non_unconfirmed(&mut self) -> Result<MmsPdu, ClientError> {
        loop {
            match self.recv_pdu().await? {
                MmsPdu::Unconfirmed(inner) => self.stash_unconfirmed(inner),
                pdu => return Ok(pdu),
            }
        }
    }

    async fn await_response(&mut self, invoke_id: u32) -> Result<MmsPdu, ClientError> {
        loop {
            let pdu = self.recv_pdu().await?;
            if let MmsPdu::Unconfirmed(inner) = pdu {
                self.stash_unconfirmed(inner);
                continue;
            }
            match response_invoke_id(&pdu) {
                Ok(Some(id)) if id == invoke_id => return Ok(pdu),
                Ok(Some(id)) => self.discard_stray_answer(id, &pdu),
                Ok(None) => return Ok(pdu),
                Err(e) => return Err(e),
            }
        }
    }

    async fn await_outstanding_slot(&mut self, limit: usize) -> Result<(), ClientError> {
        while self.abandoned_invoke_ids.len() >= limit {
            let pdu = self.recv_pdu().await?;
            if let MmsPdu::Unconfirmed(inner) = pdu {
                self.stash_unconfirmed(inner);
                continue;
            }
            match response_invoke_id(&pdu) {
                Ok(Some(id)) => self.discard_stray_answer(id, &pdu),
                _ => warn!(
                    tag = format!("0x{:02x}", pdu.tag_byte()),
                    "discarding a pdu received while no request is outstanding"
                ),
            }
        }
        Ok(())
    }

    async fn await_unconfirmed(&mut self) -> Result<Bytes, ClientError> {
        loop {
            let pdu = self.recv_pdu().await?;
            if let MmsPdu::Unconfirmed(inner) = pdu {
                if inner.is_empty() {
                    warn!("discarding an unconfirmed pdu without an unconfirmed service");
                    continue;
                }
                return Ok(inner);
            }
            if let Ok(Some(id)) = response_invoke_id(&pdu) {
                if self.take_abandoned(id) {
                    warn!(
                        invoke_id = id,
                        "discarding the late answer to a request that timed out"
                    );
                    continue;
                }
            }
            warn!(
                tag = format!("0x{:02x}", pdu.tag_byte()),
                "received a pdu that is not unconfirmed while no request is outstanding, discarding it"
            );
            return Err(ClientError::PduParse(format!(
                "expected Unconfirmed (0xa3), got tag=0x{:02x}",
                pdu.tag_byte()
            )));
        }
    }

    async fn await_conclude_response(&mut self) -> Result<(), ClientError> {
        loop {
            let mms_bytes = self.recv_mms_bytes().await?;
            if mms_bytes.first() == Some(&TAG_CONCLUDE_ERROR) {
                warn!("the peer refused the conclude request");
                return Err(ClientError::ConcludeRejected);
            }
            let pdu = MmsPdu::decode(&mms_bytes).map_err(|e| {
                warn!("mms pdu failed to decode: {e}");
                ClientError::PduParse(format!("{e}"))
            })?;
            match pdu {
                MmsPdu::ConcludeResponse => return Ok(()),
                MmsPdu::Unconfirmed(inner) => self.stash_unconfirmed(inner),
                other => warn!(
                    tag = format!("0x{:02x}", other.tag_byte()),
                    "discarding a pdu received while awaiting the conclude response"
                ),
            }
        }
    }

    /// Sends the A-RELEASE request and waits, within `request_timeout_ms`, for
    /// the peer to answer or close.
    async fn release_association(&mut self) {
        let mut rlrq = [0u8; 5];
        acse::encode_rlrq(&mut rlrq);
        let mut pres_buf = BytesMut::new();
        presentation::encode_user_data_acse(&self.presentation, &rlrq, &mut pres_buf);
        let mut sess_buf = BytesMut::new();
        if let Err(e) = session::encode_finish(&pres_buf, &mut sess_buf) {
            warn!("session fn failed to encode: {e}");
            return;
        }
        if self.send_tsdu(&sess_buf, "release").await.is_err() {
            return;
        }
        let timeout_ms = self.request_timeout_ms;
        let timer = self.timer.clone();
        if with_timeout(
            &timer,
            Duration::from_millis(timeout_ms),
            self.await_release_response(),
        )
        .await
        .is_err()
        {
            warn!(timeout_ms, "no release response arrived, closing anyway");
        }
    }

    async fn await_release_response(&mut self) {
        loop {
            let Ok(raw) = self.recv_tsdu().await else {
                return;
            };
            match self.session.parse_message(&raw) {
                Ok(SessionIndication::Disconnect) => {
                    let user_data = self.session.user_data(&raw).to_vec();
                    let carries_rlre =
                        presentation::parse_user_data(&mut self.presentation, &user_data)
                            .ok()
                            .and_then(|ud| user_data.get(ud.payload_start).copied())
                            == Some(TAG_ACSE_RLRE);
                    if carries_rlre {
                        debug!("received the release response");
                    } else {
                        warn!("the session disconnect carries no acse rlre");
                    }
                    return;
                }
                Ok(SessionIndication::Abort) => {
                    warn!("the peer aborted the association during the release");
                    return;
                }
                Ok(SessionIndication::Finish) => {
                    debug!("release collision: the peer sent its own session finish");
                }
                Ok(other) => {
                    debug!(
                        indication = ?other,
                        "discarding an spdu received while awaiting the release response"
                    );
                }
                Err(e) => {
                    warn!("session spdu failed to parse during the release: {e}");
                    return;
                }
            }
        }
    }

    // Single-PDU receive, without a timeout of its own.

    /// Receives one MMS PDU; a Conclude request from the server ends the connection.
    async fn recv_pdu(&mut self) -> Result<MmsPdu, ClientError> {
        let mms_bytes = self.recv_mms_bytes().await?;
        let pdu = MmsPdu::decode(&mms_bytes).map_err(|e| {
            warn!("mms pdu failed to decode: {e}");
            ClientError::PduParse(format!("{e}"))
        })?;

        if pdu == MmsPdu::ConcludeRequest {
            warn!(
                "received a conclude request (0x8b) from the server, answering with 0x8c and closing"
            );
            let _ = self.send_mms_pdu(&MmsPdu::ConcludeResponse).await;
            self.close_raw();
            return Err(ClientError::ReleasedByPeer);
        }

        Ok(pdu)
    }

    /// Answers the peer's Session FN with a Session DN carrying an ACSE RLRE.
    ///
    /// `finish_user_data` is the user data of the FN, which should hold the
    /// peer's RLRQ; the RLRE is sent either way, so the peer is never left
    /// without an answer.
    async fn answer_peer_release(&mut self, finish_user_data: &[u8]) {
        let carries_rlrq = presentation::parse_user_data(&mut self.presentation, finish_user_data)
            .ok()
            .and_then(|ud| finish_user_data.get(ud.payload_start).copied())
            == Some(TAG_ACSE_RLRQ);
        if !carries_rlrq {
            warn!("the session finish from the peer carries no acse rlrq");
        }
        let mut rlre = [0u8; 2];
        acse::encode_rlre(&mut rlre);
        let mut pres_buf = BytesMut::new();
        presentation::encode_user_data_acse(&self.presentation, &rlre, &mut pres_buf);
        let mut sess_buf = BytesMut::new();
        match session::encode_disconnect(&pres_buf, &mut sess_buf) {
            Ok(()) => {
                if self.send_tsdu(&sess_buf, "release response").await.is_ok() {
                    debug!("answered the release request of the peer");
                }
            }
            Err(e) => warn!("session dn failed to encode: {e}"),
        }
    }

    /// Receives one TSDU and returns the MMS bytes of its Session DT and
    /// Presentation user data.
    async fn recv_mms_bytes(&mut self) -> Result<Vec<u8>, ClientError> {
        let raw = self.recv_tsdu().await?;

        let sess_ind = self
            .session
            .parse_message(&raw)
            .map_err(|e| ClientError::IsoError(format!("session: {e}")))?;
        match sess_ind {
            SessionIndication::Data => {}
            SessionIndication::Finish => {
                warn!("the peer released the association, answering and closing the connection");
                let user_data = self.session.user_data(&raw).to_vec();
                self.answer_peer_release(&user_data).await;
                self.close_raw();
                return Err(ClientError::ReleasedByPeer);
            }
            SessionIndication::Abort | SessionIndication::Disconnect => {
                warn!(indication = ?sess_ind, "the peer ended the session, closing the connection");
                self.close_raw();
                return Err(ClientError::ConnectionLost);
            }
            other => {
                warn!("received a non-data session spdu: {:?}", other);
                return Err(ClientError::IsoError(format!(
                    "unexpected session indication: {other:?}"
                )));
            }
        }

        let sess_payload: Vec<u8> = self.session.user_data(&raw).to_vec();
        let ud_result = presentation::parse_user_data(&mut self.presentation, &sess_payload)
            .map_err(|e| ClientError::IsoError(format!("presentation: {e}")))?;
        Ok(ud_result.payload(&sess_payload).to_vec())
    }

    /// Sends one TSDU over whichever transport is open; the TLS one takes
    /// precedence when the feature is enabled.
    async fn send_tsdu(&mut self, data: &[u8], context: &str) -> Result<(), ClientError> {
        let state = self.state;
        #[cfg(feature = "tls")]
        if let Some(cotp) = self.cotp_tls.as_mut() {
            let result = cotp.send_data(data).await;
            return result.map_err(|e| self.transport_failed(context, e));
        }
        let result = match self.cotp.as_mut() {
            Some(cotp) => cotp.send_data(data).await,
            None => return Err(not_connected(state)),
        };
        result.map_err(|e| self.transport_failed(context, e))
    }

    /// Receives one TSDU from whichever transport is open.
    async fn recv_tsdu(&mut self) -> Result<Bytes, ClientError> {
        let state = self.state;
        #[cfg(feature = "tls")]
        if let Some(cotp) = self.cotp_tls.as_mut() {
            let result = cotp.recv_data().await;
            return result.map_err(|e| self.transport_failed("recv", e));
        }
        let result = match self.cotp.as_mut() {
            Some(cotp) => cotp.recv_data().await,
            None => return Err(not_connected(state)),
        };
        result.map_err(|e| self.transport_failed("recv", e))
    }

    /// Closes the connection after a COTP failure and maps the failure.
    ///
    /// The end of the transport and a COTP DR become `ConnectionLost`, an I/O
    /// error becomes `Transport` with its cause, and a framing error becomes
    /// `IsoError`.
    fn transport_failed(&mut self, context: &str, e: CotpError) -> ClientError {
        self.close_raw();
        match e {
            CotpError::UnexpectedEof | CotpError::DisconnectRequest { .. } => {
                warn!(error = %e, "cotp {context}: the transport connection was lost");
                ClientError::ConnectionLost
            }
            CotpError::Io(cause) => {
                warn!(error = %cause, "cotp {context}: the transport failed, closing the connection");
                ClientError::Transport(cause)
            }
            other => {
                warn!(error = %other, "cotp {context} failed, closing the connection");
                ClientError::IsoError(format!("cotp {context}: {other}"))
            }
        }
    }

    /// Stashes an Unconfirmed PDU received during a confirmed exchange.
    ///
    /// An Unconfirmed PDU without content carries no unconfirmedService, which
    /// is mandatory, so it is discarded rather than stashed.
    fn stash_unconfirmed(&mut self, inner: Bytes) {
        if inner.is_empty() {
            warn!("discarding an unconfirmed pdu without an unconfirmed service");
            return;
        }
        debug!(
            "stashing an unconfirmed pdu of {} bytes for a later unconfirmed read",
            inner.len()
        );
        self.push_pending_unconfirmed(inner);
    }

    /// Discards an answer whose invokeID is not the one awaited.
    fn discard_stray_answer(&mut self, invoke_id: u32, pdu: &MmsPdu) {
        if self.take_abandoned(invoke_id) {
            warn!(
                invoke_id,
                tag = format!("0x{:02x}", pdu.tag_byte()),
                "discarding the late answer to a request that timed out"
            );
        } else {
            warn!(
                invoke_id,
                tag = format!("0x{:02x}", pdu.tag_byte()),
                "discarding an answer whose invokeid matches no outstanding request"
            );
        }
    }
}

impl<T, Tm: Default> Default for MmsConnection<T, Tm> {
    fn default() -> Self {
        Self::new()
    }
}

// Association helpers

/// Returns the COTP options for an association: the T-Selectors of
/// `params` and the default TPDU size.
fn cotp_options(params: &IsoConnectionParameters) -> CotpOptions {
    CotpOptions {
        tsel_src: params.local_t_sel.clone(),
        tsel_dst: params.remote_t_sel.clone(),
        tpdu_size: crate::iso::cotp::TpduSize::default(),
    }
}

/// Maps a COTP failure met while the association is being established.
///
/// An I/O error becomes `Transport` with its cause, the end of the transport
/// and a COTP DR become `ConnectionLost`, and a framing error becomes
/// `IsoError` prefixed with `context`.
fn association_failed(context: &str, e: CotpError) -> ClientError {
    match e {
        CotpError::Io(cause) => ClientError::Transport(cause),
        CotpError::UnexpectedEof | CotpError::DisconnectRequest { .. } => {
            ClientError::ConnectionLost
        }
        other => ClientError::IsoError(format!("{context}: {other}")),
    }
}

/// Returns the negotiated outstanding calling limit: the server's answer,
/// never above the local proposal and never below 1.
fn negotiate_max_calling(local_proposal: u16, server_answer: u16) -> u16 {
    server_answer.clamp(1, local_proposal.max(1))
}

/// Returns the negotiated maximum PDU size: the smaller of the local proposal
/// and the size the server answered. A server that omits `localDetailCalled`
/// leaves the local proposal in force.
fn negotiate_max_pdu_size(local_proposal: Option<u32>, server_answer: Option<u32>) -> usize {
    let local = local_proposal.unwrap_or(DEFAULT_MAX_PDU_SIZE);
    let server = server_answer.unwrap_or(local);
    local.min(server) as usize
}

fn not_connected(state: ConnectionState) -> ClientError {
    ClientError::NotConnected {
        state: format!("{state:?}"),
    }
}

/// Returns the invokeID a confirmed answer carries.
///
/// `Ok(None)` for a PDU that carries none: a Reject without originalInvokeID,
/// or a PDU that is not an answer to a confirmed request.
fn response_invoke_id(pdu: &MmsPdu) -> Result<Option<u32>, ClientError> {
    let decoded = match pdu {
        // invokeID Unsigned32, a UNIVERSAL INTEGER
        MmsPdu::ConfirmedResponse(inner) => leading_unsigned32(inner, 0x02),
        // invokeID [0] IMPLICIT Unsigned32
        MmsPdu::ConfirmedError(inner) => leading_unsigned32(inner, 0x80),
        MmsPdu::Reject(reject) => return Ok(reject.invoke_id),
        _ => return Ok(None),
    };
    match decoded {
        Some(id) => Ok(Some(id)),
        None => {
            warn!(
                tag = format!("0x{:02x}", pdu.tag_byte()),
                "the invokeid of a confirmed answer does not decode, rejecting it"
            );
            Err(ClientError::PduParse(
                "the invokeid of a confirmed answer does not decode".to_string(),
            ))
        }
    }
}

/// Decodes the Unsigned32 that opens `content` under `tag`.
fn leading_unsigned32(content: &[u8], tag: u8) -> Option<u32> {
    if content.first() != Some(&tag) {
        return None;
    }
    let (len, header) = iec61850_asn1::decode_length(content.get(1..)?).ok()?;
    let start = 1 + header;
    let value = content.get(start..start.checked_add(len)?)?;
    // a value of 2^31 or more carries a leading zero octet
    let value = match value {
        [0x00, rest @ ..] if rest.len() == 4 => rest,
        _ => value,
    };
    if value.is_empty() || value.len() > 4 {
        return None;
    }
    Some(value.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b)))
}

/// Accepts a Session AC and turns every other indication into an error.
///
/// A REFUSE becomes `ClientError::SessionRefused`, carrying the reason code and
/// the transport disconnect parameter of the RF SPDU together with the
/// provider-reason of the CPR PPDU it carries, when that decodes. `raw` is the
/// SPDU the indication was parsed from, which the refusal user data borrows
/// from.
fn check_session_accept(raw: &[u8], indication: SessionIndication) -> Result<(), ClientError> {
    match indication {
        SessionIndication::Accept => Ok(()),
        SessionIndication::Refuse(info) => {
            let provider_reason = presentation::parse_reject(info.user_data(raw))
                .ok()
                .and_then(|reject| reject.provider_reason);
            warn!(
                reason_code = ?info.reason_code,
                provider_reason = ?provider_reason,
                "the peer refused the session connect request"
            );
            Err(ClientError::SessionRefused {
                reason_code: info.reason_code,
                transport_disconnect: info.transport_disconnect,
                provider_reason,
            })
        }
        other => {
            warn!("expected a session accept, got {:?}", other);
            Err(ClientError::IsoError(format!(
                "expected Session AC, got {other:?}"
            )))
        }
    }
}

// Unit tests

#[cfg(all(test, feature = "tls"))]
mod tls_failure_tests {
    use super::*;
    use rustls::{AlertDescription, Error as R, PeerIncompatible};

    /// Each handshake error of the TLS layer maps to its kind.
    #[test]
    fn every_tls_error_has_its_kind() {
        let cases = [
            (
                TlsError::Verification(R::NoCertificatesPresented),
                TlsFailureKind::Verification,
            ),
            (
                TlsError::VersionUnsupported(R::PeerIncompatible(
                    PeerIncompatible::ServerDoesNotSupportTls12Or13,
                )),
                TlsFailureKind::VersionUnsupported,
            ),
            (
                TlsError::CipherUnsupported(R::PeerIncompatible(
                    PeerIncompatible::NoCipherSuitesInCommon,
                )),
                TlsFailureKind::CipherUnsupported,
            ),
            (
                TlsError::Handshake(R::AlertReceived(AlertDescription::HandshakeFailure)),
                TlsFailureKind::AlertReceived,
            ),
            (
                TlsError::Handshake(R::General("other".into())),
                TlsFailureKind::Other,
            ),
            (
                TlsError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
                TlsFailureKind::Io,
            ),
            (TlsError::CertLoad("bad pem".into()), TlsFailureKind::Other),
        ];
        for (error, kind) in cases {
            assert_eq!(tls_failure_kind(&error), kind, "{error}");
        }
    }

    /// A transport failure behind which the session recorded a TLS error is
    /// that TLS error, classified like a failed handshake; a transport failure
    /// with no TLS error, and any other failure, are kept.
    #[test]
    fn a_setup_failure_is_a_tls_failure_only_with_a_tls_error_behind_it() {
        let transport = || {
            ClientError::Transport(
                TransportError::io(IoErrorKind::InvalidData).with_detail("invalid data"),
            )
        };
        let alert = R::AlertReceived(AlertDescription::CertificateRequired);
        assert!(matches!(
            tls_setup_failure(transport(), Some(&alert)),
            ClientError::TlsHandshake { kind: TlsFailureKind::AlertReceived, message, .. }
                if message == "received fatal alert: CertificateRequired"
        ));
        assert!(matches!(
            tls_setup_failure(transport(), Some(&R::DecryptError)),
            ClientError::TlsHandshake { kind: TlsFailureKind::Other, message, .. }
                if message == R::DecryptError.to_string()
        ));
        assert!(matches!(
            tls_setup_failure(transport(), None),
            ClientError::Transport(cause) if cause.kind() == IoErrorKind::InvalidData
        ));
        assert!(matches!(
            tls_setup_failure(ClientError::ConnectionLost, Some(&alert)),
            ClientError::ConnectionLost
        ));
        assert!(matches!(
            tls_setup_failure(ClientError::ConnectTimeout { timeout_ms: 10 }, Some(&alert)),
            ClientError::ConnectTimeout { timeout_ms: 10 }
        ));
    }

    /// The text of a handshake error carries the TLS error once.
    #[test]
    fn the_message_does_not_repeat_the_handshake_prefix() {
        let alert = TlsError::Handshake(R::AlertReceived(AlertDescription::ProtocolVersion));
        assert_eq!(
            tls_failure_message(&alert),
            "received fatal alert: ProtocolVersion"
        );
        let verification = TlsError::Verification(R::NoCertificatesPresented);
        assert_eq!(tls_failure_message(&verification), verification.to_string());
    }
}

#[cfg(all(test, feature = "std"))]
mod connect_deadline_tests {
    use super::*;
    use tokio::io::DuplexStream;

    /// A peer that never answers the COTP connection request ends
    /// `connect_via` at `connect_timeout_ms`, and not before, with
    /// `ConnectTimeout` and the connection closed. On the paused clock only
    /// the deadline can end the wait.
    #[tokio::test(start_paused = true)]
    async fn an_unanswered_cotp_request_ends_connect_via_at_the_connect_timeout() {
        let (transport, _peer) = tokio::io::duplex(4096);
        let mut conn = MmsConnection::<DuplexStream, TokioTimer>::new();
        conn.connect_timeout_ms = 2_000;
        let start = tokio::time::Instant::now();
        let result = conn.connect_via(transport).await;
        assert!(
            matches!(
                result,
                Err(ClientError::ConnectTimeout { timeout_ms: 2_000 })
            ),
            "{result:?}"
        );
        assert_eq!(start.elapsed(), Duration::from_millis(2_000));
        assert_eq!(conn.state, ConnectionState::Closed);
    }
}

// The connect request is built on the std transport and timer, so these run on
// a std build only.
#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::iso::cotp::encode_cr;
    use crate::iso::params::ApTitle;
    use crate::iso::presentation::PSelector;
    use crate::iso::session::{RefuseInfo, SSelector};

    /// Builds the session CN SPDU a connection with `params` would send.
    fn connect_request(params: IsoConnectionParameters) -> Vec<u8> {
        let mut conn = MmsConnection::<TcpStream, TokioTimer>::new();
        conn.set_iso_parameters(params);
        conn.build_connect_request()
            .expect("connect request must encode")
            .to_vec()
    }

    /// Reports whether `haystack` contains `needle`.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn abandoned_invoke_ids_are_bounded_and_the_oldest_is_forgotten() {
        let mut conn = MmsConnection::<TcpStream, TokioTimer>::new();
        let count = MAX_ABANDONED_INVOKE_IDS as u32 + 1;
        for id in 1..=count {
            conn.abandon_invoke_id(id);
        }
        assert_eq!(conn.abandoned_invoke_ids.len(), MAX_ABANDONED_INVOKE_IDS);
        assert!(!conn.take_abandoned(1), "the oldest invokeid is forgotten");
        assert!(conn.take_abandoned(count), "the newest invokeid is kept");
        assert!(!conn.take_abandoned(count), "an invokeid is taken once");
    }

    #[test]
    fn abandoned_invoke_ids_cover_a_negotiated_limit_above_the_minimum() {
        let mut conn = MmsConnection::<TcpStream, TokioTimer>::new();
        let limit = MAX_ABANDONED_INVOKE_IDS as u16 + 1;
        conn.negotiated_max_calling = limit;
        for id in 1..=u32::from(limit) {
            conn.abandon_invoke_id(id);
        }
        assert_eq!(conn.abandoned_invoke_ids.len(), usize::from(limit));
        assert!(conn.take_abandoned(1), "the oldest invokeid is kept");

        conn.abandon_invoke_id(u32::from(limit) + 1);
        conn.abandon_invoke_id(u32::from(limit) + 2);
        assert_eq!(conn.abandoned_invoke_ids.len(), usize::from(limit));
        assert!(
            !conn.take_abandoned(2),
            "past the limit the oldest is forgotten"
        );
    }

    #[test]
    fn negotiated_outstanding_limit_stays_within_the_proposal_and_above_zero() {
        assert_eq!(negotiate_max_calling(5, 3), 3);
        assert_eq!(negotiate_max_calling(5, 9), 5);
        assert_eq!(negotiate_max_calling(5, 0), 1);
        assert_eq!(negotiate_max_calling(0, 4), 1);
    }

    #[test]
    fn negotiated_pdu_size_never_exceeds_the_local_proposal() {
        assert_eq!(negotiate_max_pdu_size(Some(100), Some(65_000)), 100);
        assert_eq!(negotiate_max_pdu_size(Some(100), Some(64)), 64);
        assert_eq!(negotiate_max_pdu_size(Some(100), None), 100);
        assert_eq!(negotiate_max_pdu_size(None, Some(1_000)), 1_000);
        assert_eq!(
            negotiate_max_pdu_size(None, Some(u32::MAX)),
            DEFAULT_MAX_PDU_SIZE as usize
        );
    }

    #[test]
    fn default_cp_carries_the_documented_p_selectors() {
        let cn = connect_request(IsoConnectionParameters::default());
        assert!(
            contains(&cn, &[0x81, 0x04, 0x00, 0x00, 0x00, 0x01]),
            "calling-presentation-selector must be 00 00 00 01"
        );
        assert!(
            contains(&cn, &[0x82, 0x04, 0x00, 0x00, 0x00, 0x01]),
            "called-presentation-selector must be 00 00 00 01"
        );
    }

    #[test]
    fn empty_p_selectors_still_write_their_tag_and_length() {
        let params = IsoConnectionParameters {
            local_p_sel: PSelector::default(),
            remote_p_sel: PSelector::default(),
            ..IsoConnectionParameters::default()
        };
        let cn = connect_request(params);
        assert!(
            contains(&cn, &[0x81, 0x00, 0x82, 0x00]),
            "an empty selector still occupies its tag and length pair"
        );
    }

    #[test]
    fn default_cn_carries_the_documented_session_selectors() {
        let cn = connect_request(IsoConnectionParameters::default());
        // PGI 51, calling SS-SEL, and PGI 52, called SS-SEL
        assert!(contains(&cn, &[0x33, 0x02, 0x00, 0x01]), "pgi 51 is 00 01");
        assert!(contains(&cn, &[0x34, 0x02, 0x00, 0x01]), "pgi 52 is 00 01");
    }

    #[test]
    fn default_aarq_carries_the_documented_ap_titles() {
        let cn = connect_request(IsoConnectionParameters::default());
        // called-AP-title 1.1.1.999.1 and calling-AP-title 1.1.1.999
        assert!(contains(
            &cn,
            &[0xa2, 0x07, 0x06, 0x05, 0x29, 0x01, 0x87, 0x67, 0x01]
        ));
        assert!(contains(&cn, &[0xa3, 0x03, 0x02, 0x01, 0x0c]));
        assert!(contains(
            &cn,
            &[0xa6, 0x06, 0x06, 0x04, 0x29, 0x01, 0x87, 0x67]
        ));
        assert!(contains(&cn, &[0xa7, 0x03, 0x02, 0x01, 0x0c]));
    }

    #[test]
    fn custom_selectors_and_titles_reach_the_wire() {
        let params = IsoConnectionParameters {
            local_p_sel: PSelector::from_slice(&[0x00, 0x00, 0x00, 0x02]).expect("p-sel"),
            remote_p_sel: PSelector::from_slice(&[0x00, 0x00, 0x00, 0x02]).expect("p-sel"),
            local_s_sel: SSelector::from_slice(&[0x00, 0x02]).expect("s-sel"),
            remote_s_sel: SSelector::from_slice(&[0x00, 0x02]).expect("s-sel"),
            local_ap_title: Some("1.3.9999.13".parse::<ApTitle>().expect("ap-title")),
            remote_ap_title: Some("1.3.9999.13".parse::<ApTitle>().expect("ap-title")),
            local_ae_qualifier: Some(1),
            remote_ae_qualifier: Some(1),
            ..IsoConnectionParameters::default()
        };
        let cn = connect_request(params);
        assert!(contains(&cn, &[0x81, 0x04, 0x00, 0x00, 0x00, 0x02]));
        assert!(contains(&cn, &[0x82, 0x04, 0x00, 0x00, 0x00, 0x02]));
        assert!(contains(&cn, &[0x33, 0x02, 0x00, 0x02]));
        assert!(contains(&cn, &[0x34, 0x02, 0x00, 0x02]));
        // 1.3.9999.13 encodes as 2b ce 0f 0d
        assert!(contains(
            &cn,
            &[0xa6, 0x06, 0x06, 0x04, 0x2b, 0xce, 0x0f, 0x0d]
        ));
        assert!(contains(&cn, &[0xa7, 0x03, 0x02, 0x01, 0x01]));
    }

    #[test]
    fn cotp_cr_carries_the_t_selectors() {
        let opts = cotp_options(&IsoConnectionParameters::default());
        let cr = encode_cr(&opts, 1);
        // 0xC2 called TSAP then 0xC1 calling TSAP, both 00 01
        assert!(contains(&cr, &[0xc2, 0x02, 0x00, 0x01]));
        assert!(contains(&cr, &[0xc1, 0x02, 0x00, 0x01]));

        let params = IsoConnectionParameters {
            local_t_sel: crate::iso::cotp::TSelector::from_slice(&[0x00, 0x02]).expect("t-sel"),
            ..IsoConnectionParameters::default()
        };
        let cr = encode_cr(&cotp_options(&params), 1);
        assert!(contains(&cr, &[0xc1, 0x02, 0x00, 0x02]));
    }

    #[test]
    fn a_refuse_indication_becomes_a_typed_error() {
        // the refusal user data is a CPR carrying provider-reason 3
        let raw: &[u8] = &[
            0x0C, 0x0A, 0x32, 0x01, 0x81, 0xC1, 0x05, 0x30, 0x03, 0x8A, 0x01, 0x03,
        ];
        let info = RefuseInfo {
            reason_code: Some(129),
            transport_disconnect: None,
            user_data_start: 7,
            user_data_len: 5,
        };
        let err = check_session_accept(raw, SessionIndication::Refuse(info))
            .expect_err("a refusal must not be accepted");
        match err {
            ClientError::SessionRefused {
                reason_code,
                provider_reason,
                ..
            } => {
                assert_eq!(reason_code, Some(129));
                assert_eq!(provider_reason, Some(3));
            }
            other => panic!("expected SessionRefused, got {other:?}"),
        }
        let text = err.to_string();
        assert!(text.contains("session selector unknown"), "{text}");
        assert!(
            text.contains("called-presentation-address-unknown"),
            "{text}"
        );
    }

    #[test]
    fn a_refusal_without_user_data_has_no_provider_reason() {
        let raw: &[u8] = &[0x0C, 0x03, 0x32, 0x01, 0x02];
        let info = RefuseInfo {
            reason_code: Some(2),
            transport_disconnect: None,
            user_data_start: 0,
            user_data_len: 0,
        };
        let err = check_session_accept(raw, SessionIndication::Refuse(info))
            .expect_err("a refusal must not be accepted");
        assert!(matches!(
            err,
            ClientError::SessionRefused {
                provider_reason: None,
                ..
            }
        ));
    }
}
