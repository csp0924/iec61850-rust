//! Low-level MMS client connection management over an async transport.
//!
//! ## Responsibilities
//!
//! 1. Owning the transport and its I/O.
//! 2. Running the association sequence: COTP CR and CC, then Session CN with
//!    Presentation CP, ACSE AARQ and the MMS Initiate request in one message, and
//!    the matching Session AC with Presentation CPA, ACSE AARE and the MMS Initiate
//!    response.
//! 3. Running the release sequence: MMS Conclude request, Conclude response, close.
//! 4. Sending and receiving MMS PDUs inside TPKT and COTP framing, through
//!    [`crate::iso::cotp::CotpConnection`].
//! 5. An encoded PDU larger than `negotiated_max_pdu_size` is rejected
//!    instead of being sent.
//!
//! ## Design
//!
//! - The API is async throughout, and all framing goes through
//!   `CotpConnection`, which is transport generic.
//! - Synchronous callers use the `BlockingMmsClient` wrapper.
//! - `connect_timeout_ms` and `request_timeout_ms` are applied with
//!   `iec61850_hal::time::with_timeout`, so the runtime stays pluggable.
//!
//! ## Behavior
//!
//! A Conclude request arriving from the server (`0x8b`) is answered with `0x8c`
//! and reported to the caller as a lost connection.

use super::error::ClientError;
use crate::compat::prelude::*;
use crate::compat::VecDeque;
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
use core::time::Duration;
use iec61850_hal::time::{with_timeout, Timer};
use iec61850_hal::transport::AsyncTransport;
use tracing::{debug, warn};

// std only: the tokio TcpStream and TokioTimer defaults, plus the TLS connector.
#[cfg(feature = "std")]
use iec61850_hal::time::TokioTimer;
#[cfg(feature = "std")]
use tokio::net::TcpStream;

#[cfg(feature = "tls")]
use iec61850_tls::{TlsConnector, TlsError};
#[cfg(feature = "tls")]
use rustls::pki_types::ServerName;
#[cfg(feature = "tls")]
use tokio_rustls::client::TlsStream;

// Constants

/// Default connect timeout in milliseconds.
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10_000;

/// Default request timeout in milliseconds.
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 5_000;

/// indirect-reference written into the AARQ user-information; MMS uses 3.
const ACSE_INDIRECT_REFERENCE: u32 = 3;

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
    cotp_tls: Option<CotpConnection<TlsStream<TcpStream>>>,
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
    /// Negotiated ceiling on outstanding calling requests.
    pub negotiated_max_calling: u16,
    /// Negotiated ceiling on outstanding called requests.
    pub negotiated_max_called: u16,
    /// Connect timeout in milliseconds.
    pub connect_timeout_ms: u64,
    /// Request timeout in milliseconds.
    pub request_timeout_ms: u64,
    /// `localDetail` proposed in the Initiate request, the proposedMaxPduSize.
    /// `None` uses `DEFAULT_MAX_PDU_SIZE`, that is 65000. A smaller value exercises
    /// the outbound size guard end to end.
    pub local_max_pdu_size: Option<u32>,
    /// ISO addressing offered by the next association: the T, S and P selectors
    /// and the AP-title and AE-qualifier of both sides.
    pub iso_parameters: IsoConnectionParameters,
    /// Inner bytes of Unconfirmed PDUs, such as InformationReport, that arrived while
    /// a confirmed service was awaiting its response.
    ///
    /// A server may push an InformationReport, for a report control block or a
    /// command termination, in the middle of a confirmed exchange. Such a PDU is
    /// stashed here and drained by `recv_unconfirmed_pdu_with_timeout`, which keeps
    /// the caller from mistaking it for the response. The queue preserves arrival order.
    pending_unconfirmed: VecDeque<Bytes>,
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
    /// `localDetail` proposed in the Initiate request; `None` uses the default.
    pub local_max_pdu_size: Option<u32>,
    /// ISO addressing offered by the next association.
    pub iso_parameters: IsoConnectionParameters,
    pending_unconfirmed: VecDeque<Bytes>,
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
            local_max_pdu_size: None,
            iso_parameters: IsoConnectionParameters::default(),
            pending_unconfirmed: VecDeque::new(),
        }
    }

    /// Replaces the ISO addressing offered by the next association.
    ///
    /// The entry point for a caller that owns its transport and therefore never
    /// goes through `MmsClientBuilder`.
    pub fn set_iso_parameters(&mut self, params: IsoConnectionParameters) {
        self.iso_parameters = params;
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
    /// different kind of report puts it back here for the report dispatcher.
    pub fn push_pending_unconfirmed(&mut self, inner: Bytes) {
        self.pending_unconfirmed.push_back(inner);
    }
}

// TCP-specific constructors, std only

#[cfg(feature = "std")]
impl MmsConnection<TcpStream, TokioTimer> {
    /// Runs the full ISO and MMS association sequence over a new TCP connection.
    ///
    /// The sequence is TCP, COTP CR and CC, then Session CN with Presentation CP,
    /// ACSE AARQ and the MMS Initiate request, and the matching Session AC with
    /// Presentation CPA, ACSE AARE and the MMS Initiate response.
    pub async fn connect(&mut self, host: &str, port: u16) -> Result<(), ClientError> {
        let addr: std::net::SocketAddr = format!("{host}:{port}")
            .parse()
            .map_err(|e| ClientError::IsoError(format!("address parse: {e}")))?;
        let connect_dur = Duration::from_millis(self.connect_timeout_ms);

        // Step 0: TCP connect with timeout
        let tcp = with_timeout(&self.timer, connect_dur, TcpStream::connect(addr))
            .await
            .map_err(|_| ClientError::IsoError("TCP connect timeout".to_string()))?
            .map_err(|e| ClientError::IsoError(format!("TCP connect: {e}")))?;
        // disable Nagle to keep the latency of small PDUs down
        let _ = tcp.set_nodelay(true);

        // the rest of the sequence is transport generic
        self.connect_via(tcp).await
    }

    /// Runs the association sequence over TLS.
    ///
    /// The TLS handshake is inserted after the TCP connection, and every later step
    /// is identical to the plaintext path.
    #[cfg(feature = "tls")]
    pub async fn connect_tls(
        &mut self,
        addr: std::net::SocketAddr,
        connector: &TlsConnector,
        server_name: ServerName<'static>,
    ) -> Result<(), ClientError> {
        self.state = ConnectionState::Connecting;
        let connect_dur = Duration::from_millis(self.connect_timeout_ms);

        // Step 0: TCP connect
        let tcp = with_timeout(&self.timer, connect_dur, TcpStream::connect(addr))
            .await
            .map_err(|_| ClientError::IsoError("TCP connect timeout".to_string()))?
            .map_err(|e| ClientError::IsoError(format!("TCP connect: {e}")))?;
        let _ = tcp.set_nodelay(true);

        // Step 0b: TLS handshake
        let tls_stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e: TlsError| ClientError::IsoError(format!("TLS handshake: {e}")))?;
        debug!("tls handshake complete");

        // Step 1+2: COTP CR/CC
        let opts = cotp_options(&self.iso_parameters);
        let mut cotp = CotpConnection::connect(tls_stream, opts)
            .await
            .map_err(|e| ClientError::IsoError(format!("cotp tls: {e}")))?;
        debug!("cotp connection over tls established");

        // Step 3: Session CN + Presentation CP + ACSE AARQ + MMS Initiate-Request
        {
            let sess_buf = self
                .build_connect_request()
                .map_err(|e| ClientError::IsoError(format!("session cn tls: {e}")))?;

            cotp.send_data(&sess_buf)
                .await
                .map_err(|e| ClientError::IsoError(format!("cotp tls send: {e}")))?;
        }

        // Step 4: Session AC + Presentation CPA + ACSE AARE + MMS Initiate-Response
        {
            let req_dur = Duration::from_millis(self.request_timeout_ms);
            let raw = with_timeout(&self.timer, req_dur, cotp.recv_data())
                .await
                .map_err(|_| ClientError::IsoError("recv timeout (initiate tls)".to_string()))?
                .map_err(|e| ClientError::IsoError(format!("cotp tls recv: {e}")))?;

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
                    let local_max = DEFAULT_MAX_PDU_SIZE as usize;
                    let server_max =
                        resp.local_detail_called.unwrap_or(DEFAULT_MAX_PDU_SIZE) as usize;
                    self.negotiated_max_pdu_size = local_max.min(server_max);
                    self.negotiated_max_calling = resp.negotiated_max_serv_outstanding_calling;
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
        self.state = ConnectionState::Connected;
        Ok(())
    }
}

// Transport-generic association handling

impl<T: AsyncTransport, Tm: Timer> MmsConnection<T, Tm> {
    /// Runs the ISO and MMS Initiate sequence over an already connected transport.
    ///
    /// This is the entry point for callers that own the transport themselves, an
    /// embedded IP stack for instance. Only the COTP handshake and the
    /// Session, Presentation, ACSE and MMS Initiate negotiation happen here.
    ///
    /// `connect` performs the TCP connection and then calls this; the TLS path uses
    /// `connect_tls`, which drives its own COTP connection instead.
    pub async fn connect_via(&mut self, transport: T) -> Result<(), ClientError> {
        self.state = ConnectionState::Connecting;

        // Step 1+2: COTP CR/CC handshake
        let opts = cotp_options(&self.iso_parameters);
        let mut cotp = CotpConnection::connect(transport, opts)
            .await
            .map_err(|e| ClientError::IsoError(format!("cotp: {e}")))?;
        debug!("cotp connection established over the supplied transport");

        // ISO negotiation and the MMS Initiate exchange
        self.run_initiate_handshake(&mut cotp).await?;

        self.cotp = Some(cotp);
        self.state = ConnectionState::Connected;
        Ok(())
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
                .map_err(|e| ClientError::IsoError(format!("cotp send: {e}")))?;
        }

        // Step 4
        let req_dur = Duration::from_millis(self.request_timeout_ms);
        let raw = with_timeout(&self.timer, req_dur, cotp.recv_data())
            .await
            .map_err(|_| ClientError::IsoError("recv timeout (initiate)".to_string()))?
            .map_err(|e| ClientError::IsoError(format!("cotp recv: {e}")))?;

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
                let local_max = DEFAULT_MAX_PDU_SIZE as usize;
                let server_max = resp.local_detail_called.unwrap_or(DEFAULT_MAX_PDU_SIZE) as usize;
                self.negotiated_max_pdu_size = local_max.min(server_max);
                self.negotiated_max_calling = resp.negotiated_max_serv_outstanding_calling;
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

    /// Runs the MMS Conclude sequence and closes the connection.
    ///
    /// A caller-initiated disconnect does not invoke the connection-lost handler.
    pub async fn disconnect(&mut self) -> Result<(), ClientError> {
        if self.state != ConnectionState::Connected {
            return Err(ClientError::NotConnected {
                state: format!("{:?}", self.state),
            });
        }
        self.state = ConnectionState::Closing;

        // send the Conclude request
        self.send_mms_pdu(&MmsPdu::ConcludeRequest).await?;

        // await the Conclude response
        match self.recv_mms_pdu().await {
            Ok(MmsPdu::ConcludeResponse) => {
                debug!("received a conclude response (0x8c), closing normally");
            }
            Ok(other) => {
                warn!(
                    "expected a conclude response, got tag=0x{:02X}, closing anyway",
                    other.tag_byte()
                );
            }
            Err(e) => {
                warn!("failed to receive a conclude response: {e}, closing anyway");
            }
        }

        self.close_raw();
        Ok(())
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
        self.state = ConnectionState::Closed;
    }

    /// Sends an MMS PDU wrapped in the full ISO stack.
    ///
    /// An encoded PDU larger than `negotiated_max_pdu_size`
    /// returns an error instead of being sent.
    pub async fn send_mms_pdu(&mut self, pdu: &MmsPdu) -> Result<(), ClientError> {
        // MMS PDU encode
        let mut mms_buf = BytesMut::new();
        pdu.encode(&mut mms_buf);

        // wrap in Presentation Fully-Encoded-Data
        let mut pres_buf = BytesMut::new();
        presentation::encode_user_data(&self.presentation, &mms_buf, &mut pres_buf);

        // outbound PDU size guard
        if pres_buf.len() > self.negotiated_max_pdu_size {
            warn!(
                pdu_size = pres_buf.len(),
                max_size = self.negotiated_max_pdu_size,
                "pdu exceeds the negotiated maximum size, refusing to send"
            );
            return Err(ClientError::PduTooLarge {
                pdu_size: pres_buf.len(),
                max_size: self.negotiated_max_pdu_size,
            });
        }

        // wrap in a Session data SPDU
        let mut session_buf = BytesMut::new();
        session::encode_data(&pres_buf, &mut session_buf);

        // CotpConnection adds the TPKT header and segments as needed;
        // the TLS transport takes precedence when the feature is enabled
        #[cfg(feature = "tls")]
        if let Some(cotp) = self.cotp_tls.as_mut() {
            cotp.send_data(&session_buf)
                .await
                .map_err(|e| ClientError::IsoError(format!("cotp tls send: {e}")))?;
            return Ok(());
        }

        let cotp = self
            .cotp
            .as_mut()
            .ok_or_else(|| ClientError::NotConnected {
                state: format!("{:?}", self.state),
            })?;
        cotp.send_data(&session_buf)
            .await
            .map_err(|e| ClientError::IsoError(format!("cotp send: {e}")))?;
        Ok(())
    }

    /// Receives one MMS PDU, parsing the full ISO stack, under a timeout.
    ///
    /// A `timeout_dur` of `None` uses `request_timeout_ms`, and `Some(d)` uses `d`.
    ///
    /// Cancel safety: `cotp.recv_data` and `read_tpkt` keep their partial state inside
    /// the COTP connection, so a timeout loses no bytes and the next call resumes from
    /// the same point.
    ///
    /// Returns:
    /// - `Ok(Some(pdu))` when a PDU arrived.
    /// - `Ok(None)` when the link stayed idle and not a single byte arrived.
    /// - `Err(_)` on an I/O failure, a parse failure, or a partly received PDU.
    ///
    /// A PDU that arrives only partly, a TPKT header without its body for instance,
    /// yields `Err` rather than `Ok(None)`, leaving the caller to retry or close; the
    /// next receive continues from where it stopped.
    pub async fn recv_mms_pdu_with_timeout(
        &mut self,
        timeout_dur: Option<Duration>,
    ) -> Result<Option<MmsPdu>, ClientError> {
        let dur = timeout_dur.unwrap_or_else(|| Duration::from_millis(self.request_timeout_ms));
        // The timer is cloned so borrowing it does not conflict with the mutable
        // borrow of self taken by recv_mms_pdu. Timer requires Clone and is cheap
        // to clone in every backend.
        let timer = self.timer.clone();
        match with_timeout(&timer, dur, self.recv_mms_pdu()).await {
            Ok(Ok(pdu)) => Ok(Some(pdu)),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                // The timeout expired; the partial read state stays in cotp.read_state.
                // Ok(None) covers both an idle link and a stalled partial read, and the
                // next call keeps accumulating.
                Ok(None)
            }
        }
    }

    /// Receives one PDU for a confirmed call, stashing any Unconfirmed PDU in
    /// `pending_unconfirmed` and reading on until a non-Unconfirmed PDU arrives.
    ///
    /// A server may push an InformationReport while a control, read or write call is
    /// awaiting its response. Stashing it here keeps the caller from mistaking it for
    /// the response; `MmsClient::recv_unconfirmed_pdu_with_timeout` drains the stash
    /// afterwards.
    pub async fn recv_mms_pdu_confirmed(&mut self) -> Result<MmsPdu, ClientError> {
        loop {
            let pdu = self.recv_mms_pdu().await?;
            if let MmsPdu::Unconfirmed(inner) = pdu {
                debug!(
                    "stashing an unconfirmed pdu of {} bytes for a later unconfirmed read",
                    inner.len()
                );
                self.pending_unconfirmed.push_back(inner);
                continue;
            }
            return Ok(pdu);
        }
    }

    /// Receives one MMS PDU, parsing the full ISO stack.
    ///
    /// A Conclude request from the server (`0x8b`) is answered with `0x8c`, moves the
    /// connection to `Closing`, and is reported as `Err(ConnectionLost)`.
    pub async fn recv_mms_pdu(&mut self) -> Result<MmsPdu, ClientError> {
        // Take the raw bytes first so the borrow of self.cotp ends before
        // self.session and self.presentation are borrowed.
        let req_dur = Duration::from_millis(self.request_timeout_ms);
        // The timer is cloned so borrowing it does not conflict with the mutable
        // borrow of self.cotp. Timer requires Clone and is cheap to clone.
        let timer = self.timer.clone();

        // the TLS transport takes precedence when the feature is enabled
        #[cfg(feature = "tls")]
        let raw = if let Some(cotp) = self.cotp_tls.as_mut() {
            with_timeout(&timer, req_dur, cotp.recv_data())
                .await
                .map_err(|_| ClientError::IsoError("recv timeout (tls)".to_string()))?
                .map_err(|e| ClientError::IsoError(format!("cotp tls recv: {e}")))?
        } else {
            let cotp = self
                .cotp
                .as_mut()
                .ok_or_else(|| ClientError::NotConnected {
                    state: format!("{:?}", self.state),
                })?;
            with_timeout(&timer, req_dur, cotp.recv_data())
                .await
                .map_err(|_| ClientError::IsoError("recv timeout".to_string()))?
                .map_err(|e| ClientError::IsoError(format!("cotp recv: {e}")))?
        };

        #[cfg(not(feature = "tls"))]
        let raw = {
            let cotp = self
                .cotp
                .as_mut()
                .ok_or_else(|| ClientError::NotConnected {
                    state: format!("{:?}", self.state),
                })?;
            with_timeout(&timer, req_dur, cotp.recv_data())
                .await
                .map_err(|_| ClientError::IsoError("recv timeout".to_string()))?
                .map_err(|e| ClientError::IsoError(format!("cotp recv: {e}")))?
        };

        // Session data SPDU
        let sess_ind = self
            .session
            .parse_message(&raw)
            .map_err(|e| ClientError::IsoError(format!("session: {e}")))?;
        if sess_ind != SessionIndication::Data {
            warn!("received a non-data session spdu: {:?}", sess_ind);
            return Err(ClientError::IsoError(format!(
                "unexpected session indication: {sess_ind:?}"
            )));
        }

        let sess_payload: Vec<u8> = self.session.user_data(&raw).to_vec();

        // Presentation layer
        let ud_result = presentation::parse_user_data(&mut self.presentation, &sess_payload)
            .map_err(|e| ClientError::IsoError(format!("presentation: {e}")))?;
        let mms_bytes: Vec<u8> = ud_result.payload(&sess_payload).to_vec();

        // outermost MMS PDU
        let pdu = MmsPdu::decode(&mms_bytes).map_err(|e| {
            warn!("mms pdu failed to decode: {e}");
            ClientError::PduParse(format!("{e}"))
        })?;

        // a Conclude request from the server ends the association
        if pdu == MmsPdu::ConcludeRequest {
            warn!(
                "received a conclude request (0x8b) from the server, answering with 0x8c and reporting a lost connection"
            );
            let _ = self.send_mms_pdu(&MmsPdu::ConcludeResponse).await;
            self.state = ConnectionState::Closing;
            return Err(ClientError::ConnectionLost);
        }

        Ok(pdu)
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
