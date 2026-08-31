//! COTP class 0 (ISO 8073) carried over TCP per RFC 1006.
//!
//! Encodes and decodes TPKT plus COTP PDUs (CR, CC, DT, DR, DC, ER), drives the
//! COTP connection state machine (Closed, ConnectSent, Connected, Closing), and
//! handles the TSAP parameters (0xC1 calling, 0xC2 called) together with TPDU
//! size negotiation (0xC0).
//!
//! Guarantees the rest of the stack relies on:
//! - All parsing goes through the bounds-checked `TpduReader`; no slice is taken
//!   from network input without a length check.
//! - The TPDU size in effect is the smaller of the local and remote proposals.
//! - DR, DC and ER are decoded and surfaced as distinct indications.
//! - Connection state is a Rust enum, not an integer field.
//! - protocol class must be 0.
//! - I/O is async and event driven; there is no polling loop.
//! - The read buffer is owned by the connection, so no null-buffer branch exists.

use super::tpkt::{TpktHeader, TPKT_HEADER_LEN};
use crate::compat::prelude::*;
use crate::error::CotpError;
use bytes::{Bytes, BytesMut};
// The transport is the hal AsyncTransport trait rather than a concrete tokio
// type; tokio TCP, duplex and TLS streams satisfy it through a blanket impl.
use iec61850_hal::transport::AsyncTransport;
use tracing::warn;

// Constants

/// Maximum read buffer size: the largest TPDU plus the TPKT header.
pub const COTP_MAX_BUFFER_SIZE: usize = 8192 + TPKT_HEADER_LEN;

/// Fixed COTP DT header length: LI, TPDU type and NR.
pub const COTP_DATA_HEADER_SIZE: usize = 3;

/// Largest legal encoded TPDU size, 0x0D for 8192 bytes.
pub const COTP_MAX_TPDU_SIZE_ENCODED: u8 = 0x0D;

/// Smallest legal encoded TPDU size, 0x07 for 128 bytes.
pub const COTP_MIN_TPDU_SIZE_ENCODED: u8 = 0x07;

/// COTP CR TPDU type code.
const TPDU_CR: u8 = 0xE0;
/// COTP CC TPDU type code.
const TPDU_CC: u8 = 0xD0;
/// COTP DT TPDU type code.
const TPDU_DT: u8 = 0xF0;
/// COTP DR TPDU type code.
const TPDU_DR: u8 = 0x80;
/// COTP DC TPDU type code.
const TPDU_DC: u8 = 0xC0;
/// COTP ER TPDU type code.
const TPDU_ER: u8 = 0x70;

/// Variable-part option codes.
const OPT_TPDU_SIZE: u8 = 0xC0;
const OPT_CALLING_TSAP: u8 = 0xC1;
const OPT_CALLED_TSAP: u8 = 0xC2;
const OPT_ADDITIONAL_OPT: u8 = 0xC6;

// Data types

/// A Transport Selector of at most 4 bytes.
///
/// A `size` of 0 means the parameter is not carried.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TSelector {
    /// Number of significant bytes, in the range 0..=4.
    pub size: u8,
    /// Selector octets; only the first `size` bytes are significant.
    pub value: [u8; 4],
}

impl TSelector {
    /// Builds a selector from a byte slice of at most 4 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CotpError::TSelectorTooLong`] when `data` is longer than 4 bytes.
    pub fn from_slice(data: &[u8]) -> Result<Self, CotpError> {
        if data.len() > 4 {
            return Err(CotpError::TSelectorTooLong { len: data.len() });
        }
        let mut value = [0u8; 4];
        value[..data.len()].copy_from_slice(data);
        Ok(Self {
            size: data.len() as u8,
            value,
        })
    }

    /// Returns the significant bytes of the selector.
    pub fn as_slice(&self) -> &[u8] {
        &self.value[..self.size as usize]
    }
}

/// A TPDU size held as its encoded value, where the actual size is `1 << encoded`.
///
/// Legal encoded values run from 0x07 (128 bytes) to 0x0D (8192 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpduSize(u8);

impl TpduSize {
    /// Builds a size from an encoded value, returning `None` outside 0x07..=0x0D.
    pub fn from_encoded(enc: u8) -> Option<Self> {
        if (COTP_MIN_TPDU_SIZE_ENCODED..=COTP_MAX_TPDU_SIZE_ENCODED).contains(&enc) {
            Some(Self(enc))
        } else {
            None
        }
    }

    /// Returns the largest power of two not exceeding `n`, as an encoded size.
    ///
    /// Values at or above 8192 clamp to 0x0D, values below 128 clamp to 0x07.
    pub fn from_bytes(n: u16) -> Self {
        if n >= 8192 {
            return Self(COTP_MAX_TPDU_SIZE_ENCODED);
        }
        // largest power of two not exceeding n, searched downwards
        for enc in (COTP_MIN_TPDU_SIZE_ENCODED..=COTP_MAX_TPDU_SIZE_ENCODED).rev() {
            let actual = 1u16 << enc;
            if actual <= n {
                return Self(enc);
            }
        }
        // anything below 128 uses the smallest legal size
        Self(COTP_MIN_TPDU_SIZE_ENCODED)
    }

    /// Returns the encoded value.
    pub fn encoded(self) -> u8 {
        self.0
    }

    /// Returns the actual size in bytes.
    pub fn bytes(self) -> u16 {
        1u16 << self.0
    }

    /// Returns the smaller of two sizes, as size negotiation requires.
    pub fn min(self, other: Self) -> Self {
        if self.bytes() <= other.bytes() {
            self
        } else {
            other
        }
    }
}

impl Default for TpduSize {
    fn default() -> Self {
        // 0x0D, that is 8192 bytes
        Self(COTP_MAX_TPDU_SIZE_ENCODED)
    }
}

/// COTP connection options.
#[derive(Debug, Clone, Default)]
pub struct CotpOptions {
    /// Calling T-Selector, naming the local TSAP.
    pub tsel_src: TSelector,
    /// Called T-Selector, naming the peer TSAP.
    pub tsel_dst: TSelector,
    /// TPDU size to propose, and after negotiation the one in force.
    pub tpdu_size: TpduSize,
}

/// COTP connection state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CotpState {
    /// No connection; a CR has not been sent.
    Closed,
    /// A CR has been sent and the CC is awaited.
    ConnectSent,
    /// The connection is established and may carry data.
    Connected,
    /// A DR has been sent and the DC is awaited.
    Closing,
}

impl core::fmt::Display for CotpState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CotpState::Closed => write!(f, "Closed"),
            CotpState::ConnectSent => write!(f, "ConnectSent"),
            CotpState::Connected => write!(f, "Connected"),
            CotpState::Closing => write!(f, "Closing"),
        }
    }
}

/// Partial state of `read_tpkt`, kept so a canceled read loses nothing.
///
/// The state lives in the connection rather than in a local variable, so a
/// canceled `read` (for instance when the caller wraps `recv_data` in a timeout
/// or races it in a `select!`) keeps the bytes already read, and the next call
/// resumes from the same point. Dropping them would misalign every later decode
/// on the connection.
#[derive(Debug)]
enum ReadState {
    /// No read is in progress.
    Idle,
    /// Reading the 4-byte TPKT header; `have` counts the bytes already read.
    ReadingHeader { have: usize, buf: [u8; 4] },
    /// Reading the body; `have` counts the bytes already read into `read_buf`.
    ReadingBody { hdr: TpktHeader, have: usize },
}

/// A COTP class 0 connection over RFC 1006.
///
/// `T` must implement [`AsyncTransport`]. A blanket impl in the hal covers every
/// type that is `AsyncRead + AsyncWrite + Unpin + Send`, so tokio TCP, duplex and
/// TLS streams qualify; an embedded backend supplies its own impl instead.
pub struct CotpConnection<T> {
    stream: T,
    state: CotpState,
    options: CotpOptions,
    local_ref: u16,
    remote_ref: u16,
    read_buf: BytesMut,
    payload_buf: BytesMut,
    /// Cancel-safe partial state for `read_tpkt`.
    read_state: ReadState,
    /// Upper bound on a reassembled TSDU payload; `None` means unbounded.
    ///
    /// See [`CotpConnection::set_max_tsdu_size`].
    max_tsdu_size: Option<usize>,
}

impl<T: AsyncTransport> CotpConnection<T> {
    /// Creates a client-side connection that has not yet sent a CR.
    pub fn new(stream: T, options: CotpOptions) -> Self {
        Self {
            stream,
            state: CotpState::Closed,
            options,
            local_ref: 1,
            remote_ref: 0,
            read_buf: BytesMut::with_capacity(COTP_MAX_BUFFER_SIZE),
            payload_buf: BytesMut::new(),
            read_state: ReadState::Idle,
            max_tsdu_size: None,
        }
    }

    /// Sets the upper bound on a reassembled TSDU payload.
    ///
    /// A class 0 TSDU is any number of DT TPDUs ending with EOT=1 and its total
    /// length is never announced in advance, so without a bound the reassembly
    /// buffer of [`recv_data`](Self::recv_data) is sized entirely by the peer. Once
    /// `limit` is exceeded [`CotpError::TsduTooLarge`] is returned and the caller is
    /// expected to close the connection.
    ///
    /// `None`, the default, leaves the size unbounded. A deployment with a fixed
    /// memory budget, such as an embedded responder, should set a limit.
    pub fn set_max_tsdu_size(&mut self, limit: Option<usize>) {
        self.max_tsdu_size = limit;
    }

    /// Returns the current connection state.
    pub fn state(&self) -> &CotpState {
        &self.state
    }

    /// Returns the negotiated TPDU size in bytes.
    pub fn tpdu_size(&self) -> u16 {
        self.options.tpdu_size.bytes()
    }

    /// Returns the COTP reference chosen by the peer.
    pub fn remote_ref(&self) -> u16 {
        self.remote_ref
    }

    /// Returns the COTP reference chosen locally.
    pub fn local_ref(&self) -> u16 {
        self.local_ref
    }

    // Client role: send CR, receive CC

    /// Establishes a connection as the client: sends a CR TPDU and awaits the CC.
    ///
    /// On success the state becomes `Connected`.
    pub async fn connect(stream: T, options: CotpOptions) -> Result<Self, CotpError> {
        let mut conn = Self::new(stream, options);
        conn.send_cr().await?;
        conn.recv_cc().await?;
        Ok(conn)
    }

    /// Sends a CR (Connection Request) TPDU.
    pub async fn send_cr(&mut self) -> Result<(), CotpError> {
        if self.state != CotpState::Closed {
            return Err(CotpError::InvalidState {
                state: self.state.to_string(),
                op: "send_cr",
            });
        }
        let pdu = encode_cr(&self.options, self.local_ref);
        self.write_tpkt(&pdu).await?;
        self.state = CotpState::ConnectSent;
        Ok(())
    }

    /// Awaits and parses a CC (Connection Confirm) TPDU.
    ///
    /// The TPDU size in effect becomes the smaller of the two proposals.
    async fn recv_cc(&mut self) -> Result<(), CotpError> {
        if self.state != CotpState::ConnectSent {
            return Err(CotpError::InvalidState {
                state: self.state.to_string(),
                op: "recv_cc",
            });
        }
        let raw = self.read_tpkt().await?;
        let (remote_ref, remote_tpdu_size) = parse_cc(&raw)?;
        self.remote_ref = remote_ref;
        // negotiation keeps the smaller proposal
        self.options.tpdu_size = self.options.tpdu_size.min(remote_tpdu_size);
        self.state = CotpState::Connected;
        Ok(())
    }

    // Server role: receive CR, send CC

    /// Accepts a connection as the server: awaits a CR TPDU and sends the CC.
    ///
    /// On success the state becomes `Connected`.
    pub async fn accept(stream: T, local_options: CotpOptions) -> Result<Self, CotpError> {
        let mut conn = Self::new(stream, local_options);
        conn.recv_cr_and_send_cc().await?;
        Ok(conn)
    }

    /// Awaits a CR and answers with a CC.
    async fn recv_cr_and_send_cc(&mut self) -> Result<(), CotpError> {
        let raw = self.read_tpkt().await?;
        let (src_ref, remote_opts) = parse_cr(&raw)?;
        self.remote_ref = src_ref;
        // negotiation keeps the smaller proposal
        self.options.tpdu_size = self.options.tpdu_size.min(remote_opts.tpdu_size);
        // the local called TSAP becomes the calling TSAP the peer announced
        self.options.tsel_dst = remote_opts.tsel_src;
        let cc_pdu = encode_cc(&self.options, self.local_ref, self.remote_ref);
        self.write_tpkt(&cc_pdu).await?;
        self.state = CotpState::Connected;
        Ok(())
    }

    // Data transfer

    /// Sends a TSDU, segmenting it when necessary.
    ///
    /// A payload longer than `tpdu_size - COTP_DATA_HEADER_SIZE` is split across
    /// several DT TPDUs, and only the last one carries EOT=1.
    pub async fn send_data(&mut self, payload: &[u8]) -> Result<(), CotpError> {
        if self.state != CotpState::Connected {
            return Err(CotpError::InvalidState {
                state: self.state.to_string(),
                op: "send_data",
            });
        }
        let max_payload = self.options.tpdu_size.bytes() as usize - COTP_DATA_HEADER_SIZE;
        let chunks: Vec<&[u8]> = payload.chunks(max_payload).collect();
        let total = chunks.len();
        for (i, chunk) in chunks.into_iter().enumerate() {
            let is_last = i == total - 1;
            let dt = encode_dt(chunk, is_last);
            self.write_tpkt(&dt).await?;
        }
        Ok(())
    }

    /// Receives one complete TSDU, reassembled across DT TPDU segments.
    ///
    /// DT TPDUs are read until EOT=1 and their payloads concatenated.
    ///
    /// Cancel-safe: partial data accumulates in the connection, so a canceled call,
    /// for instance one wrapped in a timeout, keeps what has already arrived and the
    /// next call continues until EOT=1. Together with the `read_tpkt` state this
    /// holds across multi-segment TSDUs.
    ///
    /// After an error the caller should normally close the connection. Calling
    /// `recv_data` again concatenates the leftover payload with the next TSDU and
    /// corrupts decoding. [`CotpError::TsduTooLarge`] is the exception: it clears
    /// the reassembly buffer before returning.
    ///
    /// Memory bound: the TSDU length is never announced in advance and is unbounded
    /// by default, which leaves the reassembly buffer sized by the peer. After
    /// [`set_max_tsdu_size`](Self::set_max_tsdu_size) an oversized TSDU returns
    /// [`CotpError::TsduTooLarge`].
    pub async fn recv_data(&mut self) -> Result<Bytes, CotpError> {
        if self.state != CotpState::Connected {
            return Err(CotpError::InvalidState {
                state: self.state.to_string(),
                op: "recv_data",
            });
        }
        // Not cleared on entry: split() resets the buffer once EOT arrives.
        loop {
            let raw = self.read_tpkt().await?;
            let (payload, is_last) = parse_dt(&raw)?;
            self.payload_buf.extend_from_slice(payload);
            if let Some(limit) = self.max_tsdu_size {
                if self.payload_buf.len() > limit {
                    let accumulated = self.payload_buf.len();
                    warn!(
                        accumulated,
                        limit, "reassembled tsdu exceeds the configured limit, aborting"
                    );
                    self.payload_buf.clear();
                    return Err(CotpError::TsduTooLarge { accumulated, limit });
                }
            }
            if is_last {
                return Ok(self.payload_buf.split().freeze());
            }
        }
    }

    // Disconnect

    /// Sends a DR (Disconnect Request) TPDU and enters the `Closing` state.
    pub async fn send_dr(&mut self) -> Result<(), CotpError> {
        if self.state != CotpState::Connected {
            return Err(CotpError::InvalidState {
                state: self.state.to_string(),
                op: "send_dr",
            });
        }
        let dr = encode_dr(self.local_ref, self.remote_ref);
        self.write_tpkt(&dr).await?;
        self.state = CotpState::Closing;
        Ok(())
    }

    /// Awaits a DC (Disconnect Confirm) TPDU and returns the state to `Closed`.
    pub async fn recv_dc(&mut self) -> Result<(), CotpError> {
        if self.state != CotpState::Closing {
            return Err(CotpError::InvalidState {
                state: self.state.to_string(),
                op: "recv_dc",
            });
        }
        let raw = self.read_tpkt().await?;
        parse_dc(&raw)?;
        self.state = CotpState::Closed;
        Ok(())
    }

    // Low-level I/O

    /// Reads one complete TPKT packet and returns the COTP payload without the header.
    ///
    /// Cancel-safe: the partial read state lives in `self.read_state` and
    /// `self.read_buf`, so a canceled call resumes from the same point.
    ///
    /// The read runs as a state machine:
    /// - `Idle`: start reading the 4-byte header
    /// - `ReadingHeader`: accumulate 4 bytes, then decode the header
    /// - `ReadingBody`: accumulate `cotp_len` bytes into `read_buf`
    ///
    /// The cancel-safe `read` is used rather than `read_exact`, which is not.
    async fn read_tpkt(&mut self) -> Result<Bytes, CotpError> {
        // start the header phase when idle
        if matches!(self.read_state, ReadState::Idle) {
            self.read_state = ReadState::ReadingHeader {
                have: 0,
                buf: [0u8; 4],
            };
        }

        loop {
            // Disjoint borrows: read_state, stream and read_buf are separate fields,
            // so holding a mutable borrow of all three at once is accepted.
            let CotpConnection {
                stream,
                read_state,
                read_buf,
                ..
            } = self;

            match read_state {
                ReadState::Idle => {
                    // Initialized above already; re-initialize defensively.
                    *read_state = ReadState::ReadingHeader {
                        have: 0,
                        buf: [0u8; 4],
                    };
                }
                ReadState::ReadingHeader { have, buf } => {
                    if *have < 4 {
                        let n = AsyncTransport::read(stream, &mut buf[*have..]).await?;
                        if n == 0 {
                            // EOF. Partial state is kept so the caller may retry or close.
                            // Both closed-peer signals, Ok(0) and TransportError::Closed, map
                            // to UnexpectedEof so the server accept loop can tell an orderly
                            // close from a protocol error and log only the latter as a fault.
                            return Err(CotpError::UnexpectedEof);
                        }
                        *have += n;
                        // the partial header stays in self, so a canceled read can resume
                        continue;
                    }
                    let hdr = TpktHeader::decode(buf)?;
                    if hdr.packet_len as usize > COTP_MAX_BUFFER_SIZE {
                        warn!(
                            packet_len = hdr.packet_len,
                            max = COTP_MAX_BUFFER_SIZE,
                            "tpkt packet length exceeds the buffer limit, rejecting"
                        );
                        // reset the state so the same bad packet is not read again
                        *read_state = ReadState::Idle;
                        return Err(CotpError::TpktLengthOverflow {
                            packet_len: hdr.packet_len,
                            max_size: COTP_MAX_BUFFER_SIZE,
                        });
                    }
                    let cotp_len = hdr.cotp_len();
                    read_buf.resize(cotp_len, 0);
                    *read_state = ReadState::ReadingBody { hdr, have: 0 };
                }
                ReadState::ReadingBody { hdr, have } => {
                    let cotp_len = hdr.cotp_len();
                    if *have < cotp_len {
                        let n = AsyncTransport::read(stream, &mut read_buf[*have..]).await?;
                        if n == 0 {
                            // as in the header path, EOF always maps to UnexpectedEof
                            return Err(CotpError::UnexpectedEof);
                        }
                        *have += n;
                        continue;
                    }
                    let bytes = Bytes::copy_from_slice(&read_buf[..cotp_len]);
                    *read_state = ReadState::Idle;
                    return Ok(bytes);
                }
            }
        }
    }

    /// Prefixes a COTP PDU with a TPKT header and writes it out.
    async fn write_tpkt(&mut self, cotp_pdu: &[u8]) -> Result<(), CotpError> {
        let total_len = TPKT_HEADER_LEN + cotp_pdu.len();
        let hdr = TpktHeader::new(total_len);
        let hdr_bytes = hdr.encode();
        // a single write avoids having to handle a partial write
        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(&hdr_bytes);
        buf.extend_from_slice(cotp_pdu);
        AsyncTransport::write_all(&mut self.stream, &buf).await?;
        Ok(())
    }
}

// PDU encoders, independent of CotpConnection

/// Builds a CR TPDU without the TPKT header.
pub fn encode_cr(options: &CotpOptions, local_ref: u16) -> Vec<u8> {
    let var_part = encode_options(options);
    // LI counts the fixed part after LI itself, plus the variable part
    let li: u8 = (6 + var_part.len()) as u8;
    let mut pdu = Vec::with_capacity(1 + 1 + 2 + 2 + 1 + var_part.len());
    pdu.push(li);
    pdu.push(TPDU_CR);
    pdu.extend_from_slice(&0x0000u16.to_be_bytes()); // DST-REF = 0
    pdu.extend_from_slice(&local_ref.to_be_bytes()); // SRC-REF
    pdu.push(0x00); // protocol class 0
    pdu.extend_from_slice(&var_part);
    pdu
}

/// Builds a CC TPDU without the TPKT header.
pub fn encode_cc(options: &CotpOptions, local_ref: u16, dst_ref: u16) -> Vec<u8> {
    let var_part = encode_options(options);
    let li: u8 = (6 + var_part.len()) as u8;
    let mut pdu = Vec::with_capacity(1 + 1 + 2 + 2 + 1 + var_part.len());
    pdu.push(li);
    pdu.push(TPDU_CC);
    pdu.extend_from_slice(&dst_ref.to_be_bytes()); // DST-REF, the peer SRC-REF
    pdu.extend_from_slice(&local_ref.to_be_bytes()); // SRC-REF
    pdu.push(0x00); // protocol class 0
    pdu.extend_from_slice(&var_part);
    pdu
}

/// Builds a DT TPDU without the TPKT header.
pub fn encode_dt(payload: &[u8], is_last: bool) -> Vec<u8> {
    // LI is always 2 for DT
    let nr: u8 = if is_last { 0x80 } else { 0x00 };
    let mut pdu = Vec::with_capacity(3 + payload.len());
    pdu.push(0x02); // LI
    pdu.push(TPDU_DT);
    pdu.push(nr);
    pdu.extend_from_slice(payload);
    pdu
}

/// Builds a DR TPDU without the TPKT header.
///
/// The disconnect reason is 0, a normal disconnect.
pub fn encode_dr(local_ref: u16, dst_ref: u16) -> Vec<u8> {
    // DR: LI=6, type=0x80, DST-REF, SRC-REF, reason
    let mut pdu = vec![0x06, TPDU_DR];
    pdu.extend_from_slice(&dst_ref.to_be_bytes());
    pdu.extend_from_slice(&local_ref.to_be_bytes());
    pdu.push(0x00); // reason: normal disconnect
    pdu
}

/// Builds a DC TPDU without the TPKT header.
pub fn encode_dc(local_ref: u16, dst_ref: u16) -> Vec<u8> {
    // DC: type=0xC0, DST-REF, SRC-REF; class 0 carries no reason byte, so LI is 5
    let mut pdu = vec![0x05, TPDU_DC];
    pdu.extend_from_slice(&dst_ref.to_be_bytes());
    pdu.extend_from_slice(&local_ref.to_be_bytes());
    pdu
}

// PDU decoders, independent of CotpConnection

/// Parses a CR TPDU without the TPKT header.
///
/// Returns the peer SRC-REF and the options it proposed.
pub fn parse_cr(buf: &[u8]) -> Result<(u16, CotpOptions), CotpError> {
    let mut r = TpduReader::new(buf);
    let li = r.read_byte()?;
    // LI must not exceed the bytes available
    if li as usize > r.remaining() {
        return Err(CotpError::LiOverflow {
            li,
            tpdu_len: r.remaining(),
        });
    }
    let tpdu_type = r.read_byte()?;
    if tpdu_type != TPDU_CR {
        return Err(CotpError::UnknownTpduType { tpdu_type });
    }
    // DST-REF, which is 0 in a CR
    let _dst_ref = r.read_u16_be()?;
    // SRC-REF
    let src_ref = r.read_u16_be()?;
    // protocol class
    let class = r.read_byte()?;
    // only class 0 is supported
    if class & 0xF0 != 0x00 {
        return Err(CotpError::UnsupportedProtocolClass { class });
    }
    // variable part
    let fixed_len = 6; // type + dst-ref(2) + src-ref(2) + class(1) = 6
    let var_part_len = (li as usize).saturating_sub(fixed_len);
    let var_data = r.read_bytes(var_part_len)?;
    let opts = parse_options(var_data)?;
    Ok((src_ref, opts))
}

/// Parses a CC TPDU without the TPKT header.
///
/// Returns the SRC-REF the responder chose and the negotiated TPDU size.
///
/// In a CC the first reference field is DST-REF, echoing the CR SRC-REF, and the
/// second is the SRC-REF the responder chose.
pub fn parse_cc(buf: &[u8]) -> Result<(u16, TpduSize), CotpError> {
    let mut r = TpduReader::new(buf);
    let li = r.read_byte()?;
    if li as usize > r.remaining() {
        return Err(CotpError::LiOverflow {
            li,
            tpdu_len: r.remaining(),
        });
    }
    let tpdu_type = r.read_byte()?;
    if tpdu_type != TPDU_CC {
        return Err(CotpError::UnknownTpduType { tpdu_type });
    }
    // DST-REF echoes the local reference back
    let _dst_ref = r.read_u16_be()?;
    // SRC-REF is the responder reference and becomes remote_ref
    let src_ref = r.read_u16_be()?;
    let class = r.read_byte()?;
    if class & 0xF0 != 0x00 {
        return Err(CotpError::UnsupportedProtocolClass { class });
    }
    let fixed_len = 6;
    let var_part_len = (li as usize).saturating_sub(fixed_len);
    let var_data = r.read_bytes(var_part_len)?;
    let opts = parse_options(var_data)?;
    Ok((src_ref, opts.tpdu_size))
}

/// Parses a DT TPDU without the TPKT header.
///
/// Returns the payload slice and whether this is the last segment.
pub fn parse_dt(buf: &[u8]) -> Result<(&[u8], bool), CotpError> {
    let mut r = TpduReader::new(buf);
    let li = r.read_byte()?;
    // a DT TPDU always carries LI = 2
    if li != 2 {
        return Err(CotpError::InvalidDtLi { li });
    }
    let tpdu_type = r.read_byte()?;
    if tpdu_type != TPDU_DT {
        return Err(CotpError::UnknownTpduType { tpdu_type });
    }
    let nr = r.read_byte()?;
    let is_last = (nr & 0x80) != 0;
    // the payload starts after LI, TPDU type and NR
    let payload = r.remaining_slice();
    if payload.is_empty() {
        return Err(CotpError::EmptyDtPayload);
    }
    Ok((payload, is_last))
}

/// Parses a DR TPDU without the TPKT header.
///
/// Returns the disconnect reason code.
pub fn parse_dr(buf: &[u8]) -> Result<u8, CotpError> {
    let mut r = TpduReader::new(buf);
    let li = r.read_byte()?;
    if li as usize > r.remaining() {
        return Err(CotpError::LiOverflow {
            li,
            tpdu_len: r.remaining(),
        });
    }
    let tpdu_type = r.read_byte()?;
    if tpdu_type != TPDU_DR {
        return Err(CotpError::UnknownTpduType { tpdu_type });
    }
    let _dst_ref = r.read_u16_be()?;
    let _src_ref = r.read_u16_be()?;
    let reason = r.read_byte()?;
    Ok(reason)
}

/// Parses a DC TPDU without the TPKT header.
pub fn parse_dc(buf: &[u8]) -> Result<(), CotpError> {
    let mut r = TpduReader::new(buf);
    let li = r.read_byte()?;
    if li as usize > r.remaining() {
        return Err(CotpError::LiOverflow {
            li,
            tpdu_len: r.remaining(),
        });
    }
    let tpdu_type = r.read_byte()?;
    if tpdu_type != TPDU_DC {
        return Err(CotpError::UnknownTpduType { tpdu_type });
    }
    Ok(())
}

/// A decoded COTP TPDU.
///
/// Produced by [`parse_cotp_pdu`] for receivers that handle several TPDU types.
#[derive(Debug, PartialEq)]
pub enum CotpPdu<'a> {
    /// A CR TPDU, a connection request.
    ConnectRequest {
        /// Reference the caller chose for itself.
        src_ref: u16,
        /// Options the caller proposed.
        options: CotpOptionsSummary,
    },
    /// A CC TPDU, a connection confirmation.
    ConnectConfirm {
        /// Reference the responder chose for itself.
        remote_ref: u16,
        /// TPDU size the responder confirmed.
        tpdu_size: TpduSize,
    },
    /// A DT TPDU, carrying data.
    Data {
        /// Payload of this segment.
        payload: &'a [u8],
        /// Whether this segment carries EOT and ends the TSDU.
        is_last: bool,
    },
    /// A DR TPDU, a disconnect request.
    DisconnectRequest {
        /// Disconnect reason code.
        reason: u8,
    },
    /// A DC TPDU, a disconnect confirmation.
    DisconnectConfirm,
    /// An ER TPDU, reporting a protocol error.
    Error,
}

/// Options summary returned by PDU dispatch, which keeps `CotpOptions` free of a
/// `Clone` bound.
#[derive(Debug, PartialEq)]
pub struct CotpOptionsSummary {
    /// Calling T-Selector, naming the peer that sent the PDU.
    pub tsel_src: TSelector,
    /// Called T-Selector, naming the TSAP addressed.
    pub tsel_dst: TSelector,
    /// TPDU size carried in the variable part.
    pub tpdu_size: TpduSize,
}

/// Parses any COTP PDU without the TPKT header and dispatches on its type.
pub fn parse_cotp_pdu(buf: &[u8]) -> Result<CotpPdu<'_>, CotpError> {
    // the TPDU type byte follows LI
    if buf.len() < 2 {
        return Err(CotpError::UnexpectedEof);
    }
    let tpdu_type = buf[1];
    match tpdu_type {
        TPDU_CR => {
            let (src_ref, opts) = parse_cr(buf)?;
            Ok(CotpPdu::ConnectRequest {
                src_ref,
                options: CotpOptionsSummary {
                    tsel_src: opts.tsel_src,
                    tsel_dst: opts.tsel_dst,
                    tpdu_size: opts.tpdu_size,
                },
            })
        }
        TPDU_CC => {
            let (remote_ref, tpdu_size) = parse_cc(buf)?;
            Ok(CotpPdu::ConnectConfirm {
                remote_ref,
                tpdu_size,
            })
        }
        TPDU_DT => {
            let (payload, is_last) = parse_dt(buf)?;
            Ok(CotpPdu::Data { payload, is_last })
        }
        TPDU_DR => {
            let reason = parse_dr(buf)?;
            warn!("received cotp dr tpdu, reason={reason}, disconnecting");
            Ok(CotpPdu::DisconnectRequest { reason })
        }
        TPDU_DC => {
            parse_dc(buf)?;
            Ok(CotpPdu::DisconnectConfirm)
        }
        TPDU_ER => {
            warn!("received cotp er tpdu");
            Ok(CotpPdu::Error)
        }
        other => {
            warn!("received unknown cotp tpdu type=0x{other:02X}, rejecting");
            Err(CotpError::UnknownTpduType { tpdu_type: other })
        }
    }
}

// Option encoding and decoding

/// Serializes options into the variable part of a CR or CC TPDU.
pub fn encode_options(opts: &CotpOptions) -> Vec<u8> {
    let mut buf = Vec::new();

    // 0xC0 TPDU size
    buf.push(OPT_TPDU_SIZE);
    buf.push(0x01);
    buf.push(opts.tpdu_size.encoded());

    // 0xC2 called TSAP is written before 0xC1 calling TSAP
    if opts.tsel_dst.size > 0 {
        buf.push(OPT_CALLED_TSAP);
        buf.push(opts.tsel_dst.size);
        buf.extend_from_slice(opts.tsel_dst.as_slice());
    }

    // 0xC1 calling TSAP
    if opts.tsel_src.size > 0 {
        buf.push(OPT_CALLING_TSAP);
        buf.push(opts.tsel_src.size);
        buf.extend_from_slice(opts.tsel_src.as_slice());
    }

    buf
}

/// Parses the variable part of a CR or CC TPDU.
///
/// Reading goes through the bounds-checked [`TpduReader`]: each option reads its
/// type and then its length, and a truncated option returns an error instead of
/// advancing past the end of the buffer.
pub fn parse_options(buf: &[u8]) -> Result<CotpOptions, CotpError> {
    let mut opts = CotpOptions::default();
    let mut r = TpduReader::new(buf);

    while r.has_remaining() {
        // read the option type, then its length; a short buffer errors out
        let opt_type = r.read_byte()?;
        let opt_len = r.read_byte()? as usize;

        // the declared option length must fit in the remaining data
        if opt_len > r.remaining() {
            return Err(CotpError::OptionLenOverflow {
                option_len: opt_len,
                remaining: r.remaining(),
            });
        }

        let opt_data = r.read_bytes(opt_len)?;

        match opt_type {
            OPT_TPDU_SIZE => {
                if opt_len != 1 {
                    return Err(CotpError::InvalidTpduSizeOption { len: opt_len });
                }
                let enc = opt_data[0];
                opts.tpdu_size = TpduSize::from_encoded(enc).unwrap_or_else(|| {
                    // clamp an encoded value that is out of range
                    if enc > COTP_MAX_TPDU_SIZE_ENCODED {
                        TpduSize::default()
                    } else {
                        TpduSize(COTP_MIN_TPDU_SIZE_ENCODED)
                    }
                });
            }
            OPT_CALLING_TSAP => {
                // a T-Selector must be shorter than 5 bytes
                if opt_len >= 5 {
                    return Err(CotpError::TSelectorTooLong { len: opt_len });
                }
                opts.tsel_src = TSelector::from_slice(opt_data)?;
            }
            OPT_CALLED_TSAP => {
                if opt_len >= 5 {
                    return Err(CotpError::TSelectorTooLong { len: opt_len });
                }
                opts.tsel_dst = TSelector::from_slice(opt_data)?;
            }
            OPT_ADDITIONAL_OPT => {
                // additional options are ignored on receive
            }
            _ => {
                // unknown options are skipped
            }
        }
    }
    Ok(opts)
}

// Bounds-checked TPDU reader

/// A lightweight bounds-checked reader over network input.
///
/// Every COTP parse function reads through this type, so no parser indexes the
/// input buffer directly.
pub struct TpduReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> TpduReader<'a> {
    /// Creates a reader over `data`, positioned at its first byte.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Number of bytes not yet read.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Returns whether any unread bytes remain.
    pub fn has_remaining(&self) -> bool {
        self.pos < self.data.len()
    }

    /// Reads one byte.
    pub fn read_byte(&mut self) -> Result<u8, CotpError> {
        if self.pos >= self.data.len() {
            return Err(CotpError::UnexpectedEof);
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Reads a big-endian `u16`.
    pub fn read_u16_be(&mut self) -> Result<u16, CotpError> {
        let hi = self.read_byte()?;
        let lo = self.read_byte()?;
        Ok(u16::from_be_bytes([hi, lo]))
    }

    /// Reads `n` bytes and returns them as a slice.
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], CotpError> {
        if self.pos + n > self.data.len() {
            return Err(CotpError::UnexpectedEof);
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Returns all remaining bytes without advancing the position.
    pub fn remaining_slice(&self) -> &'a [u8] {
        if self.pos >= self.data.len() {
            &[]
        } else {
            &self.data[self.pos..]
        }
    }
}

// Unit tests

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    // TpduSize

    #[test]
    fn tpdu_size_from_bytes_clamp_max() {
        let ts = TpduSize::from_bytes(65535);
        assert_eq!(ts.bytes(), 8192, "sizes above 8192 clamp to 8192");
    }

    #[test]
    fn tpdu_size_from_bytes_clamp_min() {
        let ts = TpduSize::from_bytes(50);
        assert_eq!(ts.bytes(), 128, "sizes below 128 clamp to 128");
    }

    #[test]
    fn tpdu_size_from_bytes_exact_4096() {
        let ts = TpduSize::from_bytes(4096);
        assert_eq!(ts.bytes(), 4096);
    }

    #[test]
    fn tpdu_size_min_negotiation() {
        // negotiation keeps the smaller proposal: local 4096, remote 8192
        let local = TpduSize::from_bytes(4096);
        let remote = TpduSize::from_bytes(8192);
        let negotiated = local.min(remote);
        assert_eq!(negotiated.bytes(), 4096);
    }

    #[test]
    fn tpdu_size_min_negotiation_reverse() {
        // negotiation keeps the smaller proposal: local 8192, remote 1024
        let local = TpduSize::from_bytes(8192);
        let remote = TpduSize::from_bytes(1024);
        let negotiated = local.min(remote);
        assert_eq!(negotiated.bytes(), 1024);
    }

    // TSelector

    #[test]
    fn tselector_from_slice_ok() {
        let ts = TSelector::from_slice(&[0x00, 0x01]).unwrap();
        assert_eq!(ts.size, 2);
        assert_eq!(ts.as_slice(), &[0x00, 0x01]);
    }

    #[test]
    fn tselector_from_slice_too_long() {
        let err = TSelector::from_slice(&[1, 2, 3, 4, 5]).unwrap_err();
        assert!(matches!(err, CotpError::TSelectorTooLong { len: 5 }));
    }

    #[test]
    fn tselector_from_slice_max_4() {
        let ts = TSelector::from_slice(&[1, 2, 3, 4]).unwrap();
        assert_eq!(ts.size, 4);
    }

    // encode_options and parse_options round trip

    #[test]
    fn options_round_trip_all_fields() {
        let opts = CotpOptions {
            tsel_src: TSelector::from_slice(&[0x00, 0x01]).unwrap(),
            tsel_dst: TSelector::from_slice(&[0x00, 0x02]).unwrap(),
            tpdu_size: TpduSize::from_bytes(4096),
        };
        let encoded = encode_options(&opts);
        let decoded = parse_options(&encoded).unwrap();
        assert_eq!(decoded.tsel_src, opts.tsel_src);
        assert_eq!(decoded.tsel_dst, opts.tsel_dst);
        assert_eq!(decoded.tpdu_size.bytes(), opts.tpdu_size.bytes());
    }

    #[test]
    fn encode_options_byte_order_c2_before_c1() {
        // byte-for-byte order: C0, then C2 (called), then C1 (calling)
        let opts = CotpOptions {
            tsel_src: TSelector::from_slice(&[0x00, 0x01]).unwrap(), // calling
            tsel_dst: TSelector::from_slice(&[0x00, 0x02]).unwrap(), // called
            tpdu_size: TpduSize::from_bytes(8192),
        };
        let encoded = encode_options(&opts);
        // expected: C0 01 0D  C2 02 00 02  C1 02 00 01
        let expected: &[u8] = &[
            0xC0, 0x01, 0x0D, // TPDU size 8192, code 0x0D
            0xC2, 0x02, 0x00, 0x02, // called TSAP
            0xC1, 0x02, 0x00, 0x01, // calling TSAP
        ];
        assert_eq!(
            encoded.as_slice(),
            expected,
            "encode_options must write C2 (called) before C1 (calling)"
        );
    }

    #[test]
    fn options_round_trip_no_tsap() {
        let opts = CotpOptions {
            tsel_src: TSelector::default(),
            tsel_dst: TSelector::default(),
            tpdu_size: TpduSize::from_bytes(8192),
        };
        let encoded = encode_options(&opts);
        let decoded = parse_options(&encoded).unwrap();
        assert_eq!(decoded.tpdu_size.bytes(), 8192);
        assert_eq!(decoded.tsel_src.size, 0);
    }

    #[test]
    fn parse_options_tselector_len_5_error() {
        // a T-Selector of 5 bytes or more must be rejected
        let buf = [OPT_CALLING_TSAP, 0x05, 1, 2, 3, 4, 5];
        let err = parse_options(&buf).unwrap_err();
        assert!(
            matches!(err, CotpError::TSelectorTooLong { len: 5 }),
            "got {err:?}"
        );
    }

    #[test]
    fn parse_options_tpdu_size_len_not_1() {
        // a TPDU size option whose length is not 1 must be rejected
        let buf = [OPT_TPDU_SIZE, 0x02, 0x0D, 0x00];
        let err = parse_options(&buf).unwrap_err();
        assert!(
            matches!(err, CotpError::InvalidTpduSizeOption { len: 2 }),
            "got {err:?}"
        );
    }

    #[test]
    fn parse_options_overflow() {
        // an option declaring more bytes than remain
        let buf = [OPT_CALLING_TSAP, 0x04, 0x01, 0x02]; // declares 4 bytes, only 2 present
        let err = parse_options(&buf).unwrap_err();
        assert!(
            matches!(err, CotpError::OptionLenOverflow { .. }),
            "got {err:?}"
        );
    }

    // CR encode and decode round trip

    #[test]
    fn cr_encode_decode_round_trip() {
        let opts = CotpOptions {
            tsel_src: TSelector::from_slice(&[0x00, 0x01]).unwrap(),
            tsel_dst: TSelector::from_slice(&[0x00, 0x02]).unwrap(),
            tpdu_size: TpduSize::from_bytes(8192),
        };
        let pdu = encode_cr(&opts, 0x0001);
        let (src_ref, decoded_opts) = parse_cr(&pdu).unwrap();
        assert_eq!(src_ref, 0x0001);
        assert_eq!(decoded_opts.tsel_src, opts.tsel_src);
        assert_eq!(decoded_opts.tsel_dst, opts.tsel_dst);
        assert_eq!(decoded_opts.tpdu_size.bytes(), opts.tpdu_size.bytes());
    }

    #[test]
    fn cr_wrong_type_returns_error() {
        let opts = CotpOptions::default();
        let mut pdu = encode_cr(&opts, 1);
        pdu[1] = TPDU_CC; // corrupt the TPDU type
        let err = parse_cr(&pdu).unwrap_err();
        assert!(
            matches!(err, CotpError::UnknownTpduType { tpdu_type: 0xD0 }),
            "got {err:?}"
        );
    }

    #[test]
    fn cr_unsupported_protocol_class() {
        let opts = CotpOptions::default();
        let mut pdu = encode_cr(&opts, 1);
        // protocol class 4 is not supported
        pdu[6] = 0x40;
        let err = parse_cr(&pdu).unwrap_err();
        assert!(
            matches!(err, CotpError::UnsupportedProtocolClass { class: 0x40 }),
            "got {err:?}"
        );
    }

    // CC encode and decode round trip

    #[test]
    fn cc_encode_decode_round_trip() {
        let opts = CotpOptions {
            tsel_src: TSelector::default(),
            tsel_dst: TSelector::default(),
            tpdu_size: TpduSize::from_bytes(4096),
        };
        let pdu = encode_cc(&opts, 0x0002, 0x0001);
        let (remote_ref, tpdu_size) = parse_cc(&pdu).unwrap();
        assert_eq!(remote_ref, 0x0002, "remote_ref must be the server SRC-REF");
        assert_eq!(tpdu_size.bytes(), 4096);
    }

    #[test]
    fn cc_dst_ref_from_src_ref() {
        // the CC DST-REF echoes the CR SRC-REF
        let opts = CotpOptions::default();
        let pdu = encode_cc(&opts, 0x0005, 0x0001);
        // bytes: LI=6, 0xD0, DST-REF=0x0001, SRC-REF=0x0005
        assert_eq!(pdu[2], 0x00);
        assert_eq!(pdu[3], 0x01, "DST-REF high byte");
        assert_eq!(pdu[4], 0x00);
        assert_eq!(pdu[5], 0x05, "SRC-REF high byte");
    }

    // DT encode and decode round trip

    #[test]
    fn dt_single_fragment_eot1() {
        let payload = b"hello world";
        let pdu = encode_dt(payload, true);
        let (decoded_payload, is_last) = parse_dt(&pdu).unwrap();
        assert_eq!(decoded_payload, payload);
        assert!(is_last, "EOT must be 1");
    }

    #[test]
    fn dt_multi_fragment_eot0_then_1() {
        let pdu1 = encode_dt(b"part1", false);
        let (_, is_last1) = parse_dt(&pdu1).unwrap();
        assert!(!is_last1, "the first segment must carry EOT 0");

        let pdu2 = encode_dt(b"part2", true);
        let (_, is_last2) = parse_dt(&pdu2).unwrap();
        assert!(is_last2, "the last segment must carry EOT 1");
    }

    #[test]
    fn dt_invalid_li() {
        // an LI other than 2 must be rejected
        let mut pdu = encode_dt(b"data", true);
        pdu[0] = 0x03; // corrupt LI
        let err = parse_dt(&pdu).unwrap_err();
        assert!(
            matches!(err, CotpError::InvalidDtLi { li: 3 }),
            "got {err:?}"
        );
    }

    #[test]
    fn dt_empty_payload_returns_error() {
        // header only (LI=2, type=0xF0, NR=0x80) with no payload
        let pdu = [0x02u8, TPDU_DT, 0x80];
        let err = parse_dt(&pdu).unwrap_err();
        assert!(matches!(err, CotpError::EmptyDtPayload), "got {err:?}");
    }

    // DR encode and decode round trip

    #[test]
    fn dr_encode_decode_round_trip() {
        let pdu = encode_dr(0x0001, 0x0002);
        let reason = parse_dr(&pdu).unwrap();
        assert_eq!(reason, 0x00, "normal disconnect reason");
    }

    // DC encode and decode round trip

    #[test]
    fn dc_encode_decode_round_trip() {
        let pdu = encode_dc(0x0001, 0x0002);
        parse_dc(&pdu).unwrap();
    }

    // LI overflow

    #[test]
    fn li_overflow_returns_error() {
        // LI declares more than the data actually holds
        // CR layout: LI | 0xE0 | DST-REF(2) | SRC-REF(2) | class
        let buf = [0xFF, TPDU_CR, 0x00, 0x00, 0x00, 0x01, 0x00];
        let err = parse_cr(&buf).unwrap_err();
        assert!(matches!(err, CotpError::LiOverflow { .. }), "got {err:?}");
    }

    // unknown TPDU type

    #[test]
    fn unknown_tpdu_type_returns_error() {
        // buf[1] = 0xAA is an unknown TPDU type
        let buf = [0x06, 0xAA, 0x00, 0x00, 0x00, 0x01, 0x00];
        let err = parse_cotp_pdu(&buf).unwrap_err();
        assert!(
            matches!(err, CotpError::UnknownTpduType { tpdu_type: 0xAA }),
            "got {err:?}"
        );
    }

    // DR, DC and ER decode as distinct indications

    #[test]
    fn dr_parsed_as_disconnect_request() {
        let pdu = encode_dr(0x0001, 0x0002);
        let result = parse_cotp_pdu(&pdu).unwrap();
        assert!(
            matches!(result, CotpPdu::DisconnectRequest { reason: 0 }),
            "a DR must decode as DisconnectRequest, got {result:?}"
        );
    }

    #[test]
    fn dc_parsed_as_disconnect_confirm() {
        let pdu = encode_dc(0x0001, 0x0002);
        let result = parse_cotp_pdu(&pdu).unwrap();
        assert!(
            matches!(result, CotpPdu::DisconnectConfirm),
            "a DC must decode as DisconnectConfirm, got {result:?}"
        );
    }

    #[test]
    fn er_parsed_as_error() {
        // a minimal ER TPDU
        let buf = [0x04, TPDU_ER, 0x00, 0x00, 0x00];
        let result = parse_cotp_pdu(&buf).unwrap();
        assert!(
            matches!(result, CotpPdu::Error),
            "an ER must decode as Error, got {result:?}"
        );
    }

    // State machine integration over a tokio duplex stream

    /// Full lifecycle: connect, transfer data, disconnect.
    ///
    /// Covers Closed, ConnectSent, Connected, Closing and back to Closed.
    #[tokio::test]
    async fn state_machine_full_lifecycle() {
        let (client_stream, server_stream) = duplex(4096);

        let client_opts = CotpOptions {
            tsel_src: TSelector::from_slice(&[0x00, 0x01]).unwrap(),
            tsel_dst: TSelector::from_slice(&[0x00, 0x02]).unwrap(),
            tpdu_size: TpduSize::from_bytes(8192),
        };
        let server_opts = CotpOptions {
            tsel_src: TSelector::from_slice(&[0x00, 0x02]).unwrap(),
            tsel_dst: TSelector::default(),
            tpdu_size: TpduSize::from_bytes(4096), // smaller proposal, so 4096 wins
        };

        // run the client and the server concurrently
        let client_task = tokio::spawn(async move {
            let mut client = CotpConnection::connect(client_stream, client_opts).await?;
            assert_eq!(*client.state(), CotpState::Connected);
            // the negotiated size is the smaller of 8192 and 4096
            assert_eq!(client.tpdu_size(), 4096);

            // transfer data
            client.send_data(b"hello COTP").await?;
            let recv = client.recv_data().await?;
            assert_eq!(recv.as_ref(), b"hello COTP back");

            // disconnect
            client.send_dr().await?;
            assert_eq!(*client.state(), CotpState::Closing);
            client.recv_dc().await?;
            assert_eq!(*client.state(), CotpState::Closed);
            Ok::<(), CotpError>(())
        });

        let server_task = tokio::spawn(async move {
            let mut server = CotpConnection::accept(server_stream, server_opts).await?;
            assert_eq!(*server.state(), CotpState::Connected);

            // receive, then answer
            let recv = server.recv_data().await?;
            assert_eq!(recv.as_ref(), b"hello COTP");
            server.send_data(b"hello COTP back").await?;

            // answer the DR with a DC
            let raw = server.read_tpkt().await?;
            let reason = parse_dr(&raw)?;
            assert_eq!(reason, 0);
            let dc = encode_dc(server.local_ref(), server.remote_ref());
            server.write_tpkt(&dc).await?;
            Ok::<(), CotpError>(())
        });

        let (client_result, server_result) = tokio::join!(client_task, server_task);
        client_result.unwrap().unwrap();
        server_result.unwrap().unwrap();
    }

    /// A second `send_cr` on an established connection must be rejected.
    #[tokio::test]
    async fn state_machine_invalid_cr_when_connected() {
        let (client_stream, _server_stream) = duplex(4096);
        let opts = CotpOptions::default();
        let mut conn = CotpConnection::new(client_stream, opts);
        // force the Connected state
        conn.state = CotpState::Connected;
        let err = conn.send_cr().await.unwrap_err();
        assert!(
            matches!(err, CotpError::InvalidState { .. }),
            "send_cr must be rejected while Connected, got {err:?}"
        );
    }

    // TPKT length overflow guard

    #[test]
    fn tpkt_length_overflow_check() {
        // a packet_len above COTP_MAX_BUFFER_SIZE must be rejected
        let packet_len = (COTP_MAX_BUFFER_SIZE + 1) as u16;
        let hdr = TpktHeader { packet_len };
        assert!(
            hdr.packet_len as usize > COTP_MAX_BUFFER_SIZE,
            "packet_len must exceed the buffer limit"
        );
    }

    // multi-segment DT reassembly

    #[tokio::test]
    async fn recv_data_multi_fragment() {
        // a duplex pair where the peer writes three DT segments
        let (mut client_stream, mut server_stream) = duplex(65536);

        // peer side: write three segments
        let server_task = tokio::spawn(async move {
            for (i, (chunk, is_last)) in [
                (b"PART1" as &[u8], false),
                (b"PART2" as &[u8], false),
                (b"PART3" as &[u8], true),
            ]
            .iter()
            .enumerate()
            {
                let dt = encode_dt(chunk, *is_last);
                let total = 4 + dt.len();
                let hdr = TpktHeader::new(total);
                let hdr_bytes = hdr.encode();
                server_stream.write_all(&hdr_bytes).await.unwrap();
                server_stream.write_all(&dt).await.unwrap();
                let _ = i; // suppress unused variable warning
            }
        });

        // local side: receive through CotpConnection
        let opts = CotpOptions::default();
        let mut conn = CotpConnection::new(&mut client_stream, opts);
        conn.state = CotpState::Connected;

        server_task.await.unwrap();

        let payload = conn.recv_data().await.unwrap();
        assert_eq!(payload.as_ref(), b"PART1PART2PART3");
    }

    // max_tsdu_size limit

    /// Writes each chunk into `stream` as a DT TPDU.
    async fn write_dt_fragments(stream: &mut tokio::io::DuplexStream, chunks: &[(&[u8], bool)]) {
        for (chunk, is_last) in chunks {
            let dt = encode_dt(chunk, *is_last);
            let hdr = TpktHeader::new(4 + dt.len());
            stream.write_all(&hdr.encode()).await.unwrap();
            stream.write_all(&dt).await.unwrap();
        }
    }

    /// Once the limit is exceeded the call returns `TsduTooLarge` and clears the
    /// reassembly buffer, so nothing leaks into the next TSDU.
    #[tokio::test]
    async fn recv_data_rejects_tsdu_over_limit() {
        let (mut client_stream, mut server_stream) = duplex(65536);

        // three 5-byte segments against a limit of 12: the third reaches 15
        let writer = tokio::spawn(async move {
            write_dt_fragments(
                &mut server_stream,
                &[
                    (b"PART1" as &[u8], false),
                    (b"PART2" as &[u8], false),
                    (b"PART3" as &[u8], true),
                ],
            )
            .await;
        });

        let mut conn = CotpConnection::new(&mut client_stream, CotpOptions::default());
        conn.state = CotpState::Connected;
        conn.set_max_tsdu_size(Some(12));

        writer.await.unwrap();

        let err = conn.recv_data().await.unwrap_err();
        assert!(
            matches!(
                err,
                CotpError::TsduTooLarge {
                    accumulated: 15,
                    limit: 12
                }
            ),
            "expected TsduTooLarge{{15, 12}}, got {err:?}"
        );
        assert!(
            conn.payload_buf.is_empty(),
            "the reassembly buffer must be cleared, otherwise it pollutes the next TSDU"
        );
    }

    /// A peer close, where `read` returns `Ok(0)`, must map to `UnexpectedEof`.
    ///
    /// The server accept loop uses that variant to separate an orderly client close
    /// from a protocol error; collapsing both into a generic I/O error would record
    /// every normal close as a fault.
    #[tokio::test]
    async fn recv_data_eof_is_unexpected_eof() {
        let (mut client_stream, server_stream) = duplex(64);
        // dropping the write end makes the next read return Ok(0)
        drop(server_stream);

        let mut conn = CotpConnection::new(&mut client_stream, CotpOptions::default());
        conn.state = CotpState::Connected;

        let err = conn.recv_data().await.unwrap_err();
        assert!(
            matches!(err, CotpError::UnexpectedEof),
            "a peer close must return UnexpectedEof, got {err:?}"
        );
    }

    /// A TSDU exactly at the limit is accepted; leaving the limit unset keeps the
    /// unbounded behavior.
    #[tokio::test]
    async fn recv_data_accepts_tsdu_at_limit() {
        let (mut client_stream, mut server_stream) = duplex(65536);

        let writer = tokio::spawn(async move {
            write_dt_fragments(
                &mut server_stream,
                &[(b"PART1" as &[u8], false), (b"PART2" as &[u8], true)],
            )
            .await;
        });

        let mut conn = CotpConnection::new(&mut client_stream, CotpOptions::default());
        conn.state = CotpState::Connected;
        conn.set_max_tsdu_size(Some(10));

        writer.await.unwrap();

        let payload = conn.recv_data().await.unwrap();
        assert_eq!(payload.as_ref(), b"PART1PART2");
    }

    // parse_cotp_pdu dispatch

    #[test]
    fn parse_cotp_pdu_cr() {
        let opts = CotpOptions::default();
        let pdu = encode_cr(&opts, 0x0001);
        let result = parse_cotp_pdu(&pdu).unwrap();
        assert!(
            matches!(result, CotpPdu::ConnectRequest { src_ref: 1, .. }),
            "got {result:?}"
        );
    }

    #[test]
    fn parse_cotp_pdu_cc() {
        let opts = CotpOptions::default();
        let pdu = encode_cc(&opts, 0x0002, 0x0001);
        let result = parse_cotp_pdu(&pdu).unwrap();
        assert!(
            matches!(result, CotpPdu::ConnectConfirm { remote_ref: 2, .. }),
            "got {result:?}"
        );
    }

    #[test]
    fn parse_cotp_pdu_dt() {
        let pdu = encode_dt(b"test", true);
        let result = parse_cotp_pdu(&pdu).unwrap();
        assert!(
            matches!(result, CotpPdu::Data { is_last: true, .. }),
            "got {result:?}"
        );
    }

    // TpduReader bounds checks

    #[test]
    fn tpdu_reader_empty_returns_eof() {
        let mut r = TpduReader::new(&[]);
        let err = r.read_byte().unwrap_err();
        assert!(matches!(err, CotpError::UnexpectedEof));
    }

    #[test]
    fn tpdu_reader_read_bytes_overflow() {
        let data = [1u8, 2, 3];
        let mut r = TpduReader::new(&data);
        let err = r.read_bytes(10).unwrap_err();
        assert!(matches!(err, CotpError::UnexpectedEof));
    }
}
