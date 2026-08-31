//! ISO 8327 Session layer, restricted to the subset MMS requires.
//!
//! Encodes and decodes:
//! 1. CONNECT (CN, ID 13) and ACCEPT (AC, ID 14) SPDUs.
//! 2. Data (DT) SPDUs, whose header is the fixed four bytes 01 00 01 00.
//! 3. ABORT (AB, ID 25), FINISH (FN, ID 9), DISCONNECT (DN, ID 10) and REFUSE
//!    (RF, ID 12) SPDUs.
//! 4. No state machine and no transport: SPDUs are serialized and parsed, and
//!    connection state stays with the caller.
//!
//! Strictness rules enforced by this module:
//! - The long form of LI is not supported; a payload past 255 bytes returns
//!   `SessionError::PayloadTooLarge`.
//! - SESSION_NOT_FINISHED (SPDU ID 8) is not reassembled and returns
//!   `SessionError::UnsupportedSpdu`.
//! - An unknown PGI is skipped by its declared length, never byte by byte.
//! - A session requirement other than duplex (0x0002) is logged, not rejected.
//! - A zero-length selector is accepted and logged.
//!
//! Interoperability accommodations in `encode_refuse`:
//! - The LI byte is left at 0 rather than filled in. Writing the true length
//!   there makes the REFUSE SPDU unparseable at the peer.
//! - The nested connection-identifier length is written as 2 although 6 bytes of
//!   content follow, for the same reason.
//!
//! Both places carry a NOTE comment marking the deviation.

use crate::compat::prelude::*;
use bytes::BytesMut;
use tracing::warn;

// Constants

/// SPDU identifiers.
const SPDU_ID_FINISH: u8 = 0x09;
const SPDU_ID_DISCONNECT: u8 = 0x0A;
const SPDU_ID_REFUSE: u8 = 0x0C;
const SPDU_ID_CONNECT: u8 = 0x0D;
const SPDU_ID_ACCEPT: u8 = 0x0E;
const SPDU_ID_NOT_FINISHED: u8 = 0x08;
const SPDU_ID_DATA: u8 = 0x01;
const SPDU_ID_DATA_DT: u8 = 0x01; // the byte following DT, Data Transfer
const SPDU_ID_ABORT: u8 = 0x19;

/// PGI and PI identifiers.
const PGI_CONNECT_ACCEPT_ITEM: u8 = 0x05;
const PI_PROTOCOL_OPTIONS: u8 = 0x13; // 19
const PI_VERSION_NUMBER: u8 = 0x16; // 22
const PGI_SESSION_REQUIREMENT: u8 = 0x14; // 20
const PGI_CALLING_SS_SEL: u8 = 0x33; // 51
const PGI_CALLED_SS_SEL: u8 = 0x34; // 52
const PGI_USER_DATA: u8 = 0xC1; // 193

/// The fixed four-byte header of a Data SPDU: GT followed by DT.
///
/// On the wire this is `{0x01, 0x00, 0x01, 0x00}`, per ISO 8327-1.
pub const DATA_SPDU_HEADER: [u8; 4] = [SPDU_ID_DATA, 0x00, SPDU_ID_DATA_DT, 0x00];

/// Session requirement value announcing the duplex functional unit.
const SESSION_REQ_DUPLEX: u16 = 0x0002;

/// Maximum length of a Session Selector in bytes.
const SSELECTOR_MAX_SIZE: usize = 16;

/// Largest value a one-byte LI can carry.
const LI_MAX: usize = 255;

// Error types

/// Errors raised by the Session layer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionError {
    /// The message is too short: fewer than 2 bytes, or an LI beyond what remains.
    #[error("session message too short (len={len})")]
    TooShort {
        /// Length of the message received.
        len: usize,
    },

    /// The SPDU ID is NOT-FINISHED (0x08); segment reassembly is not supported.
    #[error("unsupported spdu (id=0x{id:02X})")]
    UnsupportedSpdu {
        /// SPDU identifier received.
        id: u8,
    },

    /// The protocol version, PI 22, is not 2.
    #[error("session version must be 2, got {version}")]
    InvalidVersion {
        /// Protocol version received; it must be 2.
        version: u8,
    },

    /// A selector is longer than 16 bytes.
    #[error("session selector length {len} exceeds the maximum of 16")]
    SelectorTooLong {
        /// Selector length received.
        len: u8,
    },

    /// A Data SPDU is malformed: byte 2 is not 1, or byte 3 is not 0.
    #[error("malformed data spdu")]
    InvalidDataSpdu,

    /// The declared LI does not match the length of the buffer.
    #[error("spdu li={li} does not match the buffer length {buf_len}")]
    LiMismatch {
        /// Length indicator the SPDU declared.
        li: usize,
        /// Length of the buffer actually supplied.
        buf_len: usize,
    },

    /// The SPDU ID is not recognized.
    #[error("unknown spdu id 0x{id:02X}")]
    UnknownSpdu {
        /// SPDU identifier received.
        id: u8,
    },

    /// The payload exceeds the 255 bytes a one-byte LI can express.
    #[error("payload size {size} exceeds the li maximum of 255; the long form is unsupported")]
    PayloadTooLarge {
        /// Payload size requested.
        size: usize,
    },
}

// Data structures

/// A Session Selector of at most 16 bytes.
///
/// A `size` of 0 is an empty selector, which is accepted and logged when parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SSelector {
    /// Number of significant bytes, in the range 0..=16.
    pub size: u8,
    /// Selector octets; only the first `size` bytes are significant.
    pub value: [u8; 16],
}

impl SSelector {
    /// Builds the default local selector, the two bytes 0x00 0x01.
    pub fn default_local() -> Self {
        let mut v = [0u8; 16];
        v[0] = 0x00;
        v[1] = 0x01;
        Self { size: 2, value: v }
    }

    /// Builds a selector from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::SelectorTooLong` when `data` is longer than 16 bytes.
    pub fn from_slice(data: &[u8]) -> Result<Self, SessionError> {
        if data.len() > SSELECTOR_MAX_SIZE {
            return Err(SessionError::SelectorTooLong {
                len: data.len() as u8,
            });
        }
        let mut value = [0u8; 16];
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

impl Default for SSelector {
    fn default() -> Self {
        Self::default_local()
    }
}

/// Connection parameters passed to `encode_connect`.
#[derive(Debug, Clone)]
pub struct IsoParameters {
    /// Local Session Selector (Calling SS-SEL).
    pub local_selector: SSelector,
    /// Peer Session Selector (Called SS-SEL).
    pub remote_selector: SSelector,
}

#[allow(clippy::derivable_impls)]
impl Default for IsoParameters {
    // SSelector::default() is all zeroes with size 0, while these parameters need the
    // two-byte default local selector, so Default is implemented by hand.
    fn default() -> Self {
        Self {
            local_selector: SSelector::default_local(),
            remote_selector: SSelector::default_local(),
        }
    }
}

/// The outcome of parsing one SPDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionIndication {
    /// A CN SPDU, a connection request. `user_data_range` locates the PGI 0xC1
    /// payload inside the input slice.
    Connect,
    /// An AC SPDU, a connection acceptance.
    Accept,
    /// A DT SPDU carrying data; `user_data_range` starts after the four-byte header.
    Data,
    /// An FN SPDU, an orderly release request.
    Finish,
    /// A DN SPDU, an orderly release confirmation.
    Disconnect,
    /// An AB SPDU. Any message beginning with 0x19 is accepted.
    Abort,
}

/// Session-layer state retained across calls.
#[derive(Debug, Clone)]
pub struct IsoSession {
    /// Local Session Selector (Calling SS-SEL).
    pub calling_selector: SSelector,
    /// Peer Session Selector (Called SS-SEL).
    pub called_selector: SSelector,
    /// Session user requirement; 0x0002 is duplex.
    pub session_requirement: u16,
    /// Protocol options byte read from the peer CONNECT or ACCEPT.
    pub protocol_options: u8,
    /// Byte offset range of the user-data seen by the most recent `parse_message`.
    user_data_start: usize,
    user_data_len: usize,
}

impl IsoSession {
    /// Creates a session with the default selectors and requirement.
    pub fn new() -> Self {
        Self {
            calling_selector: SSelector::default_local(),
            called_selector: SSelector::default_local(),
            session_requirement: SESSION_REQ_DUPLEX,
            protocol_options: 0,
            user_data_start: 0,
            user_data_len: 0,
        }
    }

    /// Returns the user-data view recorded by the most recent `parse_message`.
    ///
    /// The slice borrows `msg`, so the caller must use it before that buffer is reused.
    pub fn user_data<'msg>(&self, msg: &'msg [u8]) -> &'msg [u8] {
        let end = self.user_data_start + self.user_data_len;
        if end <= msg.len() {
            &msg[self.user_data_start..end]
        } else {
            &[]
        }
    }

    /// Parses one complete SPDU.
    ///
    /// A malformed SPDU is logged and returns an error.
    ///
    /// # Bounds checking
    ///
    /// - Every byte read is bounds checked against the remaining length.
    /// - An LI that runs past the buffer returns an error instead of reading on.
    pub fn parse_message(&mut self, msg: &[u8]) -> Result<SessionIndication, SessionError> {
        // An SPDU ID byte and an LI byte are the minimum
        if msg.len() < 2 {
            warn!(len = msg.len(), "session message too short, rejecting");
            return Err(SessionError::TooShort { len: msg.len() });
        }

        let spdu_id = msg[0];

        match spdu_id {
            SPDU_ID_DATA => self.parse_data_spdu(msg),
            SPDU_ID_CONNECT => self.parse_connect_spdu(msg),
            SPDU_ID_ACCEPT => self.parse_accept_spdu(msg),
            SPDU_ID_FINISH => {
                self.extract_user_data_from_simple(msg)?;
                Ok(SessionIndication::Finish)
            }
            SPDU_ID_DISCONNECT => {
                self.extract_user_data_from_simple(msg)?;
                Ok(SessionIndication::Disconnect)
            }
            SPDU_ID_ABORT => {
                // Any message beginning with 0x19 is accepted as an ABORT without
                // validating its content, which keeps the release path interoperable.
                self.user_data_start = 0;
                self.user_data_len = 0;
                Ok(SessionIndication::Abort)
            }
            SPDU_ID_NOT_FINISHED => {
                // segment reassembly is not supported, so the spdu is rejected
                warn!(
                    spdu_id = 0x08u8,
                    "received a not-finished spdu; segment reassembly is unsupported, rejecting"
                );
                Err(SessionError::UnsupportedSpdu { id: spdu_id })
            }
            _ => {
                warn!(spdu_id, "received an unknown spdu id, rejecting");
                Err(SessionError::UnknownSpdu { id: spdu_id })
            }
        }
    }

    // Parsing helpers

    /// Parses a Data SPDU.
    fn parse_data_spdu(&mut self, msg: &[u8]) -> Result<SessionIndication, SessionError> {
        // at least 4 bytes, with byte[1] = 0, byte[2] = 1 and byte[3] = 0
        if msg.len() < 4 {
            warn!(len = msg.len(), "data spdu shorter than 4 bytes");
            return Err(SessionError::TooShort { len: msg.len() });
        }
        if msg[1] != 0x00 || msg[2] != SPDU_ID_DATA_DT || msg[3] != 0x00 {
            warn!("malformed data spdu: bytes 1 to 3 are not 00 01 00");
            return Err(SessionError::InvalidDataSpdu);
        }
        self.user_data_start = 4;
        self.user_data_len = msg.len() - 4;
        Ok(SessionIndication::Data)
    }

    /// Parses a FINISH or DISCONNECT SPDU and returns the payload after PGI 0xC1.
    fn extract_user_data_from_simple(&mut self, msg: &[u8]) -> Result<(), SessionError> {
        // offset 0 = SPDU ID, offset 1 = LI, then params
        let li = msg[1] as usize;
        let total_expected = 2 + li;
        if total_expected > msg.len() {
            warn!(li, buf_len = msg.len(), "spdu li exceeds the buffer length");
            return Err(SessionError::LiMismatch {
                li,
                buf_len: msg.len(),
            });
        }
        // look for PGI 0xC1 inside the parameter block
        let params = &msg[2..2 + li];
        let mut offset = 0usize;
        while offset + 1 < params.len() {
            let pgi = params[offset];
            let plen = params[offset + 1] as usize;
            offset += 2;
            if offset + plen > params.len() {
                warn!(pgi, plen, "spdu parameter block runs past the end");
                return Err(SessionError::LiMismatch {
                    li,
                    buf_len: msg.len(),
                });
            }
            if pgi == PGI_USER_DATA {
                // the user-data offset inside msg: two header bytes plus the parameter offset
                let abs_start = 2 + (offset - 2) + 2; // skip the two header bytes
                let pgi_abs = 2 + (offset - 2); // position of the pgi byte inside msg
                let payload_abs = pgi_abs + 2; // skip the pgi and length bytes
                let _ = abs_start;
                self.user_data_start = payload_abs;
                self.user_data_len = plen;
                return Ok(());
            }
            offset += plen;
        }
        // a missing user-data PGI is legal; the range stays empty
        self.user_data_start = 0;
        self.user_data_len = 0;
        Ok(())
    }

    /// Parses a CN, CONNECT, SPDU.
    fn parse_connect_spdu(&mut self, msg: &[u8]) -> Result<SessionIndication, SessionError> {
        self.parse_header_parameters(msg)?;
        Ok(SessionIndication::Connect)
    }

    /// Parses an AC, ACCEPT, SPDU.
    fn parse_accept_spdu(&mut self, msg: &[u8]) -> Result<SessionIndication, SessionError> {
        self.parse_header_parameters(msg)?;
        Ok(SessionIndication::Accept)
    }

    /// Parses the PGI parameter block shared by CN and AC SPDUs.
    ///
    /// Updates `calling_selector`, `called_selector`, `session_requirement`,
    /// `protocol_options`, `user_data_start` and `user_data_len`.
    fn parse_header_parameters(&mut self, msg: &[u8]) -> Result<(), SessionError> {
        if msg.len() < 2 {
            return Err(SessionError::TooShort { len: msg.len() });
        }
        let li = msg[1] as usize;
        // LI excludes the SPDU ID and LI bytes, so 2 + li is the end of the parameters
        let params_end = 2 + li;
        if params_end > msg.len() {
            warn!(
                li,
                buf_len = msg.len(),
                "cn/ac spdu li exceeds the buffer length"
            );
            return Err(SessionError::LiMismatch {
                li,
                buf_len: msg.len(),
            });
        }

        let mut offset = 2usize; // skip the SPDU ID and the LI byte

        while offset < params_end {
            // every read first checks that enough bytes remain
            if offset + 1 >= params_end {
                // fewer than 2 bytes remain for a PGI and its length, so stop
                break;
            }
            let pgi = msg[offset];
            let pgi_len = msg[offset + 1] as usize;
            offset += 2;

            // bounds check
            if offset + pgi_len > params_end {
                warn!(
                    pgi,
                    pgi_len,
                    buf_remain = params_end - offset,
                    "pgi declares a length past the parameter block"
                );
                return Err(SessionError::LiMismatch {
                    li,
                    buf_len: msg.len(),
                });
            }

            let param_data = &msg[offset..offset + pgi_len];

            match pgi {
                PGI_CONNECT_ACCEPT_ITEM => {
                    // nested parameters: protocol options (PI 19) and version (PI 22)
                    self.parse_connect_accept_item(param_data)?;
                }
                PGI_SESSION_REQUIREMENT => {
                    // 2 bytes big-endian
                    if pgi_len < 2 {
                        warn!(pgi_len, "session requirement shorter than 2 bytes");
                    } else {
                        let req = u16::from_be_bytes([param_data[0], param_data[1]]);
                        self.session_requirement = req;
                        if req != SESSION_REQ_DUPLEX {
                            // a requirement other than duplex is logged but accepted
                            warn!(
                                req,
                                "session requirement is not duplex (0x0002), continuing"
                            );
                        }
                    }
                }
                PGI_CALLING_SS_SEL => {
                    // a selector longer than 16 bytes is rejected
                    if pgi_len > SSELECTOR_MAX_SIZE {
                        warn!(pgi_len, "calling ss-sel exceeds 16 bytes, rejecting");
                        return Err(SessionError::SelectorTooLong { len: pgi_len as u8 });
                    }
                    if pgi_len == 0 {
                        warn!("calling ss-sel is empty, accepting and logging");
                    }
                    self.calling_selector = SSelector::from_slice(param_data)?;
                }
                PGI_CALLED_SS_SEL => {
                    if pgi_len > SSELECTOR_MAX_SIZE {
                        warn!(pgi_len, "called ss-sel exceeds 16 bytes, rejecting");
                        return Err(SessionError::SelectorTooLong { len: pgi_len as u8 });
                    }
                    if pgi_len == 0 {
                        warn!("called ss-sel is empty, accepting and logging");
                    }
                    self.called_selector = SSelector::from_slice(param_data)?;
                }
                PGI_USER_DATA => {
                    // record the absolute offset of the user-data inside msg
                    self.user_data_start = offset;
                    self.user_data_len = pgi_len;
                }
                _ => {
                    // An unknown PGI is skipped by its declared length, applied by the
                    // common tail below; parsing never resumes at the next raw byte.
                }
            }

            offset += pgi_len;
        }

        Ok(())
    }

    /// Parses PI 19 and PI 22 inside PGI 5, the Connect/Accept Item.
    fn parse_connect_accept_item(&mut self, data: &[u8]) -> Result<(), SessionError> {
        let mut offset = 0usize;
        while offset + 1 < data.len() {
            let pi = data[offset];
            let pi_len = data[offset + 1] as usize;
            offset += 2;
            if offset + pi_len > data.len() {
                warn!(
                    pi,
                    pi_len, "pi declares a length past the connect/accept item"
                );
                return Err(SessionError::LiMismatch {
                    li: data.len(),
                    buf_len: data.len(),
                });
            }
            match pi {
                PI_PROTOCOL_OPTIONS => {
                    if pi_len >= 1 {
                        self.protocol_options = data[offset];
                    }
                }
                PI_VERSION_NUMBER if pi_len >= 1 => {
                    let version = data[offset];
                    if version != 2 {
                        // the version number must be 2
                        warn!(version, "session version is not 2, rejecting");
                        return Err(SessionError::InvalidVersion { version });
                    }
                }
                _ => {}
            }
            offset += pi_len;
        }
        Ok(())
    }
}

impl Default for IsoSession {
    fn default() -> Self {
        Self::new()
    }
}

// Stateless encoders

/// Encodes a CN, CONNECT, SPDU with ID 13 into `out`.
///
/// # Errors
///
/// Returns `SessionError::PayloadTooLarge` when the header plus payload exceeds the
/// 255-byte LI maximum.
pub fn encode_connect(
    params: &IsoParameters,
    session: &IsoSession,
    payload: &[u8],
    out: &mut BytesMut,
) -> Result<(), SessionError> {
    let header = build_connect_header(params, session, payload.len())?;
    out.extend_from_slice(&header);
    out.extend_from_slice(payload);
    Ok(())
}

/// Encodes an AC, ACCEPT, SPDU with ID 14 into `out`.
///
/// # Errors
///
/// Returns `SessionError::PayloadTooLarge` when the header plus payload exceeds 255 bytes.
pub fn encode_accept(
    session: &IsoSession,
    payload: &[u8],
    out: &mut BytesMut,
) -> Result<(), SessionError> {
    let header = build_accept_header(session, payload.len())?;
    out.extend_from_slice(&header);
    out.extend_from_slice(payload);
    Ok(())
}

/// Encodes a DT SPDU, the fixed header `01 00 01 00` followed by `payload`, into `out`.
pub fn encode_data(payload: &[u8], out: &mut BytesMut) {
    out.extend_from_slice(&DATA_SPDU_HEADER);
    out.extend_from_slice(payload);
}

/// Encodes an AB, ABORT, SPDU with ID 25 into `out`.
///
/// # Errors
///
/// Returns `SessionError::PayloadTooLarge` when the LI would exceed 255.
pub fn encode_abort(payload: &[u8], out: &mut BytesMut) -> Result<(), SessionError> {
    // LI = 5 (Transport Disconnect PI + User Data PGI header) + payload.len()
    // Transport Disconnect: PI=0x11(1) + len=1(1) + value(1) = 3 bytes
    // user-data PGI: 0xC1 plus its length byte, 2 bytes, so 5 in all
    let li = 5usize + payload.len();
    if li > LI_MAX {
        return Err(SessionError::PayloadTooLarge {
            size: payload.len(),
        });
    }
    out.extend_from_slice(&[
        SPDU_ID_ABORT,
        li as u8,
        0x11, // PI = Transport Disconnect
        0x01, // PI length = 1
        0x0B, // value: transport-connection-released | user-abort | no-reason
        PGI_USER_DATA,
        payload.len() as u8,
    ]);
    out.extend_from_slice(payload);
    Ok(())
}

/// Encodes an FN, FINISH, SPDU with ID 9 into `out`.
///
/// # Errors
///
/// Returns `SessionError::PayloadTooLarge` when the LI would exceed 255.
pub fn encode_finish(payload: &[u8], out: &mut BytesMut) -> Result<(), SessionError> {
    let li = 2usize + payload.len(); // PGI 0xC1(1) + len(1) + payload
    if li > LI_MAX {
        return Err(SessionError::PayloadTooLarge {
            size: payload.len(),
        });
    }
    out.extend_from_slice(&[SPDU_ID_FINISH, li as u8, PGI_USER_DATA, payload.len() as u8]);
    out.extend_from_slice(payload);
    Ok(())
}

/// Encodes a DN, DISCONNECT, SPDU with ID 10 into `out`.
///
/// # Errors
///
/// Returns `SessionError::PayloadTooLarge` when the LI would exceed 255.
pub fn encode_disconnect(payload: &[u8], out: &mut BytesMut) -> Result<(), SessionError> {
    let li = 2usize + payload.len();
    if li > LI_MAX {
        return Err(SessionError::PayloadTooLarge {
            size: payload.len(),
        });
    }
    out.extend_from_slice(&[
        SPDU_ID_DISCONNECT,
        li as u8,
        PGI_USER_DATA,
        payload.len() as u8,
    ]);
    out.extend_from_slice(payload);
    Ok(())
}

/// Encodes an RF, REFUSE, SPDU with ID 12 into `out`.
///
/// # Interoperability
///
/// 1. The LI byte at offset 1 is left at 0 instead of being filled in.
/// 2. The nested connection-identifier length is written as 2 although 6 bytes follow.
///
/// Writing the true lengths makes the REFUSE SPDU unparseable at the peer, so both
/// deviations are deliberate. Both places carry a NOTE comment.
pub fn encode_refuse(reason: u8, out: &mut BytesMut) {
    // SPDU ID = 0x0C (REFUSE)
    out.put_u8(SPDU_ID_REFUSE);

    // NOTE: deliberate non-standard encoding, kept for on-wire interoperability.
    // The LI byte is never filled in and stays 0.
    out.put_u8(0x00); // LI byte, deliberately left at 0

    // connection identifier, PGI 0x01
    out.put_u8(0x01); // PGI = Connection Identifier

    // NOTE: deliberate non-standard encoding, kept for on-wire interoperability.
    // The nested length is 2 although 6 bytes of content follow.
    out.put_u8(0x02); // nested length, deliberately 2 rather than 6

    // Transport Disconnect PI
    out.put_u8(0x11); // PI = Transport Disconnect (17)
    out.put_u8(0x01); // PI length = 1
    out.put_u8(0x01); // value: release transport connection

    // Reason code PI
    out.put_u8(0x32); // PI = Reason Code (50)
    out.put_u8(0x01); // PI length = 1
    out.put_u8(reason);
}

// Encoding helpers

/// Builds a CN SPDU header without its payload and checks the LI maximum.
fn build_connect_header(
    params: &IsoParameters,
    session: &IsoSession,
    payload_len: usize,
) -> Result<Vec<u8>, SessionError> {
    // header length:
    // PGI 5, the Connect/Accept Item: 2 header bytes plus PI 19 and PI 22
    //   PI 19 is 3 bytes and PI 22 is 3 bytes, so the PGI content is 6 bytes
    //   giving 8 bytes in all: the PGI byte, the length byte and 6 of content
    // PGI 20 (Session Req): 1+1+2 = 4 bytes
    // PGI 51 (Calling SS-SEL): 1+1+size
    // PGI 52 (Called SS-SEL): 1+1+size
    // PGI 0xC1, user data: 2 header bytes, with the payload counted separately
    // payload_len is the length of the payload itself
    //
    // LI counts every PGI byte plus the payload, excluding the SPDU ID and LI bytes

    let calling_size = params.local_selector.size as usize;
    let called_size = params.remote_selector.size as usize;

    // the PGI block, excluding the SPDU ID and LI bytes
    let pgi_area_len: usize = 8  // PGI 5 (ConnectAcceptItem: 1+1+6)
        + 4  // PGI 20 (SessionReq: 1+1+2)
        + 2 + calling_size  // PGI 51 (Calling SS-SEL: 1+1+size)
        + 2 + called_size   // PGI 52 (Called SS-SEL: 1+1+size)
        + 2                 // PGI 0xC1 header, 1 + 1, with the payload right after
        + payload_len;

    if pgi_area_len > LI_MAX {
        return Err(SessionError::PayloadTooLarge { size: payload_len });
    }

    let li = pgi_area_len as u8;
    let mut h = Vec::with_capacity(2 + pgi_area_len - payload_len);

    // SPDU ID + LI
    h.push(SPDU_ID_CONNECT);
    h.push(li);

    // PGI 5: Connect/Accept Item
    encode_connect_accept_item(&mut h, session.protocol_options);

    // PGI 20: Session User Requirements
    h.push(PGI_SESSION_REQUIREMENT);
    h.push(0x02);
    h.extend_from_slice(&session.session_requirement.to_be_bytes());

    // PGI 51: Calling SS-SEL
    h.push(PGI_CALLING_SS_SEL);
    h.push(calling_size as u8);
    h.extend_from_slice(params.local_selector.as_slice());

    // PGI 52: Called SS-SEL
    h.push(PGI_CALLED_SS_SEL);
    h.push(called_size as u8);
    h.extend_from_slice(params.remote_selector.as_slice());

    // PGI 0xC1: User Data header
    h.push(PGI_USER_DATA);
    h.push(payload_len as u8);

    Ok(h)
}

/// Builds an AC SPDU header, without its payload and without a Calling SS-SEL.
fn build_accept_header(session: &IsoSession, payload_len: usize) -> Result<Vec<u8>, SessionError> {
    let called_size = session.called_selector.size as usize;

    let pgi_area_len: usize = 8  // PGI 5
        + 4  // PGI 20
        + 2 + called_size  // PGI 52; an AC carries no Calling SS-SEL
        + 2                // PGI 0xC1 header
        + payload_len;

    if pgi_area_len > LI_MAX {
        return Err(SessionError::PayloadTooLarge { size: payload_len });
    }

    let li = pgi_area_len as u8;
    let mut h = Vec::with_capacity(2 + pgi_area_len - payload_len);

    h.push(SPDU_ID_ACCEPT);
    h.push(li);

    encode_connect_accept_item(&mut h, session.protocol_options);

    h.push(PGI_SESSION_REQUIREMENT);
    h.push(0x02);
    h.extend_from_slice(&session.session_requirement.to_be_bytes());

    h.push(PGI_CALLED_SS_SEL);
    h.push(called_size as u8);
    h.extend_from_slice(session.called_selector.as_slice());

    h.push(PGI_USER_DATA);
    h.push(payload_len as u8);

    Ok(h)
}

/// Writes PGI 5, the Connect/Accept Item, holding PI 19 and PI 22.
fn encode_connect_accept_item(out: &mut Vec<u8>, protocol_options: u8) {
    out.push(PGI_CONNECT_ACCEPT_ITEM);
    out.push(0x06); // PGI 5 length = 6
                    // PI 19: Protocol Options
    out.push(PI_PROTOCOL_OPTIONS);
    out.push(0x01);
    out.push(protocol_options);
    // PI 22: version number, always 2
    out.push(PI_VERSION_NUMBER);
    out.push(0x01);
    out.push(0x02); // version = 2
}

// A small put_u8 extension, kept inline so no extra trait is pulled in.
trait PutU8 {
    fn put_u8(&mut self, b: u8);
}

impl PutU8 for BytesMut {
    fn put_u8(&mut self, b: u8) {
        self.extend_from_slice(&[b]);
    }
}

// Unit tests

#[cfg(test)]
mod tests {
    use super::*;

    // helpers

    fn default_params() -> IsoParameters {
        IsoParameters::default()
    }

    fn default_session() -> IsoSession {
        IsoSession::new()
    }

    // CN SPDU round trip

    #[test]
    fn cn_spdu_roundtrip_empty_payload() {
        let params = default_params();
        let session = default_session();
        let payload = b"";
        let mut out = BytesMut::new();
        encode_connect(&params, &session, payload, &mut out).unwrap();

        // the SPDU ID must be 0x0D
        assert_eq!(out[0], SPDU_ID_CONNECT);
        // the LI byte cannot be 0, since PGI headers are always present
        assert!(out[1] > 0);

        // parse round-trip
        let mut sess2 = IsoSession::new();
        let bytes = out.freeze();
        let indication = sess2.parse_message(&bytes).unwrap();
        assert_eq!(indication, SessionIndication::Connect);
    }

    #[test]
    fn cn_spdu_roundtrip_with_payload() {
        let params = default_params();
        let session = default_session();
        let payload = b"hello-presentation";
        let mut out = BytesMut::new();
        encode_connect(&params, &session, payload, &mut out).unwrap();

        assert_eq!(out[0], SPDU_ID_CONNECT);

        let mut sess2 = IsoSession::new();
        let bytes = out.freeze();
        let indication = sess2.parse_message(&bytes).unwrap();
        assert_eq!(indication, SessionIndication::Connect);

        // user_data must point at the payload
        let ud = sess2.user_data(&bytes);
        assert_eq!(ud, payload);
    }

    #[test]
    fn cn_spdu_default_selectors_encoded() {
        let params = default_params();
        let session = default_session();
        let mut out = BytesMut::new();
        encode_connect(&params, &session, b"", &mut out).unwrap();

        // PGI 20, the session requirement 0x0002, must be present
        let bytes = out.freeze();
        let pgi20_pos = bytes
            .windows(2)
            .position(|w| w[0] == PGI_SESSION_REQUIREMENT);
        assert!(pgi20_pos.is_some());
        let p = pgi20_pos.unwrap();
        assert_eq!(bytes[p + 2], 0x00);
        assert_eq!(bytes[p + 3], 0x02);
    }

    // AC SPDU round trip

    #[test]
    fn ac_spdu_roundtrip_empty_payload() {
        let session = default_session();
        let mut out = BytesMut::new();
        encode_accept(&session, b"", &mut out).unwrap();

        assert_eq!(out[0], SPDU_ID_ACCEPT);

        let mut sess2 = IsoSession::new();
        let bytes = out.freeze();
        let indication = sess2.parse_message(&bytes).unwrap();
        assert_eq!(indication, SessionIndication::Accept);
    }

    #[test]
    fn ac_spdu_roundtrip_with_payload() {
        let session = default_session();
        let payload = b"accept-payload-data";
        let mut out = BytesMut::new();
        encode_accept(&session, payload, &mut out).unwrap();

        assert_eq!(out[0], SPDU_ID_ACCEPT);

        let mut sess2 = IsoSession::new();
        let bytes = out.freeze();
        let indication = sess2.parse_message(&bytes).unwrap();
        assert_eq!(indication, SessionIndication::Accept);

        let ud = sess2.user_data(&bytes);
        assert_eq!(ud, payload);
    }

    // a DT SPDU encodes the fixed header 01 00 01 00

    #[test]
    fn dt_spdu_encode_fixed_header() {
        let payload = b"some data";
        let mut out = BytesMut::new();
        encode_data(payload, &mut out);
        assert_eq!(&out[..4], &[0x01, 0x00, 0x01, 0x00]);
        assert_eq!(&out[4..], payload);
    }

    #[test]
    fn dt_spdu_encode_empty_payload() {
        let mut out = BytesMut::new();
        encode_data(b"", &mut out);
        assert_eq!(&out[..], &[0x01, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn dt_spdu_parse_happy() {
        let mut msg = vec![0x01, 0x00, 0x01, 0x00, 0xAA, 0xBB];
        let mut sess = IsoSession::new();
        let ind = sess.parse_message(&msg).unwrap();
        assert_eq!(ind, SessionIndication::Data);
        assert_eq!(sess.user_data(&msg), &[0xAA, 0xBB]);

        // editing msg does not affect user_data_start, which is an offset
        msg[4] = 0xFF;
        assert_eq!(sess.user_data(&msg), &[0xFF, 0xBB]);
    }

    // AB SPDU round trip

    #[test]
    fn ab_spdu_encode_and_parse() {
        let payload = b"abort-reason";
        let mut out = BytesMut::new();
        encode_abort(payload, &mut out).unwrap();

        assert_eq!(out[0], SPDU_ID_ABORT);

        // any message beginning with 0x19 is accepted
        let mut sess = IsoSession::new();
        let bytes = out.freeze();
        let ind = sess.parse_message(&bytes).unwrap();
        assert_eq!(ind, SessionIndication::Abort);
    }

    #[test]
    fn ab_spdu_encode_structure() {
        let mut out = BytesMut::new();
        encode_abort(b"", &mut out).unwrap();
        // Offset 0: SPDU ID = 0x19
        assert_eq!(out[0], 0x19);
        // Offset 1: LI = 5
        assert_eq!(out[1], 5);
        // Offset 2: PI = 0x11
        assert_eq!(out[2], 0x11);
        // Offset 3: PI len = 1
        assert_eq!(out[3], 0x01);
        // Offset 4: value = 0x0B
        assert_eq!(out[4], 0x0B);
        // Offset 5: PGI_USER_DATA = 0xC1
        assert_eq!(out[5], 0xC1);
        // Offset 6: payload len = 0
        assert_eq!(out[6], 0x00);
    }

    // FN and DN SPDU encoding

    #[test]
    fn fn_spdu_encode() {
        let payload = b"finish-payload";
        let mut out = BytesMut::new();
        encode_finish(payload, &mut out).unwrap();
        assert_eq!(out[0], SPDU_ID_FINISH);
        assert_eq!(out[1] as usize, 2 + payload.len());
        assert_eq!(out[2], PGI_USER_DATA);
        assert_eq!(out[3] as usize, payload.len());
        assert_eq!(&out[4..], payload);
    }

    #[test]
    fn dn_spdu_encode() {
        let payload = b"disconnect";
        let mut out = BytesMut::new();
        encode_disconnect(payload, &mut out).unwrap();
        assert_eq!(out[0], SPDU_ID_DISCONNECT);
        assert_eq!(out[1] as usize, 2 + payload.len());
        assert_eq!(out[2], PGI_USER_DATA);
        assert_eq!(&out[4..], payload);
    }

    #[test]
    fn fn_spdu_roundtrip() {
        let payload = b"finish";
        let mut out = BytesMut::new();
        encode_finish(payload, &mut out).unwrap();
        let bytes = out.freeze();

        let mut sess = IsoSession::new();
        let ind = sess.parse_message(&bytes).unwrap();
        assert_eq!(ind, SessionIndication::Finish);
        assert_eq!(sess.user_data(&bytes), payload);
    }

    #[test]
    fn dn_spdu_roundtrip() {
        let payload = b"disc";
        let mut out = BytesMut::new();
        encode_disconnect(payload, &mut out).unwrap();
        let bytes = out.freeze();

        let mut sess = IsoSession::new();
        let ind = sess.parse_message(&bytes).unwrap();
        assert_eq!(ind, SessionIndication::Disconnect);
        assert_eq!(sess.user_data(&bytes), payload);
    }

    // RF SPDU encoding, including the deliberate non-standard lengths

    #[test]
    fn rf_spdu_encode_c_bug_reproduced() {
        let mut out = BytesMut::new();
        encode_refuse(0x03, &mut out);
        // SPDU ID = 0x0C
        assert_eq!(out[0], SPDU_ID_REFUSE);
        // the LI byte stays 0
        // NOTE: deliberate non-standard encoding, kept for on-wire interoperability.
        assert_eq!(out[1], 0x00, "the rf li byte must stay 0");
        // PGI = Connection Identifier
        assert_eq!(out[2], 0x01);
        // the nested length stays 2
        // NOTE: deliberate non-standard encoding, kept for on-wire interoperability.
        assert_eq!(out[3], 0x02, "the rf nested length must stay 2");
        // the reason code sits at offset 9
        assert_eq!(out[9], 0x03);
    }

    // an unknown PGI is skipped by its declared length

    #[test]
    fn unknown_pgi_strict_skip() {
        // a hand-built CN SPDU with an unknown PGI, 0xFF with length 3, inserted
        // before the usual session requirement, selectors and user data
        let mut msg = Vec::new();
        msg.push(SPDU_ID_CONNECT); // SPDU ID
        let params_start = msg.len();

        let mut params: Vec<u8> = Vec::new();
        // PGI 5: the Connect/Accept Item
        params.extend_from_slice(&[0x05, 0x06, 0x13, 0x01, 0x00, 0x16, 0x01, 0x02]);
        // the unknown PGI 0xFF with length 3 and three filler bytes
        params.extend_from_slice(&[0xFF, 0x03, 0xAA, 0xBB, 0xCC]);
        // PGI 20: Session Requirement
        params.extend_from_slice(&[0x14, 0x02, 0x00, 0x02]);
        // PGI 51: Calling SS-SEL (2 bytes: 00 01)
        params.extend_from_slice(&[0x33, 0x02, 0x00, 0x01]);
        // PGI 52: Called SS-SEL (2 bytes: 00 01)
        params.extend_from_slice(&[0x34, 0x02, 0x00, 0x01]);
        // PGI 0xC1: User Data (3 bytes payload)
        params.extend_from_slice(&[0xC1, 0x03, 0xDE, 0xAD, 0xBE]);

        msg.push(params.len() as u8); // LI
        msg.extend_from_slice(&params);
        let _ = params_start;

        let mut sess = IsoSession::new();
        // parsing must succeed, with the unknown PGI skipped
        let ind = sess.parse_message(&msg).unwrap();
        assert_eq!(ind, SessionIndication::Connect);
        // user_data must be 0xDE 0xAD 0xBE
        assert_eq!(sess.user_data(&msg), &[0xDE, 0xAD, 0xBE]);
    }

    // out-of-bounds inputs

    #[test]
    fn too_short_message_returns_err() {
        let msg = &[0x0D]; // only one byte
        let mut sess = IsoSession::new();
        let err = sess.parse_message(msg).unwrap_err();
        assert_eq!(err, SessionError::TooShort { len: 1 });
    }

    #[test]
    fn empty_message_returns_err() {
        let msg = &[];
        let mut sess = IsoSession::new();
        let err = sess.parse_message(msg).unwrap_err();
        assert_eq!(err, SessionError::TooShort { len: 0 });
    }

    #[test]
    fn cn_spdu_li_overflow_returns_err() {
        // the li claims 100 bytes while the buffer holds 10
        let msg = [
            SPDU_ID_CONNECT,
            100u8,
            0x05,
            0x06,
            0x13,
            0x01,
            0x00,
            0x16,
            0x01,
            0x02,
        ];
        let mut sess = IsoSession::new();
        let err = sess.parse_message(&msg).unwrap_err();
        assert_eq!(
            err,
            SessionError::LiMismatch {
                li: 100,
                buf_len: msg.len()
            }
        );
    }

    #[test]
    fn dt_without_4_bytes_returns_err() {
        let msg = [0x01, 0x00, 0x01]; // only three bytes
        let mut sess = IsoSession::new();
        let err = sess.parse_message(&msg).unwrap_err();
        assert_eq!(err, SessionError::TooShort { len: 3 });
    }

    #[test]
    fn oob_read_protection_param_len_exceeds_buffer() {
        // a CN SPDU whose PGI 5 declares length 50 while the buffer holds 20 bytes
        let mut msg = vec![SPDU_ID_CONNECT, 0x12]; // LI = 18
                                                   // PGI 5 declares length 50, past what remains
        msg.extend_from_slice(&[0x05, 50]);
        // only 14 filler bytes follow, fewer than the 50 declared
        msg.resize(2 + 18, 0xAA);
        let mut sess = IsoSession::new();
        // an error must be returned rather than a panic
        let result = sess.parse_message(&msg);
        assert!(
            result.is_err(),
            "a pgi length past the buffer must return an error"
        );
    }

    #[test]
    fn selector_size_gt_16_returns_err() {
        // a CN SPDU whose PGI 51, the Calling SS-SEL, declares length 17
        let mut params: Vec<u8> = Vec::new();
        params.extend_from_slice(&[0x05, 0x06, 0x13, 0x01, 0x00, 0x16, 0x01, 0x02]);
        params.extend_from_slice(&[0x14, 0x02, 0x00, 0x02]);
        // PGI 51 len = 17
        params.push(0x33);
        params.push(17);
        params.extend(core::iter::repeat_n(0xAAu8, 17));
        params.extend_from_slice(&[0x34, 0x02, 0x00, 0x01]);
        params.extend_from_slice(&[0xC1, 0x00]);

        let mut msg = vec![SPDU_ID_CONNECT, params.len() as u8];
        msg.extend_from_slice(&params);

        let mut sess = IsoSession::new();
        let err = sess.parse_message(&msg).unwrap_err();
        assert_eq!(err, SessionError::SelectorTooLong { len: 17 });
    }

    // limits

    #[test]
    fn payload_too_large_returns_err() {
        // a 253-byte payload plus the session header exceeds 255
        let big_payload = vec![0u8; 253];
        let params = default_params();
        let session = default_session();
        let mut out = BytesMut::new();
        let result = encode_connect(&params, &session, &big_payload, &mut out);
        assert!(
            result.is_err(),
            "exceeding the li maximum must return PayloadTooLarge"
        );
        assert!(matches!(
            result.unwrap_err(),
            SessionError::PayloadTooLarge { .. }
        ));
    }

    #[test]
    fn session_not_finished_returns_err() {
        // SPDU ID 0x08, NOT-FINISHED
        let msg = [SPDU_ID_NOT_FINISHED, 0x00];
        let mut sess = IsoSession::new();
        let err = sess.parse_message(&msg).unwrap_err();
        assert_eq!(err, SessionError::UnsupportedSpdu { id: 0x08 });
    }

    // version number validation

    #[test]
    fn invalid_version_returns_err() {
        // a CN SPDU whose PI 22 version is 3 rather than 2
        let mut params: Vec<u8> = Vec::new();
        // PGI 5: PI 19 = 0 and PI 22 = 3, the wrong version
        params.extend_from_slice(&[0x05, 0x06, 0x13, 0x01, 0x00, 0x16, 0x01, 0x03]);
        params.extend_from_slice(&[0x14, 0x02, 0x00, 0x02]);
        params.extend_from_slice(&[0x33, 0x02, 0x00, 0x01]);
        params.extend_from_slice(&[0x34, 0x02, 0x00, 0x01]);
        params.extend_from_slice(&[0xC1, 0x00]);

        let mut msg = vec![SPDU_ID_CONNECT, params.len() as u8];
        msg.extend_from_slice(&params);

        let mut sess = IsoSession::new();
        let err = sess.parse_message(&msg).unwrap_err();
        assert_eq!(err, SessionError::InvalidVersion { version: 3 });
    }

    // the Data SPDU constant

    #[test]
    fn data_spdu_header_constant() {
        assert_eq!(DATA_SPDU_HEADER, [0x01, 0x00, 0x01, 0x00]);
    }

    // an abort is accepted without validating its content

    #[test]
    fn abort_any_content_accepted() {
        // any message beginning with 0x19 is accepted
        let msg = [0x19, 0xFF]; // the second byte is not validated as an li
        let mut sess = IsoSession::new();
        let ind = sess.parse_message(&msg).unwrap();
        assert_eq!(ind, SessionIndication::Abort);
    }
}
