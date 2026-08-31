//! Error types of the ISO transport stack.
//!
//! The layers stack as `CotpError`, then `IsoError`, then `MmsError`.

use crate::compat::prelude::*;
use thiserror::Error;

/// Errors of the COTP layer, ISO 8073 class 0 over RFC 1006.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CotpError {
    /// The TPKT version is not 0x03, or the reserved byte is not 0x00.
    #[error("invalid tpkt header (version={version}, reserved={reserved})")]
    InvalidTpktVersion {
        /// Version byte received; RFC 1006 requires 0x03.
        version: u8,
        /// Reserved byte received; RFC 1006 requires 0x00.
        reserved: u8,
    },

    /// The TPKT packet length is too small; it must exceed the 4-byte header.
    #[error("tpkt declares a packet length of {packet_len}, which leaves no cotp payload")]
    TpktLengthTooSmall {
        /// Packet length the TPKT header declared.
        packet_len: u16,
    },

    /// The TPKT packet length exceeds the local buffer limit.
    #[error("tpkt packet length {packet_len} exceeds the buffer limit {max_size}")]
    TpktLengthOverflow {
        /// Packet length the TPKT header declared.
        packet_len: u16,
        /// Largest packet the local buffer accepts.
        max_size: usize,
    },

    /// The COTP length indicator claims more bytes than the TPDU holds.
    #[error("cotp li {li} exceeds the tpdu length {tpdu_len}")]
    LiOverflow {
        /// Length indicator the TPDU declared.
        li: u8,
        /// Number of TPDU bytes actually present.
        tpdu_len: usize,
    },

    /// The protocol class is not class 0.
    #[error("unsupported cotp protocol class {class}, only class 0 is supported")]
    UnsupportedProtocolClass {
        /// Protocol class byte received.
        class: u8,
    },

    /// An option declares more bytes than the variable part holds.
    #[error("cotp option length {option_len} exceeds the {remaining} bytes remaining")]
    OptionLenOverflow {
        /// Length the option declared.
        option_len: usize,
        /// Bytes remaining in the variable part.
        remaining: usize,
    },

    /// A T-Selector is longer than the 4-byte maximum.
    #[error("t-selector length {len} exceeds the maximum of 4")]
    TSelectorTooLong {
        /// Selector length received.
        len: usize,
    },

    /// The TPDU size option, 0xC0, does not carry exactly one byte.
    #[error("tpdu size option must be 1 byte, got {len}")]
    InvalidTpduSizeOption {
        /// Option length received; it must be 1.
        len: usize,
    },

    /// A DT TPDU carries a length indicator other than 2.
    #[error("dt tpdu li must be 2, got {li}")]
    InvalidDtLi {
        /// Length indicator received; a DT TPDU must carry 2.
        li: u8,
    },

    /// A DT TPDU carries no payload.
    #[error("dt tpdu payload is empty")]
    EmptyDtPayload,

    /// The TPDU type code is not recognized.
    #[error("unknown tpdu type 0x{tpdu_type:02X}")]
    UnknownTpduType {
        /// TPDU type code received.
        tpdu_type: u8,
    },

    /// A Disconnect Request was received.
    #[error("received a cotp disconnect request, code={code}")]
    DisconnectRequest {
        /// Disconnect reason code carried by the DR TPDU.
        code: u8,
    },

    /// An Error TPDU was received.
    #[error("received a cotp error tpdu")]
    ErrorTpdu,

    /// The operation is not allowed in the current connection state.
    #[error("cotp state {state:?} does not allow the operation {op}")]
    InvalidState {
        /// Connection state at the time of the call.
        state: String,
        /// Operation that was attempted.
        op: &'static str,
    },

    /// An error reported by the transport.
    #[error("i/o error: {0}")]
    Io(String),

    /// The peer closed the connection before a complete PDU arrived.
    #[error("cotp input ended unexpectedly")]
    UnexpectedEof,

    /// A reassembled TSDU exceeded the caller-supplied limit; see
    /// [`crate::iso::cotp::CotpConnection::set_max_tsdu_size`].
    ///
    /// This variant appears only when a limit has been set; the default is unbounded.
    #[error("reassembled tsdu reached {accumulated} bytes, above the limit of {limit}")]
    TsduTooLarge {
        /// Bytes accumulated in the reassembly buffer.
        accumulated: usize,
        /// Configured upper bound.
        limit: usize,
    },
}

#[cfg(feature = "std")]
impl From<std::io::Error> for CotpError {
    fn from(e: std::io::Error) -> Self {
        CotpError::Io(e.to_string())
    }
}

impl From<iec61850_hal::transport::TransportError> for CotpError {
    fn from(e: iec61850_hal::transport::TransportError) -> Self {
        use iec61850_hal::transport::TransportError;
        match e {
            TransportError::Closed => CotpError::UnexpectedEof,
            // The transport error type has four variants and carries no OS error code,
            // so the textual form is all that survives the conversion.
            other => CotpError::Io(other.to_string()),
        }
    }
}

/// Errors of the ISO stack: COTP, Session, Presentation and ACSE.
#[derive(Debug, Error)]
pub enum IsoError {
    #[error("cotp error: {0}")]
    /// A COTP layer error.
    Cotp(#[from] CotpError),

    #[error("session error: {0}")]
    /// A Session layer error.
    Session(#[from] crate::iso::session::SessionError),

    #[error("presentation error: {0}")]
    /// A Presentation layer error.
    Presentation(#[from] crate::iso::presentation::PresentationError),

    #[error("acse error: {0}")]
    /// An ACSE layer error.
    Acse(#[from] crate::iso::acse::AcseError),

    /// A direct `std::io::Error`, on std builds only. A no_std build reports transport
    /// failures through `Cotp(CotpError::Io(..))` instead.
    #[cfg(feature = "std")]
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}
