//! Error type of the MMS client layer.
//!
//! Extends `MmsError` with the conditions connection management adds:
//! - `PduTooLarge`: an encoded PDU exceeds the negotiated maximum size
//! - `InvokeIdExhausted`: every invokeID is already in flight
//! - `OutstandingCallLimit`: the outstanding request ceiling has been reached
//! - `NotConnected`: a service was called while no association exists
//! - `ConcludeRejected`: the peer refused the release with `0x8d`
//! - `ServiceTimeout`: no answer arrived within the request timeout
//! - `ConnectionLost`: the transport closed
//! - `IsoError`: a lower ISO layer failed to parse
//! - `ServiceError`: the peer answered with a confirmed error PDU
//! - `DataAccessError`: a read or write reported a data access error
//! - `RejectError`: the peer answered with a reject PDU

use crate::compat::prelude::*;
use crate::mms::pdu::{DataAccessError, ErrorClass, RejectReason};
use thiserror::Error;

/// Errors raised by MMS client operations.
#[derive(Debug, Error)]
pub enum ClientError {
    /// The encoded PDU exceeds the negotiated maximum size, so it is not sent.
    ///
    /// An oversized PDU is refused rather than truncated.
    #[error("pdu size {pdu_size} exceeds the negotiated maximum {max_size}, refusing to send")]
    PduTooLarge {
        /// Size of the encoded PDU.
        pdu_size: usize,
        /// Negotiated maximum PDU size.
        max_size: usize,
    },

    /// Every invokeID is already in flight, so no new request can be issued.
    ///
    /// A collision is reported rather than routed onto an existing callback.
    #[error("invokeid collision: every pending invokeid is in use")]
    InvokeIdExhausted,

    /// The negotiated ceiling on outstanding requests has been reached.
    #[error("the outstanding request limit has been reached")]
    OutstandingCallLimit,

    /// A service was called while the association was not established.
    #[error("client is not connected (state: {state:?})")]
    NotConnected {
        /// Connection state at the time of the call.
        state: String,
    },

    /// The peer answered the release with `0x8d`, so the association stays open.
    #[error("the peer refused the conclude request")]
    ConcludeRejected,

    /// No answer arrived within the request timeout.
    #[error("request timed out after {timeout_ms} ms")]
    ServiceTimeout {
        /// Request timeout that elapsed, in milliseconds.
        timeout_ms: u64,
    },

    /// The transport closed.
    #[error("the transport connection was lost")]
    ConnectionLost,

    /// A protocol error in the COTP, Session, Presentation or ACSE layer.
    #[error("iso protocol error: {0}")]
    IsoError(String),

    /// The peer answered with a ConfirmedError PDU carrying an MMS ServiceError.
    #[error("mms service error: class={error_class:?}")]
    ServiceError {
        /// errorClass carried by the confirmed error PDU.
        error_class: ErrorClass,
    },

    /// The peer answered with a Reject PDU.
    #[error("mms reject: {reason:?}")]
    RejectError {
        /// rejectReason carried by the reject PDU.
        reason: RejectReason,
    },

    /// A read or write reported a data access error.
    #[error("data access error: {0:?}")]
    DataAccessError(DataAccessError),

    /// The ACSE association was refused.
    #[error("the acse association was refused")]
    AssociateFailed,

    /// MMS Initiate negotiation failed and the peer answered with an Initiate error.
    #[error("mms initiate failed: errorCode={error_code}")]
    InitiateFailed {
        /// Subcode carried by the Initiate error PDU.
        error_code: u8,
    },

    /// An I/O error from the transport, on std builds only.
    #[cfg(feature = "std")]
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// An MMS PDU failed to parse.
    #[error("mms pdu parse error: {0}")]
    PduParse(String),

    /// The association was not established within the connect timeout.
    #[error("connect timed out after {timeout_ms} ms")]
    ConnectTimeout {
        /// Connect timeout that elapsed, in milliseconds.
        timeout_ms: u64,
    },
}
