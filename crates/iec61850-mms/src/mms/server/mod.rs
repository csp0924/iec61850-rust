//! Server-side MMS support.
//!
//! This module handles server-side MMS PDUs only; the IEC 61850 model and its
//! mapping live in the server crate.
//!
//! ## Scope
//!
//! - `initiate`: parses an Initiate request and encodes the response or error
//! - `connection`: `MmsServerConnection`, holding the negotiated state
//! - `dispatcher`: the `MmsServiceDispatcher` trait and the `RejectAllDispatcher`
//!   default implementation, which rejects every confirmed request
//!
//! The accept loop, the listener and the model mapping are not here: the server
//! crate owns those and calls into this module.

pub mod connection;
pub mod dispatch;
pub mod dispatcher;
pub mod initiate;

pub use connection::{
    MmsServerConnection, NegotiatedParams, DEFAULT_CONCLUDE_TIMEOUT_MS, MIN_PDU_SIZE,
};
pub use dispatch::{encode_reject_pdu, parse_message, MessageOutcome};
pub use dispatcher::{
    ConfirmedRequest, ConfirmedResponse, MmsServiceDispatcher, RejectAllDispatcher,
};
pub use initiate::{negotiate_initiate, InitiateOutcome, InitiateRejectReason};
