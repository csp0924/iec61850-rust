//! Error type of the MMS client layer.
//!
//! Extends `MmsError` with the conditions connection management adds:
//! - `PduTooLarge`: an encoded PDU exceeds the negotiated maximum size
//! - `InvokeIdExhausted`: every invokeID is already in flight
//! - `OutstandingCallLimit`: requests that timed out hold every slot of the
//!   negotiated outstanding limit
//! - `NotConnected`: a service was called while no association exists
//! - `ConcludeRejected`: the peer refused the release with a Conclude-ErrorPDU
//!   (`0xad`)
//! - `ServiceTimeout`: no answer arrived within the request timeout
//! - `ConnectionLost`: the peer closed the transport or aborted the association
//! - `ReleasedByPeer`: the peer released the association
//! - `Transport`: the transport failed, with the cause it reported
//! - `IsoError`: a lower ISO layer failed to parse
//! - `ServiceError`: the peer answered with a confirmed error PDU
//! - `DataAccessError`: a read or write reported a data access error
//! - `RejectError`: the peer answered with a reject PDU
//! - `SessionRefused`: the peer answered the connect request with a session
//!   REFUSE SPDU

use crate::compat::prelude::*;
use crate::iso::presentation::provider_reason_name;
use crate::iso::session::refuse_reason_name;
use crate::mms::pdu::{DataAccessError, ErrorClass, RejectReason, ServiceSpecificInfo};
use iec61850_hal::transport::TransportError;
use thiserror::Error;

/// Renders a session refusal, naming the values ISO 8327-1 and ISO 8823 define
/// and printing an unrecognized one as a bare number.
///
/// Used by the `Display` of [`ClientError::SessionRefused`] and by the client
/// crate above it, so both render a refusal the same way.
pub fn session_refused_message(
    reason_code: Option<u8>,
    transport_disconnect: Option<u8>,
    provider_reason: Option<u8>,
) -> String {
    let mut text = String::from("session refused");
    match reason_code {
        Some(code) => match refuse_reason_name(code) {
            Some(name) => text.push_str(&format!(": {name} ({code})")),
            None => text.push_str(&format!(": reason {code}")),
        },
        None => text.push_str(": no reason code"),
    }
    if let Some(reason) = provider_reason {
        match provider_reason_name(reason) {
            Some(name) => text.push_str(&format!(
                "; presentation provider reason: {name} ({reason})"
            )),
            None => text.push_str(&format!("; presentation provider reason: {reason}")),
        }
    }
    if let Some(disconnect) = transport_disconnect {
        text.push_str(&format!("; transport disconnect: {disconnect}"));
    }
    text
}

/// Errors raised by MMS client operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    /// The encoded PDU exceeds the negotiated maximum size, so it is not sent.
    ///
    /// An oversized PDU is refused rather than truncated.
    #[error("pdu size {pdu_size} exceeds the negotiated maximum {max_size}, refusing to send")]
    #[non_exhaustive]
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

    /// Requests that timed out unanswered hold every slot of the negotiated
    /// outstanding limit, and no late answer freed one within the request
    /// timeout, so the request was not sent. The association stays
    /// established, and a late answer frees its slot; a peer that discarded
    /// those requests never answers them, so their slots stay held until the
    /// association is aborted or released and established again.
    #[error("the outstanding request limit has been reached")]
    OutstandingCallLimit,

    /// A service was called while the association was not established.
    #[error("client is not connected (state: {state:?})")]
    #[non_exhaustive]
    NotConnected {
        /// Connection state at the time of the call.
        state: String,
    },

    /// The peer answered the Conclude request with a Conclude-ErrorPDU (`0xad`),
    /// so the association stays open.
    #[error("the peer refused the conclude request")]
    ConcludeRejected,

    /// No answer arrived within the request timeout.
    #[error("request timed out after {timeout_ms} ms")]
    #[non_exhaustive]
    ServiceTimeout {
        /// Request timeout that elapsed, in milliseconds.
        timeout_ms: u64,
    },

    /// The peer closed the transport, sent a COTP DR, or aborted the
    /// association; the connection is closed.
    #[error("the transport connection was lost")]
    ConnectionLost,

    /// The peer released the association: it sent a Session FN carrying an
    /// ACSE release request, which was answered with a Session DN carrying the
    /// release response, or a Conclude request, which was answered with a
    /// Conclude response. The connection is closed either way.
    #[error("the peer released the association")]
    ReleasedByPeer,

    /// The transport failed with an I/O error; the connection is closed.
    ///
    /// Carries the category of the failure and, when the transport reported
    /// one, the text of the underlying error, such as a fatal TLS alert or the
    /// operating system message of a refused TCP connection.
    #[error("transport error: {0}")]
    Transport(TransportError),

    /// A protocol error in the COTP, Session, Presentation or ACSE layer.
    #[error("iso protocol error: {0}")]
    IsoError(String),

    /// The peer answered with a ConfirmedError PDU carrying an MMS ServiceError.
    #[error("mms service error: class={error_class:?}")]
    #[non_exhaustive]
    ServiceError {
        /// errorClass carried by the confirmed error PDU.
        error_class: ErrorClass,
        /// serviceSpecificInformation of the ServiceError, such as the
        /// numberDeleted of a failed DeleteNamedVariableList; `None` when the
        /// peer sent none or an alternative this crate does not model.
        service_specific: Option<ServiceSpecificInfo>,
    },

    /// The peer answered with a Reject PDU.
    #[error("mms reject: {reason:?}")]
    #[non_exhaustive]
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

    /// The peer answered the connect request with a session REFUSE SPDU.
    ///
    /// `reason_code` is PI 50 of the RF SPDU and `transport_disconnect` PI 17.
    /// `provider_reason` is filled in when the refusal carries a CPR PPDU whose
    /// provider-reason decodes.
    #[error("{}", session_refused_message(*reason_code, *transport_disconnect, *provider_reason))]
    #[non_exhaustive]
    SessionRefused {
        /// Reason code carried by the RF SPDU.
        reason_code: Option<u8>,
        /// Transport disconnect parameter carried by the RF SPDU.
        transport_disconnect: Option<u8>,
        /// provider-reason of the CPR PPDU inside the refusal, when present.
        provider_reason: Option<u8>,
    },

    /// MMS Initiate negotiation failed and the peer answered with an Initiate error.
    #[error("mms initiate failed: errorCode={error_code}")]
    #[non_exhaustive]
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
    #[non_exhaustive]
    ConnectTimeout {
        /// Connect timeout that elapsed, in milliseconds.
        timeout_ms: u64,
    },
}

/// Constructors for code that reports these errors itself, such as a test
/// double of a peer. Each takes the fields the error always carries; an
/// optional field starts empty and is set with the matching `with_` method,
/// so a field added later leaves every signature as it is.
impl ClientError {
    /// Builds a [`ClientError::ServiceError`] carrying `error_class` and no
    /// serviceSpecificInformation.
    pub fn service_error(error_class: ErrorClass) -> Self {
        Self::ServiceError {
            error_class,
            service_specific: None,
        }
    }

    /// Sets the serviceSpecificInformation of a [`ClientError::ServiceError`];
    /// any other error is returned unchanged.
    pub fn with_service_specific(mut self, info: ServiceSpecificInfo) -> Self {
        if let Self::ServiceError {
            service_specific, ..
        } = &mut self
        {
            *service_specific = Some(info);
        }
        self
    }

    /// Builds a [`ClientError::RejectError`].
    pub fn reject(reason: RejectReason) -> Self {
        Self::RejectError { reason }
    }

    /// Builds a [`ClientError::ServiceTimeout`] for a request timeout of
    /// `timeout_ms` milliseconds.
    pub fn service_timeout(timeout_ms: u64) -> Self {
        Self::ServiceTimeout { timeout_ms }
    }

    /// Builds a [`ClientError::ConnectTimeout`] for a connect timeout of
    /// `timeout_ms` milliseconds.
    pub fn connect_timeout(timeout_ms: u64) -> Self {
        Self::ConnectTimeout { timeout_ms }
    }

    /// Builds a [`ClientError::NotConnected`] for a call made in `state`.
    pub fn not_connected(state: impl Into<String>) -> Self {
        Self::NotConnected {
            state: state.into(),
        }
    }

    /// Builds a [`ClientError::PduTooLarge`] for a PDU of `pdu_size` octets
    /// against a negotiated maximum of `max_size`.
    pub fn pdu_too_large(pdu_size: usize, max_size: usize) -> Self {
        Self::PduTooLarge { pdu_size, max_size }
    }

    /// Builds a [`ClientError::InitiateFailed`] carrying the errorCode of the
    /// Initiate error PDU.
    pub fn initiate_failed(error_code: u8) -> Self {
        Self::InitiateFailed { error_code }
    }

    /// Builds a [`ClientError::SessionRefused`] whose RF SPDU carries no
    /// parameter.
    pub fn session_refused() -> Self {
        Self::SessionRefused {
            reason_code: None,
            transport_disconnect: None,
            provider_reason: None,
        }
    }

    /// Sets the reason code (PI 50) of a [`ClientError::SessionRefused`]; any
    /// other error is returned unchanged.
    pub fn with_refuse_reason(mut self, code: u8) -> Self {
        if let Self::SessionRefused { reason_code, .. } = &mut self {
            *reason_code = Some(code);
        }
        self
    }

    /// Sets the transport disconnect parameter (PI 17) of a
    /// [`ClientError::SessionRefused`]; any other error is returned unchanged.
    pub fn with_transport_disconnect(mut self, value: u8) -> Self {
        if let Self::SessionRefused {
            transport_disconnect,
            ..
        } = &mut self
        {
            *transport_disconnect = Some(value);
        }
        self
    }

    /// Sets the provider-reason of the CPR PPDU inside a
    /// [`ClientError::SessionRefused`]; any other error is returned unchanged.
    pub fn with_provider_reason(mut self, reason: u8) -> Self {
        if let Self::SessionRefused {
            provider_reason, ..
        } = &mut self
        {
            *provider_reason = Some(reason);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_service_error_takes_its_service_specific_information_afterwards() {
        let e = ClientError::service_error(ErrorClass::Service(6))
            .with_service_specific(ServiceSpecificInfo::DeleteNamedVariableList(3));
        assert!(matches!(
            e,
            ClientError::ServiceError {
                error_class: ErrorClass::Service(6),
                service_specific: Some(ServiceSpecificInfo::DeleteNamedVariableList(3)),
            }
        ));
    }

    #[test]
    fn a_session_refusal_takes_each_parameter_afterwards() {
        let e = ClientError::session_refused()
            .with_refuse_reason(129)
            .with_transport_disconnect(1)
            .with_provider_reason(3);
        assert!(matches!(
            e,
            ClientError::SessionRefused {
                reason_code: Some(129),
                transport_disconnect: Some(1),
                provider_reason: Some(3),
            }
        ));
    }

    #[test]
    fn a_setter_leaves_another_error_unchanged() {
        let e = ClientError::service_timeout(5)
            .with_service_specific(ServiceSpecificInfo::DeleteNamedVariableList(1))
            .with_refuse_reason(2);
        assert!(matches!(e, ClientError::ServiceTimeout { timeout_ms: 5 }));
    }
}
