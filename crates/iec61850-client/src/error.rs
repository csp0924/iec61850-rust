//! Error type returned by the `iec61850-client` service APIs.
//!
//! Every fallible operation returns `Result<T, ClientError>`; failures are
//! never signaled through an out-parameter or a sentinel return value.

#[cfg(not(feature = "std"))]
use alloc::string::{String, ToString};

use iec61850_hal::transport::TransportError;
use iec61850_mms::mms::pdu::{ErrorClass, RejectReason, ServiceSpecificInfo};
use iec61850_mms::TlsFailureKind;
use thiserror::Error;

#[cfg(feature = "reporting")]
use crate::report::ReportParseError;

/// Error returned by the client service APIs.
///
/// Errors from `iec61850-mms` arrive through the `From` impl below, each on a
/// typed variant that carries the cause: a timeout, the end of the
/// association, a transport failure with its [`TransportError`], a confirmed
/// error with its [`ErrorClass`], a reject with its [`RejectReason`], a data
/// access error, the refusals of the association, and a failed TLS handshake
/// with its [`TlsFailureKind`]. Only a failure with no variant of its own,
/// such as a PDU that does not decode, is carried as text in `Mms`.
///
/// The variants mapped from the MMS layer render as `mms layer error: `
/// followed by the text of the MMS error, as in earlier releases; a caller
/// should match on the variant rather than on that text.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientError {
    /// The `rpt_id` argument is longer than the 128-byte MMS object-name limit.
    #[error("invalid rptId: length {len} exceeds upper bound 128")]
    #[non_exhaustive]
    InvalidRptId {
        /// Length of the offending `rpt_id`, in bytes.
        len: usize,
    },

    /// A handler is already registered for this RCB reference.
    ///
    /// No path currently produces this variant: `install_report_handler`
    /// replaces an existing handler rather than refusing. It is reserved for an
    /// install that declines to replace one.
    #[error("rcb_ref {0} already registered")]
    AlreadyRegistered(String),

    /// No handler is registered for this RCB reference.
    #[error("no handler registered for rcb_ref {0}")]
    NotFound(String),

    /// A received report could not be parsed.
    #[cfg(feature = "reporting")]
    #[error("report parse failed: {0}")]
    ParseFailed(#[from] ReportParseError),

    /// An argument is malformed: bad syntax, over-long, or outside the
    /// permitted character set.
    ///
    /// An unparsable object reference produces this error rather than an empty
    /// result, so the caller learns why the call failed.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// An MMS value has a type the operation cannot accept, as raised by
    /// `update_values` or by setting an entry id.
    ///
    /// The mismatch is reported rather than skipped, and names the offending
    /// position along with the expected and received type.
    #[error("type mismatch at index {index}: expected {expected}, got {got}")]
    #[non_exhaustive]
    TypeMismatch {
        /// Position of the offending element within the data set or sequence.
        index: usize,
        /// Name of the type the operation requires.
        expected: &'static str,
        /// Name of the type that was received.
        got: &'static str,
    },

    /// A `read_<type>_value` or `write_<type>_value` convenience wrapper
    /// received a value of a type it does not cover. This is the client-side
    /// equivalent of an unexpected value received from the server.
    ///
    /// Distinct from `TypeMismatch`, which carries the position of the
    /// offending element inside a data set or sequence; this variant concerns
    /// a single variable.
    #[error("unexpected value type: expected {expected}, got {got}")]
    #[non_exhaustive]
    UnexpectedValueType {
        /// Name of the type the wrapper reads.
        expected: &'static str,
        /// Name of the type that was received.
        got: &'static str,
    },

    /// A BINARY TIME field is neither the four nor the six octets ISO 9506 defines.
    ///
    /// The length is reported rather than absorbed: a truncated or over-long
    /// field would otherwise decode to a plausible but wrong instant.
    #[error("invalid BinaryTime length {got} bytes (expected 4 or 6)")]
    #[non_exhaustive]
    InvalidBinaryTimeLen {
        /// Length of the offending field, in bytes.
        got: usize,
    },

    /// A service was called on an `IedConnection` that is not connected.
    #[error("connection is not established")]
    NotConnected,

    /// A GetNameList walk of the directory services reported more names than
    /// the connection's limit; see `IedConnection::with_max_name_list_names`.
    #[error("getnamelist returned more than {limit} names")]
    #[non_exhaustive]
    NameListLimit {
        /// The limit that was exceeded.
        limit: usize,
    },

    /// An error from the MMS or ISO layer below that no other variant
    /// describes, rendered through its `Display`: a PDU or SPDU that does not
    /// decode, an exhausted invokeID space, or another protocol failure.
    #[error("mms layer error: {0}")]
    Mms(String),

    /// No answer arrived within the request timeout.
    ///
    /// The association stays usable: the late answer, if it comes, is
    /// recognized by its invokeID and discarded.
    #[error("mms layer error: request timed out after {after_ms} ms")]
    #[non_exhaustive]
    Timeout {
        /// Request timeout that elapsed, in milliseconds.
        after_ms: u64,
    },

    /// An enhanced-security Operate was accepted, but no CommandTermination
    /// for it arrived within the wait.
    ///
    /// The fate of the command is unknown: it may still be executing, and a
    /// termination that arrives later is not reported as its outcome.
    #[error("no command termination arrived within {after_ms} ms")]
    #[non_exhaustive]
    CommandTerminationTimeout {
        /// Wait that elapsed, in milliseconds.
        after_ms: u64,
    },

    /// The association was not established within the connect timeout.
    #[error("mms layer error: connect timed out after {after_ms} ms")]
    #[non_exhaustive]
    ConnectTimeout {
        /// Connect timeout that elapsed, in milliseconds.
        after_ms: u64,
    },

    /// The peer closed the transport, sent a COTP DR, or aborted the
    /// association. The connection is closed and `is_connected` reports
    /// false.
    #[error("mms layer error: the transport connection was lost")]
    ConnectionLost,

    /// The peer released the association, and the release was answered. The
    /// connection is closed and `is_connected` reports false.
    #[error("mms layer error: the peer released the association")]
    ReleasedByPeer,

    /// The transport failed: a TCP connection was refused, a host name did not
    /// resolve, a read or write failed, or a TLS peer sent a fatal alert after
    /// the handshake. The connection is closed.
    ///
    /// [`TransportError::kind`] gives the category of the failure and
    /// [`TransportError::detail`] the text the transport reported, if any.
    #[error("mms layer error: transport error: {0}")]
    Transport(TransportError),

    /// The TLS handshake failed. The connection is closed.
    ///
    /// `kind` classifies the failure, so a caller can tell a rejected
    /// certificate from a refusal by the peer, a version or cipher mismatch, a
    /// timeout or a broken transport; `message` is the text of the TLS error.
    #[error("mms layer error: TLS handshake failed: {message}")]
    #[non_exhaustive]
    TlsHandshake {
        /// What made the handshake fail.
        kind: TlsFailureKind,
        /// Text of the TLS error.
        message: String,
    },

    /// The server answered with a Confirmed-ErrorPDU (ISO 9506-2).
    ///
    /// [`ErrorClass::context_tag`] gives the errorClass alternative and
    /// [`ErrorClass::code`] its subcode.
    #[error("mms layer error: mms service error: class={error_class:?}")]
    #[non_exhaustive]
    Service {
        /// errorClass of the ServiceError.
        error_class: ErrorClass,
        /// serviceSpecificInformation of the ServiceError, such as how many
        /// data sets a failed DeleteDataSet did delete; `None` when the server
        /// sent none.
        service_specific: Option<ServiceSpecificInfo>,
    },

    /// The server answered with a RejectPDU (ISO 9506-2).
    ///
    /// [`RejectReason::reject_type`] gives the rejectType, 1 to 11; the
    /// rejectReason value is the discriminant of the inner enum.
    #[error("mms layer error: mms reject: {reason:?}")]
    #[non_exhaustive]
    Reject {
        /// rejectReason of the RejectPDU.
        reason: RejectReason,
    },

    /// The server answered the Conclude request with a Conclude-ErrorPDU, so
    /// the association stays established.
    #[error("mms layer error: the peer refused the conclude request")]
    ConcludeRejected,

    /// The server refused the ACSE association, or its AARE did not decode as
    /// an acceptance.
    #[error("mms layer error: the acse association was refused")]
    AssociateFailed,

    /// The server answered the MMS Initiate request with an Initiate-ErrorPDU.
    #[error("mms layer error: mms initiate failed: errorCode={error_code}")]
    #[non_exhaustive]
    InitiateFailed {
        /// Subcode of the errorClass carried by the Initiate-ErrorPDU.
        error_code: u8,
    },

    /// Requests that timed out unanswered hold every slot of the negotiated
    /// outstanding limit, and no late answer freed one within the request
    /// timeout, so the request was not sent. The association stays
    /// established, and a late answer frees its slot; a peer that discarded
    /// those requests never answers them, so their slots stay held until the
    /// association is aborted or released and established again.
    #[error("mms layer error: the outstanding request limit has been reached")]
    OutstandingCallLimit,

    /// The encoded request exceeds the negotiated maximum PDU size, so it was
    /// not sent; the association stays usable.
    #[error(
        "mms layer error: pdu size {pdu_size} exceeds the negotiated maximum {max_size}, refusing to send"
    )]
    #[non_exhaustive]
    PduTooLarge {
        /// Size of the encoded MMS PDU, in bytes.
        pdu_size: usize,
        /// Negotiated maximum PDU size, in bytes.
        max_size: usize,
    },

    /// The peer answered the connect request with a session REFUSE SPDU.
    ///
    /// Surfaced as a typed variant so a caller can tell an unknown session or
    /// presentation selector from a malformed peer. `reason_code` is PI 50 of
    /// the RF SPDU, `transport_disconnect` PI 17, and `provider_reason` the
    /// provider-reason of the CPR PPDU the refusal carries, when present.
    #[error("{}", iec61850_mms::session_refused_message(*reason_code, *transport_disconnect, *provider_reason))]
    #[non_exhaustive]
    SessionRefused {
        /// Reason code carried by the RF SPDU.
        reason_code: Option<u8>,
        /// Transport disconnect parameter carried by the RF SPDU.
        transport_disconnect: Option<u8>,
        /// provider-reason of the CPR PPDU inside the refusal, when present.
        provider_reason: Option<u8>,
    },

    /// `DataAccessError` reported by the server inside an `AccessResult::Failure`.
    ///
    /// Surfaced as a typed variant (rather than `Mms(String)`) so callers can
    /// branch on the specific access error (`ObjectNonExistent`,
    /// `TypeInconsistent`, …) without parsing strings.
    #[error("data access error: {0:?}")]
    DataAccessError(iec61850_mms::DataAccessError),
}

impl From<iec61850_mms::ClientError> for ClientError {
    fn from(e: iec61850_mms::ClientError) -> Self {
        use iec61850_mms::ClientError as M;
        match e {
            M::DataAccessError(d) => ClientError::DataAccessError(d),
            M::SessionRefused {
                reason_code,
                transport_disconnect,
                provider_reason,
                ..
            } => ClientError::SessionRefused {
                reason_code,
                transport_disconnect,
                provider_reason,
            },
            M::ServiceTimeout { timeout_ms, .. } => ClientError::Timeout {
                after_ms: timeout_ms,
            },
            M::ConnectTimeout { timeout_ms, .. } => ClientError::ConnectTimeout {
                after_ms: timeout_ms,
            },
            M::ConnectionLost => ClientError::ConnectionLost,
            M::ReleasedByPeer => ClientError::ReleasedByPeer,
            M::Transport(cause) => ClientError::Transport(cause),
            M::TlsHandshake { kind, message, .. } => ClientError::TlsHandshake { kind, message },
            #[cfg(feature = "std")]
            M::Io(io) => ClientError::Transport(TransportError::from(io)),
            M::ServiceError {
                error_class,
                service_specific,
                ..
            } => ClientError::Service {
                error_class,
                service_specific,
            },
            M::RejectError { reason, .. } => ClientError::Reject { reason },
            M::ConcludeRejected => ClientError::ConcludeRejected,
            M::AssociateFailed => ClientError::AssociateFailed,
            M::InitiateFailed { error_code, .. } => ClientError::InitiateFailed { error_code },
            M::PduTooLarge {
                pdu_size, max_size, ..
            } => ClientError::PduTooLarge { pdu_size, max_size },
            M::OutstandingCallLimit => ClientError::OutstandingCallLimit,
            M::NotConnected { .. } => ClientError::NotConnected,
            other => ClientError::Mms(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iec61850_hal::transport::IoErrorKind;
    use iec61850_mms::mms::pdu::{ConfirmedRequestRejectReason, DataAccessError};
    use iec61850_mms::ClientError as M;

    fn map(e: M) -> ClientError {
        ClientError::from(e)
    }

    #[test]
    fn a_request_timeout_is_typed_and_keeps_its_text() {
        let e = map(M::service_timeout(300));
        assert_eq!(e, ClientError::Timeout { after_ms: 300 });
        assert_eq!(
            e.to_string(),
            "mms layer error: request timed out after 300 ms"
        );
    }

    #[test]
    fn a_connect_timeout_is_typed() {
        assert_eq!(
            map(M::connect_timeout(7)),
            ClientError::ConnectTimeout { after_ms: 7 }
        );
    }

    #[test]
    fn a_lost_connection_is_typed_and_keeps_its_text() {
        let e = map(M::ConnectionLost);
        assert_eq!(e, ClientError::ConnectionLost);
        assert_eq!(
            e.to_string(),
            "mms layer error: the transport connection was lost"
        );
    }

    #[test]
    fn a_release_by_the_peer_is_typed() {
        assert_eq!(map(M::ReleasedByPeer), ClientError::ReleasedByPeer);
    }

    #[test]
    fn a_transport_failure_keeps_its_cause() {
        let cause = TransportError::io(IoErrorKind::InvalidData).with_detail("alert");
        match map(M::Transport(cause.clone())) {
            ClientError::Transport(c) => assert_eq!(c, cause),
            other => panic!("got {other:?}"),
        }
    }

    /// A failed TLS handshake keeps its kind and its text, for every kind,
    /// and renders the text once.
    #[test]
    fn a_failed_tls_handshake_keeps_its_kind() {
        for kind in [
            TlsFailureKind::Verification,
            TlsFailureKind::AlertReceived,
            TlsFailureKind::VersionUnsupported,
            TlsFailureKind::CipherUnsupported,
            TlsFailureKind::Timeout,
            TlsFailureKind::Io,
            TlsFailureKind::Other,
        ] {
            assert_eq!(
                map(M::tls_handshake(
                    kind,
                    "received fatal alert: ProtocolVersion"
                )),
                ClientError::TlsHandshake {
                    kind,
                    message: "received fatal alert: ProtocolVersion".into(),
                },
                "{kind:?}"
            );
        }
        assert_eq!(
            map(M::tls_handshake(
                TlsFailureKind::AlertReceived,
                "received fatal alert: ProtocolVersion"
            ))
            .to_string(),
            "mms layer error: TLS handshake failed: received fatal alert: ProtocolVersion"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn an_io_error_becomes_a_transport_failure() {
        let io = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        match map(M::Io(io)) {
            ClientError::Transport(c) => assert_eq!(c.kind(), IoErrorKind::ConnectionRefused),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn a_confirmed_error_keeps_its_class_and_code() {
        match map(M::service_error(ErrorClass::Access(3))) {
            ClientError::Service { error_class, .. } => {
                assert_eq!(error_class.context_tag(), 7);
                assert_eq!(error_class.code(), 3);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn a_confirmed_error_keeps_its_service_specific_information() {
        match map(M::service_error(ErrorClass::Service(6))
            .with_service_specific(ServiceSpecificInfo::DeleteNamedVariableList(2)))
        {
            ClientError::Service {
                service_specific, ..
            } => assert_eq!(
                service_specific,
                Some(ServiceSpecificInfo::DeleteNamedVariableList(2))
            ),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn a_reject_keeps_its_reason() {
        let reason = RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::InvalidArgument);
        match map(M::reject(reason.clone())) {
            ClientError::Reject { reason: r, .. } => {
                assert_eq!(r, reason);
                assert_eq!(r.reject_type(), 1);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn refusals_of_the_association_are_typed() {
        assert_eq!(map(M::ConcludeRejected), ClientError::ConcludeRejected);
        assert_eq!(map(M::AssociateFailed), ClientError::AssociateFailed);
        assert_eq!(
            map(M::initiate_failed(2)),
            ClientError::InitiateFailed { error_code: 2 }
        );
    }

    #[test]
    fn a_full_outstanding_limit_is_typed() {
        assert_eq!(
            map(M::OutstandingCallLimit),
            ClientError::OutstandingCallLimit
        );
    }

    #[test]
    fn an_oversized_request_is_typed() {
        assert_eq!(
            map(M::pdu_too_large(10, 9)),
            ClientError::PduTooLarge {
                pdu_size: 10,
                max_size: 9
            }
        );
    }

    #[test]
    fn not_connected_and_data_access_errors_are_typed() {
        assert_eq!(map(M::not_connected("Closed")), ClientError::NotConnected);
        assert_eq!(
            map(M::DataAccessError(DataAccessError::ObjectNonExistent)),
            ClientError::DataAccessError(DataAccessError::ObjectNonExistent)
        );
    }

    #[test]
    fn a_failure_without_a_variant_is_carried_as_text() {
        assert_eq!(
            map(M::PduParse("bad tag".to_string())),
            ClientError::Mms("mms pdu parse error: bad tag".to_string())
        );
    }
}
