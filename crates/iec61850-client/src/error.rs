//! Error type returned by the `iec61850-client` service APIs.
//!
//! Every fallible operation returns `Result<T, ClientError>`; failures are
//! never signaled through an out-parameter or a sentinel return value.

#[cfg(not(feature = "std"))]
use alloc::string::{String, ToString};

use thiserror::Error;

#[cfg(feature = "reporting")]
use crate::report::ReportParseError;

/// Error returned by the client service APIs.
///
/// Layered errors from `iec61850-mms` arrive through the `From` impl below:
/// a `DataAccessError` keeps its typed form, everything else is flattened
/// into `Mms`.
#[derive(Debug, Error)]
pub enum ClientError {
    /// The `rpt_id` argument is longer than the 128-byte MMS object-name limit.
    #[error("invalid rptId: length {len} exceeds upper bound 128")]
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
    InvalidBinaryTimeLen {
        /// Length of the offending field, in bytes.
        got: usize,
    },

    /// A service was called on an `IedConnection` that is not connected.
    #[error("connection is not established")]
    NotConnected,

    /// An error from the MMS, ISO or TCP layer below, rendered through its
    /// `Display`.
    ///
    /// The text is kept rather than the original value so that `ClientError`
    /// stays `Debug` and `Eq` regardless of the layered type; the full value is
    /// visible in the tracing log.
    #[error("mms layer error: {0}")]
    Mms(String),

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
        match e {
            iec61850_mms::ClientError::DataAccessError(d) => ClientError::DataAccessError(d),
            other => ClientError::Mms(other.to_string()),
        }
    }
}

// `PartialEq` is implemented by hand: the layered MMS error is held as a
// string, so equality compares the variant and its contents structurally.
impl PartialEq for ClientError {
    fn eq(&self, other: &Self) -> bool {
        use ClientError::*;
        match (self, other) {
            (InvalidRptId { len: a }, InvalidRptId { len: b }) => a == b,
            (AlreadyRegistered(a), AlreadyRegistered(b)) => a == b,
            (NotFound(a), NotFound(b)) => a == b,
            #[cfg(feature = "reporting")]
            (ParseFailed(a), ParseFailed(b)) => a == b,
            (InvalidArgument(a), InvalidArgument(b)) => a == b,
            (
                TypeMismatch {
                    index: i1,
                    expected: e1,
                    got: g1,
                },
                TypeMismatch {
                    index: i2,
                    expected: e2,
                    got: g2,
                },
            ) => i1 == i2 && e1 == e2 && g1 == g2,
            (
                UnexpectedValueType {
                    expected: e1,
                    got: g1,
                },
                UnexpectedValueType {
                    expected: e2,
                    got: g2,
                },
            ) => e1 == e2 && g1 == g2,
            (NotConnected, NotConnected) => true,
            (Mms(a), Mms(b)) => a == b,
            (DataAccessError(a), DataAccessError(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for ClientError {}
