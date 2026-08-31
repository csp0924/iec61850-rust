//! Error type for `iec61850-server`.
//!
//! Every failure the server can detect is reported as an `Err`; the crate never
//! relies on an assertion that a release build would compile out.

#[cfg(not(feature = "std"))]
use alloc::string::String;
use thiserror::Error;

/// Errors raised by the IED server, its model mapping, and its runtime.
#[derive(Debug, Error)]
pub enum ServerError {
    /// `lock_data_model` was called while the data model was already locked.
    ///
    /// Reentrant locking returns this error instead of blocking, so the caller
    /// can choose between retrying and giving up rather than deadlocking.
    #[error("data model is already locked by this thread; reentrant locking is not allowed")]
    AlreadyLocked,

    /// An `update_*` call supplied an `MmsValue` whose type does not match the
    /// target data attribute.
    #[error("data attribute type mismatch: DA `{path}` expects {expected}, got {actual}")]
    TypeMismatch {
        /// Object reference of the data attribute that was written.
        path: String,
        /// Name of the value variant the attribute currently holds.
        expected: &'static str,
        /// Name of the value variant that was supplied.
        actual: &'static str,
    },

    /// An MMS domain name derived from a logical device exceeds 64 bytes.
    #[error("MMS domain name `{name}` exceeds 64 bytes")]
    DomainNameTooLong {
        /// The domain name that exceeds the limit.
        name: String,
    },

    /// Two logical devices map to the same MMS domain name.
    #[error("duplicate MMS domain name `{name}`: two logical devices resolve to it")]
    DuplicateDomain {
        /// The domain name that two logical devices share.
        name: String,
    },

    /// Model validation failed: an unresolvable data set reference, an SGCB
    /// outside LLN0, and similar structural defects.
    #[error("model validation failed: {0}")]
    InvalidModel(String),

    /// Socket error from the accept loop or from binding the listener.
    ///
    /// `std::io::Error` does not exist in a no_std build, so this variant is
    /// gated on `std`; the accept loop and listener bind are `full-server` and
    /// std-only, so an embedded build cannot reach it.
    #[cfg(feature = "std")]
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A PDU sent by the peer could not be decoded at the COTP, Session,
    /// Presentation, ACSE, or MMS layer.
    ///
    /// The offending layer has already logged the detail; this variant only
    /// propagates the failure.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// The server has been stopped and cannot serve the request.
    #[error("server is stopped")]
    NotRunning,

    /// A `ctlModel` value outside the valid range 0..=4 was found in the model.
    ///
    /// An out-of-range value is rejected rather than coerced, so construction
    /// fails immediately rather than serving a control model the engineer did
    /// not configure.
    #[error("ctlModel value {value} is outside the valid range 0..=4")]
    InvalidCtlModel {
        /// The out-of-range value found in the model.
        value: i32,
    },
}

/// Result of a server operation, with [`ServerError`] as its error type.
pub type Result<T> = core::result::Result<T, ServerError>;
