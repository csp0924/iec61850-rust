//! The error type of the model crate.
//!
//! Library code does not panic; every failure returns `Result<_, ModelError>`.

use crate::compat::prelude::*;
use thiserror::Error;

/// An error raised by a model operation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ModelError {
    /// The object reference exceeds the 128-byte limit.
    ///
    /// Rejecting an over-long reference keeps the parse bounded instead of
    /// leaving the length check to a later stage.
    #[error("object reference too long: {got} bytes, limit {limit}")]
    ObjectRefTooLong {
        /// Length of the offending reference, in bytes.
        got: usize,
        /// Maximum accepted length, in bytes.
        limit: usize,
    },

    /// The object reference is malformed: a missing `/`, an empty token or an
    /// illegal character.
    #[error("malformed object reference: {reason}")]
    InvalidObjectRef {
        /// What is wrong with the reference.
        reason: String,
    },

    /// The functional constraint abbreviation is not one of the defined tokens.
    #[error("unknown functional constraint: {0:?}")]
    UnknownFc(String),

    /// A node of that name already exists under this parent.
    #[error("name conflict: {kind} `{name}` already exists in `{parent}`")]
    DuplicateName {
        /// Kind of node that collided, such as "LogicalNode" or "DataObject".
        kind: &'static str,
        /// Name that already exists.
        name: String,
        /// Parent the node was being added to.
        parent: String,
    },

    /// The node was attached under a parent that cannot hold it, such as an
    /// SGCB outside LLN0.
    #[error(
        "wrong parent: {kind} must be attached under `{expected_parent}`, found `{got_parent}`"
    )]
    InvalidParent {
        /// Kind of node that was misplaced.
        kind: &'static str,
        /// Parent the node requires.
        expected_parent: &'static str,
        /// Parent it was attached to instead.
        got_parent: String,
    },

    /// A data set entry references a path that does not resolve.
    #[error("data set `{dataset}` has an entry `{entry}` referencing a node that does not exist")]
    DataSetEntryUnresolved {
        /// Name of the data set holding the entry.
        dataset: String,
        /// The entry, as written in the data set.
        entry: String,
    },

    /// The requested node does not exist.
    #[error("node not found: `{0}`")]
    NodeNotFound(String),

    /// The value written does not match the type the data attribute declares.
    #[error("type mismatch: DA `{path}` expects `{expected}`, received `{got}`")]
    TypeMismatch {
        /// Object reference of the data attribute written to.
        path: String,
        /// Type the data attribute declares.
        expected: &'static str,
        /// Type of the value supplied.
        got: &'static str,
    },
}

/// Shorthand for `Result<T, ModelError>`.
pub type Result<T, E = ModelError> = core::result::Result<T, E>;
