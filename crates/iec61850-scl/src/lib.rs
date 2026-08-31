//! SCL and ICD parser for IEC 61850-6.
//!
//! Parsing runs in two stages, so a failure can say exactly what is wrong.
//! Stage 1, [`raw`], reports a broken XML structure, a missing attribute or an
//! unrecognized enumeration string, with a line and column pointing into the
//! XML. Stage 2, [`resolved`], reports an unresolved type reference or a
//! cross-element inconsistency, with a line and column pointing at the
//! reference and a message naming the type kind and identifier that was
//! sought.
//!
//! Every [`error::ErrorKind`] carries the same five pieces of information -
//! line, column, element path, attribute name, and the raw value against the
//! expected one - so a malformed file is never accepted silently.
//!
//! ```ignore
//! let raw = iec61850_scl::parse_scl(xml_str)?;   // stage 1
//! let resolved = raw.resolve()?;                 // stage 2
//! let model = resolved.build_model("IED1")?;     // an IedModel
//! ```

pub mod attrs;
pub mod build_model;
pub mod enums;
pub mod error;
pub mod parser;
pub mod raw;
pub mod resolved;
pub mod summarize;

pub use error::{ErrorKind, SclParseError, SourceSpan, TypeKind};
pub use raw::RawScl;
pub use resolved::ResolvedScl;

/// Parses an SCL XML string into the stage 1 raw AST.
///
/// Call [`RawScl::resolve`] to continue into stage 2.
///
/// # Errors
///
/// [`SclParseError`] for any stage 1 failure; the categories are in
/// [`ErrorKind`].
pub fn parse_scl(xml: &str) -> Result<RawScl, SclParseError> {
    parser::parse(xml)
}

impl RawScl {
    /// Runs stage 2: resolves type references and checks cross-element
    /// consistency.
    ///
    /// # Errors
    ///
    /// [`SclParseError`] when a type reference does not resolve or a
    /// consistency rule is violated.
    pub fn resolve(self) -> Result<ResolvedScl, SclParseError> {
        ResolvedScl::from_raw(self)
    }
}

// -----------------------------------------------------------------------------
// Code generation exports
//
// The `model.rs` a build script emits references only the codegen-private
// modules below, so a user crate need not depend on `iec61850-model` directly.
// -----------------------------------------------------------------------------

/// Codegen-only re-exports, referenced by the `model.rs` a build script emits.
///
/// The double-underscore name follows the convention of other code generation
/// support modules: the contents change without notice, so user code must not
/// import from here. Model types have a stable public API in
/// `iec61850-model`.
#[doc(hidden)]
pub mod __rt {
    pub use iec61850_model::builder::{
        DataObjectBuilder, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder,
    };
    pub use iec61850_model::cb::{
        GooseControlBlock, LogControlBlock, OptFlds, ReportControlBlock, SettingGroupControlBlock,
        SvControlBlock,
    };
    pub use iec61850_model::fc::FC;
    pub use iec61850_model::tree::{
        DataAttribute, DataObject, DataSet, DataSetEntry, DoChild, IedModel,
    };
    pub use iec61850_model::types::{DataAttributeType, TrgOps};
    pub use iec61850_model::value::MmsValue;
}

/// Codegen-only helper re-exports, giving a build script the same lookup
/// functions the runtime path uses, among them `b_type_to_dat`, `parse_fc` and
/// `trg_ops_to_model`. The emit layer therefore turns values into tokens
/// without re-deriving any semantics.
///
/// As with [`__rt`], user code must not import from here.
#[doc(hidden)]
pub mod __build_internals {
    pub use crate::build_model::{
        b_type_to_dat, opt_fields_to_model, parse_fc, parse_val_for_b_type, pick_val_for_no_sgroup,
        report_trg_ops_to_model, trg_ops_to_model,
    };
    pub use crate::error::SourceSpan;
    pub use crate::raw::{OptionFieldsBits, TriggerOptionsBits};
    /// Canonical text dump used to compare the generated and the runtime build
    /// paths for equivalence. See [`crate::summarize`].
    pub use crate::summarize::summarize_model;
    // Re-exporting the helper return types keeps the build crate free of a
    // direct dependency on `iec61850-model`.
    pub use iec61850_model::cb::OptFlds;
    pub use iec61850_model::fc::FC;
    pub use iec61850_model::types::{DataAttributeType, TrgOps};
    pub use iec61850_model::value::MmsValue;
}

/// Includes the `model.rs` that a build script generated into `OUT_DIR`.
///
/// After `iec61850-scl-build` has run in `build.rs`, the user crate writes:
///
/// ```ignore
/// iec61850_scl::include_compiled_model!();          // includes OUT_DIR/model.rs
/// iec61850_scl::include_compiled_model!("foo.rs");  // includes OUT_DIR/foo.rs
///
/// fn main() {
///     let model = build_my_ied_model();             // the generated function
///     // start a server with it
/// }
/// ```
#[macro_export]
macro_rules! include_compiled_model {
    () => {
        include!(concat!(env!("OUT_DIR"), "/model.rs"));
    };
    ($file:literal) => {
        include!(concat!(env!("OUT_DIR"), "/", $file));
    };
}
