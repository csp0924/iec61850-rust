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
mod build_model;
pub mod enums;
pub mod error;
pub mod parser;
pub mod raw;
pub mod resolved;
pub mod summarize;

pub use error::{ErrorKind, SclParseError, SourceSpan, TypeKind};
pub use raw::RawScl;
pub use resolved::{ResolveOptions, ResolvedScl};

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

    /// Runs stage 2 as [`resolve`](Self::resolve) does, under the limits of
    /// `options`.
    ///
    /// # Errors
    ///
    /// As [`resolve`](Self::resolve); see [`ResolvedScl::from_raw_with`].
    pub fn resolve_with(self, options: &ResolveOptions) -> Result<ResolvedScl, SclParseError> {
        ResolvedScl::from_raw_with(self, options)
    }
}

// -----------------------------------------------------------------------------
// Code generation support
// -----------------------------------------------------------------------------

/// Code generation support for `iec61850-scl-build` and the `model.rs` it
/// emits: the model types the generated code names, and the helpers the build
/// script shares with the run-time build path, so the two derive every value
/// the same way.
///
/// The contents change without notice and are matched only by the
/// `iec61850-scl-build` of the same version, so user code must not import
/// from here. Model types have a stable public API in `iec61850-model`.
#[doc(hidden)]
pub mod __private {
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

    pub use crate::build_model::{
        apply_to_instance, attribute_type, b_type_to_dat, dai_values, derives_setting_view,
        fcda_do_path, gse_control_go_id, ld_domain_name, ld_num_of_sgs, log_trg_ops_to_model,
        opt_fields_to_model, parse_fc, parse_val_for_b_type, report_instances,
        report_trg_ops_to_model, setting_view, skip_indexed_instance, sv_control_sv_id,
        template_initial_value, trg_ops_to_model, warn_count_not_modeled,
    };
    pub use crate::error::SourceSpan;
    pub use crate::raw::{OptionFieldsBits, TriggerOptionsBits};
    pub use crate::summarize::summarize_model;
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
