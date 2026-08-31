//! Stage 1 raw AST: Rust structures mirroring the SCL elements and attributes
//! one for one, with every type identifier left as a string.
//!
//! Splitting the parse in two keeps error messages precise. A broken XML
//! structure, a missing attribute or an unrecognized enumeration string fails
//! here, with a line and column pointing into the XML. An unresolved type
//! reference or a cross-element inconsistency fails in stage 2,
//! [`crate::resolved`], with a line and column pointing at the reference and a
//! message naming the referenced type kind and identifier.

pub mod elements;

pub use elements::*;

/// The SCL root: the raw AST of the `<SCL>` element, before any type
/// resolution.
///
/// Call [`Self::resolve`] to continue into stage 2.
#[derive(Debug, Clone, Default)]
pub struct RawScl {
    /// The `<Header>` element, if the file carries one.
    pub header: Option<Header>,
    /// Every `<IED>` element, in document order.
    pub ieds: Vec<RawIed>,
    /// The `<DataTypeTemplates>` section.
    pub data_type_templates: DataTypeTemplates,
    /// The Communication and Substation sections are not parsed. The field is
    /// reserved so that adding them later does not break the API; until then
    /// the parser skips those subtrees and emits a `tracing::warn!` naming the
    /// element, line and column, so a skip is visible in a log.
    pub _unsupported_sections: (),
}
