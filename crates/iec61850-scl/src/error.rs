//! `SclParseError`, the actionable error type of the SCL parser.
//!
//! Every error states which line, which element or attribute, what was seen
//! and what was expected, so a malformed file can be corrected without
//! re-reading it by hand.

use std::fmt;

/// The root error of SCL parsing.
///
/// Always carries a [`SourceSpan`] and an [`ErrorKind`], plus the element path
/// and, for an attribute-level failure, the attribute name.
///
/// `kind` is boxed so that `Result<T, SclParseError>` does not reserve
/// 160-odd bytes on the success path. The public API still exposes it as
/// `&ErrorKind`.
#[derive(Debug, thiserror::Error)]
pub struct SclParseError {
    /// The semantic category of the failure.
    pub kind: Box<ErrorKind>,
    /// Where in the source XML the failure occurred.
    pub span: SourceSpan,
    /// An XPath-like path, for example
    /// `SCL/IED[name="IED1"]/AccessPoint/Server/LDevice[inst="LD1"]`.
    pub element_path: String,
    /// The attribute at fault; `None` for an element-level failure.
    pub attribute: Option<String>,
}

impl fmt::Display for SclParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SCL parse error at {} ({}", self.span, self.element_path)?;
        if let Some(attr) = &self.attribute {
            write!(f, " @{}", attr)?;
        }
        write!(f, "): {}", self.kind)
    }
}

/// A coordinate in the source XML. Lines and columns are one-based.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceSpan {
    /// One-based line number.
    pub line: u32,
    /// One-based column number.
    pub col: u32,
    /// Byte offset reported by the XML reader, as a fallback when the line and
    /// column are unreliable.
    pub byte_offset: u64,
}

impl fmt::Display for SourceSpan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}, col {}", self.line, self.col)
    }
}

/// The semantic category of a parse failure.
///
/// Every variant carries enough information to say what was seen and what was
/// expected, so no failure is reported as a bare "parse error".
#[derive(Debug, thiserror::Error)]
pub enum ErrorKind {
    /// The XML itself is malformed, as reported by the reader. Wrapped so the
    /// message can also carry the element path.
    #[error("malformed XML: {0}")]
    Xml(String),

    /// A required attribute is absent.
    #[error("attribute `{name}` is required but was not provided")]
    MissingRequiredAttribute {
        /// Name of the missing attribute.
        name: String,
    },

    /// A required child element is absent.
    #[error("element `{name}` must appear at least once")]
    MissingRequiredElement {
        /// Name of the missing child element.
        name: String,
    },

    /// An attribute value does not parse as the expected type.
    #[error("attribute `{name}` expects {expected_type}, saw `{raw_value}`")]
    AttributeValueInvalid {
        /// Name of the offending attribute.
        name: String,
        /// Type the parser expected, for the message.
        expected_type: String,
        /// The attribute value as written.
        raw_value: String,
        /// The underlying parse failure, in more detail.
        cause: Option<String>,
    },

    /// An enumeration string is outside the permitted set.
    #[error("enum `{name}` does not accept `{raw_value}`; permitted values: {}", allowed.join(", "))]
    EnumValueUnknown {
        /// Name of the offending attribute.
        name: String,
        /// The value as written.
        raw_value: String,
        /// The values the enumeration accepts.
        allowed: Vec<&'static str>,
    },

    /// Stage 2: a type reference does not resolve.
    ///
    /// The message names the kind of type sought, LNodeType, DOType, DAType or
    /// EnumType, and its identifier; the element path of the reference is on
    /// [`SclParseError::element_path`].
    #[error("no {type_kind} with `id=\"{type_id}\"` is declared in DataTypeTemplates")]
    UnresolvedTypeReference {
        /// Kind of type that was sought.
        type_kind: TypeKind,
        /// The identifier that did not resolve.
        type_id: String,
    },

    /// The same identifier appears twice, such as two logical devices sharing
    /// one instance name, which SCL forbids.
    #[error("`{element}` has a duplicate `{key}=\"{value}\"`; the first is at {first_span}")]
    DuplicateIdentifier {
        /// Name of the element that repeats.
        element: String,
        /// Attribute that has to be unique.
        key: String,
        /// The duplicated value.
        value: String,
        /// Where the first occurrence is.
        first_span: SourceSpan,
    },

    /// Two attribute values contradict each other.
    #[error("conflicting attributes: {detail}")]
    SemanticConflict {
        /// What the two attribute values disagree about.
        detail: String,
    },

    /// A valid SCL construct this crate does not implement yet.
    ///
    /// Currently never constructed: the parser skips a construct it does not
    /// implement, with a warning for `<Substation>` and `<Communication>` and
    /// without one otherwise. The variant is reserved for a construct that
    /// must be reported rather than skipped, because dropping it would change
    /// the model a client sees.
    // TODO: return this for a skipped construct that alters the resulting model.
    #[error("unsupported SCL construct: {element} (see {issue_ref})")]
    Unsupported {
        /// The unsupported element.
        element: String,
        /// A reference the user can look up.
        issue_ref: &'static str,
    },
}

/// The four kinds of SCL type identifier, one per DataTypeTemplates section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeKind {
    /// A `<LNodeType>` identifier.
    LNodeType,
    /// A `<DOType>` identifier.
    DOType,
    /// A `<DAType>` identifier.
    DAType,
    /// An `<EnumType>` identifier.
    EnumType,
}

impl fmt::Display for TypeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeKind::LNodeType => f.write_str("LNodeType"),
            TypeKind::DOType => f.write_str("DOType"),
            TypeKind::DAType => f.write_str("DAType"),
            TypeKind::EnumType => f.write_str("EnumType"),
        }
    }
}

/// Convenience constructors used inside the parser.
impl SclParseError {
    /// Builds an error at `span` on `path`, with no attribute attached.
    pub fn at(span: SourceSpan, path: impl Into<String>, kind: ErrorKind) -> Self {
        Self {
            kind: Box::new(kind),
            span,
            element_path: path.into(),
            attribute: None,
        }
    }

    /// Attaches the offending attribute name to the error.
    pub fn with_attribute(mut self, attr: impl Into<String>) -> Self {
        self.attribute = Some(attr.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_includes_line_col_and_path() {
        let err = SclParseError::at(
            SourceSpan {
                line: 42,
                col: 17,
                byte_offset: 1234,
            },
            "SCL/IED[name=\"IED1\"]/LDevice[inst=\"LD0\"]",
            ErrorKind::MissingRequiredAttribute {
                name: "lnClass".to_string(),
            },
        )
        .with_attribute("lnClass");

        let msg = format!("{}", err);
        assert!(msg.contains("line 42"));
        assert!(msg.contains("col 17"));
        assert!(msg.contains("LDevice[inst=\"LD0\"]"));
        assert!(msg.contains("@lnClass"));
        assert!(msg.contains("lnClass"));
    }

    #[test]
    fn unresolved_type_reference_is_actionable() {
        let err = SclParseError::at(
            SourceSpan {
                line: 100,
                col: 5,
                byte_offset: 4096,
            },
            "SCL/IED/LN0/DOI[name=\"Mod\"]",
            ErrorKind::UnresolvedTypeReference {
                type_kind: TypeKind::DOType,
                type_id: "missing_DO_type".to_string(),
            },
        );

        let msg = format!("{}", err);
        assert!(msg.contains("DOType"));
        assert!(msg.contains("missing_DO_type"));
        assert!(msg.contains("DataTypeTemplates"));
    }
}
