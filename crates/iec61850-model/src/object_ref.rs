//! Object reference parsing.
//!
//! IEC 61850 spells an object reference two ways:
//!
//! - MMS notation, per IEC 61850-8-1 §16, as it appears on the wire:
//!   `IED1WD1/LLN0$ST$Mod$stVal`, with `$` between the logical node, the
//!   functional constraint, the data object, the data attribute and any
//!   sub-attributes. The functional constraint is mandatory.
//! - IEC 61850 notation, per IEC 61850-7-2, the logical reference:
//!   `IED1WD1/LLN0.Mod.stVal`, separated by `.` and carrying no functional
//!   constraint.
//!
//! An array index is a `(N)` suffix in either form: `Ind1(0)$stVal` or
//! `Ind1(0).stVal`.
//!
//! Length is capped at 128 bytes, separators included. An over-long reference is
//! rejected before anything is copied, so no length check is left to a later
//! stage.

use crate::compat::prelude::*;
use crate::error::ModelError;
use crate::fc::FC;

/// Maximum length of an object reference string, in bytes.
pub const OBJECT_REF_MAX_LEN: usize = 128;

/// One path segment: either a name or an array index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    /// A name token: a data object, data attribute or sub-attribute.
    Name(String),
    /// An array index, which always follows the name it applies to.
    Index(u32),
}

/// A parsed object reference.
///
/// `IED1WD1/LLN0$ST$Mod$stVal` parses to
/// `domain="IED1WD1", ln="LLN0", fc=Some(ST), path=[Name("Mod"), Name("stVal")]`.
///
/// `IED1WD1/LLN0.Mod.stVal` parses to
/// `domain="IED1WD1", ln="LLN0", fc=None, path=[Name("Mod"), Name("stVal")]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectRef {
    /// The MMS domain: the IED name plus the logical device instance, or the
    /// functional `ldName`.
    pub domain: String,
    /// The logical node name: prefix, class and instance, such as `LLN0`,
    /// `MMXU1` or `XCBR1`.
    pub ln: String,
    /// The functional constraint. Always present in MMS notation, always
    /// `None` in IEC notation.
    pub fc: Option<FC>,
    /// The path below the logical node: data objects, data attributes,
    /// sub-attributes and array indices.
    pub path: Vec<Segment>,
}

impl ObjectRef {
    /// Parses MMS notation, `<domain>/<LN>$<FC>$<DO>[$<DA>[$<SDA>]*]`.
    ///
    /// An array index `(N)` follows the name it applies to.
    ///
    /// # Errors
    ///
    /// [`ModelError::ObjectRefTooLong`] above [`OBJECT_REF_MAX_LEN`];
    /// [`ModelError::InvalidObjectRef`] for a missing `/`, a missing logical
    /// node, a missing functional constraint token, an empty token or a
    /// malformed array index; [`ModelError::UnknownFc`] for an unrecognized
    /// functional constraint.
    pub fn parse_mms(s: &str) -> Result<Self, ModelError> {
        check_length(s)?;

        let (domain, rest) =
            split_once_required(s, '/').ok_or_else(|| ModelError::InvalidObjectRef {
                reason: "missing `/` between the domain and the logical node".into(),
            })?;
        require_nonempty(domain, "domain")?;

        let mut tokens = rest.split('$');
        let ln_raw = tokens.next().ok_or_else(|| ModelError::InvalidObjectRef {
            reason: "missing logical node".into(),
        })?;
        require_nonempty(ln_raw, "LN")?;

        let fc_token = tokens.next().ok_or_else(|| ModelError::InvalidObjectRef {
            reason: "MMS notation requires a functional constraint token".into(),
        })?;
        let fc = FC::parse(fc_token)?;

        let mut path = Vec::new();
        for tok in tokens {
            require_nonempty(tok, "path token")?;
            push_token_with_index(&mut path, tok)?;
        }

        Ok(Self {
            domain: domain.to_string(),
            ln: ln_raw.to_string(),
            fc: Some(fc),
            path,
        })
    }

    /// Parses IEC 61850 notation, `<domain>/<LN>.<DO>[.<DA>[.<SDA>]*]`.
    ///
    /// # Errors
    ///
    /// [`ModelError::ObjectRefTooLong`] above [`OBJECT_REF_MAX_LEN`], and
    /// [`ModelError::InvalidObjectRef`] for a missing `/`, a missing logical
    /// node, an empty token or a malformed array index.
    pub fn parse_iec(s: &str) -> Result<Self, ModelError> {
        check_length(s)?;

        let (domain, rest) =
            split_once_required(s, '/').ok_or_else(|| ModelError::InvalidObjectRef {
                reason: "missing `/` between the domain and the logical node".into(),
            })?;
        require_nonempty(domain, "domain")?;

        let mut tokens = rest.split('.');
        let ln_raw = tokens.next().ok_or_else(|| ModelError::InvalidObjectRef {
            reason: "missing logical node".into(),
        })?;
        require_nonempty(ln_raw, "LN")?;

        let mut path = Vec::new();
        for tok in tokens {
            require_nonempty(tok, "path token")?;
            push_token_with_index(&mut path, tok)?;
        }

        Ok(Self {
            domain: domain.to_string(),
            ln: ln_raw.to_string(),
            fc: None,
            path,
        })
    }

    /// Detects the notation: a `$` anywhere selects MMS notation, otherwise
    /// IEC notation.
    ///
    /// The two forms use disjoint separators, so one string can only be one of
    /// them.
    ///
    /// # Errors
    ///
    /// Whatever the selected parser reports.
    pub fn parse(s: &str) -> Result<Self, ModelError> {
        if s.contains('$') {
            Self::parse_mms(s)
        } else {
            Self::parse_iec(s)
        }
    }

    /// Serializes to MMS notation.
    ///
    /// When `fc` is `None`, `ST` is written; a caller that cares should set
    /// the functional constraint first.
    pub fn to_mms_string(&self) -> String {
        let fc = self.fc.unwrap_or(FC::St);
        let mut out = format!("{}/{}${}", self.domain, self.ln, fc);
        for seg in &self.path {
            match seg {
                Segment::Name(n) => {
                    out.push('$');
                    out.push_str(n);
                }
                Segment::Index(i) => {
                    use core::fmt::Write;
                    write!(out, "({i})").expect("write to String never fails");
                }
            }
        }
        out
    }

    /// Serializes to IEC 61850 notation, without the functional constraint.
    pub fn to_iec_string(&self) -> String {
        let mut out = format!("{}/{}", self.domain, self.ln);
        for seg in &self.path {
            match seg {
                Segment::Name(n) => {
                    out.push('.');
                    out.push_str(n);
                }
                Segment::Index(i) => {
                    use core::fmt::Write;
                    write!(out, "({i})").expect("write to String never fails");
                }
            }
        }
        out
    }
}

fn check_length(s: &str) -> Result<(), ModelError> {
    if s.len() > OBJECT_REF_MAX_LEN {
        return Err(ModelError::ObjectRefTooLong {
            got: s.len(),
            limit: OBJECT_REF_MAX_LEN,
        });
    }
    Ok(())
}

fn split_once_required(s: &str, sep: char) -> Option<(&str, &str)> {
    s.split_once(sep)
}

fn require_nonempty(s: &str, what: &'static str) -> Result<(), ModelError> {
    if s.is_empty() {
        return Err(ModelError::InvalidObjectRef {
            reason: format!("{what} is empty"),
        });
    }
    Ok(())
}

/// Splits a token such as `Name(0)` into `Name("Name")` followed by `Index(0)`.
fn push_token_with_index(path: &mut Vec<Segment>, token: &str) -> Result<(), ModelError> {
    if let Some(open) = token.find('(') {
        if !token.ends_with(')') {
            return Err(ModelError::InvalidObjectRef {
                reason: format!("malformed array index: `{token}`"),
            });
        }
        let name = &token[..open];
        let idx_str = &token[open + 1..token.len() - 1];
        require_nonempty(name, "array container name")?;
        require_nonempty(idx_str, "array index")?;
        let idx: u32 = idx_str.parse().map_err(|_| ModelError::InvalidObjectRef {
            reason: format!("array index `{idx_str}` is not a valid u32"),
        })?;
        path.push(Segment::Name(name.to_string()));
        path.push(Segment::Index(idx));
    } else {
        path.push(Segment::Name(token.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mms_basic() {
        let r = ObjectRef::parse_mms("IED1WD1/LLN0$ST$Mod$stVal").unwrap();
        assert_eq!(r.domain, "IED1WD1");
        assert_eq!(r.ln, "LLN0");
        assert_eq!(r.fc, Some(FC::St));
        assert_eq!(
            r.path,
            vec![Segment::Name("Mod".into()), Segment::Name("stVal".into())]
        );
    }

    #[test]
    fn mms_with_array_index() {
        let r = ObjectRef::parse_mms("IED1WD1/GGIO1$ST$Ind1(2)$stVal").unwrap();
        assert_eq!(
            r.path,
            vec![
                Segment::Name("Ind1".into()),
                Segment::Index(2),
                Segment::Name("stVal".into()),
            ]
        );
    }

    #[test]
    fn iec_basic() {
        let r = ObjectRef::parse_iec("IED1WD1/LLN0.Mod.stVal").unwrap();
        assert_eq!(r.fc, None);
        assert_eq!(
            r.path,
            vec![Segment::Name("Mod".into()), Segment::Name("stVal".into())]
        );
    }

    #[test]
    fn auto_detect_mms() {
        assert_eq!(
            ObjectRef::parse("IED1WD1/LLN0$ST$Mod").unwrap().fc,
            Some(FC::St)
        );
    }

    #[test]
    fn auto_detect_iec() {
        assert_eq!(ObjectRef::parse("IED1WD1/LLN0.Mod").unwrap().fc, None);
    }

    #[test]
    fn missing_slash() {
        assert!(matches!(
            ObjectRef::parse_mms("IED1WD1LLN0$ST$Mod"),
            Err(ModelError::InvalidObjectRef { .. })
        ));
    }

    #[test]
    fn missing_fc() {
        assert!(matches!(
            ObjectRef::parse_mms("IED1WD1/LLN0"),
            Err(ModelError::InvalidObjectRef { .. })
        ));
    }

    #[test]
    fn unknown_fc() {
        assert!(matches!(
            ObjectRef::parse_mms("IED1WD1/LLN0$ZZ$Mod"),
            Err(ModelError::UnknownFc(_))
        ));
    }

    #[test]
    fn empty_domain() {
        assert!(matches!(
            ObjectRef::parse_mms("/LLN0$ST$Mod"),
            Err(ModelError::InvalidObjectRef { .. })
        ));
    }

    #[test]
    fn empty_token() {
        assert!(matches!(
            ObjectRef::parse_mms("IED1WD1/LLN0$ST$$stVal"),
            Err(ModelError::InvalidObjectRef { .. })
        ));
    }

    #[test]
    fn too_long_rejected() {
        let long = format!("D/{}", "a".repeat(OBJECT_REF_MAX_LEN));
        assert!(matches!(
            ObjectRef::parse_mms(&long),
            Err(ModelError::ObjectRefTooLong { .. })
        ));
    }

    #[test]
    fn at_length_limit_accepted() {
        // Exactly 128: "domain/LN$ST" takes 9 characters, leaving 119.
        let mut s = String::from("D/LN$ST");
        while s.len() < OBJECT_REF_MAX_LEN {
            s.push_str("$x");
        }
        s.truncate(OBJECT_REF_MAX_LEN);
        // Truncation can land just after a `$`, so one character is appended.
        if s.ends_with('$') {
            s.pop();
            s.push('y');
        }
        assert!(s.len() <= OBJECT_REF_MAX_LEN);
        // Anything within the limit must not report ObjectRefTooLong; syntax is
        // checked separately.
        let res = ObjectRef::parse_mms(&s);
        assert!(!matches!(res, Err(ModelError::ObjectRefTooLong { .. })));
    }

    #[test]
    fn array_index_bad_syntax() {
        assert!(matches!(
            ObjectRef::parse_mms("IED1WD1/GGIO1$ST$Ind1($stVal"),
            Err(ModelError::InvalidObjectRef { .. })
        ));
        assert!(matches!(
            ObjectRef::parse_mms("IED1WD1/GGIO1$ST$Ind1(abc)"),
            Err(ModelError::InvalidObjectRef { .. })
        ));
    }

    #[test]
    fn round_trip_mms() {
        let s = "IED1WD1/GGIO1$ST$Ind1(2)$stVal";
        let r = ObjectRef::parse_mms(s).unwrap();
        assert_eq!(r.to_mms_string(), s);
    }

    #[test]
    fn round_trip_iec() {
        let s = "IED1WD1/GGIO1.Ind1(2).stVal";
        let r = ObjectRef::parse_iec(s).unwrap();
        assert_eq!(r.to_iec_string(), s);
    }
}
