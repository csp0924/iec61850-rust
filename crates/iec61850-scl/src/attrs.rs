//! Attribute access helpers shared by every element handler.
//!
//! Each helper reports a failure with the source span, the element path, the
//! attribute name and the raw value, so a malformed attribute never surfaces
//! as a bare parse error without context.
//!
//! - `required(attrs, "name", span, path)` returns the value, or
//!   `MissingRequiredAttribute`.
//! - `optional(attrs, "name")` returns `None` when the attribute is absent, and
//!   never fails.
//! - `optional_or(attrs, "name", default)` substitutes `default`.
//! - `parse_required::<T>(...)` requires the attribute and parses it as `T`.
//! - `parse_optional::<T>(...)` allows the attribute to be absent, but parses
//!   it when present.
//!
//! A failing `parse_*` reports [`ErrorKind::AttributeValueInvalid`] with the
//! expected type, the raw value and the underlying cause.

use quick_xml::events::attributes::Attributes;

use crate::error::{ErrorKind, SclParseError, SourceSpan};

/// Reads one attribute value, unescaped, or `None` when it is absent.
///
/// quick-xml borrows from its own buffer, so the value is copied into an owned
/// `String` and the caller never holds a reference into the reader.
///
/// An undeclared entity in an attribute yields the raw escaped text, while the
/// same entity in element text is a parse error. The two differ because this
/// function has no error channel: [`optional`] is documented never to fail, so
/// aligning them widens three signatures and every call site.
pub fn lookup<'a>(mut attrs: Attributes<'a>, name: &str) -> Option<String> {
    while let Some(Ok(attr)) = attrs.next() {
        if attr.key.as_ref() == name {
            // Unescape `&amp;` to `&`, `&lt;` to `<` and so on.
            // TODO: an unresolvable reference falls back to the raw form here
            // and is an error in element text; align the two on the error.
            let raw: &str = attr.value.as_ref();
            let val = quick_xml::escape::unescape(raw)
                .map(|c| c.into_owned())
                .unwrap_or_else(|_| raw.to_string());
            return Some(val);
        }
    }
    None
}

/// Reads a required attribute.
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when the attribute is absent.
pub fn required(
    attrs: Attributes<'_>,
    name: &str,
    span: SourceSpan,
    path: &str,
) -> Result<String, SclParseError> {
    lookup(attrs, name).ok_or_else(|| {
        SclParseError::at(
            span,
            path,
            ErrorKind::MissingRequiredAttribute {
                name: name.to_string(),
            },
        )
        .with_attribute(name)
    })
}

/// Reads an optional attribute. Never fails.
pub fn optional(attrs: Attributes<'_>, name: &str) -> Option<String> {
    lookup(attrs, name)
}

/// Reads an optional attribute, substituting `default` when it is absent.
pub fn optional_or(attrs: Attributes<'_>, name: &str, default: &str) -> String {
    lookup(attrs, name).unwrap_or_else(|| default.to_string())
}

// ------------------------------------------------------------------------
// parse_required and parse_optional, the type-converting variants
// ------------------------------------------------------------------------

/// Reads a required attribute and parses it as `T` through [`AttrParse`].
///
/// # Errors
///
/// [`ErrorKind::MissingRequiredAttribute`] when the attribute is absent, and
/// [`ErrorKind::AttributeValueInvalid`] when the value does not parse.
pub fn parse_required<T: AttrParse>(
    attrs: Attributes<'_>,
    name: &str,
    span: SourceSpan,
    path: &str,
) -> Result<T, SclParseError> {
    let raw = required(attrs, name, span, path)?;
    T::parse(&raw).map_err(|cause| {
        SclParseError::at(
            span,
            path,
            ErrorKind::AttributeValueInvalid {
                name: name.to_string(),
                expected_type: T::EXPECTED.to_string(),
                raw_value: raw.clone(),
                cause: Some(cause),
            },
        )
        .with_attribute(name)
    })
}

/// Reads an optional attribute and parses it as `T` when it is present.
///
/// # Errors
///
/// [`ErrorKind::AttributeValueInvalid`] when a present value does not parse.
pub fn parse_optional<T: AttrParse>(
    attrs: Attributes<'_>,
    name: &str,
    span: SourceSpan,
    path: &str,
) -> Result<Option<T>, SclParseError> {
    let raw = match lookup(attrs, name) {
        Some(s) => s,
        None => return Ok(None),
    };
    T::parse(&raw).map(Some).map_err(|cause| {
        SclParseError::at(
            span,
            path,
            ErrorKind::AttributeValueInvalid {
                name: name.to_string(),
                expected_type: T::EXPECTED.to_string(),
                raw_value: raw,
                cause: Some(cause),
            },
        )
        .with_attribute(name)
    })
}

/// Reads an optional attribute, substituting `default` when it is absent.
///
/// A value that is present but does not parse is an error; it never falls back
/// to `default`.
///
/// # Errors
///
/// [`ErrorKind::AttributeValueInvalid`] when a present value does not parse.
pub fn parse_optional_or<T: AttrParse + Clone>(
    attrs: Attributes<'_>,
    name: &str,
    default: T,
    span: SourceSpan,
    path: &str,
) -> Result<T, SclParseError> {
    Ok(parse_optional::<T>(attrs, name, span, path)?.unwrap_or(default))
}

// ------------------------------------------------------------------------
// The AttrParse trait, used by the parse_* helpers
// ------------------------------------------------------------------------

/// Parses an SCL attribute string into a concrete Rust type.
///
/// A failure returns a human-readable cause, which the helpers wrap in
/// [`ErrorKind::AttributeValueInvalid`].
pub trait AttrParse: Sized {
    /// The expected-type description used in an error message, such as `"u32"`.
    const EXPECTED: &'static str;
    /// Parses `s`, returning a human-readable cause on failure.
    fn parse(s: &str) -> Result<Self, String>;
}

impl AttrParse for String {
    const EXPECTED: &'static str = "string";
    fn parse(s: &str) -> Result<Self, String> {
        Ok(s.to_string())
    }
}

impl AttrParse for u32 {
    const EXPECTED: &'static str = "u32 (decimal)";
    fn parse(s: &str) -> Result<Self, String> {
        s.parse::<u32>().map_err(|e| e.to_string())
    }
}

impl AttrParse for i32 {
    const EXPECTED: &'static str = "i32 (decimal)";
    fn parse(s: &str) -> Result<Self, String> {
        s.parse::<i32>().map_err(|e| e.to_string())
    }
}

impl AttrParse for u16 {
    const EXPECTED: &'static str = "u16 (decimal)";
    fn parse(s: &str) -> Result<Self, String> {
        s.parse::<u16>().map_err(|e| e.to_string())
    }
}

/// SCL booleans are strictly `"true"` or `"false"`, case sensitive.
///
/// Anything else is rejected rather than silently treated as false, so a typo
/// in an SCL file cannot quietly disable a setting.
impl AttrParse for bool {
    const EXPECTED: &'static str = "bool (\"true\" or \"false\")";
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "true" => Ok(true),
            "false" => Ok(false),
            other => Err(format!("not a valid SCL bool, saw `{}`", other)),
        }
    }
}

/// Parses a hex string into a `u32`, for a VLAN identifier or an APPID. The
/// `0x` prefix is optional.
pub struct HexU32(pub u32);

impl AttrParse for HexU32 {
    const EXPECTED: &'static str = "hex u32, optionally prefixed with 0x";
    fn parse(s: &str) -> Result<Self, String> {
        let trimmed = s.trim_start_matches("0x").trim_start_matches("0X");
        u32::from_str_radix(trimmed, 16)
            .map(HexU32)
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quick_xml::events::BytesStart;

    fn make_attrs<'a>(start: &'a BytesStart<'a>) -> Attributes<'a> {
        start.attributes()
    }

    fn span() -> SourceSpan {
        SourceSpan {
            line: 1,
            col: 1,
            byte_offset: 0,
        }
    }

    #[test]
    fn required_present() {
        let s = BytesStart::new("LDevice").with_attributes([("inst", "LD0")]);
        let v = required(make_attrs(&s), "inst", span(), "SCL/IED/.../LDevice").unwrap();
        assert_eq!(v, "LD0");
    }

    #[test]
    fn required_missing_yields_actionable_err() {
        let s = BytesStart::new("LDevice"); // no inst attribute
        let err = required(make_attrs(&s), "inst", span(), "SCL/IED/.../LDevice").unwrap_err();
        assert_eq!(err.attribute.as_deref(), Some("inst"));
        let msg = format!("{}", err);
        assert!(msg.contains("inst"));
        assert!(msg.contains("is required"));
    }

    #[test]
    fn optional_returns_none_when_absent() {
        let s = BytesStart::new("LDevice");
        assert_eq!(optional(make_attrs(&s), "desc"), None);
    }

    #[test]
    fn optional_or_falls_back() {
        let s = BytesStart::new("RC");
        assert_eq!(optional_or(make_attrs(&s), "buffered", "false"), "false");
    }

    #[test]
    fn parse_required_u32() {
        let s = BytesStart::new("RC").with_attributes([("confRev", "42")]);
        let v: u32 = parse_required(make_attrs(&s), "confRev", span(), "SCL/.../RC").unwrap();
        assert_eq!(v, 42);
    }

    #[test]
    fn parse_required_u32_invalid_yields_actionable_err() {
        let s = BytesStart::new("RC").with_attributes([("confRev", "42x")]);
        let err =
            parse_required::<u32>(make_attrs(&s), "confRev", span(), "SCL/.../RC").unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("u32"));
        assert!(msg.contains("42x"));
    }

    #[test]
    fn parse_bool_strict() {
        let s = BytesStart::new("RC").with_attributes([("buffered", "true")]);
        assert!(parse_required::<bool>(make_attrs(&s), "buffered", span(), "/").unwrap());

        let s2 = BytesStart::new("RC").with_attributes([("buffered", "True")]);
        let err = parse_required::<bool>(make_attrs(&s2), "buffered", span(), "/").unwrap_err();
        let msg = format!("{}", err);
        // "True" must not be accepted
        assert!(msg.contains("True"));
    }

    #[test]
    fn parse_optional_some() {
        let s = BytesStart::new("RC").with_attributes([("intgPd", "1000")]);
        let v: Option<u32> = parse_optional(make_attrs(&s), "intgPd", span(), "/").unwrap();
        assert_eq!(v, Some(1000));
    }

    #[test]
    fn parse_optional_none() {
        let s = BytesStart::new("RC");
        let v: Option<u32> = parse_optional(make_attrs(&s), "intgPd", span(), "/").unwrap();
        assert_eq!(v, None);
    }

    #[test]
    fn parse_optional_or_uses_default() {
        let s = BytesStart::new("RC");
        let v: u32 = parse_optional_or(make_attrs(&s), "bufTime", 0, span(), "/").unwrap();
        assert_eq!(v, 0);
    }

    #[test]
    fn parse_hex_u32() {
        let s = BytesStart::new("P").with_attributes([("v", "0x1234")]);
        let HexU32(v) = parse_required::<HexU32>(make_attrs(&s), "v", span(), "/").unwrap();
        assert_eq!(v, 0x1234);
    }
}
