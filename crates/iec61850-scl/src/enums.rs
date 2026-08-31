//! Helpers that parse SCL enumeration and bit-string strings into Rust types.
//!
//! A failure reports [`ErrorKind::EnumValueUnknown`] together with the list of
//! permitted values, so the message says what to write instead.
//!
//! Covered here: `parse_smp_mod`, `parse_gse_type` and `parse_fc` for plain
//! attribute values, and `parse_trg_ops`, `parse_opt_fields` and
//! `parse_smv_opts`, which read an element's attributes into a bit struct.
//!
//! A coded enumeration inside `<Val>` is not handled here: the basic type has
//! to be known first to pick the right table, so it is resolved in stage 2.

use quick_xml::events::attributes::Attributes;

use crate::attrs::{optional, parse_optional_or};
use crate::error::{ErrorKind, SclParseError, SourceSpan};
use crate::raw::{
    GseControlType, OptionFieldsBits, SampledValueSmpMod, SmvOptsBits, TriggerOptionsBits,
};

// ------------------------------------------------------------------------
// Plain attribute enumerations
// ------------------------------------------------------------------------

/// Parses the `smpMod` attribute of a `<SampledValueControl>`.
///
/// The permitted values are `SmpPerPeriod`, `SmpPerSec` and `SecPerSmp`;
/// `SmpPerPeriod` applies when the attribute is absent.
///
/// # Errors
///
/// [`ErrorKind::EnumValueUnknown`] for any other string.
pub fn parse_smp_mod(
    s: &str,
    span: SourceSpan,
    path: &str,
) -> Result<SampledValueSmpMod, SclParseError> {
    match s {
        "SmpPerPeriod" => Ok(SampledValueSmpMod::SamplesPerPeriod),
        "SmpPerSec" => Ok(SampledValueSmpMod::SamplesPerSecond),
        "SecPerSmp" => Ok(SampledValueSmpMod::SecondsPerSample),
        other => Err(SclParseError::at(
            span,
            path,
            ErrorKind::EnumValueUnknown {
                name: "smpMod".to_string(),
                raw_value: other.to_string(),
                allowed: vec!["SmpPerPeriod", "SmpPerSec", "SecPerSmp"],
            },
        )
        .with_attribute("smpMod")),
    }
}

/// Parses the `type` attribute of a `<GSEControl>`.
///
/// The permitted values are `GOOSE`, which applies when the attribute is
/// absent, and `GSSE`.
///
/// # Errors
///
/// [`ErrorKind::EnumValueUnknown`] for any other string.
pub fn parse_gse_type(
    s: &str,
    span: SourceSpan,
    path: &str,
) -> Result<GseControlType, SclParseError> {
    match s {
        "GOOSE" => Ok(GseControlType::Goose),
        "GSSE" => Ok(GseControlType::GsSe),
        other => Err(SclParseError::at(
            span,
            path,
            ErrorKind::EnumValueUnknown {
                name: "type".to_string(),
                raw_value: other.to_string(),
                allowed: vec!["GOOSE", "GSSE"],
            },
        )
        .with_attribute("type")),
    }
}

/// Parses a two-letter functional constraint token.
///
/// Delegates to [`iec61850_model::fc::FC::parse`] and wraps its failure in an
/// [`SclParseError`] carrying the source span and element path.
///
/// # Errors
///
/// [`ErrorKind::EnumValueUnknown`] when the token is not a defined functional
/// constraint.
pub fn parse_fc(
    s: &str,
    span: SourceSpan,
    path: &str,
) -> Result<iec61850_model::fc::FC, SclParseError> {
    iec61850_model::fc::FC::parse(s).map_err(|e| {
        SclParseError::at(
            span,
            path,
            ErrorKind::AttributeValueInvalid {
                name: "fc".to_string(),
                expected_type: "FC token (ST/MX/CO/SP/SG/SE/...)".to_string(),
                raw_value: s.to_string(),
                cause: Some(format!("{:?}", e)),
            },
        )
        .with_attribute("fc")
    })
}

// ------------------------------------------------------------------------
// Bit-string elements: <TrgOps>, <OptFields>, <SmvOpts>
// ------------------------------------------------------------------------

/// Parses the five boolean attributes of a `<TrgOps>` element.
///
/// This covers the case where the element is present. When `<TrgOps>` is
/// absent entirely, the caller applies
/// [`TriggerOptionsBits::default_when_missing`], which leaves every bit clear.
///
/// # Errors
///
/// [`ErrorKind::AttributeValueInvalid`] when an attribute is neither `"true"`
/// nor `"false"`.
pub fn parse_trg_ops(
    attrs: Attributes<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<TriggerOptionsBits, SclParseError> {
    // The attribute iterator can be consumed only once, so it is collected first.
    let collected: Vec<(String, String)> = attrs
        .filter_map(|r| r.ok())
        .map(|a| (a.key.as_ref().to_string(), a.value.into_owned()))
        .collect();

    let lookup_bool = |name: &str, default: bool| -> Result<bool, SclParseError> {
        for (k, v) in &collected {
            if k == name {
                return match v.as_str() {
                    "true" => Ok(true),
                    "false" => Ok(false),
                    other => Err(SclParseError::at(
                        span,
                        path,
                        ErrorKind::AttributeValueInvalid {
                            name: name.to_string(),
                            expected_type: "bool (\"true\" or \"false\")".to_string(),
                            raw_value: other.to_string(),
                            cause: None,
                        },
                    )
                    .with_attribute(name)),
                };
            }
        }
        Ok(default)
    };

    Ok(TriggerOptionsBits {
        data_change: lookup_bool("dchg", false)?,
        quality_change: lookup_bool("qchg", false)?,
        data_update: lookup_bool("dupd", false)?,
        period: lookup_bool("period", false)?,
        gi: lookup_bool("gi", false)?,
    })
}

/// Parses the eight boolean attributes of an `<OptFields>` element.
///
/// `bufOvfl` defaults to true; every other attribute defaults to false.
///
/// # Errors
///
/// [`ErrorKind::AttributeValueInvalid`] when an attribute is neither `"true"`
/// nor `"false"`.
pub fn parse_opt_fields(
    attrs: Attributes<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<OptionFieldsBits, SclParseError> {
    let collected: Vec<(String, String)> = attrs
        .filter_map(|r| r.ok())
        .map(|a| (a.key.as_ref().to_string(), a.value.into_owned()))
        .collect();

    let lookup_bool = |name: &str, default: bool| -> Result<bool, SclParseError> {
        for (k, v) in &collected {
            if k == name {
                return match v.as_str() {
                    "true" => Ok(true),
                    "false" => Ok(false),
                    other => Err(SclParseError::at(
                        span,
                        path,
                        ErrorKind::AttributeValueInvalid {
                            name: name.to_string(),
                            expected_type: "bool".to_string(),
                            raw_value: other.to_string(),
                            cause: None,
                        },
                    )
                    .with_attribute(name)),
                };
            }
        }
        Ok(default)
    };

    Ok(OptionFieldsBits {
        seq_num: lookup_bool("seqNum", false)?,
        time_stamp: lookup_bool("timeStamp", false)?,
        data_set: lookup_bool("dataSet", false)?,
        reason_code: lookup_bool("reasonCode", false)?,
        data_ref: lookup_bool("dataRef", false)?,
        buffer_overflow: lookup_bool("bufOvfl", true)?, // note the true default
        ent_id: lookup_bool("entryID", false)?,
        conf_rev: lookup_bool("configRef", false)?,
        segmentation: lookup_bool("segmentation", false)?,
    })
}

/// Parses the six boolean attributes of an `<SmvOpts>` element.
///
/// # Errors
///
/// [`ErrorKind::AttributeValueInvalid`] when an attribute is neither `"true"`
/// nor `"false"`.
pub fn parse_smv_opts(
    attrs: Attributes<'_>,
    span: SourceSpan,
    path: &str,
) -> Result<SmvOptsBits, SclParseError> {
    let collected: Vec<(String, String)> = attrs
        .filter_map(|r| r.ok())
        .map(|a| (a.key.as_ref().to_string(), a.value.into_owned()))
        .collect();

    let lookup_bool = |name: &str, default: bool| -> Result<bool, SclParseError> {
        for (k, v) in &collected {
            if k == name {
                return match v.as_str() {
                    "true" => Ok(true),
                    "false" => Ok(false),
                    other => Err(SclParseError::at(
                        span,
                        path,
                        ErrorKind::AttributeValueInvalid {
                            name: name.to_string(),
                            expected_type: "bool".to_string(),
                            raw_value: other.to_string(),
                            cause: None,
                        },
                    )
                    .with_attribute(name)),
                };
            }
        }
        Ok(default)
    };

    Ok(SmvOptsBits {
        refresh_time: lookup_bool("refreshTime", false)?,
        sample_synchronized: lookup_bool("sampleSynchronized", false)?,
        sample_rate: lookup_bool("sampleRate", false)?,
        data_set: lookup_bool("dataSet", false)?,
        security: lookup_bool("security", false)?,
        data_ref: lookup_bool("dataRef", false)?,
    })
}

// ------------------------------------------------------------------------
// Fallback values for a missing element
// ------------------------------------------------------------------------

impl TriggerOptionsBits {
    /// The value to use when the `<TrgOps>` element is absent entirely.
    ///
    /// Every bit is clear. IEC 61850-6 defines no default here, so general
    /// interrogation has to be requested explicitly rather than assumed.
    pub fn default_when_missing() -> Self {
        Self::default()
    }
}

impl OptionFieldsBits {
    /// The value to use when the `<OptFields>` element is absent entirely.
    ///
    /// Every field takes its attribute-level default, so a file that omits the
    /// element parses instead of failing.
    pub fn default_when_missing() -> Self {
        Self {
            buffer_overflow: true, // the attribute-level default
            ..Default::default()
        }
    }
}

impl SmvOptsBits {
    /// The value to use when the `<SmvOpts>` element is absent entirely.
    ///
    /// Every bit is clear, so a file that omits the element parses instead of
    /// failing.
    pub fn default_when_missing() -> Self {
        Self::default()
    }
}

// Not used outside this module yet; reserved for the remaining element handlers.
#[allow(dead_code)]
fn _drop_unused_imports() {
    let _ = optional;
    let _ = parse_optional_or::<u32>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use quick_xml::events::BytesStart;

    fn span() -> SourceSpan {
        SourceSpan {
            line: 1,
            col: 1,
            byte_offset: 0,
        }
    }

    #[test]
    fn smp_mod_known() {
        assert_eq!(
            parse_smp_mod("SmpPerPeriod", span(), "/").unwrap(),
            SampledValueSmpMod::SamplesPerPeriod
        );
        assert_eq!(
            parse_smp_mod("SmpPerSec", span(), "/").unwrap(),
            SampledValueSmpMod::SamplesPerSecond
        );
        assert_eq!(
            parse_smp_mod("SecPerSmp", span(), "/").unwrap(),
            SampledValueSmpMod::SecondsPerSample
        );
    }

    #[test]
    fn smp_mod_unknown_lists_allowed() {
        let err = parse_smp_mod("Bogus", span(), "/").unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("Bogus"));
        assert!(msg.contains("SmpPerPeriod"));
        assert!(msg.contains("SecPerSmp"));
    }

    #[test]
    fn gse_type_known() {
        assert_eq!(
            parse_gse_type("GOOSE", span(), "/").unwrap(),
            GseControlType::Goose
        );
        assert_eq!(
            parse_gse_type("GSSE", span(), "/").unwrap(),
            GseControlType::GsSe
        );
    }

    #[test]
    fn fc_known() {
        let fc = parse_fc("ST", span(), "/").unwrap();
        assert_eq!(fc, iec61850_model::fc::FC::St);
    }

    #[test]
    fn fc_unknown_actionable() {
        let err = parse_fc("XX", span(), "/").unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("XX"));
    }

    #[test]
    fn trg_ops_all_false_when_no_attrs() {
        let s = BytesStart::new("TrgOps");
        let bits = parse_trg_ops(s.attributes(), span(), "/").unwrap();
        assert!(!bits.data_change && !bits.quality_change && !bits.data_update);
        assert!(!bits.period && !bits.gi);
    }

    #[test]
    fn trg_ops_attrs_set() {
        let s = BytesStart::new("TrgOps").with_attributes([
            ("dchg", "true"),
            ("qchg", "true"),
            ("gi", "true"),
        ]);
        let bits = parse_trg_ops(s.attributes(), span(), "/").unwrap();
        assert!(bits.data_change && bits.quality_change && bits.gi);
        assert!(!bits.data_update && !bits.period);
    }

    #[test]
    fn opt_fields_buf_ovfl_defaults_true() {
        let s = BytesStart::new("OptFields");
        let bits = parse_opt_fields(s.attributes(), span(), "/").unwrap();
        assert!(bits.buffer_overflow, "bufOvfl defaults to true");
        assert!(!bits.seq_num);
    }

    #[test]
    fn opt_fields_explicit_false_overrides_default() {
        let s = BytesStart::new("OptFields").with_attributes([("bufOvfl", "false")]);
        let bits = parse_opt_fields(s.attributes(), span(), "/").unwrap();
        assert!(!bits.buffer_overflow);
    }

    #[test]
    fn smv_opts_default_all_false() {
        let s = BytesStart::new("SmvOpts");
        let bits = parse_smv_opts(s.attributes(), span(), "/").unwrap();
        assert!(!bits.refresh_time && !bits.sample_synchronized);
    }

    #[test]
    fn missing_element_helpers_return_safe_defaults() {
        let trg = TriggerOptionsBits::default_when_missing();
        assert!(!trg.gi, "general interrogation is not defaulted on");

        let opt = OptionFieldsBits::default_when_missing();
        assert!(opt.buffer_overflow);
        assert!(!opt.seq_num);

        let smv = SmvOptsBits::default_when_missing();
        assert!(!smv.refresh_time);
    }
}
