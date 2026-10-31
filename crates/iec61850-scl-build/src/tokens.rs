//! Shared to-tokens helpers for functional constraints, trigger options, data
//! attribute types and default values.
//!
//! These helpers re-derive no semantics. `emit_dat` and `emit_fc` call the same
//! runtime helpers through `iec61850_scl::__private` and only serialize
//! the result, so a lookup table can never be right at run time and wrong in
//! generated code.
//!
//! Values are emitted as expressions evaluated inside the generated function
//! body rather than as constants. Several `MmsValue` variants own a `Vec<u8>`
//! or a `String`, and the model wraps them in `Arc<RwLock<_>>`, so no part of
//! the chain is const.

use proc_macro2::TokenStream;
use quote::quote;

use iec61850_scl::__private::{
    b_type_to_dat, log_trg_ops_to_model, opt_fields_to_model, parse_fc, report_trg_ops_to_model,
    trg_ops_to_model, DataAttributeType, MmsValue, OptFlds, OptionFieldsBits, SourceSpan, TrgOps,
    TriggerOptionsBits, FC,
};
use iec61850_scl::SclParseError;

/// Emits an `FC` token from its SCL spelling.
///
/// Parsing goes through the runtime [`parse_fc`] helper, so only a token the
/// parser accepts is emitted.
///
/// # Errors
///
/// [`SclParseError`] with an actionable message when `token` is not a valid
/// functional constraint.
pub fn emit_fc(token: &str, span: SourceSpan, path: &str) -> Result<TokenStream, SclParseError> {
    let fc = parse_fc(token, span, path)?;
    Ok(emit_fc_value(fc))
}

/// Emits an `FC` token from an [`FC`] value.
pub fn emit_fc_value(fc: FC) -> TokenStream {
    let ident = quote::format_ident!("{}", fc_variant_name(fc));
    quote! { ::iec61850_scl::__private::FC::#ident }
}

fn fc_variant_name(fc: FC) -> &'static str {
    match fc {
        FC::St => "St",
        FC::Mx => "Mx",
        FC::Sp => "Sp",
        FC::Sv => "Sv",
        FC::Cf => "Cf",
        FC::Dc => "Dc",
        FC::Sg => "Sg",
        FC::Se => "Se",
        FC::Sr => "Sr",
        FC::Or => "Or",
        FC::Bl => "Bl",
        FC::Ex => "Ex",
        FC::Co => "Co",
        FC::Us => "Us",
        FC::Ms => "Ms",
        FC::Rp => "Rp",
        FC::Br => "Br",
        FC::Lg => "Lg",
        FC::Go => "Go",
        // `parse_fc` accepts only the 19 valid FC tokens. The two remaining
        // variants exist for the model's own query API and cannot reach emit.
        FC::All | FC::None => unreachable!(
            "fc_variant_name: FC::{:?} cannot occur on the SCL parsing path",
            fc
        ),
    }
}

/// Emits a trigger-option token set from the bits of a `<DA trgOps="...">`.
pub fn emit_trg_ops(bits: TriggerOptionsBits) -> TokenStream {
    let trg = trg_ops_to_model(bits);
    emit_trg_ops_value(trg)
}

/// Emits a trigger-option token set from a [`TrgOps`] value, covering all five
/// bits.
///
/// A DA-level value never carries INTEGRITY or GI, because the runtime helper
/// filters them out; an RCB-level value reaches this function through
/// [`emit_report_trg_ops`], which keeps them.
pub fn emit_trg_ops_value(trg: TrgOps) -> TokenStream {
    let mut parts: Vec<TokenStream> = Vec::new();
    if trg.contains(TrgOps::DCHG) {
        parts.push(quote! { ::iec61850_scl::__private::TrgOps::DCHG });
    }
    if trg.contains(TrgOps::QCHG) {
        parts.push(quote! { ::iec61850_scl::__private::TrgOps::QCHG });
    }
    if trg.contains(TrgOps::DUPD) {
        parts.push(quote! { ::iec61850_scl::__private::TrgOps::DUPD });
    }
    if trg.contains(TrgOps::INTEGRITY) {
        parts.push(quote! { ::iec61850_scl::__private::TrgOps::INTEGRITY });
    }
    if trg.contains(TrgOps::GI) {
        parts.push(quote! { ::iec61850_scl::__private::TrgOps::GI });
    }
    if parts.is_empty() {
        quote! { ::iec61850_scl::__private::TrgOps::NONE }
    } else {
        quote! { #(#parts)|* }
    }
}

/// Emits the five-bit trigger-option set of a `<ReportControl><TrgOps>`,
/// INTEGRITY and GI included.
pub fn emit_report_trg_ops(bits: TriggerOptionsBits) -> TokenStream {
    let trg = report_trg_ops_to_model(bits);
    emit_trg_ops_value(trg)
}

/// Emits the trigger-option set of a `<LogControl><TrgOps>`: DCHG, QCHG, DUPD
/// and INTEGRITY, without GI.
pub fn emit_log_trg_ops(bits: TriggerOptionsBits) -> TokenStream {
    emit_trg_ops_value(log_trg_ops_to_model(bits))
}

/// Emits the option-field set of a `<ReportControl><OptFields>`.
pub fn emit_opt_flds(bits: OptionFieldsBits) -> TokenStream {
    let flds = opt_fields_to_model(bits);
    emit_opt_flds_value(flds)
}

/// Emits an option-field token set from an [`OptFlds`] value.
pub fn emit_opt_flds_value(flds: OptFlds) -> TokenStream {
    let mut parts: Vec<TokenStream> = Vec::new();
    if flds.contains(OptFlds::SEQ_NUM) {
        parts.push(quote! { ::iec61850_scl::__private::OptFlds::SEQ_NUM });
    }
    if flds.contains(OptFlds::TIME_STAMP) {
        parts.push(quote! { ::iec61850_scl::__private::OptFlds::TIME_STAMP });
    }
    if flds.contains(OptFlds::REASON) {
        parts.push(quote! { ::iec61850_scl::__private::OptFlds::REASON });
    }
    if flds.contains(OptFlds::DATA_SET) {
        parts.push(quote! { ::iec61850_scl::__private::OptFlds::DATA_SET });
    }
    if flds.contains(OptFlds::DATA_REFERENCE) {
        parts.push(quote! { ::iec61850_scl::__private::OptFlds::DATA_REFERENCE });
    }
    if flds.contains(OptFlds::BUFFER_OVERFLOW) {
        parts.push(quote! { ::iec61850_scl::__private::OptFlds::BUFFER_OVERFLOW });
    }
    if flds.contains(OptFlds::ENTRY_ID) {
        parts.push(quote! { ::iec61850_scl::__private::OptFlds::ENTRY_ID });
    }
    if flds.contains(OptFlds::CONF_REV) {
        parts.push(quote! { ::iec61850_scl::__private::OptFlds::CONF_REV });
    }
    if flds.contains(OptFlds::SEGMENTATION) {
        parts.push(quote! { ::iec61850_scl::__private::OptFlds::SEGMENTATION });
    }
    if parts.is_empty() {
        quote! { ::iec61850_scl::__private::OptFlds::NONE }
    } else {
        quote! { #(#parts)|* }
    }
}

/// Emits a `DataAttributeType` token from an SCL `bType` string.
///
/// Conversion goes through the runtime [`b_type_to_dat`] helper.
///
/// # Errors
///
/// [`SclParseError`] when `b_type` is not a recognized basic type.
pub fn emit_dat(b_type: &str, span: SourceSpan, path: &str) -> Result<TokenStream, SclParseError> {
    let dat = b_type_to_dat(b_type, span, path)?;
    Ok(emit_dat_value(dat))
}

/// Emits a `DataAttributeType` token from a [`DataAttributeType`] value.
pub fn emit_dat_value(dat: DataAttributeType) -> TokenStream {
    use DataAttributeType as T;
    match dat {
        T::Boolean => quote! { ::iec61850_scl::__private::DataAttributeType::Boolean },
        T::Int8 => quote! { ::iec61850_scl::__private::DataAttributeType::Int8 },
        T::Int16 => quote! { ::iec61850_scl::__private::DataAttributeType::Int16 },
        T::Int24 => quote! { ::iec61850_scl::__private::DataAttributeType::Int24 },
        T::Int32 => quote! { ::iec61850_scl::__private::DataAttributeType::Int32 },
        T::Int64 => quote! { ::iec61850_scl::__private::DataAttributeType::Int64 },
        T::Int128 => quote! { ::iec61850_scl::__private::DataAttributeType::Int128 },
        T::Int8U => quote! { ::iec61850_scl::__private::DataAttributeType::Int8U },
        T::Int16U => quote! { ::iec61850_scl::__private::DataAttributeType::Int16U },
        T::Int24U => quote! { ::iec61850_scl::__private::DataAttributeType::Int24U },
        T::Int32U => quote! { ::iec61850_scl::__private::DataAttributeType::Int32U },
        T::Float32 => quote! { ::iec61850_scl::__private::DataAttributeType::Float32 },
        T::Float64 => quote! { ::iec61850_scl::__private::DataAttributeType::Float64 },
        T::Enumerated => quote! { ::iec61850_scl::__private::DataAttributeType::Enumerated },
        T::OctetString(n) => {
            quote! { ::iec61850_scl::__private::DataAttributeType::OctetString(#n) }
        }
        T::VisibleString(n) => {
            quote! { ::iec61850_scl::__private::DataAttributeType::VisibleString(#n) }
        }
        T::UnicodeString255 => {
            quote! { ::iec61850_scl::__private::DataAttributeType::UnicodeString255 }
        }
        T::Timestamp => quote! { ::iec61850_scl::__private::DataAttributeType::Timestamp },
        T::Quality => quote! { ::iec61850_scl::__private::DataAttributeType::Quality },
        T::CodedEnum => quote! { ::iec61850_scl::__private::DataAttributeType::CodedEnum },
        T::Check => quote! { ::iec61850_scl::__private::DataAttributeType::Check },
        T::Constructed => quote! { ::iec61850_scl::__private::DataAttributeType::Constructed },
        T::GenericBitString(n) => {
            quote! { ::iec61850_scl::__private::DataAttributeType::GenericBitString(#n) }
        }
        T::EntryTime => quote! { ::iec61850_scl::__private::DataAttributeType::EntryTime },
        T::PhyComAddr => quote! { ::iec61850_scl::__private::DataAttributeType::PhyComAddr },
        T::OptFlds => quote! { ::iec61850_scl::__private::DataAttributeType::OptFlds },
        T::TrgOpsBits => quote! { ::iec61850_scl::__private::DataAttributeType::TrgOpsBits },
        T::SvOptFlds => quote! { ::iec61850_scl::__private::DataAttributeType::SvOptFlds },
        T::LogOptFlds => quote! { ::iec61850_scl::__private::DataAttributeType::LogOptFlds },
        T::Currency => quote! { ::iec61850_scl::__private::DataAttributeType::Currency },
        other => unsupported_dat(other),
    }
}

/// Emits a `compile_error!` naming a data attribute type the generator has
/// no token for.
fn unsupported_dat(dat: DataAttributeType) -> TokenStream {
    let msg = format!("iec61850-scl-build: unsupported data attribute type {dat:?}");
    quote! { ::core::compile_error!(#msg) }
}

/// Emits a concrete [`MmsValue`] as a literal expression.
///
/// Used for the initial value of every leaf and for DOI, SDI and DAI
/// overrides: the build script derives the value with the same helpers the
/// run-time path uses, then emits it here, including the full `data` bytes of
/// a bit string or the contents of a visible string, so the user's run time
/// performs no string parsing.
pub fn emit_mms_value(v: &MmsValue) -> TokenStream {
    match v {
        MmsValue::Boolean(b) => {
            let lit = *b;
            quote! { ::iec61850_scl::__private::MmsValue::Boolean(#lit) }
        }
        MmsValue::Integer(i) => {
            let lit = *i;
            quote! { ::iec61850_scl::__private::MmsValue::Integer(#lit) }
        }
        MmsValue::Unsigned(u) => {
            let lit = *u;
            quote! { ::iec61850_scl::__private::MmsValue::Unsigned(#lit) }
        }
        MmsValue::Float32(f) => {
            // Round-tripping through the bit pattern keeps NaN, infinities and
            // precision exact.
            let bits = f.to_bits();
            quote! { ::iec61850_scl::__private::MmsValue::Float32(f32::from_bits(#bits)) }
        }
        MmsValue::Float64(f) => {
            let bits = f.to_bits();
            quote! { ::iec61850_scl::__private::MmsValue::Float64(f64::from_bits(#bits)) }
        }
        MmsValue::BitString { padding, data } => {
            let pad = *padding;
            let bytes: Vec<u8> = data.to_vec();
            quote! {
                ::iec61850_scl::__private::MmsValue::BitString {
                    padding: #pad,
                    data: ::std::vec![ #( #bytes ),* ],
                }
            }
        }
        MmsValue::OctetString(bytes) => {
            let bs: Vec<u8> = bytes.clone();
            quote! {
                ::iec61850_scl::__private::MmsValue::OctetString(::std::vec![ #( #bs ),* ])
            }
        }
        MmsValue::VisibleString(s) => {
            let lit = s.as_str();
            quote! {
                ::iec61850_scl::__private::MmsValue::VisibleString(::std::string::String::from(#lit))
            }
        }
        MmsValue::MmsString(s) => {
            let lit = s.as_str();
            quote! {
                ::iec61850_scl::__private::MmsValue::MmsString(::std::string::String::from(#lit))
            }
        }
        MmsValue::UtcTime(b8) => {
            let bytes = b8.to_vec();
            quote! {
                ::iec61850_scl::__private::MmsValue::UtcTime([
                    #( #bytes ),*
                ])
            }
        }
        MmsValue::BinaryTime(bytes) => {
            let bs: Vec<u8> = bytes.clone();
            quote! {
                ::iec61850_scl::__private::MmsValue::BinaryTime(::std::vec![ #( #bs ),* ])
            }
        }
        // Array and Structure do not arise from a DAI override, because
        // `parse_val_for_b_type` returns only leaf values. The branches are kept
        // so a future extension has somewhere to land.
        MmsValue::Array(items) => {
            let inner = items.iter().map(emit_mms_value);
            quote! {
                ::iec61850_scl::__private::MmsValue::Array(::std::vec![ #( #inner ),* ])
            }
        }
        MmsValue::Structure(items) => {
            let inner = items.iter().map(emit_mms_value);
            quote! {
                ::iec61850_scl::__private::MmsValue::Structure(::std::vec![ #( #inner ),* ])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every basic type of IEC 61850-6 §9.5.4.2 that the run-time path maps
    /// onto a data attribute type has a token, so a data attribute type added
    /// without one fails here instead of in a user's build.
    #[test]
    fn every_schema_basic_type_has_a_token() {
        let span = SourceSpan {
            line: 0,
            col: 0,
            byte_offset: 0,
        };
        for b_type in [
            "BOOLEAN",
            "INT8",
            "INT16",
            "INT24",
            "INT32",
            "INT64",
            "INT128",
            "INT8U",
            "INT16U",
            "INT24U",
            "INT32U",
            "FLOAT32",
            "FLOAT64",
            "Enum",
            "Dbpos",
            "Tcmd",
            "Quality",
            "Timestamp",
            "VisString32",
            "VisString64",
            "VisString65",
            "VisString129",
            "VisString255",
            "Octet64",
            "Unicode255",
            "EntryTime",
            "Check",
            "ObjRef",
            "Currency",
            "PhyComAddr",
            "TrgOps",
            "OptFlds",
            "SvOptFlds",
            "LogOptFlds",
            "EntryID",
            "Octet6",
            "Octet16",
        ] {
            let tokens = emit_dat(b_type, span, "test")
                .unwrap_or_else(|e| panic!("{b_type}: {e}"))
                .to_string();
            assert!(!tokens.contains("compile_error"), "{b_type}: {tokens}");
        }
        for dat in [
            DataAttributeType::Constructed,
            DataAttributeType::GenericBitString(7),
        ] {
            let tokens = emit_dat_value(dat).to_string();
            assert!(!tokens.contains("compile_error"), "{dat:?}: {tokens}");
        }
    }
}
