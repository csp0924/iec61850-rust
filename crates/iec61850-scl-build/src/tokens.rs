//! Shared to-tokens helpers for functional constraints, trigger options, data
//! attribute types and default values.
//!
//! These helpers re-derive no semantics. `emit_dat` and `emit_fc` call the same
//! runtime helpers through `iec61850_scl::__build_internals` and only serialize
//! the result, so a lookup table can never be right at run time and wrong in
//! generated code.
//!
//! Default values are emitted as expressions evaluated inside the generated
//! function body rather than as constants. Several `MmsValue` variants own a
//! `Vec<u8>` or a `String`, and the model wraps them in `Arc<RwLock<_>>`, so no
//! part of the chain is const; this mirrors the runtime
//! `MmsValue::default_for(dat)`.

use proc_macro2::TokenStream;
use quote::quote;

use iec61850_scl::__build_internals::{
    b_type_to_dat, opt_fields_to_model, parse_fc, report_trg_ops_to_model, trg_ops_to_model,
    DataAttributeType, MmsValue, OptFlds, OptionFieldsBits, SourceSpan, TrgOps, TriggerOptionsBits,
    FC,
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
    quote! { ::iec61850_scl::__rt::FC::#ident }
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
        parts.push(quote! { ::iec61850_scl::__rt::TrgOps::DCHG });
    }
    if trg.contains(TrgOps::QCHG) {
        parts.push(quote! { ::iec61850_scl::__rt::TrgOps::QCHG });
    }
    if trg.contains(TrgOps::DUPD) {
        parts.push(quote! { ::iec61850_scl::__rt::TrgOps::DUPD });
    }
    if trg.contains(TrgOps::INTEGRITY) {
        parts.push(quote! { ::iec61850_scl::__rt::TrgOps::INTEGRITY });
    }
    if trg.contains(TrgOps::GI) {
        parts.push(quote! { ::iec61850_scl::__rt::TrgOps::GI });
    }
    if parts.is_empty() {
        quote! { ::iec61850_scl::__rt::TrgOps::NONE }
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

/// Emits the option-field set of a `<ReportControl><OptFields>`.
pub fn emit_opt_flds(bits: OptionFieldsBits) -> TokenStream {
    let flds = opt_fields_to_model(bits);
    emit_opt_flds_value(flds)
}

/// Emits an option-field token set from an [`OptFlds`] value.
pub fn emit_opt_flds_value(flds: OptFlds) -> TokenStream {
    let mut parts: Vec<TokenStream> = Vec::new();
    if flds.contains(OptFlds::SEQ_NUM) {
        parts.push(quote! { ::iec61850_scl::__rt::OptFlds::SEQ_NUM });
    }
    if flds.contains(OptFlds::TIME_STAMP) {
        parts.push(quote! { ::iec61850_scl::__rt::OptFlds::TIME_STAMP });
    }
    if flds.contains(OptFlds::REASON) {
        parts.push(quote! { ::iec61850_scl::__rt::OptFlds::REASON });
    }
    if flds.contains(OptFlds::DATA_SET) {
        parts.push(quote! { ::iec61850_scl::__rt::OptFlds::DATA_SET });
    }
    if flds.contains(OptFlds::DATA_REFERENCE) {
        parts.push(quote! { ::iec61850_scl::__rt::OptFlds::DATA_REFERENCE });
    }
    if flds.contains(OptFlds::BUFFER_OVERFLOW) {
        parts.push(quote! { ::iec61850_scl::__rt::OptFlds::BUFFER_OVERFLOW });
    }
    if flds.contains(OptFlds::ENTRY_ID) {
        parts.push(quote! { ::iec61850_scl::__rt::OptFlds::ENTRY_ID });
    }
    if flds.contains(OptFlds::CONF_REV) {
        parts.push(quote! { ::iec61850_scl::__rt::OptFlds::CONF_REV });
    }
    if flds.contains(OptFlds::SEGMENTATION) {
        parts.push(quote! { ::iec61850_scl::__rt::OptFlds::SEGMENTATION });
    }
    if parts.is_empty() {
        quote! { ::iec61850_scl::__rt::OptFlds::NONE }
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
        T::Boolean => quote! { ::iec61850_scl::__rt::DataAttributeType::Boolean },
        T::Int8 => quote! { ::iec61850_scl::__rt::DataAttributeType::Int8 },
        T::Int16 => quote! { ::iec61850_scl::__rt::DataAttributeType::Int16 },
        T::Int32 => quote! { ::iec61850_scl::__rt::DataAttributeType::Int32 },
        T::Int64 => quote! { ::iec61850_scl::__rt::DataAttributeType::Int64 },
        T::Int128 => quote! { ::iec61850_scl::__rt::DataAttributeType::Int128 },
        T::Int8U => quote! { ::iec61850_scl::__rt::DataAttributeType::Int8U },
        T::Int16U => quote! { ::iec61850_scl::__rt::DataAttributeType::Int16U },
        T::Int24U => quote! { ::iec61850_scl::__rt::DataAttributeType::Int24U },
        T::Int32U => quote! { ::iec61850_scl::__rt::DataAttributeType::Int32U },
        T::Float32 => quote! { ::iec61850_scl::__rt::DataAttributeType::Float32 },
        T::Float64 => quote! { ::iec61850_scl::__rt::DataAttributeType::Float64 },
        T::Enumerated => quote! { ::iec61850_scl::__rt::DataAttributeType::Enumerated },
        T::OctetString(n) => {
            quote! { ::iec61850_scl::__rt::DataAttributeType::OctetString(#n) }
        }
        T::VisibleString(n) => {
            quote! { ::iec61850_scl::__rt::DataAttributeType::VisibleString(#n) }
        }
        T::UnicodeString255 => {
            quote! { ::iec61850_scl::__rt::DataAttributeType::UnicodeString255 }
        }
        T::Timestamp => quote! { ::iec61850_scl::__rt::DataAttributeType::Timestamp },
        T::Quality => quote! { ::iec61850_scl::__rt::DataAttributeType::Quality },
        T::CodedEnum => quote! { ::iec61850_scl::__rt::DataAttributeType::CodedEnum },
        T::Check => quote! { ::iec61850_scl::__rt::DataAttributeType::Check },
        T::Constructed => quote! { ::iec61850_scl::__rt::DataAttributeType::Constructed },
        T::GenericBitString(n) => {
            quote! { ::iec61850_scl::__rt::DataAttributeType::GenericBitString(#n) }
        }
        T::EntryTime => quote! { ::iec61850_scl::__rt::DataAttributeType::EntryTime },
        T::PhyComAddr => quote! { ::iec61850_scl::__rt::DataAttributeType::PhyComAddr },
        T::OptFlds => quote! { ::iec61850_scl::__rt::DataAttributeType::OptFlds },
        T::TrgOpsBits => quote! { ::iec61850_scl::__rt::DataAttributeType::TrgOpsBits },
        T::Currency => quote! { ::iec61850_scl::__rt::DataAttributeType::Currency },
    }
}

/// Emits the zero value of a data attribute type as an expression.
///
/// Mirrors the runtime `MmsValue::default_for(dat)`, allocating a fresh `Vec`
/// or `String` on each call, so generated and runtime models start from the
/// same value.
pub fn emit_default_mms_value(dat: DataAttributeType) -> TokenStream {
    use DataAttributeType as T;
    match dat {
        T::Boolean => quote! { ::iec61850_scl::__rt::MmsValue::Boolean(false) },
        T::Int8 | T::Int16 | T::Int32 | T::Int64 | T::Int128 => {
            quote! { ::iec61850_scl::__rt::MmsValue::Integer(0) }
        }
        T::Int8U | T::Int16U | T::Int24U | T::Int32U => {
            quote! { ::iec61850_scl::__rt::MmsValue::Unsigned(0) }
        }
        T::Float32 => quote! { ::iec61850_scl::__rt::MmsValue::Float32(0.0) },
        T::Float64 => quote! { ::iec61850_scl::__rt::MmsValue::Float64(0.0) },
        T::Enumerated | T::CodedEnum => {
            quote! { ::iec61850_scl::__rt::MmsValue::Integer(0) }
        }
        T::OctetString(_) => {
            quote! { ::iec61850_scl::__rt::MmsValue::OctetString(::std::vec::Vec::new()) }
        }
        T::VisibleString(_) => {
            quote! { ::iec61850_scl::__rt::MmsValue::VisibleString(::std::string::String::new()) }
        }
        T::UnicodeString255 => {
            quote! { ::iec61850_scl::__rt::MmsValue::MmsString(::std::string::String::new()) }
        }
        T::Timestamp => {
            quote! { ::iec61850_scl::__rt::MmsValue::UtcTime([0u8; 8]) }
        }
        T::Quality => {
            quote! {
                ::iec61850_scl::__rt::MmsValue::BitString {
                    padding: 3,
                    data: ::std::vec![0u8, 0u8],
                }
            }
        }
        T::Check => {
            quote! {
                ::iec61850_scl::__rt::MmsValue::BitString {
                    padding: 6,
                    data: ::std::vec![0u8],
                }
            }
        }
        T::EntryTime => {
            quote! { ::iec61850_scl::__rt::MmsValue::BinaryTime(::std::vec::Vec::new()) }
        }
        // The rare basic types below have no dedicated representation: the
        // runtime `default_for` falls back to an octet string for them, and the
        // generated code follows.
        T::PhyComAddr
        | T::OptFlds
        | T::TrgOpsBits
        | T::Currency
        | T::Constructed
        | T::GenericBitString(_) => {
            quote! { ::iec61850_scl::__rt::MmsValue::OctetString(::std::vec::Vec::new()) }
        }
    }
}

/// Emits a concrete [`MmsValue`] as a literal expression.
///
/// Used for DOI, SDI and DAI overrides: the build script parses the SCL `<Val>`
/// text into an `MmsValue` with
/// `iec61850_scl::__build_internals::parse_val_for_b_type`, then emits it here,
/// so the user's run time performs no string parsing.
///
/// Unlike [`emit_default_mms_value`], this emits the actual value, including the
/// full `data` bytes of a bit string or the contents of a visible string,
/// rather than an empty container.
pub fn emit_mms_value(v: &MmsValue) -> TokenStream {
    match v {
        MmsValue::Boolean(b) => {
            let lit = *b;
            quote! { ::iec61850_scl::__rt::MmsValue::Boolean(#lit) }
        }
        MmsValue::Integer(i) => {
            let lit = *i;
            quote! { ::iec61850_scl::__rt::MmsValue::Integer(#lit) }
        }
        MmsValue::Unsigned(u) => {
            let lit = *u;
            quote! { ::iec61850_scl::__rt::MmsValue::Unsigned(#lit) }
        }
        MmsValue::Float32(f) => {
            // Round-tripping through the bit pattern keeps NaN, infinities and
            // precision exact.
            let bits = f.to_bits();
            quote! { ::iec61850_scl::__rt::MmsValue::Float32(f32::from_bits(#bits)) }
        }
        MmsValue::Float64(f) => {
            let bits = f.to_bits();
            quote! { ::iec61850_scl::__rt::MmsValue::Float64(f64::from_bits(#bits)) }
        }
        MmsValue::BitString { padding, data } => {
            let pad = *padding;
            let bytes: Vec<u8> = data.to_vec();
            quote! {
                ::iec61850_scl::__rt::MmsValue::BitString {
                    padding: #pad,
                    data: ::std::vec![ #( #bytes ),* ],
                }
            }
        }
        MmsValue::OctetString(bytes) => {
            let bs: Vec<u8> = bytes.clone();
            quote! {
                ::iec61850_scl::__rt::MmsValue::OctetString(::std::vec![ #( #bs ),* ])
            }
        }
        MmsValue::VisibleString(s) => {
            let lit = s.as_str();
            quote! {
                ::iec61850_scl::__rt::MmsValue::VisibleString(::std::string::String::from(#lit))
            }
        }
        MmsValue::MmsString(s) => {
            let lit = s.as_str();
            quote! {
                ::iec61850_scl::__rt::MmsValue::MmsString(::std::string::String::from(#lit))
            }
        }
        MmsValue::UtcTime(b8) => {
            let bytes = b8.to_vec();
            quote! {
                ::iec61850_scl::__rt::MmsValue::UtcTime([
                    #( #bytes ),*
                ])
            }
        }
        MmsValue::BinaryTime(bytes) => {
            let bs: Vec<u8> = bytes.clone();
            quote! {
                ::iec61850_scl::__rt::MmsValue::BinaryTime(::std::vec![ #( #bs ),* ])
            }
        }
        // Array and Structure do not arise from a DAI override, because
        // `parse_val_for_b_type` returns only leaf values. The branches are kept
        // so a future extension has somewhere to land.
        MmsValue::Array(items) => {
            let inner = items.iter().map(emit_mms_value);
            quote! {
                ::iec61850_scl::__rt::MmsValue::Array(::std::vec![ #( #inner ),* ])
            }
        }
        MmsValue::Structure(items) => {
            let inner = items.iter().map(emit_mms_value);
            quote! {
                ::iec61850_scl::__rt::MmsValue::Structure(::std::vec![ #( #inner ),* ])
            }
        }
    }
}
