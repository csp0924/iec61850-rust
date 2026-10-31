//! Build-script helper that turns an `.icd`, `.cid` or `.scd` file into Rust
//! code at compile time.
//!
//! The generated file lands in `OUT_DIR/model.rs`, and the user crate pulls it
//! in with `iec61850_scl::include_compiled_model!()`.
//!
//! In the user crate's `build.rs`:
//!
//! ```ignore
//! fn main() {
//!     iec61850_scl_build::compile_icd("config/MyIED.icd")
//!         .out_file("model.rs")
//!         .compile()
//!         .unwrap();
//! }
//! ```
//!
//! In the user crate's source:
//!
//! ```ignore
//! iec61850_scl::include_compiled_model!();
//!
//! fn main() {
//!     let model = build_MyIED_model();
//!     // start a server with it
//! }
//! ```
//!
//! The emit layer turns values into tokens and re-derives no semantics: every
//! `b_type` lookup, functional-constraint parse and trigger-option composition
//! calls the same helper the runtime path uses, through
//! `iec61850_scl::__build_internals`, and only the helper's return value is
//! serialized into a `TokenStream`. A generated model therefore cannot
//! disagree with a model built at run time.
//!
//! Before the file is written, every IED it covers is also built through
//! `ResolvedScl::build_model`, the run-time path. An SCL file that path rejects
//! fails the build script with [`CompileError::ResolveScl`] instead of
//! producing a `build_<X>_model` that panics when called.
//!
//! Layering: [`emit`] walks the `RawScl` tree and emits each level as `quote!`
//! tokens; [`tokens`] holds the shared to-tokens helpers for functional
//! constraints, trigger options, data attribute types and default values; this
//! file is the public API, [`CompileBuilder`] and [`compile_icd`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;

pub mod emit;
pub mod tokens;

/// Starts a code generation build.
///
/// The returned [`CompileBuilder`] takes the output file name, the IED name and
/// the determinism flag through a fluent API; `compile` then parses, emits and
/// writes the result into `OUT_DIR`.
pub fn compile_icd<P: AsRef<Path>>(path: P) -> CompileBuilder {
    CompileBuilder {
        input_path: path.as_ref().to_path_buf(),
        out_file: "model.rs".to_string(),
        ied_name: None,
        deterministic: true,
    }
}

/// Settings for one code generation build.
#[derive(Debug, Clone)]
pub struct CompileBuilder {
    input_path: PathBuf,
    out_file: String,
    ied_name: Option<String>,
    deterministic: bool,
}

impl CompileBuilder {
    /// Sets the output file name inside `OUT_DIR`. Defaults to `model.rs`.
    pub fn out_file(mut self, name: impl Into<String>) -> Self {
        self.out_file = name.into();
        self
    }

    /// Selects which IED of a multi-IED `.scd` to generate a function for. It
    /// can be omitted when the file holds a single IED.
    pub fn ied_name(mut self, name: impl Into<String>) -> Self {
        self.ied_name = Some(name.into());
        self
    }

    /// Sorts the raw tree before emitting, so repeated builds produce a
    /// byte-for-byte identical `model.rs` and cargo's incremental cache stays
    /// warm. Defaults to `true`.
    pub fn deterministic(mut self, yes: bool) -> Self {
        self.deterministic = yes;
        self
    }

    /// Runs the build: reads the input, parses and resolves the SCL, emits the
    /// tokens, builds the run-time model of every IED the file covers, formats
    /// the tokens and writes `OUT_DIR/<out_file>`.
    ///
    /// Also prints `cargo:rerun-if-changed=<input_path>`.
    ///
    /// # Errors
    ///
    /// See [`CompileError`]; every stage reports its own variant. A model the
    /// run-time path rejects is reported as [`CompileError::ResolveScl`], and
    /// nothing is written.
    pub fn compile(self) -> Result<(), CompileError> {
        // Cargo reads the rerun trigger from the build script's stdout.
        println!("cargo:rerun-if-changed={}", self.input_path.display());

        let xml = fs::read_to_string(&self.input_path).map_err(|e| CompileError::ReadInput {
            path: self.input_path.clone(),
            source: e,
        })?;

        let pretty = self.generate(&xml)?;

        let out_dir = std::env::var_os("OUT_DIR").ok_or(CompileError::OutDirMissing)?;
        let out_path = PathBuf::from(out_dir).join(&self.out_file);
        fs::write(&out_path, pretty).map_err(|e| CompileError::WriteOut {
            path: out_path,
            source: e,
        })?;

        Ok(())
    }

    /// Parses, resolves and emits `xml`, checks every emitted IED against the
    /// run-time model build, and returns the formatted source.
    fn generate(&self, xml: &str) -> Result<String, CompileError> {
        let raw = iec61850_scl::parse_scl(xml).map_err(CompileError::ParseScl)?;
        let resolved = raw.resolve().map_err(CompileError::ResolveScl)?;

        let tokens = emit::emit_file(&resolved, self)?;

        // The emitted functions call the model builders with `expect`; running
        // the same builders here turns each such failure into a build error.
        for ied in &resolved.raw().ieds {
            if self
                .requested_ied_name()
                .is_some_and(|name| name != ied.name)
            {
                continue;
            }
            resolved
                .build_model(&ied.name)
                .map_err(CompileError::ResolveScl)?;
        }

        // Formatting keeps a panic inside the generated code readable.
        let file: syn::File = syn::parse2(tokens).map_err(|e| CompileError::Syn {
            detail: e.to_string(),
        })?;
        Ok(prettyplease::unparse(&file))
    }

    /// The IED name the caller selected, if any.
    pub(crate) fn requested_ied_name(&self) -> Option<&str> {
        self.ied_name.as_deref()
    }

    /// Whether the emitted tree is sorted for reproducibility.
    pub(crate) fn is_deterministic(&self) -> bool {
        self.deterministic
    }
}

/// An error raised by code generation.
#[derive(Debug, Error)]
pub enum CompileError {
    /// The input SCL file could not be read.
    #[error("failed to read the input SCL `{path}`: {source}")]
    ReadInput {
        /// Path that was opened.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The XML and element stage of parsing failed.
    #[error("failed to parse the SCL: {0}")]
    ParseScl(iec61850_scl::SclParseError),

    /// Type reference resolution or a cross-element consistency check failed,
    /// or the run-time model build rejected an IED the file covers.
    #[error("failed to resolve the SCL: {0}")]
    ResolveScl(iec61850_scl::SclParseError),

    /// The emit stage found a semantic problem, such as several IEDs with no
    /// `ied_name` selected.
    #[error("code generation failed: {0}")]
    Emit(String),

    /// The emitted `TokenStream` is not a valid Rust file, which means a defect
    /// in this crate.
    #[error("the emitted TokenStream is not a valid Rust file: {detail}")]
    Syn {
        /// Text of the `syn::Error`.
        detail: String,
    },

    /// `OUT_DIR` is unset, so this is not running inside a cargo build script.
    #[error("OUT_DIR is not set; this helper only runs from a build script")]
    OutDirMissing,

    /// The generated file could not be written.
    #[error("failed to write the generated file `{path}`: {source}")]
    WriteOut {
        /// Path that was written to.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEMPLATES: &str = r#"
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <LNodeType id="MMXU_T" lnClass="MMXU">
      <DO name="TotW" type="MV_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="Enum" type="ModEnum" dchg="true"/>
      <DA name="q" fc="ST" bType="Quality" qchg="true"/>
      <DA name="t" fc="ST" bType="Timestamp"/>
    </DOType>
    <DOType id="MV_T" cdc="MV">
      <DA name="mag" fc="MX" bType="Struct" type="AV_T" dchg="true"/>
    </DOType>
    <DAType id="AV_T">
      <BDA name="f" bType="FLOAT32"/>
    </DAType>
    <EnumType id="ModEnum">
      <EnumVal ord="1">on</EnumVal>
    </EnumType>
  </DataTypeTemplates>"#;

    /// One IED whose LLN0 holds a data set naming `do_name` of MMXU1.
    fn ied(name: &str, do_name: &str) -> String {
        format!(
            r#"
  <IED name="{name}">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T">
            <DataSet name="ds1">
              <FCDA ldInst="LD0" lnClass="MMXU" lnInst="1" doName="{do_name}" fc="MX"/>
            </DataSet>
          </LN0>
          <LN lnClass="MMXU" inst="1" lnType="MMXU_T"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>"#
        )
    }

    fn scl(ieds: &[String]) -> String {
        format!("<SCL>{}{}\n</SCL>", ieds.concat(), TEMPLATES)
    }

    #[test]
    fn valid_model_generates() {
        let pretty = compile_icd("unused.icd")
            .generate(&scl(&[ied("IED1", "TotW")]))
            .expect("a model the run-time path accepts must generate");
        assert!(pretty.contains("build_IED1_model"), "{pretty}");
    }

    #[test]
    fn model_rejected_at_run_time_fails_the_build() {
        let err = compile_icd("unused.icd")
            .generate(&scl(&[ied("IED1", "Missing")]))
            .expect_err("a data set member the model lacks must fail the build");
        assert!(matches!(err, CompileError::ResolveScl(_)), "{err:?}");
    }

    #[test]
    fn every_ied_is_checked_when_none_is_selected() {
        let err = compile_icd("unused.icd")
            .generate(&scl(&[ied("Good", "TotW"), ied("Bad", "Missing")]))
            .expect_err("an IED that would panic must fail the build");
        assert!(matches!(err, CompileError::ResolveScl(_)), "{err:?}");
    }

    #[test]
    fn only_the_selected_ied_is_checked() {
        let pretty = compile_icd("unused.icd")
            .ied_name("Good")
            .generate(&scl(&[ied("Good", "TotW"), ied("Bad", "Missing")]))
            .expect("an IED that is not generated is not checked");
        assert!(pretty.contains("build_Good_model"), "{pretty}");
        assert!(!pretty.contains("build_Bad_model"), "{pretty}");
    }

    #[test]
    fn missing_selected_ied_stays_an_emit_error() {
        let err = compile_icd("unused.icd")
            .ied_name("Absent")
            .generate(&scl(&[ied("IED1", "TotW")]))
            .expect_err("an absent IED must fail the build");
        assert!(matches!(err, CompileError::Emit(_)), "{err:?}");
    }
}
