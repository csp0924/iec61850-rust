//! Stage 2: the type-resolved SCL.
//!
//! Resolves every type identifier that [`crate::raw::RawScl`] left as a
//! string: a logical node's `ln_type_ref` to its [`crate::raw::RawLNodeType`],
//! a data object's `do_type_ref` to its [`crate::raw::RawDoType`], and a data
//! attribute's `type_ref` to a [`crate::raw::RawEnumType`] when its bType is
//! Enum or to a [`crate::raw::RawDaType`] when it is Struct, descending
//! recursively through the nested attributes.
//!
//! A reference that does not resolve raises
//! [`crate::error::ErrorKind::UnresolvedTypeReference`], naming the kind of
//! type, the identifier, and the element path where the reference occurs.

use std::collections::BTreeMap;

use crate::error::{ErrorKind, SclParseError, TypeKind};
use crate::raw::{RawBda, RawScl};

/// An SCL model whose type references have all been resolved.
///
/// Call [`Self::build_model`] to produce a runtime
/// [`iec61850_model::IedModel`].
#[derive(Debug)]
pub struct ResolvedScl {
    /// The raw AST, kept because `build_model` reads it together with the
    /// index below.
    #[allow(dead_code)]
    pub(crate) raw: RawScl,
    /// The `ln_type_ref` identifiers confirmed to exist in `ln_node_types`.
    ///
    /// Only existence is recorded here; `build_model` looks the type itself up
    /// in `raw.data_type_templates.ln_node_types`.
    #[allow(dead_code)]
    pub(crate) ln_type_index: BTreeMap<String, ()>,
}

impl ResolvedScl {
    /// Returns the underlying [`RawScl`].
    ///
    /// Intended for the code generation path, which walks the raw tree
    /// directly. Every type reference has been checked by then, so a lookup
    /// there can use `expect`. The runtime path goes through
    /// [`Self::build_model`] and does not need this accessor.
    pub fn raw(&self) -> &RawScl {
        &self.raw
    }

    /// Runs stage 2, resolving every type reference.
    ///
    /// The checks are: a logical node's `ln_type_ref` exists in
    /// `ln_node_types`; a data object's `do_type_ref`, inside an LNodeType,
    /// exists in `do_types`; a sub-object's `do_type_ref`, inside a DOType,
    /// exists in `do_types`; a data attribute's `type_ref` exists in
    /// `enum_types` when its bType is Enum and in `da_types` when it is
    /// Struct; and the same rule recursively for every nested attribute.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::UnresolvedTypeReference`] when a reference does not
    /// resolve; the element path names the full logical node, data object and
    /// data attribute path of the reference, and the span is that of the
    /// referencing element. [`ErrorKind::SemanticConflict`] when structure
    /// references form a cycle.
    pub fn from_raw(raw: RawScl) -> Result<Self, SclParseError> {
        // The four tables are already in raw.data_type_templates, and stage 1
        // has rejected any duplicate identifier.
        let dtt = &raw.data_type_templates;

        // Logical node type references
        for ied in &raw.ieds {
            for ap in &ied.access_points {
                let server = match ap.server.as_ref() {
                    Some(s) => s,
                    None => continue,
                };
                for ld in &server.logical_devices {
                    for ln in &ld.logical_nodes {
                        if !dtt.ln_node_types.contains_key(&ln.ln_type_ref) {
                            let path = format!(
                                "SCL/IED[name=\"{}\"]/AccessPoint[name=\"{}\"]/Server/LDevice[inst=\"{}\"]/LN[lnClass=\"{}\",inst=\"{}\"]",
                                ied.name, ap.name, ld.inst, ln.ln_class, ln.inst
                            );
                            return Err(SclParseError::at(
                                ln.span,
                                path,
                                ErrorKind::UnresolvedTypeReference {
                                    type_kind: TypeKind::LNodeType,
                                    type_id: ln.ln_type_ref.clone(),
                                },
                            )
                            .with_attribute("lnType"));
                        }
                    }
                }
            }
        }

        // Data object type references inside each LNodeType
        for (lnt_id, lnt) in &dtt.ln_node_types {
            for do_def in &lnt.dos {
                if !dtt.do_types.contains_key(&do_def.do_type_ref) {
                    let path = format!(
                        "SCL/DataTypeTemplates/LNodeType[id=\"{}\"]/DO[name=\"{}\"]",
                        lnt_id, do_def.name
                    );
                    return Err(SclParseError::at(
                        do_def.span,
                        path,
                        ErrorKind::UnresolvedTypeReference {
                            type_kind: TypeKind::DOType,
                            type_id: do_def.do_type_ref.clone(),
                        },
                    )
                    .with_attribute("type"));
                }
            }
        }

        // Sub-object and data attribute type references inside each DOType
        for (dot_id, dot) in &dtt.do_types {
            for sdo in &dot.sdos {
                if !dtt.do_types.contains_key(&sdo.do_type_ref) {
                    let path = format!(
                        "SCL/DataTypeTemplates/DOType[id=\"{}\"]/SDO[name=\"{}\"]",
                        dot_id, sdo.name
                    );
                    return Err(SclParseError::at(
                        sdo.span,
                        path,
                        ErrorKind::UnresolvedTypeReference {
                            type_kind: TypeKind::DOType,
                            type_id: sdo.do_type_ref.clone(),
                        },
                    )
                    .with_attribute("type"));
                }
            }
            for da in &dot.das {
                check_attr_type_ref(
                    &da.b_type,
                    da.type_ref.as_deref(),
                    da.span,
                    &format!(
                        "SCL/DataTypeTemplates/DOType[id=\"{}\"]/DA[name=\"{}\"]",
                        dot_id, da.name
                    ),
                    dtt,
                )?;
            }
        }

        // Nested attributes inside each DAType, plus cycle detection.
        //
        // `visited` is a stack of DAType identifiers: one is pushed on entry
        // and popped on the way out, so a reference back into the stack is a
        // cycle and is rejected before the recursion can run away.
        for (dat_id, dat) in &dtt.da_types {
            for bda in &dat.bdas {
                let mut visited: Vec<String> = vec![dat_id.clone()];
                check_bda_recursive(
                    bda,
                    &format!(
                        "SCL/DataTypeTemplates/DAType[id=\"{}\"]/BDA[name=\"{}\"]",
                        dat_id, bda.name
                    ),
                    dtt,
                    &mut visited,
                )?;
            }
        }

        // Every ln_type_ref has been checked above, so the index is the key set.
        let ln_type_index = dtt
            .ln_node_types
            .keys()
            .map(|k| (k.clone(), ()))
            .collect::<BTreeMap<_, _>>();

        Ok(Self { raw, ln_type_index })
    }

    /// Builds the runtime model of one IED from the resolved SCL.
    ///
    /// Walks the IED, its access points, its server, its logical devices and
    /// their logical nodes, expanding each through the type tables, and
    /// produces an [`iec61850_model::IedModel`].
    ///
    /// # Errors
    ///
    /// [`SclParseError`] when the named IED is absent, or when the model
    /// builder rejects the result.
    pub fn build_model(
        &self,
        ied_name: &str,
    ) -> Result<iec61850_model::tree::IedModel, SclParseError> {
        crate::build_model::build_ied_model(&self.raw, ied_name)
    }
}

/// Checks the `type_ref` of a data attribute: it must name an `enum_types`
/// entry when the bType is Enum and a `da_types` entry when it is Struct. Any
/// other bType needs no reference.
fn check_attr_type_ref(
    b_type: &str,
    type_ref: Option<&str>,
    span: crate::error::SourceSpan,
    path: &str,
    dtt: &crate::raw::DataTypeTemplates,
) -> Result<(), SclParseError> {
    match b_type {
        "Enum" => {
            // A bType of Enum requires a type_ref that exists in enum_types.
            let id = match type_ref {
                Some(s) => s,
                None => {
                    return Err(SclParseError::at(
                        span,
                        path,
                        ErrorKind::MissingRequiredAttribute {
                            name: "type".to_string(),
                        },
                    )
                    .with_attribute("type"));
                }
            };
            if !dtt.enum_types.contains_key(id) {
                return Err(SclParseError::at(
                    span,
                    path,
                    ErrorKind::UnresolvedTypeReference {
                        type_kind: TypeKind::EnumType,
                        type_id: id.to_string(),
                    },
                )
                .with_attribute("type"));
            }
        }
        "Struct" => {
            let id = match type_ref {
                Some(s) => s,
                None => {
                    return Err(SclParseError::at(
                        span,
                        path,
                        ErrorKind::MissingRequiredAttribute {
                            name: "type".to_string(),
                        },
                    )
                    .with_attribute("type"));
                }
            };
            if !dtt.da_types.contains_key(id) {
                return Err(SclParseError::at(
                    span,
                    path,
                    ErrorKind::UnresolvedTypeReference {
                        type_kind: TypeKind::DAType,
                        type_id: id.to_string(),
                    },
                )
                .with_attribute("type"));
            }
        }
        _ => { /* any other bType needs no type_ref */ }
    }
    Ok(())
}

/// Recursively checks the `type_ref` of a nested attribute, and detects a cycle
/// between structure types.
///
/// `visited` is a stack of DAType identifiers: one is pushed each time a
/// `bType=Struct` reference is followed, and popped on the way out. A reference
/// to an identifier already on the stack is a cycle and yields
/// [`ErrorKind::SemanticConflict`].
///
/// The recursion follows the same path the model builder takes, so a cycle is
/// caught here and cannot overflow the stack later.
fn check_bda_recursive(
    bda: &RawBda,
    path: &str,
    dtt: &crate::raw::DataTypeTemplates,
    visited: &mut Vec<String>,
) -> Result<(), SclParseError> {
    check_attr_type_ref(&bda.b_type, bda.type_ref.as_deref(), bda.span, path, dtt)?;

    // A bType of Struct follows type_ref into a DAType, exactly as the model
    // builder does, so the cycle check runs before descending.
    if bda.b_type == "Struct" {
        if let Some(type_id) = bda.type_ref.as_deref() {
            if visited.iter().any(|id| id == type_id) {
                let mut cycle = visited.join(" -> ");
                cycle.push_str(" -> ");
                cycle.push_str(type_id);
                return Err(SclParseError::at(
                    bda.span,
                    path,
                    ErrorKind::SemanticConflict {
                        detail: format!("DAType cycle: {cycle}"),
                    },
                ));
            }
            // Stage 2 has already checked that type_ref exists in da_types, so
            // this lookup always succeeds.
            if let Some(dat) = dtt.da_types.get(type_id) {
                visited.push(type_id.to_string());
                for child_bda in &dat.bdas {
                    let child_path = format!("{path}/BDA[name=\"{}\"]", child_bda.name);
                    check_bda_recursive(child_bda, &child_path, dtt, visited)?;
                }
                visited.pop();
            }
        }
    }

    // Fallback for an inline nested attribute; the raw structure normally
    // reaches a DAType through type_ref instead.
    for child in &bda.bda {
        let child_path = format!("{}/BDA[name=\"{}\"]", path, child.name);
        check_bda_recursive(child, &child_path, dtt, visited)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_scl;

    fn must_parse(xml: &str) -> RawScl {
        parse_scl(xml).expect("parse should succeed")
    }

    /// A complete SCL, an IED plus DataTypeTemplates, resolves.
    #[test]
    fn full_scl_resolves_ok() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_Mod"/>
    </LNodeType>
    <DOType id="ENC_Mod" cdc="ENC">
      <DA name="stVal" fc="ST" bType="Enum" type="ModEnum"/>
      <DA name="t" fc="ST" bType="Timestamp"/>
    </DOType>
    <EnumType id="ModEnum">
      <EnumVal ord="1">on</EnumVal>
      <EnumVal ord="2">off</EnumVal>
    </EnumType>
  </DataTypeTemplates>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let raw = must_parse(xml);
        let resolved = ResolvedScl::from_raw(raw).expect("must resolve");
        assert!(resolved.ln_type_index.contains_key("LLN0_T"));
    }

    /// A logical node referencing a missing lnType yields
    /// UnresolvedTypeReference with type_kind LNodeType.
    #[test]
    fn ln_with_missing_ln_type_yields_err() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="OTHER_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC"/>
  </DataTypeTemplates>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="MISSING_T"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let raw = must_parse(xml);
        let err = ResolvedScl::from_raw(raw).expect_err("must err");
        match err.kind.as_ref() {
            ErrorKind::UnresolvedTypeReference { type_kind, type_id } => {
                assert_eq!(*type_kind, TypeKind::LNodeType);
                assert_eq!(type_id, "MISSING_T");
            }
            other => panic!("expected UnresolvedTypeReference, got {:?}", other),
        }
        // The element path must identify the logical node.
        assert!(
            err.element_path.contains("LN[lnClass=\"LLN0\""),
            "the element path must identify the logical node, saw `{}`",
            err.element_path
        );
        assert!(err.element_path.contains("LDevice[inst=\"LD0\"]"));
    }

    /// A data object referencing a missing DOType yields
    /// UnresolvedTypeReference with type_kind DOType.
    #[test]
    fn do_with_missing_do_type_yields_err() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="MISSING_DO_T"/>
    </LNodeType>
  </DataTypeTemplates>
</SCL>"#;
        let raw = must_parse(xml);
        let err = ResolvedScl::from_raw(raw).expect_err("must err");
        match err.kind.as_ref() {
            ErrorKind::UnresolvedTypeReference { type_kind, type_id } => {
                assert_eq!(*type_kind, TypeKind::DOType);
                assert_eq!(type_id, "MISSING_DO_T");
            }
            other => panic!("expected UnresolvedTypeReference, got {:?}", other),
        }
        assert!(err.element_path.contains("LNodeType[id=\"LLN0_T\"]"));
        assert!(err.element_path.contains("DO[name=\"Mod\"]"));
    }

    /// A data attribute with bType Enum referencing a missing EnumType is
    /// rejected.
    #[test]
    fn da_with_missing_enum_type_yields_err() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="Enum" type="MISSING_ENUM"/>
    </DOType>
  </DataTypeTemplates>
</SCL>"#;
        let raw = must_parse(xml);
        let err = ResolvedScl::from_raw(raw).expect_err("must err");
        match err.kind.as_ref() {
            ErrorKind::UnresolvedTypeReference { type_kind, type_id } => {
                assert_eq!(*type_kind, TypeKind::EnumType);
                assert_eq!(type_id, "MISSING_ENUM");
            }
            other => panic!("expected UnresolvedTypeReference, got {:?}", other),
        }
        assert!(err.element_path.contains("DOType[id=\"ENC_T\"]"));
        assert!(err.element_path.contains("DA[name=\"stVal\"]"));
    }

    /// A data attribute with bType Struct referencing a missing DAType is
    /// rejected.
    #[test]
    fn da_with_missing_da_type_yields_err() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <DOType id="CMV_T" cdc="CMV">
      <DA name="cVal" fc="MX" bType="Struct" type="MISSING_DA_T"/>
    </DOType>
  </DataTypeTemplates>
</SCL>"#;
        let raw = must_parse(xml);
        let err = ResolvedScl::from_raw(raw).expect_err("must err");
        match err.kind.as_ref() {
            ErrorKind::UnresolvedTypeReference { type_kind, type_id } => {
                assert_eq!(*type_kind, TypeKind::DAType);
                assert_eq!(type_id, "MISSING_DA_T");
            }
            other => panic!("expected UnresolvedTypeReference, got {:?}", other),
        }
    }

    /// A type reference nested inside a nested attribute resolves as well.
    #[test]
    fn bda_nested_type_ref_resolves_ok() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <DAType id="OuterT">
      <BDA name="inner" bType="Struct" type="InnerT"/>
    </DAType>
    <DAType id="InnerT">
      <BDA name="leaf" bType="INT32"/>
    </DAType>
  </DataTypeTemplates>
</SCL>"#;
        let raw = must_parse(xml);
        ResolvedScl::from_raw(raw).expect("nested struct should resolve");
    }

    /// A nested attribute with bType Struct and no type attribute is rejected
    /// at once rather than ignored.
    #[test]
    fn bda_struct_missing_type_yields_err() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <DAType id="OuterT">
      <BDA name="inner" bType="Struct"/>
    </DAType>
  </DataTypeTemplates>
</SCL>"#;
        let raw = must_parse(xml);
        let err = ResolvedScl::from_raw(raw).expect_err("must err");
        match err.kind.as_ref() {
            ErrorKind::MissingRequiredAttribute { name } => assert_eq!(name, "type"),
            other => panic!("expected MissingRequiredAttribute, got {:?}", other),
        }
    }

    /// `ResolvedScl::build_model` is a dispatcher; the minimal success path is
    /// covered in `crate::build_model::tests`.
    #[test]
    fn build_model_happy_minimal() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="BOOLEAN"/>
    </DOType>
  </DataTypeTemplates>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0"><LN0 inst="" lnType="LLN0_T"/></LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let raw = must_parse(xml);
        let resolved = ResolvedScl::from_raw(raw).expect("resolve ok");
        let model = resolved.build_model("IED1").expect("build_model");
        assert_eq!(model.ied_name, "IED1");
        assert!(model.ld_by_inst("LD0").is_some());
    }

    /// A DAType referencing itself yields SemanticConflict instead of
    /// overflowing the stack.
    #[test]
    fn datype_self_cycle_returns_semantic_conflict() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <DAType id="A">
      <BDA name="self_ref" bType="Struct" type="A"/>
    </DAType>
  </DataTypeTemplates>
</SCL>"#;
        let raw = must_parse(xml);
        let err = ResolvedScl::from_raw(raw).expect_err("self-cycle should error");
        let detail = match err.kind.as_ref() {
            ErrorKind::SemanticConflict { detail } => detail.clone(),
            other => panic!("expected SemanticConflict, got {other:?}"),
        };
        assert!(
            detail.starts_with("DAType cycle:"),
            "detail prefix wrong: {detail}"
        );
        assert!(detail.contains('A'), "cycle path missing A: {detail}");
    }

    /// An indirect cycle, A to B to A, yields SemanticConflict carrying the
    /// full path.
    #[test]
    fn datype_indirect_cycle_returns_semantic_conflict() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <DAType id="A">
      <BDA name="to_b" bType="Struct" type="B"/>
    </DAType>
    <DAType id="B">
      <BDA name="to_a" bType="Struct" type="A"/>
    </DAType>
  </DataTypeTemplates>
</SCL>"#;
        let raw = must_parse(xml);
        let err = ResolvedScl::from_raw(raw).expect_err("A -> B -> A must be rejected");
        let detail = match err.kind.as_ref() {
            ErrorKind::SemanticConflict { detail } => detail.clone(),
            other => panic!("expected SemanticConflict, got {other:?}"),
        };
        assert!(
            detail.starts_with("DAType cycle:"),
            "detail prefix wrong: {detail}"
        );
        assert!(
            detail.contains('A') && detail.contains('B'),
            "cycle path missing A/B: {detail}"
        );
    }

    /// A legitimate nested DAType with no cycle still resolves.
    #[test]
    fn datype_legitimate_nesting_resolves_ok() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <DAType id="Outer">
      <BDA name="inner" bType="Struct" type="Inner"/>
    </DAType>
    <DAType id="Inner">
      <BDA name="leaf" bType="BOOLEAN"/>
    </DAType>
  </DataTypeTemplates>
</SCL>"#;
        let raw = must_parse(xml);
        ResolvedScl::from_raw(raw).expect("legitimate nested DAType should resolve");
    }
}
