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

use crate::build_model::{derives_setting_view, doi_children, instance_children};
use crate::error::{ErrorKind, SclParseError, SourceSpan, TypeKind};
use crate::raw::{
    DataTypeTemplates, RawBda, RawCount, RawDataInstance, RawDoTypeChild, RawLogicalNode, RawScl,
};

/// The default of [`ResolveOptions::max_expanded_nodes`].
pub const DEFAULT_MAX_EXPANDED_NODES: u64 = 1_000_000;

/// Limits that stage 2 applies.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolveOptions {
    /// The most model nodes, logical nodes, data objects and data attributes
    /// at every nesting level, that one IED, or one type of the
    /// DataTypeTemplates, may expand to. Array elements count, and so does
    /// the FC=SG view the model builder derives from an FC=SE attribute.
    ///
    /// A type referenced several times is expanded once per reference, so a
    /// few hundred lines of nested types can describe an exponential number of
    /// nodes; the limit turns such a file into an error instead of time and
    /// memory spent on the model build. Defaults to
    /// [`DEFAULT_MAX_EXPANDED_NODES`].
    pub max_expanded_nodes: u64,
}

impl Default for ResolveOptions {
    fn default() -> Self {
        Self {
            max_expanded_nodes: DEFAULT_MAX_EXPANDED_NODES,
        }
    }
}

/// An SCL model whose type references have all been resolved.
///
/// Call [`Self::build_model`] to produce a runtime
/// [`iec61850_model::IedModel`].
#[derive(Debug)]
pub struct ResolvedScl {
    /// The raw AST, whose every `lnType` reference is confirmed to exist in
    /// `data_type_templates.ln_node_types`; `build_model` reads it.
    pub(crate) raw: RawScl,
    /// The node limit stage 2 applied, which the model builder applies to an
    /// array whose element count an instance gives.
    pub(crate) max_expanded_nodes: u64,
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

    /// Runs stage 2 with the default [`ResolveOptions`]; see
    /// [`from_raw_with`](Self::from_raw_with).
    ///
    /// # Errors
    ///
    /// As [`from_raw_with`](Self::from_raw_with).
    pub fn from_raw(raw: RawScl) -> Result<Self, SclParseError> {
        Self::from_raw_with(raw, &ResolveOptions::default())
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
    /// A `count` naming an attribute is replaced by the element count that
    /// attribute declares: IEC 61850-6 §9.5.4.1 Table 47 requires it in the
    /// same type definition, a `<DA>` of the DOType for a `<DA>` or an
    /// `<SDO>`, a `<BDA>` of the DAType for a `<BDA>`, and its `<Val>` gives
    /// the count. When the type gives that attribute no `<Val>`, the count is
    /// left naming it, and the model builder takes it from each instance.
    ///
    /// The `datSet` of every report, log, GOOSE and sampled value control
    /// block names a `<DataSet>` of its own logical node, as the keys of the
    /// SCL schema require (IEC 61850-6 Annex A.4); an absent or empty
    /// `datSet` names none.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::UnresolvedTypeReference`] when a reference does not
    /// resolve; the element path names the full logical node, data object and
    /// data attribute path of the reference, and the span is that of the
    /// referencing element. [`ErrorKind::UnresolvedDataSetReference`] when a
    /// control block names a data set its logical node does not declare, at
    /// the control block. [`ErrorKind::SemanticConflict`] when structure or
    /// sub-object references form a cycle, nest deeper than 32 levels, or
    /// expand an IED or a type to more than
    /// [`ResolveOptions::max_expanded_nodes`] nodes, array elements and
    /// derived FC=SG views included, when a `count` names no attribute of an
    /// integer bType in the same type definition, or when the `<Val>` of that
    /// attribute is not a count.
    pub fn from_raw_with(raw: RawScl, options: &ResolveOptions) -> Result<Self, SclParseError> {
        let mut raw = raw;
        resolve_counts(&mut raw.data_type_templates)?;
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
            for sdo in dot.sdos() {
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
            for da in dot.das() {
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

        // Sub-object chains between DOTypes must be acyclic: the model builder
        // expands a sub-object by recursing into its DOType.
        check_do_type_cycles(dtt)?;

        // Nested attributes inside each DAType, plus cycle detection.
        //
        // `visited` is a stack of DAType identifiers: one is pushed on entry
        // and popped on the way out, so a reference back into the stack is a
        // cycle and is rejected before the recursion can run away. `heights`
        // records each DAType checked in full, so a shared type is walked once.
        let mut heights: BTreeMap<String, usize> = BTreeMap::new();
        for (dat_id, dat) in &dtt.da_types {
            if heights.contains_key(dat_id) {
                continue;
            }
            let mut visited: Vec<String> = vec![dat_id.clone()];
            let mut below = 0;
            for bda in &dat.bdas {
                below = below.max(check_bda_recursive(
                    bda,
                    &format!(
                        "SCL/DataTypeTemplates/DAType[id=\"{}\"]/BDA[name=\"{}\"]",
                        dat_id, bda.name
                    ),
                    dtt,
                    &mut visited,
                    &mut heights,
                )?);
            }
            heights.insert(dat_id.clone(), below + 1);
        }

        // With every chain acyclic and bounded, the expansion sizes are finite.
        check_expanded_nodes(&raw, options.max_expanded_nodes)?;
        check_data_set_references(&raw)?;

        Ok(Self {
            raw,
            max_expanded_nodes: options.max_expanded_nodes,
        })
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
        crate::build_model::build_ied_model(&self.raw, ied_name, self.max_expanded_nodes)
    }
}

/// The bTypes whose value can give an element count.
const INTEGER_B_TYPES: &[&str] = &[
    "INT8", "INT16", "INT24", "INT32", "INT64", "INT128", "INT8U", "INT16U", "INT24U", "INT32U",
];

/// Replaces every `count` that names an attribute by the element count that
/// attribute declares in the same type definition; a count naming an
/// attribute that declares no `<Val>` is left for the instance to give.
///
/// # Errors
///
/// [`ErrorKind::SemanticConflict`] when the named attribute does not exist,
/// is not of an integer bType, or its value is not a count.
fn resolve_counts(dtt: &mut DataTypeTemplates) -> Result<(), SclParseError> {
    for (dot_id, dot) in dtt.do_types.iter_mut() {
        let mut resolved = Vec::new();
        for (i, child) in dot.children.iter().enumerate() {
            let (kind, name, count, span) = match child {
                RawDoTypeChild::Da(da) => ("DA", &da.name, &da.count, da.span),
                RawDoTypeChild::Sdo(sdo) => ("SDO", &sdo.name, &sdo.count, sdo.span),
            };
            let Some(RawCount::Attribute(attr)) = count else {
                continue;
            };
            let path =
                format!("SCL/DataTypeTemplates/DOType[id=\"{dot_id}\"]/{kind}[name=\"{name}\"]");
            let target = dot
                .das()
                .find(|d| &d.name == attr)
                .map(|d| (d.b_type.as_str(), d.default_value.as_deref()));
            if let Some(n) = count_value(attr, target, span, &path)? {
                resolved.push((i, n));
            }
        }
        for (i, n) in resolved {
            match dot.children.get_mut(i) {
                Some(RawDoTypeChild::Da(da)) => da.count = Some(RawCount::Elements(n)),
                Some(RawDoTypeChild::Sdo(sdo)) => sdo.count = Some(RawCount::Elements(n)),
                None => {}
            }
        }
        for child in dot.children.iter_mut() {
            if let RawDoTypeChild::Da(da) = child {
                let path = format!(
                    "SCL/DataTypeTemplates/DOType[id=\"{dot_id}\"]/DA[name=\"{}\"]",
                    da.name
                );
                resolve_bda_counts(&mut da.bda, &path)?;
            }
        }
    }
    for (dat_id, dat) in dtt.da_types.iter_mut() {
        resolve_bda_counts(
            &mut dat.bdas,
            &format!("SCL/DataTypeTemplates/DAType[id=\"{dat_id}\"]"),
        )?;
    }
    Ok(())
}

/// Resolves the `count` references among the sibling attributes `bdas`, and
/// recursively among the inline attributes nested in each.
fn resolve_bda_counts(bdas: &mut [RawBda], parent_path: &str) -> Result<(), SclParseError> {
    let mut resolved = Vec::new();
    for (i, bda) in bdas.iter().enumerate() {
        let Some(RawCount::Attribute(attr)) = &bda.count else {
            continue;
        };
        let path = format!("{parent_path}/BDA[name=\"{}\"]", bda.name);
        let target = bdas
            .iter()
            .find(|b| &b.name == attr)
            .map(|b| (b.b_type.as_str(), b.default_value.as_deref()));
        if let Some(n) = count_value(attr, target, bda.span, &path)? {
            resolved.push((i, n));
        }
    }
    for (i, n) in resolved {
        if let Some(bda) = bdas.get_mut(i) {
            bda.count = Some(RawCount::Elements(n));
        }
    }
    for bda in bdas.iter_mut() {
        let path = format!("{parent_path}/BDA[name=\"{}\"]", bda.name);
        resolve_bda_counts(&mut bda.bda, &path)?;
    }
    Ok(())
}

/// Reads the element count a `count` naming `attr` refers to, from `target`,
/// the bType and `<Val>` of the attribute of that name, if there is one;
/// `None` when the attribute declares no `<Val>`.
fn count_value(
    attr: &str,
    target: Option<(&str, Option<&str>)>,
    span: SourceSpan,
    path: &str,
) -> Result<Option<u32>, SclParseError> {
    let conflict = |detail: String| {
        SclParseError::at(span, path, ErrorKind::SemanticConflict { detail })
            .with_attribute("count")
    };
    let Some((b_type, value)) = target else {
        return Err(conflict(format!(
            "count names `{attr}`, which the same type definition does not declare"
        )));
    };
    if !INTEGER_B_TYPES.contains(&b_type) {
        return Err(conflict(format!(
            "count names `{attr}`, whose bType {b_type} is not an integer"
        )));
    }
    let Some(text) = value else {
        return Ok(None);
    };
    text.parse::<u32>().map(Some).map_err(|e| {
        conflict(format!(
            "count names `{attr}`, whose value `{text}` is not an element count: {e}"
        ))
    })
}

/// The deepest nesting of DOTypes through `<SDO>`, and of DATypes through
/// `<BDA>`, that stage 2 accepts. The model builder expands both by
/// recursion, so the bound keeps a deep but acyclic chain from exhausting the
/// stack.
pub(crate) const MAX_TYPE_NESTING: usize = 32;

/// Rejects a cycle among DOTypes formed by their `<SDO>` references, and a
/// chain of them deeper than [`MAX_TYPE_NESTING`].
///
/// Runs a depth-first walk over the sub-object graph, visiting each DOType
/// once. A reference back to a DOType still on the walk stack is a cycle and
/// yields [`ErrorKind::SemanticConflict`] naming the chain, at the span of the
/// `<SDO>` that closes it; a DOType whose sub-object chain is too deep yields
/// the same kind at its own span. Every `do_type_ref` must already be known to
/// exist.
fn check_do_type_cycles(dtt: &crate::raw::DataTypeTemplates) -> Result<(), SclParseError> {
    // The number of DOType levels from each finished DOType down to its
    // deepest sub-object, itself included.
    let mut height: BTreeMap<&str, usize> = BTreeMap::new();
    let too_deep = |id: &str, span| {
        SclParseError::at(
            span,
            format!("SCL/DataTypeTemplates/DOType[id=\"{id}\"]"),
            ErrorKind::SemanticConflict {
                detail: format!(
                    "the sub-object chain below DOType `{id}` is deeper than {MAX_TYPE_NESTING} levels"
                ),
            },
        )
    };
    for root in dtt.do_types.keys() {
        if height.contains_key(root.as_str()) {
            continue;
        }
        // Each frame is a DOType identifier and the index of its next SDO to visit.
        let mut stack: Vec<(&str, usize)> = vec![(root.as_str(), 0)];
        while let Some(top) = stack.last_mut() {
            let (id, index) = *top;
            top.1 += 1;
            let Some(dot) = dtt.do_types.get(id) else {
                stack.pop();
                continue;
            };
            let Some(sdo) = dot.sdos().nth(index) else {
                let below = dot
                    .sdos()
                    .filter_map(|s| height.get(s.do_type_ref.as_str()))
                    .max()
                    .copied()
                    .unwrap_or(0);
                if below + 1 > MAX_TYPE_NESTING {
                    return Err(too_deep(id, dot.span));
                }
                height.insert(id, below + 1);
                stack.pop();
                continue;
            };
            let target = sdo.do_type_ref.as_str();
            if stack.iter().any(|(on_stack, _)| *on_stack == target) {
                let mut cycle: Vec<&str> = stack.iter().map(|(s, _)| *s).collect();
                cycle.push(target);
                return Err(SclParseError::at(
                    sdo.span,
                    format!(
                        "SCL/DataTypeTemplates/DOType[id=\"{}\"]/SDO[name=\"{}\"]",
                        id, sdo.name
                    ),
                    ErrorKind::SemanticConflict {
                        detail: format!("DOType cycle: {}", cycle.join(" -> ")),
                    },
                )
                .with_attribute("type"));
            }
            if !height.contains_key(target) && dtt.do_types.contains_key(target) {
                if stack.len() >= MAX_TYPE_NESTING {
                    let root_id = stack.first().map_or(id, |frame| frame.0);
                    return Err(too_deep(root_id, sdo.span));
                }
                stack.push((target, 0));
            }
        }
    }
    Ok(())
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
/// between structure types. Returns the number of DAType levels below the
/// attribute.
///
/// `visited` is a stack of DAType identifiers: one is pushed each time a
/// `bType=Struct` reference is followed, and popped on the way out. A reference
/// to an identifier already on the stack is a cycle, and a chain longer than
/// [`MAX_TYPE_NESTING`] is too deep; either yields
/// [`ErrorKind::SemanticConflict`]. `heights` holds the level count of every
/// DAType already checked in full, so a type reached again is not walked
/// again.
///
/// The recursion follows the same path the model builder takes, so a cycle or
/// a runaway nesting is caught here, within the bound, and cannot overflow the
/// stack later.
fn check_bda_recursive(
    bda: &RawBda,
    path: &str,
    dtt: &DataTypeTemplates,
    visited: &mut Vec<String>,
    heights: &mut BTreeMap<String, usize>,
) -> Result<usize, SclParseError> {
    check_attr_type_ref(&bda.b_type, bda.type_ref.as_deref(), bda.span, path, dtt)?;

    let too_deep = |type_id: &str, visited: &[String]| {
        SclParseError::at(
            bda.span,
            path,
            ErrorKind::SemanticConflict {
                detail: format!(
                    "the DAType nesting below `{}` is deeper than {MAX_TYPE_NESTING} levels",
                    visited.first().map_or(type_id, |s| s.as_str())
                ),
            },
        )
    };

    let mut below = 0;
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
            if let Some(&height) = heights.get(type_id) {
                if visited.len() + height > MAX_TYPE_NESTING {
                    return Err(too_deep(type_id, visited));
                }
                below = height;
            } else {
                if visited.len() >= MAX_TYPE_NESTING {
                    return Err(too_deep(type_id, visited));
                }
                // Stage 2 has already checked that type_ref exists in
                // da_types, so this lookup always succeeds.
                if let Some(dat) = dtt.da_types.get(type_id) {
                    visited.push(type_id.to_string());
                    let mut deepest = 0;
                    for child_bda in &dat.bdas {
                        let child_path = format!("{path}/BDA[name=\"{}\"]", child_bda.name);
                        deepest = deepest.max(check_bda_recursive(
                            child_bda,
                            &child_path,
                            dtt,
                            visited,
                            heights,
                        )?);
                    }
                    visited.pop();
                    heights.insert(type_id.to_string(), deepest + 1);
                    below = deepest + 1;
                }
            }
        }
    }

    // Fallback for an inline nested attribute; the raw structure normally
    // reaches a DAType through type_ref instead.
    for child in &bda.bda {
        let child_path = format!("{}/BDA[name=\"{}\"]", path, child.name);
        below = below.max(check_bda_recursive(
            child,
            &child_path,
            dtt,
            visited,
            heights,
        )?);
    }
    Ok(below)
}

/// Rejects a control block whose `datSet` names no `<DataSet>` of its own
/// logical node. The SCL schema keys the data sets of a logical node by name
/// and makes the `datSet` of each report, log, GOOSE and sampled value
/// control block in it refer to one of them (IEC 61850-6 Annex A.4,
/// `DataSetKeyLN0`, `DataSetKeyInLN`). An absent or empty `datSet` names no
/// data set and is accepted.
fn check_data_set_references(raw: &RawScl) -> Result<(), SclParseError> {
    for ied in &raw.ieds {
        for ap in &ied.access_points {
            let Some(server) = ap.server.as_ref() else {
                continue;
            };
            for ld in &server.logical_devices {
                for ln in &ld.logical_nodes {
                    let blocks =
                        ln.report_controls
                            .iter()
                            .map(|b| ("ReportControl", &b.name, b.dat_set.as_deref(), b.span))
                            .chain(
                                ln.log_controls.iter().map(|b| {
                                    ("LogControl", &b.name, b.data_set.as_deref(), b.span)
                                }),
                            )
                            .chain(ln.gse_controls.iter().map(|b| {
                                ("GSEControl", &b.name, Some(b.data_set.as_str()), b.span)
                            }))
                            .chain(ln.smv_controls.iter().map(|b| {
                                (
                                    "SampledValueControl",
                                    &b.name,
                                    Some(b.data_set.as_str()),
                                    b.span,
                                )
                            }));
                    for (element, name, data_set, span) in blocks {
                        let Some(data_set) = data_set.filter(|d| !d.is_empty()) else {
                            continue;
                        };
                        if ln.data_sets.iter().any(|ds| ds.name == data_set) {
                            continue;
                        }
                        let path = format!(
                            "SCL/IED[name=\"{}\"]/AccessPoint[name=\"{}\"]/Server/LDevice[inst=\"{}\"]/LN[lnClass=\"{}\",inst=\"{}\"]/{element}[name=\"{name}\"]",
                            ied.name, ap.name, ld.inst, ln.ln_class, ln.inst
                        );
                        return Err(SclParseError::at(
                            span,
                            path,
                            ErrorKind::UnresolvedDataSetReference {
                                data_set: data_set.to_string(),
                            },
                        )
                        .with_attribute("datSet"));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Rejects an IED, or a type of the DataTypeTemplates, whose model expansion
/// holds more than `max` nodes.
///
/// Counts every logical node, data object, sub-object, data attribute and
/// nested attribute the model builder would create, a type being counted once
/// per reference to it, an array once per element, plus once for the array
/// itself, and an FC=SE attribute once more for the FC=SG view derived from
/// it. Each type's count is computed once and shared, so the check is
/// linear in the size of the templates. An IED counts the arrays whose element
/// count its instances give with those counts, read as the model builder
/// reads them; a type alone counts them as scalars. An IED is rejected at the
/// logical node whose nodes take the running total past the limit, with that
/// total. Every chain must already be known to be acyclic.
fn check_expanded_nodes(raw: &RawScl, max: u64) -> Result<(), SclParseError> {
    let dtt = &raw.data_type_templates;
    let mut counts = ExpansionCounts::default();
    let over = |kind: &str, id: &str, count: u64, span: SourceSpan, path: String| {
        SclParseError::at(
            span,
            path,
            ErrorKind::SemanticConflict {
                detail: format!(
                    "{kind} `{id}` expands to {count} model nodes, more than the limit of {max}"
                ),
            },
        )
    };
    for (id, dat) in &dtt.da_types {
        let count = counts.da_type(dtt, id);
        if count > max {
            return Err(over(
                "DAType",
                id,
                count,
                dat.span,
                format!("SCL/DataTypeTemplates/DAType[id=\"{id}\"]"),
            ));
        }
    }
    for (id, dot) in &dtt.do_types {
        let count = counts.do_type(dtt, id);
        if count > max {
            return Err(over(
                "DOType",
                id,
                count,
                dot.span,
                format!("SCL/DataTypeTemplates/DOType[id=\"{id}\"]"),
            ));
        }
    }
    for (id, lnt) in &dtt.ln_node_types {
        let count = counts.ln_node_type(dtt, id);
        if count > max {
            return Err(over(
                "LNodeType",
                id,
                count,
                lnt.span,
                format!("SCL/DataTypeTemplates/LNodeType[id=\"{id}\"]"),
            ));
        }
    }
    for ied in &raw.ieds {
        let mut total: u64 = 0;
        for ap in &ied.access_points {
            let Some(server) = ap.server.as_ref() else {
                continue;
            };
            for ld in &server.logical_devices {
                for ln in &ld.logical_nodes {
                    let ln_count = 1u64.saturating_add(counts.ln_node_type_in(dtt, ln));
                    total = total.saturating_add(ln_count);
                    // The logical nodes after the one that crosses the limit
                    // are not walked, so the walk stays within about twice
                    // the limit whatever the number of logical nodes.
                    if total > max {
                        return Err(SclParseError::at(
                            ied.span,
                            format!("SCL/IED[name=\"{}\"]", ied.name),
                            ErrorKind::SemanticConflict {
                                detail: format!(
                                    "IED `{}` expands to at least {total} model nodes, more than the limit of {max}",
                                    ied.name
                                ),
                            },
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// The number of model nodes each type expands to, computed on demand and
/// remembered.
#[derive(Default)]
struct ExpansionCounts {
    da_types: BTreeMap<String, u64>,
    do_types: BTreeMap<String, u64>,
    ln_node_types: BTreeMap<String, u64>,
    /// Whether a DAType, at any depth, holds a count its instances give.
    instance_da_types: BTreeMap<String, bool>,
    /// Whether a DOType, at any depth, holds a count its instances give.
    instance_do_types: BTreeMap<String, bool>,
}

impl ExpansionCounts {
    /// The node count of a logical node instance, its data objects counted
    /// with the element counts the instance gives.
    fn ln_node_type_in(&mut self, dtt: &DataTypeTemplates, ln: &RawLogicalNode) -> u64 {
        let Some(lnt) = dtt.ln_node_types.get(&ln.ln_type_ref) else {
            return 0;
        };
        lnt.dos.iter().fold(0u64, |n, do_def| {
            let values = doi_children(ln, &do_def.name);
            n.saturating_add(1u64.saturating_add(self.do_type_in(dtt, &do_def.do_type_ref, values)))
        })
    }

    /// The node count of DOType `id` in an instance whose values at its level
    /// are `values`; the memoized type count when the type holds no count its
    /// instances give.
    fn do_type_in(
        &mut self,
        dtt: &DataTypeTemplates,
        id: &str,
        values: Option<&[RawDataInstance]>,
    ) -> u64 {
        if !self.do_type_has_instance_count(dtt, id) {
            return self.do_type(dtt, id);
        }
        let Some(dot) = dtt.do_types.get(id) else {
            return 0;
        };
        let mut n: u64 = 0;
        for child in &dot.children {
            let child_count = match child {
                RawDoTypeChild::Da(da) => {
                    let element = match (da.b_type.as_str(), da.type_ref.as_deref()) {
                        ("Struct", Some(type_id)) => 1u64.saturating_add(self.da_type_in(
                            dtt,
                            type_id,
                            instance_children(values, &da.name),
                        )),
                        _ => 1,
                    };
                    with_setting_view(
                        with_count(element, instance_count(da.count.as_ref(), values)),
                        derives_setting_view(da, dot),
                    )
                }
                RawDoTypeChild::Sdo(sdo) => with_count(
                    1u64.saturating_add(self.do_type_in(
                        dtt,
                        &sdo.do_type_ref,
                        instance_children(values, &sdo.name),
                    )),
                    instance_count(sdo.count.as_ref(), values),
                ),
            };
            n = n.saturating_add(child_count);
        }
        n
    }

    /// The node count of DAType `id` in an instance, as [`Self::do_type_in`].
    fn da_type_in(
        &mut self,
        dtt: &DataTypeTemplates,
        id: &str,
        values: Option<&[RawDataInstance]>,
    ) -> u64 {
        if !self.da_type_has_instance_count(dtt, id) {
            return self.da_type(dtt, id);
        }
        match dtt.da_types.get(id) {
            Some(dat) => dat.bdas.iter().fold(0u64, |acc, bda| {
                acc.saturating_add(self.bda_in(dtt, bda, values))
            }),
            None => 0,
        }
    }

    fn bda_in(
        &mut self,
        dtt: &DataTypeTemplates,
        bda: &RawBda,
        values: Option<&[RawDataInstance]>,
    ) -> u64 {
        let inner = instance_children(values, &bda.name);
        let mut n: u64 = 1;
        if bda.b_type == "Struct" {
            if let Some(id) = bda.type_ref.as_deref() {
                n = n.saturating_add(self.da_type_in(dtt, id, inner));
            }
        }
        for child in &bda.bda {
            n = n.saturating_add(self.bda_in(dtt, child, inner));
        }
        with_count(n, instance_count(bda.count.as_ref(), values))
    }

    fn do_type_has_instance_count(&mut self, dtt: &DataTypeTemplates, id: &str) -> bool {
        if let Some(&b) = self.instance_do_types.get(id) {
            return b;
        }
        let mut found = false;
        if let Some(dot) = dtt.do_types.get(id) {
            for child in &dot.children {
                found |= match child {
                    RawDoTypeChild::Da(da) => {
                        matches!(da.count, Some(RawCount::Attribute(_)))
                            || match (da.b_type.as_str(), da.type_ref.as_deref()) {
                                ("Struct", Some(type_id)) => {
                                    self.da_type_has_instance_count(dtt, type_id)
                                }
                                _ => false,
                            }
                    }
                    RawDoTypeChild::Sdo(sdo) => {
                        matches!(sdo.count, Some(RawCount::Attribute(_)))
                            || self.do_type_has_instance_count(dtt, &sdo.do_type_ref)
                    }
                };
            }
        }
        self.instance_do_types.insert(id.to_string(), found);
        found
    }

    fn da_type_has_instance_count(&mut self, dtt: &DataTypeTemplates, id: &str) -> bool {
        if let Some(&b) = self.instance_da_types.get(id) {
            return b;
        }
        let found = match dtt.da_types.get(id) {
            Some(dat) => dat
                .bdas
                .iter()
                .any(|bda| self.bda_has_instance_count(dtt, bda)),
            None => false,
        };
        self.instance_da_types.insert(id.to_string(), found);
        found
    }

    fn bda_has_instance_count(&mut self, dtt: &DataTypeTemplates, bda: &RawBda) -> bool {
        matches!(bda.count, Some(RawCount::Attribute(_)))
            || (bda.b_type == "Struct"
                && bda
                    .type_ref
                    .as_deref()
                    .is_some_and(|id| self.da_type_has_instance_count(dtt, id)))
            || bda.bda.iter().any(|c| self.bda_has_instance_count(dtt, c))
    }

    fn da_type(&mut self, dtt: &DataTypeTemplates, id: &str) -> u64 {
        if let Some(&n) = self.da_types.get(id) {
            return n;
        }
        let n = match dtt.da_types.get(id) {
            Some(dat) => dat
                .bdas
                .iter()
                .fold(0u64, |acc, bda| acc.saturating_add(self.bda(dtt, bda))),
            None => 0,
        };
        self.da_types.insert(id.to_string(), n);
        n
    }

    fn bda(&mut self, dtt: &DataTypeTemplates, bda: &RawBda) -> u64 {
        let mut n: u64 = 1;
        if bda.b_type == "Struct" {
            if let Some(id) = bda.type_ref.as_deref() {
                n = n.saturating_add(self.da_type(dtt, id));
            }
        }
        for child in &bda.bda {
            n = n.saturating_add(self.bda(dtt, child));
        }
        with_elements(n, bda.count.as_ref())
    }

    fn do_type(&mut self, dtt: &DataTypeTemplates, id: &str) -> u64 {
        if let Some(&n) = self.do_types.get(id) {
            return n;
        }
        let mut n: u64 = 0;
        if let Some(dot) = dtt.do_types.get(id) {
            for child in &dot.children {
                let child_count = match child {
                    RawDoTypeChild::Da(da) => {
                        let element = match (da.b_type.as_str(), da.type_ref.as_deref()) {
                            ("Struct", Some(type_id)) => {
                                1u64.saturating_add(self.da_type(dtt, type_id))
                            }
                            _ => 1,
                        };
                        with_setting_view(
                            with_elements(element, da.count.as_ref()),
                            derives_setting_view(da, dot),
                        )
                    }
                    RawDoTypeChild::Sdo(sdo) => with_elements(
                        1u64.saturating_add(self.do_type(dtt, &sdo.do_type_ref)),
                        sdo.count.as_ref(),
                    ),
                };
                n = n.saturating_add(child_count);
            }
        }
        self.do_types.insert(id.to_string(), n);
        n
    }

    fn ln_node_type(&mut self, dtt: &DataTypeTemplates, id: &str) -> u64 {
        if let Some(&n) = self.ln_node_types.get(id) {
            return n;
        }
        let mut n: u64 = 0;
        if let Some(lnt) = dtt.ln_node_types.get(id) {
            for do_def in &lnt.dos {
                n = n.saturating_add(1u64.saturating_add(self.do_type(dtt, &do_def.do_type_ref)));
            }
        }
        self.ln_node_types.insert(id.to_string(), n);
        n
    }
}

/// The node count of an attribute or sub-object of `element` nodes: as is for
/// a scalar, and one node for the array plus `element` per element for an
/// array.
fn with_elements(element: u64, count: Option<&RawCount>) -> u64 {
    with_count(element, count.and_then(RawCount::elements))
}

/// The node count of an attribute or sub-object of `element` nodes and
/// `count` elements, `None` for a scalar.
fn with_count(element: u64, count: Option<u32>) -> u64 {
    match count {
        Some(n) => 1u64.saturating_add(element.saturating_mul(u64::from(n))),
        None => element,
    }
}

/// The node count of an attribute of `nodes` nodes, doubled when the model
/// builder derives an FC=SG view of it, which has the same nodes.
fn with_setting_view(nodes: u64, derives_view: bool) -> u64 {
    if derives_view {
        nodes.saturating_mul(2)
    } else {
        nodes
    }
}

/// The element count of `count` in an instance whose values at the same level
/// are `values`: the count itself, or for a count naming an attribute the
/// value of the `<DAI>` of that name, as the model builder reads it; `None`
/// for a scalar, including a value the model builder rejects.
fn instance_count(count: Option<&RawCount>, values: Option<&[RawDataInstance]>) -> Option<u32> {
    let attr = match count? {
        RawCount::Attribute(attr) => attr,
        other => return other.elements(),
    };
    let dai = values?.iter().find_map(|v| match v {
        RawDataInstance::Dai(dai) if &dai.name == attr && dai.ix.is_none() => Some(dai),
        _ => None,
    })?;
    let val = dai
        .values
        .iter()
        .find(|v| v.s_group.is_none())
        .or_else(|| dai.values.first())?;
    val.raw_text.parse::<u32>().ok().filter(|n| *n > 0)
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
        assert!(resolved
            .raw
            .data_type_templates
            .ln_node_types
            .contains_key("LLN0_T"));
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
