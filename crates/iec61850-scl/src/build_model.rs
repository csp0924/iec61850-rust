//! Builds an [`iec61850_model::IedModel`] from the stage 2 SCL.
//!
//! Expands the raw IED tree of [`crate::resolved::ResolvedScl`] through the
//! four DataTypeTemplates tables: IED, access points, server, logical devices,
//! logical nodes, data objects and data attributes. A logical node's
//! `ln_type_ref` selects the LNodeType whose data objects are expanded through
//! their DOType, including nested sub-objects, and a data attribute whose bType
//! is Struct is expanded recursively through its DAType into an
//! [`iec61850_model::DataAttribute::constructed`].
//!
//! Leaf values start at [`iec61850_model::MmsValue::default_for`], and the
//! `<DOI>`, `<SDI>` and `<DAI>` overrides are applied afterwards, writing
//! through the `Arc<RwLock<MmsValue>>` the model already holds. Data sets and
//! the control blocks are carried over as well.
//!
//! Type mapping: [`b_type_to_dat`] turns a `bType` string into a
//! [`DataAttributeType`], mapping `ObjRef` to a 129-byte visible string and
//! `EntryID` to an 8-byte octet string, and rejecting anything else with
//! [`ErrorKind::EnumValueUnknown`] rather than ignoring it. A functional
//! constraint goes through [`FC::parse`], and an unknown token is likewise an
//! `EnumValueUnknown`.

use iec61850_model::{
    builder::{DataObjectBuilder, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder},
    cb::{
        GooseControlBlock, LogControlBlock, ReportControlBlock, SettingGroupControlBlock,
        SvControlBlock,
    },
    fc::FC,
    tree::{DataAttribute, DataObject, DataSet, DataSetEntry, IedModel},
    types::{DataAttributeType, TrgOps},
    value::MmsValue,
};

use crate::error::{ErrorKind, SclParseError, SourceSpan};
use crate::raw::{
    DataTypeTemplates, OptionFieldsBits, RawBda, RawDaDef, RawDaType, RawDai, RawDataInstance,
    RawDataSet, RawDoDef, RawDoType, RawFcda, RawGseControl, RawLNodeType, RawLogControl,
    RawLogicalDevice, RawLogicalNode, RawReportControlBlock, RawSampledValueControl, RawScl,
    RawSdoDef, RawSettingControl, RawVal, TriggerOptionsBits,
};

/// Builds the runtime model of one IED. Called by
/// [`crate::resolved::ResolvedScl::build_model`].
pub(crate) fn build_ied_model(raw: &RawScl, ied_name: &str) -> Result<IedModel, SclParseError> {
    // Locate the requested IED.
    let ied = raw
        .ieds
        .iter()
        .find(|i| i.name == ied_name)
        .ok_or_else(|| {
            SclParseError::at(
                SourceSpan {
                    line: 0,
                    col: 0,
                    byte_offset: 0,
                },
                "SCL",
                ErrorKind::SemanticConflict {
                    detail: format!("no IED named `{}` in this SCL", ied_name),
                },
            )
        })?;

    let dtt = &raw.data_type_templates;

    // Walk every access point, server and logical device.
    let mut model_b = IedModelBuilder::new(ied_name);
    let mut had_any_ld = false;

    for ap in &ied.access_points {
        let server = match ap.server.as_ref() {
            Some(s) => s,
            None => continue,
        };
        for raw_ld in &server.logical_devices {
            had_any_ld = true;
            let ld = build_ld(raw_ld, dtt)?;
            model_b = model_b.add_ld(ld).map_err(|e| {
                SclParseError::at(
                    raw_ld.span,
                    format!(
                        "SCL/IED[name=\"{}\"]/AccessPoint[name=\"{}\"]/Server/LDevice[inst=\"{}\"]",
                        ied_name, ap.name, raw_ld.inst
                    ),
                    ErrorKind::SemanticConflict {
                        detail: format!("the model builder rejected a logical device: {}", e),
                    },
                )
            })?;
        }
    }

    if !had_any_ld {
        return Err(SclParseError::at(
            ied.span,
            format!("SCL/IED[name=\"{}\"]", ied_name),
            ErrorKind::MissingRequiredElement {
                name: "LDevice".to_string(),
            },
        ));
    }

    model_b.build().map_err(|e| {
        SclParseError::at(
            ied.span,
            format!("SCL/IED[name=\"{}\"]", ied_name),
            ErrorKind::SemanticConflict {
                detail: format!("the model builder rejected the IED: {}", e),
            },
        )
    })
}

fn build_ld(
    raw_ld: &RawLogicalDevice,
    dtt: &DataTypeTemplates,
) -> Result<iec61850_model::LogicalDevice, SclParseError> {
    let mut ld_b = LogicalDeviceBuilder::new(raw_ld.inst.clone());
    if let Some(name) = &raw_ld.ld_name {
        ld_b = ld_b.with_ld_name(name.clone());
    }

    for raw_ln in &raw_ld.logical_nodes {
        let ln = build_ln(raw_ln, dtt, &raw_ld.inst)?;
        ld_b = ld_b.add_ln(ln);
    }

    ld_b.build().map_err(|e| {
        SclParseError::at(
            raw_ld.span,
            format!("SCL/.../LDevice[inst=\"{}\"]", raw_ld.inst),
            ErrorKind::SemanticConflict {
                detail: format!("the model builder rejected the logical device: {}", e),
            },
        )
    })
}

fn build_ln(
    raw_ln: &RawLogicalNode,
    dtt: &DataTypeTemplates,
    ld_inst: &str,
) -> Result<iec61850_model::LogicalNode, SclParseError> {
    // Stage 2 has already checked that ln_type_ref resolves, so `expect` here
    // states an invariant rather than a hope.
    let lnt = dtt
        .ln_node_types
        .get(&raw_ln.ln_type_ref)
        .expect("ln_type_ref was checked in stage 2");

    let mut ln_b = LogicalNodeBuilder::new(
        raw_ln.prefix.clone().unwrap_or_default(),
        raw_ln.ln_class.clone(),
        raw_ln.inst.clone(),
    );

    for raw_do in &lnt.dos {
        let dobj = build_do(raw_do, dtt, raw_ln, ld_inst, lnt)?;
        ln_b = ln_b.add_do(dobj);
    }

    // Data sets: each FCDA becomes one data set entry.
    for raw_ds in &raw_ln.data_sets {
        let ds = build_dataset(raw_ds, ld_inst, raw_ln)?;
        ln_b = ln_b.add_dataset(ds);
    }

    // Report control blocks
    for raw_rcb in &raw_ln.report_controls {
        ln_b = ln_b.add_rcb(build_rcb(raw_rcb));
    }

    // GOOSE control blocks
    for raw_gcb in &raw_ln.gse_controls {
        ln_b = ln_b.add_gocb(build_gocb(raw_gcb));
    }

    // Sampled value control blocks
    for raw_svcb in &raw_ln.smv_controls {
        ln_b = ln_b.add_svcb(build_svcb(raw_svcb));
    }

    // Log control blocks
    for raw_lcb in &raw_ln.log_controls {
        ln_b = ln_b.add_lcb(build_lcb(raw_lcb));
    }

    // Setting group control block
    if let Some(raw_sgcb) = raw_ln.setting_control.as_ref() {
        ln_b = ln_b.set_sgcb(build_sgcb(raw_sgcb, raw_ln, ld_inst)?);
    }

    let ln = ln_b.build().map_err(|e| {
        SclParseError::at(
            raw_ln.span,
            format!(
                "SCL/.../LDevice[inst=\"{}\"]/LN[lnClass=\"{}\",inst=\"{}\"]",
                ld_inst, raw_ln.ln_class, raw_ln.inst
            ),
            ErrorKind::SemanticConflict {
                detail: format!("the model builder rejected the logical node: {}", e),
            },
        )
    })?;

    // The DOI, SDI and DAI overrides are applied after the build, writing
    // through the `Arc<RwLock<MmsValue>>` the model holds.
    apply_doi_overrides(&ln, raw_ln, dtt, ld_inst)?;

    Ok(ln)
}

fn build_do(
    raw_do: &RawDoDef,
    dtt: &DataTypeTemplates,
    raw_ln: &RawLogicalNode,
    ld_inst: &str,
    lnt: &RawLNodeType,
) -> Result<DataObject, SclParseError> {
    let dot = dtt
        .do_types
        .get(&raw_do.do_type_ref)
        .expect("do_type_ref was checked in stage 2");

    expand_do_type(
        &raw_do.name,
        dot,
        dtt,
        &format!(
            "SCL/.../LDevice[inst=\"{}\"]/LN[lnClass=\"{}\",inst=\"{}\"]/DO[name=\"{}\" type=\"{}\"]",
            ld_inst, raw_ln.ln_class, raw_ln.inst, raw_do.name, raw_do.do_type_ref
        ),
        lnt,
    )
}

/// Expands a DOType into a [`DataObject`], including every data attribute
/// below it and, recursively, every sub-object.
///
/// # Errors
///
/// [`SclParseError`] when an attribute cannot be built or the model builder
/// rejects the object.
fn expand_do_type(
    do_name: &str,
    dot: &RawDoType,
    dtt: &DataTypeTemplates,
    parent_path: &str,
    lnt: &RawLNodeType,
) -> Result<DataObject, SclParseError> {
    let mut do_b = DataObjectBuilder::scalar(do_name);

    // Data attributes first
    for raw_da in &dot.das {
        let da = build_da(
            raw_da,
            dtt,
            &format!("{}/DA[name=\"{}\"]", parent_path, raw_da.name),
        )?;
        do_b = do_b.add_da_node(da);
    }

    // Then the sub-objects
    for raw_sdo in &dot.sdos {
        let sdo = build_sdo(
            raw_sdo,
            dtt,
            &format!("{}/SDO[name=\"{}\"]", parent_path, raw_sdo.name),
            lnt,
        )?;
        do_b = do_b.add_sub_do(sdo);
    }

    do_b.build().map_err(|e| {
        SclParseError::at(
            dot.span,
            parent_path.to_string(),
            ErrorKind::SemanticConflict {
                detail: format!("the model builder rejected the data object: {}", e),
            },
        )
    })
}

fn build_sdo(
    raw_sdo: &RawSdoDef,
    dtt: &DataTypeTemplates,
    sdo_path: &str,
    lnt: &RawLNodeType,
) -> Result<DataObject, SclParseError> {
    let dot = dtt
        .do_types
        .get(&raw_sdo.do_type_ref)
        .expect("the sub-object type_ref was checked in stage 2");
    expand_do_type(&raw_sdo.name, dot, dtt, sdo_path, lnt)
}

/// Expands a raw data attribute into a [`DataAttribute`].
///
/// A bType of Struct is expanded recursively through its DAType into a
/// constructed attribute. Any other bType yields a leaf whose value starts at
/// the zero value of its type.
///
/// # Errors
///
/// [`SclParseError`] when the bType or the functional constraint is not
/// recognized.
fn build_da(
    raw_da: &RawDaDef,
    dtt: &DataTypeTemplates,
    da_path: &str,
) -> Result<DataAttribute, SclParseError> {
    let fc = parse_fc(&raw_da.fc, raw_da.span, da_path)?;
    let trg_ops = trg_ops_to_model(raw_da.trg_ops);

    if raw_da.b_type == "Struct" {
        let type_id = raw_da
            .type_ref
            .as_deref()
            .expect("stage 2 checked that a Struct carries a type_ref");
        let dat = dtt
            .da_types
            .get(type_id)
            .expect("stage 2 checked that the type_ref resolves");
        let children = dat
            .bdas
            .iter()
            .map(|bda| {
                build_bda(
                    bda,
                    fc,
                    dtt,
                    &format!("{}/BDA[name=\"{}\"]", da_path, bda.name),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut da = DataAttribute::constructed(raw_da.name.clone(), fc, children);
        da.trg_ops = trg_ops;
        return Ok(da);
    }

    let dat = b_type_to_dat(&raw_da.b_type, raw_da.span, da_path)?;
    let initial = MmsValue::default_for(dat);
    Ok(DataAttribute::new(
        raw_da.name.clone(),
        fc,
        dat,
        trg_ops,
        initial,
    ))
}

/// Expands a nested attribute. It has no functional constraint of its own and
/// inherits the one of its parent.
///
/// # Errors
///
/// [`SclParseError`] when the bType is not recognized.
fn build_bda(
    raw_bda: &RawBda,
    parent_fc: FC,
    dtt: &DataTypeTemplates,
    bda_path: &str,
) -> Result<DataAttribute, SclParseError> {
    if raw_bda.b_type == "Struct" {
        let type_id = raw_bda
            .type_ref
            .as_deref()
            .expect("stage 2 checked that a Struct carries a type_ref");
        let dat = dtt
            .da_types
            .get(type_id)
            .expect("stage 2 checked that the type_ref resolves");
        let children = dat
            .bdas
            .iter()
            .map(|child| {
                build_bda(
                    child,
                    parent_fc,
                    dtt,
                    &format!("{}/BDA[name=\"{}\"]", bda_path, child.name),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(DataAttribute::constructed(
            raw_bda.name.clone(),
            parent_fc,
            children,
        ));
    }

    let dat = b_type_to_dat(&raw_bda.b_type, raw_bda.span, bda_path)?;
    Ok(DataAttribute::new(
        raw_bda.name.clone(),
        parent_fc,
        dat,
        TrgOps::NONE,
        MmsValue::default_for(dat),
    ))
}

// -----------------------------------------------------------------------------
// Data set and control block conversion
// -----------------------------------------------------------------------------

/// Converts a `<DataSet>` into a [`DataSet`], turning each FCDA into an entry.
///
/// An FCDA `doName` is a path of data object and sub-object names joined with
/// `.` (IEC 61850-6 §9.3.5), so `Pos.stVal` names `stVal` under the sub-object
/// `Pos`. `daName`, when present, is the final data attribute name.
///
/// # Errors
///
/// [`SclParseError`] when an FCDA carries an unrecognized functional
/// constraint.
fn build_dataset(
    raw_ds: &RawDataSet,
    ld_inst: &str,
    raw_ln: &RawLogicalNode,
) -> Result<DataSet, SclParseError> {
    let entries = raw_ds
        .fcdas
        .iter()
        .map(|fcda| build_fcda(fcda, ld_inst, raw_ln, &raw_ds.name))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DataSet {
        name: raw_ds.name.clone(),
        entries,
    })
}

fn build_fcda(
    fcda: &RawFcda,
    ld_inst: &str,
    raw_ln: &RawLogicalNode,
    ds_name: &str,
) -> Result<DataSetEntry, SclParseError> {
    let path = format!(
        "SCL/.../LDevice[inst=\"{}\"]/LN[lnClass=\"{}\",inst=\"{}\"]/DataSet[name=\"{}\"]/FCDA",
        ld_inst, raw_ln.ln_class, raw_ln.inst, ds_name
    );
    let fc = parse_fc(&fcda.fc, fcda.span, &path)?;

    // ln_name is prefix + ln_class + ln_inst, with an absent instance read as "".
    let mut ln_name = String::new();
    if let Some(p) = &fcda.prefix {
        ln_name.push_str(p);
    }
    ln_name.push_str(&fcda.ln_class);
    if let Some(i) = &fcda.ln_inst {
        ln_name.push_str(i);
    }

    // do_path splits doName on `.`, and daName becomes the final segment. An
    // empty doName means the entry covers the whole logical node.
    let mut do_path = Vec::new();
    if let Some(do_name) = &fcda.do_name {
        for seg in do_name.split('.') {
            if !seg.is_empty() {
                do_path.push(seg.to_string());
            }
        }
    }
    if let Some(da_name) = &fcda.da_name {
        do_path.push(da_name.clone());
    }

    Ok(DataSetEntry {
        ld_inst: fcda.ld_inst.clone(),
        ln_name,
        fc,
        do_path,
        array_index: fcda.ix,
        component: None,
    })
}

/// Converts a `<ReportControl>` into a [`ReportControlBlock`].
///
/// The trigger options, option fields, integrity period and buffer time are
/// part of the model schema, so a model built from an `.icd` needs no further
/// configuration. The report instance limit stays a server runtime setting and
/// is not carried here.
fn build_rcb(raw_rcb: &RawReportControlBlock) -> ReportControlBlock {
    ReportControlBlock {
        name: raw_rcb.name.clone(),
        is_buffered: raw_rcb.buffered,
        dataset_ref: raw_rcb.dat_set.clone().unwrap_or_default(),
        conf_rev: raw_rcb.conf_rev,
        rpt_id: raw_rcb.rpt_id.clone().unwrap_or_default(),
        trg_ops: report_trg_ops_to_model(raw_rcb.trg_ops),
        opt_flds: opt_fields_to_model(raw_rcb.opt_fields),
        buf_tm_ms: raw_rcb.buf_time,
        intg_pd_ms: raw_rcb.intg_pd,
    }
}

/// Converts a `<GSEControl>` into a [`GooseControlBlock`].
///
/// SCL gives a `<GSEControl>` no goID attribute, so the control block name is
/// used as the goID.
fn build_gocb(raw_gcb: &RawGseControl) -> GooseControlBlock {
    GooseControlBlock {
        name: raw_gcb.name.clone(),
        dataset_ref: raw_gcb.data_set.clone(),
        conf_rev: raw_gcb.conf_rev,
        // SCL carries no goID attribute, so the name is used instead.
        go_id: raw_gcb.name.clone(),
    }
}

/// Converts a `<SampledValueControl>` into an [`SvControlBlock`].
///
/// The sample rate, ASDU count, sample mode and options are server settings and
/// are not part of the model schema.
fn build_svcb(raw_svcb: &RawSampledValueControl) -> SvControlBlock {
    SvControlBlock {
        name: raw_svcb.name.clone(),
        dataset_ref: raw_svcb.data_set.clone(),
        conf_rev: raw_svcb.conf_rev,
        sv_id: raw_svcb.smv_id.clone(),
        is_multicast: raw_svcb.multicast,
    }
}

/// Converts a `<LogControl>` into a [`LogControlBlock`].
///
/// SCL defaults `logName` to `LN$Log`; when the raw element carries no value,
/// the field is left empty for the caller to fill in.
fn build_lcb(raw_lcb: &RawLogControl) -> LogControlBlock {
    LogControlBlock {
        name: raw_lcb.name.clone(),
        dataset_ref: raw_lcb.data_set.clone().unwrap_or_default(),
        log_ref: raw_lcb.log_name.clone().unwrap_or_default(),
    }
}

/// Converts a `<SettingControl>` into a [`SettingGroupControlBlock`].
///
/// # Errors
///
/// [`ErrorKind::AttributeValueInvalid`] when `numOfSGs` or `actSG` falls
/// outside the 1 to 255 range the standard defines.
fn build_sgcb(
    raw_sgcb: &RawSettingControl,
    raw_ln: &RawLogicalNode,
    ld_inst: &str,
) -> Result<SettingGroupControlBlock, SclParseError> {
    let path = format!(
        "SCL/.../LDevice[inst=\"{}\"]/LN[lnClass=\"{}\",inst=\"{}\"]/SettingControl",
        ld_inst, raw_ln.ln_class, raw_ln.inst
    );
    let num_of_sg = u8::try_from(raw_sgcb.num_of_sgs).map_err(|_| {
        SclParseError::at(
            raw_sgcb.span,
            path.clone(),
            ErrorKind::AttributeValueInvalid {
                name: "numOfSGs".to_string(),
                expected_type: "u8 (1..=255)".to_string(),
                raw_value: raw_sgcb.num_of_sgs.to_string(),
                cause: None,
            },
        )
        .with_attribute("numOfSGs")
    })?;
    let act_sg = u8::try_from(raw_sgcb.act_sg).map_err(|_| {
        SclParseError::at(
            raw_sgcb.span,
            path.clone(),
            ErrorKind::AttributeValueInvalid {
                name: "actSG".to_string(),
                expected_type: "u8 (1..=255)".to_string(),
                raw_value: raw_sgcb.act_sg.to_string(),
                cause: None,
            },
        )
        .with_attribute("actSG")
    })?;
    // SCL counts `resvTms` in seconds (IEC 61850-6 §9.3.3). The model field is
    // a u16, so a larger value is clamped to 65535 s, roughly 18 hours.
    let default_resv_tms_s = raw_sgcb
        .resv_tms
        .map(|v| {
            if v > u16::MAX as u32 {
                tracing::warn!(
                    raw = v,
                    "SCL SGCB resvTms exceeds the u16 range, clamping to 65535 s"
                );
                u16::MAX
            } else {
                v as u16
            }
        })
        .unwrap_or(60);
    Ok(SettingGroupControlBlock {
        num_of_sg,
        act_sg,
        has_resv_tms: raw_sgcb.resv_tms.is_some(),
        default_resv_tms_s,
    })
}

// -----------------------------------------------------------------------------
// DOI, SDI and DAI default-value overrides
// -----------------------------------------------------------------------------

/// Applies the `<DAI>` values under `raw_ln.doi`, parsing each `<Val>` into an
/// [`MmsValue`] and writing it through the target attribute's
/// `Arc<RwLock<MmsValue>>`.
///
/// The walk runs over the runtime model and the raw DataTypeTemplates tree in
/// parallel, because a runtime [`DataAttribute`] does not carry the enumeration
/// type or the type reference the value needs to be parsed.
///
/// A `<DOI>`, `<SDI>` or `<DAI>` naming something the model does not contain is
/// logged and skipped: the model is already built, and failing the whole file
/// over one stray override would be disproportionate. Where several values
/// carry a setting group, the one without a group is applied, or the first one
/// otherwise.
///
/// # Errors
///
/// [`ErrorKind::SemanticConflict`] when a `<DAI>` lands on a constructed
/// attribute, where an `<SDI>` is required, and
/// [`ErrorKind::AttributeValueInvalid`] when a value does not parse as the
/// target type.
fn apply_doi_overrides(
    ln: &iec61850_model::LogicalNode,
    raw_ln: &RawLogicalNode,
    dtt: &DataTypeTemplates,
    ld_inst: &str,
) -> Result<(), SclParseError> {
    let lnt = dtt
        .ln_node_types
        .get(&raw_ln.ln_type_ref)
        .expect("ln_type_ref was checked in stage 2");

    for raw_doi in &raw_ln.doi {
        // Find the raw data object definition in the LNodeType.
        let raw_do_def = match lnt.dos.iter().find(|d| d.name == raw_doi.name) {
            Some(d) => d,
            None => {
                tracing::warn!(
                    "DOI name=\"{}\" has no matching DO in LNodeType id=\"{}\", skipping",
                    raw_doi.name,
                    lnt.id
                );
                continue;
            }
        };
        let dot = dtt
            .do_types
            .get(&raw_do_def.do_type_ref)
            .expect("the data object type_ref was checked in stage 2");
        let dobj = match ln.do_by_name(&raw_doi.name) {
            Some(d) => d,
            None => {
                tracing::warn!(
                    "DOI name=\"{}\" has no matching DataObject in the built logical node, skipping",
                    raw_doi.name
                );
                continue;
            }
        };
        let path = format!(
            "SCL/.../LDevice[inst=\"{}\"]/LN[lnClass=\"{}\",inst=\"{}\"]/DOI[name=\"{}\"]",
            ld_inst, raw_ln.ln_class, raw_ln.inst, raw_doi.name
        );
        apply_instances_at_do(&raw_doi.children, dobj, dot, dtt, &path)?;
    }
    Ok(())
}

/// Applies the `<SDI>` and `<DAI>` children below a data object and its DOType.
///
/// # Errors
///
/// Whatever [`apply_dai_value`] reports.
fn apply_instances_at_do(
    children: &[RawDataInstance],
    dobj: &DataObject,
    dot: &RawDoType,
    dtt: &DataTypeTemplates,
    parent_path: &str,
) -> Result<(), SclParseError> {
    for inst in children {
        match inst {
            RawDataInstance::Sdi(sdi) => {
                // Two possibilities: a sub-object, or a constructed attribute.
                if let Some(sdo) = dot.sdos.iter().find(|s| s.name == sdi.name) {
                    let sub_dot = dtt
                        .do_types
                        .get(&sdo.do_type_ref)
                        .expect("the sub-object type_ref was checked in stage 2");
                    let sub_dobj = match dobj.child_by_name(&sdi.name) {
                        Some(iec61850_model::tree::DoChild::SubDo(sd)) => sd,
                        _ => {
                            tracing::warn!(
                                "SDI name=\"{}\" expects a sub-DataObject that the built model does not have, skipping",
                                sdi.name
                            );
                            continue;
                        }
                    };
                    let path = format!("{}/SDI[name=\"{}\"]", parent_path, sdi.name);
                    apply_instances_at_do(&sdi.children, sub_dobj, sub_dot, dtt, &path)?;
                } else if let Some(da_def) = dot.das.iter().find(|d| d.name == sdi.name) {
                    if da_def.b_type != "Struct" {
                        tracing::warn!(
                            "SDI name=\"{}\" resolves to a DA that is not a Struct (bType=\"{}\"), skipping",
                            sdi.name,
                            da_def.b_type
                        );
                        continue;
                    }
                    let type_id = da_def.type_ref.as_deref().expect("checked in stage 2");
                    let dat_def = dtt
                        .da_types
                        .get(type_id)
                        .expect("the DA type_ref was checked in stage 2");
                    let da = match dobj.child_by_name(&sdi.name) {
                        Some(iec61850_model::tree::DoChild::Da(d)) => d,
                        _ => {
                            tracing::warn!(
                                "SDI name=\"{}\" expects a constructed DA that the built model does not have, skipping",
                                sdi.name
                            );
                            continue;
                        }
                    };
                    let path = format!("{}/SDI[name=\"{}\"]", parent_path, sdi.name);
                    apply_instances_at_da(&sdi.children, da, dat_def, dtt, &path)?;
                } else {
                    tracing::warn!(
                        "SDI name=\"{}\" has no matching SDO or DA in DOType id=\"{}\", skipping",
                        sdi.name,
                        dot.id
                    );
                }
            }
            RawDataInstance::Dai(dai) => {
                let da_def = match dot.das.iter().find(|d| d.name == dai.name) {
                    Some(d) => d,
                    None => {
                        tracing::warn!(
                            "DAI name=\"{}\" has no matching DA in DOType id=\"{}\", skipping",
                            dai.name,
                            dot.id
                        );
                        continue;
                    }
                };
                let da = match dobj.child_by_name(&dai.name) {
                    Some(iec61850_model::tree::DoChild::Da(d)) => d,
                    _ => {
                        tracing::warn!(
                            "DAI name=\"{}\" expects a leaf DA that the built model does not have, skipping",
                            dai.name
                        );
                        continue;
                    }
                };
                let path = format!("{}/DAI[name=\"{}\"]", parent_path, dai.name);
                apply_dai_value(
                    dai,
                    da,
                    da_def.b_type.as_str(),
                    da_def.type_ref.as_deref(),
                    dtt,
                    &path,
                )?;
            }
        }
    }
    Ok(())
}

/// Applies the `<SDI>` and `<DAI>` children below a constructed attribute and
/// its DAType.
///
/// # Errors
///
/// Whatever [`apply_dai_value`] reports.
fn apply_instances_at_da(
    children: &[RawDataInstance],
    da: &DataAttribute,
    dat: &RawDaType,
    dtt: &DataTypeTemplates,
    parent_path: &str,
) -> Result<(), SclParseError> {
    for inst in children {
        match inst {
            RawDataInstance::Sdi(sdi) => {
                let bda_def = match dat.bdas.iter().find(|b| b.name == sdi.name) {
                    Some(b) => b,
                    None => {
                        tracing::warn!(
                            "SDI name=\"{}\" has no matching BDA in DAType id=\"{}\", skipping",
                            sdi.name,
                            dat.id
                        );
                        continue;
                    }
                };
                if bda_def.b_type != "Struct" {
                    tracing::warn!(
                        "SDI name=\"{}\" resolves to a BDA that is not a Struct (bType=\"{}\"), skipping",
                        sdi.name,
                        bda_def.b_type
                    );
                    continue;
                }
                let type_id = bda_def.type_ref.as_deref().expect("checked in stage 2");
                let sub_dat = dtt
                    .da_types
                    .get(type_id)
                    .expect("the BDA type_ref was checked in stage 2");
                let sub_da = match da.child_by_name(&sdi.name) {
                    Some(c) => c,
                    None => {
                        tracing::warn!(
                            "SDI name=\"{}\" has no matching BDA in the built model, skipping",
                            sdi.name
                        );
                        continue;
                    }
                };
                let path = format!("{}/SDI[name=\"{}\"]", parent_path, sdi.name);
                apply_instances_at_da(&sdi.children, sub_da, sub_dat, dtt, &path)?;
            }
            RawDataInstance::Dai(dai) => {
                let bda_def = match dat.bdas.iter().find(|b| b.name == dai.name) {
                    Some(b) => b,
                    None => {
                        tracing::warn!(
                            "DAI name=\"{}\" has no matching BDA in DAType id=\"{}\", skipping",
                            dai.name,
                            dat.id
                        );
                        continue;
                    }
                };
                let sub_da = match da.child_by_name(&dai.name) {
                    Some(c) => c,
                    None => {
                        tracing::warn!(
                            "DAI name=\"{}\" has no matching BDA in the built model, skipping",
                            dai.name
                        );
                        continue;
                    }
                };
                let path = format!("{}/DAI[name=\"{}\"]", parent_path, dai.name);
                apply_dai_value(
                    dai,
                    sub_da,
                    bda_def.b_type.as_str(),
                    bda_def.type_ref.as_deref(),
                    dtt,
                    &path,
                )?;
            }
        }
    }
    Ok(())
}

/// Parses the values of one `<DAI>` and writes the result into the attribute's
/// `Arc<RwLock<MmsValue>>`.
///
/// The value without a setting group is applied; if every value carries one,
/// the first is applied and a warning is emitted.
///
/// # Errors
///
/// [`ErrorKind::SemanticConflict`] when the target attribute is constructed,
/// where an `<SDI>` is required instead, and
/// [`ErrorKind::AttributeValueInvalid`] when the value does not parse.
fn apply_dai_value(
    dai: &RawDai,
    da: &DataAttribute,
    b_type: &str,
    type_ref: Option<&str>,
    dtt: &DataTypeTemplates,
    path: &str,
) -> Result<(), SclParseError> {
    if dai.values.is_empty() {
        // No Val child: the DAI only declares valKind or valImport and
        // overrides no value.
        return Ok(());
    }
    if b_type == "Struct" {
        return Err(SclParseError::at(
            dai.span,
            path.to_string(),
            ErrorKind::SemanticConflict {
                detail: "the DAI resolves to a constructed DA (bType=Struct); an SDI is required to descend into it"
                    .to_string(),
            },
        ));
    }

    let val = pick_val_for_no_sgroup(&dai.values);
    let parsed = parse_val_for_b_type(val, b_type, type_ref, dtt, dai.span, path)?;
    let mut guard = da.value.write().expect("MmsValue lock poisoned");
    *guard = parsed;
    Ok(())
}

/// Picks the value to apply out of several `<Val>` elements: the one without a
/// setting group, or the first one with a warning.
///
/// Also used by the build-script path through [`crate::__build_internals`], so
/// a DAI string is parsed once while the build script runs and emitted as a
/// literal, leaving no string parsing in the user's run time.
pub fn pick_val_for_no_sgroup(values: &[RawVal]) -> &RawVal {
    if let Some(v) = values.iter().find(|v| v.s_group.is_none()) {
        return v;
    }
    tracing::warn!("every `<Val>` of this DAI carries a setting group; applying the first one");
    &values[0]
}

/// Parses an SCL `<Val>` string into an [`MmsValue`], according to the target
/// bType.
///
/// The parse is deliberately strict, so a malformed file fails instead of
/// silently taking a wrong value: a BOOLEAN accepts only `true` and `false`;
/// an integer rejects leading and trailing whitespace; a float rejects a comma
/// as the decimal separator; a visible string is length-checked against its
/// declared limit; and an enumeration is looked up by name in its EnumType
/// before falling back to an integer ordinal.
///
/// Quality, Check, Dbpos, Tcmd, Timestamp, EntryTime, Octet64, EntryID,
/// OptFlds, TrgOps and PhyComAddr are not parsed here: a value on one of them
/// is warned about and the attribute keeps its default.
///
/// Also used by the build-script path through [`crate::__build_internals`], so
/// the value is parsed once while the build script runs and emitted as a
/// literal.
///
/// # Errors
///
/// [`ErrorKind::AttributeValueInvalid`] when the string does not parse as the
/// target type, and [`ErrorKind::SemanticConflict`] when the bType is Struct,
/// which the caller must handle before calling this.
pub fn parse_val_for_b_type(
    val: &RawVal,
    b_type: &str,
    type_ref: Option<&str>,
    dtt: &DataTypeTemplates,
    span: SourceSpan,
    path: &str,
) -> Result<MmsValue, SclParseError> {
    let raw = val.raw_text.as_str();
    let invalid = |expected: &str, cause: Option<String>| -> SclParseError {
        SclParseError::at(
            span,
            path.to_string(),
            ErrorKind::AttributeValueInvalid {
                name: "Val".to_string(),
                expected_type: expected.to_string(),
                raw_value: raw.to_string(),
                cause,
            },
        )
    };

    match b_type {
        "BOOLEAN" => match raw {
            "true" => Ok(MmsValue::Boolean(true)),
            "false" => Ok(MmsValue::Boolean(false)),
            _ => Err(invalid(
                "BOOLEAN (literal `true` / `false`)",
                Some(
                    "IEC 61850-6 §A.10 allows only `true` and `false` as a BOOLEAN literal"
                        .to_string(),
                ),
            )),
        },
        "INT8" | "INT16" | "INT32" | "INT64" | "INT128" => {
            if raw.trim() != raw {
                return Err(invalid(
                    b_type,
                    Some("leading and trailing whitespace are not allowed".to_string()),
                ));
            }
            raw.parse::<i64>()
                .map(MmsValue::Integer)
                .map_err(|e| invalid(b_type, Some(e.to_string())))
        }
        "INT8U" | "INT16U" | "INT24U" | "INT32U" => {
            if raw.trim() != raw {
                return Err(invalid(
                    b_type,
                    Some("leading and trailing whitespace are not allowed".to_string()),
                ));
            }
            raw.parse::<u64>()
                .map(MmsValue::Unsigned)
                .map_err(|e| invalid(b_type, Some(e.to_string())))
        }
        "FLOAT32" => {
            if raw.contains(',') {
                return Err(invalid(
                    "FLOAT32",
                    Some("a comma is not accepted as the decimal separator".to_string()),
                ));
            }
            raw.parse::<f32>()
                .map(MmsValue::Float32)
                .map_err(|e| invalid("FLOAT32", Some(e.to_string())))
        }
        "FLOAT64" => {
            if raw.contains(',') {
                return Err(invalid(
                    "FLOAT64",
                    Some("a comma is not accepted as the decimal separator".to_string()),
                ));
            }
            raw.parse::<f64>()
                .map(MmsValue::Float64)
                .map_err(|e| invalid("FLOAT64", Some(e.to_string())))
        }
        "Enum" => {
            let id = type_ref.ok_or_else(|| {
                invalid(
                    "Enum (type_ref required)",
                    Some("stage 2 should have checked this".to_string()),
                )
            })?;
            let et = dtt
                .enum_types
                .get(id)
                .ok_or_else(|| invalid("Enum", Some(format!("no EnumType with id=\"{}\"", id))))?;
            // Look the string up as an enumeration name first.
            if let Some(ev) = et.values.iter().find(|v| v.name == raw) {
                return Ok(MmsValue::Integer(ev.ord as i64));
            }
            // Otherwise fall back to an integer ordinal.
            if let Ok(ord) = raw.parse::<i64>() {
                if et.values.iter().any(|v| v.ord as i64 == ord) {
                    return Ok(MmsValue::Integer(ord));
                }
                return Err(invalid(
                    "Enum",
                    Some(format!("ordinal {} is outside EnumType id=\"{}\"", ord, id)),
                ));
            }
            Err(invalid(
                "Enum",
                Some(format!(
                    "`{}` is neither a valid name nor a valid ordinal of EnumType id=\"{}\"",
                    raw, id
                )),
            ))
        }
        "VisString32" | "VisString64" | "VisString65" | "VisString129" | "VisString255"
        | "ObjRef" | "Currency" => {
            let cap: usize = match b_type {
                "VisString32" => 32,
                "VisString64" => 64,
                "VisString65" => 65,
                "VisString129" | "ObjRef" => 129,
                _ => 255,
            };
            if raw.len() > cap {
                return Err(invalid(
                    b_type,
                    Some(format!("length {} exceeds the limit of {}", raw.len(), cap)),
                ));
            }
            Ok(MmsValue::VisibleString(raw.to_string()))
        }
        "Unicode255" => {
            if raw.len() > 255 {
                return Err(invalid(
                    "Unicode255",
                    Some(format!("length {} exceeds the limit of 255", raw.len())),
                ));
            }
            Ok(MmsValue::MmsString(raw.to_string()))
        }
        // A bType this function does not parse: warn and return the zero value
        // of the corresponding type, which leaves the attribute at its default.
        "Quality" | "Check" | "Dbpos" | "Tcmd" | "Timestamp" | "EntryTime" | "Octet64"
        | "EntryID" | "OptFlds" | "TrgOps" | "PhyComAddr" => {
            tracing::warn!(
                "a `<Val>` on bType=\"{}\" is not parsed yet, so the attribute keeps its default",
                b_type
            );
            let dat = b_type_to_dat(b_type, span, path)?;
            Ok(MmsValue::default_for(dat))
        }
        "Struct" => Err(SclParseError::at(
            span,
            path.to_string(),
            ErrorKind::SemanticConflict {
                detail:
                    "Struct must not reach parse_val_for_b_type; the caller has to handle type_ref"
                        .to_string(),
            },
        )),
        _ => Err(invalid(
            "(known bType)",
            Some(format!("bType `{}` is not supported", b_type)),
        )),
    }
}

/// Converts the trigger-option bits of a `<DA trgOps="...">` into [`TrgOps`],
/// which at attribute level covers DCHG, QCHG and DUPD.
///
/// Also used by the build-script path through
/// `iec61850-scl::__build_internals`, so the generated model and the runtime
/// model derive their values the same way.
pub fn trg_ops_to_model(t: TriggerOptionsBits) -> TrgOps {
    let mut bits = TrgOps::NONE;
    if t.data_change {
        bits = bits | TrgOps::DCHG;
    }
    if t.quality_change {
        bits = bits | TrgOps::QCHG;
    }
    if t.data_update {
        bits = bits | TrgOps::DUPD;
    }
    bits
}

/// Converts the trigger-option bits of a `<ReportControl><TrgOps>` into
/// [`TrgOps`], which at control block level covers all five bits.
///
/// `period` becomes `TrgOps::INTEGRITY` and `gi` becomes `TrgOps::GI`.
///
/// Also used by the build-script path, as [`trg_ops_to_model`] is.
pub fn report_trg_ops_to_model(t: TriggerOptionsBits) -> TrgOps {
    let mut bits = trg_ops_to_model(t);
    if t.period {
        bits = bits | TrgOps::INTEGRITY;
    }
    if t.gi {
        bits = bits | TrgOps::GI;
    }
    bits
}

/// Converts the option-field bits of a `<ReportControl><OptFields>` into
/// [`iec61850_model::cb::OptFlds`].
///
/// Also used by the build-script path, as [`trg_ops_to_model`] is.
pub fn opt_fields_to_model(o: OptionFieldsBits) -> iec61850_model::cb::OptFlds {
    use iec61850_model::cb::OptFlds;
    let mut bits = OptFlds::NONE;
    if o.seq_num {
        bits |= OptFlds::SEQ_NUM;
    }
    if o.time_stamp {
        bits |= OptFlds::TIME_STAMP;
    }
    if o.reason_code {
        bits |= OptFlds::REASON;
    }
    if o.data_set {
        bits |= OptFlds::DATA_SET;
    }
    if o.data_ref {
        bits |= OptFlds::DATA_REFERENCE;
    }
    if o.buffer_overflow {
        bits |= OptFlds::BUFFER_OVERFLOW;
    }
    if o.ent_id {
        bits |= OptFlds::ENTRY_ID;
    }
    if o.conf_rev {
        bits |= OptFlds::CONF_REV;
    }
    if o.segmentation {
        bits |= OptFlds::SEGMENTATION;
    }
    bits
}

/// Converts an `fc` token of a `<DA>` or `<FCDA>` into an [`FC`], with an
/// actionable error.
///
/// Also used by the build-script path, as [`trg_ops_to_model`] is.
///
/// # Errors
///
/// [`ErrorKind::EnumValueUnknown`] when the token is not a defined functional
/// constraint.
pub fn parse_fc(token: &str, span: SourceSpan, path: &str) -> Result<FC, SclParseError> {
    FC::parse(token).map_err(|_| {
        SclParseError::at(
            span,
            path.to_string(),
            ErrorKind::EnumValueUnknown {
                name: "fc".to_string(),
                raw_value: token.to_string(),
                allowed: vec![
                    "ST", "MX", "SP", "SV", "CF", "DC", "SG", "SE", "SR", "OR", "BL", "EX", "CO",
                    "US", "MS", "RP", "BR", "LG", "GO",
                ],
            },
        )
        .with_attribute("fc")
    })
}

/// Converts an SCL `bType` string into a [`DataAttributeType`].
///
/// # Errors
///
/// [`ErrorKind::EnumValueUnknown`], carrying the element path and the offending
/// value, when the string is not a recognized basic type.
pub fn b_type_to_dat(
    b_type: &str,
    span: SourceSpan,
    path: &str,
) -> Result<DataAttributeType, SclParseError> {
    use DataAttributeType as T;
    let dat = match b_type {
        "BOOLEAN" => T::Boolean,
        "INT8" => T::Int8,
        "INT16" => T::Int16,
        "INT32" => T::Int32,
        "INT64" => T::Int64,
        "INT128" => T::Int128,
        "INT8U" => T::Int8U,
        "INT16U" => T::Int16U,
        "INT24U" => T::Int24U,
        "INT32U" => T::Int32U,
        "FLOAT32" => T::Float32,
        "FLOAT64" => T::Float64,
        "Enum" => T::Enumerated,
        "Dbpos" | "Tcmd" => T::CodedEnum,
        "Check" => T::Check,
        "Octet64" => T::OctetString(64),
        "Quality" => T::Quality,
        "Timestamp" => T::Timestamp,
        "Currency" => T::Currency,
        "VisString32" => T::VisibleString(32),
        "VisString64" => T::VisibleString(64),
        "VisString65" => T::VisibleString(65),
        "VisString129" => T::VisibleString(129),
        "VisString255" => T::VisibleString(255),
        // `ObjRef` maps to a 129-byte visible string: the standard calls it an
        // object reference, carried in that width.
        "ObjRef" => T::VisibleString(129),
        "Unicode255" => T::UnicodeString255,
        "OptFlds" => T::OptFlds,
        "TrgOps" => T::TrgOpsBits,
        // `EntryID` maps to an 8-byte octet string.
        "EntryID" => T::OctetString(8),
        "EntryTime" => T::EntryTime,
        "PhyComAddr" => T::PhyComAddr,
        // Struct is handled by the caller; reaching here means it was not.
        "Struct" => {
            return Err(SclParseError::at(
                span,
                path.to_string(),
                ErrorKind::SemanticConflict {
                    detail: "bType=Struct must be resolved through type_ref by the caller, not passed to b_type_to_dat"
                        .to_string(),
                },
            )
            .with_attribute("bType"));
        }
        _ => {
            return Err(SclParseError::at(
                span,
                path.to_string(),
                ErrorKind::EnumValueUnknown {
                    name: "bType".to_string(),
                    raw_value: b_type.to_string(),
                    allowed: vec![
                        "BOOLEAN",
                        "INT8",
                        "INT16",
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
                        "Check",
                        "Octet64",
                        "Quality",
                        "Timestamp",
                        "Currency",
                        "VisString32",
                        "VisString64",
                        "VisString65",
                        "VisString129",
                        "VisString255",
                        "ObjRef",
                        "Unicode255",
                        "OptFlds",
                        "TrgOps",
                        "EntryID",
                        "EntryTime",
                        "PhyComAddr",
                        "Struct",
                    ],
                },
            )
            .with_attribute("bType"));
        }
    };
    Ok(dat)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_scl;

    fn build(xml: &str, ied_name: &str) -> IedModel {
        let resolved = parse_scl(xml).expect("parse").resolve().expect("resolve");
        resolved.build_model(ied_name).expect("build_model")
    }

    /// A minimal IED: LLN0 with Mod.stVal as an enumeration, Mod.q as a quality
    /// and Mod.t as a timestamp.
    #[test]
    fn minimal_lln0_mod_builds() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="Enum" type="ModEnum" dchg="true"/>
      <DA name="q"     fc="ST" bType="Quality" qchg="true"/>
      <DA name="t"     fc="ST" bType="Timestamp"/>
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
        let m = build(xml, "IED1");
        assert_eq!(m.ied_name, "IED1");
        assert!(m.ld_by_inst("LD0").is_some());
        let ld = m.ld_by_inst("LD0").unwrap();
        assert_eq!(ld.lns.len(), 1);
        let lln0 = &ld.lns[0];
        assert_eq!(lln0.class, "LLN0");
        assert_eq!(lln0.dos.len(), 1);
        let mod_do = lln0.do_by_name("Mod").unwrap();
        // Three data attributes: stVal, q and t
        assert_eq!(mod_do.children.len(), 3);
        // All three are under ST
        let count_st = mod_do.children_with_fc(FC::St).count();
        assert_eq!(count_st, 3);
    }

    /// A constructed attribute: the cVal of a CMV is a Struct of DAType Vector,
    /// holding mag.f and ang.f.
    #[test]
    fn constructed_da_struct_expands_recursively() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <LNodeType id="MMXU_T" lnClass="MMXU">
      <DO name="A" type="WYE_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="BOOLEAN"/>
    </DOType>
    <DOType id="WYE_T" cdc="WYE">
      <DA name="phsA" fc="MX" bType="Struct" type="CMV_T"/>
    </DOType>
    <DAType id="CMV_T">
      <BDA name="cVal" bType="Struct" type="Vector"/>
      <BDA name="t" bType="Timestamp"/>
    </DAType>
    <DAType id="Vector">
      <BDA name="mag" bType="Struct" type="AnalogueValue"/>
      <BDA name="ang" bType="Struct" type="AnalogueValue"/>
    </DAType>
    <DAType id="AnalogueValue">
      <BDA name="f" bType="FLOAT32"/>
    </DAType>
  </DataTypeTemplates>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T"/>
          <LN lnClass="MMXU" inst="1" lnType="MMXU_T"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let m = build(xml, "IED1");
        let ld = m.ld_by_inst("LD0").unwrap();
        // LLN0 is at index 0 and MMXU at index 1
        let mmxu = &ld.lns[1];
        assert_eq!(mmxu.class, "MMXU");
        assert_eq!(mmxu.inst, "1");
        let a_do = mmxu.do_by_name("A").unwrap();
        // phsA is a constructed data attribute
        let phs_a = match &a_do.children[0] {
            iec61850_model::tree::DoChild::Da(da) => da,
            other => panic!("expected a data attribute, got {:?}", other),
        };
        assert_eq!(phs_a.name, "phsA");
        assert_eq!(phs_a.ty, DataAttributeType::Constructed);
        assert_eq!(phs_a.fc, FC::Mx);
        // Inside CMV_T: cVal as a Struct plus t as a timestamp
        assert_eq!(phs_a.children.len(), 2);
        let c_val = &phs_a.children[0];
        assert_eq!(c_val.name, "cVal");
        assert_eq!(c_val.ty, DataAttributeType::Constructed);
        // Inside Vector: mag and ang
        assert_eq!(c_val.children.len(), 2);
        let mag = &c_val.children[0];
        assert_eq!(mag.name, "mag");
        // Inside AnalogueValue: f as a FLOAT32
        assert_eq!(mag.children.len(), 1);
        let f = &mag.children[0];
        assert_eq!(f.name, "f");
        assert_eq!(f.ty, DataAttributeType::Float32);
        // A nested attribute has no functional constraint of its own and
        // inherits MX from its parent.
        assert_eq!(f.fc, FC::Mx);
    }

    /// A data object with a nested sub-object.
    #[test]
    fn sdo_expands_as_sub_do() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Health" type="HEALTH_T"/>
    </LNodeType>
    <DOType id="HEALTH_T" cdc="ENS">
      <DA name="stVal" fc="ST" bType="Enum" type="HealthEnum"/>
      <SDO name="Sub" type="SUB_T"/>
    </DOType>
    <DOType id="SUB_T" cdc="ING">
      <DA name="setVal" fc="SP" bType="INT32"/>
    </DOType>
    <EnumType id="HealthEnum">
      <EnumVal ord="1">Ok</EnumVal>
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
        let m = build(xml, "IED1");
        let ld = m.ld_by_inst("LD0").unwrap();
        let lln0 = &ld.lns[0];
        let health = lln0.do_by_name("Health").unwrap();
        // Children: stVal as an attribute plus Sub as a sub-object
        assert_eq!(health.children.len(), 2);
        let sub_do = match &health.children[1] {
            iec61850_model::tree::DoChild::SubDo(sd) => sd,
            other => panic!("expected a sub-object, got {:?}", other),
        };
        assert_eq!(sub_do.name, "Sub");
        // The sub-object holds one data attribute, setVal
        assert_eq!(sub_do.children.len(), 1);
    }

    /// Several logical devices: the domain index is built for each of them.
    #[test]
    fn multiple_ld_builds_domain_index() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="Enum" type="ME"/>
    </DOType>
    <EnumType id="ME"><EnumVal ord="1">on</EnumVal></EnumType>
  </DataTypeTemplates>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="WD1"><LN0 inst="" lnType="LLN0_T"/></LDevice>
        <LDevice inst="WD2"><LN0 inst="" lnType="LLN0_T"/></LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let m = build(xml, "IED1");
        assert!(m.ld_by_domain("IED1WD1").is_some());
        assert!(m.ld_by_domain("IED1WD2").is_some());
    }

    /// An ldName override: a logical device with inst=Cfg and ldName=FuncName
    /// takes FuncName as its domain.
    #[test]
    fn ld_name_overrides_domain() {
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
        <LDevice inst="Cfg" ldName="FuncName"><LN0 inst="" lnType="LLN0_T"/></LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let m = build(xml, "IED1");
        assert!(m.ld_by_domain("FuncName").is_some());
        assert!(m.ld_by_domain("IED1Cfg").is_none());
    }

    /// A missing IED yields an error rather than a panic.
    #[test]
    fn missing_ied_yields_err() {
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
        let resolved = parse_scl(xml).unwrap().resolve().unwrap();
        let err = resolved.build_model("NotThere").expect_err("must err");
        match err.kind.as_ref() {
            ErrorKind::SemanticConflict { detail } => {
                assert!(detail.contains("no IED named"), "saw `{}`", detail);
            }
            other => panic!("expected SemanticConflict, saw {:?}", other),
        }
    }

    /// An IED with no logical device yields MissingRequiredElement.
    #[test]
    fn ied_without_ld_yields_missing_element() {
        let xml = r#"<SCL>
  <IED name="IED1">
    <AccessPoint name="AP1"/>
  </IED>
</SCL>"#;
        let resolved = parse_scl(xml).unwrap().resolve().unwrap();
        let err = resolved.build_model("IED1").expect_err("must err");
        match err.kind.as_ref() {
            ErrorKind::MissingRequiredElement { name } => assert_eq!(name, "LDevice"),
            other => panic!("expected MissingRequiredElement, saw {:?}", other),
        }
    }

    /// trgOps dchg and qchg become TrgOps::DCHG | TrgOps::QCHG.
    #[test]
    fn trg_ops_propagates_to_data_attribute() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="BOOLEAN" dchg="true" qchg="true"/>
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
        let m = build(xml, "IED1");
        let lln0 = &m.ld_by_inst("LD0").unwrap().lns[0];
        let mod_do = lln0.do_by_name("Mod").unwrap();
        let st_val = match &mod_do.children[0] {
            iec61850_model::tree::DoChild::Da(da) => da,
            _ => panic!("expect DA"),
        };
        assert!(st_val.trg_ops.contains(TrgOps::DCHG));
        assert!(st_val.trg_ops.contains(TrgOps::QCHG));
        assert!(!st_val.trg_ops.contains(TrgOps::DUPD));
    }

    /// An unknown bType yields EnumValueUnknown carrying the path and the
    /// attribute.
    #[test]
    fn unknown_b_type_yields_enum_value_unknown() {
        // Stage 1 does not validate the bType string, so an unknown one never
        // reaches build_model through a parsed file; b_type_to_dat is tested
        // directly instead.
        let span = SourceSpan {
            line: 1,
            col: 1,
            byte_offset: 0,
        };
        let err = b_type_to_dat("WAT", span, "test").expect_err("must err");
        match err.kind.as_ref() {
            ErrorKind::EnumValueUnknown {
                name,
                raw_value,
                allowed,
            } => {
                assert_eq!(name, "bType");
                assert_eq!(raw_value, "WAT");
                assert!(allowed.contains(&"BOOLEAN"));
                assert!(allowed.contains(&"Struct"));
            }
            other => panic!("expected EnumValueUnknown, saw {:?}", other),
        }
    }

    /// b_type_to_dat maps ObjRef and EntryID to their special-cased types.
    #[test]
    fn b_type_special_aliases() {
        let span = SourceSpan {
            line: 0,
            col: 0,
            byte_offset: 0,
        };
        assert_eq!(
            b_type_to_dat("ObjRef", span, "x").unwrap(),
            DataAttributeType::VisibleString(129)
        );
        assert_eq!(
            b_type_to_dat("EntryID", span, "x").unwrap(),
            DataAttributeType::OctetString(8)
        );
    }

    // ---------------------------------------------------------------------
    // Data sets and control blocks
    // ---------------------------------------------------------------------

    /// A data set "Events" on LLN0 with one FCDA referencing GGIO1.Ind1.stVal
    /// in the same logical device resolves to a data set entry.
    #[test]
    fn dataset_with_fcda_resolves_via_builder() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <LNodeType id="GGIO_T" lnClass="GGIO">
      <DO name="Ind1" type="SPS_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="BOOLEAN"/>
    </DOType>
    <DOType id="SPS_T" cdc="SPS">
      <DA name="stVal" fc="ST" bType="BOOLEAN" dchg="true"/>
      <DA name="q"     fc="ST" bType="Quality" qchg="true"/>
      <DA name="t"     fc="ST" bType="Timestamp"/>
    </DOType>
  </DataTypeTemplates>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T">
            <DataSet name="Events" desc="indications">
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
            </DataSet>
          </LN0>
          <LN lnClass="GGIO" inst="1" lnType="GGIO_T"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let m = build(xml, "IED1");
        let lln0 = &m.ld_by_inst("LD0").unwrap().lns[0];
        assert_eq!(lln0.datasets.len(), 1);
        let ds = &lln0.datasets[0];
        assert_eq!(ds.name, "Events");
        assert_eq!(ds.entries.len(), 1);
        let e = &ds.entries[0];
        assert_eq!(e.ld_inst, "LD0");
        assert_eq!(e.ln_name, "GGIO1");
        assert_eq!(e.fc, FC::St);
        assert_eq!(e.do_path, vec!["Ind1".to_string(), "stVal".to_string()]);
    }

    /// An FCDA doName containing `.`, that is a sub-object path, splits into
    /// do_path segments.
    #[test]
    fn fcda_dotted_do_name_splits_into_path() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <LNodeType id="ZSTI_T" lnClass="ZSTI">
      <DO name="Pos" type="DPC_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="BOOLEAN"/>
    </DOType>
    <DOType id="DPC_T" cdc="DPC">
      <SDO name="Sub" type="SUB_T"/>
    </DOType>
    <DOType id="SUB_T" cdc="ENS">
      <DA name="stVal" fc="ST" bType="BOOLEAN"/>
    </DOType>
  </DataTypeTemplates>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T">
            <DataSet name="DS1">
              <FCDA ldInst="LD0" lnClass="ZSTI" lnInst="1" doName="Pos.Sub" daName="stVal" fc="ST"/>
            </DataSet>
          </LN0>
          <LN lnClass="ZSTI" inst="1" lnType="ZSTI_T"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let m = build(xml, "IED1");
        let ds = &m.ld_by_inst("LD0").unwrap().lns[0].datasets[0];
        let entry = &ds.entries[0];
        assert_eq!(
            entry.do_path,
            vec!["Pos".to_string(), "Sub".to_string(), "stVal".to_string()]
        );
    }

    /// Every attribute of a ReportControl reaches the model report control block.
    #[test]
    fn report_control_maps_to_rcb() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <LNodeType id="GGIO_T" lnClass="GGIO">
      <DO name="Ind1" type="SPS_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="BOOLEAN"/>
    </DOType>
    <DOType id="SPS_T" cdc="SPS">
      <DA name="stVal" fc="ST" bType="BOOLEAN" dchg="true"/>
    </DOType>
  </DataTypeTemplates>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T">
            <DataSet name="DS1">
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
            </DataSet>
            <ReportControl name="brcb1" rptID="rpt-id-1" datSet="DS1" confRev="3" buffered="true" intgPd="1000" bufTime="50">
              <TrgOps dchg="true" qchg="true"/>
              <OptFields seqNum="true" timeStamp="true"/>
            </ReportControl>
            <ReportControl name="urcb1" datSet="DS1" confRev="1" buffered="false">
              <TrgOps dchg="true"/>
            </ReportControl>
          </LN0>
          <LN lnClass="GGIO" inst="1" lnType="GGIO_T"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let m = build(xml, "IED1");
        let lln0 = &m.ld_by_inst("LD0").unwrap().lns[0];
        assert_eq!(lln0.rcbs.len(), 2);
        let brcb = &lln0.rcbs[0];
        assert_eq!(brcb.name, "brcb1");
        assert_eq!(brcb.rpt_id, "rpt-id-1");
        assert!(brcb.is_buffered);
        assert_eq!(brcb.dataset_ref, "DS1");
        assert_eq!(brcb.conf_rev, 3);
        let urcb = &lln0.rcbs[1];
        assert!(!urcb.is_buffered);
        assert_eq!(urcb.rpt_id, "");
    }

    /// A GSEControl becomes a GooseControlBlock whose goID defaults to the name.
    #[test]
    fn gse_control_maps_with_default_goid_eq_name() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <LNodeType id="GGIO_T" lnClass="GGIO">
      <DO name="Ind1" type="SPS_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="BOOLEAN"/>
    </DOType>
    <DOType id="SPS_T" cdc="SPS">
      <DA name="stVal" fc="ST" bType="BOOLEAN" dchg="true"/>
    </DOType>
  </DataTypeTemplates>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T">
            <DataSet name="DSGoose">
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
            </DataSet>
            <GSEControl name="gcb1" appID="APPID-1" datSet="DSGoose" confRev="2" type="GOOSE"/>
          </LN0>
          <LN lnClass="GGIO" inst="1" lnType="GGIO_T"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let m = build(xml, "IED1");
        let lln0 = &m.ld_by_inst("LD0").unwrap().lns[0];
        assert_eq!(lln0.gocbs.len(), 1);
        let gcb = &lln0.gocbs[0];
        assert_eq!(gcb.name, "gcb1");
        assert_eq!(gcb.dataset_ref, "DSGoose");
        assert_eq!(gcb.conf_rev, 2);
        assert_eq!(gcb.go_id, "gcb1");
    }

    /// A SampledValueControl becomes an SvControlBlock.
    #[test]
    fn smv_control_maps_to_svcb() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <LNodeType id="TVTR_T" lnClass="TVTR">
      <DO name="Vol" type="SAV_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="BOOLEAN"/>
    </DOType>
    <DOType id="SAV_T" cdc="SAV">
      <DA name="instMag" fc="MX" bType="Struct" type="AnalogueValue"/>
    </DOType>
    <DAType id="AnalogueValue">
      <BDA name="i" bType="INT32"/>
    </DAType>
  </DataTypeTemplates>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T">
            <DataSet name="DSSv">
              <FCDA ldInst="LD0" lnClass="TVTR" lnInst="1" doName="Vol" daName="instMag" fc="MX"/>
            </DataSet>
            <SampledValueControl name="svcb1" smvID="MyApp/SV1" datSet="DSSv" confRev="1" multicast="true" smpRate="80" nofASDU="1" smpMod="SmpPerPeriod"/>
          </LN0>
          <LN lnClass="TVTR" inst="1" lnType="TVTR_T"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let m = build(xml, "IED1");
        let lln0 = &m.ld_by_inst("LD0").unwrap().lns[0];
        assert_eq!(lln0.svcbs.len(), 1);
        let svcb = &lln0.svcbs[0];
        assert_eq!(svcb.name, "svcb1");
        assert_eq!(svcb.sv_id, "MyApp/SV1");
        assert_eq!(svcb.dataset_ref, "DSSv");
        assert!(svcb.is_multicast);
    }

    /// A LogControl becomes a LogControlBlock.
    #[test]
    fn log_control_maps_to_lcb() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <LNodeType id="GGIO_T" lnClass="GGIO">
      <DO name="Ind1" type="SPS_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="BOOLEAN"/>
    </DOType>
    <DOType id="SPS_T" cdc="SPS">
      <DA name="stVal" fc="ST" bType="BOOLEAN" dchg="true"/>
    </DOType>
  </DataTypeTemplates>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T">
            <DataSet name="DSLog">
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
            </DataSet>
            <LogControl name="lcb1" datSet="DSLog" logName="MyLog" logEna="true" intgPd="0" reasonCode="true" bufTime="100">
              <TrgOps dchg="true"/>
            </LogControl>
          </LN0>
          <LN lnClass="GGIO" inst="1" lnType="GGIO_T"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let m = build(xml, "IED1");
        let lln0 = &m.ld_by_inst("LD0").unwrap().lns[0];
        assert_eq!(lln0.lcbs.len(), 1);
        let lcb = &lln0.lcbs[0];
        assert_eq!(lcb.name, "lcb1");
        assert_eq!(lcb.dataset_ref, "DSLog");
        assert_eq!(lcb.log_ref, "MyLog");
    }

    // ---------------------------------------------------------------------
    // DOI, SDI and DAI default-value overrides
    // ---------------------------------------------------------------------

    fn snapshot_da(
        m: &IedModel,
        ld_inst: &str,
        ln_class: &str,
        ln_inst: &str,
        do_name: &str,
        da_path: &[&str],
    ) -> MmsValue {
        let ld = m.ld_by_inst(ld_inst).expect("ld");
        let ln = ld
            .lns
            .iter()
            .find(|n| n.class == ln_class && n.inst == ln_inst)
            .expect("ln");
        let dobj = ln.do_by_name(do_name).expect("do");
        // The first segment of da_path is a data attribute or sub-object name;
        // this helper handles a single chain of attributes.
        let mut current_da: Option<&DataAttribute> = None;
        for (i, seg) in da_path.iter().enumerate() {
            if i == 0 {
                match dobj.child_by_name(seg).expect("child") {
                    iec61850_model::tree::DoChild::Da(d) => current_da = Some(d),
                    _ => panic!("expected leaf DA at first seg"),
                }
            } else {
                let cur = current_da.expect("DA");
                current_da = Some(cur.child_by_name(seg).expect("BDA"));
            }
        }
        current_da.expect("DA").snapshot()
    }

    /// A DAI overrides the default of a BOOLEAN attribute directly.
    #[test]
    fn dai_overrides_boolean_default() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="ena" fc="CF" bType="BOOLEAN"/>
    </DOType>
  </DataTypeTemplates>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T">
            <DOI name="Mod">
              <DAI name="ena"><Val>true</Val></DAI>
            </DOI>
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let m = build(xml, "IED1");
        let v = snapshot_da(&m, "LD0", "LLN0", "", "Mod", &["ena"]);
        assert_eq!(v, MmsValue::Boolean(true));
    }

    /// A DAI overrides an INT32.
    #[test]
    fn dai_overrides_int32_default() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ING_T"/>
    </LNodeType>
    <DOType id="ING_T" cdc="ING">
      <DA name="setVal" fc="SP" bType="INT32"/>
    </DOType>
  </DataTypeTemplates>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T">
            <DOI name="Mod">
              <DAI name="setVal"><Val>-42</Val></DAI>
            </DOI>
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let m = build(xml, "IED1");
        let v = snapshot_da(&m, "LD0", "LLN0", "", "Mod", &["setVal"]);
        assert_eq!(v, MmsValue::Integer(-42));
    }

    /// Edge whitespace written as a character reference reaches the value and
    /// is rejected the same way literal edge whitespace is: the parser hands
    /// the integer converter the space the document asked for.
    #[test]
    fn dai_int32_rejects_char_ref_edge_whitespace() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ING_T"/>
    </LNodeType>
    <DOType id="ING_T" cdc="ING">
      <DA name="setVal" fc="SP" bType="INT32"/>
    </DOType>
  </DataTypeTemplates>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T">
            <DOI name="Mod">
              <DAI name="setVal"><Val>&#32;5</Val></DAI>
            </DOI>
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let resolved = parse_scl(xml).expect("parse").resolve().expect("resolve");
        let err = resolved
            .build_model("IED1")
            .expect_err("an INT32 value with edge whitespace must be rejected");
        match err.kind.as_ref() {
            ErrorKind::AttributeValueInvalid {
                expected_type,
                raw_value,
                cause,
                ..
            } => {
                assert_eq!(expected_type, "INT32");
                // The space the character reference carries reaches the value.
                assert_eq!(raw_value, " 5");
                assert_eq!(
                    cause.as_deref(),
                    Some("leading and trailing whitespace are not allowed")
                );
            }
            other => panic!("expected AttributeValueInvalid, got {:?}", other),
        }
    }

    /// A DAI overrides an enumeration, resolved by name through its EnumType.
    #[test]
    fn dai_overrides_enum_by_name() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="ctlModel" fc="CF" bType="Enum" type="CtlModelKind"/>
    </DOType>
    <EnumType id="CtlModelKind">
      <EnumVal ord="0">status-only</EnumVal>
      <EnumVal ord="1">direct-with-normal-security</EnumVal>
      <EnumVal ord="2">sbo-with-normal-security</EnumVal>
    </EnumType>
  </DataTypeTemplates>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T">
            <DOI name="Mod">
              <DAI name="ctlModel"><Val>direct-with-normal-security</Val></DAI>
            </DOI>
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let m = build(xml, "IED1");
        let v = snapshot_da(&m, "LD0", "LLN0", "", "Mod", &["ctlModel"]);
        assert_eq!(v, MmsValue::Integer(1));
    }

    /// A DAI overrides an enumeration, falling back to an integer ordinal.
    #[test]
    fn dai_overrides_enum_by_ord_fallback() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="ctlModel" fc="CF" bType="Enum" type="CtlModelKind"/>
    </DOType>
    <EnumType id="CtlModelKind">
      <EnumVal ord="0">status-only</EnumVal>
      <EnumVal ord="2">sbo-with-normal-security</EnumVal>
    </EnumType>
  </DataTypeTemplates>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T">
            <DOI name="Mod">
              <DAI name="ctlModel"><Val>2</Val></DAI>
            </DOI>
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let m = build(xml, "IED1");
        let v = snapshot_da(&m, "LD0", "LLN0", "", "Mod", &["ctlModel"]);
        assert_eq!(v, MmsValue::Integer(2));
    }

    /// An SDI descends into a constructed attribute and the DAI writes a FLOAT32.
    #[test]
    fn sdi_navigates_into_constructed_da_and_sets_float() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <LNodeType id="MMXU_T" lnClass="MMXU">
      <DO name="A" type="WYE_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="BOOLEAN"/>
    </DOType>
    <DOType id="WYE_T" cdc="WYE">
      <DA name="phsA" fc="MX" bType="Struct" type="CMV_T"/>
    </DOType>
    <DAType id="CMV_T">
      <BDA name="cVal" bType="Struct" type="Vector"/>
    </DAType>
    <DAType id="Vector">
      <BDA name="mag" bType="Struct" type="AnalogueValue"/>
    </DAType>
    <DAType id="AnalogueValue">
      <BDA name="f" bType="FLOAT32"/>
    </DAType>
  </DataTypeTemplates>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T"/>
          <LN lnClass="MMXU" inst="1" lnType="MMXU_T">
            <DOI name="A">
              <SDI name="phsA">
                <SDI name="cVal">
                  <SDI name="mag">
                    <DAI name="f"><Val>1.5</Val></DAI>
                  </SDI>
                </SDI>
              </SDI>
            </DOI>
          </LN>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let m = build(xml, "IED1");
        let v = snapshot_da(&m, "LD0", "MMXU", "1", "A", &["phsA", "cVal", "mag", "f"]);
        match v {
            MmsValue::Float32(x) => assert!((x - 1.5_f32).abs() < 1e-6),
            other => panic!("expected Float32, got {:?}", other),
        }
    }

    /// An SDI descends into a sub-object and the DAI writes an INT32.
    #[test]
    fn sdi_navigates_into_sub_do_and_sets_int() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Health" type="HEALTH_T"/>
    </LNodeType>
    <DOType id="HEALTH_T" cdc="ENS">
      <DA name="stVal" fc="ST" bType="Enum" type="HealthEnum"/>
      <SDO name="Sub" type="SUB_T"/>
    </DOType>
    <DOType id="SUB_T" cdc="ING">
      <DA name="setVal" fc="SP" bType="INT32"/>
    </DOType>
    <EnumType id="HealthEnum">
      <EnumVal ord="1">Ok</EnumVal>
    </EnumType>
  </DataTypeTemplates>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T">
            <DOI name="Health">
              <SDI name="Sub">
                <DAI name="setVal"><Val>7</Val></DAI>
              </SDI>
            </DOI>
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let m = build(xml, "IED1");
        // The path is Health, then the sub-object Sub, then the attribute
        // setVal, so the lookup goes through do_by_name and child_by_name.
        let lln0 = &m.ld_by_inst("LD0").unwrap().lns[0];
        let health = lln0.do_by_name("Health").unwrap();
        let sub = match health.child_by_name("Sub").unwrap() {
            iec61850_model::tree::DoChild::SubDo(sd) => sd,
            _ => panic!("expected SubDo"),
        };
        let set_val = match sub.child_by_name("setVal").unwrap() {
            iec61850_model::tree::DoChild::Da(d) => d,
            _ => panic!("expected DA"),
        };
        assert_eq!(set_val.snapshot(), MmsValue::Integer(7));
    }

    /// A malformed BOOLEAN literal yields AttributeValueInvalid.
    #[test]
    fn invalid_boolean_literal_yields_err() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="ena" fc="CF" bType="BOOLEAN"/>
    </DOType>
  </DataTypeTemplates>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T">
            <DOI name="Mod">
              <DAI name="ena"><Val>YES</Val></DAI>
            </DOI>
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let resolved = parse_scl(xml).unwrap().resolve().unwrap();
        let err = resolved.build_model("IED1").expect_err("must err");
        match err.kind.as_ref() {
            ErrorKind::AttributeValueInvalid {
                name, raw_value, ..
            } => {
                assert_eq!(name, "Val");
                assert_eq!(raw_value, "YES");
            }
            other => panic!("expected AttributeValueInvalid, saw {:?}", other),
        }
    }

    /// A FLOAT32 written with a comma yields AttributeValueInvalid.
    #[test]
    fn float_with_comma_rejected() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ASG_T"/>
    </LNodeType>
    <DOType id="ASG_T" cdc="ASG">
      <DA name="setMag" fc="SP" bType="FLOAT32"/>
    </DOType>
  </DataTypeTemplates>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T">
            <DOI name="Mod">
              <DAI name="setMag"><Val>1,5</Val></DAI>
            </DOI>
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let resolved = parse_scl(xml).unwrap().resolve().unwrap();
        let err = resolved.build_model("IED1").expect_err("must err");
        match err.kind.as_ref() {
            ErrorKind::AttributeValueInvalid { name, .. } => assert_eq!(name, "Val"),
            other => panic!("expected AttributeValueInvalid, saw {:?}", other),
        }
    }

    /// A VisString32 longer than its limit yields AttributeValueInvalid.
    #[test]
    fn vis_string_length_cap_enforced() {
        let xml = r#"<SCL>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="NamPlt" type="LPL_T"/>
    </LNodeType>
    <DOType id="LPL_T" cdc="LPL">
      <DA name="d" fc="DC" bType="VisString32"/>
    </DOType>
  </DataTypeTemplates>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T">
            <DOI name="NamPlt">
              <DAI name="d"><Val>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</Val></DAI>
            </DOI>
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let resolved = parse_scl(xml).unwrap().resolve().unwrap();
        let err = resolved.build_model("IED1").expect_err("must err");
        match err.kind.as_ref() {
            ErrorKind::AttributeValueInvalid { name, cause, .. } => {
                assert_eq!(name, "Val");
                assert!(cause.as_deref().unwrap_or("").contains("exceeds the limit"));
            }
            other => panic!("expected AttributeValueInvalid, saw {:?}", other),
        }
    }

    /// A DAI naming an attribute the model does not have is logged and skipped,
    /// leaving the rest of the build intact.
    #[test]
    fn dai_with_unknown_name_is_skipped_silently() {
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
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T">
            <DOI name="Mod">
              <DAI name="WhoEvenIsThis"><Val>true</Val></DAI>
            </DOI>
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        // The build must succeed rather than panic.
        let _m = build(xml, "IED1");
    }

    /// An FCDA referencing a logical node that does not exist makes the model
    /// builder report an unresolved data set entry, which build_model wraps in
    /// SemanticConflict rather than swallowing.
    #[test]
    fn dataset_with_unresolved_fcda_yields_err() {
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
        <LDevice inst="LD0">
          <LN0 inst="" lnType="LLN0_T">
            <DataSet name="DSBad">
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="9" doName="DoesNotExist" daName="stVal" fc="ST"/>
            </DataSet>
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>"#;
        let resolved = parse_scl(xml).unwrap().resolve().unwrap();
        let err = resolved.build_model("IED1").expect_err("must err");
        match err.kind.as_ref() {
            ErrorKind::SemanticConflict { detail } => {
                assert!(
                    detail.contains("model builder") || detail.contains("data set"),
                    "saw `{}`",
                    detail
                );
            }
            other => panic!("expected SemanticConflict, saw {:?}", other),
        }
    }
}
