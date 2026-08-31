//! Round-trip gate on `examples/models/demo.cid`.
//!
//! The file is loaded into an `IedModel`, serialized back to SCL, re-parsed and
//! compared through [`summarize_model`], the canonical text form of a model.
//! The comparison covers everything the runtime model retains: the LD/LN/DO/DA
//! tree with types, functional constraints, trigger options and values, plus
//! the data sets and control blocks. Labels that the model does not carry (CDC
//! names, descriptions, the Communication section) are outside the round trip
//! and are gated by `iec61850-scl/tests/demo_cid.rs` instead.
//!
//! The model is also handed to `MmsDeviceModel`, which is what an `IedServer`
//! serves, so a CID that parses but cannot be exposed over MMS fails here.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use iec61850_model::cb::{
    GooseControlBlock, LogControlBlock, ReportControlBlock, SettingGroupControlBlock,
};
use iec61850_model::tree::{
    DataAttribute, DataObject, DataSet, DoChild, IedModel, LogicalDevice, LogicalNode,
};
use iec61850_model::types::{DataAttributeType, TrgOps};
use iec61850_model::value::MmsValue;
use iec61850_scl::summarize::summarize_model;
use iec61850_server::MmsDeviceModel;

const IED_NAME: &str = "DemoIED";

/// The CID ships inside this crate, so the path resolves in a published
/// package as well as in the repository.
const DEMO_CID: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/models/demo.cid");

fn build_model(xml: &str, context: &str) -> IedModel {
    let raw = iec61850_scl::parse_scl(xml)
        .unwrap_or_else(|e| panic!("parse_scl failed for {context}: {e}"));
    let resolved = iec61850_scl::ResolvedScl::from_raw(raw)
        .unwrap_or_else(|e| panic!("ResolvedScl::from_raw failed for {context}: {e}"));
    resolved
        .build_model(IED_NAME)
        .unwrap_or_else(|e| panic!("build_model({IED_NAME}) failed for {context}: {e}"))
}

#[test]
fn demo_cid_survives_a_model_to_scl_round_trip() {
    let original_xml =
        std::fs::read_to_string(DEMO_CID).unwrap_or_else(|e| panic!("cannot read {DEMO_CID}: {e}"));

    let first = build_model(&original_xml, "demo.cid");
    let emitted_xml = emit_scl(&first);
    let second = build_model(&emitted_xml, "the re-emitted SCL");

    let want = summarize_model(&first);
    let got = summarize_model(&second);
    if want != got {
        let diff = want
            .lines()
            .zip(got.lines())
            .enumerate()
            .find(|(_, (a, b))| a != b)
            .map(|(i, (a, b))| {
                format!(
                    "line {}:\n  from demo.cid: {a}\n  re-parsed:     {b}",
                    i + 1
                )
            })
            .unwrap_or_else(|| {
                format!(
                    "no differing line; {} lines from demo.cid against {} re-parsed",
                    want.lines().count(),
                    got.lines().count()
                )
            });
        panic!("the model is not preserved across an SCL round trip.\n{diff}\n\nre-emitted SCL:\n{emitted_xml}");
    }
}

#[test]
fn demo_cid_loads_into_the_server_model() {
    let xml =
        std::fs::read_to_string(DEMO_CID).unwrap_or_else(|e| panic!("cannot read {DEMO_CID}: {e}"));
    let model = build_model(&xml, "demo.cid");

    let mms_model = MmsDeviceModel::from_ied_model(&model)
        .unwrap_or_else(|e| panic!("MmsDeviceModel::from_ied_model failed: {e}"));
    assert!(
        mms_model.domain("DemoIEDLD0").is_some(),
        "MMS domain DemoIEDLD0 is missing from the server model"
    );
}

// Model to SCL

/// Shared EnumType for every `bType="Enum"` attribute the emitter writes.
///
/// The runtime model keeps an enumerated value as its ordinal and drops the
/// enumeration it came from, so the emitter regenerates one enumeration holding
/// every ordinal in use.
const ENUM_TYPE_ID: &str = "ET_Emitted";

/// Serialize `model` as an SCL document that rebuilds an equal model.
///
/// Only what the runtime model carries is written. Every type in
/// `DataTypeTemplates` is generated per instance path, so the identifiers are
/// unique but bear no relation to the identifiers of the source document.
///
/// # Panics
///
/// Panics on a model feature the emitter cannot express (a DO array, or a
/// non-default value of a type with no SCL literal form). Such a model would be
/// silently truncated otherwise, which would turn this gate green for the wrong
/// reason.
fn emit_scl(model: &IedModel) -> String {
    let mut types = TypeTemplates::default();
    let mut body = String::new();

    let _ = writeln!(body, r#"<SCL version="2007" revision="B" release="4">"#);
    let _ = writeln!(body, r#"  <IED name="{}">"#, esc(&model.ied_name));
    let _ = writeln!(body, r#"    <AccessPoint name="AP1">"#);
    let _ = writeln!(body, "      <Server>");
    for ld in &model.lds {
        emit_ld(&mut body, ld, &mut types);
    }
    let _ = writeln!(body, "      </Server>");
    let _ = writeln!(body, "    </AccessPoint>");
    let _ = writeln!(body, "  </IED>");
    body.push_str(&types.render());
    let _ = writeln!(body, "</SCL>");
    body
}

#[derive(Default)]
struct TypeTemplates {
    ln_node_types: Vec<String>,
    do_types: Vec<String>,
    da_types: Vec<String>,
    enum_ords: BTreeSet<i64>,
}

impl TypeTemplates {
    fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "  <DataTypeTemplates>");
        for t in self
            .ln_node_types
            .iter()
            .chain(&self.do_types)
            .chain(&self.da_types)
        {
            out.push_str(t);
        }
        // Ordinal 0 is always present: it is the default of an enumerated
        // attribute that carries no instance value.
        let _ = writeln!(out, r#"    <EnumType id="{ENUM_TYPE_ID}">"#);
        for ord in self.enum_ords.iter().copied().chain(std::iter::once(0)) {
            let _ = writeln!(out, r#"      <EnumVal ord="{ord}">e{ord}</EnumVal>"#);
        }
        let _ = writeln!(out, "    </EnumType>");
        let _ = writeln!(out, "  </DataTypeTemplates>");
        out
    }
}

fn emit_ld(out: &mut String, ld: &LogicalDevice, types: &mut TypeTemplates) {
    let ld_name_attr = match &ld.ld_name {
        Some(n) => format!(r#" ldName="{}""#, esc(n)),
        None => String::new(),
    };
    let _ = writeln!(
        out,
        r#"        <LDevice inst="{}"{ld_name_attr}>"#,
        esc(&ld.inst)
    );
    for ln in &ld.lns {
        emit_ln(out, ld, ln, types);
    }
    let _ = writeln!(out, "        </LDevice>");
}

fn emit_ln(out: &mut String, ld: &LogicalDevice, ln: &LogicalNode, types: &mut TypeTemplates) {
    let ln_full = ln.full_name();
    let ln_type_id = format!("LNT_{}_{}", ld.inst, ln_full);

    let mut ln_body = String::new();
    for value in collect_values(ln) {
        ln_body.push_str(&value);
    }
    for ds in &ln.datasets {
        emit_dataset(&mut ln_body, ld, ds);
    }
    for rcb in &ln.rcbs {
        emit_rcb(&mut ln_body, rcb);
    }
    for gocb in &ln.gocbs {
        emit_gocb(&mut ln_body, gocb);
    }
    for lcb in &ln.lcbs {
        emit_lcb(&mut ln_body, lcb);
    }
    if let Some(sgcb) = &ln.sgcb {
        emit_sgcb(&mut ln_body, sgcb);
    }

    let is_ln0 = ln.class == "LLN0";
    let open = if is_ln0 {
        format!(
            r#"          <LN0 lnClass="{}" inst="{}" lnType="{}""#,
            esc(&ln.class),
            esc(&ln.inst),
            esc(&ln_type_id)
        )
    } else {
        format!(
            r#"          <LN prefix="{}" lnClass="{}" inst="{}" lnType="{}""#,
            esc(&ln.prefix),
            esc(&ln.class),
            esc(&ln.inst),
            esc(&ln_type_id)
        )
    };
    if ln_body.is_empty() {
        let _ = writeln!(out, "{open}/>");
    } else {
        let _ = writeln!(out, "{open}>");
        out.push_str(&ln_body);
        let _ = writeln!(out, "          </{}>", if is_ln0 { "LN0" } else { "LN" });
    }

    // Type templates for this LN instance.
    let mut lnt = String::new();
    let _ = writeln!(
        lnt,
        r#"    <LNodeType id="{}" lnClass="{}">"#,
        esc(&ln_type_id),
        esc(&ln.class)
    );
    for dobj in &ln.dos {
        let do_type_id = format!("DOT_{}_{}_{}", ld.inst, ln_full, dobj.name);
        let _ = writeln!(
            lnt,
            r#"      <DO name="{}" type="{}"/>"#,
            esc(&dobj.name),
            esc(&do_type_id)
        );
        emit_do_type(&do_type_id, dobj, types);
    }
    let _ = writeln!(lnt, "    </LNodeType>");
    types.ln_node_types.push(lnt);
}

fn emit_do_type(id: &str, dobj: &DataObject, types: &mut TypeTemplates) {
    assert!(
        dobj.array_count.is_none(),
        "DO {} is an array; the emitter has no SCL form for it",
        dobj.name
    );
    let mut body = String::new();
    let _ = writeln!(body, r#"    <DOType id="{}" cdc="ENS">"#, esc(id));
    for child in &dobj.children {
        match child {
            DoChild::SubDo(sub) => {
                let sub_id = format!("{id}_{}", sub.name);
                let _ = writeln!(
                    body,
                    r#"      <SDO name="{}" type="{}"/>"#,
                    esc(&sub.name),
                    esc(&sub_id)
                );
                emit_do_type(&sub_id, sub, types);
            }
            DoChild::Da(da) => {
                let da_type_id = format!("{id}_{}", da.name);
                let _ = writeln!(
                    body,
                    r#"      <DA name="{}" fc="{}" {}{}/>"#,
                    esc(&da.name),
                    da.fc.as_str(),
                    b_type_attrs(da, &da_type_id, types),
                    trg_ops_attrs(da.trg_ops)
                );
                if da.ty == DataAttributeType::Constructed {
                    emit_da_type(&da_type_id, da, types);
                }
            }
        }
    }
    let _ = writeln!(body, "    </DOType>");
    types.do_types.push(body);
}

fn emit_da_type(id: &str, da: &DataAttribute, types: &mut TypeTemplates) {
    let mut body = String::new();
    let _ = writeln!(body, r#"    <DAType id="{}">"#, esc(id));
    for child in &da.children {
        let child_id = format!("{id}_{}", child.name);
        let _ = writeln!(
            body,
            r#"      <BDA name="{}" {}/>"#,
            esc(&child.name),
            b_type_attrs(child, &child_id, types)
        );
        if child.ty == DataAttributeType::Constructed {
            emit_da_type(&child_id, child, types);
        }
    }
    let _ = writeln!(body, "    </DAType>");
    types.da_types.push(body);
}

/// `bType` plus the `type` reference an Enum or Struct attribute needs.
fn b_type_attrs(da: &DataAttribute, struct_type_id: &str, types: &mut TypeTemplates) -> String {
    use DataAttributeType as T;
    match da.ty {
        T::Constructed => format!(r#"bType="Struct" type="{}""#, esc(struct_type_id)),
        T::Enumerated => {
            if let MmsValue::Integer(ord) = da.snapshot() {
                types.enum_ords.insert(ord);
            }
            format!(r#"bType="Enum" type="{ENUM_TYPE_ID}""#)
        }
        other => format!(r#"bType="{}""#, b_type_name(other, &da.name)),
    }
}

/// SCL `bType` token for a model attribute type.
///
/// The mapping is the inverse of the parser's, restricted to the types it can
/// produce; `OctetString(8)` is written back as `EntryID` and `CodedEnum` as
/// `Dbpos`, the tokens the parser maps onto them.
fn b_type_name(ty: DataAttributeType, da_name: &str) -> &'static str {
    use DataAttributeType as T;
    match ty {
        T::Boolean => "BOOLEAN",
        T::Int8 => "INT8",
        T::Int16 => "INT16",
        T::Int32 => "INT32",
        T::Int64 => "INT64",
        T::Int128 => "INT128",
        T::Int8U => "INT8U",
        T::Int16U => "INT16U",
        T::Int24U => "INT24U",
        T::Int32U => "INT32U",
        T::Float32 => "FLOAT32",
        T::Float64 => "FLOAT64",
        T::OctetString(8) => "EntryID",
        T::OctetString(64) => "Octet64",
        T::VisibleString(32) => "VisString32",
        T::VisibleString(64) => "VisString64",
        T::VisibleString(65) => "VisString65",
        T::VisibleString(129) => "VisString129",
        T::VisibleString(255) => "VisString255",
        T::UnicodeString255 => "Unicode255",
        T::Timestamp => "Timestamp",
        T::Quality => "Quality",
        T::Check => "Check",
        T::CodedEnum => "Dbpos",
        T::Currency => "Currency",
        T::OptFlds => "OptFlds",
        T::TrgOpsBits => "TrgOps",
        T::EntryTime => "EntryTime",
        T::PhyComAddr => "PhyComAddr",
        other => panic!("attribute {da_name}: no SCL bType for {other:?}"),
    }
}

fn trg_ops_attrs(trg: TrgOps) -> String {
    format!(
        r#" dchg="{}" qchg="{}" dupd="{}""#,
        trg.contains(TrgOps::DCHG),
        trg.contains(TrgOps::QCHG),
        trg.contains(TrgOps::DUPD)
    )
}

// Instance values

/// A `<DOI>` / `<SDI>` / `<DAI>` subtree of instance values.
#[derive(Default)]
struct ValueTree {
    children: BTreeMap<String, ValueTree>,
    literal: Option<String>,
}

impl ValueTree {
    fn insert(&mut self, path: &[String], literal: String) {
        match path {
            [] => self.literal = Some(literal),
            [head, rest @ ..] => self
                .children
                .entry(head.clone())
                .or_default()
                .insert(rest, literal),
        }
    }
}

/// Render every attribute of `ln` whose value differs from the type default.
///
/// Values reach the runtime model only through `<DOI>` / `<SDI>` / `<DAI>`; a
/// `<Val>` inside `DataTypeTemplates` is parsed but not applied, so it cannot
/// carry a value across the round trip.
fn collect_values(ln: &LogicalNode) -> Vec<String> {
    let mut roots: BTreeMap<String, ValueTree> = BTreeMap::new();
    for dobj in &ln.dos {
        let mut tree = ValueTree::default();
        collect_do_values(dobj, &mut Vec::new(), &mut tree);
        if !tree.children.is_empty() {
            roots.insert(dobj.name.clone(), tree);
        }
    }

    roots
        .into_iter()
        .map(|(name, tree)| {
            let mut out = String::new();
            let _ = writeln!(out, r#"            <DOI name="{}">"#, esc(&name));
            render_value_children(&mut out, &tree, 14);
            let _ = writeln!(out, "            </DOI>");
            out
        })
        .collect()
}

fn collect_do_values(dobj: &DataObject, path: &mut Vec<String>, tree: &mut ValueTree) {
    for child in &dobj.children {
        match child {
            DoChild::SubDo(sub) => {
                path.push(sub.name.clone());
                collect_do_values(sub, path, tree);
                path.pop();
            }
            DoChild::Da(da) => {
                path.push(da.name.clone());
                collect_da_values(da, path, tree);
                path.pop();
            }
        }
    }
}

fn collect_da_values(da: &DataAttribute, path: &mut Vec<String>, tree: &mut ValueTree) {
    if da.ty == DataAttributeType::Constructed {
        for child in &da.children {
            path.push(child.name.clone());
            collect_da_values(child, path, tree);
            path.pop();
        }
        return;
    }
    let value = da.snapshot();
    if value == MmsValue::default_for(da.ty) {
        return;
    }
    tree.insert(path, value_literal(&value, &da.name));
}

fn render_value_children(out: &mut String, tree: &ValueTree, indent: usize) {
    let pad = " ".repeat(indent);
    for (name, child) in &tree.children {
        match &child.literal {
            Some(literal) => {
                let _ = writeln!(
                    out,
                    r#"{pad}<DAI name="{}"><Val>{}</Val></DAI>"#,
                    esc(name),
                    esc(literal)
                );
            }
            None => {
                let _ = writeln!(out, r#"{pad}<SDI name="{}">"#, esc(name));
                render_value_children(out, child, indent + 2);
                let _ = writeln!(out, "{pad}</SDI>");
            }
        }
    }
}

/// SCL literal for a non-default attribute value.
///
/// # Panics
///
/// Panics for a value type that has no `<Val>` literal in IEC 61850-6; leaving
/// it out would drop the value and still let the round trip compare equal.
fn value_literal(value: &MmsValue, da_name: &str) -> String {
    match value {
        MmsValue::Boolean(b) => b.to_string(),
        MmsValue::Integer(i) => i.to_string(),
        MmsValue::Unsigned(u) => u.to_string(),
        MmsValue::Float32(f) => format!("{f:?}"),
        MmsValue::Float64(f) => format!("{f:?}"),
        MmsValue::VisibleString(s) | MmsValue::MmsString(s) => s.clone(),
        other => panic!("attribute {da_name}: no SCL literal for {other:?}"),
    }
}

// Data sets and control blocks

fn emit_dataset(out: &mut String, ld: &LogicalDevice, ds: &DataSet) {
    let _ = writeln!(out, r#"            <DataSet name="{}">"#, esc(&ds.name));
    for entry in &ds.entries {
        // The parser rebuilds ln_name as prefix + class + inst, so the three
        // parts are recovered from the referenced LN when it is in this LD.
        let (prefix, class, inst) = match ld.ln_by_name(&entry.ln_name) {
            Some(ln) => (ln.prefix.clone(), ln.class.clone(), ln.inst.clone()),
            None => (String::new(), entry.ln_name.clone(), String::new()),
        };
        let do_name = entry.do_path.first().cloned().unwrap_or_default();
        let da_name = if entry.do_path.len() > 1 {
            format!(r#" daName="{}""#, esc(&entry.do_path[1..].join(".")))
        } else {
            String::new()
        };
        let ix = match entry.array_index {
            Some(i) => format!(r#" ix="{i}""#),
            None => String::new(),
        };
        let _ = writeln!(
            out,
            r#"              <FCDA ldInst="{}" prefix="{}" lnClass="{}" lnInst="{}" doName="{}"{da_name} fc="{}"{ix}/>"#,
            esc(&entry.ld_inst),
            esc(&prefix),
            esc(&class),
            esc(&inst),
            esc(&do_name),
            entry.fc.as_str()
        );
    }
    let _ = writeln!(out, "            </DataSet>");
}

fn emit_rcb(out: &mut String, rcb: &ReportControlBlock) {
    use iec61850_model::cb::OptFlds;
    let _ = writeln!(
        out,
        r#"            <ReportControl name="{}" rptID="{}" datSet="{}" buffered="{}" confRev="{}" bufTime="{}" intgPd="{}">"#,
        esc(&rcb.name),
        esc(&rcb.rpt_id),
        esc(&rcb.dataset_ref),
        rcb.is_buffered,
        rcb.conf_rev,
        rcb.buf_tm_ms,
        rcb.intg_pd_ms
    );
    let _ = writeln!(
        out,
        r#"              <TrgOps dchg="{}" qchg="{}" dupd="{}" period="{}" gi="{}"/>"#,
        rcb.trg_ops.contains(TrgOps::DCHG),
        rcb.trg_ops.contains(TrgOps::QCHG),
        rcb.trg_ops.contains(TrgOps::DUPD),
        rcb.trg_ops.contains(TrgOps::INTEGRITY),
        rcb.trg_ops.contains(TrgOps::GI)
    );
    let o = rcb.opt_flds;
    let _ = writeln!(
        out,
        r#"              <OptFields seqNum="{}" timeStamp="{}" dataSet="{}" reasonCode="{}" dataRef="{}" entryID="{}" configRef="{}" bufOvfl="{}" segmentation="{}"/>"#,
        o.contains(OptFlds::SEQ_NUM),
        o.contains(OptFlds::TIME_STAMP),
        o.contains(OptFlds::DATA_SET),
        o.contains(OptFlds::REASON),
        o.contains(OptFlds::DATA_REFERENCE),
        o.contains(OptFlds::ENTRY_ID),
        o.contains(OptFlds::CONF_REV),
        o.contains(OptFlds::BUFFER_OVERFLOW),
        o.contains(OptFlds::SEGMENTATION)
    );
    let _ = writeln!(out, "            </ReportControl>");
}

fn emit_gocb(out: &mut String, gocb: &GooseControlBlock) {
    // The parser derives goID from the GSEControl name, so appID is free to
    // carry the goID without changing the rebuilt block.
    let _ = writeln!(
        out,
        r#"            <GSEControl name="{}" appID="{}" datSet="{}" confRev="{}" type="GOOSE"/>"#,
        esc(&gocb.name),
        esc(&gocb.go_id),
        esc(&gocb.dataset_ref),
        gocb.conf_rev
    );
}

fn emit_lcb(out: &mut String, lcb: &LogControlBlock) {
    let _ = writeln!(
        out,
        r#"            <LogControl name="{}" datSet="{}" logName="{}"/>"#,
        esc(&lcb.name),
        esc(&lcb.dataset_ref),
        esc(&lcb.log_ref)
    );
}

fn emit_sgcb(out: &mut String, sgcb: &SettingGroupControlBlock) {
    let resv = if sgcb.has_resv_tms {
        format!(r#" resvTms="{}""#, sgcb.default_resv_tms_s)
    } else {
        String::new()
    };
    let _ = writeln!(
        out,
        r#"            <SettingControl numOfSGs="{}" actSG="{}"{resv}/>"#,
        sgcb.num_of_sg, sgcb.act_sg
    );
}

/// Escape the five XML metacharacters so the emitted document stays well formed.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}
