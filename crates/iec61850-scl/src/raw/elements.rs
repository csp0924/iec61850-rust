//! Raw structures for the SCL elements. Structure only; the parsing logic
//! lives in [`crate::parser`].
//!
//! A type identifier is always a `String` at this stage; stage 2,
//! [`crate::resolved`], turns each reference into the type it names.
//!
//! Covered here: IED, AccessPoint, Server, LDevice, LN, DOI, DAI, DataSet, the
//! control blocks, and the DataTypeTemplates type system. The Substation and
//! Communication sections have placeholders only; the parser skips those
//! subtrees and emits a `tracing::warn!` naming the element, line and column.

use std::collections::BTreeMap;

use crate::error::SourceSpan;

// ------------------------------------------------------------------------
// SCL Header, reduced to the fields the parser needs
// ------------------------------------------------------------------------

/// The `<Header>` element.
#[derive(Debug, Clone, Default)]
pub struct Header {
    /// The `id` attribute, which names the project.
    pub id: String,
    /// The `version` attribute.
    pub version: Option<String>,
    /// The `revision` attribute.
    pub revision: Option<String>,
    /// The `toolID` attribute, naming the tool that produced the file.
    pub tool_id: Option<String>,
}

// ------------------------------------------------------------------------
// The IED tree: IED, AccessPoint, Server, LDevice, LN, DOI, DAI, SDI
// ------------------------------------------------------------------------

/// An `<IED>` element.
#[derive(Debug, Clone)]
pub struct RawIed {
    /// The `name` attribute.
    pub name: String,
    /// The `desc` attribute.
    pub desc: Option<String>,
    /// The `manufacturer` attribute.
    pub manufacturer: Option<String>,
    /// The `configVersion` attribute.
    pub config_version: Option<String>,
    /// The `<AccessPoint>` children.
    pub access_points: Vec<RawAccessPoint>,
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}

/// An `<AccessPoint>` element.
#[derive(Debug, Clone)]
pub struct RawAccessPoint {
    /// The `name` attribute.
    pub name: String,
    /// The `<Server>` child, if the access point declares one.
    pub server: Option<RawServer>,
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}

/// A `<Server>` element.
#[derive(Debug, Clone, Default)]
pub struct RawServer {
    /// The `<Authentication>` child, if present.
    pub authentication: Option<Authentication>,
    /// The `<LDevice>` children.
    pub logical_devices: Vec<RawLogicalDevice>,
}

/// An `<LDevice>` element.
#[derive(Debug, Clone)]
pub struct RawLogicalDevice {
    /// The `inst` attribute.
    pub inst: String,
    /// The `ldName` attribute, which replaces `ied_name + inst` as the domain name.
    pub ld_name: Option<String>,
    /// The `desc` attribute.
    pub desc: Option<String>,
    /// The `<LN0>` and `<LN>` children.
    pub logical_nodes: Vec<RawLogicalNode>,
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}

/// An `<LN>` or `<LN0>` element.
#[derive(Debug, Clone)]
pub struct RawLogicalNode {
    /// The `prefix` attribute.
    pub prefix: Option<String>,
    /// The `lnClass` attribute, fixed to LLN0 for an `<LN0>`.
    pub ln_class: String,
    /// The `inst` attribute, empty on an `<LN0>`.
    pub inst: String,
    /// The `LNodeType` identifier this node references; resolved in stage 2.
    pub ln_type_ref: String,
    /// The `desc` attribute.
    pub desc: Option<String>,

    /// The `<DOI>` children, which override runtime values and settings.
    pub doi: Vec<RawDoi>,
    /// The `<DataSet>` children.
    pub data_sets: Vec<RawDataSet>,
    /// The `<ReportControl>` children.
    pub report_controls: Vec<RawReportControlBlock>,
    /// The `<LogControl>` children.
    pub log_controls: Vec<RawLogControl>,
    /// The `<GSEControl>` children, which occur only on LLN0.
    pub gse_controls: Vec<RawGseControl>,
    /// The `<SampledValueControl>` children, which occur only on LLN0.
    pub smv_controls: Vec<RawSampledValueControl>,
    /// The `<SettingControl>` child, which occurs only on LLN0 and at most
    /// once per logical device.
    pub setting_control: Option<RawSettingControl>,
    /// The `<Inputs>` element is not parsed; the parser skips the subtree
    /// without a warning.
    pub _inputs: (),
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}

/// A `<DOI>` element: a data object instance carrying overrides and default
/// values.
#[derive(Debug, Clone)]
pub struct RawDoi {
    /// The `name` attribute.
    pub name: String,
    /// The `desc` attribute.
    pub desc: Option<String>,
    /// The `<SDI>` and `<DAI>` children, kept in one flat list.
    pub children: Vec<RawDataInstance>,
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}

/// An `<SDI>` or `<DAI>` child, in one enumeration so the two share a child
/// list.
#[derive(Debug, Clone)]
pub enum RawDataInstance {
    /// An `<SDI>` child.
    Sdi(RawSdi),
    /// A `<DAI>` child.
    Dai(RawDai),
}

/// An `<SDI>` element, a structured sub-instance.
#[derive(Debug, Clone)]
pub struct RawSdi {
    /// The `name` attribute.
    pub name: String,
    /// The `ix` attribute, an array index. It is read from this element, never
    /// from the enclosing `<DOI>`.
    pub ix: Option<u32>,
    /// The nested `<SDI>` and `<DAI>` children.
    pub children: Vec<RawDataInstance>,
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}

/// A `<DAI>` element, a data attribute instance and a leaf.
#[derive(Debug, Clone)]
pub struct RawDai {
    /// The `name` attribute.
    pub name: String,
    /// The `ix` attribute, an array index.
    pub ix: Option<u32>,
    /// The `<Val>` strings. A `sGroup` index selects the setting group it
    /// applies to, and is resolved in stage 2.
    pub values: Vec<RawVal>,
    /// The `valKind` and `valImport` attributes, kept so they can be honored
    /// later.
    pub val_kind: Option<String>,
    /// The `valImport` attribute.
    pub val_import: Option<bool>,
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}

/// A `<Val>` element.
#[derive(Debug, Clone)]
pub struct RawVal {
    /// The `sGroup` attribute; `None` means the value applies to every setting
    /// group.
    pub s_group: Option<u32>,
    /// The element text, before any type-specific parsing.
    pub raw_text: String,
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}

// ------------------------------------------------------------------------
// DataSet and control blocks
// ------------------------------------------------------------------------

/// A `<DataSet>` element.
#[derive(Debug, Clone)]
pub struct RawDataSet {
    /// The `name` attribute.
    pub name: String,
    /// The `desc` attribute.
    pub desc: Option<String>,
    /// The `<FCDA>` children, whose order the wire preserves.
    pub fcdas: Vec<RawFcda>,
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}

/// An `<FCDA>` element, one data set member.
#[derive(Debug, Clone)]
pub struct RawFcda {
    /// The `ldInst` attribute, either a logical device instance or a full domain name.
    pub ld_inst: String,
    /// The `prefix` attribute of the referenced logical node.
    pub prefix: Option<String>,
    /// The `lnClass` attribute of the referenced logical node.
    pub ln_class: String,
    /// The `lnInst` attribute of the referenced logical node.
    pub ln_inst: Option<String>,
    /// The `doName` attribute, a path of names joined with `.`.
    pub do_name: Option<String>,
    /// The `daName` attribute, the final data attribute.
    pub da_name: Option<String>,
    /// The `fc` attribute, kept as a token and converted when the model is built.
    pub fc: String,
    /// The `ix` attribute, an array index.
    pub ix: Option<u32>,
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}

/// A `<ReportControl>` element.
#[derive(Debug, Clone)]
pub struct RawReportControlBlock {
    /// The `name` attribute.
    pub name: String,
    /// The `rptID` attribute.
    pub rpt_id: Option<String>,
    /// The `datSet` attribute, naming the referenced data set.
    pub dat_set: Option<String>,
    /// The `confRev` attribute.
    pub conf_rev: u32,
    /// The `buffered` attribute.
    pub buffered: bool,
    /// The `intgPd` attribute, which defaults to 0.
    pub intg_pd: u32,
    /// The `bufTime` attribute, in milliseconds.
    pub buf_time: u32,
    /// The `<TrgOps>` child, or its default when the element is absent.
    pub trg_ops: TriggerOptionsBits,
    /// The `<OptFields>` child, or its default when the element is absent.
    pub opt_fields: OptionFieldsBits,
    /// The `max` attribute of the `<RptEnabled>` child.
    pub rpt_enabled_max: Option<u32>,
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}

/// A `<LogControl>` element.
#[derive(Debug, Clone)]
pub struct RawLogControl {
    /// The `name` attribute.
    pub name: String,
    /// The `datSet` attribute, naming the referenced data set.
    pub data_set: Option<String>,
    /// The `logName` attribute.
    pub log_name: Option<String>,
    /// The `logEna` attribute, which defaults to true.
    pub log_ena: bool,
    /// The `<TrgOps>` child, or its default when the element is absent.
    pub trg_ops: TriggerOptionsBits,
    /// The `intgPd` attribute, in milliseconds.
    pub intg_pd: u32,
    /// The `reasonCode` attribute.
    pub reason_code: bool,
    /// The `bufTime` attribute, in milliseconds.
    pub buf_time: u32,
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}

/// A `<GSEControl>` element, valid only on an `<LN0>`.
#[derive(Debug, Clone)]
pub struct RawGseControl {
    /// The `name` attribute.
    pub name: String,
    /// The `appID` attribute.
    pub appl_id: String,
    /// The `datSet` attribute, naming the referenced data set.
    pub data_set: String,
    /// The `confRev` attribute.
    pub conf_rev: u32,
    /// The `fixedOffs` attribute.
    pub fixed_offs: bool,
    /// The `type` attribute.
    pub gse_type: GseControlType,
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}

/// The `type` attribute of a `<GSEControl>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GseControlType {
    /// GOOSE, the value that applies when the attribute is absent.
    Goose,
    /// GSSE.
    GsSe,
}

/// A `<SampledValueControl>` element, valid only on an `<LN0>`.
#[derive(Debug, Clone)]
pub struct RawSampledValueControl {
    /// The `name` attribute.
    pub name: String,
    /// The `smvID` attribute.
    pub smv_id: String,
    /// The `datSet` attribute, naming the referenced data set.
    pub data_set: String,
    /// The `confRev` attribute.
    pub conf_rev: u32,
    /// The `multicast` attribute, which defaults to true.
    pub multicast: bool,
    /// The `smpRate` attribute.
    pub smp_rate: u32,
    /// The `nofASDU` attribute.
    pub nofasdu: u32,
    /// The `smpMod` attribute.
    pub smp_mod: SampledValueSmpMod,
    /// The `<SmvOpts>` child, or its default when the element is absent.
    pub opts: SmvOptsBits,
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}

/// The `smpMod` attribute of a `<SampledValueControl>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampledValueSmpMod {
    /// Samples per period, the value that applies when the attribute is absent.
    SamplesPerPeriod,
    /// Samples per second.
    SamplesPerSecond,
    /// Seconds per sample.
    SecondsPerSample,
}

/// A `<SettingControl>` element, valid only on an `<LN0>`.
#[derive(Debug, Clone)]
pub struct RawSettingControl {
    /// The `numOfSGs` attribute.
    pub num_of_sgs: u32,
    /// The `actSG` attribute, which defaults to 1.
    pub act_sg: u32,
    /// The `resvTms` attribute, in seconds.
    pub resv_tms: Option<u32>,
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}

// ------------------------------------------------------------------------
// The TrgOps, OptFields and SmvOpts bit strings
// ------------------------------------------------------------------------

/// The five boolean attributes of a `<TrgOps>` element.
#[derive(Debug, Clone, Copy, Default)]
pub struct TriggerOptionsBits {
    /// The `dchg` attribute.
    pub data_change: bool,
    /// The `qchg` attribute.
    pub quality_change: bool,
    /// The `dupd` attribute.
    pub data_update: bool,
    /// The `period` attribute, which drives integrity reporting.
    pub period: bool,
    /// The `gi` attribute, general interrogation.
    pub gi: bool,
}

/// The boolean attributes of an `<OptFields>` element.
#[derive(Debug, Clone, Copy, Default)]
pub struct OptionFieldsBits {
    /// The `seqNum` attribute.
    pub seq_num: bool,
    /// The `timeStamp` attribute.
    pub time_stamp: bool,
    /// The `dataSet` attribute.
    pub data_set: bool,
    /// The `reasonCode` attribute.
    pub reason_code: bool,
    /// The `dataRef` attribute.
    pub data_ref: bool,
    /// The `bufOvfl` attribute, which defaults to true.
    pub buffer_overflow: bool,
    /// The `entryID` attribute.
    pub ent_id: bool,
    /// The `configRef` attribute.
    pub conf_rev: bool,
    /// The `segmentation` attribute.
    pub segmentation: bool,
}

/// The boolean attributes of an `<SmvOpts>` element.
#[derive(Debug, Clone, Copy, Default)]
pub struct SmvOptsBits {
    /// The `refreshTime` attribute.
    pub refresh_time: bool,
    /// The `sampleSynchronized` attribute.
    pub sample_synchronized: bool,
    /// The `sampleRate` attribute.
    pub sample_rate: bool,
    /// The `dataSet` attribute.
    pub data_set: bool,
    /// The `security` attribute.
    pub security: bool,
    /// The `dataRef` attribute.
    pub data_ref: bool,
}

// ------------------------------------------------------------------------
// Authentication: the IED security declaration; only its attributes are parsed
// ------------------------------------------------------------------------

/// An `<Authentication>` element, the security declaration of an IED.
#[derive(Debug, Clone, Copy, Default)]
pub struct Authentication {
    /// The `none` attribute.
    pub none: bool,
    /// The `password` attribute.
    pub password: bool,
    /// The `weak` attribute.
    pub weak: bool,
    /// The `strong` attribute.
    pub strong: bool,
    /// The `certificate` attribute.
    pub certificate: bool,
}

// ------------------------------------------------------------------------
// The four DataTypeTemplates tables; references are resolved in stage 2
// ------------------------------------------------------------------------

/// The `<DataTypeTemplates>` section, as four tables keyed by identifier.
#[derive(Debug, Clone, Default)]
pub struct DataTypeTemplates {
    /// The `<LNodeType>` declarations.
    pub ln_node_types: BTreeMap<String, RawLNodeType>,
    /// The `<DOType>` declarations.
    pub do_types: BTreeMap<String, RawDoType>,
    /// The `<DAType>` declarations.
    pub da_types: BTreeMap<String, RawDaType>,
    /// The `<EnumType>` declarations.
    pub enum_types: BTreeMap<String, RawEnumType>,
}

/// An `<LNodeType>` declaration.
#[derive(Debug, Clone)]
pub struct RawLNodeType {
    /// The `id` attribute.
    pub id: String,
    /// The `lnClass` attribute.
    pub ln_class: String,
    /// The `iedType` attribute.
    pub iedtype: Option<String>,
    /// The `<DO>` children.
    pub dos: Vec<RawDoDef>,
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}

/// A `<DO>` declaration inside an `<LNodeType>`.
#[derive(Debug, Clone)]
pub struct RawDoDef {
    /// The `name` attribute.
    pub name: String,
    /// The `type` attribute, resolved in stage 2.
    pub do_type_ref: String,
    /// The `transient` attribute.
    pub transient: bool,
    /// The `accessControl` attribute.
    pub access_control: Option<String>,
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}

/// A `<DOType>` declaration.
#[derive(Debug, Clone)]
pub struct RawDoType {
    /// The `id` attribute.
    pub id: String,
    /// The `cdc` attribute, naming the common data class.
    pub cdc: String,
    /// The `<DA>` children.
    pub das: Vec<RawDaDef>,
    /// The `<SDO>` children.
    pub sdos: Vec<RawSdoDef>,
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}

/// An `<SDO>` declaration inside a `<DOType>`.
#[derive(Debug, Clone)]
pub struct RawSdoDef {
    /// The `name` attribute.
    pub name: String,
    /// The `type` attribute, resolved in stage 2.
    pub do_type_ref: String,
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}

/// A `<DA>` declaration inside a `<DOType>`.
#[derive(Debug, Clone)]
pub struct RawDaDef {
    /// The `name` attribute.
    pub name: String,
    /// The `fc` attribute, kept as a token and converted when the model is built.
    pub fc: String,
    /// The `bType` attribute.
    pub b_type: String,
    /// The referenced type identifier: an `EnumType` when bType is Enum, a
    /// `DAType` when it is Struct, and `None` otherwise.
    pub type_ref: Option<String>,
    /// The `dchg`, `qchg` and `dupd` attributes.
    pub trg_ops: TriggerOptionsBits,
    /// The `dchg`, `qchg` and `dupd` attributes.
    pub count: Option<u32>,
    /// The text of the `<Val>` child, if the declaration carries a default.
    pub default_value: Option<String>,
    /// The `valKind` attribute.
    pub val_kind: Option<String>,
    /// The `<BDA>` children, for an inline nested declaration.
    pub bda: Vec<RawBda>,
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}

/// A `<BDA>` element: an attribute nested inside a structure.
///
/// Shaped like a `<DA>`, but it carries no functional constraint of its own
/// and inherits the one of its parent.
#[derive(Debug, Clone)]
pub struct RawBda {
    /// The `name` attribute.
    pub name: String,
    /// The `bType` attribute.
    pub b_type: String,
    /// The `type` attribute, resolved in stage 2.
    pub type_ref: Option<String>,
    /// The text of the `<Val>` child, if the declaration carries a default.
    pub default_value: Option<String>,
    /// The `valKind` attribute.
    pub val_kind: Option<String>,
    /// The nested `<BDA>` children.
    pub bda: Vec<RawBda>,
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}

/// A `<DAType>` declaration.
#[derive(Debug, Clone)]
pub struct RawDaType {
    /// The `id` attribute.
    pub id: String,
    /// The `<BDA>` children.
    pub bdas: Vec<RawBda>,
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}

/// An `<EnumType>` declaration.
#[derive(Debug, Clone)]
pub struct RawEnumType {
    /// The `id` attribute.
    pub id: String,
    /// The `<EnumVal>` children.
    pub values: Vec<RawEnumValue>,
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}

/// An `<EnumVal>` declaration.
#[derive(Debug, Clone)]
pub struct RawEnumValue {
    /// The `ord` attribute, the ordinal the wire carries.
    pub ord: i32,
    /// The element text, the name of the value.
    pub name: String,
    /// The `desc` attribute.
    pub desc: Option<String>,
    /// Where the element starts in the source XML.
    pub span: SourceSpan,
}
