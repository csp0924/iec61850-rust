//! Common data class factories, per IEC 61850-7-3 Table 28 and onwards.
//!
//! Each factory assembles the data object skeleton of one common data class.
//!
//! A factory returns a `DataObject` rather than a `Result`: it only builds a
//! tree, with no I/O and no fallible allocation. A name conflict is rejected
//! later, by `IedModelBuilder::build`.
//!
//! Leaf default values are materialized here through `MmsValue::default_for`.
//! `ctlModel` is the one exception: its initial value is the integer of the
//! requested control model.
//!
//! Children are emitted in the order the wire expects, because that order
//! decides how `GetVariableAccessAttributes` enumerates the type
//! specification, and client tools depend on it.
//!
//! A data object whose name is null is not expanded in place: a WYE or DEL
//! that splices CMV attributes into an existing path is built as a separate
//! data object first.
//!
//! On quality: bit 13 of `Quality` lies outside the 13-bit bit string, so it is
//! never serialized. See `Quality::DERIVED` in `types.rs`.

use crate::compat::prelude::*;
use crate::fc::FC;
use crate::tree::{DataAttribute, DataObject, DoChild};
use crate::types::{ControlModel, DataAttributeType as T, TrgOps};
use crate::value::MmsValue;

// -----------------------------------------------------------------------------
// CdcOptions / ControlOptions
// -----------------------------------------------------------------------------

/// Common data class options, such as substitution, blocking, description and
/// namespace attributes.
///
/// The bits follow the option definitions of IEC 61850-7-3; each class uses a
/// different subset.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct CdcOptions(pub u32);

impl CdcOptions {
    /// No option set.
    pub const NONE: Self = CdcOptions(0);
    /// Adds the substitution attributes: subEna, subVal, subQ and subID.
    pub const PICS_SUBST: Self = CdcOptions(0x0000_0001);
    /// Adds the blkEna attribute.
    pub const BLK_ENA: Self = CdcOptions(0x0000_0002);
    /// Adds the description attribute d.
    pub const DESC: Self = CdcOptions(0x0000_0004);
    /// Adds the Unicode description attribute dU.
    pub const DESC_UNICODE: Self = CdcOptions(0x0000_0008);
    /// Adds the data namespace attribute dataNs.
    pub const AC_DLNDA: Self = CdcOptions(0x0000_0010);
    /// Adds the common data class namespace attributes cdcNs and cdcName.
    pub const AC_DLN: Self = CdcOptions(0x0000_0020);
    /// Adds the units attribute.
    pub const UNIT: Self = CdcOptions(0x0000_0040);
    /// Adds the frozen-value attributes of a counter reading.
    pub const FROZEN_VALUE: Self = CdcOptions(0x0000_0080);
    /// Adds the physical address attribute.
    pub const ADDR: Self = CdcOptions(0x0000_0100);
    /// Adds the additional information attributes.
    pub const ADDINFO: Self = CdcOptions(0x0000_0200);
    /// Adds the instantaneous magnitude instMag.
    pub const INST_MAG: Self = CdcOptions(0x0000_0400);
    /// Adds the range attributes.
    pub const RANGE: Self = CdcOptions(0x0000_0800);
    /// Adds the multiplier to a units attribute.
    pub const UNIT_MULTIPLIER: Self = CdcOptions(0x0000_1000);
    /// Adds the scaled value configuration sVC.
    pub const AC_SCAV: Self = CdcOptions(0x0000_2000);
    /// Adds the minimum attribute.
    pub const MIN: Self = CdcOptions(0x0000_4000);
    /// Adds the maximum attribute.
    pub const MAX: Self = CdcOptions(0x0000_8000);
    /// Adds the angle sub-attribute of a complex value.
    pub const AC_CLC_O: Self = CdcOptions(0x0001_0000);
    /// Adds the angle range attributes.
    pub const RANGE_ANG: Self = CdcOptions(0x0002_0000);
    /// Adds the step size attribute.
    pub const STEP_SIZE: Self = CdcOptions(0x0040_0000);
    /// Adds the angle reference attribute.
    pub const ANGLE_REF: Self = CdcOptions(0x0080_0000);

    // Phase flags for ACD, ACT and WYE, bits 18 to 21. They share bits with the
    // nameplate flags below, which is safe because the contexts are disjoint.
    /// Adds the phase A attributes.
    pub const PHASE_A: Self = CdcOptions(0x0004_0000);
    /// Adds the phase B attributes.
    pub const PHASE_B: Self = CdcOptions(0x0008_0000);
    /// Adds the phase C attributes.
    pub const PHASE_C: Self = CdcOptions(0x0010_0000);
    /// Adds the neutral attributes.
    pub const PHASE_NEUT: Self = CdcOptions(0x0020_0000);
    /// Adds the phase A, B and C attributes.
    pub const PHASES_ABC: Self = CdcOptions(0x0004_0000 | 0x0008_0000 | 0x0010_0000);
    /// Adds the phase A, B, C and neutral attributes.
    pub const PHASES_ALL: Self = CdcOptions(0x0004_0000 | 0x0008_0000 | 0x0010_0000 | 0x0020_0000);

    // Logical node nameplate options
    /// Adds the configuration revision attribute of a nameplate on LLN0.
    pub const AC_LN0_M: Self = CdcOptions(0x0100_0000);
    /// Adds the logical device namespace attribute of a nameplate on LLN0.
    pub const AC_LN0_EX: Self = CdcOptions(0x0200_0000);
    /// Adds the logical node namespace attribute of a nameplate.
    pub const AC_DLD_M: Self = CdcOptions(0x0400_0000);

    // Device nameplate options. These deliberately share bits 17 to 21 with the
    // angle-range and phase flags: a device nameplate never carries those, so
    // the two sets cannot collide.
    /// Adds the hardware revision attribute of a device nameplate.
    pub const DPL_HWREV: Self = CdcOptions(0x0002_0000);
    /// Adds the software revision attribute of a device nameplate.
    pub const DPL_SWREV: Self = CdcOptions(0x0004_0000);
    /// Adds the serial number attribute of a device nameplate.
    pub const DPL_SERNUM: Self = CdcOptions(0x0008_0000);
    /// Adds the model attribute of a device nameplate.
    pub const DPL_MODEL: Self = CdcOptions(0x0010_0000);
    /// Adds the location attribute of a device nameplate.
    pub const DPL_LOCATION: Self = CdcOptions(0x0020_0000);

    /// Returns the union of two option sets.
    pub const fn union(self, other: Self) -> Self {
        CdcOptions(self.0 | other.0)
    }

    /// Reports whether every bit of `flag` is set.
    pub const fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) == flag.0
    }
}

impl core::ops::BitOr for CdcOptions {
    type Output = CdcOptions;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

/// Control options: the control model plus the extra status and
/// operate-received flags.
///
/// The low three bits hold the [`ControlModel`]; the remaining bits are
/// individual flags.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct ControlOptions(pub u32);

impl ControlOptions {
    /// No option set, which selects the status-only control model.
    pub const NONE: Self = ControlOptions(0);
    /// Adds the Cancel service.
    pub const HAS_CANCEL: Self = ControlOptions(0x10);
    /// Adds the operate time attribute, making the control time activated.
    pub const IS_TIME_ACTIVATED: Self = ControlOptions(0x20);
    /// Adds the origin attribute.
    pub const ORIGIN: Self = ControlOptions(0x40);
    /// Adds the control number attribute.
    pub const CTL_NUM: Self = ControlOptions(0x80);
    /// Adds the selected-state attribute stSeld.
    pub const ST_SELD: Self = ControlOptions(0x100);
    /// Adds the opRcvd attribute.
    pub const OP_RCVD: Self = ControlOptions(0x200);
    /// Adds the opOk attribute.
    pub const OP_OK: Self = ControlOptions(0x400);
    /// Adds the tOpOk attribute.
    pub const T_OP_OK: Self = ControlOptions(0x800);

    /// Returns a copy with the control model replaced, keeping every other flag.
    pub const fn with_model(self, model: ControlModel) -> Self {
        ControlOptions((self.0 & !0x7) | (model as i32 as u32 & 0x7))
    }

    /// Returns the control model held in the low three bits.
    pub const fn model(self) -> ControlModel {
        match self.0 & 0x7 {
            0 => ControlModel::StatusOnly,
            1 => ControlModel::DirectNormal,
            2 => ControlModel::SboNormal,
            3 => ControlModel::DirectEnhanced,
            4 => ControlModel::SboEnhanced,
            // IEC 61850-7-2 §17.2.4 defines models 0 to 4 only; anything above
            // is treated as status-only.
            _ => ControlModel::StatusOnly,
        }
    }

    /// Reports whether every bit of `flag` is set.
    pub const fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) == flag.0
    }

    /// Returns the union of two option sets.
    pub const fn union(self, other: Self) -> Self {
        ControlOptions(self.0 | other.0)
    }
}

impl core::ops::BitOr for ControlOptions {
    type Output = ControlOptions;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

// -----------------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------------

/// Builds a leaf data attribute whose initial value is the zero value of its
/// type.
fn leaf(name: &str, fc: FC, ty: T, trg: TrgOps) -> DataAttribute {
    DataAttribute::new(name, fc, ty, trg, MmsValue::default_for(ty))
}

/// Builds a leaf data attribute with an explicit initial value.
fn leaf_with(name: &str, fc: FC, ty: T, trg: TrgOps, value: MmsValue) -> DataAttribute {
    DataAttribute::new(name, fc, ty, trg, value)
}

/// Builds a constructed data attribute from a functional constraint and its
/// children.
fn structured(name: &str, fc: FC, children: Vec<DataAttribute>) -> DataAttribute {
    DataAttribute::constructed(name, fc, children)
}

/// The `AnalogueValue` sub-attribute: `i` as INT32, or `f` as FLOAT32.
fn cac_analogue_value(
    name: &str,
    fc: FC,
    trg: TrgOps,
    is_integer_not_float: bool,
) -> DataAttribute {
    let child = if is_integer_not_float {
        leaf("i", fc, T::Int32, trg)
    } else {
        leaf("f", fc, T::Float32, trg)
    };
    DataAttribute::new(
        name,
        fc,
        T::Constructed,
        trg,
        MmsValue::Structure(Vec::new()),
    )
    .with_children_internal(vec![child])
}

/// The `ValWithTrans` sub-attribute: `posVal` as INT8, optionally with
/// `transInd` as BOOLEAN.
fn cac_val_with_trans(
    name: &str,
    fc: FC,
    trg: TrgOps,
    has_transient_indicator: bool,
) -> DataAttribute {
    let mut children = vec![leaf("posVal", fc, T::Int8, trg)];
    if has_transient_indicator {
        children.push(leaf("transInd", fc, T::Boolean, trg));
    }
    DataAttribute::new(
        name,
        fc,
        T::Constructed,
        trg,
        MmsValue::Structure(Vec::new()),
    )
    .with_children_internal(children)
}

/// The `origin` sub-attribute: `orCat` as an enumeration and `orIdent` as a
/// 64-byte octet string.
fn add_originator(fc: FC) -> DataAttribute {
    structured(
        "origin",
        fc,
        vec![
            leaf("orCat", fc, T::Enumerated, TrgOps::NONE),
            leaf("orIdent", fc, T::OctetString(64), TrgOps::NONE),
        ],
    )
}

/// Appends the status triple `stVal`, `q` and `t`, all under ST.
fn add_status_st(stval_type: T, children: &mut Vec<DoChild>) {
    children.push(DoChild::Da(leaf(
        "stVal",
        FC::St,
        stval_type,
        TrgOps::DCHG | TrgOps::DUPD,
    )));
    add_time_quality(FC::St, children);
}

/// Appends `q` as a quality and `t` as a timestamp, under the functional
/// constraint the caller chooses, ST or MX.
fn add_time_quality(fc: FC, children: &mut Vec<DoChild>) {
    children.push(DoChild::Da(leaf("q", fc, T::Quality, TrgOps::QCHG)));
    children.push(DoChild::Da(leaf("t", fc, T::Timestamp, TrgOps::NONE)));
}

/// Appends the substitution attributes `subEna`, `subVal`, `subQ` and `subID`,
/// all under SV.
fn add_pics_subst(children: &mut Vec<DoChild>, subval_type: T) {
    children.push(DoChild::Da(leaf(
        "subEna",
        FC::Sv,
        T::Boolean,
        TrgOps::NONE,
    )));
    children.push(DoChild::Da(leaf(
        "subVal",
        FC::Sv,
        subval_type,
        TrgOps::NONE,
    )));
    children.push(DoChild::Da(leaf("subQ", FC::Sv, T::Quality, TrgOps::NONE)));
    children.push(DoChild::Da(leaf(
        "subID",
        FC::Sv,
        T::VisibleString(64),
        TrgOps::NONE,
    )));
}

/// The substitution attributes with `subVal` as a `ValWithTrans`, for the step
/// control classes.
fn add_pics_subst_valwtr(children: &mut Vec<DoChild>, has_transient_indicator: bool) {
    children.push(DoChild::Da(leaf(
        "subEna",
        FC::Sv,
        T::Boolean,
        TrgOps::NONE,
    )));
    children.push(DoChild::Da(cac_val_with_trans(
        "subVal",
        FC::Sv,
        TrgOps::NONE,
        has_transient_indicator,
    )));
    children.push(DoChild::Da(leaf("subQ", FC::Sv, T::Quality, TrgOps::NONE)));
    children.push(DoChild::Da(leaf(
        "subID",
        FC::Sv,
        T::VisibleString(64),
        TrgOps::NONE,
    )));
}

/// The substitution attributes with `subVal` as an `AnalogueValue`, for APC.
fn add_pics_subst_analogue(children: &mut Vec<DoChild>, is_integer_not_float: bool) {
    children.push(DoChild::Da(leaf(
        "subEna",
        FC::Sv,
        T::Boolean,
        TrgOps::NONE,
    )));
    children.push(DoChild::Da(cac_analogue_value(
        "subVal",
        FC::Sv,
        TrgOps::NONE,
        is_integer_not_float,
    )));
    children.push(DoChild::Da(leaf("subQ", FC::Sv, T::Quality, TrgOps::NONE)));
    children.push(DoChild::Da(leaf(
        "subID",
        FC::Sv,
        T::VisibleString(64),
        TrgOps::NONE,
    )));
}

/// Appends `blkEna` as a BOOLEAN under BL.
fn add_blk_ena(children: &mut Vec<DoChild>) {
    children.push(DoChild::Da(leaf(
        "blkEna",
        FC::Bl,
        T::Boolean,
        TrgOps::NONE,
    )));
}

/// Appends the description and namespace attributes, in the fixed order `d`,
/// `dU`, `cdcNs`, `cdcName`, `dataNs`.
fn add_standard_options(children: &mut Vec<DoChild>, options: CdcOptions) {
    if options.contains(CdcOptions::DESC) {
        children.push(DoChild::Da(leaf(
            "d",
            FC::Dc,
            T::VisibleString(255),
            TrgOps::NONE,
        )));
    }
    if options.contains(CdcOptions::DESC_UNICODE) {
        children.push(DoChild::Da(leaf(
            "dU",
            FC::Dc,
            T::UnicodeString255,
            TrgOps::NONE,
        )));
    }
    if options.contains(CdcOptions::AC_DLNDA) {
        children.push(DoChild::Da(leaf(
            "cdcNs",
            FC::Ex,
            T::VisibleString(255),
            TrgOps::NONE,
        )));
        children.push(DoChild::Da(leaf(
            "cdcName",
            FC::Ex,
            T::VisibleString(255),
            TrgOps::NONE,
        )));
    }
    if options.contains(CdcOptions::AC_DLN) {
        children.push(DoChild::Da(leaf(
            "dataNs",
            FC::Ex,
            T::VisibleString(255),
            TrgOps::NONE,
        )));
    }
}

/// The shared `Oper`, `SBOw` and `Cancel` structure, used by the non-analogue
/// controllable classes.
///
/// Layout: `ctlVal`, optionally `operTm`, then `origin`, `ctlNum`, `T`, `Test`
/// and optionally `Check`.
fn build_oper_struct(
    name: &str,
    ctl_val_type: T,
    is_time_activated: bool,
    has_check: bool,
) -> DataAttribute {
    let mut kids = Vec::new();
    kids.push(leaf("ctlVal", FC::Co, ctl_val_type, TrgOps::NONE));
    if is_time_activated {
        kids.push(leaf("operTm", FC::Co, T::Timestamp, TrgOps::NONE));
    }
    kids.push(add_originator(FC::Co));
    kids.push(leaf("ctlNum", FC::Co, T::Int8U, TrgOps::NONE));
    kids.push(leaf("T", FC::Co, T::Timestamp, TrgOps::NONE));
    kids.push(leaf("Test", FC::Co, T::Boolean, TrgOps::NONE));
    if has_check {
        kids.push(leaf("Check", FC::Co, T::Check, TrgOps::NONE));
    }
    structured(name, FC::Co, kids)
}

/// The `Oper`, `SBOw` and `Cancel` structure for analogue control, where
/// `ctlVal` is a constructed `AnalogueValue`.
fn build_oper_struct_analogue(
    name: &str,
    is_integer_not_float: bool,
    is_time_activated: bool,
    has_check: bool,
) -> DataAttribute {
    let mut kids = Vec::new();
    kids.push(cac_analogue_value(
        "ctlVal",
        FC::Co,
        TrgOps::NONE,
        is_integer_not_float,
    ));
    if is_time_activated {
        kids.push(leaf("operTm", FC::Co, T::Timestamp, TrgOps::NONE));
    }
    kids.push(add_originator(FC::Co));
    kids.push(leaf("ctlNum", FC::Co, T::Int8U, TrgOps::NONE));
    kids.push(leaf("T", FC::Co, T::Timestamp, TrgOps::NONE));
    kids.push(leaf("Test", FC::Co, T::Boolean, TrgOps::NONE));
    if has_check {
        kids.push(leaf("Check", FC::Co, T::Check, TrgOps::NONE));
    }
    structured(name, FC::Co, kids)
}

/// Appends the control attributes: `ctlModel` under CF, then `SBO` or `SBOw`
/// as the model requires, then `Oper` and optionally `Cancel`.
fn add_controls(children: &mut Vec<DoChild>, ctl_val_type: T, control_options: ControlOptions) {
    let model = control_options.model();
    let model_int = model as i32;
    children.push(DoChild::Da(leaf_with(
        "ctlModel",
        FC::Cf,
        T::Enumerated,
        TrgOps::DCHG,
        MmsValue::Integer(model_int as i64),
    )));

    if matches!(model, ControlModel::StatusOnly) {
        return;
    }

    if matches!(model, ControlModel::SboNormal) {
        children.push(DoChild::Da(leaf(
            "SBO",
            FC::Co,
            T::VisibleString(129),
            TrgOps::NONE,
        )));
    }

    let is_time_activated = control_options.contains(ControlOptions::IS_TIME_ACTIVATED);

    if matches!(model, ControlModel::SboEnhanced) {
        children.push(DoChild::Da(build_oper_struct(
            "SBOw",
            ctl_val_type,
            is_time_activated,
            true,
        )));
    }

    children.push(DoChild::Da(build_oper_struct(
        "Oper",
        ctl_val_type,
        is_time_activated,
        true,
    )));

    if control_options.contains(ControlOptions::HAS_CANCEL) {
        children.push(DoChild::Da(build_oper_struct(
            "Cancel",
            ctl_val_type,
            is_time_activated,
            false,
        )));
    }
}

/// The analogue counterpart of the control attributes, where `ctlVal` is an
/// `AnalogueValue`.
fn add_analog_controls(
    children: &mut Vec<DoChild>,
    control_options: ControlOptions,
    is_integer_not_float: bool,
) {
    let model = control_options.model();
    let model_int = model as i32;
    children.push(DoChild::Da(leaf_with(
        "ctlModel",
        FC::Cf,
        T::Enumerated,
        TrgOps::DCHG,
        MmsValue::Integer(model_int as i64),
    )));

    if matches!(model, ControlModel::StatusOnly) {
        return;
    }

    if matches!(model, ControlModel::SboNormal) {
        children.push(DoChild::Da(leaf(
            "SBO",
            FC::Co,
            T::VisibleString(129),
            TrgOps::NONE,
        )));
    }

    let is_time_activated = control_options.contains(ControlOptions::IS_TIME_ACTIVATED);

    if matches!(model, ControlModel::SboEnhanced) {
        children.push(DoChild::Da(build_oper_struct_analogue(
            "SBOw",
            is_integer_not_float,
            is_time_activated,
            true,
        )));
    }

    children.push(DoChild::Da(build_oper_struct_analogue(
        "Oper",
        is_integer_not_float,
        is_time_activated,
        true,
    )));

    if control_options.contains(ControlOptions::HAS_CANCEL) {
        children.push(DoChild::Da(build_oper_struct_analogue(
            "Cancel",
            is_integer_not_float,
            is_time_activated,
            false,
        )));
    }
}

/// Appends the originator and control-number attributes, under the functional
/// constraint the caller chooses: ST for the status classes, MX for APC.
fn add_originator_ctlnum(children: &mut Vec<DoChild>, fc: FC, control_options: ControlOptions) {
    if control_options.contains(ControlOptions::ORIGIN) {
        children.push(DoChild::Da(add_originator(fc)));
    }
    if control_options.contains(ControlOptions::CTL_NUM) {
        children.push(DoChild::Da(leaf("ctlNum", fc, T::Int8U, TrgOps::NONE)));
    }
}

/// Appends the common control attributes `opRcvd`, `opOk` and `tOpOk`, under
/// OR.
fn add_common_control_attributes(children: &mut Vec<DoChild>, control_options: ControlOptions) {
    if control_options.contains(ControlOptions::OP_RCVD) {
        children.push(DoChild::Da(leaf(
            "opRcvd",
            FC::Or,
            T::Boolean,
            TrgOps::DCHG,
        )));
    }
    if control_options.contains(ControlOptions::OP_OK) {
        children.push(DoChild::Da(leaf("opOk", FC::Or, T::Boolean, TrgOps::DCHG)));
    }
    if control_options.contains(ControlOptions::T_OP_OK) {
        children.push(DoChild::Da(leaf(
            "tOpOk",
            FC::Or,
            T::Timestamp,
            TrgOps::DCHG,
        )));
    }
}

// -----------------------------------------------------------------------------
// The common data class factories
// -----------------------------------------------------------------------------

/// SPS, single point status, per IEC 61850-7-3 §6.2.1.
pub fn sps(name: impl Into<String>, options: CdcOptions) -> DataObject {
    let mut children = Vec::new();
    add_status_st(T::Boolean, &mut children);
    if options.contains(CdcOptions::PICS_SUBST) {
        add_pics_subst(&mut children, T::Boolean);
    }
    if options.contains(CdcOptions::BLK_ENA) {
        add_blk_ena(&mut children);
    }
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

/// DPS, double point status, per IEC 61850-7-3 §6.2.2. `stVal` is a coded
/// enumeration holding a `Dbpos`.
pub fn dps(name: impl Into<String>, options: CdcOptions) -> DataObject {
    let mut children = Vec::new();
    add_status_st(T::CodedEnum, &mut children);
    if options.contains(CdcOptions::PICS_SUBST) {
        add_pics_subst(&mut children, T::CodedEnum);
    }
    if options.contains(CdcOptions::BLK_ENA) {
        add_blk_ena(&mut children);
    }
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

/// INS, integer status, per IEC 61850-7-3 §6.2.4. `stVal` is an INT32.
pub fn ins(name: impl Into<String>, options: CdcOptions) -> DataObject {
    let mut children = Vec::new();
    add_status_st(T::Int32, &mut children);
    if options.contains(CdcOptions::PICS_SUBST) {
        add_pics_subst(&mut children, T::Int32);
    }
    if options.contains(CdcOptions::BLK_ENA) {
        add_blk_ena(&mut children);
    }
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

/// ENS, enumerated status, per IEC 61850-7-3 §6.2.6. `stVal` is an
/// enumeration.
pub fn ens(name: impl Into<String>, options: CdcOptions) -> DataObject {
    let mut children = Vec::new();
    add_status_st(T::Enumerated, &mut children);
    if options.contains(CdcOptions::PICS_SUBST) {
        add_pics_subst(&mut children, T::Enumerated);
    }
    if options.contains(CdcOptions::BLK_ENA) {
        add_blk_ena(&mut children);
    }
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

/// MV, measured value, per IEC 61850-7-3 §7.4.3. The functional constraint is
/// MX and `mag` is an `AnalogueValue`.
///
/// `is_integer_not_float` selects `mag.i` as an INT32 when true, and `mag.f` as
/// a FLOAT32 when false.
///
/// The substitution option is ignored on MV: IEC 61850-7-3 leaves the type of
/// `subVal` for a measured value underspecified, so no `sub*` attribute is
/// emitted.
pub fn mv(name: impl Into<String>, options: CdcOptions, is_integer_not_float: bool) -> DataObject {
    let mut children = Vec::new();
    if options.contains(CdcOptions::INST_MAG) {
        children.push(DoChild::Da(cac_analogue_value(
            "instMag",
            FC::Mx,
            TrgOps::NONE,
            is_integer_not_float,
        )));
    }
    children.push(DoChild::Da(cac_analogue_value(
        "mag",
        FC::Mx,
        TrgOps::DCHG | TrgOps::DUPD,
        is_integer_not_float,
    )));
    if options.contains(CdcOptions::RANGE) {
        children.push(DoChild::Da(leaf(
            "range",
            FC::Mx,
            T::Enumerated,
            TrgOps::DCHG,
        )));
    }
    add_time_quality(FC::Mx, &mut children);
    // The substitution option is ignored here; see the function doc.
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

/// SPC, controllable single point, per IEC 61850-7-3 §6.5.4.
/// `Oper.ctlVal` is a BOOLEAN.
pub fn spc(
    name: impl Into<String>,
    options: CdcOptions,
    control_options: ControlOptions,
) -> DataObject {
    let mut children = Vec::new();
    add_originator_ctlnum(&mut children, FC::St, control_options);
    add_status_st(T::Boolean, &mut children);
    add_controls(&mut children, T::Boolean, control_options);
    if control_options.contains(ControlOptions::ST_SELD) {
        children.push(DoChild::Da(leaf(
            "stSeld",
            FC::St,
            T::Boolean,
            TrgOps::DCHG,
        )));
    }
    add_common_control_attributes(&mut children, control_options);
    if options.contains(CdcOptions::PICS_SUBST) {
        add_pics_subst(&mut children, T::Boolean);
    }
    if options.contains(CdcOptions::BLK_ENA) {
        add_blk_ena(&mut children);
    }
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

/// DPC, controllable double point, per IEC 61850-7-3 §6.5.5.
///
/// `Oper.ctlVal` is a BOOLEAN even though the `stVal` of a DPS is a coded
/// enumeration, which is what IEC 61850-7-3 Table 28 specifies.
pub fn dpc(
    name: impl Into<String>,
    options: CdcOptions,
    control_options: ControlOptions,
) -> DataObject {
    let mut children = Vec::new();
    add_originator_ctlnum(&mut children, FC::St, control_options);
    add_status_st(T::CodedEnum, &mut children);
    add_controls(&mut children, T::Boolean, control_options);
    if control_options.contains(ControlOptions::ST_SELD) {
        children.push(DoChild::Da(leaf(
            "stSeld",
            FC::St,
            T::Boolean,
            TrgOps::DCHG,
        )));
    }
    add_common_control_attributes(&mut children, control_options);
    if options.contains(CdcOptions::PICS_SUBST) {
        add_pics_subst(&mut children, T::CodedEnum);
    }
    if options.contains(CdcOptions::BLK_ENA) {
        add_blk_ena(&mut children);
    }
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

/// APC, controllable analogue process value, per IEC 61850-7-3 §6.5.6.
///
/// The status attributes, `origin`, `ctlNum` and `stSeld` are all under MX, and
/// `Oper.ctlVal` is an `AnalogueValue`.
pub fn apc(
    name: impl Into<String>,
    options: CdcOptions,
    control_options: ControlOptions,
    is_integer_not_float: bool,
) -> DataObject {
    let mut children = Vec::new();
    add_originator_ctlnum(&mut children, FC::Mx, control_options);
    children.push(DoChild::Da(cac_analogue_value(
        "mxVal",
        FC::Mx,
        TrgOps::DCHG,
        is_integer_not_float,
    )));
    add_time_quality(FC::Mx, &mut children);
    if control_options.contains(ControlOptions::ST_SELD) {
        children.push(DoChild::Da(leaf(
            "stSeld",
            FC::Mx,
            T::Boolean,
            TrgOps::DCHG,
        )));
    }
    add_common_control_attributes(&mut children, control_options);
    if options.contains(CdcOptions::PICS_SUBST) {
        add_pics_subst_analogue(&mut children, is_integer_not_float);
    }
    if options.contains(CdcOptions::BLK_ENA) {
        add_blk_ena(&mut children);
    }
    add_analog_controls(&mut children, control_options, is_integer_not_float);
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

/// BSC, binary step control, per IEC 61850-7-3 §6.5.7. `Oper.ctlVal` is a
/// coded enumeration holding a `Dbpos`.
pub fn bsc(
    name: impl Into<String>,
    options: CdcOptions,
    control_options: ControlOptions,
    has_transient_indicator: bool,
) -> DataObject {
    let mut children = Vec::new();
    add_originator_ctlnum(&mut children, FC::St, control_options);
    children.push(DoChild::Da(cac_val_with_trans(
        "valWTr",
        FC::St,
        TrgOps::DCHG,
        has_transient_indicator,
    )));
    add_time_quality(FC::St, &mut children);
    children.push(DoChild::Da(leaf(
        "persistent",
        FC::Cf,
        T::Boolean,
        TrgOps::DCHG,
    )));
    add_controls(&mut children, T::CodedEnum, control_options);
    if control_options.contains(ControlOptions::ST_SELD) {
        children.push(DoChild::Da(leaf(
            "stSeld",
            FC::St,
            T::Boolean,
            TrgOps::DCHG,
        )));
    }
    add_common_control_attributes(&mut children, control_options);
    if options.contains(CdcOptions::PICS_SUBST) {
        add_pics_subst_valwtr(&mut children, has_transient_indicator);
    }
    if options.contains(CdcOptions::BLK_ENA) {
        add_blk_ena(&mut children);
    }
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

/// ENC, enumerated controllable, per IEC 61850-7-3 §6.5.3. `Oper.ctlVal` is an
/// enumeration.
pub fn enc(
    name: impl Into<String>,
    options: CdcOptions,
    control_options: ControlOptions,
) -> DataObject {
    let mut children = Vec::new();
    add_originator_ctlnum(&mut children, FC::St, control_options);
    add_status_st(T::Enumerated, &mut children);
    add_controls(&mut children, T::Enumerated, control_options);
    if control_options.contains(ControlOptions::ST_SELD) {
        children.push(DoChild::Da(leaf(
            "stSeld",
            FC::St,
            T::Boolean,
            TrgOps::DCHG,
        )));
    }
    add_common_control_attributes(&mut children, control_options);
    if options.contains(CdcOptions::PICS_SUBST) {
        add_pics_subst(&mut children, T::Enumerated);
    }
    if options.contains(CdcOptions::BLK_ENA) {
        add_blk_ena(&mut children);
    }
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

// -----------------------------------------------------------------------------
// The remaining IEC 61850-7-3 common data classes
//
// The six wind power classes of IEC 61400-25 (SPV, STV, ALM, CMD, CTE, TMS)
// are deliberately not implemented.

/// The `Vector` attribute type: `mag` as an analogue value, optionally with
/// `ang` when the angle option is set.
fn cac_vector(name: &str, fc: FC, trg: TrgOps, options: CdcOptions) -> DataAttribute {
    let mut kids = vec![cac_analogue_value("mag", fc, trg, false)];
    if options.contains(CdcOptions::AC_CLC_O) {
        kids.push(cac_analogue_value("ang", fc, trg, false));
    }
    DataAttribute::new(
        name,
        fc,
        T::Constructed,
        trg,
        MmsValue::Structure(Vec::new()),
    )
    .with_children_internal(kids)
}

/// The `Unit` attribute type: `SIUnit` as an enumeration, optionally with
/// `multiplier`. Under CF.
fn cac_unit(name: &str, has_multiplier: bool) -> DataAttribute {
    let mut kids = vec![leaf("SIUnit", FC::Cf, T::Enumerated, TrgOps::NONE)];
    if has_multiplier {
        kids.push(leaf("multiplier", FC::Cf, T::Enumerated, TrgOps::NONE));
    }
    structured(name, FC::Cf, kids)
}

/// The `ScaledValueConfig` attribute type: `scaleFactor` and `offset` as
/// FLOAT32, under CF, triggering on data change.
fn cac_scaled_value_config(name: &str) -> DataAttribute {
    structured(
        name,
        FC::Cf,
        vec![
            leaf("scaleFactor", FC::Cf, T::Float32, TrgOps::DCHG),
            leaf("offset", FC::Cf, T::Float32, TrgOps::DCHG),
        ],
    )
}

// BCR

/// BCR, binary counter reading, per IEC 61850-7-3 §7.4.1. `actVal` is an
/// INT64.
///
/// The frozen-value option adds `frVal`, `frTm`, `frEna`, `strTm`, `frPd` and
/// `frRs`; the unit option adds `units` under CF.
pub fn bcr(name: impl Into<String>, options: CdcOptions) -> DataObject {
    let mut children = Vec::new();
    children.push(DoChild::Da(leaf("actVal", FC::St, T::Int64, TrgOps::DCHG)));
    if options.contains(CdcOptions::FROZEN_VALUE) {
        children.push(DoChild::Da(leaf("frVal", FC::St, T::Int64, TrgOps::DUPD)));
        children.push(DoChild::Da(leaf(
            "frTm",
            FC::St,
            T::Timestamp,
            TrgOps::NONE,
        )));
    }
    add_time_quality(FC::St, &mut children);
    if options.contains(CdcOptions::UNIT) {
        children.push(DoChild::Da(leaf(
            "units",
            FC::Cf,
            T::Enumerated,
            TrgOps::DCHG,
        )));
    }
    children.push(DoChild::Da(leaf(
        "pulsQty",
        FC::Cf,
        T::Float32,
        TrgOps::DCHG,
    )));
    if options.contains(CdcOptions::FROZEN_VALUE) {
        children.push(DoChild::Da(leaf("frEna", FC::Cf, T::Boolean, TrgOps::DCHG)));
        children.push(DoChild::Da(leaf(
            "strTm",
            FC::Cf,
            T::Timestamp,
            TrgOps::DCHG,
        )));
        children.push(DoChild::Da(leaf("frPd", FC::Cf, T::Int32, TrgOps::DCHG)));
        children.push(DoChild::Da(leaf("frRs", FC::Cf, T::Boolean, TrgOps::DCHG)));
    }
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

// SEC

/// SEC, security violation counting, per IEC 61850-7-3 §6.2.10.
pub fn sec(name: impl Into<String>, options: CdcOptions) -> DataObject {
    let mut children = Vec::new();
    children.push(DoChild::Da(leaf("cnt", FC::St, T::Int32U, TrgOps::DCHG)));
    children.push(DoChild::Da(leaf(
        "sev",
        FC::St,
        T::Enumerated,
        TrgOps::NONE,
    )));
    children.push(DoChild::Da(leaf("t", FC::St, T::Timestamp, TrgOps::NONE)));
    if options.contains(CdcOptions::ADDR) {
        children.push(DoChild::Da(leaf(
            "addr",
            FC::St,
            T::OctetString(64),
            TrgOps::NONE,
        )));
    }
    if options.contains(CdcOptions::ADDINFO) {
        children.push(DoChild::Da(leaf(
            "addInfo",
            FC::St,
            T::VisibleString(64),
            TrgOps::NONE,
        )));
    }
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

// VSS

/// VSS, visible string status, per IEC 61850-7-3 §6.2.7. `stVal` is a
/// 255-byte visible string.
///
/// The substituted value `subVal` is a visible string as well, matching
/// `stVal`. Declaring it as a BOOLEAN would contradict IEC 61850-7-3; this
/// implementation follows the standard.
pub fn vss(name: impl Into<String>, options: CdcOptions) -> DataObject {
    let mut children = Vec::new();
    add_status_st(T::VisibleString(255), &mut children);
    if options.contains(CdcOptions::PICS_SUBST) {
        // subVal has the same type as stVal, as IEC 61850-7-3 requires.
        add_pics_subst(&mut children, T::VisibleString(255));
    }
    if options.contains(CdcOptions::BLK_ENA) {
        add_blk_ena(&mut children);
    }
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

// CMV

/// CMV, complex measured value, per IEC 61850-7-3 §7.4.4.
///
/// `cVal` is a vector, optionally accompanied by `instCVal`, `range` and
/// `rangeAng`, followed by `q` and `t`. The angle option adds the `ang`
/// sub-attribute to `cVal` and `instCVal`.
///
/// As for MV, the substitution option is ignored, because the type of `subVal`
/// is underspecified for a complex measured value.
pub fn cmv(name: impl Into<String>, options: CdcOptions) -> DataObject {
    let mut children = Vec::new();
    if options.contains(CdcOptions::INST_MAG) {
        children.push(DoChild::Da(cac_vector(
            "instCVal",
            FC::Mx,
            TrgOps::NONE,
            options,
        )));
    }
    children.push(DoChild::Da(cac_vector(
        "cVal",
        FC::Mx,
        TrgOps::DCHG | TrgOps::DUPD,
        options,
    )));
    if options.contains(CdcOptions::RANGE) {
        children.push(DoChild::Da(leaf(
            "range",
            FC::Mx,
            T::Enumerated,
            TrgOps::DCHG,
        )));
    }
    if options.contains(CdcOptions::RANGE_ANG) {
        children.push(DoChild::Da(leaf(
            "rangeAng",
            FC::Mx,
            T::Enumerated,
            TrgOps::DCHG,
        )));
    }
    add_time_quality(FC::Mx, &mut children);
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

// SAV

/// SAV, sampled analogue value, per IEC 61850-7-3 §7.4.5.
///
/// `instMag` as an analogue value plus `q` and `t`, optionally followed by
/// `units`, `sVC`, `min` and `max`.
pub fn sav(name: impl Into<String>, options: CdcOptions, is_integer_not_float: bool) -> DataObject {
    let mut children = Vec::new();
    children.push(DoChild::Da(cac_analogue_value(
        "instMag",
        FC::Mx,
        TrgOps::NONE,
        is_integer_not_float,
    )));
    add_time_quality(FC::Mx, &mut children);
    if options.contains(CdcOptions::UNIT) {
        children.push(DoChild::Da(cac_unit(
            "units",
            options.contains(CdcOptions::UNIT_MULTIPLIER),
        )));
    }
    if options.contains(CdcOptions::AC_SCAV) {
        children.push(DoChild::Da(cac_scaled_value_config("sVC")));
    }
    if options.contains(CdcOptions::MIN) {
        children.push(DoChild::Da(cac_analogue_value(
            "min",
            FC::Cf,
            TrgOps::DCHG,
            is_integer_not_float,
        )));
    }
    if options.contains(CdcOptions::MAX) {
        children.push(DoChild::Da(cac_analogue_value(
            "max",
            FC::Cf,
            TrgOps::DCHG,
            is_integer_not_float,
        )));
    }
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

// HST

/// HST, histogram, per IEC 61850-7-3 §7.4.6.
///
/// `hstVal` as an INT32 array plus `q` and `t`, followed by `numPts`, `units`
/// and `maxPts` under CF.
///
/// IEC 61850-7-3 also lists `hstRangeC`. It is not emitted, so the histogram
/// keeps the narrower shape a client can match without it.
pub fn hst(name: impl Into<String>, options: CdcOptions, max_pts: u16) -> DataObject {
    let mut children = Vec::new();
    // hstVal is an array of `max_pts` elements. A data attribute carries no
    // element count of its own, and the array count on a data object describes
    // an array of data objects, so only the leaf is created here.
    children.push(DoChild::Da(leaf(
        "hstVal",
        FC::St,
        T::Int32,
        TrgOps::DCHG | TrgOps::DUPD,
    )));
    let _ = max_pts; // TODO: carry the hstVal element count on the attribute
    add_time_quality(FC::St, &mut children);
    children.push(DoChild::Da(leaf("numPts", FC::Cf, T::Int16U, TrgOps::NONE)));
    // hstRangeC is deliberately absent; see the function doc.
    children.push(DoChild::Da(cac_unit(
        "units",
        options.contains(CdcOptions::UNIT_MULTIPLIER),
    )));
    children.push(DoChild::Da(leaf("maxPts", FC::Cf, T::Int16U, TrgOps::NONE)));
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

// INC

/// INC, integer controllable, per IEC 61850-7-3 §6.5.2. `Oper.ctlVal` is an
/// INT32.
///
/// The minimum, maximum and step-size options add `minVal`, `maxVal` as INT32
/// and `stepSize` as INT32U, all under CF.
pub fn inc(
    name: impl Into<String>,
    options: CdcOptions,
    control_options: ControlOptions,
) -> DataObject {
    let mut children = Vec::new();
    add_originator_ctlnum(&mut children, FC::St, control_options);
    add_status_st(T::Int32, &mut children);
    add_controls(&mut children, T::Int32, control_options);
    if control_options.contains(ControlOptions::ST_SELD) {
        children.push(DoChild::Da(leaf(
            "stSeld",
            FC::St,
            T::Boolean,
            TrgOps::DCHG,
        )));
    }
    add_common_control_attributes(&mut children, control_options);
    if options.contains(CdcOptions::PICS_SUBST) {
        add_pics_subst(&mut children, T::Int32);
    }
    if options.contains(CdcOptions::BLK_ENA) {
        add_blk_ena(&mut children);
    }
    if options.contains(CdcOptions::MIN) {
        children.push(DoChild::Da(leaf("minVal", FC::Cf, T::Int32, TrgOps::NONE)));
    }
    if options.contains(CdcOptions::MAX) {
        children.push(DoChild::Da(leaf("maxVal", FC::Cf, T::Int32, TrgOps::NONE)));
    }
    if options.contains(CdcOptions::STEP_SIZE) {
        children.push(DoChild::Da(leaf(
            "stepSize",
            FC::Cf,
            T::Int32U,
            TrgOps::NONE,
        )));
    }
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

// ISC

/// ISC, integer step controllable, per IEC 61850-7-3 §6.5.8.
///
/// `valWTr` plus `q` and `t`, an `Oper` whose `ctlVal` is an INT8, and the
/// optional `minVal` and `maxVal` as INT32 under CF.
pub fn isc(
    name: impl Into<String>,
    options: CdcOptions,
    control_options: ControlOptions,
    has_transient_indicator: bool,
) -> DataObject {
    let mut children = Vec::new();
    add_originator_ctlnum(&mut children, FC::St, control_options);
    children.push(DoChild::Da(cac_val_with_trans(
        "valWTr",
        FC::St,
        TrgOps::DCHG,
        has_transient_indicator,
    )));
    add_time_quality(FC::St, &mut children);
    add_controls(&mut children, T::Int8, control_options);
    if control_options.contains(ControlOptions::ST_SELD) {
        children.push(DoChild::Da(leaf(
            "stSeld",
            FC::St,
            T::Boolean,
            TrgOps::DCHG,
        )));
    }
    add_common_control_attributes(&mut children, control_options);
    if options.contains(CdcOptions::PICS_SUBST) {
        add_pics_subst_valwtr(&mut children, has_transient_indicator);
    }
    if options.contains(CdcOptions::BLK_ENA) {
        add_blk_ena(&mut children);
    }
    if options.contains(CdcOptions::MIN) {
        children.push(DoChild::Da(leaf("minVal", FC::Cf, T::Int32, TrgOps::NONE)));
    }
    if options.contains(CdcOptions::MAX) {
        children.push(DoChild::Da(leaf("maxVal", FC::Cf, T::Int32, TrgOps::NONE)));
    }
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

// BAC

/// BAC, binary controlled analogue process value, per IEC 61850-7-3 §6.5.10.
///
/// Shaped like APC, with the status attributes under MX and analogue control,
/// except that `Oper.ctlVal` is an INT8 rather than an `AnalogueValue`.
///
/// Both a generic INT8 control and an analogue control are built, so two `Oper`
/// attributes coexist; note that the two names collide, which the model builder
/// may reject.
pub fn bac(
    name: impl Into<String>,
    options: CdcOptions,
    control_options: ControlOptions,
    is_integer_not_float: bool,
) -> DataObject {
    let mut children = Vec::new();
    add_originator_ctlnum(&mut children, FC::Mx, control_options);
    children.push(DoChild::Da(cac_analogue_value(
        "mxVal",
        FC::Mx,
        TrgOps::DCHG,
        is_integer_not_float,
    )));
    add_time_quality(FC::Mx, &mut children);
    if control_options.contains(ControlOptions::ST_SELD) {
        children.push(DoChild::Da(leaf(
            "stSeld",
            FC::Mx,
            T::Boolean,
            TrgOps::DCHG,
        )));
    }
    add_controls(&mut children, T::Int8, control_options);
    if options.contains(CdcOptions::PICS_SUBST) {
        add_pics_subst_analogue(&mut children, is_integer_not_float);
    }
    if options.contains(CdcOptions::BLK_ENA) {
        add_blk_ena(&mut children);
    }
    children.push(DoChild::Da(leaf(
        "persistent",
        FC::Cf,
        T::Boolean,
        TrgOps::DCHG,
    )));
    add_analog_controls(&mut children, control_options, is_integer_not_float);
    if options.contains(CdcOptions::MIN) {
        children.push(DoChild::Da(cac_analogue_value(
            "minVal",
            FC::Cf,
            TrgOps::NONE,
            is_integer_not_float,
        )));
    }
    if options.contains(CdcOptions::MAX) {
        children.push(DoChild::Da(cac_analogue_value(
            "maxVal",
            FC::Cf,
            TrgOps::NONE,
            is_integer_not_float,
        )));
    }
    if options.contains(CdcOptions::STEP_SIZE) {
        children.push(DoChild::Da(cac_analogue_value(
            "stepSize",
            FC::Cf,
            TrgOps::NONE,
            is_integer_not_float,
        )));
    }
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

// LPL

/// LPL, logical node nameplate, per IEC 61850-7-3 §6.7.1.
///
/// `vendor` and `swRev` are mandatory, under DC. `configRev`, `ldNs` and
/// `lnNs` are added by their respective options.
pub fn lpl(name: impl Into<String>, options: CdcOptions) -> DataObject {
    let mut children = Vec::new();
    children.push(DoChild::Da(leaf(
        "vendor",
        FC::Dc,
        T::VisibleString(255),
        TrgOps::NONE,
    )));
    children.push(DoChild::Da(leaf(
        "swRev",
        FC::Dc,
        T::VisibleString(255),
        TrgOps::NONE,
    )));
    if options.contains(CdcOptions::AC_LN0_M) {
        children.push(DoChild::Da(leaf(
            "configRev",
            FC::Dc,
            T::VisibleString(255),
            TrgOps::NONE,
        )));
    }
    if options.contains(CdcOptions::AC_LN0_EX) {
        children.push(DoChild::Da(leaf(
            "ldNs",
            FC::Ex,
            T::VisibleString(255),
            TrgOps::NONE,
        )));
    }
    if options.contains(CdcOptions::AC_DLD_M) {
        children.push(DoChild::Da(leaf(
            "lnNs",
            FC::Ex,
            T::VisibleString(255),
            TrgOps::NONE,
        )));
    }
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

// DPL

/// DPL, device nameplate, per IEC 61850-7-3 §6.7.2.
///
/// `vendor` is mandatory, under DC. `hwRev`, `swRev`, `serNum`, `model` and
/// `location` are added by their respective options.
///
/// The nameplate options share bits 17 to 21 with the angle-range and phase
/// flags. That is safe because a device nameplate never carries those.
pub fn dpl(name: impl Into<String>, options: CdcOptions) -> DataObject {
    let mut children = Vec::new();
    children.push(DoChild::Da(leaf(
        "vendor",
        FC::Dc,
        T::VisibleString(255),
        TrgOps::NONE,
    )));
    if options.contains(CdcOptions::DPL_HWREV) {
        children.push(DoChild::Da(leaf(
            "hwRev",
            FC::Dc,
            T::VisibleString(255),
            TrgOps::NONE,
        )));
    }
    if options.contains(CdcOptions::DPL_SWREV) {
        children.push(DoChild::Da(leaf(
            "swRev",
            FC::Dc,
            T::VisibleString(255),
            TrgOps::NONE,
        )));
    }
    if options.contains(CdcOptions::DPL_SERNUM) {
        children.push(DoChild::Da(leaf(
            "serNum",
            FC::Dc,
            T::VisibleString(255),
            TrgOps::NONE,
        )));
    }
    if options.contains(CdcOptions::DPL_MODEL) {
        children.push(DoChild::Da(leaf(
            "model",
            FC::Dc,
            T::VisibleString(255),
            TrgOps::NONE,
        )));
    }
    if options.contains(CdcOptions::DPL_LOCATION) {
        children.push(DoChild::Da(leaf(
            "location",
            FC::Dc,
            T::VisibleString(255),
            TrgOps::NONE,
        )));
    }
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

// ACD

/// ACD, directional protection activation information, per IEC 61850-7-3
/// §6.2.8.
///
/// `general` and `dirGeneral`, then a `phsX` and `dirPhsX` pair for each phase
/// option that is set, followed by `q` and `t`.
pub fn acd(name: impl Into<String>, options: CdcOptions) -> DataObject {
    let mut children = Vec::new();
    children.push(DoChild::Da(leaf(
        "general",
        FC::St,
        T::Boolean,
        TrgOps::DCHG,
    )));
    children.push(DoChild::Da(leaf(
        "dirGeneral",
        FC::St,
        T::Enumerated,
        TrgOps::DCHG,
    )));
    if options.contains(CdcOptions::PHASE_A) {
        children.push(DoChild::Da(leaf("phsA", FC::St, T::Boolean, TrgOps::DCHG)));
        children.push(DoChild::Da(leaf(
            "dirPhsA",
            FC::St,
            T::Enumerated,
            TrgOps::DCHG,
        )));
    }
    if options.contains(CdcOptions::PHASE_B) {
        children.push(DoChild::Da(leaf("phsB", FC::St, T::Boolean, TrgOps::DCHG)));
        children.push(DoChild::Da(leaf(
            "dirPhsB",
            FC::St,
            T::Enumerated,
            TrgOps::DCHG,
        )));
    }
    if options.contains(CdcOptions::PHASE_C) {
        children.push(DoChild::Da(leaf("phsC", FC::St, T::Boolean, TrgOps::DCHG)));
        children.push(DoChild::Da(leaf(
            "dirPhsC",
            FC::St,
            T::Enumerated,
            TrgOps::DCHG,
        )));
    }
    if options.contains(CdcOptions::PHASE_NEUT) {
        children.push(DoChild::Da(leaf("neut", FC::St, T::Boolean, TrgOps::DCHG)));
        children.push(DoChild::Da(leaf(
            "dirNeut",
            FC::St,
            T::Enumerated,
            TrgOps::DCHG,
        )));
    }
    add_time_quality(FC::St, &mut children);
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

// ACT

/// ACT, protection activation information, per IEC 61850-7-3 §6.2.9.
///
/// `general`, then a `phsX` attribute for each phase option that is set,
/// followed by `q` and `t`. Unlike ACD it carries no direction attributes.
pub fn act(name: impl Into<String>, options: CdcOptions) -> DataObject {
    let mut children = Vec::new();
    children.push(DoChild::Da(leaf(
        "general",
        FC::St,
        T::Boolean,
        TrgOps::DCHG,
    )));
    if options.contains(CdcOptions::PHASE_A) {
        children.push(DoChild::Da(leaf("phsA", FC::St, T::Boolean, TrgOps::DCHG)));
    }
    if options.contains(CdcOptions::PHASE_B) {
        children.push(DoChild::Da(leaf("phsB", FC::St, T::Boolean, TrgOps::DCHG)));
    }
    if options.contains(CdcOptions::PHASE_C) {
        children.push(DoChild::Da(leaf("phsC", FC::St, T::Boolean, TrgOps::DCHG)));
    }
    if options.contains(CdcOptions::PHASE_NEUT) {
        children.push(DoChild::Da(leaf("neut", FC::St, T::Boolean, TrgOps::DCHG)));
    }
    add_time_quality(FC::St, &mut children);
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

// WYE

/// WYE, phase to ground and neutral related measured values, per
/// IEC 61850-7-3 §7.4.7.
///
/// Six CMV sub-objects: `phsA`, `phsB`, `phsC`, `neut`, `net` and `res`. Every
/// one receives the same `options`, so each expands in full.
pub fn wye(name: impl Into<String>, options: CdcOptions) -> DataObject {
    let mut children = vec![
        DoChild::SubDo(cmv("phsA", options)),
        DoChild::SubDo(cmv("phsB", options)),
        DoChild::SubDo(cmv("phsC", options)),
        DoChild::SubDo(cmv("neut", options)),
        DoChild::SubDo(cmv("net", options)),
        DoChild::SubDo(cmv("res", options)),
    ];
    if options.contains(CdcOptions::ANGLE_REF) {
        children.push(DoChild::Da(leaf(
            "angRef",
            FC::Cf,
            T::Enumerated,
            TrgOps::DCHG,
        )));
    }
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

// DEL

/// DEL, phase to phase related measured values, per IEC 61850-7-3 §7.4.8.
///
/// Three CMV sub-objects, `phsAB`, `phsBC` and `phsCA`, plus `angRef` when the
/// angle-reference option is set.
///
/// The trailing underscore in the function name avoids a name that reads like
/// a delete operation in editor completion.
pub fn del_(name: impl Into<String>, options: CdcOptions) -> DataObject {
    let mut children = Vec::new();
    children.push(DoChild::SubDo(cmv("phsAB", options)));
    children.push(DoChild::SubDo(cmv("phsBC", options)));
    children.push(DoChild::SubDo(cmv("phsCA", options)));
    if options.contains(CdcOptions::ANGLE_REF) {
        children.push(DoChild::Da(leaf(
            "angRef",
            FC::Cf,
            T::Enumerated,
            TrgOps::DCHG,
        )));
    }
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

// The setting common data classes

/// SPG, single point setting group, per IEC 61850-7-3 §8.2. `setVal` is a
/// BOOLEAN under SP.
pub fn spg(name: impl Into<String>, options: CdcOptions) -> DataObject {
    let mut children = Vec::new();
    children.push(DoChild::Da(leaf(
        "setVal",
        FC::Sp,
        T::Boolean,
        TrgOps::DCHG,
    )));
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

/// VSG, visible string setting group. `setVal` is a 255-byte visible string.
pub fn vsg(name: impl Into<String>, options: CdcOptions) -> DataObject {
    let mut children = Vec::new();
    children.push(DoChild::Da(leaf(
        "setVal",
        FC::Sp,
        T::VisibleString(255),
        TrgOps::DCHG,
    )));
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

/// ENG, enumerated setting group. `setVal` is an enumeration.
pub fn eng(name: impl Into<String>, options: CdcOptions) -> DataObject {
    let mut children = Vec::new();
    children.push(DoChild::Da(leaf(
        "setVal",
        FC::Sp,
        T::Enumerated,
        TrgOps::DCHG,
    )));
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

/// ING, integer setting group. `setVal` is an INT32, with optional `units`,
/// `minVal`, `maxVal` and `stepSize`.
///
/// `units` is the `Unit` attribute type, with `SIUnit` and an optional
/// `multiplier`, not a bare enumeration leaf.
pub fn ing(name: impl Into<String>, options: CdcOptions) -> DataObject {
    let mut children = Vec::new();
    children.push(DoChild::Da(leaf("setVal", FC::Sp, T::Int32, TrgOps::DCHG)));
    if options.contains(CdcOptions::UNIT) {
        children.push(DoChild::Da(cac_unit(
            "units",
            options.contains(CdcOptions::UNIT_MULTIPLIER),
        )));
    }
    if options.contains(CdcOptions::MIN) {
        children.push(DoChild::Da(leaf("minVal", FC::Sp, T::Int32, TrgOps::DCHG)));
    }
    if options.contains(CdcOptions::MAX) {
        children.push(DoChild::Da(leaf("maxVal", FC::Sp, T::Int32, TrgOps::DCHG)));
    }
    if options.contains(CdcOptions::STEP_SIZE) {
        children.push(DoChild::Da(leaf(
            "stepSize",
            FC::Sp,
            T::Int32U,
            TrgOps::DCHG,
        )));
    }
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

/// ASG, analogue setting group. `setMag` is an `AnalogueValue`, with optional
/// `units`, a scaled value configuration, `minVal`, `maxVal` and `stepSize`.
pub fn asg(name: impl Into<String>, options: CdcOptions, is_integer_not_float: bool) -> DataObject {
    let mut children = Vec::new();
    children.push(DoChild::Da(cac_analogue_value(
        "setMag",
        FC::Sp,
        TrgOps::DCHG,
        is_integer_not_float,
    )));
    if options.contains(CdcOptions::UNIT) {
        children.push(DoChild::Da(cac_unit(
            "units",
            options.contains(CdcOptions::UNIT_MULTIPLIER),
        )));
    }
    if options.contains(CdcOptions::AC_SCAV) {
        children.push(DoChild::Da(cac_scaled_value_config("sVC")));
    }
    if options.contains(CdcOptions::MIN) {
        children.push(DoChild::Da(cac_analogue_value(
            "minVal",
            FC::Cf,
            TrgOps::DCHG,
            is_integer_not_float,
        )));
    }
    if options.contains(CdcOptions::MAX) {
        children.push(DoChild::Da(cac_analogue_value(
            "maxVal",
            FC::Cf,
            TrgOps::DCHG,
            is_integer_not_float,
        )));
    }
    if options.contains(CdcOptions::STEP_SIZE) {
        children.push(DoChild::Da(cac_analogue_value(
            "stepSize",
            FC::Cf,
            TrgOps::DCHG,
            is_integer_not_float,
        )));
    }
    add_standard_options(&mut children, options);
    DataObject {
        name: name.into(),
        array_count: None,
        children,
    }
}

// -----------------------------------------------------------------------------
// Internal chaining helper for attaching children to a constructed attribute
// -----------------------------------------------------------------------------

impl DataAttribute {
    /// Sets the children; used only inside this module to assemble a
    /// constructed data attribute.
    fn with_children_internal(mut self, children: Vec<DataAttribute>) -> Self {
        self.children = children;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::{DataObject, DoChild};

    /// Flattens the children of a data object into (name, fc, type) tuples, so
    /// a test can compare the order.
    fn flatten_da_specs(d: &DataObject) -> Vec<(&str, FC, T)> {
        d.children
            .iter()
            .filter_map(|c| match c {
                DoChild::Da(da) => Some((da.name.as_str(), da.fc, da.ty)),
                DoChild::SubDo(_) => None,
            })
            .collect()
    }

    fn da_names(d: &DataObject) -> Vec<&str> {
        d.children
            .iter()
            .map(|c| match c {
                DoChild::Da(da) => da.name.as_str(),
                DoChild::SubDo(sd) => sd.name.as_str(),
            })
            .collect()
    }

    fn find_da<'a>(d: &'a DataObject, name: &str) -> &'a DataAttribute {
        d.children
            .iter()
            .find_map(|c| match c {
                DoChild::Da(da) if da.name == name => Some(da),
                _ => None,
            })
            .unwrap_or_else(|| panic!("DA `{name}` not found"))
    }

    // SPS, DPS, INS and ENS

    #[test]
    fn sps_minimal() {
        let d = sps("Ind1", CdcOptions::NONE);
        assert_eq!(
            flatten_da_specs(&d),
            vec![
                ("stVal", FC::St, T::Boolean),
                ("q", FC::St, T::Quality),
                ("t", FC::St, T::Timestamp),
            ]
        );
        // stVal triggers on data change and data update
        let st = find_da(&d, "stVal");
        assert_eq!(st.trg_ops, TrgOps::DCHG | TrgOps::DUPD);
        // q triggers on quality change
        assert_eq!(find_da(&d, "q").trg_ops, TrgOps::QCHG);
    }

    #[test]
    fn sps_pics_subst() {
        let d = sps("Ind1", CdcOptions::PICS_SUBST);
        assert_eq!(
            da_names(&d),
            vec!["stVal", "q", "t", "subEna", "subVal", "subQ", "subID"]
        );
        // subVal has the same type as stVal
        assert_eq!(find_da(&d, "subVal").ty, T::Boolean);
        assert_eq!(find_da(&d, "subVal").fc, FC::Sv);
    }

    #[test]
    fn sps_blk_ena_after_pics_subst() {
        let d = sps("Ind1", CdcOptions::PICS_SUBST | CdcOptions::BLK_ENA);
        assert_eq!(
            da_names(&d),
            vec!["stVal", "q", "t", "subEna", "subVal", "subQ", "subID", "blkEna"]
        );
        assert_eq!(find_da(&d, "blkEna").fc, FC::Bl);
    }

    #[test]
    fn sps_standard_options_order() {
        let d = sps(
            "Ind1",
            CdcOptions::DESC | CdcOptions::DESC_UNICODE | CdcOptions::AC_DLNDA | CdcOptions::AC_DLN,
        );
        let names = da_names(&d);
        // d, dU, cdcNs, cdcName and dataNs, all after stVal, q and t
        assert_eq!(&names[3..], &["d", "dU", "cdcNs", "cdcName", "dataNs"]);
        assert_eq!(find_da(&d, "d").fc, FC::Dc);
        assert_eq!(find_da(&d, "dataNs").fc, FC::Ex);
    }

    #[test]
    fn dps_uses_codedenum() {
        let d = dps("Pos", CdcOptions::PICS_SUBST);
        assert_eq!(find_da(&d, "stVal").ty, T::CodedEnum);
        assert_eq!(find_da(&d, "subVal").ty, T::CodedEnum);
    }

    #[test]
    fn ins_uses_int32() {
        let d = ins("AnIn", CdcOptions::PICS_SUBST);
        assert_eq!(find_da(&d, "stVal").ty, T::Int32);
        assert_eq!(find_da(&d, "subVal").ty, T::Int32);
    }

    #[test]
    fn ens_uses_enumerated() {
        let d = ens("Mod", CdcOptions::NONE);
        assert_eq!(find_da(&d, "stVal").ty, T::Enumerated);
    }

    // MV

    #[test]
    fn mv_float_minimal() {
        let d = mv("Volt", CdcOptions::NONE, false);
        assert_eq!(da_names(&d), vec!["mag", "q", "t"]);
        let mag = find_da(&d, "mag");
        assert_eq!(mag.ty, T::Constructed);
        assert_eq!(mag.fc, FC::Mx);
        assert_eq!(mag.children.len(), 1);
        assert_eq!(mag.children[0].name, "f");
        assert_eq!(mag.children[0].ty, T::Float32);
    }

    #[test]
    fn mv_int_uses_i_child() {
        let d = mv("Cnt", CdcOptions::NONE, true);
        let mag = find_da(&d, "mag");
        assert_eq!(mag.children[0].name, "i");
        assert_eq!(mag.children[0].ty, T::Int32);
    }

    #[test]
    fn mv_inst_mag_before_mag() {
        let d = mv("Volt", CdcOptions::INST_MAG, false);
        assert_eq!(da_names(&d), vec!["instMag", "mag", "q", "t"]);
    }

    #[test]
    fn mv_range_after_mag() {
        let d = mv("Volt", CdcOptions::RANGE, false);
        assert_eq!(da_names(&d), vec!["mag", "range", "q", "t"]);
        assert_eq!(find_da(&d, "range").ty, T::Enumerated);
    }

    #[test]
    fn mv_q_t_fc_is_mx() {
        let d = mv("Volt", CdcOptions::NONE, false);
        assert_eq!(find_da(&d, "q").fc, FC::Mx);
        assert_eq!(find_da(&d, "t").fc, FC::Mx);
    }

    // SPC, DPC and ENC

    #[test]
    fn spc_status_only_no_co_struct() {
        let d = spc("Op", CdcOptions::NONE, ControlOptions::NONE);
        // ctlModel is status-only, so no SBO, SBOw, Oper or Cancel is built
        assert_eq!(da_names(&d), vec!["stVal", "q", "t", "ctlModel"]);
        let cm = find_da(&d, "ctlModel");
        assert_eq!(cm.fc, FC::Cf);
        assert_eq!(cm.snapshot(), MmsValue::Integer(0));
    }

    #[test]
    fn spc_direct_normal_has_oper_only() {
        let opts = ControlOptions::NONE.with_model(ControlModel::DirectNormal);
        let d = spc("Op", CdcOptions::NONE, opts);
        let names = da_names(&d);
        assert!(names.contains(&"Oper"));
        assert!(!names.contains(&"SBO"));
        assert!(!names.contains(&"SBOw"));
        assert!(!names.contains(&"Cancel"));
        // The Oper structure: ctlVal, origin, ctlNum, T, Test, Check
        let oper = find_da(&d, "Oper");
        assert_eq!(oper.fc, FC::Co);
        let names: Vec<&str> = oper.children.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["ctlVal", "origin", "ctlNum", "T", "Test", "Check"]
        );
        let ctl_val = oper.child_by_name("ctlVal").unwrap();
        assert_eq!(ctl_val.ty, T::Boolean);
    }

    #[test]
    fn spc_sbo_normal_has_sbo_string() {
        let opts = ControlOptions::NONE.with_model(ControlModel::SboNormal);
        let d = spc("Op", CdcOptions::NONE, opts);
        let names = da_names(&d);
        assert!(names.contains(&"SBO"));
        assert!(!names.contains(&"SBOw"));
        assert!(names.contains(&"Oper"));
        let sbo = find_da(&d, "SBO");
        assert_eq!(sbo.ty, T::VisibleString(129));
        assert_eq!(sbo.fc, FC::Co);
    }

    #[test]
    fn spc_sbo_enhanced_has_sbow_struct() {
        let opts = ControlOptions::NONE.with_model(ControlModel::SboEnhanced);
        let d = spc("Op", CdcOptions::NONE, opts);
        let names = da_names(&d);
        assert!(names.contains(&"SBOw"));
        let sbow = find_da(&d, "SBOw");
        assert_eq!(sbow.ty, T::Constructed);
        // SBOw has the same shape as Oper, Check included
        let kid_names: Vec<&str> = sbow.children.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            kid_names,
            vec!["ctlVal", "origin", "ctlNum", "T", "Test", "Check"]
        );
    }

    #[test]
    fn spc_has_cancel() {
        let opts = ControlOptions::HAS_CANCEL.with_model(ControlModel::DirectNormal);
        let d = spc("Op", CdcOptions::NONE, opts);
        let cancel = find_da(&d, "Cancel");
        assert_eq!(cancel.ty, T::Constructed);
        // Cancel carries no Check
        let kid_names: Vec<&str> = cancel.children.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(kid_names, vec!["ctlVal", "origin", "ctlNum", "T", "Test"]);
    }

    #[test]
    fn spc_time_activated_adds_oper_tm() {
        let opts = (ControlOptions::IS_TIME_ACTIVATED).with_model(ControlModel::DirectNormal);
        let d = spc("Op", CdcOptions::NONE, opts);
        let oper = find_da(&d, "Oper");
        let kid_names: Vec<&str> = oper.children.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            kid_names,
            vec!["ctlVal", "operTm", "origin", "ctlNum", "T", "Test", "Check"]
        );
    }

    #[test]
    fn spc_origin_ctlnum_st_seld() {
        let opts = (ControlOptions::ORIGIN | ControlOptions::CTL_NUM | ControlOptions::ST_SELD)
            .with_model(ControlModel::DirectNormal);
        let d = spc("Op", CdcOptions::NONE, opts);
        let names = da_names(&d);
        // Order: origin, ctlNum, stVal, q, t, ctlModel, Oper, stSeld
        assert_eq!(names[0], "origin");
        assert_eq!(names[1], "ctlNum");
        assert!(names.contains(&"stSeld"));
        assert_eq!(find_da(&d, "stSeld").fc, FC::St);
    }

    #[test]
    fn dpc_st_val_codedenum_oper_ctlval_boolean() {
        // The stVal of a DPS is a coded enumeration, but DPC.Oper.ctlVal stays
        // a BOOLEAN
        let opts = ControlOptions::NONE.with_model(ControlModel::DirectNormal);
        let d = dpc("Pos", CdcOptions::NONE, opts);
        assert_eq!(find_da(&d, "stVal").ty, T::CodedEnum);
        let oper = find_da(&d, "Oper");
        assert_eq!(oper.child_by_name("ctlVal").unwrap().ty, T::Boolean);
    }

    #[test]
    fn enc_oper_ctlval_enumerated() {
        let opts = ControlOptions::NONE.with_model(ControlModel::DirectNormal);
        let d = enc("Mod", CdcOptions::NONE, opts);
        let oper = find_da(&d, "Oper");
        assert_eq!(oper.child_by_name("ctlVal").unwrap().ty, T::Enumerated);
    }

    // APC

    #[test]
    fn apc_float_oper_ctlval_is_analogue() {
        let opts = ControlOptions::NONE.with_model(ControlModel::DirectNormal);
        let d = apc("Set", CdcOptions::NONE, opts, false);
        let oper = find_da(&d, "Oper");
        let ctl_val = oper.child_by_name("ctlVal").unwrap();
        assert_eq!(ctl_val.ty, T::Constructed);
        assert_eq!(ctl_val.children[0].name, "f");
        assert_eq!(ctl_val.children[0].ty, T::Float32);
    }

    #[test]
    fn apc_int_oper_ctlval_uses_i() {
        let opts = ControlOptions::NONE.with_model(ControlModel::DirectNormal);
        let d = apc("Set", CdcOptions::NONE, opts, true);
        let oper = find_da(&d, "Oper");
        let ctl_val = oper.child_by_name("ctlVal").unwrap();
        assert_eq!(ctl_val.children[0].name, "i");
        assert_eq!(ctl_val.children[0].ty, T::Int32);
    }

    #[test]
    fn apc_status_fc_is_mx() {
        let opts = (ControlOptions::ORIGIN | ControlOptions::CTL_NUM | ControlOptions::ST_SELD)
            .with_model(ControlModel::DirectNormal);
        let d = apc("Set", CdcOptions::NONE, opts, false);
        // origin, ctlNum, mxVal, q, t and stSeld are all under MX
        for n in ["origin", "ctlNum", "mxVal", "q", "t", "stSeld"] {
            assert_eq!(find_da(&d, n).fc, FC::Mx, "{n}");
        }
    }

    #[test]
    fn apc_pics_subst_uses_analogue_subval() {
        let opts = ControlOptions::NONE.with_model(ControlModel::DirectNormal);
        let d = apc("Set", CdcOptions::PICS_SUBST, opts, false);
        let sub = find_da(&d, "subVal");
        assert_eq!(sub.ty, T::Constructed);
        assert_eq!(sub.fc, FC::Sv);
        assert_eq!(sub.children[0].name, "f");
    }

    // BSC

    #[test]
    fn bsc_val_wtr_struct() {
        let opts = ControlOptions::NONE.with_model(ControlModel::DirectNormal);
        let d = bsc("Step", CdcOptions::NONE, opts, false);
        let val = find_da(&d, "valWTr");
        assert_eq!(val.ty, T::Constructed);
        assert_eq!(val.fc, FC::St);
        // Without a transient indicator only posVal is present
        let kid_names: Vec<&str> = val.children.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(kid_names, vec!["posVal"]);
        assert_eq!(val.children[0].ty, T::Int8);
    }

    #[test]
    fn bsc_with_transient() {
        let opts = ControlOptions::NONE.with_model(ControlModel::DirectNormal);
        let d = bsc("Step", CdcOptions::NONE, opts, true);
        let val = find_da(&d, "valWTr");
        let kid_names: Vec<&str> = val.children.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(kid_names, vec!["posVal", "transInd"]);
    }

    #[test]
    fn bsc_oper_ctlval_codedenum() {
        let opts = ControlOptions::NONE.with_model(ControlModel::DirectNormal);
        let d = bsc("Step", CdcOptions::NONE, opts, false);
        let oper = find_da(&d, "Oper");
        assert_eq!(oper.child_by_name("ctlVal").unwrap().ty, T::CodedEnum);
        assert!(da_names(&d).contains(&"persistent"));
        assert_eq!(find_da(&d, "persistent").fc, FC::Cf);
    }

    #[test]
    fn bsc_pics_subst_uses_valwtr_subval() {
        let opts = ControlOptions::NONE.with_model(ControlModel::DirectNormal);
        let d = bsc("Step", CdcOptions::PICS_SUBST, opts, true);
        let sub = find_da(&d, "subVal");
        assert_eq!(sub.ty, T::Constructed);
        let kid_names: Vec<&str> = sub.children.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(kid_names, vec!["posVal", "transInd"]);
    }

    // Default values

    #[test]
    fn quality_default_is_13bit_padding3() {
        let d = sps("Ind1", CdcOptions::NONE);
        let q = find_da(&d, "q");
        assert_eq!(
            q.snapshot(),
            MmsValue::BitString {
                padding: 3,
                data: vec![0, 0]
            }
        );
    }

    #[test]
    fn dbpos_default_is_2bit_padding6() {
        let d = dps("Pos", CdcOptions::NONE);
        let st = find_da(&d, "stVal");
        assert_eq!(
            st.snapshot(),
            MmsValue::BitString {
                padding: 6,
                data: vec![0]
            }
        );
    }

    #[test]
    fn timestamp_default_is_8bytes_zero() {
        let d = sps("Ind1", CdcOptions::NONE);
        let t = find_da(&d, "t");
        assert_eq!(t.snapshot(), MmsValue::UtcTime([0u8; 8]));
    }

    #[test]
    fn ctl_model_initial_value_matches_model() {
        for model in [
            ControlModel::DirectNormal,
            ControlModel::SboNormal,
            ControlModel::DirectEnhanced,
            ControlModel::SboEnhanced,
        ] {
            let opts = ControlOptions::NONE.with_model(model);
            let d = spc("Op", CdcOptions::NONE, opts);
            let cm = find_da(&d, "ctlModel");
            assert_eq!(
                cm.snapshot(),
                MmsValue::Integer(model as i32 as i64),
                "{model:?}"
            );
        }
    }

    // End to end: a CDC inside a logical node, resolved by object reference

    #[test]
    fn sda_path_resolves_via_object_ref() {
        use crate::builder::*;
        use crate::object_ref::ObjectRef;
        use crate::tree::NodeRef;

        let ggio = LogicalNodeBuilder::new("", "GGIO", "1")
            .add_do(mv("AnIn1", CdcOptions::NONE, false))
            .build()
            .unwrap();
        let lln0 = LogicalNodeBuilder::lln0().build().unwrap();
        let ld = LogicalDeviceBuilder::new("WD1")
            .add_ln(lln0)
            .add_ln(ggio)
            .build()
            .unwrap();
        let m = IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap();

        // mag.f: domain IED1WD1, ln GGIO1, fc MX, path [AnIn1, mag, f]
        let r = ObjectRef::parse_mms("IED1WD1/GGIO1$MX$AnIn1$mag$f").unwrap();
        match m.node_by_object_ref(&r) {
            Some(NodeRef::Da(da)) => {
                assert_eq!(da.name, "f");
                assert_eq!(da.ty, T::Float32);
            }
            other => panic!("expected the data attribute f, got {other:?}"),
        }

        // q: domain IED1WD1, ln GGIO1, fc MX, path [AnIn1, q]
        let r = ObjectRef::parse_mms("IED1WD1/GGIO1$MX$AnIn1$q").unwrap();
        assert!(matches!(m.node_by_object_ref(&r), Some(NodeRef::Da(_))));
    }

    #[test]
    fn sda_path_resolves_for_oper_ctlval() {
        use crate::builder::*;
        use crate::object_ref::ObjectRef;
        use crate::tree::NodeRef;

        let opts = ControlOptions::NONE.with_model(ControlModel::DirectNormal);
        let csw = LogicalNodeBuilder::new("", "CSWI", "1")
            .add_do(spc("Pos", CdcOptions::NONE, opts))
            .build()
            .unwrap();
        let lln0 = LogicalNodeBuilder::lln0().build().unwrap();
        let ld = LogicalDeviceBuilder::new("WD1")
            .add_ln(lln0)
            .add_ln(csw)
            .build()
            .unwrap();
        let m = IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap();

        // Oper.origin.orCat is two sub-attribute levels deep
        let r = ObjectRef::parse_mms("IED1WD1/CSWI1$CO$Pos$Oper$origin$orCat").unwrap();
        match m.node_by_object_ref(&r) {
            Some(NodeRef::Da(da)) => {
                assert_eq!(da.name, "orCat");
                assert_eq!(da.ty, T::Enumerated);
            }
            other => panic!("expected the data attribute orCat, got {other:?}"),
        }
    }

    // BCR

    #[test]
    fn bcr_minimal() {
        let d = bcr("Cnt", CdcOptions::NONE);
        assert_eq!(da_names(&d), vec!["actVal", "q", "t", "pulsQty"]);
        assert_eq!(find_da(&d, "actVal").ty, T::Int64);
        assert_eq!(find_da(&d, "actVal").fc, FC::St);
        assert_eq!(find_da(&d, "pulsQty").ty, T::Float32);
        assert_eq!(find_da(&d, "pulsQty").fc, FC::Cf);
    }

    #[test]
    fn bcr_frozen_value_full() {
        let d = bcr("Cnt", CdcOptions::FROZEN_VALUE);
        assert_eq!(
            da_names(&d),
            vec!["actVal", "frVal", "frTm", "q", "t", "pulsQty", "frEna", "strTm", "frPd", "frRs"]
        );
        assert_eq!(find_da(&d, "frVal").ty, T::Int64);
        assert_eq!(find_da(&d, "frVal").fc, FC::St);
        assert_eq!(find_da(&d, "frEna").fc, FC::Cf);
        assert_eq!(find_da(&d, "frPd").ty, T::Int32);
    }

    #[test]
    fn bcr_unit() {
        let d = bcr("Cnt", CdcOptions::UNIT);
        assert!(da_names(&d).contains(&"units"));
        assert_eq!(find_da(&d, "units").ty, T::Enumerated);
        assert_eq!(find_da(&d, "units").fc, FC::Cf);
    }

    // SEC

    #[test]
    fn sec_minimal() {
        let d = sec("Vio", CdcOptions::NONE);
        assert_eq!(da_names(&d), vec!["cnt", "sev", "t"]);
        assert_eq!(find_da(&d, "cnt").ty, T::Int32U);
        assert_eq!(find_da(&d, "sev").ty, T::Enumerated);
    }

    #[test]
    fn sec_addr_addinfo() {
        let d = sec("Vio", CdcOptions::ADDR | CdcOptions::ADDINFO);
        assert_eq!(da_names(&d), vec!["cnt", "sev", "t", "addr", "addInfo"]);
        assert!(matches!(find_da(&d, "addr").ty, T::OctetString(64)));
        assert!(matches!(find_da(&d, "addInfo").ty, T::VisibleString(64)));
    }

    // VSS

    #[test]
    fn vss_stval_visible_string_255() {
        let d = vss("Msg", CdcOptions::NONE);
        assert!(matches!(find_da(&d, "stVal").ty, T::VisibleString(255)));
    }

    #[test]
    fn vss_pics_subst_uses_visible_string_not_boolean() {
        // subVal follows IEC 61850-7-3 and has the same type as stVal
        let d = vss("Msg", CdcOptions::PICS_SUBST);
        let sub = find_da(&d, "subVal");
        assert!(
            matches!(sub.ty, T::VisibleString(255)),
            "subVal must be a 255-byte visible string, not a BOOLEAN"
        );
    }

    // CMV

    #[test]
    fn cmv_minimal_only_mag_no_ang() {
        let d = cmv("V1", CdcOptions::NONE);
        assert_eq!(da_names(&d), vec!["cVal", "q", "t"]);
        let cval = find_da(&d, "cVal");
        assert_eq!(cval.ty, T::Constructed);
        assert_eq!(cval.fc, FC::Mx);
        let kid_names: Vec<&str> = cval.children.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(kid_names, vec!["mag"]);
    }

    #[test]
    fn cmv_ac_clc_o_adds_ang() {
        let d = cmv("V1", CdcOptions::AC_CLC_O);
        let cval = find_da(&d, "cVal");
        let kid_names: Vec<&str> = cval.children.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(kid_names, vec!["mag", "ang"]);
    }

    #[test]
    fn cmv_full_options() {
        let d = cmv(
            "V1",
            CdcOptions::INST_MAG | CdcOptions::AC_CLC_O | CdcOptions::RANGE | CdcOptions::RANGE_ANG,
        );
        assert_eq!(
            da_names(&d),
            vec!["instCVal", "cVal", "range", "rangeAng", "q", "t"]
        );
    }

    // SAV

    #[test]
    fn sav_minimal_float() {
        let d = sav("V", CdcOptions::NONE, false);
        assert_eq!(da_names(&d), vec!["instMag", "q", "t"]);
        let inst = find_da(&d, "instMag");
        assert_eq!(inst.ty, T::Constructed);
        assert_eq!(inst.children[0].name, "f");
        assert_eq!(inst.children[0].ty, T::Float32);
    }

    #[test]
    fn sav_full_options() {
        let d = sav(
            "V",
            CdcOptions::UNIT | CdcOptions::AC_SCAV | CdcOptions::MIN | CdcOptions::MAX,
            false,
        );
        assert_eq!(
            da_names(&d),
            vec!["instMag", "q", "t", "units", "sVC", "min", "max"]
        );
        let units = find_da(&d, "units");
        let unit_kids: Vec<&str> = units.children.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(unit_kids, vec!["SIUnit"]);
        let svc = find_da(&d, "sVC");
        let svc_kids: Vec<&str> = svc.children.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(svc_kids, vec!["scaleFactor", "offset"]);
    }

    #[test]
    fn sav_unit_with_multiplier() {
        let d = sav("V", CdcOptions::UNIT | CdcOptions::UNIT_MULTIPLIER, false);
        let units = find_da(&d, "units");
        let unit_kids: Vec<&str> = units.children.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(unit_kids, vec!["SIUnit", "multiplier"]);
    }

    // HST

    #[test]
    fn hst_minimal() {
        let d = hst("H", CdcOptions::NONE, 16);
        assert_eq!(
            da_names(&d),
            vec!["hstVal", "q", "t", "numPts", "units", "maxPts"]
        );
        assert_eq!(find_da(&d, "hstVal").ty, T::Int32);
        assert_eq!(find_da(&d, "hstVal").fc, FC::St);
        assert_eq!(find_da(&d, "numPts").ty, T::Int16U);
        assert_eq!(find_da(&d, "maxPts").ty, T::Int16U);
        // hstRangeC is absent
        assert!(!da_names(&d).contains(&"hstRangeC"));
    }

    // INC

    #[test]
    fn inc_minimal_status_only() {
        let d = inc("Mod", CdcOptions::NONE, ControlOptions::NONE);
        assert_eq!(da_names(&d), vec!["stVal", "q", "t", "ctlModel"]);
        assert_eq!(find_da(&d, "stVal").ty, T::Int32);
    }

    #[test]
    fn inc_oper_ctlval_int32() {
        let opts = ControlOptions::NONE.with_model(ControlModel::DirectNormal);
        let d = inc("Mod", CdcOptions::NONE, opts);
        let oper = find_da(&d, "Oper");
        assert_eq!(oper.child_by_name("ctlVal").unwrap().ty, T::Int32);
    }

    #[test]
    fn inc_min_max_step_size() {
        let opts = ControlOptions::NONE.with_model(ControlModel::DirectNormal);
        let d = inc(
            "Mod",
            CdcOptions::MIN | CdcOptions::MAX | CdcOptions::STEP_SIZE,
            opts,
        );
        let names = da_names(&d);
        assert!(names.contains(&"minVal"));
        assert!(names.contains(&"maxVal"));
        assert!(names.contains(&"stepSize"));
        assert_eq!(find_da(&d, "minVal").ty, T::Int32);
        assert_eq!(find_da(&d, "minVal").fc, FC::Cf);
        assert_eq!(find_da(&d, "stepSize").ty, T::Int32U);
    }

    // ISC

    #[test]
    fn isc_oper_ctlval_int8() {
        let opts = ControlOptions::NONE.with_model(ControlModel::DirectNormal);
        let d = isc("Step", CdcOptions::NONE, opts, false);
        let oper = find_da(&d, "Oper");
        assert_eq!(oper.child_by_name("ctlVal").unwrap().ty, T::Int8);
    }

    #[test]
    fn isc_with_transient_indicator() {
        let opts = ControlOptions::NONE.with_model(ControlModel::DirectNormal);
        let d = isc("Step", CdcOptions::NONE, opts, true);
        let val = find_da(&d, "valWTr");
        let kid_names: Vec<&str> = val.children.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(kid_names, vec!["posVal", "transInd"]);
    }

    #[test]
    fn isc_min_max() {
        let opts = ControlOptions::NONE.with_model(ControlModel::DirectNormal);
        let d = isc("Step", CdcOptions::MIN | CdcOptions::MAX, opts, false);
        let names = da_names(&d);
        assert!(names.contains(&"minVal"));
        assert!(names.contains(&"maxVal"));
        assert_eq!(find_da(&d, "minVal").ty, T::Int32);
    }

    // BAC

    #[test]
    fn bac_persistent_and_oper_int8() {
        let opts = ControlOptions::NONE.with_model(ControlModel::DirectNormal);
        let d = bac("Set", CdcOptions::NONE, opts, false);
        // The first generic Oper, from the INT8 control path
        let names = da_names(&d);
        assert!(names.contains(&"persistent"));
        assert_eq!(find_da(&d, "persistent").fc, FC::Cf);
        // Oper appears twice, once per control path
        let oper_count = names.iter().filter(|n| **n == "Oper").count();
        assert_eq!(oper_count, 2, "BAC builds both control paths");
    }

    #[test]
    fn bac_status_fc_is_mx() {
        let opts = (ControlOptions::ORIGIN | ControlOptions::CTL_NUM | ControlOptions::ST_SELD)
            .with_model(ControlModel::DirectNormal);
        let d = bac("Set", CdcOptions::NONE, opts, false);
        for n in ["origin", "ctlNum", "mxVal", "q", "t", "stSeld"] {
            assert_eq!(find_da(&d, n).fc, FC::Mx, "{n}");
        }
    }

    #[test]
    fn bac_full_options() {
        let opts = ControlOptions::NONE.with_model(ControlModel::DirectNormal);
        let d = bac(
            "Set",
            CdcOptions::MIN | CdcOptions::MAX | CdcOptions::STEP_SIZE,
            opts,
            false,
        );
        let names = da_names(&d);
        assert!(names.contains(&"minVal"));
        assert!(names.contains(&"maxVal"));
        assert!(names.contains(&"stepSize"));
        // Both are constructed analogue values
        assert_eq!(find_da(&d, "minVal").ty, T::Constructed);
        assert_eq!(find_da(&d, "stepSize").children[0].name, "f");
    }

    // LPL

    #[test]
    fn lpl_minimal() {
        let d = lpl("LPL", CdcOptions::NONE);
        assert_eq!(da_names(&d), vec!["vendor", "swRev"]);
        assert!(matches!(find_da(&d, "vendor").ty, T::VisibleString(255)));
        assert_eq!(find_da(&d, "vendor").fc, FC::Dc);
    }

    #[test]
    fn lpl_full_lln0() {
        let d = lpl(
            "LPL",
            CdcOptions::AC_LN0_M | CdcOptions::AC_LN0_EX | CdcOptions::AC_DLD_M,
        );
        assert_eq!(
            da_names(&d),
            vec!["vendor", "swRev", "configRev", "ldNs", "lnNs"]
        );
        assert_eq!(find_da(&d, "configRev").fc, FC::Dc);
        assert_eq!(find_da(&d, "ldNs").fc, FC::Ex);
        assert_eq!(find_da(&d, "lnNs").fc, FC::Ex);
    }

    // DPL

    #[test]
    fn dpl_minimal() {
        let d = dpl("DPL", CdcOptions::NONE);
        assert_eq!(da_names(&d), vec!["vendor"]);
    }

    #[test]
    fn dpl_full_options() {
        let d = dpl(
            "DPL",
            CdcOptions::DPL_HWREV
                | CdcOptions::DPL_SWREV
                | CdcOptions::DPL_SERNUM
                | CdcOptions::DPL_MODEL
                | CdcOptions::DPL_LOCATION,
        );
        assert_eq!(
            da_names(&d),
            vec!["vendor", "hwRev", "swRev", "serNum", "model", "location"]
        );
        for n in ["hwRev", "swRev", "serNum", "model", "location"] {
            assert_eq!(find_da(&d, n).fc, FC::Dc, "{n}");
        }
    }

    // ACD

    #[test]
    fn acd_minimal() {
        let d = acd("Op", CdcOptions::NONE);
        assert_eq!(da_names(&d), vec!["general", "dirGeneral", "q", "t"]);
        assert_eq!(find_da(&d, "general").ty, T::Boolean);
        assert_eq!(find_da(&d, "dirGeneral").ty, T::Enumerated);
    }

    #[test]
    fn acd_phases_all() {
        let d = acd("Op", CdcOptions::PHASES_ALL);
        assert_eq!(
            da_names(&d),
            vec![
                "general",
                "dirGeneral",
                "phsA",
                "dirPhsA",
                "phsB",
                "dirPhsB",
                "phsC",
                "dirPhsC",
                "neut",
                "dirNeut",
                "q",
                "t",
            ]
        );
    }

    // ACT

    #[test]
    fn act_minimal() {
        let d = act("Op", CdcOptions::NONE);
        assert_eq!(da_names(&d), vec!["general", "q", "t"]);
        // no direction attributes
        assert!(!da_names(&d).contains(&"dirGeneral"));
    }

    #[test]
    fn act_phases_abc() {
        let d = act("Op", CdcOptions::PHASES_ABC);
        assert_eq!(
            da_names(&d),
            vec!["general", "phsA", "phsB", "phsC", "q", "t"]
        );
    }

    // WYE

    #[test]
    fn wye_minimal_six_cmv() {
        let d = wye("V", CdcOptions::NONE);
        assert_eq!(
            da_names(&d),
            vec!["phsA", "phsB", "phsC", "neut", "net", "res"]
        );
        // every phase is a CMV sub-object
        for c in &d.children {
            assert!(matches!(c, DoChild::SubDo(_)));
        }
    }

    #[test]
    fn wye_angle_ref() {
        let d = wye("V", CdcOptions::ANGLE_REF);
        assert!(da_names(&d).contains(&"angRef"));
        assert_eq!(find_da(&d, "angRef").fc, FC::Cf);
    }

    // DEL

    #[test]
    fn del_minimal_three_cmv() {
        let d = del_("V", CdcOptions::NONE);
        assert_eq!(da_names(&d), vec!["phsAB", "phsBC", "phsCA"]);
    }

    #[test]
    fn del_angle_ref() {
        let d = del_("V", CdcOptions::ANGLE_REF);
        assert!(da_names(&d).contains(&"angRef"));
    }

    // The setting common data classes

    #[test]
    fn spg_setval_boolean_sp() {
        let d = spg("Sp", CdcOptions::NONE);
        assert_eq!(da_names(&d), vec!["setVal"]);
        assert_eq!(find_da(&d, "setVal").ty, T::Boolean);
        assert_eq!(find_da(&d, "setVal").fc, FC::Sp);
    }

    #[test]
    fn vsg_setval_visible_string_sp() {
        let d = vsg("Sg", CdcOptions::NONE);
        assert!(matches!(find_da(&d, "setVal").ty, T::VisibleString(255)));
        assert_eq!(find_da(&d, "setVal").fc, FC::Sp);
    }

    #[test]
    fn eng_setval_enumerated_sp() {
        let d = eng("Mode", CdcOptions::NONE);
        assert_eq!(find_da(&d, "setVal").ty, T::Enumerated);
        assert_eq!(find_da(&d, "setVal").fc, FC::Sp);
    }

    #[test]
    fn ing_minimal() {
        let d = ing("Lv", CdcOptions::NONE);
        assert_eq!(da_names(&d), vec!["setVal"]);
        assert_eq!(find_da(&d, "setVal").ty, T::Int32);
    }

    #[test]
    fn ing_full_options() {
        let d = ing(
            "Lv",
            CdcOptions::UNIT | CdcOptions::MIN | CdcOptions::MAX | CdcOptions::STEP_SIZE,
        );
        assert_eq!(
            da_names(&d),
            vec!["setVal", "units", "minVal", "maxVal", "stepSize"]
        );
        // units is the Unit attribute type
        assert_eq!(find_da(&d, "units").ty, T::Constructed);
        assert_eq!(find_da(&d, "minVal").fc, FC::Sp);
        assert_eq!(find_da(&d, "stepSize").ty, T::Int32U);
    }

    #[test]
    fn asg_minimal_float() {
        let d = asg("Set", CdcOptions::NONE, false);
        assert_eq!(da_names(&d), vec!["setMag"]);
        let m = find_da(&d, "setMag");
        assert_eq!(m.ty, T::Constructed);
        assert_eq!(m.children[0].name, "f");
    }

    #[test]
    fn asg_full_options() {
        let d = asg(
            "Set",
            CdcOptions::UNIT
                | CdcOptions::AC_SCAV
                | CdcOptions::MIN
                | CdcOptions::MAX
                | CdcOptions::STEP_SIZE,
            false,
        );
        assert_eq!(
            da_names(&d),
            vec!["setMag", "units", "sVC", "minVal", "maxVal", "stepSize"]
        );
        // minVal is a constructed analogue value
        assert_eq!(find_da(&d, "minVal").ty, T::Constructed);
        assert_eq!(find_da(&d, "stepSize").children[0].name, "f");
    }
}
