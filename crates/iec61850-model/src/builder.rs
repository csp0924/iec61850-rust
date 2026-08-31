//! Builders for the model tree.
//!
//! Building freezes the structure: once `build` returns, no node is added or
//! removed. Values stay mutable through the `Arc<RwLock<MmsValue>>` each data
//! attribute holds.
//!
//! # Examples
//!
//! ```
//! use iec61850_model::*;
//!
//! let lln0 = LogicalNodeBuilder::lln0()
//!     .add_do(
//!         DataObjectBuilder::scalar("Mod")
//!             .add_da(
//!                 "stVal",
//!                 FC::St,
//!                 DataAttributeType::Enumerated,
//!                 TrgOps::DCHG,
//!                 MmsValue::Integer(1),
//!             )
//!             .build()
//!             .unwrap(),
//!     )
//!     .build()
//!     .unwrap();
//!
//! let ld = LogicalDeviceBuilder::new("WD1")
//!     .add_ln(lln0)
//!     .build()
//!     .unwrap();
//!
//! let model = IedModelBuilder::new("IED1")
//!     .add_ld(ld)
//!     .unwrap()
//!     .build()
//!     .unwrap();
//!
//! assert!(model.ld_by_domain("IED1WD1").is_some());
//! ```

use crate::cb::{
    GooseControlBlock, LogControlBlock, ReportControlBlock, SettingGroupControlBlock,
    SvControlBlock,
};
use crate::compat::prelude::*;
use crate::compat::HashSet;
use crate::error::{ModelError, Result};
use crate::fc::FC;
use crate::tree::{
    DataAttribute, DataObject, DataSet, DoChild, IedModel, LogicalDevice, LogicalNode,
};
use crate::types::{DataAttributeType, TrgOps};
use crate::value::MmsValue;

// -----------------------------------------------------------------------------
// IedModelBuilder
// -----------------------------------------------------------------------------

/// Builds an [`IedModel`] from logical devices.
#[derive(Debug, Default)]
pub struct IedModelBuilder {
    ied_name: String,
    lds: Vec<LogicalDevice>,
}

impl IedModelBuilder {
    /// Creates a builder for an IED of the given name.
    pub fn new(ied_name: impl Into<String>) -> Self {
        Self {
            ied_name: ied_name.into(),
            lds: Vec::new(),
        }
    }

    /// Adds a logical device.
    pub fn add_ld(mut self, ld: LogicalDevice) -> Result<Self> {
        if self.lds.iter().any(|x| x.inst == ld.inst) {
            return Err(ModelError::DuplicateName {
                kind: "LogicalDevice",
                name: ld.inst,
                parent: self.ied_name.clone(),
            });
        }
        self.lds.push(ld);
        Ok(self)
    }

    /// Freezes the tree into an [`IedModel`], checking the invariants and
    /// building the domain index.
    ///
    /// # Errors
    ///
    /// [`ModelError::InvalidObjectRef`] for an empty IED name, a model with no
    /// logical device, or a logical device with no logical node;
    /// [`ModelError::InvalidParent`] when LLN0 is not the first logical node or
    /// an SGCB is attached outside LLN0; [`ModelError::DuplicateName`] when two
    /// logical devices resolve to the same domain name; and
    /// [`ModelError::DataSetEntryUnresolved`] when a data set entry references a
    /// node that does not exist.
    pub fn build(self) -> Result<IedModel> {
        if self.ied_name.is_empty() {
            return Err(ModelError::InvalidObjectRef {
                reason: "IED name is empty".into(),
            });
        }
        if self.lds.is_empty() {
            return Err(ModelError::InvalidObjectRef {
                reason: "at least one logical device is required".into(),
            });
        }

        // IEC 61850-7-2 requires LLN0, and the builder requires it first.
        for ld in &self.lds {
            let first = ld.lns.first().ok_or_else(|| ModelError::InvalidObjectRef {
                reason: format!("logical device `{}` has no logical node", ld.inst),
            })?;
            if first.class != "LLN0" || !first.inst.is_empty() {
                return Err(ModelError::InvalidParent {
                    kind: "LogicalDevice",
                    expected_parent:
                        "LLN0 must be the first logical node, with class LLN0 and an empty instance",
                    got_parent: format!("{}{}{}", first.prefix, first.class, first.inst),
                });
            }
            // An SGCB may only be attached to LLN0.
            for ln in ld.lns.iter().skip(1) {
                if ln.sgcb.is_some() {
                    return Err(ModelError::InvalidParent {
                        kind: "SettingGroupControlBlock",
                        expected_parent: "LLN0",
                        got_parent: ln.full_name(),
                    });
                }
            }
        }

        // Two logical devices must not resolve to the same domain name.
        let mut seen = HashSet::new();
        for ld in &self.lds {
            let dn = ld.domain_name(&self.ied_name);
            if !seen.insert(dn.clone()) {
                return Err(ModelError::DuplicateName {
                    kind: "Domain",
                    name: dn,
                    parent: self.ied_name.clone(),
                });
            }
        }

        // Every data set entry must resolve inside its own logical device.
        let model_unchecked = IedModel::from_parts(self.ied_name.clone(), self.lds);
        validate_datasets(&model_unchecked)?;
        Ok(model_unchecked)
    }
}

fn validate_datasets(model: &IedModel) -> Result<()> {
    for ld in &model.lds {
        for ln in &ld.lns {
            for ds in &ln.datasets {
                for entry in &ds.entries {
                    let target_ld = if entry.ld_inst.is_empty() {
                        ld
                    } else {
                        // In practice an FCDA `ldInst` is written two ways
                        // (IEC 61850-6 §9.3.5): the LDevice `inst`, which is
                        // what the text says, or the wire-level name
                        // `iedName + inst`. Try the instance first, then the
                        // full name.
                        match model
                            .ld_by_inst(&entry.ld_inst)
                            .or_else(|| model.ld_by_domain(&entry.ld_inst))
                        {
                            Some(x) => x,
                            None => {
                                return Err(ModelError::DataSetEntryUnresolved {
                                    dataset: ds.name.clone(),
                                    entry: format!(
                                        "{}/{}${}${}",
                                        entry.ld_inst,
                                        entry.ln_name,
                                        entry.fc,
                                        entry.do_path.join("$")
                                    ),
                                })
                            }
                        }
                    };
                    let Some(target_ln) = target_ld.ln_by_name(&entry.ln_name) else {
                        return Err(ModelError::DataSetEntryUnresolved {
                            dataset: ds.name.clone(),
                            entry: format!(
                                "{}/{}${}${}",
                                entry.ld_inst,
                                entry.ln_name,
                                entry.fc,
                                entry.do_path.join("$")
                            ),
                        });
                    };
                    let first = entry.do_path.first().ok_or_else(|| {
                        ModelError::DataSetEntryUnresolved {
                            dataset: ds.name.clone(),
                            entry: "the data object path is empty".into(),
                        }
                    })?;
                    if target_ln.do_by_name(first).is_none() {
                        return Err(ModelError::DataSetEntryUnresolved {
                            dataset: ds.name.clone(),
                            entry: format!(
                                "{}/{}${}${}",
                                entry.ld_inst,
                                entry.ln_name,
                                entry.fc,
                                entry.do_path.join("$")
                            ),
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// LogicalDeviceBuilder
// -----------------------------------------------------------------------------

/// Builds a [`LogicalDevice`] from logical nodes.
#[derive(Debug)]
pub struct LogicalDeviceBuilder {
    inst: String,
    ld_name: Option<String>,
    lns: Vec<LogicalNode>,
}

impl LogicalDeviceBuilder {
    /// Creates a builder for a logical device of the given instance name.
    pub fn new(inst: impl Into<String>) -> Self {
        Self {
            inst: inst.into(),
            ld_name: None,
            lns: Vec::new(),
        }
    }

    /// Sets the functional `ldName` of IEC 61850-6 §8.5, which then replaces
    /// `ied_name + inst` as the MMS domain name.
    pub fn with_ld_name(mut self, ld_name: impl Into<String>) -> Self {
        self.ld_name = Some(ld_name.into());
        self
    }

    /// Adds a logical node. LLN0 has to be added first.
    pub fn add_ln(mut self, ln: LogicalNode) -> Self {
        self.lns.push(ln);
        self
    }

    /// Freezes the logical device.
    pub fn build(self) -> Result<LogicalDevice> {
        if self.inst.is_empty() {
            return Err(ModelError::InvalidObjectRef {
                reason: "logical device instance is empty".into(),
            });
        }
        // Two logical nodes in one device must not share a full name.
        let mut seen = HashSet::new();
        for ln in &self.lns {
            let n = ln.full_name();
            if !seen.insert(n.clone()) {
                return Err(ModelError::DuplicateName {
                    kind: "LogicalNode",
                    name: n,
                    parent: self.inst,
                });
            }
        }
        Ok(LogicalDevice {
            inst: self.inst,
            ld_name: self.ld_name,
            lns: self.lns,
        })
    }
}

// -----------------------------------------------------------------------------
// LogicalNodeBuilder
// -----------------------------------------------------------------------------

/// Builds a [`LogicalNode`] from data objects, data sets and control blocks.
#[derive(Debug)]
pub struct LogicalNodeBuilder {
    prefix: String,
    class: String,
    inst: String,
    dos: Vec<DataObject>,
    datasets: Vec<DataSet>,
    rcbs: Vec<ReportControlBlock>,
    gocbs: Vec<GooseControlBlock>,
    svcbs: Vec<SvControlBlock>,
    lcbs: Vec<LogControlBlock>,
    sgcb: Option<SettingGroupControlBlock>,
}

impl LogicalNodeBuilder {
    /// Creates a builder for a logical node with the given prefix, class and instance.
    pub fn new(
        prefix: impl Into<String>,
        class: impl Into<String>,
        inst: impl Into<String>,
    ) -> Self {
        Self {
            prefix: prefix.into(),
            class: class.into(),
            inst: inst.into(),
            dos: Vec::new(),
            datasets: Vec::new(),
            rcbs: Vec::new(),
            gocbs: Vec::new(),
            svcbs: Vec::new(),
            lcbs: Vec::new(),
            sgcb: None,
        }
    }

    /// Builds LLN0: an empty prefix, class `LLN0` and an empty instance.
    pub fn lln0() -> Self {
        Self::new("", "LLN0", "")
    }

    /// Adds a data object.
    pub fn add_do(mut self, d: DataObject) -> Self {
        self.dos.push(d);
        self
    }

    /// Adds a data set.
    pub fn add_dataset(mut self, ds: DataSet) -> Self {
        self.datasets.push(ds);
        self
    }

    /// Adds a report control block.
    pub fn add_rcb(mut self, rcb: ReportControlBlock) -> Self {
        self.rcbs.push(rcb);
        self
    }

    /// Adds a GOOSE control block.
    pub fn add_gocb(mut self, cb: GooseControlBlock) -> Self {
        self.gocbs.push(cb);
        self
    }

    /// Adds a sampled values control block.
    pub fn add_svcb(mut self, cb: SvControlBlock) -> Self {
        self.svcbs.push(cb);
        self
    }

    /// Adds a log control block.
    pub fn add_lcb(mut self, cb: LogControlBlock) -> Self {
        self.lcbs.push(cb);
        self
    }

    /// Sets the setting group control block. Only LLN0 may carry one; any other
    /// logical node fails at `build`.
    pub fn set_sgcb(mut self, sgcb: SettingGroupControlBlock) -> Self {
        self.sgcb = Some(sgcb);
        self
    }

    /// Freezes the logical node.
    pub fn build(self) -> Result<LogicalNode> {
        if self.class.is_empty() {
            return Err(ModelError::InvalidObjectRef {
                reason: "logical node class is empty".into(),
            });
        }
        // Two data objects in one logical node must not share a name.
        let mut seen = HashSet::new();
        for d in &self.dos {
            if !seen.insert(d.name.clone()) {
                return Err(ModelError::DuplicateName {
                    kind: "DataObject",
                    name: d.name.clone(),
                    parent: format!("{}{}{}", self.prefix, self.class, self.inst),
                });
            }
        }
        // Only LLN0 may carry a setting group control block.
        if self.sgcb.is_some() && (self.class != "LLN0" || !self.inst.is_empty()) {
            return Err(ModelError::InvalidParent {
                kind: "SettingGroupControlBlock",
                expected_parent: "LLN0",
                got_parent: format!("{}{}{}", self.prefix, self.class, self.inst),
            });
        }
        Ok(LogicalNode {
            prefix: self.prefix,
            class: self.class,
            inst: self.inst,
            dos: self.dos,
            datasets: self.datasets,
            rcbs: self.rcbs,
            gocbs: self.gocbs,
            svcbs: self.svcbs,
            lcbs: self.lcbs,
            sgcb: self.sgcb,
        })
    }
}

// -----------------------------------------------------------------------------
// DataObjectBuilder
// -----------------------------------------------------------------------------

/// Builds a [`DataObject`] from data attributes and sub-objects.
#[derive(Debug)]
pub struct DataObjectBuilder {
    name: String,
    array_count: Option<u32>,
    children: Vec<DoChild>,
}

impl DataObjectBuilder {
    /// Creates a builder for a scalar data object.
    pub fn scalar(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            array_count: None,
            children: Vec::new(),
        }
    }

    /// Creates a builder for an array data object of `count` elements.
    pub fn array(name: impl Into<String>, count: u32) -> Self {
        Self {
            name: name.into(),
            array_count: Some(count),
            children: Vec::new(),
        }
    }

    /// Adds a leaf data attribute built from its type, constraint, trigger options and initial value.
    pub fn add_da(
        mut self,
        name: impl Into<String>,
        fc: FC,
        ty: DataAttributeType,
        trg_ops: TrgOps,
        initial: MmsValue,
    ) -> Self {
        self.children.push(DoChild::Da(DataAttribute::new(
            name, fc, ty, trg_ops, initial,
        )));
        self
    }

    /// Adds an already assembled [`DataAttribute`], including the children of a
    /// constructed one.
    ///
    /// Used by the CDC factories, where for instance the `mag` of an MV is
    /// constructed and holds a `mag.f` sub-attribute.
    pub fn add_da_node(mut self, da: DataAttribute) -> Self {
        self.children.push(DoChild::Da(da));
        self
    }

    /// Adds a nested sub-object.
    pub fn add_sub_do(mut self, sd: DataObject) -> Self {
        self.children.push(DoChild::SubDo(sd));
        self
    }

    /// Freezes the data object.
    pub fn build(self) -> Result<DataObject> {
        if self.name.is_empty() {
            return Err(ModelError::InvalidObjectRef {
                reason: "data object name is empty".into(),
            });
        }
        // Data attributes and sub-objects share one namespace.
        let mut seen = HashSet::new();
        for c in &self.children {
            let n = match c {
                DoChild::Da(da) => &da.name,
                DoChild::SubDo(sd) => &sd.name,
            };
            if !seen.insert(n.clone()) {
                return Err(ModelError::DuplicateName {
                    kind: "DO child",
                    name: n.clone(),
                    parent: self.name,
                });
            }
        }
        Ok(DataObject {
            name: self.name,
            array_count: self.array_count,
            children: self.children,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::DataSetEntry;

    fn lln0_minimal() -> LogicalNode {
        LogicalNodeBuilder::lln0()
            .add_do(
                DataObjectBuilder::scalar("Mod")
                    .add_da(
                        "stVal",
                        FC::St,
                        DataAttributeType::Enumerated,
                        TrgOps::DCHG,
                        MmsValue::Integer(1),
                    )
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    }

    #[test]
    fn happy_path() {
        let ld = LogicalDeviceBuilder::new("WD1")
            .add_ln(lln0_minimal())
            .build()
            .unwrap();
        let model = IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap();
        assert!(model.ld_by_domain("IED1WD1").is_some());
    }

    #[test]
    fn ld_name_overrides_domain() {
        let ld = LogicalDeviceBuilder::new("WD1")
            .with_ld_name("CustomDomain")
            .add_ln(lln0_minimal())
            .build()
            .unwrap();
        let model = IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap();
        assert!(model.ld_by_domain("CustomDomain").is_some());
        assert!(model.ld_by_domain("IED1WD1").is_none());
    }

    #[test]
    fn missing_lln0_rejected() {
        let ggio_only = LogicalNodeBuilder::new("", "GGIO", "1").build().unwrap();
        let ld = LogicalDeviceBuilder::new("WD1")
            .add_ln(ggio_only)
            .build()
            .unwrap();
        let r = IedModelBuilder::new("IED1").add_ld(ld).unwrap().build();
        assert!(matches!(r, Err(ModelError::InvalidParent { .. })));
    }

    #[test]
    fn empty_ied_rejected() {
        let r = IedModelBuilder::new("").build();
        assert!(matches!(r, Err(ModelError::InvalidObjectRef { .. })));
    }

    #[test]
    fn no_ld_rejected() {
        let r = IedModelBuilder::new("IED1").build();
        assert!(matches!(r, Err(ModelError::InvalidObjectRef { .. })));
    }

    #[test]
    fn duplicate_ld_inst_rejected() {
        let ld1 = LogicalDeviceBuilder::new("WD1")
            .add_ln(lln0_minimal())
            .build()
            .unwrap();
        let ld2 = LogicalDeviceBuilder::new("WD1")
            .add_ln(lln0_minimal())
            .build()
            .unwrap();
        let b = IedModelBuilder::new("IED1").add_ld(ld1).unwrap();
        let r = b.add_ld(ld2);
        assert!(matches!(r, Err(ModelError::DuplicateName { .. })));
    }

    #[test]
    fn duplicate_ln_full_name_rejected() {
        let lln0_a = LogicalNodeBuilder::lln0().build().unwrap();
        let lln0_b = LogicalNodeBuilder::lln0().build().unwrap();
        let r = LogicalDeviceBuilder::new("WD1")
            .add_ln(lln0_a)
            .add_ln(lln0_b)
            .build();
        assert!(matches!(r, Err(ModelError::DuplicateName { .. })));
    }

    #[test]
    fn duplicate_do_in_ln_rejected() {
        let r = LogicalNodeBuilder::lln0()
            .add_do(DataObjectBuilder::scalar("Mod").build().unwrap())
            .add_do(DataObjectBuilder::scalar("Mod").build().unwrap())
            .build();
        assert!(matches!(r, Err(ModelError::DuplicateName { .. })));
    }

    #[test]
    fn duplicate_da_in_do_rejected() {
        let r = DataObjectBuilder::scalar("Mod")
            .add_da(
                "stVal",
                FC::St,
                DataAttributeType::Boolean,
                TrgOps::DCHG,
                MmsValue::Boolean(false),
            )
            .add_da(
                "stVal",
                FC::St,
                DataAttributeType::Boolean,
                TrgOps::DCHG,
                MmsValue::Boolean(true),
            )
            .build();
        assert!(matches!(r, Err(ModelError::DuplicateName { .. })));
    }

    #[test]
    fn sgcb_outside_lln0_rejected() {
        let r = LogicalNodeBuilder::new("", "GGIO", "1")
            .set_sgcb(SettingGroupControlBlock {
                num_of_sg: 4,
                act_sg: 1,
                has_resv_tms: false,
                default_resv_tms_s: 60,
            })
            .build();
        assert!(matches!(r, Err(ModelError::InvalidParent { .. })));
    }

    #[test]
    fn sgcb_on_lln0_ok() {
        let r = LogicalNodeBuilder::lln0()
            .set_sgcb(SettingGroupControlBlock {
                num_of_sg: 4,
                act_sg: 1,
                has_resv_tms: false,
                default_resv_tms_s: 60,
            })
            .build();
        assert!(r.is_ok());
    }

    #[test]
    fn dataset_entry_unresolved_rejected() {
        let lln0 = LogicalNodeBuilder::lln0()
            .add_dataset(DataSet {
                name: "DS1".into(),
                entries: vec![DataSetEntry {
                    ld_inst: String::new(), // the same logical device
                    ln_name: "GGIO1".into(),
                    fc: FC::St,
                    do_path: vec!["Ind1".into()],
                    array_index: None,
                    component: None,
                }],
            })
            .build()
            .unwrap();
        let ld = LogicalDeviceBuilder::new("WD1")
            .add_ln(lln0)
            .build()
            .unwrap();
        let r = IedModelBuilder::new("IED1").add_ld(ld).unwrap().build();
        assert!(matches!(r, Err(ModelError::DataSetEntryUnresolved { .. })));
    }

    #[test]
    fn dataset_entry_resolved_ok() {
        let ggio = LogicalNodeBuilder::new("", "GGIO", "1")
            .add_do(
                DataObjectBuilder::scalar("Ind1")
                    .add_da(
                        "stVal",
                        FC::St,
                        DataAttributeType::Boolean,
                        TrgOps::DCHG,
                        MmsValue::Boolean(false),
                    )
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let lln0 = LogicalNodeBuilder::lln0()
            .add_dataset(DataSet {
                name: "DS1".into(),
                entries: vec![DataSetEntry {
                    ld_inst: String::new(),
                    ln_name: "GGIO1".into(),
                    fc: FC::St,
                    do_path: vec!["Ind1".into()],
                    array_index: None,
                    component: None,
                }],
            })
            .build()
            .unwrap();
        let ld = LogicalDeviceBuilder::new("WD1")
            .add_ln(lln0)
            .add_ln(ggio)
            .build()
            .unwrap();
        let r = IedModelBuilder::new("IED1").add_ld(ld).unwrap().build();
        assert!(r.is_ok());
    }

    /// An FCDA `ldInst` written as the wire-level name, `iedName + inst`, must
    /// resolve as well as the bare instance.
    ///
    /// For example `ldInst="ied1Inverter"` refers to `<LDevice inst="Inverter">`
    /// under `<IED name="ied1">`; the instance is tried first and the full
    /// domain name second.
    #[test]
    fn dataset_entry_resolves_via_full_domain_name() {
        let ggio = LogicalNodeBuilder::new("", "GGIO", "1")
            .add_do(
                DataObjectBuilder::scalar("Ind1")
                    .add_da(
                        "stVal",
                        FC::St,
                        DataAttributeType::Boolean,
                        TrgOps::DCHG,
                        MmsValue::Boolean(false),
                    )
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let lln0 = LogicalNodeBuilder::lln0()
            .add_dataset(DataSet {
                name: "DS1".into(),
                // The full name is "ied1" + "Inverter", not the bare "Inverter".
                entries: vec![DataSetEntry {
                    ld_inst: "ied1Inverter".into(),
                    ln_name: "GGIO1".into(),
                    fc: FC::St,
                    do_path: vec!["Ind1".into()],
                    array_index: None,
                    component: None,
                }],
            })
            .build()
            .unwrap();
        let ld = LogicalDeviceBuilder::new("Inverter")
            .add_ln(lln0)
            .add_ln(ggio)
            .build()
            .unwrap();
        let r = IedModelBuilder::new("ied1").add_ld(ld).unwrap().build();
        assert!(r.is_ok(), "expected Ok, got {r:?}");
    }
}
