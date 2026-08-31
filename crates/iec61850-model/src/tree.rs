//! The model tree: `IedModel`, `LogicalDevice`, `LogicalNode`, `DataObject`
//! and `DataAttribute`.
//!
//! Shape of the tree, and why it matters to a caller:
//!
//! 1. Children live in a `Vec`, so their order is the index order. That gives
//!    the stable enumeration `GetVariableAccessAttributes` and `GetNameList`
//!    need, and keeps traversal cache-friendly.
//! 2. A control block belongs to the logical node that owns it; see `cb.rs`.
//! 3. An array container is marked with `Option<u32>` rather than by a
//!    sentinel child, so the type carries the fact instead of an implicit
//!    ordering convention.
//! 4. There is no reverse lookup from a value back to its data attribute; the
//!    read path always carries an object reference or a node reference.
//! 5. Every name is an owned `String`; there is no second borrowed path.

use crate::cb::{
    GooseControlBlock, LogControlBlock, ReportControlBlock, SettingGroupControlBlock,
    SvControlBlock,
};
use crate::compat::prelude::*;
use crate::fc::FC;
use crate::object_ref::{ObjectRef, Segment};
use crate::types::{DataAttributeType, TrgOps};
use crate::value::MmsValue;

use crate::compat::{rwlock_read, rwlock_write, Arc, HashMap, RwLock};

// -----------------------------------------------------------------------------
// IedModel
// -----------------------------------------------------------------------------

/// The root of an IED data model tree.
///
/// The structure is frozen by `IedModelBuilder::build`; values stay mutable
/// through the `Arc<RwLock<MmsValue>>` each data attribute holds.
#[derive(Debug)]
pub struct IedModel {
    /// IED name, which prefixes every wire-level domain name.
    pub ied_name: String,
    /// The logical devices, in the order the builder received them.
    pub lds: Vec<LogicalDevice>,
    /// Domain name to logical device index, built during `build`, so a lookup
    /// is constant time.
    domain_index: HashMap<String, usize>,
}

impl IedModel {
    /// Called by the builder; outside code goes through `IedModelBuilder`.
    pub(crate) fn from_parts(ied_name: String, lds: Vec<LogicalDevice>) -> Self {
        let mut domain_index = HashMap::with_capacity(lds.len());
        for (i, ld) in lds.iter().enumerate() {
            domain_index.insert(ld.domain_name(&ied_name), i);
        }
        Self {
            ied_name,
            lds,
            domain_index,
        }
    }

    /// Finds a logical device by its wire-level domain name, which is
    /// `ied_name + inst`, or `ld_name` when functional naming is used.
    pub fn ld_by_domain(&self, domain: &str) -> Option<&LogicalDevice> {
        self.domain_index.get(domain).map(|&i| &self.lds[i])
    }

    /// Finds a logical device by its SCL `inst` attribute.
    pub fn ld_by_inst(&self, inst: &str) -> Option<&LogicalDevice> {
        self.lds.iter().find(|ld| ld.inst == inst)
    }

    /// Resolves an object reference to a node, walking domain, logical node,
    /// data object and then data attributes, sub-attributes and array indices.
    ///
    /// Returns `None` when nothing matches. An over-long reference is rejected
    /// earlier, by the `ObjectRef` parser, so no lookup silently overflows.
    pub fn node_by_object_ref(&self, r: &ObjectRef) -> Option<NodeRef<'_>> {
        let ld = self.ld_by_domain(&r.domain)?;
        let ln = ld.ln_by_name(&r.ln)?;

        if r.path.is_empty() {
            return Some(NodeRef::Ln(ln));
        }

        // The first segment is always a data object name.
        let first_name = match &r.path[0] {
            Segment::Name(n) => n,
            Segment::Index(_) => return None, // an index cannot follow a logical node
        };
        let mut current_do = ln.do_by_name(first_name)?;
        let mut idx = 1;

        // What follows is either an index, or a sub-object or attribute name.
        while idx < r.path.len() {
            match &r.path[idx] {
                Segment::Index(_i) => {
                    // An index is only meaningful on an array container, so
                    // only the declaration is checked here; array elements are
                    // not materialized by the model.
                    current_do.array_count?;
                    idx += 1;
                    // After an index the path either ends or continues into a
                    // data attribute.
                    if idx >= r.path.len() {
                        return Some(NodeRef::Do(current_do));
                    }
                }
                Segment::Name(name) => {
                    // Look the name up among the data object's children.
                    match current_do.child_by_name(name) {
                        Some(DoChild::SubDo(sd)) => {
                            current_do = sd;
                            idx += 1;
                        }
                        Some(DoChild::Da(da)) => {
                            idx += 1;
                            // Sub-attributes may follow, so descend into the children.
                            return resolve_sda_path(da, &r.path, idx);
                        }
                        None => return None,
                    }
                }
            }
        }

        Some(NodeRef::Do(current_do))
    }

    /// Walks the whole tree in pre-order, parents before children.
    pub fn walk<F: FnMut(ModelNode<'_>)>(&self, mut f: F) {
        for ld in &self.lds {
            f(ModelNode::Ld(ld));
            for ln in &ld.lns {
                f(ModelNode::Ln(ln));
                for d in &ln.dos {
                    walk_do(d, &mut f);
                }
            }
        }
    }
}

/// Resolves the remainder of a path below a data attribute, that is its
/// sub-attributes.
///
/// `idx` is the next segment not yet consumed. A sub-attribute cannot carry an
/// array index, so a `Segment::Index` here yields `None`.
fn resolve_sda_path<'a>(
    mut da: &'a DataAttribute,
    path: &[Segment],
    mut idx: usize,
) -> Option<NodeRef<'a>> {
    while idx < path.len() {
        match &path[idx] {
            Segment::Name(n) => {
                let child = da.child_by_name(n)?;
                da = child;
                idx += 1;
            }
            // An array index only ever follows a data object.
            Segment::Index(_) => return None,
        }
    }
    Some(NodeRef::Da(da))
}

fn walk_do<'a, F: FnMut(ModelNode<'a>)>(d: &'a DataObject, f: &mut F) {
    f(ModelNode::Do(d));
    for c in &d.children {
        match c {
            DoChild::Da(da) => walk_da(da, f),
            DoChild::SubDo(sd) => walk_do(sd, f),
        }
    }
}

fn walk_da<'a, F: FnMut(ModelNode<'a>)>(da: &'a DataAttribute, f: &mut F) {
    f(ModelNode::Da(da));
    for child in &da.children {
        walk_da(child, f);
    }
}

// -----------------------------------------------------------------------------
// LogicalDevice
// -----------------------------------------------------------------------------

/// One logical device of an IED, and the MMS domain it maps to.
#[derive(Debug)]
pub struct LogicalDevice {
    /// The SCL `inst` attribute, such as `WD1` or `GenericIO`.
    pub inst: String,
    /// The functional `ldName` of IEC 61850-6 §8.5; `None` means the domain
    /// name is `ied_name + inst`.
    pub ld_name: Option<String>,
    /// The logical nodes; LLN0 is always first.
    pub lns: Vec<LogicalNode>,
}

impl LogicalDevice {
    /// Returns the MMS domain name: `ld_name` when set, otherwise
    /// `ied_name + inst`.
    pub fn domain_name(&self, ied_name: &str) -> String {
        match &self.ld_name {
            Some(n) => n.clone(),
            None => {
                let mut s = String::with_capacity(ied_name.len() + self.inst.len());
                s.push_str(ied_name);
                s.push_str(&self.inst);
                s
            }
        }
    }

    /// Finds a logical node by its full name, `prefix + class + inst`.
    pub fn ln_by_name(&self, name: &str) -> Option<&LogicalNode> {
        self.lns.iter().find(|ln| ln.full_name_eq(name))
    }
}

// -----------------------------------------------------------------------------
// LogicalNode
// -----------------------------------------------------------------------------

/// One logical node, holding its data objects, data sets and control blocks.
#[derive(Debug)]
pub struct LogicalNode {
    /// Logical node prefix; empty when the node has none.
    pub prefix: String,
    /// The logical node class of IEC 61850-7-4, such as `LLN0`, `MMXU` or
    /// `XCBR`.
    pub class: String,
    /// Logical node instance number, as a string; empty on LLN0.
    pub inst: String,
    /// The data objects, in the order the type declared them.
    pub dos: Vec<DataObject>,
    /// Data sets defined under this logical node, per IEC 61850-7-2 §22.
    pub datasets: Vec<DataSet>,
    /// Report control blocks owned by this logical node.
    pub rcbs: Vec<ReportControlBlock>,
    /// GOOSE control blocks owned by this logical node.
    pub gocbs: Vec<GooseControlBlock>,
    /// Sampled values control blocks owned by this logical node.
    pub svcbs: Vec<SvControlBlock>,
    /// Log control blocks owned by this logical node.
    pub lcbs: Vec<LogControlBlock>,
    /// The setting group control block. Only LLN0 may hold one; the builder
    /// rejects it on any other logical node.
    pub sgcb: Option<SettingGroupControlBlock>,
}

impl LogicalNode {
    /// Returns the full logical node name, `prefix + class + inst`.
    pub fn full_name(&self) -> String {
        let mut s = String::with_capacity(self.prefix.len() + self.class.len() + self.inst.len());
        s.push_str(&self.prefix);
        s.push_str(&self.class);
        s.push_str(&self.inst);
        s
    }

    /// Compares against a full name without allocating one.
    fn full_name_eq(&self, other: &str) -> bool {
        let p = self.prefix.len();
        let c = self.class.len();
        let i = self.inst.len();
        if other.len() != p + c + i {
            return false;
        }
        other.as_bytes()[..p] == *self.prefix.as_bytes()
            && other.as_bytes()[p..p + c] == *self.class.as_bytes()
            && other.as_bytes()[p + c..] == *self.inst.as_bytes()
    }

    /// Finds a data object by name.
    pub fn do_by_name(&self, name: &str) -> Option<&DataObject> {
        self.dos.iter().find(|d| d.name == name)
    }
}

// -----------------------------------------------------------------------------
// DataObject
// -----------------------------------------------------------------------------

/// One data object, holding data attributes and nested sub-objects.
#[derive(Debug)]
pub struct DataObject {
    /// Data object name.
    pub name: String,
    /// `Some(n)` marks an array container of `n` elements, indexed `(0)` to
    /// `(n-1)`; `None` marks a scalar data object.
    ///
    /// Array elements are not materialized: `children` holds the template, and
    /// only the element count is recorded here.
    pub array_count: Option<u32>,
    /// The children, in the order the type declared them.
    pub children: Vec<DoChild>,
}

impl DataObject {
    /// Finds a direct child by name, one level only.
    pub fn child_by_name(&self, name: &str) -> Option<&DoChild> {
        self.children.iter().find(|c| match c {
            DoChild::Da(da) => da.name == name,
            DoChild::SubDo(sd) => sd.name == name,
        })
    }

    /// Iterates the direct data attributes carrying the given functional constraint.
    pub fn children_with_fc(&self, fc: FC) -> impl Iterator<Item = &DataAttribute> {
        self.children.iter().filter_map(move |c| match c {
            DoChild::Da(da) if da.fc == fc => Some(da),
            _ => None,
        })
    }
}

/// A child of a data object: either a data attribute or a nested sub-object.
#[derive(Debug)]
pub enum DoChild {
    /// A data attribute.
    Da(DataAttribute),
    /// A nested sub-object.
    SubDo(DataObject),
}

// -----------------------------------------------------------------------------
// DataAttribute
// -----------------------------------------------------------------------------

/// One data attribute, leaf or constructed.
#[derive(Debug)]
pub struct DataAttribute {
    /// Data attribute name.
    pub name: String,
    /// Functional constraint the attribute lives under.
    pub fc: FC,
    /// Declared type of the attribute.
    pub ty: DataAttributeType,
    /// Trigger options that make this attribute report a change.
    pub trg_ops: TrgOps,
    /// The runtime value. The `Arc<RwLock<_>>` lets an update proceed without
    /// locking the model structure.
    ///
    /// Only a leaf attribute carries a value. For a constructed attribute the
    /// authoritative values live on the leaves in `children`, and this field is
    /// a placeholder no read path consults; [`snapshot`](Self::snapshot)
    /// assembles the value from the children instead.
    pub value: Arc<RwLock<MmsValue>>,
    /// Nested sub-attributes, such as `mag.f`, `origin.orCat` or
    /// `Oper.ctlVal`.
    ///
    /// Always empty unless the type is constructed. The order is fixed by the
    /// builder and decides the order in which
    /// `GetVariableAccessAttributes` enumerates the type specification, which
    /// some client tools depend on.
    pub children: Vec<DataAttribute>,
}

impl DataAttribute {
    /// Creates a leaf data attribute, that is one whose type is not
    /// constructed.
    pub fn new(
        name: impl Into<String>,
        fc: FC,
        ty: DataAttributeType,
        trg_ops: TrgOps,
        initial: MmsValue,
    ) -> Self {
        Self {
            name: name.into(),
            fc,
            ty,
            trg_ops,
            value: Arc::new(RwLock::new(initial)),
            children: Vec::new(),
        }
    }

    /// Creates a constructed data attribute. The authoritative values live on
    /// the leaves in `children`; this node's own `value` is a placeholder, and
    /// every read goes through [`snapshot`](Self::snapshot).
    pub fn constructed(name: impl Into<String>, fc: FC, children: Vec<DataAttribute>) -> Self {
        Self {
            name: name.into(),
            fc,
            ty: DataAttributeType::Constructed,
            trg_ops: TrgOps::NONE,
            value: Arc::new(RwLock::new(MmsValue::Structure(Vec::new()))),
            children,
        }
    }

    /// Returns a copy of the current value.
    ///
    /// A constructed attribute is assembled recursively from `children` into an
    /// `MmsValue::Structure` whose element order matches `children`, and so
    /// matches what `GetVariableAccessAttributes` declares. Each leaf takes its
    /// own read lock briefly, so the snapshot is not atomic across leaves.
    pub fn snapshot(&self) -> MmsValue {
        if self.ty == DataAttributeType::Constructed {
            MmsValue::Structure(self.children.iter().map(|c| c.snapshot()).collect())
        } else {
            rwlock_read(&self.value).clone()
        }
    }

    /// Overwrites the runtime value.
    ///
    /// The inverse of [`snapshot`](Self::snapshot), used when a process image
    /// or an I/O loop pushes a measured value into the model.
    ///
    /// No type check is performed: the caller must keep the variant of `value`
    /// consistent with [`ty`](Self::ty), because writing a mismatched variant
    /// makes a client read a type that contradicts what
    /// `GetVariableAccessAttributes` declared.
    ///
    /// Only meaningful on a leaf attribute. A constructed attribute is read by
    /// assembling its children, so a value stored on it is never observed; to
    /// update a constructed attribute, store into each of its leaves.
    ///
    /// This is a method rather than direct access to `self.value` because the
    /// way a guard is acquired differs between the `std` and the embedded
    /// build, and that facade is crate-internal: without the method a consumer
    /// outside the crate could not write a value from one source file.
    pub fn store(&self, value: MmsValue) {
        *rwlock_write(&self.value) = value;
    }

    /// Finds a direct sub-attribute by name, one level only.
    pub fn child_by_name(&self, name: &str) -> Option<&DataAttribute> {
        self.children.iter().find(|c| c.name == name)
    }
}

// -----------------------------------------------------------------------------
// DataSet
// -----------------------------------------------------------------------------

/// One data set, per IEC 61850-7-2 §22.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSet {
    /// The data set name, without the `LN$` prefix; the MMS mapping adds the
    /// wire name.
    pub name: String,
    /// The entries, in the order the data set declares them, which the wire preserves.
    pub entries: Vec<DataSetEntry>,
}

/// One data set entry, addressing a data attribute or one of its components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSetEntry {
    /// The logical device instance of the referenced node. Left empty for the
    /// same device, in which case the builder fills it in.
    pub ld_inst: String,
    /// Full logical node name of the referenced node.
    pub ln_name: String,
    /// Functional constraint of the referenced attribute.
    pub fc: FC,
    /// The path `["DO", "DA", "SDA", ...]`; the last segment may be a data
    /// attribute or one of its components.
    pub do_path: Vec<String>,
    /// Array index, when the referenced data object is an array container.
    pub array_index: Option<u32>,
    /// Component below the addressed attribute, if the entry names one.
    pub component: Option<String>,
}

// -----------------------------------------------------------------------------
// Node references used when traversing
// -----------------------------------------------------------------------------

/// A borrowed node, as returned by traversal and lookup.
#[derive(Debug, Copy, Clone)]
pub enum ModelNode<'a> {
    /// A logical device.
    Ld(&'a LogicalDevice),
    /// A logical node.
    Ln(&'a LogicalNode),
    /// A data object.
    Do(&'a DataObject),
    /// A data attribute.
    Da(&'a DataAttribute),
}

/// The result of `node_by_object_ref`. It is narrower than `ModelNode`, since
/// a lookup only ever ends at a logical node, a data object or a data
/// attribute.
#[derive(Debug, Copy, Clone)]
pub enum NodeRef<'a> {
    /// A logical node.
    Ln(&'a LogicalNode),
    /// A data object.
    Do(&'a DataObject),
    /// A data attribute.
    Da(&'a DataAttribute),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn da(name: &str, fc: FC, ty: DataAttributeType, trg: TrgOps, init: MmsValue) -> DataAttribute {
        DataAttribute::new(name, fc, ty, trg, init)
    }

    fn build_simple_model() -> IedModel {
        // IED1WD1/LLN0$ST$Mod$stVal
        // IED1WD1/GGIO1$ST$Ind1$stVal
        let lln0 = LogicalNode {
            prefix: String::new(),
            class: "LLN0".into(),
            inst: String::new(),
            dos: vec![DataObject {
                name: "Mod".into(),
                array_count: None,
                children: vec![DoChild::Da(da(
                    "stVal",
                    FC::St,
                    DataAttributeType::Enumerated,
                    TrgOps::DCHG,
                    MmsValue::Integer(1),
                ))],
            }],
            datasets: vec![],
            rcbs: vec![],
            gocbs: vec![],
            svcbs: vec![],
            lcbs: vec![],
            sgcb: None,
        };
        let ggio1 = LogicalNode {
            prefix: String::new(),
            class: "GGIO".into(),
            inst: "1".into(),
            dos: vec![DataObject {
                name: "Ind1".into(),
                array_count: None,
                children: vec![DoChild::Da(da(
                    "stVal",
                    FC::St,
                    DataAttributeType::Boolean,
                    TrgOps::DCHG | TrgOps::QCHG,
                    MmsValue::Boolean(false),
                ))],
            }],
            datasets: vec![],
            rcbs: vec![],
            gocbs: vec![],
            svcbs: vec![],
            lcbs: vec![],
            sgcb: None,
        };
        let ld = LogicalDevice {
            inst: "WD1".into(),
            ld_name: None,
            lns: vec![lln0, ggio1],
        };
        IedModel::from_parts("IED1".into(), vec![ld])
    }

    #[test]
    fn domain_index_works() {
        let m = build_simple_model();
        assert!(m.ld_by_domain("IED1WD1").is_some());
        assert!(m.ld_by_domain("UnknownDomain").is_none());
    }

    #[test]
    fn ld_by_inst_works() {
        let m = build_simple_model();
        assert!(m.ld_by_inst("WD1").is_some());
    }

    #[test]
    fn ld_name_overrides_domain() {
        let ld = LogicalDevice {
            inst: "Cfg".into(),
            ld_name: Some("FuncName".into()),
            lns: vec![LogicalNode {
                prefix: String::new(),
                class: "LLN0".into(),
                inst: String::new(),
                dos: vec![],
                datasets: vec![],
                rcbs: vec![],
                gocbs: vec![],
                svcbs: vec![],
                lcbs: vec![],
                sgcb: None,
            }],
        };
        let m = IedModel::from_parts("IED1".into(), vec![ld]);
        assert!(m.ld_by_domain("FuncName").is_some());
        assert!(m.ld_by_domain("IED1Cfg").is_none()); // ld_name replaces it
    }

    #[test]
    fn ln_full_name_compose() {
        let ln = LogicalNode {
            prefix: "Prot".into(),
            class: "MMXU".into(),
            inst: "1".into(),
            dos: vec![],
            datasets: vec![],
            rcbs: vec![],
            gocbs: vec![],
            svcbs: vec![],
            lcbs: vec![],
            sgcb: None,
        };
        assert_eq!(ln.full_name(), "ProtMMXU1");
        assert!(ln.full_name_eq("ProtMMXU1"));
        assert!(!ln.full_name_eq("MMXU1"));
        assert!(!ln.full_name_eq("ProtMMXU"));
    }

    #[test]
    fn lookup_da_by_object_ref() {
        let m = build_simple_model();
        let r = ObjectRef::parse_mms("IED1WD1/GGIO1$ST$Ind1$stVal").unwrap();
        match m.node_by_object_ref(&r) {
            Some(NodeRef::Da(da)) => {
                assert_eq!(da.name, "stVal");
                assert_eq!(da.fc, FC::St);
            }
            other => panic!("expected a data attribute, got {other:?}"),
        }
    }

    #[test]
    fn lookup_ln_by_object_ref() {
        let m = build_simple_model();
        let r = ObjectRef {
            domain: "IED1WD1".into(),
            ln: "LLN0".into(),
            fc: Some(FC::St),
            path: vec![],
        };
        assert!(matches!(m.node_by_object_ref(&r), Some(NodeRef::Ln(_))));
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let m = build_simple_model();
        let r = ObjectRef::parse_mms("IED1WD1/GGIO1$ST$DoesNotExist").unwrap();
        assert!(m.node_by_object_ref(&r).is_none());
    }

    /// A model whose `PhV` is a WYE holding the phase sub-data-object `phsA`,
    /// itself a CMV whose `cVal` is a Vector of AnalogValue attributes, as
    /// IEC 61850-7-3 defines them.
    fn build_sdo_model() -> IedModel {
        let leaf = |value: f32| {
            DataAttribute::constructed(
                "mag",
                FC::Mx,
                vec![da(
                    "f",
                    FC::Mx,
                    DataAttributeType::Float32,
                    TrgOps::DCHG,
                    MmsValue::Float32(value),
                )],
            )
        };
        let phs_a = DataObject {
            name: "phsA".into(),
            array_count: None,
            children: vec![DoChild::Da(DataAttribute::constructed(
                "cVal",
                FC::Mx,
                vec![leaf(4.5)],
            ))],
        };
        let mmxu1 = LogicalNode {
            prefix: String::new(),
            class: "MMXU".into(),
            inst: "1".into(),
            dos: vec![DataObject {
                name: "PhV".into(),
                array_count: None,
                children: vec![DoChild::SubDo(phs_a)],
            }],
            datasets: vec![],
            rcbs: vec![],
            gocbs: vec![],
            svcbs: vec![],
            lcbs: vec![],
            sgcb: None,
        };
        let ld = LogicalDevice {
            inst: "WD1".into(),
            ld_name: None,
            lns: vec![mmxu1],
        };
        IedModel::from_parts("IED1".into(), vec![ld])
    }

    /// A reference may cross a sub-data-object on its way to a data attribute,
    /// and further sub-attributes below it.
    #[test]
    fn lookup_crosses_a_sub_data_object_to_a_leaf() {
        let m = build_sdo_model();
        let r = ObjectRef::parse_mms("IED1WD1/MMXU1$MX$PhV$phsA$cVal$mag$f").unwrap();
        match m.node_by_object_ref(&r) {
            Some(NodeRef::Da(da)) => {
                assert_eq!(da.name, "f");
                assert_eq!(da.snapshot(), MmsValue::Float32(4.5));
            }
            other => panic!("expected the float leaf, got {other:?}"),
        }
    }

    /// A reference that stops on a sub-data-object resolves to that object, so
    /// every level of a WYE tree is addressable.
    #[test]
    fn lookup_stopping_on_a_sub_data_object_yields_the_object() {
        let m = build_sdo_model();
        let r = ObjectRef::parse_mms("IED1WD1/MMXU1$MX$PhV$phsA").unwrap();
        match m.node_by_object_ref(&r) {
            Some(NodeRef::Do(d)) => assert_eq!(d.name, "phsA"),
            other => panic!("expected the sub-data-object, got {other:?}"),
        }
    }

    /// An unknown name below a sub-data-object does not resolve.
    #[test]
    fn lookup_unknown_under_a_sub_data_object_returns_none() {
        let m = build_sdo_model();
        let r = ObjectRef::parse_mms("IED1WD1/MMXU1$MX$PhV$phsA$nosuchda").unwrap();
        assert!(m.node_by_object_ref(&r).is_none());
    }

    #[test]
    fn walk_visits_all() {
        let m = build_simple_model();
        let mut count_ld = 0;
        let mut count_ln = 0;
        let mut count_do = 0;
        let mut count_da = 0;
        m.walk(|n| match n {
            ModelNode::Ld(_) => count_ld += 1,
            ModelNode::Ln(_) => count_ln += 1,
            ModelNode::Do(_) => count_do += 1,
            ModelNode::Da(_) => count_da += 1,
        });
        assert_eq!(count_ld, 1);
        assert_eq!(count_ln, 2);
        assert_eq!(count_do, 2);
        assert_eq!(count_da, 2);
    }

    #[test]
    fn da_snapshot_clones() {
        let d = da(
            "stVal",
            FC::St,
            DataAttributeType::Boolean,
            TrgOps::DCHG,
            MmsValue::Boolean(true),
        );
        assert_eq!(d.snapshot(), MmsValue::Boolean(true));
        // The original value is still readable through the lock.
        assert_eq!(*d.value.read().unwrap(), MmsValue::Boolean(true));
    }

    #[test]
    fn children_with_fc_filters() {
        let d = DataObject {
            name: "Test".into(),
            array_count: None,
            children: vec![
                DoChild::Da(da(
                    "stVal",
                    FC::St,
                    DataAttributeType::Boolean,
                    TrgOps::DCHG,
                    MmsValue::Boolean(false),
                )),
                DoChild::Da(da(
                    "ctlModel",
                    FC::Cf,
                    DataAttributeType::Enumerated,
                    TrgOps::NONE,
                    MmsValue::Integer(0),
                )),
                DoChild::Da(da(
                    "q",
                    FC::St,
                    DataAttributeType::Quality,
                    TrgOps::QCHG,
                    MmsValue::BitString {
                        padding: 3,
                        data: vec![0, 0],
                    },
                )),
            ],
        };
        assert_eq!(d.children_with_fc(FC::St).count(), 2);
        assert_eq!(d.children_with_fc(FC::Cf).count(), 1);
        assert_eq!(d.children_with_fc(FC::Mx).count(), 0);
    }

    // store and snapshot

    /// `store` is the inverse of `snapshot`: a stored value reads back
    /// unchanged, and may be overwritten repeatedly.
    #[test]
    fn store_then_snapshot_round_trips() {
        let attr = da(
            "mag",
            FC::Mx,
            DataAttributeType::Float32,
            TrgOps::DCHG,
            MmsValue::Float32(0.0),
        );
        assert_eq!(attr.snapshot(), MmsValue::Float32(0.0));

        attr.store(MmsValue::Float32(1.5));
        assert_eq!(attr.snapshot(), MmsValue::Float32(1.5));

        // The later write wins; nothing accumulates and no old value is kept.
        attr.store(MmsValue::Float32(-2.25));
        assert_eq!(attr.snapshot(), MmsValue::Float32(-2.25));
    }

    /// `store` writes through the same `RwLock` the service layer holds.
    ///
    /// The server's read path does not re-navigate the tree; it holds the
    /// `Arc<RwLock<MmsValue>>` of the data attribute, cloned when the MMS view
    /// was built. If `store` wrote to a different lock, a client would forever
    /// read the snapshot taken at build time, and live data would silently
    /// become a dead value. This test pins the sharing.
    #[test]
    fn store_is_visible_through_a_cloned_value_handle() {
        let attr = da(
            "stVal",
            FC::St,
            DataAttributeType::Boolean,
            TrgOps::DCHG,
            MmsValue::Boolean(false),
        );
        // Stand in for the service layer: clone the value handle at build time
        // and keep it.
        let handle = Arc::clone(&attr.value);

        attr.store(MmsValue::Boolean(true));

        assert_eq!(
            *rwlock_read(&handle),
            MmsValue::Boolean(true),
            "store must write through the same RwLock, or the handle the service layer holds reads a dead value"
        );
    }

    /// Navigating the tree to a data attribute and storing there, then reading
    /// it back through the tree: how an embedded process image uses the model.
    #[test]
    fn store_through_model_navigation() {
        let model = build_simple_model();
        let da_ref = match model
            .ld_by_inst("WD1")
            .expect("LD WD1")
            .ln_by_name("GGIO1")
            .expect("LN GGIO1")
            .do_by_name("Ind1")
            .expect("DO Ind1")
            .child_by_name("stVal")
            .expect("DA stVal")
        {
            DoChild::Da(da) => da,
            DoChild::SubDo(_) => panic!("stVal must be a data attribute, not a sub-object"),
        };

        assert_eq!(da_ref.snapshot(), MmsValue::Boolean(false));
        da_ref.store(MmsValue::Boolean(true));
        assert_eq!(da_ref.snapshot(), MmsValue::Boolean(true));
    }

    // Snapshot assembly for a constructed data attribute

    /// The snapshot of a constructed attribute must be assembled from its
    /// children into a structure whose element order matches `children`, rather
    /// than returning the placeholder value the node itself holds.
    ///
    /// This is what keeps the type declared by `GetVariableAccessAttributes`
    /// consistent with the value a Read returns. The declaration walks
    /// `children`, so a value that did not would produce the wire
    /// inconsistency of declaring `mag{f}` and returning an empty structure,
    /// which client tools that build a view from the declaration do not expect.
    #[test]
    fn constructed_snapshot_composes_children() {
        let mag = DataAttribute::constructed(
            "mag",
            FC::Mx,
            vec![da(
                "f",
                FC::Mx,
                DataAttributeType::Float32,
                TrgOps::NONE,
                MmsValue::Float32(1.5),
            )],
        );
        assert_eq!(
            mag.snapshot(),
            MmsValue::Structure(vec![MmsValue::Float32(1.5)])
        );
    }

    /// A nested constructed attribute, two levels deep, is assembled
    /// recursively as well.
    #[test]
    fn constructed_snapshot_recurses_nested_levels() {
        let inner = DataAttribute::constructed(
            "mag",
            FC::Mx,
            vec![da(
                "f",
                FC::Mx,
                DataAttributeType::Float32,
                TrgOps::NONE,
                MmsValue::Float32(2.25),
            )],
        );
        let outer = DataAttribute::constructed("phsA", FC::Mx, vec![inner]);
        assert_eq!(
            outer.snapshot(),
            MmsValue::Structure(vec![MmsValue::Structure(vec![MmsValue::Float32(2.25)])])
        );
    }

    /// A live update to a leaf sub-attribute must reach the snapshot of the
    /// constructed attribute above it.
    #[test]
    fn constructed_snapshot_sees_live_leaf_updates() {
        let mag = DataAttribute::constructed(
            "mag",
            FC::Mx,
            vec![da(
                "f",
                FC::Mx,
                DataAttributeType::Float32,
                TrgOps::NONE,
                MmsValue::Float32(0.0),
            )],
        );
        // Stand in for firmware: navigate to the leaf, clone the value handle,
        // and have the measurement loop write through it.
        let leaf_handle = Arc::clone(&mag.children[0].value);
        *rwlock_write(&leaf_handle) = MmsValue::Float32(42.0);

        assert_eq!(
            mag.snapshot(),
            MmsValue::Structure(vec![MmsValue::Float32(42.0)])
        );
    }
}
