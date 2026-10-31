//! Data set: the list of members a report or log control block observes.
//!
//! A member is a functional-constrained data attribute (FCDA) or functional-
//! constrained data (FCD), IEC 61850-7-2 §13.2.2.3. Its value lives in the
//! basic-type attributes at or beneath the node it names, the leaves of the
//! member. Each leaf holds an `Arc<RwLock<MmsValue>>` shared with the model's
//! `DataAttribute::value`, so a member always sees the live values. The value
//! of an FCDA naming a basic-type attribute is that attribute's value; the
//! value of an FCD, or of an FCDA naming a constructed attribute, is the MMS
//! structure GetVariableAccessAttributes describes for its name: one member
//! per attribute or sub-object the node holds under the functional constraint,
//! in model order, down to the leaves.
//!
//! A member is the unit of a report, a log entry and a GetDataSetValues
//! result. A change of any leaf triggers its member, which a report then
//! carries whole (IEC 61850-7-2 §17.2.3.2.3), and segmentation never splits
//! one. Reports and log entries carry the values of the model: read handlers
//! decide only the reads of a client, where a handler refusing any part of a
//! member fails that member.
//!
//! Nothing caches resolved value references: a data set is normally well under
//! a hundred members, so it is walked at encode time. Report snapshots are
//! owned values, `Vec<Option<MmsValue>>`, not borrows into the model.
//!
//! A `DataAttributeRef` is the string `"<domain>/<LN>$<FC>$<DO>[$...]"`, the
//! same wire path `iec61850-model::ObjectRef` produces. The reference of a
//! leaf is the key of the reporting engine's inverted index; the reference of
//! a member is what a report, a log entry and GetDataSetDirectory carry.

use iec61850_model::{IedModel, LogicalDevice, MmsValue, FC};
use std::sync::{Arc, RwLock};

use super::dynamic_ops::DatasetError;
use crate::service::read::Node;

// ─────────────────────────────────────────────────────────────────────────────
// DataAttributeRef
// ─────────────────────────────────────────────────────────────────────────────

/// Wire-level reference to an IEC 61850 data object or data attribute.
///
/// The form is `"<IED><LD>/<LN>$<FC>$<DO>[$<SDO>...][$<DA>[$<SDA>...]]"`, for
/// example `"IED1LD0/GGIO1$ST$Ind1$stVal"` or `"IED1LD0/GGIO1$ST$Ind1"`.
pub type DataAttributeRef = String;

// ─────────────────────────────────────────────────────────────────────────────
// DatasetLeaf
// ─────────────────────────────────────────────────────────────────────────────

/// One basic-type attribute at or beneath a data set member.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DatasetLeaf {
    /// Wire-level reference of the attribute, the key an update of it is
    /// looked up by.
    pub attr_ref: DataAttributeRef,
    /// Value lock shared with the model's `DataAttribute::value`.
    pub value: Arc<RwLock<MmsValue>>,
}

impl DatasetLeaf {
    /// Creates a leaf from a reference and a shared value lock.
    pub fn new(attr_ref: impl Into<DataAttributeRef>, value: Arc<RwLock<MmsValue>>) -> Self {
        Self {
            attr_ref: attr_ref.into(),
            value,
        }
    }
}

/// The node a member names: a leaf, or a structure of nodes in member order.
#[derive(Debug, Clone)]
enum MemberNode {
    Leaf(DatasetLeaf),
    Structure(Vec<MemberNode>),
}

impl MemberNode {
    fn read_value(&self) -> Option<MmsValue> {
        match self {
            MemberNode::Leaf(leaf) => leaf.value.read().ok().map(|g| g.clone()),
            MemberNode::Structure(children) => children
                .iter()
                .map(MemberNode::read_value)
                .collect::<Option<Vec<_>>>()
                .map(MmsValue::Structure),
        }
    }

    fn collect_leaves<'a>(&'a self, out: &mut Vec<&'a DatasetLeaf>) {
        match self {
            MemberNode::Leaf(leaf) => out.push(leaf),
            MemberNode::Structure(children) => {
                for child in children {
                    child.collect_leaves(out);
                }
            }
        }
    }

    /// Replaces, within `value`, the part the leaf `leaf_ref` occupies.
    /// Returns whether the leaf is beneath this node and `value` has its shape
    /// along the way.
    fn replace_leaf(&self, value: &mut MmsValue, leaf_ref: &str, new_value: &MmsValue) -> bool {
        match self {
            MemberNode::Leaf(leaf) => {
                if leaf.attr_ref == leaf_ref {
                    *value = new_value.clone();
                    true
                } else {
                    false
                }
            }
            MemberNode::Structure(children) => {
                let MmsValue::Structure(members) = value else {
                    return false;
                };
                children
                    .iter()
                    .zip(members.iter_mut())
                    .any(|(child, member)| child.replace_leaf(member, leaf_ref, new_value))
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DatasetEntry
// ─────────────────────────────────────────────────────────────────────────────

/// One member of a data set: an FCDA or an FCD.
///
/// A member naming a basic-type attribute has a single leaf and its value is
/// that leaf's value. A member naming a data object, a sub-data-object or a
/// constructed attribute holds every leaf beneath it and its value is the MMS
/// structure of the node under its functional constraint. Either way a member
/// is reported, logged and read as one unit.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DatasetEntry {
    /// Wire-level reference of the member, emitted for the DATA_REFERENCE
    /// optional field of a report, in log entries and in GetDataSetDirectory.
    pub attr_ref: DataAttributeRef,
    node: MemberNode,
}

impl DatasetEntry {
    /// Largest number of leaves one member may hold; a member naming a larger
    /// node is refused by [`DatasetEntry::from_model`].
    pub const MAX_LEAVES: usize = 1024;

    /// Creates a member naming one basic-type attribute, from its reference and
    /// its shared value lock.
    pub fn new(attr_ref: impl Into<DataAttributeRef>, value: Arc<RwLock<MmsValue>>) -> Self {
        let attr_ref = attr_ref.into();
        Self {
            node: MemberNode::Leaf(DatasetLeaf::new(attr_ref.clone(), value)),
            attr_ref,
        }
    }

    /// Resolves the member `<LN>$<FC>$<DO>[$<SDO>...][$<DA>[$<SDA>...]]` of
    /// `domain` against `model`.
    ///
    /// The path crosses any depth of sub-data-objects; a data attribute
    /// matches by name and functional constraint, a sub-attribute by name. The
    /// path may stop on a data object or sub-data-object that holds an
    /// attribute of the functional constraint (an FCD), or on a data attribute
    /// or sub-attribute of any type (an FCDA). The member shares the value
    /// locks of the model's attributes.
    ///
    /// # Errors
    ///
    /// - [`DatasetError::MemberInvalidPath`] when the path has fewer than three
    ///   segments, an empty segment or an unknown functional constraint, or
    ///   names an array of data objects or a node holding one.
    /// - [`DatasetError::MemberNotFound`] when a node on the path is not in the
    ///   model, or the data object holds no attribute of the functional
    ///   constraint.
    /// - [`DatasetError::TooLarge`] when the node holds more than
    ///   [`DatasetEntry::MAX_LEAVES`] leaves.
    pub fn from_model(model: &IedModel, domain: &str, path: &str) -> Result<Self, DatasetError> {
        let reference = format!("{domain}/{path}");
        let invalid = || DatasetError::MemberInvalidPath {
            path: reference.clone(),
        };
        let not_found = || DatasetError::MemberNotFound {
            path: reference.clone(),
        };
        let parts: Vec<&str> = path.split('$').collect();
        if parts.len() < 3 || parts.iter().any(|p| p.is_empty()) {
            return Err(invalid());
        }
        let fc = FC::parse(parts[1]).map_err(|_| invalid())?;
        let ln = model
            .ld_by_domain(domain)
            .and_then(|ld| ld.ln_by_name(parts[0]))
            .ok_or_else(not_found)?;
        let mut node = Node::Object(ln.do_by_name(parts[2]).ok_or_else(not_found)?);
        if is_array(node) {
            return Err(invalid());
        }
        for seg in &parts[3..] {
            node = node.child(fc, seg).ok_or_else(not_found)?;
            if is_array(node) {
                return Err(invalid());
            }
        }
        if let Node::Object(obj) = node {
            if !crate::service::read::object_has_fc(obj, fc) {
                return Err(not_found());
            }
        }
        let mut leaves = 0usize;
        let node = build_node(node, fc, &reference, &mut leaves).ok_or_else(|| {
            if leaves > Self::MAX_LEAVES {
                DatasetError::TooLarge {
                    path: reference.clone(),
                }
            } else {
                invalid()
            }
        })?;
        Ok(Self {
            attr_ref: reference,
            node,
        })
    }

    /// Resolves a member of a data set the model declares, such as one an SCL
    /// file configures, against `model`; `owner` is the logical device that
    /// holds the data set.
    ///
    /// The member lies in the logical device `entry.ld_inst`, an instance name
    /// or a domain name, or in `owner` when `ld_inst` is empty, and names
    /// `<ln_name>$<fc>$<do_path...>[$<component>]`, the component split at
    /// its dots, resolved as [`DatasetEntry::from_model`] resolves a path: an
    /// entry without a data attribute is an FCD, one with a data attribute an
    /// FCDA.
    ///
    /// # Errors
    ///
    /// The errors of [`DatasetEntry::from_model`];
    /// [`DatasetError::MemberNotFound`] when `ld_inst` names no logical device
    /// of the model, and [`DatasetError::MemberInvalidPath`] when the entry
    /// carries an array index.
    pub fn from_data_set_entry(
        model: &IedModel,
        owner: &LogicalDevice,
        entry: &iec61850_model::DataSetEntry,
    ) -> Result<Self, DatasetError> {
        let ld = if entry.ld_inst.is_empty() {
            Some(owner)
        } else {
            model
                .ld_by_inst(&entry.ld_inst)
                .or_else(|| model.ld_by_domain(&entry.ld_inst))
        };
        let Some(ld) = ld else {
            return Err(DatasetError::MemberNotFound {
                path: entry.to_string(),
            });
        };
        if entry.array_index.is_some() {
            return Err(DatasetError::MemberInvalidPath {
                path: entry.to_string(),
            });
        }
        let mut path = format!("{}${}", entry.ln_name, entry.fc.as_str());
        let component = entry.component.iter().flat_map(|c| c.split('.'));
        for seg in entry.do_path.iter().map(String::as_str).chain(component) {
            path.push('$');
            path.push_str(seg);
        }
        Self::from_model(model, &ld.domain_name(&model.ied_name), &path)
    }

    /// Returns whether the member names a single basic-type attribute.
    pub fn is_leaf(&self) -> bool {
        matches!(self.node, MemberNode::Leaf(_))
    }

    /// Returns the leaves of the member in member order: the attribute itself
    /// for a basic-type FCDA, every basic-type attribute beneath the node
    /// otherwise.
    pub fn leaves(&self) -> Vec<&DatasetLeaf> {
        let mut out = Vec::new();
        self.node.collect_leaves(&mut out);
        out
    }

    /// Returns the number of leaves of the member.
    pub fn leaf_count(&self) -> usize {
        fn count(node: &MemberNode) -> usize {
            match node {
                MemberNode::Leaf(_) => 1,
                MemberNode::Structure(children) => children.iter().map(count).sum(),
            }
        }
        count(&self.node)
    }

    /// Returns the current value of the member: the leaf value, or the
    /// structure assembled from the leaves. `None` when a value lock is
    /// poisoned. Each lock is released immediately after its clone, so the
    /// structure is not atomic across leaves unless the caller excludes
    /// concurrent writers.
    pub fn read_value(&self) -> Option<MmsValue> {
        self.node.read_value()
    }

    /// Returns whether the leaf `leaf_ref` is the member or lies beneath it.
    pub fn covers(&self, leaf_ref: &str) -> bool {
        match &self.node {
            MemberNode::Leaf(leaf) => leaf.attr_ref == leaf_ref,
            MemberNode::Structure(_) => {
                leaf_ref
                    .strip_prefix(self.attr_ref.as_str())
                    .is_some_and(|rest| rest.starts_with('$'))
                    && self.leaves().iter().any(|l| l.attr_ref == leaf_ref)
            }
        }
    }

    /// Returns the value of the member with the part the leaf `leaf_ref`
    /// occupies replaced by `new_value`.
    ///
    /// `held` is the member value to start from; `None` starts from the
    /// current value. Returns `held` unchanged when the leaf is not part of
    /// the member, and `None` when no value is held and a value lock is
    /// poisoned.
    pub(crate) fn value_with(
        &self,
        held: Option<MmsValue>,
        leaf_ref: &str,
        new_value: &MmsValue,
    ) -> Option<MmsValue> {
        if let MemberNode::Leaf(leaf) = &self.node {
            return if leaf.attr_ref == leaf_ref {
                Some(new_value.clone())
            } else {
                held
            };
        }
        let mut value = match held {
            Some(v) => v,
            None => self.read_value()?,
        };
        self.node.replace_leaf(&mut value, leaf_ref, new_value);
        Some(value)
    }

    /// Returns the value of the member with the leaf whose value lock is
    /// `cell` replaced by `new_value`, starting from `held` as
    /// [`DatasetEntry::value_with`] does. `None` also when the leaf is not
    /// part of the member.
    #[cfg(feature = "full-server")]
    pub(crate) fn value_with_cell(
        &self,
        held: Option<MmsValue>,
        cell: &Arc<RwLock<MmsValue>>,
        new_value: &MmsValue,
    ) -> Option<(DataAttributeRef, MmsValue)> {
        let leaves = self.leaves();
        let leaf = leaves.iter().find(|l| Arc::ptr_eq(&l.value, cell))?;
        let leaf_ref = leaf.attr_ref.clone();
        let value = self.value_with(held, &leaf_ref, new_value)?;
        Some((leaf_ref, value))
    }
}

/// Reports whether `node` is an array of data objects, which a data set
/// member does not reach.
fn is_array(node: Node<'_>) -> bool {
    matches!(node, Node::Object(obj) if obj.array_count.is_some())
}

/// Builds the member node for `node` under `fc`, counting its leaves into
/// `leaves`. `None` when the node holds more than `DatasetEntry::MAX_LEAVES`
/// leaves, an array of data objects, or no leaf at all.
fn build_node(node: Node<'_>, fc: FC, reference: &str, leaves: &mut usize) -> Option<MemberNode> {
    if is_array(node) {
        return None;
    }
    if node.is_leaf() {
        let Node::Attribute(da) = node else {
            return None;
        };
        *leaves += 1;
        if *leaves > DatasetEntry::MAX_LEAVES {
            return None;
        }
        return Some(MemberNode::Leaf(DatasetLeaf::new(
            reference,
            Arc::clone(&da.value),
        )));
    }
    let children = node
        .children(fc)
        .map(|child| build_node(child, fc, &format!("{reference}${}", child.name()), leaves))
        .collect::<Option<Vec<_>>>()?;
    if children.is_empty() {
        return None;
    }
    Some(MemberNode::Structure(children))
}

// ─────────────────────────────────────────────────────────────────────────────
// Dataset
// ─────────────────────────────────────────────────────────────────────────────

/// The list of members a report or log control block observes.
///
/// Entries are held in a `Vec`, which is append-only while the model is being
/// built and treated as immutable once a control block is enabled.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Dataset {
    /// Data set reference name in the MMS namespace, for example `GGIO1$ds1`.
    pub name: String,
    /// Entries, in declaration order.
    pub entries: Vec<DatasetEntry>,
}

impl Dataset {
    /// Creates an empty data set.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            entries: Vec::new(),
        }
    }

    /// Appends an entry. Only called while the model is being built.
    pub fn push(&mut self, entry: DatasetEntry) {
        self.entries.push(entry);
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the data set has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the entry at `idx`, or `None` when the index is out of range.
    pub fn entry(&self, idx: usize) -> Option<&DatasetEntry> {
        self.entries.get(idx)
    }

    /// Returns the positions of the members the attribute `leaf_ref` belongs
    /// to, in order: a member naming it, and a member whose node holds it.
    pub fn members_of(&self, leaf_ref: &str) -> Vec<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.covers(leaf_ref))
            .map(|(i, _)| i)
            .collect()
    }

    /// Snapshots the current value of every entry, for report encoding.
    ///
    /// The result is as long as `entries`; a position is `None` when a value
    /// lock of that entry is poisoned.
    pub fn snapshot_values(&self) -> Vec<Option<MmsValue>> {
        self.entries.iter().map(|e| e.read_value()).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use iec61850_model::{
        DataAttribute, DataAttributeType, DataObject, DoChild, IedModelBuilder,
        LogicalDeviceBuilder, LogicalNodeBuilder, TrgOps,
    };

    fn make_bool_entry(attr_ref: &str, val: bool) -> DatasetEntry {
        let value = Arc::new(RwLock::new(MmsValue::Boolean(val)));
        DatasetEntry::new(attr_ref, value)
    }

    fn leaf(name: &str, fc: FC, ty: DataAttributeType, v: MmsValue) -> DataAttribute {
        DataAttribute::new(name, fc, ty, TrgOps::default(), v)
    }

    /// GGIO1.Ind1 with ST stVal, q, t and a CF attribute; MMXU1.TotW with a
    /// constructed MX `mag` holding `f`; MMXU1.PhV with a sub-object `phsA`
    /// holding a constructed `cVal`.
    fn build_model() -> IedModel {
        let ind1 = DataObject::new(
            "Ind1",
            vec![
                DoChild::Da(leaf(
                    "stVal",
                    FC::St,
                    DataAttributeType::Boolean,
                    MmsValue::Boolean(true),
                )),
                DoChild::Da(leaf(
                    "q",
                    FC::St,
                    DataAttributeType::Quality,
                    MmsValue::BitString {
                        padding: 3,
                        data: vec![0, 0],
                    },
                )),
                DoChild::Da(leaf(
                    "ctlModel",
                    FC::Cf,
                    DataAttributeType::Enumerated,
                    MmsValue::Integer(1),
                )),
                DoChild::Da(leaf(
                    "t",
                    FC::St,
                    DataAttributeType::Timestamp,
                    MmsValue::UtcTime([0; 8]),
                )),
            ],
        );
        let analogue = |name: &str| {
            let mut da = leaf(
                name,
                FC::Mx,
                DataAttributeType::Constructed,
                MmsValue::Structure(vec![]),
            );
            da.children = vec![leaf(
                "f",
                FC::Mx,
                DataAttributeType::Float32,
                MmsValue::Float32(2.5),
            )];
            da
        };
        let totw = DataObject::new("TotW", vec![DoChild::Da(analogue("mag"))]);
        let phs_a = DataObject::new("phsA", vec![DoChild::Da(analogue("cVal"))]);
        let phv = DataObject::new("PhV", vec![DoChild::SubDo(phs_a)]);
        let ggio1 = iec61850_model::LogicalNode::new(String::new(), "GGIO", "1", vec![ind1]);
        let mmxu1 = iec61850_model::LogicalNode::new(String::new(), "MMXU", "1", vec![totw, phv]);
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(LogicalNodeBuilder::lln0().build().unwrap())
            .add_ln(ggio1)
            .add_ln(mmxu1)
            .build()
            .unwrap();
        IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap()
    }

    #[test]
    fn dataset_new_is_empty() {
        let ds = Dataset::new("GGIO1$ds1");
        assert!(ds.is_empty());
        assert_eq!(ds.len(), 0);
        assert_eq!(ds.name, "GGIO1$ds1");
    }

    #[test]
    fn dataset_push_and_read() {
        let mut ds = Dataset::new("ds1");
        ds.push(make_bool_entry("IED1LD0/GGIO1$ST$Ind1$stVal", true));
        ds.push(make_bool_entry("IED1LD0/GGIO1$ST$Ind2$stVal", false));
        assert_eq!(ds.len(), 2);

        let v0 = ds.entry(0).unwrap().read_value().unwrap();
        assert_eq!(v0, MmsValue::Boolean(true));

        let v1 = ds.entry(1).unwrap().read_value().unwrap();
        assert_eq!(v1, MmsValue::Boolean(false));
    }

    #[test]
    fn dataset_snapshot_values() {
        let mut ds = Dataset::new("ds1");
        ds.push(make_bool_entry("A", true));
        ds.push(make_bool_entry("B", false));
        let snap = ds.snapshot_values();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0], Some(MmsValue::Boolean(true)));
        assert_eq!(snap[1], Some(MmsValue::Boolean(false)));
    }

    #[test]
    fn dataset_entry_out_of_bounds_is_none() {
        let ds = Dataset::new("ds1");
        assert!(ds.entry(0).is_none());
    }

    #[test]
    fn shared_value_update_visible_through_entry() {
        let shared = Arc::new(RwLock::new(MmsValue::Integer(0)));
        let entry = DatasetEntry::new("test", Arc::clone(&shared));

        // Update through the shared handle.
        *shared.write().unwrap() = MmsValue::Integer(42);
        let v = entry.read_value().unwrap();
        assert_eq!(v, MmsValue::Integer(42));
    }

    /// An FCD holds the attributes of its functional constraint in model
    /// order and reads as their structure; the CF attribute between them is
    /// not part of it.
    #[test]
    fn data_object_member_reads_as_the_structure_of_its_constraint() {
        let model = build_model();
        let e = DatasetEntry::from_model(&model, "IED1LD0", "GGIO1$ST$Ind1").unwrap();
        assert!(!e.is_leaf());
        assert_eq!(e.attr_ref, "IED1LD0/GGIO1$ST$Ind1");
        let refs: Vec<&str> = e.leaves().iter().map(|l| l.attr_ref.as_str()).collect();
        assert_eq!(
            refs,
            [
                "IED1LD0/GGIO1$ST$Ind1$stVal",
                "IED1LD0/GGIO1$ST$Ind1$q",
                "IED1LD0/GGIO1$ST$Ind1$t"
            ]
        );
        assert_eq!(
            e.read_value().unwrap(),
            MmsValue::Structure(vec![
                MmsValue::Boolean(true),
                MmsValue::BitString {
                    padding: 3,
                    data: vec![0, 0]
                },
                MmsValue::UtcTime([0; 8]),
            ])
        );
    }

    /// A constructed attribute and a sub-data-object read as structures of
    /// their own leaves; a basic attribute stays a single leaf.
    #[test]
    fn constructed_and_sub_object_members_hold_their_leaves() {
        let model = build_model();
        let mag = DatasetEntry::from_model(&model, "IED1LD0", "MMXU1$MX$TotW$mag").unwrap();
        assert_eq!(
            mag.read_value().unwrap(),
            MmsValue::Structure(vec![MmsValue::Float32(2.5)])
        );
        let phs_a = DatasetEntry::from_model(&model, "IED1LD0", "MMXU1$MX$PhV$phsA").unwrap();
        assert_eq!(
            phs_a.read_value().unwrap(),
            MmsValue::Structure(vec![MmsValue::Structure(vec![MmsValue::Float32(2.5)])])
        );
        assert_eq!(
            phs_a.leaves()[0].attr_ref,
            "IED1LD0/MMXU1$MX$PhV$phsA$cVal$f"
        );
        let f = DatasetEntry::from_model(&model, "IED1LD0", "MMXU1$MX$TotW$mag$f").unwrap();
        assert!(f.is_leaf());
        assert_eq!(f.read_value().unwrap(), MmsValue::Float32(2.5));
    }

    #[test]
    fn member_paths_that_do_not_resolve_are_refused() {
        let model = build_model();
        for (path, not_found) in [
            ("GGIO1$ST", false),
            ("GGIO1$ZZ$Ind1", false),
            ("GGIO1$$Ind1", false),
            ("GGIO1$MX$Ind1", true),
            ("GGIO1$ST$Ind9", true),
            ("GGIO9$ST$Ind1", true),
            ("GGIO1$CF$Ind1$stVal", true),
        ] {
            let err = DatasetEntry::from_model(&model, "IED1LD0", path).unwrap_err();
            assert_eq!(
                matches!(err, DatasetError::MemberNotFound { .. }),
                not_found,
                "{path}: {err:?}"
            );
        }
    }

    #[test]
    fn leaf_membership_and_replacement_follow_the_member_node() {
        let model = build_model();
        let e = DatasetEntry::from_model(&model, "IED1LD0", "GGIO1$ST$Ind1").unwrap();
        assert!(e.covers("IED1LD0/GGIO1$ST$Ind1$q"));
        assert!(!e.covers("IED1LD0/GGIO1$CF$Ind1$ctlModel"));
        assert!(!e.covers("IED1LD0/GGIO1$ST$Ind10$q"));
        let q = MmsValue::BitString {
            padding: 3,
            data: vec![0x40, 0],
        };
        let v = e.value_with(None, "IED1LD0/GGIO1$ST$Ind1$q", &q).unwrap();
        let MmsValue::Structure(members) = v else {
            panic!("an FCD reads as a structure");
        };
        assert_eq!(members[0], MmsValue::Boolean(true));
        assert_eq!(members[1], q);
        let mut ds = Dataset::new("GGIO1$ds");
        ds.push(make_bool_entry("IED1LD0/GGIO1$ST$Ind2$stVal", false));
        ds.push(e);
        ds.push(make_bool_entry("IED1LD0/GGIO1$ST$Ind1$t", false));
        assert_eq!(ds.members_of("IED1LD0/GGIO1$ST$Ind1$t"), [1, 2]);
        assert_eq!(ds.members_of("IED1LD0/GGIO1$ST$Ind1$q"), [1]);
        assert_eq!(ds.members_of("IED1LD0/GGIO1$ST$Ind2$stVal"), [0]);
        assert!(ds.members_of("IED1LD0/GGIO1$ST$Ind2$q").is_empty());
    }

    #[test]
    fn member_larger_than_the_leaf_limit_is_refused() {
        let attrs: Vec<DoChild> = (0..=DatasetEntry::MAX_LEAVES)
            .map(|i| {
                DoChild::Da(leaf(
                    &format!("a{i}"),
                    FC::Sp,
                    DataAttributeType::Int32,
                    MmsValue::Integer(0),
                ))
            })
            .collect();
        let big = DataObject::new("Big", attrs);
        let ggio1 = iec61850_model::LogicalNode::new(String::new(), "GGIO", "1", vec![big]);
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(LogicalNodeBuilder::lln0().build().unwrap())
            .add_ln(ggio1)
            .build()
            .unwrap();
        let model = IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap();
        assert!(matches!(
            DatasetEntry::from_model(&model, "IED1LD0", "GGIO1$SP$Big"),
            Err(DatasetError::TooLarge { .. })
        ));
        assert!(DatasetEntry::from_model(&model, "IED1LD0", "GGIO1$SP$Big$a3").is_ok());
    }

    /// A member the model declares resolves as an FCD without a data
    /// attribute and as an FCDA with one, a component descending further; an
    /// empty logical device instance is the owner's, and an array index is
    /// refused.
    #[test]
    fn a_declared_member_resolves_as_fcd_or_fcda() {
        let model = build_model();
        let owner = model.ld_by_inst("LD0").unwrap();
        let mut fcd = iec61850_model::DataSetEntry::new("GGIO1", FC::St, vec!["Ind1".into()]);
        let e = DatasetEntry::from_data_set_entry(&model, owner, &fcd).unwrap();
        assert_eq!(e.attr_ref, "IED1LD0/GGIO1$ST$Ind1");
        assert_eq!(e.leaf_count(), 3);
        fcd.ld_inst = "LD0".into();
        let e = DatasetEntry::from_data_set_entry(&model, owner, &fcd).unwrap();
        assert_eq!(e.attr_ref, "IED1LD0/GGIO1$ST$Ind1");

        let mut fcda =
            iec61850_model::DataSetEntry::new("MMXU1", FC::Mx, vec!["TotW".into(), "mag".into()]);
        let e = DatasetEntry::from_data_set_entry(&model, owner, &fcda).unwrap();
        assert_eq!(e.attr_ref, "IED1LD0/MMXU1$MX$TotW$mag");
        assert!(!e.is_leaf());
        fcda.component = Some("f".into());
        let e = DatasetEntry::from_data_set_entry(&model, owner, &fcda).unwrap();
        assert_eq!(e.attr_ref, "IED1LD0/MMXU1$MX$TotW$mag$f");
        assert!(e.is_leaf());

        fcd.array_index = Some(0);
        assert!(matches!(
            DatasetEntry::from_data_set_entry(&model, owner, &fcd),
            Err(DatasetError::MemberInvalidPath { .. })
        ));
        fcd.array_index = None;
        fcd.ld_inst = "LD9".into();
        assert!(matches!(
            DatasetEntry::from_data_set_entry(&model, owner, &fcd),
            Err(DatasetError::MemberNotFound { .. })
        ));
    }
}
