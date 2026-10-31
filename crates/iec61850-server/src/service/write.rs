//! Server handler for the Write service of IEC 61850-7-2.
//!
//! The functional constraint of the target decides the outcome, in this order:
//!
//! 1. ST, MX, EX, SG: always refused with `ObjectAccessDenied`; these are
//!    read-only views of state, measurement, or the active setting group.
//! 2. CO, GO, BR, RP, LG, MS, US, SR, OR: routed to their own services, not
//!    written here, and refused with `ObjectAccessUnsupported` if they reach
//!    this handler.
//! 3. CF, DC, SP, SV, BL: subject to the `WriteAccessPolicies` bitmask; a
//!    refusal is `ObjectAccessDenied`, otherwise the value is checked and
//!    written.
//! 4. SE: the same bitmask, plus the setting-group edit session gate: while
//!    the caller does not hold the edit session, whether because no setting
//!    group is being edited or another association edits one, the write
//!    answers `TemporarilyUnavailable`, as IEC 61850-8-1 §8.1.3.4.4.2 answers a
//!    write whose writability depends on another object or on a reservation
//!    by another client.
//!
//! A path names functional-constrained data (FCD), `LN$FC$DO[$SDO...]`, or a
//! functional-constrained data attribute (FCDA),
//! `LN$FC$DO[$SDO...]$DA[$SDA...]`, crossing any depth of sub-data-objects, as
//! IEC 61850-7-2 §11.4.3.2.1 allows SetDataValues to reference either. A path
//! naming only a logical node or a functional-constraint group answers
//! `ObjectAccessUnsupported`.
//!
//! The value of a data object or a constructed attribute lives in its leaves.
//! Writing an FCD takes a structure with one member per attribute or
//! sub-object the data object holds under the constraint, and writing a
//! constructed attribute one member per sub-attribute, both in model order, as
//! GetVariableAccessAttributes describes them; another member count answers
//! `TypeInconsistent`. Every leaf beneath the target is written: all leaves are
//! checked, and every handler on the way has its say, before any cached value
//! changes, so a refused write leaves every leaf as it was (§11.4.3.4). A
//! concurrent read may still observe some leaves written and others not.
//!
//! Each leaf takes a value of the variant currently held in the model, else
//! `ObjectValueInvalid`. The value must then lie within the type the attribute
//! declares in GetVariableAccessAttributes (IEC 61850-8-1 §8.1.1, table 15): an
//! integer outside the range of its width, and a visible, Unicode or octet
//! string longer than its maximum length, or of another length than a fixed
//! one, answer `ObjectValueInvalid` (§8.1.2.1). A bit string that does not fit
//! the declared size answers `TypeInconsistent`; one shorter than a `Max(n)`
//! size is padded with zero bits to n bits before it is stored.
//!
//! A write of a node is also a write of each node above it, up to the data
//! object: sub-data-objects, the data attribute and constructed
//! sub-attributes. The handler of every such ancestor, outermost first,
//! decides the write with the ancestor's current value under the functional
//! constraint in which the target is replaced by the written value: a refusal
//! refuses the write, and taking the value over leaves the cache alone,
//! exactly as for a write of the ancestor itself.

#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use crate::compat::Arc;
use crate::handler::{
    AttributeAccessHandler, HandlerRegistry, WriteContext, WriteOutcome as HandlerWriteOutcome,
};
use crate::mapping::{bit_string_fits, MmsDeviceModel, MmsLeafType, MmsTypeSpec, StringSize};
use crate::policy::WriteAccessPolicies;
use crate::service::convert::{bit_string_bytes, mms_data_to_mms_value, same_data_variant};
// Writing under FC SE belongs to the setting-group subsystem.
#[cfg(feature = "setting-groups")]
use crate::setting_groups::SettingGroupRegistry;
use iec61850_mms::mms::pdu::common::{DataAccessError, MmsData, ObjectName, WriteOutcome};
use iec61850_model::{DataAttribute, DataAttributeType, DataObject, DoChild, IedModel, FC};

// ─────────────────────────────────────────────────────────────────────────────
// Functional-constraint routing
// ─────────────────────────────────────────────────────────────────────────────

/// How a write is routed, based on the functional constraint of the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FcWriteRoute {
    /// Always refused. ST, MX, and EX are read-only, and SG is a read-only view
    /// of the values of the active setting group, which change only through
    /// SP or SE writes driven by the setting-group control block.
    AlwaysDenied,
    /// Belongs to a dedicated service (control, GOOSE, reporting, logging, ...)
    /// and is not written through this handler.
    Unsupported,
    /// Governed by the write access policy bitmask.
    PolicyControlled(FC),
    /// Governed by the policy bitmask and by the setting-group edit session:
    /// the writing association must own the session and the edit group must be
    /// non-zero (IEC 61850-7-2 §16.2.2.5), else temporarily-unavailable.
    #[cfg(feature = "setting-groups")]
    SettingEdit,
}

/// Classifies a functional-constraint name into a write route; an unparsable
/// name yields `None`.
fn classify_fc(fc_str: &str) -> Option<FcWriteRoute> {
    let fc = FC::parse(fc_str).ok()?;
    let route = match fc {
        FC::St | FC::Mx | FC::Ex => FcWriteRoute::AlwaysDenied,
        // SG is a read-only view of the active group; writes go through SP or SE.
        FC::Sg => FcWriteRoute::AlwaysDenied,
        FC::Co | FC::Go | FC::Br | FC::Rp | FC::Lg | FC::Ms | FC::Us | FC::Sr | FC::Or => {
            FcWriteRoute::Unsupported
        }
        FC::Cf | FC::Dc | FC::Sp | FC::Sv | FC::Bl => FcWriteRoute::PolicyControlled(fc),
        #[cfg(feature = "setting-groups")]
        FC::Se => FcWriteRoute::SettingEdit,
        // Without the setting-group runtime there is no edit session to gate on,
        // so SE cannot be honored.
        #[cfg(not(feature = "setting-groups"))]
        FC::Se => FcWriteRoute::AlwaysDenied,
        // Not real constraints; refusing them keeps a malformed path from
        // reaching the model.
        FC::All | FC::None => FcWriteRoute::AlwaysDenied,
    };
    Some(route)
}

// ─────────────────────────────────────────────────────────────────────────────
// Main handler
// ─────────────────────────────────────────────────────────────────────────────

/// Writes one value to one object name.
///
/// Only a domain-specific object name is served; anything else answers
/// `ObjectAccessUnsupported`.
///
/// When `handler_registry` is supplied and the path matches a registered
/// handler, the order is: classify the constraint, check the type, apply the
/// policy, call the handler, then update the cached value. See
/// [`AttributeAccessHandler`]. A `None` registry writes straight to the cache.
#[allow(clippy::too_many_arguments)]
pub fn handle_single_write(
    ied_model: &IedModel,
    mms_model: &MmsDeviceModel,
    policies: &WriteAccessPolicies,
    handler_registry: Option<&HandlerRegistry>,
    #[cfg(feature = "setting-groups")] setting_groups: Option<&SettingGroupRegistry>,
    conn_id: u64,
    name: &ObjectName,
    data: &MmsData,
) -> WriteOutcome {
    let (domain, item_id) = match name {
        ObjectName::DomainSpecific { domain_id, item_id } => (domain_id.as_str(), item_id.as_str()),
        ObjectName::VmdSpecific(n) => {
            tracing::warn!(name = n, "write: vmd-specific object names are not served");
            return WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported);
        }
        ObjectName::AaSpecific(n) => {
            tracing::warn!(name = n, "write: aa-specific object names are not served");
            return WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported);
        }
    };

    let parts: Vec<&str> = item_id.split('$').collect();

    // A write targets one data object or data attribute, so the path must
    // name at least a data object.
    if parts.len() < 3 {
        tracing::warn!(
            domain = domain,
            item_id = item_id,
            "write: item id names no data object, three segments are required"
        );
        return WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported);
    }

    let ln_name = parts[0];
    let fc_str = parts[1];
    // Everything from the data object down; how far it descends is a question
    // only the model can answer.
    let object_path = &parts[2..];

    let route = match classify_fc(fc_str) {
        Some(r) => r,
        None => {
            tracing::warn!(
                domain = domain,
                item_id = item_id,
                fc = fc_str,
                "write: not a functional-constraint name, refusing"
            );
            return WriteOutcome::Failure(DataAccessError::ObjectAccessDenied);
        }
    };

    match route {
        FcWriteRoute::AlwaysDenied => {
            tracing::warn!(
                domain = domain,
                item_id = item_id,
                fc = fc_str,
                "write: this functional constraint is read-only, answering object-access-denied"
            );
            WriteOutcome::Failure(DataAccessError::ObjectAccessDenied)
        }
        FcWriteRoute::Unsupported => {
            tracing::warn!(
                domain = domain,
                item_id = item_id,
                fc = fc_str,
                "write: this functional constraint belongs to a dedicated service, answering object-access-unsupported"
            );
            WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported)
        }
        FcWriteRoute::PolicyControlled(fc) => {
            if !policies.is_allowed(fc) {
                tracing::warn!(
                    domain = domain,
                    item_id = item_id,
                    ?fc,
                    "write: the write access policy refuses this functional constraint"
                );
                return WriteOutcome::Failure(DataAccessError::ObjectAccessDenied);
            }
            write_to_target(
                ied_model,
                mms_model,
                domain,
                ln_name,
                fc,
                object_path,
                data,
                handler_registry,
                conn_id,
                item_id,
            )
        }
        #[cfg(feature = "setting-groups")]
        FcWriteRoute::SettingEdit => {
            // The policy bitmask comes first, then the edit-session gate of
            // IEC 61850-7-2 §20.3.
            if !policies.is_allowed(FC::Se) {
                tracing::warn!(
                    domain = domain,
                    item_id = item_id,
                    "write: the write access policy refuses functional constraint SE"
                );
                return WriteOutcome::Failure(DataAccessError::ObjectAccessDenied);
            }
            // Whether SE is writable depends on the edit session, so a write
            // outside one is temporarily unavailable rather than denied.
            let registry = match setting_groups {
                Some(r) => r,
                None => {
                    tracing::warn!(
                        domain = domain,
                        item_id = item_id,
                        "write: no setting group registry is configured, answering temporarily-unavailable to an SE write"
                    );
                    return WriteOutcome::Failure(DataAccessError::TemporarilyUnavailable);
                }
            };
            let rt = match registry.lookup(domain) {
                Some(rt) => rt,
                None => {
                    tracing::warn!(
                        domain = domain,
                        item_id = item_id,
                        "write: the domain declares no setting group control block, answering temporarily-unavailable to an SE write"
                    );
                    return WriteOutcome::Failure(DataAccessError::TemporarilyUnavailable);
                }
            };
            if !rt.is_edit_session_owner(conn_id) {
                tracing::warn!(
                    domain = domain,
                    item_id = item_id,
                    conn_id,
                    "write: the caller does not hold the edit session, answering temporarily-unavailable to an SE write"
                );
                return WriteOutcome::Failure(DataAccessError::TemporarilyUnavailable);
            }
            write_to_target(
                ied_model,
                mms_model,
                domain,
                ln_name,
                FC::Se,
                object_path,
                data,
                handler_registry,
                conn_id,
                item_id,
            )
        }
    }
}

/// Resolves the target, checks the value, gives every handler concerned its
/// say, and updates the cached values.
#[allow(clippy::too_many_arguments)]
fn write_to_target(
    ied_model: &IedModel,
    mms_model: &MmsDeviceModel,
    domain: &str,
    ln_name: &str,
    fc: FC,
    object_path: &[&str],
    data: &MmsData,
    handler_registry: Option<&HandlerRegistry>,
    conn_id: u64,
    item_id: &str,
) -> WriteOutcome {
    // The caller guarantees a data object at least.
    let do_name = object_path[0];
    let ld = match ied_model.ld_by_domain(domain) {
        Some(ld) => ld,
        None => {
            tracing::warn!(domain = domain, "write: no such domain");
            return WriteOutcome::Failure(DataAccessError::ObjectNonExistent);
        }
    };

    let ln = match ld.ln_by_name(ln_name) {
        Some(ln) => ln,
        None => {
            tracing::warn!(domain = domain, ln = ln_name, "write: no such logical node");
            return WriteOutcome::Failure(DataAccessError::ObjectNonExistent);
        }
    };

    let do_node = match ln.do_by_name(do_name) {
        Some(d) => d,
        None => {
            tracing::warn!(
                domain = domain,
                ln = ln_name,
                do_name = do_name,
                "write: no such data object"
            );
            return WriteOutcome::Failure(DataAccessError::ObjectNonExistent);
        }
    };

    // A sub-data-object may nest to any depth before the path reaches a data
    // attribute, as WYE holds CMV in IEC 61850-7-3. The attribute must match
    // both by name and by functional constraint, so a name that matches an
    // attribute under a different constraint does not resolve; sub-attributes
    // carry the constraint of their attribute and descend by name alone. The
    // nodes passed on the way, the data object first, are the ancestors of the
    // target.
    let mut ancestors: Vec<Node<'_>> = Vec::with_capacity(object_path.len());
    let mut target = Node::Object(do_node);
    for step in &object_path[1..] {
        let child = match target {
            Node::Object(obj) => obj.children.iter().find_map(|c| match c {
                DoChild::SubDo(sub) if sub.name == *step => Some(Node::Object(sub)),
                DoChild::Da(da) if da.name == *step && da.fc == fc => Some(Node::Attribute(da)),
                _ => None,
            }),
            Node::Attribute(da) => da.child_by_name(step).map(Node::Attribute),
        };
        let Some(child) = child else {
            tracing::warn!(
                domain = domain,
                item_id = item_id,
                step = *step,
                "write: no node of that name under this functional constraint"
            );
            return WriteOutcome::Failure(DataAccessError::ObjectNonExistent);
        };
        ancestors.push(target);
        target = child;
    }

    // A data object holds a value under a functional constraint only through
    // the attributes it carries under that constraint.
    if let Node::Object(obj) = target {
        if !object_has_fc(obj, fc) {
            tracing::warn!(
                domain = domain,
                item_id = item_id,
                "write: the data object has no attribute under this functional constraint"
            );
            return WriteOutcome::Failure(DataAccessError::ObjectNonExistent);
        }
    }

    // The declared type of the target, as GetVariableAccessAttributes reports
    // it; the model and its MMS view are built together, so a resolved target
    // always has one.
    let Some(spec) = mms_model.spec_at(domain, item_id) else {
        tracing::warn!(
            domain = domain,
            item_id = item_id,
            "write: the target has no type description"
        );
        return WriteOutcome::Failure(DataAccessError::ObjectNonExistent);
    };

    // Every leaf is checked, and its value fixed, before any handler runs.
    let new_value = match check_value(target, fc, spec, data) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                domain = domain,
                item_id = item_id,
                ?e,
                "write: the value does not match the declared type"
            );
            return WriteOutcome::Failure(e);
        }
    };

    let handlers = handler_registry
        .map(|r| r.write_handlers_around(item_id))
        .unwrap_or_default();

    // A handler on an ancestor of the target decides the write as it decides a
    // write of the whole ancestor: it sees the ancestor's current value with
    // the target replaced by the written one, outermost ancestor first.
    if !handlers.is_empty() {
        for (depth, ancestor) in ancestors.iter().enumerate() {
            let path = leading_segments(item_id, depth + 3);
            let Some(handler) = handler_at(&handlers, path) else {
                continue;
            };
            let merged = merged_value(*ancestor, fc, &object_path[depth + 1..], new_value.clone());
            match consult_write_handler(handler, path, fc, conn_id, &merged) {
                HandlerWriteOutcome::Reject(e) => return WriteOutcome::Failure(e),
                // The handler takes the whole ancestor over, so no cached value
                // of it changes.
                HandlerWriteOutcome::AcceptNoUpdate => return WriteOutcome::Success,
                HandlerWriteOutcome::Accept => {}
            }
        }
    }

    // Every node the write reaches, in pre-order: the target first, then each
    // node beneath it down to the leaves. Paths are needed only to find
    // handlers.
    let mut nodes: Vec<NodeWrite<'_, '_>> = Vec::new();
    let target_path = (!handlers.is_empty()).then(|| item_id.to_string());
    collect_node_writes(target, fc, &new_value, target_path, &mut nodes);

    // The handlers run only after the policy and value checks have passed, and
    // before any cached value changes. A handler may accept and let the cache
    // be updated, accept and take ownership of the value itself, which leaves
    // the cache of the node and everything beneath it alone, or refuse with a
    // specific error, which refuses the whole write.
    let mut updates: Vec<(&DataAttribute, &iec61850_model::MmsValue)> = Vec::new();
    let mut i = 0;
    while i < nodes.len() {
        let node = &nodes[i];
        let handler = node
            .path
            .as_deref()
            .and_then(|path| Some((path, handler_at(&handlers, path)?)));
        if let Some((path, handler)) = handler {
            match consult_write_handler(handler, path, fc, conn_id, node.value) {
                HandlerWriteOutcome::Reject(e) => return WriteOutcome::Failure(e),
                HandlerWriteOutcome::AcceptNoUpdate => {
                    i = node.end;
                    continue;
                }
                HandlerWriteOutcome::Accept => {}
            }
        }
        if let Some(leaf) = node.leaf {
            updates.push((leaf, node.value));
        }
        i += 1;
    }

    for (leaf, new_value) in updates {
        if let Err(e) = store_value(leaf, new_value.clone()) {
            tracing::warn!(
                domain = domain,
                da = leaf.name.as_str(),
                "write: the value lock is poisoned, answering temporarily-unavailable"
            );
            return WriteOutcome::Failure(e);
        }
    }
    tracing::debug!(
        domain = domain,
        ln = ln_name,
        do_name = do_name,
        item_id = item_id,
        "write: value updated"
    );
    WriteOutcome::Success
}

/// A node of the model a write reaches: a data object or sub-data-object,
/// seen under the functional constraint of the write, or a data attribute.
#[derive(Debug, Clone, Copy)]
enum Node<'a> {
    Object(&'a DataObject),
    Attribute(&'a DataAttribute),
}

impl<'a> Node<'a> {
    fn name(self) -> &'a str {
        match self {
            Node::Object(obj) => &obj.name,
            Node::Attribute(da) => &da.name,
        }
    }

    /// Reports whether the node holds its value itself rather than in the
    /// nodes beneath it.
    fn is_leaf(self) -> bool {
        match self {
            Node::Object(_) => false,
            Node::Attribute(da) => {
                da.ty != DataAttributeType::Constructed && da.children.is_empty()
            }
        }
    }

    /// The nodes beneath this one under `fc`, in model order, which is the
    /// member order of its MMS structure: for an object, its attributes of
    /// `fc` and its sub-objects that hold one; for an attribute, its
    /// sub-attributes.
    fn children(self, fc: FC) -> impl Iterator<Item = Node<'a>> {
        let (object_children, attribute_children): (&'a [DoChild], &'a [DataAttribute]) = match self
        {
            Node::Object(obj) => (&obj.children, &[]),
            Node::Attribute(da) => (&[], &da.children),
        };
        object_children
            .iter()
            .filter_map(move |c| match c {
                DoChild::Da(da) if da.fc == fc => Some(Node::Attribute(da)),
                DoChild::SubDo(sub) if object_has_fc(sub, fc) => Some(Node::Object(sub)),
                _ => None,
            })
            .chain(attribute_children.iter().map(Node::Attribute))
    }

    /// The current value of the node under `fc`.
    fn snapshot(self, fc: FC) -> iec61850_model::MmsValue {
        match self {
            Node::Attribute(da) => da.snapshot(),
            Node::Object(_) => iec61850_model::MmsValue::Structure(
                self.children(fc).map(|c| c.snapshot(fc)).collect(),
            ),
        }
    }
}

/// Reports whether a data object carries an attribute of `fc`, directly or in
/// a sub-object.
fn object_has_fc(obj: &DataObject, fc: FC) -> bool {
    obj.children.iter().any(|c| match c {
        DoChild::Da(da) => da.fc == fc,
        DoChild::SubDo(sub) => object_has_fc(sub, fc),
    })
}

/// Returns the first `n` `$`-separated segments of `path`.
fn leading_segments(path: &str, n: usize) -> &str {
    match path.match_indices('$').nth(n.saturating_sub(1)) {
        Some((end, _)) if n > 0 => &path[..end],
        _ => path,
    }
}

/// Returns the current value of `node` with the node `steps` names below it
/// replaced by `new_value`.
fn merged_value(
    node: Node<'_>,
    fc: FC,
    steps: &[&str],
    new_value: iec61850_model::MmsValue,
) -> iec61850_model::MmsValue {
    let Some((step, rest)) = steps.split_first() else {
        return new_value;
    };
    let mut new_value = Some(new_value);
    iec61850_model::MmsValue::Structure(
        node.children(fc)
            .map(|child| match new_value.take_if(|_| child.name() == *step) {
                Some(v) => merged_value(child, fc, rest, v),
                None => child.snapshot(fc),
            })
            .collect(),
    )
}

/// One node a write reaches, with the value it is written: a leaf, whose
/// cached value that replaces, or a node above leaves, whose handler it
/// consults.
struct NodeWrite<'a, 'v> {
    leaf: Option<&'a DataAttribute>,
    value: &'v iec61850_model::MmsValue,
    /// The MMS item id of the node, when handlers are to be looked up.
    path: Option<String>,
    /// Index of the first node after the subtree of this one.
    end: usize,
}

/// Appends the nodes `value` writes, `node` first and then its subtree in
/// pre-order; `value` has passed [`check_value`] against `node`.
fn collect_node_writes<'a, 'v>(
    node: Node<'a>,
    fc: FC,
    value: &'v iec61850_model::MmsValue,
    path: Option<String>,
    out: &mut Vec<NodeWrite<'a, 'v>>,
) {
    let index = out.len();
    out.push(NodeWrite {
        leaf: match node {
            Node::Attribute(da) if node.is_leaf() => Some(da),
            _ => None,
        },
        value,
        path: path.clone(),
        end: index + 1,
    });
    if !node.is_leaf() {
        if let iec61850_model::MmsValue::Structure(members) = value {
            for (child, member) in node.children(fc).zip(members) {
                let child_path = path.as_ref().map(|p| format!("{p}${}", child.name()));
                collect_node_writes(child, fc, member, child_path, out);
            }
        }
    }
    out[index].end = out.len();
}

/// Checks `data` against `node` and its declared type `spec`, and returns the
/// value to store.
///
/// A data object takes a structure with one member per node it holds under
/// `fc`, and a constructed attribute one member per sub-attribute; another
/// member count, or a scalar for a data object, is type-inconsistent, a scalar
/// for a constructed attribute object-value-invalid. A leaf takes a value of
/// the variant it holds, else object-value-invalid, then
/// [`check_declared_type`] applies.
fn check_value(
    node: Node<'_>,
    fc: FC,
    spec: &MmsTypeSpec,
    data: &MmsData,
) -> Result<iec61850_model::MmsValue, DataAccessError> {
    if let Node::Attribute(da) = node {
        if node.is_leaf() {
            if !same_data_variant(data, &da.snapshot()) {
                return Err(DataAccessError::ObjectValueInvalid);
            }
            return check_declared_type(spec, data);
        }
    }
    let MmsData::Structure(members) = data else {
        return Err(match node {
            Node::Object(_) => DataAccessError::TypeInconsistent,
            Node::Attribute(_) => DataAccessError::ObjectValueInvalid,
        });
    };
    let MmsTypeSpec::Structure(member_specs) = spec else {
        // An array of data objects is not written through this path.
        return Err(DataAccessError::ObjectAccessUnsupported);
    };
    if members.len() != member_specs.len() {
        return Err(DataAccessError::TypeInconsistent);
    }
    let mut children = node.children(fc);
    let mut values = Vec::with_capacity(members.len());
    for (member_spec, member) in member_specs.iter().zip(members) {
        let Some(child) = children.next() else {
            return Err(DataAccessError::TypeInconsistent);
        };
        // The MMS view lists the members in the order the model holds them.
        debug_assert_eq!(member_spec.name, child.name());
        values.push(check_value(child, fc, &member_spec.type_spec, member)?);
    }
    if children.next().is_some() {
        return Err(DataAccessError::TypeInconsistent);
    }
    Ok(iec61850_model::MmsValue::Structure(values))
}

/// Checks a value of the right variant against the type its attribute declares
/// and returns the value to store.
///
/// The value must lie within the range of an integer width, the length of a
/// visible, Unicode or octet string, and the octet count of a binary time; a
/// structure that a scalar attribute such as PhyComAddr declares is checked
/// member by member. Anything outside the declared type is object-value-invalid
/// (IEC 61850-8-1 §8.1.2.1); a structure of another member count is
/// type-inconsistent. The length of a Unicode string counts characters, as
/// IEC 61850-8-1 §8.1.2.6 sizes an MMSString.
///
/// A bit string must fit its declared size, else type-inconsistent. One
/// shorter than a `Max(n)` size is padded with zero bits to n bits, as
/// IEC 61850-8-1 §8.1.2.1 has the server supply the bits a client leaves out,
/// so it is stored, and read, at the full length (§8.2).
fn check_declared_type(
    spec: &MmsTypeSpec,
    data: &MmsData,
) -> Result<iec61850_model::MmsValue, DataAccessError> {
    let fits = match (spec, data) {
        (MmsTypeSpec::Leaf(MmsLeafType::Integer(bits)), MmsData::Integer(v)) => {
            fits_width(i128::from(*v), *bits, true)
        }
        (MmsTypeSpec::Leaf(MmsLeafType::Integer(bits)), MmsData::Unsigned(v)) => {
            fits_width(i128::from(*v), *bits, true)
        }
        (MmsTypeSpec::Leaf(MmsLeafType::Unsigned(bits)), MmsData::Integer(v)) => {
            fits_width(i128::from(*v), *bits, false)
        }
        (MmsTypeSpec::Leaf(MmsLeafType::Unsigned(bits)), MmsData::Unsigned(v)) => {
            fits_width(i128::from(*v), *bits, false)
        }
        (MmsTypeSpec::Leaf(MmsLeafType::OctetString(size)), MmsData::OctetString(v)) => {
            fits_length(*size, v.len())
        }
        (MmsTypeSpec::Leaf(MmsLeafType::VisibleString(size)), MmsData::VisibleString(v)) => {
            fits_length(*size, v.len())
        }
        (MmsTypeSpec::Leaf(MmsLeafType::UnicodeString(size)), MmsData::MmsString(v)) => {
            fits_length(*size, v.chars().count())
        }
        (MmsTypeSpec::Leaf(MmsLeafType::BinaryTime { size }), MmsData::BinaryTime(v)) => {
            v.len() == usize::from(*size)
        }
        (
            MmsTypeSpec::Leaf(MmsLeafType::BitString(size)),
            MmsData::BitString { padding, data } | MmsData::BooleanArray { padding, data },
        ) => return fit_bit_string(*size, *padding, data),
        (MmsTypeSpec::Structure(member_specs), MmsData::Structure(members)) => {
            if member_specs.len() != members.len() {
                return Err(DataAccessError::TypeInconsistent);
            }
            return member_specs
                .iter()
                .zip(members)
                .map(|(member_spec, member)| check_declared_type(&member_spec.type_spec, member))
                .collect::<Result<Vec<_>, _>>()
                .map(iec61850_model::MmsValue::Structure);
        }
        _ => true,
    };
    if fits {
        Ok(mms_data_to_mms_value(data))
    } else {
        Err(DataAccessError::ObjectValueInvalid)
    }
}

/// Reports whether `v` lies within an integer of `bits` bits, signed or not
/// (IEC 61850-8-1 §8.1.1, table 15). A width of 64 bits or more admits every
/// value the wire decoder yields.
fn fits_width(v: i128, bits: u16, signed: bool) -> bool {
    if bits >= 64 {
        return signed || v >= 0;
    }
    let bits = u32::from(bits);
    if signed {
        let half = 1i128 << (bits - 1);
        (-half..half).contains(&v)
    } else {
        (0..1i128 << bits).contains(&v)
    }
}

/// Reports whether a string of `len` units fits a declared size: at most N for
/// `Max(N)`, exactly N for `Fixed(N)`, anything for `Generic`.
fn fits_length(size: StringSize, len: usize) -> bool {
    match size {
        StringSize::Max(n) => len <= usize::from(n),
        StringSize::Fixed(n) => len == usize::from(n),
        StringSize::Generic => true,
    }
}

/// Checks a bit string of `bytes` with `padding` unused bits against its
/// declared size and returns the bit string to store: padded with zero bits to
/// n bits for a `Max(n)` size, as written otherwise, with the unused bits of
/// the last byte cleared either way.
fn fit_bit_string(
    size: StringSize,
    padding: u8,
    bytes: &[u8],
) -> Result<iec61850_model::MmsValue, DataAccessError> {
    if !bit_string_fits(size, bytes.len(), padding) {
        return Err(DataAccessError::TypeInconsistent);
    }
    let mut data = bit_string_bytes(padding, bytes);
    let StringSize::Max(n) = size else {
        return Ok(iec61850_model::MmsValue::BitString { padding, data });
    };
    let n = usize::from(n);
    data.resize(n.div_ceil(8), 0);
    Ok(iec61850_model::MmsValue::BitString {
        // The length is at most 65535 bits, so the unused bits fit a u8.
        padding: (data.len() * 8 - n) as u8,
        data,
    })
}

/// Gives `handler`, installed on `path`, its say on `new_value`.
fn consult_write_handler(
    handler: &Arc<dyn AttributeAccessHandler>,
    path: &str,
    fc: FC,
    conn_id: u64,
    new_value: &iec61850_model::MmsValue,
) -> HandlerWriteOutcome {
    let ctx = WriteContext::new(path, fc, conn_id);
    let outcome = handler.on_write(&ctx, new_value);
    match &outcome {
        HandlerWriteOutcome::Reject(e) => tracing::warn!(
            path = path,
            ?e,
            "write: the attribute access handler refused the value"
        ),
        HandlerWriteOutcome::AcceptNoUpdate => tracing::debug!(
            path = path,
            "write: the attribute access handler accepted the value without a cache update"
        ),
        HandlerWriteOutcome::Accept => {}
    }
    outcome
}

/// Returns the handler of `handlers` installed on `path`.
fn handler_at<'h>(
    handlers: &'h [(String, Arc<dyn AttributeAccessHandler>)],
    path: &str,
) -> Option<&'h Arc<dyn AttributeAccessHandler>> {
    handlers
        .iter()
        .find_map(|(key, handler)| (key == path).then_some(handler))
}

/// Replaces the cached value of a leaf.
///
/// `std::sync::RwLock::write` yields a `Result` while `spin::RwLock::write`
/// yields the guard, hence the two arms. Only a panic while the value was
/// locked can poison it, which answers a retryable temporarily-unavailable.
fn store_value(
    da: &DataAttribute,
    new_value: iec61850_model::MmsValue,
) -> Result<(), DataAccessError> {
    #[cfg(feature = "std")]
    {
        let mut guard = da
            .value
            .write()
            .map_err(|_| DataAccessError::TemporarilyUnavailable)?;
        *guard = new_value;
    }
    #[cfg(not(feature = "std"))]
    {
        *da.value.write() = new_value;
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "setting-groups"))]
mod tests {
    use super::*;
    use crate::setting_groups::{SettingGroupRegistry, SettingGroupRuntime};
    use iec61850_model::{
        DataAttribute, DataAttributeType, DataObject, DoChild, IedModelBuilder,
        LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, SettingGroupControlBlock, TrgOps, FC,
    };
    use std::sync::Arc;

    fn build_test_model() -> (iec61850_model::IedModel, MmsDeviceModel) {
        // MMXU1.TotW.mag, MX and float32: always refused.
        let mag_da = DataAttribute::new(
            "mag",
            FC::Mx,
            DataAttributeType::Float32,
            TrgOps::default(),
            MmsValue::Float32(0.0),
        );
        // GGIO1.Mod.ctlModel, CF and int32: governed by the policy bitmask.
        let ctl_model_da = DataAttribute::new(
            "ctlModel",
            FC::Cf,
            DataAttributeType::Int32,
            TrgOps::default(),
            MmsValue::Integer(0),
        );
        // GGIO1.SPCSO1.ctlVal, SP and boolean: governed by the policy bitmask.
        let ctl_val_da = DataAttribute::new(
            "ctlVal",
            FC::Sp,
            DataAttributeType::Boolean,
            TrgOps::default(),
            MmsValue::Boolean(false),
        );

        let totw_do = DataObject::new("TotW", vec![DoChild::Da(mag_da)]);
        let mod_do = DataObject::new("Mod", vec![DoChild::Da(ctl_model_da)]);
        let spcso_do = DataObject::new("SPCSO1", vec![DoChild::Da(ctl_val_da)]);
        // GGIO1.SetPt.setMag, SP and constructed.
        let set_mag_da = DataAttribute::constructed(
            "setMag",
            FC::Sp,
            vec![DataAttribute::new(
                "f",
                FC::Sp,
                DataAttributeType::Float32,
                TrgOps::default(),
                MmsValue::Float32(0.0),
            )],
        );
        let setpt_do = DataObject::new("SetPt", vec![DoChild::Da(set_mag_da)]);

        let mmxu_ln = iec61850_model::LogicalNode::new(String::new(), "MMXU", "1", vec![totw_do]);
        let ggio_ln = iec61850_model::LogicalNode::new(
            String::new(),
            "GGIO",
            "1",
            vec![mod_do, spcso_do, setpt_do],
        );

        let lln0 = LogicalNodeBuilder::lln0().build().unwrap();
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(lln0)
            .add_ln(mmxu_ln)
            .add_ln(ggio_ln)
            .build()
            .unwrap();
        let model = IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap();
        let mms_model = MmsDeviceModel::from_ied_model(&model).unwrap();
        (model, mms_model)
    }

    // ── Happy path: policy allows CF and the type matches ───────────────

    #[test]
    fn write_cf_allowed_succeeds() {
        let (model, mms_model) = build_test_model();
        let mut policies = WriteAccessPolicies::default();
        policies.set(FC::Cf, true);

        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "GGIO1$CF$Mod$ctlModel".to_string(),
        };
        let data = MmsData::Integer(2);
        let result =
            handle_single_write(&model, &mms_model, &policies, None, None, 0, &name, &data);
        assert_eq!(result, WriteOutcome::Success);
    }

    // ── ST and MX are always refused ────────────────────────────────────

    #[test]
    fn write_mx_always_denied() {
        let (model, mms_model) = build_test_model();
        let policies = WriteAccessPolicies::default();

        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "MMXU1$MX$TotW$mag".to_string(),
        };
        let data = MmsData::Float32(99.9);
        let result =
            handle_single_write(&model, &mms_model, &policies, None, None, 0, &name, &data);
        assert_eq!(
            result,
            WriteOutcome::Failure(DataAccessError::ObjectAccessDenied)
        );
    }

    // ── The policy refuses CF unless it is enabled ──────────────────────

    #[test]
    fn write_cf_policy_denied() {
        let (model, mms_model) = build_test_model();
        // The default mask is SP | SV | SE and excludes CF.
        let policies = WriteAccessPolicies::default();

        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "GGIO1$CF$Mod$ctlModel".to_string(),
        };
        let data = MmsData::Integer(2);
        let result =
            handle_single_write(&model, &mms_model, &policies, None, None, 0, &name, &data);
        assert_eq!(
            result,
            WriteOutcome::Failure(DataAccessError::ObjectAccessDenied)
        );
    }

    // ── A type mismatch answers object-value-invalid ────────────────────

    #[test]
    fn write_type_mismatch_returns_invalid() {
        let (model, mms_model) = build_test_model();
        let mut policies = WriteAccessPolicies::default();
        policies.set(FC::Cf, true);

        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "GGIO1$CF$Mod$ctlModel".to_string(),
        };
        // ctlModel holds an integer; a boolean does not match it.
        let data = MmsData::Boolean(true);
        let result =
            handle_single_write(&model, &mms_model, &policies, None, None, 0, &name, &data);
        assert_eq!(
            result,
            WriteOutcome::Failure(DataAccessError::ObjectValueInvalid)
        );
    }

    // ── A constructed attribute is written through its leaves ──────────

    fn write_set_mag(
        model: &iec61850_model::IedModel,
        mms_model: &MmsDeviceModel,
        handlers: Option<&HandlerRegistry>,
        item_id: &str,
        data: MmsData,
    ) -> WriteOutcome {
        // The default mask includes SP, so the request reaches the attribute.
        let policies = WriteAccessPolicies::default();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: item_id.to_string(),
        };
        handle_single_write(model, mms_model, &policies, handlers, None, 0, &name, &data)
    }

    /// The value of a constructed attribute lives in its leaves, so a write of
    /// the whole attribute stores each member in the leaf of the same position.
    #[test]
    fn write_constructed_da_stores_every_leaf() {
        let (model, mms_model) = build_test_model();
        let result = write_set_mag(
            &model,
            &mms_model,
            None,
            "GGIO1$SP$SetPt$setMag",
            MmsData::Structure(vec![MmsData::Float32(1.5)]),
        );
        assert_eq!(result, WriteOutcome::Success);
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$SetPt$setMag$f"),
            MmsValue::Float32(1.5)
        );
    }

    /// A leaf below a constructed attribute is written by its own path.
    #[test]
    fn write_leaf_below_a_constructed_da() {
        let (model, mms_model) = build_test_model();
        let result = write_set_mag(
            &model,
            &mms_model,
            None,
            "GGIO1$SP$SetPt$setMag$f",
            MmsData::Float32(2.5),
        );
        assert_eq!(result, WriteOutcome::Success);
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$SetPt$setMag$f"),
            MmsValue::Float32(2.5)
        );
    }

    /// A structure whose shape does not match the attribute changes nothing: a
    /// wrong member count is type-inconsistent, a scalar or a mistyped member is
    /// object-value-invalid, and a name below a leaf does not exist.
    #[test]
    fn write_constructed_da_refuses_a_mismatched_value() {
        let (model, mms_model) = build_test_model();
        let cases = [
            (
                "GGIO1$SP$SetPt$setMag",
                MmsData::Structure(vec![MmsData::Float32(1.0), MmsData::Float32(2.0)]),
                DataAccessError::TypeInconsistent,
            ),
            (
                "GGIO1$SP$SetPt$setMag",
                MmsData::Float32(1.0),
                DataAccessError::ObjectValueInvalid,
            ),
            (
                "GGIO1$SP$SetPt$setMag",
                MmsData::Structure(vec![MmsData::Boolean(true)]),
                DataAccessError::ObjectValueInvalid,
            ),
            (
                "GGIO1$SP$SetPt$setMag$i",
                MmsData::Integer(1),
                DataAccessError::ObjectNonExistent,
            ),
            (
                "GGIO1$SP$SetPt$setMag$f$x",
                MmsData::Float32(1.0),
                DataAccessError::ObjectNonExistent,
            ),
        ];
        for (item_id, data, expected) in cases {
            assert_eq!(
                write_set_mag(&model, &mms_model, None, item_id, data),
                WriteOutcome::Failure(expected),
                "{item_id}"
            );
        }
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$SetPt$setMag$f"),
            MmsValue::Float32(0.0)
        );
    }

    #[derive(Debug)]
    struct Refuse;
    impl crate::handler::AttributeAccessHandler for Refuse {
        fn on_write(&self, _ctx: &WriteContext<'_>, _value: &MmsValue) -> HandlerWriteOutcome {
            HandlerWriteOutcome::Reject(DataAccessError::ObjectAccessDenied)
        }
    }

    #[derive(Debug)]
    struct Own;
    impl crate::handler::AttributeAccessHandler for Own {
        fn on_write(&self, _ctx: &WriteContext<'_>, _value: &MmsValue) -> HandlerWriteOutcome {
            HandlerWriteOutcome::AcceptNoUpdate
        }
    }

    /// The handler of a leaf decides a write of the constructed attribute above
    /// it as it decides a write of the leaf itself.
    #[test]
    fn write_constructed_da_consults_the_leaf_handler() {
        let (model, mms_model) = build_test_model();
        let registry = HandlerRegistry::new();
        registry
            .install_write_access_handler("GGIO1$SP$SetPt$setMag$f", Arc::new(Refuse))
            .unwrap();
        for (item_id, data) in [
            (
                "GGIO1$SP$SetPt$setMag",
                MmsData::Structure(vec![MmsData::Float32(3.0)]),
            ),
            ("GGIO1$SP$SetPt$setMag$f", MmsData::Float32(3.0)),
        ] {
            assert_eq!(
                write_set_mag(&model, &mms_model, Some(&registry), item_id, data),
                WriteOutcome::Failure(DataAccessError::ObjectAccessDenied),
                "{item_id}"
            );
        }
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$SetPt$setMag$f"),
            MmsValue::Float32(0.0)
        );
    }

    /// Records the value it is asked about, then answers as configured.
    #[derive(Debug)]
    struct Witness {
        answer: HandlerWriteOutcome,
        seen: std::sync::Mutex<Vec<MmsValue>>,
    }
    impl crate::handler::AttributeAccessHandler for Witness {
        fn on_write(&self, _ctx: &WriteContext<'_>, value: &MmsValue) -> HandlerWriteOutcome {
            self.seen.lock().unwrap().push(value.clone());
            self.answer.clone()
        }
    }

    fn witness(answer: HandlerWriteOutcome) -> Arc<Witness> {
        Arc::new(Witness {
            answer,
            seen: std::sync::Mutex::new(Vec::new()),
        })
    }

    /// A handler on a constructed attribute decides a write of a leaf below it
    /// as it decides a write of the attribute itself: a refusal refuses the
    /// leaf, and the leaf keeps its value.
    #[test]
    fn write_leaf_consults_the_handler_of_the_constructed_ancestor() {
        let (model, mms_model) = build_test_model();
        let registry = HandlerRegistry::new();
        registry
            .install_write_access_handler("GGIO1$SP$SetPt$setMag", Arc::new(Refuse))
            .unwrap();
        for (item_id, data) in [
            (
                "GGIO1$SP$SetPt$setMag",
                MmsData::Structure(vec![MmsData::Float32(5.0)]),
            ),
            ("GGIO1$SP$SetPt$setMag$f", MmsData::Float32(5.0)),
        ] {
            assert_eq!(
                write_set_mag(&model, &mms_model, Some(&registry), item_id, data),
                WriteOutcome::Failure(DataAccessError::ObjectAccessDenied),
                "{item_id}"
            );
        }
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$SetPt$setMag$f"),
            MmsValue::Float32(0.0)
        );
    }

    /// The ancestor's handler sees the ancestor as it would be after the
    /// write; accepting lets the leaf be stored, taking the value over leaves
    /// the cache alone.
    #[test]
    fn write_leaf_passes_the_merged_ancestor_value() {
        let (model, mms_model) = build_test_model();
        let accept = witness(HandlerWriteOutcome::Accept);
        let registry = HandlerRegistry::new();
        registry
            .install_write_access_handler("GGIO1$SP$SetPt$setMag", accept.clone())
            .unwrap();
        let result = write_set_mag(
            &model,
            &mms_model,
            Some(&registry),
            "GGIO1$SP$SetPt$setMag$f",
            MmsData::Float32(6.0),
        );
        assert_eq!(result, WriteOutcome::Success);
        assert_eq!(
            *accept.seen.lock().unwrap(),
            [MmsValue::Structure(vec![MmsValue::Float32(6.0)])]
        );
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$SetPt$setMag$f"),
            MmsValue::Float32(6.0)
        );

        let own = witness(HandlerWriteOutcome::AcceptNoUpdate);
        let registry = HandlerRegistry::new();
        registry
            .install_write_access_handler("GGIO1$SP$SetPt$setMag", own.clone())
            .unwrap();
        let result = write_set_mag(
            &model,
            &mms_model,
            Some(&registry),
            "GGIO1$SP$SetPt$setMag$f",
            MmsData::Float32(7.0),
        );
        assert_eq!(result, WriteOutcome::Success);
        assert_eq!(own.seen.lock().unwrap().len(), 1);
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$SetPt$setMag$f"),
            MmsValue::Float32(6.0)
        );
    }

    /// A handler on the constructed attribute that takes the value over leaves
    /// every leaf beneath it untouched, and the write succeeds.
    #[test]
    fn write_constructed_da_handler_can_own_the_value() {
        let (model, mms_model) = build_test_model();
        let registry = HandlerRegistry::new();
        registry
            .install_write_access_handler("GGIO1$SP$SetPt$setMag", Arc::new(Own))
            .unwrap();
        let result = write_set_mag(
            &model,
            &mms_model,
            Some(&registry),
            "GGIO1$SP$SetPt$setMag",
            MmsData::Structure(vec![MmsData::Float32(4.0)]),
        );
        assert_eq!(result, WriteOutcome::Success);
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$SetPt$setMag$f"),
            MmsValue::Float32(0.0)
        );
    }

    // ── Sub-data-objects on the write path ─────────────────────────────

    /// A logical node whose `PhSet` is shaped like a WYE: the settable
    /// attributes sit under phase sub-data-objects rather than directly under
    /// the data object.
    ///
    /// `phsA` holds `setMag` (SP, writable) and `setCplx` (SP, constructed);
    /// `phsB` nests a second sub-data-object so a two-level descent has a
    /// target.
    fn build_sdo_write_model() -> (iec61850_model::IedModel, MmsDeviceModel) {
        let set_mag = DataAttribute::new(
            "setMag",
            FC::Sp,
            DataAttributeType::Float32,
            TrgOps::default(),
            MmsValue::Float32(0.0),
        );
        let set_cplx = DataAttribute::constructed(
            "setCplx",
            FC::Sp,
            vec![DataAttribute::new(
                "f",
                FC::Sp,
                DataAttributeType::Float32,
                TrgOps::default(),
                MmsValue::Float32(0.0),
            )],
        );
        let phs_a = DataObject::new("phsA", vec![DoChild::Da(set_mag), DoChild::Da(set_cplx)]);
        let deep = DataObject::new(
            "cmv",
            vec![DoChild::Da(DataAttribute::new(
                "setDeep",
                FC::Sp,
                DataAttributeType::Float32,
                TrgOps::default(),
                MmsValue::Float32(0.0),
            ))],
        );
        let phs_b = DataObject::new("phsB", vec![DoChild::SubDo(deep)]);
        let phset_do = DataObject::new("PhSet", vec![DoChild::SubDo(phs_a), DoChild::SubDo(phs_b)]);
        let ggio_ln = iec61850_model::LogicalNode::new(String::new(), "GGIO", "1", vec![phset_do]);
        let lln0 = LogicalNodeBuilder::lln0().build().unwrap();
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(lln0)
            .add_ln(ggio_ln)
            .build()
            .unwrap();
        let model = IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap();
        let mms_model = MmsDeviceModel::from_ied_model(&model).unwrap();
        (model, mms_model)
    }

    fn sdo_write(
        model: &iec61850_model::IedModel,
        mms_model: &MmsDeviceModel,
        policies: &WriteAccessPolicies,
        item_id: &str,
        data: MmsData,
    ) -> WriteOutcome {
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: item_id.to_string(),
        };
        handle_single_write(model, mms_model, policies, None, None, 0, &name, &data)
    }

    /// Reads a leaf back out of the model, so a write is checked by what it
    /// stored rather than by its return value alone.
    fn leaf_value(model: &iec61850_model::IedModel, reference: &str) -> MmsValue {
        let r = iec61850_model::ObjectRef::parse_mms(reference)
            .unwrap_or_else(|e| panic!("parse {reference}: {e}"));
        match model.node_by_object_ref(&r) {
            Some(iec61850_model::NodeRef::Da(da)) => da.snapshot(),
            other => panic!("{reference} must resolve to a data attribute, got {other:?}"),
        }
    }

    /// A write reaches an attribute that sits below a sub-data-object, and the
    /// value is stored where a later read finds it.
    #[test]
    fn write_descends_a_sub_data_object_to_an_attribute() {
        let (model, mms_model) = build_sdo_write_model();
        let policies = WriteAccessPolicies::default();
        let result = sdo_write(
            &model,
            &mms_model,
            &policies,
            "GGIO1$SP$PhSet$phsA$setMag",
            MmsData::Float32(12.5),
        );
        assert_eq!(result, WriteOutcome::Success);
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$PhSet$phsA$setMag"),
            MmsValue::Float32(12.5)
        );
    }

    /// The descent crosses as many sub-data-object levels as the model nests.
    #[test]
    fn write_descends_two_sub_data_object_levels() {
        let (model, mms_model) = build_sdo_write_model();
        let policies = WriteAccessPolicies::default();
        let result = sdo_write(
            &model,
            &mms_model,
            &policies,
            "GGIO1$SP$PhSet$phsB$cmv$setDeep",
            MmsData::Float32(-3.25),
        );
        assert_eq!(result, WriteOutcome::Success);
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$PhSet$phsB$cmv$setDeep"),
            MmsValue::Float32(-3.25)
        );
    }

    /// An unknown name below a sub-data-object answers object-non-existent, the
    /// same class an unknown attribute directly under a data object answers.
    #[test]
    fn write_of_an_unknown_name_under_a_sub_data_object_returns_not_found() {
        let (model, mms_model) = build_sdo_write_model();
        let policies = WriteAccessPolicies::default();
        let result = sdo_write(
            &model,
            &mms_model,
            &policies,
            "GGIO1$SP$PhSet$phsA$nosuchda",
            MmsData::Float32(1.0),
        );
        assert_eq!(
            result,
            WriteOutcome::Failure(DataAccessError::ObjectNonExistent)
        );
    }

    /// The value of `phsA` under SP: `setMag`, then `setCplx` with its `f`.
    fn phs_a_value(set_mag: f32, f: f32) -> MmsData {
        MmsData::Structure(vec![
            MmsData::Float32(set_mag),
            MmsData::Structure(vec![MmsData::Float32(f)]),
        ])
    }

    /// A path that stops on a sub-data-object names functional-constrained
    /// data: the structure of its attributes under the constraint writes every
    /// leaf beneath it.
    #[test]
    fn write_to_a_sub_data_object_writes_every_leaf_beneath_it() {
        let (model, mms_model) = build_sdo_write_model();
        let policies = WriteAccessPolicies::default();
        let result = sdo_write(
            &model,
            &mms_model,
            &policies,
            "GGIO1$SP$PhSet$phsA",
            phs_a_value(1.5, 2.5),
        );
        assert_eq!(result, WriteOutcome::Success);
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$PhSet$phsA$setMag"),
            MmsValue::Float32(1.5)
        );
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$PhSet$phsA$setCplx$f"),
            MmsValue::Float32(2.5)
        );
    }

    /// A data object is written through every level of sub-objects it holds.
    #[test]
    fn write_to_a_data_object_crosses_its_sub_objects() {
        let (model, mms_model) = build_sdo_write_model();
        let policies = WriteAccessPolicies::default();
        let result = sdo_write(
            &model,
            &mms_model,
            &policies,
            "GGIO1$SP$PhSet",
            MmsData::Structure(vec![
                phs_a_value(3.0, 4.0),
                MmsData::Structure(vec![MmsData::Structure(vec![MmsData::Float32(5.0)])]),
            ]),
        );
        assert_eq!(result, WriteOutcome::Success);
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$PhSet$phsA$setCplx$f"),
            MmsValue::Float32(4.0)
        );
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$PhSet$phsB$cmv$setDeep"),
            MmsValue::Float32(5.0)
        );
    }

    /// An FCD value whose shape does not follow the data object under the
    /// constraint is type-inconsistent, a member outside its type fails as it
    /// does on its own, and in every case no leaf changes, not even the ones
    /// checked before the failing one.
    #[test]
    fn write_to_a_data_object_is_refused_whole() {
        let (model, mms_model) = build_sdo_write_model();
        let policies = WriteAccessPolicies::default();
        let cases = [
            (
                MmsData::Structure(vec![MmsData::Float32(9.0)]),
                DataAccessError::TypeInconsistent,
            ),
            (MmsData::Float32(9.0), DataAccessError::TypeInconsistent),
            (
                MmsData::Structure(vec![
                    MmsData::Float32(9.0),
                    MmsData::Structure(vec![MmsData::Float32(9.0), MmsData::Float32(9.0)]),
                ]),
                DataAccessError::TypeInconsistent,
            ),
            (
                MmsData::Structure(vec![
                    MmsData::Float32(9.0),
                    MmsData::Structure(vec![MmsData::Boolean(true)]),
                ]),
                DataAccessError::ObjectValueInvalid,
            ),
        ];
        for (data, expected) in cases {
            assert_eq!(
                sdo_write(&model, &mms_model, &policies, "GGIO1$SP$PhSet$phsA", data),
                WriteOutcome::Failure(expected)
            );
        }
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$PhSet$phsA$setMag"),
            MmsValue::Float32(0.0)
        );
    }

    /// A data object that holds nothing under the constraint has nothing to
    /// write, and a path naming only a functional-constraint group is not a
    /// write target.
    #[test]
    fn write_to_a_data_object_without_the_constraint_or_above_it_is_refused() {
        let (model, mms_model) = build_sdo_write_model();
        let mut policies = WriteAccessPolicies::default();
        policies.set(FC::Cf, true);
        assert_eq!(
            sdo_write(
                &model,
                &mms_model,
                &policies,
                "GGIO1$CF$PhSet",
                MmsData::Structure(Vec::new()),
            ),
            WriteOutcome::Failure(DataAccessError::ObjectNonExistent)
        );
        assert_eq!(
            sdo_write(
                &model,
                &mms_model,
                &policies,
                "GGIO1$SP",
                MmsData::Structure(Vec::new()),
            ),
            WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported)
        );
    }

    /// The handler of a leaf decides an FCD write as it decides a write of the
    /// leaf: a refusal refuses the whole write and leaves every leaf alone.
    #[test]
    fn write_to_a_data_object_consults_the_leaf_handlers() {
        let (model, mms_model) = build_sdo_write_model();
        let registry = HandlerRegistry::new();
        registry
            .install_write_access_handler("GGIO1$SP$PhSet$phsA$setCplx$f", Arc::new(Refuse))
            .unwrap();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "GGIO1$SP$PhSet$phsA".to_string(),
        };
        let result = handle_single_write(
            &model,
            &mms_model,
            &WriteAccessPolicies::default(),
            Some(&registry),
            None,
            0,
            &name,
            &phs_a_value(6.0, 7.0),
        );
        assert_eq!(
            result,
            WriteOutcome::Failure(DataAccessError::ObjectAccessDenied)
        );
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$PhSet$phsA$setMag"),
            MmsValue::Float32(0.0)
        );
    }

    /// A handler on the written data object sees the whole value and may take
    /// it over, which leaves every leaf beneath it alone.
    #[test]
    fn write_to_a_data_object_consults_its_own_handler() {
        let (model, mms_model) = build_sdo_write_model();
        let own = witness(HandlerWriteOutcome::AcceptNoUpdate);
        let registry = HandlerRegistry::new();
        registry
            .install_write_access_handler("GGIO1$SP$PhSet$phsA", own.clone())
            .unwrap();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "GGIO1$SP$PhSet$phsA".to_string(),
        };
        let result = handle_single_write(
            &model,
            &mms_model,
            &WriteAccessPolicies::default(),
            Some(&registry),
            None,
            0,
            &name,
            &phs_a_value(6.0, 7.0),
        );
        assert_eq!(result, WriteOutcome::Success);
        assert_eq!(
            *own.seen.lock().unwrap(),
            [MmsValue::Structure(vec![
                MmsValue::Float32(6.0),
                MmsValue::Structure(vec![MmsValue::Float32(7.0)]),
            ])]
        );
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$PhSet$phsA$setMag"),
            MmsValue::Float32(0.0)
        );
    }

    /// A sub-attribute is reached after the descent across a sub-data-object,
    /// and the value is stored where a later read finds it.
    #[test]
    fn write_below_an_attribute_under_a_sub_data_object() {
        let (model, mms_model) = build_sdo_write_model();
        let policies = WriteAccessPolicies::default();
        let result = sdo_write(
            &model,
            &mms_model,
            &policies,
            "GGIO1$SP$PhSet$phsA$setCplx$f",
            MmsData::Float32(1.0),
        );
        assert_eq!(result, WriteOutcome::Success);
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$PhSet$phsA$setCplx$f"),
            MmsValue::Float32(1.0)
        );
    }

    /// The constraint filter survives the descent: `setMag` exists under SP, so
    /// naming it under CF does not resolve.
    #[test]
    fn write_across_a_sub_data_object_keeps_the_constraint_filter() {
        let (model, mms_model) = build_sdo_write_model();
        let mut policies = WriteAccessPolicies::default();
        policies.set(FC::Cf, true);
        let result = sdo_write(
            &model,
            &mms_model,
            &policies,
            "GGIO1$CF$PhSet$phsA$setMag",
            MmsData::Float32(1.0),
        );
        assert_eq!(
            result,
            WriteOutcome::Failure(DataAccessError::ObjectNonExistent)
        );
    }

    /// The policy bitmask still decides before the path is resolved, so a
    /// refused constraint answers object-access-denied and not
    /// object-non-existent, whatever the path below the data object looks like.
    #[test]
    fn write_across_a_sub_data_object_still_honors_the_policy() {
        let (model, mms_model) = build_sdo_write_model();
        let mut policies = WriteAccessPolicies::default();
        policies.set(FC::Sp, false);
        let result = sdo_write(
            &model,
            &mms_model,
            &policies,
            "GGIO1$SP$PhSet$phsA$setMag",
            MmsData::Float32(1.0),
        );
        assert_eq!(
            result,
            WriteOutcome::Failure(DataAccessError::ObjectAccessDenied)
        );
    }

    /// A read-only constraint is refused before the descent runs, so a
    /// sub-data-object path under MX cannot reach a value.
    #[test]
    fn write_across_a_sub_data_object_under_a_read_only_constraint_is_denied() {
        let (model, mms_model) = build_sdo_write_model();
        let policies = WriteAccessPolicies::default();
        let result = sdo_write(
            &model,
            &mms_model,
            &policies,
            "GGIO1$MX$PhSet$phsA$setMag",
            MmsData::Float32(1.0),
        );
        assert_eq!(
            result,
            WriteOutcome::Failure(DataAccessError::ObjectAccessDenied)
        );
    }

    // ── An unresolvable path answers object-non-existent ────────────────

    #[test]
    fn write_nonexistent_da_returns_not_found() {
        let (model, mms_model) = build_test_model();
        let mut policies = WriteAccessPolicies::default();
        policies.set(FC::Cf, true);

        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "GGIO1$CF$Mod$nosuchda".to_string(),
        };
        let data = MmsData::Integer(1);
        let result =
            handle_single_write(&model, &mms_model, &policies, None, None, 0, &name, &data);
        assert_eq!(
            result,
            WriteOutcome::Failure(DataAccessError::ObjectNonExistent)
        );
    }

    // ── CO is refused here even though the dispatcher reroutes it ───────
    //
    // `handle_single_write` is not the entry point for FC CO: the dispatcher
    // sends control writes to the Operate, SelectWithValue, and Cancel handlers
    // through `handle_write_with_co_routing`. This test keeps the refusal in
    // place for a caller that reaches the helper directly.
    #[test]
    fn handle_single_write_treats_co_fc_as_unsupported() {
        let (model, mms_model) = build_test_model();
        let policies = WriteAccessPolicies::default();

        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "GGIO1$CO$SPCSO1$ctlVal".to_string(),
        };
        let data = MmsData::Boolean(true);
        let result =
            handle_single_write(&model, &mms_model, &policies, None, None, 0, &name, &data);
        assert_eq!(
            result,
            WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported)
        );
    }

    // ── VMD-specific / AA-specific → ObjectAccessUnsupported ─────────────

    #[test]
    fn write_vmd_specific_returns_unsupported() {
        let (model, mms_model) = build_test_model();
        let policies = WriteAccessPolicies::default();

        let name = ObjectName::VmdSpecific("MMXU1".to_string());
        let data = MmsData::Boolean(true);
        let result =
            handle_single_write(&model, &mms_model, &policies, None, None, 0, &name, &data);
        assert_eq!(
            result,
            WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported)
        );
    }

    // ── SE and SG enforcement ───────────────────────────────────────────

    /// Builds a model whose LLN0 carries a setting group control block with
    /// three groups, an SE attribute (GGIO1.SetVal), and an SG attribute
    /// (GGIO1.CurVal).
    fn build_sg_test_model() -> (
        iec61850_model::IedModel,
        MmsDeviceModel,
        SettingGroupRegistry,
    ) {
        // The SE attribute is the staging buffer of the edit group.
        let set_val_da = DataAttribute::new(
            "setVal",
            FC::Se,
            DataAttributeType::Int32,
            TrgOps::default(),
            MmsValue::Integer(0),
        );
        // The SG attribute is the read-only value of the active group.
        let cur_val_da = DataAttribute::new(
            "curVal",
            FC::Sg,
            DataAttributeType::Int32,
            TrgOps::default(),
            MmsValue::Integer(0),
        );
        let setpoint_do = DataObject::new(
            "Setpoint",
            vec![DoChild::Da(set_val_da), DoChild::Da(cur_val_da)],
        );

        let ggio_ln =
            iec61850_model::LogicalNode::new(String::new(), "GGIO", "1", vec![setpoint_do]);
        let lln0 = LogicalNodeBuilder::lln0()
            .set_sgcb({
                let mut sgcb = SettingGroupControlBlock::default();
                sgcb.num_of_sg = 3;
                sgcb.act_sg = 1;
                sgcb.has_resv_tms = false;
                sgcb.default_resv_tms_s = 60;
                sgcb
            })
            .build()
            .unwrap();
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(lln0)
            .add_ln(ggio_ln)
            .build()
            .unwrap();
        let model = IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap();
        let mms_model = MmsDeviceModel::from_ied_model(&model).unwrap();
        let registry = SettingGroupRegistry::from_model(&model);
        (model, mms_model, registry)
    }

    #[test]
    fn write_sg_fc_always_denied_even_with_policy() {
        let (model, mms_model, registry) = build_sg_test_model();
        let mut policies = WriteAccessPolicies::default();
        // Every policy-controlled constraint is enabled, so only the read-only
        // rule can account for the refusal.
        for fc in [FC::Cf, FC::Dc, FC::Sp, FC::Sv, FC::Bl, FC::Se] {
            policies.set(fc, true);
        }
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "GGIO1$SG$Setpoint$curVal".to_string(),
        };
        let data = MmsData::Integer(42);
        let result = handle_single_write(
            &model,
            &mms_model,
            &policies,
            None,
            Some(&registry),
            100,
            &name,
            &data,
        );
        assert_eq!(
            result,
            WriteOutcome::Failure(DataAccessError::ObjectAccessDenied),
            "a write under functional constraint SG must always be refused"
        );
    }

    #[test]
    fn write_se_fc_without_edit_session_temporarily_unavailable() {
        let (model, mms_model, registry) = build_sg_test_model();
        let mut policies = WriteAccessPolicies::default();
        policies.set(FC::Se, true);
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "GGIO1$SE$Setpoint$setVal".to_string(),
        };
        let data = MmsData::Integer(99);
        let result = handle_single_write(
            &model,
            &mms_model,
            &policies,
            None,
            Some(&registry),
            100,
            &name,
            &data,
        );
        assert_eq!(
            result,
            WriteOutcome::Failure(DataAccessError::TemporarilyUnavailable),
            "a write under functional constraint SE needs an open edit session, per IEC 61850-7-2 §20.3"
        );
    }

    #[test]
    fn write_se_fc_wrong_owner_temporarily_unavailable() {
        let (model, mms_model, registry) = build_sg_test_model();
        let mut policies = WriteAccessPolicies::default();
        policies.set(FC::Se, true);

        let rt = registry.lookup("IED1LD0").unwrap();
        rt.try_edit_sg(2, 100)
            .expect("conn 100 starts edit session");

        // Association 200 attempts the write it does not own.
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "GGIO1$SE$Setpoint$setVal".to_string(),
        };
        let data = MmsData::Integer(99);
        let result = handle_single_write(
            &model,
            &mms_model,
            &policies,
            None,
            Some(&registry),
            200,
            &name,
            &data,
        );
        assert_eq!(
            result,
            WriteOutcome::Failure(DataAccessError::TemporarilyUnavailable),
            "an association that does not own the edit session must be refused"
        );
    }

    #[test]
    fn write_se_fc_owner_succeeds() {
        let (model, mms_model, registry) = build_sg_test_model();
        let mut policies = WriteAccessPolicies::default();
        policies.set(FC::Se, true);

        let rt = registry.lookup("IED1LD0").unwrap();
        rt.try_edit_sg(2, 100)
            .expect("conn 100 starts edit session");

        // The same association writes into the session it owns.
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "GGIO1$SE$Setpoint$setVal".to_string(),
        };
        let data = MmsData::Integer(99);
        let result = handle_single_write(
            &model,
            &mms_model,
            &policies,
            None,
            Some(&registry),
            100,
            &name,
            &data,
        );
        assert_eq!(result, WriteOutcome::Success);
    }

    #[test]
    fn write_se_fc_policy_denied_short_circuits() {
        // A policy refusal must come before the edit-session check.
        let (model, mms_model, registry) = build_sg_test_model();
        let policies = WriteAccessPolicies::default();
        // The default mask includes SE, so it is cleared explicitly.
        let _ = policies;
        let mut policies = WriteAccessPolicies::default();
        policies.set(FC::Se, false);

        // The edit session is open, so only the policy can refuse the write.
        let rt = registry.lookup("IED1LD0").unwrap();
        rt.try_edit_sg(2, 100)
            .expect("conn 100 starts edit session");

        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "GGIO1$SE$Setpoint$setVal".to_string(),
        };
        let data = MmsData::Integer(99);
        let result = handle_single_write(
            &model,
            &mms_model,
            &policies,
            None,
            Some(&registry),
            100,
            &name,
            &data,
        );
        assert_eq!(
            result,
            WriteOutcome::Failure(DataAccessError::ObjectAccessDenied)
        );
    }

    #[test]
    fn write_se_fc_no_registry_temporarily_unavailable() {
        // No registry was configured, so no edit session can be verified.
        let (model, mms_model, _registry) = build_sg_test_model();
        let mut policies = WriteAccessPolicies::default();
        policies.set(FC::Se, true);
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "GGIO1$SE$Setpoint$setVal".to_string(),
        };
        let data = MmsData::Integer(99);
        let result =
            handle_single_write(&model, &mms_model, &policies, None, None, 100, &name, &data);
        assert_eq!(
            result,
            WriteOutcome::Failure(DataAccessError::TemporarilyUnavailable)
        );
    }

    #[test]
    fn write_se_fc_no_sgcb_on_domain_temporarily_unavailable() {
        // The registry is empty, so the domain has no control block.
        let (model, mms_model, _registry) = build_sg_test_model();
        let empty = SettingGroupRegistry::new();
        let mut policies = WriteAccessPolicies::default();
        policies.set(FC::Se, true);
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "GGIO1$SE$Setpoint$setVal".to_string(),
        };
        let data = MmsData::Integer(99);
        let result = handle_single_write(
            &model,
            &mms_model,
            &policies,
            None,
            Some(&empty),
            100,
            &name,
            &data,
        );
        assert_eq!(
            result,
            WriteOutcome::Failure(DataAccessError::TemporarilyUnavailable)
        );
        let _ = Arc::new(SettingGroupRuntime::new(0, 0, false, 0));
    }

    // ── A written value is readable again ───────────────────────────────

    #[test]
    fn write_value_is_persisted() {
        let (model, mms_model) = build_test_model();
        let mut policies = WriteAccessPolicies::default();
        policies.set(FC::Cf, true);

        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "GGIO1$CF$Mod$ctlModel".to_string(),
        };
        let data = MmsData::Integer(42);
        let result =
            handle_single_write(&model, &mms_model, &policies, None, None, 0, &name, &data);
        assert_eq!(result, WriteOutcome::Success);

        let ld = model.ld_by_domain("IED1LD0").unwrap();
        let ln = ld.ln_by_name("GGIO1").unwrap();
        let do_node = ln.do_by_name("Mod").unwrap();
        let da = do_node
            .children
            .iter()
            .find_map(|c| match c {
                DoChild::Da(da) if da.name == "ctlModel" => Some(da),
                _ => None,
            })
            .unwrap();
        let value = da.snapshot();
        assert_eq!(value, MmsValue::Integer(42));
    }

    // ── A bit string sent as a boolean-array fits the declared size ─────

    /// A wire boolean-array maps onto a model bit string, so it is held to the
    /// declared size too: 13 elements written to a two-bit Dbpos answer
    /// type-inconsistent and the attribute keeps its value; two elements fit.
    #[test]
    fn write_boolean_array_of_other_length_returns_type_inconsistent() {
        let pos = DataAttribute::new(
            "pos",
            FC::Cf,
            DataAttributeType::CodedEnum,
            TrgOps::default(),
            MmsValue::BitString {
                padding: 6,
                data: vec![0x40],
            },
        );
        let value = Arc::clone(&pos.value);
        let cfg_do = DataObject::new("Cfg", vec![DoChild::Da(pos)]);
        let ggio_ln = LogicalNodeBuilder::new("", "GGIO", "1")
            .add_do(cfg_do)
            .build()
            .unwrap();
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(LogicalNodeBuilder::lln0().build().unwrap())
            .add_ln(ggio_ln)
            .build()
            .unwrap();
        let model = IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap();
        let mms_model = MmsDeviceModel::from_ied_model(&model).unwrap();
        let mut policies = WriteAccessPolicies::default();
        policies.set(FC::Cf, true);
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "GGIO1$CF$Cfg$pos".to_string(),
        };

        let data = MmsData::BooleanArray {
            padding: 3,
            data: vec![0, 0],
        };
        let result =
            handle_single_write(&model, &mms_model, &policies, None, None, 0, &name, &data);
        assert_eq!(
            result,
            WriteOutcome::Failure(DataAccessError::TypeInconsistent)
        );
        assert_eq!(
            *value.read().unwrap(),
            MmsValue::BitString {
                padding: 6,
                data: vec![0x40],
            }
        );

        let data = MmsData::BooleanArray {
            padding: 6,
            data: vec![0x80],
        };
        let result =
            handle_single_write(&model, &mms_model, &policies, None, None, 0, &name, &data);
        assert_eq!(result, WriteOutcome::Success);
        assert_eq!(
            *value.read().unwrap(),
            MmsValue::BitString {
                padding: 6,
                data: vec![0x80],
            }
        );
    }

    // ── The declared range and length of a basic type ──────────────────

    /// `GGIO1.Lim` holds one SP attribute per basic type whose range or length
    /// the write path checks.
    fn build_limits_model() -> (iec61850_model::IedModel, MmsDeviceModel) {
        let attrs = vec![
            ("i8", DataAttributeType::Int8, MmsValue::Integer(0)),
            ("u8", DataAttributeType::Int8U, MmsValue::Unsigned(0)),
            ("i16", DataAttributeType::Int16, MmsValue::Integer(0)),
            ("u16", DataAttributeType::Int16U, MmsValue::Unsigned(0)),
            ("i32", DataAttributeType::Int32, MmsValue::Integer(0)),
            ("u32", DataAttributeType::Int32U, MmsValue::Unsigned(0)),
            ("i64", DataAttributeType::Int64, MmsValue::Integer(0)),
            ("en", DataAttributeType::Enumerated, MmsValue::Integer(0)),
            (
                "vis",
                DataAttributeType::VisibleString(4),
                MmsValue::VisibleString(String::new()),
            ),
            (
                "oct",
                DataAttributeType::OctetString(4),
                MmsValue::OctetString(Vec::new()),
            ),
            (
                "oct8",
                DataAttributeType::OctetString(8),
                MmsValue::OctetString(vec![0; 8]),
            ),
            (
                "uni",
                DataAttributeType::UnicodeString255,
                MmsValue::MmsString(String::new()),
            ),
            // A model may hold an unsigned type in a signed value.
            ("u8i", DataAttributeType::Int8U, MmsValue::Integer(0)),
        ];
        let lim = DataObject::new(
            "Lim",
            attrs
                .into_iter()
                .map(|(name, ty, v)| {
                    DoChild::Da(DataAttribute::new(name, FC::Sp, ty, TrgOps::default(), v))
                })
                .collect(),
        );
        let ggio_ln = LogicalNodeBuilder::new("", "GGIO", "1")
            .add_do(lim)
            .build()
            .unwrap();
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(LogicalNodeBuilder::lln0().build().unwrap())
            .add_ln(ggio_ln)
            .build()
            .unwrap();
        let model = IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap();
        let mms_model = MmsDeviceModel::from_ied_model(&model).unwrap();
        (model, mms_model)
    }

    fn write_limit(
        model: &iec61850_model::IedModel,
        mms_model: &MmsDeviceModel,
        attr: &str,
        data: MmsData,
    ) -> WriteOutcome {
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: format!("GGIO1$SP$Lim${attr}"),
        };
        let policies = WriteAccessPolicies::default();
        handle_single_write(model, mms_model, &policies, None, None, 0, &name, &data)
    }

    /// Every integer width admits its bounds and refuses the value one past
    /// each, with object-value-invalid, leaving the attribute as it was.
    #[test]
    fn write_integer_outside_its_width_is_object_value_invalid() {
        let (model, mms_model) = build_limits_model();
        let accepted = [
            ("i8", MmsData::Integer(-128)),
            ("i8", MmsData::Integer(127)),
            ("u8", MmsData::Unsigned(255)),
            ("i16", MmsData::Integer(-32768)),
            ("i16", MmsData::Integer(32767)),
            ("u16", MmsData::Unsigned(65535)),
            ("i32", MmsData::Integer(i64::from(i32::MIN))),
            ("i32", MmsData::Integer(i64::from(i32::MAX))),
            ("u32", MmsData::Unsigned(u64::from(u32::MAX))),
            ("i64", MmsData::Integer(i64::MIN)),
            ("en", MmsData::Integer(127)),
            ("u8i", MmsData::Integer(255)),
        ];
        for (attr, data) in accepted {
            assert_eq!(
                write_limit(&model, &mms_model, attr, data.clone()),
                WriteOutcome::Success,
                "{attr} = {data:?}"
            );
        }
        let refused = [
            ("i8", MmsData::Integer(-129)),
            ("i8", MmsData::Integer(128)),
            ("u8", MmsData::Unsigned(256)),
            ("i16", MmsData::Integer(-32769)),
            ("i16", MmsData::Integer(32768)),
            ("u16", MmsData::Unsigned(65536)),
            ("i32", MmsData::Integer(i64::from(i32::MIN) - 1)),
            ("i32", MmsData::Integer(i64::from(i32::MAX) + 1)),
            ("u32", MmsData::Unsigned(u64::from(u32::MAX) + 1)),
            ("en", MmsData::Integer(128)),
            ("u8i", MmsData::Integer(-1)),
            ("u8i", MmsData::Integer(256)),
        ];
        for (attr, data) in refused {
            assert_eq!(
                write_limit(&model, &mms_model, attr, data.clone()),
                WriteOutcome::Failure(DataAccessError::ObjectValueInvalid),
                "{attr} = {data:?}"
            );
        }
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$Lim$i8"),
            MmsValue::Integer(127)
        );
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$Lim$u8"),
            MmsValue::Unsigned(255)
        );
    }

    /// A string or octet string longer than its maximum length, or of another
    /// length than a fixed one, is object-value-invalid; a Unicode string is
    /// measured in characters, not octets.
    #[test]
    fn write_string_longer_than_its_maximum_is_object_value_invalid() {
        let (model, mms_model) = build_limits_model();
        let accepted = [
            ("vis", MmsData::VisibleString("abcd".into())),
            ("oct", MmsData::OctetString(vec![1, 2, 3, 4])),
            ("oct", MmsData::OctetString(Vec::new())),
            ("oct8", MmsData::OctetString(vec![9; 8])),
            ("uni", MmsData::MmsString("\u{00e9}".repeat(255))),
        ];
        for (attr, data) in accepted {
            assert_eq!(
                write_limit(&model, &mms_model, attr, data.clone()),
                WriteOutcome::Success,
                "{attr} = {data:?}"
            );
        }
        let refused = [
            ("vis", MmsData::VisibleString("abcde".into())),
            ("oct", MmsData::OctetString(vec![1, 2, 3, 4, 5])),
            ("oct8", MmsData::OctetString(vec![9; 7])),
            ("uni", MmsData::MmsString("a".repeat(256))),
        ];
        for (attr, data) in refused {
            assert_eq!(
                write_limit(&model, &mms_model, attr, data.clone()),
                WriteOutcome::Failure(DataAccessError::ObjectValueInvalid),
                "{attr} = {data:?}"
            );
        }
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$Lim$vis"),
            MmsValue::VisibleString("abcd".into())
        );
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$Lim$oct8"),
            MmsValue::OctetString(vec![9; 8])
        );
    }

    // ── A short bit string is padded to the declared maximum ───────────

    /// A Quality written with 9 bits is stored with 13: the 9 written bits,
    /// then zero bits, and the unused bits of the last byte cleared.
    #[test]
    fn write_short_bit_string_is_padded_to_its_maximum() {
        let qual = DataAttribute::new(
            "qual",
            FC::Sp,
            DataAttributeType::Quality,
            TrgOps::default(),
            MmsValue::default_for(DataAttributeType::Quality),
        );
        let value = Arc::clone(&qual.value);
        let cfg_do = DataObject::new("Cfg", vec![DoChild::Da(qual)]);
        let ggio_ln = LogicalNodeBuilder::new("", "GGIO", "1")
            .add_do(cfg_do)
            .build()
            .unwrap();
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(LogicalNodeBuilder::lln0().build().unwrap())
            .add_ln(ggio_ln)
            .build()
            .unwrap();
        let model = IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap();
        let mms_model = MmsDeviceModel::from_ied_model(&model).unwrap();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "GGIO1$SP$Cfg$qual".to_string(),
        };
        let policies = WriteAccessPolicies::default();

        // 9 bits: 1100 0000 1, with garbage in the unused bits.
        let data = MmsData::BitString {
            padding: 7,
            data: vec![0xc0, 0xff],
        };
        let result =
            handle_single_write(&model, &mms_model, &policies, None, None, 0, &name, &data);
        assert_eq!(result, WriteOutcome::Success);
        assert_eq!(
            *value.read().unwrap(),
            MmsValue::BitString {
                padding: 3,
                data: vec![0xc0, 0x80],
            }
        );

        // One bit grows a byte: 1 → 1000 0000 0000 0.
        let data = MmsData::BitString {
            padding: 7,
            data: vec![0x80],
        };
        let result =
            handle_single_write(&model, &mms_model, &policies, None, None, 0, &name, &data);
        assert_eq!(result, WriteOutcome::Success);
        assert_eq!(
            *value.read().unwrap(),
            MmsValue::BitString {
                padding: 3,
                data: vec![0x80, 0x00],
            }
        );
    }

    // ── Handlers on data objects above the target ──────────────────────

    /// A handler on a data object or a sub-data-object decides a write of any
    /// node beneath it: a refusal refuses the write and the leaf keeps its
    /// value, and the handler sees the object's value under the constraint
    /// with the written node replaced.
    #[test]
    fn write_below_a_data_object_consults_its_handler() {
        let (model, mms_model) = build_sdo_write_model();
        for (installed_on, item_id) in [
            ("GGIO1$SP$PhSet", "GGIO1$SP$PhSet$phsA$setMag"),
            ("GGIO1$SP$PhSet$phsA", "GGIO1$SP$PhSet$phsA$setCplx$f"),
            ("GGIO1$SP$PhSet", "GGIO1$SP$PhSet$phsB$cmv"),
        ] {
            let registry = HandlerRegistry::new();
            registry
                .install_write_access_handler(installed_on, Arc::new(Refuse))
                .unwrap();
            let name = ObjectName::DomainSpecific {
                domain_id: "IED1LD0".to_string(),
                item_id: item_id.to_string(),
            };
            let data = if item_id.ends_with("cmv") {
                MmsData::Structure(vec![MmsData::Float32(8.0)])
            } else {
                MmsData::Float32(8.0)
            };
            let result = handle_single_write(
                &model,
                &mms_model,
                &WriteAccessPolicies::default(),
                Some(&registry),
                None,
                0,
                &name,
                &data,
            );
            assert_eq!(
                result,
                WriteOutcome::Failure(DataAccessError::ObjectAccessDenied),
                "{installed_on} over {item_id}"
            );
        }
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$PhSet$phsA$setMag"),
            MmsValue::Float32(0.0)
        );
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$PhSet$phsB$cmv$setDeep"),
            MmsValue::Float32(0.0)
        );

        let accept = witness(HandlerWriteOutcome::Accept);
        let registry = HandlerRegistry::new();
        registry
            .install_write_access_handler("GGIO1$SP$PhSet$phsA", accept.clone())
            .unwrap();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "GGIO1$SP$PhSet$phsA$setCplx$f".to_string(),
        };
        let result = handle_single_write(
            &model,
            &mms_model,
            &WriteAccessPolicies::default(),
            Some(&registry),
            None,
            0,
            &name,
            &MmsData::Float32(9.0),
        );
        assert_eq!(result, WriteOutcome::Success);
        assert_eq!(
            *accept.seen.lock().unwrap(),
            [MmsValue::Structure(vec![
                MmsValue::Float32(0.0),
                MmsValue::Structure(vec![MmsValue::Float32(9.0)]),
            ])]
        );
        assert_eq!(
            leaf_value(&model, "IED1LD0/GGIO1$SP$PhSet$phsA$setCplx$f"),
            MmsValue::Float32(9.0)
        );
    }
}
