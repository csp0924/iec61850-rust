//! Server handler for the Read service of IEC 61850-7-2.
//!
//! Unlike GetVariableAccessAttributes, a Read resolves against the live
//! `IedModel` so that it reaches the actual shared values. An `item_id` of the
//! form `LN$FC$DO[$SDO...][$DA[$SDA...]]` selects how much of the tree is
//! expanded: one segment expands the whole logical node into a nested structure
//! of functional-constraint groups; two segments expand one group into its data
//! objects; three expand one data object into the data attributes of that
//! constraint; four or more cross any number of sub-data-object boundaries and
//! then descend to a single data attribute or sub-attribute. A path that stops
//! on a sub-data-object expands that sub-object under the constraint, so every
//! level of a WYE or CMV tree is readable on its own.
//!
//! Expansion tracks a byte budget as it goes. When the response would exceed
//! the negotiated maximum PDU size, the whole ReadResponse is replaced by a
//! `Resource(0)` ServiceError rather than an individual failure, so expansion
//! short-circuits with [`LookupResult::OverBudget`] and the dispatcher turns
//! that into a ConfirmedError.
//!
//! A path that does not resolve yields `AccessResult::Failure(ObjectNonExistent)`.
//! Read places no restriction on the functional constraint; only Write does.
//!
//! A read of a node is also a read of every node it contains, and a read of a
//! part of every node above it, so the read handlers of all of them have their
//! say, as long as the path resolves:
//!
//! - A handler above the target, on its data object, a sub-data-object or a
//!   constructed attribute, is asked first, outermost first. An error refuses
//!   the read; a value answers it with the part of that value the target
//!   occupies; a miss passes the read on.
//! - Then the handler on the target itself, with the same three outcomes.
//! - Then the handlers below the target, in model order. A value replaces the
//!   part of the answer its node occupies and the handlers below that node are
//!   not asked; an error refuses the whole read, since one access result cannot
//!   carry a failure for a part of its value.
//!
//! A read of a logical node or a functional-constraint group asks the handlers
//! of every data object in it the same way. A refused read carries the error
//! and no part of the value.
//!
//! A value a handler supplies must have the shape of its node: one member per
//! node beneath it, in model order, down to the leaves, else the read answers
//! type-inconsistent; a bit string that does not fit its declared size answers
//! object-value-invalid. The value is charged to the PDU budget as it is sent.

#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use crate::compat::Arc;
use crate::handler::{is_below, HandlerRegistry, ReadContext, ReadHandler, ReadOutcome};
use crate::mapping::{bit_string_fits, declared_bit_string_size, MmsDeviceModel};
use iec61850_mms::mms::pdu::common::{
    AccessResult, AlternateAccess, AlternateAccessSelector, DataAccessError, MmsData, ObjectName,
};
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObject, DoChild, IedModel, LogicalNode, MmsValue, FC,
};

use crate::service::convert::{mms_data_to_mms_value, mms_value_to_mms_data};

// ─────────────────────────────────────────────────────────────────────────────
// Model nodes under a functional constraint
// ─────────────────────────────────────────────────────────────────────────────

/// A node of the model below a logical node: a data object or
/// sub-data-object, seen under one functional constraint, or a data attribute.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Node<'a> {
    Object(&'a DataObject),
    Attribute(&'a DataAttribute),
}

impl<'a> Node<'a> {
    pub(crate) fn name(self) -> &'a str {
        match self {
            Node::Object(obj) => &obj.name,
            Node::Attribute(da) => &da.name,
        }
    }

    /// Reports whether the node holds its value itself rather than in the
    /// nodes beneath it.
    pub(crate) fn is_leaf(self) -> bool {
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
    pub(crate) fn children(self, fc: FC) -> impl Iterator<Item = Node<'a>> {
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

    /// The node named `step` directly beneath this one on a path under `fc`:
    /// a sub-object of that name, an attribute of that name carrying `fc`, or
    /// a sub-attribute of that name.
    pub(crate) fn child(self, fc: FC, step: &str) -> Option<Node<'a>> {
        match self {
            Node::Object(obj) => obj.children.iter().find_map(|c| match c {
                DoChild::SubDo(sub) if sub.name == step => Some(Node::Object(sub)),
                DoChild::Da(da) if da.name == step && da.fc == fc => Some(Node::Attribute(da)),
                _ => None,
            }),
            Node::Attribute(da) => da.child_by_name(step).map(Node::Attribute),
        }
    }

    /// The current value of the node under `fc`.
    pub(crate) fn snapshot(self, fc: FC) -> MmsValue {
        match self {
            Node::Attribute(da) => da.snapshot(),
            Node::Object(_) => {
                MmsValue::Structure(self.children(fc).map(|c| c.snapshot(fc)).collect())
            }
        }
    }
}

/// Reports whether a data object carries an attribute of `fc`, directly or in
/// a sub-object.
pub(crate) fn object_has_fc(obj: &DataObject, fc: FC) -> bool {
    obj.children.iter().any(|c| match c {
        DoChild::Da(da) => da.fc == fc,
        DoChild::SubDo(sub) => object_has_fc(sub, fc),
    })
}

/// Returns the first `n` `$`-separated segments of `path`.
pub(crate) fn leading_segments(path: &str, n: usize) -> &str {
    match path.match_indices('$').nth(n.saturating_sub(1)) {
        Some((end, _)) if n > 0 => &path[..end],
        _ => path,
    }
}

/// Resolves `LN$FC$DO[$...]` in `domain` to its functional constraint and the
/// nodes along the path, the data object first and the target last.
#[cfg(feature = "reporting")]
pub(crate) fn resolve_node_path<'m>(
    ied_model: &'m IedModel,
    domain: &str,
    item_id: &str,
) -> Option<(FC, Vec<Node<'m>>)> {
    let mut parts = item_id.split('$');
    let ln = ied_model.ld_by_domain(domain)?.ln_by_name(parts.next()?)?;
    let fc = FC::parse(parts.next()?).ok()?;
    let mut node = Node::Object(ln.do_by_name(parts.next()?)?);
    let mut nodes = vec![node];
    for step in parts {
        node = node.child(fc, step)?;
        nodes.push(node);
    }
    Some((fc, nodes))
}

// ─────────────────────────────────────────────────────────────────────────────
// Read handlers
// ─────────────────────────────────────────────────────────────────────────────

/// The read handlers one read consults, looked up once: those on the path
/// read, on the nodes above it and on the nodes below it.
pub(crate) struct ReadHandlerScope {
    handlers: Vec<(String, Arc<dyn ReadHandler>)>,
    conn_id: u64,
    /// The path the client named, passed to every handler.
    requested: String,
}

impl ReadHandlerScope {
    /// A scope that consults no handler.
    pub(crate) fn none() -> Self {
        Self {
            handlers: Vec::new(),
            conn_id: 0,
            requested: String::new(),
        }
    }

    /// The handlers of `registry` that bear on a read of `item_id` on the
    /// association `conn_id`; none while the registry ignores read access.
    pub(crate) fn around(registry: &HandlerRegistry, item_id: &str, conn_id: u64) -> Self {
        if registry.ignore_read_access() {
            return Self::none();
        }
        let handlers = registry.read_handlers_around(item_id);
        let requested = if handlers.is_empty() {
            String::new()
        } else {
            item_id.to_string()
        };
        Self {
            handlers,
            conn_id,
            requested,
        }
    }

    fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Reports whether a handler sits on `path` or below it.
    fn reaches(&self, path: &str) -> bool {
        self.handlers
            .iter()
            .any(|(key, _)| key == path || is_below(key, path))
    }

    /// Reports whether a handler sits below `path`.
    fn reaches_below(&self, path: &str) -> bool {
        self.handlers.iter().any(|(key, _)| is_below(key, path))
    }

    /// Asks the handler on `path`, if there is one.
    fn consult(&self, path: &str, fc: FC) -> Option<ReadOutcome> {
        let (_, handler) = self.handlers.iter().find(|(key, _)| key == path)?;
        let ctx = ReadContext::new(path, fc, self.conn_id).with_requested(&self.requested);
        Some(handler.read(&ctx))
    }

    /// Asks the handlers above the target, `ancestors[i]` naming the first
    /// `i + 3` segments of `item_id`, outermost first. `Some` carries the
    /// verdict of the first one that answers with a value or an error: the
    /// part of the value `target` occupies, or the error.
    fn decide_from_above(
        &self,
        fc: FC,
        item_id: &str,
        ancestors: &[Node<'_>],
        target: Node<'_>,
    ) -> Option<Result<MmsData, DataAccessError>> {
        let steps: Vec<&str> = item_id.split('$').skip(3).collect();
        for (depth, ancestor) in ancestors.iter().enumerate() {
            let path = leading_segments(item_id, depth + 3);
            let Some(outcome) = self.consult(path, fc) else {
                continue;
            };
            match outcome {
                ReadOutcome::CacheMiss => continue,
                ReadOutcome::Error(e) => {
                    tracing::warn!(
                        path,
                        ?e,
                        "read: a read handler above the target refused the read"
                    );
                    return Some(Err(e));
                }
                ReadOutcome::CacheHit(value) => {
                    let part = select_below(*ancestor, fc, &steps[depth..], value)
                        .and_then(|part| handler_value(target, fc, item_id, part));
                    return Some(part);
                }
            }
        }
        None
    }

    /// Applies the handlers on `node`, whose path is `path`, and below it to
    /// `value`, the model value of the node.
    fn apply(
        &self,
        node: Node<'_>,
        fc: FC,
        path: &str,
        value: MmsData,
    ) -> Result<MmsData, DataAccessError> {
        match self.consult(path, fc) {
            Some(ReadOutcome::CacheHit(v)) => return handler_value(node, fc, path, v),
            Some(ReadOutcome::Error(e)) => {
                tracing::warn!(path, ?e, "read: a read handler refused the read");
                return Err(e);
            }
            Some(ReadOutcome::CacheMiss) | None => {}
        }
        if node.is_leaf() || !self.reaches_below(path) {
            return Ok(value);
        }
        let MmsData::Structure(mut members) = value else {
            return Ok(value);
        };
        for (child, member) in node.children(fc).zip(members.iter_mut()) {
            let child_path = format!("{path}${}", child.name());
            if self.reaches(&child_path) {
                let current = core::mem::replace(member, MmsData::Boolean(false));
                *member = self.apply(child, fc, &child_path, current)?;
            }
        }
        Ok(MmsData::Structure(members))
    }
}

/// Selects, in `value`, the value of `node`, the part the node `steps` names
/// below `node` occupies. A value of another shape than the model is
/// type-inconsistent.
fn select_below(
    mut node: Node<'_>,
    fc: FC,
    steps: &[&str],
    mut value: MmsValue,
) -> Result<MmsValue, DataAccessError> {
    for step in steps {
        let found = node
            .children(fc)
            .enumerate()
            .find(|(_, child)| child.name() == *step);
        let (Some((index, child)), MmsValue::Structure(mut members)) = (found, value) else {
            return Err(DataAccessError::TypeInconsistent);
        };
        if index >= members.len() {
            return Err(DataAccessError::TypeInconsistent);
        }
        value = members.swap_remove(index);
        node = child;
    }
    Ok(value)
}

/// Turns a value a read handler supplies for `node` under `fc` into wire data,
/// once it has the shape of the node: a structure with one member per node
/// beneath it, in model order, down to the leaves, else type-inconsistent. A
/// bit string that does not fit the declared size of a bit-string attribute is
/// not sent either; the read answers object-value-invalid.
fn handler_value(
    node: Node<'_>,
    fc: FC,
    path: &str,
    value: MmsValue,
) -> Result<MmsData, DataAccessError> {
    if let Err(e) = check_handler_shape(node, fc, &value) {
        tracing::warn!(
            path,
            ?e,
            "read: the read handler returned a value that does not fit the node"
        );
        return Err(e);
    }
    Ok(mms_value_to_mms_data(&value))
}

/// Checks a handler value against the shape of `node` under `fc`.
fn check_handler_shape(node: Node<'_>, fc: FC, value: &MmsValue) -> Result<(), DataAccessError> {
    if node.is_leaf() {
        if let (Node::Attribute(da), MmsValue::BitString { padding, data }) = (node, value) {
            if let Some(size) = declared_bit_string_size(da.ty) {
                if !bit_string_fits(size, data.len(), *padding) {
                    return Err(DataAccessError::ObjectValueInvalid);
                }
            }
        }
        return Ok(());
    }
    let MmsValue::Structure(members) = value else {
        return Err(DataAccessError::TypeInconsistent);
    };
    let mut children = node.children(fc);
    for member in members {
        let Some(child) = children.next() else {
            return Err(DataAccessError::TypeInconsistent);
        };
        check_handler_shape(child, fc, member)?;
    }
    if children.next().is_some() {
        return Err(DataAccessError::TypeInconsistent);
    }
    Ok(())
}

/// Passes `baseline`, the model value of the data attribute or data object
/// `item_id` names in `domain`, through the read handlers of `registry`, as a
/// read of that path would. A failure, and a path that does not resolve, pass
/// unchanged.
#[cfg(feature = "reporting")]
pub(crate) fn apply_read_handlers(
    ied_model: &IedModel,
    registry: &HandlerRegistry,
    conn_id: u64,
    domain: &str,
    item_id: &str,
    baseline: AccessResult,
) -> AccessResult {
    let AccessResult::Success(value) = baseline else {
        return baseline;
    };
    let scope = ReadHandlerScope::around(registry, item_id, conn_id);
    if scope.is_empty() {
        return AccessResult::Success(value);
    }
    let Some((fc, nodes)) = resolve_node_path(ied_model, domain, item_id) else {
        return AccessResult::Success(value);
    };
    let Some((&target, ancestors)) = nodes.split_last() else {
        return AccessResult::Success(value);
    };
    let decided = scope
        .decide_from_above(fc, item_id, ancestors, target)
        .unwrap_or_else(|| scope.apply(target, fc, item_id, value));
    match decided {
        Ok(v) => AccessResult::Success(v),
        Err(e) => AccessResult::Failure(e),
    }
}

/// Why an expansion stopped short.
enum Halt {
    /// The response no longer fits the negotiated PDU size.
    OverBudget,
    /// A read handler refused a part of the value.
    Refused(DataAccessError),
}

impl Halt {
    fn into_lookup(self) -> LookupResult {
        match self {
            Halt::OverBudget => LookupResult::OverBudget,
            Halt::Refused(e) => LookupResult::Result(AccessResult::Failure(e)),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Budget tracking
// ─────────────────────────────────────────────────────────────────────────────

/// Bytes held back from the negotiated PDU size to cover encoding overhead the
/// estimate cannot account for exactly.
///
/// The usable budget is the negotiated maximum less this reserve and less the
/// ReadResponse frame; what remains bounds the sum of the access results.
pub const PDU_OVERHEAD_RESERVE: usize = 16;

/// Bytes a ReadResponse spends outside the list of access results.
///
/// The frame is the outer confirmed-response PDU (`0xa1`), the invoke id
/// (`0x02`, at most 6 bytes), the read service tag (`0xa4`), and the
/// listOfAccessResult tag (`0xa1`). Estimating each length in its long form
/// (`0x82` plus two bytes) gives 12 bytes of length, 4 of tag, and at most 6 of
/// invoke id, so 24 leaves a small margin over the 22-byte worst case.
const READ_RESPONSE_FRAME_OVERHEAD: usize = 24;

/// Result of a read lookup: either an access result, or the signal that the
/// response no longer fits.
///
/// Exceeding the negotiated maximum PDU size replaces the whole response with a
/// resource ServiceError, not an individual failure entry, so the two cases
/// cannot share one return type.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum LookupResult {
    /// A value, or an ordinary failure such as object-non-existent or
    /// type-inconsistent.
    Result(AccessResult),
    /// The budget ran out during expansion; the caller answers the whole
    /// request with `ServiceError(Resource(0))`.
    OverBudget,
}

/// Byte budget consumed during traversal; running past zero latches
/// `exceeded`.
struct BudgetGuard {
    /// Bytes still available. `None` means unbounded, which is the case before
    /// the association has negotiated a PDU size or when the caller passes no
    /// budget.
    remaining: Option<usize>,
    exceeded: bool,
}

impl BudgetGuard {
    fn new(budget: Option<usize>) -> Self {
        Self {
            remaining: budget,
            exceeded: false,
        }
    }

    /// Deducts `n` bytes, returning false and latching `exceeded` if the budget
    /// is already spent or `n` would overrun it.
    fn consume(&mut self, n: usize) -> bool {
        if self.exceeded {
            return false;
        }
        match self.remaining.as_mut() {
            None => true,
            Some(r) => {
                if *r < n {
                    self.exceeded = true;
                    false
                } else {
                    *r -= n;
                    true
                }
            }
        }
    }

    /// Charges `actual` bytes for a value whose first form was charged as
    /// `charged` bytes: the difference is deducted, or given back when the
    /// value shrank. Returns false, latching `exceeded`, when it no longer
    /// fits.
    fn recharge(&mut self, charged: usize, actual: usize) -> bool {
        if actual >= charged {
            return self.consume(actual - charged);
        }
        if let Some(r) = self.remaining.as_mut() {
            *r += charged - actual;
        }
        true
    }

    fn is_over(&self) -> bool {
        self.exceeded
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Logical node and functional-constraint group expansion
// ─────────────────────────────────────────────────────────────────────────────

/// Snapshots a data attribute as wire data and charges its size to the budget.
///
/// `None` means the budget is spent and the caller must propagate
/// `OverBudget`.
fn da_to_mms_data_with_budget(
    da: &iec61850_model::DataAttribute,
    budget: &mut BudgetGuard,
) -> Option<MmsData> {
    let value = da.snapshot();
    let data = mms_value_to_mms_data(&value);
    if !budget.consume(data.estimated_encoded_size()) {
        return None;
    }
    Some(data)
}

/// Expands every data attribute of a data object under one functional
/// constraint into a structure, descending recursively through sub-objects as
/// the MMS structure mapping requires.
///
/// `Ok(None)` means the constraint selects nothing in this object, whether
/// because no attribute carries it or because the sub-object tree is empty.
/// `Err(())` means the budget ran out.
fn expand_do_for_fc(
    do_node: &iec61850_model::DataObject,
    fc: FC,
    budget: &mut BudgetGuard,
) -> Result<Option<MmsData>, ()> {
    let mut children = Vec::new();
    for child in &do_node.children {
        match child {
            DoChild::Da(da) if da.fc == fc => {
                let data = match da_to_mms_data_with_budget(da, budget) {
                    Some(d) => d,
                    None => return Err(()),
                };
                children.push(data);
            }
            DoChild::Da(_) => {
                // A different functional constraint; not part of this group.
            }
            DoChild::SubDo(sub) => {
                match expand_do_for_fc(sub, fc, budget)? {
                    Some(sd) => children.push(sd),
                    None => {
                        // The sub-object selects nothing under this constraint,
                        // so it contributes no member.
                    }
                }
            }
        }
    }
    if children.is_empty() {
        return Ok(None);
    }
    let st = MmsData::Structure(children);
    // The children are already charged; only the wrapping tag and length of
    // the structure itself remain.
    let outer = st.estimated_encoded_size() - children_inner_size_sum(&st);
    if !budget.consume(outer) {
        return Err(());
    }
    Ok(Some(st))
}

/// Sums the encoded size of the members of a structure or array, which the
/// expansion has already charged to the budget.
///
/// Subtracting this from the total gives the wrapping tag and length bytes,
/// which are the only part still to be charged.
fn children_inner_size_sum(data: &MmsData) -> usize {
    match data {
        MmsData::Structure(items) | MmsData::Array(items) => {
            items.iter().map(|i| i.estimated_encoded_size()).sum()
        }
        _ => 0,
    }
}

/// Expands every data object of a logical node under one functional constraint
/// into a structure, after the `lead` members, passing each data object through
/// the read handlers of `scope`.
///
/// Per IEC 61850-8-1 each functional-constraint group is a structure whose
/// members are themselves structures, one per data object; a control block of
/// the group, which the caller supplies in `lead` and has already charged to
/// the budget, comes first. `Ok(None)` means the group is empty for this node.
fn expand_ln_for_fc(
    ln: &LogicalNode,
    fc: FC,
    lead: Vec<MmsData>,
    scope: &ReadHandlerScope,
    budget: &mut BudgetGuard,
) -> Result<Option<MmsData>, Halt> {
    let group_path = (!scope.is_empty()).then(|| format!("{}${}", ln.full_name(), fc.as_str()));
    let mut do_groups = lead;
    for d in &ln.dos {
        let Some(mut do_struct) = expand_do_for_fc(d, fc, budget).map_err(|()| Halt::OverBudget)?
        else {
            continue;
        };
        if let Some(group_path) = &group_path {
            let do_path = format!("{group_path}${}", d.name);
            if scope.reaches(&do_path) {
                let charged = do_struct.estimated_encoded_size();
                do_struct = scope
                    .apply(Node::Object(d), fc, &do_path, do_struct)
                    .map_err(Halt::Refused)?;
                if !budget.recharge(charged, do_struct.estimated_encoded_size()) {
                    return Err(Halt::OverBudget);
                }
            }
        }
        do_groups.push(do_struct);
    }
    if do_groups.is_empty() {
        return Ok(None);
    }
    let st = MmsData::Structure(do_groups);
    let outer = st.estimated_encoded_size() - children_inner_size_sum(&st);
    if !budget.consume(outer) {
        return Err(Halt::OverBudget);
    }
    Ok(Some(st))
}

/// Expands a whole logical node into a structure of its functional-constraint
/// groups, as IEC 61850-8-1 maps a logical node onto an MMS structure.
fn expand_whole_ln(
    ln: &LogicalNode,
    scope: &ReadHandlerScope,
    budget: &mut BudgetGuard,
) -> Result<MmsData, Halt> {
    let mut fc_groups = Vec::new();
    for fc in FC::WIRE_ORDER {
        if let Some(group) = expand_ln_for_fc(ln, fc, Vec::new(), scope, budget)? {
            fc_groups.push(group);
        }
    }
    let st = MmsData::Structure(fc_groups);
    let outer = st.estimated_encoded_size() - children_inner_size_sum(&st);
    if !budget.consume(outer) {
        return Err(Halt::OverBudget);
    }
    Ok(st)
}

// ─────────────────────────────────────────────────────────────────────────────
// Path lookup
// ─────────────────────────────────────────────────────────────────────────────

/// Resolves a domain-specific `item_id` against the model.
///
/// One segment expands the whole logical node, two expand one
/// functional-constraint group, three expand one data object under that
/// constraint including its sub-objects, and four or more walk the remaining
/// segments through sub-data-objects and then data attributes: the path may
/// stop on a sub-data-object, which expands under the constraint like a data
/// object, or reach a data attribute or sub-attribute, which yields its value.
/// Once the path resolves, the read handlers of `scope` have their say.
fn lookup_domain_specific_value(
    ied_model: &IedModel,
    domain: &str,
    item_id: &str,
    alt_access: Option<&AlternateAccess>,
    scope: &ReadHandlerScope,
    budget: &mut BudgetGuard,
) -> LookupResult {
    let parts: Vec<&str> = item_id.split('$').collect();
    if parts.is_empty() || parts[0].is_empty() {
        tracing::warn!(domain = domain, item_id = item_id, "read: empty item id");
        return LookupResult::Result(AccessResult::Failure(DataAccessError::ObjectNonExistent));
    }

    // Alternate access is only meaningful when the path ends at a data
    // attribute whose value materializes as an array, which needs four or more
    // segments. An expansion covering a whole node, group, or object has no
    // array shape to index into, so it is rejected here; a longer path that
    // still ends on a sub-data-object is rejected the same way once the descent
    // below has established where it lands.
    let is_da_path = parts.len() >= 4;
    if alt_access.is_some() && !is_da_path {
        tracing::warn!(
            domain = domain,
            item_id = item_id,
            "alternate-access on a path that expands a node, group or object, answering type-inconsistent"
        );
        return LookupResult::Result(AccessResult::Failure(DataAccessError::TypeInconsistent));
    }

    let ln_name = parts[0];

    let ld = match ied_model.ld_by_domain(domain) {
        Some(ld) => ld,
        None => {
            tracing::warn!(domain = domain, "read: no such domain");
            return LookupResult::Result(AccessResult::Failure(DataAccessError::ObjectNonExistent));
        }
    };

    let ln = match ld.ln_by_name(ln_name) {
        Some(ln) => ln,
        None => {
            tracing::warn!(domain = domain, ln = ln_name, "read: no such logical node");
            return LookupResult::Result(AccessResult::Failure(DataAccessError::ObjectNonExistent));
        }
    };

    // ── One segment: the whole logical node ─────────────────────────
    if parts.len() == 1 {
        return match expand_whole_ln(ln, scope, budget) {
            Ok(st) => LookupResult::Result(AccessResult::Success(st)),
            Err(halt) => halt.into_lookup(),
        };
    }

    let fc_str = parts[1];
    let target_fc = match FC::parse(fc_str) {
        Ok(f) => f,
        Err(_) => {
            tracing::warn!(
                domain = domain,
                ln = ln_name,
                fc = fc_str,
                "read: not a functional-constraint name"
            );
            return LookupResult::Result(AccessResult::Failure(DataAccessError::ObjectNonExistent));
        }
    };

    // ── Two segments: one functional-constraint group ───────────────
    if parts.len() == 2 {
        return match expand_ln_for_fc(ln, target_fc, Vec::new(), scope, budget) {
            Ok(Some(st)) => LookupResult::Result(AccessResult::Success(st)),
            Ok(None) => {
                tracing::warn!(
                    domain = domain,
                    ln = ln_name,
                    fc = fc_str,
                    "read: the logical node has no attribute under this functional constraint"
                );
                LookupResult::Result(AccessResult::Failure(DataAccessError::ObjectNonExistent))
            }
            Err(halt) => halt.into_lookup(),
        };
    }

    let do_name = parts[2];

    let do_node = match ln.do_by_name(do_name) {
        Some(d) => d,
        None => {
            tracing::warn!(
                domain = domain,
                ln = ln_name,
                do_name = do_name,
                "read: no such data object"
            );
            return LookupResult::Result(AccessResult::Failure(DataAccessError::ObjectNonExistent));
        }
    };

    // ── Three segments: one data object, sub-objects included ───────
    if parts.len() == 3 {
        return match expand_do_for_fc(do_node, target_fc, budget) {
            Ok(Some(st)) => {
                let charged = st.estimated_encoded_size();
                let decided = scope.apply(Node::Object(do_node), target_fc, item_id, st);
                charged_verdict(decided, charged, budget)
            }
            Ok(None) => {
                tracing::warn!(
                    domain = domain,
                    item_id = item_id,
                    "read: the data object has no attribute under this functional constraint"
                );
                LookupResult::Result(AccessResult::Failure(DataAccessError::ObjectNonExistent))
            }
            Err(()) => {
                debug_assert!(budget.is_over());
                LookupResult::OverBudget
            }
        };
    }

    // ── Four or more segments: cross sub-objects, then attributes ───
    // A sub-data-object may nest to any depth before the path reaches a data
    // attribute, as WYE holds CMV in IEC 61850-7-3. The walk is iterative, and
    // the segment count is bounded by the MMS identifier length, so no path
    // can drive the descent past the model's own depth. A data attribute
    // belongs to the path only under its own functional constraint, as
    // IEC 61850-8-1 groups the named variables of a logical node by it.
    let mut current_do = do_node;
    let mut next = 3;
    let mut reached_da: Option<&DataAttribute> = None;
    // The nodes above the target, the data object first.
    let mut ancestors: Vec<Node<'_>> = vec![Node::Object(do_node)];
    while next < parts.len() {
        let step = parts[next];
        let child = current_do.children.iter().find(|c| match c {
            DoChild::SubDo(sub) => sub.name == step,
            DoChild::Da(da) => da.name == step && da.fc == target_fc,
        });
        match child {
            Some(DoChild::SubDo(sub)) => {
                current_do = sub;
                next += 1;
                if next < parts.len() {
                    ancestors.push(Node::Object(sub));
                }
            }
            Some(DoChild::Da(da)) => {
                reached_da = Some(da);
                next += 1;
                break;
            }
            None => {
                tracing::warn!(
                    domain = domain,
                    ln = ln_name,
                    item_id = item_id,
                    step = parts[next],
                    "read: no such data object child"
                );
                return LookupResult::Result(AccessResult::Failure(
                    DataAccessError::ObjectNonExistent,
                ));
            }
        }
    }

    let da = match reached_da {
        Some(da) => da,
        None => {
            // The path stops on a sub-data-object, which expands under the
            // constraint exactly as a data object does. It carries no array
            // shape, so alternate access cannot apply to it.
            if alt_access.is_some() {
                tracing::warn!(
                    domain = domain,
                    item_id = item_id,
                    "alternate-access on a path that expands a sub-data-object, answering type-inconsistent"
                );
                return LookupResult::Result(AccessResult::Failure(
                    DataAccessError::TypeInconsistent,
                ));
            }
            let target = Node::Object(current_do);
            if let Some(decided) = scope.decide_from_above(target_fc, item_id, &ancestors, target) {
                return charged_verdict(decided, 0, budget);
            }
            return match expand_do_for_fc(current_do, target_fc, budget) {
                Ok(Some(st)) => {
                    let charged = st.estimated_encoded_size();
                    charged_verdict(scope.apply(target, target_fc, item_id, st), charged, budget)
                }
                Ok(None) => {
                    tracing::warn!(
                        domain = domain,
                        item_id = item_id,
                        "read: the sub-data-object has no attribute under this functional constraint"
                    );
                    LookupResult::Result(AccessResult::Failure(DataAccessError::ObjectNonExistent))
                }
                Err(()) => {
                    debug_assert!(budget.is_over());
                    LookupResult::OverBudget
                }
            };
        }
    };

    let mut current_da = da;
    for sda_name in &parts[next..] {
        ancestors.push(Node::Attribute(current_da));
        current_da = match current_da.child_by_name(sda_name) {
            Some(c) => c,
            None => {
                tracing::warn!(
                    domain = domain,
                    item_id = item_id,
                    sda = sda_name,
                    "read: no such sub-attribute"
                );
                return LookupResult::Result(AccessResult::Failure(
                    DataAccessError::ObjectNonExistent,
                ));
            }
        };
    }

    let target = Node::Attribute(current_da);
    let access = if scope.is_empty() {
        let value = current_da.snapshot();
        match alt_access {
            None => AccessResult::Success(mms_value_to_mms_data(&value)),
            Some(alt) => apply_alt_access_typed(current_da, &value, alt),
        }
    } else {
        // The handlers decide the whole attribute; an alternate access then
        // selects from what they decided.
        let decided = scope
            .decide_from_above(target_fc, item_id, &ancestors, target)
            .unwrap_or_else(|| {
                let value = mms_value_to_mms_data(&current_da.snapshot());
                scope.apply(target, target_fc, item_id, value)
            });
        match (decided, alt_access) {
            (Err(e), _) => AccessResult::Failure(e),
            (Ok(data), None) => AccessResult::Success(data),
            (Ok(data), Some(alt)) => {
                apply_alt_access_typed(current_da, &mms_data_to_mms_value(&data), alt)
            }
        }
    };
    if let AccessResult::Success(ref data) = access {
        if !budget.consume(data.estimated_encoded_size()) {
            return LookupResult::OverBudget;
        }
    }
    LookupResult::Result(access)
}

/// Turns the verdict of the read handlers into a lookup result, charging the
/// decided value to the budget in place of the `charged` bytes its model
/// value already cost.
fn charged_verdict(
    decided: Result<MmsData, DataAccessError>,
    charged: usize,
    budget: &mut BudgetGuard,
) -> LookupResult {
    match decided {
        Ok(data) => {
            if !budget.recharge(charged, data.estimated_encoded_size()) {
                return LookupResult::OverBudget;
            }
            LookupResult::Result(AccessResult::Success(data))
        }
        Err(e) => LookupResult::Result(AccessResult::Failure(e)),
    }
}

/// The members a group of a logical node holds ahead of its data objects, such
/// as the control blocks of the group: `Ok` with the values in order, possibly
/// none, or the error that fails the whole read.
#[cfg(any(
    feature = "reporting",
    feature = "logging",
    feature = "setting-groups",
    feature = "goose-mapping"
))]
pub(crate) type LeadingMembers<'a> =
    dyn FnMut(&LogicalNode, FC) -> Result<Vec<MmsData>, DataAccessError> + 'a;

/// Reads a whole logical node, `LN`, or one of its functional-constraint
/// groups, `LN$FC`, with the members `leading` supplies placed ahead of the
/// data objects of each group.
///
/// The value follows the structure GetVariableAccessAttributes describes for
/// the same name once the control blocks of the node are merged into it: a
/// group appears when it has a leading member or a data object, in the
/// IEC 61850-8-1 order. `None` means `item_id` names something below a group,
/// which the caller reads by its own route. The leading members are charged to
/// the budget like the rest of the value. Each data object passes through the
/// read handlers of `handlers` that sit on it or below it.
#[cfg(any(
    feature = "reporting",
    feature = "logging",
    feature = "setting-groups",
    feature = "goose-mapping"
))]
pub(crate) fn read_ln_with_leading_members(
    ied_model: &IedModel,
    domain: &str,
    item_id: &str,
    leading: &mut LeadingMembers<'_>,
    handlers: Option<(&HandlerRegistry, u64)>,
    budget: Option<usize>,
) -> Option<LookupResult> {
    let mut parts = item_id.split('$');
    let ln_name = parts.next()?;
    let fc_name = parts.next();
    if parts.next().is_some() || ln_name.is_empty() {
        return None;
    }
    let not_found =
        || LookupResult::Result(AccessResult::Failure(DataAccessError::ObjectNonExistent));
    let Some(ln) = ied_model
        .ld_by_domain(domain)
        .and_then(|ld| ld.ln_by_name(ln_name))
    else {
        tracing::warn!(domain, ln = ln_name, "read: no such logical node");
        return Some(not_found());
    };

    let scope = match handlers {
        Some((registry, conn_id)) => ReadHandlerScope::around(registry, item_id, conn_id),
        None => ReadHandlerScope::none(),
    };
    let mut guard = BudgetGuard::new(budget);
    let mut group = |fc: FC, guard: &mut BudgetGuard| -> Result<Option<MmsData>, LookupResult> {
        let lead = leading(ln, fc).map_err(|e| LookupResult::Result(AccessResult::Failure(e)))?;
        for member in &lead {
            if !guard.consume(member.estimated_encoded_size()) {
                return Err(LookupResult::OverBudget);
            }
        }
        expand_ln_for_fc(ln, fc, lead, &scope, guard).map_err(Halt::into_lookup)
    };

    let Some(fc_name) = fc_name else {
        let mut fc_groups = Vec::new();
        for fc in FC::WIRE_ORDER {
            match group(fc, &mut guard) {
                Ok(Some(g)) => fc_groups.push(g),
                Ok(None) => {}
                Err(r) => return Some(r),
            }
        }
        let st = MmsData::Structure(fc_groups);
        let outer = st.estimated_encoded_size() - children_inner_size_sum(&st);
        if !guard.consume(outer) {
            return Some(LookupResult::OverBudget);
        }
        return Some(LookupResult::Result(AccessResult::Success(st)));
    };

    let Ok(fc) = FC::parse(fc_name) else {
        tracing::warn!(
            domain,
            ln = ln_name,
            fc = fc_name,
            "read: not a functional-constraint name"
        );
        return Some(not_found());
    };
    Some(match group(fc, &mut guard) {
        Ok(Some(g)) => LookupResult::Result(AccessResult::Success(g)),
        Ok(None) => {
            tracing::warn!(
                domain,
                ln = ln_name,
                fc = fc_name,
                "read: the logical node has nothing under this functional constraint"
            );
            not_found()
        }
        Err(r) => r,
    })
}

/// Reads one object name with no PDU size limit.
///
/// Expansion still happens in full; nothing short-circuits. Only a
/// domain-specific object name is served: vmd-specific and aa-specific names
/// yield object-access-unsupported.
pub fn handle_single_read(
    ied_model: &IedModel,
    _mms_model: &MmsDeviceModel,
    name: &ObjectName,
) -> AccessResult {
    match handle_single_read_with_budget(ied_model, _mms_model, name, None, None) {
        LookupResult::Result(r) => r,
        // Unreachable: with no budget the guard never latches `exceeded`.
        LookupResult::OverBudget => {
            tracing::warn!("read: budget exceeded although no budget was set");
            AccessResult::Failure(DataAccessError::ObjectAccessUnsupported)
        }
    }
}

/// Reads one object name under a PDU byte budget.
///
/// `budget` bounds the bytes this access result may occupy inside the list of
/// access results; `None` leaves it unbounded. On
/// [`LookupResult::OverBudget`] the caller replaces the whole ReadResponse with
/// `ServiceError(Resource(0))`, as IEC 61850-8-1 requires.
///
/// No read handler is consulted.
pub fn handle_single_read_with_budget(
    ied_model: &IedModel,
    _mms_model: &MmsDeviceModel,
    name: &ObjectName,
    alt_access: Option<&AlternateAccess>,
    budget: Option<usize>,
) -> LookupResult {
    read_with_handlers(ied_model, name, alt_access, budget, None)
}

/// Reads one object name under a PDU byte budget, as the Read service does:
/// once the path resolves, the read handlers of `handlers` that bear on it
/// have their say on the association `conn_id`, per the module rules.
pub(crate) fn read_with_handlers(
    ied_model: &IedModel,
    name: &ObjectName,
    alt_access: Option<&AlternateAccess>,
    budget: Option<usize>,
    handlers: Option<(&HandlerRegistry, u64)>,
) -> LookupResult {
    let mut guard = BudgetGuard::new(budget);
    match name {
        ObjectName::DomainSpecific { domain_id, item_id } => {
            let scope = match handlers {
                Some((registry, conn_id)) => ReadHandlerScope::around(registry, item_id, conn_id),
                None => ReadHandlerScope::none(),
            };
            lookup_domain_specific_value(
                ied_model, domain_id, item_id, alt_access, &scope, &mut guard,
            )
        }
        ObjectName::VmdSpecific(n) => {
            tracing::warn!(name = n, "read: vmd-specific object names are not served");
            LookupResult::Result(AccessResult::Failure(
                DataAccessError::ObjectAccessUnsupported,
            ))
        }
        ObjectName::AaSpecific(n) => {
            tracing::warn!(name = n, "read: aa-specific object names are not served");
            LookupResult::Result(AccessResult::Failure(
                DataAccessError::ObjectAccessUnsupported,
            ))
        }
    }
}

/// Computes the bytes available to the list of access results.
///
/// A `None` negotiated size means the association has not finished negotiating
/// or imposes no limit, and yields `None`, which reads without a budget.
pub fn pdu_budget_for_access_results(negotiated_max_pdu_size: Option<u32>) -> Option<usize> {
    let max = negotiated_max_pdu_size? as usize;
    let usable = max
        .saturating_sub(PDU_OVERHEAD_RESERVE)
        .saturating_sub(READ_RESPONSE_FRAME_OVERHEAD);
    Some(usable)
}

// ─────────────────────────────────────────────────────────────────────────────
// AlternateAccess post-processing
// ─────────────────────────────────────────────────────────────────────────────

/// Apply an `AlternateAccess` selector to an `AccessResult` produced by the
/// regular read pipeline.
///
/// - `Failure(_)` is returned unchanged: the underlying lookup already
///   produced a definitive error.
/// - `Success(MmsData::Array(items))` indexes into `items[index]`. If a
///   component path is supplied, it is walked against the selected element
///   (expected to be `MmsData::Structure`).
/// - `Success(_)` for any non-array value yields `TypeInconsistent`: the
///   client requested element access against a target that is not an array
///   under the current model.
///
/// Out-of-range indices yield `TypeInconsistent`; unknown component segments
/// yield `ObjectNonExistent`.
pub fn apply_alt_access(result: AccessResult, alt: &AlternateAccess) -> AccessResult {
    let data = match result {
        AccessResult::Success(d) => d,
        failure @ AccessResult::Failure(_) => return failure,
    };
    match &alt.selector {
        AlternateAccessSelector::Index(idx) => match select_array_index(data, *idx) {
            Ok(elem) => AccessResult::Success(elem),
            Err(e) => AccessResult::Failure(e),
        },
        AlternateAccessSelector::IndexComponent { index, component } => {
            let elem = match select_array_index(data, *index) {
                Ok(d) => d,
                Err(e) => return AccessResult::Failure(e),
            };
            match select_component_path(elem, component) {
                Ok(d) => AccessResult::Success(d),
                Err(e) => AccessResult::Failure(e),
            }
        }
        _ => {
            tracing::warn!(
                "alternate-access: only an index selection applies here; leading components are resolved by name before the read"
            );
            AccessResult::Failure(DataAccessError::ObjectAccessUnsupported)
        }
    }
}

fn select_array_index(data: MmsData, index: u32) -> Result<MmsData, DataAccessError> {
    match data {
        MmsData::Array(mut items) => {
            let i = index as usize;
            if i >= items.len() {
                tracing::warn!(
                    index,
                    array_len = items.len(),
                    "alternate-access: index out of range"
                );
                return Err(DataAccessError::TypeInconsistent);
            }
            Ok(items.swap_remove(i))
        }
        other => {
            tracing::warn!(
                got = ?other,
                "alternate-access: index applied to a non-array value"
            );
            Err(DataAccessError::TypeInconsistent)
        }
    }
}

/// Apply an `AlternateAccess` selector against the model-typed `DataAttribute`
/// reached by the read lookup, using the DA's child template to map component
/// names to ordinal positions inside the per-element `MmsValue::Structure`.
///
/// Contract:
/// - `value` must be a snapshot of `da.value` taken under the same RwLock
///   guard the caller has already released; passing both avoids taking the
///   lock a second time.
/// - If `value` is not `MmsValue::Array`, AlternateAccess is rejected with
///   `TypeInconsistent`, so a client sees one consistent outcome for element
///   access on a non-array.
/// - `IndexComponent { component }` requires the selected element to be a
///   `MmsValue::Structure` whose ordinal layout matches `da.children`. Each
///   `$`-separated segment is looked up by name in the current template
///   slice; a match descends into the corresponding field of the value tree,
///   and into that child's `children` for the next segment.
///
/// Failure mapping:
/// - Index out of range → `TypeInconsistent` (consistent with
///   `apply_alt_access`).
/// - Component descends into a non-Structure → `ObjectAccessUnsupported`.
/// - Component name not in the template → `ObjectNonExistent`.
/// - Template/value ordinal mismatch (corrupt model) → `TypeInconsistent`.
pub fn apply_alt_access_typed(
    da: &DataAttribute,
    value: &MmsValue,
    alt: &AlternateAccess,
) -> AccessResult {
    let elems = match value {
        MmsValue::Array(items) => items.as_slice(),
        other => {
            tracing::warn!(
                da = %da.name,
                got = other.type_name(),
                "alternate-access: the target data attribute is not an array"
            );
            return AccessResult::Failure(DataAccessError::TypeInconsistent);
        }
    };
    let (index, component_opt) = match &alt.selector {
        AlternateAccessSelector::Index(i) => (*i, None),
        AlternateAccessSelector::IndexComponent { index, component } => {
            (*index, Some(component.as_str()))
        }
        _ => {
            tracing::warn!(
                da = %da.name,
                "alternate-access: only an index selection applies here; leading components are resolved by name before the read"
            );
            return AccessResult::Failure(DataAccessError::ObjectAccessUnsupported);
        }
    };
    let i = index as usize;
    if i >= elems.len() {
        tracing::warn!(
            da = %da.name,
            index,
            array_len = elems.len(),
            "alternate-access: index out of range"
        );
        return AccessResult::Failure(DataAccessError::TypeInconsistent);
    }
    let element = &elems[i];
    let leaf = match component_opt {
        None => element.clone(),
        Some(component) => match walk_component_path(da.children.as_slice(), element, component) {
            Ok(v) => v,
            Err(e) => return AccessResult::Failure(e),
        },
    };
    AccessResult::Success(mms_value_to_mms_data(&leaf))
}

/// Walk a `$`-separated component path against a value tree, using a parallel
/// template slice to resolve names to ordinal positions inside the value's
/// `MmsValue::Structure`. Returns the leaf value at the end of the path.
fn walk_component_path(
    template: &[DataAttribute],
    value: &MmsValue,
    component: &str,
) -> Result<MmsValue, DataAccessError> {
    let mut current_value: &MmsValue = value;
    let mut current_template: &[DataAttribute] = template;
    for seg in component.split('$') {
        let fields = match current_value {
            MmsValue::Structure(items) => items.as_slice(),
            other => {
                tracing::warn!(
                    seg = %seg,
                    got = other.type_name(),
                    "alternate-access component: cannot descend into a non-structure value"
                );
                return Err(DataAccessError::ObjectAccessUnsupported);
            }
        };
        let ord = match current_template.iter().position(|c| c.name == seg) {
            Some(p) => p,
            None => {
                tracing::warn!(
                    seg = %seg,
                    "alternate-access component: name not found in the template"
                );
                return Err(DataAccessError::ObjectNonExistent);
            }
        };
        if ord >= fields.len() {
            tracing::warn!(
                seg = %seg,
                ord,
                fields_len = fields.len(),
                "alternate-access component: template and value disagree on ordinal layout"
            );
            return Err(DataAccessError::TypeInconsistent);
        }
        current_value = &fields[ord];
        current_template = current_template[ord].children.as_slice();
    }
    Ok(current_value.clone())
}

fn select_component_path(data: MmsData, component_path: &str) -> Result<MmsData, DataAccessError> {
    // The wire representation carries no component names alongside the members
    // of a structure, so a named segment cannot be resolved to an ordinal here.
    // Resolving it safely would need a parallel name list from the model, so
    // the request is rejected instead.
    let _ = component_path;
    let _ = data;
    tracing::warn!(
        "alternate-access: a component path against a structure value is not supported yet \
         (Structure encoding does not carry field names)"
    );
    Err(DataAccessError::ObjectAccessUnsupported)
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use iec61850_model::{
        DataAttribute, DataAttributeType, DataObject, DoChild, IedModelBuilder,
        LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, TrgOps, FC,
    };

    fn build_test_model() -> (iec61850_model::IedModel, MmsDeviceModel) {
        // MMXU1.TotW.mag (MX, Float32, initial=1.23)
        let mag_da = DataAttribute::new(
            "mag",
            FC::Mx,
            DataAttributeType::Float32,
            TrgOps::default(),
            MmsValue::Float32(1.23),
        );
        let totw_do = DataObject::new("TotW", vec![DoChild::Da(mag_da)]);
        let mmxu_ln = iec61850_model::LogicalNode::new(String::new(), "MMXU", "1", vec![totw_do]);
        let lln0 = LogicalNodeBuilder::lln0().build().unwrap();
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(lln0)
            .add_ln(mmxu_ln)
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

    // ── Happy path: reading a data attribute ────────────────────────────

    #[test]
    fn read_da_returns_correct_value() {
        let (model, mms_model) = build_test_model();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "MMXU1$MX$TotW$mag".to_string(),
        };
        let result = handle_single_read(&model, &mms_model, &name);
        match result {
            AccessResult::Success(data) => match data {
                iec61850_mms::mms::pdu::common::MmsData::Float32(v) => {
                    assert!((v - 1.23f32).abs() < f32::EPSILON);
                }
                other => panic!("expected a float32, got {:?}", other),
            },
            AccessResult::Failure(e) => panic!("expected success, got a failure: {:?}", e),
        }
    }

    #[test]
    fn read_do_returns_structure() {
        let (model, mms_model) = build_test_model();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "MMXU1$MX$TotW".to_string(),
        };
        let result = handle_single_read(&model, &mms_model, &name);
        match result {
            AccessResult::Success(data) => match data {
                iec61850_mms::mms::pdu::common::MmsData::Structure(_) => {}
                other => panic!("expected a structure, got {:?}", other),
            },
            AccessResult::Failure(e) => panic!("expected success, got a failure: {:?}", e),
        }
    }

    // ── Constructed data attributes, such as mag.f of an MV ─────────────

    /// Mirrors the shape of the MV common data class: TotW.mag is a constructed
    /// attribute and only the leaf f carries the float.
    fn build_constructed_model() -> (iec61850_model::IedModel, MmsDeviceModel) {
        let f_da = DataAttribute::new(
            "f",
            FC::Mx,
            DataAttributeType::Float32,
            TrgOps::default(),
            MmsValue::Float32(3.5),
        );
        let mag_da = DataAttribute::constructed("mag", FC::Mx, vec![f_da]);
        let totw_do = DataObject::new("TotW", vec![DoChild::Da(mag_da)]);
        let mmxu_ln = iec61850_model::LogicalNode::new(String::new(), "MMXU", "1", vec![totw_do]);
        let lln0 = LogicalNodeBuilder::lln0().build().unwrap();
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(lln0)
            .add_ln(mmxu_ln)
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

    /// Expanding a functional-constraint group must compose a constructed
    /// attribute into a nested structure carrying its leaf values, not an empty
    /// structure: an empty one leaves the leaves of the client's object tree
    /// without values, which model-driven clients do not survive.
    #[test]
    fn read_fc_group_composes_constructed_da() {
        let (model, mms_model) = build_constructed_model();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "MMXU1$MX".to_string(),
        };
        let result = handle_single_read(&model, &mms_model, &name);
        // FC group → [DO TotW] → [DA mag] → [SDA f]
        let expect = iec61850_mms::mms::pdu::common::MmsData::Structure(vec![
            iec61850_mms::mms::pdu::common::MmsData::Structure(vec![
                iec61850_mms::mms::pdu::common::MmsData::Structure(vec![
                    iec61850_mms::mms::pdu::common::MmsData::Float32(3.5),
                ]),
            ]),
        ]);
        match result {
            AccessResult::Success(data) => assert_eq!(data, expect),
            AccessResult::Failure(e) => panic!("expected success, got a failure: {:?}", e),
        }
    }

    /// Reading a constructed attribute directly must compose its leaves too.
    #[test]
    fn read_constructed_da_directly_composes_children() {
        let (model, mms_model) = build_constructed_model();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "MMXU1$MX$TotW$mag".to_string(),
        };
        let result = handle_single_read(&model, &mms_model, &name);
        let expect = iec61850_mms::mms::pdu::common::MmsData::Structure(vec![
            iec61850_mms::mms::pdu::common::MmsData::Float32(3.5),
        ]);
        match result {
            AccessResult::Success(data) => assert_eq!(data, expect),
            AccessResult::Failure(e) => panic!("expected success, got a failure: {:?}", e),
        }
    }

    // ── Sub-data-objects, such as the phases of a WYE ───────────────────

    /// Wraps one data object into `IED1LD0/MMXU1` and maps the result, so a
    /// test only has to describe the object tree it cares about.
    fn build_model_around(do_node: DataObject) -> (iec61850_model::IedModel, MmsDeviceModel) {
        let mmxu_ln = iec61850_model::LogicalNode::new(String::new(), "MMXU", "1", vec![do_node]);
        let lln0 = LogicalNodeBuilder::lln0().build().unwrap();
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(lln0)
            .add_ln(mmxu_ln)
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

    /// Mirrors the shape of the WYE common data class of IEC 61850-7-3:
    /// `PhV` holds the sub-data-object `phsA`, a CMV whose `cVal` is a Vector
    /// of two AnalogValue attributes, so a leaf sits four names below the data
    /// object.
    fn build_sdo_model() -> (iec61850_model::IedModel, MmsDeviceModel) {
        let mag = DataAttribute::constructed(
            "mag",
            FC::Mx,
            vec![DataAttribute::new(
                "f",
                FC::Mx,
                DataAttributeType::Float32,
                TrgOps::default(),
                MmsValue::Float32(7.25),
            )],
        );
        let ang = DataAttribute::constructed(
            "ang",
            FC::Mx,
            vec![DataAttribute::new(
                "f",
                FC::Mx,
                DataAttributeType::Float32,
                TrgOps::default(),
                MmsValue::Float32(-1.5),
            )],
        );
        let phs_a = DataObject::new(
            "phsA",
            vec![DoChild::Da(DataAttribute::constructed(
                "cVal",
                FC::Mx,
                vec![mag, ang],
            ))],
        );
        let phv = DataObject::new("PhV", vec![DoChild::SubDo(phs_a)]);
        build_model_around(phv)
    }

    /// A leaf reached across a sub-data-object boundary yields its value, so a
    /// client may address one phase of a WYE without reading the whole object.
    #[test]
    fn read_descends_through_a_sub_data_object_to_a_leaf() {
        let (model, mms_model) = build_sdo_model();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "MMXU1$MX$PhV$phsA$cVal$mag$f".to_string(),
        };
        match handle_single_read(&model, &mms_model, &name) {
            AccessResult::Success(MmsData::Float32(v)) => {
                assert!((v - 7.25f32).abs() < f32::EPSILON, "got {v}");
            }
            other => panic!("expected the float leaf, got {:?}", other),
        }
    }

    /// A path that stops on a sub-data-object expands it under the constraint,
    /// exactly as a data object path does one level higher.
    #[test]
    fn read_of_a_sub_data_object_expands_it_under_the_constraint() {
        let (model, mms_model) = build_sdo_model();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "MMXU1$MX$PhV$phsA".to_string(),
        };
        // phsA holds cVal, which holds mag and ang, each holding the leaf f.
        let expect = MmsData::Structure(vec![MmsData::Structure(vec![
            MmsData::Structure(vec![MmsData::Float32(7.25)]),
            MmsData::Structure(vec![MmsData::Float32(-1.5)]),
        ])]);
        match handle_single_read(&model, &mms_model, &name) {
            AccessResult::Success(data) => assert_eq!(data, expect),
            other => panic!("expected the expanded sub-data-object, got {:?}", other),
        }
    }

    /// The whole data object holds the same values as the sub-object path, so
    /// the two levels cannot disagree.
    #[test]
    fn read_of_the_whole_data_object_agrees_with_the_sub_object_path() {
        let (model, mms_model) = build_sdo_model();
        let whole = handle_single_read(
            &model,
            &mms_model,
            &ObjectName::DomainSpecific {
                domain_id: "IED1LD0".to_string(),
                item_id: "MMXU1$MX$PhV".to_string(),
            },
        );
        let part = handle_single_read(
            &model,
            &mms_model,
            &ObjectName::DomainSpecific {
                domain_id: "IED1LD0".to_string(),
                item_id: "MMXU1$MX$PhV$phsA".to_string(),
            },
        );
        let (AccessResult::Success(whole), AccessResult::Success(part)) = (whole, part) else {
            panic!("both reads must succeed");
        };
        assert_eq!(
            whole,
            MmsData::Structure(vec![part]),
            "PhV must hold exactly its one sub-data-object"
        );
    }

    /// An unknown name under a sub-data-object answers object-non-existent, the
    /// same class as an unknown data attribute one level up.
    #[test]
    fn read_of_an_unknown_name_under_a_sub_data_object_returns_not_found() {
        let (model, mms_model) = build_sdo_model();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "MMXU1$MX$PhV$phsA$nosuchda".to_string(),
        };
        assert!(matches!(
            handle_single_read(&model, &mms_model, &name),
            AccessResult::Failure(DataAccessError::ObjectNonExistent)
        ));
    }

    /// A sub-data-object that holds nothing under the requested constraint
    /// answers object-non-existent rather than an empty structure.
    #[test]
    fn read_of_a_sub_data_object_under_an_empty_constraint_returns_not_found() {
        let (model, mms_model) = build_sdo_model();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "MMXU1$ST$PhV$phsA".to_string(),
        };
        assert!(matches!(
            handle_single_read(&model, &mms_model, &name),
            AccessResult::Failure(DataAccessError::ObjectNonExistent)
        ));
    }

    /// Alternate access needs an array-valued data attribute; a path that ends
    /// on a sub-data-object has no array shape, so it is type-inconsistent, the
    /// same answer a shorter expansion path gets.
    #[test]
    fn alternate_access_on_a_sub_data_object_path_is_type_inconsistent() {
        let (model, mms_model) = build_sdo_model();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "MMXU1$MX$PhV$phsA".to_string(),
        };
        let alt = AlternateAccess {
            selector: AlternateAccessSelector::Index(0),
        };
        assert!(matches!(
            handle_single_read_with_budget(&model, &mms_model, &name, Some(&alt), None),
            LookupResult::Result(AccessResult::Failure(DataAccessError::TypeInconsistent))
        ));
    }

    /// Expanding a sub-data-object charges the budget exactly as expanding a
    /// data object does, so a sub-object that does not fit answers OverBudget
    /// and the caller replaces the whole response with a resource error.
    #[test]
    fn read_of_a_sub_data_object_too_large_returns_over_budget() {
        let (model, mms_model) = build_sdo_model();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "MMXU1$MX$PhV$phsA".to_string(),
        };
        // A float32 leaf alone needs 7 bytes; 5 cannot hold the phase.
        let result = handle_single_read_with_budget(&model, &mms_model, &name, None, Some(5));
        assert!(
            matches!(result, LookupResult::OverBudget),
            "a 5-byte budget cannot hold the phase, got {:?}",
            result
        );
    }

    /// A budget ample for the phase still answers with its value, so the guard
    /// rejects only what genuinely does not fit.
    #[test]
    fn read_of_a_sub_data_object_with_sufficient_budget_succeeds() {
        let (model, mms_model) = build_sdo_model();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "MMXU1$MX$PhV$phsA".to_string(),
        };
        let result = handle_single_read_with_budget(&model, &mms_model, &name, None, Some(1024));
        assert!(
            matches!(
                result,
                LookupResult::Result(AccessResult::Success(MmsData::Structure(_)))
            ),
            "got {:?}",
            result
        );
    }

    /// Builds a sub-object chain `S0.S1....Sdepth.v` whose only leaf is a float.
    fn build_sdo_chain(depth: usize) -> (iec61850_model::IedModel, MmsDeviceModel) {
        let mut node = DataObject::new(
            format!("S{depth}"),
            vec![DoChild::Da(DataAttribute::new(
                "v",
                FC::Mx,
                DataAttributeType::Float32,
                TrgOps::default(),
                MmsValue::Float32(9.0),
            ))],
        );
        for level in (0..depth).rev() {
            node = DataObject::new(format!("S{level}"), vec![DoChild::SubDo(node)]);
        }
        build_model_around(node)
    }

    /// The descent is iterative and bounded only by the model, so a chain far
    /// deeper than any standard common data class still resolves. The wire
    /// cannot present an unbounded path: an `item_id` is an MMS identifier and
    /// is capped at `MAX_IDENTIFIER_LEN` bytes when it is decoded.
    #[test]
    fn read_descends_a_deep_sub_object_chain_to_its_leaf() {
        const DEPTH: usize = 12;
        let (model, mms_model) = build_sdo_chain(DEPTH);
        let mut item_id = String::from("MMXU1$MX$S0");
        for level in 1..=DEPTH {
            item_id.push_str(&format!("$S{level}"));
        }
        item_id.push_str("$v");
        assert!(
            item_id.len() <= iec61850_mms::mms::pdu::common::MAX_IDENTIFIER_LEN,
            "the probe path must stay a legal MMS identifier, got {} bytes",
            item_id.len()
        );
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id,
        };
        match handle_single_read(&model, &mms_model, &name) {
            AccessResult::Success(MmsData::Float32(v)) => {
                assert!((v - 9.0f32).abs() < f32::EPSILON, "got {v}");
            }
            other => panic!("expected the float leaf of the chain, got {:?}", other),
        }
    }

    /// A path one segment longer than the chain runs past its leaf and answers
    /// object-non-existent instead of descending further.
    #[test]
    fn read_past_the_leaf_of_a_sub_object_chain_returns_not_found() {
        let (model, mms_model) = build_sdo_chain(3);
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "MMXU1$MX$S0$S1$S2$S3$v$more".to_string(),
        };
        assert!(matches!(
            handle_single_read(&model, &mms_model, &name),
            AccessResult::Failure(DataAccessError::ObjectNonExistent)
        ));
    }

    // ── Paths that do not resolve ───────────────────────────────────────

    #[test]
    fn read_nonexistent_domain_returns_not_found() {
        let (model, mms_model) = build_test_model();
        let name = ObjectName::DomainSpecific {
            domain_id: "NOSUCHDOMAIN".to_string(),
            item_id: "MMXU1$MX$TotW$mag".to_string(),
        };
        let result = handle_single_read(&model, &mms_model, &name);
        assert!(matches!(
            result,
            AccessResult::Failure(DataAccessError::ObjectNonExistent)
        ));
    }

    #[test]
    fn read_nonexistent_ln_returns_not_found() {
        let (model, mms_model) = build_test_model();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "NOSUCHLN$MX$TotW$mag".to_string(),
        };
        let result = handle_single_read(&model, &mms_model, &name);
        assert!(matches!(
            result,
            AccessResult::Failure(DataAccessError::ObjectNonExistent)
        ));
    }

    #[test]
    fn read_nonexistent_da_returns_not_found() {
        let (model, mms_model) = build_test_model();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "MMXU1$MX$TotW$nosuchda".to_string(),
        };
        let result = handle_single_read(&model, &mms_model, &name);
        assert!(matches!(
            result,
            AccessResult::Failure(DataAccessError::ObjectNonExistent)
        ));
    }

    // ── One segment expands the whole logical node ──────────────────────

    #[test]
    fn read_whole_ln_returns_nested_structure() {
        let (model, mms_model) = build_test_model();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "MMXU1".to_string(),
        };
        let result = handle_single_read(&model, &mms_model, &name);
        match result {
            AccessResult::Success(MmsData::Structure(fc_groups)) => {
                // MMXU1 carries a single MX attribute, TotW.mag, hence one group.
                assert_eq!(fc_groups.len(), 1, "MMXU1 must expose only the MX group");
                match &fc_groups[0] {
                    MmsData::Structure(do_groups) => {
                        assert_eq!(do_groups.len(), 1, "MX must hold only TotW");
                        match &do_groups[0] {
                            MmsData::Structure(das) => {
                                assert_eq!(das.len(), 1, "TotW must hold only mag under MX");
                                assert!(matches!(das[0], MmsData::Float32(_)));
                            }
                            other => {
                                panic!("a data object group must be a structure, got {:?}", other)
                            }
                        }
                    }
                    other => panic!(
                        "a functional-constraint group must be a structure, got {:?}",
                        other
                    ),
                }
            }
            other => panic!(
                "a whole-LN read must answer with a structure, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn read_ln_fc_group_returns_structure() {
        let (model, mms_model) = build_test_model();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "MMXU1$MX".to_string(),
        };
        let result = handle_single_read(&model, &mms_model, &name);
        match result {
            AccessResult::Success(MmsData::Structure(do_groups)) => {
                assert_eq!(do_groups.len(), 1, "MMXU1$MX must hold one data object");
            }
            other => panic!(
                "an LN$FC read must answer with a structure, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn read_ln_fc_group_no_da_returns_not_found() {
        let (model, mms_model) = build_test_model();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "MMXU1$ST".to_string(), // MMXU1 carries no ST attribute.
        };
        let result = handle_single_read(&model, &mms_model, &name);
        assert!(matches!(
            result,
            AccessResult::Failure(DataAccessError::ObjectNonExistent)
        ));
    }

    #[test]
    fn read_ln_invalid_fc_returns_not_found() {
        let (model, mms_model) = build_test_model();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "MMXU1$XX".to_string(),
        };
        let result = handle_single_read(&model, &mms_model, &name);
        assert!(matches!(
            result,
            AccessResult::Failure(DataAccessError::ObjectNonExistent)
        ));
    }

    // ── Budget guard ────────────────────────────────────────────────────

    #[test]
    fn read_whole_ln_with_sufficient_budget_succeeds() {
        let (model, mms_model) = build_test_model();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "MMXU1".to_string(),
        };
        // A kilobyte is ample for one float32 attribute.
        let result = handle_single_read_with_budget(&model, &mms_model, &name, None, Some(1024));
        assert!(matches!(
            result,
            LookupResult::Result(AccessResult::Success(MmsData::Structure(_)))
        ));
    }

    #[test]
    fn read_whole_ln_too_large_returns_over_budget() {
        let (model, mms_model) = build_test_model();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "MMXU1".to_string(),
        };
        // A float32 attribute needs 7 bytes; 5 cannot hold it.
        let result = handle_single_read_with_budget(&model, &mms_model, &name, None, Some(5));
        assert!(
            matches!(result, LookupResult::OverBudget),
            "a 5-byte budget cannot hold a float32 attribute, got {:?}",
            result
        );
    }

    #[test]
    fn read_ln_fc_group_too_large_returns_over_budget() {
        let (model, mms_model) = build_test_model();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "MMXU1$MX".to_string(),
        };
        let result = handle_single_read_with_budget(&model, &mms_model, &name, None, Some(3));
        assert!(matches!(result, LookupResult::OverBudget));
    }

    #[test]
    fn read_single_da_too_large_returns_over_budget() {
        let (model, mms_model) = build_test_model();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "MMXU1$MX$TotW$mag".to_string(),
        };
        // A float32 attribute needs 7 bytes; 5 cannot hold it.
        let result = handle_single_read_with_budget(&model, &mms_model, &name, None, Some(5));
        assert!(matches!(result, LookupResult::OverBudget));
    }

    #[test]
    fn pdu_budget_returns_none_when_negotiation_missing() {
        assert_eq!(pdu_budget_for_access_results(None), None);
    }

    #[test]
    fn pdu_budget_subtracts_overhead_and_frame() {
        let budget = pdu_budget_for_access_results(Some(1024)).unwrap();
        // 1024 - 16(overhead) - 24(frame) = 984
        assert_eq!(budget, 984);
    }

    #[test]
    fn pdu_budget_saturates_to_zero_for_tiny_max() {
        // A maximum below the frame overhead saturates to zero rather than
        // wrapping around.
        let budget = pdu_budget_for_access_results(Some(8)).unwrap();
        assert_eq!(budget, 0);
    }

    // ── VMD-specific / AA-specific → Unsupported ────────────────────────

    #[test]
    fn read_vmd_specific_returns_unsupported() {
        let (model, mms_model) = build_test_model();
        let name = ObjectName::VmdSpecific("MMXU1".to_string());
        let result = handle_single_read(&model, &mms_model, &name);
        assert!(matches!(
            result,
            AccessResult::Failure(DataAccessError::ObjectAccessUnsupported)
        ));
    }

    #[test]
    fn read_aa_specific_returns_unsupported() {
        let (model, mms_model) = build_test_model();
        let name = ObjectName::AaSpecific("AA_VAR".to_string());
        let result = handle_single_read(&model, &mms_model, &name);
        assert!(matches!(
            result,
            AccessResult::Failure(DataAccessError::ObjectAccessUnsupported)
        ));
    }

    // ── Three segments answer with the data object structure ────────────

    #[test]
    fn read_do_layer_with_matching_fc_returns_structure() {
        let (model, mms_model) = build_test_model();
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "MMXU1$MX$TotW".to_string(),
        };
        let result = handle_single_read(&model, &mms_model, &name);
        match &result {
            AccessResult::Success(data) => {
                assert!(
                    matches!(data, iec61850_mms::mms::pdu::common::MmsData::Structure(_)),
                    "a data object read must answer with a structure"
                );
            }
            AccessResult::Failure(e) => panic!("a data object read must succeed, got {:?}", e),
        }
    }

    // ── AlternateAccess post-processing ──────────────────────────────────────

    #[test]
    fn alt_access_index_selects_array_element() {
        let arr = MmsData::Array(vec![
            MmsData::Boolean(false),
            MmsData::Boolean(true),
            MmsData::Boolean(false),
        ]);
        let result = apply_alt_access(AccessResult::Success(arr), &AlternateAccess::index(1));
        assert!(matches!(
            result,
            AccessResult::Success(MmsData::Boolean(true))
        ));
    }

    #[test]
    fn alt_access_index_out_of_range_returns_type_inconsistent() {
        let arr = MmsData::Array(vec![MmsData::Boolean(false)]);
        let result = apply_alt_access(AccessResult::Success(arr), &AlternateAccess::index(5));
        assert!(matches!(
            result,
            AccessResult::Failure(DataAccessError::TypeInconsistent)
        ));
    }

    #[test]
    fn alt_access_on_non_array_returns_type_inconsistent() {
        let scalar = MmsData::Boolean(true);
        let result = apply_alt_access(AccessResult::Success(scalar), &AlternateAccess::index(0));
        assert!(matches!(
            result,
            AccessResult::Failure(DataAccessError::TypeInconsistent)
        ));
    }

    #[test]
    fn alt_access_on_existing_failure_passes_through() {
        let failure = AccessResult::Failure(DataAccessError::ObjectNonExistent);
        let result = apply_alt_access(failure, &AlternateAccess::index(0));
        assert!(matches!(
            result,
            AccessResult::Failure(DataAccessError::ObjectNonExistent)
        ));
    }

    #[test]
    fn alt_access_index_component_against_unnamed_structure_unsupported() {
        let arr = MmsData::Array(vec![MmsData::Structure(vec![
            MmsData::Boolean(true),
            MmsData::Integer(7),
        ])]);
        let aa = AlternateAccess::index_component(0, "stVal").unwrap();
        let result = apply_alt_access(AccessResult::Success(arr), &aa);
        assert!(matches!(
            result,
            AccessResult::Failure(DataAccessError::ObjectAccessUnsupported)
        ));
    }

    // ── Read handlers above and below the target ───────────────────────

    /// `MMXU1.A` is shaped like a WYE under MX: `phsA` is a sub-object whose
    /// `cVal` is a constructed attribute holding `mag`, and `q` sits on `A`.
    fn build_handler_model() -> iec61850_model::IedModel {
        let mag = DataAttribute::new(
            "mag",
            FC::Mx,
            DataAttributeType::Float32,
            TrgOps::default(),
            MmsValue::Float32(1.0),
        );
        let q = || {
            DataAttribute::new(
                "q",
                FC::Mx,
                DataAttributeType::Quality,
                TrgOps::default(),
                MmsValue::default_for(DataAttributeType::Quality),
            )
        };
        let phs_a = DataObject::new(
            "phsA",
            vec![
                DoChild::Da(DataAttribute::constructed("cVal", FC::Mx, vec![mag])),
                DoChild::Da(q()),
            ],
        );
        let a = DataObject::new("A", vec![DoChild::SubDo(phs_a), DoChild::Da(q())]);
        let mmxu_ln = iec61850_model::LogicalNode::new(String::new(), "MMXU", "1", vec![a]);
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(LogicalNodeBuilder::lln0().build().unwrap())
            .add_ln(mmxu_ln)
            .build()
            .unwrap();
        IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap()
    }

    /// Answers with a fixed outcome and counts how often it is asked.
    #[derive(Debug)]
    struct Fixed {
        outcome: ReadOutcome,
        asked: std::sync::atomic::AtomicUsize,
    }

    impl ReadHandler for Fixed {
        fn read(&self, _ctx: &ReadContext<'_>) -> ReadOutcome {
            self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.outcome.clone()
        }
    }

    fn fixed(outcome: ReadOutcome) -> Arc<Fixed> {
        Arc::new(Fixed {
            outcome,
            asked: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn asked(handler: &Fixed) -> usize {
        handler.asked.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn read_through(
        model: &iec61850_model::IedModel,
        registry: &HandlerRegistry,
        item_id: &str,
    ) -> AccessResult {
        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: item_id.to_string(),
        };
        match read_with_handlers(model, &name, None, None, Some((registry, 7))) {
            LookupResult::Result(r) => r,
            LookupResult::OverBudget => panic!("no budget was set"),
        }
    }

    fn quality() -> MmsData {
        MmsData::BitString {
            padding: 3,
            data: vec![0, 0],
        }
    }

    /// A handler on a leaf is asked by a read of every node above it, the data
    /// object, the sub-object and the constructed attribute, as well as by the
    /// logical node and its functional-constraint group. Its value replaces the
    /// leaf in each answer.
    #[test]
    fn leaf_handler_decides_reads_of_every_node_above_it() {
        let model = build_handler_model();
        let registry = HandlerRegistry::new();
        let leaf = fixed(ReadOutcome::CacheHit(MmsValue::Float32(9.0)));
        registry
            .install_read_handler("MMXU1$MX$A$phsA$cVal$mag", leaf.clone())
            .unwrap();
        let c_val = MmsData::Structure(vec![MmsData::Float32(9.0)]);
        let phs_a = MmsData::Structure(vec![c_val.clone(), quality()]);
        let a = MmsData::Structure(vec![phs_a.clone(), quality()]);
        let cases = [
            ("MMXU1$MX$A$phsA$cVal", c_val),
            ("MMXU1$MX$A$phsA", phs_a),
            ("MMXU1$MX$A", a.clone()),
            ("MMXU1$MX", MmsData::Structure(vec![a.clone()])),
            (
                "MMXU1",
                MmsData::Structure(vec![MmsData::Structure(vec![a])]),
            ),
        ];
        for (item_id, expected) in cases {
            assert_eq!(
                read_through(&model, &registry, item_id),
                AccessResult::Success(expected),
                "{item_id}"
            );
        }
        assert_eq!(asked(&leaf), 5);
    }

    /// A refusal below the target refuses the whole read, and the answer
    /// carries no part of the value.
    #[test]
    fn refusal_below_the_target_refuses_the_whole_read() {
        let model = build_handler_model();
        let registry = HandlerRegistry::new();
        registry
            .install_read_handler(
                "MMXU1$MX$A$phsA$q",
                fixed(ReadOutcome::Error(DataAccessError::ObjectAccessDenied)),
            )
            .unwrap();
        for item_id in ["MMXU1$MX$A$phsA", "MMXU1$MX$A", "MMXU1$MX", "MMXU1"] {
            assert_eq!(
                read_through(&model, &registry, item_id),
                AccessResult::Failure(DataAccessError::ObjectAccessDenied),
                "{item_id}"
            );
        }
        // A sibling of the refused node is not below it.
        assert_eq!(
            read_through(&model, &registry, "MMXU1$MX$A$q"),
            AccessResult::Success(quality())
        );
    }

    /// A handler above the target decides a read of anything below it: a
    /// refusal refuses the read, and a value answers it with the part the
    /// target occupies; handlers below a deciding one are not asked.
    #[test]
    fn handler_above_the_target_decides_the_read() {
        let model = build_handler_model();
        let registry = HandlerRegistry::new();
        registry
            .install_read_handler(
                "MMXU1$MX$A",
                fixed(ReadOutcome::Error(DataAccessError::ObjectAccessDenied)),
            )
            .unwrap();
        for item_id in [
            "MMXU1$MX$A$phsA$cVal$mag",
            "MMXU1$MX$A$phsA",
            "MMXU1$MX$A$q",
        ] {
            assert_eq!(
                read_through(&model, &registry, item_id),
                AccessResult::Failure(DataAccessError::ObjectAccessDenied),
                "{item_id}"
            );
        }

        let registry = HandlerRegistry::new();
        let above = fixed(ReadOutcome::CacheHit(MmsValue::Structure(vec![
            MmsValue::Structure(vec![MmsValue::Float32(4.0)]),
            MmsValue::BitString {
                padding: 3,
                data: vec![0x40, 0x00],
            },
        ])));
        let below = fixed(ReadOutcome::Error(DataAccessError::ObjectAccessDenied));
        registry
            .install_read_handler("MMXU1$MX$A$phsA", above.clone())
            .unwrap();
        registry
            .install_read_handler("MMXU1$MX$A$phsA$cVal$mag", below.clone())
            .unwrap();
        assert_eq!(
            read_through(&model, &registry, "MMXU1$MX$A$phsA$cVal$mag"),
            AccessResult::Success(MmsData::Float32(4.0))
        );
        assert_eq!(
            read_through(&model, &registry, "MMXU1$MX$A"),
            AccessResult::Success(MmsData::Structure(vec![
                MmsData::Structure(vec![
                    MmsData::Structure(vec![MmsData::Float32(4.0)]),
                    MmsData::BitString {
                        padding: 3,
                        data: vec![0x40, 0x00],
                    },
                ]),
                quality(),
            ]))
        );
        assert_eq!(asked(&below), 0);
    }

    /// A value from a handler above the target that does not follow the model
    /// is type-inconsistent, and one that holds a bit string too long for the
    /// target object-value-invalid; neither is sent.
    #[test]
    fn misshapen_value_from_above_is_not_sent() {
        let model = build_handler_model();
        let registry = HandlerRegistry::new();
        registry
            .install_read_handler(
                "MMXU1$MX$A$phsA",
                fixed(ReadOutcome::CacheHit(MmsValue::Structure(vec![
                    MmsValue::Float32(1.0),
                    MmsValue::BitString {
                        padding: 0,
                        data: vec![0xff, 0xff],
                    },
                ]))),
            )
            .unwrap();
        assert_eq!(
            read_through(&model, &registry, "MMXU1$MX$A$phsA$cVal$mag"),
            AccessResult::Failure(DataAccessError::TypeInconsistent)
        );
        assert_eq!(
            read_through(&model, &registry, "MMXU1$MX$A$phsA$q"),
            AccessResult::Failure(DataAccessError::ObjectValueInvalid)
        );
    }

    /// A value from a handler on a data object or a constructed attribute, or
    /// below the target, that does not follow the model is type-inconsistent,
    /// whichever read asks for it.
    #[test]
    fn misshapen_value_on_a_node_above_leaves_is_type_inconsistent() {
        let model = build_handler_model();
        let cases = [
            ("MMXU1$MX$A$phsA$cVal", MmsValue::Float32(1.0)),
            ("MMXU1$MX$A$phsA$cVal", MmsValue::Structure(Vec::new())),
            (
                "MMXU1$MX$A$phsA",
                MmsValue::Structure(vec![MmsValue::Structure(vec![MmsValue::Float32(1.0)])]),
            ),
        ];
        for (installed_on, value) in cases {
            let registry = HandlerRegistry::new();
            registry
                .install_read_handler(installed_on, fixed(ReadOutcome::CacheHit(value.clone())))
                .unwrap();
            for item_id in [installed_on, "MMXU1$MX$A", "MMXU1"] {
                assert_eq!(
                    read_through(&model, &registry, item_id),
                    AccessResult::Failure(DataAccessError::TypeInconsistent),
                    "{installed_on} = {value:?}, read {item_id}"
                );
            }
        }
    }

    /// A value a handler supplies below a sub-data-object, a data object or a
    /// functional-constraint group is charged to the budget as it is sent, not
    /// as the model value it replaces.
    #[test]
    fn handler_value_is_charged_to_the_budget() {
        let model = build_handler_model();
        let registry = HandlerRegistry::new();
        registry
            .install_read_handler(
                "MMXU1$MX$A$phsA$cVal",
                fixed(ReadOutcome::CacheHit(MmsValue::Structure(vec![
                    MmsValue::Float64(1.0),
                ]))),
            )
            .unwrap();
        for item_id in ["MMXU1$MX$A$phsA", "MMXU1$MX$A", "MMXU1$MX"] {
            let name = ObjectName::DomainSpecific {
                domain_id: "IED1LD0".to_string(),
                item_id: item_id.to_string(),
            };
            let LookupResult::Result(AccessResult::Success(model_value)) =
                read_with_handlers(&model, &name, None, None, None)
            else {
                panic!("a model value for {item_id}");
            };
            // A 64-bit float takes four more octets than the 32-bit one it
            // replaces, so the exact budget of the model value is too small.
            let exact = model_value.estimated_encoded_size();
            assert_eq!(
                read_with_handlers(&model, &name, None, Some(exact), Some((&registry, 7))),
                LookupResult::OverBudget,
                "{item_id}"
            );
            assert!(matches!(
                read_with_handlers(&model, &name, None, Some(exact + 4), Some((&registry, 7))),
                LookupResult::Result(AccessResult::Success(_))
            ));
        }
    }

    /// With read access ignored, no handler is asked anywhere.
    #[test]
    fn ignored_read_access_asks_no_handler() {
        let model = build_handler_model();
        let registry = HandlerRegistry::new();
        let leaf = fixed(ReadOutcome::Error(DataAccessError::ObjectAccessDenied));
        registry
            .install_read_handler("MMXU1$MX$A$q", leaf.clone())
            .unwrap();
        registry.set_ignore_read_access(true);
        assert!(matches!(
            read_through(&model, &registry, "MMXU1$MX$A"),
            AccessResult::Success(_)
        ));
        assert_eq!(asked(&leaf), 0);
    }

    /// A data set member goes through the same rules as a read of its path.
    #[test]
    fn data_set_member_value_passes_the_handlers_above_it() {
        let model = build_handler_model();
        let registry = HandlerRegistry::new();
        registry
            .install_read_handler(
                "MMXU1$MX$A$phsA",
                fixed(ReadOutcome::Error(DataAccessError::ObjectAccessDenied)),
            )
            .unwrap();
        assert_eq!(
            apply_read_handlers(
                &model,
                &registry,
                7,
                "IED1LD0",
                "MMXU1$MX$A$phsA$cVal$mag",
                AccessResult::Success(MmsData::Float32(1.0)),
            ),
            AccessResult::Failure(DataAccessError::ObjectAccessDenied)
        );
        assert_eq!(
            apply_read_handlers(
                &model,
                &registry,
                7,
                "IED1LD0",
                "MMXU1$MX$A$q",
                AccessResult::Success(quality()),
            ),
            AccessResult::Success(quality())
        );
    }

    /// Records the path and the requested path of every read it is asked
    /// about, and answers only a read of its own path: with an error, so a
    /// read that covers its node passes through on a miss.
    #[derive(Debug, Default)]
    struct OwnPathOnly {
        seen: std::sync::Mutex<Vec<(String, String)>>,
    }

    impl ReadHandler for OwnPathOnly {
        fn read(&self, ctx: &ReadContext<'_>) -> ReadOutcome {
            self.seen
                .lock()
                .unwrap()
                .push((ctx.path.to_string(), ctx.requested.to_string()));
            if ctx.requested != ctx.path {
                return ReadOutcome::CacheMiss;
            }
            ReadOutcome::Error(DataAccessError::ObjectAccessDenied)
        }
    }

    /// A handler sees its own path and the path the client named, so one meant
    /// for its own path only can let the reads that cover it pass.
    #[test]
    fn handler_tells_its_own_path_from_the_requested_one() {
        let model = build_handler_model();
        let registry = HandlerRegistry::new();
        let leaf = Arc::new(OwnPathOnly::default());
        registry
            .install_read_handler("MMXU1$MX$A$q", leaf.clone())
            .unwrap();
        assert!(matches!(
            read_through(&model, &registry, "MMXU1$MX$A"),
            AccessResult::Success(_)
        ));
        assert!(matches!(
            read_through(&model, &registry, "MMXU1"),
            AccessResult::Success(_)
        ));
        assert_eq!(
            read_through(&model, &registry, "MMXU1$MX$A$q"),
            AccessResult::Failure(DataAccessError::ObjectAccessDenied)
        );
        assert_eq!(
            *leaf.seen.lock().unwrap(),
            [
                ("MMXU1$MX$A$q".to_string(), "MMXU1$MX$A".to_string()),
                ("MMXU1$MX$A$q".to_string(), "MMXU1".to_string()),
                ("MMXU1$MX$A$q".to_string(), "MMXU1$MX$A$q".to_string()),
            ]
        );
    }
}
