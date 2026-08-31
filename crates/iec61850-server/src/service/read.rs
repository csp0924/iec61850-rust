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

#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use crate::mapping::MmsDeviceModel;
use iec61850_mms::mms::pdu::common::{
    AccessResult, AlternateAccess, AlternateAccessSelector, DataAccessError, MmsData, ObjectName,
};
use iec61850_model::{DataAttribute, DoChild, IedModel, LogicalNode, MmsValue, FC};

use crate::service::convert::mms_value_to_mms_data;

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
/// into a structure.
///
/// Per IEC 61850-8-1 each functional-constraint group is a structure whose
/// members are themselves structures, one per data object. `Ok(None)` means the
/// group is empty for this node.
fn expand_ln_for_fc(
    ln: &LogicalNode,
    fc: FC,
    budget: &mut BudgetGuard,
) -> Result<Option<MmsData>, ()> {
    let mut do_groups = Vec::new();
    for d in &ln.dos {
        if let Some(do_struct) = expand_do_for_fc(d, fc, budget)? {
            do_groups.push(do_struct);
        }
    }
    if do_groups.is_empty() {
        return Ok(None);
    }
    let st = MmsData::Structure(do_groups);
    let outer = st.estimated_encoded_size() - children_inner_size_sum(&st);
    if !budget.consume(outer) {
        return Err(());
    }
    Ok(Some(st))
}

/// Expands a whole logical node into a structure of its functional-constraint
/// groups, as IEC 61850-8-1 maps a logical node onto an MMS structure.
fn expand_whole_ln(ln: &LogicalNode, budget: &mut BudgetGuard) -> Result<MmsData, ()> {
    let mut fc_groups = Vec::new();
    for fc in FC::WIRE_ORDER {
        if let Some(group) = expand_ln_for_fc(ln, fc, budget)? {
            fc_groups.push(group);
        }
    }
    let st = MmsData::Structure(fc_groups);
    let outer = st.estimated_encoded_size() - children_inner_size_sum(&st);
    if !budget.consume(outer) {
        return Err(());
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
fn lookup_domain_specific_value(
    ied_model: &IedModel,
    domain: &str,
    item_id: &str,
    alt_access: Option<&AlternateAccess>,
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
        return match expand_whole_ln(ln, budget) {
            Ok(st) => LookupResult::Result(AccessResult::Success(st)),
            Err(()) => {
                debug_assert!(budget.is_over());
                LookupResult::OverBudget
            }
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
        return match expand_ln_for_fc(ln, target_fc, budget) {
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
            Err(()) => {
                debug_assert!(budget.is_over());
                LookupResult::OverBudget
            }
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
            Ok(Some(st)) => LookupResult::Result(AccessResult::Success(st)),
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
    // can drive the descent past the model's own depth.
    let mut current_do = do_node;
    let mut next = 3;
    let mut reached_da: Option<&DataAttribute> = None;
    while next < parts.len() {
        match current_do.child_by_name(parts[next]) {
            Some(DoChild::SubDo(sub)) => {
                current_do = sub;
                next += 1;
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
            return match expand_do_for_fc(current_do, target_fc, budget) {
                Ok(Some(st)) => LookupResult::Result(AccessResult::Success(st)),
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

    let value = current_da.snapshot();
    let access = match alt_access {
        None => AccessResult::Success(mms_value_to_mms_data(&value)),
        Some(alt) => apply_alt_access_typed(current_da, &value, alt),
    };
    if let AccessResult::Success(ref data) = access {
        if !budget.consume(data.estimated_encoded_size()) {
            return LookupResult::OverBudget;
        }
    }
    LookupResult::Result(access)
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
pub fn handle_single_read_with_budget(
    ied_model: &IedModel,
    _mms_model: &MmsDeviceModel,
    name: &ObjectName,
    alt_access: Option<&AlternateAccess>,
    budget: Option<usize>,
) -> LookupResult {
    let mut guard = BudgetGuard::new(budget);
    match name {
        ObjectName::DomainSpecific { domain_id, item_id } => {
            lookup_domain_specific_value(ied_model, domain_id, item_id, alt_access, &mut guard)
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
        let totw_do = DataObject {
            name: "TotW".into(),
            array_count: None,
            children: vec![DoChild::Da(mag_da)],
        };
        let mmxu_ln = iec61850_model::LogicalNode {
            prefix: String::new(),
            class: "MMXU".into(),
            inst: "1".into(),
            dos: vec![totw_do],
            datasets: vec![],
            rcbs: vec![],
            gocbs: vec![],
            svcbs: vec![],
            lcbs: vec![],
            sgcb: None,
        };
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
        let totw_do = DataObject {
            name: "TotW".into(),
            array_count: None,
            children: vec![DoChild::Da(mag_da)],
        };
        let mmxu_ln = iec61850_model::LogicalNode {
            prefix: String::new(),
            class: "MMXU".into(),
            inst: "1".into(),
            dos: vec![totw_do],
            datasets: vec![],
            rcbs: vec![],
            gocbs: vec![],
            svcbs: vec![],
            lcbs: vec![],
            sgcb: None,
        };
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
        let mmxu_ln = iec61850_model::LogicalNode {
            prefix: String::new(),
            class: "MMXU".into(),
            inst: "1".into(),
            dos: vec![do_node],
            datasets: vec![],
            rcbs: vec![],
            gocbs: vec![],
            svcbs: vec![],
            lcbs: vec![],
            sgcb: None,
        };
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
        let phs_a = DataObject {
            name: "phsA".into(),
            array_count: None,
            children: vec![DoChild::Da(DataAttribute::constructed(
                "cVal",
                FC::Mx,
                vec![mag, ang],
            ))],
        };
        let phv = DataObject {
            name: "PhV".into(),
            array_count: None,
            children: vec![DoChild::SubDo(phs_a)],
        };
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
        let mut node = DataObject {
            name: format!("S{depth}"),
            array_count: None,
            children: vec![DoChild::Da(DataAttribute::new(
                "v",
                FC::Mx,
                DataAttributeType::Float32,
                TrgOps::default(),
                MmsValue::Float32(9.0),
            ))],
        };
        for level in (0..depth).rev() {
            node = DataObject {
                name: format!("S{level}"),
                array_count: None,
                children: vec![DoChild::SubDo(node)],
            };
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
}
