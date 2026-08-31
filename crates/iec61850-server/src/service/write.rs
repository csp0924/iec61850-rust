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
//!    refusal is `ObjectAccessDenied`, otherwise the type is checked and the
//!    value written.
//! 4. SE: the same bitmask, plus the setting-group edit session gate.
//!
//! The type check compares the variant of the decoded wire value against the
//! variant currently held in the model and answers `ObjectValueInvalid` on a
//! mismatch. A path is served down to one data attribute,
//! `LN$FC$DO[$SDO...]$DA`, crossing any depth of sub-data-objects on the way.
//! A path that stops on a data object, and a path that continues into a
//! sub-attribute below the attribute, both answer `ObjectAccessUnsupported`:
//! the value of a constructed node lives in its leaves, which are written one
//! at a time.

#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use crate::handler::{
    canonicalize_attr_path, HandlerRegistry, WriteContext, WriteOutcome as HandlerWriteOutcome,
};
use crate::mapping::MmsDeviceModel;
use crate::policy::WriteAccessPolicies;
use crate::service::convert::{mms_data_to_mms_value, same_data_variant};
// Writing under FC SE belongs to the setting-group subsystem.
#[cfg(feature = "setting-groups")]
use crate::setting_groups::SettingGroupRegistry;
use iec61850_mms::mms::pdu::common::{DataAccessError, MmsData, ObjectName, WriteOutcome};
use iec61850_model::{DataAttribute, DataAttributeType, DoChild, IedModel, FC};

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
    /// non-zero (IEC 61850-7-2 §20.3).
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
/// [`AttributeAccessHandler`](crate::handler::AttributeAccessHandler). A `None`
/// registry writes straight to the cache.
#[allow(clippy::too_many_arguments)]
pub fn handle_single_write(
    ied_model: &IedModel,
    _mms_model: &MmsDeviceModel,
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

    // A write targets exactly one data attribute, so the path must name one.
    if parts.len() < 4 {
        tracing::warn!(
            domain = domain,
            item_id = item_id,
            "write: item id names no data attribute, four segments are required"
        );
        return WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported);
    }

    let ln_name = parts[0];
    let fc_str = parts[1];
    // Everything from the data object down; how far it descends is a question
    // only the model can answer, so the shape verdict is left to `write_to_da`
    // alongside the other path-resolution verdicts.
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
            write_to_da(
                ied_model,
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
            let registry = match setting_groups {
                Some(r) => r,
                None => {
                    tracing::warn!(
                        domain = domain,
                        item_id = item_id,
                        "write: no setting group registry is configured, refusing an SE write"
                    );
                    return WriteOutcome::Failure(DataAccessError::ObjectAccessDenied);
                }
            };
            let rt = match registry.lookup(domain) {
                Some(rt) => rt,
                None => {
                    tracing::warn!(
                        domain = domain,
                        item_id = item_id,
                        "write: the domain declares no setting group control block, refusing an SE write"
                    );
                    return WriteOutcome::Failure(DataAccessError::ObjectAccessDenied);
                }
            };
            if !rt.is_edit_session_owner(conn_id) {
                tracing::warn!(
                    domain = domain,
                    item_id = item_id,
                    conn_id,
                    "write: the caller does not own an open edit session, refusing an SE write"
                );
                return WriteOutcome::Failure(DataAccessError::ObjectAccessDenied);
            }
            write_to_da(
                ied_model,
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

/// Resolves the data attribute, checks the type, gives any registered handler
/// its say, and updates the cached value.
#[allow(clippy::too_many_arguments)]
fn write_to_da(
    ied_model: &IedModel,
    domain: &str,
    ln_name: &str,
    fc: FC,
    object_path: &[&str],
    data: &MmsData,
    handler_registry: Option<&HandlerRegistry>,
    conn_id: u64,
    item_id: &str,
) -> WriteOutcome {
    // The caller guarantees at least a data object and one name below it.
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
    // both by name and by functional constraint, so the constraint filter
    // applies at the step that leaves the data-object tree: a name that matches
    // an attribute under a different constraint does not resolve.
    let mut current_do = do_node;
    let mut next = 1;
    let mut reached_da: Option<&DataAttribute> = None;
    'walk: while next < object_path.len() {
        let step = object_path[next];
        for child in &current_do.children {
            match child {
                DoChild::SubDo(sub) if sub.name == step => {
                    current_do = sub;
                    next += 1;
                    continue 'walk;
                }
                DoChild::Da(da) if da.name == step && da.fc == fc => {
                    reached_da = Some(da);
                    next += 1;
                    break 'walk;
                }
                _ => {}
            }
        }
        tracing::warn!(
            domain = domain,
            ln = ln_name,
            item_id = item_id,
            step = step,
            "write: no data attribute of that name under this functional constraint"
        );
        return WriteOutcome::Failure(DataAccessError::ObjectNonExistent);
    }

    let da = match reached_da {
        Some(da) => da,
        None => {
            // The path names a data object or a sub-data-object: the node
            // exists, but its value lives in the attributes below it, so there
            // is no value here to write. That is access-unsupported rather than
            // non-existent, and it is the answer a path naming no attribute at
            // all already gets.
            tracing::warn!(
                domain = domain,
                ln = ln_name,
                item_id = item_id,
                "write: the path names a data object, not a data attribute"
            );
            return WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported);
        }
    };
    let da_name = da.name.as_str();

    // Sub-attributes below the attribute are not served; a constructed
    // attribute is written one leaf at a time through its own path.
    if next < object_path.len() {
        tracing::warn!(
            domain = domain,
            item_id = item_id,
            "write: sub-attribute paths are not served"
        );
        return WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported);
    }

    // The authoritative values of a constructed attribute live in its leaves,
    // so a value stored in the attribute itself would never be read back. The
    // caller writes the leaves instead.
    if da.ty == DataAttributeType::Constructed {
        tracing::warn!(
            domain = domain,
            da = da_name,
            "write: a constructed data attribute must be written leaf by leaf"
        );
        return WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported);
    }

    let current_value = da.snapshot();
    if !same_data_variant(data, &current_value) {
        tracing::warn!(
            domain = domain,
            da = da_name,
            "write: the value type does not match the data attribute"
        );
        return WriteOutcome::Failure(DataAccessError::ObjectValueInvalid);
    }

    let new_value = mms_data_to_mms_value(data);

    // The handler runs only after the policy and type checks have passed. It
    // may accept and let the cache be updated, accept and take ownership of the
    // value itself, or refuse with a specific error.
    if let Some(reg) = handler_registry {
        if let Ok(canonical_path) = canonicalize_attr_path(item_id) {
            if let Some(handler) = reg.lookup_write(&canonical_path) {
                let ctx = WriteContext {
                    path: &canonical_path,
                    fc,
                    conn_id,
                };
                match handler.on_write(&ctx, &new_value) {
                    HandlerWriteOutcome::Reject(e) => {
                        tracing::warn!(
                            path = %canonical_path,
                            ?e,
                            "write: the attribute access handler refused the value"
                        );
                        return WriteOutcome::Failure(e);
                    }
                    HandlerWriteOutcome::AcceptNoUpdate => {
                        // The handler owns the value; the cache is left alone
                        // and the client still sees success.
                        tracing::debug!(
                            path = %canonical_path,
                            "write: the attribute access handler accepted the value without a cache update"
                        );
                        return WriteOutcome::Success;
                    }
                    HandlerWriteOutcome::Accept => {
                        // Falls through to the cache update below.
                    }
                }
            }
        }
    }

    // Reached with no handler registered, or with one that accepted the value.
    // `std::sync::RwLock::write` yields a `Result` while `spin::RwLock::write`
    // yields the guard, hence the two arms.
    #[cfg(feature = "std")]
    {
        match da.value.write() {
            Ok(mut guard) => {
                *guard = new_value;
                tracing::debug!(
                    domain = domain,
                    ln = ln_name,
                    do_name = do_name,
                    da_name = da_name,
                    "write: value updated"
                );
                WriteOutcome::Success
            }
            Err(_poisoned) => {
                // Only a panic while the value was locked can poison it, but the
                // client gets a retryable error rather than an unwrap.
                tracing::warn!(
                    domain = domain,
                    da = da_name,
                    "write: the value lock is poisoned, answering temporarily-unavailable"
                );
                WriteOutcome::Failure(DataAccessError::TemporarilyUnavailable)
            }
        }
    }
    #[cfg(not(feature = "std"))]
    {
        let mut guard = da.value.write();
        *guard = new_value;
        tracing::debug!(
            domain = domain,
            ln = ln_name,
            do_name = do_name,
            da_name = da_name,
            "write: value updated"
        );
        WriteOutcome::Success
    }
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

        let totw_do = DataObject {
            name: "TotW".into(),
            array_count: None,
            children: vec![DoChild::Da(mag_da)],
        };
        let mod_do = DataObject {
            name: "Mod".into(),
            array_count: None,
            children: vec![DoChild::Da(ctl_model_da)],
        };
        let spcso_do = DataObject {
            name: "SPCSO1".into(),
            array_count: None,
            children: vec![DoChild::Da(ctl_val_da)],
        };
        // GGIO1.SetPt.setMag, SP and constructed: refused as a whole.
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
        let setpt_do = DataObject {
            name: "SetPt".into(),
            array_count: None,
            children: vec![DoChild::Da(set_mag_da)],
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
        let ggio_ln = iec61850_model::LogicalNode {
            prefix: String::new(),
            class: "GGIO".into(),
            inst: "1".into(),
            dos: vec![mod_do, spcso_do, setpt_do],
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

    // ── A constructed attribute is not written as a whole ───────────────

    /// The value of a constructed attribute is assembled from its children and
    /// its own `value` is never read, so writing the whole attribute would
    /// discard the value silently.
    #[test]
    fn write_constructed_da_returns_unsupported() {
        let (model, mms_model) = build_test_model();
        // The default mask includes SP, so the request reaches the attribute.
        let policies = WriteAccessPolicies::default();

        let name = ObjectName::DomainSpecific {
            domain_id: "IED1LD0".to_string(),
            item_id: "GGIO1$SP$SetPt$setMag".to_string(),
        };
        let data = MmsData::Structure(vec![MmsData::Float32(1.0)]);
        let result =
            handle_single_write(&model, &mms_model, &policies, None, None, 0, &name, &data);
        assert_eq!(
            result,
            WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported)
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
        let phs_a = DataObject {
            name: "phsA".into(),
            array_count: None,
            children: vec![DoChild::Da(set_mag), DoChild::Da(set_cplx)],
        };
        let deep = DataObject {
            name: "cmv".into(),
            array_count: None,
            children: vec![DoChild::Da(DataAttribute::new(
                "setDeep",
                FC::Sp,
                DataAttributeType::Float32,
                TrgOps::default(),
                MmsValue::Float32(0.0),
            ))],
        };
        let phs_b = DataObject {
            name: "phsB".into(),
            array_count: None,
            children: vec![DoChild::SubDo(deep)],
        };
        let phset_do = DataObject {
            name: "PhSet".into(),
            array_count: None,
            children: vec![DoChild::SubDo(phs_a), DoChild::SubDo(phs_b)],
        };
        let ggio_ln = iec61850_model::LogicalNode {
            prefix: String::new(),
            class: "GGIO".into(),
            inst: "1".into(),
            dos: vec![phset_do],
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

    /// A path that stops on a sub-data-object names no attribute to write. The
    /// answer is object-access-unsupported, matching a path that names only a
    /// data object: the value of a constructed node lives in its leaves.
    #[test]
    fn write_to_a_sub_data_object_itself_returns_unsupported() {
        let (model, mms_model) = build_sdo_write_model();
        let policies = WriteAccessPolicies::default();
        let result = sdo_write(
            &model,
            &mms_model,
            &policies,
            "GGIO1$SP$PhSet$phsA",
            MmsData::Structure(vec![MmsData::Float32(1.0)]),
        );
        assert_eq!(
            result,
            WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported)
        );
    }

    /// Sub-attribute paths stay unserved after the descent: reaching the
    /// attribute across a sub-data-object does not open a path into its leaves.
    #[test]
    fn write_below_an_attribute_under_a_sub_data_object_is_unsupported() {
        let (model, mms_model) = build_sdo_write_model();
        let policies = WriteAccessPolicies::default();
        let result = sdo_write(
            &model,
            &mms_model,
            &policies,
            "GGIO1$SP$PhSet$phsA$setCplx$f",
            MmsData::Float32(1.0),
        );
        assert_eq!(
            result,
            WriteOutcome::Failure(DataAccessError::ObjectAccessUnsupported)
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
        let setpoint_do = DataObject {
            name: "Setpoint".into(),
            array_count: None,
            children: vec![DoChild::Da(set_val_da), DoChild::Da(cur_val_da)],
        };

        let ggio_ln = iec61850_model::LogicalNode {
            prefix: String::new(),
            class: "GGIO".into(),
            inst: "1".into(),
            dos: vec![setpoint_do],
            datasets: vec![],
            rcbs: vec![],
            gocbs: vec![],
            svcbs: vec![],
            lcbs: vec![],
            sgcb: None,
        };
        let lln0 = LogicalNodeBuilder::lln0()
            .set_sgcb(SettingGroupControlBlock {
                num_of_sg: 3,
                act_sg: 1,
                has_resv_tms: false,
                default_resv_tms_s: 60,
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
    fn write_se_fc_without_edit_session_denied() {
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
            WriteOutcome::Failure(DataAccessError::ObjectAccessDenied),
            "a write under functional constraint SE needs an open edit session, per IEC 61850-7-2 §20.3"
        );
    }

    #[test]
    fn write_se_fc_wrong_owner_denied() {
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
            WriteOutcome::Failure(DataAccessError::ObjectAccessDenied),
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
    fn write_se_fc_no_registry_denied() {
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
            WriteOutcome::Failure(DataAccessError::ObjectAccessDenied)
        );
    }

    #[test]
    fn write_se_fc_no_sgcb_on_domain_denied() {
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
            WriteOutcome::Failure(DataAccessError::ObjectAccessDenied)
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
}
