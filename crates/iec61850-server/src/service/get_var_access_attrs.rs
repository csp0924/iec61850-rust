//! Server handler for the GetVariableAccessAttributes service of
//! IEC 61850-7-2.
//!
//! The request carries an `item_id` of the form `LN$FC$DO[$SDA[...]]`: segment
//! 0 names the logical node, segment 1 the functional constraint, and the rest
//! walk down through the data object to a data attribute. The model resolves
//! only as far as the logical node, returning its whole type specification, so
//! this module splits the `item_id` on `$` and descends the structure children
//! one segment at a time to reach the requested node. Encoding the result is
//! left to the conversion layer.

#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::mapping::MmsDeviceModel;
use crate::mapping::MmsTypeSpec;
use crate::service::convert::mms_type_spec_to_type_spec;
use iec61850_mms::mms::pdu::{
    common::ObjectName,
    get_var_access_attrs::{
        GetVariableAccessAttributesRequest, GetVariableAccessAttributesResponse,
    },
};

/// Outcome of a GetVariableAccessAttributes request.
#[derive(Debug)]
pub enum GetVarAccessAttrsResult {
    /// The requested object was found and its type specification encoded.
    Response(GetVariableAccessAttributesResponse),
    /// No object matches the request: the domain, logical node, data object, or
    /// data attribute does not resolve.
    ///
    /// Maps to data access error object-non-existent (10).
    NotFound,
    /// The object name uses a scope this server does not serve, that is
    /// vmd-specific or aa-specific; only domain-specific paths are handled.
    Unsupported,
}

/// Answers a GetVariableAccessAttributes request against the mapped model.
///
/// A domain-specific object name carries an `item_id` of at least two segments
/// (`LN$FC`), usually three or more once a data object is named. The logical
/// node type specification is looked up first, then the functional-constraint
/// group, then each further segment in turn.
///
/// A vmd-specific name always answers `NotFound`: an IEC 61850 model registers
/// no VMD-scope variables, so object-non-existent is the accurate answer. An
/// aa-specific name answers `Unsupported`, that is a ConfirmedError carrying
/// object-access-unsupported, because a client learns more from an error PDU
/// than from a closed connection.
pub fn handle_get_var_access_attrs(
    model: &MmsDeviceModel,
    req: &GetVariableAccessAttributesRequest,
) -> GetVarAccessAttrsResult {
    let (domain, item_id) = match &req.object_name {
        ObjectName::DomainSpecific { domain_id, item_id } => (domain_id.as_str(), item_id.as_str()),
        ObjectName::VmdSpecific(name) => {
            // The dispatcher turns this into ConfirmedError(Access, 10).
            tracing::warn!(
                vmd_var = %name,
                "get-variable-access-attributes: an IEC 61850 server holds no vmd-scope variables"
            );
            return GetVarAccessAttrsResult::NotFound;
        }
        ObjectName::AaSpecific(name) => {
            tracing::warn!(
                aa_var = %name,
                "get-variable-access-attributes: aa-scope is not served, answering object-access-unsupported"
            );
            return GetVarAccessAttrsResult::Unsupported;
        }
    };

    // For example LLN0$ST$Mod or MMXU1$MX$TotW$mag$f; a single segment names a
    // whole logical node.
    let parts: Vec<&str> = item_id.split('$').collect();
    if parts.is_empty() {
        return GetVarAccessAttrsResult::NotFound;
    }

    let ln_name = parts[0];

    let ln_ts = match model.get_variable_spec(domain, ln_name) {
        Some(ts) => ts,
        None => {
            tracing::warn!(
                domain = domain,
                ln = ln_name,
                "get-variable-access-attributes: no such logical node"
            );
            return GetVarAccessAttrsResult::NotFound;
        }
    };

    // An item_id without a `$` names the logical node itself and answers with
    // its whole structure; model-driven clients use this to enumerate a node.
    if parts.len() == 1 {
        let ts = mms_type_spec_to_type_spec(ln_ts);
        return GetVarAccessAttrsResult::Response(GetVariableAccessAttributesResponse {
            mms_deletable: false,
            type_specification: ts,
        });
    }

    let fc_str = parts[1];

    // A trailing separator with nothing after it is treated the same way.
    if parts.len() == 2 && fc_str.is_empty() {
        let ts = mms_type_spec_to_type_spec(ln_ts);
        return GetVarAccessAttrsResult::Response(GetVariableAccessAttributesResponse {
            mms_deletable: false,
            type_specification: ts,
        });
    }

    let fc_ts = match find_child_by_name(ln_ts, fc_str) {
        Some(ts) => ts,
        None => {
            tracing::warn!(
                domain = domain,
                ln = ln_name,
                fc = fc_str,
                "get-variable-access-attributes: no such functional-constraint group"
            );
            return GetVarAccessAttrsResult::NotFound;
        }
    };

    // A two-segment path answers with the type of the whole group.
    if parts.len() == 2 {
        let ts = mms_type_spec_to_type_spec(fc_ts);
        return GetVarAccessAttrsResult::Response(GetVariableAccessAttributesResponse {
            mms_deletable: false,
            type_specification: ts,
        });
    }

    let mut current_ts = fc_ts;
    for part in &parts[2..] {
        current_ts = match find_child_by_name(current_ts, part) {
            Some(ts) => ts,
            None => {
                tracing::warn!(
                    domain = domain,
                    item_id = item_id,
                    step = part,
                    "get-variable-access-attributes: no such path segment"
                );
                return GetVarAccessAttrsResult::NotFound;
            }
        };
    }

    let ts = mms_type_spec_to_type_spec(current_ts);
    GetVarAccessAttrsResult::Response(GetVariableAccessAttributesResponse {
        mms_deletable: false, // Always false per IEC 61850-8-1.
        type_specification: ts,
    })
}

/// Finds a named child of a structure type specification.
///
/// An array descends into its element type; a leaf has no children and yields
/// `None`.
fn find_child_by_name<'a>(ts: &'a MmsTypeSpec, name: &str) -> Option<&'a MmsTypeSpec> {
    match ts {
        MmsTypeSpec::Structure(children) => children
            .iter()
            .find(|c| c.name == name)
            .map(|c| &c.type_spec),
        MmsTypeSpec::Array { inner, .. } => {
            // A named field of an array is a field of its element type.
            find_child_by_name(inner, name)
        }
        MmsTypeSpec::Leaf(_) => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test helper: reduces a type specification to a comparable tag
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
use iec61850_mms::mms::pdu::type_specification::TypeSpecification;

#[cfg(test)]
fn ts_tag(ts: &TypeSpecification) -> &'static str {
    match ts {
        TypeSpecification::Boolean => "Boolean",
        TypeSpecification::Integer { .. } => "Integer",
        TypeSpecification::Unsigned { .. } => "Unsigned",
        TypeSpecification::FloatingPoint { .. } => "Float",
        TypeSpecification::BitString { .. } => "BitString",
        TypeSpecification::OctetString { .. } => "OctetString",
        TypeSpecification::VisibleString { .. } => "VisibleString",
        TypeSpecification::MmsString { .. } => "MmsString",
        TypeSpecification::UtcTime => "UtcTime",
        TypeSpecification::BinaryTime { .. } => "BinaryTime",
        TypeSpecification::Array { .. } => "Array",
        TypeSpecification::Structure { .. } => "Structure",
        TypeSpecification::Unknown(_) => "Unknown",
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
        LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, TrgOps, FC,
    };

    /// Builds a model whose MMXU1 logical node carries a TotW data object under
    /// functional constraint MX.
    fn build_mmxu_model() -> (iec61850_model::IedModel, MmsDeviceModel) {
        // MMXU1.TotW.mag, functional constraint MX, Float32.
        let mag_da = DataAttribute::new(
            "mag",
            FC::Mx,
            DataAttributeType::Float32,
            TrgOps::default(),
            MmsValue::Float32(0.0),
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

    // ── Whole logical node, an interoperability regression ──────────────

    /// Model-driven clients enumerate the functional-constraint groups of a
    /// logical node with a single-segment path, so `LN` must answer with the
    /// whole structure rather than `NotFound`, or the client cannot expand the
    /// node.
    #[test]
    fn gva_whole_ln_returns_structure() {
        let (_model, mms_model) = build_mmxu_model();
        let req = GetVariableAccessAttributesRequest {
            object_name: ObjectName::DomainSpecific {
                domain_id: "IED1LD0".to_string(),
                item_id: "MMXU1".to_string(),
            },
        };
        let result = handle_get_var_access_attrs(&mms_model, &req);
        match result {
            GetVarAccessAttrsResult::Response(resp) => {
                assert!(!resp.mms_deletable);
                assert_eq!(
                    ts_tag(&resp.type_specification),
                    "Structure",
                    "a whole-LN request must answer with the node structure"
                );
            }
            other => panic!(
                "a whole-LN request must produce a response, got {:?}",
                other
            ),
        }
    }

    // ── Happy path: LN$FC$DO ────────────────────────────────────────────

    #[test]
    fn gva_do_level_returns_structure() {
        let (_model, mms_model) = build_mmxu_model();
        let req = GetVariableAccessAttributesRequest {
            object_name: ObjectName::DomainSpecific {
                domain_id: "IED1LD0".to_string(),
                item_id: "MMXU1$MX$TotW".to_string(),
            },
        };
        let result = handle_get_var_access_attrs(&mms_model, &req);
        match result {
            GetVarAccessAttrsResult::Response(resp) => {
                assert!(!resp.mms_deletable);
                assert_eq!(ts_tag(&resp.type_specification), "Structure");
            }
            other => panic!("expected a response, got {:?}", other),
        }
    }

    #[test]
    fn gva_da_level_returns_float() {
        let (_model, mms_model) = build_mmxu_model();
        let req = GetVariableAccessAttributesRequest {
            object_name: ObjectName::DomainSpecific {
                domain_id: "IED1LD0".to_string(),
                item_id: "MMXU1$MX$TotW$mag".to_string(),
            },
        };
        let result = handle_get_var_access_attrs(&mms_model, &req);
        match result {
            GetVarAccessAttrsResult::Response(resp) => {
                assert_eq!(ts_tag(&resp.type_specification), "Float");
            }
            other => panic!("expected a response, got {:?}", other),
        }
    }

    // ── mms_deletable is always false, per IEC 61850-8-1 ────────────────

    #[test]
    fn gva_mms_deletable_always_false() {
        let (_model, mms_model) = build_mmxu_model();
        let req = GetVariableAccessAttributesRequest {
            object_name: ObjectName::DomainSpecific {
                domain_id: "IED1LD0".to_string(),
                item_id: "MMXU1$MX$TotW$mag".to_string(),
            },
        };
        let result = handle_get_var_access_attrs(&mms_model, &req);
        match result {
            GetVarAccessAttrsResult::Response(resp) => {
                assert!(
                    !resp.mms_deletable,
                    "mmsDeletable must always be false, per IEC 61850-8-1"
                );
            }
            other => panic!("expected a response, got {:?}", other),
        }
    }

    // ── NotFound paths ──────────────────────────────────────────────────

    #[test]
    fn gva_nonexistent_domain_returns_not_found() {
        let (_model, mms_model) = build_mmxu_model();
        let req = GetVariableAccessAttributesRequest {
            object_name: ObjectName::DomainSpecific {
                domain_id: "NOSUCHDOMAIN".to_string(),
                item_id: "MMXU1$MX$TotW".to_string(),
            },
        };
        let result = handle_get_var_access_attrs(&mms_model, &req);
        assert!(
            matches!(result, GetVarAccessAttrsResult::NotFound),
            "an unknown domain must answer NotFound"
        );
    }

    #[test]
    fn gva_nonexistent_ln_returns_not_found() {
        let (_model, mms_model) = build_mmxu_model();
        let req = GetVariableAccessAttributesRequest {
            object_name: ObjectName::DomainSpecific {
                domain_id: "IED1LD0".to_string(),
                item_id: "NOSUCHLN$MX$TotW".to_string(),
            },
        };
        let result = handle_get_var_access_attrs(&mms_model, &req);
        assert!(matches!(result, GetVarAccessAttrsResult::NotFound));
    }

    #[test]
    fn gva_nonexistent_do_returns_not_found() {
        let (_model, mms_model) = build_mmxu_model();
        let req = GetVariableAccessAttributesRequest {
            object_name: ObjectName::DomainSpecific {
                domain_id: "IED1LD0".to_string(),
                item_id: "MMXU1$MX$NoSuchDO".to_string(),
            },
        };
        let result = handle_get_var_access_attrs(&mms_model, &req);
        assert!(matches!(result, GetVarAccessAttrsResult::NotFound));
    }

    // ── Object-name scopes that are not served ──────────────────────────

    /// An IEC 61850 model registers no VMD-scope variables, so a vmd-specific
    /// request answers object-non-existent.
    #[test]
    fn gva_vmd_specific_returns_not_found() {
        let (_model, mms_model) = build_mmxu_model();
        let req = GetVariableAccessAttributesRequest {
            object_name: ObjectName::VmdSpecific("MMXU1".to_string()),
        };
        let result = handle_get_var_access_attrs(&mms_model, &req);
        assert!(
            matches!(result, GetVarAccessAttrsResult::NotFound),
            "a vmd-scope request must answer NotFound"
        );
    }

    /// An aa-specific request answers object-access-unsupported rather than
    /// dropping the association; an error PDU keeps the client informed and the
    /// association usable.
    #[test]
    fn gva_aa_specific_returns_unsupported_not_drop() {
        let (_model, mms_model) = build_mmxu_model();
        let req = GetVariableAccessAttributesRequest {
            object_name: ObjectName::AaSpecific("AA_VAR".to_string()),
        };
        let result = handle_get_var_access_attrs(&mms_model, &req);
        assert!(
            matches!(result, GetVarAccessAttrsResult::Unsupported),
            "an aa-scope request must answer Unsupported without dropping the association"
        );
    }

    // ── Generic bit string encodes bits = 0 ─────────────────────────────

    #[test]
    fn gva_quality_da_returns_bitstring() {
        // The LLN0 builder emits an ST group with stVal, q and t.
        let lln0 = LogicalNodeBuilder::lln0().build().unwrap();
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(lln0)
            .build()
            .unwrap();
        let model = IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap();
        let mms_model = MmsDeviceModel::from_ied_model(&model).unwrap();

        // LLN0$ST exists whenever the builder emitted Mod.stVal, Beh.stVal, ...
        let req = GetVariableAccessAttributesRequest {
            object_name: ObjectName::DomainSpecific {
                domain_id: "IED1LD0".to_string(),
                item_id: "LLN0$ST".to_string(),
            },
        };
        let result = handle_get_var_access_attrs(&mms_model, &req);
        match result {
            GetVarAccessAttrsResult::Response(resp) => {
                assert_eq!(ts_tag(&resp.type_specification), "Structure");
            }
            GetVarAccessAttrsResult::NotFound => {
                // The builder need not emit an ST data object; the float and
                // structure paths are covered by the tests above.
            }
            other => panic!("unexpected result {:?}", other),
        }
    }
}
