//! Server handler for the GetNameList service of IEC 61850-7-2.
//!
//! Access is allowed by default: with no directory access handler installed,
//! every request is answered. Both VMD-scope domain names and domain-scope
//! named-variable names are sorted alphabetically before paging, so the order a
//! client sees does not depend on the order the model was built in.
//!
//! Paging starts at the name after `continueAfter`, which is itself excluded,
//! and returns at most `PAGE_SIZE` names; anything left sets `more_follows`. A
//! `continueAfter` that is not in the list, and a domain that does not exist,
//! are both answered with object-non-existent.

#[cfg(not(feature = "std"))]
use alloc::string::{String, ToString};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::mapping::MmsDeviceModel;
use iec61850_mms::mms::pdu::get_name_list::{
    GetNameListRequest, GetNameListResponse, ObjectClass, ObjectScope,
};

/// Largest number of names one GetNameList response carries.
///
/// 100 names keep a response inside a typical negotiated PDU size.
const PAGE_SIZE: usize = 100;

/// Outcome of a GetNameList request.
#[derive(Debug)]
pub enum GetNameListResult {
    /// One page of names, together with the `more_follows` flag.
    Response(GetNameListResponse),
    /// The named domain does not exist, or `continueAfter` is not in the list.
    ///
    /// Maps to the MMS object-non-existent error.
    NotFound,
    /// The combination of object class and object scope is not served.
    ///
    /// Maps to data access error object-access-unsupported.
    Unsupported,
}

/// Answers a GetNameList request, merging `extras` into whichever domain-scope
/// list the request asks for.
///
/// `extras` are the names of the objects the server has registered: the GOOSE,
/// report and log control blocks of the domain for object class
/// `NamedVariable`, its data sets for `NamedVariableList`. A control block or
/// data set exists only once it is registered — the read paths resolve it
/// through those same registries — so registration, not the model, is what puts
/// a name in the answer.
///
/// The extras are merged into the model's named variables, deduplicated, sorted
/// together, and only then paged. A `NamedVariableList` answer is built from
/// the extras alone, since the model contributes no named variable lists.
/// Every other class and scope combination behaves exactly as
/// [`handle_get_name_list`], and an empty `extras` leaves even that path
/// unchanged.
pub fn handle_get_name_list_with_extras(
    model: &MmsDeviceModel,
    req: &GetNameListRequest,
    extras: &[String],
) -> GetNameListResult {
    if extras.is_empty() {
        return handle_get_name_list(model, req);
    }
    let (domain, names) = match (&req.object_class, &req.object_scope) {
        (ObjectClass::NamedVariable, ObjectScope::DomainSpecific(d)) => {
            (d, model.list_named_variables_flat(d))
        }
        // `list_named_variables` only serves to test that the domain exists;
        // every name of this class comes from the registry.
        (ObjectClass::NamedVariableList, ObjectScope::DomainSpecific(d)) => (
            d,
            model.list_named_variables(d).map(|_| Vec::<String>::new()),
        ),
        _ => return handle_get_name_list(model, req),
    };
    let Some(names) = names else {
        tracing::warn!(
            domain = %domain,
            "get-name-list: no such domain, answering object-non-existent"
        );
        return GetNameListResult::NotFound;
    };
    match merged_page(names, extras, req.continue_after.as_deref()) {
        Some(resp) => GetNameListResult::Response(resp),
        None => {
            tracing::warn!(
                domain = %domain,
                continue_after = ?req.continue_after,
                "get-name-list: continueAfter is not in the name list, answering object-non-existent"
            );
            GetNameListResult::NotFound
        }
    }
}

/// Answers a GetNameList request with one page of names.
///
/// No request is refused at this layer; access control belongs to a directory
/// access handler above it. Both VMD-scope domain names and domain-scope
/// named-variable names are sorted alphabetically before paging.
pub fn handle_get_name_list(model: &MmsDeviceModel, req: &GetNameListRequest) -> GetNameListResult {
    match (&req.object_class, &req.object_scope) {
        // Every logical device becomes one MMS domain name, sorted
        // alphabetically per IEC 61850-8-1 §9.2.
        (ObjectClass::Domain, ObjectScope::VmdSpecific) => {
            let domains: Vec<String> = model.list_domains().map(|s| s.to_string()).collect();
            match merged_page(domains, &[], req.continue_after.as_deref()) {
                Some(resp) => GetNameListResult::Response(resp),
                None => {
                    tracing::warn!(
                        continue_after = ?req.continue_after,
                        "get-name-list: continueAfter is not in the domain list, answering object-non-existent"
                    );
                    GetNameListResult::NotFound
                }
            }
        }

        // The reply carries every component path of the domain flattened out
        // (`LN`, `LN$FC`, `LN$FC$DO`, ...), not just the top-level logical node
        // names: a model-driven client recognizes a functional-constraint node
        // from the `LN$FC` level and mistypes it if only bare node names arrive.
        (ObjectClass::NamedVariable, ObjectScope::DomainSpecific(domain)) => {
            let Some(names) = model.list_named_variables_flat(domain) else {
                tracing::warn!(
                    domain = %domain,
                    "get-name-list: no such domain, answering object-non-existent"
                );
                return GetNameListResult::NotFound;
            };
            match merged_page(names, &[], req.continue_after.as_deref()) {
                Some(resp) => GetNameListResult::Response(resp),
                None => {
                    tracing::warn!(
                        domain = %domain,
                        continue_after = ?req.continue_after,
                        "get-name-list: continueAfter is not in the name list, answering object-non-existent"
                    );
                    GetNameListResult::NotFound
                }
            }
        }

        // An IEC 61850 model holds no VMD-scope named variables.
        (ObjectClass::NamedVariable, ObjectScope::VmdSpecific) => {
            tracing::debug!("get-name-list: no vmd-scope named variables, answering an empty list");
            GetNameListResult::Response(GetNameListResponse {
                identifiers: vec![],
                more_follows: false,
            })
        }

        // A domain contains no domains, so this combination has no members.
        (ObjectClass::Domain, ObjectScope::DomainSpecific(_)) => {
            tracing::debug!("get-name-list: a domain holds no domains, answering an empty list");
            GetNameListResult::Response(GetNameListResponse {
                identifiers: vec![],
                more_follows: false,
            })
        }

        // A data set exists only once it is registered, and this entry point
        // sees no registry, so an existing domain answers with an empty list;
        // the registered names arrive through
        // [`handle_get_name_list_with_extras`]. A missing domain answers
        // object-non-existent. A browsing client lists the data sets of every
        // domain, so answering object-access-unsupported here would abort the
        // whole traversal.
        (ObjectClass::NamedVariableList, ObjectScope::DomainSpecific(domain)) => {
            // list_named_variables only serves to test that the domain exists.
            if model.list_named_variables(domain).is_none() {
                tracing::warn!(
                    domain = %domain,
                    "get-name-list: no such domain, answering object-non-existent"
                );
                return GetNameListResult::NotFound;
            }
            tracing::debug!(
                domain = %domain,
                "get-name-list: no data sets are registered, answering an empty list"
            );
            GetNameListResult::Response(GetNameListResponse {
                identifiers: vec![],
                more_follows: false,
            })
        }

        // Neither the model nor an association declares a VMD-scope or
        // association-scope data set; an empty list is a valid answer.
        (ObjectClass::NamedVariableList, ObjectScope::VmdSpecific)
        | (ObjectClass::NamedVariableList, ObjectScope::AaSpecific) => {
            tracing::debug!(
                scope = ?req.object_scope,
                "get-name-list: no data sets in this scope, answering an empty list"
            );
            GetNameListResult::Response(GetNameListResponse {
                identifiers: vec![],
                more_follows: false,
            })
        }

        // Journals are enumerated by the log service, not by this handler.
        (ObjectClass::Journal, _) => {
            tracing::debug!(
                scope = ?req.object_scope,
                "get-name-list: no journals in this scope, answering an empty list"
            );
            GetNameListResult::Response(GetNameListResponse {
                identifiers: vec![],
                more_follows: false,
            })
        }

        // No object is scoped to a single association.
        (_, ObjectScope::AaSpecific) => {
            tracing::debug!(
                object_class = ?req.object_class,
                "get-name-list: no association-scope objects, answering an empty list"
            );
            GetNameListResult::Response(GetNameListResponse {
                identifiers: vec![],
                more_follows: false,
            })
        }
    }
}

/// Merges `extras` into `names`, sorts the result alphabetically per
/// IEC 61850-8-1 §9.2, and returns one page of it.
///
/// A name already in `names` is not repeated, so a control block or data set
/// that both the model declares and the runtime registers appears once.
/// `None` means `continue_after` is not in the merged list, which the caller
/// reports as object-non-existent.
fn merged_page(
    mut names: Vec<String>,
    extras: &[String],
    continue_after: Option<&str>,
) -> Option<GetNameListResponse> {
    for e in extras {
        if !names.iter().any(|n| n == e) {
            names.push(e.clone());
        }
    }
    names.sort_unstable();
    let (identifiers, more_follows) = paginate(names, continue_after)?;
    Some(GetNameListResponse {
        identifiers,
        more_follows,
    })
}

/// Takes at most `PAGE_SIZE` names starting after `continue_after`, which is
/// itself excluded.
///
/// Returns the page and whether more names remain. `None` for `continue_after`
/// starts at the beginning. A `continue_after` that is not in the list yields
/// `None`, which the caller reports as object-non-existent, rather than
/// silently restarting from the beginning.
fn paginate(names: Vec<String>, continue_after: Option<&str>) -> Option<(Vec<String>, bool)> {
    let start_idx = match continue_after {
        None => 0,
        Some(ca) => names.iter().position(|n| n == ca).map(|i| i + 1).or(None)?,
    };

    let remaining = &names[start_idx..];
    if remaining.len() <= PAGE_SIZE {
        Some((remaining.to_vec(), false))
    } else {
        Some((remaining[..PAGE_SIZE].to_vec(), true))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use iec61850_model::{IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder};

    fn build_test_model() -> (iec61850_model::IedModel, MmsDeviceModel) {
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
        (model, mms_model)
    }

    fn build_model_with_two_lds() -> (iec61850_model::IedModel, MmsDeviceModel) {
        let lln0a = LogicalNodeBuilder::lln0().build().unwrap();
        let lln0b = LogicalNodeBuilder::lln0().build().unwrap();
        let lda = LogicalDeviceBuilder::new("LDA")
            .add_ln(lln0a)
            .build()
            .unwrap();
        let ldb = LogicalDeviceBuilder::new("LDB")
            .add_ln(lln0b)
            .build()
            .unwrap();
        let model = IedModelBuilder::new("IED1")
            .add_ld(lda)
            .unwrap()
            .add_ld(ldb)
            .unwrap()
            .build()
            .unwrap();
        let mms_model = MmsDeviceModel::from_ied_model(&model).unwrap();
        (model, mms_model)
    }

    /// Builds a model whose two logical devices are inserted in reverse
    /// alphabetical order, so that a sorted result cannot come from the
    /// insertion order.
    fn build_model_with_reversed_lds() -> (iec61850_model::IedModel, MmsDeviceModel) {
        let lln0b = LogicalNodeBuilder::lln0().build().unwrap();
        let lln0a = LogicalNodeBuilder::lln0().build().unwrap();
        let ldb = LogicalDeviceBuilder::new("LDB")
            .add_ln(lln0b)
            .build()
            .unwrap();
        let lda = LogicalDeviceBuilder::new("LDA")
            .add_ln(lln0a)
            .build()
            .unwrap();
        let model = IedModelBuilder::new("IED1")
            .add_ld(ldb)
            .unwrap()
            .add_ld(lda)
            .unwrap()
            .build()
            .unwrap();
        let mms_model = MmsDeviceModel::from_ied_model(&model).unwrap();
        (model, mms_model)
    }

    // ── VMD-scope Domain happy path ───────────────────────────────────────

    #[test]
    fn gnl_vmd_domain_returns_all_ld_names() {
        let (_model, mms_model) = build_test_model();
        let req = GetNameListRequest {
            object_class: ObjectClass::Domain,
            object_scope: ObjectScope::VmdSpecific,
            continue_after: None,
        };
        let result = handle_get_name_list(&mms_model, &req);
        match result {
            GetNameListResult::Response(resp) => {
                assert_eq!(resp.identifiers, vec!["IED1LD0"]);
                assert!(!resp.more_follows);
            }
            other => panic!("expected a response, got {:?}", other),
        }
    }

    #[test]
    fn gnl_vmd_domain_two_lds() {
        let (_model, mms_model) = build_model_with_two_lds();
        let req = GetNameListRequest {
            object_class: ObjectClass::Domain,
            object_scope: ObjectScope::VmdSpecific,
            continue_after: None,
        };
        let result = handle_get_name_list(&mms_model, &req);
        match result {
            GetNameListResult::Response(resp) => {
                assert_eq!(resp.identifiers.len(), 2);
                assert!(!resp.more_follows);
            }
            other => panic!("expected a response, got {:?}", other),
        }
    }

    // ── VMD-scope domain list is sorted alphabetically ──────────────────
    //
    // The VMD-scope branch sorts its result just like the domain-scope branch,
    // per IEC 61850-8-1 §9.2.

    #[test]
    fn gnl_vmd_domain_list_sorted_alphabetically_regardless_of_insertion_order() {
        // LDB is inserted first, LDA second; the reply must still be sorted.
        let (_model, mms_model) = build_model_with_reversed_lds();
        let req = GetNameListRequest {
            object_class: ObjectClass::Domain,
            object_scope: ObjectScope::VmdSpecific,
            continue_after: None,
        };
        let result = handle_get_name_list(&mms_model, &req);
        match result {
            GetNameListResult::Response(resp) => {
                assert_eq!(
                    resp.identifiers,
                    vec!["IED1LDA".to_string(), "IED1LDB".to_string()],
                    "a vmd-scope domain list must be sorted alphabetically, per IEC 61850-8-1 §9.2"
                );
                assert!(!resp.more_follows);
            }
            other => panic!("expected a response, got {:?}", other),
        }
    }

    // ── Domain-scope NamedVariable happy path ─────────────────────────────

    #[test]
    fn gnl_domain_named_variable_returns_ln_names() {
        let (_model, mms_model) = build_test_model();
        let req = GetNameListRequest {
            object_class: ObjectClass::NamedVariable,
            object_scope: ObjectScope::DomainSpecific("IED1LD0".to_string()),
            continue_after: None,
        };
        let result = handle_get_name_list(&mms_model, &req);
        match result {
            GetNameListResult::Response(resp) => {
                assert!(!resp.identifiers.is_empty());
                assert!(resp.identifiers.contains(&"LLN0".to_string()));
                assert!(!resp.more_follows);
            }
            other => panic!("expected a response, got {:?}", other),
        }
    }

    /// A domain-scope NamedVariable request must answer with every component
    /// path flattened out (`LN`, `LN$FC`, `LN$FC$DO`, `LN$FC$DO$DA`, ...), not
    /// only the top-level logical node names.
    ///
    /// Model-driven clients depend on this shape:
    /// a client identifies a functional-constraint node from the `LN$FC` level,
    /// and bare node names make it build the constraint as an ordinary data
    /// node, which fails when it constructs the object tree.
    #[test]
    fn gnl_domain_named_variable_returns_flattened_component_paths() {
        // GGIO1 carries one SPS (Ind1: stVal, q, t under ST) and one MV
        // (AnIn1: mag.f under MX).
        let ggio = iec61850_model::LogicalNodeBuilder::new("", "GGIO", "1")
            .add_do(iec61850_model::cdc::sps(
                "Ind1",
                iec61850_model::CdcOptions::NONE,
            ))
            .add_do(iec61850_model::cdc::mv(
                "AnIn1",
                iec61850_model::CdcOptions::NONE,
                false,
            ))
            .build()
            .unwrap();
        let lln0 = LogicalNodeBuilder::lln0().build().unwrap();
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(lln0)
            .add_ln(ggio)
            .build()
            .unwrap();
        let model = IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap();
        let mms_model = MmsDeviceModel::from_ied_model(&model).unwrap();

        let req = GetNameListRequest {
            object_class: ObjectClass::NamedVariable,
            object_scope: ObjectScope::DomainSpecific("IED1LD0".to_string()),
            continue_after: None,
        };
        let result = handle_get_name_list(&mms_model, &req);
        let resp = match result {
            GetNameListResult::Response(resp) => resp,
            other => panic!("expected a response, got {:?}", other),
        };
        for expected in [
            "GGIO1",
            "GGIO1$MX",
            "GGIO1$MX$AnIn1",
            "GGIO1$MX$AnIn1$mag",
            "GGIO1$MX$AnIn1$mag$f",
            "GGIO1$ST",
            "GGIO1$ST$Ind1",
            "GGIO1$ST$Ind1$stVal",
        ] {
            assert!(
                resp.identifiers.iter().any(|i| i == expected),
                "the flattened list is missing {expected}, got {:?}",
                resp.identifiers
            );
        }
    }

    #[test]
    fn gnl_domain_named_variable_sorted_alphabetically() {
        // Domain-scope names are sorted alphabetically, per IEC 61850-8-1 §9.2.
        let (_model, mms_model) = build_model_with_two_lds();
        let req = GetNameListRequest {
            object_class: ObjectClass::NamedVariable,
            object_scope: ObjectScope::DomainSpecific("IED1LDA".to_string()),
            continue_after: None,
        };
        let result = handle_get_name_list(&mms_model, &req);
        match result {
            GetNameListResult::Response(resp) => {
                let sorted = {
                    let mut s = resp.identifiers.clone();
                    s.sort();
                    s
                };
                assert_eq!(
                    resp.identifiers, sorted,
                    "domain-scope names must be sorted alphabetically"
                );
            }
            other => panic!("expected a response, got {:?}", other),
        }
    }

    // ── Access is allowed by default ────────────────────────────────────

    #[test]
    fn gnl_default_allow_no_access_handler_needed() {
        // A request is answered even with no directory access handler.
        let (_model, mms_model) = build_test_model();
        let req = GetNameListRequest {
            object_class: ObjectClass::Domain,
            object_scope: ObjectScope::VmdSpecific,
            continue_after: None,
        };
        let result = handle_get_name_list(&mms_model, &req);
        assert!(
            matches!(result, GetNameListResult::Response(_)),
            "a request must be answered with no access handler installed"
        );
    }

    // ── A missing domain answers object-non-existent ────────────────────
    //
    // The handler reports NotFound and the dispatcher turns it into a
    // ConfirmedError.

    #[test]
    fn gnl_nonexistent_domain_returns_not_found() {
        let (_model, mms_model) = build_test_model();
        let req = GetNameListRequest {
            object_class: ObjectClass::NamedVariable,
            object_scope: ObjectScope::DomainSpecific("NOSUCHDOMAIN".to_string()),
            continue_after: None,
        };
        let result = handle_get_name_list(&mms_model, &req);
        assert!(
            matches!(result, GetNameListResult::NotFound),
            "an unknown domain must answer NotFound"
        );
    }

    // ── Object classes with no members answer an empty list ─────────────

    /// A browsing client lists the data sets of every domain, so an unsupported
    /// answer here aborts the traversal. With no data sets declared, the
    /// correct answer is an empty identifier list.
    #[test]
    fn gnl_named_variable_list_vmd_returns_empty_list() {
        let (_model, mms_model) = build_test_model();
        let req = GetNameListRequest {
            object_class: ObjectClass::NamedVariableList,
            object_scope: ObjectScope::VmdSpecific,
            continue_after: None,
        };
        let result = handle_get_name_list(&mms_model, &req);
        match result {
            GetNameListResult::Response(resp) => {
                assert!(
                    resp.identifiers.is_empty(),
                    "a vmd-scope named variable list must be empty"
                );
                assert!(!resp.more_follows);
            }
            other => panic!("expected an empty response, got {:?}", other),
        }
    }

    /// An existing domain with no data sets answers an empty list.
    #[test]
    fn gnl_named_variable_list_domain_existing_returns_empty_list() {
        let (_model, mms_model) = build_test_model();
        let req = GetNameListRequest {
            object_class: ObjectClass::NamedVariableList,
            object_scope: ObjectScope::DomainSpecific("IED1LD0".into()),
            continue_after: None,
        };
        let result = handle_get_name_list(&mms_model, &req);
        match result {
            GetNameListResult::Response(resp) => {
                assert!(
                    resp.identifiers.is_empty(),
                    "a domain with no data sets must answer an empty list"
                );
            }
            other => panic!("expected an empty response, got {:?}", other),
        }
    }

    /// A missing domain answers NotFound, as it does for NamedVariable.
    #[test]
    fn gnl_named_variable_list_nonexistent_domain_returns_not_found() {
        let (_model, mms_model) = build_test_model();
        let req = GetNameListRequest {
            object_class: ObjectClass::NamedVariableList,
            object_scope: ObjectScope::DomainSpecific("NOSUCHDOMAIN".into()),
            continue_after: None,
        };
        let result = handle_get_name_list(&mms_model, &req);
        assert!(matches!(result, GetNameListResult::NotFound));
    }

    /// With no journals declared, the Journal class answers an empty list.
    #[test]
    fn gnl_journal_returns_empty_list() {
        let (_model, mms_model) = build_test_model();
        let req = GetNameListRequest {
            object_class: ObjectClass::Journal,
            object_scope: ObjectScope::VmdSpecific,
            continue_after: None,
        };
        let result = handle_get_name_list(&mms_model, &req);
        match result {
            GetNameListResult::Response(resp) => {
                assert!(
                    resp.identifiers.is_empty(),
                    "the journal list must be empty"
                );
            }
            other => panic!("expected an empty response, got {:?}", other),
        }
    }

    /// No object is scoped to a single association, so aa-scope is empty.
    #[test]
    fn gnl_aa_specific_scope_returns_empty_list() {
        let (_model, mms_model) = build_test_model();
        let req = GetNameListRequest {
            object_class: ObjectClass::NamedVariable,
            object_scope: ObjectScope::AaSpecific,
            continue_after: None,
        };
        let result = handle_get_name_list(&mms_model, &req);
        match result {
            GetNameListResult::Response(resp) => {
                assert!(
                    resp.identifiers.is_empty(),
                    "an aa-scope list must be empty"
                );
            }
            other => panic!("expected an empty response, got {:?}", other),
        }
    }

    // ── Merging the registry names into the model's ─────────────────────
    //
    // merged_page is the single funnel for every name list, so the properties
    // that hold across the seam between model-derived and registry-derived
    // names are pinned here rather than only end to end.

    fn owned(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    /// `continueAfter` naming a registry-derived name resumes at the next name
    /// of the union, which is model-derived.
    #[test]
    fn merged_page_continue_after_an_extra_resumes_into_the_model_names() {
        let names = owned(&["LLN0", "MMXU1"]);
        let extras = owned(&["LLN0$RP$urcb1"]);
        let resp = merged_page(names, &extras, Some("LLN0$RP$urcb1"))
            .expect("a continueAfter that is in the union must produce a page");
        assert_eq!(resp.identifiers, owned(&["MMXU1"]));
        assert!(!resp.more_follows);
    }

    /// `continueAfter` naming a model-derived name that sorts after an extra
    /// resumes at the next name, which is registry-derived.
    #[test]
    fn merged_page_continue_after_a_model_name_resumes_into_the_extras() {
        let names = owned(&["LLN0", "MMXU1"]);
        let extras = owned(&["LLN0$RP$urcb1", "MMXU1$BR$brcb1"]);
        let resp = merged_page(names, &extras, Some("MMXU1"))
            .expect("a continueAfter that is in the union must produce a page");
        assert_eq!(resp.identifiers, owned(&["MMXU1$BR$brcb1"]));
        assert!(!resp.more_follows);
    }

    /// A page boundary that falls inside the merged portion sets
    /// `more_follows`, and the second page holds the remainder exactly once.
    #[test]
    fn merged_page_boundary_inside_the_merged_portion_pages_without_loss() {
        // Even names are model-derived, odd names registry-derived, so the
        // sorted union alternates between the two sources and the boundary at
        // index 100 falls between an extra and a model name.
        let names: Vec<String> = (0..105).step_by(2).map(|i| format!("N{i:03}")).collect();
        let extras: Vec<String> = (1..105).step_by(2).map(|i| format!("N{i:03}")).collect();
        assert_eq!(names.len() + extras.len(), PAGE_SIZE + 5);

        let first = merged_page(names.clone(), &extras, None).expect("the first page");
        assert_eq!(first.identifiers.len(), PAGE_SIZE);
        assert!(
            first.more_follows,
            "a union longer than one page must set more_follows"
        );

        let last = first.identifiers.last().unwrap().clone();
        let second = merged_page(names, &extras, Some(&last)).expect("the second page");
        assert_eq!(
            second.identifiers,
            owned(&["N100", "N101", "N102", "N103", "N104"])
        );
        assert!(!second.more_follows);

        // Every name appears exactly once across the two pages.
        let mut all = first.identifiers;
        all.extend(second.identifiers);
        let mut deduped = all.clone();
        deduped.dedup();
        assert_eq!(all, deduped, "no name may be repeated across pages");
        assert_eq!(all.len(), PAGE_SIZE + 5);
    }

    /// A `<LN>$LG$<name>` log control block sorts into the union like any other
    /// registry-derived name, between the logical node that owns it and the
    /// next logical node.
    #[test]
    fn merged_page_sorts_a_log_control_block_name_among_the_model_names() {
        let names = owned(&["LLN0", "MMXU1"]);
        let extras = owned(&["LLN0$LG$evlog"]);
        let resp = merged_page(names, &extras, None).expect("a page");
        assert_eq!(resp.identifiers, owned(&["LLN0", "LLN0$LG$evlog", "MMXU1"]));
        assert!(!resp.more_follows);
    }

    /// A name in both sources is listed once.
    #[test]
    fn merged_page_does_not_repeat_a_name_present_in_both_sources() {
        let names = owned(&["LLN0", "LLN0$RP$urcb1"]);
        let extras = owned(&["LLN0$RP$urcb1", "LLN0$RP$urcb1"]);
        let resp = merged_page(names, &extras, None).expect("a page");
        assert_eq!(resp.identifiers, owned(&["LLN0", "LLN0$RP$urcb1"]));
    }

    /// A named-variable-list answer is built from the registry names alone: no
    /// logical node name and no `LN$FC$DO` path leaks in from the named
    /// variables of the same domain.
    #[test]
    fn gnl_named_variable_list_with_extras_carries_only_the_registry_names() {
        let (_model, mms_model) = build_test_model();
        let extras = owned(&["LLN0$dsMeas", "LLN0$dsStatus"]);
        let req = GetNameListRequest {
            object_class: ObjectClass::NamedVariableList,
            object_scope: ObjectScope::DomainSpecific("IED1LD0".into()),
            continue_after: None,
        };
        match handle_get_name_list_with_extras(&mms_model, &req, &extras) {
            GetNameListResult::Response(resp) => {
                assert_eq!(resp.identifiers, owned(&["LLN0$dsMeas", "LLN0$dsStatus"]));
            }
            other => panic!("expected a response, got {other:?}"),
        }
    }

    /// The named-variable answer keeps the model's own names and adds the
    /// registry ones.
    #[test]
    fn gnl_named_variable_with_extras_carries_both_sources() {
        let (_model, mms_model) = build_test_model();
        let extras = owned(&["LLN0$RP$urcbMeas"]);
        let req = GetNameListRequest {
            object_class: ObjectClass::NamedVariable,
            object_scope: ObjectScope::DomainSpecific("IED1LD0".into()),
            continue_after: None,
        };
        match handle_get_name_list_with_extras(&mms_model, &req, &extras) {
            GetNameListResult::Response(resp) => {
                assert!(resp.identifiers.contains(&"LLN0".to_string()));
                assert!(resp.identifiers.contains(&"LLN0$RP$urcbMeas".to_string()));
            }
            other => panic!("expected a response, got {other:?}"),
        }
    }

    /// A log control block name reaches the named-variable answer on the same
    /// path as a report control block, and the two sort together.
    #[test]
    fn gnl_named_variable_with_extras_carries_a_log_control_block() {
        let (_model, mms_model) = build_test_model();
        let extras = owned(&["LLN0$LG$evlog", "LLN0$RP$urcbMeas"]);
        let req = GetNameListRequest {
            object_class: ObjectClass::NamedVariable,
            object_scope: ObjectScope::DomainSpecific("IED1LD0".into()),
            continue_after: None,
        };
        match handle_get_name_list_with_extras(&mms_model, &req, &extras) {
            GetNameListResult::Response(resp) => {
                let lg = resp.identifiers.iter().position(|n| n == "LLN0$LG$evlog");
                let rp = resp
                    .identifiers
                    .iter()
                    .position(|n| n == "LLN0$RP$urcbMeas");
                assert!(
                    lg.is_some() && rp.is_some(),
                    "both registry names must be listed, got {:?}",
                    resp.identifiers
                );
                assert!(lg < rp, "the merged list must be sorted alphabetically");
            }
            other => panic!("expected a response, got {other:?}"),
        }
    }

    /// An unknown domain answers object-non-existent on the extras path too.
    #[test]
    fn gnl_with_extras_unknown_domain_returns_not_found() {
        let (_model, mms_model) = build_test_model();
        let extras = owned(&["LLN0$dsMeas"]);
        for class in [ObjectClass::NamedVariable, ObjectClass::NamedVariableList] {
            let req = GetNameListRequest {
                object_class: class,
                object_scope: ObjectScope::DomainSpecific("NOSUCHDOMAIN".into()),
                continue_after: None,
            };
            let result = handle_get_name_list_with_extras(&mms_model, &req, &extras);
            assert!(matches!(result, GetNameListResult::NotFound));
        }
    }

    // ── continueAfter paging ────────────────────────────────────────────

    #[test]
    fn paginate_no_continue_after() {
        let names: Vec<String> = (0..5).map(|i| format!("N{}", i)).collect();
        let result = paginate(names.clone(), None);
        let (page, more) = result.expect("an absent continueAfter must page from the start");
        assert_eq!(page, names);
        assert!(!more);
    }

    #[test]
    fn paginate_continue_after_existing() {
        let names = vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
            "D".to_string(),
        ];
        let result = paginate(names, Some("B"));
        let (page, more) = result.expect("a continueAfter that exists must produce a page");
        assert_eq!(page, vec!["C".to_string(), "D".to_string()]);
        assert!(!more);
    }

    // ── An unknown continueAfter answers object-non-existent ────────────
    //
    // Paging yields None rather than restarting from the beginning, and the
    // caller turns that into object-non-existent.

    #[test]
    fn paginate_continue_after_nonexistent_returns_none() {
        let names = vec!["A".to_string(), "B".to_string()];
        let result = paginate(names, Some("NOTEXIST"));
        assert!(
            result.is_none(),
            "an unknown continueAfter must yield None, not a page from the start"
        );
    }

    #[test]
    fn gnl_domain_continue_after_nonexistent_returns_not_found() {
        let (_model, mms_model) = build_test_model();
        let req = GetNameListRequest {
            object_class: ObjectClass::NamedVariable,
            object_scope: ObjectScope::DomainSpecific("IED1LD0".to_string()),
            continue_after: Some("NOTEXIST".to_string()),
        };
        let result = handle_get_name_list(&mms_model, &req);
        assert!(
            matches!(result, GetNameListResult::NotFound),
            "an unknown continueAfter must answer NotFound"
        );
    }

    #[test]
    fn gnl_vmd_domain_continue_after_nonexistent_returns_not_found() {
        let (_model, mms_model) = build_test_model();
        let req = GetNameListRequest {
            object_class: ObjectClass::Domain,
            object_scope: ObjectScope::VmdSpecific,
            continue_after: Some("NOTEXIST".to_string()),
        };
        let result = handle_get_name_list(&mms_model, &req);
        assert!(
            matches!(result, GetNameListResult::NotFound),
            "an unknown continueAfter in a vmd-scope list must answer NotFound"
        );
    }

    #[test]
    fn paginate_more_follows_when_exceeds_page_size() {
        let names: Vec<String> = (0..=PAGE_SIZE).map(|i| format!("N{:03}", i)).collect();
        let result = paginate(names, None);
        let (page, more) = result.expect("paging from the start must produce a page");
        assert_eq!(page.len(), PAGE_SIZE);
        assert!(more, "a list longer than one page must set more_follows");
    }
}
