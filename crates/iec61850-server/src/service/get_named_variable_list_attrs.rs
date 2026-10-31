//! Server handler for the MMS GetNamedVariableListAttributes service, the
//! mapping of the IEC 61850-7-2 GetDataSetDirectory request.
//!
//! The request names one data set; the response carries its members in
//! registration order, each as the MMS variable `<domain>` and
//! `<LN>$<FC>$<DO>[$<SDO>...][$<DA>[$<SDA>...]]` the entry holds, together with
//! `mmsDeletable`. A member naming a data object is listed by that name, as
//! the FCD it is, not as the attributes beneath it.
//!
//! ## mmsDeletable
//!
//! True exactly when the data set is in the dynamic-key set, that is when it
//! was created by DefineNamedVariableList. A configured data set is not
//! deletable, which is the same source DeleteNamedVariableList consults before
//! removing one.
//!
//! ## Scope
//!
//! Only domain-specific list names are served, matching the reporting engine
//! and the DefineNamedVariableList handler; a vmd-specific or aa-specific name
//! decodes but is answered with `ObjectAccessUnsupported`. A name absent from
//! the registry is answered with `ObjectNonExistent`.
//!
//! ## Member references
//!
//! A `DatasetEntry` holds `"<domain>/<LN>$<FC>$<DO>[$...]"`. An entry
//! without that separator violates the registry contract and is answered with
//! an access error rather than emitted as a reference the client cannot
//! resolve.
//!
//! A member naming an element of an array holds the reference reports carry,
//! the index after the array name, `<LN>$<FC>$...$<array>(<n>)[$<component>...]`
//! (IEC 61850-8-1 §8.1.3.2.4). It is listed as the variable that names the
//! array, with an alternate access selecting the index and then each component,
//! the form IEC 61850-8-1 §7.3.3, §7.3.4 and §24.2.2.4.1.3 Table 140 give the
//! reference of an array element. A member naming a whole array is listed by
//! its name alone.
//!
//! ## Response size
//!
//! The member list grows with the data set, so a response can outgrow the
//! maximum PDU size negotiated for the association. The dispatcher's outbound
//! guard measures the encoded response and answers errorClass resource other
//! when it does not fit, so this handler always builds the complete list.

use bytes::BytesMut;

use iec61850_mms::mms::pdu::{
    get_named_variable_list_attrs::{
        encode_confirmed_get_named_variable_list_attrs_response,
        GetNamedVariableListAttributesRequest, GetNamedVariableListAttributesResponse,
    },
    service_error::{
        subcode::{access, resource},
        ErrorClass,
    },
    AlternateAccess, ListOfVariableEntry, ObjectName,
};
use iec61850_mms::mms::server::dispatcher::ConfirmedResponse;

use crate::reporting::DatasetRegistry;
use crate::service::define_named_variable_list::DynamicDatasetKeys;

/// Handles a GetNamedVariableListAttributes request (confirmed service tag 0xac).
pub(crate) fn handle_get_named_variable_list_attributes(
    invoke_id: u32,
    body: &[u8],
    registry: &DatasetRegistry,
    dynamic_keys: &DynamicDatasetKeys,
) -> ConfirmedResponse {
    let req = match GetNamedVariableListAttributesRequest::decode(body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                invoke_id,
                error = %e,
                "get-named-variable-list-attributes request failed to decode, answering confirmed-error"
            );
            return crate::service::make_confirmed_error_pub(
                invoke_id,
                ErrorClass::Access(access::OTHER),
            );
        }
    };

    let (domain, list_name) = match &req.object_name {
        ObjectName::DomainSpecific { domain_id, item_id } => (domain_id.clone(), item_id.clone()),
        other => {
            tracing::warn!(
                invoke_id,
                ?other,
                "get-named-variable-list-attributes accepts only a domain-specific list name, answering object-access-unsupported"
            );
            return crate::service::make_confirmed_error_pub(
                invoke_id,
                ErrorClass::Access(access::OBJECT_ACCESS_UNSUPPORTED),
            );
        }
    };

    let dataset = match registry.read() {
        Ok(guard) => guard.get(&(domain.clone(), list_name.clone())).cloned(),
        Err(_) => {
            tracing::warn!(
                invoke_id,
                "dataset registry lock is poisoned, answering resource error"
            );
            return crate::service::make_confirmed_error_pub(
                invoke_id,
                ErrorClass::Resource(resource::OTHER),
            );
        }
    };

    let Some(dataset) = dataset else {
        tracing::warn!(
            invoke_id,
            domain,
            list_name,
            "get-named-variable-list-attributes names an unknown data set, answering object-non-existent"
        );
        return crate::service::make_confirmed_error_pub(
            invoke_id,
            ErrorClass::Access(access::OBJECT_NON_EXISTENT),
        );
    };

    let mut list_of_variable = Vec::with_capacity(dataset.entries.len());
    for entry in &dataset.entries {
        match member_variable(&entry.attr_ref) {
            Some((name, None)) => list_of_variable.push(ListOfVariableEntry::name(name)),
            Some((name, Some(alt_access))) => {
                list_of_variable.push(ListOfVariableEntry::with_alt_access(name, alt_access));
            }
            None => {
                tracing::warn!(
                    invoke_id,
                    attr_ref = %entry.attr_ref,
                    "data set member reference carries no domain separator, answering access error"
                );
                return crate::service::make_confirmed_error_pub(
                    invoke_id,
                    ErrorClass::Access(access::OTHER),
                );
            }
        }
    }

    let mms_deletable = match dynamic_keys.lock() {
        Ok(keys) => keys.contains(&(domain.clone(), list_name.clone())),
        Err(_) => {
            tracing::warn!(
                invoke_id,
                "dynamic dataset key set is poisoned, reporting the data set as not deletable"
            );
            false
        }
    };

    let resp = GetNamedVariableListAttributesResponse {
        mms_deletable,
        list_of_variable,
    };
    let mut buf = BytesMut::new();
    encode_confirmed_get_named_variable_list_attrs_response(invoke_id, &resp, &mut buf);
    ConfirmedResponse::Response(buf.freeze())
}

/// The MMS variable a data set member reference names, and the alternate
/// access selecting the array element it names, if any.
///
/// `"<domain>/<item>"` with no index names `<item>` itself.
/// `"<domain>/<array>(<n>)"` names `<array>` with an alternate access of index
/// `n`, and `"<domain>/<array>(<n>)$<c1>$<c2>..."` adds the components after
/// the index. A reference whose index does not parse, or that holds a second
/// index, names the item verbatim. Returns `None` when the domain separator is
/// missing or either part is empty.
pub(crate) fn member_variable(attr_ref: &str) -> Option<(ObjectName, Option<AlternateAccess>)> {
    let (domain_id, item_id) = split_attr_ref(attr_ref)?;
    let element = item_id.split_once('(').and_then(|(array, rest)| {
        let (index, components) = rest.split_once(')')?;
        let index: u32 = index.parse().ok()?;
        if array.is_empty() || components.contains(['(', ')']) {
            return None;
        }
        let alt_access = match components.strip_prefix('$') {
            None if components.is_empty() => AlternateAccess::index(index),
            Some(path) => AlternateAccess::index_component(index, path).ok()?,
            None => return None,
        };
        Some((array.to_string(), alt_access))
    });
    Some(match element {
        Some((array, alt_access)) => (
            ObjectName::DomainSpecific {
                domain_id,
                item_id: array,
            },
            Some(alt_access),
        ),
        None => (ObjectName::DomainSpecific { domain_id, item_id }, None),
    })
}

/// Splits `"<domain>/<item>"` into its two parts.
///
/// Returns `None` when the separator is missing or either part is empty.
pub(crate) fn split_attr_ref(attr_ref: &str) -> Option<(String, String)> {
    let (domain, item) = attr_ref.split_once('/')?;
    if domain.is_empty() || item.is_empty() {
        return None;
    }
    Some((domain.to_string(), item.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An element reference names its array with an alternate access of the
    /// index and then the components; other references name themselves.
    #[test]
    fn a_member_reference_names_a_variable_and_its_element() {
        let named = |item: &str| ObjectName::DomainSpecific {
            domain_id: "LD".into(),
            item_id: item.into(),
        };
        assert_eq!(
            member_variable("LD/MHAI1$MX$HA$phsAHar(7)$cVal$mag$f"),
            Some((
                named("MHAI1$MX$HA$phsAHar"),
                Some(AlternateAccess::index_component(7, "cVal$mag$f").unwrap())
            ))
        );
        assert_eq!(
            member_variable("LD/GGIO1$ST$Arr$hstVal(1)"),
            Some((
                named("GGIO1$ST$Arr$hstVal"),
                Some(AlternateAccess::index(1))
            ))
        );
        for item in [
            "GGIO1$ST$Ind1$stVal",
            "GGIO1$ST$Arr$hstVal(x)",
            "GGIO1$ST$Arr(1)$v(2)",
            "GGIO1$ST$Arr(1)v",
        ] {
            assert_eq!(
                member_variable(&format!("LD/{item}")),
                Some((named(item), None)),
                "{item}"
            );
        }
        assert_eq!(member_variable("GGIO1$ST$Ind1"), None);
    }

    #[test]
    fn attr_ref_splits_on_the_first_separator() {
        let (d, i) = split_attr_ref("IED1LD0/GGIO1$ST$Ind1$stVal").expect("split");
        assert_eq!(d, "IED1LD0");
        assert_eq!(i, "GGIO1$ST$Ind1$stVal");
    }

    #[test]
    fn attr_ref_without_separator_is_rejected() {
        assert!(split_attr_ref("GGIO1$ST$Ind1$stVal").is_none());
    }

    #[test]
    fn attr_ref_with_an_empty_part_is_rejected() {
        assert!(split_attr_ref("/GGIO1$ST$Ind1$stVal").is_none());
        assert!(split_attr_ref("IED1LD0/").is_none());
    }
}
