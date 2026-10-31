//! Dynamic data set operations: CreateDataSet and DeleteDataSet of
//! IEC 61850-7-2.
//!
//! Creates and deletes named variable lists at runtime. A member is resolved
//! through the `IedModel` logical node, data object, and data attribute tree, and
//! yields the `Arc<RwLock<MmsValue>>` shared with `DataAttribute::value`, the same
//! handle a statically registered data set uses.
//!
//! A member path is `<LN>$<FC>$<DO>[$<SDO>...]$<DA>[$<SDA>...]`, for example
//! `GGIO1$ST$Ind1$stVal` or `MMXU1$MX$A$phsA$cVal$mag$f`: logical node class
//! and instance, functional constraint, data object name, any number of
//! sub-data-objects, data attribute name, and any sub-attributes nested inside
//! it. The data attribute is matched by name and functional constraint, as
//! IEC 61850-7-2 §13.2.2.3 makes a member a functional-constrained data
//! attribute.
//!
//! A member is one attribute of a basic type. A member that names a data
//! object, a sub-data-object, or a constructed attribute is refused: an entry
//! holds a single value, and the value of such a member lives in the
//! attributes beneath it.
//!
//! Array indices, the `(N)` syntax, are not supported; the `dataset_admin` module
//! of the client crate rejects them before they reach this module.

use std::sync::{Arc, RwLock};

use iec61850_model::{IedModel, MmsValue, FC};

use crate::service::read::Node;

use super::dataset::{Dataset, DatasetEntry};
use super::DatasetRegistry;

/// Why a dynamic data set operation failed.
///
/// Each variant maps to one IEC 61850-7-2 service error class, which the handler
/// turns into the matching ConfirmedError code.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DatasetError {
    /// A data set with this domain and name is already registered, whether it was
    /// created statically or dynamically.
    NameAlreadyExists {
        /// MMS domain the data set was requested in.
        domain: String,
        /// Data set name that is already taken.
        name: String,
    },
    /// The member path names a logical node, data object, or data attribute that is
    /// not in the model.
    MemberNotFound {
        /// The member path that did not resolve.
        path: String,
    },
    /// The member path is malformed, with too few segments or an unparseable
    /// functional constraint token, or it names a member form this server does
    /// not serve: a data object, a sub-data-object, or a constructed attribute.
    MemberInvalidPath {
        /// The malformed member path.
        path: String,
    },
    /// A static data set was asked to be deleted; `mmsDeletable` is false for it.
    StaticNotDeletable {
        /// Name of the static data set.
        name: String,
    },
    /// The `DatasetRegistry` lock is poisoned.
    RegistryPoisoned,
}

impl std::fmt::Display for DatasetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NameAlreadyExists { domain, name } => {
                write!(f, "dataset already exists: {domain}/{name}")
            }
            Self::MemberNotFound { path } => write!(f, "dataset member not found: {path}"),
            Self::MemberInvalidPath { path } => {
                write!(f, "dataset member invalid path: {path}")
            }
            Self::StaticNotDeletable { name } => {
                write!(f, "dataset is static and not deletable: {name}")
            }
            Self::RegistryPoisoned => write!(f, "dataset registry RwLock poisoned"),
        }
    }
}

impl std::error::Error for DatasetError {}

/// Namespace for the dynamic data set operations; stateless.
#[derive(Debug)]
pub struct DynamicDatasetOps;

/// Result metadata from a successful `add_dynamic`.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct DatasetMeta {
    /// Number of entries in the data set that was created.
    pub entry_count: usize,
}

impl DynamicDatasetOps {
    /// Creates a dynamic data set, resolving every member through the model.
    ///
    /// Every member is resolved before anything is registered, so a failure part
    /// way through leaves no half-built data set behind.
    ///
    /// # Errors
    /// - [`DatasetError::NameAlreadyExists`] when the domain and name are taken.
    /// - [`DatasetError::MemberNotFound`] when a member is not in the model.
    /// - [`DatasetError::MemberInvalidPath`] when a member path is malformed.
    /// - [`DatasetError::RegistryPoisoned`] when the registry lock is poisoned.
    pub fn add_dynamic(
        registry: &DatasetRegistry,
        ied_model: &IedModel,
        domain: &str,
        list_name: &str,
        members: Vec<(String, String)>,
    ) -> Result<DatasetMeta, DatasetError> {
        // Check the name first, before doing the resolution work.
        {
            let guard = registry
                .read()
                .map_err(|_| DatasetError::RegistryPoisoned)?;
            if guard.contains_key(&(domain.to_string(), list_name.to_string())) {
                return Err(DatasetError::NameAlreadyExists {
                    domain: domain.to_string(),
                    name: list_name.to_string(),
                });
            }
        }

        // Resolve every member; the registry is written only if all of them resolve.
        let mut entries: Vec<DatasetEntry> = Vec::with_capacity(members.len());
        for (mem_domain, mem_path) in &members {
            let value = resolve_attr_value(ied_model, mem_domain, mem_path)?;
            let attr_ref = format!("{mem_domain}/{mem_path}");
            entries.push(DatasetEntry::new(attr_ref, value));
        }

        let dataset = Arc::new(Dataset {
            name: list_name.to_string(),
            entries,
        });
        let entry_count = dataset.len();

        let mut guard = registry
            .write()
            .map_err(|_| DatasetError::RegistryPoisoned)?;
        // Checked again: another writer may have inserted between the two locks.
        match guard.entry((domain.to_string(), list_name.to_string())) {
            std::collections::hash_map::Entry::Occupied(_) => {
                Err(DatasetError::NameAlreadyExists {
                    domain: domain.to_string(),
                    name: list_name.to_string(),
                })
            }
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(dataset);
                Ok(DatasetMeta { entry_count })
            }
        }
    }

    /// Returns whether a data set with this domain and name is registered, whether
    /// it was created statically or dynamically.
    pub fn contains(registry: &DatasetRegistry, domain: &str, list_name: &str) -> bool {
        match registry.read() {
            Ok(g) => g.contains_key(&(domain.to_string(), list_name.to_string())),
            Err(_) => false,
        }
    }

    /// Removes a data set from the registry. `Ok(true)` means one was removed,
    /// `Ok(false)` that the key was not present.
    ///
    /// # Errors
    ///
    /// Returns [`DatasetError::RegistryPoisoned`] when the registry lock is poisoned.
    pub fn remove(
        registry: &DatasetRegistry,
        domain: &str,
        list_name: &str,
    ) -> Result<bool, DatasetError> {
        let mut guard = registry
            .write()
            .map_err(|_| DatasetError::RegistryPoisoned)?;
        Ok(guard
            .remove(&(domain.to_string(), list_name.to_string()))
            .is_some())
    }
}

/// Resolves the MMS path `<LN>$<FC>$<DO>[$<SDO>...]$<DA>[$<SDA>...]` to the
/// value handle shared with the model.
fn resolve_attr_value(
    ied_model: &IedModel,
    domain: &str,
    mms_path: &str,
) -> Result<Arc<RwLock<MmsValue>>, DatasetError> {
    let parts: Vec<&str> = mms_path.split('$').collect();
    if parts.len() < 4 {
        return Err(DatasetError::MemberInvalidPath {
            path: format!("{domain}/{mms_path}"),
        });
    }
    let invalid = || DatasetError::MemberInvalidPath {
        path: format!("{domain}/{mms_path}"),
    };
    let not_found = || DatasetError::MemberNotFound {
        path: format!("{domain}/{mms_path}"),
    };
    if parts.iter().any(|p| p.is_empty()) {
        return Err(invalid());
    }
    let fc = FC::parse(parts[1]).map_err(|_| invalid())?;

    let ln = ied_model
        .ld_by_domain(domain)
        .and_then(|ld| ld.ln_by_name(parts[0]))
        .ok_or_else(not_found)?;
    let dobj = ln.do_by_name(parts[2]).ok_or_else(not_found)?;

    // Sub-data-objects may nest to any depth before the data attribute, which
    // must carry the functional constraint of the path; sub-attributes are
    // descended by name.
    let mut node = Node::Object(dobj);
    for seg in &parts[3..] {
        node = node.child(fc, seg).ok_or_else(not_found)?;
    }

    // A data object, a sub-data-object or a constructed attribute holds no
    // value of its own.
    match node {
        Node::Attribute(da) if node.is_leaf() => Ok(Arc::clone(&da.value)),
        _ => Err(invalid()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iec61850_model::{
        DataAttribute, DataAttributeType, DataObject, DoChild, IedModelBuilder,
        LogicalDeviceBuilder, LogicalNodeBuilder, TrgOps,
    };
    use std::collections::HashMap;

    fn build_model() -> Arc<IedModel> {
        let stval = DataAttribute::new(
            "stVal",
            FC::St,
            DataAttributeType::Boolean,
            TrgOps::default(),
            MmsValue::Boolean(false),
        );
        let ind1 = DataObject::new("Ind1", vec![DoChild::Da(stval)]);
        let ggio1 = iec61850_model::LogicalNode::new(String::new(), "GGIO", "1", vec![ind1]);
        let lln0 = LogicalNodeBuilder::lln0().build().unwrap();
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(lln0)
            .add_ln(ggio1)
            .build()
            .unwrap();
        Arc::new(
            IedModelBuilder::new("IED1")
                .add_ld(ld)
                .unwrap()
                .build()
                .unwrap(),
        )
    }

    fn empty_registry() -> DatasetRegistry {
        Arc::new(RwLock::new(HashMap::new()))
    }

    #[test]
    fn resolve_simple_path_ok() {
        let model = build_model();
        let v = resolve_attr_value(&model, "IED1LD0", "GGIO1$ST$Ind1$stVal").unwrap();
        assert_eq!(*v.read().unwrap(), MmsValue::Boolean(false));
    }

    #[test]
    fn resolve_unknown_ln_returns_not_found() {
        let model = build_model();
        let err = resolve_attr_value(&model, "IED1LD0", "BOGUS$ST$Ind1$stVal").unwrap_err();
        assert!(matches!(err, DatasetError::MemberNotFound { .. }));
    }

    #[test]
    fn resolve_wrong_fc_returns_not_found() {
        let model = build_model();
        let err = resolve_attr_value(&model, "IED1LD0", "GGIO1$MX$Ind1$stVal").unwrap_err();
        assert!(matches!(err, DatasetError::MemberNotFound { .. }));
    }

    /// A member reaches a data attribute across any depth of
    /// sub-data-objects; one that stops on a sub-data-object is not a
    /// single value.
    #[test]
    fn resolve_descends_sub_data_objects() {
        let set_mag = DataAttribute::new(
            "setMag",
            FC::Sp,
            DataAttributeType::Float32,
            TrgOps::default(),
            MmsValue::Float32(2.5),
        );
        let cmv = DataObject::new("cmv", vec![DoChild::Da(set_mag)]);
        let phs_a = DataObject::new("phsA", vec![DoChild::SubDo(cmv)]);
        let phset = DataObject::new("PhSet", vec![DoChild::SubDo(phs_a)]);
        let ggio1 = iec61850_model::LogicalNode::new(String::new(), "GGIO", "1", vec![phset]);
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
        let v = resolve_attr_value(&model, "IED1LD0", "GGIO1$SP$PhSet$phsA$cmv$setMag").unwrap();
        assert_eq!(*v.read().unwrap(), MmsValue::Float32(2.5));
        assert!(matches!(
            resolve_attr_value(&model, "IED1LD0", "GGIO1$SP$PhSet$phsA"),
            Err(DatasetError::MemberInvalidPath { .. })
        ));
        assert!(matches!(
            resolve_attr_value(&model, "IED1LD0", "GGIO1$ST$PhSet$phsA$cmv$setMag"),
            Err(DatasetError::MemberNotFound { .. })
        ));
    }

    #[test]
    fn resolve_short_path_returns_invalid() {
        let model = build_model();
        let err = resolve_attr_value(&model, "IED1LD0", "GGIO1$ST$Ind1").unwrap_err();
        assert!(matches!(err, DatasetError::MemberInvalidPath { .. }));
    }

    #[test]
    fn add_dynamic_then_contains_then_remove() {
        let model = build_model();
        let reg = empty_registry();
        let meta = DynamicDatasetOps::add_dynamic(
            &reg,
            &model,
            "IED1LD0",
            "GGIO1$ds_dyn",
            vec![("IED1LD0".into(), "GGIO1$ST$Ind1$stVal".into())],
        )
        .unwrap();
        assert_eq!(meta.entry_count, 1);
        assert!(DynamicDatasetOps::contains(&reg, "IED1LD0", "GGIO1$ds_dyn"));
        assert!(DynamicDatasetOps::remove(&reg, "IED1LD0", "GGIO1$ds_dyn").unwrap());
        assert!(!DynamicDatasetOps::contains(
            &reg,
            "IED1LD0",
            "GGIO1$ds_dyn"
        ));
    }

    #[test]
    fn add_dynamic_duplicate_name_rejected() {
        let model = build_model();
        let reg = empty_registry();
        DynamicDatasetOps::add_dynamic(
            &reg,
            &model,
            "IED1LD0",
            "GGIO1$ds_dyn",
            vec![("IED1LD0".into(), "GGIO1$ST$Ind1$stVal".into())],
        )
        .unwrap();
        let err = DynamicDatasetOps::add_dynamic(
            &reg,
            &model,
            "IED1LD0",
            "GGIO1$ds_dyn",
            vec![("IED1LD0".into(), "GGIO1$ST$Ind1$stVal".into())],
        )
        .unwrap_err();
        assert!(matches!(err, DatasetError::NameAlreadyExists { .. }));
    }

    #[test]
    fn add_dynamic_atomic_on_resolve_failure() {
        let model = build_model();
        let reg = empty_registry();
        // The second member path does not resolve, so the whole add must fail and
        // leave the registry empty.
        let err = DynamicDatasetOps::add_dynamic(
            &reg,
            &model,
            "IED1LD0",
            "GGIO1$ds_dyn",
            vec![
                ("IED1LD0".into(), "GGIO1$ST$Ind1$stVal".into()),
                ("IED1LD0".into(), "GGIO1$ST$BOGUS$stVal".into()),
            ],
        )
        .unwrap_err();
        assert!(matches!(err, DatasetError::MemberNotFound { .. }));
        assert!(!DynamicDatasetOps::contains(
            &reg,
            "IED1LD0",
            "GGIO1$ds_dyn"
        ));
    }
}
