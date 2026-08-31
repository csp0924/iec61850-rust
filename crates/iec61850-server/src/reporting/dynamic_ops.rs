//! Dynamic data set operations: CreateDataSet and DeleteDataSet of
//! IEC 61850-7-2.
//!
//! Creates and deletes named variable lists at runtime. A member is resolved
//! through the `IedModel` logical node, data object, and data attribute tree, and
//! yields the `Arc<RwLock<MmsValue>>` shared with `DataAttribute::value`, the same
//! handle a statically registered data set uses.
//!
//! A member path is `<LN>$<FC>$<DO>[$<SDA>...]`, for example
//! `GGIO1$ST$Ind1$stVal`: logical node class and instance, functional constraint,
//! data object name, data attribute name. A fifth and later segment is a
//! sub-attribute nested inside the data attribute and is descended in order.
//!
//! Array indices, the `(N)` syntax, are not supported; the `dataset_admin` module
//! of the client crate rejects them before they reach this module.

use std::sync::{Arc, RwLock};

use iec61850_model::{DoChild, IedModel, MmsValue, FC};

use super::dataset::{Dataset, DatasetEntry};
use super::DatasetRegistry;

/// Why a dynamic data set operation failed.
///
/// Each variant maps to one IEC 61850-7-2 service error class, which the handler
/// turns into the matching ConfirmedError code.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// The member path is malformed: too few segments, or an unparseable functional
    /// constraint token.
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

/// Resolves the MMS path `<LN>$<FC>$<DO>[$<SDA>...]` to the value handle shared
/// with the model.
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
    let ln_name = parts[0];
    let fc_token = parts[1];
    let do_name = parts[2];
    let da_name = parts[3];
    let sda_segments = &parts[4..];

    if ln_name.is_empty() || do_name.is_empty() || da_name.is_empty() {
        return Err(DatasetError::MemberInvalidPath {
            path: format!("{domain}/{mms_path}"),
        });
    }

    let fc = FC::parse(fc_token).map_err(|_| DatasetError::MemberInvalidPath {
        path: format!("{domain}/{mms_path}"),
    })?;

    let ld = ied_model
        .ld_by_domain(domain)
        .ok_or_else(|| DatasetError::MemberNotFound {
            path: format!("{domain}/{mms_path}"),
        })?;
    let ln = ld
        .ln_by_name(ln_name)
        .ok_or_else(|| DatasetError::MemberNotFound {
            path: format!("{domain}/{mms_path}"),
        })?;
    let dobj = ln
        .do_by_name(do_name)
        .ok_or_else(|| DatasetError::MemberNotFound {
            path: format!("{domain}/{mms_path}"),
        })?;

    // Look for the data attribute among the direct children of the data object;
    // a sub-data-object is descended one level first. Sub-attributes are reached
    // through the data attribute's own children.
    let mut da = match dobj.child_by_name(da_name) {
        Some(DoChild::Da(da)) => da,
        Some(DoChild::SubDo(_)) => {
            // A sub-data-object is not a value node.
            return Err(DatasetError::MemberInvalidPath {
                path: format!("{domain}/{mms_path}"),
            });
        }
        None => {
            return Err(DatasetError::MemberNotFound {
                path: format!("{domain}/{mms_path}"),
            });
        }
    };

    // The functional constraint in the path must match the one the data attribute
    // declares; the check is explicit rather than implied by the variable name.
    if da.fc != fc {
        return Err(DatasetError::MemberNotFound {
            path: format!("{domain}/{mms_path}"),
        });
    }

    // Remaining segments are sub-attributes, descended one level at a time.
    for seg in sda_segments {
        if seg.is_empty() {
            return Err(DatasetError::MemberInvalidPath {
                path: format!("{domain}/{mms_path}"),
            });
        }
        da = da
            .child_by_name(seg)
            .ok_or_else(|| DatasetError::MemberNotFound {
                path: format!("{domain}/{mms_path}"),
            })?;
    }

    Ok(Arc::clone(&da.value))
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
        let ind1 = DataObject {
            name: "Ind1".into(),
            array_count: None,
            children: vec![DoChild::Da(stval)],
        };
        let ggio1 = iec61850_model::LogicalNode {
            prefix: String::new(),
            class: "GGIO".into(),
            inst: "1".into(),
            dos: vec![ind1],
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
