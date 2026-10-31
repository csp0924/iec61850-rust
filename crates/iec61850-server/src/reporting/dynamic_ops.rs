//! Dynamic data set operations: CreateDataSet and DeleteDataSet of
//! IEC 61850-7-2.
//!
//! Creates and deletes named variable lists at runtime. Each member is resolved
//! through the `IedModel` logical node, data object, and data attribute tree by
//! [`DatasetEntry::from_model`], and shares the value locks of the model's
//! attributes, as a statically registered data set does.
//!
//! A member path is `<LN>$<FC>$<DO>[$<SDO>...][$<DA>[$<SDA>...]]`: functional-
//! constrained data (FCD) naming a data object or sub-data-object, or a
//! functional-constrained data attribute (FCDA) naming a data attribute or
//! sub-attribute of any type, for example `GGIO1$ST$Ind1`,
//! `MMXU1$MX$TotW$mag` or `MMXU1$MX$A$phsA$cVal$mag$f`. IEC 61850-7-2
//! §13.2.2.3 lets a member be either, and an IED that supports CreateDataSet
//! must handle any valid one.
//!
//! A run-time data set holds at most [`DynamicDatasetOps::MAX_MEMBERS`]
//! members and [`DynamicDatasetOps::MAX_LEAVES`] leaves across them, and each
//! member at most [`DatasetEntry::MAX_LEAVES`] leaves, so a request naming
//! large data objects cannot make the server hold an unbounded number of
//! value references.
//!
//! A member may name an element of an array, and components inside it, with
//! the index after the array name as the reference of the member carries it
//! (IEC 61850-8-1 §8.1.3.2.4), for example `MHAI1$MX$HA$phsAHar(3)$cVal$mag$f`.

use std::sync::Arc;

use iec61850_model::IedModel;

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
    #[non_exhaustive]
    NameAlreadyExists {
        /// MMS domain the data set was requested in.
        domain: String,
        /// Data set name that is already taken.
        name: String,
    },
    /// The member path names a logical node, data object, or data attribute that is
    /// not in the model, or a functional constraint that does not exist.
    #[non_exhaustive]
    MemberNotFound {
        /// The member path that did not resolve.
        path: String,
    },
    /// The member path is malformed, with too few segments or an empty
    /// segment; it names a member past an array, whose elements have no
    /// names; or its array index is past the end of the array or selects no
    /// array.
    #[non_exhaustive]
    MemberInvalidPath {
        /// The malformed member path.
        path: String,
    },
    /// A static data set was asked to be deleted; `mmsDeletable` is false for it.
    #[non_exhaustive]
    StaticNotDeletable {
        /// Name of the static data set.
        name: String,
    },
    /// The `DatasetRegistry` lock is poisoned.
    RegistryPoisoned,
    /// A size limit is exceeded: a member holds more than
    /// [`DatasetEntry::MAX_LEAVES`] leaves, and `path` names the member, or a
    /// run-time data set holds more than [`DynamicDatasetOps::MAX_MEMBERS`]
    /// members or [`DynamicDatasetOps::MAX_LEAVES`] leaves, and `path` names
    /// the data set.
    #[non_exhaustive]
    TooLarge {
        /// The member or data set over the limit.
        path: String,
    },
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
            Self::TooLarge { path } => write!(f, "dataset size limit exceeded: {path}"),
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

/// Splits a member path into the path without its array index and the index:
/// `MHAI1$MX$HA$phsAHar(3)$cVal` gives `MHAI1$MX$HA$phsAHar$cVal` and 3. A path
/// without an index is returned whole. `None` when the index is not a decimal
/// number, is not followed by the end of the path or by `$`, or is not the
/// only one.
fn split_element_index(path: &str) -> Option<(String, Option<u32>)> {
    let Some((head, rest)) = path.split_once('(') else {
        return Some((path.to_string(), None));
    };
    let (digits, tail) = rest.split_once(')')?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if tail.contains(['(', ')']) || !(tail.is_empty() || tail.starts_with('$')) {
        return None;
    }
    let index = digits.parse().ok()?;
    Some((format!("{head}{tail}"), Some(index)))
}

const _: () = assert!(
    iec61850_mms::mms::pdu::MAX_DEFINE_ENTRIES >= DynamicDatasetOps::MAX_MEMBERS,
    "a request at the member limit must decode"
);

impl DynamicDatasetOps {
    /// Largest number of members of a data set created at run time.
    ///
    /// A DefineNamedVariableList request decodes with up to
    /// [`MAX_DEFINE_ENTRIES`](iec61850_mms::mms::pdu::MAX_DEFINE_ENTRIES)
    /// members, which is never fewer, so a request at this limit always
    /// reaches the service; one with more members than this is answered
    /// `resource` `capability-unavailable` whichever limit refuses it.
    pub const MAX_MEMBERS: usize = 1024;

    /// Largest number of leaves, summed over its members, of a data set created
    /// at run time.
    pub const MAX_LEAVES: usize = 4096;

    /// Creates a dynamic data set, resolving every member through the model.
    ///
    /// A member is a domain and a path; a path naming an array element carries
    /// the index after the array name, `<array>(<n>)`, followed by the
    /// components inside the element, and at most one index. Every member is
    /// resolved before anything is registered, so a failure part way through
    /// leaves no half-built data set behind.
    ///
    /// # Errors
    /// - [`DatasetError::NameAlreadyExists`] when the domain and name are taken.
    /// - [`DatasetError::MemberNotFound`] when a member is not in the model,
    ///   or its index selects no element: one past the end of the array, or
    ///   one that does not follow the name of the first array on the path.
    /// - [`DatasetError::MemberInvalidPath`] when a member path is malformed.
    /// - [`DatasetError::TooLarge`] when a member or the data set exceeds a size
    ///   limit.
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

        let too_large = || DatasetError::TooLarge {
            path: format!("{domain}/{list_name}"),
        };
        if members.len() > Self::MAX_MEMBERS {
            return Err(too_large());
        }

        // Resolve every member; the registry is written only if all of them resolve.
        let mut entries: Vec<DatasetEntry> = Vec::with_capacity(members.len());
        let mut leaves = 0usize;
        for (mem_domain, mem_path) in &members {
            let reference = format!("{mem_domain}/{mem_path}");
            let (path, index) =
                split_element_index(mem_path).ok_or_else(|| DatasetError::MemberInvalidPath {
                    path: reference.clone(),
                })?;
            // An index that selects no element names no object. The index
            // selects an element of the first array on the path, so the
            // reference also shows whether that is where the path puts it.
            let not_found = || DatasetError::MemberNotFound {
                path: reference.clone(),
            };
            let entry = match DatasetEntry::from_model_at(ied_model, mem_domain, &path, index) {
                Err(DatasetError::MemberInvalidPath { .. }) if index.is_some() => {
                    return Err(not_found());
                }
                other => other?,
            };
            if index.is_some() && entry.attr_ref != reference {
                return Err(not_found());
            }
            leaves += entry.leaf_count();
            if leaves > Self::MAX_LEAVES {
                return Err(too_large());
            }
            entries.push(entry);
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

#[cfg(test)]
mod tests {
    use super::*;
    use iec61850_model::{
        DataAttribute, DataAttributeType, DataObject, DoChild, IedModelBuilder,
        LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, TrgOps, FC,
    };
    use std::collections::HashMap;
    use std::sync::RwLock;

    fn resolve_attr_value(
        model: &IedModel,
        domain: &str,
        path: &str,
    ) -> Result<MmsValue, DatasetError> {
        DatasetEntry::from_model(model, domain, path).map(|e| e.read_value().unwrap())
    }

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
        assert_eq!(v, MmsValue::Boolean(false));
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
    /// sub-data-objects; one that stops on a sub-data-object reads as its
    /// structure.
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
        assert_eq!(v, MmsValue::Float32(2.5));
        assert_eq!(
            resolve_attr_value(&model, "IED1LD0", "GGIO1$SP$PhSet$phsA").unwrap(),
            MmsValue::Structure(vec![MmsValue::Structure(vec![MmsValue::Float32(2.5)])])
        );
        assert!(matches!(
            resolve_attr_value(&model, "IED1LD0", "GGIO1$ST$PhSet$phsA$cmv$setMag"),
            Err(DatasetError::MemberNotFound { .. })
        ));
    }

    #[test]
    fn resolve_short_path_returns_invalid() {
        let model = build_model();
        let err = resolve_attr_value(&model, "IED1LD0", "GGIO1$ST").unwrap_err();
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

    /// A run-time data set beyond the member or leaf limit is refused whole;
    /// one at the limits is created.
    #[test]
    fn add_dynamic_holds_the_size_limits() {
        let model = build_model();
        let reg = empty_registry();
        let leaf = || ("IED1LD0".to_string(), "GGIO1$ST$Ind1$stVal".to_string());
        let at_limit = vec![leaf(); DynamicDatasetOps::MAX_MEMBERS];
        DynamicDatasetOps::add_dynamic(&reg, &model, "IED1LD0", "GGIO1$full", at_limit)
            .expect("a data set at the member limit");
        let over = vec![leaf(); DynamicDatasetOps::MAX_MEMBERS + 1];
        assert!(matches!(
            DynamicDatasetOps::add_dynamic(&reg, &model, "IED1LD0", "GGIO1$over", over),
            Err(DatasetError::TooLarge { .. })
        ));
        assert!(!DynamicDatasetOps::contains(&reg, "IED1LD0", "GGIO1$over"));

        // Members of 1000 leaves each: four fit the leaf limit, five do not.
        let attrs: Vec<DoChild> = (0..1000)
            .map(|i| {
                DoChild::Da(DataAttribute::new(
                    format!("a{i}"),
                    FC::Sp,
                    DataAttributeType::Int32,
                    TrgOps::default(),
                    MmsValue::Integer(0),
                ))
            })
            .collect();
        let ggio1 = iec61850_model::LogicalNode::new(
            String::new(),
            "GGIO",
            "1",
            vec![DataObject::new("Big", attrs)],
        );
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(LogicalNodeBuilder::lln0().build().unwrap())
            .add_ln(ggio1)
            .build()
            .unwrap();
        let big = IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap();
        let member = || ("IED1LD0".to_string(), "GGIO1$SP$Big".to_string());
        DynamicDatasetOps::add_dynamic(&reg, &big, "IED1LD0", "GGIO1$four", vec![member(); 4])
            .expect("4000 leaves");
        assert!(matches!(
            DynamicDatasetOps::add_dynamic(&reg, &big, "IED1LD0", "GGIO1$five", vec![member(); 5]),
            Err(DatasetError::TooLarge { .. })
        ));
    }

    #[test]
    fn an_element_index_splits_off_the_path() {
        assert_eq!(
            split_element_index("MHAI1$MX$HA$phsAHar(3)$cVal$mag$f"),
            Some(("MHAI1$MX$HA$phsAHar$cVal$mag$f".to_string(), Some(3)))
        );
        assert_eq!(
            split_element_index("GGIO1$ST$Arr$hstVal(1)"),
            Some(("GGIO1$ST$Arr$hstVal".to_string(), Some(1)))
        );
        assert_eq!(
            split_element_index("GGIO1$ST$Ind1$stVal"),
            Some(("GGIO1$ST$Ind1$stVal".to_string(), None))
        );
        for bad in [
            "A$B$C()",
            "A$B$C(+1)",
            "A$B$C(1",
            "A$B$C(1)(2)",
            "A$B$C(1)$D(2)",
            "A$B$C(1)x",
            "A$B$C(99999999999)",
        ] {
            assert_eq!(split_element_index(bad), None, "{bad}");
        }
    }
}
