//! Structural view of an `IedModel` as MMS domains, named variables, and type
//! specifications.
//!
//! The model is walked once when the server is built, and the resulting view is
//! shared read-only by the GetNameList, GetVariableAccessAttributes, Read, and
//! Write services.
//!
//! Invariants the view guarantees:
//!
//! - Functional-constraint groups appear in the order MX, ST, CO, CF, DC, SP,
//!   SG, RP, LG, BR, GO, SV, SE, MS, US, EX, SR, OR, BL, per IEC 61850-8-1.
//!   A client that builds an object tree depends on this order.
//! - Data attribute types map onto MMS types as IEC 61850-8-1 prescribes.
//! - A domain name over 64 bytes is an error, never a truncation, and two
//!   logical devices resolving to the same name are an error too.

use crate::compat::HashMap;
use crate::error::{Result, ServerError};
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::format;
#[cfg(not(feature = "std"))]
use alloc::string::{String, ToString};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObject, DoChild, IedModel, LogicalDevice, LogicalNode, FC,
};

/// Order in which the functional-constraint groups of a logical node appear.
///
/// A client that enumerates a node depends on this order, so it is fixed by
/// IEC 61850-8-1 rather than by the model.
const LN_FC_ORDER: &[FC] = &[
    FC::Mx,
    FC::St,
    FC::Co,
    FC::Cf,
    FC::Dc,
    FC::Sp,
    FC::Sg,
    FC::Rp,
    FC::Lg,
    FC::Br,
    FC::Go,
    FC::Sv,
    FC::Se,
    FC::Ms,
    FC::Us,
    FC::Ex,
    FC::Sr,
    FC::Or,
    FC::Bl,
];

/// Longest MMS domain name IEC 61850-8-1 permits.
const MAX_DOMAIN_NAME_LEN: usize = 64;

/// A leaf of an MMS type specification, as IEC 61850-8-1 §5.2 maps the data
/// attribute types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MmsLeafType {
    /// Boolean.
    Boolean,
    /// Signed integer, sized in bits: 8, 16, 32, 64, or 128.
    Integer(u16),
    /// Unsigned integer, sized in bits: 8, 16, 24, or 32.
    Unsigned(u16),
    /// Floating point. A 32-bit float is format width 32 with exponent width 8,
    /// a 64-bit float format width 64 with exponent width 11. The field order
    /// matches the encoding of the floating-point type specification.
    Float {
        /// Total width of the encoded value, in bits.
        format_width: u16,
        /// Width of the exponent field, in bits.
        exponent_width: u16,
    },
    /// Bit string of the given size.
    BitString(StringSize),
    /// Octet string of the given size.
    OctetString(StringSize),
    /// Visible string of the given size.
    VisibleString(StringSize),
    /// Unicode string of the given size.
    UnicodeString(StringSize),
    /// UTC timestamp, 8 octets.
    UtcTime,
    /// Binary time, 4 or 6 octets.
    BinaryTime {
        /// Encoded width in octets, 4 or 6.
        size: u16,
    },
}

/// Size of a string, bit string, or octet string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringSize {
    /// Variable length, at most N. Encodes as a negative bound.
    Max(u16),
    /// Exactly N. Encodes as a positive bound.
    Fixed(u16),
    /// No declared size. Encodes as zero.
    Generic,
}

/// An MMS type specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MmsTypeSpec {
    /// A scalar value.
    Leaf(MmsLeafType),
    /// A structure whose members keep the order the model declares.
    Structure(Vec<NamedVariableSpec>),
    /// An array, produced by a data attribute with an element count.
    Array {
        /// Number of elements.
        count: u32,
        /// Type of every element.
        inner: Box<MmsTypeSpec>,
    },
}

/// One named member of an MMS structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedVariableSpec {
    /// Name within the enclosing structure, such as `stVal`, `q`, `t`, or a
    /// logical node name.
    pub name: String,
    /// Type of the member.
    pub type_spec: MmsTypeSpec,
}

/// View of one MMS domain, which is one logical device.
#[derive(Debug, Clone)]
pub struct DomainView {
    /// MMS domain name: the configured logical device name where there is one,
    /// otherwise the IED name followed by the instance.
    pub name: String,
    /// Logical nodes, in the order GetNameList reports them.
    pub named_variables: Vec<NamedVariableSpec>,
}

impl DomainView {
    /// Returns the type specification of a top-level named variable.
    pub fn get_variable_spec(&self, name: &str) -> Option<&MmsTypeSpec> {
        self.named_variables
            .iter()
            .find(|nv| nv.name == name)
            .map(|nv| &nv.type_spec)
    }
}

/// Read-only MMS view of every domain in a model.
///
/// Built once while the server is constructed and shared by the services from
/// then on.
#[derive(Debug, Clone)]
pub struct MmsDeviceModel {
    /// Domains in the order the model declares its logical devices, which is
    /// the order GetNameList reports them in.
    domains: Vec<DomainView>,
    /// Name to position, so a lookup costs constant time.
    domain_index: HashMap<String, usize>,
}

impl MmsDeviceModel {
    /// Builds the view from a model.
    ///
    /// # Errors
    ///
    /// Returns `DomainNameTooLong` for a domain name over 64 bytes and
    /// `DuplicateDomain` when two logical devices resolve to the same name.
    pub fn from_ied_model(model: &IedModel) -> Result<Self> {
        let mut domains = Vec::with_capacity(model.lds.len());
        let mut domain_index = HashMap::with_capacity(model.lds.len());

        for ld in &model.lds {
            let name = ld.domain_name(&model.ied_name);
            if name.len() > MAX_DOMAIN_NAME_LEN {
                return Err(ServerError::DomainNameTooLong { name });
            }
            if domain_index.contains_key(&name) {
                return Err(ServerError::DuplicateDomain { name });
            }
            let view = build_domain_view(name.clone(), ld)?;
            domain_index.insert(name, domains.len());
            domains.push(view);
        }

        Ok(Self {
            domains,
            domain_index,
        })
    }

    /// Lists every domain name.
    pub fn list_domains(&self) -> impl Iterator<Item = &str> + '_ {
        self.domains.iter().map(|d| d.name.as_str())
    }

    /// Lists the top-level named variables of a domain, or `None` when no such
    /// domain exists.
    pub fn list_named_variables(&self, domain: &str) -> Option<Vec<String>> {
        let idx = self.domain_index.get(domain)?;
        Some(
            self.domains[*idx]
                .named_variables
                .iter()
                .map(|nv| nv.name.clone())
                .collect(),
        )
    }

    /// Lists every component path of a domain, flattened: `LN`, `LN$FC`,
    /// `LN$FC$DO`, `LN$FC$DO$DA`, and so on. Array elements are not expanded.
    ///
    /// This is what GetNameList reports for a domain. A model-driven client
    /// identifies a functional-constraint node from the `LN$FC` level, and
    /// reporting only the top-level names makes it mistype those nodes.
    pub fn list_named_variables_flat(&self, domain: &str) -> Option<Vec<String>> {
        let idx = self.domain_index.get(domain)?;
        let mut out = Vec::new();
        for nv in &self.domains[*idx].named_variables {
            push_flat_paths(&nv.name, &nv.type_spec, &mut out);
        }
        Some(out)
    }

    /// Returns the type specification of a named variable in a domain.
    pub fn get_variable_spec(&self, domain: &str, var: &str) -> Option<&MmsTypeSpec> {
        let idx = self.domain_index.get(domain)?;
        self.domains[*idx].get_variable_spec(var)
    }

    /// Returns the view of one domain by name.
    pub fn domain(&self, name: &str) -> Option<&DomainView> {
        let idx = self.domain_index.get(name)?;
        Some(&self.domains[*idx])
    }

    /// Returns how many domains the model exposes.
    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Building a domain view from a logical device
// ─────────────────────────────────────────────────────────────────────────────

/// Collects the path of `prefix` and, depth first, of every structure member
/// beneath it.
///
/// An array contributes its own path but not its elements, which a client
/// reaches by index through AlternateAccess rather than by name.
fn push_flat_paths(prefix: &str, spec: &MmsTypeSpec, out: &mut Vec<String>) {
    out.push(prefix.to_string());
    if let MmsTypeSpec::Structure(components) = spec {
        for c in components {
            let path = format!("{prefix}${}", c.name);
            push_flat_paths(&path, &c.type_spec, out);
        }
    }
}

fn build_domain_view(name: String, ld: &LogicalDevice) -> Result<DomainView> {
    let mut named_variables = Vec::with_capacity(ld.lns.len());
    for ln in &ld.lns {
        let ln_name = format!("{}{}{}", ln.prefix, ln.class, ln.inst);
        let ln_struct = build_ln_structure(ln)?;
        named_variables.push(NamedVariableSpec {
            name: ln_name,
            type_spec: ln_struct,
        });
    }
    Ok(DomainView {
        name,
        named_variables,
    })
}

/// Builds the structure of a logical node, one member per functional-constraint
/// group, in the order of [`LN_FC_ORDER`].
///
/// Only a group that actually holds data appears. A setting group control block
/// is the first member of the SP group.
fn build_ln_structure(ln: &LogicalNode) -> Result<MmsTypeSpec> {
    let mut components = Vec::new();

    for &fc in LN_FC_ORDER {
        let dos_in_fc = collect_dos_with_fc(ln, fc);
        let has_sgcb_for_fc = fc == FC::Sp && ln.sgcb.is_some();

        if dos_in_fc.is_empty() && !has_sgcb_for_fc {
            continue;
        }

        let mut fc_children = Vec::new();

        // The setting group control block comes first in the SP group.
        if has_sgcb_for_fc {
            fc_children.push(NamedVariableSpec {
                name: "SGCB".to_string(),
                type_spec: build_sgcb_type_spec(),
            });
        }

        for (do_name, do_node) in dos_in_fc {
            fc_children.push(NamedVariableSpec {
                name: do_name,
                type_spec: build_do_type_spec(do_node, fc)?,
            });
        }

        if !fc_children.is_empty() {
            components.push(NamedVariableSpec {
                name: fc.as_str().to_string(),
                type_spec: MmsTypeSpec::Structure(fc_children),
            });
        }
    }

    Ok(MmsTypeSpec::Structure(components))
}

/// Collects the data objects of a logical node that hold data under one
/// functional constraint.
fn collect_dos_with_fc(ln: &LogicalNode, fc: FC) -> Vec<(String, &DataObject)> {
    ln.dos
        .iter()
        .filter(|d| do_has_fc(d, fc))
        .map(|d| (d.name.clone(), d))
        .collect()
}

/// Reports whether a data object or any of its sub-objects holds an attribute
/// under one functional constraint.
fn do_has_fc(d: &DataObject, fc: FC) -> bool {
    d.children.iter().any(|c| match c {
        DoChild::Da(da) => da.fc == fc,
        DoChild::SubDo(sd) => do_has_fc(sd, fc),
    })
}

/// Builds the structure of a data object, keeping only the attributes and
/// sub-objects that carry one functional constraint.
fn build_do_type_spec(d: &DataObject, fc: FC) -> Result<MmsTypeSpec> {
    let inner = build_do_struct_for_fc(d, fc)?;
    if let Some(count) = d.array_count {
        Ok(MmsTypeSpec::Array {
            count,
            inner: Box::new(inner),
        })
    } else {
        Ok(inner)
    }
}

fn build_do_struct_for_fc(d: &DataObject, fc: FC) -> Result<MmsTypeSpec> {
    let mut children = Vec::new();
    for c in &d.children {
        match c {
            DoChild::Da(da) if da.fc == fc => {
                children.push(NamedVariableSpec {
                    name: da.name.clone(),
                    type_spec: build_da_type_spec(da)?,
                });
            }
            DoChild::Da(_) => {} // A different functional constraint.
            DoChild::SubDo(sd) => {
                if do_has_fc(sd, fc) {
                    children.push(NamedVariableSpec {
                        name: sd.name.clone(),
                        type_spec: build_do_type_spec(sd, fc)?,
                    });
                }
            }
        }
    }
    Ok(MmsTypeSpec::Structure(children))
}

/// Maps a data attribute onto a type specification, per IEC 61850-8-1 §5.2.
fn build_da_type_spec(da: &DataAttribute) -> Result<MmsTypeSpec> {
    if da.ty == DataAttributeType::Constructed {
        // Sub-attributes keep the order the model declares; a client depends on it.
        let children = da
            .children
            .iter()
            .map(|child| {
                let ts = build_da_type_spec(child)?;
                Ok(NamedVariableSpec {
                    name: child.name.clone(),
                    type_spec: ts,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        return Ok(MmsTypeSpec::Structure(children));
    }

    // PhyComAddr is a fixed four-member structure.
    if da.ty == DataAttributeType::PhyComAddr {
        return Ok(MmsTypeSpec::Structure(vec![
            NamedVariableSpec {
                name: "Addr".into(),
                type_spec: MmsTypeSpec::Leaf(MmsLeafType::OctetString(StringSize::Fixed(6))),
            },
            NamedVariableSpec {
                name: "PRIORITY".into(),
                type_spec: MmsTypeSpec::Leaf(MmsLeafType::Unsigned(8)),
            },
            NamedVariableSpec {
                name: "VID".into(),
                type_spec: MmsTypeSpec::Leaf(MmsLeafType::Unsigned(16)),
            },
            NamedVariableSpec {
                name: "APPID".into(),
                type_spec: MmsTypeSpec::Leaf(MmsLeafType::Unsigned(16)),
            },
        ]));
    }

    let leaf = leaf_from_da_type(da.ty)?;
    Ok(MmsTypeSpec::Leaf(leaf))
}

/// Maps a scalar data attribute type onto an MMS leaf type, per
/// IEC 61850-8-1 §5.2.
///
/// # Errors
///
/// Returns `InvalidModel` for a constructed type, which has no leaf mapping.
fn leaf_from_da_type(ty: DataAttributeType) -> Result<MmsLeafType> {
    use DataAttributeType as T;
    let leaf = match ty {
        T::Boolean => MmsLeafType::Boolean,
        T::Int8 => MmsLeafType::Integer(8),
        T::Int16 => MmsLeafType::Integer(16),
        T::Int32 => MmsLeafType::Integer(32),
        T::Int64 => MmsLeafType::Integer(64),
        T::Int128 => MmsLeafType::Integer(128),
        T::Int8U => MmsLeafType::Unsigned(8),
        T::Int16U => MmsLeafType::Unsigned(16),
        T::Int24U => MmsLeafType::Unsigned(24),
        T::Int32U => MmsLeafType::Unsigned(32),
        T::Float32 => MmsLeafType::Float {
            format_width: 32,
            exponent_width: 8,
        },
        T::Float64 => MmsLeafType::Float {
            format_width: 64,
            exponent_width: 11,
        },
        T::Enumerated => MmsLeafType::Integer(8), // IEC 61850-8-1 §4.4
        T::Check => MmsLeafType::BitString(StringSize::Max(2)),
        T::CodedEnum => MmsLeafType::BitString(StringSize::Fixed(2)),
        T::Quality => MmsLeafType::BitString(StringSize::Max(13)),
        T::OptFlds => MmsLeafType::BitString(StringSize::Max(10)),
        T::TrgOpsBits => MmsLeafType::BitString(StringSize::Max(6)),
        T::GenericBitString(n) => {
            if n == 0 {
                // A generic bit string declares no size.
                MmsLeafType::BitString(StringSize::Generic)
            } else {
                MmsLeafType::BitString(StringSize::Max(n))
            }
        }
        T::OctetString(n) => MmsLeafType::OctetString(map_size(n, 6, 8, 64)),
        T::VisibleString(n) => MmsLeafType::VisibleString(StringSize::Max(n)),
        T::UnicodeString255 => MmsLeafType::UnicodeString(StringSize::Max(255)),
        T::Currency => MmsLeafType::VisibleString(StringSize::Max(3)),
        T::Timestamp => MmsLeafType::UtcTime,
        T::EntryTime => MmsLeafType::BinaryTime { size: 6 },
        T::Constructed | T::PhyComAddr => {
            // Unreachable: both are handled before this function is called.
            return Err(ServerError::InvalidModel(format!(
                "data attribute type {:?} is not a leaf type",
                ty
            )));
        }
    };
    Ok(leaf)
}

/// Applies the octet-string size convention of IEC 61850-8-1 §5.2: a size equal
/// to `fixed_b` is a fixed length, every other size is an upper bound.
///
/// The standard declares octet strings as either exactly 8 octets or at most 6
/// or 64, so only the fixed case needs distinguishing; the remaining bounds are
/// parameters for sizes a future edition may add.
fn map_size(n: u16, _max_a: u16, fixed_b: u16, _max_c: u16) -> StringSize {
    if n == fixed_b {
        StringSize::Fixed(n)
    } else {
        StringSize::Max(n)
    }
}

/// Builds the structure of a setting group control block, whose five members
/// are `NumOfSG`, `ActSG`, `EditSG`, `CnfEdit`, and `LActTm`.
fn build_sgcb_type_spec() -> MmsTypeSpec {
    MmsTypeSpec::Structure(vec![
        NamedVariableSpec {
            name: "NumOfSG".into(),
            type_spec: MmsTypeSpec::Leaf(MmsLeafType::Unsigned(8)),
        },
        NamedVariableSpec {
            name: "ActSG".into(),
            type_spec: MmsTypeSpec::Leaf(MmsLeafType::Unsigned(8)),
        },
        NamedVariableSpec {
            name: "EditSG".into(),
            type_spec: MmsTypeSpec::Leaf(MmsLeafType::Unsigned(8)),
        },
        NamedVariableSpec {
            name: "CnfEdit".into(),
            type_spec: MmsTypeSpec::Leaf(MmsLeafType::Boolean),
        },
        NamedVariableSpec {
            name: "LActTm".into(),
            type_spec: MmsTypeSpec::Leaf(MmsLeafType::UtcTime),
        },
    ])
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use iec61850_model::{
        DataAttribute, DataAttributeType, DataObject, DoChild, IedModelBuilder, MmsValue, TrgOps,
    };

    /// Builds a data attribute list carrying data under functional constraint
    /// SP, so that a logical node has an SP group.
    fn ln_with_sp_da() -> Vec<DataAttribute> {
        vec![DataAttribute::new(
            "spVal",
            FC::Sp,
            DataAttributeType::Boolean,
            TrgOps::default(),
            MmsValue::Boolean(false),
        )]
    }

    fn build_lln0() -> iec61850_model::LogicalNode {
        iec61850_model::LogicalNodeBuilder::lln0()
            .build()
            .expect("lln0")
    }

    fn build_ied_with_one_lln0() -> IedModel {
        let ld = iec61850_model::LogicalDeviceBuilder::new("LD0")
            .add_ln(build_lln0())
            .build()
            .expect("ld");
        IedModelBuilder::new("IED1")
            .add_ld(ld)
            .expect("add_ld")
            .build()
            .expect("build minimal model")
    }

    #[test]
    fn happy_path_domain_naming_ied_plus_inst() {
        // ldName = None → domain = ied_name + inst
        let model = build_ied_with_one_lln0();
        let mapping = MmsDeviceModel::from_ied_model(&model).unwrap();
        let domains: Vec<&str> = mapping.list_domains().collect();
        assert_eq!(domains, vec!["IED1LD0"]);
    }

    #[test]
    fn happy_path_domain_naming_ld_name_override() {
        let ld = iec61850_model::LogicalDeviceBuilder::new("LD0")
            .with_ld_name("SubstA")
            .add_ln(build_lln0())
            .build()
            .expect("ld");
        let model = IedModelBuilder::new("IED1")
            .add_ld(ld)
            .expect("add_ld")
            .build()
            .unwrap();
        let mapping = MmsDeviceModel::from_ied_model(&model).unwrap();
        let domains: Vec<&str> = mapping.list_domains().collect();
        assert_eq!(domains, vec!["SubstA"]);
    }

    #[test]
    fn domain_name_overflow_returns_err() {
        // One byte past the 64-byte limit.
        let long_name = "X".repeat(65);
        let ld = iec61850_model::LogicalDeviceBuilder::new("LD0")
            .with_ld_name(&long_name)
            .add_ln(build_lln0())
            .build()
            .expect("ld");
        let model = IedModelBuilder::new("IED1")
            .add_ld(ld)
            .expect("add_ld")
            .build()
            .unwrap();
        let result = MmsDeviceModel::from_ied_model(&model);
        assert!(matches!(result, Err(ServerError::DomainNameTooLong { .. })));
    }

    #[test]
    fn lln0_minimum_named_variable_present() {
        // LLN0 is present; how many members its structure has is up to the
        // builder.
        let model = build_ied_with_one_lln0();
        let mapping = MmsDeviceModel::from_ied_model(&model).unwrap();
        let vars = mapping.list_named_variables("IED1LD0").unwrap();
        assert_eq!(vars, vec!["LLN0"]);
    }

    #[test]
    fn unknown_domain_returns_none() {
        let model = build_ied_with_one_lln0();
        let mapping = MmsDeviceModel::from_ied_model(&model).unwrap();
        assert!(mapping.list_named_variables("nonexistent").is_none());
    }

    // ── Data attribute types map onto MMS leaf types, per §5.2 ──────────

    #[test]
    fn da_type_float32_maps_to_mms_float() {
        assert_eq!(
            leaf_from_da_type(DataAttributeType::Float32).unwrap(),
            MmsLeafType::Float {
                format_width: 32,
                exponent_width: 8,
            }
        );
    }

    #[test]
    fn da_type_float64_maps_to_mms_float() {
        assert_eq!(
            leaf_from_da_type(DataAttributeType::Float64).unwrap(),
            MmsLeafType::Float {
                format_width: 64,
                exponent_width: 11,
            }
        );
    }

    #[test]
    fn da_type_quality_maps_to_bit_string_max_13() {
        assert_eq!(
            leaf_from_da_type(DataAttributeType::Quality).unwrap(),
            MmsLeafType::BitString(StringSize::Max(13))
        );
    }

    #[test]
    fn da_type_timestamp_maps_to_utc_time() {
        assert_eq!(
            leaf_from_da_type(DataAttributeType::Timestamp).unwrap(),
            MmsLeafType::UtcTime
        );
    }

    #[test]
    fn da_type_enumerated_fixed_8_bit() {
        assert_eq!(
            leaf_from_da_type(DataAttributeType::Enumerated).unwrap(),
            MmsLeafType::Integer(8)
        );
    }

    // ── PhyComAddr is a four-member structure ───────────────────────────

    #[test]
    fn phycomaddr_has_four_elements() {
        let da = DataAttribute::new(
            "addr",
            FC::Cf,
            DataAttributeType::PhyComAddr,
            TrgOps::default(),
            MmsValue::Structure(vec![]),
        );
        let spec = build_da_type_spec(&da).unwrap();
        match spec {
            MmsTypeSpec::Structure(children) => {
                assert_eq!(children.len(), 4);
                let names: Vec<&str> = children.iter().map(|c| c.name.as_str()).collect();
                assert_eq!(names, vec!["Addr", "PRIORITY", "VID", "APPID"]);
            }
            other => panic!("PhyComAddr must be a structure, got {:?}", other),
        }
    }

    // ── An array data object becomes an MMS array ───────────────────────

    #[test]
    fn array_do_wraps_in_mms_array() {
        let inner_da = DataAttribute::new(
            "stVal",
            FC::St,
            DataAttributeType::Boolean,
            TrgOps::default(),
            MmsValue::Boolean(false),
        );
        let do_node = DataObject {
            name: "Ind".to_string(),
            array_count: Some(3),
            children: vec![DoChild::Da(inner_da)],
        };
        let spec = build_do_type_spec(&do_node, FC::St).unwrap();
        match spec {
            MmsTypeSpec::Array { count, inner } => {
                assert_eq!(count, 3);
                assert!(matches!(*inner, MmsTypeSpec::Structure(_)));
            }
            other => panic!("an array data object must map to an array, got {:?}", other),
        }
    }

    // ── Functional-constraint group order ───────────────────────────────

    #[test]
    fn ln_fc_order_mx_st_cf() {
        // The node is built directly: the model builder admits only LLN0
        // outside a logical device.
        let ln = LogicalNode {
            prefix: String::new(),
            class: "MMXU".into(),
            inst: "1".into(),
            dos: vec![DataObject {
                name: "TotW".into(),
                array_count: None,
                children: vec![
                    DoChild::Da(DataAttribute::new(
                        "mag",
                        FC::Mx,
                        DataAttributeType::Float32,
                        TrgOps::default(),
                        MmsValue::Float32(0.0),
                    )),
                    DoChild::Da(DataAttribute::new(
                        "stVal",
                        FC::St,
                        DataAttributeType::Int32,
                        TrgOps::default(),
                        MmsValue::Integer(0),
                    )),
                    DoChild::Da(DataAttribute::new(
                        "units",
                        FC::Cf,
                        DataAttributeType::VisibleString(20),
                        TrgOps::default(),
                        MmsValue::VisibleString(String::new()),
                    )),
                ],
            }],
            datasets: vec![],
            rcbs: vec![],
            gocbs: vec![],
            svcbs: vec![],
            lcbs: vec![],
            sgcb: None,
        };
        let spec = build_ln_structure(&ln).unwrap();
        match spec {
            MmsTypeSpec::Structure(comps) => {
                let names: Vec<&str> = comps.iter().map(|c| c.name.as_str()).collect();
                assert_eq!(names, vec!["MX", "ST", "CF"]);
            }
            other => panic!("a logical node must map to a structure, got {:?}", other),
        }
    }

    #[test]
    fn ln_only_existing_fc_groups_present() {
        let ln = LogicalNode {
            prefix: String::new(),
            class: "MMXU".into(),
            inst: "1".into(),
            dos: vec![DataObject {
                name: "TotW".into(),
                array_count: None,
                children: vec![DoChild::Da(DataAttribute::new(
                    "mag",
                    FC::Mx,
                    DataAttributeType::Float32,
                    TrgOps::default(),
                    MmsValue::Float32(0.0),
                ))],
            }],
            datasets: vec![],
            rcbs: vec![],
            gocbs: vec![],
            svcbs: vec![],
            lcbs: vec![],
            sgcb: None,
        };
        let spec = build_ln_structure(&ln).unwrap();
        match spec {
            MmsTypeSpec::Structure(comps) => {
                assert_eq!(comps.len(), 1);
                assert_eq!(comps[0].name, "MX");
            }
            other => panic!("got {:?}", other),
        }
    }

    // ── The setting group control block leads the SP group ──────────────

    #[test]
    fn sgcb_inserted_first_in_sp_structure() {
        use iec61850_model::SettingGroupControlBlock;
        let ln = LogicalNode {
            prefix: String::new(),
            class: "LLN0".into(),
            inst: String::new(),
            dos: vec![DataObject {
                name: "Mod".into(),
                array_count: None,
                children: ln_with_sp_da().into_iter().map(DoChild::Da).collect(),
            }],
            datasets: vec![],
            rcbs: vec![],
            gocbs: vec![],
            svcbs: vec![],
            lcbs: vec![],
            sgcb: Some(SettingGroupControlBlock {
                num_of_sg: 1,
                act_sg: 1,
                has_resv_tms: false,
                default_resv_tms_s: 60,
            }),
        };
        let spec = build_ln_structure(&ln).unwrap();
        match spec {
            MmsTypeSpec::Structure(comps) => {
                let sp = comps
                    .iter()
                    .find(|c| c.name == "SP")
                    .expect("the SP group must exist");
                if let MmsTypeSpec::Structure(sp_children) = &sp.type_spec {
                    assert_eq!(
                        sp_children[0].name, "SGCB",
                        "the setting group control block must lead the SP group"
                    );
                } else {
                    panic!("the SP group must be a structure");
                }
            }
            _ => panic!("a logical node must map to a structure"),
        }
    }

    // ── Long object references ──────────────────

    /// An object reference whose `LD/LN.DO.DA` path
    /// runs past 129 bytes is built in full. Implementations that assemble the
    /// reference into a fixed stack buffer overrun it instead.
    ///
    /// Every step of the mapping builds owned strings, so the length of a data
    /// object or attribute name is bounded only by the model. The 64-byte
    /// domain name limit is enforced separately.
    ///
    /// The test holds three properties: a path far longer than 129 bytes builds
    /// without panicking, the resulting tree is complete rather than truncated,
    /// and a domain name of exactly 64 bytes is still accepted.
    #[test]
    fn long_do_da_path_no_overflow() {
        // An 80-byte object name and an 80-byte attribute name, plus the node
        // and device prefixes, put the reference well past 129 bytes.
        let long_do = "D".repeat(80);
        let long_da = "A".repeat(80);

        let ln = LogicalNode {
            prefix: String::new(),
            class: "MMXU".into(),
            inst: "1".into(),
            dos: vec![DataObject {
                name: long_do.clone(),
                array_count: None,
                children: vec![DoChild::Da(DataAttribute::new(
                    long_da.clone(),
                    FC::Mx,
                    DataAttributeType::Float32,
                    TrgOps::default(),
                    MmsValue::Float32(0.0),
                ))],
            }],
            datasets: vec![],
            rcbs: vec![],
            gocbs: vec![],
            svcbs: vec![],
            lcbs: vec![],
            sgcb: None,
        };

        let spec = build_ln_structure(&ln).expect("a long name path must build");
        match spec {
            MmsTypeSpec::Structure(comps) => {
                let mx = comps
                    .iter()
                    .find(|c| c.name == "MX")
                    .expect("the MX group must exist");
                if let MmsTypeSpec::Structure(do_list) = &mx.type_spec {
                    let do_entry = do_list
                        .iter()
                        .find(|c| c.name == long_do)
                        .expect("the 80-byte object name must survive");
                    assert_eq!(
                        do_entry.name.len(),
                        80,
                        "the object name must not be truncated"
                    );
                    if let MmsTypeSpec::Structure(da_list) = &do_entry.type_spec {
                        let da_entry = da_list
                            .iter()
                            .find(|c| c.name == long_da)
                            .expect("the 80-byte attribute name must survive");
                        assert_eq!(
                            da_entry.name.len(),
                            80,
                            "the attribute name must not be truncated"
                        );
                    } else {
                        panic!("a data object must map to a structure");
                    }
                } else {
                    panic!("a functional-constraint group must be a structure");
                }
            }
            _ => panic!("a logical node must map to a structure"),
        }
    }

    /// at the boundary: a domain name of exactly 64
    /// bytes, the longest IEC 61850-8-1 permits.
    #[test]
    fn domain_at_max_len_ok() {
        let name = "D".repeat(64);
        let ld = iec61850_model::LogicalDeviceBuilder::new("LD0")
            .with_ld_name(&name)
            .add_ln(build_lln0())
            .build()
            .expect("ld");
        let model = IedModelBuilder::new("IED1")
            .add_ld(ld)
            .expect("add_ld")
            .build()
            .expect("build");
        let mapping = MmsDeviceModel::from_ied_model(&model)
            .expect("a 64-byte domain name is within the limit");
        let domains: Vec<&str> = mapping.list_domains().collect();
        assert_eq!(domains, vec![name.as_str()]);
    }
}
