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

use crate::compat::{Arc, HashMap, RwLock};
use crate::error::{Result, ServerError};
use crate::service::write::{WrittenLeaf, WrittenLeaves};
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::format;
#[cfg(not(feature = "std"))]
use alloc::string::{String, ToString};
#[cfg(not(feature = "std"))]
use alloc::sync::Weak;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObject, DoChild, IedModel, LogicalDevice, LogicalNode, FC,
};
#[cfg(feature = "std")]
use std::sync::Weak;

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
#[non_exhaustive]
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
#[non_exhaustive]
pub enum MmsTypeSpec {
    /// A scalar value.
    Leaf(MmsLeafType),
    /// A structure whose members keep the order the model declares.
    Structure(Vec<NamedVariableSpec>),
    /// An array, produced by a data attribute or sub-data-object with an
    /// element count (IEC 61850-8-1 §8.1.2.7).
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
    /// Held shared while a read or a full data set snapshot of the reporting
    /// engine takes the values of several attributes, and exclusively while a
    /// write stores them, so a read sees a write of a data object or a
    /// constructed attribute whole or not at all.
    ///
    /// The reporting engine takes it under the engine lock, so whoever holds
    /// it must not take the engine lock; no read handler runs while it is
    /// held. A read that consults handlers also reads values outside it while
    /// it asks them, and those values decide only a read refused for its size.
    value_lock: Arc<RwLock<()>>,
    /// Where a write hands the leaves it stored, to raise their report and log
    /// triggers; unset for a view no server owns.
    written_leaves: Arc<RwLock<Option<Weak<dyn WrittenLeaves>>>>,
    /// The leaves stored so far by the write request each association is
    /// being served, keyed by connection id, while the request lasts.
    write_batches: Arc<RwLock<HashMap<u64, Vec<WrittenLeaf>>>>,
}

/// Keeps the write batch of an association open while one write request is
/// served; dropping it hands the leaves the request stored over as one batch.
pub(crate) struct WriteBatch<'a> {
    view: &'a MmsDeviceModel,
    conn_id: u64,
    /// Whether this guard opened the batch, rather than finding it open.
    opened: bool,
}

impl Drop for WriteBatch<'_> {
    fn drop(&mut self) {
        if !self.opened {
            return;
        }
        let leaves = crate::compat::rwlock_write(&self.view.write_batches)
            .and_then(|mut batches| batches.remove(&self.conn_id));
        if let (Some(leaves), Some(sink)) = (leaves, self.view.written_leaves()) {
            if !leaves.is_empty() {
                sink.leaves_written(&leaves);
            }
        }
    }
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
            value_lock: Arc::new(RwLock::new(())),
            written_leaves: Arc::new(RwLock::new(None)),
            write_batches: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Opens the write batch of association `conn_id` for one write request:
    /// until the returned guard is dropped, the leaves its writes store are
    /// held back, and then handed over together. A batch already open for
    /// the association stays in the hands of its own guard.
    #[cfg_attr(not(feature = "full-server"), allow(dead_code))]
    pub(crate) fn open_write_batch(&self, conn_id: u64) -> WriteBatch<'_> {
        let opened = crate::compat::rwlock_write(&self.write_batches).is_some_and(|mut batches| {
            let open = batches.len();
            batches.entry(conn_id).or_default();
            batches.len() > open
        });
        WriteBatch {
            view: self,
            conn_id,
            opened,
        }
    }

    /// Hands over the leaves one write of association `conn_id` stored: into
    /// its open write batch, or, with none open, straight to where a write
    /// hands its leaves.
    pub(crate) fn hand_over_written(&self, conn_id: u64, leaves: Vec<WrittenLeaf>) {
        if leaves.is_empty() {
            return;
        }
        let leaves = match crate::compat::rwlock_write(&self.write_batches) {
            Some(mut batches) => match batches.get_mut(&conn_id) {
                Some(batch) => {
                    batch.extend(leaves);
                    return;
                }
                None => leaves,
            },
            None => leaves,
        };
        if let Some(sink) = self.written_leaves() {
            sink.leaves_written(&leaves);
        }
    }

    /// Sets where a write hands the leaves it stored.
    #[cfg_attr(not(feature = "full-server"), allow(dead_code))]
    pub(crate) fn set_written_leaves(&self, sink: Weak<dyn WrittenLeaves>) {
        if let Some(mut g) = crate::compat::rwlock_write(&self.written_leaves) {
            *g = Some(sink);
        }
    }

    /// Returns where a write hands the leaves it stored, while its owner lives.
    pub(crate) fn written_leaves(&self) -> Option<Arc<dyn WrittenLeaves>> {
        crate::compat::rwlock_read(&self.written_leaves)?
            .as_ref()?
            .upgrade()
    }

    /// The lock that keeps a read from seeing part of a write; see the field.
    pub(crate) fn value_lock(&self) -> &RwLock<()> {
        &self.value_lock
    }

    /// A handle on the same lock as [`value_lock`](Self::value_lock), for the
    /// reporting engine.
    #[cfg(feature = "full-server")]
    pub(crate) fn shared_value_lock(&self) -> Arc<RwLock<()>> {
        Arc::clone(&self.value_lock)
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

    /// Returns the type specification an item id names, `LN[$FC[$DO...]]`,
    /// walking the structure of its logical node one name at a time.
    ///
    /// `None` means the domain or a step does not exist, or a step passes
    /// through something other than a structure.
    pub(crate) fn spec_at(&self, domain: &str, item_id: &str) -> Option<&MmsTypeSpec> {
        let mut steps = item_id.split('$');
        let mut spec = self.get_variable_spec(domain, steps.next()?)?;
        for step in steps {
            let MmsTypeSpec::Structure(members) = spec else {
                return None;
            };
            spec = &members.iter().find(|m| m.name == step)?.type_spec;
        }
        Some(spec)
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
        if let Some(sgcb) = ln.sgcb.as_ref().filter(|_| has_sgcb_for_fc) {
            fc_children.push(NamedVariableSpec {
                name: "SGCB".to_string(),
                type_spec: build_sgcb_type_spec(sgcb.has_resv_tms),
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
/// sub-objects that carry one functional constraint; an array of
/// sub-data-objects is an array of that structure.
fn build_do_type_spec(d: &DataObject, fc: FC) -> Result<MmsTypeSpec> {
    match (d.array_count, d.element(0)) {
        (Some(count), Some(element)) => Ok(MmsTypeSpec::Array {
            count,
            inner: Box::new(build_do_struct_for_fc(element, fc)?),
        }),
        _ => build_do_struct_for_fc(d, fc),
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

/// Maps a data attribute onto a type specification, per IEC 61850-8-1 §5.2;
/// an array maps onto an MMS array of its element type (§8.1.2.7).
fn build_da_type_spec(da: &DataAttribute) -> Result<MmsTypeSpec> {
    if let (Some(count), Some(element)) = (da.array_count, da.element(0)) {
        return Ok(MmsTypeSpec::Array {
            count,
            inner: Box::new(build_da_type_spec(element)?),
        });
    }
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

    if da.ty == DataAttributeType::PhyComAddr {
        return Ok(phy_com_addr_type_spec());
    }

    let leaf = leaf_from_da_type(da.ty)?;
    Ok(MmsTypeSpec::Leaf(leaf))
}

/// The PhyComAddr structure: `Addr`, `PRIORITY`, `VID` and `APPID`.
fn phy_com_addr_type_spec() -> MmsTypeSpec {
    MmsTypeSpec::Structure(vec![
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
    ])
}

/// Returns the declared size of a bit-string data attribute type, or `None` for
/// a type that is not a bit string.
pub(crate) fn declared_bit_string_size(ty: DataAttributeType) -> Option<StringSize> {
    match leaf_from_da_type(ty) {
        Ok(MmsLeafType::BitString(size)) => Some(size),
        _ => None,
    }
}

/// Returns the bit count of a bit string of `byte_len` bytes with `padding`
/// unused bits in its last byte, or `None` when `padding` is 8 or more, or
/// nonzero for an empty string.
pub(crate) fn bit_string_len(byte_len: usize, padding: u8) -> Option<usize> {
    if padding >= 8 || (byte_len == 0 && padding != 0) {
        return None;
    }
    byte_len.checked_mul(8)?.checked_sub(usize::from(padding))
}

/// Reports whether a bit string of `byte_len` bytes with `padding` unused bits
/// in its last byte fits a declared size: exactly N bits for `Fixed(N)`, 1 to N
/// bits for `Max(N)`, any length for `Generic`.
///
/// A padding [`bit_string_len`] refuses never fits.
pub(crate) fn bit_string_fits(size: StringSize, byte_len: usize, padding: u8) -> bool {
    let Some(bits) = bit_string_len(byte_len, padding) else {
        return false;
    };
    match size {
        StringSize::Fixed(n) => bits == usize::from(n),
        StringSize::Max(n) => (1..=usize::from(n)).contains(&bits),
        StringSize::Generic => true,
    }
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
        T::Int24 => MmsLeafType::Integer(24),
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
        T::SvOptFlds => MmsLeafType::BitString(StringSize::Max(5)),
        T::LogOptFlds => MmsLeafType::BitString(StringSize::Max(1)),
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
        _ => {
            return Err(ServerError::InvalidModel(format!(
                "data attribute type {:?} has no MMS mapping",
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

/// Builds the structure of a setting group control block: `NumOfSG`, `ActSG`,
/// `EditSG`, `CnfEdit`, and `LActTm`, followed by `ResvTms` when the control
/// block exposes it, as IEC 61850-8-1 Ed2 maps it.
fn build_sgcb_type_spec(has_resv_tms: bool) -> MmsTypeSpec {
    use MmsLeafType as L;
    let mut members = vec![
        leaf_member("NumOfSG", L::Unsigned(8)),
        leaf_member("ActSG", L::Unsigned(8)),
        leaf_member("EditSG", L::Unsigned(8)),
        leaf_member("CnfEdit", L::Boolean),
        leaf_member("LActTm", L::UtcTime),
    ];
    if has_resv_tms {
        members.push(leaf_member("ResvTms", L::Unsigned(16)));
    }
    MmsTypeSpec::Structure(members)
}

fn leaf_member(name: &str, leaf: MmsLeafType) -> NamedVariableSpec {
    NamedVariableSpec {
        name: name.to_string(),
        type_spec: MmsTypeSpec::Leaf(leaf),
    }
}

/// Returns `name` as the fully qualified MMS name a control block attribute
/// carries, per IEC 61850-8-1 §8.1.3.2.2: a name in the form `<LN>$<object>`
/// becomes `<domain>/<LN>$<object>`. An empty name, an association-specific
/// name (`@<object>`), and a name that already has a scope (`<domain>/...` or
/// `/<object>`) are returned unchanged.
#[cfg(any(feature = "reporting", feature = "logging", feature = "goose-mapping"))]
pub(crate) fn qualified_object_reference(domain: &str, name: &str) -> String {
    if name.is_empty() || name.starts_with('@') || name.contains('/') || domain.is_empty() {
        name.to_string()
    } else {
        format!("{domain}/{name}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Control blocks registered at run time
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of a control block a server registers at run time, which decides
/// the functional-constraint group it appears in and its MMS structure.
#[cfg(any(feature = "reporting", feature = "logging", feature = "goose-mapping"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlBlockKind {
    /// An unbuffered report control block, under RP.
    #[cfg(feature = "reporting")]
    Unbuffered,
    /// A buffered report control block, under BR.
    #[cfg(feature = "reporting")]
    Buffered,
    /// A log control block, under LG.
    #[cfg(feature = "logging")]
    Log,
    /// A GOOSE control block, under GO.
    #[cfg(feature = "goose-mapping")]
    Goose,
}

#[cfg(any(feature = "reporting", feature = "logging", feature = "goose-mapping"))]
impl ControlBlockKind {
    /// The functional-constraint group the control block belongs to.
    pub(crate) fn fc(self) -> FC {
        match self {
            #[cfg(feature = "reporting")]
            Self::Unbuffered => FC::Rp,
            #[cfg(feature = "reporting")]
            Self::Buffered => FC::Br,
            #[cfg(feature = "logging")]
            Self::Log => FC::Lg,
            #[cfg(feature = "goose-mapping")]
            Self::Goose => FC::Go,
        }
    }

    /// The MMS structure of the control block, members in the order
    /// IEC 61850-8-1 maps them.
    ///
    /// A report control block ends in `Owner`. A log control block has the nine
    /// members `LogEna`, `LogRef`, `DatSet`, `OldEntrTm`, `NewEntrTm`, `OldEnt`,
    /// `NewEnt`, `TrgOps`, and `IntgPd`: the ACSI attributes OldEntr and NewEntr
    /// map onto the MMS components `OldEnt` and `NewEnt`. A GOOSE control block
    /// has the nine components of IEC 61850-8-1 §18.1.1.1.1 Table 83, named by
    /// [`GOCB_DA_NAMES`](crate::goose_mapping::GOCB_DA_NAMES).
    pub(crate) fn type_spec(self) -> MmsTypeSpec {
        use MmsLeafType as L;
        let object_ref = || L::VisibleString(StringSize::Max(129));
        let members = match self {
            #[cfg(feature = "reporting")]
            Self::Unbuffered => vec![
                leaf_member("RptID", object_ref()),
                leaf_member("RptEna", L::Boolean),
                leaf_member("Resv", L::Boolean),
                leaf_member("DatSet", object_ref()),
                leaf_member("ConfRev", L::Unsigned(32)),
                leaf_member("OptFlds", L::BitString(StringSize::Max(10))),
                leaf_member("BufTm", L::Unsigned(32)),
                leaf_member("SqNum", L::Unsigned(8)),
                leaf_member("TrgOps", L::BitString(StringSize::Max(6))),
                leaf_member("IntgPd", L::Unsigned(32)),
                leaf_member("GI", L::Boolean),
                leaf_member("Owner", L::OctetString(StringSize::Max(64))),
            ],
            #[cfg(feature = "reporting")]
            Self::Buffered => vec![
                leaf_member("RptID", object_ref()),
                leaf_member("RptEna", L::Boolean),
                leaf_member("DatSet", object_ref()),
                leaf_member("ConfRev", L::Unsigned(32)),
                leaf_member("OptFlds", L::BitString(StringSize::Max(10))),
                leaf_member("BufTm", L::Unsigned(32)),
                leaf_member("SqNum", L::Unsigned(16)),
                leaf_member("TrgOps", L::BitString(StringSize::Max(6))),
                leaf_member("IntgPd", L::Unsigned(32)),
                leaf_member("GI", L::Boolean),
                leaf_member("PurgeBuf", L::Boolean),
                leaf_member("EntryID", L::OctetString(StringSize::Fixed(8))),
                leaf_member("TimeofEntry", L::BinaryTime { size: 6 }),
                leaf_member("ResvTms", L::Integer(16)),
                leaf_member("Owner", L::OctetString(StringSize::Max(64))),
            ],
            #[cfg(feature = "logging")]
            Self::Log => vec![
                leaf_member("LogEna", L::Boolean),
                leaf_member("LogRef", object_ref()),
                leaf_member("DatSet", object_ref()),
                leaf_member("OldEntrTm", L::BinaryTime { size: 6 }),
                leaf_member("NewEntrTm", L::BinaryTime { size: 6 }),
                leaf_member("OldEnt", L::OctetString(StringSize::Fixed(8))),
                leaf_member("NewEnt", L::OctetString(StringSize::Fixed(8))),
                leaf_member("TrgOps", L::BitString(StringSize::Max(6))),
                leaf_member("IntgPd", L::Unsigned(32)),
            ],
            #[cfg(feature = "goose-mapping")]
            Self::Goose => {
                let types = [
                    MmsTypeSpec::Leaf(L::Boolean),
                    MmsTypeSpec::Leaf(object_ref()),
                    MmsTypeSpec::Leaf(object_ref()),
                    MmsTypeSpec::Leaf(L::Unsigned(32)),
                    MmsTypeSpec::Leaf(L::Boolean),
                    phy_com_addr_type_spec(),
                    MmsTypeSpec::Leaf(L::Unsigned(32)),
                    MmsTypeSpec::Leaf(L::Unsigned(32)),
                    MmsTypeSpec::Leaf(L::Boolean),
                ];
                crate::goose_mapping::GOCB_DA_NAMES
                    .iter()
                    .zip(types)
                    .map(|(name, type_spec)| NamedVariableSpec {
                        name: (*name).to_string(),
                        type_spec,
                    })
                    .collect()
            }
        };
        MmsTypeSpec::Structure(members)
    }
}

/// Maps a member name a client may use for a log control block onto the MMS
/// component it stands for: the ACSI attribute names `OldEntr` and `NewEntr`
/// are accepted for `OldEnt` and `NewEnt`. Any other name maps onto itself.
///
/// The ACSI names are never listed; they only resolve.
#[cfg(feature = "logging")]
pub(crate) fn lcb_member_name(name: &str) -> &str {
    match name {
        "OldEntr" => "OldEnt",
        "NewEntr" => "NewEnt",
        other => other,
    }
}

/// One control block of a logical node, registered at run time.
#[cfg(any(feature = "reporting", feature = "logging", feature = "goose-mapping"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ControlBlockEntry {
    /// The control block kind.
    pub(crate) kind: ControlBlockKind,
    /// The control block name, the member name within its group.
    pub(crate) name: String,
}

/// Returns the structure of a logical node with its run-time control blocks
/// merged in.
///
/// Each control block becomes a member of the group of its functional
/// constraint, ahead of the data objects of that group and in the order
/// `blocks` lists them; a group the model has no data for is created in its
/// place in the IEC 61850-8-1 order. A Read of a logical node or of one of its
/// groups lays its value out the same way.
#[cfg(any(feature = "reporting", feature = "logging", feature = "goose-mapping"))]
pub(crate) fn ln_spec_with_control_blocks(
    base: &MmsTypeSpec,
    blocks: &[ControlBlockEntry],
) -> MmsTypeSpec {
    let MmsTypeSpec::Structure(groups) = base else {
        return base.clone();
    };
    let mut merged = Vec::with_capacity(groups.len() + 3);
    for &fc in LN_FC_ORDER {
        let mut members: Vec<NamedVariableSpec> = blocks
            .iter()
            .filter(|b| b.kind.fc() == fc)
            .map(|b| NamedVariableSpec {
                name: b.name.clone(),
                type_spec: b.kind.type_spec(),
            })
            .collect();
        if let Some(group) = groups.iter().find(|g| g.name == fc.as_str()) {
            if let MmsTypeSpec::Structure(existing) = &group.type_spec {
                members.extend(existing.iter().cloned());
            }
        }
        if !members.is_empty() {
            merged.push(NamedVariableSpec {
                name: fc.as_str().to_string(),
                type_spec: MmsTypeSpec::Structure(members),
            });
        }
    }
    MmsTypeSpec::Structure(merged)
}

/// Returns the path of `prefix` and of every structure member beneath it, the
/// flattened form GetNameList reports.
#[cfg(any(feature = "reporting", feature = "logging", feature = "goose-mapping"))]
pub(crate) fn flat_paths(prefix: &str, spec: &MmsTypeSpec) -> Vec<String> {
    let mut out = Vec::new();
    push_flat_paths(prefix, spec, &mut out);
    out
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

    /// A data set name without a scope is qualified with the domain; every other
    /// form of IEC 61850-8-1 §8.1.3.2.2 is kept as it is.
    #[cfg(any(feature = "reporting", feature = "logging", feature = "goose-mapping"))]
    #[test]
    fn object_reference_is_qualified_only_when_it_has_no_scope() {
        assert_eq!(
            qualified_object_reference("IED1LD0", "LLN0$ds1"),
            "IED1LD0/LLN0$ds1"
        );
        for kept in ["", "IED1LD1/LLN0$ds1", "@ds1", "/ds1"] {
            assert_eq!(qualified_object_reference("IED1LD0", kept), kept);
        }
    }

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
        let element = DataObject::new("Ind".to_string(), vec![DoChild::Da(inner_da)]);
        let do_node = DataObject::array(element, 3).unwrap();
        let spec = build_do_type_spec(&do_node, FC::St).unwrap();
        match spec {
            MmsTypeSpec::Array { count, inner } => {
                assert_eq!(count, 3);
                assert!(matches!(*inner, MmsTypeSpec::Structure(ref m) if m.len() == 1));
            }
            other => panic!("an array data object must map to an array, got {:?}", other),
        }
    }

    /// An array data attribute maps onto an MMS array of its element type,
    /// basic or constructed (IEC 61850-8-1 §8.1.2.7).
    #[test]
    fn array_da_wraps_its_element_type() {
        let leaf = DataAttribute::new(
            "vals",
            FC::Sp,
            DataAttributeType::Int32,
            TrgOps::default(),
            MmsValue::Integer(0),
        );
        let spec = build_da_type_spec(&DataAttribute::array(leaf, 4).unwrap()).unwrap();
        assert_eq!(
            spec,
            MmsTypeSpec::Array {
                count: 4,
                inner: Box::new(MmsTypeSpec::Leaf(MmsLeafType::Integer(32))),
            }
        );
        let point = DataAttribute::constructed(
            "pts",
            FC::Sp,
            vec![DataAttribute::new(
                "x",
                FC::Sp,
                DataAttributeType::Float32,
                TrgOps::default(),
                MmsValue::Float32(0.0),
            )],
        );
        match build_da_type_spec(&DataAttribute::array(point, 2).unwrap()).unwrap() {
            MmsTypeSpec::Array { count: 2, inner } => match *inner {
                MmsTypeSpec::Structure(members) => {
                    assert_eq!(members.len(), 1);
                    assert_eq!(members[0].name, "x");
                }
                other => panic!("the element must be a structure, got {other:?}"),
            },
            other => panic!("an array attribute must map to an array, got {other:?}"),
        }
    }

    // ── Functional-constraint group order ───────────────────────────────

    #[test]
    fn ln_fc_order_mx_st_cf() {
        // The node is built directly: the model builder admits only LLN0
        // outside a logical device.
        let ln = LogicalNode::new(
            String::new(),
            "MMXU",
            "1",
            vec![DataObject::new(
                "TotW",
                vec![
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
            )],
        );
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
        let ln = LogicalNode::new(
            String::new(),
            "MMXU",
            "1",
            vec![DataObject::new(
                "TotW",
                vec![DoChild::Da(DataAttribute::new(
                    "mag",
                    FC::Mx,
                    DataAttributeType::Float32,
                    TrgOps::default(),
                    MmsValue::Float32(0.0),
                ))],
            )],
        );
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
        let mut ln = LogicalNode::new(
            String::new(),
            "LLN0",
            String::new(),
            vec![DataObject::new(
                "Mod",
                ln_with_sp_da().into_iter().map(DoChild::Da).collect(),
            )],
        );
        ln.sgcb = Some({
            let mut sgcb = SettingGroupControlBlock::default();
            sgcb.num_of_sg = 1;
            sgcb.act_sg = 1;
            sgcb.has_resv_tms = false;
            sgcb.default_resv_tms_s = 60;
            sgcb
        });
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

        let ln = LogicalNode::new(
            String::new(),
            "MMXU",
            "1",
            vec![DataObject::new(
                long_do.clone(),
                vec![DoChild::Da(DataAttribute::new(
                    long_da.clone(),
                    FC::Mx,
                    DataAttributeType::Float32,
                    TrgOps::default(),
                    MmsValue::Float32(0.0),
                ))],
            )],
        );

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
