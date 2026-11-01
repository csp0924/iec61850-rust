//! GoCB mapping onto MMS variables.
//!
//! Exposes a `GoosePublisher` as the MMS variable path
//! `<LD>/<LN>$GO$<gcbName>$<DA>`, so a client drives GetGoCBValues and
//! SetGoCBValues through the ordinary MMS Read and Write services.
//!
//! The GoCB is the MMS structure of IEC 61850-8-1 §18.1.1.1.1 Table 83, with
//! its components in this order:
//!
//! | Component | FC | Type | Access |
//! |---|---|---|---|
//! | GoEna | GO | BOOLEAN | read and write |
//! | GoID | GO | VisibleString | read; write up to Ed2 |
//! | DatSet | GO | VisibleString | read; write up to Ed2 |
//! | ConfRev | GO | UINT32 | read |
//! | NdsCom | GO | BOOLEAN | read |
//! | DstAddress | GO | PhyComAddress structure | read |
//! | MinTime | GO | UINT32, milliseconds | read |
//! | MaxTime | GO | UINT32, milliseconds | read |
//! | FixedOffs | GO | BOOLEAN | read |
//!
//! The GoCB reference is the name of the variable, not a component. MinTime,
//! MaxTime and FixedOffs are optional in Table 83 and always present here.
//!
//! The registry's [`Edition`] decides whether GoID and DatSet are writable:
//! `Ed2_1` follows Table 83, which makes both read-only, while `Ed2` and `Ed1`
//! follow IEC 61850-7-2 §18.2.1 Table 42, which lets a client write both while
//! the GoCB is disabled. The behavior of `Ed1` is that of `Ed2`.
//!
//! The publisher is the only source of every value: a read takes GoEna, goID,
//! datSet, confRev, ndsCom and the destination address from the publisher, and
//! MinTime and MaxTime from its first retransmission interval and its
//! steady-state interval, so what a client reads is what the publication
//! carries (IEC 61850-8-1 §18.1.2.5.2). FixedOffs is always FALSE: the
//! publisher encodes every value in its shortest form. GoID reads as the GoCB
//! reference while the publisher has no goID of its own, which is the
//! publication's goID too.
//!
//! Writing GoEna sets the publisher's enabled flag; it does not start or stop a
//! publishing thread. A caller decides from `enabled()` whether to transmit, which
//! keeps this mapping independent of how frames reach the network. Writing
//! DatSet replaces the publisher's datSet and increments its confRev; the
//! caller reads `data_set_ref()` to know which data set to publish.
//!
//! DstAddress is exposed as a structure of four members: the six-byte destination
//! MAC address as an OctetString, then the VLAN priority, VLAN identifier, and
//! APPID as unsigned integers.
//!
//! A control block the configuration gives no destination
//! ([`GoCBHandle::without_destination`]) is disabled by that configuration
//! (IEC 61850-8-1 §25.3.2): its `DstAddress$Addr` reads as the NULL address,
//! six zero octets, since `Addr` is a fixed six-octet OctetString (IEC 61850-8-1
//! §8.1.3.3 Table 16) and a fixed-length NULL value is all zero octets, as the
//! NULL EntryID of IEC 61850-7-2 is. Setting GoEna TRUE is refused with
//! `TemporarilyUnavailable`, since whether GoEna is writable depends on the
//! value of another attribute (IEC 61850-8-1 §8.1.3.4.4.2 Table 27).
//!
//! An unknown component name is refused with ObjectNonExistent on both read and
//! write, and a write to a read-only component with ObjectAccessDenied, rather
//! than being silently ignored.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use iec61850_goose::GoosePublisher;
use iec61850_mms::mms::pdu::common::{DataAccessError, MmsData, WriteOutcome};

use crate::config::Edition;
use crate::mapping::{ControlBlockKind, MmsTypeSpec};

// GoCB handle

/// One server-side GoCB: where it sits in the MMS name space and the publisher
/// it controls.
///
/// A caller registers the handle once through `GoCBRegistry::register`, and MMS
/// reads and writes drive it afterwards. The handle stores no GoCB value of its
/// own: every read goes to the publisher, behind its mutex, so a change the
/// application makes on the publisher is what the next read returns.
#[non_exhaustive]
pub struct GoCBHandle {
    /// Logical device, which is the MMS domain, for example `"IED1LD0"`.
    pub ld: String,
    /// Logical node, normally `"LLN0"`.
    pub ln: String,
    /// GoCB name, without the `$GO$` prefix.
    pub name: String,
    /// The publisher this control block drives and reads its values from.
    pub publisher: Arc<Mutex<GoosePublisher>>,
    /// Whether the configuration gives the control block a destination.
    /// `false` marks a control block an SCD file disables by giving it no
    /// `<GSE>`: its `DstAddress$Addr` reads as the NULL address, six zero
    /// octets, and GoEna cannot be set TRUE, whatever the publisher holds.
    pub has_destination: bool,
}

impl std::fmt::Debug for GoCBHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoCBHandle")
            .field("ld", &self.ld)
            .field("ln", &self.ln)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl GoCBHandle {
    /// Creates a GoCB handle.
    ///
    /// The publisher's gocbRef should be the reference of this control block,
    /// `<ld>/<ln>$GO$<name>`; registration warns when it is not.
    pub fn new(
        ld: impl Into<String>,
        ln: impl Into<String>,
        name: impl Into<String>,
        publisher: Arc<Mutex<GoosePublisher>>,
    ) -> Self {
        Self {
            ld: ld.into(),
            ln: ln.into(),
            name: name.into(),
            publisher,
            has_destination: true,
        }
    }

    /// Marks the control block as given no destination by the configuration;
    /// see [`has_destination`](Self::has_destination).
    pub fn without_destination(mut self) -> Self {
        self.has_destination = false;
        self
    }

    /// Returns the GoCBRef, `<LD>/<LN>$GO$<name>`.
    pub fn go_cb_ref(&self) -> String {
        format!("{}/{}$GO${}", self.ld, self.ln, self.name)
    }

    /// Returns GoEna as the publisher holds it; `false` when the publisher's
    /// mutex is poisoned.
    pub fn enabled(&self) -> bool {
        self.publisher.lock().map(|p| p.enabled()).unwrap_or(false)
    }

    /// Returns the MMS item base, `<LN>$GO$<name>`, which the dispatcher matches a
    /// `$GO$` path against.
    pub fn mms_item_base(&self) -> String {
        format!("{}$GO${}", self.ln, self.name)
    }

    /// Qualifies a data set reference with this control block's domain, so it
    /// reads `<LD>/<LN>$<dsName>` (IEC 61850-8-1 §8.1.3.2.2).
    ///
    /// An empty reference, a reference that already names a domain, a
    /// VMD-scope reference `/<name>` and an association-scope reference
    /// `@<name>` are kept; one in the form `<LN>$<dsName>` gains the domain,
    /// and a bare data set name gains the domain and this control block's
    /// logical node. A control block whose logical device is empty adds no
    /// domain.
    pub fn qualify_data_set_ref(&self, data_set_ref: &str) -> String {
        let bare = !data_set_ref.is_empty()
            && !data_set_ref.contains(['/', '$'])
            && !data_set_ref.starts_with('@');
        if bare {
            crate::mapping::qualified_object_reference(
                &self.ld,
                &format!("{}${}", self.ln, data_set_ref),
            )
        } else {
            crate::mapping::qualified_object_reference(&self.ld, data_set_ref)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GoCBRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// Registry of every GoCB the server exposes.
///
/// `IedServer` holds an `Arc<GoCBRegistry>` and the dispatcher shares that `Arc`.
/// Entries are keyed by `(domain, item_base)`, for example
/// `("IED1LD0", "LLN0$GO$gcb01")`. The registry carries the edition the server
/// presents, which decides the writable components, and the lookup a DatSet
/// write checks its data set against.
pub struct GoCBRegistry {
    inner: std::sync::RwLock<HashMap<(String, String), Arc<GoCBHandle>>>,
    edition: Edition,
    data_sets: Option<DataSetLookup>,
}

/// Answers whether the server holds a data set, given its domain and its name
/// within the domain; a VMD-scope data set has the empty domain.
pub type DataSetLookup = Arc<dyn Fn(&str, &str) -> bool + Send + Sync + std::panic::RefUnwindSafe>;

impl std::fmt::Debug for GoCBRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoCBRegistry")
            .field("len", &self.len())
            .field("edition", &self.edition)
            .field("data_sets", &self.data_sets.is_some())
            .finish()
    }
}

impl Default for GoCBRegistry {
    fn default() -> Self {
        Self::with_edition(Edition::Ed2)
    }
}

impl GoCBRegistry {
    /// Creates an empty registry for the default edition, `Ed2`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty registry for `edition`.
    pub fn with_edition(edition: Edition) -> Self {
        Self {
            inner: std::sync::RwLock::default(),
            edition,
            data_sets: None,
        }
    }

    /// Sets the lookup a DatSet write checks its data set against. Without one,
    /// a DatSet write is checked for its form only.
    pub fn with_data_set_lookup(mut self, lookup: DataSetLookup) -> Self {
        self.data_sets = Some(lookup);
        self
    }

    /// Returns the edition the registry's control blocks follow.
    pub fn edition(&self) -> Edition {
        self.edition
    }

    /// Whether the data set `data_set_ref` names exists: `true` when the
    /// registry has no lookup. `data_set_ref` is `<domain>/<name>`, or
    /// `/<name>` for a VMD-scope data set.
    fn data_set_exists(&self, data_set_ref: &str) -> bool {
        let Some(lookup) = &self.data_sets else {
            return true;
        };
        data_set_ref
            .split_once('/')
            .is_some_and(|(domain, name)| lookup(domain, name))
    }

    /// Registers a GoCB. An entry with the same key is replaced, and the call then
    /// returns `false`.
    ///
    /// A publisher datSet that names no domain is qualified with the control
    /// block's domain first, so the publication and a read carry the same
    /// complete reference.
    pub fn register(&self, handle: Arc<GoCBHandle>) -> bool {
        match handle.publisher.lock() {
            Ok(mut p) => {
                if p.gocb_ref() != handle.go_cb_ref() {
                    tracing::warn!(
                        gocb = handle.go_cb_ref(),
                        publisher_gocb_ref = p.gocb_ref(),
                        "the publisher's gocbRef is not the reference of the control block it is registered under"
                    );
                }
                let qualified = handle.qualify_data_set_ref(p.data_set_ref());
                if qualified != p.data_set_ref() {
                    tracing::info!(
                        gocb = handle.go_cb_ref(),
                        dat_set = %qualified,
                        "qualified the publisher's datSet with the control block's domain"
                    );
                    if p.set_data_set_ref(qualified).is_err() {
                        tracing::warn!(
                            gocb = handle.go_cb_ref(),
                            "the publisher refused the qualified datSet"
                        );
                    }
                }
            }
            Err(_) => tracing::warn!(
                gocb = handle.go_cb_ref(),
                "gocb publisher mutex poisoned, its datSet is registered as it is"
            ),
        }
        let key = (handle.ld.clone(), handle.mms_item_base());
        let Ok(mut g) = self.inner.write() else {
            tracing::warn!("gocb registry lock poisoned, control block not registered");
            return false;
        };
        g.insert(key, handle).is_none()
    }

    /// Looks up a GoCB by name, without the `$GO$` prefix.
    pub fn find(&self, domain: &str, ln: &str, name: &str) -> Option<Arc<GoCBHandle>> {
        let key = (domain.to_string(), format!("{ln}$GO${name}"));
        self.inner.read().ok()?.get(&key).cloned()
    }

    /// Looks up a GoCB by its MMS item base, `<LN>$GO$<name>`.
    pub fn find_by_item_base(&self, domain: &str, item_base: &str) -> Option<Arc<GoCBHandle>> {
        let key = (domain.to_string(), item_base.to_string());
        self.inner.read().ok()?.get(&key).cloned()
    }

    /// Lists the MMS item bases, `<LN>$GO$<name>`, of every GoCB in a domain.
    pub fn item_bases_in_domain(&self, domain: &str) -> Vec<String> {
        let Ok(g) = self.inner.read() else {
            tracing::warn!(
                domain,
                "gocb registry lock poisoned, no control block is listed"
            );
            return vec![];
        };
        let mut out: Vec<String> = g
            .keys()
            .filter(|(d, _)| d == domain)
            .map(|(_, item_base)| item_base.clone())
            .collect();
        out.sort();
        out
    }

    /// Returns whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.read().map(|g| g.is_empty()).unwrap_or(true)
    }

    /// Returns the number of registered control blocks.
    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }
}

/// Longest ObjectReference, VISIBLE STRING129 (IEC 61850-7-2 §6.1.2.3 Table 4).
const MAX_OBJECT_REFERENCE_LEN: usize = 129;

/// The nine components of the GoCB MMS structure, in the order of
/// IEC 61850-8-1 §18.1.1.1.1 Table 83.
pub const GOCB_DA_NAMES: &[&str] = &[
    "GoEna",
    "GoID",
    "DatSet",
    "ConfRev",
    "NdsCom",
    "DstAddress",
    "MinTime",
    "MaxTime",
    "FixedOffs",
];

// ─────────────────────────────────────────────────────────────────────────────
// Read service helper
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes a whole GoCB as an `MmsData::Structure` of nine components, in the
/// order of `GOCB_DA_NAMES`, from one consistent view of the publisher.
///
/// This answers a client read of `<LN>$GO$<name>` with no component suffix.
///
/// # Errors
///
/// `HardwareFault` when the publisher's mutex is poisoned.
pub fn encode_gocb_structure(handle: &GoCBHandle) -> Result<MmsData, DataAccessError> {
    let publisher = lock_publisher(handle)?;
    let items = GOCB_DA_NAMES
        .iter()
        .filter_map(|name| encode_component(&publisher, handle.has_destination, name))
        .collect();
    Ok(MmsData::Structure(items))
}

/// Encodes one GoCB component, or a member below one.
///
/// `da_name` is a component name such as `GoEna`, or a `$`-separated path into
/// a structured component such as `DstAddress$APPID`; members are found by the
/// names the GoCB's type description gives them.
///
/// # Errors
///
/// `ObjectNonExistent` for a path that names no component or member of
/// Table 83, and `HardwareFault` when the publisher's mutex is poisoned.
pub fn encode_gocb_da(handle: &GoCBHandle, da_name: &str) -> Result<MmsData, DataAccessError> {
    let mut segments = da_name.split('$');
    let component = segments.next().unwrap_or_default();
    let value = {
        let publisher = lock_publisher(handle)?;
        encode_component(&publisher, handle.has_destination, component)
    };
    let (Some(mut value), Some(mut spec)) = (value, component_type_spec(component)) else {
        tracing::warn!(da_name, "read of an unknown GoCB component");
        return Err(DataAccessError::ObjectNonExistent);
    };
    for member in segments {
        match select_member(value, &spec, member) {
            Some((v, s)) => {
                value = v;
                spec = s;
            }
            None => {
                tracing::warn!(da_name, member, "read of an unknown GoCB component member");
                return Err(DataAccessError::ObjectNonExistent);
            }
        }
    }
    Ok(value)
}

/// The type description of one GoCB component.
fn component_type_spec(component: &str) -> Option<MmsTypeSpec> {
    let MmsTypeSpec::Structure(members) = ControlBlockKind::Goose.type_spec() else {
        return None;
    };
    members
        .into_iter()
        .find(|m| m.name == component)
        .map(|m| m.type_spec)
}

/// Selects the member called `name` of a structured value, by the position its
/// type description gives it.
fn select_member(value: MmsData, spec: &MmsTypeSpec, name: &str) -> Option<(MmsData, MmsTypeSpec)> {
    let (MmsData::Structure(items), MmsTypeSpec::Structure(members)) = (value, spec) else {
        return None;
    };
    let index = members.iter().position(|m| m.name == name)?;
    let item = items.into_iter().nth(index)?;
    Some((item, members[index].type_spec.clone()))
}

/// Locks the publisher, reporting a poisoned mutex as a hardware fault, the
/// access error a client expects when the server cannot reach the underlying
/// object.
fn lock_publisher(
    handle: &GoCBHandle,
) -> Result<std::sync::MutexGuard<'_, GoosePublisher>, DataAccessError> {
    handle.publisher.lock().map_err(|_| {
        tracing::warn!(gocb = handle.go_cb_ref(), "gocb publisher mutex poisoned");
        DataAccessError::HardwareFault
    })
}

/// Encodes one component from the publisher; `None` for a name that is not a
/// component. Without a destination, `DstAddress$Addr` is six zero octets.
fn encode_component(p: &GoosePublisher, has_destination: bool, da_name: &str) -> Option<MmsData> {
    let millis =
        |d: std::time::Duration| u64::from(u32::try_from(d.as_millis()).unwrap_or(u32::MAX));
    let value = match da_name {
        "GoEna" => MmsData::Boolean(p.enabled()),
        "GoID" => MmsData::VisibleString(p.go_id().unwrap_or(p.gocb_ref()).to_string()),
        "DatSet" => MmsData::VisibleString(p.data_set_ref().to_string()),
        "ConfRev" => MmsData::Unsigned(u64::from(p.conf_rev())),
        "NdsCom" => MmsData::Boolean(p.needs_commission()),
        "DstAddress" => {
            let comm = p.comm_parameters();
            let vlan = comm.vlan;
            MmsData::Structure(vec![
                // Addr: the six-byte MAC address, an OctetString on the wire;
                // the NULL address, six zero octets, for a control block the
                // configuration disables (IEC 61850-8-1 §25.3.2).
                MmsData::OctetString(if has_destination {
                    comm.dst_mac.to_vec()
                } else {
                    vec![0; 6]
                }),
                // PRIORITY: the VLAN priority, 0 when there is no VLAN tag.
                MmsData::Unsigned(vlan.map_or(0, |v| u64::from(v.priority.value()))),
                // VID: the VLAN identifier, 0 when there is no VLAN tag.
                MmsData::Unsigned(vlan.map_or(0, |v| u64::from(v.vlan_id))),
                // APPID.
                MmsData::Unsigned(u64::from(comm.app_id)),
            ])
        }
        "MinTime" => MmsData::Unsigned(millis(p.retrans_intervals().t1)),
        "MaxTime" => MmsData::Unsigned(millis(p.retrans_intervals().tmax)),
        "FixedOffs" => MmsData::Boolean(false),
        _ => return None,
    };
    Some(value)
}

// ─────────────────────────────────────────────────────────────────────────────
// Write service helper
// ─────────────────────────────────────────────────────────────────────────────

/// Applies an MMS write to one GoCB component under the edition of `registry`.
///
/// GoEna, a boolean, is writable in every edition; setting it TRUE is refused
/// with `ObjectValueInvalid` while DatSet is empty or ConfRev is 0, the
/// inconsistent configuration of IEC 61850-7-2 §18.2.1.3, and with
/// `TemporarilyUnavailable` when the control block has no destination
/// (IEC 61850-8-1 §8.1.3.4.4.2 Table 27); either leaves it disabled.
///
/// Under `Edition::Ed2_1`, GoID and DatSet are read-only and refused with
/// `ObjectAccessDenied` (IEC 61850-8-1 §18.1.1.1.1 Table 83). Under `Ed2` and
/// `Ed1`, GoID and DatSet, visible strings, are writable while the publisher
/// is disabled, and otherwise they are refused with `TemporarilyUnavailable`
/// (IEC 61850-7-2 §18.2.2.6.3).
///
/// A DatSet write takes a data set reference with or without its domain and
/// stores it qualified with the control block's domain. It must name a data
/// set the registry's lookup knows, VMD or domain scope; a reference that is
/// empty, longer than an ObjectReference's 129 characters, association scope
/// (`@<name>`, IEC 61850-8-1 §18.1.1.1.1 Table 83 and §8.1.3.2.2) or unknown is
/// refused with `ObjectValueInvalid` and changes nothing. Every accepted DatSet
/// write increments ConfRev, also when the value is unchanged, skipping the
/// reserved value 0 (IEC 61850-7-2 §18.2.1.6).
///
/// The other six components are read-only and are
/// refused with `ObjectAccessDenied`, and so is a member below a component,
/// such as `DstAddress$APPID`. An unknown component is refused with
/// `ObjectNonExistent` and a value of the wrong type with `ObjectValueInvalid`.
pub fn apply_gocb_write(
    registry: &GoCBRegistry,
    handle: &GoCBHandle,
    da_name: &str,
    value: &MmsData,
) -> WriteOutcome {
    let edition = registry.edition();
    if da_name.contains('$') {
        return match encode_gocb_da(handle, da_name) {
            Ok(_) => {
                tracing::warn!(
                    da_name,
                    "write to a member of a read-only GoCB component refused"
                );
                WriteOutcome::Failure(DataAccessError::ObjectAccessDenied)
            }
            Err(e) => WriteOutcome::Failure(e),
        };
    }
    if edition == Edition::Ed2_1 && matches!(da_name, "GoID" | "DatSet") {
        tracing::warn!(da_name, "write refused: read-only in IEC 61850-8-1 Ed2.1");
        return WriteOutcome::Failure(DataAccessError::ObjectAccessDenied);
    }
    match da_name {
        "GoEna" => {
            let MmsData::Boolean(b) = value else {
                tracing::warn!(
                    da_name,
                    ?value,
                    "write GoEna refused: a Boolean is required"
                );
                return WriteOutcome::Failure(DataAccessError::ObjectValueInvalid);
            };
            let p = match lock_publisher(handle) {
                Ok(p) => p,
                Err(e) => return WriteOutcome::Failure(e),
            };
            if *b && !handle.has_destination {
                tracing::warn!(
                    gocb = handle.go_cb_ref(),
                    "write GoEna=TRUE refused: the configuration gives no destination"
                );
                return WriteOutcome::Failure(DataAccessError::TemporarilyUnavailable);
            }
            if *b && (p.data_set_ref().is_empty() || p.conf_rev() == 0) {
                tracing::warn!(
                    gocb = handle.go_cb_ref(),
                    conf_rev = p.conf_rev(),
                    "write GoEna=TRUE refused: DatSet is empty or ConfRev is 0"
                );
                return WriteOutcome::Failure(DataAccessError::ObjectValueInvalid);
            }
            p.set_enabled(*b);
            tracing::info!(gocb = handle.go_cb_ref(), go_ena = *b, "GoCB GoEna changed");
            WriteOutcome::Success
        }
        "GoID" => {
            let MmsData::VisibleString(s) = value else {
                tracing::warn!(
                    da_name,
                    ?value,
                    "write GoID refused: a VisibleString is required"
                );
                return WriteOutcome::Failure(DataAccessError::ObjectValueInvalid);
            };
            let mut p = match lock_publisher(handle) {
                Ok(p) => p,
                Err(e) => return WriteOutcome::Failure(e),
            };
            // IEC 61850-7-2 SetGoCBValues: only GoEna may change while the
            // control block is enabled.
            if p.enabled() {
                tracing::warn!(da_name, "write GoID refused: GoEna is true");
                return WriteOutcome::Failure(DataAccessError::TemporarilyUnavailable);
            }
            p.set_go_id(Some(s.clone()));
            tracing::info!(gocb = handle.go_cb_ref(), go_id = %s, "GoCB GoID changed");
            WriteOutcome::Success
        }
        "DatSet" => {
            let MmsData::VisibleString(s) = value else {
                tracing::warn!(
                    da_name,
                    ?value,
                    "write DatSet refused: a VisibleString is required"
                );
                return WriteOutcome::Failure(DataAccessError::ObjectValueInvalid);
            };
            let qualified = handle.qualify_data_set_ref(s);
            let association_scope = qualified
                .split_once('/')
                .map_or(qualified.as_str(), |(_, name)| name)
                .starts_with('@');
            if s.is_empty() || association_scope || qualified.len() > MAX_OBJECT_REFERENCE_LEN {
                tracing::warn!(
                    da_name,
                    dat_set = %qualified,
                    "write DatSet refused: not a VMD or domain scope data set reference"
                );
                return WriteOutcome::Failure(DataAccessError::ObjectValueInvalid);
            }
            if !registry.data_set_exists(&qualified) {
                tracing::warn!(
                    da_name,
                    dat_set = %qualified,
                    "write DatSet refused: no such data set"
                );
                return WriteOutcome::Failure(DataAccessError::ObjectValueInvalid);
            }
            let mut p = match lock_publisher(handle) {
                Ok(p) => p,
                Err(e) => return WriteOutcome::Failure(e),
            };
            if p.enabled() {
                tracing::warn!(da_name, "write DatSet refused: GoEna is true");
                return WriteOutcome::Failure(DataAccessError::TemporarilyUnavailable);
            }
            if p.set_data_set_ref(qualified.clone()).is_err() {
                return WriteOutcome::Failure(DataAccessError::ObjectValueInvalid);
            }
            let conf_rev = match p.conf_rev().wrapping_add(1) {
                0 => 1,
                next => next,
            };
            p.set_conf_rev(conf_rev);
            tracing::info!(
                gocb = handle.go_cb_ref(),
                dat_set = %qualified,
                conf_rev,
                "GoCB DatSet changed"
            );
            WriteOutcome::Success
        }
        // Read-only components.
        "ConfRev" | "NdsCom" | "DstAddress" | "MinTime" | "MaxTime" | "FixedOffs" => {
            tracing::warn!(da_name, "write to a read-only GoCB component refused");
            WriteOutcome::Failure(DataAccessError::ObjectAccessDenied)
        }
        _ => {
            tracing::warn!(da_name, "write to an unknown GoCB component refused");
            WriteOutcome::Failure(DataAccessError::ObjectNonExistent)
        }
    }
}

/// Splits an MMS item identifier of the form `<LN>$GO$<name>` or
/// `<LN>$GO$<name>$<da>[$<member>...]` into its item base and the optional
/// component path below it, such as `GoEna` or `DstAddress$APPID`.
///
/// Returns `None` when the identifier has fewer than three segments, an empty
/// segment, or a second segment other than `GO`.
pub fn parse_go_item_id(item_id: &str) -> Option<(&str, Option<&str>)> {
    let mut parts = item_id.splitn(4, '$');
    let (Some(ln), Some("GO"), Some(name)) = (parts.next(), parts.next(), parts.next()) else {
        return None;
    };
    if ln.is_empty() || name.is_empty() {
        return None;
    }
    match parts.next() {
        None => Some((item_id, None)),
        Some(path) if !path.is_empty() && !path.split('$').any(str::is_empty) => {
            let base_len = ln.len() + "$GO$".len() + name.len();
            Some((&item_id[..base_len], Some(path)))
        }
        Some(_) => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use iec61850_goose::frame::{VlanPriority, VlanTag};
    use iec61850_goose::publisher::{CommParameters, RetransIntervals};
    use std::time::Duration;

    fn sample_publisher(data_set_ref: &str) -> Arc<Mutex<GoosePublisher>> {
        let comm = CommParameters::new(0x1000, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01])
            .with_src_mac([0x00, 0x50, 0xc2, 0x12, 0x34, 0x56])
            .with_vlan(VlanTag {
                priority: VlanPriority::new(4).unwrap(),
                vlan_id: 100,
            });
        let p = GoosePublisher::new(comm, "IED1LD0/LLN0$GO$gcb01", None, data_set_ref, 5).unwrap();
        Arc::new(Mutex::new(p))
    }

    fn sample_handle() -> Arc<GoCBHandle> {
        Arc::new(GoCBHandle::new(
            "IED1LD0",
            "LLN0",
            "gcb01",
            sample_publisher("IED1LD0/LLN0$ds1"),
        ))
    }

    fn read(h: &GoCBHandle, da: &str) -> MmsData {
        encode_gocb_da(h, da).unwrap()
    }

    // ── Registry ───────────────────────────────────────────────────────────────

    #[test]
    fn register_and_find() {
        let reg = GoCBRegistry::new();
        let h = sample_handle();
        assert!(reg.register(h.clone()));
        let found = reg.find("IED1LD0", "LLN0", "gcb01").expect("registered");
        assert_eq!(found.go_cb_ref(), "IED1LD0/LLN0$GO$gcb01");
    }

    #[test]
    fn register_duplicate_returns_false() {
        let reg = GoCBRegistry::new();
        let h = sample_handle();
        assert!(reg.register(h.clone()));
        // Registering the same key again replaces the entry and reports false.
        assert!(!reg.register(h));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn register_qualifies_a_data_set_ref_without_a_domain() {
        for (configured, qualified) in [
            ("LLN0$ds1", "IED1LD0/LLN0$ds1"),
            ("ds1", "IED1LD0/LLN0$ds1"),
            ("OTHER/LLN0$ds1", "OTHER/LLN0$ds1"),
        ] {
            let h = Arc::new(GoCBHandle::new(
                "IED1LD0",
                "LLN0",
                "gcb01",
                sample_publisher(configured),
            ));
            GoCBRegistry::new().register(h.clone());
            assert_eq!(h.publisher.lock().unwrap().data_set_ref(), qualified);
            assert_eq!(read(&h, "DatSet"), MmsData::VisibleString(qualified.into()));
        }
    }

    #[test]
    fn find_by_item_base() {
        let reg = GoCBRegistry::new();
        let h = sample_handle();
        reg.register(h);
        let found = reg.find_by_item_base("IED1LD0", "LLN0$GO$gcb01");
        assert!(found.is_some());
        assert!(reg.find_by_item_base("IED1LD0", "LLN0$GO$nosuch").is_none());
    }

    #[test]
    fn item_bases_in_domain_lists_each_registered_block() {
        let reg = GoCBRegistry::new();
        reg.register(sample_handle());
        assert_eq!(reg.item_bases_in_domain("IED1LD0"), ["LLN0$GO$gcb01"]);
        assert!(reg.item_bases_in_domain("OTHER").is_empty());
    }

    // ── encode_gocb_da ──────────────────────────────────────────────────────────

    #[test]
    fn encode_fixed_offs_is_false() {
        let h = sample_handle();
        assert_eq!(read(&h, "FixedOffs"), MmsData::Boolean(false));
    }

    #[test]
    fn encode_go_ena_default_false() {
        let h = sample_handle();
        assert_eq!(read(&h, "GoEna"), MmsData::Boolean(false));
    }

    #[test]
    fn encode_go_id_falls_back_to_gocbref() {
        let h = sample_handle();
        assert_eq!(
            read(&h, "GoID"),
            MmsData::VisibleString("IED1LD0/LLN0$GO$gcb01".into())
        );
    }

    #[test]
    fn encode_dat_set() {
        let h = sample_handle();
        assert_eq!(
            read(&h, "DatSet"),
            MmsData::VisibleString("IED1LD0/LLN0$ds1".into())
        );
    }

    #[test]
    fn encode_conf_rev() {
        let h = sample_handle();
        assert_eq!(read(&h, "ConfRev"), MmsData::Unsigned(5));
    }

    #[test]
    fn encode_nds_com() {
        let h = sample_handle();
        assert_eq!(read(&h, "NdsCom"), MmsData::Boolean(false));
    }

    #[test]
    fn encode_dst_address_structure() {
        let h = sample_handle();
        match read(&h, "DstAddress") {
            MmsData::Structure(items) => {
                assert_eq!(items.len(), 4);
                assert_eq!(
                    items[0],
                    MmsData::OctetString(vec![0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01])
                );
                assert_eq!(items[1], MmsData::Unsigned(4)); // priority
                assert_eq!(items[2], MmsData::Unsigned(100)); // vid
                assert_eq!(items[3], MmsData::Unsigned(0x1000)); // appid
            }
            other => panic!("expected a Structure, got {:?}", other),
        }
    }

    #[test]
    fn encode_min_max_time_follow_the_retransmission_intervals() {
        let h = sample_handle();
        assert_eq!(read(&h, "MinTime"), MmsData::Unsigned(4));
        assert_eq!(read(&h, "MaxTime"), MmsData::Unsigned(1000));
    }

    #[test]
    fn encode_unknown_component_is_non_existent() {
        let h = sample_handle();
        for da in ["NoSuchDA", "GoCBRef"] {
            assert_eq!(
                encode_gocb_da(&h, da),
                Err(DataAccessError::ObjectNonExistent)
            );
        }
    }

    /// A change the application makes on the publisher is what the next read
    /// returns; the handle keeps no second copy.
    #[test]
    fn reads_follow_changes_made_on_the_publisher() {
        let h = sample_handle();
        {
            let mut p = h.publisher.lock().unwrap();
            p.set_conf_rev(9);
            p.set_needs_commission(true);
            p.set_go_id(Some("app-goid".into()));
            p.set_enabled(true);
            let mut intervals = RetransIntervals::default();
            intervals.t1 = Duration::from_millis(2);
            intervals.tmax = Duration::from_millis(5000);
            p.set_retrans_intervals(intervals);
        }
        assert_eq!(read(&h, "ConfRev"), MmsData::Unsigned(9));
        assert_eq!(read(&h, "NdsCom"), MmsData::Boolean(true));
        assert_eq!(read(&h, "GoID"), MmsData::VisibleString("app-goid".into()));
        assert_eq!(read(&h, "GoEna"), MmsData::Boolean(true));
        assert!(h.enabled());
        assert_eq!(read(&h, "MinTime"), MmsData::Unsigned(2));
        assert_eq!(read(&h, "MaxTime"), MmsData::Unsigned(5000));
    }

    #[test]
    fn encode_full_structure() {
        let h = sample_handle();
        match encode_gocb_structure(&h).unwrap() {
            MmsData::Structure(items) => {
                assert_eq!(items.len(), 9);
                assert_eq!(items[0], MmsData::Boolean(false), "GoEna leads");
                assert_eq!(items[8], MmsData::Boolean(false), "FixedOffs ends");
                for (item, name) in items.iter().zip(GOCB_DA_NAMES) {
                    assert_eq!(item, &read(&h, name), "component {name}");
                }
            }
            other => panic!("expected a Structure, got {:?}", other),
        }
    }

    // ── apply_gocb_write ────────────────────────────────────────────────────────

    #[test]
    fn write_go_ena_true_succeeds_and_publisher_enabled() {
        let h = sample_handle();
        assert!(!h.enabled());
        let r = apply_gocb_write(&GoCBRegistry::new(), &h, "GoEna", &MmsData::Boolean(true));
        assert_eq!(r, WriteOutcome::Success);
        assert!(h.enabled());
        assert!(h.publisher.lock().unwrap().enabled());
    }

    #[test]
    fn write_go_ena_false_after_true_disables() {
        let h = sample_handle();
        apply_gocb_write(&GoCBRegistry::new(), &h, "GoEna", &MmsData::Boolean(true));
        assert!(h.enabled());
        apply_gocb_write(&GoCBRegistry::new(), &h, "GoEna", &MmsData::Boolean(false));
        assert!(!h.enabled());
        assert!(!h.publisher.lock().unwrap().enabled());
    }

    #[test]
    fn enabling_with_conf_rev_zero_is_refused() {
        let h = sample_handle();
        h.publisher.lock().unwrap().set_conf_rev(0);
        assert_eq!(
            apply_gocb_write(&GoCBRegistry::new(), &h, "GoEna", &MmsData::Boolean(true)),
            WriteOutcome::Failure(DataAccessError::ObjectValueInvalid)
        );
        assert!(!h.enabled());
        assert_eq!(
            apply_gocb_write(&GoCBRegistry::new(), &h, "GoEna", &MmsData::Boolean(false)),
            WriteOutcome::Success
        );
        h.publisher.lock().unwrap().set_conf_rev(1);
        assert_eq!(
            apply_gocb_write(&GoCBRegistry::new(), &h, "GoEna", &MmsData::Boolean(true)),
            WriteOutcome::Success
        );
        assert!(h.enabled());
    }

    #[test]
    fn write_go_ena_wrong_type_rejects() {
        let h = sample_handle();
        let r = apply_gocb_write(&GoCBRegistry::new(), &h, "GoEna", &MmsData::Unsigned(1));
        assert_eq!(
            r,
            WriteOutcome::Failure(DataAccessError::ObjectValueInvalid)
        );
    }

    #[test]
    fn write_go_id_succeeds() {
        let h = sample_handle();
        let r = apply_gocb_write(
            &GoCBRegistry::new(),
            &h,
            "GoID",
            &MmsData::VisibleString("MyGoID".into()),
        );
        assert_eq!(r, WriteOutcome::Success);
        assert_eq!(read(&h, "GoID"), MmsData::VisibleString("MyGoID".into()));
        assert_eq!(h.publisher.lock().unwrap().go_id(), Some("MyGoID"));
    }

    #[test]
    fn write_go_id_wrong_type_rejects() {
        let h = sample_handle();
        let r = apply_gocb_write(&GoCBRegistry::new(), &h, "GoID", &MmsData::Boolean(true));
        assert_eq!(
            r,
            WriteOutcome::Failure(DataAccessError::ObjectValueInvalid)
        );
    }

    #[test]
    fn write_readonly_da_rejects() {
        let h = sample_handle();
        for da in [
            "ConfRev",
            "NdsCom",
            "DstAddress",
            "MinTime",
            "MaxTime",
            "FixedOffs",
        ] {
            let r = apply_gocb_write(&GoCBRegistry::new(), &h, da, &MmsData::Boolean(true));
            assert_eq!(
                r,
                WriteOutcome::Failure(DataAccessError::ObjectAccessDenied),
                "{da} must be refused as read-only"
            );
        }
    }

    #[test]
    fn write_dat_set_qualifies_it_and_increments_conf_rev() {
        let h = sample_handle();
        for (written, stored, conf_rev) in [
            ("IED1LD0/LLN0$ds2", "IED1LD0/LLN0$ds2", 6),
            ("LLN0$ds3", "IED1LD0/LLN0$ds3", 7),
            // The same value again still counts as a change.
            ("IED1LD0/LLN0$ds3", "IED1LD0/LLN0$ds3", 8),
        ] {
            let r = apply_gocb_write(
                &GoCBRegistry::new(),
                &h,
                "DatSet",
                &MmsData::VisibleString(written.into()),
            );
            assert_eq!(r, WriteOutcome::Success, "{written}");
            assert_eq!(read(&h, "DatSet"), MmsData::VisibleString(stored.into()));
            assert_eq!(read(&h, "ConfRev"), MmsData::Unsigned(conf_rev));
        }
    }

    /// A registry whose lookup knows `IED1LD0/LLN0$ds1`, `IED1LD0/LLN0$ds2`
    /// and the VMD-scope `vmdds`.
    fn registry_with_data_sets() -> GoCBRegistry {
        GoCBRegistry::new().with_data_set_lookup(Arc::new(|domain: &str, name: &str| {
            matches!(
                (domain, name),
                ("IED1LD0", "LLN0$ds1") | ("IED1LD0", "LLN0$ds2") | ("", "vmdds")
            )
        }))
    }

    #[test]
    fn write_dat_set_must_name_a_known_data_set() {
        let reg = registry_with_data_sets();
        let h = sample_handle();
        for refused in [
            "IED1LD0/LLN0$nosuch",
            "nosuch",
            "/nosuch",
            "@ds1",
            "IED1LD0/@ds1",
        ] {
            assert_eq!(
                apply_gocb_write(&reg, &h, "DatSet", &MmsData::VisibleString(refused.into())),
                WriteOutcome::Failure(DataAccessError::ObjectValueInvalid),
                "{refused}"
            );
            assert_eq!(
                read(&h, "DatSet"),
                MmsData::VisibleString("IED1LD0/LLN0$ds1".into())
            );
            assert_eq!(read(&h, "ConfRev"), MmsData::Unsigned(5));
        }
        for (accepted, stored) in [("ds2", "IED1LD0/LLN0$ds2"), ("/vmdds", "/vmdds")] {
            assert_eq!(
                apply_gocb_write(&reg, &h, "DatSet", &MmsData::VisibleString(accepted.into())),
                WriteOutcome::Success,
                "{accepted}"
            );
            assert_eq!(read(&h, "DatSet"), MmsData::VisibleString(stored.into()));
        }
        assert_eq!(read(&h, "ConfRev"), MmsData::Unsigned(7));
    }

    /// Without a data set lookup only the form is checked, and an
    /// association-scope reference is still refused.
    #[test]
    fn write_dat_set_refuses_association_scope_without_a_lookup() {
        let h = sample_handle();
        for refused in ["@ds1", "IED1LD0/@ds1"] {
            assert_eq!(
                apply_gocb_write(
                    &GoCBRegistry::new(),
                    &h,
                    "DatSet",
                    &MmsData::VisibleString(refused.into())
                ),
                WriteOutcome::Failure(DataAccessError::ObjectValueInvalid),
                "{refused}"
            );
        }
        assert_eq!(read(&h, "ConfRev"), MmsData::Unsigned(5));
    }

    #[test]
    fn qualify_keeps_vmd_and_association_scope_references() {
        let h = sample_handle();
        assert_eq!(h.qualify_data_set_ref("@ds1"), "@ds1");
        assert_eq!(h.qualify_data_set_ref("/ds1"), "/ds1");
        assert_eq!(h.qualify_data_set_ref("LLN0$ds1"), "IED1LD0/LLN0$ds1");
        assert_eq!(h.qualify_data_set_ref("ds1"), "IED1LD0/LLN0$ds1");
        assert_eq!(h.qualify_data_set_ref(""), "");
    }

    #[test]
    fn write_dat_set_skips_the_reserved_conf_rev() {
        let h = sample_handle();
        h.publisher.lock().unwrap().set_conf_rev(u32::MAX);
        let r = apply_gocb_write(
            &GoCBRegistry::new(),
            &h,
            "DatSet",
            &MmsData::VisibleString("ds2".into()),
        );
        assert_eq!(r, WriteOutcome::Success);
        assert_eq!(read(&h, "ConfRev"), MmsData::Unsigned(1));
    }

    #[test]
    fn write_dat_set_refused_while_enabled_or_malformed() {
        let h = sample_handle();
        for bad in [
            MmsData::Boolean(true),
            MmsData::VisibleString(String::new()),
            MmsData::VisibleString("x".repeat(130)),
        ] {
            assert_eq!(
                apply_gocb_write(&GoCBRegistry::new(), &h, "DatSet", &bad),
                WriteOutcome::Failure(DataAccessError::ObjectValueInvalid)
            );
        }
        apply_gocb_write(&GoCBRegistry::new(), &h, "GoEna", &MmsData::Boolean(true));
        assert_eq!(
            apply_gocb_write(
                &GoCBRegistry::new(),
                &h,
                "DatSet",
                &MmsData::VisibleString("ds2".into())
            ),
            WriteOutcome::Failure(DataAccessError::TemporarilyUnavailable)
        );
        assert_eq!(
            read(&h, "DatSet"),
            MmsData::VisibleString("IED1LD0/LLN0$ds1".into())
        );
        assert_eq!(read(&h, "ConfRev"), MmsData::Unsigned(5));
    }

    #[test]
    fn ed2_1_refuses_go_id_and_dat_set_writes() {
        let h = sample_handle();
        for (da, value) in [
            ("GoID", MmsData::VisibleString("x".into())),
            ("DatSet", MmsData::VisibleString("ds2".into())),
        ] {
            assert_eq!(
                apply_gocb_write(&GoCBRegistry::with_edition(Edition::Ed2_1), &h, da, &value),
                WriteOutcome::Failure(DataAccessError::ObjectAccessDenied),
                "{da}"
            );
        }
        assert_eq!(
            read(&h, "GoID"),
            MmsData::VisibleString("IED1LD0/LLN0$GO$gcb01".into())
        );
        assert_eq!(read(&h, "ConfRev"), MmsData::Unsigned(5));
        assert_eq!(
            apply_gocb_write(
                &GoCBRegistry::with_edition(Edition::Ed2_1),
                &h,
                "GoEna",
                &MmsData::Boolean(true)
            ),
            WriteOutcome::Success
        );
    }

    #[test]
    fn ed1_writes_like_ed2() {
        let h = sample_handle();
        assert_eq!(
            apply_gocb_write(
                &GoCBRegistry::with_edition(Edition::Ed1),
                &h,
                "GoID",
                &MmsData::VisibleString("x".into())
            ),
            WriteOutcome::Success
        );
    }

    #[test]
    fn registry_carries_its_edition() {
        assert_eq!(GoCBRegistry::new().edition(), Edition::Ed2);
        assert_eq!(
            GoCBRegistry::with_edition(Edition::Ed2_1).edition(),
            Edition::Ed2_1
        );
    }

    #[test]
    fn write_unknown_da_returns_nonexistent() {
        let h = sample_handle();
        for da in ["NoSuchDA", "GoCBRef"] {
            let r = apply_gocb_write(&GoCBRegistry::new(), &h, da, &MmsData::Boolean(true));
            assert_eq!(r, WriteOutcome::Failure(DataAccessError::ObjectNonExistent));
        }
    }

    // ── parse_go_item_id ────────────────────────────────────────────────────────

    #[test]
    fn parse_go_item_id_three_parts_no_da() {
        let r = parse_go_item_id("LLN0$GO$gcb01");
        assert_eq!(r, Some(("LLN0$GO$gcb01", None)));
    }

    #[test]
    fn parse_go_item_id_four_parts_with_da() {
        let r = parse_go_item_id("LLN0$GO$gcb01$GoEna");
        assert_eq!(r, Some(("LLN0$GO$gcb01", Some("GoEna"))));
    }

    #[test]
    fn parse_go_item_id_wrong_fc_rejects() {
        assert!(parse_go_item_id("LLN0$RP$gcb01").is_none());
        assert!(parse_go_item_id("LLN0$ST$Mod").is_none());
    }

    #[test]
    fn parse_go_item_id_member_path() {
        let r = parse_go_item_id("LLN0$GO$gcb01$DstAddress$APPID");
        assert_eq!(r, Some(("LLN0$GO$gcb01", Some("DstAddress$APPID"))));
    }

    #[test]
    fn parse_go_item_id_malformed_rejects() {
        assert!(parse_go_item_id("LLN0$GO").is_none());
        assert!(parse_go_item_id("LLN0$GO$").is_none());
        assert!(parse_go_item_id("LLN0$GO$gcb01$").is_none());
        assert!(parse_go_item_id("LLN0$GO$gcb01$DstAddress$$APPID").is_none());
    }

    #[test]
    fn encode_member_of_dst_address() {
        let h = sample_handle();
        assert_eq!(read(&h, "DstAddress$APPID"), MmsData::Unsigned(0x1000));
        assert_eq!(
            read(&h, "DstAddress$Addr"),
            MmsData::OctetString(vec![0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01])
        );
        for path in ["DstAddress$Nope", "GoEna$x", "DstAddress$APPID$x"] {
            assert_eq!(
                encode_gocb_da(&h, path),
                Err(DataAccessError::ObjectNonExistent),
                "{path}"
            );
        }
    }

    #[test]
    fn write_member_of_dst_address_is_denied() {
        let h = sample_handle();
        assert_eq!(
            apply_gocb_write(
                &GoCBRegistry::new(),
                &h,
                "DstAddress$APPID",
                &MmsData::Unsigned(1)
            ),
            WriteOutcome::Failure(DataAccessError::ObjectAccessDenied)
        );
        assert_eq!(
            apply_gocb_write(
                &GoCBRegistry::new(),
                &h,
                "DstAddress$Nope",
                &MmsData::Unsigned(1)
            ),
            WriteOutcome::Failure(DataAccessError::ObjectNonExistent)
        );
    }
}
