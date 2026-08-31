//! GoCB mapping onto MMS variables.
//!
//! Exposes a `GoosePublisher` as the MMS variable path
//! `<LD>/<LN>$GO$<gcbName>$<DA>`, so a client drives GetGoCBValues and
//! SetGoCBValues through the ordinary MMS Read and Write services.
//!
//! The GoCB attributes of IEC 61850-7-2:
//!
//! | DA | FC | Type | Access |
//! |---|---|---|---|
//! | GoCBRef | GO | VisibleString | read |
//! | GoEna | GO | BOOLEAN | read and write |
//! | GoID | GO | VisibleString | read and write |
//! | DatSet | GO | VisibleString | read |
//! | ConfRev | GO | UINT32 | read |
//! | NdsCom | GO | BOOLEAN | read |
//! | DstAddress | GO | PhyComAddress structure | read |
//! | MinTime | GO | UINT32, milliseconds | read |
//! | MaxTime | GO | UINT32, milliseconds | read |
//!
//! Writing GoEna sets the publisher's enabled flag; it does not start or stop a
//! publishing thread. A caller decides from `enabled()` whether to transmit, which
//! keeps this mapping independent of how frames reach the network.
//!
//! DstAddress is exposed as a structure of four members: the six-byte destination
//! MAC address as an OctetString, then the VLAN priority, VLAN identifier, and
//! APPID as unsigned integers.
//!
//! An unknown DA name is refused with ObjectNonExistent on both read and write,
//! and a write to a read-only attribute with ObjectAccessDenied, rather than being
//! silently ignored.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use iec61850_goose::publisher::CommParameters as GoosePhyComAddress;
use iec61850_goose::GoosePublisher;
use iec61850_mms::mms::pdu::common::{DataAccessError, MmsData, WriteOutcome};

// GoCB handle

/// One server-side GoCB: its static metadata and the publisher it controls.
///
/// A caller registers the handle once through `GoCBRegistry::register`, and MMS
/// reads and writes drive it afterwards. The publisher is shared behind a mutex:
/// reading GoEna or GoID reads through it, writing GoEna calls `set_enabled`, and
/// writing GoID calls `set_go_id`.
pub struct GoCBHandle {
    /// Logical device, which is the MMS domain, for example `"IED1LD0"`.
    pub ld: String,
    /// Logical node, normally `"LLN0"`.
    pub ln: String,
    /// GoCB name, without the `$GO$` prefix.
    pub name: String,
    /// The publisher this control block drives.
    pub publisher: Arc<Mutex<GoosePublisher>>,
    /// ConfRev, fixed after construction; it is the ConfRev field on the wire.
    pub conf_rev: u32,
    /// Referenced data set, in the form `<LD>/<LN>$<dsName>`.
    pub data_set_ref: String,
    /// Configured GoID; `None` means the GoCBRef is sent instead.
    pub go_id: Mutex<Option<String>>,
    /// NdsCom: whether the control block still needs commissioning.
    pub nds_com: bool,
    /// Layer 2 communication parameters: destination MAC, APPID, and VLAN tag.
    pub dst_address: GoosePhyComAddress,
    /// MinTime in milliseconds, when configured.
    pub min_time_ms: Option<u32>,
    /// MaxTime in milliseconds, when configured.
    pub max_time_ms: Option<u32>,
    /// GoEna, kept in step with the publisher's own flag so a read does not have to
    /// lock the publisher.
    enabled: AtomicBool,
}

impl std::fmt::Debug for GoCBHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoCBHandle")
            .field("ld", &self.ld)
            .field("ln", &self.ln)
            .field("name", &self.name)
            .field("conf_rev", &self.conf_rev)
            .field("data_set_ref", &self.data_set_ref)
            .field("nds_com", &self.nds_com)
            .field("enabled", &self.enabled.load(Ordering::Acquire))
            .finish()
    }
}

impl GoCBHandle {
    /// Creates a GoCB handle.
    ///
    /// The caller aligns the publisher's own `gocb_ref`, `data_set_ref`, and
    /// `conf_rev` beforehand; this constructor only records the values the MMS read
    /// path needs and does not overwrite them.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ld: impl Into<String>,
        ln: impl Into<String>,
        name: impl Into<String>,
        publisher: Arc<Mutex<GoosePublisher>>,
        conf_rev: u32,
        data_set_ref: impl Into<String>,
        go_id: Option<String>,
        nds_com: bool,
        dst_address: GoosePhyComAddress,
        min_time_ms: Option<u32>,
        max_time_ms: Option<u32>,
    ) -> Self {
        Self {
            ld: ld.into(),
            ln: ln.into(),
            name: name.into(),
            publisher,
            conf_rev,
            data_set_ref: data_set_ref.into(),
            go_id: Mutex::new(go_id),
            nds_com,
            dst_address,
            min_time_ms,
            max_time_ms,
            enabled: AtomicBool::new(false),
        }
    }

    /// Returns the GoCBRef, `<LD>/<LN>$GO$<name>`.
    pub fn go_cb_ref(&self) -> String {
        format!("{}/{}$GO${}", self.ld, self.ln, self.name)
    }

    /// Returns whether publishing is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    /// Returns the configured GoID; `None` means the GoCBRef is used instead.
    pub fn go_id_snapshot(&self) -> Option<String> {
        self.go_id.lock().ok().and_then(|g| g.clone())
    }

    /// Returns the MMS item base, `<LN>$GO$<name>`, which the dispatcher matches a
    /// `$GO$` path against.
    pub fn mms_item_base(&self) -> String {
        format!("{}$GO${}", self.ln, self.name)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GoCBRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// Registry of every GoCB the server exposes.
///
/// `IedServer` holds an `Arc<GoCBRegistry>` and the dispatcher shares that `Arc`.
/// Entries are keyed by `(domain, item_base)`, for example
/// `("IED1LD0", "LLN0$GO$gcb01")`.
#[derive(Debug, Default)]
pub struct GoCBRegistry {
    inner: std::sync::RwLock<HashMap<(String, String), Arc<GoCBHandle>>>,
}

impl GoCBRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a GoCB. An entry with the same key is replaced, and the call then
    /// returns `false`.
    pub fn register(&self, handle: Arc<GoCBHandle>) -> bool {
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

    /// Lists the MMS names of every GoCB in a domain, for GetNameList.
    ///
    /// The result looks like `["LLN0$GO$gcb01$GoCBRef", "LLN0$GO$gcb01$GoEna", ...]`.
    pub fn list_mms_names_in_domain(&self, domain: &str) -> Vec<String> {
        let Ok(g) = self.inner.read() else {
            return vec![];
        };
        let mut out = Vec::new();
        for (d, item_base) in g.keys() {
            if d != domain {
                continue;
            }
            // Both the control block itself and its attributes are listed. A client
            // could reach the attributes through GetVariableAccessAttributes, but
            // listing them keeps the name list self-sufficient.
            out.push(item_base.clone());
            for da in GOCB_DA_NAMES {
                out.push(format!("{item_base}${da}"));
            }
        }
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

/// The nine GoCB attribute names of IEC 61850-7-2, in the order they are listed.
pub const GOCB_DA_NAMES: &[&str] = &[
    "GoCBRef",
    "GoEna",
    "GoID",
    "DatSet",
    "ConfRev",
    "NdsCom",
    "DstAddress",
    "MinTime",
    "MaxTime",
];

// ─────────────────────────────────────────────────────────────────────────────
// Read service helper
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes a whole GoCB as an `MmsData::Structure` of nine members, in the order
/// of `GOCB_DA_NAMES`.
///
/// This answers a client read of `<LN>$GO$<name>` with no attribute suffix.
pub fn encode_gocb_structure(handle: &GoCBHandle) -> MmsData {
    let items = GOCB_DA_NAMES
        .iter()
        .map(|name| encode_gocb_da(handle, name))
        .collect();
    MmsData::Structure(items)
}

/// Encodes one GoCB attribute.
///
/// An unrecognized name yields `MmsData::VisibleString("<unknown>")`. The
/// dispatcher checks the name first, so this helper does not return a `Result` and
/// spare the caller a second layer of matching.
pub fn encode_gocb_da(handle: &GoCBHandle, da_name: &str) -> MmsData {
    match da_name {
        "GoCBRef" => MmsData::VisibleString(handle.go_cb_ref()),
        "GoEna" => MmsData::Boolean(handle.enabled()),
        "GoID" => {
            let go_id = handle
                .go_id_snapshot()
                .unwrap_or_else(|| handle.go_cb_ref());
            MmsData::VisibleString(go_id)
        }
        "DatSet" => MmsData::VisibleString(handle.data_set_ref.clone()),
        "ConfRev" => MmsData::Unsigned(handle.conf_rev as u64),
        "NdsCom" => MmsData::Boolean(handle.nds_com),
        "DstAddress" => MmsData::Structure(vec![
            // Addr: the six-byte MAC address, an OctetString on the wire.
            MmsData::OctetString(handle.dst_address.dst_mac.to_vec()),
            // PRIORITY: the VLAN priority, 0 when there is no VLAN tag.
            MmsData::Unsigned(
                handle
                    .dst_address
                    .vlan
                    .map(|v| v.priority.value() as u64)
                    .unwrap_or(0),
            ),
            // VID: the VLAN identifier, 0 when there is no VLAN tag.
            MmsData::Unsigned(
                handle
                    .dst_address
                    .vlan
                    .map(|v| v.vlan_id as u64)
                    .unwrap_or(0),
            ),
            // APPID.
            MmsData::Unsigned(handle.dst_address.app_id as u64),
        ]),
        "MinTime" => MmsData::Unsigned(handle.min_time_ms.unwrap_or(0) as u64),
        "MaxTime" => MmsData::Unsigned(handle.max_time_ms.unwrap_or(0) as u64),
        _ => {
            tracing::warn!(da_name, "encode_gocb_da: unknown GoCB attribute name");
            MmsData::VisibleString("<unknown>".into())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Write service helper
// ─────────────────────────────────────────────────────────────────────────────

/// Applies an MMS write to one GoCB attribute.
///
/// GoEna, a boolean, and GoID, a visible string, are writable. The other seven
/// attributes are read-only and are refused with `ObjectAccessDenied`. An unknown
/// attribute is refused with `ObjectNonExistent` and a value of the wrong type with
/// `ObjectValueInvalid`.
pub fn apply_gocb_write(handle: &GoCBHandle, da_name: &str, value: &MmsData) -> WriteOutcome {
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
            // A poisoned publisher lock is reported as a hardware fault, which is
            // the access error a client expects when the server cannot reach the
            // underlying object.
            let lock_ok = match handle.publisher.lock() {
                Ok(p) => {
                    p.set_enabled(*b);
                    true
                }
                Err(_) => {
                    tracing::warn!(da_name, "write GoEna failed: publisher mutex poisoned");
                    false
                }
            };
            if !lock_ok {
                return WriteOutcome::Failure(DataAccessError::HardwareFault);
            }
            handle.enabled.store(*b, Ordering::Release);
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
            // The publisher and the handle are both updated, so what is on the wire
            // matches what a read returns.
            if let Ok(mut p) = handle.publisher.lock() {
                p.set_go_id(Some(s.clone()));
            } else {
                tracing::warn!(da_name, "write GoID failed: publisher mutex poisoned");
                return WriteOutcome::Failure(DataAccessError::HardwareFault);
            }
            if let Ok(mut g) = handle.go_id.lock() {
                *g = Some(s.clone());
            }
            tracing::info!(gocb = handle.go_cb_ref(), go_id = %s, "GoCB GoID changed");
            WriteOutcome::Success
        }
        // Read-only attributes.
        "GoCBRef" | "DatSet" | "ConfRev" | "NdsCom" | "DstAddress" | "MinTime" | "MaxTime" => {
            tracing::warn!(da_name, "write to a read-only GoCB attribute refused");
            WriteOutcome::Failure(DataAccessError::ObjectAccessDenied)
        }
        _ => {
            tracing::warn!(da_name, "write to an unknown GoCB attribute refused");
            WriteOutcome::Failure(DataAccessError::ObjectNonExistent)
        }
    }
}

/// Splits an MMS item identifier of the form `<LN>$GO$<name>` or
/// `<LN>$GO$<name>$<da>` into its item base and optional attribute name.
///
/// Returns `None` when the identifier has the wrong number of segments or its
/// second segment is not `GO`.
pub fn parse_go_item_id(item_id: &str) -> Option<(&str, Option<&str>)> {
    let parts: Vec<&str> = item_id.split('$').collect();
    match parts.len() {
        // <LN>$GO$<name>
        3 if parts[1] == "GO" => Some((item_id, None)),
        // <LN>$GO$<name>$<da>
        4 if parts[1] == "GO" => {
            // Split at the last separator.
            let last = item_id.rfind('$')?;
            let base = &item_id[..last];
            let da = &item_id[last + 1..];
            Some((base, Some(da)))
        }
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use iec61850_goose::frame::{VlanPriority, VlanTag};
    use iec61850_goose::publisher::CommParameters;

    fn sample_publisher() -> Arc<Mutex<GoosePublisher>> {
        let comm = CommParameters::new(0x1000, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01])
            .with_src_mac([0x00, 0x50, 0xc2, 0x12, 0x34, 0x56])
            .with_vlan(VlanTag {
                priority: VlanPriority::new(4).unwrap(),
                vlan_id: 100,
            });
        let p = GoosePublisher::new(comm, "IED1LD0/LLN0$GO$gcb01", None, "IED1LD0/LLN0$ds1", 5)
            .unwrap();
        Arc::new(Mutex::new(p))
    }

    fn sample_handle() -> Arc<GoCBHandle> {
        let p = sample_publisher();
        let comm =
            CommParameters::new(0x1000, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01]).with_vlan(VlanTag {
                priority: VlanPriority::new(4).unwrap(),
                vlan_id: 100,
            });
        Arc::new(GoCBHandle::new(
            "IED1LD0",
            "LLN0",
            "gcb01",
            p,
            5,
            "IED1LD0/LLN0$ds1",
            None,
            false,
            comm,
            Some(10),
            Some(2000),
        ))
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
    fn find_by_item_base() {
        let reg = GoCBRegistry::new();
        let h = sample_handle();
        reg.register(h);
        let found = reg.find_by_item_base("IED1LD0", "LLN0$GO$gcb01");
        assert!(found.is_some());
        assert!(reg.find_by_item_base("IED1LD0", "LLN0$GO$nosuch").is_none());
    }

    #[test]
    fn list_mms_names_in_domain_includes_all_da() {
        let reg = GoCBRegistry::new();
        let h = sample_handle();
        reg.register(h);
        let names = reg.list_mms_names_in_domain("IED1LD0");
        // One base name plus nine attributes.
        assert_eq!(names.len(), 10);
        assert!(names.contains(&"LLN0$GO$gcb01".to_string()));
        assert!(names.contains(&"LLN0$GO$gcb01$GoEna".to_string()));
        assert!(names.contains(&"LLN0$GO$gcb01$DstAddress".to_string()));
    }

    #[test]
    fn list_mms_names_in_other_domain_empty() {
        let reg = GoCBRegistry::new();
        let h = sample_handle();
        reg.register(h);
        let names = reg.list_mms_names_in_domain("OTHER");
        assert!(names.is_empty());
    }

    // ── encode_gocb_da ──────────────────────────────────────────────────────────

    #[test]
    fn encode_go_cb_ref() {
        let h = sample_handle();
        let v = encode_gocb_da(&h, "GoCBRef");
        assert_eq!(v, MmsData::VisibleString("IED1LD0/LLN0$GO$gcb01".into()));
    }

    #[test]
    fn encode_go_ena_default_false() {
        let h = sample_handle();
        let v = encode_gocb_da(&h, "GoEna");
        assert_eq!(v, MmsData::Boolean(false));
    }

    #[test]
    fn encode_go_id_falls_back_to_gocbref() {
        let h = sample_handle();
        let v = encode_gocb_da(&h, "GoID");
        assert_eq!(v, MmsData::VisibleString("IED1LD0/LLN0$GO$gcb01".into()));
    }

    #[test]
    fn encode_dat_set() {
        let h = sample_handle();
        let v = encode_gocb_da(&h, "DatSet");
        assert_eq!(v, MmsData::VisibleString("IED1LD0/LLN0$ds1".into()));
    }

    #[test]
    fn encode_conf_rev() {
        let h = sample_handle();
        assert_eq!(encode_gocb_da(&h, "ConfRev"), MmsData::Unsigned(5));
    }

    #[test]
    fn encode_nds_com() {
        let h = sample_handle();
        assert_eq!(encode_gocb_da(&h, "NdsCom"), MmsData::Boolean(false));
    }

    #[test]
    fn encode_dst_address_structure() {
        let h = sample_handle();
        let v = encode_gocb_da(&h, "DstAddress");
        match v {
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
    fn encode_min_max_time() {
        let h = sample_handle();
        assert_eq!(encode_gocb_da(&h, "MinTime"), MmsData::Unsigned(10));
        assert_eq!(encode_gocb_da(&h, "MaxTime"), MmsData::Unsigned(2000));
    }

    #[test]
    fn encode_full_structure() {
        let h = sample_handle();
        let v = encode_gocb_structure(&h);
        match v {
            MmsData::Structure(items) => {
                assert_eq!(items.len(), 9);
            }
            other => panic!("expected a Structure, got {:?}", other),
        }
    }

    // ── apply_gocb_write ────────────────────────────────────────────────────────

    #[test]
    fn write_go_ena_true_succeeds_and_publisher_enabled() {
        let h = sample_handle();
        assert!(!h.enabled());
        let r = apply_gocb_write(&h, "GoEna", &MmsData::Boolean(true));
        assert_eq!(r, WriteOutcome::Success);
        assert!(h.enabled());
        assert!(h.publisher.lock().unwrap().enabled());
    }

    #[test]
    fn write_go_ena_false_after_true_disables() {
        let h = sample_handle();
        apply_gocb_write(&h, "GoEna", &MmsData::Boolean(true));
        assert!(h.enabled());
        apply_gocb_write(&h, "GoEna", &MmsData::Boolean(false));
        assert!(!h.enabled());
        assert!(!h.publisher.lock().unwrap().enabled());
    }

    #[test]
    fn write_go_ena_wrong_type_rejects() {
        let h = sample_handle();
        let r = apply_gocb_write(&h, "GoEna", &MmsData::Unsigned(1));
        assert_eq!(
            r,
            WriteOutcome::Failure(DataAccessError::ObjectValueInvalid)
        );
    }

    #[test]
    fn write_go_id_succeeds() {
        let h = sample_handle();
        let r = apply_gocb_write(&h, "GoID", &MmsData::VisibleString("MyGoID".into()));
        assert_eq!(r, WriteOutcome::Success);
        assert_eq!(h.go_id_snapshot(), Some("MyGoID".to_string()));
        assert_eq!(h.publisher.lock().unwrap().go_id(), Some("MyGoID"));
    }

    #[test]
    fn write_go_id_wrong_type_rejects() {
        let h = sample_handle();
        let r = apply_gocb_write(&h, "GoID", &MmsData::Boolean(true));
        assert_eq!(
            r,
            WriteOutcome::Failure(DataAccessError::ObjectValueInvalid)
        );
    }

    #[test]
    fn write_readonly_da_rejects() {
        let h = sample_handle();
        for da in [
            "GoCBRef",
            "DatSet",
            "ConfRev",
            "NdsCom",
            "DstAddress",
            "MinTime",
            "MaxTime",
        ] {
            let r = apply_gocb_write(&h, da, &MmsData::Boolean(true));
            assert_eq!(
                r,
                WriteOutcome::Failure(DataAccessError::ObjectAccessDenied),
                "{da} must be refused as read-only"
            );
        }
    }

    #[test]
    fn write_unknown_da_returns_nonexistent() {
        let h = sample_handle();
        let r = apply_gocb_write(&h, "NoSuchDA", &MmsData::Boolean(true));
        assert_eq!(r, WriteOutcome::Failure(DataAccessError::ObjectNonExistent));
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
    fn parse_go_item_id_wrong_segment_count_rejects() {
        assert!(parse_go_item_id("LLN0$GO").is_none());
        assert!(parse_go_item_id("LLN0$GO$gcb01$GoEna$extra").is_none());
    }
}
