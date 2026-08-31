//! Server runtime for the setting group control block.
//!
//! A client drives the control block through three writes: `ActSG` selects the
//! active setting group and accepts 1 through the configured group count,
//! `EditSG` opens an edit session on a group and zero cancels it, and `CnfEdit`
//! set to true commits the edit.
//!
//! An edit session belongs to one association, identified by its connection id.
//! While another association holds the session, `EditSG` answers
//! `TemporarilyUnavailable` and `CnfEdit` answers `ObjectAccessDenied`.
//!
//! A session also carries a reservation deadline. Every `EditSG` and `CnfEdit`
//! checks it first, so an expired session counts as no session at all;
//! [`SettingGroupRegistry::tick_reservations`] releases expired sessions in the
//! background as well.
//!
//! This module implements the control protocol only. The values of a setting
//! group are stored by the application, which receives the commit through
//! [`SettingGroupHandler::confirm_edit_sg`] and writes the data attributes
//! itself.

use crate::connection::ConnectionId;
use iec61850_mms::mms::pdu::common::{
    AccessResult, DataAccessError, MmsData, ObjectName, WriteOutcome,
};
use iec61850_model::IedModel;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

// ─────────────────────────────────────────────────────────────────────────────
// SettingGroupHandler trait
// ─────────────────────────────────────────────────────────────────────────────

/// Application callbacks for the setting group control block.
///
/// Every default implementation allows the operation, which is also the
/// behavior when no handler is installed. The commit callback is a
/// notification and cannot veto.
pub trait SettingGroupHandler: Send + Sync {
    /// Called before the active setting group changes. Returning `false`
    /// refuses the change with `ObjectAccessDenied`.
    fn act_sg_changed(&self, _new_act_sg: u8, _conn_id: ConnectionId) -> bool {
        true
    }

    /// Called before an edit session opens. Returning `false` refuses it with
    /// `ObjectAccessDenied`. A cancellation, that is a group of zero, does not
    /// reach this callback.
    fn edit_sg_changed(&self, _new_edit_sg: u8, _conn_id: ConnectionId) -> bool {
        true
    }

    /// Called once a commit has passed every check and just before the edit
    /// session is cleared. The application reads the edited values here and
    /// stores them.
    fn confirm_edit_sg(&self, _edit_sg: u8, _conn_id: ConnectionId) {}
}

/// Handler that allows every operation and stores nothing on commit.
#[derive(Debug)]
pub struct DefaultSettingGroupHandler;
impl SettingGroupHandler for DefaultSettingGroupHandler {}

// ─────────────────────────────────────────────────────────────────────────────
// Per-logical-device runtime
// ─────────────────────────────────────────────────────────────────────────────

/// Mutable state of one setting group control block (IEC 61850-7-2 §13), with
/// the configured fields kept apart from the ones that change at run time.
pub struct SettingGroupRuntime {
    /// Number of setting groups; fixed when the server is built.
    pub num_of_sg: u8,
    /// Whether the control block exposes `ResvTms`; fixed when the server is
    /// built.
    pub has_resv_tms: bool,
    /// Reservation lifetime in seconds; fixed when the server is built.
    pub default_resv_tms_s: u16,
    state: RwLock<State>,
    handler: RwLock<Arc<dyn SettingGroupHandler>>,
}

#[derive(Debug, Clone, Copy)]
struct State {
    act_sg: u8,
    edit_sg: u8, // Zero means no edit session is open.
    last_act_tm_ms: u64,
    /// The association holding the edit session, if any.
    editing_conn: Option<ConnectionId>,
    /// When the edit session expires, in milliseconds since the epoch;
    /// meaningless while no session is open.
    reservation_expiry_ms: u64,
}

/// Values a read of the setting group control block reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SgcbSnapshot {
    /// Number of setting groups the device holds.
    pub num_of_sg: u8,
    /// Setting group currently active.
    pub act_sg: u8,
    /// Setting group being edited, or zero when no edit session is open.
    pub edit_sg: u8,
    /// Always false: the commit trigger is write-only.
    pub cnf_edit: bool,
    /// When the active group last changed, in milliseconds since the epoch.
    pub last_act_tm_ms: u64,
    /// Reservation lifetime in seconds, present only when the control block
    /// exposes `ResvTms`.
    pub resv_tms_s: Option<u16>,
}

impl SettingGroupRuntime {
    /// Creates the runtime with its configured fields.
    pub fn new(num_of_sg: u8, act_sg: u8, has_resv_tms: bool, default_resv_tms_s: u16) -> Self {
        let now_ms = now_ms();
        Self {
            num_of_sg,
            has_resv_tms,
            default_resv_tms_s,
            state: RwLock::new(State {
                act_sg,
                edit_sg: 0,
                last_act_tm_ms: now_ms,
                editing_conn: None,
                reservation_expiry_ms: 0,
            }),
            handler: RwLock::new(Arc::new(DefaultSettingGroupHandler)),
        }
    }

    /// Installs the application handler, replacing the default one.
    pub fn install_handler(&self, h: Arc<dyn SettingGroupHandler>) {
        if let Ok(mut g) = self.handler.write() {
            *g = h;
        } else {
            tracing::warn!("setting group handler lock is poisoned, handler not installed");
        }
    }

    /// Returns the current values of the control block.
    pub fn snapshot(&self) -> SgcbSnapshot {
        let s = match self.state.read() {
            Ok(g) => *g,
            Err(_) => {
                tracing::error!("setting group state lock is poisoned");
                return SgcbSnapshot {
                    num_of_sg: self.num_of_sg,
                    act_sg: 1,
                    edit_sg: 0,
                    cnf_edit: false,
                    last_act_tm_ms: 0,
                    resv_tms_s: if self.has_resv_tms {
                        Some(self.default_resv_tms_s)
                    } else {
                        None
                    },
                };
            }
        };
        SgcbSnapshot {
            num_of_sg: self.num_of_sg,
            act_sg: s.act_sg,
            edit_sg: s.edit_sg,
            // CnfEdit is a write-only trigger and always reads back as false.
            cnf_edit: false,
            last_act_tm_ms: s.last_act_tm_ms,
            resv_tms_s: if self.has_resv_tms {
                Some(self.default_resv_tms_s)
            } else {
                None
            },
        }
    }

    /// Selects the active setting group.
    ///
    /// Selecting the group that is already active succeeds and changes nothing.
    ///
    /// # Errors
    ///
    /// Returns `ObjectValueInvalid` for a group outside 1 through the group
    /// count, and `ObjectAccessDenied` when the handler refuses.
    pub fn try_select_active_sg(
        &self,
        new_act_sg: u8,
        conn_id: ConnectionId,
    ) -> Result<(), DataAccessError> {
        if new_act_sg < 1 || new_act_sg > self.num_of_sg {
            tracing::warn!(
                requested = new_act_sg,
                num_of_sg = self.num_of_sg,
                "select-active-sg: the group is outside the configured range"
            );
            return Err(DataAccessError::ObjectValueInvalid);
        }
        let handler = self.handler_clone();
        if !handler.act_sg_changed(new_act_sg, conn_id) {
            tracing::warn!(
                requested = new_act_sg,
                conn_id,
                "select-active-sg: the handler refused the change"
            );
            return Err(DataAccessError::ObjectAccessDenied);
        }
        let mut g = self.state.write().map_err(|_| {
            tracing::error!("setting group state lock is poisoned");
            DataAccessError::HardwareFault
        })?;
        g.act_sg = new_act_sg;
        g.last_act_tm_ms = now_ms();
        Ok(())
    }

    /// Opens an edit session on a setting group; a group of zero cancels the
    /// session this association holds.
    ///
    /// # Errors
    ///
    /// Returns `ObjectValueInvalid` for a group above the group count,
    /// `TemporarilyUnavailable` while another association holds the session,
    /// and `ObjectAccessDenied` when the handler refuses.
    pub fn try_edit_sg(
        &self,
        new_edit_sg: u8,
        conn_id: ConnectionId,
    ) -> Result<(), DataAccessError> {
        if new_edit_sg > self.num_of_sg {
            tracing::warn!(
                requested = new_edit_sg,
                num_of_sg = self.num_of_sg,
                "edit-sg: the group is outside the configured range"
            );
            return Err(DataAccessError::ObjectValueInvalid);
        }
        // An expired reservation is released first, so the conflict check below
        // does not see a session that no longer exists.
        self.expire_stale_session_if_any();

        let mut g = self.state.write().map_err(|_| {
            tracing::error!("setting group state lock is poisoned");
            DataAccessError::HardwareFault
        })?;

        if let Some(owner) = g.editing_conn {
            if owner != conn_id {
                tracing::warn!(
                    owner,
                    requester = conn_id,
                    "edit-sg: another association holds the edit session"
                );
                return Err(DataAccessError::TemporarilyUnavailable);
            }
        }

        // A cancellation does not consult the handler.
        if new_edit_sg > 0 {
            // The handler may perform I/O, so the write lock is released first.
            drop(g);
            let handler = self.handler_clone();
            if !handler.edit_sg_changed(new_edit_sg, conn_id) {
                tracing::warn!(
                    requested = new_edit_sg,
                    conn_id,
                    "edit-sg: the handler refused the session"
                );
                return Err(DataAccessError::ObjectAccessDenied);
            }
            let mut g = self.state.write().map_err(|_| {
                tracing::error!("setting group state lock is poisoned");
                DataAccessError::HardwareFault
            })?;
            g.edit_sg = new_edit_sg;
            g.editing_conn = Some(conn_id);
            g.reservation_expiry_ms =
                now_ms().saturating_add(self.default_resv_tms_s as u64 * 1000);
        } else {
            g.edit_sg = 0;
            g.editing_conn = None;
            g.reservation_expiry_ms = 0;
        }
        Ok(())
    }

    /// Commits the open edit session and clears it.
    ///
    /// The application is notified through
    /// [`SettingGroupHandler::confirm_edit_sg`] before the session is cleared.
    ///
    /// # Errors
    ///
    /// Returns `ObjectValueInvalid` when the written value is not `true`, and
    /// `ObjectAccessDenied` when no session is open, when the session has
    /// expired, or when it belongs to another association.
    pub fn try_confirm_edit_sg(
        &self,
        cnf_edit_value: bool,
        conn_id: ConnectionId,
    ) -> Result<(), DataAccessError> {
        if !cnf_edit_value {
            tracing::warn!(conn_id, "confirm-edit-sg: the written value must be true");
            return Err(DataAccessError::ObjectValueInvalid);
        }
        self.expire_stale_session_if_any();

        let edit_sg = {
            let g = self.state.read().map_err(|_| {
                tracing::error!("setting group state lock is poisoned");
                DataAccessError::HardwareFault
            })?;
            if g.edit_sg == 0 {
                tracing::warn!(conn_id, "confirm-edit-sg: no edit session is open");
                return Err(DataAccessError::ObjectAccessDenied);
            }
            match g.editing_conn {
                Some(owner) if owner == conn_id => {}
                Some(owner) => {
                    tracing::warn!(
                        owner,
                        requester = conn_id,
                        "confirm-edit-sg: the edit session belongs to another association"
                    );
                    return Err(DataAccessError::ObjectAccessDenied);
                }
                None => {
                    // An edit group without an owner is what expiry leaves
                    // behind, so there is no session to commit.
                    tracing::warn!(conn_id, "confirm-edit-sg: the edit session has expired");
                    return Err(DataAccessError::ObjectAccessDenied);
                }
            }
            g.edit_sg
        };

        // The application may persist the values, so the callback runs without
        // the lock held.
        let handler = self.handler_clone();
        handler.confirm_edit_sg(edit_sg, conn_id);

        let mut g = self.state.write().map_err(|_| {
            tracing::error!("setting group state lock is poisoned");
            DataAccessError::HardwareFault
        })?;
        g.edit_sg = 0;
        g.editing_conn = None;
        g.reservation_expiry_ms = 0;
        Ok(())
    }

    /// Reports whether the association owns an open edit session, that is
    /// whether a group is being edited and this association opened it. An
    /// expired session is released first.
    ///
    /// The Write service uses this to gate writes under functional constraint
    /// SE.
    pub fn is_edit_session_owner(&self, conn_id: ConnectionId) -> bool {
        self.expire_stale_session_if_any();
        let g = match self.state.read() {
            Ok(g) => *g,
            Err(_) => return false,
        };
        g.edit_sg > 0 && g.editing_conn == Some(conn_id)
    }

    /// Releases the edit session if its reservation has expired, returning the
    /// association that held it so the caller can log or notify. `None` means
    /// no session was open or it has not expired.
    pub fn tick_reservation(&self) -> Option<ConnectionId> {
        self.tick_reservation_at(now_ms())
    }

    /// [`SettingGroupRuntime::tick_reservation`] against a supplied clock.
    pub(crate) fn tick_reservation_at(&self, now: u64) -> Option<ConnectionId> {
        let mut g = match self.state.write() {
            Ok(g) => g,
            Err(_) => return None,
        };
        if g.editing_conn.is_some() && g.reservation_expiry_ms > 0 && now >= g.reservation_expiry_ms
        {
            let owner = g.editing_conn;
            g.edit_sg = 0;
            g.editing_conn = None;
            g.reservation_expiry_ms = 0;
            owner
        } else {
            None
        }
    }

    /// Releases the edit session an association holds, called when it closes.
    pub fn release_edit_session_for_conn(&self, conn_id: ConnectionId) {
        let mut g = match self.state.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!("setting group state lock is poisoned");
                return;
            }
        };
        if g.editing_conn == Some(conn_id) {
            tracing::info!(
                conn_id,
                "association closed, releasing its setting group edit session"
            );
            g.edit_sg = 0;
            g.editing_conn = None;
            g.reservation_expiry_ms = 0;
        }
    }

    /// Changes the active setting group from the server side, bypassing the
    /// handler; intended for application start-up.
    ///
    /// # Errors
    ///
    /// Returns `ObjectValueInvalid` for a group outside 1 through the group
    /// count.
    pub fn force_active_sg(&self, new_act_sg: u8) -> Result<(), DataAccessError> {
        if new_act_sg < 1 || new_act_sg > self.num_of_sg {
            return Err(DataAccessError::ObjectValueInvalid);
        }
        let mut g = self.state.write().map_err(|_| {
            tracing::error!("setting group state lock is poisoned");
            DataAccessError::HardwareFault
        })?;
        g.act_sg = new_act_sg;
        g.last_act_tm_ms = now_ms();
        Ok(())
    }

    fn handler_clone(&self) -> Arc<dyn SettingGroupHandler> {
        match self.handler.read() {
            Ok(g) => Arc::clone(&*g),
            Err(_) => {
                tracing::error!("setting group handler lock is poisoned");
                Arc::new(DefaultSettingGroupHandler)
            }
        }
    }

    /// Clears the edit session if its reservation deadline has passed.
    fn expire_stale_session_if_any(&self) {
        let now = now_ms();
        let mut g = match self.state.write() {
            Ok(g) => g,
            Err(_) => return,
        };
        if g.editing_conn.is_some() && g.reservation_expiry_ms > 0 && now >= g.reservation_expiry_ms
        {
            tracing::info!(
                "setting group edit session reservation expired at {} (deadline {}), releasing it",
                now,
                g.reservation_expiry_ms
            );
            g.edit_sg = 0;
            g.editing_conn = None;
            g.reservation_expiry_ms = 0;
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Registry across logical devices
// ─────────────────────────────────────────────────────────────────────────────

/// Setting group runtimes, keyed by MMS domain name.
pub struct SettingGroupRegistry {
    inner: RwLock<HashMap<String, Arc<SettingGroupRuntime>>>,
}

impl std::fmt::Debug for SettingGroupRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.inner.read().map(|g| g.len()).unwrap_or(0);
        f.debug_struct("SettingGroupRegistry")
            .field("entries", &count)
            .finish()
    }
}

impl std::fmt::Debug for SettingGroupRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let snap = self.snapshot();
        f.debug_struct("SettingGroupRuntime")
            .field("num_of_sg", &self.num_of_sg)
            .field("act_sg", &snap.act_sg)
            .field("edit_sg", &snap.edit_sg)
            .field("has_resv_tms", &self.has_resv_tms)
            .finish()
    }
}

impl Default for SettingGroupRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SettingGroupRegistry {
    /// Returns an empty registry.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Builds a registry from a model, with one runtime per logical device
    /// whose LLN0 declares a setting group control block.
    pub fn from_model(model: &IedModel) -> Self {
        let reg = Self::new();
        for ld in &model.lds {
            for ln in &ld.lns {
                if let Some(sgcb) = &ln.sgcb {
                    let domain = ld.domain_name(&model.ied_name);
                    let rt = Arc::new(SettingGroupRuntime::new(
                        sgcb.num_of_sg,
                        sgcb.act_sg,
                        sgcb.has_resv_tms,
                        sgcb.default_resv_tms_s,
                    ));
                    if let Ok(mut g) = reg.inner.write() {
                        g.insert(domain, rt);
                    }
                    // A logical device holds at most one control block.
                    break;
                }
            }
        }
        reg
    }

    /// Returns the setting group runtime of a domain, if it has one.
    pub fn lookup(&self, domain: &str) -> Option<Arc<SettingGroupRuntime>> {
        self.inner.read().ok()?.get(domain).cloned()
    }

    /// Returns how many control blocks are registered.
    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Reports whether no control block is registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Releases every expired edit session, returning the domain and the
    /// association that held each one, so the caller can log or notify.
    ///
    /// The server calls this from its periodic timer.
    pub fn tick_reservations(&self) -> Vec<(String, ConnectionId)> {
        self.tick_reservations_at(now_ms())
    }

    /// [`SettingGroupRegistry::tick_reservations`] against a supplied clock.
    pub(crate) fn tick_reservations_at(&self, now: u64) -> Vec<(String, ConnectionId)> {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let mut released = Vec::new();
        for (domain, rt) in g.iter() {
            if let Some(owner) = rt.tick_reservation_at(now) {
                released.push((domain.clone(), owner));
            }
        }
        released
    }

    /// Releases every edit session an association holds, across all domains.
    pub fn release_all_for_conn(&self, conn_id: ConnectionId) {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return,
        };
        for rt in g.values() {
            rt.release_edit_session_for_conn(conn_id);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire path routing
// ─────────────────────────────────────────────────────────────────────────────

/// What part of a setting group control block an object name selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SgcbField {
    /// The whole control block, named as `LN$SP$SGCB`.
    Whole,
    /// `NumOfSG`, the number of setting groups. Read-only.
    NumOfSg,
    /// `ActSG`, the active setting group.
    ActSg,
    /// `EditSG`, the setting group being edited.
    EditSg,
    /// `CnfEdit`, the commit trigger.
    CnfEdit,
    /// `LActTm`, when the active group last changed. Read-only.
    LActTm,
    /// `ResvTms`, the reservation lifetime. Read-only.
    ResvTms,
}

impl SgcbField {
    fn from_leaf_name(s: &str) -> Option<Self> {
        Some(match s {
            "NumOfSG" => Self::NumOfSg,
            "ActSG" => Self::ActSg,
            "EditSG" => Self::EditSg,
            "CnfEdit" => Self::CnfEdit,
            "LActTm" => Self::LActTm,
            "ResvTms" => Self::ResvTms,
            _ => return None,
        })
    }
}

/// Parses a domain-specific object name as a setting group control block path.
///
/// Three segments (`<LN>$SP$SGCB`) select the whole block and four select one
/// field. Any other name yields `None` and the caller continues with its other
/// routes.
pub fn extract_sgcb_target(name: &ObjectName) -> Option<(&str, &str, SgcbField)> {
    let (domain, item_id) = match name {
        ObjectName::DomainSpecific { domain_id, item_id } => (domain_id.as_str(), item_id.as_str()),
        _ => return None,
    };
    let parts: Vec<&str> = item_id.split('$').collect();
    if parts.len() < 3 || parts.len() > 4 {
        return None;
    }
    if parts[1] != "SP" || parts[2] != "SGCB" {
        return None;
    }
    let ln_name = parts[0];
    if ln_name.is_empty() {
        return None;
    }
    let field = if parts.len() == 3 {
        SgcbField::Whole
    } else {
        SgcbField::from_leaf_name(parts[3])?
    };
    Some((domain, ln_name, field))
}

/// Encodes milliseconds since the epoch as an IEC 61850 UTC timestamp: four
/// octets of whole seconds, three of fraction, and one of time quality.
///
/// The quality octet reports an accuracy of 10 bits, that is millisecond
/// resolution (IEC 61850-7-2 §6.2.3.4).
fn ms_to_utc_time(ms: u64) -> [u8; 8] {
    let secs = (ms / 1000) as u32;
    // The fraction is a 24-bit fixed-point value.
    let frac24 = ((ms % 1000) * (1u64 << 24) / 1000) as u32;
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&secs.to_be_bytes());
    out[4] = ((frac24 >> 16) & 0xff) as u8;
    out[5] = ((frac24 >> 8) & 0xff) as u8;
    out[6] = (frac24 & 0xff) as u8;
    out[7] = 0x0a; // accuracy = 10 (1 ms)
    out
}

/// Encodes a snapshot as the structure a whole-block read returns.
///
/// The members follow the order of the type specification: `NumOfSG`, `ActSG`,
/// `EditSG`, `CnfEdit`, `LActTm`, and `ResvTms` where it is exposed.
fn snapshot_to_struct(snap: &SgcbSnapshot) -> MmsData {
    let mut fields = vec![
        MmsData::Unsigned(snap.num_of_sg as u64),
        MmsData::Unsigned(snap.act_sg as u64),
        MmsData::Unsigned(snap.edit_sg as u64),
        MmsData::Boolean(snap.cnf_edit),
        MmsData::UtcTime(ms_to_utc_time(snap.last_act_tm_ms)),
    ];
    if let Some(resv) = snap.resv_tms_s {
        fields.push(MmsData::Unsigned(resv as u64));
    }
    MmsData::Structure(fields)
}

/// Answers a read of a setting group control block.
///
/// A domain with no control block answers `ObjectNonExistent`. The logical node
/// name is not checked: a control block always belongs to LLN0, so the
/// per-domain registry alone decides.
pub fn handle_sgcb_read(
    registry: &SettingGroupRegistry,
    domain: &str,
    _ln: &str,
    field: SgcbField,
) -> AccessResult {
    let rt = match registry.lookup(domain) {
        Some(rt) => rt,
        None => {
            tracing::warn!(
                domain,
                "read: the domain declares no setting group control block, answering object-non-existent"
            );
            return AccessResult::Failure(DataAccessError::ObjectNonExistent);
        }
    };
    let snap = rt.snapshot();
    let data = match field {
        SgcbField::Whole => snapshot_to_struct(&snap),
        SgcbField::NumOfSg => MmsData::Unsigned(snap.num_of_sg as u64),
        SgcbField::ActSg => MmsData::Unsigned(snap.act_sg as u64),
        SgcbField::EditSg => MmsData::Unsigned(snap.edit_sg as u64),
        SgcbField::CnfEdit => MmsData::Boolean(snap.cnf_edit),
        SgcbField::LActTm => MmsData::UtcTime(ms_to_utc_time(snap.last_act_tm_ms)),
        SgcbField::ResvTms => match snap.resv_tms_s {
            Some(v) => MmsData::Unsigned(v as u64),
            None => return AccessResult::Failure(DataAccessError::ObjectNonExistent),
        },
    };
    AccessResult::Success(data)
}

/// Answers a write to a setting group control block.
///
/// `ActSG` and `EditSG` take an unsigned value within the range of a byte and
/// `CnfEdit` takes `true`. `NumOfSG`, `LActTm`, `ResvTms`, and the block as a
/// whole are read-only and answer `ObjectAccessDenied`.
pub fn handle_sgcb_write(
    registry: &SettingGroupRegistry,
    domain: &str,
    _ln: &str,
    field: SgcbField,
    data: &MmsData,
    conn_id: ConnectionId,
) -> WriteOutcome {
    let rt = match registry.lookup(domain) {
        Some(rt) => rt,
        None => {
            tracing::warn!(
                domain,
                "write: the domain declares no setting group control block, answering object-non-existent"
            );
            return WriteOutcome::Failure(DataAccessError::ObjectNonExistent);
        }
    };
    match field {
        SgcbField::ActSg => {
            let v = match unsigned_to_u8(data) {
                Some(v) => v,
                None => return WriteOutcome::Failure(DataAccessError::TypeInconsistent),
            };
            match rt.try_select_active_sg(v, conn_id) {
                Ok(()) => WriteOutcome::Success,
                Err(e) => WriteOutcome::Failure(e),
            }
        }
        SgcbField::EditSg => {
            let v = match unsigned_to_u8(data) {
                Some(v) => v,
                None => return WriteOutcome::Failure(DataAccessError::TypeInconsistent),
            };
            match rt.try_edit_sg(v, conn_id) {
                Ok(()) => WriteOutcome::Success,
                Err(e) => WriteOutcome::Failure(e),
            }
        }
        SgcbField::CnfEdit => {
            let b = match data {
                MmsData::Boolean(b) => *b,
                _ => return WriteOutcome::Failure(DataAccessError::TypeInconsistent),
            };
            match rt.try_confirm_edit_sg(b, conn_id) {
                Ok(()) => WriteOutcome::Success,
                Err(e) => WriteOutcome::Failure(e),
            }
        }
        SgcbField::Whole | SgcbField::NumOfSg | SgcbField::LActTm | SgcbField::ResvTms => {
            tracing::warn!(
                ?field,
                "write: this setting group control block field is read-only"
            );
            WriteOutcome::Failure(DataAccessError::ObjectAccessDenied)
        }
    }
}

fn unsigned_to_u8(data: &MmsData) -> Option<u8> {
    match data {
        MmsData::Unsigned(v) if *v <= u8::MAX as u64 => Some(*v as u8),
        MmsData::Integer(v) if *v >= 0 && *v <= u8::MAX as i64 => Some(*v as u8),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

    fn rt_three_sg() -> SettingGroupRuntime {
        SettingGroupRuntime::new(3, 1, false, 60)
    }

    #[test]
    fn select_active_sg_happy_path() {
        let rt = rt_three_sg();
        rt.try_select_active_sg(2, 100).expect("ok");
        assert_eq!(rt.snapshot().act_sg, 2);
    }

    #[test]
    fn select_active_sg_zero_rejected() {
        let rt = rt_three_sg();
        let r = rt.try_select_active_sg(0, 100);
        assert_eq!(r, Err(DataAccessError::ObjectValueInvalid));
    }

    #[test]
    fn select_active_sg_above_num_rejected() {
        let rt = rt_three_sg();
        let r = rt.try_select_active_sg(4, 100);
        assert_eq!(r, Err(DataAccessError::ObjectValueInvalid));
        assert_eq!(
            rt.snapshot().act_sg,
            1,
            "a refused selection must leave the active group alone"
        );
    }

    #[test]
    fn select_active_sg_handler_veto() {
        struct Veto;
        impl SettingGroupHandler for Veto {
            fn act_sg_changed(&self, _: u8, _: ConnectionId) -> bool {
                false
            }
        }
        let rt = rt_three_sg();
        rt.install_handler(Arc::new(Veto));
        let r = rt.try_select_active_sg(2, 100);
        assert_eq!(r, Err(DataAccessError::ObjectAccessDenied));
        assert_eq!(rt.snapshot().act_sg, 1);
    }

    #[test]
    fn edit_sg_happy_path() {
        let rt = rt_three_sg();
        rt.try_edit_sg(2, 100).expect("ok");
        let s = rt.snapshot();
        assert_eq!(s.edit_sg, 2);
    }

    #[test]
    fn edit_sg_zero_cancels_session() {
        let rt = rt_three_sg();
        rt.try_edit_sg(2, 100).expect("start");
        rt.try_edit_sg(0, 100).expect("cancel");
        assert_eq!(rt.snapshot().edit_sg, 0);
    }

    #[test]
    fn edit_sg_multi_client_conflict() {
        let rt = rt_three_sg();
        rt.try_edit_sg(2, 100).expect("client A start");
        let r = rt.try_edit_sg(2, 200);
        assert_eq!(r, Err(DataAccessError::TemporarilyUnavailable));
    }

    #[test]
    fn edit_sg_same_client_can_change_target() {
        let rt = rt_three_sg();
        rt.try_edit_sg(2, 100).expect("first");
        rt.try_edit_sg(3, 100).expect("retarget same client");
        assert_eq!(rt.snapshot().edit_sg, 3);
    }

    #[test]
    fn edit_sg_above_num_rejected() {
        let rt = rt_three_sg();
        let r = rt.try_edit_sg(4, 100);
        assert_eq!(r, Err(DataAccessError::ObjectValueInvalid));
    }

    #[test]
    fn confirm_edit_without_session_denied() {
        let rt = rt_three_sg();
        let r = rt.try_confirm_edit_sg(true, 100);
        assert_eq!(r, Err(DataAccessError::ObjectAccessDenied));
    }

    #[test]
    fn confirm_edit_wrong_client_denied() {
        let rt = rt_three_sg();
        rt.try_edit_sg(2, 100).expect("A start");
        let r = rt.try_confirm_edit_sg(true, 200);
        assert_eq!(r, Err(DataAccessError::ObjectAccessDenied));
    }

    #[test]
    fn confirm_edit_value_must_be_true() {
        let rt = rt_three_sg();
        rt.try_edit_sg(2, 100).expect("start");
        let r = rt.try_confirm_edit_sg(false, 100);
        assert_eq!(r, Err(DataAccessError::ObjectValueInvalid));
    }

    #[test]
    fn confirm_edit_happy_path_clears_session_and_fires_callback() {
        struct Spy {
            count: AtomicUsize,
            last: AtomicU8,
        }
        impl SettingGroupHandler for Spy {
            fn confirm_edit_sg(&self, edit_sg: u8, _: ConnectionId) {
                self.count.fetch_add(1, Ordering::SeqCst);
                self.last.store(edit_sg, Ordering::SeqCst);
            }
        }
        let spy = Arc::new(Spy {
            count: AtomicUsize::new(0),
            last: AtomicU8::new(0),
        });
        let rt = rt_three_sg();
        rt.install_handler(spy.clone());
        rt.try_edit_sg(2, 100).expect("start");
        rt.try_confirm_edit_sg(true, 100).expect("commit");
        assert_eq!(spy.count.load(Ordering::SeqCst), 1);
        assert_eq!(spy.last.load(Ordering::SeqCst), 2);
        let s = rt.snapshot();
        assert_eq!(s.edit_sg, 0, "a commit must clear the edit session");
    }

    #[test]
    fn release_session_on_conn_disconnect() {
        let rt = rt_three_sg();
        rt.try_edit_sg(2, 100).expect("start");
        rt.release_edit_session_for_conn(100);
        assert_eq!(rt.snapshot().edit_sg, 0);
    }

    #[test]
    fn release_session_for_other_conn_noop() {
        let rt = rt_three_sg();
        rt.try_edit_sg(2, 100).expect("start");
        rt.release_edit_session_for_conn(200);
        assert_eq!(
            rt.snapshot().edit_sg,
            2,
            "another association closing must not clear this session"
        );
    }

    // ── Reservation expiry ──────────────────────────────────────────────

    #[test]
    fn is_edit_session_owner_true_for_owner() {
        let rt = rt_three_sg();
        rt.try_edit_sg(2, 100).expect("start");
        assert!(rt.is_edit_session_owner(100));
        assert!(!rt.is_edit_session_owner(200));
    }

    #[test]
    fn is_edit_session_owner_false_when_no_session() {
        let rt = rt_three_sg();
        assert!(!rt.is_edit_session_owner(100));
    }

    #[test]
    fn tick_reservation_does_not_expire_when_not_due() {
        let rt = rt_three_sg(); // 60-second reservation
        rt.try_edit_sg(2, 100).expect("start");
        // One millisecond later the reservation still stands.
        assert_eq!(rt.tick_reservation_at(now_ms() + 1), None);
        assert_eq!(rt.snapshot().edit_sg, 2);
    }

    #[test]
    fn tick_reservation_expires_due_session_and_returns_owner() {
        let rt = rt_three_sg();
        rt.try_edit_sg(2, 100).expect("start");
        // One millisecond past the 60-second reservation.
        let future = now_ms() + 60_001;
        assert_eq!(rt.tick_reservation_at(future), Some(100));
        // The session is gone, so a second pass releases nothing.
        assert_eq!(rt.tick_reservation_at(future), None);
        let s = rt.snapshot();
        assert_eq!(s.edit_sg, 0);
    }

    #[test]
    fn tick_reservation_no_op_without_session() {
        let rt = rt_three_sg();
        assert_eq!(rt.tick_reservation_at(now_ms() + 1_000_000), None);
    }

    #[test]
    fn registry_tick_reservations_collects_expired_entries() {
        let reg = SettingGroupRegistry::new();
        let rt_a = Arc::new(SettingGroupRuntime::new(3, 1, false, 60));
        let rt_b = Arc::new(SettingGroupRuntime::new(3, 1, false, 60));
        rt_a.try_edit_sg(2, 111).expect("A start");
        rt_b.try_edit_sg(2, 222).expect("B start");
        reg.inner.write().unwrap().insert("LDA".into(), rt_a);
        reg.inner.write().unwrap().insert("LDB".into(), rt_b);

        // Past the reservation of both devices.
        let mut released = reg.tick_reservations_at(now_ms() + 60_001);
        released.sort();
        assert_eq!(
            released,
            vec![("LDA".into(), 111), ("LDB".into(), 222)],
            "both sessions must be released at the same deadline"
        );
        // Both sessions are gone, so a second pass releases nothing.
        assert!(reg.tick_reservations_at(now_ms() + 60_002).is_empty());
    }

    #[test]
    fn registry_tick_reservations_skips_unexpired_entries() {
        let reg = SettingGroupRegistry::new();
        let rt = Arc::new(SettingGroupRuntime::new(3, 1, false, 60));
        rt.try_edit_sg(2, 111).expect("start");
        reg.inner.write().unwrap().insert("LDA".into(), rt);
        // One millisecond later the reservation still stands.
        let released = reg.tick_reservations_at(now_ms() + 1);
        assert!(released.is_empty());
    }

    #[test]
    fn force_active_sg_bypasses_handler() {
        struct Veto;
        impl SettingGroupHandler for Veto {
            fn act_sg_changed(&self, _: u8, _: ConnectionId) -> bool {
                false
            }
        }
        let rt = rt_three_sg();
        rt.install_handler(Arc::new(Veto));
        rt.force_active_sg(3).expect("force ok");
        assert_eq!(rt.snapshot().act_sg, 3);
    }

    #[test]
    fn snapshot_has_resv_tms_when_configured() {
        let rt = SettingGroupRuntime::new(2, 1, true, 30);
        assert_eq!(rt.snapshot().resv_tms_s, Some(30));
    }

    #[test]
    fn snapshot_resv_tms_none_when_not_configured() {
        let rt = SettingGroupRuntime::new(2, 1, false, 60);
        assert_eq!(rt.snapshot().resv_tms_s, None);
    }

    #[test]
    fn registry_from_model_picks_up_sgcbs() {
        use iec61850_model::{
            IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder, SettingGroupControlBlock,
        };

        let lln0 = LogicalNodeBuilder::lln0()
            .set_sgcb(SettingGroupControlBlock {
                num_of_sg: 4,
                act_sg: 1,
                has_resv_tms: true,
                default_resv_tms_s: 45,
            })
            .build()
            .unwrap();
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(lln0)
            .build()
            .unwrap();
        let model = IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap();

        let reg = SettingGroupRegistry::from_model(&model);
        assert_eq!(reg.len(), 1);
        let rt = reg.lookup("IED1LD0").expect("entry should exist");
        assert_eq!(rt.num_of_sg, 4);
        assert_eq!(rt.snapshot().resv_tms_s, Some(45));
    }

    #[test]
    fn registry_skips_lns_without_sgcb() {
        use iec61850_model::{IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder};

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

        let reg = SettingGroupRegistry::from_model(&model);
        assert_eq!(reg.len(), 0);
    }

    // ── wire-path helpers ───────────────────────────────────────────────────

    fn dom(item: &str) -> ObjectName {
        ObjectName::DomainSpecific {
            domain_id: "IED1LD0".into(),
            item_id: item.into(),
        }
    }

    fn registry_with_one(num_of_sg: u8, has_resv_tms: bool) -> SettingGroupRegistry {
        let reg = SettingGroupRegistry::new();
        let rt = Arc::new(SettingGroupRuntime::new(num_of_sg, 1, has_resv_tms, 60));
        reg.inner.write().unwrap().insert("IED1LD0".into(), rt);
        reg
    }

    #[test]
    fn extract_target_three_segment_whole_struct() {
        let n = dom("LLN0$SP$SGCB");
        let r = extract_sgcb_target(&n);
        assert_eq!(r, Some(("IED1LD0", "LLN0", SgcbField::Whole)));
    }

    #[test]
    fn extract_target_four_segment_actsg() {
        let n = dom("LLN0$SP$SGCB$ActSG");
        let r = extract_sgcb_target(&n);
        assert_eq!(r, Some(("IED1LD0", "LLN0", SgcbField::ActSg)));
    }

    #[test]
    fn extract_target_unknown_field_returns_none() {
        let n = dom("LLN0$SP$SGCB$BogusField");
        let r = extract_sgcb_target(&n);
        assert_eq!(
            r, None,
            "an unknown field leaves the caller to answer object-non-existent"
        );
    }

    #[test]
    fn extract_target_wrong_fc_skips() {
        // A setting group control block exists only under SP.
        let st = dom("LLN0$ST$SGCB");
        let cf = dom("LLN0$CF$SGCB");
        assert_eq!(extract_sgcb_target(&st), None);
        assert_eq!(extract_sgcb_target(&cf), None);
    }

    #[test]
    fn extract_target_non_domain_specific_returns_none() {
        let n = ObjectName::VmdSpecific("LLN0$SP$SGCB".into());
        let r = extract_sgcb_target(&n);
        assert_eq!(r, None);
    }

    #[test]
    fn read_actsg_returns_unsigned() {
        let reg = registry_with_one(3, false);
        let r = handle_sgcb_read(&reg, "IED1LD0", "LLN0", SgcbField::ActSg);
        assert_eq!(r, AccessResult::Success(MmsData::Unsigned(1)));
    }

    #[test]
    fn read_numofsg_returns_configured_value() {
        let reg = registry_with_one(5, false);
        let r = handle_sgcb_read(&reg, "IED1LD0", "LLN0", SgcbField::NumOfSg);
        assert_eq!(r, AccessResult::Success(MmsData::Unsigned(5)));
    }

    #[test]
    fn read_resvtms_when_not_configured_returns_object_nonexistent() {
        let reg = registry_with_one(3, false);
        let r = handle_sgcb_read(&reg, "IED1LD0", "LLN0", SgcbField::ResvTms);
        assert_eq!(r, AccessResult::Failure(DataAccessError::ObjectNonExistent));
    }

    #[test]
    fn read_resvtms_when_configured_returns_value() {
        let reg = registry_with_one(3, true);
        let r = handle_sgcb_read(&reg, "IED1LD0", "LLN0", SgcbField::ResvTms);
        assert_eq!(r, AccessResult::Success(MmsData::Unsigned(60)));
    }

    #[test]
    fn read_whole_struct_returns_five_or_six_fields() {
        let reg = registry_with_one(3, false);
        match handle_sgcb_read(&reg, "IED1LD0", "LLN0", SgcbField::Whole) {
            AccessResult::Success(MmsData::Structure(v)) => assert_eq!(v.len(), 5),
            other => panic!("expected Structure(5), got {:?}", other),
        }
        let reg2 = registry_with_one(3, true);
        match handle_sgcb_read(&reg2, "IED1LD0", "LLN0", SgcbField::Whole) {
            AccessResult::Success(MmsData::Structure(v)) => assert_eq!(v.len(), 6),
            other => panic!("expected Structure(6), got {:?}", other),
        }
    }

    #[test]
    fn read_unknown_domain_returns_object_nonexistent() {
        let reg = registry_with_one(3, false);
        let r = handle_sgcb_read(&reg, "WRONG", "LLN0", SgcbField::ActSg);
        assert_eq!(r, AccessResult::Failure(DataAccessError::ObjectNonExistent));
    }

    #[test]
    fn write_actsg_unsigned_succeeds() {
        let reg = registry_with_one(3, false);
        let r = handle_sgcb_write(
            &reg,
            "IED1LD0",
            "LLN0",
            SgcbField::ActSg,
            &MmsData::Unsigned(2),
            100,
        );
        assert_eq!(r, WriteOutcome::Success);
        assert_eq!(reg.lookup("IED1LD0").unwrap().snapshot().act_sg, 2);
    }

    #[test]
    fn write_actsg_wrong_type_returns_typeinconsistent() {
        let reg = registry_with_one(3, false);
        let r = handle_sgcb_write(
            &reg,
            "IED1LD0",
            "LLN0",
            SgcbField::ActSg,
            &MmsData::Boolean(true),
            100,
        );
        assert_eq!(r, WriteOutcome::Failure(DataAccessError::TypeInconsistent));
    }

    #[test]
    fn write_editsg_starts_session() {
        let reg = registry_with_one(3, false);
        let r = handle_sgcb_write(
            &reg,
            "IED1LD0",
            "LLN0",
            SgcbField::EditSg,
            &MmsData::Unsigned(2),
            100,
        );
        assert_eq!(r, WriteOutcome::Success);
        assert_eq!(reg.lookup("IED1LD0").unwrap().snapshot().edit_sg, 2);
    }

    #[test]
    fn write_cnfedit_without_session_denied() {
        let reg = registry_with_one(3, false);
        let r = handle_sgcb_write(
            &reg,
            "IED1LD0",
            "LLN0",
            SgcbField::CnfEdit,
            &MmsData::Boolean(true),
            100,
        );
        assert_eq!(
            r,
            WriteOutcome::Failure(DataAccessError::ObjectAccessDenied)
        );
    }

    #[test]
    fn write_cnfedit_full_state_machine() {
        let reg = registry_with_one(3, false);
        // 1. EditSG=2
        let r = handle_sgcb_write(
            &reg,
            "IED1LD0",
            "LLN0",
            SgcbField::EditSg,
            &MmsData::Unsigned(2),
            100,
        );
        assert_eq!(r, WriteOutcome::Success);
        // 2. CnfEdit=true
        let r = handle_sgcb_write(
            &reg,
            "IED1LD0",
            "LLN0",
            SgcbField::CnfEdit,
            &MmsData::Boolean(true),
            100,
        );
        assert_eq!(r, WriteOutcome::Success);
        assert_eq!(reg.lookup("IED1LD0").unwrap().snapshot().edit_sg, 0);
    }

    #[test]
    fn write_readonly_field_denied() {
        let reg = registry_with_one(3, false);
        for f in [SgcbField::NumOfSg, SgcbField::LActTm, SgcbField::Whole] {
            let r = handle_sgcb_write(&reg, "IED1LD0", "LLN0", f, &MmsData::Unsigned(0), 100);
            assert_eq!(
                r,
                WriteOutcome::Failure(DataAccessError::ObjectAccessDenied),
                "{:?} must be read-only",
                f
            );
        }
    }

    #[test]
    fn ms_to_utc_time_first_4_bytes_are_seconds() {
        let bytes = ms_to_utc_time(1_700_000_000_500);
        let secs = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(secs, 1_700_000_000);
        // The eighth octet is the time quality; accuracy 10 encodes as 0x0a.
        assert_eq!(bytes[7], 0x0a);
    }
}
