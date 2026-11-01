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
//! A session also carries a reservation deadline on the monotonic clock, so a
//! step of the wall clock neither shortens nor extends it. Every `EditSG` and
//! `CnfEdit` checks it first, so an expired session counts as no session at
//! all; [`SettingGroupRegistry::tick_reservations`] releases expired sessions in
//! the background as well.
//!
//! A write under functional constraint SE is admitted to the session its
//! association holds and stores its values only while that same session is
//! still open: a session that has ended, expired or been opened again since
//! takes no value from it (IEC 61850-7-2 §16.3.3, §16.3.4).
//!
//! The runtime also holds the values of every setting group (IEC 61850-7-2
//! §16). In the model the FC=SG data attribute of a setting is the active
//! buffer and the FC=SE data attribute of the same name the edit buffer; the
//! runtime keeps, for each such setting of its logical device, one value per
//! group:
//!
//! - initially the `<Val sGroup="n">` of the model, and for a group the model
//!   gives no value, the value of the attribute itself;
//! - SelectActiveSG loads the values of the new group into the FC=SG
//!   attributes (§16.3.2.2.2);
//! - SelectEditSG loads the values of the selected group into the FC=SE
//!   attributes (§16.3.3.1);
//! - ConfirmEditSGValues stores the FC=SE values into the edited group and,
//!   when that group is active, loads them into the FC=SG attributes as well
//!   (§16.2.2.5, §16.3.5.1).
//!
//! A value an application writes to an FC=SG attribute directly lasts until
//! the active group is loaded again; [`SettingGroupRuntime::set_group_value`]
//! changes what a group holds. Inside an `IedServer` the values are written
//! through the server's update path, so a data set member they change triggers
//! reports and log entries as an `update_*` call does.
//!
//! The values to load are taken under the lock of the settings and written
//! once it is released, in the order the changes were made: a load that a
//! later change of the same buffer has overtaken writes nothing, so the
//! attributes always end at the values of the latest change. A storage or a
//! handler reached from such a write may read [`SettingGroupRuntime::group_value`]
//! but must not change a group from within it.

use crate::connection::ConnectionId;
use iec61850_mms::mms::pdu::common::{
    AccessResult, DataAccessError, MmsData, ObjectName, WriteOutcome,
};
use iec61850_model::{DataAttribute, DataObject, DoChild, IedModel, MmsValue, FC};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ─────────────────────────────────────────────────────────────────────────────
// SettingGroupHandler trait
// ─────────────────────────────────────────────────────────────────────────────

/// Application callbacks for the setting group control block.
///
/// Every default implementation allows the operation, which is also the
/// behavior when no handler is installed. The server keeps the values of every
/// group itself, so a handler only decides whether an operation proceeds and
/// may persist the values elsewhere; it does not have to write any data
/// attribute.
pub trait SettingGroupHandler: Send + Sync {
    /// Called before the active setting group changes. Returning `false`
    /// refuses the change with `ObjectAccessDenied`, and the FC=SG values stay
    /// those of the current group.
    fn act_sg_changed(&self, _new_act_sg: u8, _conn_id: ConnectionId) -> bool {
        true
    }

    /// Called before an edit session opens. Returning `false` refuses it with
    /// `ObjectAccessDenied`. A cancellation, that is a group of zero, does not
    /// reach this callback.
    fn edit_sg_changed(&self, _new_edit_sg: u8, _conn_id: ConnectionId) -> bool {
        true
    }

    /// Called once a commit has passed every check, before the server stores
    /// the edited values. The FC=SE data attributes hold the edited values of
    /// group `edit_sg` at this point. Returning `false` refuses the commit with
    /// `ObjectAccessDenied`: the group keeps its values and the edit session
    /// stays open.
    fn confirm_edit_sg(&self, _edit_sg: u8, _conn_id: ConnectionId) -> bool {
        true
    }
}

/// Handler that allows every operation.
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
    /// The settings of the logical device and the values of each group. Held
    /// across every change of the active or edited group and the loads it
    /// causes, so the values loaded always belong to the group the state
    /// names.
    settings: Mutex<Vec<SettingLeaf>>,
    writer: WriterSlot,
    /// Serializes the writes of the loads, outside the settings lock.
    loads: Mutex<()>,
    /// Number of loads of the FC=SG attributes taken so far.
    active_loads: AtomicU64,
    /// Number of loads of the FC=SE attributes taken so far.
    edit_loads: AtomicU64,
}

/// Which buffer a load writes.
#[derive(Debug, Clone, Copy)]
enum Buffer {
    /// The FC=SG attributes, the values of the active group.
    Active,
    /// The FC=SE attributes, the edit buffer.
    Edit,
}

/// The values of one group for one buffer, taken under the settings lock and
/// written once it is released.
struct Load {
    buffer: Buffer,
    /// The position of this load among the loads of its buffer.
    ticket: u64,
    writes: Vec<(DataAttribute, MmsValue)>,
}

/// Writes a setting value into a data attribute of the served model.
pub(crate) type SettingWriter = Arc<dyn Fn(&DataAttribute, MmsValue) + Send + Sync>;

/// The writer a registry and its runtimes share; empty until a server installs
/// its update path, in which case a value is stored directly.
type WriterSlot = Arc<RwLock<Option<SettingWriter>>>;

/// One leaf setting of a logical device: the FC=SG and FC=SE attributes that
/// share its path, and the value each group holds, group `n` at index `n - 1`.
struct SettingLeaf {
    active: Option<DataAttribute>,
    edit: Option<DataAttribute>,
    groups: Vec<MmsValue>,
}

impl SettingLeaf {
    fn holds(&self, da: &DataAttribute) -> bool {
        [&self.active, &self.edit]
            .into_iter()
            .flatten()
            .any(|own| Arc::ptr_eq(&own.value, &da.value))
    }
}

#[derive(Debug, Clone, Copy)]
struct State {
    act_sg: u8,
    edit_sg: u8, // Zero means no edit session is open.
    last_act_tm_ms: u64,
    /// The association holding the edit session, if any.
    editing_conn: Option<ConnectionId>,
    /// When the edit session expires; `None` while no session is open.
    reservation_deadline: Option<Instant>,
    /// Number of the latest edit session; every SelectEditSG that opens a
    /// session, on the same group or another, takes the next one.
    session: u64,
}

/// An edit session as a write found it open: the association holding it and
/// the number of the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EditSession {
    conn_id: ConnectionId,
    number: u64,
}

/// Keeps the edit session it was taken for open, unchanged, until dropped:
/// opening, ending and expiring a session wait for it.
pub(crate) struct EditSessionHold<'a> {
    _state: RwLockReadGuard<'a, State>,
}

impl State {
    /// Whether `session` is the open session and its reservation has not
    /// passed at `now`.
    fn is_current(&self, session: EditSession, now: Instant) -> bool {
        self.edit_sg > 0
            && self.editing_conn == Some(session.conn_id)
            && self.session == session.number
            && self.reservation_deadline.is_none_or(|d| now < d)
    }
}

/// Values a read of the setting group control block reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
    /// Creates the runtime with its configured fields and no settings; a
    /// runtime that [`SettingGroupRegistry::from_model`] creates holds the
    /// settings of its logical device.
    pub fn new(num_of_sg: u8, act_sg: u8, has_resv_tms: bool, default_resv_tms_s: u16) -> Self {
        Self::with_writer(
            num_of_sg,
            act_sg,
            has_resv_tms,
            default_resv_tms_s,
            Arc::default(),
        )
    }

    fn with_writer(
        num_of_sg: u8,
        act_sg: u8,
        has_resv_tms: bool,
        default_resv_tms_s: u16,
        writer: WriterSlot,
    ) -> Self {
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
                reservation_deadline: None,
                session: 0,
            }),
            handler: RwLock::new(Arc::new(DefaultSettingGroupHandler)),
            settings: Mutex::new(Vec::new()),
            writer,
            loads: Mutex::new(()),
            active_loads: AtomicU64::new(0),
            edit_loads: AtomicU64::new(0),
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

    /// Selects the active setting group and loads its values into the FC=SG
    /// attributes.
    ///
    /// Selecting the group that is already active loads its values again.
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
        self.activate(new_act_sg)
    }

    /// Makes `group` the active group and loads its values into the FC=SG
    /// attributes; the caller has checked the range.
    fn activate(&self, group: u8) -> Result<(), DataAccessError> {
        let load = {
            let settings = self.lock_settings()?;
            let mut g = self.state.write().map_err(|_| {
                tracing::error!("setting group state lock is poisoned");
                DataAccessError::HardwareFault
            })?;
            g.act_sg = group;
            g.last_act_tm_ms = now_ms();
            self.prepare_load(&settings, Buffer::Active, group)
        };
        self.run_load(load);
        Ok(())
    }

    /// Opens an edit session on a setting group and loads its values into the
    /// FC=SE attributes; a group of zero cancels the session this association
    /// holds and loads nothing.
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
            let load = {
                let settings = self.lock_settings()?;
                let mut g = self.state.write().map_err(|_| {
                    tracing::error!("setting group state lock is poisoned");
                    DataAccessError::HardwareFault
                })?;
                // Another association may have taken the session while the
                // callback ran; the first to take it keeps it.
                if let Some(owner) = g.editing_conn {
                    if owner != conn_id {
                        tracing::warn!(
                            owner,
                            requester = conn_id,
                            "edit-sg: another association took the edit session"
                        );
                        return Err(DataAccessError::TemporarilyUnavailable);
                    }
                }
                g.edit_sg = new_edit_sg;
                g.editing_conn = Some(conn_id);
                g.session = g.session.wrapping_add(1);
                let lifetime = Duration::from_secs(u64::from(self.default_resv_tms_s));
                g.reservation_deadline = Instant::now().checked_add(lifetime);
                self.prepare_load(&settings, Buffer::Edit, new_edit_sg)
            };
            self.run_load(load);
        } else {
            g.edit_sg = 0;
            g.editing_conn = None;
            g.reservation_deadline = None;
        }
        Ok(())
    }

    /// Commits the open edit session and clears it.
    ///
    /// Once [`SettingGroupHandler::confirm_edit_sg`] allows it, the FC=SE
    /// values become the values of the edited group, and when that group is
    /// the active one at the time of the commit, the FC=SG attributes take them
    /// too.
    ///
    /// # Errors
    ///
    /// Returns `ObjectValueInvalid` when the written value is not `true`, and
    /// `ObjectAccessDenied` when no session is open, when the session has
    /// expired, when it belongs to another association, or when the handler
    /// refuses.
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
        if !handler.confirm_edit_sg(edit_sg, conn_id) {
            tracing::warn!(
                edit_sg,
                conn_id,
                "confirm-edit-sg: the handler refused the commit"
            );
            return Err(DataAccessError::ObjectAccessDenied);
        }

        let mut settings = self.lock_settings()?;
        let act_sg = {
            let mut g = self.state.write().map_err(|_| {
                tracing::error!("setting group state lock is poisoned");
                DataAccessError::HardwareFault
            })?;
            // The session may have ended while the callback ran.
            if g.edit_sg != edit_sg || g.editing_conn != Some(conn_id) {
                tracing::warn!(
                    conn_id,
                    "confirm-edit-sg: the edit session ended before the commit"
                );
                return Err(DataAccessError::ObjectAccessDenied);
            }
            g.edit_sg = 0;
            g.editing_conn = None;
            g.reservation_deadline = None;
            // Read under the settings lock, which a change of the active group
            // also takes, so the group cannot change before the load below.
            g.act_sg
        };
        let index = usize::from(edit_sg) - 1;
        for leaf in settings.iter_mut() {
            let Some(edit) = &leaf.edit else {
                continue;
            };
            let value = edit.snapshot();
            if let Some(slot) = leaf.groups.get_mut(index) {
                *slot = value;
            }
        }
        let load =
            (edit_sg == act_sg).then(|| self.prepare_load(&settings, Buffer::Active, act_sg));
        drop(settings);
        if let Some(load) = load {
            self.run_load(load);
        }
        Ok(())
    }

    /// Reports whether the association owns an open edit session, that is
    /// whether a group is being edited and this association opened it. An
    /// expired session is released first.
    pub fn is_edit_session_owner(&self, conn_id: ConnectionId) -> bool {
        self.edit_session_of(conn_id).is_some()
    }

    /// Returns the open edit session the association holds, or `None` when it
    /// holds none. An expired session is released first.
    ///
    /// The Write service admits a write under functional constraint SE to the
    /// session this returns, and stores its values under
    /// [`hold_edit_session`](Self::hold_edit_session).
    pub(crate) fn edit_session_of(&self, conn_id: ConnectionId) -> Option<EditSession> {
        self.expire_stale_session_if_any();
        let g = self.state.read().ok()?;
        (g.edit_sg > 0 && g.editing_conn == Some(conn_id)).then_some(EditSession {
            conn_id,
            number: g.session,
        })
    }

    /// Keeps `session` open until the returned hold is dropped, or returns
    /// `None` when it has ended, its reservation has passed, or a session has
    /// been opened since, by its association or another.
    ///
    /// The hold takes the state lock for reading, after the value lock of the
    /// served model; nothing that holds the state lock takes the value lock.
    pub(crate) fn hold_edit_session(&self, session: EditSession) -> Option<EditSessionHold<'_>> {
        let g = self.state.read().ok()?;
        g.is_current(session, Instant::now())
            .then_some(EditSessionHold { _state: g })
    }

    /// Whether the session state is locked, as a hold keeps it.
    #[cfg(test)]
    pub(crate) fn session_state_is_locked(&self) -> bool {
        self.state.try_write().is_err()
    }

    /// Releases the edit session if its reservation has expired, returning the
    /// association that held it so the caller can log or notify. `None` means
    /// no session was open or it has not expired.
    pub fn tick_reservation(&self) -> Option<ConnectionId> {
        self.tick_reservation_at(Instant::now())
    }

    /// [`SettingGroupRuntime::tick_reservation`] against a supplied instant of
    /// the monotonic clock, so an application or a test can drive the
    /// reservation with clock readings of its own.
    pub fn tick_reservation_at(&self, now: Instant) -> Option<ConnectionId> {
        let mut g = match self.state.write() {
            Ok(g) => g,
            Err(_) => return None,
        };
        if g.editing_conn.is_some() && g.reservation_deadline.is_some_and(|d| now >= d) {
            let owner = g.editing_conn;
            g.edit_sg = 0;
            g.editing_conn = None;
            g.reservation_deadline = None;
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
            g.reservation_deadline = None;
        }
    }

    /// Changes the active setting group from the server side, bypassing the
    /// handler, and loads its values into the FC=SG attributes; intended for
    /// application start-up.
    ///
    /// # Errors
    ///
    /// Returns `ObjectValueInvalid` for a group outside 1 through the group
    /// count.
    pub fn force_active_sg(&self, new_act_sg: u8) -> Result<(), DataAccessError> {
        if new_act_sg < 1 || new_act_sg > self.num_of_sg {
            return Err(DataAccessError::ObjectValueInvalid);
        }
        self.activate(new_act_sg)
    }

    /// Returns the value setting group `group` holds for the setting `da`,
    /// the FC=SG or the FC=SE data attribute of a leaf setting of this logical
    /// device, as the served model holds it.
    ///
    /// Returns `None` for a group outside 1 through the group count or an
    /// attribute that is not such a setting.
    pub fn group_value(&self, group: u8, da: &DataAttribute) -> Option<MmsValue> {
        let index = usize::from(group).checked_sub(1)?;
        let settings = self.settings.lock().ok()?;
        settings
            .iter()
            .find(|leaf| leaf.holds(da))
            .and_then(|leaf| leaf.groups.get(index).cloned())
    }

    /// Replaces the value setting group `group` holds for the setting `da`, as
    /// an application restoring values it persisted does. When `group` is the
    /// active group, the FC=SG attribute takes the value too.
    ///
    /// # Errors
    ///
    /// Returns `ObjectValueInvalid` for a group outside 1 through the group
    /// count, `ObjectNonExistent` when `da` is not the FC=SG or FC=SE data
    /// attribute of a leaf setting of this logical device, and
    /// `TypeInconsistent` when `value` is not of the type the setting holds.
    pub fn set_group_value(
        &self,
        group: u8,
        da: &DataAttribute,
        value: MmsValue,
    ) -> Result<(), DataAccessError> {
        if group < 1 || group > self.num_of_sg {
            return Err(DataAccessError::ObjectValueInvalid);
        }
        let mut settings = self.lock_settings()?;
        let leaf = settings
            .iter_mut()
            .find(|leaf| leaf.holds(da))
            .ok_or(DataAccessError::ObjectNonExistent)?;
        let slot = leaf
            .groups
            .get_mut(usize::from(group) - 1)
            .ok_or(DataAccessError::ObjectNonExistent)?;
        if core::mem::discriminant(slot) != core::mem::discriminant(&value) {
            return Err(DataAccessError::TypeInconsistent);
        }
        *slot = value;
        let load = (group == self.snapshot().act_sg)
            .then(|| self.prepare_load(&settings, Buffer::Active, group));
        drop(settings);
        if let Some(load) = load {
            self.run_load(load);
        }
        Ok(())
    }

    /// Takes the values of `group` for `buffer`, under the settings lock the
    /// caller holds, as the latest load of that buffer.
    fn prepare_load(&self, settings: &[SettingLeaf], buffer: Buffer, group: u8) -> Load {
        let ticket = self.load_count(buffer).fetch_add(1, Ordering::SeqCst) + 1;
        let index = usize::from(group).saturating_sub(1);
        let writes = settings
            .iter()
            .filter_map(|leaf| {
                let da = match buffer {
                    Buffer::Active => leaf.active.as_ref(),
                    Buffer::Edit => leaf.edit.as_ref(),
                }?;
                Some((handle(da), leaf.groups.get(index)?.clone()))
            })
            .collect();
        Load {
            buffer,
            ticket,
            writes,
        }
    }

    /// Writes a load, with no settings lock held, unless a later load of the
    /// same buffer has been taken, which then writes its own values.
    fn run_load(&self, load: Load) {
        let _order = self.loads.lock().unwrap_or_else(|e| e.into_inner());
        if self.load_count(load.buffer).load(Ordering::SeqCst) != load.ticket {
            return;
        }
        let writer = self.writer();
        for (da, value) in load.writes {
            write_setting(writer.as_ref(), &da, value);
        }
    }

    fn load_count(&self, buffer: Buffer) -> &AtomicU64 {
        match buffer {
            Buffer::Active => &self.active_loads,
            Buffer::Edit => &self.edit_loads,
        }
    }

    fn lock_settings(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Vec<SettingLeaf>>, DataAccessError> {
        self.settings.lock().map_err(|_| {
            tracing::error!("setting group values lock is poisoned");
            DataAccessError::HardwareFault
        })
    }

    fn writer(&self) -> Option<SettingWriter> {
        self.writer.read().ok().and_then(|g| g.clone())
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
        if let Some(owner) = self.tick_reservation_at(Instant::now()) {
            tracing::info!(
                owner,
                "setting group edit session reservation expired, releasing it"
            );
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
    /// Time quality octet of every timestamp the control blocks report.
    time_quality: u8,
    writer: WriterSlot,
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
    /// Returns an empty registry whose timestamps carry the default
    /// [`IedServerConfig::time_quality`](crate::IedServerConfig::time_quality).
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            time_quality: crate::config::DEFAULT_TIME_QUALITY.to_byte(),
            writer: Arc::default(),
        }
    }

    /// Sets the time quality every timestamp of the control blocks reports,
    /// such as `LActTm`.
    #[cfg(feature = "full-server")]
    pub(crate) fn with_time_quality(mut self, quality: crate::TimeQuality) -> Self {
        self.time_quality = quality.to_byte();
        self
    }

    /// Installs the writer every runtime of the registry writes setting
    /// values through.
    #[cfg(feature = "full-server")]
    pub(crate) fn set_writer(&self, writer: SettingWriter) {
        match self.writer.write() {
            Ok(mut g) => *g = Some(writer),
            Err(_) => tracing::warn!(
                "setting group writer lock is poisoned, values are stored without the update path"
            ),
        }
    }

    /// Builds a registry from a model, with one runtime per logical device
    /// whose LLN0 declares a setting group control block.
    ///
    /// Each runtime holds the settings of its logical device with the initial
    /// value of every group, and the FC=SG attributes of `model` are set to the
    /// values of the active group. The FC=SE attributes are left as they are
    /// until an edit session loads them.
    pub fn from_model(model: &IedModel) -> Self {
        let reg = Self::new();
        for ld in &model.lds {
            // A logical device holds at most one control block.
            let Some(sgcb) = ld.lns.iter().find_map(|ln| ln.sgcb.as_ref()) else {
                continue;
            };
            let rt = SettingGroupRuntime::with_writer(
                sgcb.num_of_sg,
                sgcb.act_sg,
                sgcb.has_resv_tms,
                sgcb.default_resv_tms_s,
                Arc::clone(&reg.writer),
            );
            let mut leaves = Vec::new();
            for ln in &ld.lns {
                for dobj in &ln.dos {
                    collect_settings(dobj, sgcb.num_of_sg, &mut leaves);
                }
            }
            let active = usize::from(sgcb.act_sg.max(1)) - 1;
            for leaf in &leaves {
                if let (Some(da), Some(value)) = (&leaf.active, leaf.groups.get(active)) {
                    da.store(value.clone());
                }
            }
            if let Ok(mut g) = rt.settings.lock() {
                *g = leaves;
            }
            if let Ok(mut g) = reg.inner.write() {
                g.insert(ld.domain_name(&model.ied_name), Arc::new(rt));
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
        self.tick_reservations_at(Instant::now())
    }

    /// [`SettingGroupRegistry::tick_reservations`] against a supplied instant of
    /// the monotonic clock, so an application or a test can drive the
    /// reservations with clock readings of its own.
    pub fn tick_reservations_at(&self, now: Instant) -> Vec<(String, ConnectionId)> {
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
// Setting values
// ─────────────────────────────────────────────────────────────────────────────

/// Collects the leaf settings below `dobj`, pairing each FC=SG attribute with
/// the FC=SE attribute of the same name, type and element count.
fn collect_settings(dobj: &DataObject, num_of_sg: u8, out: &mut Vec<SettingLeaf>) {
    let same_shape =
        |a: &DataAttribute, b: &DataAttribute| a.ty == b.ty && a.array_count == b.array_count;
    for child in &dobj.children {
        match child {
            DoChild::SubDo(sub) => collect_settings(sub, num_of_sg, out),
            DoChild::Da(sg) if sg.fc == FC::Sg => {
                let se = dobj
                    .children_with_fc(FC::Se)
                    .find(|se| se.name == sg.name && same_shape(se, sg));
                collect_leaves(Some(sg), se, num_of_sg, out);
            }
            DoChild::Da(se) if se.fc == FC::Se => {
                let paired = dobj
                    .children_with_fc(FC::Sg)
                    .any(|sg| sg.name == se.name && same_shape(sg, se));
                if !paired {
                    collect_leaves(None, Some(se), num_of_sg, out);
                }
            }
            DoChild::Da(_) => {}
        }
    }
}

/// Collects the leaves of one setting attribute, walking the FC=SG and the
/// FC=SE tree side by side: the elements of an array by index, the
/// sub-attributes of a constructed attribute by name.
fn collect_leaves(
    active: Option<&DataAttribute>,
    edit: Option<&DataAttribute>,
    num_of_sg: u8,
    out: &mut Vec<SettingLeaf>,
) {
    let Some(first) = active.or(edit) else {
        return;
    };
    if first.is_array() {
        for index in (0..first.children.len()).filter_map(|i| u32::try_from(i).ok()) {
            let a = active.and_then(|a| a.element(index));
            let e = edit
                .and_then(|e| e.element(index))
                .filter(|e| a.is_none_or(|a| a.ty == e.ty));
            collect_leaves(a, e, num_of_sg, out);
        }
        return;
    }
    if !first.is_leaf() {
        for c in &first.children {
            let a = active.and_then(|a| a.child_by_name(&c.name));
            let e = edit
                .and_then(|e| e.child_by_name(&c.name))
                .filter(|e| a.is_none_or(|a| a.ty == e.ty && a.array_count == e.array_count));
            collect_leaves(a, e, num_of_sg, out);
        }
        return;
    }
    let groups = (1..=num_of_sg)
        .map(|g| {
            active
                .and_then(|a| a.sgroup_value(g))
                .or_else(|| edit.and_then(|e| e.sgroup_value(g)))
                .cloned()
                .unwrap_or_else(|| first.snapshot())
        })
        .collect();
    out.push(SettingLeaf {
        active: active.map(handle),
        edit: edit.map(handle),
        groups,
    });
}

/// A handle on a leaf attribute of the model, sharing its value.
fn handle(da: &DataAttribute) -> DataAttribute {
    DataAttribute::with_shared_value(
        da.name.clone(),
        da.fc,
        da.ty,
        da.trg_ops,
        Arc::clone(&da.value),
    )
}

/// Writes a setting value through the server's update path when one is
/// installed, and stores it directly otherwise.
fn write_setting(writer: Option<&SettingWriter>, da: &DataAttribute, value: MmsValue) {
    match writer {
        Some(w) => w(da, value),
        None => da.store(value),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire path routing
// ─────────────────────────────────────────────────────────────────────────────

/// What part of a setting group control block an object name selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
/// Three segments (`LLN0$SP$SGCB`) select the whole block and four select one
/// field. A setting group control block exists only in LLN0, so the same path
/// under any other logical node is not one. Any other name yields `None` and
/// the caller continues with its other routes.
pub fn extract_sgcb_target(name: &ObjectName) -> Option<(&str, &str, SgcbField)> {
    let (domain, item_id) = match name {
        ObjectName::DomainSpecific { domain_id, item_id } => (domain_id.as_str(), item_id.as_str()),
        _ => return None,
    };
    let parts: Vec<&str> = item_id.split('$').collect();
    if parts.len() < 3 || parts.len() > 4 {
        return None;
    }
    if parts[0] != "LLN0" || parts[1] != "SP" || parts[2] != "SGCB" {
        return None;
    }
    let ln_name = parts[0];
    let field = if parts.len() == 3 {
        SgcbField::Whole
    } else {
        SgcbField::from_leaf_name(parts[3])?
    };
    Some((domain, ln_name, field))
}

/// Encodes milliseconds since the epoch as an IEC 61850 UTC timestamp: four
/// octets of whole seconds, three of fraction, and the time quality octet
/// `quality` (IEC 61850-7-2 §6.2.3.4).
fn ms_to_utc_time(ms: u64, quality: u8) -> [u8; 8] {
    let secs = (ms / 1000) as u32;
    // The fraction is a 24-bit fixed-point value.
    let frac24 = ((ms % 1000) * (1u64 << 24) / 1000) as u32;
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&secs.to_be_bytes());
    out[4] = ((frac24 >> 16) & 0xff) as u8;
    out[5] = ((frac24 >> 8) & 0xff) as u8;
    out[6] = (frac24 & 0xff) as u8;
    out[7] = quality;
    out
}

/// Encodes a snapshot as the structure a whole-block read returns.
///
/// The members follow the order of the type specification: `NumOfSG`, `ActSG`,
/// `EditSG`, `CnfEdit`, `LActTm`, and `ResvTms` where it is exposed.
fn snapshot_to_struct(snap: &SgcbSnapshot, time_quality: u8) -> MmsData {
    let mut fields = vec![
        MmsData::Unsigned(snap.num_of_sg as u64),
        MmsData::Unsigned(snap.act_sg as u64),
        MmsData::Unsigned(snap.edit_sg as u64),
        MmsData::Boolean(snap.cnf_edit),
        MmsData::UtcTime(ms_to_utc_time(snap.last_act_tm_ms, time_quality)),
    ];
    if let Some(resv) = snap.resv_tms_s {
        fields.push(MmsData::Unsigned(resv as u64));
    }
    MmsData::Structure(fields)
}

/// Answers a read of a setting group control block.
///
/// A domain with no control block answers `ObjectNonExistent`. The logical node
/// name is not consulted: [`extract_sgcb_target`] only routes LLN0 here, and a
/// domain holds at most one control block, so the per-domain registry alone
/// decides.
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
        SgcbField::Whole => snapshot_to_struct(&snap, registry.time_quality),
        SgcbField::NumOfSg => MmsData::Unsigned(snap.num_of_sg as u64),
        SgcbField::ActSg => MmsData::Unsigned(snap.act_sg as u64),
        SgcbField::EditSg => MmsData::Unsigned(snap.edit_sg as u64),
        SgcbField::CnfEdit => MmsData::Boolean(snap.cnf_edit),
        SgcbField::LActTm => {
            MmsData::UtcTime(ms_to_utc_time(snap.last_act_tm_ms, registry.time_quality))
        }
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
    use iec61850_model::DataAttributeType;
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
            fn confirm_edit_sg(&self, edit_sg: u8, _: ConnectionId) -> bool {
                self.count.fetch_add(1, Ordering::SeqCst);
                self.last.store(edit_sg, Ordering::SeqCst);
                true
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
        assert_eq!(
            rt.tick_reservation_at(Instant::now() + Duration::from_millis(1)),
            None
        );
        assert_eq!(rt.snapshot().edit_sg, 2);
    }

    #[test]
    fn tick_reservation_expires_due_session_and_returns_owner() {
        let rt = rt_three_sg();
        rt.try_edit_sg(2, 100).expect("start");
        // One millisecond past the 60-second reservation.
        let future = Instant::now() + Duration::from_millis(60_001);
        assert_eq!(rt.tick_reservation_at(future), Some(100));
        // The session is gone, so a second pass releases nothing.
        assert_eq!(rt.tick_reservation_at(future), None);
        let s = rt.snapshot();
        assert_eq!(s.edit_sg, 0);
    }

    /// A hold keeps every change of the session waiting until it is dropped,
    /// and only the session it was found for, unexpired, can be held.
    #[test]
    fn a_hold_keeps_its_session_until_dropped() {
        let rt = rt_three_sg();
        rt.try_edit_sg(2, 100).unwrap();
        let session = rt.edit_session_of(100).expect("conn 100 holds the session");
        assert_eq!(rt.edit_session_of(200), None);

        let hold = rt.hold_edit_session(session).expect("the session is open");
        assert!(
            rt.session_state_is_locked(),
            "opening, ending and expiring a session wait for the hold"
        );
        drop(hold);
        assert!(!rt.session_state_is_locked());

        let past_the_reservation = Instant::now() + Duration::from_millis(60_001);
        assert!(rt.state.read().unwrap().is_current(session, Instant::now()));
        assert!(!rt
            .state
            .read()
            .unwrap()
            .is_current(session, past_the_reservation));

        rt.try_edit_sg(3, 100).unwrap();
        assert!(
            rt.hold_edit_session(session).is_none(),
            "a session opened again by the same association is another one"
        );
        let reopened = rt.edit_session_of(100).expect("conn 100 holds the session");
        assert!(rt.hold_edit_session(reopened).is_some());
        rt.try_edit_sg(0, 100).unwrap();
        assert!(
            rt.hold_edit_session(reopened).is_none(),
            "a cancelled session"
        );
    }

    #[test]
    fn tick_reservation_no_op_without_session() {
        let rt = rt_three_sg();
        assert_eq!(
            rt.tick_reservation_at(Instant::now() + Duration::from_secs(1_000)),
            None
        );
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
        let later = Instant::now() + Duration::from_millis(60_001);
        let mut released = reg.tick_reservations_at(later);
        released.sort();
        assert_eq!(
            released,
            vec![("LDA".into(), 111), ("LDB".into(), 222)],
            "both sessions must be released at the same deadline"
        );
        // Both sessions are gone, so a second pass releases nothing.
        assert!(reg
            .tick_reservations_at(later + Duration::from_millis(1))
            .is_empty());
    }

    #[test]
    fn registry_tick_reservations_skips_unexpired_entries() {
        let reg = SettingGroupRegistry::new();
        let rt = Arc::new(SettingGroupRuntime::new(3, 1, false, 60));
        rt.try_edit_sg(2, 111).expect("start");
        reg.inner.write().unwrap().insert("LDA".into(), rt);
        // One millisecond later the reservation still stands.
        let released = reg.tick_reservations_at(Instant::now() + Duration::from_millis(1));
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
            .set_sgcb({
                let mut sgcb = SettingGroupControlBlock::default();
                sgcb.num_of_sg = 4;
                sgcb.act_sg = 1;
                sgcb.has_resv_tms = true;
                sgcb.default_resv_tms_s = 45;
                sgcb
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
        let bytes = ms_to_utc_time(1_700_000_000_500, 0x8a);
        let secs = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(secs, 1_700_000_000);
        // The eighth octet is the time quality, passed through unchanged.
        assert_eq!(bytes[7], 0x8a);
    }

    #[cfg(feature = "full-server")]
    #[test]
    fn last_act_tm_carries_the_configured_time_quality() {
        let quality =
            crate::TimeQuality::new(false, false, true, crate::TimeAccuracy::bits(7).unwrap());
        let reg = registry_with_one(3, false).with_time_quality(quality);
        let AccessResult::Success(MmsData::UtcTime(t)) =
            handle_sgcb_read(&reg, "IED1LD0", "LLN0", SgcbField::LActTm)
        else {
            panic!("LActTm reads as a UTC time");
        };
        assert_eq!(t[7], quality.to_byte());
        let AccessResult::Success(MmsData::Structure(members)) =
            handle_sgcb_read(&reg, "IED1LD0", "LLN0", SgcbField::Whole)
        else {
            panic!("the whole block reads as a structure");
        };
        assert_eq!(members[4], MmsData::UtcTime(t));
    }

    #[test]
    fn last_act_tm_defaults_to_the_default_time_quality() {
        let reg = registry_with_one(3, false);
        let AccessResult::Success(MmsData::UtcTime(t)) =
            handle_sgcb_read(&reg, "IED1LD0", "LLN0", SgcbField::LActTm)
        else {
            panic!("LActTm reads as a UTC time");
        };
        assert_eq!(t[7], crate::config::DEFAULT_TIME_QUALITY.to_byte());
    }

    #[test]
    fn extract_target_only_routes_lln0() {
        assert_eq!(extract_sgcb_target(&dom("GGIO1$SP$SGCB")), None);
        assert_eq!(extract_sgcb_target(&dom("GGIO1$SP$SGCB$ActSG")), None);
        assert_eq!(extract_sgcb_target(&dom("$SP$SGCB$ActSG")), None);
    }

    // ── Values of the setting groups ────────────────────────────────────────

    /// A setting declared under `fc` with one value per group.
    fn setting(fc: FC, values: [i64; 3]) -> DataAttribute {
        let mut da = DataAttribute::new(
            "setVal",
            fc,
            DataAttributeType::Int32,
            iec61850_model::TrgOps::DCHG,
            MmsValue::Integer(values[0]),
        );
        da.sgroup_values = (1u8..).zip(values.map(MmsValue::Integer)).collect();
        da
    }

    /// LD0 with three setting groups, group 1 active, and `PTOC1.OpDlTmms`
    /// holding 10, 20 and 30 under FC=SE and FC=SG, plus
    /// `PTOC1.StrVal.setMag.f`, an FC=SE-only structured setting with one value
    /// for every group.
    fn settings_model() -> IedModel {
        use iec61850_model::{
            IedModelBuilder, LogicalDeviceBuilder, LogicalNode, LogicalNodeBuilder,
            SettingGroupControlBlock,
        };
        let op_dl = DataObject::new(
            "OpDlTmms",
            vec![
                DoChild::Da(setting(FC::Se, [10, 20, 30])),
                DoChild::Da(setting(FC::Sg, [10, 20, 30])),
            ],
        );
        let f = DataAttribute::new(
            "f",
            FC::Se,
            DataAttributeType::Float32,
            iec61850_model::TrgOps::NONE,
            MmsValue::Float32(1.5),
        );
        let str_val = DataObject::new(
            "StrVal",
            vec![DoChild::Da(DataAttribute::constructed(
                "setMag",
                FC::Se,
                vec![f],
            ))],
        );
        let ptoc = LogicalNode::new(String::new(), "PTOC", "1", vec![op_dl, str_val]);
        let lln0 = LogicalNodeBuilder::lln0()
            .set_sgcb({
                let mut sgcb = SettingGroupControlBlock::default();
                sgcb.num_of_sg = 3;
                sgcb.act_sg = 1;
                sgcb
            })
            .build()
            .unwrap();
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(lln0)
            .add_ln(ptoc)
            .build()
            .unwrap();
        IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap()
    }

    fn setting_da(model: &IedModel, fc: FC) -> &DataAttribute {
        let dobj = model.lds[0]
            .ln_by_name("PTOC1")
            .unwrap()
            .do_by_name("OpDlTmms")
            .unwrap();
        match dobj.child_by_name("setVal", Some(fc)) {
            Some(DoChild::Da(da)) => da,
            other => panic!("setVal under {fc:?}: {other:?}"),
        }
    }

    fn str_val_f(model: &IedModel) -> &DataAttribute {
        let dobj = model.lds[0]
            .ln_by_name("PTOC1")
            .unwrap()
            .do_by_name("StrVal")
            .unwrap();
        match dobj.child_by_name("setMag", Some(FC::Se)) {
            Some(DoChild::Da(da)) => da.child_by_name("f").unwrap(),
            other => panic!("setMag: {other:?}"),
        }
    }

    fn int(da: &DataAttribute) -> i64 {
        match da.snapshot() {
            MmsValue::Integer(v) => v,
            other => panic!("{} holds {other:?}", da.name),
        }
    }

    fn settings_runtime(model: &IedModel) -> Arc<SettingGroupRuntime> {
        SettingGroupRegistry::from_model(model)
            .lookup("IED1LD0")
            .expect("runtime")
    }

    #[test]
    fn the_model_starts_at_the_values_of_the_active_group() {
        let model = settings_model();
        setting_da(&model, FC::Sg).store(MmsValue::Integer(99));
        let rt = settings_runtime(&model);
        assert_eq!(int(setting_da(&model, FC::Sg)), 10);
        assert_eq!(int(setting_da(&model, FC::Se)), 10);
        assert_eq!(
            rt.group_value(3, setting_da(&model, FC::Sg)),
            Some(MmsValue::Integer(30))
        );
        // A setting with no value for a group takes the value it holds.
        assert_eq!(
            rt.group_value(2, str_val_f(&model)),
            Some(MmsValue::Float32(1.5))
        );
    }

    #[test]
    fn selecting_the_active_group_loads_its_values() {
        let model = settings_model();
        let rt = settings_runtime(&model);
        rt.try_select_active_sg(2, 100).expect("select 2");
        assert_eq!(int(setting_da(&model, FC::Sg)), 20);
        assert_eq!(int(setting_da(&model, FC::Se)), 10, "the edit buffer stays");
        rt.force_active_sg(3).expect("force 3");
        assert_eq!(int(setting_da(&model, FC::Sg)), 30);
    }

    #[test]
    fn a_refused_selection_loads_nothing() {
        struct Veto;
        impl SettingGroupHandler for Veto {
            fn act_sg_changed(&self, _: u8, _: ConnectionId) -> bool {
                false
            }
        }
        let model = settings_model();
        let rt = settings_runtime(&model);
        rt.install_handler(Arc::new(Veto));
        assert!(rt.try_select_active_sg(2, 100).is_err());
        assert_eq!(int(setting_da(&model, FC::Sg)), 10);
    }

    #[test]
    fn an_edited_group_keeps_its_values_across_selections() {
        let model = settings_model();
        let rt = settings_runtime(&model);
        rt.try_edit_sg(3, 100).expect("edit 3");
        assert_eq!(int(setting_da(&model, FC::Se)), 30);
        setting_da(&model, FC::Se).store(MmsValue::Integer(777));
        str_val_f(&model).store(MmsValue::Float32(9.5));
        rt.try_confirm_edit_sg(true, 100).expect("commit");
        assert_eq!(int(setting_da(&model, FC::Sg)), 10, "group 3 is not active");
        assert_eq!(
            rt.group_value(3, setting_da(&model, FC::Sg)),
            Some(MmsValue::Integer(777))
        );
        assert_eq!(
            rt.group_value(3, str_val_f(&model)),
            Some(MmsValue::Float32(9.5))
        );

        rt.try_select_active_sg(3, 100).expect("select 3");
        assert_eq!(int(setting_da(&model, FC::Sg)), 777);
        rt.try_select_active_sg(1, 100).expect("select 1");
        assert_eq!(int(setting_da(&model, FC::Sg)), 10);
        rt.try_select_active_sg(3, 100).expect("select 3 again");
        assert_eq!(int(setting_da(&model, FC::Sg)), 777);

        rt.try_edit_sg(1, 100).expect("edit 1");
        assert_eq!(int(setting_da(&model, FC::Se)), 10);
        assert_eq!(str_val_f(&model).snapshot(), MmsValue::Float32(1.5));
    }

    #[test]
    fn committing_the_active_group_loads_the_edited_values() {
        let model = settings_model();
        let rt = settings_runtime(&model);
        rt.try_edit_sg(1, 100).expect("edit 1");
        setting_da(&model, FC::Se).store(MmsValue::Integer(11));
        assert_eq!(int(setting_da(&model, FC::Sg)), 10, "not before the commit");
        rt.try_confirm_edit_sg(true, 100).expect("commit");
        assert_eq!(int(setting_da(&model, FC::Sg)), 11);
    }

    #[test]
    fn a_cancelled_edit_changes_no_group() {
        let model = settings_model();
        let rt = settings_runtime(&model);
        rt.try_edit_sg(2, 100).expect("edit 2");
        setting_da(&model, FC::Se).store(MmsValue::Integer(22));
        rt.try_edit_sg(0, 100).expect("cancel");
        assert_eq!(
            rt.group_value(2, setting_da(&model, FC::Se)),
            Some(MmsValue::Integer(20))
        );
    }

    #[test]
    fn a_commit_the_handler_refuses_keeps_the_group_and_the_session() {
        struct Refuse;
        impl SettingGroupHandler for Refuse {
            fn confirm_edit_sg(&self, _: u8, _: ConnectionId) -> bool {
                false
            }
        }
        let model = settings_model();
        let rt = settings_runtime(&model);
        rt.install_handler(Arc::new(Refuse));
        rt.try_edit_sg(1, 100).expect("edit 1");
        setting_da(&model, FC::Se).store(MmsValue::Integer(11));
        assert_eq!(
            rt.try_confirm_edit_sg(true, 100),
            Err(DataAccessError::ObjectAccessDenied)
        );
        assert_eq!(rt.snapshot().edit_sg, 1, "the session stays open");
        assert_eq!(int(setting_da(&model, FC::Sg)), 10);
        assert_eq!(
            rt.group_value(1, setting_da(&model, FC::Sg)),
            Some(MmsValue::Integer(10))
        );
    }

    #[test]
    fn a_commit_loads_only_into_the_group_active_when_it_completes() {
        /// Selects group 2 while the commit of group 1 is under way, as
        /// another association can.
        struct SwitchDuringCommit(std::sync::OnceLock<Arc<SettingGroupRuntime>>);
        impl SettingGroupHandler for SwitchDuringCommit {
            fn confirm_edit_sg(&self, _: u8, _: ConnectionId) -> bool {
                self.0.get().unwrap().force_active_sg(2).unwrap();
                true
            }
        }
        let model = settings_model();
        let rt = settings_runtime(&model);
        let handler = Arc::new(SwitchDuringCommit(std::sync::OnceLock::new()));
        assert!(handler.0.set(Arc::clone(&rt)).is_ok());
        rt.install_handler(handler);
        rt.try_edit_sg(1, 100).expect("edit 1");
        setting_da(&model, FC::Se).store(MmsValue::Integer(11));
        rt.try_confirm_edit_sg(true, 100).expect("commit");
        assert_eq!(int(setting_da(&model, FC::Sg)), 20, "group 2 is active");
        assert_eq!(
            rt.group_value(1, setting_da(&model, FC::Sg)),
            Some(MmsValue::Integer(11))
        );
    }

    #[test]
    fn a_group_value_set_by_the_application_is_kept() {
        let model = settings_model();
        let rt = settings_runtime(&model);
        let sg = setting_da(&model, FC::Sg);
        rt.set_group_value(2, sg, MmsValue::Integer(25))
            .expect("group 2");
        assert_eq!(int(sg), 10, "group 2 is not active");
        rt.set_group_value(1, setting_da(&model, FC::Se), MmsValue::Integer(15))
            .expect("group 1 through the edit attribute");
        assert_eq!(int(sg), 15, "group 1 is active");
        rt.try_select_active_sg(2, 100).expect("select 2");
        assert_eq!(int(sg), 25);

        assert_eq!(
            rt.set_group_value(2, sg, MmsValue::Boolean(true)),
            Err(DataAccessError::TypeInconsistent)
        );
        assert_eq!(
            rt.set_group_value(4, sg, MmsValue::Integer(1)),
            Err(DataAccessError::ObjectValueInvalid)
        );
        let stranger = DataAttribute::new(
            "setVal",
            FC::Sg,
            DataAttributeType::Int32,
            iec61850_model::TrgOps::NONE,
            MmsValue::Integer(0),
        );
        assert_eq!(
            rt.set_group_value(1, &stranger, MmsValue::Integer(1)),
            Err(DataAccessError::ObjectNonExistent)
        );
        assert_eq!(rt.group_value(1, &stranger), None);
    }

    #[cfg(feature = "full-server")]
    #[test]
    fn values_are_written_through_the_installed_writer() {
        let model = settings_model();
        let reg = SettingGroupRegistry::from_model(&model);
        let written: Arc<std::sync::Mutex<Vec<(FC, MmsValue)>>> = Arc::default();
        let log = Arc::clone(&written);
        reg.set_writer(Arc::new(move |da: &DataAttribute, v: MmsValue| {
            log.lock().unwrap().push((da.fc, v));
        }));
        let rt = reg.lookup("IED1LD0").unwrap();
        rt.try_select_active_sg(2, 100).expect("select 2");
        assert_eq!(
            *written.lock().unwrap(),
            vec![(FC::Sg, MmsValue::Integer(20))]
        );
        assert_eq!(int(setting_da(&model, FC::Sg)), 10, "the writer decides");
    }

    #[test]
    fn a_session_taken_while_the_handler_runs_stays_with_its_owner() {
        /// Lets association 200 take the session while the request of
        /// association 100 is in the handler.
        struct TakenMeanwhile(std::sync::OnceLock<Arc<SettingGroupRuntime>>);
        impl SettingGroupHandler for TakenMeanwhile {
            fn edit_sg_changed(&self, _: u8, conn_id: ConnectionId) -> bool {
                if conn_id == 100 {
                    self.0.get().unwrap().try_edit_sg(2, 200).unwrap();
                }
                true
            }
        }
        let model = settings_model();
        let rt = settings_runtime(&model);
        let handler = Arc::new(TakenMeanwhile(std::sync::OnceLock::new()));
        assert!(handler.0.set(Arc::clone(&rt)).is_ok());
        rt.install_handler(handler);
        assert_eq!(
            rt.try_edit_sg(3, 100),
            Err(DataAccessError::TemporarilyUnavailable)
        );
        assert!(rt.is_edit_session_owner(200));
        assert_eq!(rt.snapshot().edit_sg, 2);
        assert_eq!(
            int(setting_da(&model, FC::Se)),
            20,
            "group 3 was not loaded"
        );
    }

    #[test]
    fn a_load_overtaken_by_a_later_one_writes_nothing() {
        let model = settings_model();
        let rt = settings_runtime(&model);
        let (first, second) = {
            let settings = rt.settings.lock().unwrap();
            (
                rt.prepare_load(&settings, Buffer::Active, 2),
                rt.prepare_load(&settings, Buffer::Active, 3),
            )
        };
        rt.run_load(second);
        rt.run_load(first);
        assert_eq!(int(setting_da(&model, FC::Sg)), 30);
    }

    #[cfg(feature = "full-server")]
    #[test]
    fn the_writer_runs_without_the_settings_lock() {
        let model = settings_model();
        let reg = SettingGroupRegistry::from_model(&model);
        let rt = reg.lookup("IED1LD0").unwrap();
        let seen: Arc<std::sync::Mutex<Vec<Option<MmsValue>>>> = Arc::default();
        let (log, reader) = (Arc::clone(&seen), Arc::clone(&rt));
        reg.set_writer(Arc::new(move |da: &DataAttribute, v: MmsValue| {
            // Reading a group takes the settings lock, which a writer called
            // under it would never get.
            log.lock().unwrap().push(reader.group_value(1, da));
            da.store(v);
        }));
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = Arc::clone(&rt);
        std::thread::spawn(move || {
            let _ = tx.send(worker.try_select_active_sg(2, 100));
        });
        let outcome = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the selection completes");
        assert_eq!(outcome, Ok(()));
        assert_eq!(*seen.lock().unwrap(), vec![Some(MmsValue::Integer(10))]);
        assert_eq!(int(setting_da(&model, FC::Sg)), 20);
    }
}
