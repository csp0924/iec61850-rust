//! `ControlObject`: the per-data-object control state.
//!
//! One instance per controllable data object, holding the state machine of
//! IEC 61850-7-2 control, the selection timer, and the selection change handler.
//!
//! The control model of an object is defined by the configuration attributes
//! `ctlModel`, `sboTimeout`, `sboClass` and `operTimeout` of its data object,
//! IEC 61850-7-2 §20.1. An object bound to the model reads them from it, so a
//! change of one takes effect at the next request; a selection or a command
//! already under way completes under the settings it started with.
//!
//! The mutable state sits behind a `Mutex`, so several tasks may drive the same
//! object. A selection expires on a timer task of the current tokio runtime,
//! whose clock a test can pause; without a runtime it expires when the next
//! request finds its timeout elapsed. Every change of the selection of a
//! select-before-operate object is reported to the registry the object is
//! registered with, which inside an `IedServer` keeps `stSeld`, and then to the
//! selection change handler.

use super::handler::{SelectStateChangedHandler, SelectStateChangedReason};
use super::model::{
    ControlAction, ControlAddCause, ControlModel, OperParams, OriginValue, SboClass,
};
use super::state::ControlState;
use crate::error::ServerError;
use iec61850_model::{DoChild, IedModel, MmsValue, FC};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;
use tokio::time::Instant;

// ─────────────────────────────────────────────────────────────────────────────
// ControlObjectConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration of one control object: the data object it controls, and the
/// settings used where the model declares no configuration attribute.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ControlObjectConfig {
    /// Data object name.
    pub name: String,
    /// Logical node name.
    pub ln_name: String,
    /// Logical device domain, the IED name and LD instance, for example `IED1LD0`.
    pub domain: String,
    /// Control model, used when the model declares no `ctlModel` attribute.
    pub ctl_model: ControlModel,
    /// Select timeout in milliseconds, 0 disabling it; used when the model
    /// declares no `sboTimeout` attribute.
    pub sbo_timeout_ms: u32,
    /// Select class, whether one selection admits a single Operate or several;
    /// used when the model declares no `sboClass` attribute.
    pub sbo_class: SboClass,
    /// Time limit of an executing command in milliseconds, 0 for none; used
    /// when the model declares no `operTimeout` attribute.
    pub oper_timeout_ms: u32,
}

impl ControlObjectConfig {
    /// Creates the configuration of the control object `name` under the
    /// logical node `ln_name` of the logical device `domain`, using the
    /// control model `ctl_model`.
    ///
    /// `sbo_timeout_ms` is 30000, `sbo_class` is [`SboClass::OperateOnce`], and
    /// `oper_timeout_ms` is 0, leaving a command unlimited.
    pub fn new(
        name: impl Into<String>,
        ln_name: impl Into<String>,
        domain: impl Into<String>,
        ctl_model: ControlModel,
    ) -> Self {
        Self {
            name: name.into(),
            ln_name: ln_name.into(),
            domain: domain.into(),
            ctl_model,
            sbo_timeout_ms: 30_000,
            sbo_class: SboClass::OperateOnce,
            oper_timeout_ms: 0,
        }
    }

    /// Validates a raw `ctlModel` value.
    ///
    /// A value outside 0..=4 is refused rather than silently coerced, so a
    /// misconfigured model fails at startup instead of behaving unexpectedly at
    /// runtime.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::InvalidCtlModel` when the value is out of range.
    pub fn validate_ctl_model(val: i32) -> Result<ControlModel, ServerError> {
        match val {
            0 => Ok(ControlModel::StatusOnly),
            1 => Ok(ControlModel::DirectNormal),
            2 => Ok(ControlModel::SboNormal),
            3 => Ok(ControlModel::DirectEnhanced),
            4 => Ok(ControlModel::SboEnhanced),
            _ => {
                tracing::warn!(
                    ctl_model = val,
                    "ctlModel out of range, valid values are 0 to 4"
                );
                Err(ServerError::InvalidCtlModel { value: val })
            }
        }
    }

    fn settings(&self) -> ControlSettings {
        ControlSettings {
            ctl_model: self.ctl_model,
            sbo_timeout_ms: self.sbo_timeout_ms,
            sbo_class: self.sbo_class,
            oper_timeout_ms: self.oper_timeout_ms,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ControlSettings and the configuration attributes of the model
// ─────────────────────────────────────────────────────────────────────────────

/// The settings that define the control model of an object, per
/// IEC 61850-7-2 §20.1 and the configuration attributes of IEC 61850-7-3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ControlSettings {
    /// Control model, `ctlModel`.
    pub ctl_model: ControlModel,
    /// Select timeout in milliseconds, `sboTimeout`; 0 disables it.
    pub sbo_timeout_ms: u32,
    /// Select class, `sboClass`.
    pub sbo_class: SboClass,
    /// Time limit of an executing command in milliseconds, `operTimeout`; 0
    /// for none.
    pub oper_timeout_ms: u32,
}

impl ControlSettings {
    fn is_sbo(&self) -> bool {
        matches!(
            self.ctl_model,
            ControlModel::SboNormal | ControlModel::SboEnhanced
        )
    }
}

type ValueCell = Arc<RwLock<MmsValue>>;

/// The configuration attributes of the data object, as value cells of the
/// model; an attribute the model does not declare is `None`.
#[derive(Default)]
struct CfBinding {
    ctl_model: Option<ValueCell>,
    sbo_timeout: Option<ValueCell>,
    sbo_class: Option<ValueCell>,
    oper_timeout: Option<ValueCell>,
}

impl CfBinding {
    /// Binds the configuration attributes of `<domain>/<ln_name>.<do_name>`.
    fn from_model(model: &IedModel, domain: &str, ln_name: &str, do_name: &str) -> Self {
        let mut binding = Self::default();
        let Some(data_object) = model
            .ld_by_domain(domain)
            .and_then(|ld| ld.ln_by_name(ln_name))
            .and_then(|ln| ln.do_by_name(do_name))
        else {
            return binding;
        };
        for child in &data_object.children {
            let DoChild::Da(da) = child else { continue };
            if da.fc != FC::Cf {
                continue;
            }
            let slot = match da.name.as_str() {
                "ctlModel" => &mut binding.ctl_model,
                "sboTimeout" => &mut binding.sbo_timeout,
                "sboClass" => &mut binding.sbo_class,
                "operTimeout" => &mut binding.oper_timeout,
                _ => continue,
            };
            *slot = Some(Arc::clone(&da.value));
        }
        binding
    }

    /// Returns the settings the bound attributes hold, taking `fallback` for
    /// an attribute that is absent or holds a value out of its range.
    fn read(&self, name: &str, fallback: ControlSettings) -> ControlSettings {
        let ctl_model = read_cell(&self.ctl_model, name, "ctlModel", |v| {
            integer(v)
                .and_then(|n| i32::try_from(n).ok())
                .and_then(|n| ControlObjectConfig::validate_ctl_model(n).ok())
        });
        let sbo_class = read_cell(&self.sbo_class, name, "sboClass", |v| match integer(v) {
            Some(0) => Some(SboClass::OperateOnce),
            Some(1) => Some(SboClass::OperateMany),
            _ => None,
        });
        let millis = |v: &MmsValue| integer(v).and_then(|n| u32::try_from(n).ok());
        ControlSettings {
            ctl_model: ctl_model.unwrap_or(fallback.ctl_model),
            sbo_timeout_ms: read_cell(&self.sbo_timeout, name, "sboTimeout", millis)
                .unwrap_or(fallback.sbo_timeout_ms),
            sbo_class: sbo_class.unwrap_or(fallback.sbo_class),
            oper_timeout_ms: read_cell(&self.oper_timeout, name, "operTimeout", millis)
                .unwrap_or(fallback.oper_timeout_ms),
        }
    }
}

/// Reads one bound attribute through `parse`; a value it rejects is logged and
/// yields `None`.
fn read_cell<T>(
    cell: &Option<ValueCell>,
    name: &str,
    attribute: &str,
    parse: impl FnOnce(&MmsValue) -> Option<T>,
) -> Option<T> {
    let guard = cell.as_ref()?.read().ok()?;
    let parsed = parse(&guard);
    if parsed.is_none() {
        tracing::warn!(
            name,
            attribute,
            value = ?*guard,
            "control setting out of range in the model, using the configured value"
        );
    }
    parsed
}

fn integer(v: &MmsValue) -> Option<i64> {
    match v {
        MmsValue::Integer(n) => Some(*n),
        MmsValue::Unsigned(n) => i64::try_from(*n).ok(),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ControlObjectInner: the state behind the mutex
// ─────────────────────────────────────────────────────────────────────────────

struct ControlObjectInner {
    state: ControlState,

    /// Parameters of the most recent Oper or SBOw, kept to compare an Operate
    /// against the select that preceded it.
    last_oper_params: Option<OperParams>,

    /// Connection holding the selection, or 0 when none does.
    owner_conn_id: u64,

    /// The settings in force while the object is not unselected, taken when it
    /// left the unselected state.
    active: Option<ControlSettings>,

    /// When the object last entered the ready state, for the select timeout.
    select_time: Option<Instant>,

    /// Counts the entries into the ready state; a select timer deselects only
    /// the period it was armed for.
    ready_period: u64,

    /// Whether the connection holding the selection closed while a command
    /// executed, which ends the selection once the command finishes.
    owner_lost: bool,

    /// The timer task of the current ready period, aborted when the period
    /// ends, so at most one timer per object is alive.
    timer: Option<tokio::task::AbortHandle>,
}

impl ControlObjectInner {
    fn new() -> Self {
        Self {
            state: ControlState::default(),
            last_oper_params: None,
            owner_conn_id: 0,
            active: None,
            select_time: None,
            ready_period: 0,
            owner_lost: false,
            timer: None,
        }
    }

    /// Aborts the timer of the ready period that is ending.
    fn stop_timer(&mut self) {
        if let Some(timer) = self.timer.take() {
            timer.abort();
        }
    }

    /// Enters the ready state for `conn_id` under `settings` and returns the
    /// new ready period.
    fn enter_ready(&mut self, conn_id: u64, settings: ControlSettings) -> u64 {
        self.stop_timer();
        self.state = ControlState::Ready;
        self.owner_conn_id = conn_id;
        self.active = Some(settings);
        self.select_time = Some(Instant::now());
        self.ready_period = self.ready_period.wrapping_add(1);
        self.ready_period
    }

    /// Returns to the unselected state and returns the connection that held the
    /// object.
    fn clear(&mut self) -> u64 {
        self.stop_timer();
        let owner = self.owner_conn_id;
        self.state = ControlState::Unselected;
        self.owner_conn_id = 0;
        self.active = None;
        self.select_time = None;
        self.last_oper_params = None;
        self.owner_lost = false;
        owner
    }
}

/// A change of the selection to report once the state lock is released.
struct SelectionChange {
    conn_id: u64,
    is_selected: bool,
    reason: SelectStateChangedReason,
    t: [u8; 8],
    origin: OriginValue,
    ctl_num: u8,
}

impl SelectionChange {
    fn ended(conn_id: u64, reason: SelectStateChangedReason) -> Self {
        Self {
            conn_id,
            is_selected: false,
            reason,
            t: [0u8; 8],
            origin: OriginValue::default(),
            ctl_num: 0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ControlObject: the public handle
// ─────────────────────────────────────────────────────────────────────────────

/// Control state of one controllable data object.
///
/// Implements the control object of IEC 61850-7-2 with a mutex around the mutable
/// state rather than a semaphore. Its settings come from the configuration
/// attributes of the data object once it is bound to the model, which
/// [`ControlObject::from_model`] does at creation and the server does when the
/// object first serves a request; a setting the model does not declare comes
/// from [`config`](Self::config).
#[derive(Clone)]
pub struct ControlObject {
    /// Configuration, shared by every clone of this handle.
    pub config: Arc<ControlObjectConfig>,
    inner: Arc<Mutex<ControlObjectInner>>,
    binding: Arc<OnceLock<CfBinding>>,

    /// Selection change handler, installed by `set_select_state_handler`.
    pub select_state_handler: Arc<Mutex<Option<Arc<dyn SelectStateChangedHandler>>>>,

    /// The observer of the registry the object is registered with, told of
    /// every change of the selection before the handler.
    observer: Arc<Mutex<Option<ObserverSlot>>>,
}

/// Told that the selection of a control object changed, with whether it is
/// now selected.
pub(crate) type SelectionObserver = Arc<dyn Fn(&ControlObjectConfig, bool) + Send + Sync>;

/// The observer a registry shares with the objects registered with it; empty
/// until one is installed.
pub(crate) type ObserverSlot = Arc<RwLock<Option<SelectionObserver>>>;

impl std::fmt::Debug for ControlObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlObject")
            .field("name", &self.config.name)
            .field("ln_name", &self.config.ln_name)
            .field("domain", &self.config.domain)
            .finish()
    }
}

impl ControlObject {
    /// Creates a control object in the unselected state, not yet bound to a
    /// model.
    pub fn new(config: ControlObjectConfig) -> Self {
        Self {
            config: Arc::new(config),
            inner: Arc::new(Mutex::new(ControlObjectInner::new())),
            binding: Arc::new(OnceLock::new()),
            select_state_handler: Arc::new(Mutex::new(None)),
            observer: Arc::new(Mutex::new(None)),
        }
    }

    /// Creates the control object of the data object `<domain>/<ln_name>.<do_name>`
    /// of `model`, bound to its configuration attributes.
    ///
    /// Returns `None` when the model does not declare the data object or its
    /// `ctlModel` attribute, or `ctlModel` holds a value outside 0..=4. A
    /// setting whose attribute the model does not declare takes the default of
    /// [`ControlObjectConfig::new`].
    pub fn from_model(
        model: &IedModel,
        domain: &str,
        ln_name: &str,
        do_name: &str,
    ) -> Option<Self> {
        let binding = CfBinding::from_model(model, domain, ln_name, do_name);
        let cell = binding.ctl_model.as_ref()?;
        let ctl_model = cell
            .read()
            .ok()
            .and_then(|v| integer(&v))
            .and_then(|n| i32::try_from(n).ok())
            .and_then(|n| ControlObjectConfig::validate_ctl_model(n).ok())?;
        let mut config = ControlObjectConfig::new(do_name, ln_name, domain, ctl_model);
        let settings = binding.read(do_name, config.settings());
        config.sbo_timeout_ms = settings.sbo_timeout_ms;
        config.sbo_class = settings.sbo_class;
        config.oper_timeout_ms = settings.oper_timeout_ms;
        let obj = Self::new(config);
        let _ = obj.binding.set(binding);
        Some(obj)
    }

    /// Binds the object to the configuration attributes `model` declares for
    /// its data object, unless it is bound already.
    pub(crate) fn bind_model(&self, model: &IedModel) {
        self.binding.get_or_init(|| {
            CfBinding::from_model(
                model,
                &self.config.domain,
                &self.config.ln_name,
                &self.config.name,
            )
        });
    }

    /// Returns the settings the configuration attributes currently hold.
    fn live_settings(&self) -> ControlSettings {
        let fallback = self.config.settings();
        match self.binding.get() {
            Some(binding) => binding.read(&self.config.name, fallback),
            None => fallback,
        }
    }

    /// Returns the settings in force: those a selection or command under way
    /// started with, or else those the configuration attributes hold.
    pub fn settings(&self) -> ControlSettings {
        match self.inner.lock() {
            Ok(g) => self.settings_locked(&g),
            Err(_) => self.live_settings(),
        }
    }

    fn settings_locked(&self, g: &ControlObjectInner) -> ControlSettings {
        match g.active {
            Some(active) if g.state != ControlState::Unselected => active,
            _ => self.live_settings(),
        }
    }

    /// Returns the current state.
    pub fn state(&self) -> ControlState {
        self.inner
            .lock()
            .map(|g| g.state)
            .unwrap_or(ControlState::Unselected)
    }

    /// Installs the select state changed handler.
    pub fn set_select_state_handler(&self, h: Arc<dyn SelectStateChangedHandler>) {
        if let Ok(mut g) = self.select_state_handler.lock() {
            *g = Some(h);
        }
    }

    /// Reports every later change of the selection to the observer `slot`
    /// holds, replacing the slot of a registry the object was registered with
    /// before.
    pub(crate) fn watch_selection(&self, slot: ObserverSlot) {
        if let Ok(mut g) = self.observer.lock() {
            *g = Some(slot);
        }
    }

    // ─── Select and deselect ─────────────────────────────────────────────

    /// Selects the object for a connection, moving it from unselected to ready.
    ///
    /// Returns `Ok(true)` when the object is now selected, `Ok(false)` when the
    /// request was refused because the object is already selected, by this or
    /// another connection, or the state does not allow a select. A successful
    /// select starts the select timeout and reports `Selected`.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::Protocol` when the state mutex is poisoned.
    pub fn try_select(&self, conn_id: u64) -> Result<bool, ServerError> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| ServerError::Protocol("ControlObject Mutex poisoned on select".into()))?;

        match g.state {
            ControlState::Unselected => {
                let settings = self.live_settings();
                let period = g.enter_ready(conn_id, settings);
                drop(g);
                tracing::debug!(
                    name = %self.config.name,
                    conn_id,
                    "select accepted, object is now ready"
                );
                // Reported before the timer exists, so a Timeout cannot precede it.
                self.notify(SelectionChange {
                    conn_id,
                    is_selected: true,
                    reason: SelectStateChangedReason::Selected,
                    t: [0u8; 8],
                    origin: OriginValue::default(),
                    ctl_num: 0,
                });
                self.arm_select_timer(period, settings.sbo_timeout_ms);
                Ok(true)
            }
            ControlState::Ready => {
                // Already selected, whichever connection asks; IEC 61850-7-2
                // Table 47.
                tracing::warn!(
                    name = %self.config.name,
                    owner = g.owner_conn_id,
                    requester = conn_id,
                    "select refused: the object is already selected"
                );
                Ok(false)
            }
            other => {
                tracing::warn!(
                    name = %self.config.name,
                    ?other,
                    "select refused: the current state does not allow it"
                );
                Ok(false)
            }
        }
    }

    /// Deselects a selected object, on Cancel, timeout, or a lost connection,
    /// and reports `reason`.
    ///
    /// The deselection happens only when the object is selected and `conn_id`
    /// holds the selection, or `unconditional` is set. An object executing a
    /// command is not deselected. Returns whether the object was deselected.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::Protocol` when the state mutex is poisoned.
    pub fn try_unselect(
        &self,
        conn_id: u64,
        reason: SelectStateChangedReason,
        unconditional: bool,
    ) -> Result<bool, ServerError> {
        let mut g = self.inner.lock().map_err(|_| {
            ServerError::Protocol("ControlObject Mutex poisoned on unselect".into())
        })?;

        if g.state != ControlState::Ready {
            return Ok(false);
        }
        if !unconditional && g.owner_conn_id != conn_id {
            tracing::warn!(
                name = %self.config.name,
                owner = g.owner_conn_id,
                requester = conn_id,
                "deselect refused: the selection is held by another connection"
            );
            return Ok(false);
        }

        let owner = g.clear();
        drop(g);
        tracing::debug!(name = %self.config.name, ?reason, "SBO unselected");
        self.notify(SelectionChange::ended(owner, reason));
        Ok(true)
    }

    /// Deselects the object when its select timeout has elapsed.
    ///
    /// A timer task does this on its own; a request calls it first so that a
    /// selection made without a tokio runtime also expires. Returns whether the
    /// timeout fired. A select timeout of 0 never fires.
    pub fn check_sbo_timeout(&self) -> bool {
        let period = match self.inner.lock() {
            Ok(g) => match (g.state, g.select_time, g.active) {
                (ControlState::Ready, Some(t), Some(active))
                    if active.sbo_timeout_ms != 0
                        && t.elapsed()
                            >= Duration::from_millis(u64::from(active.sbo_timeout_ms)) =>
                {
                    g.ready_period
                }
                _ => return false,
            },
            Err(_) => return false,
        };
        self.expire_selection(period)
    }

    /// Starts the timer that ends the ready period `period` after `timeout_ms`,
    /// when it is not 0, a tokio runtime is available, and the period has not
    /// ended already. The timer is aborted when the period ends otherwise.
    fn arm_select_timer(&self, period: u64, timeout_ms: u32) {
        if timeout_ms == 0 {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let Ok(mut g) = self.inner.lock() else {
            return;
        };
        if g.state != ControlState::Ready || g.ready_period != period {
            return;
        }
        let obj = self.clone();
        let task = runtime.spawn(async move {
            tokio::time::sleep(Duration::from_millis(u64::from(timeout_ms))).await;
            // The deselect reaches the selection change handlers.
            let _ = crate::blocking::off_the_runtime(move || obj.expire_selection(period)).await;
        });
        g.stop_timer();
        g.timer = Some(task.abort_handle());
    }

    /// Deselects the object when it is still in the ready period `period`, the
    /// end of its select timeout, and reports `Timeout`.
    fn expire_selection(&self, period: u64) -> bool {
        let owner = {
            let mut g = match self.inner.lock() {
                Ok(g) => g,
                Err(_) => return false,
            };
            if g.state != ControlState::Ready || g.ready_period != period {
                return false;
            }
            g.clear()
        };
        tracing::warn!(name = %self.config.name, "select timeout elapsed, deselecting");
        self.notify(SelectionChange::ended(
            owner,
            SelectStateChangedReason::Timeout,
        ));
        true
    }

    // ─── Operate ─────────────────────────────────────────────────────────

    /// Admits an Operate request and moves the object into the executing states.
    ///
    /// Returns `Ok(Some(Accepted))` when the command may proceed, and
    /// `Ok(Some(Denied(cause)))` when it is refused, for example because the
    /// connection does not hold the selection, the state does not allow it, or the
    /// parameters do not match the preceding select. Parameters that differ from
    /// those of the SelectWithValue also end the selection.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::Protocol` when the state mutex is poisoned.
    pub fn begin_operate(
        &self,
        conn_id: u64,
        params: &OperParams,
    ) -> Result<Option<OperateBeginResult>, ServerError> {
        let mut g = self.inner.lock().map_err(|_| {
            ServerError::Protocol("ControlObject Mutex poisoned on begin_operate".into())
        })?;
        let settings = self.settings_locked(&g);

        // A status-only object never accepts a control request.
        if settings.ctl_model == ControlModel::StatusOnly {
            tracing::warn!(name = %self.config.name, "operate refused: ctlModel is status-only");
            return Ok(Some(OperateBeginResult::Denied(
                ControlAddCause::NotSupported,
            )));
        }

        // The origin field must be well formed.
        if !params.origin.is_valid() {
            tracing::warn!(
                name = %self.config.name,
                or_cat = params.origin.or_cat,
                or_ident_len = params.origin.or_ident.len(),
                "operate refused: malformed origin field"
            );
            return Ok(Some(OperateBeginResult::Denied(
                ControlAddCause::InconsistentParameters,
            )));
        }

        if !settings.is_sbo() {
            // Direct control is idle in the unselected state.
            if g.state != ControlState::Unselected {
                tracing::warn!(
                    name = %self.config.name,
                    state = ?g.state,
                    "operate refused: direct control requires an idle object"
                );
                return Ok(Some(OperateBeginResult::Denied(
                    ControlAddCause::CommandAlreadyInExecution,
                )));
            }
            g.state = ControlState::WaitForExecution;
            g.owner_conn_id = conn_id;
            g.active = Some(settings);
            g.last_oper_params = Some(params.clone());
            return Ok(Some(OperateBeginResult::Accepted));
        }

        // Select-before-operate: the object must be selected by this connection.
        if g.state != ControlState::Ready {
            tracing::warn!(
                name = %self.config.name,
                state = ?g.state,
                "operate refused: the object is not selected"
            );
            return Ok(Some(OperateBeginResult::Denied(
                ControlAddCause::ObjectNotSelected,
            )));
        }
        if g.owner_conn_id != conn_id {
            tracing::warn!(
                name = %self.config.name,
                owner = g.owner_conn_id,
                requester = conn_id,
                "operate refused: the selection is held by another connection"
            );
            return Ok(Some(OperateBeginResult::Denied(
                ControlAddCause::LockedByOtherClient,
            )));
        }
        if settings.ctl_model == ControlModel::SboEnhanced {
            // Enhanced security requires the parameters of the SelectWithValue.
            let consistent = g
                .last_oper_params
                .as_ref()
                .is_some_and(|sbow| params_consistent(params, sbow));
            if !consistent {
                tracing::warn!(
                    name = %self.config.name,
                    "operate refused: parameters differ from the preceding SBOw"
                );
                let owner = g.clear();
                drop(g);
                self.notify(SelectionChange::ended(
                    owner,
                    SelectStateChangedReason::OperateRefused,
                ));
                return Ok(Some(OperateBeginResult::Denied(
                    ControlAddCause::InconsistentParameters,
                )));
            }
        }
        g.stop_timer();
        g.state = ControlState::WaitForExecution;
        g.last_oper_params = Some(params.clone());
        Ok(Some(OperateBeginResult::Accepted))
    }

    /// Completes an Operate, returning to ready or unselected according to the
    /// select class.
    ///
    /// An operate-many selection returns to ready and restarts its select
    /// timeout; an operate-once selection ends and reports `OperateDone`, or
    /// `Disconnected` when the connection holding it closed during the command.
    pub fn finish_operate(&self) {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if !g.state.is_executing() {
            return;
        }
        let settings = self.settings_locked(&g);
        if !settings.is_sbo() {
            g.clear();
            return;
        }
        if settings.sbo_class == SboClass::OperateMany && !g.owner_lost {
            let owner = g.owner_conn_id;
            let period = g.enter_ready(owner, settings);
            drop(g);
            self.arm_select_timer(period, settings.sbo_timeout_ms);
            return;
        }
        let reason = if g.owner_lost {
            SelectStateChangedReason::Disconnected
        } else {
            SelectStateChangedReason::OperateDone
        };
        let owner = g.clear();
        drop(g);
        self.notify(SelectionChange::ended(owner, reason));
    }

    /// Moves the object from awaiting the dynamic check to executing the command.
    pub fn set_state_operate(&self) {
        if let Ok(mut g) = self.inner.lock() {
            if g.state == ControlState::WaitForExecution {
                g.state = ControlState::Operate;
            }
        }
    }

    /// Returns the object to unselected after a refused check or a failed
    /// command; a select-before-operate object reports `OperateRefused`.
    pub fn abort_to_unselected(&self) {
        self.abort(SelectStateChangedReason::OperateRefused);
    }

    /// Returns the object to unselected and, when it held a selection of a
    /// select-before-operate model, reports `reason`.
    pub(crate) fn abort(&self, reason: SelectStateChangedReason) {
        let Ok(mut g) = self.inner.lock() else {
            return;
        };
        let held = g.state != ControlState::Unselected && self.settings_locked(&g).is_sbo();
        let owner = g.clear();
        drop(g);
        if held {
            self.notify(SelectionChange::ended(owner, reason));
        }
    }

    // ─── Select with value ───────────────────────────────────────────────

    /// Selects the object with a value, recording the SBOw parameters an Operate
    /// will later be compared against.
    ///
    /// Returns whether the object was selected.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::Protocol` when the state mutex is poisoned.
    pub fn try_sbow_select(&self, conn_id: u64, params: &OperParams) -> Result<bool, ServerError> {
        self.sbow_select(conn_id, params).map(|r| r.is_ok())
    }

    /// Selects the object with a value, returning the add cause of a refusal.
    ///
    /// A selected object refuses with `ObjectAlreadySelected`, whichever
    /// connection holds the selection, an executing one with
    /// `CommandAlreadyInExecution`, and a malformed origin is refused with
    /// `InconsistentParameters`. A successful select starts the select timeout
    /// and reports `Selected`.
    pub(crate) fn sbow_select(
        &self,
        conn_id: u64,
        params: &OperParams,
    ) -> Result<Result<(), ControlAddCause>, ServerError> {
        let mut g = self.inner.lock().map_err(|_| {
            ServerError::Protocol("ControlObject Mutex poisoned on sbow_select".into())
        })?;

        if g.state != ControlState::Unselected {
            tracing::warn!(
                name = %self.config.name,
                state = ?g.state,
                "select-with-value refused: the object is already selected or executing"
            );
            let cause = if g.state == ControlState::Ready {
                ControlAddCause::ObjectAlreadySelected
            } else {
                ControlAddCause::CommandAlreadyInExecution
            };
            return Ok(Err(cause));
        }

        // The origin field must be well formed.
        if !params.origin.is_valid() {
            tracing::warn!(
                name = %self.config.name,
                "select-with-value refused: malformed origin field"
            );
            return Ok(Err(ControlAddCause::InconsistentParameters));
        }

        let settings = self.live_settings();
        let period = g.enter_ready(conn_id, settings);
        g.last_oper_params = Some(params.clone());
        drop(g);
        tracing::debug!(name = %self.config.name, conn_id, "select-with-value accepted");
        // Reported before the timer exists, so a Timeout cannot precede it.
        self.notify(SelectionChange {
            conn_id,
            is_selected: true,
            reason: SelectStateChangedReason::Selected,
            t: params.t,
            origin: params.origin.clone(),
            ctl_num: params.ctl_num,
        });
        self.arm_select_timer(period, settings.sbo_timeout_ms);
        Ok(Ok(()))
    }

    // ─── Cancel ──────────────────────────────────────────────────────────

    /// Cancels a selection.
    ///
    /// An executing command is not cancellable and is refused with
    /// `CommandAlreadyInExecution`. A selected object is deselected when the
    /// request comes from the connection that holds it, and reports
    /// `Canceled`. An idle object of a direct control model has no selection to
    /// cancel and refuses with `NotSupported`, per IEC 61850-7-2 Table 47;
    /// canceling an unselected select-before-operate object succeeds and does
    /// nothing.
    pub fn try_cancel(&self, conn_id: u64) -> CancelResult {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return CancelResult::Denied(ControlAddCause::Unknown),
        };

        if g.state.is_executing() {
            tracing::warn!(
                name = %self.config.name,
                state = ?g.state,
                "cancel refused: a command is executing"
            );
            return CancelResult::Denied(ControlAddCause::CommandAlreadyInExecution);
        }

        if g.state == ControlState::Ready {
            if g.owner_conn_id != conn_id {
                tracing::warn!(
                    name = %self.config.name,
                    owner = g.owner_conn_id,
                    requester = conn_id,
                    "cancel refused: the selection is held by another connection"
                );
                return CancelResult::Denied(ControlAddCause::LockedByOtherClient);
            }
            let owner = g.clear();
            drop(g);
            tracing::debug!(name = %self.config.name, "selection canceled");
            self.notify(SelectionChange::ended(
                owner,
                SelectStateChangedReason::Canceled,
            ));
            return CancelResult::Accepted;
        }

        if !self.settings_locked(&g).is_sbo() {
            tracing::warn!(
                name = %self.config.name,
                "cancel refused: direct control has no selection to cancel"
            );
            return CancelResult::Denied(ControlAddCause::NotSupported);
        }

        // Canceling an unselected object is accepted and does nothing.
        CancelResult::Accepted
    }

    // ─── Connection loss ─────────────────────────────────────────────────

    /// Ends the selection held by a connection that has closed.
    ///
    /// A selected object is deselected at once and reports `Disconnected`. A
    /// command already executing for that connection runs to its end, after
    /// which the selection ends as well. Nothing happens for an object
    /// `conn_id` does not hold.
    pub fn on_connection_closed(&self, conn_id: u64) {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if g.owner_conn_id != conn_id {
            return;
        }
        match g.state {
            ControlState::Ready => {
                let owner = g.clear();
                drop(g);
                self.notify(SelectionChange::ended(
                    owner,
                    SelectStateChangedReason::Disconnected,
                ));
            }
            ControlState::WaitForExecution | ControlState::Operate => g.owner_lost = true,
            ControlState::Unselected => {}
        }
    }

    // ─── Select state notification ───────────────────────────────────────

    fn notify(&self, change: SelectionChange) {
        let observer = self
            .observer
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .and_then(|slot| slot.read().ok().and_then(|g| g.clone()));
        if let Some(observe) = observer {
            observe(&self.config, change.is_selected);
        }
        let handler = self
            .select_state_handler
            .lock()
            .ok()
            .and_then(|g| g.clone());
        if let Some(h) = handler {
            let action = ControlAction::new(
                change.ctl_num,
                change.origin,
                change.t,
                false,
                false,
                false,
                change.is_selected,
                change.conn_id,
            );
            h.on_select_state_changed(&action, change.is_selected, change.reason);
        }
    }

    // ─── Object reference ────────────────────────────────────────────────

    /// Returns the object reference in the form `<LD>/<LN>$CO$<DO>`.
    pub fn object_ref(&self) -> String {
        format!(
            "{}/{}$CO${}",
            self.config.domain, self.config.ln_name, self.config.name
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Supporting types
// ─────────────────────────────────────────────────────────────────────────────

/// Result of `begin_operate`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OperateBeginResult {
    /// The command may proceed; the object is now awaiting the dynamic check.
    Accepted,
    /// The command is refused, with the cause to report.
    Denied(ControlAddCause),
}

/// Result of `try_cancel`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CancelResult {
    /// The cancel was accepted.
    Accepted,
    /// The cancel was refused, with the cause to report.
    Denied(ControlAddCause),
}

// ─────────────────────────────────────────────────────────────────────────────
// Parameter comparison for enhanced security
// ─────────────────────────────────────────────────────────────────────────────

/// Returns whether an Operate carries the same parameters as its SBOw, which
/// enhanced security requires per IEC 61850-7-2.
///
/// The control value is compared by its bit pattern, so a NaN float compares equal
/// to itself.
fn params_consistent(oper: &OperParams, sbow: &OperParams) -> bool {
    use super::model::mms_value_binary_equal;

    mms_value_binary_equal(&oper.ctl_val, &sbow.ctl_val)
        && oper.origin == sbow.origin
        && oper.ctl_num == sbow.ctl_num
        && oper.interlock_check == sbow.interlock_check
        && oper.synchro_check == sbow.synchro_check
        && oper.test == sbow.test
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use iec61850_model::MmsValue;

    fn make_config(model: ControlModel) -> ControlObjectConfig {
        ControlObjectConfig {
            name: "SPCSO1".into(),
            ln_name: "GGIO1".into(),
            domain: "IED1LD0".into(),
            ctl_model: model,
            sbo_timeout_ms: 5000,
            sbo_class: SboClass::OperateOnce,
            oper_timeout_ms: 0,
        }
    }

    fn make_oper_params(ctl_val: MmsValue) -> OperParams {
        OperParams {
            ctl_val,
            oper_tm_ms: 0,
            origin: OriginValue {
                or_cat: 3,
                or_ident: vec![0x01],
            },
            ctl_num: 7,
            t: [0u8; 8],
            test: false,
            synchro_check: false,
            interlock_check: true,
        }
    }

    // ── A second select with value ───────────────────────────────────────

    #[test]
    fn sbow_select_on_a_selected_object_is_object_already_selected() {
        let obj = ControlObject::new(make_config(ControlModel::SboEnhanced));
        let params = make_oper_params(MmsValue::Boolean(true));
        assert_eq!(obj.sbow_select(1, &params).unwrap(), Ok(()));
        assert_eq!(
            obj.sbow_select(1, &params).unwrap(),
            Err(ControlAddCause::ObjectAlreadySelected)
        );
        assert_eq!(
            obj.sbow_select(2, &params).unwrap(),
            Err(ControlAddCause::ObjectAlreadySelected)
        );
        assert_eq!(obj.state(), ControlState::Ready);
    }

    // ── An out-of-range ctlModel is refused ──────────────────────────────

    #[test]
    fn ctl_model_out_of_range_returns_err() {
        assert!(ControlObjectConfig::validate_ctl_model(5).is_err());
        assert!(ControlObjectConfig::validate_ctl_model(-1).is_err());
        assert!(ControlObjectConfig::validate_ctl_model(100).is_err());
    }

    #[test]
    fn ctl_model_valid_range_ok() {
        for v in 0i32..=4 {
            assert!(ControlObjectConfig::validate_ctl_model(v).is_ok());
        }
    }

    // ── A status-only object refuses Operate ─────────────────────────────

    #[test]
    fn status_only_denies_operate() {
        let obj = ControlObject::new(make_config(ControlModel::StatusOnly));
        let params = make_oper_params(MmsValue::Boolean(true));
        let result = obj.begin_operate(1, &params).unwrap();
        assert_eq!(
            result,
            Some(OperateBeginResult::Denied(ControlAddCause::NotSupported))
        );
    }

    // ── Direct control, normal security ──────────────────────────────────

    #[test]
    fn direct_normal_operate_transitions() {
        let obj = ControlObject::new(make_config(ControlModel::DirectNormal));
        assert_eq!(obj.state(), ControlState::Unselected);

        let params = make_oper_params(MmsValue::Boolean(true));
        let result = obj.begin_operate(1, &params).unwrap();
        assert_eq!(result, Some(OperateBeginResult::Accepted));
        assert_eq!(obj.state(), ControlState::WaitForExecution);

        obj.set_state_operate();
        assert_eq!(obj.state(), ControlState::Operate);

        obj.finish_operate();
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    // ── SBO-Normal select / operate / finish ───────────────────────────

    #[test]
    fn sbo_normal_select_operate_flow() {
        let obj = ControlObject::new(make_config(ControlModel::SboNormal));

        // select
        assert!(obj.try_select(1).unwrap());
        assert_eq!(obj.state(), ControlState::Ready);

        // Operate from the same connection.
        let params = make_oper_params(MmsValue::Boolean(true));
        let r = obj.begin_operate(1, &params).unwrap();
        assert_eq!(r, Some(OperateBeginResult::Accepted));
        assert_eq!(obj.state(), ControlState::WaitForExecution);

        obj.set_state_operate();
        obj.finish_operate();
        // a once-only selection returns to unselected
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    // ── Select-before-operate refuses another connection ─────────────────

    #[test]
    fn sbo_normal_wrong_conn_denied() {
        let obj = ControlObject::new(make_config(ControlModel::SboNormal));
        assert!(obj.try_select(1).unwrap());

        let params = make_oper_params(MmsValue::Boolean(true));
        let r = obj.begin_operate(2, &params).unwrap();
        assert_eq!(
            r,
            Some(OperateBeginResult::Denied(
                ControlAddCause::LockedByOtherClient
            ))
        );
    }

    // ── Enhanced security accepts matching parameters ────────────────────

    #[test]
    fn sbo_enhanced_consistent_params_accepted() {
        let obj = ControlObject::new(make_config(ControlModel::SboEnhanced));
        let params = make_oper_params(MmsValue::Boolean(true));

        assert!(obj.try_sbow_select(1, &params).unwrap());
        assert_eq!(obj.state(), ControlState::Ready);

        let r = obj.begin_operate(1, &params).unwrap();
        assert_eq!(r, Some(OperateBeginResult::Accepted));
    }

    // ── Enhanced security refuses differing parameters and deselects ─────

    #[test]
    fn sbo_enhanced_inconsistent_params_denied() {
        let obj = ControlObject::new(make_config(ControlModel::SboEnhanced));
        let sbow_params = make_oper_params(MmsValue::Boolean(true));
        let oper_params = make_oper_params(MmsValue::Boolean(false)); // a different ctlVal

        assert!(obj.try_sbow_select(1, &sbow_params).unwrap());
        let r = obj.begin_operate(1, &oper_params).unwrap();
        assert_eq!(
            r,
            Some(OperateBeginResult::Denied(
                ControlAddCause::InconsistentParameters
            ))
        );
        // Differing parameters also deselect the object.
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    // ── The select timeout without a runtime ─────────────────────────────

    #[test]
    fn a_select_timeout_of_zero_never_fires() {
        let mut config = make_config(ControlModel::SboNormal);
        config.sbo_timeout_ms = 0;
        let obj = ControlObject::new(config);
        assert!(obj.try_select(1).unwrap());
        assert!(!obj.check_sbo_timeout(), "a timeout of 0 never fires");
        assert_eq!(obj.state(), ControlState::Ready);
    }

    // ── Selection changes and the select timer ───────────────────────────

    type Changes = tokio::sync::mpsc::UnboundedReceiver<(SelectStateChangedReason, u64, u8)>;

    /// Records every selection change: its reason, connection, and ctlNum.
    struct ChangeLog(tokio::sync::mpsc::UnboundedSender<(SelectStateChangedReason, u64, u8)>);

    impl SelectStateChangedHandler for ChangeLog {
        fn on_select_state_changed(
            &self,
            action: &ControlAction,
            is_selected: bool,
            reason: SelectStateChangedReason,
        ) {
            assert_eq!(is_selected, reason == SelectStateChangedReason::Selected);
            let _ = self.0.send((reason, action.conn_id(), action.ctl_num()));
        }
    }

    fn observed(config: ControlObjectConfig) -> (ControlObject, Changes) {
        let obj = ControlObject::new(config);
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        obj.set_select_state_handler(Arc::new(ChangeLog(tx)));
        (obj, rx)
    }

    /// Returns the next change, or `None` when none comes within an hour of the
    /// paused clock.
    async fn next(rx: &mut Changes) -> Option<(SelectStateChangedReason, u64, u8)> {
        tokio::time::timeout(Duration::from_secs(3600), rx.recv())
            .await
            .ok()
            .flatten()
    }

    fn drained(rx: &mut Changes) -> Vec<SelectStateChangedReason> {
        let mut out = Vec::new();
        while let Ok((reason, _, _)) = rx.try_recv() {
            out.push(reason);
        }
        out
    }

    #[tokio::test(start_paused = true)]
    async fn select_timeout_deselects_exactly_at_the_limit() {
        let mut config = make_config(ControlModel::SboNormal);
        config.sbo_timeout_ms = 100;
        let (obj, mut rx) = observed(config);
        let started = Instant::now();
        assert!(obj.try_select(7).unwrap());
        assert_eq!(
            next(&mut rx).await,
            Some((SelectStateChangedReason::Selected, 7, 0))
        );
        assert_eq!(
            next(&mut rx).await,
            Some((SelectStateChangedReason::Timeout, 7, 0))
        );
        assert_eq!(started.elapsed(), Duration::from_millis(100));
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_selection_is_not_ended_by_the_timer_of_the_previous_one() {
        let mut config = make_config(ControlModel::SboNormal);
        config.sbo_timeout_ms = 100;
        let (obj, mut rx) = observed(config);
        let started = Instant::now();
        assert!(obj.try_select(1).unwrap());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(obj.try_cancel(1), CancelResult::Accepted);
        assert!(obj.try_select(1).unwrap());
        assert_eq!(
            drained(&mut rx),
            vec![
                SelectStateChangedReason::Selected,
                SelectStateChangedReason::Canceled,
                SelectStateChangedReason::Selected
            ]
        );
        assert_eq!(
            next(&mut rx).await,
            Some((SelectStateChangedReason::Timeout, 1, 0))
        );
        assert_eq!(started.elapsed(), Duration::from_millis(150));
    }

    #[tokio::test(start_paused = true)]
    async fn operate_many_restarts_the_select_timeout() {
        let mut config = make_config(ControlModel::SboNormal);
        config.sbo_timeout_ms = 100;
        config.sbo_class = SboClass::OperateMany;
        let (obj, mut rx) = observed(config);
        let started = Instant::now();
        assert!(obj.try_select(1).unwrap());
        tokio::time::sleep(Duration::from_millis(60)).await;
        let params = make_oper_params(MmsValue::Boolean(true));
        assert_eq!(
            obj.begin_operate(1, &params).unwrap(),
            Some(OperateBeginResult::Accepted)
        );
        obj.finish_operate();
        assert_eq!(obj.state(), ControlState::Ready);
        assert_eq!(drained(&mut rx), vec![SelectStateChangedReason::Selected]);
        assert_eq!(
            next(&mut rx).await,
            Some((SelectStateChangedReason::Timeout, 1, 0))
        );
        assert_eq!(started.elapsed(), Duration::from_millis(160));
    }

    /// Yields until the runtime has polled every task it has queued.
    async fn reap() {
        for _ in 0..256 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn select_timers_do_not_outlive_their_selection() {
        let mut config = make_config(ControlModel::SboNormal);
        config.sbo_timeout_ms = 30_000;
        let obj = ControlObject::new(config);
        let metrics = tokio::runtime::Handle::current().metrics();
        let params = make_oper_params(MmsValue::Boolean(true));
        for _ in 0..50 {
            assert!(obj.try_select(1).unwrap());
            assert_eq!(obj.try_cancel(1), CancelResult::Accepted);
            assert!(obj.try_select(1).unwrap());
            obj.begin_operate(1, &params).unwrap();
            obj.finish_operate();
        }
        assert!(obj.try_select(1).unwrap());
        // Aborted tasks are reaped once the runtime polls them.
        reap().await;
        assert_eq!(
            metrics.num_alive_tasks(),
            1,
            "only the timer of the current selection is alive"
        );
        assert_eq!(obj.try_cancel(1), CancelResult::Accepted);
        reap().await;
        assert_eq!(metrics.num_alive_tasks(), 0);
    }

    #[tokio::test]
    async fn every_selection_change_is_reported() {
        let (obj, mut rx) = observed(make_config(ControlModel::SboNormal));
        let params = make_oper_params(MmsValue::Boolean(true));

        // Cancel.
        assert!(obj.try_select(1).unwrap());
        assert_eq!(obj.try_cancel(1), CancelResult::Accepted);
        // An operate-once command.
        assert!(obj.try_select(1).unwrap());
        obj.begin_operate(1, &params).unwrap();
        obj.finish_operate();
        // A lost connection while selected, and while executing.
        assert!(obj.try_select(1).unwrap());
        obj.on_connection_closed(1);
        assert!(obj.try_select(2).unwrap());
        obj.begin_operate(2, &params).unwrap();
        obj.on_connection_closed(2);
        assert_eq!(obj.state(), ControlState::WaitForExecution);
        obj.finish_operate();
        // A refused Operate.
        assert!(obj.try_select(3).unwrap());
        obj.begin_operate(3, &params).unwrap();
        obj.abort_to_unselected();

        use SelectStateChangedReason as R;
        assert_eq!(
            drained(&mut rx),
            vec![
                R::Selected,
                R::Canceled,
                R::Selected,
                R::OperateDone,
                R::Selected,
                R::Disconnected,
                R::Selected,
                R::Disconnected,
                R::Selected,
                R::OperateRefused,
            ]
        );
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    #[tokio::test]
    async fn select_with_value_reports_its_parameters_and_a_mismatch() {
        let (obj, mut rx) = observed(make_config(ControlModel::SboEnhanced));
        let params = make_oper_params(MmsValue::Boolean(true));
        assert_eq!(obj.sbow_select(4, &params).unwrap(), Ok(()));
        assert_eq!(
            rx.try_recv().ok(),
            Some((SelectStateChangedReason::Selected, 4, params.ctl_num))
        );
        let other = make_oper_params(MmsValue::Boolean(false));
        assert_eq!(
            obj.begin_operate(4, &other).unwrap(),
            Some(OperateBeginResult::Denied(
                ControlAddCause::InconsistentParameters
            ))
        );
        assert_eq!(
            rx.try_recv().ok(),
            Some((SelectStateChangedReason::OperateRefused, 4, 0))
        );
    }

    #[tokio::test]
    async fn direct_control_reports_no_selection_change() {
        let (obj, mut rx) = observed(make_config(ControlModel::DirectEnhanced));
        let params = make_oper_params(MmsValue::Boolean(true));
        obj.begin_operate(1, &params).unwrap();
        obj.finish_operate();
        obj.begin_operate(1, &params).unwrap();
        obj.abort_to_unselected();
        assert!(drained(&mut rx).is_empty());
    }

    // ── A selected object refuses a second select ────────────────────────

    #[test]
    fn select_of_a_selected_object_is_refused_for_every_connection() {
        let obj = ControlObject::new(make_config(ControlModel::SboNormal));
        assert!(obj.try_select(1).unwrap());
        assert!(!obj.try_select(1).unwrap(), "the same connection");
        assert!(!obj.try_select(2).unwrap(), "another connection");
        assert_eq!(obj.state(), ControlState::Ready);
    }

    // ── Cancel is refused while a command executes ───────────────────────

    #[test]
    fn cancel_during_execute_denied() {
        let obj = ControlObject::new(make_config(ControlModel::DirectNormal));
        let params = make_oper_params(MmsValue::Boolean(true));
        obj.begin_operate(1, &params).unwrap();
        obj.set_state_operate(); // move into the executing state

        let r = obj.try_cancel(1);
        assert_eq!(
            r,
            CancelResult::Denied(ControlAddCause::CommandAlreadyInExecution)
        );
    }

    // ── Cancel from the selecting connection succeeds ────────────────────

    #[test]
    fn cancel_selected_same_conn_ok() {
        let obj = ControlObject::new(make_config(ControlModel::SboNormal));
        assert!(obj.try_select(1).unwrap());

        let r = obj.try_cancel(1);
        assert_eq!(r, CancelResult::Accepted);
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    // ── Cancel from another connection is refused ────────────────────────

    #[test]
    fn cancel_selected_wrong_conn_denied() {
        let obj = ControlObject::new(make_config(ControlModel::SboNormal));
        assert!(obj.try_select(1).unwrap());

        let r = obj.try_cancel(2);
        assert_eq!(
            r,
            CancelResult::Denied(ControlAddCause::LockedByOtherClient)
        );
        assert_eq!(obj.state(), ControlState::Ready);
    }

    // ── Cancel of an idle direct object ──────────────────────────────────

    #[test]
    fn cancel_of_an_idle_direct_object_is_not_supported() {
        for model in [ControlModel::DirectNormal, ControlModel::DirectEnhanced] {
            let obj = ControlObject::new(make_config(model));
            assert_eq!(
                obj.try_cancel(1),
                CancelResult::Denied(ControlAddCause::NotSupported)
            );
        }
        let obj = ControlObject::new(make_config(ControlModel::SboNormal));
        assert_eq!(obj.try_cancel(1), CancelResult::Accepted);
    }

    // ── Losing the connection deselects the object ───────────────────────

    #[test]
    fn connection_closed_auto_unselect() {
        let obj = ControlObject::new(make_config(ControlModel::SboNormal));
        assert!(obj.try_select(5).unwrap());

        obj.on_connection_closed(5);
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    /// A selection lost with its association reports that association.
    #[tokio::test(start_paused = true)]
    async fn a_lost_selection_reports_the_association_that_held_it() {
        let (obj, mut rx) = observed(make_config(ControlModel::SboNormal));
        assert!(obj.try_select(5).unwrap());
        obj.on_connection_closed(5);
        assert_eq!(
            rx.try_recv().ok(),
            Some((SelectStateChangedReason::Selected, 5, 0))
        );
        assert_eq!(
            rx.try_recv().ok(),
            Some((SelectStateChangedReason::Disconnected, 5, 0))
        );
    }

    // ── Losing another connection changes nothing ────────────────────────

    #[test]
    fn connection_closed_wrong_conn_no_effect() {
        let obj = ControlObject::new(make_config(ControlModel::SboNormal));
        assert!(obj.try_select(5).unwrap());

        obj.on_connection_closed(6); // a different connection
        assert_eq!(obj.state(), ControlState::Ready);
    }

    // ── A malformed origin is refused ────────────────────────────────────

    #[test]
    fn invalid_origin_denied() {
        let obj = ControlObject::new(make_config(ControlModel::DirectNormal));
        let mut params = make_oper_params(MmsValue::Boolean(true));
        params.origin.or_cat = 99; // outside 0 to 8

        let r = obj.begin_operate(1, &params).unwrap();
        assert_eq!(
            r,
            Some(OperateBeginResult::Denied(
                ControlAddCause::InconsistentParameters
            ))
        );
    }

    // ── The object reference has the expected form ───────────────────────

    #[test]
    fn object_ref_format() {
        let obj = ControlObject::new(make_config(ControlModel::DirectNormal));
        assert_eq!(obj.object_ref(), "IED1LD0/GGIO1$CO$SPCSO1");
    }

    // ── Very long names do not panic ─────────────

    #[test]
    fn long_names_no_panic() {
        // A logical node name and data object name that
        // together exceed a fixed-size item identifier buffer must not overflow.
        // The reference is formatted into an allocated String, so any length is safe.
        let long_name = "A".repeat(64);
        let long_ln = "B".repeat(32);
        let config = ControlObjectConfig {
            name: long_name.clone(),
            ln_name: long_ln.clone(),
            domain: "IED1LD0".into(),
            ctl_model: ControlModel::DirectNormal,
            sbo_timeout_ms: 30000,
            sbo_class: SboClass::OperateOnce,
            oper_timeout_ms: 0,
        };
        let obj = ControlObject::new(config);
        // Formatting cannot panic, however long the names are.
        let r = obj.object_ref();
        assert!(r.contains(&long_name));
        assert!(r.contains(&long_ln));
    }

    // ── A many-operate selection stays selected after Operate ────────────

    #[test]
    fn sbo_operate_many_stays_ready() {
        let mut config = make_config(ControlModel::SboNormal);
        config.sbo_class = SboClass::OperateMany;
        let obj = ControlObject::new(config);

        assert!(obj.try_select(1).unwrap());
        let params = make_oper_params(MmsValue::Boolean(true));
        obj.begin_operate(1, &params).unwrap();
        obj.set_state_operate();
        obj.finish_operate();

        // A many-operate selection stays ready.
        assert_eq!(obj.state(), ControlState::Ready);
    }
}
