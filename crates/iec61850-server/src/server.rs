//! `IedServer`, the IEC 61850 server object.
//!
//! The server owns its listener directly and keeps its associations in a map
//! keyed by connection id. Values are updated through typed entry points, so the
//! type of an update is checked by the compiler where it can be and reported as
//! an error where it cannot. A negotiated MMS PDU size is clamped to a floor of
//! `MIN_PDU_SIZE`, enforced during Initiate negotiation in `iec61850-mms`.
//!
//! The data model lock is a mutex acquired without blocking, so locking the
//! model again from a thread that already holds it returns `Err(AlreadyLocked)`
//! instead of deadlocking. While the lock is held, an update still writes its
//! value at once, but the report and log triggers it raises are held back and
//! raised together when the lock is released; the periodic report and log
//! triggers wait for the release as well.

use crate::config::IedServerConfig;
use crate::connection::{ClientConnection, ConnectionId};
use crate::control::{ChannelCommandTermination, ControlObjectsRegistry};
use crate::error::{Result, ServerError};
use crate::handler::{AttributeAccessHandler, HandlerRegistry, ReadHandler};
use crate::mapping::{
    bit_string_fits, bit_string_len, declared_bit_string_size, MmsDeviceModel, StringSize,
};
use crate::policy::WriteAccessPolicies;
use crate::reporting::{
    BufferedReportControl, ChannelReportSink, DataAttributeRef, Dataset, InclusionFlag,
    ReportControl, ReportingEngine, TriggerOptions,
};
use crate::service::write::{WrittenLeaf, WrittenLeaves};
use crate::service::MmsModelDispatcher;
use iec61850_mms::mms::server::MmsServiceDispatcher;
use iec61850_model::{DataAttribute, IedModel, MmsValue, TrgOps};
#[cfg(feature = "tls")]
use iec61850_tls::TlsAcceptor;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{
    Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockError,
};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// IEC 61850 server runtime.
///
/// Cloning shares one server: the model, the association map, the dispatcher,
/// and every registry live behind a single reference-counted inner object.
#[derive(Clone)]
pub struct IedServer {
    inner: Arc<IedServerInner>,
}

struct IedServerInner {
    model: Arc<IedModel>,
    /// The MMS view the built-in dispatcher serves, whose value lock an
    /// update of several leaves holds so a read sees it whole; `None` with a
    /// dispatcher the application supplied.
    mms_view: Option<Arc<MmsDeviceModel>>,
    /// Start-up settings, including the association limit the accept loop
    /// enforces.
    config: IedServerConfig,
    bind_addr: SocketAddr,

    /// Open associations, keyed by connection id.
    connections: RwLock<HashMap<ConnectionId, ClientConnection>>,
    /// Accepted sockets, from accept until their task ends, whether or not
    /// they have finished associating; `max_mms_connections` bounds it.
    open_sockets: AtomicUsize,
    /// Source of the next connection id.
    next_connection_id: AtomicU64,

    /// Which functional constraints accept a remote Write; changeable at run
    /// time, hence the lock.
    write_access_policies: RwLock<WriteAccessPolicies>,

    /// Whether the server still accepts associations.
    running: AtomicBool,

    /// Held for the duration of a data model lock; acquired without blocking so
    /// that reentrancy is an error rather than a deadlock.
    data_model_lock_guard: Mutex<()>,

    /// Set while the data model is locked.
    is_model_locked: AtomicBool,

    /// Triggers raised while the data model is locked, raised when it is
    /// released. Deferring a trigger and releasing the batch both happen under
    /// this lock, so a batch is delivered before any update that follows it.
    deferred: Mutex<DeferredTriggers>,

    /// Held for writing while the data model is locked, and for reading by
    /// each tick of the periodic report and log triggers, so a tick never runs
    /// in the middle of a batch of updates.
    batch_gate: RwLock<()>,

    /// Routes confirmed requests. The builder constructs a model-backed
    /// dispatcher unless the caller supplies one.
    dispatcher: Arc<dyn MmsServiceDispatcher>,

    /// Value of the request-blocking flag given to each new association once it
    /// finishes negotiating. Setting the flag also writes it to every
    /// association already open, so it acts as one server-wide policy.
    connection_block_requests_default: AtomicBool,

    /// Control objects, shared with the dispatcher.
    control_objects: Arc<ControlObjectsRegistry>,

    /// Routes command terminations to the association that issued the command:
    /// the connection task registers a sender and the control service posts
    /// through it.
    ct_sink: Arc<ChannelCommandTermination>,

    /// Reporting engine, shared with the dispatcher and driven by the tick loop.
    reporting_engine: Arc<Mutex<ReportingEngine>>,
    /// The engine's index of bound data set members, queried without its lock.
    value_index: crate::reporting::engine::ValueIndex,

    /// Maps the address of a shared data attribute value to the reference the
    /// reporting engine knows it by, so that an update can trigger a report
    /// without carrying the path along.
    ///
    /// Registering a report control block fills this from the members of its
    /// data set.
    attr_ref_index: RwLock<HashMap<usize, DataAttributeRef>>,

    /// Data sets, keyed by `(domain, mms_list_name)` such as
    /// (`"simpleIOGenericIO"`, `"GGIO1$ds1"`), so a Read that names a data set
    /// can resolve it.
    ///
    /// Registering two control blocks under one data set name leaves the later
    /// one in place; the data set belongs to the model and a control block only
    /// refers to it.
    ///
    /// Shared with the dispatcher, so a data set registered at run time is
    /// visible to it at once.
    dataset_registry: crate::reporting::DatasetRegistry,

    /// Keys of the data sets created at run time, shared with the dispatcher.
    dynamic_dataset_keys: crate::service::define_named_variable_list::DynamicDatasetKeys,

    /// Routes encoded reports to the association that subscribed: the
    /// connection task registers a sender and the engine posts through it.
    report_sink: Arc<ChannelReportSink>,

    /// Read and write handlers, shared with the dispatcher.
    handler_registry: Arc<HandlerRegistry>,

    /// Log control blocks, shared with the dispatcher.
    log_controls: crate::logging::LogControlRegistry,

    /// Setting group runtimes, shared with the dispatcher and projected from the
    /// model when the server is built.
    setting_groups: Arc<crate::setting_groups::SettingGroupRegistry>,

    /// TLS acceptor. When present, the accept loop performs the handshake
    /// before the connection task starts; otherwise the connection is plain
    /// TCP.
    #[cfg(feature = "tls")]
    pub(crate) tls_acceptor: Option<TlsAcceptor>,

    /// GOOSE control blocks, shared with the dispatcher, which exposes them
    /// through Read, Write, and GetNameList.
    gocb_registry: Arc<crate::goose_mapping::GoCBRegistry>,
}

impl std::fmt::Debug for IedServerInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IedServerInner")
            .field("ied_name", &self.model.ied_name)
            .field("bind_addr", &self.bind_addr)
            .field("running", &self.running.load(Ordering::SeqCst))
            .field(
                "connection_count",
                &self.connections.read().map(|g| g.len()),
            )
            .finish()
    }
}

impl std::fmt::Debug for IedServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

/// One of the `max_mms_connections` slots, held by an accepted socket for the
/// life of its connection task and given back on drop.
#[derive(Debug)]
pub(crate) struct ConnectionSlot {
    server: IedServer,
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.server
            .inner
            .open_sockets
            .fetch_sub(1, Ordering::SeqCst);
    }
}

impl IedServer {
    /// Starts building a server.
    pub fn builder() -> IedServerBuilder<NoModel> {
        IedServerBuilder {
            model: None,
            config: IedServerConfig::default(),
            bind_addr: None,
            dispatcher: None,
            #[cfg(feature = "tls")]
            tls_acceptor: None,
            _state: PhantomData,
        }
    }

    /// Returns the model, which is immutable and shared.
    pub fn model(&self) -> Arc<IedModel> {
        self.inner.model.clone()
    }

    /// Returns how many associations are open.
    pub fn connection_count(&self) -> usize {
        self.inner.connections.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Returns the address the server listens on.
    pub fn bind_addr(&self) -> SocketAddr {
        self.inner.bind_addr
    }

    /// Reports whether the server still accepts associations.
    pub fn is_running(&self) -> bool {
        self.inner.running.load(Ordering::SeqCst)
    }

    /// Allows or refuses remote writes under one functional constraint.
    ///
    /// # Errors
    ///
    /// Returns `InvalidModel` when the policy lock is poisoned.
    pub fn set_write_access_policy(&self, fc: iec61850_model::FC, allow: bool) -> Result<()> {
        let mut g = self
            .inner
            .write_access_policies
            .write()
            .map_err(|_| ServerError::InvalidModel("write_access_policies poisoned".into()))?;
        g.set(fc, allow);
        Ok(())
    }

    /// Reports whether remote writes are allowed under a functional constraint.
    pub fn write_access_allowed(&self, fc: iec61850_model::FC) -> bool {
        self.inner
            .write_access_policies
            .read()
            .map(|g| g.is_allowed(fc))
            .unwrap_or(false)
    }

    /// Reports whether the data model is locked, in which case the report and
    /// log triggers of an update are deferred until it is released.
    pub fn is_data_model_locked(&self) -> bool {
        self.inner.is_model_locked.load(Ordering::SeqCst)
    }

    /// Suspends or resumes the handling of confirmed requests.
    ///
    /// While suspended, every association answers a confirmed request with a
    /// reject and logs it, and an association that opens meanwhile is suspended
    /// as soon as it finishes negotiating.
    ///
    /// The flag is written to every open association, so it acts as one
    /// server-wide policy rather than per-association state.
    pub fn block_requests(&self, on: bool) {
        if let Ok(g) = self.inner.connections.read() {
            for conn in g.values() {
                conn.set_block_requests(on);
            }
        }
        self.inner
            .connection_block_requests_default
            .store(on, Ordering::SeqCst);
    }

    /// Returns the request-blocking flag a new association starts with.
    pub fn connection_block_requests_default(&self) -> bool {
        self.inner
            .connection_block_requests_default
            .load(Ordering::SeqCst)
    }

    /// Marks one association for abort.
    ///
    /// The connection task picks the mark up on its next iteration, sends an
    /// ACSE A-ABORT wrapped in presentation user data, a session data TPDU, and
    /// a COTP data TPDU, and closes the socket. Sending the abort tells the
    /// client what happened instead of leaving it to infer a bare close.
    ///
    /// Returns `Ok(false)`: the mark is set, but the abort has not been sent
    /// yet when this returns.
    ///
    /// # Errors
    ///
    /// Returns `InvalidModel` when the association map lock is poisoned.
    pub fn abort_connection(&self, id: ConnectionId) -> Result<bool> {
        let g = self
            .inner
            .connections
            .read()
            .map_err(|_| ServerError::InvalidModel("connections RwLock poisoned".into()))?;
        match g.get(&id) {
            Some(conn) => {
                conn.request_abort();
                tracing::warn!(
                    conn_id = id,
                    "association marked for abort; the abort is sent by its connection task"
                );
                Ok(false)
            }
            None => {
                tracing::warn!(conn_id = id, "no association with this id");
                Ok(false)
            }
        }
    }

    /// Marks every open association for abort and returns how many were marked.
    ///
    /// Each connection task sends its abort and closes its socket on the next
    /// iteration of its loop.
    pub fn abort_all_connections(&self) -> usize {
        let Ok(g) = self.inner.connections.read() else {
            return 0;
        };
        for conn in g.values() {
            conn.request_abort();
        }
        g.len()
    }

    /// Locks the data model for a batch of updates.
    ///
    /// While the returned guard is held, every `update_*` call writes its value
    /// at once, but the report and log triggers it raises are deferred.
    /// Dropping the guard raises them together: an attribute updated more than
    /// once counts once, with its last value and the reasons of all its
    /// updates merged, and the reporting engine takes the whole batch at once,
    /// so a report control block with no buffer time sends one report, and a
    /// buffered one buffers one entry, holding every member the batch
    /// triggered. The periodic triggers, buffer time expiry, integrity and
    /// general interrogation reports, and integrity log entries, wait until the
    /// guard is dropped, so none of them sees part of a batch. A client Read is
    /// not held back and can see part of a batch.
    ///
    /// The server publishes no GOOSE message on its own, so the lock defers
    /// none; an application that publishes GOOSE drives its publisher itself.
    ///
    /// A guard dropped while its thread unwinds from a panic still raises the
    /// deferred triggers, so reports and log entries stay in step with the
    /// values already written, and the model can be locked again afterwards.
    ///
    /// Acquiring the lock can wait for a tick of the periodic triggers that is
    /// under way, which holds the lock off for no longer than that tick.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyLocked` when the model is already locked, including from
    /// the same thread: acquiring without blocking turns reentrancy into an
    /// error the caller can act on instead of a deadlock.
    pub fn lock_data_model(&self) -> Result<DataModelGuard<'_>> {
        let mutex_guard = match self.inner.data_model_lock_guard.try_lock() {
            Ok(g) => g,
            Err(TryLockError::Poisoned(p)) => p.into_inner(),
            Err(TryLockError::WouldBlock) => return Err(ServerError::AlreadyLocked),
        };
        let gate = self
            .inner
            .batch_gate
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        self.deferred().active = true;
        self.inner.is_model_locked.store(true, Ordering::SeqCst);
        Ok(DataModelGuard {
            server: self,
            _gate: gate,
            _guard: mutex_guard,
        })
    }

    /// Holds off a data model lock for one tick of the periodic triggers, or
    /// returns `None` while the model is locked, in which case the tick skips
    /// them.
    pub(crate) fn periodic_gate(&self) -> Option<RwLockReadGuard<'_, ()>> {
        match self.inner.batch_gate.try_read() {
            Ok(g) => Some(g),
            Err(TryLockError::Poisoned(p)) => Some(p.into_inner()),
            Err(TryLockError::WouldBlock) => None,
        }
    }

    /// Returns the deferral state, recovered from a poisoned lock.
    fn deferred(&self) -> MutexGuard<'_, DeferredTriggers> {
        self.inner
            .deferred
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Ends the deferral and raises the deferred triggers as one batch.
    ///
    /// The deferral lock is held until the batch is raised, so an update that
    /// follows the release raises its triggers after the batch.
    fn release_deferred(&self) {
        let mut deferred = self.deferred();
        let triggers = deferred.release();
        self.raise_triggers(&triggers);
        drop(deferred);
    }

    // ── Typed value updates ─────────────────────────────────────────────
    //
    // There is no generic update entry point: a new value type gets its own
    // method, so the type is stated at the call site.

    /// Updates a boolean data attribute.
    ///
    /// # Errors
    ///
    /// Returns `TypeMismatch` when the attribute does not currently hold a
    /// boolean. The mismatch is reported at run time rather than through an
    /// assertion a release build would drop.
    pub fn update_boolean(&self, da: &DataAttribute, value: bool) -> Result<()> {
        self.update_typed(da, iec61850_model::MmsValue::Boolean(value), "Boolean")
    }

    /// Updates an integer data attribute from a 32-bit value.
    ///
    /// The model stores every integer as 64 bits and the encoder chooses the
    /// wire width from the value.
    ///
    /// # Errors
    ///
    /// Returns `TypeMismatch` when the attribute does not currently hold an
    /// integer.
    pub fn update_int32(&self, da: &DataAttribute, value: i32) -> Result<()> {
        self.update_typed(
            da,
            iec61850_model::MmsValue::Integer(value as i64),
            "Integer",
        )
    }

    /// Updates an integer data attribute from a 64-bit value.
    ///
    /// # Errors
    ///
    /// Returns `TypeMismatch` when the attribute does not currently hold an
    /// integer.
    pub fn update_int64(&self, da: &DataAttribute, value: i64) -> Result<()> {
        self.update_typed(da, iec61850_model::MmsValue::Integer(value), "Integer")
    }

    /// Updates an unsigned data attribute.
    ///
    /// # Errors
    ///
    /// Returns `TypeMismatch` when the attribute does not currently hold an
    /// unsigned value.
    pub fn update_unsigned(&self, da: &DataAttribute, value: u32) -> Result<()> {
        self.update_typed(
            da,
            iec61850_model::MmsValue::Unsigned(value as u64),
            "Unsigned",
        )
    }

    /// Updates a 32-bit floating-point data attribute.
    ///
    /// # Errors
    ///
    /// Returns `TypeMismatch` when the attribute does not currently hold a
    /// 32-bit float.
    pub fn update_float32(&self, da: &DataAttribute, value: f32) -> Result<()> {
        self.update_typed(da, iec61850_model::MmsValue::Float32(value), "Float32")
    }

    /// Updates a 64-bit floating-point data attribute.
    ///
    /// # Errors
    ///
    /// Returns `TypeMismatch` when the attribute does not currently hold a
    /// 64-bit float.
    pub fn update_float64(&self, da: &DataAttribute, value: f64) -> Result<()> {
        self.update_typed(da, iec61850_model::MmsValue::Float64(value), "Float64")
    }

    /// Updates a visible-string data attribute.
    ///
    /// # Errors
    ///
    /// Returns `TypeMismatch` when the attribute does not currently hold a
    /// visible string.
    pub fn update_visible_string(
        &self,
        da: &DataAttribute,
        value: impl Into<String>,
    ) -> Result<()> {
        self.update_typed(
            da,
            iec61850_model::MmsValue::VisibleString(value.into()),
            "VisibleString",
        )
    }

    /// Updates a bit-string data attribute from its encoded bytes.
    ///
    /// `data` carries the bits most significant first, as on the wire: bit 0 of
    /// the string is the high-order bit of `data[0]`. `padding` counts the
    /// unused low-order bits of the last byte, which are stored as zero. The
    /// bit count `data.len() * 8 - padding` must fit the declared size of the
    /// attribute, as a remote Write must: exactly N bits for a fixed-size bit
    /// string such as a `Dbpos`, 1 to N bits for a bounded one such as a
    /// `Quality`, and the bit count the attribute holds for a type that
    /// declares no size.
    ///
    /// # Errors
    ///
    /// Returns `TypeMismatch` when the attribute does not currently hold a bit
    /// string, when `padding` is 8 or more or nonzero for empty `data`, when
    /// the bit count does not fit the attribute, or, for a type that declares
    /// no size, when the bit string it holds is malformed. The attribute is
    /// left unchanged on error.
    pub fn update_bit_string(&self, da: &DataAttribute, data: &[u8], padding: u8) -> Result<()> {
        let new_bits = bit_string_len(data.len(), padding).ok_or_else(|| {
            let actual = if padding >= 8 {
                "BitString with padding above 7"
            } else {
                "empty BitString with nonzero padding"
            };
            bit_string_mismatch(da, "BitString with valid padding", actual)
        })?;
        let mut bytes = data.to_vec();
        if let Some(last) = bytes.last_mut() {
            *last &= u8::MAX.checked_shl(u32::from(padding)).unwrap_or(0);
        }
        let new_value = MmsValue::BitString {
            padding,
            data: bytes,
        };
        let byte_len = data.len();
        self.update_with(da, "BitString", |current| {
            let fits = match declared_bit_string_size(da.ty) {
                Some(size @ (StringSize::Fixed(_) | StringSize::Max(_))) => {
                    bit_string_fits(size, byte_len, padding)
                }
                _ => held_bit_string_len(da, current)? == new_bits,
            };
            if !fits {
                return Err(bit_string_mismatch(
                    da,
                    "BitString of the attribute's length",
                    "BitString of another length",
                ));
            }
            Ok(new_value)
        })
    }

    /// Updates a bit-string data attribute of 1 to 32 bits from an integer.
    ///
    /// With `n` the declared size of the attribute, or the bit count it holds
    /// for a type that declares no size, `value` is taken as an `n`-bit
    /// unsigned number written most significant bit first: bit 0 of the string
    /// carries 2^(n-1) and bit n-1 carries 1. A `Dbpos`, a `BIT STRING(2)`,
    /// therefore stores 2 (on) as data `0x80` with padding 6 and 1 (off) as
    /// `0x40` with padding 6; a `Quality` is always written as 13 bits.
    ///
    /// # Errors
    ///
    /// Returns `TypeMismatch` when the attribute does not currently hold a bit
    /// string, when `n` is 0 or above 32, when `value` does not fit in `n`
    /// bits, or, for a type that declares no size, when the bit string it
    /// holds is malformed. The attribute is left unchanged on error.
    pub fn update_bit_string_from_int(&self, da: &DataAttribute, value: u32) -> Result<()> {
        self.update_with(da, "BitString", |current| {
            let n = match declared_bit_string_size(da.ty) {
                Some(StringSize::Fixed(n) | StringSize::Max(n)) => usize::from(n),
                _ => held_bit_string_len(da, current)?,
            };
            if n == 0 || n > 32 {
                return Err(bit_string_mismatch(
                    da,
                    "BitString of 1 to 32 bits",
                    "BitString of 0 or more than 32 bits",
                ));
            }
            if u64::from(value) >> n != 0 {
                return Err(bit_string_mismatch(
                    da,
                    "integer within the attribute's length",
                    "integer wider than the attribute",
                ));
            }
            let byte_len = n.div_ceil(8);
            let padding = byte_len * 8 - n;
            let aligned = u64::from(value) << padding;
            Ok(MmsValue::BitString {
                padding: padding as u8,
                data: aligned
                    .to_be_bytes()
                    .into_iter()
                    .skip(8 - byte_len)
                    .collect(),
            })
        })
    }

    /// Updates every element of an array data attribute from an
    /// `MmsValue::Array`, and raises the report and log triggers of all of
    /// them as one batch.
    ///
    /// `value` holds one element per element of `da`, each a structure of one
    /// member per sub-attribute for an array of a constructed type, down to
    /// leaves that each take a value of the variant they hold. The whole shape
    /// is checked before any element changes. The elements are stored under
    /// the value lock MMS reads take, so a client read sees the update whole
    /// or not at all. Each leaf raises the triggers its trigger options declare
    /// for its change, as an `update_*` call does, and the triggers go out
    /// together: a report control block without a buffer time sends one
    /// report holding every member the update changed. While the data model is
    /// locked the triggers are deferred until it is released.
    ///
    /// One element is updated with the typed `update_*` methods on
    /// [`DataAttribute::element`].
    ///
    /// # Errors
    ///
    /// Returns `TypeMismatch` when `da` is not an array, when `value` is not an
    /// array of its element count, or when an element, a member or a leaf
    /// value does not have the shape or the variant the attribute holds; no
    /// element changes then.
    pub fn update_array(&self, da: &DataAttribute, value: MmsValue) -> Result<()> {
        if !da.is_array() {
            return Err(ServerError::TypeMismatch {
                path: da.name.clone(),
                expected: "array attribute",
                actual: "scalar attribute",
            });
        }
        let mut leaves = Vec::new();
        collect_update_leaves(da, value, &mut leaves)?;
        let triggers = {
            let _values = self
                .inner
                .mms_view
                .as_ref()
                .map(|view| crate::compat::rwlock_write(view.value_lock()));
            let mut triggers = Vec::new();
            for (leaf, new_value) in leaves {
                let mut guard = leaf.value.write().map_err(|_| {
                    ServerError::InvalidModel("DataAttribute value RwLock poisoned".into())
                })?;
                let flag = update_triggers(leaf.trg_ops, &guard, &new_value);
                *guard = new_value.clone();
                // A leaf that raises nothing goes along with no reason, so a
                // member above several elements takes every value of the update.
                triggers.push(PendingTrigger {
                    cell: Arc::clone(&leaf.value),
                    value: new_value,
                    flag,
                });
            }
            triggers
        };
        self.dispatch_triggers(triggers);
        Ok(())
    }

    /// Checks that the attribute currently holds the same variant as the new
    /// value, writes it, and raises the report and log triggers of the update.
    fn update_typed(
        &self,
        da: &DataAttribute,
        new_value: MmsValue,
        expected_name: &'static str,
    ) -> Result<()> {
        self.update_with(da, expected_name, |_| Ok(new_value))
    }

    /// Checks that the attribute currently holds the `expected_name` variant,
    /// writes the value `build` derives from the current one, and raises the
    /// report and log triggers of the update.
    ///
    /// The check and the write happen under one write lock, so the attribute is
    /// unchanged when `build` fails. The triggers are chosen under the same
    /// lock, by comparing the new value with the old one against the trigger
    /// options of the attribute (IEC 61850-7-2 TrgOp, table 21):
    ///
    /// - a changed value raises each of data-change, quality-change and
    ///   data-update the attribute declares in `dchg`, `qchg` and `dupd`;
    /// - an unchanged value raises data-update when the attribute declares
    ///   `dupd`;
    /// - an attribute that declares none of them raises nothing.
    ///
    /// Reports and log entries act on the same triggers, each control block on
    /// those its TrgOps enable. While the data model is locked the triggers are
    /// deferred until it is released.
    fn update_with(
        &self,
        da: &DataAttribute,
        expected_name: &'static str,
        build: impl FnOnce(&MmsValue) -> Result<MmsValue>,
    ) -> Result<()> {
        let trigger = {
            let mut guard = da.value.write().map_err(|_| {
                ServerError::InvalidModel("DataAttribute value RwLock poisoned".into())
            })?;
            let actual_name = mms_value_variant_name(&guard);
            if actual_name != expected_name {
                return Err(ServerError::TypeMismatch {
                    path: da.name.clone(),
                    expected: expected_name,
                    actual: actual_name,
                });
            }
            let new_value = build(&guard)?;
            let flag = update_triggers(da.trg_ops, &guard, &new_value);
            *guard = new_value.clone();
            PendingTrigger {
                cell: Arc::clone(&da.value),
                value: new_value,
                flag,
            }
        };
        // The write lock is released before any trigger is raised.
        if !trigger.flag.has_trigger() {
            return Ok(());
        }
        {
            let mut deferred = self.deferred();
            if deferred.active {
                deferred.merge(trigger);
                return Ok(());
            }
        }
        self.raise_triggers(std::slice::from_ref(&trigger));
        Ok(())
    }

    /// Raises the report and log triggers of the leaves an MMS write request
    /// stored, as one batch, or defers them while the data model is locked.
    /// Each leaf raises the triggers its trigger options declare for the
    /// change from its old value to its new one, as an `update_*` call would.
    ///
    /// A leaf that raises nothing goes along with no reason, so a member
    /// naming a data object or a constructed attribute takes every value the
    /// request wrote rather than one another client wrote in the meantime.
    fn raise_written(&self, leaves: &[WrittenLeaf]) {
        let triggers: Vec<PendingTrigger> = leaves
            .iter()
            .map(|leaf| PendingTrigger {
                cell: Arc::clone(&leaf.value),
                value: leaf.new.clone(),
                flag: update_triggers(leaf.trg_ops, &leaf.old, &leaf.new),
            })
            .collect();
        self.dispatch_triggers(triggers);
    }

    /// Raises `triggers` as one batch, or defers them while the data model is
    /// locked; nothing when none of them raises a reason.
    fn dispatch_triggers(&self, triggers: Vec<PendingTrigger>) {
        if !triggers.iter().any(|t| t.flag.has_trigger()) {
            return;
        }
        {
            let mut deferred = self.deferred();
            if deferred.active {
                for trigger in triggers {
                    deferred.merge(trigger);
                }
                return;
            }
        }
        self.raise_triggers(&triggers);
    }

    /// Raises the log and report triggers of attribute updates.
    ///
    /// Every attribute is looked up in the report indexes before the reporting
    /// engine is locked, and the engine then takes all of them at once. An
    /// update with no reason only lends its value to the members above it.
    fn raise_triggers(&self, triggers: &[PendingTrigger]) {
        self.log_updates(triggers);
        let indexed: Vec<(DataAttributeRef, MmsValue, InclusionFlag)> = {
            let index = self.inner.attr_ref_index.read().ok();
            triggers
                .iter()
                .filter_map(|t| {
                    index
                        .as_ref()
                        .and_then(|g| g.get(&t.key()).cloned())
                        // A member of a data set a control block was bound to
                        // over MMS is in the engine's index only, which is read
                        // without the engine lock.
                        .or_else(|| self.inner.value_index.attr_ref_for(&t.cell))
                        .map(|attr_ref| (attr_ref, t.value.clone(), t.flag))
                })
                .collect()
        };
        let (updates, context): (Vec<_>, Vec<_>) = indexed
            .into_iter()
            .partition(|(_, _, flag)| flag.has_trigger());
        // An attribute in no data set has no index entry, which is the ordinary
        // case and needs no report.
        if updates.is_empty() {
            return;
        }
        let context: Vec<(DataAttributeRef, MmsValue)> =
            context.into_iter().map(|(r, v, _)| (r, v)).collect();
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        match self.inner.reporting_engine.lock() {
            Ok(engine) => engine.on_values_updated_with(&updates, &context, now_ms),
            Err(_) => tracing::warn!(
                updates = updates.len(),
                "the reporting engine lock is poisoned, the update triggered no report"
            ),
        }
    }

    /// Writes the log entry of a batch of attribute updates through every
    /// enabled log control block whose data set holds one of the attributes.
    ///
    /// An attribute is identified by its shared value, which is how a data set
    /// member refers to it. A control block takes an update when its TrgOps
    /// enable at least one reason of it, data-change, quality-change or
    /// data-update, and its DatSet names a registered data set of the domain,
    /// as `<LN>$<name>` or `<LD>/<LN>$<name>`, with a member the attribute is
    /// or lies beneath. It then writes one entry for the whole batch, holding
    /// each member the batch reaches once, in data set order, with the member
    /// reference, the member value and the reason code of the enabled reasons
    /// of the updates beneath it. The value of a member naming a data object
    /// or a constructed attribute is its current structure with the parts of
    /// the updated attributes set to the values written. A control block
    /// registered under several keys writes once.
    fn log_updates(&self, triggers: &[PendingTrigger]) {
        if !triggers.iter().any(|t| t.flag.has_trigger()) {
            return;
        }
        let Some(controls) = self.unique_log_controls() else {
            return;
        };
        // Positions in the batch of the updates of each attribute, keyed by
        // its shared value, so a member finds the updates beneath it by
        // walking its own leaves once.
        let mut by_cell: HashMap<usize, Vec<usize>> = HashMap::with_capacity(triggers.len());
        for (i, t) in triggers.iter().enumerate() {
            by_cell.entry(t.key()).or_default().push(i);
        }
        let mut now_ms: Option<u64> = None;
        for lc in controls {
            let (data_set, trg_ops) = match lc.state.lock() {
                Ok(state) if matches!(state.log_ena, crate::logging::LogState::Enabled) => {
                    match state.data_set.clone() {
                        Some(data_set) => (data_set, state.trg_ops),
                        None => continue,
                    }
                }
                Ok(_) => continue,
                Err(_) => {
                    tracing::warn!(
                        mms_path = %lc.mms_path,
                        "the log control block state is poisoned, the update was not logged"
                    );
                    continue;
                }
            };
            let Some(ds) = self.log_data_set(&lc, data_set) else {
                continue;
            };
            // Each member in data set order, with the updates of the batch
            // beneath it. A member an update with an enabled reason reaches
            // takes every value of the batch beneath it in batch order, the
            // values of updates with no reason included.
            let mut data: Vec<(String, MmsValue, u8)> = Vec::new();
            let mut beneath: Vec<(usize, &str)> = Vec::new();
            for entry in &ds.entries {
                beneath.clear();
                entry.for_each_leaf(|leaf| {
                    let key = Arc::as_ptr(&leaf.value) as usize;
                    if let Some(positions) = by_cell.get(&key) {
                        beneath.extend(positions.iter().map(|&i| (i, leaf.attr_ref.as_str())));
                    }
                });
                let reason_code = beneath.iter().fold(0, |code, &(i, _)| {
                    code | log_reason(triggers[i].flag, trg_ops)
                });
                if reason_code == 0 {
                    continue;
                }
                beneath.sort_unstable_by_key(|&(i, _)| i);
                let mut value = entry.read_value();
                for &(i, leaf_ref) in &beneath {
                    value = entry.value_with(value, leaf_ref, &triggers[i].value);
                }
                let Some(value) = value else {
                    continue;
                };
                data.push((entry.attr_ref.clone(), value, reason_code));
            }
            if data.is_empty() {
                continue;
            }
            let time_ms = *now_ms.get_or_insert_with(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64
            });
            if let Err(e) = lc.write_members(time_ms, &data) {
                tracing::warn!(
                    mms_path = %lc.mms_path,
                    error = %e,
                    "the log storage backend failed, the update was not logged"
                );
            }
        }
    }

    /// Writes the integrity log entries due at `now`.
    ///
    /// An enabled log control block whose TrgOps hold integrity and whose
    /// IntgPd is above zero writes one entry every IntgPd milliseconds, counted
    /// from when it was enabled. The entry holds every member of its data set
    /// with its current value and the integrity reason code. General
    /// interrogation writes no log entry, as IEC 61850-7-2 does not support it
    /// for logging.
    ///
    /// The tick loop of a started server calls this every millisecond, except
    /// while the data model is locked. It is public so an application or a test
    /// can drive it with clock readings of its own; `now_ms` is the time the
    /// entries carry. Returns how many entries were written.
    pub fn tick_log_integrity(&self, now: Instant, now_ms: u64) -> usize {
        let Some(controls) = self.unique_log_controls() else {
            return 0;
        };
        let mut written = 0;
        for lc in controls {
            let Some(data_set) = lc.integrity_due(now) else {
                continue;
            };
            let Some(ds) = self.log_data_set(&lc, data_set) else {
                continue;
            };
            let data: Vec<(String, MmsValue)> = ds
                .entries
                .iter()
                .filter_map(|e| e.read_value().map(|v| (e.attr_ref.clone(), v)))
                .collect();
            if data.is_empty() {
                continue;
            }
            match lc.write_entry(now_ms, &data, LOG_REASON_INTEGRITY) {
                Ok(Some(_)) => written += 1,
                Ok(None) => {}
                Err(e) => tracing::warn!(
                    mms_path = %lc.mms_path,
                    error = %e,
                    "the log storage backend failed, the integrity entry was not logged"
                ),
            }
        }
        written
    }

    /// Returns every registered log control block once, however many keys it
    /// is registered under, or `None` when the registry lock is poisoned.
    fn unique_log_controls(&self) -> Option<Vec<Arc<crate::logging::LogControl>>> {
        let mut controls: Vec<Arc<crate::logging::LogControl>> =
            match self.inner.log_controls.read() {
                Ok(g) => g.values().cloned().collect(),
                Err(_) => {
                    tracing::warn!("the log control registry lock is poisoned, nothing was logged");
                    return None;
                }
            };
        controls.sort_by_key(|lc| Arc::as_ptr(lc) as usize);
        controls.dedup_by_key(|lc| Arc::as_ptr(lc) as usize);
        Some(controls)
    }

    /// Resolves the data set a log control block's DatSet names, in the domain
    /// of the control block unless the name carries one.
    fn log_data_set(
        &self,
        lc: &crate::logging::LogControl,
        data_set: String,
    ) -> Option<Arc<Dataset>> {
        let lcb_domain = lc.mms_path.split_once('/').map(|(d, _)| d)?;
        let key = match data_set.split_once('/') {
            Some((domain, name)) => (domain.to_string(), name.to_string()),
            None => (lcb_domain.to_string(), data_set),
        };
        match self.inner.dataset_registry.read() {
            Ok(g) => g.get(&key).cloned(),
            Err(_) => {
                tracing::warn!("the data set registry lock is poisoned, nothing was logged");
                None
            }
        }
    }

    /// Registers an association once it is established.
    pub(crate) fn add_connection(&self, conn: ClientConnection) {
        if let Ok(mut g) = self.inner.connections.write() {
            g.insert(conn.id(), conn);
        }
    }

    /// Removes an association when it closes.
    pub(crate) fn remove_connection(&self, id: ConnectionId) -> Option<ClientConnection> {
        let conn = self.inner.connections.write().ok()?.remove(&id)?;
        conn.invalidate();
        Some(conn)
    }

    /// Returns the ids of the registered associations.
    #[cfg(test)]
    pub(crate) fn connection_ids(&self) -> Vec<ConnectionId> {
        self.inner
            .connections
            .read()
            .map(|g| g.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Allocates the next connection id.
    pub(crate) fn next_connection_id(&self) -> ConnectionId {
        self.inner.next_connection_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Returns the dispatcher a connection task routes requests through.
    pub(crate) fn dispatcher(&self) -> Arc<dyn MmsServiceDispatcher> {
        self.inner.dispatcher.clone()
    }

    /// Returns the TLS acceptor, if one is configured; the accept loop performs
    /// a handshake only when it is.
    #[cfg(feature = "tls")]
    pub(crate) fn tls_acceptor(&self) -> Option<&TlsAcceptor> {
        self.inner.tls_acceptor.as_ref()
    }

    /// Returns the control object registry, where an application registers its
    /// control objects and their handlers once the server is built.
    ///
    /// The connection tasks also use it to release the selects an association
    /// held when it closes.
    pub fn control_objects(&self) -> Arc<ControlObjectsRegistry> {
        self.inner.control_objects.clone()
    }

    /// Returns the command termination router.
    pub(crate) fn ct_sink(&self) -> Arc<ChannelCommandTermination> {
        self.inner.ct_sink.clone()
    }

    /// Returns the reporting engine, for callers that drive it directly.
    pub fn reporting_engine(&self) -> Arc<Mutex<ReportingEngine>> {
        self.inner.reporting_engine.clone()
    }

    /// Registers an unbuffered report control block and its data set.
    ///
    /// Besides handing both to the engine, this indexes every leaf of the data
    /// set members by the address of its value, so that a later update can
    /// find the attribute reference the engine knows it by, and registers the
    /// data set so that a read by name resolves it. A data set with an empty
    /// name stands for none and is not registered.
    ///
    /// # Errors
    ///
    /// Returns the error of the engine registration.
    pub fn register_urcb(&self, mut rc: ReportControl, ds: Dataset) -> Result<()> {
        // IEC 61850-7-2 §15: an empty report id defaults to the object
        // reference of the control block. Without this the server sends an
        // empty RptID and the client, which matches reports by that reference,
        // finds no handler and drops them. Both the template and the state
        // snapshot taken from it have to be set.
        if rc.rcb.rpt_id.is_empty() {
            rc.rcb.rpt_id = rc.mms_path.clone();
            if let Ok(mut state) = rc.state.lock() {
                state.rpt_id = rc.mms_path.clone();
            }
        }

        // Collected before the engine takes the data set, while these are still
        // the same shared values.
        let index_entries = leaf_index_entries(&ds);

        // The domain comes from the object reference of the control block,
        // `<domain>/<LN>$RP$<rcb>`, and the data set keeps its own name. The
        // copy placed in the registry is a separate data set object sharing the
        // same member values.
        // A control block that names no data set registers none.
        let dataset_key: Option<(String, String)> = rc
            .mms_path
            .split_once('/')
            .filter(|_| !ds.name.is_empty())
            .map(|(domain, _)| (domain.to_string(), ds.name.clone()));
        let dataset_arc = Arc::new(ds.clone());

        self.inner
            .reporting_engine
            .lock()
            .map_err(|_| ServerError::InvalidModel("ReportingEngine Mutex poisoned".into()))?
            .register_rcb(rc, ds)?;

        match self.inner.attr_ref_index.write() {
            Ok(mut g) => {
                for (ptr_key, attr_ref) in index_entries {
                    g.insert(ptr_key, attr_ref);
                }
            }
            Err(_) => {
                tracing::warn!("the attribute index lock is poisoned; updates will trigger no report for this control block");
            }
        }

        if let Some(key) = dataset_key {
            match self.inner.dataset_registry.write() {
                Ok(mut g) => {
                    g.insert(key, dataset_arc);
                }
                Err(_) => {
                    tracing::warn!(
                        "the data set registry lock is poisoned; the data set was not registered"
                    );
                }
            }
        } else if !dataset_arc.name.is_empty() {
            tracing::warn!(
                rcb_path = %dataset_arc.name,
                "the control block reference names no domain; the data set was not registered"
            );
        }

        Ok(())
    }

    /// Registers a buffered report control block and its data set.
    ///
    /// The counterpart of [`IedServer::register_urcb`]: it indexes the data set
    /// members the same way and registers the data set so that a read by name
    /// can resolve it.
    ///
    /// # Errors
    ///
    /// Returns the error of the engine registration.
    pub fn register_brcb(&self, mut brc: BufferedReportControl, ds: Dataset) -> Result<()> {
        // An empty report id defaults to the object reference of the control
        // block, as it does for an unbuffered one.
        if brc.brcb.rpt_id.is_empty() {
            brc.brcb.rpt_id = brc.mms_path.clone();
            if let Ok(mut state) = brc.state.lock() {
                state.rpt_id = brc.mms_path.clone();
            }
        }

        let index_entries = leaf_index_entries(&ds);

        let dataset_key: Option<(String, String)> = brc
            .mms_path
            .split_once('/')
            .filter(|_| !ds.name.is_empty())
            .map(|(domain, _)| (domain.to_string(), ds.name.clone()));
        let dataset_arc = Arc::new(ds.clone());

        self.inner
            .reporting_engine
            .lock()
            .map_err(|_| ServerError::InvalidModel("ReportingEngine Mutex poisoned".into()))?
            .register_brcb_with_dataset(brc, ds)?;

        match self.inner.attr_ref_index.write() {
            Ok(mut g) => {
                for (ptr_key, attr_ref) in index_entries {
                    g.insert(ptr_key, attr_ref);
                }
            }
            Err(_) => {
                tracing::warn!("the attribute index lock is poisoned; updates will trigger no report for this control block");
            }
        }

        if let Some(key) = dataset_key {
            match self.inner.dataset_registry.write() {
                Ok(mut g) => {
                    g.insert(key, dataset_arc);
                }
                Err(_) => {
                    tracing::warn!(
                        "the data set registry lock is poisoned; the data set was not registered"
                    );
                }
            }
        } else if !dataset_arc.name.is_empty() {
            tracing::warn!(
                rcb_path = %dataset_arc.name,
                "the control block reference names no domain; the data set was not registered"
            );
        }

        Ok(())
    }

    /// Returns the GOOSE control block registry, which the dispatcher shares,
    /// so a block registered at run time is served immediately.
    pub fn gocb_registry(&self) -> Arc<crate::goose_mapping::GoCBRegistry> {
        self.inner.gocb_registry.clone()
    }

    /// Registers a GOOSE control block.
    ///
    /// Call this after the server is built and before it is started. The
    /// dispatcher shares the registry, so the block is served as soon as it is
    /// registered. Registering twice under one name replaces the earlier block
    /// and logs a warning.
    pub fn register_gocb(&self, handle: Arc<crate::goose_mapping::GoCBHandle>) {
        let inserted = self.inner.gocb_registry.register(handle);
        if !inserted {
            tracing::warn!("a GOOSE control block was already registered under this name and has been replaced");
        }
    }

    /// Registers a data set that no report control block refers to, so that a
    /// client can still read it by name.
    ///
    /// `domain` is the MMS domain, such as `"simpleIOGenericIO"`; the data set
    /// keeps its own `<LN>$<name>` form. A name without the owning logical node
    /// is registered as given but logs a warning: GetNameList reports it
    /// verbatim, and a client that splits `<LN>$<name>` then drops it, so the
    /// data set is invisible to a browsing client.
    pub fn register_dataset(&self, domain: impl Into<String>, ds: Dataset) {
        if !ds.name.contains('$') {
            tracing::warn!(
                dataset = %ds.name,
                "register_dataset: the name carries no `<LN>$` prefix, so a browsing client will not see this data set"
            );
        }
        let key = (domain.into(), ds.name.clone());
        match self.inner.dataset_registry.write() {
            Ok(mut g) => {
                g.insert(key, Arc::new(ds));
            }
            Err(_) => {
                tracing::warn!(
                    "the data set registry lock is poisoned; the data set was not registered"
                );
            }
        }
    }

    /// Returns how many data sets were created at run time. A data set
    /// registered by the application is not counted.
    pub fn dynamic_dataset_count(&self) -> usize {
        self.inner
            .dynamic_dataset_keys
            .lock()
            .map(|g| g.len())
            .unwrap_or(0)
    }

    /// Registers a log control block under its MMS domain, such as
    /// `"IED1LD0"`, and its path within the domain, such as
    /// `"MMXU1$LG$lcb01"`.
    ///
    /// A ReadJournal request names the journal by the LogRef of the control
    /// block, such as `"IED1LD0/MMXU1$GeneralLog"`, never by the key it is
    /// registered under.
    pub fn register_log_control(
        &self,
        domain: impl Into<String>,
        item: impl Into<String>,
        lc: Arc<crate::logging::LogControl>,
    ) {
        let key = (domain.into(), item.into());
        match self.inner.log_controls.write() {
            Ok(mut g) => {
                g.insert(key, lc);
            }
            Err(_) => {
                tracing::warn!("the log control registry lock is poisoned; the control block was not registered");
            }
        }
    }

    /// Returns the log control registry.
    pub fn log_controls(&self) -> crate::logging::LogControlRegistry {
        Arc::clone(&self.inner.log_controls)
    }

    /// Returns the data set registry.
    ///
    /// The dispatcher holds the same registry, so the Read and Write services
    /// resolve a data set through it rather than through this method.
    pub(crate) fn dataset_registry(&self) -> crate::reporting::DatasetRegistry {
        Arc::clone(&self.inner.dataset_registry)
    }

    /// Returns the report router.
    pub(crate) fn report_sink(&self) -> Arc<ChannelReportSink> {
        self.inner.report_sink.clone()
    }

    /// Returns the handler registry, for a caller that needs to inspect it;
    /// installing a handler goes through the methods below.
    pub fn handler_registry(&self) -> Arc<HandlerRegistry> {
        self.inner.handler_registry.clone()
    }

    /// Installs a read handler for an attribute path.
    ///
    /// The path is canonicalized first, so a `.` separator and a lower-case
    /// functional constraint are accepted. Installing twice on one path
    /// replaces the earlier handler and logs a warning.
    ///
    /// # Errors
    ///
    /// Returns `InvalidModel` for a malformed path.
    pub fn install_read_handler(&self, path: &str, handler: Arc<dyn ReadHandler>) -> Result<()> {
        self.inner
            .handler_registry
            .install_read_handler(path, handler)
    }

    /// Installs a write access handler for an attribute path.
    ///
    /// A write is classified by functional constraint, type-checked, and put
    /// through the write access policy before the handler is consulted, so the
    /// handler never sees a value the server would have refused on its own.
    ///
    /// # Errors
    ///
    /// Returns `InvalidModel` for a malformed path.
    pub fn install_write_access_handler(
        &self,
        path: &str,
        handler: Arc<dyn AttributeAccessHandler>,
    ) -> Result<()> {
        self.inner
            .handler_registry
            .install_write_access_handler(path, handler)
    }

    /// Enables or disables the read handler bypass.
    ///
    /// While enabled, the Read service consults no read handler and answers
    /// from the model. A path that does not exist still answers
    /// object-non-existent.
    pub fn set_ignore_read_access(&self, on: bool) {
        self.inner.handler_registry.set_ignore_read_access(on);
    }

    /// Sets the running flag, which the accept loop does when it starts.
    pub(crate) fn set_running(&self, on: bool) {
        self.inner.running.store(on, Ordering::SeqCst);
    }

    /// Takes one of the `max_mms_connections` slots for an accepted socket, or
    /// returns `None` when every slot is taken. The slot is given back when the
    /// returned guard drops.
    pub(crate) fn try_acquire_connection_slot(&self) -> Option<ConnectionSlot> {
        let max = self.inner.config.max_mms_connections;
        let open = &self.inner.open_sockets;
        let mut n = open.load(Ordering::SeqCst);
        loop {
            if n >= max {
                return None;
            }
            match open.compare_exchange_weak(n, n + 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => break,
                Err(current) => n = current,
            }
        }
        Some(ConnectionSlot {
            server: self.clone(),
        })
    }

    /// Returns how many accepted sockets hold a connection slot.
    pub(crate) fn open_socket_count(&self) -> usize {
        self.inner.open_sockets.load(Ordering::SeqCst)
    }

    /// Returns the configured start-up settings.
    pub(crate) fn config(&self) -> &IedServerConfig {
        &self.inner.config
    }

    // ── Setting groups ──────────────────────────────────────────────────

    /// Returns the setting group registry.
    pub fn setting_groups(&self) -> Arc<crate::setting_groups::SettingGroupRegistry> {
        self.inner.setting_groups.clone()
    }

    /// Installs the setting group callbacks for one logical device.
    ///
    /// `domain` is the MMS domain name. One trait supplies all three callbacks;
    /// the default implementations allow every operation and store nothing.
    ///
    /// # Errors
    ///
    /// Returns `InvalidModel` when the domain declares no setting group control
    /// block.
    pub fn register_setting_group_handler(
        &self,
        domain: &str,
        handler: Arc<dyn crate::setting_groups::SettingGroupHandler>,
    ) -> Result<()> {
        let rt = self.inner.setting_groups.lookup(domain).ok_or_else(|| {
            ServerError::InvalidModel(format!(
                "domain '{}' declares no setting group control block on its LLN0",
                domain
            ))
        })?;
        rt.install_handler(handler);
        Ok(())
    }

    /// Changes the active setting group of a logical device without consulting
    /// the callbacks, as an application does at start-up or when restoring
    /// stored state, and loads the values of the group into the FC=SG data
    /// attributes. A client write goes through the callbacks instead.
    ///
    /// # Errors
    ///
    /// Returns `InvalidModel` when the domain declares no setting group control
    /// block or the group is out of range.
    pub fn force_active_setting_group(&self, domain: &str, sg: u8) -> Result<()> {
        let rt = self.inner.setting_groups.lookup(domain).ok_or_else(|| {
            ServerError::InvalidModel(format!(
                "domain '{}' declares no setting group control block",
                domain
            ))
        })?;
        rt.force_active_sg(sg).map_err(|e| {
            ServerError::InvalidModel(format!("setting group {} is out of range: {:?}", sg, e))
        })
    }

    /// Writes the selection state of a control object to the `stSeld` of its
    /// data object, under FC=ST or, for an analogue or binary step control,
    /// FC=MX (IEC 61850-7-3), when the model declares one.
    fn update_st_seld(&self, object: &crate::control::ControlObjectConfig, selected: bool) {
        let st_seld = self
            .inner
            .model
            .ld_by_domain(&object.domain)
            .and_then(|ld| ld.ln_by_name(&object.ln_name))
            .and_then(|ln| ln.do_by_name(&object.name))
            .and_then(|dobj| match dobj.child_by_name("stSeld", None) {
                Some(iec61850_model::DoChild::Da(da)) => Some(da),
                _ => None,
            });
        let Some(da) = st_seld else {
            return;
        };
        if let Err(e) = self.update_boolean(da, selected) {
            tracing::warn!(
                domain = %object.domain,
                ln = %object.ln_name,
                data_object = %object.name,
                error = %e,
                "stSeld is not a boolean and was not updated"
            );
        }
    }

    /// Writes `value`, of whatever variant the attribute holds, through the
    /// update path, so it triggers reports and log entries as an `update_*`
    /// call does; for values the server itself loads.
    fn update_value(&self, da: &DataAttribute, value: MmsValue) -> Result<()> {
        let expected = mms_value_variant_name(&value);
        self.update_with(da, expected, |_| Ok(value))
    }
}

/// Log reason code of a data change: bit 1 of ReasonForInclusionInLog.
const LOG_REASON_DATA_CHANGE: u8 = 0x02;

/// Log reason code of a quality change: bit 2 of ReasonForInclusionInLog.
const LOG_REASON_QUALITY_CHANGE: u8 = 0x04;

/// Log reason code of a data update: bit 3 of ReasonForInclusionInLog.
const LOG_REASON_DATA_UPDATE: u8 = 0x08;

/// Log reason code of an integrity entry: bit 4 of ReasonForInclusionInLog.
const LOG_REASON_INTEGRITY: u8 = 0x10;

/// Returns the log reason code of the reasons of `flag` that `trg_ops` enable,
/// with the bits of ReasonForInclusionInLog (IEC 61850-8-1 table 39).
fn log_reason(flag: InclusionFlag, trg_ops: TriggerOptions) -> u8 {
    let mut code = 0;
    for (reason, trigger, bit) in [
        (
            InclusionFlag::VALUE_CHANGED,
            TriggerOptions::DATA_CHANGED,
            LOG_REASON_DATA_CHANGE,
        ),
        (
            InclusionFlag::QUALITY_CHANGED,
            TriggerOptions::QUALITY_CHANGED,
            LOG_REASON_QUALITY_CHANGE,
        ),
        (
            InclusionFlag::VALUE_UPDATE,
            TriggerOptions::DATA_UPDATE,
            LOG_REASON_DATA_UPDATE,
        ),
    ] {
        if flag.contains(reason) && trg_ops.contains(trigger) {
            code |= bit;
        }
    }
    code
}

/// Chooses the reasons for inclusion an update raises, from whether it
/// changes the value and from the trigger options the attribute declares.
///
/// An attribute raises only the triggers it declares (IEC 61850-7-2 TrgOp,
/// table 21): a changed value raises data-change for `dchg`, quality-change
/// for `qchg` and data-update for `dupd`; an unchanged value raises
/// data-update for `dupd` and nothing else.
fn update_triggers(trg_ops: TrgOps, old: &MmsValue, new: &MmsValue) -> InclusionFlag {
    let declared = |trg: TrgOps, flag: InclusionFlag| {
        if trg_ops.contains(trg) {
            flag
        } else {
            InclusionFlag::NONE
        }
    };
    let update = declared(TrgOps::DUPD, InclusionFlag::VALUE_UPDATE);
    if same_value(old, new) {
        return update;
    }
    declared(TrgOps::DCHG, InclusionFlag::VALUE_CHANGED)
        .union(declared(TrgOps::QCHG, InclusionFlag::QUALITY_CHANGED))
        .union(update)
}

/// Compares two values as they are encoded, so a floating-point value equals
/// one with the same bits, NaN included.
fn same_value(a: &MmsValue, b: &MmsValue) -> bool {
    match (a, b) {
        (MmsValue::Float32(x), MmsValue::Float32(y)) => x.to_bits() == y.to_bits(),
        (MmsValue::Float64(x), MmsValue::Float64(y)) => x.to_bits() == y.to_bits(),
        _ => a == b,
    }
}

/// The address of the value of every leaf of the members of `ds`, with the
/// attribute reference the reporting engine knows the leaf by.
fn leaf_index_entries(ds: &Dataset) -> Vec<(usize, DataAttributeRef)> {
    ds.entries
        .iter()
        .flat_map(|e| e.leaves())
        .map(|leaf| (Arc::as_ptr(&leaf.value) as usize, leaf.attr_ref.clone()))
        .collect()
}

/// Pairs each leaf of `da` with its part of `value`, an array of one element
/// per element of `da`, a structure of one member per sub-attribute of a
/// constructed node, and a value of the variant a leaf holds.
fn collect_update_leaves<'a>(
    da: &'a DataAttribute,
    value: MmsValue,
    out: &mut Vec<(&'a DataAttribute, MmsValue)>,
) -> Result<()> {
    if da.is_leaf() {
        let held = mms_value_variant_name(&da.snapshot());
        let given = mms_value_variant_name(&value);
        if held != given {
            return Err(ServerError::TypeMismatch {
                path: da.name.clone(),
                expected: held,
                actual: given,
            });
        }
        out.push((da, value));
        return Ok(());
    }
    let (expected, members) = match value {
        MmsValue::Array(members) if da.is_array() => ("Array", members),
        MmsValue::Structure(members) if !da.is_array() => ("Structure", members),
        other => {
            return Err(ServerError::TypeMismatch {
                path: da.name.clone(),
                expected: if da.is_array() { "Array" } else { "Structure" },
                actual: mms_value_variant_name(&other),
            })
        }
    };
    if members.len() != da.children.len() {
        return Err(ServerError::TypeMismatch {
            path: da.name.clone(),
            expected,
            actual: "another member count",
        });
    }
    for (child, member) in da.children.iter().zip(members) {
        collect_update_leaves(child, member, out)?;
    }
    Ok(())
}

/// An attribute update whose report and log triggers are still to be raised.
/// One with no reason carries only its value, for the members above it.
struct PendingTrigger {
    /// The shared value of the attribute, which identifies it.
    cell: Arc<RwLock<MmsValue>>,
    /// The value the update wrote.
    value: MmsValue,
    /// The reasons for inclusion the update raised.
    flag: InclusionFlag,
}

impl PendingTrigger {
    /// Identifies the attribute by the address of its shared value.
    fn key(&self) -> usize {
        Arc::as_ptr(&self.cell) as usize
    }
}

/// The triggers deferred while the data model is locked, in the order their
/// attributes were first updated.
#[derive(Default)]
struct DeferredTriggers {
    /// Whether the data model is locked, so a new trigger is deferred.
    active: bool,
    triggers: Vec<PendingTrigger>,
    /// Position in `triggers` of each attribute, by the address of its value.
    index: HashMap<usize, usize>,
}

impl DeferredTriggers {
    /// Adds a trigger; a later update of an attribute already held replaces
    /// its value and adds its reasons.
    fn merge(&mut self, trigger: PendingTrigger) {
        match self.index.get(&trigger.key()) {
            Some(&i) => {
                let held = &mut self.triggers[i];
                held.value = trigger.value;
                held.flag = held.flag.union(trigger.flag);
            }
            None => {
                self.index.insert(trigger.key(), self.triggers.len());
                self.triggers.push(trigger);
            }
        }
    }

    /// Ends the deferral and takes the deferred triggers.
    fn release(&mut self) -> Vec<PendingTrigger> {
        self.active = false;
        self.index.clear();
        std::mem::take(&mut self.triggers)
    }
}

/// Returns the bit count of the bit string an attribute currently holds.
fn held_bit_string_len(da: &DataAttribute, current: &MmsValue) -> Result<usize> {
    let held = match current {
        MmsValue::BitString { padding, data } => bit_string_len(data.len(), *padding),
        _ => None,
    };
    held.ok_or_else(|| bit_string_mismatch(da, "well-formed BitString", "malformed BitString"))
}

/// Builds the `TypeMismatch` a rejected bit-string update returns.
fn bit_string_mismatch(
    da: &DataAttribute,
    expected: &'static str,
    actual: &'static str,
) -> ServerError {
    ServerError::TypeMismatch {
        path: da.name.clone(),
        expected,
        actual,
    }
}

/// Names the variant of a value, for a type-mismatch message.
fn mms_value_variant_name(v: &iec61850_model::MmsValue) -> &'static str {
    use iec61850_model::MmsValue;
    match v {
        MmsValue::Boolean(_) => "Boolean",
        MmsValue::Integer(_) => "Integer",
        MmsValue::Unsigned(_) => "Unsigned",
        MmsValue::Float32(_) => "Float32",
        MmsValue::Float64(_) => "Float64",
        MmsValue::BitString { .. } => "BitString",
        MmsValue::OctetString(_) => "OctetString",
        MmsValue::VisibleString(_) => "VisibleString",
        MmsValue::MmsString(_) => "MmsString",
        MmsValue::UtcTime(_) => "UtcTime",
        MmsValue::BinaryTime(_) => "BinaryTime",
        MmsValue::Structure(_) => "Structure",
        MmsValue::Array(_) => "Array",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Data model lock guard
// ─────────────────────────────────────────────────────────────────────────────

/// Holds the data model lock; dropping it raises the deferred triggers and
/// releases the lock.
pub struct DataModelGuard<'a> {
    server: &'a IedServer,
    // Dropped in declaration order: the periodic triggers resume before the
    // mutex is released.
    _gate: RwLockWriteGuard<'a, ()>,
    _guard: MutexGuard<'a, ()>,
}

impl<'a> std::fmt::Debug for DataModelGuard<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataModelGuard")
            .field("server", &self.server)
            .finish()
    }
}

impl<'a> Drop for DataModelGuard<'a> {
    fn drop(&mut self) {
        // The deferred triggers are raised before the flag is cleared, so an
        // observer that sees the model unlocked also sees the batch delivered.
        self.server.release_deferred();
        self.server
            .inner
            .is_model_locked
            .store(false, Ordering::SeqCst);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Type-state builder
// ─────────────────────────────────────────────────────────────────────────────

/// Marks a builder that has no model yet.
#[derive(Debug)]
pub struct NoModel;
/// Marks a builder that has a model but no bind address yet.
#[derive(Debug)]
pub struct HasModel;
/// Marks a builder that has both a model and a bind address, and can be built.
#[derive(Debug)]
pub struct Bound;

/// Builds an [`IedServer`], tracking through `S` which settings are already
/// supplied so that `build` is reachable only once the model and bind address
/// are both present.
pub struct IedServerBuilder<S> {
    model: Option<Arc<IedModel>>,
    config: IedServerConfig,
    bind_addr: Option<SocketAddr>,
    dispatcher: Option<Arc<dyn MmsServiceDispatcher>>,
    /// With an acceptor set, the accept loop performs a TLS handshake before
    /// the connection task starts.
    #[cfg(feature = "tls")]
    tls_acceptor: Option<TlsAcceptor>,
    _state: PhantomData<S>,
}

impl<S> std::fmt::Debug for IedServerBuilder<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IedServerBuilder")
            .field("model_set", &self.model.is_some())
            .field("config", &self.config)
            .field("bind_addr", &self.bind_addr)
            .field("dispatcher_set", &self.dispatcher.is_some())
            .finish()
    }
}

impl IedServerBuilder<NoModel> {
    /// Supplies the model.
    pub fn model(self, model: Arc<IedModel>) -> IedServerBuilder<HasModel> {
        IedServerBuilder {
            model: Some(model),
            config: self.config,
            bind_addr: self.bind_addr,
            dispatcher: self.dispatcher,
            #[cfg(feature = "tls")]
            tls_acceptor: self.tls_acceptor,
            _state: PhantomData,
        }
    }
}

impl IedServerBuilder<HasModel> {
    /// Supplies the address to listen on.
    pub fn bind(self, addr: impl Into<SocketAddr>) -> IedServerBuilder<Bound> {
        IedServerBuilder {
            model: self.model,
            config: self.config,
            bind_addr: Some(addr.into()),
            dispatcher: self.dispatcher,
            #[cfg(feature = "tls")]
            tls_acceptor: self.tls_acceptor,
            _state: PhantomData,
        }
    }
}

impl<S> IedServerBuilder<S> {
    /// Supplies the start-up settings.
    pub fn config(mut self, config: IedServerConfig) -> Self {
        self.config = config;
        self
    }

    /// Supplies a dispatcher, replacing the model-backed one the builder would
    /// otherwise construct.
    pub fn dispatcher(mut self, d: Arc<dyn MmsServiceDispatcher>) -> Self {
        self.dispatcher = Some(d);
        self
    }
}

/// The TLS builder method exists only when the `tls` feature is enabled.
#[cfg(feature = "tls")]
impl<S> IedServerBuilder<S> {
    /// Serves TLS instead of plain TCP.
    ///
    /// The accept loop completes the handshake before handing the stream to the
    /// COTP layer. Without this call the server serves plain TCP.
    pub fn with_tls(mut self, acceptor: TlsAcceptor) -> Self {
        self.tls_acceptor = Some(acceptor);
        self
    }
}

impl IedServerBuilder<Bound> {
    /// Builds the server.
    ///
    /// Without a dispatcher of its own the builder constructs a model-backed
    /// one, so the server serves requests as soon as it starts.
    ///
    /// That dispatcher holds the write access policy as it stood when the
    /// server was built. A later `set_write_access_policy` changes what
    /// [`IedServer::write_access_allowed`] reports but not what the Write
    /// service enforces, so set every policy before starting the server.
    ///
    /// # Errors
    ///
    /// Returns the error of the model-to-MMS mapping, such as a domain name
    /// that is too long or duplicated.
    pub fn build(self) -> Result<IedServer> {
        // The type state guarantees both are present.
        let model = self
            .model
            .expect("type-state guarantees model is set in HasModel phase");
        let bind_addr = self
            .bind_addr
            .expect("type-state guarantees bind_addr is set in Bound phase");

        let write_access_policies = self.config.write_access_policies;

        // Every registry below is created even when the caller supplied its own
        // dispatcher; in that case the caller is responsible for wiring them in,
        // while the model-backed dispatcher takes them from here.
        let ct_sink: Arc<ChannelCommandTermination> = Arc::new(ChannelCommandTermination::new());
        let control_objects: Arc<ControlObjectsRegistry> =
            Arc::new(ControlObjectsRegistry::with_sink(
                ct_sink.clone() as Arc<dyn crate::control::CommandTerminationSink>
            ));

        // The report sink is bounded, so a slow reader gives the engine
        // backpressure rather than an unbounded queue.
        let report_sink: Arc<ChannelReportSink> = Arc::new(ChannelReportSink::new());
        let dataset_registry: crate::reporting::DatasetRegistry =
            Arc::new(RwLock::new(HashMap::new()));
        // DatSet writes resolve against the same registry the dispatcher serves.
        let engine =
            ReportingEngine::new_with_channel_sink(report_sink.clone(), dataset_registry.clone());
        let value_index = engine.value_index();
        let reporting_engine: Arc<Mutex<ReportingEngine>> = Arc::new(Mutex::new(engine));

        let handler_registry: Arc<HandlerRegistry> = Arc::new(HandlerRegistry::new());

        let log_controls: crate::logging::LogControlRegistry =
            crate::logging::new_log_control_registry();

        // Projected from the setting group control blocks the model declares.
        let setting_groups: Arc<crate::setting_groups::SettingGroupRegistry> = Arc::new(
            crate::setting_groups::SettingGroupRegistry::from_model(&model)
                .with_time_quality(self.config.time_quality),
        );

        let dynamic_dataset_keys: crate::service::define_named_variable_list::DynamicDatasetKeys =
            crate::service::define_named_variable_list::new_dynamic_dataset_keys();
        let dynamic_dataset_quota = Arc::new(
            crate::service::define_named_variable_list::DynamicDatasetQuota::new(
                self.config.max_dynamic_datasets,
                self.config.max_dynamic_datasets_per_association,
            ),
        );

        // A GoCB DatSet write checks its data set against the registry the
        // dispatcher serves.
        let gocb_data_sets = dataset_registry.clone();
        let gocb_registry: Arc<crate::goose_mapping::GoCBRegistry> = Arc::new(
            crate::goose_mapping::GoCBRegistry::with_edition(self.config.edition)
                .with_data_set_lookup(Arc::new(move |domain: &str, name: &str| {
                    gocb_data_sets
                        .read()
                        .map(|sets| sets.contains_key(&(domain.to_string(), name.to_string())))
                        .unwrap_or(false)
                })),
        );

        // The MMS view of a dispatcher the builder makes hands the leaves each
        // write stores back to the server, which raises their triggers.
        let mut written_view: Option<Arc<MmsDeviceModel>> = None;
        let dispatcher: Arc<dyn MmsServiceDispatcher> = match self.dispatcher {
            Some(d) => d,
            None => {
                let mms_model = Arc::new(MmsDeviceModel::from_ied_model(&model)?);
                written_view = Some(Arc::clone(&mms_model));
                let ident = crate::service::IdentificationStrings {
                    vendor_name: self.config.vendor_name.clone().unwrap_or_else(|| {
                        crate::service::IdentificationStrings::DEFAULT_VENDOR.into()
                    }),
                    model_name: self.config.model_name.clone().unwrap_or_else(|| {
                        crate::service::IdentificationStrings::DEFAULT_MODEL.into()
                    }),
                    revision: self.config.revision.clone().unwrap_or_else(|| {
                        crate::service::IdentificationStrings::DEFAULT_REVISION.into()
                    }),
                };
                let dispatcher = MmsModelDispatcher::with_identification(
                    model.clone(),
                    mms_model,
                    Arc::new(write_access_policies),
                    Arc::new(ident),
                )
                .with_control_objects(control_objects.clone())
                .with_reporting_engine(reporting_engine.clone())
                .with_handler_registry(handler_registry.clone())
                .with_dataset_registry(dataset_registry.clone())
                .with_log_controls(log_controls.clone())
                .with_setting_groups(setting_groups.clone())
                .with_dynamic_dataset_keys(dynamic_dataset_keys.clone())
                .with_dynamic_dataset_quota(dynamic_dataset_quota)
                .with_gocb_registry(gocb_registry.clone());
                Arc::new(dispatcher)
            }
        };

        let server = IedServer {
            inner: Arc::new(IedServerInner {
                model,
                mms_view: written_view.clone(),
                config: self.config,
                bind_addr,
                connections: RwLock::new(HashMap::new()),
                open_sockets: AtomicUsize::new(0),
                next_connection_id: AtomicU64::new(1),
                write_access_policies: RwLock::new(write_access_policies),
                running: AtomicBool::new(false),
                data_model_lock_guard: Mutex::new(()),
                is_model_locked: AtomicBool::new(false),
                deferred: Mutex::new(DeferredTriggers::default()),
                batch_gate: RwLock::new(()),
                dispatcher,
                connection_block_requests_default: AtomicBool::new(false),
                control_objects,
                ct_sink,
                reporting_engine,
                value_index,
                attr_ref_index: RwLock::new(HashMap::new()),
                dataset_registry,
                report_sink,
                handler_registry,
                log_controls,
                setting_groups,
                dynamic_dataset_keys,
                #[cfg(feature = "tls")]
                tls_acceptor: self.tls_acceptor,
                gocb_registry,
            }),
        };
        server.install_value_hooks();
        if let Some(mms_model) = written_view {
            let sink: Arc<dyn WrittenLeaves> = server.inner.clone();
            mms_model.set_written_leaves(Arc::downgrade(&sink));
        }
        Ok(server)
    }
}

impl IedServer {
    /// Routes the values the server writes on its own, the setting group
    /// values and the `stSeld` of the control objects, through the update
    /// path. The hooks hold the server weakly, so they do not keep it alive.
    fn install_value_hooks(&self) {
        let weak = Arc::downgrade(&self.inner);
        self.inner.control_objects.set_selection_observer(Arc::new(
            move |object: &crate::control::ControlObjectConfig, selected: bool| {
                if let Some(inner) = weak.upgrade() {
                    (IedServer { inner }).update_st_seld(object, selected);
                }
            },
        ));
        let weak = Arc::downgrade(&self.inner);
        self.inner.setting_groups.set_writer(Arc::new(
            move |da: &DataAttribute, value: MmsValue| {
                let Some(inner) = weak.upgrade() else {
                    da.store(value);
                    return;
                };
                if let Err(e) = (IedServer { inner }).update_value(da, value) {
                    tracing::warn!(
                        attribute = %da.name,
                        error = %e,
                        "a setting group value does not fit its attribute and was not written"
                    );
                }
            },
        ));
    }
}

impl WrittenLeaves for IedServerInner {
    fn leaves_written(self: Arc<Self>, leaves: &[WrittenLeaf]) {
        IedServer { inner: self }.raise_written(leaves);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use iec61850_model::{IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder, FC};

    fn minimal_model() -> Arc<IedModel> {
        // The smallest model that builds: one logical device with one LLN0.
        let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(lln0)
            .build()
            .expect("ld");
        let model = IedModelBuilder::new("TEST")
            .add_ld(ld)
            .expect("add_ld")
            .build()
            .expect("minimal model build");
        Arc::new(model)
    }

    fn test_server() -> IedServer {
        IedServer::builder()
            .model(minimal_model())
            .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .build()
            .expect("test server build")
    }

    #[test]
    fn builder_type_state_compiles() {
        let _server = test_server();
    }

    /// An array update stores every element under the value lock: while one
    /// element is held, the elements before it are stored and no read can take
    /// the lock, so none sees part of the update.
    #[test]
    fn array_update_stores_every_element_under_the_value_lock() {
        use iec61850_model::{DataAttribute, DataAttributeType, DataObjectBuilder, DoChild};
        let element = DataAttribute::new(
            "vals",
            FC::Sp,
            DataAttributeType::Int32,
            TrgOps::NONE,
            MmsValue::Integer(0),
        );
        let arr = DataObjectBuilder::scalar("Arr")
            .add_da_node(DataAttribute::array(element, 2).expect("array"))
            .build()
            .expect("data object");
        let ggio = LogicalNodeBuilder::new("", "GGIO", "1")
            .add_do(arr)
            .build()
            .expect("ggio");
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(LogicalNodeBuilder::lln0().build().expect("lln0"))
            .add_ln(ggio)
            .build()
            .expect("ld");
        let model = Arc::new(
            IedModelBuilder::new("TEST")
                .add_ld(ld)
                .expect("add_ld")
                .build()
                .expect("model"),
        );
        let server = IedServer::builder()
            .model(Arc::clone(&model))
            .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .build()
            .expect("server");
        let vals = || match model.lds[0].lns[1].dos[0].child_by_name("vals", None) {
            Some(DoChild::Da(da)) => da,
            _ => panic!("vals is an attribute"),
        };
        let view = server
            .inner
            .mms_view
            .clone()
            .expect("the built-in dispatcher");
        let hold = vals().element(1).expect("element 1").value.read().unwrap();

        let writer = std::thread::spawn({
            let server = server.clone();
            let model = Arc::clone(&model);
            move || {
                let Some(DoChild::Da(vals)) =
                    model.lds[0].lns[1].dos[0].child_by_name("vals", None)
                else {
                    panic!("vals is an attribute");
                };
                server.update_array(
                    vals,
                    MmsValue::Array(vec![MmsValue::Integer(1), MmsValue::Integer(2)]),
                )
            }
        });

        let deadline = Instant::now() + std::time::Duration::from_secs(30);
        while vals().element(0).expect("element 0").snapshot() != MmsValue::Integer(1) {
            assert!(
                Instant::now() < deadline,
                "the first element is never stored"
            );
            std::thread::yield_now();
        }
        assert!(
            view.value_lock().try_read().is_err(),
            "the update holds the value lock across its elements"
        );

        drop(hold);
        writer.join().unwrap().expect("update_array");
        assert!(view.value_lock().try_read().is_ok());
        assert_eq!(
            vals().snapshot(),
            MmsValue::Array(vec![MmsValue::Integer(1), MmsValue::Integer(2)])
        );
    }

    // ── Buffered report control block registration ──────────────────────

    fn make_brcb_with_one_entry(
        mms_path: &str,
        ds_name: &str,
    ) -> (
        crate::reporting::BufferedReportControl,
        crate::reporting::Dataset,
    ) {
        use crate::reporting::{Brcb, BufferedReportControl, Dataset, DatasetEntry};
        use iec61850_model::MmsValue;
        use std::sync::RwLock as StdRwLock;

        let brc = BufferedReportControl::new(mms_path, Brcb::new("brcb01", ds_name));
        let value = Arc::new(StdRwLock::new(MmsValue::Boolean(false)));
        let entry = DatasetEntry::new("LD0/LLN0$ST$Beh$stVal", value);
        let mut ds = Dataset::new(ds_name);
        ds.entries.push(entry);
        (brc, ds)
    }

    #[test]
    fn register_brcb_happy_path_returns_ok() {
        let server = test_server();
        let (brc, ds) = make_brcb_with_one_entry("IED1LD0/LLN0$BR$brcb01", "LLN0$ds1");
        server
            .register_brcb(brc, ds)
            .expect("registration must succeed");
    }

    #[test]
    fn register_brcb_duplicate_path_errs() {
        let server = test_server();
        let (brc1, ds1) = make_brcb_with_one_entry("IED1LD0/LLN0$BR$brcb01", "LLN0$ds1");
        server
            .register_brcb(brc1, ds1)
            .expect("the first registration must succeed");

        let (brc2, ds2) = make_brcb_with_one_entry("IED1LD0/LLN0$BR$brcb01", "LLN0$ds2");
        let err = server
            .register_brcb(brc2, ds2)
            .expect_err("registering the same object reference twice must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("already registered"),
            "the error must name the duplicate: {msg}"
        );
    }

    // ── Setting groups ──────────────────────────────────────────────────

    fn model_with_sgcb() -> Arc<IedModel> {
        use iec61850_model::SettingGroupControlBlock;
        let lln0 = LogicalNodeBuilder::lln0()
            .set_sgcb({
                let mut sgcb = SettingGroupControlBlock::default();
                sgcb.num_of_sg = 3;
                sgcb.act_sg = 1;
                sgcb.has_resv_tms = true;
                sgcb.default_resv_tms_s = 30;
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
        Arc::new(model)
    }

    fn server_with_sgcb() -> IedServer {
        IedServer::builder()
            .model(model_with_sgcb())
            .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .build()
            .unwrap()
    }

    #[test]
    fn build_populates_setting_groups_from_model() {
        let server = server_with_sgcb();
        let reg = server.setting_groups();
        assert_eq!(reg.len(), 1);
        let rt = reg.lookup("IED1LD0").expect("SGCB on IED1LD0");
        assert_eq!(rt.num_of_sg, 3);
        let snap = rt.snapshot();
        assert_eq!(snap.act_sg, 1);
        assert_eq!(snap.resv_tms_s, Some(30));
    }

    #[test]
    fn register_setting_group_handler_unknown_domain_errs() {
        let server = server_with_sgcb();
        let r = server.register_setting_group_handler(
            "WRONG",
            Arc::new(crate::setting_groups::DefaultSettingGroupHandler),
        );
        assert!(matches!(r, Err(ServerError::InvalidModel(_))));
    }

    #[test]
    fn register_setting_group_handler_takes_effect() {
        use crate::setting_groups::SettingGroupHandler;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct Counter(AtomicUsize);
        impl SettingGroupHandler for Counter {
            fn act_sg_changed(&self, _: u8, _: crate::ConnectionId) -> bool {
                self.0.fetch_add(1, Ordering::SeqCst);
                true
            }
        }
        impl std::fmt::Debug for Counter {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("Counter").finish()
            }
        }

        let server = server_with_sgcb();
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        server
            .register_setting_group_handler("IED1LD0", counter.clone())
            .unwrap();

        // Driven through the runtime directly; the wire path is covered by the
        // setting group tests.
        let rt = server.setting_groups().lookup("IED1LD0").unwrap();
        rt.try_select_active_sg(2, 999).unwrap();
        assert_eq!(counter.0.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn force_active_setting_group_works_and_validates() {
        let server = server_with_sgcb();
        server.force_active_setting_group("IED1LD0", 3).unwrap();
        let snap = server
            .setting_groups()
            .lookup("IED1LD0")
            .unwrap()
            .snapshot();
        assert_eq!(snap.act_sg, 3);

        // Out of range.
        let r = server.force_active_setting_group("IED1LD0", 10);
        assert!(matches!(r, Err(ServerError::InvalidModel(_))));

        // Unknown domain.
        let r = server.force_active_setting_group("WRONG", 1);
        assert!(matches!(r, Err(ServerError::InvalidModel(_))));
    }

    #[test]
    fn server_starts_inactive() {
        let server = test_server();
        assert!(!server.is_running());
        assert_eq!(server.connection_count(), 0);
    }

    #[test]
    fn write_access_default_allows_sp_sv_se_only() {
        let server = test_server();
        assert!(server.write_access_allowed(FC::Sp));
        assert!(server.write_access_allowed(FC::Sv));
        assert!(server.write_access_allowed(FC::Se));
        assert!(!server.write_access_allowed(FC::Dc));
        assert!(!server.write_access_allowed(FC::Cf));
        assert!(!server.write_access_allowed(FC::Bl));
    }

    #[test]
    fn bl_write_access_can_be_enabled_at_run_time() {
        let server = test_server();
        server.set_write_access_policy(FC::Bl, true).unwrap();
        assert!(
            server.write_access_allowed(FC::Bl),
            "FC::Bl must be settable at run time"
        );
    }

    #[test]
    fn lock_data_model_first_call_succeeds() {
        let server = test_server();
        assert!(!server.is_data_model_locked());
        let guard = server.lock_data_model().unwrap();
        assert!(server.is_data_model_locked());
        drop(guard);
        assert!(!server.is_data_model_locked());
    }

    #[test]
    fn lock_data_model_reentry_returns_err() {
        // A reentrant lock reports an error instead of
        // deadlocking.
        let server = test_server();
        let _guard1 = server.lock_data_model().unwrap();
        let result = server.lock_data_model();
        assert!(matches!(result, Err(ServerError::AlreadyLocked)));
    }

    #[test]
    fn lock_drop_clears_flag_in_correct_order() {
        let server = test_server();
        {
            let _g = server.lock_data_model().unwrap();
            assert!(server.is_data_model_locked());
        }
        // Dropping the guard clears the flag.
        assert!(!server.is_data_model_locked());
    }

    #[test]
    fn periodic_triggers_wait_for_the_data_model_lock() {
        let server = test_server();
        assert!(server.periodic_gate().is_some());
        let guard = server.lock_data_model().unwrap();
        assert!(
            server.periodic_gate().is_none(),
            "a tick skips its periodic triggers while the model is locked"
        );
        drop(guard);
        assert!(server.periodic_gate().is_some());
    }

    // ── Update triggers ─────────────────────────────────────────────────

    #[test]
    fn an_update_raises_the_triggers_its_attribute_declares() {
        let (t, f) = (MmsValue::Boolean(true), MmsValue::Boolean(false));
        let vc = InclusionFlag::VALUE_CHANGED;
        let qc = InclusionFlag::QUALITY_CHANGED;
        let vu = InclusionFlag::VALUE_UPDATE;
        let cases = [
            (TrgOps::DCHG, &f, &t, vc),
            (TrgOps::DCHG, &t, &t, InclusionFlag::NONE),
            (TrgOps::QCHG, &f, &t, qc),
            (TrgOps::QCHG, &t, &t, InclusionFlag::NONE),
            (TrgOps::DUPD, &f, &t, vu),
            (TrgOps::DUPD, &t, &t, vu),
            (TrgOps::DCHG | TrgOps::DUPD, &f, &t, vc.union(vu)),
            (TrgOps::DCHG | TrgOps::DUPD, &t, &t, vu),
            (TrgOps::QCHG | TrgOps::DUPD, &f, &t, qc.union(vu)),
            (TrgOps::DCHG | TrgOps::QCHG, &f, &t, vc.union(qc)),
            (TrgOps::NONE, &f, &t, InclusionFlag::NONE),
            (TrgOps::NONE, &t, &t, InclusionFlag::NONE),
        ];
        for (trg_ops, old, new, expected) in cases {
            let da = DataAttribute::new(
                "a",
                FC::St,
                iec61850_model::DataAttributeType::Boolean,
                trg_ops,
                old.clone(),
            );
            assert_eq!(
                update_triggers(da.trg_ops, old, new),
                expected,
                "{trg_ops:?}: {old:?} -> {new:?}"
            );
        }
    }

    #[test]
    fn a_float_is_unchanged_only_when_its_bits_are() {
        assert!(same_value(
            &MmsValue::Float32(f32::NAN),
            &MmsValue::Float32(f32::NAN)
        ));
        assert!(same_value(
            &MmsValue::Float64(f64::NAN),
            &MmsValue::Float64(f64::NAN)
        ));
        assert!(!same_value(
            &MmsValue::Float32(0.0),
            &MmsValue::Float32(-0.0)
        ));
        assert!(same_value(&MmsValue::Float64(2.5), &MmsValue::Float64(2.5)));
    }

    #[test]
    fn a_deferred_attribute_keeps_its_last_value_and_every_reason() {
        let cell = Arc::new(RwLock::new(MmsValue::Integer(0)));
        let other = Arc::new(RwLock::new(MmsValue::Integer(0)));
        let mut deferred = DeferredTriggers {
            active: true,
            ..DeferredTriggers::default()
        };
        for (c, v, flag) in [
            (&cell, 1, InclusionFlag::VALUE_CHANGED),
            (&other, 5, InclusionFlag::VALUE_CHANGED),
            (&cell, 1, InclusionFlag::VALUE_UPDATE),
        ] {
            deferred.merge(PendingTrigger {
                cell: Arc::clone(c),
                value: MmsValue::Integer(v),
                flag,
            });
        }
        let released = deferred.release();
        assert!(!deferred.active);
        let got: Vec<_> = released
            .iter()
            .map(|t| (Arc::ptr_eq(&t.cell, &cell), t.value.clone(), t.flag))
            .collect();
        assert_eq!(
            got,
            [
                (
                    true,
                    MmsValue::Integer(1),
                    InclusionFlag::VALUE_CHANGED.union(InclusionFlag::VALUE_UPDATE)
                ),
                (false, MmsValue::Integer(5), InclusionFlag::VALUE_CHANGED),
            ]
        );
        assert!(deferred.release().is_empty());
    }

    #[test]
    fn a_log_entry_takes_the_enabled_reasons() {
        let all = InclusionFlag::VALUE_CHANGED
            .union(InclusionFlag::QUALITY_CHANGED)
            .union(InclusionFlag::VALUE_UPDATE);
        assert_eq!(log_reason(all, TriggerOptions::DATA_CHANGED), 0x02);
        assert_eq!(log_reason(all, TriggerOptions::QUALITY_CHANGED), 0x04);
        assert_eq!(log_reason(all, TriggerOptions::DATA_UPDATE), 0x08);
        assert_eq!(
            log_reason(
                InclusionFlag::VALUE_UPDATE,
                TriggerOptions::DATA_CHANGED | TriggerOptions::INTEGRITY | TriggerOptions::GI
            ),
            0
        );
    }

    #[test]
    fn dispatcher_default_is_model_dispatcher() {
        // Only that a dispatcher exists; its behavior is covered by the service
        // tests.
        let server = test_server();
        let d = server.dispatcher();
        let _ = Arc::strong_count(&d);
    }

    #[test]
    fn next_connection_id_increments() {
        let server = test_server();
        assert_eq!(server.next_connection_id(), 1);
        assert_eq!(server.next_connection_id(), 2);
        assert_eq!(server.next_connection_id(), 3);
    }

    #[test]
    fn connection_slots_stop_at_max_and_return_on_drop() {
        let server = test_server();
        let max = IedServerConfig::default().max_mms_connections;
        let slots: Vec<_> = (0..max)
            .map(|_| server.try_acquire_connection_slot().expect("a free slot"))
            .collect();
        assert!(
            server.try_acquire_connection_slot().is_none(),
            "no slot is handed out beyond the limit"
        );
        drop(slots);
        assert_eq!(server.open_socket_count(), 0);
        assert!(server.try_acquire_connection_slot().is_some());
    }

    // ── Request blocking and connection abort ───────────────────────────

    #[test]
    fn block_requests_default_is_false() {
        let server = test_server();
        assert!(!server.connection_block_requests_default());
    }

    #[test]
    fn block_requests_propagates_to_open_connections() {
        use iec61850_mms::mms::server::MmsServerConnection;
        let server = test_server();
        let c1 = ClientConnection::new(
            1,
            "127.0.0.1:1".parse().unwrap(),
            MmsServerConnection::new(),
        );
        let c2 = ClientConnection::new(
            2,
            "127.0.0.1:2".parse().unwrap(),
            MmsServerConnection::new(),
        );
        server.add_connection(c1.clone());
        server.add_connection(c2.clone());
        assert!(!c1.block_requests());
        assert!(!c2.block_requests());

        server.block_requests(true);
        assert!(
            c1.block_requests(),
            "the flag must reach every open association"
        );
        assert!(c2.block_requests());
        assert!(server.connection_block_requests_default());

        server.block_requests(false);
        assert!(!c1.block_requests());
        assert!(!c2.block_requests());
    }

    #[test]
    fn abort_connection_marks_flag_and_reports_not_yet_sent() {
        use iec61850_mms::mms::server::MmsServerConnection;
        let server = test_server();
        let c = ClientConnection::new(
            7,
            "127.0.0.1:7".parse().unwrap(),
            MmsServerConnection::new(),
        );
        server.add_connection(c.clone());
        assert!(!c.abort_requested());

        let sent = server.abort_connection(7).unwrap();
        assert!(!sent, "the abort has not been sent when this returns");
        assert!(
            c.abort_requested(),
            "the association must be marked for abort"
        );
    }

    #[test]
    fn abort_connection_unknown_id_returns_false() {
        let server = test_server();
        let result = server.abort_connection(9999).unwrap();
        assert!(
            !result,
            "an unknown connection id must report nothing marked"
        );
    }
}

#[cfg(test)]
mod write_context_tests {
    use super::*;
    use crate::logging::storage::CollectingVisitor;
    use crate::logging::{InMemoryLogStorage, LogControl, LogControlBlock};
    use crate::reporting::{DatasetEntry, Rcb};
    use crate::service::write::WrittenLeaf;
    use iec61850_model::{
        DataAttributeType, DataObject, DoChild, IedModelBuilder, LogicalDeviceBuilder,
        LogicalNodeBuilder, FC,
    };

    /// A server whose URCB, enabled without a client so its report stays
    /// pending, and whose log control block both observe the FCD
    /// `GGIO1$SP$Lim`, holding `lo` and `hi`, which declare dchg.
    fn server() -> (IedServer, Arc<dyn crate::logging::LogStorage>) {
        let limit = |name: &str, v: i64| {
            DoChild::Da(DataAttribute::new(
                name,
                FC::Sp,
                DataAttributeType::Int32,
                TrgOps::DCHG,
                MmsValue::Integer(v),
            ))
        };
        let lim = DataObject::new("Lim", vec![limit("lo", 1), limit("hi", 9)]);
        let ggio = iec61850_model::LogicalNode::new(String::new(), "GGIO", "1", vec![lim]);
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(LogicalNodeBuilder::lln0().build().unwrap())
            .add_ln(ggio)
            .build()
            .unwrap();
        let model = Arc::new(
            IedModelBuilder::new("IED1")
                .add_ld(ld)
                .unwrap()
                .build()
                .unwrap(),
        );
        let server = IedServer::builder()
            .model(model.clone())
            .bind("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .build()
            .unwrap();
        let mut ds = Dataset::new("LLN0$dsLim");
        ds.push(DatasetEntry::from_model(&model, "IED1LD0", "GGIO1$SP$Lim").unwrap());
        let rcb = Rcb::new("urcbA", "LLN0$dsLim").with_trg_ops(TriggerOptions::DATA_CHANGED);
        server
            .register_urcb(ReportControl::new("IED1LD0/LLN0$RP$urcbA", rcb), ds)
            .unwrap();
        {
            let engine = server.inner.reporting_engine.lock().unwrap();
            let rc = engine.get_rcb("IED1LD0/LLN0$RP$urcbA").unwrap();
            rc.lock().unwrap().state.lock().unwrap().rpt_ena = true;
        }
        let storage: Arc<dyn crate::logging::LogStorage> = Arc::new(InMemoryLogStorage::new());
        let block = LogControlBlock::new("evlog")
            .with_dataset("LLN0$dsLim")
            .with_trg_ops(TriggerOptions::DATA_CHANGED)
            .with_log_ref("IED1LD0/LLN0$EventLog");
        let lc = LogControl::new("IED1LD0/LLN0$LG$evlog", block).with_storage(Arc::clone(&storage));
        server.register_log_control("IED1LD0", "LLN0$LG$evlog", Arc::new(lc));
        (server, storage)
    }

    fn cell(server: &IedServer, name: &str) -> Arc<RwLock<MmsValue>> {
        let model = server.model();
        let r =
            iec61850_model::ObjectRef::parse_mms(&format!("IED1LD0/GGIO1$SP$Lim${name}")).unwrap();
        let Some(iec61850_model::NodeRef::Da(da)) = model.node_by_object_ref(&r) else {
            panic!("{name} is a data attribute");
        };
        Arc::clone(&da.value)
    }

    /// The leaves of a write of `Lim` = {5, 9} over {1, 9}: `lo` changes and
    /// `hi` keeps its value, so only `lo` raises a trigger.
    fn write_of_5_9(lo: &Arc<RwLock<MmsValue>>, hi: &Arc<RwLock<MmsValue>>) -> [WrittenLeaf; 2] {
        [
            WrittenLeaf {
                value: Arc::clone(lo),
                trg_ops: TrgOps::DCHG,
                old: MmsValue::Integer(1),
                new: MmsValue::Integer(5),
            },
            WrittenLeaf {
                value: Arc::clone(hi),
                trg_ops: TrgOps::DCHG,
                old: MmsValue::Integer(9),
                new: MmsValue::Integer(9),
            },
        ]
    }

    /// Checks that the pending report and the only log entry carry `Lim` as
    /// {5, 9}.
    fn assert_carries_5_9(server: &IedServer, storage: &Arc<dyn crate::logging::LogStorage>) {
        let written = MmsValue::Structure(vec![MmsValue::Integer(5), MmsValue::Integer(9)]);
        {
            let engine = server.inner.reporting_engine.lock().unwrap();
            let rc = engine.get_rcb("IED1LD0/LLN0$RP$urcbA").unwrap();
            let rc = rc.lock().unwrap();
            let state = rc.state.lock().unwrap();
            let pending = state.pending.as_ref().expect("a pending report");
            assert_eq!(pending.snapshot[0], Some(written.clone()), "report");
        }
        let mut v = CollectingVisitor::new();
        storage.query_by_time(0, u64::MAX / 2, &mut v).unwrap();
        assert_eq!(v.entries.len(), 1);
        assert_eq!(v.entries[0].variables[0].value, written, "log entry");
    }

    /// A write of `Lim` = {5, 9} whose triggers are raised after another
    /// client has already written {6, 10}: the report and the log entry of
    /// the first write carry {5, 9}, the state it left, and not the mix
    /// {5, 10} of its changed leaf and the other client's value of `hi`,
    /// which the first write left unchanged and so raised nothing for.
    #[test]
    fn a_write_reports_its_own_values_after_a_concurrent_write() {
        let (server, storage) = server();
        let (lo, hi) = (cell(&server, "lo"), cell(&server, "hi"));
        *lo.write().unwrap() = MmsValue::Integer(6);
        *hi.write().unwrap() = MmsValue::Integer(10);

        server.raise_written(&write_of_5_9(&lo, &hi));

        assert_carries_5_9(&server, &storage);
    }

    /// The same write handed over while the data model is locked, with the
    /// other client's {6, 10} stored before the lock is released: the
    /// deferred batch keeps the value of `hi` that raised nothing, so the
    /// report and the log entry carry {5, 9} once the lock is released.
    #[test]
    fn a_deferred_write_reports_its_own_values() {
        let (server, storage) = server();
        let (lo, hi) = (cell(&server, "lo"), cell(&server, "hi"));
        let guard = server.lock_data_model().unwrap();
        server.raise_written(&write_of_5_9(&lo, &hi));
        *lo.write().unwrap() = MmsValue::Integer(6);
        *hi.write().unwrap() = MmsValue::Integer(10);
        drop(guard);

        assert_carries_5_9(&server, &storage);
    }
}
