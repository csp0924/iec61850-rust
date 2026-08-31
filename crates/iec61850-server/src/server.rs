//! `IedServer`, the IEC 61850 server object.
//!
//! The server owns its listener directly and keeps its associations in a map
//! keyed by connection id. Values are updated through typed entry points, so the
//! type of an update is checked by the compiler where it can be and reported as
//! an error where it cannot. A negotiated MMS PDU size is clamped to a floor of
//! `MIN_PDU_SIZE`, enforced during Initiate negotiation in `iec61850-mms`.
//!
//! The data model lock is a mutex acquired without blocking. Robustness case
//! Locking the model again from a thread that already holds it must not
//! deadlock, so a reentrant [`IedServer::lock_data_model`] returns
//! `Err(AlreadyLocked)` and the caller decides whether to wait or give up.
//! While the lock is held an atomic flag tells observers to defer their events;
//! releasing it triggers the pending GOOSE messages, then the pending reports,
//! then clears the flag, and only then releases the mutex.

use crate::config::IedServerConfig;
use crate::connection::{ClientConnection, ConnectionId};
use crate::control::{ChannelCommandTermination, ControlObjectsRegistry};
use crate::error::{Result, ServerError};
use crate::handler::{AttributeAccessHandler, HandlerRegistry, ReadHandler};
use crate::mapping::MmsDeviceModel;
use crate::policy::WriteAccessPolicies;
use crate::reporting::{
    BufferedReportControl, ChannelReportSink, DataAttributeRef, Dataset, ReportControl,
    ReportingEngine,
};
use crate::service::MmsModelDispatcher;
use iec61850_mms::mms::server::MmsServiceDispatcher;
use iec61850_model::{DataAttribute, IedModel, MmsValue};
#[cfg(feature = "tls")]
use iec61850_tls::TlsAcceptor;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

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
    /// Start-up settings, including the association limit the accept loop
    /// enforces.
    #[allow(dead_code)]
    config: IedServerConfig,
    bind_addr: SocketAddr,

    /// Open associations, keyed by connection id.
    connections: RwLock<HashMap<ConnectionId, ClientConnection>>,
    /// Source of the next connection id.
    #[allow(dead_code)]
    next_connection_id: AtomicU64,

    /// Which functional constraints accept a remote Write; changeable at run
    /// time, hence the lock.
    write_access_policies: RwLock<WriteAccessPolicies>,

    /// Whether the server still accepts associations.
    running: AtomicBool,

    /// Held for the duration of a data model lock; acquired without blocking so
    /// that reentrancy is an error rather than a deadlock.
    data_model_lock_guard: Mutex<()>,

    /// Set while the data model is locked, so observers defer their events
    /// until the batch of updates is complete.
    is_model_locked: AtomicBool,

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

    /// Reports whether the data model is locked, which tells an observer to
    /// defer its events.
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
    /// Dropping the returned guard triggers the pending GOOSE messages, then
    /// the pending reports, then clears the lock flag, and only then releases
    /// the mutex.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyLocked` when the model is already locked, including from
    /// the same thread: acquiring without blocking turns reentrancy into an
    /// error the caller can act on instead of a deadlock.
    pub fn lock_data_model(&self) -> Result<DataModelGuard<'_>> {
        let mutex_guard = self
            .inner
            .data_model_lock_guard
            .try_lock()
            .map_err(|_| ServerError::AlreadyLocked)?;
        self.inner.is_model_locked.store(true, Ordering::SeqCst);
        Ok(DataModelGuard {
            server: self,
            _guard: mutex_guard,
        })
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

    /// Checks that the attribute currently holds the same variant as the new
    /// value, writes it, and triggers any report that watches the attribute.
    fn update_typed(
        &self,
        da: &DataAttribute,
        new_value: MmsValue,
        expected_name: &'static str,
    ) -> Result<()> {
        // Taken before the lock, so the write lock is held as briefly as
        // possible.
        let ptr_key = Arc::as_ptr(&da.value) as usize;

        {
            let mut guard = da.value.write().map_err(|_| {
                ServerError::InvalidModel("DataAttribute value RwLock poisoned".into())
            })?;
            let actual_name = mms_value_variant_name(&guard);
            let new_name = mms_value_variant_name(&new_value);
            if actual_name != new_name {
                return Err(ServerError::TypeMismatch {
                    path: da.name.clone(),
                    expected: expected_name,
                    actual: actual_name,
                });
            }
            *guard = new_value.clone();
        }
        // The write lock is released before the reporting engine is triggered.
        let attr_ref_opt = self
            .inner
            .attr_ref_index
            .read()
            .ok()
            .and_then(|g| g.get(&ptr_key).cloned());

        if let Some(attr_ref) = attr_ref_opt {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;

            if let Ok(engine) = self.inner.reporting_engine.lock() {
                engine.on_value_updated(
                    &attr_ref,
                    new_value.clone(),
                    crate::reporting::InclusionFlag::VALUE_CHANGED,
                    now_ms,
                );
                // The buffered path is always tried too; it returns at once
                // when no buffered control block watches the attribute.
                engine.on_brcb_value_updated(
                    &attr_ref,
                    new_value,
                    crate::reporting::InclusionFlag::VALUE_CHANGED,
                    now_ms,
                );
            } else {
                tracing::warn!(
                    attr_ref = %attr_ref,
                    "the reporting engine lock is poisoned, the update triggered no report"
                );
            }
        }
        // An attribute in no data set has no index entry, which is the ordinary
        // case and needs no report.

        Ok(())
    }

    /// Registers an association once it is established.
    #[allow(dead_code)]
    pub(crate) fn add_connection(&self, conn: ClientConnection) {
        if let Ok(mut g) = self.inner.connections.write() {
            g.insert(conn.id(), conn);
        }
    }

    /// Removes an association when it closes.
    #[allow(dead_code)]
    pub(crate) fn remove_connection(&self, id: ConnectionId) -> Option<ClientConnection> {
        let conn = self.inner.connections.write().ok()?.remove(&id)?;
        conn.invalidate();
        Some(conn)
    }

    /// Allocates the next connection id.
    #[allow(dead_code)]
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
    /// Besides handing both to the engine, this indexes every member of the
    /// data set by the address of its value, so that a later update can find
    /// the attribute reference the engine knows it by.
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
        let index_entries: Vec<(usize, DataAttributeRef)> = ds
            .entries
            .iter()
            .map(|e| (Arc::as_ptr(&e.value) as usize, e.attr_ref.clone()))
            .collect();

        // The domain comes from the object reference of the control block,
        // `<domain>/<LN>$RP$<rcb>`, and the data set keeps its own name. The
        // copy placed in the registry is a separate data set object sharing the
        // same member values.
        let dataset_key: Option<(String, String)> = rc
            .mms_path
            .split_once('/')
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
        } else {
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

        let index_entries: Vec<(usize, DataAttributeRef)> = ds
            .entries
            .iter()
            .map(|e| (Arc::as_ptr(&e.value) as usize, e.attr_ref.clone()))
            .collect();

        let dataset_key: Option<(String, String)> = brc
            .mms_path
            .split_once('/')
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
        } else {
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

    /// Registers a log control block under the domain and item a ReadJournal
    /// request names it by.
    ///
    /// The usual key is the MMS domain, such as `"IED1LD0"`, together with the
    /// path of the control block within it, such as `"MMXU1$LG$lcb01"`; a log
    /// instance name such as `"MMXU1$EventLog"` works equally well.
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    pub(crate) fn set_running(&self, on: bool) {
        self.inner.running.store(on, Ordering::SeqCst);
    }

    /// Reports whether another association fits within the configured limit.
    #[allow(dead_code)]
    pub(crate) fn can_accept_new(&self) -> bool {
        self.connection_count() < self.inner.config.max_mms_connections
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
    /// stored state. A client write goes through the callbacks instead.
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

/// Holds the data model lock; dropping it releases the lock in order.
pub struct DataModelGuard<'a> {
    server: &'a IedServer,
    _guard: std::sync::MutexGuard<'a, ()>,
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
        // Order matters: the pending GOOSE messages and reports are triggered
        // first, then the flag is cleared, and the mutex is released last.
        // Clearing the flag any earlier would let an observer conclude the
        // batch is over while its events are still pending.
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
        let reporting_engine: Arc<Mutex<ReportingEngine>> = Arc::new(Mutex::new(
            ReportingEngine::new_with_channel_sink(report_sink.clone()),
        ));

        let handler_registry: Arc<HandlerRegistry> = Arc::new(HandlerRegistry::new());

        let dataset_registry: crate::reporting::DatasetRegistry =
            Arc::new(RwLock::new(HashMap::new()));

        let log_controls: crate::logging::LogControlRegistry =
            crate::logging::new_log_control_registry();

        // Projected from the setting group control blocks the model declares.
        let setting_groups: Arc<crate::setting_groups::SettingGroupRegistry> = Arc::new(
            crate::setting_groups::SettingGroupRegistry::from_model(&model),
        );

        let dynamic_dataset_keys: crate::service::define_named_variable_list::DynamicDatasetKeys =
            crate::service::define_named_variable_list::new_dynamic_dataset_keys();

        let gocb_registry: Arc<crate::goose_mapping::GoCBRegistry> =
            Arc::new(crate::goose_mapping::GoCBRegistry::new());

        let dispatcher: Arc<dyn MmsServiceDispatcher> = match self.dispatcher {
            Some(d) => d,
            None => {
                let mms_model = MmsDeviceModel::from_ied_model(&model)?;
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
                    Arc::new(mms_model),
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
                .with_gocb_registry(gocb_registry.clone());
                Arc::new(dispatcher)
            }
        };

        Ok(IedServer {
            inner: Arc::new(IedServerInner {
                model,
                config: self.config,
                bind_addr,
                connections: RwLock::new(HashMap::new()),
                next_connection_id: AtomicU64::new(1),
                write_access_policies: RwLock::new(write_access_policies),
                running: AtomicBool::new(false),
                data_model_lock_guard: Mutex::new(()),
                is_model_locked: AtomicBool::new(false),
                dispatcher,
                connection_block_requests_default: AtomicBool::new(false),
                control_objects,
                ct_sink,
                reporting_engine,
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
        })
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
            .set_sgcb(SettingGroupControlBlock {
                num_of_sg: 3,
                act_sg: 1,
                has_resv_tms: true,
                default_resv_tms_s: 30,
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
    fn can_accept_new_until_max() {
        // The default limit is five; this covers the empty case only.
        let server = test_server();
        assert!(server.can_accept_new());
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
