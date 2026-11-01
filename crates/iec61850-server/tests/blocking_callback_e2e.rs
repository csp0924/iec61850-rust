//! Application callbacks that block leave the rest of the server serving.
//!
//! Each test installs one callback that, once entered, waits on a gate the
//! test holds closed, and makes the server reach it: a read handler, a write
//! handler, the selection change handler on a select, the select timeout, the
//! end of a command and the loss of an association, and a log storage written
//! by the integrity period. While the callback is held, another association
//! must read and write and a new association must be accepted; the callback
//! is still held when they finish, so they cannot have waited for it. Opening
//! the gate then completes whatever the callback held up.
//!
//! Two calls into the server do not wait for a held callback either:
//! `IedServer::block_requests`, also when a handler makes it, and registering a
//! control object while a selection change handler hears of a lost
//! association.
//!
//! The server runs on a runtime of its own, on its own thread: a
//! current-thread runtime, or a multi-thread runtime with one worker, where a
//! callback blocking the thread that polls the server's tasks would stall
//! every association. The clients run on the test's runtime. The
//! `STALL` bound only turns such a stall into a failure; nothing passes by
//! finishing within it.

use std::net::SocketAddr;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use iec61850_mms::mms::client::{ClientError, MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::reject::{ConfirmedRequestRejectReason, RejectReason};
use iec61850_mms::mms::MmsData;
use iec61850_model::cdc::{self, CdcOptions, ControlOptions};
use iec61850_model::{
    ControlModel, DataAttribute, DataAttributeType, DataObject, DoChild, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::control::handler::WaitForExecFuture;
use iec61850_server::control::{
    AlwaysSuccessOperateHandler, ControlAction, ControlAddCause, ControlHandler,
    SelectStateChangedHandler, SelectStateChangedReason, WaitForExecutionHandler,
};
use iec61850_server::handler::{
    AttributeAccessHandler, ReadContext, ReadHandler, ReadOutcome, WriteContext,
    WriteOutcome as HandlerWriteOutcome,
};
use iec61850_server::{
    Dataset, DatasetEntry, IedServer, InMemoryLogStorage, JournalEntryData, LogControl,
    LogControlBlock, LogEntryId, LogEntryVisitor, LogStorage, LogStorageError, TriggerOptions,
};

const DOMAIN: &str = "blkLD0";
/// Read by the gated read handler.
const GATED_READ: &str = "GGIO1$ST$Ind1$stVal";
/// Written through the gated write handler.
const GATED_WRITE: &str = "GGIO1$SP$Lim$setVal";
/// Read by the other association, and the member of the logged data set.
const PROBE_READ: &str = "GGIO1$ST$Ind2$stVal";
/// Written by the other association.
const PROBE_WRITE: &str = "GGIO1$SP$SetPt$setVal";

/// Turns a stalled server into a failure; never a condition for passing.
const STALL: Duration = Duration::from_secs(30);

// ─────────────────────────────────────────────────────────────────────────────
// Gate
// ─────────────────────────────────────────────────────────────────────────────

/// Holds every callback that passes it until the test opens it.
#[derive(Debug, Default)]
struct Gate {
    state: Mutex<GateState>,
    changed: Condvar,
}

#[derive(Debug, Default)]
struct GateState {
    entered: usize,
    open: bool,
}

impl Gate {
    /// Records the entry and waits until the gate is open.
    fn pass(&self) {
        let mut g = self.state.lock().unwrap();
        g.entered += 1;
        self.changed.notify_all();
        while !g.open {
            g = self.changed.wait(g).unwrap();
        }
    }

    fn open(&self) {
        self.state.lock().unwrap().open = true;
        self.changed.notify_all();
    }

    fn entered(&self) -> usize {
        self.state.lock().unwrap().entered
    }

    /// Waits on the test's runtime until a callback has entered the gate.
    async fn wait_entered(self: &Arc<Self>) {
        let gate = self.clone();
        let waited = tokio::task::spawn_blocking(move || {
            let g = gate.state.lock().unwrap();
            let (g, _) = gate
                .changed
                .wait_timeout_while(g, STALL, |s| s.entered == 0)
                .unwrap();
            g.entered > 0
        })
        .await
        .unwrap();
        assert!(waited, "the server never reached the callback");
    }

    /// Opens the gate when dropped, so a failing test does not leave the
    /// server's thread held.
    fn opener(self: &Arc<Self>) -> Opener {
        Opener(self.clone())
    }
}

struct Opener(Arc<Gate>);

impl Drop for Opener {
    fn drop(&mut self) {
        self.0.open();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Callbacks
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct GatedRead(Arc<Gate>);

impl ReadHandler for GatedRead {
    fn read(&self, _ctx: &ReadContext<'_>) -> ReadOutcome {
        self.0.pass();
        ReadOutcome::CacheHit(MmsValue::Boolean(true))
    }
}

#[derive(Debug)]
struct GatedWrite(Arc<Gate>);

impl AttributeAccessHandler for GatedWrite {
    fn on_write(&self, _ctx: &WriteContext<'_>, _value: &MmsValue) -> HandlerWriteOutcome {
        self.0.pass();
        HandlerWriteOutcome::Accept
    }
}

/// Holds the selection changes of one reason at the gate.
struct GatedSelection {
    gate: Arc<Gate>,
    reason: SelectStateChangedReason,
}

impl SelectStateChangedHandler for GatedSelection {
    fn on_select_state_changed(
        &self,
        _action: &ControlAction,
        _is_selected: bool,
        reason: SelectStateChangedReason,
    ) {
        if reason == self.reason {
            self.gate.pass();
        }
    }
}

/// An in-memory log whose writes wait at the gate.
#[derive(Debug)]
struct GatedLog {
    gate: Arc<Gate>,
    inner: InMemoryLogStorage,
}

impl LogStorage for GatedLog {
    fn add_entry(&self, time_ms: u64) -> Result<LogEntryId, LogStorageError> {
        self.gate.pass();
        self.inner.add_entry(time_ms)
    }

    fn add_entry_data(
        &self,
        entry_id: LogEntryId,
        data_ref: &str,
        value: MmsValue,
        reason_code: u8,
    ) -> Result<(), LogStorageError> {
        self.inner
            .add_entry_data(entry_id, data_ref, value, reason_code)
    }

    fn add_entry_with_data(
        &self,
        time_ms: u64,
        data: &[JournalEntryData],
    ) -> Result<LogEntryId, LogStorageError> {
        self.gate.pass();
        self.inner.add_entry_with_data(time_ms, data)
    }

    fn query_by_time(
        &self,
        start_ms: u64,
        end_ms: u64,
        visitor: &mut dyn LogEntryVisitor,
    ) -> Result<(), LogStorageError> {
        self.inner.query_by_time(start_ms, end_ms, visitor)
    }

    fn query_after(
        &self,
        starting_time_ms: u64,
        entry_id: LogEntryId,
        visitor: &mut dyn LogEntryVisitor,
    ) -> Result<(), LogStorageError> {
        self.inner.query_after(starting_time_ms, entry_id, visitor)
    }

    fn oldest_and_newest(
        &self,
    ) -> Result<
        Option<(
            iec61850_server::logging::storage::EntryMeta,
            iec61850_server::logging::storage::EntryMeta,
        )>,
        LogStorageError,
    > {
        self.inner.oldest_and_newest()
    }

    fn count(&self) -> usize {
        self.inner.count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Server on a runtime of its own
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum Flavor {
    CurrentThread,
    OneWorker,
}

/// A server running on its own thread and runtime.
struct ServerThread {
    port: u16,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ServerThread {
    fn start(server: &IedServer, flavor: Flavor) -> Self {
        let server = server.clone();
        let (port_tx, port_rx) = std::sync::mpsc::channel();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::spawn(move || {
            let runtime = match flavor {
                Flavor::CurrentThread => tokio::runtime::Builder::new_current_thread(),
                Flavor::OneWorker => {
                    let mut b = tokio::runtime::Builder::new_multi_thread();
                    b.worker_threads(1);
                    b
                }
            }
            .enable_all()
            .build()
            .expect("server runtime");
            runtime.block_on(async move {
                let handle = server.start().await.expect("start");
                port_tx.send(handle.bound_addr.port()).unwrap();
                let _ = stopped.await;
                handle.stop().await;
            });
        });
        let port = port_rx.recv().expect("server port");
        Self {
            port,
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    /// Stops the server and waits for its thread.
    fn stop(mut self) {
        let _ = self.stop.take().map(|s| s.send(()));
        if let Some(t) = self.thread.take() {
            t.join().expect("server thread");
        }
    }
}

impl Drop for ServerThread {
    fn drop(&mut self) {
        // A failing test does not wait for a server that may still be held.
        let _ = self.stop.take().map(|s| s.send(()));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Model and clients
// ─────────────────────────────────────────────────────────────────────────────

fn leaf(do_name: &str, da_name: &str, fc: FC, ty: DataAttributeType, v: MmsValue) -> DataObject {
    DataObject::new(
        do_name,
        vec![DoChild::Da(DataAttribute::new(
            da_name,
            fc,
            ty,
            TrgOps::NONE,
            v,
        ))],
    )
}

/// `GGIO1` with two boolean status points, two integer settings and
/// `SPCSO2`, an SPC under normal-security select-before-operate with
/// `stSeld` and the select timeout `sbo_timeout_ms`.
fn build_model(sbo_timeout_ms: u64) -> Arc<IedModel> {
    let mut spc: DataObject = cdc::spc(
        "SPCSO2",
        CdcOptions::NONE,
        ControlOptions::NONE
            .with_model(ControlModel::SboNormal)
            .union(ControlOptions::ST_SELD),
    );
    spc.children.push(DoChild::Da(DataAttribute::new(
        "sboTimeout",
        FC::Cf,
        DataAttributeType::Int32U,
        TrgOps::NONE,
        MmsValue::Unsigned(sbo_timeout_ms),
    )));
    let ggio = LogicalNodeBuilder::new("", "GGIO", "1")
        .add_do(leaf(
            "Ind1",
            "stVal",
            FC::St,
            DataAttributeType::Boolean,
            MmsValue::Boolean(false),
        ))
        .add_do(leaf(
            "Ind2",
            "stVal",
            FC::St,
            DataAttributeType::Boolean,
            MmsValue::Boolean(false),
        ))
        .add_do(leaf(
            "SetPt",
            "setVal",
            FC::Sp,
            DataAttributeType::Int32,
            MmsValue::Integer(0),
        ))
        .add_do(leaf(
            "Lim",
            "setVal",
            FC::Sp,
            DataAttributeType::Int32,
            MmsValue::Integer(0),
        ))
        .add_do(spc)
        .build()
        .expect("ggio");
    let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .add_ln(ggio)
        .build()
        .expect("ld");
    Arc::new(
        IedModelBuilder::new("blk")
            .add_ld(ld)
            .expect("add_ld")
            .build()
            .expect("model"),
    )
}

fn build_server(sbo_timeout_ms: u64) -> IedServer {
    IedServer::builder()
        .model(build_model(sbo_timeout_ms))
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()
        .expect("server")
}

/// Registers `SPCSO2` with a control handler that succeeds and `selection` as
/// its selection change handler.
fn register_control(server: &IedServer, selection: Arc<dyn SelectStateChangedHandler>) {
    register_control_with(server, selection, None);
}

/// As [`register_control`], with `wait` as the dynamic check.
fn register_control_with(
    server: &IedServer,
    selection: Arc<dyn SelectStateChangedHandler>,
    wait: Option<Arc<dyn WaitForExecutionHandler>>,
) {
    let registry = server.control_objects();
    assert_eq!(registry.register_from_model(&server.model()), 1);
    let entry = registry
        .lookup(DOMAIN, "GGIO1", "SPCSO2")
        .expect("registered");
    entry.object.set_select_state_handler(selection);
    let entry =
        entry.with_operate(Arc::new(AlwaysSuccessOperateHandler) as Arc<dyn ControlHandler>);
    registry.register(match wait {
        Some(wait) => entry.with_wait(wait),
        None => entry,
    });
}

async fn connect(port: u16) -> MmsClient {
    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(60_000)
        .request_timeout_ms(60_000)
        .build();
    client.connect("127.0.0.1", port).await.expect("connect");
    client
}

/// Reads and writes on `other`, an association opened before the callback
/// was entered, and opens and reads on a new association.
async fn serve_others(port: u16, other: &mut MmsClient) {
    let served = tokio::time::timeout(STALL, async {
        assert_eq!(
            other.read(DOMAIN, PROBE_READ).await.expect("read"),
            MmsData::Boolean(false)
        );
        other
            .write(DOMAIN, PROBE_WRITE, MmsData::Integer(5))
            .await
            .expect("write");
        assert_eq!(
            other.read(DOMAIN, PROBE_WRITE).await.expect("read back"),
            MmsData::Integer(5)
        );
        let mut late = connect(port).await;
        assert_eq!(
            late.read(DOMAIN, PROBE_READ).await.expect("read"),
            MmsData::Boolean(false)
        );
    })
    .await;
    assert!(
        served.is_ok(),
        "the other associations stalled while a callback was held"
    );
}

fn oper(ctl_num: u64) -> MmsData {
    MmsData::Structure(vec![
        MmsData::Boolean(true),
        MmsData::Structure(vec![
            MmsData::Integer(3),
            MmsData::OctetString(b"probe".to_vec()),
        ]),
        MmsData::Unsigned(ctl_num),
        MmsData::UtcTime([0; 8]),
        MmsData::Boolean(false),
        MmsData::BitString {
            padding: 6,
            data: vec![0],
        },
    ])
}

async fn select(c: &mut MmsClient) {
    match c.read(DOMAIN, "GGIO1$CO$SPCSO2$SBO").await {
        Ok(MmsData::VisibleString(s)) if !s.is_empty() => {}
        other => panic!("select refused: {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Request handlers
// ─────────────────────────────────────────────────────────────────────────────

async fn blocked_read_handler(flavor: Flavor) {
    let server = build_server(30_000);
    let gate = Arc::new(Gate::default());
    let _opener = gate.opener();
    server
        .handler_registry()
        .install_read_handler(GATED_READ, Arc::new(GatedRead(gate.clone())))
        .unwrap();
    let running = ServerThread::start(&server, flavor);
    let mut other = connect(running.port).await;

    let mut held = connect(running.port).await;
    let held_read = tokio::spawn(async move { held.read(DOMAIN, GATED_READ).await });
    gate.wait_entered().await;

    serve_others(running.port, &mut other).await;
    assert!(!held_read.is_finished(), "the read waits for its handler");
    assert_eq!(gate.entered(), 1);

    gate.open();
    assert_eq!(
        held_read.await.unwrap().expect("held read"),
        MmsData::Boolean(true),
        "the read answers with the handler's value"
    );
    running.stop();
}

/// A read handler that blocks on a current-thread runtime.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_read_handler_leaves_a_current_thread_server_serving() {
    blocked_read_handler(Flavor::CurrentThread).await;
}

/// A read handler that blocks on a multi-thread runtime with one worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_read_handler_leaves_a_one_worker_server_serving() {
    blocked_read_handler(Flavor::OneWorker).await;
}

/// A write handler that blocks; the write is stored once it accepts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_write_handler_leaves_the_server_serving() {
    let server = build_server(30_000);
    let gate = Arc::new(Gate::default());
    let _opener = gate.opener();
    server
        .handler_registry()
        .install_write_access_handler(GATED_WRITE, Arc::new(GatedWrite(gate.clone())))
        .unwrap();
    let running = ServerThread::start(&server, Flavor::CurrentThread);
    let mut other = connect(running.port).await;

    let mut held = connect(running.port).await;
    let held_write = tokio::spawn(async move {
        held.write(DOMAIN, GATED_WRITE, MmsData::Integer(9)).await?;
        held.read(DOMAIN, GATED_WRITE).await
    });
    gate.wait_entered().await;

    serve_others(running.port, &mut other).await;
    assert!(!held_write.is_finished(), "the write waits for its handler");

    gate.open();
    assert_eq!(
        held_write.await.unwrap().expect("held write"),
        MmsData::Integer(9)
    );
    running.stop();
}

/// A read handler may call `IedServer::block_requests`, which reaches the
/// association whose request the handler is answering.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_handler_may_block_and_unblock_requests() {
    #[derive(Debug)]
    struct Blocking(IedServer);
    impl ReadHandler for Blocking {
        fn read(&self, _ctx: &ReadContext<'_>) -> ReadOutcome {
            self.0.block_requests(true);
            self.0.block_requests(false);
            ReadOutcome::CacheHit(MmsValue::Boolean(true))
        }
    }

    let server = build_server(30_000);
    server
        .handler_registry()
        .install_read_handler(GATED_READ, Arc::new(Blocking(server.clone())))
        .unwrap();
    let running = ServerThread::start(&server, Flavor::OneWorker);
    let mut client = connect(running.port).await;
    let answered = tokio::time::timeout(STALL, client.read(DOMAIN, GATED_READ)).await;
    assert_eq!(
        answered
            .expect("the read deadlocked in its handler")
            .unwrap(),
        MmsData::Boolean(true)
    );
    assert_eq!(
        client.read(DOMAIN, PROBE_READ).await.unwrap(),
        MmsData::Boolean(false),
        "requests are served again"
    );
    running.stop();
}

/// `IedServer::block_requests` returns while a handler of an association is
/// held, and the association answers the held request afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_requests_does_not_wait_for_a_blocked_handler() {
    let server = build_server(30_000);
    let gate = Arc::new(Gate::default());
    let _opener = gate.opener();
    server
        .handler_registry()
        .install_read_handler(GATED_READ, Arc::new(GatedRead(gate.clone())))
        .unwrap();
    let running = ServerThread::start(&server, Flavor::OneWorker);

    let mut held = connect(running.port).await;
    let held_read = tokio::spawn(async move { held.read(DOMAIN, GATED_READ).await });
    gate.wait_entered().await;

    let toggled = tokio::time::timeout(
        STALL,
        tokio::task::spawn_blocking({
            let server = server.clone();
            move || {
                server.block_requests(true);
                server.block_requests(false);
            }
        }),
    )
    .await;
    assert!(
        toggled.is_ok(),
        "block_requests waited for the held handler"
    );
    assert!(!held_read.is_finished());

    gate.open();
    assert_eq!(
        held_read.await.unwrap().expect("held read"),
        MmsData::Boolean(true)
    );
    running.stop();
}

fn is_blocked(result: Result<MmsData, ClientError>) -> bool {
    matches!(
        result,
        Err(ClientError::RejectError {
            reason: RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::Other),
            ..
        })
    )
}

/// `IedServer::block_requests` reaches an association that is already open
/// from its next request on: that request is rejected, and once the flag is
/// cleared the association is served again. A request being dispatched when
/// the flag is set completes; the one after it is rejected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_requests_applies_to_an_open_association_from_its_next_request() {
    let server = build_server(30_000);
    let gate = Arc::new(Gate::default());
    let _opener = gate.opener();
    server
        .handler_registry()
        .install_read_handler(GATED_READ, Arc::new(GatedRead(gate.clone())))
        .unwrap();
    let running = ServerThread::start(&server, Flavor::OneWorker);
    let mut client = connect(running.port).await;

    assert_eq!(
        client.read(DOMAIN, PROBE_READ).await.unwrap(),
        MmsData::Boolean(false)
    );
    server.block_requests(true);
    assert!(
        is_blocked(client.read(DOMAIN, PROBE_READ).await),
        "the next request is rejected"
    );
    server.block_requests(false);
    assert_eq!(
        client.read(DOMAIN, PROBE_READ).await.unwrap(),
        MmsData::Boolean(false),
        "the association is served again"
    );

    let held_read = tokio::spawn(async move {
        let held = client.read(DOMAIN, GATED_READ).await;
        (client, held)
    });
    gate.wait_entered().await;
    server.block_requests(true);
    gate.open();
    let (mut client, held) = held_read.await.unwrap();
    assert_eq!(
        held.expect("the request being dispatched completes"),
        MmsData::Boolean(true)
    );
    assert!(
        is_blocked(client.read(DOMAIN, PROBE_READ).await),
        "the request after it is rejected"
    );
    server.block_requests(false);
    assert_eq!(
        client.read(DOMAIN, PROBE_READ).await.unwrap(),
        MmsData::Boolean(false)
    );
    running.stop();
}

// ─────────────────────────────────────────────────────────────────────────────
// Selection change handler
// ─────────────────────────────────────────────────────────────────────────────

/// Holds the selection change of `reason` while `cause` makes it happen on a
/// fresh association, and checks that the server keeps serving. The task
/// `cause` spawns hands the association back, which keeps it open until the
/// gate opens.
async fn blocked_selection(
    reason: SelectStateChangedReason,
    sbo_timeout_ms: u64,
    cause: impl FnOnce(MmsClient) -> tokio::task::JoinHandle<MmsClient>,
) {
    blocked_selection_with(reason, sbo_timeout_ms, None, cause).await;
}

/// As [`blocked_selection`], with `wait` as the dynamic check.
async fn blocked_selection_with(
    reason: SelectStateChangedReason,
    sbo_timeout_ms: u64,
    wait: Option<Arc<dyn WaitForExecutionHandler>>,
    cause: impl FnOnce(MmsClient) -> tokio::task::JoinHandle<MmsClient>,
) {
    let server = build_server(sbo_timeout_ms);
    let gate = Arc::new(Gate::default());
    let _opener = gate.opener();
    register_control_with(
        &server,
        Arc::new(GatedSelection {
            gate: gate.clone(),
            reason,
        }),
        wait,
    );
    let running = ServerThread::start(&server, Flavor::CurrentThread);
    let mut other = connect(running.port).await;

    let caused = cause(connect(running.port).await);
    gate.wait_entered().await;

    serve_others(running.port, &mut other).await;
    assert_eq!(gate.entered(), 1, "the change is still held");

    gate.open();
    let client = caused.await.unwrap();
    drop(client);
    running.stop();
}

/// The handler hearing of a select, inside the select request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_selection_handler_on_a_select_leaves_the_server_serving() {
    blocked_selection(SelectStateChangedReason::Selected, 30_000, |mut c| {
        tokio::spawn(async move {
            select(&mut c).await;
            c
        })
    })
    .await;
}

/// The handler hearing of the select timeout, from the select timer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_selection_handler_on_the_select_timeout_leaves_the_server_serving() {
    blocked_selection(SelectStateChangedReason::Timeout, 50, |mut c| {
        tokio::spawn(async move {
            select(&mut c).await;
            c
        })
    })
    .await;
}

/// The handler hearing of the end of a command, from the command's task.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_selection_handler_at_the_end_of_a_command_leaves_the_server_serving() {
    blocked_selection(SelectStateChangedReason::OperateDone, 30_000, |mut c| {
        tokio::spawn(async move {
            select(&mut c).await;
            c.write(DOMAIN, "GGIO1$CO$SPCSO2$Oper", oper(1))
                .await
                .expect("operate");
            c
        })
    })
    .await;
}

/// The handler hearing of a selection lost with its association, from the
/// association's teardown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_selection_handler_on_a_lost_association_leaves_the_server_serving() {
    blocked_selection(SelectStateChangedReason::Disconnected, 30_000, |mut c| {
        tokio::spawn(async move {
            select(&mut c).await;
            c.close_raw();
            c
        })
    })
    .await;
}

/// A dynamic check that refuses every command.
struct RefusingCheck;

impl WaitForExecutionHandler for RefusingCheck {
    fn wait_for_execution<'a>(
        &'a self,
        _action: &'a ControlAction,
        _ctl_val: &'a MmsValue,
        _test: bool,
        _synchro_check: bool,
    ) -> WaitForExecFuture<'a> {
        Box::pin(async { Err(ControlAddCause::BlockedBySynchrocheck) })
    }
}

/// A dynamic check that passes once the test lets it.
#[derive(Default)]
struct HeldCheck {
    entered: tokio::sync::Notify,
    go: tokio::sync::Notify,
}

impl WaitForExecutionHandler for HeldCheck {
    fn wait_for_execution<'a>(
        &'a self,
        _action: &'a ControlAction,
        _ctl_val: &'a MmsValue,
        _test: bool,
        _synchro_check: bool,
    ) -> WaitForExecFuture<'a> {
        Box::pin(async move {
            self.entered.notify_one();
            self.go.notified().await;
            Ok(())
        })
    }
}

/// The handler hearing of a selection a refusing dynamic check ends, from
/// the command's task.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_selection_handler_on_a_refused_dynamic_check_leaves_the_server_serving() {
    blocked_selection_with(
        SelectStateChangedReason::OperateRefused,
        30_000,
        Some(Arc::new(RefusingCheck)),
        |mut c| {
            tokio::spawn(async move {
                select(&mut c).await;
                assert!(c
                    .write(DOMAIN, "GGIO1$CO$SPCSO2$Oper", oper(1))
                    .await
                    .is_err());
                c
            })
        },
    )
    .await;
}

/// The handler hearing of a command abandoned because its association closed
/// before the positive response, from the command's task.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_selection_handler_on_an_abandoned_command_leaves_the_server_serving() {
    let server = build_server(30_000);
    let gate = Arc::new(Gate::default());
    let _opener = gate.opener();
    let check = Arc::new(HeldCheck::default());
    register_control_with(
        &server,
        Arc::new(GatedSelection {
            gate: gate.clone(),
            reason: SelectStateChangedReason::Disconnected,
        }),
        Some(check.clone()),
    );
    let running = ServerThread::start(&server, Flavor::CurrentThread);
    let mut other = connect(running.port).await;

    let mut lost = connect(running.port).await;
    select(&mut lost).await;
    let (close, closed) = tokio::sync::oneshot::channel::<()>();
    let operating = tokio::spawn(async move {
        tokio::select! {
            _ = lost.write(DOMAIN, "GGIO1$CO$SPCSO2$Oper", oper(1)) => {
                panic!("the operate was answered before its dynamic check passed")
            }
            _ = closed => lost.close_raw(),
        }
    });
    tokio::time::timeout(STALL, check.entered.notified())
        .await
        .expect("the dynamic check never started");
    close.send(()).unwrap();
    operating.await.unwrap();
    let released = tokio::time::timeout(STALL, async {
        while server.connection_count() != 1 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await;
    assert!(
        released.is_ok(),
        "the closed association was never released"
    );

    check.go.notify_one();
    gate.wait_entered().await;

    serve_others(running.port, &mut other).await;
    assert_eq!(gate.entered(), 1, "the change is still held");

    gate.open();
    running.stop();
}

// ─────────────────────────────────────────────────────────────────────────────
// Log storage written by the tick loop
// ─────────────────────────────────────────────────────────────────────────────

/// A log storage that blocks while the integrity period writes an entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_log_storage_leaves_the_server_serving() {
    let server = build_server(30_000);
    let gate = Arc::new(Gate::default());
    let _opener = gate.opener();
    let storage = Arc::new(GatedLog {
        gate: gate.clone(),
        inner: InMemoryLogStorage::new(),
    });

    let member = server
        .model()
        .ld_by_domain(DOMAIN)
        .and_then(|ld| ld.ln_by_name("GGIO1"))
        .and_then(|ln| ln.do_by_name("Ind2"))
        .and_then(|d| match d.child_by_name("stVal", Some(FC::St)) {
            Some(DoChild::Da(da)) => Some(Arc::clone(&da.value)),
            _ => None,
        })
        .expect("Ind2.stVal");
    let mut ds = Dataset::new("LLN0$dsLog");
    ds.push(DatasetEntry::new(format!("{DOMAIN}/{PROBE_READ}"), member));
    server.register_dataset(DOMAIN, ds);
    let block = LogControlBlock::new("lcbBlk")
        .with_dataset("LLN0$dsLog")
        .with_trg_ops(TriggerOptions::INTEGRITY)
        .with_intg_pd_ms(50)
        .with_log_ref(format!("{DOMAIN}/LLN0$BlkLog"))
        .with_default_enabled(true);
    server.register_log_control(
        DOMAIN,
        "LLN0$LG$lcbBlk",
        Arc::new(
            LogControl::new(format!("{DOMAIN}/LLN0$LG$lcbBlk"), block)
                .with_storage(storage.clone() as Arc<dyn LogStorage>),
        ),
    );

    let running = ServerThread::start(&server, Flavor::CurrentThread);
    let mut other = connect(running.port).await;
    gate.wait_entered().await;

    serve_others(running.port, &mut other).await;
    assert_eq!(gate.entered(), 1, "the integrity entry is still held");

    gate.open();
    running.stop();
    assert!(storage.count() >= 1, "the held entry is written");
}

/// Registering a control object returns while the selection change handler
/// of a lost association is held: the release holds no lock of the registry
/// while it reports.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registering_a_control_does_not_wait_for_a_held_selection_handler() {
    let server = build_server(30_000);
    let gate = Arc::new(Gate::default());
    let _opener = gate.opener();
    register_control(
        &server,
        Arc::new(GatedSelection {
            gate: gate.clone(),
            reason: SelectStateChangedReason::Disconnected,
        }),
    );
    let running = ServerThread::start(&server, Flavor::CurrentThread);
    let mut lost = connect(running.port).await;
    select(&mut lost).await;
    lost.close_raw();
    gate.wait_entered().await;

    let registered = tokio::time::timeout(
        STALL,
        tokio::task::spawn_blocking({
            let registry = server.control_objects();
            move || {
                let entry = registry
                    .lookup(DOMAIN, "GGIO1", "SPCSO2")
                    .expect("registered");
                registry.register(entry)
            }
        }),
    )
    .await;
    assert!(
        registered.is_ok(),
        "registering waited for the held selection handler"
    );
    assert_eq!(gate.entered(), 1, "the change is still held");

    gate.open();
    drop(lost);
    running.stop();
}
