//! Serves `examples/models/demo.cid` with its data sets, report control blocks
//! and control object wired to the runtime.
//!
//! Where `min_server` only exposes the model, this example walks the model the
//! SCL parser produced and registers every control block it declares:
//!
//! - data sets `dsMeas` and `dsStatus`, resolved to the live attribute slots
//! - unbuffered report control block `urcbMeas` on `dsMeas`
//! - buffered report control block `brcbMeas` on `dsMeas`
//! - control object `GGIO1.SPCSO1` with the control model the CID configures
//!
//! A background task then drives the process values so a subscribed client sees
//! reports: `Ind1` toggles every second and the three measured values ramp.
//!
//! Pairs with the `client_reporting_subscriber` and `read_write_cycle` examples.
//!
//! ```sh
//! # Terminal 1
//! cargo run -p iec61850-server --example server_from_scl
//!
//! # Terminal 2
//! cargo run -p iec61850-client --example read_write_cycle
//! ```
//!
//! Expected stdout:
//!
//! ```text
//! model DemoIED loaded from .../examples/models/demo.cid
//! data set DemoIEDLD0/LLN0$dsMeas with 3 members
//! data set DemoIEDLD0/LLN0$dsStatus with 4 members
//! URCB DemoIEDLD0/LLN0$RP$urcbMeas on dsMeas
//! BRCB DemoIEDLD0/LLN0$BR$brcbMeas on dsMeas
//! control object DemoIEDLD0/GGIO1.SPCSO1 (DirectNormal)
//! listening on 127.0.0.1:8102
//! press Ctrl+C to stop
//! ```
//!
//! The default bind address is `127.0.0.1:8102` rather than the port 102 the
//! CID names, so the example runs without elevated privileges. Pass a bind
//! address to override it.

use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iec61850_model::cb::{OptFlds, ReportControlBlock};
use iec61850_model::tree::{DataAttribute, DataSet, DataSetEntry, IedModel, LogicalNode};
use iec61850_model::{ControlModel, MmsValue, NodeRef, ObjectRef, TrgOps, FC};
use iec61850_server::control::handler::OperateFuture;
use iec61850_server::control::{
    AlwaysAcceptCheckHandler, AlwaysAcceptWaitHandler, CheckHandler, ControlAction,
    ControlAddCause, ControlHandler, ControlObject, ControlObjectConfig, ControlObjectEntry,
    SboClass, WaitForExecutionHandler,
};
use iec61850_server::reporting::{Brcb, BufferedReportControl};
use iec61850_server::{
    Dataset, DatasetEntry, IedServer, IedServerConfig, Rcb, ReportControl, TriggerOptions,
    WriteAccessPolicies,
};

const IED_NAME: &str = "DemoIED";
const LD_INST: &str = "LD0";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr: SocketAddr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8102".to_string())
        .parse()?;

    let model = load_model(Path::new(DEMO_CID))?;
    println!("model {IED_NAME} loaded from {DEMO_CID}");

    let domain = model
        .ld_by_inst(LD_INST)
        .ok_or("the CID has no logical device LD0")?
        .domain_name(&model.ied_name);

    let mut write_access = WriteAccessPolicies::default();
    write_access.set(FC::Dc, true);
    write_access.set(FC::Cf, true);

    let server = IedServer::builder()
        .model(Arc::new(model))
        .bind(bind_addr)
        .config(IedServerConfig {
            max_mms_connections: 5,
            write_access_policies: write_access,
            ..Default::default()
        })
        .build()?;

    register_control_blocks(&server, &domain)?;
    let operated = register_control_object(&server, &domain)?;
    let updater_handles = resolve_updater_handles(&server, &domain)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        let handle = server.start().await?;
        println!("listening on {}", handle.bound_addr);
        println!("press Ctrl+C to stop");

        let updater = tokio::spawn(run_value_updater(server.clone(), updater_handles));

        tokio::signal::ctrl_c().await?;
        updater.abort();
        let count = operated.lock().expect("operate log lock").len();
        println!("shutting down after {count} control operations");
        handle.stop().await;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;

    Ok(())
}

/// The CID ships inside this crate, so the path resolves in a published
/// package as well as in the repository.
const DEMO_CID: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/models/demo.cid");

fn load_model(path: &Path) -> Result<IedModel, Box<dyn std::error::Error>> {
    let xml = std::fs::read_to_string(path)?;
    let raw = iec61850_scl::parse_scl(&xml)?;
    let resolved = iec61850_scl::ResolvedScl::from_raw(raw)?;
    Ok(resolved.build_model(IED_NAME)?)
}

// Model control blocks to server registrations

/// Register every data set and report control block the model declares.
///
/// The SCL parser produces the schema of the control blocks; the server needs
/// the same blocks bound to the live attribute slots, which is what this does.
fn register_control_blocks(
    server: &IedServer,
    domain: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let model = server.model();
    let ln0 = model
        .ld_by_inst(LD_INST)
        .and_then(|ld| ld.ln_by_name("LLN0"))
        .ok_or("LD0 has no LLN0")?;

    let mut datasets: HashMap<&str, Dataset> = HashMap::new();
    for ds in &ln0.datasets {
        let built = build_dataset(&model, domain, ln0, ds)?;
        println!(
            "data set {}/{} with {} members",
            domain,
            built.name,
            ds.entries.len()
        );
        server.register_dataset(domain.to_string(), built.clone());
        datasets.insert(ds.name.as_str(), built);
    }

    for rcb in &ln0.rcbs {
        let ds = datasets
            .get(rcb.dataset_ref.as_str())
            .ok_or_else(|| format!("RCB {} references unknown data set", rcb.name))?
            .clone();
        if rcb.is_buffered {
            let mms_path = format!("{domain}/LLN0$BR${}", rcb.name);
            let brcb = Brcb::new(rcb.name.clone(), ds.name.clone())
                .with_rpt_id(rcb.rpt_id.clone())
                .with_conf_rev(rcb.conf_rev)
                .with_trg_ops(trigger_options(rcb.trg_ops))
                .with_opt_flds(opt_flds(rcb))
                .with_buf_tm_ms(rcb.buf_tm_ms)
                .with_intg_pd_ms(rcb.intg_pd_ms);
            server.register_brcb(BufferedReportControl::new(mms_path.clone(), brcb), ds)?;
            println!("BRCB {mms_path} on {}", rcb.dataset_ref);
        } else {
            let mms_path = format!("{domain}/LLN0$RP${}", rcb.name);
            let urcb = Rcb::new(rcb.name.clone(), ds.name.clone())
                .with_rpt_id(rcb.rpt_id.clone())
                .with_conf_rev(rcb.conf_rev)
                .with_trg_ops(trigger_options(rcb.trg_ops))
                .with_opt_flds(opt_flds(rcb))
                .with_buf_tm_ms(rcb.buf_tm_ms)
                .with_intg_pd_ms(rcb.intg_pd_ms);
            server.register_urcb(ReportControl::new(&mms_path, urcb), ds)?;
            println!("URCB {mms_path} on {}", rcb.dataset_ref);
        }
    }
    Ok(())
}

/// Resolve a model data set into the server data set of live attribute slots.
fn build_dataset(
    model: &IedModel,
    domain: &str,
    owner: &LogicalNode,
    ds: &DataSet,
) -> Result<Dataset, Box<dyn std::error::Error>> {
    let mut out = Dataset::new(format!("{}${}", owner.full_name(), ds.name));
    for entry in &ds.entries {
        let da = resolve_da(model, &iec_path(domain, entry))
            .ok_or_else(|| format!("data set {} references missing {}", ds.name, entry.ln_name))?;
        out.push(DatasetEntry::new(data_reference(domain, entry), da.value));
    }
    Ok(out)
}

/// Object reference of a data set member in `ldName/lnName.doName.daName` form.
fn iec_path(domain: &str, entry: &DataSetEntry) -> String {
    format!("{domain}/{}.{}", entry.ln_name, entry.do_path.join("."))
}

/// Wire data reference of a data set member, `<domain>/<LN>$<FC>$<DO>$<DA>`
/// per IEC 61850-8-1. Reports carry it in the optional DataRef field.
fn data_reference(domain: &str, entry: &DataSetEntry) -> String {
    // An FCDA carries its daName as one dotted attribute path, so the dots are
    // normalized here: every level of the reference is separated by `$`.
    let path = entry.do_path.join(".").replace('.', "$");
    format!("{domain}/{}${}${path}", entry.ln_name, entry.fc.as_str())
}

fn trigger_options(trg: TrgOps) -> TriggerOptions {
    let mut out = TriggerOptions::NONE;
    for (model_bit, server_bit) in [
        (TrgOps::DCHG, TriggerOptions::DATA_CHANGED),
        (TrgOps::QCHG, TriggerOptions::QUALITY_CHANGED),
        (TrgOps::DUPD, TriggerOptions::DATA_UPDATE),
        (TrgOps::INTEGRITY, TriggerOptions::INTEGRITY),
        (TrgOps::GI, TriggerOptions::GI),
    ] {
        if trg.contains(model_bit) {
            out = out.union(server_bit);
        }
    }
    out
}

/// Optional report fields, with the two BRCB-only bits cleared on a URCB.
fn opt_flds(rcb: &ReportControlBlock) -> OptFlds {
    if rcb.is_buffered {
        rcb.opt_flds
    } else {
        rcb.opt_flds.mask_urcb()
    }
}

// Control object

/// Every accepted Operate, keyed by object reference.
type OperateLog = Arc<Mutex<HashMap<String, MmsValue>>>;

/// Records the control value and reports success, standing in for the process
/// side of a real IED.
struct RecordingHandler {
    key: String,
    log: OperateLog,
}

impl ControlHandler for RecordingHandler {
    fn operate<'a>(
        &'a self,
        _action: &'a ControlAction,
        ctl_val: &'a MmsValue,
        _test: bool,
    ) -> OperateFuture<'a> {
        let key = self.key.clone();
        let log = Arc::clone(&self.log);
        let value = ctl_val.clone();
        Box::pin(async move {
            println!("operate {key} = {value:?}");
            log.lock().expect("operate log lock").insert(key, value);
            Ok::<(), ControlAddCause>(())
        })
    }
}

/// Register `GGIO1.SPCSO1` under the control model the CID configures.
fn register_control_object(
    server: &IedServer,
    domain: &str,
) -> Result<OperateLog, Box<dyn std::error::Error>> {
    let model = server.model();
    let ctl_model = control_model(&model, domain, "GGIO1", "SPCSO1")?;
    let log: OperateLog = Arc::new(Mutex::new(HashMap::new()));

    let obj = ControlObject::new(ControlObjectConfig {
        name: "SPCSO1".into(),
        ln_name: "GGIO1".into(),
        domain: domain.into(),
        ctl_model,
        sbo_timeout_ms: 30_000,
        sbo_class: SboClass::OperateOnce,
    });
    let entry = ControlObjectEntry::new(obj)
        .with_check(Arc::new(AlwaysAcceptCheckHandler) as Arc<dyn CheckHandler>)
        .with_wait(Arc::new(AlwaysAcceptWaitHandler) as Arc<dyn WaitForExecutionHandler>)
        .with_operate(Arc::new(RecordingHandler {
            key: format!("{domain}/GGIO1.SPCSO1"),
            log: Arc::clone(&log),
        }) as Arc<dyn ControlHandler>);
    server.control_objects().register(entry);
    println!("control object {domain}/GGIO1.SPCSO1 ({ctl_model:?})");
    Ok(log)
}

/// Read `ctlModel` (FC=CF) off the model and map it to the runtime enum.
fn control_model(
    model: &IedModel,
    domain: &str,
    ln: &str,
    do_name: &str,
) -> Result<ControlModel, Box<dyn std::error::Error>> {
    let path = format!("{domain}/{ln}.{do_name}.ctlModel");
    let da = resolve_da(model, &path).ok_or_else(|| format!("{path} not found in the model"))?;
    let ord = match da.snapshot() {
        MmsValue::Integer(v) => v,
        other => return Err(format!("{path} is {other:?}, not an enumerated value").into()),
    };
    Ok(match ord {
        0 => ControlModel::StatusOnly,
        1 => ControlModel::DirectNormal,
        2 => ControlModel::SboNormal,
        3 => ControlModel::DirectEnhanced,
        4 => ControlModel::SboEnhanced,
        other => return Err(format!("{path} holds unknown ctlModel {other}").into()),
    })
}

// Process value updates

/// Live slots the background task writes to.
struct UpdaterHandles {
    ind1: DataAttribute,
    tot_w: DataAttribute,
    hz: DataAttribute,
    phv_a: DataAttribute,
}

fn resolve_updater_handles(
    server: &IedServer,
    domain: &str,
) -> Result<UpdaterHandles, Box<dyn std::error::Error>> {
    let model = server.model();
    let need = |path: String| -> Result<DataAttribute, Box<dyn std::error::Error>> {
        resolve_da(&model, &path).ok_or_else(|| format!("{path} not found in the model").into())
    };
    Ok(UpdaterHandles {
        ind1: need(format!("{domain}/GGIO1.Ind1.stVal"))?,
        tot_w: need(format!("{domain}/MMXU1.TotW.mag.f"))?,
        hz: need(format!("{domain}/MMXU1.Hz.mag.f"))?,
        phv_a: need(format!("{domain}/MMXU1.PhV.phsA.cVal.mag.f"))?,
    })
}

/// Drive the process values once a second so report triggers fire.
async fn run_value_updater(server: IedServer, handles: UpdaterHandles) {
    let mut on = false;
    let mut ticks: f32 = 0.0;
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    loop {
        ticker.tick().await;
        on = !on;
        ticks += 1.0;
        if let Err(e) = server.update_boolean(&handles.ind1, on) {
            eprintln!("update Ind1.stVal failed: {e}");
        }
        for (da, value) in [
            (&handles.tot_w, 1000.0 + ticks),
            (&handles.hz, 50.0 + (ticks % 10.0) * 0.01),
            (&handles.phv_a, 230.0 + (ticks % 5.0)),
        ] {
            if let Err(e) = server.update_float32(da, value) {
                eprintln!("update {} failed: {e}", da.name);
            }
        }
    }
}

/// Resolve an object reference to an owned handle on the shared value slot.
///
/// The returned attribute shares the `Arc` of the model node, so
/// `IedServer::update_*` writes into the served model.
fn resolve_da(model: &IedModel, iec_path: &str) -> Option<DataAttribute> {
    let r = ObjectRef::parse_iec(iec_path).ok()?;
    match model.node_by_object_ref(&r)? {
        NodeRef::Da(da) => Some(DataAttribute {
            name: da.name.clone(),
            fc: da.fc,
            ty: da.ty,
            trg_ops: da.trg_ops,
            value: da.value.clone(),
            children: Vec::new(),
        }),
        _ => None,
    }
}
