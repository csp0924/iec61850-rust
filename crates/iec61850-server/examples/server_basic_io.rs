//! Serves the demonstration IED with live process values.
//!
//! Loads `examples/models/demo.cid`, opens the name plate for writing and runs
//! a background task that moves the process values once a second: `Ind1`
//! toggles and the three measured values ramp. That is enough for a client to
//! see a model whose values change, without any reporting or control service.
//!
//! Pairs with `min_client`, `read_write_cycle` and `directory_browser`.
//!
//! ```sh
//! # Terminal 1
//! cargo run -p iec61850-server --example server_basic_io
//!
//! # Terminal 2
//! cargo run -p iec61850-client --example read_write_cycle
//! ```
//!
//! Expected stdout:
//!
//! ```text
//! serving DemoIEDLD0 from .../examples/models/demo.cid
//! listening on 127.0.0.1:8102
//! press Ctrl+C to stop
//! ```
//!
//! The default bind address is `127.0.0.1:8102` rather than the port 102 the
//! CID names, so the example runs without elevated privileges. Pass a bind
//! address to override it.

use std::env;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use iec61850_model::tree::{DataAttribute, IedModel};
use iec61850_model::{NodeRef, ObjectRef, FC};
use iec61850_server::{IedServer, IedServerConfig, WriteAccessPolicies};

const IED_NAME: &str = "DemoIED";
const LD_INST: &str = "LD0";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr: SocketAddr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8102".to_string())
        .parse()?;

    let model = load_model(Path::new(DEMO_CID))?;
    let domain = model
        .ld_by_inst(LD_INST)
        .ok_or("the CID has no logical device LD0")?
        .domain_name(&model.ied_name);
    println!("serving {domain} from {DEMO_CID}");

    // The name plate carries the DC constraint, which the default policy keeps
    // read-only; opening it lets a client demonstrate Write.
    let mut write_access = WriteAccessPolicies::default();
    write_access.set(FC::Dc, true);

    let server = IedServer::builder()
        .model(Arc::new(model))
        .bind(bind_addr)
        .config(IedServerConfig {
            max_mms_connections: 5,
            write_access_policies: write_access,
            ..Default::default()
        })
        .build()?;

    let handles = resolve_handles(&server, &domain)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        let handle = server.start().await?;
        println!("listening on {}", handle.bound_addr);
        println!("press Ctrl+C to stop");

        let updater = tokio::spawn(run_value_updater(server.clone(), handles));
        tokio::signal::ctrl_c().await?;
        println!("shutting down");
        updater.abort();
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

/// Live slots the background task writes to.
struct UpdaterHandles {
    ind1: DataAttribute,
    tot_w: DataAttribute,
    hz: DataAttribute,
    phv_a: DataAttribute,
}

fn resolve_handles(
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

/// Move the process values once a second so a client sees them change.
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
