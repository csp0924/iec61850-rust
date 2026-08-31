//! Serves the demonstration IED with a log control block and a seeded journal.
//!
//! Loads `examples/models/demo.cid` and registers one LCB,
//! `DemoIEDLD0/LLN0$LG$evlog`, whose journal already holds 20 entries when the
//! server starts listening. A client can then read the journal back with
//! `ReadJournal`, filtered by time or by entry identifier, without waiting for
//! events to accumulate.
//!
//! Each entry carries one boolean variable,
//! `DemoIEDLD0/GGIO1$ST$Ind1$stVal`, with reason code `0x02` (data change),
//! and the entries are 100 ms apart starting at a fixed epoch, so the same run
//! produces the same journal every time.
//!
//! ```sh
//! cargo run -p iec61850-server --example server_with_log
//! ```
//!
//! Expected stdout:
//!
//! ```text
//! serving DemoIEDLD0 from .../examples/models/demo.cid
//! LCB DemoIEDLD0/LLN0$LG$evlog seeded with 20 entries
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

use iec61850_model::tree::IedModel;
use iec61850_model::{MmsValue, FC};
use iec61850_server::{
    IedServer, IedServerConfig, InMemoryLogStorage, LogControl, LogControlBlock, LogStorage,
    TriggerOptions, WriteAccessPolicies,
};

const IED_NAME: &str = "DemoIED";
const LD_INST: &str = "LD0";
const LCB_ITEM: &str = "LLN0$LG$evlog";
/// Epoch of the first journal entry, fixed so the seeded journal is reproducible.
const BASE_TIME_MS: u64 = 1_700_000_000_000;
const TIME_STEP_MS: u64 = 100;
const ENTRY_COUNT: usize = 20;
/// Reason code recorded on every seeded entry: data change.
const REASON_DATA_CHANGE: u8 = 0x02;

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

    let lcb_path = format!("{domain}/{LCB_ITEM}");
    register_seeded_lcb(&server, &domain, &lcb_path)?;
    println!("LCB {lcb_path} seeded with {ENTRY_COUNT} entries");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        let handle = server.start().await?;
        println!("listening on {}", handle.bound_addr);
        println!("press Ctrl+C to stop");
        tokio::signal::ctrl_c().await?;
        println!("shutting down");
        handle.stop().await;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;

    Ok(())
}

/// Register the LCB and fill its journal before the server accepts clients.
fn register_seeded_lcb(
    server: &IedServer,
    domain: &str,
    lcb_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let storage: Arc<dyn LogStorage> = Arc::new(InMemoryLogStorage::new());
    let block = LogControlBlock::new("evlog")
        .with_dataset("LLN0$evlogds")
        .with_log_ref(lcb_path)
        .with_trg_ops(TriggerOptions::DATA_CHANGED);
    let lc = LogControl::new(lcb_path, block).with_storage(storage);
    lc.set_log_ena(true)
        .map_err(|e| format!("set_log_ena failed: {e}"))?;

    let data_ref = format!("{domain}/GGIO1$ST$Ind1$stVal");
    for i in 0..ENTRY_COUNT {
        let time_ms = BASE_TIME_MS + (i as u64) * TIME_STEP_MS;
        lc.log_single_value(
            time_ms,
            &data_ref,
            MmsValue::Boolean(i % 2 == 0),
            REASON_DATA_CHANGE,
        )?;
    }

    server.register_log_control(domain, LCB_ITEM, Arc::new(lc));
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
