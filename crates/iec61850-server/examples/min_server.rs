//! The smallest complete IEC 61850 server: load an SCL file, serve it over MMS.
//!
//! The model comes from `examples/models/demo.cid`, so nothing about the data
//! model is written in Rust here. A client can browse the directory, read every
//! data attribute and write `LLN0.NamPlt.vendor`, whose functional constraint
//! (DC) this example adds to the write-access policy.
//!
//! Pairs with the `min_client` example.
//!
//! ```sh
//! # Terminal 1
//! cargo run -p iec61850-server --example min_server
//!
//! # Terminal 2
//! cargo run -p iec61850-client --example min_client
//! ```
//!
//! Expected stdout:
//!
//! ```text
//! loaded DemoIED from .../examples/models/demo.cid
//! serving MMS domain DemoIEDLD0 with 4 logical nodes
//! listening on 127.0.0.1:8102
//! press Ctrl+C to stop
//! ```
//!
//! The default bind address is `127.0.0.1:8102` rather than the port 102 the
//! CID names, so the example runs without elevated privileges. Pass a bind
//! address to override it:
//!
//! ```sh
//! cargo run -p iec61850-server --example min_server -- 127.0.0.1:102
//! ```

use std::env;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use iec61850_model::tree::IedModel;
use iec61850_model::FC;
use iec61850_server::{IedServer, IedServerConfig, WriteAccessPolicies};

/// IED served by this example, and the name of the IED element in the CID.
const IED_NAME: &str = "DemoIED";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr: SocketAddr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8102".to_string())
        .parse()?;

    let model = load_model(Path::new(DEMO_CID))?;
    println!("loaded {IED_NAME} from {DEMO_CID}");
    for ld in &model.lds {
        println!(
            "serving MMS domain {} with {} logical nodes",
            ld.domain_name(&model.ied_name),
            ld.lns.len()
        );
    }

    // The CID gives NamPlt.vendor the DC constraint, which is read-only under
    // the default policy; opening it lets the paired client demonstrate Write.
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

/// The CID ships inside this crate, so the path resolves from any working
/// directory, and in a published package as well as in the repository.
const DEMO_CID: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/models/demo.cid");

/// Parse the SCL file and build the runtime model of `IED_NAME`.
fn load_model(path: &std::path::Path) -> Result<IedModel, Box<dyn std::error::Error>> {
    let xml = std::fs::read_to_string(path)?;
    let raw = iec61850_scl::parse_scl(&xml)?;
    let resolved = iec61850_scl::ResolvedScl::from_raw(raw)?;
    Ok(resolved.build_model(IED_NAME)?)
}
