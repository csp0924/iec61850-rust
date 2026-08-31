//! Shortest path from an ICD file to a running server: build-time code
//! generation, then start the model it produced.
//!
//! # Running
//!
//! ```sh
//! # Binds 0.0.0.0:10102 by default, since port 102 needs privileges. Runs
//! # until Ctrl-C, or until DEMO_AUTO_EXIT_MS elapses.
//! cargo run -p iec61850-scl-build-example
//!
//! # Exit unattended, for CI or a smoke test:
//! DEMO_AUTO_EXIT_MS=2000 cargo run -p iec61850-scl-build-example
//!
//! # Bind somewhere else:
//! BIND=0.0.0.0:8102 cargo run -p iec61850-scl-build-example
//! ```
//!
//! # Flow
//!
//! 1. `build.rs` turns `scl/demo.icd` into `OUT_DIR/model.rs` at build time,
//!    which defines `pub fn build_Demo_model() -> IedModel`.
//! 2. `iec61850_scl::include_compiled_model!()` includes that file here.
//! 3. `build_Demo_model()` yields the model, which `IedServer::builder()`
//!    turns into a running server.
//! 4. Ctrl-C, or the `DEMO_AUTO_EXIT_MS` deadline, triggers a graceful
//!    shutdown.

// Brings the generated build_Demo_model() into scope; the macro expands to
// `include!(concat!(env!("OUT_DIR"), "/model.rs"))`.
iec61850_scl::include_compiled_model!();

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iec61850_server::{IedServer, IedServerConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Output goes through println!, so the example pulls in no subscriber crate.
    let bind_addr: SocketAddr = env::var("BIND")
        .unwrap_or_else(|_| "0.0.0.0:10102".to_string())
        .parse()?;

    // Step 1: take the generated IedModel. The generated function is named
    // `build_<sanitized IED name>_model`; this demo uses IED name "Demo".
    let model = build_Demo_model();
    println!(
        "[server_from_scl] loaded generated IedModel: ied_name={}, logical_devices={}",
        model.ied_name,
        model.lds.len()
    );

    // Step 2: start the server.
    let server = IedServer::builder()
        .model(Arc::new(model))
        .bind(bind_addr)
        .config(IedServerConfig {
            max_mms_connections: 5,
            ..Default::default()
        })
        .build()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        let handle = server.start().await?;
        println!(
            "[server_from_scl] listening on {} (IED=Demo, LD=LD0)",
            handle.bound_addr
        );

        // With DEMO_AUTO_EXIT_MS set the demo quits after that many
        // milliseconds; otherwise it waits for Ctrl-C. CI takes the timed path
        // so a smoke test cannot hang.
        match env::var("DEMO_AUTO_EXIT_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
        {
            Some(ms) => {
                println!("[server_from_scl] auto exit in {ms}ms");
                tokio::time::sleep(Duration::from_millis(ms)).await;
            }
            None => {
                println!("[server_from_scl] press Ctrl+C to stop");
                let _ = tokio::signal::ctrl_c().await;
                println!("[server_from_scl] shutdown requested");
            }
        }

        handle.stop().await;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;

    Ok(())
}
