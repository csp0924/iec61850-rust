//! Runs one MMS association against a server, below the IEC 61850 layer.
//!
//! `MmsClient` speaks ISO 9506 over the OSI stack of IEC 61850-8-1 and knows
//! nothing of logical nodes or functional constraints: it addresses a domain
//! and an item name. This example walks a whole association with it:
//! Initiate, GetNameList, Read, Write, read back, then Conclude and Release.
//!
//! Pairs with the `min_server` example of `iec61850-server`, which serves the
//! `DemoIEDLD0` domain the item names below belong to.
//!
//! ```sh
//! # Terminal 1
//! cargo run -p iec61850-server --example min_server
//!
//! # Terminal 2
//! MMS_EXAMPLE_PORT=8102 cargo run -p iec61850-mms --example mms_client
//! ```
//!
//! Expected stdout:
//!
//! ```text
//! [connect] 127.0.0.1:8102
//! [connect] negotiated max PDU size = 65000 bytes
//! [get_name_list] domain=DemoIEDLD0, class=NamedVariable
//! [get_name_list] 100 names, more_follows=true; first 5:
//!   - GGIO1
//!   - GGIO1$CF
//!   - GGIO1$CF$SPCSO1
//!   - GGIO1$CF$SPCSO1$ctlModel
//!   - GGIO1$CO
//! [read] DemoIEDLD0/GGIO1$ST$Ind1$stVal
//! [read] value = Boolean(false)
//! [write] DemoIEDLD0/LLN0$DC$NamPlt$vendor = "mms-client"
//! [read-back] value matches
//! [disconnect] ok
//! ```
//!
//! Host and port come from `MMS_EXAMPLE_HOST` and `MMS_EXAMPLE_PORT` and
//! default to `127.0.0.1` and port 102.
//!
//! # Exit status
//!
//! `0` when the association completes, `1` otherwise. A server that is not
//! listening produces an I/O error at connect rather than a panic.

use std::process::ExitCode;

use iec61850_mms::mms::pdu::ObjectClass;
use iec61850_mms::mms::MmsData;
use iec61850_mms::{ClientError, MmsClientBuilder};

/// MMS domain of the demonstration IED: the IED name and the LD instance.
const DOMAIN: &str = "DemoIEDLD0";
/// Item names carry the functional constraint between `$` separators.
const VENDOR_ITEM: &str = "LLN0$DC$NamPlt$vendor";
const SPS_ITEM: &str = "GGIO1$ST$Ind1$stVal";

#[tokio::main]
async fn main() -> ExitCode {
    // The example installs no tracing subscriber, so that it depends on
    // nothing beyond the crate under demonstration.
    if std::env::var("RUST_LOG").is_ok() {
        eprintln!("RUST_LOG is set but this example installs no tracing subscriber");
    }

    let host = std::env::var("MMS_EXAMPLE_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = std::env::var("MMS_EXAMPLE_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(102);

    match run(&host, port).await {
        Ok(()) => {
            println!("\n[OK] association completed");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("\n[FAIL] {e}");
            eprintln!("an I/O error here usually means no server is listening");
            ExitCode::FAILURE
        }
    }
}

async fn run(host: &str, port: u16) -> Result<(), ClientError> {
    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(5_000)
        .build();

    println!("[connect] {host}:{port}");
    client.connect(host, port).await?;
    println!(
        "[connect] negotiated max PDU size = {} bytes",
        client.negotiated_max_pdu_size()
    );

    // GetNameList enumerates the named variables of one domain.
    println!("[get_name_list] domain={DOMAIN}, class=NamedVariable");
    let (names, more) = client
        .get_name_list(ObjectClass::NamedVariable, Some(DOMAIN), None)
        .await?;
    println!(
        "[get_name_list] {} names, more_follows={more}; first 5:",
        names.len()
    );
    for n in names.iter().take(5) {
        println!("  - {n}");
    }

    println!("[read] {DOMAIN}/{SPS_ITEM}");
    match client.read(DOMAIN, SPS_ITEM).await {
        Ok(val) => println!("[read] value = {val:?}"),
        Err(e) => println!("[read] failed, which is not fatal here: {e}"),
    }

    // Writing the name plate needs the server to allow FC=DC writes.
    let new_vendor = "mms-client";
    println!("[write] {DOMAIN}/{VENDOR_ITEM} = {new_vendor:?}");
    client
        .write(
            DOMAIN,
            VENDOR_ITEM,
            MmsData::VisibleString(new_vendor.to_string()),
        )
        .await?;
    println!("[write] ok");

    println!("[read-back] {DOMAIN}/{VENDOR_ITEM}");
    let got = client.read(DOMAIN, VENDOR_ITEM).await?;
    println!("[read-back] value = {got:?}");
    match &got {
        MmsData::VisibleString(s) if s == new_vendor => {
            println!("[read-back] value matches");
        }
        _ => {
            eprintln!("[read-back] value differs, so the server refused the write");
        }
    }

    println!("[disconnect] Conclude + Release");
    client.disconnect().await?;
    println!("[disconnect] ok");

    Ok(())
}
