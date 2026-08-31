//! Runs the type-narrow read and write helpers over one association.
//!
//! Each helper returns a Rust type instead of an `MmsValue`, so the example
//! reads a string, a float, a quality, a timestamp and a boolean off the
//! demonstration IED and writes the vendor name back. Every object reference
//! names an object of
//! `crates/iec61850-server/examples/models/demo.cid`.
//!
//! Pairs with the `server_from_scl` example, whose background task moves the
//! measured values between runs.
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
//! connecting to 127.0.0.1:8102
//! connected
//!
//! read  DemoIEDLD0/LLN0.NamPlt.vendor[DC] = "rust61850"
//! write DemoIEDLD0/LLN0.NamPlt.vendor[DC] = "read-write-cycle" OK
//! read  DemoIEDLD0/LLN0.NamPlt.vendor[DC] = "read-write-cycle" (round trip)
//!
//! read  DemoIEDLD0/MMXU1.TotW.mag.f[MX] = 1027
//! read  DemoIEDLD0/MMXU1.TotW.q[MX] = Quality(0)
//! read  DemoIEDLD0/MMXU1.TotW.t[MX] = [0, 0, 0, 0, 0, 0, 0, 0]
//!
//! read  DemoIEDLD0/GGIO1.Ind1.stVal[ST] = true
//!
//! disconnected
//! ```
//!
//! The measured value depends on how long the paired server has been running,
//! and the timestamp stays zero until a time source sets it.
//!
//! Host and port default to `127.0.0.1` and `8102` and can be overridden.

use iec61850_client::IedConnection;
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_model::FC;
use std::env;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let port: u16 = env::args()
        .nth(2)
        .unwrap_or_else(|| "8102".to_string())
        .parse()?;

    let mms = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    let conn = IedConnection::with_mms_client(mms);

    println!("connecting to {host}:{port}");
    conn.connect(&host, port).await?;
    println!("connected\n");

    // A string round trip: read, write, read back.
    let vendor_ref = "DemoIEDLD0/LLN0.NamPlt.vendor";
    match conn.read_string(vendor_ref, FC::Dc).await {
        Ok(v) => println!("read  {vendor_ref}[DC] = {v:?}"),
        Err(e) => println!("read  {vendor_ref}[DC] err: {e}"),
    }
    match conn
        .write_visible_string(vendor_ref, FC::Dc, "read-write-cycle")
        .await
    {
        Ok(()) => println!("write {vendor_ref}[DC] = \"read-write-cycle\" OK"),
        Err(e) => println!("write {vendor_ref}[DC] err: {e}"),
    }
    match conn.read_string(vendor_ref, FC::Dc).await {
        Ok(v) => println!("read  {vendor_ref}[DC] = {v:?} (round trip)"),
        Err(e) => println!("read  {vendor_ref}[DC] err: {e}"),
    }
    println!();

    // The three parts of a measured value: magnitude, quality, timestamp.
    let mag_ref = "DemoIEDLD0/MMXU1.TotW.mag.f";
    let q_ref = "DemoIEDLD0/MMXU1.TotW.q";
    let t_ref = "DemoIEDLD0/MMXU1.TotW.t";
    match conn.read_float(mag_ref, FC::Mx).await {
        Ok(v) => println!("read  {mag_ref}[MX] = {v}"),
        Err(e) => println!("read  {mag_ref}[MX] err: {e}"),
    }
    match conn.read_quality(q_ref, FC::Mx).await {
        Ok(q) => println!("read  {q_ref}[MX] = {q:?}"),
        Err(e) => println!("read  {q_ref}[MX] err: {e}"),
    }
    match conn.read_timestamp(t_ref, FC::Mx).await {
        Ok(ts) => println!("read  {t_ref}[MX] = {ts:?}"),
        Err(e) => println!("read  {t_ref}[MX] err: {e}"),
    }
    println!();

    // A single point status.
    let ind1_ref = "DemoIEDLD0/GGIO1.Ind1.stVal";
    match conn.read_boolean(ind1_ref, FC::St).await {
        Ok(v) => println!("read  {ind1_ref}[ST] = {v}"),
        Err(e) => println!("read  {ind1_ref}[ST] err: {e}"),
    }

    let _ = conn.disconnect().await;
    println!("\ndisconnected");
    Ok(())
}
