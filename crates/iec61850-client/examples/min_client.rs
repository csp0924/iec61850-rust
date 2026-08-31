//! The smallest complete IEC 61850 client: connect, read, write, disconnect.
//!
//! Reads four data attributes of the demonstration IED and writes the vendor
//! name back, then closes the association. Every object reference below names
//! an object of `crates/iec61850-server/examples/models/demo.cid`,
//! so the example needs no knowledge
//! of the server beyond the SCL both sides share.
//!
//! Pairs with the `min_server` example.
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
//! connecting to 127.0.0.1:8102
//! connected
//! read  DemoIEDLD0/LLN0.NamPlt.vendor[DC] = VisibleString("rust61850")
//! read  DemoIEDLD0/MMXU1.TotW.mag.f[MX] = Float32(0.0)
//! read  DemoIEDLD0/MMXU1.TotW.q[MX] = BitString { padding: 3, data: [0, 0] }
//! read  DemoIEDLD0/GGIO1.Ind1.stVal[ST] = Boolean(false)
//! write DemoIEDLD0/LLN0.NamPlt.vendor[DC] = "min-client"
//! disconnected
//! ```
//!
//! Host and port default to `127.0.0.1` and `8102` and can be overridden:
//!
//! ```sh
//! cargo run -p iec61850-client --example min_client -- 127.0.0.1 102
//! ```

use iec61850_client::IedConnection;
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_model::value::MmsValue;
use iec61850_model::FC;
use std::env;

#[tokio::main(flavor = "current_thread")]
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
    println!("connected");

    let vendor = "DemoIEDLD0/LLN0.NamPlt.vendor";
    for (object_ref, fc) in [
        (vendor, FC::Dc),
        ("DemoIEDLD0/MMXU1.TotW.mag.f", FC::Mx),
        ("DemoIEDLD0/MMXU1.TotW.q", FC::Mx),
        ("DemoIEDLD0/GGIO1.Ind1.stVal", FC::St),
    ] {
        match conn.read_object(object_ref, fc).await {
            Ok(v) => println!("read  {object_ref}[{}] = {v:?}", fc.as_str()),
            Err(e) => println!("read  {object_ref}[{}] err: {e}", fc.as_str()),
        }
    }

    // The server opens FC=DC for writing, which makes the name plate the one
    // attribute this example can write without a control service.
    match conn
        .write_object(
            vendor,
            FC::Dc,
            MmsValue::VisibleString("min-client".to_string()),
        )
        .await
    {
        Ok(()) => println!("write {vendor}[DC] = \"min-client\""),
        Err(e) => println!("write {vendor}[DC] err: {e}"),
    }

    conn.disconnect().await?;
    println!("disconnected");
    Ok(())
}
