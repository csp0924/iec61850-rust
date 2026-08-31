//! Walks the whole object model of a server and prints it.
//!
//! Exercises the directory services of IEC 61850-7-2 in the order a browsing
//! tool uses them:
//!
//! 1. `GetServerDirectory` for the logical devices
//! 2. `GetLogicalDeviceDirectory` for the logical nodes of each LD
//! 3. `GetLogicalNodeDirectory` for the data objects of each LN, and for the
//!    URCBs, BRCBs and data sets of LLN0
//! 4. `GetVariableAccessAttributes` on one measured value, printing its type tree
//! 5. a forced refresh of the cached device model
//!
//! Pairs with any of the server examples. What a client discovers under LLN0
//! is what the server has registered, not what its model declares: a control
//! block or data set is served out of the reporting engine and the data set
//! registry, so an object nothing registered is deliberately left out of the
//! directory rather than advertised and then refused.
//!
//! That makes the three servers differ, and each line below is from a real run:
//!
//! - `server_from_scl` loads `examples/models/demo.cid` and registers both data
//!   sets and both report control blocks, which is the transcript below.
//!   `gcbStatus` is declared in the CID but never registered by that example,
//!   so it is absent from the GOOSE control block list.
//! - `min_server` loads the same CID and registers nothing, so it prints
//!   `URCB: []`, `BRCB: []`, `DataSet: []` and 135 named variables.
//! - `server_with_reporting` builds its model in Rust and registers one report
//!   control block and one data set, so it prints `URCB: ["urcbMeas"]`,
//!   `BRCB: []`, `DataSet: ["dsMeas"]` and 129 named variables.
//!
//! ```sh
//! # Terminal 1
//! cargo run -p iec61850-server --example server_from_scl
//!
//! # Terminal 2
//! cargo run -p iec61850-client --example directory_browser
//! ```
//!
//! Expected stdout:
//!
//! ```text
//! connecting to 127.0.0.1:8102
//! connected
//!
//! server directory (1 LD)
//!   LD: DemoIEDLD0
//!
//! DemoIEDLD0 (4 LN)
//!   GGIO1: 5 DO ["SPCSO1", "Ind1", "Ind2", "Ind3", "Ind4"]
//!   LLN0: 4 DO ["NamPlt", "Beh", "Health", "Mod"]
//!     URCB: ["urcbMeas"]
//!     BRCB: ["brcbMeas"]
//!     DataSet: ["dsMeas", "dsStatus"]
//!   LPHD1: 3 DO ["PhyNam", "PhyHealth", "Proxy"]
//!   MMXU1: 3 DO ["Hz", "PhV", "TotW"]
//!
//! type of DemoIEDLD0/MMXU1.TotW.mag[MX]
//! Structure {
//!   f:
//!     FloatingPoint(format=32, exponent=8)
//! }
//!
//! device model refreshed: 1 LD, 137 named variables
//! ```
//!
//! Host and port default to `127.0.0.1` and `8102` and can be overridden.

use iec61850_client::{AcsiClass, IedConnection, StructComponent, TypeSpecification};
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

    // The logical devices, which are the MMS domains.
    let lds = conn.get_server_directory(false).await?;
    println!("server directory ({} LD)", lds.len());
    for ld in &lds {
        println!("  LD: {ld}");
    }
    println!();

    // Every LD down to its LNs, and every LN down to its DOs.
    for ld in &lds {
        let lns = conn.get_logical_device_directory(ld).await?;
        println!("{ld} ({} LN)", lns.len());
        for ln in &lns {
            let ln_ref = format!("{ld}/{ln}");
            let dos = match conn
                .get_logical_node_directory(&ln_ref, AcsiClass::DataObject)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    println!("  {ln}: get_logical_node_directory(DataObject) err: {e}");
                    continue;
                }
            };
            println!("  {ln}: {} DO {:?}", dos.len(), dos);

            // Control blocks and data sets live under LLN0.
            if ln == "LLN0" {
                if let Ok(urcbs) = conn
                    .get_logical_node_directory(&ln_ref, AcsiClass::Urcb)
                    .await
                {
                    println!("    URCB: {urcbs:?}");
                }
                if let Ok(brcbs) = conn
                    .get_logical_node_directory(&ln_ref, AcsiClass::Brcb)
                    .await
                {
                    println!("    BRCB: {brcbs:?}");
                }
                if let Ok(dsets) = conn
                    .get_logical_node_directory(&ln_ref, AcsiClass::DataSet)
                    .await
                {
                    println!("    DataSet: {dsets:?}");
                }
            }
        }
        println!();
    }

    // The type tree of one measured value.
    let gva_ref = "DemoIEDLD0/MMXU1.TotW.mag";
    println!("type of {gva_ref}[MX]");
    match conn.get_variable_specification(gva_ref, FC::Mx).await {
        Ok(ts) => print_type_spec(&ts, 0),
        Err(e) => println!("  not present on this server: {e}"),
    }
    println!();

    // A forced refresh, which re-reads the model rather than using the cache.
    let model = conn.get_device_model_from_server().await?;
    let total_vars: usize = model
        .logical_devices
        .iter()
        .map(|ld| ld.variables.len())
        .sum();
    println!(
        "device model refreshed: {} LD, {} named variables",
        model.logical_devices.len(),
        total_vars
    );

    let _ = conn.disconnect().await;
    println!("\ndisconnected");
    Ok(())
}

fn print_type_spec(ts: &TypeSpecification, indent: usize) {
    let pad = "  ".repeat(indent);
    match ts {
        TypeSpecification::Boolean => println!("{pad}Boolean"),
        TypeSpecification::BitString { bits } => println!("{pad}BitString({bits})"),
        TypeSpecification::Integer { width_bits } => println!("{pad}Integer({width_bits} bits)"),
        TypeSpecification::Unsigned { width_bits } => {
            println!("{pad}Unsigned({width_bits} bits)")
        }
        TypeSpecification::FloatingPoint {
            format_width,
            exponent_width,
        } => println!("{pad}FloatingPoint(format={format_width}, exponent={exponent_width})"),
        TypeSpecification::OctetString { max_octets } => {
            println!("{pad}OctetString(max={max_octets})")
        }
        TypeSpecification::VisibleString { max_chars } => {
            println!("{pad}VisibleString(max={max_chars})")
        }
        TypeSpecification::MmsString { max_chars } => {
            println!("{pad}MmsString(max={max_chars})")
        }
        TypeSpecification::UtcTime => println!("{pad}UtcTime"),
        TypeSpecification::BinaryTime { use_long_form } => {
            println!("{pad}BinaryTime(long={use_long_form})")
        }
        TypeSpecification::Array {
            element_count,
            element_type,
        } => {
            println!("{pad}Array[{element_count}]");
            print_type_spec(element_type, indent + 1);
        }
        TypeSpecification::Structure { components } => {
            println!("{pad}Structure {{");
            for c in components {
                print_struct_component(c, indent + 1);
            }
            println!("{pad}}}");
        }
        TypeSpecification::Unknown(tag) => println!("{pad}Unknown(tag=0x{tag:02x})"),
    }
}

fn print_struct_component(c: &StructComponent, indent: usize) {
    let pad = "  ".repeat(indent);
    println!("{pad}{}:", c.name);
    print_type_spec(&c.type_spec, indent + 1);
}
