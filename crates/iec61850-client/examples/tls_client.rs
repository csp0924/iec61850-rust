//! Connects to a server over TLS and runs one read and one write.
//!
//! Shows the mutually authenticated profile of IEC 62351-4: the client presents
//! its own certificate and validates the server certificate against the given
//! CA, then speaks MMS over the established channel. Object references name
//! objects of
//! `crates/iec61850-server/examples/models/demo.cid`.
//!
//! Unlike the other client examples this one needs certificates, so it takes
//! them as arguments and pairs with a server built through
//! `IedServerBuilder::with_tls_acceptor` rather than with an example here.
//!
//! ```sh
//! cargo run -p iec61850-client --features tls --example tls_client -- \
//!     127.0.0.1 3782 ca.pem client-cert.pem client-key.pem
//! ```
//!
//! Expected stdout:
//!
//! ```text
//! connecting to tls://127.0.0.1:3782 (resolved 127.0.0.1:3782)
//! TLS handshake and MMS Initiate completed
//! read DemoIEDLD0/MMXU1.TotW.mag.f = 1003
//! write DemoIEDLD0/LLN0.NamPlt.vendor accepted
//! all stages passed
//! ```
//!
//! `host` must match a subject alternative name of the server certificate, or
//! the peer verification rejects the connection.
//!
//! # Exit status
//!
//! `0` when every stage passes, `1` when the connection or the arguments fail,
//! `2` when the connection succeeds but a stage does not.

use iec61850_client::IedConnection;
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_model::FC;
use iec61850_tls::{TlsConfigBuilder, TlsConnector};
use rustls::pki_types::ServerName;
use std::env;
use std::net::SocketAddr;
use std::process::ExitCode;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() < 6 {
        eprintln!(
            "usage: {} <host> <port> <ca.pem> <client_cert.pem> <client_key.pem>",
            args.first().map(String::as_str).unwrap_or("tls_client")
        );
        return ExitCode::from(1);
    }
    let host = &args[1];
    let port: u16 = match args[2].parse() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("invalid port: {}", args[2]);
            return ExitCode::from(1);
        }
    };
    let ca_path = &args[3];
    let cert_path = &args[4];
    let key_path = &args[5];

    match run(host, port, ca_path, cert_path, key_path).await {
        Ok(0) => {
            println!("all stages passed");
            ExitCode::SUCCESS
        }
        Ok(n) => {
            eprintln!("{n} stage(s) failed");
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("connection failed: {e}");
            ExitCode::from(1)
        }
    }
}

async fn run(
    host: &str,
    port: u16,
    ca_path: &str,
    cert_path: &str,
    key_path: &str,
) -> Result<usize, Box<dyn std::error::Error>> {
    let tls_cfg = TlsConfigBuilder::new()
        .with_cert_pem_file(cert_path, key_path)?
        .add_ca_pem_file(ca_path)?
        .build_client()?;
    let connector = TlsConnector::new(tls_cfg);

    // The server name drives certificate verification: an IP literal is
    // matched against an IP SAN, anything else against a DNS SAN.
    let server_name: ServerName<'static> = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        ServerName::IpAddress(ip.into())
    } else {
        ServerName::try_from(host.to_string())?
    };

    let addr: SocketAddr = tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or("DNS lookup yielded 0 addresses")?;

    let mms = MmsClientBuilder::new()
        .connect_timeout_ms(8_000)
        .request_timeout_ms(5_000)
        .build();
    let conn = IedConnection::with_mms_client(mms);

    println!("connecting to tls://{host}:{port} (resolved {addr})");
    conn.connect_tls(addr, &connector, server_name).await?;
    println!("TLS handshake and MMS Initiate completed");

    let mut failures: usize = 0;

    let power_ref = "DemoIEDLD0/MMXU1.TotW.mag.f";
    match conn.read_float(power_ref, FC::Mx).await {
        Ok(v) => println!("read {power_ref} = {v}"),
        Err(e) => {
            eprintln!("read {power_ref} failed: {e}");
            failures += 1;
        }
    }

    let vendor_ref = "DemoIEDLD0/LLN0.NamPlt.vendor";
    match conn
        .write_visible_string(vendor_ref, FC::Dc, "tls-client")
        .await
    {
        Ok(()) => println!("write {vendor_ref} accepted"),
        Err(e) => {
            // Whether a name plate accepts a write is a server policy, so a
            // refusal is reported without counting as a failed stage: the TLS
            // channel is what this example proves.
            let msg = e.to_string();
            if msg.contains("ACCESS_DENIED") || msg.contains("access-denied") {
                println!("write {vendor_ref} refused by server policy: {msg}");
            } else {
                eprintln!("write {vendor_ref} failed: {e}");
                failures += 1;
            }
        }
    }

    let _ = conn.disconnect().await;
    Ok(failures)
}
