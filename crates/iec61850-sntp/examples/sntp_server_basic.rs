//! Serves SNTPv4 time on a UDP socket.
//!
//! IEC 61850 leaves clock synchronization to SNTP or PTP; this example runs the
//! SNTP server of `iec61850-sntp` so an IED, or any SNTP client, can set its
//! clock from it. It answers every request from the host clock and needs no
//! other component of this repository.
//!
//! ```sh
//! # Terminal 1
//! cargo run -p iec61850-sntp --example sntp_server_basic
//!
//! # Terminal 2
//! ntpdate -q -u -p 1 127.0.0.1
//! ```
//!
//! Expected stderr:
//!
//! ```text
//! SNTPv4 server listening on 0.0.0.0:12300
//! ```
//!
//! The default bind address is `0.0.0.0:12300` rather than the assigned port
//! 123, so the example runs without elevated privileges. Pass a bind address to
//! override it.

use std::env;
use std::net::SocketAddr;

use iec61850_sntp::SntpServer;

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    tracing_subscriber_fallback();

    let addr: SocketAddr = env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:12300".to_string())
        .parse()
        .expect("invalid SocketAddr");

    let server = SntpServer::bind(addr).await?;
    let local = server.local_addr()?;
    eprintln!("SNTPv4 server listening on {local}");
    server.run().await
}

/// Placeholder for the tracing subscriber an application would install.
///
/// The server reports refused packets through `tracing`, which is silent
/// without a subscriber. The example installs none, so that it depends on
/// nothing beyond the crate under demonstration.
fn tracing_subscriber_fallback() {}
