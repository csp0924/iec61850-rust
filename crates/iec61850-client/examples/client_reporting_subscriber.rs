//! Subscribes to a report control block and prints every report it receives.
//!
//! Shows the full client side of IEC 61850-7-2 reporting:
//!
//! 1. connect, then install a report callback for the RCB
//! 2. write `Resv` and `RptEna` to enable the RCB over the wire
//! 3. run a background dispatcher that hands arriving reports to the callback
//! 4. on Ctrl+C, disable the RCB and close the association
//!
//! Pairs with the `server_from_scl` example, which registers `urcbMeas` on the
//! `dsMeas` data set of `crates/iec61850-server/examples/models/demo.cid`
//! and moves the measured
//! values once a second, so a report arrives about every second.
//!
//! ```sh
//! # Terminal 1
//! cargo run -p iec61850-server --example server_from_scl
//!
//! # Terminal 2
//! cargo run -p iec61850-client --example client_reporting_subscriber
//! ```
//!
//! Expected stdout:
//!
//! ```text
//! connecting to 127.0.0.1:8102
//! connected
//! URCB enabled (rcb_ref=DemoIEDLD0/LLN0$RP$urcbMeas)
//! subscribed; press Ctrl+C to stop
//! [#1] seq=Some(0) ts_ms=Some(..) conf_rev=Some(1) dataset_size=Some(3)
//!     [0] DemoIEDLD0/MMXU1$MX$TotW$mag$f = Float32(1001.0)  reason=Some(..)
//! ```
//!
//! Host and port default to `127.0.0.1` and `8102` and can be overridden.

use iec61850_client::{
    rcb::{RcbHandle, RcbWriteMask},
    ClientReport, IedConnection, ReportCallback,
};
use iec61850_mms::mms::client::MmsClientBuilder;
use std::env;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const RCB_REF: &str = "DemoIEDLD0/LLN0$RP$urcbMeas";

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let port: u16 = env::args()
        .nth(2)
        .unwrap_or_else(|| "8102".to_string())
        .parse()?;

    println!("connecting to {host}:{port}");

    let mms = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    let conn = IedConnection::with_mms_client(mms);
    conn.connect(&host, port).await?;
    println!("connected");

    // The callback runs on the dispatcher task for every report.
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_for_cb = Arc::clone(&counter);
    let cb: ReportCallback = Arc::new(move |snap: Arc<ClientReport>| {
        let n = counter_for_cb.fetch_add(1, Ordering::SeqCst) + 1;
        print_report(n, &snap);
    });
    // The report identifier is given explicitly so it matches the RptID the
    // CID configures; passing None would let the registry derive one.
    conn.install_report_handler(Some(RCB_REF.to_string()), RCB_REF, None, cb)
        .await?;

    // Resv must be written before RptEna; the write sequence enforces that.
    let mut rcb = RcbHandle::new(RCB_REF)?;
    rcb.set_resv(true);
    rcb.set_rpt_ena(true);
    let mask = RcbWriteMask::RESV | RcbWriteMask::RPT_ENA;
    conn.set_rcb_values(&rcb, mask, false).await?;
    println!("URCB enabled (rcb_ref={RCB_REF})");

    // The dispatcher polls the association and drives the callback.
    let dispatcher = conn.spawn_report_dispatcher(Duration::from_millis(100));
    println!("subscribed; press Ctrl+C to stop");

    let _ = tokio::signal::ctrl_c().await;
    println!("\nshutdown requested");

    // Disable the RCB before dropping the association so the server stops
    // buffering for a client that has gone.
    let mut rcb_off = RcbHandle::new(RCB_REF)?;
    rcb_off.set_rpt_ena(false);
    if let Err(e) = conn
        .set_rcb_values(&rcb_off, RcbWriteMask::RPT_ENA, false)
        .await
    {
        eprintln!("could not disable the RCB before closing: {e}");
    }
    let _ = conn.disconnect().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), dispatcher).await;
    println!("total reports received: {}", counter.load(Ordering::SeqCst));
    Ok(())
}

fn print_report(n: usize, snap: &ClientReport) {
    println!(
        "[#{n}] seq={:?} ts_ms={:?} conf_rev={:?} dataset_size={:?}",
        snap.seq_num, snap.timestamp_ms, snap.conf_rev, snap.dataset_size
    );
    for (i, v) in snap.data_set_values.iter().enumerate() {
        let reason = snap.reasons.get(i);
        let path = snap
            .data_references
            .get(i)
            .and_then(|x| x.as_deref())
            .unwrap_or("(no data-ref)");
        match v {
            Some(value) => println!("    [{i}] {path} = {value:?}  reason={reason:?}"),
            None => println!("    [{i}] {path} = (not included)  reason={reason:?}"),
        }
    }
}
