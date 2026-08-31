//! Integration tests that the server lifecycle really drives buffered report
//! control blocks.
//!
//! No client connects; the tests start the server, register a BRCB on the
//! reporting engine, raise a trigger with a 50 ms buffer time, wait past that
//! deadline and require the one-millisecond tick loop to have flushed the
//! trigger into the BRCB buffer. Without that wiring a BRCB would never flush
//! on its own.

use iec61850_model::{
    DataAttribute, DataAttributeType, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder,
    MmsValue, TrgOps, FC,
};
use iec61850_server::reporting::{Brcb, BufferedReportControl};
use iec61850_server::{Dataset, DatasetEntry, IedServer, InclusionFlag, TriggerOptions};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

fn build_server() -> IedServer {
    let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .build()
        .expect("ld");
    let model = Arc::new(
        IedModelBuilder::new("IED1")
            .add_ld(ld)
            .expect("add_ld")
            .build()
            .expect("model"),
    );
    IedServer::builder()
        .model(model)
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()
        .expect("server build")
}

#[tokio::test(flavor = "current_thread")]
async fn lifecycle_tick_loop_drives_tick_brcb_buftm_flush() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();

        // Register a BRCB with a 50 ms buffer time over a stand-in data set;
        // the data set does not have to be part of the model here.
        let brcb_path = "IED1LD0/GGIO1$BR$brcb01";
        let attr_ref = "IED1LD0/GGIO1$ST$Ind1$stVal".to_string();
        let val = Arc::new(RwLock::new(MmsValue::Boolean(false)));

        let mut ds = Dataset::new("GGIO1$ds1");
        ds.push(DatasetEntry::new(&attr_ref, val.clone()));

        let brcb = Brcb::new("brcb01", "GGIO1$ds1")
            .with_trg_ops(TriggerOptions::DATA_CHANGED)
            .with_buf_tm_ms(50);
        let brc = BufferedReportControl::new(brcb_path, brcb);

        let engine_arc = server.reporting_engine();
        let brcb_arc = {
            let mut eng = engine_arc.lock().unwrap();
            eng.register_brcb_with_dataset(brc, ds).unwrap();
            // Triggers are only enqueued while RptEna is true.
            let arc = eng.get_brcb(brcb_path).unwrap();
            arc.state.lock().unwrap().rpt_ena = true;
            arc.state.lock().unwrap().is_buffering = true;
            arc
        };

        let handle = server.start().await.expect("server start");

        // Raise a trigger; the 50 ms buffer time defers it.
        {
            let eng = engine_arc.lock().unwrap();
            eng.on_brcb_value_updated(
                &attr_ref,
                MmsValue::Boolean(true),
                InclusionFlag::VALUE_CHANGED,
                1_000_000,
            );
        }

        // The buffer time has not expired yet, so nothing is buffered.
        assert_eq!(
            brcb_arc.lock_buffer().unwrap().len(),
            0,
            "the buffer stays empty until the 50 ms buffer time expires"
        );

        // Wait well past the buffer time so the tick loop crosses it.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let entries_after = brcb_arc.lock_buffer().unwrap().len();
        handle.stop().await;

        assert!(
            entries_after >= 1,
            "an expired buffer time must enqueue at least one entry, got {}",
            entries_after
        );
    })
    .await
    .expect("lifecycle_tick_loop_drives_tick_brcb_buftm_flush 5s timeout");
}

/// Checks that the lifecycle also drives the once-per-second reservation tick.
///
/// With no BRCB reserved the tick is a no-op, so this only asserts that the
/// loop keeps running and does not panic.
#[tokio::test(flavor = "current_thread")]
async fn lifecycle_tick_loop_runs_reservation_tick_without_panic() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let server = build_server();
        let handle = server.start().await.expect("server start");

        // Run past the one-second reservation boundary.
        tokio::time::sleep(Duration::from_millis(1200)).await;

        handle.stop().await;
    })
    .await
    .expect("lifecycle_tick_loop_runs_reservation_tick_without_panic 3s timeout");
}

// Keeps the model imports used; they are reserved for tests that bind a BRCB
// to a real model data set.
#[allow(dead_code)]
fn _silence_unused() {
    let _ = DataAttribute::new(
        "x",
        FC::St,
        DataAttributeType::Boolean,
        TrgOps::DCHG,
        MmsValue::Boolean(false),
    );
}
