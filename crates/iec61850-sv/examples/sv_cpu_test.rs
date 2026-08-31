//! Measures the processor cost of one Sampled Values stream.
//!
//! Runs a 4000 samples-per-second publisher through
//! `iec61850_sv::publish_thread::spawn_publish_loop`, the production path: an
//! absolute-time `clock_nanosleep` with an optional real-time scheduling class,
//! rather than the busy-wait `sv_jitter_test` uses. What the process consumes
//! is therefore the publisher itself, which is one PDU encode and the frame
//! template written back per sample.
//!
//! The design target is under 3% of one core for a single 4000 sps stream.
//!
//! # Arguments
//!
//! An optional duration in seconds, default 60. The measurement comes from the
//! process accounting of the shell, not from the example:
//!
//! ```sh
//! /usr/bin/time -v ./sv_cpu_test 60
//! ```
//!
//! Expected stderr:
//!
//! ```text
//! [cpu] publishing 4000 sps for 60s on the production publish thread
//! [cpu] done; the CPU percentage reported by `time -v` is the result
//! ```
//!
//! Linux only: the publish loop uses `clock_nanosleep` with an absolute deadline.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("sv_cpu_test needs clock_nanosleep with an absolute deadline, which is Linux only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    linux_impl::run();
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use std::time::Duration;

    use iec61850_sv::nine_two_le::SAMPLE_SIZE;
    use iec61850_sv::publish_thread::spawn_publish_loop;
    use iec61850_sv::publisher::SvPublisherBuilder;
    use iec61850_sv::SV_DEFAULT_DST_MAC;

    const SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const APP_ID: u16 = 0x4000;
    const SV_ID: &str = "cputest";
    const SPS: u64 = 4000;
    const PERIOD_NS: u64 = 1_000_000_000 / SPS;

    pub fn run() {
        let duration_secs: u64 = std::env::args()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(60);

        let mut builder = SvPublisherBuilder::new(SRC_MAC)
            .with_dst_mac(SV_DEFAULT_DST_MAC)
            .with_app_id(APP_ID);
        let h = builder
            .add_asdu(SV_ID, None::<&str>, 1, SAMPLE_SIZE)
            .expect("add_asdu");
        let publisher = builder.setup_complete().expect("setup_complete");

        eprintln!(
            "[cpu] publishing {SPS} sps for {duration_secs}s on the production publish thread"
        );

        let zero_sample = [0u8; 64];
        let handle = spawn_publish_loop(publisher, PERIOD_NS, move |p| {
            let _ = p.set_sample(h, &zero_sample);
            let _bytes = p.frame_bytes();
            let _ = p.increase_smp_cnt(h);
        });

        std::thread::sleep(Duration::from_secs(duration_secs));
        handle.stop();
        handle.join();

        eprintln!("[cpu] done; the CPU percentage reported by `time -v` is the result");
        eprintln!("[cpu] the target is under 3% of one core for a single 4000 sps stream");
    }
}
