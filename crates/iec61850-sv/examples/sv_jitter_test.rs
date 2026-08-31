//! Measures the encode-path jitter of a Sampled Values publisher.
//!
//! Publishes at 4000 samples per second for a given duration and records the
//! interval between consecutive publications, reporting both that interval and
//! its deviation from the 250 microsecond target period. Nothing is sent: the
//! frame bytes are produced and dropped, so the figures cover the encode path
//! alone. `goose_jitter_test` measures a path that includes the socket.
//!
//! The design target is a 99th percentile jitter under 200 microseconds, which
//! needs a release build, a PREEMPT_RT kernel and a real-time scheduling class.
//! This example requests none of those, so that it runs unprivileged; the
//! production loop `iec61850_sv::publish_thread::spawn_publish_loop` is what a
//! qualifying measurement uses.
//!
//! # Arguments
//!
//! An interface name, kept for symmetry with the publisher examples and unused
//! here, and an optional duration in seconds (default 10).
//!
//! ```sh
//! ./sv_jitter_test lo 60
//! ```
//!
//! Expected stderr:
//!
//! ```text
//! [jitter] measuring 60 s (240000 samples) at 4000 sps, encode path only
//! [jitter] target period = 250 us at 4000 sps
//! [jitter] inter-publish delta us:    min=201 p50=250 p99=298 max=1102 mean=250
//! [jitter] |delta - target| (jitter): min=0 p50=6 p99=48 max=852 mean=9
//! [jitter] jitter p99 under 200 us: PASS
//! ```
//!
//! Linux only.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("sv_jitter_test is Linux only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    linux_impl::run();
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use std::time::{Duration, Instant};

    use iec61850_sv::nine_two_le::SAMPLE_SIZE;
    use iec61850_sv::publisher::SvPublisherBuilder;
    use iec61850_sv::SV_DEFAULT_DST_MAC;

    const SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const APP_ID: u16 = 0x4000;
    const SV_ID: &str = "jittertest";
    const SPS: u64 = 4000;
    const PERIOD: Duration = Duration::from_nanos(1_000_000_000 / SPS);

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        let duration_secs: u64 = if args.len() >= 3 {
            args[2].parse().unwrap_or(10)
        } else {
            10
        };

        let mut builder = SvPublisherBuilder::new(SRC_MAC)
            .with_dst_mac(SV_DEFAULT_DST_MAC)
            .with_app_id(APP_ID);
        let h = builder
            .add_asdu(SV_ID, None::<&str>, 1, SAMPLE_SIZE)
            .expect("add_asdu");
        let mut publisher = builder.setup_complete().expect("setup_complete");

        let total_samples = SPS * duration_secs;
        let mut deltas_us: Vec<u64> = Vec::with_capacity(total_samples as usize);

        // The sample content does not affect the encode cost, so it stays zero.
        let zero_sample = [0u8; 64];

        eprintln!(
            "[jitter] measuring {duration_secs} s ({total_samples} samples) at {SPS} sps, encode path only"
        );

        let start = Instant::now();
        let mut prev = Instant::now();
        let mut next_publish = prev;
        for _ in 0..total_samples {
            // A spin down to the deadline, with a sleep while there is room for one.
            loop {
                let now = Instant::now();
                if now >= next_publish {
                    let delta = now.saturating_duration_since(prev);
                    deltas_us.push(delta.as_micros() as u64);
                    prev = now;
                    publisher.set_sample(h, &zero_sample).expect("set_sample");
                    let _bytes = publisher.frame_bytes(); // encoded, never sent
                    publisher.increase_smp_cnt(h).expect("increase_smp_cnt");
                    next_publish += PERIOD;
                    break;
                }
                if next_publish - now > Duration::from_micros(50) {
                    std::thread::sleep(next_publish - now - Duration::from_micros(50));
                }
            }
        }
        let elapsed = start.elapsed();

        let target = 1_000_000 / SPS;

        // The interval itself averages the target period, so the figure to hold
        // to a limit is its absolute deviation from that period, not the interval.
        let mut jitter_us: Vec<u64> = deltas_us.iter().map(|&d| d.abs_diff(target)).collect();

        deltas_us.sort_unstable();
        jitter_us.sort_unstable();
        let n = deltas_us.len();
        let d_min = *deltas_us.first().unwrap();
        let d_max = *deltas_us.last().unwrap();
        let d_p50 = deltas_us[n / 2];
        let d_p99 = deltas_us[(n * 99) / 100];
        let d_mean = deltas_us.iter().sum::<u64>() / n as u64;
        let j_min = *jitter_us.first().unwrap();
        let j_max = *jitter_us.last().unwrap();
        let j_p50 = jitter_us[n / 2];
        let j_p99 = jitter_us[(n * 99) / 100];
        let j_mean = jitter_us.iter().sum::<u64>() / n as u64;

        eprintln!(
            "[jitter] finished in {:?}, {} s requested",
            elapsed, duration_secs
        );
        eprintln!("[jitter] target period = {target} us at {SPS} sps");
        eprintln!(
            "[jitter] inter-publish delta us:    min={d_min} p50={d_p50} p99={d_p99} max={d_max} mean={d_mean}"
        );
        eprintln!(
            "[jitter] |delta - target| (jitter): min={j_min} p50={j_p50} p99={j_p99} max={j_max} mean={j_mean}"
        );
        eprintln!(
            "[jitter] jitter p99 under 200 us: {}",
            if j_p99 < 200 {
                "PASS"
            } else {
                "FAIL, which needs a release build, SCHED_FIFO and a PREEMPT_RT kernel"
            }
        );
    }
}
