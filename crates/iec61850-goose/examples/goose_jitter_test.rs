//! Measures the publish jitter of a GOOSE publisher on a real interface.
//!
//! Publishes on a fixed 1 ms period through
//! `iec61850_hal::ethernet::linux::AfPacketSocket` and records the interval
//! between consecutive publications, reporting the distribution of that
//! interval and of its deviation from the target period. The measured path
//! includes the socket send, so the numbers reflect what leaves the interface
//! rather than only what the encoder costs. `sv_jitter_test` measures the
//! encode path alone.
//!
//! The target is a 99th percentile jitter under 100 microseconds, which needs a
//! release build, a PREEMPT_RT kernel and a real-time scheduling class. A
//! general-purpose kernel reports far higher figures, and a virtualized kernel
//! reports figures that mean nothing at all.
//!
//! # Arguments
//!
//! The interface name, required, and an optional duration in seconds
//! (default 10). Setting `GOOSE_RT_PRIO` switches the thread to SCHED_FIFO at
//! that priority, which needs `CAP_SYS_NICE`.
//!
//! ```sh
//! sudo setcap cap_net_raw,cap_sys_nice=eip ./goose_jitter_test
//! GOOSE_RT_PRIO=50 ./goose_jitter_test eth0 60
//! ```
//!
//! Expected stderr:
//!
//! ```text
//! [goose-jitter] SCHED_FIFO prio=50 set
//! [goose-jitter] finished in 60.001s, 60 s requested
//! [goose-jitter] target period = 1000 us
//! [goose-jitter] inter-publish delta us: min=961 p50=1000 p99=1043 max=1712 mean=1000
//! [goose-jitter] jitter |delta-target| us: min=0 p50=4 p99=43 max=712 mean=6
//! [goose-jitter] jitter p99 under 100 us: PASS
//! ```
//!
//! Linux only: it needs both AF_PACKET and SCHED_FIFO.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("goose_jitter_test needs AF_PACKET and SCHED_FIFO, which is Linux only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    impl_::run();
}

#[cfg(target_os = "linux")]
mod impl_ {
    use std::time::{Duration, Instant};

    use iec61850_goose::frame::VlanPriority;
    use iec61850_goose::publisher::{CommParameters, GoosePublisher};
    use iec61850_hal::ethernet::linux::AfPacketSocket;
    use iec61850_hal::ethernet::{EthernetAddr, EthernetConfig, EthernetSink};
    use iec61850_model::MmsValue;

    const DST_MAC: [u8; 6] = [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01];
    const SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const GOCB_REF: &str = "DemoIED/LLN0$GO$gcbStatus";
    const DATASET_REF: &str = "DemoIED/LLN0$dsStatus";
    const APP_ID: u16 = 0x1000;
    /// Publish period. Steady-state GOOSE retransmits every 1000 ms; the tight
    /// 1 ms period here is what makes scheduling delay visible.
    const PERIOD: Duration = Duration::from_millis(1);

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        if args.len() < 2 {
            eprintln!("usage: {} <iface> [duration_secs]", args[0]);
            std::process::exit(2);
        }
        let iface = &args[1];
        let duration_secs: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10);

        if let Ok(prio_str) = std::env::var("GOOSE_RT_PRIO") {
            if let Ok(prio) = prio_str.parse::<i32>() {
                set_sched_fifo(prio);
            }
        }

        let comm = CommParameters::new(APP_ID, DST_MAC)
            .with_priority(VlanPriority::new(4).unwrap())
            .with_src_mac(SRC_MAC);
        let mut publisher =
            GoosePublisher::new(comm, GOCB_REF, None, DATASET_REF, 1).expect("publisher new");

        let cfg = EthernetConfig::new(iface).with_multicast(EthernetAddr(DST_MAC));
        let mut sink =
            AfPacketSocket::open(&cfg).expect("open AF_PACKET socket, which needs CAP_NET_RAW");

        let total: u64 = duration_secs * 1000; // one publication per millisecond
        let mut deltas_us: Vec<u64> = Vec::with_capacity(total as usize);

        let dataset = vec![
            MmsValue::Boolean(true),
            MmsValue::Integer(100),
            MmsValue::Integer(0),
        ];

        eprintln!(
            "[goose-jitter] iface={iface} appid=0x{APP_ID:04x} period={}ms total={total}",
            PERIOD.as_millis()
        );

        let start = Instant::now();
        let mut prev = Instant::now();
        let mut next_publish = prev;
        for _ in 0..total {
            loop {
                let now = Instant::now();
                if now >= next_publish {
                    let delta = now.saturating_duration_since(prev);
                    deltas_us.push(delta.as_micros() as u64);
                    prev = now;
                    let frame = publisher.publish_at(&dataset, now).expect("publish");
                    if let Err(e) = sink.send(&frame) {
                        eprintln!("[goose-jitter] send failed: {e}");
                        std::process::exit(3);
                    }
                    next_publish += PERIOD;
                    break;
                }
                if next_publish - now > Duration::from_micros(100) {
                    std::thread::sleep(next_publish - now - Duration::from_micros(100));
                }
            }
        }
        let elapsed = start.elapsed();

        // Jitter is the absolute deviation of each interval from the target.
        let target_us = PERIOD.as_micros() as u64;
        let mut jitter_us: Vec<u64> = deltas_us.iter().map(|&d| d.abs_diff(target_us)).collect();

        deltas_us.sort_unstable();
        jitter_us.sort_unstable();
        let n = deltas_us.len();
        let stat = |sorted: &[u64]| -> (u64, u64, u64, u64, u64) {
            (
                *sorted.first().unwrap(),
                sorted[n / 2],
                sorted[(n * 99) / 100],
                *sorted.last().unwrap(),
                sorted.iter().sum::<u64>() / n as u64,
            )
        };
        let (d_min, d_p50, d_p99, d_max, d_mean) = stat(&deltas_us);
        let (j_min, j_p50, j_p99, j_max, j_mean) = stat(&jitter_us);

        eprintln!(
            "[goose-jitter] finished in {:?}, {duration_secs} s requested",
            elapsed
        );
        eprintln!("[goose-jitter] target period = {target_us} us");
        eprintln!(
            "[goose-jitter] inter-publish delta us: min={d_min} p50={d_p50} p99={d_p99} max={d_max} mean={d_mean}"
        );
        eprintln!(
            "[goose-jitter] jitter |delta-target| us: min={j_min} p50={j_p50} p99={j_p99} max={j_max} mean={j_mean}"
        );
        eprintln!(
            "[goose-jitter] jitter p99 under 100 us: {}",
            if j_p99 < 100 {
                "PASS"
            } else {
                "FAIL, which needs a release build, GOOSE_RT_PRIO and a PREEMPT_RT kernel"
            }
        );
    }

    fn set_sched_fifo(prio: i32) {
        // SAFETY: pthread_self and pthread_setschedparam are POSIX calls that
        // take a stack-allocated, fully initialized sched_param.
        unsafe {
            let mut param: libc::sched_param = std::mem::zeroed();
            param.sched_priority = prio;
            let rc = libc::pthread_setschedparam(libc::pthread_self(), libc::SCHED_FIFO, &param);
            if rc != 0 {
                eprintln!(
                    "[goose-jitter] pthread_setschedparam(SCHED_FIFO, {prio}) failed with rc={rc}; CAP_SYS_NICE is required"
                );
            } else {
                eprintln!("[goose-jitter] SCHED_FIFO prio={prio} set");
            }
        }
    }
}
