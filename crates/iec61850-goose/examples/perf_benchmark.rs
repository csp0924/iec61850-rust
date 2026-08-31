//! Measures the two latencies a GOOSE publisher is held to.
//!
//! Neither measurement touches a socket, so both run anywhere:
//!
//! 1. First-publish latency: the wall clock from `GoosePublisher::new` to the
//!    bytes of the first `publish`. The cost is one PDU encode, one clone of
//!    the frame template and the length fields written back, which lands in
//!    microseconds against a 5 ms budget. Exceeding it at the 99th percentile
//!    fails the run.
//! 2. Retransmission scheduling jitter: how far each publication lands from the
//!    instant `next_publish_at` asked for. This is reported, never failed: on a
//!    general-purpose scheduler the sleep granularity alone is about a
//!    millisecond, and reaching the 100 microsecond target needs a real-time
//!    scheduling class.
//!
//! ```sh
//! cargo run -p iec61850-goose --example perf_benchmark --release
//! ```
//!
//! A release build is required for the numbers to mean anything; a debug build
//! can be an order of magnitude slower, and the example says so before running.
//!
//! Expected stdout:
//!
//! ```text
//! GOOSE publisher latency
//!
//! A. first publish (new plus the first publish, wall clock)
//!   first_publish_latency       n=  100  min=  1000 ns  p50=  1100 ns  p99=  1400 ns  max=  1400 ns
//!     [PASS] first_publish_latency p99 1400 ns <= budget 5000.00 us
//! ```
//!
//! The exit status is 1 when the first-publish budget is exceeded, so a
//! continuous integration job can gate on it.

use std::time::{Duration, Instant};

use iec61850_goose::frame::VlanPriority;
use iec61850_goose::publisher::{CommParameters, GoosePublisher};
use iec61850_model::MmsValue;

const FIRST_PUBLISH_SAMPLES: usize = 100;
const JITTER_SAMPLES: usize = 1000;
/// Budget for the first publish; exceeding it at p99 fails the run.
const FIRST_PUBLISH_BUDGET: Duration = Duration::from_millis(5);
/// Target for scheduling jitter. Reported only: meeting it needs a real-time
/// scheduling class, which this example does not request.
const RETRANS_JITTER_TARGET: Duration = Duration::from_micros(100);

fn make_publisher() -> GoosePublisher {
    let comm = CommParameters::new(0x1000, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01])
        .with_priority(VlanPriority::new(4).unwrap())
        .with_src_mac([0x02, 0, 0, 0, 0, 1]);
    GoosePublisher::new(
        comm,
        "DemoIED/LLN0$GO$gcbStatus",
        None,
        "DemoIED/LLN0$dsStatus",
        1,
    )
    .expect("publisher new")
}

fn typical_dataset() -> Vec<MmsValue> {
    // The same three-member data set the publisher and subscriber examples send.
    vec![
        MmsValue::Boolean(true),
        MmsValue::Integer(12345),
        MmsValue::Integer(0),
    ]
}

/// Nearest-rank percentile of an already sorted slice.
fn pct(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn fmt_dur(d: Duration) -> String {
    let ns = d.as_nanos();
    if ns < 10_000 {
        format!("{} ns", ns)
    } else if ns < 10_000_000 {
        format!("{:.2} us", ns as f64 / 1_000.0)
    } else {
        format!("{:.2} ms", ns as f64 / 1_000_000.0)
    }
}

// -- A. First publish: new plus the first publish, wall clock --

fn bench_first_publish_latency() -> Vec<Duration> {
    let dataset = typical_dataset();
    let mut samples = Vec::with_capacity(FIRST_PUBLISH_SAMPLES);

    // A warm-up round primes the caches so the first sample is not an outlier.
    for _ in 0..10 {
        let mut p = make_publisher();
        let _ = p.publish(&dataset).unwrap();
    }

    for _ in 0..FIRST_PUBLISH_SAMPLES {
        let t0 = Instant::now();
        let mut p = make_publisher();
        let frame = p.publish(&dataset).unwrap();
        let dt = t0.elapsed();
        std::hint::black_box(&frame);
        samples.push(dt);
    }

    samples
}

// -- B. Retransmission scheduling: how far each publication lands from its target --

fn bench_retrans_jitter() -> Vec<Duration> {
    let dataset = typical_dataset();
    let mut publisher = make_publisher();
    // Sampling runs in the steady retransmission phase, past the exponential
    // back-off, with the interval shortened to 1 ms so a run takes seconds.
    use iec61850_goose::publisher::RetransIntervals;
    publisher.set_retrans_intervals(RetransIntervals {
        t1: Duration::from_millis(1),
        t2: Duration::from_millis(1),
        t3: Duration::from_millis(1),
        t4: Duration::from_millis(1),
        tmax: Duration::from_millis(1),
    });

    let mut samples = Vec::with_capacity(JITTER_SAMPLES);

    let _ = publisher.publish(&dataset).unwrap();

    for _ in 0..JITTER_SAMPLES {
        let target = publisher.next_publish_at(Instant::now());
        // Sleeping until the target instant is the caller-driven schedule.
        let now = Instant::now();
        if target > now {
            std::thread::sleep(target - now);
        }
        let actual = Instant::now();
        let _ = publisher.publish_at(&dataset, actual).unwrap();
        // A publication never happens early, so the sample is actual minus target.
        let dev = actual.saturating_duration_since(target);
        samples.push(dev);
    }

    samples
}

// -- Reporting --

fn report(label: &str, samples: &mut [Duration], budget: Duration, fail_on_p99_over: bool) {
    samples.sort();
    let min = samples.first().copied().unwrap_or_default();
    let p50 = pct(samples, 0.50);
    let p90 = pct(samples, 0.90);
    let p99 = pct(samples, 0.99);
    let max = samples.last().copied().unwrap_or_default();

    println!(
        "  {label:30}  n={n:5}  min={min:>10}  p50={p50:>10}  p90={p90:>10}  p99={p99:>10}  max={max:>10}",
        n = samples.len(),
        min = fmt_dur(min),
        p50 = fmt_dur(p50),
        p90 = fmt_dur(p90),
        p99 = fmt_dur(p99),
        max = fmt_dur(max),
    );

    let verdict = if p99 <= budget {
        "[PASS]"
    } else if fail_on_p99_over {
        "[FAIL]"
    } else {
        "[INFO]"
    };
    println!(
        "    {verdict} {label} p99 {p99} {op} budget {budget}",
        p99 = fmt_dur(p99),
        op = if p99 <= budget { "<=" } else { ">" },
        budget = fmt_dur(budget),
    );
}

fn main() {
    if cfg!(debug_assertions) {
        eprintln!(
            "[perf_benchmark] this is a debug build and the numbers will be far too high\n\
             [perf_benchmark] run: cargo run -p iec61850-goose --example perf_benchmark --release"
        );
    }

    println!("GOOSE publisher latency\n");

    println!("A. first publish (new plus the first publish, wall clock)");
    let mut a = bench_first_publish_latency();
    report(
        "first_publish_latency",
        &mut a,
        FIRST_PUBLISH_BUDGET,
        true, // a p99 over the budget fails the run
    );

    println!("\nB. retransmission scheduling (target against actual)");
    println!("    reaching the 100 us target needs a real-time scheduling class");
    let mut b = bench_retrans_jitter();
    report(
        "retrans_scheduling_jitter",
        &mut b,
        RETRANS_JITTER_TARGET,
        false, // reported, never failed
    );

    // The exit status carries the verdict so a continuous integration job can gate on it.
    let p99_a = pct(&a, 0.99);
    if p99_a > FIRST_PUBLISH_BUDGET {
        eprintln!("[perf_benchmark] first-publish p99 is over budget");
        std::process::exit(1);
    }
}
