//! Dedicated publish loop for Sampled Values, on Linux.
//!
//! `spawn_publish_loop` runs the publisher on its own OS thread and paces it
//! with `clock_nanosleep` against absolute `CLOCK_MONOTONIC` deadlines, so the
//! period does not drift with the work done in each tick. 4000 samples per
//! second corresponds to a 250 us period.
//!
//! The thread asks for `SCHED_FIFO`, which is what the design target of under
//! 200 us of p99 jitter assumes. Without `CAP_SYS_NICE` that request fails; the
//! loop logs a warning and continues under normal scheduling rather than
//! failing to start, so a publisher still runs in an unprivileged process.
//!
//! ## Example
//!
//! ```ignore
//! use iec61850_sv::publish_thread::spawn_publish_loop;
//! use iec61850_sv::publisher::SvPublisher;
//!
//! let handle = spawn_publish_loop(publisher, 250_000, |pub_| {
//!     pub_.increase_smp_cnt(h).ok();
//!     // Write the sample data, then send the frame:
//!     // socket.send(pub_.frame_bytes()).ok();
//! });
//! ```

// The loop calls libc directly; every unsafe block carries a SAFETY comment.
#![allow(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use crate::publisher::SvPublisher;

/// Requests `SCHED_FIFO` at `priority` for the calling thread.
///
/// A failure, such as EPERM without `CAP_SYS_NICE`, is logged and the thread
/// keeps running under normal scheduling.
#[cfg(target_os = "linux")]
fn try_set_sched_fifo(priority: libc::c_int) {
    let param = libc::sched_param {
        sched_priority: priority,
    };
    // SAFETY: `pthread_self` names the calling thread and `param` is a valid
    // initialized value that outlives the call.
    let ret =
        unsafe { libc::pthread_setschedparam(libc::pthread_self(), libc::SCHED_FIFO, &param) };
    if ret != 0 {
        tracing::warn!(
            "sv-publisher cannot set sched_fifo priority={} (errno={}), continuing with normal scheduling",
            priority,
            ret
        );
    } else {
        tracing::debug!("sv-publisher set sched_fifo priority={}", priority);
    }
}

/// Sleeps until the absolute `CLOCK_MONOTONIC` deadline `target`.
///
/// A signal (EINTR) resumes the sleep so the deadline is still honored; any
/// other error ends the sleep to avoid spinning.
#[cfg(target_os = "linux")]
fn clock_nanosleep_abs(target: &libc::timespec) {
    loop {
        // SAFETY: `target` is a valid timespec that outlives the call, and the
        // null remainder pointer is accepted by clock_nanosleep.
        let ret = unsafe {
            libc::clock_nanosleep(
                libc::CLOCK_MONOTONIC,
                libc::TIMER_ABSTIME,
                target as *const _,
                std::ptr::null_mut(),
            )
        };
        if ret == 0 || ret == libc::EINTR {
            if ret == 0 {
                break;
            }
        } else {
            tracing::warn!("clock_nanosleep failed with {}, leaving the sleep", ret);
            break;
        }
    }
}

/// Reads the current `CLOCK_MONOTONIC` time.
#[cfg(target_os = "linux")]
fn clock_gettime_monotonic() -> libc::timespec {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, live timespec the call writes into.
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    ts
}

/// Adds `ns` nanoseconds to a timespec, carrying into `tv_sec`.
#[cfg(target_os = "linux")]
fn timespec_add_ns(ts: libc::timespec, ns: u64) -> libc::timespec {
    const NS_PER_SEC: u64 = 1_000_000_000;
    let total_ns = ts.tv_nsec as u64 + ns;
    libc::timespec {
        tv_sec: ts.tv_sec + (total_ns / NS_PER_SEC) as libc::time_t,
        tv_nsec: (total_ns % NS_PER_SEC) as libc::c_long,
    }
}

/// Handle to a publish loop thread.
///
/// Dropping the handle signals the loop to stop and blocks until it exits.
pub struct PublishLoopHandle {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl PublishLoopHandle {
    /// Signals the loop to stop; it exits after the current period.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Waits for the loop thread to exit.
    pub fn join(mut self) {
        if let Some(handle) = self.join.take() {
            handle.join().ok();
        }
    }
}

impl Drop for PublishLoopHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.join.take() {
            handle.join().ok();
        }
    }
}

/// Runs `publisher` on a dedicated thread, calling `on_tick` once every
/// `period_ns` nanoseconds.
///
/// The thread takes ownership of the publisher. `on_tick` writes the sample
/// data and sends the frame; deadlines are absolute, so time spent in the
/// callback does not accumulate as drift. The thread requests `SCHED_FIFO` at
/// priority 50 and continues under normal scheduling if that is refused.
///
/// # Panics
///
/// Panics if the publish thread cannot be spawned.
#[cfg(target_os = "linux")]
pub fn spawn_publish_loop<F>(
    publisher: SvPublisher,
    period_ns: u64,
    on_tick: F,
) -> PublishLoopHandle
where
    F: FnMut(&mut SvPublisher) + Send + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);

    let mut pub_ = publisher;
    let mut on_tick = on_tick;

    let handle = thread::Builder::new()
        .name("sv-publisher".to_string())
        .spawn(move || {
            try_set_sched_fifo(50);

            let mut next = clock_gettime_monotonic();

            loop {
                if stop_clone.load(Ordering::Relaxed) {
                    tracing::debug!("sv-publisher stopping");
                    break;
                }

                on_tick(&mut pub_);

                next = timespec_add_ns(next, period_ns);
                clock_nanosleep_abs(&next);
            }
        })
        .expect("spawn sv-publisher thread");

    PublishLoopHandle {
        stop,
        join: Some(handle),
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;
    use crate::publisher::SvPublisherBuilder;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    const SRC_MAC: [u8; 6] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];

    fn make_publisher() -> SvPublisher {
        let mut builder = SvPublisherBuilder::new(SRC_MAC);
        builder.add_asdu("sv1", None::<String>, 1, 8).unwrap();
        builder.setup_complete().unwrap()
    }

    #[test]
    fn spawn_and_drop_no_panic() {
        let pub_ = make_publisher();
        let handle = spawn_publish_loop(pub_, 10_000_000, |_| {});
        std::thread::sleep(Duration::from_millis(50));
        // Dropping the handle stops the loop and joins the thread.
        drop(handle);
    }

    #[test]
    fn spawn_stop_explicit() {
        let pub_ = make_publisher();
        let handle = spawn_publish_loop(pub_, 10_000_000, |_| {});
        std::thread::sleep(Duration::from_millis(30));
        handle.stop();
        handle.join();
    }

    #[test]
    fn on_tick_called_multiple_times() {
        let pub_ = make_publisher();
        let count = Arc::new(Mutex::new(0u32));
        let count_clone = Arc::clone(&count);

        let handle = spawn_publish_loop(pub_, 5_000_000, move |_| {
            let mut c = count_clone.lock().unwrap();
            *c += 1;
        });

        std::thread::sleep(Duration::from_millis(100));
        handle.stop();
        handle.join();

        let final_count = *count.lock().unwrap();
        // 100 ms at a 5 ms period is about 20 ticks; the bound is loose to
        // tolerate scheduling delay on a busy machine.
        assert!(
            final_count >= 5,
            "on_tick ran {} times, expected at least 5",
            final_count
        );
    }
}
