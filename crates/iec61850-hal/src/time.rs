//! Async `Timer` trait, used together with the `transport` module.
//!
//! Timeout, retry and heartbeat logic in the layers above takes a `Timer`
//! instead of calling `tokio::time::sleep` directly. The std backend is
//! `TokioTimer` (feature `transport-tokio`); the embedded backend is
//! `EmbassyTimer` (feature `transport-embassy`).
//!
//! The trait takes `&self` rather than exposing static methods, so a caller
//! can inject a mock or a fake clock without binding to a concrete type.

pub use core::time::Duration;

/// Async sleep abstraction.
///
/// An implementation is `Send + Sync`, because futures cross await points on
/// a multi-threaded runtime, and `Clone`, because a caller holding
/// `&mut self` frequently needs `&self.timer` at the same time and cloning
/// the timer is the cleanest way out of that borrow conflict. Timers are
/// normally zero-sized or `Arc`-wrapped, so the clone costs nothing.
pub trait Timer: Clone + Send + Sync {
    /// Suspends the current task for `duration`.
    ///
    /// Resolution and jitter are decided by the backend: milliseconds on
    /// tokio, RTC ticks on embassy-time.
    fn sleep(&self, duration: Duration) -> impl core::future::Future<Output = ()> + Send;
}

// --- Timeout helper -----------------------------------------------------------

/// The future did not complete before [`with_timeout`] elapsed.
///
/// Equivalent to `tokio::time::error::Elapsed`, but decoupled from the
/// runtime so it also exists in a no_std build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutError;

impl core::fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("operation timed out")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TimeoutError {}

/// Races `fut` against `timer.sleep(duration)`.
///
/// Returns `Ok(v)` when `fut` finishes first, and `Err(TimeoutError)` when
/// the sleep finishes first. Same semantics as `tokio::time::timeout`, but
/// expressed over the [`Timer`] trait, so it also works under no_std + alloc.
///
/// Each poll polls `fut` before the timer, so a future that is already ready
/// is never lost to the sleep.
pub async fn with_timeout<Tm, F>(
    timer: &Tm,
    duration: Duration,
    fut: F,
) -> Result<F::Output, TimeoutError>
where
    Tm: Timer,
    F: core::future::Future,
{
    use core::future::Future as _;
    let mut fut = core::pin::pin!(fut);
    let mut sleep = core::pin::pin!(timer.sleep(duration));
    core::future::poll_fn(move |cx| {
        if let core::task::Poll::Ready(v) = fut.as_mut().poll(cx) {
            return core::task::Poll::Ready(Ok(v));
        }
        if let core::task::Poll::Ready(()) = sleep.as_mut().poll(cx) {
            return core::task::Poll::Ready(Err(TimeoutError));
        }
        core::task::Poll::Pending
    })
    .await
}

// --- std backend --------------------------------------------------------------

/// [`Timer`] backed by `tokio::time::sleep`.
#[cfg(feature = "transport-tokio")]
#[derive(Debug, Default, Clone, Copy)]
pub struct TokioTimer;

#[cfg(feature = "transport-tokio")]
impl Timer for TokioTimer {
    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await
    }
}

// --- embassy-time backend -----------------------------------------------------

/// [`Timer`] backed by `embassy_time::Timer::after`.
///
/// The embassy global time driver has to be initialized by the caller at HAL
/// level, for example through `embassy_stm32::time_driver_setup()`. This type
/// holds no state and exists only for trait dispatch.
#[cfg(feature = "transport-embassy")]
#[derive(Debug, Default, Clone, Copy)]
pub struct EmbassyTimer;

#[cfg(feature = "transport-embassy")]
impl Timer for EmbassyTimer {
    async fn sleep(&self, duration: Duration) {
        let nanos = duration.as_nanos();
        // embassy_time::Duration counts microseconds; round up so a sleep is
        // never shorter than requested.
        let micros = nanos.div_ceil(1_000).min(u64::MAX as u128) as u64;
        embassy_time::Timer::after(embassy_time::Duration::from_micros(micros)).await;
    }
}

#[cfg(all(test, feature = "transport-tokio"))]
mod tests_tokio {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn tokio_timer_advances() {
        let timer = TokioTimer;
        let start = tokio::time::Instant::now();
        timer.sleep(Duration::from_millis(50)).await;
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(50));
    }

    #[tokio::test(start_paused = true)]
    async fn with_timeout_fut_first() {
        let timer = TokioTimer;
        let fut = async { 42 };
        let r = with_timeout(&timer, Duration::from_millis(100), fut).await;
        assert_eq!(r, Ok(42));
    }

    #[tokio::test(start_paused = true)]
    async fn with_timeout_sleep_first() {
        let timer = TokioTimer;
        let slow = async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            "never"
        };
        let r = with_timeout(&timer, Duration::from_millis(50), slow).await;
        assert_eq!(r, Err(TimeoutError));
    }
}
