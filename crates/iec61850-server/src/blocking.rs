//! Running the work that reaches application callbacks off the runtime's
//! worker threads.
//!
//! Every callback an application installs is synchronous, and nothing keeps
//! one from blocking on I/O, a lock or a channel. The server's own tasks, the
//! association tasks, the tick loop, the select timers and the command tasks,
//! run each stretch of work that can reach a callback on the blocking thread
//! pool of the runtime. A callback that blocks then holds one pool thread and
//! the task waiting for it, while every other task keeps running, on a
//! current-thread runtime too.
//!
//! The callbacks share the pool with every other user of `spawn_blocking` on
//! the runtime, `tokio::fs` included. Past its `max_blocking_threads` limit,
//! 512 by default, further work waits in a queue: requests, ticks, select
//! timeouts and releases alike. A runtime built with a small limit can
//! therefore be stalled by as few callbacks blocking at once.

/// Runs `work` on the blocking thread pool of the current runtime and returns
/// its result once it finishes.
///
/// A panic in `work` resumes in the caller. Returns `None` when the runtime is
/// shutting down and `work` never started.
pub(crate) async fn off_the_runtime<R, F>(work: F) -> Option<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(r) => Some(r),
        Err(e) => match e.try_into_panic() {
            Ok(payload) => std::panic::resume_unwind(payload),
            Err(_) => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn work_runs_off_the_thread_of_a_current_thread_runtime() {
        let caller = std::thread::current().id();
        let worker = off_the_runtime(|| std::thread::current().id()).await;
        assert_ne!(worker, Some(caller));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_panic_resumes_in_the_caller() {
        let task = tokio::spawn(off_the_runtime(|| panic!("in the work")));
        let err = task.await.expect_err("the panic reaches the caller");
        assert!(err.is_panic());
    }
}
