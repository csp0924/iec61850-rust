//! Synchronization primitive facade selected by environment feature.
//!
//! The reporting, control and data set subsystems take locks across await
//! points (network IO, poll loops, dispatch loops), so the guards must be held
//! across a suspension. `std::sync::MutexGuard` is not `Send` and the borrow
//! checker rejects that, hence an async lock API in both environments:
//!
//! - `std`: re-exports `tokio::sync::*` unchanged.
//! - `embedded`: wraps `spin::*` behind the same shape, where `lock`, `read`
//!   and `write` are `async fn` that acquire synchronously. On a single-core,
//!   single-future target there is no contention, so the await never yields.
//!
//! Preemption from an interrupt handler on a multi-core embedded target is not
//! covered by this facade.

#![allow(clippy::module_name_repetitions)]

#[cfg(feature = "std")]
pub use tokio::sync::Mutex;
#[cfg(all(feature = "std", feature = "reporting"))]
pub use tokio::sync::RwLock;

#[cfg(not(feature = "std"))]
mod embedded_locks {
    use core::ops::{Deref, DerefMut};
    #[cfg(feature = "reporting")]
    use spin::RwLock as SpinRwLock;
    use spin::{Mutex as SpinMutex, MutexGuard as SpinMutexGuard};

    /// Mutex with the call shape of `tokio::sync::Mutex`, backed by `spin`.
    pub struct Mutex<T> {
        inner: SpinMutex<T>,
    }

    impl<T> Mutex<T> {
        /// Wraps a value in an unlocked mutex.
        pub const fn new(t: T) -> Self {
            Self {
                inner: SpinMutex::new(t),
            }
        }

        /// Acquires the lock. The signature is `async` only to match the call
        /// shape; on a single-core target the acquisition always succeeds
        /// immediately and the await does not yield.
        #[allow(clippy::should_implement_trait)]
        pub async fn lock(&self) -> MutexGuard<'_, T> {
            MutexGuard {
                inner: self.inner.lock(),
            }
        }
    }

    /// Guard returned by `Mutex::lock`, releasing the lock when dropped.
    pub struct MutexGuard<'a, T> {
        inner: SpinMutexGuard<'a, T>,
    }

    impl<T> Deref for MutexGuard<'_, T> {
        type Target = T;
        fn deref(&self) -> &T {
            self.inner.deref()
        }
    }

    impl<T> DerefMut for MutexGuard<'_, T> {
        fn deref_mut(&mut self) -> &mut T {
            self.inner.deref_mut()
        }
    }

    /// Read-write lock with an async `read` and `write`, backed by `spin`.
    #[cfg(feature = "reporting")]
    pub struct RwLock<T> {
        inner: SpinRwLock<T>,
    }

    #[cfg(feature = "reporting")]
    impl<T> RwLock<T> {
        /// Wraps a value in an unlocked read-write lock.
        pub const fn new(t: T) -> Self {
            Self {
                inner: SpinRwLock::new(t),
            }
        }

        /// Acquires shared access. As with `Mutex::lock`, the signature is
        /// `async` only to match the call shape.
        pub async fn read(&self) -> RwLockReadGuard<'_, T> {
            RwLockReadGuard {
                inner: self.inner.read(),
            }
        }

        /// Acquires exclusive access. As with `Mutex::lock`, the signature is
        /// `async` only to match the call shape.
        pub async fn write(&self) -> RwLockWriteGuard<'_, T> {
            RwLockWriteGuard {
                inner: self.inner.write(),
            }
        }
    }

    /// Guard returned by `RwLock::read`, releasing the lock when dropped.
    #[cfg(feature = "reporting")]
    pub struct RwLockReadGuard<'a, T> {
        inner: spin::RwLockReadGuard<'a, T>,
    }

    #[cfg(feature = "reporting")]
    impl<T> Deref for RwLockReadGuard<'_, T> {
        type Target = T;
        fn deref(&self) -> &T {
            self.inner.deref()
        }
    }

    /// Guard returned by `RwLock::write`, releasing the lock when dropped.
    #[cfg(feature = "reporting")]
    pub struct RwLockWriteGuard<'a, T> {
        inner: spin::RwLockWriteGuard<'a, T>,
    }

    #[cfg(feature = "reporting")]
    impl<T> Deref for RwLockWriteGuard<'_, T> {
        type Target = T;
        fn deref(&self) -> &T {
            self.inner.deref()
        }
    }

    #[cfg(feature = "reporting")]
    impl<T> DerefMut for RwLockWriteGuard<'_, T> {
        fn deref_mut(&mut self) -> &mut T {
            self.inner.deref_mut()
        }
    }
}

#[cfg(not(feature = "std"))]
pub use embedded_locks::Mutex;
#[cfg(all(not(feature = "std"), feature = "reporting"))]
pub use embedded_locks::RwLock;
