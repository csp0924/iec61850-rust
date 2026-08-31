//! Synchronization and collection facade shared by the `std` and embedded builds.
//!
//! - `Arc`: `alloc::sync::Arc` on both targets.
//! - `Mutex` / `RwLock`: `std::sync::*` (poison-aware) under `std`, `spin::*`
//!   (busy-wait) under `embedded`.
//! - `HashMap` / `HashSet`: `std::collections::*` under `std`, `hashbrown::*`
//!   under `embedded`.
//!
//! Spin locks are never used in a `std` build, where busy-waiting would
//! saturate a host CPU; every `spin` import is gated on `not(feature = "std")`.
//! `Mutex` is re-exported without a wrapper because `std::sync::Mutex::lock`
//! yields a `Result` while `spin::Mutex::lock` yields the guard directly; every
//! `Mutex` call site in `service`, `handler`, and `mapping` is gated behind
//! `full-server`, so a no_std build never reaches one.

pub use alloc::sync::Arc;

#[cfg(all(not(feature = "std"), feature = "embedded"))]
pub use hashbrown::{HashMap, HashSet};
#[cfg(feature = "std")]
pub use std::collections::{HashMap, HashSet};

#[cfg(all(not(feature = "std"), feature = "embedded"))]
pub use spin::{Mutex, RwLock};
#[cfg(feature = "std")]
pub use std::sync::{Mutex, RwLock};

// `RwLock::read` / `::write` return `Result<Guard, PoisonError>` under std and a
// bare guard under spin. Both helpers normalize to `Option<Guard>` (`None` =
// poisoned, never produced by spin); both guard types `Deref<Target = T>`.
#[cfg(feature = "std")]
#[allow(dead_code)]
pub(crate) fn rwlock_read<T>(lock: &RwLock<T>) -> Option<std::sync::RwLockReadGuard<'_, T>> {
    lock.read().ok()
}
#[cfg(all(not(feature = "std"), feature = "embedded"))]
#[allow(dead_code)]
pub(crate) fn rwlock_read<T>(lock: &RwLock<T>) -> Option<spin::RwLockReadGuard<'_, T>> {
    Some(lock.read())
}

#[cfg(feature = "std")]
#[allow(dead_code)]
pub(crate) fn rwlock_write<T>(lock: &RwLock<T>) -> Option<std::sync::RwLockWriteGuard<'_, T>> {
    lock.write().ok()
}
#[cfg(all(not(feature = "std"), feature = "embedded"))]
#[allow(dead_code)]
pub(crate) fn rwlock_write<T>(lock: &RwLock<T>) -> Option<spin::RwLockWriteGuard<'_, T>> {
    Some(lock.write())
}
