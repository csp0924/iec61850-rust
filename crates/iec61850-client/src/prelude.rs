//! Allocation and collection facade shared by the `std` and `embedded` builds.
//!
//! Submodules take `String`, `Vec`, `Arc` and `HashMap` from here so that no
//! call site needs its own `cfg` branch:
//!
//! - `Arc`: `std::sync::Arc`, or `alloc::sync::Arc` on embedded.
//! - `String`, `Vec`, `format!`, `ToString`: from `alloc` on embedded.
//!   They are in the std prelude anyway, but are re-exported here to keep one
//!   spelling across both environments.
//! - `HashMap`: `std::collections`, or `hashbrown` on embedded; only the
//!   report dispatch of the `reporting` feature uses it.
//! - `BTreeSet`: `std::collections`, or `alloc::collections` on embedded.
//!
//! Synchronization primitives are deliberately absent: `spin` must never be
//! reached on a std target, where busy-waiting burns a core. The async lock
//! facade lives in `crate::sync` instead.

// Arc
#[cfg(not(feature = "std"))]
pub(crate) use alloc::sync::Arc;
#[cfg(feature = "std")]
pub(crate) use std::sync::Arc;

// HashMap
#[cfg(all(not(feature = "std"), feature = "embedded", feature = "reporting"))]
pub(crate) use hashbrown::HashMap;
#[cfg(all(feature = "std", feature = "reporting"))]
pub(crate) use std::collections::HashMap;

// BTreeSet
#[cfg(not(feature = "std"))]
pub(crate) use alloc::collections::BTreeSet;
#[cfg(feature = "std")]
pub(crate) use std::collections::BTreeSet;

// String / Vec / format! / ToString
// These are already in the std prelude; re-exporting them keeps submodules on
// a single import path. The `vec!` macro is not re-exported: it is in the std
// prelude, and on no_std the `extern crate alloc` in `lib.rs` makes it visible
// crate-wide.
#[cfg(not(feature = "std"))]
pub(crate) use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
#[cfg(feature = "std")]
pub(crate) use std::{
    format,
    string::{String, ToString},
    vec::Vec,
};
