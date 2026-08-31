//! Allocation and collection facade shared by the `std` and `embedded` builds.
//!
//! Submodules take `String`, `Vec`, `Arc`, `HashMap` and `HashSet` from here so
//! that no call site needs its own `cfg` branch:
//!
//! - `Arc`: `std::sync::Arc`, or `alloc::sync::Arc` on embedded.
//! - `String`, `Vec`, `format!`, `Box`, `ToString`: from `alloc` on embedded.
//!   They are in the std prelude anyway, but are re-exported here to keep one
//!   spelling across both environments.
//! - `HashMap` and `HashSet`: `std::collections`, or `hashbrown` on embedded.
//!
//! Synchronization primitives are deliberately absent: `spin` must never be
//! reached on a std target, where busy-waiting burns a core. The async lock
//! facade lives in `crate::sync` instead.

#![allow(unused_imports)]

// Arc
#[cfg(not(feature = "std"))]
pub(crate) use alloc::sync::Arc;
#[cfg(feature = "std")]
pub(crate) use std::sync::Arc;

// HashMap / HashSet
#[cfg(all(not(feature = "std"), feature = "embedded"))]
pub(crate) use hashbrown::{HashMap, HashSet};
#[cfg(feature = "std")]
pub(crate) use std::collections::{HashMap, HashSet};

// String / Vec / format! / Box / ToString
// These are already in the std prelude; re-exporting them keeps submodules on
// a single import path. The `vec!` macro is not re-exported: it is in the std
// prelude, and on no_std the `extern crate alloc` in `lib.rs` makes it visible
// crate-wide.
#[cfg(not(feature = "std"))]
pub(crate) use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};
#[cfg(feature = "std")]
pub(crate) use std::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};
