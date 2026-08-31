//! The IEC 61850 data model tree - IED, logical device, logical node, data
//! object, data attribute - together with the `MmsValue` type and the common
//! data class factories.
//!
//! Structure and semantics follow IEC 61850-7-2 and IEC 61850-7-3.
//!
//! Shape of the model, which callers rely on: children live in `Vec`s, so
//! their order is stable and indexable, which is what `GetVariableAccessAttributes`
//! and `GetNameList` enumeration need; a control block belongs to the logical
//! node that owns it rather than to a flat list on the model root; an array
//! container is marked by `Option<u32>` rather than by a sentinel node; there
//! is no reverse lookup from a value back to its data attribute; and every
//! name is an owned `String`.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_debug_implementations)]
#![forbid(unsafe_code)]

// `#[macro_use]` keeps `vec!` and `format!` available across the crate in a
// no_std build. Under `std` this `extern crate alloc` is redundant but
// harmless, since `std` re-exports the same types.
#[macro_use]
extern crate alloc;

/// Facade shared by the `std` and `no_std` builds.
///
/// `HashMap` and `HashSet` come from `std::collections` or from `hashbrown`,
/// `Arc` from `std::sync` or from `alloc::sync`, and `RwLock` from
/// `std::sync`, with poison handling, or from `spin`, which busy-waits.
/// `rwlock_read` and `rwlock_write` hide the difference in how a guard is
/// acquired.
///
/// A `std` build never uses `spin::RwLock`: busy-waiting would saturate a CPU.
pub(crate) mod compat {
    // Both builds take the prelude from `alloc`; `std` re-exports the same
    // types. A file needs only `use crate::compat::prelude::*;` to bring
    // String, Vec, Box and ToString into scope.
    pub mod prelude {
        pub use alloc::string::{String, ToString};
        pub use alloc::vec::Vec;
        // `Box` is unused so far; add it when a caller needs it.
    }

    #[cfg(not(feature = "std"))]
    pub use hashbrown::{HashMap, HashSet};
    #[cfg(feature = "std")]
    pub use std::collections::{HashMap, HashSet};

    #[cfg(not(feature = "std"))]
    pub use alloc::sync::Arc;
    #[cfg(not(feature = "std"))]
    pub use spin::{RwLock, RwLockReadGuard, RwLockWriteGuard};
    #[cfg(feature = "std")]
    pub use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

    /// Acquires a read guard. The `std` version resolves poisoning; the spin
    /// version has no such state.
    #[cfg(feature = "std")]
    #[inline]
    pub fn rwlock_read<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
        lock.read().expect("RwLock poisoned")
    }
    #[cfg(not(feature = "std"))]
    #[inline]
    pub fn rwlock_read<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
        lock.read()
    }

    /// Acquires a write guard. The `std` version resolves poisoning; the spin
    /// version has no such state. The model itself only reads; this helper
    /// exists for the server's write path.
    #[cfg(feature = "std")]
    #[inline]
    #[allow(dead_code)]
    pub fn rwlock_write<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
        lock.write().expect("RwLock poisoned")
    }
    #[cfg(not(feature = "std"))]
    #[inline]
    #[allow(dead_code)]
    pub fn rwlock_write<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
        lock.write()
    }
}

pub mod builder;
pub mod cb;
pub mod cdc;
pub mod error;
pub mod fc;
pub mod object_ref;
pub mod tree;
pub mod types;
pub mod value;

pub use builder::{DataObjectBuilder, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder};
pub use cb::{
    GooseControlBlock, LogControlBlock, ReportControlBlock, SettingGroupControlBlock,
    SvControlBlock,
};
pub use cdc::{CdcOptions, ControlOptions};
pub use error::{ModelError, Result};
pub use fc::FC;
pub use object_ref::{ObjectRef, Segment, OBJECT_REF_MAX_LEN};
pub use tree::{
    DataAttribute, DataObject, DataSet, DataSetEntry, DoChild, IedModel, LogicalDevice,
    LogicalNode, ModelNode, NodeRef,
};
pub use types::{ControlModel, DataAttributeType, Dbpos, OrCat, Quality, TrgOps, Validity};
pub use value::MmsValue;
