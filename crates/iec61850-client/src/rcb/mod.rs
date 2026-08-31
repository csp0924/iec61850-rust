//! Client-side Report Control Block (RCB) access.
//!
//! [`mask`] defines `RcbWriteMask` and `TriggerOptions`; [`handle`] holds the
//! `RcbHandle` state with its accessors and the `update_values` decoder;
//! [`read`] fetches an RCB from a server; [`mod@write`] writes one back.
//!
//! Read-only fields are filtered out of a write with a warning, the write
//! order is derived from the field enum rather than maintained by hand, and a
//! value of an unexpected type is reported as an error rather than ignored.

pub mod handle;
pub mod mask;
pub mod read;
pub mod write;

pub use handle::{update_values, RcbHandle};
pub use mask::{RcbWriteMask, TriggerOptions};
pub use read::{create_rcb_from_mms, get_rcb_values, refresh_rcb_values, update_rcb_from_mms};
pub use write::set_rcb_values;
// `build_write_sequence`, `validate_mask_vs_type` and `RcbWriteItem` stay
// crate-internal.
