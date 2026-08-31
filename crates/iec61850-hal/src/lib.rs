//! Platform abstraction layer: L2 Ethernet sockets, async transport, timers.
//!
//! `ethernet` (feature `ethernet`, on by default) is the L2 raw socket
//! abstraction shared by GOOSE and Sampled Values. `transport` (feature
//! `transport`) is the async byte-stream trait the MMS layer is written
//! against, and `time` (same feature) is the async timer trait that goes
//! with it. Nothing here carries IEC 61850 semantics.
//!
//! Feature flags, with `default = ["std", "ethernet"]`:
//!
//! - `std` (default): uses the std prelude and implies `alloc`.
//! - `alloc`: the no_std path; required on embedded targets.
//! - `embedded`: currently equivalent to `alloc`, reserved as a backend switch.
//! - `ethernet` (default): traits and shared types, no platform dependency.
//! - `ethernet-linux-afpacket`: the Linux AF_PACKET backend; implies `std`.
//! - `ethernet-pcap` / `ethernet-windows-npcap`: the libpcap backend; implies `std`.
//! - `transport`: the `AsyncTransport` and `Timer` traits, definitions only.
//! - `transport-tokio`: a blanket `AsyncTransport` impl for
//!   `tokio::io::AsyncRead + AsyncWrite`, plus `TokioTimer`; implies `std`.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

/// Facade shared by the std and no_std builds. The crate itself needs no
/// `alloc` types yet; the module is kept so future additions have one place
/// to import from.
#[allow(unused_imports, dead_code)]
pub(crate) mod compat {
    pub mod prelude {
        pub use alloc::string::{String, ToString};
        pub use alloc::vec::Vec;
    }
}

#[cfg(feature = "ethernet")]
pub mod ethernet;

#[cfg(feature = "transport")]
pub mod transport;

#[cfg(feature = "transport")]
pub mod time;
