//! SNTPv4 (RFC 4330) server and client.
//!
//! A minimal unicast SNTP server for IED time synchronization, plus a client
//! that queries an NTP or SNTP server.
//!
//! Invariants a caller relies on: no library path panics, every fallible one
//! returns a [`Result`]; a received datagram is length-checked by
//! [`SntpPacket::decode`] against the fixed 48-byte packet length before any
//! field is read; time is carried by
//! [`NtpTimestamp`], which names its epoch rather than exposing a bare
//! `u64`; and every rejected packet is reported through `tracing::warn!`.

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod client;
mod error;
mod packet;
mod server;
mod time;

pub use client::{SntpClient, SntpResponse};
pub use error::SntpError;
pub use packet::{LeapIndicator, Mode, SntpPacket, SNTP_PACKET_LEN};
pub use server::{SntpServer, SntpServerConfig};
pub use time::{NtpTimestamp, NTP_UNIX_OFFSET_S};
