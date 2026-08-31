//! L2 Ethernet raw socket abstraction, shared by GOOSE, Sampled Values and
//! the routable profiles.
//!
//! The abstraction is a set of traits rather than a socket struct, so the
//! caller picks the backend. Receive and transmit are separate traits, so a
//! subscriber-only build carries no sink. No frame buffer is owned: the
//! caller passes `&mut [u8]` and gets back the number of bytes written, where
//! 0 means no frame was pending in non-blocking mode. The error type is
//! defined here instead of borrowed from `std::io`, which leaves a no_std
//! path open, and a MAC address is always the [`EthernetAddr`] newtype rather
//! than a bare `[u8; 6]`.
//!
//! Backends: `linux::AfPacketSocket` under feature `ethernet-linux-afpacket`
//! (Linux only), and `pcap::PcapSocket` under `ethernet-pcap` or
//! `ethernet-windows-npcap` (cross-platform; libpcap on Linux and the NPCAP
//! runtime on Windows have to be installed separately).
//!
//! TODO: add a macOS and BSD BPF backend.

use std::time::Duration;

#[cfg(all(feature = "ethernet-linux-afpacket", target_os = "linux"))]
#[cfg_attr(
    docsrs,
    doc(cfg(all(feature = "ethernet-linux-afpacket", target_os = "linux")))
)]
pub mod linux;

#[cfg(any(feature = "ethernet-pcap", feature = "ethernet-windows-npcap"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "ethernet-pcap", feature = "ethernet-windows-npcap")))
)]
pub mod pcap;

// --- MAC address --------------------------------------------------------------

/// A 6-byte L2 MAC address.
///
/// Used for GOOSE and SV destination addresses, multicast groups and
/// interface address comparisons.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct EthernetAddr(pub [u8; 6]);

impl EthernetAddr {
    /// The all-ones broadcast address.
    pub const BROADCAST: Self = Self([0xFF; 6]);

    /// Returns true when the group bit of octet 0 is set (IEEE 802.1D).
    pub const fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Returns true for the all-ones broadcast address.
    pub const fn is_broadcast(&self) -> bool {
        let b = self.0;
        b[0] == 0xFF && b[1] == 0xFF && b[2] == 0xFF && b[3] == 0xFF && b[4] == 0xFF && b[5] == 0xFF
    }

    /// Builds an address from a slice, or `None` if it is not 6 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let arr: [u8; 6] = bytes.try_into().ok()?;
        Some(Self(arr))
    }
}

impl core::fmt::Debug for EthernetAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5],
        )
    }
}

impl core::fmt::Display for EthernetAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self, f)
    }
}

// --- EtherType ----------------------------------------------------------------

/// EtherType constants used by IEC 61850, as big-endian wire values.
pub mod ethertype {
    /// GOOSE, per IEC 61850-8-1.
    pub const GOOSE: u16 = 0x88B8;
    /// Sampled Values, per IEC 61850-9-2.
    pub const SV: u16 = 0x88BA;
    /// VLAN tag, per IEEE 802.1Q.
    pub const VLAN: u16 = 0x8100;
}

// --- Error --------------------------------------------------------------------

/// An error raised by an L2 socket operation.
#[derive(Debug, thiserror::Error)]
pub enum EthernetError {
    /// The interface does not exist, or opening it is not permitted.
    #[error("interface `{0}` not found or not permitted")]
    InterfaceNotFound(String),

    /// The backend is unavailable here: the feature is off, or `target_os`
    /// does not match.
    #[error("backend not supported on this platform: {0}")]
    BackendNotSupported(&'static str),

    /// `CAP_NET_RAW` or administrator rights are missing.
    #[error("permission denied (CAP_NET_RAW or admin required): {0}")]
    PermissionDenied(String),

    /// A blocking receive exceeded its timeout.
    #[error("recv timeout")]
    Timeout,

    /// An underlying OS error, carrying the errno text.
    #[error("os error: {0}")]
    Os(String),

    /// The configuration is invalid, for example a malformed multicast group
    /// or an over-long interface name.
    #[error("invalid config: {0}")]
    InvalidConfig(&'static str),
}

// --- Config -------------------------------------------------------------------

/// L2 socket configuration, passed when a backend is constructed.
#[derive(Debug, Clone)]
pub struct EthernetConfig {
    /// Platform-dependent interface name, such as `eth0`, `Ethernet 1` or `en0`.
    pub interface: String,

    /// Multicast groups to join: `01:0C:CD:01:xx:xx` for GOOSE,
    /// `01:0C:CD:04:xx:xx` for SV.
    pub multicast_groups: Vec<EthernetAddr>,

    /// Whether to enable promiscuous mode. A subscriber normally leaves this
    /// off; diagnostics turn it on.
    pub promiscuous: bool,

    /// Receive timeout. `None` blocks; `Some(d)` sets `SO_RCVTIMEO`.
    pub recv_timeout: Option<Duration>,
}

impl EthernetConfig {
    /// Creates a configuration for `interface` with no multicast group, no
    /// promiscuous mode and no receive timeout.
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            multicast_groups: Vec::new(),
            promiscuous: false,
            recv_timeout: None,
        }
    }

    /// Adds a multicast group to join.
    pub fn with_multicast(mut self, addr: EthernetAddr) -> Self {
        self.multicast_groups.push(addr);
        self
    }

    /// Sets promiscuous mode.
    pub fn with_promiscuous(mut self, on: bool) -> Self {
        self.promiscuous = on;
        self
    }

    /// Sets the receive timeout.
    pub fn with_recv_timeout(mut self, timeout: Duration) -> Self {
        self.recv_timeout = Some(timeout);
        self
    }
}

// --- Trait --------------------------------------------------------------------

/// Receives L2 frames.
pub trait EthernetSource: Send {
    /// Reads one frame into `buf` and returns how many bytes were written,
    /// including the complete L2 header.
    ///
    /// `timeout` overrides [`EthernetConfig::recv_timeout`]; `None` keeps the
    /// value the socket was configured with.
    ///
    /// # Errors
    ///
    /// [`EthernetError::Timeout`] when a blocking receive expires, and any
    /// other variant for a socket failure. `Ok(0)` is not an error: it means
    /// no frame was pending in non-blocking mode.
    fn recv(&mut self, buf: &mut [u8], timeout: Option<Duration>) -> Result<usize, EthernetError>;
}

/// Sends L2 frames.
pub trait EthernetSink: Send {
    /// Sends one complete frame, whose L2 header the caller has already built
    /// as destination MAC, source MAC, EtherType and payload.
    ///
    /// Returns the number of bytes sent. Some backends, AF_PACKET among them,
    /// either send the whole frame or fail.
    ///
    /// # Errors
    ///
    /// Any [`EthernetError`] variant the backend reports for a failed send.
    fn send(&mut self, frame: &[u8]) -> Result<usize, EthernetError>;
}

/// A socket that both receives and sends.
pub trait EthernetSocket: EthernetSource + EthernetSink {}

impl<T: EthernetSource + EthernetSink> EthernetSocket for T {}

// --- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethernet_addr_multicast_bit() {
        assert!(EthernetAddr([0x01, 0x0C, 0xCD, 0x01, 0x00, 0x00]).is_multicast());
        assert!(EthernetAddr([0x01, 0x0C, 0xCD, 0x04, 0x00, 0x00]).is_multicast());
        assert!(!EthernetAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]).is_multicast());
    }

    #[test]
    fn ethernet_addr_broadcast() {
        assert!(EthernetAddr::BROADCAST.is_broadcast());
        assert!(EthernetAddr::BROADCAST.is_multicast()); // broadcast implies multicast
        assert!(!EthernetAddr([0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).is_broadcast());
    }

    #[test]
    fn ethernet_addr_from_slice_size_check() {
        assert!(EthernetAddr::from_slice(&[1, 2, 3, 4, 5, 6]).is_some());
        assert!(EthernetAddr::from_slice(&[1, 2, 3, 4, 5]).is_none());
        assert!(EthernetAddr::from_slice(&[1, 2, 3, 4, 5, 6, 7]).is_none());
    }

    #[test]
    fn ethernet_addr_display_is_lowercase_colon() {
        let s = format!("{}", EthernetAddr([0x01, 0x0C, 0xCD, 0x01, 0xab, 0xCD]));
        assert_eq!(s, "01:0c:cd:01:ab:cd");
    }

    #[test]
    fn ethertype_constants_match_ieee() {
        assert_eq!(ethertype::GOOSE, 0x88B8);
        assert_eq!(ethertype::SV, 0x88BA);
        assert_eq!(ethertype::VLAN, 0x8100);
    }

    #[test]
    fn config_builder_chain() {
        let cfg = EthernetConfig::new("eth0")
            .with_multicast(EthernetAddr([0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01]))
            .with_multicast(EthernetAddr([0x01, 0x0C, 0xCD, 0x04, 0x00, 0x01]))
            .with_promiscuous(true)
            .with_recv_timeout(Duration::from_millis(100));
        assert_eq!(cfg.interface, "eth0");
        assert_eq!(cfg.multicast_groups.len(), 2);
        assert!(cfg.promiscuous);
        assert_eq!(cfg.recv_timeout, Some(Duration::from_millis(100)));
    }

    /// The traits stay dyn-compatible: receivers hold their backend as
    /// `Box<dyn EthernetSource>`.
    #[test]
    fn traits_are_object_safe() {
        fn _accept_source(_: Box<dyn EthernetSource>) {}
        fn _accept_sink(_: Box<dyn EthernetSink>) {}
        fn _accept_socket(_: Box<dyn EthernetSocket>) {}
    }
}
