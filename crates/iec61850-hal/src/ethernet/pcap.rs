//! libpcap and NPCAP backend for L2 raw sockets.
//!
//! Used on Windows through NPCAP, and as a cross-platform fallback for
//! development and testing.
//!
//! Deployment: Linux needs libpcap (`libpcap-dev` or `libpcap-devel`), and
//! opening a raw L2 socket still requires `CAP_NET_RAW`, usually granted by
//!
//! ```sh
//! sudo setcap cap_net_raw=eip /path/to/binary
//! ```
//!
//! Windows needs the NPCAP runtime from <https://npcap.com>, installed with
//! WinPcap-compatible mode enabled, and its SDK to build; check the NPCAP
//! license before commercial use. macOS and BSD ship libpcap.
//!
//! `ethernet-pcap` and `ethernet-windows-npcap` both select this
//! implementation. They are separate features so that deployment
//! documentation and license exposure can be split: the NPCAP license is not
//! GPL compatible, while libpcap carries no such restriction.
//!
//! Implemented here: a wrapper over `pcap::Capture`, receive with the
//! configured timeout mapped to [`EthernetError::Timeout`], send, promiscuous
//! mode, interface lookup by name, and the duplex `EthernetSocket`.
//! Multicast groups are not joined explicitly, because libpcap has no
//! portable join API; the backend relies on the OS and NIC defaults.
//!
//! TODO: filter on EtherType with BPF to cut per-frame callback overhead.

use std::time::Duration;

use ::pcap::{Active, Capture, Device, Error as PcapError};

use super::{EthernetConfig, EthernetError, EthernetSink, EthernetSource};

/// The libpcap and NPCAP backend.
///
/// Wraps one active `pcap::Capture` for duplex reads and writes, and releases
/// the underlying handle on [`Drop`].
pub struct PcapSocket {
    cap: Capture<Active>,
    /// The configured timeout. pcap fixes it when the capture is opened, so
    /// it cannot be changed per receive.
    open_timeout_ms: Option<i32>,
}

impl std::fmt::Debug for PcapSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PcapSocket")
            .field("open_timeout_ms", &self.open_timeout_ms)
            .finish()
    }
}

impl PcapSocket {
    /// Opens a capture handle and applies `cfg`.
    ///
    /// `interface` is a platform identifier: `eth0`, `en0` or `lo` on Linux
    /// and macOS; a full device path such as `\Device\NPF_{GUID}`, or a
    /// friendly name obtained from [`list_devices`], on Windows.
    ///
    /// `multicast_groups` is ignored by this backend, since libpcap and NPCAP
    /// have no portable multicast join API; the OS and the NIC driver decide
    /// which multicast traffic arrives.
    ///
    /// # Errors
    ///
    /// [`EthernetError::InvalidConfig`] for an empty interface name,
    /// [`EthernetError::InterfaceNotFound`] when no device matches,
    /// [`EthernetError::PermissionDenied`] when the capture may not be
    /// opened, and [`EthernetError::Os`] for any other libpcap failure.
    pub fn open(cfg: &EthernetConfig) -> Result<Self, EthernetError> {
        if cfg.interface.is_empty() {
            return Err(EthernetError::InvalidConfig("interface name is empty"));
        }

        let device = find_device(&cfg.interface)?;

        let timeout_ms = cfg
            .recv_timeout
            .map(|d| {
                // pcap counts the timeout in milliseconds; clamp to i32.
                let ms = d.as_millis();
                if ms > i32::MAX as u128 {
                    i32::MAX
                } else {
                    ms as i32
                }
            })
            .unwrap_or(0); // 0 blocks until a frame arrives

        let mut builder = Capture::from_device(device)
            .map_err(|e| EthernetError::Os(format!("pcap from_device: {e}")))?
            .promisc(cfg.promiscuous)
            .immediate_mode(true)
            .snaplen(65535);

        if timeout_ms > 0 {
            builder = builder.timeout(timeout_ms);
        }

        let cap = builder.open().map_err(map_pcap_open_err)?;

        Ok(Self {
            cap,
            open_timeout_ms: cfg
                .recv_timeout
                .map(|d| d.as_millis().min(i32::MAX as u128) as i32),
        })
    }

    /// Returns the underlying capture, for advanced use such as installing a
    /// BPF filter.
    pub fn capture_mut(&mut self) -> &mut Capture<Active> {
        &mut self.cap
    }
}

impl EthernetSource for PcapSocket {
    fn recv(&mut self, buf: &mut [u8], _timeout: Option<Duration>) -> Result<usize, EthernetError> {
        // The timeout is fixed when the capture is opened, so the argument
        // cannot be honored here; callers set it through EthernetConfig.
        match self.cap.next_packet() {
            Ok(packet) => {
                let n = packet.data.len().min(buf.len());
                buf[..n].copy_from_slice(&packet.data[..n]);
                Ok(n)
            }
            Err(PcapError::TimeoutExpired) => Err(EthernetError::Timeout),
            Err(PcapError::NoMorePackets) => Ok(0),
            Err(e) => Err(EthernetError::Os(format!("pcap recv: {e}"))),
        }
    }
}

impl EthernetSink for PcapSocket {
    fn send(&mut self, frame: &[u8]) -> Result<usize, EthernetError> {
        self.cap
            .sendpacket(frame)
            .map_err(|e| EthernetError::Os(format!("pcap sendpacket: {e}")))?;
        Ok(frame.len())
    }
}

// --- helpers -----------------------------------------------------------------

fn find_device(name: &str) -> Result<Device, EthernetError> {
    // Try the name directly first: a full NPCAP device path or a Linux
    // interface name resolves this way.
    let direct = Device::from(name);
    if !direct.name.is_empty() {
        return Ok(direct);
    }

    // Otherwise match against the friendly name or the description.
    let list = Device::list().map_err(|e| EthernetError::Os(format!("pcap Device::list: {e}")))?;
    for dev in list {
        if dev.name == name || dev.desc.as_deref() == Some(name) {
            return Ok(dev);
        }
    }
    Err(EthernetError::InterfaceNotFound(name.to_string()))
}

fn map_pcap_open_err(err: PcapError) -> EthernetError {
    let msg = err.to_string();
    let lower = msg.to_lowercase();
    // pcap does not expose errno, so the permission case is recognized from
    // the message text.
    if lower.contains("permission")
        || lower.contains("operation not permitted")
        || lower.contains("access is denied")
    {
        EthernetError::PermissionDenied(msg)
    } else if lower.contains("no such device") || lower.contains("not found") {
        // A missing interface usually surfaces at open or activate time.
        EthernetError::InterfaceNotFound(msg)
    } else {
        EthernetError::Os(format!("pcap open: {msg}"))
    }
}

/// Lists the pcap interfaces available on this host.
///
/// Intended for examples and diagnostics. On Windows `Device::name` is a
/// `\Device\NPF_{GUID}` path; the friendly name is in `desc`.
///
/// # Errors
///
/// [`EthernetError::Os`] when libpcap cannot enumerate the devices.
pub fn list_devices() -> Result<Vec<Device>, EthernetError> {
    Device::list().map_err(|e| EthernetError::Os(format!("pcap Device::list: {e}")))
}

// --- tests -------------------------------------------------------------------

// Running these tests on Windows needs wpcap.lib from the NPCAP SDK, which a
// CI or plain development machine usually lacks, so they are compiled on
// Linux and macOS only to avoid a link failure. On Windows, use the example
// as a smoke test, or install the NPCAP SDK and set `LIB` first.
#[cfg(all(test, not(target_os = "windows")))]
mod tests {
    use super::*;

    /// `list_devices` returns `Ok` even on a host with no interfaces. The
    /// output is platform-dependent, so the test only pins that the call
    /// neither panics nor is unusable.
    #[test]
    fn list_devices_does_not_panic() {
        // May fail where libpcap is absent, but must not panic.
        let _ = list_devices();
    }

    /// An empty interface name is rejected before pcap is reached.
    #[test]
    fn open_empty_interface_returns_invalid_config() {
        let cfg = EthernetConfig::new("");
        assert!(matches!(
            PcapSocket::open(&cfg),
            Err(EthernetError::InvalidConfig(_))
        ));
    }
}
