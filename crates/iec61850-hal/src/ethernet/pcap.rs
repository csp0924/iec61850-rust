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
//! On Linux, `send` replaces an all-zero source address with the
//! interface address read from sysfs; elsewhere the caller supplies it.
//!
//! TODO: filter on EtherType with BPF to cut per-frame callback overhead.

use std::time::Duration;

use ::pcap::{Active, Capture, Device, Error as PcapError};

use super::{EthernetAddr, EthernetConfig, EthernetError, EthernetSink, EthernetSource};

/// The libpcap and NPCAP backend.
///
/// Wraps one active `pcap::Capture` for duplex reads and writes, and releases
/// the underlying handle on [`Drop`].
pub struct PcapSocket {
    cap: Capture<Active>,
    /// The configured timeout. pcap fixes it when the capture is opened, so
    /// it cannot be changed per receive.
    open_timeout_ms: Option<i32>,
    /// Hardware address of the interface, when the platform reports one.
    hw_addr: Option<EthernetAddr>,
    /// Copy of an outgoing frame whose source address is filled in.
    send_scratch: Vec<u8>,
}

impl std::fmt::Debug for PcapSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PcapSocket")
            .field("open_timeout_ms", &self.open_timeout_ms)
            .field("hw_addr", &self.hw_addr)
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
        let hw_addr = interface_hw_addr(&device.name);

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
            hw_addr,
            send_scratch: Vec::new(),
        })
    }

    /// Returns the hardware address of the interface, or `None` when the
    /// platform does not report one or it is all zero.
    pub fn hw_addr(&self) -> Option<EthernetAddr> {
        self.hw_addr
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
    /// Sends one frame; an all-zero source address is replaced with
    /// [`hw_addr`](PcapSocket::hw_addr) when the interface has one.
    fn send(&mut self, frame: &[u8]) -> Result<usize, EthernetError> {
        let frame = match self.hw_addr {
            Some(addr) if has_zero_source(frame) => {
                self.send_scratch.clear();
                self.send_scratch.extend_from_slice(frame);
                if let Some(src) = self.send_scratch.get_mut(6..12) {
                    src.copy_from_slice(&addr.0);
                }
                self.send_scratch.as_slice()
            }
            _ => frame,
        };
        self.cap
            .sendpacket(frame)
            .map_err(|e| EthernetError::Os(format!("pcap sendpacket: {e}")))?;
        Ok(frame.len())
    }
}

// --- helpers -----------------------------------------------------------------

/// Returns whether `frame` carries an all-zero source address.
fn has_zero_source(frame: &[u8]) -> bool {
    frame
        .get(6..12)
        .is_some_and(|src| src.iter().all(|b| *b == 0))
}

/// Reads the hardware address of interface `name` from
/// `/sys/class/net/<name>/address`.
#[cfg(target_os = "linux")]
fn interface_hw_addr(name: &str) -> Option<EthernetAddr> {
    if name.contains('/') {
        return None;
    }
    let text = std::fs::read_to_string(format!("/sys/class/net/{name}/address")).ok()?;
    parse_mac(text.trim())
}

/// Hardware address lookup is only implemented for Linux.
#[cfg(not(target_os = "linux"))]
fn interface_hw_addr(_name: &str) -> Option<EthernetAddr> {
    None
}

/// Parses `aa:bb:cc:dd:ee:ff`, returning `None` for any other form and for
/// the all-zero address.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_mac(text: &str) -> Option<EthernetAddr> {
    let mut out = [0u8; 6];
    let mut parts = text.split(':');
    for byte in &mut out {
        let part = parts.next()?;
        if part.len() != 2 {
            return None;
        }
        *byte = u8::from_str_radix(part, 16).ok()?;
    }
    if parts.next().is_some() || out == [0; 6] {
        return None;
    }
    Some(EthernetAddr(out))
}

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

    #[test]
    fn parse_mac_accepts_sysfs_form() {
        assert_eq!(
            parse_mac("02:42:ac:11:00:02"),
            Some(EthernetAddr([0x02, 0x42, 0xac, 0x11, 0x00, 0x02]))
        );
    }

    #[test]
    fn parse_mac_rejects_other_forms() {
        for bad in [
            "",
            "00:00:00:00:00:00",
            "02:42:ac:11:00",
            "02:42:ac:11:00:02:03",
            "2:42:ac:11:00:02",
            "zz:42:ac:11:00:02",
        ] {
            assert_eq!(parse_mac(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn zero_source_is_detected() {
        let mut f = [0xffu8; 20];
        f[6..12].fill(0);
        assert!(has_zero_source(&f));
        f[6] = 2;
        assert!(!has_zero_source(&f));
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
