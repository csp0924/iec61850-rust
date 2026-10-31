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
//! Implemented here: a wrapper over `pcap::Capture`, receive with a timeout
//! mapped to [`EthernetError::Timeout`], send, promiscuous mode, interface
//! lookup by name, and the duplex `EthernetSocket`.
//!
//! The libpcap read timeout is fixed when a capture is opened and, on some
//! platforms, does not end a read on a quiet link at all. The capture is
//! therefore opened in non-blocking mode, and `recv` polls it every
//! [`POLL_INTERVAL`] until a frame arrives or its own timeout has passed. A
//! timeout is honored per call, and a frame waits at most one poll interval
//! before `recv` returns it.
//! Multicast groups are not joined explicitly, because libpcap has no
//! portable join API; the backend relies on the OS and NIC defaults.
//!
//! A frame longer than the caller's buffer is dropped rather than returned
//! truncated. On Linux, `send` replaces an all-zero source address with the
//! interface address read from sysfs; elsewhere the caller supplies it.
//!
//! TODO: filter on EtherType with BPF to cut per-frame callback overhead.

use std::time::{Duration, Instant};

use ::pcap::{Active, Capture, Device, Error as PcapError};

use super::{EthernetAddr, EthernetConfig, EthernetError, EthernetSink, EthernetSource};

/// Pause between two reads of a capture that had no frame.
pub const POLL_INTERVAL: Duration = Duration::from_millis(1);

/// The libpcap and NPCAP backend.
///
/// Wraps one active `pcap::Capture` for duplex reads and writes, and releases
/// the underlying handle on [`Drop`].
pub struct PcapSocket {
    cap: Capture<Active>,
    /// The receive timeout from [`EthernetConfig::recv_timeout`], used when
    /// `recv` is given none.
    recv_timeout: Option<Duration>,
    /// Hardware address of the interface, when the platform reports one.
    hw_addr: Option<EthernetAddr>,
    /// Copy of an outgoing frame whose source address is filled in.
    send_scratch: Vec<u8>,
}

impl std::fmt::Debug for PcapSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PcapSocket")
            .field("recv_timeout", &self.recv_timeout)
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

        let cap = Capture::from_device(device)
            .map_err(|e| EthernetError::Os(format!("pcap from_device: {e}")))?
            .promisc(cfg.promiscuous)
            .immediate_mode(true)
            .snaplen(65535)
            .open()
            .map_err(map_pcap_open_err)?
            .setnonblock()
            .map_err(|e| EthernetError::Os(format!("pcap setnonblock: {e}")))?;

        Ok(Self {
            cap,
            recv_timeout: cfg.recv_timeout,
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
    /// Receives one frame.
    ///
    /// `timeout`, or the configured receive timeout when it is `None`, bounds
    /// the wait, give or take one [`POLL_INTERVAL`]; with neither the call
    /// waits for a frame. A frame that does not fit `buf` is dropped and reported as
    /// [`EthernetError::Os`] naming both lengths, so no truncated frame
    /// reaches a decoder.
    fn recv(&mut self, buf: &mut [u8], timeout: Option<Duration>) -> Result<usize, EthernetError> {
        let deadline = timeout.or(self.recv_timeout).map(|d| Instant::now() + d);
        let cap = &mut self.cap;
        let poll = || match cap.next_packet() {
            Ok(packet) => {
                let n = packet.data.len();
                let Some(dst) = buf.get_mut(..n) else {
                    return Poll::Failed(EthernetError::Os(format!(
                        "dropped a {n} byte frame that does not fit the {} byte buffer",
                        buf.len()
                    )));
                };
                dst.copy_from_slice(packet.data);
                Poll::Frame(n)
            }
            Err(PcapError::TimeoutExpired) => Poll::Idle,
            Err(PcapError::NoMorePackets) => Poll::Frame(0),
            Err(e) => Poll::Failed(EthernetError::Os(format!("pcap recv: {e}"))),
        };
        wait_for_frame(deadline, Instant::now, std::thread::sleep, poll)
    }
}

/// Outcome of one wait of the capture.
enum Poll {
    /// A frame of this many bytes was copied, or 0 when the capture has
    /// nothing more to deliver.
    Frame(usize),
    /// No frame was pending.
    Idle,
    /// The receive failed.
    Failed(EthernetError),
}

/// Repeats `poll`, pausing [`POLL_INTERVAL`] with `sleep` after each idle
/// read, until it yields a frame or a failure, or until `now` reaches
/// `deadline` after an idle read; no deadline waits indefinitely.
fn wait_for_frame(
    deadline: Option<Instant>,
    mut now: impl FnMut() -> Instant,
    mut sleep: impl FnMut(Duration),
    mut poll: impl FnMut() -> Poll,
) -> Result<usize, EthernetError> {
    loop {
        match poll() {
            Poll::Frame(n) => return Ok(n),
            Poll::Failed(e) => return Err(e),
            Poll::Idle => {
                if deadline.is_some_and(|d| now() >= d) {
                    return Err(EthernetError::Timeout);
                }
                sleep(POLL_INTERVAL);
            }
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

/// Timeout handling of `recv`, which needs no capture device.
#[cfg(test)]
mod wait_tests {
    use super::*;
    use std::cell::Cell;

    /// Runs `wait_for_frame` against a capture that is idle for `idle_reads`
    /// reads and then yields `then`, on a clock that only the injected sleep
    /// advances. Returns the result, the number of reads, and the time slept.
    fn run(
        deadline_after: Option<Duration>,
        idle_reads: usize,
        then: Poll,
    ) -> (Result<usize, EthernetError>, usize, Duration) {
        let start = Instant::now();
        let slept = Cell::new(Duration::ZERO);
        let reads = Cell::new(0usize);
        let mut then = Some(then);
        let r = wait_for_frame(
            deadline_after.map(|d| start + d),
            || start + slept.get(),
            |d| slept.set(slept.get() + d),
            || {
                let n = reads.get();
                reads.set(n + 1);
                if n < idle_reads {
                    Poll::Idle
                } else {
                    then.take().unwrap_or(Poll::Idle)
                }
            },
        );
        (r, reads.get(), slept.get())
    }

    #[test]
    fn a_deadline_ends_the_wait_after_an_idle_read() {
        let (r, reads, slept) = run(Some(Duration::from_millis(5)), usize::MAX, Poll::Idle);
        assert_eq!(r, Err(EthernetError::Timeout));
        assert_eq!(reads, 6, "reads at 0 to 5 ms");
        assert_eq!(slept, Duration::from_millis(5));
    }

    #[test]
    fn a_zero_timeout_reads_once() {
        let (r, reads, slept) = run(Some(Duration::ZERO), usize::MAX, Poll::Idle);
        assert_eq!(r, Err(EthernetError::Timeout));
        assert_eq!(reads, 1);
        assert_eq!(slept, Duration::ZERO);
    }

    #[test]
    fn a_frame_before_the_deadline_is_returned() {
        let (r, reads, _) = run(Some(Duration::from_secs(1)), 2, Poll::Frame(60));
        assert_eq!(r, Ok(60));
        assert_eq!(reads, 3);
    }

    #[test]
    fn no_deadline_keeps_waiting_through_idle_reads() {
        let (r, reads, slept) = run(None, 50, Poll::Frame(64));
        assert_eq!(r, Ok(64));
        assert_eq!(reads, 51);
        assert_eq!(slept, POLL_INTERVAL * 50);
    }

    #[test]
    fn a_failure_ends_the_wait() {
        let (r, _, _) = run(None, 1, Poll::Failed(EthernetError::Os("gone".into())));
        assert_eq!(r, Err(EthernetError::Os("gone".into())));
    }
}
