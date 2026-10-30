//! Linux AF_PACKET backend for L2 raw sockets.
//!
//! Implements the L2 raw socket over `AF_PACKET / SOCK_RAW` for GOOSE,
//! Sampled Values and the routable profiles.
//!
//! Opening such a socket needs `CAP_NET_RAW`, usually granted at deployment
//! with
//!
//! ```sh
//! sudo setcap cap_net_raw=eip /path/to/binary
//! ```
//!
//! otherwise the process has to start as root.
//!
//! Implemented here: `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` bound to
//! an interface index, multicast join through `PACKET_ADD_MEMBERSHIP` with
//! `packet_mreq`, blocking and timed receive through `SO_RCVTIMEO`, send, and
//! promiscuous mode through `PACKET_MR_PROMISC`.
//!
//! The kernel moves an 802.1Q tag out of a received frame into
//! `PACKET_AUXDATA`; `recv` puts it back, so a caller sees the frame as it was
//! on the wire. A frame longer than the caller's buffer is dropped rather than
//! returned truncated. `send` replaces an all-zero source address with the
//! address of the bound interface.
//!
//! TODO: PACKET_MMAP zero-copy fast path.
//! TODO: RX timestamping (SO_TIMESTAMPING) for SV jitter measurement.

use std::io;
use std::mem::{size_of, zeroed, MaybeUninit};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use libc::{
    bind, c_int, c_void, close, getsockname, if_nametoindex, iovec, msghdr, packet_mreq, recvmsg,
    send, setsockopt, sockaddr_ll, socket, socklen_t, timeval, tpacket_auxdata, AF_PACKET,
    ETH_P_ALL, MSG_TRUNC, PACKET_ADD_MEMBERSHIP, PACKET_AUXDATA, PACKET_DROP_MEMBERSHIP,
    PACKET_MR_MULTICAST, PACKET_MR_PROMISC, SOCK_RAW, SOL_PACKET, SOL_SOCKET, SO_RCVTIMEO,
    TP_STATUS_VLAN_TPID_VALID, TP_STATUS_VLAN_VALID,
};

use super::{EthernetAddr, EthernetConfig, EthernetError, EthernetSink, EthernetSource};

/// Linux AF_PACKET raw socket.
///
/// Closes the file descriptor on drop, which also leaves every multicast
/// group the kernel still has joined.
#[derive(Debug)]
pub struct AfPacketSocket {
    fd: OwnedFd,
    ifindex: u32,
    /// Hardware address of the bound interface, when it has a 6-byte one.
    hw_addr: Option<EthernetAddr>,
    /// Groups joined so far, so `Drop` can leave them explicitly. The kernel
    /// would release them at close anyway.
    joined_groups: Vec<EthernetAddr>,
    /// Copy of an outgoing frame whose source address is filled in.
    send_scratch: Vec<u8>,
}

impl AfPacketSocket {
    /// Opens the socket, binds it to the configured interface and applies the
    /// rest of `cfg`.
    ///
    /// # Errors
    ///
    /// [`EthernetError::InvalidConfig`] for an empty interface name or one
    /// containing NUL, [`EthernetError::InterfaceNotFound`] when the name has
    /// no index, [`EthernetError::PermissionDenied`] when `CAP_NET_RAW` is
    /// missing, and [`EthernetError::Os`] for any other syscall failure.
    pub fn open(cfg: &EthernetConfig) -> Result<Self, EthernetError> {
        if cfg.interface.is_empty() {
            return Err(EthernetError::InvalidConfig("interface name is empty"));
        }

        let ifindex = lookup_ifindex(&cfg.interface)?;

        let fd = unsafe { socket(AF_PACKET, SOCK_RAW, (ETH_P_ALL as u16).to_be() as c_int) };
        if fd < 0 {
            let err = io::Error::last_os_error();
            return Err(map_open_err(err));
        }
        let fd: OwnedFd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };

        let mut sll: sockaddr_ll = unsafe { zeroed() };
        sll.sll_family = AF_PACKET as u16;
        sll.sll_protocol = (ETH_P_ALL as u16).to_be();
        sll.sll_ifindex = ifindex as i32;
        let rc = unsafe {
            bind(
                fd.as_raw_fd(),
                &sll as *const sockaddr_ll as *const _,
                size_of::<sockaddr_ll>() as socklen_t,
            )
        };
        if rc < 0 {
            return Err(EthernetError::Os(io::Error::last_os_error().to_string()));
        }

        let on: c_int = 1;
        // SAFETY: `fd` is an open packet socket and `on` is a live `c_int` whose
        // size is the option length passed.
        let rc = unsafe {
            setsockopt(
                fd.as_raw_fd(),
                SOL_PACKET,
                PACKET_AUXDATA,
                &on as *const c_int as *const c_void,
                size_of::<c_int>() as socklen_t,
            )
        };
        if rc < 0 {
            return Err(EthernetError::Os(io::Error::last_os_error().to_string()));
        }

        let hw_addr = bound_hw_addr(&fd);

        let mut me = AfPacketSocket {
            fd,
            ifindex,
            hw_addr,
            joined_groups: Vec::new(),
            send_scratch: Vec::new(),
        };

        for group in &cfg.multicast_groups {
            me.join_multicast(*group)?;
        }

        if cfg.promiscuous {
            me.set_promiscuous(true)?;
        }

        if let Some(d) = cfg.recv_timeout {
            me.set_recv_timeout(d)?;
        }

        Ok(me)
    }

    /// Returns the hardware address of the bound interface, or `None` when the
    /// interface has no 6-byte address or it is all zero, as on loopback.
    pub fn hw_addr(&self) -> Option<EthernetAddr> {
        self.hw_addr
    }

    /// Joins one multicast group, through `PACKET_ADD_MEMBERSHIP` with
    /// `PACKET_MR_MULTICAST`.
    ///
    /// # Errors
    ///
    /// [`EthernetError::PermissionDenied`] or [`EthernetError::Os`] if the
    /// `setsockopt` call fails.
    pub fn join_multicast(&mut self, addr: EthernetAddr) -> Result<(), EthernetError> {
        let mreq = make_mreq(self.ifindex, PACKET_MR_MULTICAST, addr);
        setsockopt_packet(&self.fd, PACKET_ADD_MEMBERSHIP, &mreq)?;
        self.joined_groups.push(addr);
        Ok(())
    }

    /// Leaves one multicast group.
    ///
    /// # Errors
    ///
    /// [`EthernetError::PermissionDenied`] or [`EthernetError::Os`] if the
    /// `setsockopt` call fails.
    pub fn leave_multicast(&mut self, addr: EthernetAddr) -> Result<(), EthernetError> {
        let mreq = make_mreq(self.ifindex, PACKET_MR_MULTICAST, addr);
        setsockopt_packet(&self.fd, PACKET_DROP_MEMBERSHIP, &mreq)?;
        self.joined_groups.retain(|a| a != &addr);
        Ok(())
    }

    /// Enables or disables promiscuous mode. A subscriber normally does not
    /// need it; diagnostics do.
    ///
    /// # Errors
    ///
    /// [`EthernetError::PermissionDenied`] or [`EthernetError::Os`] if the
    /// `setsockopt` call fails.
    pub fn set_promiscuous(&mut self, on: bool) -> Result<(), EthernetError> {
        let mreq = make_mreq(self.ifindex, PACKET_MR_PROMISC, EthernetAddr([0; 6]));
        let opt = if on {
            PACKET_ADD_MEMBERSHIP
        } else {
            PACKET_DROP_MEMBERSHIP
        };
        setsockopt_packet(&self.fd, opt, &mreq)
    }

    /// Sets `SO_RCVTIMEO`, after which a receive that finds no frame returns
    /// [`EthernetError::Timeout`].
    ///
    /// # Errors
    ///
    /// [`EthernetError::Os`] if the `setsockopt` call fails.
    pub fn set_recv_timeout(&mut self, timeout: Duration) -> Result<(), EthernetError> {
        let tv = timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: timeout.subsec_micros() as libc::suseconds_t,
        };
        let rc = unsafe {
            setsockopt(
                self.fd.as_raw_fd(),
                SOL_SOCKET,
                SO_RCVTIMEO,
                &tv as *const timeval as *const c_void,
                size_of::<timeval>() as socklen_t,
            )
        };
        if rc < 0 {
            return Err(EthernetError::Os(io::Error::last_os_error().to_string()));
        }
        Ok(())
    }
}

impl EthernetSource for AfPacketSocket {
    /// Receives one frame, with an 802.1Q tag the kernel moved into
    /// `PACKET_AUXDATA` written back after the source address.
    ///
    /// A frame that does not fit `buf`, counting a restored tag, is dropped
    /// and reported as [`EthernetError::Os`] naming both lengths, so no
    /// truncated frame reaches a decoder.
    fn recv(&mut self, buf: &mut [u8], timeout: Option<Duration>) -> Result<usize, EthernetError> {
        if let Some(d) = timeout {
            self.set_recv_timeout(d)?;
        }

        // Aligned for `cmsghdr`; room for one `tpacket_auxdata` message.
        let mut control = [0u64; 8];
        let mut iov = iovec {
            iov_base: buf.as_mut_ptr() as *mut c_void,
            iov_len: buf.len(),
        };
        // SAFETY: `msghdr` is a plain C struct; all-zero bytes are a valid value,
        // null pointers with zero lengths, before the fields are set below.
        let mut msg: msghdr = unsafe { zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = size_of_val(&control) as _;

        // SAFETY: `msg` points at `iov`, which covers exactly `buf`, and at
        // `control`; all three outlive the call.
        let n = unsafe { recvmsg(self.fd.as_raw_fd(), &mut msg, MSG_TRUNC) };
        if n < 0 {
            let err = io::Error::last_os_error();
            // SO_RCVTIMEO reports expiry as EAGAIN, EWOULDBLOCK on Linux.
            if err.raw_os_error() == Some(libc::EAGAIN) {
                return Err(EthernetError::Timeout);
            }
            return Err(EthernetError::Os(err.to_string()));
        }
        // With MSG_TRUNC a packet socket returns the length on the wire.
        let len = n as usize;

        // SAFETY: the kernel filled `msg_controllen` bytes of `control`, and
        // the CMSG macros stay within the length recorded in `msg`.
        let vlan = unsafe { auxdata_vlan(&msg) };

        let total = len + if vlan.is_some() { 4 } else { 0 };
        if total > buf.len() {
            return Err(EthernetError::Os(format!(
                "dropped a {total} byte frame that does not fit the {} byte buffer",
                buf.len()
            )));
        }
        match vlan {
            Some((tpid, tci)) => Ok(insert_vlan_tag(buf, len, tpid, tci)),
            None => Ok(len),
        }
    }
}

impl EthernetSink for AfPacketSocket {
    /// Sends one frame; an all-zero source address is replaced with
    /// [`hw_addr`](AfPacketSocket::hw_addr) when the interface has one.
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
        let n = unsafe {
            send(
                self.fd.as_raw_fd(),
                frame.as_ptr() as *const c_void,
                frame.len(),
                0,
            )
        };
        if n < 0 {
            return Err(EthernetError::Os(io::Error::last_os_error().to_string()));
        }
        Ok(n as usize)
    }
}

// --- helpers ------------------------------------------------------------------

/// Reads the hardware address of the interface a packet socket is bound to.
fn bound_hw_addr(fd: &OwnedFd) -> Option<EthernetAddr> {
    // SAFETY: `sockaddr_ll` is a plain C struct of integers and byte arrays,
    // for which all-zero bytes are a valid value.
    let mut sll: sockaddr_ll = unsafe { zeroed() };
    let mut len = size_of::<sockaddr_ll>() as socklen_t;
    // SAFETY: `sll` is a writable `sockaddr_ll` of the size passed in `len`.
    let rc = unsafe {
        getsockname(
            fd.as_raw_fd(),
            &mut sll as *mut sockaddr_ll as *mut _,
            &mut len,
        )
    };
    if rc < 0 || sll.sll_halen != 6 {
        return None;
    }
    let addr = EthernetAddr::from_slice(sll.sll_addr.get(..6)?)?;
    (addr.0 != [0; 6]).then_some(addr)
}

/// Returns the TPID and TCI of a VLAN tag reported in `PACKET_AUXDATA`.
///
/// # Safety
///
/// `msg` must be a `msghdr` that `recvmsg` has just filled, with its control
/// buffer still alive.
unsafe fn auxdata_vlan(msg: &msghdr) -> Option<(u16, u16)> {
    let mut cmsg = libc::CMSG_FIRSTHDR(msg);
    while !cmsg.is_null() {
        let hdr = &*cmsg;
        let data_len = (hdr.cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize);
        if hdr.cmsg_level == SOL_PACKET
            && hdr.cmsg_type == PACKET_AUXDATA
            && data_len >= size_of::<tpacket_auxdata>()
        {
            let aux = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const tpacket_auxdata);
            return vlan_from_auxdata(&aux);
        }
        cmsg = libc::CMSG_NXTHDR(msg, cmsg);
    }
    None
}

/// Returns the TPID and TCI the kernel recorded for a stripped tag.
///
/// A kernel that predates `TP_STATUS_VLAN_VALID` signals a tag only by a
/// non-zero TCI; a TPID it does not report is 802.1Q's 0x8100.
fn vlan_from_auxdata(aux: &tpacket_auxdata) -> Option<(u16, u16)> {
    if aux.tp_status & TP_STATUS_VLAN_VALID == 0 && aux.tp_vlan_tci == 0 {
        return None;
    }
    let tpid = if aux.tp_status & TP_STATUS_VLAN_TPID_VALID != 0 {
        aux.tp_vlan_tpid
    } else {
        0x8100
    };
    Some((tpid, aux.tp_vlan_tci))
}

/// Writes a VLAN tag after the source address of the `len`-byte frame in
/// `buf` and returns the new length.
///
/// A frame shorter than the two addresses is returned unchanged. The caller
/// guarantees `len + 4 <= buf.len()`.
fn insert_vlan_tag(buf: &mut [u8], len: usize, tpid: u16, tci: u16) -> usize {
    if len < 12 || len + 4 > buf.len() {
        return len;
    }
    buf.copy_within(12..len, 16);
    buf[12..14].copy_from_slice(&tpid.to_be_bytes());
    buf[14..16].copy_from_slice(&tci.to_be_bytes());
    len + 4
}

/// Returns whether `frame` carries an all-zero source address.
fn has_zero_source(frame: &[u8]) -> bool {
    frame
        .get(6..12)
        .is_some_and(|src| src.iter().all(|b| *b == 0))
}

fn lookup_ifindex(name: &str) -> Result<u32, EthernetError> {
    let cstr = std::ffi::CString::new(name)
        .map_err(|_| EthernetError::InvalidConfig("interface name contains NUL"))?;
    let idx = unsafe { if_nametoindex(cstr.as_ptr()) };
    if idx == 0 {
        return Err(EthernetError::InterfaceNotFound(name.to_string()));
    }
    Ok(idx)
}

fn make_mreq(ifindex: u32, mr_type: c_int, addr: EthernetAddr) -> packet_mreq {
    let mut mreq: packet_mreq = unsafe { MaybeUninit::zeroed().assume_init() };
    mreq.mr_ifindex = ifindex as i32;
    mreq.mr_type = mr_type as u16;
    mreq.mr_alen = 6;
    mreq.mr_address[..6].copy_from_slice(&addr.0);
    mreq
}

fn setsockopt_packet(fd: &OwnedFd, opt: c_int, mreq: &packet_mreq) -> Result<(), EthernetError> {
    let rc = unsafe {
        setsockopt(
            fd.as_raw_fd(),
            SOL_PACKET,
            opt,
            mreq as *const packet_mreq as *const c_void,
            size_of::<packet_mreq>() as socklen_t,
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return Err(map_setsockopt_err(err));
    }
    Ok(())
}

fn map_open_err(err: io::Error) -> EthernetError {
    match err.raw_os_error() {
        Some(libc::EPERM) | Some(libc::EACCES) => EthernetError::PermissionDenied(err.to_string()),
        _ => EthernetError::Os(err.to_string()),
    }
}

fn map_setsockopt_err(err: io::Error) -> EthernetError {
    match err.raw_os_error() {
        Some(libc::EPERM) | Some(libc::EACCES) => EthernetError::PermissionDenied(err.to_string()),
        _ => EthernetError::Os(err.to_string()),
    }
}

impl Drop for AfPacketSocket {
    fn drop(&mut self) {
        // Leave the groups explicitly; the kernel would also clear them at close.
        let groups = std::mem::take(&mut self.joined_groups);
        for g in groups {
            let mreq = make_mreq(self.ifindex, PACKET_MR_MULTICAST, g);
            // Errors are ignored: the drop path is best effort.
            unsafe {
                setsockopt(
                    self.fd.as_raw_fd(),
                    SOL_PACKET,
                    PACKET_DROP_MEMBERSHIP,
                    &mreq as *const packet_mreq as *const c_void,
                    size_of::<packet_mreq>() as socklen_t,
                );
            }
        }
        // The descriptor is closed when the `fd` field drops.
        let _ = close; // keeps the import available for a future fast path
    }
}

// --- tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn aux(status: u32, tci: u16, tpid: u16) -> tpacket_auxdata {
        let mut a: tpacket_auxdata = unsafe { zeroed() };
        a.tp_status = status;
        a.tp_vlan_tci = tci;
        a.tp_vlan_tpid = tpid;
        a
    }

    #[test]
    fn auxdata_without_a_tag_reports_none() {
        assert_eq!(vlan_from_auxdata(&aux(0, 0, 0)), None);
    }

    #[test]
    fn auxdata_tag_with_tpid_is_reported() {
        let a = aux(
            TP_STATUS_VLAN_VALID | TP_STATUS_VLAN_TPID_VALID,
            0x8064,
            0x88a8,
        );
        assert_eq!(vlan_from_auxdata(&a), Some((0x88a8, 0x8064)));
    }

    #[test]
    fn auxdata_tag_without_tpid_defaults_to_8021q() {
        assert_eq!(
            vlan_from_auxdata(&aux(TP_STATUS_VLAN_VALID, 0, 0)),
            Some((0x8100, 0))
        );
        assert_eq!(
            vlan_from_auxdata(&aux(0, 0x0064, 0)),
            Some((0x8100, 0x0064))
        );
    }

    #[test]
    fn vlan_tag_is_inserted_after_the_source_address() {
        let mut buf = [0u8; 24];
        let frame: Vec<u8> = (1..=18).collect();
        buf[..18].copy_from_slice(&frame);
        let n = insert_vlan_tag(&mut buf, 18, 0x8100, 0x8064);
        assert_eq!(n, 22);
        assert_eq!(&buf[..12], &frame[..12]);
        assert_eq!(&buf[12..16], &[0x81, 0x00, 0x80, 0x64]);
        assert_eq!(&buf[16..22], &frame[12..18]);
    }

    #[test]
    fn vlan_tag_that_does_not_fit_leaves_the_frame() {
        let mut buf = [7u8; 20];
        assert_eq!(insert_vlan_tag(&mut buf, 18, 0x8100, 1), 18);
        assert_eq!(buf, [7u8; 20]);
    }

    #[test]
    fn zero_source_is_detected() {
        let mut f = [0xffu8; 20];
        f[6..12].fill(0);
        assert!(has_zero_source(&f));
        f[11] = 1;
        assert!(!has_zero_source(&f));
        assert!(!has_zero_source(&[0u8; 11]));
    }

    /// A missing interface yields `InterfaceNotFound`. The test runs without
    /// `CAP_NET_RAW`, because `if_nametoindex` needs no privilege.
    #[test]
    fn open_nonexistent_interface_returns_not_found() {
        let cfg = EthernetConfig::new("definitely-not-a-real-iface-zzz999");
        match AfPacketSocket::open(&cfg) {
            Err(EthernetError::InterfaceNotFound(name)) => {
                assert_eq!(name, "definitely-not-a-real-iface-zzz999");
            }
            other => panic!("expected InterfaceNotFound, got {:?}", other),
        }
    }

    /// An empty interface name yields `InvalidConfig`.
    #[test]
    fn open_empty_interface_returns_invalid_config() {
        let cfg = EthernetConfig::new("");
        assert!(matches!(
            AfPacketSocket::open(&cfg),
            Err(EthernetError::InvalidConfig(_))
        ));
    }

    /// An interface name containing NUL yields `InvalidConfig`.
    #[test]
    fn open_interface_with_nul_returns_invalid_config() {
        let cfg = EthernetConfig::new("eth\0bad");
        assert!(matches!(
            AfPacketSocket::open(&cfg),
            Err(EthernetError::InvalidConfig(_))
        ));
    }
}
