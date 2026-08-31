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
//! TODO: VLAN tag inject and strip for the GOOSE 5-tuple.
//! TODO: PACKET_MMAP zero-copy fast path.
//! TODO: RX timestamping (SO_TIMESTAMPING) for SV jitter measurement.

use std::io;
use std::mem::{size_of, zeroed, MaybeUninit};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use libc::{
    bind, c_int, c_void, close, if_nametoindex, packet_mreq, recv, send, setsockopt, sockaddr_ll,
    socket, socklen_t, timeval, AF_PACKET, ETH_P_ALL, PACKET_ADD_MEMBERSHIP,
    PACKET_DROP_MEMBERSHIP, PACKET_MR_MULTICAST, PACKET_MR_PROMISC, SOCK_RAW, SOL_PACKET,
    SOL_SOCKET, SO_RCVTIMEO,
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
    /// Groups joined so far, so `Drop` can leave them explicitly. The kernel
    /// would release them at close anyway.
    joined_groups: Vec<EthernetAddr>,
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

        let mut me = AfPacketSocket {
            fd,
            ifindex,
            joined_groups: Vec::new(),
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
    fn recv(&mut self, buf: &mut [u8], timeout: Option<Duration>) -> Result<usize, EthernetError> {
        if let Some(d) = timeout {
            self.set_recv_timeout(d)?;
        }

        let n = unsafe {
            recv(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            // SO_RCVTIMEO reports expiry as EAGAIN, EWOULDBLOCK on Linux.
            if err.raw_os_error() == Some(libc::EAGAIN) {
                return Err(EthernetError::Timeout);
            }
            return Err(EthernetError::Os(err.to_string()));
        }
        Ok(n as usize)
    }
}

impl EthernetSink for AfPacketSocket {
    fn send(&mut self, frame: &[u8]) -> Result<usize, EthernetError> {
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
