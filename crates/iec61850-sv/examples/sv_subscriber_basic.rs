//! Subscribes to a Sampled Values stream and reports what arrives.
//!
//! Shows the receiving side of IEC 61850-9-2:
//!
//! 1. `SvSubscriberBuilder` sets the APPID and svID filter and the listener
//! 2. `SvReceiver` collects subscribers while idle
//! 3. `start_thread` runs the receive loop, which reads frames from the HAL
//!    Ethernet source and dispatches them to the matching subscriber
//! 4. every five seconds the example prints how many samples fired and how many
//!    the sample count says were missed
//!
//! Pairs with the `sv_publisher_basic` example on the same interface.
//!
//! ```sh
//! cargo build -p iec61850-sv --examples
//!
//! # Terminal 1
//! sudo ./target/debug/examples/sv_publisher_basic
//!
//! # Terminal 2, on loopback
//! sudo ./target/debug/examples/sv_subscriber_basic
//! ```
//!
//! Expected stderr:
//!
//! ```text
//! [subscriber] iface=lo appid=0x4000 svID=rustSV01
//! [subscriber] smpCnt=4000 IA=0 VA=1000000
//! [subscriber] fired=20000 missed=0 expected_size=64
//! ```
//!
//! The interface defaults to `lo`; pass another one as the first argument.
//!
//! Sampled Values ride directly on Ethernet, so this example needs a raw socket
//! rather than a TCP loopback connection: Linux only, and `CAP_NET_RAW` is
//! required.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("sv_subscriber_basic needs an AF_PACKET raw socket, which is Linux only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    linux_impl::run();
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use iec61850_sv::receiver::{Idle, SvReceiver};
    use iec61850_sv::subscriber::SvSubscriberBuilder;

    const APP_ID: u16 = 0x4000;
    const SV_ID: &str = "rustSV01";

    pub fn run() {
        let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".to_string());

        let counter = Arc::new(AtomicU64::new(0));
        let counter_cb = Arc::clone(&counter);
        let sub = Arc::new(
            SvSubscriberBuilder::new()
                .app_id(APP_ID)
                .sv_id(SV_ID)
                .listener(move |asdu| {
                    counter_cb.fetch_add(1, Ordering::Relaxed);
                    if counter_cb.load(Ordering::Relaxed).is_multiple_of(4000) {
                        // One sample a second is decoded and printed.
                        if let Ok(le) = asdu.parse_9_2_le() {
                            eprintln!(
                                "[subscriber] smpCnt={} IA={} VA={}",
                                asdu.smp_cnt,
                                le.ia().value,
                                le.va().value
                            );
                        }
                    }
                })
                .build(),
        );

        let mut rx = SvReceiver::<Idle>::new();
        rx.add_subscriber(Arc::clone(&sub));
        let source = raw_socket::open_l2_rx(&iface).expect("open AF_PACKET socket");
        let _handle = rx.start_thread(Box::new(source));

        eprintln!(
            "[subscriber] iface={iface} appid=0x{APP_ID:04x} svID={SV_ID}\n\
             [subscriber] one sample of every 4000 is printed; Ctrl+C to stop"
        );

        loop {
            std::thread::sleep(Duration::from_secs(5));
            eprintln!(
                "[subscriber] fired={} missed={} expected_size={}",
                counter.load(Ordering::Relaxed),
                sub.missed_count(),
                sub.expected_sample_size(),
            );
        }
    }

    mod raw_socket {
        use std::ffi::CString;
        use std::io::Error as IoError;
        use std::mem;
        use std::os::fd::{AsRawFd, OwnedFd};
        use std::time::Duration;

        use iec61850_hal::ethernet::{EthernetError, EthernetSource};

        pub struct L2RxSocket {
            fd: OwnedFd,
        }

        impl EthernetSource for L2RxSocket {
            fn recv(
                &mut self,
                buf: &mut [u8],
                _timeout: Option<Duration>,
            ) -> Result<usize, EthernetError> {
                let n = unsafe {
                    libc::recv(
                        self.fd.as_raw_fd(),
                        buf.as_mut_ptr() as *mut _,
                        buf.len(),
                        0,
                    )
                };
                if n < 0 {
                    Err(EthernetError::Os(format!(
                        "recv failed: {}",
                        IoError::last_os_error()
                    )))
                } else {
                    Ok(n as usize)
                }
            }
        }

        pub fn open_l2_rx(iface: &str) -> Result<L2RxSocket, IoError> {
            const ETH_P_SV: u16 = 0x88BA;
            let fd =
                unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, ETH_P_SV.to_be() as i32) };
            if fd < 0 {
                return Err(IoError::last_os_error());
            }
            let owned: OwnedFd = unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) };

            let iface_index = if_nametoindex(iface)?;
            let mut sa: libc::sockaddr_ll = unsafe { mem::zeroed() };
            sa.sll_family = libc::AF_PACKET as u16;
            sa.sll_protocol = ETH_P_SV.to_be();
            sa.sll_ifindex = iface_index;
            let rc = unsafe {
                libc::bind(
                    owned.as_raw_fd(),
                    &sa as *const _ as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_ll>() as u32,
                )
            };
            if rc < 0 {
                return Err(IoError::last_os_error());
            }
            Ok(L2RxSocket { fd: owned })
        }

        fn if_nametoindex(iface: &str) -> Result<i32, IoError> {
            let cstr = CString::new(iface).unwrap();
            let idx = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
            if idx == 0 {
                return Err(IoError::last_os_error());
            }
            Ok(idx as i32)
        }
    }
}
