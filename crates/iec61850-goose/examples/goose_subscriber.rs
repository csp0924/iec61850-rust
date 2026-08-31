//! Subscribes to a GOOSE publication and prints every event it raises.
//!
//! Shows the smallest complete subscriber of IEC 61850-8-1:
//!
//! 1. `GooseSubscriberBuilder` sets the filter (gocbRef, APPID, destination
//!    MAC) and the listener closure
//! 2. `GooseReceiver::new`, `add_subscriber` and `start` move the receiver from
//!    the idle state into the running one
//! 3. the loop owns the socket: received bytes go to `handle_message`
//! 4. the listener sees three kinds of event: `NewState` when stNum advances,
//!    `Retransmission` when only sqNum does, and `Expired` when
//!    `timeAllowedToLive` elapses with no frame
//!
//! An stNum that goes backwards is reported with `state_valid` false, and a
//! confRev that does not match the filter arrives as a parse error rather than
//! a silently dropped frame.
//!
//! Pairs with the `goose_publisher` example on the same interface.
//!
//! ```sh
//! cargo build -p iec61850-goose --examples
//!
//! # Terminal 1
//! sudo ./target/debug/examples/goose_publisher
//!
//! # Terminal 2, on loopback
//! sudo ./target/debug/examples/goose_subscriber
//! ```
//!
//! Expected stderr:
//!
//! ```text
//! [subscriber] iface=lo appid=0x1000 gocbRef=DemoIED/LLN0$GO$gcbStatus
//! [subscriber] [NewState] stNum=1 sqNum=0 entries=3 valid=true
//! [subscriber]   data[0] = Boolean(true)
//! [subscriber] [Retx]     stNum=1 sqNum=1 valid=true
//! ```
//!
//! The interface defaults to `lo`; pass another one as the first argument.
//!
//! GOOSE rides directly on Ethernet, so this example needs a raw socket rather
//! than a TCP loopback connection: Linux only, and `CAP_NET_RAW` is required.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("goose_subscriber needs an AF_PACKET raw socket, which is Linux only");
    eprintln!("the subscriber API is covered by `cargo test -p iec61850-goose subscriber`");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    linux_impl::run();
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use std::time::{Duration, Instant};

    use iec61850_goose::receiver::GooseReceiver;
    use iec61850_goose::subscriber::{GooseEvent, GooseSubscriberBuilder};

    /// Filter parameters, matching what the `goose_publisher` example sends.
    const APP_ID: u16 = 0x1000;
    const DST_MAC: [u8; 6] = [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01];
    const GOCB_REF: &str = "DemoIED/LLN0$GO$gcbStatus";

    pub fn run() {
        let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".to_string());

        // The subscriber pairs a frame filter with the listener closure.
        let subscriber = GooseSubscriberBuilder::new()
            .gocb_ref(GOCB_REF)
            .app_id(APP_ID)
            .dst_mac(DST_MAC)
            .listener(|ev| match ev {
                GooseEvent::NewState {
                    prev_st_num,
                    state,
                    parse_result,
                } => {
                    eprintln!(
                        "[subscriber] [NewState] stNum {} → {} sqNum={} dataset_len={} valid={}",
                        prev_st_num,
                        state.st_num,
                        state.sq_num,
                        state.dataset_values.len(),
                        state.state_valid,
                    );
                    if let Err(e) = parse_result {
                        eprintln!("[subscriber]   parse_result err: {e:?}");
                    }
                    for (i, v) in state.dataset_values.iter().enumerate() {
                        eprintln!("[subscriber]   data[{i}] = {v:?}");
                    }
                }
                GooseEvent::Retransmission {
                    state,
                    parse_result,
                } => {
                    eprintln!(
                        "[subscriber] [Retx]     stNum={} sqNum={} valid={}",
                        state.st_num, state.sq_num, state.state_valid,
                    );
                    if let Err(e) = parse_result {
                        eprintln!("[subscriber]   parse_result Err: {e:?}");
                    }
                }
                GooseEvent::Expired { last_state } => {
                    eprintln!(
                        "[subscriber] [Expired]  last stNum={} sqNum={} after TATL={}ms",
                        last_state.st_num, last_state.sq_num, last_state.time_allowed_to_live_ms,
                    );
                }
            })
            .build();

        // Starting the receiver moves it from the idle state into the running one.
        let mut receiver = GooseReceiver::new();
        receiver.set_interface_id(iface.clone());
        receiver.add_subscriber(subscriber);
        let mut receiver = receiver.start();

        // The receiver owns no socket, so the example opens one and binds it.
        let sock =
            raw_socket::open_l2(&iface).expect("open AF_PACKET socket, which needs CAP_NET_RAW");
        sock.set_recv_timeout(Duration::from_millis(100))
            .expect("set recv timeout");

        eprintln!(
            "[subscriber] iface={iface} appid=0x{APP_ID:04x} gocbRef={GOCB_REF}\n\
             [subscriber] waiting for GOOSE frames; Ctrl+C to stop"
        );

        // handle_message checks expiry for the frames it sees; the separate
        // tick below covers a silent link, where no frame arrives at all.
        let mut buf = vec![0u8; 1518];
        let mut next_tick = Instant::now() + Duration::from_millis(500);
        loop {
            match sock.recv(&mut buf) {
                Ok(n) if n > 0 => {
                    receiver.handle_message(&buf[..n]);
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // A receive timeout leaves room for the expiry scan below.
                }
                Err(e) => {
                    eprintln!("[subscriber] recv failed: {e}");
                    break;
                }
            }
            // Scan for expiry twice a second even when nothing arrives.
            let now = Instant::now();
            if now >= next_tick {
                receiver.tick(None);
                next_tick = now + Duration::from_millis(500);
            }
        }
    }

    /// Minimal AF_PACKET raw socket, enough to send and receive L2 frames.
    mod raw_socket {
        use std::ffi::CString;
        use std::io::Error as IoError;
        use std::mem;
        use std::os::fd::{AsRawFd, OwnedFd};
        use std::time::Duration;

        pub struct L2Socket {
            fd: OwnedFd,
        }

        impl L2Socket {
            pub fn recv(&self, buf: &mut [u8]) -> Result<usize, IoError> {
                let n = unsafe {
                    libc::recv(
                        self.fd.as_raw_fd(),
                        buf.as_mut_ptr() as *mut _,
                        buf.len(),
                        0,
                    )
                };
                if n < 0 {
                    return Err(IoError::last_os_error());
                }
                Ok(n as usize)
            }

            pub fn set_recv_timeout(&self, dur: Duration) -> Result<(), IoError> {
                let tv = libc::timeval {
                    tv_sec: dur.as_secs() as libc::time_t,
                    tv_usec: dur.subsec_micros() as libc::suseconds_t,
                };
                let rc = unsafe {
                    libc::setsockopt(
                        self.fd.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_RCVTIMEO,
                        &tv as *const _ as *const _,
                        mem::size_of::<libc::timeval>() as u32,
                    )
                };
                if rc < 0 {
                    return Err(IoError::last_os_error());
                }
                Ok(())
            }
        }

        pub fn open_l2(iface: &str) -> Result<L2Socket, IoError> {
            let fd = unsafe {
                libc::socket(
                    libc::AF_PACKET,
                    libc::SOCK_RAW,
                    (libc::ETH_P_ALL as u16).to_be() as i32,
                )
            };
            if fd < 0 {
                return Err(IoError::last_os_error());
            }
            let owned: OwnedFd = unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) };

            let iface_index = if_nametoindex(iface)?;
            let mut sa: libc::sockaddr_ll = unsafe { mem::zeroed() };
            sa.sll_family = libc::AF_PACKET as u16;
            sa.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
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
            Ok(L2Socket { fd: owned })
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
