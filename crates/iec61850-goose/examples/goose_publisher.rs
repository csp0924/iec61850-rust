//! Publishes a GOOSE data set on an Ethernet interface.
//!
//! Shows the smallest complete publisher of IEC 61850-8-1:
//!
//! 1. `CommParameters` carries the APPID, the destination MAC and the VLAN tag
//! 2. `GoosePublisher::new` builds the frame template and opens no socket, so
//!    the caller owns the transport
//! 3. the loop calls `tick(now)` to learn when the next frame is due, then
//!    `publish_at` to encode it and sends the bytes itself
//! 4. every five seconds the simulated process value changes and
//!    `increase_st_num` restarts the retransmission sequence at T1, the
//!    exponential back-off of IEC 61850-8-1
//!
//! Pairs with the `goose_subscriber` example on the same interface.
//!
//! ```sh
//! cargo build -p iec61850-goose --examples
//!
//! # Terminal 1, on loopback
//! sudo ./target/debug/examples/goose_publisher
//!
//! # Terminal 2
//! sudo ./target/debug/examples/goose_subscriber
//! ```
//!
//! Expected stderr:
//!
//! ```text
//! [publisher] iface=lo appid=0x1000 gocbRef=DemoIED/LLN0$GO$gcbStatus
//! [publisher] tx stNum=1 sqNum=0 bytes=113
//! [publisher] tx stNum=1 sqNum=1 bytes=113
//! [publisher] event stNum=2 breaker=false current=0mA counter=1
//! ```
//!
//! The interface defaults to `lo`; pass another one as the first argument.
//!
//! GOOSE rides directly on Ethernet, so this example needs a raw socket rather
//! than a TCP loopback connection: Linux only, and `CAP_NET_RAW` is required
//! (`sudo setcap cap_net_raw+ep <bin>` avoids running the whole example as
//! root). Other platforms print a note and exit.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("goose_publisher needs an AF_PACKET raw socket, which is Linux only");
    eprintln!("the publisher API is covered by `cargo test -p iec61850-goose publisher`");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    linux_impl::run();
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use std::time::{Duration, Instant};

    use iec61850_goose::frame::VlanPriority;
    use iec61850_goose::publisher::{CommParameters, GoosePublisher};
    use iec61850_model::MmsValue;

    /// GOOSE multicast MAC, from the `01:0c:cd:01:xx:xx` range that
    /// IEC 61850-8-1 reserves.
    const DST_MAC: [u8; 6] = [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01];
    /// Source MAC of this publisher; any non-zero address identifies it in a capture.
    const SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    /// Control block and data set of the demonstration CID,
    /// `crates/iec61850-server/examples/models/demo.cid`.
    const GOCB_REF: &str = "DemoIED/LLN0$GO$gcbStatus";
    const DATASET_REF: &str = "DemoIED/LLN0$dsStatus";
    const APP_ID: u16 = 0x1000;

    pub fn run() {
        let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".to_string());

        // Communication parameters: APPID, destination MAC, VLAN priority.
        let comm = CommParameters::new(APP_ID, DST_MAC)
            .with_priority(VlanPriority::new(4).unwrap())
            .with_src_mac(SRC_MAC);

        // confRev 1, and no goID, which falls back to the gocbRef.
        let mut publisher =
            GoosePublisher::new(comm, GOCB_REF, None, DATASET_REF, 1).expect("publisher new");

        // A three-member data set: a breaker position, a current, a counter.
        let mut breaker_position = true; // Boolean
        let mut current_value: i32 = 100; // Integer (mA)
        let mut event_counter: i32 = 0; // Integer

        let make_dataset = |breaker: bool, current: i32, counter: i32| -> Vec<MmsValue> {
            vec![
                MmsValue::Boolean(breaker),
                MmsValue::Integer(current as i64),
                MmsValue::Integer(counter as i64),
            ]
        };

        // The publisher owns no socket, so the example opens one and binds it.
        let sock =
            raw_socket::open_l2(&iface).expect("open AF_PACKET socket, which needs CAP_NET_RAW");
        eprintln!(
            "[publisher] iface={iface} appid=0x{APP_ID:04x} gocbRef={GOCB_REF}\n\
             [publisher] dataset={{ Boolean(breaker), Integer(current_mA), Integer(event_counter) }}\n\
             [publisher] the data changes every 5 s; Ctrl+C to stop"
        );

        // The retransmission schedule is driven by the caller, not a timer thread.
        let start = Instant::now();
        let mut next_event_at = start + Duration::from_secs(5);

        loop {
            let now = Instant::now();

            // A data change bumps stNum, which restarts the retransmission at T1.
            if now >= next_event_at {
                breaker_position = !breaker_position;
                current_value = if breaker_position { 100 } else { 0 };
                event_counter += 1;
                publisher.increase_st_num();
                eprintln!(
                    "[publisher] event stNum={} breaker={} current={}mA counter={}",
                    publisher.st_num(),
                    breaker_position,
                    current_value,
                    event_counter
                );
                next_event_at = now + Duration::from_secs(5);
            }

            if publisher.tick(now).is_some() {
                let st = publisher.st_num();
                let sq = publisher.sq_num();
                let dataset = make_dataset(breaker_position, current_value, event_counter);
                let frame = publisher.publish_at(&dataset, now).expect("publish");
                if let Err(e) = sock.send_l2(&frame) {
                    eprintln!("[publisher] send failed: {e}");
                    std::process::exit(3);
                }
                eprintln!("[publisher] tx stNum={st} sqNum={sq} bytes={}", frame.len());
            }

            // Sleeping is clamped to 100 ms so the data-change instant does not drift.
            let next = publisher.next_publish_at(Instant::now()).min(next_event_at);
            let now2 = Instant::now();
            if next > now2 {
                std::thread::sleep((next - now2).min(Duration::from_millis(100)));
            }
        }
    }

    /// Minimal AF_PACKET raw socket, enough to send and receive L2 frames.
    mod raw_socket {
        use std::ffi::CString;
        use std::io::Error as IoError;
        use std::mem;
        use std::os::fd::{AsRawFd, OwnedFd};

        pub struct L2Socket {
            fd: OwnedFd,
            iface_index: i32,
        }

        impl L2Socket {
            pub fn send_l2(&self, frame: &[u8]) -> Result<(), IoError> {
                let mut sa: libc::sockaddr_ll = unsafe { mem::zeroed() };
                sa.sll_family = libc::AF_PACKET as u16;
                sa.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
                sa.sll_ifindex = self.iface_index;
                sa.sll_halen = 6;
                if frame.len() >= 6 {
                    sa.sll_addr[..6].copy_from_slice(&frame[..6]);
                }
                let n = unsafe {
                    libc::sendto(
                        self.fd.as_raw_fd(),
                        frame.as_ptr() as *const _,
                        frame.len(),
                        0,
                        &sa as *const _ as *const libc::sockaddr,
                        mem::size_of::<libc::sockaddr_ll>() as u32,
                    )
                };
                if n < 0 {
                    return Err(IoError::last_os_error());
                }
                if (n as usize) != frame.len() {
                    return Err(IoError::other(format!("short send: {n}/{}", frame.len())));
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
            Ok(L2Socket {
                fd: owned,
                iface_index,
            })
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
