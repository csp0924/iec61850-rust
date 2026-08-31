//! Publishes a Sampled Values stream in the IEC 61850-9-2 LE profile.
//!
//! Shows the smallest complete publisher of IEC 61850-9-2:
//!
//! 1. `SvPublisherBuilder` sets the source and destination MAC and the APPID
//! 2. `add_asdu` declares one ASDU with an svID and a 64-byte sample
//! 3. `setup_complete` freezes the frame template, after which only the sample
//!    payload and the sample count change
//! 4. the loop writes a new sample every 250 microseconds, 4000 per second,
//!    and sends the frame itself
//!
//! The payload is the eight-channel LE profile: three phase currents and the
//! neutral, then three phase voltages and the neutral, each a scaled integer
//! with a quality word. The example drives them from a 50 Hz sine.
//!
//! Pairs with the `sv_subscriber_basic` example on the same interface.
//!
//! ```sh
//! cargo build -p iec61850-sv --examples
//!
//! # Terminal 1, on loopback
//! sudo ./target/debug/examples/sv_publisher_basic
//!
//! # Terminal 2
//! sudo ./target/debug/examples/sv_subscriber_basic
//! ```
//!
//! Expected stderr:
//!
//! ```text
//! [publisher] iface=lo appid=0x4000 svID=rustSV01 sps=4000
//! [publisher] 9-2 LE, 8 channels: IA IB IC IN VA VB VC VN
//! [publisher] 4000 samples sent, 1 s
//! ```
//!
//! The interface defaults to `lo`; pass another one as the first argument.
//!
//! Sampled Values ride directly on Ethernet, so this example needs a raw socket
//! rather than a TCP loopback connection: Linux only, and `CAP_NET_RAW` is
//! required.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("sv_publisher_basic needs an AF_PACKET raw socket, which is Linux only");
    eprintln!("the publisher API is covered by `cargo test -p iec61850-sv publisher`");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    linux_impl::run();
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use std::time::{Duration, Instant};

    use iec61850_model::Quality;
    use iec61850_sv::nine_two_le::{ChannelSample, NineTwoLE, SAMPLE_SIZE};
    use iec61850_sv::publisher::SvPublisherBuilder;
    use iec61850_sv::SV_DEFAULT_DST_MAC;

    const SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const APP_ID: u16 = 0x4000;
    const SV_ID: &str = "rustSV01";
    /// 80 samples per 50 Hz cycle, the rate the LE profile specifies.
    const SAMPLES_PER_SECOND: u32 = 4000;
    const PERIOD: Duration = Duration::from_nanos(1_000_000_000 / SAMPLES_PER_SECOND as u64);

    pub fn run() {
        let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".to_string());

        let mut builder = SvPublisherBuilder::new(SRC_MAC)
            .with_dst_mac(SV_DEFAULT_DST_MAC)
            .with_app_id(APP_ID);
        let h = builder
            .add_asdu(SV_ID, None::<&str>, 1, SAMPLE_SIZE)
            .expect("add_asdu");
        builder
            .set_smp_cnt_limit(h, std::num::NonZeroU16::new(SAMPLES_PER_SECOND as u16))
            .expect("set_smp_cnt_limit");

        let mut publisher = builder.setup_complete().expect("setup_complete");
        let sock =
            raw_socket::open_l2(&iface).expect("open AF_PACKET socket, which needs CAP_NET_RAW");

        eprintln!(
            "[publisher] iface={iface} appid=0x{APP_ID:04x} svID={SV_ID} sps={SAMPLES_PER_SECOND}\n\
             [publisher] 9-2 LE, 8 channels: IA IB IC IN VA VB VC VN\n\
             [publisher] Ctrl+C to stop"
        );

        // The sample count carries the phase of the simulated 50 Hz waveform.
        let start = Instant::now();
        let mut next_publish = start;
        let mut total_published: u64 = 0;
        loop {
            let now = Instant::now();
            if now >= next_publish {
                let phase_idx = total_published % 80;
                let sample = make_9_2_le_sample(phase_idx);
                publisher
                    .set_sample(h, &sample.to_sample())
                    .expect("set_sample");
                if let Err(e) = sock.send_l2(publisher.frame_bytes()) {
                    eprintln!("[publisher] send failed: {e}");
                    std::process::exit(3);
                }
                publisher.increase_smp_cnt(h).expect("increase_smp_cnt");
                total_published += 1;
                if total_published.is_multiple_of(SAMPLES_PER_SECOND as u64) {
                    eprintln!(
                        "[publisher] {total_published} samples sent, {} s",
                        total_published / SAMPLES_PER_SECOND as u64
                    );
                }
                next_publish += PERIOD;
            }
            // Sleeping stops 50 us short of the deadline, so the spin that
            // follows keeps the period from drifting.
            let now2 = Instant::now();
            if next_publish > now2 {
                let gap = next_publish - now2;
                if gap > Duration::from_micros(50) {
                    std::thread::sleep(gap - Duration::from_micros(50));
                }
            }
        }
    }

    /// One LE-profile sample: eight channels at the phase `phase_idx` names,
    /// counted in 80ths of a cycle.
    fn make_9_2_le_sample(phase_idx: u64) -> NineTwoLE {
        let phase = phase_idx as f32 * std::f32::consts::TAU / 80.0;
        // Current is carried in units of 1 mA per LSB.
        let i = (1000.0 * phase.sin() * 1000.0) as i32;
        // Voltage is carried in units of 10 mV per LSB.
        let v = (10000.0 * phase.cos() * 100.0) as i32;
        let q_good = Quality(0); // valid / 0 = good

        NineTwoLE {
            channels: [
                ChannelSample::new(i, q_good),                        // IA
                ChannelSample::new((i as f32 * 0.5) as i32, q_good),  // IB
                ChannelSample::new((i as f32 * -0.5) as i32, q_good), // IC
                ChannelSample::new(0, q_good),                        // IN
                ChannelSample::new(v, q_good),                        // VA
                ChannelSample::new((v as f32 * -0.5) as i32, q_good), // VB
                ChannelSample::new((v as f32 * -0.5) as i32, q_good), // VC
                ChannelSample::new(0, q_good),                        // VN
            ],
        }
    }

    /// Minimal AF_PACKET raw socket. The publisher hands out frame bytes and
    /// the caller sends them, so the library owns no transport.
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
