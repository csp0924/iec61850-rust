//! Publishes Sampled Values through the HAL Ethernet backend on a real interface.
//!
//! Same stream as the `sv_publisher_basic` example, but the frames leave
//! through `iec61850_hal::ethernet` rather than a socket the example opens
//! itself. That is the path a deployed publisher takes.
//!
//! The loop here runs at ordinary scheduling priority. A stream that has to
//! hold its period under load belongs in
//! `iec61850_sv::publish_thread::spawn_publish_loop`, which the `sv_cpu_test`
//! example drives.
//!
//! # Arguments
//!
//! The interface name, which is required: this example transmits on a real NIC.
//!
//! ```sh
//! sudo setcap cap_net_raw=eip ./sv_publisher_live
//! ./sv_publisher_live eth0
//! ```
//!
//! Expected stderr:
//!
//! ```text
//! [publisher-live] iface=eth0 appid=0x4000 svID=rustSV01 sps=4000
//! [publisher-live] backend=AfPacketSocket
//! [publisher-live] 4000 samples sent, 1 s
//! ```
//!
//! # Platforms
//!
//! Linux uses `AfPacketSocket` and needs `CAP_NET_RAW`. On Windows and macOS
//! the pcap backend has to be selected explicitly, because linking it needs an
//! SDK that a default build must not require:
//!
//! ```sh
//! cargo build -p iec61850-sv --example sv_publisher_live \
//!     --features iec61850-hal/ethernet-pcap
//! ```

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("sv_publisher_live uses the Linux AF_PACKET backend of the HAL");
    eprintln!("build with --features iec61850-hal/ethernet-pcap for a pcap backend");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    impl_::run();
}

#[cfg(target_os = "linux")]
mod impl_ {
    use std::time::{Duration, Instant};

    use iec61850_hal::ethernet::linux::AfPacketSocket;
    use iec61850_hal::ethernet::{EthernetAddr, EthernetConfig, EthernetSink};
    use iec61850_model::Quality;
    use iec61850_sv::nine_two_le::{ChannelSample, NineTwoLE, SAMPLE_SIZE};
    use iec61850_sv::publisher::SvPublisherBuilder;
    use iec61850_sv::SV_DEFAULT_DST_MAC;

    const SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const APP_ID: u16 = 0x4000;
    const SV_ID: &str = "rustSV01";
    const SAMPLES_PER_SECOND: u32 = 4000;
    const PERIOD: Duration = Duration::from_nanos(1_000_000_000 / SAMPLES_PER_SECOND as u64);

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        if args.len() < 2 {
            eprintln!("usage: {} <iface>", args[0]);
            eprintln!("this example transmits on a real NIC, so the interface is required");
            std::process::exit(2);
        }
        let iface = &args[1];
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
        let cfg = EthernetConfig::new(iface).with_multicast(EthernetAddr(SV_DEFAULT_DST_MAC));
        let mut sink =
            AfPacketSocket::open(&cfg).expect("open AF_PACKET socket, which needs CAP_NET_RAW");

        eprintln!(
            "[publisher-live] iface={iface} appid=0x{APP_ID:04x} svID={SV_ID} sps={SAMPLES_PER_SECOND}\n\
             [publisher-live] backend=AfPacketSocket\n\
             [publisher-live] 9-2 LE, 8 channels: IA IB IC IN VA VB VC VN\n\
             [publisher-live] Ctrl+C to stop"
        );
        let start = Instant::now();
        let mut next_publish = start;
        let mut total: u64 = 0;
        loop {
            let now = Instant::now();
            if now >= next_publish {
                let phase_idx = total % 80;
                let sample = make_9_2_le_sample(phase_idx);
                publisher
                    .set_sample(h, &sample.to_sample())
                    .expect("set_sample");
                if let Err(e) = sink.send(publisher.frame_bytes()) {
                    eprintln!("[publisher-live] send failed: {e}");
                    std::process::exit(3);
                }
                publisher.increase_smp_cnt(h).expect("increase_smp_cnt");
                total += 1;
                if total.is_multiple_of(SAMPLES_PER_SECOND as u64) {
                    eprintln!(
                        "[publisher-live] {total} samples sent, {} s",
                        total / SAMPLES_PER_SECOND as u64
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

    fn make_9_2_le_sample(phase_idx: u64) -> NineTwoLE {
        let phase = phase_idx as f32 * std::f32::consts::TAU / 80.0;
        let i = (1000.0 * phase.sin() * 1000.0) as i32;
        let v = (10000.0 * phase.cos() * 100.0) as i32;
        let q_good = Quality(0);
        NineTwoLE {
            channels: [
                ChannelSample::new(i, q_good),
                ChannelSample::new((i as f32 * 0.5) as i32, q_good),
                ChannelSample::new((i as f32 * -0.5) as i32, q_good),
                ChannelSample::new(0, q_good),
                ChannelSample::new(v, q_good),
                ChannelSample::new((v as f32 * -0.5) as i32, q_good),
                ChannelSample::new((v as f32 * -0.5) as i32, q_good),
                ChannelSample::new(0, q_good),
            ],
        }
    }
}
