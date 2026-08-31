//! Publishes GOOSE through the HAL Ethernet backend on a real interface.
//!
//! Same publication as the `goose_publisher` example, but the frames leave
//! through `iec61850_hal::ethernet` rather than a socket the example opens
//! itself. That is the path a deployed publisher takes, and the one the
//! `goose_jitter_test` example measures.
//!
//! # Arguments
//!
//! The interface name, which is required: this example transmits on a real NIC.
//!
//! ```sh
//! sudo setcap cap_net_raw=eip ./goose_publisher_live
//! ./goose_publisher_live eth0
//! ```
//!
//! Expected stderr:
//!
//! ```text
//! [publisher-live] iface=eth0 appid=0x1000 gocbRef=DemoIED/LLN0$GO$gcbStatus
//! [publisher-live] backend=AfPacketSocket
//! [publisher-live] tx stNum=1 sqNum=0 bytes=113
//! ```
//!
//! # Platforms
//!
//! Linux uses `AfPacketSocket` and needs `CAP_NET_RAW`. On Windows and macOS
//! the pcap backend has to be selected explicitly, because linking it needs an
//! SDK that a default build must not require:
//!
//! ```sh
//! cargo build -p iec61850-goose --example goose_publisher_live \
//!     --features iec61850-hal/ethernet-pcap
//! ```

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("goose_publisher_live uses the Linux AF_PACKET backend of the HAL");
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

    use iec61850_goose::frame::VlanPriority;
    use iec61850_goose::publisher::{CommParameters, GoosePublisher};
    use iec61850_hal::ethernet::linux::AfPacketSocket;
    use iec61850_hal::ethernet::{EthernetAddr, EthernetConfig, EthernetSink};
    use iec61850_model::MmsValue;

    const DST_MAC: [u8; 6] = [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01];
    const SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const GOCB_REF: &str = "DemoIED/LLN0$GO$gcbStatus";
    const DATASET_REF: &str = "DemoIED/LLN0$dsStatus";
    const APP_ID: u16 = 0x1000;

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        if args.len() < 2 {
            eprintln!("usage: {} <iface>", args[0]);
            eprintln!("this example transmits on a real NIC, so the interface is required");
            std::process::exit(2);
        }
        let iface = &args[1];

        // Communication parameters: APPID, destination MAC, VLAN priority.
        let comm = CommParameters::new(APP_ID, DST_MAC)
            .with_priority(VlanPriority::new(4).unwrap())
            .with_src_mac(SRC_MAC);

        // The publisher builds frames; the HAL backend transmits them.
        let mut publisher =
            GoosePublisher::new(comm, GOCB_REF, None, DATASET_REF, 1).expect("publisher new");

        let cfg = EthernetConfig::new(iface)
            .with_multicast(EthernetAddr(DST_MAC))
            .with_recv_timeout(Duration::from_millis(100));
        let mut sink: Box<dyn EthernetSink> = Box::new(
            AfPacketSocket::open(&cfg).expect("open AF_PACKET socket, which needs CAP_NET_RAW"),
        );

        eprintln!(
            "[publisher-live] iface={iface} appid=0x{APP_ID:04x} gocbRef={GOCB_REF}\n\
             [publisher-live] backend=AfPacketSocket\n\
             [publisher-live] dataset={{ Boolean(breaker), Integer(current_mA), Integer(event_counter) }}\n\
             [publisher-live] the data changes every 5 s; Ctrl+C to stop"
        );

        let mut breaker_position = true;
        let mut current_value: i32 = 100;
        let mut event_counter: i32 = 0;

        let make_dataset = |breaker: bool, current: i32, counter: i32| -> Vec<MmsValue> {
            vec![
                MmsValue::Boolean(breaker),
                MmsValue::Integer(current as i64),
                MmsValue::Integer(counter as i64),
            ]
        };

        let start = Instant::now();
        let mut next_event_at = start + Duration::from_secs(5);

        loop {
            let now = Instant::now();

            if now >= next_event_at {
                breaker_position = !breaker_position;
                current_value = if breaker_position { 100 } else { 0 };
                event_counter += 1;
                publisher.increase_st_num();
                eprintln!(
                    "[publisher-live] [event] stNum={} breaker={} current={}mA counter={}",
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
                if let Err(e) = sink.send(&frame) {
                    eprintln!("[publisher-live] send failed: {e}");
                    std::process::exit(3);
                }
                eprintln!(
                    "[publisher-live] tx stNum={st} sqNum={sq} bytes={}",
                    frame.len()
                );
            }

            let next = publisher.next_publish_at(Instant::now()).min(next_event_at);
            let now2 = Instant::now();
            if next > now2 {
                std::thread::sleep((next - now2).min(Duration::from_millis(100)));
            }
        }
    }
}
