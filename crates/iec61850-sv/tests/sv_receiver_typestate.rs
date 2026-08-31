//! Integration tests for the `SvReceiver` typestate: moving from idle to
//! running, registering subscribers, dispatching a valid frame, and stopping a
//! receive thread.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::BytesMut;
use iec61850_hal::ethernet::{EthernetError, EthernetSource};
use iec61850_sv::frame::{SvFrame, SvFrameHeader, SV_APP_HEADER_SIZE, SV_DEFAULT_APPID};
use iec61850_sv::pdu::{encode_sav_pdu, Asdu, SavPdu, SmpSynch};
use iec61850_sv::receiver::{Idle, SvReceiver};
use iec61850_sv::subscriber::SvSubscriberBuilder;
use iec61850_sv::{SvSubscriber, SV_DEFAULT_DST_MAC};

fn make_asdu(sv_id: &str, smp_cnt: u16, sample_size: usize) -> Asdu {
    Asdu {
        sv_id: sv_id.to_owned(),
        dat_set: None,
        smp_cnt,
        conf_rev: 1,
        refr_tm: None,
        smp_synch: SmpSynch::GlobalClock,
        smp_rate: None,
        sample: vec![0xBBu8; sample_size],
        smp_mod: None,
        gm_identity: None,
    }
}

fn encode_frame(pdu: &SavPdu, app_id: u16, dst_mac: [u8; 6]) -> Vec<u8> {
    let mut pdu_buf = BytesMut::new();
    encode_sav_pdu(pdu, &mut pdu_buf).unwrap();
    let pdu_bytes = pdu_buf.to_vec();
    let pdu_len = pdu_bytes.len();
    let frame = SvFrame {
        header: SvFrameHeader {
            dst_mac,
            src_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            vlan: None,
            app_id,
            length: (SV_APP_HEADER_SIZE + pdu_len) as u16,
        },
        pdu_bytes,
    };
    let mut buf = BytesMut::new();
    frame.encode(&mut buf).unwrap();
    buf.to_vec()
}

#[test]
fn idle_to_threadless_running_can_tick() {
    let rx = SvReceiver::<Idle>::new();
    let mut running = rx.into_threadless();

    let result = running.tick(&[]);
    assert_eq!(result, Ok(0));

    let pdu = SavPdu {
        asdus: vec![make_asdu("sv1", 0, 8)],
    };
    let frame_bytes = encode_frame(&pdu, SV_DEFAULT_APPID, SV_DEFAULT_DST_MAC);
    let result = running.tick(&frame_bytes);
    assert_eq!(result, Ok(0), "no subscriber means no dispatch");
}

#[test]
fn add_two_subscribers_count_equals_two() {
    let mut rx = SvReceiver::<Idle>::new();
    let sub1 = Arc::new(SvSubscriber::new("sv1"));
    let sub2 = Arc::new(SvSubscriber::new("sv2"));
    rx.add_subscriber(sub1);
    rx.add_subscriber(sub2);

    let running = rx.into_threadless();
    assert_eq!(running.subscriber_count(), 2);
}

#[test]
fn tick_valid_frame_callback_count_correct() {
    let counter: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let c = counter.clone();

    let sub = Arc::new(
        SvSubscriberBuilder::new()
            .sv_id("IED1/LLN0$SV$sv1")
            .listener(move |_| {
                *c.lock().unwrap() += 1;
            })
            .build(),
    );

    let mut rx = SvReceiver::<Idle>::new();
    rx.add_subscriber(sub);
    let mut running = rx.into_threadless();

    let pdu = SavPdu {
        asdus: vec![make_asdu("IED1/LLN0$SV$sv1", 0, 64)],
    };
    let frame_bytes = encode_frame(&pdu, SV_DEFAULT_APPID, SV_DEFAULT_DST_MAC);

    let dispatch_count = running.tick(&frame_bytes).unwrap();
    assert_eq!(
        dispatch_count, 1,
        "the matching subscriber is dispatched once"
    );
    assert_eq!(*counter.lock().unwrap(), 1, "the listener ran once");
}

#[test]
fn start_thread_drop_joins_thread() {
    /// Always reports no frame, so the loop keeps checking the stop flag.
    struct MockSource;
    impl EthernetSource for MockSource {
        fn recv(
            &mut self,
            _buf: &mut [u8],
            _timeout: Option<Duration>,
        ) -> Result<usize, EthernetError> {
            Ok(0)
        }
    }

    let rx = SvReceiver::<Idle>::new();
    let handle = rx.start_thread(Box::new(MockSource));
    assert!(handle.is_running(), "the thread reports itself running");
    handle.stop_and_join();
}

#[test]
fn multi_asdu_frame_subscriber_receives_twice() {
    let counter: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let c = counter.clone();

    let sub = Arc::new(
        SvSubscriberBuilder::new()
            .sv_id("sv1")
            .listener(move |_| {
                *c.lock().unwrap() += 1;
            })
            .build(),
    );

    let mut rx = SvReceiver::<Idle>::new();
    rx.add_subscriber(sub);
    let mut running = rx.into_threadless();

    let pdu = SavPdu {
        asdus: vec![make_asdu("sv1", 0, 64), make_asdu("sv1", 1, 64)],
    };
    let dispatch_count = running
        .tick(&encode_frame(&pdu, SV_DEFAULT_APPID, SV_DEFAULT_DST_MAC))
        .unwrap();

    assert_eq!(
        dispatch_count, 2,
        "each of the two asdus is dispatched once"
    );
    assert_eq!(*counter.lock().unwrap(), 2, "the listener ran twice");
}
