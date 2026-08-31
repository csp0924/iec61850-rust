//! Sampled Values receiver: frame dispatch and subscriber management.
//!
//! A receiver decodes each frame and offers every ASDU to every subscriber
//! whose filters match it, so two subscriptions on the same stream both see the
//! samples.
//!
//! The type parameter is a typestate. `SvReceiver<Idle>` accepts subscribers;
//! `SvReceiver<Running>` handles frames. Frames come either from an
//! `EthernetSource` driven by `start_thread`, or from the caller through
//! `into_threadless` and `tick`.
//!
//! Validation is layered: the frame layer checks the Ethernet length, the
//! EtherType, and the SV header; the PDU layer bounds the ASDU count and every
//! field; and the subscriber checks sample length consistency and smpCnt
//! continuity as it dispatches.
//!
//! TODO: refrTm plausibility is not validated at any layer.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use iec61850_hal::ethernet::{EthernetError, EthernetSource};

use crate::error::SvError;
use crate::frame::{SvFrame, SV_ETHER_TYPE};
use crate::pdu::decode_sav_pdu;
use crate::subscriber::{SvSubscriber, SvSubscriberAsdu};

/// Typestate for a receiver that accepts subscribers but no frames.
pub struct Idle;

/// Typestate for a receiver that handles frames but accepts no subscribers.
pub struct Running;

/// Handle to a receiver running on its own thread.
///
/// Dropping the handle stops the thread and joins it.
pub struct SvReceiverHandle {
    join: Option<JoinHandle<()>>,
    running: Arc<AtomicBool>,
}

impl SvReceiverHandle {
    /// Signals the thread to stop and waits for it to finish.
    pub fn stop_and_join(mut self) {
        self.running.store(false, Ordering::Release);
        if let Some(h) = self.join.take() {
            let _ = h.join();
        }
    }

    /// Returns whether the thread has been asked to keep running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }
}

impl Drop for SvReceiverHandle {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        if let Some(h) = self.join.take() {
            let _ = h.join();
        }
    }
}

/// State shared by both typestates.
struct SvReceiverInner {
    /// Subscriptions, each dispatched independently.
    subscribers: Vec<Arc<SvSubscriber>>,
    /// Whether the receiver validates the destination MAC before dispatch.
    ///
    /// Off by default, which preserves the on-wire behavior of a receiver that
    /// does not filter on the destination address. Per-subscription filtering
    /// is separate.
    ///
    /// TODO: implement the receiver-level check this flag selects.
    dest_addr_check: bool,
}

/// Sampled Values receive and dispatch point.
///
/// `SvReceiver<Idle>` adds subscribers; `SvReceiver<Running>` handles frames.
pub struct SvReceiver<S> {
    inner: SvReceiverInner,
    _state: std::marker::PhantomData<S>,
}

impl SvReceiver<Idle> {
    /// Creates an idle receiver with no subscribers.
    pub fn new() -> Self {
        SvReceiver {
            inner: SvReceiverInner {
                subscribers: Vec::new(),
                dest_addr_check: false,
            },
            _state: std::marker::PhantomData,
        }
    }

    /// Adds a subscription.
    pub fn add_subscriber(&mut self, sub: Arc<SvSubscriber>) {
        self.inner.subscribers.push(sub);
    }

    /// Enables the receiver-level destination MAC check, which is off by
    /// default.
    pub fn set_dest_addr_check(&mut self, enable: bool) {
        self.inner.dest_addr_check = enable;
    }

    /// Starts a thread that reads frames from `source` and dispatches them.
    ///
    /// The loop receives with a 100 ms timeout so it observes the stop flag on
    /// a quiet link. A receive error other than a timeout is logged and the
    /// loop continues.
    ///
    /// # Panics
    ///
    /// Panics if the receive thread cannot be spawned.
    pub fn start_thread(self, mut source: Box<dyn EthernetSource>) -> SvReceiverHandle {
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        let mut rx_running = SvReceiver::<Running> {
            inner: self.inner,
            _state: std::marker::PhantomData,
        };

        let join = thread::Builder::new()
            .name("sv-receiver".into())
            .spawn(move || {
                let mut buf = vec![0u8; 1518];
                while running_clone.load(Ordering::Acquire) {
                    match source.recv(&mut buf, Some(Duration::from_millis(100))) {
                        Ok(0) => {}
                        Ok(n) => {
                            let _ = rx_running.tick(&buf[..n]);
                        }
                        Err(EthernetError::Timeout) => {}
                        Err(e) => {
                            tracing::warn!("sv receiver recv error, continuing: {}", e);
                        }
                    }
                }
            })
            .expect("spawn sv-receiver thread");

        SvReceiverHandle {
            join: Some(join),
            running,
        }
    }

    /// Moves the receiver to the running state without starting a thread; the
    /// caller supplies frames through `tick`.
    pub fn into_threadless(self) -> SvReceiver<Running> {
        SvReceiver {
            inner: self.inner,
            _state: std::marker::PhantomData,
        }
    }
}

impl Default for SvReceiver<Idle> {
    fn default() -> Self {
        Self::new()
    }
}

impl SvReceiver<Running> {
    /// Decodes one Ethernet frame and dispatches its ASDUs, returning the
    /// number of listener calls made.
    ///
    /// A frame that is not Sampled Values, or that is too short to be one, is
    /// dropped and reported as zero dispatches rather than as an error, so a
    /// receiver on a shared interface is not error-driven by other traffic.
    ///
    /// # Errors
    ///
    /// Returns the frame-layer or PDU-layer decode error for a frame that
    /// claims to be Sampled Values but is malformed.
    pub fn tick(&mut self, frame: &[u8]) -> Result<usize, SvError> {
        let sv_frame = match SvFrame::decode(frame) {
            Ok(f) => f,
            // Traffic that is not Sampled Values is not an error here.
            Err(SvError::WrongEtherType(_)) => {
                return Ok(0);
            }
            Err(SvError::EthernetFrameTooShort(_)) => {
                return Ok(0);
            }
            Err(e) => {
                tracing::warn!("sv frame decode failed: {}", e);
                return Err(e);
            }
        };

        let frame_app_id = sv_frame.header.app_id;
        let dst_mac = sv_frame.header.dst_mac;

        // A decoded frame always carries the SV EtherType.
        let _ = SV_ETHER_TYPE;

        let sav_pdu = match decode_sav_pdu(&sv_frame.pdu_bytes) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    "sv pdu decode failed for appid 0x{:04x}: {}",
                    frame_app_id,
                    e
                );
                return Err(e);
            }
        };

        // Every ASDU is offered to every subscriber, not just the first match.
        let mut dispatch_count = 0usize;

        for asdu in &sav_pdu.asdus {
            let view = SvSubscriberAsdu::from_asdu(asdu);
            for sub in &self.inner.subscribers {
                if sub.matches(frame_app_id, &dst_mac, asdu) {
                    sub.dispatch(&view);
                    dispatch_count += 1;
                }
            }
        }

        Ok(dispatch_count)
    }

    /// Returns the number of subscriptions.
    pub fn subscriber_count(&self) -> usize {
        self.inner.subscribers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{SvFrame, SvFrameHeader, SV_APP_HEADER_SIZE, SV_DEFAULT_APPID};
    use crate::pdu::{encode_sav_pdu, Asdu, SavPdu, SmpSynch};
    use crate::subscriber::SvSubscriberBuilder;
    use bytes::BytesMut;
    use std::sync::{Arc, Mutex};

    /// Builds an ASDU with only the mandatory fields.
    fn make_asdu(sv_id: &str, smp_cnt: u16, sample_size: usize) -> Asdu {
        Asdu {
            sv_id: sv_id.to_owned(),
            dat_set: None,
            smp_cnt,
            conf_rev: 1,
            refr_tm: None,
            smp_synch: SmpSynch::GlobalClock,
            smp_rate: None,
            sample: vec![0xAAu8; sample_size],
            smp_mod: None,
            gm_identity: None,
        }
    }

    /// Encodes a PDU into a complete Ethernet frame.
    fn encode_frame(pdu: &SavPdu, app_id: u16, dst_mac: [u8; 6]) -> Vec<u8> {
        let mut pdu_buf = BytesMut::new();
        encode_sav_pdu(pdu, &mut pdu_buf).unwrap();
        let pdu_bytes = pdu_buf.to_vec();
        let pdu_len = pdu_bytes.len();
        let frame = SvFrame {
            header: SvFrameHeader {
                dst_mac,
                src_mac: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
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
    fn typestate_idle_to_running_tick() {
        let rx = SvReceiver::<Idle>::new();
        let mut running = rx.into_threadless();
        let result = running.tick(&[]);
        assert_eq!(result, Ok(0));
    }

    #[test]
    fn typestate_idle_add_subscribers_count() {
        let mut rx = SvReceiver::<Idle>::new();
        let sub1 = Arc::new(SvSubscriber::new("sv1"));
        let sub2 = Arc::new(SvSubscriber::new("sv2"));
        rx.add_subscriber(sub1);
        rx.add_subscriber(sub2);
        let running = rx.into_threadless();
        assert_eq!(running.subscriber_count(), 2);
    }

    #[test]
    fn single_subscriber_matching_asdu_callback_once() {
        let counter: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let c = counter.clone();

        let sub = Arc::new(
            SvSubscriberBuilder::new()
                .sv_id("IED1/LLN0$SV$sv1")
                .app_id(SV_DEFAULT_APPID)
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
        let frame = encode_frame(&pdu, SV_DEFAULT_APPID, crate::frame::SV_DEFAULT_DST_MAC);
        let result = running.tick(&frame).unwrap();

        assert_eq!(result, 1, "the matching subscriber is dispatched once");
        assert_eq!(*counter.lock().unwrap(), 1);
    }

    #[test]
    fn single_subscriber_non_matching_app_id_no_callback() {
        let counter: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let c = counter.clone();

        let sub = Arc::new(
            SvSubscriberBuilder::new()
                .app_id(0x4001)
                .listener(move |_| {
                    *c.lock().unwrap() += 1;
                })
                .build(),
        );

        let mut rx = SvReceiver::<Idle>::new();
        rx.add_subscriber(sub);
        let mut running = rx.into_threadless();

        let pdu = SavPdu {
            asdus: vec![make_asdu("sv1", 0, 8)],
        };
        let frame = encode_frame(&pdu, SV_DEFAULT_APPID, crate::frame::SV_DEFAULT_DST_MAC);
        let result = running.tick(&frame).unwrap();

        assert_eq!(result, 0, "a non-matching appid is not dispatched");
        assert_eq!(*counter.lock().unwrap(), 0);
    }

    #[test]
    fn single_subscriber_non_matching_sv_id_no_callback() {
        let counter: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let c = counter.clone();

        let sub = Arc::new(
            SvSubscriberBuilder::new()
                .sv_id("IED1/LLN0$SV$sv99")
                .listener(move |_| {
                    *c.lock().unwrap() += 1;
                })
                .build(),
        );

        let mut rx = SvReceiver::<Idle>::new();
        rx.add_subscriber(sub);
        let mut running = rx.into_threadless();

        let pdu = SavPdu {
            asdus: vec![make_asdu("IED1/LLN0$SV$sv1", 0, 8)],
        };
        let frame = encode_frame(&pdu, SV_DEFAULT_APPID, crate::frame::SV_DEFAULT_DST_MAC);
        let result = running.tick(&frame).unwrap();

        assert_eq!(result, 0, "a non-matching svid is not dispatched");
        assert_eq!(*counter.lock().unwrap(), 0);
    }

    #[test]
    fn subscriber_dst_mac_filter_on() {
        let counter: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let c = counter.clone();

        let target_mac = [0x01, 0x0C, 0xCD, 0x04, 0x00, 0x01];
        let sub = Arc::new(
            SvSubscriberBuilder::new()
                .dst_mac(target_mac)
                .listener(move |_| {
                    *c.lock().unwrap() += 1;
                })
                .build(),
        );

        let mut rx = SvReceiver::<Idle>::new();
        rx.add_subscriber(sub);
        let mut running = rx.into_threadless();

        let pdu = SavPdu {
            asdus: vec![make_asdu("sv1", 0, 8)],
        };

        // The configured address is dispatched.
        let frame_match = encode_frame(&pdu, SV_DEFAULT_APPID, target_mac);
        running.tick(&frame_match).unwrap();
        assert_eq!(*counter.lock().unwrap(), 1);

        // Any other address is not.
        let frame_no_match =
            encode_frame(&pdu, SV_DEFAULT_APPID, [0x01, 0x0C, 0xCD, 0x04, 0x00, 0x02]);
        running.tick(&frame_no_match).unwrap();
        assert_eq!(
            *counter.lock().unwrap(),
            1,
            "a non-matching dst mac is not dispatched"
        );
    }

    #[test]
    fn two_subscribers_same_app_id_different_sv_id_dispatch_each() {
        let cnt1: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let cnt2: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let c1 = cnt1.clone();
        let c2 = cnt2.clone();

        let sub1 = Arc::new(
            SvSubscriberBuilder::new()
                .app_id(SV_DEFAULT_APPID)
                .sv_id("sv1")
                .listener(move |_| {
                    *c1.lock().unwrap() += 1;
                })
                .build(),
        );
        let sub2 = Arc::new(
            SvSubscriberBuilder::new()
                .app_id(SV_DEFAULT_APPID)
                .sv_id("sv2")
                .listener(move |_| {
                    *c2.lock().unwrap() += 1;
                })
                .build(),
        );

        let mut rx = SvReceiver::<Idle>::new();
        rx.add_subscriber(sub1);
        rx.add_subscriber(sub2);
        let mut running = rx.into_threadless();

        let pdu1 = SavPdu {
            asdus: vec![make_asdu("sv1", 0, 8)],
        };
        running
            .tick(&encode_frame(
                &pdu1,
                SV_DEFAULT_APPID,
                crate::frame::SV_DEFAULT_DST_MAC,
            ))
            .unwrap();
        assert_eq!(*cnt1.lock().unwrap(), 1, "the sv1 subscriber is dispatched");
        assert_eq!(
            *cnt2.lock().unwrap(),
            0,
            "the sv2 subscriber is not dispatched"
        );

        let pdu2 = SavPdu {
            asdus: vec![make_asdu("sv2", 0, 8)],
        };
        running
            .tick(&encode_frame(
                &pdu2,
                SV_DEFAULT_APPID,
                crate::frame::SV_DEFAULT_DST_MAC,
            ))
            .unwrap();
        assert_eq!(*cnt1.lock().unwrap(), 1);
        assert_eq!(*cnt2.lock().unwrap(), 1, "the sv2 subscriber is dispatched");
    }

    #[test]
    fn two_subscribers_identical_filter_both_dispatched() {
        let cnt1: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let cnt2: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let c1 = cnt1.clone();
        let c2 = cnt2.clone();

        let sub1 = Arc::new(
            SvSubscriberBuilder::new()
                .sv_id("sv1")
                .listener(move |_| {
                    *c1.lock().unwrap() += 1;
                })
                .build(),
        );
        let sub2 = Arc::new(
            SvSubscriberBuilder::new()
                .sv_id("sv1")
                .listener(move |_| {
                    *c2.lock().unwrap() += 1;
                })
                .build(),
        );

        let mut rx = SvReceiver::<Idle>::new();
        rx.add_subscriber(sub1);
        rx.add_subscriber(sub2);
        let mut running = rx.into_threadless();

        let pdu = SavPdu {
            asdus: vec![make_asdu("sv1", 0, 64)],
        };
        let result = running
            .tick(&encode_frame(
                &pdu,
                SV_DEFAULT_APPID,
                crate::frame::SV_DEFAULT_DST_MAC,
            ))
            .unwrap();

        assert_eq!(result, 2, "both matching subscribers are dispatched");
        assert_eq!(*cnt1.lock().unwrap(), 1);
        assert_eq!(*cnt2.lock().unwrap(), 1);
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
        let result = running
            .tick(&encode_frame(
                &pdu,
                SV_DEFAULT_APPID,
                crate::frame::SV_DEFAULT_DST_MAC,
            ))
            .unwrap();

        assert_eq!(result, 2, "each of the two asdus is dispatched once");
        assert_eq!(*counter.lock().unwrap(), 2);
    }

    #[test]
    fn too_many_asdus_returns_err() {
        use iec61850_asn1::encode_length;

        // A frame announcing 11 ASDUs, one past the limit.
        let mut pdu_buf = BytesMut::new();
        let inner = vec![0x80u8, 0x01, 11u8, 0xA2, 0x00];
        pdu_buf.extend_from_slice(&[0x60u8]);
        encode_length(inner.len(), &mut pdu_buf);
        pdu_buf.extend_from_slice(&inner);
        let pdu_bytes = pdu_buf.to_vec();

        let frame = SvFrame {
            header: SvFrameHeader {
                dst_mac: crate::frame::SV_DEFAULT_DST_MAC,
                src_mac: [0u8; 6],
                vlan: None,
                app_id: SV_DEFAULT_APPID,
                length: (SV_APP_HEADER_SIZE + pdu_bytes.len()) as u16,
            },
            pdu_bytes,
        };
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut rx = SvReceiver::<Idle>::new().into_threadless();
        let result = rx.tick(&buf);
        assert!(
            matches!(result, Err(SvError::TooManyAsdus(11))),
            "an noasdu of 11 returns toomanyasdus"
        );
    }

    #[test]
    fn corrupt_frame_asdu_count_mismatch_returns_err() {
        use iec61850_asn1::encode_length;

        // One ASDU carrying only svID; the mandatory fields are missing.
        let mut inner_asdu = Vec::new();
        inner_asdu.extend_from_slice(&[0x80u8, 0x03]);
        inner_asdu.extend_from_slice(b"sv1");

        let asdu_tlv = {
            let mut v = Vec::new();
            v.push(0x30u8);
            let mut tbuf = BytesMut::new();
            encode_length(inner_asdu.len(), &mut tbuf);
            v.extend_from_slice(&tbuf);
            v.extend_from_slice(&inner_asdu);
            v
        };

        let seq_tlv = {
            let mut v = Vec::new();
            v.push(0xA2u8);
            let mut tbuf = BytesMut::new();
            encode_length(asdu_tlv.len(), &mut tbuf);
            v.extend_from_slice(&tbuf);
            v.extend_from_slice(&asdu_tlv);
            v
        };

        let no_asdu_bytes = vec![0x80u8, 0x01, 0x01];
        let contents = [no_asdu_bytes.as_slice(), seq_tlv.as_slice()].concat();
        let mut pdu_buf = BytesMut::new();
        pdu_buf.extend_from_slice(&[0x60u8]);
        encode_length(contents.len(), &mut pdu_buf);
        pdu_buf.extend_from_slice(&contents);
        let pdu_bytes = pdu_buf.to_vec();

        let frame = SvFrame {
            header: SvFrameHeader {
                dst_mac: crate::frame::SV_DEFAULT_DST_MAC,
                src_mac: [0u8; 6],
                vlan: None,
                app_id: SV_DEFAULT_APPID,
                length: (SV_APP_HEADER_SIZE + pdu_bytes.len()) as u16,
            },
            pdu_bytes,
        };
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut rx = SvReceiver::<Idle>::new().into_threadless();
        let result = rx.tick(&buf);
        assert!(result.is_err(), "an incomplete asdu returns err");
    }

    #[test]
    fn start_thread_and_drop_joins() {
        // Always reports no frame, so the loop keeps checking the stop flag.
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
        assert!(handle.is_running());
        handle.stop_and_join();
    }
}
