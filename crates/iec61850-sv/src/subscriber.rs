//! Sampled Values subscriber: stream filters and per-ASDU callbacks.
//!
//! An `SvSubscriber` selects streams by APPID, destination MAC, and svID, and
//! hands each matching ASDU to its listener as an `SvSubscriberAsdu` borrowed
//! from the receive buffer, so dispatch copies no samples. Every ASDU is
//! delivered to every subscriber that matches it.
//!
//! Two consistency checks run before the listener. The sample length is locked
//! to the length of the first ASDU delivered; a later ASDU of a different
//! length is reported and dropped, so a listener never reads a sample laid out
//! differently from the one it was written for. A smpCnt that does not follow
//! its predecessor is counted in `missed_count`, which exposes gaps in the
//! stream; that ASDU is still delivered.
//!
//! The state a subscriber accumulates is atomic, so one `Arc<SvSubscriber>`
//! can be shared across threads.

use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use iec61850_model::Quality;

use crate::error::SvError;
use crate::nine_two_le::{NineTwoLE, SAMPLE_SIZE};
use crate::pdu::{Asdu, SmpMod, SmpSynch};

/// Listener invoked once per matching ASDU.
pub type SvListener = Arc<dyn Fn(&SvSubscriberAsdu<'_>) + Send + Sync>;

/// A borrowed view of one ASDU, valid for the duration of the callback.
pub struct SvSubscriberAsdu<'a> {
    /// svID, the identifier of this stream.
    pub sv_id: &'a str,
    /// datSet object reference, when present.
    pub dat_set: Option<&'a str>,
    /// Sample counter.
    pub smp_cnt: u16,
    /// Configuration revision.
    pub conf_rev: u32,
    /// Raw refrTm bytes, when present.
    pub refr_tm: Option<&'a [u8; 8]>,
    /// Synchronization state.
    pub smp_synch: SmpSynch,
    /// Sample rate, when present.
    pub smp_rate: Option<u16>,
    /// Raw sample bytes, borrowed from the received frame.
    pub sample: &'a [u8],
    /// Sampling mode, when present.
    pub smp_mod: Option<SmpMod>,
    /// Raw PTP grandmaster identity, when present.
    pub gm_identity: Option<&'a [u8; 8]>,
}

impl<'a> SvSubscriberAsdu<'a> {
    /// Borrows a decoded ASDU as a view.
    pub fn from_asdu(asdu: &'a Asdu) -> Self {
        SvSubscriberAsdu {
            sv_id: &asdu.sv_id,
            dat_set: asdu.dat_set.as_deref(),
            smp_cnt: asdu.smp_cnt,
            conf_rev: asdu.conf_rev,
            refr_tm: asdu.refr_tm.as_ref(),
            smp_synch: asdu.smp_synch,
            smp_rate: asdu.smp_rate,
            sample: &asdu.sample,
            smp_mod: asdu.smp_mod,
            gm_identity: asdu.gm_identity.as_ref(),
        }
    }

    /// Decodes the sample as a 9-2 LE frame of eight channels.
    ///
    /// # Errors
    ///
    /// Returns `SampleSizeMismatch` when the sample is not `SAMPLE_SIZE`
    /// bytes.
    pub fn parse_9_2_le(&self) -> Result<NineTwoLE, SvError> {
        if self.sample.len() != SAMPLE_SIZE {
            return Err(SvError::SampleSizeMismatch {
                expected: SAMPLE_SIZE,
                actual: self.sample.len(),
            });
        }
        let arr: &[u8; SAMPLE_SIZE] =
            self.sample
                .try_into()
                .map_err(|_| SvError::SampleSizeMismatch {
                    expected: SAMPLE_SIZE,
                    actual: self.sample.len(),
                })?;
        Ok(NineTwoLE::from_sample(arr))
    }

    /// Reads a big-endian `i32` at `offset` in the sample.
    ///
    /// Returns `None` when the four bytes do not fit the sample.
    pub fn get_i32(&self, offset: usize) -> Option<i32> {
        if offset + 4 > self.sample.len() {
            tracing::warn!(
                "get_i32 offset {} is past the {} byte sample",
                offset,
                self.sample.len()
            );
            return None;
        }
        let bytes = &self.sample[offset..offset + 4];
        Some(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Reads a big-endian `u32` at `offset` in the sample.
    ///
    /// Returns `None` when the four bytes do not fit the sample.
    pub fn get_u32(&self, offset: usize) -> Option<u32> {
        if offset + 4 > self.sample.len() {
            tracing::warn!(
                "get_u32 offset {} is past the {} byte sample",
                offset,
                self.sample.len()
            );
            return None;
        }
        let bytes = &self.sample[offset..offset + 4];
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Reads a 4-byte quality field at `offset` in the sample.
    ///
    /// Only the low 16 bits are significant; non-zero upper bytes are logged
    /// and dropped. Returns `None` when the four bytes do not fit the
    /// sample.
    pub fn get_quality(&self, offset: usize) -> Option<Quality> {
        if offset + 4 > self.sample.len() {
            tracing::warn!(
                "get_quality offset {} is past the {} byte sample",
                offset,
                self.sample.len()
            );
            return None;
        }
        let bytes = &self.sample[offset..offset + 4];
        let q_raw = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if q_raw > 0xFFFF {
            tracing::warn!(
                "quality at offset {} has non-zero upper bytes (raw=0x{:08x}), keeping the low 16 bits",
                offset,
                q_raw
            );
        }
        Some(Quality(q_raw as u16))
    }
}

/// Builds an `SvSubscriber`.
pub struct SvSubscriberBuilder {
    app_id_filter: Option<u16>,
    sv_id_filter: Option<String>,
    dst_mac_filter: Option<[u8; 6]>,
    listener: Option<SvListener>,
}

// `dyn Fn` does not implement Default, so the impl is written out.
#[allow(clippy::derivable_impls)]
impl Default for SvSubscriberBuilder {
    fn default() -> Self {
        SvSubscriberBuilder {
            app_id_filter: None,
            sv_id_filter: None,
            dst_mac_filter: None,
            listener: None,
        }
    }
}

impl SvSubscriberBuilder {
    /// Creates a builder with no filters and no listener.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the APPID filter; leaving it unset accepts any APPID.
    pub fn app_id(mut self, app_id: u16) -> Self {
        self.app_id_filter = Some(app_id);
        self
    }

    /// Sets the svID filter; leaving it unset accepts any stream.
    pub fn sv_id(mut self, sv_id: impl Into<String>) -> Self {
        self.sv_id_filter = Some(sv_id.into());
        self
    }

    /// Sets the destination MAC filter; leaving it unset accepts any address.
    pub fn dst_mac(mut self, mac: [u8; 6]) -> Self {
        self.dst_mac_filter = Some(mac);
        self
    }

    /// Sets the listener invoked for each matching ASDU.
    pub fn listener(mut self, cb: impl Fn(&SvSubscriberAsdu<'_>) + Send + Sync + 'static) -> Self {
        self.listener = Some(Arc::new(cb));
        self
    }

    /// Builds the subscriber.
    pub fn build(self) -> SvSubscriber {
        SvSubscriber {
            app_id_filter: self.app_id_filter,
            sv_id_filter: self.sv_id_filter,
            dst_mac_filter: self.dst_mac_filter,
            listener: self.listener,
            expected_sample_size: AtomicUsize::new(0),
            last_smp_cnt: AtomicU16::new(u16::MAX),
            missed_count: AtomicU64::new(0),
            first_received: AtomicBool::new(false),
        }
    }
}

/// A Sampled Values subscription: stream filters, a listener, and the stream
/// state that dispatch maintains.
///
/// Filters are fixed once built; the accumulated state is atomic, so the
/// subscriber can be shared across threads behind an `Arc`.
pub struct SvSubscriber {
    /// APPID filter; `None` accepts any APPID.
    app_id_filter: Option<u16>,
    /// svID filter; `None` accepts any stream.
    sv_id_filter: Option<String>,
    /// Destination MAC filter; `None` accepts any address.
    dst_mac_filter: Option<[u8; 6]>,
    /// Listener invoked for each matching ASDU.
    listener: Option<SvListener>,
    /// Sample length locked by the first ASDU delivered; 0 until then.
    expected_sample_size: AtomicUsize,
    /// smpCnt of the most recent ASDU.
    last_smp_cnt: AtomicU16,
    /// Number of samples missed, summed over every detected gap.
    missed_count: AtomicU64,
    /// Whether an ASDU has been delivered yet.
    first_received: AtomicBool,
}

impl std::fmt::Debug for SvSubscriber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SvSubscriber")
            .field("app_id_filter", &self.app_id_filter)
            .field("sv_id_filter", &self.sv_id_filter)
            .field("dst_mac_filter", &self.dst_mac_filter)
            .field("has_listener", &self.listener.is_some())
            .field(
                "expected_sample_size",
                &self.expected_sample_size.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl SvSubscriber {
    /// Creates a subscriber filtered on `sv_id`, with no listener.
    pub fn new(sv_id: impl Into<String>) -> Self {
        SvSubscriberBuilder::new().sv_id(sv_id).build()
    }

    /// Returns a builder.
    pub fn builder() -> SvSubscriberBuilder {
        SvSubscriberBuilder::new()
    }

    /// Returns the APPID filter.
    pub fn app_id_filter(&self) -> Option<u16> {
        self.app_id_filter
    }

    /// Returns the svID filter.
    pub fn sv_id_filter(&self) -> Option<&str> {
        self.sv_id_filter.as_deref()
    }

    /// Returns the destination MAC filter.
    pub fn dst_mac_filter(&self) -> Option<[u8; 6]> {
        self.dst_mac_filter
    }

    /// Returns the locked sample length, or 0 before the first ASDU.
    pub fn expected_sample_size(&self) -> usize {
        self.expected_sample_size.load(Ordering::Relaxed)
    }

    /// Returns the number of samples missed so far.
    pub fn missed_count(&self) -> u64 {
        self.missed_count.load(Ordering::Relaxed)
    }

    /// Sets the listener.
    ///
    /// Call this before the subscriber is added to a receiver, which
    /// dispatches from its own thread.
    pub fn set_listener(&mut self, cb: impl Fn(&SvSubscriberAsdu<'_>) + Send + Sync + 'static) {
        self.listener = Some(Arc::new(cb));
    }

    /// Returns whether every configured filter accepts this frame and ASDU.
    ///
    /// A subscriber with no filters accepts everything.
    pub fn matches(&self, frame_app_id: u16, dst_mac: &[u8; 6], asdu: &Asdu) -> bool {
        if let Some(id) = self.app_id_filter {
            if id != frame_app_id {
                return false;
            }
        }
        if let Some(m) = self.dst_mac_filter {
            if &m != dst_mac {
                return false;
            }
        }
        if let Some(ref sv_id) = self.sv_id_filter {
            if sv_id != &asdu.sv_id {
                return false;
            }
        }
        true
    }

    /// Delivers one ASDU to the listener.
    ///
    /// The first ASDU locks the sample length; one of a different length is
    /// reported and dropped. A smpCnt that skips ahead adds the gap to
    /// `missed_count` but is still delivered.
    pub fn dispatch(&self, asdu_view: &SvSubscriberAsdu<'_>) {
        let sample_len = asdu_view.sample.len();

        let expected = self.expected_sample_size.load(Ordering::Acquire);
        if expected == 0 {
            // Two threads may reach this at once; whichever wins the exchange
            // sets the length, and the other re-reads it below.
            let _ = self.expected_sample_size.compare_exchange(
                0,
                sample_len,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            let locked = self.expected_sample_size.load(Ordering::Acquire);
            if locked != sample_len {
                tracing::warn!(
                    "sv subscriber svid={:?}: sample length {} differs from the locked {}, dropping",
                    asdu_view.sv_id,
                    sample_len,
                    locked
                );
                return;
            }
        } else if expected != sample_len {
            tracing::warn!(
                "sv subscriber svid={:?}: sample length {} differs from the expected {}, dropping",
                asdu_view.sv_id,
                sample_len,
                expected
            );
            return;
        }

        let cur_cnt = asdu_view.smp_cnt;
        let is_first = !self.first_received.load(Ordering::Acquire);
        if is_first {
            self.last_smp_cnt.store(cur_cnt, Ordering::Release);
            self.first_received.store(true, Ordering::Release);
        } else {
            let prev = self.last_smp_cnt.load(Ordering::Acquire);
            let expected_next = prev.wrapping_add(1);
            if cur_cnt != expected_next {
                // Wrapping subtraction makes the counter wrapping from 65535 to
                // 0 a gap of zero rather than a gap of 65535.
                let diff = cur_cnt.wrapping_sub(expected_next) as u64;
                tracing::warn!(
                    "sv subscriber svid={:?}: smpcnt gap, prev={} cur={} missed={}",
                    asdu_view.sv_id,
                    prev,
                    cur_cnt,
                    diff
                );
                self.missed_count.fetch_add(diff, Ordering::Relaxed);
            }
            self.last_smp_cnt.store(cur_cnt, Ordering::Release);
        }

        if let Some(ref cb) = self.listener {
            cb(asdu_view);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::{Asdu, SmpMod, SmpSynch};
    use std::sync::{Arc, Mutex};

    /// Builds an ASDU with only the mandatory fields.
    fn make_asdu(sv_id: &str, smp_cnt: u16, sample: Vec<u8>) -> Asdu {
        Asdu {
            sv_id: sv_id.to_owned(),
            dat_set: None,
            smp_cnt,
            conf_rev: 1,
            refr_tm: None,
            smp_synch: SmpSynch::GlobalClock,
            smp_rate: None,
            sample,
            smp_mod: None,
            gm_identity: None,
        }
    }

    /// Builds an ASDU with every optional field present.
    fn make_full_asdu(sv_id: &str, smp_cnt: u16) -> Asdu {
        Asdu {
            sv_id: sv_id.to_owned(),
            dat_set: Some("IED1/LLN0$SV$ds".to_owned()),
            smp_cnt,
            conf_rev: 0xDEADBEEF,
            refr_tm: Some([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            smp_synch: SmpSynch::LocalIdentified(10),
            smp_rate: Some(4000),
            sample: vec![0xABu8; 64],
            smp_mod: Some(SmpMod::SamplesPerSecond),
            gm_identity: Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
        }
    }

    #[test]
    fn asdu_view_fields_from_full_asdu() {
        let asdu = make_full_asdu("IED1/LLN0$SV$sv1", 42);
        let view = SvSubscriberAsdu::from_asdu(&asdu);

        assert_eq!(view.sv_id, "IED1/LLN0$SV$sv1");
        assert_eq!(view.dat_set, Some("IED1/LLN0$SV$ds"));
        assert_eq!(view.smp_cnt, 42);
        assert_eq!(view.conf_rev, 0xDEADBEEF);
        assert_eq!(
            view.refr_tm,
            Some(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        );
        assert_eq!(view.smp_synch, SmpSynch::LocalIdentified(10));
        assert_eq!(view.smp_rate, Some(4000));
        assert_eq!(view.sample.len(), 64);
        assert_eq!(view.smp_mod, Some(SmpMod::SamplesPerSecond));
        assert_eq!(
            view.gm_identity,
            Some(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
        );
    }

    #[test]
    fn get_i32_happy_path() {
        // Big-endian 500 in the first four bytes.
        let mut sample = vec![0u8; 8];
        sample[0] = 0x00;
        sample[1] = 0x00;
        sample[2] = 0x01;
        sample[3] = 0xF4;
        let asdu = make_asdu("sv1", 0, sample);
        let view = SvSubscriberAsdu::from_asdu(&asdu);
        assert_eq!(view.get_i32(0), Some(500));
    }

    #[test]
    fn get_i32_out_of_range_returns_none() {
        let asdu = make_asdu("sv1", 0, vec![0u8; 8]);
        let view = SvSubscriberAsdu::from_asdu(&asdu);
        // Reading 4 bytes at offset 5 would need 9 bytes.
        assert_eq!(view.get_i32(5), None);
    }

    #[test]
    fn get_u32_happy_path() {
        let mut sample = vec![0u8; 8];
        sample[4] = 0x00;
        sample[5] = 0x00;
        sample[6] = 0xAB;
        sample[7] = 0xCD;
        let asdu = make_asdu("sv1", 0, sample);
        let view = SvSubscriberAsdu::from_asdu(&asdu);
        assert_eq!(view.get_u32(4), Some(0x0000ABCD));
    }

    #[test]
    fn get_quality_happy_path() {
        let mut sample = vec![0u8; 8];
        sample[4] = 0x00;
        sample[5] = 0x00;
        sample[6] = 0x00;
        sample[7] = 0x04; // Quality bit
        let asdu = make_asdu("sv1", 0, sample);
        let view = SvSubscriberAsdu::from_asdu(&asdu);
        assert_eq!(view.get_quality(4), Some(Quality(0x0004)));
    }

    #[test]
    fn get_quality_out_of_range_returns_none() {
        // IC-G
        let asdu = make_asdu("sv1", 0, vec![0u8; 4]);
        let view = SvSubscriberAsdu::from_asdu(&asdu);
        assert_eq!(view.get_quality(1), None); // 1+4=5 > 4
    }

    #[test]
    fn parse_9_2_le_64byte_sample() {
        use crate::nine_two_le::{ChannelSample, NineTwoLE, SAMPLE_SIZE};
        let channels = [
            ChannelSample::new(500, Quality(0)),
            ChannelSample::new(-500, Quality(0)),
            ChannelSample::new(750, Quality(0)),
            ChannelSample::new(0, Quality(0)),
            ChannelSample::new(220000, Quality(0)),
            ChannelSample::new(220000, Quality(0)),
            ChannelSample::new(220000, Quality(0)),
            ChannelSample::new(0, Quality(0)),
        ];
        let sv = NineTwoLE { channels };
        let raw = sv.to_sample();
        assert_eq!(raw.len(), SAMPLE_SIZE);

        let asdu = make_asdu("sv1", 0, raw.to_vec());
        let view = SvSubscriberAsdu::from_asdu(&asdu);
        let decoded = view.parse_9_2_le().unwrap();
        assert_eq!(decoded, sv);
    }

    #[test]
    fn parse_9_2_le_wrong_size_returns_err() {
        let asdu = make_asdu("sv1", 0, vec![0u8; 32]); // 32 != 64
        let view = SvSubscriberAsdu::from_asdu(&asdu);
        assert!(matches!(
            view.parse_9_2_le(),
            Err(SvError::SampleSizeMismatch {
                expected: 64,
                actual: 32
            })
        ));
    }

    #[test]
    fn subscriber_no_filter_matches_any() {
        let sub = SvSubscriberBuilder::new().build();
        let asdu = make_asdu("anySvId", 0, vec![0u8; 8]);
        let dst_mac = [0x01, 0x0C, 0xCD, 0x04, 0x00, 0x00];
        assert!(sub.matches(0x4000, &dst_mac, &asdu));
        assert!(sub.matches(0x0001, &[0u8; 6], &asdu));
    }

    #[test]
    fn subscriber_app_id_filter() {
        let sub = SvSubscriberBuilder::new().app_id(0x4001).build();
        let asdu = make_asdu("sv1", 0, vec![0u8; 8]);
        assert!(sub.matches(0x4001, &[0u8; 6], &asdu));
        assert!(!sub.matches(0x4000, &[0u8; 6], &asdu));
    }

    #[test]
    fn subscriber_sv_id_filter() {
        let sub = SvSubscriberBuilder::new().sv_id("IED1/LLN0$SV$sv1").build();
        let asdu_match = make_asdu("IED1/LLN0$SV$sv1", 0, vec![0u8; 8]);
        let asdu_no_match = make_asdu("IED1/LLN0$SV$sv2", 0, vec![0u8; 8]);
        assert!(sub.matches(0x4000, &[0u8; 6], &asdu_match));
        assert!(!sub.matches(0x4000, &[0u8; 6], &asdu_no_match));
    }

    #[test]
    fn subscriber_dst_mac_filter() {
        let mac = [0x01, 0x0C, 0xCD, 0x04, 0x00, 0x01];
        let sub = SvSubscriberBuilder::new().dst_mac(mac).build();
        let asdu = make_asdu("sv1", 0, vec![0u8; 8]);
        assert!(sub.matches(0x4000, &mac, &asdu));
        assert!(!sub.matches(0x4000, &[0x01, 0x0C, 0xCD, 0x04, 0x00, 0x02], &asdu));
    }

    #[test]
    fn dispatch_callback_fires() {
        let counter: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let c = counter.clone();
        let sub = SvSubscriberBuilder::new()
            .listener(move |_asdu| {
                *c.lock().unwrap() += 1;
            })
            .build();

        let asdu = make_asdu("sv1", 0, vec![0u8; 8]);
        let view = SvSubscriberAsdu::from_asdu(&asdu);
        sub.dispatch(&view);
        assert_eq!(*counter.lock().unwrap(), 1);
    }

    #[test]
    fn dispatch_q4_first_call_locks_sample_size() {
        let counter: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let c = counter.clone();
        let sub = SvSubscriberBuilder::new()
            .listener(move |_| {
                *c.lock().unwrap() += 1;
            })
            .build();

        // The first ASDU locks the sample length at 8.
        let asdu1 = make_asdu("sv1", 0, vec![0u8; 8]);
        let view1 = SvSubscriberAsdu::from_asdu(&asdu1);
        sub.dispatch(&view1);
        assert_eq!(sub.expected_sample_size(), 8);
        assert_eq!(*counter.lock().unwrap(), 1);

        // A matching length is delivered.
        let asdu2 = make_asdu("sv1", 1, vec![0u8; 8]);
        let view2 = SvSubscriberAsdu::from_asdu(&asdu2);
        sub.dispatch(&view2);
        assert_eq!(*counter.lock().unwrap(), 2);
    }

    #[test]
    fn dispatch_q4_size_mismatch_skips_callback() {
        let counter: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let c = counter.clone();
        let sub = SvSubscriberBuilder::new()
            .listener(move |_| {
                *c.lock().unwrap() += 1;
            })
            .build();

        // The first ASDU locks the sample length at 64.
        let asdu1 = make_asdu("sv1", 0, vec![0u8; 64]);
        sub.dispatch(&SvSubscriberAsdu::from_asdu(&asdu1));
        assert_eq!(*counter.lock().unwrap(), 1);

        // A different length is dropped.
        let asdu2 = make_asdu("sv1", 1, vec![0u8; 80]);
        sub.dispatch(&SvSubscriberAsdu::from_asdu(&asdu2));
        assert_eq!(
            *counter.lock().unwrap(),
            1,
            "a differing sample length is not delivered"
        );
    }

    #[test]
    fn dispatch_smp_cnt_gap_detection() {
        let counter: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let c = counter.clone();
        let sub = SvSubscriberBuilder::new()
            .listener(move |_| {
                *c.lock().unwrap() += 1;
            })
            .build();

        // The first ASDU sets the baseline.
        let a1 = make_asdu("sv1", 1, vec![0u8; 8]);
        sub.dispatch(&SvSubscriberAsdu::from_asdu(&a1));
        assert_eq!(sub.missed_count(), 0);

        // The next counter follows on.
        let a2 = make_asdu("sv1", 2, vec![0u8; 8]);
        sub.dispatch(&SvSubscriberAsdu::from_asdu(&a2));
        assert_eq!(sub.missed_count(), 0);

        // Counter 3 is missing, so one sample is counted as missed.
        let a4 = make_asdu("sv1", 4, vec![0u8; 8]);
        sub.dispatch(&SvSubscriberAsdu::from_asdu(&a4));
        assert_eq!(sub.missed_count(), 1, "one missed sample is counted");

        // The ASDU after a gap is still delivered.
        assert_eq!(*counter.lock().unwrap(), 3);
    }
}
