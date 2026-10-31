//! Sampled Values subscriber: stream filters and per-ASDU callbacks.
//!
//! An `SvSubscriber` selects streams by APPID, destination MAC, and svID, and
//! hands each matching ASDU to its listener as an `SvSubscriberAsdu` borrowed
//! from the receive buffer, so dispatch copies no samples. Every ASDU is
//! delivered to every subscriber that matches it.
//!
//! Two consistency checks run before the listener. A subscriber built with a
//! sample length, the encoded size of the data set it subscribes to, reports
//! and drops an ASDU of any other length, so a listener never reads a sample
//! laid out differently from the one it was written for. Without one every
//! ASDU is delivered with its own sample, whose accessors check bounds, and no
//! received frame decides the length later frames must have. A smpCnt that
//! does not follow its predecessor is counted in `missed_count`, which exposes
//! gaps in the stream; that ASDU is still delivered. smpCnt wraps to 0 at the
//! configured limit, or at a smpRate sent with smpMod samples-per-second;
//! without either, a smpCnt below its predecessor is taken as the
//! once-a-second reset of a synchronized stream, and only the samples from 0
//! up to it count as missed.
//! Continuity is followed per svID, so a subscriber without an svID filter
//! checks each stream against its own predecessor; the number of streams it
//! follows is bounded.
//!
//! The state a subscriber accumulates is atomic, so one `Arc<SvSubscriber>`
//! can be shared across threads.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use iec61850_model::Quality;

use crate::error::SvError;
use crate::nine_two_le::{NineTwoLE, SAMPLE_SIZE};
use crate::pdu::{Asdu, SmpMod, SmpSynch};

/// Default number of streams a subscriber follows for smpCnt continuity.
pub const DEFAULT_MAX_STREAMS: usize = 64;

/// Listener invoked once per matching ASDU.
pub type SvListener = Arc<dyn Fn(&SvSubscriberAsdu<'_>) + Send + Sync>;

/// A borrowed view of one ASDU, valid for the duration of the callback.
#[non_exhaustive]
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
    sample_size: Option<usize>,
    smp_cnt_limit: Option<u16>,
    max_streams: Option<usize>,
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
            sample_size: None,
            smp_cnt_limit: None,
            max_streams: None,
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

    /// Sets the sample length, in bytes, every delivered ASDU must have.
    ///
    /// The length follows from the data set the stream publishes, for instance
    /// [`SAMPLE_SIZE`] for the 9-2 LE profile. An ASDU of any other length is
    /// reported and dropped. Leaving it unset delivers every ASDU whatever its
    /// sample length.
    pub fn sample_size(mut self, len: usize) -> Self {
        self.sample_size = Some(len);
        self
    }

    /// Sets the smpCnt value at which the stream wraps to 0.
    ///
    /// IEC 61850-9-2 §8.5.2 Table 14 increments smpCnt with every sample and
    /// resets it to 0 on synchronization; a stream synchronized once a second,
    /// as IEC 61850-9-2LE has it, wraps at its number of samples per second,
    /// for instance 4000 at 80 samples per period and 50 Hz. A step from `limit - 1` to 0 is then
    /// continuous, and a step to 0 from earlier counts the samples skipped. A
    /// limit of 0 is ignored.
    pub fn smp_cnt_limit(mut self, limit: u16) -> Self {
        self.smp_cnt_limit = Some(limit).filter(|l| *l > 0);
        self
    }

    /// Sets how many svIDs the subscriber follows for smpCnt continuity; the
    /// default is [`DEFAULT_MAX_STREAMS`] and the minimum 1.
    ///
    /// When an ASDU of a new svID arrives with every slot taken, the stream
    /// heard from least recently is forgotten, and its next ASDU starts a new
    /// baseline; the first eviction is logged. A subscriber with an svID filter
    /// follows one stream.
    pub fn max_streams(mut self, n: usize) -> Self {
        self.max_streams = Some(n);
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
            expected_sample_size: self.sample_size,
            smp_cnt_limit: self.smp_cnt_limit,
            max_streams: self.max_streams.unwrap_or(DEFAULT_MAX_STREAMS).max(1),
            streams: Mutex::new(StreamTable::default()),
            missed_count: AtomicU64::new(0),
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
    /// Sample length every delivered ASDU must have; `None` accepts any length.
    expected_sample_size: Option<usize>,
    /// smpCnt value at which the stream wraps to 0, when configured.
    smp_cnt_limit: Option<u16>,
    /// Upper bound on the streams followed.
    max_streams: usize,
    /// Last smpCnt per svID.
    streams: Mutex<StreamTable>,
    /// Number of samples missed, summed over every detected gap.
    missed_count: AtomicU64,
}

/// Last smpCnt of each followed stream.
#[derive(Default)]
struct StreamTable {
    /// One entry per svID.
    entries: Vec<StreamEntry>,
    /// Dispatch counter, the recency stamp of `StreamEntry::last_seen`.
    clock: u64,
    /// Whether an eviction has been logged; later ones are not, so a peer
    /// cycling through svIDs cannot flood the log.
    eviction_reported: bool,
}

/// Continuity state of one svID.
struct StreamEntry {
    sv_id: String,
    last_smp_cnt: u16,
    last_seen: u64,
}

impl StreamTable {
    /// Records `cnt` for `sv_id` and returns the previous smpCnt of that
    /// stream, or `None` when the stream is new; at `max` entries the least
    /// recent one makes room.
    fn swap(&mut self, sv_id: &str, cnt: u16, max: usize) -> Option<u16> {
        self.clock = self.clock.wrapping_add(1);
        let clock = self.clock;
        if let Some(e) = self.entries.iter_mut().find(|e| e.sv_id == sv_id) {
            e.last_seen = clock;
            return Some(std::mem::replace(&mut e.last_smp_cnt, cnt));
        }
        if self.entries.len() >= max {
            let oldest = self
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.last_seen)
                .map(|(i, _)| i);
            if let Some(i) = oldest {
                let gone = self.entries.swap_remove(i);
                if !self.eviction_reported {
                    self.eviction_reported = true;
                    tracing::warn!(
                        "sv subscriber follows {} streams, forgetting svid={:?}; later evictions are not logged",
                        max,
                        gone.sv_id
                    );
                }
            }
        }
        self.entries.push(StreamEntry {
            sv_id: sv_id.to_owned(),
            last_smp_cnt: cnt,
            last_seen: clock,
        });
        None
    }
}

impl std::fmt::Debug for SvSubscriber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SvSubscriber")
            .field("app_id_filter", &self.app_id_filter)
            .field("sv_id_filter", &self.sv_id_filter)
            .field("dst_mac_filter", &self.dst_mac_filter)
            .field("has_listener", &self.listener.is_some())
            .field("expected_sample_size", &self.expected_sample_size)
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

    /// Returns the configured sample length, or 0 when none is configured.
    pub fn expected_sample_size(&self) -> usize {
        self.expected_sample_size.unwrap_or(0)
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
    /// When a sample length is configured, an ASDU of a different length is
    /// reported and dropped. A smpCnt that skips ahead adds the gap to
    /// `missed_count` but is still delivered.
    pub fn dispatch(&self, asdu_view: &SvSubscriberAsdu<'_>) {
        let sample_len = asdu_view.sample.len();
        if let Some(expected) = self.expected_sample_size {
            if expected != sample_len {
                tracing::warn!(
                    "sv subscriber svid={:?}: sample length {} differs from the expected {}, dropping",
                    asdu_view.sv_id,
                    sample_len,
                    expected
                );
                return;
            }
        }

        let cur_cnt = asdu_view.smp_cnt;
        let prev = self
            .streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .swap(asdu_view.sv_id, cur_cnt, self.max_streams);
        if let Some(prev) = prev {
            let limit = self.smp_cnt_limit.or_else(|| announced_limit(asdu_view));
            let diff = smp_cnt_gap(prev, cur_cnt, limit);
            if diff != 0 {
                tracing::warn!(
                    "sv subscriber svid={:?}: smpcnt gap, prev={} cur={} missed={}",
                    asdu_view.sv_id,
                    prev,
                    cur_cnt,
                    diff
                );
                self.missed_count.fetch_add(diff, Ordering::Relaxed);
            }
        }

        if let Some(ref cb) = self.listener {
            cb(asdu_view);
        }
    }
}

/// Returns the smpCnt limit an ASDU announces: its smpRate when smpMod is
/// samples per second.
fn announced_limit(asdu: &SvSubscriberAsdu<'_>) -> Option<u16> {
    match (asdu.smp_mod, asdu.smp_rate) {
        (Some(SmpMod::SamplesPerSecond), Some(rate)) if rate > 0 => Some(rate),
        _ => None,
    }
}

/// Returns how many samples lie between `prev` and `cur`.
///
/// With a limit both counters are taken modulo it. Without one a counter
/// below its predecessor restarted at 0, by the once-a-second reset or by the
/// wrap at 65536, so the samples `0..cur` are the ones missed.
fn smp_cnt_gap(prev: u16, cur: u16, limit: Option<u16>) -> u64 {
    match limit {
        Some(l) if prev < l && cur < l => {
            let l = u32::from(l);
            let expected = (u32::from(prev) + 1) % l;
            u64::from((u32::from(cur) + l - expected) % l)
        }
        Some(_) => u64::from(cur.wrapping_sub(prev.wrapping_add(1))),
        None if cur < prev => u64::from(cur),
        None => u64::from(cur.wrapping_sub(prev.wrapping_add(1))),
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
    fn dispatch_unconfigured_delivers_every_sample_length() {
        let counter: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let c = counter.clone();
        let sub = SvSubscriberBuilder::new()
            .listener(move |_| {
                *c.lock().unwrap() += 1;
            })
            .build();

        let asdu1 = make_asdu("sv1", 0, vec![0u8; 8]);
        sub.dispatch(&SvSubscriberAsdu::from_asdu(&asdu1));
        let asdu2 = make_asdu("sv1", 1, vec![0u8; 16]);
        sub.dispatch(&SvSubscriberAsdu::from_asdu(&asdu2));
        assert_eq!(sub.expected_sample_size(), 0);
        assert_eq!(*counter.lock().unwrap(), 2);
    }

    #[test]
    fn dispatch_q4_size_mismatch_skips_callback() {
        let counter: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let c = counter.clone();
        let sub = SvSubscriberBuilder::new()
            .sample_size(64)
            .listener(move |_| {
                *c.lock().unwrap() += 1;
            })
            .build();

        // The configured length is delivered.
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
