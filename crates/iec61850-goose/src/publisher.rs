//! GOOSE publisher: state numbering, retransmission timing, and the prebuilt
//! frame template.
//!
//! `GoosePublisher` owns stNum, sqNum, and the retransmission phase, and
//! produces complete Ethernet frames. It opens no socket and spawns no thread:
//! the caller drives it with `tick(now)` and `next_publish_at(now)` and sends
//! the returned bytes itself, which keeps the hot path free of any runtime.
//!
//! Retransmission follows the IEC 61850-8-1 Table D.2 defaults of 4, 8, 16,
//! and 32 ms after an event and 1000 ms in the steady state, with
//! `timeAllowedToLive = 2 x next_interval`. A data change is not detected
//! automatically; the application calls `increase_st_num()` when the data set
//! value changes, which avoids a deep `MmsValue` comparison per publication.

use bytes::{Bytes, BytesMut};
use core::time::Duration;
use iec61850_model::MmsValue;
use std::time::Instant;

use crate::error::GooseError;
use crate::frame::{GooseFrame, GooseFrameHeader, VlanPriority, VlanTag};
use crate::pdu::GoosePdu;

/// Maximum size of a GOOSE frame including the Ethernet header.
pub const GOOSE_MAX_FRAME_SIZE: usize = 1518;

/// Communication parameters of a GOOSE publication: APPID, destination MAC,
/// and the optional VLAN tag and source MAC.
///
/// ## Example
///
/// ```ignore
/// let comm = CommParameters::new(0x1000, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01])
///     .with_vlan(VlanTag { priority: VlanPriority::new(4)?, vlan_id: 100 })
///     .with_src_mac([0x00, 0x50, 0xc2, 0x12, 0x34, 0x56]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommParameters {
    /// Application identifier; GOOSE conventionally uses 0x0000-0x3FFF.
    pub app_id: u16,
    /// Destination MAC address, normally a multicast address.
    pub dst_mac: [u8; 6],
    /// Source MAC address; when `None` the frame template is built with an
    /// all-zero address for the sending interface to fill in.
    pub src_mac: Option<[u8; 6]>,
    /// Optional 802.1Q VLAN tag.
    pub vlan: Option<VlanTag>,
}

impl CommParameters {
    /// Creates parameters with no VLAN tag and no source MAC override.
    pub fn new(app_id: u16, dst_mac: [u8; 6]) -> Self {
        Self {
            app_id,
            dst_mac,
            src_mac: None,
            vlan: None,
        }
    }

    /// Sets the 802.1Q VLAN tag.
    pub fn with_vlan(mut self, vlan: VlanTag) -> Self {
        self.vlan = Some(vlan);
        self
    }

    /// Sets the source MAC address.
    pub fn with_src_mac(mut self, src: [u8; 6]) -> Self {
        self.src_mac = Some(src);
        self
    }

    /// Sets the VLAN priority, keeping the current VLAN ID or 0 when no tag
    /// has been set yet.
    pub fn with_priority(mut self, priority: VlanPriority) -> Self {
        let vlan_id = self.vlan.map(|v| v.vlan_id).unwrap_or(0);
        self.vlan = Some(VlanTag { priority, vlan_id });
        self
    }
}

/// Retransmission intervals of a GOOSE publication.
///
/// `Default` is the IEC 61850-8-1 Table D.2 set: T1 = 4 ms, T2 = 8 ms,
/// T3 = 16 ms, T4 = 32 ms after an event, and Tmax = 1000 ms in the steady
/// state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetransIntervals {
    /// Interval before the first retransmission after an event.
    pub t1: Duration,
    /// Interval before the second retransmission.
    pub t2: Duration,
    /// Interval before the third retransmission.
    pub t3: Duration,
    /// Interval before the fourth retransmission.
    pub t4: Duration,
    /// Steady-state retransmission interval.
    pub tmax: Duration,
}

impl Default for RetransIntervals {
    fn default() -> Self {
        Self {
            t1: Duration::from_millis(4),
            t2: Duration::from_millis(8),
            t3: Duration::from_millis(16),
            t4: Duration::from_millis(32),
            tmax: Duration::from_millis(1000),
        }
    }
}

/// Retransmission phase, the backoff state after an event.
///
/// Each publication advances T1 to T2 to T3 to T4 to Stable and then stays at
/// Stable; `increase_st_num` resets the phase to T1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetransPhase {
    /// First publication after an event; the next interval is T1.
    T1,
    /// Second publication; the next interval is T2.
    T2,
    /// Third publication; the next interval is T3.
    T3,
    /// Fourth publication; the next interval is T4.
    T4,
    /// Steady state; the next interval is Tmax.
    Stable,
}

impl RetransPhase {
    /// Returns the interval this phase schedules before the next publication.
    pub fn interval(self, intervals: &RetransIntervals) -> Duration {
        match self {
            RetransPhase::T1 => intervals.t1,
            RetransPhase::T2 => intervals.t2,
            RetransPhase::T3 => intervals.t3,
            RetransPhase::T4 => intervals.t4,
            RetransPhase::Stable => intervals.tmax,
        }
    }

    /// Returns the following phase; Stable maps to itself.
    fn advance(self) -> Self {
        match self {
            RetransPhase::T1 => RetransPhase::T2,
            RetransPhase::T2 => RetransPhase::T3,
            RetransPhase::T3 => RetransPhase::T4,
            RetransPhase::T4 => RetransPhase::Stable,
            RetransPhase::Stable => RetransPhase::Stable,
        }
    }
}

/// GOOSE publisher holding stNum, sqNum, the retransmission phase, and the
/// prebuilt frame template.
///
/// The publisher produces frame bytes; sending them is the caller's job.
///
/// ## Example
///
/// ```ignore
/// let mut publisher = GoosePublisher::new(comm, "A/L$GO$gcb", None, "A/L$DS", 1)?;
/// loop {
///     let now = Instant::now();
///     if let Some(action) = publisher.tick(now) {
///         let frame = publisher.publish(&dataset)?;
///         // hal.send(&frame);
///     }
///     // sleep until publisher.next_publish_at(Instant::now())
/// }
/// // On a data change:
/// publisher.increase_st_num();
/// ```
pub struct GoosePublisher {
    gocb_ref: String,
    data_set_ref: String,
    go_id: Option<String>,
    conf_rev: u32,
    /// State number; never 0.
    st_num: u32,
    /// Sequence number, incremented after each publication and wrapping to 1.
    sq_num: u32,
    simulation: bool,
    needs_commission: bool,
    /// Event timestamp as an 8-byte UTC time.
    timestamp_8: [u8; 8],
    /// Caller override for timeAllowedToLive; `None` derives it from the phase.
    time_allowed_to_live_override: Option<u32>,

    /// Prebuilt Ethernet and GOOSE header bytes. The Length field holds a
    /// placeholder that each publication overwrites in the output copy.
    frame_header_bytes: Vec<u8>,
    /// Offset of the GOOSE Length field within `frame_header_bytes`.
    length_field_offset: usize,

    retrans_intervals: RetransIntervals,
    phase: RetransPhase,
    /// Time of the next publication; `None` means nothing has been published
    /// yet and the first frame is due immediately.
    next_publish_at: Option<Instant>,

    /// GoEna, the flag a server writes through SetGoCBValues.
    ///
    /// The flag only records intent: the publisher starts and stops nothing,
    /// and the caller reads `enabled()` to decide whether to transmit. It is
    /// atomic so `set_enabled` takes `&self` and can be called from the thread
    /// serving MMS while the publish loop holds the publisher.
    enabled: std::sync::atomic::AtomicBool,
}

impl GoosePublisher {
    /// Creates a publisher and prebuilds the frame header, so that publishing
    /// only encodes the PDU, copies the header, and patches the Length field.
    ///
    /// # Errors
    ///
    /// Returns `FieldTooLong(0)` when `gocb_ref` or `data_set_ref` is empty.
    pub fn new(
        comm: CommParameters,
        gocb_ref: impl Into<String>,
        go_id: Option<String>,
        data_set_ref: impl Into<String>,
        conf_rev: u32,
    ) -> Result<Self, GooseError> {
        let gocb_ref = gocb_ref.into();
        let data_set_ref = data_set_ref.into();

        if gocb_ref.is_empty() {
            return Err(GooseError::FieldTooLong(0));
        }
        if data_set_ref.is_empty() {
            return Err(GooseError::FieldTooLong(0));
        }

        let src_mac = comm.src_mac.unwrap_or([0u8; 6]);
        let header = GooseFrameHeader {
            dst_mac: comm.dst_mac,
            src_mac,
            vlan: comm.vlan,
            app_id: comm.app_id,
            length: 8, // placeholder, patched per publication
        };

        // Encoding an empty PDU yields exactly the header bytes.
        let template_frame = GooseFrame::new(header, Vec::new());
        let mut tmp = BytesMut::new();
        template_frame.encode(&mut tmp)?;
        let frame_header_bytes: Vec<u8> = tmp.to_vec();

        // The Length field follows the APPID: 14 + 2 without a VLAN tag,
        // 18 + 2 with one.
        let length_field_offset = if comm.vlan.is_some() { 20 } else { 16 };

        Ok(Self {
            gocb_ref,
            data_set_ref,
            go_id,
            conf_rev,
            st_num: 1,
            sq_num: 0,
            simulation: false,
            needs_commission: false,
            timestamp_8: [0u8; 8],
            time_allowed_to_live_override: None,
            frame_header_bytes,
            length_field_offset,
            retrans_intervals: RetransIntervals::default(),
            phase: RetransPhase::T1,
            next_publish_at: None,
            enabled: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Sets GoEna. The flag is advisory: no thread is started or stopped.
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, std::sync::atomic::Ordering::Release);
    }

    /// Returns GoEna.
    pub fn enabled(&self) -> bool {
        self.enabled.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Returns the configured goID, or `None` when gocbRef is sent instead.
    pub fn go_id(&self) -> Option<&str> {
        self.go_id.as_deref()
    }

    /// Sets the simulation bit, called `test` in IEC 61850-8-1.
    pub fn set_simulation(&mut self, v: bool) {
        self.simulation = v;
    }

    /// Sets the ndsCom flag.
    pub fn set_needs_commission(&mut self, v: bool) {
        self.needs_commission = v;
    }

    /// Sets the goID; `None` sends gocbRef in the goID field.
    pub fn set_go_id(&mut self, id: Option<String>) {
        self.go_id = id;
    }

    /// Sets confRev.
    pub fn set_conf_rev(&mut self, v: u32) {
        self.conf_rev = v;
    }

    /// Replaces the retransmission intervals.
    pub fn set_retrans_intervals(&mut self, intervals: RetransIntervals) {
        self.retrans_intervals = intervals;
    }

    /// Returns the retransmission intervals in use.
    pub fn retrans_intervals(&self) -> &RetransIntervals {
        &self.retrans_intervals
    }

    /// Overrides timeAllowedToLive in milliseconds; `None` restores the
    /// derived value.
    pub fn set_time_allowed_to_live(&mut self, ms: Option<u32>) {
        self.time_allowed_to_live_override = ms;
    }

    /// Returns the current stNum.
    pub fn st_num(&self) -> u32 {
        self.st_num
    }

    /// Returns the sqNum the next publication will put on the wire.
    ///
    /// It is 0 after a reset or a state change, because the counter is
    /// incremented after encoding.
    pub fn sq_num(&self) -> u32 {
        self.sq_num
    }

    /// Returns the current retransmission phase.
    pub fn phase(&self) -> RetransPhase {
        self.phase
    }

    /// Returns the interval before the next publication.
    pub fn next_interval(&self) -> Duration {
        self.phase.interval(&self.retrans_intervals)
    }

    /// Returns timeAllowedToLive in milliseconds: the override when one is
    /// set, otherwise twice the next interval.
    pub fn time_allowed_to_live_ms(&self) -> u32 {
        if let Some(v) = self.time_allowed_to_live_override {
            return v;
        }
        // Saturate rather than wrap on an extreme custom interval.
        let doubled = self.next_interval().as_millis().saturating_mul(2);
        u32::try_from(doubled).unwrap_or(u32::MAX)
    }

    /// Returns the prebuilt frame header bytes.
    #[cfg(test)]
    pub(crate) fn frame_header_bytes(&self) -> &[u8] {
        &self.frame_header_bytes
    }

    /// Records a data change: stNum advances, sqNum returns to 0, and the
    /// retransmission phase resets to T1 so the burst restarts.
    ///
    /// `stNum` wraps to 1 rather than 0, which subscribers read as an
    /// uninitialized publisher.
    pub fn increase_st_num(&mut self) {
        let new_st = self.st_num.wrapping_add(1);
        self.st_num = if new_st == 0 { 1 } else { new_st };
        self.sq_num = 0;
        self.phase = RetransPhase::T1;
        self.next_publish_at = None;
        // The timestamp is left to the caller through `set_timestamp`, so this
        // path makes no clock syscall.
    }

    /// Resets the publisher to stNum 1, sqNum 0, and phase T1.
    pub fn reset(&mut self) {
        self.st_num = 1;
        self.sq_num = 0;
        self.phase = RetransPhase::T1;
        self.next_publish_at = None;
    }

    /// Sets the 8-byte UTC event timestamp.
    ///
    /// The value persists until it is set again, so a caller that never calls
    /// this publishes the same timestamp on every frame.
    pub fn set_timestamp(&mut self, ts: [u8; 8]) {
        self.timestamp_8 = ts;
    }

    /// Returns the time of the next publication.
    ///
    /// Before the first publication this is `now`, so an event is sent without
    /// waiting for T1; afterwards it is the last publication plus the interval
    /// of the phase that was current then.
    pub fn next_publish_at(&self, now: Instant) -> Instant {
        self.next_publish_at.unwrap_or(now)
    }

    /// Returns `Some(PublishAction)` when a publication is due at `now`, and
    /// `None` when the caller should keep waiting.
    ///
    /// This never publishes by itself; the caller owns the data source and the
    /// send.
    pub fn tick(&self, now: Instant) -> Option<PublishAction> {
        let target = self.next_publish_at(now);
        if now >= target {
            Some(PublishAction { at: target })
        } else {
            None
        }
    }

    /// Encodes one GOOSE frame and returns the complete Ethernet bytes.
    ///
    /// The current sqNum is encoded and then incremented, the retransmission
    /// phase advances, and the next publication is scheduled one interval
    /// ahead. A data change is not detected here; call `increase_st_num` for
    /// that.
    ///
    /// # Errors
    ///
    /// Returns `PduOverflow` when the frame would exceed
    /// `GOOSE_MAX_FRAME_SIZE`, and any encode error from the data set values.
    pub fn publish(&mut self, data: &[MmsValue]) -> Result<Bytes, GooseError> {
        self.publish_at(data, Instant::now())
    }

    /// `publish` with the current time supplied by the caller.
    pub fn publish_at(&mut self, data: &[MmsValue], now: Instant) -> Result<Bytes, GooseError> {
        let pdu = GoosePdu {
            gocb_ref: self.gocb_ref.clone(),
            time_allowed_to_live: self.time_allowed_to_live_ms(),
            dat_set: self.data_set_ref.clone(),
            go_id: self.go_id.clone(),
            t: self.timestamp_8,
            st_num: self.st_num,
            // Encoded before the increment, so per IEC 61850-8-1 §A.3 the first
            // frame after a reset carries sqNum 0.
            sq_num: self.sq_num,
            simulation: self.simulation,
            conf_rev: self.conf_rev,
            nds_com: self.needs_commission,
            num_dataset_entries: data.len() as u32,
            all_data: data.to_vec(),
        };

        let mut pdu_buf = BytesMut::new();
        pdu.encode_ber(&mut pdu_buf)?;
        let pdu_bytes = pdu_buf.freeze();

        let frame_size = self.frame_header_bytes.len() + pdu_bytes.len();
        if frame_size > GOOSE_MAX_FRAME_SIZE {
            tracing::warn!(
                "goose frame size {} exceeds the {} byte limit",
                frame_size,
                GOOSE_MAX_FRAME_SIZE
            );
            return Err(GooseError::PduOverflow);
        }

        // Copy the template, patch its Length field, then append the PDU.
        let mut out = BytesMut::with_capacity(frame_size);
        out.extend_from_slice(&self.frame_header_bytes);
        let length: u16 = u16::try_from(pdu_bytes.len() + 8).unwrap_or(u16::MAX);
        let length_be = length.to_be_bytes();
        out[self.length_field_offset] = length_be[0];
        out[self.length_field_offset + 1] = length_be[1];
        out.extend_from_slice(&pdu_bytes);

        // IEC 61850-8-1 §A.3 reserves sqNum 0 for the first frame of a state,
        // so the counter wraps to 1.
        let new_sq = self.sq_num.wrapping_add(1);
        self.sq_num = if new_sq == 0 { 1 } else { new_sq };

        let interval = self.next_interval();
        self.phase = self.phase.advance();
        self.next_publish_at = Some(now + interval);

        Ok(out.freeze())
    }

    /// Publishes and returns the frame bytes for the caller to handle, such as
    /// writing a capture file or duplicating the frame onto a second path.
    ///
    /// Identical to `publish`; no extra copy is made.
    ///
    /// # Errors
    ///
    /// Same as `publish`.
    pub fn publish_and_dump(&mut self, data: &[MmsValue]) -> Result<Bytes, GooseError> {
        self.publish(data)
    }
}

/// Describes a publication that `tick` reports as due.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishAction {
    /// Scheduled time of this publication, from which the caller can measure
    /// jitter against the actual send.
    pub at: Instant,
}

#[cfg(feature = "tokio-runtime")]
pub mod tokio_helper {
    //! Async retransmission loop, available under the `tokio-runtime` feature.
    //!
    //! Timing here is only as good as the runtime: a busy executor can delay a
    //! publication by milliseconds. Deployments that need bounded jitter drive
    //! the publisher from a dedicated thread instead.

    use super::*;
    use tokio::sync::mpsc;
    use tokio::time::{sleep_until, Instant as TokioInstant};

    /// Runs the retransmission loop until canceled.
    ///
    /// `data_provider` supplies the current data set for each publication and
    /// the encoded frames are sent to `tx`. The loop returns the publisher when
    /// `cancel_rx` receives a signal or `tx` is closed.
    ///
    /// # Errors
    ///
    /// Returns the first publish error, which ends the loop.
    pub async fn run_retrans_loop<F>(
        mut publisher: GoosePublisher,
        mut data_provider: F,
        tx: mpsc::Sender<Bytes>,
        mut cancel_rx: mpsc::Receiver<()>,
    ) -> Result<GoosePublisher, GooseError>
    where
        F: FnMut() -> Vec<MmsValue> + Send + 'static,
    {
        loop {
            let now_std = std::time::Instant::now();
            let target_std = publisher.next_publish_at(now_std);
            let target_tokio = if target_std <= now_std {
                TokioInstant::now()
            } else {
                TokioInstant::now() + (target_std - now_std)
            };

            tokio::select! {
                _ = sleep_until(target_tokio) => {
                    let data = data_provider();
                    let frame = publisher.publish(&data)?;
                    if tx.send(frame).await.is_err() {
                        return Ok(publisher);
                    }
                }
                _ = cancel_rx.recv() => {
                    return Ok(publisher);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{VlanPriority, VlanTag, GOOSE_ETHER_TYPE};

    fn sample_comm() -> CommParameters {
        CommParameters::new(0x1000, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01])
            .with_src_mac([0x00, 0x50, 0xc2, 0x12, 0x34, 0x56])
    }

    fn sample_publisher() -> GoosePublisher {
        GoosePublisher::new(sample_comm(), "A/L$GO$gcb", None, "A/L$DS", 1).unwrap()
    }

    fn sample_data() -> Vec<MmsValue> {
        vec![MmsValue::Boolean(true)]
    }

    #[test]
    fn new_basic_no_vlan() {
        let p = sample_publisher();
        assert_eq!(p.st_num(), 1);
        assert_eq!(p.sq_num(), 0);
        assert_eq!(p.phase(), RetransPhase::T1);
        // 14 Ethernet bytes plus the 8-byte GOOSE header.
        assert_eq!(p.frame_header_bytes().len(), 14 + 8);
    }

    #[test]
    fn new_with_vlan_header_size() {
        let comm = sample_comm().with_vlan(VlanTag {
            priority: VlanPriority::new(4).unwrap(),
            vlan_id: 100,
        });
        let p = GoosePublisher::new(comm, "A/L$GO$gcb", None, "A/L$DS", 1).unwrap();
        // 18 Ethernet bytes with the VLAN tag, plus the 8-byte GOOSE header.
        assert_eq!(p.frame_header_bytes().len(), 18 + 8);
    }

    #[test]
    fn new_rejects_empty_gocb_ref() {
        let r = GoosePublisher::new(sample_comm(), "", None, "A/L$DS", 1);
        assert!(r.is_err());
    }

    #[test]
    fn new_rejects_empty_data_set_ref() {
        let r = GoosePublisher::new(sample_comm(), "A/L$GO$gcb", None, "", 1);
        assert!(r.is_err());
    }

    #[test]
    fn frame_template_immutable_across_publish() {
        let mut p = sample_publisher();
        let template = p.frame_header_bytes().to_vec();

        for _ in 0..3 {
            let _ = p.publish(&sample_data()).unwrap();
        }
        // The Length patch lands in the output copy, never in the template.
        assert_eq!(p.frame_header_bytes(), &template[..]);
    }

    #[test]
    fn sq_num_sequence_5_publish() {
        let mut p = sample_publisher();
        // sq_num() reports what the next publication will encode, so the wire
        // sequence trails the state sequence by one.
        let mut wire_seq = Vec::new();
        let mut state_seq = vec![p.sq_num()];
        for _ in 0..5 {
            let frame = p.publish(&sample_data()).unwrap();
            let goose_frame = GooseFrame::decode(&frame).unwrap();
            let pdu = GoosePdu::decode_ber(&goose_frame.pdu_bytes).unwrap();
            wire_seq.push(pdu.sq_num);
            state_seq.push(p.sq_num());
        }
        assert_eq!(
            wire_seq,
            vec![0, 1, 2, 3, 4],
            "wire sqnum sequence starts at 0"
        );
        assert_eq!(state_seq, vec![0, 1, 2, 3, 4, 5]);
        assert_eq!(p.st_num(), 1);
    }

    #[test]
    fn wire_first_packet_sq_num_is_zero() {
        // A subscriber that sees sqNum 1 first would read the publication as
        // already in progress and may report a gap.
        let mut p = sample_publisher();
        let bytes = p.publish(&[]).unwrap();
        let frame = GooseFrame::decode(&bytes).unwrap();
        let pdu = GoosePdu::decode_ber(&frame.pdu_bytes).unwrap();
        assert_eq!(pdu.sq_num, 0, "first frame carries sqnum 0");
    }

    #[test]
    fn sq_num_wraps_to_one_not_zero() {
        let mut p = sample_publisher();
        p.sq_num = 0xFFFFFFFF;

        let frame1 = p.publish(&sample_data()).unwrap();
        let pdu1 = GoosePdu::decode_ber(&GooseFrame::decode(&frame1).unwrap().pdu_bytes).unwrap();
        assert_eq!(pdu1.sq_num, 0xFFFFFFFF);
        assert_eq!(p.sq_num(), 1, "sqnum wraps to 1, not 0");

        let frame2 = p.publish(&sample_data()).unwrap();
        let pdu2 = GoosePdu::decode_ber(&GooseFrame::decode(&frame2).unwrap().pdu_bytes).unwrap();
        assert_eq!(pdu2.sq_num, 1, "the frame after the wrap carries sqnum 1");
    }

    #[test]
    fn st_num_wraps_to_one_not_zero() {
        let mut p = sample_publisher();
        p.st_num = 0xFFFFFFFF;
        p.increase_st_num();
        assert_eq!(p.st_num(), 1, "stnum wraps to 1, not 0");
        assert_eq!(p.sq_num(), 0, "a state change resets sqnum");
    }

    #[test]
    fn st_num_increase_normal() {
        let mut p = sample_publisher();
        assert_eq!(p.st_num(), 1);
        p.increase_st_num();
        assert_eq!(p.st_num(), 2);
        assert_eq!(p.sq_num(), 0);
        assert_eq!(p.phase(), RetransPhase::T1);
    }

    #[test]
    fn increase_st_num_resets_sq_num() {
        let mut p = sample_publisher();
        for _ in 0..3 {
            let _ = p.publish(&sample_data()).unwrap();
        }
        assert_eq!(p.sq_num(), 3);
        p.increase_st_num();
        assert_eq!(p.sq_num(), 0);
        assert_eq!(p.phase(), RetransPhase::T1);

        let frame = p.publish(&sample_data()).unwrap();
        let pdu = GoosePdu::decode_ber(&GooseFrame::decode(&frame).unwrap().pdu_bytes).unwrap();
        assert_eq!(pdu.sq_num, 0, "first frame of a new state carries sqnum 0");
        assert_eq!(p.sq_num(), 1, "the counter advances after encoding");
    }

    #[test]
    fn retrans_phase_progression() {
        let mut p = sample_publisher();
        let phases_observed: Vec<RetransPhase> = (0..6)
            .map(|_| {
                let phase_before = p.phase();
                let _ = p.publish(&sample_data()).unwrap();
                phase_before
            })
            .collect();
        // Phase observed before each publication.
        assert_eq!(
            phases_observed,
            vec![
                RetransPhase::T1,
                RetransPhase::T2,
                RetransPhase::T3,
                RetransPhase::T4,
                RetransPhase::Stable,
                RetransPhase::Stable,
            ]
        );
    }

    #[test]
    fn time_allowed_to_live_doubled() {
        let p = sample_publisher();
        // T1 is 4 ms, so timeAllowedToLive is 8 ms.
        assert_eq!(p.time_allowed_to_live_ms(), 8);
    }

    #[test]
    fn time_allowed_to_live_each_phase() {
        let mut p = sample_publisher();
        // Twice the interval of each phase in turn.
        let expected_ms = vec![8, 16, 32, 64, 2000, 2000];
        let mut actual = Vec::new();
        for _ in 0..6 {
            actual.push(p.time_allowed_to_live_ms());
            let _ = p.publish(&sample_data()).unwrap();
        }
        assert_eq!(actual, expected_ms);
    }

    #[test]
    fn time_allowed_to_live_override() {
        let mut p = sample_publisher();
        p.set_time_allowed_to_live(Some(500));
        assert_eq!(p.time_allowed_to_live_ms(), 500);
        p.set_time_allowed_to_live(None);
        assert_eq!(p.time_allowed_to_live_ms(), 8); // derived again from T1
    }

    #[test]
    fn publish_returns_bytes_with_correct_size() {
        let mut p = sample_publisher();
        let frame = p.publish(&sample_data()).unwrap();
        assert!(
            frame.len() > 22,
            "frame holds the 14 byte ethernet header, the 8 byte goose header, and a pdu"
        );
        let length = u16::from_be_bytes([frame[16], frame[17]]) as usize;
        assert_eq!(
            length,
            frame.len() - 14,
            "length covers the goose header and pdu"
        );
    }

    #[test]
    fn publish_and_dump_returns_bytes() {
        let mut p = sample_publisher();
        let frame = p.publish_and_dump(&sample_data()).unwrap();
        assert!(frame.len() > 22);
    }

    #[test]
    fn published_frame_decodes_back() {
        let mut p = sample_publisher();
        let frame = p.publish(&sample_data()).unwrap();

        let goose_frame = GooseFrame::decode(&frame).unwrap();
        let pdu = GoosePdu::decode_ber(&goose_frame.pdu_bytes).unwrap();
        assert_eq!(pdu.gocb_ref, "A/L$GO$gcb");
        assert_eq!(pdu.dat_set, "A/L$DS");
        // A None goID is sent as gocbRef.
        assert_eq!(pdu.go_id, Some("A/L$GO$gcb".to_string()));
        assert_eq!(pdu.st_num, 1);
        // The first frame carries sqNum 0.
        assert_eq!(pdu.sq_num, 0);
        assert!(!pdu.simulation);
        assert!(!pdu.nds_com);
        assert_eq!(pdu.conf_rev, 1);
        assert_eq!(pdu.num_dataset_entries, 1);
        assert_eq!(pdu.all_data, vec![MmsValue::Boolean(true)]);
        assert_eq!(pdu.time_allowed_to_live, 8);
    }

    #[test]
    fn simulation_flag_propagates_to_pdu() {
        let mut p = sample_publisher();
        p.set_simulation(true);
        let frame = p.publish(&sample_data()).unwrap();
        let goose_frame = GooseFrame::decode(&frame).unwrap();
        let pdu = GoosePdu::decode_ber(&goose_frame.pdu_bytes).unwrap();
        assert!(pdu.simulation);
    }

    #[test]
    fn needs_commission_propagates_to_pdu() {
        let mut p = sample_publisher();
        p.set_needs_commission(true);
        let frame = p.publish(&sample_data()).unwrap();
        let goose_frame = GooseFrame::decode(&frame).unwrap();
        let pdu = GoosePdu::decode_ber(&goose_frame.pdu_bytes).unwrap();
        assert!(pdu.nds_com);
    }

    #[test]
    fn go_id_some_overrides_gocb_ref() {
        let mut p = sample_publisher();
        p.set_go_id(Some("MyGoID".to_string()));
        let frame = p.publish(&sample_data()).unwrap();
        let goose_frame = GooseFrame::decode(&frame).unwrap();
        let pdu = GoosePdu::decode_ber(&goose_frame.pdu_bytes).unwrap();
        assert_eq!(pdu.go_id, Some("MyGoID".to_string()));
    }

    #[test]
    fn reject_payload_too_large() {
        let mut p = sample_publisher();
        // 200 entries of 100 bytes each overflow the 1518-byte frame.
        let huge_data: Vec<MmsValue> = (0..200)
            .map(|_| MmsValue::OctetString(vec![0xAA; 100]))
            .collect();
        let result = p.publish(&huge_data);
        assert!(
            matches!(result, Err(GooseError::PduOverflow)),
            "an oversized frame must return pduoverflow, got {:?}",
            result
        );
    }

    #[test]
    fn publish_100_times_st_num_and_sq_num_correct() {
        let mut p = sample_publisher();
        // The wire sequence runs 0 through 99.
        for expected_wire in 0u32..100 {
            let frame = p.publish(&sample_data()).unwrap();
            let pdu = GoosePdu::decode_ber(&GooseFrame::decode(&frame).unwrap().pdu_bytes).unwrap();
            assert_eq!(
                pdu.sq_num,
                expected_wire,
                "publication {1} carries wire sqnum {0}",
                expected_wire,
                expected_wire + 1
            );
            // The state holds what the next publication will encode.
            assert_eq!(p.sq_num(), expected_wire + 1);
            assert_eq!(p.st_num(), 1);
        }
    }

    #[test]
    fn publish_100_times_with_st_num_increases() {
        let mut p = sample_publisher();
        // Ten publications per state, then a state change.
        for round in 1..=10 {
            for _ in 0..10 {
                let _ = p.publish(&sample_data()).unwrap();
            }
            assert_eq!(p.st_num(), round);
            assert_eq!(p.sq_num(), 10);
            p.increase_st_num();
            assert_eq!(p.st_num(), round + 1);
            assert_eq!(p.sq_num(), 0);
        }
    }

    #[test]
    fn tick_returns_some_when_due() {
        let p = sample_publisher();
        let now = Instant::now();
        // Nothing published yet, so the first frame is due immediately.
        assert!(p.tick(now).is_some());
    }

    #[test]
    fn tick_returns_none_before_due() {
        let mut p = sample_publisher();
        let t0 = Instant::now();
        let _ = p.publish_at(&sample_data(), t0).unwrap();
        // The next publication is due at t0 + 4 ms.
        assert!(p.tick(t0 + Duration::from_millis(1)).is_none());
    }

    #[test]
    fn tick_returns_some_after_interval() {
        let mut p = sample_publisher();
        let t0 = Instant::now();
        let _ = p.publish_at(&sample_data(), t0).unwrap();
        // Due once T1 has elapsed.
        assert!(p.tick(t0 + Duration::from_millis(5)).is_some());
    }

    #[test]
    fn custom_retrans_intervals() {
        let mut p = sample_publisher();
        p.set_retrans_intervals(RetransIntervals {
            t1: Duration::from_millis(2),
            t2: Duration::from_millis(4),
            t3: Duration::from_millis(8),
            t4: Duration::from_millis(16),
            tmax: Duration::from_millis(500),
        });
        assert_eq!(p.time_allowed_to_live_ms(), 4); // twice T1
        let _ = p.publish(&sample_data()).unwrap();
        assert_eq!(p.time_allowed_to_live_ms(), 8); // twice T2
    }

    #[test]
    fn reset_clears_state() {
        let mut p = sample_publisher();
        for _ in 0..5 {
            let _ = p.publish(&sample_data()).unwrap();
        }
        p.increase_st_num();
        p.reset();
        assert_eq!(p.st_num(), 1);
        assert_eq!(p.sq_num(), 0);
        assert_eq!(p.phase(), RetransPhase::T1);
    }

    #[test]
    fn timestamp_propagates_to_pdu() {
        let mut p = sample_publisher();
        let ts = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        p.set_timestamp(ts);
        let frame = p.publish(&sample_data()).unwrap();
        let goose_frame = GooseFrame::decode(&frame).unwrap();
        let pdu = GoosePdu::decode_ber(&goose_frame.pdu_bytes).unwrap();
        assert_eq!(pdu.t, ts);
    }

    #[test]
    fn vlan_frame_has_vlan_tag_in_output() {
        let comm = sample_comm().with_vlan(VlanTag {
            priority: VlanPriority::new(4).unwrap(),
            vlan_id: 100,
        });
        let mut p = GoosePublisher::new(comm, "A/L$GO$gcb", None, "A/L$DS", 1).unwrap();
        let frame = p.publish(&sample_data()).unwrap();
        // The VLAN TPID sits at offset 12.
        assert_eq!(frame[12], 0x81);
        assert_eq!(frame[13], 0x00);
        // The EtherType follows the tag at offset 16.
        assert_eq!(u16::from_be_bytes([frame[16], frame[17]]), GOOSE_ETHER_TYPE);
    }

    #[test]
    fn ether_type_is_goose() {
        let mut p = sample_publisher();
        let frame = p.publish(&sample_data()).unwrap();
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), GOOSE_ETHER_TYPE);
    }

    #[test]
    fn comm_builder_chains() {
        let comm = CommParameters::new(0x1000, [0; 6])
            .with_vlan(VlanTag {
                priority: VlanPriority::new(2).unwrap(),
                vlan_id: 50,
            })
            .with_src_mac([1, 2, 3, 4, 5, 6])
            .with_priority(VlanPriority::new(7).unwrap());
        assert_eq!(comm.app_id, 0x1000);
        assert_eq!(comm.src_mac, Some([1, 2, 3, 4, 5, 6]));
        let v = comm.vlan.unwrap();
        assert_eq!(v.priority.value(), 7);
        assert_eq!(v.vlan_id, 50, "with_priority keeps the vlan id");
    }

    #[test]
    fn publish_action_carries_at() {
        let p = sample_publisher();
        let now = Instant::now();
        let action = p.tick(now).unwrap();
        assert!(action.at <= now);
    }
}

#[cfg(all(test, feature = "tokio-runtime"))]
mod tokio_tests {
    use super::tokio_helper::run_retrans_loop;
    use super::*;
    use tokio::sync::mpsc;
    use tokio::time::{timeout, Duration as TokioDuration};

    fn make_publisher() -> GoosePublisher {
        GoosePublisher::new(
            CommParameters::new(0x1000, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01]),
            "A/L$GO$gcb",
            None,
            "A/L$DS",
            1,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn run_retrans_loop_emits_frames() {
        let publisher = make_publisher();
        let (tx, mut rx) = mpsc::channel::<bytes::Bytes>(16);
        let (cancel_tx, cancel_rx) = mpsc::channel::<()>(1);

        let provider = || vec![MmsValue::Boolean(true)];

        let task = tokio::spawn(async move {
            run_retrans_loop(publisher, provider, tx, cancel_rx)
                .await
                .unwrap()
        });

        // The first frame plus one retransmission.
        let mut received = 0;
        for _ in 0..2 {
            match timeout(TokioDuration::from_secs(5), rx.recv()).await {
                Ok(Some(_)) => received += 1,
                _ => break,
            }
        }

        let _ = cancel_tx.send(()).await;
        let _ = timeout(TokioDuration::from_secs(5), task).await;

        assert!(
            received >= 2,
            "expected at least 2 frames, got {}",
            received
        );
    }
}
