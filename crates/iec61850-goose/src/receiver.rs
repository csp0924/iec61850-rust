//! GOOSE receiver: frame dispatch and subscriber management.
//!
//! A receiver owns the subscriptions and routes each frame to at most one of
//! them: an APPID lookup selects candidates, the frame-level filters narrow
//! them, and the decoded gocbRef picks the subscriber that is notified.
//!
//! The type parameter is a typestate. `GooseReceiver<Idle>` accepts
//! subscribers; `GooseReceiver<Running>` handles frames. The transition
//! consumes the receiver, so the subscriber list cannot be mutated while the
//! receive thread walks it.
//!
//! Decoding is strict: an unknown PDU member tag, a timestamp that is not 8
//! bytes, and an over-long object reference are all rejected, and every member
//! length is checked against the PDU bounds before the value is read. Frames
//! may be injected directly with `handle_message`, or read from an
//! `EthernetSource` by `start_thread`. Both paths also sweep the subscribers
//! for expired publications.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use iec61850_asn1::decode_length;
use iec61850_hal::ethernet::{EthernetError, EthernetSource};
use iec61850_model::MmsValue;

use crate::error::GooseError;
use crate::frame::GooseFrame;
use crate::pdu::GoosePdu;
use crate::subscriber::{GooseSubscriber, GooseSubscriberState, GOOSE_STRING_MAX_LEN};

/// Size of the receive buffer, the maximum untagged Ethernet frame.
const ETH_BUFFER_LENGTH: usize = 1518;

/// Typestate for a receiver that accepts subscribers but no frames.
pub struct Idle;

/// Typestate for a receiver that handles frames but accepts no subscribers.
pub struct Running;

/// GOOSE receive and dispatch point.
///
/// `GooseReceiver<Idle>` adds and removes subscribers; `GooseReceiver<Running>`
/// handles frames. Mutating the subscriber list of a running receiver is a
/// compile error rather than a documented hazard.
pub struct GooseReceiver<S = Idle> {
    /// Network interface name used when binding the L2 socket.
    interface_id: Option<String>,
    /// Owned receive buffer; no caller-supplied buffer is accepted.
    _buffer: Box<[u8; ETH_BUFFER_LENGTH]>,
    /// Subscribers by index; a removed slot becomes `None` so the indexes
    /// handed to callers stay valid.
    subscribers: Vec<Option<GooseSubscriber>>,
    /// APPID to subscriber indexes, for constant-time lookup per frame.
    appid_index: HashMap<u16, Vec<usize>>,
    /// Indexes of subscribers with no APPID filter.
    wildcard_indices: Vec<usize>,
    /// Typestate marker.
    _state: std::marker::PhantomData<S>,
}

impl GooseReceiver<Idle> {
    /// Creates an idle receiver with no subscribers.
    pub fn new() -> Self {
        Self {
            interface_id: None,
            _buffer: Box::new([0u8; ETH_BUFFER_LENGTH]),
            subscribers: Vec::new(),
            appid_index: HashMap::new(),
            wildcard_indices: Vec::new(),
            _state: std::marker::PhantomData,
        }
    }

    /// Sets the interface name used by `start_thread`.
    pub fn set_interface_id(&mut self, id: impl Into<String>) {
        self.interface_id = Some(id.into());
    }

    /// Returns the configured interface name.
    pub fn interface_id(&self) -> Option<&str> {
        self.interface_id.as_deref()
    }

    /// Adds a subscriber and returns its index, which `remove_subscriber` and
    /// `subscriber` take.
    pub fn add_subscriber(&mut self, sub: GooseSubscriber) -> usize {
        let idx = self.subscribers.len();
        match sub.app_id() {
            Some(id) => {
                self.appid_index.entry(id).or_default().push(idx);
            }
            None => {
                self.wildcard_indices.push(idx);
            }
        }
        self.subscribers.push(Some(sub));
        idx
    }

    /// Removes the subscriber at `idx`, returning whether one was there.
    pub fn remove_subscriber(&mut self, idx: usize) -> bool {
        if idx >= self.subscribers.len() {
            return false;
        }
        let Some(sub) = self.subscribers[idx].take() else {
            return false;
        };
        match sub.app_id() {
            Some(id) => {
                if let Some(list) = self.appid_index.get_mut(&id) {
                    list.retain(|&i| i != idx);
                }
            }
            None => {
                self.wildcard_indices.retain(|&i| i != idx);
            }
        }
        true
    }

    /// Moves the receiver to the running state. No socket is opened; frames
    /// arrive through `handle_message` or through `start_thread`.
    pub fn start(self) -> GooseReceiver<Running> {
        GooseReceiver {
            interface_id: self.interface_id,
            _buffer: self._buffer,
            subscribers: self.subscribers,
            appid_index: self.appid_index,
            wildcard_indices: self.wildcard_indices,
            _state: std::marker::PhantomData,
        }
    }
}

impl Default for GooseReceiver<Idle> {
    fn default() -> Self {
        Self::new()
    }
}

impl GooseReceiver<Running> {
    /// Returns the receiver to the idle state so subscribers can be changed.
    pub fn stop(self) -> GooseReceiver<Idle> {
        GooseReceiver {
            interface_id: self.interface_id,
            _buffer: self._buffer,
            subscribers: self.subscribers,
            appid_index: self.appid_index,
            wildcard_indices: self.wildcard_indices,
            _state: std::marker::PhantomData,
        }
    }

    /// Decodes one Ethernet frame and dispatches it to the matching
    /// subscriber, then sweeps every subscriber for an expired publication.
    ///
    /// A frame that fails to decode is logged and dropped; the receiver stays
    /// usable.
    pub fn handle_message(&mut self, buf: &[u8]) {
        match self.do_handle_message(buf) {
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("dropped goose frame that failed to decode: {}", e);
            }
        }
        self.check_all_expired();
    }

    /// Processes one polling step for a caller-driven receive loop.
    ///
    /// `Some(frame)` is handled like `handle_message`; `None` only sweeps for
    /// expired publications. Returns whether a non-empty frame was supplied.
    pub fn tick(&mut self, frame: Option<&[u8]>) -> bool {
        if let Some(buf) = frame {
            let had_data = !buf.is_empty();
            self.handle_message(buf);
            return had_data;
        }
        self.check_all_expired();
        false
    }

    /// Returns the subscriber at `idx`, for queries such as `is_valid`.
    pub fn subscriber(&self, idx: usize) -> Option<&GooseSubscriber> {
        self.subscribers.get(idx)?.as_ref()
    }

    fn do_handle_message(&mut self, buf: &[u8]) -> Result<(), GooseError> {
        let frame = GooseFrame::decode(buf)?;
        let hdr = &frame.header;
        let app_id = hdr.app_id;
        let dst_mac = hdr.dst_mac;
        let src_mac = hdr.src_mac;
        let vlan = hdr.vlan;

        // At most one subscriber is notified per frame, the first that matches.
        let first_match_idx = self.find_first_frame_match(app_id, &dst_mac);

        let Some(first_idx) = first_match_idx else {
            return Ok(());
        };

        let pdu_result = parse_goose_payload(&frame.pdu_bytes);

        match pdu_result {
            Err(e) => {
                tracing::warn!("goose pdu decode failed for appid 0x{:04x}: {}", app_id, e);
                return Err(e);
            }
            Ok(parsed) => {
                let gocb_ref = &parsed.gocb_ref;

                // The gocbRef may select a different subscriber than the
                // frame-level filters did.
                let pdu_match_idx = self.find_first_pdu_match(first_idx, gocb_ref);

                let Some(match_idx) = pdu_match_idx else {
                    return Ok(());
                };

                let state = GooseSubscriberState {
                    gocb_ref: parsed.gocb_ref.clone(),
                    dat_set: parsed.dat_set.clone(),
                    go_id: parsed.go_id.clone(),
                    time_allowed_to_live_ms: parsed.time_allowed_to_live,
                    st_num: parsed.st_num,
                    sq_num: parsed.sq_num,
                    conf_rev: parsed.conf_rev,
                    timestamp_raw: parsed.timestamp_raw,
                    simulation: parsed.simulation,
                    nds_com: parsed.nds_com,
                    dataset_values: parsed.dataset_values,
                    src_mac,
                    dst_mac,
                    vlan,
                    received_at: Instant::now(),
                    state_valid: true,
                };

                if let Some(Some(sub)) = self.subscribers.get_mut(match_idx) {
                    sub.update_and_dispatch(state);
                }
            }
        }

        Ok(())
    }

    /// Returns the first subscriber index whose frame-level filters accept
    /// this APPID and destination MAC, checking exact APPID matches before
    /// subscribers with no APPID filter.
    fn find_first_frame_match(&self, app_id: u16, dst_mac: &[u8; 6]) -> Option<usize> {
        if let Some(indices) = self.appid_index.get(&app_id) {
            for &idx in indices {
                if let Some(Some(sub)) = self.subscribers.get(idx) {
                    if sub.matches_frame(app_id, dst_mac) {
                        return Some(idx);
                    }
                }
            }
        }
        for &idx in &self.wildcard_indices {
            if let Some(Some(sub)) = self.subscribers.get(idx) {
                if sub.matches_frame(app_id, dst_mac) {
                    return Some(idx);
                }
            }
        }
        None
    }

    /// Returns the first subscriber index accepting `gocb_ref`, trying
    /// `first_idx` before scanning the rest in order.
    fn find_first_pdu_match(&self, first_idx: usize, gocb_ref: &str) -> Option<usize> {
        if let Some(Some(sub)) = self.subscribers.get(first_idx) {
            if sub.matches_gocb_ref(gocb_ref) {
                return Some(first_idx);
            }
        }
        for (idx, slot) in self.subscribers.iter().enumerate() {
            if idx == first_idx {
                continue;
            }
            if let Some(sub) = slot {
                if sub.matches_gocb_ref(gocb_ref) {
                    return Some(idx);
                }
            }
        }
        None
    }

    /// Raises the expiry event on every subscriber whose publication has
    /// outlived its timeAllowedToLive.
    fn check_all_expired(&mut self) {
        for sub in self.subscribers.iter_mut().flatten() {
            sub.check_expired();
        }
    }
}

/// Handle to a receiver running on its own thread.
///
/// Dropping the handle stops the thread and joins it.
pub struct GooseReceiverHandle {
    join: Option<JoinHandle<()>>,
    running: Arc<AtomicBool>,
}

impl GooseReceiverHandle {
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

impl Drop for GooseReceiverHandle {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        if let Some(h) = self.join.take() {
            let _ = h.join();
        }
    }
}

impl GooseReceiver<Idle> {
    /// Starts a thread that reads frames from `source` and dispatches them.
    ///
    /// `source` must be an already opened L2 socket; joining the GOOSE
    /// multicast group is the caller's responsibility when opening it. The loop
    /// receives with a 100 ms timeout so that a quiet link still sweeps for
    /// expired publications and observes the stop flag. A receive error other
    /// than a timeout is logged and the loop continues.
    ///
    /// # Panics
    ///
    /// Panics if the receive thread cannot be spawned.
    pub fn start_thread(self, mut source: Box<dyn EthernetSource>) -> GooseReceiverHandle {
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();
        let mut rx_running = self.start();

        let join = thread::Builder::new()
            .name("goose-receiver".into())
            .spawn(move || {
                let mut buf = vec![0u8; ETH_BUFFER_LENGTH];
                while running_clone.load(Ordering::Acquire) {
                    match source.recv(&mut buf, Some(Duration::from_millis(100))) {
                        Ok(0) => {
                            rx_running.tick(None);
                        }
                        Ok(n) => {
                            rx_running.handle_message(&buf[..n]);
                        }
                        Err(EthernetError::Timeout) => {
                            rx_running.tick(None);
                        }
                        Err(e) => {
                            tracing::warn!("goose receiver recv error, continuing: {}", e);
                        }
                    }
                }
            })
            .expect("spawn goose-receiver thread");

        GooseReceiverHandle {
            join: Some(join),
            running,
        }
    }
}

/// Fields decoded from a GOOSE PDU before they are turned into a subscriber
/// state snapshot.
#[derive(Debug)]
struct ParsedGoosePdu {
    gocb_ref: String,
    dat_set: String,
    go_id: String,
    time_allowed_to_live: u32,
    st_num: u32,
    sq_num: u32,
    conf_rev: u32,
    timestamp_raw: [u8; 8],
    simulation: bool,
    nds_com: bool,
    dataset_values: Vec<MmsValue>,
}

/// Decodes a GOOSE PDU starting at the outer `0x61` tag.
///
/// The cursor checks `pos + element_length <= end`
/// before every member, so a length field that overstates the payload is
/// rejected instead of read past.
///
/// # Errors
///
/// - `TagDecode` when the outer tag is not `0x61`.
/// - `TruncatedInput` when a member reaches past the PDU.
/// - `FieldTooLong` when gocbRef, datSet, or goID exceeds 129 bytes.
/// - `TimestampBadLength` when the timestamp is not 8 bytes.
/// - `UnknownTag` for any member tag not defined for the PDU.
fn parse_goose_payload(buf: &[u8]) -> Result<ParsedGoosePdu, GooseError> {
    let total = buf.len();
    if total < 2 {
        return Err(GooseError::TruncatedInput {
            needed: 2,
            available: total,
        });
    }

    if buf[0] != 0x61 {
        tracing::warn!("goose pdu outer tag is 0x{:02x}, expected 0x61", buf[0]);
        return Err(GooseError::TagDecode);
    }

    let (goose_length, mut pos) = {
        let mut tmp_pos = 1usize;
        let (len, consumed) = decode_length(&buf[tmp_pos..])?;
        tmp_pos += consumed;
        (len, tmp_pos)
    };

    // The declared PDU length must fit the buffer.
    let end = pos
        .checked_add(goose_length)
        .ok_or(GooseError::TruncatedInput {
            needed: pos + goose_length,
            available: total,
        })?;
    if end > total {
        return Err(GooseError::TruncatedInput {
            needed: end,
            available: total,
        });
    }

    let mut gocb_ref = String::new();
    let mut dat_set = String::new();
    let mut go_id = String::new();
    let mut time_allowed_to_live = 0u32;
    let mut st_num = 0u32;
    let mut sq_num = 0u32;
    let mut conf_rev = 0u32;
    let mut timestamp_raw = [0u8; 8];
    let mut has_timestamp = false;
    let mut simulation = false;
    let mut nds_com = false;
    let mut _num_dataset_entries = 0u32;
    let mut all_data_pos: Option<(usize, usize)> = None;

    while pos < end {
        // A member needs at least a tag and one length byte.
        if pos + 2 > end {
            break;
        }
        let tag = buf[pos];
        pos += 1;

        let (element_length, consumed) = decode_length(&buf[pos..])?;
        pos += consumed;

        if pos + element_length > end {
            tracing::warn!(
                "goose pdu tag 0x{:02x} element length {} reaches past the pdu",
                tag,
                element_length
            );
            return Err(GooseError::TruncatedInput {
                needed: pos + element_length,
                available: end,
            });
        }

        let val_start = pos;
        pos += element_length;

        match tag {
            0x80 => {
                if element_length > GOOSE_STRING_MAX_LEN {
                    tracing::warn!(
                        "goose gocbref length {} exceeds the {} byte limit",
                        element_length,
                        GOOSE_STRING_MAX_LEN
                    );
                    return Err(GooseError::FieldTooLong(element_length));
                }
                gocb_ref = parse_ia5string(&buf[val_start..val_start + element_length])?;
            }
            0x81 => {
                time_allowed_to_live = decode_uint32(&buf[val_start..val_start + element_length])?;
            }
            0x82 => {
                if element_length > GOOSE_STRING_MAX_LEN {
                    tracing::warn!(
                        "goose datset length {} exceeds the {} byte limit",
                        element_length,
                        GOOSE_STRING_MAX_LEN
                    );
                    return Err(GooseError::FieldTooLong(element_length));
                }
                dat_set = parse_ia5string(&buf[val_start..val_start + element_length])?;
            }
            0x83 => {
                if element_length > GOOSE_STRING_MAX_LEN {
                    tracing::warn!(
                        "goose goid length {} exceeds the {} byte limit",
                        element_length,
                        GOOSE_STRING_MAX_LEN
                    );
                    return Err(GooseError::FieldTooLong(element_length));
                }
                go_id = parse_ia5string(&buf[val_start..val_start + element_length])?;
            }
            0x84 => {
                if element_length != 8 {
                    tracing::warn!(
                        "goose timestamp field is {} bytes, expected 8",
                        element_length
                    );
                    return Err(GooseError::TimestampBadLength(element_length));
                }
                timestamp_raw.copy_from_slice(&buf[val_start..val_start + 8]);
                has_timestamp = true;
            }
            0x85 => {
                st_num = decode_uint32(&buf[val_start..val_start + element_length])?;
            }
            0x86 => {
                sq_num = decode_uint32(&buf[val_start..val_start + element_length])?;
            }
            0x87 => {
                if element_length < 1 {
                    return Err(GooseError::LengthMismatch);
                }
                simulation = buf[val_start] != 0x00;
            }
            0x88 => {
                conf_rev = decode_uint32(&buf[val_start..val_start + element_length])?;
            }
            0x89 => {
                if element_length < 1 {
                    return Err(GooseError::LengthMismatch);
                }
                nds_com = buf[val_start] != 0x00;
            }
            0x8a => {
                _num_dataset_entries = decode_uint32(&buf[val_start..val_start + element_length])?;
            }
            0xab => {
                // Decoded after the loop, once the whole member is bounded.
                all_data_pos = Some((val_start, element_length));
            }
            other => {
                tracing::warn!("goose pdu rejected unknown tag 0x{:02x}", other);
                return Err(GooseError::UnknownTag(other));
            }
        }
    }

    // A publication without tag 0x84 is reported and its timestamp stays zero.
    if !has_timestamp {
        tracing::warn!(
            "goose pdu gocbref={:?} has no timestamp field, using zero",
            gocb_ref
        );
    }

    let dataset_values = if let Some((start, length)) = all_data_pos {
        decode_all_data(&buf[start..start + length])?
    } else {
        Vec::new()
    };

    Ok(ParsedGoosePdu {
        gocb_ref,
        dat_set,
        go_id,
        time_allowed_to_live,
        st_num,
        sq_num,
        conf_rev,
        timestamp_raw,
        simulation,
        nds_com,
        dataset_values,
    })
}

/// Decodes an IA5String field.
///
/// # Errors
///
/// Returns `FieldTooLong` when the bytes are not valid UTF-8.
fn parse_ia5string(bytes: &[u8]) -> Result<String, GooseError> {
    // IA5String is an ASCII subset, so UTF-8 validation accepts it.
    std::str::from_utf8(bytes)
        .map(|s| s.to_string())
        .map_err(|_| GooseError::FieldTooLong(bytes.len()))
}

/// Decodes an unsigned integer of at most 4 BER content bytes.
///
/// # Errors
///
/// Returns `LengthMismatch` when the field is empty or wider than 4 bytes.
fn decode_uint32(bytes: &[u8]) -> Result<u32, GooseError> {
    if bytes.is_empty() || bytes.len() > 4 {
        return Err(GooseError::LengthMismatch);
    }
    let mut val = 0u32;
    for &b in bytes {
        val = (val << 8) | (b as u32);
    }
    Ok(val)
}

/// Decodes the content bytes of the allData member.
fn decode_all_data(bytes: &[u8]) -> Result<Vec<MmsValue>, GooseError> {
    decode_data_sequence(bytes)
}

/// Decodes the SEQUENCE OF Data inside allData.
fn decode_data_sequence(bytes: &[u8]) -> Result<Vec<MmsValue>, GooseError> {
    crate::pdu::decode_all_data_bytes(bytes)
}

/// Decodes a complete Ethernet frame into a `GoosePdu`.
///
/// Equivalent to `GooseFrame::decode` followed by `GoosePdu::decode_ber`.
///
/// # Errors
///
/// Returns any frame-layer or PDU-layer decode error.
pub fn parse_frame_to_pdu(buf: &[u8]) -> Result<GoosePdu, GooseError> {
    let frame = GooseFrame::decode(buf)?;
    GoosePdu::decode_ber(&frame.pdu_bytes)
}

/// A receiver shared between threads.
///
/// Contention on this lock lands in the receive path; a single-threaded
/// `tick` loop that forwards decoded events over a channel avoids it.
pub type SharedReceiver = Arc<Mutex<GooseReceiver<Running>>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{GooseFrameHeader, VlanPriority, VlanTag};
    use crate::pdu::GoosePdu;
    use crate::publisher::{CommParameters, GoosePublisher};
    use crate::subscriber::GooseSubscriberBuilder;
    use bytes::BytesMut;
    use iec61850_model::MmsValue;
    use std::sync::{Arc, Mutex};

    /// Encodes a PDU to owned bytes.
    fn encode_pdu_to_vec(pdu: &GoosePdu) -> Vec<u8> {
        let mut buf = BytesMut::new();
        pdu.encode_ber(&mut buf).unwrap();
        buf.to_vec()
    }

    /// Wraps encoded PDU bytes in a GOOSE frame with the given APPID and
    /// destination MAC.
    fn encode_frame_with_pdu(pdu: &GoosePdu, app_id: u16, dst_mac: [u8; 6]) -> Vec<u8> {
        let pdu_bytes = encode_pdu_to_vec(pdu);
        let header = GooseFrameHeader {
            dst_mac,
            src_mac: [0x00, 0x50, 0xC2, 0x12, 0x34, 0x56],
            vlan: None,
            app_id,
            length: 0,
        };
        let frame = GooseFrame::new(header, pdu_bytes);
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        buf.to_vec()
    }

    fn make_pdu(gocb_ref: &str, st_num: u32, sq_num: u32, conf_rev: u32) -> GoosePdu {
        GoosePdu {
            gocb_ref: gocb_ref.to_string(),
            time_allowed_to_live: 2000,
            dat_set: format!(
                "{}/LLN0$GO$gcbData",
                gocb_ref.split('/').next().unwrap_or("IED")
            ),
            go_id: Some(gocb_ref.to_string()),
            t: [0u8; 8],
            st_num,
            sq_num,
            simulation: false,
            conf_rev,
            nds_com: false,
            num_dataset_entries: 1,
            all_data: vec![MmsValue::Boolean(true)],
        }
    }

    #[test]
    fn happy_path_subscriber_receives_callback() {
        let events: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(vec![]));
        let ev_clone = events.clone();

        let sub = GooseSubscriberBuilder::new()
            .gocb_ref("IED1/LLN0$GO$gcb")
            .app_id(0x0001)
            .listener(move |e| {
                if let crate::subscriber::GooseEvent::NewState { state, .. } = e {
                    ev_clone.lock().unwrap().push(state.st_num);
                }
            })
            .build();

        let pdu = make_pdu("IED1/LLN0$GO$gcb", 1, 0, 1);
        let frame_bytes = encode_frame_with_pdu(&pdu, 0x0001, [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01]);

        let mut rx = GooseReceiver::new();
        rx.add_subscriber(sub);
        let mut running = rx.start();
        running.handle_message(&frame_bytes);

        assert_eq!(*events.lock().unwrap(), vec![1u32]);
    }

    #[test]
    fn happy_path_two_frames_st_num_sequence() {
        let st_nums: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(vec![]));
        let clone = st_nums.clone();

        let sub = GooseSubscriberBuilder::new()
            .gocb_ref("IED1/LLN0$GO$gcb")
            .listener(move |e| match e {
                crate::subscriber::GooseEvent::NewState { state, .. } => {
                    clone.lock().unwrap().push(state.st_num);
                }
                crate::subscriber::GooseEvent::Retransmission { state, .. } => {
                    clone.lock().unwrap().push(state.st_num);
                }
                _ => {}
            })
            .build();

        let mut rx = GooseReceiver::new();
        rx.add_subscriber(sub);
        let mut running = rx.start();

        let frame1 =
            encode_frame_with_pdu(&make_pdu("IED1/LLN0$GO$gcb", 1, 0, 1), 0x0001, [0u8; 6]);
        let frame2 =
            encode_frame_with_pdu(&make_pdu("IED1/LLN0$GO$gcb", 1, 1, 1), 0x0001, [0u8; 6]);

        running.handle_message(&frame1);
        running.handle_message(&frame2);

        assert_eq!(*st_nums.lock().unwrap(), vec![1u32, 1u32]);
    }

    #[test]
    fn appid_filter_rejects_wrong_appid() {
        let called: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
        let clone = called.clone();

        let sub = GooseSubscriberBuilder::new()
            .gocb_ref("IED1/LLN0$GO$gcb")
            .app_id(0x0001)
            .listener(move |_| {
                *clone.lock().unwrap() = true;
            })
            .build();

        let mut rx = GooseReceiver::new();
        rx.add_subscriber(sub);
        let mut running = rx.start();

        // The subscriber filters on APPID 0x0001.
        let frame = encode_frame_with_pdu(&make_pdu("IED1/LLN0$GO$gcb", 1, 0, 1), 0x0002, [0u8; 6]);
        running.handle_message(&frame);

        assert!(
            !*called.lock().unwrap(),
            "a non-matching appid is not dispatched"
        );
    }

    #[test]
    fn dst_mac_filter_rejects_wrong_mac() {
        let called: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
        let clone = called.clone();

        let mac_filter = [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01];
        let mac_wrong = [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x02];

        let sub = GooseSubscriberBuilder::new()
            .gocb_ref("IED1/LLN0$GO$gcb")
            .dst_mac(mac_filter)
            .listener(move |_| {
                *clone.lock().unwrap() = true;
            })
            .build();

        let mut rx = GooseReceiver::new();
        rx.add_subscriber(sub);
        let mut running = rx.start();

        let frame =
            encode_frame_with_pdu(&make_pdu("IED1/LLN0$GO$gcb", 1, 0, 1), 0x0001, mac_wrong);
        running.handle_message(&frame);

        assert!(
            !*called.lock().unwrap(),
            "a non-matching dst mac is not dispatched"
        );
    }

    #[test]
    fn dst_mac_filter_accepts_matching_mac() {
        let called: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
        let clone = called.clone();

        let mac = [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01];

        let sub = GooseSubscriberBuilder::new()
            .gocb_ref("IED1/LLN0$GO$gcb")
            .dst_mac(mac)
            .listener(move |_| {
                *clone.lock().unwrap() = true;
            })
            .build();

        let mut rx = GooseReceiver::new();
        rx.add_subscriber(sub);
        let mut running = rx.start();

        let frame = encode_frame_with_pdu(&make_pdu("IED1/LLN0$GO$gcb", 1, 0, 1), 0x0001, mac);
        running.handle_message(&frame);

        assert!(*called.lock().unwrap(), "a matching dst mac is dispatched");
    }

    #[test]
    fn gocb_ref_mismatch_does_not_trigger_callback() {
        let called: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
        let clone = called.clone();

        let sub = GooseSubscriberBuilder::new()
            .gocb_ref("IED1/LLN0$GO$gcbOther")
            .listener(move |_| {
                *clone.lock().unwrap() = true;
            })
            .build();

        let mut rx = GooseReceiver::new();
        rx.add_subscriber(sub);
        let mut running = rx.start();

        // The frame carries a different gocbRef than the subscription.
        let frame = encode_frame_with_pdu(&make_pdu("IED1/LLN0$GO$gcb", 1, 0, 1), 0x0001, [0u8; 6]);
        running.handle_message(&frame);

        assert!(
            !*called.lock().unwrap(),
            "a non-matching gocbref is not dispatched"
        );
    }

    #[test]
    fn observer_receives_any_gocb_ref() {
        let refs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
        let clone = refs.clone();

        let sub = GooseSubscriberBuilder::new()
            .observer()
            .listener(move |e| {
                if let crate::subscriber::GooseEvent::NewState { state, .. }
                | crate::subscriber::GooseEvent::Retransmission { state, .. } = e
                {
                    clone.lock().unwrap().push(state.gocb_ref.clone());
                }
            })
            .build();

        let mut rx = GooseReceiver::new();
        rx.add_subscriber(sub);
        let mut running = rx.start();

        let frame1 =
            encode_frame_with_pdu(&make_pdu("IED1/LLN0$GO$gcbA", 1, 0, 1), 0x0001, [0u8; 6]);
        let frame2 =
            encode_frame_with_pdu(&make_pdu("IED2/LLN0$GO$gcbB", 1, 0, 1), 0x0002, [0u8; 6]);

        running.handle_message(&frame1);
        running.handle_message(&frame2);

        let r = refs.lock().unwrap();
        assert!(r.contains(&"IED1/LLN0$GO$gcbA".to_string()));
        assert!(r.contains(&"IED2/LLN0$GO$gcbB".to_string()));
    }

    #[test]
    fn st_num_rollback_sets_invalid_and_warns() {
        let valid_flags: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(vec![]));
        let clone = valid_flags.clone();

        let sub = GooseSubscriberBuilder::new()
            .gocb_ref("IED1/LLN0$GO$gcb")
            .listener(move |e| {
                let v = match &e {
                    crate::subscriber::GooseEvent::NewState { state, .. } => state.state_valid,
                    crate::subscriber::GooseEvent::Retransmission { state, .. } => {
                        state.state_valid
                    }
                    crate::subscriber::GooseEvent::Expired { last_state } => last_state.state_valid,
                };
                clone.lock().unwrap().push(v);
            })
            .build();

        let mut rx = GooseReceiver::new();
        rx.add_subscriber(sub);
        let mut running = rx.start();

        let f1 = encode_frame_with_pdu(&make_pdu("IED1/LLN0$GO$gcb", 5, 0, 1), 0x0001, [0u8; 6]);
        // The second frame carries a lower stNum.
        let f2 = encode_frame_with_pdu(&make_pdu("IED1/LLN0$GO$gcb", 4, 0, 1), 0x0001, [0u8; 6]);

        running.handle_message(&f1);
        running.handle_message(&f2);

        let flags = valid_flags.lock().unwrap();
        assert!(flags[0], "the first publication is valid");
        assert!(!flags[1], "a lower stnum is invalid");
    }

    #[test]
    fn tatl_expired_triggers_callback() {
        let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
        let clone = events.clone();

        let sub = GooseSubscriberBuilder::new()
            .gocb_ref("IED1/LLN0$GO$gcb")
            .listener(move |e| {
                let tag = match &e {
                    crate::subscriber::GooseEvent::NewState { .. } => "new",
                    crate::subscriber::GooseEvent::Retransmission { .. } => "retx",
                    crate::subscriber::GooseEvent::Expired { .. } => "exp",
                };
                clone.lock().unwrap().push(tag.to_string());
            })
            .build();

        let mut rx = GooseReceiver::new();
        rx.add_subscriber(sub);
        let mut running = rx.start();

        // A publication that lives for 1 ms.
        let mut pdu = make_pdu("IED1/LLN0$GO$gcb", 1, 0, 1);
        pdu.time_allowed_to_live = 1;
        let frame = encode_frame_with_pdu(&pdu, 0x0001, [0u8; 6]);

        running.handle_message(&frame);

        std::thread::sleep(std::time::Duration::from_millis(50));

        running.tick(None);

        let ev = events.lock().unwrap();
        assert!(ev.contains(&"new".to_string()), "newstate was raised");
        assert!(ev.contains(&"exp".to_string()), "expired was raised");
    }

    #[test]
    fn conf_rev_mismatch_parse_result_is_err() {
        let results: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(vec![]));
        let clone = results.clone();

        let sub = GooseSubscriberBuilder::new()
            .gocb_ref("IED1/LLN0$GO$gcb")
            .listener(move |e| {
                let is_err = match e {
                    crate::subscriber::GooseEvent::NewState { parse_result, .. } => {
                        parse_result.is_err()
                    }
                    crate::subscriber::GooseEvent::Retransmission { parse_result, .. } => {
                        parse_result.is_err()
                    }
                    _ => false,
                };
                clone.lock().unwrap().push(is_err);
            })
            .build();

        let mut rx = GooseReceiver::new();
        rx.add_subscriber(sub);
        let mut running = rx.start();

        let f1 = encode_frame_with_pdu(&make_pdu("IED1/LLN0$GO$gcb", 1, 0, 1), 0x0001, [0u8; 6]);
        // The second frame announces a different confRev.
        let f2 = encode_frame_with_pdu(&make_pdu("IED1/LLN0$GO$gcb", 2, 0, 2), 0x0001, [0u8; 6]);

        running.handle_message(&f1);
        running.handle_message(&f2);

        let r = results.lock().unwrap();
        assert!(!r[0], "the first confrev sets the baseline");
        assert!(r[1], "a changed confrev reports an error");
    }

    /// A member length that reaches past the PDU is
    /// rejected without reading past the buffer.
    #[test]
    fn malformed_element_length_returns_err() {
        let pdu = make_pdu("IED1/LLN0$GO$gcb", 1, 0, 1);
        let mut pdu_bytes = encode_pdu_to_vec(&pdu);

        // Keep the outer length and overstate the numDatSetEntries member.
        if let Some(pos) = pdu_bytes.iter().position(|&b| b == 0x8a) {
            if pos + 1 < pdu_bytes.len() {
                pdu_bytes[pos + 1] = 0x7e;
            }
        }

        let header = crate::frame::GooseFrameHeader {
            dst_mac: [0u8; 6],
            src_mac: [0u8; 6],
            vlan: None,
            app_id: 0x0001,
            length: 0,
        };
        let frame = GooseFrame::new(header, pdu_bytes);
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        let frame_bytes = buf.to_vec();

        // Skip the 14 Ethernet and 8 GOOSE header bytes.
        let result = parse_goose_payload(&frame_bytes[22..]);
        assert!(
            result.is_err(),
            "an out-of-bounds element length returns err without panicking"
        );
    }

    #[test]
    fn gocb_ref_too_long_returns_err() {
        // Assembled by hand because the encoder would reject the field first.
        let long_ref = "A".repeat(130);
        let mut inner = Vec::new();
        inner.push(0x80u8); // gocbRef tag
                            // Long-form length: 0x81 announces one length byte.
        inner.push(0x81u8);
        inner.push(130u8);
        inner.extend_from_slice(long_ref.as_bytes());

        let mut buf = Vec::new();
        buf.push(0x61u8); // IECGoosePdu
        let olen = inner.len();
        if olen <= 127 {
            buf.push(olen as u8);
        } else {
            buf.push(0x81u8);
            buf.push(olen as u8);
        }
        buf.extend_from_slice(&inner);

        let result = parse_goose_payload(&buf);
        assert!(
            matches!(result, Err(GooseError::FieldTooLong(130))),
            "an over-long gocbref returns fieldtoolong, got {:?}",
            result
        );
    }

    #[test]
    fn truncated_ethernet_frame_returns_err() {
        let short = [0x01u8; 10];
        let result = GooseFrame::decode(&short);
        assert!(
            matches!(result, Err(GooseError::EthernetFrameTooShort)),
            "a frame under 14 bytes returns ethernetframetooshort"
        );
    }

    #[test]
    fn vlan_priority_decode_corrected() {
        // Priority 5 encodes as TCI[0] = 0xA0 and must decode from bits 7:5.
        let pdu = make_pdu("IED1/LLN0$GO$gcb", 1, 0, 1);
        let pdu_bytes = encode_pdu_to_vec(&pdu);

        let priority = VlanPriority::new(5).unwrap();
        let header = crate::frame::GooseFrameHeader {
            dst_mac: [0u8; 6],
            src_mac: [0u8; 6],
            vlan: Some(VlanTag {
                priority,
                vlan_id: 100,
            }),
            app_id: 0x0001,
            length: 0,
        };
        let frame_obj = GooseFrame::new(header, pdu_bytes);
        let mut buf = BytesMut::new();
        frame_obj.encode(&mut buf).unwrap();

        let decoded = GooseFrame::decode(&buf).unwrap();
        let vlan = decoded.header.vlan.unwrap();
        assert_eq!(
            vlan.priority.value(),
            5,
            "vlan priority decodes from the top three bits of tci[0]"
        );
    }

    #[test]
    fn round_trip_publisher_to_subscriber_decode() {
        let received: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(vec![]));
        let clone = received.clone();

        let sub = GooseSubscriberBuilder::new()
            .gocb_ref("IED1/LLN0$GO$gcb")
            .app_id(0x0001)
            .listener(move |e| {
                if let crate::subscriber::GooseEvent::NewState { state, .. } = e {
                    clone.lock().unwrap().push(state.st_num);
                }
            })
            .build();

        let mut rx = GooseReceiver::new();
        rx.add_subscriber(sub);
        let mut running = rx.start();

        let comm = CommParameters::new(0x0001, [0u8; 6])
            .with_src_mac([0x00, 0x50, 0xC2, 0x12, 0x34, 0x56]);
        let mut pub_ = GoosePublisher::new(
            comm,
            "IED1/LLN0$GO$gcb",
            Some("IED1/LLN0$GO$gcb".to_string()),
            "IED1/LLN0$GO$gcbData",
            1,
        )
        .unwrap();

        let data = vec![MmsValue::Boolean(true), MmsValue::Unsigned(42)];
        let frame_bytes = pub_.publish(&data).unwrap();

        running.handle_message(&frame_bytes);

        assert_eq!(*received.lock().unwrap(), vec![1u32]);
    }

    #[test]
    fn typestate_idle_can_add_subscriber() {
        let mut rx = GooseReceiver::new();
        let sub = GooseSubscriber::new("IED1/LLN0$GO$gcb");
        let idx = rx.add_subscriber(sub);
        assert_eq!(idx, 0);
    }

    #[test]
    fn typestate_running_can_handle_message() {
        let rx = GooseReceiver::new();
        let mut running = rx.start();
        // An empty frame is logged and dropped rather than panicking.
        running.handle_message(&[]);
    }

    #[test]
    fn known_hex_vector_from_pdu_encode_decode() {
        let pdu = GoosePdu {
            gocb_ref: "IED1/LLN0$GO$gcbEvents".to_string(),
            time_allowed_to_live: 2000,
            dat_set: "IED1/LLN0$GO$gcbEvents".to_string(),
            go_id: Some("gcbEvents".to_string()),
            t: [0x5A, 0x3B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            st_num: 1,
            sq_num: 0,
            simulation: false,
            conf_rev: 1,
            nds_com: false,
            num_dataset_entries: 1,
            all_data: vec![MmsValue::Boolean(false)],
        };

        let pdu_bytes = encode_pdu_to_vec(&pdu);
        let frame_bytes = {
            let header = crate::frame::GooseFrameHeader {
                dst_mac: [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01],
                src_mac: [0x00, 0x50, 0xC2, 0x12, 0x34, 0x56],
                vlan: None,
                app_id: 0x0001,
                length: 0,
            };
            let frame = GooseFrame::new(header, pdu_bytes.clone());
            let mut buf = BytesMut::new();
            frame.encode(&mut buf).unwrap();
            buf.to_vec()
        };

        let received: Arc<Mutex<Option<GoosePdu>>> = Arc::new(Mutex::new(None));
        let clone = received.clone();
        let sub = GooseSubscriberBuilder::new()
            .gocb_ref("IED1/LLN0$GO$gcbEvents")
            .listener(move |e| {
                if let crate::subscriber::GooseEvent::NewState { state, .. } = e {
                    assert_eq!(state.st_num, 1);
                    assert_eq!(state.sq_num, 0);
                    assert_eq!(state.conf_rev, 1);
                    *clone.lock().unwrap() = Some(GoosePdu {
                        gocb_ref: state.gocb_ref.clone(),
                        time_allowed_to_live: state.time_allowed_to_live_ms,
                        dat_set: state.dat_set.clone(),
                        go_id: Some(state.go_id.clone()),
                        t: state.timestamp_raw,
                        st_num: state.st_num,
                        sq_num: state.sq_num,
                        simulation: state.simulation,
                        conf_rev: state.conf_rev,
                        nds_com: state.nds_com,
                        num_dataset_entries: state.dataset_values.len() as u32,
                        all_data: state.dataset_values.clone(),
                    });
                }
            })
            .build();

        let mut rx = GooseReceiver::new();
        rx.add_subscriber(sub);
        let mut running = rx.start();
        running.handle_message(&frame_bytes);

        let got = received.lock().unwrap();
        assert!(got.is_some(), "the pdu reached the subscriber");
        let decoded = got.as_ref().unwrap();
        assert_eq!(decoded.gocb_ref, pdu.gocb_ref);
        assert_eq!(decoded.st_num, pdu.st_num);
        assert_eq!(decoded.sq_num, pdu.sq_num);
        assert_eq!(decoded.all_data, pdu.all_data);
    }

    #[test]
    fn start_thread_with_hal_source_drop_joins() {
        use iec61850_hal::ethernet::{EthernetError, EthernetSource};
        use std::time::Duration;

        struct MockSource;
        impl EthernetSource for MockSource {
            fn recv(
                &mut self,
                _buf: &mut [u8],
                _timeout: Option<Duration>,
            ) -> Result<usize, EthernetError> {
                // Always time out, so the loop sweeps and rechecks the flag.
                Err(EthernetError::Timeout)
            }
        }

        let rx = GooseReceiver::new();
        let handle = rx.start_thread(Box::new(MockSource));
        assert!(handle.is_running());
        handle.stop_and_join();
    }
}
