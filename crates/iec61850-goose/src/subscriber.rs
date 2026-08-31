//! GOOSE subscriber: subscription filters, per-GoCB state, and event dispatch.
//!
//! A `GooseSubscriber` is a passive container. The receiver matches an incoming
//! frame against its APPID, destination MAC, and gocbRef filters, then hands it
//! the decoded PDU; the subscriber tracks stNum and sqNum and calls the
//! listener with a `GooseEvent`.
//!
//! Each event carries an owned `Arc<GooseSubscriberState>` snapshot rather than
//! a borrow of subscriber internals, so a listener may keep or move it. State
//! anomalies are reported, never hidden: an stNum that moves backwards or a
//! repeated sqNum clears `state_valid`, a confRev change is delivered as
//! `Err(ConfRevMismatch)` alongside the state, and expiry of
//! `timeAllowedToLive` raises `Expired` from `check_expired`.

use std::sync::Arc;
use std::time::Instant;

use iec61850_model::MmsValue;

use crate::error::GooseError;
use crate::frame::VlanTag;

/// Maximum length in bytes of the gocbRef, datSet, and goID fields, per
/// IEC 61850-8-1 §A.2.
pub const GOOSE_STRING_MAX_LEN: usize = 129;

/// Snapshot of one decoded GOOSE publication.
///
/// The snapshot is immutable and owned, so a listener can hold it across
/// threads after the receiver has moved on.
#[derive(Debug, Clone)]
pub struct GooseSubscriberState {
    /// GoCB object reference.
    pub gocb_ref: String,
    /// Data set object reference.
    pub dat_set: String,
    /// goID.
    pub go_id: String,
    /// timeAllowedToLive in milliseconds.
    pub time_allowed_to_live_ms: u32,
    /// State number.
    pub st_num: u32,
    /// Sequence number.
    pub sq_num: u32,
    /// Configuration revision.
    pub conf_rev: u32,
    /// Raw 8-byte UTC time from the PDU.
    ///
    /// A publication that carries no `t` field leaves this zero and is logged,
    /// so a zero value is not a trustworthy timestamp.
    pub timestamp_raw: [u8; 8],
    /// Simulation bit, called `test` in IEC 61850-8-1.
    pub simulation: bool,
    /// ndsCom, needs commissioning.
    pub nds_com: bool,
    /// Decoded data set values.
    pub dataset_values: Vec<MmsValue>,
    /// Source MAC address of the frame.
    pub src_mac: [u8; 6],
    /// Destination MAC address of the frame.
    pub dst_mac: [u8; 6],
    /// VLAN tag, when the frame carried one.
    pub vlan: Option<VlanTag>,
    /// Arrival time, against which timeAllowedToLive is measured.
    pub received_at: Instant,
    /// False when the publication is out of sequence, such as an stNum that
    /// moved backwards or an sqNum that did not advance.
    pub state_valid: bool,
}

/// Event delivered to a subscriber's listener.
#[derive(Debug, Clone)]
pub enum GooseEvent {
    /// A new stNum, meaning the publisher reported a data change.
    ///
    /// `prev_st_num` is 0 for the first publication received. `parse_result`
    /// carries a decode or consistency error while `state` is still provided,
    /// leaving the decision to the application.
    NewState {
        prev_st_num: u32,
        state: Arc<GooseSubscriberState>,
        parse_result: Result<(), GooseError>,
    },
    /// A retransmission of the same state.
    Retransmission {
        state: Arc<GooseSubscriberState>,
        parse_result: Result<(), GooseError>,
    },
    /// timeAllowedToLive elapsed without a new publication.
    ///
    /// Raised by `check_expired` once per state; `last_state` is the snapshot
    /// that expired.
    Expired {
        last_state: Arc<GooseSubscriberState>,
    },
}

/// Builds a `GooseSubscriber`.
///
/// Filters are fixed once `build` returns.
#[derive(Default)]
pub struct GooseSubscriberBuilder {
    gocb_ref: Option<String>,
    app_id: Option<u16>,
    dst_mac: Option<[u8; 6]>,
    is_observer: bool,
    listener: Option<Box<dyn Fn(GooseEvent) + Send + Sync + 'static>>,
}

impl GooseSubscriberBuilder {
    /// Creates a builder with no filters and no listener.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the gocbRef filter; leaving it unset selects observer mode.
    pub fn gocb_ref(mut self, gocb_ref: impl Into<String>) -> Self {
        self.gocb_ref = Some(gocb_ref.into());
        self
    }

    /// Sets the APPID filter; leaving it unset accepts any APPID.
    pub fn app_id(mut self, app_id: u16) -> Self {
        self.app_id = Some(app_id);
        self
    }

    /// Sets the destination MAC filter; leaving it unset accepts any address.
    pub fn dst_mac(mut self, mac: [u8; 6]) -> Self {
        self.dst_mac = Some(mac);
        self
    }

    /// Selects observer mode, which accepts every GOOSE frame.
    pub fn observer(mut self) -> Self {
        self.is_observer = true;
        self
    }

    /// Sets the listener invoked for each event.
    pub fn listener(mut self, cb: impl Fn(GooseEvent) + Send + Sync + 'static) -> Self {
        self.listener = Some(Box::new(cb));
        self
    }

    /// Builds the subscriber. A subscriber with no gocbRef filter is an
    /// observer.
    pub fn build(self) -> GooseSubscriber {
        let is_observer = self.is_observer || self.gocb_ref.is_none();
        GooseSubscriber {
            gocb_ref: self.gocb_ref.unwrap_or_default(),
            app_id: self.app_id,
            dst_mac: self.dst_mac,
            is_observer,
            listener: self.listener,
            last_state: None,
            expired_fired: false,
        }
    }
}

/// A GOOSE subscription: filters, the last decoded state, and a listener.
///
/// Construct one through `GooseSubscriberBuilder` or `GooseSubscriber::new`.
pub struct GooseSubscriber {
    /// gocbRef filter; empty in observer mode.
    pub(crate) gocb_ref: String,
    /// APPID filter; `None` accepts any APPID.
    pub(crate) app_id: Option<u16>,
    /// Destination MAC filter; `None` accepts any address.
    pub(crate) dst_mac: Option<[u8; 6]>,
    /// Observer mode, which bypasses every filter.
    pub(crate) is_observer: bool,
    /// Listener invoked for each event.
    pub(crate) listener: Option<Box<dyn Fn(GooseEvent) + Send + Sync + 'static>>,
    /// Most recent state snapshot.
    pub(crate) last_state: Option<Arc<GooseSubscriberState>>,
    /// Whether `Expired` has already fired for the current state; cleared when
    /// a new publication arrives.
    pub(crate) expired_fired: bool,
}

impl std::fmt::Debug for GooseSubscriber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GooseSubscriber")
            .field("gocb_ref", &self.gocb_ref)
            .field("app_id", &self.app_id)
            .field("dst_mac", &self.dst_mac)
            .field("is_observer", &self.is_observer)
            .field("has_listener", &self.listener.is_some())
            .finish()
    }
}

impl GooseSubscriber {
    /// Creates a subscriber filtered on `gocb_ref`, with no listener.
    pub fn new(gocb_ref: impl Into<String>) -> Self {
        GooseSubscriberBuilder::new().gocb_ref(gocb_ref).build()
    }

    /// Creates an observer subscriber, which accepts every GOOSE frame.
    pub fn new_observer() -> Self {
        GooseSubscriberBuilder::new().observer().build()
    }

    /// Returns the gocbRef filter.
    pub fn gocb_ref(&self) -> &str {
        &self.gocb_ref
    }

    /// Returns the APPID filter.
    pub fn app_id(&self) -> Option<u16> {
        self.app_id
    }

    /// Returns the destination MAC filter.
    pub fn dst_mac_filter(&self) -> Option<[u8; 6]> {
        self.dst_mac
    }

    /// Returns whether this is an observer subscription.
    pub fn is_observer(&self) -> bool {
        self.is_observer
    }

    /// Sets the listener.
    ///
    /// Call this before the subscriber is added to a receiver; a running
    /// receiver dispatches from its own thread.
    pub fn set_listener(&mut self, cb: impl Fn(GooseEvent) + Send + Sync + 'static) {
        self.listener = Some(Box::new(cb));
    }

    /// Returns whether the last publication is still valid and within its
    /// timeAllowedToLive.
    pub fn is_valid(&self) -> bool {
        let Some(state) = &self.last_state else {
            return false;
        };
        if !state.state_valid {
            return false;
        }
        let elapsed_ms = state.received_at.elapsed().as_millis() as u64;
        elapsed_ms <= state.time_allowed_to_live_ms as u64
    }

    /// Returns the most recent state snapshot, or `None` before the first
    /// publication.
    pub fn last_state(&self) -> Option<Arc<GooseSubscriberState>> {
        self.last_state.clone()
    }

    /// Returns the last stNum, or 0 before the first publication.
    pub fn st_num(&self) -> u32 {
        self.last_state.as_ref().map(|s| s.st_num).unwrap_or(0)
    }

    /// Returns the last sqNum, or 0 before the first publication.
    pub fn sq_num(&self) -> u32 {
        self.last_state.as_ref().map(|s| s.sq_num).unwrap_or(0)
    }

    /// Returns the last confRev, or 0 before the first publication.
    pub fn conf_rev(&self) -> u32 {
        self.last_state.as_ref().map(|s| s.conf_rev).unwrap_or(0)
    }

    /// Returns the gocbRef of the last publication, or an empty string.
    pub fn last_gocb_ref(&self) -> &str {
        self.last_state
            .as_ref()
            .map(|s| s.gocb_ref.as_str())
            .unwrap_or("")
    }

    /// Returns whether the frame-level filters accept this APPID and
    /// destination MAC. Observer mode always accepts.
    pub(crate) fn matches_frame(&self, app_id: u16, dst_mac: &[u8; 6]) -> bool {
        if self.is_observer {
            return true;
        }
        let appid_ok = self.app_id.is_none_or(|id| id == app_id);
        let mac_ok = self.dst_mac.is_none_or(|m| &m == dst_mac);
        appid_ok && mac_ok
    }

    /// Returns whether the gocbRef filter accepts this reference. Observer
    /// mode always accepts.
    pub(crate) fn matches_gocb_ref(&self, gocb_ref: &str) -> bool {
        self.is_observer || self.gocb_ref == gocb_ref
    }

    /// Applies a decoded publication and invokes the listener.
    ///
    /// A higher stNum, or the first publication, raises `NewState`; the same
    /// stNum raises `Retransmission`. An stNum that moves backwards, or an
    /// sqNum that does not advance within a state, clears `state_valid` while
    /// the listener is still called. A change of confRev is passed as
    /// `Err(ConfRevMismatch)` in `parse_result`.
    pub(crate) fn update_and_dispatch(&mut self, new_state: GooseSubscriberState) {
        let prev_st_num = self.last_state.as_ref().map(|s| s.st_num).unwrap_or(0);
        let prev_sq_num = self.last_state.as_ref().map(|s| s.sq_num).unwrap_or(0);
        let prev_conf_rev = self.last_state.as_ref().map(|s| s.conf_rev).unwrap_or(0);

        let new_st_num = new_state.st_num;
        let new_sq_num = new_state.sq_num;
        let new_conf_rev = new_state.conf_rev;

        let st_num_rollback = self.last_state.is_some() && new_st_num < prev_st_num;
        if st_num_rollback {
            tracing::warn!(
                "goose subscriber gocbref={:?}: stnum went backwards from {} to {}",
                self.gocb_ref,
                prev_st_num,
                new_st_num
            );
        }

        let sq_num_rollback = !st_num_rollback
            && self.last_state.is_some()
            && new_st_num == prev_st_num
            && new_sq_num <= prev_sq_num;
        if sq_num_rollback {
            tracing::warn!(
                "goose subscriber gocbref={:?}: stnum={} sqnum {} did not advance past {}",
                self.gocb_ref,
                new_st_num,
                new_sq_num,
                prev_sq_num
            );
        }

        let conf_rev_mismatch =
            self.last_state.is_some() && prev_conf_rev != 0 && new_conf_rev != prev_conf_rev;
        let parse_result: Result<(), GooseError> = if conf_rev_mismatch {
            tracing::warn!(
                "goose subscriber gocbref={:?}: confrev changed from {} to {}",
                self.gocb_ref,
                prev_conf_rev,
                new_conf_rev
            );
            Err(GooseError::ConfRevMismatch {
                expected: prev_conf_rev,
                actual: new_conf_rev,
            })
        } else {
            Ok(())
        };

        let state_valid = !st_num_rollback && !sq_num_rollback && new_state.state_valid;

        let final_state = Arc::new(GooseSubscriberState {
            state_valid,
            ..new_state
        });

        // A fresh publication re-arms the expiry event.
        if !sq_num_rollback {
            self.expired_fired = false;
        }

        let event = if st_num_rollback || new_st_num > prev_st_num || prev_st_num == 0 {
            GooseEvent::NewState {
                prev_st_num,
                state: final_state.clone(),
                parse_result,
            }
        } else {
            GooseEvent::Retransmission {
                state: final_state.clone(),
                parse_result,
            }
        };

        self.last_state = Some(final_state);

        if let Some(cb) = &self.listener {
            cb(event);
        }
    }

    /// Raises `Expired` when timeAllowedToLive has elapsed since the last
    /// publication.
    ///
    /// The event fires at most once per state; a new publication re-arms it.
    pub(crate) fn check_expired(&mut self) {
        if self.expired_fired {
            return;
        }
        let Some(state) = &self.last_state else {
            return;
        };
        if !state.state_valid {
            return;
        }
        let elapsed_ms = state.received_at.elapsed().as_millis() as u64;
        if elapsed_ms > state.time_allowed_to_live_ms as u64 {
            self.expired_fired = true;
            let last = state.clone();
            if let Some(cb) = &self.listener {
                cb(GooseEvent::Expired { last_state: last });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    /// Builds a state snapshot with the given sequence and revision numbers.
    fn make_state(
        gocb_ref: &str,
        st_num: u32,
        sq_num: u32,
        conf_rev: u32,
        tatl_ms: u32,
    ) -> GooseSubscriberState {
        GooseSubscriberState {
            gocb_ref: gocb_ref.to_string(),
            dat_set: "IED1/LLN0$GO$gcbEvents".to_string(),
            go_id: "gooseEvents".to_string(),
            time_allowed_to_live_ms: tatl_ms,
            st_num,
            sq_num,
            conf_rev,
            timestamp_raw: [0u8; 8],
            simulation: false,
            nds_com: false,
            dataset_values: vec![],
            src_mac: [0u8; 6],
            dst_mac: [0u8; 6],
            vlan: None,
            received_at: Instant::now(),
            state_valid: true,
        }
    }

    #[test]
    fn builder_sets_filter_fields() {
        let sub = GooseSubscriberBuilder::new()
            .gocb_ref("IED1/LLN0$GO$gcbEvents")
            .app_id(0x0001)
            .dst_mac([0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01])
            .build();

        assert_eq!(sub.gocb_ref(), "IED1/LLN0$GO$gcbEvents");
        assert_eq!(sub.app_id(), Some(0x0001));
        assert_eq!(
            sub.dst_mac_filter(),
            Some([0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01])
        );
        assert!(!sub.is_observer());
    }

    #[test]
    fn observer_mode_accepts_any_gocb_ref() {
        let mut obs = GooseSubscriber::new_observer();
        assert!(obs.is_observer());
        assert!(obs.matches_gocb_ref("IED1/LLN0$GO$gcbEvents"));
        assert!(obs.matches_gocb_ref("IED2/XCBR1$GO$gcbProtect"));

        // Observer mode bypasses the frame filters.
        assert!(obs.matches_frame(0x0001, &[0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01]));
        assert!(obs.matches_frame(0xFFFF, &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]));

        // Dispatch works the same way in observer mode.
        let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
        let ev_clone = events.clone();
        obs.set_listener(move |e| {
            let tag = match &e {
                GooseEvent::NewState { .. } => "new",
                GooseEvent::Retransmission { .. } => "retx",
                GooseEvent::Expired { .. } => "exp",
            };
            ev_clone.lock().unwrap().push(tag.to_string());
        });

        let s = make_state("IED1/LLN0$GO$gcbEvents", 1, 0, 1, 1000);
        obs.update_and_dispatch(s);
        assert_eq!(events.lock().unwrap().as_slice(), &["new"]);
    }

    #[test]
    fn appid_filter_works() {
        let sub = GooseSubscriberBuilder::new()
            .gocb_ref("IED1/LLN0$GO$gcb")
            .app_id(0x0001)
            .build();

        let dst = [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01];
        assert!(sub.matches_frame(0x0001, &dst));
        assert!(!sub.matches_frame(0x0002, &dst));
    }

    #[test]
    fn dst_mac_filter_works() {
        let mac_a = [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01];
        let mac_b = [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x02];

        let sub = GooseSubscriberBuilder::new()
            .gocb_ref("IED1/LLN0$GO$gcb")
            .dst_mac(mac_a)
            .build();

        assert!(sub.matches_frame(0x0001, &mac_a));
        assert!(!sub.matches_frame(0x0001, &mac_b));
    }

    #[test]
    fn no_appid_filter_accepts_any() {
        let sub = GooseSubscriberBuilder::new()
            .gocb_ref("IED1/LLN0$GO$gcb")
            .build();

        // An unset APPID filter accepts any APPID.
        assert!(sub.matches_frame(0x0000, &[0u8; 6]));
        assert!(sub.matches_frame(0xFFFF, &[0u8; 6]));
    }

    #[test]
    fn first_pdu_triggers_new_state() {
        let events: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(vec![]));
        let ev_clone = events.clone();
        let mut sub = GooseSubscriberBuilder::new()
            .gocb_ref("IED1/LLN0$GO$gcb")
            .listener(move |e| {
                if let GooseEvent::NewState { state, .. } = e {
                    ev_clone.lock().unwrap().push(state.st_num);
                }
            })
            .build();

        let s = make_state("IED1/LLN0$GO$gcb", 5, 0, 1, 1000);
        sub.update_and_dispatch(s);
        assert_eq!(*events.lock().unwrap(), vec![5u32]);
        assert!(sub.is_valid());
    }

    #[test]
    fn retransmission_same_st_num_incremented_sq_num() {
        let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
        let ev_clone = events.clone();
        let mut sub = GooseSubscriberBuilder::new()
            .gocb_ref("IED1/LLN0$GO$gcb")
            .listener(move |e| {
                let tag = match &e {
                    GooseEvent::NewState { .. } => "new",
                    GooseEvent::Retransmission { .. } => "retx",
                    GooseEvent::Expired { .. } => "exp",
                };
                ev_clone.lock().unwrap().push(tag.to_string());
            })
            .build();

        // First publication of state 5.
        sub.update_and_dispatch(make_state("IED1/LLN0$GO$gcb", 5, 0, 1, 1000));
        sub.update_and_dispatch(make_state("IED1/LLN0$GO$gcb", 5, 1, 1, 1000));
        // Two retransmissions of the same state.
        sub.update_and_dispatch(make_state("IED1/LLN0$GO$gcb", 5, 2, 1, 1000));

        assert_eq!(events.lock().unwrap().as_slice(), &["new", "retx", "retx"]);
    }

    #[test]
    fn st_num_increase_triggers_new_state() {
        let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
        let ev_clone = events.clone();
        let mut sub = GooseSubscriberBuilder::new()
            .gocb_ref("IED1/LLN0$GO$gcb")
            .listener(move |e| {
                let tag = match &e {
                    GooseEvent::NewState { .. } => "new",
                    GooseEvent::Retransmission { .. } => "retx",
                    GooseEvent::Expired { .. } => "exp",
                };
                ev_clone.lock().unwrap().push(tag.to_string());
            })
            .build();

        sub.update_and_dispatch(make_state("IED1/LLN0$GO$gcb", 5, 10, 1, 1000));
        // The next state restarts sqNum at 0.
        sub.update_and_dispatch(make_state("IED1/LLN0$GO$gcb", 6, 0, 1, 1000));

        assert_eq!(events.lock().unwrap().as_slice(), &["new", "new"]);
    }

    #[test]
    fn sq_num_rollback_sets_state_invalid() {
        let events: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(vec![]));
        let ev_clone = events.clone();
        let mut sub = GooseSubscriberBuilder::new()
            .gocb_ref("IED1/LLN0$GO$gcb")
            .listener(move |e| {
                let valid = match &e {
                    GooseEvent::NewState { state, .. } => state.state_valid,
                    GooseEvent::Retransmission { state, .. } => state.state_valid,
                    GooseEvent::Expired { last_state } => last_state.state_valid,
                };
                ev_clone.lock().unwrap().push(valid);
            })
            .build();

        sub.update_and_dispatch(make_state("IED1/LLN0$GO$gcb", 5, 5, 1, 1000));
        // Repeat, then a lower sqNum within the same state.
        sub.update_and_dispatch(make_state("IED1/LLN0$GO$gcb", 5, 5, 1, 1000));
        sub.update_and_dispatch(make_state("IED1/LLN0$GO$gcb", 5, 2, 1, 1000));

        let vals = events.lock().unwrap();
        assert!(vals[0], "first publication is valid");
        assert!(!vals[1], "a repeated sqnum is invalid");
        assert!(!vals[2], "a lower sqnum is invalid");
    }

    #[test]
    fn st_num_rollback_sets_state_invalid_and_warns() {
        let events: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(vec![]));
        let ev_clone = events.clone();
        let mut sub = GooseSubscriberBuilder::new()
            .gocb_ref("IED1/LLN0$GO$gcb")
            .listener(move |e| {
                let valid = match &e {
                    GooseEvent::NewState { state, .. } => state.state_valid,
                    GooseEvent::Retransmission { state, .. } => state.state_valid,
                    GooseEvent::Expired { last_state } => last_state.state_valid,
                };
                ev_clone.lock().unwrap().push(valid);
            })
            .build();

        sub.update_and_dispatch(make_state("IED1/LLN0$GO$gcb", 5, 0, 1, 1000));
        // A lower stNum than the one already seen.
        sub.update_and_dispatch(make_state("IED1/LLN0$GO$gcb", 4, 0, 1, 1000));

        let vals = events.lock().unwrap();
        assert!(vals[0], "first publication is valid");
        assert!(!vals[1], "a lower stnum is invalid");
    }

    #[test]
    fn conf_rev_mismatch_logs_warn_and_returns_err() {
        let results: Arc<Mutex<Vec<Result<(), GooseError>>>> = Arc::new(Mutex::new(vec![]));
        let res_clone = results.clone();
        let mut sub = GooseSubscriberBuilder::new()
            .gocb_ref("IED1/LLN0$GO$gcb")
            .listener(move |e| {
                let pr = match e {
                    GooseEvent::NewState { parse_result, .. } => parse_result,
                    GooseEvent::Retransmission { parse_result, .. } => parse_result,
                    GooseEvent::Expired { .. } => Ok(()),
                };
                res_clone.lock().unwrap().push(pr);
            })
            .build();

        sub.update_and_dispatch(make_state("IED1/LLN0$GO$gcb", 5, 0, 1, 1000));
        // Second publication announces a different confRev.
        sub.update_and_dispatch(make_state("IED1/LLN0$GO$gcb", 6, 0, 2, 1000));

        let res = results.lock().unwrap();
        assert!(res[0].is_ok(), "the first confrev sets the baseline");
        assert!(
            matches!(
                &res[1],
                Err(GooseError::ConfRevMismatch {
                    expected: 1,
                    actual: 2
                })
            ),
            "a changed confrev reports confrevmismatch"
        );
    }

    #[test]
    fn expired_callback_fires_once_per_stnum_change() {
        let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
        let ev_clone = events.clone();
        let mut sub = GooseSubscriberBuilder::new()
            .gocb_ref("IED1/LLN0$GO$gcb")
            .listener(move |e| {
                let tag = match &e {
                    GooseEvent::NewState { .. } => "new",
                    GooseEvent::Retransmission { .. } => "retx",
                    GooseEvent::Expired { .. } => "exp",
                };
                ev_clone.lock().unwrap().push(tag.to_string());
            })
            .build();

        // A 1 ms timeAllowedToLive with an arrival 10 ms in the past.
        let mut s = make_state("IED1/LLN0$GO$gcb", 5, 0, 1, 1);
        s.received_at = Instant::now() - std::time::Duration::from_millis(10);
        sub.update_and_dispatch(s);

        sub.check_expired();
        // The second call must not fire again.
        sub.check_expired();

        let ev = events.lock().unwrap();
        assert_eq!(ev.as_slice(), &["new", "exp"]);
    }

    #[test]
    fn is_valid_returns_false_before_first_pdu() {
        let sub = GooseSubscriber::new("IED1/LLN0$GO$gcb");
        assert!(!sub.is_valid());
    }

    #[test]
    fn is_valid_returns_true_after_pdu_within_tatl() {
        let mut sub = GooseSubscriber::new("IED1/LLN0$GO$gcb");
        // A publication that just arrived with a 5000 ms lifetime.
        sub.update_and_dispatch(make_state("IED1/LLN0$GO$gcb", 1, 0, 1, 5000));
        assert!(sub.is_valid());
    }
}
