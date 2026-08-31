//! `MmsServerConnection`, the negotiated state of one association.
//!
//! Only the negotiated parameters and the dispatcher hook live here. The transport
//! and the association object belong to the server crate that owns the accept loop.
//!
//! ## Negotiated parameters
//!
//! `NegotiatedParams` is written once, when negotiation completes, and read-only
//! afterwards, so no service handler shares mutable state across an await point.

use crate::compat::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

// The permit pool is a plain atomic counter rather than an async semaphore: every
// use here is synchronous (try_acquire, available_permits, release on drop) with no
// await point, and a counter also works in a no_std build with alloc.
//
// - `try_acquire()` returns `Option<OutstandingPermit>`
// - `available_permits()` reports how many remain
// - dropping an `OutstandingPermit` releases it with Release ordering, so the next
//   acquire observes the release

/// Shared state of the outstanding-permit pool.
#[derive(Debug)]
struct OutstandingPermitsInner {
    used: AtomicUsize,
    capacity: usize,
}

/// Permit pool bounding the number of outstanding ConfirmedRequests.
///
/// A plain counter, so the pool works in a no_std build with alloc.
#[derive(Debug, Clone)]
pub struct OutstandingPermits {
    inner: Arc<OutstandingPermitsInner>,
}

impl OutstandingPermits {
    /// Creates a pool holding `capacity` permits.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(OutstandingPermitsInner {
                used: AtomicUsize::new(0),
                capacity,
            }),
        }
    }

    /// Tries to take a permit without blocking; the permit is released when dropped.
    pub fn try_acquire(&self) -> Option<OutstandingPermit> {
        let mut current = self.inner.used.load(Ordering::Relaxed);
        loop {
            if current >= self.inner.capacity {
                return None;
            }
            match self.inner.used.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(OutstandingPermit {
                        inner: Arc::clone(&self.inner),
                    });
                }
                Err(actual) => current = actual,
            }
        }
    }

    /// Returns how many permits remain.
    pub fn available_permits(&self) -> usize {
        let used = self.inner.used.load(Ordering::Relaxed);
        self.inner.capacity.saturating_sub(used)
    }
}

/// One outstanding permit, released back to the pool when dropped.
#[derive(Debug)]
pub struct OutstandingPermit {
    inner: Arc<OutstandingPermitsInner>,
}

impl Drop for OutstandingPermit {
    fn drop(&mut self) {
        self.inner.used.fetch_sub(1, Ordering::Release);
    }
}

use super::super::pdu::initiate::{
    DEFAULT_DATA_STRUCTURE_NESTING_LEVEL, DEFAULT_MAX_PDU_SIZE,
    DEFAULT_MAX_SERV_OUTSTANDING_CALLED, DEFAULT_MAX_SERV_OUTSTANDING_CALLING,
    DEFAULT_PARAMETER_CBB_CLIENT,
};

/// Smallest MMS PDU size the server accepts.
///
/// A proposal below this is refused rather than accepted, because a peer proposing
/// 0 would otherwise underflow the `maxPduSize - 27` header overhead downstream.
/// 64 bytes is the smallest MMS PDU header ISO 9506-1 can express, which is exactly
/// the point where that subtraction stays positive.
pub const MIN_PDU_SIZE: u32 = 64;

/// Largest MMS PDU in bytes the server itself accepts.
pub const SERVER_MAX_PDU_SIZE: u32 = DEFAULT_MAX_PDU_SIZE;

/// parameterCBB the server supports, padding byte included.
///
/// The same value the client default uses, `{0x05, 0xf1, 0x00}`: padding 5 and data
/// 0xf1 0x00, covering str1, str2, vnam, valt and vlis. Negotiation takes the
/// bitwise AND with the value the peer proposes.
pub const SERVER_PARAMETER_CBB: [u8; 3] = DEFAULT_PARAMETER_CBB_CLIENT;

/// servicesSupportedCalled the server announces: 11 raw bytes, padding byte excluded.
///
/// This is the capability set of a build without the file, obtain-file and journal
/// services:
///
/// - byte 0 `0xee` = STATUS | GET_NAME_LIST | IDENTIFY | READ | WRITE |
///   GET_VARIABLE_ACCESS_ATTRIBUTES
/// - byte 1 `0x1c` = DEFINE_NAMED_VARIABLE_LIST | GET_NAMED_VARIABLE_LIST_ATTRS |
///   DELETE_NAMED_VARIABLE_LIST
/// - bytes 2 to 8 are `0x00`: no file, obtain-file or journal service
/// - byte 9 `0x01` = INFORMATION_REPORT
/// - byte 10 `0x18` = CONCLUDE | CANCEL
///
/// This must not be set to `DEFAULT_SERVICES_SUPPORTED_CLIENT`. The client and
/// server bitmaps are independent: the client default sets the file and journal bits
/// to say it would accept such responses, while a server without those services must
/// not announce them. Announcing them makes a client believe the file service
/// exists and fail when it tries to use it.
///
/// A build that adds reporting, logging or the file service should compute this
/// bitmap from the features it enables, turning on the matching bits.
pub const SERVER_SERVICES_SUPPORTED: [u8; 11] = [
    0xee, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x18,
];

/// Largest dataStructureNestingLevel the server accepts.
///
/// Matches `MAX_NESTING_LEVEL`, the ceiling of 32 the PDU decoder applies.
pub const SERVER_MAX_NESTING_LEVEL: u8 = 32;

/// Largest number of outstanding ConfirmedRequests the server accepts, per direction.
pub const SERVER_MAX_OUTSTANDING: u16 = 5;

/// Smallest negotiated outstanding-request count.
///
/// A proposal of 0 is clamped up to 1 rather than accepted, since 0 has no useful
/// meaning and would leave the dispatch path with an ambiguous ceiling.
pub const MIN_OUTSTANDING: u16 = 1;

/// The immutable state produced by negotiation.
///
/// Written once per connection, when Initiate completes, and read-only thereafter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedParams {
    /// Negotiated maximum PDU size: the smaller proposal, floored at `MIN_PDU_SIZE`.
    pub max_pdu_size: u32,
    /// Negotiated calling outstanding ceiling, floored at `MIN_OUTSTANDING`.
    pub max_serv_outstanding_calling: u16,
    /// Negotiated called outstanding ceiling, floored at `MIN_OUTSTANDING`.
    pub max_serv_outstanding_called: u16,
    /// Negotiated dataStructureNestingLevel, capped at `SERVER_MAX_NESTING_LEVEL`.
    pub data_structure_nesting_level: u8,
    /// The parameterCBB after the bitwise AND, padding byte included, 3 bytes.
    pub parameter_cbb: [u8; 3],
    /// servicesSupportedCalled the server announced, padding byte excluded, 11 bytes.
    pub services_supported_called: [u8; 11],
    /// servicesSupportedCalling the peer proposed, padding byte excluded, 11 bytes.
    ///
    /// The value is recorded and logged but never enforced, so a peer that uses a
    /// service it did not announce is still served.
    ///
    /// `None` when the peer omitted the field, which is rare.
    pub client_proposed_services: Option<[u8; 11]>,
}

impl Default for NegotiatedParams {
    /// The values in force between association setup and the Initiate exchange.
    ///
    /// Service handlers must not use these: `MmsServerConnection::negotiated` returns
    /// `None` until Initiate completes.
    fn default() -> Self {
        Self {
            max_pdu_size: SERVER_MAX_PDU_SIZE,
            max_serv_outstanding_calling: DEFAULT_MAX_SERV_OUTSTANDING_CALLING,
            max_serv_outstanding_called: DEFAULT_MAX_SERV_OUTSTANDING_CALLED,
            data_structure_nesting_level: DEFAULT_DATA_STRUCTURE_NESTING_LEVEL,
            parameter_cbb: SERVER_PARAMETER_CBB,
            services_supported_called: SERVER_SERVICES_SUPPORTED,
            client_proposed_services: None,
        }
    }
}

/// Default release timeout in milliseconds.
///
/// A peer is expected to send the Session FINISH SPDU after receiving the MMS
/// Conclude response. Without a timeout a peer that never does would hold the
/// connection open forever, so the transport is closed once this elapses.
pub const DEFAULT_CONCLUDE_TIMEOUT_MS: u64 = 10_000;

/// Per-connection MMS state, valid once negotiation has completed.
///
/// Only the negotiated parameters and the invokeID counter live here; the transport
/// and the association object belong to the server crate.
#[derive(Debug)]
pub struct MmsServerConnection {
    /// Filled in when Initiate completes; `None` before that.
    negotiated: Option<NegotiatedParams>,
    /// Highest ConfirmedRequest invokeID seen so far.
    last_invoke_id: u32,
    /// While true, dispatch answers every request with Reject(other) and a warning.
    ///
    /// Set by the server abort path or by a maintenance mode: the association is
    /// negotiated but temporarily not serving requests.
    block_requests: bool,
    /// Timestamp, in milliseconds, at which the MMS Conclude response was sent and the
    /// wait for the Session FINISH SPDU began.
    ///
    /// The server lifecycle writes this field and closes the transport once
    /// `conclude_timeout_ms` elapses; the dispatch layer only reads it.
    /// While it is `Some`, dispatch answers every request with Reject(other), since no
    /// further PDU is expected.
    concluded: bool,
    /// Milliseconds to wait for the Session FINISH SPDU after a Conclude response.
    conclude_timeout_ms: u64,
    /// Connection identifier assigned by the server crate.
    ///
    /// The MMS layer has no notion of a connection id, but control and reporting
    /// handlers route unsolicited PDUs back to a connection task by it. `None` means
    /// none was assigned, which happens in tests; the dispatcher then warns and drops
    /// the PDU rather than routing it.
    connection_id: Option<u64>,
    /// Bounds how many ConfirmedRequests the peer may have outstanding at once.
    ///
    /// The pool holds `negotiated.max_serv_outstanding_calling` permits. Before
    /// negotiation it starts at `SERVER_MAX_OUTSTANDING`, so a request arriving ahead
    /// of Initiate can still be dispatched; `set_negotiated` rebuilds it. The
    /// dispatcher takes a permit on entry and drops it once the response is produced.
    ///
    /// Enforcing the ceiling keeps a peer from tying up server resources by issuing
    /// requests without waiting for responses: request N+1 is answered with
    /// Reject(MaxServOutstandingExceeded).
    outstanding: OutstandingPermits,
}

impl Default for MmsServerConnection {
    fn default() -> Self {
        Self::new()
    }
}

impl MmsServerConnection {
    /// Creates a connection that has not negotiated yet, just after the association
    /// indication.
    pub fn new() -> Self {
        Self {
            negotiated: None,
            last_invoke_id: 0,
            block_requests: false,
            concluded: false,
            conclude_timeout_ms: DEFAULT_CONCLUDE_TIMEOUT_MS,
            connection_id: None,
            outstanding: OutstandingPermits::new(SERVER_MAX_OUTSTANDING as usize),
        }
    }

    /// Returns the assigned connection identifier.
    pub fn connection_id(&self) -> Option<u64> {
        self.connection_id
    }

    /// Assigns the connection identifier, once the accept loop has completed Initiate.
    pub fn set_connection_id(&mut self, id: u64) {
        self.connection_id = Some(id);
    }

    /// Returns whether requests are temporarily refused.
    pub fn block_requests(&self) -> bool {
        self.block_requests
    }

    /// Sets the request-blocking flag, used by maintenance mode and the abort path.
    pub fn set_block_requests(&mut self, on: bool) {
        self.block_requests = on;
    }

    /// Returns whether an MMS Conclude response has been sent.
    pub fn is_concluded(&self) -> bool {
        self.concluded
    }

    /// Marks the Conclude response as sent, so the caller can start the release timeout.
    pub fn mark_concluded(&mut self) {
        self.concluded = true;
    }

    /// Returns the release timeout in milliseconds.
    pub fn conclude_timeout_ms(&self) -> u64 {
        self.conclude_timeout_ms
    }

    /// Sets the release timeout in milliseconds.
    pub fn set_conclude_timeout_ms(&mut self, ms: u64) {
        self.conclude_timeout_ms = ms;
    }

    /// Records the result of negotiation.
    ///
    /// A connection negotiates once. A second call overwrites the first and logs a
    /// warning, which the normal flow never triggers.
    ///
    /// The outstanding-permit pool is rebuilt from
    /// `params.max_serv_outstanding_calling`. Any permit already taken belongs to the
    /// previous pool and does not affect the new count, since negotiation precedes any
    /// ConfirmedRequest.
    pub fn set_negotiated(&mut self, params: NegotiatedParams) {
        if self.negotiated.is_some() {
            tracing::warn!(
                "set_negotiated called twice, overwriting the earlier values; a connection normally negotiates once"
            );
        }
        self.outstanding = OutstandingPermits::new(params.max_serv_outstanding_calling as usize);
        self.negotiated = Some(params);
    }

    /// Returns the negotiated parameters, or `None` before Initiate completes.
    pub fn negotiated(&self) -> Option<&NegotiatedParams> {
        self.negotiated.as_ref()
    }

    /// Returns the negotiated maximum PDU size, or `None` before Initiate completes.
    pub fn negotiated_max_pdu_size(&self) -> Option<u32> {
        self.negotiated.as_ref().map(|p| p.max_pdu_size)
    }

    /// Returns whether negotiation has completed and the Initiate response was sent.
    pub fn is_active(&self) -> bool {
        self.negotiated.is_some()
    }

    /// Allocates a fresh invokeID for a server-initiated request, such as a report.
    pub fn next_invoke_id(&mut self) -> u32 {
        self.last_invoke_id = self.last_invoke_id.wrapping_add(1);
        self.last_invoke_id
    }

    /// Tries to take an outstanding-request permit without blocking.
    ///
    /// `Some(permit)` succeeds and the permit is released when dropped. `None` means
    /// the negotiated ceiling is reached and the dispatcher must answer with
    /// Reject(ConfirmedRequest, MaxServOutstandingExceeded).
    pub fn try_acquire_outstanding(&self) -> Option<OutstandingPermit> {
        self.outstanding.try_acquire()
    }

    /// Returns how many outstanding permits remain.
    pub fn outstanding_available(&self) -> usize {
        self.outstanding.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_connection_is_inactive() {
        let conn = MmsServerConnection::new();
        assert!(!conn.is_active());
        assert!(conn.negotiated().is_none());
        assert!(conn.negotiated_max_pdu_size().is_none());
    }

    #[test]
    fn set_negotiated_marks_active() {
        let mut conn = MmsServerConnection::new();
        conn.set_negotiated(NegotiatedParams {
            max_pdu_size: 4096,
            ..Default::default()
        });
        assert!(conn.is_active());
        assert_eq!(conn.negotiated_max_pdu_size(), Some(4096));
    }

    #[test]
    fn invoke_id_increments_from_one() {
        let mut conn = MmsServerConnection::new();
        assert_eq!(conn.next_invoke_id(), 1);
        assert_eq!(conn.next_invoke_id(), 2);
    }

    #[test]
    fn block_requests_default_false_can_toggle() {
        let mut conn = MmsServerConnection::new();
        assert!(!conn.block_requests());
        conn.set_block_requests(true);
        assert!(conn.block_requests());
        conn.set_block_requests(false);
        assert!(!conn.block_requests());
    }

    #[test]
    fn concluded_flag_lifecycle() {
        // after mark_concluded, is_concluded reports true
        let mut conn = MmsServerConnection::new();
        assert!(!conn.is_concluded());
        conn.mark_concluded();
        assert!(conn.is_concluded());
    }

    #[test]
    fn conclude_timeout_default_and_setter() {
        // the default release timeout is 10 seconds
        let mut conn = MmsServerConnection::new();
        assert_eq!(conn.conclude_timeout_ms(), DEFAULT_CONCLUDE_TIMEOUT_MS);
        assert_eq!(DEFAULT_CONCLUDE_TIMEOUT_MS, 10_000);
        conn.set_conclude_timeout_ms(3_000);
        assert_eq!(conn.conclude_timeout_ms(), 3_000);
    }

    // the outstanding-permit pool

    #[test]
    fn outstanding_default_permits_match_server_max() {
        // before negotiation the pool starts at SERVER_MAX_OUTSTANDING
        let conn = MmsServerConnection::new();
        assert_eq!(
            conn.outstanding_available(),
            SERVER_MAX_OUTSTANDING as usize
        );
    }

    #[test]
    fn outstanding_set_negotiated_resizes_permits() {
        // after negotiation the permits match max_serv_outstanding_calling
        let mut conn = MmsServerConnection::new();
        conn.set_negotiated(NegotiatedParams {
            max_serv_outstanding_calling: 3,
            ..Default::default()
        });
        assert_eq!(conn.outstanding_available(), 3);
    }

    #[test]
    fn outstanding_acquire_decrements_release_returns() {
        let mut conn = MmsServerConnection::new();
        conn.set_negotiated(NegotiatedParams {
            max_serv_outstanding_calling: 2,
            ..Default::default()
        });
        let p1 = conn.try_acquire_outstanding().expect("permit 1");
        assert_eq!(conn.outstanding_available(), 1);
        let p2 = conn.try_acquire_outstanding().expect("permit 2");
        assert_eq!(conn.outstanding_available(), 0);
        // the third acquire fails
        assert!(conn.try_acquire_outstanding().is_none());
        // dropping p1 releases one permit
        drop(p1);
        assert_eq!(conn.outstanding_available(), 1);
        drop(p2);
        assert_eq!(conn.outstanding_available(), 2);
    }
}
