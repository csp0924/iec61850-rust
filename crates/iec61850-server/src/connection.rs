//! `ClientConnection`: the server-side handle for one MMS association.
//!
//! Ownership is reference-counted through an `Arc`, and the MMS state sits
//! behind a `Mutex<Option<_>>`. A peer that closes the
//! association while a request is in flight must not leave another task reading
//! an invalidated handle; taking the option out under the mutex makes the
//! invalidation and the access mutually exclusive.
//!
//! Background work counts itself with `pending_tasks` through the `TaskGuard`
//! returned by `ClientConnection::task_guard`, which decrements on drop, so
//! that a release waits for the count to reach zero before invalidating.

use iec61850_mms::mms::server::MmsServerConnection;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

/// Identifies one association within a server; assigned in increasing order.
pub type ConnectionId = u64;

/// Handle to one client association.
///
/// Cloning claims a share of the association and dropping releases it; the
/// reference count is the ownership, so no explicit claim or release call is
/// needed.
#[derive(Debug, Clone)]
pub struct ClientConnection {
    inner: Arc<ClientConnectionInner>,
}

#[derive(Debug)]
struct ClientConnectionInner {
    id: ConnectionId,
    /// Address of the peer.
    peer: SocketAddr,
    /// Per-association MMS state, available once the association is
    /// established. `None` means the connection task has invalidated it.
    mms: Mutex<Option<MmsServerConnection>>,
    /// Background tasks still running on this association.
    ///
    /// Only the task guard touches the counter, so the field is never read
    /// directly.
    #[allow(dead_code)]
    pending_tasks: AtomicU32,
    /// Set when the server decides to abort the association.
    ///
    /// The connection task checks it once per loop iteration and, when set,
    /// sends an ACSE A-ABORT wrapped in Presentation, Session, and COTP before
    /// closing the socket.
    abort_requested: std::sync::atomic::AtomicBool,
}

impl ClientConnection {
    /// Creates the handle once the association is established.
    #[allow(dead_code)]
    pub(crate) fn new(id: ConnectionId, peer: SocketAddr, mms: MmsServerConnection) -> Self {
        Self {
            inner: Arc::new(ClientConnectionInner {
                id,
                peer,
                mms: Mutex::new(Some(mms)),
                pending_tasks: AtomicU32::new(0),
                abort_requested: std::sync::atomic::AtomicBool::new(false),
            }),
        }
    }

    /// Returns the identifier of this association.
    pub fn id(&self) -> ConnectionId {
        self.inner.id
    }

    /// Returns the address of the peer, which stays available after the
    /// association is invalidated.
    pub fn peer_address(&self) -> SocketAddr {
        self.inner.peer
    }

    /// Reports whether the association still holds its MMS state.
    pub fn is_active(&self) -> bool {
        match self.inner.mms.lock() {
            Ok(g) => g.is_some(),
            // A poisoned lock means a task panicked mid-update; the state can
            // no longer be trusted, so the association counts as inactive.
            Err(_) => false,
        }
    }

    /// Returns the negotiated maximum PDU size, or `None` when the association
    /// is inactive or has not finished negotiating.
    pub fn negotiated_max_pdu_size(&self) -> Option<u32> {
        self.inner
            .mms
            .lock()
            .ok()
            .and_then(|g| g.as_ref().and_then(|m| m.negotiated_max_pdu_size()))
    }

    /// Invalidates the association after the peer closes it.
    ///
    /// The MMS state is taken out under the mutex, so a concurrent access
    /// either sees it whole or sees `None`. The peer address is a copy and
    /// stays readable.
    #[cfg_attr(not(feature = "full-server"), allow(dead_code))]
    pub(crate) fn invalidate(&self) {
        if let Ok(mut g) = self.inner.mms.lock() {
            *g = None;
        }
    }

    /// Gives the callback mutable access to the MMS state, or returns `None`
    /// when the association is invalidated.
    ///
    /// The callback runs while the mutex is held, so it must not await.
    #[allow(dead_code)]
    pub(crate) fn with_mms_mut<R>(
        &self,
        f: impl FnOnce(&mut MmsServerConnection) -> R,
    ) -> Option<R> {
        let mut g = self.inner.mms.lock().ok()?;
        g.as_mut().map(f)
    }

    /// Gives the callback read access to the MMS state, or returns `None` when
    /// the association is invalidated.
    #[allow(dead_code)]
    pub(crate) fn with_mms<R>(&self, f: impl FnOnce(&MmsServerConnection) -> R) -> Option<R> {
        let g = self.inner.mms.lock().ok()?;
        g.as_ref().map(f)
    }

    /// Sets the request-blocking flag of this association, returning whether
    /// the association was still active.
    ///
    /// While the flag is set, every ConfirmedRequest is answered with
    /// `Reject(other)` and logged.
    pub fn set_block_requests(&self, on: bool) -> bool {
        self.with_mms_mut(|m| m.set_block_requests(on)).is_some()
    }

    /// Reports whether requests on this association are being blocked.
    pub fn block_requests(&self) -> bool {
        self.with_mms(|m| m.block_requests()).unwrap_or(false)
    }

    /// Marks the association for abort.
    ///
    /// The connection task picks this up on its next loop iteration, sends an
    /// A-ABORT, and closes the socket.
    pub fn request_abort(&self) {
        self.inner
            .abort_requested
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Reports whether an abort has been requested.
    pub fn abort_requested(&self) -> bool {
        self.inner
            .abort_requested
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Registers a background task on this association.
    ///
    /// The returned guard decrements the count when it is dropped.
    #[allow(dead_code)]
    pub(crate) fn task_guard(&self) -> TaskGuard {
        self.inner.pending_tasks.fetch_add(1, Ordering::AcqRel);
        TaskGuard {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Returns the number of background tasks registered on this association.
    #[cfg(test)]
    pub(crate) fn pending_tasks(&self) -> u32 {
        self.inner.pending_tasks.load(Ordering::SeqCst)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Background task guard
// ─────────────────────────────────────────────────────────────────────────────

/// Counts one background task against its association for as long as it lives.
///
/// When every guard has been dropped the count reaches zero, which is the
/// signal that the association can be invalidated safely.
#[allow(dead_code)]
pub(crate) struct TaskGuard {
    inner: Arc<ClientConnectionInner>,
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.inner.pending_tasks.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_addr() -> SocketAddr {
        "127.0.0.1:1234".parse().unwrap()
    }

    #[test]
    fn new_connection_is_active() {
        let conn = ClientConnection::new(1, dummy_addr(), MmsServerConnection::new());
        assert!(conn.is_active());
        assert_eq!(conn.id(), 1);
        assert_eq!(conn.peer_address(), dummy_addr());
        assert_eq!(conn.pending_tasks(), 0);
    }

    #[test]
    fn invalidate_marks_inactive() {
        let conn = ClientConnection::new(1, dummy_addr(), MmsServerConnection::new());
        conn.invalidate();
        assert!(!conn.is_active());
        // The peer address survives invalidation.
        assert_eq!(conn.peer_address(), dummy_addr());
    }

    #[test]
    fn arc_clone_acts_as_claim_ownership() {
        let conn = ClientConnection::new(1, dummy_addr(), MmsServerConnection::new());
        let cloned = conn.clone();
        assert!(cloned.is_active());
        // Cloning leaves the original handle usable.
        assert!(conn.is_active());
    }

    #[test]
    fn block_requests_round_trip_via_handle() {
        let conn = ClientConnection::new(1, dummy_addr(), MmsServerConnection::new());
        assert!(!conn.block_requests());
        assert!(conn.set_block_requests(true));
        assert!(conn.block_requests(), "the flag must read back as set");
        assert!(conn.set_block_requests(false));
        assert!(!conn.block_requests());
    }

    #[test]
    fn request_abort_sets_flag() {
        let conn = ClientConnection::new(1, dummy_addr(), MmsServerConnection::new());
        assert!(!conn.abort_requested());
        conn.request_abort();
        assert!(
            conn.abort_requested(),
            "the abort flag must read back as set"
        );
    }

    #[test]
    fn invalidated_connection_set_block_requests_returns_false() {
        let conn = ClientConnection::new(1, dummy_addr(), MmsServerConnection::new());
        conn.invalidate();
        // With no MMS state left there is nothing to set the flag on.
        assert!(!conn.set_block_requests(true));
    }

    #[test]
    fn negotiated_pdu_size_visible_after_negotiation() {
        use iec61850_mms::mms::server::NegotiatedParams;
        let mut mms = MmsServerConnection::new();
        mms.set_negotiated(NegotiatedParams {
            max_pdu_size: 4096,
            ..Default::default()
        });
        let conn = ClientConnection::new(1, dummy_addr(), mms);
        assert_eq!(conn.negotiated_max_pdu_size(), Some(4096));
    }

    /// A task guard increments on creation and decrements on drop.
    #[test]
    fn task_guard_inc_dec_on_drop() {
        let conn = ClientConnection::new(1, dummy_addr(), MmsServerConnection::new());
        assert_eq!(conn.pending_tasks(), 0);
        {
            let _g = conn.task_guard();
            assert_eq!(conn.pending_tasks(), 1);
            let _g2 = conn.task_guard();
            assert_eq!(conn.pending_tasks(), 2);
        }
        // Dropping both guards returns the count to zero.
        assert_eq!(conn.pending_tasks(), 0);
    }
}
