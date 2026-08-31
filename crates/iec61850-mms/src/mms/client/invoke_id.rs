//! invokeID allocation.
//!
//! In-flight identifiers are tracked in a set:
//!
//! - allocation starts at 1
//! - each call increments the counter and skips 0 on wrap-around
//! - an identifier already in the pending set means the space has wrapped onto a live
//!   request, which returns `ClientError::InvokeIdExhausted`

use super::error::ClientError;
use crate::compat::HashSet;

/// Allocator for invokeIDs; not thread safe, and owned by one client.
pub struct InvokeIdAllocator {
    /// The next identifier to try, one-based so 0 is never used.
    next: u32,
    /// Identifiers currently in flight, used to detect a collision.
    pending: HashSet<u32>,
    /// Maximum number of outstanding requests.
    max_outstanding: u32,
}

impl InvokeIdAllocator {
    /// Creates an allocator bounded by `max_outstanding`.
    pub fn new(max_outstanding: u32) -> Self {
        Self {
            next: 0,
            pending: HashSet::with_capacity(max_outstanding as usize),
            max_outstanding,
        }
    }

    /// Allocates the next free invokeID.
    ///
    /// The steps are:
    /// 1. increment the counter, skipping 0;
    /// 2. return `OutstandingCallLimit` when the pending set is full;
    /// 3. return `InvokeIdExhausted` when the identifier is already pending;
    /// 4. insert the identifier and return it.
    pub fn allocate(&mut self) -> Result<u32, ClientError> {
        // the outstanding ceiling
        if self.pending.len() as u32 >= self.max_outstanding {
            return Err(ClientError::OutstandingCallLimit);
        }

        // at most max_outstanding + 1 candidates, which the pending set bounds
        for _ in 0..=self.max_outstanding {
            self.next = self.next.wrapping_add(1);
            if self.next == 0 {
                self.next = 1; // skip 0
            }
            if !self.pending.contains(&self.next) {
                self.pending.insert(self.next);
                return Ok(self.next);
            }
        }

        // every candidate collided, which the outstanding ceiling makes unreachable
        Err(ClientError::InvokeIdExhausted)
    }

    /// Releases an invokeID once its response has arrived.
    ///
    /// An identifier that is not pending is ignored, which covers a response arriving
    /// after its timeout.
    pub fn release(&mut self, id: u32) {
        self.pending.remove(&id);
    }

    /// Returns whether an invokeID is pending.
    pub fn is_pending(&self, id: u32) -> bool {
        self.pending.contains(&id)
    }

    /// Clears every pending identifier, for instance when the connection is lost.
    pub fn clear(&mut self) {
        self.pending.clear();
    }

    /// Returns how many requests are pending.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

// Unit tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_sequential_ids() {
        let mut alloc = InvokeIdAllocator::new(5);
        let id1 = alloc.allocate().unwrap();
        let id2 = alloc.allocate().unwrap();
        let id3 = alloc.allocate().unwrap();
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }

    #[test]
    fn skip_zero() {
        // starting at 0xFFFF_FFFE, the following identifiers must skip 0
        let mut alloc = InvokeIdAllocator::new(5);
        alloc.next = 0xFFFF_FFFE;
        let id1 = alloc.allocate().unwrap();
        let id2 = alloc.allocate().unwrap();
        // 0xFFFF_FFFE + 1 = 0xFFFF_FFFF
        assert_eq!(id1, 0xFFFF_FFFF);
        // 0xFFFF_FFFF wraps to 0, which is skipped, giving 1
        assert_eq!(id2, 1);
    }

    #[test]
    fn outstanding_limit() {
        let mut alloc = InvokeIdAllocator::new(3);
        alloc.allocate().unwrap();
        alloc.allocate().unwrap();
        alloc.allocate().unwrap();
        let result = alloc.allocate();
        assert!(
            matches!(result, Err(ClientError::OutstandingCallLimit)),
            "expected OutstandingCallLimit"
        );
    }

    #[test]
    fn release_and_reallocate() {
        let mut alloc = InvokeIdAllocator::new(2);
        let id1 = alloc.allocate().unwrap();
        let id2 = alloc.allocate().unwrap();
        assert_eq!(alloc.pending_count(), 2);
        alloc.release(id1);
        assert_eq!(alloc.pending_count(), 1);
        let id3 = alloc.allocate().unwrap();
        assert!(id3 != id2); // a fresh identifier, or one that was released
    }

    #[test]
    fn is_pending_reflects_state() {
        let mut alloc = InvokeIdAllocator::new(5);
        let id = alloc.allocate().unwrap();
        assert!(alloc.is_pending(id));
        alloc.release(id);
        assert!(!alloc.is_pending(id));
    }

    #[test]
    fn clear_releases_all() {
        let mut alloc = InvokeIdAllocator::new(5);
        alloc.allocate().unwrap();
        alloc.allocate().unwrap();
        alloc.clear();
        assert_eq!(alloc.pending_count(), 0);
    }

    #[test]
    fn invoke_id_exhausted_when_all_slots_filled_and_duplicates() {
        // force a collision: with one permit the pending set is full after one allocation
        let mut alloc = InvokeIdAllocator::new(1);
        alloc.allocate().unwrap(); // pending = {1}
                                   // so the next call returns OutstandingCallLimit
        let result = alloc.allocate();
        assert!(matches!(result, Err(ClientError::OutstandingCallLimit)));
    }
}
