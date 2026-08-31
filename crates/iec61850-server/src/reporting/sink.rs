//! `ChannelReportSink`: routes report PDUs to the connection task over a bounded
//! mpsc channel.
//!
//! A report PDU is produced by `ReportingEngine::tick`, which may run on any task,
//! but only the connection task can write the socket. The receiving task drains the
//! channel and writes each PDU out; when the client is slow, that write blocks, the
//! channel fills, and `try_send` fails with `SendOutcome::WouldBlock`. A bounded
//! channel therefore approximates socket backpressure without touching the socket.
//!
//! The sink knows nothing about metrics: the engine decides what a `WouldBlock`
//! means, counts it, logs it, and closes the connection after enough of them in a
//! row.
//!
//! `REPORT_CHANNEL_CAP` is 32. At a 5 ms buffer time and roughly 200 reports per
//! second, that is about one entry every 5 ms, so 32 slots hold about 160 ms of
//! traffic. A client that consumes nothing for 160 ms is treated as stalled.

use crate::connection::ConnectionId;
use crate::reporting::ReportSink;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Capacity of the bounded report channel, sized for roughly 160 ms of traffic at
/// a 5 ms buffer time and 200 reports per second.
pub const REPORT_CHANNEL_CAP: usize = 32;

// ─────────────────────────────────────────────────────────────────────────────
// SendOutcome
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of one `ChannelReportSink` send attempt.
///
/// The engine reads this to decide whether to count a drop, log a warning, or
/// close the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    /// The PDU is queued and the connection task will write it to the socket.
    Sent,
    /// The channel is full: the PDU was dropped and the caller should count it as
    /// socket backpressure.
    WouldBlock,
    /// The receiver is gone, so the connection task has ended; the caller should
    /// treat the connection as dropped.
    ReceiverDropped,
    /// No channel is registered for this connection.
    NotFound,
}

// ─────────────────────────────────────────────────────────────────────────────
// ChannelReportSink
// ─────────────────────────────────────────────────────────────────────────────

/// Routes report PDUs to per-connection bounded mpsc channels.
///
/// The connection lifecycle calls `register(conn_id, tx)` when a connection is
/// established and `deregister(conn_id)` when it ends. `ReportingEngine` pushes
/// PDUs in through `try_send_pdu`, and the connection task takes them out of the
/// receiver and writes them to the socket.
///
/// The channel is bounded and `try_send_pdu` never blocks; what a full channel
/// means is decided by the caller.
#[derive(Clone, Default)]
pub struct ChannelReportSink {
    inner: Arc<RwLock<HashMap<ConnectionId, mpsc::Sender<Bytes>>>>,
}

impl std::fmt::Debug for ChannelReportSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.inner.read().map(|g| g.len()).unwrap_or(0);
        f.debug_struct("ChannelReportSink")
            .field("connections", &count)
            .finish()
    }
}

impl ChannelReportSink {
    /// Creates an empty sink with no registered connections.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates one bounded channel and returns both ends.
    ///
    /// The connection lifecycle keeps the receiver in its own `select!` and hands
    /// the sender to `register`.
    pub fn create_channel() -> (mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) {
        mpsc::channel(REPORT_CHANNEL_CAP)
    }

    /// Registers the sender for one connection.
    pub fn register(&self, conn_id: ConnectionId, sender: mpsc::Sender<Bytes>) {
        if let Ok(mut g) = self.inner.write() {
            g.insert(conn_id, sender);
        } else {
            tracing::warn!(conn_id, "channel report sink registry mutex poisoned");
        }
    }

    /// Removes the sender for one connection, called when it closes.
    pub fn deregister(&self, conn_id: ConnectionId) {
        if let Ok(mut g) = self.inner.write() {
            g.remove(&conn_id);
        }
    }

    /// Pushes PDU bytes into the channel of one connection.
    ///
    /// This is not the `ReportSink` trait method, because that returns a plain
    /// `bool` and cannot express `WouldBlock`. The engine calls this directly and
    /// acts on the `SendOutcome`.
    pub fn try_send_pdu(&self, conn_id: ConnectionId, pdu: Bytes) -> SendOutcome {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::warn!(conn_id, "channel report sink registry read lock poisoned");
                return SendOutcome::NotFound;
            }
        };
        match g.get(&conn_id) {
            Some(tx) => match tx.try_send(pdu) {
                Ok(()) => SendOutcome::Sent,
                Err(mpsc::error::TrySendError::Full(_)) => SendOutcome::WouldBlock,
                Err(mpsc::error::TrySendError::Closed(_)) => SendOutcome::ReceiverDropped,
            },
            None => SendOutcome::NotFound,
        }
    }
}

/// `ReportSink` implementation for callers that only need a boolean result.
///
/// `WouldBlock` is reported as `true`: the connection is alive and only this PDU
/// was dropped, so `on_connection_dropped` is not triggered and no counter moves.
/// A caller that needs backpressure accounting uses `try_send_pdu` instead.
/// `ReceiverDropped` and `NotFound` both return `false`, which makes the engine
/// release the connection.
impl ReportSink for ChannelReportSink {
    fn send_pdu(&self, conn_id: ConnectionId, pdu: Bytes) -> bool {
        match self.try_send_pdu(conn_id, pdu) {
            SendOutcome::Sent => true,
            SendOutcome::WouldBlock => {
                // This path deliberately keeps no counters; the try_send_pdu path
                // does the accounting.
                tracing::warn!(conn_id, "report pdu dropped: channel full");
                true // the connection is alive, only this pdu was dropped
            }
            SendOutcome::ReceiverDropped => {
                tracing::warn!(
                    conn_id,
                    "report pdu undeliverable: receiver gone, connection treated as closed"
                );
                false
            }
            SendOutcome::NotFound => {
                tracing::warn!(
                    conn_id,
                    "report pdu dropped: no channel registered for this connection"
                );
                false
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[tokio::test]
    async fn register_and_send_pdu_delivers_bytes() {
        let sink = ChannelReportSink::new();
        let (tx, mut rx) = ChannelReportSink::create_channel();
        sink.register(1, tx);

        let pdu = Bytes::from_static(b"\xa3\x00");
        let outcome = sink.try_send_pdu(1, pdu.clone());
        assert_eq!(outcome, SendOutcome::Sent, "try_send_pdu must report Sent");

        let received = rx.recv().await.unwrap();
        assert_eq!(received, pdu, "the received pdu must match the one sent");
    }

    #[tokio::test]
    async fn send_pdu_unregistered_conn_returns_not_found() {
        let sink = ChannelReportSink::new();
        let pdu = Bytes::from_static(b"\xa3\x00");
        let outcome = sink.try_send_pdu(999, pdu);
        assert_eq!(
            outcome,
            SendOutcome::NotFound,
            "an unregistered connection must report NotFound"
        );
    }

    #[tokio::test]
    async fn deregister_removes_sender() {
        let sink = ChannelReportSink::new();
        let (tx, _rx) = ChannelReportSink::create_channel();
        sink.register(2, tx);
        sink.deregister(2);

        let pdu = Bytes::from_static(b"\xa3\x00");
        let outcome = sink.try_send_pdu(2, pdu);
        assert_eq!(
            outcome,
            SendOutcome::NotFound,
            "try_send_pdu must report NotFound after deregister"
        );
    }

    #[tokio::test]
    async fn send_pdu_dropped_receiver_returns_receiver_dropped() {
        let sink = ChannelReportSink::new();
        let (tx, rx) = ChannelReportSink::create_channel();
        sink.register(3, tx);
        drop(rx); // simulates the connection task ending

        let pdu = Bytes::from_static(b"\xa3\x00");
        let outcome = sink.try_send_pdu(3, pdu);
        assert_eq!(
            outcome,
            SendOutcome::ReceiverDropped,
            "try_send_pdu must report ReceiverDropped once the receiver is gone"
        );
    }

    #[tokio::test]
    async fn channel_full_returns_would_block() {
        let sink = ChannelReportSink::new();
        let (tx, _rx) = ChannelReportSink::create_channel();
        sink.register(4, tx);

        // Fill the channel without consuming anything.
        let pdu = Bytes::from_static(b"\xa3\x00");
        for _ in 0..REPORT_CHANNEL_CAP {
            let outcome = sink.try_send_pdu(4, pdu.clone());
            assert_eq!(
                outcome,
                SendOutcome::Sent,
                "every pdu up to the cap must be Sent"
            );
        }

        // One past the capacity must report WouldBlock.
        let outcome = sink.try_send_pdu(4, pdu.clone());
        assert_eq!(
            outcome,
            SendOutcome::WouldBlock,
            "a full channel must report WouldBlock"
        );
    }

    /// The trait method reports success on `WouldBlock`, keeping the connection.
    #[tokio::test]
    async fn report_sink_trait_would_block_returns_true() {
        let sink = ChannelReportSink::new();
        let (tx, _rx) = ChannelReportSink::create_channel();
        sink.register(5, tx);

        let pdu = Bytes::from_static(b"\xa3\x00");
        // fill the channel
        for _ in 0..REPORT_CHANNEL_CAP {
            ReportSink::send_pdu(&sink, 5, pdu.clone());
        }
        // WouldBlock must still report success
        let ok = ReportSink::send_pdu(&sink, 5, pdu.clone());
        assert!(
            ok,
            "ReportSink::send_pdu must report true on WouldBlock, keeping the connection"
        );
    }
}
