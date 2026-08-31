//! Server-side dispatcher trait for MMS confirmed requests.
//!
//! This module defines the trait and a default implementation that rejects every
//! request. A dispatcher that serves GetNameList, GetVariableAccessAttributes, Read
//! and Write lives in the server crate, which owns the device model.

use super::connection::MmsServerConnection;
use bytes::Bytes;

/// The raw content of a received ConfirmedRequest.
///
/// The service body is not decoded here; a dispatcher that serves specific services
/// parses it according to its service tag.
#[derive(Debug, Clone)]
pub struct ConfirmedRequest {
    /// invokeID, parsed from the `[0]` field of the ConfirmedRequest.
    pub invoke_id: u32,
    /// Service body bytes, service tag included; GetNameList carries `0xa1`.
    pub service_body: Bytes,
}

/// What a dispatcher returns.
#[derive(Debug, Clone)]
pub enum ConfirmedResponse {
    /// Content of a ConfirmedResponse PDU; the caller adds the outer `0xa1 <len>`.
    Response(Bytes),
    /// Content of a ConfirmedError PDU; the caller adds the outer `0xa2 <len>`.
    Error(Bytes),
    /// A Reject PDU, used for a service the dispatcher does not recognize.
    Reject,
}

/// Routes server-side MMS confirmed requests.
///
/// The implementation in this module rejects everything; a dispatcher backed by a
/// device model serves the real services.
pub trait MmsServiceDispatcher: Send + Sync {
    /// Handles one confirmed request and returns what the caller should send back.
    fn dispatch(&self, conn: &MmsServerConnection, req: ConfirmedRequest) -> ConfirmedResponse;

    /// servicesSupportedCalled bitmap for the Initiate response.
    ///
    /// This is what the server announces to a peer, which uses it to decide which
    /// services to offer and to call. Announcing a service that is not implemented
    /// leads a peer into requests that must fail, so an implementation returns the
    /// bitmap matching what it actually handles.
    ///
    /// No default is provided on purpose: a wrapper such as a logging or metrics layer
    /// would otherwise erase the capabilities of the dispatcher it wraps, so it must
    /// forward or choose explicitly.
    fn services_supported(&self) -> [u8; 11];
}

/// Default dispatcher: every ConfirmedRequest is rejected.
///
/// Used where the association and Initiate negotiation must work but no service is
/// implemented yet.
#[derive(Debug, Default, Clone, Copy)]
pub struct RejectAllDispatcher;

impl MmsServiceDispatcher for RejectAllDispatcher {
    fn dispatch(&self, _conn: &MmsServerConnection, req: ConfirmedRequest) -> ConfirmedResponse {
        tracing::warn!(
            invoke_id = req.invoke_id,
            "rejectalldispatcher: rejecting every confirmed request"
        );
        ConfirmedResponse::Reject
    }

    /// Test scaffolding: association tests need negotiation to succeed, so the baseline
    /// bitmap is reused. This dispatcher serves no peer, so what it announces has no
    /// interoperability effect.
    fn services_supported(&self) -> [u8; 11] {
        super::connection::SERVER_SERVICES_SUPPORTED
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_all_returns_reject() {
        let d = RejectAllDispatcher;
        let conn = MmsServerConnection::new();
        let req = ConfirmedRequest {
            invoke_id: 42,
            service_body: Bytes::from_static(&[0xa1, 0x00]),
        };
        let resp = d.dispatch(&conn, req);
        assert!(matches!(resp, ConfirmedResponse::Reject));
    }
}
