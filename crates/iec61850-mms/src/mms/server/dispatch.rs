//! MMS server PDU dispatch.
//!
//! ## Overview
//!
//! Raw MMS PDU bytes, already stripped of the ACSE, Presentation, Session and COTP
//! wrappers, are routed to a handler that returns a [`MessageOutcome`]; the caller
//! decides what to do with it.
//!
//! ```text
//! incoming MMS payload (Bytes)
//!     |
//!     +-- 0xa8: Initiate request -> MessageOutcome::SendInitiateResponse / SendInitiateError
//!     +-- 0xa0: Confirmed request -> dispatcher.dispatch() -> SendResponse / SendError / SendReject
//!     +-- 0x8b: Conclude request -> SendConcludeResponse (caller marks concluded)
//!     +-- 0xa4: Reject received -> ignored, logged at debug level
//!     +-- 0x00: indefinite-length end tag -> ignored
//!     +-- default -> SendReject(unknown PDU type)
//!     +-- fewer than 2 bytes, or a length that fails to decode -> SendReject(invalid PDU)
//! ```
//!
//! ## Error handling
//!
//! Every input produces an outcome, so a peer is never left waiting on a request
//! the server has already discarded.
//!
//! - A PDU shorter than 2 bytes, or one whose length field fails to decode, is
//!   answered with `Reject(pdu-error/invalid-pdu)` and logged at warn level.
//! - An unrecognized PDU tag is answered with `Reject(unknown PDU type)`.
//! - A request arriving while the connection blocks requests is answered with
//!   `Reject(confirmedrequest/other)` and logged at warn level.
//! - An incoming `0xa4` Reject is logged at debug level and otherwise ignored:
//!   answering a reject with a reject would loop between the two peers.
//!
//! ## Contract with the caller
//!
//! - `parse_message` does not mutate `MmsServerConnection` state.
//! - Initiate negotiation stays in `super::initiate::negotiate_initiate`; this
//!   module only routes.
//! - On `MessageOutcome::SendConcludeResponse` the caller must both send the wire
//!   bytes and call `conn.mark_concluded()`, which starts the release timeout.

use bytes::{Bytes, BytesMut};

use super::super::pdu::reject::{
    ConfirmedRequestRejectReason, PduErrorRejectReason, RejectPdu, RejectReason,
};
use super::connection::MmsServerConnection;
use super::dispatcher::{ConfirmedRequest, ConfirmedResponse, MmsServiceDispatcher};
use super::initiate::{negotiate_initiate, InitiateOutcome};

// Public types

/// The result of dispatching one PDU.
///
/// The caller uses it to decide which wire bytes to send, whether to mark the
/// association concluded, and whether to close the transport.
#[derive(Debug, Clone)]
pub enum MessageOutcome {
    /// The Initiate request was accepted: send the Initiate response bytes and pass
    /// `params` to `MmsServerConnection::set_negotiated`.
    SendInitiateResponse {
        /// Encoded Initiate response to send.
        response_bytes: Bytes,
        /// Parameters the caller stores in the connection.
        params: super::connection::NegotiatedParams,
    },
    /// The Initiate request was refused: send the Initiate error bytes, then close.
    ///
    /// The error is sent before closing so the peer learns why it was refused.
    SendInitiateErrorAndClose {
        /// Encoded Initiate error to send before closing.
        error_bytes: Bytes,
    },
    /// Wire bytes of an ordinary ConfirmedResponse, ConfirmedError or Reject.
    SendBytes(Bytes),
    /// An MMS Conclude response (`0x8c 0x00`) is ready. After sending it the caller
    /// must call `conn.mark_concluded()` to start the release timeout.
    SendConcludeResponse {
        /// Encoded Conclude response to send.
        response_bytes: Bytes,
    },
    /// A Reject was received: nothing is sent in response.
    Silent,
}

// PDU routing

/// Parses and dispatches one MMS PDU.
///
/// `incoming` is the raw MMS PDU, stripped of the ACSE, Presentation, Session and
/// COTP wrappers.
///
/// `dispatcher` handles ConfirmedRequest services.
///
/// A malformed PDU is always answered:
/// - fewer than 2 bytes, or a length that fails to decode, yields
///   Reject(pdu-error / invalid-pdu)
/// - a blocked or already concluded connection yields Reject(other) and a warning
pub fn parse_message(
    conn: &MmsServerConnection,
    dispatcher: &dyn MmsServiceDispatcher,
    incoming: &[u8],
) -> MessageOutcome {
    // A blocked or already concluded connection still answers with a Reject, so the
    // peer learns the server will not serve the request rather than waiting.
    if conn.block_requests() {
        tracing::warn!("requests are blocked, answering reject(confirmedrequest/other)");
        return MessageOutcome::SendBytes(encode_reject_pdu(
            None,
            RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::Other),
        ));
    }
    if conn.is_concluded() {
        tracing::warn!(
            "pdu received after the association was concluded, answering reject(pdu-error/invalid-pdu)"
        );
        return MessageOutcome::SendBytes(encode_reject_pdu(
            None,
            RejectReason::PduError(PduErrorRejectReason::InvalidPdu),
        ));
    }

    // A PDU shorter than a tag plus a length byte is rejected explicitly.
    if incoming.len() < 2 {
        tracing::warn!(
            size = incoming.len(),
            "mms pdu shorter than 2 bytes, answering reject(pdu-error/invalid-pdu)"
        );
        return MessageOutcome::SendBytes(encode_reject_pdu(
            None,
            RejectReason::PduError(PduErrorRejectReason::InvalidPdu),
        ));
    }

    let tag = incoming[0];
    match tag {
        // Initiate request
        0xa8 => {
            tracing::debug!("dispatching an initiate request");
            match negotiate_initiate(incoming, dispatcher.services_supported()) {
                InitiateOutcome::Accepted {
                    params,
                    response_bytes,
                } => MessageOutcome::SendInitiateResponse {
                    response_bytes: response_bytes.freeze(),
                    params,
                },
                InitiateOutcome::Rejected {
                    reason,
                    error_bytes,
                } => {
                    tracing::warn!(
                        ?reason,
                        "initiate request refused, sending an initiate error and closing"
                    );
                    MessageOutcome::SendInitiateErrorAndClose {
                        error_bytes: error_bytes.freeze(),
                    }
                }
            }
        }

        // Confirmed request
        0xa0 => {
            // extract the invokeID and the service body
            let (invoke_id, service_body) = match parse_confirmed_request(incoming) {
                Ok(v) => v,
                Err(reject_reason) => {
                    tracing::warn!(
                        ?reject_reason,
                        "confirmed request failed to decode, answering with a reject"
                    );
                    return MessageOutcome::SendBytes(encode_reject_pdu(None, reject_reason));
                }
            };

            // Enforce the negotiated maxServOutstandingCalling: request N+1 is answered
            // with Reject(confirmedRequest / maxServOutstandingExceeded). The permit is
            // held here and released when `_outstanding_permit` is dropped, whatever the
            // dispatcher returns.
            let _outstanding_permit = match conn.try_acquire_outstanding() {
                Some(p) => p,
                None => {
                    tracing::warn!(
                        invoke_id,
                        "outstanding request cap reached, answering reject(confirmedrequest/maxservoutstandingexceeded)"
                    );
                    return MessageOutcome::SendBytes(encode_reject_pdu(
                        Some(invoke_id),
                        RejectReason::ConfirmedRequest(
                            ConfirmedRequestRejectReason::MaxServOutstandingExceeded,
                        ),
                    ));
                }
            };

            let resp = dispatcher.dispatch(
                conn,
                ConfirmedRequest {
                    invoke_id,
                    service_body: service_body.clone(),
                },
            );
            match resp {
                ConfirmedResponse::Response(bytes) => MessageOutcome::SendBytes(bytes),
                ConfirmedResponse::Error(bytes) => MessageOutcome::SendBytes(bytes),
                ConfirmedResponse::Reject => {
                    // A reject from the dispatcher means the service was not recognized.
                    let bytes = encode_reject_pdu(
                        Some(invoke_id),
                        RejectReason::ConfirmedRequest(
                            ConfirmedRequestRejectReason::UnrecognizedService,
                        ),
                    );
                    MessageOutcome::SendBytes(bytes)
                }
            }
        }

        // MMS Conclude request
        //
        // Answered with a Conclude response; the transport stays open and is closed by
        // the session layer. The caller starts a timeout so a peer that never finishes
        // the release cannot hold the connection open.
        0x8b => {
            // strict check: tag 0x8b must carry length 0
            if incoming.len() < 2 || incoming[1] != 0x00 {
                tracing::warn!(
                    "conclude request length is not 0, answering reject(pdu-error/invalid-pdu)"
                );
                return MessageOutcome::SendBytes(encode_reject_pdu(
                    None,
                    RejectReason::PduError(PduErrorRejectReason::InvalidPdu),
                ));
            }
            tracing::debug!("dispatching a conclude request, answering with a conclude response");
            let response_bytes = Bytes::from_static(&[0x8c, 0x00]);
            MessageOutcome::SendConcludeResponse { response_bytes }
        }

        // Reject received
        //
        // A Reject from the peer is logged and otherwise ignored.
        0xa4 => {
            // decoded only for the log line; a failure here is not fatal
            match RejectPdu::decode(incoming) {
                Ok(pdu) => {
                    tracing::debug!(
                        invoke_id = ?pdu.invoke_id,
                        reason = ?pdu.reason,
                        "received a reject from the peer, ignoring it"
                    );
                }
                Err(e) => {
                    tracing::debug!(
                        error = %e,
                        "received a malformed reject pdu, ignoring it"
                    );
                }
            }
            MessageOutcome::Silent
        }

        // indefinite-length end tag
        0x00 => {
            tracing::debug!("received an indefinite-length end tag (0x00), ignoring it");
            MessageOutcome::Silent
        }

        // PDUs the server itself sends must not arrive from a peer
        //
        // Receiving one is treated as a PDU error.
        0xa9 | 0xaa | 0x8c => {
            tracing::warn!(
                tag = format!("0x{:02X}", tag),
                "received a tag the server itself sends, answering reject(pdu-error/unknown-pdu-type)"
            );
            MessageOutcome::SendBytes(encode_reject_pdu(
                None,
                RejectReason::PduError(PduErrorRejectReason::UnknownPduType),
            ))
        }

        // any other tag
        unknown => {
            tracing::warn!(
                tag = format!("0x{:02X}", unknown),
                "unknown pdu tag, answering reject(pdu-error/unknown-pdu-type)"
            );
            MessageOutcome::SendBytes(encode_reject_pdu(
                None,
                RejectReason::PduError(PduErrorRejectReason::UnknownPduType),
            ))
        }
    }
}

// ConfirmedRequest invokeID extraction

/// Extracts the invokeID and the service body from a complete ConfirmedRequest PDU,
/// outer `0xa0 <len>` included.
///
/// On failure returns the `RejectReason` the caller encodes into a RejectPdu.
///
/// Only the short form and the one- and two-byte long forms of a BER length are
/// accepted; any other form is rejected. Every field is bounds checked against the
/// buffer, so no read runs past the end.
fn parse_confirmed_request(data: &[u8]) -> Result<(u32, Bytes), RejectReason> {
    // the caller has already checked data.len() >= 2 and data[0] == 0xa0
    debug_assert_eq!(data[0], 0xa0);
    if data.len() < 2 {
        return Err(RejectReason::PduError(PduErrorRejectReason::InvalidPdu));
    }

    // outer length
    let (outer_len, outer_hdr) = decode_ber_length(&data[1..])
        .map_err(|()| RejectReason::PduError(PduErrorRejectReason::InvalidPdu))?;
    let inner_start = 1 + outer_hdr;
    let inner_end = inner_start
        .checked_add(outer_len)
        .ok_or(RejectReason::PduError(PduErrorRejectReason::InvalidPdu))?;
    if inner_end > data.len() {
        return Err(RejectReason::PduError(PduErrorRejectReason::InvalidPdu));
    }
    let inner = &data[inner_start..inner_end];

    // invokeID, encoded as 0x02 <len> <bytes>
    if inner.len() < 2 || inner[0] != 0x02 {
        return Err(RejectReason::ConfirmedRequest(
            ConfirmedRequestRejectReason::InvalidArgument,
        ));
    }
    let (id_len, id_hdr) = decode_ber_length(&inner[1..]).map_err(|()| {
        RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::InvalidArgument)
    })?;
    let id_start = 1 + id_hdr;
    let id_end = id_start
        .checked_add(id_len)
        .ok_or(RejectReason::ConfirmedRequest(
            ConfirmedRequestRejectReason::InvalidArgument,
        ))?;
    if id_end > inner.len() {
        return Err(RejectReason::ConfirmedRequest(
            ConfirmedRequestRejectReason::InvalidArgument,
        ));
    }
    let invoke_id = decode_uint32_be(&inner[id_start..id_end]);

    // the service body runs from the end of the invokeID to the end of the content
    let service_body = Bytes::copy_from_slice(&inner[id_end..]);
    Ok((invoke_id, service_body))
}

/// Decodes a BER definite length, accepting the short form and long forms of one or
/// two length bytes.
///
/// Returns the length value and the number of header bytes consumed. The indefinite
/// form and longer long forms are rejected.
fn decode_ber_length(data: &[u8]) -> Result<(usize, usize), ()> {
    if data.is_empty() {
        return Err(());
    }
    let b0 = data[0];
    if b0 < 0x80 {
        Ok((b0 as usize, 1))
    } else if b0 == 0x81 {
        if data.len() < 2 {
            return Err(());
        }
        Ok((data[1] as usize, 2))
    } else if b0 == 0x82 {
        if data.len() < 3 {
            return Err(());
        }
        Ok((((data[1] as usize) << 8) | (data[2] as usize), 3))
    } else {
        Err(())
    }
}

/// Decodes a big-endian unsigned integer of 1 to 4 bytes; an empty slice yields 0.
fn decode_uint32_be(v: &[u8]) -> u32 {
    let mut acc = 0u32;
    for &b in v.iter().take(5) {
        acc = acc.wrapping_shl(8) | (b as u32);
    }
    acc
}

// Reject PDU encode helper

/// Encodes a `RejectReason` into complete RejectPdu wire bytes, outer `0xa4 <len>`
/// included.
pub fn encode_reject_pdu(invoke_id: Option<u32>, reason: RejectReason) -> Bytes {
    let pdu = RejectPdu { invoke_id, reason };
    let mut buf = BytesMut::new();
    pdu.encode(&mut buf);
    buf.freeze()
}

// Unit tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mms::server::dispatcher::RejectAllDispatcher;
    use crate::mms::server::NegotiatedParams;

    fn fresh_conn() -> MmsServerConnection {
        MmsServerConnection::new()
    }

    fn negotiated_conn() -> MmsServerConnection {
        let mut c = MmsServerConnection::new();
        c.set_negotiated(NegotiatedParams::default());
        c
    }

    // dispatch by tag

    #[test]
    fn dispatch_initiate_request_accepted() {
        // encode a default InitiateRequestPdu and feed it in
        let req = crate::mms::pdu::initiate::InitiateRequestPdu::default();
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let conn = fresh_conn();
        let dispatcher = RejectAllDispatcher;
        let outcome = parse_message(&conn, &dispatcher, &buf);
        assert!(matches!(
            outcome,
            MessageOutcome::SendInitiateResponse { .. }
        ));
    }

    #[test]
    fn dispatch_initiate_request_rejected_size_too_small() {
        // a PDU negotiate_initiate refuses, because local_detail_calling is too small
        let req = crate::mms::pdu::initiate::InitiateRequestPdu {
            local_detail_calling: Some(32), // < MIN_PDU_SIZE
            ..Default::default()
        };
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let conn = fresh_conn();
        let dispatcher = RejectAllDispatcher;
        let outcome = parse_message(&conn, &dispatcher, &buf);
        assert!(matches!(
            outcome,
            MessageOutcome::SendInitiateErrorAndClose { .. }
        ));
    }

    #[test]
    fn dispatch_confirmed_request_invokes_dispatcher() {
        // negotiated already; send 0xa0 with content 0x02 0x01 0x05 and body 0xa1 0x00,
        // giving outer length 5: 0xa0 0x05 0x02 0x01 0x05 0xa1 0x00
        let pdu: &[u8] = &[0xa0, 0x05, 0x02, 0x01, 0x05, 0xa1, 0x00];
        let conn = negotiated_conn();
        let dispatcher = RejectAllDispatcher;
        let outcome = parse_message(&conn, &dispatcher, pdu);
        match outcome {
            MessageOutcome::SendBytes(b) => {
                // RejectAllDispatcher -> unrecognized-service Reject
                assert_eq!(b[0], 0xa4, "a reject must carry the outer tag 0xa4");
            }
            other => panic!("expected SendBytes(reject), got {:?}", other),
        }
    }

    #[test]
    fn dispatch_confirmed_request_invalid_invoke_id_tag() {
        // no invokeId tag (0x02), so the reason is invalid-argument
        let pdu: &[u8] = &[0xa0, 0x02, 0xff, 0x00];
        let conn = negotiated_conn();
        let dispatcher = RejectAllDispatcher;
        let outcome = parse_message(&conn, &dispatcher, pdu);
        match outcome {
            MessageOutcome::SendBytes(b) => {
                assert_eq!(b[0], 0xa4);
                // decode the reject to inspect its reason
                let pdu = RejectPdu::decode(&b).unwrap();
                assert!(matches!(
                    pdu.reason,
                    RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::InvalidArgument)
                ));
            }
            other => panic!("expected SendBytes(reject), got {:?}", other),
        }
    }

    #[test]
    fn dispatch_conclude_request_returns_response() {
        let pdu: &[u8] = &[0x8b, 0x00];
        let conn = negotiated_conn();
        let dispatcher = RejectAllDispatcher;
        let outcome = parse_message(&conn, &dispatcher, pdu);
        match outcome {
            MessageOutcome::SendConcludeResponse { response_bytes } => {
                assert_eq!(&response_bytes[..], &[0x8c, 0x00]);
            }
            other => panic!("expected SendConcludeResponse, got {:?}", other),
        }
    }

    #[test]
    fn dispatch_conclude_request_nonzero_length_rejected() {
        // 0x8b with a non-zero length is rejected, since the NULL body must be empty
        let pdu: &[u8] = &[0x8b, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00];
        let conn = negotiated_conn();
        let dispatcher = RejectAllDispatcher;
        let outcome = parse_message(&conn, &dispatcher, pdu);
        match outcome {
            MessageOutcome::SendBytes(b) => {
                let pdu = RejectPdu::decode(&b).unwrap();
                assert!(matches!(
                    pdu.reason,
                    RejectReason::PduError(PduErrorRejectReason::InvalidPdu)
                ));
            }
            other => panic!("expected SendBytes(reject), got {:?}", other),
        }
    }

    #[test]
    fn dispatch_reject_received_silent() {
        // a received reject is ignored and only logged
        let pdu: &[u8] = &[0xa4, 0x03, 0x81, 0x01, 0x00];
        let conn = negotiated_conn();
        let dispatcher = RejectAllDispatcher;
        let outcome = parse_message(&conn, &dispatcher, pdu);
        assert!(matches!(outcome, MessageOutcome::Silent));
    }

    #[test]
    fn dispatch_indefinite_end_tag_silent() {
        // two bytes, so the minimum-size check passes
        let pdu: &[u8] = &[0x00, 0x00];
        let conn = negotiated_conn();
        let dispatcher = RejectAllDispatcher;
        let outcome = parse_message(&conn, &dispatcher, pdu);
        assert!(matches!(outcome, MessageOutcome::Silent));
    }

    #[test]
    fn dispatch_unknown_tag_returns_reject_unknown_pdu_type() {
        let pdu: &[u8] = &[0xff, 0x00];
        let conn = negotiated_conn();
        let dispatcher = RejectAllDispatcher;
        let outcome = parse_message(&conn, &dispatcher, pdu);
        match outcome {
            MessageOutcome::SendBytes(b) => {
                let r = RejectPdu::decode(&b).unwrap();
                assert!(matches!(
                    r.reason,
                    RejectReason::PduError(PduErrorRejectReason::UnknownPduType)
                ));
            }
            other => panic!(
                "an unknown tag must yield SendBytes(reject), got {:?}",
                other
            ),
        }
    }

    #[test]
    fn dispatch_server_only_tags_rejected() {
        // 0xa9, 0xaa and 0x8c are sent by the server, so receiving one is a pdu error
        for tag in [0xa9u8, 0xaa, 0x8c] {
            let pdu = [tag, 0x00];
            let conn = negotiated_conn();
            let dispatcher = RejectAllDispatcher;
            let outcome = parse_message(&conn, &dispatcher, &pdu);
            match outcome {
                MessageOutcome::SendBytes(b) => {
                    let r = RejectPdu::decode(&b).unwrap();
                    assert!(
                        matches!(
                            r.reason,
                            RejectReason::PduError(PduErrorRejectReason::UnknownPduType)
                        ),
                        "tag 0x{:02X} must yield unknown-pdu-type",
                        tag
                    );
                }
                other => panic!(
                    "tag 0x{:02X} must yield SendBytes(reject), got {:?}",
                    tag, other
                ),
            }
        }
    }

    // a malformed PDU is answered with a reject

    #[test]
    fn empty_pdu_returns_reject() {
        let conn = negotiated_conn();
        let dispatcher = RejectAllDispatcher;
        let outcome = parse_message(&conn, &dispatcher, &[]);
        match outcome {
            MessageOutcome::SendBytes(b) => {
                let r = RejectPdu::decode(&b).unwrap();
                assert!(matches!(
                    r.reason,
                    RejectReason::PduError(PduErrorRejectReason::InvalidPdu)
                ));
            }
            other => panic!("an empty pdu must yield SendBytes(reject), got {:?}", other),
        }
    }

    #[test]
    fn one_byte_pdu_returns_reject() {
        let conn = negotiated_conn();
        let dispatcher = RejectAllDispatcher;
        let outcome = parse_message(&conn, &dispatcher, &[0xa0]);
        match outcome {
            MessageOutcome::SendBytes(b) => {
                let r = RejectPdu::decode(&b).unwrap();
                assert!(matches!(
                    r.reason,
                    RejectReason::PduError(PduErrorRejectReason::InvalidPdu)
                ));
            }
            other => panic!(
                "a one-byte pdu must yield SendBytes(reject), got {:?}",
                other
            ),
        }
    }

    // maxServOutstandingCalling enforcement

    /// Builds a negotiated connection whose outstanding permit count is `cap`.
    fn negotiated_conn_with_outstanding_cap(cap: u16) -> MmsServerConnection {
        let mut c = MmsServerConnection::new();
        c.set_negotiated(NegotiatedParams {
            max_serv_outstanding_calling: cap,
            ..Default::default()
        });
        c
    }

    #[test]
    fn outstanding_cap_rejects_n_plus_1_request() {
        // two permits, both taken, standing in for two requests already in flight
        let conn = negotiated_conn_with_outstanding_cap(2);
        let dispatcher = RejectAllDispatcher;
        let p1 = conn.try_acquire_outstanding().expect("permit 1");
        let p2 = conn.try_acquire_outstanding().expect("permit 2");
        assert_eq!(conn.outstanding_available(), 0);

        // the third confirmed request, invokeId 0x42, must be rejected
        let pdu: &[u8] = &[0xa0, 0x05, 0x02, 0x01, 0x42, 0xa1, 0x00];
        let outcome = parse_message(&conn, &dispatcher, pdu);
        match outcome {
            MessageOutcome::SendBytes(b) => {
                let r = RejectPdu::decode(&b).unwrap();
                assert_eq!(r.invoke_id, Some(0x42), "a reject must carry the invokeId");
                assert!(
                    matches!(
                        r.reason,
                        RejectReason::ConfirmedRequest(
                            ConfirmedRequestRejectReason::MaxServOutstandingExceeded
                        )
                    ),
                    "expected MaxServOutstandingExceeded, got {:?}",
                    r.reason
                );
            }
            other => panic!("expected SendBytes(reject), got {:?}", other),
        }

        // releasing a permit lets the next confirmed request reach the dispatcher, which
        // answers UnrecognizedService rather than an outstanding-limit reject
        drop(p1);
        assert_eq!(conn.outstanding_available(), 1);
        let outcome = parse_message(&conn, &dispatcher, pdu);
        match outcome {
            MessageOutcome::SendBytes(b) => {
                let r = RejectPdu::decode(&b).unwrap();
                assert!(
                    matches!(
                        r.reason,
                        RejectReason::ConfirmedRequest(
                            ConfirmedRequestRejectReason::UnrecognizedService
                        )
                    ),
                    "after a permit is released the request must reach the dispatcher, got {:?}",
                    r.reason
                );
            }
            other => panic!("expected SendBytes(reject), got {:?}", other),
        }
        // the dispatcher releases its permit, bringing the count back to 1
        assert_eq!(conn.outstanding_available(), 1);
        drop(p2);
        assert_eq!(conn.outstanding_available(), 2);
    }

    /// A peer that ignores the announced capabilities and sends an unsupported PDU,
    /// here a Cancel request (0x85), still receives a RejectPDU rather than silence,
    /// so it never waits indefinitely for an answer.
    #[test]
    fn unsupported_cancel_pdu_still_gets_reject_response() {
        let conn = negotiated_conn_with_outstanding_cap(5);
        let dispatcher = RejectAllDispatcher;
        let cancel: &[u8] = &[0x85, 0x03, 0x02, 0x01, 0x07];
        match parse_message(&conn, &dispatcher, cancel) {
            MessageOutcome::SendBytes(b) => {
                RejectPdu::decode(&b).expect("the answer must be a decodable RejectPDU");
            }
            other => panic!(
                "a cancel request must be answered with a reject, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn outstanding_permit_released_after_dispatch() {
        // one permit: it must be released after dispatch so the next request passes
        let conn = negotiated_conn_with_outstanding_cap(1);
        let dispatcher = RejectAllDispatcher;
        let pdu: &[u8] = &[0xa0, 0x05, 0x02, 0x01, 0x01, 0xa1, 0x00];

        for _ in 0..3 {
            let outcome = parse_message(&conn, &dispatcher, pdu);
            match outcome {
                MessageOutcome::SendBytes(b) => {
                    let r = RejectPdu::decode(&b).unwrap();
                    // all three must reach the dispatcher, which answers
                    // UnrecognizedService, rather than hitting the outstanding limit
                    assert!(
                        matches!(
                            r.reason,
                            RejectReason::ConfirmedRequest(
                                ConfirmedRequestRejectReason::UnrecognizedService
                            )
                        ),
                        "the permit must be released after each dispatch, got {:?}",
                        r.reason
                    );
                }
                other => panic!("expected SendBytes(reject), got {:?}", other),
            }
            assert_eq!(
                conn.outstanding_available(),
                1,
                "the permit must be returned after each parse_message"
            );
        }
    }

    #[test]
    fn outstanding_cap_invokes_id_unaffected_by_permits() {
        // an outstanding-exceeded reject must carry the multi-byte invokeId unchanged
        let conn = negotiated_conn_with_outstanding_cap(1);
        let _hold = conn
            .try_acquire_outstanding()
            .expect("hold the only permit");
        let dispatcher = RejectAllDispatcher;
        // invokeId 0x1234, two bytes
        let pdu: &[u8] = &[0xa0, 0x06, 0x02, 0x02, 0x12, 0x34, 0xa1, 0x00];
        let outcome = parse_message(&conn, &dispatcher, pdu);
        match outcome {
            MessageOutcome::SendBytes(b) => {
                let r = RejectPdu::decode(&b).unwrap();
                assert_eq!(r.invoke_id, Some(0x1234));
                assert!(matches!(
                    r.reason,
                    RejectReason::ConfirmedRequest(
                        ConfirmedRequestRejectReason::MaxServOutstandingExceeded
                    )
                ));
            }
            other => panic!("expected SendBytes(reject), got {:?}", other),
        }
    }

    // blocked and concluded connections answer with a reject

    #[test]
    fn block_requests_returns_reject_other() {
        let mut conn = negotiated_conn();
        conn.set_block_requests(true);
        let dispatcher = RejectAllDispatcher;
        let pdu: &[u8] = &[0xa0, 0x05, 0x02, 0x01, 0x01, 0xa1, 0x00];
        let outcome = parse_message(&conn, &dispatcher, pdu);
        match outcome {
            MessageOutcome::SendBytes(b) => {
                let r = RejectPdu::decode(&b).unwrap();
                assert!(matches!(
                    r.reason,
                    RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::Other)
                ));
            }
            other => panic!(
                "a blocked connection must yield SendBytes(reject), got {:?}",
                other
            ),
        }
    }

    #[test]
    fn already_concluded_returns_reject_invalid_pdu() {
        let mut conn = negotiated_conn();
        conn.mark_concluded();
        let dispatcher = RejectAllDispatcher;
        let pdu: &[u8] = &[0x8b, 0x00];
        let outcome = parse_message(&conn, &dispatcher, pdu);
        match outcome {
            MessageOutcome::SendBytes(b) => {
                let r = RejectPdu::decode(&b).unwrap();
                assert!(matches!(
                    r.reason,
                    RejectReason::PduError(PduErrorRejectReason::InvalidPdu)
                ));
            }
            other => panic!(
                "a concluded connection must yield SendBytes(reject), got {:?}",
                other
            ),
        }
    }

    // parse_confirmed_request paths

    #[test]
    fn parse_confirmed_request_happy() {
        // 0xa0 0x06 0x02 0x02 0x01 0x2a 0xa1 0x00
        // outer_len=6 (inner 6 bytes), invokeId=0x012a = 298, service_body = [0xa1, 0x00]
        let data: &[u8] = &[0xa0, 0x06, 0x02, 0x02, 0x01, 0x2a, 0xa1, 0x00];
        let (id, body) = parse_confirmed_request(data).unwrap();
        assert_eq!(id, 0x012a);
        assert_eq!(&body[..], &[0xa1, 0x00]);
    }

    #[test]
    fn parse_confirmed_request_truncated_outer_length() {
        let data: &[u8] = &[0xa0, 0x82, 0xff]; // a long-form length missing one byte
        assert!(parse_confirmed_request(data).is_err());
    }

    #[test]
    fn parse_confirmed_request_outer_length_exceeds_buffer() {
        // the outer length claims 10 bytes with only 4 present
        let data: &[u8] = &[0xa0, 0x0a, 0x02, 0x01];
        assert!(parse_confirmed_request(data).is_err());
    }

    // encode_reject_pdu is byte exact

    #[test]
    fn encode_reject_pdu_no_invoke_id_byte_exact() {
        let bytes = encode_reject_pdu(
            None,
            RejectReason::PduError(PduErrorRejectReason::UnknownPduType),
        );
        assert_eq!(&bytes[..], &[0xa4, 0x03, 0x85, 0x01, 0x00]);
    }

    #[test]
    fn encode_reject_pdu_with_invoke_id_byte_exact() {
        let bytes = encode_reject_pdu(
            Some(1),
            RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::UnrecognizedService),
        );
        assert_eq!(
            &bytes[..],
            &[0xa4, 0x06, 0x80, 0x01, 0x01, 0x81, 0x01, 0x01]
        );
    }

    // rejection of unsupported BER length forms

    #[test]
    fn extended_ber_length_form_returns_reject() {
        // A first length byte of 0x83 selects a three-byte long form, outside the 0x81
        // and 0x82 forms decode_ber_length accepts, so the PDU is rejected as invalid.
        // The bytes after it do not matter, since the length form itself is refused.
        let pdu: &[u8] = &[0xa0, 0x83, 0x00, 0x01, 0x00, 0x02, 0x01, 0x01];
        let conn = negotiated_conn();
        let dispatcher = RejectAllDispatcher;
        let outcome = parse_message(&conn, &dispatcher, pdu);
        match outcome {
            MessageOutcome::SendBytes(b) => {
                let r = RejectPdu::decode(&b).unwrap();
                assert!(
                    matches!(
                        r.reason,
                        RejectReason::PduError(PduErrorRejectReason::InvalidPdu)
                    ),
                    "an extended-length ber header must yield InvalidPdu, got reason={:?}",
                    r.reason
                );
            }
            other => panic!("expected SendBytes(reject), got {:?}", other),
        }
    }

    #[test]
    fn decode_ber_length_rejects_extended_forms() {
        // the helper itself must refuse 0x83 and above
        for first in [0x83u8, 0x84, 0x85, 0xff] {
            let data = [first, 0x00, 0x00, 0x00];
            assert!(
                decode_ber_length(&data).is_err(),
                "first=0x{:02X} must return an error",
                first
            );
        }
    }

    // end to end: Initiate, ConfirmedRequest, Conclude, then rejection

    #[test]
    fn e2e_initiate_then_confirmed_then_conclude_then_reject() {
        // a fresh connection accepts the Initiate request and reports the negotiation
        let req = crate::mms::pdu::initiate::InitiateRequestPdu::default();
        let mut req_bytes = BytesMut::new();
        req.encode(&mut req_bytes);
        let mut conn = MmsServerConnection::new();
        let dispatcher = RejectAllDispatcher;

        let outcome1 = parse_message(&conn, &dispatcher, &req_bytes);
        let params = match outcome1 {
            MessageOutcome::SendInitiateResponse {
                params,
                response_bytes,
            } => {
                assert!(response_bytes[0] == 0xa9);
                params
            }
            other => panic!("expected SendInitiateResponse, got {:?}", other),
        };
        conn.set_negotiated(params);
        assert!(conn.is_active());

        // a confirmed read request, which RejectAllDispatcher answers with a reject
        let read_req: &[u8] = &[0xa0, 0x05, 0x02, 0x01, 0x09, 0xa4, 0x00];
        let outcome2 = parse_message(&conn, &dispatcher, read_req);
        match outcome2 {
            MessageOutcome::SendBytes(b) => assert_eq!(b[0], 0xa4),
            other => panic!("expected SendBytes(reject), got {:?}", other),
        }

        // the conclude request yields a conclude response; the caller marks it concluded
        let outcome3 = parse_message(&conn, &dispatcher, &[0x8b, 0x00]);
        match outcome3 {
            MessageOutcome::SendConcludeResponse { response_bytes } => {
                assert_eq!(&response_bytes[..], &[0x8c, 0x00]);
            }
            other => panic!("expected SendConcludeResponse, got {:?}", other),
        }
        conn.mark_concluded();

        // a PDU after the association was concluded is rejected as invalid
        let outcome4 = parse_message(&conn, &dispatcher, read_req);
        match outcome4 {
            MessageOutcome::SendBytes(b) => {
                let r = RejectPdu::decode(&b).unwrap();
                assert!(matches!(
                    r.reason,
                    RejectReason::PduError(PduErrorRejectReason::InvalidPdu)
                ));
            }
            other => panic!(
                "a pdu after conclude must yield SendBytes(reject), got {:?}",
                other
            ),
        }
    }

    // end to end: a malformed PDU is rejected

    #[test]
    fn e2e_malformed_pdu_dispatched_to_reject() {
        // a single illegal byte is answered with reject(invalid-pdu)
        let conn = negotiated_conn();
        let dispatcher = RejectAllDispatcher;
        let outcome = parse_message(&conn, &dispatcher, &[0xa0]);
        match outcome {
            MessageOutcome::SendBytes(b) => {
                let r = RejectPdu::decode(&b).unwrap();
                assert!(matches!(
                    r.reason,
                    RejectReason::PduError(PduErrorRejectReason::InvalidPdu)
                ));
            }
            other => panic!(
                "a malformed pdu must yield SendBytes(reject), got {:?}",
                other
            ),
        }
    }
}
