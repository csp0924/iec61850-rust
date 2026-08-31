//! Server-side MMS Initiate negotiation and Initiate response or error encoding.
//!
//! ## Flow
//!
//! 1. Decode the raw Initiate request, outer tag `0xa8`.
//! 2. Apply the negotiation rules field by field, producing `NegotiatedParams`.
//! 3. On failure, encode an Initiate error PDU with errorClass 8 and errorCode 0.
//! 4. On success, encode an Initiate response and hand the parameters to
//!    `MmsServerConnection`.
//!
//! ## Negotiation rules
//!
//! - A proposed maximum PDU size below 64 bytes is refused with an Initiate error.
//! - maxServOutstandingCalling and maxServOutstandingCalled are clamped to at
//!   least 1, since 0 has no useful meaning.
//! - dataStructureNestingLevel is clamped to 32.
//! - A parameterCBB whose length is not 3 is refused.
//! - A proposed version number below 1 is refused.
//! - servicesSupportedCalling is recorded and logged but not enforced, so a peer
//!   that announces fewer services than it uses is not cut off.
//!
//! ## Initiate error encoding
//!
//! Every failure path sends errorClass 8 with errorCode 0. The standard defines
//! finer subcodes; using this one pair keeps the refusal unambiguous and is a
//! conservative choice for interoperability.

use super::super::error::MmsError;
use super::super::pdu::initiate::{
    InitResponseDetail, InitiateErrorPdu, InitiateRequestPdu, InitiateResponsePdu,
};
use super::connection::{
    NegotiatedParams, MIN_OUTSTANDING, MIN_PDU_SIZE, SERVER_MAX_NESTING_LEVEL,
    SERVER_MAX_OUTSTANDING, SERVER_MAX_PDU_SIZE, SERVER_PARAMETER_CBB,
};
use bytes::BytesMut;

/// The outcome of negotiating an Initiate request.
#[derive(Debug)]
pub enum InitiateOutcome {
    /// The request was accepted: `response_bytes` holds the encoded Initiate response
    /// and `params` the values the caller writes into `MmsServerConnection`.
    Accepted {
        /// Parameters the caller stores in the connection.
        params: NegotiatedParams,
        /// Encoded Initiate response to send.
        response_bytes: BytesMut,
    },
    /// The request was refused: `error_bytes` holds the encoded Initiate error, and
    /// `reason` is local diagnostic detail that never reaches the wire, which always
    /// carries errorClass 8 and errorCode 0.
    Rejected {
        /// Local diagnostic reason; it never reaches the wire.
        reason: InitiateRejectReason,
        /// Encoded Initiate error to send before closing.
        error_bytes: BytesMut,
    },
}

/// Local diagnostic reason for refusing an Initiate request; it does not affect the
/// bytes sent.
#[derive(Debug, PartialEq, Eq)]
pub enum InitiateRejectReason {
    /// The Initiate request itself failed to decode.
    ParseFailed(MmsError),
    /// The proposed version number is below 1.
    VersionTooLow {
        /// Version number the peer proposed.
        proposed: u16,
    },
    /// `localDetailCalling` is below `MIN_PDU_SIZE`, which includes the case where
    /// the peer omitted the field.
    PduSizeTooSmall {
        /// Maximum PDU size the peer proposed.
        proposed: u32,
    },
}

/// Negotiates an Initiate request received from a peer.
///
/// `incoming` is the complete Initiate request PDU, outer `0xa8 <len>` included. A
/// decode failure yields `InitiateOutcome::Rejected`.
///
/// `services_supported` is the servicesSupportedCalled bitmap returned to the peer.
/// The dispatcher supplies it through `MmsServiceDispatcher::services_supported` and
/// must announce only services it actually handles.
pub fn negotiate_initiate(incoming: &[u8], services_supported: [u8; 11]) -> InitiateOutcome {
    // decode the PDU
    let req = match InitiateRequestPdu::decode(incoming) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("initiate request failed to parse: {}", e);
            return reject_with(InitiateRejectReason::ParseFailed(e));
        }
    };

    // version number
    let version = req.init_request_detail.proposed_version_number;
    if version < 1 {
        tracing::warn!("version number {} is below 1, refusing", version);
        return reject_with(InitiateRejectReason::VersionTooLow { proposed: version });
    }

    // localDetailCalling: the smaller of the two proposals, floored at MIN_PDU_SIZE.
    // A proposal below that floor is refused, as is an absent field: a peer that
    // cannot state a usable PDU size has nothing this server can serve.
    let proposed_pdu = req.local_detail_calling.unwrap_or(0);
    if proposed_pdu < MIN_PDU_SIZE {
        tracing::warn!(
            proposed = proposed_pdu,
            min = MIN_PDU_SIZE,
            "proposed maximum pdu size is too small, refusing"
        );
        return reject_with(InitiateRejectReason::PduSizeTooSmall {
            proposed: proposed_pdu,
        });
    }
    let max_pdu_size = proposed_pdu.min(SERVER_MAX_PDU_SIZE);

    // maxServOutstandingCalling and maxServOutstandingCalled, clamped at both ends
    // so the negotiated value is at least 1.
    let max_serv_outstanding_calling = clamp_outstanding(req.proposed_max_serv_outstanding_calling);
    let max_serv_outstanding_called = clamp_outstanding(req.proposed_max_serv_outstanding_called);

    // dataStructureNestingLevel, clamped to the server ceiling. Decoding already
    // rejects a value above MAX_NESTING_LEVEL; the minimum here keeps the negotiated
    // value inside the ceiling, and an absent field takes the ceiling itself.
    let proposed_nesting = req
        .proposed_data_structure_nesting_level
        .unwrap_or(SERVER_MAX_NESTING_LEVEL);
    let data_structure_nesting_level = proposed_nesting.min(SERVER_MAX_NESTING_LEVEL);

    // parameterCBB, the bitwise AND of both capability sets. The field is three bytes
    // on the wire: a padding count of 5 followed by two data bytes. Only the data
    // bytes are combined, so the padding count stays 5.
    let client_cbb = req.init_request_detail.proposed_parameter_cbb;
    let parameter_cbb = [
        client_cbb[0], // padding count, fixed at 0x05 on both sides
        client_cbb[1] & SERVER_PARAMETER_CBB[1],
        client_cbb[2] & SERVER_PARAMETER_CBB[2],
    ];

    // servicesSupportedCalling is recorded and logged, never enforced, so a peer that
    // uses a service it did not announce is still served.
    let client_proposed_services = Some(req.init_request_detail.services_supported_calling);
    tracing::debug!(
        services = ?req.init_request_detail.services_supported_calling,
        "recorded the client servicesSupportedCalling bitmap without enforcing it"
    );

    let params = NegotiatedParams {
        max_pdu_size,
        max_serv_outstanding_calling,
        max_serv_outstanding_called,
        data_structure_nesting_level,
        parameter_cbb,
        services_supported_called: services_supported,
        client_proposed_services,
    };

    // encode the Initiate response
    let resp = InitiateResponsePdu {
        local_detail_called: Some(params.max_pdu_size),
        negotiated_max_serv_outstanding_calling: params.max_serv_outstanding_calling,
        negotiated_max_serv_outstanding_called: params.max_serv_outstanding_called,
        negotiated_data_structure_nesting_level: Some(params.data_structure_nesting_level),
        init_response_detail: InitResponseDetail {
            negotiated_version_number: 1, // always answered as 1
            negotiated_parameter_cbb: params.parameter_cbb,
            services_supported_called: params.services_supported_called,
        },
    };

    let mut response_bytes = BytesMut::new();
    resp.encode(&mut response_bytes);

    InitiateOutcome::Accepted {
        params,
        response_bytes,
    }
}

/// Encodes an Initiate error, always with errorClass 8 and errorCode 0.
fn reject_with(reason: InitiateRejectReason) -> InitiateOutcome {
    let err_pdu = InitiateErrorPdu::new(0); // errorCode 0, other
    let mut error_bytes = BytesMut::new();
    err_pdu.encode(&mut error_bytes);
    InitiateOutcome::Rejected {
        reason,
        error_bytes,
    }
}

/// Clamps a proposed outstanding count into `[MIN_OUTSTANDING, SERVER_MAX_OUTSTANDING]`.
fn clamp_outstanding(proposed: u16) -> u16 {
    proposed.clamp(MIN_OUTSTANDING, SERVER_MAX_OUTSTANDING)
}

// Unit tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mms::pdu::initiate::InitiateRequestPdu;
    use crate::mms::server::connection::SERVER_SERVICES_SUPPORTED;

    /// Encodes an `InitiateRequestPdu` into wire bytes for `negotiate_initiate`.
    fn encode_request(req: &InitiateRequestPdu) -> Vec<u8> {
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        buf.to_vec()
    }

    fn assert_initiate_error_bytes(bytes: &[u8]) {
        // fixed form: 0xaa 0x05 0xa0 0x03 0x88 0x01 0x00, errorClass 8 and code 0
        assert_eq!(
            bytes,
            &[0xaa, 0x05, 0xa0, 0x03, 0x88, 0x01, 0x00],
            "the initiate error must be byte exact"
        );
    }

    // accepted requests

    #[test]
    fn happy_path_default_request() {
        // both sides propose 65000, so 65000 is negotiated
        let req = InitiateRequestPdu::default();
        let outcome = negotiate_initiate(&encode_request(&req), SERVER_SERVICES_SUPPORTED);
        match outcome {
            InitiateOutcome::Accepted { params, .. } => {
                assert_eq!(params.max_pdu_size, 65000);
                assert_eq!(params.max_serv_outstanding_calling, 5);
                assert_eq!(params.max_serv_outstanding_called, 5);
                assert_eq!(params.data_structure_nesting_level, 10);
                assert!(params.client_proposed_services.is_some());
            }
            other => panic!("expected Accepted, got {:?}", other),
        }
    }

    /// Both the negotiated parameters and the wire response must carry the bitmap the
    /// dispatcher supplied, since the dispatcher is the authority on services.
    #[test]
    fn services_supported_uses_caller_provided_bitmap() {
        let custom: [u8; 11] = [0xee, 0x00, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x18];
        let req = InitiateRequestPdu::default();
        let outcome = negotiate_initiate(&encode_request(&req), custom);
        match outcome {
            InitiateOutcome::Accepted {
                params,
                response_bytes,
            } => {
                assert_eq!(params.services_supported_called, custom);
                let wire = response_bytes.to_vec();
                assert!(
                    wire.windows(custom.len()).any(|w| w == custom),
                    "the initiate response must carry the bitmap the caller supplied"
                );
            }
            other => panic!("expected Accepted, got {:?}", other),
        }
    }

    #[test]
    fn happy_path_smaller_client_pdu_takes_min() {
        // the peer proposes 4096 against 65000, so 4096 is negotiated
        let req = InitiateRequestPdu {
            local_detail_calling: Some(4096),
            ..InitiateRequestPdu::default()
        };
        let outcome = negotiate_initiate(&encode_request(&req), SERVER_SERVICES_SUPPORTED);
        match outcome {
            InitiateOutcome::Accepted { params, .. } => {
                assert_eq!(params.max_pdu_size, 4096);
            }
            other => panic!("expected Accepted, got {:?}", other),
        }
    }

    #[test]
    fn happy_path_larger_client_pdu_clamps_to_server_max() {
        // the peer proposes 100000 above the 65000 ceiling, so 65000 is negotiated
        let req = InitiateRequestPdu {
            local_detail_calling: Some(100_000),
            ..InitiateRequestPdu::default()
        };
        let outcome = negotiate_initiate(&encode_request(&req), SERVER_SERVICES_SUPPORTED);
        match outcome {
            InitiateOutcome::Accepted { params, .. } => {
                assert_eq!(params.max_pdu_size, SERVER_MAX_PDU_SIZE);
            }
            other => panic!("expected Accepted, got {:?}", other),
        }
    }

    #[test]
    fn happy_path_outstanding_clamped_to_server_max() {
        // the peer proposes 100 against a ceiling of 5, so 5 is negotiated
        let req = InitiateRequestPdu {
            proposed_max_serv_outstanding_calling: 100,
            proposed_max_serv_outstanding_called: 100,
            ..InitiateRequestPdu::default()
        };
        let outcome = negotiate_initiate(&encode_request(&req), SERVER_SERVICES_SUPPORTED);
        match outcome {
            InitiateOutcome::Accepted { params, .. } => {
                assert_eq!(params.max_serv_outstanding_calling, 5);
                assert_eq!(params.max_serv_outstanding_called, 5);
            }
            other => panic!("expected Accepted, got {:?}", other),
        }
    }

    #[test]
    fn outstanding_zero_clamped_up_to_one() {
        // a proposal of 0 is clamped up to MIN_OUTSTANDING
        let req = InitiateRequestPdu {
            proposed_max_serv_outstanding_calling: 0,
            proposed_max_serv_outstanding_called: 0,
            ..InitiateRequestPdu::default()
        };
        let outcome = negotiate_initiate(&encode_request(&req), SERVER_SERVICES_SUPPORTED);
        match outcome {
            InitiateOutcome::Accepted { params, .. } => {
                assert_eq!(
                    params.max_serv_outstanding_calling, 1,
                    "a proposal of 0 must clamp to MIN_OUTSTANDING"
                );
                assert_eq!(params.max_serv_outstanding_called, 1);
            }
            other => panic!("expected Accepted, got {:?}", other),
        }
    }

    #[test]
    fn nesting_level_clamped_to_server_max() {
        // the peer proposes 31, inside MAX_NESTING_LEVEL, so 31 is negotiated
        let req = InitiateRequestPdu {
            proposed_data_structure_nesting_level: Some(31),
            ..InitiateRequestPdu::default()
        };
        let outcome = negotiate_initiate(&encode_request(&req), SERVER_SERVICES_SUPPORTED);
        match outcome {
            InitiateOutcome::Accepted { params, .. } => {
                assert_eq!(params.data_structure_nesting_level, 31);
            }
            other => panic!("expected Accepted, got {:?}", other),
        }
    }

    #[test]
    fn parameter_cbb_anded_with_server() {
        // both sides carry the same CBB, so the AND leaves it unchanged
        let req = InitiateRequestPdu::default();
        let outcome = negotiate_initiate(&encode_request(&req), SERVER_SERVICES_SUPPORTED);
        match outcome {
            InitiateOutcome::Accepted { params, .. } => {
                // the padding count stays 5
                assert_eq!(params.parameter_cbb[0], 0x05);
                assert_eq!(params.parameter_cbb[1], 0xf1 & 0xf1);
                assert_eq!(params.parameter_cbb[2], 0x00);
            }
            other => panic!("expected Accepted, got {:?}", other),
        }
    }

    #[test]
    fn services_supported_calling_recorded_not_enforced() {
        // a custom client bitmap is accepted and only recorded
        let custom_services = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];
        let mut req = InitiateRequestPdu::default();
        req.init_request_detail.services_supported_calling = custom_services;
        let outcome = negotiate_initiate(&encode_request(&req), SERVER_SERVICES_SUPPORTED);
        match outcome {
            InitiateOutcome::Accepted { params, .. } => {
                assert_eq!(params.client_proposed_services, Some(custom_services));
                // the response still carries the server bitmap
                assert_eq!(params.services_supported_called, SERVER_SERVICES_SUPPORTED);
            }
            other => panic!("expected Accepted, got {:?}", other),
        }
    }

    // refused requests

    #[test]
    fn pdu_size_below_min_rejected() {
        // a proposal of 32, below MIN_PDU_SIZE of 64, is refused
        let req = InitiateRequestPdu {
            local_detail_calling: Some(32),
            ..InitiateRequestPdu::default()
        };
        let outcome = negotiate_initiate(&encode_request(&req), SERVER_SERVICES_SUPPORTED);
        match outcome {
            InitiateOutcome::Rejected {
                reason,
                error_bytes,
            } => {
                assert_eq!(
                    reason,
                    InitiateRejectReason::PduSizeTooSmall { proposed: 32 }
                );
                assert_initiate_error_bytes(&error_bytes);
            }
            other => panic!("expected Rejected, got {:?}", other),
        }
    }

    #[test]
    fn pdu_size_zero_rejected() {
        // anything below MIN_PDU_SIZE is refused
        let req = InitiateRequestPdu {
            local_detail_calling: Some(0),
            ..InitiateRequestPdu::default()
        };
        let outcome = negotiate_initiate(&encode_request(&req), SERVER_SERVICES_SUPPORTED);
        match outcome {
            InitiateOutcome::Rejected { reason, .. } => {
                assert_eq!(
                    reason,
                    InitiateRejectReason::PduSizeTooSmall { proposed: 0 }
                );
            }
            other => panic!("expected Rejected, got {:?}", other),
        }
    }

    #[test]
    fn pdu_size_at_min_accepted() {
        // MIN_PDU_SIZE itself is accepted
        let req = InitiateRequestPdu {
            local_detail_calling: Some(MIN_PDU_SIZE),
            ..InitiateRequestPdu::default()
        };
        let outcome = negotiate_initiate(&encode_request(&req), SERVER_SERVICES_SUPPORTED);
        match outcome {
            InitiateOutcome::Accepted { params, .. } => {
                assert_eq!(params.max_pdu_size, MIN_PDU_SIZE);
            }
            other => panic!("MIN_PDU_SIZE must be accepted, got {:?}", other),
        }
    }

    #[test]
    fn version_zero_rejected() {
        // a version number of 0 is refused; the field is patched on a default request
        let mut req = InitiateRequestPdu::default();
        req.init_request_detail.proposed_version_number = 0;
        let outcome = negotiate_initiate(&encode_request(&req), SERVER_SERVICES_SUPPORTED);
        match outcome {
            InitiateOutcome::Rejected {
                reason,
                error_bytes,
            } => {
                assert_eq!(reason, InitiateRejectReason::VersionTooLow { proposed: 0 });
                assert_initiate_error_bytes(&error_bytes);
            }
            other => panic!("expected Rejected, got {:?}", other),
        }
    }

    #[test]
    fn version_two_accepted() {
        // version 2 is accepted, since 1 or above is legal, and 1 is answered
        let mut req = InitiateRequestPdu::default();
        req.init_request_detail.proposed_version_number = 2;
        let outcome = negotiate_initiate(&encode_request(&req), SERVER_SERVICES_SUPPORTED);
        match outcome {
            InitiateOutcome::Accepted { response_bytes, .. } => {
                // the decoded response must carry negotiated version 1
                let resp = crate::mms::InitiateResponsePdu::decode(&response_bytes).unwrap();
                assert_eq!(resp.init_response_detail.negotiated_version_number, 1);
            }
            other => panic!("version 2 must be accepted, got {:?}", other),
        }
    }

    #[test]
    fn malformed_cbb_length_rejected() {
        // an illegal CBB length of 2, injected by patching the wire bytes
        let req = InitiateRequestPdu::default();
        let mut bytes = encode_request(&req);
        // find 0x81 0x03, the CBB tag and length, and set the length to 2
        for i in 0..bytes.len().saturating_sub(1) {
            if bytes[i] == 0x81 && bytes[i + 1] == 0x03 {
                bytes[i + 1] = 0x02;
                break;
            }
        }
        let outcome = negotiate_initiate(&bytes, SERVER_SERVICES_SUPPORTED);
        match outcome {
            InitiateOutcome::Rejected {
                reason,
                error_bytes,
            } => {
                // the PDU layer rejects it, so the reason is a parse failure
                assert!(matches!(
                    reason,
                    InitiateRejectReason::ParseFailed(MmsError::InvalidParameterCbbLength { .. })
                ));
                assert_initiate_error_bytes(&error_bytes);
            }
            other => panic!("expected Rejected, got {:?}", other),
        }
    }

    #[test]
    fn malformed_truncated_pdu_rejected() {
        // a truncated PDU
        let bytes = &[0xa8, 0x82, 0xff, 0xff]; // declares length 65535 with too few bytes
        let outcome = negotiate_initiate(bytes, SERVER_SERVICES_SUPPORTED);
        match outcome {
            InitiateOutcome::Rejected {
                reason,
                error_bytes,
            } => {
                assert!(matches!(reason, InitiateRejectReason::ParseFailed(_)));
                assert_initiate_error_bytes(&error_bytes);
            }
            other => panic!("expected Rejected, got {:?}", other),
        }
    }

    #[test]
    fn nesting_level_above_max_rejected_at_decode() {
        // a nesting level the PDU layer rejects as NestingLevelExceeded
        let req = InitiateRequestPdu::default();
        let mut bytes = encode_request(&req);
        // find 0x83 0x01 <level> and set the level to 255
        for i in 0..bytes.len().saturating_sub(2) {
            if bytes[i] == 0x83 && bytes[i + 1] == 0x01 {
                bytes[i + 2] = 255;
                break;
            }
        }
        let outcome = negotiate_initiate(&bytes, SERVER_SERVICES_SUPPORTED);
        match outcome {
            InitiateOutcome::Rejected { reason, .. } => {
                assert!(matches!(
                    reason,
                    InitiateRejectReason::ParseFailed(MmsError::NestingLevelExceeded { .. })
                ));
            }
            other => panic!("expected Rejected, got {:?}", other),
        }
    }

    // golden exchange: the encoded response must be byte-exact

    /// Golden Initiate request.
    ///
    /// Decoded fields:
    /// - localDetailCalling = 65000 (0x00FDE8)
    /// - maxServOutstandingCalling = 5
    /// - maxServOutstandingCalled = 5
    /// - dataStructureNestingLevel = 1
    /// - parameterCBB = `[05 f1 00]`
    /// - servicesSupportedCalling = `[ee 1c 00 00 04 08 00 00 79 ef 18]`, the client bitmap
    const WIRE_INITIATE_REQUEST: &[u8] = &[
        0xa8, 0x26, 0x80, 0x03, 0x00, 0xfd, 0xe8, 0x81, 0x01, 0x05, 0x82, 0x01, 0x05, 0x83, 0x01,
        0x01, 0xa4, 0x16, 0x80, 0x01, 0x01, 0x81, 0x03, 0x05, 0xf1, 0x00, 0x82, 0x0c, 0x03, 0xee,
        0x1c, 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x79, 0xef, 0x18,
    ];

    /// Golden Initiate response for the request above.
    /// This implementation must reproduce these bytes exactly.
    ///
    /// The only difference from the request is servicesSupportedCalled, bytes 33 to 40:
    /// `[ee 1c 00 00 00 00 00 00 00 01 18]`, a server bitmap without file, journal or
    /// obtain-file support.
    const WIRE_INITIATE_RESPONSE: &[u8] = &[
        0xa9, 0x26, 0x80, 0x03, 0x00, 0xfd, 0xe8, 0x81, 0x01, 0x05, 0x82, 0x01, 0x05, 0x83, 0x01,
        0x01, 0xa4, 0x16, 0x80, 0x01, 0x01, 0x81, 0x03, 0x05, 0xf1, 0x00, 0x82, 0x0c, 0x03, 0xee,
        0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x18,
    ];

    /// `SERVER_SERVICES_SUPPORTED` must stay the server bitmap and must not be set to
    /// `DEFAULT_SERVICES_SUPPORTED_CLIENT`: announcing services the server does not
    /// implement makes peers issue requests it cannot answer.
    ///
    /// Feeding the golden request through `negotiate_initiate` must reproduce the
    /// golden response byte for byte, so any change that echoes the client bitmap
    /// back fails here.
    #[test]
    fn server_services_supported_reproduces_golden_response() {
        let outcome = negotiate_initiate(WIRE_INITIATE_REQUEST, SERVER_SERVICES_SUPPORTED);
        match outcome {
            InitiateOutcome::Accepted {
                response_bytes,
                params,
            } => {
                // the constant itself
                assert_eq!(
                    params.services_supported_called,
                    [0xee, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x18],
                    "SERVER_SERVICES_SUPPORTED must be the server bitmap"
                );
                // and the encoded response, byte for byte
                assert_eq!(
                    &response_bytes[..],
                    WIRE_INITIATE_RESPONSE,
                    "the initiate response must match the golden bytes exactly"
                );
            }
            other => panic!(
                "the golden initiate request must be accepted, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn happy_path_response_decodable() {
        // the response bytes must decode on the client side with matching fields
        let req = InitiateRequestPdu {
            local_detail_calling: Some(8192),
            ..InitiateRequestPdu::default()
        };
        let outcome = negotiate_initiate(&encode_request(&req), SERVER_SERVICES_SUPPORTED);
        match outcome {
            InitiateOutcome::Accepted { response_bytes, .. } => {
                let resp = crate::mms::InitiateResponsePdu::decode(&response_bytes)
                    .expect("the response must decode");
                assert_eq!(resp.local_detail_called, Some(8192));
                assert_eq!(resp.negotiated_max_serv_outstanding_calling, 5);
                assert_eq!(resp.negotiated_max_serv_outstanding_called, 5);
                assert_eq!(resp.init_response_detail.negotiated_version_number, 1);
            }
            other => panic!("expected Accepted, got {:?}", other),
        }
    }
}
