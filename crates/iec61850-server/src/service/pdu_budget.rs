//! Outbound size limit applied to every confirmed response the dispatcher
//! returns.
//!
//! The maximum PDU size negotiated at association setup bounds what the peer
//! can accept. A response larger than that is not deliverable, so the
//! dispatcher replaces it with a ConfirmedError of errorClass resource other,
//! which is what IEC 61850-8-1 requires of a response that does not fit,
//! rather than handing the peer a PDU it must discard or abort on.
//!
//! The guard sits on the dispatcher's outbound path so that a service added
//! later is bounded without having to remember this, and measures the encoded
//! Confirmed-ResponsePDU rather than an estimate of it.
//!
//! ## Services that bound themselves
//!
//! [`SELF_BUDGETED_SERVICE_TAGS`] lists the services that already size or
//! paginate their own response and are therefore left alone: replacing a
//! deliberately truncated or paged answer with an error would lose the
//! continuation the client needs. ReadJournal belongs to that group as well
//! and never reaches the guard, as the long-form tag path answers directly.

use iec61850_mms::mms::pdu::get_name_list::SERVICE_TAG_GET_NAME_LIST;
use iec61850_mms::mms::pdu::read::SERVICE_TAG_READ;
use iec61850_mms::mms::pdu::service_error::{subcode::resource, ErrorClass};
use iec61850_mms::mms::server::dispatcher::ConfirmedResponse;

use crate::service::read::PDU_OVERHEAD_RESERVE;

/// Confirmed service tags whose handler already bounds the size of its own
/// response and must keep that answer.
///
/// - Read (`0xa4`) charges each access result against a running budget derived
///   from the same negotiated maximum and answers resource other itself.
/// - GetNameList (`0xa1`) returns a fixed-size page and reports the remainder
///   through `moreFollows`, which the client continues with `continueAfter`.
const SELF_BUDGETED_SERVICE_TAGS: [u8; 2] = [SERVICE_TAG_READ, SERVICE_TAG_GET_NAME_LIST];

/// Bytes an encoded Confirmed-ResponsePDU may occupy under a negotiated
/// maximum PDU size.
///
/// The negotiated maximum covers the MMS PDU together with the Presentation,
/// Session, and COTP frames that carry it, so [`PDU_OVERHEAD_RESERVE`] is held
/// back. A maximum smaller than the reserve saturates to zero rather than
/// wrapping. `None` means the association has not negotiated a maximum, which
/// leaves the response unbounded, matching the Read path.
pub(crate) fn confirmed_response_budget(negotiated_max_pdu_size: Option<u32>) -> Option<usize> {
    Some((negotiated_max_pdu_size? as usize).saturating_sub(PDU_OVERHEAD_RESERVE))
}

/// Reports whether an encoded Confirmed-ResponsePDU of `encoded_len` bytes
/// exceeds what the association can accept.
///
/// A length equal to the budget fits; one byte more does not. Without a
/// negotiated maximum no length exceeds.
pub(crate) fn response_exceeds_pdu_budget(
    encoded_len: usize,
    negotiated_max_pdu_size: Option<u32>,
) -> bool {
    match confirmed_response_budget(negotiated_max_pdu_size) {
        Some(budget) => encoded_len > budget,
        None => false,
    }
}

/// Replaces an undeliverable response with a ConfirmedError of errorClass
/// resource other.
///
/// A `Reject`, an existing `Error`, a service in [`SELF_BUDGETED_SERVICE_TAGS`]
/// and a response that fits all pass through unchanged.
pub(crate) fn guard_outbound_pdu_size(
    invoke_id: u32,
    service_tag: u8,
    response: ConfirmedResponse,
    negotiated_max_pdu_size: Option<u32>,
) -> ConfirmedResponse {
    let ConfirmedResponse::Response(bytes) = &response else {
        return response;
    };
    if SELF_BUDGETED_SERVICE_TAGS.contains(&service_tag) {
        return response;
    }
    if !response_exceeds_pdu_budget(bytes.len(), negotiated_max_pdu_size) {
        return response;
    }
    tracing::warn!(
        invoke_id,
        service_tag = format!("0x{service_tag:02X}"),
        encoded_len = bytes.len(),
        negotiated_max_pdu_size,
        "the response exceeds the negotiated maximum PDU size, answering a resource error"
    );
    super::make_confirmed_error(invoke_id, ErrorClass::Resource(resource::OTHER))
}

#[cfg(test)]
mod tests {
    use super::*;

    use bytes::Bytes;
    use iec61850_mms::mms::pdu::service_error::decode_confirmed_error_pdu;

    /// A confirmed service tag that bounds nothing of its own; Identify.
    const GUARDED_TAG: u8 = 0x82;

    const INVOKE_ID: u32 = 9;

    /// A response body of `len` bytes. Its contents never reach a decoder on
    /// the paths under test, only its length is read.
    fn response_of(len: usize) -> ConfirmedResponse {
        ConfirmedResponse::Response(Bytes::from(vec![0xa1; len]))
    }

    fn guard(tag: u8, len: usize, max: Option<u32>) -> ConfirmedResponse {
        guard_outbound_pdu_size(INVOKE_ID, tag, response_of(len), max)
    }

    fn assert_resource_other(resp: ConfirmedResponse) {
        match resp {
            ConfirmedResponse::Error(bytes) => {
                let (invoke_id, service_error) =
                    decode_confirmed_error_pdu(&bytes).expect("the confirmed error must decode");
                assert_eq!(invoke_id, INVOKE_ID);
                assert_eq!(
                    service_error.error_class,
                    ErrorClass::Resource(resource::OTHER)
                );
            }
            other => panic!("expected a confirmed error, got {other:?}"),
        }
    }

    fn assert_passed_through(resp: ConfirmedResponse, len: usize) {
        match resp {
            ConfirmedResponse::Response(bytes) => assert_eq!(bytes.len(), len),
            other => panic!("expected the response to pass through, got {other:?}"),
        }
    }

    #[test]
    fn budget_is_the_negotiated_maximum_less_the_reserve() {
        assert_eq!(confirmed_response_budget(Some(1024)), Some(1024 - 16));
    }

    #[test]
    fn budget_saturates_to_zero_below_the_reserve() {
        assert_eq!(confirmed_response_budget(Some(8)), Some(0));
    }

    #[test]
    fn an_unnegotiated_association_has_no_budget() {
        assert_eq!(confirmed_response_budget(None), None);
        assert!(!response_exceeds_pdu_budget(usize::MAX, None));
    }

    #[test]
    fn a_response_equal_to_the_budget_fits_and_one_byte_more_does_not() {
        let max: u32 = 200;
        let budget =
            confirmed_response_budget(Some(max)).expect("a negotiated maximum has a budget");
        assert!(!response_exceeds_pdu_budget(budget, Some(max)));
        assert!(response_exceeds_pdu_budget(budget + 1, Some(max)));
    }

    #[test]
    fn the_guard_refuses_a_response_over_the_budget() {
        let max: u32 = 200;
        let budget = confirmed_response_budget(Some(max)).expect("budget");
        assert_resource_other(guard(GUARDED_TAG, budget + 1, Some(max)));
    }

    #[test]
    fn the_guard_passes_a_response_of_exactly_the_budget() {
        let max: u32 = 200;
        let budget = confirmed_response_budget(Some(max)).expect("budget");
        assert_passed_through(guard(GUARDED_TAG, budget, Some(max)), budget);
    }

    #[test]
    fn the_guard_passes_an_unnegotiated_association() {
        assert_passed_through(guard(GUARDED_TAG, 60_000, None), 60_000);
    }

    /// A service that paginates or budgets its own answer keeps it, so that a
    /// truncated page is never turned into an error the client cannot
    /// continue from.
    #[test]
    fn the_guard_leaves_self_budgeted_services_alone() {
        let max: u32 = 200;
        let budget = confirmed_response_budget(Some(max)).expect("budget");
        for tag in SELF_BUDGETED_SERVICE_TAGS {
            assert_passed_through(guard(tag, budget + 1_000, Some(max)), budget + 1_000);
        }
        assert_eq!(
            SELF_BUDGETED_SERVICE_TAGS.len(),
            2,
            "both self-budgeted services must be covered"
        );
    }

    /// A refusal is already small and must not be replaced by another one.
    #[test]
    fn the_guard_leaves_errors_and_rejects_alone() {
        let oversized = ConfirmedResponse::Error(Bytes::from(vec![0xa2; 10_000]));
        assert!(matches!(
            guard_outbound_pdu_size(INVOKE_ID, GUARDED_TAG, oversized, Some(64)),
            ConfirmedResponse::Error(_)
        ));
        assert!(matches!(
            guard_outbound_pdu_size(INVOKE_ID, GUARDED_TAG, ConfirmedResponse::Reject, Some(64)),
            ConfirmedResponse::Reject
        ));
    }
}
