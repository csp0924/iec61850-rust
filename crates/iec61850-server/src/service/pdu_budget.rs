//! Outbound size limit for confirmed responses that are encoded as a whole.
//!
//! A service that builds its complete response before sending it measures the
//! encoded Confirmed-ResponsePDU directly and compares it against the maximum
//! PDU size negotiated for the association. A response that does not fit is
//! replaced by a ConfirmedError of errorClass resource other, as
//! IEC 61850-8-1 requires of a response that exceeds the negotiated size,
//! rather than handed to a peer that cannot accept it.
//!
//! Services that assemble a response incrementally, Read and ReadJournal,
//! carry their own running budget instead and are not served from here.

use crate::service::read::PDU_OVERHEAD_RESERVE;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
