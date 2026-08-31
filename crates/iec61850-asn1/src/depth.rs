//! Recursion-depth guards for BER decoding.
//!
//! A crafted PDU can nest constructed values without bound and exhaust the
//! stack. `MAX_DATA_NESTING_DEPTH` sets a local ceiling and
//! `effective_nesting_cap` narrows it to the negotiated value, so neither
//! the local default nor the peer alone decides how deep decoding may go.

/// Default local ceiling for recursive `Data` / `AccessResult` decoding.
///
/// Set to 32. The ceiling is deliberately generous so that a deeply nested but
/// legitimate structure still decodes, and `effective_nesting_cap` still clamps
/// it whenever the negotiated limit is smaller.
pub const MAX_DATA_NESTING_DEPTH: u8 = 32;

/// Returns the effective decoding depth limit, `min(local_cap, negotiated)`.
///
/// `negotiated` is `None` for the initial PDU, before negotiation completes;
/// the local cap applies in that case.
///
/// Taking the minimum keeps both guards live. The negotiated value is under
/// the peer's control and must not be able to raise the local ceiling, while
/// a peer that negotiates a smaller depth is still honored.
pub const fn effective_nesting_cap(local_cap: u8, negotiated: Option<u8>) -> u8 {
    match negotiated {
        Some(n) => {
            if n < local_cap {
                n
            } else {
                local_cap
            }
        }
        None => local_cap,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_falls_back_to_local() {
        assert_eq!(effective_nesting_cap(32, None), 32);
        assert_eq!(effective_nesting_cap(10, None), 10);
    }

    #[test]
    fn negotiated_lower_clamps() {
        assert_eq!(effective_nesting_cap(32, Some(15)), 15);
    }

    #[test]
    fn negotiated_higher_clamps_to_local() {
        assert_eq!(effective_nesting_cap(32, Some(100)), 32);
    }

    #[test]
    fn negotiated_equal_to_local() {
        assert_eq!(effective_nesting_cap(32, Some(32)), 32);
    }

    #[test]
    fn max_depth_constant_is_32() {
        assert_eq!(MAX_DATA_NESTING_DEPTH, 32);
    }
}
