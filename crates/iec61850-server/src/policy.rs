//! Global write-access policy, expressed as a functional-constraint bitmask.
//!
//! The mask decides which functional constraints a remote client may write.
//! The default is `SP | SV | SE` (0x1C), the set IEC 61850 leaves writable
//! without further configuration. All six writable constraints can be enabled,
//! `FC::Bl` included.

use iec61850_model::FC;

/// Which functional constraints accept a remote Write, as a bitmask.
///
/// Bit positions: `DC = 1`, `CF = 2`, `SP = 4`, `SV = 8`, `SE = 16`, `BL = 32`.
///
/// Defaults to `SP | SV | SE` (0x1C).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteAccessPolicies(u8);

impl WriteAccessPolicies {
    /// FC DC, bit 0 (mask 1).
    const BIT_DC: u8 = 0x01;
    /// FC CF, bit 1 (mask 2).
    const BIT_CF: u8 = 0x02;
    /// FC SP, bit 2 (mask 4).
    const BIT_SP: u8 = 0x04;
    /// FC SV, bit 3 (mask 8).
    const BIT_SV: u8 = 0x08;
    /// FC SE, bit 4 (mask 16).
    const BIT_SE: u8 = 0x10;
    /// FC BL, bit 5 (mask 32).
    ///
    /// [`WriteAccessPolicies::set`] accepts it like any other writable
    /// constraint.
    const BIT_BL: u8 = 0x20;

    /// Returns the default mask, `SP | SV | SE`.
    pub const fn default_policy() -> Self {
        Self(Self::BIT_SP | Self::BIT_SV | Self::BIT_SE)
    }

    /// Maps a functional constraint to its mask bit; returns `None` for a
    /// constraint that is never writable (ST, MX, CO, ...).
    fn fc_bit(fc: FC) -> Option<u8> {
        match fc {
            FC::Dc => Some(Self::BIT_DC),
            FC::Cf => Some(Self::BIT_CF),
            FC::Sp => Some(Self::BIT_SP),
            FC::Sv => Some(Self::BIT_SV),
            FC::Se => Some(Self::BIT_SE),
            FC::Bl => Some(Self::BIT_BL),
            _ => None,
        }
    }

    /// Sets the policy for one functional constraint: `allow = true` adds the
    /// bit, `false` clears it.
    ///
    /// `FC::Bl` is accepted. A constraint that is never writable (ST, MX, CO,
    /// ...) leaves the mask unchanged and is logged at warn level.
    pub fn set(&mut self, fc: FC, allow: bool) {
        match Self::fc_bit(fc) {
            Some(bit) => {
                if allow {
                    self.0 |= bit;
                } else {
                    self.0 &= !bit;
                }
            }
            None => {
                tracing::warn!(
                    ?fc,
                    "write access policy set for a non-writable FC, ignored"
                );
            }
        }
    }

    /// Reports whether the functional constraint accepts a remote Write; a
    /// constraint that is never writable always returns `false`.
    pub fn is_allowed(&self, fc: FC) -> bool {
        match Self::fc_bit(fc) {
            Some(bit) => self.0 & bit != 0,
            None => false,
        }
    }

    /// Returns the raw bitmask. Test-only; not a stable part of the API.
    #[cfg(test)]
    pub(crate) fn raw(&self) -> u8 {
        self.0
    }
}

impl Default for WriteAccessPolicies {
    fn default() -> Self {
        Self::default_policy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_mask_is_sp_sv_se() {
        // SP | SV | SE = 4 + 8 + 16 = 0x1C
        assert_eq!(WriteAccessPolicies::default().raw(), 0x1C);
    }

    #[test]
    fn default_allows_sp_sv_se_only() {
        let p = WriteAccessPolicies::default();
        assert!(p.is_allowed(FC::Sp));
        assert!(p.is_allowed(FC::Sv));
        assert!(p.is_allowed(FC::Se));
        assert!(!p.is_allowed(FC::Dc));
        assert!(!p.is_allowed(FC::Cf));
        assert!(!p.is_allowed(FC::Bl));
    }

    #[test]
    fn set_dc_cf_works() {
        let mut p = WriteAccessPolicies::default();
        p.set(FC::Dc, true);
        p.set(FC::Cf, true);
        assert!(p.is_allowed(FC::Dc));
        assert!(p.is_allowed(FC::Cf));
    }

    #[test]
    fn bl_write_access_can_be_enabled_and_disabled() {
        let mut p = WriteAccessPolicies::default();
        assert!(!p.is_allowed(FC::Bl));
        p.set(FC::Bl, true);
        assert!(p.is_allowed(FC::Bl), "FC::Bl must be settable");
        p.set(FC::Bl, false);
        assert!(!p.is_allowed(FC::Bl));
    }

    #[test]
    fn set_unsupported_fc_ignored() {
        let mut p = WriteAccessPolicies::default();
        let before = p.raw();
        p.set(FC::St, true);
        p.set(FC::Mx, true);
        p.set(FC::Co, true);
        assert_eq!(p.raw(), before, "a non-writable FC must be ignored");
    }
}
