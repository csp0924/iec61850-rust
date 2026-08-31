//! Functional constraints, per IEC 61850-7-2 §6.2.
//!
//! A functional constraint decides where a data attribute sits in the MMS
//! namespace: one data object maps to a different MMS named variable under
//! each constraint. The `Pos` object of an SPC, for instance, is
//! `Pos$stVal/q/t` under ST, `Pos$Oper/SBO/SBOw/Cancel` under CO and
//! `Pos$ctlModel/sboTimeout/...` under CF.

use crate::compat::prelude::*;
#[cfg(test)]
use crate::compat::HashSet;
use crate::error::ModelError;

/// A functional constraint, per IEC 61850-7-2 §6.2: 21 values, `ALL` and
/// `NONE` included.
///
/// The discriminants match the numbering common IEC 61850 implementations
/// use, so a future ABI can share them; nothing here depends on the value.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(i32)]
pub enum FC {
    /// Status: `stVal`, `q`, `t`.
    St = 0,
    /// Measurands: `mag`, `q`, `t`, `units`.
    Mx = 1,
    /// Setpoint, writable.
    Sp = 2,
    /// Substitution, that is a replacement value in test mode.
    Sv = 3,
    /// Configuration, such as `ctlModel` and `sboTimeout`.
    Cf = 4,
    /// Description: the `d` and `dU` attributes.
    Dc = 5,
    /// Setting group: the group currently active.
    Sg = 6,
    /// Setting group editable: the group being edited.
    Se = 7,
    /// Service tracking response.
    Sr = 8,
    /// Operate received, the control echo.
    Or = 9,
    /// Blocking.
    Bl = 10,
    /// Extended definition, for namespace extensions.
    Ex = 11,
    /// Control: `Oper`, `SBO`, `SBOw`, `Cancel`.
    Co = 12,
    /// Unicast sampled value control.
    Us = 13,
    /// Multicast sampled value control.
    Ms = 14,
    /// Unbuffered report control block.
    Rp = 15,
    /// Buffered report control block.
    Br = 16,
    /// Log control block.
    Lg = 17,
    /// GOOSE control block.
    Go = 18,
    /// Wildcard, discriminant 99, used by the query API.
    All = 99,
    /// No functional constraint, discriminant -1.
    None = -1,
}

impl FC {
    /// Returns the two-character abbreviation used as a token inside an MMS
    /// variable name, per IEC 61850-8-1 §16.
    pub const fn as_str(self) -> &'static str {
        match self {
            FC::St => "ST",
            FC::Mx => "MX",
            FC::Sp => "SP",
            FC::Sv => "SV",
            FC::Cf => "CF",
            FC::Dc => "DC",
            FC::Sg => "SG",
            FC::Se => "SE",
            FC::Sr => "SR",
            FC::Or => "OR",
            FC::Bl => "BL",
            FC::Ex => "EX",
            FC::Co => "CO",
            FC::Us => "US",
            FC::Ms => "MS",
            FC::Rp => "RP",
            FC::Br => "BR",
            FC::Lg => "LG",
            FC::Go => "GO",
            FC::All => "ALL",
            FC::None => "NONE",
        }
    }

    /// Parses a functional constraint from its two-character abbreviation.
    ///
    /// # Errors
    ///
    /// [`ModelError::UnknownFc`] when the abbreviation is not one of the
    /// defined tokens.
    pub fn parse(token: &str) -> Result<Self, ModelError> {
        Ok(match token {
            "ST" => FC::St,
            "MX" => FC::Mx,
            "SP" => FC::Sp,
            "SV" => FC::Sv,
            "CF" => FC::Cf,
            "DC" => FC::Dc,
            "SG" => FC::Sg,
            "SE" => FC::Se,
            "SR" => FC::Sr,
            "OR" => FC::Or,
            "BL" => FC::Bl,
            "EX" => FC::Ex,
            "CO" => FC::Co,
            "US" => FC::Us,
            "MS" => FC::Ms,
            "RP" => FC::Rp,
            "BR" => FC::Br,
            "LG" => FC::Lg,
            "GO" => FC::Go,
            "ALL" => FC::All,
            "NONE" => FC::None,
            _ => return Err(ModelError::UnknownFc(token.to_string())),
        })
    }

    /// The order in which functional constraints are filled into a logical
    /// node when its MMS view is built.
    ///
    /// Some client tools are sensitive to this order when they enumerate a
    /// model, so it is fixed: MX, ST, CO, CF, DC, SP, SG, RP, LG, BR, GO, SV,
    /// SE, MS, US, EX, SR, OR, BL.
    pub const WIRE_ORDER: [FC; 19] = [
        FC::Mx,
        FC::St,
        FC::Co,
        FC::Cf,
        FC::Dc,
        FC::Sp,
        FC::Sg,
        FC::Rp,
        FC::Lg,
        FC::Br,
        FC::Go,
        FC::Sv,
        FC::Se,
        FC::Ms,
        FC::Us,
        FC::Ex,
        FC::Sr,
        FC::Or,
        FC::Bl,
    ];
}

impl core::fmt::Display for FC {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_fcs() {
        for fc in [
            FC::St,
            FC::Mx,
            FC::Sp,
            FC::Sv,
            FC::Cf,
            FC::Dc,
            FC::Sg,
            FC::Se,
            FC::Sr,
            FC::Or,
            FC::Bl,
            FC::Ex,
            FC::Co,
            FC::Us,
            FC::Ms,
            FC::Rp,
            FC::Br,
            FC::Lg,
            FC::Go,
            FC::All,
            FC::None,
        ] {
            assert_eq!(FC::parse(fc.as_str()).unwrap(), fc, "{fc:?}");
        }
    }

    #[test]
    fn parse_unknown() {
        assert!(matches!(
            FC::parse("XX"),
            Err(ModelError::UnknownFc(s)) if s == "XX"
        ));
    }

    #[test]
    fn wire_order_19_distinct_no_all_no_none() {
        // ALL and NONE are not part of the wire-observable order.
        let mut seen = HashSet::new();
        for fc in FC::WIRE_ORDER {
            assert!(seen.insert(fc), "duplicate functional constraint: {fc:?}");
            assert!(fc != FC::All && fc != FC::None);
        }
        assert_eq!(seen.len(), 19);
    }

    #[test]
    fn display_uses_as_str() {
        assert_eq!(format!("{}", FC::St), "ST");
        assert_eq!(format!("{}", FC::Co), "CO");
    }
}
