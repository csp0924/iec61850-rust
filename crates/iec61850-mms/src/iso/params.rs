//! ISO connection parameters: the addressing a client offers when it associates.
//!
//! Collects the selectors of the transport, session and presentation layers
//! together with the ACSE application-entity title, so that one value carries
//! every address the association sequence needs.
//!
//! The defaults are the values IEC 61850-8-1 Annex A lists for an MMS
//! association: T-Selector `00 01`, S-Selector `00 01` and P-Selector
//! `00 00 00 01`, with an AP-title and an AE-qualifier present on both sides.
//!
//! An AP-title is an OBJECT IDENTIFIER, the ISO 8650 AARQ-apdu fields
//! `called-AP-title` and `calling-AP-title`. [`ApTitle`] holds it as its arc
//! values, parses the dotted form and encodes the BER content octets.

use crate::compat::prelude::*;
use core::fmt;
use core::str::FromStr;

use super::cotp::TSelector;
use super::presentation::PSelector;
use super::session::SSelector;

// Defaults

/// Default T-Selector on both sides of the association.
pub const DEFAULT_T_SELECTOR: [u8; 2] = [0x00, 0x01];

/// Default S-Selector on both sides of the association.
pub const DEFAULT_S_SELECTOR: [u8; 2] = [0x00, 0x01];

/// Default P-Selector on both sides of the association.
pub const DEFAULT_P_SELECTOR: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

/// Arc values of the default local, that is calling, AP-title `1.1.1.999`.
pub const DEFAULT_LOCAL_AP_TITLE: [u32; 4] = [1, 1, 1, 999];

/// Arc values of the default remote, that is called, AP-title `1.1.1.999.1`.
pub const DEFAULT_REMOTE_AP_TITLE: [u32; 5] = [1, 1, 1, 999, 1];

/// Default AE-qualifier on both sides of the association.
pub const DEFAULT_AE_QUALIFIER: i32 = 12;

/// Number of value bits an OID arc contributes to one base-128 octet.
const OID_ARC_BITS: u32 = 7;

/// Continuation bit of a base-128 OID arc octet; clear on the final octet.
const OID_CONTINUATION_BIT: u8 = 0x80;

/// Mask selecting the value bits of a base-128 OID arc octet.
const OID_ARC_MASK: u8 = 0x7F;

/// Multiplier applied to the first arc where it is joined with the second.
const OID_FIRST_ARC_FACTOR: u32 = 40;

/// Largest value the second arc may take while the first is 0 or 1.
const OID_SECOND_ARC_MAX: u32 = 39;

/// Largest value the first arc of an OID may take.
const OID_FIRST_ARC_MAX: u32 = 2;

/// Number of base-128 octets a 32-bit arc can occupy.
const OID_MAX_ARC_OCTETS: usize = 5;

// Errors

/// Errors raised while parsing or decoding an AP-title.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ApTitleError {
    /// Fewer than the two arcs an OBJECT IDENTIFIER requires.
    #[error("ap-title needs at least two arcs, got {count}")]
    TooFewArcs {
        /// Number of arcs supplied.
        count: usize,
    },

    /// An arc is not a decimal number, or does not fit in 32 bits.
    #[error("ap-title arc {arc} is not a 32-bit decimal number")]
    InvalidArc {
        /// Text of the offending arc.
        arc: String,
    },

    /// The first arc is above 2, or the second is above 39 while the first is
    /// 0 or 1; neither combination is encodable.
    #[error("ap-title arcs {first}.{second} are outside the encodable range")]
    ArcOutOfRange {
        /// First arc value.
        first: u32,
        /// Second arc value.
        second: u32,
    },

    /// The BER content octets are empty, or the last one still carries the
    /// continuation bit.
    #[error("ap-title ber content is truncated")]
    Truncated,

    /// A base-128 arc does not fit in 32 bits.
    #[error("ap-title ber content holds an arc wider than 32 bits")]
    ArcOverflow,
}

// ApTitle

/// An AP-title, the OBJECT IDENTIFIER naming an application process.
///
/// Held as arc values, so `1.1.1.999` is `[1, 1, 1, 999]`. `Display` renders
/// the dotted form and [`FromStr`] parses it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApTitle {
    arcs: Vec<u32>,
}

impl ApTitle {
    /// Builds a title from its arc values.
    ///
    /// # Errors
    ///
    /// - `TooFewArcs` for fewer than two arcs.
    /// - `ArcOutOfRange` when the first two arcs are not encodable.
    pub fn from_arcs(arcs: &[u32]) -> Result<Self, ApTitleError> {
        if arcs.len() < 2 {
            return Err(ApTitleError::TooFewArcs { count: arcs.len() });
        }
        let (first, second) = (arcs[0], arcs[1]);
        if first > OID_FIRST_ARC_MAX || (first < OID_FIRST_ARC_MAX && second > OID_SECOND_ARC_MAX) {
            return Err(ApTitleError::ArcOutOfRange { first, second });
        }
        Ok(Self {
            arcs: arcs.to_vec(),
        })
    }

    /// Returns the arc values.
    pub fn arcs(&self) -> &[u32] {
        &self.arcs
    }

    /// Encodes the title as the BER content octets of an OBJECT IDENTIFIER.
    ///
    /// The first two arcs are joined as `40 * first + second`, and every
    /// further arc is written base-128, most significant group first, with the
    /// continuation bit set on all but the last octet.
    pub fn to_ber_content(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let joined = OID_FIRST_ARC_FACTOR * self.arcs[0] + self.arcs[1];
        write_base128(joined, &mut out);
        for &arc in &self.arcs[2..] {
            write_base128(arc, &mut out);
        }
        out
    }

    /// Decodes the BER content octets of an OBJECT IDENTIFIER.
    ///
    /// # Errors
    ///
    /// - `Truncated` for empty content, or content whose last octet still
    ///   carries the continuation bit.
    /// - `ArcOverflow` for an arc wider than 32 bits.
    pub fn from_ber_content(content: &[u8]) -> Result<Self, ApTitleError> {
        if content.is_empty() {
            return Err(ApTitleError::Truncated);
        }
        let mut arcs: Vec<u32> = Vec::new();
        let mut value: u32 = 0;
        let mut in_progress = false;

        for &byte in content {
            // shifting in the next group must not drop significant bits
            if value >> (u32::BITS - OID_ARC_BITS) != 0 {
                return Err(ApTitleError::ArcOverflow);
            }
            value = (value << OID_ARC_BITS) | (byte & OID_ARC_MASK) as u32;
            in_progress = byte & OID_CONTINUATION_BIT != 0;
            if !in_progress {
                if arcs.is_empty() {
                    // the first octet group carries the first two arcs joined
                    let first = (value / OID_FIRST_ARC_FACTOR).min(OID_FIRST_ARC_MAX);
                    let second = value - OID_FIRST_ARC_FACTOR * first;
                    arcs.push(first);
                    arcs.push(second);
                } else {
                    arcs.push(value);
                }
                value = 0;
            }
        }

        if in_progress {
            return Err(ApTitleError::Truncated);
        }
        Ok(Self { arcs })
    }
}

impl FromStr for ApTitle {
    type Err = ApTitleError;

    /// Parses the dotted form, for instance `1.1.1.999`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut arcs: Vec<u32> = Vec::new();
        for part in s.split('.') {
            let arc = part.parse::<u32>().map_err(|_| ApTitleError::InvalidArc {
                arc: part.to_string(),
            })?;
            arcs.push(arc);
        }
        Self::from_arcs(&arcs)
    }
}

impl fmt::Display for ApTitle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, arc) in self.arcs.iter().enumerate() {
            if i > 0 {
                write!(f, ".")?;
            }
            write!(f, "{arc}")?;
        }
        Ok(())
    }
}

/// Appends one arc to `out` in base-128 form, most significant group first.
fn write_base128(mut value: u32, out: &mut Vec<u8>) {
    let mut group = [0u8; OID_MAX_ARC_OCTETS];
    let mut len = 0usize;
    loop {
        group[len] = (value as u8) & OID_ARC_MASK;
        len += 1;
        value >>= OID_ARC_BITS;
        if value == 0 {
            break;
        }
    }
    for i in (0..len).rev() {
        let is_last = i == 0;
        out.push(if is_last {
            group[i]
        } else {
            group[i] | OID_CONTINUATION_BIT
        });
    }
}

// AarqAddressing

/// The addressing fields of an AARQ, as named in the ISO 8650 AARQ-apdu.
///
/// Every field is OPTIONAL; a `None` field is not written to the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AarqAddressing {
    /// called-AP-title `[2]`.
    pub called_ap_title: Option<ApTitle>,
    /// called-AE-qualifier `[3]`.
    pub called_ae_qualifier: Option<i32>,
    /// calling-AP-title `[6]`.
    pub calling_ap_title: Option<ApTitle>,
    /// calling-AE-qualifier `[7]`.
    pub calling_ae_qualifier: Option<i32>,
}

// IsoConnectionParameters

/// The ISO addressing a client offers when it associates.
///
/// `local_*` names the calling side and `remote_*` the called side. The
/// defaults are the values IEC 61850-8-1 Annex A lists for an MMS association.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsoConnectionParameters {
    /// Calling T-Selector, at most 4 bytes.
    pub local_t_sel: TSelector,
    /// Called T-Selector, at most 4 bytes.
    pub remote_t_sel: TSelector,
    /// Calling S-Selector.
    pub local_s_sel: SSelector,
    /// Called S-Selector.
    pub remote_s_sel: SSelector,
    /// Calling P-Selector.
    pub local_p_sel: PSelector,
    /// Called P-Selector.
    pub remote_p_sel: PSelector,
    /// calling-AP-title; `None` leaves the field out of the AARQ.
    pub local_ap_title: Option<ApTitle>,
    /// called-AP-title; `None` leaves the field out of the AARQ.
    pub remote_ap_title: Option<ApTitle>,
    /// calling-AE-qualifier; `None` leaves the field out of the AARQ.
    pub local_ae_qualifier: Option<i32>,
    /// called-AE-qualifier; `None` leaves the field out of the AARQ.
    pub remote_ae_qualifier: Option<i32>,
}

impl IsoConnectionParameters {
    /// Returns the AARQ addressing fields, mapping local to calling and remote
    /// to called.
    pub fn aarq_addressing(&self) -> AarqAddressing {
        AarqAddressing {
            called_ap_title: self.remote_ap_title.clone(),
            called_ae_qualifier: self.remote_ae_qualifier,
            calling_ap_title: self.local_ap_title.clone(),
            calling_ae_qualifier: self.local_ae_qualifier,
        }
    }
}

impl Default for IsoConnectionParameters {
    fn default() -> Self {
        Self {
            local_t_sel: default_t_sel(),
            remote_t_sel: default_t_sel(),
            local_s_sel: default_s_sel(),
            remote_s_sel: default_s_sel(),
            local_p_sel: default_p_sel(),
            remote_p_sel: default_p_sel(),
            local_ap_title: ApTitle::from_arcs(&DEFAULT_LOCAL_AP_TITLE).ok(),
            remote_ap_title: ApTitle::from_arcs(&DEFAULT_REMOTE_AP_TITLE).ok(),
            local_ae_qualifier: Some(DEFAULT_AE_QUALIFIER),
            remote_ae_qualifier: Some(DEFAULT_AE_QUALIFIER),
        }
    }
}

/// Builds the default T-Selector without going through a fallible constructor.
fn default_t_sel() -> TSelector {
    let mut value = [0u8; 4];
    value[..DEFAULT_T_SELECTOR.len()].copy_from_slice(&DEFAULT_T_SELECTOR);
    TSelector {
        size: DEFAULT_T_SELECTOR.len() as u8,
        value,
    }
}

/// Builds the default S-Selector without going through a fallible constructor.
fn default_s_sel() -> SSelector {
    let mut value = [0u8; 16];
    value[..DEFAULT_S_SELECTOR.len()].copy_from_slice(&DEFAULT_S_SELECTOR);
    SSelector {
        size: DEFAULT_S_SELECTOR.len() as u8,
        value,
    }
}

/// Builds the default P-Selector without going through a fallible constructor.
fn default_p_sel() -> PSelector {
    let mut value = [0u8; 16];
    value[..DEFAULT_P_SELECTOR.len()].copy_from_slice(&DEFAULT_P_SELECTOR);
    PSelector {
        size: DEFAULT_P_SELECTOR.len() as u8,
        value,
    }
}

// Unit tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ap_title_encodes_the_local_default_oid() {
        let title: ApTitle = "1.1.1.999".parse().expect("parse");
        assert_eq!(title.to_ber_content(), vec![0x29, 0x01, 0x87, 0x67]);
    }

    #[test]
    fn ap_title_encodes_the_remote_default_oid() {
        let title: ApTitle = "1.1.1.999.1".parse().expect("parse");
        assert_eq!(title.to_ber_content(), vec![0x29, 0x01, 0x87, 0x67, 0x01]);
    }

    #[test]
    fn ap_title_ber_content_round_trips() {
        for text in ["1.1.1.999", "1.1.1.999.1", "1.3.9999.13", "2.16.840.1.101"] {
            let title: ApTitle = text.parse().expect("parse");
            let decoded = ApTitle::from_ber_content(&title.to_ber_content()).expect("decode");
            assert_eq!(decoded, title, "{text}");
            assert_eq!(decoded.to_string(), text);
        }
    }

    #[test]
    fn ap_title_rejects_malformed_text() {
        assert!(matches!(
            "1".parse::<ApTitle>(),
            Err(ApTitleError::TooFewArcs { count: 1 })
        ));
        assert!(matches!(
            "1.x".parse::<ApTitle>(),
            Err(ApTitleError::InvalidArc { .. })
        ));
        assert!(matches!(
            "3.1".parse::<ApTitle>(),
            Err(ApTitleError::ArcOutOfRange {
                first: 3,
                second: 1
            })
        ));
        assert!(matches!(
            "1.40".parse::<ApTitle>(),
            Err(ApTitleError::ArcOutOfRange {
                first: 1,
                second: 40
            })
        ));
    }

    #[test]
    fn ap_title_rejects_truncated_ber_content() {
        assert_eq!(
            ApTitle::from_ber_content(&[]),
            Err(ApTitleError::Truncated),
            "empty content"
        );
        assert_eq!(
            ApTitle::from_ber_content(&[0x29, 0x87]),
            Err(ApTitleError::Truncated),
            "continuation bit set on the last octet"
        );
    }

    #[test]
    fn ap_title_rejects_an_arc_wider_than_32_bits() {
        // six continuation octets carry more than 32 value bits
        let content = [0x29, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F];
        assert_eq!(
            ApTitle::from_ber_content(&content),
            Err(ApTitleError::ArcOverflow)
        );
    }

    #[test]
    fn defaults_match_the_documented_values() {
        let params = IsoConnectionParameters::default();
        assert_eq!(params.local_t_sel.as_slice(), &[0x00, 0x01]);
        assert_eq!(params.remote_t_sel.as_slice(), &[0x00, 0x01]);
        assert_eq!(params.local_s_sel.as_slice(), &[0x00, 0x01]);
        assert_eq!(params.remote_s_sel.as_slice(), &[0x00, 0x01]);
        assert_eq!(params.local_p_sel.as_slice(), &[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(params.remote_p_sel.as_slice(), &[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(
            params.local_ap_title.as_ref().map(|t| t.to_string()),
            Some("1.1.1.999".to_string())
        );
        assert_eq!(
            params.remote_ap_title.as_ref().map(|t| t.to_string()),
            Some("1.1.1.999.1".to_string())
        );
        assert_eq!(params.local_ae_qualifier, Some(DEFAULT_AE_QUALIFIER));
        assert_eq!(params.remote_ae_qualifier, Some(DEFAULT_AE_QUALIFIER));
    }

    #[test]
    fn aarq_addressing_maps_local_to_calling() {
        let params = IsoConnectionParameters::default();
        let addressing = params.aarq_addressing();
        assert_eq!(addressing.calling_ap_title, params.local_ap_title);
        assert_eq!(addressing.called_ap_title, params.remote_ap_title);
        assert_eq!(addressing.calling_ae_qualifier, params.local_ae_qualifier);
        assert_eq!(addressing.called_ae_qualifier, params.remote_ae_qualifier);
    }
}
