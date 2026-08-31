//! Encoders for the Oper, SBOw and Cancel structures of a control object.
//!
//! ```text
//! Oper / SBOw STRUCTURE (6 elements, no operTm):
//!   [0] ctlVal       (type follows the data object: BOOLEAN, INT, FLOAT, ...)
//!   [1] origin       STRUCTURE { orCat: INT, orIdent: OCTET STRING }
//!   [2] ctlNum       UNSIGNED(8)
//!   [3] T            UTC TIME
//!   [4] Test         BOOLEAN
//!   [5] Check        BIT STRING(2)  // bit 0 synchroCheck, bit 1 interlockCheck
//!
//! Cancel STRUCTURE (5 elements):
//!   [0] ctlVal
//!   [1] origin
//!   [2] ctlNum
//!   [3] T
//!   [4] Test
//! ```
//!
//! The bit assignment has to match what a server decodes; the two sides are
//! exercised together by the control end-to-end tests.

use iec61850_model::value::MmsValue;

use super::model::OriginValue;

/// Encodes an `OriginValue` as the two-element origin structure.
fn origin_to_mms(origin: &OriginValue) -> MmsValue {
    MmsValue::Structure(vec![
        MmsValue::Integer(origin.or_cat as i64),
        MmsValue::OctetString(origin.or_ident.clone()),
    ])
}

/// Encodes the Check flags as a two-bit BIT STRING.
///
/// The bits are MSB first, so synchroCheck is 0x80 and interlockCheck is 0x40
/// of the single data byte, with a padding of 6.
fn check_bits(synchro_check: bool, interlock_check: bool) -> MmsValue {
    let mut byte = 0u8;
    if synchro_check {
        byte |= 0x80;
    }
    if interlock_check {
        byte |= 0x40;
    }
    MmsValue::BitString {
        padding: 6,
        data: vec![byte],
    }
}

/// Builds the six-element Oper or SBOw structure.
///
/// `t` is an 8-byte UTC TIME supplied by the caller, normally from
/// [`current_utc_time`] or [`ms_to_utc_time`].
#[allow(clippy::too_many_arguments)]
pub fn build_oper_struct(
    ctl_val: MmsValue,
    origin: &OriginValue,
    ctl_num: u8,
    t: [u8; 8],
    test: bool,
    synchro_check: bool,
    interlock_check: bool,
) -> MmsValue {
    MmsValue::Structure(vec![
        ctl_val,
        origin_to_mms(origin),
        MmsValue::Unsigned(ctl_num as u64),
        MmsValue::UtcTime(t),
        MmsValue::Boolean(test),
        check_bits(synchro_check, interlock_check),
    ])
}

/// Builds the five-element Cancel structure.
pub fn build_cancel_struct(
    ctl_val: MmsValue,
    origin: &OriginValue,
    ctl_num: u8,
    t: [u8; 8],
    test: bool,
) -> MmsValue {
    MmsValue::Structure(vec![
        ctl_val,
        origin_to_mms(origin),
        MmsValue::Unsigned(ctl_num as u64),
        MmsValue::UtcTime(t),
        MmsValue::Boolean(test),
    ])
}

/// Converts milliseconds since the UNIX epoch into an 8-byte UTC TIME.
///
/// Bytes 0 to 3 hold the seconds and bytes 4 to 6 the fraction of a second in
/// 1/2^24 units; byte 7 carries the time quality, left at zero.
pub fn ms_to_utc_time(ms: u64) -> [u8; 8] {
    let secs = (ms / 1000) as u32;
    let frac_ms = ms % 1000;
    let frac24 = (frac_ms * (1 << 24) / 1000) as u32;
    let sb = secs.to_be_bytes();
    [
        sb[0],
        sb[1],
        sb[2],
        sb[3],
        (frac24 >> 16) as u8,
        (frac24 >> 8) as u8,
        frac24 as u8,
        0,
    ]
}

/// Returns the current wall-clock time as an 8-byte UTC TIME.
///
/// Without `std` there is no wall clock and this returns all zeros; an
/// embedded caller reads its own real-time clock and passes the result
/// through [`ms_to_utc_time`]. The hal `Timer` trait is not used here: it
/// offers relative sleeps only, with no monotonic-to-wall-clock mapping.
#[cfg(feature = "std")]
pub fn current_utc_time() -> [u8; 8] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d: core::time::Duration| d.as_millis() as u64)
        .unwrap_or(0);
    ms_to_utc_time(ms)
}

/// Returns all zeros: a `no_std` build has no wall clock. See
/// [`ms_to_utc_time`].
#[cfg(not(feature = "std"))]
pub fn current_utc_time() -> [u8; 8] {
    [0u8; 8]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oper_struct_layout_6_fields() {
        let v = build_oper_struct(
            MmsValue::Boolean(true),
            &OriginValue::bay_control(),
            7,
            [0u8; 8],
            false,
            false,
            true,
        );
        if let MmsValue::Structure(items) = v {
            assert_eq!(items.len(), 6);
            assert!(matches!(items[0], MmsValue::Boolean(true)));
            assert!(matches!(items[1], MmsValue::Structure(_)));
            assert!(matches!(items[2], MmsValue::Unsigned(7)));
            assert!(matches!(items[3], MmsValue::UtcTime(_)));
            assert!(matches!(items[4], MmsValue::Boolean(false)));
            // Check byte 0x40: interlockCheck only.
            if let MmsValue::BitString { padding, data } = &items[5] {
                assert_eq!(*padding, 6);
                assert_eq!(data, &vec![0x40]);
            } else {
                panic!("element 5 must be a BitString");
            }
        } else {
            panic!("oper structure must be a Structure");
        }
    }

    #[test]
    fn cancel_struct_layout_5_fields() {
        let v = build_cancel_struct(
            MmsValue::Boolean(false),
            &OriginValue::bay_control(),
            3,
            [0u8; 8],
            false,
        );
        if let MmsValue::Structure(items) = v {
            assert_eq!(items.len(), 5);
        } else {
            panic!();
        }
    }

    #[test]
    fn check_bits_synchro_only() {
        let v = check_bits(true, false);
        if let MmsValue::BitString { padding, data } = v {
            assert_eq!(padding, 6);
            assert_eq!(data, vec![0x80]);
        }
    }

    #[test]
    fn check_bits_both() {
        let v = check_bits(true, true);
        if let MmsValue::BitString { data, .. } = v {
            assert_eq!(data, vec![0xC0]);
        }
    }
}
