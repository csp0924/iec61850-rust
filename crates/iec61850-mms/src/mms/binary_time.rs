//! MMS BINARY-TIME conversion, per ISO 9506 and IEC 61850-8-1.
//!
//! BINARY-TIME is an OCTET STRING of either four or six octets. Both forms open
//! with four big-endian octets of milliseconds elapsed since midnight. The
//! six-octet form appends two big-endian octets counting whole days since
//! 1984-01-01, which is the epoch of the type; the four-octet form carries no
//! date at all.
//!
//! Every encoder and decoder in this workspace routes through this module so
//! that the wire epoch is 1984-01-01 on both sides of a link.

/// Number of octets of the long BINARY-TIME form: milliseconds of day plus day count.
pub const BINARY_TIME6_LEN: usize = 6;

/// Milliseconds in one day.
const MS_PER_DAY: u64 = 86_400_000;

/// Whole days from 1970-01-01 to the BINARY-TIME epoch of 1984-01-01.
///
/// Fourteen years of 365 days plus the leap days of 1972, 1976 and 1980.
const DAYS_1970_TO_1984: u64 = 5113;

/// The BINARY-TIME epoch 1984-01-01T00:00:00Z, in milliseconds since 1970-01-01.
pub const EPOCH_1984_MS: u64 = DAYS_1970_TO_1984 * MS_PER_DAY;

/// Largest instant the six-octet form can express: day count 0xFFFF, last millisecond.
const MAX_BINARY_TIME6_MS: u64 = EPOCH_1984_MS + (u16::MAX as u64) * MS_PER_DAY + (MS_PER_DAY - 1);

/// Converts milliseconds since 1970-01-01 into the six-octet BINARY-TIME form.
///
/// The result is four big-endian octets of milliseconds since midnight followed
/// by two big-endian octets of days since 1984-01-01.
///
/// The type cannot express an instant outside its epoch range, and the encoders
/// that call this are infallible, so the value saturates: an instant before
/// 1984-01-01 encodes as the epoch itself (all six octets zero) and an instant
/// beyond day count 0xFFFF encodes as the last millisecond of that day.
/// Saturation is silent, since the signature carries no error channel: a caller
/// that must distinguish an out-of-range instant checks the range itself before
/// encoding.
pub fn binary_time6_from_epoch_ms(epoch_ms: u64) -> [u8; BINARY_TIME6_LEN] {
    let clamped = epoch_ms.clamp(EPOCH_1984_MS, MAX_BINARY_TIME6_MS);
    let since_1984 = clamped - EPOCH_1984_MS;
    let days_since_1984 = (since_1984 / MS_PER_DAY) as u16;
    let ms_of_day = (since_1984 % MS_PER_DAY) as u32;
    let mut out = [0u8; BINARY_TIME6_LEN];
    out[0..4].copy_from_slice(&ms_of_day.to_be_bytes());
    out[4..6].copy_from_slice(&days_since_1984.to_be_bytes());
    out
}

/// Converts the six-octet BINARY-TIME form into milliseconds since 1970-01-01.
///
/// Inverse of [`binary_time6_from_epoch_ms`] for every instant the type can
/// express. A day count of 0xFFFF with a milliseconds-of-day field above
/// 86 399 999 is out of range for the type; the field is added as given rather
/// than rejected, since the caller has no error channel here.
pub fn epoch_ms_from_binary_time6(b: [u8; BINARY_TIME6_LEN]) -> u64 {
    let ms_of_day = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
    let days_since_1984 = u16::from_be_bytes([b[4], b[5]]) as u64;
    EPOCH_1984_MS + days_since_1984 * MS_PER_DAY + ms_of_day
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_1984_constant_matches_day_count() {
        assert_eq!(EPOCH_1984_MS, 441_763_200_000);
    }

    #[test]
    fn epoch_encodes_to_all_zero_octets() {
        assert_eq!(binary_time6_from_epoch_ms(EPOCH_1984_MS), [0u8; 6]);
        assert_eq!(epoch_ms_from_binary_time6([0u8; 6]), EPOCH_1984_MS);
    }

    #[test]
    fn round_trip_over_representable_instants() {
        let cases = [
            EPOCH_1984_MS,
            EPOCH_1984_MS + 1,
            EPOCH_1984_MS + MS_PER_DAY - 1,
            EPOCH_1984_MS + MS_PER_DAY,
            1_700_000_000_000, // 2023-11-14T22:13:20Z
            MAX_BINARY_TIME6_MS,
        ];
        for ms in cases {
            let bt = binary_time6_from_epoch_ms(ms);
            assert_eq!(
                epoch_ms_from_binary_time6(bt),
                ms,
                "round trip failed at {ms}"
            );
        }
    }

    #[test]
    fn splits_milliseconds_of_day_and_day_count() {
        let ms_of_day = 12 * 3_600_000 + 34 * 60_000 + 56_789;
        let epoch_ms = EPOCH_1984_MS + MS_PER_DAY + ms_of_day;
        let bt = binary_time6_from_epoch_ms(epoch_ms);
        assert_eq!(
            u32::from_be_bytes([bt[0], bt[1], bt[2], bt[3]]) as u64,
            ms_of_day
        );
        assert_eq!(u16::from_be_bytes([bt[4], bt[5]]), 1);
    }

    #[test]
    fn instants_before_the_epoch_saturate_to_the_epoch() {
        assert_eq!(binary_time6_from_epoch_ms(0), [0u8; 6]);
        assert_eq!(binary_time6_from_epoch_ms(EPOCH_1984_MS - 1), [0u8; 6]);
    }

    #[test]
    fn instants_beyond_the_day_count_saturate_to_the_maximum() {
        let bt = binary_time6_from_epoch_ms(MAX_BINARY_TIME6_MS + 1);
        assert_eq!(bt, binary_time6_from_epoch_ms(MAX_BINARY_TIME6_MS));
        assert_eq!(u16::from_be_bytes([bt[4], bt[5]]), u16::MAX);
    }

    #[test]
    fn known_wire_vector_for_a_fixed_instant() {
        // 1984-01-03T00:00:01.000Z: day count 2, 1000 ms of day.
        let epoch_ms = EPOCH_1984_MS + 2 * MS_PER_DAY + 1_000;
        assert_eq!(
            binary_time6_from_epoch_ms(epoch_ms),
            [0x00, 0x00, 0x03, 0xe8, 0x00, 0x02]
        );
    }
}
