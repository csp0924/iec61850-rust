//! `UtcTime`, the eight-octet encoding of a TimeStamp.
//!
//! A TimeStamp (IEC 61850-7-2 §6.1.2.9) is mapped onto the UtcTime encoding of
//! IEC 61850-8-1 §8.1.3.7 and Annex F. It carries the `t` member of a GOOSE
//! PDU (IEC 61850-8-1 §18.1.2.5 Table 88) and the refrTm member of a Sampled
//! Values ASDU (IEC 61850-9-2 §8.5.2 Table 14):
//!
//! ```text
//! octets 0..4   SecondSinceEpoch   u32 big-endian, seconds since 1970-01-01 UTC
//! octets 4..7   FractionOfSecond   24 bits, value = fraction / 2^24 s
//! octet  7      TimeQuality        0x80 LeapSecondsKnown
//!                                  0x40 ClockFailure
//!                                  0x20 ClockNotSynchronized
//!                                  0x1F TimeAccuracy
//! ```
//!
//! IEC 61850-8-1 Table 36 numbers the TimeQuality bits from the most
//! significant one: its bit 0 is the mask `0x80` above and its bits 3 to 7
//! are the mask `0x1F`.
//!
//! A value of this type is always well formed. Every bit pattern is legal
//! except the TimeAccuracy codes 25 through 30, which IEC 61850-8-1 Table 36
//! defines as invalid; [`UtcTime::from_bytes`] rejects them and every
//! constructor makes them unrepresentable. A fraction is 24 bits wide, so it
//! is always below one second.
//!
//! What the encoding leaves to the application is not judged here: how far
//! the time lies from the local clock, whether it advances between messages,
//! and the meaning of the quality flags. In particular IEC 61850-7-2
//! §6.1.2.9.3.3 requires the time value to be ignored when ClockFailure is
//! set; the flag is reported in [`TimeQuality::clock_failure`] and the value
//! is still returned.

use core::time::Duration;

use thiserror::Error;

/// Number of octets of an encoded `UtcTime`.
pub const UTC_TIME_SIZE: usize = 8;

/// Largest FractionOfSecond, `2^24 - 1`.
pub const FRACTION_OF_SECOND_MAX: u32 = 0x00FF_FFFF;

/// Number of FractionOfSecond steps in one second, `2^24`.
const FRACTION_PER_SECOND: u64 = 1 << 24;

const NANOS_PER_SECOND: u64 = 1_000_000_000;

const LEAP_SECONDS_KNOWN: u8 = 0x80;
const CLOCK_FAILURE: u8 = 0x40;
const CLOCK_NOT_SYNCHRONIZED: u8 = 0x20;
const TIME_ACCURACY_MASK: u8 = 0x1F;

/// Error building or decoding a `UtcTime`.
#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum UtcTimeError {
    /// A FractionOfSecond above [`FRACTION_OF_SECOND_MAX`], which does not fit
    /// the 24-bit field.
    #[error("fraction of second 0x{0:x} exceeds the 24 bit field")]
    FractionOutOfRange(u32),

    /// A time past the 32-bit SecondSinceEpoch field, in seconds since the
    /// epoch.
    #[error("{0} seconds since the epoch exceed the 32 bit field")]
    SecondsOutOfRange(u64),

    /// A TimeAccuracy that is not a valid code: 25 through 30, which
    /// IEC 61850-8-1 Table 36 defines as invalid, or a value that does not fit
    /// the five-bit field. From [`TimeAccuracy::bits`], a requested number of
    /// bits above 24.
    #[error("time accuracy {0} is not a valid code")]
    InvalidTimeAccuracy(u8),
}

/// TimeAccuracy, the number of significant bits of FractionOfSecond
/// (IEC 61850-7-2 §6.1.2.9.3.3 Table 9, IEC 61850-8-1 Table 36).
///
/// It holds one of the valid five-bit codes: 0 through 24 significant bits, or
/// 31 for unspecified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimeAccuracy(u8);

impl TimeAccuracy {
    /// Accuracy not specified, code 31.
    pub const UNSPECIFIED: Self = Self(31);

    /// Largest number of significant bits, 24.
    pub const MAX_BITS: u8 = 24;

    /// Accuracy of `n` significant bits of FractionOfSecond, a time interval
    /// of `2^-n` seconds.
    ///
    /// # Errors
    ///
    /// Returns `InvalidTimeAccuracy` when `n` exceeds [`MAX_BITS`](Self::MAX_BITS).
    pub const fn bits(n: u8) -> Result<Self, UtcTimeError> {
        if n > Self::MAX_BITS {
            return Err(UtcTimeError::InvalidTimeAccuracy(n));
        }
        Ok(Self(n))
    }

    /// Decodes a five-bit TimeAccuracy code.
    ///
    /// # Errors
    ///
    /// Returns `InvalidTimeAccuracy` for the invalid codes 25 through 30 and
    /// for a value above 31.
    pub const fn from_code(code: u8) -> Result<Self, UtcTimeError> {
        match code {
            0..=24 | 31 => Ok(Self(code)),
            _ => Err(UtcTimeError::InvalidTimeAccuracy(code)),
        }
    }

    /// Returns the five-bit code.
    pub const fn code(self) -> u8 {
        self.0
    }

    /// Returns the number of significant bits, or `None` when unspecified.
    pub const fn significant_bits(self) -> Option<u8> {
        if self.0 <= Self::MAX_BITS {
            Some(self.0)
        } else {
            None
        }
    }
}

/// TimeQuality, the eighth octet of a `UtcTime` (IEC 61850-7-2 §6.1.2.9.3.3
/// Table 8, IEC 61850-8-1 §8.1.3.7 Table 36).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct TimeQuality {
    /// LeapSecondsKnown: SecondSinceEpoch includes every leap second that has
    /// occurred.
    pub leap_seconds_known: bool,
    /// ClockFailure: the time source of the sender is unreliable, and the time
    /// value is to be ignored.
    pub clock_failure: bool,
    /// ClockNotSynchronized: the time source of the sender is not synchronized
    /// to external UTC time.
    pub clock_not_synchronized: bool,
    /// TimeAccuracy, the number of significant bits of FractionOfSecond.
    pub time_accuracy: TimeAccuracy,
}

impl TimeQuality {
    /// Creates a TimeQuality from its flags and accuracy.
    pub const fn new(
        leap_seconds_known: bool,
        clock_failure: bool,
        clock_not_synchronized: bool,
        time_accuracy: TimeAccuracy,
    ) -> Self {
        Self {
            leap_seconds_known,
            clock_failure,
            clock_not_synchronized,
            time_accuracy,
        }
    }

    /// Decodes the TimeQuality octet.
    ///
    /// # Errors
    ///
    /// Returns `InvalidTimeAccuracy` when the TimeAccuracy bits hold one of the
    /// invalid codes 25 through 30.
    pub const fn from_byte(b: u8) -> Result<Self, UtcTimeError> {
        match TimeAccuracy::from_code(b & TIME_ACCURACY_MASK) {
            Ok(_) => Ok(Self::from_valid_byte(b)),
            Err(e) => Err(e),
        }
    }

    /// Decodes a TimeQuality octet whose TimeAccuracy bits hold a valid code.
    const fn from_valid_byte(b: u8) -> Self {
        Self {
            leap_seconds_known: b & LEAP_SECONDS_KNOWN != 0,
            clock_failure: b & CLOCK_FAILURE != 0,
            clock_not_synchronized: b & CLOCK_NOT_SYNCHRONIZED != 0,
            time_accuracy: TimeAccuracy(b & TIME_ACCURACY_MASK),
        }
    }

    /// Encodes the TimeQuality octet.
    pub const fn to_byte(self) -> u8 {
        let mut b = self.time_accuracy.code();
        if self.leap_seconds_known {
            b |= LEAP_SECONDS_KNOWN;
        }
        if self.clock_failure {
            b |= CLOCK_FAILURE;
        }
        if self.clock_not_synchronized {
            b |= CLOCK_NOT_SYNCHRONIZED;
        }
        b
    }
}

/// An IEC 61850 UtcTime: SecondSinceEpoch, FractionOfSecond, and TimeQuality.
///
/// See the [module documentation](self) for the encoding and for what a value
/// of this type guarantees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UtcTime([u8; UTC_TIME_SIZE]);

impl UtcTime {
    /// The NULL TimeStamp, every octet zero (IEC 61850-7-2 §6.1.2.9.3.3).
    pub const NULL: Self = Self([0; UTC_TIME_SIZE]);

    /// Creates a time from SecondSinceEpoch, a 24-bit FractionOfSecond in
    /// units of `2^-24` s, and its quality.
    ///
    /// # Errors
    ///
    /// Returns `FractionOutOfRange` when `fraction` exceeds
    /// [`FRACTION_OF_SECOND_MAX`].
    pub const fn new(
        seconds: u32,
        fraction: u32,
        quality: TimeQuality,
    ) -> Result<Self, UtcTimeError> {
        if fraction > FRACTION_OF_SECOND_MAX {
            return Err(UtcTimeError::FractionOutOfRange(fraction));
        }
        let s = seconds.to_be_bytes();
        let f = fraction.to_be_bytes();
        Ok(Self([
            s[0],
            s[1],
            s[2],
            s[3],
            f[1],
            f[2],
            f[3],
            quality.to_byte(),
        ]))
    }

    /// Creates a time from a duration since the epoch, 1970-01-01 00:00:00
    /// UTC, and its quality.
    ///
    /// The sub-second part is truncated to the `2^-24` s resolution of
    /// FractionOfSecond.
    ///
    /// # Errors
    ///
    /// Returns `SecondsOutOfRange` when the whole seconds exceed `u32::MAX`.
    pub fn from_duration_since_epoch(
        since_epoch: Duration,
        quality: TimeQuality,
    ) -> Result<Self, UtcTimeError> {
        let secs = since_epoch.as_secs();
        let seconds = u32::try_from(secs).map_err(|_| UtcTimeError::SecondsOutOfRange(secs))?;
        // Below one second of nanoseconds, so the quotient is below 2^24.
        let fraction =
            (u64::from(since_epoch.subsec_nanos()) * FRACTION_PER_SECOND / NANOS_PER_SECOND) as u32;
        Self::new(seconds, fraction, quality)
    }

    /// Decodes the eight octets of a UtcTime.
    ///
    /// # Errors
    ///
    /// Returns `InvalidTimeAccuracy` when the TimeQuality octet holds one of
    /// the invalid TimeAccuracy codes 25 through 30.
    pub const fn from_bytes(bytes: [u8; UTC_TIME_SIZE]) -> Result<Self, UtcTimeError> {
        match TimeQuality::from_byte(bytes[7]) {
            Ok(_) => Ok(Self(bytes)),
            Err(e) => Err(e),
        }
    }

    /// Returns the eight encoded octets.
    pub const fn to_bytes(self) -> [u8; UTC_TIME_SIZE] {
        self.0
    }

    /// Returns SecondSinceEpoch, the seconds since 1970-01-01 00:00:00 UTC.
    pub const fn seconds_since_epoch(self) -> u32 {
        u32::from_be_bytes([self.0[0], self.0[1], self.0[2], self.0[3]])
    }

    /// Returns FractionOfSecond in units of `2^-24` s, at most
    /// [`FRACTION_OF_SECOND_MAX`].
    pub const fn fraction_of_second(self) -> u32 {
        u32::from_be_bytes([0, self.0[4], self.0[5], self.0[6]])
    }

    /// Returns FractionOfSecond as whole nanoseconds, truncated; always below
    /// one second.
    pub const fn subsec_nanos(self) -> u32 {
        (self.fraction_of_second() as u64 * NANOS_PER_SECOND / FRACTION_PER_SECOND) as u32
    }

    /// Returns the time as a duration since 1970-01-01 00:00:00 UTC.
    pub const fn duration_since_epoch(self) -> Duration {
        Duration::new(self.seconds_since_epoch() as u64, self.subsec_nanos())
    }

    /// Returns the TimeQuality.
    pub const fn time_quality(self) -> TimeQuality {
        TimeQuality::from_valid_byte(self.0[7])
    }

    /// Returns whether this is the NULL TimeStamp, every octet zero.
    pub const fn is_null(self) -> bool {
        u64::from_be_bytes(self.0) == 0
    }
}

impl TryFrom<[u8; UTC_TIME_SIZE]> for UtcTime {
    type Error = UtcTimeError;

    fn try_from(bytes: [u8; UTC_TIME_SIZE]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl From<UtcTime> for [u8; UTC_TIME_SIZE] {
    fn from(t: UtcTime) -> Self {
        t.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(accuracy: u8) -> TimeQuality {
        TimeQuality::new(true, false, false, TimeAccuracy::bits(accuracy).unwrap())
    }

    #[test]
    fn layout_of_fields() {
        let t = UtcTime::new(0x0102_0304, 0x00AB_CDEF, q(10)).unwrap();
        assert_eq!(
            t.to_bytes(),
            [0x01, 0x02, 0x03, 0x04, 0xAB, 0xCD, 0xEF, 0x8A]
        );
        assert_eq!(t.seconds_since_epoch(), 0x0102_0304);
        assert_eq!(t.fraction_of_second(), 0x00AB_CDEF);
        assert_eq!(t.time_quality(), q(10));
    }

    #[test]
    fn quality_flag_bits() {
        let all = TimeQuality::new(true, true, true, TimeAccuracy::UNSPECIFIED);
        assert_eq!(all.to_byte(), 0xFF);
        assert_eq!(TimeQuality::from_byte(0xFF), Ok(all));
        let tq = TimeQuality::new(false, true, false, TimeAccuracy::bits(0).unwrap());
        assert_eq!(tq.to_byte(), 0x40);
        let tq = TimeQuality::new(false, false, true, TimeAccuracy::bits(24).unwrap());
        assert_eq!(tq.to_byte(), 0x38);
        assert_eq!(TimeQuality::from_byte(0x38), Ok(tq));
    }

    #[test]
    fn every_quality_octet_decodes_unless_accuracy_is_invalid() {
        for b in 0..=u8::MAX {
            let code = b & 0x1F;
            let decoded = TimeQuality::from_byte(b);
            if (25..=30).contains(&code) {
                assert_eq!(
                    decoded,
                    Err(UtcTimeError::InvalidTimeAccuracy(code)),
                    "{b:#04x}"
                );
            } else {
                assert_eq!(decoded.map(TimeQuality::to_byte), Ok(b), "{b:#04x}");
            }
        }
    }

    #[test]
    fn accuracy_codes() {
        assert_eq!(TimeAccuracy::bits(24).map(TimeAccuracy::code), Ok(24));
        assert_eq!(TimeAccuracy::bits(24).unwrap().significant_bits(), Some(24));
        assert_eq!(
            TimeAccuracy::bits(25),
            Err(UtcTimeError::InvalidTimeAccuracy(25))
        );
        assert_eq!(TimeAccuracy::from_code(31), Ok(TimeAccuracy::UNSPECIFIED));
        assert_eq!(
            TimeAccuracy::from_code(30),
            Err(UtcTimeError::InvalidTimeAccuracy(30))
        );
        assert_eq!(
            TimeAccuracy::from_code(32),
            Err(UtcTimeError::InvalidTimeAccuracy(32))
        );
        assert_eq!(TimeAccuracy::UNSPECIFIED.significant_bits(), None);
        assert_eq!(TimeAccuracy::bits(0).unwrap().significant_bits(), Some(0));
    }

    #[test]
    fn fraction_bound() {
        assert!(UtcTime::new(0, FRACTION_OF_SECOND_MAX, q(24)).is_ok());
        assert_eq!(
            UtcTime::new(0, FRACTION_OF_SECOND_MAX + 1, q(24)),
            Err(UtcTimeError::FractionOutOfRange(0x0100_0000))
        );
    }

    #[test]
    fn from_bytes_rejects_only_invalid_accuracy() {
        let mut b = [0x5F, 0xA1, 0x23, 0x45, 0xFF, 0xFF, 0xFF, 0x00];
        for code in 0..=31u8 {
            b[7] = 0xE0 | code;
            let r = UtcTime::from_bytes(b);
            if (25..=30).contains(&code) {
                assert_eq!(r, Err(UtcTimeError::InvalidTimeAccuracy(code)));
            } else {
                assert_eq!(r.map(UtcTime::to_bytes), Ok(b));
            }
        }
    }

    #[test]
    fn nanos_conversion() {
        let half = UtcTime::new(7, 0x0080_0000, q(1)).unwrap();
        assert_eq!(half.subsec_nanos(), 500_000_000);
        assert_eq!(half.duration_since_epoch(), Duration::new(7, 500_000_000));
        let max = UtcTime::new(0, FRACTION_OF_SECOND_MAX, q(24)).unwrap();
        assert_eq!(max.subsec_nanos(), 999_999_940);

        let d = Duration::new(1_700_000_000, 250_000_000);
        let t = UtcTime::from_duration_since_epoch(d, q(20)).unwrap();
        assert_eq!(t.seconds_since_epoch(), 1_700_000_000);
        assert_eq!(t.fraction_of_second(), 0x0040_0000);
        assert_eq!(t.duration_since_epoch(), d);

        let last = Duration::new(0, 999_999_999);
        let t = UtcTime::from_duration_since_epoch(last, q(24)).unwrap();
        assert_eq!(t.fraction_of_second(), FRACTION_OF_SECOND_MAX);
    }

    #[test]
    fn seconds_bound() {
        let ok = Duration::from_secs(u64::from(u32::MAX));
        assert!(UtcTime::from_duration_since_epoch(ok, q(0)).is_ok());
        let over = Duration::from_secs(u64::from(u32::MAX) + 1);
        assert_eq!(
            UtcTime::from_duration_since_epoch(over, q(0)),
            Err(UtcTimeError::SecondsOutOfRange(u64::from(u32::MAX) + 1))
        );
    }

    #[test]
    fn null_timestamp() {
        assert!(UtcTime::NULL.is_null());
        assert_eq!(UtcTime::from_bytes([0; 8]), Ok(UtcTime::NULL));
        assert!(!UtcTime::new(0, 1, q(0)).unwrap().is_null());
        // The NULL TimeStamp has every field zero, TimeQuality included.
        assert!(!UtcTime::from_bytes([0, 0, 0, 0, 0, 0, 0, 0x8A])
            .unwrap()
            .is_null());
        assert!(!UtcTime::new(1, 0, TimeQuality::from_byte(0).unwrap())
            .unwrap()
            .is_null());
    }
}
