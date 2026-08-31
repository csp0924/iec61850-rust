//! NTP timestamps: 64-bit fixed point counted from 1900-01-01.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::SntpError;

/// Seconds between the NTP epoch (1900-01-01 00:00:00 UTC) and the Unix
/// epoch (1970-01-01): 70 years plus 17 leap days.
pub const NTP_UNIX_OFFSET_S: u64 = 2_208_988_800;

/// An NTP 64-bit timestamp: 32 bits of seconds, then 32 bits of fraction in
/// units of 2^-32 s.
///
/// The type names its epoch instead of exposing a bare `u64`, so an NTP
/// value cannot be mistaken for a Unix one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NtpTimestamp {
    /// Seconds since the NTP epoch.
    pub seconds: u32,
    /// Sub-second fraction, in units of 2^-32 s.
    pub fraction: u32,
}

impl NtpTimestamp {
    /// The zero timestamp, meaning unspecified or unknown.
    pub const ZERO: Self = Self {
        seconds: 0,
        fraction: 0,
    };

    /// Decodes a timestamp from its 64-bit big-endian wire word.
    pub fn from_u64(raw: u64) -> Self {
        Self {
            seconds: (raw >> 32) as u32,
            fraction: (raw & 0xFFFF_FFFF) as u32,
        }
    }

    /// Encodes the timestamp as a 64-bit raw word.
    pub fn to_u64(self) -> u64 {
        (u64::from(self.seconds) << 32) | u64::from(self.fraction)
    }

    /// Reads the current system time as an NTP timestamp.
    ///
    /// # Errors
    ///
    /// [`SntpError::TimeBeforeEpoch`] if the system clock is before the Unix
    /// epoch, or if adding the epoch offset would overflow.
    pub fn now() -> Result<Self, SntpError> {
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SntpError::TimeBeforeEpoch)?;
        let unix_secs_s = unix.as_secs();
        let unix_nanos_ns = u64::from(unix.subsec_nanos());

        // Checked, so a clock far in the future cannot wrap the addition.
        let ntp_secs_s = unix_secs_s
            .checked_add(NTP_UNIX_OFFSET_S)
            .ok_or(SntpError::TimeBeforeEpoch)?;

        // fraction = nanos * 2^32 / 1e9, shifted first in u128 to keep precision.
        let fraction = ((u128::from(unix_nanos_ns) << 32) / 1_000_000_000) as u32;

        Ok(Self {
            seconds: (ntp_secs_s & 0xFFFF_FFFF) as u32,
            fraction,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_u64() {
        let ts = NtpTimestamp {
            seconds: 0xAABBCCDD,
            fraction: 0x11223344,
        };
        let raw = ts.to_u64();
        assert_eq!(raw, 0xAABBCCDD_11223344);
        assert_eq!(NtpTimestamp::from_u64(raw), ts);
    }

    #[test]
    fn now_seconds_makes_sense() {
        // A 2026 wall clock lands near NTP second 3_976_000_000; coarse sanity check.
        let ts = NtpTimestamp::now().expect("system time post-epoch");
        // 2024-01-01 is NTP second 3_913_056_000, so any sane clock is above 3.9e9.
        assert!(ts.seconds > 3_900_000_000);
    }

    #[test]
    fn zero_round_trip() {
        assert_eq!(NtpTimestamp::from_u64(0), NtpTimestamp::ZERO);
        assert_eq!(NtpTimestamp::ZERO.to_u64(), 0);
    }
}
