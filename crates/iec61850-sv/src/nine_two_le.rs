//! The 64-byte sample layout of IEC 61850-9-2 Light Edition.
//!
//! `NineTwoLE` encodes and decodes the eight fixed channels of 9-2 LE: the
//! three phase currents, the neutral current, the three phase voltages, and the
//! neutral voltage.
//!
//! ## Channel layout, 64 bytes, big-endian
//!
//! ```text
//! Offset  Type   Channel
//!  0      i32    IA (phase A current)
//!  4      u32    IA quality (13 significant bits)
//!  8      i32    IB
//! 12      u32    IB quality
//! 16      i32    IC
//! 20      u32    IC quality
//! 24      i32    IN (neutral current)
//! 28      u32    IN quality
//! 32      i32    VA (phase A voltage)
//! 36      u32    VA quality
//! 40      i32    VB
//! 44      u32    VB quality
//! 48      i32    VC
//! 52      u32    VC quality
//! 56      i32    VN (neutral voltage)
//! 60      u32    VN quality
//! ```
//!
//! ## Quality encoding
//!
//! A quality field occupies 4 big-endian bytes of which only the low 16 bits
//! are significant, so the upper two bytes are sent as zero. Decoding keeps the
//! low 16 bits and logs a warning if the upper bytes are not zero, which keeps
//! a publisher that sets reserved bits from being rejected outright.

use iec61850_model::Quality;

/// Number of channels in a 9-2 LE sample.
pub const CHANNEL_COUNT: usize = 8;

/// Bytes per channel: a 4-byte value followed by a 4-byte quality.
pub const BYTES_PER_CHANNEL: usize = 8;

/// Total size of one 9-2 LE sample.
pub const SAMPLE_SIZE: usize = CHANNEL_COUNT * BYTES_PER_CHANNEL;

/// Channel names in the order the standard defines.
pub const CHANNEL_NAMES: [&str; CHANNEL_COUNT] = ["IA", "IB", "IC", "IN", "VA", "VB", "VC", "VN"];

/// One channel of a sample: an instantaneous value and its quality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelSample {
    /// Instantaneous value; the unit and scaling come from the data set.
    pub value: i32,
    /// Quality bit string as defined by IEC 61850-7-3.
    pub quality: Quality,
}

impl ChannelSample {
    /// Creates a channel sample.
    pub fn new(value: i32, quality: Quality) -> Self {
        ChannelSample { value, quality }
    }
}

/// A complete 9-2 LE sample, the decoded form of the 64-byte ASDU sample
/// field, with named channel accessors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NineTwoLE {
    /// Channels in standard order: IA, IB, IC, IN, VA, VB, VC, VN.
    pub channels: [ChannelSample; CHANNEL_COUNT],
}

impl NineTwoLE {
    /// Decodes a 64-byte sample buffer.
    ///
    /// A quality field whose upper two bytes are non-zero is logged and its low
    /// 16 bits are kept.
    pub fn from_sample(buf: &[u8; SAMPLE_SIZE]) -> Self {
        let mut channels = [ChannelSample {
            value: 0,
            quality: Quality::GOOD,
        }; CHANNEL_COUNT];

        for i in 0..CHANNEL_COUNT {
            let off = i * BYTES_PER_CHANNEL;

            let value = i32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);

            let q_raw =
                u32::from_be_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);

            if q_raw > 0xFFFF {
                tracing::warn!(
                    "sv quality channel {} has non-zero upper bytes (raw=0x{:08x}), keeping the low 16 bits",
                    CHANNEL_NAMES[i],
                    q_raw
                );
            }
            let quality = Quality(q_raw as u16);

            channels[i] = ChannelSample { value, quality };
        }

        NineTwoLE { channels }
    }

    /// Encodes the sample into a 64-byte buffer.
    ///
    /// The upper two bytes of each quality field are written as zero.
    pub fn to_sample(&self) -> [u8; SAMPLE_SIZE] {
        let mut buf = [0u8; SAMPLE_SIZE];

        for (i, ch) in self.channels.iter().enumerate() {
            let off = i * BYTES_PER_CHANNEL;

            buf[off..off + 4].copy_from_slice(&ch.value.to_be_bytes());

            let q_u32 = ch.quality.0 as u32;
            buf[off + 4..off + 8].copy_from_slice(&q_u32.to_be_bytes());
        }

        buf
    }

    /// Returns the channel at `idx`, or `None` when `idx` exceeds 7.
    pub fn channel(&self, idx: usize) -> Option<&ChannelSample> {
        self.channels.get(idx)
    }

    /// Returns the phase A current.
    pub fn ia(&self) -> ChannelSample {
        self.channels[0]
    }

    /// Returns the phase B current.
    pub fn ib(&self) -> ChannelSample {
        self.channels[1]
    }

    /// Returns the phase C current.
    pub fn ic(&self) -> ChannelSample {
        self.channels[2]
    }

    /// Returns the neutral current.
    pub fn in_(&self) -> ChannelSample {
        self.channels[3]
    }

    /// Returns the phase A voltage.
    pub fn va(&self) -> ChannelSample {
        self.channels[4]
    }

    /// Returns the phase B voltage.
    pub fn vb(&self) -> ChannelSample {
        self.channels[5]
    }

    /// Returns the phase C voltage.
    pub fn vc(&self) -> ChannelSample {
        self.channels[6]
    }

    /// Returns the neutral voltage.
    pub fn vn(&self) -> ChannelSample {
        self.channels[7]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns an all-zero sample buffer.
    fn zero_buf() -> [u8; SAMPLE_SIZE] {
        [0u8; SAMPLE_SIZE]
    }

    #[test]
    fn from_sample_all_zeros() {
        let buf = zero_buf();
        let sv = NineTwoLE::from_sample(&buf);
        for ch in &sv.channels {
            assert_eq!(ch.value, 0);
            assert_eq!(ch.quality, Quality::GOOD);
        }
    }

    #[test]
    fn to_sample_all_zeros() {
        let sv = NineTwoLE {
            channels: [ChannelSample {
                value: 0,
                quality: Quality::GOOD,
            }; CHANNEL_COUNT],
        };
        let buf = sv.to_sample();
        assert_eq!(buf, [0u8; SAMPLE_SIZE]);
    }

    #[test]
    fn roundtrip_known_values() {
        let mut channels = [ChannelSample {
            value: 0,
            quality: Quality::GOOD,
        }; CHANNEL_COUNT];
        channels[0] = ChannelSample::new(1000_i32, Quality(0x0001));
        channels[1] = ChannelSample::new(-500_i32, Quality(0x0002));
        channels[2] = ChannelSample::new(750_i32, Quality(0x0004));
        channels[3] = ChannelSample::new(0_i32, Quality(0x0008));
        channels[4] = ChannelSample::new(220000_i32, Quality(0x0010));
        channels[5] = ChannelSample::new(220000_i32, Quality(0x0020));
        channels[6] = ChannelSample::new(220000_i32, Quality(0x0040));
        channels[7] = ChannelSample::new(0_i32, Quality(0x0080));

        let sv = NineTwoLE { channels };
        let buf = sv.to_sample();
        let decoded = NineTwoLE::from_sample(&buf);
        assert_eq!(decoded, sv);
    }

    #[test]
    fn roundtrip_negative_values() {
        let mut channels = [ChannelSample {
            value: 0,
            quality: Quality::GOOD,
        }; CHANNEL_COUNT];
        channels[0] = ChannelSample::new(i32::MIN, Quality(0x1FFF)); // max quality bits
        channels[7] = ChannelSample::new(i32::MAX, Quality(0x0000));
        let sv = NineTwoLE { channels };
        let buf = sv.to_sample();
        let decoded = NineTwoLE::from_sample(&buf);
        assert_eq!(decoded.channels[0].value, i32::MIN);
        assert_eq!(decoded.channels[0].quality, Quality(0x1FFF));
        assert_eq!(decoded.channels[7].value, i32::MAX);
    }

    #[test]
    fn quality_encode_high_bytes_zero() {
        let ch = ChannelSample::new(42, Quality(0xABCD));
        let sv = NineTwoLE {
            channels: {
                let mut arr = [ChannelSample::new(0, Quality::GOOD); CHANNEL_COUNT];
                arr[0] = ch;
                arr
            },
        };
        let buf = sv.to_sample();
        // The quality of channel 0 occupies bytes 4 through 7.
        assert_eq!(buf[4], 0x00, "quality upper byte 0 is zero");
        assert_eq!(buf[5], 0x00, "quality upper byte 1 is zero");
        assert_eq!(buf[6], 0xAB, "quality byte 2");
        assert_eq!(buf[7], 0xCD, "quality byte 3");
    }

    #[test]
    fn channel_accessors() {
        let mut channels = [ChannelSample::new(0, Quality::GOOD); CHANNEL_COUNT];
        channels[0] = ChannelSample::new(100, Quality(0x0001));
        channels[4] = ChannelSample::new(220000, Quality(0x0002));
        let sv = NineTwoLE { channels };
        assert_eq!(sv.ia().value, 100);
        assert_eq!(sv.va().value, 220000);
        assert_eq!(sv.channel(0), Some(&channels[0]));
        assert_eq!(sv.channel(8), None);
    }

    #[test]
    fn roundtrip_9_2_le_full_sample() {
        // Typical steady-state values across all eight channels.
        let sv = NineTwoLE {
            channels: [
                ChannelSample::new(500, Quality::GOOD),    // IA
                ChannelSample::new(500, Quality::GOOD),    // IB
                ChannelSample::new(500, Quality::GOOD),    // IC
                ChannelSample::new(0, Quality::GOOD),      // IN
                ChannelSample::new(220000, Quality::GOOD), // VA (220V)
                ChannelSample::new(220000, Quality::GOOD), // VB
                ChannelSample::new(220000, Quality::GOOD), // VC
                ChannelSample::new(0, Quality::GOOD),      // VN
            ],
        };
        let buf = sv.to_sample();
        assert_eq!(buf.len(), SAMPLE_SIZE);
        let decoded = NineTwoLE::from_sample(&buf);
        assert_eq!(decoded, sv);
    }

    #[test]
    fn known_wire_bytes_decode() {
        let mut buf = [0u8; SAMPLE_SIZE];
        buf[0] = 0x00;
        buf[1] = 0x00;
        buf[2] = 0x01;
        buf[3] = 0xF4; // IA value 0x000001F4 = 500
        buf[4] = 0x00;
        buf[5] = 0x00;
        buf[6] = 0x00;
        buf[7] = 0x00; // IA quality = 0

        let sv = NineTwoLE::from_sample(&buf);
        assert_eq!(sv.ia().value, 500);
        assert_eq!(sv.ia().quality, Quality::GOOD);
    }
}
