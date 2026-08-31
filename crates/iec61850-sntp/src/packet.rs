//! SNTPv4 packet encoding and decoding (RFC 4330 §4).
//!
//! Wire layout, 48 bytes:
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |LI | VN  |Mode |    Stratum    |     Poll      |   Precision   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          Root Delay                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       Root Dispersion                         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     Reference Identifier                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                    Reference Timestamp (64)                   |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                    Originate Timestamp (64)                   |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                     Receive Timestamp (64)                    |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                     Transmit Timestamp (64)                   |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use crate::error::SntpError;
use crate::time::NtpTimestamp;

/// Fixed SNTP packet length, excluding the optional authenticator.
pub const SNTP_PACKET_LEN: usize = 48;

/// Leap indicator (RFC 4330 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LeapIndicator {
    /// 0 - no warning.
    NoWarning = 0,
    /// 1 - the last minute of the day has 61 seconds.
    LastMinute61 = 1,
    /// 2 - the last minute of the day has 59 seconds.
    LastMinute59 = 2,
    /// 3 - alarm condition; the clock is not synchronized.
    AlarmUnsynchronized = 3,
}

impl LeapIndicator {
    fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0 => Self::NoWarning,
            1 => Self::LastMinute61,
            2 => Self::LastMinute59,
            // Only value 3 remains, and it means alarm; matched to avoid a panic.
            _ => Self::AlarmUnsynchronized,
        }
    }
}

/// Association mode (RFC 4330 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    /// 0 - reserved.
    Reserved = 0,
    /// 1 - symmetric active.
    SymmetricActive = 1,
    /// 2 - symmetric passive.
    SymmetricPassive = 2,
    /// 3 - client.
    Client = 3,
    /// 4 - server.
    Server = 4,
    /// 5 - broadcast.
    Broadcast = 5,
    /// 6 - reserved for the NTP control message.
    NtpControl = 6,
    /// 7 - reserved for private use.
    Private = 7,
}

impl Mode {
    fn from_bits(bits: u8) -> Self {
        match bits & 0b111 {
            0 => Self::Reserved,
            1 => Self::SymmetricActive,
            2 => Self::SymmetricPassive,
            3 => Self::Client,
            4 => Self::Server,
            5 => Self::Broadcast,
            6 => Self::NtpControl,
            _ => Self::Private,
        }
    }
}

/// A structured view of an SNTP packet, as decoded from or encoded to the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SntpPacket {
    /// Leap indicator.
    pub leap: LeapIndicator,
    /// Version number, normally 4.
    pub version: u8,
    /// Association mode.
    pub mode: Mode,
    /// Stratum: 0 unspecified, 1 primary reference, 2 and above secondary.
    pub stratum: u8,
    /// Poll interval, as log2 seconds.
    pub poll: i8,
    /// Precision, as log2 seconds.
    pub precision: i8,
    /// Root delay, an NTP short in 16.16 fixed point.
    pub root_delay: u32,
    /// Root dispersion, an NTP short in 16.16 fixed point.
    pub root_dispersion: u32,
    /// Reference identifier: four ASCII characters at stratum 1, an IPv4
    /// address or a hash otherwise.
    pub reference_id: [u8; 4],
    /// Reference timestamp.
    pub reference_ts: NtpTimestamp,
    /// Originate timestamp: the client transmit time, echoed by the server.
    pub originate_ts: NtpTimestamp,
    /// Receive timestamp: when the server received the request.
    pub receive_ts: NtpTimestamp,
    /// Transmit timestamp: when the server sent the reply.
    pub transmit_ts: NtpTimestamp,
}

impl SntpPacket {
    /// Builds an empty client request: mode 3, version 4, every other field zero.
    pub fn client_request() -> Self {
        Self {
            leap: LeapIndicator::NoWarning,
            version: 4,
            mode: Mode::Client,
            stratum: 0,
            poll: 0,
            precision: 0,
            root_delay: 0,
            root_dispersion: 0,
            reference_id: [0; 4],
            reference_ts: NtpTimestamp::ZERO,
            originate_ts: NtpTimestamp::ZERO,
            receive_ts: NtpTimestamp::ZERO,
            transmit_ts: NtpTimestamp::ZERO,
        }
    }

    /// Decodes a 48-byte wire packet.
    ///
    /// The length is validated before any field is read, so an external byte
    /// slice is never indexed unchecked.
    ///
    /// # Errors
    ///
    /// [`SntpError::InvalidLength`] if fewer than 48 bytes are supplied, and
    /// [`SntpError::InvalidHeader`] if the version number is neither 3 nor 4.
    pub fn decode(buf: &[u8]) -> Result<Self, SntpError> {
        if buf.len() < SNTP_PACKET_LEN {
            return Err(SntpError::InvalidLength {
                got: buf.len(),
                expected: SNTP_PACKET_LEN,
            });
        }

        // The length check above keeps every fixed offset below in range.
        let header = buf[0];
        let leap = LeapIndicator::from_bits(header >> 6);
        let version = (header >> 3) & 0b111;
        let mode = Mode::from_bits(header);

        // RFC 4330 accepts version 3 and version 4 only.
        if !(3..=4).contains(&version) {
            return Err(SntpError::InvalidHeader("version must be 3 or 4"));
        }

        let stratum = buf[1];
        let poll = buf[2] as i8;
        let precision = buf[3] as i8;

        let root_delay = read_u32(buf, 4)?;
        let root_dispersion = read_u32(buf, 8)?;
        let reference_id = read_array4(buf, 12)?;
        let reference_ts = NtpTimestamp::from_u64(read_u64(buf, 16)?);
        let originate_ts = NtpTimestamp::from_u64(read_u64(buf, 24)?);
        let receive_ts = NtpTimestamp::from_u64(read_u64(buf, 32)?);
        let transmit_ts = NtpTimestamp::from_u64(read_u64(buf, 40)?);

        Ok(Self {
            leap,
            version,
            mode,
            stratum,
            poll,
            precision,
            root_delay,
            root_dispersion,
            reference_id,
            reference_ts,
            originate_ts,
            receive_ts,
            transmit_ts,
        })
    }

    /// Encodes the packet into its 48-byte wire form.
    pub fn encode(&self) -> [u8; SNTP_PACKET_LEN] {
        let mut buf = [0u8; SNTP_PACKET_LEN];
        let header =
            ((self.leap as u8) << 6) | ((self.version & 0b111) << 3) | (self.mode as u8 & 0b111);
        buf[0] = header;
        buf[1] = self.stratum;
        buf[2] = self.poll as u8;
        buf[3] = self.precision as u8;
        buf[4..8].copy_from_slice(&self.root_delay.to_be_bytes());
        buf[8..12].copy_from_slice(&self.root_dispersion.to_be_bytes());
        buf[12..16].copy_from_slice(&self.reference_id);
        buf[16..24].copy_from_slice(&self.reference_ts.to_u64().to_be_bytes());
        buf[24..32].copy_from_slice(&self.originate_ts.to_u64().to_be_bytes());
        buf[32..40].copy_from_slice(&self.receive_ts.to_u64().to_be_bytes());
        buf[40..48].copy_from_slice(&self.transmit_ts.to_u64().to_be_bytes());
        buf
    }
}

fn read_u32(buf: &[u8], off: usize) -> Result<u32, SntpError> {
    let arr: [u8; 4] = buf
        .get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .ok_or(SntpError::InvalidHeader("u32 read out of range"))?;
    Ok(u32::from_be_bytes(arr))
}

fn read_u64(buf: &[u8], off: usize) -> Result<u64, SntpError> {
    let arr: [u8; 8] = buf
        .get(off..off + 8)
        .and_then(|s| s.try_into().ok())
        .ok_or(SntpError::InvalidHeader("u64 read out of range"))?;
    Ok(u64::from_be_bytes(arr))
}

fn read_array4(buf: &[u8], off: usize) -> Result<[u8; 4], SntpError> {
    buf.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .ok_or(SntpError::InvalidHeader("4-byte field out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_packet() -> SntpPacket {
        SntpPacket {
            leap: LeapIndicator::NoWarning,
            version: 4,
            mode: Mode::Server,
            stratum: 1,
            poll: 6,
            precision: -20,
            root_delay: 0x0001_0000,
            root_dispersion: 0x0002_0000,
            reference_id: *b"GPS\0",
            reference_ts: NtpTimestamp {
                seconds: 0xAAAA_AAAA,
                fraction: 0x1111_1111,
            },
            originate_ts: NtpTimestamp {
                seconds: 0xBBBB_BBBB,
                fraction: 0x2222_2222,
            },
            receive_ts: NtpTimestamp {
                seconds: 0xCCCC_CCCC,
                fraction: 0x3333_3333,
            },
            transmit_ts: NtpTimestamp {
                seconds: 0xDDDD_DDDD,
                fraction: 0x4444_4444,
            },
        }
    }

    #[test]
    fn round_trip() {
        let pkt = sample_packet();
        let buf = pkt.encode();
        assert_eq!(buf.len(), SNTP_PACKET_LEN);
        let decoded = SntpPacket::decode(&buf).expect("decode round-trip");
        assert_eq!(pkt, decoded);
    }

    #[test]
    fn header_bits_layout() {
        // LI=0b11, VN=0b100, Mode=0b011 gives 0b11_100_011 = 0xE3.
        let pkt = SntpPacket {
            leap: LeapIndicator::AlarmUnsynchronized,
            version: 4,
            mode: Mode::Client,
            ..sample_packet()
        };
        let buf = pkt.encode();
        assert_eq!(buf[0], 0b11_100_011);
    }

    #[test]
    fn reject_short_packet() {
        let buf = [0u8; 47];
        let err = SntpPacket::decode(&buf).expect_err("must reject");
        match err {
            SntpError::InvalidLength { got, expected } => {
                assert_eq!(got, 47);
                assert_eq!(expected, 48);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn reject_invalid_version() {
        let mut buf = [0u8; SNTP_PACKET_LEN];
        // Version 2 is deprecated and must be rejected.
        buf[0] = 0b00_010_011;
        let err = SntpPacket::decode(&buf).expect_err("must reject v2");
        assert!(matches!(err, SntpError::InvalidHeader(_)));
    }

    #[test]
    fn client_request_defaults() {
        let req = SntpPacket::client_request();
        assert_eq!(req.mode, Mode::Client);
        assert_eq!(req.version, 4);
        assert_eq!(req.stratum, 0);
        assert_eq!(req.transmit_ts, NtpTimestamp::ZERO);
    }

    #[test]
    fn mode_round_trip_all_values() {
        for raw in 0u8..8 {
            let mode = Mode::from_bits(raw);
            let mut pkt = sample_packet();
            pkt.mode = mode;
            let buf = pkt.encode();
            let decoded = SntpPacket::decode(&buf).expect("decode");
            assert_eq!(decoded.mode, mode);
        }
    }
}
