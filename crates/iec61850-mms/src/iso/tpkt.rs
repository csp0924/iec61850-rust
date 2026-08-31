//! TPKT header encoding and decoding, per RFC 1006.
//!
//! TPKT is the thin framing that carries an ISO 8073 COTP PDU over TCP. The header
//! is a fixed 4 bytes: a version of 0x03, a reserved 0x00, and a big-endian u16
//! total length that includes the header itself, so its smallest legal value is 4.
//!
//! # Robustness
//!
//! A `packet_len` of 4 or less leaves no COTP payload, and a decoder that reads the
//! length indicator anyway reads past the buffer. [`TpktHeader::decode`] therefore
//! requires `packet_len > 4` and returns [`CotpError::TpktLengthTooSmall`] otherwise.

use crate::error::CotpError;

/// The fixed version byte of a TPKT header.
pub const TPKT_VERSION: u8 = 0x03;

/// The fixed reserved byte of a TPKT header.
pub const TPKT_RESERVED: u8 = 0x00;

/// Size of a TPKT header in bytes.
pub const TPKT_HEADER_LEN: usize = 4;

/// A decoded TPKT header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpktHeader {
    /// Total length of the TPKT packet in bytes, header included.
    pub packet_len: u16,
}

impl TpktHeader {
    /// Decodes a TPKT header from four bytes.
    ///
    /// Checks that:
    /// - version == 0x03
    /// - reserved == 0x00
    /// - `packet_len` is greater than 4, so a COTP payload is present
    ///
    /// # Errors
    ///
    /// - [`CotpError::InvalidTpktVersion`] when the version or reserved byte is wrong.
    /// - [`CotpError::TpktLengthTooSmall`] when `packet_len` is 4 or less.
    pub fn decode(buf: &[u8; 4]) -> Result<Self, CotpError> {
        if buf[0] != TPKT_VERSION || buf[1] != TPKT_RESERVED {
            return Err(CotpError::InvalidTpktVersion {
                version: buf[0],
                reserved: buf[1],
            });
        }
        let packet_len = u16::from_be_bytes([buf[2], buf[3]]);
        // A packet_len of 4 or less carries no cotp payload
        if packet_len <= 4 {
            return Err(CotpError::TpktLengthTooSmall { packet_len });
        }
        Ok(Self { packet_len })
    }

    /// Serializes the header into four bytes.
    pub fn encode(&self) -> [u8; 4] {
        let [hi, lo] = self.packet_len.to_be_bytes();
        [TPKT_VERSION, TPKT_RESERVED, hi, lo]
    }

    /// Builds a header whose `total_len` covers the TPKT header plus the COTP data.
    ///
    /// # Panics
    ///
    /// Debug builds assert that `total_len` is at least 5, since at least one byte of
    /// COTP data must follow the header.
    pub fn new(total_len: usize) -> Self {
        debug_assert!(
            total_len >= 5,
            "tpkt total_len must be at least 5, header included"
        );
        Self {
            packet_len: total_len as u16,
        }
    }

    /// Returns the number of COTP payload bytes, that is `packet_len - 4`.
    pub fn cotp_len(&self) -> usize {
        (self.packet_len as usize).saturating_sub(TPKT_HEADER_LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        let hdr = TpktHeader { packet_len: 100 };
        let bytes = hdr.encode();
        let decoded = TpktHeader::decode(&bytes).unwrap();
        assert_eq!(hdr, decoded);
    }

    #[test]
    fn decode_happy_path_min() {
        // the smallest legal packet_len is 5: a 4-byte header plus 1 byte of COTP
        let buf = [0x03, 0x00, 0x00, 0x05];
        let hdr = TpktHeader::decode(&buf).unwrap();
        assert_eq!(hdr.packet_len, 5);
        assert_eq!(hdr.cotp_len(), 1);
    }

    #[test]
    fn decode_happy_path_typical() {
        // a typical MMS packet of 7 bytes: 4 of TPKT and 3 of a COTP CR
        let buf = [0x03, 0x00, 0x00, 0x07];
        let hdr = TpktHeader::decode(&buf).unwrap();
        assert_eq!(hdr.packet_len, 7);
        assert_eq!(hdr.cotp_len(), 3);
    }

    /// A packet_len of 4 leaves no COTP payload and must be rejected.
    #[test]
    fn packet_len_4_rejected() {
        let buf = [0x03, 0x00, 0x00, 0x04];
        let err = TpktHeader::decode(&buf).unwrap_err();
        assert!(
            matches!(err, CotpError::TpktLengthTooSmall { packet_len: 4 }),
            "expected TpktLengthTooSmall(4), got {err:?}"
        );
    }

    /// A packet_len of 0 must be rejected.
    #[test]
    fn packet_len_0_rejected() {
        let buf = [0x03, 0x00, 0x00, 0x00];
        let err = TpktHeader::decode(&buf).unwrap_err();
        assert!(
            matches!(err, CotpError::TpktLengthTooSmall { packet_len: 0 }),
            "expected TpktLengthTooSmall(0), got {err:?}"
        );
    }

    /// A packet_len of 3, shorter than the header itself, must be rejected.
    #[test]
    fn packet_len_3_rejected() {
        let buf = [0x03, 0x00, 0x00, 0x03];
        let err = TpktHeader::decode(&buf).unwrap_err();
        assert!(
            matches!(err, CotpError::TpktLengthTooSmall { packet_len: 3 }),
            "expected TpktLengthTooSmall(3), got {err:?}"
        );
    }

    #[test]
    fn decode_invalid_version() {
        let buf = [0x02, 0x00, 0x00, 0x07];
        let err = TpktHeader::decode(&buf).unwrap_err();
        assert!(
            matches!(
                err,
                CotpError::InvalidTpktVersion {
                    version: 2,
                    reserved: 0
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn decode_invalid_reserved() {
        let buf = [0x03, 0x01, 0x00, 0x07];
        let err = TpktHeader::decode(&buf).unwrap_err();
        assert!(
            matches!(
                err,
                CotpError::InvalidTpktVersion {
                    version: 3,
                    reserved: 1
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn decode_max_len() {
        // 0xFFFF is 65535, which is legal here though the negotiated size bounds it
        let buf = [0x03, 0x00, 0xFF, 0xFF];
        let hdr = TpktHeader::decode(&buf).unwrap();
        assert_eq!(hdr.packet_len, 65535);
        assert_eq!(hdr.cotp_len(), 65531);
    }
}
