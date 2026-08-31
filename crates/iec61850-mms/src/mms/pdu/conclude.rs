//! Conclude request and response PDUs.
//!
//! Both carry an empty body:
//! - ConcludeRequest is `0x8b 0x00`, MmsPdu `[11]` primitive NULL
//! - ConcludeResponse is `0x8c 0x00`, MmsPdu `[12]` primitive NULL
//!
//! Both tags are primitive rather than constructed, hence 0x8b and 0x8c rather than
//! 0xab and 0xac.

use bytes::BytesMut;

use super::super::error::MmsError;

// Constants

/// The fixed two-byte encoding of a ConcludeRequest.
pub const CONCLUDE_REQUEST_BYTES: [u8; 2] = [0x8b, 0x00];

/// The fixed two-byte encoding of a ConcludeResponse.
pub const CONCLUDE_RESPONSE_BYTES: [u8; 2] = [0x8c, 0x00];

// Types

/// An MMS Conclude-RequestPDU, `[11]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConcludeRequestPdu;

/// An MMS Conclude-ResponsePDU, `[12]`, with a NULL body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConcludeResponsePdu;

impl ConcludeRequestPdu {
    /// Encodes the fixed two bytes `0x8b 0x00`.
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&CONCLUDE_REQUEST_BYTES);
    }

    /// Decodes a request; `data` starts at the `0x8b` tag byte.
    ///
    /// The tag must be 0x8b and the length 0. A non-zero length returns
    /// `MmsError::InvalidPdu`, and fewer than two bytes returns `MmsError::TruncatedPdu`.
    ///
    /// The length is checked strictly because the body is a NULL.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        if data.len() < 2 {
            return Err(MmsError::TruncatedPdu);
        }
        let tag = data[0];
        if tag != 0x8b {
            return Err(MmsError::InvalidTag {
                expected: 0x8b,
                actual: tag,
            });
        }
        let length = data[1] as usize;
        if length != 0 {
            tracing::warn!(
                "conclude request body length {} is not zero, rejecting",
                length
            );
            return Err(MmsError::InvalidPdu);
        }
        // a declared length beyond the buffer is rejected as well
        if 2 + length > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        Ok(ConcludeRequestPdu)
    }
}

impl ConcludeResponsePdu {
    /// Encodes the fixed two bytes `0x8c 0x00`.
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&CONCLUDE_RESPONSE_BYTES);
    }

    /// Decodes a response; `data` starts at the `0x8c` tag byte.
    ///
    /// The tag must be 0x8c and the length 0. A non-zero length returns
    /// `MmsError::InvalidPdu`, and fewer than two bytes returns `MmsError::TruncatedPdu`.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        if data.len() < 2 {
            return Err(MmsError::TruncatedPdu);
        }
        let tag = data[0];
        if tag != 0x8c {
            return Err(MmsError::InvalidTag {
                expected: 0x8c,
                actual: tag,
            });
        }
        let length = data[1] as usize;
        if length != 0 {
            tracing::warn!(
                "conclude response body length {} is not zero, rejecting",
                length
            );
            return Err(MmsError::InvalidPdu);
        }
        if 2 + length > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        Ok(ConcludeResponsePdu)
    }
}

// Unit tests

#[cfg(test)]
mod tests {
    use super::*;

    // byte-exact encoding

    #[test]
    fn conclude_request_encode_exact() {
        let mut buf = BytesMut::new();
        ConcludeRequestPdu.encode(&mut buf);
        assert_eq!(&buf[..], &[0x8b, 0x00]);
    }

    #[test]
    fn conclude_response_encode_exact() {
        let mut buf = BytesMut::new();
        ConcludeResponsePdu.encode(&mut buf);
        assert_eq!(&buf[..], &[0x8c, 0x00]);
    }

    #[test]
    fn conclude_request_constant_matches() {
        assert_eq!(CONCLUDE_REQUEST_BYTES, [0x8b, 0x00]);
    }

    #[test]
    fn conclude_response_constant_matches() {
        assert_eq!(CONCLUDE_RESPONSE_BYTES, [0x8c, 0x00]);
    }

    // decode of a well-formed pdu

    #[test]
    fn conclude_request_decode_valid() {
        let pdu = ConcludeRequestPdu::decode(&[0x8b, 0x00]).unwrap();
        assert_eq!(pdu, ConcludeRequestPdu);
    }

    #[test]
    fn conclude_response_decode_valid() {
        let pdu = ConcludeResponsePdu::decode(&[0x8c, 0x00]).unwrap();
        assert_eq!(pdu, ConcludeResponsePdu);
    }

    // encode and decode round trips

    #[test]
    fn conclude_request_roundtrip() {
        let mut buf = BytesMut::new();
        ConcludeRequestPdu.encode(&mut buf);
        let got = ConcludeRequestPdu::decode(&buf).unwrap();
        assert_eq!(got, ConcludeRequestPdu);
    }

    #[test]
    fn conclude_response_roundtrip() {
        let mut buf = BytesMut::new();
        ConcludeResponsePdu.encode(&mut buf);
        let got = ConcludeResponsePdu::decode(&buf).unwrap();
        assert_eq!(got, ConcludeResponsePdu);
    }

    // a non-empty body is rejected

    #[test]
    fn conclude_request_nonzero_body_rejected() {
        // 0x8b 0x01 0xff declares a one-byte body and must yield InvalidPdu
        let result = ConcludeRequestPdu::decode(&[0x8b, 0x01, 0xff]);
        assert!(
            matches!(result, Err(MmsError::InvalidPdu)),
            "a non-empty body must return InvalidPdu, got: {:?}",
            result
        );
    }

    #[test]
    fn conclude_response_nonzero_body_rejected() {
        let result = ConcludeResponsePdu::decode(&[0x8c, 0x01, 0x00]);
        assert!(
            matches!(result, Err(MmsError::InvalidPdu)),
            "a non-empty body must return InvalidPdu, got: {:?}",
            result
        );
    }

    #[test]
    fn conclude_request_large_nonzero_length_rejected() {
        // a declared length of 5 must be rejected rather than skipping trailing bytes
        let result = ConcludeRequestPdu::decode(&[0x8b, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert!(matches!(result, Err(MmsError::InvalidPdu)));
    }

    // truncated input is rejected

    #[test]
    fn conclude_request_truncated_no_length_byte() {
        // only a tag byte and no length byte must yield TruncatedPdu
        let result = ConcludeRequestPdu::decode(&[0x8b]);
        assert!(
            matches!(result, Err(MmsError::TruncatedPdu)),
            "a truncated pdu must return TruncatedPdu, got: {:?}",
            result
        );
    }

    #[test]
    fn conclude_response_truncated_empty_input() {
        let result = ConcludeResponsePdu::decode(&[]);
        assert!(matches!(result, Err(MmsError::TruncatedPdu)));
    }

    // a wrong tag is rejected

    #[test]
    fn conclude_request_wrong_tag_rejected() {
        // the ConcludeResponse tag 0x8c given to the request decoder yields InvalidTag
        let result = ConcludeRequestPdu::decode(&[0x8c, 0x00]);
        assert!(
            matches!(
                result,
                Err(MmsError::InvalidTag {
                    expected: 0x8b,
                    actual: 0x8c
                })
            ),
            "a wrong tag must return InvalidTag, got: {:?}",
            result
        );
    }

    #[test]
    fn conclude_response_wrong_tag_rejected() {
        let result = ConcludeResponsePdu::decode(&[0x8b, 0x00]);
        assert!(
            matches!(
                result,
                Err(MmsError::InvalidTag {
                    expected: 0x8c,
                    actual: 0x8b
                })
            ),
            "a wrong tag must return InvalidTag, got: {:?}",
            result
        );
    }

    // trailing bytes are ignored, since only the first two are read

    #[test]
    fn conclude_request_extra_trailing_bytes_ok() {
        // 0x8b 0x00 0xde 0xad: only the tag and length are inspected
        let pdu = ConcludeRequestPdu::decode(&[0x8b, 0x00, 0xde, 0xad]).unwrap();
        assert_eq!(pdu, ConcludeRequestPdu);
    }
}
