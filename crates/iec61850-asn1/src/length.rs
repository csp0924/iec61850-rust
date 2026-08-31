//! BER definite-length encoding and decoding per ISO/IEC 8825-1 §8.1.3.
//!
//! Encoding uses the short form below 128, the long form `0x81 <byte>` below
//! 256, and the long form `0x82 <2 bytes big-endian>` below 65536. A longer
//! value is a caller error and trips a `debug_assert`, because every layer
//! segments its PDUs below 65535 bytes.
//!
//! Decoding accepts the short form, `0x81` and `0x82` only. The indefinite
//! form `0x80` is rejected, as is a long form of
//! three or more length bytes.

use bytes::BytesMut;

use crate::error::Asn1Error;

/// Encodes a BER definite-form length field into `buf`.
///
/// Uses the short form below 128 and a long form of at most two length bytes
/// above it.
///
/// # Panics
///
/// Debug builds assert that `len <= 0xFFFF`. Release builds emit `0x82`
/// followed by the low 16 bits; callers must not rely on that, since PDUs
/// are segmented by COTP/TPKT before reaching this function.
pub fn encode_length(len: usize, buf: &mut BytesMut) {
    debug_assert!(
        len <= 0xFFFF,
        "BER length {} exceeds 65535; the PDU must be segmented by COTP/TPKT",
        len
    );
    if len < 128 {
        buf.extend_from_slice(&[len as u8]);
    } else if len <= 0xFF {
        buf.extend_from_slice(&[0x81, len as u8]);
    } else {
        buf.extend_from_slice(&[0x82, (len >> 8) as u8, (len & 0xFF) as u8]);
    }
}

/// Decodes a BER definite-form length field.
///
/// Returns the length value and the number of header bytes consumed.
///
/// # Errors
///
/// - [`Asn1Error::TruncatedInput`] when the slice ends inside the field.
/// - [`Asn1Error::LengthTooLong`] for the indefinite form `0x80` and for a
///   long form of three or more length bytes.
pub fn decode_length(data: &[u8]) -> Result<(usize, usize), Asn1Error> {
    if data.is_empty() {
        return Err(Asn1Error::TruncatedInput);
    }
    let b0 = data[0];
    if b0 < 0x80 {
        Ok((b0 as usize, 1))
    } else if b0 == 0x81 {
        if data.len() < 2 {
            return Err(Asn1Error::TruncatedInput);
        }
        Ok((data[1] as usize, 2))
    } else if b0 == 0x82 {
        if data.len() < 3 {
            return Err(Asn1Error::TruncatedInput);
        }
        let len = ((data[1] as usize) << 8) | (data[2] as usize);
        Ok((len, 3))
    } else {
        tracing::warn!(
            "rejecting BER length field, not definite form or longer than two bytes (first byte 0x{:02X})",
            b0
        );
        Err(Asn1Error::LengthTooLong { first_byte: b0 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_short_form() {
        let mut buf = BytesMut::new();
        encode_length(0, &mut buf);
        assert_eq!(&buf[..], &[0x00]);

        let mut buf = BytesMut::new();
        encode_length(127, &mut buf);
        assert_eq!(&buf[..], &[0x7F]);
    }

    #[test]
    fn encode_long_form_1_byte() {
        let mut buf = BytesMut::new();
        encode_length(128, &mut buf);
        assert_eq!(&buf[..], &[0x81, 0x80]);

        let mut buf = BytesMut::new();
        encode_length(255, &mut buf);
        assert_eq!(&buf[..], &[0x81, 0xFF]);
    }

    #[test]
    fn encode_long_form_2_bytes() {
        let mut buf = BytesMut::new();
        encode_length(256, &mut buf);
        assert_eq!(&buf[..], &[0x82, 0x01, 0x00]);

        let mut buf = BytesMut::new();
        encode_length(65535, &mut buf);
        assert_eq!(&buf[..], &[0x82, 0xFF, 0xFF]);
    }

    #[test]
    fn decode_short_form() {
        assert_eq!(decode_length(&[0x00]).unwrap(), (0, 1));
        assert_eq!(decode_length(&[0x7F]).unwrap(), (127, 1));
    }

    #[test]
    fn decode_long_form_1_byte() {
        assert_eq!(decode_length(&[0x81, 0x80]).unwrap(), (128, 2));
        assert_eq!(decode_length(&[0x81, 0xFF]).unwrap(), (255, 2));
    }

    #[test]
    fn decode_long_form_2_bytes() {
        assert_eq!(decode_length(&[0x82, 0x01, 0x00]).unwrap(), (256, 3));
        assert_eq!(decode_length(&[0x82, 0xFF, 0xFF]).unwrap(), (65535, 3));
    }

    #[test]
    fn decode_empty_input() {
        assert_eq!(decode_length(&[]), Err(Asn1Error::TruncatedInput));
    }

    #[test]
    fn decode_truncated_long_form() {
        assert_eq!(decode_length(&[0x81]), Err(Asn1Error::TruncatedInput));
        assert_eq!(decode_length(&[0x82, 0x01]), Err(Asn1Error::TruncatedInput));
    }

    /// The indefinite form `0x80` must return an
    /// error instead of looping in search of an end-of-contents marker.
    #[test]
    fn decode_indefinite_length_rejected() {
        assert_eq!(
            decode_length(&[0x80]),
            Err(Asn1Error::LengthTooLong { first_byte: 0x80 })
        );
    }

    /// A long form of three or more length bytes must be rejected.
    #[test]
    fn decode_long_form_3_bytes_rejected() {
        assert_eq!(
            decode_length(&[0x83, 0x00, 0x00, 0x01]),
            Err(Asn1Error::LengthTooLong { first_byte: 0x83 })
        );
        assert_eq!(
            decode_length(&[0xFF, 0x00]),
            Err(Asn1Error::LengthTooLong { first_byte: 0xFF })
        );
    }

    #[test]
    fn roundtrip_boundary_values() {
        for &len in &[0usize, 1, 127, 128, 255, 256, 1024, 65535] {
            let mut buf = BytesMut::new();
            encode_length(len, &mut buf);
            let (decoded, consumed) = decode_length(&buf).unwrap();
            assert_eq!(decoded, len, "len={}", len);
            assert_eq!(consumed, buf.len(), "len={}", len);
        }
    }
}
