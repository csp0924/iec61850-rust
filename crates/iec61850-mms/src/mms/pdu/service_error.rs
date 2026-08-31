//! The MMS ServiceError type and its errorClass CHOICE, per ISO 9506-2.
//!
//! `ServiceError` is also the payload of a ConfirmedError PDU.
//!
//! Wire format when carried in an InitiateError PDU, whose outer `0xaa` is written
//! by `MmsPdu`:
//! ```text
//! 0xa0 0x03          -- errorClass [0] EXPLICIT CHOICE
//!   0x88 0x01 <code> -- initiate [8] IMPLICIT INTEGER, the subcode
//! ```
//!
//! `errorClass` carries an EXPLICIT tag, adding one wrapper; every other field is
//! IMPLICIT.

use super::super::error::MmsError;
use crate::compat::prelude::*;
use bytes::BytesMut;

// The errorClass CHOICE, thirteen alternatives

/// The errorClass CHOICE of a ServiceError.
///
/// The `u8` in each variant is the subcode INTEGER, and the BER context tag is the
/// index of the alternative, `[0]` through `[12]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorClass {
    /// `[0]` vmd-state (sub-code 0=vmd-state-conflict, 1=vmd-operational-problem, ...)
    VmdState(u8),
    /// `[1]` application-reference
    ApplicationReference(u8),
    /// `[2]` definition
    Definition(u8),
    /// `[3]` resource
    Resource(u8),
    /// `[4]` service
    Service(u8),
    /// `[5]` service-preempt
    ServicePreempt(u8),
    /// `[6]` time-resolution
    TimeResolution(u8),
    /// `[7]` access
    Access(u8),
    /// `[8]` initiate. Subcodes: 0 other, 1 version-incompatible,
    ///             3=max-calling-outstanding, 4=max-called-outstanding,
    ///             5 service-error, 6 continuing, 7 user-error.
    Initiate(u8),
    /// `[9]` conclude
    Conclude(u8),
    /// `[10]` cancel
    Cancel(u8),
    /// `[11]` file
    File(u8),
    /// `[12]` others
    Others(u8),
}

impl ErrorClass {
    /// Returns the context tag of the alternative, 0 through 12.
    pub fn context_tag(&self) -> u8 {
        match self {
            ErrorClass::VmdState(_) => 0,
            ErrorClass::ApplicationReference(_) => 1,
            ErrorClass::Definition(_) => 2,
            ErrorClass::Resource(_) => 3,
            ErrorClass::Service(_) => 4,
            ErrorClass::ServicePreempt(_) => 5,
            ErrorClass::TimeResolution(_) => 6,
            ErrorClass::Access(_) => 7,
            ErrorClass::Initiate(_) => 8,
            ErrorClass::Conclude(_) => 9,
            ErrorClass::Cancel(_) => 10,
            ErrorClass::File(_) => 11,
            ErrorClass::Others(_) => 12,
        }
    }

    /// Returns the subcode.
    pub fn code(&self) -> u8 {
        match self {
            ErrorClass::VmdState(c)
            | ErrorClass::ApplicationReference(c)
            | ErrorClass::Definition(c)
            | ErrorClass::Resource(c)
            | ErrorClass::Service(c)
            | ErrorClass::ServicePreempt(c)
            | ErrorClass::TimeResolution(c)
            | ErrorClass::Access(c)
            | ErrorClass::Initiate(c)
            | ErrorClass::Conclude(c)
            | ErrorClass::Cancel(c)
            | ErrorClass::File(c)
            | ErrorClass::Others(c) => *c,
        }
    }

    /// Encodes the errorClass CHOICE, including its EXPLICIT `[0]` wrapper.
    ///
    /// The output is `0xa0 0x03 0x8<n> 0x01 <code>`, where `0x8<n>` is
    /// `0x80 | context_tag()`, an IMPLICIT primitive tag.
    pub fn encode_explicit(&self, buf: &mut BytesMut) {
        // the inner TLV, an IMPLICIT primitive context tag
        let inner_tag = 0x80 | self.context_tag();
        let inner_code = self.code();

        // errorClass [0] EXPLICIT, whose content is 3 bytes: tag, length and value
        buf.extend_from_slice(&[
            0xa0,       // EXPLICIT [0] constructed
            0x03,       // outer length = 3
            inner_tag,  // inner IMPLICIT tag
            0x01,       // inner length = 1
            inner_code, // sub-code
        ]);
    }

    /// Decodes the errorClass CHOICE, starting at its EXPLICIT `[0]` wrapper.
    ///
    /// `data` starts at the `0xa0` byte; the number of bytes consumed is returned.
    pub fn decode_explicit(data: &[u8]) -> Result<(Self, usize), MmsError> {
        // at least 5 bytes are needed: 0xa0 len 0x8n 0x01 code
        if data.len() < 5 {
            return Err(MmsError::TruncatedPdu);
        }

        // the outer tag
        if data[0] != 0xa0 {
            return Err(MmsError::InvalidTag {
                expected: 0xa0,
                actual: data[0],
            });
        }

        let outer_len = data[1] as usize;
        if outer_len < 3 || data.len() < 2 + outer_len {
            return Err(MmsError::InvalidLength);
        }

        // the inner tag is context-specific and primitive, with the choice index in
        // its low five bits
        let inner_tag = data[2];
        if inner_tag & 0xe0 != 0x80 {
            return Err(MmsError::InvalidTag {
                expected: 0x80,
                actual: inner_tag,
            });
        }

        let choice_idx = inner_tag & 0x1f;
        if data[3] != 0x01 {
            return Err(MmsError::InvalidLength);
        }
        let code = data[4];

        let ec = match choice_idx {
            0 => ErrorClass::VmdState(code),
            1 => ErrorClass::ApplicationReference(code),
            2 => ErrorClass::Definition(code),
            3 => ErrorClass::Resource(code),
            4 => ErrorClass::Service(code),
            5 => ErrorClass::ServicePreempt(code),
            6 => ErrorClass::TimeResolution(code),
            7 => ErrorClass::Access(code),
            8 => ErrorClass::Initiate(code),
            9 => ErrorClass::Conclude(code),
            10 => ErrorClass::Cancel(code),
            11 => ErrorClass::File(code),
            12 => ErrorClass::Others(code),
            _ => {
                tracing::warn!(
                    "unknown serviceerror errorclass choice index {}",
                    choice_idx
                );
                return Err(MmsError::UnknownMmsPduTag(inner_tag));
            }
        };

        Ok((ec, 2 + outer_len))
    }
}

// ServiceError

/// An MMS ServiceError, carried by an InitiateError and by a ConfirmedError PDU.
///
/// Wire format, whose outer `0xaa` is written by `MmsPdu`:
/// ```text
/// 0xa0 0x03      -- errorClass [0] EXPLICIT CHOICE
///   0x8n 0x01 c  -- inner choice tag + sub-code
/// (0x81 ... )    -- additionalCode [1] IMPLICIT INTEGER, OPTIONAL
/// (0x82 ... )    -- additionalDescription [2] IMPLICIT VisibleString, OPTIONAL
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError {
    /// errorClass `[0]` EXPLICIT, the one mandatory field.
    pub error_class: ErrorClass,
    /// additionalCode `[1]` IMPLICIT INTEGER, OPTIONAL.
    pub additional_code: Option<i32>,
    /// additionalDescription `[2]` IMPLICIT VisibleString, OPTIONAL.
    pub additional_description: Option<String>,
}

impl ServiceError {
    /// Builds a `ServiceError` carrying only an errorClass.
    pub fn new(error_class: ErrorClass) -> Self {
        Self {
            error_class,
            additional_code: None,
            additional_description: None,
        }
    }

    /// Encodes the content of a ServiceError, without the outer MmsPdu tag.
    ///
    /// `MmsPdu::encode` wraps the result in `0xaa <len>`.
    pub fn encode_inner(&self, buf: &mut BytesMut) {
        self.error_class.encode_explicit(buf);

        if let Some(code) = self.additional_code {
            // [1] IMPLICIT INTEGER
            let code_bytes = encode_int32_minimal(code);
            buf.extend_from_slice(&[0x81, code_bytes.len() as u8]);
            buf.extend_from_slice(&code_bytes);
        }

        if let Some(ref desc) = self.additional_description {
            // additionalDescription [2] IMPLICIT VisibleString
            let bytes = desc.as_bytes();
            buf.extend_from_slice(&[0x82, bytes.len() as u8]);
            buf.extend_from_slice(bytes);
        }
    }

    /// Decodes ServiceError content; `data` is what follows the outer `0xaa` length.
    pub fn decode_inner(data: &[u8]) -> Result<Self, MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }

        let mut pos = 0usize;

        // errorClass [0] EXPLICIT is mandatory
        let (error_class, consumed) = ErrorClass::decode_explicit(&data[pos..])?;
        pos += consumed;

        let mut additional_code: Option<i32> = None;
        let mut additional_description: Option<String> = None;

        // optional fields
        while pos < data.len() {
            let tag = data[pos];
            pos += 1;
            if pos >= data.len() {
                return Err(MmsError::TruncatedPdu);
            }
            let len = data[pos] as usize;
            pos += 1;
            if pos + len > data.len() {
                return Err(MmsError::TruncatedPdu);
            }
            let val_bytes = &data[pos..pos + len];
            pos += len;

            match tag {
                0x81 => {
                    // additionalCode [1] IMPLICIT INTEGER
                    additional_code = Some(decode_int32(val_bytes)?);
                }
                0x82 => {
                    // additionalDescription [2] IMPLICIT VisibleString
                    let s = core::str::from_utf8(val_bytes)
                        .map_err(|_| MmsError::InvalidUtf8)?
                        .to_string();
                    additional_description = Some(s);
                }
                _ => {
                    // an unknown optional field is logged and skipped
                    tracing::debug!("skipping unknown serviceerror tag 0x{:02X}", tag);
                }
            }
        }

        Ok(Self {
            error_class,
            additional_code,
            additional_description,
        })
    }
}

// ConfirmedError PDU encoder

/// Builds a complete ConfirmedError PDU, outer `0xa2 <len>` included.
///
/// Wire format:
///
/// ```text
/// 0xa2 <len>            -- confirmedErrorPdu [2] IMPLICIT SEQUENCE
///   0x80 <len> <id>     -- invokeID [0] IMPLICIT Unsigned32, minimal-length big-endian
///   0xa2 <len>          -- serviceError [2] IMPLICIT ServiceError
///     0xa0 0x03         -- errorClass [0] EXPLICIT (CHOICE wrapper)
///       0x8X 0x01 <c>   -- access [7] / vmd-state [0] / ... IMPLICIT INTEGER
///     (0x81 ... )       -- additionalCode [1] IMPLICIT INTEGER, OPTIONAL
///     (0x82 ... )       -- additionalDescription [2] IMPLICIT VisibleString, OPTIONAL
/// ```
///
/// This is the reference encoding for the server-side `service::make_confirmed_error`.
pub fn encode_confirmed_error_pdu(
    invoke_id: u32,
    service_error: &ServiceError,
    buf: &mut BytesMut,
) {
    use super::common::encode_unsigned_int_minimal;
    use super::initiate::encode_length;

    let mut inner = BytesMut::new();

    // invokeID [0] IMPLICIT Unsigned32 -> tag 0x80
    let id_bytes = encode_unsigned_int_minimal(invoke_id as u64);
    inner.extend_from_slice(&[0x80]);
    encode_length(id_bytes.len(), &mut inner);
    inner.extend_from_slice(&id_bytes);

    // serviceError [2] IMPLICIT ServiceError, tag 0xa2 and constructed
    let mut se_body = BytesMut::new();
    service_error.encode_inner(&mut se_body);
    inner.extend_from_slice(&[0xa2]);
    encode_length(se_body.len(), &mut inner);
    inner.extend_from_slice(&se_body);

    // the outer confirmedErrorPdu [2] IMPLICIT SEQUENCE, tag 0xa2
    buf.extend_from_slice(&[0xa2]);
    encode_length(inner.len(), buf);
    buf.extend_from_slice(&inner);
}

// Helpers

/// Encodes an `i32` as a minimal-length signed big-endian BER INTEGER.
fn encode_int32_minimal(val: i32) -> Vec<u8> {
    if val == 0 {
        return vec![0x00];
    }
    let raw = val.to_be_bytes();
    // find the first byte that is neither a redundant 0x00 nor a redundant 0xff
    let mut start = 0usize;
    while start < 3 {
        let b = raw[start];
        let next = raw[start + 1];
        // a positive value drops leading 0x00 bytes while its top bit stays 0;
        // a negative value drops leading 0xff bytes while its top bit stays 1
        let redundant = if val > 0 {
            b == 0x00 && (next & 0x80) == 0
        } else {
            b == 0xff && (next & 0x80) != 0
        };
        if redundant {
            start += 1;
        } else {
            break;
        }
    }
    raw[start..].to_vec()
}

/// Decodes a signed big-endian BER INTEGER into an `i32`.
fn decode_int32(data: &[u8]) -> Result<i32, MmsError> {
    if data.is_empty() || data.len() > 4 {
        return Err(MmsError::InvalidLength);
    }
    let sign_extend: i32 = if data[0] & 0x80 != 0 { -1 } else { 0 };
    let mut val = sign_extend;
    for &b in data {
        val = (val << 8) | (b as i32);
    }
    Ok(val)
}

// Unit tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_class_initiate_encode_explicit() {
        // an InitiateError encodes errorClass.initiate(0) as 0xa0 0x03 0x88 0x01 0x00
        let ec = ErrorClass::Initiate(0);
        let mut buf = BytesMut::new();
        ec.encode_explicit(&mut buf);
        assert_eq!(&buf[..], &[0xa0, 0x03, 0x88, 0x01, 0x00]);
    }

    #[test]
    fn error_class_decode_roundtrip() {
        let ec = ErrorClass::Initiate(1);
        let mut buf = BytesMut::new();
        ec.encode_explicit(&mut buf);
        let (decoded, consumed) = ErrorClass::decode_explicit(&buf).unwrap();
        assert_eq!(decoded, ec);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn error_class_others() {
        let ec = ErrorClass::Others(3);
        let mut buf = BytesMut::new();
        ec.encode_explicit(&mut buf);
        // context_tag = 12 -> inner_tag = 0x80 | 12 = 0x8c
        assert_eq!(buf[2], 0x8c);
        assert_eq!(buf[4], 3);
    }

    #[test]
    fn service_error_encode_decode_minimal() {
        let se = ServiceError::new(ErrorClass::Initiate(0));
        let mut buf = BytesMut::new();
        se.encode_inner(&mut buf);
        let decoded = ServiceError::decode_inner(&buf).unwrap();
        assert_eq!(decoded.error_class, se.error_class);
        assert_eq!(decoded.additional_code, None);
        assert_eq!(decoded.additional_description, None);
    }

    #[test]
    fn service_error_with_optional_fields() {
        let se = ServiceError {
            error_class: ErrorClass::Access(2),
            additional_code: Some(42),
            additional_description: Some("test error".to_string()),
        };
        let mut buf = BytesMut::new();
        se.encode_inner(&mut buf);
        let decoded = ServiceError::decode_inner(&buf).unwrap();
        assert_eq!(decoded, se);
    }

    #[test]
    fn decode_truncated_returns_err() {
        // fewer than 5 bytes
        let result = ErrorClass::decode_explicit(&[0xa0, 0x03, 0x88]);
        assert!(result.is_err());
    }
}
