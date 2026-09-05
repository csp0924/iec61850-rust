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

// Subcodes of the errorClass alternatives

/// Named subcodes of every `errorClass` alternative, one module per alternative.
///
/// The values are the INTEGER named numbers of the ISO 9506-2 `ServiceError`
/// ASN.1 definition. Every alternative except `others [12]`, which enumerates
/// nothing, defines `OTHER = 0`.
///
/// The subcode namespaces are disjoint: the same number means different things
/// under different alternatives, so a subcode is only meaningful together with
/// the alternative that carries it.
pub mod subcode {
    /// Subcodes of `vmd-state [0]`.
    pub mod vmd_state {
        /// other
        pub const OTHER: u8 = 0;
        /// vmd-state-conflict
        pub const VMD_STATE_CONFLICT: u8 = 1;
        /// vmd-operational-problem
        pub const VMD_OPERATIONAL_PROBLEM: u8 = 2;
        /// domain-transfer-problem
        pub const DOMAIN_TRANSFER_PROBLEM: u8 = 3;
        /// state-machine-id-invalid
        pub const STATE_MACHINE_ID_INVALID: u8 = 4;
    }

    /// Subcodes of `application-reference [1]`.
    pub mod application_reference {
        /// other
        pub const OTHER: u8 = 0;
        /// application-unreachable
        pub const APPLICATION_UNREACHABLE: u8 = 1;
        /// connection-lost
        pub const CONNECTION_LOST: u8 = 2;
        /// application-reference-invalid
        pub const APPLICATION_REFERENCE_INVALID: u8 = 3;
        /// context-unsupported
        pub const CONTEXT_UNSUPPORTED: u8 = 4;
    }

    /// Subcodes of `definition [2]`.
    pub mod definition {
        /// other
        pub const OTHER: u8 = 0;
        /// object-undefined
        pub const OBJECT_UNDEFINED: u8 = 1;
        /// invalid-address
        pub const INVALID_ADDRESS: u8 = 2;
        /// type-unsupported
        pub const TYPE_UNSUPPORTED: u8 = 3;
        /// type-inconsistent
        pub const TYPE_INCONSISTENT: u8 = 4;
        /// object-exists
        pub const OBJECT_EXISTS: u8 = 5;
        /// object-attribute-inconsistent
        pub const OBJECT_ATTRIBUTE_INCONSISTENT: u8 = 6;
    }

    /// Subcodes of `resource [3]`.
    pub mod resource {
        /// other
        pub const OTHER: u8 = 0;
        /// memory-unavailable
        pub const MEMORY_UNAVAILABLE: u8 = 1;
        /// processor-resource-unavailable
        pub const PROCESSOR_RESOURCE_UNAVAILABLE: u8 = 2;
        /// mass-storage-unavailable
        pub const MASS_STORAGE_UNAVAILABLE: u8 = 3;
        /// capability-unavailable
        pub const CAPABILITY_UNAVAILABLE: u8 = 4;
        /// capability-unknown
        pub const CAPABILITY_UNKNOWN: u8 = 5;
    }

    /// Subcodes of `service [4]`.
    pub mod service {
        /// other
        pub const OTHER: u8 = 0;
        /// primitives-out-of-sequence
        pub const PRIMITIVES_OUT_OF_SEQUENCE: u8 = 1;
        /// object-state-conflict
        pub const OBJECT_STATE_CONFLICT: u8 = 2;
        /// pdu-size
        pub const PDU_SIZE: u8 = 3;
        /// continuation-invalid
        pub const CONTINUATION_INVALID: u8 = 4;
        /// object-constraint-conflict
        pub const OBJECT_CONSTRAINT_CONFLICT: u8 = 5;
    }

    /// Subcodes of `service-preempt [5]`.
    pub mod service_preempt {
        /// other
        pub const OTHER: u8 = 0;
        /// timeout
        pub const TIMEOUT: u8 = 1;
        /// deadlock
        pub const DEADLOCK: u8 = 2;
        /// cancel
        pub const CANCEL: u8 = 3;
    }

    /// Subcodes of `time-resolution [6]`.
    pub mod time_resolution {
        /// other
        pub const OTHER: u8 = 0;
        /// unsupportable-time-resolution
        pub const UNSUPPORTABLE_TIME_RESOLUTION: u8 = 1;
    }

    /// Subcodes of `access [7]`.
    ///
    /// These are not the `DataAccessError` codes: `DataAccessError` is a
    /// separate INTEGER carried inside an `AccessResult`, with its own,
    /// unrelated numbering.
    pub mod access {
        /// other
        pub const OTHER: u8 = 0;
        /// object-access-unsupported
        pub const OBJECT_ACCESS_UNSUPPORTED: u8 = 1;
        /// object-non-existent
        pub const OBJECT_NON_EXISTENT: u8 = 2;
        /// object-access-denied
        pub const OBJECT_ACCESS_DENIED: u8 = 3;
        /// object-invalidated
        pub const OBJECT_INVALIDATED: u8 = 4;
    }

    /// Subcodes of `initiate [8]`.
    pub mod initiate {
        /// other
        pub const OTHER: u8 = 0;
        /// version-incompatible
        pub const VERSION_INCOMPATIBLE: u8 = 1;
        /// max-segment-insufficient
        pub const MAX_SEGMENT_INSUFFICIENT: u8 = 2;
        /// max-services-outstanding-calling-insufficient
        pub const MAX_SERVICES_OUTSTANDING_CALLING_INSUFFICIENT: u8 = 3;
        /// max-services-outstanding-called-insufficient
        pub const MAX_SERVICES_OUTSTANDING_CALLED_INSUFFICIENT: u8 = 4;
        /// service-CBB-insufficient
        pub const SERVICE_CBB_INSUFFICIENT: u8 = 5;
        /// parameter-CBB-insufficient
        pub const PARAMETER_CBB_INSUFFICIENT: u8 = 6;
        /// nesting-level-insufficient
        pub const NESTING_LEVEL_INSUFFICIENT: u8 = 7;
    }

    /// Subcodes of `conclude [9]`.
    pub mod conclude {
        /// other
        pub const OTHER: u8 = 0;
        /// further-communication-required
        pub const FURTHER_COMMUNICATION_REQUIRED: u8 = 1;
    }

    /// Subcodes of `cancel [10]`.
    pub mod cancel {
        /// other
        pub const OTHER: u8 = 0;
        /// invoke-id-unknown
        pub const INVOKE_ID_UNKNOWN: u8 = 1;
        /// cancel-not-possible
        pub const CANCEL_NOT_POSSIBLE: u8 = 2;
    }

    /// Subcodes of `file [11]`.
    pub mod file {
        /// other
        pub const OTHER: u8 = 0;
        /// filename-ambiguous
        pub const FILENAME_AMBIGUOUS: u8 = 1;
        /// file-busy
        pub const FILE_BUSY: u8 = 2;
        /// filename-syntax-error
        pub const FILENAME_SYNTAX_ERROR: u8 = 3;
        /// content-type-invalid
        pub const CONTENT_TYPE_INVALID: u8 = 4;
        /// position-invalid
        pub const POSITION_INVALID: u8 = 5;
        /// file-access-denied
        pub const FILE_ACCESS_DENIED: u8 = 6;
        /// file-non-existent
        pub const FILE_NON_EXISTENT: u8 = 7;
        /// duplicate-filename
        pub const DUPLICATE_FILENAME: u8 = 8;
        /// insufficient-space-in-filestore
        pub const INSUFFICIENT_SPACE_IN_FILESTORE: u8 = 9;
    }
}

// The errorClass CHOICE, thirteen alternatives

/// The errorClass CHOICE of a ServiceError.
///
/// The `u8` in each variant is the subcode INTEGER, and the BER context tag is the
/// index of the alternative, `[0]` through `[12]`. The named subcodes are in
/// [`subcode`], one module per alternative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorClass {
    /// `[0]` vmd-state; subcodes in [`subcode::vmd_state`].
    VmdState(u8),
    /// `[1]` application-reference; subcodes in [`subcode::application_reference`].
    ApplicationReference(u8),
    /// `[2]` definition; subcodes in [`subcode::definition`].
    Definition(u8),
    /// `[3]` resource; subcodes in [`subcode::resource`].
    Resource(u8),
    /// `[4]` service; subcodes in [`subcode::service`].
    Service(u8),
    /// `[5]` service-preempt; subcodes in [`subcode::service_preempt`].
    ServicePreempt(u8),
    /// `[6]` time-resolution; subcodes in [`subcode::time_resolution`].
    TimeResolution(u8),
    /// `[7]` access; subcodes in [`subcode::access`].
    Access(u8),
    /// `[8]` initiate; subcodes in [`subcode::initiate`].
    Initiate(u8),
    /// `[9]` conclude; subcodes in [`subcode::conclude`].
    Conclude(u8),
    /// `[10]` cancel; subcodes in [`subcode::cancel`].
    Cancel(u8),
    /// `[11]` file; subcodes in [`subcode::file`].
    File(u8),
    /// `[12]` others, which enumerates no subcodes.
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

    /// The named subcodes are compared against a second, hand-written
    /// transcription of the ISO 9506-2 named numbers, so that a wrong constant
    /// cannot travel on the wire unnoticed.
    #[test]
    fn subcode_constants_match_the_asn1_named_numbers() {
        // (alternative, subcode name, value)
        let expected: &[(&str, &str, u8)] = &[
            ("vmd-state", "other", subcode::vmd_state::OTHER),
            (
                "vmd-state",
                "vmd-state-conflict",
                subcode::vmd_state::VMD_STATE_CONFLICT,
            ),
            (
                "vmd-state",
                "vmd-operational-problem",
                subcode::vmd_state::VMD_OPERATIONAL_PROBLEM,
            ),
            (
                "vmd-state",
                "domain-transfer-problem",
                subcode::vmd_state::DOMAIN_TRANSFER_PROBLEM,
            ),
            (
                "vmd-state",
                "state-machine-id-invalid",
                subcode::vmd_state::STATE_MACHINE_ID_INVALID,
            ),
            (
                "application-reference",
                "other",
                subcode::application_reference::OTHER,
            ),
            (
                "application-reference",
                "application-unreachable",
                subcode::application_reference::APPLICATION_UNREACHABLE,
            ),
            (
                "application-reference",
                "connection-lost",
                subcode::application_reference::CONNECTION_LOST,
            ),
            (
                "application-reference",
                "application-reference-invalid",
                subcode::application_reference::APPLICATION_REFERENCE_INVALID,
            ),
            (
                "application-reference",
                "context-unsupported",
                subcode::application_reference::CONTEXT_UNSUPPORTED,
            ),
            ("definition", "other", subcode::definition::OTHER),
            (
                "definition",
                "object-undefined",
                subcode::definition::OBJECT_UNDEFINED,
            ),
            (
                "definition",
                "invalid-address",
                subcode::definition::INVALID_ADDRESS,
            ),
            (
                "definition",
                "type-unsupported",
                subcode::definition::TYPE_UNSUPPORTED,
            ),
            (
                "definition",
                "type-inconsistent",
                subcode::definition::TYPE_INCONSISTENT,
            ),
            (
                "definition",
                "object-exists",
                subcode::definition::OBJECT_EXISTS,
            ),
            (
                "definition",
                "object-attribute-inconsistent",
                subcode::definition::OBJECT_ATTRIBUTE_INCONSISTENT,
            ),
            ("resource", "other", subcode::resource::OTHER),
            (
                "resource",
                "memory-unavailable",
                subcode::resource::MEMORY_UNAVAILABLE,
            ),
            (
                "resource",
                "processor-resource-unavailable",
                subcode::resource::PROCESSOR_RESOURCE_UNAVAILABLE,
            ),
            (
                "resource",
                "mass-storage-unavailable",
                subcode::resource::MASS_STORAGE_UNAVAILABLE,
            ),
            (
                "resource",
                "capability-unavailable",
                subcode::resource::CAPABILITY_UNAVAILABLE,
            ),
            (
                "resource",
                "capability-unknown",
                subcode::resource::CAPABILITY_UNKNOWN,
            ),
            ("service", "other", subcode::service::OTHER),
            (
                "service",
                "primitives-out-of-sequence",
                subcode::service::PRIMITIVES_OUT_OF_SEQUENCE,
            ),
            (
                "service",
                "object-state-conflict",
                subcode::service::OBJECT_STATE_CONFLICT,
            ),
            ("service", "pdu-size", subcode::service::PDU_SIZE),
            (
                "service",
                "continuation-invalid",
                subcode::service::CONTINUATION_INVALID,
            ),
            (
                "service",
                "object-constraint-conflict",
                subcode::service::OBJECT_CONSTRAINT_CONFLICT,
            ),
            ("service-preempt", "other", subcode::service_preempt::OTHER),
            (
                "service-preempt",
                "timeout",
                subcode::service_preempt::TIMEOUT,
            ),
            (
                "service-preempt",
                "deadlock",
                subcode::service_preempt::DEADLOCK,
            ),
            (
                "service-preempt",
                "cancel",
                subcode::service_preempt::CANCEL,
            ),
            ("time-resolution", "other", subcode::time_resolution::OTHER),
            (
                "time-resolution",
                "unsupportable-time-resolution",
                subcode::time_resolution::UNSUPPORTABLE_TIME_RESOLUTION,
            ),
            ("access", "other", subcode::access::OTHER),
            (
                "access",
                "object-access-unsupported",
                subcode::access::OBJECT_ACCESS_UNSUPPORTED,
            ),
            (
                "access",
                "object-non-existent",
                subcode::access::OBJECT_NON_EXISTENT,
            ),
            (
                "access",
                "object-access-denied",
                subcode::access::OBJECT_ACCESS_DENIED,
            ),
            (
                "access",
                "object-invalidated",
                subcode::access::OBJECT_INVALIDATED,
            ),
            ("initiate", "other", subcode::initiate::OTHER),
            (
                "initiate",
                "version-incompatible",
                subcode::initiate::VERSION_INCOMPATIBLE,
            ),
            (
                "initiate",
                "max-segment-insufficient",
                subcode::initiate::MAX_SEGMENT_INSUFFICIENT,
            ),
            (
                "initiate",
                "max-services-outstanding-calling-insufficient",
                subcode::initiate::MAX_SERVICES_OUTSTANDING_CALLING_INSUFFICIENT,
            ),
            (
                "initiate",
                "max-services-outstanding-called-insufficient",
                subcode::initiate::MAX_SERVICES_OUTSTANDING_CALLED_INSUFFICIENT,
            ),
            (
                "initiate",
                "service-CBB-insufficient",
                subcode::initiate::SERVICE_CBB_INSUFFICIENT,
            ),
            (
                "initiate",
                "parameter-CBB-insufficient",
                subcode::initiate::PARAMETER_CBB_INSUFFICIENT,
            ),
            (
                "initiate",
                "nesting-level-insufficient",
                subcode::initiate::NESTING_LEVEL_INSUFFICIENT,
            ),
            ("conclude", "other", subcode::conclude::OTHER),
            (
                "conclude",
                "further-communication-required",
                subcode::conclude::FURTHER_COMMUNICATION_REQUIRED,
            ),
            ("cancel", "other", subcode::cancel::OTHER),
            (
                "cancel",
                "invoke-id-unknown",
                subcode::cancel::INVOKE_ID_UNKNOWN,
            ),
            (
                "cancel",
                "cancel-not-possible",
                subcode::cancel::CANCEL_NOT_POSSIBLE,
            ),
            ("file", "other", subcode::file::OTHER),
            (
                "file",
                "filename-ambiguous",
                subcode::file::FILENAME_AMBIGUOUS,
            ),
            ("file", "file-busy", subcode::file::FILE_BUSY),
            (
                "file",
                "filename-syntax-error",
                subcode::file::FILENAME_SYNTAX_ERROR,
            ),
            (
                "file",
                "content-type-invalid",
                subcode::file::CONTENT_TYPE_INVALID,
            ),
            ("file", "position-invalid", subcode::file::POSITION_INVALID),
            (
                "file",
                "file-access-denied",
                subcode::file::FILE_ACCESS_DENIED,
            ),
            (
                "file",
                "file-non-existent",
                subcode::file::FILE_NON_EXISTENT,
            ),
            (
                "file",
                "duplicate-filename",
                subcode::file::DUPLICATE_FILENAME,
            ),
            (
                "file",
                "insufficient-space-in-filestore",
                subcode::file::INSUFFICIENT_SPACE_IN_FILESTORE,
            ),
        ];

        // the named numbers, transcribed independently of the constants above
        let asn1: &[(&str, &str, u8)] = &[
            ("vmd-state", "other", 0),
            ("vmd-state", "vmd-state-conflict", 1),
            ("vmd-state", "vmd-operational-problem", 2),
            ("vmd-state", "domain-transfer-problem", 3),
            ("vmd-state", "state-machine-id-invalid", 4),
            ("application-reference", "other", 0),
            ("application-reference", "application-unreachable", 1),
            ("application-reference", "connection-lost", 2),
            ("application-reference", "application-reference-invalid", 3),
            ("application-reference", "context-unsupported", 4),
            ("definition", "other", 0),
            ("definition", "object-undefined", 1),
            ("definition", "invalid-address", 2),
            ("definition", "type-unsupported", 3),
            ("definition", "type-inconsistent", 4),
            ("definition", "object-exists", 5),
            ("definition", "object-attribute-inconsistent", 6),
            ("resource", "other", 0),
            ("resource", "memory-unavailable", 1),
            ("resource", "processor-resource-unavailable", 2),
            ("resource", "mass-storage-unavailable", 3),
            ("resource", "capability-unavailable", 4),
            ("resource", "capability-unknown", 5),
            ("service", "other", 0),
            ("service", "primitives-out-of-sequence", 1),
            ("service", "object-state-conflict", 2),
            ("service", "pdu-size", 3),
            ("service", "continuation-invalid", 4),
            ("service", "object-constraint-conflict", 5),
            ("service-preempt", "other", 0),
            ("service-preempt", "timeout", 1),
            ("service-preempt", "deadlock", 2),
            ("service-preempt", "cancel", 3),
            ("time-resolution", "other", 0),
            ("time-resolution", "unsupportable-time-resolution", 1),
            ("access", "other", 0),
            ("access", "object-access-unsupported", 1),
            ("access", "object-non-existent", 2),
            ("access", "object-access-denied", 3),
            ("access", "object-invalidated", 4),
            ("initiate", "other", 0),
            ("initiate", "version-incompatible", 1),
            ("initiate", "max-segment-insufficient", 2),
            (
                "initiate",
                "max-services-outstanding-calling-insufficient",
                3,
            ),
            (
                "initiate",
                "max-services-outstanding-called-insufficient",
                4,
            ),
            ("initiate", "service-CBB-insufficient", 5),
            ("initiate", "parameter-CBB-insufficient", 6),
            ("initiate", "nesting-level-insufficient", 7),
            ("conclude", "other", 0),
            ("conclude", "further-communication-required", 1),
            ("cancel", "other", 0),
            ("cancel", "invoke-id-unknown", 1),
            ("cancel", "cancel-not-possible", 2),
            ("file", "other", 0),
            ("file", "filename-ambiguous", 1),
            ("file", "file-busy", 2),
            ("file", "filename-syntax-error", 3),
            ("file", "content-type-invalid", 4),
            ("file", "position-invalid", 5),
            ("file", "file-access-denied", 6),
            ("file", "file-non-existent", 7),
            ("file", "duplicate-filename", 8),
            ("file", "insufficient-space-in-filestore", 9),
        ];

        assert_eq!(
            expected.len(),
            asn1.len(),
            "every named number must have exactly one constant"
        );
        assert_eq!(
            expected.len(),
            63,
            "the twelve enumerated alternatives together define 63 named numbers"
        );
        for (got, want) in expected.iter().zip(asn1.iter()) {
            assert_eq!(got, want, "subcode {}.{} is wrong", want.0, want.1);
        }
    }

    /// The access subcode travels as a one-byte INTEGER inside the errorClass
    /// CHOICE, under the IMPLICIT tag `0x87`.
    #[test]
    fn access_object_non_existent_wire_vector() {
        let ec = ErrorClass::Access(subcode::access::OBJECT_NON_EXISTENT);
        let mut buf = BytesMut::new();
        ec.encode_explicit(&mut buf);
        assert_eq!(&buf[..], &[0xa0, 0x03, 0x87, 0x01, 0x02]);
    }

    /// The access subcodes are not the `DataAccessError` codes; the two sets
    /// overlap numerically and mean different things.
    #[test]
    fn access_subcodes_are_distinct_from_data_access_error_codes() {
        use super::super::common::DataAccessError;
        assert_eq!(DataAccessError::ObjectNonExistent as u8, 10);
        assert_eq!(subcode::access::OBJECT_NON_EXISTENT, 2);
        assert_eq!(DataAccessError::ObjectAccessUnsupported as u8, 9);
        assert_eq!(subcode::access::OBJECT_ACCESS_UNSUPPORTED, 1);
    }
}
