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
    /// The output is `0xa0 <len> 0x8<n> <len> <code>`, where `0x8<n>` is
    /// `0x80 | context_tag()`, an IMPLICIT primitive tag, and `<code>` is the
    /// subcode as a minimal non-negative INTEGER: one octet below 128, two
    /// octets with a leading zero from 128 up.
    pub fn encode_explicit(&self, buf: &mut BytesMut) {
        let inner_tag = 0x80 | self.context_tag();
        let code = super::common::encode_unsigned_int_minimal(u64::from(self.code()));
        buf.extend_from_slice(&[0xa0, (code.len() + 2) as u8, inner_tag, code.len() as u8]);
        buf.extend_from_slice(&code);
    }

    /// Decodes the errorClass CHOICE, starting at its EXPLICIT `[0]` wrapper.
    ///
    /// `data` starts at the `0xa0` byte; the number of bytes consumed is returned.
    /// Lengths may use the short or the long form. The wrapper must hold
    /// exactly one primitive alternative, `[0]` through `[12]`, whose subcode
    /// is a non-negative INTEGER no larger than 255. A subcode carrying
    /// redundant leading zero octets, a non-minimal INTEGER encoding, is
    /// accepted.
    pub fn decode_explicit(data: &[u8]) -> Result<(Self, usize), MmsError> {
        let (tag, content, consumed) = split_tlv(data)?;
        if tag != 0xa0 {
            return Err(MmsError::InvalidTag {
                expected: 0xa0,
                actual: tag,
            });
        }

        // the inner tag is context-specific and primitive, with the choice index in
        // its low five bits
        let (inner_tag, code_bytes, inner_used) = split_tlv(content)?;
        if inner_used != content.len() {
            return Err(MmsError::InvalidLength);
        }
        if inner_tag & 0xe0 != 0x80 {
            return Err(MmsError::InvalidTag {
                expected: 0x80,
                actual: inner_tag,
            });
        }
        let code =
            u8::try_from(decode_unsigned32(code_bytes)?).map_err(|_| MmsError::InvalidLength)?;

        let ec = match inner_tag & 0x1f {
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
            choice_idx => {
                tracing::warn!(
                    "unknown serviceerror errorclass choice index {}",
                    choice_idx
                );
                return Err(MmsError::UnknownMmsPduTag(inner_tag));
            }
        };

        Ok((ec, consumed))
    }
}

// ServiceError

/// An MMS ServiceError, carried by an InitiateError and by a ConfirmedError PDU.
///
/// Wire format, whose outer `0xaa` is written by `MmsPdu`:
/// ```text
/// 0xa0 <len>     -- errorClass [0] EXPLICIT CHOICE
///   0x8n <len> c -- inner choice tag + sub-code
/// (0x81 ... )    -- additionalCode [1] IMPLICIT INTEGER, OPTIONAL
/// (0x82 ... )    -- additionalDescription [2] IMPLICIT VisibleString, OPTIONAL
/// (0xa3 ... )    -- serviceSpecificInformation [3] CHOICE, OPTIONAL
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServiceError {
    /// errorClass `[0]` EXPLICIT, the one mandatory field.
    pub error_class: ErrorClass,
    /// additionalCode `[1]` IMPLICIT INTEGER, OPTIONAL.
    ///
    /// A value outside the `i32` range decodes as `None`.
    pub additional_code: Option<i32>,
    /// additionalDescription `[2]` IMPLICIT VisibleString, OPTIONAL.
    pub additional_description: Option<String>,
    /// serviceSpecificInformation `[3]` CHOICE, OPTIONAL.
    ///
    /// An alternative this type does not model decodes as `None`.
    pub service_specific: Option<ServiceSpecificInfo>,
}

/// The serviceSpecificInformation of a ServiceError: the extra result a
/// failed service reports beside its error class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServiceSpecificInfo {
    /// deleteNamedVariableList `[6]` IMPLICIT Unsigned32: how many named
    /// variable lists the failed DeleteNamedVariableList did delete.
    DeleteNamedVariableList(u32),
}

impl ServiceSpecificInfo {
    /// Context tag of the alternative inside the serviceSpecificInformation
    /// CHOICE.
    const DELETE_NAMED_VARIABLE_LIST: u8 = 0x86;

    /// Encodes the alternative, without the `[3]` wrapper.
    fn encode(&self, buf: &mut BytesMut) {
        match self {
            ServiceSpecificInfo::DeleteNamedVariableList(n) => {
                let bytes = super::common::encode_unsigned_int_minimal(u64::from(*n));
                buf.extend_from_slice(&[Self::DELETE_NAMED_VARIABLE_LIST]);
                super::initiate::encode_length(bytes.len(), buf);
                buf.extend_from_slice(&bytes);
            }
        }
    }

    /// Decodes the content of the `[3]` wrapper: `None` for an alternative
    /// this type does not model, and for content that does not decode, so the
    /// rest of the ServiceError still does.
    fn decode(data: &[u8]) -> Option<Self> {
        let decoded = split_tlv(data).and_then(|(tag, content, _)| match tag {
            Self::DELETE_NAMED_VARIABLE_LIST => decode_unsigned32(content)
                .map(|n| Some(ServiceSpecificInfo::DeleteNamedVariableList(n))),
            other => {
                tracing::debug!(
                    "skipping unmodelled servicespecificinformation alternative 0x{:02X}",
                    other
                );
                Ok(None)
            }
        });
        decoded.unwrap_or_else(|e| {
            tracing::debug!(error = %e, "skipping undecodable servicespecificinformation");
            None
        })
    }
}

impl ServiceError {
    /// Builds a `ServiceError` carrying only an errorClass.
    pub fn new(error_class: ErrorClass) -> Self {
        Self {
            error_class,
            additional_code: None,
            additional_description: None,
            service_specific: None,
        }
    }

    /// Sets the additionalCode.
    pub fn with_additional_code(mut self, code: i32) -> Self {
        self.additional_code = Some(code);
        self
    }

    /// Sets the additionalDescription.
    pub fn with_additional_description(mut self, description: impl Into<String>) -> Self {
        self.additional_description = Some(description.into());
        self
    }

    /// Sets the serviceSpecificInformation.
    pub fn with_service_specific(mut self, info: ServiceSpecificInfo) -> Self {
        self.service_specific = Some(info);
        self
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
            buf.extend_from_slice(&[0x82]);
            super::initiate::encode_length(bytes.len(), buf);
            buf.extend_from_slice(bytes);
        }

        if let Some(info) = &self.service_specific {
            // serviceSpecificInformation [3] CHOICE, an explicit wrapper
            let mut inner = BytesMut::new();
            info.encode(&mut inner);
            buf.extend_from_slice(&[0xa3]);
            super::initiate::encode_length(inner.len(), buf);
            buf.extend_from_slice(&inner);
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
        let mut service_specific: Option<ServiceSpecificInfo> = None;

        // optional fields
        while pos < data.len() {
            let (tag, val_bytes, consumed) = split_tlv(&data[pos..])?;
            pos += consumed;

            match tag {
                0x81 => {
                    // additionalCode [1] IMPLICIT INTEGER, unbounded on the wire
                    additional_code = if val_bytes.len() > 4 {
                        tracing::debug!("skipping additionalcode outside the i32 range");
                        None
                    } else {
                        Some(decode_int32(val_bytes)?)
                    };
                }
                0x82 => {
                    // additionalDescription [2] IMPLICIT VisibleString
                    let s = core::str::from_utf8(val_bytes)
                        .map_err(|_| MmsError::InvalidUtf8)?
                        .to_string();
                    additional_description = Some(s);
                }
                0xa3 => {
                    // serviceSpecificInformation [3] CHOICE
                    service_specific = ServiceSpecificInfo::decode(val_bytes);
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
            service_specific,
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

// ConfirmedError PDU decoder

/// Splits one TLV at the start of `data`.
///
/// Returns the tag, the content and the total number of bytes the TLV occupies,
/// header included.
fn split_tlv(data: &[u8]) -> Result<(u8, &[u8], usize), MmsError> {
    if data.len() < 2 {
        return Err(MmsError::TruncatedPdu);
    }
    let tag = data[0];
    let (len, len_size) = super::initiate::decode_length(&data[1..])?;
    let start = 1 + len_size;
    let end = start.checked_add(len).ok_or(MmsError::InvalidLength)?;
    if data.len() < end {
        return Err(MmsError::TruncatedPdu);
    }
    Ok((tag, &data[start..end], end))
}

/// Decodes a BER INTEGER holding an ASN.1 `Unsigned32`.
///
/// The encoder pads a value whose most significant bit is set with a leading
/// `0x00`, so five content bytes are the widest legal form. A shorter encoding
/// whose first byte has its top bit set is a negative INTEGER, which an
/// `Unsigned32` field cannot carry.
fn decode_unsigned32(data: &[u8]) -> Result<u32, MmsError> {
    if data.is_empty() || data.len() > 5 {
        return Err(MmsError::InvalidLength);
    }
    if data[0] & 0x80 != 0 || (data.len() == 5 && data[0] != 0x00) {
        return Err(MmsError::InvalidLength);
    }
    let mut val: u32 = 0;
    for &b in data {
        val = (val << 8) | b as u32;
    }
    Ok(val)
}

/// Decodes a complete ConfirmedError PDU, outer `0xa2 <len>` included, into its
/// invokeID and ServiceError.
///
/// The inverse of [`encode_confirmed_error_pdu`].
pub fn decode_confirmed_error_pdu(data: &[u8]) -> Result<(u32, ServiceError), MmsError> {
    let (tag, inner, _) = split_tlv(data)?;
    if tag != 0xa2 {
        return Err(MmsError::InvalidTag {
            expected: 0xa2,
            actual: tag,
        });
    }
    decode_confirmed_error_inner(inner)
}

/// Decodes the content of a ConfirmedError PDU, what follows the outer
/// `0xa2 <len>`, into its invokeID and ServiceError.
///
/// Wire format:
///
/// ```text
/// 0x80 <len> <id>  -- invokeID [0] IMPLICIT Unsigned32
/// (0x81 <len> ...) -- modifierPosition [1] IMPLICIT Unsigned32, OPTIONAL
/// 0xa2 <len> ...   -- serviceError [2] IMPLICIT ServiceError
/// ```
///
/// invokeID carries the context tag `0x80`, not the universal INTEGER tag
/// `0x02` that an unqualified `invokeID` field would carry in a
/// Confirmed-RequestPDU or a Confirmed-ResponsePDU.
///
/// `modifierPosition` is accepted and skipped; nothing in this implementation
/// produces one.
pub fn decode_confirmed_error_inner(data: &[u8]) -> Result<(u32, ServiceError), MmsError> {
    // invokeID [0] IMPLICIT Unsigned32, mandatory and first
    let (tag, id_bytes, used) = split_tlv(data)?;
    if tag != 0x80 {
        return Err(MmsError::InvalidTag {
            expected: 0x80,
            actual: tag,
        });
    }
    let invoke_id = decode_unsigned32(id_bytes)?;
    let mut pos = used;

    // modifierPosition [1] IMPLICIT Unsigned32, OPTIONAL
    if data.get(pos) == Some(&0x81) {
        let (_, _, used) = split_tlv(&data[pos..])?;
        pos += used;
    }

    // serviceError [2] IMPLICIT ServiceError, mandatory
    let (tag, se_bytes, _) = split_tlv(&data[pos..])?;
    if tag != 0xa2 {
        return Err(MmsError::InvalidTag {
            expected: 0xa2,
            actual: tag,
        });
    }
    let service_error = ServiceError::decode_inner(se_bytes)?;

    Ok((invoke_id, service_error))
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
            service_specific: None,
        };
        let mut buf = BytesMut::new();
        se.encode_inner(&mut buf);
        let decoded = ServiceError::decode_inner(&buf).unwrap();
        assert_eq!(decoded, se);
    }

    #[test]
    fn service_specific_delete_named_variable_list_encodes_as_choice_six() {
        let se = ServiceError::new(ErrorClass::Access(3))
            .with_service_specific(ServiceSpecificInfo::DeleteNamedVariableList(2));
        let mut buf = BytesMut::new();
        se.encode_inner(&mut buf);
        assert_eq!(
            &buf[..],
            &[0xa0, 0x03, 0x87, 0x01, 0x03, 0xa3, 0x03, 0x86, 0x01, 0x02]
        );
    }

    #[test]
    fn service_specific_round_trips_alongside_the_other_optional_fields() {
        for n in [0u32, 1, 0x7f, 0x80, 0xffff_ffff] {
            let se = ServiceError::new(ErrorClass::Access(3))
                .with_additional_code(-5)
                .with_additional_description("partly deleted")
                .with_service_specific(ServiceSpecificInfo::DeleteNamedVariableList(n));
            let mut buf = BytesMut::new();
            se.encode_inner(&mut buf);
            assert_eq!(ServiceError::decode_inner(&buf).unwrap(), se, "n = {n}");
        }
    }

    #[test]
    fn service_specific_survives_a_confirmed_error_pdu() {
        let se = ServiceError::new(ErrorClass::Access(3))
            .with_service_specific(ServiceSpecificInfo::DeleteNamedVariableList(300));
        let mut buf = BytesMut::new();
        encode_confirmed_error_pdu(9, &se, &mut buf);
        let (invoke_id, decoded) = decode_confirmed_error_pdu(&buf).unwrap();
        assert_eq!(invoke_id, 9);
        assert_eq!(decoded, se);
    }

    #[test]
    fn unmodelled_service_specific_alternative_decodes_as_none() {
        // serviceSpecificInformation [3] carrying obtainFile [0] IMPLICIT.
        let data = [0xa0, 0x03, 0x87, 0x01, 0x00, 0xa3, 0x03, 0x80, 0x01, 0x01];
        let decoded = ServiceError::decode_inner(&data).unwrap();
        assert_eq!(decoded.error_class, ErrorClass::Access(0));
        assert_eq!(decoded.service_specific, None);
    }

    #[test]
    fn undecodable_service_specific_keeps_the_error_class() {
        for data in [
            // A negative count.
            &[0xa0, 0x03, 0x87, 0x01, 0x03, 0xa3, 0x03, 0x86, 0x01, 0x80][..],
            // An empty CHOICE.
            &[0xa0, 0x03, 0x87, 0x01, 0x03, 0xa3, 0x00][..],
            // A count wider than an Unsigned32.
            &[
                0xa0, 0x03, 0x87, 0x01, 0x03, 0xa3, 0x08, 0x86, 0x06, 0, 1, 2, 3, 4, 5,
            ][..],
        ] {
            let decoded = ServiceError::decode_inner(data).unwrap();
            assert_eq!(decoded.error_class, ErrorClass::Access(3), "{data:02x?}");
            assert_eq!(decoded.service_specific, None, "{data:02x?}");
        }
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

    /// A hand-written ConfirmedError PDU, whose bytes follow the ISO 9506-2
    /// Confirmed-ErrorPDU SEQUENCE: invokeID under the context tag `0x80` and
    /// serviceError under `0xa2`.
    const CONFIRMED_ERROR_VECTOR: &[u8] = &[
        0xa2, 0x0a, // confirmedErrorPdu [2] IMPLICIT SEQUENCE, len 10
        0x80, 0x01, 0x03, // invokeID [0] IMPLICIT Unsigned32 = 3
        0xa2, 0x05, // serviceError [2] IMPLICIT, len 5
        0xa0, 0x03, // errorClass [0] EXPLICIT, len 3
        0x87, 0x01, 0x02, // access [7] IMPLICIT INTEGER = 2, object-non-existent
    ];

    #[test]
    fn confirmed_error_pdu_encodes_the_wire_vector() {
        let se = ServiceError::new(ErrorClass::Access(subcode::access::OBJECT_NON_EXISTENT));
        let mut buf = BytesMut::new();
        encode_confirmed_error_pdu(3, &se, &mut buf);
        assert_eq!(&buf[..], CONFIRMED_ERROR_VECTOR);
    }

    #[test]
    fn confirmed_error_pdu_decodes_the_wire_vector() {
        let (invoke_id, se) = decode_confirmed_error_pdu(CONFIRMED_ERROR_VECTOR).unwrap();
        assert_eq!(invoke_id, 3);
        assert_eq!(
            se.error_class,
            ErrorClass::Access(subcode::access::OBJECT_NON_EXISTENT)
        );
    }

    /// What the encoder writes, the decoder reads back, for a spread of
    /// invokeIDs and errorClass alternatives.
    #[test]
    fn confirmed_error_pdu_round_trip() {
        let cases = [
            (0u32, ErrorClass::Access(subcode::access::OTHER)),
            (
                1,
                ErrorClass::Access(subcode::access::OBJECT_ACCESS_UNSUPPORTED),
            ),
            (
                127,
                ErrorClass::Access(subcode::access::OBJECT_NON_EXISTENT),
            ),
            (
                128,
                ErrorClass::Definition(subcode::definition::OBJECT_EXISTS),
            ),
            (
                65_535,
                ErrorClass::Definition(subcode::definition::INVALID_ADDRESS),
            ),
            (16_777_216, ErrorClass::Resource(subcode::resource::OTHER)),
            (
                u32::MAX,
                ErrorClass::Service(subcode::service::OBJECT_CONSTRAINT_CONFLICT),
            ),
        ];
        assert_eq!(cases.len(), 7);
        for (invoke_id, error_class) in cases {
            let se = ServiceError::new(error_class.clone());
            let mut buf = BytesMut::new();
            encode_confirmed_error_pdu(invoke_id, &se, &mut buf);
            let (got_id, got_se) = decode_confirmed_error_pdu(&buf)
                .unwrap_or_else(|e| panic!("invoke id {invoke_id} failed to decode: {e}"));
            assert_eq!(got_id, invoke_id, "invoke id must survive the round trip");
            assert_eq!(got_se.error_class, error_class);
        }
    }

    /// The optional additionalCode and additionalDescription survive the round
    /// trip, so a ServiceError carrying them is not truncated.
    #[test]
    fn confirmed_error_pdu_round_trip_keeps_optional_fields() {
        let se = ServiceError {
            error_class: ErrorClass::Access(subcode::access::OBJECT_ACCESS_DENIED),
            additional_code: Some(-7),
            additional_description: Some("no read access".to_string()),
            service_specific: None,
        };
        let mut buf = BytesMut::new();
        encode_confirmed_error_pdu(9, &se, &mut buf);
        let (invoke_id, got) = decode_confirmed_error_pdu(&buf).unwrap();
        assert_eq!(invoke_id, 9);
        assert_eq!(got, se);
    }

    /// A Confirmed-RequestPDU carries an untagged `invokeID`, which travels
    /// under the universal INTEGER tag `0x02`. The Confirmed-ErrorPDU field is
    /// `[0] IMPLICIT`, so `0x02` in that position is a different PDU shape and
    /// must be refused rather than skipped.
    #[test]
    fn confirmed_error_rejects_a_universal_integer_invoke_id() {
        let with_universal_tag: &[u8] = &[
            0xa2, 0x0a, 0x02, 0x01, 0x03, 0xa2, 0x05, 0xa0, 0x03, 0x87, 0x01, 0x02,
        ];
        let err = decode_confirmed_error_pdu(with_universal_tag)
            .expect_err("a universal INTEGER invokeID is not a Confirmed-ErrorPDU");
        assert!(
            matches!(
                err,
                MmsError::InvalidTag {
                    expected: 0x80,
                    actual: 0x02
                }
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn confirmed_error_accepts_and_skips_a_modifier_position() {
        // 0x81 modifierPosition sits between the invokeID and the serviceError
        let with_modifier: &[u8] = &[
            0xa2, 0x0d, 0x80, 0x01, 0x03, 0x81, 0x01, 0x01, 0xa2, 0x05, 0xa0, 0x03, 0x87, 0x01,
            0x02,
        ];
        let (invoke_id, se) = decode_confirmed_error_pdu(with_modifier).unwrap();
        assert_eq!(invoke_id, 3);
        assert_eq!(
            se.error_class,
            ErrorClass::Access(subcode::access::OBJECT_NON_EXISTENT)
        );
    }

    #[test]
    fn confirmed_error_rejects_truncated_and_mistagged_input() {
        // every prefix of a valid PDU fails rather than panicking
        for n in 0..CONFIRMED_ERROR_VECTOR.len() {
            assert!(
                decode_confirmed_error_pdu(&CONFIRMED_ERROR_VECTOR[..n]).is_err(),
                "prefix of {n} bytes must not decode"
            );
        }
        // the whole vector does decode, so the loop above is not vacuous
        assert!(decode_confirmed_error_pdu(CONFIRMED_ERROR_VECTOR).is_ok());

        // an outer tag that is not 0xa2
        let mut wrong_outer = CONFIRMED_ERROR_VECTOR.to_vec();
        wrong_outer[0] = 0xa1;
        assert!(decode_confirmed_error_pdu(&wrong_outer).is_err());

        // a serviceError under a tag that is not 0xa2
        let mut wrong_service = CONFIRMED_ERROR_VECTOR.to_vec();
        wrong_service[5] = 0xa3;
        assert!(decode_confirmed_error_pdu(&wrong_service).is_err());
    }

    #[test]
    fn confirmed_error_rejects_an_oversized_invoke_id() {
        // six content bytes for a Unsigned32, and a negative INTEGER
        let too_wide: &[u8] = &[
            0xa2, 0x0f, 0x80, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0xa2, 0x05, 0xa0, 0x03,
            0x87, 0x01, 0x02,
        ];
        assert!(decode_confirmed_error_pdu(too_wide).is_err());

        let negative: &[u8] = &[
            0xa2, 0x0d, 0x80, 0x04, 0xff, 0xff, 0xff, 0xff, 0xa2, 0x05, 0xa0, 0x03, 0x87, 0x01,
            0x02,
        ];
        assert!(decode_confirmed_error_pdu(negative).is_err());
    }

    /// Wraps ServiceError content in a ConfirmedError PDU under the invokeID
    /// content bytes `invoke_id`, with every length in the short form.
    fn confirmed_error(invoke_id: &[u8], service_error: &[u8]) -> Vec<u8> {
        let mut inner = vec![0x80, invoke_id.len() as u8];
        inner.extend_from_slice(invoke_id);
        inner.extend_from_slice(&[0xa2, service_error.len() as u8]);
        inner.extend_from_slice(service_error);
        let mut pdu = vec![0xa2, inner.len() as u8];
        pdu.extend_from_slice(&inner);
        pdu
    }

    /// Every errorClass alternative decodes under its own context tag.
    #[test]
    fn confirmed_error_decodes_every_error_class_alternative() {
        for idx in 0u8..=12 {
            let pdu = confirmed_error(&[0x05], &[0xa0, 0x03, 0x80 | idx, 0x01, 0x01]);
            let (invoke_id, se) = decode_confirmed_error_pdu(&pdu)
                .unwrap_or_else(|e| panic!("alternative {idx} failed to decode: {e}"));
            assert_eq!(invoke_id, 5);
            assert_eq!(se.error_class.context_tag(), idx);
            assert_eq!(se.error_class.code(), 1);
        }
    }

    /// An errorClass index outside the thirteen alternatives does not decode.
    #[test]
    fn confirmed_error_rejects_an_unknown_error_class_alternative() {
        let pdu = confirmed_error(&[0x05], &[0xa0, 0x03, 0x8d, 0x01, 0x01]);
        assert!(decode_confirmed_error_pdu(&pdu).is_err());
    }

    /// The invokeID decodes at every content width an Unsigned32 takes.
    #[test]
    fn confirmed_error_decodes_every_invoke_id_width() {
        let service_error = [0xa0, 0x03, 0x87, 0x01, 0x02];
        let cases: &[(&[u8], u32)] = &[
            (&[0x00], 0),
            (&[0x7f], 0x7f),
            (&[0x00, 0x80], 0x80),
            (&[0x7f, 0xff], 0x7fff),
            (&[0x00, 0x80, 0x00], 0x8000),
            (&[0x01, 0x00, 0x00, 0x00], 0x0100_0000),
            (&[0x00, 0xff, 0xff, 0xff, 0xff], u32::MAX),
        ];
        for (content, want) in cases {
            let pdu = confirmed_error(content, &service_error);
            let (invoke_id, se) = decode_confirmed_error_pdu(&pdu)
                .unwrap_or_else(|e| panic!("invoke id {content:02x?} failed to decode: {e}"));
            assert_eq!(invoke_id, *want);
            assert_eq!(se.error_class, ErrorClass::Access(2));
        }
    }

    /// Lengths written in the long form, with one and with two length octets,
    /// decode at every level of the PDU.
    #[test]
    fn confirmed_error_decodes_long_form_lengths() {
        let cases: &[&[u8]] = &[
            // the outer SEQUENCE length as 0x81
            &[
                0xa2, 0x81, 0x0a, 0x80, 0x01, 0x03, 0xa2, 0x05, 0xa0, 0x03, 0x87, 0x01, 0x02,
            ],
            // the outer SEQUENCE length as 0x82
            &[
                0xa2, 0x82, 0x00, 0x0a, 0x80, 0x01, 0x03, 0xa2, 0x05, 0xa0, 0x03, 0x87, 0x01, 0x02,
            ],
            // the invokeID length as 0x81
            &[
                0xa2, 0x0b, 0x80, 0x81, 0x01, 0x03, 0xa2, 0x05, 0xa0, 0x03, 0x87, 0x01, 0x02,
            ],
            // the serviceError length as 0x82
            &[
                0xa2, 0x0c, 0x80, 0x01, 0x03, 0xa2, 0x82, 0x00, 0x05, 0xa0, 0x03, 0x87, 0x01, 0x02,
            ],
            // the errorClass wrapper length as 0x81
            &[
                0xa2, 0x0b, 0x80, 0x01, 0x03, 0xa2, 0x06, 0xa0, 0x81, 0x03, 0x87, 0x01, 0x02,
            ],
            // the errorClass wrapper length as 0x82
            &[
                0xa2, 0x0c, 0x80, 0x01, 0x03, 0xa2, 0x07, 0xa0, 0x82, 0x00, 0x03, 0x87, 0x01, 0x02,
            ],
            // the subcode length as 0x81
            &[
                0xa2, 0x0b, 0x80, 0x01, 0x03, 0xa2, 0x06, 0xa0, 0x04, 0x87, 0x81, 0x01, 0x02,
            ],
            // every length in the long form
            &[
                0xa2, 0x81, 0x10, 0x80, 0x81, 0x01, 0x03, 0xa2, 0x82, 0x00, 0x08, 0xa0, 0x82, 0x00,
                0x04, 0x87, 0x81, 0x01, 0x02,
            ],
        ];
        for pdu in cases {
            let (invoke_id, se) = decode_confirmed_error_pdu(pdu)
                .unwrap_or_else(|e| panic!("{pdu:02x?} failed to decode: {e}"));
            assert_eq!(invoke_id, 3, "{pdu:02x?}");
            assert_eq!(
                se.error_class,
                ErrorClass::Access(subcode::access::OBJECT_NON_EXISTENT),
                "{pdu:02x?}"
            );
        }
    }

    /// A subcode from 128 up carries a leading zero octet to stay
    /// non-negative, and decodes to the same value.
    #[test]
    fn confirmed_error_decodes_a_two_octet_subcode() {
        let pdu = confirmed_error(&[0x03], &[0xa0, 0x04, 0x8c, 0x02, 0x00, 0xc8]);
        let (_, se) = decode_confirmed_error_pdu(&pdu).unwrap();
        assert_eq!(se.error_class, ErrorClass::Others(200));
    }

    /// A subcode that is negative, too large for the subcode type or empty does
    /// not decode; neither does a wrapper holding anything but exactly one
    /// primitive alternative.
    #[test]
    fn confirmed_error_rejects_malformed_error_class() {
        let cases: &[&[u8]] = &[
            // a negative subcode
            &[0xa0, 0x03, 0x87, 0x01, 0xff],
            // a subcode of 256
            &[0xa0, 0x04, 0x87, 0x02, 0x01, 0x00],
            // an empty subcode
            &[0xa0, 0x02, 0x87, 0x00],
            // a wrapper carrying a second alternative
            &[0xa0, 0x06, 0x87, 0x01, 0x02, 0x87, 0x01, 0x02],
            // a constructed alternative
            &[0xa0, 0x03, 0xa7, 0x01, 0x02],
            // a wrapper length that runs past the ServiceError
            &[0xa0, 0x04, 0x87, 0x01, 0x02],
        ];
        for service_error in cases {
            let pdu = confirmed_error(&[0x03], service_error);
            assert!(
                decode_confirmed_error_pdu(&pdu).is_err(),
                "{service_error:02x?} must not decode"
            );
        }
    }

    /// The optional ServiceError fields decode in every combination, each with
    /// its length in the short and in the long form.
    #[test]
    fn confirmed_error_decodes_the_optional_fields() {
        let class = [0xa0, 0x03, 0x87, 0x01, 0x03];
        let code_short: &[u8] = &[0x81, 0x01, 0x07];
        let code_long: &[u8] = &[0x81, 0x81, 0x02, 0xff, 0x00];
        let desc_short: &[u8] = &[0x82, 0x02, 0x6e, 0x6f];
        let desc_long: &[u8] = &[0x82, 0x82, 0x00, 0x02, 0x6e, 0x6f];
        let info_short: &[u8] = &[0xa3, 0x03, 0x86, 0x01, 0x02];
        let info_long: &[u8] = &[0xa3, 0x81, 0x04, 0x86, 0x81, 0x01, 0x02];
        for code in [None, Some(code_short), Some(code_long)] {
            for desc in [None, Some(desc_short), Some(desc_long)] {
                for info in [None, Some(info_short), Some(info_long)] {
                    let mut body = class.to_vec();
                    for field in [code, desc, info].into_iter().flatten() {
                        body.extend_from_slice(field);
                    }
                    let pdu = confirmed_error(&[0x03], &body);
                    let (_, se) = decode_confirmed_error_pdu(&pdu)
                        .unwrap_or_else(|e| panic!("{body:02x?} failed to decode: {e}"));
                    assert_eq!(se.error_class, ErrorClass::Access(3));
                    let want_code = code.map(|c| if c.len() == 3 { 7 } else { -256 });
                    assert_eq!(se.additional_code, want_code, "{body:02x?}");
                    assert_eq!(
                        se.additional_description.as_deref(),
                        desc.map(|_| "no"),
                        "{body:02x?}"
                    );
                    assert_eq!(
                        se.service_specific,
                        info.map(|_| ServiceSpecificInfo::DeleteNamedVariableList(2)),
                        "{body:02x?}"
                    );
                }
            }
        }
    }

    /// An additionalCode wider than 32 bits is a legal INTEGER this type
    /// cannot hold: it decodes as `None` and the error class still decodes.
    #[test]
    fn wide_additional_code_keeps_the_error_class() {
        let body = [
            0xa0, 0x03, 0x87, 0x01, 0x03, 0x81, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        let pdu = confirmed_error(&[0x03], &body);
        let (_, se) = decode_confirmed_error_pdu(&pdu).unwrap();
        assert_eq!(se.error_class, ErrorClass::Access(3));
        assert_eq!(se.additional_code, None);
    }

    /// The same alternative as `ec`, carrying `code`.
    fn with_code(ec: &ErrorClass, code: u8) -> ErrorClass {
        match ec {
            ErrorClass::VmdState(_) => ErrorClass::VmdState(code),
            ErrorClass::ApplicationReference(_) => ErrorClass::ApplicationReference(code),
            ErrorClass::Definition(_) => ErrorClass::Definition(code),
            ErrorClass::Resource(_) => ErrorClass::Resource(code),
            ErrorClass::Service(_) => ErrorClass::Service(code),
            ErrorClass::ServicePreempt(_) => ErrorClass::ServicePreempt(code),
            ErrorClass::TimeResolution(_) => ErrorClass::TimeResolution(code),
            ErrorClass::Access(_) => ErrorClass::Access(code),
            ErrorClass::Initiate(_) => ErrorClass::Initiate(code),
            ErrorClass::Conclude(_) => ErrorClass::Conclude(code),
            ErrorClass::Cancel(_) => ErrorClass::Cancel(code),
            ErrorClass::File(_) => ErrorClass::File(code),
            ErrorClass::Others(_) => ErrorClass::Others(code),
        }
    }

    /// Every subcode value, under every alternative, survives the round trip.
    #[test]
    fn error_class_round_trips_every_subcode() {
        for idx in 0u8..=12 {
            let pdu = confirmed_error(&[0x01], &[0xa0, 0x03, 0x80 | idx, 0x01, 0x00]);
            let (_, template) = decode_confirmed_error_pdu(&pdu).unwrap();
            for code in 0u8..=255 {
                let ec = with_code(&template.error_class, code);
                let mut buf = BytesMut::new();
                ec.encode_explicit(&mut buf);
                let (decoded, consumed) = ErrorClass::decode_explicit(&buf)
                    .unwrap_or_else(|e| panic!("{ec:?} failed to decode: {e}"));
                assert_eq!(decoded, ec);
                assert_eq!(consumed, buf.len());
            }
        }
    }

    /// A subcode from 128 up is encoded with a leading zero octet, so it does
    /// not read back as a negative INTEGER.
    #[test]
    fn error_class_encodes_a_high_subcode_as_a_non_negative_integer() {
        let mut buf = BytesMut::new();
        ErrorClass::Others(200).encode_explicit(&mut buf);
        assert_eq!(&buf[..], &[0xa0, 0x04, 0x8c, 0x02, 0x00, 0xc8]);
    }

    /// An additionalDescription of 128 bytes or more is written with a long
    /// form length and reads back whole.
    #[test]
    fn confirmed_error_round_trips_a_long_additional_description() {
        for n in [127usize, 128, 255, 256, 300] {
            let se = ServiceError::new(ErrorClass::Access(3))
                .with_additional_description("d".repeat(n))
                .with_additional_code(i32::MIN);
            let mut buf = BytesMut::new();
            encode_confirmed_error_pdu(7, &se, &mut buf);
            let (invoke_id, got) = decode_confirmed_error_pdu(&buf)
                .unwrap_or_else(|e| panic!("a {n}-byte description failed to decode: {e}"));
            assert_eq!(invoke_id, 7);
            assert_eq!(got, se, "n = {n}");
        }
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
