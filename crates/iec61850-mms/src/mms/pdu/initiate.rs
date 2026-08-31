//! InitiateRequest, InitiateResponse and InitiateError PDUs.
//!
//! ## BIT STRING encoding
//!
//! The first content byte of a BIT STRING is the number of unused bits, and the
//! data follows it.
//! - `parameterCBB` is 11 bits with 5 unused, so the content is `0x05 0xf1 0x00`,
//!   three bytes including the padding byte.
//! - `servicesSupported` is 85 bits with 3 unused, so the content is `0x03`
//!   followed by 11 data bytes, twelve bytes in all.
//!
//! A decoder that forgets to skip the padding byte shifts
//! the services bitmap by one byte. This implementation reads the padding byte
//! first and only then the data.
//!
//! Deliberate behaviors:
//!
//! - A `parameterCBB` whose length is not 3 returns
//!   `MmsError::InvalidParameterCbbLength` rather than being ignored.
//! - A `dataStructureNestingLevel` above `MAX_NESTING_LEVEL` returns an error
//!   rather than being accepted as proposed.

use super::super::error::MmsError;
use crate::compat::prelude::*;
use bytes::BytesMut;

// Protocol constants

/// Default maximum PDU size in bytes.
pub const DEFAULT_MAX_PDU_SIZE: u32 = 65000;

/// Default maximum number of outstanding requests the caller may issue.
pub const DEFAULT_MAX_SERV_OUTSTANDING_CALLING: u16 = 5;

/// Default maximum number of outstanding requests the called party may issue.
pub const DEFAULT_MAX_SERV_OUTSTANDING_CALLED: u16 = 5;

/// Default maximum data structure nesting level, the ISO 9506 default.
pub const DEFAULT_DATA_STRUCTURE_NESTING_LEVEL: u8 = 10;

/// Decode ceiling for dataStructureNestingLevel, which bounds nesting depth.
/// A proposed value above this is rejected rather than accepted.
pub const MAX_NESTING_LEVEL: u8 = 32;

/// MMS protocol version number, fixed at 1.
pub const MMS_VERSION_NUMBER: u8 = 1;

/// Default client parameterCBB, a BIT STRING including its padding byte.
/// Three bytes: padding 5 and data 0xf1 0x00, covering str1, str2, vnam, valt and vlis.
pub const DEFAULT_PARAMETER_CBB_CLIENT: [u8; 3] = [0x05, 0xf1, 0x00];

/// Default client servicesSupported: 85 bits carried in 11 data bytes.
pub const DEFAULT_SERVICES_SUPPORTED_CLIENT: [u8; 11] = [
    0xee, 0x1c, 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x79, 0xef, 0x18,
];

/// Padding for the servicesSupported BIT STRING: 8 * 11 - 85 = 3 unused bits.
const SERVICES_SUPPORTED_PADDING: u8 = 3;

// InitRequestDetail / InitResponseDetail

/// MMS `InitRequestDetail`, field 5 of `InitiateRequestPdu`, tag `[4]` SEQUENCE.
///
/// Wire format of the content; the enclosing `0xa4` is written by
/// `InitiateRequestPdu::encode`:
/// ```text
/// 0x80 0x01 0x01              -- proposedVersionNumber [0], fixed at 1
/// 0x81 0x03 0x05 0xf1 0x00    -- proposedParameterCBB [1] BIT STRING, 11 bits
/// 0x82 0x0c 0x03 <11 bytes>   -- servicesSupportedCalling [2] BIT STRING, 85 bits
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitRequestDetail {
    /// MMS version number, fixed at 1.
    pub proposed_version_number: u16,
    /// parameterCBB BIT STRING: 11 bits in three bytes, padding byte included.
    pub proposed_parameter_cbb: [u8; 3],
    /// servicesSupportedCalling BIT STRING: 85 bits in 11 data bytes.
    pub services_supported_calling: [u8; 11],
}

impl Default for InitRequestDetail {
    fn default() -> Self {
        Self {
            proposed_version_number: 1,
            proposed_parameter_cbb: DEFAULT_PARAMETER_CBB_CLIENT,
            services_supported_calling: DEFAULT_SERVICES_SUPPORTED_CLIENT,
        }
    }
}

impl InitRequestDetail {
    /// Encodes the content of an InitRequestDetail; the caller writes `0xa4 <len>`.
    pub fn encode_inner(&self, buf: &mut BytesMut) {
        // [0] proposedVersionNumber, always 0x80 0x01 0x01
        buf.extend_from_slice(&[0x80, 0x01, self.proposed_version_number as u8]);

        // [1] proposedParameterCBB, a BIT STRING of three bytes including padding
        buf.extend_from_slice(&[0x81, 0x03]);
        buf.extend_from_slice(&self.proposed_parameter_cbb);

        // [2] servicesSupportedCalling, a BIT STRING of 12 bytes: padding plus 11 data
        buf.extend_from_slice(&[0x82, 0x0c, SERVICES_SUPPORTED_PADDING]);
        buf.extend_from_slice(&self.services_supported_calling);
    }

    /// Decodes InitRequestDetail content; `data` is the content of the `0xa4` field.
    ///
    /// A parameterCBB whose length is not 3 returns an error rather than being ignored.
    pub fn decode_inner(data: &[u8]) -> Result<Self, MmsError> {
        let mut pos = 0usize;
        let mut version: u16 = 1;
        let mut param_cbb = DEFAULT_PARAMETER_CBB_CLIENT;
        let mut services = DEFAULT_SERVICES_SUPPORTED_CLIENT;

        while pos < data.len() {
            if pos + 2 > data.len() {
                return Err(MmsError::TruncatedPdu);
            }
            let tag = data[pos];
            pos += 1;
            let len = data[pos] as usize;
            pos += 1;
            if pos + len > data.len() {
                return Err(MmsError::TruncatedPdu);
            }
            let val = &data[pos..pos + len];
            pos += len;

            match tag {
                0x80 => {
                    // proposedVersionNumber [0]
                    if val.is_empty() {
                        return Err(MmsError::InvalidLength);
                    }
                    version = val[0] as u16;
                }
                0x81 => {
                    // proposedParameterCBB [1] BIT STRING, padding byte included.
                    // The length must be exactly 3.
                    if val.len() != 3 {
                        tracing::warn!(
                            "invalid parametercbb bit string length {}, expected 3",
                            val.len()
                        );
                        return Err(MmsError::InvalidParameterCbbLength { actual: val.len() });
                    }
                    param_cbb = [val[0], val[1], val[2]];
                }
                0x82 => {
                    // servicesSupportedCalling [2] BIT STRING: padding byte plus 11 data bytes
                    if val.len() != 12 {
                        return Err(MmsError::InvalidServicesSupportedLength { actual: val.len() });
                    }
                    // val[0] is the padding count, expected 3, and val[1..] the data.
                    // Skip the padding byte before reading the data.
                    services.copy_from_slice(&val[1..12]);
                }
                _ => {
                    // unknown tag: logged and skipped for forward compatibility
                    tracing::debug!("skipping unknown initrequestdetail tag 0x{:02X}", tag);
                }
            }
        }

        Ok(Self {
            proposed_version_number: version,
            proposed_parameter_cbb: param_cbb,
            services_supported_calling: services,
        })
    }
}

/// MMS `InitResponseDetail`, field 5 of `InitiateResponsePdu`, tag `[4]` SEQUENCE.
///
/// Structurally identical to `InitRequestDetail`; the fields carry the values the
/// responder negotiated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitResponseDetail {
    /// Negotiated version number: the proposed version, or the local minimum.
    pub negotiated_version_number: u16,
    /// negotiatedParameterCBB, the bitwise AND of both capability sets.
    pub negotiated_parameter_cbb: [u8; 3],
    /// servicesSupportedCalled, the services the responder announces.
    pub services_supported_called: [u8; 11],
}

impl Default for InitResponseDetail {
    fn default() -> Self {
        Self {
            negotiated_version_number: 1,
            negotiated_parameter_cbb: DEFAULT_PARAMETER_CBB_CLIENT,
            services_supported_called: DEFAULT_SERVICES_SUPPORTED_CLIENT,
        }
    }
}

impl InitResponseDetail {
    /// Encodes the content of an InitResponseDetail; the caller writes `0xa4 <len>`.
    pub fn encode_inner(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&[0x80, 0x01, self.negotiated_version_number as u8]);
        buf.extend_from_slice(&[0x81, 0x03]);
        buf.extend_from_slice(&self.negotiated_parameter_cbb);
        buf.extend_from_slice(&[0x82, 0x0c, SERVICES_SUPPORTED_PADDING]);
        buf.extend_from_slice(&self.services_supported_called);
    }

    /// Decodes InitResponseDetail content.
    ///
    /// A parameterCBB whose length is not 3 returns an error rather than being ignored.
    pub fn decode_inner(data: &[u8]) -> Result<Self, MmsError> {
        let mut pos = 0usize;
        let mut version: u16 = 1;
        let mut param_cbb = DEFAULT_PARAMETER_CBB_CLIENT;
        let mut services = DEFAULT_SERVICES_SUPPORTED_CLIENT;

        while pos < data.len() {
            if pos + 2 > data.len() {
                return Err(MmsError::TruncatedPdu);
            }
            let tag = data[pos];
            pos += 1;
            let len = data[pos] as usize;
            pos += 1;
            if pos + len > data.len() {
                return Err(MmsError::TruncatedPdu);
            }
            let val = &data[pos..pos + len];
            pos += len;

            match tag {
                0x80 => {
                    if val.is_empty() {
                        return Err(MmsError::InvalidLength);
                    }
                    version = val[0] as u16;
                }
                0x81 => {
                    if val.len() != 3 {
                        tracing::warn!(
                            "invalid negotiatedparametercbb bit string length {}, expected 3",
                            val.len()
                        );
                        return Err(MmsError::InvalidParameterCbbLength { actual: val.len() });
                    }
                    param_cbb = [val[0], val[1], val[2]];
                }
                0x82 => {
                    if val.len() != 12 {
                        return Err(MmsError::InvalidServicesSupportedLength { actual: val.len() });
                    }
                    // Skip the padding byte before reading the data
                    services.copy_from_slice(&val[1..12]);
                }
                _ => {
                    tracing::debug!("skipping unknown initresponsedetail tag 0x{:02X}", tag);
                }
            }
        }

        Ok(Self {
            negotiated_version_number: version,
            negotiated_parameter_cbb: param_cbb,
            services_supported_called: services,
        })
    }
}

// InitiateRequestPdu

/// MMS `InitiateRequestPdu`, MmsPdu `[8]`, tag `0xa8`.
///
/// The encoder always writes every optional field, so `local_detail_calling` and
/// `proposed_data_structure_nesting_level` are normally present in what it produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiateRequestPdu {
    /// `[0]` localDetailCalling, OPTIONAL: the largest PDU the caller accepts, in bytes.
    pub local_detail_calling: Option<u32>,
    /// `[1]` proposedMaxServOutstandingCalling: outstanding requests the caller may issue.
    pub proposed_max_serv_outstanding_calling: u16,
    /// `[2]` proposedMaxServOutstandingCalled: outstanding requests the peer may issue.
    pub proposed_max_serv_outstanding_called: u16,
    /// `[3]` proposedDataStructureNestingLevel, OPTIONAL: the maximum nesting depth.
    pub proposed_data_structure_nesting_level: Option<u8>,
    /// `[4]` mmsInitRequestDetail: version number and announced capabilities.
    pub init_request_detail: InitRequestDetail,
}

impl Default for InitiateRequestPdu {
    fn default() -> Self {
        Self {
            local_detail_calling: Some(DEFAULT_MAX_PDU_SIZE),
            proposed_max_serv_outstanding_calling: DEFAULT_MAX_SERV_OUTSTANDING_CALLING,
            proposed_max_serv_outstanding_called: DEFAULT_MAX_SERV_OUTSTANDING_CALLED,
            proposed_data_structure_nesting_level: Some(DEFAULT_DATA_STRUCTURE_NESTING_LEVEL),
            init_request_detail: InitRequestDetail::default(),
        }
    }
}

impl InitiateRequestPdu {
    /// Encodes the PDU as BER, including the outer `0xa8 <len>` tag.
    pub fn encode(&self, buf: &mut BytesMut) {
        // build the content first, then prefix the outer tag and length
        let mut inner = BytesMut::new();
        self.encode_inner(&mut inner);

        // outer tag 0xa8, CONTEXT [8] CONSTRUCTED
        buf.extend_from_slice(&[0xa8]);
        encode_length(inner.len(), buf);
        buf.extend_from_slice(&inner);
    }

    fn encode_inner(&self, buf: &mut BytesMut) {
        // [0] localDetailCalling, OPTIONAL
        if let Some(pdu_size) = self.local_detail_calling {
            let bytes = encode_uint32_minimal(pdu_size);
            buf.extend_from_slice(&[0x80, bytes.len() as u8]);
            buf.extend_from_slice(&bytes);
        }

        // [1] proposedMaxServOutstandingCalling
        let b1 = encode_uint16_minimal(self.proposed_max_serv_outstanding_calling);
        buf.extend_from_slice(&[0x81, b1.len() as u8]);
        buf.extend_from_slice(&b1);

        // [2] proposedMaxServOutstandingCalled
        let b2 = encode_uint16_minimal(self.proposed_max_serv_outstanding_called);
        buf.extend_from_slice(&[0x82, b2.len() as u8]);
        buf.extend_from_slice(&b2);

        // [3] proposedDataStructureNestingLevel, OPTIONAL
        if let Some(level) = self.proposed_data_structure_nesting_level {
            buf.extend_from_slice(&[0x83, 0x01, level]);
        }

        // [4] mmsInitRequestDetail, a SEQUENCE under CONTEXT [4] CONSTRUCTED (0xa4)
        let mut detail_inner = BytesMut::new();
        self.init_request_detail.encode_inner(&mut detail_inner);
        buf.extend_from_slice(&[0xa4]);
        encode_length(detail_inner.len(), buf);
        buf.extend_from_slice(&detail_inner);
    }

    /// Decodes the PDU; `data` starts at the `0xa8` byte.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        if data[0] != 0xa8 {
            return Err(MmsError::InvalidTag {
                expected: 0xa8,
                actual: data[0],
            });
        }
        let (inner_len, hdr_size) = decode_length(&data[1..])?;
        let inner_start = 1 + hdr_size;
        if inner_start + inner_len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let inner = &data[inner_start..inner_start + inner_len];
        decode_initiate_request_inner(inner)
    }
}

fn decode_initiate_request_inner(data: &[u8]) -> Result<InitiateRequestPdu, MmsError> {
    let mut pos = 0usize;
    let mut local_detail: Option<u32> = None;
    let mut calling_outstanding: Option<u16> = None;
    let mut called_outstanding: Option<u16> = None;
    let mut nesting_level: Option<u8> = None;
    let mut detail: Option<InitRequestDetail> = None;

    while pos < data.len() {
        if pos + 2 > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let tag = data[pos];
        pos += 1;
        let (len, hdr) = decode_length(&data[pos..])?;
        pos += hdr;
        if pos + len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let val = &data[pos..pos + len];
        pos += len;

        match tag {
            0x80 => {
                // localDetailCalling [0] INTEGER
                local_detail = Some(decode_uint(val)?);
            }
            0x81 => {
                // proposedMaxServOutstandingCalling [1] INTEGER
                calling_outstanding = Some(decode_uint(val)? as u16);
            }
            0x82 => {
                // proposedMaxServOutstandingCalled [2] INTEGER
                called_outstanding = Some(decode_uint(val)? as u16);
            }
            0x83 => {
                // proposedDataStructureNestingLevel [3] INTEGER
                if val.is_empty() {
                    return Err(MmsError::InvalidLength);
                }
                let level = val[0];
                // a level above MAX_NESTING_LEVEL is rejected
                if level > MAX_NESTING_LEVEL {
                    tracing::warn!(
                        "datastructurenestinglevel {} exceeds the limit of {}",
                        level,
                        MAX_NESTING_LEVEL
                    );
                    return Err(MmsError::NestingLevelExceeded {
                        max: MAX_NESTING_LEVEL,
                        got: level,
                    });
                }
                nesting_level = Some(level);
            }
            0xa4 => {
                // mmsInitRequestDetail [4] SEQUENCE, CONSTRUCTED
                detail = Some(InitRequestDetail::decode_inner(val)?);
            }
            _ => {
                tracing::debug!("skipping unknown initiaterequestpdu tag 0x{:02X}", tag);
            }
        }
    }

    // mandatory fields
    let proposed_max_serv_outstanding_calling =
        calling_outstanding.ok_or(MmsError::TruncatedPdu)?;
    let proposed_max_serv_outstanding_called = called_outstanding.ok_or(MmsError::TruncatedPdu)?;
    let init_request_detail = detail.ok_or(MmsError::TruncatedPdu)?;

    Ok(InitiateRequestPdu {
        local_detail_calling: local_detail,
        proposed_max_serv_outstanding_calling,
        proposed_max_serv_outstanding_called,
        proposed_data_structure_nesting_level: nesting_level,
        init_request_detail,
    })
}

// InitiateResponsePdu

/// MMS `InitiateResponsePdu`, MmsPdu `[9]`, tag `0xa9`.
///
/// Structurally identical to the request; the fields carry the negotiated values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiateResponsePdu {
    /// `[0]` localDetailCalled, OPTIONAL: the largest PDU the responder accepts.
    pub local_detail_called: Option<u32>,
    /// `[1]` negotiatedMaxServOutstandingCalling.
    pub negotiated_max_serv_outstanding_calling: u16,
    /// `[2]` negotiatedMaxServOutstandingCalled.
    pub negotiated_max_serv_outstanding_called: u16,
    /// `[3]` negotiatedDataStructureNestingLevel, OPTIONAL.
    pub negotiated_data_structure_nesting_level: Option<u8>,
    /// `[4]` mmsInitResponseDetail.
    pub init_response_detail: InitResponseDetail,
}

impl Default for InitiateResponsePdu {
    fn default() -> Self {
        Self {
            local_detail_called: Some(DEFAULT_MAX_PDU_SIZE),
            negotiated_max_serv_outstanding_calling: DEFAULT_MAX_SERV_OUTSTANDING_CALLING,
            negotiated_max_serv_outstanding_called: DEFAULT_MAX_SERV_OUTSTANDING_CALLED,
            negotiated_data_structure_nesting_level: Some(DEFAULT_DATA_STRUCTURE_NESTING_LEVEL),
            init_response_detail: InitResponseDetail::default(),
        }
    }
}

impl InitiateResponsePdu {
    /// Encodes the PDU, including the outer `0xa9 <len>` tag.
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut inner = BytesMut::new();
        self.encode_inner(&mut inner);
        buf.extend_from_slice(&[0xa9]);
        encode_length(inner.len(), buf);
        buf.extend_from_slice(&inner);
    }

    fn encode_inner(&self, buf: &mut BytesMut) {
        if let Some(pdu_size) = self.local_detail_called {
            let bytes = encode_uint32_minimal(pdu_size);
            buf.extend_from_slice(&[0x80, bytes.len() as u8]);
            buf.extend_from_slice(&bytes);
        }

        let b1 = encode_uint16_minimal(self.negotiated_max_serv_outstanding_calling);
        buf.extend_from_slice(&[0x81, b1.len() as u8]);
        buf.extend_from_slice(&b1);

        let b2 = encode_uint16_minimal(self.negotiated_max_serv_outstanding_called);
        buf.extend_from_slice(&[0x82, b2.len() as u8]);
        buf.extend_from_slice(&b2);

        if let Some(level) = self.negotiated_data_structure_nesting_level {
            buf.extend_from_slice(&[0x83, 0x01, level]);
        }

        let mut detail_inner = BytesMut::new();
        self.init_response_detail.encode_inner(&mut detail_inner);
        buf.extend_from_slice(&[0xa4]);
        encode_length(detail_inner.len(), buf);
        buf.extend_from_slice(&detail_inner);
    }

    /// Decodes the PDU; `data` starts at the `0xa9` byte.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        if data[0] != 0xa9 {
            return Err(MmsError::InvalidTag {
                expected: 0xa9,
                actual: data[0],
            });
        }
        let (inner_len, hdr_size) = decode_length(&data[1..])?;
        let inner_start = 1 + hdr_size;
        if inner_start + inner_len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let inner = &data[inner_start..inner_start + inner_len];
        decode_initiate_response_inner(inner)
    }
}

fn decode_initiate_response_inner(data: &[u8]) -> Result<InitiateResponsePdu, MmsError> {
    let mut pos = 0usize;
    let mut local_detail: Option<u32> = None;
    let mut calling_outstanding: Option<u16> = None;
    let mut called_outstanding: Option<u16> = None;
    let mut nesting_level: Option<u8> = None;
    let mut detail: Option<InitResponseDetail> = None;

    while pos < data.len() {
        if pos + 2 > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let tag = data[pos];
        pos += 1;
        let (len, hdr) = decode_length(&data[pos..])?;
        pos += hdr;
        if pos + len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let val = &data[pos..pos + len];
        pos += len;

        match tag {
            0x80 => {
                local_detail = Some(decode_uint(val)?);
            }
            0x81 => {
                calling_outstanding = Some(decode_uint(val)? as u16);
            }
            0x82 => {
                called_outstanding = Some(decode_uint(val)? as u16);
            }
            0x83 => {
                if val.is_empty() {
                    return Err(MmsError::InvalidLength);
                }
                let level = val[0];
                if level > MAX_NESTING_LEVEL {
                    tracing::warn!(
                        "negotiateddatastructurenestinglevel {} exceeds the limit of {}",
                        level,
                        MAX_NESTING_LEVEL
                    );
                    return Err(MmsError::NestingLevelExceeded {
                        max: MAX_NESTING_LEVEL,
                        got: level,
                    });
                }
                nesting_level = Some(level);
            }
            0xa4 => {
                detail = Some(InitResponseDetail::decode_inner(val)?);
            }
            _ => {
                tracing::debug!("skipping unknown initiateresponsepdu tag 0x{:02X}", tag);
            }
        }
    }

    let negotiated_max_serv_outstanding_calling =
        calling_outstanding.ok_or(MmsError::TruncatedPdu)?;
    let negotiated_max_serv_outstanding_called =
        called_outstanding.ok_or(MmsError::TruncatedPdu)?;
    let init_response_detail = detail.ok_or(MmsError::TruncatedPdu)?;

    Ok(InitiateResponsePdu {
        local_detail_called: local_detail,
        negotiated_max_serv_outstanding_calling,
        negotiated_max_serv_outstanding_called,
        negotiated_data_structure_nesting_level: nesting_level,
        init_response_detail,
    })
}

// InitiateErrorPdu

/// MMS `InitiateErrorPdu`, MmsPdu `[10]`, tag `0xaa`.
///
/// The body is a `ServiceError` whose errorClass is initiate; the subcode is
/// normally 0, meaning other.
///
/// Wire format, outer `0xaa` included:
/// ```text
/// 0xaa 0x05          -- MmsPdu [10]
///   0xa0 0x03        -- errorClass [0] EXPLICIT
///     0x88 0x01 0x00 -- initiate [8] = 0, other
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiateErrorPdu {
    /// ServiceError carried as the body of the PDU.
    pub service_error: super::service_error::ServiceError,
}

impl InitiateErrorPdu {
    /// Builds an InitiateErrorPdu with errorClass initiate and subcode `code`.
    ///
    /// Callers currently pass 0, meaning other.
    pub fn new(code: u8) -> Self {
        use super::service_error::{ErrorClass, ServiceError};
        Self {
            service_error: ServiceError::new(ErrorClass::Initiate(code)),
        }
    }

    /// Encodes the PDU, including the outer `0xaa <len>` tag.
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut inner = BytesMut::new();
        self.service_error.encode_inner(&mut inner);
        buf.extend_from_slice(&[0xaa]);
        encode_length(inner.len(), buf);
        buf.extend_from_slice(&inner);
    }

    /// Decodes the PDU; `data` starts at the `0xaa` byte.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        if data.is_empty() {
            return Err(MmsError::TruncatedPdu);
        }
        if data[0] != 0xaa {
            return Err(MmsError::InvalidTag {
                expected: 0xaa,
                actual: data[0],
            });
        }
        let (inner_len, hdr_size) = decode_length(&data[1..])?;
        let inner_start = 1 + hdr_size;
        if inner_start + inner_len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let inner = &data[inner_start..inner_start + inner_len];
        let service_error = super::service_error::ServiceError::decode_inner(inner)?;
        Ok(Self { service_error })
    }
}

// BER helpers, re-exported from `iec61850-asn1`

/// BER definite-length encoding, re-exported from `iec61850_asn1::encode_length`.
///
/// The re-export keeps the `super::initiate::{encode_length, decode_length}` import
/// path available to the other PDU modules.
pub(super) use iec61850_asn1::encode_length;

/// BER definite-length decoding, re-exported from `iec61850_asn1::decode_length`.
///
/// Returns `Result<(usize, usize), Asn1Error>`; callers convert with `?` through
/// `From<Asn1Error> for MmsError`.
pub(super) use iec61850_asn1::decode_length;

/// Encodes a `u32` as a minimal-length big-endian BER INTEGER.
///
/// BER INTEGER is signed, so a leading 0x00 is prepended when the most significant
/// byte has its top bit set, keeping the value positive. For example 65000 is
/// 0x0000FDE8 and encodes as the three bytes `0x00 0xFD 0xE8`.
fn encode_uint32_minimal(val: u32) -> Vec<u8> {
    if val == 0 {
        return vec![0x00];
    }
    // five bytes: a 0x00 prefix plus four big-endian bytes, keeping the value positive
    let mut buf = [0u8; 5];
    buf[1..].copy_from_slice(&val.to_be_bytes());
    // drop leading 0x00 bytes, but only while the next byte keeps its top bit clear
    let mut start = 0usize;
    while start < 4 {
        if buf[start] == 0x00 && (buf[start + 1] & 0x80) == 0 {
            start += 1;
        } else {
            break;
        }
    }
    buf[start..].to_vec()
}

/// Encodes a `u16` as a minimal-length big-endian BER INTEGER.
///
/// A leading 0x00 is prepended when the top bit of the leading byte is set.
fn encode_uint16_minimal(val: u16) -> Vec<u8> {
    if val == 0 {
        return vec![0x00];
    }
    let bytes = val.to_be_bytes();
    if bytes[0] == 0x00 && (bytes[1] & 0x80) == 0 {
        // the leading 0x00 can be dropped
        vec![bytes[1]]
    } else if bytes[0] == 0x00 {
        // the top bit of bytes[1] is set, so the leading 0x00 must stay
        vec![bytes[0], bytes[1]]
    } else {
        vec![bytes[0], bytes[1]]
    }
}

/// Decodes a big-endian BER INTEGER into a `u32`.
///
/// BER INTEGER is signed, so a positive value whose leading byte has the top bit
/// set carries a `0x00` prefix, as `encode_uint32_minimal` writes. A legal u32
/// encoding therefore reaches five bytes for the range `0x80000000..=0xFFFFFFFF`.
///
/// Lengths 1 to 4 are accepted, as is 5 when the first byte is `0x00`; any other
/// length returns `InvalidLength`.
///
/// Accepting the five-byte form keeps `decode(encode(x))` equal to `x`, which a
/// four-byte-only decoder breaks for values with the top bit set, such as
/// `0xec810200`.
fn decode_uint(data: &[u8]) -> Result<u32, MmsError> {
    let bytes = match data.len() {
        0 => return Err(MmsError::InvalidLength),
        1..=4 => data,
        5 if data[0] == 0x00 => &data[1..],
        _ => return Err(MmsError::InvalidLength),
    };
    let mut val = 0u32;
    for &b in bytes {
        val = (val << 8) | (b as u32);
    }
    Ok(val)
}

// Unit tests

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)] // readability first; one reassignment stays clear
mod tests {
    use super::*;

    // InitiateRequestPdu

    #[test]
    fn initiate_request_encode_decode_roundtrip() {
        let req = InitiateRequestPdu::default();
        let mut buf = BytesMut::new();
        req.encode(&mut buf);

        // the outer tag
        assert_eq!(buf[0], 0xa8);

        let decoded = InitiateRequestPdu::decode(&buf).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn initiate_request_encode_has_version_one() {
        let req = InitiateRequestPdu::default();
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let bytes = &buf[..];
        // locate proposedVersionNumber, 0x80 0x01 0x01
        let has_version = bytes.windows(3).any(|w| w == [0x80, 0x01, 0x01]);
        assert!(has_version, "proposedVersionNumber 1 must be present");
    }

    #[test]
    fn initiate_request_services_supported_correct() {
        // ServicesSupported must survive an encode and decode unchanged
        let req = InitiateRequestPdu::default();
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let decoded = InitiateRequestPdu::decode(&buf).unwrap();
        assert_eq!(
            decoded.init_request_detail.services_supported_calling,
            DEFAULT_SERVICES_SUPPORTED_CLIENT,
            "servicesSupported must not be shifted"
        );
    }

    #[test]
    fn initiate_request_parameter_cbb_correct() {
        let req = InitiateRequestPdu::default();
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let decoded = InitiateRequestPdu::decode(&buf).unwrap();
        assert_eq!(
            decoded.init_request_detail.proposed_parameter_cbb,
            DEFAULT_PARAMETER_CBB_CLIENT
        );
    }

    // InitiateResponsePdu

    #[test]
    fn initiate_response_encode_decode_roundtrip() {
        let resp = InitiateResponsePdu::default();
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        assert_eq!(buf[0], 0xa9);
        let decoded = InitiateResponsePdu::decode(&buf).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn initiate_response_custom_pdu_size() {
        let mut resp = InitiateResponsePdu::default();
        resp.local_detail_called = Some(4096);
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        let decoded = InitiateResponsePdu::decode(&buf).unwrap();
        assert_eq!(decoded.local_detail_called, Some(4096));
    }

    // InitiateErrorPdu

    #[test]
    fn initiate_error_encode_exact() {
        // byte exact: 0xaa 0x05 0xa0 0x03 0x88 0x01 0x00
        let err_pdu = InitiateErrorPdu::new(0);
        let mut buf = BytesMut::new();
        err_pdu.encode(&mut buf);
        assert_eq!(
            &buf[..],
            &[0xaa, 0x05, 0xa0, 0x03, 0x88, 0x01, 0x00],
            "InitiateErrorPdu encoding is not byte exact"
        );
    }

    #[test]
    fn initiate_error_decode_roundtrip() {
        let err_pdu = InitiateErrorPdu::new(2);
        let mut buf = BytesMut::new();
        err_pdu.encode(&mut buf);
        let decoded = InitiateErrorPdu::decode(&buf).unwrap();
        assert_eq!(decoded, err_pdu);
    }

    // Rejection of out-of-range fields

    #[test]
    fn parameter_cbb_wrong_length_returns_err() {
        // build a parameterCBB with the illegal length 2 by encoding a valid PDU and
        // patching the length byte of its parameterCBB TLV
        //       0x83 0x01 0x0a 0xa4 <len> 0x80 0x01 0x01 0x81 0x02 0x05 0xf1 0x82 ...
        let req = InitiateRequestPdu::default();
        let mut buf = BytesMut::new();
        req.encode(&mut buf);

        // find 0x81 0x03, the parameterCBB tag and length, and set the length to 2
        let bytes = buf.as_mut();
        let mut found = false;
        for i in 0..bytes.len().saturating_sub(1) {
            if bytes[i] == 0x81 && bytes[i + 1] == 0x03 {
                bytes[i + 1] = 0x02; // illegal length 2
                found = true;
                break;
            }
        }
        assert!(found, "the parameterCBB TLV to mutate was not found");

        let result = InitiateRequestPdu::decode(bytes);
        assert!(
            matches!(result, Err(MmsError::InvalidParameterCbbLength { .. })),
            "a parameterCBB length other than 3 must return InvalidParameterCbbLength"
        );
    }

    #[test]
    fn nesting_level_exceeded_returns_err() {
        // build a nesting level of 255, above MAX_NESTING_LEVEL of 32
        let req = InitiateRequestPdu::default();
        let mut buf = BytesMut::new();
        req.encode(&mut buf);

        // find 0x83 0x01 <level> and set the level to 255
        let bytes = buf.as_mut();
        let mut found = false;
        for i in 0..bytes.len().saturating_sub(2) {
            if bytes[i] == 0x83 && bytes[i + 1] == 0x01 {
                bytes[i + 2] = 255;
                found = true;
                break;
            }
        }
        assert!(found, "the nesting level TLV was not found");

        let result = InitiateRequestPdu::decode(bytes);
        assert!(
            matches!(result, Err(MmsError::NestingLevelExceeded { .. })),
            "a nesting level of 255 must return NestingLevelExceeded"
        );
    }

    #[test]
    fn bit_string_padding_skipped() {
        // BIT STRING decoding must skip the padding byte: build an InitResponseDetail
        // carrying servicesSupported and check the decoded service list
        let detail = InitResponseDetail {
            negotiated_version_number: 1,
            negotiated_parameter_cbb: DEFAULT_PARAMETER_CBB_CLIENT,
            services_supported_called: DEFAULT_SERVICES_SUPPORTED_CLIENT,
        };
        let mut buf = BytesMut::new();
        detail.encode_inner(&mut buf);

        let decoded = InitResponseDetail::decode_inner(&buf).unwrap();
        assert_eq!(
            decoded.services_supported_called, DEFAULT_SERVICES_SUPPORTED_CLIENT,
            "servicesSupported must not be shifted by the padding byte"
        );
        // the top bits of the first byte, service 0 status onwards, must be intact
        // DEFAULT_SERVICES_SUPPORTED_CLIENT[0] = 0xee = 0b11101110
        // 0xee is 0b11101110: bit 7 is status, bit 6 getNameList, and so on
        assert_eq!(decoded.services_supported_called[0], 0xee);
    }

    #[test]
    fn bit_string_padding_boundary_large_length() {
        // an oversized length must not panic
        let malformed: &[u8] = &[
            0xa8, 0x82, 0xff,
            0xff, // outer tag plus a long-form length of 65535 with far less data present
        ];
        let result = InitiateRequestPdu::decode(malformed);
        assert!(
            result.is_err(),
            "an oversized length must return an error, not panic"
        );
    }

    // decode_uint accepts the five-byte signed form

    #[test]
    fn decode_uint_accepts_5_byte_with_leading_zero() {
        // 0xff_00_00_00 has its top bit set, so the positive BER form takes five bytes
        assert_eq!(
            decode_uint(&[0x00, 0xff, 0x00, 0x00, 0x00]).unwrap(),
            0xff00_0000
        );
        // u32::MAX also uses the five-byte form
        assert_eq!(
            decode_uint(&[0x00, 0xff, 0xff, 0xff, 0xff]).unwrap(),
            u32::MAX
        );
        // the four-byte form stays legal when the top bit is clear
        assert_eq!(decode_uint(&[0x7f, 0xff, 0xff, 0xff]).unwrap(), 0x7fff_ffff);
        // a four-byte value with the top bit set is still accepted and read as unsigned
        assert_eq!(decode_uint(&[0xec, 0x81, 0x02, 0x00]).unwrap(), 0xec81_0200);
    }

    #[test]
    fn decode_uint_rejects_5_byte_without_leading_zero() {
        // five bytes whose first byte is not 0x00 are rejected: the value would not fit
        assert!(matches!(
            decode_uint(&[0x01, 0x00, 0x00, 0x00, 0x00]),
            Err(MmsError::InvalidLength)
        ));
        // six or more bytes are always rejected
        assert!(matches!(
            decode_uint(&[0x00, 0x00, 0xff, 0xff, 0xff, 0xff]),
            Err(MmsError::InvalidLength)
        ));
        assert!(matches!(decode_uint(&[]), Err(MmsError::InvalidLength)));
    }

    #[test]
    fn decode_uint_roundtrip_with_high_bit_value() {
        // encode_uint32_minimal produces five bytes for a u32 with the top bit set,
        // and decode_uint must accept them
        for val in [0x8000_0000u32, 0xff00_0000, 0xec81_0200, u32::MAX] {
            let encoded = encode_uint32_minimal(val);
            assert_eq!(
                decode_uint(&encoded).unwrap(),
                val,
                "encode and decode are not idempotent for val=0x{:08x}",
                val
            );
        }
    }

    #[test]
    fn initiate_response_roundtrip_with_high_bit_local_detail() {
        // minimized regression input: local_detail_called = 0xec81_0200, whose top bit
        // is set, with every other field at its smallest legal value
        let pdu = InitiateResponsePdu {
            local_detail_called: Some(0xec81_0200),
            negotiated_max_serv_outstanding_calling: 1,
            negotiated_max_serv_outstanding_called: 1,
            negotiated_data_structure_nesting_level: Some(0),
            init_response_detail: InitResponseDetail::default(),
        };
        let mut buf = BytesMut::new();
        pdu.encode(&mut buf);
        // encoding then decoding must reproduce the value
        let decoded = InitiateResponsePdu::decode(&buf).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn fuzz_artifact_initiate_response_roundtrip() {
        // A 57-byte input that once decoded but failed to round trip.
        // Decoding must succeed and encoding the result must decode back to it.
        use crate::mms::MmsPdu;
        let data: &[u8] = &[
            0xa9, 0x2d, 0x81, 0x02, 0x00, 0x06, 0x0d, 0x81, 0x02, 0xa4, 0x06, 0x82, 0x01, 0x05,
            0x00, 0x00, 0x32, 0x04, 0xa9, 0x00, 0x02, 0x1b, 0x83, 0x02, 0x00, 0x06, 0xa4, 0x06,
            0xc0, 0x01, 0x11, 0x89, 0x01, 0x29, 0x80, 0x04, 0xec, 0x81, 0x02, 0x00, 0x06, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa4, 0x06, 0x80, 0x01, 0x11, 0x89, 0x01,
            0x11, 0x01,
        ];
        let pdu = MmsPdu::decode(data).expect("the artifact must decode");
        let mut buf = BytesMut::new();
        pdu.encode(&mut buf);
        let redecoded = MmsPdu::decode(&buf).expect("encode then decode must be idempotent");
        assert_eq!(pdu, redecoded);
    }
}
