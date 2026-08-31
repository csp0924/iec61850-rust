//! ACSE, the Association Control Service Element, per ISO 8650 and ITU-T X.227.
//!
//! Encodes and decodes the five PDUs AARQ, AARE, RLRQ, RLRE and ABRT, carries the
//! MMS application-context-name OID (1.0.9506.2.3), supports the no-auth and
//! password mechanisms, and returns the user-information payload as a slice
//! borrowed from the input buffer.
//!
//! Robustness cases covered:
//! - A PDU shorter than a tag plus one length byte is rejected.
//! - An AARQ TLV whose length runs past the buffer is rejected without
//!   reading past the end.
//! - The same guard applies to every TLV inside an AARE.
//!
//! Deliberate behaviors:
//! - A non-MMS application-context-name is logged and accepted, not rejected.
//! - The association-reject encoder omits user-information, which ISO 8650 makes
//!   optional, so no empty payload is emitted.
//! - calling-AE-qualifier is decoded from the INTEGER in its field content.
//! - Fields are appended straight to a `BytesMut`, with no intermediate buffer chain.

use crate::compat::prelude::*;
use bytes::BytesMut;
use tracing::warn;

// Error types

/// Errors raised by the ACSE layer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AcseError {
    /// The PDU is shorter than a tag plus one length byte.
    #[error("acse pdu too short (len={len}, at least 2 bytes required)")]
    TooShort {
        /// Length of the PDU received.
        len: usize,
    },

    /// A BER length runs past the buffer.
    #[error("ber length {claimed} exceeds the {remaining} bytes remaining in the buffer")]
    OobRead {
        /// Length the BER field declared.
        claimed: usize,
        /// Bytes remaining in the buffer.
        remaining: usize,
    },

    /// The PDU tag is not one of the five ACSE types.
    #[error("unknown acse pdu tag 0x{tag:02X}")]
    UnknownPduType {
        /// PDU tag received.
        tag: u8,
    },

    /// An AARQ or AARE carries no user-information (0xbe).
    #[error("acse pdu is missing user-information (0xbe)")]
    NoUserData,

    /// The BER length field is malformed.
    #[error("malformed ber length field")]
    MalformedLength,

    /// The authenticator rejected the association.
    #[error("acse authentication failed")]
    AuthFailed,
}

// Constants

/// MMS application-context-name OID 1.0.9506.2.3, as BER content octets.
/// Listed in IEC 61850-8-1 Table A.1.
const APP_CONTEXT_NAME_MMS: [u8; 5] = [0x28, 0xca, 0x22, 0x02, 0x03];

/// Password mechanism OID 2.16.840.1.101.2.1.22.3, as BER content octets.
const AUTH_MECH_PASSWORD_OID: [u8; 3] = [0x52, 0x03, 0x01];

/// sender-ACSE-requirements BIT STRING value; bit 0 signals authentication.
const REQUIREMENTS_AUTHENTICATION: [u8; 1] = [0x80];

// Data structures

/// ACSE association state.
///
/// This module never advances the state; the caller owns every transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AcseConnectionState {
    #[default]
    /// No association has been requested yet.
    Idle = 0,
    /// An AARQ has been received and is awaiting a response.
    RequestIndicated = 1,
    /// The association is established.
    Connected = 2,
}

/// Outcome of parsing an ACSE PDU.
///
/// Returned by [`AcseConnection::parse_message`] on success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcseIndication {
    /// An AARQ that parsed and authenticated, or an AARE with result 0.
    Associate,
    /// An AARQ that failed authentication, or an AARE with a non-zero result.
    AssociateFailed,
    /// An RLRQ, tag 0x62.
    ReleaseRequest,
    /// An RLRE, tag 0x63.
    ReleaseResponse,
    /// An ABRT, tag 0x64.
    Abort,
}

/// ACSE authentication credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcseAuth {
    /// No authentication; the mechanism fields are absent.
    None,
    /// Password authentication in the charstring form.
    Password(Vec<u8>),
    /// TLS certificate authentication. Unimplemented placeholder: no
    /// mechanism-name OID is emitted, so on the wire an association carrying this
    /// variant is indistinguishable from `AcseAuth::None`, and the certificate is
    /// only checked by the TLS handshake itself.
    // TODO: emit the certificate mechanism-name OID so a peer can tell the two apart.
    TlsCertificate(Vec<u8>),
}

/// Application reference taken from calling-AP-title and calling-AE-qualifier.
#[derive(Debug, Clone, Default)]
pub struct IsoApplicationReference {
    /// calling-AP-title OID bytes, from AARQ tag 0xa6.
    pub ap_title: Vec<u8>,
    /// calling-AE-qualifier integer value, from AARQ tag 0xa7.
    pub ae_qualifier: i32,
}

/// ACSE association state and configuration.
///
/// The user-information payload is not stored here: `parse_message` returns it as
/// a slice borrowed from the input buffer, which keeps this type free of borrows.
pub struct AcseConnection {
    /// Association state, advanced by the caller.
    pub state: AcseConnectionState,
    /// indirect-reference value; MMS uses 3, and an AARE echoes it back.
    pub next_reference: u32,
    /// Application reference decoded from the AARQ.
    pub application_reference: IsoApplicationReference,
    /// Authentication callback; `None` accepts every association.
    authenticator: Option<Box<dyn AcseAuthenticator>>,
}

/// Callback that decides whether an association is accepted.
///
/// Supplied by the caller; returning true accepts the association.
pub trait AcseAuthenticator: Send {
    /// Returns whether the association carrying these credentials is accepted.
    fn authenticate(&self, auth: &AcseAuth, app_ref: &IsoApplicationReference) -> bool;
}

impl AcseConnection {
    /// Creates a connection with the given authenticator.
    pub fn new(authenticator: Option<Box<dyn AcseAuthenticator>>) -> Self {
        Self {
            state: AcseConnectionState::Idle,
            next_reference: 0,
            application_reference: IsoApplicationReference::default(),
            authenticator,
        }
    }

    /// Parses any ACSE PDU and dispatches on AARQ, AARE, RLRQ, RLRE or ABRT.
    ///
    /// On success returns the indication together with the user-information payload,
    /// borrowed from `buf`.
    ///
    /// For RLRQ, RLRE and ABRT the payload slice is empty.
    ///
    /// # Errors
    ///
    /// - `TooShort` when `buf` is shorter than 2 bytes.
    /// - `OobRead`, `MalformedLength` or `UnknownPduType` for a malformed PDU.
    pub fn parse_message<'buf>(
        &mut self,
        buf: &'buf [u8],
    ) -> Result<(AcseIndication, &'buf [u8]), AcseError> {
        // A tag byte plus at least one length byte are required
        if buf.len() < 2 {
            warn!(len = buf.len(), "acse pdu too short, rejecting");
            return Err(AcseError::TooShort { len: buf.len() });
        }

        let tag = buf[0];
        match tag {
            0x60 => {
                // AARQ
                let user_data = self.parse_aarq(buf)?;
                let (passed, auth_type) = self.check_authentication();
                if !passed {
                    warn!(
                        mechanism = ?auth_type,
                        "acse aarq authentication failed, rejecting association"
                    );
                    return Ok((AcseIndication::AssociateFailed, &[]));
                }
                Ok((AcseIndication::Associate, user_data))
            }
            0x61 => {
                // AARE
                let (result, user_data) = self.parse_aare(buf)?;
                if result == 0 {
                    Ok((AcseIndication::Associate, user_data))
                } else {
                    Ok((AcseIndication::AssociateFailed, user_data))
                }
            }
            0x62 => {
                // RLRQ: only the tag is examined
                Ok((AcseIndication::ReleaseRequest, &[]))
            }
            0x63 => {
                // RLRE: only the tag is examined
                Ok((AcseIndication::ReleaseResponse, &[]))
            }
            0x64 => {
                // ABRT: only the tag is examined
                Ok((AcseIndication::Abort, &[]))
            }
            other => {
                warn!(
                    tag = format!("0x{:02X}", other),
                    "received unknown acse pdu tag, rejecting"
                );
                Err(AcseError::UnknownPduType { tag: other })
            }
        }
    }

    /// Checks the association against the authenticator.
    ///
    /// Returns whether the association is accepted, together with the credentials used.
    ///
    /// - Without an authenticator every association is accepted.
    /// - With one it is called with `AcseAuth::None`, since an AARQ without
    ///   authentication fields carries no credentials.
    fn check_authentication(&self) -> (bool, AcseAuth) {
        match &self.authenticator {
            None => (true, AcseAuth::None),
            Some(auth_fn) => {
                let auth = AcseAuth::None;
                let passed = auth_fn.authenticate(&auth, &self.application_reference);
                (passed, auth)
            }
        }
    }

    /// Parses an AARQ PDU, tag 0x60, and updates `application_reference`.
    ///
    /// Every TLV is bounds checked before it is read.
    fn parse_aarq<'buf>(&mut self, buf: &'buf [u8]) -> Result<&'buf [u8], AcseError> {
        let mut pos = 1usize; // skip the outer tag 0x60
        let outer_len = ber_decode_length(buf, &mut pos, buf.len())?;
        let end = pos + outer_len;
        if end > buf.len() {
            return Err(AcseError::OobRead {
                claimed: outer_len,
                remaining: buf.len().saturating_sub(pos),
            });
        }

        let mut user_data: Option<&'buf [u8]> = None;

        while pos < end {
            // Bound the tag byte before reading it
            let tag = safe_get_byte(buf, &mut pos, end)?;
            let len = ber_decode_length(buf, &mut pos, end)?;

            // The value bytes must stay inside the PDU
            if pos + len > end {
                return Err(AcseError::OobRead {
                    claimed: len,
                    remaining: end.saturating_sub(pos),
                });
            }

            if len == 0 {
                // the tag and length bytes are already consumed, so the loop advances
                continue;
            }

            match tag {
                0xa1 => {
                    // application-context-name [1] EXPLICIT OID.
                    // A non-MMS OID is logged and accepted rather than rejected.
                    let context_bytes = safe_slice(buf, pos, len, end)?;
                    parse_app_context_name_warn(context_bytes);
                    pos += len;
                }
                0xa2 | 0xa3 | 0xa4 | 0xa5 | 0xa8 | 0xa9 | 0xaa | 0xad => {
                    // called, calling and responding titles; only user-information is needed
                    pos += len;
                }
                0xa6 => {
                    // calling-AP-title [6] EXPLICIT OID
                    let field = safe_slice(buf, pos, len, end)?;
                    self.application_reference.ap_title = parse_ap_title(field);
                    pos += len;
                }
                0xa7 => {
                    // calling-AE-qualifier [7] EXPLICIT INTEGER
                    let field = safe_slice(buf, pos, len, end)?;
                    self.application_reference.ae_qualifier = parse_ae_qualifier(field);
                    pos += len;
                }
                0x8a => {
                    // sender-ACSE-requirements [10] IMPLICIT BIT STRING, skipped
                    pos += len;
                }
                0x8b => {
                    // mechanism-name [11] IMPLICIT OID, skipped
                    pos += len;
                }
                0xac => {
                    // calling-authentication-value [12] EXPLICIT, skipped
                    pos += len;
                }
                0xbe => {
                    // user-information [30] IMPLICIT
                    let field = safe_slice(buf, pos, len, end)?;
                    user_data = Some(parse_user_information(buf, pos, field)?);
                    pos += len;
                }
                _ => {
                    // unknown tag, skipped
                    pos += len;
                }
            }
        }

        match user_data {
            Some(ud) => Ok(ud),
            None => {
                warn!("aarq is missing user-information (0xbe)");
                Err(AcseError::NoUserData)
            }
        }
    }

    /// Parses an AARE PDU, tag 0x61, and returns the result code with the
    /// user-information payload. Result 0 accepts, any other value rejects.
    ///
    /// Every TLV is bounds checked before it is read.
    fn parse_aare<'buf>(&mut self, buf: &'buf [u8]) -> Result<(u32, &'buf [u8]), AcseError> {
        let mut pos = 1usize; // skip the outer tag 0x61
        let outer_len = ber_decode_length(buf, &mut pos, buf.len())?;
        let end = pos + outer_len;
        if end > buf.len() {
            return Err(AcseError::OobRead {
                claimed: outer_len,
                remaining: buf.len().saturating_sub(pos),
            });
        }

        let mut result_code: u32 = 0;
        let mut user_data: Option<&'buf [u8]> = None;
        let mut saw_result = false;

        while pos < end {
            // Bound the tag byte before reading it
            let tag = safe_get_byte(buf, &mut pos, end)?;
            let len = ber_decode_length(buf, &mut pos, end)?;

            // The value bytes must stay inside the PDU
            if pos + len > end {
                return Err(AcseError::OobRead {
                    claimed: len,
                    remaining: end.saturating_sub(pos),
                });
            }

            if len == 0 {
                continue;
            }

            match tag {
                0xa1 => {
                    // application-context-name, logged and accepted as in an AARQ
                    let field = safe_slice(buf, pos, len, end)?;
                    parse_app_context_name_warn(field);
                    pos += len;
                }
                0xa2 => {
                    // result [2] EXPLICIT, wrapping tag 0x02 with a length and value
                    let mut inner_pos = pos;
                    let inner_end = pos + len;
                    let inner_tag = safe_get_byte(buf, &mut inner_pos, inner_end)?;
                    if inner_tag != 0x02 {
                        // malformed, skipped
                        pos += len;
                        continue;
                    }
                    let inner_len = ber_decode_length(buf, &mut inner_pos, inner_end)?;
                    if inner_pos + inner_len > inner_end {
                        return Err(AcseError::OobRead {
                            claimed: inner_len,
                            remaining: inner_end.saturating_sub(inner_pos),
                        });
                    }
                    result_code = ber_decode_uint(buf, inner_pos, inner_len);
                    saw_result = true;
                    pos += len;
                }
                0xa3 => {
                    // result-source-diagnostic [3] EXPLICIT, a fixed value, skipped
                    pos += len;
                }
                0xbe => {
                    // user-information [30] IMPLICIT
                    let field = safe_slice(buf, pos, len, end)?;
                    user_data = Some(parse_user_information(buf, pos, field)?);
                    pos += len;
                }
                _ => {
                    pos += len;
                }
            }
        }

        if !saw_result {
            warn!("aare is missing the result field (0xa2), treating it as accepted");
        }

        // user-information is mandatory when result is 0 and optional otherwise
        let ud = match user_data {
            Some(ud) => ud,
            None => {
                if result_code == 0 {
                    warn!("aare result is 0 (accepted) but user-information is missing");
                    return Err(AcseError::NoUserData);
                }
                // a rejecting AARE may omit user-information
                &[]
            }
        };

        Ok((result_code, ud))
    }
}

// Stateless encoders

/// Serializes an AARQ PDU, tag 0x60, into `out`.
///
/// - `payload`: the MMS Initiate PDU carried inside user-information.
/// - `auth`: credentials; `None` selects no authentication.
/// - `next_reference`: the indirect-reference value, 3 for MMS.
pub fn encode_aarq(
    payload: &[u8],
    auth: Option<&AcseAuth>,
    next_reference: u32,
    out: &mut BytesMut,
) {
    // user-information field
    let user_info_inner = build_user_information(payload, next_reference);

    // application-context-name field
    let app_ctx_bytes = build_app_context_name();

    // authentication fields
    let auth_bytes = build_auth_fields(auth);

    // AARQ body length
    let body_len = app_ctx_bytes.len() + auth_bytes.len() + user_info_inner.len();

    let start = out.len();
    write_tl(0x60, body_len, out);
    out.extend_from_slice(&app_ctx_bytes);
    out.extend_from_slice(&auth_bytes);
    out.extend_from_slice(&user_info_inner);

    let _ = start;
}

/// Serializes an AARE PDU, tag 0x61, into `out`.
///
/// - `result`: 0 accepts, 1 rejects permanently, 2 rejects transiently.
/// - `payload`: the MMS Initiate response; required when `result` is 0.
/// - `next_reference`: the indirect-reference echoed from the AARQ, normally 3.
pub fn encode_aare(result: u32, payload: Option<&[u8]>, next_reference: u32, out: &mut BytesMut) {
    let app_ctx_bytes = build_app_context_name();

    // result [2] EXPLICIT: a2 03 02 01 <result>
    let result_byte = result.min(255) as u8;
    let result_bytes: [u8; 5] = [0xa2, 0x03, 0x02, 0x01, result_byte];

    // result-source-diagnostic [3] EXPLICIT, fixed: a3 05 a1 03 02 01 00
    let diag_bytes: [u8; 7] = [0xa3, 0x05, 0xa1, 0x03, 0x02, 0x01, 0x00];

    // user-information is written only for result 0 with a non-empty payload
    let user_info = match payload {
        Some(p) if !p.is_empty() => build_user_information(p, next_reference),
        _ => Vec::new(),
    };

    let body_len = app_ctx_bytes.len() + result_bytes.len() + diag_bytes.len() + user_info.len();

    write_tl(0x61, body_len, out);
    out.extend_from_slice(&app_ctx_bytes);
    out.extend_from_slice(&result_bytes);
    out.extend_from_slice(&diag_bytes);
    if !user_info.is_empty() {
        out.extend_from_slice(&user_info);
    }
}

/// Serializes a rejecting AARE, result 1, without user-information.
///
/// ISO 8650 makes user-information optional in a reject, so it is omitted rather
/// than emitted as an empty payload.
pub fn encode_associate_failed(out: &mut BytesMut) {
    // result 1, reject-permanent, without user-information
    encode_aare(1, None, 0, out);
}

/// Serializes an ABRT PDU, tag 0x64, a fixed 5 bytes.
///
/// `is_provider` selects abort-source 1, the service provider, over 0, the user.
pub fn encode_abrt(is_provider: bool, out: &mut [u8; 5]) {
    let source: u8 = if is_provider { 1 } else { 0 };
    out[0] = 0x64; // ABRT tag
    out[1] = 0x03; // length = 3
    out[2] = 0x80; // abort-source [0] IMPLICIT INTEGER tag
    out[3] = 0x01; // length = 1
    out[4] = source;
}

/// Serializes an RLRQ PDU, tag 0x62, a fixed 5 bytes.
pub fn encode_rlrq(out: &mut [u8; 5]) {
    out[0] = 0x62; // RLRQ tag
    out[1] = 0x03; // length = 3
    out[2] = 0x80; // reason [0] IMPLICIT INTEGER tag
    out[3] = 0x01; // length = 1
    out[4] = 0x00; // reason = 0, normal
}

/// Serializes an RLRE PDU, tag 0x63, a fixed 2 bytes.
pub fn encode_rlre(out: &mut [u8; 2]) {
    out[0] = 0x63; // RLRE tag
    out[1] = 0x00; // length = 0, no content
}

// Private helpers

/// Builds the application-context-name field: a1 07 06 05 followed by the MMS OID.
fn build_app_context_name() -> Vec<u8> {
    // 0xa1 is the [1] EXPLICIT wrapper around the OID
    let oid_tl_len = 2 + APP_CONTEXT_NAME_MMS.len(); // OID tag, length byte, content
    let mut out = Vec::with_capacity(2 + oid_tl_len);
    out.push(0xa1);
    out.push(oid_tl_len as u8);
    out.push(0x06); // OID tag
    out.push(APP_CONTEXT_NAME_MMS.len() as u8);
    out.extend_from_slice(&APP_CONTEXT_NAME_MMS);
    out
}

/// Builds the user-information field: 0xbe wrapping association-data, which holds
/// an indirect-reference and the encoding that carries `payload`.
fn build_user_information(payload: &[u8], next_reference: u32) -> Vec<u8> {
    // indirect-reference; only a single-byte reference is emitted, and MMS uses 3
    let ref_byte = next_reference.min(127) as u8;
    let indirect_ref: [u8; 3] = [0x02, 0x01, ref_byte];

    // encoding [0] EXPLICIT: 0xa0 <L> <payload>
    let encoding_body_len = payload.len();
    let encoding_tl_size = 1 + ber_length_size(encoding_body_len);
    let encoding_total = encoding_tl_size + encoding_body_len;

    // association-data, tag 0x28: indirect-reference followed by the encoding
    let assoc_data_body_len = indirect_ref.len() + encoding_total;
    let assoc_data_tl_size = 1 + ber_length_size(assoc_data_body_len);
    let assoc_data_total = assoc_data_tl_size + assoc_data_body_len;

    // user-information, tag 0xbe
    let user_info_body_len = assoc_data_total;
    let user_info_tl_size = 1 + ber_length_size(user_info_body_len);

    let total_capacity = user_info_tl_size + user_info_body_len;
    let mut out = Vec::with_capacity(total_capacity);

    out.push(0xbe);
    write_ber_length(&mut out, user_info_body_len);

    out.push(0x28);
    write_ber_length(&mut out, assoc_data_body_len);

    out.extend_from_slice(&indirect_ref);

    out.push(0xa0);
    write_ber_length(&mut out, encoding_body_len);
    out.extend_from_slice(payload);

    out
}

/// Builds the authentication fields for the no-auth and password mechanisms.
///
/// `AcseAuth::TlsCertificate` emits no fields: the client certificate is validated
/// during the TLS handshake and IEC 62351-4 does not repeat it in the AARQ. The
/// mechanism-name OID that marks certificate authentication is not emitted yet, so
/// a peer cannot tell this apart from no authentication.
// TODO: emit the IEC 62351-4 mechanism-name OID for certificate authentication.
fn build_auth_fields(auth: Option<&AcseAuth>) -> Vec<u8> {
    match auth {
        None | Some(AcseAuth::None) | Some(AcseAuth::TlsCertificate(_)) => Vec::new(),
        Some(AcseAuth::Password(pw)) => {
            // sender-ACSE-requirements [10] IMPLICIT BIT STRING: 8a 02 04 80
            let req: [u8; 4] = [0x8a, 0x02, 0x04, REQUIREMENTS_AUTHENTICATION[0]];
            // mechanism-name [11] IMPLICIT OID: 8b 03 <OID>
            let mech: [u8; 5] = [
                0x8b,
                AUTH_MECH_PASSWORD_OID.len() as u8,
                AUTH_MECH_PASSWORD_OID[0],
                AUTH_MECH_PASSWORD_OID[1],
                AUTH_MECH_PASSWORD_OID[2],
            ];
            // calling-authentication-value [12] EXPLICIT charstring: ac <L> 80 <L> <pw>
            let pw_inner_len = pw.len();
            let pw_inner_tl = 1 + ber_length_size(pw_inner_len); // 0x80 + len
            let ac_body_len = pw_inner_tl + pw_inner_len;

            let mut out = Vec::with_capacity(req.len() + mech.len() + 2 + ac_body_len);
            out.extend_from_slice(&req);
            out.extend_from_slice(&mech);
            out.push(0xac);
            write_ber_length(&mut out, ac_body_len);
            out.push(0x80); // charstring, context tag 0
            write_ber_length(&mut out, pw_inner_len);
            out.extend_from_slice(pw);
            out
        }
    }
}

/// Parses the user-information field and returns the encoding, the MMS payload.
///
/// `field` holds the bytes after the 0xbe tag and length, and `field_offset` locates
/// them inside `buf`, so the returned slice borrows from `buf`.
fn parse_user_information<'buf>(
    buf: &'buf [u8],
    field_offset: usize,
    field: &[u8],
) -> Result<&'buf [u8], AcseError> {
    if field.is_empty() {
        warn!("user-information (0xbe) carries an empty value");
        return Err(AcseError::NoUserData);
    }

    // The content must be association-data, tag 0x28, checked before indexing.
    if field[0] != 0x28 {
        warn!(
            tag = format!("0x{:02X}", field[0]),
            "user-information tag is not association-data (0x28), rejecting"
        );
        return Err(AcseError::NoUserData);
    }

    let mut pos = 1usize; // skip the 0x28 tag
    let field_len = ber_decode_length(field, &mut pos, field.len())?;
    let assoc_end = pos + field_len;
    if assoc_end > field.len() {
        return Err(AcseError::OobRead {
            claimed: field_len,
            remaining: field.len().saturating_sub(pos),
        });
    }

    let mut has_indirect_ref = false;
    let mut encoding_slice: Option<&'buf [u8]> = None;

    while pos < assoc_end {
        let tag = safe_field_byte(field, &mut pos, assoc_end)?;
        let len = ber_decode_length(field, &mut pos, assoc_end)?;

        if pos + len > assoc_end {
            return Err(AcseError::OobRead {
                claimed: len,
                remaining: assoc_end.saturating_sub(pos),
            });
        }

        if len == 0 {
            continue;
        }

        match tag {
            0x02 => {
                // indirect-reference; only its presence is recorded, because an AARE
                // receives the reference to echo as a parameter.
                has_indirect_ref = true;
                pos += len;
            }
            0xa0 => {
                // encoding [0] EXPLICIT, the MMS Initiate PDU.
                // The slice comes from buf rather than field so its lifetime is tied
                // to the caller buffer.
                let abs_pos = field_offset + pos;
                if abs_pos + len > buf.len() {
                    return Err(AcseError::OobRead {
                        claimed: len,
                        remaining: buf.len().saturating_sub(abs_pos),
                    });
                }
                encoding_slice = Some(&buf[abs_pos..abs_pos + len]);
                pos += len;
            }
            _ => {
                pos += len;
            }
        }
    }

    if !has_indirect_ref {
        warn!("user-information is missing the indirect-reference (0x02)");
        return Err(AcseError::NoUserData);
    }

    match encoding_slice {
        Some(s) => Ok(s),
        None => {
            warn!("user-information is missing the encoding (0xa0)");
            Err(AcseError::NoUserData)
        }
    }
}

/// Parses application-context-name and logs a mismatched OID without rejecting it.
fn parse_app_context_name_warn(field: &[u8]) {
    // expected encoding: 06 05 28 ca 22 02 03
    if field.len() < 7 || field[0] != 0x06 || field[1] != 0x05 {
        warn!("application-context-name is malformed, an oid tag was expected");
        return;
    }
    let oid = &field[2..7];
    if oid != APP_CONTEXT_NAME_MMS {
        warn!(
            oid = format!("{:02X?}", oid),
            expected = format!("{:02X?}", APP_CONTEXT_NAME_MMS),
            "application-context-name oid is not mms (1.0.9506.2.3), accepting and logging"
        );
    }
}

/// Parses calling-AP-title and returns its OID bytes.
///
/// Expected encoding: 06 <len> <oid bytes>.
fn parse_ap_title(field: &[u8]) -> Vec<u8> {
    if field.len() < 2 || field[0] != 0x06 {
        return Vec::new();
    }
    let oid_len = field[1] as usize;
    if 2 + oid_len > field.len() {
        return Vec::new();
    }
    field[2..2 + oid_len].to_vec()
}

/// Parses calling-AE-qualifier and returns its integer value.
///
/// Expected encoding, where `field` is the content of tag 0xa7: 02 <len> <int bytes>.
fn parse_ae_qualifier(field: &[u8]) -> i32 {
    if field.len() < 2 || field[0] != 0x02 {
        return 0;
    }
    let int_len = field[1] as usize;
    if 2 + int_len > field.len() || int_len == 0 {
        return 0;
    }
    let int_bytes = &field[2..2 + int_len];
    // BER signed integer, most significant byte first
    let mut val: i32 = if int_bytes[0] & 0x80 != 0 {
        -1i32
    } else {
        0i32
    };
    for &b in int_bytes {
        val = (val << 8) | (b as i32);
    }
    val
}

// BER encoding and decoding helpers

/// Returns the number of bytes a BER definite-form length field occupies.
fn ber_length_size(n: usize) -> usize {
    if n < 128 {
        1
    } else if n < 256 {
        2
    } else if n < 65536 {
        3
    } else {
        4
    }
}

/// Appends a BER length to a `Vec<u8>`.
fn write_ber_length(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 65536 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    } else {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    }
}

/// Appends a BER tag and length to a `BytesMut`.
fn write_tl(tag: u8, len: usize, out: &mut BytesMut) {
    out.extend_from_slice(&[tag]);
    if len < 128 {
        out.extend_from_slice(&[len as u8]);
    } else if len < 256 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else if len < 65536 {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, (len & 0xFF) as u8]);
    } else {
        out.extend_from_slice(&[
            0x83,
            (len >> 16) as u8,
            (len >> 8) as u8,
            (len & 0xFF) as u8,
        ]);
    }
}

/// Parses a BER length at `buf[*pos]` and advances `*pos` past it.
///
/// Every step is bounds checked against `end`: a truncated field returns `TooShort`
/// and an unsupported form returns `MalformedLength`.
fn ber_decode_length(buf: &[u8], pos: &mut usize, end: usize) -> Result<usize, AcseError> {
    if *pos >= end {
        return Err(AcseError::TooShort { len: buf.len() });
    }
    let first = buf[*pos];
    *pos += 1;

    if first < 0x80 {
        // short form
        return Ok(first as usize);
    }

    if first == 0x80 {
        // the indefinite form is not supported
        return Err(AcseError::MalformedLength);
    }

    let num_bytes = (first & 0x7F) as usize;
    if num_bytes > 3 {
        return Err(AcseError::MalformedLength);
    }
    if *pos + num_bytes > end {
        return Err(AcseError::TooShort { len: buf.len() });
    }

    let mut len = 0usize;
    for _ in 0..num_bytes {
        len = (len << 8) | (buf[*pos] as usize);
        *pos += 1;
    }
    Ok(len)
}

/// Reads one byte from `buf` at `*pos` and advances it, bounded by `end`.
fn safe_get_byte(buf: &[u8], pos: &mut usize, end: usize) -> Result<u8, AcseError> {
    if *pos >= end {
        return Err(AcseError::TooShort { len: buf.len() });
    }
    let b = buf[*pos];
    *pos += 1;
    Ok(b)
}

/// Reads one byte from `field` at `*pos` and advances it, bounded by `end`.
fn safe_field_byte(field: &[u8], pos: &mut usize, end: usize) -> Result<u8, AcseError> {
    if *pos >= end {
        return Err(AcseError::TooShort { len: field.len() });
    }
    let b = field[*pos];
    *pos += 1;
    Ok(b)
}

/// Returns `buf[pos..pos + len]`, or `OobRead` when it would run past `end`.
fn safe_slice(buf: &[u8], pos: usize, len: usize, end: usize) -> Result<&[u8], AcseError> {
    if pos + len > end || pos + len > buf.len() {
        return Err(AcseError::OobRead {
            claimed: len,
            remaining: end.saturating_sub(pos),
        });
    }
    Ok(&buf[pos..pos + len])
}

/// Decodes an unsigned BER INTEGER of at most 4 bytes.
fn ber_decode_uint(buf: &[u8], pos: usize, len: usize) -> u32 {
    let mut val = 0u32;
    let end = (pos + len).min(pos + 4).min(buf.len());
    for &b in &buf[pos..end] {
        val = (val << 8) | (b as u32);
    }
    val
}

// Unit tests

#[cfg(test)]
mod tests {
    use super::*;

    // encode helpers

    fn make_aarq(payload: &[u8]) -> Vec<u8> {
        let mut out = BytesMut::new();
        encode_aarq(payload, None, 3, &mut out);
        out.to_vec()
    }

    fn make_aarq_pw(payload: &[u8], pw: &[u8]) -> Vec<u8> {
        let mut out = BytesMut::new();
        let auth = AcseAuth::Password(pw.to_vec());
        encode_aarq(payload, Some(&auth), 3, &mut out);
        out.to_vec()
    }

    fn make_aare_accept(payload: &[u8]) -> Vec<u8> {
        let mut out = BytesMut::new();
        encode_aare(0, Some(payload), 3, &mut out);
        out.to_vec()
    }

    fn make_aare_reject() -> Vec<u8> {
        let mut out = BytesMut::new();
        encode_aare(1, None, 0, &mut out);
        out.to_vec()
    }

    // AARQ encoding

    #[test]
    fn test_encode_aarq_has_mms_oid() {
        let pdu = make_aarq(&[0xde, 0xad]);
        // the outermost tag is 0x60
        assert_eq!(pdu[0], 0x60);
        // application-context-name starts with a1 07 06 05 28 ca 22 02 03
        let oid_seq: &[u8] = &[0xa1, 0x07, 0x06, 0x05, 0x28, 0xca, 0x22, 0x02, 0x03];
        assert!(
            pdu.windows(oid_seq.len()).any(|w| w == oid_seq),
            "aarq must carry the mms application-context-name oid"
        );
    }

    #[test]
    fn test_encode_aarq_has_user_information() {
        let mms_payload = &[0xde, 0xad];
        let pdu = make_aarq(mms_payload);
        // user-information starts with be ?? 28 ?? 02 01 03
        let ui_start: &[u8] = &[0xbe];
        let assoc_tag: &[u8] = &[0x28];
        let indirect_ref: &[u8] = &[0x02, 0x01, 0x03];
        assert!(
            pdu.windows(1).any(|w| w == ui_start),
            "aarq must contain 0xbe user-information"
        );
        assert!(
            pdu.windows(3).any(|w| w == indirect_ref),
            "aarq must carry indirect-reference 3"
        );
        assert!(
            pdu.windows(1).any(|w| w == assoc_tag),
            "aarq must contain 0x28 association-data"
        );
    }

    #[test]
    fn test_encode_aarq_with_password_has_auth_fields() {
        let pw = b"testpw";
        let pdu = make_aarq_pw(&[0x01], pw);
        // sender-ACSE-requirements: 8a 02 04 80
        let req: &[u8] = &[0x8a, 0x02, 0x04, 0x80];
        // mechanism-name: 8b 03 52 03 01
        let mech: &[u8] = &[0x8b, 0x03, 0x52, 0x03, 0x01];
        assert!(
            pdu.windows(req.len()).any(|w| w == req),
            "password authentication must add sender-ACSE-requirements"
        );
        assert!(
            pdu.windows(mech.len()).any(|w| w == mech),
            "password authentication must add the mechanism-name oid"
        );
    }

    // AARE encoding

    #[test]
    fn test_encode_aare_accept_result_zero() {
        let pdu = make_aare_accept(&[0xde, 0xad]);
        assert_eq!(pdu[0], 0x61);
        // result=0: a2 03 02 01 00
        let result_field: &[u8] = &[0xa2, 0x03, 0x02, 0x01, 0x00];
        assert!(
            pdu.windows(result_field.len()).any(|w| w == result_field),
            "an accepting aare must carry result 0"
        );
        // user-information must be present
        assert!(
            pdu.contains(&0xbe),
            "an accepting aare must carry user-information"
        );
    }

    #[test]
    fn test_encode_aare_reject_result_one_no_userinfo() {
        let pdu = make_aare_reject();
        assert_eq!(pdu[0], 0x61);
        // result=1: a2 03 02 01 01
        let result_field: &[u8] = &[0xa2, 0x03, 0x02, 0x01, 0x01];
        assert!(
            pdu.windows(result_field.len()).any(|w| w == result_field),
            "a rejecting aare must carry result 1"
        );
        // a rejecting aare omits user-information
        assert!(
            !pdu.contains(&0xbe),
            "a rejecting aare must not contain user-information (0xbe)"
        );
    }

    // ABRT, RLRQ and RLRE encoding

    #[test]
    fn test_encode_abrt_provider() {
        let mut out = [0u8; 5];
        encode_abrt(true, &mut out);
        assert_eq!(out, [0x64, 0x03, 0x80, 0x01, 0x01]);
    }

    #[test]
    fn test_encode_abrt_user() {
        let mut out = [0u8; 5];
        encode_abrt(false, &mut out);
        assert_eq!(out, [0x64, 0x03, 0x80, 0x01, 0x00]);
    }

    #[test]
    fn test_encode_rlrq() {
        let mut out = [0u8; 5];
        encode_rlrq(&mut out);
        assert_eq!(out, [0x62, 0x03, 0x80, 0x01, 0x00]);
    }

    #[test]
    fn test_encode_rlre() {
        let mut out = [0u8; 2];
        encode_rlre(&mut out);
        assert_eq!(out, [0x63, 0x00]);
    }

    // AARQ and AARE round trips

    #[test]
    fn test_aarq_roundtrip() {
        let mms_payload = &[0x01, 0x02, 0x03, 0x04];
        let aarq_bytes = make_aarq(mms_payload);

        let mut conn = AcseConnection::new(None);
        let (indication, user_data) = conn.parse_message(&aarq_bytes).expect("aarq parse failed");

        assert_eq!(indication, AcseIndication::Associate);
        assert_eq!(user_data, mms_payload);
    }

    /// An AARQ whose application-context-name OID is not the MMS one is still
    /// accepted; `parse_app_context_name_warn` logs the mismatch.
    #[test]
    fn test_aarq_non_mms_oid_warn_accept() {
        let mms_payload = &[0x01, 0x02, 0x03, 0x04];
        let mut aarq_bytes = make_aarq(mms_payload);
        // find the MMS OID sequence 28 ca 22 02 03 and change its first byte to 0x29
        let mms_oid = APP_CONTEXT_NAME_MMS;
        let pos = aarq_bytes
            .windows(mms_oid.len())
            .position(|w| w == mms_oid)
            .expect("the aarq must contain the mms oid");
        aarq_bytes[pos] = 0x29;

        let mut conn = AcseConnection::new(None);
        let (indication, user_data) = conn
            .parse_message(&aarq_bytes)
            .expect("a non-mms oid must be logged but still accepted");
        assert_eq!(indication, AcseIndication::Associate);
        assert_eq!(user_data, mms_payload);
    }

    #[test]
    fn test_aare_accept_roundtrip() {
        let mms_payload = &[0xde, 0xad, 0xbe, 0xef];
        let aare_bytes = make_aare_accept(mms_payload);

        let mut conn = AcseConnection::new(None);
        let (indication, user_data) = conn.parse_message(&aare_bytes).expect("aare parse failed");

        assert_eq!(indication, AcseIndication::Associate);
        assert_eq!(user_data, mms_payload);
    }

    #[test]
    fn test_aare_reject_roundtrip() {
        let aare_bytes = make_aare_reject();

        let mut conn = AcseConnection::new(None);
        let (indication, user_data) = conn
            .parse_message(&aare_bytes)
            .expect("rejecting aare parse failed");

        assert_eq!(indication, AcseIndication::AssociateFailed);
        assert_eq!(user_data, &[]);
    }

    // RLRQ, RLRE and ABRT parsing

    #[test]
    fn test_parse_rlrq() {
        let bytes = [0x62u8, 0x03, 0x80, 0x01, 0x00];
        let mut conn = AcseConnection::new(None);
        let (ind, ud) = conn.parse_message(&bytes).unwrap();
        assert_eq!(ind, AcseIndication::ReleaseRequest);
        assert_eq!(ud, &[]);
    }

    #[test]
    fn test_parse_rlre() {
        let bytes = [0x63u8, 0x00];
        let mut conn = AcseConnection::new(None);
        let (ind, ud) = conn.parse_message(&bytes).unwrap();
        assert_eq!(ind, AcseIndication::ReleaseResponse);
        assert_eq!(ud, &[]);
    }

    #[test]
    fn test_parse_abrt() {
        let bytes = [0x64u8, 0x03, 0x80, 0x01, 0x01];
        let mut conn = AcseConnection::new(None);
        let (ind, ud) = conn.parse_message(&bytes).unwrap();
        assert_eq!(ind, AcseIndication::Abort);
        assert_eq!(ud, &[]);
    }

    // Boundary conditions

    #[test]
    fn test_empty_buf_err() {
        let mut conn = AcseConnection::new(None);
        assert!(matches!(
            conn.parse_message(&[]),
            Err(AcseError::TooShort { .. })
        ));
    }

    #[test]
    fn test_single_byte_err() {
        let mut conn = AcseConnection::new(None);
        assert!(matches!(
            conn.parse_message(&[0x60]),
            Err(AcseError::TooShort { .. })
        ));
    }

    #[test]
    fn test_unknown_tag_err() {
        let mut conn = AcseConnection::new(None);
        let bytes = [0x65u8, 0x00];
        assert!(matches!(
            conn.parse_message(&bytes),
            Err(AcseError::UnknownPduType { tag: 0x65 })
        ));
    }

    #[test]
    fn test_aarq_missing_user_info_err() {
        // an AARQ carrying only application-context-name and no user-information
        let mut out = BytesMut::new();
        // built by hand: a1 07 06 05 28 ca 22 02 03
        let body: [u8; 9] = [0xa1, 0x07, 0x06, 0x05, 0x28, 0xca, 0x22, 0x02, 0x03];
        out.extend_from_slice(&[0x60, body.len() as u8]);
        out.extend_from_slice(&body);
        let bytes = out.to_vec();

        let mut conn = AcseConnection::new(None);
        assert!(
            conn.parse_message(&bytes).is_err(),
            "an aarq without user-information must return an error"
        );
    }

    #[test]
    fn test_aare_accept_missing_user_info_err() {
        // a hand-built AARE with result 0 and no user-information
        // a1 07 06 05 ... + a2 03 02 01 00 + a3 05 a1 03 02 01 00
        let body: Vec<u8> = vec![
            0xa1, 0x07, 0x06, 0x05, 0x28, 0xca, 0x22, 0x02, 0x03, // app-ctx
            0xa2, 0x03, 0x02, 0x01, 0x00, // result=0
            0xa3, 0x05, 0xa1, 0x03, 0x02, 0x01, 0x00, // diag
        ];
        let mut bytes = vec![0x61u8, body.len() as u8];
        bytes.extend_from_slice(&body);

        let mut conn = AcseConnection::new(None);
        let result = conn.parse_message(&bytes);
        assert!(
            matches!(result, Err(AcseError::NoUserData)),
            "result 0 without user-information must return NoUserData"
        );
    }

    #[test]
    fn test_encode_associate_failed_no_userinfo() {
        let mut out = BytesMut::new();
        encode_associate_failed(&mut out);
        let pdu = out.as_ref();
        // 0xbe user-information must be absent
        assert!(
            !pdu.contains(&0xbe),
            "encode_associate_failed must not contain user-information"
        );
        // result=1
        let result_field: &[u8] = &[0xa2, 0x03, 0x02, 0x01, 0x01];
        assert!(
            pdu.windows(result_field.len()).any(|w| w == result_field),
            "encode_associate_failed must carry result 1"
        );
    }
}
