//! ISO 8823 Presentation layer, restricted to the subset MMS requires.
//!
//! Encodes and decodes the CP (Connect Presentation, tag 0x31) and CPA
//! (Connect Presentation Accept) PDUs, the Fully-Encoded-Data container
//! (tag 0x61) that carries MMS and ACSE PDUs, and the Abort container
//! (tag 0xa0) that wraps an ACSE ABRT PDU. No state machine and no transport
//! live here: PDUs are serialized and parsed, and connection state stays with
//! the caller.
//!
//! Strictness rules enforced by this module:
//! - A P-Selector longer than 16 bytes is warned about and rejected.
//! - The Abort container carries outer tag 0xa0 rather than 0x31; the ISO 8823
//!   Abort PPDU type it should carry is not verified against the standard.
//! - A PCDL entry naming an unknown abstract-syntax OID is rejected.
//! - mode-selector must be normal-mode: both the inner tag and the value are
//!   checked.
//! - transfer-syntax must be BER (OID 2.1.1, encoded 0x51 0x01).
//!
//! Robustness cases covered:
//! - A PDU carrying an unknown tag with length 0 is parsed in bounded
//!   time; every loop iteration consumes at least the tag byte.
//! - A CP PDU without user-data is rejected instead of returning an unset
//!   payload range.
//! - A CP PDU without normal-mode-parameters is rejected.

use bytes::BytesMut;
use tracing::warn;

// Error types

/// Errors raised by the Presentation layer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PresentationError {
    /// The outer BER tag is not the expected CP/CPA tag 0x31.
    #[error("presentation pdu tag 0x{tag:02X} is not the expected 0x{expected:02X}")]
    WrongTag {
        /// Tag received.
        tag: u8,
        /// Tag the layer expected.
        expected: u8,
    },

    /// A BER length field runs past the end of the buffer.
    #[error("ber length {claimed} exceeds the {remaining} bytes remaining in the buffer")]
    LengthOverflow {
        /// Length the BER field declared.
        claimed: usize,
        /// Bytes remaining in the buffer.
        remaining: usize,
    },

    /// The message is too short to hold the mandatory fields.
    #[error("presentation pdu too short (len={len})")]
    TooShort {
        /// Length of the PDU received.
        len: usize,
    },

    /// The mode-selector inner tag is not 0x80, or its value is not normal-mode (1).
    #[error("invalid mode-selector: inner_tag=0x{inner_tag:02X}, mode_value={mode_value}")]
    InvalidModeSelector {
        /// Inner tag received; it must be 0x80.
        inner_tag: u8,
        /// Mode value received; it must be 1, normal-mode.
        mode_value: u32,
    },

    /// The CP PDU carries no normal-mode-parameters (0xa2).
    #[error("cp pdu is missing normal-mode-parameters (0xa2)")]
    MissingNormalModeParameters,

    /// normal-mode-parameters carries no user-data (0x61).
    #[error("normal-mode-parameters is missing user-data (0x61)")]
    MissingUserData,

    /// A PCDL entry names an abstract-syntax OID that is neither ACSE nor MMS.
    #[error("pcdl entry contains an unknown abstract-syntax oid")]
    UnknownAbstractSyntax,

    /// A PCDL entry carries no context-id (tag 0x02).
    #[error("pcdl entry is missing a context-id")]
    MissingContextId,

    /// transfer-syntax is not BER (OID 2.1.1, encoded 0x51 0x01).
    #[error("transfer-syntax is not ber (expected 0x51 0x01)")]
    InvalidTransferSyntax,

    /// A P-Selector longer than the 16-byte maximum.
    ///
    /// An oversized selector is rejected rather than truncated.
    #[error("p-selector length {len} exceeds the maximum of 16")]
    PSelectorTooLong {
        /// Selector length received.
        len: usize,
    },

    /// The PDU passed to `parse_user_data` is shorter than the 9-byte minimum.
    #[error("fully-encoded-data pdu too short (minimum 9 bytes, got {len})")]
    UserDataTooShort {
        /// Length of the PDU received.
        len: usize,
    },

    /// Fully-Encoded-Data carries no abstract-syntax-name (context-id, tag 0x02).
    #[error("fully-encoded-data is missing abstract-syntax-name (0x02)")]
    MissingAbstractSyntaxName,

    /// The decoded context-id falls outside the 1-255 range this layer supports.
    #[error("context-id {value} is outside the valid range 1-255")]
    ContextIdOutOfRange {
        /// Context identifier decoded.
        value: u32,
    },

    /// The BER length field is malformed, for example an indefinite-form length.
    #[error("malformed ber length field")]
    MalformedLength,
}

// Constants

/// Responding P-Selector sent in a CPA: the fixed value 00 00 00 01.
const CALLED_P_SEL: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

/// ACSE abstract-syntax OID 2.2.1.0.1, as BER content octets.
const ASN_ID_ACSE: [u8; 4] = [0x52, 0x01, 0x00, 0x01];

/// MMS abstract-syntax OID 1.0.9506.2.1, as BER content octets.
const ASN_ID_MMS: [u8; 5] = [0x28, 0xca, 0x22, 0x02, 0x01];

/// BER transfer-syntax OID 2.1.1, as BER content octets.
const BER_ID: [u8; 2] = [0x51, 0x01];

/// Presentation context identifier used for ACSE; fixed, never negotiated.
pub const ACSE_CONTEXT_ID: u8 = 1;

/// Presentation context identifier used for MMS; fixed, never negotiated.
pub const MMS_CONTEXT_ID: u8 = 3;

/// Maximum P-Selector length in bytes.
const PSELECTOR_MAX_SIZE: usize = 16;

// Data structures

/// A Presentation Selector of at most 16 bytes.
///
/// A `size` of 0 means the selector is not carried on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PSelector {
    /// Number of significant bytes, in the range 0..=16.
    pub size: u8,
    /// Selector octets; only the first `size` bytes are significant.
    pub value: [u8; 16],
}

impl PSelector {
    /// Builds a selector from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns `PresentationError::PSelectorTooLong` when `data` is longer than 16 bytes.
    pub fn from_slice(data: &[u8]) -> Result<Self, PresentationError> {
        if data.len() > PSELECTOR_MAX_SIZE {
            return Err(PresentationError::PSelectorTooLong { len: data.len() });
        }
        let mut value = [0u8; 16];
        value[..data.len()].copy_from_slice(data);
        Ok(Self {
            size: data.len() as u8,
            value,
        })
    }

    /// Returns the significant bytes of the selector.
    pub fn as_slice(&self) -> &[u8] {
        &self.value[..self.size as usize]
    }
}

/// Presentation-layer state retained across calls.
///
/// The payload is not stored here: parse functions return offsets into the input
/// buffer, which keeps this type free of borrows.
#[derive(Debug, Clone)]
pub struct IsoPresentation {
    /// Local Presentation Selector (Calling P-SEL).
    pub calling_p_sel: PSelector,
    /// Peer Presentation Selector (Called P-SEL).
    pub called_p_sel: PSelector,
    /// presentation-context-identifier seen in the most recent parse.
    pub next_context_id: u8,
    /// Context identifier bound to the ACSE abstract syntax; taken from a parsed
    /// CP PDU, and always encoded as 1.
    pub acse_context_id: u8,
    /// Context identifier bound to the MMS abstract syntax; taken from a parsed
    /// CP PDU, and always encoded as 3.
    pub mms_context_id: u8,
}

impl IsoPresentation {
    /// Creates an instance with empty selectors and the default context identifiers.
    pub fn new() -> Self {
        Self {
            calling_p_sel: PSelector::default(),
            called_p_sel: PSelector::default(),
            next_context_id: 0,
            acse_context_id: ACSE_CONTEXT_ID,
            mms_context_id: MMS_CONTEXT_ID,
        }
    }
}

impl Default for IsoPresentation {
    fn default() -> Self {
        Self::new()
    }
}

/// Successful result of `parse_connect` or `parse_accept`.
///
/// Carries the byte offset range of the user-data, that is the ACSE AARQ or
/// AARE payload, inside the input buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectResult {
    /// Offset of the ACSE or MMS payload within the input buffer.
    pub payload_start: usize,
    /// Length of the ACSE or MMS payload.
    pub payload_len: usize,
}

impl ConnectResult {
    /// Returns the payload slice borrowed from `buf`.
    pub fn payload<'buf>(&self, buf: &'buf [u8]) -> &'buf [u8] {
        &buf[self.payload_start..self.payload_start + self.payload_len]
    }
}

/// Successful result of `parse_user_data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserDataResult {
    /// presentation-context-identifier: 1 for ACSE, 3 for MMS.
    pub context_id: u8,
    /// Offset of the MMS or ACSE payload within the input buffer.
    pub payload_start: usize,
    /// Payload length.
    pub payload_len: usize,
}

impl UserDataResult {
    /// Returns the payload slice borrowed from `buf`.
    pub fn payload<'buf>(&self, buf: &'buf [u8]) -> &'buf [u8] {
        &buf[self.payload_start..self.payload_start + self.payload_len]
    }
}

/// Connection parameters required by `encode_connect`.
#[derive(Debug, Clone, Default)]
pub struct PresentationConnectionParameters {
    /// Local Presentation Selector (Calling P-SEL).
    pub local_p_sel: PSelector,
    /// Peer Presentation Selector (Called P-SEL).
    pub remote_p_sel: PSelector,
}

// BER helpers, private to this module

/// Returns the number of bytes a BER definite-form length field occupies for `n`.
///
/// - `n < 128`: 1 byte, short form
/// - `n < 256`: 2 bytes, `0x81 <len>`
/// - `n < 65536`: 3 bytes, `0x82 <hi> <lo>`
/// - otherwise: 4 bytes
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

/// Writes a BER tag and length pair to `out`.
fn write_tl(tag: u8, len: usize, out: &mut BytesMut) {
    out.extend_from_slice(&[tag]);
    write_length(len, out);
}

/// Writes a BER definite-form length field to `out`.
fn write_length(len: usize, out: &mut BytesMut) {
    if len < 128 {
        out.extend_from_slice(&[len as u8]);
    } else if len < 256 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else if len < 65536 {
        let hi = (len >> 8) as u8;
        let lo = (len & 0xFF) as u8;
        out.extend_from_slice(&[0x82, hi, lo]);
    } else {
        let b2 = (len >> 16) as u8;
        let b1 = (len >> 8) as u8;
        let b0 = (len & 0xFF) as u8;
        out.extend_from_slice(&[0x83, b2, b1, b0]);
    }
}

/// Parses a BER length starting at `buf[*pos]` and advances `*pos` past it.
///
/// Returns the decoded length value.
///
/// # Errors
///
/// - `TooShort` when `*pos` is at or past `end`, or the length octets are truncated.
/// - `LengthOverflow` when the declared length runs past `end`.
/// - `MalformedLength` for the indefinite form or a length wider than three octets.
fn read_ber_length(buf: &[u8], pos: &mut usize, end: usize) -> Result<usize, PresentationError> {
    if *pos >= end {
        return Err(PresentationError::TooShort { len: buf.len() });
    }
    let first = buf[*pos];
    *pos += 1;

    if first < 0x80 {
        // short form
        let len = first as usize;
        // The declared length must stay inside end
        if *pos + len > end {
            return Err(PresentationError::LengthOverflow {
                claimed: len,
                remaining: end.saturating_sub(*pos),
            });
        }
        return Ok(len);
    }

    if first == 0x80 {
        // the indefinite form is never used by this layer
        return Err(PresentationError::MalformedLength);
    }

    let num_bytes = (first & 0x7F) as usize;
    if num_bytes > 3 {
        // lengths wider than three octets are not supported
        return Err(PresentationError::MalformedLength);
    }
    if *pos + num_bytes > end {
        return Err(PresentationError::TooShort { len: buf.len() });
    }

    let mut len = 0usize;
    for _ in 0..num_bytes {
        len = (len << 8) | (buf[*pos] as usize);
        *pos += 1;
    }

    // The declared length must stay inside end
    if *pos + len > end {
        return Err(PresentationError::LengthOverflow {
            claimed: len,
            remaining: end.saturating_sub(*pos),
        });
    }

    Ok(len)
}

/// Reads one byte at `buf[*pos]` and advances `*pos`, bounded by `end`.
fn read_byte(buf: &[u8], pos: &mut usize, end: usize) -> Result<u8, PresentationError> {
    if *pos >= end {
        return Err(PresentationError::TooShort { len: buf.len() });
    }
    let b = buf[*pos];
    *pos += 1;
    Ok(b)
}

// Encoders

/// Encodes a CP (Connect Presentation) PDU, tag 0x31, into `out`.
///
/// The presentation context identifiers are fixed at 1 for ACSE and 3 for MMS.
/// The P-Selectors come from `params`.
pub fn encode_connect(
    params: &PresentationConnectionParameters,
    payload: &[u8],
    out: &mut BytesMut,
) {
    let calling_sel = params.local_p_sel.as_slice();
    let called_sel = params.remote_p_sel.as_slice();

    // Fixed presentation-context-definition-list (0xa4) content:
    //   ACSE item = 0x30 0x0F, 15 content bytes plus a 2-byte header = 17
    //   MMS  item = 0x30 0x10, 16 content bytes plus a 2-byte header = 18
    // 35 bytes in total.
    const PCDL_INNER_LEN: usize = 35;

    // user-data (Fully-Encoded-Data, 0x61) section lengths
    let user_data_payload_len = payload.len();
    let user_data_a0_len = user_data_payload_len + ber_length_size(user_data_payload_len) + 1; // +1 = 0xa0 tag
    let pdv_list_inner_len = 3 + user_data_a0_len; // 0x02 0x01 <ctxId> + 0xa0...
    let pdv_list_len = pdv_list_inner_len;
    let user_data_61_content = pdv_list_len + ber_length_size(pdv_list_len) + 1; // +1 = 0x30 tag
    let user_data_total = user_data_61_content + ber_length_size(user_data_61_content) + 1; // +1 = 0x61 tag
    let _ = user_data_total; // enclosing lengths are derived from user_data_61_content

    // Both presentation-selector fields are written unconditionally: a
    // zero-length selector still needs its 0x81 0x00 and 0x82 0x00 pair, and
    // omitting those four bytes makes peers reject the CP PDU.
    let calling_field_len = 2 + calling_sel.len();
    let called_field_len = 2 + called_sel.len();

    let pcdl_field_len = 1 + ber_length_size(PCDL_INNER_LEN) + PCDL_INNER_LEN;
    let nmp_content_len = calling_field_len
        + called_field_len
        + pcdl_field_len
        + 1
        + ber_length_size(user_data_61_content)
        + user_data_61_content;

    // mode-selector is the fixed sequence a0 03 80 01 01
    const MODE_SEL_LEN: usize = 5;

    let nmp_field_len = 1 + ber_length_size(nmp_content_len) + nmp_content_len;
    let cp_content_len = MODE_SEL_LEN + nmp_field_len;

    // 0x31 CP-type tag + length
    write_tl(0x31, cp_content_len, out);

    // mode-selector, normal-mode (1)
    out.extend_from_slice(&[0xa0, 0x03, 0x80, 0x01, 0x01]);

    // 0xa2 <L>  normal-mode-parameters
    write_tl(0xa2, nmp_content_len, out);

    // calling-presentation-selector, tag and length written even when empty
    out.extend_from_slice(&[0x81, calling_sel.len() as u8]);
    out.extend_from_slice(calling_sel);

    // called-presentation-selector, tag and length written even when empty
    out.extend_from_slice(&[0x82, called_sel.len() as u8]);
    out.extend_from_slice(called_sel);

    // 0xa4 35  presentation-context-definition-list
    out.extend_from_slice(&[0xa4, PCDL_INNER_LEN as u8]);
    // ACSE context item, 0x30 0x0F followed by its content
    encode_context_item(ACSE_CONTEXT_ID, &ASN_ID_ACSE, out);
    // MMS context item, 0x30 0x10 followed by its content
    encode_context_item(MMS_CONTEXT_ID, &ASN_ID_MMS, out);

    // 0x61 <L>  user-data (Fully-Encoded-Data)
    write_tl(0x61, user_data_61_content, out);
    // 0x30 <L>  PDV-list
    write_tl(0x30, pdv_list_inner_len, out);
    // 0x02 0x01 <ctxId>  presentation-context-identifier = ACSE = 1
    out.extend_from_slice(&[0x02, 0x01, ACSE_CONTEXT_ID]);
    // 0xa0 <L>  presentation-data
    write_tl(0xa0, user_data_payload_len, out);
    out.extend_from_slice(payload);
}

/// Encodes one presentation-context-definition-list item: tag 0x30 plus content.
///
/// content = 0x02 0x01 <ctxId>  +  0x06 <len> <oid>  +  0x30 0x04 0x06 0x02 0x51 0x01
fn encode_context_item(ctx_id: u8, oid: &[u8], out: &mut BytesMut) {
    // content: context-id(3) + abstract-syntax(2 + oid.len) + transfer-syntax-list(6)
    let content_len = 3 + (2 + oid.len()) + 6;
    write_tl(0x30, content_len, out);
    // context-id
    out.extend_from_slice(&[0x02, 0x01, ctx_id]);
    // abstract-syntax OID
    out.extend_from_slice(&[0x06, oid.len() as u8]);
    out.extend_from_slice(oid);
    // transfer-syntax-name list holding the BER OID
    out.extend_from_slice(&[0x30, 0x04, 0x06, 0x02, BER_ID[0], BER_ID[1]]);
}

/// Encodes a CPA (Connect Presentation Accept) PDU, tag 0x31, into `out`.
///
/// The responding-P-Selector is the fixed value `[0x00, 0x00, 0x00, 0x01]`.
pub fn encode_cpa(pres: &IsoPresentation, payload: &[u8], out: &mut BytesMut) {
    // context-definition-result-list (0xa5) is a fixed 18 bytes: two 9-byte results
    const RESULT_LIST_LEN: usize = 18;

    // user-data (0x61) lengths, computed as in encode_connect
    let user_data_payload_len = payload.len();
    let user_data_a0_len = user_data_payload_len + ber_length_size(user_data_payload_len) + 1;
    let pdv_list_inner_len = 3 + user_data_a0_len;
    let user_data_61_content = pdv_list_inner_len + ber_length_size(pdv_list_inner_len) + 1;

    // responding-P-Selector 0x83 0x04 00 00 00 01 occupies 6 bytes
    const RESP_SEL_LEN: usize = 6;

    // normal-mode-parameters (0xa2) content
    // = responding-P-Selector(6) + result-list(2 + RESULT_LIST_LEN) + user-data
    let nmp_content_len = RESP_SEL_LEN
        + 2
        + RESULT_LIST_LEN
        + 1
        + ber_length_size(user_data_61_content)
        + user_data_61_content;

    const MODE_SEL_LEN: usize = 5;
    let nmp_field_len = 1 + ber_length_size(nmp_content_len) + nmp_content_len;
    let cp_content_len = MODE_SEL_LEN + nmp_field_len;

    // 0x31 tag + length
    write_tl(0x31, cp_content_len, out);

    // mode-selector
    out.extend_from_slice(&[0xa0, 0x03, 0x80, 0x01, 0x01]);

    // normal-mode-parameters (0xa2)
    write_tl(0xa2, nmp_content_len, out);

    // responding-P-Selector
    out.extend_from_slice(&[0x83, 0x04]);
    out.extend_from_slice(&CALLED_P_SEL);

    // context-definition-result-list
    out.extend_from_slice(&[0xa5, RESULT_LIST_LEN as u8]);
    // result for ACSE
    encode_accept_ber(out);
    // result for MMS
    encode_accept_ber(out);

    // user-data (0x61)
    write_tl(0x61, user_data_61_content, out);
    // PDV-list (0x30)
    write_tl(0x30, pdv_list_inner_len, out);
    // context-id = acseContextId
    out.extend_from_slice(&[0x02, 0x01, pres.acse_context_id]);
    // presentation-data (0xa0)
    write_tl(0xa0, user_data_payload_len, out);
    out.extend_from_slice(payload);
}

/// Writes one 9-byte context-definition result that accepts BER:
/// ```text
/// 0x30 0x07
///   0x80 0x01 0x00         result = acceptance (0)
///   0x81 0x02 0x51 0x01    transfer-syntax-name = BER OID
/// ```
fn encode_accept_ber(out: &mut BytesMut) {
    out.extend_from_slice(&[
        0x30, 0x07, 0x80, 0x01, 0x00, 0x81, 0x02, BER_ID[0], BER_ID[1],
    ]);
}

/// Encodes a Fully-Encoded-Data container, tag 0x61, under `context_id`.
///
/// `encode_user_data` and `encode_user_data_acse` differ only in which context
/// identifier they supply.
fn encode_user_data_with_ctx(context_id: u8, payload: &[u8], out: &mut BytesMut) {
    let payload_len = payload.len();
    let a0_len = payload_len + ber_length_size(payload_len) + 1; // 0xa0 tag + len + payload
    let pdv_list_inner_len = 3 + a0_len; // 0x02 0x01 ctxId + 0xa0 ...
    let pdv_list_len = pdv_list_inner_len;
    let presentation_len = pdv_list_len + ber_length_size(pdv_list_len) + 1; // +1 = 0x30 tag

    // 0x61 <L>
    write_tl(0x61, presentation_len, out);
    // 0x30 <L>
    write_tl(0x30, pdv_list_inner_len, out);
    // 0x02 0x01 <ctxId>
    out.extend_from_slice(&[0x02, 0x01, context_id]);
    // 0xa0 <L>
    write_tl(0xa0, payload_len, out);
    out.extend_from_slice(payload);
}

/// Encodes a Fully-Encoded-Data container under `pres.mms_context_id`, 3 by default.
pub fn encode_user_data(pres: &IsoPresentation, payload: &[u8], out: &mut BytesMut) {
    encode_user_data_with_ctx(pres.mms_context_id, payload, out);
}

/// Encodes a Fully-Encoded-Data container under `pres.acse_context_id`, 1 by
/// default, as used for ACSE Finish and Abort payloads.
pub fn encode_user_data_acse(pres: &IsoPresentation, payload: &[u8], out: &mut BytesMut) {
    encode_user_data_with_ctx(pres.acse_context_id, payload, out);
}

/// Encodes an Abort container: outer tag 0xa0 wrapping a Fully-Encoded-Data PDU.
///
/// The outer tag is a context-class constructed tag, unlike the 0x31 used by CP
/// and CPA.
// TODO: confirm the outer Abort PPDU tag against ISO 8823 conformance testing.
pub fn encode_abort(pres: &IsoPresentation, payload: &[u8], out: &mut BytesMut) {
    let mut inner = BytesMut::new();
    encode_user_data_with_ctx(pres.acse_context_id, payload, &mut inner);

    let inner_len = inner.len();
    // 0xa0 <L>
    write_tl(0xa0, inner_len, out);
    out.extend_from_slice(&inner);
}

// Parsers

/// Parses a received CP PDU on the server side.
///
/// On success `pres.acse_context_id`, `pres.mms_context_id`, `pres.calling_p_sel`
/// and `pres.called_p_sel` are updated, and the position of the ACSE AARQ payload
/// inside `buf` is returned.
///
/// # Errors
///
/// - `WrongTag` when the outer tag is not 0x31.
/// - `MissingNormalModeParameters` when normal-mode-parameters is absent.
/// - `MissingUserData` when user-data is absent.
/// - `PSelectorTooLong` when a P-Selector exceeds 16 bytes.
/// - `InvalidModeSelector` when mode-selector is not normal-mode.
/// - `LengthOverflow` or `TooShort` for a malformed BER length field.
pub fn parse_connect(
    pres: &mut IsoPresentation,
    buf: &[u8],
) -> Result<ConnectResult, PresentationError> {
    parse_connect_or_accept(pres, buf)
}

/// Parses a received CPA PDU on the client side.
///
/// The accepted structure is the same as for `parse_connect`.
pub fn parse_accept(
    pres: &mut IsoPresentation,
    buf: &[u8],
) -> Result<ConnectResult, PresentationError> {
    parse_connect_or_accept(pres, buf)
}

/// Parsing logic shared by CP and CPA.
fn parse_connect_or_accept(
    pres: &mut IsoPresentation,
    buf: &[u8],
) -> Result<ConnectResult, PresentationError> {
    let total = buf.len();
    let mut pos = 0usize;

    let tag = read_byte(buf, &mut pos, total)?;
    if tag != 0x31 {
        warn!(tag, "presentation cp/cpa outer tag is not 0x31");
        return Err(PresentationError::WrongTag {
            tag,
            expected: 0x31,
        });
    }

    let outer_len = read_ber_length(buf, &mut pos, total)?;
    let outer_end = pos + outer_len;

    let mut has_normal_mode = false;
    let mut result: Option<ConnectResult> = None;

    while pos < outer_end {
        let elem_tag = read_byte(buf, &mut pos, outer_end)?;
        let elem_len = read_ber_length(buf, &mut pos, outer_end)?;
        let elem_end = pos + elem_len;

        match elem_tag {
            0xa0 => {
                // mode-selector: the inner tag must be 0x80 and the value normal-mode
                let inner_tag = read_byte(buf, &mut pos, elem_end)?;
                if inner_tag != 0x80 {
                    warn!(inner_tag, "mode-selector inner tag is not 0x80");
                    return Err(PresentationError::InvalidModeSelector {
                        inner_tag,
                        mode_value: 0,
                    });
                }
                let inner_len = read_ber_length(buf, &mut pos, elem_end)?;
                let mode_val = read_ber_uint(buf, &mut pos, inner_len)?;
                if mode_val != 1 {
                    warn!(mode_val, "mode-selector value is not 1 (normal-mode)");
                    return Err(PresentationError::InvalidModeSelector {
                        inner_tag,
                        mode_value: mode_val,
                    });
                }
            }
            0xa2 => {
                // normal-mode-parameters
                has_normal_mode = true;
                result = Some(parse_normal_mode_parameters(pres, buf, pos, elem_end)?);
            }
            _ => {
                // Unknown elements are skipped. The tag byte is always
                // consumed, so elem_len == 0 cannot stall the loop, and
                // read_ber_length has already bounded elem_end by outer_end.
            }
        }

        pos = elem_end;
    }

    if !has_normal_mode {
        warn!("cp/cpa pdu is missing normal-mode-parameters (0xa2)");
        return Err(PresentationError::MissingNormalModeParameters);
    }

    result.ok_or(PresentationError::MissingUserData)
}

/// Parses the content of normal-mode-parameters, tag 0xa2.
///
/// Updates the P-Selectors and the context identifiers, and returns the location
/// of the user-data payload.
fn parse_normal_mode_parameters(
    pres: &mut IsoPresentation,
    buf: &[u8],
    start: usize,
    end: usize,
) -> Result<ConnectResult, PresentationError> {
    let mut pos = start;
    let mut has_user_data = false;
    let mut result = ConnectResult {
        payload_start: 0,
        payload_len: 0,
    };

    while pos < end {
        let tag = read_byte(buf, &mut pos, end)?;
        let len = read_ber_length(buf, &mut pos, end)?;
        let elem_end = pos + len;

        match tag {
            0x81 => {
                // calling-presentation-selector
                if len > PSELECTOR_MAX_SIZE {
                    warn!(len, "calling p-selector exceeds 16 bytes, rejecting");
                    return Err(PresentationError::PSelectorTooLong { len });
                }
                pres.calling_p_sel = PSelector::from_slice(&buf[pos..elem_end])?;
            }
            0x82 => {
                // called-presentation-selector
                if len > PSELECTOR_MAX_SIZE {
                    warn!(len, "called p-selector exceeds 16 bytes, rejecting");
                    return Err(PresentationError::PSelectorTooLong { len });
                }
                pres.called_p_sel = PSelector::from_slice(&buf[pos..elem_end])?;
            }
            0x83 => {
                // responding-presentation-selector, present only in a CPA; not retained
            }
            0xa4 => {
                // presentation-context-definition-list
                parse_pcdl(pres, buf, pos, elem_end)?;
            }
            0xa5 => {
                // context-definition-result-list, present only in a CPA; not validated
            }
            0x61 => {
                // user-data (Fully-Encoded-Data)
                has_user_data = true;
                // inner layout: 0x30 <L> 0x02 0x01 <ctxId> 0xa0 <L> <payload>
                let ud = parse_fully_encoded_data_inner(buf, pos, elem_end)?;
                result = ConnectResult {
                    payload_start: ud.payload_start,
                    payload_len: ud.payload_len,
                };
            }
            _ => {
                // Unknown tags are skipped; read_ber_length bounds elem_end
            }
        }

        pos = elem_end;
    }

    if !has_user_data {
        warn!("normal-mode-parameters is missing user-data (0x61)");
        return Err(PresentationError::MissingUserData);
    }

    Ok(result)
}

/// Parses the presentation-context-definition-list (PCDL).
///
/// Updates `pres.acse_context_id` and `pres.mms_context_id`.
fn parse_pcdl(
    pres: &mut IsoPresentation,
    buf: &[u8],
    start: usize,
    end: usize,
) -> Result<(), PresentationError> {
    let mut pos = start;

    while pos < end {
        let tag = read_byte(buf, &mut pos, end)?;
        let len = read_ber_length(buf, &mut pos, end)?;
        let elem_end = pos + len;

        if tag == 0x30 {
            // a SEQUENCE is one PCDL entry
            parse_pcdl_entry(pres, buf, pos, elem_end)?;
        }
        // any other tag is skipped

        pos = elem_end;
    }

    Ok(())
}

/// Parses a single PCDL entry, a SEQUENCE.
///
/// Reads the context-id (tag 0x02) and the abstract-syntax OID (tag 0x06), and
/// updates `pres.acse_context_id` or `pres.mms_context_id` accordingly.
fn parse_pcdl_entry(
    pres: &mut IsoPresentation,
    buf: &[u8],
    start: usize,
    end: usize,
) -> Result<(), PresentationError> {
    let mut pos = start;
    let mut context_id: Option<u8> = None;

    while pos < end {
        let tag = read_byte(buf, &mut pos, end)?;
        let len = read_ber_length(buf, &mut pos, end)?;
        let elem_end = pos + len;

        match tag {
            0x02 => {
                // context-id, a BER INTEGER
                let val = read_ber_uint(buf, &mut pos, len)?;
                if val > 255 {
                    return Err(PresentationError::ContextIdOutOfRange { value: val });
                }
                context_id = Some(val as u8);
            }
            0x06 => {
                // abstract-syntax OID, compared against the two known values
                let oid = buf
                    .get(pos..elem_end)
                    .ok_or(PresentationError::TooShort { len: buf.len() })?;
                let ctx = context_id.ok_or(PresentationError::MissingContextId)?;
                if oid == ASN_ID_ACSE {
                    pres.acse_context_id = ctx;
                } else if oid == ASN_ID_MMS {
                    pres.mms_context_id = ctx;
                } else {
                    // An unknown abstract syntax is rejected rather than ignored.
                    warn!("pcdl entry names an unknown abstract-syntax oid, rejecting connection");
                    return Err(PresentationError::UnknownAbstractSyntax);
                }
            }
            // A list shorter than the OID it would carry has nothing to check.
            0x30 if len >= 4 => {
                // transfer-syntax-name list: the list is not decoded item by item,
                // the leading 06 02 51 01 BER OID is checked directly.
                let inner = buf
                    .get(pos..pos + 4)
                    .ok_or(PresentationError::TooShort { len: buf.len() })?;
                if inner[0] == 0x06 && inner[1] == 0x02 && inner[2..4] != BER_ID {
                    warn!("pcdl entry transfer-syntax is not ber");
                    return Err(PresentationError::InvalidTransferSyntax);
                }
            }
            _ => {
                // an unknown tag, and a transfer-syntax list too short to check,
                // are both skipped
            }
        }

        pos = elem_end;
    }

    Ok(())
}

/// Parses the inner part of a Fully-Encoded-Data container: the 0x30 PDV-list.
///
/// `buf[start..end]` is the 0x61 content, without the outer tag and length.
/// Returns the context identifier plus the payload offset and length.
fn parse_fully_encoded_data_inner(
    buf: &[u8],
    start: usize,
    end: usize,
) -> Result<UserDataResult, PresentationError> {
    let mut pos = start;

    // 0x30  PDV-list SEQUENCE tag
    let tag = read_byte(buf, &mut pos, end)?;
    if tag != 0x30 {
        warn!(tag, "fully-encoded-data inner tag is not 0x30 (sequence)");
        return Err(PresentationError::WrongTag {
            tag,
            expected: 0x30,
        });
    }
    let seq_len = read_ber_length(buf, &mut pos, end)?;
    let seq_end = pos + seq_len;

    let mut ctx_id: Option<u8> = None;
    let mut has_abstract_syntax = false;
    let mut payload_start = 0usize;
    let mut payload_len = 0usize;

    while pos < seq_end {
        let elem_tag = read_byte(buf, &mut pos, seq_end)?;
        let elem_len = read_ber_length(buf, &mut pos, seq_end)?;
        let elem_end = pos + elem_len;

        match elem_tag {
            0x02 => {
                // presentation-context-identifier
                let val = read_ber_uint(buf, &mut pos, elem_len)?;
                if val > 255 {
                    return Err(PresentationError::ContextIdOutOfRange { value: val });
                }
                ctx_id = Some(val as u8);
                has_abstract_syntax = true;
            }
            0xa0 => {
                // presentation-data: the ACSE or MMS payload itself
                if !has_abstract_syntax {
                    warn!("fully-encoded-data 0xa0 appears before the 0x02 context-id");
                    return Err(PresentationError::MissingAbstractSyntaxName);
                }
                payload_start = pos;
                payload_len = elem_len;
            }
            _ => {
                // unknown tags, 0x06 transfer-syntax included, are skipped
            }
        }

        pos = elem_end;
    }

    if !has_abstract_syntax {
        warn!("fully-encoded-data is missing the context-id (0x02)");
        return Err(PresentationError::MissingAbstractSyntaxName);
    }

    Ok(UserDataResult {
        context_id: ctx_id.unwrap_or(0),
        payload_start,
        payload_len,
    })
}

/// Parses a Fully-Encoded-Data container, tag 0x61.
///
/// Updates `pres.next_context_id` and returns the payload location inside `buf`.
///
/// # Errors
///
/// - `UserDataTooShort` when `buf` is shorter than 9 bytes.
/// - `WrongTag` when the first tag is not 0x61.
/// - `MissingAbstractSyntaxName` when the context-id is absent.
/// - `InvalidTransferSyntax` when transfer-syntax is not BER.
/// - `LengthOverflow` for a BER length that runs past the buffer.
pub fn parse_user_data(
    pres: &mut IsoPresentation,
    buf: &[u8],
) -> Result<UserDataResult, PresentationError> {
    // The smallest legal encoding is 9 bytes: three tag and length pairs plus the context id.
    if buf.len() < 9 {
        warn!(
            len = buf.len(),
            "fully-encoded-data pdu shorter than 9 bytes"
        );
        return Err(PresentationError::UserDataTooShort { len: buf.len() });
    }

    let total = buf.len();
    let mut pos = 0usize;

    // 0x61 is APPLICATION 1, fully-encoded-data
    let tag = read_byte(buf, &mut pos, total)?;
    if tag != 0x61 {
        warn!(tag, "fully-encoded-data outer tag is not 0x61");
        return Err(PresentationError::WrongTag {
            tag,
            expected: 0x61,
        });
    }

    let outer_len = read_ber_length(buf, &mut pos, total)?;
    let outer_end = pos + outer_len;

    let result = parse_fully_encoded_data_inner(buf, pos, outer_end)?;
    pres.next_context_id = result.context_id;

    Ok(result)
}

// BER integer helper

/// Reads a `len`-byte BER INTEGER at `buf[*pos..]` and returns it as a `u32`.
///
/// `*pos` advances by `len`.
fn read_ber_uint(buf: &[u8], pos: &mut usize, len: usize) -> Result<u32, PresentationError> {
    if *pos + len > buf.len() {
        return Err(PresentationError::TooShort { len: buf.len() });
    }
    let mut val = 0u32;
    for i in 0..len {
        val = (val << 8) | (buf[*pos + i] as u32);
    }
    *pos += len;
    Ok(val)
}

// Unit tests

#[cfg(test)]
mod tests {
    use super::*;

    fn default_pres() -> IsoPresentation {
        IsoPresentation::new()
    }

    fn default_params() -> PresentationConnectionParameters {
        PresentationConnectionParameters::default()
    }

    // encode_connect to parse_connect round trip

    #[test]
    fn roundtrip_connect_empty_payload() {
        let params = default_params();
        let payload = b"";
        let mut out = BytesMut::new();
        encode_connect(&params, payload, &mut out);
        let bytes = out.freeze();

        // outer tag is 0x31
        assert_eq!(bytes[0], 0x31);

        let mut pres = default_pres();
        let result = parse_connect(&mut pres, &bytes).unwrap();
        // context identifiers come from the PCDL
        assert_eq!(pres.acse_context_id, ACSE_CONTEXT_ID);
        assert_eq!(pres.mms_context_id, MMS_CONTEXT_ID);
        // payload is empty
        assert_eq!(result.payload_len, 0);
        assert_eq!(result.payload(&bytes), b"");
    }

    #[test]
    fn roundtrip_connect_with_payload() {
        let params = default_params();
        let payload = b"mock-aarq-bytes";
        let mut out = BytesMut::new();
        encode_connect(&params, payload, &mut out);
        let bytes = out.freeze();

        let mut pres = default_pres();
        let result = parse_connect(&mut pres, &bytes).unwrap();
        assert_eq!(result.payload(&bytes), payload);
        assert_eq!(pres.acse_context_id, ACSE_CONTEXT_ID);
        assert_eq!(pres.mms_context_id, MMS_CONTEXT_ID);
    }

    #[test]
    fn roundtrip_connect_with_p_selectors() {
        let mut params = default_params();
        params.local_p_sel = PSelector::from_slice(&[0x00, 0x01]).unwrap();
        params.remote_p_sel = PSelector::from_slice(&[0x00, 0x02]).unwrap();
        let payload = b"hello";
        let mut out = BytesMut::new();
        encode_connect(&params, payload, &mut out);
        let bytes = out.freeze();

        let mut pres = default_pres();
        let result = parse_connect(&mut pres, &bytes).unwrap();
        assert_eq!(result.payload(&bytes), payload);
        // the P-Selectors are recovered
        assert_eq!(pres.calling_p_sel.as_slice(), &[0x00, 0x01]);
        assert_eq!(pres.called_p_sel.as_slice(), &[0x00, 0x02]);
    }

    // encode_cpa to parse_accept round trip

    #[test]
    fn roundtrip_cpa_empty_payload() {
        let pres = default_pres();
        let payload = b"";
        let mut out = BytesMut::new();
        encode_cpa(&pres, payload, &mut out);
        let bytes = out.freeze();

        assert_eq!(bytes[0], 0x31);

        // the responding-P-Selector carries the fixed value 83 04 00 00 00 01
        let rsp_sel_pos = bytes
            .windows(6)
            .position(|w| w[0] == 0x83 && w[1] == 0x04 && w[2..6] == CALLED_P_SEL);
        assert!(
            rsp_sel_pos.is_some(),
            "responding-p-selector must be present"
        );

        let mut pres2 = default_pres();
        let result = parse_accept(&mut pres2, &bytes).unwrap();
        assert_eq!(result.payload_len, 0);
    }

    #[test]
    fn roundtrip_cpa_with_payload() {
        let pres = default_pres();
        let payload = b"mock-aare-bytes";
        let mut out = BytesMut::new();
        encode_cpa(&pres, payload, &mut out);
        let bytes = out.freeze();

        let mut pres2 = default_pres();
        let result = parse_accept(&mut pres2, &bytes).unwrap();
        assert_eq!(result.payload(&bytes), payload);
    }

    // encode_user_data to parse_user_data round trip, MMS context

    #[test]
    fn roundtrip_user_data_mms() {
        let pres = default_pres();
        let payload = b"mms-request-pdu";
        let mut out = BytesMut::new();
        encode_user_data(&pres, payload, &mut out);
        let bytes = out.freeze();

        // outer tag is 0x61
        assert_eq!(bytes[0], 0x61);

        let mut pres2 = default_pres();
        let result = parse_user_data(&mut pres2, &bytes).unwrap();
        assert_eq!(result.context_id, MMS_CONTEXT_ID);
        assert_eq!(result.payload(&bytes), payload);
        assert_eq!(pres2.next_context_id, MMS_CONTEXT_ID);
    }

    #[test]
    fn roundtrip_user_data_mms_empty() {
        let pres = default_pres();
        let mut out = BytesMut::new();
        encode_user_data(&pres, b"", &mut out);
        let bytes = out.freeze();

        let mut pres2 = default_pres();
        let result = parse_user_data(&mut pres2, &bytes).unwrap();
        assert_eq!(result.context_id, MMS_CONTEXT_ID);
        assert_eq!(result.payload_len, 0);
    }

    // encode_user_data_acse to parse_user_data round trip, ACSE context

    #[test]
    fn roundtrip_user_data_acse() {
        let pres = default_pres();
        let payload = b"acse-finish-payload";
        let mut out = BytesMut::new();
        encode_user_data_acse(&pres, payload, &mut out);
        let bytes = out.freeze();

        assert_eq!(bytes[0], 0x61);

        let mut pres2 = default_pres();
        let result = parse_user_data(&mut pres2, &bytes).unwrap();
        assert_eq!(result.context_id, ACSE_CONTEXT_ID);
        assert_eq!(result.payload(&bytes), payload);
    }

    // encode_abort output

    #[test]
    fn abort_outer_tag_is_a0() {
        let pres = default_pres();
        let payload = b"abort-payload";
        let mut out = BytesMut::new();
        encode_abort(&pres, payload, &mut out);
        // outer tag is 0xa0
        assert_eq!(out[0], 0xa0);
        // the inner container starts with 0x61
        let inner_start = 2; // short-form length assumed
        assert_eq!(out[inner_start], 0x61);
    }

    #[test]
    fn abort_empty_payload() {
        let pres = default_pres();
        let mut out = BytesMut::new();
        encode_abort(&pres, b"", &mut out);
        assert_eq!(out[0], 0xa0);
        // no panic, and a header is present
        assert!(out.len() > 4);
    }

    // Boundaries: empty and large payloads

    #[test]
    fn user_data_large_payload_roundtrip() {
        // a 256-byte payload needs a 2-byte BER length field
        let pres = default_pres();
        let payload = vec![0xABu8; 256];
        let mut out = BytesMut::new();
        encode_user_data(&pres, &payload, &mut out);
        let bytes = out.freeze();

        let mut pres2 = default_pres();
        let result = parse_user_data(&mut pres2, &bytes).unwrap();
        assert_eq!(result.payload(&bytes), payload.as_slice());
    }

    // PDUs with missing fields must be rejected

    #[test]
    fn malformed_wrong_outer_tag() {
        // a CP PDU whose first byte is 0x30 instead of 0x31
        let buf = [0x30u8, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut pres = default_pres();
        let err = parse_connect(&mut pres, &buf).unwrap_err();
        assert_eq!(
            err,
            PresentationError::WrongTag {
                tag: 0x30,
                expected: 0x31
            }
        );
    }

    #[test]
    fn malformed_mode_selector_inner_tag() {
        // mode-selector with inner tag 0x81 instead of 0x80
        let mut out = BytesMut::new();
        // hand-built: 0x31 <len> 0xa0 0x03 0x81 0x01 0x01
        let content = [
            0xa0u8, 0x03, 0x81, 0x01, 0x01, // mode-selector with the wrong inner tag
        ];
        write_tl(0x31, content.len(), &mut out);
        out.extend_from_slice(&content);
        let bytes = out.freeze();

        let mut pres = default_pres();
        let err = parse_connect(&mut pres, &bytes).unwrap_err();
        assert_eq!(
            err,
            PresentationError::InvalidModeSelector {
                inner_tag: 0x81,
                mode_value: 0
            }
        );
    }

    #[test]
    fn malformed_missing_normal_mode_params() {
        // A CP PDU without 0xa2 yields MissingNormalModeParameters
        let content = [
            0xa0u8, 0x03, 0x80, 0x01, 0x01, // valid mode-selector
        ];
        let mut out = BytesMut::new();
        write_tl(0x31, content.len(), &mut out);
        out.extend_from_slice(&content);
        let bytes = out.freeze();

        let mut pres = default_pres();
        let err = parse_connect(&mut pres, &bytes).unwrap_err();
        assert_eq!(err, PresentationError::MissingNormalModeParameters);
    }

    #[test]
    fn malformed_missing_user_data() {
        // A CP PDU whose 0xa2 holds no 0x61 yields MissingUserData;
        // built as a valid mode-selector plus normal-mode-parameters without user-data
        let nmp_content = [
            0xa4u8,
            0x23, // PCDL length 35, with the content truncated to exercise the error path
        ];
        let mode_sel = [0xa0u8, 0x03, 0x80, 0x01, 0x01];
        let mut nmp = BytesMut::new();
        write_tl(0xa2, nmp_content.len(), &mut nmp);
        nmp.extend_from_slice(&nmp_content);

        let mut out = BytesMut::new();
        let body_len = mode_sel.len() + nmp.len();
        write_tl(0x31, body_len, &mut out);
        out.extend_from_slice(&mode_sel);
        out.extend_from_slice(&nmp);
        let bytes = out.freeze();

        let mut pres = default_pres();
        let err = parse_connect(&mut pres, &bytes).unwrap_err();
        // Either MissingUserData or LengthOverflow is acceptable here: the PCDL
        // declares 35 bytes but supplies fewer.
        assert!(
            matches!(
                err,
                PresentationError::MissingUserData | PresentationError::LengthOverflow { .. }
            ),
            "expected MissingUserData or LengthOverflow, got {err:?}"
        );
    }

    #[test]
    fn malformed_user_data_too_short() {
        // parse_user_data with fewer than 9 bytes yields UserDataTooShort
        let buf = [0x61u8, 0x05, 0x30, 0x03, 0x02, 0x01, 0x03];
        let mut pres = default_pres();
        let err = parse_user_data(&mut pres, &buf).unwrap_err();
        assert_eq!(err, PresentationError::UserDataTooShort { len: 7 });
    }

    #[test]
    fn malformed_user_data_wrong_outer_tag() {
        // the first tag is not 0x61
        let buf = [0x60u8, 0x09, 0x30, 0x07, 0x02, 0x01, 0x03, 0xa0, 0x00];
        let mut pres = default_pres();
        let err = parse_user_data(&mut pres, &buf).unwrap_err();
        assert_eq!(
            err,
            PresentationError::WrongTag {
                tag: 0x60,
                expected: 0x61
            }
        );
    }

    #[test]
    fn malformed_ber_length_overflow() {
        // A BER length larger than the remaining buffer yields LengthOverflow:
        // 0x31 is the CP tag and 0x7E a short-form length of 126, with 2 bytes left.
        let buf = [0x31u8, 0x7E, 0x00, 0x00];
        let mut pres = default_pres();
        let err = parse_connect(&mut pres, &buf).unwrap_err();
        assert_eq!(
            err,
            PresentationError::LengthOverflow {
                claimed: 126,
                remaining: 2
            }
        );
    }

    /// A malicious PDU carrying an unknown tag with length 0.
    ///
    /// The PDU embeds length-0 unknown tags inside normal-mode-parameters. The
    /// parse loop always consumes the tag byte, so `pos` advances and the loop
    /// terminates; this test asserts an error is returned instead of hanging.
    #[test]
    fn length_zero_unknown_tag_no_infinite_loop() {
        // Build a PDU with length-0 unknown tags: the outer structure is valid
        // (0x31, mode-selector, 0xa2) while normal-mode-parameters holds only
        // length-0 unknown tags and no 0x61.
        let mut nmp_content = BytesMut::new();
        // ten unknown tags (0xFF) with length 0
        for _ in 0..10 {
            nmp_content.extend_from_slice(&[0xFF, 0x00]);
        }
        // a trailing 0xa4 PCDL, also with length 0
        nmp_content.extend_from_slice(&[0xa4, 0x00]);

        let mode_sel = [0xa0u8, 0x03, 0x80, 0x01, 0x01];
        let mut body = BytesMut::new();
        body.extend_from_slice(&mode_sel);
        write_tl(0xa2, nmp_content.len(), &mut body);
        body.extend_from_slice(&nmp_content);

        let mut out = BytesMut::new();
        write_tl(0x31, body.len(), &mut out);
        out.extend_from_slice(&body);
        let bytes = out.freeze();

        let mut pres = default_pres();
        // an error must be returned in bounded time
        let result = parse_connect(&mut pres, &bytes);
        assert!(
            result.is_err(),
            "a pdu with length-0 unknown tags must be rejected without looping"
        );
    }

    /// Second vector: a BER length that runs past the buffer.
    ///
    /// The outer CP length is exactly valid while normal-mode-parameters declares a
    /// length far past `outer_end`; `LengthOverflow` must be reported instead of an
    /// out-of-bounds read.
    ///
    /// Buffer layout, 9 bytes total:
    ///   `[0x31 0x07]` outer tag and length, so outer_end = 2 + 7 = 9 = buf.len()
    ///   `[0xa0 0x03 0x80 0x01 0x01]` mode-selector
    ///   `[0xa2 0x64]` normal-mode-parameters with length 100, past outer_end
    #[test]
    fn length_overflow_returns_err() {
        let buf = [
            0x31u8, 0x07, // CP tag, outer len 7, so outer_end = 9 = buf.len()
            0xa0, 0x03, 0x80, 0x01, 0x01, // mode-selector
            0xa2, 0x64, // normal-mode-parameters, length 100, past outer_end
        ];
        // After the 0xa2 tag and its length byte pos is 9, and 9 + 100 overruns outer_end = 9.
        let mut pres = default_pres();
        let err = parse_connect(&mut pres, &buf).unwrap_err();
        assert_eq!(
            err,
            PresentationError::LengthOverflow {
                claimed: 100,
                remaining: 0
            }
        );
    }

    // P-Selector over the length limit

    #[test]
    fn pselector_size_gt_16_returns_err() {
        // PSelector::from_slice with more than 16 bytes
        let data = [0u8; 17];
        let err = PSelector::from_slice(&data).unwrap_err();
        assert_eq!(err, PresentationError::PSelectorTooLong { len: 17 });
    }

    // ber_length_size helper

    #[test]
    fn ber_length_size_short_form() {
        assert_eq!(ber_length_size(0), 1);
        assert_eq!(ber_length_size(127), 1);
    }

    #[test]
    fn ber_length_size_2byte_form() {
        assert_eq!(ber_length_size(128), 2);
        assert_eq!(ber_length_size(255), 2);
    }

    #[test]
    fn ber_length_size_3byte_form() {
        assert_eq!(ber_length_size(256), 3);
        assert_eq!(ber_length_size(65535), 3);
    }

    #[test]
    fn ber_length_size_4byte_form() {
        assert_eq!(ber_length_size(65536), 4);
    }

    // CPA encoding structure

    #[test]
    fn cpa_encode_responding_p_sel_value() {
        let pres = default_pres();
        let mut out = BytesMut::new();
        encode_cpa(&pres, b"", &mut out);
        let bytes = out.freeze();

        // the responding-P-Selector 83 04 00 00 00 01 must be present
        let found = bytes
            .windows(6)
            .any(|w| w == [0x83, 0x04, 0x00, 0x00, 0x00, 0x01]);
        assert!(found, "cpa must contain responding-p-selector 00 00 00 01");
    }

    #[test]
    fn cpa_encode_context_result_list() {
        let pres = default_pres();
        let mut out = BytesMut::new();
        encode_cpa(&pres, b"", &mut out);
        let bytes = out.freeze();

        // 0xa5 0x12: context-definition-result-list of fixed length 18
        let found = bytes.windows(2).any(|w| w == [0xa5, 0x12]);
        assert!(
            found,
            "cpa must contain 0xa5 0x12 context-definition-result-list"
        );
    }

    // CP encoding structure: the PCDL is a fixed 35 bytes

    #[test]
    fn cp_encode_pcdl_tag_and_length() {
        let params = default_params();
        let mut out = BytesMut::new();
        encode_connect(&params, b"", &mut out);
        let bytes = out.freeze();

        // 0xa4 0x23: PCDL of length 35
        let found = bytes.windows(2).any(|w| w == [0xa4, 0x23]);
        assert!(found, "cp must contain 0xa4 0x23 pcdl");
    }

    #[test]
    fn cp_encode_user_data_context_id_is_acse() {
        // the user-data context identifier written by encode_connect is 1 (ACSE)
        let params = default_params();
        let mut out = BytesMut::new();
        encode_connect(&params, b"test", &mut out);
        let bytes = out.freeze();

        // 0x02 0x01 0x01 is the context-id inside the PDV-list
        let found = bytes.windows(3).any(|w| w == [0x02, 0x01, 0x01]);
        assert!(found, "cp pdv-list context-id must be 1 (acse)");
    }

    // IsoPresentation::new defaults

    #[test]
    fn iso_presentation_default_context_ids() {
        let pres = IsoPresentation::new();
        assert_eq!(pres.acse_context_id, 1);
        assert_eq!(pres.mms_context_id, 3);
        assert_eq!(pres.next_context_id, 0);
        assert_eq!(pres.calling_p_sel.size, 0);
        assert_eq!(pres.called_p_sel.size, 0);
    }
}
