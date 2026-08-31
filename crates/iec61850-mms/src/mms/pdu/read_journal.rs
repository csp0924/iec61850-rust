//! MMS ReadJournal request and response PDUs.
//!
//! ## Wire format
//!
//! ### Request
//!
//! ```text
//! 0xa0 <len>                   -- ConfirmedRequestPdu [0]
//!   0x02 <len> <id>            -- invokeID INTEGER
//!   0xbf 0x41 <len>            -- readJournal [65] IMPLICIT SEQUENCE  (long-form context tag)
//!     0xa0 <len>               -- journalName [0] EXPLICIT
//!       0xa1 <len>             -- domain-specific [1] IMPLICIT
//!         0x1a <len> <bytes>   -- domainId VisibleString
//!         0x1a <len> <bytes>   -- itemId VisibleString
//!     -- form A, a time range:
//!     0xa1 <len>               -- rangeStartSpec [1] EXPLICIT
//!       0x80 <len> <BinaryTime> -- startingTime
//!     0xa2 <len>               -- rangeStopSpec  [2] EXPLICIT
//!       0x80 <len> <BinaryTime> -- endingTime
//!     -- or form B, starting after an entry:
//!     0xa5 <len>               -- entryToStartAfter [5] EXPLICIT
//!       0x80 <len> <BinaryTime> -- timeSpecification
//!       0x81 <len> <bytes>      -- entrySpecification OCTET STRING (8 bytes)
//! ```
//!
//! ### Response
//!
//! ```text
//! 0xa1 <len>                   -- ConfirmedResponsePdu [1]
//!   0x02 <len> <id>            -- invokeID
//!   0xbf 0x41 <len>            -- readJournalResponse [65] IMPLICIT SEQUENCE
//!     0xa0 <len>               -- listOfJournalEntry [0] IMPLICIT SEQUENCE OF
//!       0x30 <len>             -- JournalEntry SEQUENCE, repeated
//!         0x80 8 <8-byte ID>   -- entryID OCTET STRING(8)
//!         0xa1 0x02 0x30 0x00  -- originatingApplication, a fixed empty SEQUENCE
//!         0xa2 <len>           -- entryContent [2] EXPLICIT
//!           0x80 6 <BinaryTime6> -- occurenceTime
//!           0xa2 <len>             -- journalVariables [2] EXPLICIT
//!             0xa1 <len>           -- listOfVariables [1] EXPLICIT SEQUENCE OF
//!               0x30 <len>         -- variable SEQUENCE; each data point takes
//!                                     -- two, one for the value and one for its reason code
//!                 0x80 <len> <utf8> -- dataRef tag (OCTET STRING UTF-8)
//!                 0xa1 <len> <Data> -- valueSpec [1] EXPLICIT, inner = MmsData wire
//!     0x81 1 0x00|0xff         -- moreFollows BOOLEAN  (OPTIONAL)
//! ```
//!
//! ## Interoperability notes
//!
//! - `originatingApplication` is always the four bytes `[0xa1, 0x02, 0x30, 0x00]`,
//!   a `[1]` wrapper around an empty SEQUENCE, emitted as a fixed constant rather
//!   than derived from the association.
//! - `entryToStartAfter.startingTime` is accepted and kept on the wire; the log
//!   storage in this workspace honors both conditions.
//! - The long-form tag `0xbf 0x41` is a context-class constructed identifier whose
//!   five tag-number bits are all ones, 11111, which is what selects the long form;
//!   the tag number continues in the next byte, 0x41, that is 65. One continuation
//!   byte suffices because 65 is below 128.

use super::super::binary_time::{binary_time6_from_epoch_ms, epoch_ms_from_binary_time6};
use super::super::error::MmsError;
use super::common::{DataAccessError, MmsData};
use super::initiate::{decode_length, encode_length};
use crate::compat::prelude::*;
use bytes::BytesMut;

// Tag constants

/// Long-form tag of ReadJournal inside the ConfirmedService CHOICE.
///
/// `0xbf 0x41` is `[65] IMPLICIT SEQUENCE`, context class and constructed.
pub const SERVICE_TAG_READ_JOURNAL: [u8; 2] = [0xbf, 0x41];

/// Upper bound on the length of each journalName part, in bytes.
pub const MAX_JOURNAL_ID_LEN: usize = 64;

/// Size of an EntryID on the wire: exactly 8 bytes.
pub const ENTRY_ID_SIZE: usize = 8;

/// The fixed wire bytes of `originatingApplication`.
const ORIGINATING_APPLICATION_FIXED: [u8; 4] = [0xa1, 0x02, 0x30, 0x00];

// ReadJournalRequest

/// The query range CHOICE of a ReadJournal request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalRange {
    /// Form A: a time range, rangeStartSpec through rangeStopSpec.
    TimeRange {
        /// Start of the range, in epoch milliseconds.
        start_ms: u64,
        /// End of the range, in epoch milliseconds.
        end_ms: u64,
    },
    /// Form B: everything after a given entry, entryToStartAfter.
    StartAfter {
        /// Timestamp to resume from, in epoch milliseconds.
        starting_time_ms: u64,
        /// EntryID, 8 bytes big-endian.
        entry_id: [u8; ENTRY_ID_SIZE],
    },
}

/// An MMS ReadJournalRequest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadJournalRequest {
    /// journalName.domain-specific.domainId, a VisibleString.
    pub domain_id: String,
    /// journalName.domain-specific.itemId, a VisibleString.
    pub item_id: String,
    /// The query range.
    pub range: JournalRange,
}

impl ReadJournalRequest {
    /// Builds a request covering a time range.
    pub fn time_range(
        domain_id: impl Into<String>,
        item_id: impl Into<String>,
        start_ms: u64,
        end_ms: u64,
    ) -> Self {
        Self {
            domain_id: domain_id.into(),
            item_id: item_id.into(),
            range: JournalRange::TimeRange { start_ms, end_ms },
        }
    }

    /// Builds a request starting after a given entry.
    pub fn start_after(
        domain_id: impl Into<String>,
        item_id: impl Into<String>,
        starting_time_ms: u64,
        entry_id: [u8; ENTRY_ID_SIZE],
    ) -> Self {
        Self {
            domain_id: domain_id.into(),
            item_id: item_id.into(),
            range: JournalRange::StartAfter {
                starting_time_ms,
                entry_id,
            },
        }
    }

    /// Encodes the request, including the `0xbf 0x41 <len>` service wrapper.
    ///
    /// The caller adds the ConfirmedRequestPdu invokeID and its outer `0xa0` wrapper.
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut inner = BytesMut::new();
        encode_journal_name(&self.domain_id, &self.item_id, &mut inner);
        match &self.range {
            JournalRange::TimeRange { start_ms, end_ms } => {
                encode_time_range_spec(0xa1, *start_ms, &mut inner);
                encode_time_range_spec(0xa2, *end_ms, &mut inner);
            }
            JournalRange::StartAfter {
                starting_time_ms,
                entry_id,
            } => {
                encode_entry_to_start_after(*starting_time_ms, entry_id, &mut inner);
            }
        }

        buf.extend_from_slice(&SERVICE_TAG_READ_JOURNAL);
        encode_length(inner.len(), buf);
        buf.extend_from_slice(&inner);
    }

    /// Decodes a request; `data` starts at the `0xbf` byte.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        let inner = check_service_tag_and_take(data)?;
        decode_request_inner(inner)
    }
}

fn encode_journal_name(domain_id: &str, item_id: &str, buf: &mut BytesMut) {
    // journalName [0] EXPLICIT -> 0xa0 <len> <ObjectName>
    let mut name_buf = BytesMut::new();
    encode_object_name_domain_specific(domain_id, item_id, &mut name_buf);
    buf.extend_from_slice(&[0xa0]);
    encode_length(name_buf.len(), buf);
    buf.extend_from_slice(&name_buf);
}

fn encode_object_name_domain_specific(domain_id: &str, item_id: &str, buf: &mut BytesMut) {
    // 0xa1 <inner_len> 0x1a <dlen> <domain> 0x1a <ilen> <item>
    let db = domain_id.as_bytes();
    let ib = item_id.as_bytes();
    let inner_len = 2 + db.len() + 2 + ib.len();
    buf.extend_from_slice(&[0xa1]);
    encode_length(inner_len, buf);
    buf.extend_from_slice(&[0x1a]);
    encode_length(db.len(), buf);
    buf.extend_from_slice(db);
    buf.extend_from_slice(&[0x1a]);
    encode_length(ib.len(), buf);
    buf.extend_from_slice(ib);
}

fn encode_time_range_spec(outer_tag: u8, time_ms: u64, buf: &mut BytesMut) {
    // 0xa1 / 0xa2 <len>
    //   0x80 6 <BinaryTime6>
    let bt = binary_time6_from_epoch_ms(time_ms);
    buf.extend_from_slice(&[outer_tag]);
    encode_length(2 + bt.len(), buf);
    buf.extend_from_slice(&[0x80]);
    encode_length(bt.len(), buf);
    buf.extend_from_slice(&bt);
}

fn encode_entry_to_start_after(
    starting_time_ms: u64,
    entry_id: &[u8; ENTRY_ID_SIZE],
    buf: &mut BytesMut,
) {
    // 0xa5 <len>
    //   0x80 6 <BinaryTime6 timeSpecification>
    //   0x81 8 <entryID OctetString>
    let bt = binary_time6_from_epoch_ms(starting_time_ms);
    let inner_len = (2 + bt.len()) + (2 + entry_id.len());
    buf.extend_from_slice(&[0xa5]);
    encode_length(inner_len, buf);
    buf.extend_from_slice(&[0x80]);
    encode_length(bt.len(), buf);
    buf.extend_from_slice(&bt);
    buf.extend_from_slice(&[0x81]);
    encode_length(entry_id.len(), buf);
    buf.extend_from_slice(entry_id);
}

fn check_service_tag_and_take(data: &[u8]) -> Result<&[u8], MmsError> {
    if data.len() < 2 {
        return Err(MmsError::TruncatedPdu);
    }
    if data[0] != SERVICE_TAG_READ_JOURNAL[0] || data[1] != SERVICE_TAG_READ_JOURNAL[1] {
        return Err(MmsError::InvalidTag {
            expected: SERVICE_TAG_READ_JOURNAL[0],
            actual: data[0],
        });
    }
    let (inner_len, hdr) = decode_length(&data[2..])?;
    let inner_start = 2 + hdr;
    if inner_start + inner_len > data.len() {
        return Err(MmsError::TruncatedPdu);
    }
    Ok(&data[inner_start..inner_start + inner_len])
}

fn decode_request_inner(data: &[u8]) -> Result<ReadJournalRequest, MmsError> {
    let mut pos = 0usize;
    let mut domain_id: Option<String> = None;
    let mut item_id: Option<String> = None;
    let mut range_start: Option<u64> = None;
    let mut range_stop: Option<u64> = None;
    let mut after: Option<JournalRange> = None;

    while pos < data.len() {
        let tag = data[pos];
        let (len, hdr) = decode_length(&data[pos + 1..])?;
        let val_start = pos + 1 + hdr;
        if val_start + len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let val = &data[val_start..val_start + len];
        pos = val_start + len;

        match tag {
            0xa0 => {
                let (d, i) = decode_journal_name(val)?;
                domain_id = Some(d);
                item_id = Some(i);
            }
            0xa1 => {
                range_start = Some(decode_time_range_spec(val)?);
            }
            0xa2 => {
                range_stop = Some(decode_time_range_spec(val)?);
            }
            0xa5 => {
                after = Some(decode_entry_to_start_after(val)?);
            }
            other => {
                tracing::debug!("skipping unknown readjournalrequest tag 0x{:02X}", other);
            }
        }
    }

    let domain_id = domain_id.ok_or(MmsError::TruncatedPdu)?;
    let item_id = item_id.ok_or(MmsError::TruncatedPdu)?;
    let range = match (range_start, range_stop, after) {
        (Some(start_ms), Some(end_ms), None) => JournalRange::TimeRange { start_ms, end_ms },
        (None, None, Some(r)) => r,
        _ => return Err(MmsError::TruncatedPdu),
    };
    Ok(ReadJournalRequest {
        domain_id,
        item_id,
        range,
    })
}

fn decode_journal_name(data: &[u8]) -> Result<(String, String), MmsError> {
    // the content must start with 0xa1, the domain-specific alternative
    if data.is_empty() || data[0] != 0xa1 {
        return Err(MmsError::TruncatedPdu);
    }
    let (len, hdr) = decode_length(&data[1..])?;
    let val_start = 1 + hdr;
    if val_start + len > data.len() {
        return Err(MmsError::TruncatedPdu);
    }
    let mut p = val_start;
    let end = val_start + len;
    let domain_id = decode_visible_string_field(data, &mut p, end)?;
    let item_id = decode_visible_string_field(data, &mut p, end)?;
    Ok((domain_id, item_id))
}

fn decode_visible_string_field(
    data: &[u8],
    pos: &mut usize,
    end: usize,
) -> Result<String, MmsError> {
    if *pos >= end || data[*pos] != 0x1a {
        return Err(MmsError::TruncatedPdu);
    }
    let (slen, shdr) = decode_length(&data[*pos + 1..])?;
    let s_start = *pos + 1 + shdr;
    if s_start + slen > end {
        return Err(MmsError::TruncatedPdu);
    }
    let s = core::str::from_utf8(&data[s_start..s_start + slen])
        .map_err(|_| MmsError::InvalidPdu)?
        .to_string();
    *pos = s_start + slen;
    Ok(s)
}

fn decode_time_range_spec(val: &[u8]) -> Result<u64, MmsError> {
    // val = 0x80 <len> <BinaryTime>
    if val.is_empty() || val[0] != 0x80 {
        return Err(MmsError::TruncatedPdu);
    }
    let (blen, bhdr) = decode_length(&val[1..])?;
    let b_start = 1 + bhdr;
    if b_start + blen > val.len() {
        return Err(MmsError::TruncatedPdu);
    }
    decode_binary_time_to_ms(&val[b_start..b_start + blen])
}

fn decode_entry_to_start_after(val: &[u8]) -> Result<JournalRange, MmsError> {
    // val = 0x80 <len> <BinaryTime>  0x81 <len> <entryID>
    let mut p = 0usize;
    let mut starting_time_ms: Option<u64> = None;
    let mut entry_id: Option<[u8; ENTRY_ID_SIZE]> = None;

    while p < val.len() {
        let tag = val[p];
        let (l, h) = decode_length(&val[p + 1..])?;
        let v_start = p + 1 + h;
        if v_start + l > val.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let v = &val[v_start..v_start + l];
        p = v_start + l;
        match tag {
            0x80 => {
                starting_time_ms = Some(decode_binary_time_to_ms(v)?);
            }
            0x81 => {
                if v.len() != ENTRY_ID_SIZE {
                    return Err(MmsError::InvalidLength);
                }
                let mut id = [0u8; ENTRY_ID_SIZE];
                id.copy_from_slice(v);
                entry_id = Some(id);
            }
            other => {
                tracing::debug!("skipping unknown entrytostartafter tag 0x{:02X}", other);
            }
        }
    }

    Ok(JournalRange::StartAfter {
        starting_time_ms: starting_time_ms.ok_or(MmsError::TruncatedPdu)?,
        entry_id: entry_id.ok_or(MmsError::TruncatedPdu)?,
    })
}

fn decode_binary_time_to_ms(b: &[u8]) -> Result<u64, MmsError> {
    match b.len() {
        6 => {
            let mut a = [0u8; 6];
            a.copy_from_slice(b);
            Ok(epoch_ms_from_binary_time6(a))
        }
        4 => {
            // BinaryTime4 carries only milliseconds within the day, with no date, so
            // the value is taken as an offset from midnight on 1970-01-01.
            let ms_of_day = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
            Ok(ms_of_day)
        }
        _ => Err(MmsError::InvalidLength),
    }
}

// ReadJournalResponse

/// One journal entry as it appears on the wire.
#[derive(Debug, Clone, PartialEq)]
pub struct WireJournalEntry {
    /// EntryID, 8 bytes big-endian.
    pub entry_id: [u8; ENTRY_ID_SIZE],
    /// occurenceTime as epoch milliseconds; encoded on the wire as BinaryTime6.
    pub occurence_time_ms: u64,
    /// The data points of this entry. Each one becomes two variable elements on the
    /// wire: the value itself and its reason code.
    pub variables: Vec<WireJournalVariable>,
}

/// One data point of a journal entry.
#[derive(Debug, Clone, PartialEq)]
pub struct WireJournalVariable {
    /// dataRef, a UTF-8 string.
    pub data_ref: String,
    /// The decoded value.
    pub value: MmsData,
    /// reasonCode, carried as a seven-bit BitString with one padding bit.
    pub reason_code: u8,
}

/// An MMS ReadJournalResponse.
#[derive(Debug, Clone, PartialEq)]
pub struct ReadJournalResponse {
    /// listOfJournalEntry.
    pub entries: Vec<WireJournalEntry>,
    /// moreFollows, OPTIONAL and present only when further entries remain.
    pub more_follows: Option<bool>,
}

impl ReadJournalResponse {
    /// Encodes the response, including the `0xbf 0x41 <len>` service wrapper.
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut inner = BytesMut::new();

        // listOfJournalEntry [0] IMPLICIT SEQUENCE OF
        let mut list_buf = BytesMut::new();
        for entry in &self.entries {
            encode_wire_journal_entry(entry, &mut list_buf);
        }
        inner.extend_from_slice(&[0xa0]);
        encode_length(list_buf.len(), &mut inner);
        inner.extend_from_slice(&list_buf);

        // moreFollows [1] IMPLICIT BOOLEAN  (OPTIONAL)
        if let Some(mf) = self.more_follows {
            inner.extend_from_slice(&[0x81, 0x01, if mf { 0xff } else { 0x00 }]);
        }

        buf.extend_from_slice(&SERVICE_TAG_READ_JOURNAL);
        encode_length(inner.len(), buf);
        buf.extend_from_slice(&inner);
    }

    /// Decodes a response; `data` starts at the `0xbf` byte.
    pub fn decode(data: &[u8]) -> Result<Self, MmsError> {
        let inner = check_service_tag_and_take(data)?;
        decode_response_inner(inner)
    }
}

fn encode_wire_journal_entry(entry: &WireJournalEntry, buf: &mut BytesMut) {
    let mut entry_buf = BytesMut::new();

    // 0x80 8 <entryID>
    entry_buf.extend_from_slice(&[0x80]);
    encode_length(entry.entry_id.len(), &mut entry_buf);
    entry_buf.extend_from_slice(&entry.entry_id);

    // originatingApplication, always the same four bytes
    entry_buf.extend_from_slice(&ORIGINATING_APPLICATION_FIXED);

    // entryContent [2] EXPLICIT
    let mut content_buf = BytesMut::new();
    // occurenceTime 0x80 6 <BinaryTime6>
    let bt = binary_time6_from_epoch_ms(entry.occurence_time_ms);
    content_buf.extend_from_slice(&[0x80]);
    encode_length(bt.len(), &mut content_buf);
    content_buf.extend_from_slice(&bt);
    // journalVariables [2] EXPLICIT
    let mut jvars_buf = BytesMut::new();
    encode_journal_variables(&entry.variables, &mut jvars_buf);
    content_buf.extend_from_slice(&[0xa2]);
    encode_length(jvars_buf.len(), &mut content_buf);
    content_buf.extend_from_slice(&jvars_buf);

    entry_buf.extend_from_slice(&[0xa2]);
    encode_length(content_buf.len(), &mut entry_buf);
    entry_buf.extend_from_slice(&content_buf);

    // wrap the whole entry in a 0x30 SEQUENCE
    buf.extend_from_slice(&[0x30]);
    encode_length(entry_buf.len(), buf);
    buf.extend_from_slice(&entry_buf);
}

fn encode_journal_variables(vars: &[WireJournalVariable], buf: &mut BytesMut) {
    // 0xa1 <len> -- listOfVariables [1] EXPLICIT SEQUENCE OF
    let mut list_buf = BytesMut::new();
    for v in vars {
        // first variable: the value itself
        encode_data_variable(&v.data_ref, &v.value, &mut list_buf);
        // second variable: the reason code
        encode_reason_code_variable(v.reason_code, &mut list_buf);
    }
    buf.extend_from_slice(&[0xa1]);
    encode_length(list_buf.len(), buf);
    buf.extend_from_slice(&list_buf);
}

fn encode_data_variable(data_ref: &str, value: &MmsData, buf: &mut BytesMut) {
    let mut var_buf = BytesMut::new();
    // dataRef tag 0x80 + UTF-8 bytes
    let r = data_ref.as_bytes();
    var_buf.extend_from_slice(&[0x80]);
    encode_length(r.len(), &mut var_buf);
    var_buf.extend_from_slice(r);
    // valueSpec [1] EXPLICIT wrapping the value
    let mut data_buf = BytesMut::new();
    value.encode(&mut data_buf);
    var_buf.extend_from_slice(&[0xa1]);
    encode_length(data_buf.len(), &mut var_buf);
    var_buf.extend_from_slice(&data_buf);

    buf.extend_from_slice(&[0x30]);
    encode_length(var_buf.len(), buf);
    buf.extend_from_slice(&var_buf);
}

fn encode_reason_code_variable(reason_code: u8, buf: &mut BytesMut) {
    // the second variable is tagged "ReasonCode" and carries a BitString of seven bits
    let mut var_buf = BytesMut::new();
    let tag_bytes = b"ReasonCode";
    var_buf.extend_from_slice(&[0x80]);
    encode_length(tag_bytes.len(), &mut var_buf);
    var_buf.extend_from_slice(tag_bytes);
    // BitString MmsData wire = 0x84 <len> <padding=1> <data byte>
    let bs = MmsData::BitString {
        padding: 1,
        data: vec![reason_code],
    };
    let mut data_buf = BytesMut::new();
    bs.encode(&mut data_buf);
    var_buf.extend_from_slice(&[0xa1]);
    encode_length(data_buf.len(), &mut var_buf);
    var_buf.extend_from_slice(&data_buf);

    buf.extend_from_slice(&[0x30]);
    encode_length(var_buf.len(), buf);
    buf.extend_from_slice(&var_buf);
}

fn decode_response_inner(data: &[u8]) -> Result<ReadJournalResponse, MmsError> {
    let mut pos = 0usize;
    let mut entries = Vec::new();
    let mut more_follows: Option<bool> = None;

    while pos < data.len() {
        let tag = data[pos];
        let (len, hdr) = decode_length(&data[pos + 1..])?;
        let val_start = pos + 1 + hdr;
        if val_start + len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let val = &data[val_start..val_start + len];
        pos = val_start + len;

        match tag {
            0xa0 => {
                // listOfJournalEntry, a run of 0x30 sequences
                entries = decode_list_of_entries(val)?;
            }
            0x81 => {
                // moreFollows BOOLEAN
                if val.is_empty() {
                    return Err(MmsError::InvalidLength);
                }
                more_follows = Some(val[0] != 0);
            }
            other => {
                tracing::debug!("skipping unknown readjournalresponse tag 0x{:02X}", other);
            }
        }
    }

    Ok(ReadJournalResponse {
        entries,
        more_follows,
    })
}

fn decode_list_of_entries(data: &[u8]) -> Result<Vec<WireJournalEntry>, MmsError> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p < data.len() {
        if data[p] != 0x30 {
            return Err(MmsError::TruncatedPdu);
        }
        let (l, h) = decode_length(&data[p + 1..])?;
        let v_start = p + 1 + h;
        if v_start + l > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let v = &data[v_start..v_start + l];
        p = v_start + l;
        out.push(decode_wire_journal_entry(v)?);
    }
    Ok(out)
}

fn decode_wire_journal_entry(data: &[u8]) -> Result<WireJournalEntry, MmsError> {
    let mut pos = 0usize;
    let mut entry_id: Option<[u8; ENTRY_ID_SIZE]> = None;
    let mut occurence_time_ms: Option<u64> = None;
    let mut variables: Vec<WireJournalVariable> = Vec::new();

    while pos < data.len() {
        let tag = data[pos];
        let (len, hdr) = decode_length(&data[pos + 1..])?;
        let val_start = pos + 1 + hdr;
        if val_start + len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let val = &data[val_start..val_start + len];
        pos = val_start + len;

        match tag {
            0x80 => {
                if val.len() != ENTRY_ID_SIZE {
                    return Err(MmsError::InvalidLength);
                }
                let mut id = [0u8; ENTRY_ID_SIZE];
                id.copy_from_slice(val);
                entry_id = Some(id);
            }
            0xa1 => {
                // originatingApplication is a fixed empty SEQUENCE and is not decoded
            }
            0xa2 => {
                // entryContent
                let (t, vs) = decode_entry_content(val)?;
                occurence_time_ms = Some(t);
                variables = vs;
            }
            other => {
                tracing::debug!("skipping unknown journal entry tag 0x{:02X}", other);
            }
        }
    }

    Ok(WireJournalEntry {
        entry_id: entry_id.ok_or(MmsError::TruncatedPdu)?,
        occurence_time_ms: occurence_time_ms.ok_or(MmsError::TruncatedPdu)?,
        variables,
    })
}

fn decode_entry_content(data: &[u8]) -> Result<(u64, Vec<WireJournalVariable>), MmsError> {
    let mut pos = 0usize;
    let mut occurence_time_ms: Option<u64> = None;
    let mut variables: Vec<WireJournalVariable> = Vec::new();

    while pos < data.len() {
        let tag = data[pos];
        let (len, hdr) = decode_length(&data[pos + 1..])?;
        let val_start = pos + 1 + hdr;
        if val_start + len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let val = &data[val_start..val_start + len];
        pos = val_start + len;

        match tag {
            0x80 => {
                occurence_time_ms = Some(decode_binary_time_to_ms(val)?);
            }
            0xa2 => {
                variables = decode_journal_variables(val)?;
            }
            other => {
                tracing::debug!("skipping unknown entrycontent tag 0x{:02X}", other);
            }
        }
    }
    Ok((occurence_time_ms.ok_or(MmsError::TruncatedPdu)?, variables))
}

fn decode_journal_variables(data: &[u8]) -> Result<Vec<WireJournalVariable>, MmsError> {
    // the content must start with 0xa1 followed by a run of 0x30 sequences
    if data.is_empty() || data[0] != 0xa1 {
        return Err(MmsError::TruncatedPdu);
    }
    let (len, hdr) = decode_length(&data[1..])?;
    let val_start = 1 + hdr;
    if val_start + len > data.len() {
        return Err(MmsError::TruncatedPdu);
    }
    let inner = &data[val_start..val_start + len];

    // Each data point occupies two variable elements:
    //   variable[i]   = data variable
    //   variable[i+1] = the reason code, tagged "ReasonCode"
    let raw = decode_raw_variables(inner)?;
    let mut out = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        let (data_ref, value) = match &raw[i] {
            RawVariable::Data { tag, value } => (tag.clone(), value.clone()),
            RawVariable::ReasonCode(_) => {
                tracing::warn!(
                    "wire order is wrong: a reasoncode variable precedes its data variable"
                );
                return Err(MmsError::InvalidPdu);
            }
        };
        let reason_code = match raw.get(i + 1) {
            Some(RawVariable::ReasonCode(rc)) => *rc,
            _ => 0,
        };
        out.push(WireJournalVariable {
            data_ref,
            value,
            reason_code,
        });
        i += if matches!(raw.get(i + 1), Some(RawVariable::ReasonCode(_))) {
            2
        } else {
            1
        };
    }
    Ok(out)
}

#[derive(Debug, Clone)]
enum RawVariable {
    Data { tag: String, value: MmsData },
    ReasonCode(u8),
}

fn decode_raw_variables(data: &[u8]) -> Result<Vec<RawVariable>, MmsError> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p < data.len() {
        if data[p] != 0x30 {
            return Err(MmsError::TruncatedPdu);
        }
        let (l, h) = decode_length(&data[p + 1..])?;
        let v_start = p + 1 + h;
        if v_start + l > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let v = &data[v_start..v_start + l];
        p = v_start + l;
        out.push(decode_raw_variable(v)?);
    }
    Ok(out)
}

fn decode_raw_variable(data: &[u8]) -> Result<RawVariable, MmsError> {
    // expect 0x80 <len> <tag bytes>  0xa1 <len> <Data wire>
    let mut pos = 0usize;
    let mut tag_str: Option<String> = None;
    let mut value: Option<MmsData> = None;

    while pos < data.len() {
        let tag = data[pos];
        let (len, hdr) = decode_length(&data[pos + 1..])?;
        let val_start = pos + 1 + hdr;
        if val_start + len > data.len() {
            return Err(MmsError::TruncatedPdu);
        }
        let val = &data[val_start..val_start + len];
        pos = val_start + len;
        match tag {
            0x80 => {
                tag_str = Some(
                    core::str::from_utf8(val)
                        .map_err(|_| MmsError::InvalidPdu)?
                        .to_string(),
                );
            }
            0xa1 => {
                let (d, _) = MmsData::decode(val)?;
                value = Some(d);
            }
            other => {
                tracing::debug!("skipping unknown raw variable tag 0x{:02X}", other);
            }
        }
    }

    let tag_str = tag_str.ok_or(MmsError::TruncatedPdu)?;
    let value = value.ok_or(MmsError::TruncatedPdu)?;

    if tag_str == "ReasonCode" {
        if let MmsData::BitString { data, .. } = value {
            let rc = data.first().copied().unwrap_or(0);
            Ok(RawVariable::ReasonCode(rc))
        } else {
            tracing::warn!("the valuespec of a reasoncode variable is not a bitstring");
            Err(MmsError::InvalidPdu)
        }
    } else {
        Ok(RawVariable::Data {
            tag: tag_str,
            value,
        })
    }
}

// ConfirmedRequestPdu and ConfirmedResponsePdu wrappers

/// Encodes a ReadJournalRequest as a complete ConfirmedRequestPdu, outer `0xa0`
/// tag included.
pub fn encode_confirmed_read_journal_request(
    invoke_id: u32,
    req: &ReadJournalRequest,
    buf: &mut BytesMut,
) {
    let mut inner = BytesMut::new();
    encode_invoke_id(invoke_id, &mut inner);
    req.encode(&mut inner);

    buf.extend_from_slice(&[0xa0]);
    encode_length(inner.len(), buf);
    buf.extend_from_slice(&inner);
}

/// Encodes a ReadJournalResponse as a complete ConfirmedResponsePdu, outer `0xa1`
/// tag included.
pub fn encode_confirmed_read_journal_response(
    invoke_id: u32,
    resp: &ReadJournalResponse,
    buf: &mut BytesMut,
) {
    let mut inner = BytesMut::new();
    encode_invoke_id(invoke_id, &mut inner);
    resp.encode(&mut inner);

    buf.extend_from_slice(&[0xa1]);
    encode_length(inner.len(), buf);
    buf.extend_from_slice(&inner);
}

/// Decodes the request inside a ConfirmedRequestPdu; `data` starts at `0xa0`.
pub fn decode_confirmed_read_journal_request(
    data: &[u8],
) -> Result<(u32, ReadJournalRequest), MmsError> {
    let (invoke_id, service_data) = decode_confirmed_pdu_inner(data, 0xa0)?;
    let req = ReadJournalRequest::decode(service_data)?;
    Ok((invoke_id, req))
}

/// Decodes the response inside a ConfirmedResponsePdu; `data` starts at `0xa1`.
pub fn decode_confirmed_read_journal_response(
    data: &[u8],
) -> Result<(u32, ReadJournalResponse), MmsError> {
    let (invoke_id, service_data) = decode_confirmed_pdu_inner(data, 0xa1)?;
    let resp = ReadJournalResponse::decode(service_data)?;
    Ok((invoke_id, resp))
}

fn encode_invoke_id(invoke_id: u32, buf: &mut BytesMut) {
    use super::common::encode_unsigned_int_minimal;
    let bytes = encode_unsigned_int_minimal(invoke_id as u64);
    buf.extend_from_slice(&[0x02]);
    encode_length(bytes.len(), buf);
    buf.extend_from_slice(&bytes);
}

fn decode_confirmed_pdu_inner(data: &[u8], outer_tag: u8) -> Result<(u32, &[u8]), MmsError> {
    if data.is_empty() {
        return Err(MmsError::TruncatedPdu);
    }
    if data[0] != outer_tag {
        return Err(MmsError::InvalidTag {
            expected: outer_tag,
            actual: data[0],
        });
    }
    let (outer_len, outer_hdr) = decode_length(&data[1..])?;
    let inner_start = 1 + outer_hdr;
    if inner_start + outer_len > data.len() {
        return Err(MmsError::TruncatedPdu);
    }
    let inner = &data[inner_start..inner_start + outer_len];

    if inner.is_empty() || inner[0] != 0x02 {
        return Err(MmsError::TruncatedPdu);
    }
    let (id_len, id_hdr) = decode_length(&inner[1..])?;
    let id_start = 1 + id_hdr;
    if id_start + id_len > inner.len() {
        return Err(MmsError::TruncatedPdu);
    }
    let id_val = &inner[id_start..id_start + id_len];
    let mut id = 0u32;
    for &b in id_val {
        id = (id << 8) | (b as u32);
    }
    let service_start = id_start + id_len;
    Ok((id, &inner[service_start..]))
}

// DataAccessError is not used on the ReadJournal path yet; the import is kept for
// the dispatcher error path.
#[allow(dead_code)]
fn _silence_unused(_e: DataAccessError) {}

// Unit tests

#[cfg(test)]
mod tests {
    use super::*;

    // the long-form service tag

    #[test]
    fn service_tag_constant_is_long_form_65() {
        assert_eq!(SERVICE_TAG_READ_JOURNAL, [0xbf, 0x41]);
    }

    // ReadJournalRequest time-range round trip

    #[test]
    fn request_time_range_round_trip() {
        // an epoch after 1984, as BinaryTime6 requires
        let req = ReadJournalRequest::time_range(
            "LD0",
            "LLN0$GLOG",
            1_700_000_000_000,
            1_700_000_001_000,
        );
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        assert_eq!(buf[0], 0xbf);
        assert_eq!(buf[1], 0x41);
        let back = ReadJournalRequest::decode(&buf).unwrap();
        assert_eq!(back, req);
    }

    // ReadJournalRequest start-after round trip

    #[test]
    fn request_start_after_round_trip() {
        let req = ReadJournalRequest::start_after(
            "LD0",
            "LLN0$GLOG",
            1_700_000_500_000,
            [0, 0, 0, 0, 0, 0, 0x12, 0x34],
        );
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let back = ReadJournalRequest::decode(&buf).unwrap();
        assert_eq!(back, req);
    }

    // full ConfirmedRequest wrapper round trip

    #[test]
    fn confirmed_request_wrapper_round_trip() {
        let req = ReadJournalRequest::time_range(
            "LD0",
            "LLN0$GLOG",
            1_700_000_000_100,
            1_700_000_000_200,
        );
        let mut buf = BytesMut::new();
        encode_confirmed_read_journal_request(42, &req, &mut buf);
        assert_eq!(buf[0], 0xa0, "the ConfirmedRequest outer tag");
        let (invoke_id, back) = decode_confirmed_read_journal_request(&buf).unwrap();
        assert_eq!(invoke_id, 42);
        assert_eq!(back, req);
    }

    // ReadJournalResponse round trip

    #[test]
    fn response_empty_list_round_trip() {
        let resp = ReadJournalResponse {
            entries: vec![],
            more_follows: None,
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        let back = ReadJournalResponse::decode(&buf).unwrap();
        assert_eq!(back, resp);
    }

    #[test]
    fn response_one_entry_round_trip() {
        let entry = WireJournalEntry {
            entry_id: [0, 0, 0, 0, 0, 0, 0, 7],
            occurence_time_ms: 1_700_000_500_000,
            variables: vec![WireJournalVariable {
                data_ref: "LD0/MMXU1$MX$A$mag$f".to_string(),
                value: MmsData::Boolean(true),
                reason_code: 0x02, // dchg
            }],
        };
        let resp = ReadJournalResponse {
            entries: vec![entry.clone()],
            more_follows: Some(false),
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        let back = ReadJournalResponse::decode(&buf).unwrap();
        assert_eq!(back, resp);
    }

    #[test]
    fn response_two_entries_with_more_follows_round_trip() {
        let v1 = WireJournalVariable {
            data_ref: "LD0/A".into(),
            value: MmsData::Integer(42),
            reason_code: 0x10, // integrity
        };
        let v2 = WireJournalVariable {
            data_ref: "LD0/B".into(),
            value: MmsData::Float32(2.5),
            reason_code: 0x04, // qchg
        };
        let entry1 = WireJournalEntry {
            entry_id: [0, 0, 0, 0, 0, 0, 0, 1],
            occurence_time_ms: 1_700_000_001_000,
            variables: vec![v1.clone()],
        };
        let entry2 = WireJournalEntry {
            entry_id: [0, 0, 0, 0, 0, 0, 0, 2],
            occurence_time_ms: 1_700_000_002_000,
            variables: vec![v1, v2],
        };
        let resp = ReadJournalResponse {
            entries: vec![entry1, entry2],
            more_follows: Some(true),
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        let back = ReadJournalResponse::decode(&buf).unwrap();
        assert_eq!(back, resp);
    }

    // full ConfirmedResponse wrapper round trip

    #[test]
    fn confirmed_response_wrapper_round_trip() {
        let resp = ReadJournalResponse {
            entries: vec![WireJournalEntry {
                entry_id: [0, 0, 0, 0, 0, 0, 0, 99],
                occurence_time_ms: 1_700_009_999_999,
                variables: vec![WireJournalVariable {
                    data_ref: "LD0/X".into(),
                    value: MmsData::Boolean(false),
                    reason_code: 0,
                }],
            }],
            more_follows: None,
        };
        let mut buf = BytesMut::new();
        encode_confirmed_read_journal_response(7, &resp, &mut buf);
        assert_eq!(buf[0], 0xa1);
        let (invoke_id, back) = decode_confirmed_read_journal_response(&buf).unwrap();
        assert_eq!(invoke_id, 7);
        assert_eq!(back, resp);
    }

    // boundaries and negative cases

    #[test]
    fn decode_request_truncated_returns_err() {
        let r = ReadJournalRequest::decode(&[0xbf]);
        assert!(matches!(r, Err(MmsError::TruncatedPdu)));
    }

    #[test]
    fn decode_request_wrong_first_tag_returns_invalid_tag() {
        let r = ReadJournalRequest::decode(&[0xa0, 0x00]);
        assert!(matches!(r, Err(MmsError::InvalidTag { .. })));
    }

    #[test]
    fn decode_response_invalid_entry_id_size_returns_err() {
        // a malformed PDU whose entryID is shorter than 8 bytes
        let mut bad = BytesMut::new();
        bad.extend_from_slice(&SERVICE_TAG_READ_JOURNAL);
        // content: 0xa0 0x06 0x30 0x04 0x80 0x02 0xaa 0xbb, an entryID of only 2 bytes
        bad.extend_from_slice(&[0x08, 0xa0, 0x06, 0x30, 0x04, 0x80, 0x02, 0xaa, 0xbb]);
        let r = ReadJournalResponse::decode(&bad);
        assert!(matches!(r, Err(MmsError::InvalidLength)));
    }

    #[test]
    fn originating_application_emitted_as_fixed_bytes() {
        let resp = ReadJournalResponse {
            entries: vec![WireJournalEntry {
                entry_id: [0, 0, 0, 0, 0, 0, 0, 1],
                occurence_time_ms: 1_700_000_000_000,
                variables: vec![],
            }],
            more_follows: None,
        };
        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        // locate the fixed originatingApplication sequence 0xa1 0x02 0x30 0x00
        let needle = ORIGINATING_APPLICATION_FIXED;
        assert!(
            buf.windows(needle.len()).any(|w| w == needle),
            "the wire bytes must contain the fixed originatingApplication"
        );
    }
}
