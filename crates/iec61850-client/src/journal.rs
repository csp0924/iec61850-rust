//! Journal (log) client API: the ACSI QueryLogByTime and QueryLogAfterEntry
//! services, carried by the MMS ReadJournal request.
//!
//! `IedConnection::query_journal_by_time` and `query_journal_after_entry` issue
//! the request; this module holds the query and entry types and the
//! conversions to and from the wire representation in `iec61850-mms`.
//!
//! An `originatingApplication` field is carried on the wire but ignored while
//! decoding. Both filters of a start-after query apply: an entry must be newer
//! than the starting time and follow the given entry id.

use crate::error::ClientError;
use crate::prelude::{format, String, ToString, Vec};
use iec61850_mms::mms::pdu::common::MmsData;
use iec61850_mms::mms::pdu::{
    JournalRange as WireJournalRange, ReadJournalRequest as WireReadJournalRequest,
    WireJournalEntry,
};
use iec61850_model::MmsValue;

/// Journal entry identifier, an 8-byte big-endian value on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ClientJournalEntryId(pub [u8; 8]);

impl ClientJournalEntryId {
    /// The all-zero identifier, which precedes every real entry.
    pub const ZERO: Self = ClientJournalEntryId([0; 8]);

    /// Builds an identifier from its wire bytes.
    pub fn from_bytes(b: [u8; 8]) -> Self {
        Self(b)
    }

    /// Returns the identifier as a `u64`, for comparison and display.
    pub fn as_u64(&self) -> u64 {
        u64::from_be_bytes(self.0)
    }
}

/// One journal entry as returned by a server.
#[derive(Debug, Clone)]
pub struct ClientJournalEntry {
    /// Identifier of this entry, unique within the log.
    pub entry_id: ClientJournalEntryId,
    /// Time of occurrence in milliseconds since the epoch; a 6-byte BINARY TIME
    /// on the wire.
    pub time_ms: u64,
    /// The data points the entry records.
    pub variables: Vec<ClientJournalEntryData>,
}

/// One data point inside a journal entry.
#[derive(Debug, Clone)]
pub struct ClientJournalEntryData {
    /// Object reference of the logged data attribute.
    pub data_ref: String,
    /// Value that was logged.
    pub value: MmsValue,
    /// The reasonCode bit string data byte, padded as an RCB bit string is.
    pub reason_code: u8,
}

/// A journal query.
///
/// Either a time range, or everything after a given entry.
#[derive(Debug, Clone)]
pub enum JournalQuery {
    /// Entries within a time range.
    TimeRange {
        /// Start of the range, in milliseconds since the epoch, inclusive.
        start_ms: u64,
        /// End of the range, in milliseconds since the epoch.
        end_ms: u64,
    },
    /// Entries after a given entry id, no earlier than a starting time.
    StartAfter {
        /// Earliest time an entry may carry, in milliseconds since the epoch.
        starting_time_ms: u64,
        /// Entry the result starts after.
        entry_id: ClientJournalEntryId,
    },
}

impl JournalQuery {
    /// Builds a time-range query.
    pub fn by_time(start_ms: u64, end_ms: u64) -> Self {
        Self::TimeRange { start_ms, end_ms }
    }

    /// Builds a start-after query.
    pub fn after_entry(starting_time_ms: u64, entry_id: ClientJournalEntryId) -> Self {
        Self::StartAfter {
            starting_time_ms,
            entry_id,
        }
    }
}

/// Splits a log reference `<domain>/<item>` into its two parts.
///
/// The reference is the MMS path of the log, such as
/// `IED1LD0/MMXU1$LG$lcb01`; the caller assembles the domain itself, so no
/// space-separated form is accepted.
///
/// # Errors
///
/// `InvalidArgument` if the `/` is missing or either part is empty.
pub fn parse_journal_ref(log_ref: &str) -> Result<(String, String), ClientError> {
    let (domain, item) = log_ref.split_once('/').ok_or_else(|| {
        ClientError::InvalidArgument(format!(
            "journal log reference must be '<domain>/<item>', got {log_ref:?}"
        ))
    })?;
    if domain.is_empty() || item.is_empty() {
        return Err(ClientError::InvalidArgument(format!(
            "journal log reference has an empty domain or item: {log_ref:?}"
        )));
    }
    Ok((domain.to_string(), item.to_string()))
}

/// Converts a wire journal entry into its client representation.
///
/// Values pass through `mms_compat::mms_data_to_mms_value`, so the variant
/// mapping matches the RCB path.
pub fn wire_entry_to_client(wire: WireJournalEntry) -> ClientJournalEntry {
    ClientJournalEntry {
        entry_id: ClientJournalEntryId(wire.entry_id),
        time_ms: wire.occurence_time_ms,
        variables: wire
            .variables
            .into_iter()
            .map(|v| ClientJournalEntryData {
                data_ref: v.data_ref,
                value: crate::mms_compat::mms_data_to_mms_value(&v.value),
                reason_code: v.reason_code,
            })
            .collect(),
    }
}

/// Converts a `JournalQuery` into the wire request.
pub(crate) fn build_wire_request(
    domain: String,
    item: String,
    query: &JournalQuery,
) -> WireReadJournalRequest {
    let range = match *query {
        JournalQuery::TimeRange { start_ms, end_ms } => {
            WireJournalRange::TimeRange { start_ms, end_ms }
        }
        JournalQuery::StartAfter {
            starting_time_ms,
            entry_id,
        } => WireJournalRange::StartAfter {
            starting_time_ms,
            entry_id: entry_id.0,
        },
    };
    WireReadJournalRequest {
        domain_id: domain,
        item_id: item,
        range,
    }
}

// `MmsData` is reached only through `mms_compat`; this keeps the import from
// reading as unused.
#[allow(dead_code)]
fn _silence_unused(_d: MmsData) {}

/// Retained so that downstream references keep compiling. The journal query
/// API is implemented and never returns this type.
#[deprecated(
    since = "0.1.0",
    note = "the journal query is implemented; use IedConnection::query_journal_by_time or query_journal_after_entry"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryJournalNotImplemented;

#[allow(deprecated)]
impl core::fmt::Display for QueryJournalNotImplemented {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the journal query is implemented; this type is a deprecated marker")
    }
}

// `core::error::Error` is available on both std and no_std targets.
#[allow(deprecated)]
impl core::error::Error for QueryJournalNotImplemented {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_id_round_trip() {
        let id = ClientJournalEntryId([1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(id.as_u64(), 0x0102030405060708);
        assert_eq!(ClientJournalEntryId::from_bytes(id.0), id);
    }

    #[test]
    fn journal_query_by_time_builder() {
        let q = JournalQuery::by_time(100, 200);
        match q {
            JournalQuery::TimeRange { start_ms, end_ms } => {
                assert_eq!(start_ms, 100);
                assert_eq!(end_ms, 200);
            }
            _ => panic!("expected a TimeRange query"),
        }
    }

    #[test]
    fn journal_query_after_entry_builder() {
        let q = JournalQuery::after_entry(50, ClientJournalEntryId([0, 0, 0, 0, 0, 0, 0, 7]));
        match q {
            JournalQuery::StartAfter {
                starting_time_ms,
                entry_id,
            } => {
                assert_eq!(starting_time_ms, 50);
                assert_eq!(entry_id.as_u64(), 7);
            }
            _ => panic!("expected a StartAfter query"),
        }
    }

    #[test]
    fn parse_journal_ref_happy_path() {
        let (d, i) = parse_journal_ref("IED1LD0/MMXU1$LG$lcb01").unwrap();
        assert_eq!(d, "IED1LD0");
        assert_eq!(i, "MMXU1$LG$lcb01");
    }

    #[test]
    fn parse_journal_ref_missing_separator_fails() {
        let r = parse_journal_ref("IED1LD0_MMXU1");
        assert!(matches!(r, Err(ClientError::InvalidArgument(_))));
    }

    #[test]
    fn parse_journal_ref_empty_part_fails() {
        let r = parse_journal_ref("/MMXU1");
        assert!(matches!(r, Err(ClientError::InvalidArgument(_))));
        let r = parse_journal_ref("IED1LD0/");
        assert!(matches!(r, Err(ClientError::InvalidArgument(_))));
    }

    #[test]
    fn build_wire_request_time_range_maps_directly() {
        let q = JournalQuery::by_time(100, 999);
        let req = build_wire_request("IED1LD0".into(), "MMXU1$LG$lcb01".into(), &q);
        assert_eq!(req.domain_id, "IED1LD0");
        assert_eq!(req.item_id, "MMXU1$LG$lcb01");
        match req.range {
            iec61850_mms::mms::pdu::JournalRange::TimeRange { start_ms, end_ms } => {
                assert_eq!(start_ms, 100);
                assert_eq!(end_ms, 999);
            }
            _ => panic!("expected a TimeRange range"),
        }
    }

    #[test]
    fn build_wire_request_start_after_carries_entry_id_bytes() {
        let q =
            JournalQuery::after_entry(500, ClientJournalEntryId([0, 0, 0, 0, 0, 0, 0xab, 0xcd]));
        let req = build_wire_request("D".into(), "I".into(), &q);
        match req.range {
            iec61850_mms::mms::pdu::JournalRange::StartAfter {
                starting_time_ms,
                entry_id,
            } => {
                assert_eq!(starting_time_ms, 500);
                assert_eq!(entry_id, [0, 0, 0, 0, 0, 0, 0xab, 0xcd]);
            }
            _ => panic!("expected a StartAfter range"),
        }
    }

    #[test]
    fn wire_entry_to_client_carries_reason_code() {
        let wire = WireJournalEntry {
            entry_id: [0, 0, 0, 0, 0, 0, 0, 1],
            occurence_time_ms: 1_700_000_000_000,
            variables: vec![iec61850_mms::mms::pdu::WireJournalVariable {
                data_ref: "LD0/A".into(),
                value: MmsData::Boolean(true),
                reason_code: 0x10,
            }],
        };
        let c = wire_entry_to_client(wire);
        assert_eq!(c.entry_id.as_u64(), 1);
        assert_eq!(c.time_ms, 1_700_000_000_000);
        assert_eq!(c.variables.len(), 1);
        assert_eq!(c.variables[0].data_ref, "LD0/A");
        assert_eq!(c.variables[0].reason_code, 0x10);
        match &c.variables[0].value {
            iec61850_model::value::MmsValue::Boolean(b) => assert!(*b),
            _ => panic!("expected a Boolean value"),
        }
    }
}
