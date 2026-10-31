//! Journal (log) client API: the ACSI QueryLogByTime and QueryLogAfter
//! services, carried by the MMS ReadJournal request.
//!
//! A [`JournalQuery`] holds the four OPTIONAL selections of a ReadJournal
//! request; `IedConnection::query_journal` sends one request and
//! `IedConnection::query_journal_all` follows `moreFollows` until the
//! selection is exhausted. `IedConnection::query_journal_by_time` and
//! `query_journal_after_entry` are the two ACSI services in their usual form.
//! This module also holds the entry types and the conversions to and from the
//! wire representation in `iec61850-mms`.
//!
//! An `originatingApplication` field is carried on the wire but ignored while
//! decoding.

use crate::error::ClientError;
use crate::prelude::{format, String, ToString, Vec};
use iec61850_hal::time::Timer;
use iec61850_hal::transport::AsyncTransport;
use iec61850_mms::mms::pdu::common::MmsData;
use iec61850_mms::mms::pdu::{
    JournalRangeStart, JournalRangeStop, ReadJournalRequest as WireReadJournalRequest,
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
#[non_exhaustive]
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
#[non_exhaustive]
pub struct ClientJournalEntryData {
    /// Object reference of the logged data attribute.
    pub data_ref: String,
    /// Value that was logged.
    pub value: MmsValue,
    /// reasonCode (ReasonForInclusionInLog): mask `1 << n` holds bit `n` of
    /// the BIT STRING, so data-change is 0x02, quality-change 0x04,
    /// data-update 0x08, integrity 0x10, general-interrogation 0x20 and
    /// application-trigger 0x40.
    pub reason_code: u8,
}

/// Where a journal query begins: rangeStartSpecification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalStart {
    /// The entries whose time is at or after this instant, in milliseconds
    /// since the epoch.
    Time(u64),
    /// This entry and the entries after it.
    Entry(ClientJournalEntryId),
}

/// Where a journal query ends: rangeStopSpecification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalStop {
    /// The entries whose time is at or before this instant, in milliseconds
    /// since the epoch.
    Time(u64),
    /// At most this many entries.
    Count(u32),
}

/// The entry a journal query resumes after: entryToStartAfter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalCursor {
    /// Time of that entry, in milliseconds since the epoch.
    pub time_ms: u64,
    /// Identifier of that entry.
    pub entry_id: ClientJournalEntryId,
}

/// A journal query: the four OPTIONAL selections of a ReadJournal request.
///
/// Each selection that is set narrows the result, and a server returns the
/// entries that meet all of them; with none set the query reads the whole
/// journal. [`Self::by_time`] is the ACSI QueryLogByTime and
/// [`Self::after_entry`] the ACSI QueryLogAfter; the `with_` methods add the
/// other selections to either.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct JournalQuery {
    /// Where the query begins, or `None` for the oldest entry.
    pub start: Option<JournalStart>,
    /// Where the query ends, or `None` for the newest entry.
    pub stop: Option<JournalStop>,
    /// Data references of the data points to return; empty returns every
    /// data point.
    pub variables: Vec<String>,
    /// The entry to resume after, or `None`.
    pub after: Option<JournalCursor>,
}

impl JournalQuery {
    /// Builds a query for the whole journal.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a time-range query, ACSI QueryLogByTime: the entries whose time
    /// lies between `start_ms` and `end_ms`, both included.
    pub fn by_time(start_ms: u64, end_ms: u64) -> Self {
        Self::new().with_start_time(start_ms).with_end_time(end_ms)
    }

    /// Builds a start-after query, ACSI QueryLogAfter: the entries after
    /// `entry_id` whose time is at or after `time_ms`.
    pub fn after_entry(time_ms: u64, entry_id: ClientJournalEntryId) -> Self {
        Self::new().with_entry_to_start_after(time_ms, entry_id)
    }

    /// Begins the query at the entries whose time is at or after `ms`.
    pub fn with_start_time(mut self, ms: u64) -> Self {
        self.start = Some(JournalStart::Time(ms));
        self
    }

    /// Begins the query at the entry `entry_id`, that entry included.
    pub fn with_start_entry(mut self, entry_id: ClientJournalEntryId) -> Self {
        self.start = Some(JournalStart::Entry(entry_id));
        self
    }

    /// Ends the query at the entries whose time is at or before `ms`.
    pub fn with_end_time(mut self, ms: u64) -> Self {
        self.stop = Some(JournalStop::Time(ms));
        self
    }

    /// Limits the query to `n` entries.
    pub fn with_max_entries(mut self, n: u32) -> Self {
        self.stop = Some(JournalStop::Count(n));
        self
    }

    /// Returns only the data points whose data reference is listed.
    pub fn with_variables<I, S>(mut self, data_refs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.variables = data_refs.into_iter().map(Into::into).collect();
        self
    }

    /// Resumes the query after the entry `entry_id` of time `time_ms`.
    pub fn with_entry_to_start_after(
        mut self,
        time_ms: u64,
        entry_id: ClientJournalEntryId,
    ) -> Self {
        self.after = Some(JournalCursor { time_ms, entry_id });
        self
    }

    /// The query that continues this one after `page`, the entries its last
    /// request returned with `moreFollows` set.
    ///
    /// The continuation keeps the start, the stop and the variables, resumes
    /// after the last entry of `page`, and lowers an entry count by the
    /// entries `page` holds. `None` when `page` is empty, since a continuation
    /// needs an entry to resume after.
    pub fn continuation(&self, page: &[ClientJournalEntry]) -> Option<Self> {
        let last = page.last()?;
        let mut next = self
            .clone()
            .with_entry_to_start_after(last.time_ms, last.entry_id);
        if let Some(JournalStop::Count(n)) = next.stop {
            let received = u32::try_from(page.len()).unwrap_or(u32::MAX);
            next.stop = Some(JournalStop::Count(n.saturating_sub(received)));
        }
        Some(next)
    }
}

/// Whether `page`, the answer to a continuation that resumes after `cursor`,
/// moves past it: its first entry is neither the cursor entry nor older than
/// it, nor `previous_first`, the first entry of the page before, which a
/// server that ignores entryToStartAfter sends again. An empty page moves
/// nothing back.
fn advances(
    cursor: &JournalCursor,
    previous_first: ClientJournalEntryId,
    page: &[ClientJournalEntry],
) -> bool {
    page.first().is_none_or(|first| {
        first.entry_id != cursor.entry_id
            && first.entry_id != previous_first
            && first.time_ms >= cursor.time_ms
    })
}

/// Splits a log reference `<domain>/<item>` into its two parts.
///
/// The reference is the LogRef of the journal, such as
/// `IED1LD0/LLN0$GeneralLog`; the caller assembles the domain itself, so no
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
    let mut req = WireReadJournalRequest::new(domain, item);
    req.range_start = query.start.map(|start| match start {
        JournalStart::Time(ms) => JournalRangeStart::StartingTime(ms),
        JournalStart::Entry(id) => JournalRangeStart::StartingEntry(id.0),
    });
    req.range_stop = query.stop.map(|stop| match stop {
        JournalStop::Time(ms) => JournalRangeStop::EndingTime(ms),
        JournalStop::Count(n) => JournalRangeStop::NumberOfEntries(n),
    });
    req.list_of_variables = query.variables.clone();
    if let Some(after) = query.after {
        req = req.with_entry_to_start_after(after.time_ms, after.entry_id.0);
    }
    req
}

impl<T: AsyncTransport, Tm: Timer> crate::connection::IedConnection<T, Tm> {
    /// Sends one ReadJournal request for `query` and returns the entries of
    /// its response and whether more follow.
    ///
    /// `log_ref` is the LogRef of the journal, an MMS path of the form
    /// `<domain>/<item>`, for example `IED1LD0/LLN0$GeneralLog`. When more
    /// follow, [`JournalQuery::continuation`] gives the next request; it
    /// keeps the stop of `query`, so the result never runs past it.
    ///
    /// # Errors
    ///
    /// `NotConnected` when the association is not established;
    /// `InvalidArgument` for a malformed `log_ref`; the request error when the
    /// server refuses the query.
    pub async fn query_journal(
        &self,
        log_ref: &str,
        query: &JournalQuery,
    ) -> Result<(Vec<ClientJournalEntry>, bool), ClientError> {
        if !self.is_connected() {
            return Err(ClientError::NotConnected);
        }
        let (domain, item) = parse_journal_ref(log_ref)?;
        let wire_req = build_wire_request(domain, item, query);
        let resp = {
            let mut client = self.mms_client.lock().await;
            client.read_journal(&wire_req).await?
        };
        let entries = resp.entries.into_iter().map(wire_entry_to_client).collect();
        Ok((entries, resp.more_follows.unwrap_or(false)))
    }

    /// Reads every entry `query` selects, following `moreFollows` with one
    /// request after another.
    ///
    /// Each continuation keeps the start, stop and variables of `query`, so
    /// the end time of a time-range query bounds every page, and an entry
    /// count bounds the total.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::query_journal`]; `Mms` when the server reports
    /// that more entries follow but returns none, which leaves nothing to
    /// resume after, and when a continuation page does not move past the
    /// entry it resumes after, as from a server that ignores
    /// entryToStartAfter, which would otherwise repeat the same page forever.
    pub async fn query_journal_all(
        &self,
        log_ref: &str,
        query: &JournalQuery,
    ) -> Result<Vec<ClientJournalEntry>, ClientError> {
        let mut all = Vec::new();
        let mut next = query.clone();
        let mut resumed: Option<(JournalCursor, ClientJournalEntryId)> = None;
        loop {
            let (page, more) = self.query_journal(log_ref, &next).await?;
            if let Some((cursor, previous_first)) = &resumed {
                if !advances(cursor, *previous_first, &page) {
                    return Err(ClientError::Mms(
                        "the server did not advance past the last journal entry".to_string(),
                    ));
                }
            }
            if !more {
                all.extend(page);
                return Ok(all);
            }
            let Some(continued) = next.continuation(&page) else {
                return Err(ClientError::Mms(
                    "the server reported more journal entries but returned none".to_string(),
                ));
            };
            resumed = continued.after.zip(page.first().map(|e| e.entry_id));
            next = continued;
            all.extend(page);
        }
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
    fn journal_query_by_time_sets_a_start_and_an_end_time() {
        let q = JournalQuery::by_time(100, 200);
        assert_eq!(q.start, Some(JournalStart::Time(100)));
        assert_eq!(q.stop, Some(JournalStop::Time(200)));
        assert_eq!(q.after, None);
        assert!(q.variables.is_empty());
    }

    #[test]
    fn journal_query_after_entry_sets_only_the_cursor() {
        let q = JournalQuery::after_entry(50, ClientJournalEntryId([0, 0, 0, 0, 0, 0, 0, 7]));
        assert_eq!(q.start, None);
        assert_eq!(q.stop, None);
        assert_eq!(
            q.after,
            Some(JournalCursor {
                time_ms: 50,
                entry_id: ClientJournalEntryId([0, 0, 0, 0, 0, 0, 0, 7]),
            })
        );
    }

    fn entry(id: u64, time_ms: u64) -> ClientJournalEntry {
        ClientJournalEntry {
            entry_id: ClientJournalEntryId(id.to_be_bytes()),
            time_ms,
            variables: Vec::new(),
        }
    }

    #[test]
    fn a_continuation_keeps_the_end_time_and_the_variables() {
        let q = JournalQuery::by_time(100, 900).with_variables(["LD0/A"]);
        let next = q
            .continuation(&[entry(1, 100), entry(2, 150)])
            .expect("a page to resume after");
        assert_eq!(next.start, Some(JournalStart::Time(100)));
        assert_eq!(next.stop, Some(JournalStop::Time(900)));
        assert_eq!(next.variables, vec!["LD0/A".to_string()]);
        assert_eq!(
            next.after,
            Some(JournalCursor {
                time_ms: 150,
                entry_id: ClientJournalEntryId(2u64.to_be_bytes()),
            })
        );
    }

    #[test]
    fn a_continuation_lowers_an_entry_count_by_the_page() {
        let q = JournalQuery::new().with_max_entries(5);
        let next = q.continuation(&[entry(1, 10), entry(2, 20)]).unwrap();
        assert_eq!(next.stop, Some(JournalStop::Count(3)));
    }

    #[test]
    fn a_page_after_the_cursor_advances() {
        let cursor = JournalCursor {
            time_ms: 150,
            entry_id: ClientJournalEntryId(2u64.to_be_bytes()),
        };
        let previous_first = ClientJournalEntryId(1u64.to_be_bytes());
        assert!(advances(
            &cursor,
            previous_first,
            &[entry(3, 160), entry(4, 170)]
        ));
        assert!(advances(&cursor, previous_first, &[entry(3, 150)]));
        assert!(advances(&cursor, previous_first, &[]));
    }

    #[test]
    fn a_page_that_does_not_move_past_the_cursor_does_not_advance() {
        let cursor = JournalCursor {
            time_ms: 150,
            entry_id: ClientJournalEntryId(2u64.to_be_bytes()),
        };
        let previous_first = ClientJournalEntryId(1u64.to_be_bytes());
        // The page before, sent again by a server that ignores the cursor.
        assert!(!advances(
            &cursor,
            previous_first,
            &[entry(1, 100), entry(2, 150)]
        ));
        // The cursor entry itself.
        assert!(!advances(&cursor, previous_first, &[entry(2, 150)]));
        // An entry older than the cursor.
        assert!(!advances(&cursor, previous_first, &[entry(9, 140)]));
    }

    #[test]
    fn an_empty_page_has_no_continuation() {
        assert_eq!(JournalQuery::by_time(0, 1).continuation(&[]), None);
    }

    #[test]
    fn parse_journal_ref_happy_path() {
        let (d, i) = parse_journal_ref("IED1LD0/LLN0$GeneralLog").unwrap();
        assert_eq!(d, "IED1LD0");
        assert_eq!(i, "LLN0$GeneralLog");
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
        assert_eq!(
            req,
            WireReadJournalRequest::time_range("IED1LD0", "MMXU1$LG$lcb01", 100, 999)
        );
    }

    #[test]
    fn build_wire_request_start_after_carries_entry_id_bytes() {
        let q =
            JournalQuery::after_entry(500, ClientJournalEntryId([0, 0, 0, 0, 0, 0, 0xab, 0xcd]));
        let req = build_wire_request("D".into(), "I".into(), &q);
        assert_eq!(
            req,
            WireReadJournalRequest::start_after("D", "I", 500, [0, 0, 0, 0, 0, 0, 0xab, 0xcd])
        );
    }

    #[test]
    fn build_wire_request_carries_every_selection() {
        let q = JournalQuery::new()
            .with_start_entry(ClientJournalEntryId(3u64.to_be_bytes()))
            .with_max_entries(10)
            .with_variables(["LD0/A", "LD0/B"])
            .with_entry_to_start_after(40, ClientJournalEntryId(4u64.to_be_bytes()));
        let req = build_wire_request("D".into(), "I".into(), &q);
        assert_eq!(
            req,
            WireReadJournalRequest::new("D", "I")
                .with_range_start(JournalRangeStart::StartingEntry(3u64.to_be_bytes()))
                .with_range_stop(JournalRangeStop::NumberOfEntries(10))
                .with_list_of_variables(["LD0/A", "LD0/B"])
                .with_entry_to_start_after(40, 4u64.to_be_bytes())
        );
    }

    #[test]
    fn wire_entry_to_client_carries_reason_code() {
        let wire = WireJournalEntry::new(
            [0, 0, 0, 0, 0, 0, 0, 1],
            1_700_000_000_000,
            vec![iec61850_mms::mms::pdu::WireJournalVariable::new(
                "LD0/A",
                MmsData::Boolean(true),
                0x10,
            )],
        );
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
