//! Log service and the log control block (LCB) of IEC 61850-7-2.
//!
//! A log control block records entries into persistent storage on the server; a
//! client pulls them with ReadJournal, and nothing is pushed. That is the
//! difference from a buffered report control block, which pushes reports to a
//! client and evicts its oldest entry when its buffer fills. How much a log holds
//! is up to the storage backend.
//!
//! Storage is reached through the `LogStorage` trait, so a backend can be
//! substituted; entries are read back through the `LogEntryVisitor` trait, which
//! is called once per entry. A query for the entries after a point applies both
//! the starting time and the entry identifier.
//!
//! Not implemented here: WriteJournal, and a real `originatingApplication` value,
//! which is sent as an empty sequence.

pub mod lcb;
pub mod storage;

pub use lcb::{LogControl, LogControlBlock, LogEna, LogState};
pub use storage::{
    EntryId as LogEntryId, InMemoryLogStorage, JournalEntry, JournalEntryData, LogEntryVisitor,
    LogStorage, LogStorageError,
};

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Shared registry of log control blocks, which the dispatcher uses to route a
/// ReadJournal request.
///
/// Entries are keyed by `(mms domain, mms item)`, matching the
/// `journalName.domain-specific.{domainId, itemId}` of the request on the wire.
///
/// The usual key splits a `LogControl::mms_path` such as
/// `IED1LD0/MMXU1$LG$lcb01` into `("IED1LD0", "MMXU1$LG$lcb01")`. A caller may
/// also register a log-instance style key such as `("IED1LD0", "MMXU1$EventLog")`.
///
/// `IedServerInner` and `MmsModelDispatcher` hold clones of the same `Arc`, so a
/// runtime registration is visible to the dispatcher immediately.
pub type LogControlRegistry = Arc<RwLock<HashMap<(String, String), Arc<LogControl>>>>;

/// Creates an empty `LogControlRegistry`.
pub fn new_log_control_registry() -> LogControlRegistry {
    Arc::new(RwLock::new(HashMap::new()))
}
