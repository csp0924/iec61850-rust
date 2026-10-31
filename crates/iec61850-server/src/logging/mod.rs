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
/// Entries are keyed by the MMS domain and item of the control block: a
/// `LogControl::mms_path` such as `IED1LD0/MMXU1$LG$lcb01` is the key
/// `("IED1LD0", "MMXU1$LG$lcb01")`. The key names no journal; a ReadJournal
/// request names its journal by the LogRef of a control block, and the
/// dispatcher reads the log of the control block whose LogRef it names.
///
/// `IedServerInner` and `MmsModelDispatcher` hold clones of the same `Arc`, so a
/// runtime registration is visible to the dispatcher immediately.
pub type LogControlRegistry = Arc<RwLock<HashMap<(String, String), Arc<LogControl>>>>;

/// Creates an empty `LogControlRegistry`.
pub fn new_log_control_registry() -> LogControlRegistry {
    Arc::new(RwLock::new(HashMap::new()))
}
