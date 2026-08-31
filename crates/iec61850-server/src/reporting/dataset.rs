//! Data set: the list of data attributes a report control block observes.
//!
//! An entry holds an `Arc<RwLock<MmsValue>>` shared with the model's
//! `DataAttribute::value`, so a read takes the read lock and clones the value.
//! Nothing caches resolved value references: a data set is normally well under a
//! hundred entries, so it is walked at encode time. Report snapshots are owned
//! values, `Vec<Option<MmsValue>>`, not borrows into the model.
//!
//! A `DataAttributeRef` is the string `"<domain>/<LN>$<FC>$<DO>$<DA>"`, the same
//! wire path `iec61850-model::ObjectRef` produces, and is the key of the reporting
//! engine's inverted index.

use iec61850_model::MmsValue;
use std::sync::{Arc, RwLock};

// ─────────────────────────────────────────────────────────────────────────────
// DataAttributeRef
// ─────────────────────────────────────────────────────────────────────────────

/// Wire-level reference to one IEC 61850 data attribute.
///
/// The form is `"<IED><LD>/<LN>$<FC>$<DO>$<DA>"`, for example
/// `"IED1LD0/GGIO1$ST$Ind1$stVal"`. It is the key of the reporting engine's
/// inverted index.
pub type DataAttributeRef = String;

// ─────────────────────────────────────────────────────────────────────────────
// DatasetEntry
// ─────────────────────────────────────────────────────────────────────────────

/// One data attribute entry in a data set.
///
/// Holds an `Arc<RwLock<MmsValue>>` shared with the model's
/// `DataAttribute::value`, so an entry always sees the live value.
#[derive(Debug, Clone)]
pub struct DatasetEntry {
    /// Wire-level reference, emitted for the DATA_REFERENCE optional field.
    pub attr_ref: DataAttributeRef,
    /// Value lock shared with the model's `DataAttribute::value`.
    pub value: Arc<RwLock<MmsValue>>,
}

impl DatasetEntry {
    /// Creates an entry from a reference and a shared value lock.
    pub fn new(attr_ref: impl Into<DataAttributeRef>, value: Arc<RwLock<MmsValue>>) -> Self {
        Self {
            attr_ref: attr_ref.into(),
            value,
        }
    }

    /// Returns a clone of the current value, or `None` when the value lock is
    /// poisoned. The lock is released immediately after the clone.
    pub fn read_value(&self) -> Option<MmsValue> {
        self.value.read().ok().map(|g| g.clone())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Dataset
// ─────────────────────────────────────────────────────────────────────────────

/// The list of data attributes a report control block observes.
///
/// Entries are held in a `Vec`, which is append-only while the model is being
/// built and treated as immutable once a control block is enabled.
#[derive(Debug, Clone, Default)]
pub struct Dataset {
    /// Data set reference name in the MMS namespace, for example `GGIO1$ds1`.
    pub name: String,
    /// Entries, in declaration order.
    pub entries: Vec<DatasetEntry>,
}

impl Dataset {
    /// Creates an empty data set.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            entries: Vec::new(),
        }
    }

    /// Appends an entry. Only called while the model is being built.
    pub fn push(&mut self, entry: DatasetEntry) {
        self.entries.push(entry);
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the data set has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the entry at `idx`, or `None` when the index is out of range.
    pub fn entry(&self, idx: usize) -> Option<&DatasetEntry> {
        self.entries.get(idx)
    }

    /// Snapshots the current value of every entry, for report encoding.
    ///
    /// The result is as long as `entries`; a position is `None` when that entry's
    /// value lock is poisoned.
    pub fn snapshot_values(&self) -> Vec<Option<MmsValue>> {
        self.entries.iter().map(|e| e.read_value()).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bool_entry(attr_ref: &str, val: bool) -> DatasetEntry {
        let value = Arc::new(RwLock::new(MmsValue::Boolean(val)));
        DatasetEntry::new(attr_ref, value)
    }

    #[test]
    fn dataset_new_is_empty() {
        let ds = Dataset::new("GGIO1$ds1");
        assert!(ds.is_empty());
        assert_eq!(ds.len(), 0);
        assert_eq!(ds.name, "GGIO1$ds1");
    }

    #[test]
    fn dataset_push_and_read() {
        let mut ds = Dataset::new("ds1");
        ds.push(make_bool_entry("IED1LD0/GGIO1$ST$Ind1$stVal", true));
        ds.push(make_bool_entry("IED1LD0/GGIO1$ST$Ind2$stVal", false));
        assert_eq!(ds.len(), 2);

        let v0 = ds.entry(0).unwrap().read_value().unwrap();
        assert_eq!(v0, MmsValue::Boolean(true));

        let v1 = ds.entry(1).unwrap().read_value().unwrap();
        assert_eq!(v1, MmsValue::Boolean(false));
    }

    #[test]
    fn dataset_snapshot_values() {
        let mut ds = Dataset::new("ds1");
        ds.push(make_bool_entry("A", true));
        ds.push(make_bool_entry("B", false));
        let snap = ds.snapshot_values();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0], Some(MmsValue::Boolean(true)));
        assert_eq!(snap[1], Some(MmsValue::Boolean(false)));
    }

    #[test]
    fn dataset_entry_out_of_bounds_is_none() {
        let ds = Dataset::new("ds1");
        assert!(ds.entry(0).is_none());
    }

    #[test]
    fn shared_value_update_visible_through_entry() {
        let shared = Arc::new(RwLock::new(MmsValue::Integer(0)));
        let entry = DatasetEntry::new("test", Arc::clone(&shared));

        // Update through the shared handle.
        *shared.write().unwrap() = MmsValue::Integer(42);
        let v = entry.read_value().unwrap();
        assert_eq!(v, MmsValue::Integer(42));
    }
}
