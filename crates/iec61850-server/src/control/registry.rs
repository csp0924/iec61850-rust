//! `ControlObjectsRegistry`: the table the MMS dispatcher uses to find a
//! `ControlObject` and its handlers.
//!
//! Entries are keyed by `(domain, logical node, data object)` and hold the control
//! object together with the check, wait-for-execution, and control handlers an
//! application supplied. A `RwLock<HashMap<..>>` gives the dispatcher a constant
//! time lookup.
//!
//! `MmsModelDispatcher::dispatch` is a synchronous trait method while a control
//! sequence involves asynchronous handlers, so the dispatcher looks the object and
//! its handlers up here, takes the command-termination sink, and blocks on the
//! futures. Keeping the lookup in its own module leaves the dispatcher and the MMS
//! mapping free of control-specific state.

use super::handler::{CheckHandler, ControlHandler, WaitForExecutionHandler};
use super::object::ControlObject;
use super::service::CommandTerminationSink;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// ─────────────────────────────────────────────────────────────────────────────
// Lookup key
// ─────────────────────────────────────────────────────────────────────────────

/// Lookup key: the owned `(domain_id, ln_name, do_name)` triple.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ControlObjectKey {
    /// MMS domain, which is the logical device name.
    pub domain: String,
    /// Logical node name.
    pub ln_name: String,
    /// Data object name.
    pub do_name: String,
}

impl ControlObjectKey {
    /// Builds a lookup key from its three parts.
    pub fn new(domain: &str, ln_name: &str, do_name: &str) -> Self {
        Self {
            domain: domain.to_string(),
            ln_name: ln_name.to_string(),
            do_name: do_name.to_string(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Registry entry: one control object and its handlers
// ─────────────────────────────────────────────────────────────────────────────

/// One controllable data object: its state machine and the three callbacks.
#[derive(Clone)]
pub struct ControlObjectEntry {
    /// The control object and its state machine.
    pub object: ControlObject,
    /// Static check handler, when the application installed one.
    pub check_handler: Option<Arc<dyn CheckHandler>>,
    /// Dynamic check handler, when the application installed one.
    pub wait_handler: Option<Arc<dyn WaitForExecutionHandler>>,
    /// Control handler, when the application installed one.
    pub operate_handler: Option<Arc<dyn ControlHandler>>,
}

impl std::fmt::Debug for ControlObjectEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlObjectEntry")
            .field("object", &self.object)
            .field("has_check", &self.check_handler.is_some())
            .field("has_wait", &self.wait_handler.is_some())
            .field("has_operate", &self.operate_handler.is_some())
            .finish()
    }
}

impl ControlObjectEntry {
    /// Creates an entry with no handlers installed.
    pub fn new(object: ControlObject) -> Self {
        Self {
            object,
            check_handler: None,
            wait_handler: None,
            operate_handler: None,
        }
    }

    /// Installs the static check handler.
    pub fn with_check(mut self, h: Arc<dyn CheckHandler>) -> Self {
        self.check_handler = Some(h);
        self
    }

    /// Installs the dynamic check handler.
    pub fn with_wait(mut self, h: Arc<dyn WaitForExecutionHandler>) -> Self {
        self.wait_handler = Some(h);
        self
    }

    /// Installs the control handler.
    pub fn with_operate(mut self, h: Arc<dyn ControlHandler>) -> Self {
        self.operate_handler = Some(h);
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Registry: the table the dispatcher holds
// ─────────────────────────────────────────────────────────────────────────────

/// Central registry of control objects.
///
/// `IedServerBuilder` fills it during build; `register` can also add entries at
/// runtime.
///
/// `ct_sink` is the server-wide command-termination router, held as an
/// `Arc<dyn CommandTerminationSink>`. The sink resolves the connection id to that
/// connection's channel and sends the termination message there.
#[derive(Clone)]
pub struct ControlObjectsRegistry {
    inner: Arc<RwLock<HashMap<ControlObjectKey, ControlObjectEntry>>>,
    ct_sink: Arc<dyn CommandTerminationSink>,
}

impl std::fmt::Debug for ControlObjectsRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.inner.read().map(|g| g.len()).unwrap_or(0);
        f.debug_struct("ControlObjectsRegistry")
            .field("entries", &count)
            .finish()
    }
}

impl Default for ControlObjectsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlObjectsRegistry {
    /// Creates an empty registry whose command-termination sink discards messages.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            ct_sink: Arc::new(super::service::NoOpCommandTermination),
        }
    }

    /// Creates an empty registry with the given command-termination sink.
    pub fn with_sink(ct_sink: Arc<dyn CommandTerminationSink>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            ct_sink,
        }
    }

    /// Replaces the command-termination sink.
    pub fn set_ct_sink(&mut self, sink: Arc<dyn CommandTerminationSink>) {
        self.ct_sink = sink;
    }

    /// Returns the current command-termination sink, which the dispatcher passes to
    /// `handle_operate`.
    pub fn ct_sink(&self) -> &Arc<dyn CommandTerminationSink> {
        &self.ct_sink
    }

    /// Registers one control object with its handlers.
    ///
    /// An entry with the same key is replaced. Returns `true` when the entry is new
    /// and `false` when it replaced an existing one.
    pub fn register(&self, entry: ControlObjectEntry) -> bool {
        let key = ControlObjectKey::new(
            &entry.object.config.domain,
            &entry.object.config.ln_name,
            &entry.object.config.name,
        );
        let mut g = match self.inner.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::warn!("control object registry lock poisoned, entry not registered");
                return false;
            }
        };
        let was_new = !g.contains_key(&key);
        g.insert(key, entry);
        was_new
    }

    /// Looks up one control object entry.
    pub fn lookup(&self, domain: &str, ln_name: &str, do_name: &str) -> Option<ControlObjectEntry> {
        let g = self.inner.read().ok()?;
        g.get(&ControlObjectKey::new(domain, ln_name, do_name))
            .cloned()
    }

    /// Releases every selection held by a connection that has closed.
    pub fn release_connection(&self, conn_id: u64) {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return,
        };
        for entry in g.values() {
            entry.object.on_connection_closed(conn_id);
        }
    }

    /// Returns the number of registered entries.
    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Returns whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::handler::AlwaysAcceptCheckHandler;
    use crate::control::model::{ControlModel, SboClass};
    use crate::control::object::{ControlObject, ControlObjectConfig};

    fn make_obj(name: &str) -> ControlObject {
        ControlObject::new(ControlObjectConfig {
            name: name.into(),
            ln_name: "GGIO1".into(),
            domain: "IED1LD0".into(),
            ctl_model: ControlModel::DirectNormal,
            sbo_timeout_ms: 5000,
            sbo_class: SboClass::OperateOnce,
        })
    }

    #[test]
    fn registry_register_and_lookup() {
        let reg = ControlObjectsRegistry::new();
        assert!(reg.is_empty());

        let entry = ControlObjectEntry::new(make_obj("SPCSO1"))
            .with_check(Arc::new(AlwaysAcceptCheckHandler));
        assert!(reg.register(entry));
        assert_eq!(reg.len(), 1);

        let found = reg
            .lookup("IED1LD0", "GGIO1", "SPCSO1")
            .expect("entry must be found");
        assert!(found.check_handler.is_some());
        assert_eq!(found.object.config.name, "SPCSO1");
    }

    #[test]
    fn registry_lookup_miss_returns_none() {
        let reg = ControlObjectsRegistry::new();
        assert!(reg.lookup("X", "Y", "Z").is_none());
    }

    #[test]
    fn registry_register_overwrite() {
        let reg = ControlObjectsRegistry::new();
        reg.register(ControlObjectEntry::new(make_obj("SPCSO1")));
        // Registering the same key again replaces the entry.
        let was_new = reg.register(ControlObjectEntry::new(make_obj("SPCSO1")));
        assert!(!was_new, "a replacement must report false");
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn release_connection_resets_selected_objects() {
        use crate::control::state::ControlState;

        let reg = ControlObjectsRegistry::new();
        // A select-before-operate object, selected.
        let obj_cfg = ControlObjectConfig {
            name: "SPCSO1".into(),
            ln_name: "GGIO1".into(),
            domain: "IED1LD0".into(),
            ctl_model: ControlModel::SboNormal,
            sbo_timeout_ms: 5000,
            sbo_class: SboClass::OperateOnce,
        };
        let obj = ControlObject::new(obj_cfg);
        obj.try_select(99).unwrap();
        assert_eq!(obj.state(), ControlState::Ready);
        reg.register(ControlObjectEntry::new(obj.clone()));

        // Closing connection 99 deselects it.
        reg.release_connection(99);
        assert_eq!(obj.state(), ControlState::Unselected);
    }
}
