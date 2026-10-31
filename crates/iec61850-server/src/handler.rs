//! Application hooks for the Read and Write services, keyed by attribute path.
//!
//! A read handler answers with one of three outcomes: a value that replaces the
//! model snapshot, a miss that leaves the model to answer, or an error the
//! client receives. A write handler likewise accepts and lets the server update
//! the cached value, accepts and keeps the value itself, or refuses with a
//! specific error. Three distinct outcomes keep "the handler supplied nothing"
//! separate from "the handler refused".
//!
//! Registration and lookup both canonicalize the path through
//! `canonicalize_attr_path`, so a handler installed as `MMXU1.mx.TotW.mag` is
//! found by a request for `MMXU1$MX$TotW$mag`. Installing twice on one path
//! replaces the handler and logs a warning, so an operator can see the
//! shadowing rather than having to infer it.

// AtomicBool comes from core; the rest goes through the compat facade.
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use iec61850_mms::mms::pdu::common::DataAccessError;
use iec61850_model::{MmsValue, FC};

use crate::compat::{Arc, HashMap, RwLock};
use crate::error::{Result, ServerError};

// ─────────────────────────────────────────────────────────────────────────────
// Handler context
// ─────────────────────────────────────────────────────────────────────────────

/// Context passed to [`ReadHandler::read`].
///
/// The paths arrive canonicalized, so a handler can compare them as strings
/// without trimming or changing case.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ReadContext<'a> {
    /// Canonical path the handler is registered against,
    /// `LN$FC$DO[$SDO...][$DA[$SDA...]]`.
    pub path: &'a str,
    /// Functional constraint of the path, already parsed out of it.
    pub fc: FC,
    /// Association the request arrived on; 0 before one is established.
    pub conn_id: u64,
    /// Path the client named: `path` itself, a node above it such as its data
    /// object, its logical node `LN` or its group `LN$FC`, a node below it, or
    /// the data set member being read.
    pub requested: &'a str,
}

impl<'a> ReadContext<'a> {
    /// Creates the context of a read of `path` under `fc` on the association
    /// `conn_id`, requested by that same path.
    pub fn new(path: &'a str, fc: FC, conn_id: u64) -> Self {
        Self {
            path,
            fc,
            conn_id,
            requested: path,
        }
    }

    /// Sets the path the client named.
    pub fn with_requested(mut self, requested: &'a str) -> Self {
        self.requested = requested;
        self
    }
}

/// Context passed to [`AttributeAccessHandler::on_write`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct WriteContext<'a> {
    /// Canonical path the handler is registered against,
    /// `LN$FC$DO[$SDO...][$DA[$SDA...]]`.
    pub path: &'a str,
    /// Functional constraint of the path.
    pub fc: FC,
    /// Association the request arrived on.
    pub conn_id: u64,
    /// Path the client named: `path` itself, a node above it, or a node below
    /// it.
    pub requested: &'a str,
}

impl<'a> WriteContext<'a> {
    /// Creates the context of a write of `path` under `fc` on the association
    /// `conn_id`, requested by that same path.
    pub fn new(path: &'a str, fc: FC, conn_id: u64) -> Self {
        Self {
            path,
            fc,
            conn_id,
            requested: path,
        }
    }

    /// Sets the path the client named.
    pub fn with_requested(mut self, requested: &'a str) -> Self {
        self.requested = requested;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Handler outcomes
// ─────────────────────────────────────────────────────────────────────────────

/// What a read handler decided.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ReadOutcome {
    /// The handler supplies this value and the model is not consulted.
    ///
    /// A bit string that does not fit the declared size of a bit-string
    /// attribute is not sent; the client receives `ObjectValueInvalid`.
    CacheHit(MmsValue),
    /// The handler declines this read; the model answers it.
    CacheMiss,
    /// The handler refuses this read and the client receives this error.
    Error(DataAccessError),
}

/// What a write handler decided.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum WriteOutcome {
    /// The handler accepts the value and the server updates the cached value.
    Accept,
    /// The handler accepts the value and owns it: the cached value is left
    /// alone, as when the handler writes a device and reads it back, and the
    /// client still sees success.
    AcceptNoUpdate,
    /// The handler refuses the value; nothing is written and the client
    /// receives this error.
    Reject(DataAccessError),
}

// ─────────────────────────────────────────────────────────────────────────────
// Traits
// ─────────────────────────────────────────────────────────────────────────────

/// Application hook on the Read path.
///
/// A handler is registered against the path of a data object, a
/// sub-data-object, a data attribute or a sub-attribute. Every read that
/// covers that node consults it and follows the [`ReadOutcome`] it returns: a
/// read of the node itself, of any node above it up to the logical node, and
/// of any node below it, whether named directly or as a data set member.
///
/// A handler above the node read decides first, outermost first; its value
/// answers with the part the node read occupies. A handler below the node
/// read replaces the part its own node occupies, and its error refuses the
/// whole read, which then carries no part of the value. Handlers below one
/// that answered with a value are not consulted.
///
/// [`ReadContext::requested`] tells a read of the node itself from a read
/// that covers it; a handler meant for its own path only answers
/// [`ReadOutcome::CacheMiss`] when the two differ.
pub trait ReadHandler: Send + Sync + core::fmt::Debug {
    /// Answers a read that covers the node this handler is registered
    /// against, `ctx.path`; the client named `ctx.requested`.
    ///
    /// The server calls this while it holds the lock that keeps a read from
    /// seeing part of a concurrent write, shared. The handler must not read or
    /// write the model through the server, such as by calling
    /// `handle_single_read`, `handle_single_read_with_budget` or
    /// `handle_single_write`, from here: taking that lock again on the same
    /// thread can deadlock.
    fn read(&self, ctx: &ReadContext<'_>) -> ReadOutcome;
}

/// Application hook on the Write path.
///
/// A write is classified by functional constraint, type-checked against the
/// model, and put through the write access policy before the handler is
/// consulted, so the handler never sees a value the server would have refused
/// on its own. Only an `Accept` reaches the cached value.
pub trait AttributeAccessHandler: Send + Sync + core::fmt::Debug {
    /// Decides what happens to a value written to the node this handler is
    /// registered against, `ctx.path`; the client named `ctx.requested`.
    ///
    /// One write can consult several handlers: those of the nodes above the
    /// written one, up to its data object, and, for a data object or a
    /// constructed attribute, those of the nodes beneath it. A handler on a
    /// data object therefore decides every write that reaches the object
    /// under the functional constraint of its path.
    ///
    /// The write fails as a whole when any of those handlers refuses, after
    /// the earlier ones may already have answered `Accept` or
    /// `AcceptNoUpdate`. No cached value changes in that case, but a handler
    /// that applies a value itself on `AcceptNoUpdate` sees no notice of the
    /// failure, so it should tolerate a write that ends up refused.
    ///
    /// A handler above the written node receives that node's value merged
    /// into the current values of its siblings, read when the write is
    /// checked. A concurrent write of a sibling leaf can land between that
    /// read and the store, so the merged value may differ from the final state
    /// by that leaf; the decision the handler makes still applies to this
    /// write only.
    fn on_write(&self, ctx: &WriteContext<'_>, value: &MmsValue) -> WriteOutcome;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test-only helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A read handler that always refuses with the error it holds.
///
/// It serves both as a way to check that the read path reports an error
/// faithfully and as a per-path denial, in contrast to the registry-wide
/// `ignore_read_access` flag. It is not test-gated, so examples and harnesses
/// can use it too.
#[derive(Debug, Clone, Copy)]
pub struct DenyAllReadHandler {
    /// The error every read is refused with.
    pub error: DataAccessError,
}

impl ReadHandler for DenyAllReadHandler {
    fn read(&self, _ctx: &ReadContext<'_>) -> ReadOutcome {
        ReadOutcome::Error(self.error)
    }
}

/// A read handler that always declines, that is, one installed but never
/// taking over, so that a miss can be compared against having no handler at
/// all.
#[derive(Debug, Clone, Copy, Default)]
pub struct SilentReadHandler;

impl ReadHandler for SilentReadHandler {
    fn read(&self, _ctx: &ReadContext<'_>) -> ReadOutcome {
        ReadOutcome::CacheMiss
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Path canonicalization
// ─────────────────────────────────────────────────────────────────────────────

/// Canonicalizes an attribute path so that registration and lookup agree on one
/// key.
///
/// Surrounding whitespace is trimmed, a `.` separator is accepted and rewritten
/// to `$`, and the functional-constraint segment is upper-cased; the logical
/// node, data object, and attribute segments keep their case, which is
/// significant in IEC 61850 names.
///
/// # Errors
///
/// Returns `ServerError::InvalidModel` for an empty path, for fewer than three
/// segments, for an empty segment, which a repeated or leading separator
/// produces, and for a second segment that is not a functional-constraint name.
pub(crate) fn canonicalize_attr_path(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ServerError::InvalidModel("handler path is empty".into()));
    }
    let normalized: String = trimmed
        .chars()
        .map(|c| if c == '.' { '$' } else { c })
        .collect();
    let parts: Vec<&str> = normalized.split('$').collect();
    if parts.len() < 3 {
        return Err(ServerError::InvalidModel(format!(
            "handler path `{raw}` has fewer than three segments, LN$FC$DO[$DA]* is required"
        )));
    }
    if parts.iter().any(|p| p.is_empty()) {
        return Err(ServerError::InvalidModel(format!(
            "handler path `{raw}` has an empty segment"
        )));
    }
    let fc_upper = parts[1].to_ascii_uppercase();
    FC::parse(&fc_upper).map_err(|e| {
        ServerError::InvalidModel(format!(
            "handler path `{raw}` names no functional constraint `{}`: {e}",
            parts[1]
        ))
    })?;

    let mut rebuilt = String::with_capacity(normalized.len());
    for (i, seg) in parts.iter().enumerate() {
        if i > 0 {
            rebuilt.push('$');
        }
        if i == 1 {
            rebuilt.push_str(&fc_upper);
        } else {
            rebuilt.push_str(seg);
        }
    }
    Ok(rebuilt)
}

/// Reports whether canonical path `below` names a node beneath the node `above`
/// names.
pub(crate) fn is_below(below: &str, above: &str) -> bool {
    below.len() > above.len() && below.starts_with(above) && below.as_bytes()[above.len()] == b'$'
}

/// Reports whether two canonical paths name the same node, or one names a node
/// beneath the other.
fn on_the_same_branch(a: &str, b: &str) -> bool {
    a == b || is_below(a, b) || is_below(b, a)
}

// ─────────────────────────────────────────────────────────────────────────────
// HandlerRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// Holds the read and write handlers, keyed by canonical attribute path,
/// together with the flag that bypasses read handlers entirely.
///
/// The flag is atomic rather than locked, so a read need not take the lock to
/// find out that handlers are disabled.
#[derive(Debug, Default)]
pub struct HandlerRegistry {
    read: RwLock<HashMap<String, Arc<dyn ReadHandler>>>,
    write: RwLock<HashMap<String, Arc<dyn AttributeAccessHandler>>>,
    /// While set, the Read service consults no read handler and answers from
    /// the model. It does not otherwise change the service: a path that does
    /// not exist still answers object-non-existent.
    ignore_read_access: AtomicBool,
}

impl HandlerRegistry {
    /// Returns an empty registry with the read handler bypass disabled.
    pub fn new() -> Self {
        Self::default()
    }

    // ─── Read handlers ──────────────────────────────────────────────────

    /// Registers a read handler for an attribute path.
    ///
    /// Installing twice on one path replaces the earlier handler and logs a
    /// warning, so the shadowing is visible to an operator.
    ///
    /// # Errors
    ///
    /// Returns the error of `canonicalize_attr_path` for a malformed path.
    pub fn install_read_handler(&self, path: &str, handler: Arc<dyn ReadHandler>) -> Result<()> {
        let key = canonicalize_attr_path(path)?;
        let mut g = crate::compat::rwlock_write(&self.read).ok_or_else(|| {
            ServerError::InvalidModel("HandlerRegistry.read RwLock poisoned".into())
        })?;
        if g.contains_key(&key) {
            tracing::warn!(
                path = %key,
                "a read handler was already installed on this path and has been replaced"
            );
        }
        g.insert(key, handler);
        Ok(())
    }

    /// Looks up the read handler for a path, canonicalizing it first.
    pub fn lookup_read(&self, path: &str) -> Option<Arc<dyn ReadHandler>> {
        let key = canonicalize_attr_path(path).ok()?;
        let g = crate::compat::rwlock_read(&self.read)?;
        g.get(&key).cloned()
    }

    /// Returns the read handlers installed on the path `path`, on the nodes
    /// above it and on the nodes below it, so one read looks the registry up
    /// once. `path` may name a logical node or a functional-constraint group,
    /// which no handler is installed on but which has handlers below it.
    pub(crate) fn read_handlers_around(&self, path: &str) -> Vec<(String, Arc<dyn ReadHandler>)> {
        let Some(g) = crate::compat::rwlock_read(&self.read) else {
            return Vec::new();
        };
        g.iter()
            .filter(|(key, _)| on_the_same_branch(key, path))
            .map(|(key, handler)| (key.clone(), Arc::clone(handler)))
            .collect()
    }

    // ─── Write handlers ─────────────────────────────────────────────────

    /// Registers a write access handler for an attribute path.
    ///
    /// Installing twice on one path replaces the earlier handler and logs a
    /// warning.
    ///
    /// # Errors
    ///
    /// Returns the error of `canonicalize_attr_path` for a malformed path.
    pub fn install_write_access_handler(
        &self,
        path: &str,
        handler: Arc<dyn AttributeAccessHandler>,
    ) -> Result<()> {
        let key = canonicalize_attr_path(path)?;
        let mut g = crate::compat::rwlock_write(&self.write).ok_or_else(|| {
            ServerError::InvalidModel("HandlerRegistry.write RwLock poisoned".into())
        })?;
        if g.contains_key(&key) {
            tracing::warn!(
                path = %key,
                "a write access handler was already installed on this path and has been replaced"
            );
        }
        g.insert(key, handler);
        Ok(())
    }

    /// Looks up the write handler for a path, canonicalizing it first.
    pub fn lookup_write(&self, path: &str) -> Option<Arc<dyn AttributeAccessHandler>> {
        let key = canonicalize_attr_path(path).ok()?;
        let g = crate::compat::rwlock_read(&self.write)?;
        g.get(&key).cloned()
    }

    /// Returns the write handlers installed on the canonical path `path`, on
    /// the nodes above it and on the nodes below it, so one write looks the
    /// registry up once.
    pub(crate) fn write_handlers_around(
        &self,
        path: &str,
    ) -> Vec<(String, Arc<dyn AttributeAccessHandler>)> {
        let Some(g) = crate::compat::rwlock_read(&self.write) else {
            return Vec::new();
        };
        g.iter()
            .filter(|(key, _)| on_the_same_branch(key, path))
            .map(|(key, handler)| (key.clone(), Arc::clone(handler)))
            .collect()
    }

    // ─── Read handler bypass ────────────────────────────────────────────

    /// Enables or disables the read handler bypass.
    ///
    /// While enabled, the Read service consults no read handler and answers
    /// from the model.
    pub fn set_ignore_read_access(&self, on: bool) {
        self.ignore_read_access.store(on, Ordering::SeqCst);
    }

    /// Reports whether the read handler bypass is enabled.
    pub fn ignore_read_access(&self) -> bool {
        self.ignore_read_access.load(Ordering::SeqCst)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    #[test]
    fn canonicalize_dot_to_dollar() {
        let p = canonicalize_attr_path("MMXU1.MX.TotW.mag").unwrap();
        assert_eq!(p, "MMXU1$MX$TotW$mag");
    }

    #[test]
    fn canonicalize_fc_uppercase() {
        let p = canonicalize_attr_path("MMXU1$mx$TotW$mag").unwrap();
        assert_eq!(p, "MMXU1$MX$TotW$mag");
    }

    #[test]
    fn canonicalize_trim_whitespace() {
        let p = canonicalize_attr_path("  GGIO1$cf$Mod$ctlModel  ").unwrap();
        assert_eq!(p, "GGIO1$CF$Mod$ctlModel");
    }

    #[test]
    fn canonicalize_rejects_short_paths() {
        assert!(matches!(
            canonicalize_attr_path("MMXU1$MX"),
            Err(ServerError::InvalidModel(_))
        ));
        assert!(matches!(
            canonicalize_attr_path("MMXU1"),
            Err(ServerError::InvalidModel(_))
        ));
    }

    #[test]
    fn canonicalize_rejects_empty() {
        assert!(matches!(
            canonicalize_attr_path(""),
            Err(ServerError::InvalidModel(_))
        ));
        assert!(matches!(
            canonicalize_attr_path("   "),
            Err(ServerError::InvalidModel(_))
        ));
    }

    #[test]
    fn canonicalize_rejects_empty_segments() {
        assert!(matches!(
            canonicalize_attr_path("MMXU1$$MX$TotW"),
            Err(ServerError::InvalidModel(_))
        ));
        assert!(matches!(
            canonicalize_attr_path("MMXU1$MX$$mag"),
            Err(ServerError::InvalidModel(_))
        ));
    }

    #[test]
    fn canonicalize_rejects_unknown_fc() {
        assert!(matches!(
            canonicalize_attr_path("MMXU1$XX$TotW$mag"),
            Err(ServerError::InvalidModel(_))
        ));
    }

    #[test]
    fn deny_all_read_handler_returns_error() {
        let h = DenyAllReadHandler {
            error: DataAccessError::ObjectAccessDenied,
        };
        let ctx = ReadContext::new("MMXU1$MX$TotW$mag", FC::Mx, 1);
        match h.read(&ctx) {
            ReadOutcome::Error(DataAccessError::ObjectAccessDenied) => {}
            other => {
                panic!("the deny-all handler must refuse with object-access-denied, got {other:?}")
            }
        }
    }

    #[test]
    fn silent_read_handler_returns_cache_miss() {
        let h = SilentReadHandler;
        let ctx = ReadContext::new("MMXU1$MX$TotW$mag", FC::Mx, 1);
        assert!(matches!(h.read(&ctx), ReadOutcome::CacheMiss));
    }

    #[test]
    fn registry_install_and_lookup_read() {
        let reg = HandlerRegistry::new();
        let h = Arc::new(SilentReadHandler);
        reg.install_read_handler("MMXU1$MX$TotW$mag", h).unwrap();
        assert!(reg.lookup_read("MMXU1$MX$TotW$mag").is_some());
        assert!(reg.lookup_read("MMXU1$MX$TotW$q").is_none());
    }

    #[test]
    fn registry_lookup_uses_canonicalization() {
        // Installed with dot separators and a lower-case constraint, looked up
        // with dollar separators and an upper-case one.
        let reg = HandlerRegistry::new();
        let h = Arc::new(SilentReadHandler);
        reg.install_read_handler("MMXU1.mx.TotW.mag", h).unwrap();
        assert!(
            reg.lookup_read("MMXU1$MX$TotW$mag").is_some(),
            "both spellings must canonicalize to the same key"
        );
    }

    #[test]
    fn registry_install_replaces_with_warn() {
        // The later handler wins.
        let reg = HandlerRegistry::new();

        #[derive(Debug)]
        struct TaggedHandler(#[allow(dead_code)] u32);
        impl ReadHandler for TaggedHandler {
            fn read(&self, _ctx: &ReadContext<'_>) -> ReadOutcome {
                ReadOutcome::Error(DataAccessError::HardwareFault)
            }
        }

        reg.install_read_handler("MMXU1$MX$TotW$mag", Arc::new(TaggedHandler(1)))
            .unwrap();
        reg.install_read_handler("MMXU1$MX$TotW$mag", Arc::new(TaggedHandler(2)))
            .unwrap();
        assert!(reg.lookup_read("MMXU1$MX$TotW$mag").is_some());
        // The warning itself is not asserted here, since no subscriber is
        // installed; the test covers that the second install succeeds and the
        // path stays resolvable.
    }

    #[test]
    fn registry_ignore_read_access_default_false() {
        let reg = HandlerRegistry::new();
        assert!(!reg.ignore_read_access());
        reg.set_ignore_read_access(true);
        assert!(reg.ignore_read_access());
        reg.set_ignore_read_access(false);
        assert!(!reg.ignore_read_access());
    }

    #[test]
    fn registry_install_write_handler() {
        #[derive(Debug)]
        struct CountingWriter {
            count: AtomicU32,
        }
        impl AttributeAccessHandler for CountingWriter {
            fn on_write(&self, _ctx: &WriteContext<'_>, _v: &MmsValue) -> WriteOutcome {
                self.count.fetch_add(1, Ordering::SeqCst);
                WriteOutcome::Accept
            }
        }

        let reg = HandlerRegistry::new();
        let h = Arc::new(CountingWriter {
            count: AtomicU32::new(0),
        });
        reg.install_write_access_handler("GGIO1$CF$Mod$ctlModel", h.clone())
            .unwrap();
        let found = reg.lookup_write("GGIO1$CF$Mod$ctlModel").unwrap();
        let ctx = WriteContext::new("GGIO1$CF$Mod$ctlModel", FC::Cf, 0);
        let _ = found.on_write(&ctx, &MmsValue::Integer(2));
        assert_eq!(h.count.load(Ordering::SeqCst), 1);
    }
}
