//! Entry points of the control services.
//!
//! | Control model | MMS operation | Entry point |
//! |---|---|---|
//! | direct with normal security | Write Oper | `handle_operate` |
//! | direct with enhanced security | Write Oper | `handle_operate` |
//! | select-before-operate, normal security: select | Read SBO | `handle_read_sbo` |
//! | select-before-operate, normal security: operate | Write Oper | `handle_operate` |
//! | select-before-operate, enhanced security: select | Write SBOw | `handle_sbow` |
//! | select-before-operate, enhanced security: operate | Write Oper | `handle_operate` |
//! | cancel | Write Cancel | `handle_cancel` |
//!
//! Enhanced security, whether direct or select-before-operate, must send a
//! CommandTermination InformationReport once the command finishes, successfully or
//! not. That is an unsolicited push rather than a confirmed response, so it is
//! routed through the `CommandTerminationSink` trait instead of the request path.

use super::handler::{CheckHandler, ControlHandler, WaitForExecutionHandler};
use super::model::{CancelParams, ControlAction, ControlAddCause, ControlModel, OperParams};
use super::object::{CancelResult, ControlObject, OperateBeginResult};
use bytes::{Bytes, BytesMut};
use iec61850_model::MmsValue;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

// ─────────────────────────────────────────────────────────────────────────────
// CommandTermination sink
// ─────────────────────────────────────────────────────────────────────────────

/// Delivers a CommandTermination to one connection.
///
/// A command termination is an unsolicited InformationReport, so it cannot travel
/// on the response path of the request that caused it. This trait keeps the
/// control services independent of how a connection is written to.
pub trait CommandTerminationSink: Send + Sync {
    /// Sends a positive CommandTermination for a command that succeeded.
    ///
    /// `oper_value` is the encoded Oper structure the client sent, which the client
    /// decodes back into the Operate parameters when it receives the report.
    fn send_positive(&self, obj_ref: &str, conn_id: u64, oper_value: Bytes);
    /// Sends a negative CommandTermination, carrying the cause of the failure.
    fn send_negative(
        &self,
        obj_ref: &str,
        conn_id: u64,
        add_cause: ControlAddCause,
        oper_value: Bytes,
    );
}

/// Sink that sends nothing; normal security needs no CommandTermination.
#[derive(Debug)]
pub struct NoOpCommandTermination;

impl CommandTerminationSink for NoOpCommandTermination {
    fn send_positive(&self, _obj_ref: &str, _conn_id: u64, _oper_value: Bytes) {}
    fn send_negative(
        &self,
        _obj_ref: &str,
        _conn_id: u64,
        _add_cause: ControlAddCause,
        _oper_value: Bytes,
    ) {
    }
}

/// Sink that records what it was asked to send; for tests.
#[derive(Debug)]
pub struct RecordingCommandTermination {
    /// Every event the sink was asked to send, in order.
    pub events: Arc<std::sync::Mutex<Vec<TerminationEvent>>>,
}

/// One CommandTermination that `RecordingCommandTermination` captured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminationEvent {
    /// The command finished successfully.
    Positive {
        /// Object reference the command targeted.
        obj_ref: String,
        /// Connection the command arrived on.
        conn_id: u64,
        /// Encoded Oper structure.
        oper_value: Bytes,
    },
    /// The command failed.
    Negative {
        /// Object reference the command targeted.
        obj_ref: String,
        /// Connection the command arrived on.
        conn_id: u64,
        /// Cause reported to the client.
        add_cause: ControlAddCause,
        /// Encoded Oper structure.
        oper_value: Bytes,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// ChannelCommandTermination: routing from the dispatcher to a connection task
// ─────────────────────────────────────────────────────────────────────────────

/// One CommandTermination event delivered to a connection, with the metadata
/// needed to build the PDU.
///
/// The connection task receives this and encodes the InformationReport before
/// writing it to the socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionTerminationEvent {
    /// The command finished successfully.
    Positive {
        /// The object reference, `<LD>/<LN>$CO$<DO>`.
        obj_ref: String,
        /// Encoded Oper structure, which becomes the second AccessResult of the
        /// InformationReport.
        oper_value: Bytes,
    },
    /// The command failed.
    Negative {
        /// The object reference, `<LD>/<LN>$CO$<DO>`.
        obj_ref: String,
        /// Cause reported to the client.
        add_cause: ControlAddCause,
        /// Encoded Oper structure, which becomes the second AccessResult of the
        /// InformationReport.
        oper_value: Bytes,
    },
}

/// Routes a CommandTermination to the right connection over a per-connection
/// channel.
///
/// The connection lifecycle calls `register(conn_id, sender)` when a connection is
/// established and `deregister(conn_id)` when it ends. The control services push
/// through the `CommandTerminationSink` trait and this implementation resolves the
/// connection id to its sender.
///
/// The event is queued rather than written to the socket inline, so a control task
/// and socket I/O never block one another.
#[derive(Clone, Default)]
pub struct ChannelCommandTermination {
    inner: Arc<RwLock<HashMap<u64, mpsc::UnboundedSender<ConnectionTerminationEvent>>>>,
}

impl std::fmt::Debug for ChannelCommandTermination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.inner.read().map(|g| g.len()).unwrap_or(0);
        f.debug_struct("ChannelCommandTermination")
            .field("connections", &count)
            .finish()
    }
}

impl ChannelCommandTermination {
    /// Creates a router with no connections registered.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers the channel of one connection.
    pub fn register(
        &self,
        conn_id: u64,
        sender: mpsc::UnboundedSender<ConnectionTerminationEvent>,
    ) {
        if let Ok(mut g) = self.inner.write() {
            g.insert(conn_id, sender);
        } else {
            tracing::warn!(conn_id, "command termination registry lock poisoned");
        }
    }

    /// Removes the channel of one connection, called when it closes.
    pub fn deregister(&self, conn_id: u64) {
        if let Ok(mut g) = self.inner.write() {
            g.remove(&conn_id);
        }
    }

    fn dispatch(&self, conn_id: u64, ev: ConnectionTerminationEvent) {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::warn!(conn_id, "command termination registry read lock poisoned");
                return;
            }
        };
        match g.get(&conn_id) {
            Some(tx) => {
                if let Err(e) = tx.send(ev) {
                    // The receiver is gone, so the connection task is shutting down.
                    tracing::warn!(
                        conn_id,
                        error = %e,
                        "command termination undeliverable: receiver gone"
                    );
                }
            }
            None => {
                // The connection closed or was never registered; not fatal.
                tracing::warn!(
                    conn_id,
                    "command termination dropped: no channel registered for this connection"
                );
            }
        }
    }
}

impl CommandTerminationSink for ChannelCommandTermination {
    fn send_positive(&self, obj_ref: &str, conn_id: u64, oper_value: Bytes) {
        self.dispatch(
            conn_id,
            ConnectionTerminationEvent::Positive {
                obj_ref: obj_ref.to_string(),
                oper_value,
            },
        );
    }

    fn send_negative(
        &self,
        obj_ref: &str,
        conn_id: u64,
        add_cause: ControlAddCause,
        oper_value: Bytes,
    ) {
        self.dispatch(
            conn_id,
            ConnectionTerminationEvent::Negative {
                obj_ref: obj_ref.to_string(),
                add_cause,
                oper_value,
            },
        );
    }
}

impl CommandTerminationSink for RecordingCommandTermination {
    fn send_positive(&self, obj_ref: &str, conn_id: u64, oper_value: Bytes) {
        if let Ok(mut g) = self.events.lock() {
            g.push(TerminationEvent::Positive {
                obj_ref: obj_ref.into(),
                conn_id,
                oper_value,
            });
        }
    }
    fn send_negative(
        &self,
        obj_ref: &str,
        conn_id: u64,
        add_cause: ControlAddCause,
        oper_value: Bytes,
    ) {
        if let Ok(mut g) = self.events.lock() {
            g.push(TerminationEvent::Negative {
                obj_ref: obj_ref.into(),
                conn_id,
                add_cause,
                oper_value,
            });
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Service results
// ─────────────────────────────────────────────────────────────────────────────

/// Result of an Operate, SBOw, or Cancel service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceResult {
    /// The service succeeded.
    Success,
    /// The service failed, with the cause to report.
    Failure(ControlAddCause),
}

// ─────────────────────────────────────────────────────────────────────────────
// Select, normal security: Read SBO
// ─────────────────────────────────────────────────────────────────────────────

/// Handles a read of `$CO$<DO>$SBO`, the select of the normal-security
/// select-before-operate model.
///
/// Returns `Some(object_reference)` when the check handler admits the request and
/// the object is selected, and `None` when it is refused, which the caller answers
/// with an empty string on the wire.
pub fn handle_read_sbo(
    obj: &ControlObject,
    conn_id: u64,
    check_handler: Option<&Arc<dyn CheckHandler>>,
) -> Option<String> {
    // Every control entry point first expires a stale selection, so the object is
    // unselected again and a fresh select can succeed.
    obj.check_sbo_timeout();

    // A status-only object never accepts a control request.
    if obj.config.ctl_model == ControlModel::StatusOnly {
        tracing::warn!(
            name = %obj.config.name,
            "read SBO refused: the object is status-only"
        );
        return None;
    }

    // Only the normal-security select-before-operate model has an SBO attribute.
    if obj.config.ctl_model != ControlModel::SboNormal {
        tracing::warn!(
            name = %obj.config.name,
            ctl_model = ?obj.config.ctl_model,
            "read SBO refused: the control model is not select-before-operate with normal security"
        );
        return None;
    }

    // A select carries no control value.
    let action = ControlAction::new(
        0,
        Default::default(),
        [0u8; 8],
        false,
        false,
        false,
        true,
        0,
        conn_id,
    );

    // The check handler receives no control value on this select.
    if let Some(h) = check_handler {
        if let Err(cause) = h.check(&action, None, false, false) {
            tracing::warn!(
                name = %obj.config.name,
                ?cause,
                "read SBO refused by the check handler"
            );
            return None;
        }
    }

    match obj.try_select(conn_id) {
        Ok(true) => {
            let obj_ref = obj.object_ref();
            tracing::debug!(
                name = %obj.config.name,
                conn_id,
                obj_ref = %obj_ref,
                "select accepted"
            );
            Some(obj_ref)
        }
        Ok(false) => {
            tracing::warn!(
                name = %obj.config.name,
                "read SBO refused: the object is already selected"
            );
            None
        }
        Err(e) => {
            tracing::warn!(name = %obj.config.name, error = %e, "read SBO failed internally");
            None
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Select with value, enhanced security: Write SBOw
// ─────────────────────────────────────────────────────────────────────────────

/// Handles a write to `$CO$<DO>$SBOw`, the select of the enhanced-security
/// select-before-operate model.
pub async fn handle_sbow(
    obj: &ControlObject,
    conn_id: u64,
    raw_value: &MmsValue,
    check_handler: Option<&Arc<dyn CheckHandler>>,
) -> ServiceResult {
    // Expire a stale selection first.
    obj.check_sbo_timeout();

    // A status-only object never accepts a control request.
    if obj.config.ctl_model == ControlModel::StatusOnly {
        tracing::warn!(name = %obj.config.name, "SBOw refused: the object is status-only");
        return ServiceResult::Failure(ControlAddCause::NotSupported);
    }

    // Parse the SBOw parameters.
    let params = match OperParams::from_mms_value(raw_value) {
        Some(p) => p,
        None => {
            tracing::warn!(name = %obj.config.name, "SBOw refused: parameters did not parse");
            return ServiceResult::Failure(ControlAddCause::InconsistentParameters);
        }
    };

    // The origin field must be well formed.
    if !params.origin.is_valid() {
        tracing::warn!(name = %obj.config.name, "SBOw refused: malformed origin field");
        return ServiceResult::Failure(ControlAddCause::InconsistentParameters);
    }

    let action = ControlAction::new(
        params.ctl_num,
        params.origin.clone(),
        params.t,
        params.test,
        params.synchro_check,
        params.interlock_check,
        true, // this is a select
        0,
        conn_id,
    );

    // A select with value passes the control value to the check handler.
    if let Some(h) = check_handler {
        if let Err(cause) = h.check(
            &action,
            Some(&params.ctl_val),
            params.test,
            params.interlock_check,
        ) {
            tracing::warn!(
                name = %obj.config.name,
                ?cause,
                "SBOw refused by the check handler"
            );
            return ServiceResult::Failure(cause);
        }
    }

    // Record the SBOw parameters so the Operate can be compared against them.
    match obj.try_sbow_select(conn_id, &params) {
        Ok(true) => {
            tracing::debug!(name = %obj.config.name, conn_id, "select-with-value accepted");
            ServiceResult::Success
        }
        Ok(false) => {
            tracing::warn!(name = %obj.config.name, "SBOw refused: the object is already selected");
            ServiceResult::Failure(ControlAddCause::LockedByOtherClient)
        }
        Err(e) => {
            tracing::warn!(name = %obj.config.name, error = %e, "SBOw failed internally");
            ServiceResult::Failure(ControlAddCause::Unknown)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Operate
// ─────────────────────────────────────────────────────────────────────────────

/// Handles a write to `$CO$<DO>$Oper`, for every control model.
///
/// With enhanced security a CommandTermination is sent once the command finishes,
/// whether it succeeded or failed.
pub async fn handle_operate(
    obj: &ControlObject,
    conn_id: u64,
    raw_value: &MmsValue,
    check_handler: Option<&Arc<dyn CheckHandler>>,
    wait_handler: Option<&Arc<dyn WaitForExecutionHandler>>,
    operate_handler: Option<&Arc<dyn ControlHandler>>,
    ct_sink: &dyn CommandTerminationSink,
) -> ServiceResult {
    // Expire a stale selection first; a select-before-operate object then reports
    // that it is not selected.
    obj.check_sbo_timeout();

    // Parse the Oper parameters.
    let params = match OperParams::from_mms_value(raw_value) {
        Some(p) => p,
        None => {
            tracing::warn!(name = %obj.config.name, "operate refused: parameters did not parse");
            return ServiceResult::Failure(ControlAddCause::InconsistentParameters);
        }
    };

    // Keep the client's Oper structure encoded, so a CommandTermination can carry
    // it back as its second AccessResult.
    let oper_value_bytes: Bytes = encode_mms_value_to_bytes(raw_value);

    let is_enhanced = matches!(
        obj.config.ctl_model,
        ControlModel::DirectEnhanced | ControlModel::SboEnhanced
    );

    // Admit the request: state machine and parameter checks.
    let begin = match obj.begin_operate(conn_id, &params) {
        Ok(Some(r)) => r,
        Ok(None) => return ServiceResult::Failure(ControlAddCause::Unknown),
        Err(e) => {
            tracing::warn!(name = %obj.config.name, error = %e, "operate failed internally");
            return ServiceResult::Failure(ControlAddCause::Unknown);
        }
    };

    match begin {
        OperateBeginResult::Denied(cause) => {
            // Enhanced security must tell the client about every refused Operate,
            // including one refused because the object was not selected or its
            // parameters differed. Normal security and status-only send nothing.
            if is_enhanced {
                ct_sink.send_negative(&obj.object_ref(), conn_id, cause, oper_value_bytes.clone());
            }
            return ServiceResult::Failure(cause);
        }
        OperateBeginResult::Accepted => {}
    }

    let action = ControlAction::new(
        params.ctl_num,
        params.origin.clone(),
        params.t,
        params.test,
        params.synchro_check,
        params.interlock_check,
        false, // this is an operate, not a select
        params.oper_tm_ms,
        conn_id,
    );

    // Static check, before the dynamic one.
    if let Some(h) = check_handler {
        if let Err(cause) = h.check(
            &action,
            Some(&params.ctl_val),
            params.test,
            params.interlock_check,
        ) {
            tracing::warn!(name = %obj.config.name, ?cause, "operate refused by the check handler");
            obj.abort_to_unselected();
            if is_enhanced {
                ct_sink.send_negative(&obj.object_ref(), conn_id, cause, oper_value_bytes.clone());
            }
            return ServiceResult::Failure(cause);
        }
    }

    // Dynamic check.
    if let Some(h) = wait_handler {
        match h
            .wait_for_execution(&action, &params.ctl_val, params.test, params.synchro_check)
            .await
        {
            Ok(()) => {}
            Err(cause) => {
                tracing::warn!(name = %obj.config.name, ?cause, "operate refused by the dynamic check");
                obj.abort_to_unselected();
                if is_enhanced {
                    ct_sink.send_negative(
                        &obj.object_ref(),
                        conn_id,
                        cause,
                        oper_value_bytes.clone(),
                    );
                }
                return ServiceResult::Failure(cause);
            }
        }
    }

    obj.set_state_operate();

    // Run the command.
    let result = if let Some(h) = operate_handler {
        h.operate(&action, &params.ctl_val, params.test).await
    } else {
        // Without a handler the command is treated as successful.
        Ok(())
    };

    // Return to ready or unselected according to the select class.
    obj.finish_operate();

    match result {
        Ok(()) => {
            tracing::debug!(name = %obj.config.name, "operate succeeded");
            if is_enhanced {
                ct_sink.send_positive(&obj.object_ref(), conn_id, oper_value_bytes.clone());
            }
            ServiceResult::Success
        }
        Err(cause) => {
            tracing::warn!(name = %obj.config.name, ?cause, "operate failed in the control handler");
            if is_enhanced {
                ct_sink.send_negative(&obj.object_ref(), conn_id, cause, oper_value_bytes.clone());
            }
            ServiceResult::Failure(cause)
        }
    }
}

/// Encodes an `MmsValue` into its wire bytes.
///
/// The result becomes the second AccessResult of a CommandTermination
/// InformationReport.
fn encode_mms_value_to_bytes(v: &MmsValue) -> Bytes {
    use crate::service::convert::mms_value_to_mms_data;
    let mut buf = BytesMut::new();
    mms_value_to_mms_data(v).encode(&mut buf);
    buf.freeze()
}

// ─────────────────────────────────────────────────────────────────────────────
// Cancel
// ─────────────────────────────────────────────────────────────────────────────

/// Handles a write to `$CO$<DO>$Cancel`.
pub fn handle_cancel(obj: &ControlObject, conn_id: u64, raw_value: &MmsValue) -> ServiceResult {
    // Parameters that do not parse are reported, and the cancel is still attempted.
    if CancelParams::from_mms_value(raw_value).is_none() {
        tracing::warn!(
            name = %obj.config.name,
            "cancel parameters did not parse, attempting the cancel anyway"
        );
    }

    match obj.try_cancel(conn_id) {
        CancelResult::Accepted => {
            tracing::debug!(name = %obj.config.name, conn_id, "cancel accepted");
            ServiceResult::Success
        }
        CancelResult::Denied(cause) => {
            tracing::warn!(name = %obj.config.name, ?cause, conn_id, "cancel refused");
            ServiceResult::Failure(cause)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Parsing a control object path
// ─────────────────────────────────────────────────────────────────────────────

/// Which control attribute a path names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoAttr {
    /// `$CO$<DO>$SBO`: the select of the normal-security model, read by a client.
    Sbo,
    /// `$CO$<DO>$SBOw`: the select of the enhanced-security model, written by a
    /// client.
    SBOw,
    /// `$CO$<DO>$Oper`: the operate, written by a client.
    Oper,
    /// `$CO$<DO>$Cancel`: the cancel, written by a client.
    Cancel,
}

/// Parses an MMS item identifier as a control attribute path.
///
/// The path has four segments, `LN$CO$DO$Attr`, with the functional constraint
/// `CO`. Returns the data object name and the attribute, or `None` when the
/// identifier is not a control path.
pub fn parse_co_item_id(item_id: &str) -> Option<(&str, CoAttr)> {
    let parts: Vec<&str> = item_id.split('$').collect();
    if parts.len() == 4 && parts[1] == "CO" {
        let do_name = parts[2];
        let attr = match parts[3] {
            "SBO" => CoAttr::Sbo,
            "SBOw" => CoAttr::SBOw,
            "Oper" => CoAttr::Oper,
            "Cancel" => CoAttr::Cancel,
            _ => return None,
        };
        Some((do_name, attr))
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{
        handler::{AlwaysAcceptCheckHandler, AlwaysAcceptWaitHandler, AlwaysSuccessOperateHandler},
        model::SboClass,
        object::ControlObjectConfig,
        state::ControlState,
    };
    use iec61850_model::MmsValue;

    fn make_direct_obj(model: ControlModel) -> ControlObject {
        ControlObject::new(ControlObjectConfig {
            name: "SPCSO1".into(),
            ln_name: "GGIO1".into(),
            domain: "IED1LD0".into(),
            ctl_model: model,
            sbo_timeout_ms: 5000,
            sbo_class: SboClass::OperateOnce,
        })
    }

    fn make_oper_value() -> MmsValue {
        // 6-element Oper structure
        MmsValue::Structure(vec![
            MmsValue::Boolean(true), // ctlVal
            MmsValue::Structure(vec![
                MmsValue::Integer(3),
                MmsValue::OctetString(vec![0x01]),
            ]), // origin
            MmsValue::Unsigned(1),   // ctlNum
            MmsValue::UtcTime([0u8; 8]), // T
            MmsValue::Boolean(false), // Test
            MmsValue::BitString {
                padding: 6,
                data: vec![0x40],
            }, // Check: interlockCheck
        ])
    }

    fn make_sbow_value() -> MmsValue {
        make_oper_value() // SBOw has the same structure as Oper
    }

    fn make_cancel_value() -> MmsValue {
        MmsValue::Structure(vec![
            MmsValue::Boolean(true),
            MmsValue::Structure(vec![
                MmsValue::Integer(3),
                MmsValue::OctetString(vec![0x01]),
            ]),
            MmsValue::Unsigned(1),
            MmsValue::UtcTime([0u8; 8]),
            MmsValue::Boolean(false),
        ])
    }

    // ── parse_co_item_id ────────────────────────────────────────────────

    #[test]
    fn parse_co_item_id_oper() {
        let (do_name, attr) = parse_co_item_id("GGIO1$CO$SPCSO1$Oper").unwrap();
        assert_eq!(do_name, "SPCSO1");
        assert_eq!(attr, CoAttr::Oper);
    }

    #[test]
    fn parse_co_item_id_sbo() {
        let (do_name, attr) = parse_co_item_id("GGIO1$CO$SPCSO1$SBO").unwrap();
        assert_eq!(do_name, "SPCSO1");
        assert_eq!(attr, CoAttr::Sbo);
    }

    #[test]
    fn parse_co_item_id_sbow() {
        let (_, attr) = parse_co_item_id("GGIO1$CO$SPCSO1$SBOw").unwrap();
        assert_eq!(attr, CoAttr::SBOw);
    }

    #[test]
    fn parse_co_item_id_cancel() {
        let (_, attr) = parse_co_item_id("GGIO1$CO$SPCSO1$Cancel").unwrap();
        assert_eq!(attr, CoAttr::Cancel);
    }

    #[test]
    fn parse_co_item_id_non_co_none() {
        assert!(parse_co_item_id("GGIO1$CF$Mod$ctlModel").is_none());
        assert!(parse_co_item_id("GGIO1$CO$SPCSO1$stVal").is_none());
        assert!(parse_co_item_id("GGIO1$CO").is_none());
    }

    // ── handle_read_sbo happy path ──────────────────────────────────────

    #[test]
    fn handle_read_sbo_accepted() {
        let obj = make_direct_obj(ControlModel::SboNormal);
        let h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);
        let result = handle_read_sbo(&obj, 1, Some(&h));
        assert!(result.is_some());
        assert!(result.unwrap().contains("SPCSO1"));
        assert_eq!(obj.state(), ControlState::Ready);
    }

    #[test]
    fn handle_read_sbo_status_only_rejected() {
        let obj = make_direct_obj(ControlModel::StatusOnly);
        let h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);
        let result = handle_read_sbo(&obj, 1, Some(&h));
        assert!(result.is_none());
    }

    // ── handle_cancel ────────────────────────────────────────────────────

    #[test]
    fn handle_cancel_sbo_selected_same_conn() {
        let obj = make_direct_obj(ControlModel::SboNormal);
        obj.try_select(1).unwrap();

        let cancel_val = make_cancel_value();
        let r = handle_cancel(&obj, 1, &cancel_val);
        assert_eq!(r, ServiceResult::Success);
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    #[test]
    fn handle_cancel_wrong_conn_denied() {
        let obj = make_direct_obj(ControlModel::SboNormal);
        obj.try_select(1).unwrap();

        let cancel_val = make_cancel_value();
        let r = handle_cancel(&obj, 2, &cancel_val);
        assert_eq!(
            r,
            ServiceResult::Failure(ControlAddCause::LockedByOtherClient)
        );
        assert_eq!(obj.state(), ControlState::Ready);
    }

    // ── handle_sbow happy path ────────────────────────────────────────────

    #[tokio::test]
    async fn handle_sbow_accepted() {
        let obj = make_direct_obj(ControlModel::SboEnhanced);
        let h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);
        let sbow_val = make_sbow_value();
        let r = handle_sbow(&obj, 1, &sbow_val, Some(&h)).await;
        assert_eq!(r, ServiceResult::Success);
        assert_eq!(obj.state(), ControlState::Ready);
    }

    // ── handle_operate direct-normal happy path ───────────────────────────

    #[tokio::test]
    async fn handle_operate_direct_normal_success() {
        let obj = make_direct_obj(ControlModel::DirectNormal);
        let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);
        let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
        let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
        let ct = NoOpCommandTermination;

        let oper_val = make_oper_value();
        let r = handle_operate(
            &obj,
            1,
            &oper_val,
            Some(&check_h),
            Some(&wait_h),
            Some(&oper_h),
            &ct,
        )
        .await;
        assert_eq!(r, ServiceResult::Success);
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    // ── Direct control with enhanced security sends a positive CommandTermination ──

    #[tokio::test]
    async fn handle_operate_direct_enhanced_sends_command_termination() {
        let obj = make_direct_obj(ControlModel::DirectEnhanced);
        let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);
        let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
        let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let ct = RecordingCommandTermination {
            events: events.clone(),
        };

        let oper_val = make_oper_value();
        let r = handle_operate(
            &obj,
            1,
            &oper_val,
            Some(&check_h),
            Some(&wait_h),
            Some(&oper_h),
            &ct,
        )
        .await;
        assert_eq!(r, ServiceResult::Success);

        let recorded = events.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert!(matches!(
            recorded[0],
            TerminationEvent::Positive { conn_id: 1, .. }
        ));
    }

    // ── handle_operate sbo-normal select + operate ────────────────────────

    #[tokio::test]
    async fn handle_operate_sbo_normal_flow() {
        let obj = make_direct_obj(ControlModel::SboNormal);
        // select first
        let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);
        handle_read_sbo(&obj, 1, Some(&check_h));
        assert_eq!(obj.state(), ControlState::Ready);

        let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
        let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
        let ct = NoOpCommandTermination;

        let oper_val = make_oper_value();
        let r = handle_operate(
            &obj,
            1,
            &oper_val,
            Some(&check_h),
            Some(&wait_h),
            Some(&oper_h),
            &ct,
        )
        .await;
        assert_eq!(r, ServiceResult::Success);
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    // ── handle_operate sbo-enhanced full flow ─────────────────────────────

    #[tokio::test]
    async fn handle_operate_sbo_enhanced_full_flow() {
        let obj = make_direct_obj(ControlModel::SboEnhanced);
        let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);

        // SBOw select
        let sbow_val = make_sbow_value();
        let r = handle_sbow(&obj, 1, &sbow_val, Some(&check_h)).await;
        assert_eq!(r, ServiceResult::Success);

        // Operate with the same parameters.
        let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
        let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let ct = RecordingCommandTermination {
            events: events.clone(),
        };

        let oper_val = make_oper_value();
        let r = handle_operate(
            &obj,
            1,
            &oper_val,
            Some(&check_h),
            Some(&wait_h),
            Some(&oper_h),
            &ct,
        )
        .await;
        assert_eq!(r, ServiceResult::Success);

        // Enhanced security sends a positive CommandTermination.
        let recorded = events.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert!(matches!(
            recorded[0],
            TerminationEvent::Positive { conn_id: 1, .. }
        ));
    }

    // ── handle_operate sbo-enhanced inconsistent params ───────────────────

    #[tokio::test]
    async fn handle_operate_sbo_enhanced_inconsistent_params_denied() {
        let obj = make_direct_obj(ControlModel::SboEnhanced);
        let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);

        // SBOw with Boolean(true)
        let sbow_val = make_sbow_value();
        handle_sbow(&obj, 1, &sbow_val, Some(&check_h)).await;

        // Operate with Boolean(false), which does not match the select.
        let oper_val = MmsValue::Structure(vec![
            MmsValue::Boolean(false), // a different control value
            MmsValue::Structure(vec![
                MmsValue::Integer(3),
                MmsValue::OctetString(vec![0x01]),
            ]),
            MmsValue::Unsigned(1),
            MmsValue::UtcTime([0u8; 8]),
            MmsValue::Boolean(false),
            MmsValue::BitString {
                padding: 6,
                data: vec![0x40],
            },
        ]);

        let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
        let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysSuccessOperateHandler);
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let ct = RecordingCommandTermination {
            events: events.clone(),
        };

        let r = handle_operate(
            &obj,
            1,
            &oper_val,
            Some(&check_h),
            Some(&wait_h),
            Some(&oper_h),
            &ct,
        )
        .await;
        assert_eq!(
            r,
            ServiceResult::Failure(ControlAddCause::InconsistentParameters)
        );
        // Differing parameters also deselect the object.
        assert_eq!(obj.state(), ControlState::Unselected);
    }

    // ── A failed enhanced-security operate sends a negative CommandTermination ──

    #[tokio::test]
    async fn handle_operate_direct_enhanced_fail_sends_negative() {
        use crate::control::handler::AlwaysFailOperateHandler;
        let obj = make_direct_obj(ControlModel::DirectEnhanced);
        let check_h: Arc<dyn CheckHandler> = Arc::new(AlwaysAcceptCheckHandler);
        let wait_h: Arc<dyn WaitForExecutionHandler> = Arc::new(AlwaysAcceptWaitHandler);
        let oper_h: Arc<dyn ControlHandler> = Arc::new(AlwaysFailOperateHandler {
            cause: ControlAddCause::BlockedByProcess,
        });
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let ct = RecordingCommandTermination {
            events: events.clone(),
        };

        let oper_val = make_oper_value();
        let r = handle_operate(
            &obj,
            1,
            &oper_val,
            Some(&check_h),
            Some(&wait_h),
            Some(&oper_h),
            &ct,
        )
        .await;
        assert_eq!(r, ServiceResult::Failure(ControlAddCause::BlockedByProcess));

        let recorded = events.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert!(matches!(
            recorded[0],
            TerminationEvent::Negative {
                add_cause: ControlAddCause::BlockedByProcess,
                ..
            }
        ));
    }
}
