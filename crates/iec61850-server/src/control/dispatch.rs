//! Routing of a write under functional constraint CO from the MMS dispatcher to
//! the control services, and the per-connection outbox that carries what the
//! write produces besides its response.
//!
//! The dispatcher answers synchronously, so a write runs the parse, the type
//! check against the model, and the admission checks inline, and moves the
//! execution of an accepted Operate onto its own task:
//!
//! - A refused SelectWithValue, Operate, or Cancel queues an InformationReport
//!   carrying only `LastApplError`, which the connection sends before the
//!   negative write response, per the additional cause diagnosis of
//!   IEC 61850-8-1.
//! - An accepted Operate is answered once its dynamic check, the
//!   wait-for-execution handler, has finished, per IEC 61850-7-2: positively when
//!   it passes, after which the command runs, and negatively, preceded by
//!   `LastApplError`, when it refuses. Without a dynamic check the answer is
//!   immediate. With a dynamic check the write response is deferred: the
//!   connection holds it back and sends the outcome the task posts. A write of
//!   more than one variable cannot be deferred and is answered positively when
//!   the Operate is accepted; when its dynamic check then refuses, an
//!   enhanced-security command is ended with a negative CommandTermination, the
//!   only way left to end its command sequence, and a normal-security one is
//!   logged.
//! - Under enhanced security the outcome of the command travels in the
//!   CommandTermination that ends it; normal security reports no outcome.

use super::conform::{conforms, declared_co_attribute, CoDeclaration};
use super::model::{CancelParams, ControlAddCause, ControlLastApplError, OperParams, OriginValue};
use super::registry::{ControlObjectEntry, ControlObjectsRegistry};
use super::service::{
    admit_operate, cancel, select_with_value, AcceptedOperate, CoAttr, CommandTerminationSink,
    ConnectionTerminationEvent, Refusal,
};
use bytes::Bytes;
use iec61850_mms::mms::pdu::common::{DataAccessError, ObjectName, WriteOutcome};
use iec61850_mms::mms::pdu::information_report::{
    encode_information_report, encode_last_appl_error_struct, LastApplErrorRef, OriginRef,
};
use iec61850_model::{IedModel, MmsValue};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

// ─────────────────────────────────────────────────────────────────────────────
// ControlOutbox
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of a deferred Operate, posted by its execution task.
// Only the connection loop of the integrated server reads it.
#[cfg_attr(not(feature = "full-server"), allow(dead_code))]
#[derive(Debug)]
pub(crate) struct DeferredWrite {
    /// Identifier the outbox handed out when the write was deferred.
    pub(crate) id: u64,
    /// Outcome to answer the write with.
    pub(crate) outcome: WriteOutcome,
    /// InformationReport carrying `LastApplError`, sent before the response when
    /// the command failed.
    pub(crate) last_appl_error: Option<Bytes>,
    /// Negative CommandTermination of an enhanced-security command whose
    /// dynamic check refused it, sent instead when the write could not wait and
    /// was answered positively at acceptance.
    pub(crate) termination: Option<ConnectionTerminationEvent>,
}

struct Slot {
    tx: mpsc::UnboundedSender<DeferredWrite>,
    before_response: Vec<Bytes>,
    deferred: Vec<u64>,
}

/// Per-connection queues of the control services, keyed by connection id.
///
/// A connection that registers here sends the queued reports ahead of the
/// response of the request that produced them, and answers a deferred write when
/// its outcome arrives. Without a registration, reports are dropped and nothing
/// is deferred.
///
/// Each queue is bounded by the work of one request: the reports of one write,
/// and at most one deferred outcome per control object, since an object admits a
/// single executing command.
#[derive(Default)]
pub(crate) struct ControlOutbox {
    conns: Mutex<HashMap<u64, Slot>>,
    next_id: AtomicU64,
}

impl std::fmt::Debug for ControlOutbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.conns.lock().map(|g| g.len()).unwrap_or(0);
        f.debug_struct("ControlOutbox")
            .field("connections", &count)
            .finish()
    }
}

// The connection loop of the integrated server is the only reader.
#[cfg_attr(not(feature = "full-server"), allow(dead_code))]
impl ControlOutbox {
    /// Registers a connection and returns the receiver of its deferred outcomes.
    pub(crate) fn register(&self, conn_id: u64) -> mpsc::UnboundedReceiver<DeferredWrite> {
        let (tx, rx) = mpsc::unbounded_channel();
        if let Ok(mut g) = self.conns.lock() {
            g.insert(
                conn_id,
                Slot {
                    tx,
                    before_response: Vec::new(),
                    deferred: Vec::new(),
                },
            );
        } else {
            tracing::warn!(
                conn_id,
                "control outbox lock poisoned, connection not registered"
            );
        }
        rx
    }

    /// Removes a connection, called when it closes.
    pub(crate) fn deregister(&self, conn_id: u64) {
        if let Ok(mut g) = self.conns.lock() {
            g.remove(&conn_id);
        }
    }

    /// Queues an encoded PDU to send before the response being produced.
    fn push_before_response(&self, conn_id: u64, pdu: Bytes) {
        match self.conns.lock() {
            Ok(mut g) => match g.get_mut(&conn_id) {
                Some(slot) => slot.before_response.push(pdu),
                None => tracing::debug!(
                    conn_id,
                    "last application error dropped: no connection is registered"
                ),
            },
            Err(_) => tracing::warn!(conn_id, "control outbox lock poisoned"),
        }
    }

    /// Takes the PDUs to send before the response of the request just dispatched.
    pub(crate) fn take_before_response(&self, conn_id: u64) -> Vec<Bytes> {
        self.conns
            .lock()
            .ok()
            .and_then(|mut g| {
                g.get_mut(&conn_id)
                    .map(|s| core::mem::take(&mut s.before_response))
            })
            .unwrap_or_default()
    }

    /// Defers the response of the request being dispatched.
    ///
    /// Returns the identifier of the deferral and the sender its outcome goes to,
    /// or `None` when the connection is not registered.
    fn defer(&self, conn_id: u64) -> Option<(u64, mpsc::UnboundedSender<DeferredWrite>)> {
        let mut g = self.conns.lock().ok()?;
        let slot = g.get_mut(&conn_id)?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        slot.deferred.push(id);
        Some((id, slot.tx.clone()))
    }

    /// Takes the identifiers of the deferrals the request just dispatched made.
    pub(crate) fn take_deferred(&self, conn_id: u64) -> Vec<u64> {
        self.conns
            .lock()
            .ok()
            .and_then(|mut g| {
                g.get_mut(&conn_id)
                    .map(|s| core::mem::take(&mut s.deferred))
            })
            .unwrap_or_default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CO write
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of a write under functional constraint CO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoWriteResult {
    /// The service accepted the request.
    Accepted,
    /// The service refused the request with this add cause.
    Refused(ControlAddCause),
    /// The value does not have the type of the attribute.
    TypeInconsistent,
    /// The model declares the data object without this attribute.
    NonExistent,
}

/// Target of a write under functional constraint CO.
pub(crate) struct CoTarget<'a> {
    /// MMS domain.
    pub(crate) domain: &'a str,
    /// Logical node name.
    pub(crate) ln_name: &'a str,
    /// Data object name.
    pub(crate) do_name: &'a str,
    /// The control attribute written: SBOw, Oper, or Cancel.
    pub(crate) attr: CoAttr,
}

impl CoTarget<'_> {
    pub(crate) fn attr_name(&self) -> &'static str {
        match self.attr {
            CoAttr::Sbo => "SBO",
            CoAttr::SBOw => "SBOw",
            CoAttr::Oper => "Oper",
            CoAttr::Cancel => "Cancel",
        }
    }

    /// The `CntrlObj` member of LastApplError, `<LD>/<LN>$CO$<DO>$<attribute>`.
    fn cntrl_obj(&self) -> String {
        format!(
            "{}/{}$CO${}${}",
            self.domain,
            self.ln_name,
            self.do_name,
            self.attr_name()
        )
    }
}

/// Runs a write of `SBOw`, `Oper`, or `Cancel` on a registered control object.
///
/// The value is checked against the attribute the model declares; an attribute
/// the model leaves out of a data object it declares does not exist, and an
/// object the model does not declare is checked against the structure of the
/// service only. A refusal queues `LastApplError` on the connection before the
/// caller answers.
pub(crate) fn write(
    registry: &ControlObjectsRegistry,
    model: &IedModel,
    entry: &ControlObjectEntry,
    conn_id: u64,
    target: &CoTarget<'_>,
    value: &MmsValue,
) -> CoWriteResult {
    entry.object.bind_model(model);
    match declared_co_attribute(
        model,
        target.domain,
        target.ln_name,
        target.do_name,
        target.attr_name(),
    ) {
        CoDeclaration::Attribute(da) => {
            if !conforms(da, value) {
                tracing::warn!(
                    domain = target.domain,
                    ln = target.ln_name,
                    do_name = target.do_name,
                    attr = target.attr_name(),
                    "control write refused: the value does not have the type of the attribute"
                );
                return CoWriteResult::TypeInconsistent;
            }
        }
        CoDeclaration::Absent => {
            tracing::warn!(
                domain = target.domain,
                ln = target.ln_name,
                do_name = target.do_name,
                attr = target.attr_name(),
                "control write refused: the data object has no such attribute"
            );
            return CoWriteResult::NonExistent;
        }
        CoDeclaration::Undeclared => {}
    }

    let outbox = registry.outbox();
    match target.attr {
        CoAttr::Sbo => CoWriteResult::Refused(ControlAddCause::NotSupported),
        CoAttr::SBOw => {
            let Some(params) = OperParams::from_mms_value(value) else {
                return type_inconsistent(target);
            };
            match select_with_value(
                &entry.object,
                conn_id,
                &params,
                entry.check_handler.as_ref(),
            ) {
                Ok(()) => CoWriteResult::Accepted,
                Err(refusal) => {
                    let lae =
                        last_appl_error_report(target, &params.origin, params.ctl_num, refusal);
                    outbox.push_before_response(conn_id, lae);
                    CoWriteResult::Refused(refusal.cause)
                }
            }
        }
        CoAttr::Cancel => {
            let Some(params) = CancelParams::from_mms_value(value) else {
                return type_inconsistent(target);
            };
            match cancel(&entry.object, conn_id) {
                Ok(()) => CoWriteResult::Accepted,
                Err(refusal) => {
                    let lae =
                        last_appl_error_report(target, &params.origin, params.ctl_num, refusal);
                    outbox.push_before_response(conn_id, lae);
                    CoWriteResult::Refused(refusal.cause)
                }
            }
        }
        CoAttr::Oper => operate(registry, outbox, entry, conn_id, target, value),
    }
}

/// Returns whether the model declares the data object `<domain>/<ln>$CO$<do_name>`
/// without an `SBO` attribute, which a read of `SBO` then does not find.
pub(crate) fn sbo_absent(model: &IedModel, domain: &str, ln_name: &str, do_name: &str) -> bool {
    matches!(
        declared_co_attribute(model, domain, ln_name, do_name, "SBO"),
        CoDeclaration::Absent
    )
}

fn type_inconsistent(target: &CoTarget<'_>) -> CoWriteResult {
    tracing::warn!(
        domain = target.domain,
        ln = target.ln_name,
        do_name = target.do_name,
        attr = target.attr_name(),
        "control write refused: the value does not have the structure of the service"
    );
    CoWriteResult::TypeInconsistent
}

fn operate(
    registry: &ControlObjectsRegistry,
    outbox: &Arc<ControlOutbox>,
    entry: &ControlObjectEntry,
    conn_id: u64,
    target: &CoTarget<'_>,
    value: &MmsValue,
) -> CoWriteResult {
    let Some(params) = OperParams::from_mms_value(value) else {
        return type_inconsistent(target);
    };
    let origin = params.origin.clone();
    let ctl_num = params.ctl_num;
    let refuse = |refusal: Refusal| {
        outbox.push_before_response(
            conn_id,
            last_appl_error_report(target, &origin, ctl_num, refusal),
        );
        CoWriteResult::Refused(refusal.cause)
    };

    let accepted = match admit_operate(
        &entry.object,
        conn_id,
        params,
        value,
        entry.check_handler.as_ref(),
        entry.wait_handler.as_ref(),
        entry.operate_handler.as_ref(),
    ) {
        Ok(a) => a,
        Err(refusal) => return refuse(refusal),
    };

    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        tracing::warn!(
            domain = target.domain,
            do_name = target.do_name,
            "operate refused: no tokio runtime is available to execute the command"
        );
        entry.object.abort_to_unselected();
        return refuse(Refusal::internal());
    };

    let ct_sink = registry.ct_sink().clone();
    let accepted = accepted.with_ct_sink(ct_sink.clone());
    let cntrl_obj = target.cntrl_obj();
    if !accepted.has_dynamic_check() {
        // Without a dynamic check the Operate is answered positively at once.
        accepted.mark_answered();
        runtime.spawn(run_answered(accepted, ct_sink, cntrl_obj));
        return CoWriteResult::Accepted;
    }

    let reply = outbox.defer(conn_id).map(|(id, tx)| DeferredReply {
        id,
        tx: Some(tx),
        last_appl_error: encode_last_appl_error(
            &cntrl_obj,
            &origin_ref(&origin),
            ctl_num,
            Refusal::internal(),
        ),
        termination: accepted.negative_termination(ControlAddCause::Unknown, true),
    });
    runtime.spawn(async move {
        let checked = accepted.dynamic_check().await;
        match reply {
            Some(reply) => {
                let (outcome, last_appl_error, termination) = match checked {
                    Ok(()) => (WriteOutcome::Success, None, None),
                    Err(cause) => (
                        WriteOutcome::Failure(add_cause_to_data_access_error(cause)),
                        Some(encode_last_appl_error(
                            &cntrl_obj,
                            &origin_ref(&origin),
                            ctl_num,
                            Refusal::by_check(cause),
                        )),
                        accepted.negative_termination(cause, false),
                    ),
                };
                let id = reply.id;
                if !reply.send(DeferredWrite {
                    id,
                    outcome,
                    last_appl_error,
                    termination,
                }) {
                    tracing::warn!(
                        cntrl_obj,
                        "operate response undeliverable: the connection has closed"
                    );
                }
            }
            None => {
                if let Err(cause) = checked {
                    tracing::warn!(
                        cntrl_obj,
                        ?cause,
                        "the dynamic check refused an operate whose write was already answered"
                    );
                    accepted.terminate(ct_sink.as_ref(), Err(cause));
                }
            }
        }
        if checked.is_ok() {
            accepted.mark_answered();
            run_answered(accepted, ct_sink, cntrl_obj).await;
        }
    });
    CoWriteResult::Accepted
}

/// The pending answer of a deferred write.
///
/// Dropped unanswered, as when the dynamic check panics, it answers the write
/// negatively as an internal failure of the server: `LastApplError` with
/// `Unknown`, and the negative CommandTermination of an enhanced-security
/// command whose write was already answered.
struct DeferredReply {
    id: u64,
    tx: Option<mpsc::UnboundedSender<DeferredWrite>>,
    last_appl_error: Bytes,
    termination: Option<ConnectionTerminationEvent>,
}

impl DeferredReply {
    /// Posts the outcome; returns whether the connection is still there to
    /// receive it.
    fn send(mut self, done: DeferredWrite) -> bool {
        self.tx.take().is_some_and(|tx| tx.send(done).is_ok())
    }
}

impl Drop for DeferredReply {
    fn drop(&mut self) {
        let Some(tx) = self.tx.take() else {
            return;
        };
        tracing::warn!("operate ended before its dynamic check finished, answering negatively");
        let _ = tx.send(DeferredWrite {
            id: self.id,
            outcome: WriteOutcome::Failure(DataAccessError::ObjectAccessDenied),
            last_appl_error: Some(self.last_appl_error.clone()),
            termination: self.termination.take(),
        });
    }
}

/// Runs an Operate that has been answered positively and reports its outcome:
/// a CommandTermination under enhanced security, and a log entry for a failure
/// under normal security, which reports no outcome to the client.
async fn run_answered(
    accepted: AcceptedOperate,
    ct_sink: Arc<dyn CommandTerminationSink>,
    cntrl_obj: String,
) {
    let result = accepted.run().await;
    if accepted.is_enhanced() {
        accepted.terminate(ct_sink.as_ref(), result);
    } else if let Err(cause) = result {
        tracing::warn!(
            cntrl_obj,
            ?cause,
            "operate failed under normal security, which reports no outcome"
        );
    }
}

fn origin_ref(origin: &OriginValue) -> OriginRef {
    OriginRef {
        or_cat: origin.or_cat,
        or_ident: origin.or_ident.clone(),
    }
}

fn last_appl_error_report(
    target: &CoTarget<'_>,
    origin: &OriginValue,
    ctl_num: u8,
    refusal: Refusal,
) -> Bytes {
    encode_last_appl_error(&target.cntrl_obj(), &origin_ref(origin), ctl_num, refusal)
}

/// Encodes an InformationReport carrying only `LastApplError`, with the
/// `CntrlObj`, origin, and `ctlNum` of the refused command.
pub(crate) fn encode_last_appl_error(
    cntrl_obj: &str,
    origin: &OriginRef,
    ctl_num: u8,
    refusal: Refusal,
) -> Bytes {
    let lae = LastApplErrorRef {
        ctl_obj: cntrl_obj.to_string(),
        error: last_appl_error_code(refusal) as i32,
        origin: origin.clone(),
        ctl_num,
        add_cause: refusal.cause as i32,
    };
    encode_information_report(&[(
        ObjectName::VmdSpecific("LastApplError".to_string()),
        encode_last_appl_error_struct(&lae),
    )])
}

/// Returns the `Error` member of LastApplError for a refused request.
///
/// A refusal by the checks of the control model carries `No Error` whatever its
/// add cause, a handler's `Unknown` included; only an internal failure of the
/// server carries `Unknown`, per IEC 61850-8-1.
pub(crate) fn last_appl_error_code(refusal: Refusal) -> ControlLastApplError {
    if refusal.internal {
        ControlLastApplError::Unknown
    } else {
        ControlLastApplError::NoError
    }
}

/// Returns the `Error` member of the LastApplError of a negative
/// CommandTermination, which ends a command that failed after its Operate was
/// answered positively, unless the server failed internally.
///
/// A failed operate test command, one whose `Test` is set, carries `Operator
/// Test Not OK`, per IEC 61850-8-1 §20.11. Any other command carries `No
/// Error`, since its failure is the outcome its add cause describes. A
/// time-activated command is never admitted, so `Timeout Test Not OK` does not
/// occur.
pub(crate) fn termination_error_code(test: bool) -> ControlLastApplError {
    if test {
        ControlLastApplError::OperatorTestNotOk
    } else {
        ControlLastApplError::NoError
    }
}

/// Maps a control add cause onto the data access error of a negative write
/// response, per the SelectWithValue, Operate, and Cancel mapping of
/// IEC 61850-8-1; the add cause itself travels in `LastApplError`.
///
/// An object that is selected, locked by another client, or executing is
/// temporarily unavailable; every other refusal denies access to the object.
pub(crate) fn add_cause_to_data_access_error(cause: ControlAddCause) -> DataAccessError {
    match cause {
        ControlAddCause::ObjectAlreadySelected
        | ControlAddCause::LockedByOtherClient
        | ControlAddCause::CommandAlreadyInExecution => DataAccessError::TemporarilyUnavailable,
        _ => DataAccessError::ObjectAccessDenied,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_carry_no_error_and_internal_failures_unknown() {
        assert_eq!(
            last_appl_error_code(Refusal::by_check(ControlAddCause::ObjectNotSelected)),
            ControlLastApplError::NoError
        );
        assert_eq!(
            last_appl_error_code(Refusal::by_check(ControlAddCause::Unknown)),
            ControlLastApplError::NoError,
            "a handler's Unknown is a refusal by the checks"
        );
        assert_eq!(
            last_appl_error_code(Refusal::internal()),
            ControlLastApplError::Unknown
        );
    }

    #[test]
    fn failed_test_commands_carry_operator_test_not_ok() {
        assert_eq!(termination_error_code(false), ControlLastApplError::NoError);
        assert_eq!(
            termination_error_code(true) as i32,
            3,
            "Operator Test Not OK"
        );
    }
}
