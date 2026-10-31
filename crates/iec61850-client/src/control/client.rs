//! `ControlObjectClient`: a handle on one controllable data object, offering
//! the ACSI Select, SelectWithValue, Operate and Cancel services.
//!
//! A handle shares the MMS client and the connected flag of the
//! `IedConnection` it was created from, so every control runs over the same
//! association.
//!
//! Entry point per control model:
//!
//! | Control model     | Client action                                    |
//! |---|---|
//! | direct-normal     | `operate` writes Oper                            |
//! | direct-enhanced   | `operate` writes Oper, then awaits CT+ or CT-    |
//! | sbo-normal        | `select` reads SBO, then `operate` writes Oper   |
//! | sbo-enhanced      | `select_with_value` writes SBOw, then `operate`  |
//! |                   | writes Oper and awaits CT+ or CT-                |
//! | any               | `cancel` writes Cancel                           |
//!
//! A refused command is answered with a negative response, preceded by an
//! InformationReport carrying only `LastApplError`; that LastApplError and its
//! AddCause are returned in [`ControlOutcome::Failure`], and a refused command
//! has no command termination. An accepted enhanced Operate is concluded by
//! the command termination that follows the positive response; a negative one
//! returns the LastApplError it carries the same way.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use core::time::Duration;

use iec61850_hal::time::Timer;
use iec61850_hal::transport::AsyncTransport;
use iec61850_mms::mms::client::MmsClient;
use iec61850_mms::mms::pdu::common::{MmsData, ObjectName};
use iec61850_mms::mms::pdu::information_report::{decode_information_report, VariableAccessSpec};
use iec61850_mms::ClientError as MmsClientError;
use iec61850_model::value::MmsValue;

use crate::error::ClientError;
use crate::mms_compat::{mms_data_to_mms_value, mms_value_to_mms_data};
use crate::prelude::{format, Arc, String, ToString, Vec};
use crate::sync::Mutex;

use super::encode::{build_cancel_struct, build_oper_struct, current_utc_time};
#[cfg(feature = "std")]
use super::model::CommandTerminationParsed;
use super::model::{
    ControlAddCause, ControlLastApplError, ControlModel, ControlOutcome, LastApplError,
    OriginValue, SboClass,
};

/// Default wait for a command termination, used by the enhanced models.
#[cfg(feature = "std")]
const DEFAULT_CT_TIMEOUT: Duration = Duration::from_secs(5);

// ControlObjectClient

/// Handle on one controllable data object.
///
/// The MMS client and the connected flag are shared with the `IedConnection`
/// this handle came from; every service returns `NotConnected` once the
/// association is closed.
///
/// The type parameters follow `IedConnection<T, Tm>` and are inferred by
/// `IedConnection::create_control_object`. On an embedded build both are
/// mandatory, as the defaults depend on tokio; the fields are identical.
#[cfg(feature = "std")]
pub struct ControlObjectClient<T = tokio::net::TcpStream, Tm = iec61850_hal::time::TokioTimer> {
    /// `<LD>/<LN>.<DO>` in IEC notation; on the wire `.` becomes `$`.
    object_ref: String,
    /// MMS domain, the `<LD>` part.
    domain: String,
    /// `<LN>$CO$<DO>`, the item id prefix that `$Oper`, `$SBO` and the others
    /// are appended to.
    item_base: String,
    /// Control model this object follows.
    ctl_model: ControlModel,
    /// Whether a selection survives one operate or many.
    sbo_class: SboClass,
    /// Originator reported in each command, changeable with `set_origin`.
    origin: OriginValue,
    /// Command sequence number, incremented on each operate.
    ctl_num: AtomicU8,
    /// Default `interlockCheck` flag.
    interlock_check: AtomicBool,
    /// Default `synchroCheck` flag.
    synchro_check: AtomicBool,
    /// Default `Test` flag.
    test: AtomicBool,
    /// Shared with the originating connection.
    mms_client: Arc<Mutex<MmsClient<T, Tm>>>,
    is_connected: Arc<AtomicBool>,
}

/// `ControlObjectClient` without type-parameter defaults, for a `no_std` build.
#[cfg(not(feature = "std"))]
pub struct ControlObjectClient<T, Tm> {
    object_ref: String,
    domain: String,
    item_base: String,
    ctl_model: ControlModel,
    sbo_class: SboClass,
    origin: OriginValue,
    ctl_num: AtomicU8,
    interlock_check: AtomicBool,
    synchro_check: AtomicBool,
    test: AtomicBool,
    mms_client: Arc<Mutex<MmsClient<T, Tm>>>,
    is_connected: Arc<AtomicBool>,
}

impl<T: AsyncTransport, Tm: Timer> ControlObjectClient<T, Tm> {
    /// Creates a control handle for an object reference such as
    /// `IED1LD0/GGIO1.SPCSO1`.
    ///
    /// The part before the first `/` is the MMS domain; the rest becomes
    /// `<LN>$CO$<DO>`.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` if the reference has no `/`, or no `.` between the
    /// logical node and the data object.
    pub fn new(
        object_ref: &str,
        ctl_model: ControlModel,
        mms_client: Arc<Mutex<MmsClient<T, Tm>>>,
        is_connected: Arc<AtomicBool>,
    ) -> Result<Self, ClientError> {
        let (domain, item_base) = parse_control_object_ref(object_ref)?;
        Ok(Self {
            object_ref: object_ref.to_string(),
            domain,
            item_base,
            ctl_model,
            sbo_class: SboClass::default(),
            origin: OriginValue::bay_control(),
            ctl_num: AtomicU8::new(0),
            interlock_check: AtomicBool::new(false),
            synchro_check: AtomicBool::new(false),
            test: AtomicBool::new(false),
            mms_client,
            is_connected,
        })
    }

    // Configuration.

    /// Sets the originator reported by the following commands.
    pub fn set_origin(&mut self, origin: OriginValue) {
        self.origin = origin;
    }

    /// Overrides ctlNum. Normally the client increments it on each
    /// SelectWithValue, and on each Operate outside the sbo-enhanced model.
    pub fn set_ctl_num(&self, ctl_num: u8) {
        self.ctl_num.store(ctl_num, Ordering::Release);
    }

    /// Sets whether a selection survives one operate or many.
    pub fn set_sbo_class(&mut self, sbo_class: SboClass) {
        self.sbo_class = sbo_class;
    }

    /// Sets the `interlockCheck` flag.
    pub fn set_interlock_check(&self, on: bool) {
        self.interlock_check.store(on, Ordering::Release);
    }

    /// Sets the `synchroCheck` flag.
    pub fn set_synchro_check(&self, on: bool) {
        self.synchro_check.store(on, Ordering::Release);
    }

    /// Sets the `Test` flag.
    pub fn set_test(&self, on: bool) {
        self.test.store(on, Ordering::Release);
    }

    /// Returns the object reference in IEC notation.
    pub fn object_ref(&self) -> &str {
        &self.object_ref
    }

    /// Returns the MMS domain.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns the control model of this object.
    pub fn ctl_model(&self) -> ControlModel {
        self.ctl_model
    }

    // Services.

    /// Selects the object by reading `<LN>$CO$<DO>$SBO` (ACSI Select).
    ///
    /// `Success` when the server answers with the object reference. An empty
    /// string denies the selection, as does a value that is not a string; the
    /// denial is `Failure` with the LastApplError the server reported ahead of
    /// the response, matched on the control object only, as a Select carries
    /// no ctlNum or origin. IEC 61850-8-1 does not require that report for a
    /// Select, so a denial may carry `None` and `Unknown`.
    ///
    /// # Errors
    ///
    /// `NotConnected` if the association is closed, `InvalidArgument` unless the
    /// control model is sbo-normal, and any error from the MMS layer.
    pub async fn select(&self) -> Result<ControlOutcome, ClientError> {
        if !self.is_connected.load(Ordering::Acquire) {
            return Err(ClientError::NotConnected);
        }
        if self.ctl_model != ControlModel::SboNormal {
            return Err(ClientError::InvalidArgument(format!(
                "select() applies to sbo-normal only; this object uses {:?}",
                self.ctl_model
            )));
        }
        let item = format!("{}$SBO", self.item_base);
        let mut client = self.mms_client.lock().await;
        let resp = client.read(&self.domain, &item).await?;
        // A non-empty VisibleString means the selection was granted.
        match resp {
            MmsData::VisibleString(s) if !s.is_empty() => Ok(ControlOutcome::Success),
            MmsData::VisibleString(_) => {
                let last = self.take_last_appl_error(&mut client, None).await;
                Ok(ControlOutcome::failure(last))
            }
            other => {
                tracing::warn!(
                    ?other,
                    "select: server answered with a non-string value, treating as denied"
                );
                let last = self.take_last_appl_error(&mut client, None).await;
                Ok(ControlOutcome::failure(last))
            }
        }
    }

    /// Selects the object with a value by writing the six-element structure
    /// `<LN>$CO$<DO>$SBOw` (ACSI SelectWithValue).
    ///
    /// Must precede `operate`, and `ctl_val` must equal the value passed to it;
    /// otherwise the server answers with InconsistentParameters. A refusal is
    /// `Failure` with the server's LastApplError for this command, or with
    /// `None` and `Unknown` when the server sent none.
    ///
    /// # Errors
    ///
    /// `NotConnected` if the association is closed, `InvalidArgument` unless
    /// the control model is sbo-enhanced, and any MMS-layer error other than
    /// the server refusing the write, such as a timeout or a lost connection,
    /// after which the fate of the command is unknown.
    pub async fn select_with_value(
        &self,
        ctl_val: MmsValue,
    ) -> Result<ControlOutcome, ClientError> {
        if !self.is_connected.load(Ordering::Acquire) {
            return Err(ClientError::NotConnected);
        }
        if self.ctl_model != ControlModel::SboEnhanced {
            return Err(ClientError::InvalidArgument(format!(
                "select_with_value() applies to sbo-enhanced only; this object uses {:?}",
                self.ctl_model
            )));
        }
        let ctl_num = self.next_ctl_num();
        let sbow = build_oper_struct(
            ctl_val,
            &self.origin,
            ctl_num,
            current_utc_time(),
            self.test.load(Ordering::Acquire),
            self.synchro_check.load(Ordering::Acquire),
            self.interlock_check.load(Ordering::Acquire),
        );
        let item = format!("{}$SBOw", self.item_base);
        let mut client = self.mms_client.lock().await;
        match client
            .write(&self.domain, &item, mms_value_to_mms_data(&sbow))
            .await
        {
            Ok(()) => Ok(ControlOutcome::Success),
            Err(e) => self.refused_outcome(&mut client, e, ctl_num).await,
        }
    }

    /// Operates the object by writing the six-element structure
    /// `<LN>$CO$<DO>$Oper` (ACSI Operate).
    ///
    /// The ctlNum of an sbo-enhanced Operate is the one `select_with_value`
    /// carried, as the server requires Oper to match the selection; the other
    /// models increment ctlNum first.
    ///
    /// In the normal models the confirmed response concludes the command. In
    /// the enhanced models a positive response is followed by the
    /// CommandTermination (CT+ or CT-) for this object and ctlNum, which the
    /// call awaits for up to 5 s. The lock on the shared MMS client is held
    /// from the write until the termination arrives or the wait expires, so
    /// other services on the same connection wait meanwhile; releasing it in
    /// between would let a background report dispatcher consume the
    /// termination. A refused command concludes at the negative response in
    /// every model, as `Failure` with the server's LastApplError for this
    /// command, or with `None` and `Unknown` when the server sent none; a
    /// normal-security server need not send one. A negative command
    /// termination is `Failure` with the LastApplError it carries.
    ///
    /// The wait needs a monotonic deadline, so the enhanced models require
    /// `std`; an embedded caller uses the normal models.
    ///
    /// # Errors
    ///
    /// `NotConnected` if the association is closed;
    /// `CommandTerminationTimeout` if an accepted enhanced Operate draws no
    /// command termination within the wait; the typed error of the MMS
    /// layer, such as `Timeout` or `ConnectionLost`, when it fails other than
    /// by the server refusing the write, after which the fate of the command
    /// is unknown; and `InvalidArgument` for an enhanced model on a build
    /// without `std`.
    pub async fn operate(&self, ctl_val: MmsValue) -> Result<ControlOutcome, ClientError> {
        if !self.is_connected.load(Ordering::Acquire) {
            return Err(ClientError::NotConnected);
        }
        let is_enhanced = matches!(
            self.ctl_model,
            ControlModel::DirectEnhanced | ControlModel::SboEnhanced
        );
        #[cfg(not(feature = "std"))]
        if is_enhanced {
            return Err(ClientError::InvalidArgument(
                "the enhanced control models wait for a command termination, which requires \
                 the std feature; use direct-normal or sbo-normal on this build"
                    .to_string(),
            ));
        }

        let ctl_num = match self.ctl_model {
            ControlModel::SboEnhanced => self.ctl_num.load(Ordering::Acquire),
            _ => self.next_ctl_num(),
        };
        let oper = build_oper_struct(
            ctl_val,
            &self.origin,
            ctl_num,
            current_utc_time(),
            self.test.load(Ordering::Acquire),
            self.synchro_check.load(Ordering::Acquire),
            self.interlock_check.load(Ordering::Acquire),
        );
        let item = format!("{}$Oper", self.item_base);

        // The lock is held across the write and the wait; see the item doc.
        let mut client = self.mms_client.lock().await;
        let written = client
            .write(&self.domain, &item, mms_value_to_mms_data(&oper))
            .await;
        if let Err(e) = written {
            return self.refused_outcome(&mut client, e, ctl_num).await;
        }
        if !is_enhanced {
            return Ok(ControlOutcome::Success);
        }

        #[cfg(feature = "std")]
        {
            let expected = CtMatch {
                object_ref_oper: format!("{}/{}", self.domain, item),
                ctl_num,
            };
            match Self::recv_ct_locked(&mut client, DEFAULT_CT_TIMEOUT, &expected).await? {
                Some(ct) => match ct.last_appl_error {
                    None => Ok(ControlOutcome::Success),
                    Some(err) => Ok(ControlOutcome::failure(Some(err))),
                },
                None => Err(ClientError::CommandTerminationTimeout {
                    after_ms: duration_ms(DEFAULT_CT_TIMEOUT),
                }),
            }
        }
        #[cfg(not(feature = "std"))]
        {
            Ok(ControlOutcome::Success)
        }
    }

    /// Cancels a selection by writing the five-element structure
    /// `<LN>$CO$<DO>$Cancel` (ACSI Cancel).
    ///
    /// Accepted for every control model; the server checks that the cancel
    /// comes from the association that holds the selection. A refusal is
    /// `Failure` with the server's LastApplError for this command, or with
    /// `None` and `Unknown` when the server sent none.
    ///
    /// # Errors
    ///
    /// `NotConnected` if the association is closed, and any MMS-layer error
    /// other than the server refusing the write, such as a timeout or a lost
    /// connection.
    pub async fn cancel(&self, ctl_val: MmsValue) -> Result<ControlOutcome, ClientError> {
        if !self.is_connected.load(Ordering::Acquire) {
            return Err(ClientError::NotConnected);
        }
        let ctl_num = self.ctl_num.load(Ordering::Acquire);
        let cancel = build_cancel_struct(
            ctl_val,
            &self.origin,
            ctl_num,
            current_utc_time(),
            self.test.load(Ordering::Acquire),
        );
        let item = format!("{}$Cancel", self.item_base);
        let mut client = self.mms_client.lock().await;
        match client
            .write(&self.domain, &item, mms_value_to_mms_data(&cancel))
            .await
        {
            Ok(()) => Ok(ControlOutcome::Success),
            Err(e) => self.refused_outcome(&mut client, e, ctl_num).await,
        }
    }

    // Internal helpers.

    /// Increments ctlNum and returns the new value, wrapping past 255.
    fn next_ctl_num(&self) -> u8 {
        let prev = self.ctl_num.fetch_add(1, Ordering::AcqRel);
        prev.wrapping_add(1)
    }

    /// Maps a failed control write onto the result of the command.
    ///
    /// A data access error or a confirmed service error is the server refusing
    /// the command: the outcome is `Failure` with the LastApplError report
    /// that preceded the response for the command with `ctl_num`, if any. Any
    /// other error leaves the fate of the command unknown and is returned
    /// unchanged.
    async fn refused_outcome(
        &self,
        client: &mut MmsClient<T, Tm>,
        error: MmsClientError,
        ctl_num: u8,
    ) -> Result<ControlOutcome, ClientError> {
        if !matches!(
            error,
            MmsClientError::DataAccessError(_) | MmsClientError::ServiceError { .. }
        ) {
            return Err(error.into());
        }
        let last = self.take_last_appl_error(client, Some(ctl_num)).await;
        let outcome = ControlOutcome::failure(last);
        tracing::warn!(
            object = %self.object_ref,
            %error,
            cause = ?outcome.add_cause(),
            "control command refused"
        );
        Ok(outcome)
    }

    /// Takes the LastApplError report of a refused command from the reports
    /// the client stashed while its last request was outstanding.
    ///
    /// `ctl_num` is the ctlNum of a SelectWithValue, Operate or Cancel, and
    /// `None` for a Select, which carries none; see
    /// `parse_last_appl_error_report`. A server sends the report ahead of the
    /// negative response, so it is already stashed. An empty marker queued
    /// behind the stash bounds the scan, so no further PDU is read from the
    /// transport. Every other report is put back in arrival order; when
    /// several match, the latest is returned.
    async fn take_last_appl_error(
        &self,
        client: &mut MmsClient<T, Tm>,
        ctl_num: Option<u8>,
    ) -> Option<LastApplError> {
        client.push_back_unconfirmed(bytes::Bytes::new());
        let mut kept: Vec<bytes::Bytes> = Vec::new();
        let mut found = None;
        loop {
            match client
                .recv_unconfirmed_pdu_with_timeout(Duration::ZERO)
                .await
            {
                Ok(Some(inner)) if inner.is_empty() => break,
                Ok(Some(inner)) => match self.parse_last_appl_error_report(&inner, ctl_num) {
                    Some(e) => found = Some(e),
                    None => kept.push(inner),
                },
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!(error = %e, "cannot scan the stashed reports for a LastApplError");
                    break;
                }
            }
        }
        for inner in kept {
            client.push_back_unconfirmed(inner);
        }
        found
    }

    /// Reads an InformationReport as the LastApplError of a command on this
    /// object.
    ///
    /// IEC 61850-8-1 reports a refused command with one VMD-specific variable,
    /// `LastApplError`, whose CntrlObj names the control attribute written,
    /// such as `<LD>/<LN>$CO$<DO>$Oper`, and whose origin and ctlNum are those
    /// of the command. With `ctl_num` set, the report must carry that ctlNum
    /// and the origin of this handle, so a report of an earlier command is not
    /// taken; without it only CntrlObj is compared.
    fn parse_last_appl_error_report(
        &self,
        inner: &[u8],
        ctl_num: Option<u8>,
    ) -> Option<LastApplError> {
        let report = decode_information_report(inner).ok()?;
        let VariableAccessSpec::ListOfVariable(names) = &report.variable_access_spec else {
            return None;
        };
        let ([name], [value]) = (names.as_slice(), report.list_of_access_result.as_slice()) else {
            return None;
        };
        if !matches!(name, ObjectName::VmdSpecific(s) if s == "LastApplError") {
            return None;
        }
        let parsed = parse_last_appl_error(value)?;
        let same_command =
            ctl_num.is_none_or(|n| parsed.ctl_num == n && parsed.origin == self.origin);
        (same_command && names_control_object(&parsed.ctl_obj, &self.domain, &self.item_base))
            .then_some(parsed)
    }

    /// Waits for one command termination.
    ///
    /// # Errors
    ///
    /// `CommandTerminationTimeout` if none arrives within `timeout`, and `Mms`
    /// if a report that arrives does not decode. Requires `std` for its
    /// monotonic deadline; an embedded caller uses the normal control models.
    #[cfg(feature = "std")]
    pub async fn wait_command_termination(
        &self,
        timeout: Duration,
    ) -> Result<CommandTerminationParsed, ClientError> {
        match self.try_recv_command_termination(timeout).await? {
            Some(ct) => Ok(ct),
            None => Err(ClientError::CommandTerminationTimeout {
                after_ms: duration_ms(timeout),
            }),
        }
    }

    /// Tries to take one command termination, returning `Ok(None)` on timeout.
    ///
    /// Only a termination of this object's Oper whose ctlNum is the current one
    /// is taken. An InformationReport that is anything else, such as a report
    /// triggered by a data change during the command or a late termination of
    /// an earlier command, is pushed back onto the client's pending queue for
    /// the report dispatcher, and the wait continues.
    ///
    /// The lock is re-taken on each attempt. A caller that already holds it, to
    /// keep a dispatcher from consuming the termination, uses `recv_ct_locked`.
    ///
    /// Requires `std`, as `wait_command_termination` does.
    #[cfg(feature = "std")]
    pub async fn try_recv_command_termination(
        &self,
        timeout: Duration,
    ) -> Result<Option<CommandTerminationParsed>, ClientError> {
        let expected = CtMatch {
            object_ref_oper: format!("{}/{}$Oper", self.domain, self.item_base),
            ctl_num: self.ctl_num.load(Ordering::Acquire),
        };
        let mut client = self.mms_client.lock().await;
        Self::recv_ct_locked(&mut client, timeout, &expected).await
    }

    /// Same as `try_recv_command_termination`, but on an already locked MMS
    /// client, so the lock is held for the whole wait.
    ///
    /// Reports other than the expected termination are collected locally and
    /// pushed back once, after the termination arrives or the wait expires.
    /// Pushing one back inside the loop would pop the same report again.
    ///
    /// Requires `std` for its monotonic deadline.
    #[cfg(feature = "std")]
    pub(crate) async fn recv_ct_locked(
        client: &mut MmsClient<T, Tm>,
        timeout: Duration,
        expected: &CtMatch,
    ) -> Result<Option<CommandTerminationParsed>, ClientError> {
        let deadline = std::time::Instant::now() + timeout;
        let mut deferred: Vec<bytes::Bytes> = Vec::new();
        let result = loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break Ok(None);
            }
            match Self::recv_ct_step(client, remaining, expected).await {
                Ok(CtStep::Got(ct)) => break Ok(Some(ct)),
                Ok(CtStep::Timeout) => break Ok(None),
                Ok(CtStep::PushBackAndRetry(inner)) => {
                    deferred.push(inner);
                }
                Err(e) => break Err(e),
            }
        };
        // Push the deferred reports back in arrival order.
        for inner in deferred {
            client.push_back_unconfirmed(inner);
        }
        result
    }

    /// Receives one unconfirmed PDU and tries to read it as the expected
    /// command termination.
    #[cfg(feature = "std")]
    async fn recv_ct_step(
        client: &mut MmsClient<T, Tm>,
        remaining: Duration,
        expected: &CtMatch,
    ) -> Result<CtStep, ClientError> {
        let opt_inner = client.recv_unconfirmed_pdu_with_timeout(remaining).await?;
        let Some(inner) = opt_inner else {
            return Ok(CtStep::Timeout);
        };
        let report = decode_information_report(&inner)
            .map_err(|e| ClientError::Mms(format!("cannot decode command termination: {e}")))?;
        match parse_command_termination(&report) {
            Some((ct, ctl_num)) if expected.matches(&ct, ctl_num) => Ok(CtStep::Got(ct)),
            Some((ct, ctl_num)) => {
                tracing::warn!(
                    object = %ct.object_ref_oper,
                    ?ctl_num,
                    expected_object = %expected.object_ref_oper,
                    expected_ctl_num = expected.ctl_num,
                    "command termination of another command, leaving it for the report dispatcher"
                );
                Ok(CtStep::PushBackAndRetry(inner))
            }
            None => Ok(CtStep::PushBackAndRetry(inner)),
        }
    }
}

#[cfg(feature = "std")]
enum CtStep {
    Got(CommandTerminationParsed),
    Timeout,
    PushBackAndRetry(bytes::Bytes),
}

/// The command a command termination must belong to.
#[cfg(feature = "std")]
pub(crate) struct CtMatch {
    /// `<LD>/<LN>$CO$<DO>$Oper` of the object operated.
    object_ref_oper: String,
    /// ctlNum the Operate carried.
    ctl_num: u8,
}

#[cfg(feature = "std")]
impl CtMatch {
    /// Reports whether a termination names this object and, when its Oper
    /// carries a readable ctlNum, this ctlNum.
    fn matches(&self, ct: &CommandTerminationParsed, ctl_num: Option<u8>) -> bool {
        ct.object_ref_oper == self.object_ref_oper && ctl_num.is_none_or(|n| n == self.ctl_num)
    }
}

/// Converts a wait into whole milliseconds, saturating at `u64::MAX`.
#[cfg(feature = "std")]
fn duration_ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Reports whether a CntrlObj reference names the control object
/// `<domain>/<item_base>` or one of its control attributes.
fn names_control_object(ctl_obj: &str, domain: &str, item_base: &str) -> bool {
    ctl_obj
        .strip_prefix(domain)
        .and_then(|rest| rest.strip_prefix('/'))
        .and_then(|rest| rest.strip_prefix(item_base))
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('$'))
}

// CommandTermination parser, reached only from the enhanced control path.

/// Parses an InformationReport as a command termination, together with the
/// ctlNum of the Oper structure it carries when that is readable.
///
/// A CT+ names one variable, `<LD>` with `<LN>$CO$<DO>$Oper` and the Oper
/// structure. A CT- names two, `LastApplError` followed by `Oper`. Anything
/// else yields `None`.
#[cfg(feature = "std")]
fn parse_command_termination(
    report: &iec61850_mms::mms::pdu::information_report::InformationReportInner,
) -> Option<(CommandTerminationParsed, Option<u8>)> {
    let names = match &report.variable_access_spec {
        VariableAccessSpec::ListOfVariable(names) => names,
        _ => return None,
    };
    if names.is_empty() || report.list_of_access_result.len() != names.len() {
        return None;
    }

    // The Oper variable is the domain-specific name ending in `$Oper`.
    let oper_idx = names.iter().position(|n| match n {
        ObjectName::DomainSpecific { item_id, .. } => item_id.ends_with("$Oper"),
        _ => false,
    })?;
    let oper_name = match &names[oper_idx] {
        ObjectName::DomainSpecific { domain_id, item_id } => {
            format!("{domain_id}/{}", item_id.trim_end_matches("$Oper"))
        }
        _ => return None,
    };
    let ctl_num = report
        .list_of_access_result
        .get(oper_idx)
        .and_then(oper_ctl_num);

    // In a CT- the first variable is the VMD-specific `LastApplError`.
    let last_appl = if names.len() == 2 {
        let first_is_last_appl = matches!(
            &names[0],
            ObjectName::VmdSpecific(s) if s == "LastApplError"
        );
        if !first_is_last_appl {
            return None;
        }
        let parsed = parse_last_appl_error(&report.list_of_access_result[0])?;
        Some(parsed)
    } else {
        None
    };

    Some((
        CommandTerminationParsed {
            object_ref_oper: format!("{oper_name}$Oper"),
            last_appl_error: last_appl,
        },
        ctl_num,
    ))
}

/// Reads ctlNum from an Oper structure.
///
/// Oper ends with ctlNum, T, Test and Check whether or not it carries operTm,
/// so ctlNum is the fourth element from the end.
#[cfg(feature = "std")]
fn oper_ctl_num(d: &MmsData) -> Option<u8> {
    let MmsData::Structure(items) = d else {
        return None;
    };
    let idx = items.len().checked_sub(4)?;
    match items.get(idx)? {
        MmsData::Unsigned(n) => u8::try_from(*n).ok(),
        MmsData::Integer(n) => u8::try_from(*n).ok(),
        _ => None,
    }
}

/// Parses the five-element LastApplError structure.
fn parse_last_appl_error(d: &MmsData) -> Option<LastApplError> {
    let v = mms_data_to_mms_value(d);
    let MmsValue::Structure(items) = v else {
        return None;
    };
    if items.len() != 5 {
        return None;
    }
    let ctl_obj = match &items[0] {
        MmsValue::VisibleString(s) => s.clone(),
        _ => return None,
    };
    let error = match &items[1] {
        MmsValue::Integer(i) => ControlLastApplError::from_i32(*i as i32),
        _ => return None,
    };
    let origin = match &items[2] {
        MmsValue::Structure(fields) if fields.len() == 2 => {
            let or_cat = match &fields[0] {
                MmsValue::Integer(i) => *i as i32,
                _ => return None,
            };
            let or_ident = match &fields[1] {
                MmsValue::OctetString(b) => b.clone(),
                _ => return None,
            };
            OriginValue { or_cat, or_ident }
        }
        _ => return None,
    };
    let ctl_num = match &items[3] {
        MmsValue::Unsigned(n) => u8::try_from(*n).ok()?,
        MmsValue::Integer(n) => u8::try_from(*n).ok()?,
        _ => return None,
    };
    let add_cause = match &items[4] {
        MmsValue::Integer(i) => ControlAddCause::from_i32(*i as i32),
        _ => return None,
    };
    Some(LastApplError {
        ctl_obj,
        error,
        origin,
        ctl_num,
        add_cause,
    })
}

// Control object reference parsing.

/// Splits `<LD>/<LN>.<DO>` into the MMS domain and the item base
/// `<LN>$CO$<DO>`.
///
/// # Errors
///
/// `InvalidArgument` if the `/` or the `.` is missing, or either part is empty.
fn parse_control_object_ref(object_ref: &str) -> Result<(String, String), ClientError> {
    let slash_pos = object_ref.find('/').ok_or_else(|| {
        ClientError::InvalidArgument(format!(
            "control object reference is missing the '/' before the logical node: '{object_ref}'"
        ))
    })?;
    let domain = object_ref[..slash_pos].to_string();
    let rest = &object_ref[slash_pos + 1..];
    // The remainder is `<LN>.<DO>`; only a single data object level is supported.
    let dot_pos = rest.find('.').ok_or_else(|| {
        ClientError::InvalidArgument(format!(
            "control object reference is missing the '.' between LN and DO: '{object_ref}'"
        ))
    })?;
    let ln = &rest[..dot_pos];
    let do_part = &rest[dot_pos + 1..];
    if ln.is_empty() || do_part.is_empty() {
        return Err(ClientError::InvalidArgument(format!(
            "control object reference has an empty LN or DO part: '{object_ref}'"
        )));
    }
    // A nested data attribute is addressed with an explicit '$' instead.
    let item_base = format!("{ln}$CO${do_part}");
    Ok((domain, item_base))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_object_ref_simple() {
        let (d, b) = parse_control_object_ref("IED1LD0/GGIO1.SPCSO1").unwrap();
        assert_eq!(d, "IED1LD0");
        assert_eq!(b, "GGIO1$CO$SPCSO1");
    }

    #[test]
    fn parse_object_ref_missing_slash() {
        let r = parse_control_object_ref("noSlashHere");
        assert!(matches!(r, Err(ClientError::InvalidArgument(_))));
    }

    #[test]
    fn parse_object_ref_missing_dot() {
        let r = parse_control_object_ref("IED1LD0/GGIO1");
        assert!(matches!(r, Err(ClientError::InvalidArgument(_))));
    }

    #[test]
    fn parse_object_ref_empty_segments() {
        let r = parse_control_object_ref("IED1LD0/.SPCSO1");
        assert!(matches!(r, Err(ClientError::InvalidArgument(_))));
    }
}
