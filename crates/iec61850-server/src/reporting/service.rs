//! MMS read and write routing for report control block fields.
//!
//! Implements GetURCBValues, SetURCBValues, GetBRCBValues, and SetBRCBValues
//! access control per IEC 61850-7-2.
//!
//! Write rules, Edition 2.1 model:
//!
//! | Field | Condition for a write to be accepted |
//! |---|---|
//! | Resv | any client, moving the block from idle to reserved |
//! | RptID, DatSet, OptFlds, BufTm, TrgOps, IntgPd | reserved, and the writer owns the reservation |
//! | RptEna = true | reserved by the writer, or unreserved, in which case the write reserves it for the writer |
//! | RptEna = false | enabled, and the writer owns the reservation; the reservation is kept |
//! | GI = true | enabled, the writer owns the reservation, and trgOps includes GI |
//! | ConfRev, SqNum, Owner, TimeOfEntry | never writable; answered with ObjectAccessDenied |
//!
//! A DatSet write must name a data set the server knows; a name it does not
//! know is refused with ObjectValueInvalid. An accepted DatSet write binds the
//! control block to the members of the named data set, for URCBs and BRCBs
//! alike.

use super::engine::ReportingEngine;
use crate::connection::ConnectionId;
use iec61850_mms::mms::pdu::common::DataAccessError;
use std::sync::{Arc, Mutex};

/// Identifies one report control block field.
///
/// Corresponds to the MMS variableName `<LN>$RP$<rcb>$<field>`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RcbField {
    /// The RptID attribute.
    RptId,
    /// The RptEna attribute, which enables reporting.
    RptEna,
    /// The Resv attribute, which only a URCB has.
    Resv,
    /// The DatSet attribute, naming the observed data set.
    DatSet,
    /// The ConfRev attribute, which a client may not write.
    ConfRev,
    /// The OptFlds attribute.
    OptFlds,
    /// The BufTm attribute, the buffer time in milliseconds.
    BufTm,
    /// The SqNum attribute, the report sequence number.
    SqNum,
    /// The TrgOps attribute, the trigger options.
    TrgOps,
    /// The IntgPd attribute, the integrity period in milliseconds.
    IntgPd,
    /// The GI attribute, which requests a general interrogation.
    Gi,
    /// The Owner attribute.
    Owner,
    /// EntryID, an eight-byte big-endian OCTET STRING; BRCB only.
    EntryId,
    /// PurgeBuf, a request to discard the buffered entries; BRCB only.
    PurgeBuf,
    /// TimeOfEntry, MMS component `TimeofEntry`, the time of the exposed EntryID;
    /// BRCB only, never writable.
    TimeOfEntry,
    /// ResvTms, the reservation time in seconds as an INT16; BRCB only.
    ResvTms,
    /// A field name this server does not recognize.
    Unknown(String),
}

impl RcbField {
    /// Parses an MMS component name, as IEC 61850-8-1 Tables 72 and 73 spell it.
    pub fn from_name(name: &str) -> Self {
        match name {
            "RptID" => Self::RptId,
            "RptEna" => Self::RptEna,
            "Resv" => Self::Resv,
            "DatSet" => Self::DatSet,
            "ConfRev" => Self::ConfRev,
            "OptFlds" => Self::OptFlds,
            "BufTm" => Self::BufTm,
            "SqNum" => Self::SqNum,
            "TrgOps" => Self::TrgOps,
            "IntgPd" => Self::IntgPd,
            "GI" => Self::Gi,
            "Owner" => Self::Owner,
            "EntryID" => Self::EntryId,
            "PurgeBuf" => Self::PurgeBuf,
            "TimeofEntry" => Self::TimeOfEntry,
            "ResvTms" => Self::ResvTms,
            other => Self::Unknown(other.to_string()),
        }
    }

    /// Returns the MMS component name.
    pub fn as_str(&self) -> &str {
        match self {
            Self::RptId => "RptID",
            Self::RptEna => "RptEna",
            Self::Resv => "Resv",
            Self::DatSet => "DatSet",
            Self::ConfRev => "ConfRev",
            Self::OptFlds => "OptFlds",
            Self::BufTm => "BufTm",
            Self::SqNum => "SqNum",
            Self::TrgOps => "TrgOps",
            Self::IntgPd => "IntgPd",
            Self::Gi => "GI",
            Self::Owner => "Owner",
            Self::EntryId => "EntryID",
            Self::PurgeBuf => "PurgeBuf",
            Self::TimeOfEntry => "TimeofEntry",
            Self::ResvTms => "ResvTms",
            Self::Unknown(s) => s.as_str(),
        }
    }
}

/// One field value to write, already decoded by the caller.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum RcbWriteValue {
    /// A BOOLEAN value.
    Bool(bool),
    /// An UNSIGNED value.
    Unsigned(u32),
    /// An INTEGER value, of any width the wire carries.
    Integer(i64),
    /// A VisibleString value.
    VisibleString(String),
    /// A BIT_STRING as raw wire bytes, including the leading padding byte.
    BitString(Vec<u8>),
    /// An OctetString, used by the Owner field.
    OctetString(Vec<u8>),
}

/// Applies one SetURCBValues field write.
///
/// Implements the SetURCBValues access rules of IEC 61850-7-2.
///
/// # Errors
///
/// Returns the `DataAccessError` the client is to be answered with: a
/// non-writable field or a writer that does not own the reservation gives
/// `ObjectAccessDenied`, a wrong value type gives `TypeInconsistent`, a DatSet
/// naming no known data set gives `ObjectValueInvalid`, an enabled control block
/// gives `TemporarilyUnavailable`, and a poisoned mutex gives `HardwareFault`.
pub fn handle_set_rcb_field(
    engine: &Arc<Mutex<ReportingEngine>>,
    mms_path: &str,
    field: RcbField,
    value: RcbWriteValue,
    conn_id: ConnectionId,
) -> Result<(), DataAccessError> {
    // The engine lock is held throughout, before the control block lock as on
    // every other path, so a DatSet write rebinds the inverted index atomically.
    let mut eng = engine.lock().map_err(|_| DataAccessError::HardwareFault)?;

    let rc_arc = eng
        .get_rcb(mms_path)
        .ok_or(DataAccessError::ObjectNonExistent)?;

    let rc = rc_arc.lock().map_err(|_| DataAccessError::HardwareFault)?;
    let mut state = rc
        .state
        .lock()
        .map_err(|_| DataAccessError::HardwareFault)?;

    // Never writable: ConfRev, SqNum, Owner, and TimeOfEntry.
    match &field {
        RcbField::ConfRev => {
            tracing::warn!(
                mms_path,
                "SetURCBValues: ConfRev is not writable, answering ObjectAccessDenied"
            );
            return Err(DataAccessError::ObjectAccessDenied);
        }
        RcbField::SqNum => {
            tracing::warn!(
                mms_path,
                "SetURCBValues: SqNum is not writable, answering ObjectAccessDenied"
            );
            return Err(DataAccessError::ObjectAccessDenied);
        }
        RcbField::Owner => {
            tracing::warn!(
                mms_path,
                "SetURCBValues: Owner is not writable, answering ObjectAccessDenied"
            );
            return Err(DataAccessError::ObjectAccessDenied);
        }
        _ => {}
    }

    // Resv = true moves an unreserved control block to reserved; any client may do it.
    if field == RcbField::Resv {
        let v = match value {
            RcbWriteValue::Bool(b) => b,
            _ => return Err(DataAccessError::TypeInconsistent),
        };
        if v {
            if state.resv && state.client_conn_id != Some(conn_id) {
                // Already held by another client.
                tracing::warn!(
                    mms_path,
                    conn_id,
                    "SetURCBValues Resv=true: the control block is reserved by another client"
                );
                return Err(DataAccessError::TemporarilyUnavailable);
            }
            state.resv = true;
            state.client_conn_id = Some(conn_id);
        } else {
            // Only the holder may clear the reservation.
            if state.client_conn_id.is_some() && state.client_conn_id != Some(conn_id) {
                tracing::warn!(
                    mms_path,
                    conn_id,
                    "SetURCBValues Resv=false: writer does not hold the reservation"
                );
                return Err(DataAccessError::ObjectAccessDenied);
            }
            if !state.rpt_ena {
                state.resv = false;
                state.client_conn_id = None;
            }
        }
        return Ok(());
    }

    // RptEna = true on an unreserved control block reserves it for the writer,
    // per the Resv semantics of IEC 61850-7-2; the reservation is taken below,
    // only once the enable succeeds.
    let implicit_reservation = !state.resv
        && state.client_conn_id.is_none()
        && field == RcbField::RptEna
        && matches!(value, RcbWriteValue::Bool(true));

    // Otherwise a client that does not hold the reservation may not write any
    // other field, per the RCB write conditions of IEC 61850-7-2.
    if !implicit_reservation && (!state.resv || state.client_conn_id != Some(conn_id)) {
        tracing::warn!(
            mms_path,
            conn_id,
            field = field.as_str(),
            "SetURCBValues: not reserved by this client, answering ObjectAccessDenied"
        );
        return Err(DataAccessError::ObjectAccessDenied);
    }

    // RptEna: enable or disable.
    if field == RcbField::RptEna {
        let v = match value {
            RcbWriteValue::Bool(b) => b,
            _ => return Err(DataAccessError::TypeInconsistent),
        };
        if v {
            // Enabling requires a non-empty DatSet.
            if state.dat_set.is_empty() {
                tracing::warn!(mms_path, "SetURCBValues RptEna=true: DatSet is empty");
                return Err(DataAccessError::TemporarilyUnavailable);
            }
            if state.rpt_ena {
                // Already enabled.
                return Ok(());
            }
            if implicit_reservation {
                state.resv = true;
                state.client_conn_id = Some(conn_id);
            }
            state.rpt_ena = true;
            state.sq_num = 0;
            // The integrity period runs from the moment reporting is enabled.
            state.next_intg_report = (state.intg_pd_ms > 0).then(|| {
                std::time::Instant::now()
                    + std::time::Duration::from_millis(u64::from(state.intg_pd_ms))
            });
        } else {
            // Disabling clears the pending report. The reservation stays with
            // the holder: only Resv = false or the end of its association
            // releases it, per the Resv semantics of IEC 61850-7-2.
            if !state.rpt_ena {
                return Ok(());
            }
            state.rpt_ena = false;
            state.pending = None;
            state.triggered = false;
            state.report_due = None;
        }
        return Ok(());
    }

    // While the control block is enabled, RptID, DatSet, OptFlds, BufTm, TrgOps,
    // and IntgPd may not be changed; every such write is refused with
    // TemporarilyUnavailable.
    if state.rpt_ena
        && matches!(
            field,
            RcbField::RptId
                | RcbField::DatSet
                | RcbField::OptFlds
                | RcbField::BufTm
                | RcbField::TrgOps
                | RcbField::IntgPd
        )
    {
        tracing::warn!(
            mms_path,
            field = field.as_str(),
            "SetURCBValues: the control block is enabled"
        );
        return Err(DataAccessError::TemporarilyUnavailable);
    }

    // GI = true requires an enabled control block whose trgOps includes GI.
    if field == RcbField::Gi {
        let v = match value {
            RcbWriteValue::Bool(b) => b,
            _ => return Err(DataAccessError::TypeInconsistent),
        };
        if v {
            if !state.rpt_ena {
                tracing::warn!(
                    mms_path,
                    "SetURCBValues GI=true: the control block is not enabled"
                );
                return Ok(()); // silently ignored, per the GI conditions of IEC 61850-7-2
            }
            if !state.trg_ops.contains(crate::flags::TriggerOptions::GI) {
                tracing::warn!(
                    mms_path,
                    "SetURCBValues GI=true: trgOps does not include GI"
                );
                return Ok(()); // silently ignored
            }
            state.gi = true;
        }
        return Ok(());
    }

    // Ordinary field writes.
    match field {
        RcbField::RptId => {
            let s = match value {
                RcbWriteValue::VisibleString(s) => s,
                _ => return Err(DataAccessError::TypeInconsistent),
            };
            if s.len() > 129 {
                tracing::warn!(mms_path, "SetURCBValues RptID: longer than 129 bytes");
                return Err(DataAccessError::ObjectValueInvalid);
            }
            state.rpt_id = s;
        }
        RcbField::DatSet => {
            let s = match value {
                RcbWriteValue::VisibleString(s) => s,
                _ => return Err(DataAccessError::TypeInconsistent),
            };
            if s != state.dat_set {
                let dataset = if s.is_empty() {
                    None
                } else {
                    match eng.resolve_dataset(mms_path, &s) {
                        Some(ds) => Some(ds),
                        None => {
                            tracing::warn!(
                                mms_path,
                                dat_set = s.as_str(),
                                "SetURCBValues DatSet: no such data set, answering ObjectValueInvalid"
                            );
                            return Err(DataAccessError::ObjectValueInvalid);
                        }
                    }
                };
                eng.rebind_rcb_watches(&rc_arc, state.dataset.as_ref(), dataset.as_ref());
                state.dataset = dataset;
                state.pending = None;
                state.triggered = false;
                state.report_due = None;
                state.dat_set = s;
                state.increase_conf_rev();
            }
        }
        RcbField::OptFlds => {
            let bytes = match value {
                RcbWriteValue::BitString(b) => b,
                _ => return Err(DataAccessError::TypeInconsistent),
            };
            if let Some(flds) = crate::flags::OptFlds::from_ber_bit_string(&bytes) {
                state.opt_flds = flds.mask_urcb();
            } else {
                return Err(DataAccessError::TypeInconsistent);
            }
        }
        RcbField::BufTm => {
            let v = match value {
                RcbWriteValue::Unsigned(u) => u,
                _ => return Err(DataAccessError::TypeInconsistent),
            };
            state.buf_tm_ms = v;
        }
        RcbField::TrgOps => {
            let bytes = match value {
                RcbWriteValue::BitString(b) => b,
                _ => return Err(DataAccessError::TypeInconsistent),
            };
            if let Some(ops) = crate::flags::TriggerOptions::from_ber_bit_string(&bytes) {
                state.trg_ops = ops;
            } else {
                return Err(DataAccessError::TypeInconsistent);
            }
        }
        RcbField::IntgPd => {
            let v = match value {
                RcbWriteValue::Unsigned(u) => u,
                _ => return Err(DataAccessError::TypeInconsistent),
            };
            state.intg_pd_ms = v;
        }
        _ => {
            tracing::warn!(
                mms_path,
                field = field.as_str(),
                "unknown field, answering ObjectNonExistent"
            );
            return Err(DataAccessError::ObjectNonExistent);
        }
    }

    Ok(())
}

/// Reads one GetURCBValues field.
///
/// Returns the `AccessResult` the ReadResponse is assembled from, or `None` when
/// the field does not exist on a URCB, which the caller turns into
/// ObjectNonExistent. Implements the GetURCBValues semantics of IEC 61850-7-2.
pub fn handle_get_rcb_field(
    engine: &Arc<Mutex<ReportingEngine>>,
    mms_path: &str,
    field: RcbField,
) -> Option<iec61850_mms::mms::pdu::common::AccessResult> {
    use iec61850_mms::mms::pdu::common::{AccessResult, MmsData};

    let eng = engine.lock().ok()?;
    let rc_arc = eng.get_rcb(mms_path)?;
    drop(eng);

    let rc = rc_arc.lock().ok()?;
    let state = rc.state.lock().ok()?;

    let data = match field {
        RcbField::RptId => MmsData::VisibleString(state.rpt_id.clone()),
        RcbField::RptEna => MmsData::Boolean(state.rpt_ena),
        RcbField::Resv => MmsData::Boolean(state.resv),
        RcbField::DatSet => MmsData::VisibleString(state.dat_set.clone()),
        RcbField::ConfRev => MmsData::Unsigned(state.conf_rev as u64),
        RcbField::OptFlds => {
            let wire = state.opt_flds.to_ber_bit_string();
            MmsData::BitString {
                padding: wire[0],
                data: wire[1..].to_vec(),
            }
        }
        RcbField::BufTm => MmsData::Unsigned(state.buf_tm_ms as u64),
        RcbField::SqNum => MmsData::Unsigned(state.sq_num as u64),
        RcbField::TrgOps => {
            let wire = state.trg_ops.to_ber_bit_string();
            MmsData::BitString {
                padding: wire[0],
                data: wire[1..].to_vec(),
            }
        }
        RcbField::IntgPd => MmsData::Unsigned(state.intg_pd_ms as u64),
        RcbField::Gi => MmsData::Boolean(state.gi),
        RcbField::Owner => match state.owner {
            Some(std::net::IpAddr::V4(a)) => MmsData::OctetString(a.octets().to_vec()),
            Some(std::net::IpAddr::V6(a)) => MmsData::OctetString(a.octets().to_vec()),
            None => MmsData::OctetString(vec![]),
        },
        // These exist only on a BRCB; a client that addressed $RP$ instead of $BR$
        // gets ObjectNonExistent from the caller.
        RcbField::EntryId | RcbField::PurgeBuf | RcbField::TimeOfEntry | RcbField::ResvTms => {
            return None
        }
        RcbField::Unknown(_) => return None,
    };

    Some(AccessResult::Success(data))
}

// ─────────────────────────────────────────────────────────────────────────────
// BRCB field access: SetBRCBValues and GetBRCBValues
// ─────────────────────────────────────────────────────────────────────────────

use super::brcb::{ApplyEntryIdError, BrcbConfigField};
use super::buffer::EntryId;
use crate::flags::{OptFlds, TriggerOptions};
use iec61850_mms::binary_time6_from_epoch_ms;

/// Applies one SetBRCBValues field write received on connection `conn_id`.
///
/// Implements the BRCB branch of the RCB write rules of IEC 61850-7-2, including
/// the EntryID resynchronization path.
///
/// Returns `Some(Ok(()))` when the write is accepted, `Some(Err(..))` with the
/// `DataAccessError` to answer, and `None` when this server does not recognize the
/// field, which the caller turns into ObjectNonExistent.
///
/// Field rules:
/// - ConfRev, SqNum, TimeOfEntry, and Owner are never writable and give
///   ObjectAccessDenied
/// - RptEna = true binds the BRCB to `conn_id`, which then receives its reports;
///   enabling a BRCB whose transmit anchor is unset sends its buffer from the
///   oldest entry
/// - while the BRCB is enabled or reserved by another connection, or held for
///   the owner of a reservation whose association has ended, every write gives
///   ObjectAccessDenied
/// - a positive ResvTms reserves the BRCB for `conn_id` and its peer address;
///   the reservation outlives the association by ResvTms seconds
/// - DatSet, OptFlds, TrgOps, IntgPd, BufTm, RptID, EntryID, and PurgeBuf are
///   refused with TemporarilyUnavailable while RptEna is true, per
///   IEC 61850-8-1 Table 72
/// - an accepted change to one of those fields purges the report buffer, through
///   `BufferedReportControl::set_config_field`; of them only DatSet increments
///   ConfRev, and an OptFlds change does neither
///
/// The owner of a reservation is the peer address the server records for the
/// association `conn_id`, so clients that share an address, behind one NAT or
/// on one host, are the same owner. A connection with no recorded address may
/// not write a BRCB with a pre-configured owner, and a reservation it makes has
/// no owner: any client may take it over once its association has ended.
pub fn handle_set_brcb_field(
    engine: &Arc<Mutex<ReportingEngine>>,
    mms_path: &str,
    field: RcbField,
    value: RcbWriteValue,
    conn_id: ConnectionId,
) -> Option<Result<(), DataAccessError>> {
    // Never writable.
    match &field {
        RcbField::ConfRev => {
            tracing::warn!(mms_path, "SetBRCBValues: ConfRev is not writable");
            return Some(Err(DataAccessError::ObjectAccessDenied));
        }
        RcbField::SqNum => {
            tracing::warn!(mms_path, "SetBRCBValues: SqNum is not writable");
            return Some(Err(DataAccessError::ObjectAccessDenied));
        }
        // Resv exists only on a URCB, so addressing it here is a client error.
        RcbField::Resv => return None,
        _ => {}
    }

    // Take the control block handle and release the engine lock before locking it.
    let (brcb, writer_ip) = {
        let eng = engine
            .lock()
            .map_err(|_| DataAccessError::HardwareFault)
            .ok()?;
        match eng.get_brcb(mms_path) {
            Some(b) => (b, eng.peer(conn_id)),
            None => return Some(Err(DataAccessError::ObjectNonExistent)),
        }
    };
    if let Err(e) = claim_brcb(&brcb, conn_id, writer_ip) {
        return Some(Err(e));
    }

    match field {
        // EntryID.
        RcbField::EntryId => {
            let bytes = match value {
                RcbWriteValue::OctetString(b) => b,
                _ => {
                    tracing::warn!(
                        mms_path,
                        "SetBRCBValues EntryID: value is not an OctetString"
                    );
                    return Some(Err(DataAccessError::TypeInconsistent));
                }
            };
            if bytes.len() != 8 {
                tracing::warn!(
                    mms_path,
                    actual_len = bytes.len(),
                    "SetBRCBValues EntryID: an OctetString of exactly 8 bytes is required"
                );
                return Some(Err(DataAccessError::ObjectValueInvalid));
            }
            // External input is converted, never sliced blindly.
            let id_bytes: [u8; 8] = match <[u8; 8]>::try_from(&bytes[..]) {
                Ok(a) => a,
                Err(_) => return Some(Err(DataAccessError::ObjectValueInvalid)),
            };
            let id = EntryId(id_bytes);
            match brcb.apply_entry_id_write(id) {
                Ok(Ok(())) => Some(Ok(())),
                Ok(Err(ApplyEntryIdError::InvalidEntryId)) => {
                    Some(Err(DataAccessError::ObjectValueInvalid))
                }
                Ok(Err(ApplyEntryIdError::ReportingEnabled)) => {
                    Some(Err(DataAccessError::TemporarilyUnavailable))
                }
                Err(_) => Some(Err(DataAccessError::HardwareFault)),
            }
        }

        // PurgeBuf.
        RcbField::PurgeBuf => set_brcb_purge_buf(&brcb, value),

        // RptEna: enable or disable; the integrity period runs from the moment
        // reporting is enabled.
        RcbField::RptEna => match set_brcb_rpt_ena(&brcb, value, conn_id, writer_ip) {
            Ok(true) => {
                match engine.lock() {
                    Ok(eng) => eng.refresh_brcb_integrity_period(mms_path),
                    Err(_) => return Some(Err(DataAccessError::HardwareFault)),
                }
                Some(Ok(()))
            }
            Ok(false) => Some(Ok(())),
            Err(e) => Some(Err(e)),
        },

        // GI: trigger a general interrogation.
        RcbField::Gi => set_brcb_gi(&brcb, value),

        // Configuration fields; each is refused with TemporarilyUnavailable while
        // RptEna is true.
        RcbField::RptId => set_brcb_config_string(&brcb, value, "RptID"),
        RcbField::DatSet => set_brcb_dat_set(engine, &brcb, value),
        RcbField::OptFlds => set_brcb_opt_flds(&brcb, value),
        RcbField::BufTm => set_brcb_unsigned32(&brcb, value, "BufTm"),
        RcbField::TrgOps => set_brcb_trg_ops(&brcb, value),
        RcbField::IntgPd => set_brcb_unsigned32(&brcb, value, "IntgPd"),

        // ResvTms, an INT16 introduced in Edition 2.
        RcbField::ResvTms => set_brcb_resv_tms(&brcb, value, conn_id, writer_ip),

        // Owner and TimeOfEntry are never writable, per IEC 61850-8-1 Table 72.
        RcbField::Owner | RcbField::TimeOfEntry => {
            tracing::warn!(
                mms_path,
                field = field.as_str(),
                "SetBRCBValues: the field is not writable"
            );
            Some(Err(DataAccessError::ObjectAccessDenied))
        }

        // Remaining cases.
        RcbField::Unknown(_) => None,
        RcbField::ConfRev | RcbField::SqNum | RcbField::Resv => {
            // Handled above; unreachable, refused defensively.
            Some(Err(DataAccessError::ObjectAccessDenied))
        }
    }
}

/// Reads one GetBRCBValues field.
///
/// Returns `Some(AccessResult)` when the field was read, `None` when the field
/// does not exist on a BRCB, which the caller turns into ObjectNonExistent.
pub fn handle_get_brcb_field(
    engine: &Arc<Mutex<ReportingEngine>>,
    mms_path: &str,
    field: RcbField,
) -> Option<iec61850_mms::mms::pdu::common::AccessResult> {
    use iec61850_mms::mms::pdu::common::{AccessResult, MmsData};

    let brcb = {
        let eng = engine.lock().ok()?;
        eng.get_brcb(mms_path)?
    };

    // EntryID and TimeofEntry may need the buffer, whose lock is never held
    // together with the state lock.
    match field {
        RcbField::EntryId => {
            let (id, _) = exposed_entry(&brcb)?;
            return Some(AccessResult::Success(MmsData::OctetString(id.0.to_vec())));
        }
        RcbField::TimeOfEntry => {
            // BinaryTime6 wire format; the stored value is host-order milliseconds.
            let (_, ms) = exposed_entry(&brcb)?;
            return Some(AccessResult::Success(MmsData::BinaryTime(
                encode_binary_time6_bytes(ms),
            )));
        }
        _ => {}
    }

    // The other fields come from the runtime state.
    let state_guard = brcb.state.lock().ok()?;

    let data = match field {
        RcbField::RptId => MmsData::VisibleString(state_guard.rpt_id.clone()),
        RcbField::RptEna => MmsData::Boolean(state_guard.rpt_ena),
        // A BRCB has no Resv field; that one is specific to a URCB.
        RcbField::Resv => return None,
        RcbField::DatSet => MmsData::VisibleString(state_guard.dat_set.clone()),
        RcbField::ConfRev => MmsData::Unsigned(state_guard.conf_rev as u64),
        RcbField::OptFlds => {
            // A BRCB does not mask OptFlds, so BUFFER_OVERFLOW and ENTRY_ID survive.
            // `to_ber_bit_string` would mask them, so the wire bytes are built here.
            let v = state_guard.opt_flds.0;
            // Same byte layout as encode_opt_flds_unmasked in the PDU encoder.
            let byte0: u8 = ((v & 0x001) << 6) as u8
                | ((v & 0x002) << 4) as u8
                | ((v & 0x004) << 2) as u8
                | (v & 0x008) as u8
                | ((v & 0x010) >> 2) as u8
                | ((v & 0x020) >> 4) as u8
                | ((v & 0x040) >> 6) as u8;
            let byte1: u8 = (v & 0x080) as u8 | ((v & 0x100) >> 2) as u8;
            MmsData::BitString {
                padding: 6,
                data: vec![byte0, byte1],
            }
        }
        RcbField::BufTm => MmsData::Unsigned(state_guard.buf_tm_ms as u64),
        // A BRCB SqNum is 16 bits wide.
        RcbField::SqNum => MmsData::Unsigned(state_guard.sq_num as u64),
        RcbField::TrgOps => {
            let wire = state_guard.trg_ops.to_ber_bit_string();
            MmsData::BitString {
                padding: wire[0],
                data: wire[1..].to_vec(),
            }
        }
        RcbField::IntgPd => MmsData::Unsigned(state_guard.intg_pd_ms as u64),
        RcbField::Gi => MmsData::Boolean(state_guard.gi),
        RcbField::Owner => match state_guard.owner {
            Some(std::net::IpAddr::V4(a)) => MmsData::OctetString(a.octets().to_vec()),
            Some(std::net::IpAddr::V6(a)) => MmsData::OctetString(a.octets().to_vec()),
            None => MmsData::OctetString(vec![]),
        },
        // Read above, before the state lock is taken.
        RcbField::EntryId => return None,
        RcbField::TimeOfEntry => return None,
        RcbField::PurgeBuf => {
            // PurgeBuf is a trigger flag: it reads back false once the purge has run.
            MmsData::Boolean(state_guard.purge_buf_pending)
        }
        RcbField::ResvTms => {
            // INT16 wire format.
            MmsData::Integer(state_guard.resv_tms.to_wire() as i64)
        }
        RcbField::Unknown(_) => return None,
    };

    Some(AccessResult::Success(data))
}

/// Returns the EntryID a GetBRCBValues response exposes, with its TimeOfEntry
/// in milliseconds, per IEC 61850-7-2.
///
/// With RptEna true it is the last entry formatted and queued for transmission.
/// With RptEna false it is the newest entry in the buffer, or the all-zero
/// EntryID with a zero timestamp when the buffer is empty. A client write of
/// EntryID moves the transmit anchor only and does not change this value.
///
/// Returns `None` when a mutex is poisoned.
fn exposed_entry(brcb: &super::brcb::BufferedReportControl) -> Option<(EntryId, u64)> {
    let (rpt_ena, last_sent) = {
        let state = brcb.state.lock().ok()?;
        (
            state.rpt_ena,
            (state.last_sent_entry_id, state.last_sent_time_of_entry_ms),
        )
    };
    if rpt_ena {
        return Some(last_sent);
    }
    let buffer = brcb.report_buffer.lock().ok()?;
    let newest = buffer
        .newest_entry()
        .map_or((EntryId::ZERO, 0), |e| (e.entry_id, e.time_of_entry_ms));
    Some(newest)
}

// ─────────────────────────────────────────────────────────────────────────────
// BRCB field write helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Decides whether connection `writer`, whose peer address is `writer_ip`, may
/// write a field of the BRCB.
///
/// Per the BRCB reservation of IEC 61850-7-2: a BRCB that another association
/// has enabled or reserved is refused with ObjectAccessDenied. A reservation
/// whose association has ended (positive ResvTms, still running) or a
/// pre-configured one is refused to every client whose address is not the
/// owner's; the owner's new association takes the BRCB over and the
/// reservation timer stops.
fn claim_brcb(
    brcb: &super::brcb::BufferedReportControl,
    writer: ConnectionId,
    writer_ip: Option<std::net::IpAddr>,
) -> Result<(), DataAccessError> {
    let mut state = brcb
        .lock_state()
        .map_err(|_| DataAccessError::HardwareFault)?;
    claim_brcb_locked(brcb, &mut state, writer, writer_ip)
}

/// Applies the `claim_brcb` decision to state the caller already holds locked.
///
/// A setter that changes which connection holds the BRCB repeats the decision
/// inside its own critical section, so a claim decided before another
/// connection's write cannot overwrite that write.
fn claim_brcb_locked(
    brcb: &super::brcb::BufferedReportControl,
    state: &mut super::brcb::BrcbState,
    writer: ConnectionId,
    writer_ip: Option<std::net::IpAddr>,
) -> Result<(), DataAccessError> {
    use super::brcb::ResvTmsState;
    let reserved = state.resv_tms != ResvTmsState::NotReserved;
    match state.client_conn_id {
        Some(holder) if holder == writer => return Ok(()),
        Some(_) if state.rpt_ena || reserved => {
            tracing::warn!(
                mms_path = %brcb.mms_path,
                conn_id = writer,
                "SetBRCBValues: the control block is held by another client"
            );
            return Err(DataAccessError::ObjectAccessDenied);
        }
        _ => {}
    }
    if !reserved {
        return Ok(());
    }
    let owner = match state.resv_tms {
        ResvTmsState::Preconfigured => brcb.brcb.client_reservation.or(state.owner),
        _ => state.owner,
    };
    if owner.is_some() && owner != writer_ip {
        tracing::warn!(
            mms_path = %brcb.mms_path,
            conn_id = writer,
            "SetBRCBValues: the control block is reserved for another client"
        );
        return Err(DataAccessError::ObjectAccessDenied);
    }
    state.client_conn_id = Some(writer);
    state.owner = owner.or(writer_ip);
    state.reservation_timeout = None;
    Ok(())
}

fn set_brcb_purge_buf(
    brcb: &Arc<super::brcb::BufferedReportControl>,
    value: RcbWriteValue,
) -> Option<Result<(), DataAccessError>> {
    let v = match value {
        RcbWriteValue::Bool(b) => b,
        _ => return Some(Err(DataAccessError::TypeInconsistent)),
    };
    // While RptEna is false, writing false has no effect and writing true purges
    // the buffer; while it is true, either value is refused.
    match brcb.handle_purge_buf_write(v) {
        Ok(_purged) => Some(Ok(())),
        Err(crate::error::ServerError::InvalidModel(msg)) if msg.contains("RptEna=true") => {
            Some(Err(DataAccessError::TemporarilyUnavailable))
        }
        Err(_) => Some(Err(DataAccessError::HardwareFault)),
    }
}

/// Applies a RptEna write; returns whether the write enabled the BRCB.
fn set_brcb_rpt_ena(
    brcb: &Arc<super::brcb::BufferedReportControl>,
    value: RcbWriteValue,
    conn_id: ConnectionId,
    writer_ip: Option<std::net::IpAddr>,
) -> Result<bool, DataAccessError> {
    let v = match value {
        RcbWriteValue::Bool(b) => b,
        _ => return Err(DataAccessError::TypeInconsistent),
    };
    let mut state = match brcb.lock_state() {
        Ok(s) => s,
        Err(_) => return Err(DataAccessError::HardwareFault),
    };
    claim_brcb_locked(brcb, &mut state, conn_id, writer_ip)?;
    if v {
        if state.dat_set.is_empty() {
            tracing::warn!(
                mms_path = %brcb.mms_path,
                "SetBRCBValues RptEna=true: DatSet is empty"
            );
            return Err(DataAccessError::TemporarilyUnavailable);
        }
        state.client_conn_id = Some(conn_id);
        if state.rpt_ena {
            return Ok(false);
        }
        state.rpt_ena = true;
        // A client that enables reporting without writing EntryID first receives
        // the buffer from its oldest entry.
        if state.transmit_anchor == super::brcb::TransmitAnchor::None {
            state.transmit_anchor = super::brcb::TransmitAnchor::FromHead;
        }
        // SqNum is not reset on enable: a BRCB sequence number is 16 bits and wraps
        // naturally, unlike the URCB counter.
    } else {
        if !state.rpt_ena {
            return Ok(false);
        }
        state.rpt_ena = false;
        // Disabling a BRCB keeps the buffer; only the overflow indication matters,
        // and the send path already implies it for a from-head or unset anchor, so
        // the backend is left untouched here.
    }
    Ok(v)
}

fn set_brcb_gi(
    brcb: &Arc<super::brcb::BufferedReportControl>,
    value: RcbWriteValue,
) -> Option<Result<(), DataAccessError>> {
    let v = match value {
        RcbWriteValue::Bool(b) => b,
        _ => return Some(Err(DataAccessError::TypeInconsistent)),
    };
    if !v {
        return Some(Ok(()));
    }
    let mut state = match brcb.lock_state() {
        Ok(s) => s,
        Err(_) => return Some(Err(DataAccessError::HardwareFault)),
    };
    if !state.rpt_ena {
        tracing::warn!(mms_path = %brcb.mms_path, "SetBRCBValues GI=true: the control block is not enabled");
        return Some(Ok(()));
    }
    if !state.trg_ops.contains(TriggerOptions::GI) {
        tracing::warn!(
            mms_path = %brcb.mms_path,
            "SetBRCBValues GI=true: trgOps does not include GI"
        );
        return Some(Ok(()));
    }
    state.gi = true;
    Some(Ok(()))
}

fn set_brcb_config_string(
    brcb: &Arc<super::brcb::BufferedReportControl>,
    value: RcbWriteValue,
    which: &str,
) -> Option<Result<(), DataAccessError>> {
    let s = match value {
        RcbWriteValue::VisibleString(s) => s,
        _ => return Some(Err(DataAccessError::TypeInconsistent)),
    };
    if s.len() > 129 {
        tracing::warn!(mms_path = %brcb.mms_path, which, len = s.len(), "brcb string longer than 129 bytes");
        return Some(Err(DataAccessError::ObjectValueInvalid));
    }
    let field = match which {
        "RptID" => BrcbConfigField::RptId(s),
        _ => return None,
    };
    match brcb.set_config_field(field) {
        Ok(_) => Some(Ok(())),
        Err(crate::error::ServerError::InvalidModel(msg)) if msg.contains("RptEna=true") => {
            // Configuration may not change while RptEna is true.
            Some(Err(DataAccessError::TemporarilyUnavailable))
        }
        Err(_) => Some(Err(DataAccessError::HardwareFault)),
    }
}

/// Applies a DatSet write: the name must resolve to a known data set, and the
/// BRCB is then bound to its members. A non-persistent data set, whose name
/// starts with `@`, may not be the DatSet of a BRCB, per IEC 61850-7-2.
fn set_brcb_dat_set(
    engine: &Arc<Mutex<ReportingEngine>>,
    brcb: &Arc<super::brcb::BufferedReportControl>,
    value: RcbWriteValue,
) -> Option<Result<(), DataAccessError>> {
    let s = match value {
        RcbWriteValue::VisibleString(s) => s,
        _ => return Some(Err(DataAccessError::TypeInconsistent)),
    };
    if s.len() > 129 {
        tracing::warn!(mms_path = %brcb.mms_path, len = s.len(), "brcb DatSet longer than 129 bytes");
        return Some(Err(DataAccessError::ObjectValueInvalid));
    }
    // The engine lock is held across resolution and rebinding.
    let Ok(mut eng) = engine.lock() else {
        return Some(Err(DataAccessError::HardwareFault));
    };
    let (enabled, unchanged) = match brcb.lock_state() {
        Ok(state) => (state.rpt_ena, state.dat_set == s),
        Err(_) => return Some(Err(DataAccessError::HardwareFault)),
    };
    if enabled {
        return Some(Err(DataAccessError::TemporarilyUnavailable));
    }
    if unchanged {
        return Some(Ok(()));
    }
    let item = s.split_once('/').map_or(s.as_str(), |(_, item)| item);
    if item.starts_with('@') {
        tracing::warn!(
            mms_path = %brcb.mms_path,
            dat_set = s.as_str(),
            "SetBRCBValues DatSet: a non-persistent data set, answering ObjectValueInvalid"
        );
        return Some(Err(DataAccessError::ObjectValueInvalid));
    }
    let dataset = if s.is_empty() {
        None
    } else {
        match eng.resolve_dataset(&brcb.mms_path, &s) {
            Some(ds) => Some(ds),
            None => {
                tracing::warn!(
                    mms_path = %brcb.mms_path,
                    dat_set = s.as_str(),
                    "SetBRCBValues DatSet: no such data set, answering ObjectValueInvalid"
                );
                return Some(Err(DataAccessError::ObjectValueInvalid));
            }
        }
    };
    match brcb.set_config_field(BrcbConfigField::DatSet(s)) {
        Ok(super::brcb::ConfigChangeResult::NoChange) => Some(Ok(())),
        Ok(_) => {
            eng.rebind_brcb_dataset(&brcb.mms_path, dataset);
            Some(Ok(()))
        }
        Err(crate::error::ServerError::InvalidModel(msg)) if msg.contains("RptEna=true") => {
            Some(Err(DataAccessError::TemporarilyUnavailable))
        }
        Err(_) => Some(Err(DataAccessError::HardwareFault)),
    }
}

fn set_brcb_unsigned32(
    brcb: &Arc<super::brcb::BufferedReportControl>,
    value: RcbWriteValue,
    which: &str,
) -> Option<Result<(), DataAccessError>> {
    let v = match value {
        RcbWriteValue::Unsigned(u) => u,
        _ => return Some(Err(DataAccessError::TypeInconsistent)),
    };
    let field = match which {
        "BufTm" => BrcbConfigField::BufTmMs(v),
        "IntgPd" => BrcbConfigField::IntgPdMs(v),
        _ => return None,
    };
    match brcb.set_config_field(field) {
        Ok(_) => Some(Ok(())),
        Err(crate::error::ServerError::InvalidModel(msg)) if msg.contains("RptEna=true") => {
            Some(Err(DataAccessError::TemporarilyUnavailable))
        }
        Err(_) => Some(Err(DataAccessError::HardwareFault)),
    }
}

fn set_brcb_trg_ops(
    brcb: &Arc<super::brcb::BufferedReportControl>,
    value: RcbWriteValue,
) -> Option<Result<(), DataAccessError>> {
    let bytes = match value {
        RcbWriteValue::BitString(b) => b,
        _ => return Some(Err(DataAccessError::TypeInconsistent)),
    };
    let ops = match TriggerOptions::from_ber_bit_string(&bytes) {
        Some(o) => o,
        None => return Some(Err(DataAccessError::TypeInconsistent)),
    };
    match brcb.set_config_field(BrcbConfigField::TrgOps(ops)) {
        Ok(_) => Some(Ok(())),
        Err(crate::error::ServerError::InvalidModel(msg)) if msg.contains("RptEna=true") => {
            Some(Err(DataAccessError::TemporarilyUnavailable))
        }
        Err(_) => Some(Err(DataAccessError::HardwareFault)),
    }
}

fn set_brcb_opt_flds(
    brcb: &Arc<super::brcb::BufferedReportControl>,
    value: RcbWriteValue,
) -> Option<Result<(), DataAccessError>> {
    let bytes = match value {
        RcbWriteValue::BitString(b) => b,
        _ => return Some(Err(DataAccessError::TypeInconsistent)),
    };
    let flds = match OptFlds::from_ber_bit_string(&bytes) {
        Some(f) => f,
        None => return Some(Err(DataAccessError::TypeInconsistent)),
    };
    let mut state = match brcb.lock_state() {
        Ok(s) => s,
        Err(_) => return Some(Err(DataAccessError::HardwareFault)),
    };
    if state.rpt_ena {
        return Some(Err(DataAccessError::TemporarilyUnavailable));
    }
    // A BRCB keeps BUFFER_OVERFLOW and ENTRY_ID rather than masking them. An
    // OptFlds change neither purges the buffer nor counts in ConfRev.
    state.opt_flds = flds;
    Some(Ok(()))
}

/// Applies a ResvTms write.
///
/// A positive value received on connection `conn_id` reserves the BRCB for that
/// association, owned by `writer_ip`; the reservation timer starts only when the
/// association ends. Zero releases the reservation; an enabled BRCB keeps its
/// connection.
fn set_brcb_resv_tms(
    brcb: &Arc<super::brcb::BufferedReportControl>,
    value: RcbWriteValue,
    conn_id: ConnectionId,
    writer_ip: Option<std::net::IpAddr>,
) -> Option<Result<(), DataAccessError>> {
    // ResvTms is an INT16; an UNSIGNED in its non-negative range is accepted as
    // well. A negative value or one past 32767 is refused.
    let wide: i64 = match value {
        RcbWriteValue::Integer(i) => i,
        RcbWriteValue::Unsigned(u) => i64::from(u),
        _ => return Some(Err(DataAccessError::TypeInconsistent)),
    };
    let v_i16 = match i16::try_from(wide) {
        Ok(v) if v >= 0 => v,
        _ => {
            tracing::warn!(
                mms_path = %brcb.mms_path,
                value = wide,
                "SetBRCBValues ResvTms: outside 0..=32767, answering ObjectValueInvalid"
            );
            return Some(Err(DataAccessError::ObjectValueInvalid));
        }
    };
    let mut state = match brcb.lock_state() {
        Ok(s) => s,
        Err(_) => return Some(Err(DataAccessError::HardwareFault)),
    };
    if let Err(e) = claim_brcb_locked(brcb, &mut state, conn_id, writer_ip) {
        return Some(Err(e));
    }
    let new_state = super::brcb::ResvTmsState::from_wire(v_i16);
    state.resv_tms = new_state;
    match new_state {
        super::brcb::ResvTmsState::WithTimeout(_) => {
            state.client_conn_id = Some(conn_id);
            state.owner = writer_ip;
            state.reservation_timeout = None;
        }
        super::brcb::ResvTmsState::NotReserved => {
            state.reservation_timeout = None;
            if !state.rpt_ena {
                state.client_conn_id = None;
                state.owner = None;
            }
        }
        super::brcb::ResvTmsState::Preconfigured => {}
    }
    Some(Ok(()))
}

/// Encodes milliseconds since 1970-01-01 as BinaryTime6 wire bytes.
///
/// Four big-endian bytes of milliseconds since midnight followed by two
/// big-endian bytes counting days since 1984-01-01, the same layout the report
/// PDU encoder writes for TimeOfEntry.
fn encode_binary_time6_bytes(ms: u64) -> Vec<u8> {
    binary_time6_from_epoch_ms(ms).to_vec()
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::{OptFlds, TriggerOptions};
    use crate::reporting::dataset::{Dataset, DatasetEntry};
    use crate::reporting::rcb::Rcb;
    use iec61850_model::MmsValue;
    use std::sync::{Arc, RwLock};
    use std::time::{Duration, Instant};

    fn make_engine_with_rcb(
        rcb_name: &str,
        trg_ops: TriggerOptions,
    ) -> (Arc<Mutex<ReportingEngine>>, String) {
        use super::super::engine::ReportingEngine;

        let mut engine = ReportingEngine::new(Arc::new(super::super::engine::NullReportSink));
        let rcb = Rcb::new(rcb_name, "GGIO1$ds1")
            .with_trg_ops(trg_ops)
            .with_opt_flds(OptFlds::SEQ_NUM | OptFlds::TIME_STAMP)
            .with_buf_tm_ms(100)
            .with_intg_pd_ms(0);
        let path = format!("IED1LD0/GGIO1$RP${}", rcb_name);
        let rc = super::super::rcb::ReportControl::new(&path, rcb);
        let mut ds = Dataset::new("GGIO1$ds1");
        ds.push(DatasetEntry::new(
            "IED1LD0/GGIO1$ST$Ind1$stVal",
            Arc::new(RwLock::new(MmsValue::Boolean(false))),
        ));
        engine.register_rcb(rc, ds).unwrap();
        (Arc::new(Mutex::new(engine)), path)
    }

    /// Installs a registry on `engine` holding one single-member data set per
    /// `(domain, list_name, member)`, and returns the member value locks.
    fn install_registry(
        engine: &Arc<Mutex<ReportingEngine>>,
        sets: &[(&str, &str, &str)],
    ) -> Vec<Arc<RwLock<MmsValue>>> {
        let registry: super::super::DatasetRegistry = Default::default();
        let mut values = Vec::new();
        for (domain, list_name, member) in sets {
            let value = Arc::new(RwLock::new(MmsValue::Integer(0)));
            let mut ds = Dataset::new(*list_name);
            ds.push(DatasetEntry::new(*member, value.clone()));
            registry
                .write()
                .unwrap()
                .insert((domain.to_string(), list_name.to_string()), Arc::new(ds));
            values.push(value);
        }
        engine.lock().unwrap().set_dataset_registry(registry);
        values
    }

    // ── DatSet resolution and rebinding ──────────────────────────────────────

    const DS2_MEMBER: &str = "IED1LD0/GGIO1$ST$Ind2$stVal";

    fn urcb_dataset_refs(engine: &Arc<Mutex<ReportingEngine>>, path: &str) -> Vec<String> {
        let rc_arc = engine.lock().unwrap().get_rcb(path).unwrap();
        let rc = rc_arc.lock().unwrap();
        let state = rc.state.lock().unwrap();
        state
            .dataset
            .as_ref()
            .map(|d| d.entries.iter().map(|e| e.attr_ref.clone()).collect())
            .unwrap_or_default()
    }

    #[test]
    fn urcb_dat_set_naming_no_data_set_is_refused() {
        let (engine, path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED);
        install_registry(&engine, &[("IED1LD0", "GGIO1$ds2", DS2_MEMBER)]);
        handle_set_rcb_field(&engine, &path, RcbField::Resv, RcbWriteValue::Bool(true), 1).unwrap();
        let res = handle_set_rcb_field(
            &engine,
            &path,
            RcbField::DatSet,
            RcbWriteValue::VisibleString("IED1LD0/GGIO1$noSuchDs".to_string()),
            1,
        );
        assert_eq!(res, Err(DataAccessError::ObjectValueInvalid));
        let get = handle_get_rcb_field(&engine, &path, RcbField::DatSet);
        assert!(matches!(
            get,
            Some(iec61850_mms::mms::pdu::common::AccessResult::Success(
                iec61850_mms::mms::pdu::common::MmsData::VisibleString(ref v)
            )) if v == "GGIO1$ds1"
        ));
        assert_eq!(
            urcb_dataset_refs(&engine, &path),
            ["IED1LD0/GGIO1$ST$Ind1$stVal"]
        );
    }

    #[test]
    fn urcb_dat_set_write_rebinds_the_members() {
        let (engine, path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED);
        let values = install_registry(&engine, &[("IED1LD0", "GGIO1$ds2", DS2_MEMBER)]);
        handle_set_rcb_field(&engine, &path, RcbField::Resv, RcbWriteValue::Bool(true), 1).unwrap();
        for dat_set in ["IED1LD0/GGIO1$ds2", "GGIO1$ds2"] {
            handle_set_rcb_field(
                &engine,
                &path,
                RcbField::DatSet,
                RcbWriteValue::VisibleString(String::new()),
                1,
            )
            .unwrap();
            handle_set_rcb_field(
                &engine,
                &path,
                RcbField::DatSet,
                RcbWriteValue::VisibleString(dat_set.to_string()),
                1,
            )
            .unwrap();
            assert_eq!(urcb_dataset_refs(&engine, &path), [DS2_MEMBER], "{dat_set}");
        }
        handle_set_rcb_field(
            &engine,
            &path,
            RcbField::RptEna,
            RcbWriteValue::Bool(true),
            1,
        )
        .unwrap();

        let eng = engine.lock().unwrap();
        assert_eq!(
            eng.value_index().attr_ref_for(&values[0]).as_deref(),
            Some(DS2_MEMBER)
        );
        let flag = crate::flags::InclusionFlag::VALUE_CHANGED;
        // The previous member no longer triggers the control block.
        eng.on_value_updated(
            &"IED1LD0/GGIO1$ST$Ind1$stVal".to_string(),
            MmsValue::Boolean(true),
            flag,
            1,
        );
        let rc_arc = eng.get_rcb(&path).unwrap();
        assert!(rc_arc
            .lock()
            .unwrap()
            .state
            .lock()
            .unwrap()
            .pending
            .is_none());
        eng.on_value_updated(&DS2_MEMBER.to_string(), MmsValue::Integer(5), flag, 2);
        let rc = rc_arc.lock().unwrap();
        let state = rc.state.lock().unwrap();
        let pending = state.pending.as_ref().expect("the new member triggers");
        assert_eq!(pending.snapshot, [Some(MmsValue::Integer(5))]);
    }

    #[test]
    fn brcb_dat_set_naming_no_data_set_is_refused() {
        let (engine, path) = make_engine_with_brcb("05", TriggerOptions::DATA_CHANGED);
        install_registry(&engine, &[("IED1LD0", "MMXU1$ds2", DS2_MEMBER)]);
        let res = handle_set_brcb_field(
            &engine,
            &path,
            RcbField::DatSet,
            RcbWriteValue::VisibleString("MMXU1$noSuchDs".to_string()),
            1,
        );
        assert_eq!(res, Some(Err(DataAccessError::ObjectValueInvalid)));
        let b = engine.lock().unwrap().get_brcb(&path).unwrap();
        assert_eq!(b.state.lock().unwrap().dat_set, "MMXU1$ds1");
    }

    #[test]
    fn brcb_dat_set_naming_a_non_persistent_data_set_is_refused() {
        let (engine, path) = make_engine_with_brcb("05", TriggerOptions::DATA_CHANGED);
        install_registry(&engine, &[("IED1LD0", "@dsTmp", DS2_MEMBER)]);
        for dat_set in ["@dsTmp", "IED1LD0/@dsTmp"] {
            let res = handle_set_brcb_field(
                &engine,
                &path,
                RcbField::DatSet,
                RcbWriteValue::VisibleString(dat_set.to_string()),
                1,
            );
            assert_eq!(
                res,
                Some(Err(DataAccessError::ObjectValueInvalid)),
                "{dat_set}"
            );
        }

        // Control: a URCB may refer to it.
        let (engine, path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED);
        install_registry(&engine, &[("IED1LD0", "@dsTmp", DS2_MEMBER)]);
        handle_set_rcb_field(&engine, &path, RcbField::Resv, RcbWriteValue::Bool(true), 1).unwrap();
        handle_set_rcb_field(
            &engine,
            &path,
            RcbField::DatSet,
            RcbWriteValue::VisibleString("@dsTmp".to_string()),
            1,
        )
        .unwrap();
    }

    #[test]
    fn brcb_dat_set_write_rebinds_the_members() {
        let (engine, path) = make_engine_with_brcb("05", TriggerOptions::DATA_CHANGED);
        let values = install_registry(&engine, &[("IED1LD0", "MMXU1$ds2", DS2_MEMBER)]);
        let res = handle_set_brcb_field(
            &engine,
            &path,
            RcbField::DatSet,
            RcbWriteValue::VisibleString("IED1LD0/MMXU1$ds2".to_string()),
            1,
        );
        assert_eq!(res, Some(Ok(())));
        let eng = engine.lock().unwrap();
        let refs: Vec<_> = eng
            .brcb_dataset(&path)
            .expect("bound")
            .entries
            .iter()
            .map(|e| e.attr_ref.clone())
            .collect();
        assert_eq!(refs, [DS2_MEMBER]);
        assert_eq!(
            eng.value_index().attr_ref_for(&values[0]).as_deref(),
            Some(DS2_MEMBER)
        );
        eng.on_brcb_value_updated(
            &DS2_MEMBER.to_string(),
            MmsValue::Integer(5),
            crate::flags::InclusionFlag::VALUE_CHANGED,
            1_000,
        );
        let b = eng.get_brcb(&path).unwrap();
        let entries = b.lock_buffer().unwrap().iter_entries();
        assert_eq!(entries.len(), 1, "the new member triggers the BRCB");
        let snap = entries[0].snapshot.as_ref().expect("snapshot");
        assert_eq!(snap.values, [Some(MmsValue::Integer(5))]);
    }

    #[test]
    fn dataset_in_use_follows_the_dat_set_of_every_control_block() {
        let (engine, path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED);
        install_registry(&engine, &[("IED1LD0", "GGIO1$ds2", DS2_MEMBER)]);
        {
            let eng = engine.lock().unwrap();
            assert!(eng.dataset_in_use("IED1LD0", "GGIO1$ds1"));
            assert!(!eng.dataset_in_use("IED1LD0", "GGIO1$ds2"));
            assert!(!eng.dataset_in_use("OTHER", "GGIO1$ds1"));
        }
        handle_set_rcb_field(&engine, &path, RcbField::Resv, RcbWriteValue::Bool(true), 1).unwrap();
        handle_set_rcb_field(
            &engine,
            &path,
            RcbField::DatSet,
            RcbWriteValue::VisibleString("IED1LD0/GGIO1$ds2".to_string()),
            1,
        )
        .unwrap();
        let eng = engine.lock().unwrap();
        assert!(!eng.dataset_in_use("IED1LD0", "GGIO1$ds1"));
        assert!(eng.dataset_in_use("IED1LD0", "GGIO1$ds2"));
    }

    #[test]
    fn dataset_in_use_follows_the_dat_set_of_a_brcb() {
        let (engine, path) = make_engine_with_brcb("05", TriggerOptions::DATA_CHANGED);
        install_registry(&engine, &[("IED1LD0", "MMXU1$ds2", DS2_MEMBER)]);
        {
            let eng = engine.lock().unwrap();
            assert!(eng.dataset_in_use("IED1LD0", "MMXU1$ds1"));
            assert!(!eng.dataset_in_use("IED1LD0", "MMXU1$ds2"));
        }
        let res = handle_set_brcb_field(
            &engine,
            &path,
            RcbField::DatSet,
            RcbWriteValue::VisibleString("IED1LD0/MMXU1$ds2".to_string()),
            1,
        );
        assert_eq!(res, Some(Ok(())));
        let eng = engine.lock().unwrap();
        assert!(!eng.dataset_in_use("IED1LD0", "MMXU1$ds1"));
        assert!(eng.dataset_in_use("IED1LD0", "MMXU1$ds2"));
    }

    #[test]
    fn dat_set_naming_another_logical_device_resolves_there() {
        const LD1_MEMBER: &str = "IED1LD1/GGIO1$ST$Ind2$stVal";
        let (engine, path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED);
        let values = install_registry(
            &engine,
            &[
                ("IED1LD0", "GGIO1$ds2", DS2_MEMBER),
                ("IED1LD1", "GGIO1$ds2", LD1_MEMBER),
            ],
        );
        handle_set_rcb_field(&engine, &path, RcbField::Resv, RcbWriteValue::Bool(true), 1).unwrap();
        handle_set_rcb_field(
            &engine,
            &path,
            RcbField::DatSet,
            RcbWriteValue::VisibleString("IED1LD1/GGIO1$ds2".to_string()),
            1,
        )
        .unwrap();
        assert_eq!(urcb_dataset_refs(&engine, &path), [LD1_MEMBER]);
        let eng = engine.lock().unwrap();
        assert!(eng.dataset_in_use("IED1LD1", "GGIO1$ds2"));
        assert!(!eng.dataset_in_use("IED1LD0", "GGIO1$ds2"));
        assert_eq!(
            eng.value_index().attr_ref_for(&values[1]).as_deref(),
            Some(LD1_MEMBER)
        );
        assert_eq!(eng.value_index().attr_ref_for(&values[0]), None);
    }

    #[test]
    fn value_index_ignores_a_value_no_data_set_holds() {
        let (engine, _path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED);
        let other = Arc::new(RwLock::new(MmsValue::Integer(0)));
        assert_eq!(
            engine.lock().unwrap().value_index().attr_ref_for(&other),
            None
        );
    }

    // ── RcbField parsing ─────────────────────────────────────────────────────

    #[test]
    fn rcb_field_from_name_round_trip() {
        for (name, expected) in [
            ("RptID", RcbField::RptId),
            ("RptEna", RcbField::RptEna),
            ("Resv", RcbField::Resv),
            ("DatSet", RcbField::DatSet),
            ("ConfRev", RcbField::ConfRev),
            ("OptFlds", RcbField::OptFlds),
            ("BufTm", RcbField::BufTm),
            ("SqNum", RcbField::SqNum),
            ("TrgOps", RcbField::TrgOps),
            ("IntgPd", RcbField::IntgPd),
            ("GI", RcbField::Gi),
            ("Owner", RcbField::Owner),
            ("EntryID", RcbField::EntryId),
            ("PurgeBuf", RcbField::PurgeBuf),
            ("TimeofEntry", RcbField::TimeOfEntry),
            ("ResvTms", RcbField::ResvTms),
        ] {
            let parsed = RcbField::from_name(name);
            assert_eq!(parsed, expected, "from_name({}) parsed incorrectly", name);
            assert_eq!(
                parsed.as_str(),
                name,
                "as_str() must return the original name"
            );
        }
    }

    // ── Fields that are never writable ───────────────────────────────────────

    #[test]
    fn conf_rev_write_denied() {
        let (engine, path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED);
        let res = handle_set_rcb_field(
            &engine,
            &path,
            RcbField::ConfRev,
            RcbWriteValue::Unsigned(42),
            1,
        );
        assert_eq!(res, Err(DataAccessError::ObjectAccessDenied));
    }

    #[test]
    fn sq_num_write_denied() {
        let (engine, path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED);
        let res = handle_set_rcb_field(
            &engine,
            &path,
            RcbField::SqNum,
            RcbWriteValue::Unsigned(5),
            1,
        );
        assert_eq!(res, Err(DataAccessError::ObjectAccessDenied));
    }

    #[test]
    fn owner_write_denied() {
        let (engine, path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED);
        let res = handle_set_rcb_field(
            &engine,
            &path,
            RcbField::Owner,
            RcbWriteValue::OctetString(vec![127, 0, 0, 1]),
            1,
        );
        assert_eq!(res, Err(DataAccessError::ObjectAccessDenied));
    }

    // ── Reservation transitions ──────────────────────────────────────────────

    #[test]
    fn resv_true_sets_reserved() {
        let (engine, path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED);
        let res =
            handle_set_rcb_field(&engine, &path, RcbField::Resv, RcbWriteValue::Bool(true), 1);
        assert_eq!(res, Ok(()));

        let eng = engine.lock().unwrap();
        let rc_arc = eng.get_rcb(&path).unwrap();
        drop(eng);
        let rc = rc_arc.lock().unwrap();
        let state = rc.state.lock().unwrap();
        assert!(state.resv, "resv must be set");
        assert_eq!(state.client_conn_id, Some(1));
    }

    #[test]
    fn second_client_resv_denied() {
        let (engine, path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED);
        // connection 1 reserves first
        handle_set_rcb_field(&engine, &path, RcbField::Resv, RcbWriteValue::Bool(true), 1).unwrap();
        // connection 2 then tries to reserve
        let res =
            handle_set_rcb_field(&engine, &path, RcbField::Resv, RcbWriteValue::Bool(true), 2);
        assert_eq!(res, Err(DataAccessError::TemporarilyUnavailable));
    }

    // ── An unreserved client may not write other fields ──────────────────────

    #[test]
    fn ed21_non_reserved_write_denied() {
        let (engine, path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED);
        // Write RptID without reserving first.
        let res = handle_set_rcb_field(
            &engine,
            &path,
            RcbField::RptId,
            RcbWriteValue::VisibleString("newId".to_string()),
            1,
        );
        assert_eq!(res, Err(DataAccessError::ObjectAccessDenied));
    }

    // ── Enable and disable ───────────────────────────────────────────────────

    #[test]
    fn enable_disable_round_trip() {
        let (engine, path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED);
        // reserve
        handle_set_rcb_field(&engine, &path, RcbField::Resv, RcbWriteValue::Bool(true), 5).unwrap();
        // enable
        let res = handle_set_rcb_field(
            &engine,
            &path,
            RcbField::RptEna,
            RcbWriteValue::Bool(true),
            5,
        );
        assert_eq!(res, Ok(()));

        let eng = engine.lock().unwrap();
        let rc_arc = eng.get_rcb(&path).unwrap();
        drop(eng);
        {
            let rc = rc_arc.lock().unwrap();
            let state = rc.state.lock().unwrap();
            assert!(state.rpt_ena, "rpt_ena must be set after enabling");
            assert_eq!(state.sq_num, 0, "SqNum must be reset to 0 on enable");
        }

        // disable
        let res2 = handle_set_rcb_field(
            &engine,
            &path,
            RcbField::RptEna,
            RcbWriteValue::Bool(false),
            5,
        );
        assert_eq!(res2, Ok(()));

        let eng2 = engine.lock().unwrap();
        let rc_arc2 = eng2.get_rcb(&path).unwrap();
        drop(eng2);
        let rc2 = rc_arc2.lock().unwrap();
        let state2 = rc2.state.lock().unwrap();
        assert!(!state2.rpt_ena, "rpt_ena must be clear after disabling");
        assert!(state2.resv, "disabling keeps the reservation");
        assert_eq!(state2.client_conn_id, Some(5));
    }

    fn urcb_resv(engine: &Arc<Mutex<ReportingEngine>>, path: &str) -> (bool, Option<ConnectionId>) {
        let rc_arc = engine.lock().unwrap().get_rcb(path).unwrap();
        let rc = rc_arc.lock().unwrap();
        let state = rc.state.lock().unwrap();
        (state.resv, state.client_conn_id)
    }

    /// Disabling a URCB keeps it reserved for the client that holds it: the
    /// holder may still configure it and another client is still refused.
    #[test]
    fn urcb_disable_keeps_the_reservation() {
        let (engine, path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED);
        let set = |field: RcbField, value: RcbWriteValue, conn_id: ConnectionId| {
            handle_set_rcb_field(&engine, &path, field, value, conn_id)
        };
        set(RcbField::Resv, RcbWriteValue::Bool(true), 1).unwrap();
        set(RcbField::RptEna, RcbWriteValue::Bool(true), 1).unwrap();
        set(RcbField::RptEna, RcbWriteValue::Bool(false), 1).unwrap();
        assert_eq!(urcb_resv(&engine, &path), (true, Some(1)));

        assert_eq!(
            set(RcbField::BufTm, RcbWriteValue::Unsigned(250), 1),
            Ok(())
        );
        assert_eq!(
            set(RcbField::Resv, RcbWriteValue::Bool(true), 2),
            Err(DataAccessError::TemporarilyUnavailable)
        );
        assert_eq!(
            set(RcbField::IntgPd, RcbWriteValue::Unsigned(1000), 2),
            Err(DataAccessError::ObjectAccessDenied)
        );
        assert_eq!(urcb_resv(&engine, &path), (true, Some(1)));

        // The holder releases it with Resv = false.
        set(RcbField::Resv, RcbWriteValue::Bool(false), 1).unwrap();
        assert_eq!(urcb_resv(&engine, &path), (false, None));
    }

    /// RptEna = TRUE on an unreserved URCB reserves it for the writer, which
    /// another client then cannot take or write.
    #[test]
    fn urcb_rpt_ena_true_reserves_an_unreserved_urcb() {
        let (engine, path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED);
        let set = |field: RcbField, value: RcbWriteValue, conn_id: ConnectionId| {
            handle_set_rcb_field(&engine, &path, field, value, conn_id)
        };
        assert_eq!(set(RcbField::RptEna, RcbWriteValue::Bool(true), 1), Ok(()));
        assert_eq!(urcb_resv(&engine, &path), (true, Some(1)));
        assert_eq!(
            set(RcbField::RptEna, RcbWriteValue::Bool(true), 2),
            Err(DataAccessError::ObjectAccessDenied)
        );
        assert_eq!(
            set(RcbField::Resv, RcbWriteValue::Bool(true), 2),
            Err(DataAccessError::TemporarilyUnavailable)
        );
        assert_eq!(set(RcbField::RptEna, RcbWriteValue::Bool(false), 1), Ok(()));
        assert_eq!(urcb_resv(&engine, &path), (true, Some(1)));
    }

    /// Only RptEna = TRUE reserves implicitly: RptEna = FALSE and every other
    /// attribute are still refused on an unreserved URCB, and an enable that
    /// fails leaves the URCB unreserved.
    #[test]
    fn urcb_without_resv_only_an_enable_reserves() {
        let (engine, path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED);
        for (field, value) in [
            (RcbField::RptEna, RcbWriteValue::Bool(false)),
            (RcbField::BufTm, RcbWriteValue::Unsigned(250)),
            (RcbField::Gi, RcbWriteValue::Bool(true)),
        ] {
            assert_eq!(
                handle_set_rcb_field(&engine, &path, field, value, 1),
                Err(DataAccessError::ObjectAccessDenied)
            );
        }
        assert_eq!(urcb_resv(&engine, &path), (false, None));

        {
            let rc_arc = engine.lock().unwrap().get_rcb(&path).unwrap();
            let rc = rc_arc.lock().unwrap();
            rc.state.lock().unwrap().dat_set = String::new();
        }
        assert_eq!(
            handle_set_rcb_field(
                &engine,
                &path,
                RcbField::RptEna,
                RcbWriteValue::Bool(true),
                1
            ),
            Err(DataAccessError::TemporarilyUnavailable)
        );
        assert_eq!(urcb_resv(&engine, &path), (false, None));
    }

    /// The end of the association releases a disabled URCB as well.
    #[test]
    fn urcb_reservation_ends_with_the_association() {
        let (engine, path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED);
        handle_set_rcb_field(&engine, &path, RcbField::Resv, RcbWriteValue::Bool(true), 1).unwrap();
        engine.lock().unwrap().on_connection_dropped(1);
        assert_eq!(urcb_resv(&engine, &path), (false, None));
    }

    #[test]
    fn enable_with_empty_dataset_denied() {
        // Enabling with an empty DatSet is refused with TemporarilyUnavailable.
        use super::super::engine::ReportingEngine;

        let mut engine = ReportingEngine::new(Arc::new(super::super::engine::NullReportSink));
        let rcb = Rcb::new("urcb01", "").with_trg_ops(TriggerOptions::DATA_CHANGED);
        let path = "IED1LD0/GGIO1$RP$urcb01".to_string();
        let rc = super::super::rcb::ReportControl::new(&path, rcb);
        let ds = Dataset::new(""); // what matters is that the dat_set name is empty
        engine.register_rcb(rc, ds).unwrap();
        // Make sure dat_set really is empty.
        {
            let eng = engine.get_rcb(&path).unwrap();
            let rc = eng.lock().unwrap();
            let mut s = rc.state.lock().unwrap();
            s.dat_set = String::new(); // explicitly empty
        }

        let eng_arc = Arc::new(Mutex::new(engine));
        // reserve
        handle_set_rcb_field(
            &eng_arc,
            &path,
            RcbField::Resv,
            RcbWriteValue::Bool(true),
            1,
        )
        .unwrap();
        // Enabling must fail.
        let res = handle_set_rcb_field(
            &eng_arc,
            &path,
            RcbField::RptEna,
            RcbWriteValue::Bool(true),
            1,
        );
        assert_eq!(res, Err(DataAccessError::TemporarilyUnavailable));
    }

    // ── GI = true is silently ignored unless its conditions hold ─────────────

    #[test]
    fn gi_true_without_gi_trg_ops_silently_ignored() {
        // trgOps without GI: the write is accepted and ignored.
        let (engine, path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED); // no GI
        handle_set_rcb_field(&engine, &path, RcbField::Resv, RcbWriteValue::Bool(true), 1).unwrap();
        handle_set_rcb_field(
            &engine,
            &path,
            RcbField::RptEna,
            RcbWriteValue::Bool(true),
            1,
        )
        .unwrap();

        let res = handle_set_rcb_field(&engine, &path, RcbField::Gi, RcbWriteValue::Bool(true), 1);
        assert_eq!(res, Ok(()), "GI=true without GI in trgOps must be ignored");

        let eng = engine.lock().unwrap();
        let rc_arc = eng.get_rcb(&path).unwrap();
        drop(eng);
        let rc = rc_arc.lock().unwrap();
        let state = rc.state.lock().unwrap();
        assert!(!state.gi, "the gi flag must not be set");
    }

    #[test]
    fn gi_true_sets_gi_flag_when_trg_ops_contains_gi() {
        let (engine, path) =
            make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED | TriggerOptions::GI);
        handle_set_rcb_field(&engine, &path, RcbField::Resv, RcbWriteValue::Bool(true), 1).unwrap();
        handle_set_rcb_field(
            &engine,
            &path,
            RcbField::RptEna,
            RcbWriteValue::Bool(true),
            1,
        )
        .unwrap();

        let res = handle_set_rcb_field(&engine, &path, RcbField::Gi, RcbWriteValue::Bool(true), 1);
        assert_eq!(res, Ok(()));

        let eng = engine.lock().unwrap();
        let rc_arc = eng.get_rcb(&path).unwrap();
        drop(eng);
        let rc = rc_arc.lock().unwrap();
        let state = rc.state.lock().unwrap();
        assert!(state.gi, "the gi flag must be set");
    }

    // ── Changing DatSet increments ConfRev ───────────────────────────────────

    #[test]
    fn dat_set_change_increments_conf_rev() {
        let (engine, path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED);
        install_registry(&engine, &[("IED1LD0", "GGIO1$ds2", DS2_MEMBER)]);
        handle_set_rcb_field(&engine, &path, RcbField::Resv, RcbWriteValue::Bool(true), 1).unwrap();

        let initial_conf_rev = {
            let eng = engine.lock().unwrap();
            let rc_arc = eng.get_rcb(&path).unwrap();
            drop(eng);
            let rc = rc_arc.lock().unwrap();
            let s = rc.state.lock().unwrap();
            s.conf_rev
        };

        handle_set_rcb_field(
            &engine,
            &path,
            RcbField::DatSet,
            RcbWriteValue::VisibleString("GGIO1$ds2".to_string()),
            1,
        )
        .unwrap();

        let eng = engine.lock().unwrap();
        let rc_arc = eng.get_rcb(&path).unwrap();
        drop(eng);
        let rc = rc_arc.lock().unwrap();
        let state = rc.state.lock().unwrap();
        assert_eq!(
            state.conf_rev,
            initial_conf_rev + 1,
            "ConfRev must increase when DatSet changes"
        );
    }

    // ── GetURCBValues ─────────────────────────────────────────────────────────

    #[test]
    fn get_rpt_id_returns_visible_string() {
        use iec61850_mms::mms::pdu::common::{AccessResult, MmsData};

        let (engine, path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED);
        let result = handle_get_rcb_field(&engine, &path, RcbField::RptId);
        match result {
            Some(AccessResult::Success(MmsData::VisibleString(_))) => {}
            other => panic!("RptID must read back as a VisibleString, got {:?}", other),
        }
    }

    #[test]
    fn get_rpt_ena_returns_false_initially() {
        use iec61850_mms::mms::pdu::common::{AccessResult, MmsData};

        let (engine, path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED);
        let result = handle_get_rcb_field(&engine, &path, RcbField::RptEna);
        assert_eq!(
            result,
            Some(AccessResult::Success(MmsData::Boolean(false))),
            "RptEna must start out false"
        );
    }

    #[test]
    fn get_conf_rev_returns_unsigned() {
        use iec61850_mms::mms::pdu::common::{AccessResult, MmsData};

        let (engine, path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED);
        let result = handle_get_rcb_field(&engine, &path, RcbField::ConfRev);
        match result {
            Some(AccessResult::Success(MmsData::Unsigned(_))) => {}
            other => panic!("ConfRev must read back as an Unsigned, got {:?}", other),
        }
    }

    #[test]
    fn get_sq_num_returns_zero_initially() {
        use iec61850_mms::mms::pdu::common::{AccessResult, MmsData};

        let (engine, path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED);
        let result = handle_get_rcb_field(&engine, &path, RcbField::SqNum);
        assert_eq!(
            result,
            Some(AccessResult::Success(MmsData::Unsigned(0))),
            "SqNum must start at 0"
        );
    }

    #[test]
    fn get_unknown_field_returns_none() {
        let (engine, path) = make_engine_with_rcb("urcb01", TriggerOptions::DATA_CHANGED);
        let result = handle_get_rcb_field(
            &engine,
            &path,
            RcbField::Unknown("NonExistentField".to_string()),
        );
        assert!(result.is_none(), "an unknown field must read back as None");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // BRCB field access tests
    // ─────────────────────────────────────────────────────────────────────────

    fn make_engine_with_brcb(
        rcb_name: &str,
        trg_ops: TriggerOptions,
    ) -> (Arc<Mutex<super::super::engine::ReportingEngine>>, String) {
        use super::super::brcb::{Brcb, BufferedReportControl};
        use super::super::engine::ReportingEngine;

        let mut engine = ReportingEngine::new(Arc::new(super::super::engine::NullReportSink));
        let brcb = Brcb::new(rcb_name, "MMXU1$ds1")
            .with_trg_ops(trg_ops)
            .with_opt_flds(OptFlds::SEQ_NUM | OptFlds::BUFFER_OVERFLOW | OptFlds::ENTRY_ID)
            .with_buf_tm_ms(0)
            .with_intg_pd_ms(0);
        let path = format!("IED1LD0/MMXU1$BR$brcb{}", rcb_name);
        let brc = BufferedReportControl::new(&path, brcb);
        engine.register_brcb(brc).unwrap();
        (Arc::new(Mutex::new(engine)), path)
    }

    /// A BRCB accepts RptEna = true while DatSet is not empty.
    #[test]
    fn brcb_set_rpt_ena_true_with_dataset_succeeds() {
        let (engine, path) = make_engine_with_brcb("01", TriggerOptions::DATA_CHANGED);
        let res = handle_set_brcb_field(
            &engine,
            &path,
            RcbField::RptEna,
            RcbWriteValue::Bool(true),
            1,
        );
        assert_eq!(res, Some(Ok(())));

        let eng = engine.lock().unwrap();
        let brcb = eng.get_brcb(&path).unwrap();
        drop(eng);
        let s = brcb.state.lock().unwrap();
        assert!(s.rpt_ena);
    }

    /// A BRCB refuses writes to ConfRev and SqNum.
    #[test]
    fn brcb_set_conf_rev_denied() {
        let (engine, path) = make_engine_with_brcb("02", TriggerOptions::DATA_CHANGED);
        let res = handle_set_brcb_field(
            &engine,
            &path,
            RcbField::ConfRev,
            RcbWriteValue::Unsigned(99),
            1,
        );
        assert_eq!(res, Some(Err(DataAccessError::ObjectAccessDenied)));
    }

    #[test]
    fn brcb_set_sq_num_denied() {
        let (engine, path) = make_engine_with_brcb("03", TriggerOptions::DATA_CHANGED);
        let res = handle_set_brcb_field(
            &engine,
            &path,
            RcbField::SqNum,
            RcbWriteValue::Unsigned(5),
            1,
        );
        assert_eq!(res, Some(Err(DataAccessError::ObjectAccessDenied)));
    }

    /// A BRCB refuses writes to Owner.
    #[test]
    fn brcb_set_owner_denied() {
        let (engine, path) = make_engine_with_brcb("04", TriggerOptions::DATA_CHANGED);
        let res = handle_set_brcb_field(
            &engine,
            &path,
            RcbField::Owner,
            RcbWriteValue::OctetString(vec![127, 0, 0, 1]),
            1,
        );
        assert_eq!(res, Some(Err(DataAccessError::ObjectAccessDenied)));
    }

    /// Writing DatSet on a BRCB increments ConfRev and purges the buffer.
    #[test]
    fn brcb_set_dat_set_increments_conf_rev() {
        let (engine, path) = make_engine_with_brcb("05", TriggerOptions::DATA_CHANGED);
        install_registry(&engine, &[("IED1LD0", "MMXU1$ds2", DS2_MEMBER)]);
        let initial = {
            let eng = engine.lock().unwrap();
            let b = eng.get_brcb(&path).unwrap();
            drop(eng);
            let v = b.state.lock().unwrap().conf_rev;
            v
        };
        let res = handle_set_brcb_field(
            &engine,
            &path,
            RcbField::DatSet,
            RcbWriteValue::VisibleString("MMXU1$ds2".to_string()),
            1,
        );
        assert_eq!(res, Some(Ok(())));
        let after = {
            let eng = engine.lock().unwrap();
            let b = eng.get_brcb(&path).unwrap();
            drop(eng);
            let v = b.state.lock().unwrap().conf_rev;
            v
        };
        assert!(after > initial, "changing DatSet must increase ConfRev");
    }

    fn brcb_conf_rev_and_len(engine: &Arc<Mutex<ReportingEngine>>, path: &str) -> (u32, usize) {
        let brcb = engine.lock().unwrap().get_brcb(path).unwrap();
        let conf_rev = brcb.state.lock().unwrap().conf_rev;
        let len = brcb.lock_buffer().unwrap().len();
        (conf_rev, len)
    }

    /// OptFlds changes neither ConfRev nor the buffer; BufTm, TrgOps, IntgPd and
    /// RptID purge the buffer and leave ConfRev alone; only DatSet counts.
    #[test]
    fn brcb_conf_rev_and_purge_are_decided_per_field() {
        let (engine, path) = make_engine_with_brcb("24", TriggerOptions::DATA_CHANGED);
        install_registry(&engine, &[("IED1LD0", "MMXU1$ds2", DS2_MEMBER)]);
        let brcb = engine.lock().unwrap().get_brcb(&path).unwrap();
        let fill = || {
            brcb.enqueue_entry(1000, false, false, bytes::Bytes::from_static(b"x"))
                .unwrap();
        };
        let write = |field: RcbField, value: RcbWriteValue| {
            handle_set_brcb_field(&engine, &path, field, value, 1)
        };
        fill();
        let opt_flds = OptFlds::SEQ_NUM | OptFlds::DATA_SET;
        assert_eq!(
            write(
                RcbField::OptFlds,
                RcbWriteValue::BitString(opt_flds.to_ber_bit_string().to_vec())
            ),
            Some(Ok(()))
        );
        assert_eq!(brcb_conf_rev_and_len(&engine, &path), (1, 1));

        for (field, value) in [
            (RcbField::BufTm, RcbWriteValue::Unsigned(250)),
            (
                RcbField::TrgOps,
                RcbWriteValue::BitString(TriggerOptions::INTEGRITY.to_ber_bit_string().to_vec()),
            ),
            (RcbField::IntgPd, RcbWriteValue::Unsigned(5000)),
            (
                RcbField::RptId,
                RcbWriteValue::VisibleString("renamed".to_string()),
            ),
        ] {
            fill();
            let name = field.as_str().to_string();
            assert_eq!(write(field, value), Some(Ok(())), "{name}");
            assert_eq!(brcb_conf_rev_and_len(&engine, &path), (1, 0), "{name}");
        }

        fill();
        assert_eq!(
            write(
                RcbField::DatSet,
                RcbWriteValue::VisibleString("MMXU1$ds2".to_string())
            ),
            Some(Ok(()))
        );
        assert_eq!(brcb_conf_rev_and_len(&engine, &path), (2, 0));
    }

    /// Writing BufTm on a BRCB purges the buffer.
    #[test]
    fn brcb_set_buf_tm_changes_state() {
        let (engine, path) = make_engine_with_brcb("06", TriggerOptions::DATA_CHANGED);
        let res = handle_set_brcb_field(
            &engine,
            &path,
            RcbField::BufTm,
            RcbWriteValue::Unsigned(500),
            1,
        );
        assert_eq!(res, Some(Ok(())));
        let eng = engine.lock().unwrap();
        let brcb = eng.get_brcb(&path).unwrap();
        drop(eng);
        let s = brcb.state.lock().unwrap();
        assert_eq!(s.buf_tm_ms, 500);
    }

    /// Writing IntgPd on a BRCB.
    #[test]
    fn brcb_set_intg_pd_changes_state() {
        let (engine, path) = make_engine_with_brcb("07", TriggerOptions::DATA_CHANGED);
        let res = handle_set_brcb_field(
            &engine,
            &path,
            RcbField::IntgPd,
            RcbWriteValue::Unsigned(1000),
            1,
        );
        assert_eq!(res, Some(Ok(())));
        let eng = engine.lock().unwrap();
        let brcb = eng.get_brcb(&path).unwrap();
        drop(eng);
        let s = brcb.state.lock().unwrap();
        assert_eq!(s.intg_pd_ms, 1000);
    }

    /// A BRCB sets the gi flag when trgOps includes GI and RptEna is true.
    #[test]
    fn brcb_set_gi_true_with_trg_ops_gi_sets_flag() {
        let (engine, path) =
            make_engine_with_brcb("08", TriggerOptions::DATA_CHANGED | TriggerOptions::GI);
        // enable first
        handle_set_brcb_field(
            &engine,
            &path,
            RcbField::RptEna,
            RcbWriteValue::Bool(true),
            1,
        )
        .unwrap()
        .unwrap();
        // then request general interrogation
        let res = handle_set_brcb_field(&engine, &path, RcbField::Gi, RcbWriteValue::Bool(true), 1);
        assert_eq!(res, Some(Ok(())));
        let eng = engine.lock().unwrap();
        let brcb = eng.get_brcb(&path).unwrap();
        drop(eng);
        let s = brcb.state.lock().unwrap();
        assert!(s.gi);
    }

    /// A BRCB ignores GI = true when trgOps does not include GI.
    #[test]
    fn brcb_set_gi_true_without_trg_ops_gi_silently_ignored() {
        let (engine, path) = make_engine_with_brcb("09", TriggerOptions::DATA_CHANGED);
        handle_set_brcb_field(
            &engine,
            &path,
            RcbField::RptEna,
            RcbWriteValue::Bool(true),
            1,
        )
        .unwrap()
        .unwrap();
        let res = handle_set_brcb_field(&engine, &path, RcbField::Gi, RcbWriteValue::Bool(true), 1);
        assert_eq!(res, Some(Ok(())));
        let eng = engine.lock().unwrap();
        let brcb = eng.get_brcb(&path).unwrap();
        drop(eng);
        let s = brcb.state.lock().unwrap();
        assert!(!s.gi, "the gi flag must stay clear when trgOps has no GI");
    }

    /// Writing PurgeBuf = true purges a BRCB buffer while RptEna is false.
    #[test]
    fn brcb_set_purge_buf_true_when_disabled_purges() {
        use bytes::Bytes;
        let (engine, path) = make_engine_with_brcb("10", TriggerOptions::DATA_CHANGED);
        // enqueue a few entries first
        {
            let eng = engine.lock().unwrap();
            let brcb = eng.get_brcb(&path).unwrap();
            drop(eng);
            brcb.enqueue_entry(1000, false, false, Bytes::from_static(b"x"))
                .unwrap();
            brcb.enqueue_entry(1001, false, false, Bytes::from_static(b"y"))
                .unwrap();
        }
        let res = handle_set_brcb_field(
            &engine,
            &path,
            RcbField::PurgeBuf,
            RcbWriteValue::Bool(true),
            1,
        );
        assert_eq!(res, Some(Ok(())));
        let eng = engine.lock().unwrap();
        let brcb = eng.get_brcb(&path).unwrap();
        drop(eng);
        let buf = brcb.lock_buffer().unwrap();
        assert_eq!(buf.len(), 0, "PurgeBuf=true must empty the buffer");
    }

    /// While a BRCB is enabled, EntryID and PurgeBuf writes are refused with
    /// TemporarilyUnavailable and change nothing; once it is disabled both are
    /// accepted again.
    #[test]
    fn brcb_entry_id_and_purge_buf_refused_while_enabled() {
        use super::super::brcb::TransmitAnchor;
        let (engine, path) = make_engine_with_brcb("25", TriggerOptions::DATA_CHANGED);
        let brcb = engine.lock().unwrap().get_brcb(&path).unwrap();
        brcb.enqueue_entry(1000, false, false, bytes::Bytes::from_static(b"x"))
            .unwrap();
        let write = |field: RcbField, value: RcbWriteValue| {
            handle_set_brcb_field(&engine, &path, field, value, 1)
        };
        assert_eq!(
            write(RcbField::RptEna, RcbWriteValue::Bool(true)),
            Some(Ok(()))
        );
        let anchor = brcb_state(&engine, &path).2;
        for (field, value) in [
            (RcbField::EntryId, RcbWriteValue::OctetString(vec![0; 8])),
            (RcbField::PurgeBuf, RcbWriteValue::Bool(true)),
            (RcbField::PurgeBuf, RcbWriteValue::Bool(false)),
        ] {
            assert_eq!(
                write(field, value),
                Some(Err(DataAccessError::TemporarilyUnavailable))
            );
        }
        assert_eq!(brcb_state(&engine, &path).2, anchor);
        assert_eq!(brcb.lock_buffer().unwrap().len(), 1);

        assert_eq!(
            write(RcbField::RptEna, RcbWriteValue::Bool(false)),
            Some(Ok(()))
        );
        assert_eq!(
            write(RcbField::EntryId, RcbWriteValue::OctetString(vec![0; 8])),
            Some(Ok(()))
        );
        assert_eq!(brcb_state(&engine, &path).2, TransmitAnchor::FromHead);
        assert_eq!(
            write(RcbField::PurgeBuf, RcbWriteValue::Bool(true)),
            Some(Ok(()))
        );
        assert_eq!(brcb.lock_buffer().unwrap().len(), 0);
    }

    /// Every BRCB field reads back with the expected type.
    #[test]
    fn brcb_get_rpt_id_returns_visible_string() {
        use iec61850_mms::mms::pdu::common::{AccessResult, MmsData};
        let (engine, path) = make_engine_with_brcb("11", TriggerOptions::DATA_CHANGED);
        let r = handle_get_brcb_field(&engine, &path, RcbField::RptId);
        match r {
            Some(AccessResult::Success(MmsData::VisibleString(_))) => {}
            other => panic!("expected a VisibleString, got {:?}", other),
        }
    }

    #[test]
    fn brcb_get_buf_tm_returns_unsigned() {
        use iec61850_mms::mms::pdu::common::{AccessResult, MmsData};
        let (engine, path) = make_engine_with_brcb("12", TriggerOptions::DATA_CHANGED);
        let r = handle_get_brcb_field(&engine, &path, RcbField::BufTm);
        match r {
            Some(AccessResult::Success(MmsData::Unsigned(_))) => {}
            other => panic!("expected an Unsigned, got {:?}", other),
        }
    }

    #[test]
    fn brcb_get_resv_tms_returns_integer() {
        use iec61850_mms::mms::pdu::common::{AccessResult, MmsData};
        let (engine, path) = make_engine_with_brcb("13", TriggerOptions::DATA_CHANGED);
        let r = handle_get_brcb_field(&engine, &path, RcbField::ResvTms);
        match r {
            Some(AccessResult::Success(MmsData::Integer(0))) => {}
            other => panic!("ResvTms must start at Integer(0), got {:?}", other),
        }
    }

    #[test]
    fn brcb_get_time_of_entry_returns_binary_time() {
        use iec61850_mms::mms::pdu::common::{AccessResult, MmsData};
        let (engine, path) = make_engine_with_brcb("14", TriggerOptions::DATA_CHANGED);
        let r = handle_get_brcb_field(&engine, &path, RcbField::TimeOfEntry);
        match r {
            Some(AccessResult::Success(MmsData::BinaryTime(b))) => {
                assert_eq!(b.len(), 6, "a BinaryTime must be 6 bytes");
            }
            other => panic!("expected a BinaryTime, got {:?}", other),
        }
    }

    /// While RptEna is true, EntryID and TimeofEntry expose the last entry sent,
    /// not a newer entry already in the buffer; while it is false, the newest
    /// entry in the buffer.
    #[test]
    fn brcb_get_entry_id_follows_rpt_ena() {
        use iec61850_mms::mms::pdu::common::{AccessResult, MmsData};
        let (engine, path) = make_engine_with_brcb("16", TriggerOptions::DATA_CHANGED);
        let brcb = engine.lock().unwrap().get_brcb(&path).unwrap();
        let (sent, _) = brcb
            .enqueue_entry(1_700_000_000_000, false, false, bytes::Bytes::new())
            .unwrap();
        let (newest, _) = brcb
            .enqueue_entry(1_700_000_000_500, false, false, bytes::Bytes::new())
            .unwrap();
        {
            let mut state = brcb.lock_state().unwrap();
            state.rpt_ena = true;
            state.last_sent_entry_id = sent;
            state.last_sent_time_of_entry_ms = 1_700_000_000_000;
        }
        let read = |field: RcbField| match handle_get_brcb_field(&engine, &path, field) {
            Some(AccessResult::Success(d)) => d,
            other => panic!("expected a value, got {other:?}"),
        };
        let time_of_entry = || RcbField::TimeOfEntry;

        assert_eq!(
            read(RcbField::EntryId),
            MmsData::OctetString(sent.0.to_vec())
        );
        assert_eq!(
            read(time_of_entry()),
            MmsData::BinaryTime(encode_binary_time6_bytes(1_700_000_000_000))
        );

        brcb.lock_state().unwrap().rpt_ena = false;
        assert_eq!(
            read(RcbField::EntryId),
            MmsData::OctetString(newest.0.to_vec())
        );
        assert_eq!(
            read(time_of_entry()),
            MmsData::BinaryTime(encode_binary_time6_bytes(1_700_000_000_500))
        );
    }

    /// A buffer backend that counts how often each read path is taken and, on
    /// every `newest_entry` call, stands for a buffer one entry newer than at the
    /// previous call, as if an entry had been enqueued in between.
    #[derive(Debug, Default)]
    struct CountingBuffer {
        iter_calls: Arc<std::sync::atomic::AtomicUsize>,
        newest_calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl CountingBuffer {
        fn entry(n: usize) -> Arc<super::super::buffer::ReportEntry> {
            let ms = 1_700_000_000_000 + n as u64;
            Arc::new(super::super::buffer::ReportEntry::new(
                EntryId::from_ms(ms),
                ms,
                false,
                false,
                bytes::Bytes::new(),
            ))
        }
    }

    impl super::super::buffer::ReportBufferBackend for CountingBuffer {
        fn push(&mut self, _entry: Arc<super::super::buffer::ReportEntry>) -> bool {
            false
        }
        fn find_entry(&self, _id: &EntryId) -> Option<Arc<super::super::buffer::ReportEntry>> {
            None
        }
        fn seek_to_after_entry_id(&self, _id: &EntryId) -> super::super::buffer::SeekResult {
            super::super::buffer::SeekResult::NotFound
        }
        fn purge(&mut self) -> usize {
            0
        }
        fn len(&self) -> usize {
            1
        }
        fn is_overflow(&self) -> bool {
            false
        }
        fn clear_overflow(&mut self) {}
        fn iter_entries(&self) -> Vec<Arc<super::super::buffer::ReportEntry>> {
            use std::sync::atomic::Ordering;
            let n = self.iter_calls.fetch_add(1, Ordering::SeqCst)
                + self.newest_calls.load(Ordering::SeqCst);
            vec![Self::entry(n)]
        }
        fn newest_entry(&self) -> Option<Arc<super::super::buffer::ReportEntry>> {
            use std::sync::atomic::Ordering;
            let n = self.newest_calls.fetch_add(1, Ordering::SeqCst)
                + self.iter_calls.load(Ordering::SeqCst);
            Some(Self::entry(n))
        }
    }

    /// Registers a disabled BRCB backed by a `CountingBuffer` and returns the
    /// engine, the path, and the call counters for iter_entries and newest_entry.
    #[allow(clippy::type_complexity)]
    fn counting_brcb() -> (
        Arc<Mutex<ReportingEngine>>,
        String,
        Arc<std::sync::atomic::AtomicUsize>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use super::super::brcb::{Brcb, BufferedReportControl};
        let backend = CountingBuffer::default();
        let (iter_calls, newest_calls) = (backend.iter_calls.clone(), backend.newest_calls.clone());
        let mut engine = ReportingEngine::new(Arc::new(super::super::engine::NullReportSink));
        let path = "IED1LD0/MMXU1$BR$brcbCount".to_string();
        engine
            .register_brcb(BufferedReportControl::with_backend(
                &path,
                Brcb::new("brcbCount", "MMXU1$ds1"),
                Box::new(backend),
            ))
            .unwrap();
        (Arc::new(Mutex::new(engine)), path, iter_calls, newest_calls)
    }

    /// A disabled BRCB reads its exposed EntryID through `newest_entry`, without
    /// copying the buffer through `iter_entries`.
    #[test]
    fn exposed_entry_reads_only_the_newest_entry() {
        use iec61850_mms::mms::pdu::common::{AccessResult, MmsData};
        use std::sync::atomic::Ordering;
        let (engine, path, iter_calls, newest_calls) = counting_brcb();
        let r = handle_get_brcb_field(&engine, &path, RcbField::EntryId);
        assert_eq!(
            r,
            Some(AccessResult::Success(MmsData::OctetString(
                CountingBuffer::entry(0).entry_id.0.to_vec()
            )))
        );
        assert_eq!(iter_calls.load(Ordering::SeqCst), 0);
        assert_eq!(newest_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn binary_time6_bytes_use_the_1984_epoch() {
        use iec61850_mms::{epoch_ms_from_binary_time6, EPOCH_1984_MS};
        // 1984-01-03T00:00:01.000Z: day count 2, 1000 ms of day.
        let epoch_ms = EPOCH_1984_MS + 2 * 86_400_000 + 1_000;
        let bytes = encode_binary_time6_bytes(epoch_ms);
        assert_eq!(bytes, vec![0x00, 0x00, 0x03, 0xe8, 0x00, 0x02]);
        let field: [u8; 6] = bytes.try_into().expect("six byte binary time");
        assert_eq!(epoch_ms_from_binary_time6(field), epoch_ms);
    }

    #[test]
    fn brcb_get_owner_returns_octet_string_empty_initially() {
        use iec61850_mms::mms::pdu::common::{AccessResult, MmsData};
        let (engine, path) = make_engine_with_brcb("15", TriggerOptions::DATA_CHANGED);
        let r = handle_get_brcb_field(&engine, &path, RcbField::Owner);
        assert_eq!(r, Some(AccessResult::Success(MmsData::OctetString(vec![]))));
    }

    /// A BRCB has no Resv field, so it neither reads nor writes.
    #[test]
    fn brcb_resv_field_returns_none() {
        let (engine, path) = make_engine_with_brcb("16", TriggerOptions::DATA_CHANGED);
        assert!(handle_get_brcb_field(&engine, &path, RcbField::Resv).is_none());
        assert!(handle_set_brcb_field(
            &engine,
            &path,
            RcbField::Resv,
            RcbWriteValue::Bool(true),
            1
        )
        .is_none());
    }

    /// Writing a positive ResvTms reserves a BRCB for the writer; the timer starts
    /// only once its association ends.
    #[test]
    fn brcb_set_resv_tms_reserves_for_the_writer() {
        let (engine, path) = make_engine_with_brcb("17", TriggerOptions::DATA_CHANGED);
        let res = handle_set_brcb_field(
            &engine,
            &path,
            RcbField::ResvTms,
            RcbWriteValue::Unsigned(30),
            1,
        );
        assert_eq!(res, Some(Ok(())));
        let eng = engine.lock().unwrap();
        let brcb = eng.get_brcb(&path).unwrap();
        drop(eng);
        let s = brcb.state.lock().unwrap();
        assert!(matches!(
            s.resv_tms,
            super::super::brcb::ResvTmsState::WithTimeout(_)
        ));
        assert_eq!(s.client_conn_id, Some(1));
        assert!(s.reservation_timeout.is_none());
    }

    /// TimeOfEntry is never writable and is refused as read-only, like Owner.
    #[test]
    fn brcb_set_time_of_entry_denied() {
        let (engine, path) = make_engine_with_brcb("23", TriggerOptions::DATA_CHANGED);
        let res = handle_set_brcb_field(
            &engine,
            &path,
            RcbField::from_name("TimeofEntry"),
            RcbWriteValue::OctetString(vec![0; 6]),
            1,
        );
        assert_eq!(res, Some(Err(DataAccessError::ObjectAccessDenied)));
        assert_eq!(
            handle_set_brcb_field(
                &engine,
                &path,
                RcbField::from_name("TimeOfEntry"),
                RcbWriteValue::OctetString(vec![0; 6]),
                1,
            ),
            None,
            "only the MMS component name of IEC 61850-8-1 Table 72 is recognized"
        );
    }

    /// ResvTms takes an INTEGER or an UNSIGNED from 0 to 32767; any other value is
    /// refused as invalid and any other type as inconsistent.
    #[test]
    fn brcb_resv_tms_range_and_type_are_checked_by_the_field() {
        let (engine, path) = make_engine_with_brcb("22", TriggerOptions::DATA_CHANGED);
        let write = |value: RcbWriteValue| {
            handle_set_brcb_field(&engine, &path, RcbField::ResvTms, value, 1)
        };
        assert_eq!(write(RcbWriteValue::Integer(32_767)), Some(Ok(())));
        assert_eq!(write(RcbWriteValue::Unsigned(30)), Some(Ok(())));
        for value in [
            RcbWriteValue::Integer(-1),
            RcbWriteValue::Integer(32_768),
            RcbWriteValue::Unsigned(32_768),
        ] {
            assert_eq!(write(value), Some(Err(DataAccessError::ObjectValueInvalid)));
        }
        assert_eq!(
            write(RcbWriteValue::Bool(true)),
            Some(Err(DataAccessError::TypeInconsistent))
        );
        let brcb = engine.lock().unwrap().get_brcb(&path).unwrap();
        assert_eq!(brcb.state.lock().unwrap().resv_tms.to_wire(), 30);
        assert_eq!(
            handle_set_brcb_field(
                &engine,
                &path,
                RcbField::IntgPd,
                RcbWriteValue::Integer(100),
                1
            ),
            Some(Err(DataAccessError::TypeInconsistent))
        );
    }

    fn brcb_state(
        engine: &Arc<Mutex<ReportingEngine>>,
        path: &str,
    ) -> (
        Option<ConnectionId>,
        bool,
        super::super::brcb::TransmitAnchor,
    ) {
        let brcb = engine.lock().unwrap().get_brcb(path).unwrap();
        let s = brcb.state.lock().unwrap();
        (s.client_conn_id, s.rpt_ena, s.transmit_anchor.clone())
    }

    #[test]
    fn brcb_rpt_ena_for_connection_binds_the_writer() {
        use super::super::brcb::TransmitAnchor;
        let (engine, path) = make_engine_with_brcb("18", TriggerOptions::DATA_CHANGED);
        let res = handle_set_brcb_field(
            &engine,
            &path,
            RcbField::RptEna,
            RcbWriteValue::Bool(true),
            3,
        );
        assert_eq!(res, Some(Ok(())));
        assert_eq!(
            brcb_state(&engine, &path),
            (Some(3), true, TransmitAnchor::FromHead)
        );
    }

    #[test]
    fn brcb_rpt_ena_keeps_a_resynchronized_anchor() {
        use super::super::brcb::TransmitAnchor;
        let (engine, path) = make_engine_with_brcb("20", TriggerOptions::DATA_CHANGED);
        let res = handle_set_brcb_field(
            &engine,
            &path,
            RcbField::EntryId,
            RcbWriteValue::OctetString(vec![0; 8]),
            3,
        );
        assert_eq!(res, Some(Ok(())));
        {
            let brcb = engine.lock().unwrap().get_brcb(&path).unwrap();
            brcb.state.lock().unwrap().transmit_anchor =
                TransmitAnchor::AfterEntryId(super::super::buffer::EntryId::from_ms(7));
        }
        let res = handle_set_brcb_field(
            &engine,
            &path,
            RcbField::RptEna,
            RcbWriteValue::Bool(true),
            3,
        );
        assert_eq!(res, Some(Ok(())));
        assert_eq!(
            brcb_state(&engine, &path).2,
            TransmitAnchor::AfterEntryId(super::super::buffer::EntryId::from_ms(7))
        );
    }

    #[test]
    fn brcb_rpt_ena_from_another_connection_denied() {
        let (engine, path) = make_engine_with_brcb("21", TriggerOptions::DATA_CHANGED);
        let set = |value: bool, conn_id: ConnectionId| {
            handle_set_brcb_field(
                &engine,
                &path,
                RcbField::RptEna,
                RcbWriteValue::Bool(value),
                conn_id,
            )
        };
        assert_eq!(set(true, 3), Some(Ok(())));
        assert_eq!(set(true, 4), Some(Err(DataAccessError::ObjectAccessDenied)));
        assert_eq!(
            set(false, 4),
            Some(Err(DataAccessError::ObjectAccessDenied))
        );
        for (field, value) in [
            (RcbField::ResvTms, RcbWriteValue::Unsigned(30)),
            (RcbField::Gi, RcbWriteValue::Bool(true)),
            (RcbField::EntryId, RcbWriteValue::OctetString(vec![0; 8])),
        ] {
            assert_eq!(
                handle_set_brcb_field(&engine, &path, field, value, 4),
                Some(Err(DataAccessError::ObjectAccessDenied))
            );
        }
        assert_eq!(brcb_state(&engine, &path).0, Some(3));
        assert!(brcb_state(&engine, &path).1);

        assert_eq!(set(false, 3), Some(Ok(())));
        assert_eq!(set(true, 4), Some(Ok(())));
        assert_eq!(brcb_state(&engine, &path).0, Some(4));
    }

    // ── Integrity period of a control block enabled over MMS ────────────────

    const URCB_CONN: ConnectionId = 1;
    const BRCB_CONN: ConnectionId = 2;

    struct IntegrityFixture {
        engine: Arc<Mutex<ReportingEngine>>,
        sink: Arc<super::super::engine::CollectReportSink>,
        urcb: String,
        brcb: String,
    }

    /// A URCB and a BRCB over one data set, both with `trg_ops` and an IntgPd of
    /// `intg_pd_ms`, neither enabled.
    fn integrity_fixture(trg_ops: TriggerOptions, intg_pd_ms: u32) -> IntegrityFixture {
        use super::super::brcb::{Brcb, BufferedReportControl};
        let sink = Arc::new(super::super::engine::CollectReportSink::default());
        let mut engine = ReportingEngine::new(sink.clone());
        let value = Arc::new(RwLock::new(MmsValue::Boolean(false)));
        let data_set = || {
            let mut ds = Dataset::new("GGIO1$ds1");
            ds.push(DatasetEntry::new(
                "IED1LD0/GGIO1$ST$Ind1$stVal",
                value.clone(),
            ));
            ds
        };
        let urcb = "IED1LD0/GGIO1$RP$urcbIntg".to_string();
        let rcb = Rcb::new("urcbIntg", "GGIO1$ds1")
            .with_trg_ops(trg_ops)
            .with_opt_flds(OptFlds::SEQ_NUM | OptFlds::REASON)
            .with_intg_pd_ms(intg_pd_ms);
        engine
            .register_rcb(
                super::super::rcb::ReportControl::new(&urcb, rcb),
                data_set(),
            )
            .unwrap();
        let brcb = "IED1LD0/GGIO1$BR$brcbIntg".to_string();
        let brc = Brcb::new("brcbIntg", "GGIO1$ds1")
            .with_trg_ops(trg_ops)
            .with_intg_pd_ms(intg_pd_ms);
        engine
            .register_brcb_with_dataset(BufferedReportControl::new(&brcb, brc), data_set())
            .unwrap();
        IntegrityFixture {
            engine: Arc::new(Mutex::new(engine)),
            sink,
            urcb,
            brcb,
        }
    }

    impl IntegrityFixture {
        fn write_intg_pd(&self, intg_pd_ms: u32) {
            let urcb_res = handle_set_rcb_field(
                &self.engine,
                &self.urcb,
                RcbField::IntgPd,
                RcbWriteValue::Unsigned(intg_pd_ms),
                URCB_CONN,
            );
            assert_eq!(urcb_res, Ok(()));
            let brcb_res = handle_set_brcb_field(
                &self.engine,
                &self.brcb,
                RcbField::IntgPd,
                RcbWriteValue::Unsigned(intg_pd_ms),
                BRCB_CONN,
            );
            assert_eq!(brcb_res, Some(Ok(())));
        }

        fn reserve_urcb(&self) {
            let res = handle_set_rcb_field(
                &self.engine,
                &self.urcb,
                RcbField::Resv,
                RcbWriteValue::Bool(true),
                URCB_CONN,
            );
            assert_eq!(res, Ok(()));
        }

        /// Writes RptEna to both control blocks over MMS.
        fn set_rpt_ena(&self, on: bool) {
            let urcb_res = handle_set_rcb_field(
                &self.engine,
                &self.urcb,
                RcbField::RptEna,
                RcbWriteValue::Bool(on),
                URCB_CONN,
            );
            assert_eq!(urcb_res, Ok(()));
            let brcb_res = handle_set_brcb_field(
                &self.engine,
                &self.brcb,
                RcbField::RptEna,
                RcbWriteValue::Bool(on),
                BRCB_CONN,
            );
            assert_eq!(brcb_res, Some(Ok(())));
        }

        /// Enables both control blocks and returns the clock readings taken
        /// just before and just after.
        fn enable(&self) -> (Instant, Instant) {
            let before = Instant::now();
            self.set_rpt_ena(true);
            (before, Instant::now())
        }

        /// Ticks the engine at `now` and returns how many reports each control
        /// block sent, URCB first.
        fn tick(&self, now: Instant) -> (usize, usize) {
            let eng = self.engine.lock().unwrap();
            eng.tick_at(now, 1_000);
            eng.tick_brcb(now, 1_000);
            drop(eng);
            let pdus = std::mem::take(&mut *self.sink.pdus.lock().unwrap());
            let count = |conn| pdus.iter().filter(|(c, _)| *c == conn).count();
            (count(URCB_CONN), count(BRCB_CONN))
        }
    }

    #[test]
    fn integrity_reports_follow_the_period_of_a_block_enabled_over_mms() {
        let f = integrity_fixture(TriggerOptions::INTEGRITY, 100);
        let period = Duration::from_millis(100);
        f.reserve_urcb();
        let (before, after) = f.enable();

        assert_eq!(f.tick(before + period - Duration::from_millis(1)), (0, 0));
        assert_eq!(f.tick(after + period), (1, 1));
        assert_eq!(
            f.tick(after + period + period - Duration::from_millis(1)),
            (0, 0)
        );
        assert_eq!(f.tick(after + period + period), (1, 1));

        f.set_rpt_ena(false);
        assert_eq!(f.tick(after + period * 10), (0, 0));
    }

    #[test]
    fn integrity_period_restarts_with_the_intg_pd_in_force_when_enabled() {
        let f = integrity_fixture(TriggerOptions::INTEGRITY, 100);
        f.reserve_urcb();
        f.enable();
        f.set_rpt_ena(false);
        f.reserve_urcb();
        f.write_intg_pd(40);
        let (before, after) = f.enable();

        let new_period = Duration::from_millis(40);
        assert_eq!(
            f.tick(before + new_period - Duration::from_millis(1)),
            (0, 0)
        );
        assert_eq!(f.tick(after + new_period), (1, 1));
    }

    #[test]
    fn rewriting_rpt_ena_true_keeps_the_integrity_period() {
        let f = integrity_fixture(TriggerOptions::INTEGRITY, 100);
        let period = Duration::from_millis(100);
        f.reserve_urcb();
        let (_, after) = f.enable();
        // The rewrite happens strictly later than `after`, so a period restarted
        // by it would not yet be due at `after + period`.
        while Instant::now() <= after {
            std::hint::spin_loop();
        }
        f.set_rpt_ena(true);
        assert_eq!(f.tick(after + period), (1, 1));
    }

    #[test]
    fn no_integrity_report_without_the_trigger_option() {
        let f = integrity_fixture(TriggerOptions::DATA_CHANGED, 100);
        f.reserve_urcb();
        let (_, after) = f.enable();
        assert_eq!(f.tick(after + Duration::from_millis(1_000)), (0, 0));
    }

    #[test]
    fn no_integrity_report_with_a_zero_period() {
        let f = integrity_fixture(TriggerOptions::INTEGRITY, 0);
        f.reserve_urcb();
        let (_, after) = f.enable();
        assert_eq!(f.tick(after + Duration::from_millis(1_000)), (0, 0));
    }

    // ── BRCB reservation across associations ─────────────────────────────────

    const OWNER: ConnectionId = 11;
    const OTHER: ConnectionId = 12;
    const OWNER_AGAIN: ConnectionId = 13;
    const RESV_TMS_S: u32 = 30;

    /// A BRCB with three associations: `OWNER` and `OWNER_AGAIN` from one address,
    /// `OTHER` from another.
    fn reservation_fixture(
        brcb: super::super::brcb::Brcb,
    ) -> (Arc<Mutex<ReportingEngine>>, String) {
        use super::super::brcb::BufferedReportControl;
        let path = "IED1LD0/MMXU1$BR$brcbResv".to_string();
        let mut engine = ReportingEngine::new(Arc::new(super::super::engine::NullReportSink));
        engine
            .register_brcb(BufferedReportControl::new(&path, brcb))
            .unwrap();
        let owner_ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        engine.register_peer(OWNER, owner_ip);
        engine.register_peer(OWNER_AGAIN, owner_ip);
        engine.register_peer(OTHER, "10.0.0.2".parse().unwrap());
        (Arc::new(Mutex::new(engine)), path)
    }

    fn plain_brcb() -> super::super::brcb::Brcb {
        super::super::brcb::Brcb::new("brcbResv", "MMXU1$ds1")
    }

    fn write_brcb(
        engine: &Arc<Mutex<ReportingEngine>>,
        path: &str,
        conn_id: ConnectionId,
        field: &str,
        value: RcbWriteValue,
    ) -> Option<Result<(), DataAccessError>> {
        handle_set_brcb_field(engine, path, RcbField::from_name(field), value, conn_id)
    }

    fn reserve(engine: &Arc<Mutex<ReportingEngine>>, path: &str, conn_id: ConnectionId) {
        let res = write_brcb(
            engine,
            path,
            conn_id,
            "ResvTms",
            RcbWriteValue::Unsigned(RESV_TMS_S),
        );
        assert_eq!(res, Some(Ok(())));
    }

    const DENIED: Option<Result<(), DataAccessError>> =
        Some(Err(DataAccessError::ObjectAccessDenied));

    #[test]
    fn brcb_reserved_by_resv_tms_refuses_other_clients() {
        let (engine, path) = reservation_fixture(plain_brcb());
        reserve(&engine, &path, OWNER);

        let intg_pd = || RcbWriteValue::Unsigned(500);
        assert_eq!(
            write_brcb(&engine, &path, OTHER, "IntgPd", intg_pd()),
            DENIED
        );
        assert_eq!(
            write_brcb(&engine, &path, OTHER, "RptEna", RcbWriteValue::Bool(true)),
            DENIED
        );
        assert_eq!(
            write_brcb(&engine, &path, OTHER, "ResvTms", RcbWriteValue::Unsigned(0)),
            DENIED
        );
        assert_eq!(
            write_brcb(&engine, &path, OWNER, "IntgPd", intg_pd()),
            Some(Ok(()))
        );
        let brcb = engine.lock().unwrap().get_brcb(&path).unwrap();
        let s = brcb.state.lock().unwrap();
        assert_eq!(s.client_conn_id, Some(OWNER));
        assert_eq!(s.owner, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(
            s.reservation_timeout, None,
            "the timer waits for the association to end"
        );
    }

    #[test]
    fn brcb_reservation_is_held_for_its_owner_after_close() {
        let (engine, path) = reservation_fixture(plain_brcb());
        reserve(&engine, &path, OWNER);
        assert_eq!(
            write_brcb(&engine, &path, OWNER, "RptEna", RcbWriteValue::Bool(true)),
            Some(Ok(()))
        );
        let before = Instant::now();
        engine.lock().unwrap().on_connection_dropped(OWNER);
        let after = Instant::now();
        let resv = Duration::from_secs(u64::from(RESV_TMS_S));

        let brcb = engine.lock().unwrap().get_brcb(&path).unwrap();
        let deadline = brcb.state.lock().unwrap().reservation_timeout.unwrap();
        assert!(before + resv <= deadline && deadline <= after + resv);
        assert_eq!(
            engine
                .lock()
                .unwrap()
                .tick_brcb_reservations_at(before + resv - Duration::from_millis(1)),
            0
        );

        assert_eq!(
            write_brcb(&engine, &path, OTHER, "RptEna", RcbWriteValue::Bool(true)),
            DENIED
        );
        assert_eq!(
            write_brcb(
                &engine,
                &path,
                OWNER_AGAIN,
                "RptEna",
                RcbWriteValue::Bool(true)
            ),
            Some(Ok(()))
        );
        let s = brcb.state.lock().unwrap();
        assert_eq!(s.client_conn_id, Some(OWNER_AGAIN));
        assert!(s.rpt_ena);
        assert_eq!(s.reservation_timeout, None);
    }

    #[test]
    fn brcb_reservation_is_released_when_resv_tms_expires_after_close() {
        use super::super::brcb::ResvTmsState;
        let (engine, path) = reservation_fixture(plain_brcb());
        reserve(&engine, &path, OWNER);
        engine.lock().unwrap().on_connection_dropped(OWNER);
        let after = Instant::now();
        let resv = Duration::from_secs(u64::from(RESV_TMS_S));

        assert_eq!(
            engine
                .lock()
                .unwrap()
                .tick_brcb_reservations_at(after + resv),
            1
        );
        {
            let brcb = engine.lock().unwrap().get_brcb(&path).unwrap();
            let s = brcb.state.lock().unwrap();
            assert_eq!(s.resv_tms, ResvTmsState::NotReserved);
            assert_eq!(s.owner, None);
        }
        assert_eq!(
            write_brcb(&engine, &path, OTHER, "RptEna", RcbWriteValue::Bool(true)),
            Some(Ok(()))
        );
    }

    #[test]
    fn unreserved_brcb_accepts_any_client() {
        let (engine, path) = reservation_fixture(plain_brcb());
        for conn_id in [OWNER, OTHER] {
            assert_eq!(
                write_brcb(
                    &engine,
                    &path,
                    conn_id,
                    "IntgPd",
                    RcbWriteValue::Unsigned(500)
                ),
                Some(Ok(()))
            );
        }
        engine.lock().unwrap().on_connection_dropped(OWNER);
        let brcb = engine.lock().unwrap().get_brcb(&path).unwrap();
        assert_eq!(brcb.state.lock().unwrap().reservation_timeout, None);
    }

    #[test]
    fn resv_tms_zero_keeps_an_enabled_brcb_bound() {
        let (engine, path) = reservation_fixture(plain_brcb());
        reserve(&engine, &path, OWNER);
        assert_eq!(
            write_brcb(&engine, &path, OWNER, "RptEna", RcbWriteValue::Bool(true)),
            Some(Ok(()))
        );
        assert_eq!(
            write_brcb(&engine, &path, OWNER, "ResvTms", RcbWriteValue::Unsigned(0)),
            Some(Ok(()))
        );
        let brcb = engine.lock().unwrap().get_brcb(&path).unwrap();
        assert_eq!(brcb.state.lock().unwrap().client_conn_id, Some(OWNER));
    }

    #[test]
    fn preconfigured_brcb_refuses_other_addresses() {
        let brcb = plain_brcb().with_preconfigured_owner("10.0.0.1".parse().unwrap());
        let (engine, path) = reservation_fixture(brcb);
        let intg_pd = || RcbWriteValue::Unsigned(500);
        assert_eq!(
            write_brcb(&engine, &path, OTHER, "IntgPd", intg_pd()),
            DENIED
        );
        assert_eq!(
            write_brcb(&engine, &path, OWNER, "IntgPd", intg_pd()),
            Some(Ok(()))
        );
    }

    fn other_ip() -> Option<std::net::IpAddr> {
        Some("10.0.0.2".parse().unwrap())
    }

    #[test]
    fn resv_tms_rechecks_a_claim_overtaken_by_another_reservation() {
        let (engine, path) = reservation_fixture(plain_brcb());
        let brcb = engine.lock().unwrap().get_brcb(&path).unwrap();
        // OTHER passes the claim while the BRCB is free; OWNER then reserves it
        // before OTHER's ResvTms write takes the state lock.
        assert_eq!(claim_brcb(&brcb, OTHER, other_ip()), Ok(()));
        reserve(&engine, &path, OWNER);
        assert_eq!(
            set_brcb_resv_tms(&brcb, RcbWriteValue::Unsigned(30), OTHER, other_ip()),
            DENIED
        );
        let s = brcb.state.lock().unwrap();
        assert_eq!(s.client_conn_id, Some(OWNER));
        assert_eq!(s.owner, Some("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn rpt_ena_rechecks_a_claim_overtaken_by_another_reservation() {
        let (engine, path) = reservation_fixture(plain_brcb());
        let brcb = engine.lock().unwrap().get_brcb(&path).unwrap();
        assert_eq!(claim_brcb(&brcb, OTHER, other_ip()), Ok(()));
        reserve(&engine, &path, OWNER);
        assert_eq!(
            set_brcb_rpt_ena(&brcb, RcbWriteValue::Bool(true), OTHER, other_ip()),
            Err(DataAccessError::ObjectAccessDenied)
        );
        let s = brcb.state.lock().unwrap();
        assert_eq!(s.client_conn_id, Some(OWNER));
        assert!(!s.rpt_ena);
    }

    #[test]
    fn resv_tms_zero_on_a_disabled_brcb_forgets_its_owner() {
        let (engine, path) = reservation_fixture(plain_brcb());
        reserve(&engine, &path, OWNER);
        assert_eq!(
            write_brcb(&engine, &path, OWNER, "ResvTms", RcbWriteValue::Unsigned(0)),
            Some(Ok(()))
        );
        let brcb = engine.lock().unwrap().get_brcb(&path).unwrap();
        let s = brcb.state.lock().unwrap();
        assert_eq!(s.client_conn_id, None);
        assert_eq!(s.owner, None);
    }
}
