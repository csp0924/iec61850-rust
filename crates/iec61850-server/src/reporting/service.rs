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
//! | RptEna = true | reserved, and the writer owns the reservation |
//! | RptEna = false | enabled, and the writer owns the reservation |
//! | GI = true | enabled, the writer owns the reservation, and trgOps includes GI |
//! | ConfRev, SqNum, Owner, TimeOfEntry | never writable; answered with ObjectAccessDenied |

use super::engine::ReportingEngine;
use crate::connection::ConnectionId;
use iec61850_mms::mms::pdu::common::DataAccessError;
use std::sync::{Arc, Mutex};

/// Identifies one report control block field.
///
/// Corresponds to the MMS variableName `<LN>$RP$<rcb>$<field>`.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// A field name this server does not recognize.
    Unknown(String),
}

impl RcbField {
    /// Parses an MMS field name.
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
            other => Self::Unknown(other.to_string()),
        }
    }

    /// Returns the MMS field name.
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
            Self::Unknown(s) => s.as_str(),
        }
    }
}

/// One field value to write, already decoded by the caller.
#[derive(Debug, Clone)]
pub enum RcbWriteValue {
    /// A BOOLEAN value.
    Bool(bool),
    /// An UNSIGNED value.
    Unsigned(u32),
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
/// `ObjectAccessDenied`, a wrong value type gives `TypeInconsistent`, an enabled
/// control block gives `TemporarilyUnavailable`, and a poisoned mutex gives
/// `HardwareFault`.
pub fn handle_set_rcb_field(
    engine: &Arc<Mutex<ReportingEngine>>,
    mms_path: &str,
    field: RcbField,
    value: RcbWriteValue,
    conn_id: ConnectionId,
) -> Result<(), DataAccessError> {
    let eng = engine.lock().map_err(|_| DataAccessError::HardwareFault)?;

    let rc_arc = eng
        .get_rcb(mms_path)
        .ok_or(DataAccessError::ObjectNonExistent)?;
    drop(eng); // release the engine lock before taking the control block lock

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

    // Edition 2.1: a client that does not hold the reservation may not write any
    // other field, per the RCB write conditions of IEC 61850-7-2.
    if !state.resv || state.client_conn_id != Some(conn_id) {
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
            state.rpt_ena = true;
            state.sq_num = 0;
        } else {
            // Disabling clears the pending report and the reservation.
            if !state.rpt_ena {
                return Ok(());
            }
            state.rpt_ena = false;
            state.pending = None;
            state.triggered = false;
            state.report_due = None;
            // A lost or released control block always clears Resv.
            state.resv = false;
            state.client_conn_id = None;
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
        // EntryID exists only on a BRCB; a client that addressed $RP$ instead of
        // $BR$ gets ObjectNonExistent from the caller.
        RcbField::EntryId => return None,
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

/// Applies one SetBRCBValues field write.
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
/// - DatSet, TrgOps, IntgPd, BufTm, and RptID are refused with
///   TemporarilyUnavailable while RptEna is true
/// - an accepted change to one of those fields purges the report buffer, through
///   `BufferedReportControl::set_config_field`
pub fn handle_set_brcb_field(
    engine: &Arc<Mutex<ReportingEngine>>,
    mms_path: &str,
    field: RcbField,
    value: RcbWriteValue,
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
    let brcb = {
        let eng = engine
            .lock()
            .map_err(|_| DataAccessError::HardwareFault)
            .ok()?;
        match eng.get_brcb(mms_path) {
            Some(b) => b,
            None => return Some(Err(DataAccessError::ObjectNonExistent)),
        }
    };

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
                Err(_) => Some(Err(DataAccessError::HardwareFault)),
            }
        }

        // PurgeBuf.
        RcbField::Unknown(ref n) if n == "PurgeBuf" => set_brcb_purge_buf(&brcb, value),

        // RptEna: enable or disable.
        RcbField::RptEna => set_brcb_rpt_ena(&brcb, value),

        // GI: trigger a general interrogation.
        RcbField::Gi => set_brcb_gi(&brcb, value),

        // Configuration fields; each is refused with TemporarilyUnavailable while
        // RptEna is true.
        RcbField::RptId => set_brcb_config_string(&brcb, value, "RptID"),
        RcbField::DatSet => set_brcb_config_string(&brcb, value, "DatSet"),
        RcbField::OptFlds => set_brcb_opt_flds(&brcb, value),
        RcbField::BufTm => set_brcb_unsigned32(&brcb, value, "BufTm"),
        RcbField::TrgOps => set_brcb_trg_ops(&brcb, value),
        RcbField::IntgPd => set_brcb_unsigned32(&brcb, value, "IntgPd"),

        // ResvTms, an INT16 introduced in Edition 2.
        RcbField::Unknown(ref n) if n == "ResvTms" => set_brcb_resv_tms(&brcb, value),

        // Owner is never writable, per IEC 61850-7-2.
        RcbField::Owner => Some(Err(DataAccessError::ObjectAccessDenied)),

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

    // Most fields come from the runtime state.
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
        // EntryID.
        RcbField::EntryId => {
            // The state lock is already held here, so the field is read directly.
            MmsData::OctetString(state_guard.last_committed_entry_id.0.to_vec())
        }
        RcbField::Unknown(ref n) if n == "PurgeBuf" => {
            // PurgeBuf is a trigger flag: it reads back false once the purge has run.
            MmsData::Boolean(state_guard.purge_buf_pending)
        }
        RcbField::Unknown(ref n) if n == "TimeofEntry" => {
            // BinaryTime6 wire format; the stored value is host-order milliseconds.
            let ms = state_guard.last_sent_time_of_entry_ms;
            MmsData::BinaryTime(encode_binary_time6_bytes(ms))
        }
        RcbField::Unknown(ref n) if n == "ResvTms" => {
            // INT16 wire format.
            MmsData::Integer(state_guard.resv_tms.to_wire() as i64)
        }
        RcbField::Unknown(_) => return None,
    };

    Some(AccessResult::Success(data))
}

// ─────────────────────────────────────────────────────────────────────────────
// BRCB field write helpers
// ─────────────────────────────────────────────────────────────────────────────

fn set_brcb_purge_buf(
    brcb: &Arc<super::brcb::BufferedReportControl>,
    value: RcbWriteValue,
) -> Option<Result<(), DataAccessError>> {
    let v = match value {
        RcbWriteValue::Bool(b) => b,
        _ => return Some(Err(DataAccessError::TypeInconsistent)),
    };
    // Writing false has no effect and is not an error; writing true purges the
    // buffer while RptEna is false.
    match brcb.handle_purge_buf_write(v) {
        Ok(_purged) => Some(Ok(())),
        Err(_) => Some(Err(DataAccessError::HardwareFault)),
    }
}

fn set_brcb_rpt_ena(
    brcb: &Arc<super::brcb::BufferedReportControl>,
    value: RcbWriteValue,
) -> Option<Result<(), DataAccessError>> {
    let v = match value {
        RcbWriteValue::Bool(b) => b,
        _ => return Some(Err(DataAccessError::TypeInconsistent)),
    };
    let mut state = match brcb.lock_state() {
        Ok(s) => s,
        Err(_) => return Some(Err(DataAccessError::HardwareFault)),
    };
    if v {
        if state.dat_set.is_empty() {
            tracing::warn!(
                mms_path = %brcb.mms_path,
                "SetBRCBValues RptEna=true: DatSet is empty"
            );
            return Some(Err(DataAccessError::TemporarilyUnavailable));
        }
        if state.rpt_ena {
            return Some(Ok(()));
        }
        state.rpt_ena = true;
        // SqNum is not reset on enable: a BRCB sequence number is 16 bits and wraps
        // naturally, unlike the URCB counter.
    } else {
        if !state.rpt_ena {
            return Some(Ok(()));
        }
        state.rpt_ena = false;
        // Disabling a BRCB keeps the buffer; only the overflow indication matters,
        // and the send path already implies it for a from-head or unset anchor, so
        // the backend is left untouched here.
    }
    Some(Ok(()))
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
        "DatSet" => BrcbConfigField::DatSet(s),
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
    // A BRCB keeps BUFFER_OVERFLOW and ENTRY_ID rather than masking them.
    state.opt_flds = flds;
    state.increase_conf_rev();
    Some(Ok(()))
}

fn set_brcb_resv_tms(
    brcb: &Arc<super::brcb::BufferedReportControl>,
    value: RcbWriteValue,
) -> Option<Result<(), DataAccessError>> {
    // ResvTms is an INT16 on the wire. `RcbWriteValue` has no signed variant, so a
    // client encodes the positive range as an Unsigned.
    let v_i16: i16 = match value {
        RcbWriteValue::Unsigned(u) => {
            if u > i16::MAX as u32 {
                return Some(Err(DataAccessError::ObjectValueInvalid));
            }
            u as i16
        }
        _ => return Some(Err(DataAccessError::TypeInconsistent)),
    };
    let mut state = match brcb.lock_state() {
        Ok(s) => s,
        Err(_) => return Some(Err(DataAccessError::HardwareFault)),
    };
    let new_state = super::brcb::ResvTmsState::from_wire(v_i16);
    state.resv_tms = new_state;
    if let super::brcb::ResvTmsState::WithTimeout(secs) = new_state {
        state.reservation_timeout =
            Some(std::time::Instant::now() + std::time::Duration::from_secs(secs.get() as u64));
    } else if matches!(new_state, super::brcb::ResvTmsState::NotReserved) {
        state.reservation_timeout = None;
        state.client_conn_id = None;
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
        assert!(!state2.resv, "resv must be cleared on disable");
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
        let res =
            handle_set_brcb_field(&engine, &path, RcbField::RptEna, RcbWriteValue::Bool(true));
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
        );
        assert_eq!(res, Some(Err(DataAccessError::ObjectAccessDenied)));
    }

    #[test]
    fn brcb_set_sq_num_denied() {
        let (engine, path) = make_engine_with_brcb("03", TriggerOptions::DATA_CHANGED);
        let res =
            handle_set_brcb_field(&engine, &path, RcbField::SqNum, RcbWriteValue::Unsigned(5));
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
        );
        assert_eq!(res, Some(Err(DataAccessError::ObjectAccessDenied)));
    }

    /// Writing DatSet on a BRCB increments ConfRev and purges the buffer.
    #[test]
    fn brcb_set_dat_set_increments_conf_rev() {
        let (engine, path) = make_engine_with_brcb("05", TriggerOptions::DATA_CHANGED);
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

    /// Writing BufTm on a BRCB purges the buffer.
    #[test]
    fn brcb_set_buf_tm_changes_state() {
        let (engine, path) = make_engine_with_brcb("06", TriggerOptions::DATA_CHANGED);
        let res = handle_set_brcb_field(
            &engine,
            &path,
            RcbField::BufTm,
            RcbWriteValue::Unsigned(500),
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
        handle_set_brcb_field(&engine, &path, RcbField::RptEna, RcbWriteValue::Bool(true))
            .unwrap()
            .unwrap();
        // then request general interrogation
        let res = handle_set_brcb_field(&engine, &path, RcbField::Gi, RcbWriteValue::Bool(true));
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
        handle_set_brcb_field(&engine, &path, RcbField::RptEna, RcbWriteValue::Bool(true))
            .unwrap()
            .unwrap();
        let res = handle_set_brcb_field(&engine, &path, RcbField::Gi, RcbWriteValue::Bool(true));
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
            RcbField::Unknown("PurgeBuf".to_string()),
            RcbWriteValue::Bool(true),
        );
        assert_eq!(res, Some(Ok(())));
        let eng = engine.lock().unwrap();
        let brcb = eng.get_brcb(&path).unwrap();
        drop(eng);
        let buf = brcb.lock_buffer().unwrap();
        assert_eq!(buf.len(), 0, "PurgeBuf=true must empty the buffer");
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
        let r = handle_get_brcb_field(&engine, &path, RcbField::Unknown("ResvTms".to_string()));
        match r {
            Some(AccessResult::Success(MmsData::Integer(0))) => {}
            other => panic!("ResvTms must start at Integer(0), got {:?}", other),
        }
    }

    #[test]
    fn brcb_get_time_of_entry_returns_binary_time() {
        use iec61850_mms::mms::pdu::common::{AccessResult, MmsData};
        let (engine, path) = make_engine_with_brcb("14", TriggerOptions::DATA_CHANGED);
        let r = handle_get_brcb_field(&engine, &path, RcbField::Unknown("TimeofEntry".to_string()));
        match r {
            Some(AccessResult::Success(MmsData::BinaryTime(b))) => {
                assert_eq!(b.len(), 6, "a BinaryTime must be 6 bytes");
            }
            other => panic!("expected a BinaryTime, got {:?}", other),
        }
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
        assert!(
            handle_set_brcb_field(&engine, &path, RcbField::Resv, RcbWriteValue::Bool(true))
                .is_none()
        );
    }

    /// Writing ResvTms on a BRCB arms the reservation timeout.
    #[test]
    fn brcb_set_resv_tms_sets_timeout() {
        let (engine, path) = make_engine_with_brcb("17", TriggerOptions::DATA_CHANGED);
        let res = handle_set_brcb_field(
            &engine,
            &path,
            RcbField::Unknown("ResvTms".to_string()),
            RcbWriteValue::Unsigned(30),
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
        assert!(s.reservation_timeout.is_some());
    }
}
