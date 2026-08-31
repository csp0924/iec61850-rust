//! Writing RCB fields back to a server (IEC 61850-7-2 SetRCBValues).
//!
//! The order of the individual writes is an invariant:
//!
//! 1. `RptEna = false` goes first, because a server rejects changes to the
//!    other fields while reporting is enabled.
//! 2. `Resv` and `ResvTms` precede every field other than `RptEna`.
//! 3. `RptEna = true` goes last, so reporting starts on a fully configured
//!    control block.
//! 4. `GI` follows `RptEna = true` when both are set, so the general
//!    interrogation runs against enabled reporting.
//!
//! ConfRev, SqNum, TimeOfEntry and Owner are read-only: they are dropped from
//! the write mask and the removal is logged rather than left silent.

use crate::connection::IedConnection;
use crate::error::ClientError;
use crate::mms_compat::mms_value_to_mms_data;
use crate::prelude::{format, String, ToString, Vec};
use crate::rcb::handle::{encode_opt_flds_to_bit_string, encode_trg_ops_to_bit_string, RcbHandle};
use crate::rcb::mask::{RcbWriteMask, READ_ONLY_MASK};
use iec61850_hal::time::Timer;
use iec61850_hal::transport::AsyncTransport;
use iec61850_model::value::MmsValue;

// Write sequence items.

/// One write in an RCB update sequence.
///
/// `build_write_sequence` returns these in an order satisfying the invariants
/// above; `set_rcb_values` turns each into one MMS Write request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RcbWriteItem {
    /// `Resv = true`, written early (URCB only).
    ResvFirst,
    /// ResvTms, written early (BRCB only).
    ResvTms,
    /// `RptEna = false`, written first to unlock the other fields.
    RptEnaFalse,
    /// RptId.
    RptId,
    /// DatSet.
    DatSet,
    /// OptFlds.
    OptFlds,
    /// BufTm.
    BufTm,
    /// TrgOps.
    TrgOps,
    /// IntgPd.
    IntgPd,
    /// EntryId (BRCB only).
    EntryId,
    /// PurgeBuf (BRCB only).
    PurgeBuf,
    /// `RptEna = true`, written last.
    RptEnaTrue,
    /// GI, placed after `RptEna = true` when both are written.
    Gi,
}

// build_write_sequence

/// Builds the write sequence for a mask over an RCB.
///
/// The sequence satisfies the ordering invariants of the module header:
/// `RptEnaFalse` first, `ResvFirst` and `ResvTms` next, `RptEnaTrue` last, and
/// `Gi` after `RptEnaTrue` when both are requested.
///
/// Read-only mask bits are filtered out with a warning. A field that does not
/// exist on this kind of RCB, such as PurgeBuf on a URCB, produces no item;
/// `set_rcb_values` rejects such a mask up front through
/// `validate_mask_vs_type`.
pub(crate) fn build_write_sequence(rcb: &RcbHandle, mask: RcbWriteMask) -> Vec<RcbWriteItem> {
    // Drop the read-only bits, and say which ones were dropped.
    let ro_overlap = mask & READ_ONLY_MASK;
    if !ro_overlap.is_empty() {
        tracing::warn!(
            "set_rcb_values: dropping read-only fields {:?} from the write mask",
            ro_overlap
        );
    }
    let effective_mask = mask & !READ_ONLY_MASK;

    let wants_rpt_ena = effective_mask.contains(RcbWriteMask::RPT_ENA);
    let rpt_ena_value = rcb.rpt_ena.unwrap_or(false);

    // GI moves behind `RptEna = true` when both are requested.
    let send_gi_last = wants_rpt_ena && rpt_ena_value && effective_mask.contains(RcbWriteMask::GI);

    let mut seq: Vec<RcbWriteItem> = Vec::new();

    // `RptEna = false` first.
    if wants_rpt_ena && !rpt_ena_value {
        seq.push(RcbWriteItem::RptEnaFalse);
    }

    // Resv and ResvTms, immediately after `RptEna = false` if that is present.
    if effective_mask.contains(RcbWriteMask::RESV) && !rcb.is_buffered {
        // URCB only; a BRCB with this bit is rejected by validate_mask_vs_type.
        seq.push(RcbWriteItem::ResvFirst);
    }
    if effective_mask.contains(RcbWriteMask::RESV_TMS) && rcb.is_buffered {
        // BRCB only.
        seq.push(RcbWriteItem::ResvTms);
    }

    // The remaining writable fields, in mask bit order.
    if effective_mask.contains(RcbWriteMask::RPT_ID) {
        seq.push(RcbWriteItem::RptId);
    }
    if effective_mask.contains(RcbWriteMask::DAT_SET) {
        seq.push(RcbWriteItem::DatSet);
    }
    if effective_mask.contains(RcbWriteMask::OPT_FLDS) {
        seq.push(RcbWriteItem::OptFlds);
    }
    if effective_mask.contains(RcbWriteMask::BUF_TM) {
        seq.push(RcbWriteItem::BufTm);
    }
    if effective_mask.contains(RcbWriteMask::TRG_OPS) {
        seq.push(RcbWriteItem::TrgOps);
    }
    if effective_mask.contains(RcbWriteMask::INTG_PD) {
        seq.push(RcbWriteItem::IntgPd);
    }
    if effective_mask.contains(RcbWriteMask::ENTRY_ID) && rcb.is_buffered {
        seq.push(RcbWriteItem::EntryId);
    }

    // GI, unless it has to follow `RptEna = true`.
    if effective_mask.contains(RcbWriteMask::GI) && !send_gi_last {
        seq.push(RcbWriteItem::Gi);
    }

    // PurgeBuf (BRCB only).
    if effective_mask.contains(RcbWriteMask::PURGE_BUF) && rcb.is_buffered {
        seq.push(RcbWriteItem::PurgeBuf);
    }

    // `RptEna = true` last.
    if wants_rpt_ena && rpt_ena_value {
        seq.push(RcbWriteItem::RptEnaTrue);
    }

    // GI after `RptEna = true`.
    if send_gi_last {
        seq.push(RcbWriteItem::Gi);
    }

    seq
}

// Mask validation.

/// Checks that a write mask only names fields the RCB actually has.
///
/// # Errors
///
/// `InvalidArgument` for a BRCB-only field on a URCB, or Resv on a BRCB. The
/// check runs before anything reaches the wire.
pub(crate) fn validate_mask_vs_type(
    rcb: &RcbHandle,
    mask: RcbWriteMask,
) -> Result<(), ClientError> {
    // A URCB has no PurgeBuf, EntryId or ResvTms.
    if !rcb.is_buffered {
        if mask.contains(RcbWriteMask::PURGE_BUF) {
            return Err(ClientError::InvalidArgument(
                "PURGE_BUF applies to a buffered RCB only".to_string(),
            ));
        }
        if mask.contains(RcbWriteMask::ENTRY_ID) {
            return Err(ClientError::InvalidArgument(
                "ENTRY_ID applies to a buffered RCB only".to_string(),
            ));
        }
        if mask.contains(RcbWriteMask::RESV_TMS) {
            return Err(ClientError::InvalidArgument(
                "RESV_TMS applies to a buffered RCB only".to_string(),
            ));
        }
    }
    // Resv is the reservation flag of an unbuffered RCB.
    if rcb.is_buffered && mask.contains(RcbWriteMask::RESV) {
        return Err(ClientError::InvalidArgument(
            "RESV applies to an unbuffered RCB only".to_string(),
        ));
    }
    Ok(())
}

// Mapping a write item onto an MMS field name and value.

/// Maps a write item onto the MMS field name suffix and the value to write.
///
/// The suffix is appended to the item id base, as in
/// `("$RptEna", MmsValue::Boolean(true))`.
pub(crate) fn item_to_field_value(
    item: &RcbWriteItem,
    rcb: &RcbHandle,
) -> Option<(&'static str, MmsValue)> {
    match item {
        RcbWriteItem::RptEnaFalse => Some(("$RptEna", MmsValue::Boolean(false))),
        RcbWriteItem::RptEnaTrue => Some(("$RptEna", MmsValue::Boolean(true))),
        RcbWriteItem::ResvFirst => {
            let v = rcb.resv.unwrap_or(false);
            Some(("$Resv", MmsValue::Boolean(v)))
        }
        RcbWriteItem::ResvTms => {
            let v = rcb.resv_tms.unwrap_or(0);
            Some(("$ResvTms", MmsValue::Integer(v as i64)))
        }
        RcbWriteItem::RptId => {
            let s = rcb.rpt_id.as_deref().unwrap_or("").to_string();
            Some(("$RptID", MmsValue::VisibleString(s)))
        }
        RcbWriteItem::DatSet => {
            let s = rcb.data_set_reference.as_deref().unwrap_or("").to_string();
            Some(("$DatSet", MmsValue::VisibleString(s)))
        }
        RcbWriteItem::OptFlds => {
            let opt = rcb.opt_flds.unwrap_or_default();
            let (padding, data) = encode_opt_flds_to_bit_string(opt);
            Some(("$OptFlds", MmsValue::BitString { padding, data }))
        }
        RcbWriteItem::BufTm => {
            let v = rcb.buf_tm_ms.unwrap_or(0);
            Some(("$BufTm", MmsValue::Unsigned(v as u64)))
        }
        RcbWriteItem::TrgOps => {
            let ops = rcb.trg_ops.unwrap_or_default();
            let (padding, data) = encode_trg_ops_to_bit_string(ops);
            Some(("$TrgOps", MmsValue::BitString { padding, data }))
        }
        RcbWriteItem::IntgPd => {
            let v = rcb.intg_pd_ms.unwrap_or(0);
            Some(("$IntgPd", MmsValue::Unsigned(v as u64)))
        }
        RcbWriteItem::EntryId => {
            let bytes = rcb.entry_id.as_deref().unwrap_or(&[]).to_vec();
            Some(("$EntryId", MmsValue::OctetString(bytes)))
        }
        RcbWriteItem::PurgeBuf => {
            let v = rcb.purge_buf.unwrap_or(false);
            Some(("$PurgeBuf", MmsValue::Boolean(v)))
        }
        RcbWriteItem::Gi => Some(("$GI", MmsValue::Boolean(true))),
    }
}

/// Splits an object reference into the MMS domain id and item id base.
///
/// `simpleIOGenericIO/LLN0.RP.urcb01` becomes `simpleIOGenericIO` and
/// `LLN0$RP$urcb01`: per IEC 61850-8-1 every `.` maps to `$`.
pub(crate) fn parse_object_reference(reference: &str) -> Option<(String, String)> {
    // The domain id ends at the first '/'.
    let slash_pos = reference.find('/')?;
    let domain_id = reference[..slash_pos].to_string();
    let rest = &reference[slash_pos + 1..];
    let item_id = rest.replace('.', "$");
    Some((domain_id, item_id))
}

// set_rcb_values.

/// Writes the `RcbHandle` fields selected by `mask` back to the server
/// (IEC 61850-7-2 SetRCBValues).
///
/// The writes are issued one at a time, in the order `build_write_sequence`
/// returns, while holding the connection's MMS client lock.
///
/// `single_request` asks for a single WriteMultiple request. The MMS layer
/// writes one variable per request, so the flag currently logs a warning and
/// falls back to the sequential path.
///
/// # Errors
///
/// `InvalidArgument` if the mask names a field this kind of RCB does not have,
/// or if the object reference cannot be split into a domain and an item id.
/// `NotConnected` if the association is not established. The first failing
/// write ends the sequence; the remaining fields are not written.
pub async fn set_rcb_values<T: AsyncTransport, Tm: Timer>(
    conn: &IedConnection<T, Tm>,
    rcb: &RcbHandle,
    mask: RcbWriteMask,
    single_request: bool,
) -> Result<(), ClientError> {
    // The mask must match the kind of RCB before anything goes to the wire.
    validate_mask_vs_type(rcb, mask)?;

    // Read-only bits are dropped here, with a warning.
    let seq = build_write_sequence(rcb, mask);
    if seq.is_empty() {
        return Ok(());
    }

    let (domain, item_base) = parse_object_reference(rcb.object_reference()).ok_or_else(|| {
        ClientError::InvalidArgument(format!(
            "set_rcb_values: cannot parse object reference '{}'",
            rcb.object_reference()
        ))
    })?;

    if !conn.is_connected() {
        return Err(ClientError::NotConnected);
    }

    // WriteMultiple is not available in the MMS layer yet.
    if single_request {
        tracing::warn!(
            "set_rcb_values: single_request is not supported; writing one field per request"
        );
    }

    // One MMS Write per item, serialized under the client lock.
    let mut client = conn.mms_client.lock().await;
    for item in &seq {
        if let Some((suffix, value)) = item_to_field_value(item, rcb) {
            let full_item = format!("{item_base}{suffix}");
            let mms_data = mms_value_to_mms_data(&value);
            client.write(&domain, &full_item, mms_data).await?;
        }
    }
    drop(client);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rcb::handle::RcbHandle;
    use crate::rcb::mask::RcbWriteMask;

    fn urcb(rpt_ena: bool) -> RcbHandle {
        let mut h = RcbHandle::new("IED1/LD0$RP$rcb01").unwrap();
        h.set_rpt_ena(rpt_ena);
        h
    }

    fn brcb(rpt_ena: bool) -> RcbHandle {
        let mut h = RcbHandle::new("IED1/LD0$BR$brcb01").unwrap();
        h.set_rpt_ena(rpt_ena);
        h
    }

    #[test]
    fn sequence_rpt_ena_true_only() {
        let mut rcb = urcb(true);
        rcb.set_rpt_ena(true);
        let seq = build_write_sequence(&rcb, RcbWriteMask::RPT_ENA);
        assert_eq!(seq, vec![RcbWriteItem::RptEnaTrue]);
    }

    #[test]
    fn sequence_rpt_ena_true_with_datset_and_optflds() {
        let mut rcb = urcb(true);
        rcb.set_rpt_ena(true);
        let mask = RcbWriteMask::RPT_ENA | RcbWriteMask::DAT_SET | RcbWriteMask::OPT_FLDS;
        let seq = build_write_sequence(&rcb, mask);
        // DatSet and OptFlds must precede RptEnaTrue.
        let rpt_pos = seq
            .iter()
            .position(|i| *i == RcbWriteItem::RptEnaTrue)
            .unwrap();
        let dat_pos = seq.iter().position(|i| *i == RcbWriteItem::DatSet).unwrap();
        let opt_pos = seq
            .iter()
            .position(|i| *i == RcbWriteItem::OptFlds)
            .unwrap();
        assert!(dat_pos < rpt_pos, "DatSet must precede RptEnaTrue");
        assert!(opt_pos < rpt_pos, "OptFlds must precede RptEnaTrue");
        // RptEnaTrue is the last item.
        assert_eq!(seq.last(), Some(&RcbWriteItem::RptEnaTrue));
    }

    #[test]
    fn sequence_rpt_ena_false_first() {
        let mut rcb = urcb(false);
        rcb.set_rpt_ena(false);
        let mask = RcbWriteMask::RPT_ENA | RcbWriteMask::DAT_SET;
        let seq = build_write_sequence(&rcb, mask);
        // RptEnaFalse is the first item.
        assert_eq!(seq.first(), Some(&RcbWriteItem::RptEnaFalse));
        // DatSet follows it.
        let false_pos = seq
            .iter()
            .position(|i| *i == RcbWriteItem::RptEnaFalse)
            .unwrap();
        let dat_pos = seq.iter().position(|i| *i == RcbWriteItem::DatSet).unwrap();
        assert!(dat_pos > false_pos, "DatSet must follow RptEnaFalse");
    }

    #[test]
    fn sequence_resv_first_gi_last_after_rpt_ena_true() {
        let mut rcb = urcb(true);
        rcb.set_rpt_ena(true);
        rcb.set_resv(true);
        rcb.set_gi(true);
        let mask = RcbWriteMask::RESV | RcbWriteMask::RPT_ENA | RcbWriteMask::GI;
        let seq = build_write_sequence(&rcb, mask);
        // ResvFirst leads, there being no RptEnaFalse.
        assert_eq!(seq.first(), Some(&RcbWriteItem::ResvFirst));
        // RptEnaTrue precedes Gi.
        let rpt_pos = seq
            .iter()
            .position(|i| *i == RcbWriteItem::RptEnaTrue)
            .unwrap();
        let gi_pos = seq.iter().position(|i| *i == RcbWriteItem::Gi).unwrap();
        assert!(rpt_pos < gi_pos, "RptEnaTrue must precede Gi");
        // Gi is the last item.
        assert_eq!(seq.last(), Some(&RcbWriteItem::Gi));
    }

    #[test]
    fn sequence_gi_only() {
        let rcb = urcb(false);
        let seq = build_write_sequence(&rcb, RcbWriteMask::GI);
        assert_eq!(seq, vec![RcbWriteItem::Gi]);
    }

    #[test]
    fn sequence_read_only_fields_filtered() {
        let mut rcb = urcb(false);
        rcb.set_rpt_ena(false);
        // CONF_REV is read-only and must be filtered out.
        let mask = RcbWriteMask::RPT_ENA | RcbWriteMask::CONF_REV | RcbWriteMask::DAT_SET;
        let seq = build_write_sequence(&rcb, mask);
        // No item corresponds to ConfRev.
        assert!(!seq.is_empty());
        // RptEnaFalse still leads.
        assert_eq!(seq.first(), Some(&RcbWriteItem::RptEnaFalse));
        // DatSet is present.
        assert!(seq.contains(&RcbWriteItem::DatSet));
        // Exactly RptEnaFalse and DatSet remain.
        assert_eq!(seq.len(), 2);
    }

    // validate_mask_vs_type.

    #[test]
    fn validate_urcb_purge_buf_fails() {
        let rcb = urcb(false);
        let err = validate_mask_vs_type(&rcb, RcbWriteMask::PURGE_BUF).unwrap_err();
        assert!(matches!(err, ClientError::InvalidArgument(_)));
    }

    #[test]
    fn validate_brcb_resv_fails() {
        let rcb = brcb(false);
        let err = validate_mask_vs_type(&rcb, RcbWriteMask::RESV).unwrap_err();
        assert!(matches!(err, ClientError::InvalidArgument(_)));
    }

    // parse_object_reference.

    #[test]
    fn parse_ref_dot_sep() {
        let (domain, item) = parse_object_reference("simpleIOGenericIO/LLN0.RP.urcb01").unwrap();
        assert_eq!(domain, "simpleIOGenericIO");
        assert_eq!(item, "LLN0$RP$urcb01");
    }

    #[test]
    fn parse_ref_dollar_sep() {
        let (domain, item) = parse_object_reference("simpleIOGenericIO/LLN0$BR$brcb01").unwrap();
        assert_eq!(domain, "simpleIOGenericIO");
        assert_eq!(item, "LLN0$BR$brcb01");
    }

    // set_rcb_values.

    /// `set_rcb_values` returns `NotConnected` before reaching the wire.
    #[tokio::test]
    async fn set_rcb_values_not_connected_returns_err() {
        let conn = IedConnection::new();
        let mut rcb = RcbHandle::new("IED1/LD0$RP$rcb01").unwrap();
        rcb.set_rpt_ena(true);
        let err = set_rcb_values(&conn, &rcb, RcbWriteMask::RPT_ENA, false)
            .await
            .unwrap_err();
        assert!(matches!(err, ClientError::NotConnected));
    }

    /// Mask validation runs before the connection check, so an invalid mask is
    /// reported as `InvalidArgument` rather than `NotConnected`.
    #[tokio::test]
    async fn set_rcb_values_validate_failure_precedes_connection_check() {
        let conn = IedConnection::new(); // not connected
        let rcb = RcbHandle::new("IED1/LD0$RP$urcb01").unwrap();
        // PURGE_BUF on a URCB fails validate_mask_vs_type.
        let err = set_rcb_values(&conn, &rcb, RcbWriteMask::PURGE_BUF, false)
            .await
            .unwrap_err();
        assert!(matches!(err, ClientError::InvalidArgument(_)));
    }

    /// An empty mask is a no-op and succeeds without a connection.
    #[tokio::test]
    async fn set_rcb_values_empty_mask_ok_without_connection() {
        let conn = IedConnection::new(); // not connected
        let rcb = RcbHandle::new("IED1/LD0$RP$urcb01").unwrap();
        // An empty mask yields an empty sequence.
        let result = set_rcb_values(&conn, &rcb, RcbWriteMask::empty(), false).await;
        assert!(result.is_ok());
    }
}
