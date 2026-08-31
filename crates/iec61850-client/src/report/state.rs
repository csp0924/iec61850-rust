//! Report state: applying a parsed report to the values a subscriber keeps.
//!
//! No IO and no callbacks; those belong to `dispatch.rs`.
//!
//! Values are owned and replaced wholesale rather than updated in place, which
//! matches how `MmsValue` is handled everywhere else. The data set size is
//! learned from the first report and fixed from then on: a later report of a
//! different size is rejected instead of silently resizing the state.

use thiserror::Error;

use crate::prelude::{String, Vec};
use crate::report::parse::{ParsedReport, ReasonForInclusion, Segmentation};
use iec61850_model::value::MmsValue;

/// The accumulated state of one report subscription.
///
/// One `ClientReport` belongs to one registered RCB reference and callback;
/// each incoming report is folded into it by `apply_report`.
#[derive(Debug, Clone)]
pub struct ClientReport {
    /// RCB object reference the handler was installed for.
    pub rcb_reference: String,
    /// RptId override given at install time. `None` selects the default,
    /// derived from the RCB reference by replacing '.' with '$'.
    pub rpt_id: Option<String>,

    /// Number of data set members, fixed by the first report. `None` until one
    /// arrives.
    pub dataset_size: Option<usize>,

    // Owned snapshot of the most recent report.
    /// Sequence number of the latest report, when it carried one.
    pub seq_num: Option<u16>,
    /// Timestamp of the latest report in milliseconds since the epoch, when it
    /// carried one.
    pub timestamp_ms: Option<u64>,
    /// Data set name of the latest report, when it carried one.
    pub data_set_name: Option<String>,
    /// Buffer overflow flag of the latest report, when it carried one.
    pub buf_ovfl: Option<bool>,
    /// Entry id of the latest report, when it carried one.
    pub entry_id: Option<Vec<u8>>,
    /// Configuration revision of the latest report, when it carried one.
    pub conf_rev: Option<u32>,
    /// Segmentation header of the latest report, when it carried one.
    pub segmentation: Option<Segmentation>,

    /// One entry per data set member: `Some(value)` once a report has carried
    /// it, keeping the previous value for a member the latest report omitted.
    pub data_set_values: Vec<Option<MmsValue>>,

    /// One entry per data set member, empty flags until a report supplies one.
    pub reasons: Vec<ReasonForInclusion>,

    /// One entry per data set member, holding the member's object reference
    /// when the report carried one.
    pub data_references: Vec<Option<String>>,
}

impl ClientReport {
    /// Creates the state of a subscription that has received no report yet.
    pub fn new(rcb_reference: String, rpt_id: Option<String>) -> Self {
        Self {
            rcb_reference,
            rpt_id,
            dataset_size: None,
            seq_num: None,
            timestamp_ms: None,
            data_set_name: None,
            buf_ovfl: None,
            entry_id: None,
            conf_rev: None,
            segmentation: None,
            data_set_values: Vec::new(),
            reasons: Vec::new(),
            data_references: Vec::new(),
        }
    }

    /// Returns the RptId a report must carry to match this subscription.
    ///
    /// Without an explicit RptId, the RCB reference with '.' replaced by '$' is
    /// used: `simpleIOGenericIO/LLN0.RP.EventsRCB01` becomes
    /// `simpleIOGenericIO/LLN0$RP$EventsRCB01`.
    pub fn effective_rpt_id(&self) -> String {
        match &self.rpt_id {
            Some(id) => id.clone(),
            None => self.rcb_reference.replace('.', "$"),
        }
    }
}

/// Failure reported by `apply_report`.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum StateError {
    /// A report carries a different number of data set members than the first
    /// one did.
    #[error("dataset size changed from {prev} to {new} — discarding report")]
    DataSetSizeChanged {
        /// Member count fixed by the first report.
        prev: usize,
        /// Member count the rejected report carried.
        new: usize,
    },

    /// The data set name exceeds the 128-byte MMS object-name limit.
    #[error("dataSetName length {len} exceeds upper bound 128")]
    DataSetNameTooLong {
        /// Length of the offending data set name, in bytes.
        len: usize,
    },
}

/// Applies a parsed report to the subscription state. No IO, no callbacks.
///
/// Members the report omits keep their previous value; those it includes are
/// replaced outright.
///
/// # Errors
///
/// `DataSetSizeChanged` or `DataSetNameTooLong`, each also logged as a
/// warning; the caller decides whether to drop the report.
pub fn apply_report(state: &mut ClientReport, parsed: ParsedReport) -> Result<(), StateError> {
    // Fix the data set size on the first report, then hold the caller to it.
    let dataset_size = parsed.inclusion_bits.len();
    match state.dataset_size {
        None => {
            state.dataset_size = Some(dataset_size);
            state.data_set_values = vec![None; dataset_size];
            state.reasons = vec![ReasonForInclusion::empty(); dataset_size];
            state.data_references = vec![None; dataset_size];
        }
        Some(prev) if prev != dataset_size => {
            tracing::warn!(
                rcb_ref = %state.rcb_reference,
                prev,
                new = dataset_size,
                "dataset size changed across reports — rejecting"
            );
            return Err(StateError::DataSetSizeChanged {
                prev,
                new: dataset_size,
            });
        }
        Some(_) => {}
    }

    // An MMS object name is limited to 128 bytes.
    if let Some(ref name) = parsed.data_set_name {
        if name.len() > 128 {
            tracing::warn!(
                rcb_ref = %state.rcb_reference,
                len = name.len(),
                "dataSetName too long — rejecting"
            );
            return Err(StateError::DataSetNameTooLong { len: name.len() });
        }
    }

    // Take ownership of the report's fields.
    state.seq_num = parsed.seq_num;
    state.timestamp_ms = parsed.timestamp_ms;
    state.data_set_name = parsed.data_set_name;
    state.buf_ovfl = parsed.buf_ovfl;
    state.entry_id = parsed.entry_id;
    state.conf_rev = parsed.conf_rev;
    state.segmentation = parsed.segmentation;

    // The report carries one value per included member, in member order.
    // Members that are not included keep the value of the previous report.
    let mut included_iter = 0usize;
    let has_data_ref = !parsed.data_references.is_empty();
    let has_reasons = !parsed.reasons.is_empty();
    for (i, &included) in parsed.inclusion_bits.iter().enumerate() {
        if !included {
            continue;
        }
        let value = parsed.data_values.get(included_iter).cloned().ok_or(
            StateError::DataSetSizeChanged {
                prev: dataset_size,
                new: parsed.data_values.len(),
            },
        )?;
        state.data_set_values[i] = Some(value);
        if has_reasons {
            if let Some(r) = parsed.reasons.get(included_iter) {
                state.reasons[i] = *r;
            }
        }
        if has_data_ref {
            if let Some(s) = parsed.data_references.get(included_iter) {
                state.data_references[i] = Some(s.clone());
            }
        }
        included_iter += 1;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::parse::ReportOptFlds;

    fn make_parsed(
        inclusion: Vec<bool>,
        values: Vec<MmsValue>,
        reasons: Vec<ReasonForInclusion>,
    ) -> ParsedReport {
        ParsedReport {
            rpt_id: "rpt".to_string(),
            opt_flds: ReportOptFlds::empty(),
            seq_num: None,
            timestamp_ms: None,
            data_set_name: None,
            buf_ovfl: None,
            entry_id: None,
            conf_rev: None,
            segmentation: None,
            inclusion_bits: inclusion,
            data_references: Vec::new(),
            data_values: values,
            reasons,
        }
    }

    #[test]
    fn first_report_locks_dataset_size() {
        let mut s = ClientReport::new("L/N$RP$X".to_string(), None);
        let p = make_parsed(vec![true, false], vec![MmsValue::Integer(1)], vec![]);
        apply_report(&mut s, p).unwrap();
        assert_eq!(s.dataset_size, Some(2));
        assert_eq!(s.data_set_values[0], Some(MmsValue::Integer(1)));
        assert_eq!(s.data_set_values[1], None);
    }

    #[test]
    fn second_report_with_different_size_rejects() {
        let mut s = ClientReport::new("rcb".to_string(), None);
        apply_report(
            &mut s,
            make_parsed(vec![true], vec![MmsValue::Integer(1)], vec![]),
        )
        .unwrap();
        let r = apply_report(
            &mut s,
            make_parsed(
                vec![true, true],
                vec![MmsValue::Integer(1), MmsValue::Integer(2)],
                vec![],
            ),
        );
        assert!(matches!(
            r,
            Err(StateError::DataSetSizeChanged { prev: 1, new: 2 })
        ));
    }

    #[test]
    fn excluded_slots_preserve_previous_value() {
        let mut s = ClientReport::new("rcb".to_string(), None);
        // Both members included, with values 1 and 2.
        apply_report(
            &mut s,
            make_parsed(
                vec![true, true],
                vec![MmsValue::Integer(1), MmsValue::Integer(2)],
                vec![],
            ),
        )
        .unwrap();
        // Only the first member included, with value 99.
        apply_report(
            &mut s,
            make_parsed(vec![true, false], vec![MmsValue::Integer(99)], vec![]),
        )
        .unwrap();
        assert_eq!(s.data_set_values[0], Some(MmsValue::Integer(99)));
        // The second member keeps its previous value.
        assert_eq!(s.data_set_values[1], Some(MmsValue::Integer(2)));
    }

    #[test]
    fn reasons_only_update_included_slots() {
        let mut s = ClientReport::new("rcb".to_string(), None);
        apply_report(
            &mut s,
            make_parsed(
                vec![true, true],
                vec![MmsValue::Integer(1), MmsValue::Integer(2)],
                vec![ReasonForInclusion::DATA_CHANGE, ReasonForInclusion::GI],
            ),
        )
        .unwrap();
        assert_eq!(s.reasons[0], ReasonForInclusion::DATA_CHANGE);
        assert_eq!(s.reasons[1], ReasonForInclusion::GI);
    }

    #[test]
    fn data_set_name_too_long_rejects() {
        let mut s = ClientReport::new("rcb".to_string(), None);
        let mut parsed = make_parsed(vec![true], vec![MmsValue::Integer(1)], vec![]);
        parsed.data_set_name = Some("x".repeat(129));
        let r = apply_report(&mut s, parsed);
        assert!(matches!(
            r,
            Err(StateError::DataSetNameTooLong { len: 129 })
        ));
    }

    #[test]
    fn effective_rpt_id_default_replaces_dot() {
        let s = ClientReport::new("simpleIOGenericIO/LLN0.RP.EventsRCB01".to_string(), None);
        assert_eq!(
            s.effective_rpt_id(),
            "simpleIOGenericIO/LLN0$RP$EventsRCB01"
        );
    }

    #[test]
    fn effective_rpt_id_explicit_overrides() {
        let s = ClientReport::new("ignored".to_string(), Some("custom_rpt".to_string()));
        assert_eq!(s.effective_rpt_id(), "custom_rpt");
    }
}
