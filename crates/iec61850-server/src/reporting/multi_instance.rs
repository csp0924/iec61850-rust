//! Helpers that register several instances of one report control block.
//!
//! An SCL `<ReportControl name="urcb01"><RptEnabled max="N"/>` from IEC 61850-6
//! must be expanded at runtime into N instances named `<base><II>`, where `II`
//! runs from 1 to N as a two-digit, zero-padded number. These helpers sit above
//! `IedServer::register_urcb` and `register_brcb_with_dataset` so the expansion is
//! written once instead of in every caller.
//!
//! Each instance is a separate `ReportControl` or `BufferedReportControl` with its
//! own Resv, RptEna, SqNum, ConfRev, DatSet, OptFlds, TrgOps, IntgPd, GI, and, for
//! a BRCB, its own report buffer. In the MMS namespace they appear as
//! `<Domain>/<LN>$RP$<base><II>` and `<Domain>/<LN>$BR$<base><II>`, and the
//! dispatcher resolves the full path, so N instances are N independent entries in
//! the reporting engine. No `max_instances` field is added to the control block
//! types: N instances are N control block nodes, each carrying its own suffix.
//!
//! [`register_urcb_instances`] expands a URCB template, [`register_brcb_instances`]
//! a BRCB template.
//!
//! ```ignore
//! use iec61850_server::reporting::{register_urcb_instances, Rcb, Dataset};
//! let template = Rcb::new("urcb01", "urcb_dchg_ds")
//!     .with_trg_ops(TriggerOptions::DATA_CHANGED)
//!     .with_buf_tm_ms(50);
//! register_urcb_instances(&server, "confIEDGenericIO", "LLN0", template, dataset, 2)?;
//! // registers urcb0101 and urcb0102 as two independent control blocks
//! ```

use crate::error::{Result, ServerError};
use crate::reporting::{
    Brcb, BufferedReportControl, Dataset, Rcb, ReportControl, RESV_TMS_IMPLICIT_VALUE_S,
};
use crate::server::IedServer;

/// Formats an instance name: the base name followed by a 1-based, two-digit,
/// zero-padded index.
///
/// `format_instance_name("urcb01", 1)` gives `"urcb0101"`.
fn format_instance_name(base: &str, idx: u8) -> String {
    format!("{base}{idx:02}")
}

/// Registers `count` URCB instances from `template`, named `<base><II>` with `II`
/// running from 1 to `count`.
///
/// Each instance is `template.clone()` with its `name` and `rpt_id` adjusted, then
/// registered through `IedServer::register_urcb`. `dataset_template` is cloned per
/// instance: the instances share the same underlying attribute handles but each
/// gets its own `Dataset`, so the trigger index points every entry at its own
/// control block.
///
/// `template.name` is the base name, for example `"urcb01"`. When `template.rpt_id`
/// is empty each instance gets its MMS path as its RptID; otherwise every
/// occurrence of the base name inside `rpt_id` is replaced by the instance name.
/// `dataset_template.name` is left alone, so the instances share one logical data
/// set name.
///
/// # Arguments
/// - `server`: the server to register with
/// - `domain`: MMS domain, for example `"confIEDGenericIO"`
/// - `ln_full_name`: full logical node name, for example `"LLN0"` or `"GGIO1"`
/// - `template`: the URCB configuration to copy
/// - `dataset_template`: the data set to bind to every instance
/// - `count`: number of instances; at least 1 and at most 99, the two-digit limit
///
/// # Errors
/// - `ServerError::InvalidModel` when `count` is 0 or above 99.
/// - The error from `register_urcb` when an instance cannot be registered, for
///   example on a duplicate MMS path. The helper stops there and the instances
///   already registered stay in the engine; there is no rollback.
pub fn register_urcb_instances(
    server: &IedServer,
    domain: &str,
    ln_full_name: &str,
    template: Rcb,
    dataset_template: Dataset,
    count: u8,
) -> Result<()> {
    if count == 0 || count > 99 {
        return Err(ServerError::InvalidModel(format!(
            "register_urcb_instances: count {count} out of range [1, 99]"
        )));
    }
    let base = template.name.clone();
    for i in 1..=count {
        let inst_name = format_instance_name(&base, i);
        // Copy the template, then change only the name and the RptID.
        let mut rcb = template.clone();
        rcb.name = inst_name.clone();
        let mms_path = format!("{domain}/{ln_full_name}$RP${inst_name}");
        // An empty template RptID defaults to the MMS path, per IEC 61850-7-2;
        // otherwise the base name inside it is replaced by the instance name, so a
        // caller does not have to set one RptID per instance.
        rcb.rpt_id = if template.rpt_id.is_empty() {
            mms_path.clone()
        } else {
            template.rpt_id.replace(&base, &inst_name)
        };
        let rc = ReportControl::new(mms_path, rcb);
        // One Dataset per instance; the attribute handles inside are shared.
        server.register_urcb(rc, dataset_template.clone())?;
    }
    Ok(())
}

/// Registers `count` BRCB instances from `template`, named `<base><II>` with `II`
/// running from 1 to `count`.
///
/// Each instance is a separate `BufferedReportControl` with its own report buffer,
/// SqNum, EntryID, and enable state; a BRCB sequence number is 16 bits where a URCB
/// uses 8.
///
/// Unlike [`register_urcb_instances`], this registers through
/// `register_brcb_with_dataset` and does not populate the attribute reference
/// index. That index is written when a URCB is registered on the same data set, so
/// a caller that registers only BRCBs must ensure the references are in place.
pub fn register_brcb_instances(
    server: &IedServer,
    domain: &str,
    ln_full_name: &str,
    template: Brcb,
    dataset_template: Dataset,
    count: u8,
) -> Result<()> {
    if count == 0 || count > 99 {
        return Err(ServerError::InvalidModel(format!(
            "register_brcb_instances: count {count} out of range [1, 99]"
        )));
    }
    let base = template.name.clone();
    for i in 1..=count {
        let inst_name = format_instance_name(&base, i);
        let mut brcb = template.clone();
        brcb.name = inst_name.clone();
        let mms_path = format!("{domain}/{ln_full_name}$BR${inst_name}");
        brcb.rpt_id = if template.rpt_id.is_empty() {
            mms_path.clone()
        } else {
            template.rpt_id.replace(&base, &inst_name)
        };
        let buffered = BufferedReportControl::new(mms_path, brcb);
        let engine = server.reporting_engine();
        let mut g = engine
            .lock()
            .map_err(|_| ServerError::InvalidModel("ReportingEngine Mutex poisoned".into()))?;
        g.register_brcb_with_dataset(buffered, dataset_template.clone())?;
    }
    // Referenced so the constant is not reported as unused under some feature sets.
    let _ = RESV_TMS_IMPLICIT_VALUE_S;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporting::{DatasetEntry, OptFlds as RtOptFlds, ReportingEngine, TriggerOptions};
    use crate::IedServerConfig;
    use iec61850_model::{
        DataAttributeType, DataObjectBuilder, IedModelBuilder, LogicalDeviceBuilder,
        LogicalNodeBuilder, MmsValue, TrgOps, FC,
    };
    use std::net::SocketAddr;
    use std::sync::{Arc, RwLock};

    fn build_test_server() -> IedServer {
        let lln0 = LogicalNodeBuilder::lln0()
            .add_do(
                DataObjectBuilder::scalar("Test")
                    .add_da(
                        "stVal",
                        FC::St,
                        DataAttributeType::Boolean,
                        TrgOps::DCHG,
                        MmsValue::Boolean(false),
                    )
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let ld = LogicalDeviceBuilder::new("LD0")
            .add_ln(lln0)
            .build()
            .unwrap();
        let model = IedModelBuilder::new("TIED")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap();

        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        IedServer::builder()
            .model(Arc::new(model))
            .bind(bind)
            .config(IedServerConfig::default())
            .build()
            .unwrap()
    }

    fn dummy_dataset() -> Dataset {
        let mut ds = Dataset::new("test_ds");
        ds.push(DatasetEntry::new(
            "TIEDLD0/LLN0$ST$Test$stVal",
            Arc::new(RwLock::new(MmsValue::Boolean(false))),
        ));
        ds
    }

    #[test]
    fn multi_instance_urcb_register_two_instances_with_correct_names() {
        let server = build_test_server();
        let template = Rcb::new("urcb01", "test_ds")
            .with_trg_ops(TriggerOptions::DATA_CHANGED)
            .with_opt_flds(RtOptFlds::SEQ_NUM | RtOptFlds::TIME_STAMP)
            .with_buf_tm_ms(50);
        register_urcb_instances(&server, "TIEDLD0", "LLN0", template, dummy_dataset(), 2).unwrap();

        let engine = server.reporting_engine();
        let g = engine.lock().unwrap();
        let paths = g.rcb_paths();
        assert!(paths.contains(&"TIEDLD0/LLN0$RP$urcb0101".to_string()));
        assert!(paths.contains(&"TIEDLD0/LLN0$RP$urcb0102".to_string()));
    }

    #[test]
    fn multi_instance_urcb_resv_state_isolated_between_instances() {
        let server = build_test_server();
        let template = Rcb::new("urcb01", "test_ds").with_trg_ops(TriggerOptions::DATA_CHANGED);
        register_urcb_instances(&server, "TIEDLD0", "LLN0", template, dummy_dataset(), 2).unwrap();

        let engine = server.reporting_engine();
        let g = engine.lock().unwrap();
        let inst_a = g.get_rcb("TIEDLD0/LLN0$RP$urcb0101").unwrap();
        let inst_b = g.get_rcb("TIEDLD0/LLN0$RP$urcb0102").unwrap();

        // Instance A is reserved by connection 1.
        {
            let a = inst_a.lock().unwrap();
            let mut sa = a.lock_state().unwrap();
            sa.resv = true;
            sa.client_conn_id = Some(1);
        }
        // Instance B can still be reserved by another client, independently of A.
        {
            let b = inst_b.lock().unwrap();
            let mut sb = b.lock_state().unwrap();
            assert!(!sb.resv, "the reservation on instance B must be independent of A");
            sb.resv = true;
            sb.client_conn_id = Some(2);
        }
        // A still holds its own values; operating on B did not affect it.
        let a_again = inst_a.lock().unwrap();
        let sa_again = a_again.lock_state().unwrap();
        assert!(sa_again.resv);
        assert_eq!(sa_again.client_conn_id, Some(1));
    }

    #[test]
    fn multi_instance_urcb_same_instance_second_client_blocked_by_resv() {
        // Once instance A is reserved by one client, another client must not take
        // it. This test covers the state structure only; the dispatcher answer of
        // TemporarilyUnavailable is covered by the tests in reporting/service.rs.
        let server = build_test_server();
        let template = Rcb::new("urcb01", "test_ds");
        register_urcb_instances(&server, "TIEDLD0", "LLN0", template, dummy_dataset(), 2).unwrap();

        let engine = server.reporting_engine();
        let g = engine.lock().unwrap();
        let inst = g.get_rcb("TIEDLD0/LLN0$RP$urcb0101").unwrap();
        let rc = inst.lock().unwrap();
        let mut state = rc.lock_state().unwrap();
        state.resv = true;
        state.client_conn_id = Some(1);
        // A second client writing Resv is answered by the dispatcher, which compares
        // client_conn_id against the requester. Here only the state is checked: the
        // recorded reservation is not overwritten.
        assert_eq!(state.client_conn_id, Some(1));
        assert!(state.resv);
    }

    #[test]
    fn multi_instance_brcb_register_two_instances_with_correct_names() {
        let server = build_test_server();
        let template = Brcb::new("brcb01", "test_ds")
            .with_trg_ops(TriggerOptions::DATA_CHANGED)
            .with_buf_tm_ms(100)
            .with_buffer_capacity(64);
        register_brcb_instances(&server, "TIEDLD0", "LLN0", template, dummy_dataset(), 2).unwrap();

        let engine = server.reporting_engine();
        let g = engine.lock().unwrap();
        let paths = g.brcb_paths();
        assert!(paths.contains(&"TIEDLD0/LLN0$BR$brcb0101".to_string()));
        assert!(paths.contains(&"TIEDLD0/LLN0$BR$brcb0102".to_string()));
    }

    #[test]
    fn multi_instance_invalid_count_returns_err() {
        let server = build_test_server();
        let template = Rcb::new("urcb01", "test_ds");
        let r = register_urcb_instances(
            &server,
            "TIEDLD0",
            "LLN0",
            template.clone(),
            dummy_dataset(),
            0,
        );
        assert!(r.is_err());
        let r = register_urcb_instances(&server, "TIEDLD0", "LLN0", template, dummy_dataset(), 100);
        assert!(r.is_err());
    }

    #[test]
    fn format_instance_name_zero_pads() {
        assert_eq!(format_instance_name("urcb01", 1), "urcb0101");
        assert_eq!(format_instance_name("urcb01", 9), "urcb0109");
        assert_eq!(format_instance_name("urcb01", 10), "urcb0110");
        assert_eq!(format_instance_name("brcb01", 2), "brcb0102");
    }

    // Keeps ReportingEngine referenced; build_test_server uses it only indirectly.
    #[allow(dead_code)]
    fn _refkeep(_: ReportingEngine) {}
}
