//! Registration of the instances of a report control block.
//!
//! A report control block of the model declares how many instances its logical
//! node holds and how they are named (IEC 61850-6 §9.3.8 `RptEnabled` and
//! `indexed`, IEC 61850-8-1 §17.1.2, §17.1.3): with `indexed` set the
//! instances are `<name>01` to `<name>NN`, otherwise the single instance is
//! `<name>`. [`ReportControlBlock::instance_names`] gives the names.
//!
//! Each instance is a control block of its own in the reporting engine, at
//! `<domain>/<LN>$RP$<instance>` or `<domain>/<LN>$BR$<instance>`, with its
//! own reservation, enable state, sequence number and settings and, when
//! buffered, its own report buffer. Every instance starts from the settings
//! the model declares; one whose `RptID` is empty takes its own reference as
//! its report identifier.

use crate::error::Result;
use crate::flags::TriggerOptions;
use crate::reporting::{Brcb, BufferedReportControl, Dataset, Rcb, ReportControl};
use crate::server::IedServer;
use iec61850_model::{ReportControlBlock, TrgOps};

/// Returns the MMS path of every instance of `rcb`, a control block of the
/// logical node `ln_name` of `domain`, in order.
pub(crate) fn instance_paths(domain: &str, ln_name: &str, rcb: &ReportControlBlock) -> Vec<String> {
    let group = if rcb.is_buffered { "BR" } else { "RP" };
    rcb.instance_names()
        .into_iter()
        .map(|name| format!("{domain}/{ln_name}${group}${name}"))
        .collect()
}

/// Registers every instance of `rcb` with `server`, each reporting `dataset`,
/// which the control blocks name `dataset_name`, and returns how many it
/// registered.
///
/// # Errors
///
/// Returns the error of the first registration that fails; the instances
/// registered before it stay registered.
pub(crate) fn register_rcb_instances(
    server: &IedServer,
    domain: &str,
    ln_name: &str,
    rcb: &ReportControlBlock,
    dataset_name: &str,
    dataset: &Dataset,
) -> Result<usize> {
    let names = rcb.instance_names();
    let paths = instance_paths(domain, ln_name, rcb);
    let trg_ops = trigger_options(rcb.trg_ops);
    for (name, path) in names.iter().zip(&paths) {
        if rcb.is_buffered {
            let brcb = Brcb::new(name.clone(), dataset_name)
                .with_rpt_id(rcb.rpt_id.clone())
                .with_conf_rev(rcb.conf_rev)
                .with_trg_ops(trg_ops)
                .with_opt_flds(rcb.opt_flds)
                .with_buf_tm_ms(rcb.buf_tm_ms)
                .with_intg_pd_ms(rcb.intg_pd_ms)
                .with_owner(rcb.has_owner)
                .with_resv_tms(rcb.has_resv_tms);
            server.register_brcb(
                BufferedReportControl::new(path.clone(), brcb),
                dataset.clone(),
            )?;
        } else {
            let urcb = Rcb::new(name.clone(), dataset_name)
                .with_rpt_id(rcb.rpt_id.clone())
                .with_conf_rev(rcb.conf_rev)
                .with_trg_ops(trg_ops)
                .with_opt_flds(rcb.opt_flds.mask_urcb())
                .with_buf_tm_ms(rcb.buf_tm_ms)
                .with_intg_pd_ms(rcb.intg_pd_ms)
                .with_owner(rcb.has_owner);
            server.register_urcb(ReportControl::new(path.clone(), urcb), dataset.clone())?;
        }
    }
    Ok(paths.len())
}

/// Converts the trigger options of the model into those of the reporting
/// engine.
pub(crate) fn trigger_options(trg: TrgOps) -> TriggerOptions {
    [
        (TrgOps::DCHG, TriggerOptions::DATA_CHANGED),
        (TrgOps::QCHG, TriggerOptions::QUALITY_CHANGED),
        (TrgOps::DUPD, TriggerOptions::DATA_UPDATE),
        (TrgOps::INTEGRITY, TriggerOptions::INTEGRITY),
        (TrgOps::GI, TriggerOptions::GI),
    ]
    .into_iter()
    .filter(|(model, _)| trg.contains(*model))
    .fold(TriggerOptions::NONE, |acc, (_, engine)| acc.union(engine))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporting::{DatasetEntry, OptFlds};
    use crate::IedServerConfig;
    use iec61850_model::{
        DataAttributeType, DataObjectBuilder, IedModelBuilder, LogicalDeviceBuilder,
        LogicalNodeBuilder, MmsValue, FC,
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
        IedServer::builder()
            .model(Arc::new(model))
            .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .config(IedServerConfig::default())
            .build()
            .unwrap()
    }

    fn dataset() -> Dataset {
        let mut ds = Dataset::new("LLN0$ds");
        ds.push(DatasetEntry::new(
            "TIEDLD0/LLN0$ST$Test$stVal",
            Arc::new(RwLock::new(MmsValue::Boolean(false))),
        ));
        ds
    }

    fn rcb(buffered: bool, indexed: bool, max: u32) -> ReportControlBlock {
        let mut rcb = ReportControlBlock::new("rcb", "ds");
        rcb.is_buffered = buffered;
        rcb.indexed = indexed;
        rcb.max_instances = max;
        rcb.trg_ops = TrgOps::DCHG | TrgOps::GI;
        rcb.opt_flds = OptFlds::SEQ_NUM | OptFlds::ENTRY_ID;
        rcb.buf_tm_ms = 50;
        rcb.conf_rev = 3;
        rcb
    }

    #[test]
    fn indexed_instances_are_numbered_from_01() {
        let server = build_test_server();
        let n = register_rcb_instances(
            &server,
            "TIEDLD0",
            "LLN0",
            &rcb(false, true, 2),
            "LLN0$ds",
            &dataset(),
        )
        .unwrap();
        assert_eq!(n, 2);
        let mut paths = server.reporting_engine().lock().unwrap().rcb_paths();
        paths.sort();
        assert_eq!(
            paths,
            vec!["TIEDLD0/LLN0$RP$rcb01", "TIEDLD0/LLN0$RP$rcb02"]
        );
    }

    #[test]
    fn an_instance_that_is_not_indexed_keeps_the_name() {
        let server = build_test_server();
        register_rcb_instances(
            &server,
            "TIEDLD0",
            "LLN0",
            &rcb(true, false, 1),
            "LLN0$ds",
            &dataset(),
        )
        .unwrap();
        assert_eq!(
            server.reporting_engine().lock().unwrap().brcb_paths(),
            vec!["TIEDLD0/LLN0$BR$rcb"]
        );
    }

    #[test]
    fn every_instance_has_its_own_state() {
        let server = build_test_server();
        register_rcb_instances(
            &server,
            "TIEDLD0",
            "LLN0",
            &rcb(false, true, 2),
            "LLN0$ds",
            &dataset(),
        )
        .unwrap();
        let engine = server.reporting_engine();
        let g = engine.lock().unwrap();
        let a = g.get_rcb("TIEDLD0/LLN0$RP$rcb01").unwrap();
        let b = g.get_rcb("TIEDLD0/LLN0$RP$rcb02").unwrap();
        {
            let a = a.lock().unwrap();
            let mut sa = a.lock_state().unwrap();
            sa.resv = true;
            sa.client_conn_id = Some(1);
        }
        let b = b.lock().unwrap();
        let sb = b.lock_state().unwrap();
        assert!(!sb.resv);
        assert_eq!(sb.client_conn_id, None);
        assert_eq!(sb.rpt_id, "TIEDLD0/LLN0$RP$rcb02");
    }

    #[test]
    fn every_buffered_instance_has_its_own_buffer_and_settings() {
        let server = build_test_server();
        register_rcb_instances(
            &server,
            "TIEDLD0",
            "LLN0",
            &rcb(true, true, 2),
            "LLN0$ds",
            &dataset(),
        )
        .unwrap();
        let engine = server.reporting_engine();
        let g = engine.lock().unwrap();
        let a = g.get_brcb("TIEDLD0/LLN0$BR$rcb01").unwrap();
        let b = g.get_brcb("TIEDLD0/LLN0$BR$rcb02").unwrap();
        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(a.brcb.conf_rev, 3);
        assert_eq!(
            a.brcb.trg_ops,
            TriggerOptions::DATA_CHANGED.union(TriggerOptions::GI)
        );
        assert!(a.brcb.opt_flds.contains(OptFlds::ENTRY_ID));
        assert_eq!(b.brcb.buf_tm_ms, 50);
    }

    #[test]
    fn an_unbuffered_instance_drops_the_buffered_option_fields() {
        let server = build_test_server();
        register_rcb_instances(
            &server,
            "TIEDLD0",
            "LLN0",
            &rcb(false, false, 1),
            "LLN0$ds",
            &dataset(),
        )
        .unwrap();
        let engine = server.reporting_engine();
        let g = engine.lock().unwrap();
        let rc = g.get_rcb("TIEDLD0/LLN0$RP$rcb").unwrap();
        let rc = rc.lock().unwrap();
        assert!(!rc.rcb.opt_flds.contains(OptFlds::ENTRY_ID));
        assert!(rc.rcb.opt_flds.contains(OptFlds::SEQ_NUM));
    }

    #[test]
    fn every_trigger_option_converts() {
        assert_eq!(
            trigger_options(
                TrgOps::DCHG | TrgOps::QCHG | TrgOps::DUPD | TrgOps::INTEGRITY | TrgOps::GI
            ),
            TriggerOptions::ALL
        );
        assert_eq!(trigger_options(TrgOps::NONE), TriggerOptions::NONE);
        assert_eq!(
            trigger_options(TrgOps::QCHG),
            TriggerOptions::QUALITY_CHANGED
        );
    }
}
