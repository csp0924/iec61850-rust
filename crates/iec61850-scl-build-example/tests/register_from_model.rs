//! The models `build.rs` generates from `scl/demo.icd` and `scl/schema.icd`,
//! registered with a server in one call: what each file declares is what the
//! server serves.

iec61850_scl::include_compiled_model!("model.rs");

mod schema {
    iec61850_scl::include_compiled_model!("schema_model.rs");
}

use iec61850_server::{FromModelSummary, IedServer};
use std::net::SocketAddr;
use std::sync::Arc;

fn server(model: IedModel) -> IedServer {
    IedServer::builder()
        .model(Arc::new(model))
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()
        .expect("server")
}

/// `demo.icd`: one data set and `urcb01` with `<RptEnabled max="2">`, indexed
/// by default, so two instances, which have Owner through
/// `<ReportSettings owner="true">`; `CSWI1.Pos` declares no `ctlModel` and is
/// no control object.
#[test]
fn the_demo_model_registers_two_report_instances() {
    let server = server(build_Demo_model());
    let summary = server.register_from_model().expect("register_from_model");
    let mut expected = FromModelSummary::default();
    expected.data_sets = 1;
    expected.urcbs = 2;
    assert_eq!(summary, expected);
    let mut paths = server.reporting_engine().lock().unwrap().rcb_paths();
    paths.sort();
    assert_eq!(
        paths,
        vec!["DemoLD0/LLN0$RP$urcb0101", "DemoLD0/LLN0$RP$urcb0102"]
    );
    for path in &paths {
        let rc = server
            .reporting_engine()
            .lock()
            .unwrap()
            .get_rcb(path)
            .expect("registered");
        assert!(rc.lock().unwrap().rcb.with_owner, "{path}");
    }
}

/// `schema.icd`: one data set, `brcbSeq` with three instances, a log control
/// block and a setting group control block; without `<ReportSettings>` the
/// instances have neither Owner nor ResvTms.
#[test]
fn the_schema_model_registers_its_buffered_instances_and_log() {
    let server = server(schema::build_Schema_model());
    let summary = server.register_from_model().expect("register_from_model");
    let mut expected = FromModelSummary::default();
    expected.data_sets = 1;
    expected.brcbs = 3;
    expected.lcbs = 1;
    expected.sgcbs = 1;
    assert_eq!(summary, expected);
    let mut paths = server.reporting_engine().lock().unwrap().brcb_paths();
    paths.sort();
    assert_eq!(
        paths,
        vec![
            "SchemaLD0/LLN0$BR$brcbSeq01",
            "SchemaLD0/LLN0$BR$brcbSeq02",
            "SchemaLD0/LLN0$BR$brcbSeq03",
        ]
    );
    for path in &paths {
        let brcb = server
            .reporting_engine()
            .lock()
            .unwrap()
            .get_brcb(path)
            .expect("registered");
        assert!(!brcb.brcb.with_owner, "{path}");
        assert!(!brcb.brcb.with_resv_tms, "{path}");
    }
    let logs = server.log_controls();
    let logs = logs.read().unwrap();
    let lcb = logs
        .get(&("SchemaLD0".to_string(), "LLN0$LG$lcbSeq".to_string()))
        .expect("lcbSeq");
    assert_eq!(lcb.lcb.log_ref.as_deref(), Some("SchemaLD0/LLN0$Log"));
    assert!(!lcb.lcb.include_reason_code);
    assert_eq!(lcb.lcb.intg_period_ms, 2000);
}
