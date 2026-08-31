//! End-to-end tests that GetNameList reports the registered control blocks and
//! data sets, and only those.
//!
//! A server is started on loopback over `examples/models/demo.cid` and browsed
//! with the client's GetLogicalNodeDirectory. The CID declares two data sets,
//! two report control blocks and one GOOSE control block, which lets one model
//! separate the two cases that matter: a declared object that nothing
//! registered is not listed, because the Read paths resolve a control block
//! through the reporting engine and a data set through the data set registry
//! and would answer object-non-existent for it; a registered object is listed,
//! whether or not the model declares it.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use iec61850_client::{AcsiClass, IedConnection};
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_model::IedModel;
use iec61850_model::MmsValue;
use iec61850_model::FC;
use iec61850_server::reporting::{Brcb, BufferedReportControl};
use iec61850_server::{
    Dataset, IedServer, IedServerConfig, InMemoryLogStorage, LogControl, LogControlBlock, Rcb,
    ReportControl, ServerHandle, TriggerOptions,
};

const IED_NAME: &str = "DemoIED";
const DOMAIN: &str = "DemoIEDLD0";
const LN_REF: &str = "DemoIEDLD0/LLN0";
/// Path of the log control block the LCB tests register, as the registry keys
/// it within the domain.
const LCB_ITEM: &str = "LLN0$LG$evlog";
/// IEC reference of that same control block, for a Read under FC = LG.
const LCB_REF: &str = "DemoIEDLD0/LLN0.evlog";

/// Registers `LLN0$LG$evlog` on `server`, with a data set and an integrity
/// period so a read back has something other than a default to show.
fn register_demo_lcb(server: &IedServer) {
    let lcb = LogControlBlock::new("evlog")
        .with_dataset("LLN0$dsMeas")
        .with_intg_pd_ms(1_000);
    let lc = LogControl::new(format!("{DOMAIN}/{LCB_ITEM}"), lcb)
        .with_storage(Arc::new(InMemoryLogStorage::new()));
    server.register_log_control(DOMAIN, LCB_ITEM, Arc::new(lc));
}

/// The CID ships inside this crate, so the path resolves in a published package
/// as well as in the repository.
const DEMO_CID: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/models/demo.cid");

fn load_demo_model() -> Arc<IedModel> {
    let xml = std::fs::read_to_string(Path::new(DEMO_CID))
        .unwrap_or_else(|e| panic!("cannot read {DEMO_CID}: {e}"));
    let raw = iec61850_scl::parse_scl(&xml).expect("parse demo.cid");
    let resolved = iec61850_scl::ResolvedScl::from_raw(raw).expect("resolve demo.cid");
    Arc::new(
        resolved
            .build_model(IED_NAME)
            .expect("build the demo model"),
    )
}

/// Builds a server over the demo CID with nothing registered, so every control
/// block and data set the CID declares is present in the model and absent from
/// the registries.
fn build_server() -> IedServer {
    IedServer::builder()
        .model(load_demo_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig::default())
        .build()
        .expect("build the server")
}

async fn connect(handle: &ServerHandle) -> IedConnection {
    let mms = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    let conn = IedConnection::with_mms_client(mms);
    conn.connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect to the server");
    conn
}

/// Reads one class of ACSI object out of `LLN0`, with a timeout so a hung
/// server fails the test instead of blocking it.
async fn ln_directory(conn: &IedConnection, class: AcsiClass) -> Vec<String> {
    tokio::time::timeout(
        Duration::from_secs(5),
        conn.get_logical_node_directory(LN_REF, class),
    )
    .await
    .unwrap_or_else(|_| panic!("GetLogicalNodeDirectory({class:?}) timed out"))
    .unwrap_or_else(|e| panic!("GetLogicalNodeDirectory({class:?}) failed: {e}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declared_but_unregistered_control_block_or_data_set_is_not_listed() {
    let server = build_server();
    let handle = server.start().await.expect("start the server");
    let conn = connect(&handle).await;

    // The CID declares urcbMeas, brcbMeas, gcbStatus, dsMeas and dsStatus, and
    // this server registered none of them. Listing any of them would advertise
    // a name that Read answers object-non-existent for.
    for (class, declared) in [
        (AcsiClass::Urcb, "urcbMeas"),
        (AcsiClass::Brcb, "brcbMeas"),
        (AcsiClass::GoCb, "gcbStatus"),
    ] {
        let names = ln_directory(&conn, class).await;
        assert!(
            names.is_empty(),
            "{class:?} must be empty while {declared} is unregistered, got {names:?}"
        );
    }

    let datasets = ln_directory(&conn, AcsiClass::DataSet).await;
    assert!(
        datasets.is_empty(),
        "no data set is registered, so the list must be empty, got {datasets:?}"
    );

    // A log control block reaches the directory through the log control
    // registry alone, and this server registered none.
    let lcbs = ln_directory(&conn, AcsiClass::Lcb).await;
    assert!(
        lcbs.is_empty(),
        "no log control block is registered, so the list must be empty, got {lcbs:?}"
    );

    // The logical node itself is unaffected: its data objects still come from
    // the model.
    let dos = ln_directory(&conn, AcsiClass::DataObject).await;
    assert!(
        dos.iter().any(|n| n == "NamPlt"),
        "the data objects of the model must still be listed, got {dos:?}"
    );

    let _ = conn.disconnect().await;
    handle.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registered_control_blocks_and_data_sets_are_listed_under_their_class() {
    let server = build_server();

    // The CID's own objects, now bound to the runtime the way `server_from_scl`
    // binds them.
    let meas = Dataset::new("LLN0$dsMeas");
    let status = Dataset::new("LLN0$dsStatus");
    server.register_dataset(DOMAIN.to_string(), status);
    server
        .register_urcb(
            ReportControl::new(
                format!("{DOMAIN}/LLN0$RP$urcbMeas"),
                Rcb::new("urcbMeas", meas.name.clone()).with_trg_ops(TriggerOptions::NONE),
            ),
            meas.clone(),
        )
        .expect("register the unbuffered control block");
    server
        .register_brcb(
            BufferedReportControl::new(
                format!("{DOMAIN}/LLN0$BR$brcbMeas"),
                Brcb::new("brcbMeas", meas.name.clone()).with_trg_ops(TriggerOptions::NONE),
            ),
            meas,
        )
        .expect("register the buffered control block");

    let handle = server.start().await.expect("start the server");
    let conn = connect(&handle).await;

    let urcbs = ln_directory(&conn, AcsiClass::Urcb).await;
    assert_eq!(
        urcbs,
        vec!["urcbMeas".to_string()],
        "the registered unbuffered control block must be listed alone"
    );

    let brcbs = ln_directory(&conn, AcsiClass::Brcb).await;
    assert_eq!(
        brcbs,
        vec!["brcbMeas".to_string()],
        "the registered buffered control block must be listed alone"
    );

    let mut datasets = ln_directory(&conn, AcsiClass::DataSet).await;
    datasets.sort();
    assert_eq!(
        datasets,
        vec!["dsMeas".to_string(), "dsStatus".to_string()],
        "both registered data sets must be listed"
    );

    // gcbStatus is declared by the CID but was never registered, so it stays
    // out even though its siblings are now in.
    let gocbs = ln_directory(&conn, AcsiClass::GoCb).await;
    assert!(
        gocbs.is_empty(),
        "an unregistered GOOSE control block must stay unlisted, got {gocbs:?}"
    );

    // A control block is not a data object, so the two lists stay disjoint.
    let dos = ln_directory(&conn, AcsiClass::DataObject).await;
    assert!(
        !dos.iter().any(|n| n == "urcbMeas" || n == "brcbMeas"),
        "a control block must not appear among the data objects, got {dos:?}"
    );

    let _ = conn.disconnect().await;
    handle.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_control_block_the_model_does_not_declare_is_listed_once_when_registered() {
    let server = build_server();

    // Named so that nothing in the CID can account for the entry.
    let dataset = Dataset::new("LLN0$dsRuntime");
    server
        .register_urcb(
            ReportControl::new(
                format!("{DOMAIN}/LLN0$RP$urcbRuntime"),
                Rcb::new("urcbRuntime", dataset.name.clone()).with_trg_ops(TriggerOptions::NONE),
            ),
            dataset,
        )
        .expect("register the runtime control block");

    let handle = server.start().await.expect("start the server");
    let conn = connect(&handle).await;

    let urcbs = ln_directory(&conn, AcsiClass::Urcb).await;
    assert_eq!(
        urcbs,
        vec!["urcbRuntime".to_string()],
        "a control block absent from the model must be listed once when registered"
    );

    let datasets = ln_directory(&conn, AcsiClass::DataSet).await;
    assert_eq!(
        datasets,
        vec!["dsRuntime".to_string()],
        "register_urcb also registers its data set, which must be listed once"
    );

    let _ = conn.disconnect().await;
    handle.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_registered_log_control_block_is_listed_under_the_lcb_class() {
    let server = build_server();

    // The CID declares no log control block, so nothing but the registration
    // can account for the entry.
    register_demo_lcb(&server);

    let handle = server.start().await.expect("start the server");
    let conn = connect(&handle).await;

    let lcbs = ln_directory(&conn, AcsiClass::Lcb).await;
    assert_eq!(
        lcbs,
        vec!["evlog".to_string()],
        "the registered log control block must be listed alone"
    );

    // A log control block is not a data object, so the two lists stay disjoint:
    // the LG functional constraint is excluded from the data object listing.
    let dos = ln_directory(&conn, AcsiClass::DataObject).await;
    assert!(
        !dos.iter().any(|n| n == "evlog"),
        "a log control block must not appear among the data objects, got {dos:?}"
    );
    assert!(
        dos.iter().any(|n| n == "NamPlt"),
        "the data objects of the model must still be listed, got {dos:?}"
    );

    // Registering a log control block leaves the other classes untouched.
    for class in [AcsiClass::Urcb, AcsiClass::Brcb, AcsiClass::GoCb] {
        let names = ln_directory(&conn, class).await;
        assert!(names.is_empty(), "{class:?} must stay empty, got {names:?}");
    }

    let _ = conn.disconnect().await;
    handle.stop().await;
}

/// Every name GetNameList reports must be readable, so the `$LG$` name the
/// directory now advertises is read back here: the whole control block, each
/// served attribute, and the two error classes that separate an attribute this
/// server does not serve from a name that does not exist.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listed_log_control_block_is_readable() {
    let server = build_server();
    register_demo_lcb(&server);

    let handle = server.start().await.expect("start the server");
    let conn = connect(&handle).await;

    // The whole control block answers a structure of the served attributes.
    let whole = conn
        .read_object(LCB_REF, FC::Lg)
        .await
        .expect("a listed log control block must be readable");
    match whole {
        MmsValue::Structure(members) => assert_eq!(
            members.len(),
            5,
            "the structure must carry LogEna, LogRef, DatSet, TrgOps and IntgPd, got {members:?}"
        ),
        other => panic!("expected a structure, got {other:?}"),
    }

    // LogEna starts false: enabling is a separate write, and the control block
    // is constructed disabled whatever its configured default.
    let log_ena = conn
        .read_boolean(&format!("{LCB_REF}.LogEna"), FC::Lg)
        .await
        .expect("LogEna must be readable");
    assert!(
        !log_ena,
        "a freshly registered control block is not enabled"
    );

    let dat_set = conn
        .read_string(&format!("{LCB_REF}.DatSet"), FC::Lg)
        .await
        .expect("DatSet must be readable");
    assert_eq!(dat_set, "LLN0$dsMeas");

    // No LogRef is configured, so the default applies. It carries the logical
    // device, because a LogRef is an MMS path a client hands straight to
    // ReadJournal: the value the server serves must be one the client can parse.
    let log_ref = conn
        .read_string(&format!("{LCB_REF}.LogRef"), FC::Lg)
        .await
        .expect("LogRef must be readable");
    let (log_domain, log_item) = iec61850_client::parse_journal_ref(&log_ref)
        .expect("the served LogRef must be a reference the client can resolve");
    assert_eq!(log_domain, DOMAIN);
    assert_eq!(log_item, "LLN0$GeneralLog");
    assert_eq!(log_ref, "DemoIEDLD0/LLN0$GeneralLog");

    let intg_pd = conn
        .read_uint32(&format!("{LCB_REF}.IntgPd"), FC::Lg)
        .await
        .expect("IntgPd must be readable");
    assert_eq!(intg_pd, 1_000);

    // TrgOps is a bit string, so it is read untyped.
    let trg_ops = conn
        .read_object(&format!("{LCB_REF}.TrgOps"), FC::Lg)
        .await
        .expect("TrgOps must be readable");
    assert!(
        matches!(trg_ops, MmsValue::BitString { .. }),
        "TrgOps must be a bit string, got {trg_ops:?}"
    );

    // An attribute the standard declares but this server does not serve is
    // reported as unsupported, not as absent: the name exists.
    let unserved = conn
        .read_object(&format!("{LCB_REF}.NewEntrTm"), FC::Lg)
        .await
        .expect_err("an unserved attribute must fail");
    let unserved = unserved.to_string();
    assert!(
        unserved.contains("object-access-unsupported")
            || unserved.contains("ObjectAccessUnsupported"),
        "an unserved attribute must answer object-access-unsupported, got `{unserved}`"
    );

    // A control block that was never registered is absent, not unsupported.
    let missing = conn
        .read_object("DemoIEDLD0/LLN0.nosuchlog", FC::Lg)
        .await
        .expect_err("an unregistered control block must fail");
    let missing = missing.to_string();
    assert!(
        missing.contains("object-non-existent") || missing.contains("ObjectNonExistent"),
        "an unregistered control block must answer object-non-existent, got `{missing}`"
    );

    let _ = conn.disconnect().await;
    handle.stop().await;
}
