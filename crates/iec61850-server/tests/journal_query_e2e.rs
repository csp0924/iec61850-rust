//! End-to-end tests of ReadJournal over a real MMS association: how a journal
//! is named and what a request selects from it.

use std::net::SocketAddr;
use std::sync::Arc;

use iec61850_mms::mms::client::{MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::get_name_list::ObjectClass;
use iec61850_mms::mms::pdu::ReadJournalRequest;
use iec61850_model::{IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder};
use iec61850_server::logging::{InMemoryLogStorage, LogControl, LogControlBlock};
use iec61850_server::{IedServer, IedServerConfig, ServerHandle};

const DOM: &str = "TESTLD0";

fn model() -> Arc<IedModel> {
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(LogicalNodeBuilder::lln0().build().unwrap())
        .build()
        .unwrap();
    Arc::new(
        IedModelBuilder::new("TEST")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap(),
    )
}

fn server() -> IedServer {
    IedServer::builder()
        .model(model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig::default())
        .build()
        .expect("build server")
}

async fn client(h: &ServerHandle) -> MmsClient {
    let mut c = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    c.connect("127.0.0.1", h.bound_addr.port())
        .await
        .expect("connect");
    c
}

async fn readable(c: &mut MmsClient, item: &str) -> bool {
    c.read_journal(&ReadJournalRequest::time_range(DOM, item, 0, u64::MAX / 2))
        .await
        .is_ok()
}

/// A journal answers to the name its LogRef gives it, and only to that name:
/// neither the path a control block is registered under nor any other key
/// reads it, and GetNameList lists exactly the names that read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_journal_answers_only_to_its_log_ref() {
    let srv = server();
    let with_log_ref = LogControl::new(
        format!("{DOM}/LLN0$LG$evlog"),
        LogControlBlock::new("evlog").with_log_ref(format!("{DOM}/LLN0$EventLog")),
    )
    .with_storage(Arc::new(InMemoryLogStorage::new()));
    srv.register_log_control(DOM, "LLN0$LG$evlog", Arc::new(with_log_ref));
    // No LogRef: the default `<LD>/<LN>$GeneralLog` names the journal.
    let by_instance_key = LogControl::new(
        format!("{DOM}/GGIO1$Instance"),
        LogControlBlock::new("inst"),
    )
    .with_storage(Arc::new(InMemoryLogStorage::new()));
    srv.register_log_control(DOM, "GGIO1$Instance", Arc::new(by_instance_key));
    let h = srv.start().await.unwrap();
    let mut c = client(&h).await;

    let (journals, more) = c
        .get_name_list(ObjectClass::Journal, Some(DOM), None)
        .await
        .expect("journal names");
    assert!(!more);
    assert_eq!(journals, vec!["GGIO1$GeneralLog", "LLN0$EventLog"]);
    for name in &journals {
        assert!(readable(&mut c, name).await, "listed journal {name} reads");
    }
    for key in ["LLN0$LG$evlog", "GGIO1$Instance"] {
        assert!(
            !readable(&mut c, key).await,
            "registry key {key} names no journal"
        );
    }
    c.disconnect().await.ok();
    h.stop().await;
}
