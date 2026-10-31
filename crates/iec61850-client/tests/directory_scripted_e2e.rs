//! End-to-end tests of the directory services against a scripted server, over
//! real TCP and the full ISO stack.
//!
//! The server answers GetNameList from a script keyed on the domain asked for:
//! a well-formed model, servers that page names in an order other than byte
//! order or send the continuation name again, a server that repeats the same
//! page while reporting more names, and a server that keeps reporting new
//! names.

mod support;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use iec61850_client::directory::DEFAULT_MAX_NAME_LIST_NAMES;
use iec61850_client::{AcsiClass, ClientError, IedConnection};
use iec61850_mms::mms::pdu::get_name_list::{
    decode_confirmed_get_name_list_request, encode_confirmed_get_name_list_response,
    GetNameListResponse, ObjectScope,
};
use iec61850_mms::MmsClientBuilder;
use support::Plan;

/// Pages of the endless walk.
const ENDLESS_PAGE: usize = 2_000;
/// Pages the endless walk sends before reporting no more names; enough to pass
/// the client's limit of one million names.
const ENDLESS_PAGES: usize = 600;
/// Pages the repeating walk sends before reporting no more names.
const REPEATED_PAGES: u32 = 20;
/// Names in each page of the walk sorted without regard to case.
const NOCASE_PAGE: usize = 3;

/// GetNameList requests for the `STUCKEND` domain.
static STUCKEND_REQUESTS: AtomicU32 = AtomicU32::new(0);

/// The variables of the `NOCASE` domain, in the order of a server that sorts
/// names without regard to case, which is not byte order.
fn nocase_names() -> Vec<String> {
    let mut list = names(&[
        "GGIO1",
        "GGIO1$CO",
        "GGIO1$CO$SPCSO1",
        "GGIO1$CO$SPCSO1$Oper",
        "GGIO1$CO$SPCSO1$Oper$ctlNum",
        "GGIO1$CO$SPCSO1$Oper$ctlVal",
        "GGIO1$CO$SPCSO1$Oper$origin",
        "GGIO1$CO$SPCSO1$Oper$T",
        "GGIO1$CO$SPCSO1$Oper$Test",
        "GGIO1$ST",
        "GGIO1$ST$Ind1",
        "GGIO1$ST$Ind1$q",
        "GGIO1$ST$Ind1$stVal",
        "GGIO1$ST$Ind1$t",
        "LLN0",
        "LLN0$ST",
        "LLN0$ST$Mod",
        "LLN0$ST$Mod$stVal",
    ]);
    list.sort_by_key(|name| name.to_lowercase());
    list
}

/// The page of `list` that continues after `after`, and whether more follow.
fn page_after(list: &[String], after: Option<&str>, size: usize) -> (Vec<String>, bool) {
    let from = after.map_or(0, |after| {
        list.iter()
            .position(|n| n == after)
            .map_or(list.len(), |i| i + 1)
    });
    let page: Vec<String> = list.iter().skip(from).take(size).cloned().collect();
    (page, from + size < list.len())
}

fn name_list(invoke_id: u32, identifiers: Vec<String>, more_follows: bool) -> Plan {
    let mut buf = BytesMut::new();
    encode_confirmed_get_name_list_response(
        invoke_id,
        &GetNameListResponse {
            identifiers,
            more_follows,
        },
        &mut buf,
    );
    Plan::reply(buf.freeze())
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// Answers GetNameList. The VMD scope lists one domain, chosen by `domain`;
/// that domain's variables follow the script of the same name.
fn script_for(domain: &'static str) -> Arc<support::Script> {
    Arc::new(move |mms: &[u8], seq: u32| {
        let (invoke_id, req) = decode_confirmed_get_name_list_request(mms).ok()?;
        match req.object_scope {
            ObjectScope::VmdSpecific => Some(name_list(invoke_id, names(&[domain]), false)),
            ObjectScope::DomainSpecific(_) => match domain {
                "MODEL" => Some(name_list(
                    invoke_id,
                    names(&[
                        "GGIO1",
                        "GGIO1$ST",
                        "GGIO1$ST$Ind1",
                        "LLN0",
                        "LLN0$SP",
                        "LLN0$SP$SGCB",
                    ]),
                    false,
                )),
                // The same page every time, with moreFollows set until the
                // script gives up.
                "REPEAT" => Some(name_list(
                    invoke_id,
                    names(&["GGIO1", "GGIO1$ST"]),
                    seq < REPEATED_PAGES,
                )),
                // Two pages in order.
                "PAGED" => match req.continue_after.as_deref() {
                    None => Some(name_list(invoke_id, names(&["GGIO1", "GGIO1$ST"]), true)),
                    Some(_) => Some(name_list(invoke_id, names(&["LLN0"]), false)),
                },
                // A second page that goes back before the first one.
                "BACK" => match req.continue_after.as_deref() {
                    None => Some(name_list(invoke_id, names(&["LLN0", "LLN0$SP"]), true)),
                    Some("LLN0$SP") => {
                        Some(name_list(invoke_id, names(&["GGIO1", "GGIO1$ST"]), true))
                    }
                    Some(_) => Some(name_list(invoke_id, names(&["MMXU1"]), false)),
                },
                // Names sorted without regard to case, a few to a page.
                "NOCASE" => {
                    let (page, more) =
                        page_after(&nocase_names(), req.continue_after.as_deref(), NOCASE_PAGE);
                    Some(name_list(invoke_id, page, more))
                }
                // Every continuation starts with the name it continues after.
                "INCLUSIVE" => match req.continue_after.as_deref() {
                    None => Some(name_list(invoke_id, names(&["GGIO1", "GGIO1$ST"]), true)),
                    Some("GGIO1$ST") => {
                        Some(name_list(invoke_id, names(&["GGIO1$ST", "LLN0"]), true))
                    }
                    Some(_) => Some(name_list(invoke_id, names(&["LLN0", "LLN0$ST"]), false)),
                },
                // Every continuation brings only names already sent, ending on a
                // name other than its continuation, until the script gives up.
                "RECYCLE" => match req.continue_after.as_deref() {
                    None => Some(name_list(
                        invoke_id,
                        names(&["GGIO1", "LLN0", "MMXU1"]),
                        true,
                    )),
                    Some(after) => {
                        let others: Vec<String> = ["GGIO1", "LLN0", "MMXU1"]
                            .iter()
                            .filter(|n| **n != after)
                            .map(|n| n.to_string())
                            .collect();
                        Some(name_list(invoke_id, others, seq < REPEATED_PAGES))
                    }
                },
                // A continuation that ends on the name it continues after.
                "STUCKEND" => {
                    STUCKEND_REQUESTS.fetch_add(1, Ordering::SeqCst);
                    match req.continue_after.as_deref() {
                        None => Some(name_list(invoke_id, names(&["GGIO1", "LLN0"]), true)),
                        Some(_) => Some(name_list(invoke_id, names(&["MMXU1", "LLN0"]), true)),
                    }
                }
                // A new page of names every time, past the client's limit.
                "ENDLESS" => {
                    let page = seq as usize;
                    let list = (0..ENDLESS_PAGE)
                        .map(|i| format!("V{:07}", page * ENDLESS_PAGE + i))
                        .collect();
                    Some(name_list(invoke_id, list, page < ENDLESS_PAGES))
                }
                _ => None,
            },
            ObjectScope::AaSpecific => None,
        }
    })
}

async fn connect(domain: &'static str) -> IedConnection {
    let port = support::start(script_for(domain)).await;
    let conn = IedConnection::with_mms_client(
        MmsClientBuilder::new()
            .connect_timeout_ms(3_000)
            .request_timeout_ms(3_000)
            .build(),
    );
    conn.connect("127.0.0.1", port).await.expect("connect");
    conn
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sgcb_is_listed_only_in_lln0() {
    let conn = connect("MODEL").await;
    assert_eq!(
        conn.get_logical_node_directory("MODEL/LLN0", AcsiClass::Sgcb)
            .await
            .expect("lln0 directory"),
        vec!["SGCB".to_string()]
    );
    assert_eq!(
        conn.get_logical_node_directory("MODEL/GGIO1", AcsiClass::Sgcb)
            .await
            .expect("ggio1 directory"),
        Vec::<String>::new()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn well_formed_name_list_walk_completes() {
    let conn = connect("MODEL").await;
    let lds = conn.get_server_directory(false).await.expect("directory");
    assert_eq!(lds, vec!["MODEL".to_string()]);
    let lns = conn
        .get_logical_device_directory("MODEL")
        .await
        .expect("ld directory");
    assert_eq!(lns, vec!["GGIO1".to_string(), "LLN0".to_string()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn name_list_walk_that_does_not_advance_is_an_error() {
    let conn = connect("REPEAT").await;
    let r = conn.get_server_directory(false).await;
    assert!(matches!(r, Err(ClientError::Mms(_))), "got {r:?}");
}

/// A page whose names sort before the continuation is accepted: no order is
/// required of the names.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn name_list_walk_out_of_byte_order_completes() {
    let conn = connect("BACK").await;
    let lns = conn
        .get_logical_device_directory("BACK")
        .await
        .expect("ld directory");
    assert_eq!(lns, names(&["LLN0", "GGIO1", "MMXU1"]));
}

/// A walk over small pages from a server that sorts names without regard to
/// case returns every name once, in the order of the server.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn name_list_walk_sorted_without_regard_to_case_completes() {
    let conn = connect("NOCASE").await;
    let all = nocase_names();
    let lns = conn
        .get_logical_device_directory("NOCASE")
        .await
        .expect("ld directory");
    assert_eq!(lns, names(&["GGIO1", "LLN0"]));
    let vars = conn
        .get_logical_node_variables("NOCASE/GGIO1")
        .await
        .expect("ln variables");
    let expected: Vec<String> = all
        .iter()
        .filter_map(|n| n.strip_prefix("GGIO1$").map(str::to_string))
        .collect();
    assert_eq!(vars, expected);
    assert!(expected
        .windows(2)
        .any(|w| w[0].as_bytes() > w[1].as_bytes()));
}

/// A server that starts each continuation with the name it continues after
/// yields every name once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn name_list_walk_that_repeats_the_continuation_yields_each_name_once() {
    let conn = connect("INCLUSIVE").await;
    let model = conn
        .get_device_model_from_server()
        .await
        .expect("device model");
    assert_eq!(
        model.logical_devices[0].variables,
        names(&["GGIO1", "GGIO1$ST", "LLN0", "LLN0$ST"])
    );
}

/// A page that reports more names but ends on the name it continues after
/// ends the walk at once, even when it brings a new name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn name_list_walk_that_ends_on_its_continuation_is_an_error() {
    let conn = connect("STUCKEND").await;
    let r = conn.get_server_directory(false).await;
    assert!(matches!(r, Err(ClientError::Mms(_))), "got {r:?}");
    assert_eq!(STUCKEND_REQUESTS.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn name_list_walk_over_ordered_pages_completes() {
    let conn = connect("PAGED").await;
    let lns = conn
        .get_logical_device_directory("PAGED")
        .await
        .expect("ld directory");
    assert_eq!(lns, vec!["GGIO1".to_string(), "LLN0".to_string()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn name_list_walk_past_the_name_limit_is_an_error() {
    let conn = connect("ENDLESS").await;
    assert_eq!(conn.max_name_list_names(), DEFAULT_MAX_NAME_LIST_NAMES);
    let r = conn.get_server_directory(false).await;
    assert!(
        matches!(r, Err(ClientError::NameListLimit { limit, .. }) if limit == DEFAULT_MAX_NAME_LIST_NAMES),
        "{r:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn name_list_walk_past_a_configured_limit_is_an_error() {
    let port = support::start(script_for("ENDLESS")).await;
    let conn = IedConnection::with_mms_client(
        MmsClientBuilder::new()
            .connect_timeout_ms(3_000)
            .request_timeout_ms(3_000)
            .build(),
    )
    .with_max_name_list_names(3_000);
    conn.connect("127.0.0.1", port).await.expect("connect");
    let r = conn.get_server_directory(false).await;
    assert!(
        matches!(r, Err(ClientError::NameListLimit { limit: 3_000, .. })),
        "{r:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn name_list_walk_within_a_configured_limit_completes() {
    let port = support::start(script_for("MODEL")).await;
    let conn = IedConnection::with_mms_client(
        MmsClientBuilder::new()
            .connect_timeout_ms(3_000)
            .request_timeout_ms(3_000)
            .build(),
    )
    .with_max_name_list_names(6);
    conn.connect("127.0.0.1", port).await.expect("connect");
    let lns = conn
        .get_logical_device_directory("MODEL")
        .await
        .expect("ld directory");
    assert_eq!(lns, vec!["GGIO1".to_string(), "LLN0".to_string()]);
}

/// Answers a Conclude with a Conclude-ErrorPDU and every other request as the
/// `MODEL` script does.
fn refusing_conclude() -> Arc<support::Script> {
    let model = script_for("MODEL");
    Arc::new(move |mms: &[u8], seq: u32| {
        if mms == [0x8b, 0x00] {
            // [13] IMPLICIT ServiceError: errorClass conclude [9],
            // further-communication-required(1)
            return Some(Plan::reply(Bytes::from_static(&[
                0xad, 0x05, 0xa0, 0x03, 0x89, 0x01, 0x01,
            ])));
        }
        model(mms, seq)
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_conclude_keeps_the_device_model() {
    let port = support::start(refusing_conclude()).await;
    let conn = IedConnection::with_mms_client(
        MmsClientBuilder::new()
            .connect_timeout_ms(3_000)
            .request_timeout_ms(3_000)
            .build(),
    );
    conn.connect("127.0.0.1", port).await.expect("connect");
    conn.get_server_directory(false).await.expect("directory");

    assert_eq!(conn.disconnect().await, Err(ClientError::ConcludeRejected));
    assert!(conn.is_connected());
    assert!(
        conn.cached_device_model().await.is_some(),
        "the association is still open, so its model is kept"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completed_disconnect_drops_the_device_model() {
    let conn = connect("MODEL").await;
    conn.get_server_directory(false).await.expect("directory");
    assert!(conn.cached_device_model().await.is_some());

    conn.disconnect().await.expect("disconnect");
    assert!(!conn.is_connected());
    assert!(conn.cached_device_model().await.is_none());
}

/// A server that reports more names but sends only names already received
/// ends the walk, although each page ends on a different name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn name_list_walk_without_new_names_is_an_error() {
    let conn = connect("RECYCLE").await;
    let r = conn.get_server_directory(false).await;
    assert!(matches!(r, Err(ClientError::Mms(_))), "got {r:?}");
}
