//! End-to-end tests of the directory services against a scripted server, over
//! real TCP and the full ISO stack.
//!
//! The server answers GetNameList from a script keyed on the domain asked for:
//! a well-formed model, a server that repeats the same page while reporting
//! more names, and a server that keeps reporting new names.

mod support;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn name_list_walk_that_goes_back_is_an_error() {
    let conn = connect("BACK").await;
    let r = conn.get_server_directory(false).await;
    assert!(matches!(r, Err(ClientError::Mms(_))), "got {r:?}");
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
    assert_eq!(
        r,
        Err(ClientError::NameListLimit {
            limit: DEFAULT_MAX_NAME_LIST_NAMES
        })
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
    assert_eq!(r, Err(ClientError::NameListLimit { limit: 3_000 }));
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
