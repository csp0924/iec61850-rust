//! End-to-end tests of the directory services against a scripted server, over
//! real TCP and the full ISO stack.
//!
//! The server answers GetNameList from a script keyed on the domain asked for:
//! a well-formed model, a server that repeats the same page while reporting
//! more names, and a server that keeps reporting new names.

mod support;

use std::sync::Arc;

use bytes::BytesMut;
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
async fn name_list_walk_past_the_name_limit_is_an_error() {
    let conn = connect("ENDLESS").await;
    let r = conn.get_server_directory(false).await;
    assert!(matches!(r, Err(ClientError::Mms(_))), "got {r:?}");
}
