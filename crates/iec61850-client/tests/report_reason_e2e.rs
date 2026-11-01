//! End-to-end tests of the inclusion and the reasons a report subscription
//! exposes.
//!
//! A URCB reports a data set of `Pos.stVal` (`dchg`) and `Pos.q` (`qchg`). A
//! `stVal` change is reported first, then a `q` change alone. The second
//! report carries only `q`, so the subscription state keeps the previous
//! `stVal` value but marks `stVal` as not included and gives it no reason.
//!
//! A scripted server sends a report whose ReasonCode is seven bits long, with
//! bit 6 set, which a report does not define, and a report split into two
//! segments, each delivered with its own inclusion. It also sends a report
//! that is rejected, which must leave the subscription as it was.

mod support;

use bytes::{Bytes, BytesMut};
use iec61850_client::rcb::{RcbHandle, RcbWriteMask};
use iec61850_client::report::{ClientReport, ReasonForInclusion, ReportCallback};
use iec61850_client::IedConnection;
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_mms::{
    decode_confirmed_read_request, encode_confirmed_read_response, AccessResult, MmsData,
    ReadResponse,
};
use iec61850_model::{
    cdc, DataAttribute, IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder,
    MmsValue, NodeRef, ObjectRef,
};
use iec61850_server::{
    Dataset, DatasetEntry, IedServer, OptFlds, Rcb, ReportControl, TriggerOptions,
};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use support::{tlv, Plan};

const RCB_PATH: &str = "IED1LD0/LLN0$RP$urcbPos";

fn build_model() -> Arc<IedModel> {
    let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
    let cswi = LogicalNodeBuilder::new("", "CSWI", "1")
        .add_do(cdc::dps("Pos", cdc::CdcOptions::NONE))
        .build()
        .expect("cswi");
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .add_ln(cswi)
        .build()
        .expect("ld");
    Arc::new(
        IedModelBuilder::new("IED1")
            .add_ld(ld)
            .expect("add_ld")
            .build()
            .expect("model"),
    )
}

fn resolve_da(model: &IedModel, path: &str) -> DataAttribute {
    let r = ObjectRef::parse_iec(path).expect("parse_iec");
    match model.node_by_object_ref(&r).expect("node lookup") {
        NodeRef::Da(da) => DataAttribute::with_shared_value(
            da.name.clone(),
            da.fc,
            da.ty,
            da.trg_ops,
            Arc::clone(&da.value),
        ),
        _ => panic!("expected a data attribute at {path}"),
    }
}

/// Polls until the handler has seen `count` reports; fails after four seconds.
async fn wait_for_reports(
    conn: &IedConnection,
    seen: &Mutex<Vec<Arc<ClientReport>>>,
    count: usize,
) -> Arc<ClientReport> {
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        conn.poll_reports(Duration::from_millis(200))
            .await
            .expect("poll reports");
        let seen = seen.lock().unwrap();
        if seen.len() >= count {
            return Arc::clone(&seen[count - 1]);
        }
    }
    panic!("report {count} did not arrive");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn member_omitted_from_a_report_has_no_reason() {
    let server = IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()
        .expect("server build");
    let model = server.model();
    let st_val = resolve_da(&model, "IED1LD0/CSWI1.Pos.stVal");
    let q = resolve_da(&model, "IED1LD0/CSWI1.Pos.q");
    let mut ds = Dataset::new("LLN0$dsPos");
    ds.push(DatasetEntry::new(
        "IED1LD0/CSWI1$ST$Pos$stVal",
        Arc::clone(&st_val.value),
    ));
    ds.push(DatasetEntry::new(
        "IED1LD0/CSWI1$ST$Pos$q",
        Arc::clone(&q.value),
    ));
    let rcb = Rcb::new("urcbPos", "LLN0$dsPos")
        .with_trg_ops(TriggerOptions::DATA_CHANGED | TriggerOptions::QUALITY_CHANGED)
        .with_opt_flds(
            OptFlds::SEQ_NUM | OptFlds::REASON | OptFlds::DATA_SET | OptFlds::DATA_REFERENCE,
        )
        .with_buf_tm_ms(10);
    server
        .register_urcb(ReportControl::new(RCB_PATH, rcb), ds)
        .expect("register_urcb");
    let handle = server.start().await.expect("server start");

    let mms = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    let conn = IedConnection::with_mms_client(mms);
    conn.connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    let seen: Arc<Mutex<Vec<Arc<ClientReport>>>> = Arc::default();
    let sink = Arc::clone(&seen);
    let cb: ReportCallback = Arc::new(move |snap: Arc<ClientReport>| {
        sink.lock().unwrap().push(snap);
    });
    conn.install_report_handler(Some(RCB_PATH.to_string()), RCB_PATH, None, cb)
        .await
        .expect("install handler");
    let mut rcb = RcbHandle::new(RCB_PATH).unwrap();
    rcb.set_resv(true);
    rcb.set_rpt_ena(true);
    conn.set_rcb_values(&rcb, RcbWriteMask::RESV | RcbWriteMask::RPT_ENA, false)
        .await
        .expect("enable the control block");

    let dbpos_on = MmsValue::BitString {
        padding: 6,
        data: vec![0x80],
    };
    server.update_bit_string_from_int(&st_val, 2).unwrap();
    let first = wait_for_reports(&conn, &seen, 1).await;
    assert_eq!(first.included, vec![true, false]);
    assert_eq!(first.data_set_values[0], Some(dbpos_on.clone()));
    assert_eq!(first.reasons[0], ReasonForInclusion::DATA_CHANGE);
    assert_eq!(first.reasons[1], ReasonForInclusion::empty());

    server.update_bit_string(&q, &[0x60, 0x00], 3).unwrap();
    let second = wait_for_reports(&conn, &seen, 2).await;
    assert_eq!(second.included, vec![false, true]);
    assert_eq!(second.reasons[1], ReasonForInclusion::QUALITY_CHANGE);
    assert_eq!(
        second.data_set_values[1],
        Some(MmsValue::BitString {
            padding: 3,
            data: vec![0x60, 0x00],
        })
    );
    // `stVal` keeps the value of the first report but is not part of this one.
    assert_eq!(second.data_set_values[0], Some(dbpos_on));
    assert_eq!(
        second.data_references[0].as_deref(),
        Some("IED1LD0/CSWI1$ST$Pos$stVal")
    );
    assert_eq!(second.reasons[0], ReasonForInclusion::empty());

    conn.disconnect().await.expect("disconnect");
}

/// An unbuffered report `RPT` of one member, with OptFlds asking for the
/// reason and a seven-bit ReasonCode carrying quality-change and bit 6.
fn seven_bit_reason_report(rpt_id: &str) -> Bytes {
    let values = [
        MmsData::VisibleString(rpt_id.to_string()),
        // OptFlds, ten bits: reason-for-inclusion is wire bit 3.
        MmsData::BitString {
            padding: 6,
            data: vec![0x10, 0x00],
        },
        // Inclusion, one member.
        MmsData::BitString {
            padding: 7,
            data: vec![0x80],
        },
        MmsData::Boolean(true),
        // ReasonCode, seven bits: quality-change is wire bit 2.
        MmsData::BitString {
            padding: 1,
            data: vec![0x22],
        },
    ];
    let mut results = BytesMut::new();
    for v in &values {
        v.encode(&mut results);
    }
    let mut name = BytesMut::new();
    tlv(0x80, b"RPT", &mut name);
    let mut body = BytesMut::new();
    tlv(0xa1, &name, &mut body);
    tlv(0xa0, &results, &mut body);
    let mut combined = BytesMut::new();
    tlv(0xa0, &body, &mut combined);
    let mut pdu = BytesMut::new();
    tlv(0xa3, &combined, &mut pdu);
    pdu.freeze()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn seven_bit_reason_code_is_accepted_and_bit_six_ignored() {
    const RPT_ID: &str = "rptLong";
    // Any Read is answered with a boolean, followed by the report.
    let port = support::start(Arc::new(|mms: &[u8], _seq: u32| {
        let (invoke_id, _) = decode_confirmed_read_request(mms).ok()?;
        let mut buf = BytesMut::new();
        encode_confirmed_read_response(
            invoke_id,
            &ReadResponse {
                variable_access_spec: None,
                list_of_access_result: vec![AccessResult::Success(MmsData::Boolean(true))],
            },
            &mut buf,
        );
        Some(Plan {
            reply: Some(buf.freeze()),
            after: vec![seven_bit_reason_report(RPT_ID)],
            ..Plan::default()
        })
    }))
    .await;

    let conn = IedConnection::with_mms_client(
        MmsClientBuilder::new()
            .connect_timeout_ms(3_000)
            .request_timeout_ms(3_000)
            .build(),
    );
    conn.connect("127.0.0.1", port).await.expect("connect");
    let seen: Arc<Mutex<Vec<Arc<ClientReport>>>> = Arc::default();
    let sink = Arc::clone(&seen);
    let cb: ReportCallback = Arc::new(move |snap: Arc<ClientReport>| {
        sink.lock().unwrap().push(snap);
    });
    conn.install_report_handler(
        Some(RPT_ID.to_string()),
        "IED1LD0/LLN0$RP$urcbLong",
        None,
        cb,
    )
    .await
    .expect("install handler");
    conn.read_object("IED1LD0/LLN0.Beh.stVal", iec61850_model::FC::St)
        .await
        .expect("read");

    let report = wait_for_reports(&conn, &seen, 1).await;
    assert_eq!(report.data_set_values[0], Some(MmsValue::Boolean(true)));
    assert_eq!(report.included, vec![true]);
    assert_eq!(report.reasons[0], ReasonForInclusion::QUALITY_CHANGE);
}

/// Wraps the access results of an unbuffered report `RPT` in an
/// InformationReport PDU.
fn information_report(values: &[MmsData]) -> Bytes {
    let mut results = BytesMut::new();
    for v in values {
        v.encode(&mut results);
    }
    let mut name = BytesMut::new();
    tlv(0x80, b"RPT", &mut name);
    let mut body = BytesMut::new();
    tlv(0xa1, &name, &mut body);
    tlv(0xa0, &results, &mut body);
    let mut combined = BytesMut::new();
    tlv(0xa0, &body, &mut combined);
    let mut pdu = BytesMut::new();
    tlv(0xa3, &combined, &mut pdu);
    pdu.freeze()
}

/// Encodes a three-member inclusion bitstring.
fn inclusion3(bits: [bool; 3]) -> MmsData {
    let byte = bits
        .iter()
        .enumerate()
        .fold(0u8, |acc, (i, &b)| if b { acc | (0x80 >> i) } else { acc });
    MmsData::BitString {
        padding: 5,
        data: vec![byte],
    }
}

/// One segment of a general-interrogation report of a three-member data set,
/// with SeqNum 5 and the reason for inclusion.
fn gi_segment(
    rpt_id: &str,
    sub_seq_num: u64,
    more: bool,
    bits: [bool; 3],
    values: &[i64],
) -> Bytes {
    // ReasonCode, six bits: general-interrogation is wire bit 5.
    let gi = MmsData::BitString {
        padding: 2,
        data: vec![0x04],
    };
    let mut items = vec![
        MmsData::VisibleString(rpt_id.to_string()),
        // OptFlds, ten bits: sequence-number is wire bit 1, reason-for-
        // inclusion bit 3 and segmentation bit 9.
        MmsData::BitString {
            padding: 6,
            data: vec![0x50, 0x40],
        },
        MmsData::Unsigned(5),
        MmsData::Unsigned(sub_seq_num),
        MmsData::Boolean(more),
        inclusion3(bits),
    ];
    items.extend(values.iter().map(|&v| MmsData::Integer(v)));
    items.extend(values.iter().map(|_| gi.clone()));
    information_report(&items)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn segmented_report_is_delivered_per_segment_with_its_own_inclusion() {
    const RPT_ID: &str = "rptSeg";
    // Any Read is answered with a boolean, followed by both segments.
    let port = support::start(Arc::new(|mms: &[u8], _seq: u32| {
        let (invoke_id, _) = decode_confirmed_read_request(mms).ok()?;
        let mut buf = BytesMut::new();
        encode_confirmed_read_response(
            invoke_id,
            &ReadResponse {
                variable_access_spec: None,
                list_of_access_result: vec![AccessResult::Success(MmsData::Boolean(true))],
            },
            &mut buf,
        );
        Some(Plan {
            reply: Some(buf.freeze()),
            after: vec![
                gi_segment(RPT_ID, 0, true, [true, true, false], &[1, 2]),
                gi_segment(RPT_ID, 1, false, [false, false, true], &[3]),
            ],
            ..Plan::default()
        })
    }))
    .await;

    let conn = IedConnection::with_mms_client(
        MmsClientBuilder::new()
            .connect_timeout_ms(3_000)
            .request_timeout_ms(3_000)
            .build(),
    );
    conn.connect("127.0.0.1", port).await.expect("connect");
    let seen: Arc<Mutex<Vec<Arc<ClientReport>>>> = Arc::default();
    let sink = Arc::clone(&seen);
    let cb: ReportCallback = Arc::new(move |snap: Arc<ClientReport>| {
        sink.lock().unwrap().push(snap);
    });
    conn.install_report_handler(
        Some(RPT_ID.to_string()),
        "IED1LD0/LLN0$RP$urcbSeg",
        None,
        cb,
    )
    .await
    .expect("install handler");
    conn.read_object("IED1LD0/LLN0.Beh.stVal", iec61850_model::FC::St)
        .await
        .expect("read");

    let first = wait_for_reports(&conn, &seen, 1).await;
    let seg = first.segmentation.expect("segmentation");
    assert_eq!((seg.sub_seq_num, seg.more_segments_follow), (0, true));
    assert_eq!(first.seq_num, Some(5));
    assert_eq!(first.included, vec![true, true, false]);
    assert_eq!(
        first.data_set_values,
        vec![Some(MmsValue::Integer(1)), Some(MmsValue::Integer(2)), None]
    );

    let second = wait_for_reports(&conn, &seen, 2).await;
    let seg = second.segmentation.expect("segmentation");
    assert_eq!((seg.sub_seq_num, seg.more_segments_follow), (1, false));
    assert_eq!(second.seq_num, Some(5));
    // The inclusion and the reasons are those of this segment; the values the
    // first segment carried are kept.
    assert_eq!(second.included, vec![false, false, true]);
    assert_eq!(
        second.reasons,
        vec![
            ReasonForInclusion::empty(),
            ReasonForInclusion::empty(),
            ReasonForInclusion::GI
        ]
    );
    assert_eq!(
        second.data_set_values,
        vec![
            Some(MmsValue::Integer(1)),
            Some(MmsValue::Integer(2)),
            Some(MmsValue::Integer(3))
        ]
    );
    assert_eq!(seen.lock().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_report_leaves_the_subscription_unchanged() {
    const RPT_ID: &str = "rptRejected";
    // A two-member report whose DatSet exceeds the MMS object-name limit,
    // then a valid one-member report.
    let rejected = information_report(&[
        MmsData::VisibleString(RPT_ID.to_string()),
        // OptFlds, ten bits: data-set-name is wire bit 4.
        MmsData::BitString {
            padding: 6,
            data: vec![0x08, 0x00],
        },
        MmsData::VisibleString(format!("IED1LD0/LLN0${}", "d".repeat(121))),
        MmsData::BitString {
            padding: 6,
            data: vec![0xc0],
        },
        MmsData::Integer(1),
        MmsData::Integer(2),
    ]);
    let valid = information_report(&[
        MmsData::VisibleString(RPT_ID.to_string()),
        MmsData::BitString {
            padding: 6,
            data: vec![0x00, 0x00],
        },
        MmsData::BitString {
            padding: 7,
            data: vec![0x80],
        },
        MmsData::Integer(7),
    ]);
    let port = support::start(Arc::new(move |mms: &[u8], _seq: u32| {
        let (invoke_id, _) = decode_confirmed_read_request(mms).ok()?;
        let mut buf = BytesMut::new();
        encode_confirmed_read_response(
            invoke_id,
            &ReadResponse {
                variable_access_spec: None,
                list_of_access_result: vec![AccessResult::Success(MmsData::Boolean(true))],
            },
            &mut buf,
        );
        Some(Plan {
            reply: Some(buf.freeze()),
            after: vec![rejected.clone(), valid.clone()],
            ..Plan::default()
        })
    }))
    .await;

    let conn = IedConnection::with_mms_client(
        MmsClientBuilder::new()
            .connect_timeout_ms(3_000)
            .request_timeout_ms(3_000)
            .build(),
    );
    conn.connect("127.0.0.1", port).await.expect("connect");
    let seen: Arc<Mutex<Vec<Arc<ClientReport>>>> = Arc::default();
    let sink = Arc::clone(&seen);
    let cb: ReportCallback = Arc::new(move |snap: Arc<ClientReport>| {
        sink.lock().unwrap().push(snap);
    });
    conn.install_report_handler(
        Some(RPT_ID.to_string()),
        "IED1LD0/LLN0$RP$urcbRejected",
        None,
        cb,
    )
    .await
    .expect("install handler");
    conn.read_object("IED1LD0/LLN0.Beh.stVal", iec61850_model::FC::St)
        .await
        .expect("read");

    let report = wait_for_reports(&conn, &seen, 1).await;
    assert_eq!(report.dataset_size, Some(1));
    assert_eq!(report.data_set_values, vec![Some(MmsValue::Integer(7))]);
    assert_eq!(report.data_set_name, None);
    assert_eq!(seen.lock().unwrap().len(), 1);
}
