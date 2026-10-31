//! Report segmentation at the PDU size an association negotiated.
//!
//! Every test drives a started `IedServer` from a raw `MmsClient` over TCP and
//! the full ISO stack. The client proposes a small maximum PDU size, so a
//! general interrogation or a buffered entry over the data set does not fit in
//! one MMSpdu. IEC 61850-8-1 §6.2.2.2 (b) bounds every MMSpdu by the
//! negotiated size, and §17.2.1 makes the inclusion bitstring of each segment
//! mark only the members that segment carries.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use iec61850_client::mms_compat::mms_data_to_mms_value;
use iec61850_client::report::parse::{parse_report, ParsedReport};
use iec61850_mms::mms::client::{MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::common::ObjectName;
use iec61850_mms::mms::pdu::information_report::{decode_information_report, VariableAccessSpec};
use iec61850_mms::mms::MmsData;
use iec61850_model::{
    DataAttribute, DataAttributeType, IedModel, IedModelBuilder, LogicalDeviceBuilder,
    LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::reporting::{Brcb, BufferedReportControl};
use iec61850_server::{
    Dataset, DatasetEntry, IedServer, OptFlds, Rcb, ReportControl, ServerHandle, TriggerOptions,
};

const DOMAIN: &str = "IED1LD0";
const URCB_ITEM: &str = "LLN0$RP$urcbSeg";
const BRCB_ITEM: &str = "LLN0$BR$brcbSeg";
/// Members of the data set; their references and values take about 3000
/// bytes, three or more segments of a 1024-byte PDU.
const MEMBERS: usize = 60;
const SMALL_PDU: u32 = 1024;

fn build_model() -> Arc<IedModel> {
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(LogicalNodeBuilder::lln0().build().expect("lln0"))
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

fn member_ref(i: usize) -> String {
    format!("{DOMAIN}/GGIO1$MX$AnIn{i:03}$mag$i")
}

struct Fixture {
    server: IedServer,
    handle: ServerHandle,
    members: Vec<DataAttribute>,
}

/// Starts a server with one URCB and one BRCB over a data set of `MEMBERS`
/// INT32 values; the BRCB buffers a data change for `brcb_buf_tm_ms`.
async fn start(brcb_buf_tm_ms: u32) -> Fixture {
    let server = IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()
        .expect("server build");
    let members: Vec<DataAttribute> = (0..MEMBERS)
        .map(|i| {
            DataAttribute::with_shared_value(
                "i",
                FC::Mx,
                DataAttributeType::Int32,
                TrgOps::DCHG,
                Arc::new(RwLock::new(MmsValue::Integer(i as i64))),
            )
        })
        .collect();
    let data_set = || {
        let mut ds = Dataset::new("LLN0$dsSeg");
        for (i, da) in members.iter().enumerate() {
            ds.push(DatasetEntry::new(member_ref(i), Arc::clone(&da.value)));
        }
        ds
    };
    let trg_ops = TriggerOptions::DATA_CHANGED | TriggerOptions::GI;
    let opt_flds = OptFlds::SEQ_NUM | OptFlds::REASON | OptFlds::DATA_REFERENCE;
    let rcb = Rcb::new("urcbSeg", "LLN0$dsSeg")
        .with_trg_ops(trg_ops)
        .with_opt_flds(opt_flds);
    let brcb = Brcb::new("brcbSeg", "LLN0$dsSeg")
        .with_trg_ops(trg_ops)
        .with_opt_flds(opt_flds | OptFlds::ENTRY_ID | OptFlds::TIME_STAMP)
        .with_buf_tm_ms(brcb_buf_tm_ms);
    server
        .register_urcb(
            ReportControl::new(format!("{DOMAIN}/{URCB_ITEM}"), rcb),
            data_set(),
        )
        .expect("register_urcb");
    server
        .register_brcb(
            BufferedReportControl::new(format!("{DOMAIN}/{BRCB_ITEM}"), brcb),
            data_set(),
        )
        .expect("register_brcb");
    let handle = server.start().await.expect("server start");
    Fixture {
        server,
        handle,
        members,
    }
}

impl Fixture {
    async fn connect(&self, max_pdu: Option<u32>) -> MmsClient {
        let mut builder = MmsClientBuilder::new()
            .connect_timeout_ms(3_000)
            .request_timeout_ms(3_000);
        if let Some(size) = max_pdu {
            builder = builder.local_max_pdu_size(size);
        }
        let mut mms = builder.build();
        mms.connect("127.0.0.1", self.handle.bound_addr.port())
            .await
            .expect("connect");
        mms
    }
}

/// One received report PDU: its size as an MMSpdu and its decoded fields.
struct Segment {
    pdu_len: usize,
    report: ParsedReport,
}

/// Returns the size of the MMSpdu whose unconfirmed-PDU content is `inner`:
/// the `0xa3` tag, its BER length, and the content.
fn mms_pdu_len(inner: &[u8]) -> usize {
    let length_len = match inner.len() {
        0..=127 => 1,
        128..=255 => 2,
        _ => 3,
    };
    1 + length_len + inner.len()
}

async fn next_segment(mms: &mut MmsClient) -> Segment {
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "no report arrived");
        let Some(inner) = mms
            .recv_unconfirmed_pdu_with_timeout(remaining)
            .await
            .expect("receive")
        else {
            continue;
        };
        let decoded = decode_information_report(&inner).expect("decode information report");
        let is_rpt = matches!(
            &decoded.variable_access_spec,
            VariableAccessSpec::VariableListName(ObjectName::VmdSpecific(s)) if s == "RPT"
        );
        if !is_rpt {
            continue;
        }
        let elements: Vec<MmsValue> = decoded
            .list_of_access_result
            .iter()
            .map(mms_data_to_mms_value)
            .collect();
        let report = parse_report(&MmsValue::Array(elements)).expect("each segment parses");
        return Segment {
            pdu_len: mms_pdu_len(&inner),
            report,
        };
    }
}

/// Receives the segments of one report, up to the one that clears
/// MoreSegmentsFollow.
async fn next_segmented_report(mms: &mut MmsClient) -> Vec<Segment> {
    let mut segments = Vec::new();
    loop {
        let s = next_segment(mms).await;
        let more = s
            .report
            .segmentation
            .expect("a segmented report carries SubSeqNum")
            .more_segments_follow;
        segments.push(s);
        if !more {
            return segments;
        }
        assert!(segments.len() < 64, "the report does not end");
    }
}

/// Checks the segments of one report over the whole data set: each fits the
/// negotiated size, they share SqNum and count SubSeqNum up from zero, and
/// their inclusion bitstrings mark disjoint sets of members whose union is the
/// data set, with the references and values of exactly those members.
fn assert_covers_the_data_set(segments: &[Segment], expected: impl Fn(usize) -> i64) {
    assert!(segments.len() >= 3, "{} segments", segments.len());
    let seq_num = segments[0].report.seq_num;
    let mut seen = [false; MEMBERS];
    for (n, s) in segments.iter().enumerate() {
        let r = &s.report;
        assert!(
            s.pdu_len <= SMALL_PDU as usize,
            "segment {n}: {} bytes over the negotiated {SMALL_PDU}",
            s.pdu_len
        );
        assert_eq!(r.seq_num, seq_num, "segment {n}: SqNum");
        let seg = r.segmentation.expect("segmentation");
        assert_eq!(usize::from(seg.sub_seq_num), n, "segment {n}: SubSeqNum");
        assert_eq!(seg.more_segments_follow, n + 1 < segments.len());
        assert_eq!(r.inclusion_bits.len(), MEMBERS, "segment {n}: bit count");
        let marked: Vec<usize> = (0..MEMBERS).filter(|i| r.inclusion_bits[*i]).collect();
        assert!(!marked.is_empty(), "segment {n} carries no member");
        assert_eq!(r.data_references.len(), marked.len(), "segment {n}");
        assert_eq!(r.data_values.len(), marked.len(), "segment {n}");
        assert_eq!(r.reasons.len(), marked.len(), "segment {n}");
        for (k, i) in marked.iter().enumerate() {
            assert!(!seen[*i], "member {i} is marked by two segments");
            seen[*i] = true;
            assert_eq!(r.data_references[k], member_ref(*i), "segment {n}");
            assert_eq!(r.data_values[k], MmsValue::Integer(expected(*i)));
        }
    }
    assert!(seen.iter().all(|s| *s), "a member is in no segment");
}

async fn write(mms: &mut MmsClient, item: &str, value: bool) {
    mms.write(DOMAIN, item, MmsData::Boolean(value))
        .await
        .unwrap_or_else(|e| panic!("write {item}: {e:?}"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn urcb_gi_is_segmented_at_the_negotiated_pdu_size() {
    let f = start(0).await;
    let mut mms = f.connect(Some(SMALL_PDU)).await;
    write(&mut mms, &format!("{URCB_ITEM}$Resv"), true).await;
    write(&mut mms, &format!("{URCB_ITEM}$RptEna"), true).await;
    write(&mut mms, &format!("{URCB_ITEM}$GI"), true).await;
    let segments = next_segmented_report(&mut mms).await;
    assert_covers_the_data_set(&segments, |i| i as i64);

    // The control block keeps reporting after the segmented report.
    f.server.update_int32(&f.members[7], 700).expect("update");
    let s = next_segment(&mut mms).await;
    assert!(s.report.segmentation.is_none(), "one member fits one PDU");
    assert_eq!(s.report.data_references, vec![member_ref(7)]);
    assert_eq!(s.report.data_values, vec![MmsValue::Integer(700)]);
}

/// Control: the same general interrogation fits one PDU for a client that
/// proposes the default maximum PDU size.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn urcb_gi_fits_one_pdu_of_the_default_size() {
    let f = start(0).await;
    let mut mms = f.connect(None).await;
    write(&mut mms, &format!("{URCB_ITEM}$Resv"), true).await;
    write(&mut mms, &format!("{URCB_ITEM}$RptEna"), true).await;
    write(&mut mms, &format!("{URCB_ITEM}$GI"), true).await;
    let s = next_segment(&mut mms).await;
    assert!(s.report.segmentation.is_none());
    assert!(s.pdu_len > SMALL_PDU as usize, "{} bytes", s.pdu_len);
    assert!(s.report.inclusion_bits.iter().all(|b| *b));
    assert_eq!(s.report.data_values.len(), MEMBERS);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brcb_buffered_entry_and_gi_are_segmented_at_the_negotiated_pdu_size() {
    // A buffer time far longer than the test keeps every update in one window
    // until member 0 triggers again and closes it.
    let f = start(600_000).await;
    for (i, da) in f.members.iter().enumerate() {
        f.server.update_int32(da, 1_000 + i as i32).expect("update");
    }
    f.server.update_int32(&f.members[0], 5).expect("retrigger");

    let mut mms = f.connect(Some(SMALL_PDU)).await;
    write(&mut mms, &format!("{BRCB_ITEM}$RptEna"), true).await;
    let entry = next_segmented_report(&mut mms).await;
    assert_covers_the_data_set(&entry, |i| 1_000 + i as i64);
    let entry_id = entry[0].report.entry_id.clone().expect("EntryID");
    let time = entry[0].report.timestamp_ms.expect("TimeOfEntry");
    for s in &entry {
        assert_eq!(s.report.entry_id.as_ref(), Some(&entry_id), "same EntryID");
        assert_eq!(s.report.timestamp_ms, Some(time), "same TimeOfEntry");
    }

    write(&mut mms, &format!("{BRCB_ITEM}$GI"), true).await;
    let gi = next_segmented_report(&mut mms).await;
    assert_covers_the_data_set(&gi, |i| if i == 0 { 5 } else { 1_000 + i as i64 });
    assert_ne!(gi[0].report.entry_id.as_ref(), Some(&entry_id));
    assert_ne!(gi[0].report.seq_num, entry[0].report.seq_num);
}
