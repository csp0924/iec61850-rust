//! Report member inclusion on the wire.
//!
//! A data set holds `Pos.stVal` (`dchg`) and `Pos.q` (`qchg`). A report carries
//! only the members whose trigger fired since the previous report, each with
//! its own reason for inclusion, per IEC 61850-7-2; triggers that fall inside
//! one buffer time are merged into one report. Reports are decoded without any
//! client-side report state, so what is checked is what the server sends: a
//! URCB is driven through `IedServer` and received on a raw MMS association, a
//! BRCB is driven on a `ReportingEngine` whose sink keeps the PDUs and whose
//! clock is passed in.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use iec61850_client::mms_compat::mms_data_to_mms_value;
use iec61850_client::report::parse::{parse_report, ParsedReport, ReasonForInclusion};
use iec61850_mms::mms::client::{MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::common::ObjectName;
use iec61850_mms::mms::pdu::information_report::{decode_information_report, VariableAccessSpec};
use iec61850_mms::mms::MmsData;
use iec61850_model::{
    cdc, DataAttribute, IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder,
    MmsValue, NodeRef, ObjectRef,
};
use iec61850_server::connection::ConnectionId;
use iec61850_server::reporting::{Brcb, BufferedReportControl, EntryId};
use iec61850_server::{
    Dataset, DatasetEntry, IedServer, InclusionFlag, OptFlds, Rcb, ReportControl, ReportSink,
    ReportingEngine, ServerHandle, TriggerOptions,
};

const DOMAIN: &str = "IED1LD0";
const ST_VAL_REF: &str = "IED1LD0/CSWI1$ST$Pos$stVal";
const Q_REF: &str = "IED1LD0/CSWI1$ST$Pos$q";

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

fn trg_ops() -> TriggerOptions {
    TriggerOptions::DATA_CHANGED | TriggerOptions::QUALITY_CHANGED
}

fn opt_flds() -> OptFlds {
    OptFlds::SEQ_NUM | OptFlds::REASON | OptFlds::DATA_SET | OptFlds::DATA_REFERENCE
}

fn dbpos_on() -> MmsValue {
    MmsValue::BitString {
        padding: 6,
        data: vec![0x80],
    }
}

fn quality_invalid_overflow() -> MmsValue {
    MmsValue::BitString {
        padding: 3,
        data: vec![0x60, 0x00],
    }
}

fn assert_only(
    report: &ParsedReport,
    member_ref: &str,
    reason: ReasonForInclusion,
    value: MmsValue,
) {
    let expected_bits = if member_ref == ST_VAL_REF {
        [true, false]
    } else {
        [false, true]
    };
    assert_eq!(report.inclusion_bits, expected_bits, "inclusion bitmap");
    assert_eq!(report.data_references, [member_ref], "data references");
    assert_eq!(report.reasons, [reason], "reasons for inclusion");
    assert_eq!(report.data_values, [value], "data values");
}

fn assert_merged(report: &ParsedReport) {
    assert_eq!(report.inclusion_bits, [true, true], "inclusion bitmap");
    assert_eq!(
        report.data_references,
        [ST_VAL_REF, Q_REF],
        "data references"
    );
    assert_eq!(
        report.reasons,
        [
            ReasonForInclusion::DATA_CHANGE,
            ReasonForInclusion::QUALITY_CHANGE
        ],
        "reasons for inclusion"
    );
    assert_eq!(
        report.data_values,
        [dbpos_on(), quality_invalid_overflow()],
        "data values"
    );
}

/// Decodes an InformationReport, given the bytes after the outer
/// unconfirmed-PDU tag and length; `None` for a report other than `RPT`.
fn parse_information_report(inner: &[u8]) -> Option<ParsedReport> {
    let report = decode_information_report(inner).expect("decode information report");
    let is_rpt = matches!(
        &report.variable_access_spec,
        VariableAccessSpec::VariableListName(ObjectName::VmdSpecific(s)) if s == "RPT"
    );
    if !is_rpt {
        return None;
    }
    let elements: Vec<MmsValue> = report
        .list_of_access_result
        .iter()
        .map(mms_data_to_mms_value)
        .collect();
    Some(parse_report(&MmsValue::Array(elements)).expect("parse report"))
}

// ── URCB, through IedServer and a raw MMS association ───────────────────────

/// A running server with one enabled URCB over `[stVal, q]` and a raw MMS
/// association that receives its reports.
struct UrcbFixture {
    server: IedServer,
    _handle: ServerHandle,
    mms: MmsClient,
    st_val: DataAttribute,
    q: DataAttribute,
}

async fn start_urcb(buf_tm_ms: u32) -> UrcbFixture {
    let server = IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()
        .expect("server build");
    let model = server.model();
    let st_val = resolve_da(&model, "IED1LD0/CSWI1.Pos.stVal");
    let q = resolve_da(&model, "IED1LD0/CSWI1.Pos.q");

    let mut ds = Dataset::new("LLN0$dsPos");
    ds.push(DatasetEntry::new(ST_VAL_REF, Arc::clone(&st_val.value)));
    ds.push(DatasetEntry::new(Q_REF, Arc::clone(&q.value)));
    let rcb = Rcb::new("urcbPos", "LLN0$dsPos")
        .with_trg_ops(trg_ops())
        .with_opt_flds(opt_flds())
        .with_buf_tm_ms(buf_tm_ms);
    server
        .register_urcb(ReportControl::new("IED1LD0/LLN0$RP$urcbPos", rcb), ds)
        .expect("register_urcb");

    let handle = server.start().await.expect("server start");
    let mut mms = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    mms.connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    for item in ["LLN0$RP$urcbPos$Resv", "LLN0$RP$urcbPos$RptEna"] {
        mms.write(DOMAIN, item, MmsData::Boolean(true))
            .await
            .expect("enable the control block");
    }

    UrcbFixture {
        server,
        _handle: handle,
        mms,
        st_val,
        q,
    }
}

/// Receives the next report; fails after four seconds.
async fn next_report(mms: &mut MmsClient) -> ParsedReport {
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
        if let Some(report) = parse_information_report(&inner) {
            return report;
        }
    }
}

/// After the report of a `stVal` change, a `q` change alone is reported with
/// `q` as the only member, whatever the buffer time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn urcb_quality_change_report_carries_only_q() {
    for buf_tm_ms in [0, 10] {
        let mut f = start_urcb(buf_tm_ms).await;

        f.server.update_bit_string_from_int(&f.st_val, 2).unwrap();
        let first = next_report(&mut f.mms).await;
        assert_only(
            &first,
            ST_VAL_REF,
            ReasonForInclusion::DATA_CHANGE,
            dbpos_on(),
        );

        f.server.update_bit_string(&f.q, &[0x60, 0x00], 3).unwrap();
        let second = next_report(&mut f.mms).await;
        assert_only(
            &second,
            Q_REF,
            ReasonForInclusion::QUALITY_CHANGE,
            quality_invalid_overflow(),
        );
    }
}

/// A `stVal` change and a `q` change inside one buffer time are merged into
/// one report that carries each member with its own reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn urcb_triggers_inside_one_buffer_time_merge() {
    let mut f = start_urcb(1_000).await;

    f.server.update_bit_string_from_int(&f.st_val, 2).unwrap();
    f.server.update_bit_string(&f.q, &[0x60, 0x00], 3).unwrap();
    assert_merged(&next_report(&mut f.mms).await);
}

// ── BRCB, on a ReportingEngine with an injected clock ───────────────────────

const BRCB_PATH: &str = "IED1LD0/LLN0$BR$brcbPos";
const CONN: ConnectionId = 7;

/// A sink that keeps every PDU it is handed.
#[derive(Default)]
struct CaptureSink {
    pdus: Mutex<Vec<Bytes>>,
}

impl ReportSink for CaptureSink {
    fn send_pdu(&self, conn_id: ConnectionId, pdu: Bytes) -> bool {
        assert_eq!(conn_id, CONN);
        self.pdus.lock().unwrap().push(pdu);
        true
    }
}

impl CaptureSink {
    /// Decodes and removes every report sent so far.
    fn take_reports(&self) -> Vec<ParsedReport> {
        let pdus = std::mem::take(&mut *self.pdus.lock().unwrap());
        pdus.iter()
            .map(|pdu| {
                // The unconfirmed-PDU tag 0xa3, then a short or long-form length.
                assert_eq!(pdu[0], 0xa3, "unconfirmed PDU tag");
                let header = match pdu[1] {
                    n if n < 0x80 => 2,
                    n => 2 + usize::from(n & 0x7f),
                };
                parse_information_report(&pdu[header..]).expect("a report")
            })
            .collect()
    }
}

/// A BRCB over `[stVal, q]`, enabled for connection `CONN` and resynchronized
/// to the head of its buffer.
fn brcb_engine(buf_tm_ms: u32) -> (ReportingEngine, Arc<CaptureSink>) {
    let sink = Arc::new(CaptureSink::default());
    let mut engine = ReportingEngine::new(sink.clone());
    let mut ds = Dataset::new("LLN0$dsPos");
    ds.push(DatasetEntry::new(
        ST_VAL_REF,
        Arc::new(RwLock::new(dbpos_on())),
    ));
    ds.push(DatasetEntry::new(
        Q_REF,
        Arc::new(RwLock::new(quality_invalid_overflow())),
    ));
    let brcb = Brcb::new("brcbPos", "LLN0$dsPos")
        .with_trg_ops(trg_ops())
        .with_opt_flds(opt_flds())
        .with_buf_tm_ms(buf_tm_ms);
    engine
        .register_brcb_with_dataset(BufferedReportControl::new(BRCB_PATH, brcb), ds)
        .expect("register_brcb_with_dataset");
    let brcb = engine.get_brcb(BRCB_PATH).unwrap();
    brcb.apply_entry_id_write(EntryId::ZERO).unwrap().unwrap();
    {
        let mut state = brcb.lock_state().unwrap();
        state.rpt_ena = true;
        state.client_conn_id = Some(CONN);
    }
    (engine, sink)
}

/// Raises the trigger `IedServer` raises for a `stVal` (`dchg`) update.
fn trigger_st_val(engine: &ReportingEngine, now_ms: u64) {
    engine.on_brcb_value_updated(
        &ST_VAL_REF.to_string(),
        dbpos_on(),
        InclusionFlag::VALUE_CHANGED,
        now_ms,
    );
}

/// Raises the trigger `IedServer` raises for a `q` (`qchg`) update.
fn trigger_q(engine: &ReportingEngine, now_ms: u64) {
    engine.on_brcb_value_updated(
        &Q_REF.to_string(),
        quality_invalid_overflow(),
        InclusionFlag::QUALITY_CHANGED,
        now_ms,
    );
}

/// After the report of a `stVal` change, a `q` change alone is reported with
/// `q` as the only member, whatever the buffer time.
#[test]
fn brcb_quality_change_report_carries_only_q() {
    for buf_tm_ms in [0u32, 10] {
        let (engine, sink) = brcb_engine(buf_tm_ms);
        let past_buf_tm = Duration::from_millis(u64::from(buf_tm_ms) + 1);

        trigger_st_val(&engine, 1_000);
        engine.tick_brcb(Instant::now() + past_buf_tm, 1_000);
        let reports = sink.take_reports();
        assert_eq!(reports.len(), 1, "buf_tm_ms {buf_tm_ms}");
        assert_only(
            &reports[0],
            ST_VAL_REF,
            ReasonForInclusion::DATA_CHANGE,
            dbpos_on(),
        );

        trigger_q(&engine, 2_000);
        engine.tick_brcb(Instant::now() + past_buf_tm, 2_000);
        let reports = sink.take_reports();
        assert_eq!(reports.len(), 1, "buf_tm_ms {buf_tm_ms}");
        assert_only(
            &reports[0],
            Q_REF,
            ReasonForInclusion::QUALITY_CHANGE,
            quality_invalid_overflow(),
        );
    }
}

/// A `stVal` change and a `q` change inside one buffer time are merged into
/// one report that carries each member with its own reason.
#[test]
fn brcb_triggers_inside_one_buffer_time_merge() {
    let (engine, sink) = brcb_engine(1_000);

    trigger_st_val(&engine, 1_000);
    trigger_q(&engine, 1_000);
    engine.tick_brcb(Instant::now(), 1_000);
    assert!(
        sink.take_reports().is_empty(),
        "the buffer time is still running"
    );

    engine.tick_brcb(Instant::now() + Duration::from_millis(1_001), 2_001);
    let reports = sink.take_reports();
    assert_eq!(reports.len(), 1);
    assert_merged(&reports[0]);
}
