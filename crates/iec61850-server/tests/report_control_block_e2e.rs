//! Report control block behavior over a real MMS association.
//!
//! Every test drives a started `IedServer` from a raw `MmsClient` over TCP and
//! the full ISO stack, decodes the InformationReport PDUs with `parse_report`,
//! and checks what IEC 61850-7-2 and IEC 61850-8-1 require of the reports and
//! of the control block services.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use iec61850_client::mms_compat::mms_data_to_mms_value;
use iec61850_client::report::parse::{parse_report, ParsedReport, ReasonForInclusion};
use iec61850_mms::mms::client::{ClientError, MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::common::{DataAccessError, ObjectName};
use iec61850_mms::mms::pdu::information_report::{decode_information_report, VariableAccessSpec};
use iec61850_mms::mms::pdu::service_error::{subcode, ErrorClass};
use iec61850_mms::mms::pdu::DefineNamedVariableEntry;
use iec61850_mms::mms::MmsData;
use iec61850_model::{
    cdc, DataAttribute, IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder,
    MmsValue, NodeRef, ObjectRef,
};
use iec61850_server::reporting::{Brcb, BufferedReportControl};
use iec61850_server::{
    Dataset, DatasetEntry, IedServer, OptFlds, Rcb, ReportControl, ServerHandle, TriggerOptions,
};

const DOMAIN: &str = "IED1LD0";
const ST_VAL_REF: &str = "IED1LD0/CSWI1$ST$Pos$stVal";
const Q_REF: &str = "IED1LD0/CSWI1$ST$Pos$q";
const BRCB_PATH: &str = "IED1LD0/LLN0$BR$brcbPos";
const URCB_PATH: &str = "IED1LD0/LLN0$RP$urcbPos";
const BRCB_ITEM: &str = "LLN0$BR$brcbPos";
const URCB_ITEM: &str = "LLN0$RP$urcbPos";

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

fn dbpos(n: u8) -> MmsValue {
    MmsValue::BitString {
        padding: 6,
        data: vec![n << 6],
    }
}

#[derive(Clone)]
struct Cfg {
    trg_ops: TriggerOptions,
    opt_flds: OptFlds,
    buf_tm_ms: u32,
    intg_pd_ms: u32,
    conf_rev: Option<u32>,
    /// Extra data set members that alias `stVal` under long references.
    extra_members: usize,
}

impl Default for Cfg {
    fn default() -> Self {
        Self {
            trg_ops: TriggerOptions::DATA_CHANGED,
            opt_flds: OptFlds::SEQ_NUM | OptFlds::REASON,
            buf_tm_ms: 0,
            intg_pd_ms: 0,
            conf_rev: None,
            extra_members: 0,
        }
    }
}

struct Fixture {
    server: IedServer,
    handle: ServerHandle,
    st_val: DataAttribute,
    q: DataAttribute,
}

/// Starts a server with one BRCB and one URCB over the data set `LLN0$dsPos`,
/// which holds `Pos.stVal`.
async fn start(cfg: Cfg) -> Fixture {
    let server = IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()
        .expect("server build");
    let model = server.model();
    let st_val = resolve_da(&model, "IED1LD0/CSWI1.Pos.stVal");
    let q = resolve_da(&model, "IED1LD0/CSWI1.Pos.q");
    let tail = "x".repeat(90);
    let data_set = || {
        let mut ds = Dataset::new("LLN0$dsPos");
        ds.push(DatasetEntry::new(ST_VAL_REF, Arc::clone(&st_val.value)));
        for i in 0..cfg.extra_members {
            ds.push(DatasetEntry::new(
                format!("IED1LD0/CSWI1$ST$Pos$stVal_alias_{i:04}_{tail}"),
                Arc::clone(&st_val.value),
            ));
        }
        ds
    };

    let mut brcb = Brcb::new("brcbPos", "LLN0$dsPos")
        .with_trg_ops(cfg.trg_ops)
        .with_opt_flds(cfg.opt_flds | OptFlds::ENTRY_ID | OptFlds::BUFFER_OVERFLOW)
        .with_buf_tm_ms(cfg.buf_tm_ms)
        .with_intg_pd_ms(cfg.intg_pd_ms);
    let mut rcb = Rcb::new("urcbPos", "LLN0$dsPos")
        .with_trg_ops(cfg.trg_ops)
        .with_opt_flds(cfg.opt_flds)
        .with_buf_tm_ms(cfg.buf_tm_ms)
        .with_intg_pd_ms(cfg.intg_pd_ms);
    if let Some(c) = cfg.conf_rev {
        brcb = brcb.with_conf_rev(c);
        rcb = rcb.with_conf_rev(c);
    }
    server
        .register_brcb(BufferedReportControl::new(BRCB_PATH, brcb), data_set())
        .expect("register_brcb");
    server
        .register_urcb(ReportControl::new(URCB_PATH, rcb), data_set())
        .expect("register_urcb");

    let handle = server.start().await.expect("server start");
    Fixture {
        server,
        handle,
        st_val,
        q,
    }
}

impl Fixture {
    async fn connect(&self) -> MmsClient {
        let mut mms = MmsClientBuilder::new()
            .connect_timeout_ms(3_000)
            .request_timeout_ms(3_000)
            .build();
        mms.connect("127.0.0.1", self.handle.bound_addr.port())
            .await
            .expect("connect");
        mms
    }

    fn set_st_val(&self, n: u32) {
        self.server
            .update_bit_string_from_int(&self.st_val, n)
            .expect("update stVal");
    }

    fn set_q(&self, data: &[u8]) {
        self.server
            .update_bit_string(&self.q, data, 3)
            .expect("update q");
    }

    /// Registers `LLN0$dsQ`, holding `Pos.q`, as a data set no control block
    /// refers to.
    fn register_ds_q(&self) {
        let mut ds = Dataset::new("LLN0$dsQ");
        ds.push(DatasetEntry::new(Q_REF, Arc::clone(&self.q.value)));
        self.server.register_dataset(DOMAIN, ds);
    }

    async fn wait_for_no_connection(&self) {
        let deadline = Instant::now() + Duration::from_secs(4);
        while self.server.connection_count() > 0 {
            assert!(
                Instant::now() < deadline,
                "the association was not released"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

/// One received report: the raw InformationReport bytes, the access results,
/// and the decoded fields.
struct Received {
    raw: Vec<u8>,
    elements: Vec<MmsValue>,
    parsed: Result<ParsedReport, String>,
}

async fn next_raw_report(mms: &mut MmsClient) -> Received {
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
        let report = decode_information_report(&inner).expect("decode information report");
        let is_rpt = matches!(
            &report.variable_access_spec,
            VariableAccessSpec::VariableListName(ObjectName::VmdSpecific(s)) if s == "RPT"
        );
        if !is_rpt {
            continue;
        }
        let elements: Vec<MmsValue> = report
            .list_of_access_result
            .iter()
            .map(mms_data_to_mms_value)
            .collect();
        return Received {
            raw: inner.to_vec(),
            parsed: parse_report(&MmsValue::Array(elements.clone())).map_err(|e| e.to_string()),
            elements,
        };
    }
}

async fn next_report(mms: &mut MmsClient) -> ParsedReport {
    next_raw_report(mms).await.parsed.expect("parse report")
}

async fn write(mms: &mut MmsClient, item: &str, value: MmsData) -> Result<(), ClientError> {
    mms.write(DOMAIN, item, value).await
}

async fn read(mms: &mut MmsClient, item: &str) -> MmsData {
    mms.read(DOMAIN, item).await.expect("read")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

async fn reserve_urcb(mms: &mut MmsClient) {
    write(mms, &format!("{URCB_ITEM}$Resv"), MmsData::Boolean(true))
        .await
        .expect("Resv");
}

async fn enable_urcb(mms: &mut MmsClient) {
    reserve_urcb(mms).await;
    write(mms, &format!("{URCB_ITEM}$RptEna"), MmsData::Boolean(true))
        .await
        .expect("RptEna");
}

async fn enable_brcb(mms: &mut MmsClient) {
    write(mms, &format!("{BRCB_ITEM}$RptEna"), MmsData::Boolean(true))
        .await
        .expect("RptEna");
}

fn is_object_value_invalid(r: &Result<(), ClientError>) -> bool {
    format!("{r:?}").contains(&format!("{:?}", DataAccessError::ObjectValueInvalid))
}

/// Returns where `needle` first occurs in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ─── Field order ─────────────────────────────────────────────────────────────

/// A BRCB report with ConfRev, BufOvfl, and EntryID carries them in the order
/// of IEC 61850-8-1, so a standard client parses it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brcb_report_with_conf_rev_keeps_the_standard_field_order() {
    let f = start(Cfg {
        opt_flds: OptFlds::SEQ_NUM | OptFlds::REASON | OptFlds::DATA_SET | OptFlds::CONF_REV,
        conf_rev: Some(0x55),
        ..Cfg::default()
    })
    .await;
    let mut mms = f.connect().await;
    enable_brcb(&mut mms).await;
    f.set_st_val(2);
    let r = next_raw_report(&mut mms).await;
    let dat_set = find(&r.raw, b"LLN0$dsPos").expect("DatSet");
    let entry_id = find(&r.raw, &[0x89, 0x08]).expect("EntryID");
    let conf_rev = find(&r.raw, &[0x86, 0x01, 0x55]).expect("ConfRev");
    assert!(dat_set < entry_id && entry_id < conf_rev, "raw order");
    let p = r.parsed.expect("the report parses");
    assert_eq!(p.conf_rev, Some(0x55));
    assert!(p.buf_ovfl.is_some() && p.entry_id.is_some());
    assert_eq!(p.data_values, [dbpos(2)]);
}

/// Control: a URCB report with ConfRev.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn urcb_report_with_conf_rev_parses() {
    let f = start(Cfg {
        opt_flds: OptFlds::SEQ_NUM | OptFlds::REASON | OptFlds::DATA_SET | OptFlds::CONF_REV,
        conf_rev: Some(0x55),
        ..Cfg::default()
    })
    .await;
    let mut mms = f.connect().await;
    enable_urcb(&mut mms).await;
    f.set_st_val(2);
    let p = next_report(&mut mms).await;
    assert_eq!(p.conf_rev, Some(0x55));
}

// ─── UNSIGNED encoding ───────────────────────────────────────────────────────

/// UNSIGNED fields of a report are BER INTEGER contents: a value whose top bit
/// is set takes a leading zero octet.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn report_unsigned_fields_are_ber_integers() {
    let f = start(Cfg {
        opt_flds: OptFlds::SEQ_NUM | OptFlds::CONF_REV,
        conf_rev: Some(200),
        ..Cfg::default()
    })
    .await;
    let mut mms = f.connect().await;
    enable_urcb(&mut mms).await;
    f.set_st_val(2);
    let r = next_raw_report(&mut mms).await;
    assert!(
        find(&r.raw, &[0x86, 0x02, 0x00, 0xc8]).is_some(),
        "86 02 00 c8"
    );
    assert!(find(&r.raw, &[0x86, 0x01, 0xc8]).is_none());
    assert_eq!(r.parsed.expect("parse").conf_rev, Some(200));
}

// ─── BufTm ───────────────────────────────────────────────────────────────────

/// A member that triggers twice inside one buffer time is reported twice: the
/// second trigger sends the first value at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn urcb_retrigger_inside_buf_tm_keeps_the_first_value() {
    let f = start(Cfg {
        buf_tm_ms: 1_000,
        ..Cfg::default()
    })
    .await;
    let mut mms = f.connect().await;
    enable_urcb(&mut mms).await;
    f.set_st_val(2);
    f.set_st_val(1);
    let first = next_report(&mut mms).await;
    assert_eq!(first.data_values, [dbpos(2)], "the first value");
    let second = next_report(&mut mms).await;
    assert_eq!(second.data_values, [dbpos(1)], "the second value");
}

/// Same as the URCB case, on a BRCB.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brcb_retrigger_inside_buf_tm_keeps_the_first_value() {
    let f = start(Cfg {
        buf_tm_ms: 1_000,
        ..Cfg::default()
    })
    .await;
    let mut mms = f.connect().await;
    enable_brcb(&mut mms).await;
    f.set_st_val(2);
    f.set_st_val(1);
    let first = next_report(&mut mms).await;
    assert_eq!(first.data_values, [dbpos(2)], "the first value");
    let second = next_report(&mut mms).await;
    assert_eq!(second.data_values, [dbpos(1)], "the second value");
}

// ─── Reason for inclusion ────────────────────────────────────────────────────

/// Every member of a BRCB general interrogation report carries only the
/// general-interrogation reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brcb_gi_report_reason_is_gi_only() {
    let f = start(Cfg {
        trg_ops: TriggerOptions::DATA_CHANGED | TriggerOptions::GI,
        ..Cfg::default()
    })
    .await;
    let mut mms = f.connect().await;
    enable_brcb(&mut mms).await;
    write(&mut mms, &format!("{BRCB_ITEM}$GI"), MmsData::Boolean(true))
        .await
        .expect("GI");
    let r = next_report(&mut mms).await;
    assert_eq!(r.reasons, [ReasonForInclusion::GI]);
}

/// Control: the URCB general interrogation report.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn urcb_gi_report_reason_is_gi_only() {
    let f = start(Cfg {
        trg_ops: TriggerOptions::DATA_CHANGED | TriggerOptions::GI,
        ..Cfg::default()
    })
    .await;
    let mut mms = f.connect().await;
    enable_urcb(&mut mms).await;
    write(&mut mms, &format!("{URCB_ITEM}$GI"), MmsData::Boolean(true))
        .await
        .expect("GI");
    let r = next_report(&mut mms).await;
    assert_eq!(r.reasons, [ReasonForInclusion::GI]);
}

/// Every member of a BRCB integrity report carries only the integrity reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brcb_integrity_report_reason_is_integrity_only() {
    let f = start(Cfg {
        trg_ops: TriggerOptions::INTEGRITY,
        intg_pd_ms: 200,
        ..Cfg::default()
    })
    .await;
    let mut mms = f.connect().await;
    enable_brcb(&mut mms).await;
    let r = next_report(&mut mms).await;
    assert_eq!(r.reasons, [ReasonForInclusion::INTEGRITY]);
}

// ─── TimeOfEntry ─────────────────────────────────────────────────────────────

/// A buffered entry sent after the client comes back carries the time it was
/// entered into the buffer, the same instant `TimeofEntry` reads back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brcb_report_time_of_entry_is_the_buffering_time() {
    let f = start(Cfg {
        opt_flds: OptFlds::SEQ_NUM | OptFlds::REASON | OptFlds::TIME_STAMP,
        ..Cfg::default()
    })
    .await;
    let mut a = f.connect().await;
    enable_brcb(&mut a).await;
    f.set_st_val(2);
    let _ = next_report(&mut a).await;
    a.disconnect().await.expect("disconnect");
    drop(a);
    f.wait_for_no_connection().await;

    f.set_st_val(1);
    let buffered_by = now_ms();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut b = f.connect().await;
    enable_brcb(&mut b).await;
    let r = next_report(&mut b).await;
    assert_eq!(r.data_values, [dbpos(1)]);
    let t = r.timestamp_ms.expect("TimeOfEntry");
    assert!(
        t <= buffered_by,
        "TimeOfEntry {t} is after the entry was buffered ({buffered_by})"
    );
    let toe = read(&mut b, &format!("{BRCB_ITEM}$TimeofEntry")).await;
    let MmsData::BinaryTime(bytes) = toe else {
        panic!("TimeofEntry is a BinaryTime, got {toe:?}");
    };
    let bytes: [u8; 6] = bytes.try_into().expect("six octets");
    assert_eq!(
        iec61850_mms::epoch_ms_from_binary_time6(bytes),
        t,
        "the report and TimeofEntry agree"
    );
}

// ─── Reports over 65535 bytes ────────────────────────────────────────────────

/// A general interrogation report larger than 65535 bytes is segmented within
/// the PDU limit, and the control block keeps working afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn report_over_65535_bytes_is_segmented_and_reporting_continues() {
    let f = start(Cfg {
        trg_ops: TriggerOptions::DATA_CHANGED | TriggerOptions::GI,
        opt_flds: OptFlds::SEQ_NUM | OptFlds::REASON | OptFlds::DATA_REFERENCE,
        extra_members: 600,
        ..Cfg::default()
    })
    .await;
    let mut mms = f.connect().await;
    enable_urcb(&mut mms).await;
    write(&mut mms, &format!("{URCB_ITEM}$GI"), MmsData::Boolean(true))
        .await
        .expect("GI");
    let mut segments = 0;
    let mut total = 0;
    loop {
        let r = next_raw_report(&mut mms).await;
        assert!(r.raw.len() <= 65_000, "segment of {} bytes", r.raw.len());
        segments += 1;
        total += r.raw.len();
        // RptID, OptFlds, SqNum, subSeqNum, moreFollows.
        let more = match r.elements.get(4) {
            Some(MmsValue::Boolean(b)) => *b,
            other => panic!("moreFollows expected, got {other:?}"),
        };
        if !more {
            break;
        }
        assert!(segments < 10, "too many segments");
    }
    assert!(
        segments > 1 && total > 65_535,
        "{segments} segments, {total} bytes"
    );

    // The engine still serves the control block.
    assert!(matches!(
        read(&mut mms, &format!("{URCB_ITEM}$RptEna")).await,
        MmsData::Boolean(true)
    ));
    f.set_st_val(2);
    let r = next_raw_report(&mut mms).await;
    assert!(r.raw.len() < 65_000);
}

// ─── DatSet ──────────────────────────────────────────────────────────────────

/// A URCB DatSet write naming no data set is refused and changes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn urcb_dat_set_naming_no_data_set_is_refused() {
    let f = start(Cfg {
        opt_flds: OptFlds::SEQ_NUM | OptFlds::DATA_SET | OptFlds::DATA_REFERENCE,
        ..Cfg::default()
    })
    .await;
    let mut mms = f.connect().await;
    reserve_urcb(&mut mms).await;
    let r = write(
        &mut mms,
        &format!("{URCB_ITEM}$DatSet"),
        MmsData::VisibleString("IED1LD0/LLN0$noSuchDataSet".into()),
    )
    .await;
    assert!(is_object_value_invalid(&r), "{r:?}");
    assert!(matches!(
        read(&mut mms, &format!("{URCB_ITEM}$DatSet")).await,
        MmsData::VisibleString(ref s) if s == "IED1LD0/LLN0$dsPos"
    ));
    write(
        &mut mms,
        &format!("{URCB_ITEM}$RptEna"),
        MmsData::Boolean(true),
    )
    .await
    .expect("RptEna");
    f.set_st_val(2);
    let r = next_report(&mut mms).await;
    assert_eq!(r.data_references, [ST_VAL_REF]);
}

/// A BRCB DatSet write naming no data set is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brcb_dat_set_naming_no_data_set_is_refused() {
    let f = start(Cfg::default()).await;
    let mut mms = f.connect().await;
    let r = write(
        &mut mms,
        &format!("{BRCB_ITEM}$DatSet"),
        MmsData::VisibleString("IED1LD0/LLN0$noSuchDataSet".into()),
    )
    .await;
    assert!(is_object_value_invalid(&r), "{r:?}");
    assert!(matches!(
        read(&mut mms, &format!("{BRCB_ITEM}$DatSet")).await,
        MmsData::VisibleString(ref s) if s == "IED1LD0/LLN0$dsPos"
    ));
}

/// A URCB whose DatSet is written to a registered data set reports that data
/// set's members.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn urcb_dat_set_write_rebinds_the_members() {
    let f = start(Cfg {
        trg_ops: TriggerOptions::DATA_CHANGED | TriggerOptions::QUALITY_CHANGED,
        opt_flds: OptFlds::SEQ_NUM | OptFlds::REASON | OptFlds::DATA_SET | OptFlds::DATA_REFERENCE,
        ..Cfg::default()
    })
    .await;
    f.register_ds_q();
    let mut mms = f.connect().await;
    reserve_urcb(&mut mms).await;
    write(
        &mut mms,
        &format!("{URCB_ITEM}$DatSet"),
        MmsData::VisibleString("IED1LD0/LLN0$dsQ".into()),
    )
    .await
    .expect("DatSet");
    write(
        &mut mms,
        &format!("{URCB_ITEM}$RptEna"),
        MmsData::Boolean(true),
    )
    .await
    .expect("RptEna");
    f.set_st_val(2);
    f.set_q(&[0x60, 0x00]);
    let r = next_report(&mut mms).await;
    assert_eq!(r.data_set_name.as_deref(), Some("IED1LD0/LLN0$dsQ"));
    assert_eq!(r.data_references, [Q_REF], "members of the new data set");
}

/// Same as the URCB case, on a BRCB.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brcb_dat_set_write_rebinds_the_members() {
    let f = start(Cfg {
        trg_ops: TriggerOptions::DATA_CHANGED | TriggerOptions::QUALITY_CHANGED,
        opt_flds: OptFlds::SEQ_NUM | OptFlds::REASON | OptFlds::DATA_SET | OptFlds::DATA_REFERENCE,
        ..Cfg::default()
    })
    .await;
    f.register_ds_q();
    let mut mms = f.connect().await;
    write(
        &mut mms,
        &format!("{BRCB_ITEM}$DatSet"),
        MmsData::VisibleString("IED1LD0/LLN0$dsQ".into()),
    )
    .await
    .expect("DatSet");
    enable_brcb(&mut mms).await;
    f.set_st_val(2);
    f.set_q(&[0x60, 0x00]);
    let r = next_report(&mut mms).await;
    assert_eq!(r.data_set_name.as_deref(), Some("IED1LD0/LLN0$dsQ"));
    assert_eq!(r.data_references, [Q_REF], "members of the new data set");
}

// ─── Data sets created over MMS ──────────────────────────────────────────────

const DYN_ITEM: &str = "LLN0$dynQ";

async fn define_dyn_q(mms: &mut MmsClient) {
    mms.define_named_variable_list(
        DOMAIN,
        DYN_ITEM,
        vec![DefineNamedVariableEntry::domain(DOMAIN, "CSWI1$ST$Pos$q")],
    )
    .await
    .expect("define dynQ");
}

/// A URCB bound to a data set created over MMS reports updates of its members,
/// and the data set cannot be deleted while the URCB refers to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dynamic_data_set_in_use_reports_and_cannot_be_deleted() {
    let f = start(Cfg {
        trg_ops: TriggerOptions::DATA_CHANGED | TriggerOptions::QUALITY_CHANGED,
        opt_flds: OptFlds::SEQ_NUM | OptFlds::REASON | OptFlds::DATA_REFERENCE,
        ..Cfg::default()
    })
    .await;
    let mut mms = f.connect().await;
    define_dyn_q(&mut mms).await;
    reserve_urcb(&mut mms).await;
    write(
        &mut mms,
        &format!("{URCB_ITEM}$DatSet"),
        MmsData::VisibleString(format!("{DOMAIN}/{DYN_ITEM}")),
    )
    .await
    .expect("DatSet");
    write(
        &mut mms,
        &format!("{URCB_ITEM}$RptEna"),
        MmsData::Boolean(true),
    )
    .await
    .expect("RptEna");
    f.set_q(&[0x60, 0x00]);
    let r = next_report(&mut mms).await;
    assert_eq!(r.data_references, [Q_REF]);

    let deleted = mms.delete_named_variable_list(DOMAIN, DYN_ITEM).await;
    assert!(
        matches!(
            deleted,
            Err(ClientError::ServiceError {
                error_class: ErrorClass::Service(subcode::service::OBJECT_CONSTRAINT_CONFLICT)
            })
        ),
        "{deleted:?}"
    );
    mms.get_named_variable_list_attributes(DOMAIN, DYN_ITEM)
        .await
        .expect("the data set still exists");
    f.set_q(&[0x40, 0x00]);
    let r = next_report(&mut mms).await;
    assert_eq!(r.data_references, [Q_REF], "the URCB still reports");
}

/// Control: once no control block refers to it, the data set is deleted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dynamic_data_set_no_longer_in_use_is_deleted() {
    let f = start(Cfg::default()).await;
    let mut mms = f.connect().await;
    define_dyn_q(&mut mms).await;
    reserve_urcb(&mut mms).await;
    write(
        &mut mms,
        &format!("{URCB_ITEM}$DatSet"),
        MmsData::VisibleString(format!("{DOMAIN}/{DYN_ITEM}")),
    )
    .await
    .expect("DatSet");
    write(
        &mut mms,
        &format!("{URCB_ITEM}$DatSet"),
        MmsData::VisibleString("LLN0$dsPos".into()),
    )
    .await
    .expect("DatSet back");
    let deleted = mms
        .delete_named_variable_list(DOMAIN, DYN_ITEM)
        .await
        .expect("delete");
    assert_eq!(deleted, (1, 1));
}

/// A configured data set is never deletable: deleting one that report control
/// blocks use is answered positively with nothing deleted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn configured_data_set_in_use_is_matched_but_not_deleted() {
    let f = start(Cfg::default()).await;
    let mut mms = f.connect().await;
    let deleted = mms
        .delete_named_variable_list(DOMAIN, "LLN0$dsPos")
        .await
        .expect("a positive response");
    assert_eq!(deleted, (1, 0));
    mms.get_named_variable_list_attributes(DOMAIN, "LLN0$dsPos")
        .await
        .expect("the data set still exists");
}

/// A data set created over MMS cannot be deleted while a BRCB refers to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dynamic_data_set_used_by_a_brcb_cannot_be_deleted() {
    let f = start(Cfg::default()).await;
    let mut mms = f.connect().await;
    define_dyn_q(&mut mms).await;
    write(
        &mut mms,
        &format!("{BRCB_ITEM}$DatSet"),
        MmsData::VisibleString(format!("{DOMAIN}/{DYN_ITEM}")),
    )
    .await
    .expect("DatSet");
    let deleted = mms.delete_named_variable_list(DOMAIN, DYN_ITEM).await;
    assert!(
        matches!(
            deleted,
            Err(ClientError::ServiceError {
                error_class: ErrorClass::Service(subcode::service::OBJECT_CONSTRAINT_CONFLICT)
            })
        ),
        "{deleted:?}"
    );
    mms.get_named_variable_list_attributes(DOMAIN, DYN_ITEM)
        .await
        .expect("the data set still exists");
}
