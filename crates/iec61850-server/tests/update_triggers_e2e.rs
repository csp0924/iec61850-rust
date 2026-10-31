//! The triggers an attribute update raises, over a real MMS association.
//!
//! An update compares the new value with the old one and raises only the
//! triggers the attribute declares: a changed value raises data-change for
//! `dchg`, quality-change for `qchg` and data-update for `dupd`, an unchanged
//! value raises data-update for `dupd` and nothing else (IEC 61850-7-2 TrgOp,
//! table 21).
//! Report control blocks and log control blocks act on the same triggers,
//! each on those its TrgOps enable. Reports are received on a raw MMS
//! association and decoded without client-side report state.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use iec61850_client::mms_compat::mms_data_to_mms_value;
use iec61850_client::report::parse::{parse_report, ParsedReport, ReasonForInclusion};
use iec61850_mms::mms::client::{MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::common::ObjectName;
use iec61850_mms::mms::pdu::information_report::{decode_information_report, VariableAccessSpec};
use iec61850_mms::mms::pdu::{ReadJournalRequest, ReadJournalResponse};
use iec61850_mms::mms::MmsData;
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObject, DoChild, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, NodeRef, ObjectRef, TrgOps, FC,
};
use iec61850_server::logging::{InMemoryLogStorage, LogControl, LogControlBlock, LogStorage};
use iec61850_server::{
    Dataset, DatasetEntry, IedServer, OptFlds, Rcb, ReportControl, ServerHandle, TriggerOptions,
};

const DOM: &str = "TESTLD0";
const IND1: &str = "TESTLD0/GGIO1$ST$Ind1$stVal";
const IND2: &str = "TESTLD0/GGIO1$ST$Ind2$stVal";
const IND3: &str = "TESTLD0/GGIO1$ST$Ind3$stVal";
const MAG: &str = "TESTLD0/GGIO1$MX$AnIn1$mag";
const CNT: &str = "TESTLD0/GGIO1$ST$Cnt1$frVal";
const DATA_SET: &str = "LLN0$dsAll";
const URCB: &str = "LLN0$RP$urcb01";
const LCB: &str = "LLN0$LG$evlog";
const LOG: &str = "LLN0$EventLog";

/// GGIO1 with three boolean `stVal` attributes that declare `dchg`, a float
/// `mag` that declares `dchg` and `dupd`, and an integer `frVal` that declares
/// only `dupd`, as a frozen counter value does.
fn model() -> Arc<IedModel> {
    let ind = |name: &str| {
        DataObject::new(
            name,
            vec![DoChild::Da(DataAttribute::new(
                "stVal",
                FC::St,
                DataAttributeType::Boolean,
                TrgOps::DCHG,
                MmsValue::Boolean(false),
            ))],
        )
    };
    let an_in = DataObject::new(
        "AnIn1",
        vec![DoChild::Da(DataAttribute::new(
            "mag",
            FC::Mx,
            DataAttributeType::Float32,
            TrgOps::DCHG | TrgOps::DUPD,
            MmsValue::Float32(1.5),
        ))],
    );
    let cnt = DataObject::new(
        "Cnt1",
        vec![DoChild::Da(DataAttribute::new(
            "frVal",
            FC::St,
            DataAttributeType::Int32,
            TrgOps::DUPD,
            MmsValue::Integer(0),
        ))],
    );
    let ggio = LogicalNodeBuilder::new("", "GGIO", "1")
        .add_do(ind("Ind1"))
        .add_do(ind("Ind2"))
        .add_do(ind("Ind3"))
        .add_do(an_in)
        .add_do(cnt)
        .build()
        .unwrap();
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(LogicalNodeBuilder::lln0().build().unwrap())
        .add_ln(ggio)
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

/// The single attribute of data object `index` of GGIO1: Ind1, Ind2, Ind3,
/// AnIn1, then Cnt1.
fn da(m: &IedModel, index: usize) -> &DataAttribute {
    let DoChild::Da(da) = &m.lds[0].lns[1].dos[index].children[0] else {
        panic!("fixture shape")
    };
    da
}

/// The data set `[Ind1.stVal, Ind2.stVal, Ind3.stVal, AnIn1.mag]`.
fn data_set(m: &IedModel) -> Dataset {
    let mut ds = Dataset::new(DATA_SET);
    for (i, r) in [IND1, IND2, IND3, MAG].into_iter().enumerate() {
        ds.push(DatasetEntry::new(r, da(m, i).value.clone()));
    }
    ds
}

/// The data set of the report control blocks: `data_set` and Cnt1.frVal.
fn report_data_set(m: &IedModel) -> Dataset {
    let mut ds = data_set(m);
    ds.push(DatasetEntry::new(CNT, da(m, 4).value.clone()));
    ds
}

fn server(m: Arc<IedModel>) -> IedServer {
    IedServer::builder()
        .model(m)
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()
        .expect("build server")
}

fn opt_flds() -> OptFlds {
    OptFlds::SEQ_NUM | OptFlds::REASON | OptFlds::DATA_SET | OptFlds::DATA_REFERENCE
}

async fn connect(handle: &ServerHandle) -> MmsClient {
    let mut c = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    c.connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    c
}

// ── Reports ─────────────────────────────────────────────────────────────────

/// A started server with one enabled URCB over the report data set, and the
/// association that enabled it.
struct UrcbFixture {
    m: Arc<IedModel>,
    srv: IedServer,
    _handle: ServerHandle,
    mms: MmsClient,
}

/// Starts a URCB with no buffer time.
async fn start_urcb(trg_ops: TriggerOptions) -> UrcbFixture {
    start_urcb_with(trg_ops, 0).await
}

async fn start_urcb_with(trg_ops: TriggerOptions, buf_tm_ms: u32) -> UrcbFixture {
    let m = model();
    let srv = server(m.clone());
    let rcb = Rcb::new("urcb01", DATA_SET)
        .with_trg_ops(trg_ops)
        .with_opt_flds(opt_flds())
        .with_buf_tm_ms(buf_tm_ms);
    srv.register_urcb(
        ReportControl::new(format!("{DOM}/{URCB}"), rcb),
        report_data_set(&m),
    )
    .expect("register_urcb");
    let handle = srv.start().await.expect("start");
    let mut mms = connect(&handle).await;
    for field in ["Resv", "RptEna"] {
        mms.write(DOM, &format!("{URCB}${field}"), MmsData::Boolean(true))
            .await
            .expect("enable the URCB");
    }
    UrcbFixture {
        m,
        srv,
        _handle: handle,
        mms,
    }
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

/// The members a report carries, each with its reasons and value.
fn members(r: &ParsedReport) -> Vec<(&str, ReasonForInclusion, MmsValue)> {
    r.data_references
        .iter()
        .zip(&r.reasons)
        .zip(&r.data_values)
        .map(|((d, reason), v)| (d.as_str(), *reason, v.clone()))
        .collect()
}

/// Rewriting a value with itself raises no data-change: the report that
/// follows is the one of the next real change.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_update_to_the_same_value_sends_no_data_change_report() {
    let mut f = start_urcb(TriggerOptions::DATA_CHANGED).await;

    f.srv.update_boolean(da(&f.m, 0), true).unwrap();
    let first = next_report(&mut f.mms).await;
    assert_eq!(
        members(&first),
        [(
            IND1,
            ReasonForInclusion::DATA_CHANGE,
            MmsValue::Boolean(true)
        )]
    );

    f.srv.update_boolean(da(&f.m, 0), true).unwrap();
    f.srv.update_float32(da(&f.m, 3), 1.5).unwrap();
    f.srv.update_boolean(da(&f.m, 1), true).unwrap();
    let second = next_report(&mut f.mms).await;
    assert_eq!(
        members(&second),
        [(
            IND2,
            ReasonForInclusion::DATA_CHANGE,
            MmsValue::Boolean(true)
        )],
        "the two rewrites of an unchanged value sent nothing"
    );
}

/// An attribute that declares `dupd` raises data-update when it is rewritten
/// with its own value, and a control block that enables only `dupd` reports
/// it with that reason alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rewriting_a_dupd_attribute_sends_a_data_update_report() {
    let mut f = start_urcb(TriggerOptions::DATA_UPDATE).await;

    f.srv.update_float32(da(&f.m, 3), 1.5).unwrap();
    let report = next_report(&mut f.mms).await;
    assert_eq!(
        members(&report),
        [(MAG, ReasonForInclusion::DATA_UPDATE, MmsValue::Float32(1.5))]
    );

    // A change of the same attribute is an update as well.
    f.srv.update_float32(da(&f.m, 3), 2.5).unwrap();
    let report = next_report(&mut f.mms).await;
    assert_eq!(
        members(&report),
        [(MAG, ReasonForInclusion::DATA_UPDATE, MmsValue::Float32(2.5))]
    );
}

/// A change of an attribute that declares `dchg` and `dupd` carries only the
/// reasons the control block enables.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_report_carries_only_the_enabled_reasons_of_a_change() {
    let mut f = start_urcb(TriggerOptions::DATA_CHANGED).await;
    f.srv.update_float32(da(&f.m, 3), 2.5).unwrap();
    let report = next_report(&mut f.mms).await;
    assert_eq!(
        members(&report),
        [(MAG, ReasonForInclusion::DATA_CHANGE, MmsValue::Float32(2.5))]
    );

    let mut f = start_urcb(TriggerOptions::DATA_CHANGED | TriggerOptions::DATA_UPDATE).await;
    f.srv.update_float32(da(&f.m, 3), 2.5).unwrap();
    let report = next_report(&mut f.mms).await;
    assert_eq!(
        members(&report),
        [(
            MAG,
            ReasonForInclusion::DATA_CHANGE | ReasonForInclusion::DATA_UPDATE,
            MmsValue::Float32(2.5)
        )]
    );
}

/// An attribute that declares only `dupd` raises data-update when it changes
/// and no data-change: a control block that enables only `dchg` does not
/// report it, one that enables `dupd` does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dupd_only_attribute_is_reported_only_as_a_data_update() {
    let mut f = start_urcb(TriggerOptions::DATA_CHANGED).await;
    f.srv.update_int32(da(&f.m, 4), 7).unwrap();
    f.srv.update_boolean(da(&f.m, 1), true).unwrap();
    let report = next_report(&mut f.mms).await;
    assert_eq!(
        members(&report),
        [(
            IND2,
            ReasonForInclusion::DATA_CHANGE,
            MmsValue::Boolean(true)
        )],
        "the change of the dupd-only attribute sent nothing"
    );

    let mut f = start_urcb(TriggerOptions::DATA_UPDATE).await;
    f.srv.update_int32(da(&f.m, 4), 7).unwrap();
    let report = next_report(&mut f.mms).await;
    assert_eq!(
        members(&report),
        [(CNT, ReasonForInclusion::DATA_UPDATE, MmsValue::Integer(7))]
    );
}

/// The model of the demonstration CID shipped with the crate, with `edit`
/// applied to its text first.
fn demo_model(edit: impl FnOnce(String) -> String) -> Arc<IedModel> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/models/demo.cid");
    let xml = edit(std::fs::read_to_string(path).expect("read demo.cid"));
    let raw = iec61850_scl::parse_scl(&xml).expect("parse demo.cid");
    let resolved = iec61850_scl::ResolvedScl::from_raw(raw).expect("resolve demo.cid");
    Arc::new(
        resolved
            .build_model("DemoIED")
            .expect("build the demo model"),
    )
}

/// The data attribute an IEC-notation reference names in `m`.
fn scl_da<'m>(m: &'m IedModel, reference: &str) -> &'m DataAttribute {
    let r = ObjectRef::parse_iec(reference).expect("parse the reference");
    match m.node_by_object_ref(&r).expect("look the node up") {
        NodeRef::Da(da) => da,
        _ => panic!("expected a data attribute at {reference}"),
    }
}

const DEMO_DOM: &str = "DemoIEDLD0";
const MAG_F: &str = "DemoIEDLD0/MMXU1$MX$TotW$mag$f";
const DEMO_ST_VAL: &str = "DemoIEDLD0/GGIO1$ST$Ind1$stVal";

/// A started server on `m` with one enabled URCB over
/// `[MMXU1.TotW.mag.f, GGIO1.Ind1.stVal]`, and the association that enabled
/// it.
async fn start_demo_urcb(
    m: &Arc<IedModel>,
    trg_ops: TriggerOptions,
) -> (IedServer, ServerHandle, MmsClient) {
    const DEMO_URCB: &str = "LLN0$RP$urcbMag";
    let srv = server(m.clone());
    let mut ds = Dataset::new("LLN0$dsMag");
    ds.push(DatasetEntry::new(
        MAG_F,
        scl_da(m, "DemoIEDLD0/MMXU1.TotW.mag.f").value.clone(),
    ));
    ds.push(DatasetEntry::new(
        DEMO_ST_VAL,
        scl_da(m, "DemoIEDLD0/GGIO1.Ind1.stVal").value.clone(),
    ));
    let rcb = Rcb::new("urcbMag", "LLN0$dsMag")
        .with_trg_ops(trg_ops)
        .with_opt_flds(opt_flds());
    srv.register_urcb(
        ReportControl::new(format!("{DEMO_DOM}/{DEMO_URCB}"), rcb),
        ds,
    )
    .expect("register_urcb");
    let handle = srv.start().await.expect("start");
    let mut mms = connect(&handle).await;
    for field in ["Resv", "RptEna"] {
        mms.write(
            DEMO_DOM,
            &format!("{DEMO_URCB}${field}"),
            MmsData::Boolean(true),
        )
        .await
        .expect("enable the URCB");
    }
    (srv, handle, mms)
}

/// A leaf of a structured attribute loaded from SCL, `mag.f` of an MV whose
/// `mag` declares `dchg`, raises the triggers its top-level attribute
/// declares: a change is reported as a data change, a rewrite of the same
/// value is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_leaf_of_a_structured_scl_attribute_takes_its_attribute_triggers() {
    let m = demo_model(|xml| xml);
    let (srv, _handle, mut mms) = start_demo_urcb(&m, TriggerOptions::DATA_CHANGED).await;
    let mag_f = scl_da(&m, "DemoIEDLD0/MMXU1.TotW.mag.f");
    let st_val = scl_da(&m, "DemoIEDLD0/GGIO1.Ind1.stVal");

    srv.update_float32(mag_f, 230.5).unwrap();
    let report = next_report(&mut mms).await;
    assert_eq!(
        members(&report),
        [(
            MAG_F,
            ReasonForInclusion::DATA_CHANGE,
            MmsValue::Float32(230.5)
        )]
    );

    srv.update_float32(mag_f, 230.5).unwrap();
    srv.update_boolean(st_val, true).unwrap();
    let report = next_report(&mut mms).await;
    assert_eq!(
        members(&report),
        [(
            DEMO_ST_VAL,
            ReasonForInclusion::DATA_CHANGE,
            MmsValue::Boolean(true)
        )],
        "the rewrite of the same value sent nothing"
    );
}

/// When the SCL `mag` of an MV also declares `dupd`, its leaf `mag.f` raises
/// data-update on every rewrite: a control block that enables only `dupd`
/// reports a rewrite of the same value and a change alike, with reason
/// data-update.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_leaf_of_a_structured_scl_attribute_declaring_dupd_reports_updates() {
    const MV_MAG: &str =
        r#"<DA name="mag" fc="MX" bType="Struct" type="AnalogValue_T" dchg="true"/>"#;
    let m = demo_model(|xml| {
        assert_eq!(xml.matches(MV_MAG).count(), 1, "the MV type of demo.cid");
        xml.replace(
            MV_MAG,
            r#"<DA name="mag" fc="MX" bType="Struct" type="AnalogValue_T" dchg="true" dupd="true"/>"#,
        )
    });
    let (srv, _handle, mut mms) = start_demo_urcb(&m, TriggerOptions::DATA_UPDATE).await;
    let mag_f = scl_da(&m, "DemoIEDLD0/MMXU1.TotW.mag.f");
    let held = match &*mag_f.value.read().unwrap() {
        MmsValue::Float32(v) => *v,
        other => panic!("mag.f holds {other:?}"),
    };

    srv.update_float32(mag_f, held).unwrap();
    let report = next_report(&mut mms).await;
    assert_eq!(
        members(&report),
        [(
            MAG_F,
            ReasonForInclusion::DATA_UPDATE,
            MmsValue::Float32(held)
        )]
    );

    srv.update_float32(mag_f, held + 1.0).unwrap();
    let report = next_report(&mut mms).await;
    assert_eq!(
        members(&report),
        [(
            MAG_F,
            ReasonForInclusion::DATA_UPDATE,
            MmsValue::Float32(held + 1.0)
        )]
    );
}

// ── Logs ────────────────────────────────────────────────────────────────────

/// Registers the data set and a log control block over it whose LogEna is
/// left at its configured default, so it is enabled once its storage is bound.
fn register_lcb(
    srv: &IedServer,
    m: &IedModel,
    trg_ops: TriggerOptions,
    intg_pd_ms: u32,
) -> Arc<dyn LogStorage> {
    srv.register_dataset(DOM, data_set(m));
    let storage: Arc<dyn LogStorage> = Arc::new(InMemoryLogStorage::new());
    let block = LogControlBlock::new("evlog")
        .with_dataset(DATA_SET)
        .with_trg_ops(trg_ops)
        .with_intg_pd_ms(intg_pd_ms)
        .with_log_ref(format!("{DOM}/{LOG}"));
    let lc = LogControl::new(format!("{DOM}/{LCB}"), block).with_storage(storage.clone());
    srv.register_log_control(DOM, LCB, Arc::new(lc));
    storage
}

async fn read_journal(c: &mut MmsClient) -> ReadJournalResponse {
    c.read_journal(&ReadJournalRequest::time_range(DOM, LOG, 0, u64::MAX / 2))
        .await
        .expect("read journal")
}

/// The data reference and reason code of each variable of each entry.
fn journal(resp: &ReadJournalResponse) -> Vec<Vec<(&str, u8)>> {
    resp.entries
        .iter()
        .map(|e| {
            e.variables
                .iter()
                .map(|v| (v.data_ref.as_str(), v.reason_code))
                .collect()
        })
        .collect()
}

/// A log control block left at its configured LogEna logs from the start; a
/// rewrite of an unchanged value is not a data change, and a rewrite of a
/// `dupd` attribute is logged as a data update.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_log_takes_the_triggers_the_reports_take() {
    let m = model();
    let srv = server(m.clone());
    let storage = register_lcb(
        &srv,
        &m,
        TriggerOptions::DATA_CHANGED | TriggerOptions::DATA_UPDATE,
        0,
    );
    let handle = srv.start().await.unwrap();

    srv.update_boolean(da(&m, 0), true).unwrap();
    srv.update_boolean(da(&m, 0), true).unwrap();
    srv.update_float32(da(&m, 3), 1.5).unwrap();
    srv.update_float32(da(&m, 3), 2.5).unwrap();
    assert_eq!(storage.count(), 3);

    let mut c = connect(&handle).await;
    let log_ena = c.read(DOM, &format!("{LCB}$LogEna")).await.unwrap();
    assert_eq!(log_ena, MmsData::Boolean(true));
    let resp = read_journal(&mut c).await;
    assert_eq!(
        journal(&resp),
        [
            vec![(IND1, 0x02)],
            vec![(MAG, 0x08)],
            vec![(MAG, 0x02 | 0x08)],
        ]
    );
    c.disconnect().await.ok();
    handle.stop().await;
}
