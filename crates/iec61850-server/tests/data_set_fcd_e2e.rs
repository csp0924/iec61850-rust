//! Data set members naming a data object (FCD) or a constructed attribute.
//!
//! IEC 61850-7-2 §13.2.2.3 lets a data set member be functional-constrained
//! data or a functional-constrained data attribute, and an IED that supports
//! CreateDataSet must handle any valid one. Such a member reads, reports and
//! logs as one unit whose value is the MMS structure of the node under its
//! functional constraint; any attribute beneath it triggers it
//! (§17.2.3.2.3). A client of this crate drives the server over TCP.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use iec61850_client::mms_compat::mms_data_to_mms_value;
use iec61850_client::report::parse::{parse_report, ParsedReport, ReasonForInclusion};
use iec61850_mms::mms::client::{MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::common::{AccessResult, DataAccessError, ObjectName, WriteOutcome};
use iec61850_mms::mms::pdu::information_report::{decode_information_report, VariableAccessSpec};
use iec61850_mms::mms::pdu::{DefineNamedVariableEntry, ReadJournalRequest};
use iec61850_mms::mms::MmsData;
use iec61850_model::{
    cdc, DataAttribute, DataAttributeType, DataObject, DoChild, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, NodeRef, ObjectRef, TrgOps, FC,
};
use iec61850_server::handler::{ReadContext, ReadHandler, ReadOutcome};
use iec61850_server::logging::{InMemoryLogStorage, LogControl, LogControlBlock, LogStorage};
use iec61850_server::{
    Dataset, DatasetEntry, IedServer, OptFlds, Rcb, ReportControl, ServerHandle, TriggerOptions,
};

const DOM: &str = "IED1LD0";
const IND1: &str = "IED1LD0/GGIO1$ST$Ind1";
const TOTW_MAG: &str = "IED1LD0/MMXU1$MX$TotW$mag";
const LIM: &str = "IED1LD0/GGIO1$SP$Lim";
const IND3_ST_VAL: &str = "IED1LD0/GGIO1$ST$Ind3$stVal";
const URCB: &str = "LLN0$RP$urcbA";
const LOG: &str = "LLN0$EventLog";
/// Single points beside Ind1 to Ind3, for a data set that needs segmenting.
const EXTRA_POINTS: usize = 24;

/// GGIO1 holds the single points Ind1, Ind2, Ind3 and Pt01 to Pt24, Lim,
/// whose SP attributes `lo` and `hi` both declare dchg, and Upd, whose SP
/// attribute `v` declares dupd; MMXU1 holds the measured value TotW.
fn model() -> Arc<IedModel> {
    let limit = |name: &str, v: i32| {
        DoChild::Da(DataAttribute::new(
            name,
            FC::Sp,
            DataAttributeType::Int32,
            TrgOps::DCHG,
            MmsValue::Integer(i64::from(v)),
        ))
    };
    let mut ggio = LogicalNodeBuilder::new("", "GGIO", "1")
        .add_do(cdc::sps("Ind1", cdc::CdcOptions::NONE))
        .add_do(cdc::sps("Ind2", cdc::CdcOptions::NONE))
        .add_do(cdc::sps("Ind3", cdc::CdcOptions::NONE))
        .add_do(DataObject::new("Lim", vec![limit("lo", 1), limit("hi", 2)]))
        .add_do(DataObject::new(
            "Upd",
            vec![DoChild::Da(DataAttribute::new(
                "v",
                FC::Sp,
                DataAttributeType::Int32,
                TrgOps::DUPD,
                MmsValue::Integer(0),
            ))],
        ));
    for i in 1..=EXTRA_POINTS {
        ggio = ggio.add_do(cdc::sps(format!("Pt{i:02}"), cdc::CdcOptions::NONE));
    }
    let mmxu = LogicalNodeBuilder::new("", "MMXU", "1")
        .add_do(cdc::mv("TotW", cdc::CdcOptions::NONE, false))
        .build()
        .unwrap();
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(LogicalNodeBuilder::lln0().build().unwrap())
        .add_ln(ggio.build().unwrap())
        .add_ln(mmxu)
        .build()
        .unwrap();
    Arc::new(
        IedModelBuilder::new("IED1")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap(),
    )
}

fn da(model: &IedModel, path: &str) -> DataAttribute {
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

/// A server whose URCB starts on `LLN0$dsBase`, holding `Ind3.stVal`, with
/// reasons dchg, qchg, dupd and GI and no buffer time.
fn server() -> IedServer {
    let server = IedServer::builder()
        .model(model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()
        .expect("server build");
    let m = server.model();
    let mut base = Dataset::new("LLN0$dsBase");
    base.push(DatasetEntry::from_model(&m, DOM, "GGIO1$ST$Ind3$stVal").unwrap());
    let rcb = Rcb::new("urcbA", "LLN0$dsBase")
        .with_trg_ops(
            TriggerOptions::DATA_CHANGED
                | TriggerOptions::QUALITY_CHANGED
                | TriggerOptions::DATA_UPDATE
                | TriggerOptions::GI,
        )
        .with_opt_flds(
            OptFlds::SEQ_NUM | OptFlds::REASON | OptFlds::DATA_SET | OptFlds::DATA_REFERENCE,
        );
    server
        .register_urcb(ReportControl::new(format!("{DOM}/{URCB}"), rcb), base)
        .expect("register_urcb");
    server
}

async fn connect(handle: &ServerHandle, max_pdu: Option<u32>) -> MmsClient {
    let mut builder = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000);
    if let Some(size) = max_pdu {
        builder = builder.local_max_pdu_size(size);
    }
    let mut mms = builder.build();
    mms.connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    mms
}

async fn define(mms: &mut MmsClient, list_name: &str, members: &[&str]) {
    let entries = members
        .iter()
        .map(|m| DefineNamedVariableEntry::domain(DOM, *m))
        .collect();
    mms.define_named_variable_list(DOM, list_name, entries)
        .await
        .unwrap_or_else(|e| panic!("define {list_name}: {e:?}"));
}

/// Binds the URCB to `data_set` and enables it.
async fn enable_urcb(mms: &mut MmsClient, data_set: &str) {
    let writes = [
        ("Resv", MmsData::Boolean(true)),
        ("DatSet", MmsData::VisibleString(data_set.into())),
        ("RptEna", MmsData::Boolean(true)),
    ];
    for (field, value) in writes {
        mms.write(DOM, &format!("{URCB}${field}"), value)
            .await
            .unwrap_or_else(|e| panic!("write {field}: {e:?}"));
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
        return parse_report(&MmsValue::Array(elements)).expect("parse report");
    }
}

fn quality(byte0: u8) -> MmsValue {
    MmsValue::BitString {
        padding: 3,
        data: vec![byte0, 0x00],
    }
}

/// Returns member `i` of a structure value.
fn member(value: &MmsValue, i: usize) -> &MmsValue {
    match value {
        MmsValue::Structure(members) => &members[i],
        other => panic!("not a structure: {other:?}"),
    }
}

// ── Reading ──────────────────────────────────────────────────────────────

/// CreateDataSet takes an FCD and a constructed attribute; GetDataSetValues
/// answers each with the structure a Read of its name answers, members in the
/// order of the type description, and GetDataSetDirectory lists the names the
/// client gave.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn data_object_and_constructed_members_read_as_structures() {
    let server = server();
    let handle = server.start().await.unwrap();
    let mut mms = connect(&handle, None).await;
    define(
        &mut mms,
        "LLN0$dynFcd",
        &["GGIO1$ST$Ind1", "MMXU1$MX$TotW$mag"],
    )
    .await;

    let values = mms
        .read_named_variable_list_values(DOM, "LLN0$dynFcd")
        .await
        .expect("read data set");
    assert_eq!(values.len(), 2);
    for (result, item) in values.iter().zip(["GGIO1$ST$Ind1", "MMXU1$MX$TotW$mag"]) {
        let AccessResult::Success(data) = result else {
            panic!("{item}: {result:?}");
        };
        let direct = mms.read(DOM, item).await.expect("read member");
        assert_eq!(data, &direct, "{item}");
    }
    let AccessResult::Success(ind1) = &values[0] else {
        unreachable!()
    };
    let ind1 = mms_data_to_mms_value(ind1);
    assert!(
        matches!(member(&ind1, 0), MmsValue::Boolean(false)),
        "stVal first"
    );
    assert!(
        matches!(member(&ind1, 1), MmsValue::BitString { .. }),
        "then q"
    );
    assert!(matches!(member(&ind1, 2), MmsValue::UtcTime(_)), "then t");
    let AccessResult::Success(mag) = &values[1] else {
        unreachable!()
    };
    assert!(matches!(
        mms_data_to_mms_value(mag),
        MmsValue::Structure(ref f) if matches!(f[..], [MmsValue::Float32(_)])
    ));

    let dir = mms
        .get_named_variable_list_attributes(DOM, "LLN0$dynFcd")
        .await
        .expect("data set directory");
    let names: Vec<String> = dir
        .list_of_variable
        .iter()
        .map(|v| match &v.name {
            ObjectName::DomainSpecific { domain_id, item_id } => format!("{domain_id}/{item_id}"),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(names, [IND1, TOTW_MAG]);
    handle.stop().await;
}

#[derive(Debug)]
struct Deny;
impl ReadHandler for Deny {
    fn read(&self, _ctx: &ReadContext<'_>) -> ReadOutcome {
        ReadOutcome::Error(DataAccessError::ObjectAccessDenied)
    }
}

/// A read handler refusing an attribute beneath an FCD member fails that
/// member alone; the other member answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_attribute_fails_only_its_member() {
    let server = server();
    server
        .install_read_handler("GGIO1$ST$Ind1$q", Arc::new(Deny))
        .unwrap();
    let handle = server.start().await.unwrap();
    let mut mms = connect(&handle, None).await;
    define(
        &mut mms,
        "LLN0$dynFcd",
        &["GGIO1$ST$Ind1", "MMXU1$MX$TotW$mag"],
    )
    .await;

    let values = mms
        .read_named_variable_list_values(DOM, "LLN0$dynFcd")
        .await
        .expect("read data set");
    assert_eq!(
        values[0],
        AccessResult::Failure(DataAccessError::ObjectAccessDenied)
    );
    assert!(matches!(values[1], AccessResult::Success(_)), "{values:?}");
    handle.stop().await;
}

// ── Reporting ────────────────────────────────────────────────────────────

/// A quality change beneath an FCD member reports that member whole, with
/// reason quality-change; attributes changed in one batch report it once with
/// the union of their reasons; a constructed member reports on its leaf.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attribute_change_reports_its_whole_member() {
    let server = server();
    let m = server.model();
    let handle = server.start().await.unwrap();
    let mut mms = connect(&handle, None).await;
    define(
        &mut mms,
        "LLN0$dynFcd",
        &["GGIO1$ST$Ind1", "MMXU1$MX$TotW$mag"],
    )
    .await;
    enable_urcb(&mut mms, "IED1LD0/LLN0$dynFcd").await;

    let q = da(&m, "IED1LD0/GGIO1.Ind1.q");
    server.update_bit_string(&q, &[0x40, 0x00], 3).unwrap();
    let r = next_report(&mut mms).await;
    assert_eq!(r.inclusion_bits, [true, false]);
    assert_eq!(r.data_references, [IND1]);
    assert_eq!(r.reasons, [ReasonForInclusion::QUALITY_CHANGE]);
    assert_eq!(r.data_values.len(), 1);
    assert_eq!(member(&r.data_values[0], 0), &MmsValue::Boolean(false));
    assert_eq!(member(&r.data_values[0], 1), &quality(0x40));
    assert!(matches!(member(&r.data_values[0], 2), MmsValue::UtcTime(_)));

    {
        let _guard = server.lock_data_model().unwrap();
        server
            .update_boolean(&da(&m, "IED1LD0/GGIO1.Ind1.stVal"), true)
            .unwrap();
        server.update_bit_string(&q, &[0x00, 0x00], 3).unwrap();
    }
    let r = next_report(&mut mms).await;
    assert_eq!(r.data_references, [IND1]);
    // stVal declares dchg and dupd, q declares qchg.
    assert_eq!(
        r.reasons,
        [ReasonForInclusion::DATA_CHANGE
            | ReasonForInclusion::QUALITY_CHANGE
            | ReasonForInclusion::DATA_UPDATE]
    );
    assert_eq!(member(&r.data_values[0], 0), &MmsValue::Boolean(true));
    assert_eq!(member(&r.data_values[0], 1), &quality(0x00));

    server
        .update_float32(&da(&m, "IED1LD0/MMXU1.TotW.mag.f"), 4.5)
        .unwrap();
    let r = next_report(&mut mms).await;
    assert_eq!(r.inclusion_bits, [false, true]);
    assert_eq!(r.data_references, [TOTW_MAG]);
    assert_eq!(
        r.reasons,
        [ReasonForInclusion::DATA_CHANGE | ReasonForInclusion::DATA_UPDATE]
    );
    assert_eq!(
        r.data_values,
        [MmsValue::Structure(vec![MmsValue::Float32(4.5)])]
    );
    handle.stop().await;
}

/// A general interrogation segmented at a small PDU size keeps every FCD
/// member whole within one segment.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_segmented_report_keeps_each_member_whole() {
    const SMALL_PDU: u32 = 300;
    let server = server();
    let handle = server.start().await.unwrap();
    let members: Vec<String> = (1..=EXTRA_POINTS)
        .map(|i| format!("GGIO1$ST$Pt{i:02}"))
        .collect();
    let refs: Vec<&str> = members.iter().map(String::as_str).collect();
    // The definition itself does not fit the small PDU size.
    define(&mut connect(&handle, None).await, "LLN0$dynPts", &refs).await;
    let mut mms = connect(&handle, Some(SMALL_PDU)).await;
    enable_urcb(&mut mms, "IED1LD0/LLN0$dynPts").await;
    mms.write(DOM, &format!("{URCB}$GI"), MmsData::Boolean(true))
        .await
        .expect("GI");

    let mut seen = [false; EXTRA_POINTS];
    let mut segments = 0;
    loop {
        let r = next_report(&mut mms).await;
        segments += 1;
        assert!(segments < 64, "the report does not end");
        let seg = r.segmentation.expect("the report is segmented");
        let marked: Vec<usize> = (0..EXTRA_POINTS).filter(|i| r.inclusion_bits[*i]).collect();
        assert_eq!(r.data_values.len(), marked.len());
        for (k, i) in marked.iter().enumerate() {
            assert!(!seen[*i], "member {i} is in two segments");
            seen[*i] = true;
            assert_eq!(r.data_references[k], format!("{DOM}/{}", members[*i]));
            assert!(
                matches!(&r.data_values[k], MmsValue::Structure(v) if v.len() == 3),
                "member {i} is whole: {:?}",
                r.data_values[k]
            );
        }
        if !seg.more_segments_follow {
            break;
        }
    }
    assert!(segments >= 2, "{segments} segments");
    assert!(seen.iter().all(|s| *s), "a member is in no segment");
    handle.stop().await;
}

// ── Client writes ────────────────────────────────────────────────────────

/// Registers `LLN0$dsLim`, holding the FCD `Lim` and `Ind3.stVal`, and logs
/// it through an enabled log control block.
fn register_lim(server: &IedServer) -> Arc<dyn LogStorage> {
    register_logged(
        server,
        "LLN0$dsLim",
        &["GGIO1$SP$Lim", "GGIO1$ST$Ind3$stVal"],
    )
}

/// Registers the data set `name` of `members` and logs it through an enabled
/// log control block.
fn register_logged(server: &IedServer, name: &str, members: &[&str]) -> Arc<dyn LogStorage> {
    let m = server.model();
    let mut ds = Dataset::new(name);
    for member in members {
        ds.push(DatasetEntry::from_model(&m, DOM, member).unwrap());
    }
    server.register_dataset(DOM, ds);
    let storage: Arc<dyn LogStorage> = Arc::new(InMemoryLogStorage::new());
    let block = LogControlBlock::new("evlog")
        .with_dataset(name)
        .with_trg_ops(TriggerOptions::DATA_CHANGED)
        .with_log_ref(format!("{DOM}/{LOG}"));
    let lc = LogControl::new(format!("{DOM}/LLN0$LG$evlog"), block).with_storage(storage.clone());
    server.register_log_control(DOM, "LLN0$LG$evlog", Arc::new(lc));
    storage
}

/// A client write of an FCD raises the triggers of all its leaves as one
/// batch: one report and one log entry carry the member with both new
/// values. The next report is that of the next change, so the write raised no
/// second report; a leaf write reports the member whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_write_of_a_data_object_reports_and_logs_once() {
    let server = server();
    let m = server.model();
    let storage = register_lim(&server);
    let handle = server.start().await.unwrap();
    let mut mms = connect(&handle, None).await;
    enable_urcb(&mut mms, "IED1LD0/LLN0$dsLim").await;

    let lim =
        |lo: i64, hi: i64| MmsValue::Structure(vec![MmsValue::Integer(lo), MmsValue::Integer(hi)]);
    mms.write(
        DOM,
        "GGIO1$SP$Lim",
        MmsData::Structure(vec![MmsData::Integer(5), MmsData::Integer(9)]),
    )
    .await
    .expect("write the data object");
    let r = next_report(&mut mms).await;
    assert_eq!(r.data_references, [LIM]);
    assert_eq!(r.reasons, [ReasonForInclusion::DATA_CHANGE]);
    assert_eq!(r.data_values, [lim(5, 9)]);
    assert_eq!(storage.count(), 1, "one log entry for the write");

    server
        .update_boolean(&da(&m, "IED1LD0/GGIO1.Ind3.stVal"), true)
        .unwrap();
    let r = next_report(&mut mms).await;
    assert_eq!(r.data_references, [IND3_ST_VAL], "no second report of Lim");

    mms.write(DOM, "GGIO1$SP$Lim$lo", MmsData::Integer(6))
        .await
        .expect("write a leaf");
    let r = next_report(&mut mms).await;
    assert_eq!(r.data_references, [LIM]);
    assert_eq!(r.data_values, [lim(6, 9)]);

    let journal = mms
        .read_journal(&ReadJournalRequest::time_range(DOM, LOG, 0, u64::MAX / 2))
        .await
        .expect("read journal");
    let entries: Vec<Vec<(&str, u8)>> = journal
        .entries
        .iter()
        .map(|e| {
            e.variables
                .iter()
                .map(|v| (v.data_ref.as_str(), v.reason_code))
                .collect()
        })
        .collect();
    assert_eq!(
        entries,
        [
            vec![(LIM, 0x02)],
            vec![(IND3_ST_VAL, 0x02)],
            vec![(LIM, 0x02)]
        ]
    );
    assert_eq!(
        journal.entries[0].variables[0].value,
        MmsData::Structure(vec![MmsData::Integer(5), MmsData::Integer(9)])
    );
    handle.stop().await;
}

/// A client write of the value an attribute already holds reports nothing for
/// an attribute declaring dchg only, and a data update for one declaring
/// dupd.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_write_of_an_unchanged_value_reports_only_a_data_update() {
    let server = server();
    let m = server.model();
    let mut ds = Dataset::new("LLN0$dsUpd");
    ds.push(DatasetEntry::from_model(&m, DOM, "GGIO1$SP$Lim").unwrap());
    ds.push(DatasetEntry::from_model(&m, DOM, "GGIO1$SP$Upd$v").unwrap());
    server.register_dataset(DOM, ds);
    let handle = server.start().await.unwrap();
    let mut mms = connect(&handle, None).await;
    enable_urcb(&mut mms, "IED1LD0/LLN0$dsUpd").await;

    mms.write(DOM, "GGIO1$SP$Lim$lo", MmsData::Integer(1))
        .await
        .expect("rewrite lo");
    mms.write(DOM, "GGIO1$SP$Upd$v", MmsData::Integer(0))
        .await
        .expect("rewrite v");
    let r = next_report(&mut mms).await;
    assert_eq!(r.data_references, ["IED1LD0/GGIO1$SP$Upd$v"]);
    assert_eq!(r.reasons, [ReasonForInclusion::DATA_UPDATE]);
    assert_eq!(r.data_values, [MmsValue::Integer(0)]);
    handle.stop().await;
}

/// A CreateDataSet member naming an object that does not exist, whether by
/// its name, a functional constraint it lacks or one that does not exist, or
/// its logical device, answers
/// definition object-undefined (IEC 61850-8-1 §8.1.3.4.3.4, table 23); a
/// list name in a logical node that does not exist still answers access
/// object-non-existent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_undefined_member_answers_object_undefined() {
    use iec61850_mms::mms::client::ClientError;
    use iec61850_mms::mms::pdu::service_error::subcode::{access, definition};
    use iec61850_mms::mms::pdu::service_error::ErrorClass;

    let server = server();
    let handle = server.start().await.unwrap();
    let mut mms = connect(&handle, None).await;
    let undefined = [
        DefineNamedVariableEntry::domain(DOM, "GGIO1$ST$NoSuchDo"),
        DefineNamedVariableEntry::domain(DOM, "GGIO1$MX$Ind1"),
        DefineNamedVariableEntry::domain(DOM, "GGIO1$XX$Ind1"),
        DefineNamedVariableEntry::domain(DOM, "GGIO1$ST$Ind1$noSuchDa"),
        DefineNamedVariableEntry::domain("IED1NOLD", "GGIO1$ST$Ind1"),
    ];
    for entry in undefined {
        let item = format!("{}/{}", entry.domain_id, entry.item_id);
        match mms
            .define_named_variable_list(DOM, "LLN0$dynBad", vec![entry])
            .await
        {
            Err(ClientError::ServiceError { error_class }) => assert_eq!(
                error_class,
                ErrorClass::Definition(definition::OBJECT_UNDEFINED),
                "{item}"
            ),
            other => panic!("{item}: {other:?}"),
        }
    }
    match mms
        .define_named_variable_list(
            DOM,
            "NOSUCH1$dynBad",
            vec![DefineNamedVariableEntry::domain(DOM, "GGIO1$ST$Ind1")],
        )
        .await
    {
        Err(ClientError::ServiceError { error_class }) => {
            assert_eq!(error_class, ErrorClass::Access(access::OBJECT_NON_EXISTENT))
        }
        other => panic!("{other:?}"),
    }
    define(&mut mms, "LLN0$dynGood", &["GGIO1$ST$Ind1"]).await;
    handle.stop().await;
}

/// A SetDataSetValues writing a structure to an FCD member and a value to a
/// leaf member stores every leaf and raises all their triggers as one batch:
/// one report and one log entry carry both members. The next report is that
/// of the next write, so the request raised no other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_data_set_write_of_a_data_object_member_reports_once() {
    const UPD_V: &str = "IED1LD0/GGIO1$SP$Upd$v";
    let server = server();
    let storage = register_logged(&server, "LLN0$dsSet", &["GGIO1$SP$Lim", "GGIO1$SP$Upd$v"]);
    let handle = server.start().await.unwrap();
    let mut mms = connect(&handle, None).await;
    enable_urcb(&mut mms, "IED1LD0/LLN0$dsSet").await;

    let outcomes = mms
        .write_named_variable_list_values(
            DOM,
            "LLN0$dsSet",
            vec![
                MmsData::Structure(vec![MmsData::Integer(11), MmsData::Integer(12)]),
                MmsData::Integer(3),
            ],
        )
        .await
        .expect("SetDataSetValues");
    assert!(
        outcomes.iter().all(|o| *o == WriteOutcome::Success),
        "{outcomes:?}"
    );
    assert_eq!(storage.count(), 1, "one log entry for the request");
    let r = next_report(&mut mms).await;
    assert_eq!(r.data_references, [LIM, UPD_V]);
    assert_eq!(
        r.reasons,
        [
            ReasonForInclusion::DATA_CHANGE,
            ReasonForInclusion::DATA_UPDATE
        ]
    );
    assert_eq!(
        r.data_values,
        [
            MmsValue::Structure(vec![MmsValue::Integer(11), MmsValue::Integer(12)]),
            MmsValue::Integer(3)
        ]
    );
    assert_eq!(
        mms.read(DOM, "GGIO1$SP$Lim").await.expect("read Lim"),
        MmsData::Structure(vec![MmsData::Integer(11), MmsData::Integer(12)])
    );

    mms.write(DOM, "GGIO1$SP$Upd$v", MmsData::Integer(4))
        .await
        .expect("write v");
    let r = next_report(&mut mms).await;
    assert_eq!(r.data_references, [UPD_V], "no other report of the request");
    handle.stop().await;
}
