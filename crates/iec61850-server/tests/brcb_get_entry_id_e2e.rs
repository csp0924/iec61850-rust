//! The EntryID and TimeofEntry a BRCB exposes to GetBRCBValues, over MMS.
//!
//! Per IEC 61850-7-2, an enabled BRCB exposes the last entry formatted and
//! queued for transmission, and a disabled one the newest entry in its buffer;
//! the all-zero EntryID stands for an empty buffer. TimeofEntry is the timestamp
//! of the entry whose EntryID is exposed. A client write of EntryID moves where
//! transmission resumes and does not change the value read back.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use iec61850_client::mms_compat::mms_data_to_mms_value;
use iec61850_client::report::parse::{parse_report, ParsedReport};
use iec61850_mms::mms::client::{MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::common::ObjectName;
use iec61850_mms::mms::pdu::information_report::{decode_information_report, VariableAccessSpec};
use iec61850_mms::mms::MmsData;
use iec61850_mms::{epoch_ms_from_binary_time6, EPOCH_1984_MS};
use iec61850_model::{
    cdc, DataAttribute, IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder,
    MmsValue, NodeRef, ObjectRef,
};
use iec61850_server::reporting::{Brcb, BufferedReportControl};
use iec61850_server::{Dataset, DatasetEntry, IedServer, OptFlds, ServerHandle, TriggerOptions};

const DOMAIN: &str = "IED1LD0";
const ST_VAL_REF: &str = "IED1LD0/CSWI1$ST$Pos$stVal";
const BRCB_PATH: &str = "IED1LD0/LLN0$BR$brcbPos";

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

/// A started server with one BRCB over `[stVal]`, not enabled, with a zero
/// buffer time so that every change is buffered as it happens.
struct Fixture {
    server: IedServer,
    handle: ServerHandle,
    st_val: DataAttribute,
}

async fn start() -> Fixture {
    let server = IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()
        .expect("server build");
    let model = server.model();
    let st_val = resolve_da(&model, "IED1LD0/CSWI1.Pos.stVal");
    let mut ds = Dataset::new("LLN0$dsPos");
    ds.push(DatasetEntry::new(ST_VAL_REF, Arc::clone(&st_val.value)));

    let brcb = Brcb::new("brcbPos", "LLN0$dsPos")
        .with_trg_ops(TriggerOptions::DATA_CHANGED)
        .with_opt_flds(
            OptFlds::SEQ_NUM | OptFlds::TIME_STAMP | OptFlds::ENTRY_ID | OptFlds::BUFFER_OVERFLOW,
        );
    server
        .register_brcb(BufferedReportControl::new(BRCB_PATH, brcb), ds)
        .expect("register_brcb");

    let handle = server.start().await.expect("server start");
    Fixture {
        server,
        handle,
        st_val,
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

    /// Changes `stVal`; with a zero buffer time the entry is in the buffer when
    /// this returns.
    fn set_st_val(&self, n: u32) {
        self.server
            .update_bit_string_from_int(&self.st_val, n)
            .expect("update stVal");
    }
}

async fn write_brcb(mms: &mut MmsClient, field: &str, value: MmsData) {
    mms.write(DOMAIN, &format!("LLN0$BR$brcbPos${field}"), value)
        .await
        .unwrap_or_else(|e| panic!("write {field}: {e:?}"));
}

/// Reads the EntryID and the TimeofEntry the BRCB exposes, the latter in
/// milliseconds since 1970-01-01.
async fn read_exposed(mms: &mut MmsClient) -> (Vec<u8>, u64) {
    let entry_id = match mms
        .read(DOMAIN, "LLN0$BR$brcbPos$EntryID")
        .await
        .expect("read EntryID")
    {
        MmsData::OctetString(b) => b,
        other => panic!("EntryID is an octet string, got {other:?}"),
    };
    let time_of_entry = match mms
        .read(DOMAIN, "LLN0$BR$brcbPos$TimeofEntry")
        .await
        .expect("read TimeofEntry")
    {
        MmsData::BinaryTime(b) => {
            let field: [u8; 6] = b.try_into().expect("TimeofEntry is a BinaryTime6");
            epoch_ms_from_binary_time6(field)
        }
        other => panic!("TimeofEntry is a binary time, got {other:?}"),
    };
    (entry_id, time_of_entry)
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

/// The EntryID and TimeOfEntry a report carries.
fn carried(report: &ParsedReport) -> (Vec<u8>, u64) {
    (
        report.entry_id.clone().expect("the report carries EntryID"),
        report.timestamp_ms.expect("the report carries TimeOfEntry"),
    )
}

/// An empty buffer exposes the all-zero EntryID, with TimeofEntry at the
/// BinaryTime epoch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn empty_buffer_exposes_the_zero_entry_id() {
    let f = start().await;
    let mut mms = f.connect().await;
    assert_eq!(read_exposed(&mut mms).await, (vec![0; 8], EPOCH_1984_MS));
}

/// While enabled, the BRCB exposes the last entry it sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enabled_brcb_exposes_the_last_entry_sent() {
    let f = start().await;
    let mut mms = f.connect().await;
    write_brcb(&mut mms, "RptEna", MmsData::Boolean(true)).await;

    let mut last = None;
    for n in [2, 1, 2] {
        f.set_st_val(n);
        last = Some(next_report(&mut mms).await);
    }
    let last = last.expect("three reports");
    assert_eq!(read_exposed(&mut mms).await, carried(&last));
}

/// While disabled, the BRCB exposes the newest entry in its buffer, which is the
/// one it sends next once enabled again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disabled_brcb_exposes_the_newest_buffered_entry() {
    let f = start().await;
    let mut mms = f.connect().await;
    write_brcb(&mut mms, "RptEna", MmsData::Boolean(true)).await;
    f.set_st_val(2);
    let sent = next_report(&mut mms).await;
    write_brcb(&mut mms, "RptEna", MmsData::Boolean(false)).await;
    assert_eq!(read_exposed(&mut mms).await, carried(&sent));

    f.set_st_val(1);
    let exposed = read_exposed(&mut mms).await;
    assert!(
        exposed.0 > carried(&sent).0,
        "a newer entry is in the buffer"
    );

    write_brcb(&mut mms, "RptEna", MmsData::Boolean(true)).await;
    let resumed = next_report(&mut mms).await;
    assert_eq!(resumed.data_values, [dbpos(1)]);
    assert_eq!(carried(&resumed), exposed);
}

/// Writing EntryID moves where transmission resumes and leaves the exposed
/// EntryID on the newest buffered entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn entry_id_write_does_not_change_the_value_read() {
    let f = start().await;
    let mut mms = f.connect().await;
    write_brcb(&mut mms, "RptEna", MmsData::Boolean(true)).await;
    f.set_st_val(2);
    let first = next_report(&mut mms).await;
    f.set_st_val(1);
    let second = next_report(&mut mms).await;
    write_brcb(&mut mms, "RptEna", MmsData::Boolean(false)).await;

    let (first_id, _) = carried(&first);
    write_brcb(&mut mms, "EntryID", MmsData::OctetString(first_id)).await;
    assert_eq!(read_exposed(&mut mms).await, carried(&second));

    // The write took effect on the send path: the entry after it is sent again.
    write_brcb(&mut mms, "RptEna", MmsData::Boolean(true)).await;
    let resent = next_report(&mut mms).await;
    assert_eq!(carried(&resent), carried(&second));
    assert_eq!(resent.data_values, [dbpos(1)]);
}

/// Purging the buffer of a disabled BRCB brings the exposed EntryID back to the
/// all-zero value, whatever EntryID was written before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn purged_buffer_exposes_the_zero_entry_id() {
    let f = start().await;
    let mut mms = f.connect().await;
    write_brcb(&mut mms, "RptEna", MmsData::Boolean(true)).await;
    f.set_st_val(2);
    let sent = next_report(&mut mms).await;
    write_brcb(&mut mms, "RptEna", MmsData::Boolean(false)).await;
    f.set_st_val(1);

    let (sent_id, _) = carried(&sent);
    write_brcb(&mut mms, "EntryID", MmsData::OctetString(sent_id)).await;
    write_brcb(&mut mms, "PurgeBuf", MmsData::Boolean(true)).await;
    assert_eq!(read_exposed(&mut mms).await, (vec![0; 8], EPOCH_1984_MS));
}

/// The `stVal` a Dbpos of `n` reads as.
fn dbpos(n: u8) -> MmsValue {
    MmsValue::BitString {
        padding: 6,
        data: vec![n << 6],
    }
}

/// While enabled, the BRCB exposes the last entry it sent even when that entry
/// is no longer the newest in the buffer: after the buffer is purged and the
/// BRCB enabled again, and before anything new is sent, the entry sent last is
/// exposed rather than the all-zero EntryID of the empty buffer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enabled_brcb_exposes_the_last_entry_sent_after_a_purge() {
    let f = start().await;
    let mut mms = f.connect().await;
    write_brcb(&mut mms, "RptEna", MmsData::Boolean(true)).await;
    f.set_st_val(2);
    let sent = next_report(&mut mms).await;
    write_brcb(&mut mms, "RptEna", MmsData::Boolean(false)).await;
    write_brcb(&mut mms, "PurgeBuf", MmsData::Boolean(true)).await;
    assert_eq!(read_exposed(&mut mms).await, (vec![0; 8], EPOCH_1984_MS));

    write_brcb(&mut mms, "RptEna", MmsData::Boolean(true)).await;
    assert_eq!(read_exposed(&mut mms).await, carried(&sent));
}
