//! Report control block attribute services over MMS.
//!
//! SetURCBValues and SetBRCBValues as two clients see them over real TCP and the
//! full ISO stack: who holds a URCB reservation and when it is released, which
//! BRCB writes count ConfRev and which purge the buffer, and which writes an
//! enabled BRCB refuses.

use std::net::SocketAddr;
use std::sync::Arc;

use std::time::{Duration, Instant};

use iec61850_client::mms_compat::mms_data_to_mms_value;
use iec61850_client::report::parse::{parse_report, ParsedReport};
use iec61850_mms::mms::client::{ClientError, MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::common::{DataAccessError, ObjectName};
use iec61850_mms::mms::pdu::information_report::{decode_information_report, VariableAccessSpec};
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
const BRCB_PATH: &str = "IED1LD0/LLN0$BR$brcbPos";
const URCB_PATH: &str = "IED1LD0/LLN0$RP$urcbPos";
const URCB_ITEM: &str = "LLN0$RP$urcbPos";
const BRCB_ITEM: &str = "LLN0$BR$brcbPos";

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

/// A started server with one BRCB and one URCB over `[stVal]`, neither
/// reserved nor enabled.
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
    let data_set = || {
        let mut ds = Dataset::new("LLN0$dsPos");
        ds.push(DatasetEntry::new(ST_VAL_REF, Arc::clone(&st_val.value)));
        ds
    };

    let brcb = Brcb::new("brcbPos", "LLN0$dsPos")
        .with_trg_ops(TriggerOptions::DATA_CHANGED)
        .with_opt_flds(
            OptFlds::SEQ_NUM | OptFlds::REASON | OptFlds::ENTRY_ID | OptFlds::BUFFER_OVERFLOW,
        );
    server
        .register_brcb(BufferedReportControl::new(BRCB_PATH, brcb), data_set())
        .expect("register_brcb");
    let rcb = Rcb::new("urcbPos", "LLN0$dsPos")
        .with_trg_ops(TriggerOptions::DATA_CHANGED)
        .with_opt_flds(OptFlds::SEQ_NUM | OptFlds::REASON);
    server
        .register_urcb(ReportControl::new(URCB_PATH, rcb), data_set())
        .expect("register_urcb");

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

    fn set_st_val(&self, n: u32) {
        self.server
            .update_bit_string_from_int(&self.st_val, n)
            .expect("update stVal");
    }
}

async fn write_urcb(mms: &mut MmsClient, field: &str, value: MmsData) -> Result<(), ClientError> {
    mms.write(DOMAIN, &format!("{URCB_ITEM}${field}"), value)
        .await
}

async fn read_urcb(mms: &mut MmsClient, field: &str) -> MmsData {
    mms.read(DOMAIN, &format!("{URCB_ITEM}${field}"))
        .await
        .unwrap_or_else(|e| panic!("read {field}: {e:?}"))
}

async fn write_brcb(mms: &mut MmsClient, field: &str, value: MmsData) -> Result<(), ClientError> {
    mms.write(DOMAIN, &format!("{BRCB_ITEM}${field}"), value)
        .await
}

async fn read_brcb(mms: &mut MmsClient, field: &str) -> MmsData {
    mms.read(DOMAIN, &format!("{BRCB_ITEM}${field}"))
        .await
        .unwrap_or_else(|e| panic!("read {field}: {e:?}"))
}

/// Waits until GetBRCBValues reports a non-zero EntryID, that is until the BRCB
/// has buffered an entry, and returns it.
async fn wait_for_buffered_entry(mms: &mut MmsClient) -> MmsData {
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        let entry_id = read_brcb(mms, "EntryID").await;
        if entry_id != MmsData::OctetString(vec![0; 8]) {
            return entry_id;
        }
        assert!(Instant::now() < deadline, "the BRCB buffered nothing");
        tokio::time::sleep(Duration::from_millis(5)).await;
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

fn assert_refused_with(result: Result<(), ClientError>, expected: DataAccessError) {
    match result {
        Err(ClientError::DataAccessError(e)) if e == expected => {}
        other => panic!("expected {expected:?}, got {other:?}"),
    }
}

/// A URCB that its holder disables stays reserved: Resv reads TRUE, the holder
/// may reconfigure it, and another client is still refused until the holder
/// writes Resv = FALSE.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn urcb_disable_keeps_the_reservation() {
    let f = start().await;
    let mut holder = f.connect().await;
    let mut other = f.connect().await;

    write_urcb(&mut holder, "Resv", MmsData::Boolean(true))
        .await
        .expect("reserve");
    write_urcb(&mut holder, "RptEna", MmsData::Boolean(true))
        .await
        .expect("enable");
    write_urcb(&mut holder, "RptEna", MmsData::Boolean(false))
        .await
        .expect("disable");
    assert_eq!(read_urcb(&mut other, "Resv").await, MmsData::Boolean(true));

    write_urcb(&mut holder, "IntgPd", MmsData::Unsigned(2_000))
        .await
        .expect("the holder reconfigures a disabled URCB");
    assert_refused_with(
        write_urcb(&mut other, "Resv", MmsData::Boolean(true)).await,
        DataAccessError::TemporarilyUnavailable,
    );
    assert_refused_with(
        write_urcb(&mut other, "RptEna", MmsData::Boolean(true)).await,
        DataAccessError::ObjectAccessDenied,
    );

    write_urcb(&mut holder, "Resv", MmsData::Boolean(false))
        .await
        .expect("release");
    write_urcb(&mut other, "Resv", MmsData::Boolean(true))
        .await
        .expect("another client reserves a released URCB");
}

/// RptEna = TRUE on an unreserved URCB reserves it for the writer, which then
/// receives its reports; another client is refused until the reservation ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn urcb_enable_reserves_implicitly() {
    let f = start().await;
    let mut holder = f.connect().await;
    let mut other = f.connect().await;

    write_urcb(&mut holder, "RptEna", MmsData::Boolean(true))
        .await
        .expect("enable without reserving first");
    assert_eq!(read_urcb(&mut other, "Resv").await, MmsData::Boolean(true));
    f.set_st_val(2);
    assert_eq!(next_report(&mut holder).await.rpt_id, URCB_PATH);

    assert_refused_with(
        write_urcb(&mut other, "RptEna", MmsData::Boolean(true)).await,
        DataAccessError::ObjectAccessDenied,
    );
    assert_refused_with(
        write_urcb(&mut other, "Resv", MmsData::Boolean(true)).await,
        DataAccessError::TemporarilyUnavailable,
    );

    write_urcb(&mut holder, "RptEna", MmsData::Boolean(false))
        .await
        .expect("disable");
    assert_eq!(read_urcb(&mut other, "Resv").await, MmsData::Boolean(true));
    assert_refused_with(
        write_urcb(&mut other, "RptEna", MmsData::Boolean(true)).await,
        DataAccessError::ObjectAccessDenied,
    );
}

/// On an unreserved URCB, a write of any attribute other than RptEna = TRUE is
/// still refused and does not reserve it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn urcb_other_writes_do_not_reserve() {
    let f = start().await;
    let mut mms = f.connect().await;
    assert_refused_with(
        write_urcb(
            &mut mms,
            "TrgOps",
            MmsData::BitString {
                padding: 2,
                data: vec![0x40],
            },
        )
        .await,
        DataAccessError::ObjectAccessDenied,
    );
    assert_refused_with(
        write_urcb(&mut mms, "RptEna", MmsData::Boolean(false)).await,
        DataAccessError::ObjectAccessDenied,
    );
    assert_eq!(read_urcb(&mut mms, "Resv").await, MmsData::Boolean(false));
}

/// A disabled BRCB keeps its ConfRev and its buffer when OptFlds is written; a
/// write of BufTm purges the buffer, so the exposed EntryID returns to all
/// zeros, and still leaves ConfRev alone. A DatSet write counts in ConfRev.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brcb_opt_flds_and_buf_tm_writes_keep_conf_rev() {
    let f = start().await;
    let mut mms = f.connect().await;
    f.set_st_val(2);
    let buffered = wait_for_buffered_entry(&mut mms).await;
    assert_eq!(read_brcb(&mut mms, "ConfRev").await, MmsData::Unsigned(1));

    let opt_flds = OptFlds::SEQ_NUM | OptFlds::DATA_SET | OptFlds::ENTRY_ID;
    let [padding, data @ ..] = opt_flds.to_ber_bit_string();
    write_brcb(
        &mut mms,
        "OptFlds",
        MmsData::BitString {
            padding,
            data: data.to_vec(),
        },
    )
    .await
    .expect("write OptFlds");
    assert_eq!(read_brcb(&mut mms, "ConfRev").await, MmsData::Unsigned(1));
    assert_eq!(read_brcb(&mut mms, "EntryID").await, buffered);

    write_brcb(&mut mms, "BufTm", MmsData::Unsigned(50))
        .await
        .expect("write BufTm");
    assert_eq!(read_brcb(&mut mms, "ConfRev").await, MmsData::Unsigned(1));
    assert_eq!(
        read_brcb(&mut mms, "EntryID").await,
        MmsData::OctetString(vec![0; 8])
    );

    write_brcb(&mut mms, "DatSet", MmsData::VisibleString(String::new()))
        .await
        .expect("write DatSet");
    assert_eq!(read_brcb(&mut mms, "ConfRev").await, MmsData::Unsigned(2));
}

/// The `stVal` a Dbpos of `n` reads as.
fn dbpos(n: u8) -> MmsValue {
    MmsValue::BitString {
        padding: 6,
        data: vec![n << 6],
    }
}

/// An enabled BRCB refuses EntryID and PurgeBuf with temporarily-unavailable:
/// the buffer is neither resent nor purged, and the next report is the next
/// entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brcb_entry_id_and_purge_buf_refused_while_enabled() {
    let f = start().await;
    let mut mms = f.connect().await;
    write_brcb(&mut mms, "RptEna", MmsData::Boolean(true))
        .await
        .expect("enable");
    f.set_st_val(2);
    let first = next_report(&mut mms).await;
    assert_eq!(first.data_values, [dbpos(2)]);

    assert_refused_with(
        write_brcb(&mut mms, "EntryID", MmsData::OctetString(vec![0; 8])).await,
        DataAccessError::TemporarilyUnavailable,
    );
    assert_refused_with(
        write_brcb(&mut mms, "PurgeBuf", MmsData::Boolean(true)).await,
        DataAccessError::TemporarilyUnavailable,
    );

    f.set_st_val(1);
    let second = next_report(&mut mms).await;
    assert_eq!(second.data_values, [dbpos(1)], "no entry is resent");
    assert!(second.entry_id > first.entry_id);

    write_brcb(&mut mms, "RptEna", MmsData::Boolean(false))
        .await
        .expect("disable");
    assert_eq!(
        read_brcb(&mut mms, "EntryID").await,
        MmsData::OctetString(second.entry_id.clone().unwrap())
    );
    write_brcb(&mut mms, "PurgeBuf", MmsData::Boolean(true))
        .await
        .expect("purge a disabled BRCB");
    assert_eq!(
        read_brcb(&mut mms, "EntryID").await,
        MmsData::OctetString(vec![0; 8])
    );
}
