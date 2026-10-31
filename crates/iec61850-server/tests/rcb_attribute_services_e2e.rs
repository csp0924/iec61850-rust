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

fn brcb_config() -> Brcb {
    Brcb::new("brcbPos", "LLN0$dsPos")
        .with_trg_ops(TriggerOptions::DATA_CHANGED)
        .with_opt_flds(
            OptFlds::SEQ_NUM | OptFlds::REASON | OptFlds::ENTRY_ID | OptFlds::BUFFER_OVERFLOW,
        )
}

async fn start() -> Fixture {
    start_with(BufferedReportControl::new(BRCB_PATH, brcb_config())).await
}

/// Starts the fixture with `brcb` as its buffered control block.
async fn start_with(brcb: BufferedReportControl) -> Fixture {
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

    server
        .register_brcb(brcb, data_set())
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

/// A BRCB on the SQLite backend reports each buffered entry with the values it
/// was enqueued with, and exposes its newest buffered entry: the EntryID and
/// TimeofEntry read while it is disabled belong to the last report it then
/// sends.
#[cfg(feature = "sqlite-backend")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brcb_on_sqlite_exposes_its_newest_entry() {
    use iec61850_server::reporting::{OverflowStrategy, SqliteReportBuffer};
    let dir = tempfile::TempDir::new().expect("temp dir");
    let backend = SqliteReportBuffer::open(
        &dir.path().join("buffer.db"),
        "brcbPos",
        16,
        OverflowStrategy::DropOldest,
    )
    .expect("open sqlite buffer");
    let f = start_with(BufferedReportControl::with_backend(
        BRCB_PATH,
        brcb_config(),
        Box::new(backend),
    ))
    .await;
    let mut mms = f.connect().await;
    f.set_st_val(2);
    let first = wait_for_buffered_entry(&mut mms).await;
    f.set_st_val(1);
    let deadline = Instant::now() + Duration::from_secs(4);
    let newest = loop {
        let entry_id = read_brcb(&mut mms, "EntryID").await;
        if entry_id != first {
            break entry_id;
        }
        assert!(
            Instant::now() < deadline,
            "the second entry was not buffered"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    let MmsData::BinaryTime(time_of_entry) = read_brcb(&mut mms, "TimeofEntry").await else {
        panic!("TimeofEntry is a BinaryTime");
    };

    write_brcb(&mut mms, "RptEna", MmsData::Boolean(true))
        .await
        .expect("enable");
    let r1 = next_report(&mut mms).await;
    let r2 = next_report(&mut mms).await;
    assert_eq!(r1.data_values, [dbpos(2)]);
    assert_eq!(r2.data_values, [dbpos(1)]);
    assert_eq!(MmsData::OctetString(r1.entry_id.clone().unwrap()), first);
    assert_eq!(MmsData::OctetString(r2.entry_id.clone().unwrap()), newest);
    assert_eq!(read_brcb(&mut mms, "EntryID").await, newest);
    assert_eq!(
        read_brcb(&mut mms, "TimeofEntry").await,
        MmsData::BinaryTime(time_of_entry)
    );
}

/// DatSet reads back as `<LD>/<LN>$<data set>` on both control blocks, alone and
/// in a whole-block read, and reports carry the same name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dat_set_carries_the_logical_device() {
    const QUALIFIED: &str = "IED1LD0/LLN0$dsPos";
    let f = start().await;
    let mut mms = f.connect().await;
    assert_eq!(
        read_urcb(&mut mms, "DatSet").await,
        MmsData::VisibleString(QUALIFIED.into())
    );
    assert_eq!(
        read_brcb(&mut mms, "DatSet").await,
        MmsData::VisibleString(QUALIFIED.into())
    );
    let MmsData::Structure(members) = mms.read(DOMAIN, BRCB_ITEM).await.expect("read BRCB") else {
        panic!("a BRCB reads as a structure");
    };
    assert_eq!(members[2], MmsData::VisibleString(QUALIFIED.into()));
    let MmsData::Structure(members) = mms.read(DOMAIN, URCB_ITEM).await.expect("read URCB") else {
        panic!("a URCB reads as a structure");
    };
    assert_eq!(members[3], MmsData::VisibleString(QUALIFIED.into()));

    let opt_flds = OptFlds::SEQ_NUM | OptFlds::DATA_SET;
    let [padding, data @ ..] = opt_flds.to_ber_bit_string();
    write_urcb(&mut mms, "Resv", MmsData::Boolean(true))
        .await
        .expect("reserve");
    for item in [URCB_ITEM, BRCB_ITEM] {
        mms.write(
            DOMAIN,
            &format!("{item}$OptFlds"),
            MmsData::BitString {
                padding,
                data: data.to_vec(),
            },
        )
        .await
        .expect("write OptFlds");
        mms.write(DOMAIN, &format!("{item}$RptEna"), MmsData::Boolean(true))
            .await
            .expect("enable");
    }
    f.set_st_val(2);
    let mut seen = Vec::new();
    for _ in 0..2 {
        let report = next_report(&mut mms).await;
        assert_eq!(report.data_set_name.as_deref(), Some(QUALIFIED));
        seen.push(report.rpt_id);
    }
    seen.sort();
    assert_eq!(seen, [BRCB_PATH, URCB_PATH]);
}

/// The client reads DatSet and writes it back unchanged: the server takes the
/// qualified name it reported, the data set stays bound, and ConfRev does not
/// move.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_writes_back_the_dat_set_it_read() {
    use iec61850_client::rcb::RcbWriteMask;
    use iec61850_client::IedConnection;
    let f = start().await;
    let conn = IedConnection::with_mms_client(
        MmsClientBuilder::new()
            .connect_timeout_ms(3_000)
            .request_timeout_ms(3_000)
            .build(),
    );
    conn.connect("127.0.0.1", f.handle.bound_addr.port())
        .await
        .expect("connect");
    for path in [URCB_PATH, BRCB_PATH] {
        let mut rcb = conn.get_rcb_values(path).await.expect("get_rcb_values");
        assert_eq!(rcb.data_set_reference(), Some("IED1LD0/LLN0$dsPos"));
        rcb.set_resv(true);
        let mask = if rcb.is_buffered() {
            RcbWriteMask::DAT_SET
        } else {
            RcbWriteMask::RESV | RcbWriteMask::DAT_SET
        };
        conn.set_rcb_values(&rcb, mask, false)
            .await
            .expect("write DatSet back");
        let after = conn.get_rcb_values(path).await.expect("get_rcb_values");
        assert_eq!(after.data_set_reference(), Some("IED1LD0/LLN0$dsPos"));
        assert_eq!(after.conf_rev(), 1);
    }
}

/// Resv of an enabled URCB and ResvTms of an enabled BRCB are refused with
/// temporarily-unavailable, whatever the value, and change nothing; once the
/// holder disables reporting it can release them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resv_and_resv_tms_refused_while_enabled() {
    let f = start().await;
    let mut mms = f.connect().await;
    write_urcb(&mut mms, "RptEna", MmsData::Boolean(true))
        .await
        .expect("enable the URCB");
    write_brcb(&mut mms, "ResvTms", MmsData::Integer(30))
        .await
        .expect("reserve the BRCB");
    write_brcb(&mut mms, "RptEna", MmsData::Boolean(true))
        .await
        .expect("enable the BRCB");

    for v in [false, true] {
        assert_refused_with(
            write_urcb(&mut mms, "Resv", MmsData::Boolean(v)).await,
            DataAccessError::TemporarilyUnavailable,
        );
    }
    for v in [0, 60] {
        assert_refused_with(
            write_brcb(&mut mms, "ResvTms", MmsData::Integer(v)).await,
            DataAccessError::TemporarilyUnavailable,
        );
    }
    assert_eq!(read_urcb(&mut mms, "Resv").await, MmsData::Boolean(true));
    assert_eq!(read_brcb(&mut mms, "ResvTms").await, MmsData::Integer(30));

    write_urcb(&mut mms, "RptEna", MmsData::Boolean(false))
        .await
        .expect("disable the URCB");
    write_urcb(&mut mms, "Resv", MmsData::Boolean(false))
        .await
        .expect("release the URCB");
    write_brcb(&mut mms, "RptEna", MmsData::Boolean(false))
        .await
        .expect("disable the BRCB");
    write_brcb(&mut mms, "ResvTms", MmsData::Integer(0))
        .await
        .expect("release the BRCB");
    assert_eq!(read_urcb(&mut mms, "Resv").await, MmsData::Boolean(false));
    assert_eq!(read_brcb(&mut mms, "ResvTms").await, MmsData::Integer(0));
}

/// Owner names the client that holds a control block by its IP address:
/// the client that reserved a URCB, and the client that enabled a BRCB. A
/// control block no client holds has an empty Owner.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owner_names_the_holding_client() {
    const LOOPBACK: [u8; 4] = [127, 0, 0, 1];
    let empty = MmsData::OctetString(Vec::new());
    let f = start().await;
    let mut holder = f.connect().await;
    let mut other = f.connect().await;
    assert_eq!(read_urcb(&mut other, "Owner").await, empty);
    assert_eq!(read_brcb(&mut other, "Owner").await, empty);

    write_urcb(&mut holder, "Resv", MmsData::Boolean(true))
        .await
        .expect("reserve the URCB");
    write_brcb(&mut holder, "RptEna", MmsData::Boolean(true))
        .await
        .expect("enable the BRCB");
    assert_eq!(
        read_urcb(&mut other, "Owner").await,
        MmsData::OctetString(LOOPBACK.to_vec())
    );
    assert_eq!(
        read_brcb(&mut other, "Owner").await,
        MmsData::OctetString(LOOPBACK.to_vec())
    );

    write_urcb(&mut holder, "Resv", MmsData::Boolean(false))
        .await
        .expect("release the URCB");
    write_brcb(&mut holder, "RptEna", MmsData::Boolean(false))
        .await
        .expect("disable the BRCB");
    assert_eq!(read_urcb(&mut other, "Owner").await, empty);
    assert_eq!(read_brcb(&mut other, "Owner").await, empty);
}
