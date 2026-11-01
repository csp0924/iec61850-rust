//! Buffered reporting enabled by a client over MMS.
//!
//! A client that writes `RptEna` of a BRCB receives its reports on the
//! association it wrote from, with or without writing `EntryID` first and
//! whatever the buffer time. A BRCB enabled by one association refuses `RptEna`
//! from another. When the association ends the BRCB is disabled and keeps
//! buffering, so a client that reconnects and enables it again receives the
//! entries buffered in between, from after the last entry sent or from an
//! `EntryID` it writes. No write other than one to `ResvTms` reserves the BRCB:
//! `ResvTms` stays 0 through configuration, enabling and the end of the
//! association. Reports are received on a raw MMS association and decoded
//! without client-side report state.

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

/// The `stVal` a Dbpos of `n` reads as.
fn dbpos(n: u8) -> MmsValue {
    MmsValue::BitString {
        padding: 6,
        data: vec![n << 6],
    }
}

/// A started server with one BRCB and one URCB over `[stVal]`, neither enabled.
struct Fixture {
    server: IedServer,
    handle: ServerHandle,
    st_val: DataAttribute,
}

async fn start(buf_tm_ms: u32) -> Fixture {
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
        )
        .with_buf_tm_ms(buf_tm_ms);
    server
        .register_brcb(BufferedReportControl::new(BRCB_PATH, brcb), data_set())
        .expect("register_brcb");
    let rcb = Rcb::new("urcbPos", "LLN0$dsPos")
        .with_trg_ops(TriggerOptions::DATA_CHANGED)
        .with_opt_flds(OptFlds::SEQ_NUM | OptFlds::REASON)
        .with_buf_tm_ms(buf_tm_ms);
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

    /// Waits until the server has released every association.
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

async fn write_brcb(mms: &mut MmsClient, field: &str, value: MmsData) -> Result<(), ClientError> {
    mms.write(DOMAIN, &format!("LLN0$BR$brcbPos${field}"), value)
        .await
}

async fn brcb_rpt_ena(mms: &mut MmsClient) -> MmsData {
    mms.read(DOMAIN, "LLN0$BR$brcbPos$RptEna")
        .await
        .expect("read RptEna")
}

fn assert_access_denied(result: Result<(), ClientError>) {
    match result {
        Err(ClientError::DataAccessError(DataAccessError::ObjectAccessDenied)) => {}
        other => panic!("expected object-access-denied, got {other:?}"),
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

fn assert_brcb_report(report: &ParsedReport, st_val: MmsValue) {
    assert_eq!(report.rpt_id, BRCB_PATH, "report id");
    assert_eq!(report.data_values, [st_val], "data values");
    assert!(
        report.entry_id.is_some(),
        "a buffered report carries EntryID"
    );
}

/// A BRCB enabled over MMS reports every change on the association that
/// enabled it, with or without an `EntryID` written first and whatever the
/// buffer time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brcb_enabled_over_mms_sends_reports() {
    for buf_tm_ms in [0, 10] {
        for write_entry_id in [false, true] {
            let f = start(buf_tm_ms).await;
            let mut mms = f.connect().await;
            if write_entry_id {
                write_brcb(&mut mms, "EntryID", MmsData::OctetString(vec![0; 8]))
                    .await
                    .expect("write EntryID");
            }
            write_brcb(&mut mms, "RptEna", MmsData::Boolean(true))
                .await
                .expect("enable the brcb");

            f.set_st_val(2);
            let first = next_report(&mut mms).await;
            assert_brcb_report(&first, dbpos(2));

            f.set_st_val(1);
            let second = next_report(&mut mms).await;
            assert_brcb_report(&second, dbpos(1));
            assert!(second.entry_id > first.entry_id, "entry ids increase");
            assert_eq!(
                second.seq_num.map(|n| n.wrapping_sub(1)),
                first.seq_num,
                "sequence numbers advance by one"
            );
        }
    }
}

/// A URCB reserved and enabled over MMS reports on the association that
/// enabled it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn urcb_enabled_over_mms_sends_reports() {
    for buf_tm_ms in [0, 10] {
        let f = start(buf_tm_ms).await;
        let mut mms = f.connect().await;
        for item in ["LLN0$RP$urcbPos$Resv", "LLN0$RP$urcbPos$RptEna"] {
            mms.write(DOMAIN, item, MmsData::Boolean(true))
                .await
                .expect("enable the urcb");
        }

        f.set_st_val(2);
        let report = next_report(&mut mms).await;
        assert_eq!(report.rpt_id, URCB_PATH, "report id");
        assert_eq!(report.data_values, [dbpos(2)], "data values");
    }
}

/// A BRCB enabled by one association refuses `RptEna` from another, and keeps
/// reporting to the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brcb_enabled_by_another_association_refuses_rpt_ena() {
    let f = start(0).await;
    let mut owner = f.connect().await;
    let mut other = f.connect().await;
    write_brcb(&mut owner, "RptEna", MmsData::Boolean(true))
        .await
        .expect("enable the brcb");

    assert_access_denied(write_brcb(&mut other, "RptEna", MmsData::Boolean(true)).await);
    assert_access_denied(write_brcb(&mut other, "RptEna", MmsData::Boolean(false)).await);
    assert_eq!(brcb_rpt_ena(&mut other).await, MmsData::Boolean(true));

    f.set_st_val(2);
    assert_brcb_report(&next_report(&mut owner).await, dbpos(2));

    // The owner may write RptEna again, and disabling releases it to others.
    write_brcb(&mut owner, "RptEna", MmsData::Boolean(true))
        .await
        .expect("re-enable on the owner");
    write_brcb(&mut owner, "RptEna", MmsData::Boolean(false))
        .await
        .expect("disable on the owner");
    write_brcb(&mut other, "RptEna", MmsData::Boolean(true))
        .await
        .expect("enable on the other association");
    f.set_st_val(1);
    assert_brcb_report(&next_report(&mut other).await, dbpos(1));
}

/// When the association that enabled a BRCB ends, the BRCB is disabled and
/// keeps buffering; a client that reconnects and enables it again receives the
/// entry buffered in between, after the last entry sent or after the `EntryID`
/// it writes, and nothing it already received. As the first report after the
/// control block is enabled, it carries `BufOvfl = TRUE`
/// (IEC 61850-7-2 §17.2.3.2.2.8).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brcb_resumes_after_the_client_reconnects() {
    for resync in [false, true] {
        let f = start(0).await;
        let mut first = f.connect().await;
        write_brcb(&mut first, "RptEna", MmsData::Boolean(true))
            .await
            .expect("enable the brcb");
        f.set_st_val(2);
        let sent = next_report(&mut first).await;
        assert_brcb_report(&sent, dbpos(2));

        first.disconnect().await.expect("disconnect");
        f.wait_for_no_connection().await;
        f.set_st_val(1);

        let mut second = f.connect().await;
        assert_eq!(brcb_rpt_ena(&mut second).await, MmsData::Boolean(false));
        if resync {
            let entry_id = sent.entry_id.clone().expect("EntryID");
            write_brcb(&mut second, "EntryID", MmsData::OctetString(entry_id))
                .await
                .expect("write EntryID");
        }
        write_brcb(&mut second, "RptEna", MmsData::Boolean(true))
            .await
            .expect("enable the brcb again");

        let resumed = next_report(&mut second).await;
        assert_brcb_report(&resumed, dbpos(1));
        assert!(resumed.entry_id > sent.entry_id, "resync {resync}");
        assert_eq!(resumed.buf_ovfl, Some(true), "resync {resync}");
    }
}

/// A client that reserves a BRCB through `ResvTms` is its owner, by address:
/// `Owner` reads back the client address, and after the association ends a new
/// association from the same address takes the BRCB back and receives the
/// entries buffered in between.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brcb_reserved_over_mms_is_taken_back_by_its_owner() {
    let f = start(0).await;
    let mut first = f.connect().await;
    write_brcb(&mut first, "ResvTms", MmsData::Integer(30))
        .await
        .expect("write ResvTms");
    assert_eq!(
        first
            .read(DOMAIN, "LLN0$BR$brcbPos$Owner")
            .await
            .expect("read Owner"),
        MmsData::OctetString(vec![127, 0, 0, 1])
    );
    write_brcb(&mut first, "RptEna", MmsData::Boolean(true))
        .await
        .expect("enable the brcb");
    f.set_st_val(2);
    let sent = next_report(&mut first).await;
    assert_brcb_report(&sent, dbpos(2));

    first.disconnect().await.expect("disconnect");
    f.wait_for_no_connection().await;
    f.set_st_val(1);

    let mut second = f.connect().await;
    write_brcb(&mut second, "RptEna", MmsData::Boolean(true))
        .await
        .expect("the owner enables the brcb again");
    let resumed = next_report(&mut second).await;
    assert_brcb_report(&resumed, dbpos(1));
    assert!(resumed.entry_id > sent.entry_id);
}

async fn brcb_resv_tms(mms: &mut MmsClient) -> MmsData {
    mms.read(DOMAIN, "LLN0$BR$brcbPos$ResvTms")
        .await
        .expect("read ResvTms")
}

/// On a BRCB with `ResvTms` = 0, writes other than one to `ResvTms` reserve
/// nothing (IEC 61850-7-2 §17.2.2.17): after configuration writes another client
/// still configures it, enabling and disabling leave `ResvTms` at 0, disabling
/// lets another client configure it again, and once the association that
/// enabled it ends `ResvTms` reads 0 and another client takes the BRCB at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brcb_writes_other_than_resv_tms_do_not_reserve() {
    let f = start(0).await;
    let mut first = f.connect().await;
    let mut other = f.connect().await;

    write_brcb(&mut first, "IntgPd", MmsData::Unsigned(0))
        .await
        .expect("configure the brcb");
    write_brcb(&mut first, "EntryID", MmsData::OctetString(vec![0; 8]))
        .await
        .expect("write EntryID");
    assert_eq!(brcb_resv_tms(&mut other).await, MmsData::Integer(0));
    write_brcb(&mut other, "IntgPd", MmsData::Unsigned(0))
        .await
        .expect("another client configures the unreserved brcb");

    for enable in [true, false, true] {
        write_brcb(&mut first, "RptEna", MmsData::Boolean(enable))
            .await
            .expect("write RptEna");
        assert_eq!(brcb_resv_tms(&mut other).await, MmsData::Integer(0));
        if !enable {
            write_brcb(&mut other, "IntgPd", MmsData::Unsigned(0))
                .await
                .expect("another client configures the disabled brcb");
        }
    }

    first.disconnect().await.expect("disconnect");
    other.disconnect().await.expect("disconnect");
    f.wait_for_no_connection().await;

    let mut next = f.connect().await;
    assert_eq!(brcb_resv_tms(&mut next).await, MmsData::Integer(0));
    write_brcb(&mut next, "RptEna", MmsData::Boolean(true))
        .await
        .expect("another association enables the brcb at once");
    f.set_st_val(2);
    assert_brcb_report(&next_report(&mut next).await, dbpos(2));
}

fn assert_refused_with(result: Result<(), ClientError>, expected: DataAccessError) {
    match result {
        Err(ClientError::DataAccessError(e)) if e == expected => {}
        other => panic!("expected {expected:?}, got {other:?}"),
    }
}

/// `ResvTms` takes an INT16 from 0 to 32767 or an unsigned value in that range;
/// any other value is refused with object-value-invalid and leaves the
/// reservation as it was. No other field takes an INT.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brcb_resv_tms_takes_only_its_range() {
    let f = start(0).await;
    let mut mms = f.connect().await;
    write_brcb(&mut mms, "ResvTms", MmsData::Integer(30))
        .await
        .expect("write ResvTms");

    for value in [
        MmsData::Integer(-1),
        MmsData::Integer(40_000),
        MmsData::Integer(5_000_000_000),
        MmsData::Unsigned(40_000),
        MmsData::Unsigned(1 << 32),
    ] {
        assert_refused_with(
            write_brcb(&mut mms, "ResvTms", value).await,
            DataAccessError::ObjectValueInvalid,
        );
    }
    assert_eq!(
        mms.read(DOMAIN, "LLN0$BR$brcbPos$ResvTms")
            .await
            .expect("read ResvTms"),
        MmsData::Integer(30)
    );

    assert_refused_with(
        write_brcb(&mut mms, "IntgPd", MmsData::Integer(100)).await,
        DataAccessError::TypeInconsistent,
    );
}
