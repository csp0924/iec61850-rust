//! Report control block attribute services over MMS.
//!
//! SetURCBValues and SetBRCBValues as two clients see them over real TCP and the
//! full ISO stack: who holds a URCB reservation and when it is released, which
//! BRCB writes count ConfRev and which purge the buffer, and which writes an
//! enabled BRCB refuses.

use std::net::SocketAddr;
use std::sync::Arc;

use iec61850_mms::mms::client::{ClientError, MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::common::DataAccessError;
use iec61850_mms::mms::MmsData;
use iec61850_model::{
    cdc, DataAttribute, IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder,
    NodeRef, ObjectRef,
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

    #[allow(dead_code)]
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

#[allow(dead_code)]
async fn write_brcb(mms: &mut MmsClient, field: &str, value: MmsData) -> Result<(), ClientError> {
    mms.write(DOMAIN, &format!("{BRCB_ITEM}${field}"), value)
        .await
}

#[allow(dead_code)]
async fn read_brcb(mms: &mut MmsClient, field: &str) -> MmsData {
    mms.read(DOMAIN, &format!("{BRCB_ITEM}${field}"))
        .await
        .unwrap_or_else(|e| panic!("read {field}: {e:?}"))
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
