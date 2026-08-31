//! Builds the demonstration model in Rust instead of loading SCL, and reports on it.
//!
//! Every other server example here loads `examples/models/demo.cid`. This one
//! constructs the same IED through `IedModelBuilder` and the common data class
//! factories, which is the path an application takes when its model comes from
//! somewhere other than an SCL file. The object names match the CID, so the
//! client examples work against either server.
//!
//! It then registers one unbuffered report control block by hand,
//! `DemoIEDLD0/LLN0$RP$urcbMeas` over the three measured values, and drives
//! those values once a second so reports keep arriving.
//!
//! Pairs with the `client_reporting_subscriber` example.
//!
//! ```sh
//! # Terminal 1
//! cargo run -p iec61850-server --example server_with_reporting
//!
//! # Terminal 2
//! cargo run -p iec61850-client --example client_reporting_subscriber
//! ```
//!
//! Expected stdout:
//!
//! ```text
//! model DemoIED built in memory, MMS domain DemoIEDLD0
//! URCB DemoIEDLD0/LLN0$RP$urcbMeas over 3 members
//! listening on 127.0.0.1:8102
//! press Ctrl+C to stop
//! ```
//!
//! The default bind address is `127.0.0.1:8102`. Pass a bind address to
//! override it.

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iec61850_model::{
    cdc, ControlModel, ControlOptions, DataAttribute, DataAttributeType, DataObjectBuilder,
    IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNode, LogicalNodeBuilder, MmsValue,
    NodeRef, ObjectRef, TrgOps, FC,
};
use iec61850_server::{
    Dataset, DatasetEntry, IedServer, IedServerConfig, OptFlds, Rcb, ReportControl, TriggerOptions,
    WriteAccessPolicies,
};

const IED_NAME: &str = "DemoIED";
const LD_INST: &str = "LD0";
const DOMAIN: &str = "DemoIEDLD0";
const RCB_NAME: &str = "urcbMeas";
const RCB_MMS_PATH: &str = "DemoIEDLD0/LLN0$RP$urcbMeas";
/// Data set name in MMS form: the owning LN, then the SCL data set name.
const DATASET_NAME: &str = "LLN0$dsMeas";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr: SocketAddr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8102".to_string())
        .parse()?;

    let model = build_model()?;
    println!("model {IED_NAME} built in memory, MMS domain {DOMAIN}");

    let mut write_access = WriteAccessPolicies::default();
    write_access.set(FC::Dc, true);

    let server = IedServer::builder()
        .model(Arc::new(model))
        .bind(bind_addr)
        .config(IedServerConfig {
            max_mms_connections: 5,
            write_access_policies: write_access,
            ..Default::default()
        })
        .build()?;

    let handles = register_urcb(&server)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        let handle = server.start().await?;
        println!("listening on {}", handle.bound_addr);
        println!("press Ctrl+C to stop");

        let updater = tokio::spawn(run_value_updater(server.clone(), handles));
        tokio::signal::ctrl_c().await?;
        println!("shutting down");
        updater.abort();
        handle.stop().await;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;

    Ok(())
}

// Model

/// Build the same IED the CID describes: LD0 with LLN0, LPHD1, MMXU1 and GGIO1.
fn build_model() -> Result<IedModel, Box<dyn std::error::Error>> {
    let ld = LogicalDeviceBuilder::new(LD_INST)
        .add_ln(build_lln0()?)
        .add_ln(build_lphd1()?)
        .add_ln(build_mmxu1()?)
        .add_ln(build_ggio1()?)
        .build()?;
    Ok(IedModelBuilder::new(IED_NAME).add_ld(ld)?.build()?)
}

/// LLN0 carries the mandatory Mod, Beh and Health plus the name plate.
fn build_lln0() -> Result<LogicalNode, Box<dyn std::error::Error>> {
    let name_plate = DataObjectBuilder::scalar("NamPlt")
        .add_da(
            "vendor",
            FC::Dc,
            DataAttributeType::VisibleString(255),
            TrgOps::NONE,
            MmsValue::VisibleString("rust61850".into()),
        )
        .add_da(
            "swRev",
            FC::Dc,
            DataAttributeType::VisibleString(255),
            TrgOps::NONE,
            MmsValue::VisibleString("0.1.0".into()),
        )
        .add_da(
            "d",
            FC::Dc,
            DataAttributeType::VisibleString(255),
            TrgOps::NONE,
            MmsValue::VisibleString("iec61850-rust demonstration IED".into()),
        )
        .add_da(
            "configRev",
            FC::Dc,
            DataAttributeType::VisibleString(255),
            TrgOps::NONE,
            MmsValue::VisibleString("1.0".into()),
        )
        .build()?;

    Ok(LogicalNodeBuilder::lln0()
        .add_do(cdc::ens("Mod", cdc::CdcOptions::NONE))
        .add_do(cdc::ens("Beh", cdc::CdcOptions::NONE))
        .add_do(cdc::ens("Health", cdc::CdcOptions::NONE))
        .add_do(name_plate)
        .build()?)
}

/// LPHD1 describes the physical device behind the logical one.
fn build_lphd1() -> Result<LogicalNode, Box<dyn std::error::Error>> {
    let phy_name = DataObjectBuilder::scalar("PhyNam")
        .add_da(
            "vendor",
            FC::Dc,
            DataAttributeType::VisibleString(255),
            TrgOps::NONE,
            MmsValue::VisibleString("rust61850".into()),
        )
        .add_da(
            "swRev",
            FC::Dc,
            DataAttributeType::VisibleString(255),
            TrgOps::NONE,
            MmsValue::VisibleString("0.1.0".into()),
        )
        .add_da(
            "model",
            FC::Dc,
            DataAttributeType::VisibleString(255),
            TrgOps::NONE,
            MmsValue::VisibleString("iec61850-rust".into()),
        )
        .build()?;

    Ok(LogicalNodeBuilder::new("", "LPHD", "1")
        .add_do(phy_name)
        .add_do(cdc::ens("PhyHealth", cdc::CdcOptions::NONE))
        .add_do(cdc::sps("Proxy", cdc::CdcOptions::NONE))
        .build()?)
}

/// MMXU1 holds the measured values: two scalars and one three-phase set.
///
/// `cdc::wye` builds all six phases of the CDC, so `PhV` here is a superset of
/// the three phases the CID declares.
fn build_mmxu1() -> Result<LogicalNode, Box<dyn std::error::Error>> {
    Ok(LogicalNodeBuilder::new("", "MMXU", "1")
        .add_do(cdc::mv("TotW", cdc::CdcOptions::NONE, false))
        .add_do(cdc::mv("Hz", cdc::CdcOptions::NONE, false))
        .add_do(cdc::wye("PhV", cdc::CdcOptions::NONE))
        .build()?)
}

/// GGIO1 holds the binary status points and the one control point.
fn build_ggio1() -> Result<LogicalNode, Box<dyn std::error::Error>> {
    let mut b = LogicalNodeBuilder::new("", "GGIO", "1");
    for i in 1..=4 {
        b = b.add_do(cdc::sps(format!("Ind{i}"), cdc::CdcOptions::NONE));
    }
    let spc = ControlOptions::HAS_CANCEL.with_model(ControlModel::DirectNormal);
    Ok(b.add_do(cdc::spc("SPCSO1", cdc::CdcOptions::NONE, spc))
        .build()?)
}

// Reporting

/// Live slots the background task writes to.
struct UpdaterHandles {
    tot_w: DataAttribute,
    hz: DataAttribute,
    phv_a: DataAttribute,
}

/// Register the data set and the URCB over it, by hand rather than from SCL.
fn register_urcb(server: &IedServer) -> Result<UpdaterHandles, Box<dyn std::error::Error>> {
    let model = server.model();
    let need = |path: &str| -> Result<DataAttribute, Box<dyn std::error::Error>> {
        resolve_da(&model, path).ok_or_else(|| format!("{path} not found in the model").into())
    };

    // Each member pairs the live value slot with the wire data reference,
    // `<domain>/<LN>$<FC>$<DO>$<DA>` per IEC 61850-8-1.
    let members = [
        (
            need(&format!("{DOMAIN}/MMXU1.TotW.mag.f"))?,
            format!("{DOMAIN}/MMXU1$MX$TotW$mag$f"),
        ),
        (
            need(&format!("{DOMAIN}/MMXU1.Hz.mag.f"))?,
            format!("{DOMAIN}/MMXU1$MX$Hz$mag$f"),
        ),
        (
            need(&format!("{DOMAIN}/MMXU1.PhV.phsA.cVal.mag.f"))?,
            format!("{DOMAIN}/MMXU1$MX$PhV$phsA$cVal$mag$f"),
        ),
    ];

    let mut ds = Dataset::new(DATASET_NAME);
    for (da, data_ref) in &members {
        ds.push(DatasetEntry::new(data_ref.clone(), Arc::clone(&da.value)));
    }

    let rcb = Rcb::new(RCB_NAME, DATASET_NAME)
        .with_rpt_id(RCB_MMS_PATH)
        .with_conf_rev(1)
        .with_trg_ops(
            TriggerOptions::DATA_CHANGED | TriggerOptions::QUALITY_CHANGED | TriggerOptions::GI,
        )
        .with_opt_flds(
            OptFlds::SEQ_NUM
                | OptFlds::TIME_STAMP
                | OptFlds::DATA_SET
                | OptFlds::REASON
                | OptFlds::DATA_REFERENCE
                | OptFlds::CONF_REV,
        )
        .with_buf_tm_ms(100);
    server.register_urcb(ReportControl::new(RCB_MMS_PATH, rcb), ds)?;
    println!("URCB {RCB_MMS_PATH} over {} members", members.len());

    let [(tot_w, _), (hz, _), (phv_a, _)] = members;
    Ok(UpdaterHandles { tot_w, hz, phv_a })
}

/// Move the measured values once a second so data-change triggers fire.
async fn run_value_updater(server: IedServer, handles: UpdaterHandles) {
    let mut ticks: f32 = 0.0;
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    loop {
        ticker.tick().await;
        ticks += 1.0;
        for (da, value) in [
            (&handles.tot_w, 1000.0 + ticks),
            (&handles.hz, 50.0 + (ticks % 10.0) * 0.01),
            (&handles.phv_a, 230.0 + (ticks % 5.0)),
        ] {
            if let Err(e) = server.update_float32(da, value) {
                eprintln!("update {} failed: {e}", da.name);
            }
        }
    }
}

/// Resolve an object reference to an owned handle on the shared value slot.
fn resolve_da(model: &IedModel, iec_path: &str) -> Option<DataAttribute> {
    let r = ObjectRef::parse_iec(iec_path).ok()?;
    match model.node_by_object_ref(&r)? {
        NodeRef::Da(da) => Some(DataAttribute {
            name: da.name.clone(),
            fc: da.fc,
            ty: da.ty,
            trg_ops: da.trg_ops,
            value: da.value.clone(),
            children: Vec::new(),
        }),
        _ => None,
    }
}
