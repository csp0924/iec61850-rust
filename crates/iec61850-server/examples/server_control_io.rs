//! Serves the demonstration IED and exercises the control service.
//!
//! Loads `examples/models/demo.cid` and registers its one control point,
//! `GGIO1.SPCSO1`, under the control model given on the command line. The four
//! models of IEC 61850-7-2 differ in what a client must do before the value
//! moves, so running the example once per model walks the whole matrix:
//!
//! | Argument | Control model | Client sequence |
//! |---|---|---|
//! | `direct-normal` (default) | direct-with-normal-security | Operate |
//! | `direct-enhanced` | direct-with-enhanced-security | Operate, CommandTermination |
//! | `sbo-normal` | select-before-operate, normal | Select, Operate |
//! | `sbo-enhanced` | select-before-operate, enhanced | SelectWithValue, Operate, CommandTermination |
//!
//! Passing `--interlock` additionally installs a check handler that refuses
//! every command with `BlockedByInterlocking`, which is the failure path a
//! client has to handle.
//!
//! ```sh
//! cargo run -p iec61850-server --example server_control_io
//! cargo run -p iec61850-server --example server_control_io -- sbo-enhanced
//! cargo run -p iec61850-server --example server_control_io -- direct-normal --interlock
//! ```
//!
//! Expected stdout:
//!
//! ```text
//! serving DemoIEDLD0 from .../examples/models/demo.cid
//! control object DemoIEDLD0/GGIO1.SPCSO1 as sbo-enhanced
//! listening on 127.0.0.1:8102
//! press Ctrl+C to stop
//! ```
//!
//! A bind address may be given as well, as in `-- sbo-normal 127.0.0.1:8102`.

use std::env;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use iec61850_model::tree::IedModel;
use iec61850_model::{ControlModel, MmsValue};
use iec61850_server::control::{
    AlwaysAcceptCheckHandler, AlwaysAcceptWaitHandler, AlwaysSuccessOperateHandler, CheckHandler,
    ControlAction, ControlAddCause, ControlHandler, ControlObject, ControlObjectConfig,
    ControlObjectEntry, SboClass, WaitForExecutionHandler,
};
use iec61850_server::{IedServer, IedServerConfig};

const IED_NAME: &str = "DemoIED";
const LD_INST: &str = "LD0";
const LN_NAME: &str = "GGIO1";
const DO_NAME: &str = "SPCSO1";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    let interlock = args.iter().any(|a| a == "--interlock");
    let (ctl_model, model_label) = parse_control_model(&args)?;
    let bind_addr: SocketAddr = args
        .iter()
        .find(|a| a.contains(':'))
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:8102".to_string())
        .parse()?;

    let model = load_model(Path::new(DEMO_CID))?;
    let domain = model
        .ld_by_inst(LD_INST)
        .ok_or("the CID has no logical device LD0")?
        .domain_name(&model.ied_name);
    println!("serving {domain} from {DEMO_CID}");

    let server = IedServer::builder()
        .model(Arc::new(model))
        .bind(bind_addr)
        .config(IedServerConfig {
            max_mms_connections: 5,
            ..Default::default()
        })
        .build()?;

    register_control_object(&server, &domain, ctl_model, interlock);
    println!("control object {domain}/{LN_NAME}.{DO_NAME} as {model_label}");
    if interlock {
        println!("every command is refused with BlockedByInterlocking");
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        let handle = server.start().await?;
        println!("listening on {}", handle.bound_addr);
        println!("press Ctrl+C to stop");
        tokio::signal::ctrl_c().await?;
        println!("shutting down");
        handle.stop().await;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;

    Ok(())
}

/// Map the control-model argument onto the runtime enum.
///
/// # Errors
///
/// Returns an error naming the accepted values when the argument is not one of
/// them.
fn parse_control_model(
    args: &[String],
) -> Result<(ControlModel, &'static str), Box<dyn std::error::Error>> {
    let requested = args
        .iter()
        .find(|a| !a.starts_with("--") && !a.contains(':'))
        .map(String::as_str)
        .unwrap_or("direct-normal");
    match requested {
        "direct-normal" => Ok((ControlModel::DirectNormal, "direct-normal")),
        "direct-enhanced" => Ok((ControlModel::DirectEnhanced, "direct-enhanced")),
        "sbo-normal" => Ok((ControlModel::SboNormal, "sbo-normal")),
        "sbo-enhanced" => Ok((ControlModel::SboEnhanced, "sbo-enhanced")),
        other => Err(format!(
            "unknown control model {other}, expected one of direct-normal, direct-enhanced, sbo-normal, sbo-enhanced"
        )
        .into()),
    }
}

fn register_control_object(
    server: &IedServer,
    domain: &str,
    ctl_model: ControlModel,
    interlock: bool,
) {
    let obj = ControlObject::new(ControlObjectConfig {
        name: DO_NAME.into(),
        ln_name: LN_NAME.into(),
        domain: domain.into(),
        ctl_model,
        sbo_timeout_ms: 30_000,
        sbo_class: SboClass::OperateOnce,
    });
    let check: Arc<dyn CheckHandler> = if interlock {
        Arc::new(AlwaysBlockedCheck)
    } else {
        Arc::new(AlwaysAcceptCheckHandler)
    };
    let entry = ControlObjectEntry::new(obj)
        .with_check(check)
        .with_wait(Arc::new(AlwaysAcceptWaitHandler) as Arc<dyn WaitForExecutionHandler>)
        .with_operate(Arc::new(AlwaysSuccessOperateHandler) as Arc<dyn ControlHandler>);
    server.control_objects().register(entry);
}

/// Refuses every command, so a client sees the interlocking failure path.
struct AlwaysBlockedCheck;

impl CheckHandler for AlwaysBlockedCheck {
    fn check(
        &self,
        _action: &ControlAction,
        _ctl_val: Option<&MmsValue>,
        _test: bool,
        _interlock_check: bool,
    ) -> Result<(), ControlAddCause> {
        Err(ControlAddCause::BlockedByInterlocking)
    }
}

/// The CID ships inside this crate, so the path resolves in a published
/// package as well as in the repository.
const DEMO_CID: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/models/demo.cid");

fn load_model(path: &Path) -> Result<IedModel, Box<dyn std::error::Error>> {
    let xml = std::fs::read_to_string(path)?;
    let raw = iec61850_scl::parse_scl(&xml)?;
    let resolved = iec61850_scl::ResolvedScl::from_raw(raw)?;
    Ok(resolved.build_model(IED_NAME)?)
}
