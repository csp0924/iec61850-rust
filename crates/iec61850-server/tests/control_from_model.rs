//! Control objects built from the model: registration from the data objects
//! that declare `ctlModel`, settings read from their configuration attributes,
//! and a change of those attributes over the wire.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iec61850_mms::mms::client::{ClientError, MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::common::{DataAccessError, MmsData};
use iec61850_model::cdc::{self, CdcOptions, ControlOptions};
use iec61850_model::{
    ControlModel, DataAttribute, DataAttributeType, DataObject, DoChild, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::control::{
    AlwaysSuccessOperateHandler, ControlHandler, ControlObject, ControlObjectConfig,
    ControlObjectEntry, ControlObjectsRegistry, ControlState, SboClass,
};
use iec61850_server::{IedServer, IedServerConfig, ServerHandle, WriteAccessPolicies};

const DOMAIN: &str = "ctlLD0";

fn cf(name: &str, ty: DataAttributeType, value: MmsValue) -> DoChild {
    DoChild::Da(DataAttribute::new(name, FC::Cf, ty, TrgOps::DCHG, value))
}

fn spc(name: &str, model: ControlModel) -> DataObject {
    cdc::spc(
        name,
        CdcOptions::NONE,
        ControlOptions::NONE
            .with_model(model)
            .union(ControlOptions::HAS_CANCEL),
    )
}

/// One SPC per control model, a status-only one, a DPC, and an SPC that
/// declares every configuration attribute.
fn build_model() -> Arc<IedModel> {
    let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
    let mut configured = spc("SPCSO6", ControlModel::SboNormal);
    configured.children.push(cf(
        "sboTimeout",
        DataAttributeType::Int32U,
        MmsValue::Unsigned(500),
    ));
    configured.children.push(cf(
        "sboClass",
        DataAttributeType::Enumerated,
        MmsValue::Integer(1),
    ));
    configured.children.push(cf(
        "operTimeout",
        DataAttributeType::Int32U,
        MmsValue::Unsigned(250),
    ));
    let ggio = LogicalNodeBuilder::new("", "GGIO", "1")
        .add_do(spc("SPCSO0", ControlModel::StatusOnly))
        .add_do(spc("SPCSO1", ControlModel::DirectNormal))
        .add_do(spc("SPCSO2", ControlModel::SboNormal))
        .add_do(spc("SPCSO3", ControlModel::DirectEnhanced))
        .add_do(spc("SPCSO4", ControlModel::SboEnhanced))
        .add_do(configured)
        .build()
        .expect("ggio");
    let cswi = LogicalNodeBuilder::new("", "CSWI", "1")
        .add_do(cdc::dpc(
            "Pos",
            CdcOptions::NONE,
            ControlOptions::NONE.with_model(ControlModel::SboEnhanced),
        ))
        .build()
        .expect("cswi");
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .add_ln(ggio)
        .add_ln(cswi)
        .build()
        .expect("ld");
    Arc::new(
        IedModelBuilder::new("ctl")
            .add_ld(ld)
            .expect("add_ld")
            .build()
            .expect("model"),
    )
}

fn ctl_model_of(registry: &ControlObjectsRegistry, ln: &str, do_name: &str) -> ControlModel {
    registry
        .lookup(DOMAIN, ln, do_name)
        .unwrap_or_else(|| panic!("{ln}.{do_name} is registered"))
        .object
        .settings()
        .ctl_model
}

#[test]
fn every_controllable_data_object_is_registered_with_its_model() {
    let model = build_model();
    let registry = ControlObjectsRegistry::new();
    assert_eq!(registry.register_from_model(&model), 6);
    assert_eq!(registry.len(), 6);
    assert!(
        registry.lookup(DOMAIN, "GGIO1", "SPCSO0").is_none(),
        "a status-only object is not controllable"
    );
    for (ln, name, ctl_model) in [
        ("GGIO1", "SPCSO1", ControlModel::DirectNormal),
        ("GGIO1", "SPCSO2", ControlModel::SboNormal),
        ("GGIO1", "SPCSO3", ControlModel::DirectEnhanced),
        ("GGIO1", "SPCSO4", ControlModel::SboEnhanced),
        ("GGIO1", "SPCSO6", ControlModel::SboNormal),
        ("CSWI1", "Pos", ControlModel::SboEnhanced),
    ] {
        assert_eq!(ctl_model_of(&registry, ln, name), ctl_model, "{ln}.{name}");
    }
    // Registering again leaves the existing entries alone.
    assert_eq!(registry.register_from_model(&model), 0);
}

#[test]
fn settings_come_from_the_configuration_attributes() {
    let model = build_model();
    let configured = ControlObject::from_model(&model, DOMAIN, "GGIO1", "SPCSO6").expect("SPCSO6");
    let s = configured.settings();
    assert_eq!(s.ctl_model, ControlModel::SboNormal);
    assert_eq!(s.sbo_timeout_ms, 500);
    assert_eq!(s.sbo_class, SboClass::OperateMany);
    assert_eq!(s.oper_timeout_ms, 250);

    // Attributes the model leaves out take the documented defaults.
    let plain = ControlObject::from_model(&model, DOMAIN, "GGIO1", "SPCSO2").expect("SPCSO2");
    let s = plain.settings();
    assert_eq!(s.sbo_timeout_ms, 30_000);
    assert_eq!(s.sbo_class, SboClass::OperateOnce);
    assert_eq!(s.oper_timeout_ms, 0);

    assert!(ControlObject::from_model(&model, DOMAIN, "GGIO1", "SPCSO9").is_none());
}

fn cf_value(
    model: &IedModel,
    ln: &str,
    do_name: &str,
    attr: &str,
) -> Arc<std::sync::RwLock<MmsValue>> {
    let data_object = model
        .ld_by_domain(DOMAIN)
        .and_then(|ld| ld.ln_by_name(ln))
        .and_then(|l| l.do_by_name(do_name))
        .expect("data object");
    data_object
        .children
        .iter()
        .find_map(|c| match c {
            DoChild::Da(da) if da.name == attr && da.fc == FC::Cf => Some(Arc::clone(&da.value)),
            _ => None,
        })
        .expect("attribute")
}

#[test]
fn a_selection_completes_under_the_settings_it_started_with() {
    let model = build_model();
    let obj = ControlObject::from_model(&model, DOMAIN, "GGIO1", "SPCSO2").expect("SPCSO2");
    let ctl_model = cf_value(&model, "GGIO1", "SPCSO2", "ctlModel");

    assert!(obj.try_select(1).expect("select"));
    *ctl_model.write().unwrap() = MmsValue::Integer(1);
    assert_eq!(
        obj.settings().ctl_model,
        ControlModel::SboNormal,
        "the selection keeps its control model"
    );
    assert!(!obj.try_select(1).expect("select"), "still selected");
    assert!(obj
        .try_unselect(
            1,
            iec61850_server::control::SelectStateChangedReason::Canceled,
            false
        )
        .expect("unselect"));
    assert_eq!(obj.settings().ctl_model, ControlModel::DirectNormal);

    // An out-of-range value falls back to the configured model.
    *ctl_model.write().unwrap() = MmsValue::Integer(9);
    assert_eq!(obj.settings().ctl_model, ControlModel::SboNormal);
}

#[tokio::test]
async fn the_select_class_of_the_model_decides_what_follows_an_operate() {
    let model = build_model();
    let params = iec61850_server::control::OperParams::from_mms_value(&MmsValue::Structure(vec![
        MmsValue::Boolean(true),
        MmsValue::Structure(vec![MmsValue::Integer(3), MmsValue::OctetString(vec![1])]),
        MmsValue::Unsigned(1),
        MmsValue::UtcTime([0; 8]),
        MmsValue::Boolean(false),
        MmsValue::BitString {
            padding: 6,
            data: vec![0],
        },
    ]))
    .expect("oper");
    for (name, after) in [
        ("SPCSO6", ControlState::Ready),
        ("SPCSO2", ControlState::Unselected),
    ] {
        let obj = ControlObject::from_model(&model, DOMAIN, "GGIO1", name).expect(name);
        assert!(obj.try_select(1).expect("select"));
        obj.begin_operate(1, &params).expect("operate");
        obj.finish_operate();
        assert_eq!(obj.state(), after, "{name}");
    }
}

#[test]
fn the_sample_configuration_registers_its_one_control_object() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/models/demo.cid");
    let xml = std::fs::read_to_string(path).expect("read demo.cid");
    let raw = iec61850_scl::parse_scl(&xml).expect("parse");
    let model = iec61850_scl::ResolvedScl::from_raw(raw)
        .expect("resolve")
        .build_model("DemoIED")
        .expect("model");
    let registry = ControlObjectsRegistry::new();
    assert_eq!(registry.register_from_model(&model), 1);
    let ld = model.lds.first().expect("one logical device");
    let domain = ld.domain_name(&model.ied_name);
    let entry = registry
        .lookup(&domain, "GGIO1", "SPCSO1")
        .expect("GGIO1.SPCSO1");
    assert_eq!(
        entry.object.settings().ctl_model,
        ControlModel::DirectNormal
    );
}

// ── Over the wire ───────────────────────────────────────────────────────────

fn server(model: Arc<IedModel>) -> IedServer {
    IedServer::builder()
        .model(model)
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config({
            let mut config = IedServerConfig::default();
            config.max_mms_connections = 2;
            let mut policies = WriteAccessPolicies::default_policy();
            policies.set(FC::Cf, true);
            config.write_access_policies = policies;
            config
        })
        .build()
        .expect("server")
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

fn oper(ctl_num: u64) -> MmsData {
    MmsData::Structure(vec![
        MmsData::Boolean(true),
        MmsData::Structure(vec![
            MmsData::Integer(3),
            MmsData::OctetString(b"probe".to_vec()),
        ]),
        MmsData::Unsigned(ctl_num),
        MmsData::UtcTime([0; 8]),
        MmsData::Boolean(false),
        MmsData::BitString {
            padding: 6,
            data: vec![0],
        },
    ])
}

fn denied(r: Result<(), ClientError>) -> DataAccessError {
    match r {
        Err(ClientError::DataAccessError(e)) => e,
        other => panic!("expected a data access error, got {other:?}"),
    }
}

/// Returns the members of the LastApplError report the client has queued.
async fn last_appl_error(c: &mut MmsClient) -> Vec<MmsData> {
    let inner = c
        .recv_unconfirmed_pdu_with_timeout(Duration::ZERO)
        .await
        .expect("receive")
        .expect("a LastApplError report");
    let report = iec61850_mms::mms::pdu::information_report::decode_information_report(&inner)
        .expect("report");
    match report.list_of_access_result.into_iter().next() {
        Some(MmsData::Structure(members)) => members,
        other => panic!("LastApplError is not a structure: {other:?}"),
    }
}

/// Registers every controllable object of the server's model with a control
/// handler that succeeds.
fn register_all(s: &IedServer) {
    let registry = s.control_objects();
    registry.register_from_model(&s.model());
    for (ln, name) in [("GGIO1", "SPCSO2"), ("GGIO1", "SPCSO4")] {
        let entry = registry.lookup(DOMAIN, ln, name).expect("registered");
        registry.register(
            entry.with_operate(Arc::new(AlwaysSuccessOperateHandler) as Arc<dyn ControlHandler>),
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn writing_ctl_model_switches_the_control_model() {
    let s = server(build_model());
    register_all(&s);
    let h = s.start().await.expect("start");
    let mut a = connect(&h).await;

    // Select-before-operate refuses an Operate without a select.
    let r = a.write(DOMAIN, "GGIO1$CO$SPCSO2$Oper", oper(1)).await;
    assert_eq!(denied(r), DataAccessError::ObjectAccessDenied);
    assert_eq!(
        last_appl_error(&mut a).await[4],
        MmsData::Integer(18),
        "AddCause Object-not-selected"
    );

    a.write(DOMAIN, "GGIO1$CF$SPCSO2$ctlModel", MmsData::Integer(1))
        .await
        .expect("write ctlModel");
    // Direct control now operates without a select, and has no SBO.
    a.write(DOMAIN, "GGIO1$CO$SPCSO2$Oper", oper(2))
        .await
        .expect("direct operate");
    match a.read(DOMAIN, "GGIO1$CO$SPCSO2$SBO").await {
        Err(ClientError::DataAccessError(e)) => assert_eq!(e, DataAccessError::ObjectNonExistent),
        other => panic!("expected object-non-existent, got {other:?}"),
    }

    // The model still declares SBOw on SPCSO4; under direct control a
    // SelectWithValue answers unknown.
    a.write(DOMAIN, "GGIO1$CF$SPCSO4$ctlModel", MmsData::Integer(3))
        .await
        .expect("write ctlModel");
    let r = a.write(DOMAIN, "GGIO1$CO$SPCSO4$SBOw", oper(3)).await;
    assert_eq!(denied(r), DataAccessError::ObjectAccessDenied);
    let lae = last_appl_error(&mut a).await;
    assert_eq!(lae[4], MmsData::Integer(0), "AddCause Unknown");
    let obj = s
        .control_objects()
        .lookup(DOMAIN, "GGIO1", "SPCSO4")
        .expect("SPCSO4")
        .object;
    assert_eq!(obj.state(), ControlState::Unselected);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_object_registered_by_hand_follows_the_model() {
    let s = server(build_model());
    // The configuration says direct control; the model says select-before-operate.
    let obj = ControlObject::new(ControlObjectConfig::new(
        "SPCSO2",
        "GGIO1",
        DOMAIN,
        ControlModel::DirectNormal,
    ));
    s.control_objects().register(
        ControlObjectEntry::new(obj.clone())
            .with_operate(Arc::new(AlwaysSuccessOperateHandler) as Arc<dyn ControlHandler>),
    );
    let h = s.start().await.expect("start");
    let mut a = connect(&h).await;

    let r = a.write(DOMAIN, "GGIO1$CO$SPCSO2$Oper", oper(1)).await;
    assert_eq!(denied(r), DataAccessError::ObjectAccessDenied);
    assert_eq!(last_appl_error(&mut a).await[4], MmsData::Integer(18));
    assert_eq!(obj.settings().ctl_model, ControlModel::SboNormal);

    a.write(DOMAIN, "GGIO1$CF$SPCSO2$ctlModel", MmsData::Integer(1))
        .await
        .expect("write ctlModel");
    a.write(DOMAIN, "GGIO1$CO$SPCSO2$Oper", oper(2))
        .await
        .expect("direct operate");
    h.stop().await;
}
