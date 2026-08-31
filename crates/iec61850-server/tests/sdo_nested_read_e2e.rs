//! End-to-end tests that Read and Write resolve references crossing
//! sub-data-object boundaries, over a loopback association.
//!
//! The Read and GetVariableAccessAttributes cases run against
//! `examples/models/demo.cid`, whose `MMXU1.PhV` is a WYE: the phase `phsA` is
//! a CMV whose `cVal` is a Vector of the AnalogValue attributes `mag` and
//! `ang`, each holding the leaf `f`. A client therefore addresses a float four
//! names below the data object, and the same values must be reachable at every
//! level in between: the whole data object, one phase, one attribute, and the
//! leaf. Browsing is checked on the same references, so it and reading agree on
//! what exists.
//!
//! The Write case needs a settable attribute below a sub-data-object, and every
//! functional constraint the CID nests under a phase is read-only, so it serves
//! a model built in this file instead: `PhSet.phsA.setMag` under SP, which the
//! default write access policy admits.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use iec61850_client::{ClientError, IedConnection};
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_mms::mms::pdu::type_specification::TypeSpecification;
use iec61850_model::tree::{DataAttribute, DataObject, DoChild, LogicalNode};
use iec61850_model::types::{DataAttributeType, TrgOps};
use iec61850_model::{IedModel, MmsValue, NodeRef, ObjectRef, FC};
use iec61850_model::{IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder};
use iec61850_server::{IedServer, IedServerConfig, ServerHandle};

const IED_NAME: &str = "DemoIED";
const PHV: &str = "DemoIEDLD0/MMXU1.PhV";
const PHS_A: &str = "DemoIEDLD0/MMXU1.PhV.phsA";
const C_VAL: &str = "DemoIEDLD0/MMXU1.PhV.phsA.cVal";
const MAG_F: &str = "DemoIEDLD0/MMXU1.PhV.phsA.cVal.mag.f";
const ANG_F: &str = "DemoIEDLD0/MMXU1.PhV.phsA.cVal.ang.f";

/// The CID ships inside this crate, so the path resolves in a published package
/// as well as in the repository.
const DEMO_CID: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/models/demo.cid");

/// The values seeded into the two leaves of `phsA.cVal` before the server
/// starts. They differ from each other and from the default so an assertion
/// distinguishes the leaves rather than matching two zeroes.
const MAG_SEED: f32 = 231.75;
const ANG_SEED: f32 = -12.5;

fn load_demo_model() -> Arc<IedModel> {
    let xml = std::fs::read_to_string(Path::new(DEMO_CID))
        .unwrap_or_else(|e| panic!("cannot read {DEMO_CID}: {e}"));
    let raw = iec61850_scl::parse_scl(&xml).expect("parse demo.cid");
    let resolved = iec61850_scl::ResolvedScl::from_raw(raw).expect("resolve demo.cid");
    let model = resolved
        .build_model(IED_NAME)
        .expect("build the demo model");
    seed_leaf(&model, MAG_F, MAG_SEED);
    seed_leaf(&model, ANG_F, ANG_SEED);
    Arc::new(model)
}

/// Stores a float into the leaf a reference names, resolving through the model
/// rather than the server so the read path under test is not also the path that
/// set the value.
fn seed_leaf(model: &IedModel, reference: &str, value: f32) {
    let mut object_ref =
        ObjectRef::parse_iec(reference).unwrap_or_else(|e| panic!("parse {reference}: {e}"));
    object_ref.fc = Some(FC::Mx);
    match model.node_by_object_ref(&object_ref) {
        Some(NodeRef::Da(da)) => da.store(MmsValue::Float32(value)),
        other => panic!("{reference} must resolve to a data attribute, got {other:?}"),
    }
}

fn build_server() -> IedServer {
    IedServer::builder()
        .model(load_demo_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig::default())
        .build()
        .expect("build the server")
}

async fn connect(handle: &ServerHandle) -> IedConnection {
    let mms = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    let conn = IedConnection::with_mms_client(mms);
    conn.connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect to the server");
    conn
}

/// Reads one reference under MX with a timeout, so a hung server fails the test
/// instead of blocking it.
async fn read_mx(conn: &IedConnection, reference: &str) -> Result<MmsValue, ClientError> {
    tokio::time::timeout(Duration::from_secs(5), conn.read_object(reference, FC::Mx))
        .await
        .unwrap_or_else(|_| panic!("Read({reference}) timed out"))
}

fn expect_read(value: Result<MmsValue, ClientError>, reference: &str) -> MmsValue {
    value.unwrap_or_else(|e| panic!("Read({reference}) failed: {e}"))
}

/// Unwraps a structure, naming the reference in the panic so a shape change is
/// attributable.
fn fields(value: &MmsValue, reference: &str) -> Vec<MmsValue> {
    match value {
        MmsValue::Structure(items) => items.clone(),
        other => panic!("Read({reference}) must answer a structure, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_descends_sub_data_objects_to_a_leaf_and_every_level_agrees() {
    let server = build_server();
    let handle = server.start().await.expect("start the server");
    let conn = connect(&handle).await;

    // The leaf four names below the data object: WYE, phase CMV, Vector,
    // AnalogValue, float.
    let mag_f = expect_read(read_mx(&conn, MAG_F).await, MAG_F);
    let mag_value = match mag_f {
        MmsValue::Float32(v) => v,
        other => panic!("Read({MAG_F}) must answer a float32, got {other:?}"),
    };
    assert_eq!(mag_value, MAG_SEED, "the leaf must carry the seeded value");
    let ang_f = expect_read(read_mx(&conn, ANG_F).await, ANG_F);
    let ang_value = match ang_f {
        MmsValue::Float32(v) => v,
        other => panic!("Read({ANG_F}) must answer a float32, got {other:?}"),
    };
    assert_eq!(ang_value, ANG_SEED, "the leaf must carry the seeded value");

    // The mid-path levels: the constructed attribute, one phase, and the whole
    // data object. Each must contain the leaf the level below reported.
    let c_val = expect_read(read_mx(&conn, C_VAL).await, C_VAL);
    assert_eq!(
        fields(&c_val, C_VAL),
        vec![
            MmsValue::Structure(vec![MmsValue::Float32(mag_value)]),
            MmsValue::Structure(vec![MmsValue::Float32(ang_value)]),
        ],
        "cVal must hold mag and ang in declaration order"
    );

    let phs_a = expect_read(read_mx(&conn, PHS_A).await, PHS_A);
    let phs_a_fields = fields(&phs_a, PHS_A);
    assert_eq!(
        phs_a_fields.len(),
        3,
        "a CMV under MX holds cVal, q and t, got {phs_a_fields:?}"
    );
    assert_eq!(
        phs_a_fields[0], c_val,
        "the first member of phsA must be the cVal the direct read returned"
    );

    let phv = expect_read(read_mx(&conn, PHV).await, PHV);
    let phv_fields = fields(&phv, PHV);
    assert_eq!(
        phv_fields.len(),
        3,
        "the WYE declares phsA, phsB and phsC, got {phv_fields:?}"
    );
    assert_eq!(
        phv_fields[0], phs_a,
        "the first phase of PhV must be the phsA the sub-object read returned"
    );

    // A name that does not exist under a sub-data-object stays a failure, so the
    // descent does not turn an unknown reference into a partial answer.
    let missing = "DemoIEDLD0/MMXU1.PhV.phsA.nosuchda";
    let err = read_mx(&conn, missing).await.expect_err("must not resolve");
    assert!(
        format!("{err}").contains("object-non-existent")
            || format!("{err:?}").contains("ObjectNonExistent"),
        "an unknown name under a sub-data-object must answer object-non-existent, got {err:?}"
    );

    conn.disconnect().await.ok();
    handle.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_variable_access_attributes_reports_the_same_sub_data_object_path() {
    let server = build_server();
    let handle = server.start().await.expect("start the server");
    let conn = connect(&handle).await;

    // Browsing must reach the same nodes a Read resolves, otherwise a
    // model-driven client builds a tree it cannot read.
    let leaf = conn
        .get_variable_specification(MAG_F, FC::Mx)
        .await
        .unwrap_or_else(|e| panic!("GetVariableAccessAttributes({MAG_F}) failed: {e}"));
    assert!(
        matches!(leaf, TypeSpecification::FloatingPoint { .. }),
        "the leaf f must be reported as a float, got {leaf:?}"
    );

    let phase = conn
        .get_variable_specification(PHS_A, FC::Mx)
        .await
        .unwrap_or_else(|e| panic!("GetVariableAccessAttributes({PHS_A}) failed: {e}"));
    match phase {
        TypeSpecification::Structure { components } => {
            let names: Vec<&str> = components.iter().map(|c| c.name.as_str()).collect();
            assert_eq!(
                names,
                vec!["cVal", "q", "t"],
                "a CMV under MX reports cVal, q and t"
            );
        }
        other => panic!("phsA must be reported as a structure, got {other:?}"),
    }

    conn.disconnect().await.ok();
    handle.stop().await;
}

// ── Write across a sub-data-object ───────────────────────────────────────────

/// The reference of the settable leaf below a phase sub-data-object, in the
/// model `build_setpoint_model` returns.
const SET_MAG: &str = "IED1LD0/GGIO1.PhSet.phsA.setMag";

/// A model whose settable attribute sits below a sub-data-object, which is the
/// shape a WYE of setpoints takes. `demo.cid` nests nothing writable, so the
/// write path needs a model of its own.
fn build_setpoint_model() -> Arc<IedModel> {
    let phs_a = DataObject {
        name: "phsA".into(),
        array_count: None,
        children: vec![DoChild::Da(DataAttribute::new(
            "setMag",
            FC::Sp,
            DataAttributeType::Float32,
            TrgOps::default(),
            MmsValue::Float32(0.0),
        ))],
    };
    let ggio = LogicalNode {
        prefix: String::new(),
        class: "GGIO".into(),
        inst: "1".into(),
        dos: vec![DataObject {
            name: "PhSet".into(),
            array_count: None,
            children: vec![DoChild::SubDo(phs_a)],
        }],
        datasets: vec![],
        rcbs: vec![],
        gocbs: vec![],
        svcbs: vec![],
        lcbs: vec![],
        sgcb: None,
    };
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(LogicalNodeBuilder::lln0().build().expect("build LLN0"))
        .add_ln(ggio)
        .build()
        .expect("build the logical device");
    Arc::new(
        IedModelBuilder::new("IED1")
            .add_ld(ld)
            .expect("add the logical device")
            .build()
            .expect("build the setpoint model"),
    )
}

/// A Write reaches an attribute below a sub-data-object and the value comes
/// back through a Read, so the two paths agree on where the attribute is.
///
/// The default write access policy admits SP, so no policy override is needed;
/// that is what makes this the constraint to test on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_descends_sub_data_objects_and_reads_back() {
    let server = IedServer::builder()
        .model(build_setpoint_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig::default())
        .build()
        .expect("build the server");
    let handle = server.start().await.expect("start the server");
    let conn = connect(&handle).await;

    // The leaf starts at its model default, so a successful read-back of the
    // written value cannot be a coincidence.
    let before = tokio::time::timeout(Duration::from_secs(5), conn.read_object(SET_MAG, FC::Sp))
        .await
        .expect("the initial Read timed out")
        .expect("the initial Read failed");
    assert_eq!(before, MmsValue::Float32(0.0));

    tokio::time::timeout(
        Duration::from_secs(5),
        conn.write_object(SET_MAG, FC::Sp, MmsValue::Float32(48.75)),
    )
    .await
    .expect("the Write timed out")
    .expect("the Write failed");

    let after = tokio::time::timeout(Duration::from_secs(5), conn.read_object(SET_MAG, FC::Sp))
        .await
        .expect("the read-back timed out")
        .expect("the read-back failed");
    assert_eq!(
        after,
        MmsValue::Float32(48.75),
        "the value written across the sub-data-object must be the value read back"
    );

    // A path that stops on the sub-data-object names no attribute to write, and
    // an unknown name below it does not resolve. Both must stay failures, so
    // the descent does not turn a bad reference into a silent partial write.
    let on_the_sdo = tokio::time::timeout(
        Duration::from_secs(5),
        conn.write_object("IED1LD0/GGIO1.PhSet.phsA", FC::Sp, MmsValue::Float32(1.0)),
    )
    .await
    .expect("the sub-data-object Write timed out");
    assert!(
        on_the_sdo.is_err(),
        "writing the sub-data-object itself must fail, got {on_the_sdo:?}"
    );

    let unknown = tokio::time::timeout(
        Duration::from_secs(5),
        conn.write_object(
            "IED1LD0/GGIO1.PhSet.phsA.nosuchda",
            FC::Sp,
            MmsValue::Float32(1.0),
        ),
    )
    .await
    .expect("the unknown-name Write timed out");
    assert!(
        unknown.is_err(),
        "writing an unknown name below a sub-data-object must fail, got {unknown:?}"
    );

    // The refused writes must not have disturbed the attribute.
    let still = tokio::time::timeout(Duration::from_secs(5), conn.read_object(SET_MAG, FC::Sp))
        .await
        .expect("the final Read timed out")
        .expect("the final Read failed");
    assert_eq!(still, MmsValue::Float32(48.75));

    conn.disconnect().await.ok();
    handle.stop().await;
}
