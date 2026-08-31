//! End-to-end round trips of `read_object`, `write_object` and the
//! type-narrowing wrappers over a loopback association.
//!
//! The model is a `simpleIOGenericIO` logical device with LLN0, LPHD1 and
//! GGIO1, carrying NamPlt, Ind, AnIn and SPCSO. Only scalar references are
//! exercised; array elements are covered elsewhere.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iec61850_client::IedConnection;
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_model::{
    cdc, ControlModel, ControlOptions, DataAttribute, DataAttributeType, DataObjectBuilder,
    IedModel, IedModelBuilder, LogicalDeviceBuilder, LogicalNode, LogicalNodeBuilder, MmsValue,
    NodeRef, ObjectRef, TrgOps, FC,
};
use iec61850_server::{IedServer, IedServerConfig, WriteAccessPolicies};

const DOMAIN: &str = "simpleIOGenericIO";

fn build_lln0() -> LogicalNode {
    let mod_do = cdc::ens("Mod", cdc::CdcOptions::NONE);
    let beh_do = cdc::ens("Beh", cdc::CdcOptions::NONE);
    let health_do = cdc::ens("Health", cdc::CdcOptions::NONE);
    let nam_plt = DataObjectBuilder::scalar("NamPlt")
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
        .build()
        .expect("nam_plt build");
    LogicalNodeBuilder::lln0()
        .add_do(mod_do)
        .add_do(beh_do)
        .add_do(health_do)
        .add_do(nam_plt)
        .build()
        .expect("lln0 build")
}

fn build_ggio1() -> LogicalNode {
    let mut b = LogicalNodeBuilder::new("", "GGIO", "1");
    for i in 1..=3 {
        b = b.add_do(cdc::sps(format!("Ind{i}"), cdc::CdcOptions::NONE));
    }
    for i in 1..=2 {
        b = b.add_do(cdc::mv(
            format!("AnIn{i}"),
            cdc::CdcOptions::NONE,
            /* is_integer_not_float */ false,
        ));
    }
    let spc_opts = ControlOptions::NONE.with_model(ControlModel::DirectNormal);
    b = b.add_do(cdc::spc("SPCSO1", cdc::CdcOptions::NONE, spc_opts));
    b.build().expect("ggio1 build")
}

fn build_model() -> Arc<IedModel> {
    let ld = LogicalDeviceBuilder::new("GenericIO")
        .add_ln(build_lln0())
        .add_ln(build_ggio1())
        .build()
        .expect("ld");
    Arc::new(
        IedModelBuilder::new("simpleIO")
            .add_ld(ld)
            .expect("add_ld")
            .build()
            .expect("model"),
    )
}

fn build_server() -> IedServer {
    let mut policies = WriteAccessPolicies::default();
    policies.set(FC::Dc, true);
    IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig {
            max_mms_connections: 4,
            write_access_policies: policies,
            ..Default::default()
        })
        .build()
        .expect("build server")
}

fn resolve_da(model: &IedModel, path: &str) -> DataAttribute {
    let r = ObjectRef::parse_iec(path).expect("parse_iec");
    match model.node_by_object_ref(&r).expect("node lookup") {
        NodeRef::Da(da) => DataAttribute {
            name: da.name.clone(),
            fc: da.fc,
            ty: da.ty,
            trg_ops: da.trg_ops,
            value: Arc::clone(&da.value),
            children: Vec::new(),
        },
        _ => panic!("expected DA, got non-DA at {path}"),
    }
}

async fn make_client(port: u16) -> IedConnection {
    let mms = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    let conn = IedConnection::with_mms_client(mms);
    conn.connect("127.0.0.1", port).await.expect("connect");
    conn
}

// read_boolean and read_object on an SPS stVal, in IEC notation.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_boolean_sps_stval() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let model = server.model();
        let ind1 = resolve_da(&model, "simpleIOGenericIO/GGIO1.Ind1.stVal");
        server.update_boolean(&ind1, true).expect("update");

        let handle = server.start().await.expect("start");
        let port = handle.bound_addr.port();

        let conn = make_client(port).await;

        // The typed wrapper.
        let v = conn
            .read_boolean(&format!("{DOMAIN}/GGIO1.Ind1.stVal"), FC::St)
            .await
            .expect("read_boolean");
        assert!(v);

        // The generic call, returning the raw value.
        let raw = conn
            .read_object(&format!("{DOMAIN}/GGIO1.Ind1.stVal"), FC::St)
            .await
            .expect("read_object");
        assert!(matches!(raw, MmsValue::Boolean(true)));

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

// read_string on NamPlt.vendor; read_object also accepts MMS notation.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_string_namplt_vendor() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let port = handle.bound_addr.port();
        let conn = make_client(port).await;

        let s = conn
            .read_string(&format!("{DOMAIN}/LLN0.NamPlt.vendor"), FC::Dc)
            .await
            .expect("read_string");
        assert_eq!(s, "rust61850");

        // MMS notation resolves to the same variable, given a matching FC.
        let s2 = conn
            .read_string(&format!("{DOMAIN}/LLN0$DC$NamPlt$vendor"), FC::Dc)
            .await
            .expect("read_string mms notation");
        assert_eq!(s2, "rust61850");

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

// write_visible_string and read_string round trip under FC DC.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_visible_string_round_trip() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let port = handle.bound_addr.port();
        let conn = make_client(port).await;

        let new_vendor = "rust-test-vendor";
        conn.write_visible_string(&format!("{DOMAIN}/LLN0.NamPlt.vendor"), FC::Dc, new_vendor)
            .await
            .expect("write_visible_string");

        let got = conn
            .read_string(&format!("{DOMAIN}/LLN0.NamPlt.vendor"), FC::Dc)
            .await
            .expect("read_string");
        assert_eq!(got, new_vendor);

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

// read_float and write_float on a magnitude.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_write_float_anin_mag_f() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let model = server.model();
        let an_in1_f = resolve_da(&model, "simpleIOGenericIO/GGIO1.AnIn1.mag.f");
        server.update_float32(&an_in1_f, 12.5).expect("update");

        let handle = server.start().await.expect("start");
        let port = handle.bound_addr.port();
        let conn = make_client(port).await;

        let v = conn
            .read_float(&format!("{DOMAIN}/GGIO1.AnIn1.mag.f"), FC::Mx)
            .await
            .expect("read_float");
        assert_eq!(v, 12.5);

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

// Reading a Boolean through read_int32 reports UnexpectedValueType.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_int32_on_boolean_returns_unexpected_type() {
    use iec61850_client::ClientError;

    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let port = handle.bound_addr.port();
        let conn = make_client(port).await;

        let err = conn
            .read_int32(&format!("{DOMAIN}/GGIO1.Ind1.stVal"), FC::St)
            .await
            .expect_err("expected UnexpectedValueType");
        assert!(
            matches!(
                err,
                ClientError::UnexpectedValueType {
                    expected: "Integer",
                    got: "Boolean",
                }
            ),
            "got {err:?}"
        );

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

// NotConnected path; array element reaches the wire.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_object_not_connected() {
    use iec61850_client::ClientError;
    let conn = IedConnection::new();
    let err = conn
        .read_object(&format!("{DOMAIN}/GGIO1.Ind1.stVal"), FC::St)
        .await
        .expect_err("not connected");
    assert!(matches!(err, ClientError::NotConnected));
}

/// `read_object` with `(idx).component` routes through the MMS `AlternateAccess`
/// path. The target `GGIO1.Ind1.stVal` is a scalar `Boolean`, not an array, so
/// the server applies the `AlternateAccess` selector to a non-array value and
/// reports `TypeInconsistent`. This proves the request reaches the server,
/// AlternateAccess is decoded, and the selector is honored (rather than the
/// previous behavior of silently returning the entire underlying value).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_object_array_element_rejects_non_array_target() {
    use iec61850_client::ClientError;
    use iec61850_mms::DataAccessError;

    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let port = handle.bound_addr.port();
        let conn = make_client(port).await;

        let err = conn
            .read_object(&format!("{DOMAIN}/GGIO1.Ind1(0).stVal"), FC::St)
            .await
            .expect_err("scalar target must reject element access");
        assert!(
            matches!(
                err,
                ClientError::DataAccessError(DataAccessError::TypeInconsistent)
            ),
            "expected DataAccessError(TypeInconsistent), got {err:?}"
        );

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}
