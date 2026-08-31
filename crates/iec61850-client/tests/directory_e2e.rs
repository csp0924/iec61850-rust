//! End-to-end tests of the directory services over a loopback association.
//!
//! The model is the `simpleIOGenericIO` logical device used by the object IO
//! tests: LLN0 with NamPlt, Beh, Health and Mod, and GGIO1 with Ind, AnIn and
//! SPCSO.
//!
//! Scope and limits:
//!
//! - `get_server_directory(false)` reports the single logical device.
//! - `get_logical_device_directory` reports `LLN0` and `GGIO1`, which the
//!   server exposes as top-level named variables whose names carry no `$`.
//! - The calls that read the flattened `<LN>$<FC>$<DO>$<DA>` variable names
//!   (`get_logical_node_directory` for data objects, `get_logical_node_variables`,
//!   and the `get_data_directory` family) return empty lists here, because the
//!   server lists only the logical node names. Their filtering logic is covered
//!   by the unit tests of `directory.rs`.
//! - Edge cases: `get_server_directory(true)`, an unknown logical device, a
//!   malformed reference and an unusable functional constraint all report
//!   `InvalidArgument`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iec61850_client::{AcsiClass, ClientError, IedConnection, TypeSpecification};
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_model::{
    cdc, ControlModel, ControlOptions, DataAttributeType, DataObjectBuilder, IedModel,
    IedModelBuilder, LogicalDevice, LogicalDeviceBuilder, LogicalNode, LogicalNodeBuilder,
    MmsValue, TrgOps, FC,
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

fn build_ld() -> LogicalDevice {
    LogicalDeviceBuilder::new("GenericIO")
        .add_ln(build_lln0())
        .add_ln(build_ggio1())
        .build()
        .expect("ld")
}

fn build_model() -> Arc<IedModel> {
    Arc::new(
        IedModelBuilder::new("simpleIO")
            .add_ld(build_ld())
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

async fn make_client(port: u16) -> IedConnection {
    let mms = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    let conn = IedConnection::with_mms_client(mms);
    conn.connect("127.0.0.1", port).await.expect("connect");
    conn
}

// (1) get_server_directory: the logical device list.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_directory_lists_lds() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let port = handle.bound_addr.port();
        let conn = make_client(port).await;

        let lds = conn
            .get_server_directory(false)
            .await
            .expect("get_server_directory");
        assert_eq!(lds, vec![DOMAIN.to_string()]);

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_directory_file_names_rejected() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let port = handle.bound_addr.port();
        let conn = make_client(port).await;

        let err = conn
            .get_server_directory(true)
            .await
            .expect_err("get_file_names=true should be refused");
        assert!(matches!(err, ClientError::InvalidArgument(_)));

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

// (2) get_logical_device_directory: the logical node list. The server exposes a
// logical node as a top-level named variable, whose name carries no `$`.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn logical_device_directory_lists_lns() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let port = handle.bound_addr.port();
        let conn = make_client(port).await;

        let mut lns = conn
            .get_logical_device_directory(DOMAIN)
            .await
            .expect("ld dir");
        lns.sort_unstable();
        assert_eq!(lns, vec!["GGIO1".to_string(), "LLN0".to_string()]);

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn logical_device_directory_unknown_ld_rejected() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let port = handle.bound_addr.port();
        let conn = make_client(port).await;

        let err = conn
            .get_logical_device_directory("nonExistent")
            .await
            .expect_err("an unknown logical device should be refused");
        assert!(matches!(err, ClientError::InvalidArgument(_)));

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

// (3) The device model cache is reused, and cleared on disconnect.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn device_model_cache_repopulates_after_disconnect() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let port = handle.bound_addr.port();

        let conn = make_client(port).await;
        let _ = conn
            .get_server_directory(false)
            .await
            .expect("get_server_directory");
        assert!(conn.cached_device_model().await.is_some());

        let _ = conn.disconnect().await;
        // Disconnecting clears the cache.
        assert!(conn.cached_device_model().await.is_none());

        // Reconnecting rebuilds it.
        conn.connect("127.0.0.1", port).await.expect("reconnect");
        let _ = conn
            .get_server_directory(false)
            .await
            .expect("get_server_directory after reconnect");
        assert!(conn.cached_device_model().await.is_some());

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

// (4) get_logical_node_directory for data sets and logs goes to the server.
// This model defines neither, so both return an empty list rather than an error.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ln_directory_dataset_empty_against_no_ds_server() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let port = handle.bound_addr.port();
        let conn = make_client(port).await;

        let ds = conn
            .get_logical_node_directory(&format!("{DOMAIN}/LLN0"), AcsiClass::DataSet)
            .await
            .expect("dataset list");
        assert!(ds.is_empty(), "this model defines no data set");

        let logs = conn
            .get_logical_node_directory(&format!("{DOMAIN}/LLN0"), AcsiClass::Log)
            .await
            .expect("log list");
        assert!(logs.is_empty(), "this model defines no log");

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

// (5) get_logical_node_directory refuses an unsupported ACSI class.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ln_directory_unsupported_class_rejected() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let port = handle.bound_addr.port();
        let conn = make_client(port).await;

        for class in [AcsiClass::GsCb, AcsiClass::Msvcb, AcsiClass::Usvcb] {
            let err = conn
                .get_logical_node_directory(&format!("{DOMAIN}/LLN0"), class)
                .await
                .expect_err("an unsupported class should be refused");
            assert!(matches!(err, ClientError::InvalidArgument(_)), "{class:?}");
        }

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

// (6) get_data_directory_by_fc refuses FC::None and FC::All.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn data_directory_by_fc_rejects_none_and_all() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let port = handle.bound_addr.port();
        let conn = make_client(port).await;

        for fc in [FC::None, FC::All] {
            let err = conn
                .get_data_directory_by_fc(&format!("{DOMAIN}/GGIO1.AnIn1"), fc)
                .await
                .expect_err("FC::None and FC::All should be refused");
            assert!(matches!(err, ClientError::InvalidArgument(_)), "{fc}");
        }

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

// (7) A directory call without an association reports NotConnected.

#[tokio::test]
async fn directory_apis_require_connection() {
    let conn = IedConnection::new();
    assert!(matches!(
        conn.get_server_directory(false).await,
        Err(ClientError::NotConnected)
    ));
    assert!(matches!(
        conn.get_logical_device_directory("X").await,
        Err(ClientError::NotConnected)
    ));
    assert!(matches!(
        conn.get_logical_node_variables("X/Y").await,
        Err(ClientError::NotConnected)
    ));
    assert!(matches!(
        conn.get_data_directory("X/Y.Z").await,
        Err(ClientError::NotConnected)
    ));
    assert!(matches!(
        conn.get_data_directory_fc("X/Y.Z").await,
        Err(ClientError::NotConnected)
    ));
    assert!(matches!(
        conn.get_data_directory_by_fc("X/Y.Z", FC::St).await,
        Err(ClientError::NotConnected)
    ));
}

// (8) A malformed reference is rejected before anything reaches the server.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bad_references_rejected_locally() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let port = handle.bound_addr.port();
        let conn = make_client(port).await;

        // A logical node reference without `/`.
        let e1 = conn
            .get_logical_node_variables("noSlash")
            .await
            .expect_err("missing `/`");
        assert!(matches!(e1, ClientError::InvalidArgument(_)));

        // A data reference without `.`.
        let e2 = conn
            .get_data_directory("LD/LN")
            .await
            .expect_err("missing `.`");
        assert!(matches!(e2, ClientError::InvalidArgument(_)));

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

// (9) get_variable_specification

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn variable_spec_visible_string_for_namplt_vendor() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let port = handle.bound_addr.port();
        let conn = make_client(port).await;

        let ts = conn
            .get_variable_specification(&format!("{DOMAIN}/LLN0.NamPlt.vendor"), FC::Dc)
            .await
            .expect("get_variable_specification NamPlt.vendor");
        match ts {
            TypeSpecification::VisibleString { max_chars } => {
                assert!(
                    max_chars != 0,
                    "NamPlt.vendor must not be a zero-length string"
                );
            }
            other => panic!("expected VisibleString, got {other:?}"),
        }

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn variable_spec_float32_for_anin_mag_f() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let port = handle.bound_addr.port();
        let conn = make_client(port).await;

        let ts = conn
            .get_variable_specification(&format!("{DOMAIN}/GGIO1.AnIn1.mag.f"), FC::Mx)
            .await
            .expect("get_variable_specification AnIn1.mag.f");
        match ts {
            TypeSpecification::FloatingPoint {
                format_width,
                exponent_width,
            } => {
                assert_eq!(format_width, 32);
                assert_eq!(exponent_width, 8);
            }
            other => panic!("expected FloatingPoint{{32,8}}, got {other:?}"),
        }

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn variable_spec_boolean_for_ind_stval() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let port = handle.bound_addr.port();
        let conn = make_client(port).await;

        let ts = conn
            .get_variable_specification(&format!("{DOMAIN}/GGIO1.Ind1.stVal"), FC::St)
            .await
            .expect("get_variable_specification Ind1.stVal");
        assert!(
            matches!(ts, TypeSpecification::Boolean),
            "Ind1.stVal should be Boolean, got {ts:?}"
        );

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn variable_spec_structure_for_do_container() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let port = handle.bound_addr.port();
        let conn = make_client(port).await;

        // The type of a whole data object is a structure of its attributes.
        let ts = conn
            .get_variable_specification(&format!("{DOMAIN}/GGIO1.Ind1"), FC::St)
            .await
            .expect("get_variable_specification Ind1");
        match ts {
            TypeSpecification::Structure { components } => {
                assert!(
                    !components.is_empty(),
                    "a data object structure should have components"
                );
                let names: Vec<&str> = components.iter().map(|c| c.name.as_str()).collect();
                assert!(
                    names.contains(&"stVal"),
                    "Ind1 should contain stVal, got {names:?}"
                );
            }
            other => panic!("expected Structure, got {other:?}"),
        }

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn variable_spec_array_index_rejected() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let port = handle.bound_addr.port();
        let conn = make_client(port).await;

        let err = conn
            .get_variable_specification(&format!("{DOMAIN}/GGIO1.Ind1(0).stVal"), FC::St)
            .await
            .expect_err("an array index should be refused");
        assert!(matches!(err, ClientError::InvalidArgument(_)));

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

#[tokio::test]
async fn variable_spec_requires_connection() {
    let conn = IedConnection::new();
    let err = conn
        .get_variable_specification("LD/LN.DO.DA", FC::St)
        .await
        .expect_err("a call without an association should report NotConnected");
    assert!(matches!(err, ClientError::NotConnected));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn variable_spec_rejects_fc_none_and_all() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let port = handle.bound_addr.port();
        let conn = make_client(port).await;

        for fc in [FC::None, FC::All] {
            let err = conn
                .get_variable_specification(&format!("{DOMAIN}/GGIO1.Ind1.stVal"), fc)
                .await
                .expect_err("FC::None and FC::All should be refused");
            assert!(matches!(err, ClientError::InvalidArgument(_)), "{fc}");
        }

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

// (10) get_device_model_from_server forces a refresh.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_device_model_from_server_returns_lds() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let port = handle.bound_addr.port();
        let conn = make_client(port).await;

        let model = conn
            .get_device_model_from_server()
            .await
            .expect("get_device_model_from_server");
        assert_eq!(
            model.logical_devices.len(),
            1,
            "expected one logical device"
        );
        assert_eq!(model.logical_devices[0].name, DOMAIN);
        assert!(
            !model.logical_devices[0].variables.is_empty(),
            "the variable list of a logical device should not be empty"
        );

        // The cache is written at the same time.
        let cached = conn
            .cached_device_model()
            .await
            .expect("cache should exist");
        assert_eq!(cached.logical_devices[0].name, DOMAIN);

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_device_model_from_server_overrides_cache() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server = build_server();
        let handle = server.start().await.expect("start");
        let port = handle.bound_addr.port();
        let conn = make_client(port).await;

        // Populate the cache through the lazy path.
        let _ = conn.get_server_directory(false).await.expect("server dir");
        let before = conn.cached_device_model().await.expect("initial cache");
        assert_eq!(before.logical_devices.len(), 1);

        // A forced refresh reads from the server even though the cache is warm.
        let refreshed = conn
            .get_device_model_from_server()
            .await
            .expect("force refresh");
        assert_eq!(refreshed.logical_devices.len(), 1);
        assert_eq!(refreshed.logical_devices[0].name, DOMAIN);
        // Two reads of the same server yield the same tree.
        let cached_after = conn
            .cached_device_model()
            .await
            .expect("cache after refresh");
        assert_eq!(
            cached_after.logical_devices[0].variables,
            refreshed.logical_devices[0].variables
        );

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

#[tokio::test]
async fn get_device_model_from_server_requires_connection() {
    let conn = IedConnection::new();
    let err = conn
        .get_device_model_from_server()
        .await
        .expect_err("a call without an association should report NotConnected");
    assert!(matches!(err, ClientError::NotConnected));
}
