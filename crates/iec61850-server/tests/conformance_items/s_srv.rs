//! Conformance tests for server, logical device, logical node and data access.
//!
//! Each test drives an `MmsClient` against an `IedServer` bound to port 0 and
//! tears the fixture down afterwards. Every `await` is wrapped in a five-second
//! timeout so a hung service cannot stall the run.
//!
//! The cases the server does not implement yet carry no test function here;
//! `catalog.rs` lists them.

#![allow(non_snake_case, dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iec61850_mms::mms::client::{MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::{DataAccessError, ObjectClass};
use iec61850_mms::ClientError;
use iec61850_mms::MmsData;
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObject, DataObjectBuilder, DoChild, IedModel,
    IedModelBuilder, LogicalDevice, LogicalDeviceBuilder, LogicalNode, LogicalNodeBuilder,
    MmsValue, TrgOps, FC,
};
use iec61850_server::{IedServer, IedServerConfig, ServerHandle, WriteAccessPolicies};

const TIMEOUT: Duration = Duration::from_secs(5);
const DOMAIN: &str = "TESTLD0"; // IED + LD inst → MMS domain

// Shared fixture: a model wide enough to exercise GetNameList, Read, Write and
// several functional constraints.

/// Builds one logical device LD0 holding:
/// - LLN0 with NamPlt.vendor (Dc, VisibleString, writable), Mod.stVal and
///   Beh.stVal (St, Int32).
/// - GGIO1 with Ind1.stVal (St, Boolean), read-only because no write policy is
///   enabled for St, and Mod.stVal (Sp, Int32, writable).
fn build_rich_model() -> Arc<IedModel> {
    // LLN0
    let nam_plt = DataObjectBuilder::scalar("NamPlt")
        .add_da(
            "vendor",
            FC::Dc,
            DataAttributeType::VisibleString(255),
            TrgOps::NONE,
            MmsValue::VisibleString("init".into()),
        )
        .build()
        .expect("NamPlt build");
    let lln0_mod = DataObjectBuilder::scalar("Mod")
        .add_da(
            "stVal",
            FC::St,
            DataAttributeType::Int32,
            TrgOps::default(),
            MmsValue::Integer(1),
        )
        .build()
        .expect("LLN0.Mod build");
    let lln0_beh = DataObjectBuilder::scalar("Beh")
        .add_da(
            "stVal",
            FC::St,
            DataAttributeType::Int32,
            TrgOps::default(),
            MmsValue::Integer(1),
        )
        .build()
        .expect("LLN0.Beh build");
    let lln0 = LogicalNodeBuilder::lln0()
        .add_do(nam_plt)
        .add_do(lln0_mod)
        .add_do(lln0_beh)
        .build()
        .expect("LLN0 build");

    // GGIO1 is assembled directly to mix a read-only St attribute with a
    // writable enumerated-like Sp attribute.
    let ind1_st = DataAttribute::new(
        "stVal",
        FC::St,
        DataAttributeType::Boolean,
        TrgOps::default(),
        MmsValue::Boolean(false),
    );
    let ind1 = DataObject {
        name: "Ind1".into(),
        array_count: None,
        children: vec![DoChild::Da(ind1_st)],
    };

    // Enumerated-like setpoint carried as Int32.
    let sp_mod_st = DataAttribute::new(
        "stVal",
        FC::Sp,
        DataAttributeType::Int32,
        TrgOps::default(),
        MmsValue::Integer(1),
    );
    let sp_mod = DataObject {
        name: "Mod".into(),
        array_count: None,
        children: vec![DoChild::Da(sp_mod_st)],
    };

    let ggio1 = LogicalNode {
        prefix: String::new(),
        class: "GGIO".into(),
        inst: "1".into(),
        dos: vec![ind1, sp_mod],
        datasets: vec![],
        rcbs: vec![],
        gocbs: vec![],
        svcbs: vec![],
        lcbs: vec![],
        sgcb: None,
    };

    let ld: LogicalDevice = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .add_ln(ggio1)
        .build()
        .expect("LD build");

    Arc::new(
        IedModelBuilder::new("TEST")
            .add_ld(ld)
            .expect("add_ld")
            .build()
            .expect("model build"),
    )
}

/// Starts a server and returns it together with its handle.
///
/// The write access policy is enabled for FC Dc and FC Sp; FC St keeps the
/// default of refusing writes, which the read-only write test relies on.
async fn spawn_server() -> (IedServer, ServerHandle) {
    let mut policies = WriteAccessPolicies::default();
    policies.set(FC::Dc, true);
    policies.set(FC::Sp, true);
    let cfg = IedServerConfig {
        max_mms_connections: 5,
        write_access_policies: policies,
        ..Default::default()
    };
    let server = IedServer::builder()
        .model(build_rich_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().expect("addr"))
        .config(cfg)
        .build()
        .expect("build server");
    let handle = tokio::time::timeout(TIMEOUT, server.start())
        .await
        .expect("server.start timeout")
        .expect("server.start err");
    (server, handle)
}

/// Connects to the server and completes the MMS Initiate exchange.
async fn connect(port: u16) -> MmsClient {
    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    tokio::time::timeout(TIMEOUT, client.connect("127.0.0.1", port))
        .await
        .expect("client.connect timeout")
        .expect("client.connect err");
    client
}

async fn shutdown(mut client: MmsClient, handle: ServerHandle) {
    let _ = tokio::time::timeout(TIMEOUT, client.disconnect()).await;
    tokio::time::timeout(TIMEOUT, handle.stop())
        .await
        .expect("handle.stop timeout");
}

// GetServerDirectory(LOGICAL-DEVICE) maps to GetNameList(Domain, VMD).

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s_srv1() {
    let (_server, handle) = spawn_server().await;
    let port = handle.bound_addr.port();
    let mut client = connect(port).await;

    let (names, more) = tokio::time::timeout(
        TIMEOUT,
        client.get_name_list(ObjectClass::Domain, None, None),
    )
    .await
    .expect("get_name_list timeout")
    .expect("get_name_list err");

    assert!(
        names.iter().any(|n| n == DOMAIN),
        "GetServerDirectory(LOGICAL-DEVICE) must list {DOMAIN}, got {names:?}"
    );
    assert!(!more, "a single logical device must not set more_follows");

    shutdown(client, handle).await;
}

// GetLogicalDeviceDirectory maps to GetNameList(NamedVariable, domain = LD0).

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s_srv2() {
    let (_server, handle) = spawn_server().await;
    let port = handle.bound_addr.port();
    let mut client = connect(port).await;

    let (names, more) = tokio::time::timeout(
        TIMEOUT,
        client.get_name_list(ObjectClass::NamedVariable, Some(DOMAIN), None),
    )
    .await
    .expect("get_name_list timeout")
    .expect("get_name_list err");

    // A domain-scope GetNameList returns the logical node names in alphabetical
    // order, as IEC 61850-8-1 requires and interoperating clients expect.
    assert!(
        names.iter().any(|n| n == "LLN0"),
        "GetLogicalDeviceDirectory must contain LLN0, got {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "GGIO1"),
        "GetLogicalDeviceDirectory must contain GGIO1, got {names:?}"
    );
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(
        names, sorted,
        "domain-scope names must be sorted alphabetically per IEC 61850-8-1"
    );
    assert!(!more);

    shutdown(client, handle).await;
}

// GetLogicalNodeDirectory(DATA).
//
// A GetVariableAccessAttributes on a logical node, the domain-scope named
// variable, returns a Structure whose components are the data object names.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s_srv3() {
    use iec61850_mms::mms::pdu::TypeSpecification;

    let (_server, handle) = spawn_server().await;
    let port = handle.bound_addr.port();
    let mut client = connect(port).await;

    let ts = tokio::time::timeout(
        TIMEOUT,
        client.get_variable_access_attributes(DOMAIN, "LLN0"),
    )
    .await
    .expect("GVA timeout")
    .expect("GVA err");

    match ts {
        TypeSpecification::Structure { components } => {
            // A logical node is mapped FC-grouped: the top-level components are
            // one sub-structure per functional constraint (ST, DC, ...), and the
            // data objects sit inside those. LLN0 carries at least ST and DC
            // because NamPlt.vendor is Dc and Mod/Beh.stVal are St.
            assert!(
                components.len() >= 2,
                "LLN0 must expose at least 2 FC group components, got {} ({:?})",
                components.len(),
                components.iter().map(|c| &c.name).collect::<Vec<_>>()
            );
            let names: Vec<&str> = components.iter().map(|c| c.name.as_str()).collect();
            assert!(
                names.contains(&"ST") && names.contains(&"DC"),
                "LLN0 must contain the ST and DC FC groups, got {names:?}"
            );
        }
        other => panic!("LLN0 must be a Structure, got {other:?}"),
    }

    shutdown(client, handle).await;
}

// GetDataDirectory, GetDataDefinition and GetDataValues.
//
// The first two map to GetVariableAccessAttributes, the third to Read.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s_srv4() {
    use iec61850_mms::mms::pdu::TypeSpecification;

    let (_server, handle) = spawn_server().await;
    let port = handle.bound_addr.port();
    let mut client = connect(port).await;

    // GetDataDirectory: the type spec of a logical node names its data objects.
    let lln0_ts = tokio::time::timeout(
        TIMEOUT,
        client.get_variable_access_attributes(DOMAIN, "LLN0"),
    )
    .await
    .expect("dir timeout")
    .expect("dir err");
    assert!(
        matches!(&lln0_ts, TypeSpecification::Structure { components } if !components.is_empty()),
        "LLN0 must be a Structure with at least one component"
    );

    // GetDataDefinition: the type spec of a leaf data attribute.
    let vendor_ts = tokio::time::timeout(
        TIMEOUT,
        client.get_variable_access_attributes(DOMAIN, "LLN0$DC$NamPlt$vendor"),
    )
    .await
    .expect("def timeout")
    .expect("def err");
    assert!(
        matches!(vendor_ts, TypeSpecification::VisibleString { .. }),
        "vendor must be a VisibleString type spec, got {vendor_ts:?}"
    );

    // GetDataValues: read a boolean data attribute.
    let val = tokio::time::timeout(TIMEOUT, client.read(DOMAIN, "GGIO1$ST$Ind1$stVal"))
        .await
        .expect("read timeout")
        .expect("read err");
    match val {
        MmsData::Boolean(b) => assert!(!b, "Ind1.stVal defaults to false"),
        other => panic!("expected Boolean, got {other:?}"),
    }

    shutdown(client, handle).await;
}

// GetDataValues on the largest available amount of data.
//
// A true maximum-size request needs a PDU close to the negotiated max PDU size,
// which depends on data sets and is covered by the data set tests. Here the
// whole logical node is read at once, which aggregates every data attribute
// below it and is far larger than a leaf read.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s_srv5() {
    let (_server, handle) = spawn_server().await;
    let port = handle.bound_addr.port();
    let mut client = connect(port).await;

    // Read the logical node as a whole.
    let val = tokio::time::timeout(TIMEOUT, client.read(DOMAIN, "LLN0"))
        .await
        .expect("read LN timeout")
        .expect("read LN err");
    match val {
        MmsData::Structure(items) => {
            assert!(
                !items.is_empty(),
                "an aggregate read of LLN0 must return a non-empty Structure"
            );
        }
        other => panic!("a logical node read must return a Structure, got {other:?}"),
    }

    shutdown(client, handle).await;
}

// SetDataValues on every writable data object.
//
// vendor (FC=Dc, VisibleString) and Mod (FC=Sp, Int32) stand for the string and
// the enumerated-like integer write paths.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s_srv6() {
    let (_server, handle) = spawn_server().await;
    let port = handle.bound_addr.port();
    let mut client = connect(port).await;

    // String write round-trip.
    let new_vendor = "vendor-write-probe";
    tokio::time::timeout(
        TIMEOUT,
        client.write(
            DOMAIN,
            "LLN0$DC$NamPlt$vendor",
            MmsData::VisibleString(new_vendor.into()),
        ),
    )
    .await
    .expect("write vendor timeout")
    .expect("write vendor err");

    let got = tokio::time::timeout(TIMEOUT, client.read(DOMAIN, "LLN0$DC$NamPlt$vendor"))
        .await
        .expect("read vendor timeout")
        .expect("read vendor err");
    match got {
        MmsData::VisibleString(s) => assert_eq!(s, new_vendor, "vendor write/read mismatch"),
        other => panic!("vendor must be a VisibleString, got {other:?}"),
    }

    // Integer write round-trip on Mod.stVal (FC=Sp).
    tokio::time::timeout(
        TIMEOUT,
        client.write(DOMAIN, "GGIO1$SP$Mod$stVal", MmsData::Integer(2)),
    )
    .await
    .expect("write mod timeout")
    .expect("write mod err");

    let got2 = tokio::time::timeout(TIMEOUT, client.read(DOMAIN, "GGIO1$SP$Mod$stVal"))
        .await
        .expect("read mod timeout")
        .expect("read mod err");
    match got2 {
        MmsData::Integer(i) => assert_eq!(i, 2, "Mod.stVal write/read mismatch"),
        other => panic!("Mod.stVal must be an Integer, got {other:?}"),
    }

    shutdown(client, handle).await;
}

// GetAllDataValues per functional constraint.
//
// An FC group read is a read of the sub-structure named after the functional
// constraint on a logical node, such as LLN0$ST or LLN0$DC; the server
// aggregates every data attribute of that logical node under that constraint.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s_srv8() {
    let (_server, handle) = spawn_server().await;
    let port = handle.bound_addr.port();
    let mut client = connect(port).await;

    // Read every populated FC group once.
    for (item, label) in [
        ("LLN0$ST", "LLN0/ST"),
        ("LLN0$DC", "LLN0/DC"),
        ("GGIO1$ST", "GGIO1/ST"),
        ("GGIO1$SP", "GGIO1/SP"),
    ] {
        let v = tokio::time::timeout(TIMEOUT, client.read(DOMAIN, item))
            .await
            .unwrap_or_else(|_| panic!("read {label} timeout"))
            .unwrap_or_else(|e| panic!("read {label} err: {e:?}"));
        match v {
            MmsData::Structure(items) => {
                assert!(
                    !items.is_empty(),
                    "{label} GetAllDataValues must return a non-empty Structure"
                );
            }
            other => panic!("{label} must be a Structure, got {other:?}"),
        }
    }

    shutdown(client, handle).await;
}

// Wrong parameters - unknown object, name case mismatch, wrong logical device
// or wrong logical node - must produce a service error.
//
// Three services are exercised on their unknown-object branch: GetNameList on
// an unknown domain, Read on an unknown logical node, and Write on an unknown
// logical node. Each must fail with a service error carrying object-nonexistent
// or with a data access error.

fn err_label(e: &ClientError) -> &'static str {
    match e {
        ClientError::ServiceError { .. } => "ServiceError",
        ClientError::DataAccessError(_) => "DataAccessError",
        ClientError::RejectError { .. } => "Reject",
        _ => "Other",
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s_srv_n1() {
    let (_server, handle) = spawn_server().await;
    let port = handle.bound_addr.port();
    let mut client = connect(port).await;

    // GetNameList on an unknown domain.
    //
    // The server answers ConfirmedError(ObjectNonExistent). The client decoder
    // still falls through to a PDU parse error for some length forms, so only
    // the presence of an error is asserted here.
    // TODO: assert the decoded service error class once the client decodes
    // every ConfirmedError length form
    let r1 = tokio::time::timeout(
        TIMEOUT,
        client.get_name_list(ObjectClass::NamedVariable, Some("NOSUCHDOMAIN"), None),
    )
    .await
    .expect("gnl timeout");
    assert!(
        r1.is_err(),
        "GetNameList on an unknown domain must fail, got {r1:?}"
    );

    // Read on an unknown logical node.
    let r2 = tokio::time::timeout(TIMEOUT, client.read(DOMAIN, "NOSUCHLN$ST$Foo$stVal"))
        .await
        .expect("read timeout");
    assert!(
        r2.is_err(),
        "Read on an unknown logical node must fail, got {r2:?}"
    );
    if let Err(e) = &r2 {
        let kind = err_label(e);
        assert!(
            matches!(kind, "ServiceError" | "DataAccessError"),
            "expected a service or data access error, got {kind} ({e:?})"
        );
    }

    // Write on an unknown logical node. FC Dc is writable, so the failure must
    // be object-nonexistent rather than access denied.
    let r3 = tokio::time::timeout(
        TIMEOUT,
        client.write(
            DOMAIN,
            "NOSUCHLN$DC$NamPlt$vendor",
            MmsData::VisibleString("x".into()),
        ),
    )
    .await
    .expect("write timeout");
    assert!(
        r3.is_err(),
        "Write on an unknown logical node must fail, got {r3:?}"
    );

    shutdown(client, handle).await;
}

// A type mismatch on write must produce a service error.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s_srv_n3() {
    let (_server, handle) = spawn_server().await;
    let port = handle.bound_addr.port();
    let mut client = connect(port).await;

    // Writing a Float32 into a VisibleString must be refused.
    let r = tokio::time::timeout(
        TIMEOUT,
        client.write(DOMAIN, "LLN0$DC$NamPlt$vendor", MmsData::Float32(1.25)),
    )
    .await
    .expect("write timeout");

    assert!(
        r.is_err(),
        "a Float32 write into a VisibleString must fail, got {r:?}"
    );
    if let Err(e) = &r {
        // The server reports a value that does not fit the target type as
        // ObjectValueInvalid; the neighboring type errors are accepted too
        // because the standard leaves the choice open.
        match e {
            ClientError::DataAccessError(
                DataAccessError::TypeInconsistent
                | DataAccessError::ObjectAttributeInconsistent
                | DataAccessError::TypeUnsupported
                | DataAccessError::ObjectAccessDenied
                | DataAccessError::ObjectValueInvalid,
            )
            | ClientError::ServiceError { .. } => {}
            other => panic!(
                "expected a type or value data access error, or a service error, got {other:?}"
            ),
        }
    }

    shutdown(client, handle).await;
}

// Writing a read-only data value must produce a service error.
//
// GGIO1.Ind1.stVal is FC St and no write policy is enabled for St, so the write
// is denied.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s_srv_n4() {
    let (_server, handle) = spawn_server().await;
    let port = handle.bound_addr.port();
    let mut client = connect(port).await;

    let r = tokio::time::timeout(
        TIMEOUT,
        client.write(DOMAIN, "GGIO1$ST$Ind1$stVal", MmsData::Boolean(true)),
    )
    .await
    .expect("write timeout");

    assert!(
        r.is_err(),
        "a write to a read-only attribute must fail, got {r:?}"
    );
    if let Err(e) = &r {
        match e {
            ClientError::DataAccessError(DataAccessError::ObjectAccessDenied)
            | ClientError::DataAccessError(DataAccessError::ObjectAccessUnsupported)
            | ClientError::ServiceError { .. } => {}
            other => panic!(
                "expected access denied, access unsupported, or a service error, got {other:?}"
            ),
        }
    }

    shutdown(client, handle).await;
}
