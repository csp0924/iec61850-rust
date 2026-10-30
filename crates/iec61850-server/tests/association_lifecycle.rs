//! Integration tests for association setup and teardown over a real socket.
//!
//! The cases are: an AARQ whose user information is not an Initiate-RequestPDU,
//! which must be refused without running the PDU it carries; and a connection
//! that ends on a transport error, whose URCB reservation and setting group
//! edit session must be released at once.
//!
//! Every test binds 127.0.0.1:0 so concurrent tests cannot collide on a port.

use bytes::BytesMut;
use iec61850_mms::iso::acse::encode_aarq;
use iec61850_mms::iso::cotp::{CotpConnection, CotpOptions};
use iec61850_mms::iso::presentation::{
    encode_connect as pres_encode_connect, PresentationConnectionParameters,
};
use iec61850_mms::iso::session::{
    encode_connect as sess_encode_connect, IsoParameters, IsoSession,
};
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_mms::mms::pdu::write::{encode_confirmed_write_request, WriteRequest};
use iec61850_mms::mms::MmsData;
use iec61850_mms::AarqAddressing;
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObjectBuilder, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, SettingGroupControlBlock, TrgOps, FC,
};
use iec61850_server::control::{
    ControlModel, ControlObject, ControlObjectConfig, ControlObjectEntry, ControlState, SboClass,
};
use iec61850_server::reporting::rcb::Rcb;
use iec61850_server::reporting::{Dataset, ReportControl};
use iec61850_server::{IedServer, IedServerConfig, WriteAccessPolicies};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::TcpStream;

/// A model whose `TESTLD0/LLN0$DC$NamPlt$vendor` is writable, with the handle
/// to its value. LLN0 also carries an SGCB of three groups whose edit session
/// has no reservation timeout.
fn model_with_writable_vendor() -> (Arc<IedModel>, Arc<RwLock<MmsValue>>) {
    let vendor = DataAttribute::new(
        "vendor",
        FC::Dc,
        DataAttributeType::VisibleString(255),
        TrgOps::NONE,
        MmsValue::VisibleString("initial".into()),
    );
    let handle = vendor.value.clone();
    let nam_plt = DataObjectBuilder::scalar("NamPlt")
        .add_da_node(vendor)
        .build()
        .unwrap();
    let lln0 = LogicalNodeBuilder::lln0()
        .add_do(nam_plt)
        .set_sgcb(SettingGroupControlBlock {
            num_of_sg: 3,
            act_sg: 1,
            has_resv_tms: false,
            default_resv_tms_s: 60,
        })
        .build()
        .unwrap();
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .build()
        .unwrap();
    let model = IedModelBuilder::new("TEST")
        .add_ld(ld)
        .unwrap()
        .build()
        .unwrap();
    (Arc::new(model), handle)
}

fn build_server(model: Arc<IedModel>, cfg: IedServerConfig) -> IedServer {
    let mut policies = WriteAccessPolicies::default();
    policies.set(FC::Dc, true);
    policies.set(FC::Sp, true);
    IedServer::builder()
        .model(model)
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig {
            write_access_policies: policies,
            ..cfg
        })
        .build()
        .expect("build server")
}

/// Session CN carrying a Presentation CP and an ACSE AARQ whose user
/// information is `mms_pdu`.
fn connect_request(mms_pdu: &[u8]) -> BytesMut {
    let mut aarq = BytesMut::new();
    encode_aarq(mms_pdu, None, 3, &AarqAddressing::default(), &mut aarq);
    let mut cp = BytesMut::new();
    pres_encode_connect(&PresentationConnectionParameters::default(), &aarq, &mut cp);
    let mut cn = BytesMut::new();
    sess_encode_connect(&IsoParameters::default(), &IsoSession::new(), &cp, &mut cn)
        .expect("the CN fits");
    cn
}

/// Reads until the server closes the socket, failing if that takes over 2 s.
async fn expect_closed(cotp: &mut CotpConnection<TcpStream>) {
    let closed = tokio::time::timeout(Duration::from_secs(2), async {
        while cotp.recv_data().await.is_ok() {}
    })
    .await;
    assert!(
        closed.is_ok(),
        "the server did not close the socket within 2s"
    );
}

/// An AARQ carrying a confirmed Write instead of an Initiate-RequestPDU is
/// refused and the socket closed, and the Write never reaches the model. An
/// association that negotiates first can write the same attribute.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_in_place_of_initiate_is_not_executed() {
    let (model, vendor) = model_with_writable_vendor();
    let server = build_server(model, IedServerConfig::default());
    let handle = server.start().await.expect("start");

    let mut write = BytesMut::new();
    encode_confirmed_write_request(
        1,
        &WriteRequest::single_domain(
            "TESTLD0",
            "LLN0$DC$NamPlt$vendor",
            MmsData::VisibleString("injected".into()),
        ),
        &mut write,
    );
    let stream = TcpStream::connect(handle.bound_addr).await.unwrap();
    let mut cotp = CotpConnection::connect(stream, CotpOptions::default())
        .await
        .expect("COTP handshake");
    cotp.send_data(&connect_request(&write)).await.unwrap();
    expect_closed(&mut cotp).await;
    assert_eq!(
        *vendor.read().unwrap(),
        MmsValue::VisibleString("initial".into()),
        "a request carried in the AARQ must not run"
    );

    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(2_000)
        .request_timeout_ms(2_000)
        .build();
    client
        .connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    client
        .write(
            "TESTLD0",
            "LLN0$DC$NamPlt$vendor",
            MmsData::VisibleString("written".into()),
        )
        .await
        .expect("a negotiated association writes");
    assert_eq!(
        *vendor.read().unwrap(),
        MmsValue::VisibleString("written".into())
    );
    let _ = client.disconnect().await;
    handle.stop().await;
}

const URCB_PATH: &str = "TESTLD0/LLN0$RP$urcb01";

fn urcb_reserved(server: &IedServer) -> bool {
    let engine = server.reporting_engine();
    let engine = engine.lock().unwrap();
    let rc = engine.get_rcb(URCB_PATH).expect("the URCB is registered");
    let rc = rc.lock().unwrap();
    let reserved = rc.state.lock().unwrap().resv;
    reserved
}

fn edit_sg(server: &IedServer) -> u8 {
    server
        .setting_groups()
        .lookup("TESTLD0")
        .expect("the SGCB is projected from the model")
        .snapshot()
        .edit_sg
}

async fn connect(port: u16) -> iec61850_mms::MmsClient {
    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(2_000)
        .request_timeout_ms(2_000)
        .build();
    client.connect("127.0.0.1", port).await.expect("connect");
    client
}

/// A connection that ends on a transport error, here the peer closing its
/// socket without a Conclude, releases its URCB reservation, its setting group
/// edit session and its control select as the connection task ends, so another
/// association can take all three.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transport_error_releases_association_state() {
    let (model, _vendor) = model_with_writable_vendor();
    let server = build_server(model, IedServerConfig::default());
    server
        .register_urcb(
            ReportControl::new(URCB_PATH, Rcb::new("urcb01", "LLN0$ds1")),
            Dataset::new("LLN0$ds1"),
        )
        .expect("register the URCB");
    let pos = ControlObject::new(ControlObjectConfig {
        name: "Pos".into(),
        ln_name: "LLN0".into(),
        domain: "TESTLD0".into(),
        ctl_model: ControlModel::SboNormal,
        sbo_timeout_ms: 600_000,
        sbo_class: SboClass::OperateOnce,
    });
    server
        .control_objects()
        .register(ControlObjectEntry::new(pos.clone()));
    let handle = server.start().await.expect("start");
    let port = handle.bound_addr.port();

    let mut first = connect(port).await;
    first
        .write("TESTLD0", "LLN0$RP$urcb01$Resv", MmsData::Boolean(true))
        .await
        .expect("reserve the URCB");
    first
        .read("TESTLD0", "LLN0$CO$Pos$SBO")
        .await
        .expect("select the control object");
    first
        .write("TESTLD0", "LLN0$SP$SGCB$EditSG", MmsData::Unsigned(2))
        .await
        .expect("open the edit session");
    assert!(urcb_reserved(&server));
    assert_eq!(edit_sg(&server), 2);
    assert_eq!(pos.state(), ControlState::Ready);
    drop(first);

    let released = tokio::time::timeout(Duration::from_secs(3), async {
        while urcb_reserved(&server)
            || edit_sg(&server) != 0
            || pos.state() != ControlState::Unselected
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        released.is_ok(),
        "the reservation, the edit session and the select must be released, resv={} edit_sg={} pos={:?}",
        urcb_reserved(&server),
        edit_sg(&server),
        pos.state()
    );

    let mut second = connect(port).await;
    second
        .write("TESTLD0", "LLN0$RP$urcb01$Resv", MmsData::Boolean(true))
        .await
        .expect("a second association reserves the URCB");
    second
        .write("TESTLD0", "LLN0$SP$SGCB$EditSG", MmsData::Unsigned(3))
        .await
        .expect("a second association opens the edit session");
    second
        .read("TESTLD0", "LLN0$CO$Pos$SBO")
        .await
        .expect("a second association selects the control object");
    assert_eq!(pos.state(), ControlState::Ready);
    let _ = second.disconnect().await;
    handle.stop().await;
}
