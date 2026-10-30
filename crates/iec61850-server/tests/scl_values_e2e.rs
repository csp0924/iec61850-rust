//! Values a model built from an inline SCL file serves over MMS: the model is
//! served on a loopback association and read back with the client, so each
//! assertion covers the parser, the model builder and the MMS projection
//! together.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iec61850_client::IedConnection;
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_mms::mms::pdu::type_specification::TypeSpecification;
use iec61850_model::{MmsValue, FC};
use iec61850_server::{IedServer, IedServerConfig, ServerHandle};

const SCL: &str = r#"<SCL>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnClass="LLN0" lnType="LLN0_T"/>
          <LN lnClass="GGIO" inst="1" lnType="GGIO_T">
            <DOI name="E"><DAI name="stVal"><Val>top</Val></DAI></DOI>
            <DOI name="W"><DAI name="stVal"><Val>wide</Val></DAI></DOI>
          </LN>
          <LN lnClass="CSWI" inst="1" lnType="CSWI_T"/>
          <LN lnClass="CSWI" inst="2" lnType="CSWI_T">
            <DOI name="Pos"><DAI name="ctlModel"><Val>direct-with-normal-security</Val></DAI></DOI>
          </LN>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <LNodeType id="GGIO_T" lnClass="GGIO">
      <DO name="Rec" type="REC_T"/>
      <DO name="E" type="ENS_T"/>
      <DO name="W" type="ENS_W"/>
    </LNodeType>
    <LNodeType id="CSWI_T" lnClass="CSWI">
      <DO name="Pos" type="DPC_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="BOOLEAN"/>
    </DOType>
    <DOType id="REC_T" cdc="SPS">
      <DA name="entryId" fc="ST" bType="EntryID"/>
      <DA name="octet64" fc="ST" bType="Octet64"/>
    </DOType>
    <DOType id="ENS_T" cdc="ENS">
      <DA name="stVal" fc="ST" bType="Enum" type="Narrow"/>
    </DOType>
    <DOType id="ENS_W" cdc="ENS">
      <DA name="stVal" fc="ST" bType="Enum" type="Wide"/>
    </DOType>
    <DOType id="DPC_T" cdc="DPC">
      <DA name="stVal" fc="ST" bType="Dbpos" dchg="true"/>
      <DA name="ctlModel" fc="CF" bType="Enum" type="CtlModels"><Val>sbo-with-normal-security</Val></DA>
      <DA name="sboTimeout" fc="CF" bType="INT32U"><Val>30000</Val></DA>
    </DOType>
    <EnumType id="CtlModels">
      <EnumVal ord="0">status-only</EnumVal>
      <EnumVal ord="1">direct-with-normal-security</EnumVal>
      <EnumVal ord="2">sbo-with-normal-security</EnumVal>
      <EnumVal ord="3">direct-with-enhanced-security</EnumVal>
      <EnumVal ord="4">sbo-with-enhanced-security</EnumVal>
    </EnumType>
    <EnumType id="Narrow">
      <EnumVal ord="-128">bottom</EnumVal>
      <EnumVal ord="127">top</EnumVal>
    </EnumType>
    <EnumType id="Wide">
      <EnumVal ord="1">narrow</EnumVal>
      <EnumVal ord="300">wide</EnumVal>
    </EnumType>
  </DataTypeTemplates>
</SCL>"#;

async fn serve(xml: &str) -> (ServerHandle, IedConnection) {
    let raw = iec61850_scl::parse_scl(xml).expect("parse");
    let model = raw
        .resolve()
        .expect("resolve")
        .build_model("IED1")
        .expect("build");
    let server = IedServer::builder()
        .model(Arc::new(model))
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig::default())
        .build()
        .expect("build the server");
    let handle = server.start().await.expect("start");
    let mms = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    let conn = IedConnection::with_mms_client(mms);
    conn.connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    (handle, conn)
}

async fn read(conn: &IedConnection, r: &str, fc: FC) -> MmsValue {
    tokio::time::timeout(Duration::from_secs(5), conn.read_object(r, fc))
        .await
        .expect("timeout")
        .unwrap_or_else(|e| panic!("read {r} failed: {e}"))
}

async fn spec(conn: &IedConnection, r: &str, fc: FC) -> TypeSpecification {
    tokio::time::timeout(
        Duration::from_secs(5),
        conn.get_variable_specification(r, fc),
    )
    .await
    .expect("timeout")
    .unwrap_or_else(|e| panic!("get variable access attributes of {r} failed: {e}"))
}

/// An EntryID is declared as a fixed 8-octet string and its default value is
/// eight octets, while a variable-length Octet64 still starts empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entry_id_default_fits_its_fixed_size() {
    let (handle, conn) = serve(SCL).await;
    let ts = spec(&conn, "IED1LD0/GGIO1.Rec.entryId", FC::St).await;
    let entry_id = read(&conn, "IED1LD0/GGIO1.Rec.entryId", FC::St).await;
    let octet64 = read(&conn, "IED1LD0/GGIO1.Rec.octet64", FC::St).await;
    conn.disconnect().await.ok();
    handle.stop().await;
    assert!(
        matches!(ts, TypeSpecification::OctetString { max_octets: 8 }),
        "entryId is declared as {ts:?}"
    );
    assert_eq!(entry_id, MmsValue::OctetString(vec![0u8; 8]));
    assert_eq!(octet64, MmsValue::OctetString(Vec::new()));
}

/// A client reads the DataTypeTemplates `<Val>` of `ctlModel` and
/// `sboTimeout`, and the `<DAI>` value where an instance overrides it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn template_defaults_are_served() {
    let (handle, conn) = serve(SCL).await;
    let ctl_model = read(&conn, "IED1LD0/CSWI1.Pos.ctlModel", FC::Cf).await;
    let sbo_timeout = read(&conn, "IED1LD0/CSWI1.Pos.sboTimeout", FC::Cf).await;
    let overridden = read(&conn, "IED1LD0/CSWI2.Pos.ctlModel", FC::Cf).await;
    conn.disconnect().await.ok();
    handle.stop().await;
    assert_eq!(ctl_model, MmsValue::Integer(2));
    assert_eq!(sbo_timeout, MmsValue::Unsigned(30000));
    assert_eq!(overridden, MmsValue::Integer(1));
}

/// An Enum whose ordinals exceed integer(8) is declared as integer(16), and
/// the value a client reads fits that declaration; one within integer(8) is
/// declared as integer(8).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enum_value_fits_its_declared_type() {
    let (handle, conn) = serve(SCL).await;
    let wide_ts = spec(&conn, "IED1LD0/GGIO1.W.stVal", FC::St).await;
    let wide = read(&conn, "IED1LD0/GGIO1.W.stVal", FC::St).await;
    let narrow_ts = spec(&conn, "IED1LD0/GGIO1.E.stVal", FC::St).await;
    let narrow = read(&conn, "IED1LD0/GGIO1.E.stVal", FC::St).await;
    conn.disconnect().await.ok();
    handle.stop().await;
    assert!(
        matches!(wide_ts, TypeSpecification::Integer { width_bits: 16 }),
        "W.stVal is declared as {wide_ts:?}"
    );
    assert_eq!(wide, MmsValue::Integer(300));
    assert!(
        matches!(narrow_ts, TypeSpecification::Integer { width_bits: 8 }),
        "E.stVal is declared as {narrow_ts:?}"
    );
    assert_eq!(narrow, MmsValue::Integer(127));
}
