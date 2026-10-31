//! The member order a model built from an inline SCL file serves over MMS:
//! the model is served on a loopback association and described and read back
//! with the client, so each assertion covers the parser, the model builder and
//! the MMS projection together.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iec61850_client::IedConnection;
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_mms::mms::pdu::type_specification::TypeSpecification;
use iec61850_model::{MmsValue, FC};
use iec61850_server::{IedServer, IedServerConfig, ServerHandle, WriteAccessPolicies};

/// `SeqA` is a SEQ whose DOType declares the sub-objects `c1` to `c3` before
/// the attribute `seqT`, the order IEC 61850-7-3 gives the CDC, with `q` and
/// `t` of another functional constraint in between. `Raw` interleaves
/// attributes of the basic types INT24, Octet16 and SvOptFlds with a
/// sub-object.
const SCL: &str = r#"<SCL>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnClass="LLN0" lnType="LLN0_T"/>
          <LN lnClass="MSQI" inst="1" lnType="MSQI_T">
            <DOI name="SeqA">
              <SDI name="c2"><SDI name="cVal"><SDI name="mag"><DAI name="f"><Val>2.5</Val></DAI></SDI></SDI></SDI>
              <DAI name="seqT"><Val>-3</Val></DAI>
            </DOI>
          </LN>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <LNodeType id="MSQI_T" lnClass="MSQI">
      <DO name="SeqA" type="SEQ_T"/>
      <DO name="Raw" type="RAW_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="BOOLEAN"/>
    </DOType>
    <DOType id="SEQ_T" cdc="SEQ">
      <SDO name="c1" type="CMV_T"/>
      <DA name="q" fc="MX" bType="Quality" qchg="true"/>
      <SDO name="c2" type="CMV_T"/>
      <SDO name="c3" type="CMV_T"/>
      <DA name="seqT" fc="MX" bType="INT24"/>
      <DA name="d" fc="DC" bType="VisString255"/>
    </DOType>
    <DOType id="CMV_T" cdc="CMV">
      <DA name="cVal" fc="MX" bType="Struct" type="Vector_T"/>
    </DOType>
    <DOType id="RAW_T" cdc="SPS">
      <DA name="i24" fc="ST" bType="INT24"><Val>-8388608</Val></DA>
      <SDO name="sub" type="ENC_T"/>
      <DA name="oct16" fc="ST" bType="Octet16"><Val>AAECAwQFBgcICQoLDA0ODw==</Val></DA>
      <DA name="svOpts" fc="ST" bType="SvOptFlds"/>
      <DA name="cfgI24" fc="CF" bType="INT24"/>
      <DA name="cfgOct6" fc="CF" bType="Octet6"/>
      <DA name="cfgSv" fc="CF" bType="SvOptFlds"/>
      <DA name="cfgLog" fc="CF" bType="LogOptFlds"/>
    </DOType>
    <DAType id="Vector_T">
      <BDA name="mag" bType="Struct" type="AV_T"/>
    </DAType>
    <DAType id="AV_T">
      <BDA name="f" bType="FLOAT32"/>
    </DAType>
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
        .config({
            let mut policies = WriteAccessPolicies::default();
            policies.set(FC::Cf, true);
            let mut config = IedServerConfig::default();
            config.write_access_policies = policies;
            config
        })
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

fn component_names(ts: &TypeSpecification) -> Vec<&str> {
    match ts {
        TypeSpecification::Structure { components } => {
            components.iter().map(|c| c.name.as_str()).collect()
        }
        other => panic!("expected a structure, got {other:?}"),
    }
}

fn component<'a>(ts: &'a TypeSpecification, name: &str) -> &'a TypeSpecification {
    match ts {
        TypeSpecification::Structure { components } => {
            &components
                .iter()
                .find(|c| c.name == name)
                .unwrap_or_else(|| panic!("no component {name}"))
                .type_spec
        }
        other => panic!("expected a structure, got {other:?}"),
    }
}

/// GetVariableAccessAttributes lists the members of a data object in the
/// order its DOType declares them, sub-objects and attributes interleaved,
/// and a read returns the values in that same order.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn data_object_members_follow_the_declared_order() {
    let (handle, conn) = serve(SCL).await;
    let ts = spec(&conn, "IED1LD0/MSQI1.SeqA", FC::Mx).await;
    let value = read(&conn, "IED1LD0/MSQI1.SeqA", FC::Mx).await;
    conn.disconnect().await.ok();
    handle.stop().await;

    assert_eq!(component_names(&ts), ["c1", "q", "c2", "c3", "seqT"]);
    let MmsValue::Structure(members) = value else {
        panic!("SeqA[MX] read as {value:?}");
    };
    assert_eq!(members.len(), 5);
    let cval = |v: &MmsValue| match v {
        MmsValue::Structure(c) => c[0].clone(),
        other => panic!("{other:?}"),
    };
    assert_eq!(
        cval(&members[2]),
        MmsValue::Structure(vec![MmsValue::Structure(vec![MmsValue::Float32(2.5)])])
    );
    assert_eq!(members[4], MmsValue::Integer(-3));
}

/// INT24, Octet16 and SvOptFlds attributes are served with the MMS types
/// their widths call for, in the declared member order, and read back their
/// SCL values.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn schema_basic_types_are_served_with_their_widths() {
    let (handle, conn) = serve(SCL).await;
    let ts = spec(&conn, "IED1LD0/MSQI1.Raw", FC::St).await;
    let i24 = read(&conn, "IED1LD0/MSQI1.Raw.i24", FC::St).await;
    let oct16 = read(&conn, "IED1LD0/MSQI1.Raw.oct16", FC::St).await;
    let sv = read(&conn, "IED1LD0/MSQI1.Raw.svOpts", FC::St).await;
    conn.disconnect().await.ok();
    handle.stop().await;

    assert_eq!(i24, MmsValue::Integer(-8_388_608));
    assert_eq!(oct16, MmsValue::OctetString((0..16).collect()));
    assert_eq!(
        sv,
        MmsValue::BitString {
            padding: 3,
            data: vec![0]
        }
    );

    assert_eq!(component_names(&ts), ["i24", "sub", "oct16", "svOpts"]);
    assert!(matches!(
        component(&ts, "i24"),
        TypeSpecification::Integer { width_bits: 24 }
    ));
    assert!(matches!(
        component(&ts, "oct16"),
        TypeSpecification::OctetString { max_octets: -16 }
    ));
    assert!(matches!(
        component(&ts, "svOpts"),
        TypeSpecification::BitString { bits: -5 }
    ));
}

/// A write of each new basic type within its width is stored and read back,
/// and a bit string longer than its declared width is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn schema_basic_types_are_written_within_their_widths() {
    let (handle, conn) = serve(SCL).await;
    let write = |r: &'static str, v: MmsValue| {
        let conn = &conn;
        async move {
            tokio::time::timeout(Duration::from_secs(5), conn.write_object(r, FC::Cf, v))
                .await
                .expect("timeout")
        }
    };
    let accepted = [
        ("IED1LD0/MSQI1.Raw.cfgI24", MmsValue::Integer(8_388_607)),
        (
            "IED1LD0/MSQI1.Raw.cfgOct6",
            MmsValue::OctetString(vec![1, 2, 3, 4, 5, 6]),
        ),
        (
            "IED1LD0/MSQI1.Raw.cfgSv",
            MmsValue::BitString {
                padding: 3,
                data: vec![0xA0],
            },
        ),
        (
            "IED1LD0/MSQI1.Raw.cfgLog",
            MmsValue::BitString {
                padding: 7,
                data: vec![0x80],
            },
        ),
    ];
    let mut stored = Vec::new();
    for (r, v) in accepted.iter().cloned() {
        let result = write(r, v).await;
        stored.push((r, result.is_ok(), read(&conn, r, FC::Cf).await));
    }
    let refused = [
        (
            "IED1LD0/MSQI1.Raw.cfgSv",
            MmsValue::BitString {
                padding: 0,
                data: vec![0xFF],
            },
        ),
        (
            "IED1LD0/MSQI1.Raw.cfgLog",
            MmsValue::BitString {
                padding: 6,
                data: vec![0xC0],
            },
        ),
    ];
    let mut rejected = Vec::new();
    for (r, v) in refused.iter().cloned() {
        rejected.push((r, write(r, v).await.is_err()));
    }
    conn.disconnect().await.ok();
    handle.stop().await;

    for ((r, ok, read_back), (_, written)) in stored.iter().zip(accepted.iter()) {
        assert!(ok, "{r} refused");
        assert_eq!(read_back, written, "{r}");
    }
    for (r, refused) in rejected {
        assert!(refused, "{r} accepted a value beyond its width");
    }
}
