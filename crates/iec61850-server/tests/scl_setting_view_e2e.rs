//! An SCL setting declared with `fc="SE"` served under FC=SG as well.
//!
//! IEC 61850-6 makes an FC=SE data attribute visible under FC=SG, the value of
//! the active setting group, which a client reads and never writes. The model
//! holds one value per setting: committing an edit of the active group makes
//! the edited value the FC=SG value, and committing another group leaves it.
//! A setting declared with `fc="SG"` only is not editable under FC=SE.

use iec61850_mms::mms::client::{ClientError, MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::get_name_list::ObjectClass;
use iec61850_mms::mms::pdu::DataAccessError;
use iec61850_mms::mms::MmsData;
use iec61850_model::{IedModel, FC};
use iec61850_server::{IedServer, IedServerConfig, ServerHandle, WriteAccessPolicies};
use std::net::SocketAddr;
use std::sync::Arc;

const DOMAIN: &str = "SettingsLD0";

const SETTINGS_SCL: &str = r#"<SCL>
  <IED name="Settings">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <SettingControl numOfSGs="2" actSG="1"/>
          </LN0>
          <LN lnClass="PTOC" inst="1" lnType="PTOC_T">
            <DOI name="OpDlTmms"><DAI name="setVal"><Val>250</Val></DAI></DOI>
            <DOI name="StrVal"><SDI name="setMag"><DAI name="f"><Val>1.5</Val></DAI></SDI></DOI>
          </LN>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="Mod" type="ENC_T"/></LNodeType>
    <LNodeType id="PTOC_T" lnClass="PTOC">
      <DO name="OpDlTmms" type="ING_SE_T"/>
      <DO name="StrVal" type="ASG_SE_T"/>
      <DO name="TmMult" type="ING_SG_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC"><DA name="stVal" fc="ST" bType="BOOLEAN"/></DOType>
    <DOType id="ING_SE_T" cdc="ING">
      <DA name="setVal" fc="SE" bType="INT32"><Val>100</Val></DA>
    </DOType>
    <DOType id="ASG_SE_T" cdc="ASG">
      <DA name="setMag" fc="SE" bType="Struct" type="AnVal_T"/>
    </DOType>
    <DOType id="ING_SG_T" cdc="ING">
      <DA name="setVal" fc="SG" bType="INT32"><Val>7</Val></DA>
    </DOType>
    <DAType id="AnVal_T"><BDA name="f" bType="FLOAT32"/></DAType>
  </DataTypeTemplates>
</SCL>"#;

fn build_model() -> Arc<IedModel> {
    let raw = iec61850_scl::parse_scl(SETTINGS_SCL).expect("parse");
    let model = raw
        .resolve()
        .expect("resolve")
        .build_model("Settings")
        .expect("build");
    Arc::new(model)
}

async fn start() -> ServerHandle {
    // Every constraint is writable by policy, so that a refusal of FC=SG comes
    // from the constraint itself.
    let mut policies = WriteAccessPolicies::default();
    for fc in [FC::Sp, FC::Se, FC::Sg] {
        policies.set(fc, true);
    }
    let cfg = IedServerConfig {
        write_access_policies: policies,
        ..Default::default()
    };
    IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(cfg)
        .build()
        .expect("build server")
        .start()
        .await
        .expect("start")
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

async fn read(c: &mut MmsClient, item: &str) -> MmsData {
    c.read(DOMAIN, item)
        .await
        .unwrap_or_else(|e| panic!("read {item}: {e:?}"))
}

async fn write(c: &mut MmsClient, item: &str, value: MmsData) -> Result<(), ClientError> {
    c.write(DOMAIN, item, value).await
}

fn assert_refused(result: Result<(), ClientError>, expected: DataAccessError) {
    match result {
        Err(ClientError::DataAccessError(e)) if e == expected => {}
        other => panic!("expected {expected:?}, got {other:?}"),
    }
}

async fn names(c: &mut MmsClient) -> Vec<String> {
    let mut all = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let (page, more) = c
            .get_name_list(ObjectClass::NamedVariable, Some(DOMAIN), after.as_deref())
            .await
            .expect("get_name_list");
        after = page.last().cloned();
        all.extend(page);
        if !more {
            return all;
        }
    }
}

/// An FC=SE setting reads under FC=SG with its initial value, and a write
/// under FC=SG is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn se_setting_reads_under_sg_and_refuses_writes() {
    let handle = start().await;
    let mut c = connect(&handle).await;

    assert_eq!(
        read(&mut c, "PTOC1$SG$OpDlTmms$setVal").await,
        MmsData::Integer(250)
    );
    assert_eq!(
        read(&mut c, "PTOC1$SG$StrVal$setMag$f").await,
        MmsData::Float32(1.5)
    );
    assert_refused(
        write(&mut c, "PTOC1$SG$OpDlTmms$setVal", MmsData::Integer(1)).await,
        DataAccessError::ObjectAccessDenied,
    );
    assert_eq!(
        read(&mut c, "PTOC1$SG$OpDlTmms$setVal").await,
        MmsData::Integer(250)
    );
}

/// The name list and the read of the logical node under FC=SG carry every
/// setting; a setting declared under FC=SG only has no FC=SE name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sg_view_is_listed_and_read_with_the_logical_node() {
    let handle = start().await;
    let mut c = connect(&handle).await;

    let names = names(&mut c).await;
    for name in [
        "PTOC1$SG",
        "PTOC1$SG$OpDlTmms$setVal",
        "PTOC1$SG$StrVal$setMag$f",
        "PTOC1$SG$TmMult$setVal",
        "PTOC1$SE$OpDlTmms$setVal",
    ] {
        assert!(names.iter().any(|n| n == name), "{name} in {names:?}");
    }
    assert!(
        !names.iter().any(|n| n.starts_with("PTOC1$SE$TmMult")),
        "{names:?}"
    );

    match read(&mut c, "PTOC1$SG").await {
        MmsData::Structure(dos) => assert_eq!(dos.len(), 3, "{dos:?}"),
        other => panic!("PTOC1$SG reads as a structure, got {other:?}"),
    }
}

/// Committing an edit of the active group makes the edited value the FC=SG
/// value; until the commit, and for a commit of another group, the FC=SG
/// value stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_of_the_active_group_updates_the_sg_view() {
    let handle = start().await;
    let mut c = connect(&handle).await;

    write(&mut c, "LLN0$SP$SGCB$EditSG", MmsData::Unsigned(1))
        .await
        .expect("edit the active group");
    write(&mut c, "PTOC1$SE$OpDlTmms$setVal", MmsData::Integer(300))
        .await
        .expect("edit the setting");
    assert_eq!(
        read(&mut c, "PTOC1$SG$OpDlTmms$setVal").await,
        MmsData::Integer(250)
    );
    write(&mut c, "LLN0$SP$SGCB$CnfEdit", MmsData::Boolean(true))
        .await
        .expect("commit");
    assert_eq!(
        read(&mut c, "PTOC1$SG$OpDlTmms$setVal").await,
        MmsData::Integer(300)
    );

    write(&mut c, "LLN0$SP$SGCB$EditSG", MmsData::Unsigned(2))
        .await
        .expect("edit another group");
    write(&mut c, "PTOC1$SE$OpDlTmms$setVal", MmsData::Integer(400))
        .await
        .expect("edit the setting");
    write(&mut c, "LLN0$SP$SGCB$CnfEdit", MmsData::Boolean(true))
        .await
        .expect("commit");
    assert_eq!(
        read(&mut c, "PTOC1$SG$OpDlTmms$setVal").await,
        MmsData::Integer(300)
    );
}
