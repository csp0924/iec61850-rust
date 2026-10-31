//! The optional Owner and ResvTms attributes of report control blocks
//! registered from an SCL model, over a real association: loopback TCP and the
//! full ISO stack.
//!
//! Owner is a conditional attribute of both control block classes and ResvTms
//! one of the buffered class (IEC 61850-7-2 Tables 37 and 39). An SCL file
//! gives them to the report control blocks of an access point with
//! `<ReportSettings owner="true" resvTms="true">`, both defaulting to false
//! (IEC 61850-6 §9.3.2). A control block without one lists, describes and
//! reads without it, and naming it answers object-non-existent.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iec61850_client::IedConnection;
use iec61850_mms::mms::client::{ClientError, MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::get_name_list::ObjectClass;
use iec61850_mms::mms::pdu::type_specification::TypeSpecification;
use iec61850_mms::mms::pdu::DataAccessError;
use iec61850_mms::mms::MmsData;
use iec61850_model::IedModel;
use iec61850_server::{IedServer, IedServerConfig, ServerHandle};

const DOM: &str = "OwLD0";
const URCB: &str = "LLN0$RP$urcb01";
const BRCB: &str = "LLN0$BR$brcb";

const URCB_MEMBERS: [&str; 11] = [
    "RptID", "RptEna", "Resv", "DatSet", "ConfRev", "OptFlds", "BufTm", "SqNum", "TrgOps",
    "IntgPd", "GI",
];

const BRCB_MEMBERS: [&str; 13] = [
    "RptID",
    "RptEna",
    "DatSet",
    "ConfRev",
    "OptFlds",
    "BufTm",
    "SqNum",
    "TrgOps",
    "IntgPd",
    "GI",
    "PurgeBuf",
    "EntryID",
    "TimeofEntry",
];

macro_rules! t {
    ($e:expr) => {
        tokio::time::timeout(Duration::from_secs(5), $e)
            .await
            .expect("timed out")
    };
}

/// An IED with one indexed URCB and one BRCB in LLN0; `ied_services` and
/// `ap_services` are placed where IED-level and access point `<Services>`
/// belong.
fn scl(ied_services: &str, ap_services: &str) -> String {
    format!(
        r#"<SCL>
  <IED name="Ow">
    {ied_services}
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <DataSet name="Events">
              <FCDA ldInst="LD0" lnClass="LLN0" lnInst="" doName="Mod" daName="stVal" fc="ST"/>
            </DataSet>
            <ReportControl name="urcb" datSet="Events" confRev="1">
              <TrgOps dchg="true"/>
              <RptEnabled max="1"/>
            </ReportControl>
            <ReportControl name="brcb" datSet="Events" buffered="true" indexed="false" confRev="1">
              <TrgOps dchg="true"/>
            </ReportControl>
          </LN0>
        </LDevice>
      </Server>
      {ap_services}
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="Mod" type="ENC_T"/></LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="BOOLEAN" dchg="true"/>
    </DOType>
  </DataTypeTemplates>
</SCL>"#
    )
}

fn model(scl: &str) -> Arc<IedModel> {
    let raw = iec61850_scl::parse_scl(scl).expect("parse");
    Arc::new(
        raw.resolve()
            .expect("resolve")
            .build_model("Ow")
            .expect("build"),
    )
}

async fn start(scl: &str) -> ServerHandle {
    let server = IedServer::builder()
        .model(model(scl))
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig::default())
        .build()
        .expect("build server");
    server.register_from_model().expect("register_from_model");
    server.start().await.expect("start server")
}

async fn mms(handle: &ServerHandle) -> MmsClient {
    let mut c = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    t!(c.connect("127.0.0.1", handle.bound_addr.port())).expect("connect");
    c
}

async fn all_names(c: &mut MmsClient) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let (page, more) =
            t!(c.get_name_list(ObjectClass::NamedVariable, Some(DOM), cursor.as_deref()))
                .expect("names");
        cursor = page.last().cloned();
        out.extend(page);
        if !more {
            return out;
        }
    }
}

fn member_names(spec: &TypeSpecification) -> Vec<String> {
    match spec {
        TypeSpecification::Structure { components } => {
            components.iter().map(|c| c.name.clone()).collect()
        }
        other => panic!("expected a structure, got {other:?}"),
    }
}

/// Checks every service that shows the members of the two control blocks
/// against `has_owner` and, for the BRCB, `has_resv_tms`.
async fn check_attributes(handle: &ServerHandle, has_owner: bool, has_resv_tms: bool) {
    let mut c = mms(handle).await;
    let names = all_names(&mut c).await;
    for (rcb, base) in [(URCB, &URCB_MEMBERS[..]), (BRCB, &BRCB_MEMBERS[..])] {
        let mut expected: Vec<String> = base.iter().map(|m| m.to_string()).collect();
        if rcb == BRCB && has_resv_tms {
            expected.push("ResvTms".to_string());
        }
        if has_owner {
            expected.push("Owner".to_string());
        }
        let spec = t!(c.get_variable_access_attributes(DOM, rcb)).expect("type description");
        assert_eq!(member_names(&spec), expected, "{rcb}");

        let MmsData::Structure(values) = t!(c.read(DOM, rcb)).expect("read") else {
            panic!("{rcb} reads as a structure");
        };
        assert_eq!(values.len(), expected.len(), "{rcb}: {values:?}");

        let owner = format!("{rcb}$Owner");
        assert_eq!(names.contains(&owner), has_owner, "{owner} in {names:?}");
        assert!(names.contains(&format!("{rcb}$GI")), "{names:?}");

        let read = t!(c.read(DOM, &owner));
        let write = t!(c.write(DOM, &owner, MmsData::OctetString(vec![127, 0, 0, 1])));
        if has_owner {
            assert_eq!(read.expect("Owner reads"), MmsData::OctetString(Vec::new()));
            assert!(
                matches!(
                    write,
                    Err(ClientError::DataAccessError(
                        DataAccessError::ObjectAccessDenied
                    ))
                ),
                "{owner}: {write:?}"
            );
        } else {
            for (service, r) in [("read", read.map(|_| ())), ("write", write)] {
                assert!(
                    matches!(
                        r,
                        Err(ClientError::DataAccessError(
                            DataAccessError::ObjectNonExistent
                        ))
                    ),
                    "{service} {owner}: {r:?}"
                );
            }
        }
    }

    let resv_tms = format!("{BRCB}$ResvTms");
    assert_eq!(
        names.contains(&resv_tms),
        has_resv_tms,
        "{resv_tms} in {names:?}"
    );
    assert!(!names.contains(&format!("{URCB}$ResvTms")), "{names:?}");
    let read = t!(c.read(DOM, &resv_tms));
    if has_resv_tms {
        assert_eq!(read.expect("ResvTms reads"), MmsData::Integer(0));
    } else {
        let write = t!(c.write(DOM, &resv_tms, MmsData::Integer(30)));
        for (service, r) in [("read", read.map(|_| ())), ("write", write)] {
            assert!(
                matches!(
                    r,
                    Err(ClientError::DataAccessError(
                        DataAccessError::ObjectNonExistent
                    ))
                ),
                "{service} {resv_tms}: {r:?}"
            );
        }
        // Without ResvTms the client that enables the BRCB reserves it.
        t!(c.write(DOM, &format!("{BRCB}$RptEna"), MmsData::Boolean(true)))
            .expect("enable the BRCB");
        let mut other = mms(handle).await;
        let taken = t!(other.write(DOM, &format!("{BRCB}$RptEna"), MmsData::Boolean(true)));
        assert!(taken.is_err(), "{taken:?}");
        t!(c.write(DOM, &format!("{BRCB}$RptEna"), MmsData::Boolean(false)))
            .expect("disable the BRCB");
    }

    let conn = IedConnection::with_mms_client(
        MmsClientBuilder::new()
            .connect_timeout_ms(3_000)
            .request_timeout_ms(3_000)
            .build(),
    );
    t!(conn.connect("127.0.0.1", handle.bound_addr.port())).expect("connect");
    for rcb in [URCB, BRCB] {
        let handle = t!(conn.get_rcb_values(&format!("{DOM}/{rcb}"))).expect("GetRCBValues");
        assert_eq!(handle.owner().is_some(), has_owner, "{rcb}");
        assert_eq!(handle.has_resv_tms(), rcb == BRCB && has_resv_tms, "{rcb}");
    }
}

/// Without `<ReportSettings>` the control blocks have neither Owner nor
/// ResvTms.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn report_control_blocks_have_no_optional_attributes_by_default() {
    let handle = start(&scl("", "")).await;
    check_attributes(&handle, false, false).await;
    handle.stop().await;
}

/// `<ReportSettings owner="true">` gives the control blocks Owner.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn report_settings_owner_gives_report_control_blocks_owner() {
    let owner = r#"<Services><ReportSettings owner="true"/></Services>"#;
    let handle = start(&scl(owner, "")).await;
    check_attributes(&handle, true, false).await;
    handle.stop().await;
}

/// `<ReportSettings resvTms="true">` gives the buffered control block ResvTms.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn report_settings_resv_tms_gives_buffered_control_blocks_resv_tms() {
    let resv_tms = r#"<Services><ReportSettings resvTms="true"/></Services>"#;
    let handle = start(&scl(resv_tms, "")).await;
    check_attributes(&handle, false, true).await;
    handle.stop().await;
}

/// The `<ReportSettings>` of the access point replaces the IED-level one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn access_point_report_settings_replace_the_ied_level_ones() {
    let both = r#"<Services><ReportSettings owner="true" resvTms="true"/></Services>"#;
    let neither = r#"<Services><ReportSettings/></Services>"#;
    let handle = start(&scl(both, neither)).await;
    check_attributes(&handle, false, false).await;
    handle.stop().await;
    let handle = start(&scl(neither, both)).await;
    check_attributes(&handle, true, true).await;
    handle.stop().await;
}
