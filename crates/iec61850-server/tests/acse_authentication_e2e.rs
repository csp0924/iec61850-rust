//! Authentication of associations over real TCP: an `AssociationAuthenticator`
//! on our server against our client sending an ACSE password and its AP-title
//! and AE-qualifier, the PDUs that carry a refusal, and the typed error the
//! client reports for it.

use bytes::BytesMut;
use iec61850_mms::iso::acse::{encode_aarq, AcseConnection, AcseIndication};
use iec61850_mms::iso::cotp::{CotpConnection, CotpOptions};
use iec61850_mms::iso::presentation::{
    encode_connect as pres_encode_connect, parse_reject, PresentationConnectionParameters,
};
use iec61850_mms::iso::session::{
    encode_connect as sess_encode_connect, IsoParameters, IsoSession, SessionIndication,
};
use iec61850_mms::mms::client::{ClientError, MmsClientBuilder};
use iec61850_mms::mms::pdu::initiate::{InitiateErrorPdu, InitiateRequestPdu};
use iec61850_mms::mms::pdu::service_error::{subcode, ErrorClass};
use iec61850_mms::{AarqAddressing, ApTitle, IsoConnectionParameters, MmsData};
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObjectBuilder, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::{
    AcseAuth, AcseServiceUserDiagnostic, AssociationAuthenticator, AssociationDecision,
    AssociationRequest, IedServer, IedServerConfig, ServerHandle,
};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;

const PASSWORD: &[u8] = b"s3cr3t-pw";

/// The calling AP-title our client offers by default.
const ALLOWED_AP_TITLE: &str = "1.1.1.999";

/// A test mechanism-name OID, 1.3.9999.1, as BER content octets.
const TEST_MECHANISM: [u8; 4] = [0x2b, 0xce, 0x0f, 0x01];

fn model() -> Arc<IedModel> {
    let vendor = DataAttribute::new(
        "vendor",
        FC::Dc,
        DataAttributeType::VisibleString(255),
        TrgOps::NONE,
        MmsValue::VisibleString("acme".into()),
    );
    let nam_plt = DataObjectBuilder::scalar("NamPlt")
        .add_da_node(vendor)
        .build()
        .unwrap();
    let lln0 = LogicalNodeBuilder::lln0().add_do(nam_plt).build().unwrap();
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .build()
        .unwrap();
    Arc::new(
        IedModelBuilder::new("TEST")
            .add_ld(ld)
            .unwrap()
            .build()
            .unwrap(),
    )
}

/// What the authenticator saw of one association request.
#[derive(Debug, Clone, PartialEq)]
struct Seen {
    calling_ap_title: Option<ApTitle>,
    calling_ae_qualifier: Option<i32>,
    called_ap_title: Option<ApTitle>,
    called_ae_qualifier: Option<i32>,
    authentication: AcseAuth,
}

/// Accepts the password `PASSWORD` from the calling AP-title
/// `ALLOWED_AP_TITLE`, and records every request it sees.
fn password_gate(seen: Arc<Mutex<Vec<Seen>>>) -> Arc<dyn AssociationAuthenticator> {
    let allowed: ApTitle = ALLOWED_AP_TITLE.parse().unwrap();
    Arc::new(move |request: &AssociationRequest<'_>| {
        seen.lock().unwrap().push(Seen {
            calling_ap_title: request.addressing.calling_ap_title.clone(),
            calling_ae_qualifier: request.addressing.calling_ae_qualifier,
            called_ap_title: request.addressing.called_ap_title.clone(),
            called_ae_qualifier: request.addressing.called_ae_qualifier,
            authentication: request.authentication.clone(),
        });
        if request.calling_ap_title() != Some(&allowed) {
            return AssociationDecision::Reject(
                AcseServiceUserDiagnostic::CallingApTitleNotRecognized,
            );
        }
        match request.authentication {
            AcseAuth::Password(password) if password.as_slice() == PASSWORD => {
                AssociationDecision::Accept
            }
            AcseAuth::Password(_) => {
                AssociationDecision::Reject(AcseServiceUserDiagnostic::AuthenticationFailure)
            }
            AcseAuth::None => {
                AssociationDecision::Reject(AcseServiceUserDiagnostic::AuthenticationRequired)
            }
            _ => AssociationDecision::Reject(
                AcseServiceUserDiagnostic::AuthenticationMechanismNameNotRecognized,
            ),
        }
    })
}

async fn start_server(
    authenticator: Option<Arc<dyn AssociationAuthenticator>>,
) -> (IedServer, ServerHandle) {
    let mut builder = IedServer::builder()
        .model(model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig::default());
    if let Some(authenticator) = authenticator {
        builder = builder.authenticator(authenticator);
    }
    let server = builder.build().expect("build server");
    let handle = server.start().await.expect("start server");
    (server, handle)
}

fn params_with(authentication: AcseAuth) -> IsoConnectionParameters {
    let mut params = IsoConnectionParameters::default();
    params.authentication = authentication;
    params
}

/// Associates our MMS client with `params` and reads the vendor name once
/// associated.
async fn associate(
    handle: &ServerHandle,
    params: IsoConnectionParameters,
) -> Result<(), ClientError> {
    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(5_000)
        .request_timeout_ms(5_000)
        .iso_parameters(params)
        .build();
    client
        .connect("127.0.0.1", handle.bound_addr.port())
        .await?;
    let vendor = client.read("TESTLD0", "LLN0$DC$NamPlt$vendor").await?;
    assert_eq!(vendor, MmsData::VisibleString("acme".into()));
    client.disconnect().await
}

#[tokio::test]
async fn correct_password_from_an_allowed_ap_title_is_accepted() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (_server, handle) = start_server(Some(password_gate(seen.clone()))).await;

    associate(&handle, params_with(AcseAuth::Password(PASSWORD.to_vec())))
        .await
        .expect("the right password associates");

    let seen = seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![Seen {
            calling_ap_title: Some("1.1.1.999".parse().unwrap()),
            calling_ae_qualifier: Some(12),
            called_ap_title: Some("1.1.1.999.1".parse().unwrap()),
            called_ae_qualifier: Some(12),
            authentication: AcseAuth::Password(PASSWORD.to_vec()),
        }],
        "the authenticator sees the addressing and the password the client sent"
    );
    handle.stop().await;
}

#[tokio::test]
async fn wrong_password_is_refused_as_an_authentication_failure() {
    let (_server, handle) = start_server(Some(password_gate(Arc::default()))).await;

    let err = associate(&handle, params_with(AcseAuth::Password(b"guess".to_vec())))
        .await
        .expect_err("a wrong password is refused");
    assert!(
        matches!(
            err,
            ClientError::AuthenticationRejected { diagnostic, .. }
                if diagnostic == AcseServiceUserDiagnostic::AuthenticationFailure
        ),
        "got {err:?}"
    );
    handle.stop().await;
}

#[tokio::test]
async fn missing_password_is_refused_as_authentication_required() {
    let (_server, handle) = start_server(Some(password_gate(Arc::default()))).await;

    let err = associate(&handle, params_with(AcseAuth::None))
        .await
        .expect_err("an association without credentials is refused");
    assert!(
        matches!(
            err,
            ClientError::AuthenticationRejected { diagnostic, .. }
                if diagnostic == AcseServiceUserDiagnostic::AuthenticationRequired
        ),
        "got {err:?}"
    );
    handle.stop().await;
}

#[tokio::test]
async fn ap_title_outside_the_allow_list_is_refused_through_the_iec61850_client() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (_server, handle) = start_server(Some(password_gate(seen.clone()))).await;

    let mut params = params_with(AcseAuth::Password(PASSWORD.to_vec()));
    params.local_ap_title = Some("1.3.9999.77".parse().unwrap());
    params.local_ae_qualifier = Some(7);
    let conn = iec61850_client::IedConnection::with_iso_parameters(params);
    let err = conn
        .connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect_err("an AP-title outside the allow list is refused");
    assert!(
        matches!(
            err,
            iec61850_client::ClientError::AuthenticationRejected { diagnostic, .. }
                if diagnostic == AcseServiceUserDiagnostic::CallingApTitleNotRecognized
        ),
        "got {err:?}"
    );
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].calling_ap_title,
        Some("1.3.9999.77".parse().unwrap())
    );
    assert_eq!(seen[0].calling_ae_qualifier, Some(7));
    handle.stop().await;
}

#[tokio::test]
async fn without_an_authenticator_every_association_is_accepted() {
    let (server, handle) = start_server(None).await;
    assert!(server.authenticator().is_none());

    associate(&handle, params_with(AcseAuth::None))
        .await
        .expect("no credentials");
    associate(
        &handle,
        params_with(AcseAuth::Password(b"anything".to_vec())),
    )
    .await
    .expect("any password");
    handle.stop().await;
}

#[tokio::test]
async fn an_authenticator_installed_or_removed_at_run_time_decides_the_next_association() {
    let (server, handle) = start_server(None).await;
    let wrong = || params_with(AcseAuth::Password(b"guess".to_vec()));

    associate(&handle, wrong())
        .await
        .expect("no authenticator yet");

    server.set_authenticator(Some(password_gate(Arc::default())));
    let err = associate(&handle, wrong()).await.expect_err("now refused");
    assert!(
        matches!(
            err,
            ClientError::AuthenticationRejected { diagnostic, .. }
                if diagnostic == AcseServiceUserDiagnostic::AuthenticationFailure
        ),
        "got {err:?}"
    );

    server.set_authenticator(None);
    associate(&handle, wrong())
        .await
        .expect("authenticator removed");
    handle.stop().await;
}

#[tokio::test]
async fn another_mechanism_reaches_the_authenticator_with_its_name_and_value() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (_server, handle) = start_server(Some(password_gate(seen.clone()))).await;
    // external [2] holding an INTEGER, a value the password mechanism cannot be
    let value = vec![0xa2, 0x03, 0x02, 0x01, 0x05];

    let err = associate(
        &handle,
        params_with(AcseAuth::other(TEST_MECHANISM.to_vec(), value.clone())),
    )
    .await
    .expect_err("the gate knows only the password mechanism");
    assert!(
        matches!(
            err,
            ClientError::AuthenticationRejected { diagnostic, .. }
                if diagnostic == AcseServiceUserDiagnostic::AuthenticationMechanismNameNotRecognized
        ),
        "got {err:?}"
    );
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].authentication,
        AcseAuth::other(TEST_MECHANISM.to_vec(), value)
    );
    handle.stop().await;
}

// The PDUs of a refusal

fn cn_with_password(password: &[u8]) -> Vec<u8> {
    let mut initiate = BytesMut::new();
    InitiateRequestPdu::default().encode(&mut initiate);
    let mut aarq = BytesMut::new();
    let addressing = IsoConnectionParameters::default().aarq_addressing();
    encode_aarq(
        &initiate,
        Some(&AcseAuth::Password(password.to_vec())),
        3,
        &addressing,
        &mut aarq,
    );
    let mut cp = BytesMut::new();
    pres_encode_connect(&PresentationConnectionParameters::default(), &aarq, &mut cp);
    let mut cn = BytesMut::new();
    sess_encode_connect(&IsoParameters::default(), &IsoSession::new(), &cp, &mut cn).unwrap();
    cn.to_vec()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn refusal_is_an_aare_with_its_diagnostic_in_a_cpr_inside_a_refuse() {
    let (_server, handle) = start_server(Some(password_gate(Arc::default()))).await;

    for (password, accepted) in [(b"guess".as_slice(), false), (PASSWORD, true)] {
        let tcp = TcpStream::connect(handle.bound_addr).await.unwrap();
        let mut cotp = CotpConnection::connect(tcp, CotpOptions::default())
            .await
            .unwrap();
        cotp.send_data(&cn_with_password(password)).await.unwrap();
        let raw = tokio::time::timeout(Duration::from_secs(5), cotp.recv_data())
            .await
            .expect("the server answers in time")
            .expect("an answer");
        let mut session = IsoSession::new();
        let indication = session.parse_message(&raw).expect("an SPDU");

        if accepted {
            // control: the right password is answered with an AC
            assert_eq!(indication, SessionIndication::Accept);
            continue;
        }
        let SessionIndication::Refuse(info) = indication else {
            panic!("a refusal travels in a session REFUSE, got {indication:?}");
        };
        assert_eq!(info.reason_code, Some(2), "rejection by the called SS-user");
        let cpr = info.user_data(&raw);
        let reject = parse_reject(cpr).expect("a CPR");
        assert_eq!(reject.provider_reason, None, "a user rejection");
        let pdv = reject.parse_user_data(cpr).expect("the CPR carries a PDV");
        assert_eq!(pdv.context_id, 1, "the AARE travels on the ACSE context");
        let aare = pdv.payload(cpr);

        // result rejected-permanent, result-source-diagnostic acse-service-user
        // authentication-failure (13)
        assert!(
            contains(aare, &[0xa2, 0x03, 0x02, 0x01, 0x01]),
            "{aare:02x?}"
        );
        assert!(
            contains(aare, &[0xa3, 0x05, 0xa1, 0x03, 0x02, 0x01, 0x0d]),
            "{aare:02x?}"
        );
        let mut acse = AcseConnection::new(None);
        let (indication, user_information) = acse.parse_message(aare).expect("an AARE");
        assert_eq!(indication, AcseIndication::AssociateFailed);
        assert_eq!(
            acse.result_source_diagnostic(),
            Some(AcseServiceUserDiagnostic::AuthenticationFailure)
        );

        // user-information: association-data on the MMS context (3) holding an
        // Initiate-ErrorPDU with access / object-access-denied
        let at = aare
            .iter()
            .position(|&b| b == 0xbe)
            .expect("the AARE carries user-information");
        assert!(
            contains(&aare[at..], &[0x02, 0x01, 0x03, 0xa0]),
            "indirect-reference is the MMS context: {aare:02x?}"
        );
        let initiate_error =
            InitiateErrorPdu::decode(user_information).expect("an Initiate-ErrorPDU");
        assert_eq!(
            initiate_error.service_error.error_class,
            ErrorClass::Access(subcode::access::OBJECT_ACCESS_DENIED)
        );

        // the server closes the connection after the refusal
        let closed = tokio::time::timeout(Duration::from_secs(5), cotp.recv_data())
            .await
            .expect("the server closes in time");
        assert!(closed.is_err(), "nothing follows the refusal");
    }
    handle.stop().await;
}

#[test]
fn association_request_accessors_read_absent_fields() {
    let addressing = AarqAddressing::default();
    let auth = AcseAuth::None;
    let peer = SocketAddr::from(([127, 0, 0, 1], 102));
    let request = AssociationRequest::new(peer, &addressing, &auth);
    assert_eq!(request.calling_ap_title(), None);
    assert_eq!(request.calling_ae_qualifier(), None);
    assert_eq!(request.password(), None);
}
