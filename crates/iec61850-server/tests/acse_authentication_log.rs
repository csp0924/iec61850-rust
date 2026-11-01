//! No ACSE password reaches the log: our client associates with our server
//! once with the right and once with a wrong password, and every event either
//! side traces is checked for the passwords as text and as decimal or
//! hexadecimal bytes.
//!
//! The test sits alone in its binary because it captures events with a
//! thread-local subscriber, which another test running on a parallel thread
//! would disturb through the shared callsite registry.

use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_mms::IsoConnectionParameters;
use iec61850_model::{
    DataAttribute, DataAttributeType, DataObjectBuilder, IedModel, IedModelBuilder,
    LogicalDeviceBuilder, LogicalNodeBuilder, MmsValue, TrgOps, FC,
};
use iec61850_server::{
    AcseAuth, AcseServiceUserDiagnostic, AssociationDecision, AssociationRequest, IedServer,
    IedServerConfig,
};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

const PASSWORD: &[u8] = b"s3cr3t-pw";
const WRONG_PASSWORD: &[u8] = b"wr0ng-pw";

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

/// A subscriber that writes every event and span field to one buffer.
struct Recorder(Arc<Mutex<String>>);

struct Fields<'a>(&'a mut String);

impl tracing::field::Visit for Fields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let _ = write!(self.0, " {}={:?}", field.name(), value);
    }
}

impl tracing::Subscriber for Recorder {
    fn register_callsite(
        &self,
        _: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        span.record(&mut Fields(&mut self.0.lock().unwrap()));
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        values.record(&mut Fields(&mut self.0.lock().unwrap()));
    }
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut log = self.0.lock().unwrap();
        log.push('\n');
        event.record(&mut Fields(&mut log));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[tokio::test(flavor = "current_thread")]
async fn no_password_reaches_the_log() {
    let log = Arc::new(Mutex::new(String::new()));
    let _guard = tracing::subscriber::set_default(Recorder(log.clone()));

    let server = IedServer::builder()
        .model(model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig::default())
        .authenticator(Arc::new(|request: &AssociationRequest<'_>| {
            if request.password() == Some(PASSWORD) {
                AssociationDecision::Accept
            } else {
                AssociationDecision::Reject(AcseServiceUserDiagnostic::AuthenticationFailure)
            }
        }))
        .build()
        .expect("build server");
    let handle = server.start().await.expect("start server");

    for (password, accepted) in [(PASSWORD, true), (WRONG_PASSWORD, false)] {
        let mut params = IsoConnectionParameters::default();
        params.authentication = AcseAuth::Password(password.to_vec());
        let mut client = MmsClientBuilder::new()
            .connect_timeout_ms(5_000)
            .request_timeout_ms(5_000)
            .iso_parameters(params)
            .build();
        let result = client.connect("127.0.0.1", handle.bound_addr.port()).await;
        assert_eq!(result.is_ok(), accepted, "{result:?}");
        if accepted {
            client.disconnect().await.expect("release");
        }
    }
    handle.stop().await;

    let log = log.lock().unwrap().clone();
    assert!(
        log.contains("the authenticator accepted the association")
            && log.contains("the authenticator refused the association"),
        "both decisions are logged: {log}"
    );
    for secret in [PASSWORD, WRONG_PASSWORD] {
        let text = std::str::from_utf8(secret).unwrap();
        let decimal = format!("{secret:?}");
        let decimal = &decimal[1..decimal.len() - 1];
        let hex = format!("{secret:02x?}");
        let hex = &hex[1..hex.len() - 1];
        let compact_hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!log.contains(text), "{text} is in the log: {log}");
        for form in [decimal, hex, compact_hex.as_str()] {
            assert!(!log.contains(form), "{form} is in the log: {log}");
        }
    }
}
