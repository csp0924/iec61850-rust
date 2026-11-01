//! The GOOSE `t` of a publisher registered from the model: the server stamps
//! it from its wall clock with the configured TimeQuality when the publisher
//! is registered and on every stNum change, and a subscriber receives it.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iec61850_goose::{GooseEvent, GooseReceiver, GooseSubscriberBuilder, UtcTime};
use iec61850_model::{IedModel, MmsValue};
use iec61850_server::{
    FromModelOptions, IedServer, IedServerConfig, TimeAccuracy, TimeQuality, WallClock,
};

const DOMAIN: &str = "TsLD0";
const GOCB_REF: &str = "TsLD0/LLN0$GO$gcbEvents";

const TS_SCL: &str = r#"<SCL>
  <IED name="Ts">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <DataSet name="Events">
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
            </DataSet>
            <GSEControl name="gcbEvents" datSet="Events" appID="TsEvents" confRev="1"/>
          </LN0>
          <LN lnClass="GGIO" inst="1" lnType="GGIO_T"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <LNodeType id="GGIO_T" lnClass="GGIO">
      <DO name="Ind1" type="SPS_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" bType="Enum" type="Mod_E" fc="ST"/>
    </DOType>
    <DOType id="SPS_T" cdc="SPS">
      <DA name="stVal" bType="BOOLEAN" fc="ST"/>
      <DA name="q" bType="Quality" fc="ST"/>
      <DA name="t" bType="Timestamp" fc="ST"/>
    </DOType>
    <EnumType id="Mod_E">
      <EnumVal ord="1">on</EnumVal>
    </EnumType>
  </DataTypeTemplates>
</SCL>"#;

fn model() -> Arc<IedModel> {
    let raw = iec61850_scl::parse_scl(TS_SCL).expect("parse");
    Arc::new(
        raw.resolve()
            .expect("resolve")
            .build_model("Ts")
            .expect("build"),
    )
}

fn quality() -> TimeQuality {
    TimeQuality::new(true, false, true, TimeAccuracy::bits(14).unwrap())
}

/// A server with the TimeQuality of [`quality`] whose model publishers read
/// `clock`.
fn server_with_clock(clock: Arc<Mutex<Duration>>) -> IedServer {
    let mut config = IedServerConfig::default();
    config.time_quality = quality();
    let server = IedServer::builder()
        .model(model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(config)
        .build()
        .expect("build server");
    let wall_clock: WallClock = Arc::new(move || *clock.lock().unwrap());
    server
        .register_from_model_with(&FromModelOptions::new().with_wall_clock(wall_clock))
        .expect("register from model");
    server
}

/// Feeds `frame` to a subscriber of `GOCB_REF` and returns the stNum and `t`
/// of the state it delivered.
fn receive(frame: &[u8]) -> (u32, UtcTime) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_cb = seen.clone();
    let sub = GooseSubscriberBuilder::new()
        .gocb_ref(GOCB_REF)
        .listener(move |e| {
            if let GooseEvent::NewState { state, .. } | GooseEvent::Retransmission { state, .. } = e
            {
                seen_cb
                    .lock()
                    .unwrap()
                    .push((state.st_num, state.timestamp));
            }
        })
        .build();
    let mut rx = GooseReceiver::new();
    rx.add_subscriber(sub);
    let mut rx = rx.start();
    rx.handle_message(frame);
    let got = seen.lock().unwrap().clone();
    assert_eq!(got.len(), 1, "one state delivered");
    got[0]
}

fn at(secs: u64, millis: u32) -> Duration {
    Duration::new(secs, millis * 1_000_000)
}

fn stamp(secs: u64, millis: u32) -> UtcTime {
    UtcTime::from_duration_since_epoch(at(secs, millis), quality()).unwrap()
}

#[test]
fn t_follows_the_state_changes_of_a_model_publisher() {
    let clock = Arc::new(Mutex::new(at(1_761_955_200, 0)));
    let server = server_with_clock(clock.clone());
    let handle = server
        .gocb_registry()
        .find(DOMAIN, "LLN0", "gcbEvents")
        .expect("model GoCB registered");
    let data = [MmsValue::Boolean(true)];
    let publish = || handle.publisher.lock().unwrap().publish(&data).unwrap();

    // Registration stamps the initial state.
    *clock.lock().unwrap() = at(1_761_955_201, 0);
    let (st, t) = receive(&publish());
    assert_eq!(st, 1);
    assert!(!t.is_null());
    assert_eq!(t, stamp(1_761_955_200, 0));
    assert_eq!(t.time_quality(), quality());

    // A retransmission keeps the time of the last state change.
    assert_eq!(receive(&publish()), (1, stamp(1_761_955_200, 0)));

    // A state change takes the clock reading at the change.
    *clock.lock().unwrap() = at(1_761_955_260, 500);
    handle.publisher.lock().unwrap().increase_st_num();
    *clock.lock().unwrap() = at(1_761_955_270, 0);
    assert_eq!(receive(&publish()), (2, stamp(1_761_955_260, 500)));
    assert_eq!(receive(&publish()), (2, stamp(1_761_955_260, 500)));

    *clock.lock().unwrap() = at(1_761_955_300, 250);
    handle.publisher.lock().unwrap().increase_st_num();
    assert_eq!(receive(&publish()), (3, stamp(1_761_955_300, 250)));

    // A reset is a state change too.
    *clock.lock().unwrap() = at(1_761_955_400, 0);
    handle.publisher.lock().unwrap().reset();
    assert_eq!(receive(&publish()), (1, stamp(1_761_955_400, 0)));
}

#[test]
fn an_unrepresentable_clock_reading_is_marked_as_clock_failure() {
    let clock = Arc::new(Mutex::new(Duration::from_secs(u64::from(u32::MAX) + 1)));
    let server = server_with_clock(clock);
    let handle = server
        .gocb_registry()
        .find(DOMAIN, "LLN0", "gcbEvents")
        .expect("model GoCB registered");
    let frame = handle
        .publisher
        .lock()
        .unwrap()
        .publish(&[MmsValue::Boolean(true)])
        .unwrap();
    let (_, t) = receive(&frame);
    assert!(t.time_quality().clock_failure);
    assert_eq!(t.seconds_since_epoch(), 0);
}

#[test]
fn without_a_wall_clock_the_system_clock_stamps_t() {
    let server = IedServer::builder()
        .model(model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()
        .expect("build server");
    server
        .register_from_model_with(&FromModelOptions::new())
        .expect("register from model");
    let handle = server
        .gocb_registry()
        .find(DOMAIN, "LLN0", "gcbEvents")
        .expect("model GoCB registered");
    let frame = handle
        .publisher
        .lock()
        .unwrap()
        .publish(&[MmsValue::Boolean(true)])
        .unwrap();
    let (_, t) = receive(&frame);
    // Any reading after 2001-09-09 has a ten-digit SecondSinceEpoch.
    assert!(t.seconds_since_epoch() > 1_000_000_000);
    assert_eq!(t.time_quality(), IedServerConfig::default().time_quality);
}
