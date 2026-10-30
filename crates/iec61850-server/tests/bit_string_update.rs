//! Run-time updates of bit-string data attributes.
//!
//! `update_bit_string_from_int` and `update_bit_string` are read back over a
//! loopback MMS Read, so the stored bytes and padding are checked as they leave
//! the server. Rejected updates leave the attribute unchanged, and an accepted
//! update triggers the report control blocks that watch the attribute according
//! to its trigger options.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iec61850_client::IedConnection;
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_model::{
    cdc, DataAttribute, DataAttributeType, IedModel, IedModelBuilder, LogicalDeviceBuilder,
    LogicalNodeBuilder, MmsValue, NodeRef, ObjectRef, TrgOps, FC,
};
use iec61850_server::{
    Dataset, DatasetEntry, IedServer, InclusionFlag, Rcb, ReportControl, ServerError,
    TriggerOptions,
};

const DOMAIN: &str = "IED1LD0";

fn build_model() -> Arc<IedModel> {
    let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
    let cswi = LogicalNodeBuilder::new("", "CSWI", "1")
        .add_do(cdc::dps("Pos", cdc::CdcOptions::NONE))
        .build()
        .expect("cswi");
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .add_ln(cswi)
        .build()
        .expect("ld");
    Arc::new(
        IedModelBuilder::new("IED1")
            .add_ld(ld)
            .expect("add_ld")
            .build()
            .expect("model"),
    )
}

fn build_server() -> IedServer {
    IedServer::builder()
        .model(build_model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()
        .expect("server build")
}

fn resolve_da(model: &IedModel, path: &str) -> DataAttribute {
    let r = ObjectRef::parse_iec(path).expect("parse_iec");
    match model.node_by_object_ref(&r).expect("node lookup") {
        NodeRef::Da(da) => DataAttribute {
            name: da.name.clone(),
            fc: da.fc,
            ty: da.ty,
            trg_ops: da.trg_ops,
            value: Arc::clone(&da.value),
            children: Vec::new(),
        },
        _ => panic!("expected a data attribute at {path}"),
    }
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

fn bit_string(padding: u8, data: &[u8]) -> MmsValue {
    MmsValue::BitString {
        padding,
        data: data.to_vec(),
    }
}

fn current(da: &DataAttribute) -> MmsValue {
    da.value.read().unwrap().clone()
}

/// The four `Dbpos` states are written most significant bit first and read
/// back over MMS as a `BIT STRING(2)`: one data byte with padding 6.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dbpos_from_int_reads_back_msb_first() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let server = build_server();
        let model = server.model();
        let st_val = resolve_da(&model, "IED1LD0/CSWI1.Pos.stVal");
        let handle = server.start().await.expect("start");
        let conn = make_client(handle.bound_addr.port()).await;

        for (value, byte) in [(0u32, 0x00u8), (1, 0x40), (2, 0x80), (3, 0xc0)] {
            server
                .update_bit_string_from_int(&st_val, value)
                .expect("update_bit_string_from_int");
            let read = conn
                .read_object(&format!("{DOMAIN}/CSWI1.Pos.stVal"), FC::St)
                .await
                .expect("read_object");
            assert_eq!(read, bit_string(6, &[byte]), "dbpos {value}");
        }

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// A 13-bit quality written as bytes reads back with padding 3 and the three
/// unused low-order bits of the last byte cleared.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quality_bytes_read_back_with_padding_cleared() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let server = build_server();
        let model = server.model();
        let q = resolve_da(&model, "IED1LD0/CSWI1.Pos.q");
        server
            .update_bit_string(&q, &[0xc0, 0x1f], 3)
            .expect("update_bit_string");

        let handle = server.start().await.expect("start");
        let conn = make_client(handle.bound_addr.port()).await;
        let read = conn
            .read_object(&format!("{DOMAIN}/CSWI1.Pos.q"), FC::St)
            .await
            .expect("read_object");
        assert_eq!(read, bit_string(3, &[0xc0, 0x18]));

        let _ = conn.disconnect().await;
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// A bit-string update of an attribute that holds another type returns
/// `TypeMismatch` and leaves the value unchanged.
#[test]
fn bit_string_update_of_non_bit_string_rejected() {
    let server = build_server();
    let da = DataAttribute::new(
        "stVal",
        FC::St,
        DataAttributeType::Boolean,
        TrgOps::DCHG,
        MmsValue::Boolean(true),
    );
    assert!(matches!(
        server.update_bit_string(&da, &[0x80], 6),
        Err(ServerError::TypeMismatch {
            expected: "BitString",
            actual: "Boolean",
            ..
        })
    ));
    assert!(matches!(
        server.update_bit_string_from_int(&da, 1),
        Err(ServerError::TypeMismatch { .. })
    ));
    assert_eq!(current(&da), MmsValue::Boolean(true));
}

/// Bytes whose bit count differs from the attribute's are rejected: 13 bits
/// for a `Dbpos`, and 8 bits with padding 0.
#[test]
fn bit_string_update_with_other_bit_count_rejected() {
    let server = build_server();
    let model = server.model();
    let st_val = resolve_da(&model, "IED1LD0/CSWI1.Pos.stVal");
    server.update_bit_string_from_int(&st_val, 2).unwrap();

    for (data, padding) in [(&[0x00u8, 0x00][..], 3u8), (&[0x40][..], 0)] {
        assert!(matches!(
            server.update_bit_string(&st_val, data, padding),
            Err(ServerError::TypeMismatch {
                actual: "BitString of another length",
                ..
            })
        ));
        assert_eq!(current(&st_val), bit_string(6, &[0x80]));
    }
}

/// Padding of 8 or more, and nonzero padding on empty data, are rejected.
#[test]
fn bit_string_update_with_invalid_padding_rejected() {
    let server = build_server();
    let model = server.model();
    let st_val = resolve_da(&model, "IED1LD0/CSWI1.Pos.stVal");
    server.update_bit_string_from_int(&st_val, 1).unwrap();

    for (data, padding, actual) in [
        (&[0x00u8, 0x80][..], 14u8, "BitString with padding above 7"),
        (&[0x80][..], 8, "BitString with padding above 7"),
        (&[][..], 1, "empty BitString with nonzero padding"),
    ] {
        match server.update_bit_string(&st_val, data, padding) {
            Err(ServerError::TypeMismatch { actual: a, .. }) => assert_eq!(a, actual),
            other => panic!("unexpected result {other:?}"),
        }
        assert_eq!(current(&st_val), bit_string(6, &[0x40]));
    }
}

/// An integer that needs more bits than the attribute holds is rejected.
#[test]
fn bit_string_from_int_value_too_wide_rejected() {
    let server = build_server();
    let model = server.model();
    let st_val = resolve_da(&model, "IED1LD0/CSWI1.Pos.stVal");
    server.update_bit_string_from_int(&st_val, 3).unwrap();

    for value in [4u32, u32::MAX] {
        assert!(matches!(
            server.update_bit_string_from_int(&st_val, value),
            Err(ServerError::TypeMismatch {
                actual: "integer wider than the attribute",
                ..
            })
        ));
        assert_eq!(current(&st_val), bit_string(6, &[0xc0]));
    }
}

/// An integer update needs a bit string of 1 to 32 bits: 0 and 33 bits are
/// rejected, 1 bit takes 0 or 1, and 32 bits take the full range. A value
/// spanning two bytes with padding is shifted left past the padding.
#[test]
fn bit_string_from_int_width_bound() {
    let server = build_server();
    let wide = DataAttribute::new(
        "wide",
        FC::Cf,
        DataAttributeType::GenericBitString(33),
        TrgOps::NONE,
        MmsValue::default_for(DataAttributeType::GenericBitString(33)),
    );
    assert!(matches!(
        server.update_bit_string_from_int(&wide, 1),
        Err(ServerError::TypeMismatch {
            actual: "BitString of 0 or more than 32 bits",
            ..
        })
    ));
    assert_eq!(current(&wide), bit_string(7, &[0, 0, 0, 0, 0]));

    let full = DataAttribute::new(
        "full",
        FC::Cf,
        DataAttributeType::GenericBitString(32),
        TrgOps::NONE,
        MmsValue::default_for(DataAttributeType::GenericBitString(32)),
    );
    server
        .update_bit_string_from_int(&full, 0x8000_0001)
        .unwrap();
    assert_eq!(current(&full), bit_string(0, &[0x80, 0x00, 0x00, 0x01]));

    let empty = DataAttribute::new(
        "empty",
        FC::Cf,
        DataAttributeType::GenericBitString(0),
        TrgOps::NONE,
        MmsValue::default_for(DataAttributeType::GenericBitString(0)),
    );
    assert!(matches!(
        server.update_bit_string_from_int(&empty, 0),
        Err(ServerError::TypeMismatch {
            actual: "BitString of 0 or more than 32 bits",
            ..
        })
    ));
    assert_eq!(current(&empty), bit_string(0, &[]));

    let one = DataAttribute::new(
        "one",
        FC::Cf,
        DataAttributeType::GenericBitString(1),
        TrgOps::NONE,
        MmsValue::default_for(DataAttributeType::GenericBitString(1)),
    );
    server.update_bit_string_from_int(&one, 1).unwrap();
    assert_eq!(current(&one), bit_string(7, &[0x80]));
    assert!(matches!(
        server.update_bit_string_from_int(&one, 2),
        Err(ServerError::TypeMismatch {
            actual: "integer wider than the attribute",
            ..
        })
    ));
    assert_eq!(current(&one), bit_string(7, &[0x80]));

    let thirteen = DataAttribute::new(
        "thirteen",
        FC::Cf,
        DataAttributeType::GenericBitString(13),
        TrgOps::NONE,
        MmsValue::default_for(DataAttributeType::GenericBitString(13)),
    );
    server
        .update_bit_string_from_int(&thirteen, 0x1000)
        .unwrap();
    assert_eq!(current(&thirteen), bit_string(3, &[0x80, 0x00]));
    server
        .update_bit_string_from_int(&thirteen, 0x0001)
        .unwrap();
    assert_eq!(current(&thirteen), bit_string(3, &[0x00, 0x08]));
}

/// A `Quality`, declared as at most 13 bits, takes an update of 1 to 13 bits
/// whatever length it holds, so a remote Write that shortened it does not lock
/// out a local 13-bit update; 16 bits and an empty string are rejected.
#[test]
fn quality_update_follows_the_declared_size() {
    let server = build_server();
    let model = server.model();
    let q = resolve_da(&model, "IED1LD0/CSWI1.Pos.q");
    // The state a remote Write of two bits leaves.
    *q.value.write().unwrap() = bit_string(6, &[0x80]);

    server.update_bit_string(&q, &[0xc0, 0x08], 3).unwrap();
    assert_eq!(current(&q), bit_string(3, &[0xc0, 0x08]));

    *q.value.write().unwrap() = bit_string(6, &[0x80]);
    server.update_bit_string_from_int(&q, 0x1000).unwrap();
    assert_eq!(current(&q), bit_string(3, &[0x80, 0x00]));

    for (data, padding) in [(&[0xffu8, 0xff][..], 0u8), (&[][..], 0)] {
        assert!(matches!(
            server.update_bit_string(&q, data, padding),
            Err(ServerError::TypeMismatch {
                actual: "BitString of another length",
                ..
            })
        ));
        assert_eq!(current(&q), bit_string(3, &[0x80, 0x00]));
    }

    server.update_bit_string(&q, &[0x40], 6).unwrap();
    assert_eq!(current(&q), bit_string(6, &[0x40]));
}

/// Registers an enabled unbuffered control block over one attribute.
fn watch(server: &IedServer, da: &DataAttribute, trg_ops: TriggerOptions) -> &'static str {
    let mms_path = "IED1LD0/LLN0$RP$urcb01";
    let mut ds = Dataset::new("LLN0$ds1");
    ds.push(DatasetEntry::new(
        format!("IED1LD0/CSWI1$ST$Pos${}", da.name),
        Arc::clone(&da.value),
    ));
    let rcb = Rcb::new("urcb01", "LLN0$ds1").with_trg_ops(trg_ops);
    server
        .register_urcb(ReportControl::new(mms_path, rcb), ds)
        .expect("register_urcb");

    let engine = server.reporting_engine();
    let engine_g = engine.lock().unwrap();
    let rc_arc = engine_g.get_rcb(mms_path).unwrap();
    let rc_g = rc_arc.lock().unwrap();
    let mut state = rc_g.state.lock().unwrap();
    state.rpt_ena = true;
    state.client_conn_id = Some(1);
    mms_path
}

/// Returns the pending snapshot and inclusion flag of the first entry, or
/// `None` when the control block was not triggered.
fn pending_entry(server: &IedServer, mms_path: &str) -> Option<(MmsValue, InclusionFlag)> {
    let engine = server.reporting_engine();
    let engine_g = engine.lock().unwrap();
    let rc_arc = engine_g.get_rcb(mms_path).unwrap();
    let rc_g = rc_arc.lock().unwrap();
    let state = rc_g.state.lock().unwrap();
    if !state.triggered {
        return None;
    }
    let pending = state.pending.as_ref()?;
    Some((pending.snapshot[0].clone()?, pending.inclusion_flags[0]))
}

/// A `dchg` attribute such as `stVal` triggers a data-change report.
#[test]
fn dbpos_update_triggers_dchg_report() {
    let server = build_server();
    let model = server.model();
    let st_val = resolve_da(&model, "IED1LD0/CSWI1.Pos.stVal");
    let mms_path = watch(&server, &st_val, TriggerOptions::DATA_CHANGED);

    server.update_bit_string_from_int(&st_val, 2).unwrap();

    let (value, flag) = pending_entry(&server, mms_path).expect("triggered");
    assert_eq!(value, bit_string(6, &[0x80]));
    assert!(flag.contains(InclusionFlag::VALUE_CHANGED));
}

/// A `qchg` attribute such as `q` triggers a quality-change report.
#[test]
fn quality_update_triggers_qchg_report() {
    let server = build_server();
    let model = server.model();
    let q = resolve_da(&model, "IED1LD0/CSWI1.Pos.q");
    let mms_path = watch(&server, &q, TriggerOptions::QUALITY_CHANGED);

    server.update_bit_string(&q, &[0x40, 0x00], 3).unwrap();

    let (value, flag) = pending_entry(&server, mms_path).expect("triggered");
    assert_eq!(value, bit_string(3, &[0x40, 0x00]));
    assert!(flag.contains(InclusionFlag::QUALITY_CHANGED));
}

/// A control block that triggers only on data change ignores a quality update.
#[test]
fn quality_update_skips_dchg_only_report() {
    let server = build_server();
    let model = server.model();
    let q = resolve_da(&model, "IED1LD0/CSWI1.Pos.q");
    let mms_path = watch(&server, &q, TriggerOptions::DATA_CHANGED);

    server.update_bit_string(&q, &[0x40, 0x00], 3).unwrap();

    assert!(pending_entry(&server, mms_path).is_none());
}
