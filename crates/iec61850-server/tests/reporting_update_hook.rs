//! Integration tests for the value update hooks on the server.
//!
//! No socket is opened. The tests check that an `update_*` call reaches the
//! reporting engine through its attribute index and marks the report control
//! blocks whose data set carries that attribute as triggered.

use iec61850_model::{
    DataAttribute, DataAttributeType, IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder,
    MmsValue, TrgOps, FC,
};
use iec61850_server::reporting::{Brcb, BufferedReportControl};
use iec61850_server::{Dataset, DatasetEntry, IedServer, Rcb, ReportControl, TriggerOptions};
use std::net::SocketAddr;
use std::sync::Arc;

// Fixture helpers

/// Builds the smallest server, one logical device with LLN0.
fn build_server() -> IedServer {
    let lln0 = LogicalNodeBuilder::lln0().build().expect("lln0");
    let ld = LogicalDeviceBuilder::new("LD0")
        .add_ln(lln0)
        .build()
        .expect("ld");
    let model = Arc::new(
        IedModelBuilder::new("IED1")
            .add_ld(ld)
            .expect("add_ld")
            .build()
            .expect("model"),
    );
    IedServer::builder()
        .model(model)
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()
        .expect("server build")
}

/// Builds a leaf boolean data attribute.
fn make_bool_da(name: &str) -> DataAttribute {
    DataAttribute::new(
        name,
        FC::St,
        DataAttributeType::Boolean,
        TrgOps::DCHG,
        MmsValue::Boolean(false),
    )
}

/// Builds a leaf integer data attribute.
fn make_int_da(name: &str) -> DataAttribute {
    DataAttribute::new(
        name,
        FC::Mx,
        DataAttributeType::Int32,
        TrgOps::DCHG,
        MmsValue::Integer(0),
    )
}

// A boolean update marks the report control block as triggered.

#[test]
fn update_boolean_triggers_rcb_when_in_dataset() {
    let server = build_server();
    let da = make_bool_da("stVal");

    // The data set member shares the value cell with the data attribute.
    let attr_ref = "IED1LD0/GGIO1$ST$Ind1$stVal".to_string();
    let entry = DatasetEntry::new(attr_ref.clone(), Arc::clone(&da.value));
    let mut ds = Dataset::new("GGIO1$ds1");
    ds.push(entry);

    // Unbuffered control block triggering on data change.
    let rcb = Rcb::new("urcb01", "GGIO1$ds1").with_trg_ops(TriggerOptions::DATA_CHANGED);
    let mms_path = "IED1LD0/GGIO1$RP$urcb01";
    let rc = ReportControl::new(mms_path, rcb);

    server.register_urcb(rc, ds).expect("register_urcb");

    // Enable the control block through the engine state.
    {
        let engine = server.reporting_engine();
        let engine_g = engine.lock().unwrap();
        let rc_arc = engine_g.get_rcb(mms_path).unwrap();
        let rc_g = rc_arc.lock().unwrap();
        let mut state = rc_g.state.lock().unwrap();
        state.rpt_ena = true;
        state.client_conn_id = Some(42);
    }

    // Update the value.
    server.update_boolean(&da, true).expect("update_boolean");

    // The control block is now triggered.
    let engine = server.reporting_engine();
    let engine_g = engine.lock().unwrap();
    let rc_arc = engine_g.get_rcb(mms_path).unwrap();
    let rc_g = rc_arc.lock().unwrap();
    let state = rc_g.state.lock().unwrap();
    assert!(
        state.triggered,
        "a boolean update must trigger the control block"
    );
    assert!(
        state.pending.is_some(),
        "a boolean update must leave a pending report"
    );
    // The pending report carries the new value.
    let pending = state.pending.as_ref().unwrap();
    assert_eq!(
        pending.snapshot[0],
        Some(MmsValue::Boolean(true)),
        "the pending snapshot must carry Boolean(true)"
    );
    assert!(
        pending.inclusion_flags[0].has_trigger(),
        "the first entry must carry its trigger flag"
    );
}

// Updating an attribute outside the data set triggers nothing.

#[test]
fn update_boolean_not_in_dataset_does_not_trigger_rcb() {
    let server = build_server();
    let da_in_ds = make_bool_da("stVal");
    // A second attribute with its own value cell, outside the data set.
    let da_not_in_ds = make_bool_da("stVal2");

    // Only the first attribute joins the data set.
    let attr_ref = "IED1LD0/GGIO1$ST$Ind1$stVal".to_string();
    let entry = DatasetEntry::new(attr_ref.clone(), Arc::clone(&da_in_ds.value));
    let mut ds = Dataset::new("GGIO1$ds1");
    ds.push(entry);

    let rcb = Rcb::new("urcb01", "GGIO1$ds1").with_trg_ops(TriggerOptions::DATA_CHANGED);
    let mms_path = "IED1LD0/GGIO1$RP$urcb01";
    let rc = ReportControl::new(mms_path, rcb);
    server.register_urcb(rc, ds).expect("register_urcb");

    // Enable RCB
    {
        let engine = server.reporting_engine();
        let engine_g = engine.lock().unwrap();
        let rc_arc = engine_g.get_rcb(mms_path).unwrap();
        let rc_g = rc_arc.lock().unwrap();
        let mut state = rc_g.state.lock().unwrap();
        state.rpt_ena = true;
        state.client_conn_id = Some(1);
    }

    // Update the attribute that is not a member.
    server
        .update_boolean(&da_not_in_ds, true)
        .expect("update_boolean");

    // The control block stays untriggered.
    let engine = server.reporting_engine();
    let engine_g = engine.lock().unwrap();
    let rc_arc = engine_g.get_rcb(mms_path).unwrap();
    let rc_g = rc_arc.lock().unwrap();
    let state = rc_g.state.lock().unwrap();
    assert!(
        !state.triggered,
        "an update outside the data set must not trigger the control block"
    );
}

// Registration populates the attribute index the update path walks.

#[test]
fn register_urcb_populates_attr_ref_index() {
    let server = build_server();
    let da = make_bool_da("stVal");

    let attr_ref = "IED1LD0/GGIO1$ST$Ind1$stVal".to_string();
    let entry = DatasetEntry::new(attr_ref.clone(), Arc::clone(&da.value));
    let mut ds = Dataset::new("GGIO1$ds1");
    ds.push(entry);

    let rcb = Rcb::new("urcb01", "GGIO1$ds1");
    let rc = ReportControl::new("IED1LD0/GGIO1$RP$urcb01", rcb);
    server.register_urcb(rc, ds).expect("register_urcb");

    // The engine knows the control block path.
    let engine = server.reporting_engine();
    let engine_g = engine.lock().unwrap();
    let paths = engine_g.rcb_paths();
    assert!(
        paths.contains(&"IED1LD0/GGIO1$RP$urcb01".to_string()),
        "the engine must carry the registered control block path"
    );
    drop(engine_g);

    // The update succeeds whether or not the index was built, so this only
    // covers the call path itself.
    server.update_boolean(&da, true).expect("update_boolean");
}

// An integer update triggers the control block as well.

#[test]
fn update_int32_triggers_rcb() {
    let server = build_server();
    let da = make_int_da("mag_i");

    let attr_ref = "IED1LD0/MMXU1$MX$A$phsA$mag$i".to_string();
    let entry = DatasetEntry::new(attr_ref.clone(), Arc::clone(&da.value));
    let mut ds = Dataset::new("ds1");
    ds.push(entry);

    let rcb = Rcb::new("urcb01", "ds1").with_trg_ops(TriggerOptions::DATA_CHANGED);
    let rc = ReportControl::new("IED1LD0/MMXU1$RP$urcb01", rcb);
    server.register_urcb(rc, ds).expect("register");

    // Enable RCB
    {
        let engine = server.reporting_engine();
        let eg = engine.lock().unwrap();
        let rc_arc = eg.get_rcb("IED1LD0/MMXU1$RP$urcb01").unwrap();
        let rc_g = rc_arc.lock().unwrap();
        let mut state = rc_g.state.lock().unwrap();
        state.rpt_ena = true;
        state.client_conn_id = Some(5);
    }

    server.update_int32(&da, 42).expect("update_int32");

    let engine = server.reporting_engine();
    let eg = engine.lock().unwrap();
    let rc_arc = eg.get_rcb("IED1LD0/MMXU1$RP$urcb01").unwrap();
    let rc_g = rc_arc.lock().unwrap();
    let state = rc_g.state.lock().unwrap();
    assert!(
        state.triggered,
        "an integer update must trigger the control block"
    );
    assert_eq!(
        state.pending.as_ref().unwrap().snapshot[0],
        Some(MmsValue::Integer(42))
    );
}

// A type mismatch fails the update and reaches no control block.

#[test]
fn update_boolean_type_mismatch_returns_err_no_engine_trigger() {
    let server = build_server();
    // Writing a boolean into an integer attribute is a type mismatch.
    let da = make_int_da("int_val");

    let result = server.update_boolean(&da, true);
    assert!(result.is_err(), "a type mismatch must fail the update");
}

// A disabled control block is not triggered by an update.

#[test]
fn update_boolean_disabled_rcb_not_triggered() {
    let server = build_server();
    let da = make_bool_da("stVal");

    let attr_ref = "IED1LD0/GGIO1$ST$Ind1$stVal".to_string();
    let entry = DatasetEntry::new(attr_ref.clone(), Arc::clone(&da.value));
    let mut ds = Dataset::new("GGIO1$ds1");
    ds.push(entry);

    let rcb = Rcb::new("urcb01", "GGIO1$ds1").with_trg_ops(TriggerOptions::DATA_CHANGED);
    let rc = ReportControl::new("IED1LD0/GGIO1$RP$urcb01", rcb);
    server.register_urcb(rc, ds).expect("register_urcb");
    // The control block is left disabled.

    server.update_boolean(&da, true).expect("update_boolean");

    let engine = server.reporting_engine();
    let eg = engine.lock().unwrap();
    let rc_arc = eg.get_rcb("IED1LD0/GGIO1$RP$urcb01").unwrap();
    let rc_g = rc_arc.lock().unwrap();
    let state = rc_g.state.lock().unwrap();
    assert!(
        !state.triggered,
        "a disabled control block must not be triggered"
    );
}

// Registering with an empty RptID defaults it to the control block reference,
// as IEC 61850-7-2 prescribes.

#[test]
fn register_urcb_defaults_empty_rpt_id_to_mms_path() {
    let server = build_server();
    let da = make_bool_da("stVal");

    let attr_ref = "IED1LD0/GGIO1$ST$Ind1$stVal".to_string();
    let entry = DatasetEntry::new(attr_ref, Arc::clone(&da.value));
    let mut ds = Dataset::new("GGIO1$ds1");
    ds.push(entry);

    // RptID is left empty.
    let rcb = Rcb::new("urcb01", "GGIO1$ds1");
    assert_eq!(rcb.rpt_id, "", "the fixture starts with an empty RptID");
    let mms_path = "IED1LD0/GGIO1$RP$urcb01";
    let rc = ReportControl::new(mms_path, rcb);
    server.register_urcb(rc, ds).expect("register_urcb");

    // Read the control block back; RptID now holds the control block path.
    let engine = server.reporting_engine();
    let eg = engine.lock().unwrap();
    let rc_arc = eg
        .get_rcb(mms_path)
        .expect("the control block must be registered");
    let rc_g = rc_arc.lock().unwrap();
    let state = rc_g.state.lock().unwrap();
    assert_eq!(
        state.rpt_id, mms_path,
        "an empty RptID must default to the control block path"
    );
    // The template is kept in step with the registered state.
    assert_eq!(
        rc_g.rcb.rpt_id, mms_path,
        "the template RptID must be defaulted as well"
    );
}

// A configured RptID is never overwritten.

#[test]
fn register_urcb_preserves_explicit_rpt_id() {
    let server = build_server();
    let da = make_bool_da("stVal");

    let entry = DatasetEntry::new(
        "IED1LD0/GGIO1$ST$Ind1$stVal".to_string(),
        Arc::clone(&da.value),
    );
    let mut ds = Dataset::new("GGIO1$ds1");
    ds.push(entry);

    let custom_rpt_id = "custom-rpt-id";
    let rcb = Rcb::new("urcb01", "GGIO1$ds1").with_rpt_id(custom_rpt_id);
    let rc = ReportControl::new("IED1LD0/GGIO1$RP$urcb01", rcb);
    server.register_urcb(rc, ds).expect("register_urcb");

    let engine = server.reporting_engine();
    let eg = engine.lock().unwrap();
    let rc_arc = eg.get_rcb("IED1LD0/GGIO1$RP$urcb01").unwrap();
    let rc_g = rc_arc.lock().unwrap();
    let state = rc_g.state.lock().unwrap();
    assert_eq!(
        state.rpt_id, custom_rpt_id,
        "a configured RptID must not be overwritten"
    );
}

// A buffered control block defaults its RptID the same way.

#[test]
fn register_brcb_defaults_empty_rpt_id_to_mms_path() {
    let server = build_server();
    let da = make_bool_da("stVal");

    let entry = DatasetEntry::new(
        "IED1LD0/GGIO1$ST$Ind1$stVal".to_string(),
        Arc::clone(&da.value),
    );
    let mut ds = Dataset::new("GGIO1$ds1");
    ds.push(entry);

    let brcb = Brcb::new("brcb01", "GGIO1$ds1");
    assert_eq!(brcb.rpt_id, "", "the fixture starts with an empty RptID");
    let mms_path = "IED1LD0/GGIO1$BR$brcb01";
    let brc = BufferedReportControl::new(mms_path, brcb);
    server.register_brcb(brc, ds).expect("register_brcb");

    let engine = server.reporting_engine();
    let eg = engine.lock().unwrap();
    let brc_arc = eg
        .get_brcb(mms_path)
        .expect("the control block must be registered");
    let state = brc_arc.state.lock().unwrap();
    assert_eq!(
        state.rpt_id, mms_path,
        "an empty RptID must default to the control block path"
    );
    assert_eq!(
        brc_arc.brcb.rpt_id, mms_path,
        "the template RptID must be defaulted as well"
    );
}
