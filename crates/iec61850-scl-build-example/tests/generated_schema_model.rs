//! The model `build.rs` generates from `scl/schema.icd` matches the one the
//! runtime path builds from the same file: the member order of data objects
//! whose DOType interleaves sub-objects and attributes, the basic types of
//! IEC 61850-6 §9.5.4.2, the report and log control block schema, and the
//! setting group values of settings declared under FC=SE, FC=SG or both.

// The generated file brings `DataObject`, `DoChild`, `IedModel` and
// `DataAttributeType` into scope.
iec61850_scl::include_compiled_model!("schema_model.rs");

const SCHEMA_ICD: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/scl/schema.icd");

fn runtime_model() -> IedModel {
    let xml = std::fs::read_to_string(SCHEMA_ICD).expect("read schema.icd");
    let raw = iec61850_scl::parse_scl(&xml).expect("parse schema.icd");
    raw.resolve()
        .expect("resolve schema.icd")
        .build_model("Schema")
        .expect("build schema.icd")
}

fn child_names(model: &IedModel, do_name: &str) -> Vec<String> {
    model
        .ld_by_inst("LD0")
        .and_then(|ld| ld.ln_by_name("MSQI1"))
        .and_then(|ln| ln.do_by_name(do_name))
        .expect("data object")
        .children
        .iter()
        .map(|c| match c {
            iec61850_scl::__private::DoChild::Da(da) => da.name.clone(),
            iec61850_scl::__private::DoChild::SubDo(sd) => sd.name.clone(),
        })
        .collect()
}

#[test]
fn generated_model_matches_the_runtime_model() {
    assert_eq!(
        iec61850_scl::summarize::summarize_model(&build_Schema_model()),
        iec61850_scl::summarize::summarize_model(&runtime_model())
    );
}

#[test]
fn generated_members_follow_the_declared_order() {
    let generated = build_Schema_model();
    assert_eq!(
        child_names(&generated, "SeqA"),
        ["c1", "q", "c2", "c3", "seqT"]
    );
    assert_eq!(
        child_names(&generated, "Raw"),
        ["i24", "sub", "oct6", "oct16", "svOpts", "logOpts"]
    );
    assert_eq!(
        child_names(&generated, "SeqA"),
        child_names(&runtime_model(), "SeqA")
    );
}

#[test]
fn generated_control_blocks_carry_the_schema() {
    let generated = build_Schema_model();
    let lln0 = &generated.lds[0].lns[0];
    assert_eq!(
        lln0.rcbs[0].instance_names(),
        ["brcbSeq01", "brcbSeq02", "brcbSeq03"]
    );
    // `<TrgOps dchg="true" period="true"/>` leaves `gi` at its default, true.
    assert_eq!(
        lln0.rcbs[0].trg_ops,
        TrgOps::DCHG | TrgOps::INTEGRITY | TrgOps::GI
    );
    assert_eq!(lln0.rcbs[0].buf_tm_ms, 50);
    assert_eq!(lln0.rcbs[0].intg_pd_ms, 1000);
    assert_eq!(
        lln0.rcbs[0].opt_flds,
        iec61850_scl::__private::OptFlds::SEQ_NUM
            | iec61850_scl::__private::OptFlds::ENTRY_ID
            | iec61850_scl::__private::OptFlds::BUFFER_OVERFLOW
    );
    let lcb = &lln0.lcbs[0];
    assert!(lcb.log_ena);
    assert!(!lcb.reason_code);
    assert_eq!(lcb.intg_pd_ms, 2000);
    assert_eq!(lcb.buf_tm_ms, 25);
    assert_eq!(lcb.trg_ops, TrgOps::DCHG | TrgOps::INTEGRITY);
}

#[test]
fn generated_settings_carry_every_group_value() {
    let generated = build_Schema_model();
    let ln = generated.lds[0].ln_by_name("PTOC1").expect("PTOC1");
    let setting = |do_name: &str, name: &str, fc: FC| match ln
        .do_by_name(do_name)
        .expect("data object")
        .child_by_name(name, Some(fc))
    {
        Some(iec61850_scl::__private::DoChild::Da(da)) => da,
        other => panic!("{do_name}.{name}[{fc}]: {other:?}"),
    };
    for fc in [FC::Se, FC::Sg] {
        let op = setting("OpDlTmms", "setVal", fc);
        assert_eq!(op.snapshot(), MmsValue::Integer(100), "{fc}");
        assert_eq!(op.sgroup_values, [(2, MmsValue::Integer(200))], "{fc}");
        let f = setting("StrVal", "setMag", fc)
            .child_by_name("f")
            .expect("f");
        assert_eq!(
            f.sgroup_values,
            [(1, MmsValue::Float32(1.5)), (2, MmsValue::Float32(2.5))],
            "{fc}"
        );
    }
}

#[test]
fn generated_structured_leaves_take_the_trigger_options_of_the_attribute() {
    let generated = build_Schema_model();
    let ln = generated.lds[0].ln_by_name("MSQI1").expect("MSQI1");
    let q = match ln
        .do_by_name("SeqA")
        .expect("SeqA")
        .child_by_name("q", None)
    {
        Some(iec61850_scl::__private::DoChild::Da(da)) => da,
        other => panic!("q: {other:?}"),
    };
    assert_eq!(q.trg_ops, TrgOps::QCHG);
    let c1 = match ln
        .do_by_name("SeqA")
        .expect("SeqA")
        .child_by_name("c1", None)
    {
        Some(iec61850_scl::__private::DoChild::SubDo(sd)) => sd,
        other => panic!("c1: {other:?}"),
    };
    let cval = match c1.child_by_name("cVal", None) {
        Some(iec61850_scl::__private::DoChild::Da(da)) => da,
        other => panic!("cVal: {other:?}"),
    };
    assert_eq!(cval.trg_ops, TrgOps::DCHG);
    let f = cval
        .child_by_name("mag")
        .and_then(|mag| mag.child_by_name("f"))
        .expect("cVal.mag.f");
    assert_eq!(f.trg_ops, TrgOps::DCHG);
}
