//! The model `build.rs` generates from `scl/schema.icd` matches the one the
//! runtime path builds from the same file: the member order of data objects
//! whose DOType interleaves sub-objects and attributes, the basic types of
//! IEC 61850-6 §9.5.4.2, and the report and log control block schema.

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
            iec61850_scl::__rt::DoChild::Da(da) => da.name.clone(),
            iec61850_scl::__rt::DoChild::SubDo(sd) => sd.name.clone(),
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
    let lcb = &lln0.lcbs[0];
    assert!(lcb.log_ena);
    assert!(!lcb.reason_code);
    assert_eq!(lcb.intg_pd_ms, 2000);
}
