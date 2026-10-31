//! The model `build.rs` generates from `scl/settings.icd` matches the one the
//! runtime path builds from the same file, including the FC=SG view of every
//! FC=SE setting, below a sub-object too, the `<DAI>` values that view starts
//! at, and a data set naming settings under either constraint.

// The generated file brings `DataAttribute`, `IedModel`, `MmsValue` and `FC`
// into scope.
iec61850_scl::include_compiled_model!("settings_model.rs");

const SETTINGS_ICD: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/scl/settings.icd");

fn runtime_model() -> IedModel {
    let xml = std::fs::read_to_string(SETTINGS_ICD).expect("read settings.icd");
    let raw = iec61850_scl::parse_scl(&xml).expect("parse settings.icd");
    raw.resolve()
        .expect("resolve settings.icd")
        .build_model("Settings")
        .expect("build settings.icd")
}

fn setting<'a>(model: &'a IedModel, do_name: &str, fc: FC) -> Vec<&'a DataAttribute> {
    let ln = model
        .ld_by_inst("LD0")
        .and_then(|ld| ld.ln_by_name("PTOC1"))
        .expect("PTOC1");
    ln.do_by_name(do_name)
        .expect("data object")
        .children_with_fc(fc)
        .collect()
}

#[test]
fn generated_model_matches_the_runtime_model() {
    let generated = build_Settings_model();
    assert_eq!(
        iec61850_scl::summarize::summarize_model(&generated),
        iec61850_scl::summarize::summarize_model(&runtime_model())
    );
}

#[test]
fn generated_model_carries_the_sg_view_of_each_se_setting() {
    let m = build_Settings_model();
    for fc in [FC::Se, FC::Sg] {
        let set_val = setting(&m, "OpDlTmms", fc);
        assert_eq!(set_val.len(), 1, "{fc:?}");
        assert_eq!(set_val[0].snapshot(), MmsValue::Integer(250), "{fc:?}");
        let mag = setting(&m, "StrVal", fc);
        assert_eq!(
            mag[0].child_by_name("f").expect("f").snapshot(),
            MmsValue::Float32(1.5),
            "{fc:?}"
        );
    }
    let ln = m
        .ld_by_inst("LD0")
        .and_then(|ld| ld.ln_by_name("PTOC1"))
        .expect("PTOC1");
    let sub = match ln.do_by_name("TmSet").and_then(|d| d.child_by_name("tm")) {
        Some(iec61850_scl::__rt::DoChild::SubDo(s)) => s,
        other => panic!("TmSet.tm: {other:?}"),
    };
    for fc in [FC::Se, FC::Sg] {
        let set_val: Vec<_> = sub.children_with_fc(fc).collect();
        assert_eq!(set_val.len(), 1, "{fc:?}");
        assert_eq!(set_val[0].snapshot(), MmsValue::Integer(9), "{fc:?}");
    }
    assert!(setting(&m, "TmMult", FC::Se).is_empty());
    assert_eq!(setting(&m, "MinOpTmms", FC::Sg).len(), 1);
    assert_eq!(setting(&m, "MinOpTmms", FC::Se).len(), 1);
}
