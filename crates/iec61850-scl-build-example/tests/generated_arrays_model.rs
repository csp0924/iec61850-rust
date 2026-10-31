//! The model `build.rs` generates from `scl/arrays.icd` matches the one the
//! runtime path builds from the same file: arrays of data attributes, of
//! nested attributes and of sub-data-objects, element counts given by number,
//! by reference to a type value and by reference to an instance value, and
//! instance values aimed at single elements.

// The generated file brings `DataObject`, `IedModel` and `MmsValue` into
// scope.
iec61850_scl::include_compiled_model!("arrays_model.rs");

use iec61850_scl::__private::DoChild;

const ARRAYS_ICD: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/scl/arrays.icd");

fn runtime_model() -> IedModel {
    let xml = std::fs::read_to_string(ARRAYS_ICD).expect("read arrays.icd");
    let raw = iec61850_scl::parse_scl(&xml).expect("parse arrays.icd");
    raw.resolve()
        .expect("resolve arrays.icd")
        .build_model("Arrays")
        .expect("build arrays.icd")
}

fn data_object<'a>(model: &'a IedModel, ln: &str, name: &str) -> &'a DataObject {
    model
        .ld_by_inst("LD0")
        .and_then(|ld| ld.ln_by_name(ln))
        .and_then(|ln| ln.do_by_name(name))
        .expect("data object")
}

fn attribute_value(d: &DataObject, name: &str) -> MmsValue {
    match d.child_by_name(name, None) {
        Some(DoChild::Da(da)) => da.snapshot(),
        _ => panic!("{name} is not a data attribute"),
    }
}

#[test]
fn generated_model_matches_the_runtime_model() {
    let summary = iec61850_scl::summarize::summarize_model(&build_Arrays_model());
    assert_eq!(
        summary,
        iec61850_scl::summarize::summarize_model(&runtime_model())
    );
    assert!(summary.contains("kind=array(4)"), "{summary}");
}

#[test]
fn generated_arrays_carry_their_element_values() {
    let model = build_Arrays_model();
    let arr = data_object(&model, "GGIO1", "Arr");
    assert_eq!(
        attribute_value(arr, "hstVal"),
        MmsValue::Array(vec![
            MmsValue::Integer(0),
            MmsValue::Integer(7),
            MmsValue::Integer(0),
        ])
    );
    assert_eq!(
        attribute_value(arr, "crvPts"),
        MmsValue::Array(vec![
            MmsValue::Structure(vec![
                MmsValue::Float32(0.0),
                MmsValue::Float32(0.0)
            ]);
            2
        ])
    );
    // A count naming an attribute the type gives no value takes the instance
    // value.
    assert_eq!(
        attribute_value(arr, "ext"),
        MmsValue::Array(vec![MmsValue::Integer(0), MmsValue::Integer(6)])
    );
    let ha = data_object(&model, "MHAI1", "HA");
    let Some(DoChild::SubDo(har)) = ha.child_by_name("phsAHar", None) else {
        panic!("phsAHar is a sub-object");
    };
    assert_eq!(har.array_count, Some(4));
    let c_val = attribute_value(har.element(3).expect("element 3"), "cVal");
    assert_eq!(
        c_val,
        MmsValue::Structure(vec![MmsValue::Structure(vec![MmsValue::Float32(3.5)])])
    );
}
