//! Control objects registered from the model `build.rs` generates from
//! `scl/demo.icd`: its one controllable data object, `CSWI1.Pos`, declares no
//! `ctlModel`, so no control model is known for it and nothing is registered.

// The generated file brings `IedModel` and the model types into scope.
iec61850_scl::include_compiled_model!("model.rs");

use iec61850_server::control::ControlObjectsRegistry;

#[test]
fn a_data_object_without_ctl_model_is_not_registered() {
    let model = build_Demo_model();
    let registry = ControlObjectsRegistry::new();
    assert_eq!(registry.register_from_model(&model), 0);
    assert!(registry.is_empty());
}
