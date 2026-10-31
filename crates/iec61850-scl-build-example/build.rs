//! Compiles `scl/demo.icd` into `OUT_DIR/model.rs` at build time.
//!
//! These few lines are all a user crate needs to turn an SCL or ICD file into
//! a `pub fn build_<IED>_model() -> IedModel`.

fn main() {
    // ied_name matches `<IED name="Demo">` in `scl/demo.icd`. It is only
    // required for a multi-IED `.scd`, and is shown here for illustration.
    iec61850_scl_build::compile_icd("scl/demo.icd")
        .out_file("model.rs")
        .ied_name("Demo")
        .compile()
        .expect("iec61850-scl-build: compile demo.icd failed");

    // The integration tests compare this generated model with the one the
    // runtime path builds from the same file.
    iec61850_scl_build::compile_icd("scl/settings.icd")
        .out_file("settings_model.rs")
        .compile()
        .expect("iec61850-scl-build: compile settings.icd failed");
}
