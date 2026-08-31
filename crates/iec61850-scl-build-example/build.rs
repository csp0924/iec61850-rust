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
}
