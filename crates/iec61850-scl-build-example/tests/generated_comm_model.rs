//! The model `build.rs` generates from `scl/comm.icd` carries the addressing of
//! the `<Communication>` section as the runtime path does: the connected
//! access points with their server addresses, and the `<GSE>` and `<SMV>`
//! addressing of the control blocks.

// The generated file brings `IedModel` into scope.
iec61850_scl::include_compiled_model!("comm_model.rs");

const COMM_ICD: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/scl/comm.icd");

fn runtime_model() -> IedModel {
    let xml = std::fs::read_to_string(COMM_ICD).expect("read comm.icd");
    let raw = iec61850_scl::parse_scl(&xml).expect("parse comm.icd");
    raw.resolve()
        .expect("resolve comm.icd")
        .build_model("Comm")
        .expect("build comm.icd")
}

#[test]
fn generated_model_matches_the_runtime_model() {
    let summary = iec61850_scl::summarize::summarize_model(&build_Comm_model());
    assert_eq!(
        summary,
        iec61850_scl::summarize::summarize_model(&runtime_model())
    );
    // The comparison covers the addressing: the summary carries it.
    assert!(summary.contains("ConnectedAP subNetwork=W01"), "{summary}");
    assert!(
        summary.contains("GSE address=MAC-Address=01-0C-CD-01-00-05"),
        "{summary}"
    );
    assert!(
        summary.contains("SMV address=MAC-Address=01-0C-CD-04-00-01"),
        "{summary}"
    );
}

#[test]
fn generated_addressing_equals_the_runtime_addressing() {
    let generated = build_Comm_model();
    let runtime = runtime_model();
    assert_eq!(generated.connected_aps, runtime.connected_aps);
    assert_eq!(generated.connected_aps.len(), 2);
    // The build script sorts control blocks by name, so they are matched by
    // name rather than by position.
    for name in ["gcbTrip", "gcbSpare"] {
        assert_eq!(
            generated.gse_address("LD0", name),
            runtime.gse_address("LD0", name),
            "{name}"
        );
    }
    assert_eq!(
        generated.lds[0].lns[0].svcbs[0].smv,
        runtime.lds[0].lns[0].svcbs[0].smv
    );

    let gse = generated
        .gse_address("LD0", "gcbTrip")
        .expect("GSE of gcbTrip");
    assert_eq!(gse.address.app_id(), Some(0x3a01));
    assert_eq!((gse.min_time_ms, gse.max_time_ms), (Some(8), Some(2000)));
    assert_eq!(generated.gse_address("LD0", "gcbSpare"), None);
    assert_eq!(
        generated
            .smv_address("LD0", "svcbMeas")
            .and_then(|a| a.vlan_id()),
        Some(5)
    );
}
