//! Stage 2 bounds how many model nodes an IED or a type expands to, so a
//! small file whose types fan out at every level fails at once instead of
//! taking exponential time and memory in the model builder.

use iec61850_scl::ResolveOptions;

/// An IED whose LLN0 has one data object `D` of a DOType holding attribute
/// `a` of DAType `T0`; `T0` to `T{levels-1}` each hold two structure
/// attributes of the next type, and the last holds two floats.
fn fan_out(levels: usize) -> String {
    let mut t = String::new();
    for i in 0..levels {
        if i + 1 < levels {
            t.push_str(&format!(
                r#"<DAType id="T{i}"><BDA name="l" bType="Struct" type="T{n}"/><BDA name="r" bType="Struct" type="T{n}"/></DAType>"#,
                n = i + 1
            ));
        } else {
            t.push_str(&format!(
                r#"<DAType id="T{i}"><BDA name="l" bType="FLOAT32"/><BDA name="r" bType="FLOAT32"/></DAType>"#
            ));
        }
    }
    format!(
        r#"<SCL>
  <IED name="IED1"><AccessPoint name="AP1"><Server><LDevice inst="LD0">
    <LN0 inst="" lnClass="LLN0" lnType="LLN0_T"/>
  </LDevice></Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="D" type="D_T"/></LNodeType>
    <DOType id="D_T" cdc="SPS"><DA name="a" fc="ST" bType="Struct" type="T0"/></DOType>
    {t}
  </DataTypeTemplates>
</SCL>"#
    )
}

fn options(max: u64) -> ResolveOptions {
    let mut o = ResolveOptions::default();
    o.max_expanded_nodes = max;
    o
}

/// Twenty levels of two branches fail in stage 2 with the exact node count of
/// the expansion, 2^21 - 2 for `T0`, which stage 2 can only report by
/// counting each shared type once rather than expanding it.
#[test]
fn twenty_levels_of_two_branches_are_counted_not_expanded() {
    let xml = fan_out(20);
    let err = iec61850_scl::parse_scl(&xml)
        .expect("parse")
        .resolve()
        .expect_err("the expansion exceeds the default limit");
    assert!(
        err.to_string()
            .contains("DAType `T0` expands to 2097150 model nodes, more than the limit of 1000000"),
        "unexpected error: {err}"
    );
}

/// The limit is configurable, and the count includes the logical node, the
/// data object and every attribute at every level.
#[test]
fn limit_is_configurable_and_counts_every_node() {
    // Three levels: T2 holds 2 leaves, T1 holds 2 × (1 + 2) = 6 nodes, T0
    // holds 2 × (1 + 6) = 14; the IED adds LLN0, D and a: 17 nodes.
    let xml = fan_out(3);
    let resolve = |max| {
        iec61850_scl::parse_scl(&xml)
            .expect("parse")
            .resolve_with(&options(max))
    };
    assert!(resolve(17).is_ok());
    let err = resolve(16).expect_err("one node over the limit");
    assert!(err.to_string().contains("IED `IED1`"), "{err}");
    let model = resolve(17)
        .unwrap()
        .build_model("IED1")
        .expect("build within the limit");
    let mut nodes = 0;
    model.walk(|n| {
        if !matches!(n, iec61850_model::ModelNode::Ld(_)) {
            nodes += 1;
        }
    });
    assert_eq!(nodes, 17);
}

/// A sub-object counts as a node of its own, besides the attributes below it.
#[test]
fn sub_objects_count_as_nodes() {
    // LLN0, D, the sub-object s and its attribute v: 4 nodes.
    let xml = fan_out(1).replace(
        r#"<DOType id="D_T" cdc="SPS"><DA name="a" fc="ST" bType="Struct" type="T0"/></DOType>"#,
        r#"<DOType id="D_T" cdc="WYE"><SDO name="s" type="S_T"/></DOType>
           <DOType id="S_T" cdc="CMV"><DA name="v" fc="MX" bType="FLOAT32"/></DOType>"#,
    );
    let resolve = |max| {
        iec61850_scl::parse_scl(&xml)
            .expect("parse")
            .resolve_with(&options(max))
    };
    assert!(resolve(4).is_ok());
    assert!(resolve(3).is_err());
}

/// A type that exceeds the limit is rejected even when no IED references it.
#[test]
fn unreferenced_type_over_the_limit_is_rejected() {
    let xml = fan_out(4).replace(
        r#"<DOType id="D_T" cdc="SPS"><DA name="a" fc="ST" bType="Struct" type="T0"/></DOType>"#,
        r#"<DOType id="D_T" cdc="SPS"><DA name="a" fc="ST" bType="BOOLEAN"/></DOType>"#,
    );
    let err = iec61850_scl::parse_scl(&xml)
        .expect("parse")
        .resolve_with(&options(10))
        .expect_err("T0 expands to 30 nodes");
    assert!(err.to_string().contains("DAType `T0`"), "{err}");
}

/// Control: an ordinary file stays far below the default limit.
#[test]
fn ordinary_file_resolves_with_the_default_limit() {
    let xml = fan_out(5);
    assert!(iec61850_scl::parse_scl(&xml).unwrap().resolve().is_ok());
}
