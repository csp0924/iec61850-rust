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

/// An IED whose LLN0 data object `D` holds the DOType body `body`, with the
/// DAType `P` of two floats available to it.
fn with_do_type(body: &str) -> String {
    format!(
        r#"<SCL>
  <IED name="IED1"><AccessPoint name="AP1"><Server><LDevice inst="LD0">
    <LN0 inst="" lnClass="LLN0" lnType="LLN0_T"/>
  </LDevice></Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="D" type="D_T"/></LNodeType>
    <DOType id="D_T" cdc="SPS">{body}</DOType>
    <DOType id="E_T" cdc="SPS"><DA name="v" fc="ST" bType="Struct" type="P"/></DOType>
    <DAType id="P"><BDA name="x" bType="FLOAT32"/><BDA name="y" bType="FLOAT32"/></DAType>
  </DataTypeTemplates>
</SCL>"#
    )
}

/// A pathological `count` is counted, one node for the array and one subtree
/// per element, and rejected in stage 2 before any element is built: the
/// largest count on a structure, a count on a sub-object, and a count that
/// names an attribute.
#[test]
fn pathological_counts_are_counted_not_built() {
    for (body, kind, nodes) in [
        (
            r#"<DA name="a" fc="ST" bType="Struct" type="P" count="4294967295"/>"#,
            "DOType `D_T`",
            // 1 + 4294967295 * (1 + 2)
            12_884_901_886u64,
        ),
        (
            r#"<SDO name="s" type="E_T" count="500000"/>"#,
            "DOType `D_T`",
            // 1 + 500000 * (1 + 1 + 2)
            2_000_001,
        ),
        (
            r#"<DA name="a" fc="ST" bType="INT32" count="n"/><DA name="n" fc="CF" bType="INT32U"><Val>3000000</Val></DA>"#,
            "DOType `D_T`",
            // 1 + 3000000 * 1, plus the attribute `n`
            3_000_002,
        ),
    ] {
        let err = iec61850_scl::parse_scl(&with_do_type(body))
            .expect("parse")
            .resolve()
            .expect_err(body);
        assert!(
            err.to_string().contains(&format!(
                "{kind} expands to {nodes} model nodes, more than the limit of 1000000"
            )),
            "{body}: {err}"
        );
    }
}

/// Control: an array within the limit resolves, and its elements count
/// against a lower limit exactly.
#[test]
fn array_elements_count_against_the_limit() {
    let xml = with_do_type(r#"<DA name="a" fc="ST" bType="Struct" type="P" count="10"/>"#);
    // D_T: 1 + 10 * 3 = 31; LLN0: 1 + 31 = 32; the IED adds LLN0 itself: 33.
    iec61850_scl::parse_scl(&xml)
        .expect("parse")
        .resolve_with(&options(33))
        .expect("33 nodes fit a limit of 33");
    let err = iec61850_scl::parse_scl(&xml)
        .expect("parse")
        .resolve_with(&options(32))
        .expect_err("33 nodes exceed a limit of 32");
    assert!(
        err.to_string()
            .contains("expands to at least 33 model nodes"),
        "{err}"
    );
}

/// An IED of LLN0 and three GGIO logical nodes, each with the data object `D`
/// whose array `a` takes its element count from the instance value of `n`,
/// which every instance sets to `count`.
fn instance_counts(count: u32) -> String {
    let doi = format!(r#"<DOI name="D"><DAI name="n"><Val>{count}</Val></DAI></DOI>"#);
    let lns: String = (1..=3)
        .map(|i| format!(r#"<LN lnClass="GGIO" inst="{i}" lnType="T_T">{doi}</LN>"#))
        .collect();
    format!(
        r#"<SCL>
  <IED name="IED1"><AccessPoint name="AP1"><Server><LDevice inst="LD0">
    <LN0 inst="" lnClass="LLN0" lnType="T_T">{doi}</LN0>
    {lns}
  </LDevice></Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="T_T" lnClass="GGIO"><DO name="D" type="D_T"/></LNodeType>
    <DOType id="D_T" cdc="HST">
      <DA name="a" fc="ST" bType="INT32" count="n"/>
      <DA name="n" fc="CF" bType="INT16U"/>
    </DOType>
  </DataTypeTemplates>
</SCL>"#
    )
}

/// The node count of an IED takes the element counts its instances give: four
/// logical nodes each within the limit on their own, whose sum is above it,
/// are rejected in stage 2. The walk stops at the logical node that takes the
/// running total past the limit, which the error reports.
#[test]
fn instance_counts_add_up_against_the_limit_of_the_ied() {
    // Each logical node: itself, D, the array a of 300 elements and n.
    // 1 + 1 + (1 + 300) + 1 = 304; the running totals are 304, 608, 912 and
    // 1216.
    let xml = instance_counts(300);
    let resolve = |max| {
        iec61850_scl::parse_scl(&xml)
            .expect("parse")
            .resolve_with(&options(max))
    };
    for (max, total) in [(1000, 1216), (500, 608), (100, 304)] {
        let err = resolve(max).expect_err("the IED exceeds the limit");
        assert!(
            err.to_string().contains(&format!(
                "IED `IED1` expands to at least {total} model nodes, more than the limit of {max}"
            )),
            "limit {max}: {err}"
        );
    }
    // Control: the same file within a limit of 1216 resolves and builds.
    resolve(1216)
        .expect("1216 nodes fit a limit of 1216")
        .build_model("IED1")
        .expect("build");
}

/// The number of model nodes of the IED `ied` of `xml` built under the
/// default limit: every node but the logical devices, as stage 2 counts them.
fn built_nodes(xml: &str, ied: &str) -> u64 {
    let model = iec61850_scl::parse_scl(xml)
        .expect("parse")
        .resolve()
        .expect("resolve")
        .build_model(ied)
        .expect("build");
    let mut nodes = 0;
    model.walk(|n| {
        if !matches!(n, iec61850_model::ModelNode::Ld(_)) {
            nodes += 1;
        }
    });
    nodes
}

/// The FC=SG view the model builder derives from an FC=SE attribute counts
/// against the limit: an FC=SE array of 10 structures of 2 floats is 31
/// nodes, and its view another 31.
#[test]
fn derived_setting_views_count_against_the_limit() {
    let xml = with_do_type(r#"<DA name="a" fc="SE" bType="Struct" type="P" count="10"/>"#);
    // D_T: 31 + 31 = 62; LLN0: 1 + 62 = 63; the IED adds LLN0 itself: 64.
    assert_eq!(built_nodes(&xml, "IED1"), 64);
    let resolve = |max| {
        iec61850_scl::parse_scl(&xml)
            .expect("parse")
            .resolve_with(&options(max))
    };
    let err = resolve(33).expect_err("64 nodes exceed a limit of 33");
    assert!(
        err.to_string()
            .contains("DOType `D_T` expands to 62 model nodes, more than the limit of 33"),
        "{err}"
    );
    let err = resolve(63).expect_err("64 nodes exceed a limit of 63");
    assert!(
        err.to_string()
            .contains("IED `IED1` expands to at least 64 model nodes"),
        "{err}"
    );
    resolve(64)
        .expect("64 nodes fit a limit of 64")
        .build_model("IED1")
        .expect("build");
}

/// Stage 2 counts exactly the nodes the model builder makes: each file below
/// resolves under a limit of the number of nodes its model has, and is
/// rejected under one less. The files cover an FC=SE attribute with its
/// derived view, one whose DOType declares the FC=SG attribute itself, an
/// FC=SE attribute of a sub-object and of an array of sub-objects, an FC=SE
/// array whose element count an instance gives, and the SCL files of the
/// repository.
#[test]
fn the_limit_counts_the_nodes_the_model_builder_makes() {
    let mut files: Vec<(String, String, &str)> = [
        (
            "derived view",
            with_do_type(r#"<DA name="a" fc="SE" bType="Struct" type="P"/>"#),
        ),
        (
            "declared view",
            with_do_type(
                r#"<DA name="a" fc="SE" bType="Struct" type="P"/><DA name="a" fc="SG" bType="Struct" type="P"/>"#,
            ),
        ),
        (
            "sub-object",
            with_do_type(r#"<SDO name="s" type="S_T"/>"#).replace(
                "<DAType id=\"P\">",
                r#"<DOType id="S_T" cdc="ASG"><DA name="setMag" fc="SE" bType="Struct" type="P"/></DOType><DAType id="P">"#,
            ),
        ),
        (
            "array of sub-objects",
            with_do_type(r#"<SDO name="s" type="S_T" count="3"/>"#).replace(
                "<DAType id=\"P\">",
                r#"<DOType id="S_T" cdc="ASG"><DA name="setMag" fc="SE" bType="Struct" type="P"/></DOType><DAType id="P">"#,
            ),
        ),
        (
            "instance count",
            instance_counts(5).replace(
                r#"<DA name="a" fc="ST" bType="INT32" count="n"/>"#,
                r#"<DA name="a" fc="SE" bType="INT32" count="n"/>"#,
            ),
        ),
    ]
    .into_iter()
    .map(|(what, xml)| (what.to_string(), xml, "IED1"))
    .collect();
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    for (path, ied) in [
        ("iec61850-scl-build-example/scl/arrays.icd", "Arrays"),
        ("iec61850-scl-build-example/scl/demo.icd", "Demo"),
        ("iec61850-scl-build-example/scl/schema.icd", "Schema"),
        ("iec61850-scl-build-example/scl/settings.icd", "Settings"),
        ("iec61850-server/examples/models/demo.cid", "DemoIED"),
    ] {
        let xml = std::fs::read_to_string(format!("{dir}/{path}"))
            .unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
        files.push((path.to_string(), xml, ied));
    }
    let mut miscounted = Vec::new();
    for (what, xml, ied) in &files {
        let nodes = built_nodes(xml, ied);
        let resolve = |max| {
            iec61850_scl::parse_scl(xml)
                .expect("parse")
                .resolve_with(&options(max))
        };
        if resolve(nodes).is_err() {
            miscounted.push(format!("{what}: {nodes} nodes rejected under {nodes}"));
        }
        if resolve(nodes - 1).is_ok() {
            miscounted.push(format!(
                "{what}: {nodes} nodes accepted under {}",
                nodes - 1
            ));
        }
    }
    assert!(miscounted.is_empty(), "{miscounted:#?}");
}
