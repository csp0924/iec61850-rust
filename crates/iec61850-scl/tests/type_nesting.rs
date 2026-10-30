//! Stage 2 bounds how deep DOTypes nest through `<SDO>` and DATypes through
//! `<BDA>`, so a deep but acyclic chain fails with an error instead of
//! exhausting the stack of the model builder.

/// An IED whose LLN0 has one data object `D` of type `S0`, with the given
/// DataTypeTemplates entries.
fn scl(templates: &str) -> String {
    format!(
        r#"<SCL>
  <IED name="IED1"><AccessPoint name="AP1"><Server><LDevice inst="LD0">
    <LN0 inst="" lnClass="LLN0" lnType="LLN0_T"/>
  </LDevice></Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="D" type="S0"/></LNodeType>
    {templates}
  </DataTypeTemplates>
</SCL>"#
    )
}

/// A chain of `n` DOTypes, each holding the next as a sub-object. The top
/// one is `S0`; with `leaf_first`, the identifiers sort from the leaf
/// upwards, so the walk meets the deep types before the top one.
fn sdo_chain(n: usize, leaf_first: bool) -> String {
    let id = |level: usize| {
        if leaf_first && level > 0 {
            format!("A{:04}", n - level)
        } else {
            format!("S{level}")
        }
    };
    let mut t = String::new();
    for i in 0..n {
        if i + 1 < n {
            t.push_str(&format!(
                r#"<DOType id="{}" cdc="WYE"><SDO name="s" type="{}"/></DOType>"#,
                id(i),
                id(i + 1)
            ));
        } else {
            t.push_str(&format!(
                r#"<DOType id="{}" cdc="CMV"><DA name="q" fc="MX" bType="Quality"/></DOType>"#,
                id(i)
            ));
        }
    }
    scl(&t)
}

/// One DOType `S0` holding a constructed attribute whose type nests `n`
/// DATypes deep.
fn bda_chain(n: usize) -> String {
    let mut t = String::from(
        r#"<DOType id="S0" cdc="MV"><DA name="v" fc="MX" bType="Struct" type="T0"/></DOType>"#,
    );
    for i in 0..n {
        if i + 1 < n {
            t.push_str(&format!(
                r#"<DAType id="T{i}"><BDA name="b" bType="Struct" type="T{}"/></DAType>"#,
                i + 1
            ));
        } else {
            t.push_str(&format!(
                r#"<DAType id="T{i}"><BDA name="f" bType="FLOAT32"/></DAType>"#
            ));
        }
    }
    scl(&t)
}

fn build(xml: &str) -> Result<iec61850_model::tree::IedModel, String> {
    iec61850_scl::parse_scl(xml)
        .and_then(|r| r.resolve())
        .and_then(|r| r.build_model("IED1"))
        .map_err(|e| e.to_string())
}

#[test]
fn sdo_chain_of_1000_levels_is_rejected() {
    let err = build(&sdo_chain(1000, false)).expect_err("a 1000-level SDO chain must be rejected");
    assert!(err.contains("deeper than 32"), "{err}");
}

#[test]
fn da_type_chain_of_1000_levels_is_rejected() {
    let err = build(&bda_chain(1000)).expect_err("a 1000-level DAType chain must be rejected");
    assert!(err.contains("deeper than 32"), "{err}");
}

/// Control: chains at the bound build, and one level more is rejected.
#[test]
fn chains_at_the_bound_build() {
    for leaf_first in [false, true] {
        assert!(build(&sdo_chain(32, leaf_first)).is_ok());
        assert!(build(&sdo_chain(33, leaf_first)).is_err());
    }
    assert!(build(&bda_chain(32)).is_ok());
    assert!(build(&bda_chain(33)).is_err());
}
