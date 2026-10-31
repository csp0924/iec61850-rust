//! The order of the children of a data object built from SCL: the order its
//! DOType declares them in, `<SDO>` and `<DA>` interleaved (IEC 61850-6
//! §9.5.3), which is the member order on the wire (IEC 61850-8-1 §7.3.1).

use iec61850_model::tree::{DoChild, IedModel};

fn build(xml: &str) -> IedModel {
    iec61850_scl::parse_scl(xml)
        .expect("parse")
        .resolve()
        .expect("resolve")
        .build_model("IED1")
        .expect("build")
}

fn scl(seq_type: &str) -> String {
    format!(
        r#"<SCL>
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnClass="LLN0" lnType="LLN0_T"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="SeqA" type="SEQ_T"/>
    </LNodeType>
    {seq_type}
    <DOType id="CMV_T" cdc="CMV">
      <DA name="cVal" fc="MX" bType="FLOAT32"/>
    </DOType>
  </DataTypeTemplates>
</SCL>"#
    )
}

fn child_names(model: &IedModel) -> Vec<String> {
    model.lds[0].lns[0]
        .do_by_name("SeqA")
        .expect("SeqA")
        .children
        .iter()
        .map(|c| match c {
            DoChild::Da(da) => format!("DA {}", da.name),
            DoChild::SubDo(sd) => format!("SDO {}", sd.name),
        })
        .collect()
}

/// Sub-objects declared before an attribute stay before it.
#[test]
fn dotype_children_keep_document_order() {
    let m = build(&scl(r#"<DOType id="SEQ_T" cdc="SEQ">
      <SDO name="c1" type="CMV_T"/>
      <SDO name="c2" type="CMV_T"/>
      <DA name="q" fc="MX" bType="Quality"/>
      <SDO name="c3" type="CMV_T"/>
      <DA name="seqT" fc="MX" bType="INT8"/>
    </DOType>"#));
    assert_eq!(
        child_names(&m),
        ["SDO c1", "SDO c2", "DA q", "SDO c3", "DA seqT"]
    );
}

/// The raw DOType keeps one ordered child list as well.
#[test]
fn raw_dotype_keeps_document_order() {
    let raw = iec61850_scl::parse_scl(&scl(r#"<DOType id="SEQ_T" cdc="SEQ">
      <SDO name="c1" type="CMV_T"/>
      <DA name="seqT" fc="MX" bType="INT8"/>
      <SDO name="c2" type="CMV_T"/>
    </DOType>"#))
    .expect("parse");
    let dot = &raw.data_type_templates.do_types["SEQ_T"];
    let names: Vec<&str> = dot
        .children
        .iter()
        .map(|c| match c {
            iec61850_scl::raw::RawDoTypeChild::Da(d) => d.name.as_str(),
            iec61850_scl::raw::RawDoTypeChild::Sdo(s) => s.name.as_str(),
        })
        .collect();
    assert_eq!(names, ["c1", "seqT", "c2"]);
}

/// Control: attributes declared first stay first.
#[test]
fn attributes_declared_first_stay_first() {
    let m = build(&scl(r#"<DOType id="SEQ_T" cdc="SEQ">
      <DA name="q" fc="MX" bType="Quality"/>
      <SDO name="c1" type="CMV_T"/>
    </DOType>"#));
    assert_eq!(child_names(&m), ["DA q", "SDO c1"]);
}
