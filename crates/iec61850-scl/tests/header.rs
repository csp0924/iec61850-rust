//! The `<Header>` of an SCL file: its attributes reach `RawScl::header`.

fn scl(header: &str) -> String {
    format!(
        r#"<SCL>
  {header}
  <DataTypeTemplates/>
</SCL>"#
    )
}

#[test]
fn header_attributes_are_read() {
    let raw = iec61850_scl::parse_scl(&scl(
        r#"<Header id="Project" version="3" revision="B" toolID="Tool 1.2" nameStructure="IEDName">
             <Text>notes</Text>
             <History><Hitem version="1" revision="A" when="2026" what="first"/></History>
           </Header>"#,
    ))
    .expect("parse");
    let header = raw.header.expect("header");
    assert_eq!(header.id, "Project");
    assert_eq!(header.version.as_deref(), Some("3"));
    assert_eq!(header.revision.as_deref(), Some("B"));
    assert_eq!(header.tool_id.as_deref(), Some("Tool 1.2"));
    assert_eq!(header.name_structure.as_deref(), Some("IEDName"));
}

#[test]
fn optional_header_attributes_may_be_absent() {
    let raw = iec61850_scl::parse_scl(&scl(r#"<Header id="P"/>"#)).expect("parse");
    let header = raw.header.expect("header");
    assert_eq!(header.id, "P");
    assert!(header.version.is_none() && header.revision.is_none());
    assert!(header.tool_id.is_none() && header.name_structure.is_none());
}

/// Control: a file without a `<Header>` has none.
#[test]
fn file_without_header_has_none() {
    let raw = iec61850_scl::parse_scl(&scl("")).expect("parse");
    assert!(raw.header.is_none());
}

/// The `id` attribute is required, and one `<SCL>` holds at most one
/// `<Header>`.
#[test]
fn malformed_headers_are_rejected() {
    for header in [
        r#"<Header version="1"/>"#,
        r#"<Header id="A"/><Header id="B"/>"#,
    ] {
        assert!(iec61850_scl::parse_scl(&scl(header)).is_err(), "{header}");
    }
}
