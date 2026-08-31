//! Gate on `demo.cid`, the configured IED description the repository examples load.
//!
//! The file is hand-authored, so nothing else proves it stays parsable and
//! keeps the object names the examples reference. Each test below pins one
//! contract of that file: the IED identity, the loopback access point, the
//! measurement data set, and the three control blocks.

use std::collections::BTreeMap;

use iec61850_model::tree::{IedModel, LogicalNode};

/// The CID belongs to `iec61850-server`, which is where it has to live so that
/// a published package carries it. Reaching across crates is acceptable here
/// because this is a test, not a shipped item.
const DEMO_CID: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../iec61850-server/examples/models/demo.cid"
);

fn demo_cid_text() -> String {
    std::fs::read_to_string(DEMO_CID).unwrap_or_else(|e| panic!("cannot read {DEMO_CID}: {e}"))
}

/// Parse, resolve and build the runtime model of the single IED in the file.
fn demo_model() -> IedModel {
    let xml = demo_cid_text();
    let raw = iec61850_scl::parse_scl(&xml).unwrap_or_else(|e| panic!("parse_scl failed: {e}"));
    let resolved = iec61850_scl::ResolvedScl::from_raw(raw)
        .unwrap_or_else(|e| panic!("ResolvedScl::from_raw failed: {e}"));
    resolved
        .build_model("DemoIED")
        .unwrap_or_else(|e| panic!("build_model(DemoIED) failed: {e}"))
}

fn lln0(model: &IedModel) -> &LogicalNode {
    model
        .ld_by_inst("LD0")
        .expect("LD0 missing from the demo model")
        .lns
        .iter()
        .find(|ln| ln.class == "LLN0")
        .expect("LLN0 missing from LD0")
}

#[test]
fn demo_cid_declares_the_expected_ied_and_logical_nodes() {
    let model = demo_model();
    assert_eq!(model.ied_name, "DemoIED");

    let ld = model.ld_by_inst("LD0").expect("LD0 missing");
    assert_eq!(ld.domain_name(&model.ied_name), "DemoIEDLD0");

    let mut lns: Vec<String> = ld.lns.iter().map(|ln| ln.full_name()).collect();
    lns.sort();
    assert_eq!(lns, vec!["GGIO1", "LLN0", "LPHD1", "MMXU1"]);

    let mmxu = ld.ln_by_name("MMXU1").expect("MMXU1 missing");
    for do_name in ["TotW", "Hz", "PhV"] {
        assert!(
            mmxu.do_by_name(do_name).is_some(),
            "MMXU1.{do_name} missing"
        );
    }

    let ggio = ld.ln_by_name("GGIO1").expect("GGIO1 missing");
    for do_name in ["Ind1", "Ind2", "Ind3", "Ind4", "SPCSO1"] {
        assert!(
            ggio.do_by_name(do_name).is_some(),
            "GGIO1.{do_name} missing"
        );
    }
}

/// The control point has to carry the four control-service attributes, or a
/// client cannot discover the select step of either select-before-operate model.
#[test]
fn demo_cid_control_point_offers_the_control_services() {
    let model = demo_model();
    let spcso1 = model
        .ld_by_inst("LD0")
        .and_then(|ld| ld.ln_by_name("GGIO1"))
        .and_then(|ln| ln.do_by_name("SPCSO1"))
        .expect("GGIO1.SPCSO1 missing");

    let children: Vec<&str> = spcso1
        .children
        .iter()
        .map(|c| match c {
            iec61850_model::tree::DoChild::Da(da) => da.name.as_str(),
            iec61850_model::tree::DoChild::SubDo(sub) => sub.name.as_str(),
        })
        .collect();

    for da in ["SBO", "SBOw", "Oper", "Cancel", "ctlModel", "stVal"] {
        assert!(
            children.contains(&da),
            "GGIO1.SPCSO1.{da} missing; present: {children:?}"
        );
    }
}

#[test]
fn demo_cid_defines_the_measurement_data_set() {
    let model = demo_model();
    let ds = lln0(&model)
        .datasets
        .iter()
        .find(|d| d.name == "dsMeas")
        .expect("data set dsMeas missing from LLN0");

    let members: Vec<String> = ds
        .entries
        .iter()
        .map(|e| format!("{}.{}", e.ln_name, e.do_path.join(".")))
        .collect();
    assert_eq!(
        members,
        vec![
            "MMXU1.TotW.mag.f",
            "MMXU1.Hz.mag.f",
            "MMXU1.PhV.phsA.cVal.mag.f",
        ]
    );
}

#[test]
fn demo_cid_defines_the_three_control_blocks() {
    let model = demo_model();
    let ln0 = lln0(&model);

    let urcb = ln0
        .rcbs
        .iter()
        .find(|r| r.name == "urcbMeas")
        .expect("urcbMeas missing");
    assert!(!urcb.is_buffered, "urcbMeas must be unbuffered");
    assert_eq!(urcb.dataset_ref, "dsMeas");

    let brcb = ln0
        .rcbs
        .iter()
        .find(|r| r.name == "brcbMeas")
        .expect("brcbMeas missing");
    assert!(brcb.is_buffered, "brcbMeas must be buffered");
    assert_eq!(brcb.dataset_ref, "dsMeas");

    let gocb = ln0
        .gocbs
        .iter()
        .find(|g| g.name == "gcbStatus")
        .expect("gcbStatus missing");
    assert_eq!(gocb.dataset_ref, "dsStatus");
}

// ---------------------------------------------------------------------------
// Contracts the runtime model does not carry
// ---------------------------------------------------------------------------

/// The address a client connects to, and the `indexed` flag that decides the
/// instantiated names of the report control blocks, live only in the document:
/// `iec61850-scl` skips `<Communication>` and drops `indexed`, so neither
/// reaches [`IedModel`]. The helpers below read the document structurally, by
/// element and attribute, so reindenting or reordering attributes in the CID
/// cannot break these assertions.
#[test]
fn demo_cid_binds_the_access_point_to_loopback() {
    let xml = demo_cid_text();
    let comm = element(&xml, "Communication").expect("no <Communication> section");

    let ap = start_tag(comm, "ConnectedAP").expect("no <ConnectedAP>");
    assert_eq!(attr(ap, "iedName").as_deref(), Some("DemoIED"));
    assert_eq!(attr(ap, "apName").as_deref(), Some("AP1"));

    let address = element(comm, "Address").expect("the ConnectedAP has no <Address>");
    let p = p_values(address);
    assert_eq!(p.get("IP").map(String::as_str), Some("127.0.0.1"));
    assert_eq!(p.get("MMS-Port").map(String::as_str), Some("102"));
}

/// The GOOSE control block needs its multicast address, APPID and VLAN tag
/// bound under the access point; a subscriber cannot join the publication from
/// `<GSEControl>` alone.
#[test]
fn demo_cid_binds_the_goose_control_block() {
    let xml = demo_cid_text();
    let comm = element(&xml, "Communication").expect("no <Communication> section");
    let gse = element(comm, "GSE").expect("no <GSE> binding for the GoCB");

    let tag = start_tag(gse, "GSE").expect("malformed <GSE>");
    assert_eq!(attr(tag, "ldInst").as_deref(), Some("LD0"));
    assert_eq!(attr(tag, "cbName").as_deref(), Some("gcbStatus"));

    let p = p_values(element(gse, "Address").expect("the GSE has no <Address>"));
    assert_eq!(
        p.get("MAC-Address").map(String::as_str),
        Some("01-0C-CD-01-00-01")
    );
    assert!(p.contains_key("APPID"), "the GSE binding carries no APPID");
    assert!(
        p.contains_key("VLAN-PRIORITY"),
        "the GSE binding carries no VLAN priority"
    );
}

/// Left at the SCL default of `true`, a conformant tool would instantiate
/// `urcbMeas01` and `urcbMeas02` rather than the `urcbMeas` that every
/// consumer in this repository names.
#[test]
fn demo_cid_report_control_blocks_are_not_indexed() {
    let xml = demo_cid_text();
    let mut rest = xml.as_str();
    let mut found = 0;
    while let Some((at, tag)) = start_tag_at(rest, "ReportControl") {
        let name = attr(tag, "name").unwrap_or_default();
        assert_eq!(
            attr(tag, "indexed").as_deref(),
            Some("false"),
            "ReportControl {name} must carry indexed=\"false\""
        );
        found += 1;
        rest = &rest[at + tag.len() + 2..];
    }
    assert_eq!(found, 2, "expected two ReportControl elements");
}

// ---------------------------------------------------------------------------
// A small structural reader, enough for the document-level assertions above
// ---------------------------------------------------------------------------

/// The byte offset of the opening `<` and the text of the first start tag of
/// `name` in `xml`, without the angle brackets.
///
/// Callers need the offset: searching `xml` for the returned text would find
/// the first place that text occurs, which for a name like `Communication` is
/// a comment long before the tag.
fn start_tag_at<'a>(xml: &'a str, name: &str) -> Option<(usize, &'a str)> {
    let mut from = 0;
    loop {
        let at = from + xml[from..].find(&format!("<{name}"))?;
        let after = at + 1 + name.len();
        // The next character must end the name, or this is a longer element
        // whose name merely starts with `name`.
        let ends = xml[after..]
            .chars()
            .next()
            .is_some_and(|c| c.is_whitespace() || c == '>' || c == '/');
        if ends {
            let close = at + xml[at..].find('>')?;
            return Some((at, &xml[at + 1..close]));
        }
        from = after;
    }
}

/// The text of the first start tag of `name`, without the angle brackets.
/// Matches on the element name, so attribute layout is irrelevant.
fn start_tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    start_tag_at(xml, name).map(|(_, tag)| tag)
}

/// The value of `name` in a start tag, with the surrounding quotes removed.
fn attr(tag: &str, name: &str) -> Option<String> {
    let mut from = 0;
    loop {
        let at = from + tag[from..].find(name)?;
        let before_ok = at == 0
            || tag[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_whitespace());
        let rest = tag[at + name.len()..].trim_start();
        if before_ok && rest.starts_with('=') {
            let value = rest[1..].trim_start();
            let quote = value.chars().next()?;
            let end = value[1..].find(quote)?;
            return Some(value[1..1 + end].to_string());
        }
        from = at + name.len();
    }
}

/// The first `<name>…</name>` element of `xml`, start tag included.
fn element<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let (start, _) = start_tag_at(xml, name)?;
    let close = format!("</{name}>");
    let end = xml[start..].find(&close)? + start + close.len();
    let slice = &xml[start..end];
    assert!(
        slice.starts_with('<'),
        "element({name}) did not begin at a tag: {:?}",
        &slice[..slice.len().min(40)]
    );
    Some(slice)
}

/// Every `<P type="…">value</P>` inside `scope`, keyed by the `type` attribute.
fn p_values(scope: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut rest = scope;
    while let Some((at, tag)) = start_tag_at(rest, "P") {
        // Past the `<`, the tag text and the `>`.
        let after_tag = at + tag.len() + 2;
        if let (Some(key), Some(end)) = (attr(tag, "type"), rest[after_tag..].find("</P>")) {
            out.insert(key, rest[after_tag..after_tag + end].trim().to_string());
        }
        rest = &rest[after_tag..];
    }
    out
}
