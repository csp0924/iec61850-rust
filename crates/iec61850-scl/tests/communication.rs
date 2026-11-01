//! The `<Communication>` section: the subnetworks, the connected access points
//! with their server addresses, and the `<GSE>` and `<SMV>` addressing of the
//! control blocks (IEC 61850-6 §9.4), checked as it is read and carried into
//! the model of each IED.

use std::net::Ipv4Addr;

use iec61850_model::comm::Address;
use iec61850_model::tree::IedModel;
use iec61850_scl::{ErrorKind, SclParseError};

/// Two IEDs: `IED1` with a GOOSE and a sampled values control block on
/// `LD0`, and `IED2` with a GOOSE control block, so an SCD-like file can
/// address both.
fn scl(communication: &str) -> String {
    format!(
        r#"<SCL>
  <Header id="comm"/>
  {communication}
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnClass="LLN0" lnType="LLN0_T">
            <DataSet name="ds1">
              <FCDA ldInst="LD0" lnClass="LLN0" doName="Mod" daName="stVal" fc="ST"/>
            </DataSet>
            <GSEControl name="gcb1" datSet="ds1" appID="G1" confRev="1"/>
            <GSEControl name="gcb2" datSet="ds1" appID="G2" confRev="1"/>
            <SampledValueControl name="svcb1" datSet="ds1" smvID="S1" smpRate="80" nofASDU="1" confRev="1"/>
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
    <AccessPoint name="AP2"/>
  </IED>
  <IED name="IED2">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 inst="" lnClass="LLN0" lnType="LLN0_T">
            <DataSet name="ds1">
              <FCDA ldInst="LD0" lnClass="LLN0" doName="Mod" daName="stVal" fc="ST"/>
            </DataSet>
            <GSEControl name="gcb1" datSet="ds1" appID="H1" confRev="1"/>
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0">
      <DO name="Mod" type="ENC_T"/>
    </LNodeType>
    <DOType id="ENC_T" cdc="ENC">
      <DA name="stVal" fc="ST" bType="BOOLEAN" dchg="true"/>
    </DOType>
  </DataTypeTemplates>
</SCL>"#
    )
}

/// A `<Communication>` with one subnetwork holding `body`.
fn subnetwork(body: &str) -> String {
    scl(&format!(
        r#"<Communication>
    <SubNetwork name="W01" type="8-MMS">
      {body}
    </SubNetwork>
  </Communication>"#
    ))
}

/// A connected access point `IED1`/`AP1` holding `body`.
fn ied1_ap(body: &str) -> String {
    subnetwork(&format!(
        r#"<ConnectedAP iedName="IED1" apName="AP1">
        {body}
      </ConnectedAP>"#
    ))
}

/// A `<GSE>` for `IED1`/`LD0`/`gcb1` whose address holds one parameter.
fn gse_with_p(p_type: &str, value: &str) -> String {
    ied1_ap(&format!(
        r#"<GSE ldInst="LD0" cbName="gcb1">
          <Address><P type="{p_type}">{value}</P></Address>
        </GSE>"#
    ))
}

fn try_build(xml: &str, ied: &str) -> Result<IedModel, SclParseError> {
    iec61850_scl::parse_scl(xml)?.resolve()?.build_model(ied)
}

fn build(xml: &str, ied: &str) -> IedModel {
    try_build(xml, ied).unwrap_or_else(|e| panic!("{e}"))
}

fn error(xml: &str) -> SclParseError {
    error_of(xml, "IED1")
}

fn error_of(xml: &str, ied: &str) -> SclParseError {
    match try_build(xml, ied) {
        Ok(_) => panic!("the file was accepted"),
        Err(e) => e,
    }
}

const FULL: &str = r#"<Communication>
    <SubNetwork name="W01" type="8-MMS">
      <Text>Station bus</Text>
      <BitRate unit="b/s" multiplier="M">100</BitRate>
      <ConnectedAP iedName="IED1" apName="AP1">
        <Address>
          <P type="IP">10.0.0.11</P>
          <P type="IP-SUBNET">255.255.255.0</P>
          <P type="IP-GATEWAY">10.0.0.101</P>
          <P type="OSI-TSEL">00000001</P>
          <P type="OSI-PSEL">01</P>
          <P type="OSI-SSEL">0001</P>
          <P type="OSI-AP-Title">1,1,9999,1</P>
          <P type="OSI-AE-Qualifier">12</P>
          <P type="MMS-Port">102</P>
        </Address>
        <GSE ldInst="LD0" cbName="gcb1">
          <Address>
            <P type="MAC-Address">01-0C-CD-01-00-05</P>
            <P type="APPID">3A01</P>
            <P type="VLAN-ID">07B</P>
            <P type="VLAN-PRIORITY">6</P>
          </Address>
          <MinTime unit="s" multiplier="m">8</MinTime>
          <MaxTime unit="s" multiplier="m">2000</MaxTime>
        </GSE>
        <SMV ldInst="LD0" cbName="svcb1">
          <Address>
            <P type="MAC-Address">01-0C-CD-04-00-01</P>
            <P type="APPID">4001</P>
          </Address>
        </SMV>
        <PhysConn type="Connection">
          <P type="Type">FOC</P>
          <P type="Plug">ST</P>
        </PhysConn>
      </ConnectedAP>
      <ConnectedAP iedName="IED2" apName="AP1">
        <GSE ldInst="LD0" cbName="gcb1">
          <Address><P type="MAC-Address">01-0C-CD-01-00-09</P></Address>
        </GSE>
      </ConnectedAP>
    </SubNetwork>
    <SubNetwork name="P01">
      <ConnectedAP iedName="IED1" apName="AP2">
        <Address><P type="IP">192.168.1.5</P></Address>
      </ConnectedAP>
    </SubNetwork>
  </Communication>"#;

/// Every element of the section reaches the raw AST, in document order.
#[test]
fn the_section_is_read_into_the_raw_ast() {
    let raw = iec61850_scl::parse_scl(&scl(FULL)).expect("parse");
    let communication = raw.communication.as_ref().expect("Communication");
    let names: Vec<&str> = communication
        .sub_networks
        .iter()
        .map(|n| n.name.as_str())
        .collect();
    assert_eq!(names, ["W01", "P01"]);
    let w01 = &communication.sub_networks[0];
    assert_eq!(w01.net_type.as_deref(), Some("8-MMS"));
    assert_eq!(w01.connected_aps.len(), 2);
    let ap = &w01.connected_aps[0];
    assert_eq!((ap.ied_name.as_str(), ap.ap_name.as_str()), ("IED1", "AP1"));
    assert_eq!(ap.address.as_ref().map(|a| a.parameters.len()), Some(9));
    let gse = &ap.gses[0];
    assert_eq!(
        (gse.ld_inst.as_str(), gse.cb_name.as_str()),
        ("LD0", "gcb1")
    );
    assert_eq!((gse.min_time_ms, gse.max_time_ms), (Some(8), Some(2000)));
    assert_eq!(ap.smvs[0].cb_name, "svcb1");
    assert_eq!(communication.sub_networks[1].net_type, None);
}

/// The model of an IED holds its own connected access points, with their
/// server addresses, and the addressing of its own control blocks.
#[test]
fn the_model_holds_the_addressing_of_its_ied() {
    let model = build(&scl(FULL), "IED1");

    assert_eq!(model.connected_aps.len(), 2);
    let ap1 = &model.connected_aps[0];
    assert_eq!(ap1.sub_network, "W01");
    assert_eq!(ap1.sub_network_type.as_deref(), Some("8-MMS"));
    assert_eq!(ap1.ap_name, "AP1");
    let address = ap1.address.as_ref().expect("server address");
    assert_eq!(address.ip(), Some(Ipv4Addr::new(10, 0, 0, 11)));
    assert_eq!(address.ip_subnet(), Some(Ipv4Addr::new(255, 255, 255, 0)));
    assert_eq!(address.ip_gateway(), Some(Ipv4Addr::new(10, 0, 0, 101)));
    assert_eq!(address.osi_tsel(), Some(vec![0, 0, 0, 1]));
    assert_eq!(address.osi_psel(), Some(vec![1]));
    assert_eq!(address.osi_ssel(), Some(vec![0, 1]));
    assert_eq!(address.osi_ap_title(), Some(vec![1, 1, 9999, 1]));
    assert_eq!(address.osi_ae_qualifier(), Some(12));
    assert_eq!(address.mms_port(), Some(102));
    let ap2: Vec<_> = model.connected_ap("AP2").collect();
    assert_eq!(ap2.len(), 1);
    assert_eq!(ap2[0].sub_network, "P01");
    assert_eq!(
        ap2[0].address.as_ref().and_then(Address::ip),
        Some(Ipv4Addr::new(192, 168, 1, 5))
    );

    let gse = model.gse_address("LD0", "gcb1").expect("GSE of gcb1");
    assert_eq!(
        gse.address.mac_address(),
        Some([0x01, 0x0c, 0xcd, 0x01, 0x00, 0x05])
    );
    assert_eq!(gse.address.app_id(), Some(0x3a01));
    assert_eq!(gse.address.vlan_id(), Some(0x07b));
    assert_eq!(gse.address.vlan_priority(), Some(6));
    assert_eq!((gse.min_time_ms, gse.max_time_ms), (Some(8), Some(2000)));
    let lln0 = &model.lds[0].lns[0];
    assert_eq!(lln0.gocbs[0].gse.as_ref(), Some(gse));

    let smv = model.smv_address("LD0", "svcb1").expect("SMV of svcb1");
    assert_eq!(
        smv.mac_address(),
        Some([0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01])
    );
    assert_eq!(smv.app_id(), Some(0x4001));
    assert_eq!(lln0.svcbs[0].smv.as_ref(), Some(smv));
}

/// A control block the section does not address has no addressing, and the
/// addressing of another IED does not leak into this one.
#[test]
fn a_control_block_without_gse_has_no_addressing() {
    let model = build(&scl(FULL), "IED1");
    assert_eq!(model.gse_address("LD0", "gcb2"), None);
    assert!(model.lds[0].lns[0].gocbs[1].gse.is_none());
    assert_eq!(model.gse_address("LD0", "absent"), None);
    assert_eq!(model.smv_address("LD9", "svcb1"), None);

    let other = build(&scl(FULL), "IED2");
    assert_eq!(other.connected_aps.len(), 1);
    assert_eq!(
        other
            .gse_address("LD0", "gcb1")
            .and_then(|g| g.address.mac_address()),
        Some([0x01, 0x0c, 0xcd, 0x01, 0x00, 0x09])
    );

    let bare = build(&scl(""), "IED1");
    assert!(bare.connected_aps.is_empty());
    assert_eq!(bare.gse_address("LD0", "gcb1"), None);
}

/// A `<GSE>` without `<Address>`, `<MinTime>` or `<MaxTime>` addresses its
/// control block with an empty address and no times.
#[test]
fn a_gse_without_children_has_an_empty_address() {
    let model = build(&ied1_ap(r#"<GSE ldInst="LD0" cbName="gcb1"/>"#), "IED1");
    let gse = model.gse_address("LD0", "gcb1").expect("GSE");
    assert!(gse.address.is_empty());
    assert_eq!((gse.min_time_ms, gse.max_time_ms), (None, None));
    assert_eq!(model.connected_aps[0].address, None);
}

/// How a value relates to the schema form of its type, in the tests.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Form {
    Schema,
    Readable,
    Unreadable,
}

/// Every value is kept as written and the file loads; a value in the schema
/// form passes silently, and any other is reported with its type, its value
/// and the schema form, saying whether it reads.
#[test]
fn each_address_type_keeps_its_value_and_reports_other_forms() {
    use Form::*;
    let cases: &[(&str, &str, Form)] = &[
        ("IP", "10.0.0.11", Schema),
        ("IP", "010.000.000.011", Readable),
        ("IP", "10.0.0.256", Unreadable),
        ("IP-SUBNET", "255.255.255", Unreadable),
        ("OSI-TSEL", "00000001", Schema),
        ("OSI-TSEL", "00 00 00 01", Readable),
        ("OSI-TSEL", "000g", Unreadable),
        ("OSI-SSEL", "1", Readable),
        ("OSI-PSEL", "00 00 00 01", Readable),
        ("OSI-PSEL", "0x01", Unreadable),
        ("OSI-AP-Title", "1,3,9999,33", Schema),
        ("OSI-AP-Title", "1 3 9999 33", Readable),
        ("OSI-AP-Title", "1.3.9999.33", Unreadable),
        ("OSI-AE-Qualifier", "123456", Readable),
        ("MAC-Address", "01-0C-CD-01-00-01", Schema),
        ("MAC-Address", "01-0c-cd-01-00-01", Readable),
        ("MAC-Address", "01:0C:CD:01:00:01", Readable),
        ("MAC-Address", "01-0C-CD-01-00", Unreadable),
        ("APPID", "3A01", Schema),
        ("APPID", "3a01", Readable),
        ("APPID", "301", Readable),
        ("APPID", "30001", Unreadable),
        ("VLAN-ID", "07B", Schema),
        ("VLAN-ID", "1", Readable),
        ("VLAN-ID", "7b", Readable),
        ("VLAN-ID", "1000", Unreadable),
        ("VLAN-PRIORITY", "04", Readable),
        ("VLAN-PRIORITY", "8", Unreadable),
        ("MMS-Port", "0102", Readable),
        ("MMS-Port", "65536", Unreadable),
        ("IPv6", "fe80:0:0:0:0:0:0:1", Schema),
        ("IPv6", "fe80::1", Readable),
        ("Vendor-Extension", "anything", Schema),
    ];
    for (p_type, value, form) in cases {
        let (model, seen) = warnings(|| try_build(&gse_with_p(p_type, value), "IED1"));
        let model = model.unwrap_or_else(|e| panic!("{p_type} `{value}` failed the file: {e}"));
        let gse = model.gse_address("LD0", "gcb1").expect("GSE");
        assert_eq!(gse.address.get(p_type), Some(*value), "kept as written");
        let report: Vec<&String> = seen
            .iter()
            .filter(|w| w.contains(&format!("`{value}`")))
            .collect();
        match form {
            Schema => assert!(report.is_empty(), "{p_type} `{value}`: {report:?}"),
            Readable => assert!(
                report.len() == 1
                    && report[0].contains(p_type)
                    && report[0].contains("not in the schema form")
                    && report[0].contains("it is read as `"),
                "{p_type} `{value}`: {seen:?}"
            ),
            Unreadable => assert!(
                report.len() == 1 && report[0].contains("cannot be read"),
                "{p_type} `{value}`: {seen:?}"
            ),
        }
    }
}

/// The deviations found in practice read as intended: a one-digit VLAN-ID, a
/// lower-case MAC address, an AP title and OSI selectors separated by white
/// space.
#[test]
fn common_deviations_read_as_intended() {
    let xml = ied1_ap(
        r#"<Address>
          <P type="IP">10.0.0.11</P>
          <P type="OSI-AP-Title">1 3 9999 33</P>
          <P type="OSI-PSEL">00 00 00 01</P>
          <P type="OSI-SSEL">00 01</P>
          <P type="OSI-TSEL">00 01</P>
        </Address>
        <GSE ldInst="LD0" cbName="gcb1">
          <Address>
            <P type="MAC-Address">01-0c-cd-01-00-05</P>
            <P type="APPID">1</P>
            <P type="VLAN-ID">1</P>
          </Address>
        </GSE>"#,
    );
    let (model, seen) = warnings(|| build(&xml, "IED1"));
    assert!(
        seen.iter()
            .any(|w| w.contains("`1`") && w.contains("it is read as `001`")),
        "{seen:?}"
    );
    assert!(
        seen.iter()
            .any(|w| w.contains("it is read as `1,3,9999,33`")),
        "{seen:?}"
    );
    let address = model.connected_aps[0].address.as_ref().expect("address");
    assert_eq!(address.osi_ap_title(), Some(vec![1, 3, 9999, 33]));
    assert_eq!(address.osi_psel(), Some(vec![0, 0, 0, 1]));
    assert_eq!(address.osi_ssel(), Some(vec![0, 1]));
    assert_eq!(address.osi_tsel(), Some(vec![0, 1]));
    let gse = model.gse_address("LD0", "gcb1").expect("GSE");
    assert_eq!(
        gse.address.mac_address(),
        Some([0x01, 0x0c, 0xcd, 0x01, 0x00, 0x05])
    );
    assert_eq!(gse.address.app_id(), Some(1));
    assert_eq!(gse.address.vlan_id(), Some(1));
}

/// The warning about a value written another way carries its line.
#[test]
fn a_value_written_another_way_is_reported_at_its_line() {
    let xml = gse_with_p("VLAN-ID", "1");
    let line = xml
        .lines()
        .position(|l| l.contains(r#"type="VLAN-ID""#))
        .expect("the value is in the file")
        + 1;
    let (model, seen) = warnings(|| try_build(&xml, "IED1"));
    model.expect("the file loads");
    assert!(
        seen.iter().any(|w| w.contains(&format!("line={line} "))
            && w.contains("VLAN-ID")
            && w.contains("three digits 0-9 and A-F")),
        "{seen:?}"
    );
}

/// A value that cannot be read loads, and its accessor reads `None`.
#[test]
fn an_unreadable_value_loads_and_reads_as_none() {
    let model = build(&gse_with_p("VLAN-ID", "FFFF"), "IED1");
    let gse = model.gse_address("LD0", "gcb1").expect("GSE");
    assert_eq!(gse.address.get("VLAN-ID"), Some("FFFF"));
    assert_eq!(gse.address.vlan_id(), None);
}

/// A `<P>` of no address parameter type, or with an empty value, is left out
/// of the address with a warning; an `<Address>` without `<P>` is still
/// refused, as the schema requires one.
#[test]
fn a_malformed_type_or_an_empty_value_is_left_out() {
    for xml in [
        gse_with_p("mac-address", "01-0C-CD-01-00-01"),
        gse_with_p("APPID", ""),
    ] {
        let (model, seen) = warnings(|| try_build(&xml, "IED1"));
        let model = model.expect("the file loads");
        let gse = model.gse_address("LD0", "gcb1").expect("GSE");
        assert!(gse.address.is_empty());
        assert!(
            seen.iter().any(|w| w.contains("left out of the address")),
            "{seen:?}"
        );
    }
    let e = error(&ied1_ap(
        r#"<GSE ldInst="LD0" cbName="gcb1"><Address/></GSE>"#,
    ));
    assert!(
        matches!(&*e.kind, ErrorKind::MissingRequiredElement { name, .. } if name == "P"),
        "{e}"
    );
}

/// An address value of another IED that cannot be read does not affect the
/// IED being built, and the other IED loads too, reading it as `None`.
#[test]
fn an_unreadable_address_of_another_ied_does_not_fail_either() {
    let xml = subnetwork(
        r#"<ConnectedAP iedName="IED1" apName="AP1">
        <GSE ldInst="LD0" cbName="gcb1">
          <Address><P type="MAC-Address">01-0C-CD-01-00-01</P></Address>
        </GSE>
      </ConnectedAP>
      <ConnectedAP iedName="IED2" apName="AP1">
        <Address><P type="IP">10.0.0.256</P></Address>
      </ConnectedAP>"#,
    );
    let resolved = iec61850_scl::parse_scl(&xml)
        .expect("parse")
        .resolve()
        .expect("resolve");
    let ied1 = resolved.build_model("IED1").expect("IED1 builds");
    assert_eq!(
        ied1.gse_address("LD0", "gcb1")
            .and_then(|g| g.address.mac_address()),
        Some([0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01])
    );
    let ied2 = resolved.build_model("IED2").expect("IED2 builds");
    let address = ied2.connected_aps[0].address.as_ref().expect("address");
    assert_eq!(address.get("IP"), Some("10.0.0.256"));
    assert_eq!(address.ip(), None);
}

/// `MinTime` and `MaxTime` take any `xs:decimal` number of milliseconds,
/// rounded to the nearest whole millisecond, and the fixed unit and
/// multiplier of `tDurationInMilliSec`.
#[test]
fn min_and_max_time_round_to_whole_milliseconds() {
    let gse = |min: &str| {
        ied1_ap(&format!(
            r#"<GSE ldInst="LD0" cbName="gcb1">{min}<MaxTime>5000</MaxTime></GSE>"#
        ))
    };
    let min_time = |min: &str| {
        build(&gse(min), "IED1")
            .gse_address("LD0", "gcb1")
            .and_then(|g| g.min_time_ms)
    };
    assert_eq!(min_time("<MinTime>4.000</MinTime>"), Some(4));
    assert_eq!(min_time("<MinTime>4.4</MinTime>"), Some(4));
    assert_eq!(min_time("<MinTime>4.5</MinTime>"), Some(5));
    assert_eq!(min_time("<MinTime>+.7</MinTime>"), Some(1));
    // xs:decimal collapses white space, the spelled-out kind included.
    assert_eq!(min_time("<MinTime>\n      12\n    </MinTime>"), Some(12));
    assert_eq!(min_time("<MinTime>&#32;7.6&#10;&#9;</MinTime>"), Some(8));
    assert_eq!(min_time("<MinTime><![CDATA[ 9 ]]></MinTime>"), Some(9));
    for bad in [
        "<MinTime>-4</MinTime>",
        "<MinTime>4ms</MinTime>",
        "<MinTime>.</MinTime>",
        "<MinTime>4294967296</MinTime>",
        "<MinTime>4294967295.5</MinTime>",
        r#"<MinTime unit="ms">4</MinTime>"#,
        r#"<MinTime multiplier="k">4</MinTime>"#,
        "<MinTime>4</MinTime><MinTime>5</MinTime>",
    ] {
        error(&gse(bad));
    }
}

/// A `MinTime` above the `MaxTime` contradicts the repetition scheme.
#[test]
fn a_min_time_above_the_max_time_is_refused() {
    let e = error(&ied1_ap(
        r#"<GSE ldInst="LD0" cbName="gcb1"><MinTime>50</MinTime><MaxTime>40</MaxTime></GSE>"#,
    ));
    assert!(
        matches!(&*e.kind, ErrorKind::SemanticConflict { detail, .. } if detail.contains("MinTime 50")),
        "{e}"
    );
}

/// A reference of a connected access point of the IED being built that names
/// nothing in the file is an error naming the attribute.
#[test]
fn a_reference_to_nothing_is_refused() {
    let unknown_ap = subnetwork(r#"<ConnectedAP iedName="IED1" apName="AP9"/>"#);
    assert_eq!(error(&unknown_ap).attribute.as_deref(), Some("apName"));

    let unknown_ld = ied1_ap(r#"<GSE ldInst="LD9" cbName="gcb1"/>"#);
    assert_eq!(error(&unknown_ld).attribute.as_deref(), Some("ldInst"));

    let unknown_cb = ied1_ap(r#"<GSE ldInst="LD0" cbName="nope"/>"#);
    assert_eq!(error(&unknown_cb).attribute.as_deref(), Some("cbName"));

    // A sampled values control block is not a GOOSE control block, and the
    // other way round.
    let wrong_kind = ied1_ap(r#"<GSE ldInst="LD0" cbName="svcb1"/>"#);
    assert_eq!(error(&wrong_kind).attribute.as_deref(), Some("cbName"));
    let wrong_kind = ied1_ap(r#"<SMV ldInst="LD0" cbName="gcb1"/>"#);
    assert_eq!(error(&wrong_kind).attribute.as_deref(), Some("cbName"));

    // AP2 has no server, so it holds no logical device.
    let no_server = subnetwork(
        r#"<ConnectedAP iedName="IED1" apName="AP2"><SMV ldInst="LD0" cbName="svcb1"/></ConnectedAP>"#,
    );
    assert_eq!(error(&no_server).attribute.as_deref(), Some("ldInst"));
}

/// The uniqueness rules of the schema: subnetwork names, connected access
/// points within a subnetwork, and control blocks within a connected access
/// point.
#[test]
fn duplicates_are_refused() {
    let duplicate = |xml: &str, element: &str| {
        let e = error(xml);
        match &*e.kind {
            ErrorKind::DuplicateIdentifier { element: got, .. } => assert_eq!(got, element),
            other => panic!("{element}: {other:?}"),
        }
    };
    duplicate(
        &scl(r#"<Communication>
    <SubNetwork name="W01"><ConnectedAP iedName="IED1" apName="AP1"/></SubNetwork>
    <SubNetwork name="W01"><ConnectedAP iedName="IED1" apName="AP2"/></SubNetwork>
  </Communication>"#),
        "SubNetwork",
    );
    duplicate(
        &subnetwork(
            r#"<ConnectedAP iedName="IED1" apName="AP1"/><ConnectedAP iedName="IED1" apName="AP1"/>"#,
        ),
        "ConnectedAP",
    );
    duplicate(
        &ied1_ap(r#"<GSE ldInst="LD0" cbName="gcb1"/><GSE ldInst="LD0" cbName="gcb1"/>"#),
        "GSE",
    );
    duplicate(
        &ied1_ap(r#"<SMV ldInst="LD0" cbName="svcb1"/><SMV ldInst="LD0" cbName="svcb1"/>"#),
        "SMV",
    );
}

/// The structure the schema requires: a subnetwork in the section, a
/// connected access point in a subnetwork, the section at most once and
/// directly under `<SCL>`.
#[test]
fn the_required_structure_is_enforced() {
    let e = error(&scl("<Communication/>"));
    assert!(
        matches!(&*e.kind, ErrorKind::MissingRequiredElement { name, .. } if name == "SubNetwork"),
        "{e}"
    );
    let e = error(&scl(
        r#"<Communication><SubNetwork name="W01"/></Communication>"#,
    ));
    assert!(
        matches!(&*e.kind, ErrorKind::MissingRequiredElement { name, .. } if name == "ConnectedAP"),
        "{e}"
    );
    let twice = scl(&format!("{FULL}{FULL}"));
    assert!(matches!(&*error(&twice).kind, ErrorKind::Xml(_)));
    let e = error(&subnetwork(r#"<ConnectedAP iedName="IED1"/>"#));
    assert!(
        matches!(&*e.kind, ErrorKind::MissingRequiredAttribute { name, .. } if name == "apName"),
        "{e}"
    );
}

/// The summary lists the connected access points and the addressing below
/// each control block, and a model without addressing summarizes as before.
#[test]
fn the_summary_lists_the_addressing() {
    let summary = iec61850_scl::summarize::summarize_model(&build(&scl(FULL), "IED1"));
    assert!(summary.contains(
        "  ConnectedAP subNetwork=W01 type=8-MMS ap=AP1 address=IP=10.0.0.11,IP-SUBNET=255.255.255.0,"
    ), "{summary}");
    assert!(
        summary.contains("  ConnectedAP subNetwork=P01 type=<None> ap=AP2 address=IP=192.168.1.5"),
        "{summary}"
    );
    assert!(summary.contains(
        "        GSE address=MAC-Address=01-0C-CD-01-00-05,APPID=3A01,VLAN-ID=07B,VLAN-PRIORITY=6 minTime=8 maxTime=2000"
    ), "{summary}");
    assert!(
        summary.contains("        SMV address=MAC-Address=01-0C-CD-04-00-01,APPID=4001"),
        "{summary}"
    );

    let bare = iec61850_scl::summarize::summarize_model(&build(&scl(""), "IED1"));
    assert!(
        !bare.contains("ConnectedAP")
            && !bare.contains("GSE address")
            && !bare.contains("SMV address")
    );
}

/// Collects the messages of the WARN events emitted while `f` runs.
fn warnings<T>(f: impl FnOnce() -> T) -> (T, Vec<String>) {
    struct Collect(std::sync::Arc<std::sync::Mutex<Vec<String>>>);
    impl tracing::Subscriber for Collect {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Text(String);
            impl tracing::field::Visit for Text {
                fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                    self.0.push_str(&format!("{}={:?} ", f.name(), v));
                }
            }
            if *event.metadata().level() == tracing::Level::WARN {
                let mut text = Text(String::new());
                event.record(&mut text);
                self.0.lock().unwrap().push(text.0);
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let out = tracing::subscriber::with_default(Collect(seen.clone()), f);
    let seen = seen.lock().unwrap().clone();
    (out, seen)
}

/// A ConnectedAP naming an IED the file does not declare is skipped with a
/// warning naming that IED: the file loads and the IED it declares builds.
#[test]
fn a_connected_ap_naming_an_undeclared_ied_is_skipped() {
    let xml = subnetwork(
        r#"<ConnectedAP iedName="IED1" apName="AP1">
        <Address><P type="IP">10.0.0.11</P></Address>
      </ConnectedAP>
      <ConnectedAP iedName="UNDECLARED" apName="AP1">
        <Address><P type="IP">10.0.0.99</P></Address>
        <GSE ldInst="LD0" cbName="gcbAbsent"/>
      </ConnectedAP>"#,
    );
    let (model, seen) = warnings(|| try_build(&xml, "IED1"));
    let model = model.expect("a ConnectedAP of an absent IED does not fail the file");
    assert_eq!(model.connected_aps.len(), 1);
    assert_eq!(model.connected_aps[0].ap_name, "AP1");
    assert!(
        seen.iter()
            .any(|w| w.contains("UNDECLARED") && w.contains("declares no IED")),
        "{seen:?}"
    );
}

/// A reference of another IED that names nothing only warns: the file loads,
/// the IED being built is unaffected, and building the other IED fails at the
/// reference.
#[test]
fn a_bad_reference_of_another_ied_only_warns() {
    let xml = subnetwork(
        r#"<ConnectedAP iedName="IED1" apName="AP1">
        <GSE ldInst="LD0" cbName="gcb1"><MinTime>4</MinTime><MaxTime>100</MaxTime></GSE>
      </ConnectedAP>
      <ConnectedAP iedName="IED2" apName="AP1">
        <GSE ldInst="LD0" cbName="nope"/>
      </ConnectedAP>
      <ConnectedAP iedName="IED2" apName="AP9"/>"#,
    );
    let (resolved, seen) = warnings(|| {
        iec61850_scl::parse_scl(&xml)
            .expect("parse")
            .resolve()
            .expect("references of IED2 do not fail stage 2")
    });
    assert!(
        seen.iter().any(|w| w.contains("GSEControl named `nope`")),
        "{seen:?}"
    );
    assert!(
        seen.iter()
            .any(|w| w.contains("no access point named `AP9`")),
        "{seen:?}"
    );
    let ied1 = resolved.build_model("IED1").expect("IED1 builds");
    assert_eq!(
        ied1.gse_address("LD0", "gcb1").and_then(|g| g.max_time_ms),
        Some(100)
    );
    let e = resolved
        .build_model("IED2")
        .expect_err("IED2 has a dangling reference");
    assert_eq!(e.attribute.as_deref(), Some("cbName"), "{e}");
    assert!(
        e.element_path
            .contains("ConnectedAP[iedName=\"IED2\",apName=\"AP1\"]"),
        "{}",
        e.element_path
    );
}

/// A `MinTime` above its `MaxTime` in another IED only warns, while the same
/// in the IED being built fails its build.
#[test]
fn a_min_time_above_the_max_time_of_another_ied_only_warns() {
    let xml = subnetwork(
        r#"<ConnectedAP iedName="IED1" apName="AP1"/>
      <ConnectedAP iedName="IED2" apName="AP1">
        <GSE ldInst="LD0" cbName="gcb1"><MinTime>50</MinTime><MaxTime>40</MaxTime></GSE>
      </ConnectedAP>"#,
    );
    build(&xml, "IED1");
    let e = error_of(&xml, "IED2");
    assert!(
        matches!(&*e.kind, ErrorKind::SemanticConflict { detail, .. } if detail.contains("MinTime 50")),
        "{e}"
    );
}

/// The code `iec61850-scl-build` generates reads the addressing through the
/// same helpers, so it skips and rejects the same references.
#[test]
fn the_build_script_helpers_check_the_built_ied_only() {
    let xml = subnetwork(
        r#"<ConnectedAP iedName="IED1" apName="AP1"/>
      <ConnectedAP iedName="UNDECLARED" apName="AP1"/>
      <ConnectedAP iedName="IED2" apName="AP9"/>"#,
    );
    let resolved = iec61850_scl::parse_scl(&xml)
        .expect("parse")
        .resolve()
        .expect("resolve");
    let raw = resolved.raw();
    let aps = iec61850_scl::__private::connected_access_points(raw, "IED1").expect("IED1");
    assert_eq!(aps.len(), 1);
    assert!(iec61850_scl::__private::gse_addresses(raw, "IED1").is_ok());
    let e = iec61850_scl::__private::connected_access_points(raw, "IED2")
        .expect_err("IED2 names an access point it lacks");
    assert_eq!(e.attribute.as_deref(), Some("apName"));
    assert!(iec61850_scl::__private::smv_addresses(raw, "IED2").is_err());
}

/// White space around a value, a line break or a tab included, is read past
/// with a warning, and a value spread over lines stays in the address.
#[test]
fn white_space_around_a_value_is_read_past() {
    let xml = ied1_ap(
        r#"<GSE ldInst="LD0" cbName="gcb1">
          <Address>
            <P type="MAC-Address">01-0C-CD-01-00-05&#32;</P>
            <P type="VLAN-ID">&#10;07B&#10;&#9;</P>
            <P type="APPID">
              3A01
            </P>
          </Address>
        </GSE>"#,
    );
    let (model, seen) = warnings(|| build(&xml, "IED1"));
    let gse = model.gse_address("LD0", "gcb1").expect("GSE");
    assert_eq!(
        gse.address.mac_address(),
        Some([0x01, 0x0c, 0xcd, 0x01, 0x00, 0x05])
    );
    assert_eq!(gse.address.vlan_id(), Some(0x07b));
    assert_eq!(gse.address.app_id(), Some(0x3a01));
    assert_eq!(gse.address.parameters().len(), 3, "nothing is left out");
    assert!(
        seen.iter()
            .any(|w| w.contains("MAC-Address") && w.contains("it is read as `01-0C-CD-01-00-05`")),
        "{seen:?}"
    );
    assert!(
        seen.iter()
            .any(|w| w.contains("VLAN-ID") && w.contains("it is read as `07B`")),
        "{seen:?}"
    );
}
