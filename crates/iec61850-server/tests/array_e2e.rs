//! Arrays served over MMS from a model built from SCL: arrays of data
//! attributes, of nested attributes and of sub-data-objects, read whole and by
//! element, written whole and by element, and described with the type the
//! read returns (IEC 61850-8-1 §8.1.2.7, §24.2.2.4.1.2 Table 138). The model is
//! served on a loopback association and driven with the MMS client, so each
//! assertion covers the parser, the model builder and the MMS projection
//! together. An array updated whole through the server raises the report
//! triggers of its elements as one batch.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iec61850_mms::mms::client::{ClientError, MmsClient, MmsClientBuilder};
use iec61850_mms::mms::pdu::common::{
    AccessResult, AlternateAccess, DataAccessError, ListOfVariableEntry, ObjectName,
};
use iec61850_mms::mms::pdu::get_name_list::ObjectClass;
use iec61850_mms::mms::pdu::type_specification::TypeSpecification;
use iec61850_mms::mms::MmsData;
use iec61850_model::{IedModel, MmsValue, NodeRef, ObjectRef, FC};
use iec61850_server::{
    AttributeAccessHandler, HandlerWriteOutcome as WriteOutcome, IedServer, IedServerConfig,
    ReadContext, ReadHandler, ReadOutcome, ServerHandle, WriteContext,
};

const DOMAIN: &str = "ArraysLD0";

/// `GGIO1.Arr` holds arrays of a basic type under ST and SP, an array of
/// structures under SP, a structure holding an array, and an array whose
/// element count names another attribute; `GGIO1.Spt` an array of
/// sub-data-objects under SP; `MHAI1.HA` an array of CMV sub-data-objects, as
/// the harmonics of HWYE are. Instance values set single elements.
const SCL: &str = r#"<SCL>
  <IED name="Arrays">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <DataSet name="Harm">
              <FCDA ldInst="LD0" lnClass="MHAI" lnInst="1" doName="HA.phsAHar(3)" daName="cVal.mag.f" fc="MX"/>
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Arr" daName="hstVal" fc="ST" ix="1"/>
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Arr" daName="cfg.lims" fc="SP"/>
              <FCDA ldInst="LD0" lnClass="MHAI" lnInst="1" doName="HA.phsAHar" fc="MX"/>
            </DataSet>
            <ReportControl name="HarmRCB" datSet="Harm" rptID="Harm" buffered="true" indexed="false" confRev="1">
              <TrgOps dchg="true"/>
              <OptFields dataRef="true" reasonCode="true"/>
            </ReportControl>
          </LN0>
          <LN lnClass="GGIO" inst="1" lnType="GGIO_T">
            <DOI name="Arr">
              <DAI name="hstVal" ix="1"><Val>7</Val></DAI>
              <DAI name="setVals" ix="2"><Val>-4</Val></DAI>
              <SDI name="pts" ix="2"><DAI name="y"><Val>1.5</Val></DAI></SDI>
              <SDI name="cfg"><DAI name="lims" ix="0"><Val>-3</Val></DAI></SDI>
            </DOI>
            <DOI name="Spt">
              <SDI name="setPts" ix="1"><DAI name="setVal"><Val>11</Val></DAI></SDI>
            </DOI>
          </LN>
          <LN lnClass="MHAI" inst="1" lnType="MHAI_T">
            <DOI name="HA">
              <SDI name="phsAHar" ix="3">
                <SDI name="cVal"><SDI name="mag"><DAI name="f"><Val>3.5</Val></DAI></SDI></SDI>
              </SDI>
            </DOI>
          </LN>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="Mod" type="ENC_T"/></LNodeType>
    <LNodeType id="GGIO_T" lnClass="GGIO">
      <DO name="Arr" type="ARR_T"/>
      <DO name="Spt" type="SPT_T"/>
    </LNodeType>
    <LNodeType id="MHAI_T" lnClass="MHAI"><DO name="HA" type="HWYE_T"/></LNodeType>
    <DOType id="ENC_T" cdc="ENC"><DA name="stVal" fc="ST" bType="BOOLEAN"/></DOType>
    <DOType id="ARR_T" cdc="HST">
      <DA name="hstVal" fc="ST" bType="INT32" count="3" dchg="true"/>
      <DA name="setVals" fc="SP" bType="INT32" count="4"/>
      <DA name="pts" fc="SP" bType="Struct" type="PT_T" count="3"/>
      <DA name="cfg" fc="SP" bType="Struct" type="CFG_T" dchg="true"/>
      <DA name="crvPts" fc="DC" bType="Struct" type="PT_T" count="maxPts"/>
      <DA name="maxPts" fc="CF" bType="INT16U"><Val>2</Val></DA>
    </DOType>
    <DOType id="SPT_T" cdc="ING"><SDO name="setPts" type="ING_T" count="2"/></DOType>
    <DOType id="ING_T" cdc="ING"><DA name="setVal" fc="SP" bType="INT32"/></DOType>
    <DOType id="HWYE_T" cdc="HWYE">
      <SDO name="phsAHar" type="CMV_T" count="4"/>
      <DA name="numHar" fc="CF" bType="INT16U"><Val>4</Val></DA>
    </DOType>
    <DOType id="CMV_T" cdc="CMV">
      <DA name="cVal" fc="MX" bType="Struct" type="VEC_T" dchg="true"/>
      <DA name="q" fc="MX" bType="Quality"/>
      <DA name="t" fc="MX" bType="Timestamp"/>
    </DOType>
    <DAType id="VEC_T"><BDA name="mag" bType="Struct" type="AV_T"/></DAType>
    <DAType id="AV_T"><BDA name="f" bType="FLOAT32"/></DAType>
    <DAType id="PT_T"><BDA name="x" bType="FLOAT32"/><BDA name="y" bType="FLOAT32"/></DAType>
    <DAType id="CFG_T">
      <BDA name="lims" bType="INT16" count="3"/>
      <BDA name="name" bType="VisString32"/>
    </DAType>
  </DataTypeTemplates>
</SCL>"#;

fn model() -> Arc<IedModel> {
    let raw = iec61850_scl::parse_scl(SCL).expect("parse");
    Arc::new(
        raw.resolve()
            .expect("resolve")
            .build_model("Arrays")
            .expect("build"),
    )
}

async fn serve(model: Arc<IedModel>) -> (ServerHandle, MmsClient) {
    serve_with(model, |_| {}).await
}

async fn serve_with(
    model: Arc<IedModel>,
    setup: impl FnOnce(&IedServer),
) -> (ServerHandle, MmsClient) {
    let server = IedServer::builder()
        .model(model)
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .config(IedServerConfig::default())
        .build()
        .expect("build the server");
    setup(&server);
    let handle = server.start().await.expect("start");
    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    client
        .connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    (handle, client)
}

async fn read(client: &mut MmsClient, item: &str) -> MmsData {
    tokio::time::timeout(Duration::from_secs(5), client.read(DOMAIN, item))
        .await
        .expect("timeout")
        .unwrap_or_else(|e| panic!("read {item}: {e:?}"))
}

async fn read_element(
    client: &mut MmsClient,
    item: &str,
    index: u32,
    component: Option<&str>,
) -> Result<MmsData, ClientError> {
    tokio::time::timeout(
        Duration::from_secs(5),
        client.read_single_array_element(DOMAIN, item, index, component),
    )
    .await
    .expect("timeout")
}

async fn write_element(
    client: &mut MmsClient,
    item: &str,
    index: u32,
    component: Option<&str>,
    value: MmsData,
) -> Result<(), ClientError> {
    tokio::time::timeout(
        Duration::from_secs(5),
        client.write_single_array_element(DOMAIN, item, index, component, value),
    )
    .await
    .expect("timeout")
}

async fn write(client: &mut MmsClient, item: &str, value: MmsData) -> Result<(), ClientError> {
    tokio::time::timeout(Duration::from_secs(5), client.write(DOMAIN, item, value))
        .await
        .expect("timeout")
}

async fn gvaa(client: &mut MmsClient, item: &str) -> Option<TypeSpecification> {
    tokio::time::timeout(
        Duration::from_secs(5),
        client.get_variable_access_attributes(DOMAIN, item),
    )
    .await
    .expect("timeout")
    .ok()
}

fn ints(values: &[i64]) -> MmsData {
    MmsData::Array(values.iter().map(|v| MmsData::Integer(*v)).collect())
}

fn point(x: f32, y: f32) -> MmsData {
    MmsData::Structure(vec![MmsData::Float32(x), MmsData::Float32(y)])
}

fn data_access(e: ClientError) -> DataAccessError {
    match e {
        ClientError::DataAccessError(e) => e,
        other => panic!("expected a data access error, got {other:?}"),
    }
}

/// Reports whether `data` has the shape `ts` describes: the same element
/// count and element shape for an array, the same member count and member
/// shapes for a structure, a scalar for a scalar.
fn has_shape(ts: &TypeSpecification, data: &MmsData) -> bool {
    match (ts, data) {
        (
            TypeSpecification::Array {
                element_count,
                element_type,
            },
            MmsData::Array(items),
        ) => {
            items.len() == *element_count as usize
                && items.iter().all(|i| has_shape(element_type, i))
        }
        (TypeSpecification::Structure { components }, MmsData::Structure(items)) => {
            components.len() == items.len()
                && components
                    .iter()
                    .zip(items)
                    .all(|(c, i)| has_shape(&c.type_spec, i))
        }
        (TypeSpecification::Array { .. } | TypeSpecification::Structure { .. }, _) => false,
        (_, MmsData::Array(_) | MmsData::Structure(_)) => false,
        _ => true,
    }
}

/// GetVariableAccessAttributes describes an array of a basic type, an array of
/// structures, an array nested in a structure and an array of
/// sub-data-objects as MMS arrays of their element type and count.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn arrays_are_described_as_mms_arrays() {
    let (handle, mut client) = serve(model()).await;
    let set_vals = gvaa(&mut client, "GGIO1$SP$Arr$setVals").await;
    let pts = gvaa(&mut client, "GGIO1$SP$Arr$pts").await;
    let lims = gvaa(&mut client, "GGIO1$SP$Arr$cfg$lims").await;
    let crv = gvaa(&mut client, "GGIO1$DC$Arr$crvPts").await;
    let har = gvaa(&mut client, "MHAI1$MX$HA$phsAHar").await;
    let past_array = gvaa(&mut client, "GGIO1$SP$Arr$pts$x").await;
    handle.stop().await;

    let array = |ts: Option<TypeSpecification>| match ts {
        Some(TypeSpecification::Array {
            element_count,
            element_type,
        }) => (element_count, *element_type),
        other => panic!("expected an array, got {other:?}"),
    };
    let (n, element) = array(set_vals);
    assert_eq!(n, 4);
    assert!(matches!(
        element,
        TypeSpecification::Integer { width_bits: 32 }
    ));
    let (n, element) = array(pts);
    assert_eq!(n, 3);
    let TypeSpecification::Structure { components } = element else {
        panic!("pts holds structures");
    };
    let names: Vec<&str> = components.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["x", "y"]);
    let (n, element) = array(lims);
    assert_eq!(n, 3);
    assert!(matches!(
        element,
        TypeSpecification::Integer { width_bits: 16 }
    ));
    assert_eq!(array(crv).0, 2);
    let (n, element) = array(har);
    assert_eq!(n, 4);
    let TypeSpecification::Structure { components } = element else {
        panic!("phsAHar holds structures");
    };
    let names: Vec<&str> = components.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["cVal", "q", "t"]);
    // An element has no name, so no flattened name reaches past an array.
    assert!(past_array.is_none());
}

/// Every name GetNameList lists reads a value of the shape
/// GetVariableAccessAttributes describes for it, arrays and the logical
/// nodes, groups and data objects holding them included.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_listed_name_reads_the_shape_it_is_described_with() {
    let (handle, mut client) = serve(model()).await;
    let mut names = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let (page, more) = tokio::time::timeout(
            Duration::from_secs(5),
            client.get_name_list(ObjectClass::NamedVariable, Some(DOMAIN), cursor.as_deref()),
        )
        .await
        .expect("timeout")
        .expect("GetNameList");
        cursor = page.last().cloned();
        names.extend(page);
        if !more {
            break;
        }
    }
    let mut checked = Vec::new();
    for name in &names {
        let ts = gvaa(&mut client, name)
            .await
            .unwrap_or_else(|| panic!("{name} has no type description"));
        let value = read(&mut client, name).await;
        assert!(has_shape(&ts, &value), "{name}: {ts:?} read as {value:?}");
        checked.push(name.as_str());
    }
    handle.stop().await;
    for array in [
        "GGIO1$ST$Arr$hstVal",
        "GGIO1$SP$Arr$pts",
        "GGIO1$SP$Arr$cfg$lims",
        "GGIO1$SP$Spt$setPts",
        "MHAI1$MX$HA$phsAHar",
        "MHAI1$MX",
        "MHAI1",
    ] {
        assert!(checked.contains(&array), "{array} is not listed");
    }
}

/// A read returns a whole array with the values the SCL instance gives single
/// elements, and an alternate access reads one element, or a member below
/// one, of an array of attributes and of an array of sub-data-objects.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn arrays_read_whole_and_by_element() {
    let (handle, mut client) = serve(model()).await;
    let hst = read(&mut client, "GGIO1$ST$Arr$hstVal").await;
    let pts = read(&mut client, "GGIO1$SP$Arr$pts").await;
    let lims = read(&mut client, "GGIO1$SP$Arr$cfg$lims").await;
    let element = read_element(&mut client, "GGIO1$ST$Arr$hstVal", 1, None).await;
    let y = read_element(&mut client, "GGIO1$SP$Arr$pts", 2, Some("y")).await;
    let whole_point = read_element(&mut client, "GGIO1$SP$Arr$pts", 2, None).await;
    let har = read(&mut client, "MHAI1$MX$HA$phsAHar").await;
    let f = read_element(&mut client, "MHAI1$MX$HA$phsAHar", 3, Some("cVal$mag$f")).await;
    let set_val = read_element(&mut client, "GGIO1$SP$Spt$setPts", 1, Some("setVal")).await;
    handle.stop().await;

    assert_eq!(hst, ints(&[0, 7, 0]));
    assert_eq!(
        pts,
        MmsData::Array(vec![point(0.0, 0.0), point(0.0, 0.0), point(0.0, 1.5)])
    );
    assert_eq!(lims, ints(&[-3, 0, 0]));
    assert_eq!(element.expect("hstVal(1)"), MmsData::Integer(7));
    assert_eq!(y.expect("pts(2).y"), MmsData::Float32(1.5));
    assert_eq!(whole_point.expect("pts(2)"), point(0.0, 1.5));
    let MmsData::Array(elements) = har else {
        panic!("phsAHar read as {har:?}");
    };
    assert_eq!(elements.len(), 4);
    let MmsData::Structure(members) = &elements[3] else {
        panic!("an element of phsAHar is a structure");
    };
    assert_eq!(
        members[0],
        MmsData::Structure(vec![MmsData::Structure(vec![MmsData::Float32(3.5)])])
    );
    assert_eq!(f.expect("phsAHar(3).cVal.mag.f"), MmsData::Float32(3.5));
    assert_eq!(set_val.expect("setPts(1).setVal"), MmsData::Integer(11));
}

/// The alternate access of IEC 61850-8-1 Table 139, components down to the
/// array, an index and components below it, reads the same value as the
/// flattened name with an index; an index out of range, an index on a
/// scalar and a component an element does not hold are refused, and a
/// flattened name carrying an index names nothing, since IEC 61850-8-1
/// §7.3.1 builds flattened names from component names alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn element_access_follows_table_139_and_refuses_what_names_nothing() {
    let (handle, mut client) = serve(model()).await;
    let entry = |item: &str, access: AlternateAccess| {
        ListOfVariableEntry::with_alt_access(
            ObjectName::DomainSpecific {
                domain_id: DOMAIN.to_string(),
                item_id: item.to_string(),
            },
            access,
        )
    };
    let results = tokio::time::timeout(
        Duration::from_secs(5),
        client.read_list(vec![
            entry(
                "MHAI1",
                AlternateAccess::component_then(
                    "MX$HA$phsAHar",
                    AlternateAccess::index_component(3, "cVal$mag$f").unwrap(),
                )
                .unwrap(),
            ),
            entry("GGIO1$ST$Arr$hstVal", AlternateAccess::index(3)),
            entry("GGIO1$SP$Arr$cfg$name", AlternateAccess::index(0)),
            entry(
                "GGIO1$SP$Arr$pts",
                AlternateAccess::index_component(0, "z").unwrap(),
            ),
            entry("MHAI1$MX$HA", AlternateAccess::index(0)),
            ListOfVariableEntry::name(ObjectName::DomainSpecific {
                domain_id: DOMAIN.to_string(),
                item_id: "GGIO1$ST$Arr$hstVal(1)".to_string(),
            }),
        ]),
    )
    .await
    .expect("timeout")
    .expect("read");
    handle.stop().await;

    assert_eq!(
        results,
        vec![
            AccessResult::Success(MmsData::Float32(3.5)),
            AccessResult::Failure(DataAccessError::TypeInconsistent),
            AccessResult::Failure(DataAccessError::TypeInconsistent),
            AccessResult::Failure(DataAccessError::ObjectNonExistent),
            AccessResult::Failure(DataAccessError::TypeInconsistent),
            AccessResult::Failure(DataAccessError::ObjectNonExistent),
        ]
    );
}

/// A write of one element, of a basic type, of a structure member, or of a
/// member of an element of an array of sub-data-objects, changes that element
/// alone, and the change reads back whole and by element.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_elements_write_and_read_back() {
    let (handle, mut client) = serve(model()).await;
    write_element(
        &mut client,
        "GGIO1$SP$Arr$setVals",
        1,
        None,
        MmsData::Integer(42),
    )
    .await
    .expect("setVals(1)");
    write_element(
        &mut client,
        "GGIO1$SP$Arr$pts",
        0,
        Some("x"),
        MmsData::Float32(2.5),
    )
    .await
    .expect("pts(0).x");
    write_element(&mut client, "GGIO1$SP$Arr$pts", 1, None, point(4.0, 5.0))
        .await
        .expect("pts(1)");
    write_element(
        &mut client,
        "GGIO1$SP$Spt$setPts",
        0,
        Some("setVal"),
        MmsData::Integer(5),
    )
    .await
    .expect("setPts(0).setVal");
    write_element(
        &mut client,
        "GGIO1$SP$Arr$cfg$lims",
        2,
        None,
        MmsData::Integer(9),
    )
    .await
    .expect("cfg.lims(2)");
    let set_vals = read(&mut client, "GGIO1$SP$Arr$setVals").await;
    let pts = read(&mut client, "GGIO1$SP$Arr$pts").await;
    let set_pts = read(&mut client, "GGIO1$SP$Spt$setPts").await;
    let lim = read_element(&mut client, "GGIO1$SP$Arr$cfg$lims", 2, None).await;
    handle.stop().await;

    assert_eq!(set_vals, ints(&[0, 42, -4, 0]));
    assert_eq!(
        pts,
        MmsData::Array(vec![point(2.5, 0.0), point(4.0, 5.0), point(0.0, 1.5)])
    );
    assert_eq!(
        set_pts,
        MmsData::Array(vec![
            MmsData::Structure(vec![MmsData::Integer(5)]),
            MmsData::Structure(vec![MmsData::Integer(11)]),
        ])
    );
    assert_eq!(lim.expect("cfg.lims(2)"), MmsData::Integer(9));
}

/// A whole array is written with exactly its element count, each element held
/// to the declared type; another count, an element out of range, an index
/// past the end and an element of a read-only constraint are refused and
/// change nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn whole_arrays_write_with_their_element_count_and_type() {
    let (handle, mut client) = serve(model()).await;
    write(&mut client, "GGIO1$SP$Arr$setVals", ints(&[1, 2, 3, 4]))
        .await
        .expect("setVals");
    let short = write(&mut client, "GGIO1$SP$Arr$setVals", ints(&[1, 2, 3])).await;
    let scalar = write(&mut client, "GGIO1$SP$Arr$setVals", MmsData::Integer(1)).await;
    let too_wide = write(&mut client, "GGIO1$SP$Arr$cfg$lims", ints(&[1, 40_000, 3])).await;
    let too_wide_element = write_element(
        &mut client,
        "GGIO1$SP$Arr$cfg$lims",
        1,
        None,
        MmsData::Integer(40_000),
    )
    .await;
    let past_end = write_element(
        &mut client,
        "GGIO1$SP$Arr$setVals",
        4,
        None,
        MmsData::Integer(1),
    )
    .await;
    let read_only = write_element(
        &mut client,
        "GGIO1$ST$Arr$hstVal",
        0,
        None,
        MmsData::Integer(1),
    )
    .await;
    let set_vals = read(&mut client, "GGIO1$SP$Arr$setVals").await;
    let lims = read(&mut client, "GGIO1$SP$Arr$cfg$lims").await;
    let hst = read(&mut client, "GGIO1$ST$Arr$hstVal").await;
    handle.stop().await;

    assert_eq!(
        data_access(short.expect_err("a short array")),
        DataAccessError::TypeInconsistent
    );
    assert_eq!(
        data_access(scalar.expect_err("a scalar")),
        DataAccessError::TypeInconsistent
    );
    assert_eq!(
        data_access(too_wide.expect_err("40000 in an INT16")),
        DataAccessError::ObjectValueInvalid
    );
    assert_eq!(
        data_access(too_wide_element.expect_err("40000 in an INT16 element")),
        DataAccessError::ObjectValueInvalid
    );
    assert_eq!(
        data_access(past_end.expect_err("index 4 of 4")),
        DataAccessError::TypeInconsistent
    );
    assert_eq!(
        data_access(read_only.expect_err("an ST element")),
        DataAccessError::ObjectAccessDenied
    );
    assert_eq!(set_vals, ints(&[1, 2, 3, 4]));
    assert_eq!(lims, ints(&[-3, 0, 0]));
    assert_eq!(hst, ints(&[0, 7, 0]));
}

/// The model reaches an element through an object reference with an index,
/// and a value stored into an element is what a client reads, whole and by
/// element.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_element_updated_in_the_model_reads_back() {
    let model = model();
    let r = ObjectRef::parse("ArraysLD0/MHAI1$MX$HA$phsAHar(2)$cVal$mag$f").expect("reference");
    let Some(NodeRef::Da(f)) = model.node_by_object_ref(&r) else {
        panic!("the element resolves to an attribute");
    };
    f.store(MmsValue::Float32(9.25));
    let r = ObjectRef::parse("ArraysLD0/GGIO1$ST$Arr$hstVal(0)").expect("reference");
    let Some(NodeRef::Da(h)) = model.node_by_object_ref(&r) else {
        panic!("the element resolves to an attribute");
    };
    h.store(MmsValue::Integer(-1));
    let (handle, mut client) = serve(model).await;
    let f = read_element(&mut client, "MHAI1$MX$HA$phsAHar", 2, Some("cVal$mag$f")).await;
    let hst = read(&mut client, "GGIO1$ST$Arr$hstVal").await;
    handle.stop().await;

    assert_eq!(f.expect("phsAHar(2)"), MmsData::Float32(9.25));
    assert_eq!(hst, ints(&[-1, 7, 0]));
}

/// A write handler that records the values it is asked about and answers
/// with `outcome`.
#[derive(Debug)]
struct Recording {
    seen: std::sync::Mutex<Vec<(String, MmsValue)>>,
    outcome: WriteOutcome,
}

impl AttributeAccessHandler for Recording {
    fn on_write(&self, ctx: &WriteContext<'_>, value: &MmsValue) -> WriteOutcome {
        self.seen
            .lock()
            .unwrap()
            .push((ctx.path.to_string(), value.clone()));
        self.outcome.clone()
    }
}

/// A read handler that answers with a fixed value.
#[derive(Debug)]
struct Fixed(MmsValue);

impl ReadHandler for Fixed {
    fn read(&self, _ctx: &ReadContext<'_>) -> ReadOutcome {
        ReadOutcome::CacheHit(self.0.clone())
    }
}

/// A write of one element is a write of the array and of every node above
/// it: the handler on the array decides it with the whole array, the element
/// replaced by the written value, and its refusal leaves the element as it
/// was.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_handler_on_an_array_decides_a_write_of_an_element() {
    let accept = Arc::new(Recording {
        seen: std::sync::Mutex::new(Vec::new()),
        outcome: WriteOutcome::Accept,
    });
    let refuse = Arc::new(Recording {
        seen: std::sync::Mutex::new(Vec::new()),
        outcome: WriteOutcome::Reject(DataAccessError::ObjectAccessDenied),
    });
    let (accept_h, refuse_h) = (Arc::clone(&accept), Arc::clone(&refuse));
    let (handle, mut client) = serve_with(model(), move |server| {
        server
            .install_write_access_handler("GGIO1$SP$Arr$setVals", accept_h)
            .expect("install");
        server
            .install_write_access_handler("GGIO1$SP$Spt", refuse_h)
            .expect("install");
    })
    .await;
    write_element(
        &mut client,
        "GGIO1$SP$Arr$setVals",
        3,
        None,
        MmsData::Integer(8),
    )
    .await
    .expect("setVals(3)");
    let refused = write_element(
        &mut client,
        "GGIO1$SP$Spt$setPts",
        1,
        Some("setVal"),
        MmsData::Integer(99),
    )
    .await;
    let set_vals = read(&mut client, "GGIO1$SP$Arr$setVals").await;
    let set_pts = read(&mut client, "GGIO1$SP$Spt$setPts").await;
    handle.stop().await;

    let ints_value = |v: &[i64]| MmsValue::Array(v.iter().map(|i| MmsValue::Integer(*i)).collect());
    assert_eq!(
        *accept.seen.lock().unwrap(),
        vec![(
            "GGIO1$SP$Arr$setVals".to_string(),
            ints_value(&[0, 0, -4, 8])
        )]
    );
    assert_eq!(set_vals, ints(&[0, 0, -4, 8]));
    assert_eq!(
        data_access(refused.expect_err("the handler refuses")),
        DataAccessError::ObjectAccessDenied
    );
    let one = |v| MmsValue::Structure(vec![MmsValue::Integer(v)]);
    assert_eq!(
        *refuse.seen.lock().unwrap(),
        vec![(
            "GGIO1$SP$Spt".to_string(),
            MmsValue::Structure(vec![MmsValue::Array(vec![one(0), one(99)])])
        )]
    );
    assert_eq!(
        set_pts,
        MmsData::Array(vec![
            MmsData::Structure(vec![MmsData::Integer(0)]),
            MmsData::Structure(vec![MmsData::Integer(11)]),
        ])
    );
}

/// A read handler on an array answers reads of the array and of its
/// elements, which select from its value; a value that is not an array of
/// the element count is not sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_read_handler_on_an_array_answers_its_elements() {
    let (handle, mut client) = serve_with(model(), |server| {
        server
            .install_read_handler(
                "GGIO1$ST$Arr$hstVal",
                Arc::new(Fixed(MmsValue::Array(vec![
                    MmsValue::Integer(4),
                    MmsValue::Integer(5),
                    MmsValue::Integer(6),
                ]))),
            )
            .expect("install");
        server
            .install_read_handler(
                "MHAI1$MX$HA$phsAHar",
                Arc::new(Fixed(MmsValue::Array(vec![MmsValue::Integer(1)]))),
            )
            .expect("install");
    })
    .await;
    let whole = read(&mut client, "GGIO1$ST$Arr$hstVal").await;
    let element = read_element(&mut client, "GGIO1$ST$Arr$hstVal", 2, None).await;
    let misshapen = tokio::time::timeout(
        Duration::from_secs(5),
        client.read(DOMAIN, "MHAI1$MX$HA$phsAHar"),
    )
    .await
    .expect("timeout");
    handle.stop().await;

    assert_eq!(whole, ints(&[4, 5, 6]));
    assert_eq!(element.expect("hstVal(2)"), MmsData::Integer(6));
    assert_eq!(
        data_access(misshapen.expect_err("one element of four")),
        DataAccessError::TypeInconsistent
    );
}

/// `PTOC1.Crv` holds two settings declared under FC=SE, an array of INT32
/// and an array of structures, each with its FC=SG view; the SCL gives one
/// element of each a value per setting group.
const SETTINGS_SCL: &str = r#"<SCL>
  <IED name="Arrays">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <SettingControl numOfSGs="2" actSG="1"/>
          </LN0>
          <LN lnClass="PTOC" inst="1" lnType="PTOC_T">
            <DOI name="Crv">
              <DAI name="vals" ix="1"><Val sGroup="1">10</Val><Val sGroup="2">20</Val></DAI>
              <SDI name="pts" ix="0"><DAI name="y"><Val sGroup="1">1.5</Val><Val sGroup="2">2.5</Val></DAI></SDI>
            </DOI>
          </LN>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="Mod" type="ENC_T"/></LNodeType>
    <LNodeType id="PTOC_T" lnClass="PTOC"><DO name="Crv" type="CRV_T"/></LNodeType>
    <DOType id="ENC_T" cdc="ENC"><DA name="stVal" fc="ST" bType="BOOLEAN"/></DOType>
    <DOType id="CRV_T" cdc="CSG">
      <DA name="vals" fc="SE" bType="INT32" count="3"/>
      <DA name="pts" fc="SE" bType="Struct" type="PT_T" count="2"/>
    </DOType>
    <DAType id="PT_T"><BDA name="x" bType="FLOAT32"/><BDA name="y" bType="FLOAT32"/></DAType>
  </DataTypeTemplates>
</SCL>"#;

async fn serve_settings() -> (ServerHandle, MmsClient) {
    let raw = iec61850_scl::parse_scl(SETTINGS_SCL).expect("parse");
    let model = raw
        .resolve()
        .expect("resolve")
        .build_model("Arrays")
        .expect("build");
    serve(Arc::new(model)).await
}

/// An edit of FC=SE array settings, one element of an array of INT32 and a
/// whole array of structures, becomes the FC=SG value once the active group
/// is committed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn committed_array_settings_reach_the_sg_view() {
    let (handle, mut client) = serve_settings().await;
    write(&mut client, "LLN0$SP$SGCB$EditSG", MmsData::Unsigned(1))
        .await
        .expect("edit the active group");
    write_element(
        &mut client,
        "PTOC1$SE$Crv$vals",
        2,
        None,
        MmsData::Integer(7),
    )
    .await
    .expect("vals(2)");
    write(
        &mut client,
        "PTOC1$SE$Crv$pts",
        MmsData::Array(vec![point(3.0, 4.0), point(5.0, 6.0)]),
    )
    .await
    .expect("pts");
    let before = read(&mut client, "PTOC1$SG$Crv$vals").await;
    write(&mut client, "LLN0$SP$SGCB$CnfEdit", MmsData::Boolean(true))
        .await
        .expect("commit");
    let vals = read(&mut client, "PTOC1$SG$Crv$vals").await;
    let pts = read(&mut client, "PTOC1$SG$Crv$pts").await;
    handle.stop().await;

    assert_eq!(before, ints(&[0, 10, 0]));
    assert_eq!(vals, ints(&[0, 10, 7]));
    assert_eq!(pts, MmsData::Array(vec![point(3.0, 4.0), point(5.0, 6.0)]));
}

/// The values the SCL gives array elements per setting group are the FC=SG
/// values of the group that is active, and follow a change of the active
/// group.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn array_settings_follow_the_active_group() {
    let (handle, mut client) = serve_settings().await;
    let vals_1 = read(&mut client, "PTOC1$SG$Crv$vals").await;
    let pts_1 = read(&mut client, "PTOC1$SG$Crv$pts").await;
    write(&mut client, "LLN0$SP$SGCB$ActSG", MmsData::Unsigned(2))
        .await
        .expect("activate group 2");
    let vals_2 = read(&mut client, "PTOC1$SG$Crv$vals").await;
    let pts_2 = read(&mut client, "PTOC1$SG$Crv$pts").await;
    write(&mut client, "LLN0$SP$SGCB$ActSG", MmsData::Unsigned(1))
        .await
        .expect("activate group 1");
    let vals_back = read(&mut client, "PTOC1$SG$Crv$vals").await;
    handle.stop().await;

    assert_eq!(vals_1, ints(&[0, 10, 0]));
    assert_eq!(
        pts_1,
        MmsData::Array(vec![point(0.0, 1.5), point(0.0, 0.0)])
    );
    assert_eq!(vals_2, ints(&[0, 20, 0]));
    assert_eq!(
        pts_2,
        MmsData::Array(vec![point(0.0, 2.5), point(0.0, 0.0)])
    );
    assert_eq!(vals_back, ints(&[0, 10, 0]));
}

/// A running server on `model()` whose BRCB `brcbHst` reports the elements 0
/// and 2 of `GGIO1.Arr.hstVal` on a data change, with no buffer time, so one
/// report per trigger batch, to an MMS association that enabled it.
async fn start_reporting() -> (IedServer, ServerHandle, MmsClient) {
    use iec61850_server::reporting::{Brcb, BufferedReportControl};
    use iec61850_server::{Dataset, DatasetEntry, OptFlds, TriggerOptions};

    let server = IedServer::builder()
        .model(model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()
        .expect("build server");
    let model = server.model();
    let mut ds = Dataset::new("LLN0$dsHst");
    for index in [0, 2] {
        let reference = format!("{DOMAIN}/GGIO1$ST$Arr$hstVal({index})");
        let Some(NodeRef::Da(da)) =
            model.node_by_object_ref(&ObjectRef::parse(&reference).unwrap())
        else {
            panic!("{reference} is an element");
        };
        ds.push(DatasetEntry::new(reference.clone(), Arc::clone(&da.value)));
    }
    let brcb = Brcb::new("brcbHst", "LLN0$dsHst")
        .with_trg_ops(TriggerOptions::DATA_CHANGED)
        .with_opt_flds(OptFlds::REASON | OptFlds::DATA_SET);
    server
        .register_brcb(
            BufferedReportControl::new(format!("{DOMAIN}/LLN0$BR$brcbHst"), brcb),
            ds,
        )
        .expect("register_brcb");
    let handle = server.start().await.expect("start");
    let mut client = connect_to(&handle).await;
    write(
        &mut client,
        "LLN0$BR$brcbHst$RptEna",
        MmsData::Boolean(true),
    )
    .await
    .expect("enable the control block");
    (server, handle, client)
}

async fn connect_to(handle: &ServerHandle) -> MmsClient {
    let mut client = MmsClientBuilder::new()
        .connect_timeout_ms(3_000)
        .request_timeout_ms(3_000)
        .build();
    client
        .connect("127.0.0.1", handle.bound_addr.port())
        .await
        .expect("connect");
    client
}

/// The inclusion bitmap and the values of the next report; fails after four
/// seconds without one.
async fn next_report(client: &mut MmsClient) -> (Vec<bool>, Vec<MmsValue>) {
    let (inclusion, _, values) = next_report_with_references(client).await;
    (inclusion, values)
}

/// The inclusion bitmap, the data references and the values of the next
/// report; fails after four seconds without one.
async fn next_report_with_references(
    client: &mut MmsClient,
) -> (Vec<bool>, Vec<String>, Vec<MmsValue>) {
    use iec61850_client::mms_compat::mms_data_to_mms_value;
    use iec61850_client::report::parse::parse_report;
    use iec61850_mms::mms::pdu::information_report::{
        decode_information_report, VariableAccessSpec,
    };

    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        assert!(!remaining.is_zero(), "no report arrived");
        let Some(inner) = client
            .recv_unconfirmed_pdu_with_timeout(remaining)
            .await
            .expect("receive")
        else {
            continue;
        };
        let report = decode_information_report(&inner).expect("decode information report");
        if !matches!(
            &report.variable_access_spec,
            VariableAccessSpec::VariableListName(ObjectName::VmdSpecific(s)) if s == "RPT"
        ) {
            continue;
        }
        let elements = report
            .list_of_access_result
            .iter()
            .map(mms_data_to_mms_value)
            .collect();
        let parsed = parse_report(&MmsValue::Array(elements)).expect("parse report");
        return (
            parsed.inclusion_bits,
            parsed.data_references,
            parsed.data_values,
        );
    }
}

/// `GGIO1.Arr.hstVal` of the model `server` serves.
fn with_hst_val<R>(server: &IedServer, f: impl FnOnce(&iec61850_model::DataAttribute) -> R) -> R {
    let model = server.model();
    let r = ObjectRef::parse(&format!("{DOMAIN}/GGIO1$ST$Arr$hstVal")).unwrap();
    match model.node_by_object_ref(&r) {
        Some(NodeRef::Da(da)) => f(da),
        _ => panic!("hstVal is an attribute"),
    }
}

/// An update of a whole array stores every element and goes out as one
/// report holding every member it changed; an update of one element is
/// reported with that element alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_array_update_is_reported_as_one_batch() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (server, handle, mut client) = start_reporting().await;

        with_hst_val(&server, |hst| {
            server.update_array(
                hst,
                MmsValue::Array(vec![
                    MmsValue::Integer(1),
                    MmsValue::Integer(7),
                    MmsValue::Integer(3),
                ]),
            )
        })
        .expect("update_array");
        assert_eq!(
            next_report(&mut client).await,
            (
                vec![true, true],
                vec![MmsValue::Integer(1), MmsValue::Integer(3)]
            )
        );
        assert_eq!(
            read(&mut client, "GGIO1$ST$Arr$hstVal").await,
            ints(&[1, 7, 3])
        );

        with_hst_val(&server, |hst| {
            server.update_int32(hst.element(2).unwrap(), 9)
        })
        .expect("update one element");
        assert_eq!(
            next_report(&mut client).await,
            (vec![false, true], vec![MmsValue::Integer(9)])
        );

        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// Entries in the buffer of `brcbHst`.
fn brcb_hst_entries(server: &IedServer) -> usize {
    let brcb = server
        .reporting_engine()
        .lock()
        .unwrap()
        .get_brcb(&format!("{DOMAIN}/LLN0$BR$brcbHst"))
        .expect("brcbHst is registered");
    let entries = brcb.lock_buffer().unwrap().len();
    entries
}

/// While the data model is locked, the triggers of an array update wait for
/// the release and then go out as one report. With no buffer time a trigger
/// is buffered as it is raised, so the buffer staying as it was while the
/// lock is held shows that the triggers were held back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_array_update_under_the_model_lock_is_reported_on_release() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (server, handle, mut client) = start_reporting().await;
        let before = brcb_hst_entries(&server);

        let guard = server.lock_data_model().expect("lock the data model");
        with_hst_val(&server, |hst| {
            server.update_array(
                hst,
                MmsValue::Array(vec![
                    MmsValue::Integer(4),
                    MmsValue::Integer(7),
                    MmsValue::Integer(6),
                ]),
            )
        })
        .expect("update_array");
        assert_eq!(
            brcb_hst_entries(&server),
            before,
            "nothing is buffered while the model is locked"
        );
        drop(guard);
        assert_eq!(
            brcb_hst_entries(&server),
            before + 1,
            "the release buffers the update as one entry"
        );
        assert_eq!(
            next_report(&mut client).await,
            (
                vec![true, true],
                vec![MmsValue::Integer(4), MmsValue::Integer(6)]
            )
        );

        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// An array update of another element count or element variant, or on an
/// attribute that is not an array, is refused and changes no element.
#[test]
fn an_array_update_of_another_shape_changes_nothing() {
    let server = IedServer::builder()
        .model(model())
        .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .build()
        .expect("build server");
    with_hst_val(&server, |hst| {
        for bad in [
            MmsValue::Array(vec![MmsValue::Integer(1), MmsValue::Integer(2)]),
            MmsValue::Array(vec![
                MmsValue::Integer(1),
                MmsValue::Float32(2.0),
                MmsValue::Integer(3),
            ]),
            MmsValue::Structure(vec![MmsValue::Integer(1); 3]),
        ] {
            assert!(
                matches!(
                    server.update_array(hst, bad.clone()),
                    Err(iec61850_server::ServerError::TypeMismatch { .. })
                ),
                "{bad:?}"
            );
        }
        assert!(matches!(
            server.update_array(hst.element(0).unwrap(), MmsValue::Array(vec![])),
            Err(iec61850_server::ServerError::TypeMismatch { .. })
        ));
        assert_eq!(
            hst.snapshot(),
            MmsValue::Array(vec![
                MmsValue::Integer(0),
                MmsValue::Integer(7),
                MmsValue::Integer(0)
            ])
        );
    });
}

/// `register_from_model` binds a data set member that names an array element,
/// by an index in its name or its `ix`, to that element, with the DataRef of
/// IEC 61850-8-1 §8.1.3.2.4, the index after the array name; a member naming
/// a whole array, of nested attributes or of sub-data-objects, is one member
/// whose value is the MMS array, reported whole when any element changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn model_data_sets_bind_array_elements() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let server = IedServer::builder()
            .model(model())
            .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .build()
            .expect("build server");
        let summary = server.register_from_model().expect("register_from_model");
        assert_eq!(summary.data_sets, 1);
        let handle = server.start().await.expect("start");
        let mut client = connect_to(&handle).await;

        let values = tokio::time::timeout(
            Duration::from_secs(5),
            client.read_named_variable_list_values(DOMAIN, "LLN0$Harm"),
        )
        .await
        .expect("timeout")
        .expect("GetDataSetValues");
        assert_eq!(
            values,
            vec![
                AccessResult::Success(MmsData::Float32(3.5)),
                AccessResult::Success(MmsData::Integer(7)),
                AccessResult::Success(ints(&[-3, 0, 0])),
                AccessResult::Success(har_value(3.5)),
            ]
        );

        write(
            &mut client,
            "LLN0$BR$HarmRCB$RptEna",
            MmsData::Boolean(true),
        )
        .await
        .expect("enable the control block");
        with_hst_val(&server, |hst| {
            server.update_array(
                hst,
                MmsValue::Array(vec![
                    MmsValue::Integer(5),
                    MmsValue::Integer(8),
                    MmsValue::Integer(5),
                ]),
            )
        })
        .expect("update_array");
        assert_eq!(
            next_report_with_references(&mut client).await,
            (
                vec![false, true, false, false],
                vec![format!("{DOMAIN}/GGIO1$ST$Arr$hstVal(1)")],
                vec![MmsValue::Integer(8)],
            )
        );

        let model = server.model();
        let r = ObjectRef::parse(&format!("{DOMAIN}/MHAI1$MX$HA$phsAHar(3)$cVal$mag$f")).unwrap();
        let Some(NodeRef::Da(f)) = model.node_by_object_ref(&r) else {
            panic!("the element resolves to an attribute");
        };
        server.update_float32(f, 4.5).expect("update_float32");
        let (inclusion, references, values) = next_report_with_references(&mut client).await;
        assert_eq!(inclusion, vec![true, false, false, true]);
        assert_eq!(
            references,
            vec![
                format!("{DOMAIN}/MHAI1$MX$HA$phsAHar(3)$cVal$mag$f"),
                format!("{DOMAIN}/MHAI1$MX$HA$phsAHar"),
            ]
        );
        assert_eq!(values[0], MmsValue::Float32(4.5));
        assert_eq!(
            iec61850_client::mms_compat::mms_value_to_mms_data(&values[1]),
            har_value(4.5)
        );

        // A member naming an array of nested attributes is reported whole.
        let r = ObjectRef::parse(&format!("{DOMAIN}/GGIO1$SP$Arr$cfg$lims(2)")).unwrap();
        let Some(NodeRef::Da(lim)) = model.node_by_object_ref(&r) else {
            panic!("the element resolves to an attribute");
        };
        server.update_int32(lim, 4).expect("update_int32");
        assert_eq!(
            next_report_with_references(&mut client).await,
            (
                vec![false, false, true, false],
                vec![format!("{DOMAIN}/GGIO1$SP$Arr$cfg$lims")],
                vec![MmsValue::Array(vec![
                    MmsValue::Integer(-3),
                    MmsValue::Integer(0),
                    MmsValue::Integer(4)
                ])],
            )
        );

        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// The MX value of `MHAI1.HA.phsAHar`: four elements of `cVal`, `q` and `t`,
/// the fourth with `cVal.mag.f` equal to `f`.
fn har_value(f: f32) -> MmsData {
    let element = |f: f32| {
        MmsData::Structure(vec![
            MmsData::Structure(vec![MmsData::Structure(vec![MmsData::Float32(f)])]),
            MmsData::BitString {
                padding: 3,
                data: vec![0, 0],
            },
            MmsData::UtcTime([0; 8]),
        ])
    };
    MmsData::Array(vec![element(0.0), element(0.0), element(0.0), element(f)])
}

/// A model data set member whose index is past the end of its array, or that
/// carries an index on a path holding no array, fails the registration.
#[test]
fn model_data_set_members_naming_no_element_fail_the_registration() {
    for (path, index) in [(vec!["Arr", "hstVal"], 3), (vec!["Arr", "cfg", "name"], 0)] {
        let mut model = iec61850_scl::parse_scl(SCL)
            .expect("parse")
            .resolve()
            .expect("resolve")
            .build_model("Arrays")
            .expect("build");
        // The model builder refuses such a member; one placed in a built model
        // reaches the check of the server.
        let entry = &mut model.lds[0].lns[0].datasets[0].entries[1];
        entry.do_path = path.iter().map(|s| s.to_string()).collect();
        entry.fc = if path.len() == 2 { FC::St } else { FC::Sp };
        entry.array_index = Some(index);
        let server = IedServer::builder()
            .model(Arc::new(model))
            .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .build()
            .expect("build server");
        assert!(
            matches!(
                server.register_from_model(),
                Err(iec61850_server::ServerError::InvalidModel(_))
            ),
            "{path:?}({index}) accepted"
        );
    }
}

/// GetDataSetDirectory lists a member naming an array element as the variable
/// naming the array with an alternate access of the index and then each
/// component (IEC 61850-8-1 §24.2.2.4.1.3 Table 140), and a member naming a
/// whole array by its name alone; the client maps both back to IEC
/// references.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn data_set_directory_names_array_elements_by_alternate_access() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (handle, mut client) = serve_with(model(), |server| {
            server.register_from_model().expect("register_from_model");
        })
        .await;
        let named = |item: &str| ObjectName::DomainSpecific {
            domain_id: DOMAIN.into(),
            item_id: item.into(),
        };

        let dir = tokio::time::timeout(
            Duration::from_secs(5),
            client.get_named_variable_list_attributes(DOMAIN, "LLN0$Harm"),
        )
        .await
        .expect("timeout")
        .expect("GetNamedVariableListAttributes");
        assert_eq!(
            dir.list_of_variable,
            vec![
                ListOfVariableEntry::with_alt_access(
                    named("MHAI1$MX$HA$phsAHar"),
                    AlternateAccess::index_component(3, "cVal$mag$f").unwrap()
                ),
                ListOfVariableEntry::with_alt_access(
                    named("GGIO1$ST$Arr$hstVal"),
                    AlternateAccess::index(1)
                ),
                ListOfVariableEntry::name(named("GGIO1$SP$Arr$cfg$lims")),
                ListOfVariableEntry::name(named("MHAI1$MX$HA$phsAHar")),
            ]
        );

        let conn = iec61850_client::IedConnection::with_mms_client(
            MmsClientBuilder::new()
                .connect_timeout_ms(3_000)
                .request_timeout_ms(3_000)
                .build(),
        );
        tokio::time::timeout(
            Duration::from_secs(5),
            conn.connect("127.0.0.1", handle.bound_addr.port()),
        )
        .await
        .expect("timeout")
        .expect("connect");
        let dir = tokio::time::timeout(
            Duration::from_secs(5),
            conn.get_data_set_directory(&format!("{DOMAIN}/LLN0.Harm")),
        )
        .await
        .expect("timeout")
        .expect("get_data_set_directory");
        let members: Vec<(String, FC)> = dir
            .members
            .iter()
            .map(|m| (m.reference.clone(), m.fc))
            .collect();
        assert_eq!(
            members,
            vec![
                (format!("{DOMAIN}/MHAI1.HA.phsAHar(3).cVal.mag.f"), FC::Mx),
                (format!("{DOMAIN}/GGIO1.Arr.hstVal(1)"), FC::St),
                (format!("{DOMAIN}/GGIO1.Arr.cfg.lims"), FC::Sp),
                (format!("{DOMAIN}/MHAI1.HA.phsAHar"), FC::Mx),
            ]
        );
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// Registers `LLN0$Lims`, whose only member names the element
/// `GGIO1.Arr.cfg.lims(1)`.
fn register_lims_element(server: &IedServer) {
    let model = server.model();
    let r = ObjectRef::parse(&format!("{DOMAIN}/GGIO1$SP$Arr$cfg$lims(1)")).unwrap();
    let Some(NodeRef::Da(lim)) = model.node_by_object_ref(&r) else {
        panic!("the element resolves to an attribute");
    };
    let mut ds = iec61850_server::Dataset::new("LLN0$Lims");
    ds.push(iec61850_server::DatasetEntry::new(
        format!("{DOMAIN}/GGIO1$SP$Arr$cfg$lims(1)"),
        Arc::clone(&lim.value),
    ));
    server.register_dataset(DOMAIN, ds);
}

#[derive(Debug)]
struct DenyRead;
impl ReadHandler for DenyRead {
    fn read(&self, _ctx: &ReadContext<'_>) -> ReadOutcome {
        ReadOutcome::Error(DataAccessError::ObjectAccessDenied)
    }
}

/// A data set member naming an array element is written by SetDataSetValues
/// as that element of the array, and read by GetDataSetValues through the
/// read handlers of the array, as a Read of the array with an alternate access
/// is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_data_set_member_naming_an_element_is_served_as_that_element() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (handle, mut client) = serve_with(model(), register_lims_element).await;
        let outcomes = tokio::time::timeout(
            Duration::from_secs(5),
            client.write_named_variable_list_values(DOMAIN, "LLN0$Lims", vec![MmsData::Integer(4)]),
        )
        .await
        .expect("timeout")
        .expect("SetDataSetValues");
        assert_eq!(
            outcomes,
            vec![iec61850_mms::mms::pdu::common::WriteOutcome::Success]
        );
        assert_eq!(
            read_element(&mut client, "GGIO1$SP$Arr$cfg$lims", 1, None)
                .await
                .expect("lims(1)"),
            MmsData::Integer(4)
        );
        let values = tokio::time::timeout(
            Duration::from_secs(5),
            client.read_named_variable_list_values(DOMAIN, "LLN0$Lims"),
        )
        .await
        .expect("timeout")
        .expect("GetDataSetValues");
        assert_eq!(values, vec![AccessResult::Success(MmsData::Integer(4))]);
        handle.stop().await;

        let (handle, mut client) = serve_with(model(), |server| {
            register_lims_element(server);
            server
                .install_read_handler("GGIO1$SP$Arr$cfg$lims", Arc::new(DenyRead))
                .expect("install_read_handler");
        })
        .await;
        let values = tokio::time::timeout(
            Duration::from_secs(5),
            client.read_named_variable_list_values(DOMAIN, "LLN0$Lims"),
        )
        .await
        .expect("timeout")
        .expect("GetDataSetValues");
        assert_eq!(
            values,
            vec![AccessResult::Failure(DataAccessError::ObjectAccessDenied)]
        );
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// A read handler on the array that supplies its value decides a data set
/// member naming one element: GetDataSetValues answers the element the
/// member's alternate access selects from the handler's array, as a Read of
/// the array with that alternate access does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_handler_value_answers_the_element_a_member_names() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (handle, mut client) = serve_with(model(), |server| {
            register_lims_element(server);
            server
                .install_read_handler(
                    "GGIO1$SP$Arr$cfg$lims",
                    Arc::new(Fixed(MmsValue::Array(vec![
                        MmsValue::Integer(70),
                        MmsValue::Integer(71),
                        MmsValue::Integer(72),
                    ]))),
                )
                .expect("install_read_handler");
        })
        .await;
        let values = tokio::time::timeout(
            Duration::from_secs(5),
            client.read_named_variable_list_values(DOMAIN, "LLN0$Lims"),
        )
        .await
        .expect("timeout")
        .expect("GetDataSetValues");
        assert_eq!(values, vec![AccessResult::Success(MmsData::Integer(71))]);
        assert_eq!(
            read_element(&mut client, "GGIO1$SP$Arr$cfg$lims", 1, None)
                .await
                .expect("lims(1)"),
            MmsData::Integer(71)
        );
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// A SetDataSetValues writing a member that names an array element is
/// decided by the write handler on the array, as a Write of the element is:
/// the handler sees the array with the element replaced, and its refusal
/// fails the member and leaves the element as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_handler_on_an_array_decides_a_data_set_write_of_an_element() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let refuse = Arc::new(Recording {
            seen: std::sync::Mutex::new(Vec::new()),
            outcome: WriteOutcome::Reject(DataAccessError::ObjectAccessDenied),
        });
        let handler = Arc::clone(&refuse);
        let (handle, mut client) = serve_with(model(), move |server| {
            register_lims_element(server);
            server
                .install_write_access_handler("GGIO1$SP$Arr$cfg$lims", handler)
                .expect("install_write_access_handler");
        })
        .await;
        let outcomes = tokio::time::timeout(
            Duration::from_secs(5),
            client.write_named_variable_list_values(DOMAIN, "LLN0$Lims", vec![MmsData::Integer(4)]),
        )
        .await
        .expect("timeout")
        .expect("SetDataSetValues");
        assert_eq!(
            outcomes,
            vec![iec61850_mms::mms::pdu::common::WriteOutcome::Failure(
                DataAccessError::ObjectAccessDenied
            )]
        );
        assert_eq!(
            *refuse.seen.lock().unwrap(),
            vec![(
                "GGIO1$SP$Arr$cfg$lims".to_string(),
                MmsValue::Array(vec![
                    MmsValue::Integer(-3),
                    MmsValue::Integer(4),
                    MmsValue::Integer(0),
                ])
            )]
        );
        assert_eq!(
            read_element(&mut client, "GGIO1$SP$Arr$cfg$lims", 1, None)
                .await
                .expect("lims(1)"),
            MmsData::Integer(0)
        );
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// A client writing a data set member that names an array element triggers
/// the report of that member to a control block bound to the data set.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_data_set_write_of_an_element_is_reported() {
    use iec61850_server::{OptFlds, Rcb, ReportControl, TriggerOptions};

    tokio::time::timeout(Duration::from_secs(20), async {
        let (handle, mut client) = serve_with(model(), |server| {
            let model = server.model();
            let r = ObjectRef::parse(&format!("{DOMAIN}/GGIO1$SP$Arr$cfg$lims(1)")).unwrap();
            let Some(NodeRef::Da(lim)) = model.node_by_object_ref(&r) else {
                panic!("the element resolves to an attribute");
            };
            let mut ds = iec61850_server::Dataset::new("LLN0$Lims");
            ds.push(iec61850_server::DatasetEntry::new(
                format!("{DOMAIN}/GGIO1$SP$Arr$cfg$lims(1)"),
                Arc::clone(&lim.value),
            ));
            let rcb = Rcb::new("urcbLims", "LLN0$Lims")
                .with_trg_ops(TriggerOptions::DATA_CHANGED)
                .with_opt_flds(OptFlds::SEQ_NUM | OptFlds::DATA_REFERENCE);
            server
                .register_urcb(
                    ReportControl::new(format!("{DOMAIN}/LLN0$RP$urcbLims"), rcb),
                    ds,
                )
                .expect("register_urcb");
        })
        .await;
        for field in ["Resv", "RptEna"] {
            write(
                &mut client,
                &format!("LLN0$RP$urcbLims${field}"),
                MmsData::Boolean(true),
            )
            .await
            .expect("enable the control block");
        }
        let outcomes = tokio::time::timeout(
            Duration::from_secs(5),
            client.write_named_variable_list_values(DOMAIN, "LLN0$Lims", vec![MmsData::Integer(5)]),
        )
        .await
        .expect("timeout")
        .expect("SetDataSetValues");
        assert_eq!(
            outcomes,
            vec![iec61850_mms::mms::pdu::common::WriteOutcome::Success]
        );
        assert_eq!(
            next_report_with_references(&mut client).await,
            (
                vec![true],
                vec![format!("{DOMAIN}/GGIO1$SP$Arr$cfg$lims(1)")],
                vec![MmsValue::Integer(5)],
            )
        );
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// A data set a client creates with members naming array elements holds those
/// elements: GetDataSetValues reads them, GetNamedVariableListAttributes lists
/// them in the form CreateDataSet took, the client reads back the references
/// it created them with, and a report names each by the index after the array
/// name (IEC 61850-8-1 §7.3.3, §7.3.4, Table 151, §8.1.3.2.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_data_set_takes_array_element_members() {
    use iec61850_client::{DataSetMember, IedConnection};
    use iec61850_server::{OptFlds, Rcb, ReportControl, TriggerOptions};

    tokio::time::timeout(Duration::from_secs(30), async {
        let (handle, mut client) = serve_with(model(), |server| {
            register_lims_element(server);
            let rcb = Rcb::new("urcbDyn", "LLN0$Lims")
                .with_trg_ops(TriggerOptions::DATA_CHANGED)
                .with_opt_flds(OptFlds::SEQ_NUM | OptFlds::DATA_REFERENCE);
            let mut ds = iec61850_server::Dataset::new("LLN0$Lims");
            let model = server.model();
            let r = ObjectRef::parse(&format!("{DOMAIN}/GGIO1$SP$Arr$cfg$lims(1)")).unwrap();
            let Some(NodeRef::Da(lim)) = model.node_by_object_ref(&r) else {
                panic!("the element resolves to an attribute");
            };
            ds.push(iec61850_server::DatasetEntry::new(
                format!("{DOMAIN}/GGIO1$SP$Arr$cfg$lims(1)"),
                Arc::clone(&lim.value),
            ));
            server
                .register_urcb(
                    ReportControl::new(format!("{DOMAIN}/LLN0$RP$urcbDyn"), rcb),
                    ds,
                )
                .expect("register_urcb");
        })
        .await;
        let conn = IedConnection::with_mms_client(
            MmsClientBuilder::new()
                .connect_timeout_ms(3_000)
                .request_timeout_ms(3_000)
                .build(),
        );
        tokio::time::timeout(
            Duration::from_secs(5),
            conn.connect("127.0.0.1", handle.bound_addr.port()),
        )
        .await
        .expect("timeout")
        .expect("connect");

        let members = [
            (format!("{DOMAIN}/MHAI1.HA.phsAHar(3).cVal.mag.f"), FC::Mx),
            (format!("{DOMAIN}/GGIO1.Arr.hstVal(1)"), FC::St),
            (format!("{DOMAIN}/GGIO1.Arr.cfg.lims(2)"), FC::Sp),
            (format!("{DOMAIN}/GGIO1.Arr.cfg.lims"), FC::Sp),
        ];
        let requested: Vec<DataSetMember> = members
            .iter()
            .map(|(r, fc)| DataSetMember::new(r.clone(), *fc))
            .collect();
        tokio::time::timeout(
            Duration::from_secs(5),
            conn.create_data_set(&format!("{DOMAIN}/LLN0.dynEl"), &requested),
        )
        .await
        .expect("timeout")
        .expect("CreateDataSet with array element members");

        let values = tokio::time::timeout(
            Duration::from_secs(5),
            client.read_named_variable_list_values(DOMAIN, "LLN0$dynEl"),
        )
        .await
        .expect("timeout")
        .expect("GetDataSetValues");
        assert_eq!(
            values,
            vec![
                AccessResult::Success(MmsData::Float32(3.5)),
                AccessResult::Success(MmsData::Integer(7)),
                AccessResult::Success(MmsData::Integer(0)),
                AccessResult::Success(ints(&[-3, 0, 0])),
            ]
        );

        let named = |item: &str| ObjectName::DomainSpecific {
            domain_id: DOMAIN.into(),
            item_id: item.into(),
        };
        let dir = tokio::time::timeout(
            Duration::from_secs(5),
            client.get_named_variable_list_attributes(DOMAIN, "LLN0$dynEl"),
        )
        .await
        .expect("timeout")
        .expect("GetNamedVariableListAttributes");
        assert_eq!(
            dir.list_of_variable,
            vec![
                ListOfVariableEntry::with_alt_access(
                    named("MHAI1$MX$HA$phsAHar"),
                    AlternateAccess::index_component(3, "cVal$mag$f").unwrap()
                ),
                ListOfVariableEntry::with_alt_access(
                    named("GGIO1$ST$Arr$hstVal"),
                    AlternateAccess::index(1)
                ),
                ListOfVariableEntry::with_alt_access(
                    named("GGIO1$SP$Arr$cfg$lims"),
                    AlternateAccess::index(2)
                ),
                ListOfVariableEntry::name(named("GGIO1$SP$Arr$cfg$lims")),
            ]
        );
        let directory = tokio::time::timeout(
            Duration::from_secs(5),
            conn.get_data_set_directory(&format!("{DOMAIN}/LLN0.dynEl")),
        )
        .await
        .expect("timeout")
        .expect("GetDataSetDirectory");
        let read_back: Vec<(String, FC)> = directory
            .members
            .iter()
            .map(|m| (m.reference.clone(), m.fc))
            .collect();
        assert_eq!(read_back, members);

        for (field, value) in [
            ("Resv", MmsData::Boolean(true)),
            (
                "DatSet",
                MmsData::VisibleString(format!("{DOMAIN}/LLN0$dynEl")),
            ),
            ("RptEna", MmsData::Boolean(true)),
        ] {
            write(&mut client, &format!("LLN0$RP$urcbDyn${field}"), value)
                .await
                .expect("set up the control block");
        }
        write_element(
            &mut client,
            "GGIO1$SP$Arr$cfg$lims",
            2,
            None,
            MmsData::Integer(6),
        )
        .await
        .expect("write the element");
        assert_eq!(
            next_report_with_references(&mut client).await,
            (
                vec![false, false, true, true],
                vec![
                    format!("{DOMAIN}/GGIO1$SP$Arr$cfg$lims(2)"),
                    format!("{DOMAIN}/GGIO1$SP$Arr$cfg$lims"),
                ],
                vec![
                    MmsValue::Integer(6),
                    MmsValue::Array(vec![
                        MmsValue::Integer(-3),
                        MmsValue::Integer(0),
                        MmsValue::Integer(6),
                    ]),
                ],
            )
        );
        handle.stop().await;
    })
    .await
    .expect("timed out");
}

/// An alternate access may select components before the array, as Table 139
/// does; the member is the same element. An index past the end of the array,
/// on an attribute that is no array, or after an array that it does not
/// follow names no object and is answered definition object-undefined, and
/// nothing is created.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_data_set_resolves_the_alternate_access_of_a_member() {
    use iec61850_mms::mms::pdu::service_error::{subcode::definition, ErrorClass};
    use iec61850_mms::mms::pdu::DefineNamedVariableEntry;

    tokio::time::timeout(Duration::from_secs(20), async {
        let (handle, mut client) = serve(model()).await;
        let table_139 = DefineNamedVariableEntry::domain(DOMAIN, "MHAI1$MX$HA").with_alt_access(
            AlternateAccess::component_then(
                "phsAHar",
                AlternateAccess::index_component(3, "cVal$mag$f").unwrap(),
            )
            .unwrap(),
        );
        tokio::time::timeout(
            Duration::from_secs(5),
            client.define_named_variable_list(DOMAIN, "LLN0$t139", vec![table_139]),
        )
        .await
        .expect("timeout")
        .expect("a component chain then an element");
        let values = tokio::time::timeout(
            Duration::from_secs(5),
            client.read_named_variable_list_values(DOMAIN, "LLN0$t139"),
        )
        .await
        .expect("timeout")
        .expect("GetDataSetValues");
        assert_eq!(values, vec![AccessResult::Success(MmsData::Float32(3.5))]);

        for (name, entry) in [
            (
                "LLN0$past",
                DefineNamedVariableEntry::domain(DOMAIN, "GGIO1$ST$Arr$hstVal")
                    .with_alt_access(AlternateAccess::index(3)),
            ),
            (
                "LLN0$scalar",
                DefineNamedVariableEntry::domain(DOMAIN, "GGIO1$SP$Arr$cfg$name")
                    .with_alt_access(AlternateAccess::index(0)),
            ),
            (
                "LLN0$inner",
                DefineNamedVariableEntry::domain(DOMAIN, "GGIO1$SP$Spt$setPts$setVal")
                    .with_alt_access(AlternateAccess::index(0)),
            ),
        ] {
            let r = tokio::time::timeout(
                Duration::from_secs(5),
                client.define_named_variable_list(DOMAIN, name, vec![entry]),
            )
            .await
            .expect("timeout");
            assert!(
                matches!(
                    r,
                    Err(ClientError::ServiceError {
                        error_class: ErrorClass::Definition(definition::OBJECT_UNDEFINED),
                        ..
                    })
                ),
                "{name}: {r:?}"
            );
        }
        let (lists, _) = tokio::time::timeout(
            Duration::from_secs(5),
            client.get_name_list(ObjectClass::NamedVariableList, Some(DOMAIN), None),
        )
        .await
        .expect("timeout")
        .expect("names");
        assert_eq!(lists, ["LLN0$t139"]);
        handle.stop().await;
    })
    .await
    .expect("timed out");
}
