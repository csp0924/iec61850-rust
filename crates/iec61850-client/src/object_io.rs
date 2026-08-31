//! Reading and writing IEC 61850 objects: `read_object` and `write_object`
//! plus type-narrowing wrappers, mapped onto the MMS Read and Write services
//! of IEC 61850-7-2.
//!
//! An IEC-notation reference `<LD>/<LN>.<DO>[.<DA>]*` together with a
//! functional constraint becomes the MMS variable `domain = <LD>`,
//! `item = <LN>$<FC>$<DO>[$<DA>]*`, per the mapping of IEC 61850-8-1. Both
//! notations are parsed by `iec61850-model::ObjectRef`.
//!
//! ## Array elements
//!
//! References with an array index (`Ind1(0).stVal`) — an array name, an
//! index, and optional nested sub-components — are routed through MMS
//! `AlternateAccess` (IEC 61850-8-1 §17). Single-element access and
//! single-element-plus-sub-component access are supported.

use iec61850_hal::time::Timer;
use iec61850_hal::transport::AsyncTransport;
use iec61850_mms::mms::pdu::common::MmsData;
use iec61850_model::value::MmsValue;
use iec61850_model::{ObjectRef, Quality, Segment, FC};

use crate::connection::IedConnection;
use crate::error::ClientError;
use crate::mms_compat::{mms_data_to_mms_value, mms_value_to_mms_data};
use crate::prelude::{format, String, ToString, Vec};

// IEC ObjectRef + FC → MMS variable spec

/// An MMS variable address: domain, item id, and an optional array element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IecObjectPath {
    /// MMS domain, the IED name and logical device instance, such as
    /// `simpleIOGenericIO`.
    pub domain: String,
    /// MMS item id `<LN>$<FC>$<DO>[$<DA>]*`, without any array index.
    pub item_id: String,
    /// Set when the reference carried an array index.
    pub array: Option<ArrayElement>,
}

/// An array element: `Ind1(0).stVal` gives index 0 and component `stVal`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArrayElement {
    /// Zero-based index of the element within the array.
    pub index: u32,
    /// Sub-component addressed inside the element, if any.
    pub component: Option<String>,
}

/// Resolves an object reference and a functional constraint into an MMS
/// variable address.
///
/// Both IEC notation (`LD/LN.DO.DA`) and MMS notation (`LD/LN$FC$DO$DA`) are
/// accepted and told apart by `ObjectRef::parse`. An FC embedded in the
/// reference must equal `fc`.
///
/// # Errors
///
/// `InvalidArgument` for `FC::None` or `FC::All`, which name no single
/// constraint; for a reference without `/`, with an over-long logical device
/// name, with an empty path token or malformed array syntax; and for an
/// embedded FC that disagrees with `fc`.
pub fn parse_iec_object_path(reference: &str, fc: FC) -> Result<IecObjectPath, ClientError> {
    if matches!(fc, FC::None | FC::All) {
        return Err(ClientError::InvalidArgument(format!(
            "FC `{fc}` cannot be used with read_object or write_object; name a single constraint such as ST or MX"
        )));
    }

    let parsed = ObjectRef::parse(reference).map_err(|e| {
        ClientError::InvalidArgument(format!("invalid objectReference `{reference}`: {e}"))
    })?;

    if let Some(parsed_fc) = parsed.fc {
        if parsed_fc != fc {
            return Err(ClientError::InvalidArgument(format!(
                "object reference `{reference}` carries FC `{parsed_fc}`, which differs from the requested `{fc}`"
            )));
        }
    }

    // The item id is `<LN>$<FC>` followed by the path tokens. Tokens after an
    // array index belong to the element instead and are collected as its
    // component; only one index is supported.
    let mut item = String::with_capacity(parsed.ln.len() + 5 + 8);
    item.push_str(&parsed.ln);
    item.push('$');
    item.push_str(fc.as_str());

    let mut array: Option<ArrayElement> = None;
    let mut comp_buf: Option<String> = None;

    for seg in &parsed.path {
        match seg {
            Segment::Name(n) => {
                if let Some(buf) = comp_buf.as_mut() {
                    if !buf.is_empty() {
                        buf.push('$');
                    }
                    buf.push_str(n);
                } else {
                    item.push('$');
                    item.push_str(n);
                }
            }
            Segment::Index(i) => {
                if array.is_some() {
                    return Err(ClientError::InvalidArgument(format!(
                        "object reference `{reference}` has more than one array index; only a single level is supported"
                    )));
                }
                array = Some(ArrayElement {
                    index: *i,
                    component: None,
                });
                comp_buf = Some(String::new());
            }
        }
    }
    if let (Some(arr), Some(buf)) = (array.as_mut(), comp_buf) {
        if !buf.is_empty() {
            arr.component = Some(buf);
        }
    }

    Ok(IecObjectPath {
        domain: parsed.domain,
        item_id: item,
        array,
    })
}

// IedConnection::read_object / write_object

impl<T: AsyncTransport, Tm: Timer> IedConnection<T, Tm> {
    /// Read an IEC 61850 object (DA / SDA leaf, or a whole DO group).
    ///
    /// `reference` accepts either IEC notation (`<LD>/<LN>.<DO>[.<DA>]*`) or
    /// MMS notation (`<LD>/<LN>$<FC>$<DO>$<DA>`); when the reference embeds
    /// an FC token it must match `fc`.
    ///
    /// References that contain an array index (`Ind1(0).stVal`) are routed
    /// through MMS `AlternateAccess`, fetching a single element or a
    /// sub-component within it.
    pub async fn read_object(&self, reference: &str, fc: FC) -> Result<MmsValue, ClientError> {
        if !self.is_connected() {
            return Err(ClientError::NotConnected);
        }
        let path = parse_iec_object_path(reference, fc)?;
        let mut client = self.mms_client.lock().await;
        let data = match &path.array {
            None => client.read(&path.domain, &path.item_id).await?,
            Some(arr) => {
                client
                    .read_single_array_element(
                        &path.domain,
                        &path.item_id,
                        arr.index,
                        arr.component.as_deref(),
                    )
                    .await?
            }
        };
        Ok(mms_data_to_mms_value(&data))
    }

    /// Write an IEC 61850 object.
    ///
    /// Array-indexed references go through MMS `AlternateAccess`, symmetric
    /// to [`Self::read_object`].
    pub async fn write_object(
        &self,
        reference: &str,
        fc: FC,
        value: MmsValue,
    ) -> Result<(), ClientError> {
        if !self.is_connected() {
            return Err(ClientError::NotConnected);
        }
        let path = parse_iec_object_path(reference, fc)?;
        let data: MmsData = mms_value_to_mms_data(&value);
        let mut client = self.mms_client.lock().await;
        match &path.array {
            None => {
                client.write(&path.domain, &path.item_id, data).await?;
            }
            Some(arr) => {
                client
                    .write_single_array_element(
                        &path.domain,
                        &path.item_id,
                        arr.index,
                        arr.component.as_deref(),
                        data,
                    )
                    .await?;
            }
        }
        Ok(())
    }
}

// Data set access: GetDataSetValues and SetDataSetValues.

/// The MMS address of a data set: domain and named variable list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSetRef {
    /// MMS domain, the logical device name.
    pub domain: String,
    /// MMS named variable list name, `<LN>$<dataset_name>`.
    pub list_name: String,
}

/// Resolves a data set reference into its MMS address.
///
/// Accepts IEC notation `<LD>/<LN>.<dataset_name>` and MMS notation
/// `<LD>/<LN>$<dataset_name>`, and yields `domain = <LD>` with
/// `list_name = <LN>$<dataset_name>` either way. A data set name takes no
/// functional constraint, so the mapping of IEC 61850-8-1 reduces to turning
/// the separating `.` into `$`.
///
/// # Errors
///
/// `InvalidArgument` if the reference is empty, has no `/`, or has no `.` or
/// `$` separating the logical node from the data set name.
pub fn parse_data_set_ref(reference: &str) -> Result<DataSetRef, ClientError> {
    let trimmed = reference.trim();
    if trimmed.is_empty() {
        return Err(ClientError::InvalidArgument(
            "data set reference is empty".to_string(),
        ));
    }
    let slash = trimmed.find('/').ok_or_else(|| {
        ClientError::InvalidArgument(format!(
            "data set reference is missing the '/' of `<LD>/<LN>.<ds>`: {trimmed:?}"
        ))
    })?;
    let domain = &trimmed[..slash];
    let tail = &trimmed[slash + 1..];
    if domain.is_empty() || tail.is_empty() {
        return Err(ClientError::InvalidArgument(format!(
            "data set reference has an empty logical device or tail: {trimmed:?}"
        )));
    }
    // MMS notation already carries the `$`; IEC notation has the first `.`
    // replaced, a data set name containing no further `.`.
    let list_name = if tail.contains('$') {
        tail.to_string()
    } else if let Some(dot) = tail.find('.') {
        let (ln, ds) = tail.split_at(dot);
        if ln.is_empty() || ds.len() <= 1 {
            return Err(ClientError::InvalidArgument(format!(
                "data set reference has an empty logical node or data set name: {trimmed:?}"
            )));
        }
        format!("{ln}${}", &ds[1..])
    } else {
        return Err(ClientError::InvalidArgument(format!(
            "data set reference is missing the '.' or '$' between LN and data set: {trimmed:?}"
        )));
    };
    Ok(DataSetRef {
        domain: domain.to_string(),
        list_name,
    })
}

impl<T: AsyncTransport, Tm: Timer> IedConnection<T, Tm> {
    /// Reads every value of a data set (IEC 61850-7-2 GetDataSetValues).
    ///
    /// Unlike [`read_object`](Self::read_object), which names one variable,
    /// this addresses the named variable list itself and lets the server expand
    /// and read its entries.
    ///
    /// One [`AccessResult`](iec61850_mms::AccessResult) is returned per entry,
    /// so a failing entry does not hide the values of the others.
    ///
    /// # Errors
    ///
    /// `NotConnected` if the association is not established, and
    /// `InvalidArgument` for a malformed data set reference.
    pub async fn get_data_set_values(
        &self,
        dataset_ref: &str,
    ) -> Result<Vec<iec61850_mms::AccessResult>, ClientError> {
        if !self.is_connected() {
            return Err(ClientError::NotConnected);
        }
        let ds = parse_data_set_ref(dataset_ref)?;
        let mut client = self.mms_client.lock().await;
        let results = client
            .read_named_variable_list_values(&ds.domain, &ds.list_name)
            .await?;
        Ok(results)
    }

    /// Writes every value of a data set (IEC 61850-7-2 SetDataSetValues).
    ///
    /// `values` must have as many elements as the data set has entries;
    /// otherwise the server reports `DataAccessError::TypeInconsistent` per
    /// entry in the returned outcomes. The entry count comes from the data set
    /// directory.
    ///
    /// # Errors
    ///
    /// `NotConnected` if the association is not established, and
    /// `InvalidArgument` for a malformed data set reference.
    pub async fn set_data_set_values(
        &self,
        dataset_ref: &str,
        values: Vec<MmsValue>,
    ) -> Result<Vec<iec61850_mms::WriteOutcome>, ClientError> {
        if !self.is_connected() {
            return Err(ClientError::NotConnected);
        }
        let ds = parse_data_set_ref(dataset_ref)?;
        let datas: Vec<MmsData> = values.iter().map(mms_value_to_mms_data).collect();
        let mut client = self.mms_client.lock().await;
        let outcomes = client
            .write_named_variable_list_values(&ds.domain, &ds.list_name, datas)
            .await?;
        Ok(outcomes)
    }
}

// Type-narrowing read and write wrappers.

/// Names the variant of an `MmsValue`, for an `UnexpectedValueType` error.
fn variant_name(v: &MmsValue) -> &'static str {
    match v {
        MmsValue::Boolean(_) => "Boolean",
        MmsValue::Integer(_) => "Integer",
        MmsValue::Unsigned(_) => "Unsigned",
        MmsValue::Float32(_) => "Float32",
        MmsValue::Float64(_) => "Float64",
        MmsValue::BitString { .. } => "BitString",
        MmsValue::OctetString(_) => "OctetString",
        MmsValue::VisibleString(_) => "VisibleString",
        MmsValue::MmsString(_) => "MmsString",
        MmsValue::UtcTime(_) => "UtcTime",
        MmsValue::BinaryTime(_) => "BinaryTime",
        MmsValue::Array(_) => "Array",
        MmsValue::Structure(_) => "Structure",
    }
}

impl<T: AsyncTransport, Tm: Timer> IedConnection<T, Tm> {
    /// Reads a BOOLEAN data attribute.
    pub async fn read_boolean(&self, reference: &str, fc: FC) -> Result<bool, ClientError> {
        match self.read_object(reference, fc).await? {
            MmsValue::Boolean(b) => Ok(b),
            other => Err(ClientError::UnexpectedValueType {
                expected: "Boolean",
                got: variant_name(&other),
            }),
        }
    }

    /// Reads a FLOAT32 data attribute.
    ///
    /// A FLOAT64 value is reported as `UnexpectedValueType` rather than
    /// narrowed, so precision is never lost silently.
    pub async fn read_float(&self, reference: &str, fc: FC) -> Result<f32, ClientError> {
        match self.read_object(reference, fc).await? {
            MmsValue::Float32(f) => Ok(f),
            other => Err(ClientError::UnexpectedValueType {
                expected: "Float32",
                got: variant_name(&other),
            }),
        }
    }

    /// Reads a FLOAT64 data attribute.
    pub async fn read_float64(&self, reference: &str, fc: FC) -> Result<f64, ClientError> {
        match self.read_object(reference, fc).await? {
            MmsValue::Float64(f) => Ok(f),
            other => Err(ClientError::UnexpectedValueType {
                expected: "Float64",
                got: variant_name(&other),
            }),
        }
    }

    /// Reads a VISIBLE STRING or MMS STRING data attribute.
    ///
    /// Both MMS string types are accepted.
    pub async fn read_string(&self, reference: &str, fc: FC) -> Result<String, ClientError> {
        match self.read_object(reference, fc).await? {
            MmsValue::VisibleString(s) | MmsValue::MmsString(s) => Ok(s),
            other => Err(ClientError::UnexpectedValueType {
                expected: "VisibleString",
                got: variant_name(&other),
            }),
        }
    }

    /// Reads an INTEGER data attribute as an `i32`.
    ///
    /// An UNSIGNED value is accepted as well; either type outside the range of
    /// `i32` is reported as `InvalidArgument`.
    pub async fn read_int32(&self, reference: &str, fc: FC) -> Result<i32, ClientError> {
        match self.read_object(reference, fc).await? {
            MmsValue::Integer(i) => i32::try_from(i).map_err(|_| {
                ClientError::InvalidArgument(format!(
                    "server returned Integer({i}), which is out of range for i32"
                ))
            }),
            MmsValue::Unsigned(u) => i32::try_from(u).map_err(|_| {
                ClientError::InvalidArgument(format!(
                    "server returned Unsigned({u}), which is out of range for i32"
                ))
            }),
            other => Err(ClientError::UnexpectedValueType {
                expected: "Integer",
                got: variant_name(&other),
            }),
        }
    }

    /// Reads an UNSIGNED data attribute as a `u32`.
    ///
    /// A non-negative INTEGER is accepted as well; a value outside the range of
    /// `u32` is reported as `InvalidArgument`.
    pub async fn read_uint32(&self, reference: &str, fc: FC) -> Result<u32, ClientError> {
        match self.read_object(reference, fc).await? {
            MmsValue::Unsigned(u) => u32::try_from(u).map_err(|_| {
                ClientError::InvalidArgument(format!(
                    "server returned Unsigned({u}), which is out of range for u32"
                ))
            }),
            MmsValue::Integer(i) if i >= 0 => u32::try_from(i).map_err(|_| {
                ClientError::InvalidArgument(format!(
                    "server returned Integer({i}), which is out of range for u32"
                ))
            }),
            other => Err(ClientError::UnexpectedValueType {
                expected: "Unsigned",
                got: variant_name(&other),
            }),
        }
    }

    /// Reads an INTEGER data attribute as an `i64`.
    ///
    /// An UNSIGNED value is accepted as well; one beyond `i64::MAX` is reported
    /// as `InvalidArgument`.
    pub async fn read_int64(&self, reference: &str, fc: FC) -> Result<i64, ClientError> {
        match self.read_object(reference, fc).await? {
            MmsValue::Integer(i) => Ok(i),
            MmsValue::Unsigned(u) => i64::try_from(u).map_err(|_| {
                ClientError::InvalidArgument(format!(
                    "server returned Unsigned({u}), which is out of range for i64"
                ))
            }),
            other => Err(ClientError::UnexpectedValueType {
                expected: "Integer",
                got: variant_name(&other),
            }),
        }
    }

    /// Reads a UTC TIME data attribute as its 8 raw bytes.
    ///
    /// The caller decodes the milliseconds and the time quality from them.
    pub async fn read_timestamp(&self, reference: &str, fc: FC) -> Result<[u8; 8], ClientError> {
        match self.read_object(reference, fc).await? {
            MmsValue::UtcTime(arr) => Ok(arr),
            other => Err(ClientError::UnexpectedValueType {
                expected: "UtcTime",
                got: variant_name(&other),
            }),
        }
    }

    /// Reads a Quality data attribute, a BIT STRING(13) as defined in
    /// IEC 61850-7-3.
    ///
    /// The `DERIVED` flag occupies bit 13 and has no place in a 13-bit string,
    /// so it does not survive a round trip through the wire representation.
    pub async fn read_quality(&self, reference: &str, fc: FC) -> Result<Quality, ClientError> {
        match self.read_object(reference, fc).await? {
            v @ MmsValue::BitString { .. } => Quality::from_mms_bit_string(&v).map_err(|e| {
                ClientError::InvalidArgument(format!("cannot parse quality bit string: {e}"))
            }),
            other => Err(ClientError::UnexpectedValueType {
                expected: "BitString(Quality)",
                got: variant_name(&other),
            }),
        }
    }

    // Write wrappers.

    /// Writes a BOOLEAN data attribute.
    pub async fn write_boolean(
        &self,
        reference: &str,
        fc: FC,
        value: bool,
    ) -> Result<(), ClientError> {
        self.write_object(reference, fc, MmsValue::Boolean(value))
            .await
    }

    /// Writes an INTEGER data attribute from an `i32`.
    pub async fn write_int32(
        &self,
        reference: &str,
        fc: FC,
        value: i32,
    ) -> Result<(), ClientError> {
        self.write_object(reference, fc, MmsValue::Integer(value as i64))
            .await
    }

    /// Writes an UNSIGNED data attribute from a `u32`.
    pub async fn write_uint32(
        &self,
        reference: &str,
        fc: FC,
        value: u32,
    ) -> Result<(), ClientError> {
        self.write_object(reference, fc, MmsValue::Unsigned(value as u64))
            .await
    }

    /// Writes a FLOAT32 data attribute.
    pub async fn write_float(
        &self,
        reference: &str,
        fc: FC,
        value: f32,
    ) -> Result<(), ClientError> {
        self.write_object(reference, fc, MmsValue::Float32(value))
            .await
    }

    /// Writes an OCTET STRING data attribute.
    pub async fn write_octet_string(
        &self,
        reference: &str,
        fc: FC,
        value: Vec<u8>,
    ) -> Result<(), ClientError> {
        self.write_object(reference, fc, MmsValue::OctetString(value))
            .await
    }

    /// Writes a VISIBLE STRING data attribute.
    pub async fn write_visible_string(
        &self,
        reference: &str,
        fc: FC,
        value: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.write_object(reference, fc, MmsValue::VisibleString(value.into()))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str, fc: FC) -> IecObjectPath {
        parse_iec_object_path(s, fc).expect("path should parse")
    }

    #[test]
    fn iec_simple_da() {
        let r = p("simpleIOGenericIO/GGIO1.AnIn1.mag.f", FC::Mx);
        assert_eq!(r.domain, "simpleIOGenericIO");
        assert_eq!(r.item_id, "GGIO1$MX$AnIn1$mag$f");
        assert!(r.array.is_none());
    }

    #[test]
    fn iec_lln0_status() {
        let r = p("IED1LD0/LLN0.Mod.stVal", FC::St);
        assert_eq!(r.domain, "IED1LD0");
        assert_eq!(r.item_id, "LLN0$ST$Mod$stVal");
    }

    #[test]
    fn iec_lln0_namplt_vendor() {
        let r = p("simpleIOGenericIO/LLN0.NamPlt.vendor", FC::Dc);
        assert_eq!(r.item_id, "LLN0$DC$NamPlt$vendor");
    }

    #[test]
    fn iec_only_do_no_da() {
        // `LD/LN.DO` with FC ST yields `LN$ST$DO`.
        let r = p("LD/LN.DO", FC::St);
        assert_eq!(r.item_id, "LN$ST$DO");
    }

    #[test]
    fn mms_notation_with_matching_fc_accepted() {
        let r = p("IED1LD0/LLN0$ST$Mod$stVal", FC::St);
        assert_eq!(r.item_id, "LLN0$ST$Mod$stVal");
    }

    #[test]
    fn mms_notation_with_mismatched_fc_rejected() {
        assert!(matches!(
            parse_iec_object_path("IED1LD0/LLN0$ST$Mod$stVal", FC::Mx),
            Err(ClientError::InvalidArgument(_))
        ));
    }

    #[test]
    fn array_element_returns_array_spec() {
        let r = p("LD/GGIO1.Ind1(0).stVal", FC::St);
        assert_eq!(r.item_id, "GGIO1$ST$Ind1");
        let arr = r.array.expect("array spec");
        assert_eq!(arr.index, 0);
        assert_eq!(arr.component.as_deref(), Some("stVal"));
    }

    #[test]
    fn array_element_no_component() {
        let r = p("LD/GGIO1.Ind1(3)", FC::St);
        assert_eq!(r.item_id, "GGIO1$ST$Ind1");
        let arr = r.array.expect("array spec");
        assert_eq!(arr.index, 3);
        assert!(arr.component.is_none());
    }

    #[test]
    fn array_element_with_nested_component() {
        let r = p("LD/GGIO1.IndA(2).inner.f", FC::Mx);
        let arr = r.array.expect("array spec");
        assert_eq!(arr.index, 2);
        assert_eq!(arr.component.as_deref(), Some("inner$f"));
    }

    #[test]
    fn invalid_no_slash() {
        assert!(matches!(
            parse_iec_object_path("LDLN.Mod", FC::St),
            Err(ClientError::InvalidArgument(_))
        ));
    }

    #[test]
    fn invalid_fc_none_rejected() {
        assert!(matches!(
            parse_iec_object_path("LD/LN.DO", FC::None),
            Err(ClientError::InvalidArgument(_))
        ));
    }

    #[test]
    fn invalid_fc_all_rejected() {
        assert!(matches!(
            parse_iec_object_path("LD/LN.DO", FC::All),
            Err(ClientError::InvalidArgument(_))
        ));
    }

    #[test]
    fn double_array_index_rejected() {
        // The reference parses into two array indices, which is rejected.
        assert!(matches!(
            parse_iec_object_path("LD/LN.Arr1(0).inner(2).x", FC::St),
            Err(ClientError::InvalidArgument(_))
        ));
    }

    #[test]
    fn variant_name_covers_all_variants() {
        // Every known variant must map to a non-empty name.
        let cases = [
            MmsValue::Boolean(true),
            MmsValue::Integer(1),
            MmsValue::Unsigned(1),
            MmsValue::Float32(0.0),
            MmsValue::Float64(0.0),
            MmsValue::BitString {
                padding: 0,
                data: vec![0],
            },
            MmsValue::OctetString(vec![]),
            MmsValue::VisibleString(String::new()),
            MmsValue::MmsString(String::new()),
            MmsValue::UtcTime([0; 8]),
            MmsValue::BinaryTime(vec![]),
            MmsValue::Array(vec![]),
            MmsValue::Structure(vec![]),
        ];
        for v in &cases {
            assert!(!variant_name(v).is_empty(), "{v:?}");
        }
    }

    // Dataset reference parser

    #[test]
    fn dataset_iec_notation() {
        let r = parse_data_set_ref("simpleIOGenericIO/LLN0.dsCurrent").unwrap();
        assert_eq!(r.domain, "simpleIOGenericIO");
        assert_eq!(r.list_name, "LLN0$dsCurrent");
    }

    #[test]
    fn dataset_mms_notation() {
        let r = parse_data_set_ref("simpleIOGenericIO/LLN0$dsCurrent").unwrap();
        assert_eq!(r.domain, "simpleIOGenericIO");
        assert_eq!(r.list_name, "LLN0$dsCurrent");
    }

    #[test]
    fn dataset_no_slash_rejected() {
        assert!(matches!(
            parse_data_set_ref("simpleIOGenericIOLLN0.dsCurrent"),
            Err(ClientError::InvalidArgument(_))
        ));
    }

    #[test]
    fn dataset_no_separator_rejected() {
        assert!(matches!(
            parse_data_set_ref("simpleIOGenericIO/LLN0dsCurrent"),
            Err(ClientError::InvalidArgument(_))
        ));
    }

    #[test]
    fn dataset_empty_rejected() {
        assert!(matches!(
            parse_data_set_ref(""),
            Err(ClientError::InvalidArgument(_))
        ));
    }

    #[test]
    fn dataset_empty_ld_rejected() {
        assert!(matches!(
            parse_data_set_ref("/LLN0.dsCurrent"),
            Err(ClientError::InvalidArgument(_))
        ));
    }

    #[test]
    fn dataset_empty_ln_rejected() {
        assert!(matches!(
            parse_data_set_ref("LD/.dsCurrent"),
            Err(ClientError::InvalidArgument(_))
        ));
    }
}
