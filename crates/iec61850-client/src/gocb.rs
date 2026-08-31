//! GOOSE control block access: the ACSI GetGoCBValues and SetGoCBValues
//! services of IEC 61850-7-2.
//!
//! Both run over the ordinary MMS Read and Write services; a server exposes a
//! GoCB as the named variable `<LN>$GO$<gcb>` in the logical device's domain,
//! with one component per attribute.
//!
//! A reference is accepted in IEC notation `<LD>/<LN>.<gcbName>`, as in
//! `IED1LD0/LLN0.gcb01`, or in MMS notation `<LD>/<LN>$GO$<gcbName>`; either
//! resolves to the domain `IED1LD0` and the item `LLN0$GO$gcb01`.
//!
//! A write is partial: [`GoCBValuesWrite`] carries `Some` for each attribute
//! to write and `None` for the rest, and the attributes are written one
//! request at a time. Only GoEna and GoID are writable; a server answers a
//! write to any other attribute with `ObjectAccessDenied`.

use core::sync::atomic::Ordering;

use iec61850_hal::time::Timer;
use iec61850_hal::transport::AsyncTransport;
use iec61850_mms::mms::pdu::common::MmsData;
use iec61850_model::value::MmsValue;

use crate::connection::IedConnection;
use crate::error::ClientError;
use crate::mms_compat::mms_value_to_mms_data;
use crate::prelude::{format, Arc, String, ToString};
use crate::sync::Mutex;

/// A complete snapshot of the nine attributes of a GOOSE control block.
///
/// The field order follows IEC 61850-7-2 §13, which is the order a server
/// encodes them into the returned structure.
#[derive(Debug, Clone, PartialEq)]
pub struct GoCBValues {
    /// Object reference of the control block itself.
    pub go_cb_ref: String,
    /// Whether the server is publishing this control block.
    pub go_ena: bool,
    /// Identifier carried in the gocbRef field of every published frame.
    pub go_id: String,
    /// Reference of the data set the control block publishes.
    pub dat_set: String,
    /// Configuration revision of the data set.
    pub conf_rev: u32,
    /// Whether the configuration needs commissioning before it may be used.
    pub nds_com: bool,
    /// Destination address, VLAN settings and application identifier.
    pub dst_address: PhyComAddress,
    /// Shortest retransmission interval after an event, in milliseconds.
    pub min_time_ms: u32,
    /// Steady-state retransmission interval, in milliseconds.
    pub max_time_ms: u32,
}

/// The DstAddress attribute: the destination of the GOOSE publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhyComAddress {
    /// Destination MAC address.
    pub addr: [u8; 6],
    /// VLAN priority, 0 to 7; 0 means no VLAN is configured.
    pub priority: u8,
    /// VLAN identifier; 0 means no VLAN is configured.
    pub vlan_id: u16,
    /// Application identifier carried in the GOOSE frame.
    pub app_id: u16,
}

/// A partial GoCB write: an attribute is written when it is `Some` and left
/// untouched when it is `None`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GoCBValuesWrite {
    /// GoEna: `true` starts publishing, `false` stops it.
    pub go_ena: Option<bool>,
    /// GoID.
    pub go_id: Option<String>,
}

impl GoCBValuesWrite {
    /// Creates an empty request; attributes are added with the `with_` methods.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets GoEna.
    pub fn with_go_ena(mut self, on: bool) -> Self {
        self.go_ena = Some(on);
        self
    }

    /// Sets GoID.
    pub fn with_go_id(mut self, id: impl Into<String>) -> Self {
        self.go_id = Some(id.into());
        self
    }
}

// Reference parsing.

/// Splits a GoCB reference into the MMS domain and the item `<LN>$GO$<gcb>`.
///
/// Accepts `<LD>/<LN>.<gcb>` and `<LD>/<LN>$GO$<gcb>`.
///
/// # Errors
///
/// `InvalidArgument` if the `/` or the separator is missing, if a part is
/// empty, or if the control block name itself contains a `.`.
pub(crate) fn parse_gocb_ref(reference: &str) -> Result<(String, String), ClientError> {
    let slash = reference.find('/').ok_or_else(|| {
        ClientError::InvalidArgument(format!(
            "GoCB reference is missing the '/' before the logical node: '{reference}'"
        ))
    })?;
    let domain = reference[..slash].to_string();
    let rest = &reference[slash + 1..];

    // MMS notation: `<LN>$GO$<gcb>`.
    if let Some(stripped) = rest.split_once("$GO$") {
        let (ln, gcb) = stripped;
        if ln.is_empty() || gcb.is_empty() {
            return Err(ClientError::InvalidArgument(format!(
                "GoCB reference has an empty logical node or control block name: '{reference}'"
            )));
        }
        return Ok((domain, format!("{ln}$GO${gcb}")));
    }

    // IEC notation: `<LN>.<gcb>`.
    let dot = rest.find('.').ok_or_else(|| {
        ClientError::InvalidArgument(format!(
            "GoCB reference is missing the '.' between LN and control block: '{reference}'"
        ))
    })?;
    let ln = &rest[..dot];
    let gcb = &rest[dot + 1..];
    if ln.is_empty() || gcb.is_empty() {
        return Err(ClientError::InvalidArgument(format!(
            "GoCB reference has an empty logical node or control block name: '{reference}'"
        )));
    }
    if gcb.contains('.') {
        return Err(ClientError::InvalidArgument(format!(
            "GoCB reference control block name must not contain a '.': '{reference}'"
        )));
    }
    Ok((domain, format!("{ln}$GO${gcb}")))
}

// Decoding the structure a server returns.

/// Decodes the nine-element structure a server returns into [`GoCBValues`].
///
/// # Errors
///
/// `UnexpectedValueType` if the value is not a structure, and
/// `InvalidArgument` if it has the wrong number of elements.
pub(crate) fn parse_gocb_structure(data: &MmsData) -> Result<GoCBValues, ClientError> {
    let MmsData::Structure(items) = data else {
        return Err(ClientError::UnexpectedValueType {
            expected: "Structure(9)",
            got: variant_name(data),
        });
    };
    if items.len() != 9 {
        return Err(ClientError::InvalidArgument(format!(
            "GoCBValues structure has {} elements, expected 9",
            items.len()
        )));
    }
    // Element order follows the attribute order a server publishes.
    let go_cb_ref = expect_visible_string(&items[0], "GoCBRef")?;
    let go_ena = expect_boolean(&items[1], "GoEna")?;
    let go_id = expect_visible_string(&items[2], "GoID")?;
    let dat_set = expect_visible_string(&items[3], "DatSet")?;
    let conf_rev = expect_unsigned_u32(&items[4], "ConfRev")?;
    let nds_com = expect_boolean(&items[5], "NdsCom")?;
    let dst_address = parse_phy_com_address(&items[6])?;
    let min_time_ms = expect_unsigned_u32(&items[7], "MinTime")?;
    let max_time_ms = expect_unsigned_u32(&items[8], "MaxTime")?;
    Ok(GoCBValues {
        go_cb_ref,
        go_ena,
        go_id,
        dat_set,
        conf_rev,
        nds_com,
        dst_address,
        min_time_ms,
        max_time_ms,
    })
}

fn parse_phy_com_address(data: &MmsData) -> Result<PhyComAddress, ClientError> {
    let MmsData::Structure(items) = data else {
        return Err(ClientError::UnexpectedValueType {
            expected: "DstAddress Structure(4)",
            got: variant_name(data),
        });
    };
    if items.len() != 4 {
        return Err(ClientError::InvalidArgument(format!(
            "DstAddress structure has {} elements, expected 4",
            items.len()
        )));
    }
    let addr_bytes = match &items[0] {
        MmsData::OctetString(b) => b.clone(),
        other => {
            return Err(ClientError::UnexpectedValueType {
                expected: "Addr OctetString[6]",
                got: variant_name(other),
            });
        }
    };
    if addr_bytes.len() != 6 {
        return Err(ClientError::InvalidArgument(format!(
            "DstAddress.Addr is {} bytes, expected 6",
            addr_bytes.len()
        )));
    }
    let mut addr = [0u8; 6];
    addr.copy_from_slice(&addr_bytes);
    let priority = expect_unsigned_u32(&items[1], "PRIORITY")?;
    let vlan_id = expect_unsigned_u32(&items[2], "VID")?;
    let app_id = expect_unsigned_u32(&items[3], "APPID")?;
    Ok(PhyComAddress {
        addr,
        priority: priority as u8,
        vlan_id: vlan_id as u16,
        app_id: app_id as u16,
    })
}

fn expect_visible_string(data: &MmsData, _name: &str) -> Result<String, ClientError> {
    match data {
        MmsData::VisibleString(s) => Ok(s.clone()),
        other => Err(ClientError::UnexpectedValueType {
            expected: "VisibleString",
            got: variant_name(other),
        }),
    }
}

fn expect_boolean(data: &MmsData, _name: &str) -> Result<bool, ClientError> {
    match data {
        MmsData::Boolean(b) => Ok(*b),
        other => Err(ClientError::UnexpectedValueType {
            expected: "Boolean",
            got: variant_name(other),
        }),
    }
}

fn expect_unsigned_u32(data: &MmsData, _name: &str) -> Result<u32, ClientError> {
    match data {
        MmsData::Unsigned(u) => Ok((*u).min(u32::MAX as u64) as u32),
        MmsData::Integer(i) if *i >= 0 => Ok((*i as u64).min(u32::MAX as u64) as u32),
        other => Err(ClientError::UnexpectedValueType {
            expected: "Unsigned",
            got: variant_name(other),
        }),
    }
}

/// Names the variant of an `MmsData`, for use in an error.
fn variant_name(d: &MmsData) -> &'static str {
    match d {
        MmsData::Boolean(_) => "Boolean",
        MmsData::Integer(_) => "Integer",
        MmsData::Unsigned(_) => "Unsigned",
        MmsData::Float32(_) => "Float32",
        MmsData::Float64(_) => "Float64",
        MmsData::BitString { .. } => "BitString",
        MmsData::OctetString(_) => "OctetString",
        MmsData::VisibleString(_) => "VisibleString",
        MmsData::MmsString(_) => "MmsString",
        MmsData::UtcTime(_) => "UtcTime",
        MmsData::BinaryTime(_) => "BinaryTime",
        MmsData::Structure(_) => "Structure",
        MmsData::Array(_) => "Array",
        _ => "Other",
    }
}

// Connection-level entry points.

impl<T: AsyncTransport, Tm: Timer> IedConnection<T, Tm> {
    /// Reads every attribute of a GOOSE control block (ACSI GetGoCBValues).
    ///
    /// `reference` is IEC notation `<LD>/<LN>.<gcb>` or MMS notation
    /// `<LD>/<LN>$GO$<gcb>`. The control block is read as a single named
    /// variable and decoded into [`GoCBValues`].
    ///
    /// # Errors
    ///
    /// `NotConnected` if the association is not established, `InvalidArgument`
    /// for a malformed reference, and `UnexpectedValueType` if the server
    /// answers with something other than a nine-element structure.
    pub async fn get_gocb_values(&self, reference: &str) -> Result<GoCBValues, ClientError> {
        if !self.is_connected() {
            return Err(ClientError::NotConnected);
        }
        let (domain, item_id) = parse_gocb_ref(reference)?;
        let arc = self.mms_client_arc();
        let mut client = arc.lock().await;
        let data = client.read(&domain, &item_id).await?;
        drop(client);
        parse_gocb_structure(&data)
    }

    /// Writes attributes of a GOOSE control block (ACSI SetGoCBValues).
    ///
    /// Only GoEna and GoID are writable; a server answers a write to any other
    /// attribute with `ObjectAccessDenied`. The attributes are written one
    /// request at a time and the first failure ends the call.
    ///
    /// # Errors
    ///
    /// `NotConnected` if the association is not established, `InvalidArgument`
    /// for a malformed reference, and the error the server reports for a write.
    pub async fn set_gocb_values(
        &self,
        reference: &str,
        write: GoCBValuesWrite,
    ) -> Result<(), ClientError> {
        if !self.is_connected() {
            return Err(ClientError::NotConnected);
        }
        let (domain, item_base) = parse_gocb_ref(reference)?;
        let arc = self.mms_client_arc();
        let mut client = arc.lock().await;
        // GoID is written before GoEna, so publishing never starts under the
        // old identifier and then changes it mid-stream.
        if let Some(go_id) = write.go_id {
            let item = format!("{item_base}$GoID");
            let value = mms_value_to_mms_data(&MmsValue::VisibleString(go_id));
            client.write(&domain, &item, value).await?;
        }
        if let Some(go_ena) = write.go_ena {
            let item = format!("{item_base}$GoEna");
            let value = mms_value_to_mms_data(&MmsValue::Boolean(go_ena));
            client.write(&domain, &item, value).await?;
        }
        Ok(())
    }
}

// The `mms_client` field is private to the crate and this file defines its
// methods in a separate extension impl, so it reaches the field through the
// accessor on the connection.
impl<T, Tm> IedConnection<T, Tm> {
    pub(crate) fn mms_client_arc(&self) -> Arc<Mutex<iec61850_mms::mms::client::MmsClient<T, Tm>>> {
        self.mms_client_arc_inner()
    }
}

// Keeps the `Ordering` import from reading as unused: the connected flag is
// read through `is_connected` rather than directly here.
#[allow(dead_code)]
fn _force_use_atomic_ordering() {
    let _ = Ordering::Acquire;
}

#[cfg(test)]
mod tests {
    use super::*;

    // parse_gocb_ref

    #[test]
    fn parse_iec_notation() {
        let (d, i) = parse_gocb_ref("IED1LD0/LLN0.gcb01").unwrap();
        assert_eq!(d, "IED1LD0");
        assert_eq!(i, "LLN0$GO$gcb01");
    }

    #[test]
    fn parse_mms_notation() {
        let (d, i) = parse_gocb_ref("IED1LD0/LLN0$GO$gcb01").unwrap();
        assert_eq!(d, "IED1LD0");
        assert_eq!(i, "LLN0$GO$gcb01");
    }

    #[test]
    fn parse_missing_slash_rejects() {
        assert!(parse_gocb_ref("noSlashHere").is_err());
    }

    #[test]
    fn parse_missing_dot_iec_rejects() {
        assert!(parse_gocb_ref("IED1LD0/LLN0").is_err());
    }

    #[test]
    fn parse_empty_segments_rejects() {
        assert!(parse_gocb_ref("IED1LD0/.gcb01").is_err());
        assert!(parse_gocb_ref("IED1LD0/LLN0.").is_err());
        assert!(parse_gocb_ref("IED1LD0/$GO$gcb01").is_err());
    }

    #[test]
    fn parse_iec_rejects_dot_in_gcb_name() {
        // A '.' inside the control block name would be ambiguous.
        assert!(parse_gocb_ref("IED1LD0/LLN0.gcb.01").is_err());
    }

    // parse_gocb_structure

    fn sample_struct() -> MmsData {
        MmsData::Structure(vec![
            MmsData::VisibleString("IED1LD0/LLN0$GO$gcb01".into()),
            MmsData::Boolean(true),
            MmsData::VisibleString("MyGoID".into()),
            MmsData::VisibleString("IED1LD0/LLN0$ds1".into()),
            MmsData::Unsigned(7),
            MmsData::Boolean(false),
            MmsData::Structure(vec![
                MmsData::OctetString(vec![0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01]),
                MmsData::Unsigned(4),
                MmsData::Unsigned(100),
                MmsData::Unsigned(0x1000),
            ]),
            MmsData::Unsigned(10),
            MmsData::Unsigned(2000),
        ])
    }

    #[test]
    fn parse_full_structure() {
        let v = parse_gocb_structure(&sample_struct()).unwrap();
        assert_eq!(v.go_cb_ref, "IED1LD0/LLN0$GO$gcb01");
        assert!(v.go_ena);
        assert_eq!(v.go_id, "MyGoID");
        assert_eq!(v.dat_set, "IED1LD0/LLN0$ds1");
        assert_eq!(v.conf_rev, 7);
        assert!(!v.nds_com);
        assert_eq!(v.dst_address.addr, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01]);
        assert_eq!(v.dst_address.priority, 4);
        assert_eq!(v.dst_address.vlan_id, 100);
        assert_eq!(v.dst_address.app_id, 0x1000);
        assert_eq!(v.min_time_ms, 10);
        assert_eq!(v.max_time_ms, 2000);
    }

    #[test]
    fn parse_wrong_top_type_rejects() {
        let r = parse_gocb_structure(&MmsData::Boolean(true));
        assert!(matches!(r, Err(ClientError::UnexpectedValueType { .. })));
    }

    #[test]
    fn parse_wrong_element_count_rejects() {
        let r = parse_gocb_structure(&MmsData::Structure(vec![MmsData::Boolean(true)]));
        assert!(matches!(r, Err(ClientError::InvalidArgument(_))));
    }

    #[test]
    fn parse_dst_address_wrong_addr_len() {
        let mut items = match sample_struct() {
            MmsData::Structure(items) => items,
            _ => unreachable!(),
        };
        // Shorten dst_address.addr to five bytes.
        if let MmsData::Structure(inner) = &mut items[6] {
            inner[0] = MmsData::OctetString(vec![0; 5]);
        }
        let r = parse_gocb_structure(&MmsData::Structure(items));
        assert!(matches!(r, Err(ClientError::InvalidArgument(_))));
    }

    // GoCBValuesWrite builder

    #[test]
    fn write_builder_chains() {
        let w = GoCBValuesWrite::new().with_go_ena(true).with_go_id("X");
        assert_eq!(w.go_ena, Some(true));
        assert_eq!(w.go_id.as_deref(), Some("X"));
    }
}
