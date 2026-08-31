//! Reading RCB values from a server (IEC 61850-7-2 GetRCBValues).
//!
//! Reading and refreshing are separate calls: `get_rcb_values` reads an object
//! reference and returns a new `RcbHandle`, while `refresh_rcb_values` updates
//! an existing handle in place.
//!
//! Both issue an MMS Read over the connection's client, convert the returned
//! structure with [`crate::mms_compat::mms_data_to_mms_value`] and decode it
//! through `update_values`. Without an association both return
//! `ClientError::NotConnected`.

use crate::connection::IedConnection;
use crate::error::ClientError;
use crate::mms_compat::mms_data_to_mms_value;
use crate::prelude::{format, String, ToString};
use crate::rcb::handle::{unwrap_structure, update_values, RcbHandle};
use crate::rcb::write::parse_object_reference;
use iec61850_hal::time::Timer;
use iec61850_hal::transport::AsyncTransport;
use iec61850_model::value::MmsValue;

// Pure decoding, without IO.

/// Builds a new `RcbHandle` from the structure a server returned.
///
/// Performs no IO, so the decoding path is testable on its own. `rcb_ref` is
/// the object reference, `response` the `MmsValue::Structure` read back.
///
/// # Errors
///
/// `InvalidArgument` for a malformed reference, and `TypeMismatch` if the
/// response is not a structure of the expected shape.
pub fn create_rcb_from_mms(rcb_ref: &str, response: &MmsValue) -> Result<RcbHandle, ClientError> {
    let mut rcb = RcbHandle::new(rcb_ref)?;
    let elements = unwrap_structure(response, "create_rcb_from_mms")?;
    update_values(&mut rcb, elements)?;
    Ok(rcb)
}

/// Updates an existing `RcbHandle` from the structure a server returned.
///
/// Performs no IO.
///
/// # Errors
///
/// `TypeMismatch` if the response is not a structure of the expected shape.
pub fn update_rcb_from_mms(rcb: &mut RcbHandle, response: &MmsValue) -> Result<(), ClientError> {
    let elements = unwrap_structure(response, "update_rcb_from_mms")?;
    update_values(rcb, elements)
}

// Object reference to MMS domain and item id.

/// Splits an object reference into the domain id and item id of an MMS Read,
/// mapping `.` to `$` per IEC 61850-8-1.
///
/// Returns `None` when the reference has no `/`; its length and character set
/// are already checked by `RcbHandle::new`.
pub(crate) fn rcb_ref_to_mms_ids(reference: &str) -> Option<(String, String)> {
    parse_object_reference(reference)
}

// Asynchronous read API.

/// Reads an RCB from a server and returns a new `RcbHandle`.
///
/// The reference is validated (length, character set, separator, buffered or
/// unbuffered) before an MMS Read is issued over the connection.
///
/// # Errors
///
/// `InvalidArgument` for a malformed reference or a domain id longer than 64
/// bytes, `NotConnected` if the association is not established, `Mms` for an
/// error from the layer below, and `TypeMismatch` if the response does not
/// have the shape of an RCB.
pub async fn get_rcb_values<T: AsyncTransport, Tm: Timer>(
    conn: &IedConnection<T, Tm>,
    rcb_ref: &str,
) -> Result<RcbHandle, ClientError> {
    // Reference validation happens before anything reaches the wire.
    let _rcb_skeleton = RcbHandle::new(rcb_ref)?;
    let (domain, item) = rcb_ref_to_mms_ids(rcb_ref).ok_or_else(|| {
        ClientError::InvalidArgument(format!("cannot parse RCB object reference '{rcb_ref}'"))
    })?;
    if domain.len() > 64 {
        return Err(ClientError::InvalidArgument(format!(
            "domain id '{domain}' length {} exceeds the limit of 64",
            domain.len()
        )));
    }

    if !conn.is_connected() {
        return Err(ClientError::NotConnected);
    }

    let mms_data = {
        let mut client = conn.mms_client.lock().await;
        client.read(&domain, &item).await?
    };

    let value = mms_data_to_mms_value(&mms_data);
    create_rcb_from_mms(rcb_ref, &value)
}

/// Refreshes an existing `RcbHandle` in place from the server
/// (IEC 61850-7-2 GetRCBValues).
///
/// # Errors
///
/// As for [`get_rcb_values`], minus the reference validation, which the handle
/// passed when it was created.
pub async fn refresh_rcb_values<T: AsyncTransport, Tm: Timer>(
    conn: &IedConnection<T, Tm>,
    rcb: &mut RcbHandle,
) -> Result<(), ClientError> {
    let rcb_ref = rcb.object_reference().to_string();
    let (domain, item) = rcb_ref_to_mms_ids(&rcb_ref).ok_or_else(|| {
        ClientError::InvalidArgument(format!("cannot parse RCB object reference '{rcb_ref}'"))
    })?;

    if !conn.is_connected() {
        return Err(ClientError::NotConnected);
    }

    let mms_data = {
        let mut client = conn.mms_client.lock().await;
        client.read(&domain, &item).await?
    };

    let value = mms_data_to_mms_value(&mms_data);
    update_rcb_from_mms(rcb, &value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iec61850_model::value::MmsValue;

    fn make_urcb_structure() -> MmsValue {
        MmsValue::Structure(vec![
            MmsValue::VisibleString("rpt_get_test".to_string()), // 0
            MmsValue::Boolean(false),                            // 1
            MmsValue::Boolean(false),                            // 2
            MmsValue::VisibleString("IED/DS1".to_string()),      // 3
            MmsValue::Unsigned(42),                              // 4 confRev
            MmsValue::BitString {
                padding: 6,
                data: vec![0x00, 0x00],
            }, // 5 optFlds
            MmsValue::Unsigned(100),                             // 6 bufTm ms
            MmsValue::Unsigned(5),                               // 7 sqNum
            MmsValue::BitString {
                padding: 2,
                data: vec![0x40],
            }, // 8 trgOps: wire 0x40 is DATA_CHANGED
            MmsValue::Unsigned(30000),                           // 9 intgPd ms
            MmsValue::Boolean(false),                            // 10 gi
        ])
    }

    #[test]
    fn create_rcb_from_mms_urcb_ok() {
        let val = make_urcb_structure();
        let rcb = create_rcb_from_mms("IED1/LD0$RP$rcb01", &val).unwrap();
        assert_eq!(rcb.rpt_id(), Some("rpt_get_test"));
        assert_eq!(rcb.conf_rev(), 42);
        assert_eq!(rcb.buf_tm_ms(), 100);
        assert_eq!(rcb.sq_num(), 5);
        assert_eq!(rcb.intg_pd_ms(), 30000);
        // Wire byte 0x40 is wire bit 1, which is DATA_CHANGED.
        use crate::rcb::mask::TriggerOptions;
        assert!(rcb.trg_ops().contains(TriggerOptions::DATA_CHANGED));
    }

    #[test]
    fn update_rcb_from_mms_urcb_ok() {
        let mut rcb = RcbHandle::new("IED1/LD0$RP$rcb01").unwrap();
        let val = make_urcb_structure();
        update_rcb_from_mms(&mut rcb, &val).unwrap();
        assert_eq!(rcb.conf_rev(), 42);
        assert_eq!(rcb.sq_num(), 5);
    }

    #[test]
    fn create_rcb_from_mms_wrong_type_fails() {
        // A Boolean where a Structure is required.
        let val = MmsValue::Boolean(true);
        let err = create_rcb_from_mms("IED1/LD0$RP$rcb01", &val).unwrap_err();
        assert!(matches!(err, ClientError::TypeMismatch { .. }));
    }

    #[test]
    fn rcb_ref_to_mms_ids_dot_sep() {
        let (domain, item) = rcb_ref_to_mms_ids("simpleIOGenericIO/LLN0.RP.urcb01").unwrap();
        assert_eq!(domain, "simpleIOGenericIO");
        assert_eq!(item, "LLN0$RP$urcb01");
    }

    /// `get_rcb_values` reports `NotConnected` instead of letting the call fail
    /// as an opaque IO error at the transport.
    #[tokio::test]
    async fn get_rcb_values_not_connected_returns_err() {
        let conn = IedConnection::new();
        // A fresh connection has not been connected.
        let err = get_rcb_values(&conn, "IED1/LD0$RP$rcb01")
            .await
            .unwrap_err();
        assert!(matches!(err, ClientError::NotConnected));
    }

    /// The same for `refresh_rcb_values`.
    #[tokio::test]
    async fn refresh_rcb_values_not_connected_returns_err() {
        let conn = IedConnection::new();
        let mut rcb = RcbHandle::new("IED1/LD0$RP$rcb01").unwrap();
        let err = refresh_rcb_values(&conn, &mut rcb).await.unwrap_err();
        assert!(matches!(err, ClientError::NotConnected));
    }

    /// A malformed reference is rejected before the connection check.
    #[tokio::test]
    async fn get_rcb_values_invalid_ref_rejected_before_wire() {
        let conn = IedConnection::new();
        // Neither a '/' nor a separator.
        let err = get_rcb_values(&conn, "no_separators_here")
            .await
            .unwrap_err();
        assert!(matches!(err, ClientError::InvalidArgument(_)));
    }
}
