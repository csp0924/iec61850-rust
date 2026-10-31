//! Server status through the MMS Status service.
//!
//! IEC 61850-8-1 lists Status among the MMS services outside the ACSI mapping
//! and recommends it for compatibility with MMS systems: it reports the
//! logical and physical status of the virtual manufacturing device.

use iec61850_hal::time::Timer;
use iec61850_hal::transport::AsyncTransport;
use iec61850_mms::mms::pdu::{StatusResponse, VmdLogicalStatus, VmdPhysicalStatus};

use crate::connection::IedConnection;
use crate::error::ClientError;
use crate::prelude::Vec;

/// The status a server reports through the MMS Status service.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServerStatus {
    /// Which services the server currently permits, `vmdLogicalStatus`.
    pub logical: VmdLogicalStatus,
    /// Operational condition of the server, `vmdPhysicalStatus`.
    pub physical: VmdPhysicalStatus,
    /// Implementation-specific detail bits in transmission order,
    /// `localDetail`; `None` when the server leaves the field out.
    pub local_detail: Option<Vec<bool>>,
}

impl From<StatusResponse> for ServerStatus {
    fn from(resp: StatusResponse) -> Self {
        Self {
            logical: resp.logical_status,
            physical: resp.physical_status,
            local_detail: resp.local_detail,
        }
    }
}

impl<T: AsyncTransport, Tm: Timer> IedConnection<T, Tm> {
    /// Reads the logical and physical status of the server with the MMS
    /// Status service.
    ///
    /// With `extended_derivation` the server derives the status by executing
    /// its own checks rather than reporting the status it holds. A status
    /// value outside the ones ISO 9506-2 names arrives as the `Other` variant.
    ///
    /// # Errors
    ///
    /// `NotConnected` if the association is not established. A confirmed
    /// error or a reject from the server, which is how a server without the
    /// service answers, becomes `ClientError::Service` or
    /// `ClientError::Reject`.
    pub async fn get_server_status(
        &self,
        extended_derivation: bool,
    ) -> Result<ServerStatus, ClientError> {
        if !self.is_connected() {
            return Err(ClientError::NotConnected);
        }
        let mut client = self.mms_client.lock().await;
        let resp = client.status(extended_derivation).await?;
        Ok(resp.into())
    }
}
