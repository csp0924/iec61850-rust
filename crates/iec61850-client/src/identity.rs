//! Server identification through the MMS Identify service.
//!
//! IEC 61850-8-1 lists Identify among the MMS services an implementation
//! carries, outside the ACSI mapping: it names the vendor, model and revision
//! of the responding implementation.

use iec61850_hal::time::Timer;
use iec61850_hal::transport::AsyncTransport;
use iec61850_mms::mms::pdu::IdentifyResponse;

use crate::connection::IedConnection;
use crate::error::ClientError;
use crate::prelude::{String, Vec};

/// The identity a server reports through the MMS Identify service.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServerIdentity {
    /// Vendor of the server implementation, `vendorName`.
    pub vendor: String,
    /// Model of the server implementation, `modelName`.
    pub model: String,
    /// Revision of the server implementation, `revision`.
    pub revision: String,
    /// Abstract syntaxes the server lists, each OBJECT IDENTIFIER held as its
    /// arcs; empty when the server leaves `listOfAbstractSyntaxes` out.
    pub abstract_syntaxes: Vec<Vec<u32>>,
}

impl From<IdentifyResponse> for ServerIdentity {
    fn from(resp: IdentifyResponse) -> Self {
        Self {
            vendor: resp.vendor_name,
            model: resp.model_name,
            revision: resp.revision,
            abstract_syntaxes: resp.list_of_abstract_syntaxes,
        }
    }
}

impl<T: AsyncTransport, Tm: Timer> IedConnection<T, Tm> {
    /// Reads the vendor, model and revision of the server with the MMS
    /// Identify service.
    ///
    /// # Errors
    ///
    /// `NotConnected` if the association is not established. A confirmed
    /// error or a reject from the server, which is how a server without the
    /// service answers, becomes `ClientError::Mms`.
    pub async fn get_server_identity(&self) -> Result<ServerIdentity, ClientError> {
        if !self.is_connected() {
            return Err(ClientError::NotConnected);
        }
        let mut client = self.mms_client.lock().await;
        let resp = client.identify().await?;
        Ok(resp.into())
    }
}
