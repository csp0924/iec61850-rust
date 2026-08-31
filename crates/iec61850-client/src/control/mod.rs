//! Client-side control services (IEC 61850-7-2 Select, SelectWithValue,
//! Operate and Cancel).
//!
//! [`ControlObjectClient`] is the per-object handle;
//! `IedConnection::create_control_object` builds one on an existing
//! connection.
//!
//! # Examples
//!
//! ```no_run
//! use iec61850_client::IedConnection;
//! use iec61850_client::control::{ControlOutcome, OriginValue};
//! use iec61850_model::{ControlModel, MmsValue};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let conn = IedConnection::new();
//! conn.connect("127.0.0.1", 102).await?;
//! let mut spc = conn.create_control_object(
//!     "simpleIOGenericIO/GGIO1.SPCSO1",
//!     ControlModel::DirectNormal,
//! )?;
//! spc.set_origin(OriginValue::bay_control());
//! match spc.operate(MmsValue::Boolean(true)).await? {
//!     ControlOutcome::Success => println!("operate ok"),
//!     ControlOutcome::Failure(c) => println!("operate failed: {c:?}"),
//! }
//! # Ok(()) }
//! ```

pub mod client;
pub mod encode;
pub mod model;

pub use client::ControlObjectClient;
pub use model::{
    CommandTerminationParsed, ControlAddCause, ControlLastApplError, ControlModel, ControlOutcome,
    LastApplError, OriginValue, SboClass,
};

// Connection extension: create_control_object.

use iec61850_hal::time::Timer;
use iec61850_hal::transport::AsyncTransport;

use crate::connection::IedConnection;
use crate::error::ClientError;
use crate::prelude::Arc;

impl<T: AsyncTransport, Tm: Timer> IedConnection<T, Tm> {
    /// Creates a `ControlObjectClient` sharing the MMS client of this
    /// connection.
    ///
    /// `object_ref` is an IEC-notation reference such as
    /// `IED1LD0/GGIO1.SPCSO1`. `ctl_model` is the control model of the object;
    /// a caller that does not know it reads `<DO>$CF$ctlModel` first.
    ///
    /// The connection state is not checked here, so a handle may be built
    /// before connecting; the services themselves return `NotConnected`.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` if `object_ref` is not `<LD>/<LN>.<DO>`.
    pub fn create_control_object(
        &self,
        object_ref: &str,
        ctl_model: ControlModel,
    ) -> Result<ControlObjectClient<T, Tm>, ClientError> {
        ControlObjectClient::new(
            object_ref,
            ctl_model,
            Arc::clone(&self.mms_client),
            Arc::clone(self.is_connected_arc()),
        )
    }
}
