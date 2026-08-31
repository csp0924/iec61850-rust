//! `IedConnection`: the connection object carrying connect, disconnect, read
//! and write.
//!
//! The struct and its transport-independent methods live here so that a build
//! without the `reporting` feature still gets a usable connection; the
//! reporting, RCB, journal and GoCB methods are defined on it elsewhere behind
//! that feature gate. The `reports` field itself is feature-gated, and the
//! constructors branch on the same `cfg`.
//!
//! ## Type parameters
//!
//! `IedConnection<T = TcpStream, Tm = TokioTimer>` holds an `MmsClient<T, Tm>`
//! and passes both parameters straight through (`T: AsyncTransport`,
//! `Tm: Timer`). A std build therefore spells `IedConnection` without type
//! parameters; a caller with its own transport or timer builds the
//! `MmsClient` itself and hands it to `with_mms_client`.
//!
//! `new`, `connect` and `connect_tls` exist only for
//! `MmsClient<TcpStream, TokioTimer>`, because the underlying MMS client only
//! offers them on those default types. The struct is declared twice, once per
//! `std` cfg branch with identical fields, because the type-parameter defaults
//! depend on tokio.

use core::sync::atomic::AtomicBool;

use iec61850_hal::time::Timer;
use iec61850_hal::transport::AsyncTransport;
use iec61850_mms::mms::client::{ConnectionState, MmsClient};

use crate::error::ClientError;
use crate::prelude::Arc;
use crate::sync::Mutex;

// Default type parameters, matching those of `MmsClient`.
#[cfg(feature = "std")]
use iec61850_hal::time::TokioTimer;
#[cfg(feature = "std")]
use iec61850_mms::mms::client::MmsClientBuilder;
#[cfg(feature = "std")]
use tokio::net::TcpStream;

/// A connection to an IED, exposing the ACSI services over MMS.
///
/// The inner `MmsClient` is behind a mutex so that at most one service call is
/// in flight on a connection at a time, matching the single invoke-id pool the
/// MMS association provides. Concurrent callers queue; requests are not
/// pipelined.
///
/// `T` is the async transport under MMS and `Tm` the timer backend. On an
/// embedded build both parameters are mandatory, as the defaults depend on
/// tokio; the fields are identical either way.
#[cfg(feature = "std")]
pub struct IedConnection<T = TcpStream, Tm = TokioTimer> {
    #[cfg(feature = "reporting")]
    pub(crate) reports: Arc<crate::report::dispatch::ReportRegistry>,
    pub(crate) mms_client: Arc<Mutex<MmsClient<T, Tm>>>,
    pub(crate) is_connected: Arc<AtomicBool>,
    /// Device model cache, keyed by logical device name. Populated lazily on
    /// the first directory call and reused afterwards.
    pub(crate) device_model: Arc<Mutex<Option<crate::directory::DeviceModel>>>,
}

/// `IedConnection` without type-parameter defaults, for a `no_std` build.
#[cfg(not(feature = "std"))]
pub struct IedConnection<T, Tm> {
    #[cfg(feature = "reporting")]
    pub(crate) reports: Arc<crate::report::dispatch::ReportRegistry>,
    pub(crate) mms_client: Arc<Mutex<MmsClient<T, Tm>>>,
    pub(crate) is_connected: Arc<AtomicBool>,
    pub(crate) device_model: Arc<Mutex<Option<crate::directory::DeviceModel>>>,
}

// Accessors independent of transport and timer, shared by the submodules.

impl<T, Tm> IedConnection<T, Tm> {
    /// Shares the connection flag with the control module.
    #[allow(dead_code)]
    pub(crate) fn is_connected_arc(&self) -> &Arc<AtomicBool> {
        &self.is_connected
    }

    /// Shares the MMS client handle with the GoCB module, whose methods are
    /// defined in another file and would otherwise reach into the field.
    #[allow(dead_code)]
    pub(crate) fn mms_client_arc_inner(&self) -> Arc<Mutex<MmsClient<T, Tm>>> {
        self.mms_client.clone()
    }

    /// Reports whether the association is established.
    pub fn is_connected(&self) -> bool {
        self.is_connected
            .load(core::sync::atomic::Ordering::Acquire)
    }
}

// Generic construction over any transport and timer.

impl<T, Tm> IedConnection<T, Tm> {
    /// Builds a connection around an existing `MmsClient<T, Tm>`.
    ///
    /// The entry point for a caller supplying its own transport or timer: build
    /// the client with `MmsClient::from_transport_with_timer`, which completes
    /// the ISO and MMS Initiate exchange, then pass it here.
    ///
    /// The connected flag is taken from the client's own state rather than
    /// forced to false, so that an already-initiated client is usable
    /// immediately; a client from `MmsClientBuilder::build()` is still closed,
    /// which is what `IedConnection::new()` relies on.
    pub fn with_mms_client(mms_client: MmsClient<T, Tm>) -> Self {
        let connected = mms_client.state() == ConnectionState::Connected;
        Self {
            #[cfg(feature = "reporting")]
            reports: Arc::new(crate::report::dispatch::ReportRegistry::new()),
            mms_client: Arc::new(Mutex::new(mms_client)),
            is_connected: Arc::new(AtomicBool::new(connected)),
            device_model: Arc::new(Mutex::new(None)),
        }
    }
}

// Disconnect and abort, available for any transport and timer.

impl<T: AsyncTransport, Tm: Timer> IedConnection<T, Tm> {
    /// Closes the association: sends MMS Conclude, then closes the transport.
    pub async fn disconnect(&self) -> Result<(), ClientError> {
        self.is_connected
            .store(false, core::sync::atomic::Ordering::Release);
        // A later connection may reach a different server; a stale model would
        // make the directory API compare against the wrong logical devices.
        *self.device_model.lock().await = None;
        let mut client = self.mms_client.lock().await;
        client.disconnect().await?;
        Ok(())
    }

    /// Closes the transport immediately, without the Conclude exchange.
    ///
    /// This is the abort path; the peer sees the association drop.
    pub async fn abort(&self) -> Result<(), ClientError> {
        self.is_connected
            .store(false, core::sync::atomic::Ordering::Release);
        *self.device_model.lock().await = None;
        let mut client = self.mms_client.lock().await;
        client.close_raw();
        Ok(())
    }
}

// Constructors for the default types. These call inherent methods that the MMS
// client only provides on `MmsClient<TcpStream, TokioTimer>`; a caller with its
// own transport has already connected before `with_mms_client`.

#[cfg(feature = "std")]
impl IedConnection<TcpStream, TokioTimer> {
    /// Creates a connection object that is not yet connected.
    pub fn new() -> Self {
        Self::with_mms_client(MmsClientBuilder::new().build())
    }

    /// Establishes the ISO and MMS association with a server.
    pub async fn connect(&self, host: &str, port: u16) -> Result<(), ClientError> {
        let mut client = self.mms_client.lock().await;
        client.connect(host, port).await?;
        self.is_connected
            .store(true, core::sync::atomic::Ordering::Release);
        Ok(())
    }

    /// Establishes a TLS-protected ISO and MMS association.
    ///
    /// Once the TLS handshake completes, the usual COTP, Session, Presentation,
    /// ACSE and MMS Initiate sequence runs over it.
    ///
    /// `addr` is the server address; MMS over TLS is normally reached on port
    /// 3782 rather than 102. `connector` carries the IEC 62351-3 cipher suite
    /// selection, and `server_name` is used for SNI and certificate validation.
    #[cfg(feature = "tls")]
    pub async fn connect_tls(
        &self,
        addr: std::net::SocketAddr,
        connector: &iec61850_tls::TlsConnector,
        server_name: rustls::pki_types::ServerName<'static>,
    ) -> Result<(), ClientError> {
        let mut client = self.mms_client.lock().await;
        client.connect_tls(addr, connector, server_name).await?;
        self.is_connected
            .store(true, core::sync::atomic::Ordering::Release);
        Ok(())
    }
}

#[cfg(feature = "std")]
impl Default for IedConnection<TcpStream, TokioTimer> {
    fn default() -> Self {
        Self::new()
    }
}
