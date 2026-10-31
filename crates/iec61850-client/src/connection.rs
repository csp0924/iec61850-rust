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
use iec61850_mms::IsoConnectionParameters;
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
    pub(crate) device_model: Arc<Mutex<Option<Arc<crate::directory::DeviceModel>>>>,
    /// Most names one GetNameList walk may collect.
    pub(crate) max_name_list_names: usize,
}

/// `IedConnection` without type-parameter defaults, for a `no_std` build.
#[cfg(not(feature = "std"))]
pub struct IedConnection<T, Tm> {
    #[cfg(feature = "reporting")]
    pub(crate) reports: Arc<crate::report::dispatch::ReportRegistry>,
    pub(crate) mms_client: Arc<Mutex<MmsClient<T, Tm>>>,
    pub(crate) is_connected: Arc<AtomicBool>,
    pub(crate) device_model: Arc<Mutex<Option<Arc<crate::directory::DeviceModel>>>>,
    pub(crate) max_name_list_names: usize,
}

// Accessors independent of transport and timer, shared by the submodules.

impl<T, Tm> IedConnection<T, Tm> {
    /// Shares the connection flag with the control module.
    #[cfg(feature = "control")]
    pub(crate) fn is_connected_arc(&self) -> &Arc<AtomicBool> {
        &self.is_connected
    }

    /// Shares the MMS client handle with the GoCB module, whose methods are
    /// defined in another file and would otherwise reach into the field.
    #[cfg(feature = "reporting")]
    pub(crate) fn mms_client_arc(&self) -> Arc<Mutex<MmsClient<T, Tm>>> {
        self.mms_client.clone()
    }

    /// Reports whether the association is established.
    ///
    /// The flag is shared with the MMS client, so it turns false as soon as a
    /// service call finds the transport lost or the peer ending the association,
    /// and every later service call then returns `NotConnected`.
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
    /// The connected flag is the client's own [`MmsClient::connected_flag`], so
    /// an already-initiated client is usable immediately; a client from
    /// `MmsClientBuilder::build()` is still closed, which is what
    /// `IedConnection::new()` relies on.
    pub fn with_mms_client(mut mms_client: MmsClient<T, Tm>) -> Self {
        let is_connected: Arc<AtomicBool> = mms_client.connected_flag();
        Self {
            #[cfg(feature = "reporting")]
            reports: Arc::new(crate::report::dispatch::ReportRegistry::new()),
            mms_client: Arc::new(Mutex::new(mms_client)),
            is_connected,
            device_model: Arc::new(Mutex::new(None)),
            max_name_list_names: crate::directory::DEFAULT_MAX_NAME_LIST_NAMES,
        }
    }

    /// Sets the most names one GetNameList walk of the directory services may
    /// collect across its pages; a walk past it fails with
    /// [`ClientError::NameListLimit`].
    ///
    /// The limit keeps a server that keeps reporting more names from holding
    /// the client in the walk. Defaults to
    /// [`DEFAULT_MAX_NAME_LIST_NAMES`](crate::directory::DEFAULT_MAX_NAME_LIST_NAMES).
    pub fn with_max_name_list_names(mut self, max_names: usize) -> Self {
        self.max_name_list_names = max_names;
        self
    }

    /// Returns the most names one GetNameList walk may collect.
    pub fn max_name_list_names(&self) -> usize {
        self.max_name_list_names
    }
}

// Disconnect and abort, available for any transport and timer.

impl<T: AsyncTransport, Tm: Timer> IedConnection<T, Tm> {
    /// Closes the association: MMS Conclude, then the ACSE release, then the
    /// transport is closed.
    ///
    /// The cached device model is dropped once the association has ended, and
    /// kept while it stays established.
    ///
    /// # Errors
    ///
    /// `ConcludeRejected` when the server refuses the Conclude; the
    /// association then stays established and `is_connected` reports true
    /// again.
    pub async fn disconnect(&self) -> Result<(), ClientError> {
        self.is_connected
            .store(false, core::sync::atomic::Ordering::Release);
        let mut client = self.mms_client.lock().await;
        let result = client.disconnect().await;
        let still_associated = client.state() == ConnectionState::Connected;
        drop(client);
        // A later connection may reach a different server; a stale model would
        // make the directory API compare against the wrong logical devices.
        // While a refused Conclude leaves the association open, the model
        // still describes the server.
        if !still_associated {
            *self.device_model.lock().await = None;
        }
        result.map_err(ClientError::from)
    }

    /// Aborts the association without the Conclude exchange: an ACSE ABRT is
    /// sent inside a Session AB and the transport is closed.
    ///
    /// The association ends even when the abort cannot be sent, so that case is
    /// logged rather than returned.
    pub async fn abort(&self) -> Result<(), ClientError> {
        self.is_connected
            .store(false, core::sync::atomic::Ordering::Release);
        *self.device_model.lock().await = None;
        let mut client = self.mms_client.lock().await;
        if let Err(e) = client.abort().await {
            tracing::debug!(error = %e, "the abort could not be sent, the transport is closed");
        }
        Ok(())
    }
}

// Constructors for the default types. These call inherent methods that the MMS
// client only provides on `MmsClient<TcpStream, TokioTimer>`; a caller with its
// own transport has already connected before `with_mms_client`.

#[cfg(feature = "std")]
impl IedConnection<TcpStream, TokioTimer> {
    /// Creates a connection object that is not yet connected.
    ///
    /// The association it opens offers `IsoConnectionParameters::default()`.
    pub fn new() -> Self {
        Self::with_mms_client(MmsClientBuilder::new().build())
    }

    /// Creates a connection object that is not yet connected, offering
    /// caller-supplied ISO addressing.
    ///
    /// The parameters carry the T, S and P selectors and the AP-title and
    /// AE-qualifier of both sides; they apply to the next `connect` or
    /// `connect_tls`.
    pub fn with_iso_parameters(params: IsoConnectionParameters) -> Self {
        Self::with_mms_client(MmsClientBuilder::new().iso_parameters(params).build())
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
    ///
    /// # Errors
    ///
    /// The TCP connection, the TLS handshake and the COTP CR and CC share one
    /// deadline, the connect timeout of the MMS client. A failed handshake
    /// returns [`ClientError::TlsHandshake`], whose
    /// [`TlsFailureKind`](crate::TlsFailureKind) tells why; running out of the
    /// deadline during the handshake is the `Timeout` kind, and during the TCP
    /// connection or the COTP handshake [`ClientError::ConnectTimeout`].
    ///
    /// Until the association is established, a TLS error also returns
    /// [`ClientError::TlsHandshake`], classified like a failed handshake. This
    /// covers a TLS 1.3 server that refuses the client certificate: the client
    /// completes its side of the handshake first and reads the fatal alert
    /// during the COTP exchange, which returns the `AlertReceived` kind. Any
    /// other failure after the handshake returns the error of its step.
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
