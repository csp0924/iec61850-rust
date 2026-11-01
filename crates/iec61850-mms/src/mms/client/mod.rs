//! Async MMS client API.
//!
//! ## Usage
//!
//! ```no_run
//! use iec61850_mms::mms::client::{MmsClient, MmsClientBuilder};
//! use iec61850_mms::mms::pdu::ObjectClass;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let mut client = MmsClientBuilder::new()
//!     .request_timeout_ms(5_000)
//!     .build();
//!
//! client.connect("127.0.0.1", 102).await?;
//! let value = client.read("DOMAIN", "LLN0$ST$Mod$stVal").await?;
//! client.disconnect().await?;
//! # Ok(()) }
//! ```
//!
//! Synchronous callers use the `BlockingMmsClient` wrapper.
//!
//! ## Behavior
//!
//! - The API is async throughout and all framing goes through `CotpConnection`.
//! - An exhausted invokeID space returns `ClientError::InvokeIdExhausted`.
//! - A PDU above the negotiated maximum returns `ClientError::PduTooLarge`.
//! - An answer is bound to its request by invokeID. A request without an answer
//!   within the request timeout returns `ClientError::ServiceTimeout` and its late
//!   answer is discarded; the association stays usable.
//! - The end of the transport, or a Session abort or disconnect from the peer,
//!   closes the client and returns `ClientError::ConnectionLost`.
//! - A release by the peer, a Session finish or a Conclude request from the
//!   server, is answered, closes the client and returns
//!   `ClientError::ReleasedByPeer`.

// `blocking` is the synchronous wrapper; it starts a runtime internally and is std only.
#[cfg(feature = "std")]
pub mod blocking;
pub mod connection;
pub mod error;
pub mod invoke_id;
pub mod services;

#[cfg(feature = "std")]
pub use blocking::BlockingMmsClient;
pub use connection::{ConnectionState, MmsConnection};
pub use error::{ClientError, TlsFailureKind};
pub use services::MmsValue;

use crate::compat::prelude::*;
use crate::compat::Arc;
use crate::iso::params::IsoConnectionParameters;
use crate::mms::pdu::{ObjectClass, TypeSpecification};
use core::sync::atomic::AtomicBool;
use iec61850_hal::time::Timer;
use iec61850_hal::transport::AsyncTransport;

// std only: `MmsClient` and `MmsClientBuilder::build` name `TcpStream` and
// `TokioTimer` as their default type parameters, so both must be in scope here.
// Without the std feature those defaults, the builder and the `Default` impl are all
// behind the same cfg, so nothing refers to types that do not exist.
#[cfg(feature = "std")]
use iec61850_hal::time::TokioTimer;
#[cfg(feature = "std")]
use tokio::net::TcpStream;

/// Ceiling of the invokeID allocator. A service call holds one invokeID for
/// its duration and calls are serialized by `&mut self`; the negotiated
/// outstanding limit is enforced by the connection, not by the allocator.
const INVOKE_ID_POOL: u32 = 5;

// MmsClientBuilder

/// Builder for [`MmsClient`].
#[derive(Debug, Default)]
pub struct MmsClientBuilder {
    connect_timeout_ms: Option<u64>,
    request_timeout_ms: Option<u64>,
    max_outstanding: Option<u16>,
    local_max_pdu_size: Option<u32>,
    iso_parameters: Option<IsoConnectionParameters>,
    max_pending_unconfirmed: Option<usize>,
}

impl MmsClientBuilder {
    /// Creates a builder holding the default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the connect timeout in milliseconds: one deadline for the TCP
    /// connection, the TLS handshake when there is one, and the COTP CR and CC
    /// together.
    pub fn connect_timeout_ms(mut self, ms: u64) -> Self {
        self.connect_timeout_ms = Some(ms);
        self
    }

    /// Sets the request timeout in milliseconds.
    pub fn request_timeout_ms(mut self, ms: u64) -> Self {
        self.request_timeout_ms = Some(ms);
        self
    }

    /// Sets proposedMaxServOutstandingCalling, how many confirmed requests the
    /// client proposes to have outstanding at once; 0 is proposed as 1.
    ///
    /// The server may negotiate fewer, and the negotiated value is enforced:
    /// a request that timed out counts as outstanding until its late answer
    /// arrives, and once such requests hold every slot the next request waits
    /// up to the request timeout for a late answer before failing with
    /// `ClientError::OutstandingCallLimit`. A request the peer discarded holds
    /// its slot until the client reconnects. Without it
    /// `DEFAULT_MAX_SERV_OUTSTANDING_CALLING`, 5, applies.
    pub fn max_outstanding(mut self, n: u16) -> Self {
        self.max_outstanding = Some(n);
        self
    }

    /// Overrides `localDetailCalling`, the maximum PDU size proposed in the Initiate
    /// request, in bytes.
    ///
    /// Setting a small value negotiates a small `negotiated_max_pdu_size`, which
    /// exercises the outbound size guard end to end.
    /// Without it `DEFAULT_MAX_PDU_SIZE`, 65000, applies.
    pub fn local_max_pdu_size(mut self, size: u32) -> Self {
        self.local_max_pdu_size = Some(size);
        self
    }

    /// Sets the ISO addressing the association offers: the T, S and P selectors
    /// and the AP-title and AE-qualifier of both sides.
    ///
    /// Without it `IsoConnectionParameters::default()` applies, which is the
    /// addressing IEC 61850-8-1 Annex A lists for an MMS association.
    pub fn iso_parameters(mut self, params: IsoConnectionParameters) -> Self {
        self.iso_parameters = Some(params);
        self
    }

    /// Sets how many Unconfirmed PDUs, such as InformationReports, may wait for
    /// the report dispatcher while confirmed calls are in flight.
    ///
    /// When the ceiling is reached the oldest waiting PDU is dropped with a
    /// warning. Without it `DEFAULT_MAX_PENDING_UNCONFIRMED`, 1024, applies.
    pub fn max_pending_unconfirmed(mut self, n: usize) -> Self {
        self.max_pending_unconfirmed = Some(n);
        self
    }

    /// Builds a client over the default std transport and timer.
    ///
    /// This method is std only. An embedded caller uses
    /// `MmsClient::<MyTransport, MyTimer>::from_transport_with_timer` instead.
    #[cfg(feature = "std")]
    pub fn build(self) -> MmsClient {
        let mut conn = MmsConnection::<TcpStream, TokioTimer>::new();
        if let Some(t) = self.connect_timeout_ms {
            conn.connect_timeout_ms = t;
        }
        if let Some(t) = self.request_timeout_ms {
            conn.request_timeout_ms = t;
        }
        if let Some(size) = self.local_max_pdu_size {
            conn.local_max_pdu_size = Some(size);
        }
        if let Some(params) = self.iso_parameters {
            conn.set_iso_parameters(params);
        }
        if let Some(n) = self.max_pending_unconfirmed {
            conn.max_pending_unconfirmed = n;
        }
        conn.local_max_outstanding = self.max_outstanding;
        MmsClient {
            conn,
            alloc: invoke_id::InvokeIdAllocator::new(INVOKE_ID_POOL),
        }
    }
}

// MmsClient

/// An async MMS client.
///
/// Owns an `MmsConnection<T, Tm>`, the async transport with its ISO stack and timer,
/// together with an `InvokeIdAllocator`. On std the type parameters default to
/// `TcpStream` and `TokioTimer`; an embedded build states both explicitly and enters
/// through `MmsClient::<MyTransport, MyTimer>::from_transport_with_timer`.
#[cfg(feature = "std")]
pub struct MmsClient<T = TcpStream, Tm = TokioTimer> {
    conn: MmsConnection<T, Tm>,
    alloc: invoke_id::InvokeIdAllocator,
}

/// The no_std form of `MmsClient`, whose type parameters have no defaults.
#[cfg(not(feature = "std"))]
pub struct MmsClient<T, Tm> {
    conn: MmsConnection<T, Tm>,
    alloc: invoke_id::InvokeIdAllocator,
}

#[cfg(feature = "std")]
impl MmsClient<TcpStream, TokioTimer> {
    /// Builds a client with the default settings.
    pub fn new() -> Self {
        MmsClientBuilder::new().build()
    }

    /// Establishes an ISO and MMS association over a new TCP connection.
    ///
    /// The sequence is TCP, COTP CR and CC, Session CN and AC, Presentation CP and
    /// CPA, ACSE AARQ and AARE, then the MMS Initiate exchange. An association
    /// still established, over TCP or TLS, is closed first without a release.
    pub async fn connect(&mut self, host: &str, port: u16) -> Result<(), ClientError> {
        self.alloc.clear();
        self.conn.connect(host, port).await
    }

    /// Establishes an ISO and MMS association over TLS.
    ///
    /// The sequence adds a TLS handshake after the TCP connection and is otherwise
    /// identical to the plaintext path, including closing an association still
    /// established first.
    ///
    /// `addr` is the server address, `connector` a `TlsConnector` already configured
    /// with the IEC 62351-3 cipher suites, and `server_name` the name used for SNI
    /// and certificate validation. The TCP connection, the handshake and the
    /// COTP CR and CC share one deadline of the connect timeout. A failed
    /// handshake returns `ClientError::TlsHandshake` with its
    /// [`TlsFailureKind`], and so does running out of the deadline during the
    /// handshake, with the `Timeout` kind; running out of it during the TCP
    /// connection or the COTP handshake returns `ConnectTimeout`. A TLS error
    /// after the handshake and before the association is established, such as
    /// the fatal alert of a TLS 1.3 server refusing the client certificate,
    /// returns `ClientError::TlsHandshake` as well.
    #[cfg(feature = "tls")]
    pub async fn connect_tls(
        &mut self,
        addr: std::net::SocketAddr,
        connector: &iec61850_tls::TlsConnector,
        server_name: rustls::pki_types::ServerName<'static>,
    ) -> Result<(), ClientError> {
        self.alloc.clear();
        self.conn.connect_tls(addr, connector, server_name).await
    }
}

impl<T: AsyncTransport, Tm: Timer + Default> MmsClient<T, Tm> {
    /// Runs the ISO and MMS Initiate exchange over an already connected transport and
    /// returns a client ready to issue services.
    ///
    /// The timer comes from `Tm::default()`. When the timer is not `Default`, for
    /// instance an embedded driver instance, use [`Self::from_transport_with_timer`].
    ///
    /// This is the entry point for callers that own the transport themselves, having
    /// brought up the network stack outside this crate.
    pub async fn from_transport(transport: T) -> Result<Self, ClientError> {
        Self::from_transport_with_timer(transport, Tm::default()).await
    }
}

/// State accessors that read only `MmsConnection` fields and touch neither the
/// transport nor the timer, so they carry no `AsyncTransport` or `Timer` bound and
/// remain callable where those bounds are not yet available.
impl<T, Tm> MmsClient<T, Tm> {
    /// Returns the current connection state.
    pub fn state(&self) -> ConnectionState {
        self.conn.state
    }

    /// Returns the negotiated maximum PDU size.
    pub fn negotiated_max_pdu_size(&self) -> usize {
        self.conn.negotiated_max_pdu_size
    }

    /// Returns a flag that is `true` exactly while the association is established.
    ///
    /// Every call returns the same flag, which the client keeps current on every
    /// state change, including a transport loss found inside a service call. An
    /// observer can therefore test liveness without waiting for an in-flight call.
    pub fn connected_flag(&mut self) -> Arc<AtomicBool> {
        self.conn.connected_flag()
    }
}

impl<T: AsyncTransport, Tm: Timer> MmsClient<T, Tm> {
    /// As [`Self::from_transport`], but with a caller-supplied timer instance.
    ///
    /// The association uses `IsoConnectionParameters::default()`; to offer
    /// different addressing use [`Self::from_transport_with_iso_parameters`].
    pub async fn from_transport_with_timer(transport: T, timer: Tm) -> Result<Self, ClientError> {
        Self::from_transport_with_iso_parameters(
            transport,
            timer,
            IsoConnectionParameters::default(),
        )
        .await
    }

    /// As [`Self::from_transport_with_timer`], but with caller-supplied ISO
    /// addressing.
    ///
    /// This is the entry point for a caller that owns its transport, an
    /// embedded IP stack for instance, and needs selectors or an AP-title other
    /// than the defaults; such a caller never goes through `MmsClientBuilder`.
    pub async fn from_transport_with_iso_parameters(
        transport: T,
        timer: Tm,
        params: IsoConnectionParameters,
    ) -> Result<Self, ClientError> {
        let mut conn = MmsConnection::<T, Tm>::with_timer(timer);
        conn.set_iso_parameters(params);
        conn.connect_via(transport).await?;
        Ok(Self {
            conn,
            alloc: invoke_id::InvokeIdAllocator::new(INVOKE_ID_POOL),
        })
    }

    // Association management

    /// Releases the association, MMS Conclude followed by the ACSE A-RELEASE, and
    /// closes the connection.
    ///
    /// # Errors
    ///
    /// - `NotConnected` when no association is established.
    /// - `ConcludeRejected` when the server refuses the Conclude; the association
    ///   stays established.
    pub async fn disconnect(&mut self) -> Result<(), ClientError> {
        self.conn.disconnect().await
    }

    /// Aborts the association: sends an ACSE ABRT inside a Session AB and closes
    /// the transport without waiting for an answer.
    ///
    /// # Errors
    ///
    /// The transport error when the abort cannot be sent; the client is closed
    /// either way.
    pub async fn abort(&mut self) -> Result<(), ClientError> {
        self.conn.abort().await
    }

    /// Closes the transport immediately, without any release handshake.
    pub fn close_raw(&mut self) {
        self.conn.close_raw();
    }

    // Service API

    /// Reads one MMS variable.
    ///
    /// `domain` is the domain name, such as `"IED1CTRL"`, and `item` the variable
    /// name, such as `"LLN0$ST$Mod$stVal"`.
    pub async fn read(&mut self, domain: &str, item: &str) -> Result<MmsValue, ClientError> {
        services::read_variable(&mut self.conn, &mut self.alloc, domain, item).await
    }

    /// Writes one MMS variable.
    pub async fn write(
        &mut self,
        domain: &str,
        item: &str,
        value: MmsValue,
    ) -> Result<(), ClientError> {
        services::write_variable(&mut self.conn, &mut self.alloc, domain, item, value).await
    }

    /// Read a single array element, optionally targeting a sub-component.
    ///
    /// `index` is the 0-based array index. `component = None` reads the
    /// element itself; `component = Some("stVal")` (or multi-level paths
    /// such as `"inner$f"`) reads a sub-DA within the element. The request
    /// uses MMS `AlternateAccess` (IEC 61850-8-1 §17).
    pub async fn read_single_array_element(
        &mut self,
        domain: &str,
        item: &str,
        index: u32,
        component: Option<&str>,
    ) -> Result<MmsValue, ClientError> {
        services::read_single_array_element(
            &mut self.conn,
            &mut self.alloc,
            domain,
            item,
            index,
            component,
        )
        .await
    }

    /// Write a single array element, optionally targeting a sub-component.
    /// Symmetric to [`Self::read_single_array_element`].
    pub async fn write_single_array_element(
        &mut self,
        domain: &str,
        item: &str,
        index: u32,
        component: Option<&str>,
        value: MmsValue,
    ) -> Result<(), ClientError> {
        services::write_single_array_element(
            &mut self.conn,
            &mut self.alloc,
            domain,
            item,
            index,
            component,
            value,
        )
        .await
    }

    /// Reads every value of a named variable list, that is a data set.
    ///
    /// This is GetDataSetValues of IEC 61850-7-2. The result holds one `AccessResult`
    /// per entry, so the caller sees which entries succeeded.
    pub async fn read_named_variable_list_values(
        &mut self,
        domain: &str,
        list_name: &str,
    ) -> Result<Vec<crate::mms::pdu::AccessResult>, ClientError> {
        services::read_named_variable_list_values(
            &mut self.conn,
            &mut self.alloc,
            domain,
            list_name,
        )
        .await
    }

    /// Writes every value of a named variable list, that is a data set.
    ///
    /// This is SetDataSetValues of IEC 61850-7-2. `values.len()` must equal the number
    /// of entries in the data set, or the server answers with a per-entry
    /// `DataAccessError::TypeInconsistent`.
    pub async fn write_named_variable_list_values(
        &mut self,
        domain: &str,
        list_name: &str,
        values: Vec<MmsValue>,
    ) -> Result<Vec<crate::mms::pdu::WriteOutcome>, ClientError> {
        services::write_named_variable_list_values(
            &mut self.conn,
            &mut self.alloc,
            domain,
            list_name,
            values,
        )
        .await
    }

    /// Creates a dynamic data set, a named variable list.
    ///
    /// This is CreateDataSet of IEC 61850-7-2, and `entries` are stored in the order
    /// given. A confirmed error from the server, for instance because the data set
    /// already exists or a member cannot be resolved, becomes
    /// `ClientError::ServiceError`.
    pub async fn define_named_variable_list(
        &mut self,
        domain: &str,
        list_name: &str,
        entries: Vec<crate::mms::pdu::DefineNamedVariableEntry>,
    ) -> Result<(), ClientError> {
        services::define_named_variable_list(
            &mut self.conn,
            &mut self.alloc,
            domain,
            list_name,
            entries,
        )
        .await
    }

    /// Deletes a dynamic data set, a named variable list.
    ///
    /// This is DeleteDataSet of IEC 61850-7-2. It returns the number of objects matched
    /// and the number deleted; a caller normally checks that at least one was deleted,
    /// since an unknown or static data set yields 0 without being an error.
    pub async fn delete_named_variable_list(
        &mut self,
        domain: &str,
        list_name: &str,
    ) -> Result<(u32, u32), ClientError> {
        services::delete_named_variable_list(&mut self.conn, &mut self.alloc, domain, list_name)
            .await
    }

    /// Retrieves the attributes of a dynamic or configured named variable list.
    ///
    /// This is GetDataSetDirectory of IEC 61850-7-2. The response carries the
    /// members in the order the server holds them, each with an optional
    /// `AlternateAccess` selector, together with `mmsDeletable`, which is true
    /// only for a list created by DefineNamedVariableList.
    ///
    /// A list the server does not hold becomes `ClientError::ServiceError`.
    pub async fn get_named_variable_list_attributes(
        &mut self,
        domain: &str,
        list_name: &str,
    ) -> Result<crate::mms::pdu::GetNamedVariableListAttributesResponse, ClientError> {
        services::get_named_variable_list_attributes(
            &mut self.conn,
            &mut self.alloc,
            domain,
            list_name,
        )
        .await
    }

    /// Asks the server to identify itself with the MMS Identify service.
    ///
    /// The response carries the vendor name, model name and revision, and the
    /// abstract syntaxes the server lists, if any. A server that does not offer
    /// the service answers with a reject, which becomes
    /// `ClientError::RejectError`.
    pub async fn identify(&mut self) -> Result<crate::mms::pdu::IdentifyResponse, ClientError> {
        services::identify(&mut self.conn, &mut self.alloc).await
    }

    /// Asks the server for the logical and physical status of its VMD with the
    /// MMS Status service.
    ///
    /// With `extended_derivation` the server derives the status by executing
    /// its own checks rather than reporting the status it holds. A server that
    /// does not offer the service answers with a reject, which becomes
    /// `ClientError::RejectError`.
    pub async fn status(
        &mut self,
        extended_derivation: bool,
    ) -> Result<crate::mms::pdu::StatusResponse, ClientError> {
        services::status(&mut self.conn, &mut self.alloc, extended_derivation).await
    }

    /// Retrieves a list of object names.
    ///
    /// `object_class` selects the class to enumerate, such as `ObjectClass::NamedVariable`.
    /// `domain` of `Some(name)` selects a domain-specific scope, and `None` the VMD.
    /// `continue_after` is the paging cursor, and `None` starts from the beginning.
    ///
    /// Returns the names together with whether more of them remain.
    pub async fn get_name_list(
        &mut self,
        object_class: ObjectClass,
        domain: Option<&str>,
        continue_after: Option<&str>,
    ) -> Result<(Vec<String>, bool), ClientError> {
        services::get_name_list(
            &mut self.conn,
            &mut self.alloc,
            object_class,
            domain,
            continue_after,
        )
        .await
    }

    /// Retrieves the access attributes of a variable.
    pub async fn get_variable_access_attributes(
        &mut self,
        domain: &str,
        item: &str,
    ) -> Result<TypeSpecification, ClientError> {
        services::get_variable_access_attributes(&mut self.conn, &mut self.alloc, domain, item)
            .await
    }

    /// Reads journal entries.
    ///
    /// `req` carries the journal name and either the time-range or start-after form.
    pub async fn read_journal(
        &mut self,
        req: &crate::mms::pdu::ReadJournalRequest,
    ) -> Result<crate::mms::pdu::ReadJournalResponse, ClientError> {
        services::read_journal(&mut self.conn, &mut self.alloc, req).await
    }

    /// Returns a set of Unconfirmed PDU content bytes to the back of the stash.
    ///
    /// A command-termination wait that takes a report it is not waiting for puts it
    /// back here for the report dispatcher.
    pub fn push_back_unconfirmed(&mut self, inner: bytes::Bytes) {
        self.conn.push_pending_unconfirmed(inner);
    }

    /// Receives the next unconfirmed PDU, such as an InformationReport pushed by the
    /// server, under a timeout.
    ///
    /// This supports polling report subscriptions: the caller drives the loop and
    /// decodes listOfAccessResult from each report it receives.
    ///
    /// Cancel safety: the transport keeps its partial read state, so a timeout loses
    /// no bytes and the next poll continues from the same point.
    ///
    /// `timeout_dur` is the only timeout applied, so it may exceed the request
    /// timeout. The late answer to a request that timed out is discarded on the way.
    ///
    /// Returns:
    /// - `Ok(Some(inner))` for an unconfirmed PDU whose outer `0xa3` has been stripped,
    ///   leaving `0xa0 <combined_body>` for the InformationReport decoder.
    /// - `Ok(None)` when no unconfirmed PDU arrived within the timeout.
    /// - `Err(ConnectionLost)` when the peer ended the connection, which is then
    ///   closed.
    /// - `Err(ReleasedByPeer)` when the peer released the association; the
    ///   release is answered and the connection closed.
    /// - `Err(_)` otherwise on an I/O or parse failure, or when a confirmed answer
    ///   arrives that matches no request, which means the exchange is out of step.
    pub async fn recv_unconfirmed_pdu_with_timeout(
        &mut self,
        timeout_dur: core::time::Duration,
    ) -> Result<Option<bytes::Bytes>, ClientError> {
        // drain any InformationReport stashed while a confirmed call was in flight
        if let Some(inner) = self.conn.pop_pending_unconfirmed() {
            return Ok(Some(inner));
        }
        self.conn.recv_unconfirmed(timeout_dur).await
    }

    /// Reads several MMS variables with one Read service.
    ///
    /// The entries travel as a `listOfVariable`, so no temporary named
    /// variable list is needed. The result holds one `AccessResult` per entry
    /// in request order, and an entry that fails keeps its position as a
    /// `Failure`.
    ///
    /// An empty `entries` is refused before anything is sent, and a response
    /// whose access result count differs from `entries.len()` is an error
    /// rather than a padded or truncated list.
    pub async fn read_list(
        &mut self,
        entries: Vec<crate::mms::pdu::ListOfVariableEntry>,
    ) -> Result<Vec<crate::mms::pdu::AccessResult>, ClientError> {
        services::read_list(&mut self.conn, &mut self.alloc, entries).await
    }
}

#[cfg(feature = "std")]
impl Default for MmsClient<TcpStream, TokioTimer> {
    fn default() -> Self {
        Self::new()
    }
}
