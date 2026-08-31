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
//! - A Conclude request from the server is answered with `0x8c` and reported as a
//!   lost connection.

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
pub use error::ClientError;
pub use services::MmsValue;

use crate::compat::prelude::*;
use crate::mms::pdu::{ObjectClass, TypeSpecification};
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

// MmsClientBuilder

/// Builder for [`MmsClient`].
#[derive(Debug, Default)]
pub struct MmsClientBuilder {
    connect_timeout_ms: Option<u64>,
    request_timeout_ms: Option<u64>,
    max_outstanding: Option<u32>,
    local_max_pdu_size: Option<u32>,
}

impl MmsClientBuilder {
    /// Creates a builder holding the default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the connect timeout in milliseconds.
    pub fn connect_timeout_ms(mut self, ms: u64) -> Self {
        self.connect_timeout_ms = Some(ms);
        self
    }

    /// Sets the request timeout in milliseconds.
    pub fn request_timeout_ms(mut self, ms: u64) -> Self {
        self.request_timeout_ms = Some(ms);
        self
    }

    /// Sets how many requests may be outstanding at once.
    pub fn max_outstanding(mut self, n: u32) -> Self {
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
        let max_out = self.max_outstanding.unwrap_or(5);
        MmsClient {
            conn,
            alloc: invoke_id::InvokeIdAllocator::new(max_out),
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
    /// CPA, ACSE AARQ and AARE, then the MMS Initiate exchange.
    pub async fn connect(&mut self, host: &str, port: u16) -> Result<(), ClientError> {
        self.conn.connect(host, port).await
    }

    /// Establishes an ISO and MMS association over TLS.
    ///
    /// The sequence adds a TLS handshake after the TCP connection and is otherwise
    /// identical to the plaintext path.
    ///
    /// `addr` is the server address, `connector` a `TlsConnector` already configured
    /// with the IEC 62351-3 cipher suites, and `server_name` the name used for SNI
    /// and certificate validation.
    #[cfg(feature = "tls")]
    pub async fn connect_tls(
        &mut self,
        addr: std::net::SocketAddr,
        connector: &iec61850_tls::TlsConnector,
        server_name: rustls::pki_types::ServerName<'static>,
    ) -> Result<(), ClientError> {
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
}

impl<T: AsyncTransport, Tm: Timer> MmsClient<T, Tm> {
    /// As [`Self::from_transport`], but with a caller-supplied timer instance.
    pub async fn from_transport_with_timer(transport: T, timer: Tm) -> Result<Self, ClientError> {
        let mut conn = MmsConnection::<T, Tm>::with_timer(timer);
        conn.connect_via(transport).await?;
        Ok(Self {
            conn,
            alloc: invoke_id::InvokeIdAllocator::new(5),
        })
    }

    // Association management

    /// Runs the MMS Conclude sequence and closes the connection.
    pub async fn disconnect(&mut self) -> Result<(), ClientError> {
        self.conn.disconnect().await
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
    /// Returns:
    /// - `Ok(Some(inner))` for an unconfirmed PDU whose outer `0xa3` has been stripped,
    ///   leaving `0xa0 <combined_body>` for the InformationReport decoder.
    /// - `Ok(None)` when no complete PDU arrived within the timeout.
    /// - `Err(_)` on an I/O or parse failure, or when a confirmed response arrives with
    ///   no request outstanding, which means the exchange is out of step and the caller
    ///   should close the connection.
    ///
    /// A Conclude request from the server is answered with `0x8c` one layer down and
    /// surfaces here as `Err(ConnectionLost)`.
    pub async fn recv_unconfirmed_pdu_with_timeout(
        &mut self,
        timeout_dur: core::time::Duration,
    ) -> Result<Option<bytes::Bytes>, ClientError> {
        // drain any InformationReport stashed while a confirmed call was in flight
        if let Some(inner) = self.conn.pop_pending_unconfirmed() {
            return Ok(Some(inner));
        }
        match self
            .conn
            .recv_mms_pdu_with_timeout(Some(timeout_dur))
            .await?
        {
            None => Ok(None),
            Some(crate::mms::pdu::MmsPdu::Unconfirmed(inner)) => Ok(Some(inner)),
            Some(other) => {
                tracing::warn!(
                    tag = format!("0x{:02x}", other.tag_byte()),
                    "recv_unconfirmed_pdu: received a pdu that is not unconfirmed, discarding it and reporting an error"
                );
                Err(ClientError::PduParse(format!(
                    "expected Unconfirmed (0xa3), got tag=0x{:02x}",
                    other.tag_byte()
                )))
            }
        }
    }
}

#[cfg(feature = "std")]
impl Default for MmsClient<TcpStream, TokioTimer> {
    fn default() -> Self {
        Self::new()
    }
}
