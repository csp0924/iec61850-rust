//! `BlockingMmsClient`, a synchronous wrapper over the async MMS client API.
//!
//! Intended for callers that are not async. It owns a current-thread runtime and each
//! method drives the matching async call to completion on it.
//!
//! ## Usage
//!
//! ```no_run
//! use iec61850_mms::mms::client::BlockingMmsClient;
//!
//! let mut client = BlockingMmsClient::new().unwrap();
//! client.connect("127.0.0.1", 102).unwrap();
//! let value = client.read("DOMAIN", "LLN0$ST$Mod$stVal").unwrap();
//! client.disconnect().unwrap();
//! ```
//!
//! ## Coverage
//!
//! Every service of [`MmsClient`] has a blocking counterpart of the same name and
//! arguments, as do the association and state accessors. The one exception is
//! the transport-generic entry point, `MmsClient::from_transport` and its
//! variants: a caller with its own transport is async already and uses
//! `MmsClient` directly.
//!
//! ## Not for use inside a runtime
//!
//! A caller already inside a tokio runtime must not use a `BlockingMmsClient`:
//! blocking on a current-thread runtime from within a runtime panics, and so does
//! dropping one there. Await the `MmsClient` methods directly instead.

use super::error::ClientError;
use super::{ConnectionState, MmsClient, MmsClientBuilder, MmsValue};
use crate::compat::Arc;
use crate::mms::pdu::{
    AccessResult, DefineNamedVariableEntry, GetNamedVariableListAttributesResponse,
    IdentifyResponse, ListOfVariableEntry, ObjectClass, ReadJournalRequest, ReadJournalResponse,
    StatusResponse, TypeSpecification, WriteOutcome,
};
use bytes::Bytes;
use core::sync::atomic::AtomicBool;
use core::time::Duration;

/// Synchronous wrapper over [`MmsClient`], owning a private current-thread runtime.
///
/// The runtime is dropped with the client, which panics inside an async
/// runtime; see the module documentation.
pub struct BlockingMmsClient {
    inner: MmsClient,
    rt: tokio::runtime::Runtime,
}

impl BlockingMmsClient {
    /// Builds a client with the default settings.
    ///
    /// Returns the `io::Error` from building the runtime, which rarely fails.
    pub fn new() -> std::io::Result<Self> {
        Self::from_builder(MmsClientBuilder::new())
    }

    /// Builds a client from a builder, keeping its timeout and size settings.
    pub fn from_builder(builder: MmsClientBuilder) -> std::io::Result<Self> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()?;
        Ok(Self {
            inner: builder.build(),
            rt,
        })
    }

    /// Splits the wrapper into the async client and the runtime that drives it.
    ///
    /// The socket and timers of an established association belong to the
    /// returned runtime, so the client's futures must run on it, for example
    /// with `rt.block_on(client.read(..))`. Once that runtime is dropped the
    /// association can no longer be used. A client that has not connected yet
    /// carries no such binding. Like the wrapper, the returned runtime must not
    /// be dropped or blocked on from within an async runtime; see the module
    /// documentation.
    pub fn into_parts(self) -> (MmsClient, tokio::runtime::Runtime) {
        (self.inner, self.rt)
    }

    // Association management

    /// Establishes an ISO and MMS association with the given host and port.
    ///
    /// # Panics
    ///
    /// Panics when called from within an async runtime; see the module
    /// documentation.
    pub fn connect(&mut self, host: &str, port: u16) -> Result<(), ClientError> {
        self.rt.block_on(self.inner.connect(host, port))
    }

    /// Establishes an association over TLS, synchronously.
    ///
    /// # Panics
    ///
    /// Panics when called from within an async runtime; see the module
    /// documentation.
    #[cfg(feature = "tls")]
    pub fn connect_tls(
        &mut self,
        addr: std::net::SocketAddr,
        connector: &iec61850_tls::TlsConnector,
        server_name: rustls::pki_types::ServerName<'static>,
    ) -> Result<(), ClientError> {
        self.rt
            .block_on(self.inner.connect_tls(addr, connector, server_name))
    }

    /// Runs the MMS Conclude sequence and closes the connection.
    ///
    /// # Panics
    ///
    /// Panics when called from within an async runtime; see the module
    /// documentation.
    pub fn disconnect(&mut self) -> Result<(), ClientError> {
        self.rt.block_on(self.inner.disconnect())
    }

    /// Aborts the association: sends an ACSE ABRT inside a Session AB and
    /// closes the transport without waiting for an answer.
    ///
    /// # Panics
    ///
    /// Panics when called from within an async runtime; see the module
    /// documentation.
    pub fn abort(&mut self) -> Result<(), ClientError> {
        self.rt.block_on(self.inner.abort())
    }

    /// Closes the transport immediately, without any release handshake.
    pub fn close_raw(&mut self) {
        self.inner.close_raw();
    }

    /// Returns the current connection state.
    pub fn state(&self) -> ConnectionState {
        self.inner.state()
    }

    /// Returns the negotiated maximum PDU size.
    pub fn negotiated_max_pdu_size(&self) -> usize {
        self.inner.negotiated_max_pdu_size()
    }

    /// Returns the number of the current association, or of the most recent
    /// one once it has ended; 0 before the first.
    ///
    /// Every association established gets a new number; see
    /// [`MmsClient::association_id`].
    pub fn association_id(&self) -> u64 {
        self.inner.association_id()
    }

    /// Returns a flag that is `true` exactly while the association is
    /// established.
    pub fn connected_flag(&mut self) -> Arc<AtomicBool> {
        self.inner.connected_flag()
    }

    // Service API

    /// Reads one MMS variable.
    ///
    /// # Panics
    ///
    /// Panics when called from within an async runtime; see the module
    /// documentation.
    pub fn read(&mut self, domain: &str, item: &str) -> Result<MmsValue, ClientError> {
        self.rt.block_on(self.inner.read(domain, item))
    }

    /// Writes one MMS variable.
    ///
    /// # Panics
    ///
    /// Panics when called from within an async runtime; see the module
    /// documentation.
    pub fn write(&mut self, domain: &str, item: &str, value: MmsValue) -> Result<(), ClientError> {
        self.rt.block_on(self.inner.write(domain, item, value))
    }

    /// Reads one array element, or a component of it.
    ///
    /// # Panics
    ///
    /// Panics when called from within an async runtime; see the module
    /// documentation.
    pub fn read_single_array_element(
        &mut self,
        domain: &str,
        item: &str,
        index: u32,
        component: Option<&str>,
    ) -> Result<MmsValue, ClientError> {
        self.rt.block_on(
            self.inner
                .read_single_array_element(domain, item, index, component),
        )
    }

    /// Writes one array element, or a component of it.
    ///
    /// # Panics
    ///
    /// Panics when called from within an async runtime; see the module
    /// documentation.
    pub fn write_single_array_element(
        &mut self,
        domain: &str,
        item: &str,
        index: u32,
        component: Option<&str>,
        value: MmsValue,
    ) -> Result<(), ClientError> {
        self.rt.block_on(
            self.inner
                .write_single_array_element(domain, item, index, component, value),
        )
    }

    /// Reads several MMS variables with one Read service.
    ///
    /// # Panics
    ///
    /// Panics when called from within an async runtime; see the module
    /// documentation.
    pub fn read_list(
        &mut self,
        entries: Vec<ListOfVariableEntry>,
    ) -> Result<Vec<AccessResult>, ClientError> {
        self.rt.block_on(self.inner.read_list(entries))
    }

    /// Reads every value of a named variable list.
    ///
    /// # Panics
    ///
    /// Panics when called from within an async runtime; see the module
    /// documentation.
    pub fn read_named_variable_list_values(
        &mut self,
        domain: &str,
        list_name: &str,
    ) -> Result<Vec<AccessResult>, ClientError> {
        self.rt.block_on(
            self.inner
                .read_named_variable_list_values(domain, list_name),
        )
    }

    /// Writes every value of a named variable list.
    ///
    /// # Panics
    ///
    /// Panics when called from within an async runtime; see the module
    /// documentation.
    pub fn write_named_variable_list_values(
        &mut self,
        domain: &str,
        list_name: &str,
        values: Vec<MmsValue>,
    ) -> Result<Vec<WriteOutcome>, ClientError> {
        self.rt.block_on(
            self.inner
                .write_named_variable_list_values(domain, list_name, values),
        )
    }

    /// Creates a named variable list.
    ///
    /// # Panics
    ///
    /// Panics when called from within an async runtime; see the module
    /// documentation.
    pub fn define_named_variable_list(
        &mut self,
        domain: &str,
        list_name: &str,
        entries: Vec<DefineNamedVariableEntry>,
    ) -> Result<(), ClientError> {
        self.rt.block_on(
            self.inner
                .define_named_variable_list(domain, list_name, entries),
        )
    }

    /// Deletes a named variable list and returns the numbers matched and
    /// deleted.
    ///
    /// # Panics
    ///
    /// Panics when called from within an async runtime; see the module
    /// documentation.
    pub fn delete_named_variable_list(
        &mut self,
        domain: &str,
        list_name: &str,
    ) -> Result<(u32, u32), ClientError> {
        self.rt
            .block_on(self.inner.delete_named_variable_list(domain, list_name))
    }

    /// Reads journal entries.
    ///
    /// # Panics
    ///
    /// Panics when called from within an async runtime; see the module
    /// documentation.
    pub fn read_journal(
        &mut self,
        req: &ReadJournalRequest,
    ) -> Result<ReadJournalResponse, ClientError> {
        self.rt.block_on(self.inner.read_journal(req))
    }

    /// Receives the next Unconfirmed PDU, such as an InformationReport, within
    /// `timeout_dur`; `Ok(None)` when none arrives in time.
    ///
    /// # Panics
    ///
    /// Panics when called from within an async runtime; see the module
    /// documentation.
    pub fn recv_unconfirmed_pdu_with_timeout(
        &mut self,
        timeout_dur: Duration,
    ) -> Result<Option<Bytes>, ClientError> {
        self.rt
            .block_on(self.inner.recv_unconfirmed_pdu_with_timeout(timeout_dur))
    }

    /// Returns a set of Unconfirmed PDU content bytes to the back of the stash.
    pub fn push_back_unconfirmed(&mut self, inner: Bytes) {
        self.inner.push_back_unconfirmed(inner);
    }

    /// Asks the server to identify itself with the MMS Identify service.
    ///
    /// # Panics
    ///
    /// Panics when called from within an async runtime; see the module
    /// documentation.
    pub fn identify(&mut self) -> Result<IdentifyResponse, ClientError> {
        self.rt.block_on(self.inner.identify())
    }

    /// Asks the server for the status of its VMD with the MMS Status service.
    ///
    /// # Panics
    ///
    /// Panics when called from within an async runtime; see the module
    /// documentation.
    pub fn status(&mut self, extended_derivation: bool) -> Result<StatusResponse, ClientError> {
        self.rt.block_on(self.inner.status(extended_derivation))
    }

    /// Retrieves a list of object names.
    ///
    /// # Panics
    ///
    /// Panics when called from within an async runtime; see the module
    /// documentation.
    pub fn get_name_list(
        &mut self,
        object_class: ObjectClass,
        domain: Option<&str>,
        continue_after: Option<&str>,
    ) -> Result<(Vec<String>, bool), ClientError> {
        self.rt.block_on(
            self.inner
                .get_name_list(object_class, domain, continue_after),
        )
    }

    /// Retrieves the access attributes of a variable.
    ///
    /// # Panics
    ///
    /// Panics when called from within an async runtime; see the module
    /// documentation.
    pub fn get_variable_access_attributes(
        &mut self,
        domain: &str,
        item: &str,
    ) -> Result<TypeSpecification, ClientError> {
        self.rt
            .block_on(self.inner.get_variable_access_attributes(domain, item))
    }

    /// Retrieves the attributes of a named variable list: its members, in
    /// order, and whether it may be deleted.
    ///
    /// # Panics
    ///
    /// Panics when called from within an async runtime; see the module
    /// documentation.
    pub fn get_named_variable_list_attributes(
        &mut self,
        domain: &str,
        list_name: &str,
    ) -> Result<GetNamedVariableListAttributesResponse, ClientError> {
        self.rt.block_on(
            self.inner
                .get_named_variable_list_attributes(domain, list_name),
        )
    }
}
