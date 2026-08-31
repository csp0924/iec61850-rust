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
//! ## Not for use inside a runtime
//!
//! A caller already inside a tokio runtime must not construct a `BlockingMmsClient`:
//! blocking on a current-thread runtime from within a runtime panics. Await the
//! `MmsClient` methods directly instead.

use super::error::ClientError;
use super::{ConnectionState, MmsClient, MmsClientBuilder, MmsValue};
use crate::mms::pdu::{ObjectClass, TypeSpecification};

/// Synchronous wrapper over [`MmsClient`], owning a private current-thread runtime.
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

    /// Returns the wrapped async client.
    pub fn into_inner(self) -> MmsClient {
        self.inner
    }

    // Association management

    /// Establishes an ISO and MMS association with the given host and port.
    pub fn connect(&mut self, host: &str, port: u16) -> Result<(), ClientError> {
        self.rt.block_on(self.inner.connect(host, port))
    }

    /// Establishes an association over TLS, synchronously.
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
    pub fn disconnect(&mut self) -> Result<(), ClientError> {
        self.rt.block_on(self.inner.disconnect())
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

    // Service API

    /// Reads one MMS variable.
    pub fn read(&mut self, domain: &str, item: &str) -> Result<MmsValue, ClientError> {
        self.rt.block_on(self.inner.read(domain, item))
    }

    /// Writes one MMS variable.
    pub fn write(&mut self, domain: &str, item: &str, value: MmsValue) -> Result<(), ClientError> {
        self.rt.block_on(self.inner.write(domain, item, value))
    }

    /// Retrieves a list of object names.
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
    pub fn get_variable_access_attributes(
        &mut self,
        domain: &str,
        item: &str,
    ) -> Result<TypeSpecification, ClientError> {
        self.rt
            .block_on(self.inner.get_variable_access_attributes(domain, item))
    }
}
