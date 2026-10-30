//! TLS integration layer compatible with IEC 62351-3.
//!
//! [`TlsConfigBuilder`] produces client and server configurations with the
//! profile's constraints already applied: TLS 1.2 as the floor and a fixed
//! cipher suite whitelist. [`TlsConnector`] and [`TlsAcceptor`] wrap
//! `tokio-rustls` and hand back a `TlsStream<TcpStream>` that plugs straight
//! into the COTP connection type.
//!
//! The verifier wrappers add the profile's stricter certificate rules.
//! [`AllowOnlyKnownCertsServerVerifier`] and its client counterpart reject a
//! peer whose leaf certificate is not on the configured list, and reject an
//! empty list outright; on the server the client counterpart also makes a
//! client certificate mandatory. [`IgnoreValidityTimeServerVerifier`] and
//! [`IgnoreValidityTimeClientVerifier`] relax only the validity-time check
//! when it is off, and still reject every other chain error.
//!
//! [`TlsEventHandler`] carries the 20 event codes of IEC 62351-3 §5.
//! [`IEC62351_3_TLS12_CIPHERS`] and [`IEC62351_3_TLS13_CIPHERS`] are the
//! whitelist itself; its TLS 1.2 part contains ECDHE_RSA and ECDHE_ECDSA with
//! AES-GCM, because the rustls ring provider implements no finite-field DHE
//! suite. Library code never panics; every failure path returns
//! `Result<_, TlsError>`.

pub mod acceptor;
pub mod ciphers;
pub mod config;
pub mod connector;
pub mod error;
pub mod event;
mod session;
pub mod verifier;

#[cfg(test)]
mod tests;

pub use acceptor::TlsAcceptor;
pub use ciphers::{IEC62351_3_ALL_CIPHERS, IEC62351_3_TLS12_CIPHERS, IEC62351_3_TLS13_CIPHERS};
pub use config::{TlsClientConfig, TlsConfigBuilder, TlsServerConfig, TlsVersion};
pub use connector::TlsConnector;
pub use error::TlsError;
pub use event::{
    DefaultTracingHandler, NullEventHandler, TlsEventCode, TlsEventHandler, TlsEventLevel,
};
pub use verifier::{
    AllowOnlyKnownCertsClientVerifier, AllowOnlyKnownCertsServerVerifier,
    IgnoreValidityTimeClientVerifier, IgnoreValidityTimeServerVerifier,
};
