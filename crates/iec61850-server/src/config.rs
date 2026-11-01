//! `IedServerConfig`: the settings an IED server reads at start-up.
//!
//! The fields cover association handling (connection limit, edition, write
//! access) and the identification strings returned by the MMS Identify service.

#[cfg(not(feature = "std"))]
use alloc::string::String;

use iec61850_model::utc_time::{TimeAccuracy, TimeQuality};

use crate::policy::WriteAccessPolicies;

/// Start-up settings for [`crate::IedServer`].
///
/// TLS is not configured here; it is injected through the server builder.
/// `Default` reproduces the behavior IEC 61850 prescribes when nothing is
/// configured.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IedServerConfig {
    /// Maximum number of concurrent MMS connections. A connection counts from
    /// the moment its socket is accepted, before it has associated, until its
    /// socket closes. Defaults to 5.
    pub max_mms_connections: usize,

    /// Time an accepted connection has to complete the TLS handshake, when TLS
    /// is configured, and association setup through the MMS Initiate exchange;
    /// a connection that has not associated by then is closed. Defaults to
    /// 10 000 ms.
    pub association_setup_timeout_ms: u64,

    /// Time an established association may go without receiving a PDU or
    /// completing the send of one before the server aborts it, so a client
    /// that only receives reports stays open. `None` keeps an idle association
    /// open indefinitely. Defaults to 300 000 ms.
    pub association_idle_timeout_ms: Option<u64>,

    /// Time the peer has to accept each PDU the server sends on an established
    /// association; a peer that stops reading has its connection closed once a
    /// write exceeds it. Defaults to 10 000 ms.
    pub association_send_timeout_ms: u64,

    /// Maximum number of data sets clients may create at run time through
    /// DefineNamedVariableList, across all associations. Defaults to 64.
    pub max_dynamic_datasets: usize,

    /// Maximum number of run-time data sets one open association may have
    /// created. Defaults to 16.
    pub max_dynamic_datasets_per_association: usize,

    /// IEC 61850 edition the server presents. Defaults to `Ed2`.
    ///
    /// The only behavior that depends on it is which GOOSE control block
    /// components a client may write: under `Ed2_1`, GoID and DatSet are
    /// read-only (IEC 61850-8-1 §18.1.1.1.1 Table 83); under `Ed2`, and under
    /// `Ed1`, which behaves as `Ed2`, both are writable while the control
    /// block is disabled (IEC 61850-7-2 §18.2.1 Table 42).
    pub edition: Edition,

    /// Functional constraints a remote client may write. Defaults to
    /// `SP | SV | SE`.
    pub write_access_policies: WriteAccessPolicies,

    /// TimeQuality of the timestamps the server generates: the `LActTm`
    /// timestamp of the setting group control blocks and the GOOSE `t` of the
    /// publishers [`register_from_model`](crate::IedServer::register_from_model)
    /// creates.
    ///
    /// The default has leap seconds known, no clock failure, the clock
    /// synchronized, and a TimeAccuracy of 10 bits.
    pub time_quality: TimeQuality,

    /// Vendor name returned by the Identify service. `None` selects the
    /// built-in default.
    pub vendor_name: Option<String>,
    /// Model name returned by the Identify service. `None` selects the
    /// built-in default.
    pub model_name: Option<String>,
    /// Revision returned by the Identify service. `None` selects the built-in
    /// default.
    pub revision: Option<String>,
}

impl Default for IedServerConfig {
    fn default() -> Self {
        Self {
            max_mms_connections: 5,
            association_setup_timeout_ms: 10_000,
            association_idle_timeout_ms: Some(300_000),
            association_send_timeout_ms: 10_000,
            max_dynamic_datasets: 64,
            max_dynamic_datasets_per_association: 16,
            edition: Edition::Ed2,
            write_access_policies: WriteAccessPolicies::default(),
            time_quality: DEFAULT_TIME_QUALITY,
            vendor_name: None,
            model_name: None,
            revision: None,
        }
    }
}

/// IEC 61850 edition the server conforms to.
///
/// See [`IedServerConfig::edition`] for the behavior that depends on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Edition {
    /// Edition 1.
    Ed1 = 0,
    /// Edition 2.
    Ed2 = 1,
    /// Edition 2.1.
    Ed2_1 = 2,
}

/// Default [`IedServerConfig::time_quality`]: leap seconds known, no clock
/// failure, clock synchronized, and 10 significant bits of FractionOfSecond.
pub(crate) const DEFAULT_TIME_QUALITY: TimeQuality = TimeQuality::new(
    true,
    false,
    false,
    match TimeAccuracy::bits(10) {
        Ok(a) => a,
        Err(_) => panic!("10 significant bits is a valid time accuracy"),
    },
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_max_connections_is_five() {
        assert_eq!(IedServerConfig::default().max_mms_connections, 5);
    }

    #[test]
    fn default_time_quality_is_known_leap_seconds_with_accuracy_10() {
        let tq = IedServerConfig::default().time_quality;
        assert!(tq.leap_seconds_known);
        assert!(!tq.clock_failure);
        assert!(!tq.clock_not_synchronized);
        assert_eq!(tq.time_accuracy.significant_bits(), Some(10));
        assert_eq!(tq.to_byte(), 0x80 | 10);
    }
}
