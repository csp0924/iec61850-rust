//! `IedServerConfig`: the settings an IED server reads at start-up.
//!
//! The fields cover association handling (connection limit, edition, write
//! access) and the identification strings returned by the MMS Identify service.

#[cfg(not(feature = "std"))]
use alloc::string::String;

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

    /// Time quality reported with every timestamp the server generates.
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
            time_quality: TimeQuality::default(),
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

/// UTC time quality flags, encoded into the eighth byte of an IEC 61850 UTC
/// timestamp (IEC 61850-7-2 §6.2.3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeQuality {
    /// `leapSecondsKnown`.
    pub leap_seconds_known: bool,
    /// `clockFailure`.
    pub clock_failure: bool,
    /// `clockNotSynchronized`.
    pub clock_not_synchronized: bool,
    /// `timeAccuracy`, in significant bits of fraction-of-second (0..=24).
    pub time_accuracy: u8,
}

impl Default for TimeQuality {
    /// Returns `leapSecondsKnown = true`, no clock failure, clock
    /// synchronized, and `timeAccuracy = 10`.
    fn default() -> Self {
        Self {
            leap_seconds_known: true,
            clock_failure: false,
            clock_not_synchronized: false,
            time_accuracy: 10,
        }
    }
}

impl TimeQuality {
    /// Encodes the flags into the timeQuality byte of an IEC 61850-7-2 UTC
    /// timestamp.
    ///
    /// Bit 7 is `leapSecondsKnown`, bit 6 `clockFailure`, bit 5
    /// `clockNotSynchronized`, and bits 0..4 hold `timeAccuracy`; an accuracy
    /// above 31 is truncated to 0x1F.
    pub fn to_byte(&self) -> u8 {
        let mut b: u8 = 0;
        if self.leap_seconds_known {
            b |= 0x80;
        }
        if self.clock_failure {
            b |= 0x40;
        }
        if self.clock_not_synchronized {
            b |= 0x20;
        }
        b |= self.time_accuracy & 0x1F;
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_max_connections_is_five() {
        assert_eq!(IedServerConfig::default().max_mms_connections, 5);
    }

    #[test]
    fn default_time_quality_is_known_leap_seconds_with_accuracy_10() {
        let tq = TimeQuality::default();
        assert!(tq.leap_seconds_known);
        assert!(!tq.clock_failure);
        assert!(!tq.clock_not_synchronized);
        assert_eq!(tq.time_accuracy, 10);
    }

    #[test]
    fn time_quality_byte_layout() {
        let tq = TimeQuality {
            leap_seconds_known: true,
            clock_failure: false,
            clock_not_synchronized: false,
            time_accuracy: 10,
        };
        assert_eq!(tq.to_byte(), 0x80 | 10);
    }
}
