//! The MMS protocol stack.
//!
//! Implements the upper OSI layers, COTP, Session, Presentation and ACSE, together
//! with the MMS PDUs, independently of IEC 61850 semantics.
//!
//! ## no_std support
//!
//! As in the asn1, model and hal crates, `std` is a default feature, so a std build
//! is unaffected. An embedded build uses `--no-default-features --features embedded`,
//! which pulls in alloc, hashbrown and the hal transport traits, and supplies its own
//! `AsyncTransport` implementation.

#![warn(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

// `#[macro_use]` makes `vec!` and `format!` available crate-wide in a no_std build.
// In a std build this `extern crate alloc` is redundant but harmless.
#[macro_use]
extern crate alloc;

/// Facade shared by the std and no_std builds.
///
/// - `HashSet`: `std::collections` on std, `hashbrown` on embedded
/// - `Arc`: `std::sync::Arc` on std, `alloc::sync::Arc` on embedded
/// - `VecDeque`: `alloc::collections::VecDeque` in both
///
/// Spin-based synchronization primitives are never used in a std build. The only
/// shared state in this crate is an `Arc<AtomicUsize>` on the server side, which
/// needs no lock, so no spin dependency is pulled in.
pub(crate) mod compat {
    pub mod prelude {
        pub use alloc::borrow::ToOwned;
        pub use alloc::boxed::Box;
        pub use alloc::format;
        pub use alloc::string::{String, ToString};
        pub use alloc::vec::Vec;
    }

    pub use alloc::collections::VecDeque;
    pub use alloc::sync::Arc;

    #[cfg(not(feature = "std"))]
    pub use hashbrown::HashSet;
    #[cfg(feature = "std")]
    pub use std::collections::HashSet;
}

pub mod error;
pub mod iso;
pub mod mms;

// COTP types used by the layers above
pub use error::{CotpError, IsoError};
pub use iso::cotp::{
    encode_cc, encode_cr, encode_dc, encode_dr, encode_dt, encode_options, parse_cc,
    parse_cotp_pdu, parse_cr, parse_dc, parse_dr, parse_dt, parse_options, CotpConnection,
    CotpOptions, CotpOptionsSummary, CotpPdu, CotpState, TSelector, TpduSize,
    COTP_DATA_HEADER_SIZE, COTP_MAX_BUFFER_SIZE,
};
pub use iso::tpkt::{TpktHeader, TPKT_HEADER_LEN};

// ACSE types used by the MMS client
pub use iso::acse::{
    encode_aare, encode_aarq, encode_abrt, encode_associate_failed, encode_rlre, encode_rlrq,
    AcseAuth, AcseAuthenticator, AcseConnection, AcseConnectionState, AcseError, AcseIndication,
    IsoApplicationReference,
};

// MMS PDU types
pub use mms::binary_time::{
    binary_time6_from_epoch_ms, epoch_ms_from_binary_time6, BINARY_TIME6_LEN, EPOCH_1984_MS,
};
pub use mms::{
    decode_confirmed_read_request, decode_confirmed_read_response, decode_confirmed_write_request,
    decode_confirmed_write_response, encode_confirmed_error_pdu, encode_confirmed_read_request,
    encode_confirmed_read_response, encode_confirmed_write_request,
    encode_confirmed_write_response, AccessResult, AlternateAccess, AlternateAccessSelector,
    ConcludeRequestPdu, ConcludeResponsePdu, DataAccessError, ErrorClass, InitRequestDetail,
    InitResponseDetail, InitiateErrorPdu, InitiateRequestPdu, InitiateResponsePdu,
    ListOfVariableEntry, MmsData, MmsError, MmsPdu, ObjectName, ReadRequest, ReadResponse,
    ServiceError, StructComponent, TypeSpecification, VariableAccessSpecification, WriteOutcome,
    WriteRequest, WriteResponse, DEFAULT_MAX_PDU_SIZE, DEFAULT_MAX_SERV_OUTSTANDING_CALLED,
    DEFAULT_MAX_SERV_OUTSTANDING_CALLING, DEFAULT_PARAMETER_CBB_CLIENT,
    DEFAULT_SERVICES_SUPPORTED_CLIENT, MAX_DATA_NESTING_DEPTH, MAX_IDENTIFIER_LEN, MAX_WRITE_ITEMS,
    SERVICE_TAG_READ, SERVICE_TAG_WRITE,
};

// Presentation types used by ACSE and the MMS client
pub use iso::presentation::{
    encode_abort as pres_encode_abort, encode_connect as pres_encode_connect,
    encode_cpa as pres_encode_cpa, encode_user_data, encode_user_data_acse,
    parse_accept as pres_parse_accept, parse_connect as pres_parse_connect, parse_user_data,
    ConnectResult, IsoPresentation, PSelector, PresentationConnectionParameters, PresentationError,
    UserDataResult, ACSE_CONTEXT_ID, MMS_CONTEXT_ID,
};

// MMS client types
pub use mms::client::{ClientError, ConnectionState, MmsClient, MmsClientBuilder, MmsValue};
