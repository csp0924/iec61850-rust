//! MMS PDU layer.
//!
//! Encodes and decodes MMS PDUs, per ISO 9506, independently of the OSI layers
//! below: COTP, Session, Presentation and ACSE.

pub mod binary_time;
pub mod client;
pub mod error;
pub mod pdu;
pub mod server;

pub use binary_time::{
    binary_time6_from_epoch_ms, epoch_ms_from_binary_time6, BINARY_TIME6_LEN, EPOCH_1984_MS,
};
pub use error::MmsError;
pub use pdu::{
    decode_confirmed_get_name_list_request, decode_confirmed_get_name_list_response,
    decode_confirmed_get_var_access_attrs_request, decode_confirmed_get_var_access_attrs_response,
    decode_confirmed_read_request, decode_confirmed_read_response, decode_confirmed_write_request,
    decode_confirmed_write_response, encode_confirmed_error_pdu,
    encode_confirmed_get_name_list_request, encode_confirmed_get_name_list_response,
    encode_confirmed_get_var_access_attrs_request, encode_confirmed_get_var_access_attrs_response,
    encode_confirmed_read_request, encode_confirmed_read_response, encode_confirmed_write_request,
    encode_confirmed_write_response, AccessResult, AlternateAccess, AlternateAccessSelector,
    ConcludeRequestPdu, ConcludeResponsePdu, ConfirmedErrorRejectReason,
    ConfirmedRequestRejectReason, ConfirmedResponseRejectReason, DataAccessError, ErrorClass,
    GetNameListRequest, GetNameListResponse, GetVariableAccessAttributesRequest,
    GetVariableAccessAttributesResponse, InitRequestDetail, InitResponseDetail, InitiateErrorPdu,
    InitiateRequestPdu, InitiateResponsePdu, ListOfVariableEntry, MmsData, MmsPdu, ObjectClass,
    ObjectName, ObjectScope, ReadRequest, ReadResponse, RejectReason, ServiceError,
    StructComponent, TypeSpecification, VariableAccessSpecification, WriteOutcome, WriteRequest,
    WriteResponse, DEFAULT_MAX_PDU_SIZE, DEFAULT_MAX_SERV_OUTSTANDING_CALLED,
    DEFAULT_MAX_SERV_OUTSTANDING_CALLING, DEFAULT_PARAMETER_CBB_CLIENT,
    DEFAULT_SERVICES_SUPPORTED_CLIENT, MAX_DATA_NESTING_DEPTH, MAX_IDENTIFIER_LEN, MAX_WRITE_ITEMS,
    SERVICE_TAG_GET_NAME_LIST, SERVICE_TAG_GET_VAR_ACCESS_ATTRS, SERVICE_TAG_READ,
    SERVICE_TAG_WRITE,
};
