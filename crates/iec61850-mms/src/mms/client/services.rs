//! MMS confirmed services: Read, Write, GetNameList, GetVariableAccessAttributes,
//! Identify, Status and the named variable list services.
//!
//! Every service function follows the same shape:
//! 1. Take a fresh invokeID from the allocator.
//! 2. Encode the confirmed request, invokeID and service body included.
//! 3. Send it with `conn.send_mms_pdu`.
//! 4. Await the answer carrying the same invokeID with
//!    `conn.recv_confirmed_response` and dispatch on its type.
//! 5. A confirmed response succeeds, a confirmed error becomes a `ServiceError`,
//!    and a reject becomes a `RejectError`.
//!
//! ## Timeouts
//!
//! A request whose answer does not arrive within the request timeout returns
//! `ClientError::ServiceTimeout`. The association stays usable: the late answer
//! is recognized by its invokeID and discarded.
//!
//! ## PDU size guard
//!
//! A request larger than the negotiated maximum PDU size is caught by the size
//! guard inside `conn.send_mms_pdu`, after encoding and before transmission.
//!
//! ## Confirmed errors
//!
//! A ConfirmedError PDU, tag `0xa2`, is parsed by `handle_confirmed_error`, whose
//! `ErrorClass` is carried through in `ClientError::ServiceError`.
//!
//! ## Response framing
//!
//! `recv_mms_pdu` returns `MmsPdu::ConfirmedResponse(inner)`, where `inner` is the
//! content of the `0xa1` TLV with its tag and length already removed. The decoders,
//! such as `decode_confirmed_read_response`, expect to start at the `0xa1` tag, so
//! `rewrap_response` puts the tag and length back first.

use super::connection::MmsConnection;
use super::error::ClientError;
use super::invoke_id::InvokeIdAllocator;
use crate::compat::prelude::*;
use crate::mms::pdu::{
    decode_confirmed_define_named_variable_list_response,
    decode_confirmed_delete_named_variable_list_response, decode_confirmed_error_inner,
    decode_confirmed_get_name_list_response,
    decode_confirmed_get_named_variable_list_attrs_response,
    decode_confirmed_get_var_access_attrs_response, decode_confirmed_identify_response,
    decode_confirmed_read_journal_response, decode_confirmed_read_response,
    decode_confirmed_status_response, decode_confirmed_write_response,
    encode_confirmed_define_named_variable_list_request,
    encode_confirmed_delete_named_variable_list_request, encode_confirmed_get_name_list_request,
    encode_confirmed_get_named_variable_list_attrs_request,
    encode_confirmed_get_var_access_attrs_request, encode_confirmed_identify_request,
    encode_confirmed_read_journal_request, encode_confirmed_read_request,
    encode_confirmed_status_request, encode_confirmed_write_request, AccessResult, AlternateAccess,
    DefineNamedVariableEntry, DefineNamedVariableListRequest, DeleteNamedVariableListRequest,
    GetNameListRequest, GetNamedVariableListAttributesRequest,
    GetNamedVariableListAttributesResponse, GetVariableAccessAttributesRequest, IdentifyResponse,
    ListOfVariableEntry, MmsData, MmsPdu, ObjectClass, ObjectName, ObjectScope, ReadJournalRequest,
    ReadJournalResponse, ReadRequest, StatusResponse, TypeSpecification,
    VariableAccessSpecification, WriteRequest,
};
use bytes::{Bytes, BytesMut};
use iec61850_hal::time::Timer;
use iec61850_hal::transport::AsyncTransport;
use tracing::warn;

// Service-level value type

/// A value as seen by the service layer.
///
/// The service layer passes `MmsData` through unchanged.
pub type MmsValue = MmsData;

// Re-adding and stripping the outer PDU wrapper

/// Puts the `0xa1 <len>` wrapper back around ConfirmedResponse content.
///
/// `MmsPdu::ConfirmedResponse(inner)` carries content whose outer `0xa1 <len>` has
/// already been removed, while the response decoders expect to start at that tag.
fn rewrap_response(tag: u8, inner: &Bytes) -> Vec<u8> {
    let inner_len = inner.len();
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&[tag]);
    // BER length encoding
    if inner_len <= 127 {
        buf.extend_from_slice(&[inner_len as u8]);
    } else if inner_len <= 255 {
        buf.extend_from_slice(&[0x81, inner_len as u8]);
    } else {
        buf.extend_from_slice(&[0x82, (inner_len >> 8) as u8, (inner_len & 0xff) as u8]);
    }
    buf.extend_from_slice(inner);
    buf.to_vec()
}

/// Strips the outer `0xa0 <len>` from a complete confirmed request PDU.
///
/// The `inner` of `MmsPdu::ConfirmedRequest` is the content with that wrapper
/// removed, mirroring what `MmsPdu::decode` produces.
///
/// The `encode_confirmed_*_request` functions emit a complete PDU including the
/// wrapper, so one layer must come off before the bytes go into a `ConfirmedRequest`
/// variant. Otherwise `MmsPdu::encode` wraps them a second time, the peer sees an
/// inner tag of `0xa0`, and answers `RejectPDU { confirmedRequest, unrecognizedService }`.
fn strip_confirmed_wrapper(full: BytesMut) -> Result<Bytes, ClientError> {
    let data = full.freeze();
    if data.is_empty() || data[0] != 0xa0 {
        return Err(ClientError::PduParse(format!(
            "strip_confirmed_wrapper: expected 0xa0 tag, got 0x{:02x}",
            data.first().copied().unwrap_or(0)
        )));
    }
    // BER length: the short form, or the long forms 0x81 <len> and 0x82 <hi> <lo>
    let (len_bytes, content_start) = match data.get(1).copied() {
        Some(b) if b <= 0x7f => (1usize, 2usize),
        Some(0x81) => (2, 3),
        Some(0x82) => (3, 4),
        Some(0x83) => (4, 5),
        Some(0x84) => (5, 6),
        _ => {
            return Err(ClientError::PduParse(
                "strip_confirmed_wrapper: malformed outer ber length".to_string(),
            ))
        }
    };
    if data.len() < 1 + len_bytes {
        return Err(ClientError::PduParse(
            "strip_confirmed_wrapper: outer wrapper truncated".to_string(),
        ));
    }
    Ok(data.slice(content_start..))
}

/// Sends a confirmed request encoded under `invoke_id` and returns the answer
/// bound to it.
///
/// `full` is the complete ConfirmedRequestPdu, outer `0xa0` included. The
/// request is sent only once it fits within the negotiated outstanding limit,
/// counting the requests that timed out unanswered. The invokeID is released
/// whatever the outcome.
async fn exchange<T: AsyncTransport, Tm: Timer>(
    conn: &mut MmsConnection<T, Tm>,
    alloc: &mut InvokeIdAllocator,
    invoke_id: u32,
    full: BytesMut,
) -> Result<MmsPdu, ClientError> {
    let result = match strip_confirmed_wrapper(full) {
        Ok(inner) => match send_within_limit(conn, MmsPdu::ConfirmedRequest(inner)).await {
            Ok(()) => conn.recv_confirmed_response(invoke_id).await,
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    };
    alloc.release(invoke_id);
    result
}

/// Sends `pdu` once a slot within the negotiated outstanding limit is free.
async fn send_within_limit<T: AsyncTransport, Tm: Timer>(
    conn: &mut MmsConnection<T, Tm>,
    pdu: MmsPdu,
) -> Result<(), ClientError> {
    conn.reserve_outstanding_slot().await?;
    conn.send_mms_pdu(&pdu).await
}

// Service functions

/// Reads one MMS variable.
///
/// `domain` and `item` form a domain-specific ObjectName.
pub async fn read_variable<T: AsyncTransport, Tm: Timer>(
    conn: &mut MmsConnection<T, Tm>,
    alloc: &mut InvokeIdAllocator,
    domain: &str,
    item: &str,
) -> Result<MmsValue, ClientError> {
    let invoke_id = alloc.allocate()?;

    let obj = ObjectName::DomainSpecific {
        domain_id: domain.to_string(),
        item_id: item.to_string(),
    };
    let req = ReadRequest {
        specification_with_result: false,
        variable_access_spec: VariableAccessSpecification::ListOfVariable(vec![obj.into()]),
    };

    let mut full = BytesMut::new();
    encode_confirmed_read_request(invoke_id, &req, &mut full);
    let resp_pdu = exchange(conn, alloc, invoke_id, full).await?;
    dispatch_read_response(resp_pdu)
}

/// Read a single array element, optionally targeting a sub-component.
///
/// Issues a Read service with an `AlternateAccess` selector inside the single
/// `ListOfVariableSeq`:
///
/// - `component = None` -> `selectAccess.index` (element only).
/// - `component = Some("stVal")` -> `selectAlternateAccess { index, component }`
///   (sub-DA within the element; multiple levels separated by `$`).
///
/// Returns the single `AccessResult` payload, as with [`read_variable`].
pub async fn read_single_array_element<T: AsyncTransport, Tm: Timer>(
    conn: &mut MmsConnection<T, Tm>,
    alloc: &mut InvokeIdAllocator,
    domain: &str,
    item: &str,
    index: u32,
    component: Option<&str>,
) -> Result<MmsValue, ClientError> {
    let alt_access = match component {
        None => AlternateAccess::index(index),
        Some(c) => AlternateAccess::index_component(index, c).map_err(|e| {
            warn!("read_single_array_element: failed to build AlternateAccess: {e}");
            ClientError::PduParse(format!("AlternateAccess: {e}"))
        })?,
    };

    let invoke_id = alloc.allocate()?;

    let entry = ListOfVariableEntry::with_alt_access(
        ObjectName::DomainSpecific {
            domain_id: domain.to_string(),
            item_id: item.to_string(),
        },
        alt_access,
    );
    let req = ReadRequest {
        specification_with_result: false,
        variable_access_spec: VariableAccessSpecification::ListOfVariable(vec![entry]),
    };

    let mut full = BytesMut::new();
    encode_confirmed_read_request(invoke_id, &req, &mut full);
    let resp_pdu = exchange(conn, alloc, invoke_id, full).await?;
    dispatch_read_response(resp_pdu)
}

/// Write a single array element, optionally targeting a sub-component.
///
/// Symmetric to [`read_single_array_element`].
pub async fn write_single_array_element<T: AsyncTransport, Tm: Timer>(
    conn: &mut MmsConnection<T, Tm>,
    alloc: &mut InvokeIdAllocator,
    domain: &str,
    item: &str,
    index: u32,
    component: Option<&str>,
    value: MmsValue,
) -> Result<(), ClientError> {
    let alt_access = match component {
        None => AlternateAccess::index(index),
        Some(c) => AlternateAccess::index_component(index, c).map_err(|e| {
            warn!("write_single_array_element: failed to build AlternateAccess: {e}");
            ClientError::PduParse(format!("AlternateAccess: {e}"))
        })?,
    };

    let invoke_id = alloc.allocate()?;

    let entry = ListOfVariableEntry::with_alt_access(
        ObjectName::DomainSpecific {
            domain_id: domain.to_string(),
            item_id: item.to_string(),
        },
        alt_access,
    );
    let req = WriteRequest {
        variable_access_spec: VariableAccessSpecification::ListOfVariable(vec![entry]),
        list_of_data: vec![value],
    };

    let mut full = BytesMut::new();
    encode_confirmed_write_request(invoke_id, &req, &mut full);
    let resp_pdu = exchange(conn, alloc, invoke_id, full).await?;
    dispatch_write_response(resp_pdu)
}

/// Writes one MMS variable.
pub async fn write_variable<T: AsyncTransport, Tm: Timer>(
    conn: &mut MmsConnection<T, Tm>,
    alloc: &mut InvokeIdAllocator,
    domain: &str,
    item: &str,
    value: MmsValue,
) -> Result<(), ClientError> {
    let invoke_id = alloc.allocate()?;

    let obj = ObjectName::DomainSpecific {
        domain_id: domain.to_string(),
        item_id: item.to_string(),
    };
    let req = WriteRequest {
        variable_access_spec: VariableAccessSpecification::ListOfVariable(vec![obj.into()]),
        list_of_data: vec![value],
    };

    let mut full = BytesMut::new();
    encode_confirmed_write_request(invoke_id, &req, &mut full);
    let resp_pdu = exchange(conn, alloc, invoke_id, full).await?;
    dispatch_write_response(resp_pdu)
}

/// Reads every value of a named variable list.
///
/// This implements GetDataSetValues of IEC 61850-7-2. `domain` and `list_name` name
/// a NamedVariableList on the server, and the result holds one `AccessResult` per
/// entry, so a per-entry success or failure is preserved.
///
/// Unlike `read_variable`, the request carries
/// `VariableAccessSpecification::VariableListName`, a single object the server
/// expands into its member list, rather than `ListOfVariable`. The object class
/// differs, so the server resolves it through a different catalog lookup.
pub async fn read_named_variable_list_values<T: AsyncTransport, Tm: Timer>(
    conn: &mut MmsConnection<T, Tm>,
    alloc: &mut InvokeIdAllocator,
    domain: &str,
    list_name: &str,
) -> Result<Vec<AccessResult>, ClientError> {
    let invoke_id = alloc.allocate()?;

    let name = ObjectName::DomainSpecific {
        domain_id: domain.to_string(),
        item_id: list_name.to_string(),
    };
    let req = ReadRequest::named_list(name, false);

    // built through encode_confirmed_read_request, which adds the outer 0xa0 and the
    // invokeID, so strip_confirmed_wrapper behaves as it does for read_variable
    let mut full = BytesMut::new();
    encode_confirmed_read_request(invoke_id, &req, &mut full);
    let resp_pdu = exchange(conn, alloc, invoke_id, full).await?;
    dispatch_read_list_response(resp_pdu)
}

/// Writes every value of a named variable list.
///
/// This implements SetDataSetValues of IEC 61850-7-2. `values.len()` must match the
/// number of entries in the data set; a mismatch makes the server answer with a
/// per-entry `DataAccessError::TypeInconsistent`. The result holds one
/// `WriteOutcome` per entry.
pub async fn write_named_variable_list_values<T: AsyncTransport, Tm: Timer>(
    conn: &mut MmsConnection<T, Tm>,
    alloc: &mut InvokeIdAllocator,
    domain: &str,
    list_name: &str,
    values: Vec<MmsValue>,
) -> Result<Vec<crate::mms::pdu::WriteOutcome>, ClientError> {
    let invoke_id = alloc.allocate()?;

    let name = ObjectName::DomainSpecific {
        domain_id: domain.to_string(),
        item_id: list_name.to_string(),
    };
    let req = WriteRequest::named_list(name, values);

    let mut full = BytesMut::new();
    encode_confirmed_write_request(invoke_id, &req, &mut full);
    let resp_pdu = exchange(conn, alloc, invoke_id, full).await?;
    dispatch_write_list_response(resp_pdu)
}

/// Retrieves a list of object names.
///
/// `object_class` selects the class to enumerate, such as `ObjectClass::NamedVariable`.
/// `domain` of `Some(name)` selects a domain-specific scope, and `None` the VMD.
/// `continue_after` is the paging cursor, and `None` starts from the beginning.
///
/// Returns the names together with whether more of them remain.
pub async fn get_name_list<T: AsyncTransport, Tm: Timer>(
    conn: &mut MmsConnection<T, Tm>,
    alloc: &mut InvokeIdAllocator,
    object_class: ObjectClass,
    domain: Option<&str>,
    continue_after: Option<&str>,
) -> Result<(Vec<String>, bool), ClientError> {
    let invoke_id = alloc.allocate()?;

    let scope = match domain {
        Some(d) => ObjectScope::DomainSpecific(d.to_string()),
        None => ObjectScope::VmdSpecific,
    };
    let req = GetNameListRequest {
        object_class,
        object_scope: scope,
        continue_after: continue_after.map(|s| s.to_string()),
    };

    let mut full = BytesMut::new();
    encode_confirmed_get_name_list_request(invoke_id, &req, &mut full);
    let resp_pdu = exchange(conn, alloc, invoke_id, full).await?;
    dispatch_get_name_list_response(resp_pdu)
}

/// Reads journal entries.
///
/// `req` carries either the time-range or the start-after form of the request.
///
/// Returns the entries and whether more remain; an absent moreFollows counts as false.
pub async fn read_journal<T: AsyncTransport, Tm: Timer>(
    conn: &mut MmsConnection<T, Tm>,
    alloc: &mut InvokeIdAllocator,
    req: &ReadJournalRequest,
) -> Result<ReadJournalResponse, ClientError> {
    let invoke_id = alloc.allocate()?;

    let mut full = BytesMut::new();
    encode_confirmed_read_journal_request(invoke_id, req, &mut full);
    let resp_pdu = exchange(conn, alloc, invoke_id, full).await?;
    dispatch_read_journal_response(resp_pdu)
}

fn dispatch_read_journal_response(pdu: MmsPdu) -> Result<ReadJournalResponse, ClientError> {
    match pdu {
        MmsPdu::ConfirmedResponse(inner) => {
            let full = rewrap_response(0xa1, &inner);
            let (_id, resp) = decode_confirmed_read_journal_response(&full).map_err(|e| {
                warn!("readjournal response failed to decode: {e}");
                ClientError::PduParse(format!("{e}"))
            })?;
            Ok(resp)
        }
        MmsPdu::ConfirmedError(inner) => Err(handle_confirmed_error(&inner)),
        MmsPdu::Reject(reject) => {
            warn!("readjournal received a reject pdu: {:?}", reject.reason);
            Err(ClientError::RejectError {
                reason: reject.reason,
            })
        }
        other => Err(ClientError::PduParse(format!(
            "unexpected PDU tag=0x{:02X}",
            other.tag_byte()
        ))),
    }
}

/// Retrieves the access attributes of a variable.
pub async fn get_variable_access_attributes<T: AsyncTransport, Tm: Timer>(
    conn: &mut MmsConnection<T, Tm>,
    alloc: &mut InvokeIdAllocator,
    domain: &str,
    item: &str,
) -> Result<TypeSpecification, ClientError> {
    let invoke_id = alloc.allocate()?;

    let obj = ObjectName::DomainSpecific {
        domain_id: domain.to_string(),
        item_id: item.to_string(),
    };
    let req = GetVariableAccessAttributesRequest { object_name: obj };

    let mut full = BytesMut::new();
    encode_confirmed_get_var_access_attrs_request(invoke_id, &req, &mut full);
    let resp_pdu = exchange(conn, alloc, invoke_id, full).await?;
    dispatch_get_var_access_attrs_response(resp_pdu)
}

// Response dispatch helpers

/// Turns an `MmsPdu` into the result of a Read.
fn dispatch_read_response(pdu: MmsPdu) -> Result<MmsValue, ClientError> {
    match pdu {
        MmsPdu::ConfirmedResponse(inner) => {
            // the content has no 0xa1 wrapper, which the decoder expects
            let full = rewrap_response(0xa1, &inner);
            let (_id, resp) = decode_confirmed_read_response(&full).map_err(|e| {
                warn!("read response failed to decode: {e}");
                ClientError::PduParse(format!("{e}"))
            })?;
            // one variable was requested, so exactly one AccessResult answers it
            let results = check_access_result_count(resp.list_of_access_result, 1)?;
            match results.into_iter().next() {
                Some(AccessResult::Success(data)) => Ok(data),
                Some(AccessResult::Failure(err)) => {
                    warn!("read returned a data access error: {:?}", err);
                    Err(ClientError::DataAccessError(err))
                }
                None => Err(ClientError::PduParse(
                    "read response carries no access result".to_string(),
                )),
            }
        }
        MmsPdu::ConfirmedError(inner) => Err(handle_confirmed_error(&inner)),
        MmsPdu::Reject(reject) => {
            warn!("read received a reject pdu: {:?}", reject.reason);
            Err(ClientError::RejectError {
                reason: reject.reason,
            })
        }
        other => {
            warn!(
                "read received an unexpected pdu tag=0x{:02X}",
                other.tag_byte()
            );
            Err(ClientError::PduParse(format!(
                "unexpected PDU tag=0x{:02X}",
                other.tag_byte()
            )))
        }
    }
}

/// Turns an `MmsPdu` into the per-entry results of a named variable list read.
///
/// Unlike `dispatch_read_response` this keeps the whole list and does not turn a
/// `Failure` entry into an error, so the caller sees which entries succeeded.
fn dispatch_read_list_response(pdu: MmsPdu) -> Result<Vec<AccessResult>, ClientError> {
    match pdu {
        MmsPdu::ConfirmedResponse(inner) => {
            let full = rewrap_response(0xa1, &inner);
            let (_id, resp) = decode_confirmed_read_response(&full).map_err(|e| {
                warn!("read list response failed to decode: {e}");
                ClientError::PduParse(format!("{e}"))
            })?;
            Ok(resp.list_of_access_result)
        }
        MmsPdu::ConfirmedError(inner) => Err(handle_confirmed_error(&inner)),
        MmsPdu::Reject(reject) => {
            warn!("read list received a reject pdu: {:?}", reject.reason);
            Err(ClientError::RejectError {
                reason: reject.reason,
            })
        }
        other => Err(ClientError::PduParse(format!(
            "unexpected PDU tag=0x{:02X}",
            other.tag_byte()
        ))),
    }
}

/// Creates a dynamic data set, a NamedVariableList.
///
/// `domain` and `list_name` name the NamedVariableList to create, and `entries` are
/// its members, stored in the order given.
///
/// A confirmed error from the server, for instance because the data set already
/// exists or a member is unknown, becomes `ClientError::ServiceError`.
pub async fn define_named_variable_list<T: AsyncTransport, Tm: Timer>(
    conn: &mut MmsConnection<T, Tm>,
    alloc: &mut InvokeIdAllocator,
    domain: &str,
    list_name: &str,
    entries: Vec<DefineNamedVariableEntry>,
) -> Result<(), ClientError> {
    let invoke_id = alloc.allocate()?;

    let req = DefineNamedVariableListRequest::domain(domain, list_name, entries);

    let mut full = BytesMut::new();
    if let Err(e) = encode_confirmed_define_named_variable_list_request(invoke_id, &req, &mut full)
    {
        alloc.release(invoke_id);
        return Err(ClientError::PduParse(format!("{e}")));
    }
    let resp_pdu = exchange(conn, alloc, invoke_id, full).await?;
    dispatch_define_named_variable_list_response(resp_pdu)
}

/// Deletes a dynamic data set.
///
/// The request uses the specific scope, deleting one data set, and returns the number
/// of objects matched and the number deleted; a caller normally checks that at least
/// one was deleted.
pub async fn delete_named_variable_list<T: AsyncTransport, Tm: Timer>(
    conn: &mut MmsConnection<T, Tm>,
    alloc: &mut InvokeIdAllocator,
    domain: &str,
    list_name: &str,
) -> Result<(u32, u32), ClientError> {
    let invoke_id = alloc.allocate()?;

    let req = DeleteNamedVariableListRequest::specific_domain(domain, list_name);

    let mut full = BytesMut::new();
    encode_confirmed_delete_named_variable_list_request(invoke_id, &req, &mut full);
    let resp_pdu = exchange(conn, alloc, invoke_id, full).await?;
    dispatch_delete_named_variable_list_response(resp_pdu)
}

/// Retrieves the attributes of a named variable list: its members, in order,
/// and whether it may be deleted.
///
/// A confirmed error from the server, for instance because the list does not
/// exist, becomes `ClientError::ServiceError`, the same shape
/// `delete_named_variable_list` produces for a refused request.
pub async fn get_named_variable_list_attributes<T: AsyncTransport, Tm: Timer>(
    conn: &mut MmsConnection<T, Tm>,
    alloc: &mut InvokeIdAllocator,
    domain: &str,
    list_name: &str,
) -> Result<GetNamedVariableListAttributesResponse, ClientError> {
    let invoke_id = alloc.allocate()?;

    let req = GetNamedVariableListAttributesRequest::domain(domain, list_name);

    let mut full = BytesMut::new();
    encode_confirmed_get_named_variable_list_attrs_request(invoke_id, &req, &mut full);
    let resp_pdu = exchange(conn, alloc, invoke_id, full).await?;
    dispatch_get_named_variable_list_attrs_response(resp_pdu)
}

fn dispatch_get_named_variable_list_attrs_response(
    pdu: MmsPdu,
) -> Result<GetNamedVariableListAttributesResponse, ClientError> {
    match pdu {
        MmsPdu::ConfirmedResponse(inner) => {
            let full = rewrap_response(0xa1, &inner);
            let (_id, resp) = decode_confirmed_get_named_variable_list_attrs_response(&full)
                .map_err(|e| {
                    warn!("getnamedvariablelistattributes response failed to decode: {e}");
                    ClientError::PduParse(format!("{e}"))
                })?;
            Ok(resp)
        }
        MmsPdu::ConfirmedError(inner) => Err(handle_confirmed_error(&inner)),
        MmsPdu::Reject(reject) => {
            warn!(
                "getnamedvariablelistattributes received a reject pdu: {:?}",
                reject.reason
            );
            Err(ClientError::RejectError {
                reason: reject.reason,
            })
        }
        other => Err(ClientError::PduParse(format!(
            "unexpected PDU tag=0x{:02X}",
            other.tag_byte()
        ))),
    }
}

/// Asks the server to identify itself: vendor, model and revision, and
/// optionally the abstract syntaxes it supports.
///
/// A confirmed error becomes `ClientError::ServiceError` and a reject
/// `ClientError::RejectError`, which is how a server without the service
/// answers.
pub async fn identify<T: AsyncTransport, Tm: Timer>(
    conn: &mut MmsConnection<T, Tm>,
    alloc: &mut InvokeIdAllocator,
) -> Result<IdentifyResponse, ClientError> {
    let invoke_id = alloc.allocate()?;

    let mut full = BytesMut::new();
    encode_confirmed_identify_request(invoke_id, &mut full);
    let resp_pdu = exchange(conn, alloc, invoke_id, full).await?;
    dispatch_identify_response(resp_pdu)
}

fn dispatch_identify_response(pdu: MmsPdu) -> Result<IdentifyResponse, ClientError> {
    match pdu {
        MmsPdu::ConfirmedResponse(inner) => {
            let full = rewrap_response(0xa1, &inner);
            let (_id, resp) = decode_confirmed_identify_response(&full).map_err(|e| {
                warn!("identify response failed to decode: {e}");
                ClientError::PduParse(format!("{e}"))
            })?;
            Ok(resp)
        }
        MmsPdu::ConfirmedError(inner) => Err(handle_confirmed_error(&inner)),
        MmsPdu::Reject(reject) => {
            warn!("identify received a reject pdu: {:?}", reject.reason);
            Err(ClientError::RejectError {
                reason: reject.reason,
            })
        }
        other => Err(ClientError::PduParse(format!(
            "unexpected PDU tag=0x{:02X}",
            other.tag_byte()
        ))),
    }
}

/// Asks the server for the logical and physical status of its VMD.
///
/// With `extended_derivation` the server derives the status by executing its
/// own checks rather than reporting the status it holds. A confirmed error
/// becomes `ClientError::ServiceError` and a reject `ClientError::RejectError`,
/// which is how a server without the service answers.
pub async fn status<T: AsyncTransport, Tm: Timer>(
    conn: &mut MmsConnection<T, Tm>,
    alloc: &mut InvokeIdAllocator,
    extended_derivation: bool,
) -> Result<StatusResponse, ClientError> {
    let invoke_id = alloc.allocate()?;

    let mut full = BytesMut::new();
    encode_confirmed_status_request(invoke_id, extended_derivation, &mut full);
    let resp_pdu = exchange(conn, alloc, invoke_id, full).await?;
    dispatch_status_response(resp_pdu)
}

fn dispatch_status_response(pdu: MmsPdu) -> Result<StatusResponse, ClientError> {
    match pdu {
        MmsPdu::ConfirmedResponse(inner) => {
            let full = rewrap_response(0xa1, &inner);
            let (_id, resp) = decode_confirmed_status_response(&full).map_err(|e| {
                warn!("status response failed to decode: {e}");
                ClientError::PduParse(format!("{e}"))
            })?;
            Ok(resp)
        }
        MmsPdu::ConfirmedError(inner) => Err(handle_confirmed_error(&inner)),
        MmsPdu::Reject(reject) => {
            warn!("status received a reject pdu: {:?}", reject.reason);
            Err(ClientError::RejectError {
                reason: reject.reason,
            })
        }
        other => Err(ClientError::PduParse(format!(
            "unexpected PDU tag=0x{:02X}",
            other.tag_byte()
        ))),
    }
}

fn dispatch_define_named_variable_list_response(pdu: MmsPdu) -> Result<(), ClientError> {
    match pdu {
        MmsPdu::ConfirmedResponse(inner) => {
            let full = rewrap_response(0xa1, &inner);
            decode_confirmed_define_named_variable_list_response(&full)
                .map(|_| ())
                .map_err(|e| {
                    warn!("definenamedvariablelist response failed to decode: {e}");
                    ClientError::PduParse(format!("{e}"))
                })
        }
        MmsPdu::ConfirmedError(inner) => Err(handle_confirmed_error(&inner)),
        MmsPdu::Reject(reject) => {
            warn!(
                "definenamedvariablelist received a reject pdu: {:?}",
                reject.reason
            );
            Err(ClientError::RejectError {
                reason: reject.reason,
            })
        }
        other => Err(ClientError::PduParse(format!(
            "unexpected PDU tag=0x{:02X}",
            other.tag_byte()
        ))),
    }
}

fn dispatch_delete_named_variable_list_response(pdu: MmsPdu) -> Result<(u32, u32), ClientError> {
    match pdu {
        MmsPdu::ConfirmedResponse(inner) => {
            let full = rewrap_response(0xa1, &inner);
            let (_id, resp) =
                decode_confirmed_delete_named_variable_list_response(&full).map_err(|e| {
                    warn!("deletenamedvariablelist response failed to decode: {e}");
                    ClientError::PduParse(format!("{e}"))
                })?;
            Ok((resp.number_matched, resp.number_deleted))
        }
        MmsPdu::ConfirmedError(inner) => Err(handle_confirmed_error(&inner)),
        MmsPdu::Reject(reject) => {
            warn!(
                "deletenamedvariablelist received a reject pdu: {:?}",
                reject.reason
            );
            Err(ClientError::RejectError {
                reason: reject.reason,
            })
        }
        other => Err(ClientError::PduParse(format!(
            "unexpected PDU tag=0x{:02X}",
            other.tag_byte()
        ))),
    }
}

fn dispatch_write_list_response(
    pdu: MmsPdu,
) -> Result<Vec<crate::mms::pdu::WriteOutcome>, ClientError> {
    match pdu {
        MmsPdu::ConfirmedResponse(inner) => {
            let full = rewrap_response(0xa1, &inner);
            let (_id, resp) = decode_confirmed_write_response(&full).map_err(|e| {
                warn!("write list response failed to decode: {e}");
                ClientError::PduParse(format!("{e}"))
            })?;
            Ok(resp.outcomes)
        }
        MmsPdu::ConfirmedError(inner) => Err(handle_confirmed_error(&inner)),
        MmsPdu::Reject(reject) => {
            warn!("write list received a reject pdu: {:?}", reject.reason);
            Err(ClientError::RejectError {
                reason: reject.reason,
            })
        }
        other => Err(ClientError::PduParse(format!(
            "unexpected PDU tag=0x{:02X}",
            other.tag_byte()
        ))),
    }
}

/// Turns an `MmsPdu` into the result of a Write.
fn dispatch_write_response(pdu: MmsPdu) -> Result<(), ClientError> {
    match pdu {
        MmsPdu::ConfirmedResponse(inner) => {
            let full = rewrap_response(0xa1, &inner);
            let (_id, resp) = decode_confirmed_write_response(&full).map_err(|e| {
                warn!("write response failed to decode: {e}");
                ClientError::PduParse(format!("{e}"))
            })?;
            // one variable was written, so exactly one WriteOutcome answers it
            use crate::mms::pdu::WriteOutcome;
            if resp.outcomes.len() != 1 {
                warn!(
                    "write: the response carries {} outcomes for 1 written variable",
                    resp.outcomes.len()
                );
                return Err(ClientError::PduParse(format!(
                    "write response carries {} outcomes for 1 written variable",
                    resp.outcomes.len()
                )));
            }
            match resp.outcomes.into_iter().next() {
                Some(WriteOutcome::Success) => Ok(()),
                Some(WriteOutcome::Failure(err)) => {
                    warn!("write returned a data access error: {:?}", err);
                    Err(ClientError::DataAccessError(err))
                }
                None => Err(ClientError::PduParse(
                    "write response carries no outcome".to_string(),
                )),
            }
        }
        MmsPdu::ConfirmedError(inner) => Err(handle_confirmed_error(&inner)),
        MmsPdu::Reject(reject) => {
            warn!("write received a reject pdu: {:?}", reject.reason);
            Err(ClientError::RejectError {
                reason: reject.reason,
            })
        }
        other => Err(ClientError::PduParse(format!(
            "unexpected PDU tag=0x{:02X}",
            other.tag_byte()
        ))),
    }
}

/// Turns an `MmsPdu` into the result of a GetNameList.
fn dispatch_get_name_list_response(pdu: MmsPdu) -> Result<(Vec<String>, bool), ClientError> {
    match pdu {
        MmsPdu::ConfirmedResponse(inner) => {
            let full = rewrap_response(0xa1, &inner);
            let (_id, resp) = decode_confirmed_get_name_list_response(&full).map_err(|e| {
                warn!("getnamelist response failed to decode: {e}");
                ClientError::PduParse(format!("{e}"))
            })?;
            Ok((resp.identifiers, resp.more_follows))
        }
        MmsPdu::ConfirmedError(inner) => Err(handle_confirmed_error(&inner)),
        MmsPdu::Reject(reject) => {
            warn!("getnamelist received a reject pdu: {:?}", reject.reason);
            Err(ClientError::RejectError {
                reason: reject.reason,
            })
        }
        other => Err(ClientError::PduParse(format!(
            "unexpected PDU tag=0x{:02X}",
            other.tag_byte()
        ))),
    }
}

/// Turns an `MmsPdu` into the result of a GetVariableAccessAttributes.
fn dispatch_get_var_access_attrs_response(pdu: MmsPdu) -> Result<TypeSpecification, ClientError> {
    match pdu {
        MmsPdu::ConfirmedResponse(inner) => {
            let full = rewrap_response(0xa1, &inner);
            let (_id, resp) =
                decode_confirmed_get_var_access_attrs_response(&full).map_err(|e| {
                    warn!("getvariableaccessattributes response failed to decode: {e}");
                    ClientError::PduParse(format!("{e}"))
                })?;
            Ok(resp.type_specification)
        }
        MmsPdu::ConfirmedError(inner) => Err(handle_confirmed_error(&inner)),
        MmsPdu::Reject(reject) => {
            warn!(
                "getvariableaccessattributes received a reject pdu: {:?}",
                reject.reason
            );
            Err(ClientError::RejectError {
                reason: reject.reason,
            })
        }
        other => Err(ClientError::PduParse(format!(
            "unexpected PDU tag=0x{:02X}",
            other.tag_byte()
        ))),
    }
}

/// Turns the content of a ConfirmedError PDU into a `ClientError::ServiceError`.
///
/// `inner` is what follows the outer `0xa2 <len>`:
/// ```text
/// 0x80 <len> <invokeId>   -- invokeID [0] IMPLICIT Unsigned32
/// (0x81 <len> ... )       -- modifierPosition [1] IMPLICIT, OPTIONAL
/// 0xa2 <len> ...          -- serviceError [2] IMPLICIT ServiceError
/// ```
///
/// The invokeID has already been matched against the request by
/// `recv_confirmed_response`, so only the errorClass is carried out.
fn handle_confirmed_error(inner: &[u8]) -> ClientError {
    match decode_confirmed_error_inner(inner) {
        Ok((invoke_id, se)) => {
            warn!(
                "mms confirmed error: invoke_id={invoke_id} class={:?}",
                se.error_class
            );
            ClientError::ServiceError {
                error_class: se.error_class,
            }
        }
        Err(e) => {
            warn!("confirmed error failed to decode: {e}");
            ClientError::PduParse(format!("ConfirmedError decode failed: {e}"))
        }
    }
}

/// Reads several MMS variables with one Read service.
///
/// The request carries `VariableAccessSpecification::ListOfVariable`, so the
/// whole set travels under one invokeID and needs no temporary named variable
/// list. The answer holds one `AccessResult` per entry, in request order, so a
/// per-entry failure keeps its position instead of failing the whole call.
///
/// Each entry may carry an `AlternateAccess` selector, exactly as in
/// [`read_single_array_element`].
///
/// # Errors
///
/// - `PduParse` for an empty entry list; nothing is sent.
/// - `PduParse` when the response carries a number of access results that
///   differs from the number of entries requested. The list is neither padded
///   nor truncated, because position is what binds a result to its request.
pub async fn read_list<T: AsyncTransport, Tm: Timer>(
    conn: &mut MmsConnection<T, Tm>,
    alloc: &mut InvokeIdAllocator,
    entries: Vec<ListOfVariableEntry>,
) -> Result<Vec<AccessResult>, ClientError> {
    if entries.is_empty() {
        warn!("read_list: the entry list is empty, refusing to send a request");
        return Err(ClientError::PduParse(
            "read_list requires at least one variable entry".to_string(),
        ));
    }
    let requested = entries.len();

    let invoke_id = alloc.allocate()?;

    let req = ReadRequest {
        specification_with_result: false,
        variable_access_spec: VariableAccessSpecification::ListOfVariable(entries),
    };

    let mut full = BytesMut::new();
    encode_confirmed_read_request(invoke_id, &req, &mut full);
    let resp_pdu = exchange(conn, alloc, invoke_id, full).await?;
    check_access_result_count(dispatch_read_list_response(resp_pdu)?, requested)
}

/// Checks that a Read answer holds exactly one access result per requested
/// variable.
///
/// Position is what binds a result to its variable, so a mismatch is reported
/// rather than repaired: padding would invent values and truncating would hide
/// them, and either way the caller would read a result against the wrong
/// reference.
fn check_access_result_count(
    results: Vec<AccessResult>,
    requested: usize,
) -> Result<Vec<AccessResult>, ClientError> {
    if results.len() != requested {
        warn!(
            "read: the response carries {} access results for {} requested variables",
            results.len(),
            requested
        );
        return Err(ClientError::PduParse(format!(
            "read response carries {} access results for {} requested variables",
            results.len(),
            requested
        )));
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mms::pdu::DataAccessError;

    fn results(n: usize) -> Vec<AccessResult> {
        (0..n)
            .map(|_| AccessResult::Failure(DataAccessError::ObjectNonExistent))
            .collect()
    }

    #[test]
    fn matching_access_result_count_passes_through() {
        let out = check_access_result_count(results(3), 3).expect("count matches");
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn short_access_result_list_is_rejected() {
        let err = check_access_result_count(results(2), 3).expect_err("count is short");
        assert!(matches!(err, ClientError::PduParse(_)), "got {err:?}");
    }

    /// The content of a confirmed response PDU, outer `0xa1 <len>` removed.
    fn response_content(full: &[u8]) -> Bytes {
        assert!(full[1] < 0x80, "test PDUs use the short length form");
        Bytes::copy_from_slice(&full[2..])
    }

    #[test]
    fn identify_response_yields_the_three_strings() {
        let mut full = BytesMut::new();
        crate::mms::pdu::encode_confirmed_identify_response(
            3,
            &IdentifyResponse::new("vendor", "model", "1.0"),
            &mut full,
        );
        let pdu = MmsPdu::ConfirmedResponse(response_content(&full));
        let resp = dispatch_identify_response(pdu).expect("a well-formed response");
        assert_eq!(resp.vendor_name, "vendor");
        assert_eq!(resp.model_name, "model");
        assert_eq!(resp.revision, "1.0");
        assert!(resp.list_of_abstract_syntaxes.is_empty());
    }

    #[test]
    fn identify_confirmed_error_becomes_service_error() {
        use crate::mms::pdu::{encode_confirmed_error_pdu, ErrorClass, ServiceError};
        let mut full = BytesMut::new();
        encode_confirmed_error_pdu(3, &ServiceError::new(ErrorClass::Service(1)), &mut full);
        let pdu = MmsPdu::ConfirmedError(response_content(&full));
        let err = dispatch_identify_response(pdu).expect_err("a confirmed error");
        assert!(
            matches!(
                err,
                ClientError::ServiceError {
                    error_class: ErrorClass::Service(1)
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn identify_reject_becomes_reject_error() {
        use crate::mms::pdu::{ConfirmedRequestRejectReason, RejectPdu, RejectReason};
        let reason =
            RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::UnrecognizedService);
        let pdu = MmsPdu::Reject(RejectPdu {
            invoke_id: Some(3),
            reason: reason.clone(),
        });
        let err = dispatch_identify_response(pdu).expect_err("a reject");
        assert!(
            matches!(&err, ClientError::RejectError { reason: r } if *r == reason),
            "got {err:?}"
        );
    }

    #[test]
    fn identify_response_of_another_service_is_a_parse_error() {
        // a GetNameList response body under the identify invokeID
        let content = Bytes::from_static(&[0x02, 0x01, 0x03, 0xa1, 0x03, 0xa0, 0x01, 0x00]);
        let err = dispatch_identify_response(MmsPdu::ConfirmedResponse(content))
            .expect_err("not an identify response");
        assert!(matches!(err, ClientError::PduParse(_)), "got {err:?}");
    }

    #[test]
    fn status_response_yields_both_values() {
        use crate::mms::pdu::{VmdLogicalStatus, VmdPhysicalStatus};
        let mut sent = StatusResponse::new(
            VmdLogicalStatus::NoStateChangesAllowed,
            VmdPhysicalStatus::PartiallyOperational,
        );
        sent.local_detail = Some(vec![true, false, true]);
        let mut full = BytesMut::new();
        crate::mms::pdu::encode_confirmed_status_response(3, &sent, &mut full);
        let pdu = MmsPdu::ConfirmedResponse(response_content(&full));
        let resp = dispatch_status_response(pdu).expect("a well-formed response");
        assert_eq!(resp, sent);
    }

    #[test]
    fn status_confirmed_error_becomes_service_error() {
        use crate::mms::pdu::{encode_confirmed_error_pdu, ErrorClass, ServiceError};
        let mut full = BytesMut::new();
        encode_confirmed_error_pdu(3, &ServiceError::new(ErrorClass::Service(1)), &mut full);
        let pdu = MmsPdu::ConfirmedError(response_content(&full));
        let err = dispatch_status_response(pdu).expect_err("a confirmed error");
        assert!(
            matches!(
                err,
                ClientError::ServiceError {
                    error_class: ErrorClass::Service(1)
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn status_reject_becomes_reject_error() {
        use crate::mms::pdu::{ConfirmedRequestRejectReason, RejectPdu, RejectReason};
        let reason =
            RejectReason::ConfirmedRequest(ConfirmedRequestRejectReason::UnrecognizedService);
        let pdu = MmsPdu::Reject(RejectPdu {
            invoke_id: Some(3),
            reason: reason.clone(),
        });
        let err = dispatch_status_response(pdu).expect_err("a reject");
        assert!(
            matches!(&err, ClientError::RejectError { reason: r } if *r == reason),
            "got {err:?}"
        );
    }

    #[test]
    fn status_response_of_another_service_is_a_parse_error() {
        // an Identify response body under the status invokeID
        let content = Bytes::from_static(&[
            0x02, 0x01, 0x03, 0xa2, 0x09, 0x80, 0x01, b'V', 0x81, 0x01, b'M', 0x82, 0x01, b'1',
        ]);
        let err = dispatch_status_response(MmsPdu::ConfirmedResponse(content))
            .expect_err("not a status response");
        assert!(matches!(err, ClientError::PduParse(_)), "got {err:?}");
    }

    #[test]
    fn long_access_result_list_is_rejected() {
        let err = check_access_result_count(results(4), 3).expect_err("count is long");
        assert!(matches!(err, ClientError::PduParse(_)), "got {err:?}");
    }
}
