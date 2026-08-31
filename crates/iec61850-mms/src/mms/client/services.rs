//! MMS confirmed services: Read, Write, GetNameList and GetVariableAccessAttributes.
//!
//! Every service function follows the same shape:
//! 1. Take a fresh invokeID from the allocator.
//! 2. Encode the confirmed request, invokeID and service body included.
//! 3. Send it with `conn.send_mms_pdu`.
//! 4. Await the answer with `conn.recv_mms_pdu_confirmed` and dispatch on its type.
//! 5. A confirmed response succeeds, a confirmed error becomes a `ServiceError`,
//!    and a reject becomes a `RejectError`.
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
    decode_confirmed_delete_named_variable_list_response, decode_confirmed_get_name_list_response,
    decode_confirmed_get_var_access_attrs_response, decode_confirmed_read_journal_response,
    decode_confirmed_read_response, decode_confirmed_write_response,
    encode_confirmed_define_named_variable_list_request,
    encode_confirmed_delete_named_variable_list_request, encode_confirmed_get_name_list_request,
    encode_confirmed_get_var_access_attrs_request, encode_confirmed_read_journal_request,
    encode_confirmed_read_request, encode_confirmed_write_request, AccessResult, AlternateAccess,
    DefineNamedVariableEntry, DefineNamedVariableListRequest, DeleteNamedVariableListRequest,
    GetNameListRequest, GetVariableAccessAttributesRequest, ListOfVariableEntry, MmsData, MmsPdu,
    ObjectClass, ObjectName, ObjectScope, ReadJournalRequest, ReadJournalResponse, ReadRequest,
    ServiceError, TypeSpecification, VariableAccessSpecification, WriteRequest,
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
    let inner = strip_confirmed_wrapper(full).inspect_err(|_| alloc.release(invoke_id))?;
    let pdu = MmsPdu::ConfirmedRequest(inner);

    // send it; the PDU size guard lives inside send_mms_pdu
    if let Err(e) = conn.send_mms_pdu(&pdu).await {
        alloc.release(invoke_id);
        return Err(e);
    }

    // await the response
    let resp_pdu = match conn.recv_mms_pdu_confirmed().await {
        Ok(p) => p,
        Err(e) => {
            alloc.release(invoke_id);
            return Err(e);
        }
    };

    alloc.release(invoke_id);
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
    let inner = strip_confirmed_wrapper(full).inspect_err(|_| alloc.release(invoke_id))?;
    let pdu = MmsPdu::ConfirmedRequest(inner);

    if let Err(e) = conn.send_mms_pdu(&pdu).await {
        alloc.release(invoke_id);
        return Err(e);
    }

    let resp_pdu = match conn.recv_mms_pdu_confirmed().await {
        Ok(p) => p,
        Err(e) => {
            alloc.release(invoke_id);
            return Err(e);
        }
    };

    alloc.release(invoke_id);
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
    let inner = strip_confirmed_wrapper(full).inspect_err(|_| alloc.release(invoke_id))?;
    let pdu = MmsPdu::ConfirmedRequest(inner);

    if let Err(e) = conn.send_mms_pdu(&pdu).await {
        alloc.release(invoke_id);
        return Err(e);
    }

    let resp_pdu = match conn.recv_mms_pdu_confirmed().await {
        Ok(p) => p,
        Err(e) => {
            alloc.release(invoke_id);
            return Err(e);
        }
    };

    alloc.release(invoke_id);
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
    let inner = strip_confirmed_wrapper(full).inspect_err(|_| alloc.release(invoke_id))?;
    let pdu = MmsPdu::ConfirmedRequest(inner);

    if let Err(e) = conn.send_mms_pdu(&pdu).await {
        alloc.release(invoke_id);
        return Err(e);
    }

    let resp_pdu = match conn.recv_mms_pdu_confirmed().await {
        Ok(p) => p,
        Err(e) => {
            alloc.release(invoke_id);
            return Err(e);
        }
    };

    alloc.release(invoke_id);
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
    let inner = strip_confirmed_wrapper(full).inspect_err(|_| alloc.release(invoke_id))?;
    let pdu = MmsPdu::ConfirmedRequest(inner);

    if let Err(e) = conn.send_mms_pdu(&pdu).await {
        alloc.release(invoke_id);
        return Err(e);
    }

    let resp_pdu = match conn.recv_mms_pdu_confirmed().await {
        Ok(p) => p,
        Err(e) => {
            alloc.release(invoke_id);
            return Err(e);
        }
    };

    alloc.release(invoke_id);
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
    let inner = strip_confirmed_wrapper(full).inspect_err(|_| alloc.release(invoke_id))?;
    let pdu = MmsPdu::ConfirmedRequest(inner);

    if let Err(e) = conn.send_mms_pdu(&pdu).await {
        alloc.release(invoke_id);
        return Err(e);
    }

    let resp_pdu = match conn.recv_mms_pdu_confirmed().await {
        Ok(p) => p,
        Err(e) => {
            alloc.release(invoke_id);
            return Err(e);
        }
    };

    alloc.release(invoke_id);
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
    let inner = strip_confirmed_wrapper(full).inspect_err(|_| alloc.release(invoke_id))?;
    let pdu = MmsPdu::ConfirmedRequest(inner);

    if let Err(e) = conn.send_mms_pdu(&pdu).await {
        alloc.release(invoke_id);
        return Err(e);
    }

    let resp_pdu = match conn.recv_mms_pdu_confirmed().await {
        Ok(p) => p,
        Err(e) => {
            alloc.release(invoke_id);
            return Err(e);
        }
    };

    alloc.release(invoke_id);
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
    let inner = strip_confirmed_wrapper(full).inspect_err(|_| alloc.release(invoke_id))?;
    let pdu = MmsPdu::ConfirmedRequest(inner);

    if let Err(e) = conn.send_mms_pdu(&pdu).await {
        alloc.release(invoke_id);
        return Err(e);
    }

    let resp_pdu = match conn.recv_mms_pdu_confirmed().await {
        Ok(p) => p,
        Err(e) => {
            alloc.release(invoke_id);
            return Err(e);
        }
    };

    alloc.release(invoke_id);
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
    let inner = strip_confirmed_wrapper(full).inspect_err(|_| alloc.release(invoke_id))?;
    let pdu = MmsPdu::ConfirmedRequest(inner);

    if let Err(e) = conn.send_mms_pdu(&pdu).await {
        alloc.release(invoke_id);
        return Err(e);
    }

    let resp_pdu = match conn.recv_mms_pdu_confirmed().await {
        Ok(p) => p,
        Err(e) => {
            alloc.release(invoke_id);
            return Err(e);
        }
    };

    alloc.release(invoke_id);
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
            // take the first AccessResult
            match resp.list_of_access_result.into_iter().next() {
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
    let inner = strip_confirmed_wrapper(full).inspect_err(|_| alloc.release(invoke_id))?;
    let pdu = MmsPdu::ConfirmedRequest(inner);

    if let Err(e) = conn.send_mms_pdu(&pdu).await {
        alloc.release(invoke_id);
        return Err(e);
    }

    let resp_pdu = match conn.recv_mms_pdu_confirmed().await {
        Ok(p) => p,
        Err(e) => {
            alloc.release(invoke_id);
            return Err(e);
        }
    };

    alloc.release(invoke_id);
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
    let inner = strip_confirmed_wrapper(full).inspect_err(|_| alloc.release(invoke_id))?;
    let pdu = MmsPdu::ConfirmedRequest(inner);

    if let Err(e) = conn.send_mms_pdu(&pdu).await {
        alloc.release(invoke_id);
        return Err(e);
    }

    let resp_pdu = match conn.recv_mms_pdu_confirmed().await {
        Ok(p) => p,
        Err(e) => {
            alloc.release(invoke_id);
            return Err(e);
        }
    };

    alloc.release(invoke_id);
    dispatch_delete_named_variable_list_response(resp_pdu)
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
            // take the first WriteOutcome
            use crate::mms::pdu::WriteOutcome;
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
/// The content after tag `0xa2` is:
/// ```text
/// 0x02 <len> <invokeId>   -- invokeID, skipped
/// 0xa2 <len> ...          -- serviceError
/// ```
fn handle_confirmed_error(inner: &[u8]) -> ClientError {
    // skip the invokeID, tag 0x02
    let mut pos = 0usize;
    if inner.len() >= 3 && inner[0] == 0x02 {
        let id_len = inner[1] as usize;
        pos = 2 + id_len;
    }
    // serviceError, EXPLICIT [2] with tag 0xa2
    if pos < inner.len() && inner[pos] == 0xa2 {
        pos += 1; // skip tag
        if pos < inner.len() {
            let svc_len = inner[pos] as usize;
            pos += 1;
            if pos + svc_len <= inner.len() {
                match ServiceError::decode_inner(&inner[pos..pos + svc_len]) {
                    Ok(se) => {
                        warn!("mms confirmed error: class={:?}", se.error_class);
                        return ClientError::ServiceError {
                            error_class: se.error_class,
                        };
                    }
                    Err(e) => {
                        warn!("confirmed error service error failed to decode: {e}");
                    }
                }
            }
        }
    }
    // nothing could be decoded, so report a generic parse failure
    ClientError::PduParse("ConfirmedError decode failed".to_string())
}
