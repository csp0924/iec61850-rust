//! MMS InformationReport, the unconfirmed PDU used for reporting and for command
//! termination.
//!
//! ## Wire format, per IEC 61850-8-1 and ISO 9506-2
//!
//! ```text
//! MMSpdu CHOICE { ..., unconfirmedPDU [3] IMPLICIT UnconfirmedPDU, ... }
//!   outer tag 0xa3
//!
//! UnconfirmedPDU ::= SEQUENCE {
//!   service [0] IMPLICIT UnconfirmedService
//! }
//!
//! UnconfirmedService ::= CHOICE {
//!   informationReport [0] IMPLICIT InformationReport
//! }
//!
//! InformationReport ::= SEQUENCE {
//!   variableAccessSpecification CHOICE {
//!     listOfVariable     [0] IMPLICIT SEQUENCE OF VariableAccessSpecification,
//!     variableListName   [1] IMPLICIT ObjectName,
//!   },
//!   listOfAccessResult [0] IMPLICIT SEQUENCE OF AccessResult,
//! }
//! ```
//!
//! ## Nesting on the wire
//!
//! The encoding carries three nested tags: the outer `0xa3`, one merged `0xa0`, and
//! two inner `0xa0` fields.
//!
//! ```text
//! 0xa3 <informationReportSize>          // unconfirmedPDU [3] IMPLICIT
//!   0xa0 <informationReportContentSize> // service [0] and informationReport [0] merged
//!     0xa0 <listOfVariableSize>         // listOfVariable [0] IMPLICIT
//!       <SEQUENCE element> ...
//!     0xa0 <accessResultSize>           // listOfAccessResult [0] IMPLICIT
//!       <AccessResult bytes> ...
//! ```
//!
//! The two `[0] IMPLICIT` layers merge because BER does not repeat the tag of an
//! implicitly tagged CHOICE inside an implicitly tagged field, so the encoding is
//! `0xa3 <total>` followed by `0xa0 <body>`. Adding a further `0xa0` wrapper makes
//! peers fail to parse the report, so the encoder must not add one.
//!
//! ## Positive command termination
//!
//! One variable: the domain-specific name `<LN>$CO$<DO>$Oper`, whose
//! AccessResult.Success is the whole Oper structure, encoded by the caller.
//!
//! ## Negative command termination
//!
//! Two variables, in this order:
//! 1. the VMD-specific `LastApplError`, whose AccessResult.Success is a five-element
//!    structure
//! 2. the domain-specific `<LN>$CO$<DO>$Oper`, whose AccessResult.Success is the
//!    whole Oper structure
//!
//! ## The LastApplError structure
//!
//! ```text
//! [0] ctlObj    VISIBLE_STRING  "<LD>/<LN>$CO$<DO>$Oper"
//! [1] error     INT32           ControlLastApplError
//! [2] origin    STRUCTURE       { orCat: INT, orIdent: OCTET_STRING }
//! [3] ctlNum    UNSIGNED(8)
//! [4] addCause  INT32           ControlAddCause
//! ```

use crate::compat::prelude::*;
use bytes::{Bytes, BytesMut};

use super::common::{MmsData, ObjectName};
use super::initiate::encode_length;
use crate::MmsError;

// Public types describing a command-termination variable

/// The fields of the LastApplError origin structure.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OriginRef {
    /// orCat, the category of the originator that issued the control.
    pub or_cat: i32,
    /// orIdent, the identity of that originator.
    pub or_ident: Vec<u8>,
}

/// The five elements of a LastApplError structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastApplErrorRef {
    /// `<LD>/<LN>$CO$<DO>$Oper`
    pub ctl_obj: String,
    /// `ControlLastApplError`, as its `i32` wire value.
    pub error: i32,
    /// origin, naming who issued the control.
    pub origin: OriginRef,
    /// ctlNum, the control sequence number.
    pub ctl_num: u8,
    /// `ControlAddCause`, as its `i32` wire value.
    pub add_cause: i32,
}

// Public decoder types

/// A decoded variableAccessSpecification CHOICE.
///
/// A report control block normally sends `VariableListName` with the VMD-specific
/// name `RPT`; command termination uses `ListOfVariable` with domain-specific names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VariableAccessSpec {
    /// `[1] variableListName`, tag `0xa1`, wrapping an ObjectName CHOICE.
    /// A report control block uses the VMD-specific name `RPT`.
    VariableListName(ObjectName),
    /// `[0] listOfVariable SEQUENCE OF`, tag `0xa0`.
    /// Command termination uses domain-specific names.
    ListOfVariable(Vec<ObjectName>),
}

/// An owned view of a decoded InformationReport.
///
/// listOfAccessResult is a flat sequence of context-tagged BER fields on the wire,
/// not a SEQUENCE OF AccessResult, so it decodes into a `Vec<MmsData>` in wire
/// order. The caller interprets that sequence, splitting out RptId, OptFlds, SqNum,
/// the inclusion bitmap and the values according to OptFlds.
#[derive(Debug, Clone, PartialEq)]
pub struct InformationReportInner {
    /// Which variables the report refers to; a report control block always uses the
    /// VMD-specific name `RPT`.
    pub variable_access_spec: VariableAccessSpec,
    /// The flat sequence inside listOfAccessResult. Each element is a context-tagged
    /// value, such as a VisibleString, BitString, Unsigned, Boolean or BinaryTime.
    pub list_of_access_result: Vec<MmsData>,
}

// Public decoder API

/// Decodes the content of an unconfirmed PDU, with the outer `0xa3 <len>` already
/// stripped, into an [`InformationReportInner`].
///
/// The expected wire shape, following the nesting described above, is:
///
/// ```text
/// 0xa0 <combined_len>                service [0] merged with informationReport [0]
///   <variableAccessSpec>             0xa1 <len> ... or 0xa0 <listOfVariable>
///   0xa0 <listOfAccessResultLen>     listOfAccessResult inner
///     <flat MmsData seq>             RptId / OptFlds / ... values ...
/// ```
///
/// The OptFlds, inclusion bitmap and value layout are not interpreted here: the
/// caller receives the `Vec<MmsData>` and aligns it itself, with RptId at index 0,
/// OptFlds at index 1, and so on.
pub fn decode_information_report(
    unconfirmed_inner: &[u8],
) -> Result<InformationReportInner, MmsError> {
    // strip the merged outer 0xa0
    let (combined_body, _hdr1): (&[u8], usize) = take_tag_and_length(
        unconfirmed_inner,
        0xa0,
        "combined service+informationReport",
    )?;

    // variableAccessSpec: tag 0xa0 for listOfVariable, 0xa1 for variableListName
    let (vas, vas_consumed) = decode_variable_access_spec(combined_body)?;

    // listOfAccessResult, tag 0xa0
    let (list_inner, _hdr2): (&[u8], usize) =
        take_tag_and_length(&combined_body[vas_consumed..], 0xa0, "listOfAccessResult")?;

    // the flat sequence of values
    let mut list_of_access_result = Vec::new();
    let mut pos = 0usize;
    while pos < list_inner.len() {
        let (data, consumed) = MmsData::decode(&list_inner[pos..])?;
        list_of_access_result.push(data);
        pos += consumed;
    }
    if pos != list_inner.len() {
        return Err(MmsError::decode(format!(
            "InformationReport listOfAccessResult: pos {pos} != len {}",
            list_inner.len()
        )));
    }

    Ok(InformationReportInner {
        variable_access_spec: vas,
        list_of_access_result,
    })
}

/// Decodes a variableAccessSpecification CHOICE.
///
/// The alternatives are:
/// - `[0] listOfVariable SEQUENCE OF VariableSpec`, tag `0xa0`
/// - `[1] variableListName ObjectName` -> tag `0xa1`
fn decode_variable_access_spec(data: &[u8]) -> Result<(VariableAccessSpec, usize), MmsError> {
    if data.is_empty() {
        return Err(MmsError::decode(
            "variableAccessSpec: empty input".to_string(),
        ));
    }
    match data[0] {
        // [1] variableListName, whose content is an ObjectName CHOICE
        0xa1 => {
            let (inner, hdr_len): (&[u8], usize) =
                take_tag_and_length(data, 0xa1, "variableListName")?;
            let (name, _) = ObjectName::decode(inner)?;
            Ok((
                VariableAccessSpec::VariableListName(name),
                hdr_len + inner.len(),
            ))
        }
        // [0] listOfVariable SEQUENCE OF VariableSpec, where each VariableSpec is
        // SEQUENCE { name [0] IMPLICIT ObjectName }, encoded as
        // 0x30 <len> 0xa0 <name_len> <ObjectName body>
        0xa0 => {
            let (inner, hdr_len): (&[u8], usize) =
                take_tag_and_length(data, 0xa0, "listOfVariable")?;
            let mut names = Vec::new();
            let mut pos = 0usize;
            while pos < inner.len() {
                if inner[pos] != 0x30 {
                    return Err(MmsError::decode(format!(
                        "listOfVariable element: expected 0x30 SEQUENCE, got 0x{:02x}",
                        inner[pos]
                    )));
                }
                let (elem_inner, elem_hdr_len): (&[u8], usize) =
                    take_tag_and_length(&inner[pos..], 0x30, "VariableSpec")?;
                // elem_inner = 0xa0 <name_len> <ObjectName body>
                let (name_inner, _hdr3): (&[u8], usize) =
                    take_tag_and_length(elem_inner, 0xa0, "VariableSpec.name")?;
                let (name, _) = ObjectName::decode(name_inner)?;
                names.push(name);
                pos += elem_hdr_len + elem_inner.len();
            }
            Ok((
                VariableAccessSpec::ListOfVariable(names),
                hdr_len + inner.len(),
            ))
        }
        other => Err(MmsError::decode(format!(
            "variableAccessSpec: unexpected tag 0x{other:02x}, expected 0xa0 or 0xa1"
        ))),
    }
}

/// Strips one `tag` and BER length, returning the content and the header length.
///
/// The short form, used when the length is below 128, gives a 2-byte header; long
/// forms of one, two or three length bytes are also accepted.
fn take_tag_and_length<'a>(
    data: &'a [u8],
    expected_tag: u8,
    field: &'static str,
) -> Result<(&'a [u8], usize), MmsError> {
    if data.is_empty() {
        return Err(MmsError::decode(format!(
            "{field}: empty input, expected tag 0x{expected_tag:02x}"
        )));
    }
    if data[0] != expected_tag {
        return Err(MmsError::decode(format!(
            "{field}: expected tag 0x{expected_tag:02x}, got 0x{:02x}",
            data[0]
        )));
    }
    if data.len() < 2 {
        return Err(MmsError::decode(format!("{field}: truncated length byte")));
    }
    let (len, len_bytes) = match data[1] {
        b if b < 0x80 => (b as usize, 1),
        0x81 => {
            if data.len() < 3 {
                return Err(MmsError::decode(format!(
                    "{field}: truncated long-form length (0x81)"
                )));
            }
            (data[2] as usize, 2)
        }
        0x82 => {
            if data.len() < 4 {
                return Err(MmsError::decode(format!(
                    "{field}: truncated long-form length (0x82)"
                )));
            }
            (((data[2] as usize) << 8) | (data[3] as usize), 3)
        }
        0x83 => {
            if data.len() < 5 {
                return Err(MmsError::decode(format!(
                    "{field}: truncated long-form length (0x83)"
                )));
            }
            (
                ((data[2] as usize) << 16) | ((data[3] as usize) << 8) | (data[4] as usize),
                4,
            )
        }
        other => {
            return Err(MmsError::decode(format!(
                "{field}: unsupported BER length form 0x{other:02x}"
            )));
        }
    };
    let header_len = 1 + len_bytes;
    let total = header_len + len;
    if data.len() < total {
        return Err(MmsError::decode(format!(
            "{field}: declared length {len} exceeds buffer (have {} after header)",
            data.len() - header_len
        )));
    }
    Ok((&data[header_len..total], header_len))
}

// Public encoder API

/// Encodes an InformationReport carrying the given variables.
///
/// Each entry of `variables` pairs an `ObjectName` with the wire bytes of its
/// AccessResult.Success value, which the caller has already encoded including tag
/// and length; the encoder places them into listOfAccessResult unchanged.
///
/// Returns the complete PDU, outer `0xa3` tag included.
pub fn encode_information_report(variables: &[(ObjectName, Bytes)]) -> Bytes {
    // listOfVariable, [0] IMPLICIT SEQUENCE OF VariableSpec, where each element is
    // SEQUENCE { name [0] IMPLICIT ObjectName }, encoded as
    // 0x30 <len> 0xa0 <name_len> <ObjectName body>. The domain-specific form starts
    // 0x30 0xa0 0xa1 0x1a 0x1a, the vmd-specific form 0x30 0xa0 0x80.
    let mut list_of_var_inner = BytesMut::new();
    for (name, _) in variables {
        let mut name_buf = BytesMut::new();
        name.encode(&mut name_buf);
        // the element SEQUENCE, tag 0x30, whose content is 0xa0 <name_len> <body>
        let inner_len = 1 + ber_len_size(name_buf.len()) + name_buf.len();
        list_of_var_inner.extend_from_slice(&[0x30]);
        encode_length(inner_len, &mut list_of_var_inner);
        list_of_var_inner.extend_from_slice(&[0xa0]);
        encode_length(name_buf.len(), &mut list_of_var_inner);
        list_of_var_inner.extend_from_slice(&name_buf);
    }

    // listOfAccessResult, [0] IMPLICIT SEQUENCE OF AccessResult
    let mut list_of_ar_inner = BytesMut::new();
    for (_, ar_bytes) in variables {
        list_of_ar_inner.extend_from_slice(ar_bytes);
    }

    // InformationReport body = listOfVariable [0] || listOfAccessResult [0]
    // the two 0xa0 fields sit side by side, with no further wrapper around them
    let mut info_report_body = BytesMut::new();
    info_report_body.extend_from_slice(&[0xa0]);
    encode_length(list_of_var_inner.len(), &mut info_report_body);
    info_report_body.extend_from_slice(&list_of_var_inner);
    info_report_body.extend_from_slice(&[0xa0]);
    encode_length(list_of_ar_inner.len(), &mut info_report_body);
    info_report_body.extend_from_slice(&list_of_ar_inner);

    // UnconfirmedPDU.service [0] and UnconfirmedService.informationReport [0] merge
    // into a single 0xa0, since BER does not repeat the tag of a nested implicit CHOICE
    let mut combined_inner = BytesMut::new();
    combined_inner.extend_from_slice(&[0xa0]);
    encode_length(info_report_body.len(), &mut combined_inner);
    combined_inner.extend_from_slice(&info_report_body);

    // the outer MmsPdu CHOICE: unconfirmedPDU [3] IMPLICIT, tag 0xa3
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&[0xa3]);
    encode_length(combined_inner.len(), &mut buf);
    buf.extend_from_slice(&combined_inner);

    buf.freeze()
}

/// Encodes a positive command termination: one variable, `<LN>$CO$<DO>$Oper` with
/// the Oper structure as its value.
///
/// `domain_id` and `item_id` form the domain-specific ObjectName; `item_id` is
/// normally `<LN>$CO$<DO>$Oper`. `oper_value_bytes` is the wire form of the Oper
/// structure, tag 0xa2 with its length and content included.
pub fn encode_command_termination_positive(
    domain_id: &str,
    item_id: &str,
    oper_value_bytes: Bytes,
) -> Bytes {
    let name = ObjectName::DomainSpecific {
        domain_id: domain_id.to_string(),
        item_id: item_id.to_string(),
    };
    encode_information_report(&[(name, oper_value_bytes)])
}

/// Encodes a negative command termination: LastApplError followed by Oper.
pub fn encode_command_termination_negative(
    last_appl_error: &LastApplErrorRef,
    domain_id: &str,
    item_id: &str,
    oper_value_bytes: Bytes,
) -> Bytes {
    let last_appl_bytes = encode_last_appl_error_struct(last_appl_error);
    let oper_name = ObjectName::DomainSpecific {
        domain_id: domain_id.to_string(),
        item_id: item_id.to_string(),
    };
    encode_information_report(&[
        (
            ObjectName::VmdSpecific("LastApplError".to_string()),
            last_appl_bytes,
        ),
        (oper_name, oper_value_bytes),
    ])
}

/// Encodes a `LastApplErrorRef` as the wire bytes of a five-element structure.
///
/// The result is used directly as an AccessResult.Success value, wrapped in the
/// structure tag 0xa2.
pub fn encode_last_appl_error_struct(e: &LastApplErrorRef) -> Bytes {
    // 5 elements as MmsData
    let elements = vec![
        MmsData::VisibleString(e.ctl_obj.clone()),
        MmsData::Integer(e.error as i64),
        MmsData::Structure(vec![
            MmsData::Integer(e.origin.or_cat as i64),
            MmsData::OctetString(e.origin.or_ident.clone()),
        ]),
        MmsData::Unsigned(e.ctl_num as u64),
        MmsData::Integer(e.add_cause as i64),
    ];
    let mut buf = BytesMut::new();
    MmsData::Structure(elements).encode(&mut buf);
    buf.freeze()
}

// Helpers

/// Returns the number of bytes a BER length field needs, matching the shared helper
/// that this module cannot reach across its visibility boundary.
fn ber_len_size(len: usize) -> usize {
    if len < 128 {
        1
    } else if len <= 0xff {
        2
    } else {
        3
    }
}

// Unit tests

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal positive command termination with one variable and a trivial Oper
    /// structure, checking the outer tag nesting and the embedded names.
    #[test]
    fn ct_positive_minimal_layout() {
        // the Oper value is Structure(Boolean(true))
        let oper_bytes = {
            let mut b = BytesMut::new();
            MmsData::Structure(vec![MmsData::Boolean(true)]).encode(&mut b);
            b.freeze()
        };
        let pdu =
            encode_command_termination_positive("IED1LD0", "GGIO1$CO$SPCSO1$Oper", oper_bytes);

        // the outer tag
        assert_eq!(
            pdu[0], 0xa3,
            "the outer tag must be unconfirmedPDU [3] IMPLICIT"
        );

        // the second layer, the merged informationReport wrapper, must be 0xa0
        // skip outer header
        let outer_hdr = if pdu[1] < 0x80 {
            2
        } else if pdu[1] == 0x81 {
            3
        } else {
            4
        };
        let inner = &pdu[outer_hdr..];
        assert_eq!(
            inner[0], 0xa0,
            "the merged service and informationReport [0] IMPLICIT must be 0xa0"
        );

        // the domain and item identifiers must appear in the bytes
        let s = String::from_utf8_lossy(&pdu);
        assert!(s.contains("IED1LD0"), "the pdu must carry the domain id");
        assert!(
            s.contains("GGIO1$CO$SPCSO1$Oper"),
            "the pdu must carry the item id"
        );
    }

    /// A byte-exact minimal InformationReport with domain "D", item "A" and an
    /// AccessResult of `0xa2 0x00`, an empty structure.
    ///
    /// The expected bytes carry exactly three nested tags. An encoder that adds two
    /// more `0xa0` wrappers produces a report peers cannot parse, so this test pins
    /// the nesting down.
    #[test]
    fn ct_positive_minimal_byte_exact() {
        // an empty structure encodes as 0xa2 0x00
        let oper_bytes = Bytes::from_static(&[0xa2, 0x00]);
        let pdu = encode_command_termination_positive("D", "A", oper_bytes);

        #[rustfmt::skip]
        let oracle: &[u8] = &[
            // 0xa3 <total=20> outer unconfirmedPDU
            0xa3, 0x14,
              // 0xa0 <body=18>, service merged with informationReport
              0xa0, 0x12,
                // 0xa0 <listOfVariable=12>
                0xa0, 0x0c,
                  // SEQUENCE <10>
                  0x30, 0x0a,
                    // VariableSpec.name [0] IMPLICIT, len=8
                    0xa0, 0x08,
                      // ObjectName.domain-specific
                      0xa1, 0x06,
                        0x1a, 0x01, b'D',
                        0x1a, 0x01, b'A',
                // 0xa0 <listOfAccessResult=2>
                0xa0, 0x02,
                  // the AccessResult bytes the caller encoded, an empty structure
                  0xa2, 0x00,
        ];

        assert_eq!(
            pdu.as_ref(),
            oracle,
            "the InformationReport must keep exactly three nested tags"
        );
    }

    #[test]
    fn ct_negative_contains_last_appl_error_and_oper() {
        let last_err = LastApplErrorRef {
            ctl_obj: "IED1LD0/GGIO1$CO$SPCSO1$Oper".into(),
            error: 0,
            origin: OriginRef {
                or_cat: 3,
                or_ident: vec![0xAA],
            },
            ctl_num: 7,
            add_cause: 9, // BlockedByProcess
        };
        let oper_bytes = {
            let mut b = BytesMut::new();
            MmsData::Structure(vec![MmsData::Boolean(false)]).encode(&mut b);
            b.freeze()
        };
        let pdu = encode_command_termination_negative(
            &last_err,
            "IED1LD0",
            "GGIO1$CO$SPCSO1$Oper",
            oper_bytes,
        );

        assert_eq!(pdu[0], 0xa3);
        let s = String::from_utf8_lossy(&pdu);
        assert!(
            s.contains("LastApplError"),
            "the pdu must carry the LastApplError name"
        );
        assert!(
            s.contains("IED1LD0/GGIO1$CO$SPCSO1$Oper"),
            "the pdu must carry ctlObj"
        );
        assert!(
            s.contains("GGIO1$CO$SPCSO1$Oper"),
            "the pdu must carry the oper path"
        );
    }

    #[test]
    fn last_appl_error_struct_5_elements() {
        let e = LastApplErrorRef {
            ctl_obj: "X/Y$CO$Z$Oper".into(),
            error: 1,
            origin: OriginRef {
                or_cat: 0,
                or_ident: vec![],
            },
            ctl_num: 0,
            add_cause: 0,
        };
        let bytes = encode_last_appl_error_struct(&e);
        // the first byte must be 0xa2, a structure, and the second a short-form length
        assert_eq!(bytes[0], 0xa2);
        // decoding must yield five elements
        let (data, _) = MmsData::decode(&bytes).expect("decode last appl error");
        if let MmsData::Structure(items) = data {
            assert_eq!(items.len(), 5, "LastApplError must have five elements");
            assert!(matches!(items[0], MmsData::VisibleString(_)));
            assert!(matches!(items[1], MmsData::Integer(_)));
            assert!(matches!(items[2], MmsData::Structure(_)));
            assert!(matches!(items[3], MmsData::Unsigned(_)));
            assert!(matches!(items[4], MmsData::Integer(_)));
        } else {
            panic!("LastApplError must be a Structure");
        }
    }

    // Decoder

    /// The decoder must parse the byte-exact positive command termination above and
    /// recover the domain-specific name plus a listOfAccessResult of one empty structure.
    #[test]
    fn decode_ct_positive_byte_exact_oracle() {
        let oper_bytes = Bytes::from_static(&[0xa2, 0x00]);
        let pdu = encode_command_termination_positive("D", "A", oper_bytes);

        // strip the outer 0xa3 and its short-form length
        let inner = &pdu[2..];
        let parsed = decode_information_report(inner).expect("decode CT+ oracle");
        match parsed.variable_access_spec {
            VariableAccessSpec::ListOfVariable(names) => {
                assert_eq!(names.len(), 1);
                match &names[0] {
                    ObjectName::DomainSpecific { domain_id, item_id } => {
                        assert_eq!(domain_id, "D");
                        assert_eq!(item_id, "A");
                    }
                    other => panic!("expected DomainSpecific, got {other:?}"),
                }
            }
            other => panic!("expected ListOfVariable, got {other:?}"),
        }
        assert_eq!(parsed.list_of_access_result.len(), 1);
        assert!(matches!(
            &parsed.list_of_access_result[0],
            MmsData::Structure(items) if items.is_empty()
        ));
    }

    /// A report control block wire form, the VMD-specific name "RPT" followed by a
    /// flat sequence of values, must decode.
    #[test]
    fn decode_urcb_report_vmd_spec_rpt() {
        // a hand-built minimal report:
        //   0xa3 0x18
        //     0xa0 0x16
        //       VAR_ACCESS_SPEC = 0xa1 0x05 0x80 0x03 'R' 'P' 'T'
        //       0xa0 0x0d
        //         RptID(VisibleString,0x8a) "RPT01"
        //         OptFlds(BitString,0x84) wire 3 bytes (padding=6, data=00 00)
        //         inclusion(BitString,0x84) wire 2 bytes (padding=7, data=00)
        let mut access = BytesMut::new();
        // RptID = "RPT01"
        access.extend_from_slice(&[0x8a, 0x05, b'R', b'P', b'T', b'0', b'1']);
        // OptFlds: tag 0x84, length 3, padding 6, two data bytes 0x00 0x00
        access.extend_from_slice(&[0x84, 0x03, 0x06, 0x00, 0x00]);
        // inclusion: tag 0x84, length 2, padding 7, one data byte 0x00 for a single
        // entry that is not included
        access.extend_from_slice(&[0x84, 0x02, 0x07, 0x00]);

        let var_spec: &[u8] = &[0xa1, 0x05, 0x80, 0x03, b'R', b'P', b'T'];
        let mut info_body = BytesMut::new();
        info_body.extend_from_slice(var_spec);
        info_body.extend_from_slice(&[0xa0, access.len() as u8]);
        info_body.extend_from_slice(&access);

        let mut combined = BytesMut::new();
        combined.extend_from_slice(&[0xa0, info_body.len() as u8]);
        combined.extend_from_slice(&info_body);

        // decode the merged content directly, starting at the 0xa0
        let parsed = decode_information_report(&combined).expect("decode URCB report");
        match parsed.variable_access_spec {
            VariableAccessSpec::VariableListName(ObjectName::VmdSpecific(name)) => {
                assert_eq!(name, "RPT");
            }
            other => panic!("expected VariableListName(VmdSpecific RPT), got {other:?}"),
        }
        assert_eq!(parsed.list_of_access_result.len(), 3);
        assert!(matches!(
            &parsed.list_of_access_result[0],
            MmsData::VisibleString(s) if s == "RPT01"
        ));
        assert!(matches!(
            &parsed.list_of_access_result[1],
            MmsData::BitString { padding: 6, data } if data.len() == 2
        ));
        assert!(matches!(
            &parsed.list_of_access_result[2],
            MmsData::BitString { padding: 7, data } if data.len() == 1
        ));
    }

    /// Short or malformed input must return an error rather than panic.
    #[test]
    fn decode_rejects_truncated_input() {
        // an outer 0xa0 whose body is incomplete
        let bad: &[u8] = &[0xa0, 0x10, 0xa1, 0x05]; // declares 16 bytes but supplies 4
        let r = decode_information_report(bad);
        assert!(matches!(r, Err(MmsError::InformationReportDecode(_))));
    }

    #[test]
    fn information_report_two_variables_round_trip() {
        // two variables, checking the layout rather than decoding the whole PDU
        let mut a_bytes = BytesMut::new();
        MmsData::Boolean(true).encode(&mut a_bytes);
        let mut b_bytes = BytesMut::new();
        MmsData::Integer(42).encode(&mut b_bytes);

        let pdu = encode_information_report(&[
            (
                ObjectName::DomainSpecific {
                    domain_id: "D1".into(),
                    item_id: "X$ST$DO$DA1".into(),
                },
                a_bytes.freeze(),
            ),
            (ObjectName::VmdSpecific("Var2".into()), b_bytes.freeze()),
        ]);

        // the outer tag
        assert_eq!(pdu[0], 0xa3);
        let s = String::from_utf8_lossy(&pdu);
        assert!(s.contains("D1"));
        assert!(s.contains("X$ST$DO$DA1"));
        assert!(s.contains("Var2"));
    }
}
