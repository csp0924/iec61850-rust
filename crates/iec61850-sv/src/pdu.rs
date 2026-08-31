//! BER encoding and decoding of the `savPdu` of IEC 61850-9-2.
//!
//! The PDU is an `[APPLICATION 0] IMPLICIT SEQUENCE` (outer tag `0x60`) holding
//! an ASDU count and a sequence of ASDUs. Decoding bounds every field against
//! its enclosing ASDU and rejects malformed input rather than skipping it.
//!
//! ## Wire format
//!
//! ```text
//! 60 LL                         savPdu
//!    80 LL <noASDU>             INTEGER, number of ASDUs
//!    A2 LL                      SEQUENCE OF ASDU (constructed, context 2)
//!      30 LL                    one ASDU (SEQUENCE)
//!        80 LL <svID>           VISIBLE_STRING
//!        [81 LL <datSet>]       VISIBLE_STRING, optional
//!        82 02 <smpCnt>         OCTET_STRING(2), big-endian u16
//!        83 04 <confRev>        INTEGER(4), big-endian u32
//!        [84 08 <refrTm>]       UtcTime(8), optional
//!        85 01 <smpSynch>       OCTET_STRING(1)
//!        [86 02 <smpRate>]      OCTET_STRING(2), big-endian u16, optional
//!        87 LL <sample>         OCTET_STRING, raw sample bytes
//!        [88 01 <smpMod>]       OCTET_STRING(1), optional
//!        [89 08 <gmIdentity>]   OCTET_STRING(8), optional
//! ```
//!
//! ## Robustness cases
//!
//! - smpMod is encoded in exactly one byte, as the standard defines. Some
//!   publishers in the field send two; decoding accepts that and takes the last
//!   byte as the value.
//! - `encode_length` emits a multi-byte BER length whenever a payload exceeds
//!   127 bytes, so a large sample field is not truncated.
//! - Every decode path propagates length errors with `?`, so a corrupt length
//!   ends the parse instead of looping.

use bytes::BytesMut;
use iec61850_asn1::{decode_length, encode_length};

use crate::error::SvError;

/// Outer tag of the savPdu, `[APPLICATION 0] IMPLICIT SEQUENCE`. GOOSE uses
/// `0x61` for the same position.
const TAG_SAV_PDU: u8 = 0x60;

/// SEQUENCE OF ASDU tag: constructed, context 2.
const TAG_ASDU_SEQ: u8 = 0xA2;

/// Outer tag of one ASDU, the universal SEQUENCE.
const TAG_ASDU: u8 = 0x30;

// Context tags of the ASDU members.

const TAG_SV_ID: u8 = 0x80;
const TAG_DAT_SET: u8 = 0x81;
const TAG_SMP_CNT: u8 = 0x82;
const TAG_CONF_REV: u8 = 0x83;
const TAG_REFR_TM: u8 = 0x84;
const TAG_SMP_SYNCH: u8 = 0x85;
const TAG_SMP_RATE: u8 = 0x86;
const TAG_SAMPLE: u8 = 0x87;
const TAG_SMP_MOD: u8 = 0x88;
const TAG_GM_IDENTITY: u8 = 0x89;

/// Maximum number of ASDUs accepted in one frame.
///
/// The bound keeps a single frame from steering the decoder into an
/// unbounded number of ASDU parses.
pub const MAX_ASDU_PER_FRAME: usize = 10;

/// Maximum length in bytes of the svID and datSet string fields.
///
/// SCL types both as `tVisString129`, so a longer value is rejected rather
/// than truncated and a subscriber never matches on a shortened reference.
pub const SV_STRING_MAX_LEN: usize = 129;

/// A UtcTime field is always 8 bytes.
const UTC_TIME_SIZE: usize = 8;

/// Sampling synchronization state, the one-byte smpSynch field.
///
/// Reserved and unassigned values are preserved rather than rejected, so a
/// publisher using a value assigned after this implementation was written
/// still round-trips.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmpSynch {
    /// 0: samples are not synchronized.
    NotSynced,
    /// 1: synchronized to an unspecified local clock.
    LocalUnspec,
    /// 2: synchronized to a global clock.
    GlobalClock,
    /// 5 to 254: synchronized to the local clock this value identifies.
    LocalIdentified(u8),
    /// 3, 4, and 255: reserved by the standard.
    Reserved(u8),
}

impl SmpSynch {
    /// Decodes the wire byte.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => SmpSynch::NotSynced,
            1 => SmpSynch::LocalUnspec,
            2 => SmpSynch::GlobalClock,
            5..=254 => SmpSynch::LocalIdentified(b),
            _ => SmpSynch::Reserved(b),
        }
    }

    /// Returns the wire byte.
    pub fn to_byte(self) -> u8 {
        match self {
            SmpSynch::NotSynced => 0,
            SmpSynch::LocalUnspec => 1,
            SmpSynch::GlobalClock => 2,
            SmpSynch::LocalIdentified(v) => v,
            SmpSynch::Reserved(v) => v,
        }
    }
}

/// Sampling mode, the one-byte smpMod field.
///
/// Unassigned values are preserved rather than rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmpMod {
    /// 0: samples per nominal period, the default.
    PerNominalPeriod,
    /// 1: samples per second.
    SamplesPerSecond,
    /// 2: seconds per sample.
    SecondsPerSample,
    /// Any other value, preserved as sent.
    Unknown(u8),
}

impl SmpMod {
    /// Decodes the wire byte.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => SmpMod::PerNominalPeriod,
            1 => SmpMod::SamplesPerSecond,
            2 => SmpMod::SecondsPerSample,
            _ => SmpMod::Unknown(b),
        }
    }

    /// Returns the wire byte.
    pub fn to_byte(self) -> u8 {
        match self {
            SmpMod::PerNominalPeriod => 0,
            SmpMod::SamplesPerSecond => 1,
            SmpMod::SecondsPerSample => 2,
            SmpMod::Unknown(v) => v,
        }
    }
}

/// One Application Service Data Unit.
///
/// The ASDU owns its strings and sample bytes, so it outlives the buffer it
/// was decoded from.
#[derive(Debug, Clone, PartialEq)]
pub struct Asdu {
    /// svID, the identifier of this Sampled Values stream.
    pub sv_id: String,
    /// datSet, the data set object reference; optional.
    pub dat_set: Option<String>,
    /// smpCnt, the sample counter.
    ///
    /// It travels as a 2-byte OCTET STRING, not as an INTEGER.
    pub smp_cnt: u16,
    /// confRev, the configuration revision.
    pub conf_rev: u32,
    /// refrTm, the refresh time as an 8-byte UtcTime; optional.
    pub refr_tm: Option<[u8; UTC_TIME_SIZE]>,
    /// smpSynch, the synchronization state.
    pub smp_synch: SmpSynch,
    /// smpRate, samples per period or per second depending on smpMod;
    /// optional.
    pub smp_rate: Option<u16>,
    /// Raw sample bytes; the layout is defined by the data set.
    pub sample: Vec<u8>,
    /// smpMod, the sampling mode; optional.
    pub smp_mod: Option<SmpMod>,
    /// gmIdentity, the 8-byte PTP grandmaster identity; optional.
    pub gm_identity: Option<[u8; 8]>,
}

/// A savPdu carrying one or more ASDUs.
#[derive(Debug, Clone, PartialEq)]
pub struct SavPdu {
    /// The ASDUs of this PDU, at most `MAX_ASDU_PER_FRAME`.
    pub asdus: Vec<Asdu>,
}

/// Returns the encoded size of an ASDU's contents, excluding its own tag and
/// length.
fn asdu_contents_size(asdu: &Asdu) -> usize {
    let mut size = 0usize;

    let sv_id_len = asdu.sv_id.len();
    size += 1 + length_size(sv_id_len) + sv_id_len;

    if let Some(ref ds) = asdu.dat_set {
        let ds_len = ds.len();
        size += 1 + length_size(ds_len) + ds_len;
    }

    // smpCnt: tag, length, and 2 value bytes.
    size += 4;

    // confRev: tag, length, and 4 value bytes.
    size += 6;

    // refrTm: tag, length, and 8 value bytes.
    if asdu.refr_tm.is_some() {
        size += 10;
    }

    // smpSynch: tag, length, and 1 value byte.
    size += 3;

    // smpRate: tag, length, and 2 value bytes.
    if asdu.smp_rate.is_some() {
        size += 4;
    }

    let sample_len = asdu.sample.len();
    size += 1 + length_size(sample_len) + sample_len;

    // smpMod: tag, length, and exactly 1 value byte.
    if asdu.smp_mod.is_some() {
        size += 3;
    }

    // gmIdentity: tag, length, and 8 value bytes.
    if asdu.gm_identity.is_some() {
        size += 10;
    }

    size
}

/// Returns the number of bytes a BER length field needs for `len`.
fn length_size(len: usize) -> usize {
    if len < 128 {
        1
    } else if len <= 0xFF {
        2
    } else {
        3
    }
}

/// Appends the BER encoding of `pdu` to `buf`.
///
/// # Errors
///
/// Returns `MissingRequiredField` when the PDU carries no ASDU.
pub fn encode_sav_pdu(pdu: &SavPdu, buf: &mut BytesMut) -> Result<(), SvError> {
    if pdu.asdus.is_empty() {
        return Err(SvError::MissingRequiredField {
            tag: TAG_SMP_CNT,
            name: "at least one asdu",
        });
    }

    // Sizes are computed first so every length field can be written ahead of
    // the content it describes.
    let mut asdu_seq_contents_size = 0usize;
    for asdu in &pdu.asdus {
        let contents = asdu_contents_size(asdu);
        asdu_seq_contents_size += 1 + length_size(contents) + contents;
    }

    // noASDU never exceeds MAX_ASDU_PER_FRAME, so one value byte suffices.
    let no_asdu_val = pdu.asdus.len() as u8;
    let no_asdu_val_size: usize = 1;
    let no_asdu_field_size = 1 + 1 + no_asdu_val_size;

    let asdu_seq_field_size = 1 + length_size(asdu_seq_contents_size) + asdu_seq_contents_size;

    let sav_pdu_contents_size = no_asdu_field_size + asdu_seq_field_size;

    buf.extend_from_slice(&[TAG_SAV_PDU]);
    encode_length(sav_pdu_contents_size, buf);

    buf.extend_from_slice(&[0x80, 0x01, no_asdu_val]);

    buf.extend_from_slice(&[TAG_ASDU_SEQ]);
    encode_length(asdu_seq_contents_size, buf);

    for asdu in &pdu.asdus {
        encode_asdu(asdu, buf)?;
    }

    Ok(())
}

/// Appends one ASDU, its SEQUENCE tag and length included.
fn encode_asdu(asdu: &Asdu, buf: &mut BytesMut) -> Result<(), SvError> {
    let contents_size = asdu_contents_size(asdu);

    buf.extend_from_slice(&[TAG_ASDU]);
    encode_length(contents_size, buf);

    let sv_id_bytes = asdu.sv_id.as_bytes();
    buf.extend_from_slice(&[TAG_SV_ID]);
    encode_length(sv_id_bytes.len(), buf);
    buf.extend_from_slice(sv_id_bytes);

    if let Some(ref ds) = asdu.dat_set {
        let ds_bytes = ds.as_bytes();
        buf.extend_from_slice(&[TAG_DAT_SET]);
        encode_length(ds_bytes.len(), buf);
        buf.extend_from_slice(ds_bytes);
    }

    buf.extend_from_slice(&[TAG_SMP_CNT, 0x02]);
    buf.extend_from_slice(&asdu.smp_cnt.to_be_bytes());

    buf.extend_from_slice(&[TAG_CONF_REV, 0x04]);
    buf.extend_from_slice(&asdu.conf_rev.to_be_bytes());

    if let Some(ref tm) = asdu.refr_tm {
        buf.extend_from_slice(&[TAG_REFR_TM, 0x08]);
        buf.extend_from_slice(tm);
    }

    buf.extend_from_slice(&[TAG_SMP_SYNCH, 0x01, asdu.smp_synch.to_byte()]);

    if let Some(rate) = asdu.smp_rate {
        buf.extend_from_slice(&[TAG_SMP_RATE, 0x02]);
        buf.extend_from_slice(&rate.to_be_bytes());
    }

    buf.extend_from_slice(&[TAG_SAMPLE]);
    encode_length(asdu.sample.len(), buf);
    buf.extend_from_slice(&asdu.sample);

    // smpMod is one byte; some publishers in the field send two, which the
    // decoder tolerates but this encoder never emits.
    if let Some(smp_mod) = asdu.smp_mod {
        buf.extend_from_slice(&[TAG_SMP_MOD, 0x01, smp_mod.to_byte()]);
    }

    if let Some(ref gm) = asdu.gm_identity {
        buf.extend_from_slice(&[TAG_GM_IDENTITY, 0x08]);
        buf.extend_from_slice(gm);
    }

    Ok(())
}

/// Decodes a `SavPdu` starting at the outer `0x60` tag, without the Ethernet
/// and SV application headers.
///
/// Unknown members of the savPdu are skipped for forward compatibility, but a
/// PDU that yields no ASDU is rejected.
///
/// # Errors
///
/// - `WrongPduTag` when the outer tag is not `0x60`.
/// - `TruncatedInput` when a length reaches past the buffer.
/// - `TooManyAsdus` when noASDU exceeds `MAX_ASDU_PER_FRAME`.
/// - `InvalidFieldLength`, `AsduFieldOutOfBounds`, `MissingRequiredField`,
///   `SvIdTooLong`, `DatSetTooLong`, and `InvalidUtf8` from the ASDUs.
/// - `Asn1` when a BER length field is malformed.
pub fn decode_sav_pdu(data: &[u8]) -> Result<SavPdu, SvError> {
    let mut pos = 0usize;

    if pos >= data.len() {
        return Err(SvError::TruncatedInput {
            needed: 1,
            available: 0,
        });
    }
    let pdu_tag = data[pos];
    pos += 1;
    if pdu_tag != TAG_SAV_PDU {
        return Err(SvError::WrongPduTag(pdu_tag));
    }

    let (pdu_len, pdu_len_size) = decode_length(&data[pos..])?;
    pos += pdu_len_size;

    let pdu_end = pos + pdu_len;
    if pdu_end > data.len() {
        return Err(SvError::TruncatedInput {
            needed: pdu_end,
            available: data.len(),
        });
    }

    let mut no_asdu: Option<u8> = None;
    let mut asdus: Vec<Asdu> = Vec::new();

    while pos < pdu_end {
        if pos >= data.len() {
            break;
        }
        let tag = data[pos];
        pos += 1;

        let (field_len, field_len_size) = decode_length(&data[pos..])?;
        pos += field_len_size;

        let field_end = pos + field_len;
        if field_end > pdu_end {
            return Err(SvError::TruncatedInput {
                needed: field_end,
                available: pdu_end,
            });
        }

        match tag {
            0x80 => {
                if field_len == 0 {
                    return Err(SvError::InvalidFieldLength {
                        tag: 0x80,
                        expected: 1,
                        actual: 0,
                    });
                }
                // The count is small, so the least significant byte carries it.
                let val = data[field_end - 1];
                if val as usize > MAX_ASDU_PER_FRAME {
                    tracing::warn!(
                        "sv noasdu {} exceeds the maximum of {}",
                        val,
                        MAX_ASDU_PER_FRAME
                    );
                    return Err(SvError::TooManyAsdus(val));
                }
                no_asdu = Some(val);
                pos = field_end;
            }
            TAG_ASDU_SEQ => {
                asdus = decode_asdu_sequence(&data[pos..field_end])?;
                pos = field_end;
            }
            _ => {
                // Skipped for forward compatibility with future members.
                tracing::warn!("savpdu skipped unknown tag 0x{:02x}", tag);
                pos = field_end;
            }
        }
    }

    if let Some(n) = no_asdu {
        if n as usize != asdus.len() {
            tracing::warn!(
                "noasdu {} does not match the {} asdus decoded",
                n,
                asdus.len()
            );
        }
    }

    // noASDU is mandatory and at least 1, and the encoder refuses to build an
    // empty PDU; the decoder rejects one symmetrically so that decode and
    // encode agree on every accepted input.
    if asdus.is_empty() {
        return Err(SvError::MissingRequiredField {
            tag: TAG_ASDU_SEQ,
            name: "at least one asdu",
        });
    }

    Ok(SavPdu { asdus })
}

/// Decodes the contents of the SEQUENCE OF ASDU member.
fn decode_asdu_sequence(data: &[u8]) -> Result<Vec<Asdu>, SvError> {
    let mut pos = 0usize;
    let mut asdus = Vec::new();

    while pos < data.len() {
        if pos >= data.len() {
            break;
        }
        let tag = data[pos];
        pos += 1;

        if tag != TAG_ASDU {
            return Err(SvError::WrongAsduTag(tag));
        }

        let (asdu_len, asdu_len_size) = decode_length(&data[pos..])?;
        pos += asdu_len_size;

        let asdu_end = pos + asdu_len;
        if asdu_end > data.len() {
            return Err(SvError::TruncatedInput {
                needed: asdu_end,
                available: data.len(),
            });
        }

        let asdu = decode_asdu(&data[pos..asdu_end])?;
        asdus.push(asdu);
        pos = asdu_end;
    }

    Ok(asdus)
}

/// Decodes the contents of one ASDU, without its own tag and length.
///
/// Every member is checked against the ASDU boundary before its value is read.
///
/// # Errors
///
/// Returns `AsduFieldOutOfBounds`, `InvalidFieldLength`, `InvalidUtf8`,
/// `SvIdTooLong`, `DatSetTooLong`, or `MissingRequiredField` for a malformed
/// or incomplete ASDU.
fn decode_asdu(data: &[u8]) -> Result<Asdu, SvError> {
    let asdu_end = data.len();
    let mut pos = 0usize;

    let mut sv_id: Option<String> = None;
    let mut dat_set: Option<String> = None;
    let mut smp_cnt: Option<u16> = None;
    let mut conf_rev: Option<u32> = None;
    let mut refr_tm: Option<[u8; UTC_TIME_SIZE]> = None;
    let mut smp_synch: Option<SmpSynch> = None;
    let mut smp_rate: Option<u16> = None;
    let mut sample: Option<Vec<u8>> = None;
    let mut smp_mod: Option<SmpMod> = None;
    let mut gm_identity: Option<[u8; 8]> = None;

    while pos < asdu_end {
        let tag = data[pos];
        pos += 1;

        let (field_len, field_len_size) = decode_length(&data[pos..])?;
        pos += field_len_size;

        let value_start = pos;
        let value_end = pos + field_len;

        if value_end > asdu_end {
            return Err(SvError::AsduFieldOutOfBounds {
                tag,
                value_end,
                asdu_end,
            });
        }

        let value = &data[value_start..value_end];

        match tag {
            TAG_SV_ID => {
                // The bound is checked on the already-delimited value, so an
                // over-long field is rejected without reading past the ASDU.
                if value.len() > SV_STRING_MAX_LEN {
                    tracing::warn!(
                        "sv svid length {} exceeds the maximum of {}",
                        value.len(),
                        SV_STRING_MAX_LEN
                    );
                    return Err(SvError::SvIdTooLong(value.len()));
                }
                let s = std::str::from_utf8(value).map_err(|_| SvError::InvalidUtf8)?;
                sv_id = Some(s.to_owned());
            }
            TAG_DAT_SET => {
                // As for svID, the bound is checked on the already-delimited
                // value, so an over-long field never reads past the ASDU.
                if value.len() > SV_STRING_MAX_LEN {
                    tracing::warn!(
                        "sv datset length {} exceeds the maximum of {}",
                        value.len(),
                        SV_STRING_MAX_LEN
                    );
                    return Err(SvError::DatSetTooLong(value.len()));
                }
                let s = std::str::from_utf8(value).map_err(|_| SvError::InvalidUtf8)?;
                dat_set = Some(s.to_owned());
            }
            TAG_SMP_CNT => {
                if field_len != 2 {
                    return Err(SvError::InvalidFieldLength {
                        tag: TAG_SMP_CNT,
                        expected: 2,
                        actual: field_len,
                    });
                }
                smp_cnt = Some(u16::from_be_bytes([value[0], value[1]]));
            }
            TAG_CONF_REV => {
                if field_len != 4 {
                    return Err(SvError::InvalidFieldLength {
                        tag: TAG_CONF_REV,
                        expected: 4,
                        actual: field_len,
                    });
                }
                conf_rev = Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
            }
            TAG_REFR_TM => {
                if field_len != UTC_TIME_SIZE {
                    return Err(SvError::InvalidFieldLength {
                        tag: TAG_REFR_TM,
                        expected: UTC_TIME_SIZE,
                        actual: field_len,
                    });
                }
                let mut tm = [0u8; UTC_TIME_SIZE];
                tm.copy_from_slice(value);
                refr_tm = Some(tm);
            }
            TAG_SMP_SYNCH => {
                if field_len != 1 {
                    return Err(SvError::InvalidFieldLength {
                        tag: TAG_SMP_SYNCH,
                        expected: 1,
                        actual: field_len,
                    });
                }
                smp_synch = Some(SmpSynch::from_byte(value[0]));
            }
            TAG_SMP_RATE => {
                if field_len != 2 {
                    return Err(SvError::InvalidFieldLength {
                        tag: TAG_SMP_RATE,
                        expected: 2,
                        actual: field_len,
                    });
                }
                smp_rate = Some(u16::from_be_bytes([value[0], value[1]]));
            }
            TAG_SAMPLE => {
                sample = Some(value.to_vec());
            }
            TAG_SMP_MOD => {
                // The standard defines one byte; some publishers in the field
                // send two, so the last byte is taken as the value.
                let byte_val = match field_len {
                    1 => value[0],
                    2 => {
                        tracing::warn!(
                            "smpmod field is 2 bytes, taking the last byte as the value"
                        );
                        value[1]
                    }
                    _ => {
                        return Err(SvError::InvalidFieldLength {
                            tag: TAG_SMP_MOD,
                            expected: 1,
                            actual: field_len,
                        });
                    }
                };
                smp_mod = Some(SmpMod::from_byte(byte_val));
            }
            TAG_GM_IDENTITY => {
                // An optional field of the wrong length is dropped rather than
                // failing the whole ASDU, since the samples remain usable.
                if field_len != 8 {
                    tracing::warn!("gmidentity field is {} bytes, not 8; ignored", field_len);
                } else {
                    let mut gm = [0u8; 8];
                    gm.copy_from_slice(value);
                    gm_identity = Some(gm);
                }
            }
            _ => {
                // Skipped for forward compatibility with future members.
                tracing::warn!("asdu skipped unknown tag 0x{:02x}, len={}", tag, field_len);
            }
        }

        pos = value_end;
    }

    let sv_id = sv_id.ok_or(SvError::MissingRequiredField {
        tag: TAG_SV_ID,
        name: "svID",
    })?;
    let smp_cnt = smp_cnt.ok_or(SvError::MissingRequiredField {
        tag: TAG_SMP_CNT,
        name: "smpCnt",
    })?;
    let conf_rev = conf_rev.ok_or(SvError::MissingRequiredField {
        tag: TAG_CONF_REV,
        name: "confRev",
    })?;
    let smp_synch = smp_synch.ok_or(SvError::MissingRequiredField {
        tag: TAG_SMP_SYNCH,
        name: "smpSynch",
    })?;
    let sample = sample.ok_or(SvError::MissingRequiredField {
        tag: TAG_SAMPLE,
        name: "sample",
    })?;

    Ok(Asdu {
        sv_id,
        dat_set,
        smp_cnt,
        conf_rev,
        refr_tm,
        smp_synch,
        smp_rate,
        sample,
        smp_mod,
        gm_identity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an ASDU with only the mandatory fields.
    fn minimal_asdu(sv_id: &str, smp_cnt: u16) -> Asdu {
        Asdu {
            sv_id: sv_id.to_owned(),
            dat_set: None,
            smp_cnt,
            conf_rev: 1,
            refr_tm: None,
            smp_synch: SmpSynch::NotSynced,
            smp_rate: None,
            sample: vec![0u8; 8],
            smp_mod: None,
            gm_identity: None,
        }
    }

    /// Builds an ASDU with every optional field present.
    fn full_asdu(sv_id: &str) -> Asdu {
        Asdu {
            sv_id: sv_id.to_owned(),
            dat_set: Some("IED1/LLN0$SV$testDS".to_owned()),
            smp_cnt: 100,
            conf_rev: 0xABCDEF01,
            refr_tm: Some([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]),
            smp_synch: SmpSynch::GlobalClock,
            smp_rate: Some(4000),
            sample: vec![0xABu8; 64],
            smp_mod: Some(SmpMod::SamplesPerSecond),
            gm_identity: Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
        }
    }

    #[test]
    fn smp_synch_roundtrip() {
        let cases = [
            SmpSynch::NotSynced,
            SmpSynch::LocalUnspec,
            SmpSynch::GlobalClock,
            SmpSynch::LocalIdentified(100),
            SmpSynch::LocalIdentified(5),
            SmpSynch::LocalIdentified(254),
            SmpSynch::Reserved(3),
            SmpSynch::Reserved(4),
            SmpSynch::Reserved(255),
        ];
        for s in cases {
            assert_eq!(SmpSynch::from_byte(s.to_byte()), s);
        }
    }

    #[test]
    fn smp_mod_roundtrip() {
        let cases = [
            SmpMod::PerNominalPeriod,
            SmpMod::SamplesPerSecond,
            SmpMod::SecondsPerSample,
            SmpMod::Unknown(42),
        ];
        for m in cases {
            assert_eq!(SmpMod::from_byte(m.to_byte()), m);
        }
    }

    #[test]
    fn minimal_asdu_roundtrip() {
        let pdu = SavPdu {
            asdus: vec![minimal_asdu("TESTLD/LLN0$SV$testSV", 0)],
        };
        let mut buf = BytesMut::new();
        encode_sav_pdu(&pdu, &mut buf).unwrap();
        let decoded = decode_sav_pdu(&buf).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn minimal_asdu_roundtrip_byte_exact() {
        let pdu = SavPdu {
            asdus: vec![minimal_asdu("TESTLD/LLN0$SV$sv1", 42)],
        };
        let mut buf1 = BytesMut::new();
        encode_sav_pdu(&pdu, &mut buf1).unwrap();
        let decoded = decode_sav_pdu(&buf1).unwrap();
        let mut buf2 = BytesMut::new();
        encode_sav_pdu(&decoded, &mut buf2).unwrap();
        assert_eq!(&buf1[..], &buf2[..]);
    }

    #[test]
    fn full_asdu_roundtrip() {
        let pdu = SavPdu {
            asdus: vec![full_asdu("IED1/LLN0$SV$sv1")],
        };
        let mut buf = BytesMut::new();
        encode_sav_pdu(&pdu, &mut buf).unwrap();
        let decoded = decode_sav_pdu(&buf).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn no_asdu_1_roundtrip() {
        let pdu = SavPdu {
            asdus: vec![minimal_asdu("sv1", 1)],
        };
        let mut buf = BytesMut::new();
        encode_sav_pdu(&pdu, &mut buf).unwrap();
        let decoded = decode_sav_pdu(&buf).unwrap();
        assert_eq!(decoded.asdus.len(), 1);
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn no_asdu_2_roundtrip() {
        let pdu = SavPdu {
            asdus: vec![minimal_asdu("sv1", 10), minimal_asdu("sv2", 20)],
        };
        let mut buf = BytesMut::new();
        encode_sav_pdu(&pdu, &mut buf).unwrap();
        let decoded = decode_sav_pdu(&buf).unwrap();
        assert_eq!(decoded.asdus.len(), 2);
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn no_asdu_4_roundtrip() {
        let pdu = SavPdu {
            asdus: (0..4)
                .map(|i| minimal_asdu(&format!("sv{}", i), i as u16 * 100))
                .collect(),
        };
        let mut buf = BytesMut::new();
        encode_sav_pdu(&pdu, &mut buf).unwrap();
        let decoded = decode_sav_pdu(&buf).unwrap();
        assert_eq!(decoded.asdus.len(), 4);
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn no_asdu_10_is_ok() {
        let pdu = SavPdu {
            asdus: (0..10)
                .map(|i| minimal_asdu(&format!("sv{}", i), i as u16))
                .collect(),
        };
        let mut buf = BytesMut::new();
        encode_sav_pdu(&pdu, &mut buf).unwrap();
        let decoded = decode_sav_pdu(&buf).unwrap();
        assert_eq!(decoded.asdus.len(), 10);
    }

    #[test]
    fn no_asdu_11_rejected() {
        // A savPdu announcing 11 ASDUs with an empty ASDU sequence.
        let mut buf = BytesMut::new();
        let inner = vec![0x80u8, 0x01, 11u8, 0xA2, 0x00];
        buf.extend_from_slice(&[TAG_SAV_PDU]);
        encode_length(inner.len(), &mut buf);
        buf.extend_from_slice(&inner);
        let result = decode_sav_pdu(&buf);
        assert!(matches!(result, Err(SvError::TooManyAsdus(11))));
    }

    #[test]
    fn smp_mod_legacy_2byte_decode_tolerant() {
        // A publisher that sends smpMod in two bytes must still be decoded.
        let extra = vec![TAG_SMP_MOD, 0x02, 0x00, 0x01];

        let mut inner_asdu = BytesMut::new();
        inner_asdu.extend_from_slice(&[TAG_SV_ID, 0x03, b's', b'v', b'1']);
        inner_asdu.extend_from_slice(&[TAG_SMP_CNT, 0x02, 0x00, 0x00]);
        inner_asdu.extend_from_slice(&[TAG_CONF_REV, 0x04, 0x00, 0x00, 0x00, 0x01]);
        inner_asdu.extend_from_slice(&[TAG_SMP_SYNCH, 0x01, 0x00]);
        inner_asdu.extend_from_slice(&[TAG_SAMPLE, 0x08]);
        inner_asdu.extend_from_slice(&[0u8; 8]);
        inner_asdu.extend_from_slice(&extra);

        let mut asdu_tlv = BytesMut::new();
        asdu_tlv.extend_from_slice(&[TAG_ASDU]);
        encode_length(inner_asdu.len(), &mut asdu_tlv);
        asdu_tlv.extend_from_slice(&inner_asdu);

        let mut seq_tlv = BytesMut::new();
        seq_tlv.extend_from_slice(&[TAG_ASDU_SEQ]);
        encode_length(asdu_tlv.len(), &mut seq_tlv);
        seq_tlv.extend_from_slice(&asdu_tlv);

        let mut no_asdu_bytes = BytesMut::new();
        no_asdu_bytes.extend_from_slice(&[0x80, 0x01, 0x01]);

        let contents_len = no_asdu_bytes.len() + seq_tlv.len();
        let mut final_buf = BytesMut::new();
        final_buf.extend_from_slice(&[TAG_SAV_PDU]);
        encode_length(contents_len, &mut final_buf);
        final_buf.extend_from_slice(&no_asdu_bytes);
        final_buf.extend_from_slice(&seq_tlv);

        let decoded = decode_sav_pdu(&final_buf).unwrap();
        assert_eq!(decoded.asdus.len(), 1);
        // The last byte, 0x01, is the value.
        assert_eq!(decoded.asdus[0].smp_mod, Some(SmpMod::SamplesPerSecond));
    }

    #[test]
    fn smp_synch_local_identified_roundtrip() {
        let asdu = Asdu {
            sv_id: "svLocal".to_owned(),
            dat_set: None,
            smp_cnt: 0,
            conf_rev: 1,
            refr_tm: None,
            smp_synch: SmpSynch::LocalIdentified(100),
            smp_rate: None,
            sample: vec![0u8; 8],
            smp_mod: None,
            gm_identity: None,
        };
        let pdu = SavPdu { asdus: vec![asdu] };
        let mut buf = BytesMut::new();
        encode_sav_pdu(&pdu, &mut buf).unwrap();
        let decoded = decode_sav_pdu(&buf).unwrap();
        assert_eq!(decoded.asdus[0].smp_synch, SmpSynch::LocalIdentified(100));
    }

    /// Robustness regression: smpMod is always encoded in exactly one byte.
    #[test]
    fn smp_mod_encodes_one_byte() {
        let asdu = Asdu {
            sv_id: "sv1".to_owned(),
            dat_set: None,
            smp_cnt: 0,
            conf_rev: 1,
            refr_tm: None,
            smp_synch: SmpSynch::NotSynced,
            smp_rate: None,
            sample: vec![0u8; 4],
            smp_mod: Some(SmpMod::SamplesPerSecond),
            gm_identity: None,
        };
        let pdu = SavPdu { asdus: vec![asdu] };
        let mut buf = BytesMut::new();
        encode_sav_pdu(&pdu, &mut buf).unwrap();
        let bytes = &buf[..];
        let mut found = false;
        for i in 0..bytes.len().saturating_sub(1) {
            if bytes[i] == TAG_SMP_MOD {
                assert_eq!(
                    bytes[i + 1],
                    0x01,
                    "smpmod ber length is 1, got {}",
                    bytes[i + 1]
                );
                found = true;
                break;
            }
        }
        assert!(found, "smpmod tag 0x88 is present in the encoding");
    }

    /// Robustness regression: a sample longer than 127 bytes uses a
    /// multi-byte BER length instead of being truncated.
    #[test]
    fn large_sample_ber_length() {
        let large_sample = vec![0xABu8; 128];
        let asdu = Asdu {
            sv_id: "sv1".to_owned(),
            dat_set: None,
            smp_cnt: 0,
            conf_rev: 1,
            refr_tm: None,
            smp_synch: SmpSynch::NotSynced,
            smp_rate: None,
            sample: large_sample,
            smp_mod: None,
            gm_identity: None,
        };
        let pdu = SavPdu { asdus: vec![asdu] };
        let mut buf = BytesMut::new();
        encode_sav_pdu(&pdu, &mut buf).unwrap();
        let bytes = &buf[..];
        let mut found = false;
        for i in 0..bytes.len().saturating_sub(2) {
            if bytes[i] == TAG_SAMPLE && bytes[i + 1] == 0x81 {
                // 0x81 is the long form with one length byte.
                assert_eq!(bytes[i + 2], 128u8);
                found = true;
                break;
            }
        }
        assert!(found, "sample tag 0x87 uses the long-form length 0x81");

        let decoded = decode_sav_pdu(&buf).unwrap();
        assert_eq!(decoded.asdus[0].sample.len(), 128);
    }

    /// Robustness regression: a corrupt BER length returns an error instead of
    /// panicking or looping.
    #[test]
    fn corrupt_ber_length_rejected() {
        // 0x83 announces a 3-byte long-form length, which is not supported.
        let corrupt = vec![TAG_SAV_PDU, 0x83, 0x00, 0x00, 0x10];
        let result = decode_sav_pdu(&corrupt);
        assert!(result.is_err(), "a corrupt ber length returns err");
    }

    #[test]
    fn malformed_truncated_input() {
        let result = decode_sav_pdu(&[]);
        assert!(matches!(result, Err(SvError::TruncatedInput { .. })));

        // A tag with no length field.
        let result = decode_sav_pdu(&[TAG_SAV_PDU]);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_pdu_tag_rejected() {
        // 0x61 is the GOOSE PDU tag.
        let result = decode_sav_pdu(&[0x61, 0x00]);
        assert!(matches!(result, Err(SvError::WrongPduTag(0x61))));
    }

    /// The svID bound is inclusive: an identifier of exactly `SV_STRING_MAX_LEN`
    /// bytes decodes.
    #[test]
    fn sv_id_at_the_limit_accepted() {
        let pdu = SavPdu {
            asdus: vec![minimal_asdu(&"A".repeat(SV_STRING_MAX_LEN), 0)],
        };
        let mut buf = BytesMut::new();
        encode_sav_pdu(&pdu, &mut buf).unwrap();
        let decoded = decode_sav_pdu(&buf).expect("an svid at the limit decodes");
        assert_eq!(decoded.asdus[0].sv_id.len(), SV_STRING_MAX_LEN);
    }

    /// Robustness regression: an svID past `SV_STRING_MAX_LEN` is rejected rather
    /// than truncated, and without reading past the enclosing ASDU.
    #[test]
    fn sv_id_too_long_rejected() {
        let pdu = SavPdu {
            asdus: vec![minimal_asdu(&"A".repeat(SV_STRING_MAX_LEN + 1), 0)],
        };
        let mut buf = BytesMut::new();
        encode_sav_pdu(&pdu, &mut buf).unwrap();
        let result = decode_sav_pdu(&buf);
        assert!(
            matches!(result, Err(SvError::SvIdTooLong(130))),
            "an over-long svid must return svidtoolong, got {:?}",
            result
        );
    }

    /// The datSet bound is inclusive: a reference of exactly
    /// `SV_STRING_MAX_LEN` bytes decodes.
    #[test]
    fn dat_set_at_the_limit_accepted() {
        let dat_set = "D".repeat(SV_STRING_MAX_LEN);
        let mut asdu = minimal_asdu("sv1", 0);
        asdu.dat_set = Some(dat_set.clone());
        let pdu = SavPdu { asdus: vec![asdu] };
        let mut buf = BytesMut::new();
        encode_sav_pdu(&pdu, &mut buf).unwrap();
        let decoded = decode_sav_pdu(&buf).expect("a datset at the limit decodes");
        assert_eq!(decoded.asdus[0].dat_set.as_deref(), Some(dat_set.as_str()));
    }

    /// Robustness regression: a datSet past `SV_STRING_MAX_LEN` is rejected
    /// rather than truncated, and without reading past the enclosing ASDU.
    #[test]
    fn dat_set_too_long_rejected() {
        let mut asdu = minimal_asdu("sv1", 0);
        asdu.dat_set = Some("D".repeat(SV_STRING_MAX_LEN + 1));
        let pdu = SavPdu { asdus: vec![asdu] };
        let mut buf = BytesMut::new();
        encode_sav_pdu(&pdu, &mut buf).unwrap();
        let result = decode_sav_pdu(&buf);
        assert!(
            matches!(result, Err(SvError::DatSetTooLong(130))),
            "an over-long datset must return datsettoolong, got {:?}",
            result
        );
    }

    #[test]
    fn missing_required_field_svid() {
        // An ASDU carrying smpCnt, confRev, smpSynch, and sample but no svID.
        let mut inner_asdu = BytesMut::new();
        inner_asdu.extend_from_slice(&[TAG_SMP_CNT, 0x02, 0x00, 0x00]);
        inner_asdu.extend_from_slice(&[TAG_CONF_REV, 0x04, 0x00, 0x00, 0x00, 0x01]);
        inner_asdu.extend_from_slice(&[TAG_SMP_SYNCH, 0x01, 0x00]);
        inner_asdu.extend_from_slice(&[TAG_SAMPLE, 0x04, 0x00, 0x00, 0x00, 0x00]);

        let mut asdu_tlv = BytesMut::new();
        asdu_tlv.extend_from_slice(&[TAG_ASDU]);
        encode_length(inner_asdu.len(), &mut asdu_tlv);
        asdu_tlv.extend_from_slice(&inner_asdu);

        let mut seq_tlv = BytesMut::new();
        seq_tlv.extend_from_slice(&[TAG_ASDU_SEQ]);
        encode_length(asdu_tlv.len(), &mut seq_tlv);
        seq_tlv.extend_from_slice(&asdu_tlv);

        let no_asdu_bytes = vec![0x80u8, 0x01, 0x01];
        let contents_len = no_asdu_bytes.len() + seq_tlv.len();
        let mut final_buf = BytesMut::new();
        final_buf.extend_from_slice(&[TAG_SAV_PDU]);
        encode_length(contents_len, &mut final_buf);
        final_buf.extend_from_slice(&no_asdu_bytes);
        final_buf.extend_from_slice(&seq_tlv);

        let result = decode_sav_pdu(&final_buf);
        assert!(
            matches!(result, Err(SvError::MissingRequiredField { tag: 0x80, .. })),
            "a missing svid reports missingrequiredfield"
        );
    }
}
