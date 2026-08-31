//! Sampled Values publisher: a prebuilt frame and the setters that update it.
//!
//! Publishing is split in two. `SvPublisherBuilder` collects the ASDUs and
//! their fixed fields; `setup_complete` consumes it, encodes the whole frame
//! once, and records the buffer offset of every field a publication changes.
//! `SvPublisher` then only overwrites those offsets, so the hot path performs
//! no BER encoding and no allocation.
//!
//! ```text
//! SvPublisherBuilder
//!     .add_asdu(...)             -> AsduHandle
//!     .setup_complete()          -> SvPublisher
//!
//! SvPublisher
//!     .set_sample(h, &[u8])
//!     .set_smp_cnt(h, u16)
//!     .increase_smp_cnt(h)       wraps per the smpCnt limit
//!     .set_smp_synch(h, SmpSynch)
//!     .set_refr_tm(h, [u8; 8])
//!     .set_gm_identity(h, [u8; 8])
//!     .frame_bytes()             -> &[u8] for the caller to send
//! ```
//!
//! The publisher owns no socket: it hands the frame bytes to the caller, or
//! writes them through an `EthernetSink`.
//!
//! ## smpCnt wrapping
//!
//! `smp_cnt_limit` is `Option<NonZeroU16>`. `None` wraps the counter across the
//! full `u16` range, 0 through 65535. `Some(n)` wraps at `n`, giving 0 through
//! `n - 1`, which is what a sample rate of `n` samples per period needs. Peers
//! that expect the counter to wrap at 65535 rather than 65536 are matched with
//! `Some(NonZeroU16::new(65535).unwrap())`.

use std::num::NonZeroU16;

use bytes::BytesMut;
use iec61850_asn1::encode_length;

use crate::error::SvError;
use crate::frame::{
    VlanTag, SV_APP_HEADER_SIZE, SV_DEFAULT_APPID, SV_DEFAULT_DST_MAC, SV_ETHER_TYPE,
    SV_HEADER_NO_VLAN, SV_HEADER_WITH_VLAN,
};
use crate::pdu::{SmpSynch, MAX_ASDU_PER_FRAME, SV_STRING_MAX_LEN};

/// Maximum size of an Ethernet frame, excluding the frame check sequence.
pub const SV_MAX_FRAME_SIZE: usize = 1518;

// BER tags used when assembling the PDU.

const TAG_SAV_PDU: u8 = 0x60;
const TAG_NO_ASDU: u8 = 0x80;
const TAG_ASDU_SEQ: u8 = 0xA2;
const TAG_ASDU: u8 = 0x30;
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

/// Configuration of one ASDU, held between `add_asdu` and `setup_complete`.
#[derive(Debug, Clone)]
struct AsduConfig {
    /// svID, the identifier of this stream.
    sv_id: String,
    /// datSet object reference; optional.
    dat_set: Option<String>,
    /// Configuration revision.
    conf_rev: u32,
    /// Size in bytes of the sample field.
    sample_size: usize,
    /// Whether the encoded ASDU carries a refrTm field.
    has_refr_tm: bool,
    /// smpRate; fixed for the life of the publisher.
    smp_rate: Option<u16>,
    /// smpMod; fixed for the life of the publisher and encoded in one byte.
    smp_mod: Option<u8>,
    /// Initial gmIdentity; when present the field can also be rewritten after
    /// setup.
    gm_identity: Option<[u8; 8]>,
    /// Initial smpSynch value.
    initial_smp_synch: SmpSynch,
    /// Value at which smpCnt wraps; `None` wraps at the full u16 range.
    smp_cnt_limit: Option<NonZeroU16>,
}

/// Buffer offsets of the mutable fields of one encoded ASDU.
///
/// After setup the publisher holds no strings, only positions in the frame.
#[derive(Debug, Clone)]
struct AsduTemplate {
    /// Offset of the 2-byte smpCnt value.
    smp_cnt_offset: usize,
    /// Offset of the 1-byte smpSynch value.
    smp_synch_offset: usize,
    /// Offset of the 8-byte refrTm value, when the field is present.
    refr_tm_offset: Option<usize>,
    /// Offset of the sample data.
    sample_offset: usize,
    /// Size in bytes of the sample data.
    sample_size: usize,
    /// Offset of the 8-byte gmIdentity value, when the field is present.
    gm_identity_offset: Option<usize>,
    /// Current smpCnt.
    smp_cnt: u16,
    /// Value at which smpCnt wraps; `None` wraps at the full u16 range.
    smp_cnt_limit: Option<NonZeroU16>,
}

/// Identifies one ASDU of a publisher; returned by `add_asdu`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsduHandle(pub usize);

/// Sends a prepared frame on an L2 interface.
///
/// Implementing this is optional: a caller may take `frame_bytes` and send the
/// frame itself.
pub trait EthernetSink {
    /// Sends one L2 frame.
    ///
    /// # Errors
    ///
    /// Returns `SvError::Other` carrying the platform error on failure.
    fn send(&mut self, frame: &[u8]) -> Result<(), SvError>;
}

/// Configures a Sampled Values publisher.
///
/// Add ASDUs with `add_asdu`, then call `setup_complete` to encode the frame
/// and obtain an `SvPublisher`.
#[derive(Debug)]
pub struct SvPublisherBuilder {
    /// Destination MAC address; defaults to `SV_DEFAULT_DST_MAC`.
    dst_mac: [u8; 6],
    /// Source MAC address.
    src_mac: [u8; 6],
    /// Application identifier.
    app_id: u16,
    /// Optional 802.1Q VLAN tag.
    vlan: Option<VlanTag>,
    /// Configured ASDUs, at most `MAX_ASDU_PER_FRAME`.
    asdus: Vec<AsduConfig>,
}

impl SvPublisherBuilder {
    /// Creates a builder for the given source MAC address.
    ///
    /// The address is supplied rather than read from an interface, so the
    /// builder needs no network access.
    pub fn new(src_mac: [u8; 6]) -> Self {
        Self {
            dst_mac: SV_DEFAULT_DST_MAC,
            src_mac,
            app_id: SV_DEFAULT_APPID,
            vlan: None,
            asdus: Vec::new(),
        }
    }

    /// Sets the destination MAC address.
    pub fn with_dst_mac(mut self, dst_mac: [u8; 6]) -> Self {
        self.dst_mac = dst_mac;
        self
    }

    /// Sets the APPID.
    pub fn with_app_id(mut self, app_id: u16) -> Self {
        self.app_id = app_id;
        self
    }

    /// Adds an 802.1Q VLAN tag to the frame.
    pub fn with_vlan(mut self, vlan: VlanTag) -> Self {
        self.vlan = Some(vlan);
        self
    }

    /// Adds an ASDU and returns its handle.
    ///
    /// `sample_size` is the byte length of the sample field, 64 for 9-2 LE.
    ///
    /// # Errors
    ///
    /// Returns `TooManyAsdus` once `MAX_ASDU_PER_FRAME` ASDUs are configured,
    /// which is checked here rather than left to overflow the frame at
    /// `setup_complete`, and `SvIdTooLong` or `DatSetTooLong` when `sv_id` or
    /// `dat_set` is longer than `SV_STRING_MAX_LEN` bytes, the bound a
    /// subscriber decoder enforces.
    pub fn add_asdu(
        &mut self,
        sv_id: impl Into<String>,
        dat_set: Option<impl Into<String>>,
        conf_rev: u32,
        sample_size: usize,
    ) -> Result<AsduHandle, SvError> {
        if self.asdus.len() >= MAX_ASDU_PER_FRAME {
            tracing::warn!(
                "add_asdu refused, already at the limit of {} asdus",
                MAX_ASDU_PER_FRAME
            );
            return Err(SvError::TooManyAsdus(self.asdus.len() as u8 + 1));
        }
        let sv_id = sv_id.into();
        if sv_id.len() > SV_STRING_MAX_LEN {
            tracing::warn!(
                "add_asdu refused, svid length {} exceeds the maximum of {} bytes",
                sv_id.len(),
                SV_STRING_MAX_LEN
            );
            return Err(SvError::SvIdTooLong(sv_id.len()));
        }
        let dat_set = dat_set.map(|s| s.into());
        if let Some(ref ds) = dat_set {
            if ds.len() > SV_STRING_MAX_LEN {
                tracing::warn!(
                    "add_asdu refused, datset length {} exceeds the maximum of {} bytes",
                    ds.len(),
                    SV_STRING_MAX_LEN
                );
                return Err(SvError::DatSetTooLong(ds.len()));
            }
        }
        let handle = AsduHandle(self.asdus.len());
        self.asdus.push(AsduConfig {
            sv_id,
            dat_set,
            conf_rev,
            sample_size,
            has_refr_tm: false,
            smp_rate: None,
            smp_mod: None,
            gm_identity: None,
            initial_smp_synch: SmpSynch::NotSynced,
            smp_cnt_limit: None,
        });
        Ok(handle)
    }

    /// Includes a refrTm field in this ASDU.
    ///
    /// # Errors
    ///
    /// Returns `InvalidAsduHandle` when `h` is not a configured ASDU.
    pub fn enable_refr_tm(&mut self, h: AsduHandle) -> Result<(), SvError> {
        let cfg = self
            .asdus
            .get_mut(h.0)
            .ok_or(SvError::InvalidAsduHandle(h.0))?;
        cfg.has_refr_tm = true;
        Ok(())
    }

    /// Sets smpRate for this ASDU.
    ///
    /// # Errors
    ///
    /// Returns `InvalidAsduHandle` when `h` is not a configured ASDU.
    pub fn set_smp_rate(&mut self, h: AsduHandle, rate: u16) -> Result<(), SvError> {
        let cfg = self
            .asdus
            .get_mut(h.0)
            .ok_or(SvError::InvalidAsduHandle(h.0))?;
        cfg.smp_rate = Some(rate);
        Ok(())
    }

    /// Sets smpMod for this ASDU.
    ///
    /// # Errors
    ///
    /// Returns `InvalidAsduHandle` when `h` is not a configured ASDU.
    pub fn set_smp_mod(&mut self, h: AsduHandle, smp_mod: u8) -> Result<(), SvError> {
        let cfg = self
            .asdus
            .get_mut(h.0)
            .ok_or(SvError::InvalidAsduHandle(h.0))?;
        cfg.smp_mod = Some(smp_mod);
        Ok(())
    }

    /// Sets the initial gmIdentity, which also makes the field writable after
    /// setup through `SvPublisher::set_gm_identity`.
    ///
    /// # Errors
    ///
    /// Returns `InvalidAsduHandle` when `h` is not a configured ASDU.
    pub fn set_gm_identity(&mut self, h: AsduHandle, gm_identity: [u8; 8]) -> Result<(), SvError> {
        let cfg = self
            .asdus
            .get_mut(h.0)
            .ok_or(SvError::InvalidAsduHandle(h.0))?;
        cfg.gm_identity = Some(gm_identity);
        Ok(())
    }

    /// Sets the initial smpSynch value.
    ///
    /// # Errors
    ///
    /// Returns `InvalidAsduHandle` when `h` is not a configured ASDU.
    pub fn set_initial_smp_synch(&mut self, h: AsduHandle, synch: SmpSynch) -> Result<(), SvError> {
        let cfg = self
            .asdus
            .get_mut(h.0)
            .ok_or(SvError::InvalidAsduHandle(h.0))?;
        cfg.initial_smp_synch = synch;
        Ok(())
    }

    /// Sets the value at which smpCnt wraps.
    ///
    /// `None` wraps across the full `u16` range; `Some(n)` counts 0 through
    /// `n - 1`.
    ///
    /// # Errors
    ///
    /// Returns `InvalidAsduHandle` when `h` is not a configured ASDU.
    pub fn set_smp_cnt_limit(
        &mut self,
        h: AsduHandle,
        limit: Option<NonZeroU16>,
    ) -> Result<(), SvError> {
        let cfg = self
            .asdus
            .get_mut(h.0)
            .ok_or(SvError::InvalidAsduHandle(h.0))?;
        cfg.smp_cnt_limit = limit;
        Ok(())
    }

    /// Encodes the frame once and returns the publisher.
    ///
    /// # Errors
    ///
    /// - `NoAsdus` when no ASDU was added.
    /// - `FrameTooLarge` when the encoded frame would exceed
    ///   `SV_MAX_FRAME_SIZE`.
    /// - `PduOverflow` if the PDU does not fit the computed buffer.
    pub fn setup_complete(self) -> Result<SvPublisher, SvError> {
        if self.asdus.is_empty() {
            tracing::warn!("setup_complete refused, no asdu configured");
            return Err(SvError::NoAsdus);
        }

        let header_size = if self.vlan.is_some() {
            SV_HEADER_WITH_VLAN
        } else {
            SV_HEADER_NO_VLAN
        };

        let pdu_size = compute_pdu_size(&self.asdus)?;

        let frame_size = header_size + pdu_size;
        if frame_size > SV_MAX_FRAME_SIZE {
            tracing::warn!(
                "sv frame size {} exceeds the maximum of {}",
                frame_size,
                SV_MAX_FRAME_SIZE
            );
            return Err(SvError::FrameTooLarge(frame_size));
        }

        let mut buffer = vec![0u8; frame_size];

        write_ethernet_header(
            &mut buffer,
            &self.dst_mac,
            &self.src_mac,
            self.vlan,
            self.app_id,
            pdu_size as u16 + SV_APP_HEADER_SIZE as u16,
        );

        let pdu_start = header_size;
        let (templates, pdu_written) =
            write_pdu_to_buffer(&mut buffer[pdu_start..], &self.asdus, pdu_start)?;

        debug_assert_eq!(pdu_written, pdu_size, "computed and written pdu size agree");

        tracing::debug!(
            "sv publisher ready: {} asdus, frame {} bytes, pdu {} bytes",
            self.asdus.len(),
            frame_size,
            pdu_size
        );

        Ok(SvPublisher {
            buffer: buffer.into_boxed_slice(),
            frame_len: frame_size,
            asdus: templates,
            pdu_start,
            no_asdu: self.asdus.len() as u8,
        })
    }
}

/// A configured Sampled Values publisher.
///
/// Only the setters that overwrite prebuilt fields and `frame_bytes` are
/// available here; the frame layout is fixed.
#[derive(Debug)]
pub struct SvPublisher {
    /// The encoded frame, Ethernet header and savPdu together.
    buffer: Box<[u8]>,
    /// Length of the frame within `buffer`.
    frame_len: usize,
    /// Field offsets of each ASDU, indexed by `AsduHandle`.
    asdus: Vec<AsduTemplate>,
    /// Offset of the savPdu within the frame, equal to the header size.
    #[allow(dead_code)]
    pdu_start: usize,
    /// Number of ASDUs, fixed at setup.
    no_asdu: u8,
}

impl SvPublisher {
    /// Writes the sample data of one ASDU into the frame.
    ///
    /// # Errors
    ///
    /// Returns `InvalidAsduHandle` for an unknown handle and
    /// `SampleSizeMismatch` when `data` is not the configured sample size.
    pub fn set_sample(&mut self, h: AsduHandle, data: &[u8]) -> Result<(), SvError> {
        let tmpl = self.asdus.get(h.0).ok_or(SvError::InvalidAsduHandle(h.0))?;
        if data.len() != tmpl.sample_size {
            return Err(SvError::SampleSizeMismatch {
                expected: tmpl.sample_size,
                actual: data.len(),
            });
        }
        let off = tmpl.sample_offset;
        let size = tmpl.sample_size;
        self.buffer[off..][..size].copy_from_slice(data);
        Ok(())
    }

    /// Sets smpCnt.
    ///
    /// # Errors
    ///
    /// Returns `InvalidAsduHandle` for an unknown handle.
    pub fn set_smp_cnt(&mut self, h: AsduHandle, cnt: u16) -> Result<(), SvError> {
        let tmpl = self
            .asdus
            .get_mut(h.0)
            .ok_or(SvError::InvalidAsduHandle(h.0))?;
        tmpl.smp_cnt = cnt;
        let off = tmpl.smp_cnt_offset;
        self.buffer[off..][..2].copy_from_slice(&cnt.to_be_bytes());
        Ok(())
    }

    /// Returns the current smpCnt.
    ///
    /// # Errors
    ///
    /// Returns `InvalidAsduHandle` for an unknown handle.
    pub fn get_smp_cnt(&self, h: AsduHandle) -> Result<u16, SvError> {
        let tmpl = self.asdus.get(h.0).ok_or(SvError::InvalidAsduHandle(h.0))?;
        Ok(tmpl.smp_cnt)
    }

    /// Advances smpCnt by one, wrapping at the configured limit.
    ///
    /// # Errors
    ///
    /// Returns `InvalidAsduHandle` for an unknown handle.
    pub fn increase_smp_cnt(&mut self, h: AsduHandle) -> Result<(), SvError> {
        let tmpl = self
            .asdus
            .get_mut(h.0)
            .ok_or(SvError::InvalidAsduHandle(h.0))?;
        tmpl.smp_cnt = match tmpl.smp_cnt_limit {
            None => tmpl.smp_cnt.wrapping_add(1),
            Some(limit) => ((tmpl.smp_cnt as u32 + 1) % limit.get() as u32) as u16,
        };
        let cnt = tmpl.smp_cnt;
        let off = tmpl.smp_cnt_offset;
        self.buffer[off..][..2].copy_from_slice(&cnt.to_be_bytes());
        Ok(())
    }

    /// Sets smpSynch.
    ///
    /// # Errors
    ///
    /// Returns `InvalidAsduHandle` for an unknown handle.
    pub fn set_smp_synch(&mut self, h: AsduHandle, synch: SmpSynch) -> Result<(), SvError> {
        let tmpl = self.asdus.get(h.0).ok_or(SvError::InvalidAsduHandle(h.0))?;
        let off = tmpl.smp_synch_offset;
        self.buffer[off] = synch.to_byte();
        Ok(())
    }

    /// Sets the 8-byte refrTm value.
    ///
    /// # Errors
    ///
    /// Returns `InvalidAsduHandle` for an unknown handle and
    /// `RefrTmNotEnabled` when the ASDU has no refrTm field.
    pub fn set_refr_tm(&mut self, h: AsduHandle, ts: [u8; 8]) -> Result<(), SvError> {
        let tmpl = self.asdus.get(h.0).ok_or(SvError::InvalidAsduHandle(h.0))?;
        let off = tmpl.refr_tm_offset.ok_or(SvError::RefrTmNotEnabled)?;
        self.buffer[off..][..8].copy_from_slice(&ts);
        Ok(())
    }

    /// Sets the 8-byte gmIdentity value, writing it straight into the frame.
    ///
    /// # Errors
    ///
    /// Returns `InvalidAsduHandle` for an unknown handle and
    /// `GmIdentityNotEnabled` when the ASDU has no gmIdentity field.
    pub fn set_gm_identity(&mut self, h: AsduHandle, gm_id: [u8; 8]) -> Result<(), SvError> {
        let tmpl = self.asdus.get(h.0).ok_or(SvError::InvalidAsduHandle(h.0))?;
        let off = tmpl
            .gm_identity_offset
            .ok_or(SvError::GmIdentityNotEnabled)?;
        self.buffer[off..][..8].copy_from_slice(&gm_id);
        Ok(())
    }

    /// Returns the current frame bytes, ready to send.
    pub fn frame_bytes(&self) -> &[u8] {
        &self.buffer[..self.frame_len]
    }

    /// Sends the current frame through `sink`.
    ///
    /// # Errors
    ///
    /// Returns whatever error the sink reports.
    pub fn publish_with_sink(&self, sink: &mut dyn EthernetSink) -> Result<(), SvError> {
        sink.send(&self.buffer[..self.frame_len])
    }

    /// Returns the noASDU value.
    pub fn no_asdu(&self) -> u8 {
        self.no_asdu
    }

    /// Returns the number of configured ASDUs.
    pub fn asdu_count(&self) -> usize {
        self.asdus.len()
    }
}

/// Returns the number of bytes a BER length field needs for `len`.
fn ber_len_size(len: usize) -> usize {
    if len < 128 {
        1
    } else if len <= 0xFF {
        2
    } else {
        3
    }
}

/// Returns the encoded size of an ASDU's contents, excluding its own tag and
/// length.
fn asdu_contents_size(cfg: &AsduConfig) -> usize {
    let mut size = 0;

    let sv_id_len = cfg.sv_id.len();
    size += 1 + ber_len_size(sv_id_len) + sv_id_len;

    if let Some(ref ds) = cfg.dat_set {
        let ds_len = ds.len();
        size += 1 + ber_len_size(ds_len) + ds_len;
    }

    // smpCnt: tag, length, and 2 value bytes.
    size += 4;

    // confRev: tag, length, and 4 value bytes.
    size += 6;

    // refrTm: tag, length, and 8 value bytes.
    if cfg.has_refr_tm {
        size += 10;
    }

    // smpSynch: tag, length, and 1 value byte.
    size += 3;

    // smpRate: tag, length, and 2 value bytes.
    if cfg.smp_rate.is_some() {
        size += 4;
    }

    size += 1 + ber_len_size(cfg.sample_size) + cfg.sample_size;

    // smpMod: tag, length, and exactly 1 value byte.
    if cfg.smp_mod.is_some() {
        size += 3;
    }

    // gmIdentity: tag, length, and 8 value bytes.
    if cfg.gm_identity.is_some() {
        size += 10;
    }

    size
}

/// Returns the encoded size of the whole savPdu, excluding the Ethernet and SV
/// headers.
fn compute_pdu_size(asdus: &[AsduConfig]) -> Result<usize, SvError> {
    let mut asdu_seq_contents = 0usize;
    for cfg in asdus {
        let contents = asdu_contents_size(cfg);
        asdu_seq_contents += 1 + ber_len_size(contents) + contents;
    }

    // noASDU never exceeds MAX_ASDU_PER_FRAME, so one value byte suffices.
    let no_asdu_field = 3;

    let asdu_seq_field = 1 + ber_len_size(asdu_seq_contents) + asdu_seq_contents;

    let sav_pdu_contents = no_asdu_field + asdu_seq_field;

    Ok(1 + ber_len_size(sav_pdu_contents) + sav_pdu_contents)
}

/// Writes the Ethernet and SV application headers at the start of `buf`.
fn write_ethernet_header(
    buf: &mut [u8],
    dst_mac: &[u8; 6],
    src_mac: &[u8; 6],
    vlan: Option<VlanTag>,
    app_id: u16,
    length: u16,
) {
    let mut pos = 0;
    buf[pos..][..6].copy_from_slice(dst_mac);
    pos += 6;
    buf[pos..][..6].copy_from_slice(src_mac);
    pos += 6;

    if let Some(v) = vlan {
        buf[pos..][..2].copy_from_slice(&0x8100u16.to_be_bytes());
        pos += 2;
        // TCI holds the priority in bits 15:13 and the VLAN ID in bits 11:0.
        let tci: u16 = ((v.priority.value() as u16) << 13) | (v.vlan_id & 0x0FFF);
        buf[pos..][..2].copy_from_slice(&tci.to_be_bytes());
        pos += 2;
    }

    buf[pos..][..2].copy_from_slice(&SV_ETHER_TYPE.to_be_bytes());
    pos += 2;
    buf[pos..][..2].copy_from_slice(&app_id.to_be_bytes());
    pos += 2;
    buf[pos..][..2].copy_from_slice(&length.to_be_bytes());
    pos += 2;
    // Reserved1 and Reserved2, transmitted as zero.
    buf[pos..][..4].fill(0);
}

/// Writes the savPdu into `buf` and records the field offsets of each ASDU.
///
/// `global_base` is the position of `buf` within the whole frame, so the
/// recorded offsets index the frame rather than this slice. Returns the
/// templates and the number of bytes written.
fn write_pdu_to_buffer(
    buf: &mut [u8],
    asdus: &[AsduConfig],
    global_base: usize,
) -> Result<(Vec<AsduTemplate>, usize), SvError> {
    let mut bm = BytesMut::new();

    let mut asdu_seq_contents = 0usize;
    for cfg in asdus {
        let contents = asdu_contents_size(cfg);
        asdu_seq_contents += 1 + ber_len_size(contents) + contents;
    }

    let no_asdu_field = 3usize;
    let asdu_seq_field = 1 + ber_len_size(asdu_seq_contents) + asdu_seq_contents;
    let sav_pdu_contents = no_asdu_field + asdu_seq_field;

    bm.extend_from_slice(&[TAG_SAV_PDU]);
    encode_length(sav_pdu_contents, &mut bm);

    bm.extend_from_slice(&[TAG_NO_ASDU, 0x01, asdus.len() as u8]);

    bm.extend_from_slice(&[TAG_ASDU_SEQ]);
    encode_length(asdu_seq_contents, &mut bm);

    let mut templates = Vec::with_capacity(asdus.len());

    for cfg in asdus {
        let asdu_contents = asdu_contents_size(cfg);
        bm.extend_from_slice(&[TAG_ASDU]);
        encode_length(asdu_contents, &mut bm);

        let sv_id_bytes = cfg.sv_id.as_bytes();
        bm.extend_from_slice(&[TAG_SV_ID]);
        encode_length(sv_id_bytes.len(), &mut bm);
        bm.extend_from_slice(sv_id_bytes);

        if let Some(ref ds) = cfg.dat_set {
            let ds_bytes = ds.as_bytes();
            bm.extend_from_slice(&[TAG_DAT_SET]);
            encode_length(ds_bytes.len(), &mut bm);
            bm.extend_from_slice(ds_bytes);
        }

        // The offsets skip the tag and length bytes of each field.
        let smp_cnt_offset = global_base + bm.len() + 2;
        bm.extend_from_slice(&[TAG_SMP_CNT, 0x02, 0x00, 0x00]);

        bm.extend_from_slice(&[TAG_CONF_REV, 0x04]);
        bm.extend_from_slice(&cfg.conf_rev.to_be_bytes());

        let refr_tm_offset = if cfg.has_refr_tm {
            let off = global_base + bm.len() + 2;
            bm.extend_from_slice(&[TAG_REFR_TM, 0x08]);
            bm.extend_from_slice(&[0u8; 8]);
            Some(off)
        } else {
            None
        };

        let smp_synch_offset = global_base + bm.len() + 2;
        bm.extend_from_slice(&[TAG_SMP_SYNCH, 0x01, cfg.initial_smp_synch.to_byte()]);

        if let Some(rate) = cfg.smp_rate {
            bm.extend_from_slice(&[TAG_SMP_RATE, 0x02]);
            bm.extend_from_slice(&rate.to_be_bytes());
        }

        let sample_offset = global_base + bm.len() + 1 + ber_len_size(cfg.sample_size);
        bm.extend_from_slice(&[TAG_SAMPLE]);
        encode_length(cfg.sample_size, &mut bm);
        let zeroes = vec![0u8; cfg.sample_size];
        bm.extend_from_slice(&zeroes);

        if let Some(smp_mod) = cfg.smp_mod {
            bm.extend_from_slice(&[TAG_SMP_MOD, 0x01, smp_mod]);
        }

        let gm_identity_offset = if let Some(ref gm) = cfg.gm_identity {
            let off = global_base + bm.len() + 2;
            bm.extend_from_slice(&[TAG_GM_IDENTITY, 0x08]);
            bm.extend_from_slice(gm);
            Some(off)
        } else {
            None
        };

        templates.push(AsduTemplate {
            smp_cnt_offset,
            smp_synch_offset,
            refr_tm_offset,
            sample_offset,
            sample_size: cfg.sample_size,
            gm_identity_offset,
            smp_cnt: 0,
            smp_cnt_limit: cfg.smp_cnt_limit,
        });
    }

    let written = bm.len();
    if written > buf.len() {
        return Err(SvError::PduOverflow);
    }
    buf[..written].copy_from_slice(&bm);

    Ok((templates, written))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::{decode_sav_pdu, SmpSynch};
    use std::num::NonZeroU16;

    const SRC_MAC: [u8; 6] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];

    fn build_single_asdu_publisher(sample_size: usize) -> (SvPublisher, AsduHandle) {
        let mut builder = SvPublisherBuilder::new(SRC_MAC);
        let h = builder
            .add_asdu("TESTLD/LLN0$SV$sv1", None::<String>, 1, sample_size)
            .unwrap();
        let pub_ = builder.setup_complete().unwrap();
        (pub_, h)
    }

    #[test]
    fn builder_add_1_asdu_ok() {
        let (pub_, _) = build_single_asdu_publisher(64);
        assert_eq!(pub_.asdu_count(), 1);
        assert_eq!(pub_.no_asdu(), 1);
    }

    #[test]
    fn builder_add_2_asdus_ok() {
        let mut builder = SvPublisherBuilder::new(SRC_MAC);
        let _h0 = builder.add_asdu("sv1", None::<String>, 1, 64).unwrap();
        let _h1 = builder.add_asdu("sv2", None::<String>, 1, 64).unwrap();
        let pub_ = builder.setup_complete().unwrap();
        assert_eq!(pub_.asdu_count(), 2);
    }

    #[test]
    fn builder_add_4_asdus_ok() {
        let mut builder = SvPublisherBuilder::new(SRC_MAC);
        for i in 0..4 {
            builder
                .add_asdu(format!("sv{}", i), None::<String>, 1, 64)
                .unwrap();
        }
        let pub_ = builder.setup_complete().unwrap();
        assert_eq!(pub_.asdu_count(), 4);
    }

    #[test]
    fn builder_add_10_asdus_ok() {
        let mut builder = SvPublisherBuilder::new(SRC_MAC);
        for i in 0..10 {
            builder
                .add_asdu(format!("sv{}", i), None::<String>, 1, 8)
                .unwrap();
        }
        let pub_ = builder.setup_complete().unwrap();
        assert_eq!(pub_.asdu_count(), 10);
    }

    #[test]
    fn builder_add_11_asdus_err() {
        let mut builder = SvPublisherBuilder::new(SRC_MAC);
        for i in 0..10 {
            builder
                .add_asdu(format!("sv{}", i), None::<String>, 1, 8)
                .unwrap();
        }
        let result = builder.add_asdu("sv10", None::<String>, 1, 8);
        assert!(
            matches!(result, Err(SvError::TooManyAsdus(11))),
            "the eleventh add_asdu returns toomanyasdus, got {:?}",
            result
        );
    }

    /// The svID bound is inclusive: an identifier of exactly `SV_STRING_MAX_LEN`
    /// bytes is accepted and reaches the frame.
    #[test]
    fn builder_sv_id_at_the_limit_ok() {
        let sv_id = "A".repeat(SV_STRING_MAX_LEN);
        let mut builder = SvPublisherBuilder::new(SRC_MAC);
        builder
            .add_asdu(sv_id.clone(), None::<String>, 1, 8)
            .expect("an svid at the limit is accepted");
        let publisher = builder.setup_complete().unwrap();
        let pdu = decode_sav_pdu(&publisher.frame_bytes()[crate::frame::SV_HEADER_NO_VLAN..])
            .expect("the frame decodes");
        assert_eq!(pdu.asdus[0].sv_id, sv_id);
    }

    /// An svID past `SV_STRING_MAX_LEN` is refused at configuration time, so a
    /// publisher never emits a stream identifier a subscriber must reject.
    #[test]
    fn builder_sv_id_too_long_err() {
        let mut builder = SvPublisherBuilder::new(SRC_MAC);
        let result = builder.add_asdu("A".repeat(SV_STRING_MAX_LEN + 1), None::<String>, 1, 8);
        assert!(
            matches!(result, Err(SvError::SvIdTooLong(130))),
            "an over-long svid returns svidtoolong, got {:?}",
            result
        );
        assert_eq!(
            builder.setup_complete().unwrap_err(),
            SvError::NoAsdus,
            "the refused asdu is not recorded"
        );
    }

    /// The datSet bound is inclusive: a reference of exactly
    /// `SV_STRING_MAX_LEN` bytes is accepted and reaches the frame.
    #[test]
    fn builder_dat_set_at_the_limit_ok() {
        let dat_set = "D".repeat(SV_STRING_MAX_LEN);
        let mut builder = SvPublisherBuilder::new(SRC_MAC);
        builder
            .add_asdu("sv1", Some(dat_set.clone()), 1, 8)
            .expect("a datset at the limit is accepted");
        let publisher = builder.setup_complete().unwrap();
        let pdu = decode_sav_pdu(&publisher.frame_bytes()[crate::frame::SV_HEADER_NO_VLAN..])
            .expect("the frame decodes");
        assert_eq!(pdu.asdus[0].dat_set.as_deref(), Some(dat_set.as_str()));
    }

    /// A datSet past `SV_STRING_MAX_LEN` is refused at configuration time, so
    /// a publisher never emits a reference a subscriber must reject.
    #[test]
    fn builder_dat_set_too_long_err() {
        let mut builder = SvPublisherBuilder::new(SRC_MAC);
        let result = builder.add_asdu("sv1", Some("D".repeat(SV_STRING_MAX_LEN + 1)), 1, 8);
        assert!(
            matches!(result, Err(SvError::DatSetTooLong(130))),
            "an over-long datset returns datsettoolong, got {:?}",
            result
        );
        assert_eq!(
            builder.setup_complete().unwrap_err(),
            SvError::NoAsdus,
            "the refused asdu is not recorded"
        );
    }

    #[test]
    fn frame_bytes_decode_roundtrip_single() {
        let sample_data = vec![0xABu8; 64];
        let (mut pub_, h) = build_single_asdu_publisher(64);

        pub_.set_sample(h, &sample_data).unwrap();
        pub_.set_smp_cnt(h, 42).unwrap();
        pub_.set_smp_synch(h, SmpSynch::GlobalClock).unwrap();

        let bytes = pub_.frame_bytes();
        // The PDU starts after the untagged 22-byte header.
        let pdu_bytes = &bytes[SV_HEADER_NO_VLAN..];
        let pdu = decode_sav_pdu(pdu_bytes).unwrap();

        assert_eq!(pdu.asdus.len(), 1);
        assert_eq!(pdu.asdus[0].smp_cnt, 42);
        assert_eq!(pdu.asdus[0].smp_synch, SmpSynch::GlobalClock);
        assert_eq!(pdu.asdus[0].sample, sample_data);
    }

    #[test]
    fn smp_cnt_none_wrap_at_65535() {
        let mut builder = SvPublisherBuilder::new(SRC_MAC);
        let h = builder.add_asdu("sv1", None::<String>, 1, 8).unwrap();
        let mut pub_ = builder.setup_complete().unwrap();

        pub_.set_smp_cnt(h, 65535).unwrap();
        pub_.increase_smp_cnt(h).unwrap();
        assert_eq!(pub_.get_smp_cnt(h).unwrap(), 0, "65535 wraps to 0");
    }

    #[test]
    fn smp_cnt_limit_80_wrap() {
        let mut builder = SvPublisherBuilder::new(SRC_MAC);
        let h = builder.add_asdu("sv1", None::<String>, 1, 8).unwrap();
        builder
            .set_smp_cnt_limit(h, Some(NonZeroU16::new(80).unwrap()))
            .unwrap();
        let mut pub_ = builder.setup_complete().unwrap();

        pub_.set_smp_cnt(h, 79).unwrap();
        pub_.increase_smp_cnt(h).unwrap();
        assert_eq!(
            pub_.get_smp_cnt(h).unwrap(),
            0,
            "79 wraps to 0 at a limit of 80"
        );
    }

    #[test]
    fn smp_cnt_limit_4000_wrap() {
        let mut builder = SvPublisherBuilder::new(SRC_MAC);
        let h = builder.add_asdu("sv1", None::<String>, 1, 8).unwrap();
        builder
            .set_smp_cnt_limit(h, Some(NonZeroU16::new(4000).unwrap()))
            .unwrap();
        let mut pub_ = builder.setup_complete().unwrap();

        pub_.set_smp_cnt(h, 3999).unwrap();
        pub_.increase_smp_cnt(h).unwrap();
        assert_eq!(
            pub_.get_smp_cnt(h).unwrap(),
            0,
            "3999 wraps to 0 at a limit of 4000"
        );

        // A mid-range value must not wrap.
        pub_.set_smp_cnt(h, 0).unwrap();
        pub_.increase_smp_cnt(h).unwrap();
        assert_eq!(pub_.get_smp_cnt(h).unwrap(), 1);
    }

    #[test]
    fn increase_smp_cnt_100_consecutive() {
        let (mut pub_, h) = build_single_asdu_publisher(8);

        for expected in 1u16..=100 {
            pub_.increase_smp_cnt(h).unwrap();
            let cnt = pub_.get_smp_cnt(h).unwrap();
            assert_eq!(
                cnt, expected,
                "smpcnt is {1} after {0} increments",
                expected, expected
            );
        }

        let bytes = pub_.frame_bytes();
        let pdu = decode_sav_pdu(&bytes[SV_HEADER_NO_VLAN..]).unwrap();
        assert_eq!(pdu.asdus[0].smp_cnt, 100);
    }

    #[test]
    fn gm_identity_post_setup_write() {
        let mut builder = SvPublisherBuilder::new(SRC_MAC);
        let h = builder.add_asdu("sv1", None::<String>, 1, 8).unwrap();
        let gm_initial = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        builder.set_gm_identity(h, gm_initial).unwrap();
        let mut pub_ = builder.setup_complete().unwrap();

        let pdu1 = decode_sav_pdu(&pub_.frame_bytes()[SV_HEADER_NO_VLAN..]).unwrap();
        assert_eq!(pdu1.asdus[0].gm_identity, Some(gm_initial));

        // Overwrite after setup.
        let gm_new = [0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02];
        pub_.set_gm_identity(h, gm_new).unwrap();
        let pdu2 = decode_sav_pdu(&pub_.frame_bytes()[SV_HEADER_NO_VLAN..]).unwrap();
        assert_eq!(pdu2.asdus[0].gm_identity, Some(gm_new));
    }

    #[test]
    fn gm_identity_not_enabled_err() {
        let (mut pub_, h) = build_single_asdu_publisher(8);
        let result = pub_.set_gm_identity(h, [0u8; 8]);
        assert!(
            matches!(result, Err(SvError::GmIdentityNotEnabled)),
            "an asdu without gmidentity reports gmidentitynotenabled"
        );
    }

    #[test]
    fn refr_tm_set_and_decode() {
        let mut builder = SvPublisherBuilder::new(SRC_MAC);
        let h = builder.add_asdu("sv1", None::<String>, 1, 8).unwrap();
        builder.enable_refr_tm(h).unwrap();
        let mut pub_ = builder.setup_complete().unwrap();

        let ts = [0x01u8, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        pub_.set_refr_tm(h, ts).unwrap();

        let pdu = decode_sav_pdu(&pub_.frame_bytes()[SV_HEADER_NO_VLAN..]).unwrap();
        assert_eq!(pdu.asdus[0].refr_tm, Some(ts));
    }

    #[test]
    fn refr_tm_not_enabled_err() {
        let (mut pub_, h) = build_single_asdu_publisher(8);
        let result = pub_.set_refr_tm(h, [0u8; 8]);
        assert!(matches!(result, Err(SvError::RefrTmNotEnabled)));
    }

    #[test]
    fn multi_asdu_frame_decode() {
        let mut builder = SvPublisherBuilder::new(SRC_MAC);
        let h0 = builder.add_asdu("sv0", None::<String>, 1, 64).unwrap();
        let h1 = builder.add_asdu("sv1", None::<String>, 1, 64).unwrap();
        let mut pub_ = builder.setup_complete().unwrap();

        let sample0 = vec![0xAAu8; 64];
        let sample1 = vec![0xBBu8; 64];
        pub_.set_sample(h0, &sample0).unwrap();
        pub_.set_sample(h1, &sample1).unwrap();
        pub_.set_smp_cnt(h0, 100).unwrap();
        pub_.set_smp_cnt(h1, 200).unwrap();

        let bytes = pub_.frame_bytes();
        let pdu = decode_sav_pdu(&bytes[SV_HEADER_NO_VLAN..]).unwrap();

        assert_eq!(pdu.asdus.len(), 2);
        assert_eq!(pdu.asdus[0].sample, sample0);
        assert_eq!(pdu.asdus[1].sample, sample1);
        assert_eq!(pdu.asdus[0].smp_cnt, 100);
        assert_eq!(pdu.asdus[1].smp_cnt, 200);
    }

    #[test]
    fn sample_size_mismatch_err() {
        let (mut pub_, h) = build_single_asdu_publisher(64);
        let wrong = vec![0u8; 8]; // the asdu expects 64
        let result = pub_.set_sample(h, &wrong);
        assert!(matches!(
            result,
            Err(SvError::SampleSizeMismatch {
                expected: 64,
                actual: 8
            })
        ));
    }

    #[test]
    fn invalid_handle_err() {
        let (mut pub_, _) = build_single_asdu_publisher(8);
        let bad = AsduHandle(99);
        assert!(matches!(
            pub_.set_smp_cnt(bad, 0),
            Err(SvError::InvalidAsduHandle(99))
        ));
        assert!(matches!(
            pub_.set_sample(bad, &[]),
            Err(SvError::InvalidAsduHandle(99))
        ));
    }

    #[test]
    fn smp_synch_hot_path_encode_decode() {
        let (mut pub_, h) = build_single_asdu_publisher(8);
        pub_.set_smp_synch(h, SmpSynch::GlobalClock).unwrap();
        let pdu = decode_sav_pdu(&pub_.frame_bytes()[SV_HEADER_NO_VLAN..]).unwrap();
        assert_eq!(pdu.asdus[0].smp_synch, SmpSynch::GlobalClock);

        pub_.set_smp_synch(h, SmpSynch::LocalIdentified(42))
            .unwrap();
        let pdu2 = decode_sav_pdu(&pub_.frame_bytes()[SV_HEADER_NO_VLAN..]).unwrap();
        assert_eq!(pdu2.asdus[0].smp_synch, SmpSynch::LocalIdentified(42));
    }

    #[test]
    fn no_asdu_zero_err() {
        let builder = SvPublisherBuilder::new(SRC_MAC);
        let result = builder.setup_complete();
        assert!(matches!(result, Err(SvError::NoAsdus)));
    }

    #[test]
    fn smp_cnt_in_buffer_correct_after_increase() {
        let (mut pub_, h) = build_single_asdu_publisher(8);
        for _ in 0..50 {
            pub_.increase_smp_cnt(h).unwrap();
        }
        let pdu = decode_sav_pdu(&pub_.frame_bytes()[SV_HEADER_NO_VLAN..]).unwrap();
        assert_eq!(pdu.asdus[0].smp_cnt, 50);
    }
}
