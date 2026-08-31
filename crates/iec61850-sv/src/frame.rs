//! Sampled Values Ethernet frame layer per IEC 61850-9-2.
//!
//! `SvFrame` owns a complete Ethernet frame: the MAC header, the optional
//! 802.1Q tag, the SV application header (APPID, Length, two reserved fields),
//! and the BER-encoded savPdu.
//!
//! ## Wire format
//!
//! ```text
//! Without VLAN (22-byte header):
//!   [0..6]   Dst MAC
//!   [6..12]  Src MAC
//!   [12..14] EtherType = 0x88BA
//!   [14..16] APPID (big-endian u16, 0x4000 by default)
//!   [16..18] Length (8 header bytes plus the savPdu length)
//!   [18..20] Reserved1 = 0x0000
//!   [20..22] Reserved2 = 0x0000
//!   [22..]   savPdu (BER)
//!
//! With VLAN (26-byte header):
//!   [0..6]   Dst MAC
//!   [6..12]  Src MAC
//!   [12..14] TPID = 0x8100 (802.1Q)
//!   [14]     TCI[0] = priority(3b)<<5 | DEI=0 | vlan_id>>8
//!   [15]     TCI[1] = vlan_id & 0xFF
//!   [16..18] EtherType = 0x88BA
//!   [18..20] APPID
//!   [20..22] Length
//!   [22..24] Reserved1
//!   [24..26] Reserved2
//!   [26..]   savPdu (BER)
//! ```

use bytes::BytesMut;

use crate::error::SvError;

/// EtherType assigned to Sampled Values.
pub const SV_ETHER_TYPE: u16 = 0x88BA;

/// 802.1Q tag protocol identifier.
const VLAN_TPID: u16 = 0x8100;

/// Default destination MAC address, per IEC 61850-9-2 §8.3.
///
/// IEC 61850-9-2 assigns Sampled Values the multicast range
/// 01:0C:CD:04:xx:xx, distinct from the GOOSE range 01:0C:CD:01:xx:xx.
///
/// Interoperability hazard: some devices in the field are configured with
/// 01:0C:CD:01:00:01, which is inside the GOOSE range and does not conform to
/// IEC 61850-9-2. A subscriber that filters on the assigned SV range will not
/// see such a stream.
pub const SV_DEFAULT_DST_MAC: [u8; 6] = [0x01, 0x0C, 0xCD, 0x04, 0x00, 0x00];

/// Default APPID for Sampled Values, per IEC 61850-9-2 §8.4.
pub const SV_DEFAULT_APPID: u16 = 0x4000;

/// Default VLAN priority for Sampled Values, per IEC 61850-9-2 §8.5.
const SV_DEFAULT_VLAN_PRIORITY: u8 = 4;

/// Combined Ethernet and SV header size without a VLAN tag.
pub const SV_HEADER_NO_VLAN: usize = 22;

/// Combined Ethernet and SV header size with a VLAN tag.
pub const SV_HEADER_WITH_VLAN: usize = 26;

/// Size of the SV application header: APPID, Length, and two reserved fields.
pub const SV_APP_HEADER_SIZE: usize = 8;

/// Smallest valid SV frame, an untagged frame with an empty APDU.
pub const SV_MIN_FRAME_SIZE: usize = 22;

/// VLAN priority code point, a 3-bit value in the range 0-7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlanPriority(u8);

impl VlanPriority {
    /// Creates a priority, rejecting values above 7.
    ///
    /// # Errors
    ///
    /// Returns `VlanPriorityOutOfRange` when `p` exceeds 7.
    pub fn new(p: u8) -> Result<Self, SvError> {
        if p > 7 {
            return Err(SvError::VlanPriorityOutOfRange(p));
        }
        Ok(VlanPriority(p))
    }

    /// Returns the priority value, 0-7.
    pub fn value(self) -> u8 {
        self.0
    }
}

impl Default for VlanPriority {
    fn default() -> Self {
        VlanPriority(SV_DEFAULT_VLAN_PRIORITY)
    }
}

/// 802.1Q VLAN tag fields carried in an SV frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VlanTag {
    /// Priority code point, 0-7.
    pub priority: VlanPriority,
    /// VLAN identifier, 0-4095.
    pub vlan_id: u16,
}

/// Ethernet and SV header: MAC addresses, optional VLAN tag, EtherType, APPID,
/// and Length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvFrameHeader {
    /// Destination MAC address.
    pub dst_mac: [u8; 6],
    /// Source MAC address.
    pub src_mac: [u8; 6],
    /// Optional 802.1Q VLAN tag.
    pub vlan: Option<VlanTag>,
    /// Application identifier.
    pub app_id: u16,
    /// Length from the APPID field through the end of the PDU: the 8 header
    /// bytes plus the savPdu. `SvFrame::encode` recomputes it.
    pub length: u16,
}

/// A complete SV Ethernet frame: header plus savPdu bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct SvFrame {
    /// Frame header.
    pub header: SvFrameHeader,
    /// BER encoding of the savPdu, starting at the outer 0x60 tag.
    pub pdu_bytes: Vec<u8>,
}

impl SvFrame {
    /// Returns the header size, with or without a VLAN tag.
    pub fn header_size(with_vlan: bool) -> usize {
        if with_vlan {
            SV_HEADER_WITH_VLAN
        } else {
            SV_HEADER_NO_VLAN
        }
    }

    /// Appends the complete Ethernet frame to `buf`.
    ///
    /// The Length field is recomputed from `pdu_bytes`; the value in `header`
    /// is ignored.
    ///
    /// # Errors
    ///
    /// Returns `PduOverflow` when the resulting length does not fit a `u16`.
    pub fn encode(&self, buf: &mut BytesMut) -> Result<(), SvError> {
        let pdu_len = self.pdu_bytes.len();
        let length_val = SV_APP_HEADER_SIZE + pdu_len;
        if length_val > u16::MAX as usize {
            return Err(SvError::PduOverflow);
        }

        buf.extend_from_slice(&self.header.dst_mac);
        buf.extend_from_slice(&self.header.src_mac);

        if let Some(vlan) = self.header.vlan {
            buf.extend_from_slice(&VLAN_TPID.to_be_bytes());
            // TCI holds the priority in bits 15:13 and the VLAN ID in bits
            // 11:0; the DEI bit is always cleared.
            let tci: u16 = ((vlan.priority.value() as u16) << 13) | (vlan.vlan_id & 0x0FFF);
            buf.extend_from_slice(&tci.to_be_bytes());
        }

        buf.extend_from_slice(&SV_ETHER_TYPE.to_be_bytes());

        buf.extend_from_slice(&self.header.app_id.to_be_bytes());

        buf.extend_from_slice(&(length_val as u16).to_be_bytes());

        // Reserved1 and Reserved2, transmitted as zero.
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        buf.extend_from_slice(&self.pdu_bytes);

        Ok(())
    }

    /// Decodes an Ethernet frame into a header and the savPdu bytes.
    ///
    /// Tagged frames are bounds-checked against the 26-byte header, not only
    /// against the 22-byte untagged minimum.
    ///
    /// # Errors
    ///
    /// - `EthernetFrameTooShort` when a header field is not fully present.
    /// - `WrongEtherType` when the EtherType is not 0x88BA.
    /// - `InvalidHeaderLength` when Length is below the 8-byte header.
    /// - `TruncatedInput` when Length exceeds the bytes actually present.
    /// - `VlanPriorityOutOfRange` is unreachable because the decoded priority
    ///   is masked to 3 bits.
    pub fn decode(data: &[u8]) -> Result<Self, SvError> {
        if data.len() < SV_MIN_FRAME_SIZE {
            return Err(SvError::EthernetFrameTooShort(data.len()));
        }

        let dst_mac: [u8; 6] = data[0..6].try_into().unwrap();
        let src_mac: [u8; 6] = data[6..12].try_into().unwrap();

        let mut pos = 12usize;

        // A TPID in the EtherType position means an 802.1Q tag follows.
        let ether_type_raw = u16::from_be_bytes([data[pos], data[pos + 1]]);

        let (vlan, ether_type) = if ether_type_raw == VLAN_TPID {
            if data.len() < SV_HEADER_WITH_VLAN {
                return Err(SvError::EthernetFrameTooShort(data.len()));
            }
            pos += 2;
            let tci = u16::from_be_bytes([data[pos], data[pos + 1]]);
            pos += 2;
            let priority_val = ((tci >> 13) & 0x07) as u8;
            let vlan_id = tci & 0x0FFF;
            let priority = VlanPriority::new(priority_val)?;
            let vlan_tag = VlanTag { priority, vlan_id };
            let et = u16::from_be_bytes([data[pos], data[pos + 1]]);
            pos += 2;
            (Some(vlan_tag), et)
        } else {
            pos += 2;
            (None, ether_type_raw)
        };

        if ether_type != SV_ETHER_TYPE {
            return Err(SvError::WrongEtherType(ether_type));
        }

        if pos + 2 > data.len() {
            return Err(SvError::EthernetFrameTooShort(data.len()));
        }
        let app_id = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        if pos + 2 > data.len() {
            return Err(SvError::EthernetFrameTooShort(data.len()));
        }
        let length = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        if length < SV_APP_HEADER_SIZE as u16 {
            tracing::warn!(
                "sv header length field {} is below the 8 byte header",
                length
            );
            return Err(SvError::InvalidHeaderLength(length));
        }

        // Reserved1 and Reserved2 are not interpreted.
        if pos + 4 > data.len() {
            return Err(SvError::EthernetFrameTooShort(data.len()));
        }
        pos += 4;

        // The Length field is attacker-controlled; the APDU must be present.
        let apdu_length = (length as usize) - SV_APP_HEADER_SIZE;
        let pdu_end = pos + apdu_length;
        if pdu_end > data.len() {
            return Err(SvError::TruncatedInput {
                needed: pdu_end,
                available: data.len(),
            });
        }

        let pdu_bytes = data[pos..pdu_end].to_vec();

        Ok(SvFrame {
            header: SvFrameHeader {
                dst_mac,
                src_mac,
                vlan,
                app_id,
                length,
            },
            pdu_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_frame(vlan: Option<VlanTag>, pdu_bytes: Vec<u8>) -> SvFrame {
        let pdu_len = pdu_bytes.len();
        SvFrame {
            header: SvFrameHeader {
                dst_mac: SV_DEFAULT_DST_MAC,
                src_mac: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
                vlan,
                app_id: SV_DEFAULT_APPID,
                length: (SV_APP_HEADER_SIZE + pdu_len) as u16,
            },
            pdu_bytes,
        }
    }

    #[test]
    fn frame_no_vlan_roundtrip() {
        let frame = make_frame(None, vec![0x60, 0x00]);
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), SV_HEADER_NO_VLAN + 2);
        assert_eq!(u16::from_be_bytes([buf[12], buf[13]]), SV_ETHER_TYPE);
        assert_eq!(u16::from_be_bytes([buf[14], buf[15]]), SV_DEFAULT_APPID);
        let decoded = SvFrame::decode(&buf).unwrap();
        assert_eq!(decoded.header.dst_mac, SV_DEFAULT_DST_MAC);
        assert_eq!(decoded.header.vlan, None);
        assert_eq!(decoded.pdu_bytes, vec![0x60, 0x00]);
    }

    #[test]
    fn frame_with_vlan_roundtrip() {
        let vlan = VlanTag {
            priority: VlanPriority::new(4).unwrap(),
            vlan_id: 100,
        };
        let frame = make_frame(Some(vlan), vec![0x60, 0x03, 0x80, 0x01, 0x01]);
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), SV_HEADER_WITH_VLAN + 5);
        assert_eq!(u16::from_be_bytes([buf[12], buf[13]]), VLAN_TPID);
        assert_eq!(u16::from_be_bytes([buf[16], buf[17]]), SV_ETHER_TYPE);
        let decoded = SvFrame::decode(&buf).unwrap();
        assert_eq!(decoded.header.vlan, Some(vlan));
        assert_eq!(decoded.header.dst_mac, SV_DEFAULT_DST_MAC);
        assert_eq!(decoded.pdu_bytes, vec![0x60, 0x03, 0x80, 0x01, 0x01]);
    }

    #[test]
    fn frame_wrong_ether_type_rejected() {
        let mut buf = BytesMut::new();
        // A frame carrying the GOOSE EtherType.
        buf.extend_from_slice(&SV_DEFAULT_DST_MAC);
        buf.extend_from_slice(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
        buf.extend_from_slice(&0x88B8u16.to_be_bytes());
        buf.extend_from_slice(&SV_DEFAULT_APPID.to_be_bytes());
        buf.extend_from_slice(&8u16.to_be_bytes()); // length = 8
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // reserved
        let result = SvFrame::decode(&buf);
        assert!(matches!(result, Err(SvError::WrongEtherType(0x88B8))));
    }

    #[test]
    fn frame_too_short_rejected() {
        let result = SvFrame::decode(&[0x01, 0x02, 0x03]);
        assert!(matches!(result, Err(SvError::EthernetFrameTooShort(3))));
    }

    #[test]
    fn frame_invalid_header_length_rejected() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&SV_DEFAULT_DST_MAC);
        buf.extend_from_slice(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
        buf.extend_from_slice(&SV_ETHER_TYPE.to_be_bytes());
        buf.extend_from_slice(&SV_DEFAULT_APPID.to_be_bytes());
        buf.extend_from_slice(&7u16.to_be_bytes()); // below the 8 byte header
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        let result = SvFrame::decode(&buf);
        assert!(matches!(result, Err(SvError::InvalidHeaderLength(7))));
    }

    #[test]
    fn default_dst_mac_in_sv_range() {
        // The default belongs to the SV range 01:0C:CD:04:xx:xx.
        assert_eq!(&SV_DEFAULT_DST_MAC[..4], &[0x01, 0x0C, 0xCD, 0x04]);
        // It must not fall in the GOOSE range 01:0C:CD:01:xx:xx.
        assert_ne!(SV_DEFAULT_DST_MAC[3], 0x01);
    }

    #[test]
    fn vlan_priority_range_check() {
        assert!(VlanPriority::new(0).is_ok());
        assert!(VlanPriority::new(7).is_ok());
        assert!(matches!(
            VlanPriority::new(8),
            Err(SvError::VlanPriorityOutOfRange(8))
        ));
    }
}
