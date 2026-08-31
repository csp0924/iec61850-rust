//! GOOSE Ethernet frame layer per IEC 61850-8-1 Annex A.
//!
//! `GooseFrame` owns a complete Ethernet frame: the MAC header, the optional
//! 802.1Q tag, the GOOSE header (APPID, Length, two reserved fields), and the
//! BER-encoded IECGoosePdu. `encode` and `decode` are the only wire-format
//! entry points used by the publisher and the receiver.
//!
//! ## Wire format
//!
//! ```text
//! Without VLAN (14-byte Ethernet header):
//!   [0..6]   Dst MAC
//!   [6..12]  Src MAC
//!   [12..14] EtherType = 0x88B8
//!   [14..16] APPID
//!   [16..18] Length (APPID through end of PDU, including these 8 bytes)
//!   [18..20] Reserved1 = 0x0000
//!   [20..22] Reserved2 = 0x0000
//!   [22..]   IECGoosePdu
//!
//! With VLAN (18-byte Ethernet header):
//!   [0..6]   Dst MAC
//!   [6..12]  Src MAC
//!   [12..14] TPID = 0x8100
//!   [14]     TCI[0] = priority(3b)<<5 | DEI=0 | vlan_id>>8
//!   [15]     TCI[1] = vlan_id & 0xFF
//!   [16..18] EtherType = 0x88B8
//!   [18..20] APPID
//!   [20..22] Length
//!   [22..24] Reserved1
//!   [24..26] Reserved2
//!   [26..]   IECGoosePdu
//! ```

use bytes::BytesMut;

use crate::error::GooseError;

/// EtherType assigned to GOOSE.
pub const GOOSE_ETHER_TYPE: u16 = 0x88B8;

/// 802.1Q tag protocol identifier.
const VLAN_TPID: u16 = 0x8100;

/// Ethernet header size without a VLAN tag.
const ETHERNET_HEADER_NO_VLAN: usize = 14;

/// Ethernet header size with a VLAN tag: 14 bytes plus the 4-byte tag.
const ETHERNET_HEADER_WITH_VLAN: usize = 18;

/// Size of APPID, Length, Reserved1, and Reserved2 together.
const GOOSE_HEADER_SIZE: usize = 8;

/// VLAN priority code point, a 3-bit value in the range 0-7.
///
/// The constructor rejects out-of-range values so that `priority << 5` can
/// never overflow into the DEI and VLAN ID bits of the TCI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlanPriority(u8);

impl VlanPriority {
    /// Creates a priority, rejecting values above 7.
    ///
    /// # Errors
    ///
    /// Returns `VlanPriorityOutOfRange` when `p` exceeds 7.
    pub fn new(p: u8) -> Result<Self, GooseError> {
        if p > 7 {
            return Err(GooseError::VlanPriorityOutOfRange(p));
        }
        Ok(VlanPriority(p))
    }

    /// Returns the priority value, 0-7.
    pub fn value(self) -> u8 {
        self.0
    }
}

/// 802.1Q VLAN tag fields carried in a GOOSE frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlanTag {
    /// Priority code point, 0-7.
    pub priority: VlanPriority,
    /// VLAN identifier, 0-4095.
    pub vlan_id: u16,
}

/// Ethernet and GOOSE header: MAC addresses, optional VLAN tag, EtherType,
/// APPID, and Length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GooseFrameHeader {
    /// Destination MAC address.
    pub dst_mac: [u8; 6],
    /// Source MAC address.
    pub src_mac: [u8; 6],
    /// Optional 802.1Q VLAN tag.
    pub vlan: Option<VlanTag>,
    /// Application identifier.
    pub app_id: u16,
    /// Length from the APPID field through the end of the PDU, including the
    /// 8 header bytes themselves.
    pub length: u16,
}

/// A complete GOOSE Ethernet frame: header plus PDU payload bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct GooseFrame {
    /// Frame header.
    pub header: GooseFrameHeader,
    /// BER encoding of the IECGoosePdu, excluding the Ethernet and GOOSE
    /// headers.
    pub pdu_bytes: Vec<u8>,
}

impl GooseFrame {
    /// Creates a frame from a header and the encoded PDU bytes.
    pub fn new(header: GooseFrameHeader, pdu_bytes: Vec<u8>) -> Self {
        GooseFrame { header, pdu_bytes }
    }

    /// Appends the complete Ethernet frame to `buf` and returns the number of
    /// bytes written.
    ///
    /// The Length field is recomputed from `pdu_bytes`; the value carried in
    /// `header` is ignored.
    pub fn encode(&self, buf: &mut BytesMut) -> Result<usize, GooseError> {
        let start = buf.len();
        let hdr = &self.header;

        buf.extend_from_slice(&hdr.dst_mac);
        buf.extend_from_slice(&hdr.src_mac);

        if let Some(vlan) = &hdr.vlan {
            buf.extend_from_slice(&VLAN_TPID.to_be_bytes());
            // TCI packs priority into bits 7:5 and the VLAN ID into bits 11:0.
            // The DEI bit is always cleared; IEC 61850-8-1 §A.4 does not use it.
            let tci0 = (vlan.priority.value() << 5) | ((vlan.vlan_id >> 8) as u8 & 0x0F);
            let tci1 = (vlan.vlan_id & 0xFF) as u8;
            buf.extend_from_slice(&[tci0, tci1]);
        }

        buf.extend_from_slice(&GOOSE_ETHER_TYPE.to_be_bytes());
        buf.extend_from_slice(&hdr.app_id.to_be_bytes());

        // Length counts the 8 GOOSE header bytes as well as the PDU.
        let length = (self.pdu_bytes.len() + GOOSE_HEADER_SIZE) as u16;
        buf.extend_from_slice(&length.to_be_bytes());

        // Reserved1 and Reserved2, 2 bytes each, transmitted as zero.
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        buf.extend_from_slice(&self.pdu_bytes);

        Ok(buf.len() - start)
    }

    /// Decodes an Ethernet frame into a header and the PDU bytes.
    ///
    /// Every field is bounds-checked against the actual buffer length before it
    /// is read, so a frame whose Length field overstates the payload is
    /// rejected instead of read past.
    ///
    /// # Errors
    ///
    /// - `EthernetFrameTooShort` when the buffer is under 14 bytes, under 18
    ///   bytes with a VLAN tag, when Length is below 8, or when Length exceeds
    ///   the bytes actually present.
    /// - `WrongEtherType` when the EtherType is not 0x88B8.
    pub fn decode(buf: &[u8]) -> Result<GooseFrame, GooseError> {
        let total_len = buf.len();

        // 6 destination + 6 source + 2 EtherType bytes.
        if total_len < ETHERNET_HEADER_NO_VLAN {
            return Err(GooseError::EthernetFrameTooShort);
        }

        let dst_mac: [u8; 6] = buf[0..6].try_into().unwrap();
        let src_mac: [u8; 6] = buf[6..12].try_into().unwrap();

        let mut pos = 12usize;

        // A TPID in the EtherType position means an 802.1Q tag follows.
        let ethertype_candidate = u16::from_be_bytes([buf[pos], buf[pos + 1]]);

        let vlan: Option<VlanTag>;
        if ethertype_candidate == VLAN_TPID {
            if total_len < ETHERNET_HEADER_WITH_VLAN {
                return Err(GooseError::EthernetFrameTooShort);
            }
            pos += 2;
            let tci0 = buf[pos];
            let tci1 = buf[pos + 1];
            pos += 2;

            // Priority occupies bits 7:5 of TCI[0]; shift before masking.
            let priority_raw = (tci0 >> 5) & 0x07;
            let priority = VlanPriority::new(priority_raw)?;
            // Bit 4 is DEI and is not retained.
            let vlan_id = ((tci0 as u16 & 0x0F) << 8) | (tci1 as u16);

            vlan = Some(VlanTag { priority, vlan_id });

            let et = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            if et != GOOSE_ETHER_TYPE {
                tracing::warn!("goose frame ethertype 0x{:04x}, expected 0x88b8", et);
                return Err(GooseError::WrongEtherType(et));
            }
            pos += 2;
        } else if ethertype_candidate == GOOSE_ETHER_TYPE {
            vlan = None;
            pos += 2;
        } else {
            tracing::warn!(
                "goose frame ethertype 0x{:04x}, expected 0x88b8",
                ethertype_candidate
            );
            return Err(GooseError::WrongEtherType(ethertype_candidate));
        }

        // APPID, Length, Reserved1, and Reserved2 follow.
        if total_len < pos + GOOSE_HEADER_SIZE {
            return Err(GooseError::EthernetFrameTooShort);
        }

        let app_id = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        pos += 2;

        let length = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        pos += 2;

        // Reserved1 and Reserved2 are not interpreted.
        pos += 4;

        let length_usize = length as usize;
        if length_usize < GOOSE_HEADER_SIZE {
            tracing::warn!(
                "goose length field {} is below the 8 byte header",
                length_usize
            );
            return Err(GooseError::EthernetFrameTooShort);
        }
        let apdu_length = length_usize - GOOSE_HEADER_SIZE;

        // IEC 61850-8-1 §A.3 bounds the payload by the Length field, which is
        // attacker-controlled, so the bytes it claims must be present in full
        // before the payload is sliced out.
        if pos + apdu_length > total_len {
            tracing::warn!(
                "goose frame is {} bytes but the length field needs {}",
                total_len,
                pos + apdu_length
            );
            return Err(GooseError::EthernetFrameTooShort);
        }

        let pdu_bytes = buf[pos..pos + apdu_length].to_vec();

        let header = GooseFrameHeader {
            dst_mac,
            src_mac,
            vlan,
            app_id,
            length,
        };

        Ok(GooseFrame { header, pdu_bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    fn sample_header_no_vlan() -> GooseFrameHeader {
        GooseFrameHeader {
            dst_mac: [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01],
            src_mac: [0x00, 0x50, 0xC2, 0x12, 0x34, 0x56],
            vlan: None,
            app_id: 0x0001,
            length: 0, // recomputed by encode
        }
    }

    fn sample_pdu_bytes() -> Vec<u8> {
        // Any non-empty PDU body; the frame layer does not decode it.
        vec![0x61, 0x03, 0x80, 0x01, 0x41]
    }

    #[test]
    fn encode_decode_no_vlan_round_trip() {
        let header = sample_header_no_vlan();
        let pdu = sample_pdu_bytes();
        let frame = GooseFrame::new(header.clone(), pdu.clone());

        let mut buf = BytesMut::new();
        let written = frame.encode(&mut buf).unwrap();
        assert_eq!(written, buf.len());

        let decoded = GooseFrame::decode(&buf).unwrap();
        assert_eq!(decoded.header.dst_mac, header.dst_mac);
        assert_eq!(decoded.header.src_mac, header.src_mac);
        assert!(decoded.header.vlan.is_none());
        assert_eq!(decoded.header.app_id, header.app_id);
        assert_eq!(decoded.pdu_bytes, pdu);
    }

    #[test]
    fn encode_decode_vlan_round_trip() {
        let priority = VlanPriority::new(4).unwrap();
        let mut header = sample_header_no_vlan();
        header.vlan = Some(VlanTag {
            priority,
            vlan_id: 100,
        });

        let pdu = sample_pdu_bytes();
        let frame = GooseFrame::new(header.clone(), pdu.clone());

        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        assert_eq!(buf[12], 0x81, "tpid high byte");
        assert_eq!(buf[13], 0x00, "tpid low byte");

        // priority=4, DEI=0, vlan_id=100 encodes as TCI = 0x80 0x64.
        assert_eq!(buf[14], 0x80, "tci[0]");
        assert_eq!(buf[15], 0x64, "tci[1]");

        assert_eq!(buf[16], 0x88, "ethertype high byte");
        assert_eq!(buf[17], 0xB8, "ethertype low byte");

        let decoded = GooseFrame::decode(&buf).unwrap();
        let vlan = decoded.header.vlan.unwrap();
        assert_eq!(vlan.priority.value(), 4);
        assert_eq!(vlan.vlan_id, 100);
        assert_eq!(decoded.pdu_bytes, pdu);
    }

    #[test]
    fn vlan_priority_decode_bit_fix() {
        // TCI[0] = 0xE0: priority bits 7:5 are 111 (7), DEI is 0, and the
        // upper nibble of the VLAN ID is 0.
        let mut frame_bytes = vec![
            0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01, // dst MAC
            0x00, 0x50, 0xC2, 0x12, 0x34, 0x56, // src MAC
            0x81, 0x00, // TPID
            0xE0, 0x00, // TCI[0] priority=7, DEI=0; TCI[1] vlan id low byte
            0x88, 0xB8, // EtherType
            0x00, 0x01, // APPID
            0x00, 0x0D, // Length = 8 header + 5 PDU
            0x00, 0x00, // Reserved1
            0x00, 0x00, // Reserved2
            0x61, 0x03, 0x80, 0x01, 0x41, // 5 PDU bytes
        ];

        let decoded = GooseFrame::decode(&frame_bytes).unwrap();
        let vlan = decoded.header.vlan.unwrap();
        assert_eq!(
            vlan.priority.value(),
            7,
            "priority comes from bits 7:5 of tci[0]"
        );

        // Setting the low nibble must not disturb the decoded priority.
        frame_bytes[14] = 0xE7; // priority=7, DEI=0, vlan id bits 11:8 = 7
        let decoded2 = GooseFrame::decode(&frame_bytes).unwrap();
        let vlan2 = decoded2.header.vlan.unwrap();
        assert_eq!(vlan2.priority.value(), 7, "priority unchanged");
        assert_eq!(vlan2.vlan_id, 0x0700, "vlan id upper nibble decoded");
    }

    #[test]
    fn vlan_priority_new_rejects_out_of_range() {
        assert!(VlanPriority::new(7).is_ok());
        assert!(VlanPriority::new(0).is_ok());
        assert_eq!(
            VlanPriority::new(8),
            Err(GooseError::VlanPriorityOutOfRange(8))
        );
        assert_eq!(
            VlanPriority::new(255),
            Err(GooseError::VlanPriorityOutOfRange(255))
        );
    }

    #[test]
    fn reject_frame_too_short() {
        // One byte short of the minimum Ethernet header.
        let short = vec![0u8; 13];
        assert_eq!(
            GooseFrame::decode(&short),
            Err(GooseError::EthernetFrameTooShort)
        );

        // Full-length header carrying a non-GOOSE EtherType.
        let wrong_et = vec![
            0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01, // dst
            0x00, 0x50, 0xC2, 0x12, 0x34, 0x56, // src
            0x08, 0x00, // EtherType = IPv4
        ];
        assert_eq!(
            GooseFrame::decode(&wrong_et),
            Err(GooseError::WrongEtherType(0x0800))
        );
    }

    #[test]
    fn reject_wrong_ether_type() {
        let mut bytes = vec![0u8; 22];
        bytes[12] = 0x08;
        bytes[13] = 0x00; // IPv4
        assert!(matches!(
            GooseFrame::decode(&bytes),
            Err(GooseError::WrongEtherType(0x0800))
        ));
    }

    #[test]
    fn reject_length_exceeds_payload() {
        // Length claims 100 bytes while the frame holds only 22.
        let frame_bytes = vec![
            0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01, // dst
            0x00, 0x50, 0xC2, 0x12, 0x34, 0x56, // src
            0x88, 0xB8, // EtherType
            0x00, 0x01, // APPID
            0x00, 0x64, // Length = 100
            0x00, 0x00, // Reserved1
            0x00, 0x00, // Reserved2
        ];
        // apdu_length becomes 92 while no payload bytes are present.
        assert!(matches!(
            GooseFrame::decode(&frame_bytes),
            Err(GooseError::EthernetFrameTooShort)
        ));
    }

    #[test]
    fn length_field_calculation() {
        let header = sample_header_no_vlan();
        let pdu = vec![0x61; 50];
        let frame = GooseFrame::new(header, pdu);

        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        // Without a VLAN tag the Length field sits at offset 16.
        let length = u16::from_be_bytes([buf[16], buf[17]]);
        assert_eq!(
            length as usize,
            50 + GOOSE_HEADER_SIZE,
            "length covers the pdu plus the 8 header bytes"
        );
    }

    #[test]
    fn reject_vlan_frame_too_short() {
        // TPID present but one byte short of the 18-byte minimum.
        let mut bytes = vec![0u8; 17];
        bytes[12] = 0x81;
        bytes[13] = 0x00; // TPID = 0x8100
        assert_eq!(
            GooseFrame::decode(&bytes),
            Err(GooseError::EthernetFrameTooShort)
        );
    }

    #[test]
    fn apdu_length_calculation() {
        // Length = 8 is the minimum and yields an empty PDU.
        let frame_bytes = vec![
            0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01, 0x00, 0x50, 0xC2, 0x12, 0x34, 0x56, 0x88, 0xB8,
            0x00, 0x01, // APPID
            0x00, 0x08, // Length = 8
            0x00, 0x00, // Reserved1
            0x00, 0x00, // Reserved2
        ];
        let decoded = GooseFrame::decode(&frame_bytes).unwrap();
        assert!(
            decoded.pdu_bytes.is_empty(),
            "zero-length apdu yields empty pdu bytes"
        );
    }
}
