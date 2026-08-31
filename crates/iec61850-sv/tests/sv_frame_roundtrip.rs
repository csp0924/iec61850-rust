//! Integration tests for `SvFrame` Ethernet and SV header encoding.

use bytes::BytesMut;
use iec61850_sv::frame::{
    SvFrame, SvFrameHeader, VlanPriority, VlanTag, SV_APP_HEADER_SIZE, SV_DEFAULT_APPID,
    SV_DEFAULT_DST_MAC, SV_ETHER_TYPE, SV_HEADER_NO_VLAN, SV_HEADER_WITH_VLAN,
};
use iec61850_sv::SvError;

const SRC_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const APP_HDR: usize = SV_APP_HEADER_SIZE;

fn make_frame_no_vlan(pdu_bytes: Vec<u8>) -> SvFrame {
    let length = (APP_HDR + pdu_bytes.len()) as u16;
    SvFrame {
        header: SvFrameHeader {
            dst_mac: SV_DEFAULT_DST_MAC,
            src_mac: SRC_MAC,
            vlan: None,
            app_id: SV_DEFAULT_APPID,
            length,
        },
        pdu_bytes,
    }
}

fn make_frame_with_vlan(pdu_bytes: Vec<u8>, priority: u8, vlan_id: u16) -> SvFrame {
    let length = (APP_HDR + pdu_bytes.len()) as u16;
    SvFrame {
        header: SvFrameHeader {
            dst_mac: SV_DEFAULT_DST_MAC,
            src_mac: SRC_MAC,
            vlan: Some(VlanTag {
                priority: VlanPriority::new(priority).unwrap(),
                vlan_id,
            }),
            app_id: SV_DEFAULT_APPID,
            length,
        },
        pdu_bytes,
    }
}

#[test]
fn no_vlan_roundtrip() {
    let pdu_bytes = vec![0x60u8, 0x03, 0x80, 0x01, 0x01];
    let frame = make_frame_no_vlan(pdu_bytes.clone());

    let mut buf = BytesMut::new();
    frame.encode(&mut buf).unwrap();

    assert_eq!(buf.len(), SV_HEADER_NO_VLAN + pdu_bytes.len());

    assert_eq!(&buf[0..6], &SV_DEFAULT_DST_MAC);
    assert_eq!(&buf[6..12], &SRC_MAC);
    assert_eq!(
        u16::from_be_bytes([buf[12], buf[13]]),
        SV_ETHER_TYPE,
        "ethertype at offset 12"
    );
    assert_eq!(u16::from_be_bytes([buf[14], buf[15]]), SV_DEFAULT_APPID);
    let expected_len = (APP_HDR + pdu_bytes.len()) as u16;
    assert_eq!(u16::from_be_bytes([buf[16], buf[17]]), expected_len);
    assert_eq!(&buf[18..20], &[0x00, 0x00]);
    assert_eq!(&buf[20..22], &[0x00, 0x00]);
    assert_eq!(&buf[22..], &pdu_bytes[..]);

    let decoded = SvFrame::decode(&buf).unwrap();
    assert_eq!(decoded, frame);
    assert_eq!(decoded.header.vlan, None);
    assert_eq!(decoded.pdu_bytes, pdu_bytes);
}

#[test]
fn with_vlan_roundtrip() {
    let pdu_bytes = vec![0x60u8, 0x05, 0x80, 0x01, 0x02, 0x00, 0x00];
    let frame = make_frame_with_vlan(pdu_bytes.clone(), 4, 100);

    let mut buf = BytesMut::new();
    frame.encode(&mut buf).unwrap();

    assert_eq!(buf.len(), SV_HEADER_WITH_VLAN + pdu_bytes.len());

    assert_eq!(
        u16::from_be_bytes([buf[12], buf[13]]),
        0x8100u16,
        "tpid at offset 12"
    );
    // priority 4 and vlan id 100 encode as TCI 0x8064.
    let tci = u16::from_be_bytes([buf[14], buf[15]]);
    let decoded_priority = ((tci >> 13) & 0x07) as u8;
    let decoded_vlan_id = tci & 0x0FFF;
    assert_eq!(decoded_priority, 4, "priority from bits 15:13");
    assert_eq!(decoded_vlan_id, 100, "vlan id from bits 11:0");
    assert_eq!(u16::from_be_bytes([buf[16], buf[17]]), SV_ETHER_TYPE);
    assert_eq!(u16::from_be_bytes([buf[18], buf[19]]), SV_DEFAULT_APPID);

    let decoded = SvFrame::decode(&buf).unwrap();
    assert_eq!(decoded, frame);
    let vlan = decoded.header.vlan.unwrap();
    assert_eq!(vlan.priority.value(), 4);
    assert_eq!(vlan.vlan_id, 100);
    assert_eq!(decoded.pdu_bytes, pdu_bytes);
}

#[test]
fn default_dst_mac_sv_range() {
    // Sampled Values use the multicast range 01:0C:CD:04:xx:xx.
    assert_eq!(
        &SV_DEFAULT_DST_MAC[..4],
        &[0x01, 0x0C, 0xCD, 0x04],
        "default dst mac is in the sv range"
    );
    // The GOOSE range 01:0C:CD:01:xx:xx must not be used.
    assert_ne!(
        SV_DEFAULT_DST_MAC[3], 0x01,
        "default dst mac is not in the goose range"
    );
}

#[test]
fn wrong_ether_type_rejected() {
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&SV_DEFAULT_DST_MAC);
    buf.extend_from_slice(&SRC_MAC);
    buf.extend_from_slice(&0x88B8u16.to_be_bytes()); // GOOSE
    buf.extend_from_slice(&SV_DEFAULT_APPID.to_be_bytes());
    buf.extend_from_slice(&8u16.to_be_bytes());
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    let result = SvFrame::decode(&buf);
    assert!(
        matches!(result, Err(SvError::WrongEtherType(0x88B8))),
        "a foreign ethertype returns wrongethertype, got {:?}",
        result
    );
}

#[test]
fn frame_too_short_rejected() {
    let result = SvFrame::decode(&[0x01, 0x0C, 0xCD]);
    assert!(matches!(result, Err(SvError::EthernetFrameTooShort(3))));
}

#[test]
fn invalid_header_length_rejected() {
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&SV_DEFAULT_DST_MAC);
    buf.extend_from_slice(&SRC_MAC);
    buf.extend_from_slice(&SV_ETHER_TYPE.to_be_bytes());
    buf.extend_from_slice(&SV_DEFAULT_APPID.to_be_bytes());
    buf.extend_from_slice(&5u16.to_be_bytes()); // below the 8 byte header
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    let result = SvFrame::decode(&buf);
    assert!(
        matches!(result, Err(SvError::InvalidHeaderLength(5))),
        "a length below the header returns invalidheaderlength, got {:?}",
        result
    );
}

#[test]
fn vlan_priority_out_of_range() {
    let result = VlanPriority::new(8);
    assert!(matches!(result, Err(SvError::VlanPriorityOutOfRange(8))));

    let result = VlanPriority::new(255);
    assert!(matches!(result, Err(SvError::VlanPriorityOutOfRange(255))));
}

#[test]
fn vlan_priority_boundary_valid() {
    assert!(VlanPriority::new(0).is_ok());
    assert!(VlanPriority::new(7).is_ok());
    assert_eq!(VlanPriority::new(0).unwrap().value(), 0);
    assert_eq!(VlanPriority::new(7).unwrap().value(), 7);
}
