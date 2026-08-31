//! Sampled Values publisher and subscriber per IEC 61850-9-2.
//!
//! Sampled Values run directly over Ethernet L2 (EtherType 0x88BA) and do not
//! use the MMS stack. The publish path targets 4000 samples per second, one
//! frame every 250 us, and prebuilds the frame so that a publication only
//! overwrites the sample data and the counters in place.
//!
//! `pdu` encodes and decodes the savPdu and its ASDUs, `frame` the Ethernet,
//! VLAN, and SV header layers, `nine_two_le` the 9-2LE channel layout,
//! `publisher` the frame template and hot-path setters, `publish_thread` a
//! Linux publish loop, `subscriber` per-svID filtering and sample continuity,
//! and `receiver` the typestate that owns the L2 source.
//!
//! Not implemented here: SVCB management over MMS, R-SV over UDP, and the
//! protection profile of 256 samples per cycle.

// publish_thread calls clock_nanosleep through libc and re-enables unsafe
// locally; the rest of the crate stays free of it.
#![deny(unsafe_code)]

pub mod error;
pub mod frame;
pub mod nine_two_le;
pub mod pdu;
pub mod publisher;
pub mod receiver;
pub mod subscriber;

#[cfg(target_os = "linux")]
pub mod publish_thread;

pub use error::SvError;
pub use frame::{
    SvFrame, SvFrameHeader, VlanPriority, VlanTag, SV_APP_HEADER_SIZE, SV_DEFAULT_APPID,
    SV_DEFAULT_DST_MAC, SV_ETHER_TYPE, SV_HEADER_NO_VLAN, SV_HEADER_WITH_VLAN, SV_MIN_FRAME_SIZE,
};
pub use nine_two_le::{
    ChannelSample, NineTwoLE, BYTES_PER_CHANNEL, CHANNEL_COUNT, CHANNEL_NAMES, SAMPLE_SIZE,
};
pub use pdu::{
    decode_sav_pdu, encode_sav_pdu, Asdu, SavPdu, SmpMod, SmpSynch, MAX_ASDU_PER_FRAME,
    SV_STRING_MAX_LEN,
};
pub use publisher::{AsduHandle, EthernetSink, SvPublisher, SvPublisherBuilder, SV_MAX_FRAME_SIZE};
pub use receiver::{Idle, Running, SvReceiver, SvReceiverHandle};
pub use subscriber::{SvSubscriber, SvSubscriberAsdu, SvSubscriberBuilder};
