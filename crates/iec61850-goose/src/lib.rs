//! GOOSE publisher, subscriber, and receiver per IEC 61850-8-1.
//!
//! GOOSE runs directly over Ethernet L2 (EtherType 0x88B8) and does not use
//! the MMS stack. The publisher prebuilds the Ethernet and GOOSE frame header
//! once and BER-encodes the PDU afresh for every publication, allocating the
//! PDU buffer and the returned frame. The receiver decodes each frame into
//! owned values: the PDU is copied out of the receive buffer, and every
//! subscriber that accepts it gets its own state snapshot.
//!
//! `pdu` encodes and decodes the IECGoosePdu, `frame` the Ethernet, VLAN, and
//! GOOSE header layers, `publisher` the state machine and retransmission
//! timing, `subscriber` the per-GoCB state and event dispatch, and `receiver`
//! the typestate that owns the L2 source and fans frames out to subscribers.

#![forbid(unsafe_code)]

pub mod error;
pub mod frame;
pub mod pdu;
pub mod publisher;
pub mod receiver;
pub mod subscriber;

pub use error::GooseError;
pub use frame::{
    GooseFrame, GooseFrameHeader, VlanPriority, VlanTag, GOOSE_ETHER_TYPE, RESERVED1_SIMULATION,
};
pub use pdu::GoosePdu;
pub use publisher::{
    CommParameters, GoosePublisher, PublishAction, RetransIntervals, RetransPhase, TimestampSource,
    GOOSE_MAX_FRAME_SIZE,
};
pub use receiver::{GooseReceiver, GooseReceiverHandle, Idle, Running, SharedReceiver};
pub use subscriber::{
    GooseEvent, GooseSubscriber, GooseSubscriberBuilder, GooseSubscriberState, SimulationFilter,
    GOOSE_STRING_MAX_LEN,
};

pub use iec61850_model::utc_time::{TimeAccuracy, TimeQuality, UtcTime, UtcTimeError};
