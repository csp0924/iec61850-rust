//! GOOSE publisher, subscriber, and receiver per IEC 61850-8-1.
//!
//! GOOSE runs directly over Ethernet L2 (EtherType 0x88B8) and does not use
//! the MMS stack. The hot path avoids allocation: the publisher prebuilds the
//! Ethernet and GOOSE frame header once, and the subscriber borrows slices out
//! of the received frame instead of copying them.
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
pub use frame::{GooseFrame, GooseFrameHeader, VlanPriority, VlanTag, GOOSE_ETHER_TYPE};
pub use pdu::GoosePdu;
pub use publisher::{
    CommParameters, GoosePublisher, PublishAction, RetransIntervals, RetransPhase,
    GOOSE_MAX_FRAME_SIZE,
};
pub use receiver::{GooseReceiver, GooseReceiverHandle, Idle, Running, SharedReceiver};
pub use subscriber::{
    GooseEvent, GooseSubscriber, GooseSubscriberBuilder, GooseSubscriberState, GOOSE_STRING_MAX_LEN,
};
