# iec61850-goose

GOOSE publisher, subscriber and receiver per IEC 61850-8-1. GOOSE runs
directly over Ethernet L2 (EtherType 0x88B8) and does not use the MMS stack.
The hot path avoids allocation: the publisher prebuilds the Ethernet and GOOSE
frame header once, and the subscriber borrows slices out of the received frame
instead of copying them.

`pdu` encodes and decodes the IECGoosePdu, `frame` the Ethernet, VLAN and
GOOSE header layers, `publisher` the state machine and retransmission timing,
`subscriber` the per-GoCB state and event dispatch, and `receiver` the
typestate that owns the L2 source and fans frames out to subscribers. The
publisher owns no socket: the caller drives the retransmission schedule and
sends the frames it hands back. Publishing and subscribing need an
`AF_PACKET` socket with `CAP_NET_RAW`, so the runtime path is Linux only; a
libpcap or NPCAP backend is available for development.

Part of [iec61850-rust](https://github.com/csp0924/iec61850-rust), an
independent Rust implementation of IEC 61850 (MMS, GOOSE, Sampled Values,
SCL) written from the published standards. See the workspace
[conformance statement](https://github.com/csp0924/iec61850-rust/blob/main/docs/PICS.md)
for exactly which ACSI services are implemented.

## The iec61850-* family

All crates are layers of one workspace, versioned and released together.
Most applications depend on the top of the stack and pull the rest in as
dependencies:

- [iec61850-client](https://crates.io/crates/iec61850-client) - IED client:
  directory browsing, read and write, data sets, reporting, control, journals
- [iec61850-server](https://crates.io/crates/iec61850-server) - IED server
  runtime: MMS mapping, reporting, control, logging, setting groups
- [iec61850-goose](https://crates.io/crates/iec61850-goose) and
  [iec61850-sv](https://crates.io/crates/iec61850-sv) - GOOSE and Sampled
  Values on raw Ethernet
- [iec61850-scl](https://crates.io/crates/iec61850-scl) and
  [iec61850-scl-build](https://crates.io/crates/iec61850-scl-build) - SCL
  parsing and compile-time model generation
- [iec61850-mms](https://crates.io/crates/iec61850-mms),
  [iec61850-model](https://crates.io/crates/iec61850-model),
  [iec61850-asn1](https://crates.io/crates/iec61850-asn1),
  [iec61850-hal](https://crates.io/crates/iec61850-hal),
  [iec61850-tls](https://crates.io/crates/iec61850-tls),
  [iec61850-sntp](https://crates.io/crates/iec61850-sntp) - the supporting
  layers

The [workspace repository](https://github.com/csp0924/iec61850-rust) ties
them together; a Python binding is published on PyPI as
[iec61850](https://pypi.org/project/iec61850/).

## Feature flags

- `tokio-runtime` - exposes `tokio_helper::run_retrans_loop`, a convenience for
  development and tests. The default caller-driven mode needs no runtime.

## Example

```rust
use iec61850_goose::frame::VlanPriority;
use iec61850_goose::publisher::{CommParameters, GoosePublisher};
use iec61850_model::MmsValue;
use std::time::Instant;

// Communication parameters: APPID, destination MAC, VLAN priority. The
// destination is from the 01:0c:cd:01:xx:xx range IEC 61850-8-1 reserves.
let comm = CommParameters::new(0x1000, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01])
    .with_priority(VlanPriority::new(4).unwrap())
    .with_src_mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

// confRev 1, and no goID, which falls back to the gocbRef.
let mut publisher = GoosePublisher::new(
    comm,
    "DemoIED/LLN0$GO$gcbStatus",
    None,
    "DemoIED/LLN0$dsStatus",
    1,
)?;

// A data change bumps stNum, which restarts the retransmission at T1.
publisher.increase_st_num();

// `tick` decides when a frame is due; the caller owns the L2 socket.
let now = Instant::now();
if publisher.tick(now).is_some() {
    let dataset = vec![MmsValue::Boolean(true), MmsValue::Integer(100)];
    let frame = publisher.publish_at(&dataset, now)?;
    sock.send_l2(&frame)?;
}
```

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/csp0924/iec61850-rust/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/csp0924/iec61850-rust/blob/main/LICENSE-MIT) at your option.
