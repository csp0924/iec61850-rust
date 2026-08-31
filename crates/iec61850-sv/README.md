# iec61850-sv

Sampled Values publisher and subscriber per IEC 61850-9-2, covering the
9-2LE profile. Sampled Values run directly over Ethernet L2 (EtherType
0x88BA) and do not use the MMS stack. The publish path targets 4000 samples
per second, one frame every 250 us, and prebuilds the frame so that a
publication only overwrites the sample data and the counters in place.

`pdu` encodes and decodes the savPdu and its ASDUs, `frame` the Ethernet,
VLAN and SV header layers, `nine_two_le` the 9-2LE channel layout,
`publisher` the frame template and hot-path setters, `publish_thread` a
Linux publish loop over `clock_nanosleep` with SCHED_FIFO, `subscriber`
per-svID filtering and sample continuity, and `receiver` the typestate that
owns the L2 source. Publishing and subscribing need an `AF_PACKET` socket
with `CAP_NET_RAW`, so the runtime path is Linux only; a libpcap or NPCAP
backend is available for development.

Not implemented here: SVCB management over MMS, R-SV over UDP, and the
protection profile of 256 samples per cycle.

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

- `tokio-runtime` - tokio-based helpers, a convenience for development and
  tests. The publisher hot path does not depend on a runtime; it runs on a
  dedicated thread.

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/csp0924/iec61850-rust/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/csp0924/iec61850-rust/blob/main/LICENSE-MIT) at your option.
