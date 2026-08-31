# iec61850-hal

The platform abstraction layer the rest of the workspace is written against:
L2 Ethernet sockets, an async byte-stream transport, and an async timer.
Nothing here carries IEC 61850 semantics.

`ethernet` is the raw L2 socket abstraction shared by GOOSE and Sampled
Values. `transport` is the async byte-stream trait the MMS layer is written
against, and `time` is the async timer trait that goes with it. Backends are
selected by feature, so a consumer picks a platform without changing the code
above it, and an embedded target can supply an `AsyncTransport` of its own.

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

Default: `std`, `ethernet`.

- `std` (default) - uses the std prelude and implies `alloc`.
- `alloc` - the `no_std` path, required on embedded targets.
- `embedded` - currently equivalent to `alloc`, reserved as a backend switch.
- `ethernet` (default) - traits and shared types, no platform dependency.
- `ethernet-linux-afpacket` - the Linux `AF_PACKET` backend; implies `std`.
- `ethernet-pcap` / `ethernet-windows-npcap` - the libpcap backend, needing
  libpcap on Linux or the NPCAP runtime on Windows; both imply `std`.
- `transport` - the `AsyncTransport` and `Timer` traits, definitions only.
- `transport-tokio` - a blanket `AsyncTransport` impl for
  `tokio::io::AsyncRead + AsyncWrite`, plus `TokioTimer`; implies `std`.
- `transport-embassy` - the embassy and `embedded-io-async` bindings for the
  `no_std` plus `alloc` path; implies `embedded`.

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/csp0924/iec61850-rust/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/csp0924/iec61850-rust/blob/main/LICENSE-MIT) at your option.
