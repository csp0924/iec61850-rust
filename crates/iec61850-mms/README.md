# iec61850-mms

The MMS protocol stack: the upper OSI layers - COTP, Session, Presentation and
ACSE - together with the ISO 9506 MMS PDUs, implemented independently of
IEC 61850 semantics. The crate carries both halves of an association, an MMS
client and an MMS server, and is what `iec61850-client` and `iec61850-server`
map the ACSI services onto.

PDU size and the outstanding-request count are negotiated on Initiate and
enforced afterwards. The stack is written against the `AsyncTransport` and
`Timer` traits of `iec61850-hal` rather than binding a runtime directly, so
the same code runs over tokio on a desktop target and over a caller-supplied
transport elsewhere. As in the `asn1`, `model` and `hal` crates, `std` is a
default feature, so a std build is unaffected; an embedded build uses
`--no-default-features --features embedded`, which pulls in `alloc`,
`hashbrown` and the hal transport traits and supplies its own `AsyncTransport`
implementation.

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

Default: `std`.

- `std` (default) - the tokio backend, through the `transport-tokio` feature of
  `iec61850-hal`.
- `alloc` - the `no_std` plus `alloc` path. Every upper-layer type stays
  available; only the `std::io` and tokio entry points are absent.
- `embedded` - `alloc` plus the hal transport traits, with the downstream
  crates switched to `no_std`. The concrete backend comes from the
  `transport-embassy` feature of the hal.
- `tls` - MMS over TLS on the secure MMS port 3782, through `iec61850-tls`.
  Implies `std`.

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/csp0924/iec61850-rust/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/csp0924/iec61850-rust/blob/main/LICENSE-MIT) at your option.
