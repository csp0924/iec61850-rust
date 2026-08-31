# iec61850-client

IEC 61850 client API: an `IedConnection` over MMS carrying the ACSI
services of IEC 61850-7-2 as mapped by IEC 61850-8-1 - directory browsing
over a cached device model, object read and write in IEC notation, dynamic
data set administration, RCB read and write with report dispatch, control
over all five control models, journal queries and GoCB access. The primary
API is `async`; a synchronous caller wraps it in `block_on`.

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

Defaults enable the full desktop client.

- `std` (default) - tokio runtime and `std::sync`; enables the async
  `IedConnection` API.
- `tls` - `IedConnection::connect_tls` per IEC 62351-3, through
  [iec61850-tls](https://crates.io/crates/iec61850-tls).
- `reporting` / `control` / `datasets` - gate report dispatch together with
  the RCB, GoCB and journal APIs, the control API, and data set
  administration. Each implies `std`.
- `mms-core` - the three service groups above in one switch.
- `embedded` - `no_std` plus `alloc`, with the MMS and model crates on
  their embedded paths. Only the error and MMS-compatibility surfaces are
  exposed, because the async API needs a runtime.
- `minimal` - environment-neutral marker; the caller states `minimal,std`
  or `minimal,embedded`.

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/csp0924/iec61850-rust/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/csp0924/iec61850-rust/blob/main/LICENSE-MIT) at your option.
