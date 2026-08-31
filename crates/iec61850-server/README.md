# iec61850-server

IEC 61850 server runtime: the `IedServer` object and the model-to-MMS
mapping of IEC 61850-8-1. It exposes an `IedModel` as MMS domains, named
variables and type specifications, answers the confirmed services a client
issues over the MMS stack, and drives reporting (URCB and BRCB), control,
logging, GOOSE control blocks and setting groups.

Behavior a caller can rely on: values are updated through typed entry
points (`update_int32`, `update_float32`, ...); PDU size negotiation clamps
to at least 64 bytes and one outstanding request; the data model lock
returns `Err(AlreadyLocked)` instead of deadlocking on reentry; an
association beyond `max_mms_connections` has its socket closed without a
COTP disconnect-request.

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

Defaults enable the full desktop server: `std`, `tls`, `full-server`.

- `full-server` (default) - the integrated `IedServer` runtime:
  `reporting`, `control`, `logging`, `goose-mapping` and `setting-groups`.
- `tls` (default) - a TLS listener per IEC 62351-3, through
  [iec61850-tls](https://crates.io/crates/iec61850-tls).
- `sqlite-backend` - a SQLite-backed buffered-report store in place of the
  in-memory ring buffer.
- `mms-core-server` - the five core MMS services without the integrated
  runtime.
- `embedded` - `no_std` plus `alloc` over the MMS transport skeleton; the
  runtime and reporting paths stay on `std`.
- `minimal` - environment-neutral marker; the caller states `minimal,std`
  or `minimal,embedded`.

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/csp0924/iec61850-rust/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/csp0924/iec61850-rust/blob/main/LICENSE-MIT) at your option.
