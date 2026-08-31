# Changelog

All notable changes to this project are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Every crate in the workspace shares one version number.

## [Unreleased]

## [0.1.1] - 2026-09-01

Documentation and packaging metadata only; no code changes.

### Added

- A README for every published crate, rendered on its crates.io page.
- `homepage` and `readme` manifest metadata for every published crate.

## [0.1.0] - 2026-08-31

Initial public release.

### Added

- **`iec61850-asn1`** — the BER codec core shared by the MMS, GOOSE and
  Sampled Values layers: definite-length encoding and decoding per
  ISO/IEC 8825-1 §8.1.3, and the recursion-depth guard for nested `Data`
  structures.
- **`iec61850-hal`** — the platform abstraction: L2 Ethernet socket traits with
  Linux `AF_PACKET`, libpcap and NPCAP backends, the `AsyncTransport`
  byte-stream trait with `tokio` and `embassy` implementations, and the `Timer`
  trait.
- **`iec61850-model`** — the IED, logical device, logical node, data object and
  data attribute tree, `MmsValue`, the functional constraints, the control block
  types, and thirty common data class factories, per IEC 61850-7-2 and
  IEC 61850-7-3.
- **`iec61850-mms`** — the upper OSI stack (TPKT per RFC 1006, COTP class 0 per
  ISO 8073, Session, Presentation and ACSE) and the ISO 9506 PDUs, with both the
  client and the server side of an association.
- **`iec61850-goose`** — GOOSE publisher, subscriber and receiver on EtherType
  0x88B8, with a prebuilt frame template on the publish path and borrowed-slice
  decoding on the receive path.
- **`iec61850-sv`** — Sampled Values publisher and subscriber on EtherType
  0x88BA for the IEC 61850-9-2 LE profile, with a `SCHED_FIFO` publish loop
  targeting 4000 samples per second.
- **`iec61850-scl`** — a two-stage SCL parser for IEC 61850-6 reading ICD, CID
  and SCD files into an `IedModel`, with line, column, element path and
  attribute on every error.
- **`iec61850-scl-build`** — a build-script helper compiling an SCL file into
  Rust in `OUT_DIR`, so a deployment ships no SCL and parses nothing at startup.
- **`iec61850-client`** — `IedConnection`: directory browsing over a cached
  device model, object read and write in IEC notation, dynamic data set
  administration, report control block read and write with report dispatch,
  control, journal queries, and GoCB access.
- **`iec61850-server`** — `IedServer`: the model-to-MMS mapping; the GetNameList,
  GetVariableAccessAttributes, Read, Write, Identify, DefineNamedVariableList,
  DeleteNamedVariableList and ReadJournal services; unbuffered and buffered
  reporting with segmentation and an optional SQLite buffer; all five control
  models of IEC 61850-7-2; the log control block; setting groups; and GoCB
  mapping onto MMS variables.
- **`iec61850-tls`** — `rustls` configuration and socket wrappers with the
  IEC 62351-3 constraints applied, allow-only-known-certificate verification,
  and the profile's event codes.
- **`iec61850-sntp`** — an SNTPv4 (RFC 4330) server and client for IED time
  synchronization.
- `no_std` plus `alloc` support in `iec61850-asn1`, `iec61850-model` and
  `iec61850-hal`, with an `embedded` feature reaching the same path in
  `iec61850-mms`, `iec61850-client` and `iec61850-server`.
- A catalog of malformed-input robustness cases in `docs/robustness.md`, each
  pinned by a named test, and nine `cargo-fuzz` targets over the GOOSE, Sampled
  Values, COTP, Session, Presentation, ACSE and MMS decoders.
- Runnable examples for every crate, sharing one demonstration IED description;
  see `examples/README.md`.

### Known limitations

- No conformance certification: the implementation has not been submitted to a
  recognized test laboratory.
- GOOSE and Sampled Values publishers and subscribers run on Linux only; they
  compile on Windows but need an `AF_PACKET` socket to run.
- MMS file services are not implemented, and no server feature advertises them.
- GetNameList lists the data sets, report control blocks and GOOSE control
  blocks that are registered at run time, not the ones the SCL model declares. A
  `Journal`-class request is answered with an empty list, so a log is read by
  name rather than discovered by browsing.
- SVCB management over MMS, R-GOOSE and R-SV are not implemented.

[Unreleased]: https://github.com/csp0924/iec61850-rust/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/csp0924/iec61850-rust/releases/tag/v0.1.1
[0.1.0]: https://github.com/csp0924/iec61850-rust/releases/tag/v0.1.0
