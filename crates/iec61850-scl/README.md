# iec61850-scl

SCL and ICD parser for IEC 61850-6: reads ICD, CID and SCD files into an
`IedModel` the server and client crates consume.

Parsing runs in two stages, so a failure can say exactly what is wrong.
Stage 1, `raw`, reports a broken XML structure, a missing attribute or an
unrecognized enumeration string, with a line and column pointing into the
XML. Stage 2, `resolved`, reports an unresolved type reference or a
cross-element inconsistency, with a line and column pointing at the
reference and a message naming the type kind and identifier that was
sought. Every `ErrorKind` carries the same five pieces of information -
line, column, element path, attribute name, and the raw value against the
expected one - so a malformed file is never accepted silently.

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

## Example

```rust,ignore
let raw = iec61850_scl::parse_scl(xml_str)?;   // stage 1
let resolved = raw.resolve()?;                 // stage 2
let model = resolved.build_model("IED1")?;     // an IedModel
```

For model generation at compile time instead of run time, see
[iec61850-scl-build](https://crates.io/crates/iec61850-scl-build).

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/csp0924/iec61850-rust/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/csp0924/iec61850-rust/blob/main/LICENSE-MIT) at your option.
