# iec61850-tls

The TLS integration layer for IEC 61850, compatible with IEC 62351-3 and built
on `rustls`. `TlsConfigBuilder` produces client and server configurations with
the profile's constraints already applied: TLS 1.2 as the floor and a fixed
cipher suite whitelist. `TlsConnector` and `TlsAcceptor` wrap `tokio-rustls`
and hand back a `TlsStream<TcpStream>` that plugs straight into the COTP
connection type.

Two verifier wrappers add the profile's stricter certificate rules.
`AllowOnlyKnownCertsServerVerifier` and its client counterpart reject a peer
whose leaf certificate is not on the configured list, and reject an empty list
outright. `IgnoreValidityTimeServerVerifier` downgrades only expiry errors when
validity-time checking is off, and still rejects every other chain error.
`TlsEventHandler` carries the 20 event codes of IEC 62351-3. The constants
`IEC62351_3_TLS12_CIPHERS` and `IEC62351_3_TLS13_CIPHERS` are the whitelist
itself; it contains only ECDHE_RSA with AES-GCM, because the rustls ring
provider implements no finite-field DHE suite. Library code never panics;
every failure path returns `Result<_, TlsError>`.

`iec61850-client` and `iec61850-server` reach this crate through their own
`tls` features, so a caller normally enables TLS there rather than depending
on this crate directly.

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

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/csp0924/iec61850-rust/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/csp0924/iec61850-rust/blob/main/LICENSE-MIT) at your option.
