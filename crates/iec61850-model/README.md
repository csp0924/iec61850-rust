# iec61850-model

The IEC 61850 data model tree - IED, logical device, logical node, data object,
data attribute - together with the `MmsValue` type and the common data class
factories. Structure and semantics follow IEC 61850-7-2 and IEC 61850-7-3, and
the crate covers the functional constraints and the common data class
factories the rest of the workspace builds on.

Shape of the model, which callers rely on: children live in `Vec`s, so their
order is stable and indexable, which is what `GetVariableAccessAttributes` and
`GetNameList` enumeration need; a control block belongs to the logical node
that owns it rather than to a flat list on the model root; an array container
is marked by `Option<u32>` rather than by a sentinel node; there is no reverse
lookup from a value back to its data attribute; and every name is an owned
`String`.

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

- `std` (default) - the std collections and `std::sync::RwLock`. A desktop
  build needs no other flag.
- `alloc` - the `no_std` base.
- `embedded` - the `no_std` path: `hashbrown` replaces `std::HashMap` and
  `std::HashSet`, and `spin::RwLock` replaces `std::sync::RwLock`. An embedded
  target builds with `--no-default-features --features embedded`.

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/csp0924/iec61850-rust/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/csp0924/iec61850-rust/blob/main/LICENSE-MIT) at your option.
