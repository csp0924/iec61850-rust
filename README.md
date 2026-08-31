# iec61850-rust

[English](README.md) | [繁體中文](README.zh-TW.md)

An independent implementation of IEC 61850 (MMS, GOOSE, Sampled Values, SCL) in
Rust, written from the published standards. The workspace covers the MMS stack
(COTP, Session, Presentation, ACSE and the ISO 9506 PDUs), GOOSE and Sampled
Values over raw Ethernet, the IEC 61850-7-x data model, an SCL parser with
compile-time model generation, and client and server runtimes carrying the ACSI
control, reporting and logging services.

**Conformance:** [`docs/PICS.md`](docs/PICS.md) states which ACSI services and
models are implemented in the server and client roles, with the known gaps
listed explicitly. No test laboratory has certified this implementation.

Licensed under `MIT OR Apache-2.0`.

## Status

The workspace builds on stable Rust and carries roughly 2,000 tests: BER and
PDU round trips, protocol state machines, loopback client-to-server integration
tests, and the malformed-input regressions cataloged in
[`docs/robustness.md`](docs/robustness.md). Nine `cargo-fuzz` targets cover the
GOOSE, Sampled Values, COTP, Session, Presentation, ACSE and MMS decoders.

What this project does not claim:

- **No conformance certification.** The implementation has not been submitted
  to a recognized test laboratory, and no certificate exists for it.
- **GOOSE and Sampled Values run on Linux only.** Both ride directly on
  Ethernet and need an `AF_PACKET` socket with `CAP_NET_RAW`. Windows compiles
  the crates but cannot run their publishers and subscribers; a libpcap or
  NPCAP backend is available for development.
- **MMS file services are not implemented.** No handler answers them, and
  `iec61850-server` advertises no feature that claims to.
- **GetNameList discovery follows the run-time registries, not the SCL model.**
  Data sets, report control blocks and GOOSE control blocks are listed once they
  are registered. Those registries are what the Read paths resolve against, so
  every listed name is readable, and one the model declares but nothing
  registered is not listed. A `Journal`-class request is answered with an empty
  list, so a log is read by name rather than discovered.
- **SVCB management over MMS, R-GOOSE and R-SV are not implemented.**

## Crates

| Crate | What it holds | `no_std` |
|---|---|---|
| `iec61850-asn1` | Shared BER codec core: definite-length coding per ISO/IEC 8825-1 and the recursion-depth guard | yes, `alloc` |
| `iec61850-hal` | Platform abstraction: L2 Ethernet sockets, async transport and timer traits | yes, `alloc` |
| `iec61850-model` | The IED / LD / LN / DO / DA tree, `MmsValue`, functional constraints and 30 common data class factories | yes, `embedded` |
| `iec61850-mms` | COTP, Session, Presentation, ACSE and the ISO 9506 PDUs, with the MMS client and server halves | yes, `embedded` |
| `iec61850-goose` | GOOSE publisher, subscriber and receiver, EtherType 0x88B8 | no |
| `iec61850-sv` | Sampled Values publisher and subscriber, EtherType 0x88BA, 9-2LE profile | no |
| `iec61850-scl` | SCL parser for IEC 61850-6: reads ICD, CID and SCD files into an `IedModel` | no |
| `iec61850-scl-build` | Build-script helper that compiles an SCL file into Rust at compile time | no |
| `iec61850-client` | `IedConnection`: directory, read and write, data sets, RCBs and reports, control, journal, GoCB | partial, `embedded` |
| `iec61850-server` | `IedServer`: the MMS mapping, reporting, control, logging, setting groups, GoCB mapping | partial, `embedded` |
| `iec61850-tls` | TLS configuration and socket wrappers per IEC 62351-3, on `rustls` | no |
| `iec61850-sntp` | SNTPv4 (RFC 4330) server and client for IED time synchronization | no |

`iec61850-scl-build-example` is a thirteenth workspace member demonstrating
compile-time model generation. It is not published.

Dependencies run strictly upward: `hal`, `asn1` and `model` depend on nothing
in the workspace; `tls`, `scl`, `goose`, `sv` and `mms` build on them; `client`
and `server` sit on top. `sntp` stands alone.
[`docs/architecture.md`](docs/architecture.md) gives the full dependency table,
the sans-IO boundaries and the contracts every crate holds to.

## Protocol coverage

**MMS services, server side.** Initiate and Conclude, GetNameList,
GetVariableAccessAttributes, Read, Write, Identify, DefineNamedVariableList,
DeleteNamedVariableList, ReadJournal, and InformationReport for reports. PDU
size is negotiated on Initiate and enforced on every outbound PDU; a report too
large for one PDU is segmented.

**Reporting.** Unbuffered (URCB) and buffered (BRCB) report control blocks:
trigger options, optional fields, general interrogation, buffer overflow and
entry ids. A BRCB buffers in memory by default; the `sqlite-backend` feature
adds a SQLite-backed buffer.

**Control.** All five control models of IEC 61850-7-2 — status-only,
direct-with-normal-security, SBO-with-normal-security,
direct-with-enhanced-security and SBO-with-enhanced-security — with Select,
SelectWithValue, Operate, Cancel, command termination, and the check and
wait-for-execution handler hooks.

**Logging.** A log control block writing through a `LogStorage` trait, read
back by a client with QueryLogByTime and QueryLogAfterEntry over ReadJournal.
WriteJournal is not implemented.

**Setting groups.** An SGCB runtime with `ActSG`, `EditSG` and `CnfEdit`, an
edit session owned by one association, and a reservation deadline that releases
an abandoned session.

**GOOSE.** A publisher whose retransmission schedule the caller drives, a
subscriber raising new-state, retransmission and expiry events, and a receiver
that fans frames out to subscribers. `iec61850-server` exposes a GoCB as MMS
variables, so GetGoCBValues and SetGoCBValues work over Read and Write.

**Sampled Values.** Publisher and subscriber for the IEC 61850-9-2 LE profile,
with a prebuilt frame template on the publish path and sample-continuity
counting on the receive path.

**Client.** Directory browsing over a cached device model, object read and
write in IEC notation, dynamic data set administration, RCB read and write with
report dispatch, control, journal queries and GoCB access.

**Security.** `iec61850-tls` builds `rustls` configurations with the IEC
62351-3 constraints already applied: TLS 1.2 as the floor, a fixed cipher suite
whitelist, optional allow-only-known-certificate verification, and the profile's
event codes. `iec61850-client` and `iec61850-server` reach it through their
`tls` features.

## Quick start

The examples share one configured IED description,
[`crates/iec61850-server/examples/models/demo.cid`](crates/iec61850-server/examples/models/demo.cid),
whose MMS domain is `DemoIEDLD0`. Start a server in one terminal:

```sh
cargo run -p iec61850-server --example min_server
```

and read from it in another:

```sh
cargo run -p iec61850-client --example min_client
```

`min_client` connects to `127.0.0.1:8102`, reads four attributes, writes one and
disconnects. `server_from_scl` is the larger counterpart: it binds every data
set, report control block and control object the SCL declares, which is what the
reporting and browsing clients expect.

```sh
cargo run -p iec61850-server --example server_from_scl
cargo run -p iec61850-client --example client_reporting_subscriber
```

[`examples/README.md`](examples/README.md) lists every example with what it
shows, the example it pairs with and its exact run command, and walks through
the demonstration IED in full.

## Server configuration

`IedServerConfig` carries the association limit, the edition, the write-access
policy as a functional-constraint mask, the reported time quality, and the three
strings the Identify service returns. Leaving an identification field unset
selects a built-in default:

| Field | Default |
|---|---|
| `vendor_name` | `rust61850` |
| `model_name` | `iec61850-rust` |
| `revision` | the crate version |

Set `vendor_name`, `model_name` or `revision` on the configuration to report
your own values. Those three strings are what a client sees in an
Identify-Response; the self-authored SCL in this repository carries the same
vendor in its name plates.

## Platform support

| Target | MMS client and server | GOOSE and SV | SNTP |
|---|---|---|---|
| Linux | yes | yes, with `CAP_NET_RAW` | yes |
| Windows | yes | builds; libpcap or NPCAP backend for development | yes |
| `thumbv7em-none-eabihf` | the `embedded` feature set, no runtime | no | no |

Granting the capability to a built binary avoids running an example as root:

```sh
cargo build -p iec61850-goose --example goose_publisher
sudo setcap cap_net_raw+ep target/debug/examples/goose_publisher
```

## `no_std`

Six crates build for `thumbv7em-none-eabihf` with `--no-default-features` plus
an `alloc` or `embedded` feature: `iec61850-asn1`, `iec61850-model`,
`iec61850-hal`, `iec61850-mms`, and `iec61850-client` and `iec61850-server` at
their `minimal,embedded` feature set. On that path `hashbrown` replaces the
standard collections, `spin::RwLock` replaces `std::sync::RwLock`, and the MMS
stack runs over the `AsyncTransport` and `Timer` traits of `iec61850-hal` rather
than binding `tokio` directly. `CONTRIBUTING.md` lists the six commands.

`std` is a default feature everywhere, so a desktop build is unaffected. The
client and server are marked partial because only part of each crosses: the
server's `full-server` runtime and the client's report dispatcher need a runtime
and an address type and stay on the `std` path.

These builds are compile checks. Nothing in this repository has been run on real
hardware, and there is no continuous integration covering the bare-metal target.

## Python binding

A Python binding is published separately as the `iec61850` package on PyPI and
is built on these crates. Its source lives at
[github.com/csp0924/iec61850-python](https://github.com/csp0924/iec61850-python).

## Who is using this?

The project is free to use in any setting, commercial deployments included, and
no registration is required. If you do run it somewhere, saying so helps other
readers judge where the implementation has been exercised. Add an entry to
[`ADOPTERS.md`](ADOPTERS.md) by opening an issue with the
[adopter template](.github/ISSUE_TEMPLATE/adopter.md), or open a GitHub
Discussion if you would rather ask something first. Naming an organization is
optional; a description of the use case on its own is welcome.

## Minimum supported Rust version

`1.88`, declared once in the workspace manifest. Raising it is a minor-version
change.

## License

`MIT OR Apache-2.0`, at your option. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).

## Security

Report a vulnerability through GitHub private vulnerability reporting rather
than a public issue. [`SECURITY.md`](SECURITY.md) has the procedure, the
supported versions, and hardening guidance for a deployment.

## Contributing

[`CONTRIBUTING.md`](CONTRIBUTING.md) covers the build, the checks CI enforces,
the comment style, the no-panic contract, and how to add a robustness case.
