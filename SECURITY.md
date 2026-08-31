# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities through GitHub private vulnerability
reporting, on the **Security** tab of
[github.com/csp0924/iec61850-rust](https://github.com/csp0924/iec61850-rust)
under **Report a vulnerability**. That channel is private: the report is not
visible publicly while it is being handled.

Do not open a public issue, a pull request or a Discussion for a suspected
vulnerability. A public report gives every reader of the repository a working
description of the weakness before a fix exists.

A useful report states the affected crate and version, the protocol layer, and
how the input reaches the vulnerable code — a client PDU, a GOOSE or Sampled
Values frame, an SCL file, or a TLS handshake. A minimal reproducer is worth
more than a description: a byte sequence, a unit test, or a fuzz artifact.

Expect an acknowledgment within seven days and an initial assessment within
thirty. A fix ships in a patch release of every affected supported version, with
an advisory published once the release is available. Reporters are credited in
the advisory unless they ask not to be.

## Supported versions

| Version | Supported |
|---|---|
| `0.1.x` | yes |
| earlier | none exist |

While the project is below `1.0`, only the latest published minor version
receives security fixes. Older minor versions are not backported.

## Threat model

The crates are written for a substation network where the peer is not trusted
to be well behaved. Every decoder treats its input as hostile, and the following
inputs are in scope:

- MMS PDUs arriving over TCP port 102 or the secure port 3782, at every layer
  from TPKT up through the ISO 9506 PDUs.
- GOOSE and Sampled Values frames arriving on a raw Ethernet socket. Neither
  protocol authenticates its sender at the link layer, so any station on the
  segment can inject frames.
- SCL files — ICD, CID and SCD — parsed by `iec61850-scl` or compiled by
  `iec61850-scl-build`.
- TLS handshakes and peer certificates handled by `iec61850-tls`.

Out of scope: the correctness of an application's own control logic, physical
access to the station bus, and the security of the operating system the library
runs on.

## Guarantees the code holds to

These are contracts, checked in review and pinned by tests:

- **Library code does not panic.** Every fallible path returns a `Result`. A
  panic reachable from untrusted input is a vulnerability, not a bug report.
- **`unsafe` is confined to two platform backends.** The Linux `AF_PACKET`
  socket in `iec61850-hal` and the real-time publish loop in `iec61850-sv` call
  `libc` directly; every block there carries a safety argument. No decoder, no
  PDU type and no protocol state machine contains any. `iec61850-asn1`,
  `iec61850-model`, `iec61850-goose`, `iec61850-scl-build` and
  `iec61850-server` carry `#![forbid(unsafe_code)]`.
- **External input is never sliced directly.** BER decoding goes through the
  bounds-checked reader in `iec61850-asn1`; a declared length that runs past the
  buffer is an error, never a read past the end.
- **Decoding is bounded.** Nesting depth is capped by the smaller of a local
  limit and the negotiated one, so a depth bomb cannot exhaust the stack. The
  indefinite BER length form is rejected rather than scanned, so a malformed
  length cannot drive an unbounded loop.
- **Rejections are not silent.** A refused PDU or a dropped frame is reported
  through `tracing::warn!`, so an operator can see an attack in progress.

[`docs/robustness.md`](docs/robustness.md) catalogs the malformed-input cases
that pin these properties, each with the class of input, the required outcome
and the test that holds it. Nine `cargo-fuzz` targets exercise the same
decoders with generated input.

## Hardening a deployment

**Network.** Keep MMS, GOOSE and Sampled Values on a segment reachable only by
the stations that need them. GOOSE and Sampled Values carry no authentication of
their own, so link-layer isolation, VLAN separation and port security are what
stand between a publisher and an injected frame.

**TLS.** Enable the `tls` feature on `iec61850-client` and `iec61850-server` and
serve MMS on port 3782. `TlsConfigBuilder` applies the IEC 62351-3 constraints —
TLS 1.2 as the floor, a fixed cipher suite whitelist — and requires client
certificates when configured to. Two settings weaken the profile and exist only
for interoperating with equipment that cannot be fixed:

- `allow_only_known_peers` pins the acceptable leaf certificates. Leaving it off
  falls back to ordinary chain validation.
- Switching validity-time checking off makes an expired peer certificate
  acceptable. Every other chain error is still rejected, and each downgrade is
  reported through the event handler. Do not use it in production.

**Server limits.** `IedServerConfig::max_mms_connections` bounds concurrent
associations; a connection beyond the limit has its socket closed. The
negotiated PDU size bounds a single request, and outbound PDUs are checked
against it. Set the write-access policy to the narrowest functional-constraint
mask the application needs — the default allows `SP`, `SV` and `SE` only.

**SCL input.** Treat SCL files as configuration from a trusted engineering
process. The parser is bounds-checked and its XML dependency carries no open
advisory, but SCL parsing has no fuzz target, so it is not a surface to point
at untrusted input.

**Logging.** Run with a `tracing` subscriber attached and keep the warning level
enabled. Rejected PDUs, dropped frames and TLS downgrades are only visible
through it.

**Time.** Report and log timestamps are only as trustworthy as the clock behind
them. `iec61850-sntp` provides a time service; the quality bits the server
reports come from `IedServerConfig::time_quality` and must be set to reflect the
real synchronization state rather than left at a default that claims more than
is true.

## Known dependency advisories

`cargo deny check advisories` runs in CI and is the authoritative list. No
advisory stands open at `0.1.1`: the `deny.toml` ignore list is empty.

An advisory is never suppressed silently. Every entry added to the `deny.toml`
ignore list carries the reason it is there.
