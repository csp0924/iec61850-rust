# Architecture

This document describes how the workspace is laid out, where the boundaries
between protocol logic and input/output fall, the contracts every crate holds
to, and the feature flags that select an environment.

## Crate layering

Dependencies run strictly upward. A crate never depends on one above it, and
that direction is what keeps the protocol layers independently testable. The
path an MMS association travels is:

```
   iec61850-client              iec61850-server
          |                     |     |       |
          +----- iec61850-mms --+     |       +-- iec61850-goose (optional)
                      |               |                     |
   +------------------+---------------+---------------------+
   |                  |                        |            |
   iec61850-hal   iec61850-asn1   iec61850-model   iec61850-tls (optional)
```

Stated exhaustively, so that the direction does not rest on reading the picture
generously. Normal dependencies only: dev-dependencies are excluded, and they
add a test-only cycle, since `iec61850-server` dev-depends on `iec61850-client`
and `iec61850-scl` for its end-to-end tests while `iec61850-client` dev-depends
on `iec61850-server` for the same reason. Those entries are path-only and carry
no version, so Cargo strips them when packaging and the cycle stays out of the
publish graph.

| Crate | Depends on, within the workspace |
|---|---|
| `iec61850-hal` | nothing |
| `iec61850-asn1` | nothing |
| `iec61850-model` | nothing |
| `iec61850-sntp` | nothing |
| `iec61850-tls` | `hal` |
| `iec61850-scl` | `model` |
| `iec61850-scl-build` | `scl` |
| `iec61850-goose` | `hal`, `asn1`, `model` |
| `iec61850-sv` | `hal`, `asn1`, `model` |
| `iec61850-mms` | `hal`, `asn1`, `model`; `tls` under its `tls` feature |
| `iec61850-client` | `mms`, `model`, `hal`; `tls` under its `tls` feature |
| `iec61850-server` | `mms`, `model`, `asn1`; `tls` under `tls`, `goose` under `goose-mapping` |

Three consequences are worth naming. GOOSE and Sampled Values do not depend on
`iec61850-mms`, because neither protocol goes through the MMS stack; the server
reaches GOOSE only to expose a control block as MMS variables, and only when the
`goose-mapping` feature is on. `iec61850-scl` depends on the model alone and on
nothing platform-specific, so an SCL file is parsed with no socket anywhere in
the build. And `iec61850-sntp` shares nothing with the rest of the workspace: it
is here because a deployment usually needs a time service, not because the
protocols are related.

`iec61850-scl-build` is used from a consumer's `build.rs` rather than at run
time.

**`iec61850-hal`** is the only crate that names a platform. It holds the L2
Ethernet socket abstraction shared by GOOSE and Sampled Values, the
`AsyncTransport` byte-stream trait the MMS stack is written against, and the
`Timer` trait that goes with it. It carries no IEC 61850 semantics.

**`iec61850-asn1`** holds what the MMS, GOOSE and Sampled Values layers all use
with identical semantics: definite-length BER coding per ISO/IEC 8825-1 §8.1.3,
the recursion-depth guard for nested `Data` structures, and the error type each
layer converts into its own. Tag dispatch stays with the layer that owns the
PDU, so this crate has no knowledge of any PDU.

**`iec61850-model`** is the IED, logical device, logical node, data object and
data attribute tree, together with `MmsValue`, the functional constraints, the
control block types and thirty common data class factories, following
IEC 61850-7-2 and IEC 61850-7-3. Children live in `Vec`s so that their order is
stable and indexable, which is what GetVariableAccessAttributes and GetNameList
enumeration require. A control block belongs to the logical node that owns it
rather than to a flat list on the model root.

**`iec61850-mms`** implements the upper OSI layers — TPKT per RFC 1006, COTP
class 0 per ISO 8073, Session, Presentation and ACSE — and the ISO 9506 PDUs,
independently of IEC 61850 semantics. It contains both halves of an
association: a client connection with the confirmed services, and the
server-side Initiate parser, connection state and `MmsServiceDispatcher` trait.
The accept loop, the listener and the model mapping are not here.

**`iec61850-goose`** and **`iec61850-sv`** ride directly on Ethernet, EtherType
0x88B8 and 0x88BA, and never touch the MMS stack. Each holds a PDU codec, the
Ethernet, VLAN and protocol header layers, a publisher, a subscriber and a
receiver.

**`iec61850-scl`** parses IEC 61850-6 files into an `IedModel`.
**`iec61850-scl-build`** drives the same parser from a build script and writes
Rust into `OUT_DIR`.

**`iec61850-tls`** wraps `rustls` with the IEC 62351-3 profile applied.

**`iec61850-client`** and **`iec61850-server`** map the ACSI services of
IEC 61850-7-2 onto MMS as IEC 61850-8-1 prescribes.

## Sans-IO boundaries

Protocol logic is written as functions over byte slices and state machines that
own no socket. Input and output is confined to a thin edge, which is what lets
the same code run under `tokio`, under an embedded executor, or under no
executor at all in a test.

The boundary sits in three places:

- **The MMS stack takes a transport trait.** Every layer from TPKT upward
  encodes into a buffer and decodes from a slice. A connection is generic over
  `T: AsyncTransport` from `iec61850-hal` rather than over
  `tokio::net::TcpStream`. Under the `transport-tokio` feature a blanket
  implementation covers every `tokio::io::AsyncRead + AsyncWrite + Unpin + Send`,
  so an ordinary tokio type satisfies the trait unchanged; under
  `transport-embassy` the same role is filled by `embedded-io-async`. The trait
  uses `async fn` in a trait and is therefore not object safe, so callers are
  generic rather than boxed.
- **The server crate owns the sockets, the MMS crate owns the PDUs.**
  `iec61850-mms` parses an Initiate request and hands back a response or an
  error; `iec61850-server` binds the listener, runs the accept loop and drives
  the per-association handshake. Confirmed requests reach the model through the
  `MmsServiceDispatcher` trait, so a dispatcher can be tested with no network.
- **GOOSE and Sampled Values separate the frame from the socket.** A publisher
  prebuilds its frame and exposes setters that overwrite the mutable fields in
  place; obtaining the encoded bytes is a pure call. A `Receiver` owns an L2
  source and fans decoded frames out to subscribers, but a subscriber can also
  be fed a frame directly, which is how the parsing tests and the fuzz targets
  reach it.

## Contracts

These hold across every crate. They are checked in review, and a violation is a
defect rather than a style question.

**No panics in library code.** Every fallible path returns
`Result<T, E>`; there are no out-parameters and no assertions standing in for
error handling. Where a caller must be told that a type does not match, the
answer is an error variant, not a debug assertion a release build would drop.
`iec61850-asn1`, `iec61850-model`, `iec61850-goose`, `iec61850-scl-build` and
`iec61850-server` additionally carry `#![forbid(unsafe_code)]`; `unsafe` exists
only in the Linux `AF_PACKET` backend of `iec61850-hal` and the real-time
publish loop of `iec61850-sv`, where each block carries a safety argument.

**Bounded decoding.** External input is never sliced directly. A decoder takes
bytes through the bounds-checked reader, so a declared length that reaches past
the enclosing buffer is an error rather than a read past the end. Two limits
back this up: nesting depth is capped by the smaller of a local limit and the
depth negotiated for the association, and the indefinite BER length form `0x80`
is rejected outright instead of being scanned for an end-of-contents marker.
The cases this pins are cataloged in [`robustness.md`](robustness.md).

**Strings are validated UTF-8.** A string field is a `&str` or a `String`.
Arbitrary bytes are an octet string and are typed as such.

**Time values carry their unit.** A duration or timestamp is named with a
`_ns`, `_ms` or `_s` suffix; a bare `u64` is never passed as a time. IEC 61850
`UtcTime` is its own eight-byte type carrying seconds, a fractional part and the
quality bits, rather than an integer whose interpretation lives in a comment.

**Errors are not silent.** A rejected PDU or a dropped frame produces a
`tracing::warn!` before it is discarded, so an operator can see malformed input
arriving. Runtime-visible strings are English lowercase fragments without a
trailing period.

## Threading and async

**MMS is async first.** The primary client and server APIs are `async`; a
synchronous caller wraps them with `block_on`. The server binds a listener and
spawns the accept loop and a periodic tick loop as tasks; each accepted
association runs its own task through COTP, Session, Presentation, ACSE and MMS
Initiate negotiation, then dispatches confirmed requests until the peer
concludes, the server aborts, or a layer fails to parse.

**Shared server state is lock-guarded, not task-local.** Associations live in a
map keyed by connection id. The reporting engine is held behind a mutex so that
reporting state stays consistent across connection tasks. The data model lock is
acquired without blocking: a reentrant `lock_data_model` returns
`Err(AlreadyLocked)` rather than deadlocking, and releasing it flushes the GOOSE
messages and then the reports that were deferred while it was held.

**The GOOSE and Sampled Values hot paths avoid the runtime.** Publishing does
not go through an executor. The Sampled Values publish loop runs on a dedicated
thread with `SCHED_FIFO` and `clock_nanosleep`, targeting 4000 samples per
second — one frame every 250 microseconds. The GOOSE publisher leaves the
retransmission schedule to the caller by default, so the timing source is
whatever the application already has; a `tokio-runtime` feature adds a
convenience loop for development and tests. Neither path allocates while
publishing: the frame is built once and only the counters, timestamp and data
are overwritten.

## Feature flags

Every crate that can build without the standard library follows the same
convention.

**Environment selection.** `std` is a default feature everywhere, so an
unqualified `cargo build` on a desktop target is the standard-library build and
is unaffected by the embedded path existing. `alloc` is the `no_std` path with
an allocator. `embedded` adds what a `no_std` target needs beyond that:
`hashbrown` in place of the standard collections and `spin::RwLock` in place of
`std::sync::RwLock`. `spin` is never enabled on a standard-library target, where
busy-waiting would saturate a processor.

`iec61850-asn1`, `iec61850-model` and `iec61850-hal` build for
`thumbv7em-none-eabihf`. `iec61850-mms`, `iec61850-client` and `iec61850-server`
carry an `embedded` feature that reaches the same path over the transport
traits; the parts that need a runtime — the server's `full-server` lifecycle,
the client's report dispatcher and the enhanced control models — stay on `std`.

**Transport backends** live in `iec61850-hal`: `transport` supplies the trait
definitions alone, `transport-tokio` the blanket implementation plus a
tokio-backed timer, and `transport-embassy` the `embedded-io-async` and
`embassy-time` equivalents. `ethernet` supplies the L2 traits with no platform
dependency; `ethernet-linux-afpacket`, `ethernet-pcap` and
`ethernet-windows-npcap` supply the backends.

**Subsystem selection** in the client and server lets a build carry only the
services it needs. On the server, `reporting`, `control`, `logging`,
`goose-mapping` and `setting-groups` each gate one subsystem, `full-server`
aggregates them together with the `IedServer` runtime, and `mms-core-server`
selects the core services without TLS or the optional subsystems. `minimal`
carries no subsystem and no environment, so a caller states one alongside it.
The client mirrors this with `reporting`, `control` and `datasets`, plus
`mms-core` and `minimal`.

**Optional backends.** `tls` on the client, server and MMS crates routes an
association through `iec61850-tls`. `sqlite-backend` on the server replaces the
in-memory buffered-report buffer with a SQLite-backed one; it is off by default
so that a deployment without persistence does not link SQLite.

## Data flow

**Server, MMS request.** Bytes arrive on the association's transport. TPKT
frames them, COTP hands up the payload, Session and Presentation unwrap it,
and the MMS layer decodes a ConfirmedRequestPdu. The dispatcher routes it by
service tag to a handler in `iec61850-server`, which resolves the MMS domain and
item identifier against a structural view of the model built once at startup,
reads or writes the data attribute, and encodes a response that the same layers
wrap on the way out. An outbound PDU larger than the negotiated size is refused
rather than truncated; a report too large for one PDU is segmented, with
`moreFollows` set on every segment but the last.

**Server, report.** A value update evaluates the trigger options of every
report control block whose data set contains that attribute. A triggered URCB
encodes an InformationReport and pushes it to its client; a BRCB appends to its
buffer, from which entries are drained with their entry ids when the client is
ready. If the data model lock is held, the report is deferred until it is
released.

**Client.** An IEC-notation object reference and a functional constraint become
an MMS domain and item identifier — `<LD>/<LN>.<DO>.<DA>` under FC becomes
domain `<LD>`, item `<LN>$<FC>$<DO>$<DA>` — which the Read or Write service
carries. Directory browsing fetches the object tree once with GetNameList over
the domains and their named variables and caches it on the connection; data sets
and logs always go to the server, because neither appears in that variable list.

**GOOSE and Sampled Values.** A publisher builds its frame template from the
control block configuration, then each publication overwrites the counters, the
timestamp and the data values in place. A subscriber filters received frames by
control block reference or stream identifier, decodes the payload as borrowed
slices of the received buffer, and raises new-state, retransmission and expiry
events; state numbers and sample counts are checked for continuity so a lost or
reordered frame is visible to the application.

## Model generation from SCL

`iec61850-scl` parses in two stages so that a failure names its cause. The first
stage reports broken XML, a missing attribute or an unrecognized enumeration
value, with a line and column into the file. The second resolves type references
and cross-element consistency, reporting an unresolved reference with the kind
and identifier that was sought. Every error carries the same five pieces of
information — line, column, element path, attribute name, and the value found
against the value expected — so a malformed file is never accepted silently.

A resolved document builds an `IedModel` for a named IED. `iec61850-scl-build`
runs the same path from a consumer's `build.rs`, writes the model as Rust into
`OUT_DIR`, and the consumer includes it with a macro from `iec61850-scl`. That
moves parsing to compile time, so a deployment ships no SCL file and pays no
parsing cost at startup.
