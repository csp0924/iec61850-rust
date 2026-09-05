# Changelog

All notable changes to this project are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Every crate in the workspace shares one version number.

## [Unreleased]

## [0.2.0] - 2026-09-06

### Added

- **`iec61850-mms`** — the MMS GetNamedVariableListAttributes PDUs (confirmed
  service tag `0xac`) and `MmsClient::get_named_variable_list_attributes`, with
  a synchronous wrapper on `BlockingMmsClient`.
- **`iec61850-server`** — a GetNamedVariableListAttributes handler answering
  from the data set registry: members in registration order, `mmsDeletable`
  true only for a data set created through DefineNamedVariableList, and
  `object-non-existent` for an unknown name. The service is advertised in
  `servicesSupportedCalled` when the reporting subsystem is compiled in.
- **`iec61850-server`** — the dispatcher bounds every confirmed response by the
  maximum PDU size negotiated for the association, answering errorClass
  `resource other` when one does not fit. A client that negotiates a small
  maximum is therefore never sent a GetNamedVariableListAttributes member list
  or a GetVariableAccessAttributes type specification it cannot accept. Read
  and GetNameList keep their own budget and pagination.
- **`iec61850-client`** — `IedConnection::get_data_set_directory`, the ACSI
  GetDataSetDirectory service, returning `DataSetDirectory` with each member as
  an IEC reference and its functional constraint.
- **`iec61850-mms`** — `MmsClient::read_list`, a Read service over an explicit
  `listOfVariable`, returning one `AccessResult` per requested variable. An
  empty list is refused before anything is sent, and a response whose access
  result count differs from the request is rejected rather than padded or
  truncated.
- **`iec61850-client`** — `IedConnection::read_objects`, reading several object
  references with their functional constraints in a single MMS Read. Results
  follow the request order, one failing reference stays a per-entry failure,
  and array-indexed references keep the `AlternateAccess` mapping of
  `read_object`. `AccessResult` is re-exported so the return type can be named
  without depending on `iec61850-mms`.
- **`iec61850-mms`** — `IsoConnectionParameters`, the ISO addressing a client
  offers when it associates: the calling and called T, S and P selectors and the
  AP-title and AE-qualifier of both sides. `ApTitle` holds an AP-title as its
  OBJECT IDENTIFIER arcs, parses the dotted form and renders it. The parameters
  reach an association through `MmsClientBuilder::iso_parameters`, and through
  `MmsClient::from_transport_with_iso_parameters` for a caller that owns its
  transport. The AARQ now emits called-AP-title `[2]`, called-AE-qualifier
  `[3]`, calling-AP-title `[6]` and calling-AE-qualifier `[7]` when they are
  set, in the order the ISO 8650 AARQ-apdu declares them.
- **`iec61850-mms`** — the session layer decodes the REFUSE SPDU (RF, SPDU ID
  12) of ISO 8327-1, returning the reason code (PI 50), the transport
  disconnect parameter (PI 17) and the user data; the long form of LI is
  accepted. The presentation layer decodes the CPR PPDU of ISO 8823 through
  `parse_reject`, returning the responding presentation selector, the
  context-definition result list, the default-context result and the
  provider-reason. `refuse_reason_name` and `provider_reason_name` give the
  names the two standards define.
- **`iec61850-mms`, `iec61850-client`** — `ClientError::SessionRefused`, carrying
  the session reason code, the transport disconnect parameter and the
  presentation provider-reason of a refused association. A refusal used to
  surface as `unknown spdu id 0x0C`.
- **`iec61850-client`** — `IedConnection::with_iso_parameters`, with
  `IsoConnectionParameters` and `ApTitle` re-exported so the addressing can be
  built without depending on `iec61850-mms`.

### Changed

- **`iec61850-mms`, `iec61850-client`** — the calling and called presentation
  selectors a client offers default to `00 00 00 01`, where they used to be
  empty. This changes the bytes on the wire: the CP PPDU now carries
  `81 04 00 00 00 01` and `82 04 00 00 00 01` where it carried `81 00` and
  `82 00`. A caller that needs the empty selectors sets them explicitly through
  `IsoConnectionParameters`; a zero-length selector still occupies its tag and
  length pair.
- **`iec61850-mms`, `iec61850-client`** — the AARQ a client sends now carries
  the calling and called AP-title and AE-qualifier by default, `1.1.1.999` and
  `1.1.1.999.1` with AE-qualifier 12, where it carried none. Setting a field to
  `None` leaves it out.
- **`iec61850-mms`** — `encode_aarq` takes the addressing fields as an
  additional `AarqAddressing` argument.

### Fixed

- **`iec61850-mms`, `iec61850-server`** — the `ServiceError` `errorClass`
  subcodes the server sends now follow the ISO 9506-2 `ServiceError` ASN.1
  named numbers. The `access [7]` alternative defines `other(0)`,
  `object-access-unsupported(1)`, `object-non-existent(2)`,
  `object-access-denied(3)` and `object-invalidated(4)`; the server was sending
  the `DataAccessError` codes 9 and 10, which that alternative does not define,
  so a client read them as `other`. This changes the bytes on the wire:
  object-non-existent goes out as `0x87 0x01 0x02` where it was `0x87 0x01
  0x0a`, and object-access-unsupported as `0x87 0x01 0x01` where it was `0x87
  0x01 0x09`. A malformed data set member reference is now
  `definition invalid-address` and a duplicate data set name
  `definition object-exists`, in place of subcodes the `access` alternative
  does not define. `ErrorClass` subcodes are available as named constants in
  `mms::pdu::service_error::subcode`, one module per alternative.

- **`iec61850-mms`** — the client reads back a Confirmed-ErrorPDU that the
  server sends. Its decoder looked for the invokeID under the universal INTEGER
  tag `0x02`, the form an untagged `invokeID` takes in a Confirmed-RequestPDU,
  while ISO 9506-2 declares the Confirmed-ErrorPDU field `[0] IMPLICIT`, tag
  `0x80`. Every refusal therefore surfaced as
  `ClientError::PduParse("ConfirmedError decode failed")` instead of
  `ClientError::ServiceError`, so a caller could not tell an unknown object from
  a malformed answer. `decode_confirmed_error_pdu` and
  `decode_confirmed_error_inner` are now public, accept the optional
  `modifierPosition [1]`, and validate the invokeID as an `Unsigned32`.

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

[Unreleased]: https://github.com/csp0924/iec61850-rust/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/csp0924/iec61850-rust/releases/tag/v0.2.0
[0.1.1]: https://github.com/csp0924/iec61850-rust/releases/tag/v0.1.1
[0.1.0]: https://github.com/csp0924/iec61850-rust/releases/tag/v0.1.0
