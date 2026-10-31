# Changelog

All notable changes to this project are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Every crate in the workspace shares one version number.

## [Unreleased]

0.4.0 is a breaking release. It removes the workarounds 0.3.x kept to stay
within patch releases, makes the public enums and structs of every crate
`#[non_exhaustive]`, and changes several behaviors on the wire to follow
IEC 61850-7-2 and IEC 61850-8-1. The steps to upgrade are arranged by use case
in [docs/migration-0.4.md](docs/migration-0.4.md); the entries below link to
the relevant section.

### Breaking changes

#### On the wire

Each entry says what a peer sees and whether both sides have to be upgraded
together. [Upgrade order](docs/migration-0.4.md#upgrade-order) collects the
pairs that do.

- **`iec61850-server`**, **`iec61850-client`** — The GOOSE control block is
  served and read as the MMS structure of IEC 61850-8-1 §18.1.1.1.1 Table 83:
  `GoEna`, `GoID`, `DatSet`, `ConfRev`, `NdsCom`, `DstAddress`, `MinTime`,
  `MaxTime`, `FixedOffs`. `GoCBRef` is no longer a component: the reference is
  the variable name, and reading or writing `…$GoCBRef` answers
  `object-non-existent`. `FixedOffs` always reads `FALSE`. A 0.3.x client
  fails to decode the GoCB of a 0.4.0 server and a 0.4.0 client fails to
  decode the GoCB of a 0.3.x server: **upgrade the client and the server
  together**.

  | Position | 0.3.x | 0.4.0 |
  |---|---|---|
  | 1 | GoCBRef | GoEna |
  | 2 | GoEna | GoID |
  | 3 | GoID | DatSet |
  | 4 | DatSet | ConfRev |
  | 5 | ConfRev | NdsCom |
  | 6 | NdsCom | DstAddress |
  | 7 | DstAddress | MinTime |
  | 8 | MinTime | MaxTime |
  | 9 | MaxTime | FixedOffs |

- **`iec61850-server`** — GoCB `DatSet` reads as the complete reference
  `<LD>/LLN0$<dsName>` (IEC 61850-8-1 §8.1.3.2.2), and registering a GoCB
  whose publisher names its data set without a domain qualifies the
  publisher's datSet, so the published GOOSE carries the same reference. A
  subscriber that matched the LN-relative name matches the qualified one.
  Only the server changes.
- **`iec61850-server`** — GoCB `MinTime` and `MaxTime` are the publisher's T1
  and Tmax, 4 and 1000 ms by default, instead of 0 when they were not
  configured twice; every GoCB value is read from the `GoosePublisher`. Only
  the server changes.
- **`iec61850-server`** — With `IedServerConfig::edition` set to
  `Edition::Ed2_1`, writes of GoCB `GoID` and `DatSet` answer
  `object-access-denied` (IEC 61850-8-1 Table 83). Under the default `Ed2` a
  client may now write `DatSet` while `GoEna` is `FALSE`: the write accepts a
  reference with or without its domain and increments `ConfRev`, also when
  the value is unchanged (IEC 61850-7-2 §18.2.1.6); it answers
  `temporarily-unavailable` while `GoEna` is `TRUE`, and
  `object-value-invalid`, changing nothing, when the reference names a data
  set the server does not hold or an association-scope one (`@<name>`,
  IEC 61850-8-1 Table 83). The application reads
  `GoosePublisher::data_set_ref()` to learn which data set to publish. The
  edition affects nothing else, and `Ed1` behaves as `Ed2`. A peer that wrote
  `GoID` or `DatSet` against an `Ed2_1` server leaves them alone; one that
  relied on `DatSet` being read-only sees the write accepted under `Ed2`.
  Only the server changes.
- **`iec61850-scl`** — The members of a data object built from SCL follow the
  order its DOType declares them in: IEC 61850-6 §9.5.3 lets `<SDO>` and
  `<DA>` interleave, and IEC 61850-8-1 §7.3.1 makes that the member order on
  the wire. The SCL path used to put every attribute before every
  sub-object. A data object such as a SEQ (`c1`, `c2`, `c3`, `seqT`), WYE or
  DEL is now described, read, reported and placed in data sets with its
  members in the declared order, so **its MMS structure changes**. A client
  that cached the type of such a data object fetches it again; the two sides
  need not be upgraded together, but a client must not reuse a structure read
  from a 0.3.x server.
- **`iec61850-scl`**, **`iec61850-server`** — The `count` of an SCL `DA`,
  `BDA` or `SDO` builds an array, which the server serves as an MMS array
  (IEC 61850-8-1 §8.1.2.7). It used to be warned about and the attribute
  built as one element, so **the MMS type of such an attribute changes** from
  the element type to an array of it: GetVariableAccessAttributes and Read
  return an array, and one element is read through an alternate access
  index. Only the server needs to be upgraded.
- **`iec61850-server`** — `IedServer::register_from_model` registers a report
  control block once per instance the model declares, named `<name>01` to
  `<name>NN` when it is indexed, the SCL default (IEC 61850-8-1 §17.1.2,
  §17.1.3). An application that switches from registering a block by hand
  under `<name>` to `register_from_model` sees its clients address
  `<name>01` instead; a block registered by hand keeps its name. Only the
  server changes; its clients use the new names.
- **`iec61850-server`** — The `DatSet` attribute of URCBs, BRCBs and log
  control blocks, and the data-set-name field of reports, carry the fully
  qualified name `<LD>/<LN>$<data set>` of IEC 61850-8-1 §8.1.3.2.2, for
  example `IED1LD0/LLN0$dsPos`, also for a control block registered with
  `LLN0$dsPos`. A `DatSet` write still accepts the name without the logical
  device, so a client that writes back what a 0.3.x server reported keeps
  working; a client that compares `DatSet` with the LN-relative name
  compares with the qualified one. Only the server changes.
- **`iec61850-server`** — An attribute update compares the new value with the
  old one and raises only the triggers the attribute declares, following the
  TrgOp of IEC 61850-7-2 Table 21: a changed value raises data-change for
  `dchg`, quality-change for `qchg` and data-update for `dupd`; an unchanged
  value raises data-update for `dupd` and nothing else, and an attribute that
  declares no trigger option raises nothing. Rewriting a value with itself
  used to send a data-change report and write a data-change log entry, every
  change raised data-change whatever the attribute declared, and no update
  ever raised data-update. Each report control block keeps the reasons its
  `TrgOps` enable, so a report carries only enabled reasons, and a block that
  enables only `dupd` is triggered. A client that relied on a report after
  each update receives one only when the value changes, or with reason
  data-update when the attribute declares `dupd` and the block enables it;
  the encoding is unchanged and the two sides need not be upgraded together.
  See [Server applications](docs/migration-0.4.md#server-applications).
- **`iec61850-server`** — Reports are segmented at the maximum MMS PDU size
  the association negotiated, counting the whole MMSpdu as IEC 61850-8-1
  defines max_mms_pdu_size, instead of at a fixed 65000 bytes. A client that
  proposes a small size now receives more, smaller segments: a general
  interrogation or a large buffered entry that used to arrive as one PDU
  arrives as several, each within the negotiated size, with SubSeqNum and
  MoreSegmentsFollow set, and every segment of a buffered entry carries its
  EntryID and TimeOfEntry. A client reads every segment; the two sides need
  not be upgraded together.
- **`iec61850-server`** — An association is released the way ACSE defines:
  after the Conclude response the server sends nothing of its own and waits
  for the client's Session FINISH carrying an ACSE RLRQ, which it answers with
  a Session DISCONNECT carrying the RLRE before closing the connection. It
  used to send a FINISH with no user data right after the Conclude response,
  answer the client's FINISH with an empty DISCONNECT, and recognise an RLRQ
  only in a data transfer. A FINISH without an RLRQ, and an ACSE PDU other
  than an abort in a data transfer, are now protocol errors answered with an
  A-ABORT. A client that never sends the FINISH is still disconnected after
  the conclude timeout, 10 seconds by default. A peer that waited for the
  server's FINISH before sending its own now waits until its own timeout; the
  `iec61850-mms` client has sent the RLRQ in a FINISH since 0.3.3 and needs no
  change. Only the server needs to be upgraded.
- **`iec61850-server`** — A refused association, for failed authentication,
  an AARQ that carries no Initiate request or a refused Initiate, is answered
  with a Session REFUSE (reason code 2) carrying a Presentation CPR for a user
  rejection, whose user data is the AARE with a rejected result; the AARE of a
  refused Initiate carries the Initiate-ErrorPDU as its user information. The
  refusal used to travel in a Presentation CPA and a Session ACCEPT, and a
  refused Initiate dropped its Initiate-ErrorPDU. The `iec61850-mms` and
  `iec61850-client` clients report it as
  `ClientError::SessionRefused { reason_code: Some(2), .. }` where they used
  to report `AssociateFailed` or `InitiateFailed`, and a refusal whose AARE
  diagnostic names the calling identity or the authentication as
  `ClientError::AuthenticationRejected` (see API). Only the server changed;
  a client that matched the old errors matches `SessionRefused` as well,
  except that a 0.4 client reports a refusal for the calling identity or the
  credentials as `AuthenticationRejected`.
- **`iec61850-mms`**, **`iec61850-server`** — The CPA answers each
  presentation context of the CP in its order: acceptance for ACSE and MMS
  offered with the BER transfer syntax, provider-rejection
  (abstract-syntax-not-supported or proposed-transfer-syntaxes-not-supported)
  otherwise. It used to carry two acceptances whatever the CP proposed, and a
  CP naming another abstract syntax was dropped unanswered. A CP without an
  acceptable ACSE and MMS context is refused with a Session REFUSE carrying a
  CPR with provider-reason reason-not-specified. A client that proposes only
  ACSE and MMS sees no difference. Only the server changes; the bytes the
  `iec61850-mms` client sends are unchanged.
- **`iec61850-mms`** — A Session FN from the peer in the middle of an
  association is answered with a Session DN carrying an ACSE RLRE before the
  client closes; the client used to close the transport without an answer.
  Nothing changes for a peer that never sends an FN. The Initiate request
  carries the configured `max_outstanding` (default 5, as before). Only the
  client changes.
- **`iec61850-goose`** — GOOSE frames are tagged with 802.1Q by default, as
  IEC 61850-8-1 Annex C.2.2 requires: `CommParameters::new` starts from
  priority 4 and VID 0. Peers see a 4-byte tag (`81 00 80 00`) after the
  source address on frames from publishers that never set one, and a server
  GoCB's `DstAddress` reads PRIORITY 4 instead of 0 for such parameters.
  Receivers must accept tagged frames (Annex C.2.4), so no peer upgrade is
  needed; `CommParameters::without_vlan` keeps untagged frames.
- **`iec61850-sv`** — Sampled Values frames are tagged with 802.1Q by
  default, as IEC 61850-9-2 Table 6 requires, with the Table 7 defaults of
  priority 4 and VID 0: `SvPublisherBuilder::new` starts from
  `VlanTag::default()`. Peers see a 4-byte tag (`81 00 80 00`) after the
  source address and the savPdu at `SV_HEADER_WITH_VLAN`; receivers must
  accept tagged frames, so no peer upgrade is needed.
  `SvPublisherBuilder::without_vlan` keeps untagged frames.
- **`iec61850-server`** — Writing `RptEna = FALSE` to a URCB no longer
  releases its reservation. The URCB stays reserved for its holder until the
  holder writes `Resv = FALSE` or its association ends, as IEC 61850-7-2 has
  Resv set and cleared by the client. A peer now reads `Resv = TRUE` after
  disabling, can reconfigure the URCB without reserving it again, and other
  clients keep getting `temporarily-unavailable` for `Resv` and
  `object-access-denied` for the other attributes. A client that disabled a
  URCB to free it for another client writes `Resv = FALSE` as well. Only the
  server changes.
- **`iec61850-server`** — Writing `RptEna = TRUE` to a URCB that no client
  has reserved reserves it for the writer and enables it, as
  IEC 61850-7-2 requires, instead of answering `object-access-denied`. A
  client that enables reporting without writing `Resv` first now receives
  reports. Writes of the other attributes of an unreserved URCB are
  described under Changed. Only the server changes.
- **`iec61850-server`** — A write of `GI = TRUE` to a URCB or a BRCB whose
  `RptEna` is false is answered with `temporarily-unavailable` and sets `GI`
  to false, as the general interrogation state machine of IEC 61850-7-2
  §17.2.2.13 requires before reporting is enabled; it used to be answered
  with success and ignored. Within one Write request a `GI = TRUE` that
  follows a successful `RptEna = TRUE` is accepted, and `GI = FALSE` is
  accepted in either state. A client that wrote `GI` before enabling writes
  it after `RptEna`; `IedConnection::set_rcb_values` already writes it last.
  Only the server changes.
- **`iec61850-server`** — A report control block registered from an SCL
  model has the optional `Owner` attribute (IEC 61850-7-2 Tables 37 and 39)
  only when the file declares `<ReportSettings owner="true">`, and a BRCB has
  the optional `ResvTms` attribute (Table 37) only when it declares
  `<ReportSettings resvTms="true">`; IEC 61850-6 defaults both to false. Every
  control block used to have `Owner`, and every BRCB `ResvTms`. For a control
  block without one of them a peer no longer sees it in GetNameList,
  GetVariableAccessAttributes or a Read of the control block, a Read or Write
  of it answers
  `object-non-existent`, and a BRCB without `ResvTms` is reserved by enabling
  it. A control block registered in code keeps them unless configured
  otherwise. Only the server changes; a server that should keep serving them
  declares them in its SCL file. See
  [SCL and scl-build](docs/migration-0.4.md#report-settings-and-trigger-options).
- **`iec61850-server`** — The holder of an enabled URCB can no longer write
  `Resv`, and the holder of an enabled BRCB can no longer write `ResvTms`;
  both are refused with `temporarily-unavailable`, per IEC 61850-8-1 Tables 72
  and 73. Writing `Resv = FALSE` to an enabled URCB used to answer success and
  keep the reservation. A client writes `RptEna = FALSE` before releasing a
  control block; one that sends `Resv = TRUE` together with `RptEna = TRUE` to
  a URCB it has already enabled now gets `temporarily-unavailable` for
  `Resv`. Only the server changes.
- **`iec61850-server`** — A BRCB increments `ConfRev` only when `DatSet`
  changes; a change of `OptFlds`, `BufTm`, `TrgOps`, `IntgPd` or `RptID` no
  longer counts. A change of `RptID`, `DatSet`, `BufTm`, `TrgOps` or `IntgPd`
  still purges the buffer, and a change of `OptFlds` no longer does anything
  to it, per IEC 61850-8-1 Table 72. A peer that compares `ConfRev` with the
  configured value no longer sees it drift after adjusting a BRCB. Only the
  server changes.
- **`iec61850-server`** — An enabled BRCB refuses a write of `EntryID` or
  `PurgeBuf` with `temporarily-unavailable`, per IEC 61850-8-1 Table 72. It
  used to accept `EntryID`, so writing all zeros resent the whole buffer as
  duplicate reports, and to answer success to `PurgeBuf` without purging. A
  client writes `RptEna = FALSE` first, as `IedConnection::set_rcb_values`
  already does when `RPT_ENA` is in the mask. A SetBRCBValues write of
  `TimeofEntry` is answered `object-access-denied`, as a read-only attribute
  is, instead of `object-access-unsupported`. Only the server changes.
- **`iec61850-server`** — A buffered report control block sets `BufOvfl` in
  the first report it sends after every transition of `RptEna` from false to
  true, and clears it in the reports after it (IEC 61850-7-2
  §17.2.3.2.2.8). It used to set it only in the first report sent from the
  head of the buffer, after the first enable or an all-zero `EntryID`. A
  client enabling a BRCB again, after it resynchronized on an `EntryID` or
  carried on after the last entry sent, sees `BufOvfl = TRUE` in the first
  report. Only the server needs to be upgraded.
- **`iec61850-server`** — A journal is named only by the `LogRef` of a log
  control block. The key a control block is registered under, such as
  `MMXU1$LG$lcb01`, no longer names a journal, so the journals GetNameList
  lists are exactly the journals ReadJournal reads. A peer that read a
  journal through the path of its control block sees `object-non-existent`
  and reads it through the LogRef, readable as `<LCB>$LogRef` (FC LG); a
  client that already used the LogRef needs no change.
- **`iec61850-server`** — The server keeps the values of every setting group
  (IEC 61850-7-2 §16). Each FC=SG and FC=SE setting starts with the
  `<Val sGroup="n">` of the model for each group, and the value of the
  attribute for a group the model gives none; the FC=SG attributes start at
  the values of the active group. SelectActiveSG loads the selected group into
  FC=SG, SelectEditSG loads the selected group into FC=SE, and
  ConfirmEditSGValues stores FC=SE into the edited group and, when that group
  is active, loads it into FC=SG. A client reading FC=SG after SelectActiveSG
  reads the values of the new group, where it used to read whatever the
  application had written, and a group edited and committed while another is
  active reads its committed values once selected. The two sides need not be
  upgraded together.
- **`iec61850-server`** — A read of FC SE, directly or as a GetDataSetValues
  member, answers `temporarily-unavailable` while no setting group is selected
  for editing (EditSG = 0) or the logical device has no setting group control
  block (IEC 61850-7-2 §16.2.2.5 Table 20), and a write of FC SE by an
  association that does not hold the edit session answers
  `temporarily-unavailable` instead of `object-access-denied`
  (IEC 61850-8-1 §8.1.3.4.4.2). A read of a whole logical node still returns
  the edit buffer values, and a write the access policy refuses still answers
  `object-access-denied`. A client selects an edit group before reading SE,
  and treats both errors of an SE write as "no edit session". Only the server
  needs to be upgraded.
- **`iec61850-server`** — A write is held to the type the attribute declares
  in GetVariableAccessAttributes, and a refused value leaves the attribute
  unchanged: an integer outside the range of its width answers
  `object-value-invalid` (IEC 61850-8-1 §8.1.1 Table 15), and a visible,
  Unicode or octet string, or a binary time, of another length than a fixed
  size or longer than a maximum one answers `type-inconsistent`
  (§8.1.3.4.4.2); a Unicode string is measured in characters. A bit string
  written with fewer bits than its `Max(n)` size, such as a 9-bit Quality, is
  stored with n bits, the missing bits zero (§8.1.2.1), so it reads back at
  the full length (§8.2). Writes that used to succeed with such values now
  fail. Only the server needs to be upgraded.
- **`iec61850-server`** — A Select of an object that is already selected is
  refused whichever client sends it, as SelectWithValue already was; the
  object keeps its selection and its select timeout. A client that reselected
  to restart the timeout sends Cancel and selects again. Only the server
  changes.
- **`iec61850-server`** — An Operate carrying an activation time `operTm`
  other than 0 is refused with the add cause Not-supported instead of being
  executed at once; TimeActivatedOperate is not supported. A client sends
  `operTm` 0. Only the server changes.
- **`iec61850-server`** — A control object follows the `ctlModel`,
  `sboTimeout`, `sboClass` and `operTimeout` attributes the model declares
  for its data object, read at each request, so writing one of them over MMS
  or through `IedServer::update_*` takes effect at the next request; a
  selection or command already under way completes under the settings it
  started with. An attribute the model does not declare, or a value out of
  range, falls back to `ControlObjectConfig`. Where the configuration and the
  model disagree, a client now sees the control model the model declares.
  Only the server changes.
- **`iec61850-client`** — `set_rcb_values` writes the GI value the
  `RcbHandle` holds, set with `RcbHandle::set_gi`. It used to write
  `GI = TRUE` whenever the mask named GI, so `set_gi(false)` had no effect,
  and on a reserved control block that is not enabled a server following
  IEC 61850-7-2 §17.2.2.13, as this crate's now does, refused the write with
  `temporarily-unavailable`. A peer now receives `GI = FALSE`
  from a handle whose GI is false, one whose GI was never set included; set
  it to true to request a general interrogation.
  `IedConnection::trigger_grefcb` still writes `GI = TRUE`. Only the client
  changes. See [GI writes](docs/migration-0.4.md#gi-writes).
- **`iec61850-goose`** — A received GOOSE whose timestamp `t` carries one of
  the TimeAccuracy codes 25 to 30, which IEC 61850-8-1 §8.1.3.7 Table 36
  defines as invalid, fails decoding with the new
  `GooseError::InvalidTimestampQuality`; the receiver logs it and drops the
  frame like any other malformed PDU, without calling the listener. Every
  other `t`, a NULL one and one with ClockFailure set included, is delivered
  as before: its value is not judged. A publisher of this crate cannot
  produce such a code, so no simultaneous upgrade is needed. See
  [Timestamps as UtcTime](docs/migration-0.4.md#timestamps-as-utctime).
- **`iec61850-sv`** — A received Sampled Values ASDU whose `refrTm` carries
  one of the TimeAccuracy codes 25 to 30 (IEC 61850-8-1 Table 36) fails
  decoding with the new `SvError::InvalidRefrTm`, and the frame is dropped as
  any other malformed frame is. Every other `refrTm` is delivered as before;
  its distance from the local clock and its quality flags are left to the
  listener. A publisher of this crate cannot produce such a code, so no
  simultaneous upgrade is needed. See
  [Timestamps as UtcTime](docs/migration-0.4.md#timestamps-as-utctime).
- **`iec61850-scl-build`** — `iec61850-scl-build` and `iec61850-scl` must be
  the same version, and the workspace pins `iec61850-scl` with an exact
  version requirement; a `model.rs` generated by an older
  `iec61850-scl-build` must be regenerated. The generated model of a data
  object follows the declared member order and builds arrays from `count`,
  as above.

#### API

- **every crate** — The public error, outcome and code enums and the
  configuration, context, parameter, state, report, control block and model
  node structs of every crate are `#[non_exhaustive]`, so later releases can
  add a variant or a field without a breaking change. This covers enums
  such as `ClientError`, `ServerError`, `MmsError`, `ControlOutcome`,
  `ControlAddCause`, `TlsError`, `DataAttributeType` and `MmsLeafType`, and
  structs (for example `IedServerConfig`, `MmsModelDispatcher`,
  `ReadContext`, `ControlObjectConfig`, `IsoConnectionParameters`,
  `ServiceError`, `LogicalNode`, `ReportControlBlock`, `DataSetEntry`,
  `GoosePdu`, `Asdu`, `SntpServerConfig`, and the SCL raw element types).
  Value enums fixed by the standard (`FC`, `MmsValue`, `Dbpos`,
  `ControlModel`, `OrCat`, the state machine states and similar) and the
  protocol structures that callers build field by field (`TrgOps`, `Quality`,
  the selectors, and the MMS PDU structs other than `ServiceError`,
  `IdentifyResponse`, `StatusResponse`, `ReadJournalRequest`,
  `WireJournalEntry` and `WireJournalVariable`) are unchanged. A `match`
  outside the crate needs a wildcard arm, and an affected struct is built
  from `Default`, a constructor or a builder instead of a struct literal;
  code generated by `iec61850-scl-build` calls the new constructors. See
  [Every crate](docs/migration-0.4.md#every-crate).
- **every crate** — Each struct variant of a public error or event enum is
  `#[non_exhaustive]` as well: the struct variants of the error enums of
  every crate, of `InitiateRejectReason`, of the MMS server's
  `MessageOutcome` and `InitiateOutcome`, of `ConfigChangeResult`, of the
  server's `TerminationEvent` and `ConnectionTerminationEvent`, of
  `GooseEvent` and of `SntpClockStatus`, so a field can be added later
  without a breaking release. An error or event variant cannot be built with
  a struct expression outside its crate, and a pattern on it ends in `..`:
  `Err(ClientError::Timeout { after_ms })` becomes
  `Err(ClientError::Timeout { after_ms, .. })`, and an `assert_eq!` against
  such a variant becomes `matches!`. Value variants, which describe data,
  names, types or PDUs (`MmsValue`, `MmsData`, `ObjectName`,
  `TypeSpecification`, `CotpPdu`, `MmsTypeSpec`, `MmsLeafType`,
  `AlternateAccessSelector`), stay constructible and can be matched
  exhaustively. Code that reports one of these errors itself, such as a test
  double of a peer, uses the constructors listed under Added.
- **`iec61850-hal`** — `TransportError` carries the cause of a failure.
  `Io { kind, detail }` holds an `IoErrorKind`, available without `std` and
  convertible to and from `std::io::ErrorKind`, and the text of the
  underlying error when the backend has one, such as a fatal TLS alert
  received on an established association. `Closed { kind }` records how
  the close was observed, and `Other` is removed. Both struct variants are
  `#[non_exhaustive]` and are built with `TransportError::io`, `closed` and
  `with_detail`; the type is no longer `Copy`. `TransportError::Io` becomes
  `TransportError::io(IoErrorKind::Other)`; see
  [MMS and transport layers](docs/migration-0.4.md#mms-and-transport-layers).
- **`iec61850-tls`** — `TlsAcceptor::accept` and `TlsConnector::connect`
  return `iec61850_tls::TlsStream`, which reads and writes through `AsyncRead`
  and `AsyncWrite` and exposes the peer certificates, the negotiated version
  and cipher suite, whether the session was resumed, and the underlying
  transport, instead of the stream types of tokio-rustls.
  `stream.get_ref().1.peer_certificates()` becomes
  `stream.peer_certificates()`. `iec61850-mms` no longer depends on
  tokio-rustls. See [TLS](docs/migration-0.4.md#tls).
- **`iec61850-tls`** — A failed handshake is classified by its cause: a
  rejected or missing peer certificate is `TlsError::Verification`, no cipher
  suite or key exchange group in common is `CipherUnsupported`, no version in
  common is `VersionUnsupported`, any other TLS error such as an alert from
  the peer is `Handshake`, and a transport failure with no TLS error is `Io`.
  Every handshake failure used to be `Io`. The three classified variants
  carry the `rustls::Error` instead of a string, and `From<rustls::Error>`
  applies the same classification. Nothing changes on the wire.
- **`iec61850-tls`** — `TlsConfigBuilder::chain_validation` and
  `renegotiation_interval` are removed; chain validation always runs and no
  renegotiation is initiated, so both only logged a warning. Drop the calls.
- **`iec61850-model`** — `IedModel::node_by_object_ref` honors the functional
  constraint the `ObjectRef` carries: with `r.fc` set, an attribute named
  right below a data object resolves only under that constraint.
  `DataObject::child_by_name` takes the constraint as a second argument, and
  `IedModel::node_by_object_ref_fc` and `DataObject::child_by_name_fc` are
  removed: `child_by_name("stVal")` becomes `child_by_name("stVal", None)`,
  and `node_by_object_ref_fc(&r, fc)` sets `r.fc = Some(fc)` and calls
  `node_by_object_ref`. See
  [SCL and scl-build](docs/migration-0.4.md#scl-and-scl-build).
- **`iec61850-model`** — A `DataSetEntry::do_path` segment holds one name; a
  segment containing `.` no longer resolves, and `IedModelBuilder::build`
  rejects the entry with `DataSetEntryUnresolved`. `"mag.f"` becomes two
  segments, `"mag"` and `"f"`.
- **`iec61850-model`** — The elements of an array data object are its
  children, one per element, instead of one template element; read the
  template as `element(0)`. An object reference index resolves to the
  element, and a data set entry index must name an element of an array on its
  path, else the build fails.
- **`iec61850-mms`** — `CotpError::Io` carries the `TransportError` instead of
  its text; call `to_string()` where the text was used. The MMS client reports
  an I/O failure of the transport, including a refused TCP connection and a
  TLS alert on an established association, as the new
  `ClientError::Transport` with that
  cause, instead of `ConnectionLost` or a string inside `IsoError`. The end of
  the transport and a COTP disconnect remain `ConnectionLost`; a caller that
  treated `ConnectionLost` as the end of the connection also handles
  `Transport(_)` and `ReleasedByPeer`.
- **`iec61850-mms`** — `MmsClientBuilder::max_outstanding` takes a `u16` and
  is the proposedMaxServOutstandingCalling of the Initiate request:
  `max_outstanding(8u32)` becomes `max_outstanding(8u16)`.
- **`iec61850-mms`** — `ClientError::ServiceError` carries the
  serviceSpecificInformation of the ServiceError as
  `service_specific: Option<ServiceSpecificInfo>`; a refused DeleteDataSet
  reports how many data sets the server deleted as
  `ServiceSpecificInfo::DeleteNamedVariableList(n)`. A pattern on the variant
  ends in `..`, and code that builds it calls
  `ClientError::service_error(error_class)`, followed by
  `with_service_specific(info)` when needed.
- **`iec61850-mms`**, **`iec61850-client`** — A failed TLS handshake in
  `connect_tls` returns `ClientError::TlsHandshake { kind, message, .. }`,
  whose `TlsFailureKind` says why the handshake failed, instead of
  `ClientError::IsoError(..)` in `iec61850-mms` or `ClientError::Mms(..)` in
  `iec61850-client`. Code that looked for the handshake in the error text
  matches the variant: `Err(ClientError::TlsHandshake { kind:
  TlsFailureKind::Verification, .. })` for a rejected certificate. A TLS
  error from the end of the handshake until the MMS Initiate response is
  accepted is a `TlsHandshake` as well, classified the same way: a TLS 1.3
  server refuses a missing or rejected client certificate after the client
  has completed its side of the handshake, and the client reads that fatal
  alert during the COTP exchange, as the `AlertReceived` kind with the alert
  named in `message`. A transport failure with no TLS error behind it, and a
  TLS error on an established association, are `Transport`. Nothing changes
  on the wire. See [TLS](docs/migration-0.4.md#tls).
- **`iec61850-mms`** — `PresentationError::UnknownAbstractSyntax` and
  `PresentationError::InvalidTransferSyntax` are removed. `parse_connect` no
  longer fails for an unsupported abstract or transfer syntax; it records a
  rejection for that context, and a caller checks
  `IsoPresentation::accepts_acse_and_mms` after it.
- **`iec61850-mms`**, **`iec61850-server`** — `JournalRange` is removed:
  `ReadJournalRequest` carries `range_start`, `range_stop`,
  `list_of_variables` and `entry_to_start_after`. `ReadJournalRequest`,
  `WireJournalEntry` and `WireJournalVariable` are non-exhaustive and are
  built with `ReadJournalRequest::new` and its `with_` methods,
  `WireJournalEntry::new` and `WireJournalVariable::new`;
  `ReadJournalRequest::time_range` and `start_after` are unchanged.
- **`iec61850-mms`** — `AlternateAccessSelector` is `#[non_exhaustive]` and
  gains `Component`; a `match` on it needs a wildcard arm.
- **`iec61850-mms`** — `DefineNamedVariableEntry` is `#[non_exhaustive]` and
  gains `alt_access`, an optional alternate access selecting an array element
  and components inside it. Build an entry with
  `DefineNamedVariableEntry::domain(domain_id, item_id)` and add the selection
  with `with_alt_access`: `DefineNamedVariableEntry { domain_id, item_id }`
  becomes `DefineNamedVariableEntry::domain(domain_id, item_id)`. See
  [MMS and transport layers](docs/migration-0.4.md#mms-and-transport-layers).
- **`iec61850-mms`** — An AARQ naming an authentication mechanism other than
  the password one, or carrying a password value that is not a charstring,
  presents its credentials to an `AcseAuthenticator` as the new
  `AcseAuth::Other { mechanism, value }`; it used to present them as
  `AcseAuth::None`, so an authenticator that accepted `None` accepted them as
  well. An authenticator that matches `AcseAuth` decides on `Other` too. The
  AARQ on the wire is the same. See
  [ACSE credentials and refused authentication](docs/migration-0.4.md#acse-credentials-and-refused-authentication).
- **`iec61850-mms`**, **`iec61850-client`** — A rejecting AARE whose
  acse-service-user diagnostic refuses the calling AP-title, AE-qualifier or
  invocation identifier, or the authentication, is reported as the new
  `ClientError::AuthenticationRejected { diagnostic }`, whether it arrives in
  a Session ACCEPT or inside the CPR of a Session REFUSE; it used to be
  reported as a failed association or as `SessionRefused`. Other refusals
  are reported as before, and
  `AcseServiceUserDiagnostic::is_authentication_refusal` gives the rule. See
  [ACSE credentials and refused authentication](docs/migration-0.4.md#acse-credentials-and-refused-authentication).
- **`iec61850-mms`** — `BlockingMmsClient::into_inner` is replaced by
  `BlockingMmsClient::into_parts`, which returns the `MmsClient` together
  with the Tokio runtime that owns the socket and timers of its association.
  The client `into_inner` returned still reported `Connected`, but its first
  request failed because the runtime had been dropped with the wrapper.
  Drive a connected client on the returned runtime,
  `rt.block_on(client.read(..))`, and, as with the wrapper, do not drop that
  runtime inside an async runtime. See
  [Blocking MMS client](docs/migration-0.4.md#blocking-mms-client).
- **`iec61850-goose`** — `GoosePdu::go_id` is a `String`, and `GoosePdu::new`
  sets it to the gocbRef: `pdu.go_id = None` becomes
  `pdu.go_id = pdu.gocb_ref.clone()`. The wire format is unchanged.
- **`iec61850-goose`** — A GOOSE subscriber applies its APPID and destination
  MAC filters whether or not a gocbRef filter is set. `observer()` means "any
  gocbRef": it drops a gocbRef filter set on the same builder and keeps the
  other filters. A subscriber with no filter at all still accepts every
  frame. A subscriber that set `app_id(..)` or `dst_mac(..)` without a
  gocbRef and relied on receiving everything drops those calls. See
  [GOOSE and Sampled Values](docs/migration-0.4.md#goose-and-sampled-values).
- **`iec61850-goose`** — `GooseReceiver::set_interface_id` and
  `GooseReceiver::interface_id`, which `start_thread` never read, are
  removed; choose the interface when opening the source. `GooseFrame` is
  `#[non_exhaustive]` and is built with `GooseFrame::new`.
- **`iec61850-goose`** — The timestamp `t` is a `UtcTime`: `GoosePdu::t` is a
  `UtcTime`, which `GoosePdu::new` sets to `UtcTime::NULL`, the same eight
  zero octets as before; `GoosePublisher::set_timestamp` takes a `UtcTime`;
  and `GooseSubscriberState::timestamp_raw: [u8; 8]` is replaced by
  `GooseSubscriberState::timestamp: UtcTime`. Eight encoded octets become a
  `UtcTime` with `UtcTime::from_bytes` and come back with `to_bytes`. See
  [Timestamps as UtcTime](docs/migration-0.4.md#timestamps-as-utctime).
- **`iec61850-sv`** — `SmpMod::Unknown` holds a `u16`, and
  `SvPublisherBuilder::set_smp_mod` takes a `u16`; an smpMod above 255 is now
  decoded and kept instead of dropped. `SmpMod::from_byte` and
  `SmpMod::to_byte` are replaced by `from_u16` and `to_u16`.
- **`iec61850-sv`** — `SvError::Other(String)` is replaced by
  `SvError::Platform(EthernetError)`: an `EthernetSink` that returned
  `Err(SvError::Other(e.to_string()))` returns `Err(e.into())`. `SvFrame` is
  `#[non_exhaustive]` and is built with `SvFrame::new`.
- **`iec61850-sv`** — The `tokio-runtime` feature, which enabled no code, is
  removed; drop it from the features. The feature of the same name in
  `iec61850-goose` stays.
- **`iec61850-sv`** — `refrTm` is a `UtcTime`: `Asdu::refr_tm` and
  `SvSubscriberAsdu::refr_tm` are `Option<UtcTime>` instead of
  `Option<[u8; 8]>` and `Option<&[u8; 8]>`, and `SvPublisher::set_refr_tm`
  takes a `UtcTime`. See
  [Timestamps as UtcTime](docs/migration-0.4.md#timestamps-as-utctime).
- **`iec61850-scl`** — The code generation support is a single hidden module,
  `__private`; `iec61850_scl::build_model` (with its public helpers),
  `iec61850_scl::__rt` and `iec61850_scl::__build_internals` are removed.
  Code that used `build_model::b_type_to_dat`, `parse_fc` or the other
  helpers works with the model types instead.
- **`iec61850-scl`** — `RawDoType::das` and `RawDoType::sdos` are replaced by
  `children`, which keeps the declared order, and the `das()` and `sdos()`
  iterators. `RawDaDef::count` is an `Option<RawCount>`, and `RawBda` and
  `RawSdoDef` carry one.
- **`iec61850-scl`** — The raw `<LogControl>` defaults `reasonCode` to true,
  as IEC 61850-6 `tLogControl` does, and `<RptEnabled max>` is read from the
  child element; the attribute `rptEnabledMax`, which IEC 61850-6 does not
  define, is no longer read.
- **`iec61850-scl`** — `SclParseError` displays as "SCL error at …" instead of
  "SCL parse error at …", since it also reports stage 2 and model build
  failures.
- **`iec61850-scl`** — The `<Communication>` section is read instead of
  skipped with a warning (IEC 61850-6 §9.4): its subnetworks, the connected
  access points with their addresses, and the `<GSE>`, with `MinTime` and
  `MaxTime`, and `<SMV>` addressing of the control blocks.
  `RawScl::communication` holds the raw section, and the model of the IED
  carries its addressing, built at run time and generated by
  `iec61850-scl-build` alike. A file that used to load may now be rejected,
  each error carrying the line, column and element path: the section follows
  the structure and uniqueness rules of the SCL schema, and the model build of
  an IED rejects a `<ConnectedAP>` of that IED naming no access point of it,
  a `<GSE>` or `<SMV>` of it naming no control block of that access point,
  and a `MinTime` above its `MaxTime`; such a reference of another IED, and a
  `<ConnectedAP>` naming an IED the file does not declare, are only logged as
  warnings and skipped. Every `<P>` value is compared with the schema form
  of its type (IEC 61850-8-1 §25.3.1 Table 162, §25.3.2 Table 163, §25.3.3
  Table 164, IEC 61850-9-2 Clause 11 Table 19), whether or not the element
  carries `xsi:type`. A value in another form is logged as a warning with its
  position, type, value and the schema form, and kept as written: one that
  reads without ambiguity, such as a lower-case MAC address, a VLAN-ID of one
  or two digits, or an AP title or OSI selectors separated by white space, is
  read by the accessors of `Address`; one that cannot be read is read as
  `None` and fails only where it is used. A `<P>` of no address parameter
  type, or with an empty value, is left out with a warning.
  A fractional `MinTime` or `MaxTime` is rounded to whole milliseconds with a
  warning. `<PhysConn>` is skipped, and `<Substation>` is still skipped with
  a warning. See
  [Communication section](docs/migration-0.4.md#communication-section).
- **`iec61850-scl`** — Stage 2 checks the `datSet` of every
  `<ReportControl>`, `<LogControl>`, `<GSEControl>` and
  `<SampledValueControl>` against the `<DataSet>` elements of its own logical
  node, as the keys of the SCL schema require (IEC 61850-6 Annex A.4). A
  `datSet` the logical node does not declare fails resolution with the new
  `ErrorKind::UnresolvedDataSetReference`, located at the control block and
  its `datSet` attribute; an absent or empty `datSet` is accepted as before.
  A file that resolved with such a reference, and built a control block that
  named nothing, is now rejected. See
  [Control block data set references](docs/migration-0.4.md#control-block-data-set-references).
- **`iec61850-scl-build`** — A model the run-time build rejects is reported as
  `CompileError::BuildModel { ied, source, .. }`, located at the offending
  element; an unresolved data set member points at its `<FCDA>`.
  `CompileError::ResolveScl` covers stage 2 only. The run-time models are
  built before anything is emitted. `tokens::emit_default_mms_value(dat)` is
  removed; use `tokens::emit_mms_value(&MmsValue::default_for(dat))`.
- **`iec61850-sntp`** — `SntpServerConfig::poll` is removed; a reply copies
  the poll field of its request, so the setting had no effect.
  `SntpServerConfig` holds an `SntpClock` and is no longer `Copy`; clone it
  instead. See [SNTP](docs/migration-0.4.md#sntp).
- **`iec61850-client`** — `ClientError` carries the cause of an MMS layer
  error on typed variants instead of the text in `ClientError::Mms`:

  | Cause | Variant |
  |---|---|
  | Request timeout | `Timeout { after_ms, .. }` |
  | Connect timeout | `ConnectTimeout { after_ms, .. }` |
  | Peer closed the transport, sent a COTP DR or aborted | `ConnectionLost` |
  | Peer released the association | `ReleasedByPeer` |
  | Transport failure | `Transport(TransportError)` |
  | Confirmed-ErrorPDU | `Service { error_class, .. }` |
  | RejectPDU | `Reject { reason, .. }` |
  | Conclude refused | `ConcludeRejected` |
  | ACSE association refused | `AssociateFailed` |
  | Initiate-ErrorPDU | `InitiateFailed { error_code, .. }` |
  | Request above the negotiated PDU size | `PduTooLarge { pdu_size, max_size, .. }` |
  | Outstanding request limit held by timed-out requests | `OutstandingCallLimit` |
  | No association | `NotConnected` |
  | TLS handshake failure | `TlsHandshake { kind, message, .. }` |

  `Mms(String)` remains for failures with no variant of their own, such as a
  PDU that does not decode. A variant that replaces a `ClientError::Mms` text
  renders that same text, so log lines keep reading the same, with these
  exceptions: an MMS layer not-connected error, which rendered as
  `mms layer error: client is not connected (state: …)`, is now
  `NotConnected` and renders `connection is not established`; `Transport`
  renders `mms layer error: transport error: …` for failures the MMS layer
  used to report as a lost connection or an ISO error; `TlsHandshake`
  renders `mms layer error: TLS handshake failed: …` (`TLS handshake failed:
  …` in `iec61850-mms`) for a handshake failure that used to be reported as
  an ISO error; and `NameListLimit`, `NameListNotAdvancing` and
  `CommandTerminationTimeout` have texts of their own. Code matches on the
  variant instead of the text. `ClientError` derives `PartialEq`, and
  `ErrorClass`, `RejectReason`, `TransportError` and `IoErrorKind` are
  re-exported. See
  [Client applications](docs/migration-0.4.md#client-applications).
- **`iec61850-client`** — A GetNameList walk of the directory services that
  passes the name limit fails with `ClientError::NameListLimit { limit, .. }`
  instead of `ClientError::Mms`.
- **`iec61850-client`** — A GetNameList walk that the server does not move on
  fails with the new `ClientError::NameListNotAdvancing` instead of
  `ClientError::Mms`, also when a page that reports more names is empty,
  which used to end the walk with the names received so far. This applies to
  `get_server_directory`, `get_logical_device_directory`,
  `get_logical_node_directory`, `get_logical_node_variables`, the
  `get_data_directory` family and `get_device_model_from_server`. Code that
  looked for "does not advance" in the text matches the variant. The bytes on
  the wire are unchanged. See
  [Client applications](docs/migration-0.4.md#directory-walks).
- **`iec61850-client`** — `QueryJournalNotImplemented` is removed. The
  journal query is implemented and nothing returned this marker; delete the
  references to it.
- **`iec61850-client`** — `ControlOutcome::Failure` carries the LastApplError
  the server reported for the command, next to its AddCause:
  `Failure { add_cause, last_appl_error, .. }`. `last_appl_error` is the
  report sent ahead of the negative response to a refused Select,
  SelectWithValue, Operate or Cancel, or the one inside a negative
  CommandTermination. A normal-security server may refuse without one
  (IEC 61850-8-1 §20.7.5, §20.8.5), in which case it is `None` and
  `add_cause` is `Unknown`. The variant is `#[non_exhaustive]`;
  `ControlOutcome::is_success()`, `add_cause()` and `last_appl_error()` read
  an outcome without a match, and `ControlOutcome::failure(..)` and
  `LastApplError::new(..)` build one, for example in a test double.
  `ControlObjectClient::last_appl_error()` is removed; the LastApplError is
  part of the returned `ControlOutcome`.
- **`iec61850-client`** — `ControlObjectClient::select()` returns
  `Result<ControlOutcome, ClientError>` instead of `Result<bool, ClientError>`;
  a denied selection is `Failure` with the LastApplError the server sent, if
  any. IEC 61850-8-1 §20.5.5 does not require a LastApplError for a Select,
  so a denied selection may carry `None` and `Unknown` in any control model.
  `if spc.select().await?` becomes `if spc.select().await?.is_success()`.
- **`iec61850-client`** — An accepted enhanced-security Operate whose
  CommandTermination does not arrive within the wait, and a
  `wait_command_termination` call that times out, return
  `ClientError::CommandTerminationTimeout { after_ms, .. }` instead of
  `ClientError::Mms` with a text message.
- **`iec61850-client`**, **`iec61850-server`** — `ControlAddCause` and
  `ControlLastApplError` use the names of IEC 61850-8-1 §20.11 in both
  crates: `BlockedBySynchroCheck` is `BlockedBySynchrocheck`,
  `AbortionByCommand` (24) is `BlockedByCommand`, `TimeoutTest` is
  `TimeoutTestNotOk` and `OperationFailed` is `OperatorTestNotOk`. The wire
  values are unchanged.
- **`iec61850-client`** — `JournalQuery` is a struct of the four ReadJournal
  selections (`start`, `stop`, `variables`, `after`) with a builder method for
  each instead of an enum; `by_time` and `after_entry` still build
  QueryLogByTime and QueryLogAfter. A `match` on `JournalQuery::TimeRange`
  and `StartAfter` reads the fields instead.
- **`iec61850-client`** — `GoCBValues::go_cb_ref` is removed; the reference
  is the one passed to `get_gocb_values`. `GoCBValues::min_time_ms` and
  `max_time_ms` are `Option<u32>`.
- **`iec61850-server`** — The control setters and fields that had no effect
  are removed: `ControlObject::set_check_handler`,
  `set_wait_for_exec_handler` and `set_operate_handler`, the public
  `check_handler`, `wait_for_exec_handler` and `operate_handler` fields they
  wrote, and `ControlAction::set_add_cause` and `set_error`. The control
  services call the handlers of `ControlObjectEntry`, installed with
  `ControlObjectEntry::with_operate` and its siblings, and a handler reports
  its outcome through the `ControlAddCause` it returns.
- **`iec61850-server`** — `ControlObject::set_oper_timeout_ms` and
  `oper_timeout_ms` are removed; the operate timeout comes from the
  `operTimeout` attribute of the model, or else
  `ControlObjectConfig::oper_timeout_ms`.
- **`iec61850-server`** — `ControlState::WaitForActivationTime` and
  `WaitForSelect`, which no transition entered, and
  `ControlAction::ctl_time_ms`, which was 0 for every admitted command, are
  removed.
- **`iec61850-server`** — A `SelectStateChangedHandler` hears of every change
  of a selection, not only of its end: a select arrives with `is_selected`
  set and the reason `Selected`, and the end of an operate-once command and
  an Operate refused in a way that ends the selection arrive as
  `OperateDone` and `OperateRefused`. A handler that treated every call as a
  deselection tells them apart by `is_selected` and `reason`.
- **`iec61850-server`** — The `Error` member of a negative CommandTermination
  is decided by the control service: `CommandTerminationSink::send_negative`
  takes it as a `ControlLastApplError`, and the `Negative` variants of
  `TerminationEvent` and `ConnectionTerminationEvent` carry it as `error`.
- **`iec61850-server`** — The server maintains `stSeld` (IEC 61850-7-3): every
  change of the selection of a select-before-operate object registered with
  the server writes it, through the update path, before the selection change
  handler is called — set by a select, cleared by the end of an operate-once
  command, a refused Operate, a Cancel, the select timeout or a lost
  association — so a data set member `stSeld` is reported and logged on each
  change. An application that wrote `stSeld` from its handler stops doing so.
- **`iec61850-server`** — `GoCBHandle` holds only its names and the
  publisher: the fields `conf_rev`, `data_set_ref`, `go_id`, `nds_com`,
  `dst_address`, `min_time_ms`, `max_time_ms` and `GoCBHandle::go_id_snapshot`
  are removed, and `GoCBHandle::new` takes the logical device, logical node,
  name and publisher; set the values on the `GoosePublisher`.
  `apply_gocb_write` takes the `GoCBRegistry` first, which supplies the
  edition and the data set lookup, and `encode_gocb_structure` and
  `encode_gocb_da` return `Result<MmsData, DataAccessError>`.
  `GoCBRegistry::list_mms_names_in_domain`, which listed neither the
  `LLN0$GO` group nor the `DstAddress` members, is removed; use GetNameList,
  or `GoCBRegistry::item_bases_in_domain` for the registered blocks.
- **`iec61850-server`** — `handle_set_brcb_field` takes the `ConnectionId`
  the write arrived on, like `handle_set_rcb_field`;
  `handle_set_brcb_field_for_connection` is removed.
- **`iec61850-server`** — `RcbField` has `PurgeBuf`, `TimeOfEntry` and
  `ResvTms` variants, which `RcbField::from_name` returns for `"PurgeBuf"`,
  `"TimeofEntry"` and `"ResvTms"`; `RcbField::Unknown` carries only names the
  server does not recognize. `ConfigChangeResult::Applied`, which no write
  produced, is removed.
- **`iec61850-server`** — `BufferedReportControl::set_config_field` and
  `handle_purge_buf_write` return `BrcbWriteError` instead of `ServerError`:
  `ReportingEnabled` while `RptEna` is true, where `handle_purge_buf_write`
  used to return `Ok(0)`, and `Server` for a poisoned lock.
- **`iec61850-server`** — The SQLite report buffer (`sqlite-backend`) stores
  each entry's snapshot in a new `snapshot` column and marks the database
  with schema version 1 (`PRAGMA user_version`). A database created by 0.3.x
  is upgraded in place when it is opened; the entries it held before the
  upgrade carry no snapshot and are still reported with the values current
  at transmission, while entries enqueued afterwards keep their snapshot.
- **`iec61850-server`** — `ReportingEngine::new` and
  `ReportingEngine::new_with_channel_sink` take the data set registry that
  DatSet writes resolve against, and `set_dataset_registry` is removed:
  `let mut e = ReportingEngine::new(sink); e.set_dataset_registry(r);`
  becomes `let e = ReportingEngine::new(sink, r);`. Pass
  `DatasetRegistry::default()` where no DatSet write needs to resolve.
  `IedServer` is unaffected.
- **`iec61850-server`** — `ReportingEngine::flush_brcb_pending` and
  `flush_all_brcb_pending` no longer take a time argument, which they did not
  use.
- **`iec61850-server`** — `ReportEncodeError::PduTooSmall` means that the
  report fields alone exceed the limit or that a report needs more segments
  than SubSeqNum can number; a member too large for the limit is reported as
  the new `MemberTooLarge`. `reporting::engine::BACKPRESSURE_CLOSE_THRESHOLD`
  is removed: a full report channel no longer releases a control block, so no
  threshold applies.
- **`iec61850-server`** — `DatasetEntry` holds the node its member names
  instead of a single value lock; the `value` field is removed. Read the
  value with `read_value()` and the value locks with `leaves()`;
  `DatasetEntry::new` still builds a member naming one basic-type attribute.
- **`iec61850-server`** — Read handlers decide every read that covers their
  node. A handler above the node read (on its data object, a sub-data-object
  or a constructed attribute) is asked first, outermost first: an error
  refuses the read and a value answers it with the part the node occupies. A
  handler below the node read replaces the part its node occupies, and its
  error refuses the whole read, which then carries no value. This applies to
  reads of a logical node or a functional-constraint group, to
  GetDataSetValues members, to reads with an alternate access, and to builds
  without the routed subsystems, none of which consulted read handlers
  before. A value a handler supplies for a data object or a constructed
  attribute must have the shape of that node, one member per node beneath it
  in model order, else the read answers `type-inconsistent`. A handler meant
  to guard only its own path returns `ReadOutcome::CacheMiss` when
  `ctx.requested` differs from `ctx.path`.
- **`iec61850-server`** — A write handler installed on a data object or
  sub-data-object is consulted for a write of any node beneath it, with the
  object's current value under the functional constraint in which the
  written node is replaced.
- **`iec61850-server`** — `LogControl::log_single_value` is removed; updates
  of data set members write their log entries themselves.
  `ReportingEngine::flush_after_unlock` and `InclusionFlag::NOT_UPDATED`,
  unused remains of an earlier design of the data model lock, are removed.
- **`iec61850-server`** — `LogControlBlock::default_enabled`, true by default
  as for an SCL `LogControl` without `logEna`, takes effect: a log control
  block whose definition sets it starts enabled once it has both a data set
  and a storage backend, which `LogControl::with_storage` completes. It used
  to start disabled whatever the flag; `LogControlBlock::with_default_enabled`
  sets it.
- **`iec61850-server`** — `SettingGroupHandler::confirm_edit_sg` returns
  `bool`: `false` refuses the commit with `object-access-denied`, keeping the
  group's values and the edit session. An application no longer stores the
  group values or writes them from `act_sg_changed`.
- **`iec61850-server`** — `IedServerConfig::time_quality` is the
  `TimeQuality` of `iec61850_model::utc_time`, re-exported at the crate root
  with `TimeAccuracy`, so `iec61850_server::TimeQuality` is the model's type.
  The server's own `TimeQuality`, whose `time_accuracy: u8` could hold the
  codes 25 to 30 that IEC 61850-8-1 Table 36 defines as invalid, is removed:
  build one with `TimeQuality::new(leap_seconds_known, clock_failure,
  clock_not_synchronized, TimeAccuracy::bits(n)?)` and take the default from
  `IedServerConfig::default().time_quality`. The octet sent for every valid
  setting is unchanged. See
  [Server TimeQuality](docs/migration-0.4.md#server-timequality).
- **`iec61850-server`** — `reporting::RESV_TMS_IMPLICIT_VALUE_S` is removed.
  It stated that IEC 61850-7-2 reserves a BRCB for ten seconds after any
  successful write other than one to `ResvTms`; the standard defines no such
  reservation (IEC 61850-7-2 §17.2.2.17, Table 37), and no write path used
  the constant. Nothing on the wire changes. See
  [Report control block API](docs/migration-0.4.md#report-control-block-api).
- **`iec61850-server`** — `MmsModelDispatcher::write_policies` is a
  `SharedWriteAccessPolicies` instead of an `Arc<WriteAccessPolicies>`: take
  a copy of the policy with `get()`, or ask `is_allowed`.
  `MmsModelDispatcher::new` and `with_identification` take any
  `Into<SharedWriteAccessPolicies>`, so a call passing `Arc::new(policies)`
  compiles unchanged. See
  [Write access policies](docs/migration-0.4.md#write-access-policies).
- **`iec61850-server`** — `IedServer::abort_connection` returns `bool`:
  `true` when an open association has the id and is marked for abort,
  `false` otherwise, for instance for one that has already closed. It used to
  return `Result<bool>`, `Ok(false)` whether or not it found the
  association, and an error only for a poisoned association registry, which
  no longer yields one. The abort may not have been sent when it returns.
  See [Associations](docs/migration-0.4.md#associations).

### Added

- **`iec61850-model`** — Constructors for the structs that callers build:
  `LogicalDevice::new`, `LogicalNode::new`, `DataObject::new`,
  `DataAttribute::with_shared_value`, `DataSet::new`, `DataSetEntry::new`,
  `ReportControlBlock::new`, `GooseControlBlock::new`,
  `SvControlBlock::new` and `LogControlBlock::new`. Each constructor in this
  release documents the value it gives the fields it does not take.
- **`iec61850-mms`** — `ServiceError::with_additional_code` and
  `ServiceError::with_additional_description`.
- **`iec61850-goose`** — `GoosePdu::new` and `GooseFrameHeader::new`.
- **`iec61850-sv`** — `Asdu::new`, `SavPdu::new` and `SvFrameHeader::new`.
- **`iec61850-client`** — `IecObjectPath::new`, `IecObjectPath::with_array`
  and `ArrayElement::new`.
- **`iec61850-server`** — `ControlObjectConfig::new`, `ReadContext::new`,
  `WriteContext::new`, `JournalEntry::new` and `JournalEntryData::new`;
  `ReportEncodeParams::new(rpt_id, dat_set, dataset, pending, max_pdu_size)`,
  and `BrcbReportEncodeParams::new` likewise ending in the maximum PDU size
  of the association.
- **`iec61850-model`** — Arrays. `DataAttribute::array` and
  `DataObject::array` build an array of a given element count, each element
  a copy with values of its own; `DataObjectBuilder::array` makes the
  elements from the children added. `is_array`, `element`,
  `DataAttribute::is_leaf`, `duplicate` and `DataAttribute::assign`, which
  stores a structure or array value into the leaves, checking the whole shape
  first. `ModelError::EmptyArray` for a count of 0.
- **`iec61850-model`** — `DataAttributeType::Int24`, `SvOptFlds` and
  `LogOptFlds`. `DataAttribute::sgroup_values` and `sgroup_value(group)`:
  every `<Val sGroup="n">` of an SCL instance (IEC 61850-6 §9.5.4.4).
  `ReportControlBlock::indexed`, `max_instances` and `instance_names()`
  (`name01` to `nameNN` when indexed, IEC 61850-8-1 §17.1.2, §17.1.3).
  `LogControlBlock::log_ena`, `reason_code`, `buf_tm_ms`, `trg_ops` and
  `intg_pd_ms`. `LogicalDevice::compose_domain_name`; `DataSetEntry`
  implements `Display`.
- **`iec61850-model`** — The `utc_time` module: `UtcTime`, `TimeQuality`,
  `TimeAccuracy` and `UtcTimeError`, the TimeStamp encoding of
  IEC 61850-8-1 §8.1.3.7 as a typed value that is always a valid encoding,
  usable without std. `iec61850-goose` and `iec61850-sv` re-export the types
  at their crate roots, and `iec61850-sv` also as its `utc_time` module.
- **`iec61850-model`** — The `comm` module holds the communication
  addressing of an SCL file: `Address`, the `<P>` parameters of an
  `<Address>` in document order, each kept as written (`Address::push`,
  which refuses only a type that is no address parameter type and an empty
  value, `with`, `get`, and accessors such as `ip`, `ipv6`, `mms_port`,
  `osi_psel`, `osi_ap_title`, `mac_address`, `app_id`, `vlan_id` and
  `vlan_priority`), with `AddressError`. `value_form` tells a value in the
  schema form (`ValueForm`) from one that reads another way and from one that
  cannot be read, `schema_form` names the schema form, `schema_value` writes
  a readable value in it, and the accessors read the first two. `GseAddress`, an
  address with `MinTime` and `MaxTime`; and `ConnectedAccessPoint`.
  `GooseControlBlock::gse`, `SvControlBlock::smv` and
  `IedModel::connected_aps` carry them, with `IedModel::gse_address`,
  `smv_address`, `connected_ap` and `IedModelBuilder::add_connected_ap`. The
  model describes addresses only; nothing binds or opens one.
- **`iec61850-scl`** — The SCL bTypes `INT24`, `Octet6`, `Octet16`,
  `SvOptFlds` and `LogOptFlds` (IEC 61850-6 §9.5.4.2) load as `Int24`,
  `OctetString(6)`, `OctetString(16)`, `SvOptFlds` (bit-string(5)) and
  `LogOptFlds` (bit-string(1)).
- **`iec61850-scl`** — The `count` of a `DA`, `BDA` and `SDO` builds an array
  (IEC 61850-6 §9.5.3 Table 44, §9.5.4.1 Tables 47 and 48), given as a number
  or as the name of an attribute of the same type definition whose `<Val>`
  holds it; the `ix` of a `DAI` or `SDI` sets the element it names (§9.3.6
  Tables 19 and 20). `RawCount`.
- **`iec61850-scl`** — `<ReportControl indexed>` and `<RptEnabled max>` reach
  the model's report control block, and the attributes and `<TrgOps>` of
  `<LogControl>` reach its log control block. `RawScl::header` carries the
  `<Header>` attributes, `Header::name_structure` included.
- **`iec61850-scl`** — `ResolveOptions::max_expanded_nodes` (default
  1,000,000), `RawScl::resolve_with`, `ResolvedScl::from_raw_with`, and
  `CompileBuilder::max_expanded_nodes` in `iec61850-scl-build`.
- **`iec61850-hal`** — `iec61850_hal::ethernet::open_socket` opens an L2
  socket on the backend the build provides (AF_PACKET on Linux, otherwise
  libpcap or NPCAP) and returns `BackendNotSupported` without one.
  `EthernetError` implements `Clone`, `PartialEq` and `Eq`.
- **`iec61850-mms`** — `BlockingMmsClient` wraps every `MmsClient` service:
  `abort`, the array element read and write, `read_list`, the named variable
  list values, `define_named_variable_list`, `delete_named_variable_list`,
  `read_journal`, `recv_unconfirmed_pdu_with_timeout`, `push_back_unconfirmed`
  and `connected_flag`. Each method documents that it panics inside an async
  runtime.
- **`iec61850-mms`** — `SERVICE_TAG_DEFINE_NAMED_VARIABLE_LIST_RESPONSE` is
  re-exported from `mms::pdu`; `session::encode_refuse_with_user_data`,
  `presentation::encode_cpr` (also `pres_encode_cpr`) and
  `IsoPresentation::accepts_acse_and_mms`.
- **`iec61850-mms`** — `ServiceError::service_specific` and
  `ServiceSpecificInfo` carry the serviceSpecificInformation of a
  ServiceError; `DeleteNamedVariableList(u32)` is the one alternative
  modelled. Other alternatives, and content that does not decode, give `None`
  while the rest of the ServiceError still decodes.
- **`iec61850-mms`** — `AlternateAccessSelector::Component` covers
  `selectAccess.component` and the `selectAlternateAccess` chains that start
  with `accessSelection.component`, including the IEC 61850-8-1
  §24.2.2.4.1.3 Table 139 form; `AlternateAccess::component`,
  `component_then`, `nesting_depth` and `leading_components`. `indexRange`,
  `allElements` and named members are not represented yet.
- **`iec61850-mms`**, **`iec61850-client`** —
  `IsoConnectionParameters::authentication` carries the ACSE credentials the
  client writes into its AARQ, for instance `AcseAuth::Password`; it defaults
  to `AcseAuth::None`. A password travels in clear unless the association
  runs over TLS. `AcseAuth::other(mechanism, value)` sends any other
  mechanism: the content octets of its mechanism-name OBJECT IDENTIFIER and
  the complete Authentication-value encoding, written as given.
  `iec61850-client` re-exports `AcseAuth` and `AcseServiceUserDiagnostic`.
- **`iec61850-mms`** — `AcseServiceUserDiagnostic` with
  `is_authentication_refusal`, `encode_aare_with_diagnostic`,
  `AcseAuth::other` and `AcseAuth::label`, `AcseConnection::aarq_addressing`,
  `calling_authentication` and `result_source_diagnostic`, and
  `PresentationReject::parse_user_data`.
- **`iec61850-mms`** — `MmsConnection::association_id`,
  `MmsClient::association_id` and `BlockingMmsClient::association_id` number
  the associations of a client: each established association gets a new
  number, kept until the next one is established, and 0 stands for none yet.
- **`iec61850-mms`** — `MmsServerConnection` implements `Clone`; a clone
  shares the outstanding-request permits of the original.
- **`iec61850-tls`** — `TlsAcceptor::report_handshake_timeout` raises
  `AlmHandshakeTimeout` for a caller that bounds the handshake.
  `TlsConfigBuilder::build_server` logs a warning when the server has no
  trust anchor and so requests no client certificate.
- **`iec61850-goose`** — The S bit of Reserved1 mirrors the Simulation
  parameter (IEC 61850-8-1 Annex C.2.5). `GoosePublisher::set_simulation`
  sets it with the PDU `simulation` member, `GooseFrameHeader::simulation`
  carries it, and `GooseSubscriberState::frame_simulation` reports it next to
  `simulation`. `GooseSubscriberBuilder::simulation` takes a
  `SimulationFilter` (`Any`, the default, `NonSimulated`, `Simulated`); a
  publication counts as simulated when either flag is set.
  `GoosePublisher::simulation()` returns the setting.
- **`iec61850-goose`** — `GoosePublisher::gocb_ref`, `data_set_ref`,
  `set_data_set_ref`, `conf_rev`, `needs_commission` and `comm_parameters`.
  `CommParameters::without_vlan`; `Default` for the GOOSE `VlanTag`
  (priority 4, VID 0) and `VlanPriority` (4).
- **`iec61850-goose`** — `CommParameters::from_address` builds the
  parameters of a layer 2 publication from the `<Address>` of an SCL
  `<GSE>`: a missing APPID is 0x0000, a missing VLAN-ID 0 and a missing
  VLAN-PRIORITY 4 (IEC 61850-8-1 Annex C); an address without `MAC-Address`
  returns the new `GooseError::MissingAddressParameter`, and one whose
  MAC-Address, APPID, VLAN-ID or VLAN-PRIORITY holds a value that cannot be
  read the new `GooseError::UnreadableAddressParameter`.
  `RetransIntervals::from_min_max` and `RetransIntervals::from_gse` derive
  the retransmission intervals from `MinTime` and `MaxTime`: T1 is MinTime,
  Tmax is MaxTime, and T2 to T4 double from T1 up to Tmax.
- **`iec61850-goose`** — `GoosePublisher::set_timestamp_source` installs a
  `TimestampSource` the publisher reads into `t` on every stNum change, in
  `increase_st_num` and `reset`; installing one reads nothing, and without
  one `t` keeps the value `set_timestamp` gave. `has_timestamp_source` and
  `timestamp` report it.
- **`iec61850-goose`** — `GooseSubscriberState::is_simulated`, true when the
  PDU `simulation` member or the S bit of Reserved1 is set; the subscriber
  filters on it and keeps the sequence state of simulated and original
  messages apart.
- **`iec61850-sv`** — The Simulate bit (bit 15 of Reserved1,
  IEC 61850-9-2 §5.3.3.4.4). `SvPublisherBuilder::with_simulate` and
  `SvPublisher::set_simulate` set it in the prebuilt frame,
  `SvFrameHeader::simulate` carries it, and `SvSubscriberAsdu::simulate`
  reports it to the listener.
- **`iec61850-sv`** — `SvSubscriber::duplicate_count` counts ASDUs whose
  smpCnt repeats the previous one of their stream.
  `SvPublisherBuilder::without_vlan`.
- **`iec61850-sv`** — `SvPublisherBuilder::with_address` takes the
  destination, APPID and 802.1Q tag of a stream from the `<Address>` of an
  SCL `<SMV>`: a missing MAC-Address or APPID keeps the builder's value, a
  missing VLAN-ID is 0 and a missing VLAN-PRIORITY 4. It returns
  `Result<SvPublisherBuilder, SvError>`, with the new
  `SvError::UnreadableAddressParameter` for a value that cannot be read.
- **`iec61850-sntp`** — `SntpServerConfig::clock`, an `SntpClock` handle
  whose clones share one `SntpClockStatus` that the application updates as
  the clock gains or loses synchronization. A synchronized clock is reported
  with leap indicator 0, the configured stratum and the time it was last set;
  an unsynchronized one with leap indicator 3, stratum 16
  (`UNSYNCHRONIZED_STRATUM`) and the time it was last set, or zero when it
  never was. The default, a synchronized clock under continuous discipline,
  replies as before: leap indicator 0, the configured stratum, and the
  receive time as the Reference Timestamp.
- **`iec61850-client`** — `IedConnection::with_max_name_list_names` sets the
  most names one GetNameList walk may collect; the default,
  `directory::DEFAULT_MAX_NAME_LIST_NAMES`, stays one million.
- **`iec61850-client`** — `ClientReport::included`: one flag per data set
  member, set when the latest report (or the latest segment of a segmented
  report) carried the member's value. `data_set_values` keeps the previous
  value of an omitted member; `included` tells the two apart even when the
  report carries no reason for inclusion.
- **`iec61850-client`** — `IedConnection::query_journal` sends one request
  for any `JournalQuery`, `JournalQuery::continuation` gives the request that
  continues a page, and `IedConnection::query_journal_all` follows
  `moreFollows` to the end of the selection. `query_journal_all` returns each
  selected entry once, none past the end time and no more than the entry
  count, also from a server that starts a continuation with the entry it
  resumes after or with the earlier entries of its time, that ignores the end
  time of a QueryLogAfter, or that ignores numberOfEntries. Entries are told
  apart by EntryID only, so a journal whose clock steps back reads to the
  end, and a read that brings no new entry while the server reports more
  ends with the new `ClientError::JournalNotAdvancing` instead of repeating
  the same request forever.
- **`iec61850-client`** — `GoCBValues::fixed_offs`; `GoCBValuesWrite::dat_set`
  and `with_dat_set`. `set_gocb_values` writes `GoEna = FALSE` before
  `DatSet` and `GoID`, so one call can disable an enabled GOOSE control block
  and change its data set; otherwise it writes `DatSet`, `GoID` and then
  `GoEna`, so enabling follows the new values.
- **`iec61850-server`** — `IedServer::register_from_model` registers, in one
  call, every data set, report control block, GOOSE control block, log
  control block and controllable data object the served model declares, and
  returns a `FromModelSummary` of what it registered;
  `register_from_model_with` takes `FromModelOptions` for the storage of the
  logs (`LogStorageFactory`) and the destination of the GOOSE publishers
  (`GooseCommFactory`), which the model does not hold. Nothing is registered
  unless the application calls it. A data set or control block already
  registered under the same reference fails the call with the new
  `ServerError::AlreadyRegistered`, before anything is registered; a control
  object already registered is kept with its handlers. A report control block
  is registered once per instance it declares, each with its own
  reservation, enable state, sequence number and, when buffered, its own
  buffer. A report, GOOSE or log control block naming a data set of another
  logical device, or one the server does not hold, fails the call with
  `InvalidModel`, likewise before anything is registered.
- **`iec61850-server`** — `register_from_model` sends each GOOSE publication
  to the destination `FromModelOptions::goose_comm` gives, otherwise to the
  address of the SCL `<GSE>` of its control block, otherwise to APPID 0 and
  `01-0C-CD-01-00-00`, with the `MinTime` and `MaxTime` of the `<GSE>`, 4 and
  1000 ms without one, so a client reads the configured `DstAddress`,
  `MinTime` and `MaxTime`. In a system configuration, an SCL whose
  Communication section connects the IED, a control block without `<GSE>`
  is disabled (IEC 61850-8-1 §25.3.2), and so is one whose `<GSE>` address
  has no `MAC-Address`, as for GOOSE over UDP/IP, which is not supported, or
  whose MAC-Address, APPID, VLAN-ID or VLAN-PRIORITY cannot be read, unless
  `goose_comm` gives a destination: `DstAddress$Addr` reads as the
  NULL address, six zero octets, `GoEna` stays false, and a write of
  `GoEna = TRUE` is refused with `temporarily-unavailable`. Each publisher
  stamps `t`, the time of the last stNum change (IEC 61850-8-1 §18.1.2.5),
  from `FromModelOptions::wall_clock` (a `WallClock`, set with
  `with_wall_clock`; the system clock by default) with
  `IedServerConfig::time_quality`, at registration and on every
  `increase_st_num` and `reset`; a clock before the epoch or past the 32-bit
  SecondSinceEpoch is sent as the epoch with ClockFailure set. A publisher
  registered through `register_gocb` is left as the application built it.
  See [Registering what the model declares](docs/migration-0.4.md#registering-what-the-model-declares).
- **`iec61850-server`** — `register_from_model` binds a data set member that
  names an array element, by an index in its name or the FCDA `ix`, and binds
  a member covering an array element by element; the reference of an element
  carries its index after the array name,
  `LD/LN$MX$HA$phsAHar(7)$cVal$mag$f` (IEC 61850-8-1 §8.1.3.2.4). An index
  past the end of its array, or one on a path holding no array, fails the
  call with `InvalidModel`.
- **`iec61850-server`** — `ControlObjectsRegistry::register_from_model`
  registers a control object, bound to the model, for every data object whose
  `ctlModel` is not status-only, and `ControlObject::from_model` creates one.
  `ControlObjectConfig::oper_timeout_ms` sets the operate timeout used when
  the model declares no `operTimeout`. The server binds an object registered
  by hand to the model when it first serves a request for it.
  `ControlObject::settings` returns the settings in force.
  `SelectStateChangedReason::OperateRefused` reports an Operate whose refusal
  ended the selection.
- **`iec61850-server`** — `SettingGroupRuntime::group_value` and
  `set_group_value` read and replace the value a setting group holds for a
  setting, for an application that restores values it persisted.
- **`iec61850-server`** — Arrays of data attributes and of sub-data-objects
  are served as MMS arrays (IEC 61850-8-1 §8.1.2.7): described by
  GetVariableAccessAttributes, read whole, and read by element through an
  alternate access index, optionally followed by components, including the
  IEC 61850-8-1 Table 139 form. A Write with an alternate access index writes
  one element or a member of it. `IedServer::update_array` updates every
  element of an array data attribute from an `MmsValue::Array`, checked whole
  before any element changes and stored under the lock MMS reads take, and
  raises the report and log triggers of all elements as one batch, so a
  report control block without a buffer time sends one report for the
  update.
- **`iec61850-server`** — A data set member may name a data object or
  sub-data-object (FCD) or a constructed attribute, as IEC 61850-7-2
  §13.2.2.3 requires of an IED that supports CreateDataSet or configured
  data sets. Such a member reads as the MMS structure of the node in the
  order of its type description, is listed by its own name in
  GetDataSetDirectory, and is reported, segmented and logged as one unit: a
  change of any attribute beneath it includes the whole member, with the
  union of the reasons of the attributes that changed.
  `DatasetEntry::from_model` and `DatasetEntry::from_data_set_entry` resolve
  a member, `DatasetEntry::leaves` lists its attributes, and
  `register_from_model` binds an SCL FCD member as one entry.
- **`iec61850-server`** — SetDataValues accepts functional-constrained data
  (FCD), `LN$FC$DO[$SDO...]`, as IEC 61850-7-2 §11.4.3.2.1 allows. The value
  is the structure GetVariableAccessAttributes describes for that name: one
  member per attribute or sub-object the data object holds under the
  constraint, in model order. Every leaf is checked and every write handler
  consulted before any leaf changes; one failing leaf fails the whole write
  (§11.4.3.4). A write of a whole data object that used to answer
  `object-access-unsupported` now succeeds or fails on its value.
- **`iec61850-server`** — `ReadContext::requested` and
  `WriteContext::requested` hold the path the client named, beside `path`,
  the path the handler is registered against; `with_requested` sets it.
- **`iec61850-server`** — A log control block whose `TrgOps` hold integrity
  and whose `IntgPd` is above zero writes one entry every `IntgPd`, counted
  from when it was enabled, holding every member of its data set with the
  integrity reason code (`0x10`). General interrogation writes no log entry,
  as IEC 61850-7-2 does not support it for logging.
  `IedServer::tick_log_integrity` drives the period with clock readings the
  caller supplies; the tick loop of a started server calls it every
  millisecond. An application that wrote integrity entries itself stops, or
  each period is logged twice.
- **`iec61850-server`** — `ReportingEngine::on_values_updated` reports several
  attribute updates as one batch. A control block whose pending report or
  open buffer time window already holds a member of the batch sends that
  report or closes that window first, so the batch stays whole; a reference
  given twice counts once.
- **`iec61850-server`** — `LogStorage::add_entry_with_data` writes an entry
  with all its data points as one unit. The in-memory backend leaves nothing
  behind when it fails; the default implementation writes the header and the
  data points in turn, so a backend that can fail part way overrides it. The
  server writes every log entry through it.
- **`iec61850-server`** — CreateDataSet holds a data set created at run time
  to 1024 members, 4096 attributes in all and 1024 attributes per member,
  and answers `resource capability-unavailable` beyond
  (IEC 61850-8-1 §8.1.3.4.3.4).
- **`iec61850-server`**, **`iec61850-client`**, **`iec61850-mms`** —
  CreateDataSet takes a member naming an array element, and components inside
  it (IEC 61850-8-1 §7.3.3, §7.3.4, Table 151). The client turns a member
  reference such as `LD/MHAI1.HA.phsAHar(3).cVal.mag.f` into the array name
  with an alternate access, the form GetDataSetDirectory reads back, where it
  used to refuse a reference with an index; the server holds the element as a
  data set member, read, written and reported as `…$phsAHar(3)$cVal$mag$f`.
  An index that selects no element answers `definition object-undefined`.
  Both sides need 0.4: a 0.3 client refuses the reference and a 0.3 server
  refuses the member.
- **`iec61850-server`** — `Rcb::with_owner`, and the existing
  `Brcb::with_owner` and `Brcb::with_resv_tms`, which had no effect, decide
  whether a control block has the optional Owner, and a BRCB the optional
  ResvTms: without it the attribute is left out of GetNameList,
  GetVariableAccessAttributes and a Read of the control block, and a Read or
  Write of it answers `object-non-existent`. All default to having the
  attribute. `Brcb::new` now sets `with_owner` to true, where 0.3 set it to
  false without effect. An application that passed `false` to one of them on
  0.3 now serves the control block without that attribute, and a peer reading
  it gets `object-non-existent`. Only the server changes.
- **`iec61850-scl`**, **`iec61850-model`** — The `owner` and `resvTms`
  attributes of `<ReportSettings>` in the `<Services>` of an access point, or
  else of the IED, are read (`RawReportSettings`, `RawIed::report_settings`,
  `RawAccessPoint::report_settings`) and reach the model's report control
  blocks as `ReportControlBlock::has_owner` and `has_resv_tms`.
- **`iec61850-server`** — On a server with TLS, a connection whose TLS
  handshake, or whose association setup after the handshake, does not
  complete within `association_setup_timeout_ms` raises
  `AlmHandshakeTimeout` on the TLS event handler.
- **`iec61850-server`** — `GoCBRegistry::with_edition`,
  `GoCBRegistry::edition`, `GoCBRegistry::with_data_set_lookup`,
  `goose_mapping::DataSetLookup`, `GoCBRegistry::item_bases_in_domain` and
  `GoCBHandle::qualify_data_set_ref`.
- **`iec61850-server`** — `RcbWriteValue::Integer`, which the MMS write path
  produces for an MMS integer; `ResvTms` takes it, or an unsigned value, from
  0 to 32767. `ApplyEntryIdError::ReportingEnabled` and
  `reporting::BrcbWriteError`.
- **`iec61850-server`** — `ReportBufferBackend::newest_entry`, with a default
  implementation; the in-memory and SQLite buffers answer it without copying
  the buffer, and GetBRCBValues uses it.
- **`iec61850-server`** — `ReportBufferBackend::mark_formatted` and
  `ReportBufferBackend::set_formatted_through`, which track the newest
  buffered entry formatted in the current transmission. The reporting engine
  advances the mark as entries go out, and an EntryID write, a purge, or a
  partly sent entry given up moves it back. A custom backend that implements
  them sets BufOvfl only when it loses an entry not yet formatted; one that
  does not keeps setting it on every eviction.
- **`iec61850-server`** — `ReportingEngineMetrics::dropped_oversized`, the
  reports and buffered entries dropped because they cannot fit the
  negotiated PDU size; `ReportEncodeError::MemberTooLarge`, naming the data
  set member that does not fit; `ChannelReportSink::available_capacity`.
- **`iec61850-mms`**, **`iec61850-client`** — `TlsFailureKind`, which says
  why a TLS handshake failed: the peer certificate was rejected
  (`Verification`), the peer sent a fatal alert (`AlertReceived`), no TLS
  version or cipher suite in common (`VersionUnsupported`,
  `CipherUnsupported`), the connect deadline ran out (`Timeout`), the
  transport broke (`Io`), or another TLS error (`Other`). It is defined with
  or without the `tls` feature, and `iec61850-client` re-exports it.
- **`iec61850-mms`** — Constructors of the client errors, which take the
  fields an error always carries, for code that reports one itself, such as
  a test double of a peer: `ClientError::service_error` with
  `with_service_specific`, `session_refused` with `with_reason_code`,
  `with_transport_disconnect` and `with_provider_reason`, and `reject`,
  `service_timeout`, `connect_timeout`, `not_connected`, `pdu_too_large`,
  `initiate_failed` and `tls_handshake(kind, message)`.
- **`iec61850-client`** — `ClientError::Service` carries the
  serviceSpecificInformation of the ServiceError as `service_specific`, and
  `ServiceSpecificInfo` is re-exported; a refused DeleteDataSet reports how
  many data sets the server deleted.
- **`iec61850-server`** — `ControlAction::conn_id` returns the
  `ConnectionId` of the association that issued a control request, or 0 when
  none did; a selection that ends by timeout or by the loss of its
  association reports the association that held it.
- **`iec61850-server`** — An `AssociationAuthenticator`, installed with
  `IedServerBuilder::authenticator` or `IedServer::set_authenticator`, decides
  on every association request (IEC 61850-7-2 §8.3.1.2.2; IEC 61850-8-1
  §10.2.2.1 Table 48). It receives the peer address, the called and calling
  AP-title and AE-qualifier and the ACSE credentials in an
  `AssociationRequest`, and returns `AssociationDecision::Accept` or
  `AssociationDecision::Reject` with an acse-service-user diagnostic; a
  closure can be installed directly. A refused association is answered with
  a Session REFUSE carrying a Presentation CPR whose user data is an AARE
  with result rejected-permanent, that diagnostic, and an Initiate-ErrorPDU
  with errorClass access and errorCode object-access-denied as its user
  information (IEC 61850-8-1 §8.1.3.4.2.1). Without an authenticator every
  association is accepted, as before. Only the mechanism and the decision
  are logged, never a password. The authenticator is asked on the blocking
  thread pool of the runtime and may block; the association waits for its
  decision within the setup timeout. See
  [Gating associations](docs/migration-0.4.md#gating-associations).
- **`iec61850-server`** — `SharedWriteAccessPolicies`, a write access policy
  its clones share, and `IedServer::write_access_policies`, which returns the
  one the server and the dispatcher it builds share; a dispatcher supplied
  through `IedServerBuilder::dispatcher` follows `set_write_access_policy`
  when built from it.
- **`iec61850-server`** — `SettingGroupRegistry::tick_reservations_at` and
  `SettingGroupRuntime::tick_reservation_at` are public, so an application or
  a test can release expired edit sessions with clock readings of its own, as
  `ReportingEngine::tick_brcb` and `IedServer::tick_log_integrity` allow.
- **`iec61850-server`** — The `GoCBHandle::has_destination` field and
  `GoCBHandle::without_destination` mark a GOOSE control block the
  configuration gives no destination: its `DstAddress$Addr` reads as the
  NULL address, six zero octets (`Addr` is a fixed six-octet OCTET STRING,
  IEC 61850-8-1 §8.1.3.3 Table 16), and a write of `GoEna = TRUE` is refused
  with `temporarily-unavailable` (IEC 61850-8-1 §25.3.2, §8.1.3.4.4.2).
- **`iec61850-sntp`** — `SntpClockStatus::synchronized(last_set)` and
  `SntpClockStatus::unsynchronized(last_set)` build the clock status an
  application hands to `SntpClock`.

### Changed

- **`iec61850-server`** — GetVariableAccessAttributes describes `LLN0$GO`,
  each GoCB, each component and the members of `DstAddress`; GetNameList
  lists the `LLN0$GO` group and every flattened name below it; reads of
  `LLN0` and `LLN0$GO` include the GoCBs; `LLN0$GO$<gcb>$DstAddress$<member>`
  is readable. A peer sees the additional `LLN0$GO…` names in GetNameList.
  Only the server changes.
- **`iec61850-server`** — A read whose alternate access selects components
  reads the same variable as the flattened name (IEC 61850-8-1 §7.3.1), for
  model data and control blocks alike. A Write whose alternate access starts
  with components writes the variable the flattened name names. Only the
  server changes.
- **`iec61850-server`** — Writing GoCB `GoEna` `TRUE` answers
  `object-value-invalid` while `DatSet` is empty or `ConfRev` is 0
  (IEC 61850-7-2 §18.2.1.3); the control block stays disabled. A write that
  used to succeed in that state is now refused. Only the server changes.
- **`iec61850-server`** — A Write of a single array element, which answered
  `object-access-unsupported`, is now served: the value is checked against
  the element type, and the write handlers on the array and above it decide
  the write with the array value in which the element is replaced. A whole
  array is written with exactly its element count, else
  `type-inconsistent`. GetVariableAccessAttributes answers
  `object-non-existent` for a name past an array, as Read does. Only the
  server changes.
- **`iec61850-server`** — A log control block takes the same triggers as the
  reports: an entry carries the code of every reason its `TrgOps` enable,
  data-update (`0x08`) included. A log control block writes one entry for a
  batch of updates, holding each data set member the batch reaches once with
  the reason code of its own updates, instead of one entry per attribute. A
  peer reading the journal sees data-update entries and one entry per batch.
  Only the server changes.
- **`iec61850-server`** — `IedServer::lock_data_model` defers the report and
  log triggers of the updates made while its guard is held, and dropping the
  guard raises them as one batch: an attribute updated several times counts
  once, with its last value and the reasons of all its updates merged, a
  report control block with no buffer time sends one report, and a buffered
  one buffers one entry, for the whole batch. Buffer time expiry and
  integrity and general interrogation reports wait while the guard is held.
  The guard used to defer nothing, although its documentation said it did,
  so code that held it while updating now receives one report per batch,
  after the guard is dropped. A guard dropped during a panic still raises its
  triggers, and the model can be locked again afterwards. A client Read is
  not held back. The server publishes no GOOSE message on its own, so the
  lock defers none. A client receives one report for a batch of updates
  instead of one per update. Only the server changes.
- **`iec61850-server`** — A value a client writes through SetDataValues or
  SetDataSetValues raises the report and log triggers its trigger options
  declare, as an `update_*` call does; before, a client write raised no
  trigger at all. The attributes every item of one Write request stores, a
  list of variables or the members of a data set, raise their triggers as one
  batch before the response is sent, once every item of the request has been
  handled, and while the data model is locked they wait for the release. A
  value the request stored and another update replaced before the request
  ended is left out of that batch, so the last report and log entry of the
  attribute carry the value it holds. Other clients receive reports after a
  client writes a data set member. Only the server changes.
- **`iec61850-server`** — An `update_*` call returns once the report and
  log triggers of its own update have been raised, and may wait for the
  updates queued before it, which another thread raises. A `LogStorage` may
  update the server from the thread the server calls it on: that update is
  raised after the batch under way and the call returns at once. A
  `LogStorage` must not wait for an update made on another thread, and a
  `ReportSink` or `ReportBufferBackend`, which the reporting engine calls
  holding its lock, must not update the server. Nor may a `LogStorage` call
  `IedServer::lock_data_model` while it writes an integrity entry, which the
  server writes while the periodic triggers hold that lock off: a 0.3 log
  storage that locked the data model from its write methods hangs in 0.4.
- **`iec61850-server`** — A synchronous application callback reached from a
  client request, the periodic triggers, the select timeout, the end of a
  command or the release of an association runs on a thread of the
  runtime's blocking pool, a different thread from one call to the next, so
  thread-local state set up in one call is not seen by the next. The
  documentation of `ReadHandler`, `AttributeAccessHandler`, the control
  handlers, `SettingGroupHandler`, `LogStorage` and `ReportBufferBackend`
  states where each is called and which locks are held. The futures of
  `WaitForExecutionHandler` and `ControlHandler` are still polled on the
  runtime, so blocking work in them belongs in `tokio::task::spawn_blocking`.
  Callbacks share the blocking pool with every other `spawn_blocking` user;
  past its `max_blocking_threads` limit further requests and periodic
  triggers queue. Call `ServerHandle::stop` before shutting the runtime down,
  or a dispatch already under way completes after its association has been
  released. `IedServer::block_requests` returns without waiting for a request
  already being dispatched; that request completes and the flag applies from
  the next request of each association on.
- **`iec61850-server`** — A log storage or report buffer backend that blocks
  while it handles a batch of value updates also holds up every later update
  whose triggers queue behind that batch: the writes other associations make
  to attributes that raise a trigger, and `IedServer::update_*` calls on any
  thread. An update called on a runtime worker stalls that worker until the
  backend returns, and the whole server on a current-thread runtime. When a
  backend can block, call `update_*` from async code through
  `tokio::task::spawn_blocking` or from a thread of its own.
- **`iec61850-server`** — The leaves of a write of a data object or a
  constructed attribute are stored under one lock that reads take shared
  while they take values, so a concurrent read sees the write whole or not at
  all, and two such writes do not interleave their leaves.
- **`iec61850-server`** — The values the server loads into FC=SG go through
  its update path, so a data set member under FC=SG with `dchg` is reported
  and logged when SelectActiveSG or a commit of the active group changes it.
  Only the server changes.
- **`iec61850-server`** — A CreateDataSet member naming an object that does
  not exist, by its name, its functional constraint, a functional constraint
  that does not exist, or its logical device, answers
  `definition object-undefined` instead of `access object-non-existent` or
  `definition invalid-address` (IEC 61850-8-1 §8.1.3.4.3.4 Table 23). A data
  set name whose domain or logical node does not exist still answers
  `access object-non-existent`. A client that took the old errors as "a
  member does not exist" matches `object-undefined`. Only the server needs
  to be upgraded.
- **`iec61850-server`** — CreateDataSet takes a member beneath a
  sub-data-object, such as `MMXU1$MX$A$phsA$cVal$mag$f`
  (IEC 61850-7-2 §13.2.2.3). A client sees the request accepted where it
  used to be refused. Only the server changes.
- **`iec61850-server`** — The negative DeleteNamedVariableList response is
  built from `ServiceError::service_specific`; the bytes on the wire are
  unchanged.
- **`iec61850-mms`**, **`iec61850-server`** — ReadJournal serves every
  combination of its four optional fields: `rangeStartSpecification`
  (starting time or starting entry), `rangeStopSpecification` (ending time or
  number of entries), `listOfVariables` and `entryToStartAfter`. Each field
  present narrows the selection: the start and stop bound the entries, a
  number of entries ends the request without `moreFollows`,
  `entryToStartAfter` resumes after an entry while the original start and
  stop still apply, and `listOfVariables` keeps only the listed data points,
  each with its reason code. Only a start time with a stop time, or an
  `entryToStartAfter` alone, used to decode; any other combination was
  answered with an access error and `listOfVariables` was ignored. A 0.4.0
  client sends the same bytes as 0.3.x for the two ACSI queries; a 0.3.x
  server refuses the new combinations with an access error.
- **`iec61850-server`** — A URCB whose report channel is full drops the
  report and stays enabled and reserved. After ten full sends in a row it was
  handled as if the association had been lost: RptEna and Resv were cleared
  while the association stayed open, and the client silently stopped
  receiving reports. The drops are counted in `dropped_socket_full`, and a
  run of drops logs one warning when it starts and one when delivery
  resumes. An association that stops reading is closed by the idle and send
  timeouts, which release its control blocks. Only the server changes.
- **`iec61850-server`** — An unreserved URCB, one with `Resv = FALSE` that no
  client holds, accepts writes of its writable attributes from any client,
  and the write does not reserve it; only `Resv = TRUE`, or `RptEna = TRUE`,
  reserves it. A single Write request that sets `TrgOps`, `IntgPd` or other
  attributes of an unreserved URCB and ends with `RptEna = TRUE` therefore
  succeeds as a whole: the attributes take effect in request order and the
  enable reserves the URCB for the writer. Every attribute other than `Resv`
  used to be refused with `object-access-denied` until the client reserved
  the URCB. A URCB reserved by another client still refuses every write with
  `object-access-denied`, and BRCB access is unchanged. A client sees the
  configuration writes accepted; one that inferred the reservation from
  their refusal reads `Resv` instead. Only the server changes.
- **`iec61850-server`** — `Owner`, on a control block that has it, names the
  client holding the control block, as IEC 61850-8-1 §17.1.2 requires: the IP
  address of the client that reserved a URCB, explicitly or by enabling it,
  or that enabled or reserved a BRCB, and the configured client of a
  pre-configured block. A URCB used to report an empty `Owner` always, and a
  BRCB only once reserved through `ResvTms`. Only the server changes.
- **`iec61850-server`** — An A-ABORT the server application decides on, on
  the idle timeout, `abort_connection` or shutdown, names the ACSE service
  user as its abort-source; it used to name the service provider, which is
  now kept for protocol errors only. A peer sees service-user in the ABRT.
  Only the server changes.
- **`iec61850-mms`** — An Initiate request without `localDetailCalling` is
  accepted at the server maximum of 65 000 octets; it used to be refused. A
  proposal below 64 octets is still refused. The Initiate response carries a
  negotiated `dataStructureNestingLevel` only when the request proposed one;
  it used to answer 32 to a request that proposed none. An Initiate that used
  to be refused is now accepted. Only the server changes.
- **`iec61850-scl`** — More malformed files are rejected, by the run-time
  loader and by `iec61850-scl-build` alike: an `<RptEnabled max="0">`, more
  than 99 indexed report instances, a `sGroup` of 0, above 255 or above
  `numOfSGs`, two values for one setting group, a `<Header>` without `id`,
  outside `<SCL>` or repeated, and a `count` naming no attribute of an integer
  bType in the same type definition. When the type gives the named attribute
  no `<Val>`, the count is the value an instance gives that attribute (a DAI
  at the same level of the DOI); without one the declaration is built as a
  scalar with a warning. A report control block with `indexed="false"` and
  `max` above 1 is logged and counted as one instance.
- **`iec61850-scl`** — The output of `summarize::summarize_model` changes,
  so saved summaries must be regenerated: the report control block line adds
  `indexed=`, `max=`, `trg=0x..`, `optFlds=0x....`, `bufTm=`, `intgPd=`,
  `owner=` and `resvTms=`; the log control block line adds `logEna=`,
  `reasonCode=`, `bufTm=`, `trg=0x..` and `intgPd=`; a data attribute line
  adds ` kind=array(n)` for an array and ` sg<n>=` for each setting group
  value; and the data objects of a logical node and the children of a data
  object or a constructed attribute are listed in the order the model holds
  them, the order their types declare, instead of sorted by name. A model
  built from a file with a `<Communication>` section adds a `ConnectedAP`
  line per connected access point and a `GSE address=` or `SMV address=`
  line below each addressed GOOSE or sampled values control block.
- **`iec61850-mms`** — `MAX_DEFINE_ENTRIES` and `MAX_WRITE_ITEMS` are 4096
  instead of 100, and a request beyond either decodes to an error the server
  answers with `resource capability-unavailable`.
- **`iec61850-hal`** — The pcap backend opens its capture in non-blocking
  mode and polls it every millisecond, so `recv` honors its timeout.
- **`iec61850-client`** — A segmented report is delivered one segment at a
  time: the report callback runs once per segment, and `included`, `reasons`
  and `segmentation` describe that segment. Segments of one report share
  SeqNum, SubSeqNum counts them from zero and the last one has
  MoreSegmentsFollow false; the client does not reassemble them.
- **`iec61850-server`** — GetDataSetDirectory lists a data set member naming
  an array element as the variable naming the array with an alternate access
  selecting the index and then each component (IEC 61850-8-1 §24.2.2.4.1.3,
  Table 140), instead of the reference with the index in parentheses, which
  names no MMS variable; a member naming a whole array is listed by its name.
  SetDataSetValues writes such a member as the element of the array, where it
  used to answer `object-non-existent`, and GetDataSetValues reads it through
  the read handlers of the array, which it used to bypass. A client sees a
  directory entry it can read back. Only the server changes.
- **`iec61850-server`** — Read handlers run while the server holds none of
  its locks. A read that consults handlers asks them first, without the value
  lock, and then takes the values under the lock, answering each consultation
  with what the handler decided; each handler is still asked once per read. A
  handler may therefore call the server, `update_*` and `lock_data_model`
  included, which could deadlock against a general interrogation or integrity
  snapshot before. A read that consults handlers walks its node twice, once
  to ask the handlers and once to take the values. The first walk also reads
  the model values outside the lock; they decide only a read refused for its
  size, and are discarded otherwise.
- **`iec61850-server`** — Logging a batch of updates finds the updates
  beneath each data set member with one pass over the member's attributes
  instead of allocating them once per update, and applying the values of a
  batch to a data object member skips values outside the member by their
  reference.
- **`iec61850-server`** — `GoCBHandle::qualify_data_set_ref` keeps an empty
  reference as it is; it used to return `<LD>/<LN>$`. Registering a GoCB
  whose publisher has no data set no longer writes that value into the
  publisher.
- **`iec61850-mms`**, **`iec61850-client`** — Establishing a connection is
  bounded by one deadline of `connect_timeout_ms` for the TCP connection, the
  TLS handshake (with `connect_tls`) and the COTP connection request and
  confirm together. The COTP exchange had no timeout before, so a peer that
  accepted the TCP connection and never answered held the client
  indefinitely, and the TLS handshake had no bound of its own. Running out of
  the deadline during the TLS handshake returns
  `ClientError::TlsHandshake { kind: TlsFailureKind::Timeout, .. }`; during
  the TCP connection or the COTP exchange it returns
  `ClientError::ConnectTimeout`. `connect_via`, which starts from a connected
  transport, bounds its COTP exchange by `connect_timeout_ms` as well. The
  Session, ACSE and MMS Initiate exchange that follows is still bounded by
  `request_timeout_ms`. Only the client changes.
- **`iec61850-hal`** — The `transport-embassy` feature no longer pulls in
  `embedded-io-async`, which the crate never used.
- **CI** — The server feature subsets run clippy on all targets with
  warnings denied, and each server test and example names the features it
  needs. New jobs run the wire tests and the TLS handshake tests with TLS
  enabled on Linux and Windows, the raw Ethernet, GOOSE and Sampled Values
  tests over a veth pair, failing when a test binary holds no test, and the
  `thumbv7em-none-eabihf` checks. The client association tests that needed
  an external server run against the server of this repository, and an
  end-to-end test runs every client service against one server started from
  an SCL model, with a TLS variant.
- **docs.rs** — Every feature of each crate is documented, the pcap backends
  of `iec61850-hal` excepted.

### Fixed

- **`iec61850-model`**, **`iec61850-scl`** — The sub-attributes of a
  constructed attribute take its trigger options (IEC 61850-7-2
  §17.3.2.3.2): a leaf such as `mag.f` of an MV built from SCL or by
  `DataObjectBuilder` now triggers reports and log entries on what `mag`
  declares; it used to carry none and never triggered.
- **`iec61850-scl`** — A `<DAI>` on a setting whose DOType declares it under
  both FC=SE and FC=SG reaches both attributes, not only the one declared
  first.
- **`iec61850-scl`** — An empty `SampledValueControl smvID` takes the control
  block reference, `<domain>/LLN0$MS$<name>` or `$US$` for a unicast block
  (IEC 61850-6 Annex I.3.2.7).
- **`iec61850-scl`** — A Timestamp `<Val>` accepts `24:00:00`, the start of
  the next day.
- **`iec61850-scl`** — A `<TrgOps>` element that leaves out the `gi`
  attribute enables general interrogation, as IEC 61850-6 §9.3.8 defaults
  `gi` to true; the other four attributes still default to false,
  `gi="false"` still disables it, and a control block without a `<TrgOps>`
  element still has no trigger option. A report control block loaded from
  SCL, at run time or by code generated with `iec61850-scl-build`, now
  serves a `TrgOps` that includes GI where the file leaves `gi` out, so a
  client that keeps the `TrgOps` of the file and writes `GI` receives a
  general interrogation report instead of nothing. A log control block is
  unchanged, as general interrogation does not apply to a log. Only the
  server changes.
- **`iec61850-scl`** — A `numOfSGs` above 255 is rejected while parsing
  (NumOfSG is an INT8U, IEC 61850-7-2 §16.2.2.3).
- **`iec61850-scl`** — A file whose types fan out at every level fails in
  stage 2 instead of taking exponential time: an IED or a type expanding to
  more than `ResolveOptions::max_expanded_nodes` model nodes is rejected, a
  shared DAType is checked once, every array element and every FC=SG view
  derived from an FC=SE attribute counts against the limit, and an IED counts
  the element counts its instances give.
- **`iec61850-mms`** — The negotiated outstanding request limit is enforced,
  whatever its value.
  A request that timed out counts as outstanding until its late answer
  arrives; once such requests hold every slot, the next request waits up to
  the request timeout for a late answer and otherwise fails with
  `OutstandingCallLimit` without being sent. With no timed-out request
  nothing changes. The negotiated value never exceeds the client's proposal.
- **`iec61850-mms`** — A Session FN from the peer in the middle of an
  association is reported as `ClientError::ReleasedByPeer`, as is a Conclude
  request from the server.
- **`iec61850-mms`** — The session layer reads and writes the long form of
  every length (0xFF and two octets) and carries more than 512 octets of
  CONNECT user data in the Extended User Data parameter. A CONNECT, ACCEPT,
  FINISH or DISCONNECT over 254 octets used to fail at both ends, which
  blocked long AP-titles and authentication values.
- **`iec61850-mms`** — A COTP connection request or confirm without the TPDU
  size parameter proposes 128 octets, the ISO 8073 default; it used to be
  read as 8192.
- **`iec61850-mms`** — An AARE whose result is an INTEGER without content
  octets is a rejection; it used to be taken as an accepted association.
- **`iec61850-mms`** — `ServiceError::decode_inner` reads optional fields with
  any BER length form.
- **`iec61850-mms`** — The client decodes the errorClass of a
  ConfirmedError or InitiateError whatever length form it uses up to a
  two-octet long form (`0x81`, `0x82`), on the `[0]` wrapper and on the
  subcode, and a subcode from 128 to 255 with its leading zero octet. These
  were reported as a PDU parse error instead of
  the service error they carried. A malformed errorClass, with a negative
  subcode or more than one alternative, is still a parse error and is no
  longer silently accepted. An additionalCode wider than 32 bits decodes as
  `additional_code: None` instead of failing the whole ServiceError. The
  peer needs no change.
- **`iec61850-mms`** — Encoding a `ServiceError` writes a subcode from 128 up
  with a leading zero octet, where it read back as a negative INTEGER, and
  an `additional_description` of 128 bytes or more with a long-form length,
  where the PDU could not be parsed. The server of this crate sends neither,
  so its answers on the wire are unchanged.
- **`iec61850-mms`** — An AP-title whose OBJECT IDENTIFIER is longer than
  127 octets, so that its length takes the long form, is decoded into the
  application reference of the AARQ; it used to be read as empty. Only the
  receiving side changes.
- **`iec61850-mms`**, **`iec61850-client`** — Connecting while an
  association is established replaces it. The old transport stayed open,
  and when it was a TLS one every later service, writes included, still went
  to the old server although the new connect succeeded. The old association
  is now closed without a release, so its server sees the connection close,
  and the Session, Presentation, ACSE and negotiated state start afresh.
  Only the client changes.
- **`iec61850-mms`** — A confirmed call dropped by its caller, for instance
  on an outer timeout, no longer leaks its invokeID: after as many dropped
  calls as the outstanding limit, five by default, every service failed with
  `OutstandingCallLimit`, also after reconnecting. A call dropped after its
  request was sent counts as outstanding until the late answer arrives, as
  after a request timeout, and that answer is discarded; a call dropped
  while its request was being written closes the connection, since the
  request may be on the wire only in part. A new association starts with
  every outstanding slot free. Only the client changes.
- **`iec61850-server`** — A CreateDataSet or Write naming more variables than
  the server handles answers `resource capability-unavailable`
  (IEC 61850-8-1 §8.1.3.4.3.4) instead of `access other`, and the limits are
  the documented ones: a data set holds up to 1024 members and a Write up to
  4096 items, where both used to stop at 100 because a longer request did not
  decode. A peer sees a data set of 101 to 1024 members created and written,
  and the capability error beyond. Only the server changes.
- **`iec61850-server`** — The server matches incoming presentation data
  against the context identifiers the client chose in its CP. It used to
  match the fixed values 1 and 3, so a client that chose other identifiers
  had its first request dropped with the connection, and one that swapped
  them had its MMS requests parsed as ACSE. The indirect-reference of the
  AARE user-information is the client's MMS context identifier as well; it
  used to be 3 whatever the client chose.
- **`iec61850-tls`** — A client the server refuses reads the alert that says
  why. The acceptor used to close the connection at once; a TLS 1.3 client
  has already sent data by then, so the connection was reset and the client
  saw only a reset. After the alert the acceptor now shuts down the write
  side and reads what the client still sends until it closes, for at most
  two seconds and 16 KiB. At most 64 refused connections drain at a time per
  acceptor; a refusal beyond them is closed at once, so a peer that keeps
  failing handshakes cannot make the server hold more sockets. A refused
  client of either version now receives the alert instead of a reset.
- **`iec61850-sntp`** — The client reports every reply it rejects through
  `tracing::warn!`, as the crate documentation states; it used to return the
  error only.
- **`iec61850-hal`** — The pcap and NPCAP backend ignored the timeout passed
  to `recv`, and with no configured receive timeout blocked until a frame
  arrived, so a GOOSE or SV receiver thread on a quiet link neither raised
  `Expired` nor stopped; `stop_and_join` and `Drop` hung.
- **`iec61850-goose`** — The GOOSE subscriber took the stNum and sqNum
  overflow from 4294967295 to 1 (IEC 61850-8-1 §18.1.2.5.2) for a counter
  moving backwards and cleared `state_valid`.
- **`iec61850-goose`** — A GOOSE subscriber with only `dst_mac` set received
  frames for every destination address.
- **`iec61850-goose`** — A subscriber keeps the sequence state, the confRev
  check and the timeAllowedToLive supervision of the simulated and of the
  original messages of one gocbRef apart. A simulation starting at stNum 1
  while the original publication was at a higher stNum was delivered with
  `state_valid = false`, as an stNum moving backwards, and the next original
  message was checked against the simulation. The first simulated message
  now raises `NewState` with `prev_st_num` 0, each of the two expires on its
  own, and an observer counts them as two publications against
  `max_streams`. Only the subscriber changes.
- **`iec61850-goose`**, **`iec61850-sv`** — `goose_publisher_live` and
  `sv_publisher_live` run on the pcap backend outside Linux when built with
  `--features iec61850-hal/ethernet-pcap`, as their help text said; without a
  backend they exit with a hint.
- **`iec61850-sv`** — `SvReceiver::set_dest_addr_check(true)` had no effect.
  With the check enabled, a frame is now dispatched only when its destination
  MAC equals the `dst_mac` filter of some subscription.
- **`iec61850-sv`** — A Sampled Values ASDU whose smpCnt repeats its
  predecessor, such as a copy a PRP or HSR network failed to remove, was
  counted as a gap of 65535 samples (or `limit - 1`); it is now counted in
  `duplicate_count`.
- **`iec61850-client`** — `IedConnection::disconnect` keeps the cached device
  model when the server refuses the Conclude and the association stays open.
- **`iec61850-client`** — A directory walk keeps each name once, in the order
  the server sends it, and ends with an error when a page that reports more
  names ends on its continuation or brings no name not yet received. A server
  that jumps back to earlier names no longer keeps the walk going with
  duplicates, and one that repeats the continuation name at the head of a
  page no longer yields it twice. As in 0.3, no order is required, since
  IEC 61850-8-1 sets none.
- **`iec61850-client`** — The directory services no longer panic when the
  device model cache is invalidated or the connection disconnected while a
  directory call is reading it.
- **`iec61850-client`** — The device model cached by the directory services
  is bound to the association it was read on. After the server ended the
  association or the transport was lost, connecting to another server still
  returned the directory of the old one; a new association now reads the
  model again, and `IedConnection::cached_device_model()` returns `None`
  until it has.
- **`iec61850-client`** — `set_gocb_values` given `GoEna = false` and a GoID
  writes `GoEna` first, so one call can disable an enabled GOOSE control block
  and change its GoID; the GoID write used to come first and be refused while
  the block was still enabled (IEC 61850-8-1 §18.1.1.1.1 Table 83). Only the
  client changes.
- **`iec61850-client`** — `get_gocb_values` reads a GOOSE control block whose
  `DstAddress.Addr` is an empty OCTET STRING, which a server may reveal for a
  GoCB the configuration leaves disabled (IEC 61850-8-1 §25.3.2); exactly six
  octets used to be required. The empty `Addr` reads as the all-zero
  address, the one the server of this crate reveals for such a block, which
  means no destination; any length other than zero or six is still refused.
  Only the client changes.
- **`iec61850-client`** — A report whose DatSet or ConfRev differs from the
  one the kept values of a subscription came with discards those values and
  their data references and fixes the data set size anew (IEC 61850-7-2
  §17.2.2.6, §17.2.2.7). After DatSet was rebound, a report carrying only
  some members used to show the others with the values and references of
  the previous data set, and a data set of another size was refused as a
  size change. A report that carries neither DatSet nor ConfRev is held to
  the data set the previous reports described.
- **`iec61850-client`** — A rejected report leaves the subscription state
  unchanged. A first report refused for an over-long data set name used to
  fix the data set size anyway, so every valid report of another size was
  refused until the handler was installed again, and a report short of
  values overwrote part of the state before it was refused.
- **`iec61850-client`** — A time query the server pages no longer runs past
  its end time: a continuation keeps the end time, the start and the variable
  list of the original query. `query_journal_after_entry` used to be the only
  way to continue, and it sends no end time, so the continued pages returned
  entries after the end.
- **`iec61850-server`** — A SelectWithValue on an object outside the
  enhanced-security select-before-operate model is refused with the add
  cause Unknown, and a read of `SBO` outside the normal-security
  select-before-operate model answers `object-non-existent`, per
  IEC 61850-8-1 Table 94 and IEC 61850-7-2 Table 47. A write of a control
  attribute the model leaves out of a data object it declares answers
  `object-non-existent`.
- **`iec61850-server`** — A Cancel of an idle direct-control object is
  refused with Not-supported instead of succeeding.
- **`iec61850-server`** — A selection expires on a timer when its select
  timeout elapses, instead of when the next request finds it elapsed; an
  operate-many command restarts it. The selection change handler hears of
  every change, including a select, the end of an operate-once command and a
  lost connection, and the server updates `stSeld` on each; a connection that
  closes while its command executes ends the selection once the command
  finishes.
- **`iec61850-server`** — A control handler or dynamic check that panics no
  longer leaves its object executing for good: before the response the object
  returns to unselected and the Operate is answered negatively with a
  LastApplError carrying Error Unknown; after a positive response the command
  ends as failed, under enhanced security with a negative CommandTermination
  carrying AddCause and Error Unknown.
- **`iec61850-server`** — An Operate whose response waits for its dynamic
  check no longer runs when the association closes before the positive
  response is sent.
- **`iec61850-server`** — A connection whose control channels or report
  channel have closed no longer spins on them and keeps serving requests.
- **`iec61850-server`** — A commit of an edit of the active setting group no
  longer loads the edited values into FC=SG when another association selects
  a different active group between the check of the commit and its
  completion.
- **`iec61850-server`** — A write under functional constraint SE stores its
  values only into the edit session it was admitted to. When that session
  expired, was cancelled or was opened again, by the same association or
  another, while a write handler ran, the write used to store into the edit
  buffer anyway, after the next SelectEditSG had loaded another group into
  it, and a ConfirmEditSGValues of that session committed the stale value.
  Such a write now answers `temporarily-unavailable` and stores nothing
  (IEC 61850-7-2 §16.3.3, §16.3.4; IEC 61850-8-1 §8.1.3.4.4.2). A
  ConfirmEditSGValues whose session expires and is opened again while the
  confirm handler runs answers `object-access-denied` and leaves the new
  session open, where it used to end it. Only the server changes.
- **`iec61850-server`** — The report and log triggers of updates are raised
  one batch at a time, in the order the values were stored (IEC 61850-7-2
  §17.2.1, §17.2.2.15). An update used to write its log entries before it
  reached the reporting engine, with nothing ordering it against another
  update of the same attribute, so a slow log storage let a later update be
  buffered first: a buffered report control block could buffer `false` then
  `true` for updates `true` then `false`, leaving a subscriber on a value the
  model no longer held, and the log could hold the entries in reverse order.
  A client now sees the reports and log entries of an attribute in the order
  its values changed; nothing changes in the encoding. Only the server
  changes.
- **`iec61850-server`** — PurgeBuf also discards the events a BRCB still
  holds inside its buffer time, and those of values stored before it whose
  triggers had not yet reached the reporting engine, for instance behind a
  slow log storage, as IEC 61850-7-2 §17.2.2.14 requires. The next tick, the
  next trigger of a member already in the window, or the late trigger, used
  to buffer them as a new entry after the purge, so a client that enabled the
  BRCB after purging still received a value set before the purge. The same
  holds for a write of `RptID`, `DatSet`, `BufTm`, `TrgOps` or `IntgPd` that
  purges the buffer. Events of values stored after the purge are reported as
  before; the log is not affected. A buffered entry, or a buffer time
  window, any member of which was stored before the purge is discarded
  whole, members stored after it included. Only the server changes.
- **`iec61850-server`** — `IedServer::set_write_access_policy` applies to the
  next Write of every association, also while the server runs. It used to
  change only what `write_access_allowed` reported: the dispatcher the
  builder made kept the policy of build time, so a remote Write was still
  allowed or refused as before. Only the server changes.
- **`iec61850-server`** — Application callbacks no longer run on a Tokio
  worker thread. Read and write handlers, the control check and selection
  change handlers, setting group handlers, and the log storages and report
  buffer backends reached from a client request, the periodic triggers, the
  select timeout, the end of a command or the release of an association run
  on the blocking thread pool of the runtime. A callback that blocks, on I/O
  for instance, holds up only the request or the tick waiting for it; it used
  to stall every association served by that worker, and the whole server on
  a current-thread runtime. The requests of one association are still
  answered in order. Nothing changes on the wire, except that the other
  associations keep being served while a handler blocks. Only the server
  changes.
- **`iec61850-server`** — A request is dispatched on a snapshot of its
  association's MMS state instead of under that state's lock. A handler that
  calls `IedServer::block_requests` no longer deadlocks, and
  `block_requests` no longer waits for a handler that blocks. Only the server
  changes.
- **`iec61850-server`** — The selection change handlers hear of the
  selections a closed association releases with no lock of the control
  object registry held. One that blocks no longer holds off registering and
  looking up control objects, and one that registers a control object no
  longer deadlocks. Only the server changes.
- **`iec61850-server`** — A whole GetBRCBValues reads `EntryID` and
  `TimeofEntry` from the same buffered entry; an entry enqueued while the
  structure was being read could give a `TimeofEntry` of another entry.
- **`iec61850-server`** — After a purge, an enabled BRCB that has sent nothing
  since exposes the all-zero `EntryID` of an empty buffer instead of the
  entry sent before the purge, which no longer exists.
- **`iec61850-server`** — A BRCB on the SQLite report buffer reports each
  entry with the values and inclusion flags captured when it was enqueued. It
  used to report the values current at transmission, with every member
  included.
- **`iec61850-server`** — The inclusion bitstring of each segment of a
  segmented report marks only the members that segment carries. Every
  segment of a general interrogation or integrity report had every bit set,
  so a client failed to decode the first segment.
- **`iec61850-server`** — A report that cannot fit the PDU size the
  association negotiated, because its header or one of its members is too
  large, is dropped and logged once, with the member that does not fit, and
  counted in `ReportingEngineMetrics::dropped_oversized`. A buffered entry
  that did not fit stayed at the head of the BRCB, was retried and logged on
  every tick, and held back every entry behind it. A control block whose
  report header alone exceeds the negotiated PDU size logs one error until
  one of its reports goes out again, instead of one per report; every
  dropped report is still counted.
- **`iec61850-server`** — A segmented report is sent only when the report
  channel has room for all its segments: a URCB report without room is
  dropped whole instead of arriving with its last segments missing, and a
  BRCB entry without room waits whole. A report with more segments than the
  channel holds is sent in parts as the channel drains, each segment once and
  in order, with nothing else from that control block in between.
- **`iec61850-server`** — An entry dropped from a full BRCB buffer while a
  long entry is still being sent in parts is reported with BufOvfl TRUE in
  the next report; the flag is cleared once the first segment of an entry
  goes out, not after its last.
- **`iec61850-server`** — Apart from the first report after each enable, a
  BRCB reports BufOvfl TRUE only when its buffer lost an entry that had not
  been formatted for transmission yet; evicting an
  entry already sent, such as the one still being sent in parts, no longer
  marks the next report as following an overflow, and an entry evicted after
  a client resynchronizes, before it is sent again, sets it. The in-memory
  and SQLite buffers behave the same.
- **`iec61850-server`** — A BRCB waiting for its next entry after a client
  resynchronized it on the newest one no longer logs an error on every tick,
  and a BRCB whose report channel is full logs once instead of on every tick.
- **`iec61850-server`** — General interrogation and integrity reports, and
  integrity log entries, take the values of their data set under the same
  lock as a read, so a concurrent write of a data object or a constructed
  attribute is seen whole or not at all rather than partly. Read handlers do
  not run under that lock; see Changed.
- **`iec61850-hal`** — `--no-default-features --features alloc,ethernet`
  builds on a `no_std` target, as the `ethernet` feature promises; the module
  took `Duration`, `String`, `Vec` and `Box` from `std`.

## [0.3.3] - 2026-10-31

### Security

- **`iec61850-tls`** — With `time_validation(false)`, an expired or not yet
  valid certificate is accepted only when it passes every other check at a
  time inside its validity period. It used to be accepted whatever its issuer,
  because the validity period is checked before the signature chain, and in
  allow-only-known mode the known-peer list was skipped as well, so any
  network peer could present a self-signed expired certificate and be taken
  for the server. An expiry error that carries no validity period now rejects.
  `iec61850-client` and `iec61850-server` are affected through their `tls`
  feature; a configuration that keeps the default `time_validation(true)` is
  not.
- **`iec61850-tls`** — A server in allow-only-known mode refuses a client that
  presents no certificate; it used to accept it, so the known-peer list did
  not restrict who could associate. By default a server with trust anchors
  still accepts a client that presents no certificate and reports it as
  `WrnNoPeerCert`; call `require_client_auth(true)` or
  `allow_only_known_peers(true)` to refuse it.

### Changed

- **`iec61850-mms`**, **`iec61850-server`** — The DefineNamedVariableList
  response is the primitive NULL `8b 00` that ISO 9506-2 defines, and the
  client accepts it as well as the constructed `ab 00` it used to require. A
  client of version 0.3.2 or earlier reports a tag mismatch against a 0.3.3
  server although the data set is created nonetheless; upgrade the client.
- **`iec61850-mms`** — The end of the transport, a COTP disconnect, a Session
  abort, finish or disconnect, and a Conclude request from the server close the
  client and return `ConnectionLost`, and a TCP connect that times out returns
  `ConnectTimeout`. These used to surface as `IsoError`, and a Conclude from
  the server left the transport open. Code that matched `IsoError` to detect a
  lost connection matches `ConnectionLost` instead.
- **`iec61850-mms`** — An AARE without a result field is a rejection and
  `connect` returns `AssociateFailed`; it used to be taken as an accepted
  association.
- **`iec61850-mms`** — The `ReasonCode` of a journal entry is sent and read
  as the seven-bit BIT STRING of IEC 61850-8-1, bit `n` carried by mask
  `1 << n` of the reason code byte, so data-change (`0x02`) reaches the wire
  as bit 1. It used to be sent as the byte unchanged, which put data-change
  on bit 6. Entries already stored keep their byte and need no migration, but
  a 0.3.2 peer reading journals from a 0.3.3 one, or the reverse, decodes the
  reasons of the other wrongly; upgrade both sides.
- **`iec61850-mms`** — A journal time that is not a six-octet TimeOfDay is
  refused; a four-octet one used to be taken as a time on 1970-01-01.
- **`iec61850-client`** — `select_with_value`, `operate` and `cancel` return a
  timeout, a lost connection, a Reject or any other MMS-layer error as `Err`;
  only a data access error or a confirmed service error, the server refusing
  the command, is `Ok(ControlOutcome::Failure)`. These errors used to be
  reported as `Failure(Unknown)` although the command may have been executed;
  a caller that only matched on `Ok` handles the `Err` as well.
- **`iec61850-client`** — An enhanced-security Operate that is refused
  concludes at the negative response instead of waiting up to 5 s for a
  command termination a refused command never gets. A server of version 0.3.2,
  which sends its cause only in such a termination, therefore yields
  `Failure(Unknown)` where it used to yield the cause; upgrade the server.
- **`iec61850-client`** — `DatasetDirectory::expected_size` is honored: a
  report whose member count differs is rejected before it reaches the
  subscription state or the callback. It used to be ignored. Leave it `None`
  to accept any member count.
- **`iec61850-server`** — A refused SelectWithValue, Operate or Cancel is
  preceded by an InformationReport carrying only `LastApplError`, with the
  origin and ctlNum of the request, as IEC 61850-8-1 defines, and a refused
  Operate under enhanced security no longer sends a CommandTermination. A
  client that waits for that termination, as `iec61850-client` 0.3.2 does,
  waits until its own timeout; upgrade the client.
- **`iec61850-server`** — Under normal security a positive Operate response
  now only means the command was accepted: it is sent once the check and
  wait-for-execution handlers pass, and no longer waits for the control
  handler. A control handler that fails used to answer the Operate
  negatively; the Operate is now answered positively and the failure is
  logged. An application that needs the outcome of the command uses enhanced
  security, whose CommandTermination reports it.
- **`iec61850-server`** — `LastApplError` carries Error `No Error` for a
  refusal by a check or a handler, even when its add cause is `Unknown`, and
  `Unknown` only for an internal failure of the server; it used to carry a
  fixed 3. A negative CommandTermination carries the origin and ctlNum of the
  command, where it carried an empty origin and 0, and carries Error
  `Operator Test Not OK` for a failed command with `Test` set, or
  `Timeout Test Not OK` when that command was time activated. A SelectWithValue
  on a selected object is refused with Object-already-selected whichever client
  holds it, and with Command-already-in-execution while the command runs. The
  negative write response of a control service answers
  `temporarily-unavailable` for a selected, locked or executing object and
  `object-access-denied` otherwise, `NotSupported` included, which used to
  answer `object-access-unsupported`.
- **`iec61850-server`** — A write of `Oper`, `SBOw` or `Cancel` whose value
  does not have the type the model declares, or the structure of the service,
  is refused with `type-inconsistent` before any handler runs; a structure that
  failed to parse used to answer `object-access-denied`. `OperParams` no longer
  truncates a ctlNum above 255 or defaults a missing `T` or `Check`,
  `CancelParams` accepts the form carrying `operTm`, and a Cancel that does not
  parse cancels nothing.
- **`iec61850-server`** — An Operate on an object whose entry has no control
  handler is refused with `NotSupported`; it used to report success, and under
  enhanced security a positive CommandTermination. Install the control handler
  on `ControlObjectEntry`.
- **`iec61850-server`** — `ControlObject::set_check_handler`,
  `set_wait_for_exec_handler` and `set_operate_handler`, which store a handler
  the control services never call, and `ControlAction::set_add_cause` and
  `set_error`, which a handler cannot reach, are documented as having no effect
  and log a warning on their first call. Install handlers on
  `ControlObjectEntry` and report a refusal by the `ControlAddCause` a handler
  returns.
- **`iec61850-server`** — SqNum, ConfRev and subSeqNum of a report are encoded
  as BER integers, with a leading zero octet when the top bit of a value is
  set; values of 128 and above used to be read as negative by a strict
  decoder.
- **`iec61850-server`** — A data set member that triggers again within the
  buffer time no longer overwrites the value still pending: the pending report
  is sent (URCB) or buffered (BRCB) at once, and the new trigger starts the
  next buffer time.
- **`iec61850-server`** — The members of a BRCB general interrogation or
  integrity report carry only the general-interrogation or integrity reason;
  they also carried data-change before.
- **`iec61850-server`** — A BRCB report carries as TimeOfEntry the time its
  entry entered the buffer, the same value `TimeofEntry` reads back, instead of
  the time it was sent.
- **`iec61850-server`** — A DatSet write on a URCB or BRCB must name a data set
  the server knows, or be empty, and is refused with `object-value-invalid`
  otherwise; a BRCB also refuses a non-persistent (`@`) data set. An accepted
  write binds the control block to the members of that data set, including one
  created with DefineNamedVariableList, so its reports carry those members;
  before, only the name changed.
- **`iec61850-server`** — DeleteNamedVariableList refuses to delete a data set
  created at run time that the DatSet of a report control block names: it
  deletes none of the requested data sets and answers with errorClass service
  object-constraint-conflict, carrying numberDeleted as the service-specific
  information. A configured data set is never deleted, whether or not a
  control block names it, and is answered positively with numberDeleted 0 as
  before.
- **`iec61850-server`** — GetVariableAccessAttributes describes every
  registered report and log control block, and GetNameList lists its group,
  the block and each member, flattened like the data objects. A Read of a
  logical node or of its RP, BR, LG or SP group carries the control blocks in
  the same layout, and a buffered report control block reads as a whole, which
  used to answer `object-access-unsupported`. The members of a log control
  block are named `OldEnt` and `NewEnt`, the IEC 61850-8-1 component names;
  `OldEntr` and `NewEntr` still resolve but are not listed.
- **`iec61850-server`** — A whole read of a log control block answers its nine
  MMS components, `LogEna`, `LogRef`, `DatSet`, `OldEntrTm`, `NewEntrTm`,
  `OldEnt`, `NewEnt`, `TrgOps` and `IntgPd`, in that order; it used to answer
  five. `OldEntrTm`, `NewEntrTm`, `OldEnt` and `NewEnt` report the oldest and
  newest entry of the log, zero for an empty log, and are readable alone,
  where they answered `object-access-unsupported`.
- **`iec61850-server`** — The type description of a setting group control
  block includes `ResvTms` when the block exposes it, and a Read of `LLN0$SP`
  or `LLN0` includes the setting group control block, so the value matches its
  type description. A setting group control block path under a logical node
  other than LLN0 answers `object-non-existent` instead of reaching the control
  block of the domain.
- **`iec61850-server`** — A Read resolves a data attribute only under its own
  functional constraint, as GetVariableAccessAttributes and Write already did;
  a path naming another constraint answers `object-non-existent`.
- **`iec61850-server`** — CreateDataSet refuses a constructed attribute as a
  member, which used to read back as an empty structure, and refuses a data
  set name that is not `<LN>$<name>` of an existing logical node: a malformed
  name answers `invalid-address`, an unknown domain or logical node
  `object-non-existent`.
- **`iec61850-server`** — GetDataSetValues of a data set that does not exist
  fails the service with `object-non-existent`, as GetDataSetDirectory does,
  instead of answering one failed access result. A client that looked for that
  access result sees a service error instead.
- **`iec61850-server`** — `LActTm` carries the time quality of
  `IedServerConfig::time_quality`, so with the default configuration it now
  reports leapSecondsKnown, `0x8a`, where it carried `0x0a`.
- **`iec61850-server`** — An attribute update writes a log entry through every
  enabled log control block whose `TrgOps` hold the trigger of the update,
  data-change or quality-change, and whose `DatSet` names a registered data set
  that holds the attribute; the entry carries the member reference, the new
  value and the reason code. Nothing used to be logged unless the application
  called `LogControl::log_single_value` itself; an application that does so
  for these members stops, or each update is logged twice. Integrity and
  general interrogation entries are not written yet.
- **`iec61850-server`** — Writing `GoID` while `GoEna` is true is refused with
  `temporarily-unavailable` and leaves the publication unchanged, per
  SetGoCBValues of IEC 61850-7-2. `GoEna` stays writable; disable the control
  block before changing its `GoID`.
- **`iec61850-tls`** — `with_dangerous_no_sni_verify()` skips the server name
  check; it used to change nothing. Chain validation, revocation, validity
  time and the allow-only-known list still apply. A configuration that calls it
  now accepts any certificate that chains to a trust anchor, whatever name it
  carries.
- **`iec61850-tls`** — `build_server` applies `time_validation(false)` to
  client certificates as well, through the new
  `IgnoreValidityTimeClientVerifier`; a server so configured now accepts an
  expired client certificate that passes every other check, where it rejected
  it.
- **`iec61850-tls`** — `session_resumption(false)` also stops TLS 1.2 session
  resumption on the server, and takes precedence over
  `session_resumption_lifetime`. `session_resumption_lifetime` bounds how long
  a TLS 1.2 session or a TLS 1.3 ticket stays resumable, instead of setting the
  number of tickets sent per handshake; a zero lifetime disables resumption.
- **`iec61850-tls`** — `chain_validation(false)` and `renegotiation_interval()`
  are documented as not applied, and building a configuration with either set
  logs a warning.
- **`iec61850-goose`** — A received frame is delivered to every subscriber
  whose APPID, destination MAC and gocbRef filters accept it. Only the first
  matching subscriber used to be notified, so an observer added first starved
  every subscription on a specific gocbRef, and a gocbRef match could reach a
  subscriber whose APPID or MAC filter rejected the frame. An application that
  registers an observer next to specific subscriptions now sees a frame in
  both.
- **`iec61850-goose`** — The receiver decodes frames with
  `GoosePdu::decode_ber`: a confRev, stNum, sqNum, timeAllowedToLive or
  numDatSetEntries of 2^31 or more, as this crate's publisher sends it, is now
  received; a PDU with stNum 0, a numDatSetEntries that disagrees with allData,
  or a missing mandatory member, goID included, is dropped with a warning
  instead of being delivered with zero or empty fields; an unknown member tag
  is skipped.
- **`iec61850-sv`** — smpMod is encoded in two octets, the INT16U of
  IEC 61850-9-2 §8.5.2 Table 14, by both `encode_sav_pdu` and `SvPublisher`;
  it used to be one octet. A received two-octet smpMod is decoded as an
  INT16U, and a one-octet smpMod is still accepted as the same value and logged
  once; a value above 255, which `SmpMod` cannot represent, drops the optional
  field, also logged once. A 0.3.2 subscriber reads the new encoding, taking
  its last octet; a third-party subscriber that requires one octet needs the
  two-octet form.
- **`iec61850-sntp`** — The server answers a symmetric-active request in
  symmetric-passive mode and copies the poll field of every request, as
  RFC 4330 §5 requires; `SntpServerConfig::poll` no longer has an effect.
- **`iec61850-scl`** — A file that contradicts IEC 61850-6 in one of the
  following ways now fails to load, where it used to load with a wrong value:
  an integer `<Val>` outside the range of its bType (an INT8 of 300, an INT8U
  of 256); a `<DA>` or `<FCDA>` `fc` that is not a data functional constraint
  (`ALL`, `NONE`, `BR`, `RP`, `LG`, `GO`, `MS`, `US`); a `SettingControl` with
  `numOfSGs` or `actSG` of 0 or an `actSG` above `numOfSGs`; a DataTypeTemplates
  `<Val>` that does not parse as its bType; an Octet64 `<Val>` that is not
  base64Binary or a Timestamp `<Val>` that is not an xs:dateTime; and an `FCDA`
  naming an attribute the model does not have or one under another functional
  constraint. Such a file has to be corrected to load.
- **`iec61850-scl`** — A sub-object chain of DOTypes, or a nesting of DATypes,
  deeper than 32 levels is rejected with `SemanticConflict`; a chain of about a
  thousand levels used to overflow the stack and abort the process.
- **`iec61850-scl`** — A `<Val>` on a `<DA>` of a DOType or a `<BDA>` of a
  DAType is the initial value of every instance without a `<DAI>` override, and
  `<Val>` values on Dbpos and Tcmd (the IEC 61850-7-3 value names), on Octet64
  (base64Binary) and on Timestamp (xs:dateTime, UTC when no time zone is given)
  are applied. They used to be ignored, so a `ctlModel` declared
  `sbo-with-normal-security` read as `status-only` and an `sboTimeout` as 0;
  models built from such files now start from the values the file declares. A
  BOOLEAN `<Val>` accepts the xs:boolean literals `1` and `0`, and `TRUE` and
  `FALSE`, as well as `true` and `false`.
- **`iec61850-scl`** — The GoID of a GOOSE control block is the `appID` of its
  `<GSEControl>`, or its GoCBRef, `<domain>/LLN0$GO$<name>`, when the `appID`
  is empty; it used to be the control block name. A publisher configured from
  the model now sends the GoID that subscribers set up from the same SCD
  expect; a subscriber that was matched to the old GoID needs the `appID`.
- **`iec61850-scl`** — An Enum attribute whose `EnumVal` ordinals do not all
  fit integer(8) is built with `DataAttribute::ty` of
  `DataAttributeType::Int16` or `DataAttributeType::Int32`, the smallest that
  holds them, instead of `DataAttributeType::Enumerated`, and
  GetVariableAccessAttributes declares it as integer(16) or integer(32)
  instead of integer(8); code that branches on `ty` sees the new type. An Enum
  whose ordinals fit integer(8) is unchanged.
- **`iec61850-scl`** — The `daName` of an `<FCDA>` is split on `.` like the
  `doName`, so `DataSetEntry::do_path` is `["TotW", "mag", "f"]` rather than
  `["TotW", "mag.f"]`; an element index written into a name, as in
  `phsAHar(9)`, becomes the entry's array index when `ix` is absent. Code that
  reads `do_path` sees one segment per name.
- **`iec61850-scl`** — An `<SDI>` or `<DAI>` carrying `ix` is skipped with a
  warning, since the model holds an array as a single element; its value used
  to be written into that element.
- **`iec61850-model`** — `IedModelBuilder::build` resolves every segment of a
  data set entry path, not only the data object, and requires the attribute it
  names, or an attribute below the data object it names, to carry the entry's
  functional constraint; any other entry is rejected with
  `DataSetEntryUnresolved`, in a model built by hand as in one built from SCL.
  A segment holding `.`-joined names, as in `["TotW", "mag.f"]`, is still
  accepted.
- **`iec61850-scl-build`** — Generated code calls a lookup of
  `iec61850-scl` 0.3.3 to apply `<DAI>` values; build a crate generated by
  `iec61850-scl-build` 0.3.3 against `iec61850-scl` 0.3.3 or later.
- **`iec61850-server`** — GetBRCBValues reads `EntryID` and `TimeofEntry` as
  IEC 61850-7-2 defines them: while `RptEna` is true, the last entry queued for
  transmission; while it is false, the newest entry in the buffer, and the
  all-zero EntryID once the buffer is empty. They used to read back the EntryID
  a client last wrote, zero until one did, together with the time of the last
  entry sent. Writing `EntryID` still sets where transmission resumes.
- **`iec61850-scl`**, **`iec61850-scl-build`** — A `<DA>` declared with
  `fc="SE"` is also an FC=SG data attribute of the same name and type, as
  IEC 61850-6 defines, starting at the same template and `<DAI>` value and
  holding a value of its own. A DOType that declares the setting with
  `fc="SG"` itself keeps its own declaration. GetNameList, a read of a whole
  logical node and GetVariableAccessAttributes include the FC=SG attributes;
  a write under FC=SG is refused as before.
- **`iec61850-server`** — Once a ConfirmEditSGValues of the active setting
  group succeeds, every FC=SE value of the logical device is copied to the
  FC=SG data attribute of the same name, so a read under FC=SG returns the
  committed value. Committing another group, or selecting another active
  group, leaves the FC=SG values to the application.
- **`iec61850-goose`** — `GooseReceiver` drops a frame of another EtherType
  with a trace event instead of two warnings; a GOOSE frame that fails to
  decode is still reported with a warning.
- **`iec61850-tls`** — A server built by `TlsConfigBuilder` sends no TLS 1.3
  session ticket by default; it used to send two. A TLS client built with
  mbedtls 3.6.0 closes the connection when it receives one, which
  broke every TLS 1.3 association from such a client. TLS 1.3 sessions
  therefore no longer resume by default, while TLS 1.2 session ID resumption
  is unchanged. Call `tls13_session_tickets(2)` on the builder to restore the
  previous behavior.

### Added

- **`iec61850-mms`** — `MmsClient::abort` aborts the association with an ACSE
  ABRT from the service user inside a Session AB, then closes the transport.
- **`iec61850-mms`** — `MmsClient::connected_flag` returns a flag that is true
  exactly while the association is established and is updated on every state
  change, including a transport loss found inside a service call.
- **`iec61850-mms`** — `MmsClientBuilder::max_pending_unconfirmed` bounds the
  Unconfirmed PDUs held for a later read while confirmed calls are in flight,
  1024 by default; when the bound is reached the oldest is dropped with a
  warning.
- **`iec61850-client`** — `ControlObjectClient::last_appl_error` returns the
  LastApplError the server reported for the most recent Select,
  SelectWithValue, Operate or Cancel on the handle: the report a server sends
  ahead of the negative response to a refused command, or the one inside a
  negative command termination. It is cleared when the next command starts.
- **`iec61850-server`** — `ControlObject::set_oper_timeout_ms` limits a running
  command (`operTimeout`); on expiry the command ends with `TimeLimitOver`,
  reported in a negative CommandTermination under enhanced security. The
  default, 0, leaves it unlimited.
- **`iec61850-server`** — `ReportingEngine::set_dataset_registry` installs the
  data set registry that DatSet writes resolve against; `IedServer` shares its
  own registry with the engine. A `ReportingEngine` used without it refuses
  every DatSet write that names a data set.
- **`iec61850-tls`** — `TlsConfigBuilder::require_client_auth` makes a client
  certificate mandatory on the server; a client presenting none is refused.
- **`iec61850-tls`** — `IgnoreValidityTimeClientVerifier`, the
  client-certificate counterpart of `IgnoreValidityTimeServerVerifier`.
- **`iec61850-tls`** — Configurations built by `TlsConfigBuilder` report each
  certificate rejection to the event handler as `AlmCertRevoked`,
  `AlmCertSanMismatch`, `AlmCertBadEncoding` or `AlmCertChainInvalid`.
  `TlsAcceptor` and `TlsConnector` raise `SessionEstablished` on success,
  `WrnNoPeerCert` when a client presents no certificate to a server that
  requests one without requiring it, `AlmCertNotConfigured` when a required
  client certificate is missing, and `AlmCipherNotAllowed`, `AlmVersionTooOld`
  or `AlmUnexpectedAlert` for the matching handshake failures.
  `SessionClosed`, `SessionRenegotiation`, `WrnCertExpiringSoon`,
  `WrnCrlExpired`, `AlmUnauthorizedAccess`, `AlmHandshakeTimeout` and
  `AlmConnectionAborted` are not raised by the crate.
- **`iec61850-goose`** — `GooseReceiver::handle_message_at` and `tick_at`
  take the arrival time and the time of the expiry check from the caller, and
  `GooseSubscriber::is_valid_at` checks validity at a given instant, so
  timeAllowedToLive supervision can be driven from the application's clock.
- **`iec61850-goose`** — `GooseSubscriberBuilder::max_streams` bounds how many
  publications an observer tracks, 64 by default.
- **`iec61850-sv`** — `SvSubscriberBuilder::smp_cnt_limit` sets the value at
  which smpCnt wraps to 0, and `SvSubscriberBuilder::max_streams` bounds how
  many svIDs a subscriber follows, 64 by default.
- **`iec61850-hal`** — `AfPacketSocket::hw_addr` and `PcapSocket::hw_addr`
  return the address of the interface the socket is bound to.
- **`iec61850-mms`** — `MmsClient::identify` and `BlockingMmsClient::identify`
  issue the MMS Identify service and return an `IdentifyResponse` with the
  vendor name, model name and revision of the server, and the abstract
  syntaxes it lists, if any. The request and response PDUs are available as
  `encode_confirmed_identify_request` and `decode_confirmed_identify_response`
  with their counterparts.
- **`iec61850-client`** — `IedConnection::get_server_identity` returns a
  `ServerIdentity` carrying the vendor, model and revision a server reports
  through the MMS Identify service, together with any abstract syntaxes it
  lists.
- **`iec61850-mms`** — `MmsClient::status` and `BlockingMmsClient::status`
  issue the MMS Status service and return a `StatusResponse` with the logical
  and physical status of the server and its local detail bits, if any. A
  status value outside the ones ISO 9506-2 names is kept as the `Other`
  variant of `VmdLogicalStatus` or `VmdPhysicalStatus`. The request and
  response PDUs are available as `encode_confirmed_status_request` and
  `decode_confirmed_status_response` with their counterparts.
- **`iec61850-client`** — `IedConnection::get_server_status` returns a
  `ServerStatus` carrying the logical and physical status a server reports
  through the MMS Status service, together with any local detail bits.
- **`iec61850-server`** — The server answers the MMS Status service with
  `state-changes-allowed` and `operational`, and announces `status` in
  `servicesSupportedCalled`.
- **`iec61850-model`** — `DataObject::child_by_name_fc` and
  `IedModel::node_by_object_ref_fc` find a data attribute under a given
  functional constraint, telling apart the FC=SE and FC=SG data attributes of
  one setting, which `child_by_name` and `node_by_object_ref` do not.
- **`iec61850-tls`** — `TlsConfigBuilder::tls13_session_tickets` sets how many
  TLS 1.3 session tickets a server sends after each handshake, 0 by default.
  `session_resumption(false)` and a zero `session_resumption_lifetime` still
  send no ticket whatever the count.

### Fixed

- **`iec61850-mms`** — A confirmed answer is bound to its request by invokeID.
  A request without an answer within the request timeout returns
  `ServiceTimeout` and leaves the association usable; its late answer, and an
  answer under any other invokeID, is discarded instead of being returned to
  the next request. A Read or Write answer must carry exactly one result.
- **`iec61850-mms`** — Each receive is bounded by one timeout, so
  `recv_unconfirmed_pdu_with_timeout` may wait longer than the request timeout
  instead of failing when the request timeout passes.
- **`iec61850-mms`** — `disconnect` releases the association with an ACSE RLRQ
  in a Session FINISH after the Conclude response and waits for the RLRE in the
  DISCONNECT. A Conclude-ErrorPDU returns `ConcludeRejected` and keeps the
  association; an InformationReport received before the Conclude response is
  kept for a later read.
- **`iec61850-mms`** — The outbound size guard measures the MMS PDU itself, so
  a PDU of exactly the negotiated size is sent, and the negotiated size never
  exceeds the size the client proposed.
- **`iec61850-mms`** — An Unconfirmed PDU with no content is discarded with a
  warning instead of being handed to the caller.
- **`iec61850-mms`** — `MmsClient::connect` resolves a host name and accepts an
  IPv6 literal with or without brackets; it used to take an IP literal only.
- **`iec61850-client`** — `IedConnection::is_connected` turns false as soon as
  a service call finds the connection lost, and later calls return
  `NotConnected`; `poll_reports` returns `NotConnected` when the connection is
  lost while it waits, and `Ok(0)` for an idle wait longer than the request
  timeout. The report dispatcher keeps running after a receive error that
  leaves the association established.
- **`iec61850-client`** — `IedConnection::abort` sends an ACSE abort before
  closing the transport.
- **`iec61850-client`** — A control command the server refuses reports, as the
  cause of `ControlOutcome::Failure`, the AddCause of the `LastApplError`
  InformationReport the server sends ahead of the negative response; it used
  to report `Unknown` whatever the server sent. The report is taken when its
  CntrlObj names the object and, for SelectWithValue, Operate and Cancel, its
  ctlNum and origin are those of the command, so a late report of an earlier
  command is not taken.
- **`iec61850-client`** — An enhanced-security Operate, and
  `try_recv_command_termination` and `wait_command_termination`, take only a
  command termination of the object's `Oper` carrying the command's ctlNum. A
  termination of another object, or a late one of an earlier command, is left
  for the report dispatcher instead of being taken as the result.
- **`iec61850-client`** — The directory services fail with an error when a
  GetNameList page reports more names but does not advance past the previous
  continuation, or when one walk passes one million names, instead of looping
  without end.
- **`iec61850-client`** — `get_logical_node_directory(_, AcsiClass::Sgcb)`
  lists `SGCB` only for `LLN0`; it used to list it for every logical node of a
  logical device that has one.
- **`iec61850-server`** — Control commands no longer run inside the MMS
  dispatcher. An Operate is answered once its wait-for-execution handler has
  finished, negatively when it refuses and positively otherwise, after which
  the control handler runs on its own task; the association keeps serving
  requests meanwhile. Under enhanced security the outcome of the command
  travels only in the CommandTermination. A control write on a
  `current_thread` runtime no longer panics.
- **`iec61850-server`** — An Operate under enhanced security in a write of
  several variables, which is answered when it is accepted, is ended with a
  negative CommandTermination when its wait-for-execution handler refuses it,
  instead of never being terminated.
- **`iec61850-server`** — A buffered report that carries ConfRev together with
  BufOvfl or EntryID sends ConfRev after them, in the order of IEC 61850-8-1;
  such reports could not be parsed before.
- **`iec61850-server`** — A report larger than 65535 bytes is segmented instead
  of overrunning the BER length, which in a debug build panicked in the tick
  loop and stopped all reporting. Every report PDU stays within the smaller of
  the server's maximum PDU size and 65535 bytes, and each segment carries as
  many members as fit.
- **`iec61850-server`** — GetDataSetValues applies the read handler of each
  member, as a direct Read of the member does.
- **`iec61850-server`** — A leaf below a constructed attribute, such as
  `setMag$f` under SP or SE, is writable by its own path, and a constructed
  attribute is writable as a structure with one member per sub-attribute;
  both used to answer `object-access-unsupported`. A refused write leaves
  every leaf unchanged. Such a write is decided by the
  write handlers of the attributes above the leaf as well, outermost first, so
  a handler on a constructed attribute also guards its leaves; one write can
  therefore consult several handlers.
- **`iec61850-server`** — GetNameList resumes at the first name after
  `continueAfter` even when that name is no longer listed; it used to answer
  `object-non-existent`.
- **`iec61850-server`** — A Read that sets specificationWithResult gets its
  variable access specification back, counted against the negotiated PDU size.
- **`iec61850-server`** — The edit session reservation of a setting group
  control block runs on the monotonic clock, so a step of the wall clock no
  longer shortens or extends it.
- **`iec61850-server`** — ReadJournal resolves the journal a log control
  block's `LogRef` names, `<LD>/<LN>$<LogName>`, and GetNameList for the
  Journal class lists the journals of a domain; the journal used to be
  readable only under the key the control block was registered with, and the
  list was always empty. A registration key still names its journal.
- **`iec61850-server`** — A ReadJournal page stops reading the log once the
  response is full, instead of copying every matching entry first.
- **`iec61850-tls`** — A server with no trust anchor and no mandatory client
  authentication builds and requests no client certificate; it used to fail to
  build. Mandatory client authentication without a trust anchor fails with
  `TlsError::Validation`.
- **`iec61850-tls`** — The TLS 1.2 whitelist includes
  `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` and
  `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`, so a peer with an ECDSA
  certificate can negotiate TLS 1.2.
- **`iec61850-goose`** — `Expired` is raised once timeAllowedToLive elapses
  after the last frame even when that frame was out of sequence, such as a
  repeated sqNum or an stNum that moved backwards; such a publication used to
  never expire.
- **`iec61850-goose`** — An observer keeps stNum, sqNum, confRev and expiry
  per gocbRef, so interleaved publications no longer report false rollbacks,
  state changes or confRev changes. The number of publications tracked is
  bounded, and only the first eviction is logged.
- **`iec61850-goose`** — A five-octet INTEGER whose first octet is not 0x00 is
  rejected; it used to be truncated to its low 32 bits.
- **`iec61850-sv`** — A smpCnt that wraps to 0 once a second, as a stream
  synchronized per IEC 61850-9-2LE does, is no longer counted as 61536 missed
  samples. The wrap point is the configured `smp_cnt_limit`, else the smpRate
  of an ASDU sent with smpMod samples-per-second; without either, a smpCnt
  below its predecessor is taken as that reset, so losing sample 0 at the
  reset counts one missed sample rather than 61537.
- **`iec61850-sv`** — A subscriber without an svID filter follows smpCnt
  continuity per svID, so interleaved streams no longer count every ASDU as a
  gap. The number of svIDs followed is bounded, and only the first eviction is
  logged.
- **`iec61850-hal`** — The `AF_PACKET` backend, and the pcap backend on Linux,
  send a frame whose source address is all zero with the interface address in
  its place; a GOOSE publisher without `src_mac` used to put a zero source
  address on the wire. On Windows the source address is still sent as the
  publisher sets it.
- **`iec61850-hal`** — The `AF_PACKET` backend restores the 802.1Q tag the
  kernel moves out of a received frame, so GOOSE and SV subscribers on Linux
  see the VLAN of a tagged frame. Both backends drop a frame larger than the
  receive buffer and report it, instead of returning it truncated; the GOOSE
  and SV receive buffers hold 1522 bytes.
- **`iec61850-sntp`** — The server keeps serving after a datagram longer than
  48 octets, such as a request with an authenticator, and after a reply meets
  an ICMP port unreachable; on Windows either one used to end `run()`. The
  client and server read datagrams of up to 1024 octets and decode the
  48-octet header.
- **`iec61850-sntp`** — The client rejects a reply whose transmit timestamp is
  zero and converts timestamps with the NTP era rule of RFC 4330 §3, so times
  from 2036-02-07 on are correct. `SntpClient::new` has no panicking path.
- **`iec61850-scl`** — A DOType that reaches itself through its `<SDO>` chain
  is rejected with `SemanticConflict` when the file is resolved; building such
  a model used to overflow the stack and abort the process.
- **`iec61850-scl`** — A `<DA>`, `<SDO>` or `<BDA>` declared with `count` is
  warned about; arrays are still built as a single element.
- **`iec61850-scl-build`** — A `<DAI>` value below a constructed attribute,
  such as `rangeC.min.f` or `units.SIUnit`, is applied by the generated model;
  it used to be dropped silently, so the generated model kept the default
  while the runtime model held the configured value.
- **`iec61850-scl-build`** — A generated model starts every leaf from the same
  value as the model built at run time; Dbpos and Tcmd used to start as an
  integer, EntryTime as an empty binary time, and OptFlds, TrgOps, Currency and
  PhyComAddr as empty octet strings.
- **`iec61850-model`** — The default value of an EntryID, an 8-octet string,
  is eight zero octets; it used to be empty, against the octet-string(8) the
  server declares.
- **`iec61850-client`** — `set_rcb_values` with `ENTRY_ID` writes the BRCB
  component `EntryID`; it used to write `EntryId`, which every server refused
  as nonexistent, so a client could not resynchronize a BRCB through it.
- **`iec61850-model`** — `DataObjectBuilder::build` accepts one data attribute
  under FC=SE and one of the same name, type and structure under FC=SG, as an
  SCL file may declare a setting; it used to refuse the pair as a duplicate
  name. A data set entry resolves the attribute that carries its own
  functional constraint, so either one of the pair can be a member.
- **`iec61850-server`** — CreateDataSet resolves a member to the data
  attribute that carries the member's functional constraint, so the FC=SE and
  the FC=SG attribute of one setting are both accepted.
- **`iec61850-mms`** — `SERVER_SERVICES_SUPPORTED` no longer announces
  `cancel`: the MMS layer rejects every Cancel-RequestPDU before a dispatcher
  sees it. `iec61850-server` already withheld the bit.
- **`iec61850-mms`** — The Initiate request of the client announces only the
  services the client issues. `DEFAULT_SERVICES_SUPPORTED_CLIENT` used to set
  `getDomainAttributes`, `kill`, `writeJournal`, `initializeJournal`,
  `reportJournalStatus`, `getCapabilityList`, the file services,
  `unsolicitedStatus` and `cancel`, none of which the client issues or
  handles.
- **`iec61850-server`** — A build with the `control` feature and without
  `reporting` announces `informationReport` in `servicesSupportedCalled`. The
  control subsystem sends `LastApplError` and command terminations as
  InformationReport, and the bit used to follow the reporting subsystem alone.
- **`iec61850-scl-build`** — `compile()` builds the run-time model of every IED
  it generates code for, and an SCL file the run-time path rejects fails the
  build script with `CompileError::ResolveScl`. Such a file used to generate a
  `build_<X>_model` that panicked when called.
- **`iec61850-tls`** — A server refusing a client that offers only RSA key
  exchange or DHE cipher suites reports `AlmCipherNotAllowed`, and one refusing
  a ClientHello without the signature_algorithms extension, as TLS 1.1 and
  older clients send, reports `AlmVersionTooOld`; both refusals used to raise
  no event.
- **Documentation** — The feature descriptions of `iec61850-model`,
  `iec61850-mms`, `iec61850-client` and `iec61850-hal` name the combinations
  that build; the `iec61850-goose` README example compiles; `SECURITY.md`
  lists `with_dangerous_no_sni_verify()` and `time_validation(false)` as the
  TLS settings that weaken the profile; and the conformance statement gives
  the URCB and BRCB attribute order as IEC 61850-8-1 Tables 73 and 72, lists
  the capability-unavailable and service-other errors the server emits, marks
  the SCL `Header` element as skipped, and states that a received ACSE
  password reaches an installed authenticator.

## [0.3.2] - 2026-10-31

### Added

- **`iec61850-server`** — `reporting::handle_set_brcb_field_for_connection`
  applies a SetBRCBValues field write received on a given connection, and the
  server routes every BRCB write it receives through it.
  `handle_set_brcb_field` keeps its signature and binds no connection.

### Fixed

- **`iec61850-server`** — A BRCB a client enables over MMS sends its reports
  to the association that wrote `RptEna`; it used to send none, because the
  write did not record the connection. A client that enables a BRCB without
  writing `EntryID` first receives the buffer from its oldest entry. While the
  BRCB is enabled, a write from another association is refused with
  `object-access-denied`. When the association ends the BRCB is disabled and
  keeps buffering, its `ResvTms` reservation kept, so a client that
  enables it again receives the entries buffered after the last one sent.
- **`iec61850-server`** — A URCB or BRCB a client enables over MMS sends an
  integrity report every `IntgPd` when its `TrgOps` include integrity; the
  period runs from the moment `RptEna` is written true and restarts, with the
  `IntgPd` then in force, each time the control block is enabled again. The
  period used to be started only after an integrity report had been sent, so
  none was ever sent. An `IntgPd` of 0 or `TrgOps` without integrity still send
  no integrity report.
- **`iec61850-server`** — A BRCB reserved with a positive `ResvTms` is held
  for the client that reserved it, identified by the peer address the server
  records for its association, which `Owner` reads back; clients that share an
  address, behind one NAT or on one host, are the same owner, and
  `handle_set_brcb_field_for_connection` called for a connection the server
  has not recorded sees no address, so it cannot write a BRCB with a
  pre-configured owner and leaves a reservation it makes without an owner.
  While the owner's association is open, a write from any other
  association is refused with `object-access-denied`; once it ends, the
  reservation lasts `ResvTms` seconds from that moment, and only a new
  association from the owner's address may write the BRCB and take it back. A
  BRCB with a pre-configured owner accepts writes only from that address.
  Other clients used to be able to write a reserved BRCB, and the reservation
  timer used to start when `ResvTms` was written. A `ResvTms` written as an
  INT16, as `IedConnection::set_rcb_values` sends it, is accepted where it was
  refused with `type-inconsistent`; a `ResvTms` outside 0 to 32767, and an
  unsigned value wider than 32 bits written to any report control block
  field, are refused with `object-value-invalid`, where the unsigned value
  used to be truncated to its low 32 bits.
- **`iec61850-client`** — `ClientReport::reasons` now describes only the
  latest report: a data set member the report omits has empty reasons, where
  it used to keep the reason of the last report that carried it. A member
  absent from a report therefore no longer looks as if it had triggered it.
  `data_set_values` still keeps the previous value of an omitted member.
- **`iec61850-server`** — A bit string that arrives in a remote Write or a
  SetDataSetValues is stored, and handed to a write handler, with the unused
  bits of its last byte cleared, and every bit string a Read returns, whether
  the cached value of the model or the value of a read handler, is sent with
  them cleared, as `IedServer::update_bit_string` already stores them.
  Nonzero unused bits used to be stored, handed on and sent as received.

## [0.3.1] - 2026-10-31

### Added

- **`iec61850-server`** — `IedServer::update_bit_string` and
  `IedServer::update_bit_string_from_int` update a BIT STRING data attribute,
  such as a `Dbpos` or a `Quality`, at run time. `update_bit_string` takes the
  bytes, most significant bit first, and a padding; the bit count must fit the
  declared size of the attribute as a remote Write must, and the unused bits of
  the last byte are stored as zero. `update_bit_string_from_int` takes an
  unsigned value n bits wide, n the declared size from 1 to 32, and writes it
  most significant bit first, so bit 0 of the string carries 2^(n-1): a `Dbpos`
  of 2 is stored as `0x80` with padding 6. A rejected update returns
  `TypeMismatch` and leaves the attribute unchanged; an accepted one triggers
  reports as the other typed updates do.
- **`iec61850-client`** — `IedConnection::write_bit_string`, a typed write of
  a BIT STRING data attribute from its bytes, most significant bit first, and
  its padding; the unused bits of the last byte are sent as zero. Padding of 8
  or more, or nonzero padding with no data, returns `InvalidArgument` without
  sending a request.

### Fixed

- **`iec61850-server`** — a typed `update_*` call triggers reports by the
  trigger options of the attribute it updates. An attribute whose trigger
  options name `qchg` and not `dchg`, such as the `q` of a common data class,
  triggers a quality change, so a report control block enabled for `qchg`
  reports it and one enabled for `dchg` alone does not; every update used to
  trigger a data change. Every other attribute still triggers a data change.
- **`iec61850-server`** — a Write, or a SetDataSetValues member, carrying a
  bit string whose length does not fit the declared size of the attribute is
  refused with `type-inconsistent` and the attribute keeps its value: a
  fixed-size bit string such as a `Dbpos` takes exactly its declared number of
  bits, and a bounded one such as a `Quality` from one bit up to its bound. The
  value variant was the only check, so an empty or 13-bit string could replace
  a two-bit `Dbpos`. A read handler value of such a length is not sent either;
  the read answers `object-value-invalid`.

## [0.3.0] - 2026-10-30

### Changed

> Upgrading from 0.2.x: an `IedServerConfig` or `MmsModelDispatcher` written as
> a struct literal needs the new fields or `..Default::default()`, and an
> exhaustive `match` on `SvError` needs an arm for `DuplicateField`. A server now
> aborts an association that stays silent past the idle timeout or stops reading
> past the send timeout, and a client or server closes a connection whose
> reassembled TSDU passes the bound; each limit is set through the configuration.

- **`iec61850-mms`** — `CotpConnection` bounds a reassembled TSDU at
  `DEFAULT_MAX_TSDU_SIZE`, 73192 bytes, where it was unbounded unless
  `set_max_tsdu_size` was called, so a peer sending DT TPDUs without EOT no
  longer grows the reassembly buffer until memory runs out. A TSDU past the
  limit returns `TsduTooLarge` and moves the connection to `Closed`, so the rest
  of it is never read as the next TSDU. `set_max_tsdu_size(None)` removes the
  bound.
- **`iec61850-sv`** — an `SvSubscriber` no longer takes its sample length
  from the first ASDU it receives, which let a single forged frame shut out the
  real stream. The length is set with `SvSubscriberBuilder::sample_size`, from
  the data set the stream publishes, and an ASDU of any other length is dropped;
  a subscriber built without it delivers every ASDU whatever its sample length.
  `SvSubscriber::expected_sample_size` returns the configured length, or 0.
- **`iec61850-server`** — `IedServerConfig` has new public fields,
  `association_setup_timeout_ms`, `association_idle_timeout_ms`,
  `association_send_timeout_ms`, `max_dynamic_datasets` and
  `max_dynamic_datasets_per_association`, and
  `MmsModelDispatcher` has a new public field, `dynamic_dataset_quota`. A
  configuration or a dispatcher written as a struct literal without
  `..Default::default()` no longer compiles and needs the fields added.
- **`iec61850-server`** — an established association that neither receives a
  PDU nor completes the send of one for
  `IedServerConfig::association_idle_timeout_ms`, 300 000 ms by default, is
  aborted with an ACSE A-ABORT. A report or command termination the peer
  accepts counts as activity, so a client that only receives reports stays
  open. `None` disables the timeout.
- **`iec61850-server`** — every PDU the server sends on an established
  association, including an A-ABORT, must be accepted by the peer within
  `IedServerConfig::association_send_timeout_ms`, 10 000 ms by default. A peer
  that stops reading has its connection closed without a further write, and
  what its association holds is released.
- **`iec61850-server`** — DefineNamedVariableList, the ACSI CreateDataSet
  service, is answered with errorClass `resource capability-unavailable` once
  the data sets created at run time reach
  `IedServerConfig::max_dynamic_datasets`, 64 by default, or the requesting
  association has created
  `IedServerConfig::max_dynamic_datasets_per_association` of them, 16 by
  default. Deleting a data set makes room again. A data set created at run
  time is persistent: it outlives its association and counts against the
  total until it is deleted.

- **`iec61850-sv`** — `SvError` has a new variant, `DuplicateField`, and
  `TooManyAsdus` reports the ASDU count, saturated at 255, where it reported the
  noASDU value; its message reads `asdu count`. An exhaustive `match` on
  `SvError` no longer compiles and needs the new arm.

### Added

- **`iec61850-mms`** — `AlternateAccess::decode_with_negotiated_cap`, and
  `ReadRequest::decode_with_negotiated_cap` with its
  `decode_confirmed_read_request_with_negotiated_cap` wrapper, decoding under
  the negotiated `dataStructureNestingLevel` as a Write request already can.
- **`iec61850-mms`** — `DEFAULT_MAX_TSDU_SIZE`, the default bound on a
  reassembled COTP TSDU: `DEFAULT_MAX_PDU_SIZE` plus 8192 bytes for the Session,
  Presentation and ACSE envelope.
- **`iec61850-sv`** — `SvSubscriberBuilder::sample_size`, the sample length
  every delivered ASDU must have.
- **`iec61850-server`** — `DynamicDatasetQuota`, the limits on the data sets
  DefineNamedVariableList creates, installed on a dispatcher through
  `MmsModelDispatcher::with_dynamic_dataset_quota`.

### Fixed

- **`iec61850-mms`** — the component chain of an `AlternateAccess` is decoded
  to a depth of at most 32, and a deeper chain is rejected with
  `NestingLevelExceeded`. A Read or Write request nesting
  `selectAlternateAccess` without bound could otherwise exhaust the stack and
  abort the process. `ReadRequest::decode_with_negotiated_cap`,
  `WriteRequest::decode_with_negotiated_cap` and
  `AlternateAccess::decode_with_negotiated_cap` lower the limit to the
  negotiated nesting level when that is smaller. `AlternateAccess::index_component`
  refuses a path of more than 32 segments, so every selector it builds decodes.
- **`iec61850-mms`** — `parse_message` refuses a confirmed request on a
  connection whose Initiate has not completed, answering
  Reject(pdu-error/invalid-pdu) without calling the service dispatcher. An AARQ
  whose user information carried a Confirmed-RequestPDU in place of the
  Initiate-RequestPDU was otherwise served before any PDU size or
  outstanding-request limit had been negotiated.
- **`iec61850-mms`** — a `Data` bit-string or boolean-array whose padding
  count is above 7, or is non-zero on an empty bit string, is rejected with
  `InvalidPdu` instead of being decoded into a `BitString` or `BooleanArray`
  that no conforming encoder produces.
- **`iec61850-sv`** — `decode_sav_pdu` decodes every content octet of
  noASDU and drops a frame whose count differs from the ASDUs it carries,
  returning `InvalidFieldLength` with tag `0xA2`, or that has no noASDU at all,
  returning `MissingRequiredField`. Only the low octet of the count was read
  before, and a mismatch was logged but the frame accepted. The sequence of
  ASDU is decoded up to `MAX_ASDU_PER_FRAME` ASDUs whatever noASDU declares; a
  further ASDU returns `TooManyAsdus` before it is parsed. A frame repeating
  noASDU or the sequence of ASDU is dropped with the new
  `SvError::DuplicateField` instead of the later copy replacing the first.
- **`iec61850-mms`** — the `AcseAuthenticator` of an `AcseConnection` is
  handed the credentials the AARQ carries: `AcseAuth::Password` with the
  charstring calling-authentication-value when mechanism-name is the password
  OID, and `AcseAuth::None` otherwise. It was always handed `AcseAuth::None`, so
  an authenticator could not check a password. A failed authentication is
  logged with the mechanism name, never the credentials, and the `Debug`
  output of `AcseAuth::Password` gives the password's length, not its content.
- **`iec61850-server`** — a Write that names a data set, the ACSI
  SetDataSetValues service, writes each member through the same checks as a
  Write that names the member alone: the functional constraint, the write
  access policy, the installed handlers and the value type. A member the
  checks refuse keeps its value and is answered with the same failure, and the
  other members of the request are written independently. The values used to
  be stored into the model without any of these checks.
- **`iec61850-server`** — an AARQ whose user information is any MMS PDU other
  than an Initiate-RequestPDU is answered with an associate reject and the
  socket closed, before the PDU reaches the dispatcher. A confirmed request
  carried there used to be executed even though the association was then
  refused.
- **`iec61850-server`** — a connection that ends on a transport or protocol
  error releases what its association holds as the connection task ends: URCB
  reservations, control selects, the command termination and report senders,
  and the setting group edit session. These used to be released only after an
  orderly close, so a peer that reset its socket after writing `Resv` kept the
  URCB reserved for a connection that no longer existed. The setting group edit
  session is now released on every close, where it used to be held until its
  reservation time expired. A BRCB reservation is still kept until its
  `ResvTms` expires, so the client can resume after reconnecting.
- **`iec61850-server`** — `max_mms_connections` counts a connection from the
  moment its socket is accepted until it closes, where it used to count only
  associations that had completed the Initiate exchange. Sockets that connect
  and then send nothing can no longer accumulate without bound. A connection
  that has not completed the TLS handshake, when TLS is configured, and
  association setup through the Initiate response within
  `IedServerConfig::association_setup_timeout_ms`, 10 000 ms by default, is
  closed.
- **`iec61850-server`** — a Read or Write request is decoded under the
  `dataStructureNestingLevel` negotiated for the association when that is
  smaller than the local limit of 32, so data or an alternate access nested
  deeper than the association allows is answered with a confirmed error
  instead of being decoded.
- **`iec61850-server`** — once the Initiate exchange completes, a connection
  bounds each reassembled COTP TSDU at the negotiated maximum PDU size plus
  8192 bytes of Session, Presentation and ACSE envelope, instead of the
  default bound sized for a 65 000-byte PDU. A TSDU past it closes the
  connection.

## [0.2.0] - 2026-09-06

### Changed

> Upgrading from 0.1.x: the first two entries below change the bytes a client puts on
> the wire during association setup. An IED that checks the calling presentation
> selector or the calling AP-title will see different values and may refuse the
> association until it is reconfigured, or until the previous values are set
> back through `IsoConnectionParameters`.

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
- **`iec61850-server`** — a Read that names a data set, the ACSI
  GetDataSetValues service, charges its access results against the negotiated
  maximum PDU size the same way as a Read that lists its variables. A data set
  whose values do not fit is answered with errorClass `resource other` for the
  whole request instead of a truncated list of access results.
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

[Unreleased]: https://github.com/csp0924/iec61850-rust/compare/v0.3.3...HEAD
[0.3.3]: https://github.com/csp0924/iec61850-rust/releases/tag/v0.3.3
[0.3.2]: https://github.com/csp0924/iec61850-rust/releases/tag/v0.3.2
[0.3.1]: https://github.com/csp0924/iec61850-rust/releases/tag/v0.3.1
[0.3.0]: https://github.com/csp0924/iec61850-rust/releases/tag/v0.3.0
[0.2.0]: https://github.com/csp0924/iec61850-rust/releases/tag/v0.2.0
[0.1.1]: https://github.com/csp0924/iec61850-rust/releases/tag/v0.1.1
[0.1.0]: https://github.com/csp0924/iec61850-rust/releases/tag/v0.1.0
