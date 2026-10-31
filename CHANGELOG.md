# Changelog

All notable changes to this project are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Every crate in the workspace shares one version number.

## [Unreleased]

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
  session ticket by default; it used to send two. A libiec61850 TLS client
  built with mbedtls 3.6.0 closes the connection when it receives one, which
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

[Unreleased]: https://github.com/csp0924/iec61850-rust/compare/v0.3.2...HEAD
[0.3.2]: https://github.com/csp0924/iec61850-rust/releases/tag/v0.3.2
[0.3.1]: https://github.com/csp0924/iec61850-rust/releases/tag/v0.3.1
[0.3.0]: https://github.com/csp0924/iec61850-rust/releases/tag/v0.3.0
[0.2.0]: https://github.com/csp0924/iec61850-rust/releases/tag/v0.2.0
[0.1.1]: https://github.com/csp0924/iec61850-rust/releases/tag/v0.1.1
[0.1.0]: https://github.com/csp0924/iec61850-rust/releases/tag/v0.1.0
