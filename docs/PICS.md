# Protocol Implementation Conformance Statement

Implementation: **iec61850-rust**, version **0.1.1**.

This document states which ACSI services and models of IEC 61850-7-2, and which
parts of the MMS mapping of IEC 61850-8-1, the crates of this workspace
implement, in the server role, the client role, or both.

This statement has **not been certified by any conformance test body**. It
describes the source code of release 0.1.1 and nothing else. Every entry below
is derived from the implementation; where a service is absent, incomplete, or
constrained, the row says so.

## Identification

| Item | Value |
|---|---|
| Implementation name | iec61850-rust |
| Version | 0.1.1 |
| Roles | Server and client |
| Editions | Edition 1, Edition 2 and Edition 2.1 selectable through `IedServerConfig::edition`; the default is Edition 2 |
| Default identification strings | vendor `rust61850`, model `iec61850-rust`, revision = crate version; all three configurable |
| Default association limit | 5 concurrent MMS associations |
| Platforms | Linux and Windows for the MMS profile; the raw-Ethernet profiles need an L2 backend (see below) |

## Notation

| Symbol | Meaning |
|---|---|
| Y | Implemented |
| N | Not implemented |
| partial | Implemented with the limitation named in the remark |
| – | Not applicable to this role or object |

---

## 1. ACSI basic conformance statement

| Item | Server | Client | Remark |
|---|:---:|:---:|---|
| Client-server association | Y | Y | Two-party application association |
| SCSM: MMS mapping per IEC 61850-8-1 | Y | Y | `iec61850-mms`, `iec61850-server`, `iec61850-client` |
| Transport profile: COTP over TCP/IP (ISO 8073 / RFC 1006) | Y | Y | Full ISO upper stack: COTP, ISO 8327 Session, ISO 8823 Presentation, ISO 8650 ACSE |
| SCSM: GOOSE per IEC 61850-8-1 | Y | Y | `iec61850-goose`, raw Ethernet, EtherType 0x88B8 |
| SCSM: GSSE | N | N | The Edition 1 GSSE mapping is not implemented |
| SCSM: Sampled Values per IEC 61850-9-2 | Y | Y | `iec61850-sv`, raw Ethernet, EtherType 0x88BA, 9-2LE channel layout |
| Routable profiles (R-GOOSE, R-SV over UDP) | N | N | Not implemented |
| Time synchronization: SNTP | Y | Y | `iec61850-sntp`, RFC 4330 SNTPv4 server and client |
| Time synchronization: PTP / IEC 61588 profiles | N | N | Not implemented; an SV ASDU carries `gmIdentity` as an opaque field only |
| Security: TLS per IEC 62351-3 | Y | Y | `iec61850-tls` |
| Security: IEC 62351-6 GOOSE and SV signatures | N | N | Not implemented |

Raw-Ethernet backends for GOOSE and Sampled Values are supplied by
`iec61850-hal`: `AF_PACKET` on Linux, and libpcap or the NPCAP runtime
elsewhere. macOS and BSD backends are absent.

---

## 2. ACSI models conformance statement

| Model | Server | Client | Remark |
|---|:---:|:---:|---|
| Server, logical device, logical node, data | Y | Y | Model tree in `iec61850-model`; MMS projection in `iec61850-server::mapping` |
| Data set (predefined) | Y | Y | |
| Data set (created at run time) | Y | Y | DefineNamedVariableList and DeleteNamedVariableList, domain scope only |
| Substitution | partial | partial | The SV functional constraint is writable by policy and `MV`/`CMV`/`SAV` carry the substitution attributes; the server Read path does not itself pivot to the substituted value |
| Setting group control | Y | partial | Server: full SGCB runtime. Client: driven through generic writes; no dedicated setting-group API |
| Unbuffered reporting (URCB) | Y | Y | |
| Buffered reporting (BRCB) | Y | Y | Includes buffer overflow indication, EntryID resynchronization and an optional persistent buffer |
| Logging (LCB, journal) | partial | partial | Recording and ReadJournal retrieval are implemented; four LCB status attributes are not served (see 3.7) |
| Control (DOns, SBOns, DOes, SBOes) | Y | Y | All four control models plus status-only |
| GOOSE publish | Y | – | |
| GOOSE subscribe | – | Y | |
| GoCB access over MMS | partial | partial | Nine attributes readable; `GoEna` and `GoID` writable |
| Sampled Values publish | Y | – | |
| Sampled Values subscribe | – | Y | |
| SvCB (MSVCB / USVCB) access over MMS | N | N | Sampled Values control blocks are not exposed as MMS variables |
| Time synchronization | Y | Y | SNTP only |
| File transfer | N | N | No file service is implemented in either role |

---

## 3. ACSI service conformance statement

### 3.1 Application association

| Service | Server | Client | Remark |
|---|:---:|:---:|---|
| Associate | Y | Y | ACSE AARQ / AARE over Presentation, Session and COTP; MMS Initiate negotiated |
| Abort | Y | Y | Both the peer-initiated ACSE abort and an immediate transport close |
| Release | Y | Y | ACSE RLRQ / RLRE, with MMS Conclude and a Session FINISH timeout on the server |
| Association authentication: none | Y | Y | Default |
| Association gating on calling AP-title and AE-qualifier | Y | – | The server calls an application-supplied authenticator with the calling application reference and refuses the AARQ when it returns false |
| Association authentication: ACSE password | N | N | The AARQ encoder can emit the charstring password mechanism, but the server skips `calling-authentication-value` and always invokes the authenticator with no credentials, and no client API exposes a password |
| Association authentication: certificate (IEC 62351-4 mechanism OID) | N | N | Peer authentication is performed by TLS; the ACSE mechanism-name OID is not emitted |

### 3.2 Server, logical device, logical node and data

| Service | Server | Client | Remark |
|---|:---:|:---:|---|
| GetServerDirectory (LOGICAL-DEVICE) | Y | Y | MMS GetNameList, domain class |
| GetServerDirectory (FILE) | N | N | Client rejects the request locally; no file service exists |
| GetLogicalDeviceDirectory | Y | Y | |
| GetLogicalNodeDirectory (DATA) | Y | Y | |
| GetLogicalNodeDirectory (DATA-SET) | Y | Y | Always resolved against the server |
| GetLogicalNodeDirectory (URCB / BRCB / GoCB / LCB / SGCB) | Y | Y | Control blocks registered at run time are merged into the domain name list |
| GetLogicalNodeDirectory (LOG) | Y | Y | Journal object class; the server answers an empty list |
| GetLogicalNodeDirectory (GsCB / MSVCB / USVCB) | N | N | The client refuses the request rather than returning a misleading empty list |
| GetAllDataValues | Y | N | Server expands a whole logical node or one functional-constraint group under a PDU budget; the client has no single-call equivalent |
| GetDataValues | Y | Y | Includes sub-data-object nesting to any depth |
| SetDataValues | Y | Y | Server-side writes are gated by a functional-constraint policy, `SP \| SV \| SE` by default; `DC`, `CF` and `BL` can be enabled |
| GetDataDirectory | Y | Y | |
| GetDataDirectory by functional constraint | – | Y | Client convenience over the same wire service |
| GetDataDefinition (GetVariableAccessAttributes) | Y | Y | Type specification including nested sub-data attributes |
| Single array element access, read | Y | Y | MMS `AlternateAccess` per IEC 61850-8-1 §17, index and index-with-component |
| Single array element access, write | N | Y | The server answers `object-access-unsupported`: per-element storage is not materialized |

### 3.3 Data set

| Service | Server | Client | Remark |
|---|:---:|:---:|---|
| GetDataSetValues | Y | Y | MMS Read with a `VariableListName`; per-entry access results |
| SetDataSetValues | Y | Y | A value count that differs from the member count fails every entry with `type-inconsistent` |
| GetDataSetDirectory | Y | Y | GetNameList over the named-variable-list class |
| CreateDataSet | Y | Y | MMS DefineNamedVariableList, domain scope; association scope is not implemented |
| DeleteDataSet | Y | Y | MMS DeleteNamedVariableList; a statically configured data set is refused |
| GetDataSetAttributes (GetNamedVariableListAttributes) | N | N | The server has no handler and does not advertise the service; the client issues no such request |

### 3.4 Setting group control

| Service | Server | Client | Remark |
|---|:---:|:---:|---|
| GetSGCBValues | Y | partial | Whole block or a single attribute: `NumOfSG`, `ActSG`, `EditSG`, `CnfEdit`, `LActTm`, `ResvTms`. The client reads it through the generic data path |
| SetSGCBValues (SelectActiveSG) | Y | partial | `ActSG` accepts 1 through the configured group count |
| SelectEditSG | Y | partial | An edit session is bound to one association and carries a reservation deadline; a competing association receives `temporarily-unavailable` |
| ConfirmEditSG | Y | partial | `CnfEdit = true` commits and notifies the application |
| GetEditSGValue / SetEditSGValue | Y | Y | Ordinary Read and Write of data attributes under functional constraint SE |

### 3.5 Unbuffered reporting

| Service | Server | Client | Remark |
|---|:---:|:---:|---|
| Report | Y | Y | MMS InformationReport |
| GetURCBValues | Y | Y | Whole-block read returns the twelve attributes in the order of IEC 61850-8-1 Table 30 |
| SetURCBValues | Y | Y | Per attribute; the client orders the sequence so that `RptEna = false` is first and a general interrogation is last |
| Trigger option: data-change | Y | Y | |
| Trigger option: quality-change | Y | Y | |
| Trigger option: data-update | Y | Y | |
| Trigger option: integrity | Y | Y | Driven by `IntgPd` |
| Trigger option: general interrogation | Y | Y | |
| Option field: sequence-number | Y | Y | |
| Option field: report-time-stamp | Y | Y | |
| Option field: reason-for-inclusion | Y | Y | |
| Option field: data-set-name | Y | Y | |
| Option field: data-reference | Y | Y | |
| Option field: buffer-overflow | – | – | Forcibly cleared on an unbuffered control block before encoding |
| Option field: entryID | – | – | Forcibly cleared on an unbuffered control block before encoding |
| Option field: conf-revision | Y | Y | |
| Option field: segmentation | Y | Y | A report larger than the negotiated PDU size is split, numbered with `subSeqNum` and flagged with `moreFollows` |
| Reservation (`Resv`) | Y | Y | Unbuffered control blocks only |

### 3.6 Buffered reporting

| Service | Server | Client | Remark |
|---|:---:|:---:|---|
| Report | Y | Y | |
| GetBRCBValues | partial | Y | Every attribute is readable individually, `RptID`, `RptEna`, `DatSet`, `ConfRev`, `OptFlds`, `BufTm`, `SqNum`, `TrgOps`, `IntgPd`, `GI`, `Owner`, `EntryID`, `PurgeBuf`, `TimeofEntry` and `ResvTms` included. A read that names the whole control block, and a read of `Resv`, answer `object-access-unsupported` |
| SetBRCBValues | Y | Y | `ConfRev`, `SqNum` and `Owner` are refused as read-only; a configuration attribute is refused while `RptEna` is true |
| EntryID resynchronization | Y | Y | An eight-octet EntryID; an unknown identifier is refused with `object-value-invalid` |
| PurgeBuf | Y | Y | Purges while `RptEna` is false |
| ResvTms | Y | Y | Edition 2 INT16 reservation, optional per control block |
| Buffer overflow indication | Y | Y | With a dropped-entry counter |
| Buffer persistence across a restart | Y | – | Optional SQLite backend, off by default |
| Trigger options and option fields | Y | Y | As in 3.5, plus buffer-overflow and entryID, which a buffered block does not mask |

### 3.7 Logging

| Service | Server | Client | Remark |
|---|:---:|:---:|---|
| Log (implicit recording on trigger) | Y | – | Entries are written to a `LogStorage` backend; an in-memory backend ships with the crate |
| GetLCBValues | partial | N | `LogEna`, `LogRef`, `DatSet`, `TrgOps` and `IntgPd` are served, individually or as one structure. `OldEntrTm`, `NewEntrTm`, `OldEntr` and `NewEntr` answer `object-access-unsupported`: the storage trait exposes no accessor for them. The client has no dedicated LCB API |
| SetLCBValues | N | N | No write route resolves a log control block path |
| GetLogStatusValues | N | N | The four journal status attributes above are not served |
| QueryLogByTime | Y | Y | MMS ReadJournal with a time range |
| QueryLogAfter | Y | Y | MMS ReadJournal with a starting time and entry identifier |
| ReadJournal pagination | Y | Y | Entries are added while they fit the negotiated PDU size; the response then sets `moreFollows` and the client resumes from the last entry it received |
| WriteJournal | N | N | The server answers `object-access-unsupported` rather than rejecting the tag |

A server built with the logging subsystem sets the MMS `readJournal` bit in the
`servicesSupported` bitmap of its Initiate-Response, so a client that selects
its own request paths from that bitmap will use both log queries. See
section 5.

### 3.8 Control

| Service | Server | Client | Remark |
|---|:---:|:---:|---|
| Select (SBO) | Y | Y | Issued as a Read of `<LN>$CO$<DO>$SBO` |
| SelectWithValue (SBOw) | Y | Y | |
| Cancel | Y | Y | Accepted while selected and while waiting for an activation time; refused while a command is executing |
| Operate | Y | Y | |
| CommandTermination | Y | Y | Positive and negative, on the enhanced-security models only |
| TimeActivatedOperate | partial | N | The server decodes the seven-element `Oper` structure and passes `operTm` to the application handler, but does not itself defer execution to the activation time. The client encodes the six-element form only |
| Control model: status-only | Y | Y | |
| Control model: direct-with-normal-security | Y | Y | |
| Control model: SBO-with-normal-security | Y | Y | |
| Control model: direct-with-enhanced-security | Y | Y | |
| Control model: SBO-with-enhanced-security | Y | Y | |
| `sboClass`: operate-once and operate-many | Y | – | |
| Attributes `origin`, `ctlNum`, `T`, `Test`, `Check` | Y | Y | `Check` carries synchro-check and interlock-check |
| LastApplError / AddCause | Y | Y | The add-cause values of IEC 61850-7-2 §20 are mapped onto MMS data access errors |
| Select timeout | Y | – | Per control object |

### 3.9 GOOSE

| Service | Server | Client | Remark |
|---|:---:|:---:|---|
| SendGOOSEMessage (publish) | Y | – | `GoosePublisher`; the frame header is prebuilt and the publish path does not allocate |
| Retransmission profile | Y | – | Configurable intervals with a backoff after a state change |
| Simulation (test) bit, `ndsCom`, VLAN tag and priority | Y | Y | |
| GOOSE subscribe | – | Y | `GooseSubscriber` and `GooseReceiver`, with `stNum` and `sqNum` continuity tracking and time-allowed-to-live supervision |
| GetGoCBValues | partial | partial | Nine attributes: `GoCBRef`, `GoEna`, `GoID`, `DatSet`, `ConfRev`, `NdsCom`, `DstAddress`, `MinTime`, `MaxTime`, readable individually or as one structure |
| SetGoCBValues | partial | partial | `GoEna` and `GoID` are writable; the other seven answer `object-access-denied`. A control block is written one attribute at a time |
| GetGOOSEElementNumber, GetGoReference | N | N | Not implemented |

### 3.10 Sampled Values

| Service | Server | Client | Remark |
|---|:---:|:---:|---|
| SendMSVMessage (publish) | Y | – | `SvPublisher`; multi-ASDU frames, `smpCnt`, `smpSynch`, `smpRate`, `smpMod`, `refrTm` and `gmIdentity` |
| Sampled Values subscribe | – | Y | `SvSubscriber` with per-`svID` filtering and sample continuity |
| 9-2LE channel layout | Y | Y | Four current and four voltage channels with quality |
| GetMSVCBValues / SetMSVCBValues | N | N | Sampled Values control blocks are not exposed as MMS variables |
| GetUSVCBValues / SetUSVCBValues | N | N | Unicast Sampled Values are not implemented |
| Protection profile, 256 samples per cycle | N | N | Not implemented |

### 3.11 Time synchronization

| Service | Server | Client | Remark |
|---|:---:|:---:|---|
| SNTP server | Y | – | RFC 4330 SNTPv4 unicast, mode 3 to mode 4, stratum 1 |
| SNTP client | – | Y | Queries an NTP or SNTP server with a receive timeout |
| Time quality reporting | Y | Y | `leapSecondsKnown`, `clockFailure`, `clockNotSynchronized` and `timeAccuracy` per IEC 61850-7-2 §6.2.3.4 |
| PTP / IEC 61588 | N | N | Not implemented |

### 3.12 File transfer

| Service | Server | Client | Remark |
|---|:---:|:---:|---|
| GetFile | N | N | Not implemented |
| SetFile | N | N | Not implemented |
| DeleteFile | N | N | Not implemented |
| GetFileAttributeValues | N | N | Not implemented |
| GetServerDirectory (FILE) | N | N | Not implemented |

---

## 4. MMS services used

The MMS services below are those the server dispatches and the client issues.
Service tags are as in ISO 9506-2.

| MMS service | Tag | Server | Client |
|---|:---:|:---:|:---:|
| Initiate | – | Y | Y |
| Conclude | – | Y | Y |
| Abort | – | Y | Y |
| Cancel | `0x83` | N | N |
| Status | `0x80` | N | N |
| GetNameList | `0xa1` | Y | Y |
| Identify | `0x82` | Y | Y |
| Read | `0xa4` | Y | Y |
| Write | `0xa5` | Y | Y |
| GetVariableAccessAttributes | `0xa6` | Y | Y |
| DefineNamedVariableList | `0xab` | Y | Y |
| GetNamedVariableListAttributes | `0xac` | N | N |
| DeleteNamedVariableList | `0xad` | Y | Y |
| InformationReport | – | Y | Y |
| ReadJournal | `0xbf 0x41` | Y | Y |
| WriteJournal | `0xbf 0x42` | N | N |
| File services (fileOpen, fileRead, fileClose, fileDirectory, obtainFile) | – | N | N |

Any other service tag is answered with a Reject PDU.

---

## 5. Association negotiation and `servicesSupported`

| Parameter | Server value |
|---|---|
| Maximum MMS PDU size proposed | 65000 octets; the negotiated value is the smaller proposal, floored at 64 |
| Maximum outstanding calling / called requests | 5 each, floored at 1 |
| `dataStructureNestingLevel` | Proposed 10, accepted up to 32 |
| `parameterCBB` | `str1`, `str2`, `vnam`, `valt`, `vlis`; the negotiated value is the bitwise AND with the peer's proposal |

The `servicesSupportedCalled` bitmap is computed from the subsystems the build
includes, so that it announces exactly what the dispatcher answers.

| Bit | Announced when |
|---|---|
| `status` | Never; no handler exists |
| `getNameList`, `identify`, `read`, `write`, `getVariableAccessAttributes` | Always |
| `defineNamedVariableList`, `deleteNamedVariableList`, `informationReport` | The reporting subsystem is compiled in |
| `getNamedVariableListAttributes` | Never; no handler exists |
| `readJournal` | The logging subsystem is compiled in |
| `writeJournal` | Never; the request is answered with an access error rather than served |
| `conclude` | Always |
| `cancel` | Never; a Cancel-RequestPDU is rejected at the PDU layer |
| File and obtain-file services | Never |

The bitmap reflects the compiled subsystems, not the registry contents. Control
blocks, data sets and log control blocks are registered after the dispatcher is
built, while the bitmap is sent once per association, so gating it on what is
registered at that moment would announce less than the server goes on to serve.

The `servicesSupportedCalling` bitmap a peer proposes is recorded and logged but
never enforced: a peer that uses a service it did not announce is still served.

---

## 6. Security

| Item | Support | Remark |
|---|:---:|---|
| TLS 1.2 | Y | The minimum version required by IEC 62351-3 Annex A, and the default floor |
| TLS 1.3 | Y | |
| TLS 1.0 / 1.1 | N | Not offered |
| Cipher suite whitelist | Y | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`. The list is fixed at compile time and cannot be extended through the API |
| Finite-field DHE suites | N | The cryptographic provider in use implements none |
| Server certificate validation | Y | Standard chain validation against a configured trust anchor set |
| Mutual authentication (client certificate) | Y | Optional or required |
| Pinned-certificate mode | Y | Only the listed leaf certificates are accepted; an empty list is refused rather than treated as "accept any" |
| Relaxed validity-time mode | Y | Downgrades expiry errors only; every other chain error still fails |
| Revocation checking: CRL | Y | Static CRL lists supplied by the operator as PEM or DER and installed on both the server and the client certificate verifier; the events `WrnCrlExpired` and `AlmCertRevoked` report the outcome. Distribution points are not fetched: the operator keeps the lists current |
| Revocation checking: OCSP | N | Neither stapling nor a responder query is implemented |
| Session resumption | Y | Enabled by default; disableable, and the TLS 1.3 ticket lifetime is configurable on the server |
| Session renegotiation | N | Never initiated, and not exposed through the API |
| IEC 62351-3 event reporting | Y | The nineteen event codes of IEC 62351-3 §5, delivered to a caller-supplied handler |
| IEC 62351-4 application-layer authentication | N | Peer authentication is performed by TLS alone; no ACSE authentication mechanism is negotiated (see 3.1) |
| IEC 62351-6 GOOSE and SV authentication | N | Not implemented |

---

## 7. SCL support (IEC 61850-6)

`iec61850-scl` parses an SCL, ICD or CID file in two stages and builds a runtime
model from it. `iec61850-scl-build` generates the same model at compile time.

| SCL element | Support | Remark |
|---|:---:|---|
| `Header` | Y | |
| `IED`, `AccessPoint`, `Server`, `LDevice`, `LN0`, `LN` | Y | |
| `DOI`, `SDI`, `DAI`, `Val` | Y | Instance values, including nested sub-data instances |
| `DataSet`, `FCDA` | Y | |
| `ReportControl` with `TrgOps`, `OptFields` | Y | Buffered and unbuffered |
| `LogControl` | Y | |
| `SettingControl` | Y | |
| `GSEControl` | Y | |
| `SampledValueControl` | Y | Parsed into the model; no MMS projection (see 3.10) |
| `DataTypeTemplates`: `LNodeType`, `DOType`, `DAType`, `EnumType`, `DO`, `SDO`, `DA`, `BDA`, `EnumVal` | Y | Type references are resolved and cross-checked |
| `Communication` (`SubNetwork`, `ConnectedAP`, `Address`, `GSE`, `SMV`) | N | The subtree is skipped with a warning; addressing parameters are supplied by the application |
| `Substation` | N | The subtree is skipped with a warning |
| `Inputs` / `ExtRef` | N | Skipped |
| `RptEnabled` | N | Skipped; it constrains service negotiation rather than the model |
| `Services` | N | Skipped |

A parse failure reports the line, the column, the element path, the attribute
name, and the value found against the value expected. A file is never accepted
silently.

---

## 8. Summary of limitations

The following are the entries above that a system integrator is most likely to
need before selecting this implementation.

1. **File transfer is absent** in both roles.
2. **Sampled Values control blocks are not reachable over MMS**; a Sampled
   Values stream is configured through the publisher API.
3. **TimeActivatedOperate is not scheduled by the server**; the activation time
   is passed to the application, which is responsible for honoring it.
4. **Four log control block status attributes** (`OldEntrTm`, `NewEntrTm`,
   `OldEntr`, `NewEntr`) are not served, so GetLogStatusValues has no complete
   answer; SetLCBValues is not implemented at all.
5. **Writing a single array element is refused** by the server.
6. **A whole-block read of a buffered report control block** answers
   `object-access-unsupported`; the attributes must be read individually.
7. **The Communication and Substation sections of an SCL file are not parsed**,
   so GOOSE and Sampled Values addressing is not taken from SCL.
8. **GetNamedVariableListAttributes has no server handler**, and no ACSE
   authentication mechanism is negotiated: an association is authenticated by
   TLS or not at all.
9. **Revocation checking is CRL only**, from static lists the operator keeps
   current; there is no OCSP and no distribution-point fetching. No
   IEC 62351-6 signatures on GOOSE or Sampled Values.
