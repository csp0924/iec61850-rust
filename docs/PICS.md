# Protocol Implementation Conformance Statement

Implementation: **iec61850-rust**, version **0.3.3**.

This document states which ACSI services and models of IEC 61850-7-2, and which
parts of the MMS mapping of IEC 61850-8-1, the crates of this workspace
implement, in the server role, the client role, or both.

This statement has **not been certified by any conformance test body**. It
describes the source code of release 0.3.3 and nothing else. Every entry below
is derived from the implementation; where a service is absent, incomplete, or
constrained, the row says so.

## Identification

| Item | Value |
|---|---|
| Implementation name | iec61850-rust |
| Version | 0.3.3 |
| Roles | Server and client |
| Editions | Edition 2 by default. `IedServerConfig::edition` selects Edition 1, Edition 2 or Edition 2.1; the only behavior that depends on it is whether a client may write the `GoID` and `DatSet` of a GOOSE control block, which Edition 2.1 makes read-only (IEC 61850-8-1 Table 83). Edition 1 behaves as Edition 2 |
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
elsewhere. macOS and BSD backends are absent. The `AF_PACKET` backend delivers
received frames with their 802.1Q tag, and on Linux a frame sent with an
all-zero source address carries the interface address instead; on Windows the
source address is sent as the publisher sets it. The pcap backend polls a
non-blocking capture, so receive timeouts are honored on every platform it
supports; `iec61850_hal::ethernet::open_socket` picks the backend the build
provides. Linux with `AF_PACKET` is the supported deployment path; the libpcap
and NPCAP backends serve development and testing.

---

## 2. ACSI models conformance statement

| Model | Server | Client | Remark |
|---|:---:|:---:|---|
| Server, logical device, logical node, data | Y | Y | Model tree in `iec61850-model`; MMS projection in `iec61850-server::mapping` |
| Data set (predefined) | Y | Y | A member is functional-constrained data (a data object or sub-data-object) or a functional-constrained data attribute of any type; it may name an array, or one element of an array by its index |
| Data set (created at run time) | Y | Y | DefineNamedVariableList and DeleteNamedVariableList, domain scope only |
| Substitution | partial | partial | The SV functional constraint is writable by policy and `MV`/`CMV`/`SAV` carry the substitution attributes; the server Read path does not itself pivot to the substituted value |
| Setting group control | Y | partial | Server: the SGCB control protocol, and the values of every setting group, which SelectActiveSG and SelectEditSG load and ConfirmEditSGValues stores (see 3.4). Client: driven through generic writes; no dedicated setting-group API |
| Unbuffered reporting (URCB) | Y | Y | |
| Buffered reporting (BRCB) | Y | Y | Includes buffer overflow indication, EntryID resynchronization and an optional persistent buffer |
| Logging (LCB, journal) | partial | partial | Recording on data-change, quality-change, data-update and integrity, LCB reads and ReadJournal retrieval are implemented; general interrogation writes no log entry, as IEC 61850-7-2 does not support it for logging, and SetLCBValues is not implemented (see 3.7) |
| Control (DOns, SBOns, DOes, SBOes) | Y | Y | All four control models plus status-only |
| GOOSE publish | Y | – | |
| GOOSE subscribe | – | Y | |
| GoCB access over MMS | partial | partial | The nine components of IEC 61850-8-1 Table 83, readable whole, by component and by `DstAddress` member; `GoEna` writable; `GoID` and `DatSet` writable while `GoEna` is false under Edition 2, read-only under Edition 2.1 |
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
| Associate | Y | Y | ACSE AARQ / AARE over Presentation, Session and COTP; MMS Initiate negotiated. The server uses the presentation context identifiers the client chose, in its PDUs and as the indirect-reference of the AARE user-information, and answers each presentation context of the CP in the CPA, accepting ACSE and MMS with BER and rejecting any other; a refused association is answered with a Session REFUSE carrying a Presentation CPR, with the rejecting AARE as its user data for a refusal by the ACSE user and the Initiate-ErrorPDU in that AARE for a refused Initiate |
| Abort | Y | Y | The client sends an ACSE ABRT inside a Session AB; the server accepts both a peer-initiated ACSE abort and an immediate transport close, and sends an ACSE ABRT naming the service user when it aborts on its own decision (idle timeout, `abort_connection`, shutdown) and the service provider on a protocol error |
| Release | Y | Y | ACSE RLRQ / RLRE: after the MMS Conclude the client sends the RLRQ in a Session FINISH and the server answers with the RLRE in a Session DISCONNECT; the server sends no FINISH of its own and closes a concluded association that sends no FINISH within 10 s. A Session FINISH from the peer in the middle of an association is answered by the client with a Session DISCONNECT carrying the RLRE |
| Association authentication: none | Y | Y | Default; without an `AssociationAuthenticator` the server accepts every AARQ |
| Association gating on calling AP-title and AE-qualifier | Y | – | An `AssociationAuthenticator` installed with `IedServerBuilder::authenticator` or `IedServer::set_authenticator` receives the called and calling AP-title and AE-qualifier of each AARQ, its ACSE credentials and the peer address, and accepts or refuses the association. A refusal is a Session REFUSE carrying a Presentation CPR whose user data is an AARE with result rejected-permanent, the acse-service-user diagnostic the authenticator names, such as calling-AP-title-not-recognized, and an Initiate-ErrorPDU with errorClass access and errorCode object-access-denied as its user-information (IEC 61850-8-1 §8.1.3.4.2.1); the socket is then closed. The client sets its AP-titles and AE-qualifiers in `IsoConnectionParameters` |
| Association authentication: ACSE password | Y | Y | The client sends the password mechanism (2.2.3.1) with a charstring value from `IsoConnectionParameters::authentication`; the server hands it to the `AssociationAuthenticator`, and logs only the mechanism and the decision, never the password. The client reports a refusal whose diagnostic names the calling AP-title, AE-qualifier or invocation identifier, or the authentication, as `ClientError::AuthenticationRejected`. A refusal carries both the ACSE diagnostic and the Initiate-ErrorPDU access object-access-denied. The password travels in clear unless the association runs over TLS. Any other mechanism, and a password value that is not a charstring, reach the authenticator as `AcseAuth::Other` with the mechanism-name and the value |
| Association authentication: certificate (IEC 62351-4 mechanism OID) | N | N | Not supported. Peer authentication is performed by TLS. The mechanism-name and the structure of the authentication value of IEC 62351-4 have not been confirmed against the text of IEC 62351-4, so the mechanism is neither sent nor recognised; an AARQ carrying it reaches the authenticator as an unrecognised mechanism |

### 3.2 Server, logical device, logical node and data

| Service | Server | Client | Remark |
|---|:---:|:---:|---|
| GetServerDirectory (LOGICAL-DEVICE) | Y | Y | MMS GetNameList, domain class |
| GetServerDirectory (FILE) | N | N | Client rejects the request locally; no file service exists |
| GetLogicalDeviceDirectory | Y | Y | |
| GetLogicalNodeDirectory (DATA) | Y | Y | |
| GetLogicalNodeDirectory (DATA-SET) | Y | Y | Always resolved against the server |
| GetLogicalNodeDirectory (URCB / BRCB / GoCB / LCB / SGCB) | Y | Y | Control blocks registered at run time are merged into the domain name list; a report, log or GOOSE control block is listed with its group and its members. The SGCB is listed, and served, only in `LLN0`. The client walk stops with `ClientError::NameListLimit` past `IedConnection::with_max_name_list_names` names, one million by default, and fails with `ClientError::NameListNotAdvancing` when a page that reports more names ends on its continuation or brings no name not yet received; names are kept in the order the server sends them, each once, and no order is required |
| GetLogicalNodeDirectory (LOG) | Y | Y | Journal object class: the journals the `LogRef` of each registered log control block names, exactly the journals ReadJournal reads |
| GetLogicalNodeDirectory (GsCB / MSVCB / USVCB) | N | N | The client refuses the request rather than returning a misleading empty list |
| GetAllDataValues | Y | N | Server expands a whole logical node or one functional-constraint group under a PDU budget, its registered report, log, GOOSE and setting group control blocks included, each attribute through the read handlers that cover it; the client has no single-call equivalent |
| GetDataValues | Y | Y | Includes sub-data-object nesting to any depth; an attribute resolves only under its own functional constraint. A read handler decides every read that covers its node: a read of the node, of any node above it up to the logical node or a functional-constraint group, and of any node below it, including reads with an alternate access; the handler context names both its own path and the requested one. A read handler runs while the server holds none of its locks, so it may call the server; the values a read returns are taken after every handler has answered. A read sees a concurrent write of a data object or constructed attribute whole or not at all. The client reads several variables with one MMS Read through `read_objects`, needing no temporary data set |
| SetDataValues | Y | Y | Server-side writes are gated by a functional-constraint policy, `SP \| SV \| SE` by default; `DC`, `CF` and `BL` can be enabled. The reference is an FCD (a data object or sub-data-object, whose value is the structure GetVariableAccessAttributes describes for it) or an FCDA (a data attribute or any sub-attribute). Every leaf is checked against its declared type (integer range: `object-value-invalid`; string, octet string and binary time length: `type-inconsistent`, IEC 61850-8-1 §8.1.3.4.4.2) and every write handler on the target, above it and below it is consulted before any leaf is written; one failure fails the whole write. A bit string shorter than its `Max(n)` size is stored padded to n bits. A written value raises the report and log triggers its attributes declare, as an application update does. A Write names at most 4096 items; beyond, `resource capability-unavailable` |
| GetDataDirectory | Y | Y | |
| GetDataDirectory by functional constraint | – | Y | Client convenience over the same wire service |
| GetDataDefinition (GetVariableAccessAttributes) | Y | Y | Type specification including nested sub-data attributes and arrays, and the registered report, log, GOOSE and setting group control blocks, down to the members of a GoCB `DstAddress`. A name past an array answers `object-non-existent`, as Read does. A specification that would exceed the negotiated maximum PDU size is answered with `resource other` |
| Single array element access, read | Y | Y | MMS `AlternateAccess` per IEC 61850-8-1 §24.2.2.4: an index, optionally followed by components, on an array of data attributes or of sub-data-objects, and component chains, which read as the flattened name. `indexRange` and `allElements` are out of the scope of IEC 61850-8-1 Table 138 and answer `object-access-unsupported` |
| Single array element access, write | Y | Y | An index, optionally followed by components; the value is checked against the element type, and the write handlers on the array and above it decide the write. A whole array is written with exactly its element count |

### 3.3 Data set

| Service | Server | Client | Remark |
|---|:---:|:---:|---|
| GetDataSetValues | Y | Y | MMS Read with a `VariableListName`; per-entry access results, each member read through the read handlers on it and above it, as a read of its path would be; a member under SE answers `temporarily-unavailable` while EditSG is 0. A member naming a data object or a constructed attribute answers the structure a Read of its name answers; a read handler refusing any attribute at, above or below it fails that member alone. A member naming an array element is read through the read handlers of the array, as a Read of the array with that alternate access is. A data set that does not exist fails the service with `object-non-existent`. A list of access results that would exceed the negotiated maximum PDU size is answered with `resource other` for the whole request, not truncated |
| SetDataSetValues | Y | Y | A value count that differs from the member count fails every entry with `type-inconsistent`. A member naming an array element is written as that element of the array, through the write handlers of the array and above it. A Write names at most 4096 items; beyond, `resource capability-unavailable` |
| GetDataSetDirectory | Y | Y | MMS GetNamedVariableListAttributes: the member list, each member as an IEC reference with its functional constraint, a data object member by its own name (FCD), a member naming a whole array by its name, and a member naming an array element as the variable naming the array with an alternate access selecting the index and then each component (IEC 61850-8-1 §24.2.2.4.1.3, Table 140), plus `mmsDeletable`. Enumerating the data set *names* of a logical node is a different service, GetLogicalNodeDirectory(DataSet), which maps onto MMS GetNameList. A member list that would exceed the negotiated maximum PDU size is answered with `resource other` |
| CreateDataSet | Y | Y | MMS DefineNamedVariableList, domain scope; association scope (`@<name>`) is not implemented in either role. The name is `<LN>$<name>` of an existing logical node. A member is functional-constrained data, a data object or sub-data-object, or a functional-constrained data attribute of any type (IEC 61850-7-2 §13.2.2.3), and may name a whole array. A member may name an element of an array, and components inside it, through an alternate access (IEC 61850-8-1 §7.3.3, §7.3.4, Table 151), including leading components as in Table 139; an index that selects no element answers `definition object-undefined`, and a flattened name continuing below an array is refused with `definition invalid-address`. The client sends a member reference with an index, such as `LD/MHAI1.HA.phsAHar(3).cVal.mag.f`, in that form. A member naming an object that does not exist, an unknown functional constraint included, answers `definition object-undefined` (IEC 61850-8-1 §8.1.3.4.3.4); a data set name whose logical node does not exist, `access object-non-existent`. A data set holds at most 1024 members, 4096 attributes in all and 1024 attributes per member, and a request may name at most 4096; beyond either, `resource capability-unavailable` (IEC 61850-8-1 §8.1.3.4.3.4). The response is the primitive NULL of ISO 9506-2 |
| DeleteDataSet | Y | Y | MMS DeleteNamedVariableList; a statically configured data set is matched but not deleted. A request naming a data set created at run time that the DatSet of a report control block uses is refused with `service` object-constraint-conflict, and deletes none of its data sets |
| GetDataSetAttributes (GetNamedVariableListAttributes) | Y | Y | The same MMS request as GetDataSetDirectory. The server answers from the data set registry, in registration order, and reports `mmsDeletable` true only for a data set created at runtime; an unknown name is answered with `object-non-existent`, and a response that would exceed the negotiated maximum PDU size with `resource other` |

### 3.4 Setting group control

| Service | Server | Client | Remark |
|---|:---:|:---:|---|
| GetSGCBValues | Y | partial | Whole block or a single attribute: `NumOfSG`, `ActSG`, `EditSG`, `CnfEdit`, `LActTm`, `ResvTms`. The client reads it through the generic data path |
| SetSGCBValues (SelectActiveSG) | Y | partial | `ActSG` accepts 1 through the configured group count and loads the values of the group into the FC=SG data attributes |
| SelectEditSG | Y | partial | An edit session is bound to one association and carries a reservation deadline; a competing association receives `temporarily-unavailable`. The values of the group are loaded into the FC=SE data attributes |
| ConfirmEditSG | Y | partial | `CnfEdit = true` stores the FC=SE values into the edited group and, when it is active, into the FC=SG data attributes; the application's handler may refuse the commit |
| GetEditSGValue / SetEditSGValue | Y | Y | Ordinary Read and Write of data attributes under functional constraint SE; GetEditSGValue under functional constraint SG reads the active group, and a write under SG is refused. An SCL data attribute declared with `fc="SE"` is served under SG as well. SetEditSGValue by an association that does not hold the edit session answers `temporarily-unavailable` (IEC 61850-8-1 §8.1.3.4.4.2); a write the access policy refuses answers `object-access-denied`. GetEditSGValue answers `temporarily-unavailable` while EditSG is 0 or the logical device has no setting group control block (IEC 61850-7-2 §16.2.2.5, Table 20); the EditSG check comes before the path is resolved, so a name under SE that does not exist also answers `temporarily-unavailable` then. While an edit group is selected, any association may read the edit buffer, not only the one that selected it. A read of the whole logical node returns the buffer values whatever EditSG is. A SetEditSGValue is stored only while the edit session it was admitted to is still open: one that outlives its session, because the session expired, was cancelled or was opened again while the write handler ran, answers `temporarily-unavailable` and stores nothing (IEC 61850-7-2 §16.3.3, §16.3.4) |

The server keeps the values of every setting group. Each setting starts with
the `<Val sGroup="n">` values of the SCL file, and with the value of the
attribute for a group the file gives none. The FC=SG data attribute holds the
value of the active group and the FC=SE data attribute of the same name the
edit buffer. Values the server loads go through its update path, so a data set
member they change is reported and logged. `SettingGroupHandler` decides
whether a selection, an edit session or a commit proceeds and may persist the
values; `SettingGroupRuntime::set_group_value` restores them.

### 3.5 Unbuffered reporting

| Service | Server | Client | Remark |
|---|:---:|:---:|---|
| Report | Y | Y | MMS InformationReport; a data set member naming a data object or a constructed attribute is included whole when any attribute beneath it triggers, with the union of their reasons, and segmentation never splits a member. A report carries the values of the model and consults no read handler. A report control block takes only the reasons its `TrgOps` enable. A report channel that is full drops URCB reports, counted in `dropped_socket_full`, without disabling the control block |
| GetURCBValues | Y | Y | Whole-block read returns the attributes in the order of IEC 61850-8-1 Table 73: `RptID`, `RptEna`, `Resv`, `DatSet`, `ConfRev`, `OptFlds`, `BufTm`, `SqNum`, `TrgOps`, `IntgPd`, `GI` and, when the block has it, `Owner` |
| SetURCBValues | Y | Y | Per attribute; the client orders the sequence so that `RptEna = false` is first and a general interrogation is last. `DatSet` reads back as `<LD>/<LN>$<name>` (IEC 61850-8-1 §8.1.3.2.2); a write may omit the logical device. An unreserved block accepts writes from any client without being reserved, so a single Write request may configure it and end with `RptEna = true`. `GI = true` is refused with `temporarily-unavailable` while `RptEna` is false, and `GI` reads back false (IEC 61850-7-2 §17.2.2.13) |
| Trigger option: data-change | Y | Y | Raised when an update changes the value of an attribute that declares `dchg` |
| Trigger option: quality-change | Y | Y | Raised when an update changes the value of an attribute that declares `qchg` |
| Trigger option: data-update | Y | Y | Raised by every update of an attribute that declares `dupd`, whether or not the value changes. The sub-attributes of a constructed attribute take its trigger options |
| Trigger option: integrity | Y | Y | Driven by `IntgPd` |
| Trigger option: general interrogation | Y | Y | |
| Option field: sequence-number | Y | Y | |
| Option field: report-time-stamp | Y | Y | |
| Option field: reason-for-inclusion | Y | Y | The client accepts a ReasonCode longer than six bits and ignores the bits a report does not define |
| Option field: data-set-name | Y | Y | |
| Option field: data-reference | Y | Y | |
| Option field: buffer-overflow | – | – | Forcibly cleared on an unbuffered control block before encoding |
| Option field: entryID | – | – | Forcibly cleared on an unbuffered control block before encoding |
| Option field: conf-revision | Y | Y | |
| Option field: segmentation | Y | Y | A report larger than the max_mms_pdu_size the association negotiated is split into segments that each fit it, numbered with `subSeqNum` and flagged with `moreFollows`; the inclusion bitstring of each segment marks only the members that segment carries. A report that cannot fit, because its header or one member is too large, is dropped, logged and counted in `dropped_oversized`. The client delivers each segment as it arrives, with its own inclusion, `subSeqNum` and `moreFollows`; it does not reassemble them |
| Reservation (`Resv`) | Y | Y | Unbuffered control blocks only. `RptEna = true` on an unreserved block reserves it for the writer; writing any other attribute of an unreserved block does not reserve it. Disabling keeps the reservation, which ends when the holder writes `Resv = false` or its association ends; not writable while `RptEna` is true |
| Owner | Y | Y | The IP address of the client holding the reservation; empty when unreserved. Present only when the SCL `ReportSettings` declares `owner="true"`, or for a control block registered in code unless `with_owner(false)` |
| Instances from the model | Y | – | `IedServer::register_from_model` registers every report control block of the model once per instance it declares (`RptEnabled max`), named `<name>01` to `<name>NN` when indexed (IEC 61850-8-1 §17.1.2, §17.1.3); otherwise registration is the application's |

### 3.6 Buffered reporting

| Service | Server | Client | Remark |
|---|:---:|:---:|---|
| Report | Y | Y | |
| GetBRCBValues | Y | Y | The whole control block, in the order of IEC 61850-8-1 Table 72, or any attribute individually: `RptID`, `RptEna`, `DatSet`, `ConfRev`, `OptFlds`, `BufTm`, `SqNum`, `TrgOps`, `IntgPd`, `GI`, `PurgeBuf`, `EntryID`, `TimeofEntry` and, when the block has them, `ResvTms` and `Owner`. A read of `Resv` answers `object-access-unsupported`, and a read of a `ResvTms` or `Owner` the block does not have, `object-non-existent` |
| SetBRCBValues | Y | Y | `ConfRev`, `SqNum`, `TimeofEntry` and `Owner` are refused as read-only; `RptID`, `DatSet`, `OptFlds`, `BufTm`, `TrgOps`, `IntgPd`, `EntryID`, `PurgeBuf` and `ResvTms` are refused with `temporarily-unavailable` while `RptEna` is true (IEC 61850-8-1 Table 72). A `DatSet` write must name a known persistent data set or be empty, with or without the logical device, and binds the control block to its members; `DatSet` reads back as `<LD>/<LN>$<name>`. `ConfRev` counts `DatSet` changes only; a change of `RptID`, `DatSet`, `BufTm`, `TrgOps` or `IntgPd` purges the buffer and a change of `OptFlds` does not. `GI = true` is refused with `temporarily-unavailable` while `RptEna` is false, and `GI` reads back false (IEC 61850-7-2 §17.2.2.13) |
| EntryID resynchronization | Y | Y | An eight-octet EntryID, written while `RptEna` is false; an unknown identifier is refused with `object-value-invalid`. After a purge the exposed EntryID is all zeros until the next entry is sent |
| PurgeBuf | Y | Y | Purges while `RptEna` is false; refused with `temporarily-unavailable` while it is true. The events the control block still holds inside its buffer time are discarded with the buffer, so none raised before the purge is reported after it (IEC 61850-7-2 §17.2.2.14) |
| ResvTms | Y | Y | Edition 2 INT16 reservation, optional per control block; not writable while `RptEna` is true. Present only when the SCL `ReportSettings` declares `resvTms="true"`, or for a BRCB registered in code unless `with_resv_tms(false)`; without it the BRCB is reserved by its pre-configured owner or by the client that enables it. A client reserves the BRCB by writing a positive `ResvTms`, how long the reservation outlasts its association; a negative value is refused with `object-value-invalid`, so `-1` comes only from the configured owner. No other write reserves a BRCB whose `ResvTms` is 0: the client that enables it holds it while it is enabled and its association lasts (IEC 61850-7-2 §17.2.2.17) |
| Owner | Y | Y | The pre-configured client, or the IP address of the client that enabled or reserved the block; empty when free. Present only when the SCL `ReportSettings` declares `owner="true"`, or for a BRCB registered in code unless `with_owner(false)` |
| Buffer overflow indication | Y | Y | With a dropped-entry counter. The first report sent after every transition of `RptEna` from false to true carries `BufOvfl` TRUE, whatever EntryID the client resynchronized on (IEC 61850-7-2 §17.2.3.2.2.8). After it, `BufOvfl` is TRUE only when the buffer has lost an entry not yet formatted for transmission while the control block is enabled; evicting an entry already formatted does not set it (§17.2.3.2.2.8, Figures 30 and 31) |
| Buffer persistence across a restart | Y | – | Optional SQLite backend, off by default; each entry keeps the values and inclusion flags it was enqueued with (schema version 1, upgraded in place from a 0.3 database, whose earlier entries are reported with the values current at transmission) |
| Trigger options and option fields | Y | Y | As in 3.5, plus buffer-overflow and entryID, which a buffered block does not mask. A report channel that is full holds BRCB entries in the buffer; a segmented entry is sent only when the channel has room for its segments, or in parts, in order, when it has more segments than the channel holds |
| Instances from the model | Y | – | As in 3.5: one control block per instance the model declares, each with its own buffer |

### 3.7 Logging

| Service | Server | Client | Remark |
|---|:---:|:---:|---|
| Log (implicit recording on trigger) | Y | – | An attribute update writes an entry through each enabled log control block whose `TrgOps` enable a reason of the update, data-change, quality-change or data-update, and whose `DatSet` holds the attribute; integrity writes one entry holding the whole data set every `IntgPd`; general interrogation writes none, as IEC 61850-7-2 does not support it for logging. A batch of updates writes one entry per log control block, each data set member once with the reason code of its updates; a data object or constructed attribute member is logged as its structure. A log control block whose definition sets LogEna starts enabled once it has a data set and a storage backend. Entries go to a `LogStorage` backend; an in-memory backend ships with the crate |
| GetLCBValues | Y | N | The nine components `LogEna`, `LogRef`, `DatSet`, `OldEntrTm`, `NewEntrTm`, `OldEnt`, `NewEnt`, `TrgOps` and `IntgPd`, individually or as one structure; `OldEntr` and `NewEntr` are accepted for `OldEnt` and `NewEnt` when read individually. `DatSet` reads as `<LD>/<LN>$<name>`. The client has no dedicated LCB API |
| SetLCBValues | N | N | No write route resolves a log control block path |
| GetLogStatusValues | Y | N | `OldEntrTm`, `NewEntrTm`, `OldEnt` and `NewEnt` report the oldest and newest entry of the log, zero for an empty log |
| QueryLogByTime | Y | Y | MMS ReadJournal with a starting time, an ending time, both or neither; the client can add a variable list. The journal is named by the `LogRef` of a log control block only; a time is a six-octet TimeOfDay, and another length is refused |
| QueryLogAfter | Y | Y | MMS ReadJournal with `entryToStartAfter`, optionally with an ending time and a variable list. The journal is named by the `LogRef` of a log control block only |
| ReadJournal pagination | Y | Y | Entries are added while they fit the negotiated PDU size; the response then sets `moreFollows`. The client continues with `JournalQuery::continuation`, or reads to the end with `IedConnection::query_journal_all`; a continuation keeps the start, the end time and the variable list of the original query. `query_journal_all` drops an entry whose EntryID it has already received, including the entry a continuation resumes after and the earlier entries of its time when the server sends them again, and the entries past the end time; it stops at the end time or the entry count, and fails with `ClientError::JournalNotAdvancing` when a page brings no new entry while the server reports more |
| ReadJournal optional fields | Y | Y | Every combination of `rangeStartSpecification` (startingTime, startingEntry), `rangeStopSpecification` (endingTime, numberOfEntries), `listOfVariables` and `entryToStartAfter`; each field present narrows the selection |
| WriteJournal | N | N | The server answers `object-access-unsupported` rather than rejecting the tag |

A server built with the logging subsystem sets the MMS `readJournal` bit in the
`servicesSupported` bitmap of its Initiate-Response, so a client that selects
its own request paths from that bitmap will use both log queries. See
section 5.

`IedServer::register_from_model` registers the log control blocks of the model
with their LogEna, DatSet, TrgOps, IntgPd and reason code; BufTm is not served.

### 3.8 Control

| Service | Server | Client | Remark |
|---|:---:|:---:|---|
| Select (SBO) | Y | Y | Issued as a Read of `<LN>$CO$<DO>$SBO`. A Select of an object that is already selected is refused whichever client sends it; a read of `SBO` outside the normal-security select-before-operate model answers `object-non-existent` (IEC 61850-8-1 Table 94, IEC 61850-7-2 Table 47). The client returns a `ControlOutcome` |
| SelectWithValue (SBOw) | Y | Y | Refused with the add cause Unknown on an object outside the enhanced-security select-before-operate model |
| Cancel | Y | Y | Accepted while selected; refused while a command is executing, and on an idle direct-control object with Not-supported |
| Operate | Y | Y | |
| CommandTermination | Y | Y | Positive and negative, on the enhanced-security models only, and only for a command whose Operate was answered positively; a refused command has none. The client takes only the termination of the object and ctlNum it operated |
| TimeActivatedOperate | N | N | The server refuses an `Oper` carrying an `operTm` other than 0 with the add cause Not-supported. The client encodes the six-element form only |
| Control model: status-only | Y | Y | |
| Control model: direct-with-normal-security | Y | Y | |
| Control model: SBO-with-normal-security | Y | Y | |
| Control model: direct-with-enhanced-security | Y | Y | |
| Control model: SBO-with-enhanced-security | Y | Y | |
| `sboClass`: operate-once and operate-many | Y | – | Read from the `sboClass` attribute of the model |
| Attributes `origin`, `ctlNum`, `T`, `Test`, `Check` | Y | Y | `Check` carries synchro-check and interlock-check |
| LastApplError / AddCause | Y | Y | Server: an InformationReport carrying only `LastApplError` precedes the negative response of SelectWithValue, Operate and Cancel, and the data access error of that response follows IEC 61850-8-1; the add causes and errors carry the names of IEC 61850-8-1 §20.11. A handler that panics ends the command with AddCause and Error Unknown. Client: the failed `ControlOutcome` carries that report, or the LastApplError of a negative CommandTermination, together with its AddCause; a normal-security server that sends none yields `Unknown` and no LastApplError |
| Select timeout | Y | – | A timer ends the selection when `sboTimeout` elapses; an operate-many command restarts it |
| Operate timeout (`operTimeout`) | Y | – | Read from the `operTimeout` attribute of the model, or `ControlObjectConfig::oper_timeout_ms`; a running command that outlasts it ends with `TimeLimitOver`; off by default |
| Control settings from the model | Y | – | `ctlModel`, `sboTimeout`, `sboClass` and `operTimeout` are read from the model at each request; `ControlObjectsRegistry::register_from_model`, and `IedServer::register_from_model` with the other control blocks, register every controllable data object. Without either, control objects are registered by the application |
| `stSeld` | Y | – | The server writes `stSeld` on every change of the selection, through the update path, before calling the selection change handler |

### 3.9 GOOSE

| Service | Server | Client | Remark |
|---|:---:|:---:|---|
| SendGOOSEMessage (publish) | Y | – | `GoosePublisher`; the frame header is prebuilt and the PDU is encoded for every publication; frames carry an 802.1Q tag by default (priority 4, VID 0, IEC 61850-8-1 Annex C.2.2) |
| Retransmission profile | Y | – | Configurable intervals with a backoff after a state change. timeAllowedToLive is twice the interval before the next publication, so it is never shorter than the time to the next retransmission (IEC 61850-8-1 §18.1.2.5.1, Figure 10); `set_time_allowed_to_live` overrides it |
| Simulation, `ndsCom`, VLAN tag and priority | Y | Y | Simulation travels in the PDU `simulation` member and in the S bit of Reserved1 (IEC 61850-8-1 Annex C.2.5); a subscriber can accept original, simulated or both publications (`SimulationFilter`), and treats a message as simulated when either flag is set (`GooseSubscriberState::is_simulated`). Original and simulated messages of one GoCB are sequenced and supervised separately |
| GOOSE subscribe | – | Y | `GooseSubscriber` and `GooseReceiver`; every subscriber whose filters accept a frame receives it, with `stNum` and `sqNum` continuity tracked per gocbRef, including their overflow to 1 (IEC 61850-8-1 §18.1.2.5.2), and time-allowed-to-live supervision, which any received frame restarts. The APPID and destination MAC filters apply with or without a gocbRef filter. The timestamp `t` is a `UtcTime` checked against IEC 61850-8-1 §8.1.3.7 Table 36: a frame whose `t` is not eight octets, or whose TimeAccuracy is one of the invalid codes 25 to 30, is dropped with a warning; the time value and its quality flags are passed to the application unjudged |
| GetGoCBValues | Y | Y | The nine components of IEC 61850-8-1 Table 83: `GoEna`, `GoID`, `DatSet`, `ConfRev`, `NdsCom`, `DstAddress`, `MinTime`, `MaxTime`, `FixedOffs` (always FALSE), readable individually or as one structure; every value is read from the `GoosePublisher`, and `DatSet` reads as `<LD>/LLN0$<name>`. The client accepts a server that omits the optional components. With `IedServer::register_from_model`, `DstAddress`, `MinTime` and `MaxTime` are those of the SCL `GSE`; a control block without a destination reads its `DstAddress` `Addr` as the NULL address, six zero octets (IEC 61850-8-1 §25.3.2, §8.1.3.3 Table 16). The client reads an empty `Addr` as six zero octets, the address that means no destination, and refuses any other length than zero or six |
| SetGoCBValues | Y | Y | `GoEna` is writable; enabling answers `object-value-invalid` while `DatSet` is empty or `ConfRev` is 0. `GoID` and `DatSet` are writable while `GoEna` is false under Edition 2 (otherwise `temporarily-unavailable`), and answer `object-access-denied` under Edition 2.1; a `DatSet` write must name a VMD- or domain-scope data set the server holds (otherwise `object-value-invalid`) and increments `ConfRev`. The other components answer `object-access-denied`. `GoEna` TRUE is refused with `temporarily-unavailable` on a GoCB that has no destination (IEC 61850-8-1 §25.3.2, §8.1.3.4.4.2). The client writes a control block one attribute at a time: `GoEna` false first, then `DatSet` and `GoID`, so one call can disable a control block and change it; otherwise `DatSet` and `GoID` first and `GoEna` last |
| Fixed-offset GOOSE encoding | N | N | `FixedOffs` reads FALSE; the publisher uses the shortest BER encoding |
| GetGOOSEElementNumber, GetGoReference | N | N | Not implemented |

### 3.10 Sampled Values

| Service | Server | Client | Remark |
|---|:---:|:---:|---|
| SendMSVMessage (publish) | Y | – | `SvPublisher`; multi-ASDU frames, `smpCnt`, `smpSynch`, `smpRate`, `smpMod` as a two-octet INT16U, `refrTm` as a `UtcTime`, which cannot hold an invalid TimeAccuracy, and `gmIdentity`; frames carry an 802.1Q tag by default (priority 4, VID 0, IEC 61850-9-2 Table 7). `SvPublisherBuilder::with_address` takes the destination, APPID and tag from the SCL `SMV` address |
| Sampled Values subscribe | – | Y | `SvSubscriber` with per-`svID` filtering and per-`svID` sample continuity, including the once-a-second `smpCnt` reset; a repeated `smpCnt` is counted as a duplicate rather than a gap. `SvReceiver::set_dest_addr_check(true)` dispatches a frame only when its destination MAC matches a subscription. A `refrTm` whose TimeAccuracy is one of the invalid codes 25 to 30 (IEC 61850-8-1 §8.1.3.7 Table 36) fails decoding with `SvError::InvalidRefrTm` and the frame is dropped; its value and quality flags are passed to the application unjudged |
| Simulate bit (Reserved1) | Y | Y | Set by `SvPublisher`, reported per ASDU to the subscriber (IEC 61850-9-2 §5.3.3.4.4) |
| 9-2LE channel layout | Y | Y | Four current and four voltage channels with quality |
| GetMSVCBValues / SetMSVCBValues | N | N | Sampled Values control blocks are not exposed as MMS variables |
| GetUSVCBValues / SetUSVCBValues | N | N | Unicast Sampled Values are not implemented |
| Protection profile, 256 samples per cycle | N | N | Not implemented |

### 3.11 Time synchronization

| Service | Server | Client | Remark |
|---|:---:|:---:|---|
| SNTP server | Y | – | RFC 4330 SNTPv4 unicast, mode 3 to mode 4 and mode 1 to mode 2, the poll copied from the request. Leap indicator, stratum and Reference Timestamp follow the clock state the application reports: synchronized at the configured stratum (1 by default), or unsynchronized with leap indicator 3 and stratum 16 |
| SNTP client | – | Y | Queries an NTP or SNTP server with a receive timeout; a reply with a zero transmit timestamp is rejected, and timestamps follow the NTP era rule of RFC 4330 §3; every rejected reply is logged at warn level |
| Time quality reporting | Y | Y | `leapSecondsKnown`, `clockFailure`, `clockNotSynchronized` and `timeAccuracy` per IEC 61850-7-2 §6.1.2.9.3.3 and IEC 61850-8-1 §8.1.3.7; the `TimeQuality` type cannot hold the TimeAccuracy codes 25 to 30 that Table 36 defines as invalid. A timestamp the application writes carries the quality it supplies; `IedServerConfig::time_quality` applies to the timestamps the server generates itself, the `LActTm` of a setting group control block and the GOOSE `t` of a publisher `IedServer::register_from_model` creates |
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
| Cancel | `0x85` | N | N |
| Status | `0x80` | Y | Y |
| GetNameList | `0xa1` | Y | Y |
| Identify | `0x82` | Y | Y |
| Read | `0xa4` | Y | Y |
| Write | `0xa5` | Y | Y |
| GetVariableAccessAttributes | `0xa6` | Y | Y |
| DefineNamedVariableList | `0xab` | Y | Y |
| GetNamedVariableListAttributes | `0xac` | Y | Y |
| DeleteNamedVariableList | `0xad` | Y | Y |
| InformationReport | – | Y | Y |
| ReadJournal | `0xbf 0x41` | Y | Y |
| WriteJournal | `0xbf 0x42` | N | N |
| File services (fileOpen, fileRead, fileClose, fileDirectory, obtainFile) | – | N | N |

Any other service tag is answered with a Reject PDU.

A service that fails as a whole is answered with a Confirmed-ErrorPDU carrying
an ISO 9506-2 `ServiceError`. The `errorClass` alternatives and subcodes the
server emits are below. They are not the `DataAccessError` codes, which are
reported per variable inside a Read or Write response and are numbered
separately.

| errorClass | Subcode | Emitted when |
|---|:---:|---|
| `access [7]` other | 0 | A request fails to decode, or a response fails to encode |
| `access [7]` object-access-unsupported | 1 | The named object class or scope is not served, and for WriteJournal |
| `access [7]` object-non-existent | 2 | The named domain, variable, data set or log control block does not exist |
| `definition [2]` object-undefined | 1 | A member of a data set a client defines names an object that does not exist, an unknown functional constraint included |
| `definition [2]` invalid-address | 2 | A data set member reference, or the name of a data set a client defines, is malformed, or a member continues below an array |
| `definition [2]` object-exists | 5 | DefineNamedVariableList names a data set that is already defined |
| `resource [3]` other | 0 | The response would exceed the negotiated maximum PDU size, or an internal lock is unusable |
| `resource [3]` capability-unavailable | 4 | DefineNamedVariableList would exceed `IedServerConfig::max_dynamic_datasets` or `max_dynamic_datasets_per_association`, or a data set of more than 1024 members, 4096 attributes in all or 1024 attributes per member |
| `service [4]` other | 0 | DeleteNamedVariableList finds the reporting engine lock unusable |
| `service [4]` object-constraint-conflict | 5 | DeleteNamedVariableList names a data set created at run time that a report control block uses; the error carries `numberDeleted` |

The client decodes a Confirmed-ErrorPDU into the errorClass alternative and
subcode the peer sent. `iec61850-mms` returns it as `ClientError::ServiceError`,
and `iec61850-client` as `ClientError::Service { error_class, .. }`, so a
refusal is distinguishable by cause at both layers; a RejectPDU becomes
`Reject { reason, .. }`. The errorClass is decoded with short and one- or
two-octet long-form lengths and any subcode from 0 to 255; a malformed one is
a parse error, and the association stays usable.

---

## 5. Association negotiation and `servicesSupported`

| Parameter | Value |
|---|---|
| Maximum MMS PDU size (server) | 65000 octets; the negotiated value is the smaller of the client's proposal and 65000, or 65000 when the client proposes none. A proposal below 64 is refused with an Initiate-ErrorPDU |
| Maximum outstanding calling / called requests (server) | The client's proposals, each clamped to 1 through 5 |
| `dataStructureNestingLevel` (server) | Accepted up to 32; answered only when the client proposes a value |
| `parameterCBB` (server) | `str1`, `str2`, `vnam`, `valt`, `vlis`; the negotiated value is the bitwise AND with the peer's proposal |
| Maximum MMS PDU size (client) | Proposed as 65000 octets unless configured; the negotiated size never exceeds the proposal |
| Maximum outstanding calling requests (client) | Proposed as `MmsClientBuilder::max_outstanding`, 5 by default, floored at 1; the negotiated value never exceeds the proposal and is enforced, also above 64, counting requests that timed out, or whose callers dropped them after they were sent, until their late answers arrive. A new association starts with every slot free |
| `dataStructureNestingLevel` (client) | Proposed as 10 |

The `servicesSupportedCalled` bitmap is computed from the subsystems the build
includes, so that it announces exactly what the dispatcher answers.

| Bit | Announced when |
|---|---|
| `status`, `getNameList`, `identify`, `read`, `write`, `getVariableAccessAttributes` | Always |
| `defineNamedVariableList`, `getNamedVariableListAttributes`, `deleteNamedVariableList` | The reporting subsystem is compiled in |
| `informationReport` | The reporting or the control subsystem is compiled in; the control subsystem sends `LastApplError` and command terminations as InformationReport |
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

### 5.1 ISO connection parameters

The addressing a client offers is carried by `IsoConnectionParameters`. Its
default selectors are the values IEC 61850-8-1 specifies for an MMS
association; the default AP-titles and AE-qualifier are the values IEDs
customarily expect, which the standard leaves to the configuration.

| Parameter | Default | Carried in |
|---|---|---|
| Calling and called T-Selector | `00 01` | COTP CR variable part, parameters `C1` and `C2` |
| Calling and called S-Selector | `00 01` | Session CONNECT, PGI 51 and PGI 52 |
| Calling and called P-Selector | `00 00 00 01` | Presentation CP, fields `81` and `82` |
| calling-AP-title | `1.1.1.999` | AARQ `[6]` |
| called-AP-title | `1.1.1.999.1` | AARQ `[2]` |
| calling and called AE-qualifier | 12 | AARQ `[7]` and `[3]` |

Every field is settable. An AP-title or an AE-qualifier set to `None` is left
out of the AARQ, and a selector of length 0 still occupies its tag and length
pair on the wire. Three entry points accept the parameters:
`MmsClientBuilder::iso_parameters`, `IedConnection::with_iso_parameters`, and
`MmsClient::from_transport_with_iso_parameters` for a caller that owns its
transport.

Without an `AssociationAuthenticator` the server accepts an association
whatever addressing it carries. With one, the called and calling AP-title and
AE-qualifier are decoded and handed to it, and it decides; see 3.1.
`IsoConnectionParameters::authentication` carries the ACSE credentials the
client sends, `AcseAuth::None` by default.

| Refusal decoding | Support | Remark |
|---|:---:|---|
| Session REFUSE (RF, SPDU ID 12) | Y | Reason code PI 50 and transport disconnect PI 17 are decoded, the connection-identifier group is traversed, and PGI 193 or PI 194 user data is returned. The long form of LI is accepted |
| Presentation CPR, normal mode | Y | responding-presentation-selector `[3]`, context-definition-result-list `[5]`, default-context-result `[7]` and provider-reason `[10]` |
| Presentation CPR, x410 mode | N | Rejected with a distinct error rather than parsed |

A refused association returns `ClientError::SessionRefused`, carrying the
session reason code, the transport disconnect parameter and, when the refusal
carries a CPR PPDU, its provider-reason. A refusal whose AARE diagnostic names
the calling identity or the authentication returns
`ClientError::AuthenticationRejected` instead, whether the AARE arrived in a
Session ACCEPT or inside the CPR of a Session REFUSE. The `Display` names the
values ISO 8327-1 and ISO 8823 define and prints an unrecognized one as a
number.

---

## 6. Security

| Item | Support | Remark |
|---|:---:|---|
| TLS 1.2 | Y | The minimum version required by IEC 62351-3 Annex A, and the default floor |
| TLS 1.3 | Y | |
| TLS 1.0 / 1.1 | N | Not offered |
| Cipher suite whitelist | Y | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`. The list is fixed at compile time and cannot be extended through the API |
| Finite-field DHE suites | N | The cryptographic provider in use implements none |
| Server certificate validation | Y | Standard chain validation against a configured trust anchor set. The name check can be skipped with `with_dangerous_no_sni_verify()` for IEDs whose certificates carry no matching subject alternative name; every other check still applies |
| Mutual authentication (client certificate) | Y | Optional or required. `require_client_auth(true)` or the pinned-certificate mode makes the client certificate mandatory; otherwise a server with trust anchors requests one and validates it when presented, and a server without trust anchors does not request one; building a server without trust anchors logs a warning. A refused client receives the alert that names the reason. The client reports a refusal by the server, including a TLS 1.3 refusal read after its side of the handshake, as `TlsHandshake` of the `AlertReceived` kind |
| Pinned-certificate mode | Y | Only the listed leaf certificates are accepted; an empty list is refused rather than treated as "accept any". On the server a client presenting no certificate is refused |
| Relaxed validity-time mode | Y | An expired or not yet valid certificate is accepted only when every other check passes at a time inside its validity period; applies to server and client certificates alike |
| Revocation checking: CRL | Y | Static CRL lists supplied by the operator as PEM or DER and installed on both the server and the client certificate verifier; the event `AlmCertRevoked` reports a revoked certificate. An expired CRL is still used, and `WrnCrlExpired` is not raised. Distribution points are not fetched: the operator keeps the lists current |
| Revocation checking: OCSP | N | Neither stapling nor a responder query is implemented |
| Session resumption | Y | Enabled by default for TLS 1.2 session IDs; TLS 1.3 resumes only when `tls13_session_tickets(n)` makes the server send tickets, which it does not by default. Disableable for TLS 1.2 and TLS 1.3 alike. The server-side lifetime of a resumable session is configurable; without it the server keeps up to 256 sessions with no time limit |
| Session renegotiation | N | Never initiated |
| IEC 62351-3 event reporting | partial | The nineteen event codes of IEC 62351-3 §5 are delivered to a caller-supplied handler. Certificate, session-establishment and handshake-failure events are raised, and the server raises `AlmHandshakeTimeout` when the TLS handshake or the association setup after it exceeds `association_setup_timeout_ms`; `SessionClosed`, `SessionRenegotiation`, `WrnCertExpiringSoon`, `WrnCrlExpired`, `AlmUnauthorizedAccess` and `AlmConnectionAborted` are not |
| Handshake failure classification | Y | A failed handshake is reported by its cause: `TlsError::Verification`, `CipherUnsupported`, `VersionUnsupported`, `Handshake` for any other TLS error, and `Io` for a transport failure. A client connecting with `connect_tls` receives `ClientError::TlsHandshake` with a `TlsFailureKind`: certificate verification, a fatal alert received, no version or no cipher suite in common, a timeout, a transport failure, or another TLS error. The TCP connection, the handshake and the COTP connection share one `connect_timeout_ms` deadline |
| IEC 62351-4 application-layer authentication | N | Peer authentication is performed by TLS; the IEC 62351-4 certificate mechanism is not supported (see 3.1). The ACSE password mechanism is available on top of TLS |
| IEC 62351-6 GOOSE and SV authentication | N | Not implemented |

---

## 7. SCL support (IEC 61850-6)

`iec61850-scl` parses an SCL, ICD or CID file in two stages and builds a runtime
model from it. `iec61850-scl-build` generates the same model at compile time.

| SCL element | Support | Remark |
|---|:---:|---|
| `Header` | Y | `id`, `version`, `revision`, `toolID` and `nameStructure` are read into `RawScl::header`; `Text` and `History` are skipped. A `Header` without `id`, outside `SCL` or repeated is rejected |
| `IED`, `AccessPoint`, `Server`, `LDevice`, `LN0`, `LN` | Y | |
| `Authentication` | partial | Its attributes are parsed into `RawServer::authentication` and not applied: a declared password or certificate authentication does not make the server require it |
| `DOI`, `SDI`, `DAI`, `Val` | partial | Instance values, including nested sub-data instances. A `<Val>` on a DataTypeTemplates `DA` or `BDA` is the initial value. Octet strings are read as base64Binary and Timestamp as xs:dateTime, `24:00:00` included; INT24 as an integer and Octet6 and Octet16 as base64Binary. Quality, Check, EntryTime, EntryID, OptFlds, SvOptFlds, LogOptFlds, TrgOps and PhyComAddr have no `<Val>` representation in IEC 61850-6; a `<Val>` on one is warned about and the default is kept. Every `<Val sGroup="n">` is kept (`DataAttribute::sgroup_values`), checked against `numOfSGs`, and the server loads them on SelectActiveSG and SelectEditSG; a `sGroup` of 0, above 255 or above `numOfSGs`, and two values for one group, are rejected. The `ix` of an `SDI` or `DAI` sets the element of the array it names; an `ix` on a scalar, past the end, or an array named without one is skipped with a warning |
| `DataSet`, `FCDA` | Y | An FCDA without `daName` is served as one functional-constrained data member, and one naming a data object or a constructed attribute as that node whole; an FCDA `ix` selects an array element. Registered with the server by `IedServer::register_from_model`, which the application calls; otherwise registration is the application's |
| `ReportControl` with `TrgOps`, `OptFields` | Y | Buffered and unbuffered; `indexed` (default true) is read. A `TrgOps` attribute left out takes the default of IEC 61850-6 §9.3.8, true for `gi` and false for the others; without a `<TrgOps>` element no trigger option is enabled. Registered with the server by `IedServer::register_from_model`, which the application calls; otherwise registration is the application's |
| `LogControl` | Y | `datSet`, `logName`, `logEna` (default true), `reasonCode` (default true), `bufTime`, `intgPd` and `TrgOps` reach the model; GI is not taken for a log, including the default `gi` of a `<TrgOps>` that leaves it out (IEC 61850-7-2 §17.3.2.3.2). Registered with the server by `IedServer::register_from_model`, which the application calls; otherwise registration is the application's |
| `SettingControl` | Y | A `numOfSGs` above 255 is rejected (NumOfSG is an INT8U, IEC 61850-7-2 §16.2.2.3); every setting group value is kept by the server |
| `GSEControl` | Y | The GoID is the `appID`, or the GoCBRef when the `appID` is empty; `fixedOffs` is not applied. Registered with the server by `IedServer::register_from_model`, which publishes to the address of its `GSE` with its `MinTime` and `MaxTime`, unless the application supplies the destination; otherwise registration is the application's. In an SCL whose Communication section connects the IED, a GSEControl without `GSE` is registered disabled: `DstAddress` `Addr` reads as the NULL address, six zero octets, and `GoEna` cannot be set TRUE (`temporarily-unavailable`); so is one whose `GSE` address has no `MAC-Address`, or one that cannot be read (GOOSE over UDP/IP is not supported) |
| `SampledValueControl` | Y | Parsed into the model; no MMS projection (see 3.10). An empty `smvID` takes the control block reference, `<domain>/LLN0$MS$<name>`, or `$US$` for a unicast block (IEC 61850-6 Annex I.3.2.7); its `SMV` address is `SvControlBlock::smv`, which `SvPublisherBuilder::with_address` applies |
| `DataTypeTemplates`: `LNodeType`, `DOType`, `DAType`, `EnumType`, `DO`, `SDO`, `DA`, `BDA`, `EnumVal` | partial | Type references are resolved and cross-checked; DOType and DAType cycles, and nesting of DOTypes through SDO and DATypes through BDA deeper than 32 levels, are rejected, and an IED or a type expanding to more than 1,000,000 model nodes (configurable through `ResolveOptions::max_expanded_nodes`) is rejected, every array element and every FC=SG view derived from an FC=SE attribute counted. SDO and DA keep their declared order, which is the member order on the wire. The bTypes INT24, Octet6, Octet16, SvOptFlds and LogOptFlds are accepted. An Enum whose ordinals exceed integer(8) is declared as INT16 or INT32. `count` on a `DA`, `SDO` or `BDA` builds an array, the count given as a number or as the name of an attribute of the same type definition whose `<Val>` holds it; a count naming an attribute without a type value takes the value the instance gives it, and without one the attribute is built as a scalar with a warning |
| `Communication` (`SubNetwork`, `ConnectedAP`, `Address`, `GSE`, `SMV`) | Y | Parsed into the model: the server address of each connected access point (`IedModel::connected_aps`), the `GSE` address with `MinTime` and `MaxTime` (`GooseControlBlock::gse`) and the `SMV` address (`SvControlBlock::smv`). Every `P` value is compared with the character rules of IEC 61850-8-1 Tables 162 to 164 and IEC 61850-9-2 Table 19, whether or not the element carries `xsi:type`: a value in another form is logged and read when it reads without ambiguity, and a value that cannot be read fails only where it is used; a reference to an access point or control block the file does not declare, or a `MinTime` above its `MaxTime`, is rejected when building the IED it belongs to, and a `ConnectedAP` naming an IED the file does not declare is skipped with a warning. A fractional `MinTime` or `MaxTime` is rounded to whole milliseconds. `PhysConn` is not read. The server binds no address from it; the application chooses where to listen |
| `Substation` | N | The subtree is skipped with a warning |
| `Inputs` / `ExtRef` | N | Skipped |
| `RptEnabled` | Y | `max` gives the number of instances of the report control block (default 1, at least 1, at most 99 when indexed); `ClientLN` is skipped. `IedServer::register_from_model` registers the instances as `name01`…`nameNN` when indexed. A block with `indexed="false"` and `max` above 1 is logged and counted as one instance |
| `Services` | partial | `ReportSettings` `owner` and `resvTms`, at IED and access point level, decide whether report control blocks have Owner and ResvTms (default false); the other elements are skipped |

A control block whose `datSet` names no `DataSet` of its own logical node is
rejected, as the keys of the SCL schema require (IEC 61850-6 Annex A.4); an
absent or empty `datSet` is accepted. A parse failure reports the line, the
column, the element path, the attribute name, and the value found against the
value expected. A known element that is
malformed is rejected. An element the parser does not know is skipped with its
subtree without a warning, so a misspelled element name is lost rather than
reported.

---

## 8. Summary of limitations

The following are the entries above that a system integrator is most likely to
need before selecting this implementation.

1. **File transfer is absent** in both roles.
2. **Sampled Values control blocks are not reachable over MMS**; a Sampled
   Values stream is configured through the publisher API.
3. **TimeActivatedOperate is not supported**; an Operate carrying an
   activation time other than 0 is refused with Not-supported.
4. **Log control blocks cannot be written** (SetLCBValues is not implemented).
5. **The Substation section of an SCL file is not parsed.**
6. **The IEC 62351-4 certificate mechanism is not negotiated**: an
   association is authenticated by TLS, by an ACSE password checked by an
   `AssociationAuthenticator`, by both, or not at all.
7. **Revocation checking is CRL only**, from static lists the operator keeps
   current; there is no OCSP and no distribution-point fetching. No
   IEC 62351-6 signatures on GOOSE or Sampled Values.
8. **Fixed-offset GOOSE encoding is not implemented**; `FixedOffs` reads FALSE.
9. **Control blocks and data sets the model declares are registered only when
   the application asks**, through `IedServer::register_from_model` or the
   individual `register_*` calls.
