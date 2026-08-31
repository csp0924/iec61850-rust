# Examples

Every example lives in the crate it demonstrates, under `crates/<crate>/examples/`.
The model they all share is
[`crates/iec61850-server/examples/models/demo.cid`](../crates/iec61850-server/examples/models/demo.cid).
It lives inside the server crate rather than beside this file so that a
published package carries it and the examples can find it at run time.

## The demonstration IED

The CID is a configured IED description written against IEC 61850-6
(SCL, 2007 revision B). Being a CID rather than an ICD, it binds its single
access point to a concrete address, so a server can start from it and a client
can be pointed at it without a further engineering step.

Its MMS domain name is the IED name followed by the logical device instance:
`DemoIEDLD0`.

| Logical node | Contents |
|---|---|
| `LLN0` | `Mod`, `Beh`, `Health`, `NamPlt`; data sets `dsMeas` and `dsStatus`; report control blocks `urcbMeas` (unbuffered) and `brcbMeas` (buffered); GOOSE control block `gcbStatus` |
| `LPHD1` | `PhyNam`, `PhyHealth`, `Proxy` |
| `MMXU1` | `TotW`, `Hz`, `PhV` (a WYE of three CMV phases) |
| `GGIO1` | `Ind1` to `Ind4` (single point status) and `SPCSO1` (controllable single point) |

`dsMeas` holds the three measured values and is the payload of both report
control blocks; `dsStatus` holds the four status points and is the payload of
the GOOSE control block. The name plates carry vendor `rust61850` and software
revision `0.1.0`.

The `ConnectedAP` gives `127.0.0.1` and port 102. The server examples bind
`127.0.0.1:8102` by default instead, so that they run without elevated
privileges; each accepts a bind address argument for the configured port.

Two tests gate the file: `crates/iec61850-scl/tests/demo_cid.rs` parses it and
pins the object names, and `crates/iec61850-server/tests/demo_cid_round_trip.rs`
loads it into a model, serializes that model back to SCL, re-parses it and
compares the two, then hands the model to the server's MMS mapping.

## Loopback walkthrough

Three terminals, no hardware, no configuration:

```sh
# Terminal 1: serve the CID with its data sets, report control blocks and
# control object wired up.
cargo run -p iec61850-server --example server_from_scl

# Terminal 2: read four attributes and write one.
cargo run -p iec61850-client --example min_client

# Terminal 2: walk the whole object model.
cargo run -p iec61850-client --example directory_browser

# Terminal 3: enable the unbuffered report control block and print the reports
# that follow. The server moves the measured values once a second, so a report
# arrives about every second. Ctrl+C to stop.
cargo run -p iec61850-client --example client_reporting_subscriber
```

`min_client` prints:

```text
connecting to 127.0.0.1:8102
connected
read  DemoIEDLD0/LLN0.NamPlt.vendor[DC] = VisibleString("rust61850")
read  DemoIEDLD0/MMXU1.TotW.mag.f[MX] = Float32(1005.0)
read  DemoIEDLD0/MMXU1.TotW.q[MX] = BitString { padding: 3, data: [0, 0] }
read  DemoIEDLD0/GGIO1.Ind1.stVal[ST] = Boolean(false)
write DemoIEDLD0/LLN0.NamPlt.vendor[DC] = "min-client"
disconnected
```

and `client_reporting_subscriber` prints one block per report:

```text
[#1] seq=Some(0) ts_ms=Some(...) conf_rev=Some(1) dataset_size=Some(3)
    [0] DemoIEDLD0/MMXU1$MX$TotW$mag$f = Float32(1005.0)  reason=Some(DATA_CHANGE)
    [1] DemoIEDLD0/MMXU1$MX$Hz$mag$f = Float32(50.05)  reason=Some(DATA_CHANGE)
    [2] DemoIEDLD0/MMXU1$MX$PhV$phsA$cVal$mag$f = Float32(230.0)  reason=Some(DATA_CHANGE)
```

To use a different port, give it to both sides:

```sh
cargo run -p iec61850-server --example server_from_scl -- 127.0.0.1:10102
cargo run -p iec61850-client --example min_client -- 127.0.0.1 10102
```

## The examples

Every header carries the run command, the expected output and the example it
pairs with.

The rows in the first table run as written on any supported platform, with one
exception: `tls_client` needs a certificate, a key and a CA, which this
repository does not ship. See "Certificates for the TLS example" below.

The GOOSE and Sampled Values rows in the second table need Linux and
`CAP_NET_RAW`, because those protocols ride directly on Ethernet; they have not
been run on this project's development machine, which is Windows.

### MMS server and client, over TCP loopback

| Crate | Example | What it shows | Pairs with | Run |
|---|---|---|---|---|
| `iec61850-server` | `min_server` | The smallest complete server: load SCL, serve it over MMS | `min_client` | `cargo run -p iec61850-server --example min_server` |
| `iec61850-server` | `server_from_scl` | Every data set and control block the SCL declares, bound to the runtime, plus the control object | `client_reporting_subscriber` | `cargo run -p iec61850-server --example server_from_scl` |
| `iec61850-server` | `server_basic_io` | The same model with a task moving the process values once a second | `read_write_cycle` | `cargo run -p iec61850-server --example server_basic_io` |
| `iec61850-server` | `server_with_reporting` | The same model built in Rust instead of loaded from SCL, with one report control block registered by hand | `client_reporting_subscriber` | `cargo run -p iec61850-server --example server_with_reporting` |
| `iec61850-server` | `server_control_io` | The four control models of IEC 61850-7-2 on one control object, and the interlocking refusal | none yet | `cargo run -p iec61850-server --example server_control_io -- sbo-enhanced` |
| `iec61850-server` | `server_with_log` | A log control block whose journal is seeded before the server starts | none yet | `cargo run -p iec61850-server --example server_with_log` |
| `iec61850-client` | `min_client` | Connect, read four attributes, write one, disconnect | `min_server` | `cargo run -p iec61850-client --example min_client` |
| `iec61850-client` | `read_write_cycle` | The type-narrow read and write helpers over one association | `server_from_scl` | `cargo run -p iec61850-client --example read_write_cycle` |
| `iec61850-client` | `directory_browser` | The directory services, a type tree, and a device-model refresh | `server_from_scl` | `cargo run -p iec61850-client --example directory_browser` |
| `iec61850-client` | `client_reporting_subscriber` | Enabling a report control block and receiving its reports | `server_from_scl` | `cargo run -p iec61850-client --example client_reporting_subscriber` |
| `iec61850-client` | `tls_client` | A mutually authenticated TLS association, per IEC 62351-4. Needs certificates, see below | a TLS-enabled server | `cargo run -p iec61850-client --features tls --example tls_client -- 127.0.0.1 3782 ca.pem cert.pem key.pem` |
| `iec61850-mms` | `mms_client` | One MMS association below the IEC 61850 layer: Initiate, GetNameList, Read, Write, read back, then Conclude and Release | `min_server` | `MMS_EXAMPLE_PORT=8102 cargo run -p iec61850-mms --example mms_client` |
| `iec61850-sntp` | `sntp_server_basic` | An SNTPv4 time service on UDP | any SNTP client | `cargo run -p iec61850-sntp --example sntp_server_basic` |

#### Certificates for the TLS example

`tls_client` presents its own certificate and validates the peer against a CA,
so it needs three PEM files that are deliberately not in the repository. Any
test hierarchy works; the server certificate has to carry a subject alternative
name matching the host argument, or peer verification rejects the connection.

With `openssl`, for a server reachable as `127.0.0.1`:

```bash
# A CA.
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -subj "/CN=iec61850-rust test CA" -keyout ca-key.pem -out ca.pem

# A client certificate signed by it.
openssl req -newkey rsa:2048 -nodes -subj "/CN=client" \
    -keyout key.pem -out client.csr
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -days 30 -out cert.pem

# A server certificate, with the address in a subject alternative name.
openssl req -newkey rsa:2048 -nodes -subj "/CN=server" \
    -keyout server-key.pem -out server.csr
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -days 30 -out server-cert.pem \
    -extfile <(printf "subjectAltName=IP:127.0.0.1")
```

The integration tests take a different route: `iec61850-server` carries `rcgen`
as a dev-dependency and generates an equivalent hierarchy in-process, so
`cargo test` needs no files on disk.

### GOOSE and Sampled Values, over raw Ethernet

GOOSE and Sampled Values ride directly on Ethernet rather than on TCP, so these
examples open an `AF_PACKET` socket: Linux only, and `CAP_NET_RAW` is required.
Granting the capability to the built binary avoids running the example itself as
root:

```sh
cargo build -p iec61850-goose --example goose_publisher
sudo setcap cap_net_raw+ep target/debug/examples/goose_publisher
```

The publisher and subscriber pairs default to the loopback interface, so they
demonstrate a full exchange on one machine; `lo` carries multicast frames the
same way a wired interface does. The examples named `*_live` transmit on a real
NIC and take its name as a required argument.

| Crate | Example | What it shows | Pairs with | Run |
|---|---|---|---|---|
| `iec61850-goose` | `goose_publisher` | Publishing a data set, with the caller driving the retransmission schedule | `goose_subscriber` | `sudo ./target/debug/examples/goose_publisher` |
| `iec61850-goose` | `goose_subscriber` | Filtering a publication and handling new-state, retransmission and expiry events | `goose_publisher` | `sudo ./target/debug/examples/goose_subscriber` |
| `iec61850-goose` | `goose_publisher_live` | The same publication through the HAL Ethernet backend | `goose_subscriber` | `./target/debug/examples/goose_publisher_live eth0` |
| `iec61850-goose` | `goose_jitter_test` | Publish jitter over the whole path, socket included | none | `GOOSE_RT_PRIO=50 ./target/release/examples/goose_jitter_test eth0 60` |
| `iec61850-goose` | `perf_benchmark` | First-publish latency and scheduling jitter, no socket, any platform | none | `cargo run -p iec61850-goose --example perf_benchmark --release` |
| `iec61850-sv` | `sv_publisher_basic` | A 4000 sample-per-second stream in the IEC 61850-9-2 LE profile | `sv_subscriber_basic` | `sudo ./target/debug/examples/sv_publisher_basic` |
| `iec61850-sv` | `sv_subscriber_basic` | Filtering a stream, decoding the LE profile, counting missed samples | `sv_publisher_basic` | `sudo ./target/debug/examples/sv_subscriber_basic` |
| `iec61850-sv` | `sv_publisher_live` | The same stream through the HAL Ethernet backend | `sv_subscriber_basic` | `./target/debug/examples/sv_publisher_live eth0` |
| `iec61850-sv` | `sv_jitter_test` | Encode-path jitter of the publisher, nothing sent | none | `./target/release/examples/sv_jitter_test lo 60` |
| `iec61850-sv` | `sv_cpu_test` | Processor cost of one stream, measured by the shell | none | `/usr/bin/time -v ./target/release/examples/sv_cpu_test 60` |

`perf_benchmark` is the one example in this section that runs anywhere: it
measures the encode path and never opens a socket.

## Fuzz corpus generators

The Sampled Values seed corpus is checked in under
`crates/iec61850-sv/fuzz/corpus/`. The GOOSE corpus is not: it is regenerated on
demand, and `.gitignore` excludes `crates/iec61850-goose/fuzz/corpus/`.

The binaries that regenerate both live beside the fuzz targets rather than among
the examples, since they demonstrate nothing about the API:

```sh
cd crates/iec61850-goose/fuzz && cargo run --bin gen_corpus
cd crates/iec61850-sv/fuzz    && cargo run --bin gen_corpus
```

Each seed has a fixed file name, so a corpus the fuzzer has grown is not
overwritten.
