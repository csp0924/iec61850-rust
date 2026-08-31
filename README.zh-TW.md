# iec61850-rust

[English](README.md) | [繁體中文](README.zh-TW.md)

IEC 61850（MMS、GOOSE、Sampled Values、SCL）的獨立 Rust 實作，依公開標準文本撰寫。本 workspace 涵蓋 MMS 堆疊（COTP、Session、Presentation、ACSE 以及 ISO 9506 PDU）、直接跑在 raw Ethernet 上的 GOOSE 與 Sampled Values、IEC 61850-7-x 資料模型、具編譯期模型生成的 SCL 解析器，以及承載 ACSI 控制、報告與記錄服務的 client 與 server runtime。

**一致性：**[`docs/PICS.md`](docs/PICS.md) 說明 server 與 client 兩種角色實作了哪些 ACSI 服務與模型，並明確列出已知缺口。本實作未經任何測試實驗室認證。

以 `MIT OR Apache-2.0` 授權。

## 現況

本 workspace 以 stable Rust 建置，帶有約 2,000 個測試：BER 與 PDU 的往返編解碼、協定狀態機、client 對 server 的 loopback 整合測試，以及 [`docs/robustness.md`](docs/robustness.md) 所編錄的畸形輸入回歸測試。九個 `cargo-fuzz` target 涵蓋 GOOSE、Sampled Values、COTP、Session、Presentation、ACSE 與 MMS 解碼器。

本專案不主張的事項：

- **未取得一致性認證。** 本實作未曾送交任何受認可的測試實驗室，也不存在對應的證書。
- **GOOSE 與 Sampled Values 僅能在 Linux 上執行。** 兩者都直接跑在 Ethernet 之上，需要具備 `CAP_NET_RAW` 的 `AF_PACKET` socket。Windows 能編譯這些 crate，但無法執行其 publisher 與 subscriber；開發用途另有 libpcap 或 NPCAP backend 可用。
- **未實作 MMS 檔案服務。** 沒有任何 handler 回應這類請求，`iec61850-server` 也不宣告任何聲稱支援它的 feature。
- **GetNameList 探索依循執行期登錄表，而非 SCL 模型。** 資料集、報告控制區塊與 GOOSE 控制區塊一經登錄即會被列出。這些登錄表正是 Read 路徑解析的依據，因此列出的每個名稱都可讀取，而模型雖有宣告但未登錄者則不會列出。`Journal` 類別的請求會得到空清單，因此 log 是以名稱讀取，而非透過探索取得。
- **未實作 MMS 之上的 SVCB 管理、R-GOOSE 與 R-SV。**

## Crate 組成

| Crate | 內容 | `no_std` |
|---|---|---|
| `iec61850-asn1` | 共用的 BER 編解碼核心：依 ISO/IEC 8825-1 的定長編碼，以及遞迴深度防護 | 是，`alloc` |
| `iec61850-hal` | 平台抽象層：L2 Ethernet socket、非同步傳輸與計時器 trait | 是，`alloc` |
| `iec61850-model` | IED / LD / LN / DO / DA 樹狀結構、`MmsValue`、功能約束，以及 30 個 common data class 工廠函式 | 是，`embedded` |
| `iec61850-mms` | COTP、Session、Presentation、ACSE 與 ISO 9506 PDU，含 MMS client 與 server 兩側 | 是，`embedded` |
| `iec61850-goose` | GOOSE publisher、subscriber 與 receiver，EtherType 0x88B8 | 否 |
| `iec61850-sv` | Sampled Values publisher 與 subscriber，EtherType 0x88BA，9-2LE profile | 否 |
| `iec61850-scl` | IEC 61850-6 的 SCL 解析器：將 ICD、CID 與 SCD 檔讀成 `IedModel` | 否 |
| `iec61850-scl-build` | build script 輔助工具，在編譯期把 SCL 檔編成 Rust | 否 |
| `iec61850-client` | `IedConnection`：目錄瀏覽、讀取與寫入、資料集、RCB 與報告、控制、journal、GoCB | 部分，`embedded` |
| `iec61850-server` | `IedServer`：MMS 映射、報告、控制、記錄、設定群組、GoCB 映射 | 部分，`embedded` |
| `iec61850-tls` | 依 IEC 62351-3 的 TLS 設定與 socket 包裝，建構於 `rustls` 之上 | 否 |
| `iec61850-sntp` | 供 IED 時間同步用的 SNTPv4（RFC 4330）server 與 client | 否 |

`iec61850-scl-build-example` 是第十三個 workspace 成員，用於示範編譯期模型生成，不會發佈。

依賴關係嚴格由下往上：`hal`、`asn1` 與 `model` 不依賴 workspace 內的任何東西；`tls`、`scl`、`goose`、`sv` 與 `mms` 建構於它們之上；`client` 與 `server` 位於最上層。`sntp` 獨立於其他 crate。[`docs/architecture.md`](docs/architecture.md) 給出完整的依賴表、各處的 sans-IO 邊界，以及每個 crate 遵守的契約。

## 協定涵蓋範圍

**MMS 服務，server 側。** Initiate 與 Conclude、GetNameList、GetVariableAccessAttributes、Read、Write、Identify、DefineNamedVariableList、DeleteNamedVariableList、ReadJournal，以及用於報告的 InformationReport。PDU 大小在 Initiate 時協商，並在每個送出的 PDU 上強制執行；單一 PDU 裝不下的報告會被分段。

**報告。** 非緩衝（URCB）與緩衝（BRCB）報告控制區塊：觸發選項、選用欄位、general interrogation、緩衝區溢位與 entry id。BRCB 預設在記憶體中緩衝，`sqlite-backend` feature 另外提供以 SQLite 為後端的緩衝區。

**控制。** IEC 61850-7-2 的全部五種控制模型 —— status-only、direct-with-normal-security、SBO-with-normal-security、direct-with-enhanced-security 與 SBO-with-enhanced-security —— 含 Select、SelectWithValue、Operate、Cancel、命令終止，以及檢查與等待執行的 handler hook。

**記錄。** log 控制區塊透過 `LogStorage` trait 寫入，client 端以 QueryLogByTime 與 QueryLogAfterEntry 經 ReadJournal 讀回。WriteJournal 未實作。

**設定群組。** SGCB runtime 提供 `ActSG`、`EditSG` 與 `CnfEdit`，編輯 session 由單一 association 持有，並以保留期限釋放遭棄置的 session。

**GOOSE。** publisher 的重送排程由呼叫端驅動，subscriber 會拋出 new-state、重送與逾期事件，receiver 則把訊框分派給各個 subscriber。`iec61850-server` 把 GoCB 暴露成 MMS 變數，因此 GetGoCBValues 與 SetGoCBValues 可透過 Read 與 Write 運作。

**Sampled Values。** 針對 IEC 61850-9-2 LE profile 的 publisher 與 subscriber，發佈路徑上使用預先建好的訊框範本，接收路徑上做取樣連續性計數。

**Client。** 以快取的裝置模型瀏覽目錄、以 IEC 表示法讀寫物件、動態資料集管理、RCB 讀寫並分派報告、控制、journal 查詢與 GoCB 存取。

**資安。** `iec61850-tls` 建立的 `rustls` 設定已套用 IEC 62351-3 的限制：TLS 1.2 為下限、固定的密碼套件白名單、可選的僅允許已知憑證驗證，以及該 profile 的事件代碼。`iec61850-client` 與 `iec61850-server` 透過各自的 `tls` feature 使用它。

## 快速上手

這些 example 共用同一份設定好的 IED 描述檔 [`crates/iec61850-server/examples/models/demo.cid`](crates/iec61850-server/examples/models/demo.cid)，其 MMS domain 為 `DemoIEDLD0`。在一個終端機啟動 server：

```sh
cargo run -p iec61850-server --example min_server
```

再從另一個終端機讀取它：

```sh
cargo run -p iec61850-client --example min_client
```

`min_client` 連到 `127.0.0.1:8102`，讀取四個屬性、寫入一個，然後中斷連線。`server_from_scl` 是規模較大的對應版本：它會綁定 SCL 宣告的每一個資料集、報告控制區塊與控制物件，這正是報告與瀏覽類 client 所預期的。

```sh
cargo run -p iec61850-server --example server_from_scl
cargo run -p iec61850-client --example client_reporting_subscriber
```

[`examples/README.md`](examples/README.md) 列出每個 example 展示什麼、與哪個 example 配對、確切的執行指令為何，並完整走過這台示範用 IED。

## Server 設定

`IedServerConfig` 帶有 association 上限、edition、以功能約束遮罩表示的寫入權限政策、回報的時間品質，以及 Identify 服務回傳的三個字串。識別欄位若未設定，則採用內建預設值：

| 欄位 | 預設值 |
|---|---|
| `vendor_name` | `rust61850` |
| `model_name` | `iec61850-rust` |
| `revision` | crate 版本 |

在設定上指定 `vendor_name`、`model_name` 或 `revision`，即可回報自己的值。這三個字串就是 client 在 Identify-Response 中看到的內容；本 repository 自行撰寫的 SCL 在其 name plate 中使用相同的 vendor。

## 平台支援

| Target | MMS client 與 server | GOOSE 與 SV | SNTP |
|---|---|---|---|
| Linux | 是 | 是，需 `CAP_NET_RAW` | 是 |
| Windows | 是 | 可編譯；開發用 libpcap 或 NPCAP backend | 是 |
| `thumbv7em-none-eabihf` | `embedded` feature 集合，無 runtime | 否 | 否 |

替建置好的執行檔授予該 capability，即可不用 root 身分執行 example：

```sh
cargo build -p iec61850-goose --example goose_publisher
sudo setcap cap_net_raw+ep target/debug/examples/goose_publisher
```

## `no_std`

六個 crate 可在 `--no-default-features` 搭配 `alloc` 或 `embedded` feature 的條件下建置到 `thumbv7em-none-eabihf`：`iec61850-asn1`、`iec61850-model`、`iec61850-hal`、`iec61850-mms`，以及採用 `minimal,embedded` feature 集合的 `iec61850-client` 與 `iec61850-server`。在這條路徑上，`hashbrown` 取代標準函式庫的集合型別，`spin::RwLock` 取代 `std::sync::RwLock`，MMS 堆疊則跑在 `iec61850-hal` 的 `AsyncTransport` 與 `Timer` trait 之上，而不直接綁定 `tokio`。`CONTRIBUTING.md` 列出這六道指令。

`std` 在每個 crate 都是 default feature，因此桌面環境的建置不受影響。client 與 server 標示為部分支援，是因為兩者各只有一部分能跨過去：server 的 `full-server` runtime 與 client 的報告分派器需要一個 runtime 與一個位址型別，仍留在 `std` 這條路徑上。

這些建置只是編譯檢查。本 repository 中沒有任何東西在實體硬體上跑過，也沒有涵蓋 bare-metal target 的持續整合。

## Python 綁定

Python 綁定以 `iec61850` 套件之名獨立發佈於 PyPI，並建構於這些 crate 之上。其原始碼位於 [github.com/csp0924/iec61850-python](https://github.com/csp0924/iec61850-python)。

## 誰在使用？

本專案可自由用於任何場合，商業部署也包含在內，而且不需註冊。如果你確實把它跑在某處，說一聲能幫助其他讀者判斷這份實作已在哪些地方被操練過。要新增條目到 [`ADOPTERS.md`](ADOPTERS.md)，請用[採用者範本](.github/ISSUE_TEMPLATE/adopter.md)開一個 issue；若想先問點什麼，也可以開一則 GitHub Discussion。具名組織是選擇性的，只描述使用情境同樣歡迎。

## 最低支援 Rust 版本

`1.88`，在 workspace manifest 中宣告一次。提高它屬於 minor 版本變更。

## 授權

`MIT OR Apache-2.0`，由你選擇其一。見 [LICENSE-MIT](LICENSE-MIT) 與 [LICENSE-APACHE](LICENSE-APACHE)。

## 資安

回報漏洞請透過 GitHub 的私密漏洞回報機制，而非公開 issue。[`SECURITY.md`](SECURITY.md) 載明處理流程、支援的版本，以及部署時的加固指引。

## 參與貢獻

[`CONTRIBUTING.md`](CONTRIBUTING.md) 涵蓋建置方式、CI 強制執行的檢查、註解風格、no-panic 契約，以及如何新增一則 robustness 案例。
