# M9 N1 設計：AI NAS 六層 SBOM（C4，2026-11-17；C0 已審，工具採用待使用者決定）

依據：D-068（PR #177）。只用公開資料。現有責任分層（bsp／os／unknown／host-tool）不改，來源層另記 `dumpling:origin-layer`。
本文件是書面設計：寫這份文件時沒有改程式、沒有跑 CI；aisbom、Semgrep 只看了公開資料，沒有安裝。下面寫的版本、digest、大小都是 2026-11-17 從公開 API 讀的值，實作時要再固定一次。

## 0. 前提：示範映像是「沒裝 OMV 的 Debian 官方雲端映像」

- 現在的 ai-nas-demo 用的是 Debian 13 官方雲端映像（不改），OMV 是另外掃的固定 commit 原始碼（`deb_bsp` 是 null）。
- 要把 OMV、容器、模型真的裝進映像，就得在 chroot 裡跑 apt（會執行套件的 maintainer script，D-035 不允許），所以**這次不做「裝好的映像」**。
- 做法：自有程式、內建容器、AI 模型在 `sources.yml` 宣告成「出貨內容」，並寫出在裝置上的安裝路徑。
  元件帶 `dumpling:origin-layer`，另外帶 `dumpling:declared=true`（是宣告的出貨內容，不是從映像裡找到的），報告照實寫。
- 不重複算的規則（第 2 節）照樣實作，並用合成的 rootfs 測試「映像裡真的有這些目錄」的情況。
  之後如果改用裝好的映像（例如 OMV 官方 ISO 安裝後的磁碟），同一套規則就能直接用。

## 1. 每一層用什麼公開輸入

| 來源層（origin-layer） | 輸入（公開） | 工具 | 漏洞資料 | 備註 |
|---|---|---|---|---|
| `os` | Debian 13 官方雲端映像（現有，sha512 對 SHA512SUMS） | Syft（現有） | Grype＋DT（現有） | 責任分層照 `os_responsibility`（自有品牌 `ours`），不寫死 |
| `kernel` | Debian `linux` 原始碼套件 6.12.116-1（現有，#168 已登記）＋映像的 `/boot/config-*`（#138） | K1／K2（現有，隨 S1 同步） | 核心列（現有） | 6.12 沒有 included-c 清單，排除仍然是 0（缺口 23） |
| `app` | OpenMediaVault 固定 commit `9d8530ff…`（現有），**拆成一支程式一份**（見下表） | cdxgen 在沙箱裡（現有的 sca-scan --git） | Grype＋DT | 沒有鎖定檔 → 「僅直接依賴」、漏洞 GAP |
| `container` | **ggml-org/llama.cpp 的 server 映像**（MIT；amd64 壓縮後約 296 MB，6 層） | Syft（`registry:<image>@sha256:…`，不需要 docker daemon） | Grype＋DT | 固定 digest（2026-11-17 `server` 的 index digest 是 `sha256:7751a6c0…`；實作時改成固定版本 tag 的 digest，不用滾動 tag） |
| `model` | **Qwen/Qwen2.5-0.5B-Instruct-GGUF** 的 `qwen2.5-0.5b-instruct-q4_k_m.gguf`（Apache-2.0；491 MB；HF repo revision `9217f5db79a2…`；LFS sha256 是上游公布的值，不是 TOFU） | 先自己寫元件（CycloneDX `machine-learning-model`，帶 sha256、授權、來源 revision）；aisbom 等使用者決定（第 4 節） | **GAP**（沒有模型漏洞資料庫） | gguf 的 chat template 可以執行 Jinja，是已知風險；工具評估見第 4 節 |
| `firmware` | **Dasharo Protectli VP46xx v1.2.0**（C2 建議，C0 同意；備選 novacustom-nuc-box-arl-v0.9.2）。用 firmware-demo Release 的 SBOM `fw-dasharo-protectli-vp46xx-v1.2.0.cdx.json`（sha256 取自該 Release 的 meta 的 `sbom_sha256`），sources.yml 固定網址＋sha256，換 tag 由人決定 | C2 的 BIOS 流程（M3）的成品，不在 AI NAS 這邊重掃 | 主要靠 C2 的公告比對與規則表屬性；DT／Grype 幾乎比不到（16 個元件只有 1 個有 purl、1 個有 CPE），比不到的寫「資料庫沒有資料，以廠商公告為準」 | **代表樣本，不是 AI NAS 實機的韌體**，報告寫明。EC：Protectli 沒有公開的 EC 韌體 → **GAP**（實機要由板廠提供；NS5x 的 EC 排第二階段） |

**容器的選擇理由**：AI NAS 常見的內建服務是本機推論。Ollama（MIT）也可以，但 amd64 壓縮後約 3.4 GB，CI 的磁碟與時間負擔大；llama.cpp server 約 0.3 GB，同樣是 MIT，能搭配上面的 GGUF 模型。
**模型的選擇理由**：官方發行者（Qwen）的 repo、Apache-2.0、不需要登入（gated=false）、HF 有每個檔的 sha256、q4_k_m 不到 0.5 GB。

### 自有程式（OMV 固定 commit 裡的程式，一支一份）

| 程式 | 路徑 | 鎖定檔 | 結果 |
|---|---|---|---|
| openmediavault-workbench（網頁介面，Angular） | `deb/openmediavault/workbench/` | `package-lock.json` | 完整的傳遞相依 |
| openmediavault（engine：Python＋PHP） | `deb/openmediavault/usr/…` | 沒有（相依是 Debian 套件，寫在 `debian/control`） | 第三方相依由 OS 層的 deb 提供；這一份只有自有程式本身，標「相依由 OS 套件提供」 |
| openmediavault-salt | `deb/openmediavault-salt/` | `requirements.txt` **沒有版本**（cached-property、click、lxml、natsort、pyudev） | **「僅直接依賴」，漏洞 GAP**（D-068 的情況） |
| openmediavault-k8s（PHP） | `deb/openmediavault-k8s/usr/share/php/openmediavault/` | `composer.lock`＋已經放進去的 `vendor/` | 完整；vendor 裡的套件以 composer.lock 為準 |

- 不是每個 OMV 外掛都要做；先做這四支（各代表一種情況）。其他外掛列在報告的「沒有掃描的程式」，標 NOT_ASSESSED。
- 「一支一份」的方法：sca-scan --git 指定子目錄（或先 sparse checkout 再各自掃）；具體由 N3 決定，可能要動 sca-scan（C1）。

### 韌體層的接法（C2 的 N5 輸入，C0 11-17 的決定）

- **示範**：用 firmware-demo Release 的 SBOM（上表）。**實際產品的介面**：`sca-scan --sbom` 匯入供應商 SBOM（先用 `firmware_dt.py prep` 正規化），用 Dasharo NS5x 的供應商 SBOM 範例測通。
- **監控不重複開 Issue**：firmware-demo 已經在每日監控同一份韌體，所以 AI NAS 的韌體層**不另開 Issue**，元件加 `dumpling:firmware-ref=<slug>@<version>`，指到 firmware-demo 的 key。監控那邊要怎麼認這個屬性（略過 firmware 層、在 Issue 內文列出「也出現在 ai-nas-demo」）由 C3 確認。
- **責任分層**：照 LAYERS.md 第 2 條歸 **bsp**（C0 決定），報告寫明「主機板韌體的代表樣本，實機由板廠／IBV 提供」。D-027 的分層規則不改。
- **合併條件**（C2 提的，交給 N2／C1）：
  - 每個韌體元件都加 `dumpling:origin-layer=firmware`，不只根元件；已經有不同值時不覆蓋，標 GAP。
  - 跨來源層不合併同名元件：韌體裡的 Intel 微碼和 OS 的 `intel-microcode` deb 是兩個東西；edk2 和 OVMF 也是（第 2 節的例外規則要涵蓋）。
  - bom-ref 保留原樣，撞到就 FAIL。
- **限制**：11-15 的 Release 還沒有 integrity 屬性，下一個 tag 才有。

## 2. 不重複算

- **規則一（D-068 (3)）**：自有程式以 cdxgen 那份為準。Syft 掃映像時，排除那些程式在裝置上的目錄（sources.yml 宣告的安裝路徑，例如
  `/usr/share/openmediavault/`、`/usr/share/php/openmediavault/`、`/usr/lib/python3/dist-packages/openmediavault/`、`/var/www/openmediavault/`）。
- **規則二**：容器與模型只在各自那一層出現。Syft 掃映像時也排除容器的儲存位置（`/var/lib/containers/`、`/var/lib/docker/`）與模型資料夾（sources.yml 宣告）。
- **規則三**：dpkg 資料庫裡的 `openmediavault*` 套件（映像真的裝了 OMV 時才會有）會留在 OS 層的清點裡，但不算 app 層的元件。
  這個 deb 和 cdxgen 的根元件怎麼對應（同一個東西兩種表示），交給 N2（C1）訂規則。
- **合併後的檢查**（D-068 (3) 的測試）：以 purl（去掉 qualifier）＋版本，以及有 sha256 時的 sha256 當鍵，同一個鍵出現在兩個來源層 → 測試失敗。
  例外清單（例如 OS 層和容器層都有 glibc，但它們是兩份不同的檔案）要看 sha256 或位置，而不是只看名稱；細節交給 N2。

## 3. 驗收（對應 D-068 (7)）

1. 用 `pipeline/new-project.sh` 建立的新專案（或 ai-nas-demo 新版本）在 CI 跑通。
2. 六層各自都有 SBOM 元件，或有明確的 GAP 與理由：
   - os、kernel、app、container：有元件；
   - model：有模型元件（sha256、授權、來源），漏洞是 GAP；
   - firmware：有 C2 流程的元件，或 GAP。
3. 合併後的 SBOM 沒有重複元件（第 2 節的測試；另用合成 rootfs 測「映像裡真的有那些目錄」時，Syft 的結果排除掉了）。
4. 報告依來源層分節列出（N2），責任分層的數字和現在一樣（標準答案裡 os／bsp／unknown 的部分，除了新加的元件，不變）。
5. 標準答案：新增 origin-layer 各層的元件數與 GAP。改動前先把前後數字交給 C0。
6. 所有新輸入（容器 digest、模型 sha256、韌體）都登記在 PROVENANCE 或 sources.yml，寫明出處與核對方式。

## 4. 新工具評估（交使用者決定；評估期間不加進 CI）

### aisbom（AI 模型）

| 項目 | 結果 |
|---|---|
| 專案 | github.com/Lab700xOrg/aisbom（PyPI `aisbom-cli`）；2026-11-17 最新 v1.7.0（2026-10-25） |
| 授權 | **Apache-2.0**（GitHub 的 license 欄位） |
| 做什麼 | 靜態檢查模型檔，不載入模型：反組譯 pickle、Keras Lambda、GGUF 的 Jinja chat template、ONNX 自訂運算子；輸出 CycloneDX 1.7（帶 sha256 與授權），也能輸出 SPDX |
| 固定版本 | 可以：PyPI 固定版本（pip `--require-hashes`）；或 GitHub release 的單一執行檔 `aisbom-linux-amd64`（54.8 MB，release 上有 sha256 `6db87fc8…`） |
| 離線 | **可以**：`--offline`（或 `AISBOM_OFFLINE=1`）時不連網：沒有 PyPI／OSV／Hugging Face 查詢、沒有 telemetry、沒有更新檢查；遠端目標（hf://、https://）與 `--share` 會被拒絕（結束碼 1） |
| 沙箱 | 用現有的 tools/e2e/sandbox.sh（bwrap，不給網路）跑單一執行檔，模型檔唯讀掛進去；同時給 `--offline`，兩層都不連網 |
| 風險 | 專案小（GitHub 84 顆星、約 30 個 commit），成熟度要考慮；不加 `--offline` 時有 telemetry；`--share`、GitHub Action 的 `token` 會把 SBOM 傳到 aisbom.io（**一律不用**）；離線時少了授權與 CVE 查詢 |
| 和 CycloneDX | 輸出 1.7，和我們的 SBOM（specVersion 1.7）相同 |
| 建議 | 可以用在 N6，限離線、沙箱、單一執行檔固定 sha256；只取模型元件與風險結果，漏洞仍然標 GAP。採用與否由使用者決定 |

### Semgrep（原始碼的新漏洞，SAST；N7 選用）

| 項目 | 結果 |
|---|---|
| 引擎 | semgrep/semgrep，**LGPL-2.1**；2026-11-17 最新 v1.185.0（2026-11-10）。另有分支 opengrep/opengrep（LGPL-2.1，v2.0.0） |
| **規則** | Semgrep 官方維護的規則（semgrep/semgrep-rules）是 **Semgrep Rules License v1.0**：只限「自己的內部業務用途」，**不能散布**、不能當服務提供給別人。**所以不能把官方規則放進這個公開 repo**；從 registry 下載又要連網 |
| 固定版本 | 可以：PyPI `semgrep==<版本>`（wheel 內含 semgrep-core）＋ `--require-hashes` |
| 離線 | 只用本機規則檔時可以：文件寫明「只用本機設定檔或命令列樣式時不送 metrics」；另外一律加 `--metrics off`（或 `SEMGREP_SEND_METRICS=off`），不登入 |
| 沙箱 | 和 cdxgen 一樣在 sandbox.sh 裡跑，不給網路，原始碼唯讀 |
| 限制 | 社群版沒有跨檔分析（Pro 才有）；結果是「可能的問題」，要人審，不是漏洞清單 |
| 建議 | 要用的話，規則只能自己寫（Apache-2.0，放在 repo），或另外評估授權允許散布的規則集；不使用官方 registry 規則。引擎選 Semgrep CE 或 opengrep 都是 LGPL-2.1，由使用者決定 |

## 5. 分工與順序（D-068 (5)）

板子檢查（S3）照 D-069 只有匯入端：M9 不依賴板上收集腳本，六層都不需要實體板子。


- N1（本文件，C4）→ C0 審，記決定。
- N2（C1）：`dumpling:origin-layer` 欄位、跨工具去重（第 2 節的規則三與例外）、報告分節。
- N3（C4）：自有程式一支一份、沒有鎖定檔標「僅直接依賴」。
- N4（C4）：內建容器（Syft registry 掃描、固定 digest）。
- N5（C2＋C4）：韌體層，輸入和 C2 對齊。
- N6：AI 模型層（先 GAP；aisbom 看使用者決定）。
- N7：SAST（選用，最後；Semgrep 看使用者決定）。

## 6. C0 的決定（2026-11-17）

1. **第 0 節的前提：同意。** 映像維持沒裝 OMV 的 Debian 雲端映像；自有程式、容器、模型用 sources.yml 宣告，加 `dumpling:declared=true`。
   報告裡每個宣告的元件都要寫明「宣告的出貨內容，沒有在映像裡核對」，整份報告不能因此看起來比較完整。去重規則用合成的 rootfs 測。
2. **輸入：同意。** 容器 llama.cpp server（固定 digest）、模型 Qwen2.5-0.5B q4_k_m（上游公布的 sha256）、韌體 Protectli VP46xx v1.2.0。
   - **下載的 cache**（N4／N6 設計）：模型 491 MB、容器約 300 MB，CI 不每次重新下載。用 GitHub Actions cache，key 用 sha256 或 digest；
     **從 cache 拿到的檔案也要重新核對 sha256（容器核對 digest）**，不能因為是 cache 就直接相信；核對不符就刪掉重抓，不符的檔不用。
3. **自有程式先做四支：同意。** 其他外掛記 NOT_ASSESSED。
4. **去重的鍵**：purl（去掉 qualifier）加版本，有 sha256 時加 sha256；例外看 sha256 或位置，交給 N2。
5. **兩個工具交給使用者決定**（C0 的建議：aisbom 有條件採用；Semgrep 先不採用）。決定會記成 D-070，這份文件等那時再合併。
