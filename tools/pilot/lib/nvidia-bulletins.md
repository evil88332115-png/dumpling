# NVIDIA 安全公告（Jetson Linux）對照表

Grype 和 DT 都比對不到 NVIDIA 對 Jetson Linux 發的公告：公告的版本是自由文字（「All versions prior to 36.5」「35.6.2 and earlier」「38.2」），CSAF 的 CPE 格式不對，也沒有 purl。NVD 大約 4 個月後才補上 `cpe:2.3:o:nvidia:jetson_linux` 的範圍。

所以由人把公告整理成一張表，程式只負責比版本。

`sca-scan` 掃映像或 `--sbom` 時，SBOM 有 `nvidia-l4t-*` 套件就會跑 `match`（`C-nvidia-bulletins`，結果在 `scan/nvidia-bulletins.json`）。不是 Jetson Linux 就沒有這一列。CRA 報告在風險評估 8.8 節列出結果。

## 檔案

| 檔案 | 內容 |
|---|---|
| `tools/mirror/nvidia-bulletins.sh` | 更新主機下載公告（只留選取群組的：jetson、gpu-firmware、gpu-driver），寫 manifest |
| `tools/pilot/lib/nvidia-bulletins.json` | 人工對照表 |
| `tools/pilot/lib/nvidia_bulletins.py` | `candidates`：列出待審公告；`match`：用對照表比對 SBOM |
| `deploy/pilot/nvbul-mirror.sh` | 部署環境的鏡像：下載、檢查、把路徑寫進 `pilot.env` 的 `NVIDIA_BULLETINS_MIRROR`（sca-scan 從這裡讀） |
| `deploy/gitlab-runner/nvbul-sync.sh` | 把常駐環境的鏡像複製一份給 GitLab runner 的 job（`/var/lib/sca-gitlab/nvidia-bulletins`） |

## 流程

1. **下載（更新主機，需連網）**

   ```
   tools/mirror/nvidia-bulletins.sh /srv/mirror/nvidia-bulletins-$(date +%F) manifest.txt
   ```

   公告來源是 github.com/NVIDIA/product-security（2026-10-01 起只在這裡發布）。腳本下載固定 commit 的 tarball，只解出標題、CSAF 產品名稱或 CVE_index.csv 符合任一**選取群組**的公告，並驗 NVIDIA 附的 `.sha256`。實測 2026-11-04：203 則選入 36 則（jetson 15、gpu-firmware 1、gpu-driver 20），約 12 MB（只有 Jetson 時約 2.6 MB）。

   | 群組 | 比對（不分大小寫） | 給誰用 |
   |---|---|---|
   | `jetson` | Jetson、IGX、JetPack、L4T | Jetson 產品（`match`、`candidates` 預設） |
   | `gpu-firmware` | VBIOS、GPU firmware（不用單獨的 firmware：會選到 DGX、BlueField） | 顯卡 vBIOS |
   | `gpu-driver` | GPU Display Driver；CSAF 產品名稱的 GeForce、RTX、Quadro（驅動公告的標題很泛） | 顯示驅動、顯卡工具軟體 |

   `index.json` 每則公告記 `groups` 與 `match_by_group`（從標題、CSAF 產品名稱或 CVE_index.csv 對到），manifest 也逐則記群組。
   NVIDIA 附的 `.sha256` 不符時：Jetson 群組的公告 → 整個鏡像失敗（不變）；只屬於 gpu 群組的公告 → 不解出、`index.json` 記
   `integrity_error`，`candidates` 列成待審（`sha256_mismatch`），不拖住 Jetson 的每日更新（2026-11-04 實際有 5586、5703 兩則）。
   格式錯的 CSAF（標題、日期不是字串，或 JSON 很深）只影響那一則：當成沒有標題或 CSAF 讀不到，鏡像、`--check`、`candidates --draft` 照常。
   多深會讀不到和 Python 版本有關（3.10／3.11 的 json 約 1000 層巢狀就 RecursionError，3.12 以上高很多），結果只差在那一則有沒有 CSAF 資料。
   鏡像主機讀得到、`--check` 的主機讀不到時：非 Jetson 群組的公告只計數，顯示在 OK 那一行（`csaf_too_deep=1 (5910)`），不算問題；
   Jetson 群組的照舊算問題（FAIL）。**兩台主機的 Python 主版本最好相同**，結果才一致。
   非 Jetson 公告的 CSAF 其他讀取或結構錯（不是 JSON、沒有 `document.tracking`、`tracking` 型別錯、`tracking.id` 不符）也一樣只計數：
   OK 那一行的 `csaf_unreadable=N (<公告>:<原因>)`。CSAF 一律以 bytes 讀（UTF-8 BOM、UTF-16 和鏡像端一樣讀得懂）。
   `vulnerabilities` 結構錯的 CSAF（例如 `cwe` 是字串、`scores` 的元素不是物件、`baseScore` 是 NaN 或不在 0–10、根不是物件）：
   `candidates --draft` 只讓那一則 `cves` 為空、記 `csaf_note`（「CSAF 結構錯（…）」），草稿列照常從 Markdown 產生，不會讓整個群組 FAIL。
   `index.json` 說有 CSAF 卻讀不到或太深時同樣記 `csaf_note`（「CSAF 無法讀取（例外類別）」），不會看起來像「CSAF 沒列漏洞」。
   `cve` 不是 CVE 編號（型別錯、空字串、格式不對）的弱點略過、同一個 CVE 出現兩次時合併，都寫在 `csaf_note`；空的 `url` 不帶進 references。
   Markdown 不是合法 UTF-8 → 那一則沒有草稿列、記 `md_note`，其他公告照常。
   `--check` 認得的群組取自同一份 `index.json` 的 `selection`；鏡像和 `nvidia_bulletins.py` 要同一版部署。
   **消費型顯卡的 vBIOS 幾乎沒有 NVIDIA 公開公告**（2026-11 的 203 則裡標題有 VBIOS 的只有 1 則，而且是 HGX／DGX）：
   vBIOS 比對沒有對到公告時要標 NOT_ASSESSED，不是 OK（`VBIOS_NOT_ASSESSED`：修補狀態要問顯卡團隊或 NVIDIA 的合作夥伴管道）。
   NVIDIA 沒有簽章，`.sha256` 和檔案放在同一個倉庫，所以只能防傳輸損壞，不能防竄改。

2. **搬到內網**，用 `--check` 確認：

   ```
   tools/mirror/nvidia-bulletins.sh --check <鏡像資料夾>
   ```

3. **看有沒有新公告**：

   ```
   python3 -I tools/pilot/lib/nvidia_bulletins.py candidates --mirror <鏡像資料夾> \
     --table tools/pilot/lib/nvidia-bulletins.json --draft /tmp/draft.json
   ```

   顯卡產品用 `--group gpu-firmware`（vBIOS）或 `--group gpu-driver`（驅動、工具軟體），各用自己的對照表（同一個 schema，
   沒有 Jetson 版本線的列可以只有 `bulletins`、`not_applicable`）。舊格式的鏡像沒有這兩個群組 → GAP。

   待審公告會逐行印出（編號、日期、原因、標題）。原因有四種：
   - `not_in_table`：不在對照表上。
   - `revised`：NVIDIA 修訂過。
   - `after_reviewed_until`：日期晚於 `reviewed_until`。
   - `unreviewed_rows`：還有未審核的列。

   `--draft` 會把待審公告的「Security Updates」表格轉成草稿列，每列都是 `reviewed=false`。版本、元件是程式從原文推測的，推測依據寫在 `note`。

4. **人工審核**。打開公告原文（`<年>/<編號>/<編號>.md`）逐列核對，然後：
   - 把草稿的 `bulletins` 和 `rows` 併進對照表，修正推測錯的欄位。
   - 核對過的列改成 `reviewed: true`，填 `reviewed_by` 和 `reviewed_at`。
   - 跟 Jetson Linux BSP 無關的公告（例如 CUDA Toolkit、nvJPEG2000 只是列出 Jetson 平台）不要放進 `rows`。改放進 `not_applicable`，寫明理由，改成 `reviewed: true` 並填審核人和日期。
   - 全部看完後，把 `reviewed_until` 設成看過的最新公告日期。

   這一步只能由人做，未審核的列不會產生發現。

5. **比對（掃描時，sca-scan 自動執行；手動時）**：

   ```
   python3 -I tools/pilot/lib/nvidia_bulletins.py match --sbom sbom.cdx.json \
     --table tools/pilot/lib/nvidia-bulletins.json --mirror <鏡像資料夾> --out nvidia-bulletins.json
   ```

## 對照表欄位

頂層：
- `reviewed_until`：人看過的最新公告的日期（`YYYY-MM-DD`）；`null` 表示還沒有人看過。
- `bulletins`：公告的標題、日期、網址，以及每個 CVE 的嚴重度、CVSS、CWE 和描述（從 CSAF 原文複製）。
- `not_applicable`：判定不適用的公告（`reason`；`reviewed=false` 表示還沒有人確認，`candidates` 會列出）。
- `rows`：見下表。
- `mirror`（選用）：表是對哪一份公告鏡像審核的，記錄鏡像的時間點，和 `reviewed_until` 分開記。
  - 格式：`commit` 是 40 位小寫十六進位；`commit_date` 是 `YYYY-MM-DD` 或帶時區的 ISO 8601；`fetched_utc` 是帶時區的 ISO 8601；其他鍵（例如 `note`）照收。
  - 沒寫或 `null`：`mirror_info()` 回 GAP，不算錯誤。
  - 格式不對：`validate_table` 擋下。
  - 過期或時間在未來：屬於時間判斷，由呼叫端決定（例如 C2 的 table-stale）。
- 公告編號（`bulletins[].id`、`not_applicable[].bulletin`）只收數字（1–8 位），避免把 `@`、Markdown 之類的字元帶進報告。

每一列是「一個 CVE × 一個版本線 × 公告表格的一行」：

| 欄位 | 說明 |
|---|---|
| `bulletin`、`cve` | 公告編號、CVE |
| `line` | Jetson Linux 主版本（`35`、`36`、`38`）；IGX OS 寫 `IGX` |
| `product_text`、`platform_text`、`affected_text`、`fixed_text` | 公告表格的原文，不改字（連 NVIDIA 的錯字也照抄） |
| `affected_below` | 受影響版本「低於」這個版本（原文 prior to） |
| `affected_max` | 受影響版本「最高到」這個版本，含這個版本（原文 and earlier） |
| `fixed_in` | 修正版本（點分版本）；原文不是版本（例如 `Kernel SRU 1035 and newer`）時留 `null` |
| `component` | 公告描述裡的元件（UEFI、kernel、NvMap、initrd…） |
| `where_it_lives` | rootfs 套件名稱（例如 `nvidia-l4t-initrd`）；在 flash 裡、SBOM 看不到的寫 `flash`；不知道寫 `unknown` |
| `source` | 出處：檔案路徑與表格那一行的原文 |
| `reviewed`、`reviewed_by`、`reviewed_at` | 審核狀態；`reviewed=true` 時另外兩欄必填 |
| `note` | 原文的空隙、推測的依據 |

版本比較用點分整數：35.6.2 < 35.6.4 < 36.5，36.5 等於 36.5.0。

### vBIOS 列（`line` 是 `vbios`）

`nvidia-bulletins-gpu-firmware.json` 用的列，比對在 `tools/cra/nvidia_vbios_advisory.py`。`validate_table` 檢查以下規則：
- 版本只寫在 `vbios_affected_below`、`vbios_affected_max`、`vbios_fixed_in`，不能用 `fixed_in`、`affected_below`、`affected_max`。
- 版本格式是 option ROM 的 `XX.XX.XX.XX.XX`：1–5 段，每段兩位十六進位，大小寫都收。只要不是 `null` 就檢查，未審核的列也一樣。
- 已審核的列另外要符合：
  - `pci_vendor` 是 4 位小寫十六進位；`pci_devices` 是非空的 4 位小寫十六進位清單。草稿列可以是 `null`。
  - 至少要有一個 `vbios_*` 版本。
  - `vbios_affected_below` 和 `vbios_affected_max` 只能寫一個。
  - `vbios_fixed_in` 不能低於 `vbios_affected_below`，也不能不高於 `vbios_affected_max`。比較前把版本補到 5 段：上界補 FF，其他補 00。
- 「`pci_vendor` 必須是 `10de`」由比對端檢查。
- 不是 vBIOS 的列不能有非 `null` 的 `vbios_*`、`pci_*` 欄位，避免欄位被靜靜忽略。

## 判定規則

`match` 從 SBOM 的 `nvidia-l4t-core` 取 Jetson Linux 版本，版本格式是 `39.2.1-<14 位時間戳>`。沒有 `nvidia-l4t-core` 時，取最多 `nvidia-l4t-*` 套件使用的版本。核心套件的版本格式是 `6.8.12-tegra-39.2.1-…`，也認得。

同版本線、已審核的每一列，依版本分三種：
- 版本 ≥ `fixed_in`：已修正。
- 在受影響範圍內：產生一筆發現，`source` 是 `NVIDIA`。
- 落在受影響範圍和修正版本之間的空隙（例如受影響寫「36.4.4 and earlier」、修正寫「36.4.6」，掃到 36.4.5）：需原廠確認。

公告完全沒列出掃描到的版本線時（例如公告只寫 35、36、38，映像是 39），看日期（使用者 2026-11-02 決定）：
- 映像的建置日期晚於公告日期（首次發布與最近修訂中較晚的那一天）：**推定已含修正**，NVIDIA 沒有確認。只列出，本身不造成 ATTENTION。建置日期取自 `nvidia-l4t-*` 版本的 14 位時間戳（`39.2.1-20260806224157` → 2026-08-06）。
- 同一天、較早，或任一日期不明：**需原廠確認**（ATTENTION）。
- 公告只列 IGX OS、沒有任何 Jetson Linux 版本線：**需原廠確認**，不用日期推定。

兩種都不是「不受影響」。這個規則只寫在 `nvidia_bulletins.py` 的 `unnamed_line_policy()`。要改成「一律需原廠確認」，把 `PRESUME_INCLUDED_IF_BUILT_AFTER` 改成 `False`。

「公告列了哪些版本線」來自對照表的列。列還沒審核時，這個分類本身也沒有經人確認：狀態說明和 CRA 8.8 節都會寫出有幾筆是這樣（目前全部都是）。

草稿列的版本線：平台欄寫 JetPack 7 時不自動填（JetPack 7 對應 Jetson Linux 38 與 39），`line` 留 `?` 由人填。

未審核的列只看掃描到的版本線：掃 R39 時，35、36、38 的未審核列不影響狀態（只計數）。

`C-nvidia-bulletins` 的狀態依序判定，取第一個成立的：

| 狀態 | 條件 |
|---|---|
| NOT_RUN | SBOM 沒有 `nvidia-l4t-*` deb（不是 Jetson Linux） |
| GAP | 下列任一：沒有對照表、沒給鏡像（`PILOT_ENV` 沒有 `NVIDIA_BULLETINS_MIRROR`）、鏡像不存在或讀不到、鏡像過期（`NVBUL_MAX_AGE_DAYS`，預設 7 天）、鏡像裡有對照表沒有的公告或 NVIDIA 修訂過的公告。說明會寫出是哪一個。發現照算，但不能當作完整 |
| ATTENTION | 下列任一：掃描到的版本線有未審核的列、有需原廠確認的 CVE、SBOM 裡有多個 Jetson Linux 版本 |
| OK | 已比較完，有沒有發現都是 OK |

`C-nvidia-bulletins-db`（`candidates`）的狀態：

| 狀態 | 條件 |
|---|---|
| GAP | 鏡像不存在、讀不到或過期 |
| ATTENTION | 有待審公告 |
| OK | 沒有待審公告 |

退出碼：輸入錯誤（SBOM 或對照表讀不到、格式不對、已審核的列沒填審核人）是 3，同時印一行 FAIL。

## 不涵蓋的部分

- **flash 裡的韌體**：MB1／MB2、BPMP 韌體、QSPI 的 UEFI、OP-TEE 映像不在 rootfs SBOM。`where_it_lives=flash` 的列用 rootfs 的 Jetson Linux 版本推定，裝置實際刷的版本可能不同。發現的 `evidence.version_basis` 會註明。
- **客戶自己改過的 BSP**：自行編譯的核心、initrd、UEFI，版本號還是 NVIDIA 的，內容不一定一樣。
- **公告的自由文字版本**：由人判讀，程式不猜。草稿只是起點。
- **IGX OS**：IGX OS 的列不和 Jetson Linux 版本比較，因為無法從 SBOM 判斷 IGX OS 版本。
- **套件 purl**：Syft 把 `nvidia-l4t-*` 記成 `pkg:deb/ubuntu/...`，這不是 Ubuntu 的套件。發現沿用 SBOM 的 purl，沒有修正。

## 部署

- `deploy/pilot/install.sh`（`N-nvbul-mirror`）：鏡像檢查不過就重新下載，把 `<PILOT_NVBUL_MIRROR_DIR>/current` 寫進 `pilot.env`。sca-persistent 的資料夾是 `~/.cache/sca-pilot-ci/nvidia-bulletins`。
- `deploy/gitlab-runner/install.sh`（`G-nvbul`）與每日的 `sca-nvd-refresh`：更新常駐環境的鏡像，複製到 `/var/lib/sca-gitlab/nvidia-bulletins`，路徑寫進 `/etc/sca-gitlab/pilot.env`。
- `sca-center 的快速檢查腳本（沒有帶進 dumpling）`：常駐環境有鏡像時，R39.2.1 的 `C-nvidia-bulletins` 應該是 OK；沒有鏡像時 GAP 是預期的。

## 目前的對照表（2026-11-02）

- 使用者決定測試階段只看 R39，對照表先不審核。
- 預填 11 個 Jetson 公告（5321、5343、5417、5442、5466、5555、5611、5617、5662、5716、5797），共 45 列，全部 `reviewed=false`。由 `candidates --draft` 從鏡像（commit 6e340ebe）產生，再補上 `note`。每列的 `source.row` 都和公告 Markdown 逐字相同。
- 只是把 Jetson 列為平台的其他產品放在 `not_applicable`，也是 `reviewed=false`：5560 CV-CUDA、5596 nvJPEG2000、5661 CUDA Toolkit，以及從鏡像 commit 7ed82859（下載時間 2026-11-04T00:11Z UTC）補上的 5910 CUDA Toolkit（nvJPEG，2026-11-03 發布）。5910 補上前，鏡像有表上沒有的公告，`C-nvidia-bulletins` 會是 GAP（`fast-check.sh` 的 `F-nvidia-*` 因此是 ATTENTION）。
- `reviewed_until` 是 `null`。
- R39.2.1 映像（建置 2026-08-06）配上這份鏡像：沒有公告列出 39。22 個 CVE、23 筆「公告 × CVE」（CVE-2022-42270 同時在 5417 與 5442）都早於建置日，全部推定已含修正，`C-nvidia-bulletins` 是 OK。這個 OK 依賴未審核的列（見上）。
