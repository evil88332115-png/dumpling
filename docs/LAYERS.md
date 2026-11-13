# 分層：報告與 DT 依層分開（M2 L 軌）

PLAN「BSP 掃描範圍」要求：BSP（我們的待辦）、OS（範例 rootfs，給客戶參考）、主機端工具（不進產品漏洞清單）分開；P1 判斷表預設只放 BSP。
本文件是實作的規則與使用方式。程式：`pipeline/lib/layers.py`（分類）、`pipeline/sbom-layers.py`（標記與拆分）、
`tools/cra/cra_report.py`、`tools/cra/report_package.py`（報告）。測試：`tests/test_layers.py`（`tests/run.d/c1-m2-layers.sh`）、
`tools/cra/tests/test_layers_report.py`（`tests/run.d/c1-tools.sh`）。

## 1. 四個層值

| 值 | 意思 | 例（Jetson） |
|---|---|---|
| `bsp` | 我們負責、必掃、算待辦 | `nvidia-l4t-*` 套件、核心與樹外模組、device tree、開機映像、我們自己的程式 |
| `os` | 作業系統層；算不算我們的待辦由專案的 `os_responsibility` 決定 | 範例 rootfs 的 Ubuntu 套件 |
| `host-tool` | 在開發主機上跑、不在產品上執行；不進產品漏洞清單 | `Linux_for_Tegra/flash.sh`、`tools/*` |
| `unknown` | **判斷不了**。不猜、不歸成 os；一律當我們的待辦（最保守，不漏報） | 沒有發行版套件身分、也沒有路徑的 Go／Python 套件 |

層寫在 SBOM 每個元件的 property：`dumpling:layer`（值）、`dumpling:layer-basis`（依據：`package-name`、`path`、`own-software`、
`own-software-list`、`component-type`、`inherited`、`unresolved`）；SBOM 的 metadata 記 `dumpling:os-responsibility`、`dumpling:platform`。
子元件（元件裡的 `components`）跟著父元件，依據標 `inherited`。cra_report 只讀這些 property（不 import `pipeline/`，兩邊的名稱由測試核對）。

## 2. 判斷規則（`layers.classify_component`，第一個成立的就是答案；**不看版本字尾**，D-027）

1. **我們的軟體**：cra 設定 `sbom.own_software` 產生的元件（bom-ref 以 `sca-center:own:` 開頭），或專案 `project.yml` 的 `own_software`
   清單對到（含 `/` 的項目比路徑，其餘比元件名稱，fnmatch；不像套件名稱的自由文字項目略過並計數）→ `bsp`。
2. 型別 `operating-system` → `os`；型別 `firmware` → `bsp`。
3. **發行版套件**（purl 類型 `deb`／`rpm`／`apk`／`alpm`）：只看套件名稱，用 `classify_package`：`layers.bsp.packages` → `bsp`、
   `layers.host-tool.packages` → `host-tool`、其餘 `os`（平台的 `default: os`）。
4. **有路徑的元件**（Syft 的 `syft:location:N:path`、`syft:metadata:path`、`syft:metadata:virtualPath`（Java）、CycloneDX `evidence.occurrences[].location`、型別 `file` 的名稱）：
   路徑去掉開頭的 `/`、`./` 後比平台的 `layers.bsp.paths` → `bsp`、`layers.host-tool.paths` → `host-tool`、`layers.os.paths` → `os`；
   **沒有任何規則對到 → `unknown`**（`default: os` 只用在發行版套件，不用在路徑）。路徑含 `..` 或 NUL 的不採用。
   核心、樹外模組、device tree、UEFI、OP-TEE／TF-A、NVIDIA 閉源韌體都在這一條，由平台設定的路徑樣式決定（不寫死在程式裡）。
5. 其他 → `unknown`。

**unknown 附原因（D-030）**：每個 unknown 元件記 `dumpling:unknown-reason`（子元件是 `inherited`），按原因計數寫進 `layers.json` 的 `unknown.by_reason`、
cra_report 的 `summary.json`（`layers.unknown_by_reason`）、風險評估 Layers 一節（"Why the layer could not be determined"）與 `漏洞清單.xlsx` 的「分層摘要」：

| 原因 | 意思 |
|---|---|
| `no-path` | 沒有路徑也不是發行版套件（Syft 沒給 `syft:location`／`virtualPath`，例如 Go 執行檔裡的模組、Python 套件） |
| `path-no-rule` | 有路徑，但 `platform.yml` 沒有任何規則對到 |
| `inherited` | 子元件，跟著父元件的 unknown |
| `file-unowned` | 檔案紀錄（`type: file`，Syft 對套件擁有的檔案產生的元件，沒有 purl／CPE）：沒有擁有它的套件，路徑也沒有對到規則 |

**檔案紀錄的層**：`sbom-layers.py split --owners <檔>`（Jetson 由 assemble 步驟從刷機包 rootfs 的 dpkg `.list` 產生 `owners.json`：`{路徑: 套件}`，路徑做 usrmerge 正規化）；
`type: file` 的元件用擁有它的套件名稱走 `classify_package`（`nvidia-l4t-*` → bsp，其餘 os），再和路徑規則取最保守的（依據 `file-owner`）。沒有 `--owners` 時照舊只看路徑。

SBOM 若帶 Syft 的路徑（`syft:location:N:path`、`virtualPath`），先套平台的路徑規則，對得到的就歸類，判斷不了的才留 unknown。

同一個元件有多個路徑時取最保守的：`bsp` > `unknown` > `os` > `host-tool`（在產品上、我們負責的優先；有一個路徑判斷不了就是 `unknown`，
不會因為另一個路徑是 host-tool 就當成 host-tool）。

**NVIDIA 套件清單（D-030）**：原則是「NVIDIA 為這個平台提供的套件都算 bsp」，但仍是名稱清單（D-027），只有清單裡的才歸 bsp。清單取自公開 Jetson BSP（R39.2.1）：
BSP 的 `nv_tegra/l4t_deb_packages/`、`kernel/`、`bootloader/` 裡全部 deb 的套件名稱（2026-11-12 讀 `Jetson_Linux_R39.2.1_aarch64.tbz2` 的成員清單），
以及 `nvidia-l4t-apt-source` 套件指向的 NVIDIA apt 倉庫（`repo.download.nvidia.com/jetson`）；範例 rootfs 的 dpkg 狀態（fixture）裡來自 NVIDIA 的只有這些。
實際出現的名稱：`nvidia-l4t-*`（69 個）與 `nvidia-igx-oobe`、`nvidia-igx-systemd-reboot-hooks`、`nvidia-igx-bootloader`（BSP 的 bootloader 套件）→ 樣式 `nvidia-l4t-*`、`nvidia-igx-*`。
不在清單的：`libdrm-tegra0`、`libcurl4t64`（Ubuntu 套件，名稱裡有 tegra／t64，維護者是 Ubuntu）、`python3-jetson-gpio`／`jetson-gpio-common`（BSP 的 `tools/` 裡的 deb，host-tool 路徑；rootfs 沒有）。
換 Jetson Linux 版本或增加 NVIDIA 套件系列時，重新讀 BSP 的 deb 清單再更新 `platform.yml`。

**路徑樣式比的是元件在映像裡的路徑**：rootfs 映像是 `usr/lib/modules/…`、`boot/…`；BSP 資料夾是 `Linux_for_Tegra/…`。平台設定兩種都列
（`pipeline/platforms/jetson/platform.yml`）。`layers.os` 只有 `paths`（選用）；套件沒列在 bsp／host-tool 的本來就是 os。

### cra_report 自己加的列

cra_report 用 BSP 專屬輸入產生的列直接是 `bsp`（依據 `synthetic:*`）：UEFI／OP-TEE 內建函式庫的列、NVIDIA 安全公告的列、
廠商核心 CVE 清單（kernel CNA）的列。其他列用元件找層：purl → 名稱＋版本 → 對應來源（`mapped_from`，例如 l4t 核心對應）→ 安裝的二進位套件
（DT 以原始碼套件比對時）→ 擁有它的 deb（Ubuntu 打包的 Python 模組）；都對不到是 `unknown`。同一列對到多個層時 `bsp` > `unknown` > `os`。

分層的 SBOM **沒有任何 bsp 或 unknown 元件**時（`customer`／`upstream-vendor` 的 `-os` 那份），BSP 專屬的附加輸入在這份不適用：刷機包韌體清單不加進產品 SBOM（sbom.md 第 6 節寫明在 BSP 報告）、UEFI 與 OP-TEE 的內建函式庫（`--uefi-source`／`--tee-source` 或 `<scan>/../uefi-source`、`tee-source`）不產生列、它們的狀態也不算進這份，避免和 `-bsp` 報告重複計算。略過哪幾項記在 `summary.json` 與 `vulnerability-rows.json` 的 `layers.bsp_inputs_not_applicable.skipped`。有 unknown 元件時照舊加入（unknown 保守算 BSP 待辦）。`ours` 或沒給 os_responsibility 時只有一份報告、沒有 `-bsp` 那份，即使 SBOM 只有 os 元件也照舊加入（不然明確給的 `--tee-source` 會沒有人處理）。

## 3. 三種 `os_responsibility` 的行為

`os_responsibility` 由專案決定（`project.yml`；`cra_report.py --os-responsibility` 可覆寫，SBOM 的 metadata 也記一份）。

| | `ours`（自有品牌 AI NAS） | `customer`（Jetson 範例 rootfs） | `upstream-vendor`（轉售 TrueNAS） | 沒給（**GAP，不預設**） |
|---|---|---|---|---|
| OS 層的列算我們的待辦 | 是 | 否 | 否 | 是（最保守） |
| `P1判斷表.xlsx` | 含 OS 層的 P1 | 只有 bsp＋unknown | 只有 bsp＋unknown | 含所有層 |
| `漏洞清單.xlsx` | 層欄位、依層排；OS 層在同一份待辦裡 | 另開「範例 rootfs（給客戶參考）」「通知客戶」；「排除後剩下的」只有我們的待辦 | 另開「OS層（上游廠商負責）」「通知客戶」 | 同 ours，加 GAP 說明 |
| OS 層出現 KEV（EUVD、人工證據同） | 我們的 P1，整體 ATTENTION | **不**讓整體 ATTENTION；列入「通知客戶」 | 同 customer（說明是上游廠商負責、我們只通知客戶） | 我們的 P1，整體 ATTENTION |
| DT | 一個專案 `<名稱>` | 兩個專案 `<名稱>-bsp`、`<名稱>-os` | 同 customer | 一個專案（全部當待辦） |
| 風險評估文件狀態 | 看內容 | 看內容（OS 層 P1 不算） | 同 customer | **GAP**（原因寫進 `risk.data_status_detail` 以外的文件理由；不影響漏洞資料狀態） |

沒有任何一個漏洞從報告消失：不算待辦的列仍在風險評估的 P1／P2／P3 表（多一欄 Layer）、`vulnerability-rows.json`、完整漏洞清單與 OS 層工作表。

### ATTENTION／狀態怎麼算（cra_report）

只改「算不算我們的待辦」，不改資料狀態（GAP／NOT_ASSESSED）的判斷：

| 項目 | 規則 |
|---|---|
| 有未處理的 P1 → ATTENTION | 只數我們的待辦的 P1；OS 層在 customer／upstream-vendor 時不數，理由文字註明「另有 N 列 P1 在 OS 層，不算在這裡」 |
| 移出 P1–P3 的 KEV 列（發行版已修補）要人工確認 → ATTENTION | 至少有一列是我們的待辦才 ATTENTION；OS 層不是待辦的列仍列在發行版小節與「通知客戶」 |
| 分級方式 `exploitation` 的出貨關卡（BLOCKED／必須判斷的範圍） | 只看我們的待辦 |
| Grype／DT 交叉核對的差異、EUVD 標示被利用但不在表上的 CVE、資料新鮮度、sbomgate | **不分層**（偏保守：這些是資料完整度，不是待辦） |
| vex_export 的發行閘門（`vex.gate`） | **不分層**（不變）。要不要讓 OS 層的未評估列也擋我們的發行是政策問題，見「待確認」 |
| 沒給 os_responsibility | 風險評估文件 GAP（`est`）；OS 層全部當待辦 |
| unknown | 是我們的待辦，不另外讓狀態變差；數量與來源（`golang 235` 這種）寫在 Layers 一節與 `summary.json` |

### host-tool

host-tool 隨 BSP 提供給客戶，在客戶的主機上執行，不在產品上執行（風險評估與報告包的主機端工具一節都有這句話）。
host-tool 元件上的 DT finding 與 Grype 比對**在列出之前**就移出產品的比對結果（所以不進清單、不進交叉核對、不進 P1，也不會讓狀態變差），
`summary.json` 的 `layers.host_tool` 記元件身分、移出的 finding／比對筆數與漏洞編號；風險評估 Layers 一節寫「Host tools (not running on the product)」。
同一個 purl（或名稱＋版本）在別的層也有時不算 host-tool 專用，保守地留在產品清單。
建議的流程裡 host-tool 根本不會被送去掃描（`sbom-layers.py split` 的 scan_plan 不含它），這一段是 SBOM 沒拆就直接給 cra_report 時的保險。
產品 SBOM（`Reports/sbom.cdx.json`）仍保留標了 `host-tool` 的元件（不默默刪元件）。

## 4. `pipeline/sbom-layers.py`

```
python3 -I pipeline/sbom-layers.py tag   <sbom> <平台> <專案資料夾> <輸出sbom>   [--os-responsibility X] [--platforms-dir D]
python3 -I pipeline/sbom-layers.py split <sbom> <平台> <專案資料夾> <輸出資料夾> [--os-responsibility X] [--platforms-dir D]
python3 -I pipeline/sbom-layers.py show  <標好層的sbom>
```
最後一行 `sbom-layers: OK｜GAP｜FAIL（說明）`；結束碼 OK 0、FAIL 1、GAP 3、用法錯誤 64。輸入可以是 `.json` 或 `.xz`（視為不可信資料，只讀）。
專案資料夾必須通過 `project_config` 驗證（所以 `os_responsibility` 一定有值；GAP 只會發生在直接用函式庫、沒給值時）。

`split` 的輸出（沒有元件的檔案不產生）：

| 檔案 | 內容 | 用途 |
|---|---|---|
| `sbom.bsp.cdx.json` | `bsp`＋`unknown` | DT 專案 `<名稱>-bsp`（unknown 當待辦） |
| `sbom.os.cdx.json` | `os` | DT 專案 `<名稱>-os` |
| `sbom.host-tool.cdx.json` | `host-tool` | **不上傳**，只留作記錄 |
| `sbom.product.cdx.json` | 除了 host-tool 以外全部（每個元件帶層） | `os_responsibility` 是 `ours` 或沒給時的單一專案 |
| `layers.json` | 各層數量、`unknown` 的來源、`scan_plan`、丟掉的跨層依賴邊數、`gaps` | scan 步驟讀它 |

不變量（測試核對）：`bsp.cdx` 與 `os.cdx` 與 `host-tool.cdx` 的 bom-ref 聯集＝原本、沒有重複；`product.cdx`＝原本扣掉 host-tool；每份的 `dependencies`
只留兩端都在同一份的邊（不留懸空的 ref），丟掉的邊數記在 `dropped_dependency_edges`（跨層依賴不會讓元件消失，但單看 `-bsp` 專案會缺少「依賴 OS 套件」的邊）。
輸出是確定的（同樣輸入同樣位元組）。

`layers.json` 的 `scan_plan` 是 scan 步驟要掃的清單：

| os_responsibility | 項目 |
|---|---|
| `customer` | `-bsp`（`sbom.bsp.cdx.json`，我們的待辦）、`-os`（`sbom.os.cdx.json`，範例 rootfs 給客戶參考） |
| `upstream-vendor` | 同上，OS 那項的說明是「上游 OS 廠商負責，我們只通知客戶」 |
| `ours`、沒給 | 一項，名稱後綴為空（`sbom.product.cdx.json`） |

## 5. DT 怎麼分

- **兩個 DT 專案**（`customer`／`upstream-vendor`）：`<名稱>-bsp`、`<名稱>-os`。理由：DT 的通知、政策、指標都是以專案為單位，分開後 BSP 專案的 KEV 才會
  通知 RD，OS 專案的 KEV 不會變成我們的待辦；也最符合 PLAN「報告與 DT 分成兩個專案」。用現有 `tools/pilot/sca-scan --sbom <檔> --name <名稱+後綴>`
  各跑一次，**不用改 sca-scan**。每一份各自得到一份 scan 輸出資料夾與一份報告。
- `ours`：不分（OS 也是我們的待辦），一個專案、一份報告；層欄位照樣標，P1 判斷表含 OS 層。
- **host-tool 不上傳 DT**（不是產品的一部分；上傳會讓產品專案出現與產品無關的 KEV）。拆分時留作記錄檔。
- DT 5.2.0 的專案階層（`PUT /api/v1/project` 的 `parent`）理論上可以讓 `-bsp`、`-os` 掛在 `<名稱>` 底下，但 sca-scan 目前建立專案時不設 parent，
  且還沒在臨時 DT 驗證，所以先用兩個平行的專案（見「待確認」）。

## 6. 給 J 軌：scan 步驟怎麼呼叫

```bash
layers="$DUMPLING_OUT/layers"
python3 -I "$DUMPLING_ROOT/pipeline/sbom-layers.py" split "$sbom" "$DUMPLING_PLATFORM" "$DUMPLING_PROJECT_DIR" "$layers" || rc=$?   # 0 OK、3 GAP
# 讀 $layers/layers.json 的 scan_plan，每一項依序做（report_package 讀 <專案>/CRA/Reports，所以一項做完再做下一項）：
#   tools/pilot/sca-scan --sbom "$layers/<sbom>" --name "<專案名><name_suffix>" --version "$DUMPLING_VERSION" --out "$DUMPLING_OUT/scan<name_suffix>" [其餘照原本]
#   python3 -I tools/cra/cra_report.py --project "$DUMPLING_PROJECT_DIR" --scan "$DUMPLING_OUT/scan<name_suffix>/<sca-scan 輸出>" \
#       --os-responsibility "$DUMPLING_OS_RESPONSIBILITY"
#   python3 -I tools/cra/report_package.py --project "$DUMPLING_PROJECT_DIR" --out "$DUMPLING_OUT/report<name_suffix>"
```
- 讀 `scan_plan` 用 `pipeline/lib/platform_scan.py` 的 `scan_plan_lines`（Jetson：`jetson_scan.py plan --layers-json <檔>`），每行「後綴 0x1F 檔名」，shell 用 `IFS=$'\x1f' read -r suffix sfile`。**不要用 TAB 分隔**：TAB 是 IFS 空白字元，開頭的空欄位會被吃掉，`ours` 的後綴是空字串，檔名就跑進 suffix。`ours` 的那一項和完整掃描同一個後綴，`collect` 取後面那次（產品 SBOM 重跑）當報告。
- **核心只在 bsp 層，其他層要告訴 sca-scan（`--kernel-in-other-report`）。** 每一項重跑都換上該層的 SBOM，但 sca-scan 的核心階段（`C-kernel-cve-list`、`C-kernel-config`、`C-kernel-module-map`）是從**映像**讀核心的，
  不看分層後的 SBOM。`-os` 層的 SBOM 沒有核心，不告訴它的話：Jetson 的 `-os` 報告多 3 列假的 GAP（CNA 拒絕 ABI 風格的版本字串，加上 config 與模組對應 GAP）；Raspberry Pi 型的映像 CNA 版本比對會「成功」，
  `-os` 報告多出約 2700 列合成的 linux-kernel 列（`cra_report` 標 `synthetic:kernel-cna`），這些是 bsp 的事。**對 `scan_plan` 裡 bsp 以外的分層重跑（`-os`），給 `--kernel-in-other-report "<專案名>-bsp"`**
  （`wiz "$suffix" --kernel-in-other-report "$DUMPLING_PROJECT-bsp" --rescan-from …`；wizard 的選項，傳到 `scan-flash-package.sh` 與 `sca-scan`，後兩者也接受環境變數 `SCA_KERNEL_IN_OTHER_REPORT`）。
  - 效果：給了而且 kernelcheck 判定這份 SBOM 沒有核心（`C-kernel-coverage` 的 NOT_RUN）時，三個階段各記一列 `NOT_RUN`「不適用：這份報告的 SBOM 沒有作業系統核心，核心在 <名稱> 報告判定」，
    不執行 CNA 版本比對、`kernel_config.py`、`kernel_module_map.py`，不記 `C-kernel-not-judged-*`，也不寫 `scan/kernel-versions.json`（出貨核心有沒有判定是 bsp 報告的事；Release 附件的 `kernel-versions` 本來就取完整掃描那次）。
  - `-bsp` 自己、完整掃描和 `ours` 的空後綴重跑**不要給**（核心就在那份報告判定）。給 `-bsp` 等於指向自己：bsp 的 SBOM 偵測不到核心時（廠商核心不是套件）會把該做的核心判定（含 CNA 退回）壓掉；sca-scan 對名稱等於自己的 `--name` 以 exit 64 拒絕。
  - **不給的話行為不變**，所以不能由「SBOM 沒有核心」自行推定：單一 SBOM 的廠商核心（不是套件）仍要走 CNA 版本比對。名稱只接受 `^[A-Za-z0-9][A-Za-z0-9._+-]{0,99}$`，否則 exit 64。
  - sca-scan 同時在 `meta.json` 記 `kernel_in_other_report: <名稱>`（結構上的標記）。`cra_report` 的核心判定階段（`C-kernel-cve-list`、`C-kernel-config`、`C-kernel-module-map`、
    `C-kernel-versions`、`C-kernel-not-judged-*`、`C-kernel-cve-mirror`）不是 OK 時資料狀態降成 GAP（ATTENTION 維持 ATTENTION；D-043：沒有 CNA 鏡像、核心版本讀不出來、
    `kernel_config.py` 失敗、出貨的核心沒判定都算沒判定完）。**只有** `meta.json` 有 `kernel_in_other_report` 時，那三個核心階段的 NOT_RUN 不降級——不看說明文字，
    說明寫「不適用」而沒有這個標記照樣 GAP（標記要是符合報告名稱格式的字串）；標記也不免除 GAP／FAIL、`C-kernel-versions`、`C-kernel-not-judged-*`。
    `--sbom` 沒給 `--kernel-build` 時，sca-scan 只在 SBOM 看得到核心時才寫 `C-kernel-config`／`C-kernel-module-map` 的 NOT_RUN（沒有核心的產品不會因此永遠 GAP）；廠商核心不是套件、SBOM 看不出來時要給 `--kernel-build` 才會判定。沒有核心的 `-os` 報告讀不到核心的列，8.7 節寫「SBOM 沒有核心」。
  - 平台轉接器（rpi、rock-5b、AI NAS…）自己的 `scan.sh` 要照 Jetson 的 `scan.sh` 這樣呼叫；規則見 `docs/PLATFORM-INTERFACE.md` §4（sources.yml 的平台參數）。
- `cra_report.py` 不需要 `--os-responsibility`（SBOM 的 metadata 已記），明確傳是保險；傳的值優先。
- 拆分前的完整 SBOM 還是要留（`sboms/`、Release）：`sbom.product.cdx.json` 是標好層的完整產品 SBOM。
- `report_package.py --p1-layers bsp,unknown,os` 可改 P1 判斷表放哪幾層（預設只放我們的待辦）。
- 各項的最終狀態取最差的；`layers.json` 的 `gaps` 非空時 scan 步驟至少回報 GAP。

## 7. Jetson 標準答案（`tests/fixtures/jetson-r39.2.1-base.cdx.json.xz`，Syft 1.55.0，3851 個元件）

D-030 校正前後（platform.yml 的 NVIDIA 套件清單加 `nvidia-igx-*`）：bsp 1537 → **1539**、os 1975 → **1973**、unknown 339 不變、host-tool 0 不變。

| 層 | 元件數 | 組成 |
|---|---|---|
| `bsp` | 1539 | `nvidia-l4t-*` deb 69 ＋ `nvidia-igx-*` deb 2 ＋ 核心與樹外模組（`/usr/lib/modules/…`，linux-kernel-module）1468 |
| `os` | 1973 | 其他 Ubuntu deb 1972 ＋ OS 元件 1 |
| `unknown` | 339 | Go 235、Python 101、Java 3。原因：沒有路徑也不是發行版套件 336（Go、Python）、路徑沒有對到任何規則 3（Java，`virtualPath` 在 `/usr/share/…`） |
| `host-tool` | 0 | rootfs 映像裡沒有刷機工具 |

測試把這些數字釘死（`tests/test_layers.py` 的 `JETSON_EXPECTED`）：規則或 platform.yml 讓數字變動時，必須確認新歸屬是對的才改。
**CI 實跑（精靈的 Syft SBOM，含檔案紀錄；2026-11-12，R39.2.1＋patch，`tests/expected/orin-nano-demo/v39.2.1-demo1.json`）**：

| 層 | 第一次實跑（只看路徑） | 加上 dpkg 擁有者（`--owners`）與 D-030 校正後 |
|---|---:|---:|
| `bsp` | 3,249 | **22,893**（`nvidia-l4t-*`／`nvidia-igx-*` 71 個套件、它們擁有的檔案紀錄、核心模組 1,536、/boot） |
| `os` | 1,973 | **88,263**（Ubuntu 套件 1,972 ＋ 它們擁有的檔案紀錄） |
| `host-tool` | 0 | 0 |
| `unknown` | 92,290 | **4,787**：沒有擁有者的檔案紀錄 4,448（`file-unowned`）、Go／Python／Java 套件 339（`path-no-rule`） |
| 總計 | 97,512 | 115,943（第一次實跑的 rootfs 漏了 18,431 個長路徑成員，已修，見 `docs/JETSON.md`） |

另一個校正：核心的漏洞列（`linux-nvidia-tegra`，Canonical 核心對應 NVIDIA 的核心套件）原本全是 `unknown`（6,556 列），因為 `mapped_from` 的值是「名稱 版本」、
`cra_report.layer_of_row` 拿整串去找套件索引；改成只用名稱後，這些列是 `bsp`（-bsp 報告：bsp 6,366 列、unknown 223 列）。

## 8. 待確認（已採最保守做法，不阻擋）

1. **unknown 339 個**（Go／Python／Java）現在全列入 BSP 待辦。它們在乾淨的 Ubuntu rootfs 幾乎都是 Ubuntu 套件帶進來的；要歸 os 需要
   「這個語言套件屬於哪個 deb」的資料（pkgdb 的 dpkg 檔案歸屬）。建議 J 軌用 pkgdb 補路徑或擁有者；cra_report 已能用「擁有它的 deb」
   （`deb_python.owner`）找層，只是 SBOM 端的標記要有路徑才行。或由 PM 決定是否在 platform.yml 用 `layers.os.paths` 宣告 rootfs 裡 Ubuntu 的路徑。
2. **NVIDIA 套件**（D-030 已處理）：`nvidia-igx-*` 加進 bsp 清單；`libdrm-tegra0`、`libcurl4t64` 是 Ubuntu 套件，維持 os。以後 NVIDIA 在 BSP 裡出現新的套件系列，要重讀 BSP 的 deb 清單更新 `platform.yml`。
3. **發行閘門（`vex.gate`）不分層**：OS 層在 customer 時，未評估的 KEV 仍會讓發行閘門 BLOCKED／ATTENTION。這是否符合「OS 由客戶負責」需要 PM／法務決定。
4. **兩個 DT 專案 vs. 專案階層（parent／child）**：見第 5 節。
5. **host-tool 是否另開 DT 專案**：現在不上傳。
6. **`platform.yml` 的路徑樣式**已對過公開 R39.2.1 BSP 的成員清單（2026-11-12）補了 `bootloader/*.fip|*.deb`、`nv_tegra/l4t_deb_packages/*`、host-tool 的腳本與簽署工具；
   但精靈的 Syft 只掃 rootfs（刷機包資料夾本身的 `Linux_for_Tegra/…` 檔案不在 SBOM 裡，由 cra_report 的 flash-inventory 另外加進產品 SBOM），所以 host-tool 在 Jetson 實跑的 SBOM 是 0 個。
7. 風險評估範本是專案自己的複本時（`CRA/templates/risk-assessment.md`）沒有 `{{ text.layer_section }}`，Layers 一節不會出現在文件裡（cra_report 會記警告；
   `summary.json`、`vulnerability-rows.json`、報告包的工作表照樣有）。
