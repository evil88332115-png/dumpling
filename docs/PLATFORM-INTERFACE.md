# 平台介面與開案範本（契約）

給 C4（Raspberry Pi、Rockchip、AI NAS 轉接器）與之後新增專案、新增平台的人照做。實作在 `pipeline/`；
測試在 `tests/test_platform_interface.py`（`tests/run.d/c1-m2-platform.sh`）。

## 1. 目錄結構

```
templates/project/             開案範本（new-project.sh 用）
pipeline/
  new-project.sh               開案：產生 projects/<專案名>/
  platform.sh                  dispatcher：workflow 只呼叫它
  project-info.py              印出專案資訊（KEY=VALUE）給 workflow 用
  lib/fetch_verify.py          共用下載核對（https only、.part、大小＋sha256、拒絕 symlink）
  lib/platform_fetch.py        共用 fetch 步驟（讀 sources.yml）
  lib/project_config.py        project.yml／sources.yml／platform.yml 的讀取與驗證
  lib/new_project.py           new-project.sh 的實作
  platforms/<平台>/
    platform.yml               平台設定（必要）
    build.sh assemble.sh scan.sh   各步驟（沒有就是 NOT_RUN）
    fetch.sh                   選用：覆寫共用的 fetch
    raw-sectors.sh             選用掛點：清點分割區外的原始磁區
projects/<專案名>/             一個產品一個資料夾
  project.yml  sources.yml  patches/  CRA/Config/{config.json,inputs.json,vex-rules.json}
```

## 2. 新增專案（不改 workflow）

```
pipeline/new-project.sh <專案名> --platform <平台> --company-role <manufacturer|supplier|both> \
    --os-responsibility <ours|customer|upstream-vendor> [--product-name …] [--brand …] [--version v0.1.0-dev1] \
    [--markets EU] [--support-until YYYY-MM-DD] [--status development|shipped]
```
1. 跑上面的指令（專案名只能用小寫英數與連字號）；會從 `templates/project/` 與平台的 `project_defaults` 產生專案，
   `CRA/Config/` 的三個檔從平台預設值帶入（`config.json`←`tools/cra/config.example.json`、`inputs.json`←`scan.inputs_template`
   指到的精靈範本、`vex-rules.json`←`tools/cra/vex-rules.example.json`）。不覆寫已存在的專案。
2. 把 `project.yml`、`sources.yml` 裡值是 `TO BE COMPLETED` 的地方填完；`python3 -I pipeline/lib/project_config.py validate projects/<專案名>` 會列出還沒填的欄位。`status` 改成 `shipped` 之前不能有待填欄位。
3. 推上去。dev／release workflow 讀 `project.yml` 的 `platform`，打 tag `<專案>/<版本>` 就走 release。

## 3. project.yml 欄位（全部必填）

| 欄位 | 型別 | 對應《開案-CRA資訊表》 |
|---|---|---|
| `schema` | `1` | |
| `product_name` | 字串 | 產品名稱 |
| `brand` | 字串 | 品牌或客戶 |
| `company_role` | `manufacturer`｜`supplier`｜`both` | 公司角色 |
| `markets` | 字串清單（不可空） | 銷售市場 |
| `platform` | 字串，必須有 `pipeline/platforms/<platform>/platform.yml` | 平台 |
| `platform_version` | 字串 | 平台與版本 |
| `bsp_os_source` | 字串 | BSP／OS 來源 |
| `kernel_source` | 字串 | 核心來源 |
| `bootloader` | 字串 | 開機程式 |
| `own_software` | 字串清單（可空 `[]`） | 自有軟體 |
| `interfaces` | 字串清單（不可空） | 對外介面 |
| `support_until` | `YYYY-MM-DD` | 支援期限 |
| `status` | `development`｜`shipped` | 狀態 |
| `os_responsibility` | `ours`｜`customer`｜`upstream-vendor` | OS 層歸誰 |

`os_responsibility`（D-025、D-027）**由專案的角色與交付方式決定，不寫死在平台設定**。分層邏輯（L 軌）依它處理 `os` 層：
- `ours`：OS 層也是我們的待辦（例如自有品牌的 AI NAS），P1 判斷表含 OS 層。
- `customer`：OS 由客戶負責（例如 Jetson 範例 rootfs）：照掃、分開列，出現 KEV 時通知客戶，不進我們的修補待辦。
- `upstream-vendor`：上游 OS 廠商負責（例如只轉售 TrueNAS）：我們只通知客戶。
個別產品用哪一種由 PM 與法務判斷；資料模型支援三種。dispatcher 會把值放進環境變數 `DUMPLING_OS_RESPONSIBILITY`，`project-info.py` 也會輸出。

## 4. sources.yml

```yaml
schema: 1
releases:                      # 一個專案多個版本；tag 是 <專案>/<版本>，版本必須以 v 加數字開頭
  v39.2.1-demo1:
    platform_params: {l4t_release: "39.2.1"}   # 選填：轉接器自己定義的參數
    files:
      - name: x.tbz2           # 檔名（落在下載資料夾）
        url: https://…         # 只允許 https
        sha256: <64 位小寫十六進位>
        size: 123              # 選填（沒記錄就省略，不核對大小，下載上限 64 GiB）
        sha1: <40 位>          # 選填：廠商公布的 SHA-1，另外核對
        role: bsp              # bsp｜rootfs｜source｜image｜package｜tool
      - name: src.tar.gz       # GitHub 動態封存檔：以 commit SHA 為準
        url: https://github.com/<組織>/<repo>/archive/<commit>.tar.gz
        sha256: <封存檔雜湊>
        commit: <40 位 commit SHA>
        repo: https://github.com/<組織>/<repo>.git
        role: source
      - name: y.tbz2           # 還沒有可核對的雜湊：用 gap 取代 sha256
        url: https://…
        role: source
        gap: 尚未記錄首次下載的 sha256
```
`files[]` 沿用 `firmware/*/*/firmware.yml` 的 `name`、`url`、`sha256`、`size`、`role`（`size` 改為選填，`role` 多了 `bsp`、`rootfs`、`tool`、`metadata`）。

| `role` | 意思 |
|---|---|
| `bsp`、`rootfs`、`source`、`image`、`package`、`tool` | 平台轉接器依 role 明確挑檔案（例如 Jetson 的 assemble 只挑 `bsp` 與 `rootfs`） |
| `metadata` | 廠商附的清單或說明檔（官方 SBOM、`.info`、`.manifest`、`.json`）：唯讀、不掃描。fetch 照樣下載並核對 sha256；assemble／scan 不可把它當掃描輸入（沒有任何程式用 role 反選，只依 role 明確挑需要的） |
規則（D-025、D-027）：
- 有 `gap` 的檔案不下載，fetch 回報 GAP；**不自動接受第一次看到的 sha256**。
- 有 `commit` 的封存檔若 sha256 不符，不接受新雜湊，改用 `git clone`（只 https、不跑 hook、不抓 submodule）取該 commit、核對 `git rev-parse HEAD`，工作樹放 `<下載資料夾>/<name>.checkout`；clone 也失敗就是 FAIL。
- 下載的檔案是不可信資料：只下載、不解開、不執行。
- `platform_params.kernel_release` 可以是字串或清單（映像有不只一顆核心時，例如 Raspberry Pi 的 Pi 5 與 Pi 4），轉給 wizard 時每個值一個 `--kernel-version`（可重複；wizard 另接受環境變數 `SCA_KERNEL_VERSIONS`，命令列優先）。值原樣往下傳到 sca-scan 與核心工具；映像出貨但沒指定的核心記為「出貨但沒有判定」（`scan/kernel-versions.json`），指定 2 顆以上時一顆都不判定（多顆逐一判定還沒實作）。

## 5. 平台轉接器

`pipeline/platform.sh <步驟> <專案資料夾> <版本> [--out <資料夾>]`，步驟：

| 步驟 | 說明 |
|---|---|
| `validate` | 驗證 project.yml、sources.yml、平台設定；不做別的 |
| `fetch` | 共用：讀 sources.yml 下載核對到 `$DUMPLING_OUT/downloads/`。轉接器可提供 `fetch.sh` 覆寫 |
| `build` | 平台各自（`build.sh`）。不編譯的平台印 `build: OK（不編譯）` |
| `assemble` | 平台各自（`assemble.sh`）：組產品映像 |
| `scan` | 平台各自（`scan.sh`）：呼叫共用掃描，只提供平台設定；**平台名稱由 project.yml 明確傳下去**（見下） |
| `raw-sectors` | 選用掛點，見下 |

**每一步**是一個指令、最後印一行 `<步驟>: OK｜GAP｜NOT_RUN｜FAIL（說明）`，結束碼：

| 狀態 | 結束碼 |
|---|---|
| OK | 0 |
| FAIL | 1 |
| GAP | 3（與 `pipeline/dt-ephemeral.sh` 一致） |
| NOT_RUN | 4（沒做；呼叫端不能當成成功，也不是 GAP） |
| 用法錯誤 | 64 |

dispatcher 先驗證專案與平台設定，失敗就印 `<步驟>: FAIL（…）` 結束；轉接器沒有該步驟的腳本 → `NOT_RUN`（4）。
轉接器腳本收到位置參數 `<專案資料夾> <版本>` 與環境變數：`DUMPLING_ROOT`、`DUMPLING_PROJECT`、`DUMPLING_PROJECT_DIR`、`DUMPLING_VERSION`、`DUMPLING_PLATFORM`、`DUMPLING_PLATFORM_DIR`、`DUMPLING_OS_RESPONSIBILITY`、`DUMPLING_ARCH`（platform.yml 的 `arch`，預設 `arm64`）、`DUMPLING_OUT`（預設 `$DUMPLING_OUT_BASE` 或 `<repo>/out` 底下的 `<專案>/<版本>/`）。`DUMPLING_PLATFORMS_DIR` 可換掉轉接器根目錄（測試用）。

**平台一律由 project.yml 明確給定、一路傳到 scan，不從映像格式推測**：`scan.sh` 要把 `$DUMPLING_PLATFORM`（或平台設定 `scan.platform_arg`）原樣傳給 `tools/demo/scan-flash-package.sh --platform` 與 `tools/wizard/cra-scan.py --platform`。沒給平台時，原始磁碟映像的開機程式分類標 GAP（「沒有指定平台，不推測」），不會預設成 Raspberry Pi。

### 選用掛點：raw-sectors

平台自己清點「分割區外的原始磁區」（例如 Rockchip GPT 原始磁碟在第一個分割區之前的開機程式；以原始磁區為準，D-027）。
平台設定 `raw_sectors.enabled: true` 時必須提供 `raw-sectors.sh`；`false`（預設）時 dispatcher 回報 `raw-sectors: OK（此平台不適用）`。
轉接器的 `assemble.sh` 或 `scan.sh` 自己呼叫 `bash "$DUMPLING_ROOT/pipeline/platform.sh" raw-sectors "$1" "$2"`。建議輸出 `$DUMPLING_OUT/raw-sectors.json`：`{"schema": 1, "platform": …, "regions": [{"start_lba": …, "sectors": …, "sha256": …, "identity": …}]}`；與 rootfs 套件不符或找不到標 GAP，不用套件版本猜磁區版本。

### Jetson 轉接器（M2 J 軌；細節見 `docs/JETSON.md`）

`pipeline/platforms/jetson/`：`fetch` 用共用的（`projects/orin-nano-demo/sources.yml` 的 BSP、範例 rootfs、`public_sources.tbz2`、NVIDIA 公布的 `public_sources_sha.txt`）；
`build.sh`（原生編核心與樹外模組，只在 aarch64）、`assemble.sh`（組刷機包）、`scan.sh`（臨時 DT＋精靈＋分層＋標準答案比對）已實作，`prepare-source.sh` 是 build 與 assemble 共用的內部腳本。

Jetson 的 `sources.yml` `platform_params`：

| 鍵 | 型別 | 意思 |
|---|---|---|
| `l4t_release` | 字串（必填） | Jetson Linux 版本（例如 `"39.2.1"`）；scan 用它設定精靈的 `upstream_set`（`jetson-r39.2.1`）與 `inputs.json` 的版本字樣 |
| `patches` | 清單（選填） | **這個版本要套的 patch**，依序套在 `projects/<專案>/patches/` 的檔案。項目是檔名字串（套在核心樹 `kernel/kernel-noble`，`patch -p1`），或 `{file: 檔名, dir: 原始碼根底下的相對資料夾}`。只收檔名、不含路徑；`--dry-run --fuzz=0` 乾淨才套，套不上 = build FAIL。沒列在任何版本的 patch 不會套用（build 警告）。同一個專案的不同版本可以套不同的 patch（例如 `v39.2.0-demo1` 不套、`v39.2.1-demo1` 套 `0001-…`） |

- `build` 輸出 `$DUMPLING_OUT/BuildRecord-<專案>-<版本>.tar.gz`、`deliver/`（Image、.ko、dtb）、`build.json`；建置不可重現，所以建置紀錄與刷機包必須來自同一次編譯（workflow 用 artifact 傳給 scan，不重編、不以雜湊當 cache key）。UEFI 未自編（D-002）。
- `scan` 的環境變數：`PILOT_ENV`（pilot.env 的路徑，放在單獨的資料夾）。輸出 `$DUMPLING_OUT/release/`（Release 附件，檔名一律 ASCII，另有 `manifest.tsv`：檔名 TAB 顯示名稱）、`scan.json`（標準答案比對用的摘要）、`summary.md`。
  結束碼：OK 0；GAP 3（沒有標準答案、分層有 GAP；結果照樣產生）；FAIL 1（含標準答案不符）。
- **標準答案**：`tests/expected/<專案>/<版本>.json`，格式與規則見 `pipeline/check-expected.py` 的說明；沒有檔案 = GAP，不是通過。
- **Release 附件命名**（機器可讀，給每日監控讀）：`sbom-<專案>-<版本>.cdx.json`（完整、標好層）、`sbom-<專案>-<版本>-bsp.cdx.json`、`-os.cdx.json`、`layers.json`、`release-meta.json`
  （`project`、`version`、`tag`、`status`、`platform`、`os_responsibility`、`commit`、`built_at`、`workflow_run`；由 `pipeline/release-meta.py` 產生）。
  已出貨版本的 SBOM 不提交進 repo（D-029）：Release 就是正式來源；開發版發到每個專案一個滾動的 pre-release `dev/<專案>`（只在 `main` 或 `dev/**` 分支發布）。

## 6. platform.yml

```yaml
schema: 1
platform: jetson               # 必須和資料夾名稱相同
description: …
arch: arm64                    # 選填：目標映像的架構 arm64｜amd64（預設 arm64）；scan 的 docker import --platform linux/<arch>
build:
  mode: compile                # compile｜none（none＝workflow 略過 build job）
  runner: arm64                # 選填：build job 的 runner arm64｜amd64（預設 arm64 → ubuntu-24.04-arm／ubuntu-24.04）
  apt: [build-essential, …]    # 選填：build job 的 apt 套件（--no-install-recommends；小寫英數與 + . -）
raw_sectors: {enabled: false}  # 見上
layers:                        # 分層規則（D-027）：套件名稱（不含版本）與路徑樣式，fnmatch 語法
  bsp:
    packages: ["nvidia-l4t-*"]
  host-tool:
    paths: ["Linux_for_Tegra/flash.sh", "Linux_for_Tegra/tools/*"]
  default: os                  # 其餘一律 os
scan:                          # 選填
  runner: amd64                # 選填：scan job 的 runner amd64｜arm64（預設 amd64 → ubuntu-24.04）
  apt: [zstd]                  # 選填：scan job 額外的 apt 套件
  inputs_template: jetson      # tools/wizard/platforms/<名稱>.json，new-project.sh 複製成 CRA/Config/inputs.json
  platform_arg: jetson         # 傳給掃描工具的 --platform
  rootfs: rootfs
project_defaults:              # 選填：new-project.sh 帶入 project.yml／sources.yml 的預設值
  platform_version: …  bsp_os_source: …  kernel_source: …  bootloader: …
  own_software: []  interfaces: […]  platform_params: {}
```
**workflow 怎麼用這些欄位**（`pipeline.yml` 的 `plan` job 讀 `pipeline/project-info.py` 的輸出 `BUILD_MODE`、`BUILD_RUNNER`、`BUILD_APT`、`SCAN_RUNNER`、`SCAN_APT`、`ARCH`）：

| 欄位 | 預設 | 作用 |
|---|---|---|
| `arch` | `arm64` | 目標映像的架構；scan 用 `docker import --platform linux/<arch>`（`DUMPLING_ARCH`／`SCA_ARCH`） |
| `build.mode` | （必填） | `none`：整個 build job 略過（`if:` 為 false），scan job 照樣跑、不下載任何 build artifact。`compile`：build job 跑，runner 與 apt 取下面兩欄 |
| `build.runner` | `arm64` | build job 的 runner：`arm64`＝`ubuntu-24.04-arm`、`amd64`＝`ubuntu-24.04` |
| `build.apt` | `[]` | build job 的 apt 相依 |
| `scan.runner` | `amd64` | scan job 的 runner（`amd64`＝`ubuntu-24.04`）。**不跟著 `arch`**：scan 只匯入與讀映像，不執行目標平台的程式，所以 runner 的架構和映像的架構無關。目前只支援 amd64（`tools/e2e/install-tools.sh` 只裝 amd64 的 Syft／Grype） |
| `scan.apt` | `[]` | scan job 額外的 apt 套件（bubblewrap、python3-yaml 由 workflow 固定裝） |

**build → scan 的交接（handoff 契約）**：`build.sh` 把要交給 scan 的東西全部放在 `$DUMPLING_OUT/handoff/`（`$DUMPLING_OUT` ＝ `$DUMPLING_OUT_BASE/<專案>/<版本>`），裡面的結構自訂。
workflow 把整個資料夾上傳成 artifact、在 scan job 放回**同一個路徑**，不指名任何個別檔案；轉接器的 `assemble.sh`／`scan.sh` 從 `$DUMPLING_OUT/handoff/` 讀。
build 若寫 `handoff/build-summary.md`，workflow 把它放進 step summary（沒有就用 build 步驟的最後一行）。`build.mode: none` 的平台沒有 handoff。

- 分層規則**只用套件名稱清單與路徑樣式，不看版本字尾**（例如不以 `+rpt` 判斷）。套件樣式：小寫英數與 `+ . - _`，可含 `* ? []`，不含 `/`。路徑樣式：相對路徑、不含 `..`；`*` 也比對 `/`。套件先比 `bsp`、再比 `host-tool`，都不符合是 `os`。
- **分層的完整規則見 `docs/LAYERS.md`**。補充（向後相容的擴充）：`layers.os.paths`（選用，只有 `paths`）可明確宣告哪些路徑是 OS；路徑樣式比的是元件在映像裡的路徑
  （rootfs 映像是 `usr/lib/modules/…`，BSP 資料夾是 `Linux_for_Tegra/…`，兩種都列）。`default: os` 只用在**發行版套件**（deb／rpm／apk 的名稱）；非套件元件的路徑沒有任何規則
  對到時是 `unknown`，不會默默歸成 os。SBOM 的拆分與標記用 `pipeline/sbom-layers.py`（J 軌的 scan 步驟呼叫，見 `docs/LAYERS.md` 第 6 節）。
- `os_responsibility` **不在平台設定裡**（由專案的角色決定）；`project_defaults` 放它會驗證失敗。

**L 軌用的讀取函式**（`pipeline/lib/project_config.py`，`python3 -I` 下 `sys.path.insert(0, "pipeline/lib")`）：
- `load_platform_config(平台名或 platform.yml 路徑)` → 驗證過的 dict；錯誤丟 `ConfigError`。
- `classify_package(名稱, config)`、`classify_path(路徑, config)` → `"bsp"｜"host-tool"｜"os"`（比對用 `fnmatch.fnmatchcase`）。
- `load_project(專案資料夾)` / `load_sources(path)` / `parse_tag(tag)`。

## 7. 新增平台（不改 dispatcher 或 workflow）

1. 建 `pipeline/platforms/<平台>/platform.yml`（上面的格式；測試用的最小範例是 `pipeline/platforms/example/`）。
2. 放需要的 `build.sh`／`assemble.sh`／`scan.sh`（`fetch.sh`、`raw-sectors.sh` 選用）；每個印一行狀態、用上面的結束碼；沒做的步驟不用放（自動 NOT_RUN）。
3. `shellcheck` 新的 `.sh`；加測試；`pipeline/new-project.sh x --platform <平台> …` 產生的專案要能通過 `validate`。
4. `scan.sh` 若要用精靈的輸入清單，把範本放 `tools/wizard/platforms/<名稱>.json` 並在 `scan.inputs_template` 指向它。

## 8. 待確認

- 欄位名稱（`os_responsibility`、`company_role` 的值、`project_defaults`、`raw_sectors`）是 C1 依 D-027 自訂的，C0／PM 若要改名請告知。
- `company_role` 目前三值（`manufacturer`、`supplier`、`both`）沿用精靈的 `--role`；若開案資訊表還有 importer／distributor 角色要再加。
- `sources.yml` 的 `commit` 封存檔 clone 核對目前只在 fetch 實作；`public_sources.tbz2`（NVIDIA 沒公布整包雜湊）的 sha256 是首次下載記錄（TOFU，2026-11-12），不是官方核對；元件 SHA-1 才對 NVIDIA 公布值。
- `fetch_verify.py` 是 `firmware_fetch.py` 的超集（`size` 可為 None、`fetch_one` 先檢查 https）；`firmware_fetch.py` 改成 import 它由 C0 與 C2 協調。
- `projects/orin-nano-demo/CRA/Config/inputs.json` 是精靈範本原樣（`upstream_set` 為 r39.2.0）；scan 步驟依 `platform_params.l4t_release` 在複本裡改成該版本（原檔不動）。
