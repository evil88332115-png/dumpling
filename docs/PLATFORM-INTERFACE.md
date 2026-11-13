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
    [--markets DE,FR,…|EU-ALL|UNKNOWN] [--support-until YYYY-MM-DD] [--status development|shipped] \
    [--os-distro debian --os-release 13]        # 只在 --os-responsibility ours 時用
```
1. 跑上面的指令（專案名只能用小寫英數與連字號）；會從 `templates/project/` 與平台的 `project_defaults` 產生專案，
   `CRA/Config/` 的三個檔**不帶範本值**（D-055）：
   - `config.json` 只有 `tools/cra/config.schema.json` 的必填欄位（`schema_version`、`manufacturer.name`、`product.name`）。`product.name` 來自 `--product-name`（沒給用專案名）；`manufacturer.name` 來自 `--brand`，沒給是 `TO BE COMPLETED`；有給 `--support-until` 時另寫 `support.end_date`（YYYY-MM）。其他欄位都不寫，CRA 文件在這些欄位標 `TO BE COMPLETED`、文件至少 GAP（D-033 (4)）。`tools/cra/config.example.json` 只當結構參考，**不要整份複製**（它的值是虛構的 Example Co.、example.com…，留著會讓文件被判成完整）。產品自有軟體列在 `sbom.own_software`；真的沒有時寫 `"own_software": []` 加 `"own_software_none_reason": "<理由>"`（B-own-software 記 OK，說明寫理由）；兩個都沒寫 → B-own-software 與 SBOM 文件 GAP（沒有宣告自有軟體）。
   - `vex-rules.json` 是空規則（`{"schema": "sca-center-vex-rules/1", "rules": []}`）；要批次規則時自己寫（具名作者、真實日期與理由、規則審過的映像雜湊），範例見 `tools/cra/vex-rules.example.json`。
   - `inputs.json` 取自 `scan.inputs_template` 指到的精靈範本。
   不覆寫已存在的專案。`--markets EU`（舊值）會被拒絕，請用 `EU-ALL`。
2. 把 `project.yml`、`sources.yml` 裡值是 `TO BE COMPLETED` 的地方填完；`python3 -I pipeline/lib/project_config.py validate projects/<專案名>` 會列出還沒填的欄位。`status` 改成 `shipped` 之前不能有待填欄位。
3. 推上去。dev／release workflow 讀 `project.yml` 的 `platform`，打 tag `<專案>/<版本>` 就走 release。

## 3. project.yml 欄位（全部必填）

| 欄位 | 型別 | 對應《開案-CRA資訊表》 |
|---|---|---|
| `schema` | `1` | |
| `product_name` | 字串 | 產品名稱 |
| `brand` | 字串 | 品牌或客戶 |
| `company_role` | `manufacturer`｜`supplier`｜`both` | 公司角色 |
| `markets` | 字串清單（不可空）：會員國代碼，或單獨一個 `EU-ALL`／`UNKNOWN`，見 3.1 | 銷售市場 |
| `platform` | 字串，必須有 `pipeline/platforms/<platform>/platform.yml` | 平台 |
| `platform_version` | 字串 | 平台與版本 |
| `bsp_os_source` | 字串 | BSP／OS 來源 |
| `kernel_source` | 字串 | 核心來源 |
| `bootloader` | 字串 | 開機程式 |
| `own_software` | 字串清單（可空 `[]`） | 自有軟體 |
| `interfaces` | 字串清單（不可空） | 對外介面 |
| `support_until` | `YYYY-MM-DD`；**以它為準**，見 3.2 | 支援期限 |
| `status` | `development`｜`shipped` | 狀態 |
| `os_responsibility` | `ours`｜`customer`｜`upstream-vendor` | OS 層歸誰 |
| `os`（選填；`ours` 時 shipped 必填） | mapping：`distro`、`release`，見 3.3 | 我們自己的 OS |

`os_responsibility`（D-025、D-027）**由專案的角色與交付方式決定，不寫死在平台設定**。分層邏輯（L 軌）依它處理 `os` 層：
- `ours`：OS 層也是我們的待辦（例如自有品牌的 AI NAS），P1 判斷表含 OS 層。
- `customer`：OS 由客戶負責（例如 Jetson 範例 rootfs）：照掃、分開列，出現 KEV 時通知客戶，不進我們的修補待辦。
- `upstream-vendor`：上游 OS 廠商負責（例如只轉售 TrueNAS）：我們只通知客戶。
個別產品用哪一種由 PM 與法務判斷；資料模型支援三種。dispatcher 會把值放進環境變數 `DUMPLING_OS_RESPONSIBILITY`，`project-info.py` 也會輸出。

### 3.1 markets（銷售市場，D-055）

值是 ISO 3166-1 alpha-2 **大寫**代碼的清單，只收歐盟 27 個會員國（希臘是 `GR`，**不收**歐盟慣用的 `EL`；程式常數 `project_config.EU_MEMBER_CODES`）：

`AT` 奧地利、`BE` 比利時、`BG` 保加利亞、`HR` 克羅埃西亞、`CY` 賽普勒斯、`CZ` 捷克、`DK` 丹麥、`EE` 愛沙尼亞、`FI` 芬蘭、`FR` 法國、`DE` 德國、`GR` 希臘、`HU` 匈牙利、`IE` 愛爾蘭、`IT` 義大利、`LV` 拉脫維亞、`LT` 立陶宛、`LU` 盧森堡、`MT` 馬爾他、`NL` 荷蘭、`PL` 波蘭、`PT` 葡萄牙、`RO` 羅馬尼亞、`SK` 斯洛伐克、`SI` 斯洛維尼亞、`ES` 西班牙、`SE` 瑞典。

保留值（都必須**單獨**一個，不可和會員國代碼或彼此混在同一個清單）：
- `EU-ALL`：全歐盟上市。不展開成 27 國。
- `UNKNOWN`：**明確表示不知道**。允許（包含 `status: shipped`），但下游要標 GAP，不能當成「已填」。
- `TO BE COMPLETED`：**還沒填**（單獨一個）。和 `UNKNOWN` 不同：它是待填欄位，`status: shipped` 時是錯誤。

其他值（`EU-27`、小寫 `de`、`EL`、重複的代碼）一律是錯誤。

**舊值 `EU`**：驗證時把 `EU` 當成 `EU-ALL` 並發警告；**只在讀進來的資料結構裡遷移，不改寫 `project.yml`、不自動展開成 27 國**。請手動把檔案改成 `EU-ALL` 或列出會員國。`EU` 和其他值混用仍是錯誤。

**下游怎麼讀**（`load_project`／`load_project_all` 回傳的 dict）：
- `project["markets"]`：遷移後的清單（舊值 `EU` 已是 `["EU-ALL"]`）。
- `project["_markets_unknown"]`：`markets` 是 `["UNKNOWN"]` 時為 `True`。報告與第 14 條通報範本看到 `True` 要標 GAP（寫明「銷售市場不明，早期預警不能依會員國通知」），不可省略不提；`project-info.py` 同時輸出 `MARKETS_UNKNOWN=true|false`，並在 stderr 印一行 `GAP`。
- `project["_warnings"]`：警告字串清單（舊值 `EU` 已遷移、`config.json` 讀不了等）；`project-info.py` 與 `project_config.py validate` 把它印成 `WARN`。
- `project["_todo"]`：待填欄位清單（含 `markets` 是 `TO BE COMPLETED` 時）。
- 只想要警告而不拋例外的程式用 `check_project(doc)` → `(錯誤, 待填, 警告, 遷移後的 doc)`；`validate_project(doc)` 維持回傳 `(錯誤, 待填)`。

### 3.2 support_until 與產品名稱：以 project.yml 為準（D-055）

- `support_until` 在 `project.yml` 必填（`status: shipped` 時不可是 `TO BE COMPLETED`）。`CRA/Config/config.json` 的 `support.end_date`（YYYY-MM）由它產生：`new-project.sh` 開案時寫入 `support_until` 的年月。
- `product_name` 同理：`new-project.sh` 把它寫進 `config.json` 的 `product.name`。
- **一致性檢查**（`load_project` 做，所以 `platform.sh validate`、`project-info.py`、`sbom-layers.py`、`release-meta.py` 都會擋）：兩邊**都有值**（非缺、非空、非 `TO BE COMPLETED`）又不一致 → FAIL。`support_until` 比月份（`2031-12-31` 對 `2031-12`）；`product_name` 要完全相同。名稱用 FAIL 不用警告：名稱會原樣寫進 CRA 文件，警告在 CI 日誌裡沒人看，不一致的文件會被發出去；修法只是改 `config.json` 一行。任一邊沒填就不比（文件欄位標 `TO BE COMPLETED`）。
- 要改支援期限或名稱：改 `project.yml`，再把 `config.json` 改成一致。

### 3.3 os（我們自己的 OS，D-055）

`os_responsibility: ours`（例如 AI NAS）時用，放在 `project.yml` 的 `os:` 底下：

```yaml
os:
  distro: debian      # /etc/os-release 的 ID：小寫英數與 . _ -
  release: "13"       # /etc/os-release 的 VERSION_ID：一律是字串，要加引號（13 不加引號是數字，會被拒）
```
- `ours`：`status: shipped` 時兩個都必填（非空、格式合格）；`development` 時可以是 `TO BE COMPLETED`，也可以整個 `os:` 省略（記成待填 `os.distro`、`os.release`）。
- 其他歸屬（`customer`、`upstream-vendor`）：可省略；有寫就照上面格式驗證。
- `os` 下不認得的鍵是錯誤。`new-project.sh` 在 `ours` 時產生 `os:` 區塊（`--os-distro`、`--os-release`，沒給是 `TO BE COMPLETED`）。
- 下游（M8 的 OS 支援期限檢查）讀 `project["os"]["distro"]`、`project["os"]["release"]`。

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
- `platform_params.kernel_upstream_version`（選用）：核心的上游版本 X.Y.Z（每日監控的核心 CNA 比對用）。字串＝只有一顆 `kernel_release` 時那一顆的；多顆寫成 `{<kernel_release>: X.Y.Z}`。
  轉給 wizard 時每個一個 `--kernel-upstream-version <kernel_release>=<X.Y.Z>`，一路傳到 `kernel_versions.py --upstream-version`：和核心原始碼 Makefile 一致 → `upstream_basis` 是 `source-makefile+platform-param`；
  不一致 → 不採用任何一個（`upstream_version` 是 null，note 寫兩個值）。scan.sh 用 `python3 -I pipeline/project-info.py --kernel-args <專案資料夾> <版本>` 取得這兩種參數（一行一個；沒設定不印），
  格式不對 → 結束碼 1（sources.yml 驗證時就會報錯）。Jetson 的 `scan.sh` 是範例。
- **分層重跑要告訴 sca-scan 核心在哪份報告**（`--kernel-in-other-report <專案>-bsp`；詳見 `docs/LAYERS.md` §6）。核心永遠在 bsp 層，`-os` 層的 SBOM 沒有核心，
  但 sca-scan 的核心階段是從**映像**讀核心的，不看分層後的 SBOM：不告訴它，`-os` 報告會對映像裡的核心再判定一遍（Jetson 得 `C-kernel-cve-list`／`C-kernel-config`／`C-kernel-module-map` 三列假的 GAP；
  Raspberry Pi 型的 CNA 版本比對會「成功」，`-os` 報告多出約 2700 列合成的 linux-kernel 列，標 `synthetic:kernel-cna`）。**平台轉接器對 `scan_plan` 裡 bsp 以外的分層重跑（`-os`）都要給**
  `wiz "$suffix" --kernel-in-other-report "$DUMPLING_PROJECT-bsp" --rescan-from …`（wizard `cra-scan.py` 的選項，一路傳到 `scan-flash-package.sh`、`sca-scan`；後兩者另接受環境變數 `SCA_KERNEL_IN_OTHER_REPORT`，命令列優先）。
  `-bsp` 自己、完整掃描和 `ours` 的空後綴重跑（SBOM 是整個產品）**不給**：給 `-bsp` 等於指向自己，bsp 的 SBOM 偵測不到核心時（廠商核心不是套件）會把該做的核心判定（含 CNA 退回）壓掉，sca-scan 對「名稱等於自己的 `--name`」以 exit 64 拒絕。給了也只有「SBOM 真的沒有核心」（kernelcheck 的 NOT_RUN）才生效。
  不能只由「SBOM 沒有核心」推定：單一 SBOM 的廠商核心（不是套件）要走 CNA 版本比對。名稱只接受 `^[A-Za-z0-9][A-Za-z0-9._+-]{0,99}$`，否則 exit 64。Jetson 的 `scan.sh` 是範例。
- **宣告核心不是發行版的核心**（`kernel_not_distro`，選用）。Grype、DT 對 Debian／Ubuntu 套件是用發行版的原始碼套件與版本字串比對；核心若不是發行版建的（廠商 BSP 核心的 deb、Raspberry Pi、Radxa），這個比對不可靠，
  而且是漏報的方向（例如 `1:6.18.50-1+rpt1` 因為 epoch，被當成比 Debian 6.12.x 的任何修補都新，Debian 修好的 CVE 全算已修好，只剩 Debian 尚未修的）。所以 `C-kernel-coverage` 在這種核心上是 GAP，
  即使 Grype 對核心有比對；核心 CVE 要改以上游版本對核心 CNA（尚未實作，見 M7）。
  - 自動判斷（`tools/pilot/lib/kernelcheck.py`，只看 deb 核心套件；規則是**或**：任何一條成立就是，沒有一條能取消另一條，所有成立的原因都寫進 `scan/kernel-coverage.json` 的 `off_series`）：
    - a. 版本的 epoch ≥ 1（`1:6.18.50-1`；解析成整數，`0:` 等於沒有 epoch，不算）。Debian、Ubuntu 自己的 `linux` 不用 epoch。
    - b. 版本含已知的廠商後綴 `+rpt`、`+rpi`（不分大小寫，上游部分或 Debian revision 都算），或套件名稱含 `+rpt`、`-rpt-`。清單與理由在 `kernelcheck.py` 的 `VENDOR_LOCAL_SUFFIXES`、`VENDOR_NAME_MARKERS`。
    - c. 明確宣告：下面的 `kernel_not_distro`。
    - d. purl 的 `upstream=`（來源套件，先 URL 解碼，`name@version` 取名稱）：`linux-upstream`（核心自己 `make deb-pkg` 的預設來源名稱）一律算；`distro=debian-*` 而且來源不在 Debian 建核心的來源清單（`linux`、`linux-latest`、`linux-signed-amd64`／`-arm64`／`-i386`）也算；
       `distro=ubuntu-*` **不**看其他 `linux-<flavor>` 來源（`linux-nvidia-tegra`、`linux-raspi`、`linux-aws`… 都是 Canonical 的核心）。清單與出處在 `tools/pilot/lib/data/distro-kernel-sources.json`；檔案讀不到或格式不對 → `C-kernel-coverage` FAIL，不當作沒有問題。
    - 名稱與版本取 SBOM 元件的欄位與 purl 兩邊（purl 先解碼），任何一邊成立就算。`nvidia-l4t-kernel*`（NVIDIA 的核心套件，經 `C-kernel-l4t-map` 對應 Canonical 核心比對）和 Canonical 的 Tegra 核心不會被標，Jetson 不受影響。
  - **自動規則抓不到的**（要用 `kernel_not_distro` 宣告）：廠商核心 deb 的版本與名稱都長得像 Debian／Ubuntu（沒有 epoch、沒有 `+rpt`／`+rpi`），而且 purl 沒有 `upstream=`／`distro=` 限定詞，或限定詞也像發行版
    （例如把來源套件命名成 `linux` 的廠商）；非 deb 的核心（rpm、apk、Yocto 的 `linux-kernel` 元件、沒有套件的廠商核心）；後綴不在清單裡的廠商（例如其他 SoC 廠商的 `+vendor1` 後綴）或不是 `+` 的寫法（`~rpt`、`.rpt`）；`distro=` 不是 Debian（例如 `raspbian-*`）而來源套件是自訂名稱、或 purl 只有 `upstream=` 沒有 `distro=`；套件名稱不在核心套件清單（`KERNEL_PACKAGE_PATTERNS`）裡，連「SBOM 有核心」都偵測不到的套件（例如 `raspberrypi-kernel`）。這些規則抓得到已知的樣子，抓不到不代表核心是發行版的。
  - 宣告：`sources.yml` 的 `releases.<版本>.platform_params.kernel_not_distro: "<理由>"`，或 `platform.yml` 的 `scan.kernel_not_distro: "<理由>"`（該平台所有專案、所有版本的預設；版本的值取代平台的預設）。理由字串非空、沒有控制字元、不以 `-` 開頭（精靈會當成選項）、最多 300 位元組。
    `project-info.py --kernel-args` 轉成 `--kernel-not-distro <理由>`（一行一個參數；理由不能是空的、不能有換行或控制字元、最多 300 位元組，否則 sources.yml／platform.yml 驗證就報錯），
    wizard → `scan-flash-package.sh` → `sca-scan` 一路傳（後兩者另接受 `SCA_KERNEL_NOT_DISTRO`）。SBOM 有核心時 `C-kernel-coverage` 是 GAP，說明寫出理由；SBOM 沒有核心（例如 `-os` 層）時照舊不寫這一列。Jetson 不設。

## 5. 平台轉接器

`pipeline/platform.sh <步驟> <專案資料夾> <版本> [--out <資料夾>]`，步驟：

| 步驟 | 說明 |
|---|---|
| `validate` | 驗證 project.yml、sources.yml、平台設定；不做別的 |
| `fetch` | 共用：讀 sources.yml 下載核對到 `$DUMPLING_OUT/downloads/`。轉接器可提供 `fetch.sh` 覆寫 |
| `build` | 平台各自（`build.sh`）。不編譯的平台（`build.mode: none`）整個 build job 略過，scan job 記 `pipeline-build NOT_RUN 4`，說明以「不適用」開頭、列尾帶 `recorded`（不是 OK；這一類 NOT_RUN 不降低 pipeline_result。其他 NOT_RUN，例如平台沒有實作某一步、結束碼 4，pipeline_result 降成 GAP） |
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
轉接器腳本收到位置參數 `<專案資料夾> <版本>` 與環境變數：`DUMPLING_ROOT`、`DUMPLING_PROJECT`、`DUMPLING_PROJECT_DIR`、`DUMPLING_VERSION`、`DUMPLING_PLATFORM`、`DUMPLING_PLATFORM_DIR`、`DUMPLING_OS_RESPONSIBILITY`、`DUMPLING_ARCH`（platform.yml 的 `arch`，預設 `arm64`）、`DUMPLING_OUT`（預設 `$DUMPLING_OUT_BASE` 或 `<repo>/out` 底下的 `<專案>/<版本>/`）、`DUMPLING_SUPPORT_UNTIL`（project.yml 的 `support_until`，YYYY-MM-DD；還沒填是空字串）。

**精靈對產品設定包複本做的事（D-039、D-055；原始的 `CRA/Config/` 不動）**：`product.version` 改成這次的版本（沒寫就填入）；有刷機包時 `product.identification` 改成這次的刷機包（沒寫而且有 MD5 就填入 `Flash package <檔名> (MD5 <md5>)`）；`support.end_date` 沒寫時由 `DUMPLING_SUPPORT_UNTIL` 產生（YYYY-MM），已寫而月份不同 → ATTENTION（project.yml 的一致性檢查會先 FAIL）。`platform_scan.collect` 之後核對每份報告設定包的 `product.version`（去掉 ` (rootfs)` 這類非版本後綴）等於 Release tag 的版本，不一致 → scan 步驟 FAIL，結果在 scan.json 的 `product_version_check`；`release-meta.py --tag` 也要等於 `<專案>/<版本>`。notes.md 開頭的 pipeline_result 由 `release-meta.py --notes` 依同一份 pipeline-steps.tsv 重寫，和 release-meta.json 一致。sbom.md 第 6 節的 BSP 說明依 list.json 的平台寫，非 Jetson 平台不出現 Jetson Linux 的文字。`DUMPLING_PLATFORMS_DIR` 可換掉轉接器根目錄（測試用）。

**平台一律由 project.yml 明確給定、一路傳到 scan，不從映像格式推測**：`scan.sh` 要把 `$DUMPLING_SCAN_PLATFORM_ARG` 原樣傳給 `tools/demo/scan-flash-package.sh --platform` 與 `tools/wizard/cra-scan.py --platform`（`pipeline/platform.sh` 匯出：平台設定的 `scan.platform_arg`，沒寫就是平台名稱；必須是工具認得的 jetson／raspberrypi／rockchip／generic，否則平台設定驗證就失敗）。沒給平台時，原始磁碟映像的開機程式分類標 GAP（「沒有指定平台，不推測」），不會預設成 Raspberry Pi。

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
- **Release 附件命名**（機器可讀，給每日監控讀）：`sbom-<專案>-<版本>.cdx.json`（完整、標好層）、`sbom-<專案>-<版本>-bsp.cdx.json`、`-os.cdx.json`、`layers.json`、`kernel-versions-<專案>-<版本>.json`（映像出貨的核心、有沒有判定、上游版本；完整掃描那次 sca-scan 的 `scan/kernel-versions.json`，有才附）、`release-meta.json`
  （`project`、`version`、`tag`、`status`、`platform`、`os_responsibility`、`commit`、`built_at`、`workflow_run`、`report_status`、`release_gate`、`pipeline_result`、`reports`、`kernel_versions`；由 `pipeline/release-meta.py` 產生）。
- **release-meta.json 的四個狀態欄位不要混用**：
  - `status`：**生命週期**（project.yml 的 `shipped`｜`development`），**不是掃描結論**。
  - `report_status`：**產品結論**＝報告（cra_report `summary.json`）的整體狀態；分層時每份報告（完整、bsp、os）各一個，列在 `reports`，這裡取最差的那份。
  - `release_gate`：VEX 發行閘門（`summary.json` 的 `vex.gate.verdict`），同樣取最差的那份。
  - `pipeline_result`：workflow 各步驟的結果（`pipeline-steps.tsv`），只代表流程有沒有跑完，**不是產品結論**。
  - 值的範圍 `OK`｜`ATTENTION`｜`NOT_RUN`｜`GAP`｜`NOT_ASSESSED`｜`FAIL`；缺檔、讀不到、值不認得 → `NOT_RUN`，不留空。Release 說明（notes.md）開頭依序印 report_status、release_gate、pipeline_result。
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
  tools: sbom-only             # 選填：sbom-only（預設）｜full（見下表）
  kernel_not_distro: "<理由>"  # 選填：宣告這個平台的核心不是發行版的核心（見 §4 sources.yml 的 `kernel_not_distro`）；Jetson 不設
  inputs_template: jetson      # tools/wizard/platforms/<名稱>.json，new-project.sh 複製成 CRA/Config/inputs.json
  platform_arg: jetson         # 傳給掃描工具的 --platform（DUMPLING_SCAN_PLATFORM_ARG）；沒寫＝平台名稱；只能是 jetson／raspberrypi／rockchip／generic
  rootfs: rootfs               # 目前只能是 rootfs（scan.sh 與 platform_scan 固定用這個名稱）；其他值驗證失敗
project_defaults:              # 選填：new-project.sh 帶入 project.yml／sources.yml 的預設值
  platform_version: …  bsp_os_source: …  kernel_source: …  bootloader: …
  own_software: []  interfaces: […]  platform_params: {}
```
**workflow 怎麼用這些欄位**（`pipeline.yml` 的 `plan` job 讀 `pipeline/project-info.py` 的輸出 `BUILD_MODE`、`BUILD_RUNNER`、`BUILD_APT`、`SCAN_RUNNER`、`SCAN_APT`、`SCAN_TOOLS`、`ARCH`）：

| 欄位 | 預設 | 作用 |
|---|---|---|
| `arch` | `arm64` | 目標映像的架構；scan 用 `docker import --platform linux/<arch>`（`DUMPLING_ARCH`／`SCA_ARCH`） |
| `build.mode` | （必填） | `none`：整個 build job 略過（`if:` 為 false），scan job 照樣跑、不下載任何 build artifact。`compile`：build job 跑，runner 與 apt 取下面兩欄 |
| `build.runner` | `arm64` | build job 的 runner：`arm64`＝`ubuntu-24.04-arm`、`amd64`＝`ubuntu-24.04` |
| `build.apt` | `[]` | build job 的 apt 相依 |
| `scan.runner` | `amd64` | scan job 的 runner（`amd64`＝`ubuntu-24.04`）。**不跟著 `arch`**：scan 只匯入與讀映像，不執行目標平台的程式，所以 runner 的架構和映像的架構無關。目前只支援 amd64（`tools/e2e/install-tools.sh` 只裝 amd64 的 Syft／Grype） |
| `scan.tools` | `sbom-only` | scan job 裝哪套掃描工具：`sbom-only`＝Syft、Grype、bubblewrap（`install-tools.sh --sbom-only`）；`full`＝`install-tools.sh` 不帶旗標（Syft、Grype、cdxgen、govulncheck、guarddog、bubblewrap，版本都固定在 `install-tools.sh`）。**不分項**：git／dir 模式的 sca-scan（A-tools）檢查整套工具的版本，只裝一部分會回 ATTENTION 或 FAIL。`full` 裝在 `/opt/dumpling-tools`（沙箱只遮蔽家目錄與 runner 目錄），guarddog 在 `/usr/local/bin` 是符號連結指向 `/opt` 底下的 venv；裝完用家目錄遮蔽的 bwrap 確認每個工具看得到。其他值：`project-info.py`／`platform.sh validate` 結束碼 64。實作 `pipeline/install-scan-tools.sh` |
| `scan.kernel_not_distro` | （不設） | 理由字串（非空、沒有控制字元、不以 `-` 開頭、最多 300 位元組）。該平台所有專案、所有版本的預設，宣告核心不是發行版的核心（`C-kernel-coverage` GAP）；`sources.yml` 的 `platform_params.kernel_not_distro` 優先。經 `project-info.py --kernel-args` 轉成精靈的 `--kernel-not-distro`，詳見 §4 sources.yml 的 `kernel_not_distro` |
| `scan.apt` | `[]` | scan job 額外的 apt 套件（bubblewrap、python3-yaml 由 workflow 固定裝） |

**步驟的結束碼規則與紀錄**（`pipeline/run-step.sh <步驟> <專案資料夾> <版本>`，workflow 所有 `platform.sh` 呼叫的唯一入口；`--record <專案資料夾> <版本> <步驟> <狀態> <結束碼> <說明>` 只記一列）：

| 結束碼 | 狀態 | 行為 |
|---|---|---|
| 0 | OK | 繼續 |
| 3 | GAP | 印 `::warning::`，繼續（結果照樣產生，但整體狀態不是 OK） |
| 4 | NOT_RUN | 印 `::notice::`，繼續（不能當成成功；照實列出） |
| 1、64 或其他 | FAIL | job 失敗 |

每一步在 `$DUMPLING_OUT/pipeline-steps.tsv` 加一列 `pipeline-<步驟>	<OK|ATTENTION|GAP|NOT_RUN|FAIL>	<結束碼>	<最後一行輸出>`。compile 的 build job 把這個檔和 `handoff/` 放進同一個 artifact（它不在 `handoff/` 裡，`handoff/` 屬於 `build.sh`），
scan job 還原後接著寫自己的列；`build.mode: none` 時 scan job 寫 `pipeline-build	NOT_RUN	4	不適用：build.mode: none（這個平台不編譯）	recorded`（`run-step.sh --record` 寫，列尾多一欄 `recorded`）。
`platform_scan.collect` 把這些列放進 `summary.md`、Release 說明（notes.md）、scan.json 的 `pipeline_steps`／`pipeline_status`；`release-meta.json` 多 `steps` 與 `pipeline_result`（`OK`｜`ATTENTION`｜`GAP`｜`FAIL`；沒給步驟檔是 `NOT_RUN`；有 FAIL 是 FAIL、有 GAP 或沒能執行的 NOT_RUN 至少 GAP、只有 ATTENTION 是 ATTENTION；有 ATTENTION 列時另有 `attention`＝那幾行說明；
`status` 仍是 project.yml 的 shipped／development）；`pipeline/scan-status-check.py --pipeline-steps` 也會看。所以平台的 scan 沒去讀 `raw-sectors.json` 之類的檔案，GAP 也不會消失。NOT_RUN 分兩類（`pipeline/lib/step_rows.py`）：workflow 用 `run-step.sh --record` 記的列（列尾多一欄 `recorded`）且說明以「不適用」開頭＝本來就不該做（目前只有 build.mode 不是 compile 的那一列），不降低整體狀態；其他 NOT_RUN（結束碼 4，例如平台沒有實作這一步）＝該做卻沒做，整體降成 GAP。平台腳本沒辦法自己宣告「不適用」：結束碼 4 的最後一行就算以「不適用」開頭，也照樣是 GAP（最後一行仍照規則寫 `<步驟>: NOT_RUN（…）`）。**這裡只處理 workflow 步驟層；掃描層（sca-scan、cra_report 的階段，例如核心階段的 NOT_RUN）見下一個 PR。**
手動觸發（workflow_dispatch）只建 draft；push tag 建正式 Release（`--verify-tag`）。**GAP 不擋正式 Release**：scan 回 3（GAP）時 `run-step.sh` 記一列、以 0 繼續，Release 照樣發，結論寫在 `release-meta.json` 的 `report_status`／`release_gate`／`pipeline_result` 與 Release 說明開頭（D-033：資料缺口照實標示，不靠擋發佈）。只有 FAIL（1、64 或其他）讓 job 失敗、不發 Release。

**ATTENTION 與弱點資料鏡像的共用函式**：ATTENTION＝這一步完成了，但用了舊資料頂替；整體狀態不是 OK、比 GAP 輕（FAIL > GAP > ATTENTION > OK），只由 `pipeline/lib/mirrors.sh` 寫。
所有平台的 scan 都 `source pipeline/lib/mirrors.sh`，用 `mirror <tools/mirror 底下的腳本> <資料夾名>`（不要各寫一份）；`mirror_kernel_cve <名>` 會把上一份核心 CVE 鏡像（`$KCVE_CACHE_DIR`）傳給 `kernel-cve.sh` 的 `KERNEL_CVE_REUSE_FROM`（上游 HEAD 沒變就沿用）與 `KERNEL_CVE_FALLBACK_FROM`（上游連不上就退而求其次）。
結果看腳本輸出的最後一行：`OK …` 成功；`ATTENTION …` 也算成功，並在 `pipeline-steps.tsv` 加 `pipeline-<腳本名>-mirror	ATTENTION	0	<那一行>`（例如 `pipeline-kernel-cve-mirror`）；其他 = 這一次失敗，重試（預設 3 次、每次換新資料夾、間隔 60 秒），仍失敗 = `mirror` 回傳 1，呼叫端 FAIL。
scan job 用 `actions/cache/restore`／`save`（釘 commit SHA）保存 `kcve/`（kernel-cves.zip、SOURCE，幾十 MB；不存 git clone）：key `kernel-cve-mirror-<run_id>-<run_attempt>`、`restore-keys: kernel-cve-mirror-`；還原與儲存用同一個路徑（cache 的版本含路徑）。
**只有這次新抓的才存**（結果 OK 且 SOURCE 沒有 `fallback=yes`）；沿用或頂替的舊資料不存回去，免得舊資料被當成新的。
**Release 決定（D-033 一致）**：ATTENTION 不擋 Release，正式 tag 也一樣；但 Release 說明最上面會有「ATTENTION（用了舊資料頂替）」區塊與那一行原文，`summary.md`、`scan.json`（`pipeline_attention`）、`release-meta.json`（`pipeline_result`、`attention`）都看得到。

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
