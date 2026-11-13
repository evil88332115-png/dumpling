> **公開版說明**：本檔是規劃原稿的公開版。內部產品代號、使用者本機路徑已移除或換成變數（`$REPO_MAIN`、`$AGENT_TMP`、`$PUBLIC_IMAGES`、`$HEAVY_LOCK`），變數值在本機 `~/.config/dumpling/local.env`，不進 repo。其他內容與原稿相同；之後的修改一律記在 `docs/DECISIONS.md`。

# 規劃：`dumpling`——可執行的 CRA 自動化掃描流程（公開 GitHub 版，之後搬到內部 GitLab）

## Context（為什麼做）

- **CRA 要求**：
  - 每個上市產品要有 SBOM（附件 I 第二部分 (1)）。
  - 要持續處理漏洞（同部分 (2)）。
  - 已被利用的漏洞，要在 24／72 小時內通報（第 14 條）。
  - 紀錄要保存 10 年。
- **現況**：CRA掃描 每一版都人工收檔、手動跑精靈，常見問題都出在人工交接（例如建置紀錄漏打包、刷機包裡的核心不一致、rootfs 選錯）。
- **使用者定的方向**（使用者本機文件《CRA自動化掃描-GitLab流程-規劃-20261112》）：
  1. RD 上傳原始碼，出貨時打 tag。
  2. runner 編譯＋掃描。
  3. 結果進 DT。
  4. 有 KEV 就通知 RD。
  5. 新專案的開案設定也上 git，開發中就開始監控。
- **這次要做「真的能跑」的版本**：
  - 先在使用者的**公開** GitHub repo `dumpling` 用**公開資料**做好、驗證好。
  - 之後直接搬到內部 GitLab，換成公司產品。
  - 範圍：Jetson BSP 的 git 流程、mini PC 的 BIOS 與 vBIOS、顯示卡的 vBIOS。**不含顯示卡驅動程式**（使用者 11-12 更正：需求裡的 GPU binary 指的是 vBIOS）。
- 新對話會開在新資料夾，不會載入 sca-center 的專案記憶，所以**這份規劃要能獨立照做**。

## 硬性限制

1. **不用任何公司資料**。只用公開 BSP，以及公開的 BIOS、vBIOS 檔。repo、Actions 執行紀錄、Issue、Release 全都是公開的。
2. **只用 GitHub 內建 runner**（ubuntu-24.04）。
   - 規格：4 vCPU、16 GB RAM、清理後約 30 GB 磁碟、每個 job 最長 6 小時、可以 sudo、有 Docker。
   - 公開 repo 用內建 runner 不扣額度。
   - 公開 repo **不接自架 runner**，因為任何人開 PR 都能在那台機器上跑程式。
3. **二進位檔不進 git**。BSP、BIOS、vBIOS 一律在 CI 裡從官方網址下載，並核對固定的 sha256。
4. **下載的檔案一律當不可信資料**：只解開、不執行，Python 用 `-I`。
5. **狀態**：缺資料、沒跑、過期，一律標 GAP、NOT_RUN 或 NOT_ASSESSED，不顯示「安全」或整體 PASS。
6. **開發規則**：
   - 寫程式的代理和驗證的代理要分開。
   - 推送一律開分支、發 PR。
   - 審查通過且 CI 綠燈才合併。
   - 版本固定，不 force-push。

## GitHub Actions 的實際限制（2026-11-12 查官方文件）

| 限制 | 數值 | 對策 |
|---|---|---|
| 費用 | 公開 repo 的標準 runner「免費且不限用量」 | — |
| 每個 job 最長 | 6 小時 | 編譯、掃描、韌體分成不同 job；Jetson 編譯＋掃描預估 1.5–3 小時 |
| 同時執行的 job | Free 方案 20 個 | 夠用 |
| runner 規格 | x64 與 arm64（`ubuntu-24.04-arm`）都是 4 CPU、16 GB RAM、**14 GB SSD** | **磁碟最緊**：Jetson 流程要約 20 GB 暫存 → 開頭刪掉預裝工具（約可再騰出 30 GB，sca-center 現有 workflow 已這樣做）；核心編譯改用 arm64 runner 原生編譯，不用交叉工具鏈 |
| Actions 產出物空間 | Free 方案 500 MB（文件列出的配額） | 報告、SBOM 放 **GitHub Release**（tag 版），產出物只放小檔、短期保存 |
| 產出物／紀錄保存 | 公開 repo 最多 90 天 | 長期紀錄靠 Release；10 年保存是內部 GitLab 階段的事 |
| 快取 | 每個 repo 10 GB | 快取 Grype DB、BSP 下載檔（超過就重新下載） |
| GITHUB_TOKEN API | 每小時 1,000 次 | 開 Issue、建 Release 用量很小 |
| **排程工作會被自動停用** | 公開 repo 60 天沒有活動，排程（每日監控）會被關掉 | 每日監控把結果提交到 repo（例如 `status/watch-latest.json`），保持有活動；並在 STATUS 寫明要檢查 |
| 執行紀錄公開 | 任何人看得到 | 只用公開資料；禁用字檢查 job |
| 沒有常駐服務 | runner 每次都是全新的 | DT 每個 job 臨時開；常駐 DT 是 GitLab 階段 |

## 決定（使用者跳過提問，先採建議值；確認規劃時可改）

1. **工具程式碼**：從 sca-center 挑出需要的檔案，清乾淨後複製進 dumpling。
   - 要拿掉的：產品名（內部產品代號，清單只放本機）、內部 IP、主機名、本機掛載路徑、個人信箱。
   - 不帶 git 歷史，不帶 `tests/results/`、`CLAUDE.md`、`AGENTS.md`、`tasks/`。
   - 每個檔案在 `docs/PROVENANCE.md` 記錄它的來源 commit。
2. **協調對話**：新開一個，跟工作對話一樣開在 dumpling 資料夾。目前這個對話回去做 sca-center。
3. **CI 編譯**：在 CI 裡從公開原始碼編核心和樹外模組，建置紀錄由 CI 產生。UEFI 先用 BSP 內建的成品，標註「UEFI 未自編」，之後再補。
4. **授權**：Apache-2.0。
5. **repo**：`evil88332115-png/dumpling`，設為公開。開 repo 和設成公開由協調對話執行；使用者已經同意公開。

## 可以沿用的東西（sca-center，origin/main 25fa89a）

| 用途 | 檔案 |
|---|---|
| 下載公開 Jetson BSP 和範例 rootfs、合併 L4T 套件（不執行內容） | `scripts/demo/jetson.sh`、`scripts/demo/jetson_rootfs.py`（下載約 3.3 GB、暫存約 20 GB） |
| 打包建置紀錄 | `scripts/demo/pack-build-record.sh`（支援 `--uefi`） |
| 安裝工具（固定版本 Syft 1.55.0、Grype 0.121.0，含 bwrap、userns 設定） | `scripts/e2e/install-tools.sh`、`scripts/e2e/sandbox.sh` |
| 掃描主流程 | `scripts/wizard/cra-scan.py` → `scripts/demo/scan-flash-package.sh` → `scripts/pilot/sca-scan` → `scripts/cra/cra_report.py` → `scripts/cra/report_package.py` |
| 臨時 DT（apiserver＋Postgres，只開 OSV） | `scripts/e2e/dt-compose.yaml`、`scripts/e2e/dtlib.sh`；workflow 範本參考 `.github/workflows/e2e-pilot.yml` |
| 資料鏡像（都能在 CI 跑） | `scripts/mirror/grype-db.sh`、`nvidia-bulletins.sh`、`euvd.sh`、`kernel-cve.sh`、`osv-distro.sh`、`ubuntu-cve-status.sh`（大小與時間見 `docs/offline-mirrors.md`） |
| OP-TEE／TF-A、上游比對、開機核心檢查 | `scripts/cra/tee_source.py`、`tee_bundled.py`、`upstream_baseline.py`、`scripts/pilot/lib/kernel_boot.py` |
| BIOS／vBIOS 盤點 | `scripts/cra/x86_firmware.py`：讀 Intel flash 描述區、CSME、微碼、FIT、IBV 字串、NVIDIA option ROM 版本。目前沒接進報告，元件也沒有 purl／CPE |
| UEFI 解析 | `scripts/cra/uefi_image.py`（FV／FFS／LZMA、OpenSSL／Mbed TLS 指紋）；原始碼面用 `uefi_source.py`、`uefi_bundled.py` |
| BIOS 試掃原型（CBFS、SELF、FSP、FV＋LZMA、路徑核對） | `$AGENT_TMP/bios-eval/scripts/`；結果見 `$PUBLIC_IMAGES/bios/BIOS-公開範例試掃-20261111.md` |
| NVIDIA 公告 | `scripts/mirror/nvidia-bulletins.sh`、`scripts/pilot/lib/nvidia_bulletins.py`（`gpu-firmware` 群組還沒有比對表；`gpu-driver` 群組不在範圍內） |
| 外部 SBOM 匯入 | `scripts/pilot/sca-scan --sbom` |
| 每日監控、廠商層級 KEV | `scripts/cra/exploited_watch.py`、`scripts/cra/exploited_vendor.py`、`deploy/exploited-watch/vendor-watch.example.json` |
| GitLab 既有基礎 | `ci/gitlab/sca-center.gitlab-ci.yml`、`deploy/gitlab-runner/`、`deploy/gitlab-bot/` |

**已知卡點**
- 沒有 DT，CRA 報告就沒有漏洞列（`cra_report.py` 約第 4200、4458 行）。解法：每個掃描 job 都開一個臨時 DT（OSV＋CISA KEV，不開 NVD，因為 NVD 第一次同步要 1–3 小時）。
- 精靈一定要 `PILOT_ENV`。寫死的路徑都有覆寫方式：`--out`、`PILOT_ENV`、`--no-company`、`SCA_TOOLS_DIR`、`MIRROR_REFRESH_STATUS=""`。CI 裡要產生站台設定檔（`SCA_WIZARD_CONFIG`）。
- 公開 BSP 的 `rootfs/` 是空的，要用範例 rootfs 補上（`jetson_rootfs.py`）。

## 架構與 repo 結構

```
dumpling/
├── LICENSE（Apache-2.0）  README.md
├── docs/  PLAN.md（本規劃）  STATUS.md（各工作包進度）  DECISIONS.md  PROVENANCE.md  GITLAB-PORT.md
├── tools/                 ← 從 sca-center 清理後複製的工具（掃描、報告、韌體、監控）
├── pipeline/              ← dumpling 自己的串接腳本（每段一個指令，印一行狀態）
│   ├── jetson-build.sh    （下載公開原始碼、套 patch、交叉編譯核心＋樹外模組、打包建置紀錄、組刷機包）
│   ├── jetson-scan.sh     （產生站台設定、開臨時 DT、跑精靈、收報告）
│   ├── firmware-bios.sh   firmware-vbios.sh
│   └── dt-ephemeral.sh    （開／關臨時 DT，輸出 pilot.env）
├── templates/project/     ← 開案範本（new-project.sh 用）
├── pipeline/platforms/    ← jetson／raspberrypi／rockchip／ai-nas 轉接器（fetch／build／assemble／scan）
├── projects/              ← 一個產品一個資料夾（＝開案資訊表的機器可讀版）
│   └── orin-nano-demo/
│       ├── project.yml    （平台、L4T 版本、狀態 development／shipped、支援期限、角色）
│       ├── sources.yml    （公開原始碼與 BSP 的網址＋sha256）
│       ├── patches/       （模擬 RD 的修改，例如把上游的 CVE 修補 backport 進來）
│       └── CRA/Config/    （設定包：config.json、inputs.json、vex-rules.json）
├── firmware/              ← bios/<型號>/firmware.yml、vbios/<型號>/firmware.yml（公開檔網址＋sha256、廠商、型號）
├── sboms/                 ← 已出貨版本的 SBOM（公開資料才可提交），給每日監控用
└── .github/workflows/
    ├── release.yml        （tag `<專案>/<版本>` → 編譯 → 掃描 → Release 附報告）
    ├── dev.yml            （開發分支 push＋每日 → 編譯＋掃描，不發 Release）
    ├── firmware.yml       （firmware/ 有變動時，或手動觸發）
    ├── watch.yml          （每日 KEV／EUVD＋廠商層級提醒 → 開 GitHub Issue）
    └── tests.yml
```

## 開案範本與平台介面（使用者 11-12 追加：不只 Jetson）

目標：**之後新增專案不是問題**。git 流程要能涵蓋 Jetson、Raspberry Pi、Rockchip、AI NAS，以後再有新平台也照同一套做。做法是「一份開案範本＋每個平台一個轉接器」。

**1. 開案範本（`templates/project/`＋`pipeline/new-project.sh`）**
- `new-project.sh <專案名> --platform <平台>`：從範本產生 `projects/<專案名>/`，欄位對應《開案-CRA資訊表》：產品名稱、品牌或客戶、公司角色、銷售市場、平台與版本、BSP／OS 來源、核心來源、開機程式、自有軟體、對外介面、支援期限、狀態（development／shipped）。
- 產生的檔案：`project.yml`（上面的欄位）、`sources.yml`（原始碼與成品的網址＋sha256）、`patches/`、`CRA/Config/`（設定包，從平台預設值帶入）。
- 開案時就能跑：`dev.yml` 讀 `project.yml` 的 `platform` 欄位，自動選對應的轉接器；打 tag 就走 `release.yml`。新增專案＝執行一次 `new-project.sh`＋填欄位＋推上去，不用改 workflow。

**2. 平台轉接器（`pipeline/platforms/<平台>/`），每個都實作同樣 4 個步驟**

| 步驟 | 介面 | 說明 |
|---|---|---|
| `fetch` | 讀 `sources.yml`，下載並核對 sha256 | 共用 |
| `build` | 編核心（＋樹外模組／開機程式），產生建置紀錄 | 平台各自不同；可標「不編譯」 |
| `assemble` | 組出產品映像（刷機包、SD 卡映像、update.img、ISO） | 平台各自不同 |
| `scan` | 呼叫共用掃描（精靈＋臨時 DT＋報告），帶入平台設定 | 共用；平台只提供設定（BSP／OS 怎麼分層、要跑哪些韌體檢查） |

**3. 第一批平台與公開示範專案**

| 平台 | 公開示範資料 | 掃描重點 | sca-center 現有支援 |
|---|---|---|---|
| Jetson | NVIDIA L4T r39.2.x 公開 BSP＋原始碼＋範例 rootfs | 見下方「BSP 掃描範圍」 | 完整（`platforms/jetson.json`） |
| Raspberry Pi | Raspberry Pi OS Lite 公開映像＋`raspberrypi/linux` 核心原始碼 | 核心、開機韌體（`start*.elf`、`bootcode`）、rootfs | 映像格式已支援（#201）、`platforms/raspberrypi.json` 草稿 |
| Rockchip | 公開的 Rockchip 開發板映像（例如 Radxa／Armbian 的公開映像）＋對應核心原始碼 | 核心、U-Boot、TF-A／OP-TEE（trust 映像）、閉源 DDR 初始化／miniloader（標 GAP） | RKFW／update.img 已支援、`platforms/rockchip.json` 草稿 |
| AI NAS（x86，Debian 系） | 公開的 Debian 系 NAS 系統映像（例如 OpenMediaVault）或 Debian trixie amd64 映像 | **整個 OS 和應用都算我們的**（自有品牌時公司是製造商）：Debian 套件、核心（Debian 修補紀錄）、NAS 網頁介面與 App 的原始碼（用 cdxgen 掃原始碼與相依套件） | 映像與 rootfs 掃描可用；原始碼掃描（cdxgen）在 sca-center 已有 |

- AI NAS 跟 BSP 不同：它不是交給客戶自己燒 OS 的板子，OS 層本身就是產品，**分層時 OS 也算我們的待辦**（由 `project.yml` 的角色與交付方式決定，不是寫死）。
- 每個平台的「哪些算 bsp、哪些算 os」寫在平台設定裡，報告依此分層。

## BSP 掃描範圍（使用者要求先定義）

實測顯示主要工作量在核心判斷與人工交接，不在 rootfs（rootfs 打包與掃描很快、漏洞列以核心為大宗）。

**BSP 層（我們負責、必掃、算待辦）**

| 部分 | 掃什麼 | 用什麼 |
|---|---|---|
| 核心 | 版本、出貨核心內建設定（IKCONFIG）、建置紀錄（CI 產生）、K1 判斷、開機核心檢查 | `kernel_config.py`、`kernel_boot.py`、核心 CNA 鏡像、linux-stable |
| 樹外模組（nvidia-oot、nvgpu、nvdisplay、hwpm、nvethernetrm…） | 建置紀錄、模組身分（srcversion／ELF 區段） | 同上 |
| device tree | 跟上游比對，列出我們改的部分（目前沒有 CVE 資料，只記身分） | `upstream_baseline.py` |
| 開機程式：UEFI（edk2-nvidia） | 版本、內建 OpenSSL／Mbed TLS、平台設定（config.dsc.inc） | `uefi_source.py`、`uefi_image.py`、`uefi_bundled.py` |
| OP-TEE／TF-A | 版本與內建 Mbed TLS | `tee_source.py`、`tee_bundled.py` |
| NVIDIA 閉源韌體（MB1／MB2／BPMP／SPE…） | 跟 NVIDIA 原版逐檔比對（身分），NVIDIA 公告 | `upstream_baseline.py artifacts`、NVIDIA 公告鏡像 |
| NVIDIA L4T 使用者空間套件（`nvidia-l4t-*` deb：驅動、函式庫、工具） | 雖然裝在 rootfs，但屬於 BSP；比對 NVIDIA 公告 | Syft（只取 `nvidia-l4t-*`）、`nvidia_bulletins.py` |
| 我們自己的程式、非套件程式 | 雜湊、版本、來源 | 自有軟體清單＋非套件程式自動列出（待辦 J1） |

**OS 層（範例 rootfs 的 Ubuntu 套件）**
- 決定權在「ODM 只負責 BSP、OS 由客戶負責」（PM＋法務）。在那之前：**照掃、但分開列**——報告與 DT 分成兩個專案或兩個區段：「BSP（我們的待辦）」與「範例 rootfs（給客戶參考）」，P1 判斷表只放 BSP 層的項目；OS 層出現 KEV 時列入「通知客戶」而不是我們的修補待辦。
- 因為 CI 自動跑，多掃 OS 層幾乎不花人力；保留它也讓客戶資料包完整。

**工具要補的**
1. 報告與 DT 依層分開（`cra_report.py`／`report_package.py` 加「層」欄位：bsp／os／host-tool），P1 判斷表預設只放 bsp。
2. Syft 結果依套件來源分層：`nvidia-l4t-*`、我們的套件 → bsp；Ubuntu 官方套件 → os。
3. 刷機工具（主機端的 `flash.sh`、`tools/`）不在板子上執行，列為 host-tool，不進產品漏洞清單。

## 每段流程

### A. Jetson（git 流程）
1. 打 tag `orin-nano-demo/v39.2.1-demo1`，觸發 `release.yml`。
2. `jetson-build.sh`：
   - 下載 NVIDIA 公開原始碼（r39.2.0／r39.2.1）、BSP、範例 rootfs，逐一核對 sha256。
   - 套用 `patches/`。
   - 用公開的 aarch64 交叉工具鏈編譯核心和樹外模組。
   - 用 `pack-build-record.sh` 打包建置紀錄。
   - 組刷機包：BSP＋rootfs，再把核心換成 CI 編出來的那顆，`rootfs/boot/Image` 也一起換，避免「兩顆核心」的情況。
3. `jetson-scan.sh`：
   - 開臨時 DT。
   - 產生站台設定檔。
   - 跑精靈（`--yes`），用 CI 的建置紀錄，不是自編模式。
   - 產出報告、SBOM、VEX、P1 判斷表。
4. 結果：
   - tag 版：發 GitHub Release，附上報告（公開資料、長期保存）。
   - 開發版：存成 Actions artifact（保存 90 天）。
5. 記錄：已出貨版本的 SBOM 提交到 `sboms/`，給每日監控用。

### B. mini PC BIOS
- **公開樣本**（網址＋sha256，由工作包挑選並記錄授權）：
  - Ubuntu OVMF（edk2）
  - Dasharo Protectli VP46xx v1.2.0（coreboot＋edk2，含 Intel ME、FSP、微碼）
  - 至少一個公開下載的 AMI Aptio 平台 BIOS 更新檔（例如 Intel／ASUS NUC 的公開 BIOS）
- **步驟**：
  1. 在 CI 安裝 UEFIExtract、ME Analyzer、MC Extractor（固定版本），加上 `x86_firmware.py`、`uefi_image.py`，以及原型腳本整理成的 CBFS／FSP 解析。
  2. 拆開映像、讀出版本：AMI 核心、ME／CSME、每個 CPUID 的微碼、FSP、EC，以及內建的 OpenSSL 等函式庫。
  3. 產生 CycloneDX：能對應的元件填 purl／CPE；讀不到的寫 version unknown，標 GAP，不猜版本。
  4. 用 `sca-scan --sbom` 上傳臨時 DT，再用 Grype 比對。
  5. Intel 的部分（ME、微碼、FSP）**標 NOT_ASSESSED**，備註「Intel 公告無法機器比對，需公告對照」。
- **第二條路**：匯入供應商給的 BIOS SBOM，先做品質檢查（sbomqs）再上傳。用一份公開的韌體 SBOM 範例驗證這條路。

### C. vBIOS（兩種產品，同一套工具）
**範圍更正（使用者 2026-11-12）**：需求裡的「GPU binary」指的是 **vBIOS**，不是驅動程式。驅動不在範圍內（11-12 的驅動安裝檔試跑只當參考，不做成工具）。

vBIOS 依產品分三種情況：

| 產品 | vBIOS 在哪裡 | 怎麼處理 |
|---|---|---|
| 顯示卡（NVIDIA GPU） | 卡上自己的 SPI flash，是 NVIDIA 簽章的 option ROM | 讀 option ROM 版本（`XX.XX.XX.XX.XX`）＋雜湊，做身分 SBOM |
| mini PC 用 NVIDIA 獨顯（MXM 或板載 GPU） | 跟顯示卡一樣，GPU 旁邊有自己的 vBIOS | 同上 |
| mini PC 用 Intel 內顯 | **包在 mini PC 的 BIOS 映像裡**：UEFI GOP 驅動（Intel Graphics GOP）＋ VBT（Video BIOS Table），舊機型可能還有 legacy VBIOS option ROM | 在 B 段拆 BIOS 時一起找出來：GOP 驅動版本、VBT 版本、legacy VBIOS 版本，列為 BIOS 的子元件 |

- **公開樣本**：
  - 獨立 vBIOS：優先找 NVIDIA 官方公開的韌體更新工具（例如 DisplayPort 韌體更新工具，內含 vBIOS 映像）。找不到可以合法下載的檔案，就用合成的 option ROM 測流程，並寫明「實際檔案由負責單位提供」。
  - Intel GOP／VBT：從 B 段的公開 BIOS 樣本（AMI／NUC 那份）裡找。
- **步驟**：
  1. `x86_firmware.py` 讀 option ROM（PCI ROM header、廠商 ID、版本字串）和雜湊；擴充：在 BIOS 映像裡辨識 Intel GOP（依 GUID／名稱）、VBT（`$VBT` 標記）與 legacy VBIOS，讀出版本。
  2. 產生身分 SBOM：獨立 vBIOS 廠商填 NVIDIA；Intel GOP／VBT 填 Intel。
  3. 比對公告：
     - NVIDIA vBIOS：比對 NVIDIA 公告的 `gpu-firmware` 群組，沒對到標 **NOT_ASSESSED**（消費型 vBIOS 幾乎沒有公開公告）。
     - Intel GOP／VBT：跟 ME、微碼一樣，Intel 公告無法機器比對，標 NOT_ASSESSED，需公告對照。
  4. `nvidia`、`intel` 自動加進廠商層級監控清單。
  5. 主要管道寫進報告說明：vBIOS 漏洞要靠 NVIDIA／Intel 的合作夥伴通知，工具只能做到「知道每個型號是哪一版」。

### E. 監控與通知（`watch.yml`，每天）
1. 對 `sboms/` 裡每一個 shipped／development 版本，用 Grype 重新比對，並對照 CISA KEV、EUVD。
2. 執行廠商層級 KEV 提醒（`exploited_vendor.py`，加上手動清單 `vendor-watch.json`）。
3. 新的命中自動開 GitHub Issue：
   - 標籤：`kev`、`shipped`／`development`、`vendor-level`。
   - 內容：CVE、受影響的專案和版本、依據。
   - 同一筆不重複開 Issue。
   - 第一次跑只建立基準，不洗版。
4. 已出貨的照內部 SOP（當天排查、交 PM）；開發中的直接給 RD。GitHub 版用 Issue 指派代表；GitLab 版改成 Issue 加 email。

### F. 搬到 GitLab（`docs/GITLAB-PORT.md`＋`gitlab/`）
- 逐一對照：
  - workflow → `.gitlab-ci.yml`
  - Release → GitLab Release 或內部檔案庫（保存 10 年）
  - Issue → GitLab Issue
  - 臨時 DT → 內部常駐 DT（已有完整鏡像）
  - 內建 runner → 內部 shell／docker runner（參考 `deploy/gitlab-runner/`）
- 要換的：資料來源（公開 BSP → 公司產品 repo）、機密設定、編譯環境（RD 的 Docker 映像）。
- 產出：`gitlab/.gitlab-ci.yml` 範本，加上搬移檢查清單。

## 工作包與對話分工

| 對話 | 工作包 | 內容 | 開始條件 |
|---|---|---|---|
| **C0 協調**（新開） | WP0 | 開 repo（公開、Apache-2.0）、放 docs 骨架和本規劃、CI 骨架（tests.yml）、分支保護；之後負責看 PR、合併、驗收，並回覆使用者要決定的事 | 立刻 |
| **C1 流程核心** | WP1＋WP6 | 清理並複製工具（附 PROVENANCE）；臨時 DT；Jetson 編譯＋掃描＋Release；`orin-nano-demo` 兩個版本（r39.2.0、r39.2.1，加一個 patch）；**報告與 DT 依層分開（bsp／os／host-tool），P1 判斷表只放 bsp**；標準答案測試 | WP0 完成 |
| **C2 韌體** | WP3＋WP4（B、C） | mini PC BIOS（含 Intel 內顯 GOP／VBT）與 vBIOS（顯示卡、mini PC 獨顯）的解析、SBOM、比對、上傳 DT | 解析部分可以跟 C1 並行；上傳 DT 要等 C1 的里程碑 M1（臨時 DT 工具） |
| **C3 監控＋GitLab** | WP2＋WP5（E、F） | 每日監控、Issue 通知、廠商層級提醒；GitLab 搬移文件和範本 | C1 的里程碑 M2（第一個 Jetson 版本跑通） |
| **C4 其他平台**（M2 之後開） | WP7 | 依「開案範本與平台介面」加 Raspberry Pi、Rockchip、AI NAS 三個轉接器與公開示範專案；驗證「新增專案只要跑 `new-project.sh`＋填欄位」 | C1 的里程碑 M2（平台介面與開案範本在 C1 完成） |

C1 額外負責：**平台介面與開案範本**（`templates/project/`、`pipeline/new-project.sh`、`pipeline/platforms/` 的共用部分），Jetson 是第一個轉接器。

**里程碑**
- **M1**：工具複製完、CI 能開臨時 DT 並上傳一份測試 SBOM。
- **M2**：打 tag 後 Jetson 版本全程跑通，產出 Release。
- **M3**：mini PC BIOS、vBIOS 各至少一個樣本產出 SBOM 並進 DT。
- **M4**：每日監控開 Issue（用合成的 KEV 測過）。
- **M5**：GitLab 範本和搬移清單完成。
- **M6**：Raspberry Pi、Rockchip、AI NAS 各一個公開示範專案用 `new-project.sh` 建立並跑通；新增第四個專案不需要改 workflow。

**代理**
- 每個對話同時最多 **3 個** Sonnet 5.5 代理：最多 2 個寫程式（做彼此不相關的部分，避免改到同一批檔案），1 個驗證；寫程式和驗證的代理一律分開（使用者 11-12 決定）。
- 協調對話自己不寫大量程式。
- **代理的模型與 effort（使用者 11-12 決定，派代理時要明確指定）**：一律 `model: sonnet`（Sonnet 5.5），`effort: medium`。以下情況改用 `effort: high`：(1) 處理不可信檔案的解析與解壓（BIOS／vBIOS 映像、BSP 壓縮檔、建置紀錄）；(2) 會影響判定結果的邏輯（K1 核心判斷、分層、P1、VEX）；(3) 獨立驗證上述兩類 PR。其他（文件、workflow 串接、樣本下載與雜湊、一般測試）用 medium。不用 low。
- 全部對話合計同時最多 **8 個**代理，由 C0 視主機負載調整（`uptime` 負載超過 6 就先暫停開新代理）。五個對話都在第二台後改為整台 10 個、負載超過 12 或可用記憶體低於 4 GB 暫停（D-048）。
- 本機重工作（完整測試、Docker、大檔解壓）一律 `flock $HEAVY_LOCK` 排隊，一次只跑一個；代理平常只跑跟自己改動有關的測試，完整測試交給 GitHub CI。

**協調方式**
- 所有決定寫進 `docs/DECISIONS.md`。
- 各工作包每做完一步就更新 `docs/STATUS.md` 自己那一節。
- 要交接或里程碑完成時，用跨對話訊息通知 C0。
- 需要使用者決定的事，一律由 C0 統一問。
- 分支命名 `wpN/<主題>`，PR 標題前綴 `[WPn]`。

## 中斷與交接（每個對話隨時可以中斷、重開）

原則：**所有狀態都放在 repo 裡，不放在對話裡**。任何對話被中斷、或換一個新對話接手，只要讀 repo 就能接著做。

1. **`docs/STATUS.md`，每個對話一節**（C0、C1、C2、C3、C4），**每做完一步就更新並推送**，不是等里程碑才寫。每節固定欄位：
   - 目前在做哪一步（對應本規劃的哪一段）
   - 分支、PR 編號、最後一個 commit
   - 開出去的代理：每個代理一行（任務、分支、狀態：進行中／完成／中斷），代理的成果一律推到分支，不留在本機
   - 正在跑的 CI（run 連結）或本機背景工作（指令、紀錄檔路徑）
   - 下一步
   - 卡住的地方、等誰決定
2. **`docs/HANDOFF.md`：重開時的固定步驟**（每個對話都照做）：
   1. 讀 `docs/PLAN.md` 自己負責的工作包。
   2. 讀 `docs/DECISIONS.md`。
   3. 讀 `docs/STATUS.md` 自己那一節。
   4. `gh pr list --search "[WPn]"`、`gh run list` 看 PR 和 CI 的現況。
   5. 檢查自己的 worktree（`git status`、`git log`）；沒推送的東西先推送。
   6. 從 STATUS 的「下一步」接著做。
3. **代理的工作不能只存在代理裡**：
   - 代理一開始就開分支、儘早推 WIP commit、開 draft PR。
   - 代理中斷了，新的代理從分支和 STATUS 接手。
   - 驗證代理的結論寫在 PR 留言或 STATUS。
4. **長時間工作交給 GitHub Actions**：對話中斷不影響已經在跑的 workflow，重開後用 `gh run list` 看結果。本機背景工作要把指令和紀錄檔路徑寫進 STATUS。
5. **每個工作的完成定義都寫在規劃裡**（見「驗證」），不靠對話記得做到哪。
6. **決定一律寫進 `docs/DECISIONS.md`**（日期、誰決定、內容、理由），對話裡講過的不算數。
7. **代理的能力**：每個對話（C0–C4）都可以自己開 Sonnet 5.5 代理，同時最多 3 個（最多 2 個寫程式、1 個驗證），寫程式和驗證分開。代理本身不再開代理。開場指令會寫明這一點。

## 這台電腦夠不夠

- **規格**：i7-7700K 4 核 8 執行緒、RAM 39 GB（可用 32 GB）、系統碟剩 97 GB、資料碟剩 696 GB。
- **編譯和掃描都在 GitHub runner 上跑**。本機只寫程式、跑單元測試，所以夠用。
- **CPU 是瓶頸**：本機的完整測試和 Docker 工作要排隊，用 `flock $HEAVY_LOCK` 鎖住，一次只跑一個。
- **工作位置**：
  - repo 放 `$REPO_MAIN`。
  - 各對話用自己的 worktree：`$AGENT_TMP/dumpling-wt-*`。
  - 暫存放 `$AGENT_TMP/dumpling-tmp-*`，不放 `/tmp`。

## 各對話的開場指令（給使用者貼到新對話）

**C0**：「你是 dumpling 的協調對話。先讀 本機的規劃原稿（＝本檔 `docs/PLAN.md`），照『WP0』建立公開 repo `evil88332115-png/dumpling`（Apache-2.0），把這份規劃放到 `docs/PLAN.md`，建立 `docs/STATUS.md`（C0–C4 各一節）、`docs/DECISIONS.md`、`docs/HANDOFF.md`（照規劃『中斷與交接』）。之後負責看 PR、合併、驗收，並回覆 C1–C4。你可以自己開 Sonnet 5.5 代理（同時最多 3 個：最多 2 個寫程式、1 個驗證，寫程式和驗證分開；全部對話合計最多 8 個），例如派代理做 PR 的獨立驗證。每做完一步就更新 STATUS 的 C0 節。若是中斷後重開：先照 `docs/HANDOFF.md` 接手。所有回覆用繁體中文。」

**C1／C2／C3／C4**：「你是 dumpling 的 C1（或 C2、C3、C4）。先照 `$REPO_MAIN/docs/HANDOFF.md` 的步驟接手：讀 `docs/PLAN.md` 你負責的工作包、`docs/DECISIONS.md`、`docs/STATUS.md` 你那一節，看你的 PR 和 CI，再從『下一步』繼續。在自己的 worktree 工作。你可以自己開 Sonnet 5.5 代理，同時最多 3 個（最多 2 個寫程式、1 個驗證，寫程式和驗證分開）；本機完整測試與 Docker 工作用 flock $HEAVY_LOCK 排隊；代理的成果一律推到分支。每做完一步就更新 STATUS 你那一節並推送；完成里程碑或需要決定時，用訊息通知 C0。所有回覆用繁體中文。」

**任何對話中斷後重開**：貼同一段開場指令即可（它一開始就會照 HANDOFF 接手）。

## 驗證（驗收方式）

- **Jetson**：
  - 打 tag 後 workflow 綠燈，Release 有報告 zip、SBOM、VEX、`漏洞清單.xlsx`、`P1判斷表.xlsx`。
  - 建置紀錄狀態 OK（CI 自編，身分相符），C-kernel-boot 為 OK。
  - 兩個版本的差異報告合理；patch 版在上游比對裡顯示 1 個檔案被修改。
  - 跟固定的標準答案比對，數字在允許範圍內。
- **BIOS**：3 個樣本都產出 SBOM。ME 和微碼版本要跟試掃結果一致（Dasharo：ME 14.0.47.1558、微碼 rev 0xF8）。讀不到的標 GAP，DT 上傳成功。
- **vBIOS**：獨立 vBIOS 讀出版本和雜湊；AMI／NUC 樣本裡找出 Intel GOP／VBT 版本；公告比對沒對到時標 NOT_ASSESSED。
- **監控**：
  - 用合成的 KEV 項目測試，會開出 Issue，而且不會重複開。
  - 真實第一次執行只建立基準，不洗版。
- **GitLab**：`.gitlab-ci.yml` 通過語法檢查，搬移清單逐項列出對應關係。
- **公開檢查**：每個 PR 都跑一次掃描，確認沒有公司字樣、內部 IP、本機路徑、個人信箱。CI 裡有一個 job 專門做這件事，用 `grep` 比對禁用字清單。
