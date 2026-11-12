# 平台研究：Raspberry Pi、Rockchip、AI NAS（WP7 第一階段）

C4 寫的研究筆記，給 M2 之後寫平台轉接器（`pipeline/platforms/<平台>/`）時用。這份文件只整理現況與建議，**不是決定**；
要定案的項目列在最後一節「待決定」，由 C0 統一問，決定寫進 `docs/DECISIONS.md`。

- 來源：sca-center 25fa89a 的 `scripts/wizard/platforms/{raspberrypi,rockchip}.json`、`scripts/demo/rpi_img.py`（#201）、
  `scripts/demo/rockchip_img.py`、`scripts/demo/flash_package.py`、`scripts/cra/bootloader_coverage.py`。
  C1 的 M1 會把這些檔案複製到 `tools/demo/`、`tools/cra/`、`tools/wizard/platforms/`；下面寫的行為以 25fa89a 為準。
- 公開示範資料（網址、大小、sha256、授權）見 `platform-samples/*/samples.yml`。
- AI NAS 有兩個參考：Debian 13＋OpenMediaVault（M6 實作，D-025）與 TrueNAS SCALE（只做研究與樣本清單，D-026）。
- 標「推論」的項目是依套件名稱或官方說明推得，**還沒有解開映像驗證**（第一階段只下載核對、不解開）；寫轉接器時要先驗證。

## 現有工具支援一覽（sca-center 25fa89a）

| 能力 | Raspberry Pi | Rockchip | AI NAS（x86 Debian） |
|---|---|---|---|
| 精靈的平台輸入清單 | `raspberrypi.json`（`draft: true`）：映像必填；原始碼、建置紀錄選填；上游映像、實機測試、設定包選填 | `rockchip.json`（`draft: true`）：刷機包、原始碼、建置紀錄**都必填**；另外交付的韌體、上游原始碼／SDK 基準選填 | 沒有平台檔 |
| 映像格式 | 原始磁碟映像 `.img`／`.img.xz`／`.img.gz`（MBR 或 GPT；FAT＋ext4 唯讀解析，`rpi_img.py`，#201） | `update.img`（RKFW＋RKAF，含超過 4 GB 的 32 位元溢位修正，`rockchip_img.py`）、裝 update.img 的 zip | 原始磁碟映像可走 `rpi_img.py` 的同一條路（GPT＋ext4）；但 Debian 映像外面多包一層 tar（見下） |
| 虛擬 tar 的內容 | `rootfs/`（ext4 root）、`bootloader/`（第一個 FAT 分割區的檔案）、`kernel/`（`kernel*.img`、`initramfs*`） | `rootfs/`（名稱是 rootfs 的 ext4 分割區）、`bootloader/<分割區>.img`（MiniLoaderAll、uboot、trust、boot…原樣）、`config/`、`kernel/Image`（boot 分割區 FIT 裡的核心） | 同 Raspberry Pi |
| 開機韌體涵蓋（`bootloader_coverage.py`） | `--platform raspberrypi`：閉源 GPU 韌體 GAP、kernel／initramfs NOT_ASSESSED、.dtb／.dtbo 資料檔；Pi 4／5 的 EEPROM 開機程式列在 `not_in_image`（NOT_ASSESSED） | `--not-assessed rockchip`：**沒有開機鏈分類**，整體 NOT_ASSESSED（"boot chain not defined for this platform"） | 沒有 |
| 依層分開（bsp／os／host-tool） | 沒有（`cra_report.py` 還沒有「層」欄位；PLAN 把它列為 C1 WP1 的工作） | 同左 | 同左 |

## Raspberry Pi

**公開示範資料**：Raspberry Pi OS Lite（trixie，arm64）2026-10-06；核心 `1:6.18.50-1+rpt1`；開機韌體 `raspi-firmware 1:1.20260915-1`；
EEPROM 套件 `rpi-eeprom 28.33-1`（取自官方 `.info` 套件清單）。核心原始碼對應 `raspberrypi/linux` 的 `stable_20260911`
（該 tag 的 Makefile 是 6.18.50；跟 Raspberry Pi apt 原始碼包 `linux_6.18.50.orig.tar.xz` 是否同一個 commit：NOT_ASSESSED）。
官方在映像旁另外附一份 SBOM（`.sbom.xz`），可以當交叉核對用的第二來源。

**分層（建議，待決定）**

| 層 | 內容 | 怎麼認 |
|---|---|---|
| bsp | 核心 `linux-image-*-rpi-v8`／`*-rpi-2712`（從 `raspberrypi/linux` 編） | 套件名稱；核心版本、IKCONFIG／`/boot/config-*` |
| bsp | 開機韌體：`start*.elf`、`fixup*.dat`、`bootcode.bin`（閉源 VideoCore 韌體）、`config.txt`、`cmdline.txt` | boot 分割區（`bootloader/`）；來源套件 `raspi-firmware` |
| bsp | device tree：`*.dtb`、`overlays/*.dtbo` | boot 分割區 |
| bsp | EEPROM 開機程式的**更新檔**（`rpi-eeprom` 套件內的 `pieeprom-*.bin`，推論） | rootfs 的套件；板子上**實際**在跑的 EEPROM 版本不在映像裡 → NOT_ASSESSED（現有 `not_in_image`） |
| bsp | 無線網路／藍牙韌體（`firmware-brcm80211`、`bluez-firmware` 的 `+rpt` 版） | 套件名稱＋版本含 `+rpt` |
| bsp 或 os（**待決定**） | Raspberry Pi 重新包的 Debian 套件（版本含 `+rpt`，例如 `alsa-utils 1.2.14-1+rpt1`、`bluez 5.82-1.1+rpt2`、`cloud-init …+rpt20`） | 版本字尾 `+rpt`；或 apt 來源 `archive.raspberrypi.com` |
| os | Debian 官方套件（沒有 `+rpt`） | 其他 |
| host-tool | `rpi-imager` 等燒錄工具（不在板子上執行，不在映像裡） | 不列 |

**韌體檢查**
- `start*.elf`／`fixup*.dat`／`bootcode.bin`：閉源，只有廠商發行說明、沒有安全公告可比對 → **GAP**（現有行為，保留）。
  可以補的是**身分**：跟 `raspi-firmware` 的官方 deb（`samples.yml` 已列，`role: package`）逐檔比 sha256，確認映像裡的檔案是官方原版（類似 Jetson 的 `upstream_baseline.py artifacts`）。
- Pi 4／5：開機程式在板子的 EEPROM。映像裡只有 `rpi-eeprom` 的更新檔，板子上實際的版本要實機讀（`rpi-eeprom-update`）→ 沒有實機時 NOT_ASSESSED。
- Pi 3 以前：`bootcode.bin` 在 boot 分割區，跟上面一起檢查。

**轉接器要注意（給 M2 之後）**
- `build`：可以真的從 `raspberrypi/linux` 編核心（建置紀錄由 CI 產生，跟 Jetson 一樣），或標「不編譯」、直接用官方 `linux-image` deb。
- `assemble`：示範專案不用重組映像，直接用官方 `.img.xz`。
- 解壓後約 3 GB（`rpi_img.py` 要隨機存取未壓縮檔），在 GitHub runner 上可行。

## Rockchip

**公開示範資料**：Radxa ROCK 5B（RK3588）官方映像 `rsdk-r6`（Debian 12 bookworm，KDE）。PLAN 原本提到 Radxa 或 Armbian，這裡選 Radxa：
它是板子廠商自己發行的映像，放在 GitHub Release（網址固定），而且套件、核心、U-Boot 都能對到公開的 commit：
- 核心 `linux-image-6.1.84-8-rk2410`：原始碼是 `radxa-pkg/linux-rk2410` tag `6.1.84-8` 的子模組 → `radxa/kernel` commit `87ba2c6cbc16dd2ddfe10248fd45220d2d25a6f9`（Rockchip BSP 核心 6.1.84，分支 `linux-6.1-stan-rkr4.1`）。
- U-Boot `u-boot-rk2410 2017.09-64-39cd993`：Rockchip 原廠系的 U-Boot 2017.09，原始碼 `radxa/u-boot` commit `39cd993e5d6296635438e84f4576b3a9bf76f86e`。
- 閉源的 DDR 初始化、TF-A BL31（Rockchip 只給成品）、OP-TEE（BL32）來自 `rockchip-linux/rkbin`（Rockchip 專有授權，只給成品）。這個映像用的是 rkbin 的哪個 commit／哪個檔案版本：**GAP**（打包資料沒寫）。

**映像格式的落差（重要）**
- 公開的 Radxa／Armbian 映像都是**原始磁碟映像**（GPT），不是 `update.img`。`rockchip_img.py` 的 RKFW 路徑用不到；要走 `rpi_img.py` 的磁碟映像路徑。
- Rockchip 的開機程式（`idbloader.img`＝DDR 初始化＋SPL、`u-boot.itb`＝U-Boot＋TF-A＋OP-TEE）放在**第一個分割區之前**的原始磁區（慣例是 sector 64 與 16384，推論），
  不屬於任何分割區。`rpi_img.py` 只讀分割區 → **這些開機程式目前不會被清點**。轉接器要補一種做法（之後 PR 決定）：
  (a) 讀分割區之前的區域並辨識 idbloader／FIT；或 (b) 從 rootfs 裡 `u-boot-rk2410` 套件的檔案（推論在 `/usr/lib/u-boot/` 底下）清點，並跟映像開頭的原始磁區比對雜湊。
- 公開的 `update.img`（RKFW）樣本：**沒有找到**可以合法、固定網址下載的。RKFW 路徑只能用合成測試資料（sca-center 已有）；之後若廠商或團隊提供，再當第二個樣本。

**分層（建議，待決定）**

| 層 | 內容 | 怎麼認 |
|---|---|---|
| bsp | 核心 `linux-image-*-rk2410`（Rockchip BSP 核心，經 Radxa 修改） | 套件名稱 |
| bsp | U-Boot（`u-boot-rk2410`、`u-boot-rock-5b`）＋開機區的 idbloader／u-boot.itb | 套件名稱；原始磁區（見上） |
| bsp | TF-A BL31、OP-TEE、DDR 初始化（rkbin 成品） | u-boot.itb／idbloader 內容 |
| bsp | Rockchip 使用者空間：`librockchip-mpp1`、`gstreamer1.0-rockchip1`、`rockchip-iqfiles-*`、`rockchip-*` 設定套件 | 套件名稱 |
| bsp | Radxa 套件：`radxa-firmware`、`radxa-system-config-*`、`rsetup*`、`task-rockchip*` | 套件名稱或 apt 來源（Radxa 的套件庫） |
| os | Debian 官方套件 | 其他 |
| host-tool | `rkdeveloptool`、`upgrade_tool`、RKDevTool（主機端燒錄） | 不在映像裡，不列 |

**韌體檢查**
- U-Boot：版本字串（`U-Boot 2017.09-…`）＋跟 `radxa/u-boot` 39cd993 對照；跟 Jetson 的 UEFI 對照檢查（`uefi-check`）是同一類，但目前只支援 UEFI。
- TF-A BL31／OP-TEE：`tee_bundled.py` 能不能從 rkbin 成品讀出版本與內建 Mbed TLS → 未驗證（NOT_ASSESSED）。BL31 是閉源成品 → 至少版本與雜湊要列，安全公告比對 **GAP**。
- DDR 初始化／miniloader（`rk3588_ddr_*.bin`、`rk3588_spl_*`、`rk3588_usbplug_*`）：閉源、沒有安全公告 → **GAP**（PLAN 已指定）。
- `bootloader_coverage.py` 要加 `--platform rockchip` 的分類（目前是整體 NOT_ASSESSED）。

**原始碼包**
- `radxa/kernel`、`radxa/u-boot` 的原始碼用 GitHub 依 commit 產生的封存檔。**GitHub 動態產生的封存檔 sha256 可能變動**（C2 的 Dasharo 樣本有同樣註記）；
  要固定雜湊的話，之後改成在 CI 用 `git clone` 到固定 commit、核對 commit SHA（不核對封存檔雜湊）。

## AI NAS（x86，Debian 系）

**公開示範資料**：Debian 13 trixie generic amd64 映像 `20261111-2659`（核心 `6.12.116-1`，來自 debian-security）；核心原始碼用
snapshot.debian.org 的固定網址（一般的 `deb.debian.org` pool 換版後舊檔會被移走）。應用層用 OpenMediaVault 的原始碼（GitHub `openmediavault/openmediavault` 的固定 commit），之後用 cdxgen 掃相依套件，代表「NAS 網頁介面與 App」（D-025）。
**不用 OMV 的安裝 ISO**：它是安裝程式，要得到裝好的系統就必須執行它，違反「只解開、不執行」。

**跟 BSP 平台最大的不同：OS 也算我們的待辦**
- 自有品牌的 NAS，公司就是整個產品的製造商：Debian 套件、核心、NAS 網頁介面、App **全部**算待辦，不是「範例 rootfs 給客戶參考」。
- 所以分層**不能寫死在平台設定**：同一個 Debian 套件，在 Jetson 是 os（通知客戶），在 AI NAS 是我們的待辦。
  建議：平台設定只給「預設的分層規則」，`project.yml` 的角色與交付方式（例如 `os_responsibility: us | customer`）決定 os 層要不要算進待辦。這要 C1 在 M2 的平台介面一起定。

**分層（建議，待決定）**

| 層 | 內容 | 待辦嗎 |
|---|---|---|
| os（我們的） | Debian 套件（含核心 `linux-image-*-amd64`、`grub-efi-amd64-signed`、`shim-signed`） | 是 |
| app（我們的） | NAS 網頁介面與 App（OMV 這類 PHP／JS／Python 程式；AI 功能的 Python 套件） | 是；原始碼用 cdxgen 掃（PLAN 已指定） |
| platform-fw | 主機板 UEFI BIOS、BMC、Intel ME、微碼 | 不在 OS 映像裡；由 C2 的 BIOS 流程處理（`firmware/bios/…`）；映像裡只有 `intel-microcode`／`amd64-microcode` 套件（推論；generic 雲端映像可能沒裝，要驗證） |
| host-tool | 安裝 ISO 的安裝程式、燒錄工具 | 不列 |

**韌體與核心檢查**
- 核心：Debian 不另外編譯（`build` 標「不編譯」）；核心設定用映像裡的 `/boot/config-*`（Debian 有附，不需要 IKCONFIG）；修補紀錄看 Debian 原始碼包的 `debian/changelog`＋`debian/patches/`。
- 開機鏈：shim → GRUB（簽章套件，版本可從 dpkg 讀）；UEFI 本身在主機板上 → 交給 C2 的 BIOS 盤點，報告裡註明「不在 OS 映像裡」。
- 映像格式：Debian 的 `.tar.xz` 裡是一個 `disk.raw`（GPT＋ext4，推論）。`flash_package.py` 不會解開 tar 裡的磁碟映像 →
  轉接器的 `assemble` 要先把 `disk.raw` 解出來（只解開、不執行），再交給磁碟映像路徑；或直接下載未壓縮的 `.raw`（約 3 GB，推論）。
- OMV 不打 git tag，版本只記在 `deb/openmediavault/debian/changelog`；官方套件庫只保留最新版的 deb。所以原始碼以 commit SHA 固定，
  跟正式發行的 deb 是否完全相同：NOT_ASSESSED。原始碼裡有 `workbench/package-lock.json`、`composer.lock`、`requirements.txt`，cdxgen 掃得到相依套件。

## AI NAS 參考二：TrueNAS Community Edition（SCALE）（D-026：只做研究與樣本清單，不寫轉接器）

**樣本**：目前的穩定版 Goldeye **25.10.8**（2026-11-03 建置；TrueNAS-26 還是 BETA、TrueNAS-27 是 RC）。用 `.update` 更新檔，不用安裝 ISO
（理由跟 OMV 一樣：要得到裝好的系統就必須執行安裝程式）。網址、大小、sha256 見 `platform-samples/truenas-scale-25.10.8/samples.yml`。

**`.update` 的格式（2026-11-12 在本機用 `unsquashfs` 解開一次確認，之後刪除；沒有執行任何內容）**

```
TrueNAS-SCALE-25.10.8.update        squashfs 4.0（gzip，2.0 GB）
├── manifest.json                   版本、日期、解開後大小、kernel_version、每個檔案的 SHA-1
├── rootfs.squashfs                 squashfs 4.0（xz）：整個系統根目錄（114,975 個項目）
└── truenas_install/                Python 安裝程式（__main__.py、dhs.py、fhs.py、utils.py；只讀，不執行）
```

- `manifest.json`：`{"version": "25.10.8", "date": …, "size": 7830791372, "kernel_version": "6.12.113-production+truenas", "checksums": {"rootfs.squashfs": <SHA-1>, …}}`。
  內層 `rootfs.squashfs` 的 SHA-1 跟 manifest 記的相同（本機核對過）。
- 簽章：官方另外放 `.update.sig`（OpenPGP 分離簽章，RSA 4096＋SHA-512），簽章者是官方文件公布的「IX SecTeam」金鑰，
  指紋 `C8D6 2DEF 767C 1DB0 DFF4 E6EC 358E AA91 12CF 7946`（文件：`truenas/documentation` 的 `content/SCALE/GettingStarted/Install/InstallingSCALE.md`）。
  2026-11-12 在本機從 keyserver.ubuntu.com 取這把公鑰（指紋相符）驗證 `.update`：**Good signature**。
  `.update` 本身沒有內嵌簽章；manifest 的 SHA-1 只保護內容一致，不是簽章。CI 可以在核對 sha256 之外，再用這個指紋驗 `.sig`。
  （`truenas-build` 的 `keys/truenas.gpg` 是另一把 apt 套件庫用的金鑰，不是這個。）
- 另外有 `rootfs.mtree`（每個檔案的路徑、權限、大小、sha256）與 `GITMANIFEST`（這一版用到的 45 個 `truenas/*` repo 與 commit），都是官方提供，可以當交叉核對。
- **能不能只解開、不執行就取出系統根目錄和 dpkg 狀態：可以。** 兩層都是標準 squashfs，`unsquashfs` 一般使用者就能解，
  不需要 mount、loop 裝置或 root。只解出需要的路徑也可以（`unsquashfs -d <目錄> rootfs.squashfs var/lib/dpkg/status`）。
  - `/var/lib/dpkg/status` 存在：1,023 筆，其中 1,014 個已安裝；基底是 Debian 12 bookworm（`usr/lib/os-release`）。
  - 版本或維護者含 truenas／`+ix` 的套件有 94 個（iXsystems 自己建的或修改過的：核心、ZFS、middlewared、網頁介面、Samba、SCST…）。
  - 幾個重點套件：`linux-image-truenas-production-amd64 6.12.113-production+truenas-1`、`openzfs-zfsutils 2.3.9-2`、
    `middlewared 20261103130803~truenas+1`、`truenas-webui 20261103122023~truenas+1`、`docker-ce 5:28.3.1-1~debian.12~bookworm`、
    `containerd.io 1.7.27-1`、`intel-microcode`、`amd64-microcode`、`grub-efi-amd64-signed`、`shim-signed`。
  - `/boot/` 有 production 與 debug 兩個核心（`vmlinuz-6.12.113-production+truenas`、`-debug+truenas`），出貨用的是 production。
  - 磁碟需求：外層 2.0 GB＋內層 2.0 GB；完整解開內層約 7.8 GB（manifest 的 `size`）。在 GitHub runner 上可行，但要先清磁碟。
  - 現有工具：`flash_package.py` 不認得 squashfs → 轉接器要先用 `unsquashfs` 解出 rootfs 目錄，再交給 Syft／rootfs 掃描（跟 Debian 的 `disk.raw` 一樣是「先解開」的步驟）。

**對應的原始碼（都有 tag `TS-25.10.8`，commit 跟官方 GITMANIFEST 相同）**

| 部分 | repo | tag → commit |
|---|---|---|
| 核心 | `truenas/linux` | `TS-25.10.8` → `d586e6d98d58c9f27f01b1cdf73c3bdb1d2c2e25` |
| 中介層（middlewared，Python） | `truenas/middleware` | `TS-25.10.8` → `29ed02b8082f38494b0d2896bada8151f0d59716` |
| 網頁介面（Angular，`yarn.lock`） | `truenas/webui` | `TS-25.10.8` → `e85f786463fd2220c138bc6313eed02d53f97616` |
| 建置設定（套件清單與來源） | `truenas/truenas-build` | `TS-25.10.8` → `453acc8fddacf20c82a509a0177730e9479d49af` |
| 其他 41 個（ZFS、Samba、SCST、Python 相依…） | `truenas/*` | 見 GITMANIFEST（短 commit） |

- Python 相依：middlewared 本身沒有鎖定檔；相依套件是個別打成 deb（`python3-*`，版本在 dpkg status 裡），另外有 `truenas/python-truenas-requirements`。
  所以 Python 相依從 dpkg／rootfs 掃比從原始碼掃準。網頁介面有 `yarn.lock`，cdxgen 掃得到。

**App 層（Docker 容器，現在不掃）**

- 官方 App 目錄是 `truenas/apps`（LGPL-3.0）。結構：
  - `ix-dev/<train>/<app>/`：原始定義。`app.yaml`（`app_version`、目錄版本 `version`、`train`、`lib_version`）、`ix_values.yaml`（容器映像）、
    `questions.yaml`（安裝畫面的欄位）、`templates/docker-compose.yaml`（Jinja 樣板＋`macros/`）、`item.yaml`（分類、圖示）。
  - `trains/<train>/<app>/<版本>/`：發布出去、已經展開的各版本，加 `app_versions.json`；根目錄有 `catalog.json`。
  - train：`stable`、`community`、`enterprise`、`dev`、`test`。
- **容器映像版本的固定方式**：`ix_values.yaml` 的每個映像寫成 `repository` ＋ `tag: "<版本>@sha256:<digest>"`
  （例如 nextcloud 的 `tag: "35.0.2@sha256:786c10…"`），所以映像已經用 digest 固定，掃描時可以直接用 digest 拉取，結果可重現。
- App 目錄**沒有版本 tag**、跟 OS 版本分開滾動更新；一台機器上實際的目錄版本要從那台機器讀（`/mnt/.ix-apps` 底下的目錄 checkout，推論）。
  樣本清單先記一個查詢當天的 master commit，標 NOT_ASSESSED。
- 之後要掃的話：對選定的 App 讀 `ix_values.yaml` → 每個映像用 digest 拉取 → Syft 掃映像 → 合併進產品 SBOM（app 層）。
  公司自己的 App 才算我們的待辦；第三方 App（使用者自己裝的）要先決定算不算（見待決定）。

**跟 Debian＋OMV 的差異**

| 項目 | Debian 13＋OMV（M6 實作） | TrueNAS 25.10.8 | 可以重用 | 要多做 | 估計工作量 |
|---|---|---|---|---|---|
| 系統映像 | 雲端映像 `tar.xz` 裡的 `disk.raw`（GPT＋ext4） | `.update`：squashfs 包 squashfs | 下載核對（`fetch_one`）、rootfs 掃描（Syft、`image_check.py`）、dpkg 讀取 | 用 `unsquashfs` 解兩層（不 mount、不執行）；manifest 的 SHA-1 核對；`.sig` 驗證 | 小（1–2 天） |
| 基底 | Debian 13 trixie | Debian 12 bookworm（＋iXsystems 自建 94 個套件） | Debian 的 OSV／DSA 比對 | 自建套件（`~truenas`、`+ix` 版本）不在 Debian 的漏洞資料裡 → 要對應到上游版本，或標 NOT_ASSESSED | 中（3–5 天） |
| 核心 | Debian 核心，原始碼 `.dsc` 固定；設定在 `/boot/config-*` | `truenas/linux` tag；production／debug 兩個核心 | 核心版本與設定讀取（`kernel_config.py`） | 選 production 那個；核心 CVE 比對要用 TrueNAS 分支的修補紀錄（不是 Debian changelog） | 中（2–4 天） |
| 中介層與網頁 | OMV 原始碼（PHP／JS／Python，有鎖定檔），cdxgen 掃 | middlewared（Python，相依打成 deb）＋webui（Angular，`yarn.lock`） | cdxgen 掃網頁介面 | middlewared 的相依從 dpkg 讀，不從原始碼；兩個 repo 的 tag 都有 | 小（1–2 天） |
| App 層 | OMV 外掛（deb，在 rootfs 裡） | Docker 容器（`truenas/apps`，映像用 digest 固定） | Syft 可掃容器映像 | 新流程：讀 `ix_values.yaml` → 依 digest 拉映像 → 掃 → 合併 SBOM；App 目錄版本要從機器讀 | 大（1–2 週） |
| 檔案系統／儲存 | ext4、mdadm（OMV） | OpenZFS 2.3.9（樹外模組 `openzfs-zfs-modules-*`）、SCST | 樹外模組身分（`.ko`） | ZFS 漏洞資料的對應（OpenZFS 公告） | 小（1–2 天） |
| 開機鏈 | shim → GRUB（Debian 簽章套件） | GRUB（`truenas/grub2` 2.12 backport）＋shim | 同左 | GRUB 是 TrueNAS 自己 backport 的版本 | 小 |
| 簽章與完整性 | Debian `SHA512SUMS` | `.update.sha256`＋`.update.sig`（IX SecTeam）＋manifest SHA-1＋`rootfs.mtree` | sha256 核對 | gpg 驗證步驟；mtree 可以拿來核對解開後的每個檔案 | 小 |
| 分層 | 自有品牌：OS 層算我們的待辦（`project.yml` 角色，D-025） | 同左；但若只是轉售 TrueNAS，OS 層的待辦在 iXsystems | 同一套 `project.yml` 角色欄位 | 要多一種角色：「上游 OS 廠商負責、我們通知客戶」 | 跟 M2 的平台介面一起定 |

## 共用下載核對能不能重用（回覆 C0）

`pipeline/lib/firmware_fetch.py`（C2）的 `curl_download`、`check_file`、`fetch_one`（https only、先下到 `.part`、核對大小與 sha256、拒絕 symlink、相符才改名）
**完全通用**，平台樣本可以直接用。不能直接用的只有 `validate()`：它寫死 `kind: bios|vbios`、`firmware_version`、`ibv` 這些韌體欄位。
建議（M2 時由 C1 決定）：把通用部分抽到 `pipeline/lib/fetch_verify.py`（或讓 PLAN 的共用 `fetch` 步驟直接 import `firmware_fetch.fetch_one`），
`sources.yml` 的 `files[]` 沿用 `firmware.yml` 的格式（`name`、`url`、`sha256`、`size`、`role`），這樣兩邊共用一份下載核對。
這次的 `platform-samples/*/samples.yml` 就是照 `firmware.yml` 的 `files[]` 格式寫的，M2 定出 `sources.yml` 後再搬過去。

## 待決定（由 C0 統一問）

1. Raspberry Pi 重新包的 Debian 套件（版本含 `+rpt`）算 bsp 還是 os？
2. AI NAS 的「OS 是不是我們的待辦」：方向已決定（D-025：寫在 `project.yml` 的角色，自有品牌時 OS 層算我們的待辦）；欄位名稱跟平台介面一起由 C1 在 M2 定。
3. Rockchip 原始磁區的開機程式要用哪種方式清點（讀原始磁區，或從 rootfs 的 u-boot 套件清點再比對）。
4. ~~AI NAS 示範要不要做「Debian＋OMV 已安裝」的映像~~：已決定（D-025）：Debian 映像＋OMV 原始碼用 cdxgen 掃，兩條分開；不用 ISO。
5. GitHub 動態封存檔（`raspberrypi/linux` tag、`radxa/kernel`、`radxa/u-boot`）要核對封存檔的 sha256，還是改成核對 git commit SHA。
   （OMV 已決定：以 commit SHA 為準，封存檔 sha256 照記；核對失敗時改用 git clone 或標 GAP，不自動接受新的 sha256。建議其他封存檔比照。）
6. TrueNAS 的 App 層：只算公司自己的 App，還是使用者自己裝的第三方 App 也要列（D-026 範圍外，之後真的要掃時再決定）。
7. 只轉售 TrueNAS（不改 OS）的情況：OS 層的待辦在上游廠商，`project.yml` 要不要多一種角色「上游 OS 廠商負責、我們通知客戶」。
