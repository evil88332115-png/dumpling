# 平台研究：Raspberry Pi、Rockchip、AI NAS（WP7 第一階段）

C4 寫的研究筆記，給 M2 之後寫平台轉接器（`pipeline/platforms/<平台>/`）時用。這份文件只整理現況與建議，**不是決定**；
要定案的項目列在最後一節「待決定」，由 C0 統一問，決定寫進 `docs/DECISIONS.md`。

- 來源：sca-center 25fa89a 的 `scripts/wizard/platforms/{raspberrypi,rockchip}.json`、`scripts/demo/rpi_img.py`（#201）、
  `scripts/demo/rockchip_img.py`、`scripts/demo/flash_package.py`、`scripts/cra/bootloader_coverage.py`。
  C1 的 M1 會把這些檔案複製到 `tools/demo/`、`tools/cra/`、`tools/wizard/platforms/`；下面寫的行為以 25fa89a 為準。
- 公開示範資料（網址、大小、sha256、授權）見 `platform-samples/*/samples.yml`。
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
snapshot.debian.org 的固定網址（一般的 `deb.debian.org` pool 換版後舊檔會被移走）。應用層候選：OpenMediaVault 8.3.1 安裝 ISO（SourceForge，見 `samples.yml`）。

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
- OMV 的安裝 ISO 不是「已安裝的系統」，沒有可以直接掃的 rootfs（套件在 ISO 的 pool 裡）。要做「Debian＋OMV 已安裝」的示範映像，
  需要在 CI 裡安裝套件（會執行套件的安裝腳本）→ 跟「下載的檔案不執行」的規則怎麼劃界線要先決定（見下）。

## 共用下載核對能不能重用（回覆 C0）

`pipeline/lib/firmware_fetch.py`（C2）的 `curl_download`、`check_file`、`fetch_one`（https only、先下到 `.part`、核對大小與 sha256、拒絕 symlink、相符才改名）
**完全通用**，平台樣本可以直接用。不能直接用的只有 `validate()`：它寫死 `kind: bios|vbios`、`firmware_version`、`ibv` 這些韌體欄位。
建議（M2 時由 C1 決定）：把通用部分抽到 `pipeline/lib/fetch_verify.py`（或讓 PLAN 的共用 `fetch` 步驟直接 import `firmware_fetch.fetch_one`），
`sources.yml` 的 `files[]` 沿用 `firmware.yml` 的格式（`name`、`url`、`sha256`、`size`、`role`），這樣兩邊共用一份下載核對。
這次的 `platform-samples/*/samples.yml` 就是照 `firmware.yml` 的 `files[]` 格式寫的，M2 定出 `sources.yml` 後再搬過去。

## 待決定（由 C0 統一問）

1. Raspberry Pi 重新包的 Debian 套件（版本含 `+rpt`）算 bsp 還是 os？
2. AI NAS 的「OS 是不是我們的待辦」放在 `project.yml` 的哪個欄位（建議跟平台介面一起由 C1 在 M2 定）。
3. Rockchip 原始磁區的開機程式要用哪種方式清點（讀原始磁區，或從 rootfs 的 u-boot 套件清點再比對）。
4. AI NAS 示範要不要做「Debian＋OMV 已安裝」的映像：要在 CI 裡安裝套件（會執行官方套件的安裝腳本），還是只做「Debian 映像＋OMV 原始碼用 cdxgen 掃」兩條分開的路。
5. GitHub 動態封存檔（`raspberrypi/linux` tag、`radxa/kernel`、`radxa/u-boot`）要核對封存檔的 sha256，還是改成核對 git commit SHA。
