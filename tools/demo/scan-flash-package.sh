#!/usr/bin/env bash
# 廠商 Jetson 刷機包（例如 product-a_OrinNano_V1.0.2_a.tbz2）的弱點掃描：核對 MD5 → 清點刷機包（rootfs 的位置、L4T 版本、bootloader 檔案）
# → 把選定的 rootfs 轉成 tar（全部 rootfs 一次讀完）、docker import 成映像（不啟動容器）→ sca-scan（Syft、Grype、上傳常駐 DT）
# → CRA 文件草稿 → 套件依賴說明（<rootfs>/package-dependencies.md：漏洞多的套件為什麼在映像裡）→ 刪除暫存與映像。
#
# 用法：tools/demo/scan-flash-package.sh (--archive <tbz2> | --dir <解開的刷機包資料夾>) --rootfs <rootfs_no_gui|rootfs_gui|all>
#         --name <DT 專案名稱> --version <產品版本>
#         Rockchip：--archive 給 update.img，或裝著 update.img 的 zip（只取出 update.img，其他成員只記名稱與大小）；--rootfs rootfs（或 all）
#         Raspberry Pi OS 等原始磁碟映像（.img、.img.xz、.img.gz；MBR／GPT）：--archive 給映像，--rootfs rootfs；壓縮的先串流解壓到 <結果>/.work/disk.img
#           （B-img-extract；磁碟需求約等於未壓縮的映像，Pi OS lite 約 3 GB；結束時刪除）。boot 的 FAT 與 root 的 ext4 直接讀（rpi_img.py）；
#           B-bootloader-coverage 用 Raspberry Pi 的真實分類（GPU 韌體 GAP、EEPROM 不在映像裡）
#         [--md5 <檔案>]（--archive 預設 <tbz2>.md5（存在時）；--dir 要給逐檔的 md5 清單，沒有時 A-md5 記 NOT_RUN）
#         [--platform <jetson|raspberrypi|rockchip|generic>]（或環境變數 SCA_PLATFORM；由 project.yml 的 platform 明確傳入，不從映像格式推測。
#           原始磁碟映像（raw-disk-img*）沒給平台時，開機程式分類標 GAP「沒有指定平台，不推測」，不預設成 raspberrypi。
#           generic＝沒有定義開機鏈的平台（例如 x86 NAS）：任何映像格式的開機程式分類都走 `bootloader_coverage.py --not-assessed generic`，狀態 NOT_ASSESSED（不是 GAP）；
#           沒給平台（空值）仍然是 GAP（--unspecified））
#         [--arch <arm64|amd64>]（或環境變數 SCA_ARCH；預設 arm64：`docker import --platform linux/<arch>` 的架構，映像只匯入與讀取、不執行。其他值結束碼 64）
#         [--out <資料夾>]（預設 $HOME/sca-results/<name>-<version>-<UTC 時間>；FLASHPKG_RESULTS 改上層資料夾）
#         [--product-config <config.json>]（產品的 CRA 設定；沒有時產生只有產品名稱與版本的最小設定，其他欄位標 TO BE COMPLETED）
#         [--uefi-source <UEFI 原始碼樹>]（公司自建 UEFI 的原始碼：tools/cra/uefi_source.py 讀 edk2 版本與內建的 OpenSSL／Mbed TLS 版本 →
#           <rootfs>/uefi-source/，再用離線的 Grype 資料庫比對（tools/cra/uefi_bundled.py grype）；cra_report.py 把這些函式庫併進產品 SBOM、
#           比對結果成為風險表的列「OpenSSL x.y.z (bundled in UEFI)」。B-uefi-source-*、B-uefi-grype-*；版本不明／讀不到 → GAP。沒給時不執行）
#           給了 --uefi-source 又有 --archive／--dir 時另做 B-uefi-binary：刷機包裡每個 uefi_*.bin 的版本字串與內嵌除錯來源路徑對照這份原始碼樹
#           （bootloader_coverage.py uefi-check；MATCH＝與用這份原始碼建置一致，不是逐位元相同；<結果>/uefi-binary-check.json；
#           [--uefi-platform-defines <Kconfig 的 config.dsc.inc>]（可重複；DSC 有 !include 在建置時才產生的檔案時，沒有它佐證不成立）
#           [--uefi-platform-dsc <樹內的平台 DSC>]（可重複；例如 edk2-nvidia/Platform/NVIDIA/NVIDIA.common.dsc）：沒有它，Mbed TLS／OpenSSL 的 absent 不成立（字串可能被去光，要 DSC 佐證）
#           同一步也把映像解開找內建的 OpenSSL／Mbed TLS（uefi_image.py），結果在該檔的 libraries，cra_report 據此判 UB1／UB2）
#         [--tee-source <廠商公開原始碼資料夾>]（tos-optee_<soc>.img 的 OP-TEE 與 TF-A 是廠商用公開原始碼建的：tools/cra/tee_source.py 唯讀讀 TF-A、OP-TEE、
#           OP-TEE 內建 Mbed TLS 的版本（版本檔矛盾／讀不到 → 版本未知 → GAP、不給 CPE）→ <rootfs>/tee-source/，再用離線的 Grype 資料庫比對
#           （tools/cra/tee_bundled.py grype）；cra_report.py 併進產品 SBOM、風險表的列「Mbed TLS x.y.z (bundled in OP-TEE)」。
#           有 --archive／--dir 時同時對照刷機包的 tos-optee 映像（版本字串；與用這份原始碼建置一致，不是逐位元相同）。B-tee-source-*、B-tee-grype-*。沒給時不執行）
#         [--extra-deliverable <檔案>]（可重複；不在刷機包裡、另外交付給客戶的韌體，例如 bootloader capsule：記名稱、大小、sha256／512、可讀的版本字串、
#           配對的刷機包，併進產品 SBOM；版本與刷機包不同 → ATTENTION，讀不到版本 → GAP；只收一般檔案、不掃描。B-extra-deliverable）
#         [--with-license]（預設只做漏洞：sca-scan 加 --no-license；整個系統映像的授權匯入要好幾個小時）
#         [--prefix <rootfs 在刷機包裡的路徑>]（同一個 rootfs 名稱出現在多個位置時指定，例如 product-a/Linux_for_Tegra/rootfs_no_gui）
#         [--company <檔案> | --no-company]（CRA 的公司共用設定；預設 /etc/sca-gitlab/company.json，讀得到時）
#         [--manufacturer <名稱>]（沒有公司共用設定也沒有 --product-config 時，CRA 文件的製造商；都沒有時不產生 CRA 文件）
#         [--kernel-source <核心原始碼樹>]（同環境變數 KERNEL_SOURCE_DIR：Makefile／Kbuild 的來源，C-kernel-config 與 C-kernel-module-map 都收到）
#         [--kernel-version <核心版本>]（可重複；環境變數 SCA_KERNEL_VERSIONS 以空白或逗號分隔，兩者都給時以命令列為準。映像有不只一顆核心
#           （/usr/lib/modules/<版本>/，例如 Raspberry Pi 有 Pi 5 與 Pi 4 兩顆）時要判定哪一顆；原樣交給 sca-scan --kernel-version（只接受英數字開頭、
#           英數字與「. _ + ~ -」，否則 exit 64）。出貨但沒指定的核心記為「出貨但沒有判定」，C-kernel-config 與 C-kernel-module-map 至少 GAP；
#           指定 2 顆以上時一顆都不判定（多顆逐一判定還沒實作）。見 tools/pilot/sca-scan）
#         [--kernel-upstream-version <核心版本>=<X.Y.Z>]（可重複；平台設定給的上游版本，原樣交給 sca-scan --kernel-upstream-version，
#           和核心原始碼 Makefile 核對，不一致不採用；格式不對 exit 64）
#         [--kernel-in-other-report <報告名稱>]（環境變數 SCA_KERNEL_IN_OTHER_REPORT；分層的重跑（--rescan-from，SBOM 換成某一層的）用：
#           這份報告的 SBOM 沒有作業系統核心、核心在 <報告名稱> 那份報告判定。原樣交給 sca-scan --kernel-in-other-report：SBOM 真的沒有核心時，
#           C-kernel-cve-list、C-kernel-config、C-kernel-module-map 記 NOT_RUN「不適用」，不跑核心階段；SBOM 有核心時照舊。名稱只接受
#           ^[A-Za-z0-9][A-Za-z0-9._+-]{0,99}$，否則 exit 64。見 docs/LAYERS.md）
#         [--kernel-not-distro <理由>]（環境變數 SCA_KERNEL_NOT_DISTRO；平台負責人宣告核心不是發行版（Debian／Ubuntu）的核心，版本字串看不出來時用。
#           原樣交給 sca-scan --kernel-not-distro：SBOM 有核心時 C-kernel-coverage 是 GAP。不是空的、沒有控制字元、最多 300 位元組，否則 exit 64）
#         [--keep-image]（不刪 docker 映像）  [--no-upload]（不上傳 DT；只用於試跑，這時不需要 PILOT_ENV）
#         [--dt-vex]（選用，預設不做：CRA 的 VEX 寫回 DT 的 rootfs 專案，讓 DT finding 帶我們的 analysis；D-dt-vex-*-<rootfs>，讀回才算套用）
#         [--dt-product-components]（選用，預設不做：刷機包韌體／UEFI 內建函式庫／自有軟體另開 DT 專案「<名稱> / <版本> (product components)」；D-dt-product-*-<rootfs>）
#         [--decisions-from <上一次的結果資料夾>]（完整掃描也帶上一次的 vex-rules.json、vex-annotations.json、security-findings.json；
#           同一個產品名稱才帶，B-decisions-*）
#         [--evidence-out <資料夾>]（掃描完凍結證據包：tools/cra/evidence_bundle.py create，F-evidence；保存位置待公司決定，預設不做）
#       弱點資料新鮮度（含 --rescan-from）：每次先更新 Grype DB。GRYPE_DB_UPDATE=online（預設，現在）｜import:<鏡像檔案或 URL>（正式離線部署必須用這個）｜off（不更新）；
#         資料庫超過 GRYPE_DB_MAX_AGE_DAYS（預設 1 天＝24 小時）→ C-grype-db GAP；另有 C-grype-db-update、C-mirror-freshness（MIRROR_REFRESH_STATUS，空字串＝不檢查）。見 tools/pilot/README.md
#       tools/demo/scan-flash-package.sh --rescan-from <上一次的結果資料夾> [--archive <tbz2> | --dir <資料夾>] [--rootfs …]
#         [--name …] [--version …] [--out …]（其他選項同上）
#         只重跑比對：用上一次 Syft 產生的 SBOM（<上一次>/<rootfs>/scan/sbom/sbom.cdx.json）執行 sca-scan --sbom（Grype、DT、
#         核心對應表、NVIDIA 公告、發行版再判…都用最新的資料與程式），不再解壓、不 docker import。給 --archive／--dir（要是上一次的
#         同一個刷機包；上一次核對過 MD5 時會再比對 MD5）時另外從刷機包讀核心的 .config 與 Makefile（C-kernel-config）；沒給時那一列記 NOT_RUN。名稱、版本沒給時沿用上一次的。
#         上一次的 CRA/Config/vex-rules.json、vex-annotations.json、security-findings.json（批次規則、人工判定、安全測試的決定）
#         一起帶過來（B-rescan-config-*）；上一次匯入的板子檢查結果（<rootfs>/board-test/，tools/demo/board-import.sh）也帶過來，
#         用這次的 board_import.py 重寫 board-test.json（B-board-test-*）。
# 環境變數：PILOT_ENV（預設 $HOME/.config/sca-scan/pilot.env，常駐 DT；一定明確傳給 sca-scan，不讓它退回 repo 預設的設定）
#   核心判定的選用環境變數（原樣傳給 sca-scan，說明見 tools/pilot/sca-scan 開頭）：KERNEL_BUILD_RECORD（核心建置紀錄）、
#   KERNEL_SOURCE_DIR（核心原始碼樹，Makefile／Kbuild 的來源；廠商核心的 rootfs headers 不完整時）、KERNEL_CVES（明確給的核心 CVE 清單）、
#   KERNEL_OOT_BUILD_RECORDS（樹外模組的建置資料夾，冒號分隔）、KERNEL_STABLE_GIT（linux-stable 的本機 clone，唯讀）。
#   廠商核心（Grype、DT 都沒有核心 CVE，例如 SoC 廠商的 BSP 核心）有 KERNEL_CVE_MIRROR 時，sca-scan 依 /lib/modules/<版本> 或 Image 的版本字串從 CNA 鏡像產生清單（狀態列 C-kernel-cve-list）。
#
# 規則：
# - 刷機包是公司的機密產品：結果、暫存都放在 --out 底下（權限 700，umask 077），不放共用的 /tmp；結果不推送、不上傳到這台主機以外的地方
#   （DT、ScanCode.io、DejaCode 都是這台主機上的常駐環境；Grype 只下載弱點資料庫）。
# - Rockchip（--archive 是 update.img 或裝著它的 zip）：flash_package.py 讀 RKFW／RKAF 分割區表（超過 4 GB 的 32 位元溢位只在能證明時修正，
#   否則 B-rockchip GAP、不掃描），名稱是 rootfs 的 ext4 分割區用 Python 直接讀（不掛載、不用 debugfs／sudo）轉成同樣的 rootfs tar；
#   zip 先把 update.img 複製到 .work（B-rk-extract）。sca-scan 加 --kernel-build <update.img> --kernel-build-prefix rootfs：
#   C-kernel-config 讀 boot 分割區（FIT）的核心的 IKCONFIG（kernel/Image）。其他 ext4 分割區（oem、userdata）只清點。
# - 刷機包是不可信資料：flash_package.py 只用串流讀 tar 結構（--dir 時用 lstat 走訪、不跟隨符號連結），不解開到主機；
#   docker import 由 Docker 解開成映像，不啟動容器（映像是 arm64，這台機器不會執行裡面的程式）。
#   選定的 rootfs 在同一次讀取裡各自寫成 tar（壓縮檔只解壓一次）；每個 tar 在 import 後刪除，映像在掃描後刪除（--keep-image 保留）。
# - 只掃 rootfs 裡安裝的套件（dpkg 紀錄、Python 套件等，Syft 認得的）。bootloader、kernel、flash.sh 等刷機用的檔案只清點
#   （flash-inventory.json：路徑、大小、sha256、sha512、核心模組的 modinfo），壓縮檔旁邊的其他交付檔（MCU 韌體、文件、原始碼資料夾）只記名稱、大小、sha256、sha512。
#   這些不在 Syft 的 rootfs SBOM 裡；cra_report.py 產生產品 SBOM 時自動讀 <結果>/flash-inventory.json，把 flash 韌體、Jetson Linux 版本、
#   lib/modules/*/updates/ 底下的核心模組（NVIDIA 等 out-of-tree）、檔名符合 MCU 樣式（或 sbom.deliverable_firmware）的交付檔加進產品 SBOM（tools/cra/firmware_bom.py，sbom.md 第 6、7 節）。
# - 映像的靜態安全檢查（tools/cra/image_check.py → <rootfs>/image-check/：開機啟動的服務、sshd 設定、帳號、權限、私鑰、
#   ELF 強化、腳本與 modprobe.d 裡映像沒有的核心模組名稱）在 docker import 之前從 rootfs tar 讀（B-image-check-*）；只讀 tar 結構與內容，不執行映像裡的程式。
# - initrd 涵蓋（tools/cra/initrd_coverage.py → <rootfs>/initrd-coverage.json、.md，B-initrd-coverage-*）：rootfs 的 /boot/initrd* 在記憶體裡解壓，
#   裡面的每個 ELF／腳本若與 rootfs 的 dpkg 套件檔案 sha256 相同 → 「copy of <套件> <版本>」；否則 initrd-only（GAP）。bootloader/l4t_initrd.img 這類
#   只在燒錄時用的 initrd 另列、不分析。Rockchip 沒有定義開機鏈：B-bootloader-coverage-* 寫 NOT_ASSESSED 與說明檔。
# - 產品自有軟體（--product-config 有 sbom.own_software 時）：tools/cra/own_software.py 同樣在 docker import 之前從 rootfs tar 算列出的檔案的雜湊
#   → <rootfs>/own-software/own-software.json（B-own-software-*；列了但找不到 → GAP），cra_report.py 以 pkg:generic 元件併進產品 SBOM。
#   沒有 --product-config 或設定沒有列 sbom.own_software：B-own-software-* 記 GAP（沒有宣告自有軟體）；設定寫 own_software: [] 加
#   own_software_none_reason（明確宣告沒有）→ OK。--rescan-from：有 --archive／--dir 就重讀（設定可能改了），
#   否則沿用上一次的 own-software.json（cra_report 會把設定有、檔案裡沒有的樣式標 GAP）。
# - sca-scan 加 --no-package-scan --no-files-scan（整個系統映像的逐套件授權與檔案層級掃描太久）；預設再加 --no-license。
#   DT 的專案版本是「<產品版本> (<rootfs 名稱>)」（sca-scan --version）。
# - 每個階段寫一列到 <out>/status.tsv，最後 Z-done。退出碼：有 FAIL → 1，有其他非 OK → 2，全 OK → 0（OK 也不代表沒有弱點）。
set -uo pipefail
umask 077
ROOT=$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)
FP=$ROOT/tools/demo/flash_package.py
usage(){ sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; }
optval(){ [ $# -ge 2 ] || { echo "$1 要給值" >&2; usage >&2; exit 64; }; }   # 要值的選項在最後又沒給值時，不讓 shift 2 失敗而無窮迴圈
KVERS=()   # --kernel-version（可重複）／SCA_KERNEL_VERSIONS：要判定的核心版本
KUPS=()    # --kernel-upstream-version（可重複）：<核心版本>=<X.Y.Z>
KOTHER=; KOTHER_CLI=0         # --kernel-in-other-report／SCA_KERNEL_IN_OTHER_REPORT：核心在哪份報告判定（分層）
KNOTDISTRO=; KNOTDISTRO_CLI=0 # --kernel-not-distro／SCA_KERNEL_NOT_DISTRO：平台宣告核心不是發行版的核心（理由）

PLATFORM=${SCA_PLATFORM:-}
ARCH=${SCA_ARCH:-arm64}
ARCHIVE= SRCDIR= MD5= RFS= PREFIX= NAME= VERSION= OUT= PCONF= LICENSE=0 KEEP=0 NOUP=0 COMPANY= NOCOMP=0 MANUF= RESCAN= IC_NOTE= EVOUT= PROV_MD5= PROV_ST= DECFROM= UEFISRC= UEFIDSC=() TEESRC= EXTRAS=() DTVEX=${DT_VEX_WRITEBACK:-0} DTPROD=${DT_PRODUCT_COMPONENTS:-0}
while [ $# -gt 0 ]; do case $1 in
  --archive) optval "$@"; ARCHIVE=$2; shift 2;;
  --dir) optval "$@"; SRCDIR=$2; shift 2;;
  --md5) optval "$@"; MD5=$2; shift 2;;
  --rootfs) optval "$@"; RFS=$2; shift 2;;
  --prefix) optval "$@"; PREFIX=$2; shift 2;;
  --name) optval "$@"; NAME=$2; shift 2;;
  --version) optval "$@"; VERSION=$2; shift 2;;
  --out) optval "$@"; OUT=$2; shift 2;;
  --platform) optval "$@"; PLATFORM=$2; shift 2;;
  --arch) optval "$@"; ARCH=$2; shift 2;;
  --product-config) optval "$@"; PCONF=$2; shift 2;;
  --vuln-only) LICENSE=0; shift;;
  --with-license) LICENSE=1; shift;;
  --keep-image) KEEP=1; shift;;
  --no-upload) NOUP=1; shift;;
  --dt-vex) DTVEX=1; shift;;
  --dt-product-components) DTPROD=1; shift;;
  --company) optval "$@"; COMPANY=$2; shift 2;;
  --manufacturer) optval "$@"; MANUF=$2; shift 2;;
  --no-company) NOCOMP=1; shift;;
  --rescan-from) optval "$@"; RESCAN=$2; shift 2;;
  --evidence-out) optval "$@"; EVOUT=$2; shift 2;;
  --decisions-from) optval "$@"; DECFROM=$2; shift 2;;
  --uefi-source) optval "$@"; UEFISRC=$2; shift 2;;
  --uefi-platform-defines) optval "$@"; UEFIDSC+=(--platform-defines "$2"); shift 2;;
  --uefi-platform-dsc) optval "$@"; UEFIDSC+=(--platform-dsc "$2"); shift 2;;
  --tee-source) optval "$@"; TEESRC=$2; shift 2;;
  --extra-deliverable) optval "$@"; EXTRAS+=("$2"); shift 2;;
  --kernel-source) optval "$@"; [ -d "$2" ] || { echo "--kernel-source 要是資料夾：$2" >&2; exit 64; }; export KERNEL_SOURCE_DIR=$(readlink -f -- "$2"); shift 2;;
  --kernel-version) optval "$@"; KVERS+=("$2"); shift 2;;
  --kernel-upstream-version) optval "$@"; KUPS+=("$2"); shift 2;;
  --kernel-in-other-report) optval "$@"; KOTHER=$2; KOTHER_CLI=1; shift 2;;
  --kernel-not-distro) optval "$@"; KNOTDISTRO=$2; KNOTDISTRO_CLI=1; shift 2;;
  -h|--help) usage; exit 0;;
  *) echo "不認得的參數：$1" >&2; usage >&2; exit 64;;
esac; done
case $PLATFORM in ""|jetson|raspberrypi|rockchip|generic) ;; *) echo "--platform（SCA_PLATFORM）只接受 jetson、raspberrypi、rockchip、generic：$PLATFORM" >&2; exit 64;; esac
case $ARCH in arm64|amd64) ;; *) echo "--arch（SCA_ARCH）只接受 arm64、amd64：$ARCH" >&2; exit 64;; esac
if [ -n "$ARCHIVE" ] && [ -n "$SRCDIR" ]; then echo "--archive 與 --dir 只能選一個" >&2; exit 64; fi
if [ -n "$DECFROM" ]; then
  [ -z "$RESCAN" ] || { echo "--decisions-from 只用於完整掃描（--rescan-from 本來就帶上一次的判定檔）" >&2; exit 64; }
  [ -f "$DECFROM/list.json" ] || { echo "--decisions-from 要是上一次 scan-flash-package.sh 的結果資料夾（有 list.json）：$DECFROM" >&2; exit 64; }
  DECFROM=$(readlink -f "$DECFROM")
fi
if [ -n "$RESCAN" ]; then
  # 重跑：上一次的結果資料夾（list.json 與各 rootfs 的 SBOM）；刷機包只用來讀核心的建置設定，可以不給
  [ -f "$RESCAN/list.json" ] || { echo "--rescan-from 要是上一次 scan-flash-package.sh 的結果資料夾（有 list.json）：$RESCAN" >&2; exit 64; }
  RESCAN=$(readlink -f "$RESCAN"); [ -n "$PREFIX" ] && RFS=${RFS:-$(basename "$PREFIX")}; RFS=${RFS:-all}
  [ -z "$MD5" ] || { echo "--rescan-from 不核對 MD5（沿用上一次的結果）" >&2; exit 64; }
  [ -z "$SRCDIR" ] || [ -d "$SRCDIR" ] || { echo "不是資料夾：--dir $SRCDIR" >&2; exit 64; }
  [ -z "$ARCHIVE" ] || [ -f "$ARCHIVE" ] || { echo "找不到 --archive $ARCHIVE" >&2; exit 64; }
  # 名稱與版本沒給時沿用上一次 sca-scan 的 meta.json（版本是「<產品版本> (<rootfs>)」）
  for m in "$RESCAN"/*/scan/meta.json; do
    [ -f "$m" ] || continue
    nv=$(python3 -I -c 'import json,re,sys;m=json.load(open(sys.argv[1]));print((m.get("name") or "")+"\t"+re.sub(r" \([^()]*\)$","",m.get("version") or ""))' "$m" 2>/dev/null) || continue
    [ -n "$NAME" ] || NAME=${nv%%$'\t'*}; [ -n "$VERSION" ] || VERSION=${nv#*$'\t'}; break
  done
elif [ -n "$SRCDIR" ]; then [ -d "$SRCDIR" ] || { echo "不是資料夾：--dir $SRCDIR" >&2; exit 64; }
else [ -f "$ARCHIVE" ] || { echo "需要 --archive <tbz2> 或 --dir <資料夾>（找不到：${ARCHIVE:-未指定}）" >&2; exit 64; }; fi
[ -n "$NAME" ] && [ -n "$VERSION" ] || { echo "需要 --name 與 --version" >&2; exit 64; }
# --version 會變成 DT 的專案版本「<版本> (<rootfs>)」：和 sca-scan --version 一樣只收安全的字元
[[ "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._+~-]{0,79}$ ]] || { echo "--version 只接受英數字開頭、英數字與「. _ + ~ -」，最多 80 字元" >&2; exit 64; }
case $RFS in rootfs_no_gui|rootfs_gui|rootfs|all) ;; *) echo "--rootfs 要是 rootfs_no_gui、rootfs_gui、rootfs 或 all" >&2; exit 64;; esac
[ -n "$PREFIX" ] && [ "$RFS" = all ] && { echo "--prefix 只能配單一個 rootfs" >&2; exit 64; }
[ -n "$PREFIX" ] && [ "$(basename "$PREFIX")" != "$RFS" ] && { echo "--prefix 的最後一層要是 $RFS" >&2; exit 64; }
[ -z "$PCONF" ] || [ -f "$PCONF" ] || { echo "找不到 --product-config $PCONF" >&2; exit 64; }
[ -z "$COMPANY" ] || [ -r "$COMPANY" ] || { echo "讀不到 --company $COMPANY" >&2; exit 64; }
[ -n "$COMPANY" ] && [ $NOCOMP = 1 ] && { echo "--company 與 --no-company 只能選一個" >&2; exit 64; }
[ -z "$MD5" ] || [ -r "$MD5" ] || { echo "讀不到 --md5 $MD5" >&2; exit 64; }
# --kernel-version／SCA_KERNEL_VERSIONS：命令列有給就不看環境變數；只收英數字開頭、英數字與「. _ + ~ -」（不含 shell 特殊字元、「/」、空白），其餘 exit 64。
# 值原樣交給 sca-scan（sca_args），核心工具自己另有檢查
kernel_versions_args(){
  local t kv uniq=() LC_ALL=C      # 字元範圍 [A-Za-z] 在 UTF-8 地區設定下可能含重音字母
  if [ ${#KVERS[@]} -eq 0 ] && [ -n "${SCA_KERNEL_VERSIONS:-}" ]; then
    kv=${SCA_KERNEL_VERSIONS//,/ }; set -f
    for t in $kv; do KVERS+=("$t"); done
    set +f
  fi
  for t in "${KVERS[@]+"${KVERS[@]}"}"; do
    [[ "$t" =~ ^[A-Za-z0-9][A-Za-z0-9._+~-]{0,99}$ ]] \
      || { echo "核心版本只接受英數字開頭、英數字與「. _ + ~ -」，最多 100 字元（--kernel-version／SCA_KERNEL_VERSIONS）：${t:0:120}" >&2; exit 64; }
    case " ${uniq[*]+"${uniq[*]}"} " in *" $t "*) ;; *) uniq+=("$t");; esac
  done
  KVERS=("${uniq[@]+"${uniq[@]}"}")
}
kernel_versions_args
kernel_upstream_args(){
  local t LC_ALL=C
  for t in "${KUPS[@]+"${KUPS[@]}"}"; do
    [[ "$t" =~ ^[A-Za-z0-9][A-Za-z0-9._+~-]{0,99}=[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}$ ]] \
      || { echo "--kernel-upstream-version 要是 <核心版本>=<X.Y.Z>：${t:0:120}" >&2; exit 64; }
  done
}
kernel_upstream_args
# --kernel-in-other-report／--kernel-not-distro：命令列有給就不看環境變數；規則同 sca-scan（值原樣交給 sca-scan，它另有同樣的檢查）
kernel_layer_args(){
  local LC_ALL=C
  [ "$KOTHER_CLI" = 1 ] || KOTHER=${SCA_KERNEL_IN_OTHER_REPORT:-}
  if [ "$KOTHER_CLI" = 1 ] || [ -n "$KOTHER" ]; then
    [[ "$KOTHER" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,99}$ ]] \
      || { echo "報告名稱只接受英數字開頭、英數字與「. _ + -」，最多 100 字元（--kernel-in-other-report／SCA_KERNEL_IN_OTHER_REPORT）：${KOTHER:0:120}" >&2; exit 64; }
  fi
  [ "$KNOTDISTRO_CLI" = 1 ] || KNOTDISTRO=${SCA_KERNEL_NOT_DISTRO:-}
  if [ "$KNOTDISTRO_CLI" = 1 ] || [ -n "$KNOTDISTRO" ]; then
    { [ -n "${KNOTDISTRO//[[:space:]]/}" ] && [ ${#KNOTDISTRO} -le 300 ] && ! [[ "$KNOTDISTRO" =~ [[:cntrl:]] ]]; } \
      || { echo "--kernel-not-distro／SCA_KERNEL_NOT_DISTRO 的理由不能是空的、不能有控制字元、最多 300 位元組：${KNOTDISTRO:0:120}" >&2; exit 64; }
  fi
}
kernel_layer_args
[ "$(id -u)" != 0 ] || { echo "不要用 root 執行（sca-scan 的沙箱要求非 root）；用常駐環境的帳號（sudo -u <帳號>）" >&2; exit 64; }
# sudo -u 時 HOME 可能還是呼叫者的：sca-scan 的 Grype 資料庫在 $HOME/.cache，改成這個帳號自己的家目錄
H=$(getent passwd "$(id -un)" | cut -d: -f6); [ -n "$H" ] && [ "$HOME" != "$H" ] && export HOME=$H
# 相對路徑先變成絕對路徑（之後 cd 到結果資料夾；呼叫者的目前資料夾，這個帳號不一定進得去）
abs(){ [ -n "$1" ] && readlink -f "$1"; }
[ -z "$UEFISRC" ] || [ -d "$UEFISRC" ] || { echo "不是資料夾：--uefi-source $UEFISRC" >&2; exit 64; }
[ -z "$TEESRC" ] || [ -d "$TEESRC" ] || { echo "不是資料夾：--tee-source $TEESRC" >&2; exit 64; }
# 另外交付的韌體：只收一般檔案（符號連結、資料夾、特殊檔案都拒絕；只讀這裡給的檔案）
for f in "${EXTRAS[@]+"${EXTRAS[@]}"}"; do
  [ ! -L "$f" ] && [ -f "$f" ] && [ -r "$f" ] || { echo "--extra-deliverable 要是讀得到的一般檔案（不收符號連結）：$f" >&2; exit 64; }
done
for i in "${!EXTRAS[@]}"; do EXTRAS[$i]=$(abs "${EXTRAS[$i]}"); done
ARCHIVE=$(abs "$ARCHIVE"); SRCDIR=$(abs "$SRCDIR"); UEFISRC=$(abs "$UEFISRC"); TEESRC=$(abs "$TEESRC"); MD5=$(abs "$MD5"); PCONF=$(abs "$PCONF"); COMPANY=$(abs "$COMPANY")
[ -z "$EVOUT" ] || EVOUT=$(readlink -m -- "$EVOUT")   # -m：上層資料夾還不存在也照樣（evidence_bundle.py 會建）
[ -n "$ARCHIVE" ] && [ -z "$MD5" ] && [ -f "$ARCHIVE.md5" ] && MD5=$ARCHIVE.md5
if [ -n "$ARCHIVE" ]; then SRC=(--archive "$ARCHIVE"); SRCNAME=$(basename "$ARCHIVE"); elif [ -n "$SRCDIR" ]; then SRC=(--dir "$SRCDIR"); SRCNAME=$(basename "$SRCDIR")
else SRC=(); SRCNAME=; fi
# Rockchip update.img（開頭 RKFW）或 zip：RKFMT 不是空的。Jetson 的 tbz2 是空的，以下所有 Rockchip 的分支都不走（行為不變）
RKFMT=; RKIMG=
if [ -n "$ARCHIVE" ]; then RKFMT=$(python3 -I "$FP" format --archive "$ARCHIVE" 2>/dev/null); case $RKFMT in rockchip-img|rockchip-zip|raw-disk-img|raw-disk-img-xz|raw-disk-img-gz) ;; *) RKFMT=;; esac; fi
safe(){ printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '-' | sed 's/^-*//; s/-*$//' | cut -c1-80; }
if [ -z "$OUT" ]; then
  RES=${FLASHPKG_RESULTS:-$HOME/sca-results}
  mkdir -p "$RES" && chmod 700 "$RES" || { echo "無法建立 $RES（用 --out 指定這個帳號可寫的資料夾）" >&2; exit 64; }
  OUT=$RES/$(safe "$NAME")-$(safe "$VERSION")-$(date -u +%Y%m%dT%H%M%SZ)${RESCAN:+-rescan}
fi
if [ -e "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then echo "輸出資料夾已存在且不是空的：$OUT（不混用舊結果）" >&2; exit 64; fi
mkdir -p "$OUT" && chmod 700 "$OUT" || { echo "無法建立 $OUT" >&2; exit 64; }
OUT=$(cd "$OUT" && pwd); WORK=$OUT/.work; mkdir -m 700 -p "$WORK"
# 測試（pytest 的暫存區在 /tmp）才設 FLASHPKG_ALLOW_TMP_OUT=1
[ "${FLASHPKG_ALLOW_TMP_OUT:-0}" = 1 ] || case $OUT in /tmp/*|/var/tmp/*|/dev/shm/*) echo "--out 不要放在共用的暫存區（$OUT）：機密資料" >&2; rm -rf "$WORK"; rmdir "$OUT" 2>/dev/null; exit 64;; esac
cd "$OUT" || exit 64
# 停止這次執行：kill 整個行程群組（含 python、sca-scan、syft）；trap 會刪除暫存 tar 與映像
PGID=$(ps -o pgid= -p $$ | tr -d ' '); printf '%s\n' "$$" > "$OUT/pid"; printf '%s\n' "$PGID" > "$OUT/pgid"
echo "OUT=$OUT"
echo "PGID=$PGID（停止：sudo kill -TERM -- -$PGID）"

ST=$OUT/status.tsv; printf 'stage\tstatus\tdetail\n' > "$ST"
status(){ local d; d=$(printf '%s' "${3:-}" | tr '\n\t\r' '   ' | cut -c1-500 | iconv -f UTF-8 -t UTF-8 -c); printf '%s\t%s\t%s\n' "$1" "$2" "$d" >> "$ST"; echo "[$2] $1 $d"; }
declare -A IID=()
PENDING_TAG=      # docker import 進行中的標籤：中斷時 import 可能已經完成，以標籤刪除
CLEANED=0
cleanup(){  # 暫存的 rootfs tar 與映像：每個 rootfs 掃完就刪；這裡是結束（含中斷）時的保險
  [ $CLEANED = 1 ] && return; CLEANED=1
  local v
  if [ $KEEP = 0 ]; then for v in "${!IID[@]}"; do docker image rm -f "${IID[$v]}" > /dev/null 2>&1 && status "Z-cleanup-image-$v" OK "刪除映像 ${IID[$v]}"; done; fi
  if [ -n "$PENDING_TAG" ]; then docker image rm -f "$PENDING_TAG" > /dev/null 2>&1 && status Z-cleanup-image OK "刪除中斷時的映像 $PENDING_TAG"; fi
  rm -rf "$WORK"
}
finish(){
  cleanup
  [ -n "$EVOUT" ] && ! grep -q $'^F-evidence\t' "$ST" && status F-evidence NOT_RUN "掃描沒有跑到摘要（見上面的 FAIL）：沒有凍結證據包"
  local x; x=$(awk -F'\t' 'NR>1 && $1!="Z-done"{ if($2=="FAIL") f=1; else if($2!="OK" && $2!="INFO") n=1 } END{ print f?1:(n?2:0) }' "$ST")
  status Z-done INFO "scan-flash-package.sh 跑完（退出碼 $x）；結果 $OUT"; exit "$x"; }
trap 'cleanup' EXIT
trap 'status Z-interrupted FAIL "中斷"; finish' INT TERM HUP
# list.json／pick 來的欄位不可信（來自刷機包的成員名稱）：變體名稱、前綴、位元組數先用白名單驗證才進路徑與算術
# （位元組數只允許數字：$(( )) 會把 a[$(cmd)] 當成算式執行）。含 TAB／換行的前綴在 flash_package.py 就已拒絕，這裡是第二道
pick_fields_ok(){   # 參數：變體 前綴 [位元組數；沒給就不驗]
  local LC_ALL=C         # [0-9]、[A-Za-z] 只比對 ASCII（不比對其他語系的數字、字母）
  [[ $1 =~ ^(rootfs_no_gui|rootfs_gui|rootfs)$ ]] || return 1
  [[ $2 =~ ^[A-Za-z0-9._+\ -]+(/[A-Za-z0-9._+\ -]+)*$ ]] || return 1
  case /$2/ in */../*|*/./*|*/-*) return 1;; esac      # 不接受 ..、. 與 - 開頭的元件（會被當成選項）
  if [ $# -ge 3 ]; then [[ $3 =~ ^[0-9]+$ ]] || return 1; fi
  return 0
}
free_bytes(){ df -B1 --output=avail "$1" 2>/dev/null | tail -1 | tr -d ' '; }
gib(){ awk -v b="${1:-0}" 'BEGIN{printf "%.1f GiB", b/1073741824}'; }
scan_worst(){  # 同 jetson.sh：sca-scan 的 status.tsv → 最嚴重的狀態；刻意不做的 NOT_RUN（逐套件、檔案層級；只做漏洞時整個 E 段）不算
  [ -f "$1" ] && grep -q $'^F-secret-scan\t' "$1" || { echo FAIL; return; }
  awk -F'\t' -v vo="$((1-LICENSE))" 'BEGIN{vo=(vo=="1");r["OK"]=0;r["INFO"]=0;r["ATTENTION"]=1;r["NOT_RUN"]=2;r["GAP"]=3;r["NOT_ASSESSED"]=4;r["FAIL"]=5;w="OK";m=0}
    NR>1 && !($2=="NOT_RUN" && ($1 ~ /^E-(package-scan-submit|package-scans|package-scan-update|license-sync|copyrights|files-scan)$/ || (vo && $1 ~ /^E-/))) {
      v=(($2 in r)?r[$2]:5); if(v>m){m=v;w=(($2 in r)?$2:"FAIL")} } END{print (NR<2?"FAIL":w)}' "$1"; }

cra_step(){
  # ---------- D. CRA 文件草稿（每個 rootfs；一般掃描與 --rescan-from 共用） ----------
  local v=$1 D=$OUT/$1 P ca cnote mf r x s
  [ -d "$D/scan" ] && [ -f "$D/scan/status.tsv" ] || { status "D-cra-$v" NOT_RUN "沒有 sca-scan 結果"; return; }
  P=$D/cra-project; mkdir -p "$P/CRA/Config"
  ca=(); cnote=
  if [ $NOCOMP = 1 ]; then ca=(--no-company); cnote="不用公司共用設定（--no-company）"
  elif [ -n "$COMPANY" ]; then ca=(--company "$COMPANY"); cnote="公司共用設定 $COMPANY"
  elif [ -r /etc/sca-gitlab/company.json ]; then ca=(--company /etc/sca-gitlab/company.json); cnote="公司共用設定 /etc/sca-gitlab/company.json"
  else ca=(--no-company); cnote="讀不到 /etc/sca-gitlab/company.json"; fi
  if [ -n "$PCONF" ]; then cp "$PCONF" "$P/CRA/Config/config.json"; cnote="產品設定 $PCONF；$cnote"
  else
    # cra_report 一定要製造商名稱；不放假的名稱（會被當成「已提供」，也會寫進產品 SBOM）
    if [ "${ca[0]}" != --company ] && [ -z "$MANUF" ]; then
      status "D-cra-$v" NOT_RUN "沒有製造商名稱（$cnote，也沒有 --manufacturer 或 --product-config）：不產生 CRA 文件；掃描結果在 $D/scan"; return; fi
    mf=(); [ -n "$MANUF" ] && mf=(--manufacturer "$MANUF")
    python3 -I "$FP" cra-config --list "$OUT/list.json" --variant "$v" --name "$NAME" --version "$VERSION" ${MD5SUM:+--md5 "$MD5SUM"} \
      "${mf[@]}" --out "$P/CRA/Config/config.json" 2> "$D/logs/cra-config.err" \
      || { status "D-cra-$v" FAIL "產生 config.json 失敗：$(tail -1 "$D/logs/cra-config.err")"; return; }
    cnote="產生的最小設定（只有產品名稱、版本、識別$([ -n "$MANUF" ] && echo "、製造商 --manufacturer")）；$cnote"
  fi
  r=$(python3 -I "$ROOT/tools/cra/cra_report.py" --project "$P" --scan "$D/scan" "${ca[@]}" 2> "$D/logs/cra.err"); x=$?
  s=${r%%$'\t'*}; case $s in OK|ATTENTION|GAP|NOT_ASSESSED|FAIL) ;; *) s=FAIL;; esac; [ $x = 1 ] && s=FAIL
  status "D-cra-$v" "$s" "$cnote；${r#*$'\t'}"
}
dtwb_step(){
  # ---------- 選用：把我們的分析寫回 DT（tools/cra/dt_writeback.py；--dt-vex、--dt-product-components 或環境變數 DT_VEX_WRITEBACK=1、DT_PRODUCT_COMPONENTS=1） ----------
  # 都沒要求時什麼都不做、不寫狀態列（輸出和沒有這一步時相同）。上傳成功、處理完成、分析套用各自一列；沒對上的 VEX 陳述是 ATTENTION。
  [ "$DTVEX" = 1 ] || [ "$DTPROD" = 1 ] || return 0
  local v=$1 D=$OUT/$1 wa=() s1 s2 s3 n=0 x r
  [ "$DTVEX" = 1 ] && wa+=(--vex); [ "$DTPROD" = 1 ] && wa+=(--product-components)
  if [ $NOUP = 1 ]; then status "D-dt-writeback-$v" NOT_RUN "--no-upload"; return; fi
  if [ ! -s "$D/cra-project/CRA/Reports/vex.cdx.json" ] || [ ! -s "$D/cra-project/CRA/Reports/sbom.cdx.json" ]; then
    status "D-dt-writeback-$v" NOT_RUN "沒有 CRA 的 vex.cdx.json／sbom.cdx.json（D-cra-$v 沒有產生文件）"; return; fi
  mkdir -p "$D/dt-writeback"
  r=$(python3 -I "$ROOT/tools/cra/dt_writeback.py" --reports "$D/cra-project/CRA/Reports" --scan "$D/scan" --out "$D/dt-writeback" --env "$PILOT_ENV" "${wa[@]}" 2> "$D/logs/dt-writeback.err"); x=$?
  while IFS=$'\t' read -r s1 s2 s3; do
    [ -n "$s1" ] || continue
    case $s2 in OK|ATTENTION|GAP|NOT_RUN|NOT_ASSESSED|FAIL) ;; *) s2=FAIL;; esac
    status "$s1-$v" "$s2" "$s3"; n=$((n+1))
  done <<< "$r"
  [ $n -gt 0 ] || status "D-dt-writeback-$v" FAIL "dt_writeback.py 沒有輸出狀態（exit $x）：$(tail -1 "$D/logs/dt-writeback.err" 2>/dev/null)"
}
pkgdb_step(){
  # 映像的 var/lib/dpkg/status 與 var/lib/apt/extended_states → <rootfs>/pkgdb/（給 pkg_why.py 寫套件依賴說明；只讀這兩個成員）
  local v=$1 from=$2 r; shift 2
  r=$(python3 -I "$ROOT/tools/cra/pkg_why.py" extract --from "$from" "$@" --out "$OUT/$v/pkgdb" 2> "$OUT/$v/logs/pkgdb.err" | grep -m1 $'^PKGDB\t')
  [ -n "$r" ] || r=$'PKGDB\tFAIL\tpkg_why.py extract 失敗：'"$(tail -1 "$OUT/$v/logs/pkgdb.err" 2>/dev/null)"
  IFS=$'\t' read -r _ s d <<< "$r"; status "B-pkgdb-$v" "$s" "$d"
  [ "$s" = FAIL ] || pyver_step "$v" "$from" "$@"
}
pyver_step(){
  # Debian 打包的 Python 模組的 egg-info 版本是 0.0.0 等佔位值時，用擁有它的 dpkg 套件的上游版本 → <rootfs>/pkgdb/python-versions.json
  # （py_dpkg_version.py；來源和 pkgdb_step 一樣，只讀；cra_report.py 讀它，版本和出處寫進報告。判定不一致或沒有擁有者 → 版本仍然未知）
  local v=$1 from=$2 r s d x; shift 2
  [ -s "$OUT/$v/pkgdb/dpkg-status" ] || return 0
  rm -f "$OUT/$v/pkgdb/python-versions.json"       # 不留上一次的檔案冒充這次的
  r=$(timeout --foreground -k 30 "${PYVER_TIMEOUT:-3600}" python3 -I "$ROOT/tools/cra/py_dpkg_version.py" scan --from "$from" "$@" --pkgdb "$OUT/$v/pkgdb" 2> "$OUT/$v/logs/pyver.err"); x=$?
  r=$(grep -m1 $'^PYVER\t' <<< "$r")
  [ -n "$r" ] || r=$'PYVER\tFAIL\tpy_dpkg_version.py 失敗（exit '"$x）：$(tail -1 "$OUT/$v/logs/pyver.err" 2>/dev/null)"
  IFS=$'\t' read -r _ s d <<< "$r"
  # 失敗不擋掃描：沒有 python-versions.json → sca-scan 用沒有改過的 SBOM（佔位值版本的 Python 模組仍未解析），明確記 GAP
  if [ "$s" = FAIL ] || [ ! -s "$OUT/$v/pkgdb/python-versions.json" ]; then rm -f "$OUT/$v/pkgdb/python-versions.json"
    status "B-pyver-$v" GAP "$d；佔位值版本的 Python 模組沒有解析，掃描照用沒有改過的 SBOM"; return 0; fi
  status "B-pyver-$v" "$s" "$d"
}
imgcheck_step(){
  # 映像的靜態安全檢查 → <rootfs>/image-check/（開機啟動的服務、sshd 設定、帳號、權限、私鑰、ELF 強化、腳本裡的核心模組名稱；tools/cra/image_check.py）
  # 映像是不可信資料：整個檢查有時間上限（IMGCHECK_TIMEOUT 秒，預設 7200；刷機包要整個解壓），逾時記 FAIL。
  # --foreground：timeout 留在這次執行的行程群組，停止指令（kill -TERM -- -$PGID）才停得到它與 python、lbzip2
  local v=$1 from=$2 r s d x t0 lim=${IMGCHECK_TIMEOUT:-7200}; shift 2; t0=$(date +%s)
  r=$(timeout --foreground -k 30 "$lim" python3 -I "$ROOT/tools/cra/image_check.py" --from "$from" "$@" --out "$OUT/$v/image-check" 2> "$OUT/$v/logs/image-check.err"); x=$?
  r=$(grep -m1 $'^D-image-check\t' <<< "$r")
  if [ $x = 124 ]; then r=$'D-image-check\tFAIL\t'"image_check.py 逾時（${lim} 秒）"
  elif [ $x = 137 ] && [ $(( $(date +%s) - t0 )) -ge "${lim%.*}" ]; then r=$'D-image-check\tFAIL\t'"image_check.py 逾時（${lim} 秒，TERM 後 30 秒還沒結束，KILL）"
  elif [ $x -gt 128 ]; then r=$'D-image-check\tFAIL\t'"image_check.py 被訊號 $((x-128)) 結束（exit $x；例如記憶體不足被 KILL）：$(tail -1 "$OUT/$v/logs/image-check.err" 2>/dev/null)"
  elif [ -z "$r" ]; then r=$'D-image-check\tFAIL\timage_check.py 失敗（exit '"$x）：$(tail -1 "$OUT/$v/logs/image-check.err" 2>/dev/null)"; fi
  IFS=$'\t' read -r _ s d <<< "$r"; status "B-image-check-$v" "$s" "${IC_NOTE:+$IC_NOTE；}$d$([ "$s" = FAIL ] || echo "；$v/image-check/image-check.md")"
}
ownsw_step(){
  # 產品自有軟體（產品設定 sbom.own_software）→ <rootfs>/own-software/own-software.json（tools/cra/own_software.py；cra_report.py 併進產品 SBOM）。
  # 沒有 --product-config 或設定沒有列 sbom.own_software：檢查不可以悄悄消失 → own_software.py --declaration 寫一列
  # （沒宣告 → GAP「沒有宣告自有軟體」；sbom.own_software: [] 加 sbom.own_software_none_reason → OK，說明寫理由），
  # 也寫 own-software.json（只有宣告的結果），cra_report.py 讀到它在 SBOM 文件標出來
  local v=$1 from=$2 r s d x c=0 lim=${OWNSW_TIMEOUT:-7200}; shift 2
  [ -n "$PCONF" ] && { python3 -I "$ROOT/tools/cra/own_software.py" --config "$PCONF" --configured 2> /dev/null || c=$?; }
  [ -n "$PCONF" ] || c=1
  if [ "$c" != 0 ]; then
    if [ "$c" = 1 ]; then
      local da=(); [ -n "$PCONF" ] && da=(--config "$PCONF")
      r=$(python3 -I "$ROOT/tools/cra/own_software.py" "${da[@]+"${da[@]}"}" --declaration --out "$OUT/$v/own-software" 2> "$OUT/$v/logs/own-software.err"); x=$?
      r=$(grep -m1 $'^B-own-software\t' <<< "$r")
      [ -n "$r" ] || r=$'B-own-software\tFAIL\town_software.py --declaration 失敗（exit '"$x）：$(tail -1 "$OUT/$v/logs/own-software.err" 2>/dev/null)"
      IFS=$'\t' read -r _ s d <<< "$r"
      case "$s:$x" in OK:0|GAP:2|FAIL:*) ;; *) d="own_software.py 印出 ${s:-（沒有狀態）} 但 exit $x：${d}"; s=FAIL;; esac
    else s=FAIL; d="讀不到產品設定（own_software.py --configured exit $c）"; fi
    status "B-own-software-$v" "$s" "$d"
    return 0
  fi
  r=$(timeout --foreground -k 30 "$lim" python3 -I "$ROOT/tools/cra/own_software.py" --from "$from" "$@" --config "$PCONF" \
        --out "$OUT/$v/own-software" 2> "$OUT/$v/logs/own-software.err"); x=$?
  printf '%s\n' "$r" > "$OUT/$v/logs/own-software.txt"
  r=$(grep -m1 $'^B-own-software\t' <<< "$r")
  if [ $x = 124 ] || [ $x = 137 ]; then r=$'B-own-software\tFAIL\t'"own_software.py 逾時（${lim} 秒）或被 KILL"
  elif [ -z "$r" ]; then r=$'B-own-software\tFAIL\town_software.py 失敗（exit '"$x）：$(tail -1 "$OUT/$v/logs/own-software.err" 2>/dev/null)"; fi
  IFS=$'\t' read -r _ s d <<< "$r"
  # 狀態和退出碼要對得上（OK 0、GAP 2）；對不上或不認得的狀態 → FAIL（同 cra_step：不讓印出來的 OK 蓋過失敗的退出碼）
  case "$s:$x" in OK:0|GAP:2|FAIL:*) ;; *) d="own_software.py 印出 ${s:-（沒有狀態）} 但 exit $x：${d}"; s=FAIL;; esac
  status "B-own-software-$v" "$s" "$d$([ "$s" = FAIL ] || echo "；GAP 與版本未知的明細在 $v/logs/own-software.txt")"
}
uefisrc_step(){
  # UEFI 原始碼樹（--uefi-source）→ <rootfs>/uefi-source/（uefi_source.py：edk2、內建 OpenSSL／Mbed TLS 的版本與 CPE）→ 離線 Grype（uefi_bundled.py grype）。
  # 第二個參數 reuse：--rescan-from 沒給樹時，沿用上一次的 uefi-source.cdx.json／uefi-source.json，只用現在的資料庫重新比對。
  # 沒給 --uefi-source（也不是 reuse）→ 什麼都不做（不寫狀態列、不建資料夾，結果和沒有這一步時相同）
  local v=$1 mode=${2:-} U=$OUT/$1/uefi-source r s d x lim=${UEFISRC_TIMEOUT:-3600}
  if [ "$mode" = reuse ]; then
    mkdir -p "$U" && cp -- "$RESCAN/$v/uefi-source/uefi-source.cdx.json" "$RESCAN/$v/uefi-source/uefi-source.json" "$U/" 2> /dev/null \
      && { if [ -f "$RESCAN/$v/uefi-source/reused.json" ] && [ ! -L "$RESCAN/$v/uefi-source/reused.json" ]; then cp -- "$RESCAN/$v/uefi-source/reused.json" "$U/"
           else printf '{"reused": true, "original_date": "%s"}\n' "$(date -u -r "$RESCAN/$v/uefi-source/uefi-source.json" +%Y-%m-%dT%H:%M:%SZ 2> /dev/null)" > "$U/reused.json"; fi; } \
      && status "B-uefi-source-$v" ATTENTION "沿用上一次的 $v/uefi-source（這次沒給 --uefi-source，沒有重讀原始碼樹）" \
      || status "B-uefi-source-$v" GAP "上一次沒有 $v/uefi-source，這次也沒給 --uefi-source：UEFI 內建函式庫不在產品 SBOM"
  else
    mkdir -p "$U"
    r=$(timeout --foreground -k 30 "$lim" python3 -I "$ROOT/tools/cra/uefi_source.py" --tree "$UEFISRC" --out "$U" 2> "$OUT/$v/logs/uefi-source.err"); x=$?
    r=$(grep -m1 $'^X-uefi-source\t' <<< "$r")
    if [ $x = 124 ] || [ $x = 137 ]; then r=$'X-uefi-source\tFAIL\t'"uefi_source.py 逾時（${lim} 秒）或被 KILL"
    elif [ -z "$r" ]; then r=$'X-uefi-source\tFAIL\tuefi_source.py 失敗（exit '"$x）：$(tail -1 "$OUT/$v/logs/uefi-source.err" 2>/dev/null)"; fi
    IFS=$'\t' read -r _ s d <<< "$r"
    case "$s:$x" in OK:0|ATTENTION:2|GAP:2|FAIL:*) ;; *) d="uefi_source.py 印出 ${s:-（沒有狀態）} 但 exit $x：${d}"; s=FAIL;; esac
    status "B-uefi-source-$v" "$s" "$d"
    uefibin_step "$v"
  fi
  [ -s "$U/uefi-source.cdx.json" ] || return 0
  r=$(timeout --foreground -k 30 600 python3 -I "$ROOT/tools/cra/uefi_bundled.py" grype --dir "$U" --max-age-days "${GRYPE_DB_MAX_AGE_DAYS:-1}" 2> "$OUT/$v/logs/uefi-grype.err"); x=$?
  r=$(grep -m1 $'^B-uefi-grype\t' <<< "$r")
  [ -n "$r" ] || r=$'B-uefi-grype\tFAIL\tuefi_bundled.py 失敗（exit '"$x）：$(tail -1 "$OUT/$v/logs/uefi-grype.err" 2>/dev/null)"
  IFS=$'\t' read -r _ s d <<< "$r"; status "B-uefi-grype-$v" "$s" "$d"
}
teesrc_step(){
  # 廠商公開原始碼（--tee-source）→ <rootfs>/tee-source/（tee_source.py：TF-A、OP-TEE、內建 Mbed TLS 的版本與 CPE；有刷機包時對照 tos-optee 映像）→ 離線 Grype（tee_bundled.py grype）。
  # 第二個參數 reuse：--rescan-from 沒給樹時沿用上一次的 tee-source，只用現在的資料庫重新比對。沒給 --tee-source（也不是 reuse）→ 不呼叫這個函式
  local v=$1 mode=${2:-} T=$OUT/$1/tee-source r s d x lim=${TEESRC_TIMEOUT:-3600} ia=()
  if [ "$mode" = reuse ]; then
    mkdir -p "$T" && cp -- "$RESCAN/$v/tee-source/tee-source.cdx.json" "$RESCAN/$v/tee-source/tee-source.json" "$T/" 2> /dev/null \
      && status "B-tee-source-$v" ATTENTION "沿用上一次的 $v/tee-source（這次沒給 --tee-source，沒有重讀原始碼樹）" \
      || status "B-tee-source-$v" GAP "上一次沒有 $v/tee-source，這次也沒給 --tee-source：OP-TEE、TF-A、內建 Mbed TLS 不在產品 SBOM"
  else
    mkdir -p "$T"
    [ ${#SRC[@]} -eq 0 ] || [ ! -f "$OUT/flash-inventory.json" ] || ia=(--inventory "$OUT/flash-inventory.json" "${SRC[@]}")
    r=$(timeout --foreground -k 30 "$lim" python3 -I "$ROOT/tools/cra/tee_source.py" --tree "$TEESRC" --out "$T" "${ia[@]+"${ia[@]}"}" 2> "$OUT/$v/logs/tee-source.err"); x=$?
    r=$(grep -m1 $'^B-tee-source\t' <<< "$r")
    if [ $x = 124 ] || [ $x = 137 ]; then r=$'B-tee-source\tFAIL\t'"tee_source.py 逾時（${lim} 秒）或被 KILL"
    elif [ -z "$r" ]; then r=$'B-tee-source\tFAIL\ttee_source.py 失敗（exit '"$x）：$(tail -1 "$OUT/$v/logs/tee-source.err" 2>/dev/null)"; fi
    IFS=$'\t' read -r _ s d <<< "$r"
    case "$s:$x" in OK:0|ATTENTION:2|GAP:2|FAIL:*) ;; *) d="tee_source.py 印出 ${s:-（沒有狀態）} 但 exit $x：${d}"; s=FAIL;; esac
    status "B-tee-source-$v" "$s" "$d"
  fi
  [ -s "$T/tee-source.cdx.json" ] || return 0
  r=$(timeout --foreground -k 30 600 python3 -I "$ROOT/tools/cra/tee_bundled.py" grype --dir "$T" --max-age-days "${GRYPE_DB_MAX_AGE_DAYS:-1}" 2> "$OUT/$v/logs/tee-grype.err"); x=$?
  r=$(grep -m1 $'^B-tee-grype\t' <<< "$r")
  [ -n "$r" ] || r=$'B-tee-grype\tFAIL\ttee_bundled.py 失敗（exit '"$x）：$(tail -1 "$OUT/$v/logs/tee-grype.err" 2>/dev/null)"
  IFS=$'\t' read -r _ s d <<< "$r"; status "B-tee-grype-$v" "$s" "$d"
}
uefibin_step(){
  # 刷機包的 uefi_*.bin 與 UEFI 原始碼樹的對照（版本字串、內嵌除錯來源路徑）→ <結果>/uefi-binary-check.json（一個產品一次；bootloader_coverage.py uefi-check）。
  # 只讀刷機包（串流，不解開到磁碟）；沒有 --archive／--dir（--rescan-from 沒給刷機包）→ NOT_RUN
  local U=$OUT/$1/uefi-source r s d x lim=${UEFIBIN_TIMEOUT:-7200} uj=()
  [ -z "$RKFMT" ] || return 0
  [ ! -f "$OUT/uefi-binary-check.json" ] || return 0
  if [ ${#SRC[@]} -eq 0 ]; then status B-uefi-binary NOT_RUN "沒有 --archive／--dir：沒有核對刷機包的 UEFI 映像與原始碼是否一致"; return 0; fi
  [ -f "$OUT/flash-inventory.json" ] || { status B-uefi-binary NOT_RUN "沒有 flash-inventory.json"; return 0; }
  [ ! -f "$U/uefi-source.json" ] || uj=(--uefi-json "$U/uefi-source.json")
  r=$(timeout --foreground -k 30 "$lim" python3 -I "$ROOT/tools/cra/bootloader_coverage.py" uefi-check --inventory "$OUT/flash-inventory.json" "${SRC[@]}" \
        --tree "$UEFISRC" "${uj[@]+"${uj[@]}"}" "${UEFIDSC[@]+"${UEFIDSC[@]}"}" --out "$OUT/uefi-binary-check.json" 2> "$WORK/uefi-binary.err"); x=$?
  r=$(grep -m1 $'^X-uefi-binary\t' <<< "$r")
  if [ $x = 124 ] || [ $x = 137 ]; then r=$'X-uefi-binary\tFAIL\t'"逾時（${lim} 秒）或被 KILL"
  elif [ -z "$r" ]; then r=$'X-uefi-binary\tFAIL\tbootloader_coverage.py uefi-check 失敗（exit '"$x）：$(tail -1 "$WORK/uefi-binary.err" 2>/dev/null)"; fi
  IFS=$'\t' read -r _ s d <<< "$r"
  case "$s:$x" in OK:0|ATTENTION:2|GAP:2|FAIL:*) ;; *) d="bootloader_coverage.py 印出 ${s:-（沒有狀態）} 但 exit $x：${d}"; s=FAIL;; esac
  status B-uefi-binary "$s" "$d（與用這份原始碼建置一致，不是逐位元相同；uefi-binary-check.json）"
}
extra_step(){
  # --extra-deliverable：另外交付的韌體 → flash-inventory.json 的 extra_deliverables（firmware_bom.py 併進產品 SBOM）與 <結果>/extra-deliverables.json
  [ ${#EXTRAS[@]} -gt 0 ] || return 0
  local a=() f r s d x l4t
  for f in "${EXTRAS[@]}"; do a+=(--deliverable "$f"); done
  [ -f "$OUT/flash-inventory.json" ] || { status B-extra-deliverable FAIL "沒有 flash-inventory.json"; return 0; }
  # 配對的 Jetson Linux 版本：list.json 的 rootfs 只有一種 L4T 版本時才用（多種就不猜）
  l4t=$(python3 -I -c 'import json,sys;v={c["l4t"]["release"] for c in json.load(open(sys.argv[1]))["rootfs"] if c.get("l4t") and c["l4t"].get("release")};print(next(iter(v)) if len(v)==1 else "")' "$OUT/list.json" 2>/dev/null)
  r=$(python3 -I "$ROOT/tools/cra/bootloader_coverage.py" extra --inventory "$OUT/flash-inventory.json" "${a[@]}" --name "$NAME" --version "$VERSION" \
        ${l4t:+--l4t "$l4t"} ${UEFISRC:+--tree "$UEFISRC"} --out "$OUT/extra-deliverables.json" 2> "$WORK/extra.err"); x=$?
  r=$(grep -m1 $'^X-extra-deliverable\t' <<< "$r")
  [ -n "$r" ] || r=$'X-extra-deliverable\tFAIL\tbootloader_coverage.py extra 失敗（exit '"$x）：$(tail -1 "$WORK/extra.err" 2>/dev/null)"
  IFS=$'\t' read -r _ s d <<< "$r"
  case "$s:$x" in OK:0|ATTENTION:2|GAP:2|FAIL:*) ;; *) d="bootloader_coverage.py 印出 ${s:-（沒有狀態）} 但 exit $x：${d}"; s=FAIL;; esac
  status B-extra-deliverable "$s" "$d"
}
coverage_step(){
  # 開機韌體涵蓋說明 → <rootfs>/bootloader-coverage.json、.md（bootloader_coverage.py coverage；Rockchip 沒有定義開機鏈：
  # 寫 NOT_ASSESSED 的說明檔與狀態列，不分類，報告才不會看起來像沒有開機韌體的問題）
  local v=$1 r s d x na=() tj=
  case $RKFMT in
    rockchip-*) na=(--not-assessed rockchip);;
    raw-disk-img*)       # 原始磁碟映像：平台一律由呼叫端明確給（project.yml 的 platform），不從映像格式推測
      case $PLATFORM in
        raspberrypi) na=(--platform raspberrypi);;     # Raspberry Pi：boot 分割區與 kernel 的真實分類（GPU 韌體 GAP、EEPROM 不在映像裡）
        "") na=(--unspecified);;                       # 沒指定平台：標 GAP，不預設成 raspberrypi
        *) na=(--not-assessed "$PLATFORM");;           # 其他平台（例如 rockchip）：沒有定義開機鏈
      esac;;
  esac
  [ "$PLATFORM" != generic ] || na=(--not-assessed generic)    # generic＝沒有定義開機鏈：不論映像格式，一律 NOT_ASSESSED（不是 GAP）
  if [ ${#na[@]} -gt 0 ]; then :
  elif [ ! -f "$OUT/flash-inventory.json" ]; then return 0; fi
  [ ! -f "$OUT/$v/tee-source/tee-source.json" ] || tj=$OUT/$v/tee-source/tee-source.json   # 和 cra_report.py 讀的同一份 tee-source
  r=$(timeout --foreground -k 30 600 python3 -I "$ROOT/tools/cra/bootloader_coverage.py" coverage --result "$OUT" --variant "$v" ${tj:+--tee "$tj"} "${na[@]}" 2> "$OUT/$v/logs/bootloader-coverage.err"); x=$?
  r=$(grep -m1 $'^X-bootloader-coverage\t' <<< "$r")
  [ -n "$r" ] || r=$'X-bootloader-coverage\tFAIL\tbootloader_coverage.py coverage 失敗（exit '"$x）：$(tail -1 "$OUT/$v/logs/bootloader-coverage.err" 2>/dev/null)"
  IFS=$'\t' read -r _ s d <<< "$r"
  case "$s:$x" in OK:0|ATTENTION:2|GAP:2|NOT_ASSESSED:2|FAIL:*) ;; *) d="bootloader_coverage.py 印出 ${s:-（沒有狀態）} 但 exit $x：${d}"; s=FAIL;; esac
  status "B-bootloader-coverage-$v" "$s" "$d；$v/bootloader-coverage.md"
}
initrd_step(){
  # rootfs 的 /boot/initrd* 裡的 ELF／腳本有沒有被套件掃描涵蓋 → <rootfs>/initrd-coverage.json、.md（tools/cra/initrd_coverage.py；唯讀，記憶體裡解壓，不執行）。
  # 映像是不可信資料：有時間上限（INITRD_TIMEOUT 秒，預設 3600）。flash-inventory.json 裡的 *initrd* 檔（燒錄時用的）另列、不分析
  local v=$1 from=$2 r s d x lim=${INITRD_TIMEOUT:-3600} inv=(); shift 2
  [ ! -f "$OUT/flash-inventory.json" ] || inv=(--inventory "$OUT/flash-inventory.json")
  r=$(timeout --foreground -k 30 "$lim" python3 -I "$ROOT/tools/cra/initrd_coverage.py" --from "$from" "$@" "${inv[@]}" --out "$OUT/$v" 2> "$OUT/$v/logs/initrd-coverage.err"); x=$?
  r=$(grep -m1 $'^B-initrd-coverage\t' <<< "$r")
  if [ $x = 124 ] || [ $x = 137 ]; then r=$'B-initrd-coverage\tFAIL\t'"initrd_coverage.py 逾時（${lim} 秒）或被 KILL"
  elif [ -z "$r" ]; then r=$'B-initrd-coverage\tFAIL\tinitrd_coverage.py 失敗（exit '"$x）：$(tail -1 "$OUT/$v/logs/initrd-coverage.err" 2>/dev/null)"; fi
  IFS=$'\t' read -r _ s d <<< "$r"
  case "$s:$x" in OK:0|INFO:0|GAP:2|FAIL:*) ;; *) d="initrd_coverage.py 印出 ${s:-（沒有狀態）} 但 exit $x：${d}"; s=FAIL;; esac
  status "B-initrd-coverage-$v" "$s" "$d$([ "$s" = FAIL ] || echo "；$v/initrd-coverage.md")"
}
pkgwhy_step(){
  local v=$1 D=$OUT/$1 r s d
  [ -s "$D/pkgdb/dpkg-status" ] || { status "D-pkg-why-$v" NOT_RUN "沒有 $v/pkgdb/dpkg-status（B-pkgdb 沒有成功）"; return; }
  [ -s "$D/cra-project/CRA/Reports/summary.json" ] || { status "D-pkg-why-$v" NOT_RUN "沒有 CRA 的 summary.json（D-cra 沒有產生文件）"; return; }
  r=$(python3 -I "$ROOT/tools/cra/pkg_why.py" report --pkgdb "$D/pkgdb" --summary "$D/cra-project/CRA/Reports/summary.json" \
        --out "$D/package-dependencies.md" 2> "$D/logs/pkg-why.err" | grep -m1 $'^D-pkg-why\t')
  [ -n "$r" ] || r=$'D-pkg-why\tFAIL\tpkg_why.py report 失敗：'"$(tail -1 "$D/logs/pkg-why.err" 2>/dev/null)"
  IFS=$'\t' read -r _ s d <<< "$r"; status "D-pkg-why-$v" "$s" "$d$([ "$s" = FAIL ] || echo "；$v/package-dependencies.md")"
}
carry_decisions(){
  # 上一次的人工判定與批次規則（CRA/Config 的 vex-rules.json、vex-annotations.json）與安全測試的決定（security-findings.json）
  # → 這次的 <rootfs>/cra-project/CRA/Config。符號連結不帶（ATTENTION）。$1 結果資料夾、$2 rootfs、$3 階段名稱、$4 說明用的稱呼。
  # 沒有可以帶的檔案時回傳 1（不寫狀態，由呼叫的人決定）
  local from=$1 v=$2 stg=$3 lab=$4 pc f ok cc=() sl=()
  pc=$from/$v/cra-project/CRA/Config
  for f in vex-rules.json vex-annotations.json security-findings.json; do
    if [ -L "$pc/$f" ]; then sl+=("$f"); elif [ -f "$pc/$f" ]; then cc+=("$f"); fi; done
  [ ${#sl[@]} -eq 0 ] || status "$stg" ATTENTION "${lab# } ${sl[*]} 是符號連結，沒有帶過來（人工判定或規則要重新確認）"
  [ ${#cc[@]} -gt 0 ] || { [ ${#sl[@]} -gt 0 ]; return $?; }
  mkdir -p "$OUT/$v/cra-project/CRA/Config"; ok=1
  for f in "${cc[@]}"; do cp -p -- "$pc/$f" "$OUT/$v/cra-project/CRA/Config/$f" || ok=0; done
  if [ $ok = 1 ]; then status "$stg" OK "沿用$lab ${cc[*]}"; else status "$stg" FAIL "無法複製$lab ${cc[*]}"; fi
}
decisions_step(){
  # --decisions-from（完整掃描）：上一次結果的判定檔帶到這次。只在上一次掃的是同一個產品（sca-scan meta.json 的名稱）時帶
  local v=$1 pn lab
  [ -n "$DECFROM" ] || return 0
  lab=" $(basename "$DECFROM") 的"
  pn=$(python3 -I -c 'import json,os,sys
p=sys.argv[1]
if not os.path.isfile(p): print("\tno-meta"); sys.exit()
try: n=json.load(open(p)).get("name")
except Exception: n=None
print(n if isinstance(n,str) and n and "\t" not in n and "\n" not in n else "\tbad-meta")' "$DECFROM/$v/scan/meta.json" 2>/dev/null)
  case $pn in
    $'\t'no-meta|"") status "B-decisions-$v" ATTENTION "${lab# } $v 沒有 sca-scan 的 meta.json（看不出是哪個產品）：判定檔沒有帶過來，要人工確認"; return;;
    $'\t'bad-meta) status "B-decisions-$v" ATTENTION "${lab# } $v 的 sca-scan meta.json 讀不出產品名稱（格式不對）：判定檔沒有帶過來，要人工確認"; return;;
  esac
  if [ "$pn" != "$NAME" ]; then status "B-decisions-$v" ATTENTION "${lab# } $v 是 $pn，不是 $NAME：判定檔沒有帶過來"; return; fi
  carry_decisions "$DECFROM" "$v" "B-decisions-$v" "$lab" || status "B-decisions-$v" ATTENTION "${lab# } $v 沒有判定檔（CRA/Config 的 vex-rules.json、vex-annotations.json、security-findings.json）"
}
prov_step(){
  # <結果>/provenance.json：這次的 sca-center commit 與刷機包身分（--archive 一次讀完算 md5 與 sha256）。$1：上一次的 provenance.json（重跑時）
  local t0 r x s; t0=$(date +%s)
  r=$(python3 -I "$FP" provenance --root "$ROOT" --out "$OUT/provenance.json" "${SRC[@]}" ${1:+--previous "$1"} 2>&1); x=$?
  s=${r%%$'\t'*}; case $s in OK|ATTENTION|FAIL) ;; *) s=FAIL;; esac; [ $x = 0 ] || s=FAIL
  status A-provenance "$s" "${r#*$'\t'}；$(( $(date +%s)-t0 )) 秒"
  PROV_MD5=; [ -n "$ARCHIVE" ] && [ "$s" != FAIL ] && PROV_MD5=$(python3 -I -c 'import json,re,sys
s=(json.load(open(sys.argv[1])).get("source") or {});m=s.get("md5") if s.get("type")=="archive" else None
print(m if isinstance(m,str) and re.fullmatch("[0-9a-f]{32}",m) else "")' "$OUT/provenance.json" 2>/dev/null)
  PROV_ST=$s
}
evidence_step(){
  # --evidence-out：凍結證據包（tools/cra/evidence_bundle.py；保存位置待公司決定，預設不做）
  [ -n "$EVOUT" ] || return 0
  local r x s
  r=$(PILOT_ENV=$PILOT_ENV EVIDENCE_ALLOW_TMP_OUT=${FLASHPKG_ALLOW_TMP_OUT:-0} python3 -I "$ROOT/tools/cra/evidence_bundle.py" create \
      --result "$OUT" --out "$EVOUT" 2> "$WORK/evidence.err" | grep -m1 $'^EVIDENCE\t'); x=$?
  [ -n "$r" ] || r=$'EVIDENCE\tFAIL\tevidence_bundle.py 失敗：'"$(tail -1 "$WORK/evidence.err" 2>/dev/null)"
  IFS=$'\t' read -r _ s d <<< "$r"; status F-evidence "$s" "$d"
}
summary_step(){
  local sa=() v
  for v in "${VARS[@]}"; do sa+=(--variant "$v"); done
  if python3 -I "$FP" summary --out-dir "$OUT" "${sa[@]}" > "$WORK/summary.txt" 2> "$WORK/summary.err"; then
    cat "$WORK/summary.txt"; status E-summary OK "$OUT/summary.md"
  else status E-summary FAIL "flash_package.py summary：$(tail -1 "$WORK/summary.err")"; fi
  evidence_step
  finish; }
rk_prepare(){  # Rockchip：zip 裡的 update.img 複製到 .work（只有這一個成員；其他成員不解開）。update.img 本身直接用
  RKIMG=$ARCHIVE
  case $RKFMT in raw-disk-img-xz|raw-disk-img-gz)
    # 壓縮的磁碟映像：串流解壓到 .work（結果資料夾所在的磁碟，不用 /tmp；需要約等於未壓縮映像的空間）；finish 之後的清理刪除
    local r x t0; t0=$(date +%s); rm -f "$WORK/disk.img"
    r=$(python3 -I "$FP" img-extract --archive "$ARCHIVE" --out "$WORK/disk.img" 2>&1); x=$?
    if [ $x = 0 ]; then RKIMG=$WORK/disk.img; status B-img-extract OK "${r#*$'\t'}；$(( $(date +%s)-t0 )) 秒"
    else status B-img-extract FAIL "$(tail -1 <<< "$r")"; finish; fi
    return 0;;
  esac
  [ "$RKFMT" = rockchip-zip ] || return 0
  local r x t0; t0=$(date +%s); rm -f "$WORK/update.img"
  r=$(python3 -I "$FP" rk-extract --archive "$ARCHIVE" --out "$WORK/update.img" 2>&1); x=$?
  if [ $x = 0 ]; then RKIMG=$WORK/update.img; status B-rk-extract OK "${r#*$'\t'}；$(( $(date +%s)-t0 )) 秒"
  else status B-rk-extract FAIL "$(tail -1 <<< "$r")"; finish; fi
}
sca_args(){  # sca-scan 的共用選項（整個系統映像的逐套件授權與檔案層級掃描太久；預設只做漏洞）
  SCA_ARGS=(--no-package-scan --no-files-scan); [ $LICENSE = 0 ] && SCA_ARGS+=(--no-license); [ $NOUP = 1 ] && SCA_ARGS+=(--no-upload)
  # Debian 打包的 Python 模組的佔位值版本（B-pyver 的 python-versions.json）：sca-scan 把 RESOLVED 的版本寫進比對與上傳用的 SBOM 副本（C-pyver）
  [ -s "$D/pkgdb/python-versions.json" ] && [ ! -L "$D/pkgdb/python-versions.json" ] && SCA_ARGS+=(--py-versions "$D/pkgdb/python-versions.json")
  local kv; for kv in "${KVERS[@]+"${KVERS[@]}"}"; do SCA_ARGS+=(--kernel-version "$kv"); done   # 核心版本原樣交給 sca-scan
  for kv in "${KUPS[@]+"${KUPS[@]}"}"; do SCA_ARGS+=(--kernel-upstream-version "$kv"); done      # 平台設定的上游版本原樣交給 sca-scan
  [ -z "$KOTHER" ] || SCA_ARGS+=(--kernel-in-other-report "$KOTHER")         # 分層：核心在另一份報告判定
  [ -z "$KNOTDISTRO" ] || SCA_ARGS+=(--kernel-not-distro "$KNOTDISTRO")      # 平台宣告核心不是發行版的核心
  return 0; }

# ---------- A. 環境與核對 ----------
PILOT_ENV=${PILOT_ENV:-$HOME/.config/sca-scan/pilot.env}
if [ $NOUP = 1 ]; then PILOT_ENV=$WORK/no-pilot.env   # 不存在的路徑：sca-scan 不會退回 repo 預設的設定
elif [ ! -r "$PILOT_ENV" ]; then status A-env FAIL "讀不到 PILOT_ENV=$PILOT_ENV（要用常駐環境的帳號執行：sudo -u <帳號>；試跑可加 --no-upload）"; finish; fi
# sudo 會把 PATH 重設成 secure_path（不含 /opt/sca-tools/bin）：找不到 grype 或 syft 時，把安裝工具的資料夾加到 PATH 前面
# （同 sca-scan；這支腳本不以 root 執行）。sca-scan 繼承這個 PATH。
TOOLS_DIR=${SCA_TOOLS_DIR:-/opt/sca-tools}; PATH_NOTE=
if { ! command -v grype > /dev/null || ! command -v syft > /dev/null; } && [ -d "$TOOLS_DIR/bin" ]; then
  add=$TOOLS_DIR/bin; for d in node/bin go/bin; do [ -d "$TOOLS_DIR/$d" ] && add+=":$TOOLS_DIR/$d"; done
  export PATH=$add:$PATH; PATH_NOTE="；PATH 加上 $add（找不到 grype 或 syft，例如 sudo 重設了 PATH）"
fi
need="grype bwrap python3 curl"; [ -z "$RESCAN" ] && need="docker syft $need"   # 重跑不用 docker 與 Syft
miss=; for t in $need; do command -v $t > /dev/null || miss+=" $t"; done
droot=; [ -z "$RESCAN" ] && droot=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null)
if [ -n "$miss" ]; then status A-tools FAIL "缺少：$miss$PATH_NOTE"; finish
elif [ -z "$RESCAN" ] && [ -z "$droot" ]; then status A-tools FAIL "docker 連不上（這個帳號要在 docker 群組）"; finish; fi
unz="Python bz2（單執行緒）"; [ -n "$ARCHIVE" ] && [ "${FLASHPKG_PARALLEL:-1}" != 0 ] && { u=$(command -v lbzip2 || command -v pbzip2) && unz=$u; }
[ -n "$SRCDIR" ] && unz="不用（--dir）"
[ -n "$RKFMT" ] && unz="不用（Rockchip $RKFMT：直接讀分割區與 ext4）"
case $RKFMT in raw-disk-img*) unz="不用（磁碟映像 $RKFMT：直接讀分割區、FAT 與 ext4；壓縮的先串流解壓到 .work）";; esac
if [ -n "$RESCAN" ]; then
  status A-env INFO "$(id -un)@$(hostname)；重跑比對（--rescan-from $RESCAN）；grype $(grype version 2>/dev/null | sed -n 's/^Version:[[:space:]]*//p')；python $(python3 -V 2>&1 | cut -d' ' -f2)；核心建置設定 ${ARCHIVE:-${SRCDIR:-沒有（沒給 --archive／--dir，C-kernel-config 不執行）}}；結果 $OUT；PILOT_ENV $([ $NOUP = 1 ] && echo '不用（--no-upload）' || echo "$PILOT_ENV")；$([ $LICENSE = 1 ] && echo 含授權 || echo 只做漏洞)$PATH_NOTE"
else
status A-env INFO "$(id -un)@$(hostname)；$(uname -m)；docker $(docker version --format '{{.Server.Version}}' 2>/dev/null)（資料 $droot，可用 $(gib "$(free_bytes "$droot")")）；syft $(syft version 2>/dev/null | sed -n 's/^Version:[[:space:]]*//p')；grype $(grype version 2>/dev/null | sed -n 's/^Version:[[:space:]]*//p')；python $(python3 -V 2>&1 | cut -d' ' -f2)；解壓 $unz；來源 ${ARCHIVE:-$SRCDIR}；結果 $OUT（可用 $(gib "$(free_bytes "$OUT")")）；PILOT_ENV $([ $NOUP = 1 ] && echo '不用（--no-upload）' || echo "$PILOT_ENV")；$([ $LICENSE = 1 ] && echo 含授權 || echo 只做漏洞)$PATH_NOTE"
fi

# ---------- 重跑比對（--rescan-from）：上一次的 SBOM → sca-scan --sbom；核心建置設定從刷機包讀 ----------
if [ -n "$RESCAN" ]; then
  # 刷機包要是上一次的同一個（list.json 記的檔名與大小；資料夾記路徑）：不然核心的 .config 可能不是這個產品的
  if [ ${#SRC[@]} -gt 0 ]; then
    chk=$(python3 -I -c 'import json,os,sys
r=json.load(open(sys.argv[1]));s=r.get("source") or {};a=r.get("archive") or {}
if sys.argv[2]=="--archive":
    ok=s.get("type")=="archive" and a.get("file")==os.path.basename(sys.argv[3]) and a.get("bytes")==os.path.getsize(sys.argv[3])
    print("OK" if ok else "上一次是 %s（%s bytes），這次是 %s（%d bytes）" % (a.get("file") or s.get("path"),a.get("bytes"),os.path.basename(sys.argv[3]),os.path.getsize(sys.argv[3])))
else:
    ok=s.get("type")=="dir" and s.get("path")==os.path.abspath(sys.argv[3])
    print("OK" if ok else "上一次是 %s，這次是 %s" % (s.get("path") or a.get("file"),os.path.abspath(sys.argv[3])))' "$RESCAN/list.json" "${SRC[@]}" 2>&1)
    [ "$chk" = OK ] || { status A-rescan FAIL "--archive／--dir 不是上一次掃描的刷機包：$chk"; finish; }
  fi
  [ -n "$RKFMT" ] && rk_prepare
  cp "$RESCAN/list.json" "$OUT/list.json" && { [ ! -f "$RESCAN/flash-inventory.json" ] || cp "$RESCAN/flash-inventory.json" "$OUT/"; } \
    || { status A-rescan FAIL "無法複製上一次的 list.json"; finish; }
  # 上一次的 UEFI 映像與原始碼的對照：這次有給原始碼樹時重做（uefisrc_step），否則沿用
  { [ -n "$UEFISRC" ] || [ ! -f "$RESCAN/uefi-binary-check.json" ] || [ -L "$RESCAN/uefi-binary-check.json" ] || cp -- "$RESCAN/uefi-binary-check.json" "$OUT/"; } \
    || status B-uefi-binary ATTENTION "無法複製上一次的 uefi-binary-check.json"
  extra_step
  # Rockchip：上一次的分割區表的狀態照樣列出（MD5 結尾、沒有掃描的分割區、沒讀到的項目）；Jetson 的 list.json 沒有 rockchip，不印
  r=$(python3 -I "$FP" rk-status --list "$OUT/list.json" --if-present 2>&1)
  if [ -n "$r" ]; then s=${r%%$'\t'*}; case $s in OK|ATTENTION|GAP) ;; *) s=FAIL;; esac; status B-rockchip "$s" "上一次的分割區表：${r#*$'\t'}"; fi
  MD5SUM=$(awk -F'\t' '$1=="A-md5" && $2=="OK"{print $3}' "$RESCAN/status.tsv" 2>/dev/null | grep -oE '[0-9a-f]{32}' | head -1)
  prov_step "$RESCAN/provenance.json"
  [ "$PROV_ST" = FAIL ] && { status A-rescan FAIL "刷機包身分（A-provenance）：不是上一次的刷機包，或讀不到"; finish; }
  # 檔名與大小相同不保證是同一個刷機包：上一次有核對過的 MD5 時再算一次比對（不同 → 核心的 .config 可能不是這個產品的，不重跑）
  # 核對過的 MD5 以 A-md5 OK 帶到這次的 status.tsv：從重跑的結果再重跑時也找得到（CRA 文件也用這個值）
  if [ -n "$ARCHIVE" ]; then
    if [ -n "$MD5SUM" ]; then
      now=$PROV_MD5
      [ "$now" = "$MD5SUM" ] || { status A-rescan FAIL "--archive 的 MD5 ${now:-（算不出來）} 和上一次核對過的 $MD5SUM 不同：不是同一個刷機包"; finish; }
      status A-md5 OK "md5 $MD5SUM：沿用上一次核對過的值（$RESCAN），這次重算 $(basename "$ARCHIVE") 相符"
    else
      # ATTENTION 而不是 GAP：SBOM 與比對資料是完整的，只是「刷機包是同一個」只核對了檔名與大小，要人確認
      status A-rescan-md5 ATTENTION "上一次沒有核對過的 MD5（A-md5 不是 OK）：--archive 只比對了檔名與大小，請確認是同一個刷機包"
    fi
  elif [ -n "$MD5SUM" ]; then
    status A-md5 OK "md5 $MD5SUM：沿用上一次核對過的值（$RESCAN；這次沒給 --archive／--dir，沒有重算，SBOM 也是那一次的）"
  fi
  if [ -n "$PREFIX" ]; then PICK=$(python3 -I -c 'import json,sys;p="/".join(x for x in sys.argv[2].split("/") if x not in ("", "."));print(next((c["variant"]+"\t"+c["prefix"]+"\t"+str(c["bytes"]) for c in json.load(open(sys.argv[1]))["rootfs"] if c["prefix"]==p),""))' "$OUT/list.json" "$PREFIX")
  else PICK=$(python3 -I "$FP" pick --list "$OUT/list.json" --rootfs "$RFS" 2> "$WORK/pick.err" | grep -v '^SKIP'$'\t'); fi
  [ -n "$PICK" ] || { status A-rescan FAIL "上一次的 list.json 裡沒有 ${PREFIX:-$RFS}：$(tail -1 "$WORK/pick.err" 2>/dev/null)"; finish; }
  VARS=()
  while IFS=$'\t' read -r v prefix bytes; do
    [ -n "$v" ] || continue
    pick_fields_ok "$v" "$prefix" "$bytes" || { status A-rescan FAIL "上一次的 list.json 的 rootfs 欄位不合法（變體、前綴或大小含不允許的字元），不處理"; finish; }
    sb=$RESCAN/$v/scan/sbom/sbom.cdx.json
    if [ ! -s "$sb" ] && [ -s "$sb.xz" ]; then xz -dc "$sb.xz" > "$WORK/$v.sbom.cdx.json" && sb=$WORK/$v.sbom.cdx.json; fi
    if [ ! -s "$sb" ]; then status "B-rescan-$v" FAIL "上一次沒有 $v 的 SBOM（$RESCAN/$v/scan/sbom/sbom.cdx.json）"; continue; fi
    VARS+=("$v"); D=$OUT/$v; mkdir -p "$D/logs"
    [ -f "$RESCAN/$v/rootfs-tar.json" ] && cp "$RESCAN/$v/rootfs-tar.json" "$D/"
    # 上一次的人工判定與批次規則（CRA/Config 的 vex-*.json）與安全測試的決定帶到這次：不帶就會回到全部未評估（config.json 照樣重新產生）
    carry_decisions "$RESCAN" "$v" "B-rescan-config-$v" "上一次的" || true
    if [ -s "$RESCAN/$v/pkgdb/dpkg-status" ]; then
      if cp -r "$RESCAN/$v/pkgdb" "$D/"; then status "B-pkgdb-$v" OK "沿用上一次的 $v/pkgdb"; else status "B-pkgdb-$v" FAIL "無法複製上一次的 $v/pkgdb"; fi
      # 上一次沒有 python-versions.json（舊版）：有刷機包就補讀，沒有就不寫（報告照舊）
      if [ ! -s "$D/pkgdb/python-versions.json" ]; then
        if [ -n "$ARCHIVE" ]; then pyver_step "$v" "${RKIMG:-$ARCHIVE}" --prefix "$prefix"
        elif [ -n "$SRCDIR" ]; then pyver_step "$v" "$SRCDIR" --prefix "$prefix"; fi
      fi
    elif [ -n "$ARCHIVE" ]; then pkgdb_step "$v" "${RKIMG:-$ARCHIVE}" --prefix "$prefix"
    elif [ -n "$SRCDIR" ]; then pkgdb_step "$v" "$SRCDIR" --prefix "$prefix"
    else status "B-pkgdb-$v" NOT_RUN "上一次沒有 $v/pkgdb，這次也沒給 --archive／--dir：不寫套件依賴說明"; fi
    # 映像的靜態安全檢查：映像沒變，沿用上一次的結果（狀態也沿用）——只在上一次不是 FAIL、而且是同一版的檢查時；
    # 否則有 --archive／--dir 就重跑（要整個解壓一次），沒有就 NOT_RUN
    IC_NOTE=; pj=$RESCAN/$v/image-check/image-check.json
    if [ -s "$pj" ]; then
      pr=$(python3 -I -c 'import json,sys;r=json.load(open(sys.argv[1]));print("\t".join([r.get("status") or "", (r.get("schema") or "")+" "+(r.get("tool_version") or "?"), r.get("generated") or "?", (r.get("summary") or "")[:300]]))' "$pj" 2>/dev/null)
      IFS=$'\t' read -r s pv g d <<< "$pr"; cv=$(python3 -I "$ROOT/tools/cra/image_check.py" --version 2>/dev/null)
      if [ "$s" = FAIL ] || [ -z "$s" ]; then IC_NOTE="上一次的 $v/image-check 是 ${s:-讀不到狀態}，不沿用"
      elif [ "$pv" != "$cv" ]; then IC_NOTE="上一次的 $v/image-check 是別的版本（$pv，這次 $cv），不沿用"; fi
    else IC_NOTE="上一次沒有 $v/image-check"; fi
    if [ -s "$pj" ] && [ -z "$IC_NOTE" ]; then
      if cp -r "$RESCAN/$v/image-check" "$D/"; then status "B-image-check-$v" "$s" "沿用上一次的 $v/image-check（$g，$pv）：$d"
      else status "B-image-check-$v" FAIL "無法複製上一次的 $v/image-check"; fi
    elif [ -n "$ARCHIVE" ]; then imgcheck_step "$v" "${RKIMG:-$ARCHIVE}" --prefix "$prefix"
    elif [ -n "$SRCDIR" ]; then imgcheck_step "$v" "$SRCDIR" --prefix "$prefix"
    else status "B-image-check-$v" NOT_RUN "$IC_NOTE，這次也沒給 --archive／--dir：沒有映像的靜態安全檢查"; fi
    IC_NOTE=
    # 產品自有軟體：有刷機包就重讀（設定可能改了）；沒有時沿用上一次的 own-software.json（不是符號連結時）
    if [ -n "$ARCHIVE" ]; then ownsw_step "$v" "${RKIMG:-$ARCHIVE}" --prefix "$prefix"
    elif [ -n "$SRCDIR" ]; then ownsw_step "$v" "$SRCDIR" --prefix "$prefix"
    elif [ -n "$PCONF" ] && python3 -I "$ROOT/tools/cra/own_software.py" --config "$PCONF" --configured 2> /dev/null; then
      if [ -f "$RESCAN/$v/own-software/own-software.json" ] && [ ! -L "$RESCAN/$v/own-software" ] && [ ! -L "$RESCAN/$v/own-software/own-software.json" ]; then
        mkdir -p "$D/own-software" && cp -- "$RESCAN/$v/own-software/own-software.json" "$D/own-software/" \
          && status "B-own-software-$v" ATTENTION "沿用上一次的 $v/own-software/own-software.json（這次沒給 --archive／--dir，沒有重讀；設定改過的樣式在 sbom.md 標 GAP）" \
          || status "B-own-software-$v" FAIL "無法複製上一次的 $v/own-software"
      else status "B-own-software-$v" GAP "上一次沒有 $v/own-software/own-software.json，這次也沒給 --archive／--dir：自有軟體不在產品 SBOM（sbom.md 標 GAP）"; fi
    fi
    # initrd 涵蓋：有刷機包就重讀；沒有時沿用上一次的 initrd-coverage（一般檔案才帶），都沒有 → NOT_RUN
    if [ -n "$ARCHIVE" ]; then initrd_step "$v" "${RKIMG:-$ARCHIVE}" --prefix "$prefix"
    elif [ -n "$SRCDIR" ]; then initrd_step "$v" "$SRCDIR" --prefix "$prefix"
    elif [ -f "$RESCAN/$v/initrd-coverage.json" ] && [ ! -L "$RESCAN/$v/initrd-coverage.json" ] && [ -f "$RESCAN/$v/initrd-coverage.md" ] && [ ! -L "$RESCAN/$v/initrd-coverage.md" ]; then
      cp -- "$RESCAN/$v/initrd-coverage.json" "$RESCAN/$v/initrd-coverage.md" "$D/" \
        && status "B-initrd-coverage-$v" ATTENTION "沿用上一次的 $v/initrd-coverage（這次沒給 --archive／--dir，沒有重讀）" \
        || status "B-initrd-coverage-$v" FAIL "無法複製上一次的 $v/initrd-coverage"
    else status "B-initrd-coverage-$v" NOT_RUN "上一次沒有 $v/initrd-coverage，這次也沒給 --archive／--dir：initrd 沒有評估"; fi
    # UEFI 內建函式庫：有給樹就重讀；沒給時沿用上一次的 uefi-source（有的話），Grype 用現在的資料庫重跑
    if [ -n "$UEFISRC" ]; then uefisrc_step "$v"
    elif [ -d "$RESCAN/$v/uefi-source" ] && [ ! -L "$RESCAN/$v/uefi-source" ]; then uefisrc_step "$v" reuse; fi
    if [ -n "$TEESRC" ]; then teesrc_step "$v"
    elif [ -d "$RESCAN/$v/tee-source" ] && [ ! -L "$RESCAN/$v/tee-source" ]; then teesrc_step "$v" reuse; fi
    # 板子的安全檢查（board-import.sh 匯入的 <rootfs>/board-test/）：映像沒變，結果照樣有效；用這次的規則重寫 board-test.json。
    # 符號連結不帶（cp -P 不跟隨；board_import.py 也只讀一般檔案）
    if [ -L "$RESCAN/$v/board-test" ]; then status "B-board-test-$v" ATTENTION "上一次的 $v/board-test 是符號連結，沒有帶過來"
    elif [ -d "$RESCAN/$v/board-test" ]; then
      if cp -R -P "$RESCAN/$v/board-test" "$D/"; then
        r=$(timeout --foreground -k 30 "${BOARD_IMPORT_TIMEOUT:-900}" python3 -I "$ROOT/tools/cra/board_import.py" --result "$D" \
              2> "$D/logs/board-import.err" | grep -m1 $'^D-board-test\t')
        [ -n "$r" ] || r=$'D-board-test\tFAIL\tboard_import.py 失敗或逾時（BOARD_IMPORT_TIMEOUT='"${BOARD_IMPORT_TIMEOUT:-900} 秒）：$(tail -1 "$D/logs/board-import.err" 2>/dev/null)"
        IFS=$'\t' read -r _ s d <<< "$r"; status "B-board-test-$v" "$s" "沿用上一次的 $v/board-test：$d"
      else status "B-board-test-$v" FAIL "無法複製上一次的 $v/board-test"; fi
    fi
    kb=(); [ ${#SRC[@]} -gt 0 ] && kb=(--kernel-build "${ARCHIVE:-$SRCDIR}" --kernel-build-prefix "$prefix")
    [ -n "$RKIMG" ] && [ ${#kb[@]} -gt 0 ] && kb[1]=$RKIMG      # Rockchip：zip 時讀取出的 update.img
    status "B-rescan-$v" OK "SBOM $sb（$(sha256sum "$sb" | cut -c1-16)…）；$prefix$([ ${#kb[@]} -gt 0 ] && echo "；核心建置設定從 $SRCNAME 讀" || echo "；沒有核心建置設定（C-kernel-config 不執行）")"
    t0=$(date +%s); sca_args
    PILOT_ENV=$PILOT_ENV bash "$ROOT/tools/pilot/sca-scan" --sbom "$sb" --name "$NAME" --version "$VERSION ($v)" --out "$D/scan" "${SCA_ARGS[@]}" \
      "${kb[@]+"${kb[@]}"}" > "$D/logs/sca-scan.txt" 2>&1; x=$?
    s=$(scan_worst "$D/scan/status.tsv"); case $x in 0|2) ;; *) s=FAIL;; esac
    status "C-scan-$v" "$s" "sca-scan --sbom exit=$x；DT $NAME @ $VERSION ($v)；$(( $(date +%s)-t0 )) 秒；非 OK 階段：$(awk -F'\t' -v vo="$((1-LICENSE))" 'NR>1 && $2!="OK" && !(vo=="1" && $2=="NOT_RUN" && $1 ~ /^E-/){printf "%s=%s ", $1, $2}' "$D/scan/status.tsv" 2>/dev/null)"
    coverage_step "$v"
    cra_step "$v"
    pkgwhy_step "$v"
    dtwb_step "$v"
  done <<< "$PICK"
  summary_step
fi

prov_step
t0=$(date +%s); MD5SUM=
if [ -z "$MD5" ]; then
  if [ -n "$SRCDIR" ]; then status A-md5 NOT_RUN "--dir 沒有給逐檔的 md5 清單（--md5）：沒有核對"
  else status A-md5 GAP "沒有 $(basename "$ARCHIVE").md5：沒有核對壓縮檔是否完整"; fi
else
  r=$(python3 -I "$FP" md5 "${SRC[@]}" --md5 "$MD5" ${PROV_MD5:+--got "$PROV_MD5"} 2>&1); x=$?
  s=${r%%$'\t'*}; [ $x = 0 ] || s=FAIL
  status A-md5 "$s" "$SRCNAME（$(basename "$MD5")）：${r#*$'\t'}；$(( $(date +%s)-t0 )) 秒"
  [ "$s" = FAIL ] && finish
  [ -n "$ARCHIVE" ] && MD5SUM=$(echo "$r" | grep -oE '[0-9a-f]{32}' | head -1)
fi

# ---------- B. 清點刷機包 ----------
SRCR=("${SRC[@]}"); CONT=()     # list 與 rootfs-tar 讀的來源：Rockchip 是 update.img（zip 時是取出的那一份，list.json 記 zip）
if [ -n "$RKFMT" ]; then rk_prepare; SRCR=(--archive "$RKIMG"); case $RKFMT in rockchip-zip|raw-disk-img-xz|raw-disk-img-gz) CONT=(--container "$ARCHIVE");; esac; fi
t0=$(date +%s); dl=(); [ -n "$ARCHIVE" ] && dl=(--deliverables "$(dirname "$ARCHIVE")")
if python3 -I "$FP" list "${SRCR[@]}" "${CONT[@]}" --out "$OUT/list.json" --inventory "$OUT/flash-inventory.json" --version "$VERSION" "${dl[@]}" \
     > "$WORK/list.txt" 2> "$WORK/list.err"; then
  fp=$(python3 -I -c 'import json,sys;r=json.load(open(sys.argv[1]));d=r["flash_package"];o=r.get("other_deliverables") or []
print("flash.sh %d 個、板子設定 %s、bootloader 檔案 %d 個（%d bytes）、rootfs 以外的檔案 %d 個（讀不到 %d）；其他交付檔 %d 個（只記 sha256，不掃描）：%s" % (len(d["flash_sh"]), ",".join(p.rsplit("/",1)[-1] for p in d["board_configs"]) or "無", d["bootloader_files"], d["bootloader_bytes"], d["outside_rootfs_files"], d["outside_rootfs_unreadable"], len(o), ", ".join(x.get("name","?") for x in o[:8])))' "$OUT/list.json" 2>/dev/null)
  status B-list OK "$(awk -F'\t' '{printf "%s（%s 個檔案、%s bytes、讀不到 %s）；", $2, $3, $4, $5}' "$WORK/list.txt")$fp；$(( $(date +%s)-t0 )) 秒"
else status B-list FAIL "flash_package.py list：$(tail -1 "$WORK/list.err")"; finish; fi
extra_step
if [ -n "$RKFMT" ]; then
  # 分割區表（溢位修正、MD5 結尾、其他 ext4 分割區）：位置無法證明或沒有 ext4 的 rootfs → GAP，不掃描
  r=$(python3 -I "$FP" rk-status --list "$OUT/list.json" 2>&1); s=${r%%$'\t'*}; case $s in OK|ATTENTION|GAP) ;; *) s=FAIL;; esac
  status B-rockchip "$s" "${r#*$'\t'}；分割區表見 list.json 的 rockchip／disk_image"
  case $s in OK|ATTENTION) ;; *) finish;; esac
fi
if [ -n "$PREFIX" ]; then
  b=$(python3 -I -c 'import json,sys;p="/".join(x for x in sys.argv[2].split("/") if x not in ("", "."));print(next((c["prefix"]+"\t"+str(c["bytes"]) for c in json.load(open(sys.argv[1]))["rootfs"] if c["prefix"]==p),""))' "$OUT/list.json" "$PREFIX")
  [ -n "$b" ] || { status B-pick FAIL "刷機包裡沒有 $PREFIX（見 list.json 的 rootfs）"; finish; }
  PICK=$(printf '%s\t%s' "$RFS" "$b")
elif ! PICK=$(python3 -I "$FP" pick --list "$OUT/list.json" --rootfs "$RFS" 2> "$WORK/pick.err"); then
  status B-pick FAIL "$(tail -1 "$WORK/pick.err")"; finish; fi
# --rootfs all 沒有選的 rootfs（不像完整的 rootfs、位置重複）：一定寫出來，不無聲略過
while IFS=$'\t' read -r tag st v prefix why; do
  [ "$tag" = SKIP ] || continue
  [[ $v =~ ^(rootfs_no_gui|rootfs_gui|rootfs)$ ]] || { status B-pick FAIL "SKIP 列的變體不合法，不處理"; finish; }
  status "B-skip-$v" "$st" "$prefix：$why"
done <<< "$PICK"
PICK=$(grep -v '^SKIP'$'\t' <<< "$PICK")

VARS=(); declare -A PFX=() BYTES=()
while IFS=$'\t' read -r v prefix bytes; do
  [ -n "$v" ] || continue
  pick_fields_ok "$v" "$prefix" "$bytes" || { status B-pick FAIL "rootfs 的變體、前綴或大小含不允許的字元（刷機包的成員名稱不可信），不處理"; finish; }
  VARS+=("$v"); PFX[$v]=$prefix; BYTES[$v]=$bytes; mkdir -p "$OUT/$v/logs"
  l4t=$(python3 -I -c 'import json,sys;c=next(c for c in json.load(open(sys.argv[1]))["rootfs"] if c["prefix"]==sys.argv[2]);l=c["l4t"];print(l["status"]+"\t"+l["detail"]+("；"+l["note"] if l.get("note") else ""))' "$OUT/list.json" "$prefix" 2>/dev/null)
  s=${l4t%%$'\t'*}; [ "$s" = OK ] && [[ "$l4t" == *注意：* ]] && s=ATTENTION   # 產品版本和 rootfs 的 L4T 版本對不起來：要人看
  status "B-l4t-$v" "${s:-FAIL}" "$prefix：${l4t#*$'\t'}"
done <<< "$PICK"

# 磁碟：所有 rootfs 的 tar 同時存在（同一次讀取寫出），之後 sca-scan 的 docker save 也差不多大；Docker 資料區一次一個映像
tot=0; big=0; for v in "${VARS[@]}"; do tot=$(( tot + BYTES[$v] )); [ "${BYTES[$v]}" -gt $big ] && big=${BYTES[$v]}; done
need=$(( tot + tot/8 + (2<<30) )); dneed=$(( big + big/8 ))
fo=$(free_bytes "$OUT"); fd=$(free_bytes "$droot")
if [ "$(stat -c %d "$OUT")" = "$(stat -c %d "$droot" 2>/dev/null)" ]; then need=$(( need + dneed )); dneed=0; fi
if [ -z "$fo" ] || [ "$fo" -lt "$need" ] || { [ "$dneed" -gt 0 ] && [ "${fd:-0}" -lt "$dneed" ]; }; then
  status B-disk FAIL "rootfs 共 $(gib "$tot")：結果資料夾需要約 $(gib "$need")（可用 $(gib "$fo")）$([ "$dneed" -gt 0 ] && echo "，Docker 資料需要約 $(gib "$dneed")（可用 $(gib "$fd")）")"
  finish; fi
status B-disk OK "rootfs 共 $(gib "$tot")；結果資料夾可用 $(gib "$fo")（需要約 $(gib "$need")）；Docker 資料可用 $(gib "$fd")"

# ---------- B. 所有選定的 rootfs 在同一次讀取裡轉成 tar ----------
t0=$(date +%s); tg=(); for v in "${VARS[@]}"; do tg+=(--target "${PFX[$v]}=$WORK/$v.tar=$OUT/$v/rootfs-tar.json"); done
if python3 -I "$FP" rootfs-tar "${SRCR[@]}" "${tg[@]}" > "$WORK/rootfs-tar.txt" 2> "$WORK/rootfs-tar.err"; then
  sec=$(( $(date +%s)-t0 ))
  for v in "${VARS[@]}"; do
    line=$(awk -F'\t' -v p="${PFX[$v]}" '$1==p{print $2}' "$WORK/rootfs-tar.txt")
    # 沒有放進映像的（讀不到、拿不到內容的硬連結、拒絕的成員）：裡面的套件不會在 SBOM 裡 → ATTENTION
    miss=$(python3 -I -c 'import json,sys;r=json.load(open(sys.argv[1]));m=[("讀不到的檔案",r["unreadable_files"]),("讀不到的資料夾",r["unreadable_dirs"]),("略過的硬連結",r["skipped_hardlinks"]),("拒絕的成員",r["rejected"]+r["rejected_through_symlink"])]
print("、".join(f"{k} {v}" for k,v in m if v))' "$OUT/$v/rootfs-tar.json" 2>/dev/null)
    s=OK; [ -n "$miss" ] && s=ATTENTION
    status "B-rootfs-tar-$v" "$s" "$line；$sec 秒（${#VARS[@]} 個 rootfs 一起）$([ -n "$miss" ] && echo "；沒有放進映像：$miss（rootfs-tar.json 的 examples）")"
  done
else
  for v in "${VARS[@]}"; do status "B-rootfs-tar-$v" FAIL "flash_package.py rootfs-tar：$(tail -1 "$WORK/rootfs-tar.err")"; done
  rm -f "$WORK"/*.tar; finish
fi

# ---------- 每個 rootfs：映像 → sca-scan → CRA ----------
for v in "${VARS[@]}"; do
  D=$OUT/$v; prefix=${PFX[$v]}
  decisions_step "$v"
  repo=$(safe "$NAME" | tr 'A-Z' 'a-z' | sed 's/^[._-]*//; s/[._-]*$//'); tag=sca-flashpkg/${repo:-product}:$(safe "$VERSION" | sed 's/^[.-]*//')-$v
  docker image rm -f "$tag" > /dev/null 2>&1 || true
  pkgdb_step "$v" "$WORK/$v.tar"
  imgcheck_step "$v" "$WORK/$v.tar"
  ownsw_step "$v" "$WORK/$v.tar"
  initrd_step "$v" "$WORK/$v.tar"
  [ -z "$UEFISRC" ] || uefisrc_step "$v"
  [ -z "$TEESRC" ] || teesrc_step "$v"
  PENDING_TAG=$tag
  msg="sca-center flash package scan: $SRCNAME $prefix (imported, never run)"
  iid=$(docker import --platform "linux/$ARCH" -m "$msg" "$WORK/$v.tar" "$tag" 2> "$D/logs/import.err") || \
    { grep -qi 'platform' "$D/logs/import.err" && iid=$(docker import -m "$msg" "$WORK/$v.tar" "$tag" 2> "$D/logs/import.err"); }
  rm -f "$WORK/$v.tar"
  if [[ "$iid" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    IID[$v]=$iid; PENDING_TAG=; status "B-import-$v" OK "$tag → $iid（$(docker image inspect --format '{{.Architecture}} {{.Size}} bytes' "$iid" 2>/dev/null)）；暫存 tar 已刪"
  else docker image rm -f "$tag" > /dev/null 2>&1; PENDING_TAG=
    status "B-import-$v" FAIL "docker import 失敗：$(tail -1 "$D/logs/import.err")；暫存 tar 已刪"; continue; fi

  t0=$(date +%s); sca_args
  # 核心的建置設定與燒錄的核心（IKCONFIG）從刷機包讀（C-kernel-config）：Rockchip 讀 update.img；Jetson 讀刷機包 tbz2／資料夾加 rootfs 前綴，
  # 才讀得到實際燒錄的 <前綴的上一層>/kernel/Image（依據公開 L4T BSP：apply_binaries.sh 把 kernel/Image 裝成 rootfs 的 /boot/Image，所以以 kernel/Image 為準，不是刷機包裡 rootfs 原本的 /boot/Image）。
  # 兩顆核心不同時 C-kernel-boot 並列證據（資訊性 ATTENTION）；環境變數 KERNEL_BOARD_OS_TXT（板子 os.txt）可讓它用 uname -v 確認。
  kb=()
  if [ -n "$RKFMT" ]; then kb=(--kernel-build "$RKIMG" --kernel-build-prefix "$prefix")
  elif [ ${#SRC[@]} -gt 0 ]; then kb=(--kernel-build "${ARCHIVE:-$SRCDIR}" --kernel-build-prefix "$prefix"); fi
  PILOT_ENV=$PILOT_ENV bash "$ROOT/tools/pilot/sca-scan" --image "$iid" --name "$NAME" --version "$VERSION ($v)" --out "$D/scan" "${SCA_ARGS[@]}" \
    "${kb[@]+"${kb[@]}"}" > "$D/logs/sca-scan.txt" 2>&1; x=$?
  s=$(scan_worst "$D/scan/status.tsv"); case $x in 0|2) ;; *) s=FAIL;; esac
  status "C-scan-$v" "$s" "sca-scan exit=$x；DT $NAME @ $VERSION ($v)；$(( $(date +%s)-t0 )) 秒；非 OK 階段：$(awk -F'\t' -v vo="$((1-LICENSE))" 'NR>1 && $2!="OK" && !(vo=="1" && $2=="NOT_RUN" && $1 ~ /^E-/){printf "%s=%s ", $1, $2}' "$D/scan/status.tsv" 2>/dev/null)"

  if [ $KEEP = 0 ]; then docker image rm -f "$iid" > /dev/null 2>&1 && { unset "IID[$v]"; status "Z-cleanup-image-$v" OK "刪除映像 $iid"; } \
    || status "Z-cleanup-image-$v" ATTENTION "刪除映像 $iid 失敗：請手動 docker image rm $iid"
  else status "Z-cleanup-image-$v" INFO "--keep-image：保留 $tag（$iid）"; unset "IID[$v]"; fi

  coverage_step "$v"
  cra_step "$v"
  pkgwhy_step "$v"
  dtwb_step "$v"
done

# ---------- 摘要 ----------
summary_step
