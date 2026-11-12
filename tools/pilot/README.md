# 試行版掃描入口：`sca-scan` 與報告

範圍見 `docs/decisions/0002-pilot-scope.md`。用法與各階段的判定寫在 `sca-scan` 檔頭；這裡只列需求、安全限制與檔案。

```
tools/pilot/sca-scan --git <網址> --ref <完整 commit SHA> [--name N]
tools/pilot/sca-scan --dir <路徑> [--name N]
tools/pilot/sca-scan --image <名稱@sha256:…> [--name N]
tools/pilot/sca-scan --sbom <CycloneDX JSON> [--name N]
共用：--out <資料夾>  --no-upload  --allow-network-resolve  --no-package-scan  --no-files-scan  --no-license（只做漏洞，不跑 ScanCode.io／DejaCode）
      --version <字串>（DT 專案版本；預設是 commit、內容雜湊或映像 ID）
```
`--version`：DT 專案（與 DejaCode 產品）的版本改用指定的字串，例如產品版本 `V39.2.0.2_a (rootfs_no_gui)`；預設由內容決定的值仍記在
`meta.json` 的 `content_version`（`image_id`、`digest` 等照舊）。只接受英數字開頭、英數字與「空白 . _ + ~ ( ) -」、最多 100 字元，其他 → 參數錯誤（64）。
同一個名稱與版本重跑會沿用同一個 DT 專案、上傳新的 SBOM（取代舊的元件清單）。
結果：`<out>/status.tsv`（每階段一列，狀態只有 OK／ATTENTION／GAP／NOT_ASSESSED／FAIL／NOT_RUN）、`report.html`、`report.json`。
退出碼：有 FAIL → 1；其他非 OK → 2；全部 OK → 0（仍不代表安全）。

## 掃描前的弱點資料新鮮度（2026-11-10 決定：每次掃描都用新的資料）
`sca-scan`（`scan-flash-package.sh` 含 `--rescan-from` 都經過它）在比對之前，先在沙箱外明確更新一次 Grype DB，比對本身仍是
`GRYPE_DB_AUTO_UPDATE=false`（不開 grype 自己的 `db.auto-update`）。環境變數 `GRYPE_DB_UPDATE`：
- `online`（預設，現在）：`grype db update`，連 Grype 官方下載網址，同一個 `GRYPE_DB_CACHE_DIR`。
- `import:<鏡像檔案或 URL>`：`grype db import`，從本機鏡像匯入（鏡像由更新主機用 `tools/mirror/grype-db.sh` 產生）。**正式的離線部署必須設成這個**，
  內網掃描器不連 Grype 官方網址。
- `off`：不更新（測試，或資料庫由別處管理）；`C-grype-db-update` 記 NOT_RUN。
狀態列：`C-grype-db-update`（OK／FAIL 與原因／NOT_RUN）、`C-grype-db`（Built 為 UTC，年齡以小時顯示；超過 `GRYPE_DB_MAX_AGE_DAYS`，預設 **1 天（24 小時）**，
→ GAP，不論更新是否成功；更新失敗但仍在上限內 → ATTENTION 並寫原因）、`C-mirror-freshness`（讀 `MIRROR_REFRESH_STATUS`，預設
`/var/lib/sca-gitlab/refresh-status.tsv`，與每日監控同一個剖析器：狀態檔 24.5 小時內完成、每個鏡像最後成功都在各自上限內 → OK；
有過期或不在狀態檔的鏡像、狀態檔讀不到 → GAP 並列出名稱；只有「最近一次更新失敗但沿用的上一份仍在上限內」→ ATTENTION；
設成空字串＝不檢查 → NOT_RUN，不是 OK）。`C-dt-feeds`（有用 DT 時；`dtsources.py` 讀 DT 的 `/api/v2/{vuln,kev}-data-sources/{nvd,osv,cisa,enisa}/mirror-runs/latest`，需要 SYSTEM_CONFIGURATION_READ；GitHub 關閉不看）：四個來源最近一次都 COMPLETED 且完成在 `DT_FEEDS_MAX_AGE_HOURS`（預設 26 小時）內 → OK；有 FAILED、不是 COMPLETED、過期或沒有紀錄 → GAP 並列出名稱；沒用 DT 或金鑰沒有權限 → NOT_RUN 並寫原因，不是 OK。
GAP 照 `status.tsv` 的規則往上傳，報告不顯示為完整。

## 需求
- 工具版本同 `tools/e2e/install-tools.sh`：cdxgen、Syft、Grype、govulncheck（Go 專案）；另需 bubblewrap、python3、curl、git。
- 非 root 使用者執行（root 在沙箱內 `sudo` 可用，探測會判 FAIL）。Ubuntu 24.04 要允許非特權 user namespace（見 install-tools.sh）。
- `sudo sca-scan …` 時 sudo 會把 PATH 重設成 secure_path，找不到裝在 `/opt/sca-tools/bin` 的 grype、syft。這時 sca-scan 自己把
  `/opt/sca-tools` 的 `bin`、`node/bin`、`go/bin` 加到 PATH 前面（`SCA_TOOLS_DIR` 可改位置；`A-tools` 的說明會寫出來）。
  root 執行時只接受 root 擁有、群組與其他人不可寫的資料夾。
- 映像需要 docker（`docker pull`、`docker save`）。
- Docker socket 對照組：沙箱探測會在沙箱外連 Docker socket 當對照組。主機沒有 Docker 或使用者沒有權限時記為「對照組不可用」，
  改以「沙箱內 /run 是空的」為證據，不阻止掃描；這時沙箱內本來就沒有這條提權路徑。
- 連 DT、DejaCode、ScanCode.io：`PILOT_ENV`（預設 `deploy/pilot/state/pilot.env`）。DT 金鑰權限見 `sca-scan` 檔頭
  （建議含 SYSTEM_CONFIGURATION_READ，才能把 BOM 處理與弱點分析分開確認）。

## 安全限制（要讀）
- 不可信的程式（cdxgen 會執行套件管理器、govulncheck 會載入專案、Syft 解析映像）只在 bwrap 沙箱內執行（`tools/e2e/sandbox.sh`）：
  根目錄唯讀；`/tmp`、`/run` 是空的 tmpfs；**家目錄（`getent passwd` 的家目錄與 `$HOME`）、`/home/runner/runners`、`$RUNNER_ROOT`（可選覆寫；runner 沒有這個變數）、
  `$RUNNER_WORKSPACE` 的上兩層一律以 tmpfs 遮蔽**，npm 全域設定 `<prefix>/etc/npmrc`、Python 的 `<base_prefix>/pip.conf`、`<base_prefix>/etc`、`.condarc`、`/etc/pip.conf`、`/etc/xdg/pip`、`/etc/conda`，以及每個掛回路徑下的 `pip.conf`、`.condarc`、`.npmrc`、`.netrc`、`etc` 一律遮蔽；所以 `~/.ssh`、`~/.docker/config.json`、
  `~/.config/gh`、`~/.git-credentials`、`~/.netrc`、`~/.npmrc`、`~/.cargo/credentials.toml`、runner 的 `.credentials` 都讀不到。
  只唯讀掛回：npm 全域套件的套件根目錄、其他工具實際檔案所在的資料夾、PATH 上的符號連結（重建），以及明確列出的暫存區、Grype DB、
  工具鏈根目錄（`JAVA_HOME`、`GOROOT`、Python `base_prefix`）。`PILOT_ENV` 所在的整個資料夾與金鑰標頭檔另外遮蔽
  （PILOT_ENV 放在系統資料夾時只遮檔案本身並在報告註明）。每次掃描都實測（`sbom/sandbox-probe.txt`、`sbom/sandbox-secrets.txt`）。
- 全域設定的取捨：掛回的工具鏈目錄下的 Maven `conf/settings.xml`、`conf/settings-security.xml`、Gradle `init.d`、`gradle.properties`
  也一律遮蔽（Maven 的換成合法的空設定，仍可啟動；遮蔽掛在 `readlink -f` 後的實際路徑，例如 Debian maven 的 `conf → /etc/maven`；解析後是 `/etc`、`/usr` 等系統層級資料夾時不整個蓋掉，記錄後略過）。代價是無法經全域設定連內部代理或私有套件庫；需要時另外準備只有讀取權限的設定，
  經 `SBX_RO` 明確掛回並在報告中標示。Maven 專案需要主機上有 java 與 mvn（固定版本見 `deploy/versions.md`）：
  **mvnw 在無網路的沙箱內會失敗**（要下載 Maven 本體），缺 java／mvn 時記 `B-toolchain` GAP。
- **`--allow-network-resolve` 只能用於可信的專案。** 這時沙箱有網路：專案的建置腳本可以把沙箱看得到的東西送出去，
  也可以連到主機 127.0.0.1 上**沒有驗證的服務**（例如 Ollama 11434 埠、沒設密碼的資料庫）。bwrap 無法依目的地過濾。
  govulncheck（連 vuln.go.dev）也在有網路的沙箱內執行，同樣的限制適用（它只載入專案，不執行專案程式）。
- 秘密：API key 只寫在權限 600 的標頭檔（`curl -H @檔案`），不出現在指令列；結束前以 `lib/leakscan.py`（秘密從檔案讀）檢查輸出，有就刪檔並記 FAIL。
- 試行版用線上資料源（不是離線鏡像），所有連外點見 `docs/offline-egress.md`。

## 規則的落實
- 規則 11：`lib/lockcheck.py` 依生態系判斷；每個清單檔都要有**同資料夾**的鎖定檔，或確認是工作區成員（npm／yarn workspaces、
  pnpm-workspace.yaml、Cargo [workspace]、uv [tool.uv.workspace]、go.work 的 use＋go.work.sum）且工作區根目錄有鎖定檔，才宣告完整；
  無法判斷一律算缺。任一生態系缺 → sbomgate 最多 PARTIAL。
  每個 package.json、requirements*.txt 都交給 sbomgate 核對；其他清單檔（go.mod、pyproject.toml、pom.xml…）記為「未比對」。
- 規則 12、13：sbomgate。版本未知的元件不比對；上傳 DT 與 ScanCode.io 的 SBOM 先移除這些元件的版本（`lib/strip_versions.py`，
  `sbom/sbom.upload.cdx.json`），原始 SBOM 原樣保留（`sbom/sbom.cdx.json`）。
- 規則 14：沒有鎖定檔的 npm 專案，cdxgen 的 `npm install` 在沙箱內執行；沒有網路時記 GAP。
- 作業系統核心（`C-kernel-coverage`，只有 `--image`、`--sbom`；`lib/kernelcheck.py`，結果 `scan/kernel-coverage.json`）：SBOM 有核心
  （Syft 的 linux-kernel／linux-kernel-module 元件、`cpe:2.3:o:linux:linux_kernel` 或明確列出的核心套件名稱）但 Grype 對核心 0 筆 → GAP，
  報告弱點節另註「核心的漏洞不在下面的數字裡」；有比對 → OK；沒有核心時不寫這一列（一般容器映像不受影響）。版本依序取 linux-kernel 元件、`/usr/lib/modules/<版本>/`、核心套件。
  證據：Jetson Linux R39.2.1 映像有 nvidia-l4t-kernel 與 1468 個核心模組、沒有 linux-kernel 元件，Grype 與 DT 對核心都是 0 筆（run 40594937149）。
- Jetson Linux 的核心（`C-kernel-l4t-map`，只有 `--image`、`--sbom`；`lib/l4t_kernel.py`，對應檔 `lib/l4t-kernel-map.json`，結果 `scan/l4t-kernel-map.json`）：
  L4T 的核心是 NVIDIA 的 deb（nvidia-l4t-kernel），Ubuntu 的弱點資料沒有它；它是從 Canonical 的 noble linux-nvidia-tegra 建的。
  `nvidia-l4t-kernel` 版本裡的 L4T 版本（`6.8.12-tegra-39.2.1-…` → 39.2.1）在對應檔有出處與核對紀錄時，給 Grype、sbomgate、上傳 DT 的副本
  加上對應的 Canonical 核心原始碼套件（R39.2.1 → `pkg:deb/ubuntu/linux-nvidia-tegra@6.8.0-1021.21?arch=source&distro=ubuntu-24.04`，
  屬性 `sca-center:matching-only`、`sca-center:kernel-mapped-from`），套用 Canonical 的修補狀態 → OK。原始 SBOM 不動，ScanCode.io／DejaCode 不收這個元件。
  模組目錄（`/usr/lib/modules/6.8.12-1021-tegra/`，1021 是 Ubuntu ABI）和對應檔不符、L4T 版本不在對應檔或還是 TODO → GAP（核心仍沒有比對）；
  SBOM 已有這個元件，或有 deb 套件是從同一個原始碼套件同版本建的（例如 Canonical 的 linux-image-*-nvidia-tegra）時不重複加。
  沒有 nvidia-l4t-kernel 時不寫這一列。NVIDIA 自己的 out-of-tree 模組（nvgpu、nvethernetrm、linux-nv-oot）與 NVIDIA SAUCE 修改不在對應內，
  它們的弱點仍未評估。新的 L4T 版本要在對應檔加一項（Canonical 版本、purl、出處、核對人與日期）。
- DT 弱點資料源：上傳前讀 `/api/v2/vuln-data-sources/{nvd,osv}/mirror-runs/latest` 與 `/api/v2/kev-data-sources/{cisa,enisa}/…`
  （需 SYSTEM_CONFIGURATION_READ；`lib/dtsources.py`，結果 `dt/data-sources.json`）。NVD 或 OSV 最近一次不是 COMPLETED、沒有紀錄或讀不到
  → `D-dt-data-sources` GAP，`D-dt-findings` 也記 GAP（讀取本身完成，結果不完整），`compare_expected.py` 對 DT 側一律判 GAP
  （「不可有」出現仍是 FAIL）；報告首頁列出各資料源狀態。KEV 另記 `D-dt-kev-sources`（只影響 KEV 標記）。
  `D-dt-deb-sources`：上傳 DT 的 SBOM 另存一份，替二進位名稱和原始碼名稱不同的 deb 元件補上原始碼套件元件（`lib/deb_sources.py`，`dt/deb-sources.json`）。
  Ubuntu／Debian 的漏洞資料以原始碼套件記錄，不補的話 DT 比對不到（Jetson 示範：名稱不同的 537 個套件 DT 只比對到 1 個）。只給 DT；ScanCode.io／DejaCode 收的 SBOM 不加。
  `D-dt-osv-coverage`：讀 DT 的 OSV 設定（`/api/v2/extension-points/vuln-data-source/extensions/osv/config`），SBOM 的 purl 類型對應的
  OSV 生態系沒有啟用時記 GAP（例如映像的 deb 套件需要 Debian；run 39947311999 的 DT 沒有啟用，DT 0 筆、Grype 942 筆）。
  findings 在 vuln-analysis 完成後讀；另外最多等 `DT_POLICY_WAIT_SECONDS`（預設 120）秒讓 analyze-project（政策評估、metrics）完成。
  `D-distro-recheck`（`lib/distro_recheck.py`，`scan/distro-recheck.json`）：DT 也以 NVD 的 CPE 比對 deb 套件，NVD 只知道上游版本，
  不知道發行版已經 backport 修補（Jetson R39.2.1：openssl 3.0.13-0ubuntu3.11 的 CVE-2024-6119，Ubuntu 在 -0ubuntu3.4 修好，卻被列成 P1）。
  每一列（CVE × 元件版本）只有 NVD／GitHub／非發行版 OSV 的 finding、Grype 沒有比對到同一個弱點、不是核心時，查發行版自己的 OSV 紀錄
  （同一發行版本、同一原始碼套件；dpkg 版本規則）：distro_fixed（安裝版本 ≥ 修補版本）、distro_affected、distro_not_listed、no_distro_record。
  以每個 CVE 一筆的紀錄（UBUNTU-CVE-…、DEBIAN-CVE-…）為準；USN／DSA／DLA 公告只在沒有那筆紀錄時才看，而且只能判
  distro_fixed_advisory_only（照常保留）：公告的 CVE 清單涵蓋整份公告，不代表每個發行版本與套件（實例：noble 的 curl 與 CVE-2026-80229）。
  鏡像來自 `PILOT_ENV` 的 `OSV_DISTRO_MIRROR`（`tools/mirror/osv-distro.sh`）；沒有、過期（3 天）或 sha256 不符 → GAP（沒有判定）。
  沒有要再判的列時不寫這一列。原始的 `dt/findings.json` 不改；CRA 報告（`tools/cra/cra_report.py`）把 distro_fixed 的列移出 P1–P3。
  `D-usn-cves`（`lib/usn_cves.py`，`scan/usn-cves.json`）：DT 的 OSV 資料裡有些 USN 沒有 CVE 別名（例如 brotli 原始碼套件上的
  USN-8956-1），同一個問題在同一個元件上另有 CVE 的列。從同一個鏡像（Ubuntu）查每個這種 USN 的 `upstream`、`aliases` 列的 CVE（不用 `related`），
  連同鏡像的來源資料（fetched_utc、sha256）寫成對應檔；CRA 報告把 USN 併進同一個元件版本上那個 CVE 的列（來源編號保留）。
  另記 `fixed`：每個 USN（沒有 CVE 的也記，撤回的不記）在一般 Ubuntu 版本（`Ubuntu:24.04:LTS` 等，Pro 不收）的原始碼套件與修補版本
  （`counts.with_fixed`）；CRA 報告用它推出自成一列的 USN 的修補狀態（USN 的修補版本）。
  沒有這種 USN 時不寫這一列；沒有鏡像或過期 → NOT_RUN（檔案記原因，USN 照舊各自成列，報告寫明對應不可用）。
  `D-ubuntu-priority`（`lib/ubuntu_priority.py`，`scan/ubuntu-priority.json`）：Ubuntu 套件（含 C-kernel-l4t-map 加上的 Canonical 核心）上的 CVE，
  從同一個鏡像讀 `UBUNTU-CVE-<CVE>` 紀錄的 Ubuntu priority（`severity` 裡 type 是 `Ubuntu` 的 score）。DT 對這些紀錄的嚴重度取自紀錄裡的 CVSS
  （多半就是 NVD 的），CRA 報告分級的嚴重度改依供應商評級優先（NVIDIA 公告 → Ubuntu priority → NVD）。untriaged 或沒有 → 往下一個來源。
  沒有 Ubuntu 套件上的 CVE 時不寫這一列；沒有鏡像或過期 → NOT_RUN（檔案記原因，嚴重度照 Grype 的 Ubuntu 比對或 DT／NVD）。
  `C-euvd`（`lib/euvd.py annotate`，`scan/euvd.json`，放在 D-dt-findings、C-grype、C-kernel-config 之後）：DT findings 與 Grype 的 CVE 標上
  ENISA EUVD 編號與已遭利用標記（PILOT_ENV 的 `EUVD_MIRROR`，`deploy/pilot/euvd-mirror.sh`；說明在 `lib/euvd.md`）。沒有設定鏡像或索引不能用 →
  GAP、檔案沒有 `cves`；過期 → GAP 但照樣標註；DT 與 Grype 都沒有 CVE 清單 → NOT_RUN。報告端（KEV 欄、不是 OK 時風險評估 GAP）在另一個 PR。
  `D-dt-kev-sources` 另讀 DT 的 ENISA KEV `feedUrl`：不完全等於 EUVD 產生的檔的網址（`EUVD_DT_FEED_URL`，預設 `http://dt-nvd-mirror/kev/euvd/eukev.json`）、
  或那份檔過期（以 `EUVD_MIRROR` 判斷）→ GAP；有 EU KEV 條目沒寫進那份檔（沒有可用的日期）→ ATTENTION。
  `D-ubuntu-status`（`lib/ubuntu_status.py`，`scan/ubuntu-status.json`）：DT findings 裡 Ubuntu 套件（核心以外）上的 (CVE, 原始碼套件, 發行版)，
  從 Ubuntu CVE Tracker 狀態鏡像（PILOT_ENV 的 `UBUNTU_CVE_STATUS_MIRROR`，`tools/mirror/ubuntu-cve-status.sh` 的輸出，PR #150）只取出這些，
  給 CRA 報告的證據規則 U1（Ubuntu 標 not-affected、安裝的版本符合註記 → not_affected），以及 Grype 沒有修補狀態的 Ubuntu 列的修補狀態
  （released → fixed、needed／pending／in-progress／deferred → not-fixed、ignored → wont-fix；tools/cra/README.md）。DT findings 裡 Ubuntu
  打包的 Python 模組（dist-packages 的 pypi 元件）也收 SBOM 裡唯一擁有它的 deb 與 (CVE, 它的原始碼套件, 發行版)（`counts.deb_python_owners`）。沒有 Ubuntu 套件上的 CVE 時不寫這一列；
  沒有鏡像、過期、sha256 不符或發行版不在鏡像裡 → NOT_RUN（檔案記原因；U1 不套用，列照樣受影響）。
  `C-kernel-boot`（`lib/kernel_boot.py`，`scan/kernel-boot.json`，在 C-kernel-config 之前；需要 `--kernel-build-prefix`）：Jetson 刷機包的 `kernel/Image` 和 `rootfs/boot/Image` 不同時並列兩顆核心的 sha256、版本字串（含 `#1 SMP PREEMPT <建置時間>`）、IKCONFIG 差異數與前 10 項、`extlinux.conf` 的 DEFAULT 標籤指向哪裡、核心建置紀錄 BUILD-INFO.txt 的 image sha256 對的是哪一顆；兩顆不同 → ATTENTION（資訊性）。實際開機的核心只能在板子上確認（`uname -v`）；廠商 Jetson 刷機包的板子實測跑 `kernel/Image`（燒錄流程會裝它），所以預設不改 K1。環境變數 `KERNEL_BOARD_OS_TXT`（board-test 的 os.txt）有 uname 那一行時比對：對上 `kernel/Image` → OK；對上 `rootfs/boot/Image` → ATTENTION，C-kernel-config 才改用它的 IKCONFIG（`--prefer-rootfs-image`），核心建置紀錄除非 BUILD-INFO sha256 對得上否則 GAP；兩顆都對不上 → ATTENTION。只有一顆核心 → NOT_RUN（不寫這一列）。
  `C-kernel-config`（`lib/kernel_config.py`，`scan/kernel-config.json`，放在 D-distro-recheck 之後）：核心元件（C-kernel-l4t-map 加上的
  Canonical 核心等）上的每個 CVE，用 Linux 核心 CNA 紀錄的 programFiles（修補動到的檔案）對照產品核心的 `.config` 與 Makefile／Kbuild
  （映像的 `/usr/lib/modules/<版本>/build` 或 `/usr/src/linux-headers-<版本>*/`），判 not_affected（每個檔案都一定沒編）、affected
  （至少一個一定有編；=m 算有編）或 unknown（標頭檔、非程式檔、沒有紀錄、條件區塊或看不懂的 Makefile）。只讀文字，不執行 make。
  不確定就是 unknown：只有 `obj-n`、`obj-`（後綴 n 或空字串）與沒開的 `CONFIG_` 算「沒編」；`subdir-`（只給 make clean）不算；
  物件清單（`obj`／`lib`／`subdir`、以 `obj` 結尾的，或右邊是 `.o`／資料夾）的其他字面後綴（例如 arm64 vdso 的 `obj-vdso`，經 incbin 編進核心）、
  沒被任何規則提到的組合物件（例如 nVHE 的 `hyp-obj-y`）、define 區塊或 `$(eval …)` 裡提到物件清單，都是 unknown。
  不是物件清單的變數（`atomic-checks`、`clean-files`、`build-version`、`hostprogs`…）忽略，不影響判定（上游 6.8 根目錄 Kbuild 的
  `atomic-checks += $(addprefix …)` 曾讓整棵樹都變成 unknown）。
  別的資料夾的規則直接編譯的原始檔（例如 xe 的 `$(obj)/i915-display/%.o: $(srctree)/drivers/gpu/drm/i915/display/%.c`；`$(src)/../…`、
  變數展開後的路徑也算）：那個 Makefile 所在的資料夾可能有編時是 unknown。
  會被別的 .c `#include` 的檔案（例如 `sound/pci/ens1371.c` include `ens1370.c`、libstub 的 zboot.c include `lib/decompress_*.c`）是 unknown：
  清單在 `lib/data/kernel-included-c-<版本>.json`，由 `lib/kernel_included_c.py` 從上游原始碼產生（所有版本的清單合併後套用；
  另保留 `lib/decompress_`、`lib/xz/` 等前綴）。清單讀不到或格式不對 → C-kernel-config FAIL。其他版本要重新產生時：
  `python3 -I tools/pilot/lib/kernel_included_c.py --source linux-X.Y.tar.xz --kernel X.Y --source-sha256 <kernel.org sha256sums.asc 的值> --out tools/pilot/lib/data/kernel-included-c-X.Y.json`
  （只讀 tar 的一般檔案，不解壓、不執行；6.8 的清單 317 個檔案，tar 的 sha256 與 kernel.org sha256sums.asc 相同，PGP 簽章未核對）。
  6.1 的清單（`data/kernel-included-c-6.1.json`，306 個檔案）從**公開上游** linux-stable 的 tag `v6.1.118`（用 `git archive` 取出的資料夾，
  `--source-tag`／`--source-commit` 記在 `source` 欄：`b67dc5c9ade9dc354b790eb64aa6a665d0a54ecd`）產生；不可以用廠商的核心樹（公司資料）。
  兩份清單都**不含廠商自己加的 `#include`**（`kernel_config.py` 的 limitations 是同一句話）。
  判 not_affected 前另外核對模組目錄：有同名的 .ko（含 updates/、extra/ 的 out-of-tree 模組，例如 nvidia-oot 帶的上游程式複本；
  組合物件的名稱也算，樹內同一個組合模組除外）或沒有模組目錄 → unknown。Kbuild 判沒編，但映像的 modules.builtin 或 modules.order
  列了那個物件（或也判沒編的組合物件）→ 那個檔案是 unknown（`Kbuild says not built but modules.builtin/modules.order lists it`）；
  組合物件有編、只是這個成員依 config 沒放進去時，清單列那個組合模組是正常的——但組合物件本身要和清單一致：=m 要在 modules.order
  的同一個路徑、而且 modules.builtin 沒有同名的；=y 不能在 modules.order（modules.builtin 只列帶模組資訊的 built-in 物件，
  bool 的組合物件如 thermal_sys.o、acpi.o 不在裡面是正常的，不要求）。
  不一致或核對不了 → unknown（`configured-out member of the composite …`）。這個成員本身是否真的不在已編的模組裡，清單看不出來
  （limitations 註明）。映像沒有這兩個清單時不核對，limitations 註明。
  `results[].files[]` 每個檔案：`path`、`configs`、`built`（true／false／null）、`built_as`（有編時依 C-kernel-module-map 的對應是
  `"builtin"` 或 `"module"`；沒編、不知道或對應不確定是 null；給 VEX 匯出分辨「=m 編成同一個模組」的 affected）、`module`
  （`built_as` 是 module、而且只連進一個模組時的模組名稱，modprobe 形式；其他 null）。`cve_data.zip_sha256` 記 CNA 鏡像 SOURCE 的 zip sha256。
  模組目錄的擷取：docker 層的單一檔案 whiteout（`.wh.<名稱>.ko`）與資料夾的 opaque whiteout 會刪掉下層的 .ko 與模組清單；
  連到 .ko 的符號連結以連結的名稱算（目標在映像的同一個模組目錄裡要存在；目標在模組目錄以外無法核對，算存在），硬連結也以名稱算。
  模組目錄裡的資料夾連結（例如 `updates -> /opt/nv/updates`）在映像裡解開，底下的 .ko 以連結的路徑算（.ko 連結經過資料夾連結時
  也解得到）。指向（或應該指向）資料夾的連結解不開、目標不存在或目標又是無法跟隨的連結時，記在模組目錄的 present_gaps，
  C-kernel-module-map 寫成 `modules_present_gaps`；指向映像裡檔案的連結（`README -> /usr/share/doc/x`）與指向沒有 .ko 的資料夾都不算。
  目標裡面的連結不跟隨：目標在模組目錄以外而底下有符號連結、或目標在另一個核心版本的模組目錄而那裡有連結 → gap；硬連結的 .ko 以名稱算，
  另一個版本的 .ko 以那個版本的清單算。每個實際的目標只展開一次，最多 10,000 個名稱（超過 → gap）；映像的路徑數超過索引上限時，
  需要索引判斷的資料夾連結一律 gap。
  來源：`--kernel-build <rootfs tar｜資料夾｜刷機包 tbz2> [--kernel-build-prefix <rootfs 路徑>]`，`--image` 沒給時用 docker save 的映像 tar；
  `--sbom` 沒給 `--kernel-build` 時記 NOT_RUN（核心的 CVE 沒有依 .config 判定）。CNA 紀錄來自 `PILOT_ENV` 的 `KERNEL_CVE_MIRROR`（`tools/mirror/kernel-cve.sh`）。
  燒錄的核心（廠商刷機包常見情形：刷機包的 `kernel/Image` 是廠商重編的，燒錄時蓋掉 rootfs 的 `/boot/Image`，headers 的 `.config` 和實際開機的核心有差異）：
  另外讀 rootfs 的 `/boot/Image`（符號連結、硬連結在映像裡解開，目標要是 `/boot` 底下的 `Image*` 檔案），有 `--prefix`（刷機包或解開的
  Linux_for_Tegra 資料夾）時再讀 `<prefix 的上一層>/kernel/Image`（沒有時 `Image.gz`；不跟隨連結），取出內建的設定（IKCONFIG：`IKCFG_ST`＋gzip＋`IKCFG_ED`，
  同 Linux 的 `scripts/extract-ikconfig`；多段 gzip 同 zcat 全部解開；Image 本身是 gzip、xz、bzip2、lzma、zstd 時先解開），只在記憶體裡
  （Image 128 MB、解壓後 256 MB、config 8 MB 的上限，超過只記原因、sha256 與 md5 照算）。和 headers 的 `.config` 比（`CONFIG_` 的值與
  `Linux/<ARCH> <版本>` 標頭），結果寫在 `kernel.config_check`（`result`、`image`（含 `ikconfig_complete`、`link_target`、`md5`）、`rootfs_image`、
  `headers_config`、`image_config_sha256`、不同時 `differences`（`name`、`headers`、`image`，最多 200 筆、值最多 200 字）、`differences_total`、
  `differences_truncated`、`dpkg`、`limitations`）。sha256 都以原始位元組算：
  - 比較時「沒有這一項」和「`# CONFIG_X is not set`」都算 n（Kconfig 的語意：bool／tristate 缺少就是 n）。`differences`、`differences_total`
    和說明的「差 N 個設定」都是正規化後的數；原始的差異數在 `raw_differences_total`，`bytes_identical` 記兩份是否逐位元組相同。
  - 相同（`same`，正規化後相同；不一定逐位元組相同，所以讀取端不以 sha256 判斷「相同」）→ 照舊用 headers。
  - 只差工具鏈衍生的設定（`same_except_toolchain`；標頭相同、IKCONFIG 完整）→ 狀態 OK，改用 IKCONFIG 判定（`config_source` 是
    `kernel/Image (IKCONFIG)`，`config_sha256` 是 IKCONFIG 的，等於 `image_config_sha256`）。NVIDIA 的 headers 套件以 Ubuntu 的工具鏈重新產生
    `.config`，公開的原廠核心因此只差這些（R39.2.0 實測：`AS_VERSION`、`LD_VERSION`、`CC_VERSION_TEXT`、`GCC_PLUGINS`）。工具鏈項目
    （`kernel_config.py` 的 `TOOLCHAIN_OPTION_*`，名稱去掉 `CONFIG_` 後比對）：
    - 完整名稱：`GCC_VERSION`、`CLANG_VERSION`、`AS_VERSION`、`LD_VERSION`、`LLD_VERSION`、`GCC_PLUGINS`；
    - 前綴：`CC_IS_`、`CC_HAS_`、`CC_CAN_`、`CC_NO_`、`AS_IS_`、`AS_HAS_`、`LD_IS_`、`LD_HAS_`、`TOOLCHAIN_HAS_`、`RUSTC_`、`PAHOLE_`（`GCC_PLUGIN_*` 是加固功能，例如 STACKLEAK 會多編 kernel/stackleak.o，**不算**；只有 `GCC_PLUGINS` 本身算）；
    - 後綴：`_VERSION_TEXT`（`CC_VERSION_TEXT`、`BINDGEN_VERSION_TEXT`…）。
    `_VERSION` 不用後綴比對：`MODVERSIONS`、`LOCALVERSION`、`ARCH_*_VERSION` 這類是功能性的設定，不算工具鏈。`differences[].toolchain` 標出每一項；
    VEX 匯出的說明前面加 `based on the flashed kernel's built-in configuration (IKCONFIG sha <12>; only toolchain options differ from the
    headers .config: N)`（`vex_export.py` 的 `kconfig_toolchain_only`：同樣要 `config_source` 是 IKCONFIG、IKCONFIG 完整、`config_sha256` 等於
    `image_config_sha256`，不然不寫這一句；status OK 本來就採用）。
  - 不同（`differs`）→ 改用 Image 的設定判定（`kernel.config_source` 是 `kernel/Image (IKCONFIG)`，`config_sha256` 是 IKCONFIG 的），狀態 ATTENTION。
    VEX 匯出（`vex_export.py` 的 `kconfig_usable`）採用這種結果，條件是 `config_check.result` 是 `differs`、`config_source` 以 ` (IKCONFIG)` 結尾、
    `image.ikconfig_complete` 是 true、`config_sha256` 等於 `image_config_sha256`；說明前面加 `based on the flashed kernel's built-in configuration (IKCONFIG sha <前 12 碼>);
    the headers .config differs from it in N option(s)`（依燒錄核心的內建設定；headers .config 與它有 N 項不同）。IKCONFIG 不完整或其他原因的 ATTENTION 不採用。
  - 讀不到 IKCONFIG → 用 rootfs 的 dpkg 驗證（`var/lib/dpkg/status` 32 MB、每個 `info/*.md5sums` 8 MB 的上限；路徑正規化成 `boot/Image`；docker 的分層與
    whiteout 照現有規則）：①擁有 `/boot/Image`（連結解開後的檔案）的套件記的 md5 和 `/boot/Image` 相同；②刷機包時 `kernel/Image` 的 md5 也相同
    （`kernel/Image.gz` 或本身是壓縮檔時比解壓後的 md5，`image.unpacked_md5`）；③ headers `.config` 的 md5 和擁有它的套件記的相同（例如為了編
    out-of-tree 模組複製進來的 `.config` 會不同），兩個套件同版本（dpkg status），而且是同一組：
    - 名稱成對：Jetson 是 `<X>` 與 `<X>-headers`（`nvidia-l4t-kernel`／`nvidia-l4t-kernel-headers`、`nvidia-l4t-rt-kernel`／`nvidia-l4t-rt-kernel-headers`；
      `nvidia-l4t-rt-kernel` 配 `nvidia-l4t-kernel-headers` 不成對）；Ubuntu 是 `linux-image-<v>`（含 `linux-image-unsigned-<v>`）與 `linux-headers-<v>`，
      `<v>` 含 flavour（`linux-image-6.8.0-45-generic`／`linux-headers-6.8.0-45-generic`；`.config` 在有 flavour 的那一層，沒有 flavour 的
      `linux-headers-6.8.0-45` 是共用的那一層，不成對）；
    - 只認名稱成對：dpkg status 的 `Source:` 相同**不算**（RT 核心和一般核心可能來自同一個原始碼套件，設定卻不同）；Source 只記錄下來。
    都成立 → 照舊（`dpkg_verified`，記套件名、版本、Source、md5）；只有 rootfs 時說明寫「看不到實際燒錄的 kernel/Image」。任何一項不成立
    （md5 不符、找不到擁有者、版本不同、不是同一組、讀不到）→ GAP（`dpkg_not_verified`，`dpkg.failed` 寫是哪一項），K1 不給 not_affected。
    dpkg 的資料和 Image、headers 來自同一個不可信的 rootfs：這只是一致性檢查，不能防竄改（`config_check.limitations` 註明）。
  - IKCONFIG 不完整、設定卻和 headers 相同 → 不算 `same`，走 dpkg 驗證。IKCONFIG 標頭的架構和 headers 不同 → GAP（`differs_arch_mismatch`），
    讀取端也檢查 `config_header` 的架構，不同就不採用（版本不同本來就由核心版本的核對記 GAP）。
  - 兩個 Image 都沒有 → 照舊（沒有 `config_check`，輸出和以前相同）。
  `C-kernel-module-map` 用同一個判斷（`kernel_config.settle_config`），`sources.config`、`sources.config_sha256`、`sources.config_check` 記下用的設定；
  GAP 時、或 IKCONFIG 不完整而設定不同時對應表也是 GAP；和 `--kernel-config` 的 `kernel.config_sha256` 不同 → GAP。
  限制：EFI zboot（`zimg`）不解開；Ubuntu 的 `/boot/vmlinuz-*` 不讀；`/boot/Image` 的連結目標在 `/boot` 以外時不讀。
  判定的規則不變，只換設定的來源。修補只動到其他架構（`arch/<非 SRCARCH>/`）的 Makefile／Kbuild／Kconfig 也判沒編（和那裡的 .c 一樣）。
  兩種 arch 規則只在架構確定時用：headers 要有 `arch/<SRCARCH>/Makefile`（標頭寫 `Linux/aarch64` 之類時不用），UML（`um`）不用。
  沒有 .config、模組目錄對不上、鏡像沒有或過期（7 天）→ GAP。只列出；PR #110 的 `tools/cra/vex_export.py` 讀這個檔（not_affected → VEX 的 code_not_present）。核心的主.次版本沒有 `data/kernel-included-c-<版本>.json`（目前只有 6.8）時不判 not_affected，limitations 註明。
  實測（Jetson R39.2.1，NVIDIA 公開的 nvidia-l4t-kernel-headers 的 .config，sha256 與 SBOM 記的相同；**PR #111 審查修正之前的版本**，
  修正後 unknown 會變多，數字要重跑）：6,270 個核心 CVE 中 2,919 個沒編進核心；
  映像實際的 1,352 個模組與 modules.builtin 的 1,305 項沒有一個被判成沒編。
  **核心原始碼樹（選用，Makefile 的來源）**：環境變數 `KERNEL_SOURCE_DIR`（只用於 `--image`、`--sbom`；轉成 `--source-tree`，兩個核心階段都收到）：
  映像／刷機包的 linux-headers 不完整（廠商核心不是套件安裝的，rootfs 的 headers 常常只有少數幾個 Makefile）時，指定一棵核心原始碼樹當 Makefile／Kbuild 的來源。
  `.config`、IKCONFIG 核對、模組與 Image 照舊來自 `--kernel-build`；只有 Makefile 類檔案與檔案名稱改讀這棵樹（沿用 `collect_tree` 的讀法與上限；唯讀、
  不執行任何東西、符號連結不跟隨）。樹有 `.config` 時和判定用的設定核對（`kernel.source_tree.config_compare`：same／same_except_toolchain／differs／no_config），
  `differs` → ATTENTION；樹的主.次版本和 `.config` 標頭不同、或讀不出版本 → GAP。輸出的 `kernel.makefiles_from: source-tree` 與 `kernel.source_tree`（版本、Makefile 數、資料夾名稱，不寫路徑）記 Makefile 的來源。
  **核心 CVE 清單（廠商核心）**：Grype、DT 都沒有核心元件的 CVE（`kernel_config.py` 回 NOT_RUN）時，sca-scan 不再靜默：環境變數 `KERNEL_CVES`（明確給的清單，每行一個 CVE；
  也可以和 Grype／DT 的合併）或有 `KERNEL_CVE_MIRROR` 時依產品核心版本（`kernel_config.py --probe-kernel-version`：`/lib/modules/<版本>`，沒有時 Image 的版本字串；
  多個版本、兩邊不一致、讀不到都是 GAP，不猜）用 `kernel_cna_version.py` 產生清單（`scan/kernel-cve-list.txt`／`.json`），
  經 `--cves --cves-origin` 給 C-kernel-config 與 C-kernel-module-map。狀態列 `C-kernel-cve-list` 記清單從哪來（CNA 版本比對一律 GAP：CNA 不含 2024-02 以前其他單位發的 CVE；
  不是 Grype／DT）；kernel-config.json 的 `inputs.cves_origin` 也記。版本取不到或被 `kernel_cna_version.py` 拒絕（發行版 ABI 的版本）→ 三列（C-kernel-cve-list、C-kernel-config、C-kernel-module-map）GAP；
  核心存在但沒有清單來源 → 三列 NOT_RUN；映像裡看不到核心（一般容器映像）→ 照舊不寫。Grype 或 DT 已有核心 CVE 的產品先照舊執行，不受影響。
  **核心建置紀錄（選用）**：環境變數 `KERNEL_BUILD_RECORD`（只用於 `--image`、`--sbom`；sca-scan 轉成 `kernel_config.py --build-record`，
  `C-kernel-module-map` 不讀）指到這個出貨版本的核心建置紀錄：`make` 之後的建置資料夾（in-tree 或 `O=` 的輸出資料夾），或把它打包的
  `.tar`／`.tar.gz`／`.tar.xz`（可以在一層資料夾底下，例如 `kernel-noble/…`）。**每個出貨版本要保留**：`.config`、每個 `.*.cmd`、
  `modules.order`、`modules.builtin`、`System.map`、`include/config/kernel.release`、`include/generated/`（至少 `utsversion.h`、`compile.h`；
  實測 6.8 arm64 約 1.6 萬個檔案、壓縮後約 100 MB；`System.map` 不讀，留給人查）。`kernel.release`、`utsversion.h`、`compile.h` 是**建置的身分**：
  和映像裡燒錄的核心 Image 的版本字串（`Linux version <release> (<by>@<host>) (<compiler>) #N SMP …`）逐項核對，對不上 → GAP（不是出貨的
  那一次建置）；都沒有（或讀不到 Image 的版本字串）時只要 `.config` 與模組清單相符照樣採用，但 `identity.result` 是 `not_tied`、
  limitations 註明、C-kernel-config 的說明寫「建置紀錄沒有和映像綁定」：同版本、同設定、但修補不同的另一次建置也會通過，所以要保留
  `include/generated/` 與 `include/config/kernel.release`。每個物件的 `.<物件>.cmd` 的 `source_`／`deps_` 列出實際編譯的原始檔與讀到的每個檔案（標頭檔、
  被 `#include` 的 `.c` 都在內），所以能直接回答「修補的檔案有沒有編進這個核心」：
  - 只讀不執行：tar 串流讀（不解開到磁碟）、只讀一般檔案，資料夾不跟隨連結；絕對路徑或含 `..` 的成員不收、不需要的連結略過，
    需要的 `.cmd` 或清單是連結 → GAP；單一檔案 16 MB、合計 4 GB、tar 成員合計 64 GB 的上限；不合格的項目只記數量與前 5 個例子。
    `.cmd` 的位置要和內容的目標一致（kbuild 的規則），archive 與 `.mod` 的成員清單要是 kbuild 的格式。
  - **對不上就不用**（`kernel.build_record.status` GAP、`reason` 寫原因，照舊依 Makefile 判定；階段的狀態不變，說明寫「建置紀錄 … 不採用」）：
    紀錄的 `.config` 和 K1 判定用的設定（headers 的 `.config` 或燒錄核心的 IKCONFIG）不同（只差工具鏈衍生的設定算相同，同上面的規則）；
    `include/config/kernel.release` 和判定的核心版本不同；不完整（沒有 `.config`、`modules.order`、最後連結的 `.vmlinux.cmd`，
    或物件的 `.cmd` 少於 200 個）；**成員不齊**：從 `vmlinux.o` 起，每個 archive（`built-in.a` 的 printf、`lib.a`／`vmlinux.a`）列的成員、
    每個 `.mod` 列的模組成員、以 `@x.mod` 連結的 `x.mod`、`modules.order` 每個模組的 `.o`／`.mod`／`.ko`，只要有一個沒有自己的 `.cmd`
    （`closure.missing`；少了某個物件的 `.cmd`，它的原始檔就會被誤當成沒編）。沒有 `source_` 的指令（連結、`objcopy`、`strip`、`ld -r`、
    vDSO 的 `.so`）裡每個樹內的 `*.o`／`*.a`／`*.so`／`*.so.dbg` 也要有 `.cmd`（kvm nVHE、EFI libstub、`arch/arm64/kernel/pi`、vDSO 都是這樣連結的），
    最後的 `vmlinux` 要有 `vmlinux.o`、`vmlinux.a`、`init/version-timestamp.o`（有模組時加 `.vmlinux.export.o`），`.incbin` 帶進來的
    `vdso/vdso.so` 也要有；`.cmd` 依**指令**分類，不依有沒有 `source_`：帶依賴檔旗標（`-Wp,-MMD` 等）、目標是 `.o`／`.s`／`.lds`／`.dtb` 的編譯指令
    卻沒有 `source_`，或沒有 `source_` 的 `.o` 不是 `ld`／`objcopy`／`strip` → GAP（編譯的 `.cmd` 被截在 `savedcmd_` 那一行之後）；
    tar 沒有結尾的零區塊（剛好截在成員邊界）→ GAP；**被截斷的 `.cmd`** → GAP：kbuild 寫的 `.cmd` 一定以換行結尾，編譯指令有 `deps_` 而且最後有
    `<目標>: $(deps_<目標>)` 與 `$(deps_<目標>):` 兩行（之後可能有 `#SYMVER`），其他指令只有 `savedcmd_` 一行（被截斷的連結或 `ar` 指令
    看得到的成員只是一部分，closure 只會要求看得到的那些）；archive 的成員有看不懂的 → GAP；沒有 `.vmlinux.cmd`（最後的連結）→ GAP；`modules.order`／`modules.builtin`
    和映像的不同；有兩棵建置樹。**映像 `kernel/` 底下有 `.ko` 不在紀錄的 `modules.order` 時不整份拒收**（廠商出貨時可能另外放了模組；
    `modules.order`／`modules.builtin` 與映像相同、身分相符才成立）：紀錄照用，這些模組另列在 `kernel.build_record.image_modules_not_in_record`——
    每個模組讀它自己的 `.modinfo`（純 Python 讀 ELF 區段表，有大小上限，支援 `.ko.xz`／`.gz`／`.zst`；讀不到、壓縮格式不支援一律當成 intree，保守；modpost 對核心樹內編出來的模組加 `intree=Y`），再看 Makefile 對得到與否，輸出每個模組的 `intree` 與 `class`（2–5）：**2** intree（或讀不到）、Makefile 對不到——可能由任何樹內檔案編出來，所有沒被紀錄證明有編的樹內 `.c`／`.S` 一律 unknown；**3** intree（或讀不到）、Makefile 對得到——組成物件的檔案 unknown；**4** 樹外（沒有 intree）、名稱對得到樹內模組（例如樹外 fork）——對應的樹內組成物件的檔案 unknown（可能含同一段程式）；**5** 樹外、名稱也對不到——樹外廠商模組，未評估（GAP），列出名稱、author、description、vermagic、srcversion，不做全面保護（它的程式不是核心樹的檔案，CNA programFiles 不涵蓋它，本身是另一個沒評估的元件）。標頭檔在有任何多出的模組時都是 unknown。**限制**：intree 標記可被偽造；樹外模組的程式本身沒有漏洞比對。模組名稱與 modinfo 進 cra_report 的待確認事項（`kernel:extra-modules`，問產品工程師來源）。原始碼樹的前綴只認絕對路徑或 `../`。
    沒有 `include/config/kernel.release` 時（例如只打包了部分檔案），`.config` 完全相同（只差工具鏈也不行）而且 `modules.order` 與 `modules.builtin` 兩個都和映像的
    比對過才採用（`kernel_release_checked: false`，`limitations` 註明），否則 GAP：所以 `kernel.release` 一定要保留。
  - 判斷（CVE 的規則不變）：樹內的 `.c`／`.S`／`.rs` 與 `.h` 在任何一個核心物件的 `source_`／`deps_` → 有編；主機程式（`scripts/`、`tools/`、
    `usr/include/`、沒有副檔名的主機程式）不算核心，`*.mod.o`（連進 `.ko`）算。絕對路徑以 `source_` 推出的原始碼樹前綴（`O=` 建置）對到樹；
    其他對不上樹的絕對路徑（in-tree 建置裡 `$(abspath …)` 的路徑，例如 arm64 vDSO 的 `lib/vdso/gettimeofday.c`；`O=` 的符號連結路徑與實際路徑
    不同）以 `/<檔案>` 結尾也算有編（`unmapped_absolute_paths` 記數量，路徑不寫出）。被 `#include` 的 `.c` 清單照舊是安全網：紀錄沒有證明
    有編就是 unknown；核心版本沒有清單時照舊不判 not_affected。都不在：Makefile 也判沒編 → 沒編；Makefile 判有編 → 矛盾，
    unknown；Makefile 判斷不了 → 要能證明這個檔案在這個核心裡（Makefile 的規則提到它的物件，或映像的 headers 有這個檔案）才算沒編，
    否則 unknown（programFiles 是主線修補當時的路徑）。標頭檔沒有任何 in-tree 物件讀、但模組目錄有 out-of-tree 模組（例如 nvidia-oot，
    另外以核心標頭編譯）→ unknown。
  - 輸出：`kernel.build_record`（來源檔名、`status`、`reason`、`.config` 的 sha256、`config_compare`、`kernel_release`、`.cmd` 數、
    `kernel_release_checked`、`closure`、`unmapped_absolute_paths`、`out_of_tree_modules`、`counts_without_record`、`decision_changes`、
    `file_judgements`、`limitations`），採用時每個 `files[]` 多一個 `evidence`
    （例如 `build record: in the deps of drivers/x/y.o`、`build record: not in the source or deps of any compiled kernel object`）。
    沒給時輸出和以前逐位元組相同。VEX 匯出照舊讀 `results`（not_affected 的 detail 寫明是建置紀錄的證據）。
  **減少「無法判斷」的四個選用輸入／規則（2026-11-10）**：
  - **樹外模組的建置紀錄**：環境變數 `KERNEL_OOT_BUILD_RECORDS`（用冒號分隔多個資料夾，需要 `KERNEL_BUILD_RECORD`；sca-scan 轉成 `kernel_config.py --oot-build-record`，可重複；
    `lib/kernel_oot_record.py`）。讀樹外模組（NVIDIA 的 nvidia-oot、nvgpu、nvdisplay…）建置資料夾裡的 `.*.o.cmd`（source／deps）與 `.*.ko.cmd`。
    標頭檔以前只要映像有樹外模組就一律 unknown；現在**映像裡每一個樹外 `.ko`（模組目錄 `kernel/` 以外）都有完整的紀錄**（`.<模組>.ko.cmd`，它連結的每個物件、
    `@x.mod` 的每個成員都有完整的 `.cmd`，可以分散在好幾個資料夾；紀錄資料夾裡有同名 `.ko` 時 `.modinfo` 的 `srcversion` 要和映像的相同）時，
    標頭檔才看紀錄：核心與樹外模組都沒有把它列進 deps → 沒編（not_affected）；樹外模組的 deps 列了它（路徑以 `/<標頭檔>` 結尾）→ 有編（affected）。
    只要有一個樹外 `.ko` 沒有紀錄、一份紀錄被截斷／太大／含連結、`srcversion` 不同、或建置紀錄（`--build-record`）本身不能用 → 全部不採用，標頭檔照舊 unknown。
    **怎麼確認紀錄的 `.ko` 和映像的是同一份建置**（依序，每個模組記用了哪一種，`identity` 有各自的模組數）：(1) 兩邊的 `.modinfo` 都有 `srcversion` 而且相同（`srcversion`；
    兩邊都有而不同 → 不同份程式，不再試別的方法）；(2) `srcversion` 讀不到（NVIDIA 的樹外模組多半沒有）時比 ELF 區段：只讀 ELF64 little-endian 的區段表，
    SHT_PROGBITS 區段（排除 `.debug*`、`.note*`、`.comment`、`.BTF*`、`.gnu_debuglink`、`.modinfo`、`__versions`、`.gnu.linkonce*`）的名稱與 sha256 全部相同（`sections`）；
    (3) 只有字串區段（`.rodata.str*`，或小於 4 KB、全是可列印文字的其他 `.rodata*`，例如版本橫幅）不同，且以 NUL 切開（略過空字串）後字串數量相同，
    不同的字串只差 `__DATE__`／`__TIME__`／ISO 日期／`date` 指令格式的日期時間、括號裡的 `(user@host)`、原始碼或物件檔絕對路徑的建置目錄前綴（最後 3 層要相同）
    （`sections_masked`，狀態文字標「遮罩」，`masked_examples` 列例子）；其他字串不同一律不遮罩、不採用。符號表（名稱、型別、所在區段、偏移、大小）與程式碼／資料區段的重定位（符號用名稱）也要相同；第 3 項只允許指向有差異字串區段的 addend 不同；日期時間只在含月份名稱日期（或 ISO 日期加 HH:MM:SS）的建置橫幅字串裡遮罩，MAC 位址、單獨的時間或日期不遮罩；至少要有一個非空的 `.text*`／`.data*` 區段；雜湊位元組有上限。殘留限制：除錯資訊不比。
    行為變更 (1)：同名 `.ko` 在紀錄裡有好幾個（例如兩種建置的 `nvidia.ko`）時，映像的 `.ko` 只要有一個候選用內容驗證過（srcversion 或 ELF 區段）就採用，其他候選的不符不再抵銷（以前任何一個候選對不上就整個模組不採用）；沒有任何候選用內容驗證過時維持原規則。行為變更 (2)：映像有 srcversion 而紀錄的 `.ko` 沒有（或相反）時，以前是「讀不到 → 不採用」，現在走 ELF 區段比對；兩邊都有而不同仍然不採用。仍然是**全部或沒有**：
    部分採用只能多判 affected（沒有被已驗證模組列出的標頭檔，未驗證的模組仍可能用到），而且 deps 要限制在已驗證模組的物件，暫不做；
    沒有驗證的模組列在 `uncovered_modules`／`uncovered_examples`（附原因）。
    結果在 `kernel.build_record.out_of_tree_records`（`used`、`reason`、`covered`／`uncovered`、`identity`）。資料夾唯讀走訪、不跟隨連結、有上限，不執行任何東西。
  - **本機 linux-stable（離線 git）**：環境變數 `KERNEL_STABLE_GIT`（`--stable-git`，clone 的資料夾，唯讀、不 fetch；`lib/kernel_git_files.py`，只執行
    `git cat-file --batch-check` 與 `git log --no-walk --name-only`，clone 的設定不信任）。(a) 沒有 CNA 紀錄的 CVE：Grype／DT 的 references 裡
    git.kernel.org／github torvalds 的 commit，**每一個都查得到**才用，取程式檔與標頭檔照一般規則判斷，一個查不到就照舊 unknown；
    (b) 有 CNA 紀錄的 CVE：紀錄裡修補 commit（git 範圍的 `lessThan`）在 clone 裡的（產品分支的 backport），實際改的程式檔／標頭檔（這個核心有的檔案）和
    `programFiles` **聯集**，只會更保守（例如主線改 `btmtk.c`、6.1 的 backport 改 `btusb.c`）。結果在 `kernel.stable_git`，
    每筆多 `files_origin`、`stable_git_commits`、`stable_git_added_files`。
  - **CNA 版本比對的分支修補**（`kernel_cna_version.py`）：同一筆紀錄有只含 git 範圍的項目（defaultStatus unaffected），另一個項目的 semver 明寫
    「X.Y.Z <= v <= X.Y.\*：unaffected」而且涵蓋產品版本 → 以分支紀錄為準判 not_affected（理由 `branch X.Y fixed in X.Y.Z`）；有 semver 項目判受影響、
    不受影響範圍內有「從這版開始有問題」、或另有其他 unknown 原因 → 仍 unknown。
  - **「規則判斷不了」的兩條安全規則**：①檔案不在出貨的核心原始碼樹（`--source-tree`，檔名完整、路徑上沒有符號連結）、Makefile 也沒有規則提到它，而且 CNA 紀錄說問題
    在比這個核心新的版本才出現（`kernel_cna_version.introduced_after`）→ 沒編，兩項證據缺一不可；②`arch/<其他架構>/` 底下被 `#include` 的 `.c`，
    `#include` 它的檔案也都在其他架構 → 沒編。
  `scan-flash-package.sh` 完整掃描（Jetson）現在也把刷機包（`--archive`／`--dir` ＋ rootfs 前綴）交給 C-kernel-config，才讀得到實際燒錄的 `kernel/Image`
  （以前只有 rootfs 的 `/boot/Image`，NVIDIA 原廠的，建置紀錄因 `.config` 不同被拒用）；`--kernel-source <核心原始碼樹>` 等同環境變數 `KERNEL_SOURCE_DIR`。
  `C-kernel-module-map`（`lib/kernel_module_map.py`，`scan/kernel-module-map.json`，緊接在 C-kernel-config 之後，同樣的輸入；
  讀取、CVE 的選取、CNA 鏡像與 Makefile 解析都沿用 `kernel_config.py`）：每個核心 CVE 的每個 programFile 依 Kbuild 的文字規則
  對應到它最後連結成的物件，而不是用檔名猜：`obj-y`／`obj-$(CONFIG_X)`=y → builtin；`obj-m`／=m → 那個物件的 `.ko`；
  組合物件 `foo-y`／`foo-objs`／`foo-$(CONFIG_Y)` 的成員跟著 `foo.o`（可多層）；資料夾以 `obj-$(CONFIG_X) += dir/` 進入（=m 或 `subdir-`
  進入時裡面的 `obj-y` 不會連進 vmlinux → unknown）；built-in 組合物件的 `foo-m` 成員 → unknown；`lib-y` → builtin。
  `$(subst m,y,$(CONFIG_X))` 與 `$(CONFIG_X:m=y)` 在 X=m 時是編進核心（物件與資料夾都是）；同一個物件同時在 obj-y 與 obj-m 時
  只編進核心（Kbuild 的 `obj-m := $(filter-out $(obj-y),$(obj-m))`）。物件（或包含它的任何一層組合物件）也列在 `extra-`／`always-`
  （另外建置的目標，不經 obj- 連結）→ 不說「只在模組」，unknown。
  Kbuild 的模組名稱要和 `/usr/lib/modules/<版本>/modules.order`（=m）一致，=y 的不能出現在 modules.order（modules.builtin 有列時記下路徑）；
  對不上 → unknown，reason 以 `kbuild/modules.order disagree` 開頭，不挑一邊（Kbuild 判沒編、清單卻列了它也算）。名稱比較時 `-` 與 `_`
  視為相同（同 modprobe）。Kbuild 判斷不了、但物件本身列在 modules.builtin → builtin（只往保守的方向補；組合物件列在 modules.builtin 不代表成員都在）。
  「只在模組」要和 C-kernel-config 的「沒編」同樣的證明（路徑上與每一層組合物件的 Makefile 都看得懂、沒有別的資料夾的規則直接編它、有 #include 的 .c 清單），
  否則 unknown；not_built 就是 kernel_config.py 判 False，且 not_affected 的前提也成立（有清單、有模組目錄、沒有同名 .ko）。
  只對應，不做 not_affected 判定（K2「模組移除或停用」讀這個檔）。C-kernel-config 與這個階段各自讀一次 CNA 鏡像：sca-scan 以
  `--kernel-config scan/kernel-config.json` 傳入，兩邊鏡像的 commit 與 zip_sha256 都記下（`sources.cna_mirror`、
  `sources.kernel_config_cna_mirror`），以 zip_sha256 比對：不同，或任何一邊沒有記錄 → 這個檔記 GAP。
  狀態：沒有核心的 CVE → NOT_RUN（不寫這一列）；沒有 .config／Makefile、版本不符、CNA 鏡像沒有或過期 → GAP（`cves` 為空）；
  沒有模組目錄或缺 modules.order／modules.builtin → GAP（`cves` 照列，`in_image` 為 null；沒有 modules.order 時名稱無法核對，
  Kbuild 判成模組的檔案一律 unknown）；其他 OK。K2 只採用 `status` 是 OK 的檔。
  格式（schema `sca-center-kernel-module-map/1`）：
  - 最上層：`schema`、`status`（OK／GAP）、`detail`、`method`（160 字元以內的一句說明，報告與 VEX 說明會引用）、
    `method_detail`（完整的方法說明）、`kernel`（`version`＝`uname -r` 形式，例如
    `6.8.12-1021-tegra`；`config_source`、`config_sha256`、`makefiles`、`source`、`config_header`、`included_c_list`、`modules`）、
    `component`（`name`、`version`、`purl`；與 kernel-config.json 同一個核心元件、同一套比對）、`sources`（`kernel_version`、`config`、
    `config_sha256`、`modules_dir`、`modules_order`／`modules_builtin`：`{path, sha256, entries}` 或 null、`modules_order_sha256`／
    `modules_builtin_sha256`（或 null）、`cna_mirror`：路徑、commit、
    下載時間、`ok`、`reason`）、`inputs`、`counts`（`cves`；`files`：各 build 值的檔案數；`builtin`：`{"true","false","null"}` 的 CVE 數；
    `all_in_modules`；`unmapped`）、`modules_order`／`modules_builtin`（映像那個核心版本的 modules.order／modules.builtin 裡的每個
    模組名稱，modprobe 形式：去掉路徑與 `.ko`、`-` 換成 `_`，排序；檔案沒有時 null）、`modules_present`（`/usr/lib/modules/<版本>/`
    底下任何位置看得到的每個 .ko 的名稱，含 `updates/`、`extra/` 與資料夾連結底下的，同樣的形式；有 gaps 時也照列看得到的名稱；
    只有沒有模組目錄時是 null）、`modules_present_gaps`（modules_present 可能不完整的原因；完整時是空清單）、`cves`、`limitations`。
    每個 CVE 的 `modules` 與 build 是 module 的 `files[].module` 一定通過 modules.order 的核對，所以一定在 `modules_order` 裡
    （K2 只把 `modules_order` 裡的名稱當成可以被移除的模組）。
  - `cves`：物件，鍵是大寫的 CVE 編號（kernel-config.json 用的是 `results` 清單；這裡依 K2 的需要用物件）。每一筆：
    `builtin`（只會是 JSON 的 true／false／null：true＝有檔案是 builtin；false＝每個檔案是 module 或 not_built，且至少一個 module——
    編進去的程式只在模組裡；null＝其他，包括有 unknown、標頭檔、非程式檔、清單對不上、沒有 CNA 紀錄，以及全部 not_built：
    reason 是 `all files not_built (K1 / kernel-config decides)`，檔案的證據照列）、`modules`（build 是 module 的檔案的模組名稱，`_` 形式，
    排序）、`modules_kbuild`（Kbuild 原名）、`all_in_modules`（每個檔案都是 module）、`shadowed_by`（`{模組名稱: [.ko 路徑]}`：
    模組目錄裡同名、但不在 modules.order 那個路徑的 .ko，例如 `updates/` 的 out-of-tree 模組；modprobe 會優先載入 `updates/`，
    Jetson 的 host1x、tegra_drm 就是這樣蓋過樹內的模組；沒有時是空清單）、`reason`、`hints`（`header_only_with_unbuilt_c`：
    修補動到標頭檔，而動到的 .c 全部沒編；只是提示，不是判定）、`files`。
  - `files[]`（K2 讀 `path`、`build`、`module`、`module_path`、`in_image`、`reason`；其他欄位是附加的證據）：`path`（CNA 的 programFile 原樣，repo 相對路徑）、`build`（`builtin`／`module`／`not_built`／`unknown`）、`object`（樹內的 .o；非程式檔為 null）、
    `module`（`_` 形式的名稱）、`module_kbuild`（Kbuild 的原名，例如 `my-dash-drv`）、`module_path`（modules.order 或 modules.builtin
    裡的原文，例如 `kernel/drivers/net/foo.ko`）、`in_image`（true／false／null）、`reason`、`configs`（決定結果的 CONFIG 符號）、
    `links`（每一條 Kbuild 路徑：`kind`、`object`、`module`、`module_kbuild`、`module_path`、`in_image`、`cross_check`（ok／unavailable）、
    `rule`、`shadowed_by`）、`other_same_name`（模組目錄裡其他位置的同名 .ko 的路徑原文，例如 `updates/` 的 out-of-tree 複本；
    只比對檔名的 `-`／`_`，資料夾名稱照原樣）。一個檔案連進多個模組時
    `module`、`module_path`、`in_image` 是 null，看 `links`。
  - `in_image` 只是證據（模組路徑的 .ko 在不在映像的模組目錄；builtin 而 modules.builtin 有列時 true）：K2 不用它判斷「模組被移除」。
  - **給 K2 的約定**：一個模組是否「不在映像裡」只能依正規化的名稱（`-`＝`_`）在整個模組目錄（含 `updates/`、`extra/` 等任何位置）
    判斷，也就是 `modules_present`；不能只看 modules.order 的路徑或 `in_image`（同名的 out-of-tree 模組會被 modprobe 載入，
    見 `shadowed_by`）。`modules_present_gaps` 不是空的時，要當成「模組在不在映像裡不知道」，不能說某個模組不在；
    `modules_present` 是 null 表示沒有模組目錄，同樣不知道。
- ScanCode.io：上傳前另產 `sbom/sbom.scancodeio.cdx.json`（`lib/scio_prep.py`，`E-scancodeio-prep`）：攤平巢狀元件、移除 `type=file`
  元件與超過 ScanCode.io 欄位上限（packageurl-python PackageURLMixin：name／version 100 字元等）的元件；DT 與原始 SBOM 不受影響。
  只移除 `type=file` 時記 OK；任何非 file 元件被移除（含沒有 purl 的）記 GAP，列出類型與數量。報告授權節列出數量鏈：
  原始 SBOM 元件 → 上傳 ScanCode.io（移除 file／過長／其他）→ ScanCode.io 套件 → DejaCode 產品套件。load_sbom 失敗時存 `dejacode/scio-run-detail.json`（`/api/runs/<uuid>/`，含完整 task_output）
  與 `dejacode/scio-messages.json`，FAIL 說明帶例外摘要（`lib/scio_diag.py`）。
- 授權與版權（`docs/benchmarks/feature-parity-2026-10.md` 第 1–5 項）：
  - `E-package-scan-submit`／`E-package-scans`／`E-package-scan-update`：DejaCode REST `load_sboms`（`scan_all_packages`、`infer_download_urls`、
    `update_existing_packages`）讓 DejaCode 以 purl 推下載網址、逐一交給 ScanCode.io `scan_single_package`；等到 `/scans/` 沒有排隊或執行中的
    （最多 `PACKAGE_SCAN_WAIT_SECONDS`，預設 3600）。webhook 可能送不到（逾時 10 秒），所以再觸發一次補上。失敗的掃描另存原因
    （`dejacode/package-scan-failures.json`，`lib/scio_failures.py`）。沒有授權的套件在上傳的 SBOM 裡標成 `unknown`（元件屬性
    `aboutcode:declared_license_expression`；`dejacode/djsbom.json`，`lib/djsbom.py`）。NuGet 改寫成 v3 下載網址、apk 補上下載網址（DejaCode 推出來的網址 HEAD 回 404，或讓整份匯入失敗；查不到 repo 時用猜的網址，只讓那個套件掃描失敗）、沒有授權的 Maven jar 有 `-sources.jar` 時改掃它（只有 .class 的 jar 掃不到授權）。下載網址也是 DejaCode 找既有套件的依據：這個修改之前匯入過的 NuGet 套件，重新匯入時同一個 purl 會多一個 v3 網址的套件，`E-package-scans` 會寫出「同一個 purl 有多個套件」並標 ATTENTION，舊的要從產品移除（離線或網路不穩時，Maven 改不了 sources jar、APKINDEX 讀不到而猜錯 repo，也會造成同樣的情形）。這時產品套件只由 `load_sboms` 匯入、不先 `import_from_scan`：
    兩者找既有套件的欄位不同（`filename`），混用會讓同一個 purl 建兩個套件（pilot-run/12）。`load_sboms` 失敗時，只有匯入已經結束（或沒有送出）、而且產品套件數和匯入前相同才改用
    `import_from_scan`（`pkgscan.py count`）；否則只讀回已匯入的。
    等待逾時時，取消這個產品留在 ScanCode.io 佇列裡的掃描與匯入（排隊中的刪 run 再刪專案；執行中的不停止、讓它跑完，因為 `stop_pipeline` 會殺掉 worker 的子程序；`dejacode/*-cancel.json`，`lib/scio_cancel.py`）：
    ScanCode.io 只有一個佇列，留下的工作會讓下一次 sca-scan 排隊逾時。ScanCode.io 是共用的，同時有別的產品在掃同一個下載網址時，那個掃描也會被取消。
    匯入逾時時 `load_sbom` 還在執行（或 DejaCode 還在匯入）的話，DejaCode 之後仍會匯入並送出整批逐套件掃描，這些會留在佇列裡（已知限制）。
    升級：main 上用 `import_from_scan` 建過的套件（DejaCode 整個 dataspace 共用）第一次遇到 `load_sboms` 時，可能因為上面的欄位差異重複建套件或撞唯一鍵；
    `E-dejacode-import` 會記 GAP（讀回數≠唯一 purl 數）或 ATTENTION（匯入有 errors）。既有的試行部署沒有核對過，要清掉 DejaCode 的套件或另開 dataspace 才能確定不受影響。
  - `E-dejacode-import`（`--no-package-scan` 與 load_sboms 失敗時的退回）：`import_from_scan` 是同步請求，ScanCode.io 結果分批送（`lib/scio_chunks.py`，
    每批 `DJ_IMPORT_CHUNK` 個套件，預設 1000；每批的時間隨產品已有的套件數增加，demo-run/4 每批 500 時 267→632 秒），每批的 http 與秒數記在 `dejacode/import-chunks.tsv`。一次送 3851 個套件時 30 分鐘沒有回應（Jetson 示範 demo-run/1–3）。
    試行版的 DejaCode 沒有背景工作（`DEJACODE_ASYNC=False`），`pull_scancodeio_project_data` 也是在請求內同步執行，所以不用它。
  - `E-os-copyrights`（只有映像；**預設關閉，`OS_COPYRIGHTS=1` 才做**：Jetson 映像的 2032 個版權檔讓 ScanCode.io 的 scan_for_files 程序池中止，demo-run/5、6，原因未查明）：映像裡的 `/usr/share/doc/<套件>/copyright`（Debian／Ubuntu 套件安裝後留下的版權檔，多數是 DEP-5）取出來
    （`lib/oscopyright.py extract`：只讀 docker save 的 tar 結構，處理 whiteout 與符號連結）交給 ScanCode.io `scan_codebase`，結果按套件名稱對回
    load_sbom 的 deb 套件（`scancode/os-copyright-evidence.json`），和逐套件掃描的證據合併給 `E-notice`（`dejacode/copyright-evidence.json`）。
    上傳的檔名是 `<套件>/debian-copyright.txt`，不讓 ScanCode 當成 Debian 套件中繼資料解析（demo-run/5：2032 個 `copyright` 讓 worker 中止）；單檔上限 512 KB。
    `E-os-license-sync`：DejaCode 產品套件授權是 unknown 或空白、版權檔掃到授權的，補上產品套件授權（`pkgscan.py sync-os`，`dejacode/os-license-sync.json`）。
    不受 `--no-package-scan`、`--no-files-scan` 影響。為什麼不逐套件下載 deb：整個系統映像上千個 deb 照目前速度要 30 幾個小時，而且 ScanCode.io
    的摘要不把 deb 的 copyright 檔當 key file，DejaCode 只拿到版權人（說明在該檔）。所以 deb 的下載網址預設不改（DejaCode 推的網址多半不存在，
    不會被掃）；只有少數 deb 又要逐套件掃描時設 `DEB_PACKAGE_SCAN=1`，`lib/djsbom.py` 改寫成 Launchpad／Debian pool／`DEB_EXTRA_REPOS` 的網址。
  - `E-license-sync`：產品套件授權仍是 unknown、套件宣告授權已知的，照 DejaCode 的 `ProductPackage.update_license_unknown` 補上（`lib/pkgscan.py`）。
  - `E-copyrights`：掃描成功的套件讀 DejaCode 的 `scan_summary`，留下宣告授權、版權人、key files 的版權聲明與 NOTICE 檔
    （`dejacode/package-scan-evidence.json`）。DejaCode 沒偵測到版權時填的「Copyright <名稱> project contributors」標成推定，不算偵測到。
  - `E-dejacode-licenses`：判定照 DejaCode 的算法（運算式裡每個授權都算、取最嚴重的）；`compliance.json` 另有 `or_choice_verdict`
    （SPDX OR 擇一時的等級，只是提示）與 `license_expression_spdx`（用 DejaCode 授權庫的 `spdx_license_key` 換成 SPDX）。
  - `E-notice`：`dejacode/NOTICE.txt`（套件、授權、偵測到的版權、NOTICE 檔、DejaCode 授權庫的全文；`lib/notice.py`）。工具產生的草稿，發布前要人工確認。
  - `E-files-scan`：專案本身（原始碼，在 cdxgen 之前封存，不含 cdxgen 裝的依賴）用 ScanCode.io `scan_codebase`，映像用 `analyze_docker_image`，
    掃檔案層級的授權與版權（`scancode/files-summary.json`，`lib/filescan.py`）。`--sbom` 沒有檔案，記 NOT_RUN。
    `--dir` 複製來源時排除 sca-scan 自己的暫存區與輸出資料夾（`lib/common.sh` 的 `copy_dir`；`sca-scan --dir .` 時它們在來源底下，暫存區有金鑰標頭檔）。
  - 逐套件掃描會從套件來源（npm、Maven Central、PyPI…）下載；離線部署要讓 DejaCode 與 ScanCode.io 連內部套件代理（CLAUDE.md 修正 4）。
    已知限制：apk 推不出下載網址（not_scannable）、deb 推出的網址用套件名稱當 pool 路徑，來源套件名稱不同時不存在（no_scan）；PyPI 名稱含 `-` 時 DejaCode 推的 sdist 網址可能不存在（e2e 第 18 輪 8 個不可達）。
- 報告：非 OK 的階段放最前面；階段說明與工具輸出原樣顯示；報告自己不寫結論字樣（`report.conclusion_hits`，否定句型放行）。

## 核心版本 → 受影響的 CVE（`lib/kernel_cna_version.py`，獨立工具，不在 sca-scan 流程裡）

給一個核心版本（例如廠商核心的 `6.1.118`），從 Linux 核心 CNA 鏡像（`tools/mirror/kernel-cve.sh` 的 `kernel-cves.zip`）
找出這個版本受影響的 CVE；產生的清單可以直接給 `kernel_config.py --cves`（再判斷修補的程式有沒有編進核心）。
```
python3 -I tools/pilot/lib/kernel_cna_version.py --kernel-version 6.1.118 --mirror <KERNEL_CVE_MIRROR> \
  --out kernel-cna-6.1.118.json --cves-out kernel-cna-6.1.118.txt [--affected-only]
```
- 只看 `containers.cna.affected[]` 裡 product 是 Linux 的 semver 範圍：`{version, status: affected}`（從這版開始有問題）、
  `{version, lessThan, status}`、`{version, lessThanOrEqual: "6.1.*" 或 "*", status: unaffected}`（在那個分支的哪一版修好）、defaultStatus。
  versionType 只認 semver 或沒有寫（git、original_commit_for_fix 與其他都不算）；只有這種版本的項目整個不用（不拿它的 defaultStatus）。
  同一個項目裡有非 semver 的受影響範圍、semver 又沒有涵蓋這個版本時，不用 defaultStatus unaffected（→ unknown）。
  不受影響的範圍裡有 ≤ 這個版本的「從這版開始有問題」（問題被移植進穩定分支）、或 status 不是 affected／unaffected 的項目涵蓋這個版本 → unknown。
- 每個 CVE 的結果：affected、not_affected、unknown（沒有 semver 資訊、範圍矛盾或看不懂）。JSON 列每個 CVE 的依據與 programFiles；
  文字清單是 affected＋unknown（不知道的不能在下游消失；`--affected-only` 只放 affected，沒列的 unknown 數量記在 `gaps`），每行一個 CVE、沒有註解。
- **狀態一律 GAP**：CNA 資料主要是 2024-02 以後核心團隊發的編號，更早由其他單位發的 CVE 不在內，要另外用 NVD 補查（這個工具沒有做）。
  鏡像過期、用 `--zip` 而沒有 SOURCE、zip 有被拒絕的成員，也寫在 `gaps`。限制逐條列在輸出的 `limitations`：
  只看版本號（廠商核心可能自己移植過修補）；主線的修補（original_commit_for_fix）只在 semver 判 affected 時使用：主線修補 ≤ 產品核心的主.次（X.Y、X.Y.0、X.Y-rcN；-rc 的修補 X.Y 正式版已含）→ not_affected（「mainline fixed in X.Y, before this branch」，穩定分支從主線分出來時已含修補）；主線修補 > 主.次且分支沒有自己的修補紀錄 → 維持 affected（記 note）；修補版本解析不了 → unknown；分支有比 v 新的修補紀錄卻說主線早已修好 → unknown（矛盾）；
  版本的後綴（例如 `-rockchip`）不看、`-rc` 不支援，像發行版 ABI 的版本（`5.15.0-125-generic`、`6.1.0-28-amd64`）與 X.Y、X.Y.0 加後綴的版本（`6.1.0-rpi7-rpi-v8`）拒絕、要給上游版本；
  結果只對這份鏡像（commit、zip_sha256）有效。
- 鏡像的 `zip_sha256` 和 SOURCE 不符 → FAIL（不輸出）；沒有任何可用的紀錄 → FAIL（不輸出空清單）。
- zip 只讀進記憶體：名稱不是 `cve/published/<年>/CVE-<年>-<數字>.json`（路徑穿越、絕對路徑）、重複的名稱、單筆超過 8 MB
  （宣告的大小與實際讀到的都檢查）、合計超過 1500 MB 的成員拒絕並列在 `zip.rejected_examples`。
- 每筆紀錄讀完就判定、只留結果（不留整份 JSON）；形狀不對的紀錄只影響那一筆（記 unreadable，狀態 GAP）。
- 輸出記錄鏡像的名稱、commit、fetched_utc、zip_sha256 與這支程式的 sha256（不記絕對路徑與年齡）；同樣的輸入除了 `generated_utc` 逐位元組相同。

## 檔案
| 檔案 | 用途 |
|---|---|
| `sca-scan` | 掃描入口 |
| `report.py` | `report.html`（單一檔案、離線、深色模式）與 `report.json` |
| `compare_expected.py`、`ci-scan-check.sh` | 對照 `tests/expected` 與 PHP 映像已知答案（給自架 runner） |
| `lib/common.sh` | 與 `tools/e2e/real-projects.sh` 共用的函式 |
| `lib/lockcheck.py`、`lib/strip_versions.py`、`lib/leakscan.py` | 規則 11、規則 13、外洩檢查 |
| `lib/kernelcheck.py` | 作業系統核心有沒有做弱點比對（C-kernel-coverage） |
| `lib/kernel_cna_version.py` | 核心版本 → 受影響的 CVE（Linux 核心 CNA 的 semver 範圍；獨立工具，清單給 `kernel_config.py --cves`） |
| `lib/l4t_kernel.py`、`lib/l4t-kernel-map.json` | Jetson Linux 核心對應的 Canonical 核心元件，只供比對（C-kernel-l4t-map） |
| `lib/djsbom.py`、`lib/pkgscan.py`、`lib/scio_failures.py`、`lib/scio_cancel.py`、`lib/notice.py`、`lib/filescan.py` | load_sboms 用 SBOM、逐套件掃描、失敗原因、逾時後取消、NOTICE、檔案層級掃描摘要 |
| `lib/dtsources.py` | DT 弱點與 KEV 資料源的 mirror 狀態 |
| `lib/distro_recheck.py` | 只經 NVD 比對到的 Debian／Ubuntu 發現以發行版的 OSV 紀錄再判（D-distro-recheck） |
| `lib/usn_cves.py` | 沒有 CVE 別名的 USN 從 Ubuntu 的 OSV 鏡像查它列的 CVE（D-usn-cves） |
| `lib/ubuntu_priority.py` | Ubuntu 套件上的 CVE 從 Ubuntu 的 OSV 鏡像讀 Ubuntu priority（D-ubuntu-priority；CRA 分級的嚴重度） |
| `lib/euvd.py` | ENISA EUVD 索引與標註（C-euvd）；由 EUVD kev/dump 產生 DT 的 ENISA KEV 來源檔（dt-feeds.sh 的 euvdkev） |
| `lib/ubuntu_status.py` | Ubuntu 套件上的 CVE 從 Ubuntu CVE Tracker 狀態鏡像取出 Ubuntu 的狀態（D-ubuntu-status；CRA 證據規則 U1） |
| `lib/scio_prep.py`、`lib/scio_diag.py` | ScanCode.io 上傳前轉換、load_sbom 失敗摘要 |
| `tests/` | pytest（CI：`.github/workflows/tests.yml`） |
