# WP7 標準答案的核對紀錄（M6）

標準答案（`tests/expected/<專案>/<版本>.json`）**不是直接存第一次的輸出**（C0 的要求）：每一項都對照官方資料或可以獨立重算的依據核對過，
再由驗證代理獨立核對一次（結果附在本檔最後）。元件數、雜湊、狀態用 `equals`；漏洞數與核心 CNA 清單隨資料庫變動，用範圍。

## rock-5b-demo v1.0.0-demo1（Rockchip，Radxa ROCK 5B rsdk-r6）

- 依據的執行：dev run 43366738948（commit 62d92b8），2026-11-13。第一版標準答案依 43354620546（2a50091）訂；驗證代理第一輪「需要修改」，改了輸出與標準答案後第二輪「可以定案」（見下面「驗證代理的獨立核對」）。
- 先前幾次執行找到並修好的問題（所以不拿那幾次當標準答案）：
  1. unknown 122187／126696：沒有 owners.json，Syft 的檔案紀錄找不到擁有的套件 → assemble 從 dpkg .list 產生 owners.json。
  2. unknown 3950：dpkg 自己的資料庫檔（var/lib/dpkg/*）不屬於任何套件 → 平台設定歸 os。
  3. 核心完全沒有評估：Grype 對廠商核心 0 筆、CNA 不把 `6.1.84-8-rk2410` 當上游版本 → D-038。
  4. OS 報告多了 8943 列 linux-kernel：KERNEL_CVES 在 -os 重跑也套用 → -os 重跑不帶。

| 項目 | 標準答案 | 怎麼核對的 |
|---|---|---|
| 映像 sha256 | 76f434fa… | sources.yml 固定；與 GitHub 附件 digest、官方 sha512sum 相同（platform-samples 時核對） |
| 解開後的 sha256 | d93a7889… | 本機與 CI 各解一次，相同 |
| deb 套件 | bsp 50＋os 1779＝1829 | 官方 `rock-5b_bookworm_kde_r6.manifest` 的 1829 個套件，名稱與版本完全相同（驗證代理逐一比對）；映像 rootfs 的 dpkg .list 也是 1829 個 |
| 元件 | 共 126696：bsp 16332、os 110333、unknown 31 | Syft 1.55.0（固定）× 固定映像；unknown 31＝pypi 30、maven 1（缺口 12，保守列待辦，會讓 bsp 報告多 46 列） |
| 原始磁區 | OK | 本機用官方 u-boot-rk2410 deb 與 rootfs 的同名檔逐位元組比對（idbloader.img、u-boot.itb）；FIT 5 個映像重算 sha256 與 FIT 記載的相同；CI 結果相同 |
| 原始磁區讀到的版本 | U-Boot／SPL rk2410-2017.09-64-39cd993、DDR v1.22、BL31 v1.54 | 磁區字串；與 deb 的版本（2017.09-64-39cd993）一致 |
| U-Boot CVE | 48 個候選（U-Boot、SPL 各一列） | D-034：CPE `cpe:2.3:a:denx:u-boot:2017.09`，advisory-check ATTENTION、進待人審 |
| DDR 初始化、BL31 | advisory-check GAP | 閉源成品，沒有可機器比對的安全公告 |
| 核心判定範圍 | judged [6.1.84-8-rk2410]、not_judged [] | 映像只有一顆核心（/usr/lib/modules） |
| 上游版本 | 6.1.84，兩個來源一致 | 映像模組資料夾與 radxa/kernel@87ba2c6 的 Makefile；本機與 CI 結果相同 |
| 出貨 config | /boot/config-6.1.84-8-rk2410（sha256 cedfaa40…） | 核心 config 檢查用的 linux-headers 的 .config 與它的 sha256 相同（cedfaa402b3c…） |
| 核心 CNA 清單 | 8943 個候選（範圍 8000–12000） | vulns.git commit 625c095b0b852f8b19d8d8eb68c8eac032e6706a（2026-11-11）；CNA 紀錄 18225 筆，affected 7718＋unknown 1225；清單本身標 GAP（2024-02 以前其他單位發的 CVE 不在 CNA 資料裡） |
| 依 .config 排除 | accepted 3627 | VEX not_affected／code_not_present，source 目前是 `kconfig`；依據是實際出貨的 config（shipped-config），名稱在 C1 的 M7 統一 |
| 開機鏈分類 | NOT_ASSESSED | Rockchip 沒有定義開機鏈（缺口 3） |
| 對外連線服務 | NOT_ASSESSED | 只有 Raspberry Pi 定義了清單；Rockchip 的映像有 ssh、avahi 等服務，沒有評估（缺口 15） |
| 報告的核心列 | os 0、bsp 8943；U-Boot 列只在 bsp（96） | scan.json 的 report_rows（機器可核對） |
| OS 報告 | 2812 個 CVE（範圍 2000–4500），沒有核心的列 | Debian 12 KDE 桌面的套件；核心只屬於 bsp |

**預期的 GAP（不是錯）**：C-kernel-coverage（Grype 對廠商核心沒有比對，改由 CNA 清單）、C-sbomgate（版本未知的元件不比對）、
D-dt-data-sources／C-dt-feeds／D-dt-findings（NVD 照設計關閉）、D-dt-kev-sources（DT 讀的 ENISA KEV 檔沒有發布日期）、
核心 CNA 清單（2024-02 以前的資料範圍）。精靈的「3b. A0 與 NVIDIA 原版的逐檔比對」是 Jetson 專用，這裡照實是 GAP（缺口 2）。

## rpi-lite-demo v1.0.0-demo1（Raspberry Pi OS Lite 2026-10-06）

（待補：最新一次執行完成後核對）

## ai-nas-demo v1.0.0-demo1（Debian 13＋OpenMediaVault）

- 依據的執行：dev run 43386797521（commit 5bd67f0），2026-11-13；標準答案草稿 60 項，等驗證代理獨立核對。
- os_responsibility 是 ours：只有一份報告，是補充（OMV 原始碼）與分層**之後**用產品 SBOM 重跑的（platform_scan.collect 同一個後綴取後面那次）；notes 原本沿用「完整報告是分層之前」的說法，已改成依 os_responsibility 分開寫。
- 先前幾次執行找到並修好的問題（不拿那幾次當標準答案）：cdxgen 沒裝（C1 加 `scan.tools: full`）；Debian 映像的 GNU sparse tar；分層計畫用 TAB 分隔讓 ours 的空後綴被吃掉（改用 C1 的 0x1F）；own_software 對不到元件（app_name／app_version 由 sources.yml 指定）；sca-scan 非 0 時原始碼掃描的非 OK 階段沒有記錄（改記在 scan_stages_not_ok）。

| 項目 | 標準答案 | 怎麼核對的 |
|---|---|---|
| 映像 sha256 | 1e10629e… | sources.yml 固定；與官方 SHA512SUMS 同一個檔（platform-samples 時核對） |
| disk.raw sha256 | 5b38b6ee…（3 GiB） | assemble 串流取出；精靈的 A-provenance 重算是同一個值 |
| deb 套件 | os 322、bsp 沒有 | Debian 官方清單 `debian-13-generic-amd64-20261111-2659.json`（sha256 59bc90c5…，D-037）的 322 個套件，名稱（去掉 `:amd64`）與版本和 SBOM 的 pkg:deb 完全相同（C4 逐一比對） |
| 元件 | 共 27220：bsp 2、os 25493、unknown 1725 | bsp＝OMV 根元件（own_software）＋子元件；unknown＝OMV 原始碼相依 1691（npm 1679、pypi 5、composer 4、github 3，缺口 7）＋映像的語言套件 34（pypi 33、maven 1，缺口 12） |
| OMV 原始碼 | commit 9d8530ff、8.6.1-1 | 固定 commit 的 `deb/openmediavault/debian/changelog` 第一行是 `openmediavault (8.6.1-1)`（C4 從 GitHub 讀過）；原始碼 vs deb、版本 vs commit 都是 NOT_ASSESSED（D-025） |
| 核心原始碼 | OK：86／86 個 patch，Debian 6.12.116-1 | D-035；映像的核心套件版本也是 6.12.116-1 |
| 核心 | 6.12.116+deb13-amd64，上游 6.12.116 | 映像只有一顆核心；C-kernel-coverage OK（Debian 自己的核心，Grype 依 Debian 資料比對，428 列） |
| 核心 .config | C-kernel-config、C-kernel-module-map GAP | 雲端映像沒有核心 headers 套件 |
| 開機鏈 | NOT_ASSESSED | x86 沒有定義（缺口 3） |
| 對外連線服務 | NOT_ASSESSED | 沒有定義清單（缺口 15）；映像開機就有 ssh（image-check） |
| 漏洞 | 934 個 CVE、990 列（範圍 500–3000／500–3500）；unknown 層 169 列（50–800） | 資料庫會變；unknown 層的下限用來抓「原始碼沒有併入」 |
| 產品狀態 | 報告 GAP、發行閘門 GAP | 釘住，避免被默默變成 OK |

**預期的 GAP（不是錯）**：C-pyver（OMV 的 5 個 Python 相依沒有版本）、C-sbomgate、C-kernel-config／C-kernel-module-map（沒有 headers）、
D-dt-data-sources／D-dt-kev-sources（NVD 照設計關閉、ENISA KEV 沒有日期）、A-md5（Debian 沒有 md5）、
B-own-software（CRA 設定的 own_software 是範本的虛構路徑，缺口 21；標準答案不釘）。B-rockchip 的 ATTENTION 名稱與 EEPROM 訊息對 x86 不適用（缺口 20）。

## 驗證代理的獨立核對

### rock-5b-demo（第一版標準答案，2026-11-13）

驗證代理（Sonnet 5.5，effort high，只讀）不看 C4 的結論，從 artifact、官方 manifest 與官方 deb 重算每一項。總結：**需要修改**。
重算的數字（元件數、雜湊、核心版本、.config sha256、accepted 列）全部與原始資料吻合，沒有寫錯的值；問題與處理：

| 嚴重度 | 發現 | 處理 |
|---|---|---|
| 嚴重 | `external_services` equals []：清單只定義了 rpi-connect，Rockchip 從來沒評估過，卻寫成「沒有」 | scan.json 改成 {status, items, reason}，沒有定義清單的平台記 NOT_ASSESSED；標準答案釘 status |
| 中 | CNA 清單已知不完整（2024-02 以前）沒有機器可核對的標記 | 加 `kernel_upstream.cna.gap`（true）並釘住 |
| 中 | 三個漏洞數的上限太窄（核心 CVE 約每月 +500，半年內會誤失敗） | cna.cves 與 bsp.cves_total 上限 35000、accepted 12000、os 6000 |
| 中 | 完整報告是補充與分層之前的掃描（沒有 U-Boot、沒有層） | notes 加說明；缺口 14；標準答案不釘完整報告的漏洞數 |
| 中 | -os 重跑的核心階段出現沒有意義的 GAP | 缺口 13；標準答案只釘完整與 -bsp 的核心階段 |
| 中 | `rtl8852bu-dkms`、`rtw89-dkms` 與已歸 bsp 的 `rtk-btusb-dkms` 同類卻歸 os；C4 原本「板上藍牙」的註解是錯的（ROCK 5B 板上沒有） | 三個都歸 bsp（板子廠商替選購無線模組提供的 DKMS 驅動），deb 50／1779 |
| 中 | unknown 31 會讓 bsp 報告多 46 列（含 1 個 P1） | reason 補上 |
| 漏項 | 開機程式的 sha256 與版本、U-Boot 候選數、-bsp 的核心階段、OS 報告不含核心列、預期的 GAP | scan.json 加 raw_sectors.by_slot（鍵不含「.」）、report_rows、product_status；標準答案從 27 項增加到 68 項 |
| 輕 | 幾個 reason 不精確（bsp 的組成、C-kernel-coverage 的原因寫成推測、config 實際讀的是 linux-headers 的副本、judged 的意思） | 改寫 |

未確認（驗證代理沒有讀磁碟映像、沒有連網）：解開後的 sha256、映像與官方 sha512sum 的關係、FIT 內 5 個映像各自重算、radxa/kernel@87ba2c6 是否確為套件的建置來源。


### rock-5b-demo（第二輪複驗，2026-11-13）

同一個驗證代理，依 dev run 43366738948 的 artifact、官方 manifest 與官方 deb 重算 64 項，並讀 D-034～D-041 全文。結論：**可以定案**。

- 上一輪的嚴重 1、中 6、輕與漏項都已處理且正確（逐項對照）；沒有新的「該 GAP 卻被寫成正常值」。
- 補驗上一輪「未確認」的一項：自己解析 FIT，5 個內嵌映像（uboot、atf-1、atf-2、atf-3、fdt）的 sha256 都等於 FIT 記載。
- 元件組成重算：bsp 16332＝50 deb＋15033 檔案紀錄＋1230 核心模組＋13 模組資料夾檔案＋2 firmware＋4 子元件；os 110333＝1779 deb＋104634 檔案紀錄＋3919 dpkg 資料庫檔＋1 OS。DKMS 改歸 bsp 移動的檔案數兩邊相同（1119）。
- 產品狀態：三份報告的 summary.json status 與 vex.gate 都是 GAP（不是 OK）。
- D-038：除了「報告註明候選、廠商可能已回移修補」只出現在 notes.md 與 JSON、沒有進交付的 CRA 報告（cra_report 是 C1 的檔，缺口 16），其他五項要求與實作、標準答案一致。

輕微項目的處理：標準答案的 note 與本紀錄的 run／項數更新；產品狀態六項的 reason 依層各自寫；補釘 A-source、B-sandbox、unknown_by_purl_type（共 68 項）。
dthelper、libmraa*（Radxa 發行、可能和硬體存取有關）目前歸 os，是否歸 bsp 列為缺口 17、待確認。

未確認（沒有讀磁碟映像、沒有連網）：解開後的 sha256、映像與官方 sha512sum 的關係、radxa/kernel@87ba2c6 是否確為套件 6.1.84-8 的建置來源。

### rock-5b-demo（第三輪：差異核對，2026-11-13）

範圍只有兩件：C0 決定 dthelper、libmraa2、libmraa-dev 歸 bsp（第 17 項），以及新增的 D-038 兩邊核對（kernel_upstream_crosscheck）。
依據 dev run 43378104334（commit eacb60d）；標準答案 72 項。結論：**可以定案**。

- deb 50／1779 → 53／1776：正好這三個套件（版本與 manifest 相同），總數仍是 1829；其他套件沒有換層。
- bsp 16332 → 16376、os 110333 → 110289：變動的 44 個是 3 個 deb 與 41 個它們擁有的檔案紀錄（路徑含 mraa／dthelper）；其他類別都沒變。
- 漏洞列數完全沒變（這三個套件沒有任何漏洞列）；只有「沒有弱點資料的套件」清單跟著換層。
- D-038 兩邊核對：C4（兩個來源）與 C1（kernel-versions /2：upstream_version 6.1.84、basis source-makefile+platform-param）都是 6.1.84；
  agree 的計算在任一邊是 null 時是 false，不會誤判。兩邊用同一份 Makefile 與宣告值，這一項是防止實作漂移（reason 已寫明）。
- 沒有新的「該 GAP 卻寫成正常值」。

### ai-nas-demo（第一版標準答案，2026-11-13）

驗證代理（Sonnet 5.5，只讀，沒有連網）不看 C4 的核對紀錄，從 artifact（dev run 43386797521）、Debian 官方清單、本機的 Debian 核心 debian.tar.xz 與 OMV 固定 commit 的 tarball 重算。
結論：**需要修改**。60 項的值全部重算吻合（deb 322 個雙向差集為空、元件 27220 與各層、unknown 的拆分、86 個 patch、changelog 8.6.1-1、報告取 0744 那次、990 列／934 CVE／os 821／unknown 169），
沒有「該 GAP 卻寫成正常值」；要改的是 reason 與漏項：

| 嚴重度 | 發現 | 處理 |
|---|---|---|
| 中 | 核心的 reason 寫成「Grype 依 Debian 資料比對（已考慮 Debian 的修補）」：實際 428 列都是 linux-kernel 元件（pkg:generic）依 NVD 上游範圍比對，Debian 的核心 deb 沒有列 | reason 與 notes 改寫；缺口 22 |
| 中 | C-sbomgate 的 reason 說版本未知的主要是 OMV 相依與檔案紀錄：實際是核心模組 3847 個 UNKNOWN＋5 個 pypi | 改寫 |
| 中 | C-kernel-config／module-map 的 GAP：映像其實有 /boot/config-*，工具只找 build/ 與 linux-headers | reason 補上；缺口 23（工具改善後要更新） |
| 輕 | bsp 2 的組成寫得不精確；根元件的 purl 還是 cdxgen 的 pkg:npm/openmediavault-workbench@0.0.0，與名稱版本不一致；cdxgen-src 是占位元件 | sbom_augment 改了名稱或版本時 purl 改成 pkg:generic/<名稱>@<版本>?vcs_url=…，原值留在 dumpling:source-root-purl（加測試）；reason 照實寫 |
| 輕 | cdxgen 版本沒有固定，元件數依賴它 | reason 註明 |
| 輕 | kernel_versions.shipped 整句 equals | check-expected 不支援清單索引，保留整筆，reason 註明 |
| 漏項 | 沒釘 os 層的漏洞列、D-dt-findings、C-dt-feeds | 加 vulnerabilities.full.layers.os（300–2500）與兩個 GAP |
| 漏項（不屬標準答案） | ours 時 p1_rows 0、P1 判斷表沒有 OS 的 4 個 P1；notes 仍寫「分層之前」 | 缺口 24；notes 的修正（894debd）在這次 run 之後，下一次 run 生效 |

追加核對（同一個代理）：缺口 21 的 own_software 四個樣式在固定 commit 都有對應的檔案（omv-*、183 個 .inc、16 個 .py、3 個 .php），出處 openmediavault.install 相符；GAP／matched 0 是正確結果。

未確認：映像與官方 SHA512SUMS 的關係（本機沒有 SHA512SUMS）、/boot/config 是否真的在磁碟上（只從 SBOM 的檔案紀錄看到）、4 個 P1 的 EPSS／KEV、B-sbom-provided 寫 27219 與 27220 差 1 的原因。
own_software 三項與各文件狀態要等下一次 CI。
