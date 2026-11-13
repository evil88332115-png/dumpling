# WP7 標準答案的核對紀錄（M6）

標準答案（`tests/expected/<專案>/<版本>.json`）**不是直接存第一次的輸出**（C0 的要求）：每一項都對照官方資料或可以獨立重算的依據核對過，
再由驗證代理獨立核對一次（結果附在本檔最後）。元件數、雜湊、狀態用 `equals`；漏洞數與核心 CNA 清單隨資料庫變動，用範圍。

## rock-5b-demo v1.0.0-demo1（Rockchip，Radxa ROCK 5B rsdk-r6）

- 依據的執行：dev run 43354620546（commit 2a50091），2026-11-13。
- 先前幾次執行找到並修好的問題（所以不拿那幾次當標準答案）：
  1. unknown 122187／126696：沒有 owners.json，Syft 的檔案紀錄找不到擁有的套件 → assemble 從 dpkg .list 產生 owners.json。
  2. unknown 3950：dpkg 自己的資料庫檔（var/lib/dpkg/*）不屬於任何套件 → 平台設定歸 os。
  3. 核心完全沒有評估：Grype 對廠商核心 0 筆、CNA 不把 `6.1.84-8-rk2410` 當上游版本 → D-038。
  4. OS 報告多了 8943 列 linux-kernel：KERNEL_CVES 在 -os 重跑也套用 → -os 重跑不帶。

| 項目 | 標準答案 | 怎麼核對的 |
|---|---|---|
| 映像 sha256 | 76f434fa… | sources.yml 固定；與 GitHub 附件 digest、官方 sha512sum 相同（platform-samples 時核對） |
| 解開後的 sha256 | d93a7889… | 本機與 CI 各解一次，相同 |
| deb 套件 | bsp 48＋os 1781＝1829 | 官方 `rock-5b_bookworm_kde_r6.manifest` 的套件數 1829；映像 rootfs 的 dpkg .list 也是 1829 個 |
| 元件 | 共 126696：bsp 15211、os 111454、unknown 31 | Syft 1.55.0（固定）× 固定映像；unknown 31＝pypi 30、maven 1（缺口 12，保守列待辦） |
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
| OS 報告 | 2812 個 CVE（範圍 2000–4500），沒有核心的列 | Debian 12 KDE 桌面的套件；核心只屬於 bsp |

**預期的 GAP（不是錯）**：C-kernel-coverage（Grype 對廠商核心沒有比對，改由 CNA 清單）、C-sbomgate（版本未知的元件不比對）、
D-dt-data-sources／C-dt-feeds／D-dt-findings（NVD 照設計關閉）、D-dt-kev-sources（DT 讀的 ENISA KEV 檔沒有發布日期）、
核心 CNA 清單（2024-02 以前的資料範圍）。精靈的「3b. A0 與 NVIDIA 原版的逐檔比對」是 Jetson 專用，這裡照實是 GAP（缺口 2）。

## rpi-lite-demo v1.0.0-demo1（Raspberry Pi OS Lite 2026-10-06）

（待補：最新一次執行完成後核對）

## ai-nas-demo v1.0.0-demo1（Debian 13＋OpenMediaVault）

（待補：等 C1 的 `scan.tools: full`）

## 驗證代理的獨立核對

（待補）
