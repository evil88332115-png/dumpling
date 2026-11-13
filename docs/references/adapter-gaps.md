# WP7 轉接器的已知缺口（不擋 M6；M2 合併後由 C0 排進之後的里程碑）

C4 寫轉接器時發現、但沒有擋住 M6 的缺口。擋住的已經直接回報 C0（並在 M2 處理）：見本檔最後「已在 M2 處理」。
每一項寫：現象、影響（報告上會看到什麼）、目前的處理、建議。

| # | 項目 | 現象與影響 | 目前的處理 | 建議 |
|---|---|---|---|---|
| 1 | 多顆核心逐顆判定 | 映像有多顆核心（Raspberry Pi OS：Pi 5 的 `rpi-2712` 與 Pi 4 的 `rpi-v8`）；D-036：指定 1 顆時只判定那顆，其他列「已出貨、未判定」並標 GAP；指定超過 1 顆整個 GAP | rpi-lite-demo 只指定 Pi 5（`6.18.50+rpt-rpi-2712`），v8 列「已出貨、未判定」 | 逐顆判定再合併（D-036 排在 M7） |
| 2 | 精靈裡 Jetson 專用的步驟 | 精靈的「3b. A0 與 NVIDIA 原版的逐檔比對」在其他平台也跑，結果是 GAP（沒有上游基準檔），訊息提到 NVIDIA | 照實標 GAP（沒有誤判成通過） | 平台設定沒有上游基準時改標 NOT_ASSESSED 並說明「此平台沒有上游基準比對」，或不跑這一步 |
| 3 | 開機鏈分類 | Rockchip（`--not-assessed rockchip`）與 x86 NAS（`generic`）的 bootloader_coverage 是 NOT_ASSESSED；Rockchip 的開機程式身分由 raw-sectors 另外提供 | raw-sectors 的元件（D-034 的 U-Boot CPE、閉源 DDR／BL31 標 GAP）併進 SBOM | bootloader_coverage.py 加 `--platform rockchip` 的分類，讀 raw-sectors.json |
| 4 | rkbin 版本 | DDR 初始化 v1.22、BL31 v1.54 只能從磁區字串讀到版本，rkbin 的來源 commit 不明 | GAP（安全公告比對也是 GAP） | 廠商提供 rkbin commit 或 SBOM 時改用它 |
| 5 | OMV 原始碼與正式 deb | 掃的是固定 commit 的原始碼，沒有比對與正式 deb 是否完全相同 | `dumpling:source-vs-package` = NOT_ASSESSED（D-025） | 示範映像改用裝好 OMV 的映像，或比對 deb 的檔案清單 |
| 6 | OMV 原始碼的相依解析 | sca-scan `--git` 沒開 `--allow-network-resolve`，cdxgen 只讀鎖定檔；沒有鎖定檔的生態系元件會缺（pypi 沒有鎖定檔：C-lockfiles GAP；cached-property、click、lxml、natsort、pyudev 5 個沒有版本，C-pyver GAP） | 原樣 | 確認 OMV 各子專案有哪些鎖定檔；必要時開網路解析（要評估沙箱） |
| 7 | AI NAS 原始碼元件的層 | OMV 原始碼掃到的第三方相依（composer／npm／pypi）沒有路徑，分層是 unknown（當我們的待辦）；2026-11-13（dev run 43386797521）：1691 個（no-path 1630、path-no-rule 61），layers.classify_component 沒有看 `dumpling:origin` 的規則 | os_responsibility 是 ours，所以都算待辦（結論相同，只差層的標籤） | 依 `dumpling:origin=source` 歸 bsp（自有應用的相依） |
| 8 | TrueNAS App 層 | D-026：TrueNAS 只做研究；App 目錄的容器映像範圍暫緩 | 未實作 | 使用者決定範圍後再評估 |
| 9 | Radxa 的 manifest 與 SBOM 交叉核對 | 官方 manifest（role: metadata）只用來核對套件數，沒有自動比對 | 標準答案核對時人工比對 | collect 加「官方清單 vs SBOM」的差異表 |
| 10 | metadata 檔的 sha256 不符 | 官方附的清單檔可能被重新產生（Debian 的 `debian-13-generic-amd64-20261111-2659.json` 在 2026-11-12 15:10 GMT 重新產生）；現在 fetch 會 FAIL，整個 run 停下，但這個檔不進掃描 | D-037：人工核對（官方 SHA512SUMS 相符、套件清單與映像的 dpkg status 一致）後更新 sha256；在 11 做好之前遇到就照同樣方式核對後問 C0 | role: metadata 的 sha256 不符時 fetch 回 GAP（不下載或不採用），不回 FAIL |
| 11 | Debian SHA512SUMS 的簽章 | 目前只用 https 下載 SHA512SUMS 比對，沒有驗 GPG 簽章 | 簽章沒有驗（記在 note） | 可行的話加驗 SHA512SUMS 的簽章（Debian cloud 映像的簽章檔與金鑰來源要先確認） |
| 12 | 語言套件與內嵌模組的擁有者 | owners.json（dpkg .list）只用在型別 file 的元件；deb 帶進來的 Python 套件（`usr/lib/python3/dist-packages`）與執行檔裡內嵌的 Go 模組（例如 `rpi-connect` 的 98 個）有路徑、擁有者是 deb，卻因為不是 file 型別而標 unknown（Raspberry Pi 2026-10-06：pypi 220、golang 98） | 列入我們的待辦（保守） | layers.classify_component 對有路徑的非 file 元件也查 owners，依擁有它的 deb 名稱分層；不能改用路徑規則（bsp 的 python3-rpi-lgpio 也在同一個資料夾） |
| 13 | 分層重跑時沒有核心的那一份 | `-os` 重跑（SBOM 裡沒有核心）仍沿用完整掃描的資料夾，核心的 C-kernel-cve-list／config／module-map 標 GAP（版本像 ABI 字串），kernel-versions.json 的 judged 仍列出核心 | **已處理**：C1 的 D-044（--kernel-in-other-report）；scan-disk 對 -os 重跑傳 `<專案>-bsp`，三個核心階段 NOT_RUN（不適用）。rock、rpi 的標準答案已釘 | — |
| 14 | 「完整」報告的範圍 | 完整（全部層）那份是補充元件（原始磁區的開機程式、NAS 應用原始碼）與分層之前的掃描：不含開機程式、沒有層欄位，但報告與 notes 把它跟分層報告並列。os_responsibility 是 ours 時（AI NAS）不同：只有一份報告，是補充與分層之後用產品 SBOM 重跑的（platform_scan.collect 同一個後綴取後面那次），notes 從 894debd 起依 os_responsibility 分開寫（dev run 43386797521 的 notes.md 還是舊的寫法） | notes 加一句說明；標準答案不釘完整報告的漏洞數 | 完整報告改用補充後的 SBOM 重跑，或在 Release 不列為一般報告 |
| 15 | 對外連線服務清單 | 只有 Raspberry Pi 定義了清單（rpi-connect）；Rockchip、AI NAS 的映像有 ssh、avahi、samba 等服務，沒有評估 | scan.json 的 external_services 記 NOT_ASSESSED（不寫成「沒有」） | 依平台定義清單，或改用板子實測（board-test）的對外埠 |
| 16 | D-038 的候選說明沒有進交付報告 | D-038 要求報告註明「廠商核心、依上游版本列出的候選，廠商可能已回移修補」；目前只在 notes.md 與 kernel-upstream JSON，交付的 CRA 報告（risk-assessment.md、kernel-vulnerabilities.md）只寫「CVE from an explicit list (KERNEL_CVES)」 | notes 與 scan.json 有寫 | cra_report 對 KERNEL_CVES 來源的核心列加「候選、廠商可能已回移修補」說明（C1，M7） |
| 17 | Radxa 發行、和硬體存取有關的套件 | dthelper（device tree overlay 工具）、libmraa2／libmraa-dev（GPIO／I2C／SPI 函式庫）原本歸 os | **已處理**：C0 決定歸 bsp（D-027 的原則），加進 rockchip 的 bsp 清單、重訂標準答案 | — |
| 18 | 分層重跑時 sca-scan 退回核心 CNA | -os 的 SBOM 沒有核心套件，Grype 對核心 0 筆，sca-scan 改用 CNA 產生 2700 列核心候選（layer bsp）進 OS 報告（Raspberry Pi） | **已處理**：同 13（D-044）；dev run 43396859926 的 rpi OS 報告核心列 0 | — |
| 19 | 帶 epoch 的廠商核心被 Grype 當成已修補 | Raspberry Pi 的核心套件 1:6.18.50-1+rpt1 比 Debian 6.12.x 的修補版本「新」，只對到 Debian 還沒修的 332 個 CVE；上游 6.18.50 的 CNA 候選是 2700 個，約 2400 個沒有列出（漏報） | C4 的部分已修（b907181：D-038 核對讀得出 6.18.50+rpt-rpi-2712，dev run 43410313151 產生 2700 個 CNA 候選、C-kernel-config 也用了）；D-044 讓 C-kernel-coverage 照實 GAP。**還沒解決的在報告端**：Grype 對核心 deb 有比對到時，交付報告（vulnerability-rows、kernel-vulnerabilities.md）的核心列只有 Grype 的 332 個 CVE（×4 個核心套件＝1328 列），KERNEL_CVES 的候選沒有成列；標準答案不釘 bsp 的核心列數 | sca-scan／cra_report：有 KERNEL_CVES 時，清單裡 Grype 沒有的 CVE 也成列（候選、待人審）；同一個 CVE 不要在 4 個核心套件各列一次 |
| 20 | x86 磁碟映像的分割區步驟名稱與訊息 | 精靈對原始磁碟映像的分割區清點步驟叫 `B-rockchip`，x86 的 Debian 映像（AI NAS）也是這個名稱，訊息還寫「Raspberry Pi 4/5 的 EEPROM 開機程式不在映像裡」；BIOS boot 分割區（p2，3 MiB）只清點 sha256 | ATTENTION 照實；不影響漏洞比對 | 步驟改用中性的名稱（例如 B-disk-partitions），EEPROM 那句只在 raspberrypi 平台出現 |
| 21 | 示範專案的 CRA 設定是範本的虛構值 | new-project.sh 從 tools/cra/config.example.json 複製 CRA/Config/config.json，只換公司與產品名稱；其餘（例如 own_software 的 /usr/bin/example-agent、/opt/example/bin/*、example_*.ko）是範本的虛構值，四個示範專案（含 orin-nano-demo）都是。AI NAS 的 B-own-software 因此是 GAP（3 個樣式都對不到） | 照實 GAP；標準答案不釘 B-own-software | new-project 產生的 config.json 對 own_software 等專案專屬欄位改用 project.yml 的值或留空並標 TO BE COMPLETED；示範專案的值由 C0 決定 |
| 22 | Debian 核心的比對依據 | AI NAS（Debian 13 自己的核心 6.12.116-1）的 428 列核心都來自 linux-kernel 元件（pkg:generic），Grype 依 NVD 的上游版本範圍比對；Debian 的核心 deb（linux-image-6.12.116+deb13-amd64）沒有任何一列，也就是沒有用到 Debian 安全追蹤的修補資訊。C-kernel-coverage 是 OK（只表示有比對） | 標準答案與 notes 照實寫成 NVD 上游比對、可能有誤報 | 確認 Grype 為什麼沒有用 Debian 資料比對核心 deb；發行版核心改用發行版資料（或兩者並列，標出來源） |
| 23 | 映像有 /boot/config 但核心 .config 判定沒有用 | Debian 雲端映像沒有 linux-headers，但有 /boot/config-6.12.116+deb13-amd64；sca-scan 的 C-kernel-config／C-kernel-module-map 只找 /usr/lib/modules/<版本>/build 與 /usr/src/linux-headers-*，所以 GAP（428 個核心 CVE 沒有依 .config 判定）。D-038 的廠商核心是 C4 的 kernel_upstream.py 讀 /boot/config | 照實 GAP；標準答案註明工具改善後要更新 | sca-scan 找不到 headers 時改讀 /boot/config-<版本>（出貨的 config，依據 shipped-config） |
| 24 | ours 時 scan.json 的 p1_rows 少算 OS | scan.json 的 p1_rows（platform_scan.vuln_metrics）只算 bsp／unknown 層：AI NAS 是 ours，4 個 P1（3 個核心、1 個 openssh）都在 os 層，p1_rows 是 0。**P1 判斷表本身是對的**（dev run 43386797521：附件 p1-table-*.xlsx 與報告包裡的 P1判斷表.xlsx 都是 0744 重跑那份，標題「BSP、層未定（unknown）、OS」，Q1～Q4 四列）；驗證代理說「只有表頭」是看錯，C4 沒有先核對就轉報 | 標準答案先不釘 p1_rows | C1 已修 p1_rows（23ff7a5，M2）；修好後 ai-nas 釘 4 |

## 已在 M2 處理（C4 回報、C1 實作）

- 原始磁碟映像一律套 Raspberry Pi 分類（改成平台由 project.yml 明確給定，沒給 GAP）
- 不編譯的平台 build job 與 handoff（build.mode: none、handoff/）
- scan-flash-package 的 `--platform generic` 與 `--arch`
- `platform_scan.py`（共用 collect）
- sources.yml 的 `role: metadata`
- rpi_img.py 依內容選 boot 分割區（Radxa 的 config FAT 不再被當成 boot）
- cra-scan 沒給 `--source` 時不去目前資料夾找（標 GAP）
- assemble／各步驟的 GAP 由 `pipeline/run-step.sh` 接手（警告後繼續）
- 多顆核心的 `--kernel-version`／`SCA_KERNEL_VERSIONS` 與 `kernel-versions.json`（D-036）
