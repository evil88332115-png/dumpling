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
| 6 | OMV 原始碼的相依解析 | sca-scan `--git` 沒開 `--allow-network-resolve`，cdxgen 只讀鎖定檔；沒有鎖定檔的生態系元件會缺 | 原樣 | 確認 OMV 各子專案有哪些鎖定檔；必要時開網路解析（要評估沙箱） |
| 7 | AI NAS 原始碼元件的層 | OMV 原始碼掃到的第三方相依（composer／npm／pypi）沒有路徑，分層是 unknown（當我們的待辦） | os_responsibility 是 ours，所以都算待辦（結論相同） | 依 `dumpling:origin=source` 歸 bsp（自有應用的相依） |
| 8 | TrueNAS App 層 | D-026：TrueNAS 只做研究；App 目錄的容器映像範圍暫緩 | 未實作 | 使用者決定範圍後再評估 |
| 9 | Radxa 的 manifest 與 SBOM 交叉核對 | 官方 manifest（role: metadata）只用來核對套件數，沒有自動比對 | 標準答案核對時人工比對 | collect 加「官方清單 vs SBOM」的差異表 |
| 10 | metadata 檔的 sha256 不符 | 官方附的清單檔可能被重新產生（Debian 的 `debian-13-generic-amd64-20261111-2659.json` 在 2026-11-12 15:10 GMT 重新產生）；現在 fetch 會 FAIL，整個 run 停下，但這個檔不進掃描 | D-037：人工核對（官方 SHA512SUMS 相符、套件清單與映像的 dpkg status 一致）後更新 sha256；在 11 做好之前遇到就照同樣方式核對後問 C0 | role: metadata 的 sha256 不符時 fetch 回 GAP（不下載或不採用），不回 FAIL |
| 11 | Debian SHA512SUMS 的簽章 | 目前只用 https 下載 SHA512SUMS 比對，沒有驗 GPG 簽章 | 簽章沒有驗（記在 note） | 可行的話加驗 SHA512SUMS 的簽章（Debian cloud 映像的簽章檔與金鑰來源要先確認） |
| 12 | 語言套件與內嵌模組的擁有者 | owners.json（dpkg .list）只用在型別 file 的元件；deb 帶進來的 Python 套件（`usr/lib/python3/dist-packages`）與執行檔裡內嵌的 Go 模組（例如 `rpi-connect` 的 98 個）有路徑、擁有者是 deb，卻因為不是 file 型別而標 unknown（Raspberry Pi 2026-10-06：pypi 220、golang 98） | 列入我們的待辦（保守） | layers.classify_component 對有路徑的非 file 元件也查 owners，依擁有它的 deb 名稱分層；不能改用路徑規則（bsp 的 python3-rpi-lgpio 也在同一個資料夾） |
| 13 | 分層重跑時沒有核心的那一份 | `-os` 重跑（SBOM 裡沒有核心）仍沿用完整掃描的資料夾，核心的 C-kernel-cve-list／config／module-map 標 GAP（版本像 ABI 字串），kernel-versions.json 的 judged 仍列出核心 | 照實 GAP；標準答案只釘完整與 -bsp 那兩次的核心階段 | SBOM 裡沒有核心元件時，核心階段記 NOT_RUN（不適用），judged 不列 |
| 14 | 「完整」報告的範圍 | 完整（全部層）那份是補充元件（原始磁區的開機程式、NAS 應用原始碼）與分層之前的掃描：不含開機程式、沒有層欄位，但報告與 notes 把它跟分層報告並列 | notes 加一句說明；標準答案不釘完整報告的漏洞數 | 完整報告改用補充後的 SBOM 重跑，或在 Release 不列為一般報告 |
| 15 | 對外連線服務清單 | 只有 Raspberry Pi 定義了清單（rpi-connect）；Rockchip、AI NAS 的映像有 ssh、avahi、samba 等服務，沒有評估 | scan.json 的 external_services 記 NOT_ASSESSED（不寫成「沒有」） | 依平台定義清單，或改用板子實測（board-test）的對外埠 |
| 16 | D-038 的候選說明沒有進交付報告 | D-038 要求報告註明「廠商核心、依上游版本列出的候選，廠商可能已回移修補」；目前只在 notes.md 與 kernel-upstream JSON，交付的 CRA 報告（risk-assessment.md、kernel-vulnerabilities.md）只寫「CVE from an explicit list (KERNEL_CVES)」 | notes 與 scan.json 有寫 | cra_report 對 KERNEL_CVES 來源的核心列加「候選、廠商可能已回移修補」說明（C1，M7） |
| 17 | Radxa 發行、和硬體存取有關的套件 | dthelper（device tree overlay 工具）、libmraa2／libmraa-dev（GPIO／I2C／SPI 函式庫）原本歸 os | **已處理**：C0 決定歸 bsp（D-027 的原則），加進 rockchip 的 bsp 清單、重訂標準答案 | — |
| 18 | 分層重跑時 sca-scan 退回核心 CNA | -os 的 SBOM 沒有核心套件，Grype 對核心 0 筆，sca-scan 改用 CNA 產生 2700 列核心候選（layer bsp）進 OS 報告（Raspberry Pi） | 已回報 C0／C1；標準答案不釘 OS 報告的核心列 | SBOM 沒有核心元件時，核心階段記 NOT_RUN（不適用），不退回 CNA（缺口 13 同類） |
| 19 | 帶 epoch 的廠商核心被 Grype 當成已修補 | Raspberry Pi 的核心套件 1:6.18.50-1+rpt1 比 Debian 6.12.x 的修補版本「新」，只對到 Debian 還沒修的 332 個 CVE；上游 6.18.50 的 CNA 候選是 2700 個，約 2400 個沒有列出（漏報） | 已回報 C0／C1；標準答案不釘 bsp 的核心比對 | 像 D-038 一樣改用上游版本對核心 CNA（kernel_upstream_version 6.18.50），sca-scan 要在 Grype 有核心比對時也能用 CNA |

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
