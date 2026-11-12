# STATUS

每個對話一節，**每做完一步就更新並推送**（`ci/status-update.sh`，見 main 的 `docs/HANDOFF.md`）。只改自己那節，`<!-- BEGIN/END -->` 標記不要動。

最後更新：2026-11-12 10:47 -0500（C1）

<!-- BEGIN C0 -->
## C0 協調（WP0）

- 目前在做：看 PR、合併、驗收，回覆 C1–C4
- 分支／PR／commit：main d342a87；本機累積分支 `wp0/docs-batch-2`（0cb0089：D-023 合成測試資料可收、D-024 第二台電腦、公開檢查擋 Windows 使用者路徑），還沒推，等 M1 合併時一起開 PR
- 代理：
  - 預審代理（Sonnet 5.5）：預審 wp1/m1-tools f9d0cee，狀態：完成（#9 留言：有必須修的項目——測試檔語法錯誤、scripts→tools 路徑沒改完、一處版本被改、5 處疑似內部實測資訊、缺少被引用的檔），已轉給 C1
- 代理總數（全部對話）：C1 寫程式 2＋驗證 1、C2 寫程式 2＋驗證 1，約 6／上限 8；C0 目前沒有代理在跑
- CI：無進行中
- 下一步：等 C1 修完 pilot／demo 的 37 個失敗 → M1 正式 PR（d1fd77b 起；cra 1734 passed；含 public-check 掃壓縮檔的擴充）→ C0 派獨立驗證代理 → 合併；C2 做到 M3
- 設定：main 分支保護不再要求分支最新（D-021，使用者同意）；auto-merge 因帳號沒有驗證過的信箱而無法使用，改由 C0 背景等 CI 後合併
- C4（另一台電腦 WSL2，asus wsl）：環境已設好（clone、noreply 身分、pre-push hook、local.env）；第一階段在本機做：三個平台的公開示範資料清單＋平台設定研究（分支 wp7/platform-samples），轉接器等 M2
- 給 C3 的交接：M1 沒帶 `alert_mail.py`（每日監控寄信），exploited_* 測試約 29 個寄信相關的已刪；watch.yml 要寄信時由 C3 帶回
- 卡住／等決定：使用者要在 WSL 那台親手建立 forbidden.txt（C4 在那之前不推送）
<!-- END C0 -->

<!-- BEGIN C1 -->
## C1 流程核心（WP1＋WP6）

- 目前在做：M1 完成、等 C0 合併（PR #9 已轉正式）；M2 試驗（`wp1/m2-spike`）進行中
- 分支／PR／commit：
  - `wp1/m1-tools`：bd95a8c（fb1ac02 之後只有 PROVENANCE 文件修正；V2 修正已併入：public-check f7830fc、F 的 8ae599b、C1 的 fb1ac02；tools/ 全部、PROVENANCE C1 節、白名單、public-check 掃壓縮檔、provenance-check、c1-tools／c1-pipeline／c1-public-check、tests.yml 裝 bubblewrap、臨時 DT＋dt-smoke 用 `sca-scan --sbom`）；PR #9（**正式 PR，等 C0 合併**；說明附逐檔對照 196 檔（實際比對：相同 56、有修改或自寫 140）、資料來源表、給 C0 的決定事項）
  - `wp1/m1-tools-pilot`（b210000）已 fast-forward 併入 m1-tools；`wp1/m1-dt` 已併入；PR #6 已關
  - 來源：sca-center 25fa89a
- 代理：
  - 寫程式 A（cra／vexconv／sbomgate）：完成
  - 寫程式 P（pilot／demo／mirror／wizard／e2e、dt-smoke 整合、DT 加固）：完成；pilot 分支 tests run 43237031501（c1-tools 2918 passed／0 failed／NOT_RUN 0）、dt-smoke run 43237039925 綠燈；wait=0 失敗會變紅的證明 run 43231324313
  - 寫程式 B（臨時 DT）：完成
  - 驗證 V1（m1-dt）：不通過（pipefail）→ P 已修，併入 V2 重驗
  - 寫程式 S（M2 試驗，使用者同意、C0 轉達）：分支 `wp1/m2-spike`（從 2555a66 開，**不合併、不開 PR**），`.github/workflows/m2-spike.yml`（只有 workflow_dispatch）量測 arm runner 磁碟清理、L4T BSP／原始碼下載＋sha256＋actions/cache、原生編譯核心＋樹外模組；結果放分支的 `docs/m2-spike-results.md`，C1 摘要寫進下面的 M2 設計備忘；Sonnet 5.5／high；進行中
  - 驗證 V2（M1 全部，2555a66）：完成，**不通過**（PR #9 issuecomment-6827049283）；必須修 3 項：(1) public-check 壓縮檔檢查被非 ASCII 檔名繞過 → C1 已修（f7830fc：-z、不分大小寫、.tgz／.tar、.zip 等算命中、白名單完整字串比對）；(2) PROVENANCE 引用改寫前的內部原值；(3) PROVENANCE 多處與實際不符 → 交給 F；CI（tests、dt-smoke，workflow_dispatch＋pull_request）全綠
  - 寫程式 F（`wp1/m1-fix` 8ae599b，已 fast-forward 併入、worktree 已移除）：完成——PROVENANCE 不引用原值且與實際一致、還原 2 處多刪的斷言、scan-status-check 加 B-sandbox／C-upload-sbom／D-dt-vuln-analysis、dt-ephemeral 數值參數驗證、約 42 個檔的註解移除上游私有 repo 編號與內部部署描述；tests run 43246075631、dt-smoke run 43246083315 綠燈
  - 驗證 V3（M1 全部，fb1ac02）：**通過**（PR #9 issuecomment-6828295257），沒有必須修
- CI：fb1ac02：tests run 43249261477、dt-smoke run 43249270588 綠燈（各含 pull_request 一次）
- 下一步：C0 合併 #9 → 通知 C2（臨時 DT 可用）→ 清 C1 的舊 worktree（m1-dt、m1-tools-pilot）→ 開 M2（先讀 C4 的 platforms-research.md 與 m2-spike 結果）
- M2 設計備忘（C0 轉達，C4 的平台研究；試驗結果待 S 回報後補）：
  - `sources.yml` 的 fetch 重用 C2 的 `pipeline/lib/firmware_fetch.py`（curl_download／check_file／fetch_one 通用，validate() 寫死韌體欄位）：M2 新增共用模組、firmware_fetch.py 改呼叫它；`sources.yml` 的 files[] 沿用 firmware.yml 格式（C4 的 samples.yml 已照此格式）。**動 C2 的檔前先通知 C0**
  - 公開 Rockchip 映像是 GPT 原始磁碟（不是 update.img），開機程式在第一個分割區之前：平台介面的 assemble／scan 要留掛點，讓平台自己清點「分割區外的原始磁區」
  - C4 平台研究：`wp7/platform-samples` 754f7f3 的 `docs/platforms-research.md`（M2 開工前讀）
  - `project.yml` 要有欄位表示「OS 層也是我們的待辦」（自有品牌 AI NAS；D-025：由角色決定，不寫死在平台設定）
  - 角色值要能表示「上游 OS 廠商負責、我們只通知客戶」，例如 `os_responsibility: upstream-vendor`（只轉售 TrueNAS；與 Jetson OS 層「通知客戶」同一概念）
  - bsp／os 分層：平台設定裡的「套件名稱清單」決定，不看版本字尾（同 nvidia-l4t-* 做法）
  - Rockchip 分割區外的開機程式：以原始磁區為準
- 卡住／等決定：
  - 等使用者（C0 轉問）：PR 內歷史 WIP commit 含內部 CI 執行編號等（禁用字 0 命中）——選項只有接受或刪 repo 重建
  - 請 C0 決定：public-check 對非壓縮的二進位檔（.pdf .png .bin）不掃、巢狀封存只解一層，是否改成反向規則（ci/ 是 WP0）
  - （已定）假交付物命名符合 D-023；`prefilled_from.by` 保留
  - 已處理：alert_mail.py 沒帶（PROVENANCE 標「C3 視需要帶回」）；D-023（形狀參考內部觀察的合成測資可收）已套用；上限註解的「實測」精確數量改成估計
  - M1 合併前本機 pre-push hook 不掃壓縮檔：改了 *.xz 等要手動跑 worktree 裡的新版 public-check
<!-- END C1 -->

<!-- BEGIN C2 -->
## C2 韌體（WP3＋WP4）

- 目前在做：M3（BIOS、vBIOS 各至少一個樣本產出 SBOM 並進 DT）。D-020：做到 M3 才開**一個** PR；過程只推分支，CI 用 `gh workflow run` 手動觸發
- 已合併：PR #7（樣本清單＋下載核對）、PR #8（x86_firmware → CycloneDX）
- **整合分支 `wp3/m3` 7b67b1b**（worktree `$AGENT_TMP/dumpling-wt-c2-m3`），已含：
  - coreboot CBFS（FMAP、LZMA／LZ4、coreboot 版本／config、FSP、VBT、SELF payload）＋預驗修正 0f28182（ReDoS、掃描雜湊放大、解壓失敗計量、FSP ExtendedImageRevision）
  - AMI PFAT 解封裝＋預驗修正（清單數字欄位崩潰、MAX_TOTAL 跨巢狀、檔名截短）；fetch 測試補強、run.d venv 快取、firmware.yml pipefail 修正（綠 run 43229479139／故意 sha256 不符紅 run 43229520867）
  - 真實樣本 CI 驗收 `pipeline/firmware-expect.py`（綠 run 43231626732：Dasharo 11 項 OK、NUC 1 項 OK；改錯 ME 版本紅 run 43231826497）
  - vBIOS：NVIDIA DP 更新工具**沒有完整 vBIOS**（只有 3 組 GPU 家族 GOP 範本，佔位版本字串）；合成獨立 vBIOS（`tools/cra/tests/synthetic_vbios.py`）端到端產 SBOM；Intel legacy VBIOS 辨識（NUC 樣本 `Build Number: 1003 PC 14.34`）；`intel_vbt.py` 共用；`gop_driver()`（GOP 版本只讀得到 build 1070）待接 FV 走訪
  - 本機 c2 測試 279 passed、0 skip；Dasharo 16 個元件不變。CI：8688cd4 的 tests 43232541990／firmware 43232547319 綠；4183a96 的 tests 43233831760、firmware 43233837796 已觸發
  - 供應商 SBOM 品質檢查（a2ed40f，已併入）：3mdeb Dasharo SBOM 範例 → ATTENTION（10 元件、1 缺版本、5 缺 cpe、sbomqs v2.1.3 分數 4.3 僅供參考）；sbomqs 版本與 sha256 固定在 `pipeline/lib/tools.lock`。CI：firmware 43234922758、tests 43234916860 綠
  - 韌體 SBOM → DT 的準備（4781bc5，已併入）：`pipeline/lib/firmware_dt.py` prep／expected／report。專案名稱 `firmware-<kind>[-synthetic]-<slug>`、SBOM 正規化（metadata.component、bom-ref／dependencies 檢查）、expected 兩種（C1 dt-verify 格式＋介面無關的）；report 漏洞欄以 Grype（sca-scan C-grype）為主、DT 只收件留存。暫存試接 C1 pilot 分支：sca-scan A／B／C 階段 OK、C-sbomgate NOT_ASSESSED（firmware 不算套件，預期）、dt-verify 吃得懂 expected。workflow job 只有草稿（`docs/notes/c2-firmware-dt.md`），等 M1
- M3 剩下要做的（等 C1 M1，C1 估 1～2 小時轉正式 PR）：
  - BIOS 成品端 UEFI FV 解開：用 `tools/cra/uefi_image.py`（D-016）→ 接 Intel GOP（`gop_driver()`）／AMI 映像裡的 VBT／legacy VBIOS
  - NVIDIA gpu-firmware 公告比對：用 C1 的 `tools/pilot/lib/nvidia_bulletins.py`，沒對到標 NOT_ASSESSED
  - 上傳臨時 DT＋Grype（BIOS SBOM、vBIOS SBOM、供應商 SBOM）
- 代理：
  - 代理 G（寫程式，Sonnet 5.5 medium）：`wp3/supplier-sbom`，狀態：完成
  - 代理 H（寫程式，Sonnet 5.5 medium）：`wp3/firmware-dt`，狀態：完成
  - 預驗 `wp3/m3` 4183a96（完成，不通過）：cbfs／pfat 的修正複驗都過；必修 1：我上一輪加的 FSP ExtendedImageRevision 讀錯偏移（+0x44 是 SiliconInit 入口，應為 +0x4C、header ≥ 0x50），Dasharo FSP-S 多出假 note；中等 1：Intel VBIOS 橫幅 regex 128 倍放大。**已在 7e40fe7 修好**（依 coreboot info_header.h 逐欄核對；橫幅改線性搜尋；PROVENANCE 措辭）
  - 預驗 `wp3/m3` 7e40fe7（完成，**通過**）：FSP 偏移（依 info_header.h 逐欄核對、Dasharo 與 4183a96 diff 只少了假 property）、find_banner（20 萬組隨機對照舊 regex 0 不一致、16 MiB 構造 <0.07 秒）、供應商 SBOM（sbomqs sha256 與 release 一致、sha 改錯不解開、不連外）。建議 B1～B8（Markdown 注入、巢狀過深靜默截斷、佔位值、記憶體放大等）交代理 I
  - 代理 I（寫程式，Sonnet 5.5 high）：`wp3/sbom-check-hardening` 7b67b1b，狀態：完成（已快轉併入 m3）。Markdown 注入共用 `md_safe`、巢狀過深 ATTENTION、佔位值當缺、上限 16 MiB＋物件數估計、O_NOFOLLOW、sbomqs 版本對 tools.lock、無樣本 NOT_RUN、用法錯誤 64。CI tests 43239787867（c2-firmware 143、c2-x86-firmware 283，0 skip）、firmware 43239795302 綠
  - 已完成：代理 A～F；預驗 cbfs（不通過→已修）、預驗 pfat（不通過→已修）
- 下一步：等預驗 7e40fe7＋供應商 SBOM 的結果；C1 M1 合併後：merge main → 接 firmware.yml 的 firmware-dt job（照草稿）＋uefi_image.py 接 GOP／AMI VBT／legacy VBIOS＋NVIDIA 公告比對 → CI 跑通 → M3 開 PR（附各輪預驗結論）→ 驗證 → 通知 C0
- 卡住／等決定：UEFI 解開、GOP、公告比對、DT 上傳等 C1 M1。代理暫存資料夾 `$AGENT_TMP/dumpling-tmp-c2-cbfs`、`-pfat`、`-verify-cbfs`、`-verify-m3b`、`-supsbom`、`-sbomfix`（約 22 MB）等被安全檢查擋下沒刪，要使用者手動刪
<!-- END C2 -->

<!-- BEGIN C3 -->
## C3 監控＋GitLab（WP2＋WP5）

- 目前在做：尚未開始（開始條件：C1 的 M2）
- 分支／PR／commit：—
- 代理：無
- CI：無
- 下一步：等 M2
- 卡住／等決定：無
<!-- END C3 -->

<!-- BEGIN C4 -->
## C4 其他平台（WP7）

- 目前在做：WP7 第一階段（不依賴 M2）完成：公開示範資料清單與平台研究（含 D-025、D-026、D-027）；等 M2 期間的 CRA 開源專案與文件調查已完成（使用者經 C0 指派）
- 分支／PR／commit：`wp7/platform-samples`（最後 commit 1489d48）、`wp7/cra-survey`（最後 commit 1bc801a）；PR 都尚未開（D-020）
- 代理：研究代理 1 個（Sonnet 5.5，effort medium，只讀；任務：CRA 開源專案與文件調查 → `docs/references/cra-github-survey.md`；分支 `wp7/cra-survey`；狀態：完成，C4 已檢查並推送）
- CI：無；本機背景工作：無（下載的樣本與解開的檔案都已刪除）
- 已完成：`docs/platforms-research.md`；`platform-samples/` 四份清單：Raspberry Pi OS Lite 2026-10-06、Radxa ROCK 5B rsdk-r6、Debian 13 generic amd64 20261111-2659＋OMV 8.6.1-1 原始碼、TrueNAS 25.10.8（只做研究）。所有檔案實際下載核對，跟官方公布的雜湊相符；TrueNAS .update 簽章已驗證
- 下一步：等 C1 的 M2（平台介面與開案範本）後寫 Raspberry Pi、Rockchip、AI NAS 轉接器與示範專案；samples.yml 搬到 projects/<專案>/sources.yml
- 卡住／等決定：無（D-027 已寫進研究文件；TrueNAS App 層範圍暫緩）。等 C1 的 M2；M1 合併後先 merge main 熟悉 tools/
<!-- END C4 -->
