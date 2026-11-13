# STATUS

每個對話一節，**每做完一步就更新並推送**（`ci/status-update.sh`，見 main 的 `docs/HANDOFF.md`）。只改自己那節，`<!-- BEGIN/END -->` 標記不要動。

最後更新：2026-11-13 23:12 +0800（C1）

<!-- BEGIN C0 -->
## C0 協調（WP0）

- 目前在做：**M2 已合併（#40，cc7d101）**；正式 tag 等使用者（C1 推 tag 被權限擋，C0 不代推）；文件批次 PR #41 已開、驗證代理在跑
- 分支／PR／commit：main cc7d101。已合併：**M2 #40**（2026-11-13，兩份驗證通過、CI 綠）、M1（#9）、M3（#14）、M4（#28）＋修正 #32、**D-042 AMD／新世代 CSME #39**（2026-11-13，驗證報告貼在 PR）；文件批次 #13、#15。C0 分支 `wp0/docs-batch-4`（**PR #41 已開**，已併 main；worktree `$AGENT_TMP/dumpling-wt-c0-docs`）：D-034～D-052＋HANDOFF「在第二台電腦（WSL2）接手」一節（#41 合併前新對話請從這個分支讀 DECISIONS／HANDOFF）
- 代理：1 個驗證代理（Sonnet 5.5）：驗文件批次 PR #41，報告 `$AGENT_TMP/dumpling-tmp-c0-verify-docs/report.md`。M2 的獨立驗證已完成（通過，應修 0、建議 8，已貼 #40）
- CI：C0 無。C1 的兩個 Jetson release run 與 C3／C4 的 dev run 由各自的 STATUS 記錄
- 各對話現況（細節看各節）：
  - C1（第二台）：M2 #40 已合併。**推正式 tag 被 C1 的權限擋下，等使用者**（自己推，或放行 C1；C0 不代推）。tag 後 C1 用本機草稿附件核對正式 Release 再刪 wp1/m2-pr-draft。wp1/m2-followup（[WP1] 小 PR：C1 建議 1、2、5＋C0 驗證建議 1 pipeline_result 區分「不適用／未執行」）進行中
  - C2（第二台）：wp3/cse-layout-size dc7589a（CSE layout Size 0x60，公開樣本 Dasharo NovaCustom NUC BOX ARL v0.9.2，ME 18.1.18.2724）預驗中，C0 用私有檔本機複核中。wp3/fw-advisory 複驗不通過 3 項、修正中；D-051 補上限 30（a3cf183）。supplier-normalize 等 M2
  - C3（第二台）：wp2/watch-m2 等 M2 後接 mirrors.sh 開 PR；wp2/art14（e66f499）等 M7 的銷售市場欄位，M8 再開；wp5/gitlab（M5）等 M2 後核對範本指令再開
  - C4（第二台）：三平台差異核對完成、標準答案定案（403fae7；rpi 90、rock 99、ai-nas 76 項，最後一輪 run rpi 43419144284、rock 43413770363、ai-nas 43416974360，併入 61d7c6f）；驗證代理只拿原始資料。#27 已由 C0 決定（D-049：lgpio 維持 os）。下一步：M2 合併後併 main 重跑，核對 rock／rpi 的 -os 項目（852b6d3 影響），再開 M6 PR
- 下一步（新 C0 接手後）：
  1. 等 C1 開 M2 PR → **C0 另派獨立驗證代理**（不附 C1 的結論）→ 兩份驗證都通過、CI 綠 → `gh pr merge --squash --match-head-commit <SHA> --author-email 287638252+evil88332115-png@users.noreply.github.com`
  2. M2 合併後：問使用者何時打第一個正式 tag（例如 `orin-nano-demo/v39.2.1-demo1`）；開 `wp0/docs-batch-4` 的 PR；通知 C2／C3／C4 併 main 後各自開 PR
  3. （完成）D-042 PR #39 已合併；私有檔驗證由 C0 用使用者提供的 3 份樣本完成（暫存在 C0 的 scratchpad，待使用者決定刪除）
  4. 監控 real Issue：C3 修完 F1–F3（已在 wp2/watch-m2）→ M2 合併 → 手動 baseline → 排程 dry_run 一天 → C3 回報會開哪些 Issue → C0 才設 repo 變數 `WATCH_REAL_ISSUES=on`
  5. 排 M7：A1–A4、C1（D-033）＋D-035 依據類型＋D-036 逐顆核心＋D-038 交付報告說明（adapter-gaps #16）＋D-039 可利用性分層＋D-044 非發行版核心改用 CNA 合併＋new-project 不帶範本值（config、vex-rules）＋adapter-gaps #7、#19（rpi 報告端：有 KERNEL_CVES 時補 Grype 沒有的 CVE 成列、同一個 CVE 不按核心套件重複列；屬 D-044 (2)，M7 交給 C1；修好後 C4 再釘 rpi 的「bsp 核心候選 ≥ CNA 清單」）、#20、#22、#23、C0 的 M2 驗證建議 2–8（-os 8.7 節、LAYERS 列數說明、check-expected 下限測試、patch CVE 仍 P3 說明、步驟表缺 pipeline-scan、SBOM 上游信箱、test_layers_report sys.path）、C1 的 M2 驗證建議 3（-os sbom.md 開機韌體一節矛盾）、4（略過清單進風險評估 Layers 節）、6（Release 附件 SBOM 與報告包 SBOM 差別說明＋標準答案「-os 只有 os」）、#25（missing_fields 少算 flash_package_supplier、sbom.md 非 Jetson 平台出現 L4T 文字）、#26（notes.md 的 pipeline_result 改成跟 release-meta.json 一致）
  6. M7 之後：D-046 新版本加入逐步自動化（先 Jetson／C1，再 C4 其他平台、C2 BIOS、C3 監控偵測；附手動步驟手冊）
- 給 PM／法務的待決定：VEX 發行閘門要不要分層（D-030）；附件 III／IV 分類、CVD 政策內容、單一聯絡窗口（D-032）；第 14 條期間計算（1182/71，C3 的 ART14.md）
- 卡住／等決定：無
- 代理上限（D-048，C0 依第二台實測調整：16 執行緒、23 GB、負載 0.2）：每個對話 3 個（2 寫程式＋1 驗證），整台 10 個；負載 >12 或可用記憶體 <4 GB 不開新的。已用訊息通知 C1–C4
- 第二台接手檢查（已完成 2026-11-13）：local.env 五個變數、forbidden.txt（含主機名與 Windows 路徑）、`$REPO_MAIN` 在 main 已 pull 到 26a6377、pre-push hook、user.email 是 noreply、`$SCA_CENTER` 有 25fa89a、gh 同一帳號都 OK。tmux 未使用（五個對話是各自的 Claude Code 視窗，名稱 c0–c4，跨對話訊息可達）
- 主要主機舊環境：使用者同意刪除（2026-11-13）。新 C1、C2 確認可以刪（分支 SHA 已在 origin 核對：wp1/m2 877ffbc、m2-pr-draft d3efdc8、amd-psp ebac3e9、csme-new 61e8ef7、supplier-normalize 8a960c0）。已通知 c1-old、c2-old 先自己檢查再移除各自的 worktree 和暫存，最後由 c0-old 檢查整個 clone 後刪 repo。**範圍只限 dumpling-* 項目**：主要主機的 `$AGENT_TMP` 和 sca-center 共用，不刪整個資料夾（c0-old 指出，HANDOFF 已補 f9e8d70）；`dumpling-heavy.lock`、`~/.config/dumpling/` 保留。c0-old 刪之前會直接向使用者確認範圍；等 c0-old 回報
<!-- END C0 -->

<!-- BEGIN C1 -->
## C1 流程核心（WP1＋WP6）

> **D-045：C1 已在第二台電腦重開（2026-11-13，WSL2）。** worktree `$AGENT_TMP/dumpling-wt-c1-m2`（wp1/m2），暫存 `$AGENT_TMP/dumpling-tmp-c1/`。代理上限照 D-048（每對話 3 個：2 寫程式＋1 驗證；整台 10 個；負載 >12 或可用記憶體 <4 GB 不開）。
> 第二台的 `python3` 是 3.14、沒有 pytest：本機測試用 uv 建的 venv `$AGENT_TMP/dumpling-tmp-c1/venv/bin/python`（3.12＋pytest、pyyaml；已建）。`tools/cra` 的 test_kernel_modules 有 3 個在本機失敗（沒有 zstd 解碼器，改動前就失敗，CI 綠燈）。完整測試交給 CI。

- 目前在做：**M2 已合併**（PR #40 → main cc7d101，C0 與 C1 第四輪驗證都通過）。**正式 tag 被 C1 session 的權限機制擋下（建立公開 Release），等使用者決定**；同時做 [WP1] 小 PR（wp1/m2-followup）
- 分支與 commit：
  - **`wp1/m2`＝1e18ed9**（已推，**已合併為 main cc7d101**，內容相同）：M2 整合分支；1e18ed9 併入 main c0a54eb（C2 #39，沒有衝突；本機 tools pytest 3607 通過）。877ffbc 改 docs/JETSON.md 10b；852b6d3 修第三輪驗證的應修（見下）；078710d：scan-flash-package.sh 的 UEFI／OP-TEE Grype 比對移到 sca-scan 之後（原本排在前面，CI 全新機器還沒有資料庫 → 完整報告 tee Grype 一定 NOT_RUN、Mbed TLS 0 列，-bsp＋-os 與完整報告列數對不上；新測試 test_bundled_grype_order.py，舊順序 NOT_RUN）；c08de27（C0 審查）：import 失敗沒走到比對時 B-uefi-grype／B-tee-grype 照樣記 NOT_RUN（D-043），tests 43429786314。只改失敗路徑，078710d 的 release draft 照樣用來驗收
  - `wp1/m2-pr-draft`＝d3efdc8（已推，**不合併**）：PR 說明草稿與 `m2table.py`；開完 PR 後刪掉
  - 其他 M2 子分支都已併入或不合併，不用再動
- 開出去的代理：
  - 第四輪獨立驗證（Sonnet、high）：**完成，通過**（應修 0、建議 6），已貼 #40 留言（報告 `$AGENT_TMP/dumpling-tmp-c1/verify4/report.md`）。建議 1（bsp_na 沒看 os_responsibility）、2（完整掃描成功路徑沒有順序測試）、5（NOT_RUN 說明）提議合併後開小 PR；3、4、6 排 M7；等 C0 決定
  - 第三輪獨立驗證（Sonnet、high）：**完成**，結論「驗證：不通過」，報告 `$AGENT_TMP/dumpling-tmp-c1/verify3/report.md`（開 PR 時貼成留言）。應修 1：-os 報告混入 bsp 的 OP-TEE Mbed TLS 11 列（另外我查到 -os 產品 SBOM 也有刷機包韌體 441 個 bsp 元件）→ 852b6d3：分層 SBOM 沒有 bsp／unknown 元件時，刷機包韌體、UEFI／OP-TEE 內建函式庫不適用（`layers.bsp_inputs_not_applicable`）；建議已處理：Release 說明成品上游比對不印 JSON、PLATFORM-INTERFACE 補 kernel_not_distro 不以 - 開頭；其餘建議（kernelcheck 上標數字 epoch 會 FAIL、完整報告 P1 沒範圍說明、步驟表沒有 pipeline-scan、標準答案沒固定 -os 核心階段）排 M7 或寫進 PR 說明
- 驗收 run（f11bfdb）：release v39.2.0-demo1 **43399785656 綠**、v39.2.1-demo1 **43399800268 綠**、tests **43399813005 綠**；877ffbc 的 tests 43412769902 綠。
- 852b6d3 的驗收 run：43416140192、43416151433、43416163311 **都綠**。draft 核對：-os 沒有 bsp 列（3780／3582 列全是 os）、-os 產品 SBOM 全是 os 元件（87518／88263；唯一含 flash 字樣的是 Ubuntu 的 libflashrom1）、`bsp_inputs_not_applicable.skipped`＝tee-source、flash-firmware；-bsp 照舊有 Mbed TLS 11 列與刷機包韌體 436／438 個元件；-os 的 Mbed TLS 只剩 Ubuntu deb（libmbedcrypto7t64 34、mbedtls 3）。**完整報告 tee Grype 兩輪都是 NOT_RUN（資料庫不可用）→ 078710d**
- **新一輪驗收 run（078710d，重新編譯）**：release v39.2.0-demo1 **43429199382**、v39.2.1-demo1 **43429215851**、tests **43429232513****都綠**（tests 43429232513 被 c08de27 的 tests 取消；c08de27 tests 43429786314 綠）。draft6 核對：標準答案兩版 24 項、pipeline_result 兩版 OK、完整報告 tee Grype OK＋Mbed TLS 11 列（10360／10167）、-os 只有 os、-bsp 有 Mbed TLS 與刷機包韌體；-bsp＋-os 比完整多 1 列（CVE-2025-66034 fonttools：完整報告把 deb 與內含的 PyPI 併成一列，分層兩邊各算，排 M7，PR 已知限制）
- draft 檢查結果（下一步 1，已完成）：
  - 兩份各 20 個附件；`check-expected.py` 兩版 24 項都符合；build_record_status、kernel_boot OK；上游被修改的檔案 v39.2.1＝1、v39.2.0＝0
  - release-meta：report_status／release_gate 都 GAP（NVD 沒開）；pipeline_result v39.2.1＝OK、**v39.2.0＝ATTENTION**：那次 git.kernel.org 連不上，kernel-cve 鏡像沿用 3 小時前的快取（設計中的退回，步驟表與 C-kernel-cve-mirror 都照實標 ATTENTION，scan 標準答案仍通過）→ 不重跑，PR 說明註明
  - -os 的 C-kernel-cve-list／config／module-map 是 NOT_RUN「不適用…核心在 orin-nano-demo-bsp 報告判定」；-bsp 的 C-kernel-coverage OK；own_software GAP；三份報告 documents.user-information 都是 GAP
  - bsp p1_rows 10（同上一輪）、accepted 2990（同上一輪）：**accepted 全部來自核心設定檢查（VEX source kconfig、code_not_present），不是 R1～R5**——R1～R5 只設 exploitable／in_triage；f11bfdb 的 commit 訊息與 JETSON.md 10b 原文說錯了，877ffbc 已更正文件。標準答案不用重訂
  - 兩版差異：bsp +11／−0 列（pip、setuptools、wheel）、os +37／−235（mysql、webkit2gtk、vim 等升版修掉）、tier 沒變
- 本機背景工作：PR #42 的驗證代理（會用 HEAVY_LOCK）
- **下一步（照順序）**：
  1. **正式 tag（D-052）**：從 cc7d101 打輕量 tag `orin-nano-demo/v39.2.0-demo1`、`orin-nano-demo/v39.2.1-demo1` 並推送——C1 的推送被權限機制擋下，等使用者自己推或放行（本機與遠端都還沒有 tag）。推了之後：release run 綠 → 用 `$AGENT_TMP/dumpling-tmp-c1/draft6/` 核對正式 Release（附件數、標準答案 24 項、各層列數）→ 回報 C0 run 編號與結果 → 刪 `wp1/m2-pr-draft`（draft Release 由 release.yml 自動刪）
  2. **[WP1] 小 PR #42**（https://github.com/evil88332115-png/dumpling/pull/42，wp1/m2-followup＝a475ec1，從 main cc7d101）：我的第四輪建議 1、2、5（c137451）＋C0 驗證建議 1（a475ec1：step_rows.overall 的 NOT_RUN 分「不適用」與沒能執行）。驗證代理（Sonnet、high）進行中 → 報告公開資料掃描後貼 #42 留言 → 有應修就修 → 通知 C0
  3. M7 待辦加上 C0 驗證建議 2–8（-os 8.7 節寫明核心在 -bsp 判定、LAYERS.md 註明各層加總≠完整、check-expected 下限檢查的測試、patch 修的 CVE 在 patched 版仍 P3 的說明、Release 說明步驟表少 pipeline-scan、SBOM 的上游維護者信箱、test_layers_report.py 單獨執行缺 sys.path）
- 驗證（這輪之前）：
  - 第一輪（7dd351c）：5／6 PASS、第 6 項附缺口；應修 3 項（間歇性測試、scan.platform_arg／rootfs 沒人讀、文件兩處）都已修，建議 6、9、10 已修，其餘寫進 `docs/JETSON.md` 第 7 節已知限制
  - 第二輪（be36327）：8／9 PASS、1 項 FAIL（小）；應修 2 項（-bsp 指向自己、沒有 scan 區塊時沒檢查 platform_arg）與建議 3–8 都在 61d7c6f 修了；draft 沒驗到（run 當時沒跑完）
- 凍結例外（D-036 之後吸收進 M2 的契約修改，PR 說明 `mid.md` 有表）：scan.tools；kernel-cve 鏡像 cache 與退回；kernel-versions.json schema /2 與 Release 附件；platform_params.kernel_upstream_version；release-meta 的 report_status／release_gate／reports／kernel_versions（result 改名 pipeline_result）；scan_plan 用 0x1F 分隔與 collect 同後綴取後面那次；
  分層報告的核心不適用（`--kernel-in-other-report`，只給 -os）與核心不在發行版序列上的防護（kernelcheck 四條 OR 規則、`tools/pilot/lib/data/distro-kernel-sources.json`、`platform_params.kernel_not_distro`／platform.yml `scan.kernel_not_distro`；D-044）；沒宣告自有軟體 → B-own-software GAP（`sbom.own_software_none_reason`；scan.json `own_software`）；scan.json p1_rows 依 layer_todo；scan.platform_arg 傳到工具（`DUMPLING_SCAN_PLATFORM_ARG`）；
  orin-nano-demo 的 config.json 只留必填、vex-rules.json 只留 K1／K2／U1（C0 決定）
- M7 待辦（M2 合併後；判斷邏輯一起驗證）：D-035 排除依據類型；D-036 逐顆核心判定與合併；D-038 出貨的 /boot/config-* 優先（C4 缺口 23）；D-039 核心可利用性三層判斷（從 sca-center 同步，PROVENANCE 更新來源 commit）與精靈以掃描版本覆寫 version／identification；
  D-044 真正的修法：上游版本對核心 CNA、cra_report `kernel_cna_rows` 補 Grype 沒有的 CVE、「核心覆蓋 OK」的判斷條件（C4 缺口 22）；new-project.sh 不帶範本值（config.json、vex-rules.json；同 D-033 的文件骨架）；C4 缺口 7（OMV 原始碼相依依 dumpling:origin=source 歸層）、20（x86 映像的分割區訊息）；sbx-stubs 測試殘留；PR #40 第四輪驗證建議 3（-os sbom.md 的開機韌體一節仍寫 OP-TEE 已掃）、4（略過清單也列在風險評估 Layers 一節）、6（Release 附件說明寫明附件 SBOM 與報告包內 SBOM 的差別；標準答案加「-os 只有 os 層」）；-bsp＋-os 比完整多的 Python deb／PyPI 合併列（fonttools、pip、wheel）；C0 驗證建議 2–8（見下一步 3）
- M2 範圍已凍結（D-036）：之後的缺口沒擋住 C4 就排到 M7
- 對外約定（給 C4，已通知）：分層重跑只對 -os 給 `--kernel-in-other-report <專案>-bsp`（-bsp 給了 sca-scan 以 exit 64 拒絕）；scan 腳本用 `DUMPLING_SCAN_PLATFORM_ARG`；platform_arg 只能是 jetson／raspberrypi／rockchip／generic，scan.rootfs 只能是 rootfs；
  標準答案的 Jetson 驗收項目（build_record_status、kernel_boot、upstream_source.modified）只對 platform: jetson 的專案要求（6a87c15）
- 工作習慣（對話記憶不跨機器）：推上去的 commit 永久公開，內部原值連暫時都不能進 commit；推送前 `ci/public-check.sh --rev HEAD --private ~/.config/dumpling/forbidden.txt`；完整測試 `flock "$HEAVY_LOCK" env PYTHON=<有相依套件的 python> tests/run.sh`（第二台要先建 venv；venv 不要放進 PATH）；
  tools/ 的 pytest 要從 repo 根目錄給資料夾（`python -m pytest tools/cra -k …`，`tools/cra/tests/conftest.py` 設路徑；給單一檔案路徑會 import 失敗）；tests/ 底下的 unittest 用 `python3.10 tests/<檔>.py`；改 `tools/` 的檔要在 PROVENANCE 那一列補 M2 的說明（`ci/provenance-check.sh`）；
  STATUS 用 `ci/status-update.sh C1 <檔>`（timeout 給 280 秒，150 秒曾逾時）；代理：Sonnet，medium 或 high（不可信的解析與判斷用 high），寫程式與驗證分開，上限照 D-048
- M2 設計備忘：
  - C4 平台研究：`wp7/platform-samples` 的 `docs/platforms-research.md`
  - `project.yml` 要有 OS 歸屬欄位（ours／customer／upstream-vendor；D-025、D-027：由角色決定，不寫死在平台設定）
  - bsp／os 分層：平台設定裡的「套件名稱清單」決定，不看版本字尾（同 nvidia-l4t-* 做法，D-027）
  - Rockchip 分割區外的開機程式：以原始磁區為準（D-027）；assemble／scan 留掛點
  - **平台一律由 project.yml 明確給定、一路傳到 scan，不從映像格式推測；沒給就把開機程式分類標 GAP**（C4 發現 scan-flash-package.sh 對所有 raw-disk-img 固定傳 raspberrypi；P 軌修）
  - 共用下載核對：P 新增 `pipeline/lib/fetch_verify.py`（行為與簽名同 firmware_fetch.py）；M2 合併後由 C2 把 firmware_fetch.py 改成 import（C0 會通知 C2）
  - D-028：看不到內容的二進位檔要登記在 `ci/public-binary-allow.txt`（路徑＋sha256＋原因）；M2 的二進位測資盡量當場產生
  - GitHub 動態封存檔：以 commit SHA 為準，sha256 不符時 clone＋checkout 再核對或標 GAP，不自動接受新的 sha256（D-025、D-027）
  - **試驗結果（D-029，以實測為準）**：runner `/` 145 GiB，清理前可用 arm 106 GiB、x64 86 GiB（不用清理）；`public_sources.tbz2` 沒有 NVIDIA 公布的整包雜湊——整包 SHA-256 寫「首次下載記錄（TOFU）」，元件 SHA-1 對 NVIDIA `public_sources_sha.txt`；核心建置不可重現——建置紀錄與刷機包的核心要同一次編譯
  - J 的 job 拆法：build（arm，約 40 分鐘）→ artifact（BuildRecord 約 169 MB＋交付與紀錄約 152 MB，compression 0、retention 1 天）→ scan（arm，重新下載 BSP／rootfs 約 32 秒，比 cache 快）→ release（只有它 contents: write）
  - **SBOM 存放（D-029）**：不提交 `sboms/`，Release 是正式來源；附件 `sbom-<專案>-<版本>.cdx.json`＋`release-meta.json`（project、version、tag、status、platform、os_responsibility、commit、built_at、workflow_run）；開發版發到滾動 pre-release `dev/<專案>`（只在 main 或 dev/** 發佈）
  - 新 workflow 不在預設分支時 `gh workflow run <檔名>` 回 404：先用一次 push 觸發登錄，之後改回（PR 裡不留 push 觸發）
- 對外介面約定（改之前先通知對方）：
  - C2 依賴 `tools/cra/uefi_image.py` 的內部名稱：`Scan`（子類別覆寫 `scan_bytes(data, module)` 接 GOP／VBT／legacy VBIOS）、`parse_fvs(data, sc, depth)`、`Stop`、`MAX_*` 常數（C2 有契約測試）
  - C2 依賴 `tools/pilot/lib/nvidia-bulletins-gpu-firmware.json`（路徑與檔名；`wp1/m2` fdabd22 新增的空表，M2 合併後生效；C2 在檔不存在時印 GAP）
  - C2 依賴臨時 DT 介面：`pipeline/dt-ephemeral.sh up|wait|env|down`、`tools/pilot/sca-scan --sbom`、`pipeline/scan-status-check.py`（預設 11 個必要階段）、`pipeline/dt-verify.py verify`
- 卡住／等決定：
  - （已定，D-030）unknown 保守算 BSP 待辦，J 校正時先用 Syft locations 套路徑規則，報告附「為什麼判斷不了」；NVIDIA 為平台提供的套件都算 bsp——J 依公開 BSP 的 apt 來源補 Jetson 的 bsp 名稱清單；VEX 發行閘門不分層（列入 C0 給 PM／法務的待決定清單）；DT 維持兩個平行專案（parent／child 留到 GitLab 階段，C3 的 GITLAB-PORT 待辦）；host-tool 不上傳 DT，報告那節加「隨 BSP 提供給客戶，在客戶主機上執行，不在產品上執行」
  - 等使用者（C0 轉問）：M1 PR 內歷史 WIP commit 含內部 CI 執行編號等（禁用字 0 命中）——選項只有接受或刪 repo 重建
  - （已定）public-check 反向規則：D-028（C0 做）；上游部署預設路徑保留；alert_mail.py 留給 C3
<!-- END C1 -->

<!-- BEGIN C2 -->
## C2 韌體（WP3＋WP4）

> **現況（2026-11-13，第二台 WSL2 重開後）**：C2 已在第二台接手（D-045）。worktree `$AGENT_TMP/dumpling-wt-c2-amd`（wp3/amd-psp，從 origin ebac3e9 重建）。AMD 三個公開樣本（B550M 3404、B650M 1807、ASRock PG4 3.40）已在第二台重新下載並核對 sha256 OK，放 `$PUBLIC_IMAGES/bios/`；main 的 Protectli、NUC11、OVMF、vbios、供應商 SBOM，以及 csme-new 的 NovaCustom V540TU 也都用 firmware-fetch 下載核對 OK（放 `$PUBLIC_IMAGES/<bios|vbios|sbom>/<名稱>/`）。代理上限照 D-048（每對話 3 個：2 寫＋1 驗；整台 10；負載 >12 或可用記憶體 <4 GB 不開）。
>
> **開出去的代理**
> - 寫程式（Sonnet 5.5，effort high）：D-047 (1) 歧義規則改窄＋(2) 拿掉 sys._getframe，分支 `wp3/amd-psp`，暫存 `$AGENT_TMP/dumpling-tmp-c2-amd47/`（samples、out、venv 留給驗證用），狀態：**完成**（第三輪 **29a2cc9**）。F1–F4 和建議 1–6 都修了：上限、限制、超時一律無法判斷；走訪依深度逐層；任何 loop／limit 都讓競爭讀法全部 ambiguous。上一輪的重現腳本全部符合要求，test_amd_psp 共 90 個，本機 431 passed，99／25／101 不變
>   - 第一輪完成 **9fc6d1e**。(1) 改成依結構檢查採用／拒絕：checksum、條目範圍、slot header、combo 子目錄、目錄表不落在自己的條目裡。恰好一種讀法通過就採用，另一種讀法記 `reading-rejected`（ATTENTION）並附證據；都通過但內容不同、或都不通過，仍是 GAP。真樣本 SBOM 元件數：B550M 21→99、B650M 2→25、ASRock 101→101；B550M expected 3 項 OK。本機 408 passed
>   - 第二輪：(2) 第一輪改用 `Scan.layers` 計數，這不在介面約定內，C2 決定改照 D-047 字面：原始位元組有任何 AGESA 標記就 complete=False，只在原始位元組有的值照樣列出。三個真樣本的原始位元組標記數都是 0，結果不受影響。第二輪完成 **1cd25aa**：SBOM 元件數仍是 99／25／101，B550M expected 3 項 OK，本機 406 passed
> - 驗證（Sonnet 5.5，effort high）：複驗 ebac3e9..1cd25aa（D-047 兩點，加上 ebac3e9 本身還沒複驗的部分），暫存 `$AGENT_TMP/dumpling-tmp-c2-verify47/`（重現腳本放 scripts/），狀態：**完成：驗證不通過**（1cd25aa）
>   - 真樣本、證據重算、frame 移除都確認 OK（99／25／101、expected 3 OK、2 萬次 fuzz 零例外）
>   - 應修 F1：上限截斷被當成「不通過」，沒檢查的讀法讓另一邊被採用
>   - 應修 F2：工具不支援的條目（mode 3、MAX_BLOB）被當成反證
>   - 應修 F3：超時中途的半個目錄被拿去採用
>   - 應修 F4：loop／MAX_DEPTH 讓結果依賴處理順序
>   - 建議：存活的變異要補測試；FV 外非空白位元組裡的 LZMA 會讓 AGESA complete=True 卻漏搜；排序鍵；notes 精簡
>   - 已交回寫程式代理修正
> - 驗證（Sonnet 5.5，effort high，新代理）：二次複驗 ebac3e9..29a2cc9，暫存 `$AGENT_TMP/dumpling-tmp-c2-verify47b/`，狀態：**完成：驗證通過**（29a2cc9）
>   - 沒有應修項目。F1–F4 都確認修好
>   - 順序打亂 fuzz：合成 4200 張、真樣本變異 315 次，零差異、零例外
>   - 證據用獨立腳本重算過；99／25／101、expected 3 OK、431 passed
>   - 建議（不擋）：檔頭與程式不一致、AGESA 值超過上限時要 complete=False、members 排序、補邊界測試、notes 寫取捨、拿掉歷史口吻
> - 寫程式代理第四輪（收尾）：**完成** **48058e1**。程式只改了排序，另加 AGESA 不同值上限時 complete=False；C2 已看過 diff。test_amd_psp 共 103 個，99／25／101 不變
> - **C2 已把 origin/wp3/csme-new 併進 wp3/amd-psp → ca80b27**：只有清單衝突，三處都保留兩邊的項目。main 仍是 26a6377，不用併。本機 C2 測試組 527 passed。所有代理都已結束
>
> - 寫程式（Sonnet 5.5，effort high）：D-043 (1) 的 Intel 部分（微碼公告比對：固定 commit 的 Intel microcode release notes → 資料表 → CPUID＋rev 比對；CSME 加 NVD CPE），分支 `wp3/fw-advisory`（從 main 26a6377 開，worktree `$AGENT_TMP/dumpling-wt-c2-advisory`），暫存 `$AGENT_TMP/dumpling-tmp-c2-adv/`，狀態：**完成 5bddbf8**。NVIDIA vBIOS 那項要用 gpu-firmware 對照表，等 M2 進 main 才做
>   - 資料表：microcode-20261110 的 releasenote.md（commit d71fe4e2…，sha256 338b556b…），45 個 release、920 列，SA 只列在 release 層級
>   - 結果分四種：affected-candidate（候選）、older-no-sa、up-to-date（不代表沒有漏洞）、NOT_ASSESSED（資料庫沒有資料，以廠商公告為準）；vuln-assessment 仍是 NOT_ASSESSED
>   - CSME CPE：NVD 的 product 是 converged_security_management_engine_firmware，版本只到三段，NVD 資料止於 2022
>   - **D-051（C0 決定）**：family 讀不出來時 major ≥ 11 推定為 CSME（cpe-basis=inferred）。報告要寫明「family 是由版本推定、比對結果待人審」，這句還要補；若預驗找到公開反例就改回 GAP，並通知 C0
>   - CI tests 43436190471、firmware 43436194559（進行中）
> - 驗證（Sonnet 5.5，effort high）：預驗 wp3/fw-advisory 5bddbf8，暫存 `$AGENT_TMP/dumpling-tmp-c2-verify-adv/`，狀態：**完成：驗證不通過**。
>   - 確認沒問題的部分：資料表重現 OK；獨立解析器對照一致；差分測試 2188 案例一致；6 份樣本微碼核對了原檔行號；major ≥ 11 沒找到 TXE／SPS 的反例，D-051 維持
>   - 應修 1：揭露表（New Disclosures Updated in Prior Releases）沒有納入候選
>   - 應修 2：20250812 的散文會影響 ADL 等的候選，只放在 unparsed
>   - 應修 3：同 F-M-S 被新的 mask 取代時，舊 mask 被標 up-to-date
>   - 應修 4：cpe-basis 的依據句不實（漏了 AMT）
>   - 建議：補邊界測試；validate 的強化；產生器超線性；授權方面（release notes 沒有明確授權）只留事實性欄位
>   - 供應商 SBOM 的公告比對還沒做，等 supplier-normalize 合併後由 C2 處理
>   - 已交回寫程式代理修正：**完成 9e8e59e**（4 項應修和建議都修了）
>   - C2 併入 main → **03b33cd**：3 處清單與說明衝突；648 passed；NovaCustom V540TU 現在帶 CSME CPE 18.0.10（inferred）
>   - CI tests 43443887986、firmware 43443892464
> - 驗證（Sonnet 5.5，effort high，新代理）：複驗 wp3/fw-advisory 03b33cd，暫存 `$AGENT_TMP/dumpling-tmp-c2-verify-adv2/`，狀態：**完成：驗證不通過**
>   - 前輪 4 項確認修好；獨立 oracle 約 33 萬個案例 0 不符
>   - 應修 1：AMD 微碼已解析 19 份，報告與 CI 摘要卻寫「沒有解析」；AMD 元件也沒有 advisory-match
>   - 應修 2：06-be-00/19（ADL-N＋TWL）的散文對照被整組設成 GAP，候選因此漏列
>   - 應修 3：notes 有過時的地方，以及寫起因的句子
>   - 建議：revert 註記；cpe-basis 改成列舉值（listed／inferred）；註解邊界；補測試
>   - 已交回寫程式代理（第三輪）：**完成 d8a20ec**。AMD 元件都有 advisory-match=NOT_ASSESSED，報告照實寫「已解析 N 份」；06-be-00/19 已納入（散文對照 30 個 key、0 個 GAP，AZB 加註）；cpe-basis 改成 listed／inferred；633 passed，四個樣本的 expected 全 OK
>   - CI tests 43447781681、firmware 43447786318
> - 驗證（Sonnet 5.5，effort high，新代理）：複驗 wp3/fw-advisory d8a20ec，暫存 `$AGENT_TMP/dumpling-tmp-c2-verify-adv3/`，狀態：**進行中**
>   - C0 已把上限補進 D-051（a3cf183）：major 11～30 才推定 CSME；cpe-basis 用列舉值 listed／inferred
>
> - 寫程式（同一個 AMD 代理，第五輪）：C0 驗證後的 3 項修正，分支 `wp3/amd-psp`，狀態：**完成 34fd4f9**
>   - checksum 不符的目錄標 untrusted，只經由它找到的目錄標 untrusted-path（dir-untrusted-path），都不採用
>   - D-050 的兩個前提已寫進 notes 與報告依據；firmware.yml 的兩種口徑分開寫
>   - 本機 532 passed，99／25／101 不變；C0 的重現由 C2 親手跑過
>   - CI tests 43435020981、firmware 43435026101 **綠**
>
> - 寫程式（Sonnet 5.5，effort high）：CSE layout Size 0x60 的支援。分支 `wp3/cse-layout-size`（從 main c0a54eb 開，worktree `$AGENT_TMP/dumpling-wt-c2-cse60`），暫存 `$AGENT_TMP/dumpling-tmp-c2-cse60/`。先找公開的 Arrow Lake／Lunar Lake／Panther Lake／Wildcat Lake 樣本，找不到就做合成測試，並寫明沒有公開真樣本核對。狀態：**完成 dc7589a**
>   - 公開真樣本 Dasharo NovaCustom NUC BOX v0.9.2（Arrow Lake-U/H FSP）：Size 0x60、CRC 相符、RBEP＝NFTP＝18.1.18.2724，有 release notes 為出處；已登記成 `firmware/bios/novacustom-nuc-box-arl-v0.9.2`
>   - Size 逐值列舉 0x40／0x48／0x58／0x60；+0x58 之後要全 0，否則 GAP
>   - 其他 7 個樣本改動前後逐位元相同；本機 221 passed
>   - CI tests 43443071116、firmware 43443076668 **綠**
> - 驗證（Sonnet 5.5，effort high）：預驗 wp3/cse-layout-size dc7589a，暫存 `$AGENT_TMP/dumpling-tmp-c2-verify-cse/`，狀態：**完成：驗證通過**（dc7589a）
>   - 應修是公開文字：4 處「以前…現在」
>   - 建議：微碼出處要寫到正確小節；license.url 改指 release notes 頁；補測試（0x44～0x54、ELog 非 0、BP 落在表內）
>   - C0 私有檔複核：CSME 18.1 那份 found；19.0、21.x 那兩份因為表尾非 0 而 GAP
>   - → **D-053**：表尾非 0 時，CRC 相符、BP 全過、RBEP＝NFTP（或有 FTPR）三項都成立才採用，並記 ATTENTION 列原始值，用合成測試
> - 寫程式（同一個 cse 代理，第二輪）：文字修正＋建議＋D-053，狀態：**完成 c185446**
>   - 表尾非 0 時，CRC、BP、版本三項都成立才 found，並記 `layout-undocumented-fields`（ATTENTION，列原始值），整份狀態變 ATTENTION
>   - test_intel_cse_layout 共 132 個；7 個樣本逐位元相同
>   - 授權改指 release notes 頁，沒有出處的授權名稱拿掉了；V540TU 的 license 還沒核對
> - C2 併入 main cc7d101 → **40bdd2f**（沒有衝突，581 passed）；CI tests 43449879817、firmware 43449885845
> - **下一步**：fw-advisory 複驗結束後派 cse 預驗（40bdd2f）→ 新的 HEAD 給 C0 用私有檔複核 → 開 PR
>
> **本機背景工作**：無。**CI**：ca80b27 的 tests 43429449008、firmware 43429452991 **綠**；firmware-expect 五個樣本全 OK（B550M 3、Protectli 11、NUC11 2、NovaCustom 2；OVMF 沒有 expected）。

### 公開資料規定（D-042／D-043，重要）
repo 裡的所有文字（程式註解、文件、commit 訊息、PR 說明、firmware.yml、STATUS）**不能提到這兩項工作的起因**，也不能寫是哪種產品或平台需要它。一律寫成「擴充 AMD 平台／新世代 Intel CSME 的解析範圍」，選樣本只講技術理由（例如「沒有 $FPT 的分割區配置」「有 L2 目錄的 PSP」）。只用公開可下載的樣本和公開資料；不使用、也不索取任何公司的 BIOS 檔。代理的指示也照這個寫，不要告訴代理起因。

### 已完成
- M3（C2 唯一的里程碑）：PR #14 合併（main b6d341a）。已合併的 PR：#7、#8、#14
- D-042 新世代 Intel CSME：分支 `wp3/csme-new` **61e8ef7**，預驗＋複驗都**通過**
  - 新模組 `tools/cra/intel_cse_layout.py`：CSE layout table（1.7 驗 CRC-32，Size 從 +0x10 起算，認 0x40／0x48／0x58；1.6 靠表長 0x48＋後面全 0xFF 辨識，讀 BP1…BP5）→ BPDT v1／v2 → FTPR，或 RBEP 與 NFTP 兩種都有且版本相同 → `.man` 的 `$MN2` 版本；矛盾、單一來源、結構不一致 → GAP；整個 BP 都是 0xFF 才算清除。`x86_firmware.py` 只在舊的 `$FPT` 路徑（`me_info_fpt`）沒找到時才走這條
  - 公開樣本 `firmware/bios/novacustom-v540tu-mtl-v1.0.1`：改動前 unknown → 18.0.10.2285。expected 有 `intel_me`，以及微碼 000A06A4／0xE6／0x25（出處：Dasharo release notes 原始 HTML、Intel microcode-20250812 的 releasenote.md，我都直接抓原始檔核對過）
  - 驗證：fuzz 約 36 萬次零例外，44 個變異全殺；Protectli、NUC、OVMF 新舊輸出逐位元相同。CI（70db3f6）firmware 43382783573、tests 43382788001 綠；61e8ef7 只改文件一行
  - 文件：`docs/notes/c2-csme-layout.md`
- supplier-normalize（M3 之後的收尾，C0 同意合成一個 PR）：分支 `wp3/supplier-normalize` **8a960c0**，內容完成
  - (1) 供應商 SBOM 上傳前的最小正規化：`pipeline/lib/firmware_sbom_normalize.py`。報告的假 OK 路徑已堵住（`firmware_dt.py` 的 `attention_reasons`）。預驗通過
  - (2) `firmware_fetch.py` 改 import C1 的 `pipeline/lib/fetch_verify.py`：已先併 `origin/wp1/m2`（54dbf48）
  - CI tests 43323859797、firmware 43323866206 綠。五個真樣本全 ATTENTION；NVIDIA「有表」路徑跑出 `C-nvidia-bulletins-db ATTENTION`（5674 待人審）

### 進行中：D-042 AMD 平台（分支 `wp3/amd-psp` **ebac3e9**，從 main 26a6377）
- 新模組 `tools/cra/amd_psp.py`：
  - 目錄：EFS（依視窗大小分三張位置表，與 coreboot 相同）→ combo／L1／L2 的 PSP 與 BIOS 目錄、A/B 復原 slot header（ISH checksum 照 coreboot amdfwtool.c:854）；目錄 checksum 是 Fletcher-32，照 coreboot 的寫法
  - 內容：PSP 韌體標頭版本；AMD 微碼的 patch level、日期、equivalence id（CPUID 只在有等價表時才填）；AGESA 字串
  - GAP：未知 type、size 0（有 destination 的 APOB 0x61 除外）、壓縮條目、Promontory、AGESA 截斷
  - 歧義：同一位置只要被兩種基底讀過，就是歧義（C0 決定：一律 GAP、兩邊都列，不選邊），歧義目錄的條目不進 SBOM
  - `analyze()` 不丟例外
- 公開樣本 `firmware/bios/asus-prime-b550m-a-3404`。expected 有 `amd_agesa` "1.2.0.B"（我用 ASUS API GetPDBIOS 核對過）和 `amd_microcode` 兩份（與 linux-firmware c4586ffaac0c 位元組相同）
- 驗證歷程：
  - 預驗 41353d3 **不通過**（4 項應修）→ f41f5eb 修完
  - 複驗 f41f5eb **不通過**（1 項應修：目錄去重只看 offset、不看基底）→ ebac3e9 修完：目錄紀錄改以（位置，基底）為單位、與處理順序無關，另做了建議 a／b／c／e
  - **ebac3e9 還沒有複驗**
- ebac3e9：CI tests 43397906497、firmware 43397901286 綠（expected 3 項 OK）。本機 c2-x86-firmware 372（test_amd_psp 52 個）、c2-firmware OK、c1-tools 3166
- 驗證代理的重現腳本在這台的 `$AGENT_TMP/dumpling-tmp-c2-verify-amd/scripts/`、`scripts2/`（t1～t14、fuzz1～4、fl.py、mut3），第二台沒有這些檔案；需要時照複驗報告的描述重寫
- **已由 C0 決定（D-047，見下一步 1）**：ebac3e9 的歧義規則很保守
  - ASUS B550M 的 PSP 韌體版本 78 個全部進不了 SBOM，SBOM 只剩 21 個元件（映像、19 份微碼、AGESA）
  - ASUS B650M-A 1807（只在 notes 做過驗證）只剩 2 個元件；ASRock B550 PG4 沒有歧義，不受影響
  - 較窄的替代規則：只讓「不歧義路徑讀出的那筆」確定，另一種基底的讀法只列出，不連帶讓確定的那筆變歧義。代理沒有實作，notes 有寫這個取捨
- **新發現（已由 D-047 決定拿掉）**：AGESA 搜尋的「位置比對」（建議 a）用 `sys._getframe(1)` 讀 C1 `uefi_image` 呼叫端的區域變數 `where`、`out`（amd_psp.py:746、:860 附近）
  - 這不在 C1 的對外介面約定裡，屬於脆弱的耦合；失敗時方向是保守的（標成不完整）
  - 處理選項：(a) 請 C1 在 `uefi_image` 提供正式的回呼或來源資訊；(b) 拿掉 frame 讀取，只要原始位元組裡有任何標記不在走訪範圍內，就一律 complete=False
  - D-047：採 (b)；(a) 留到 M7
- 其他已知限制：壓縮的 BIOS 條目（0x62）和壓縮的微碼不解壓；真樣本的 AGESA 搜尋仍是「不完整」（2 個 `CE3233F5-…` GUID-defined section、1 個 FFS 檔的 section 串不乾淨）

### 下一步（新對話照這個順序接手）
1. **D-042 AMD**：C0 已決定（**D-047**，在 wp0/docs-batch-4），照這兩點修（**寫程式代理已派出，進行中**），改完和 ebac3e9 的改動一起複驗：
   - (a) **歧義規則改窄，但要有校驗佐證**：同一位置被兩種基底讀到時，只有一種讀法的目錄通過自身的結構與校驗（目錄 checksum、條目範圍都在映像內等），就採用那一種的條目；另一種只列出來，並附上它沒通過的證據。兩種都通過而且內容衝突，或兩種都不通過 → 維持 GAP。（我的補充：子目錄要沿用被採用那一讀法的基底；測試要涵蓋「一邊 checksum 壞」「兩邊都過且內容不同」「兩邊都壞」，以及處理順序反過來結果相同；真樣本 B550M、B650M 重跑，報 SBOM 元件數的變化。）
   - (b) **拿掉 `sys._getframe`**（amd_psp.py:746、:860 附近）：原始位元組裡只要有 AGESA 標記不在走訪範圍內，就標「搜尋不完整」（complete=False）。需要精確結果的話，M7 再請 C1 提供正式回呼介面，現在不跟 C1 談
   - **已完成**：複驗兩次，第二次在 29a2cc9 通過；收尾 48058e1；併入 csme-new，得到 ca80b27。CI 綠、已通知 C0。**C0 回覆：PR 先不開**，等兩件事：(1) sca-center 用私有檔在本機驗 ca80b27；(2) C0 已對 ca80b27 派獨立驗證代理。兩件都沒問題，C0 會通知開 PR，驗證報告由 C0 貼。「目錄表落在自己的條目範圍裡」要不要補進 DECISIONS，C0 等驗證結果再決定。**更新**：C0 對 ca80b27 的獨立驗證「通過」；延伸證據定為 **D-050**（wp0/docs-batch-4 b5c5015）。開 PR 前要修 3 項：(1) checksum 不符的單一讀法目錄仍被標 adopted，它的 L2 子目錄版本因此進了 SBOM；(2) notes 和報告依據要寫明 D-050 的兩個前提；(3) firmware.yml 的目錄與條目數要把兩種口徑分開寫。**已派寫程式代理到 wp3/amd-psp 修**（第 1 項做法：untrusted／untrusted-path 不採用），34fd4f9 的 diff C0 已看過，沒問題；CI 兩個都綠。**PR #39 已合併**（main c0a54eb，內容與 34fd4f9 相同）。worktree `dumpling-wt-c2-amd` 已移除。遠端的 `wp3/amd-psp` 已自動刪除。遠端的 `wp3/csme-new` 要刪，但刪除指令被權限擋下，**等使用者決定**（它的 commit 都保留在 refs/pull/39/head 裡，刪了不會遺失）。**私有檔驗證已由 C0 跑完**（ca80b27，結果不進 repo）：沒有當掉，也沒有確知錯誤的值；ME 是 GAP，因為 CSE layout 的 Size 0x60 不在支援清單。這一項**不擋**這次 PR，C0 看過 diff 就請 C2 開 PR。PR 說明草稿在 `$AGENT_TMP/dumpling-tmp-c2/pr-body.md`
   - 把 `origin/wp3/csme-new` 併進 `wp3/amd-psp`。會衝突的有 `docs/PROVENANCE.md`、`tests/run.d/c2-x86-firmware.sh`（兩邊都改了最後的測試清單），x86_firmware.py 兩邊改的是不同段落
   - 併 origin/main（D-021：有衝突才併，開 PR 前確認只剩自己的改動）
   - 重跑 CI
   - **先通知 C0（sca-center 端要用私有檔在本機驗證）**，再開一個 PR，標題「[WP3] 擴充 AMD 平台／新世代 Intel CSME 的解析範圍」，PR 說明照公開資料規定寫
   - 驗證由 C0 派，C0 合併
1b. **CSE layout Size 0x60 的支援**（**進行中**，見上方代理）：標準答案用公開可下載的新世代 BIOS 更新檔，要確認 Size 是 0x60、CRC 相符、RBEP 和 NFTP 一致；找不到公開樣本就用合成測試，並在 notes 寫明「沒有公開真樣本核對」。順便評估更大的 Size 值。repo 裡只寫技術理由，不索取私有檔
2. **supplier-normalize**（**M2 已合併**。C2 已併入 main cc7d101 → **1322c67**：C2 沒改過的檔案一律取 main 的版本，只有 PROVENANCE 和 run.d 是手動合併；755 passed；CI tests 43449745772、firmware 43449751297。下一步是預驗 → 開 PR）：等 C1 的 M2 合併進 main → 併 origin/main（確定只剩自己的改動）→ 重跑 CI → 開一個 PR → 驗證（C0 派）→ C0 合併。現況：沒有任何真樣本能到 OK（保守、符合原則，不放寬）
3. **D-043**（排在 D-042 之後）：韌體 SBOM 的公告比對，只用公開資料。順序是 (1) → (2)，每段完成通知 C0
   - (1) 自動比對：
     - NVIDIA vBIOS：用每日鏡像的 NVIDIA product-security CSAF 填 `tools/pilot/lib/nvidia-bulletins-gpu-firmware.json`，依 vBIOS 版本＋裝置 ID 判定受影響／已修補／NOT_ASSESSED
     - Intel 微碼：用 intel/Intel-Linux-Processor-Microcode-Data-Files 的 release notes（固定 tag／commit＋sha256）。SBOM 的 CPUID＋rev 比較舊時，列出中間的 INTEL-SA；讀不到 → GAP
     - Intel CSME：加 NVD CPE（converged_security_and_management_engine_firmware），並註明 NVD 資料不完整
   - (2) 規則表：比照 D-039，一個公告一筆（INTEL-SA、AMI-SA、AMD-SB），條件＝元件＋版本範圍，記出處、確認者（角色）、日期；結果只給建議，排除照 D-035 記 vendor-statement
   - (3) vendor-watch 由 C3 改，C2 不動
   - 產出：每份韌體 SBOM 都要有比對結果（受影響／不受影響／NOT_ASSESSED＋依據）並寫進報告；比不到的寫「資料庫沒有資料，以廠商公告為準」，不可以顯示成沒有漏洞
4. 代理規則（D-048）：同時最多 3 個（寫程式最多 2 個、驗證 1 個，兩者分開），整台 10 個；Sonnet 5.5，effort 用 high（解析不可信資料、判定邏輯）。開代理前看 uptime 與 free -g，1 分鐘負載 >12 或可用記憶體 <4 GB 不開。PR 的驗證由 C0 派，C2 只派 PR 前的預驗

### 第二台要準備的
- worktree：從 origin 重建三條分支 `wp3/amd-psp`（ebac3e9）、`wp3/csme-new`（61e8ef7）、`wp3/supplier-normalize`（8a960c0）
- 公開樣本：這台的 `$PUBLIC_IMAGES/bios/` 只有 Protectli v1.2.0 和 OVMF 的原始碼包。其他樣本都在這台的代理暫存資料夾裡，第二台要重新下載。網址、sha256、size 都在各分支的 `firmware/**/firmware.yml`，可用 `pipeline/firmware-fetch.sh <firmware.yml>... --out <目錄>` 下載核對：
  - main：`firmware/bios/dasharo-protectli-vp46xx-v1.2.0`、`intel-nuc11-patgl357-0059`、`ubuntu-ovmf-2024.02`，`firmware/vbios/*`，`firmware/sbom/dasharo-novacustom-ns5x-tgl-v1.6.0`
  - `wp3/csme-new`：`firmware/bios/novacustom-v540tu-mtl-v1.0.1`（32 MiB）
  - `wp3/amd-psp`：`firmware/bios/asus-prime-b550m-a-3404`（16.7 MB zip）
  - 只做過驗證、沒登記成樣本的檔案（網址和 sha256 寫在 `wp3/amd-psp` 的 `docs/notes/c2-amd-psp.md`）：ASRock B550 PG4 3.40、ASUS B650M-A 1807
- 依賴 C1：
  - `uefi_image.py` 的 Scan／scan_bytes／parse_fvs／Stop／MAX_*（已記入 C1 的對外介面約定）
  - `dt-verify` 的檢查名稱「弱點分析完成」「元件數」
  - `fetch_verify.py`（隨 M2 進 main）
  - gpu-firmware 對照表（隨 M2 進 main）

### 卡住／等決定
- 無待決定事項（AMD 的兩件已由 D-047 決定）
- 這台的代理暫存資料夾被安全檢查擋下沒刪，要使用者手動刪：`$AGENT_TMP/dumpling-tmp-c2-*` 共 21 個，`dumpling-tmp-c2` 本身是 STATUS 草稿，搬完再刪
- worktree `$AGENT_TMP/dumpling-wt-c2-amd`、`-csme`、`-norm` 等使用者確認後再刪
<!-- END C2 -->

<!-- BEGIN C3 -->
## C3 監控＋GitLab（WP2＋WP5）

- 目前在做：M4 已合併（PR #28）；PR #32（第一輪應修）驗證通過、C0 背景合併；**M2 之後的監控 PR 分支 `wp2/watch-m2` 已先做好 #32 驗證的 F1–F6 與 concurrency**，等 M2 合併後接 mirrors.sh 再開 PR；M5 第一版完成，等 M2 合併後核對指令再開 PR
- 架構（已合併）：每日不開 DT；Grype＋CISA KEV＋EUVD＋核心 CNA＋廠商層級；狀態放在 `watch-state` Issue；D-040（只開 KEV／廠商層級、超過 20 個併成彙總、示範專案＋demo、排程 real 預設 dry_run、不開 art14）
- 分支／PR／commit：
  - PR #32 已合併（main 26a6377），worktree 已移除
  - `wp2/watch-m2` a4628dd（2026-11-13：release-meta 已照 C1 wp1/m2 9f1d2f0 的實際格式收斂成一種讀法——六種值照原值、reports 列每份報告、attention 寫進 Issue、kernel_versions 照欄位找附件；D-043 廠商清單端到端測試 bbcb489；141 個測試）。之前 f204260（已併 main 26a6377；worktree `$AGENT_TMP/dumpling-wt-c3-m2`，從 #32 head 開）：F1 大小警告算 ATTENTION、7 天一次；F2 修剪過的群組再出現用 open_if_closed（`dumpling.pruned_keys`）；F3 Grype DB 過期與 L4T 對應 GAP／FAIL 擋第一次基準；F4 有 Release 卻沒有基準 → 只開「還沒有基準」提醒 Issue（plan.state=null，不寫狀態、不算監控 Issue）；F5 演練三輪都可建基準；F6／concurrency：group 依 ref、compute 用 actions: read 查上一次排程 run（cancelled／失敗／超過 36 小時 → 降級）、keepalive 印最近 3 次排程。PR 未開（等 M2 的 mirrors.sh）
  - `wp5/gitlab` b0079fc（worktree `$AGENT_TMP/dumpling-wt-c3-gitlab`）
- M8 B1（第 14 條通報，C0 交辦：等 M2 期間先做不需要 M7 欄位的部分）：分支 `wp2/art14`（worktree `$AGENT_TMP/dumpling-wt-c3-art14`，從 main 26a6377），只推分支、M8 才開 PR。條文已核對：EUR-Lex CELEX:32024R2847（OJ L 2024/2847, 20.11.2024）第 14(1)–(4) 條、第 71 條（第 14 條自 2026-09-11 適用）；期間的法定計算規則未核對 → 工具算保守值、交法務。銷售市場欄位等 C1 的 M7 → GAP
- 代理（上限 D-048：每對話 3 個 Sonnet 5.5，寫程式 2、驗證 1；整台 10 個；負載 >12 或可用記憶體 <4 GB 不開）：
  - 寫程式 B1 art14（Sonnet high）：完成。`wp2/art14` e66f499（177 個測試）。**已在 GitHub 實跑 action=drill 六步兩次全綠**（run 43369037768、43369266378；暫時的分支 push 觸發已拿掉）；實跑發現依標籤列 Issue 有索引延遲 → 演練步驟重試、countdown 跳過已關閉的。ART14.md 已加 1182/71 參考（未核對、採較早保守值）與 Bot 例外理由。目前沒有代理在跑
- CI：wp2/watch-m2 b1b236e：演練 43365208989 綠、tests 43365156856 綠（132 個 c3-watch 測試）、real＋dry_run 43366085628 綠（GAP）。main：real＋dry_run 43362385127 綠
- 防 60 天停用：**下次人工檢查日期：2026-12-13**（`gh workflow view watch.yml`）
- 下一步：
  - M2 合併 → `wp2/watch-m2` 併 origin/main → 每日監控改用 `pipeline/lib/mirrors.sh`（kernel-cve 沿用舊鏡像時，報告與 Issue 寫出那行 ATTENTION）＋release-meta 的 `report_status`（報告整體狀態）與 `release_gate`（發行閘門）寫進 Issue 內文與報告，欄位不存在填 NOT_RUN（名稱 C1 已定案：report_status、release_gate、pipeline_result；已做在 7caa0f2；已依 C1 實際格式收斂（a4628dd），M2 合併後再對合併版核對一次）→ 演練／real dry_run → 開 PR → 驗證 → 合併
  - 之後：手動 `mode=real`＋`baseline=true` 建第一次真實基準 → 排程 dry_run 跑一天 → 回報「打開會開哪些 Issue」→ C0 設 WATCH_REAL_ISSUES=on
  - M5：M2 合併後核對 gitlab/.gitlab-ci.yml 的指令（T-01）→ 重跑 CI → 驗證 → 開 PR
- B1 art14 的待辦（M8）：等 M7 的銷售市場欄位再一起開 M8 PR；銷售市場接 M7 的 project.yml 欄位；GitLab 版（私密 Issue、email、SRP）只列在 docs/ART14.md 第 10 節，M5／M8 再做。已實測：github-actions[bot] 開的 Issue 是 author_association=NONE（#21），所以程式接受 Bot 作者是必要的
- 卡住／等決定：等 M2 合併
<!-- END C3 -->

<!-- BEGIN C4 -->
## C4 其他平台（WP7）

- 目前在做：M6 收尾。M2（PR #40）已合併，`wp7/adapters` 用 merge 併上 main cc7d101（736bbee，不 rebase；C1 的檔案取 main 版、PROVENANCE 保留 C4 節）；product_status 加 `bsp_inputs_not_applicable`（8429d1f）；三個示範專案依序重跑中（rock → rpi → ai-nas），跑完核對 rock／rpi 的 -os 項目（852b6d3 的影響）並釘進標準答案
- 分支／PR／commit：`wp7/adapters`（8429d1f）；`wp7/platform-samples`（868f064）；PR 尚未開（M6 完成才開，D-020）
- 代理：0 個（重跑完、標準答案更新後派 1 個驗證代理；D-048 上限 3）
- CI：單元測試 c4-wp7 88 項、c1-m2-jetson 40、c1-m2-platform 63、c1-m2-layers 35 都通過（併 main 之後）；dev 重跑中
- 今天處理：缺口 21、D-044、D-038 的 +rpt 版本讀法、三專案標準答案定案（403fae7）；adapter-gaps #25～#27 依 C0 決定（#27 D-049 維持現狀）
- 下一步：重跑結果核對 → 更新標準答案 → 獨立驗證 → 完成 PR 草稿 → 開 M6 PR、通知 C0
- 卡住／等決定：無。缺口 19（rpi 核心 CNA 候選沒有成列）、7、20、22、23、25、26 排 M7
<!-- END C4 -->
