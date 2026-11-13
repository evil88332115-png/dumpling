# STATUS

每個對話一節，**每做完一步就更新並推送**（`ci/status-update.sh`，見 main 的 `docs/HANDOFF.md`）。只改自己那節，`<!-- BEGIN/END -->` 標記不要動。

最後更新：2026-11-13 04:25 -0500（C0）

<!-- BEGIN C0 -->
## C0 協調（WP0）

- 目前在做：**搬家準備完成：可在第二台（WSL2）以原開場指令接手**（D-045，使用者已確認）。C0、C1、C2 都已推送並停下；主要主機上的對話、worktree、repo 在使用者確認第二台接上前不刪
- 分支／PR／commit：main 26a6377。已合併：M1（#9）、M3（#14）、M4（#28）＋修正 #32；文件批次 #13、#15。C0 分支 `wp0/docs-batch-4`（已推送 53a3112，**未開 PR**）：D-034～D-047＋HANDOFF「在第二台電腦（WSL2）接手」一節；**M2 合併後開 PR**（新對話請先從這個分支讀 DECISIONS／HANDOFF，main 上還沒有）
- 代理：無
- CI：C0 無。C1 的兩個 Jetson release run 與 C3／C4 的 dev run 由各自的 STATUS 記錄
- 各對話現況（細節看各節）：
  - C1：**搬家準備完成、已停下**。wp1/m2 f11bfdb（全推，本機完整測試 OK）；PR 草稿在 wp1/m2-pr-draft d3efdc8（不合併，開 PR 後刪）。驗收 run 在 f11bfdb 上跑：release v39.2.0 43399785656、v39.2.1 43399800268、tests 43399813005。下一步見 C1 節：檢查 draft → 新的獨立驗證 → 併 main → 開 M2 PR
  - C2：**搬家準備完成、已停下**（C2 節 f48ffb2）。D-042 CSME 完成（wp3/csme-new 61e8ef7）；AMD（wp3/amd-psp ebac3e9）應修已修、**還沒複驗**；新 C2 先照 D-047 改歧義規則（需校驗佐證）與拿掉 sys._getframe，再複驗，兩半合成一個 PR（開之前請 sca-center 用私有檔本機驗）；D-043 接在後面；supplier-normalize（8a960c0）等 M2；公開樣本在第二台要照各分支 firmware.yml 重新下載
  - C3（第二台）：wp2/watch-m2 等 M2 後接 mirrors.sh 開 PR；wp2/art14（e66f499）等 M7 的銷售市場欄位，M8 再開；wp5/gitlab（M5）等 M2 後核對範本指令再開
  - C4（第二台）：wp7/adapters 三平台重跑中（d31c872），標準答案依結果重訂後驗證；M6 PR 草稿已備
- 下一步（新 C0 接手後）：
  1. 等 C1 開 M2 PR → **C0 另派獨立驗證代理**（不附 C1 的結論）→ 兩份驗證都通過、CI 綠 → `gh pr merge --squash --match-head-commit <SHA> --author-email 287638252+evil88332115-png@users.noreply.github.com`
  2. M2 合併後：問使用者何時打第一個正式 tag（例如 `orin-nano-demo/v39.2.1-demo1`）；開 `wp0/docs-batch-4` 的 PR；通知 C2／C3／C4 併 main 後各自開 PR
  3. C2 的 D-042 PR 開出前，請 sca-center 對話用私有檔在本機驗（結果不回 repo）
  4. 監控 real Issue：C3 修完 F1–F3（已在 wp2/watch-m2）→ M2 合併 → 手動 baseline → 排程 dry_run 一天 → C3 回報會開哪些 Issue → C0 才設 repo 變數 `WATCH_REAL_ISSUES=on`
  5. 排 M7：A1–A4、C1（D-033）＋D-035 依據類型＋D-036 逐顆核心＋D-038 交付報告說明（adapter-gaps #16）＋D-039 可利用性分層＋D-044 非發行版核心改用 CNA 合併＋new-project 不帶範本值（config、vex-rules）＋adapter-gaps #7、#20、#22、#23
  6. M7 之後：D-046 新版本加入逐步自動化（先 Jetson／C1，再 C4 其他平台、C2 BIOS、C3 監控偵測；附手動步驟手冊）
- 給 PM／法務的待決定：VEX 發行閘門要不要分層（D-030）；附件 III／IV 分類、CVD 政策內容、單一聯絡窗口（D-032）；第 14 條期間計算（1182/71，C3 的 ART14.md）
- 卡住／等決定：無。D-045 使用者已確認；五個對話都在第二台時的代理上限，使用者授權**新 C0 搬過去後依那台實際負載調整**（D-041 的整台合計 8，調整前沿用；調整後寫進 DECISIONS 並通知 C1–C4）
- 第二台上要先做的事（詳見 `wp0/docs-batch-4` 的 docs/HANDOFF.md「在第二台電腦（WSL2）接手」）：
  1. `~/.config/dumpling/local.env` 與 `forbidden.txt` 已在那台（C4 確認），變數 REPO_MAIN、AGENT_TMP、PUBLIC_IMAGES、SCA_CENTER、HEAVY_LOCK 都有
  2. 主 checkout `$REPO_MAIN`（C4 回報為 `$HOME/dumpling`）在 main、工作樹乾淨，C3／C4 只用 worktree，**直接當 C0 的主 checkout**；先 `git -C "$REPO_MAIN" pull --ff-only`（落後 origin/main）
  3. 確認 `.git/hooks/pre-push` 存在、`git config user.email` 是 noreply（D-011）
  4. `$SCA_CENTER` 有 25fa89a，但 checkout 停在別的分支：取檔一律 `git -C "$SCA_CENTER" show 25fa89a:<路徑>`，不要依賴目前分支
  5. `gh auth status`：同一帳號（C4 確認）
  6. tmux 每個對話一個 window，對話名稱 C0–C4；C1、C2 的新 worktree 照 `$AGENT_TMP/dumpling-wt-<對話>-<主題>` 從推送的分支開
  7. 可清掉的舊 worktree：wt-c4-cra-survey（已併進 #15），由 C4 自己清
  8. 新對話建議在 WSL 裡從 `$REPO_MAIN`（C0）或自己的 worktree 啟動 Claude Code，不要從 Windows 的 C: 啟動後在那裡 clone（C3 提醒）；`$AGENT_TMP` 是 `$HOME/dumpling-agent-tmp`，`HEAVY_LOCK` 是 `$AGENT_TMP/dumpling-heavy.lock`
- 主要主機上的 C0–C2、worktree、repo：使用者確認第二台接上前不刪除、不關閉
<!-- END C0 -->

<!-- BEGIN C1 -->
## C1 流程核心（WP1＋WP6）

> **D-045：C1 搬到第二台電腦（2026-11-13）。** 這一節寫到新對話不用問就能接手；路徑一律用 `local.env` 的變數（`$REPO_MAIN`、`$AGENT_TMP`、`$SCA_CENTER`、`$HEAVY_LOCK`）。
> 第一台的 worktree 與暫存在使用者確認第二台接上之前不刪。

- 目前在做：**M2 收尾**（PLAN「里程碑」M2：打 tag 後 Jetson 版本全程跑通、產出 Release；含平台介面與開案範本、依層分開）。M2 的程式與文件都做完了，**正在跑最後一輪驗收 run**。M1 已合併（PR #9）
- 分支與 commit：
  - **`wp1/m2`＝f11bfdb**（已推）：M2 整合分支，含 J、P、L、K、KS 各軌與之後的修正；base 是 main 26a6377。本機完整測試（`tests/run.sh`）在 61d7c6f＋f11bfdb 上 10 組全部 OK
  - `wp1/m2-pr-draft`＝d3efdc8（已推，**不合併**）：`pr-draft/` 放 PR 說明草稿（head.md、mid.md 凍結例外、datasrc.md 資料來源）與逐檔對照表腳本 `m2table.py`（用法見該分支的 README）；開完 PR 後刪掉這個分支
  - `wp1/m2-kscope`＝b671488：KS 軌，已併入 wp1/m2（ac8cd5c），不用再動
  - 其他 M2 子分支（m2-layers、m2-platform、m2-jetson、m2-kernels*、m2-spike）都已併入或不合併，不用再動
- **正在跑的 GitHub Actions（都在 f11bfdb；第二台的 C1 接著看結果）**：
  - release.yml `orin-nano-demo/v39.2.0-demo1`：run **43399785656**（從新的 build；手動觸發只建 draft；約 75–90 分鐘）
  - release.yml `orin-nano-demo/v39.2.1-demo1`：run **43399800268**
  - tests.yml：run **43399813005**
  - 查：`gh run view <id> -R evil88332115-png/dumpling --json status,conclusion`；kernel-cve 鏡像連不上 git.kernel.org（間歇）而失敗時，重跑那個 run
  - 前一輪 be36327 的兩個 release run（43394028388、43394040313）是我取消的（C0 決定改 vex-rules 後要重訂標準答案）；那輪 tests 43394051461 綠燈
- 本機背景工作：沒有（完整測試已跑完；代理都已結束）
- **下一步（照順序）**：
  1. 兩個 release run 綠燈後，檢查兩份 draft（`gh release view/download orin-nano-demo/<版本>`）：附件 20 個（每份報告 zip／SBOM／VEX／漏洞清單／P1 判斷表 ×3＋layers.json、build-record、scan-summary、kernel-versions、release-meta）；`python3.10 -I pipeline/check-expected.py tests/expected/orin-nano-demo/<版本>.json scan-summary-*.json` 24 項（scan.sh 已在 CI 比對，失敗會讓 run 失敗）；
     release-meta 的 report_status／release_gate（預期 GAP，NVD 沒開）、pipeline_result OK；-os 報告包 `報告/內部存檔/scan-status.tsv` 的 C-kernel-cve-list／config／module-map 是 NOT_RUN「不適用…核心在 orin-nano-demo-bsp 報告判定」；-bsp 的 C-kernel-coverage 仍 OK（Jetson 不是 off-series）；scan-summary 的 `own_software` 是 GAP；報告 summary.json 的 documents.user-information 不是 OK；
     上游被修改的檔案 v39.2.1＝1（inet_connection_sock.c）、v39.2.0＝0；build_record_status 與 kernel_boot OK；兩版 diff 合理（上一輪 bsp +33／−22 列、只有元件版本變動）。
     **vex-rules 拿掉 R1～R5 之後 accepted 會變少、P1 可能變**：記下前後數字（上一輪 9f1d2f0：bsp p1_rows 10、accepted 2990），bsp.p1_rows 範圍 1–40 不符就依實際值重訂並寫理由
  2. 請一個**新的**獨立驗證代理（Sonnet、high，只給程式與 draft，不給結論）驗這一輪的 draft 與 61d7c6f、f11bfdb 的改動；前兩輪驗證報告的結論已處理（見下面「驗證」）
  3. 併最新 main（`git fetch && git merge origin/main`；不 rebase、不 force-push）→ 本機完整測試 → 推
  4. 開 M2 PR（D-020 一個 PR，C0 合併）：說明用 `wp1/m2-pr-draft` 的草稿；`m2table.py` 在併 main 之後重新產生逐檔對照表；補「驗收 run」（上面三個 run 的結果）與「驗證」（第三輪的留言連結：把驗證報告貼成 PR 留言）；最後一行 `🤖 Generated with [Claude Code](https://claude.com/claude-code)`
  5. 通知 C0（C0 會另派自己的驗證代理，兩份都過才合併；正式 tag 由 C0 問使用者）。刪掉這輪的 draft Release 與 `wp1/m2-pr-draft`
- 驗證（這輪之前）：
  - 第一輪（7dd351c）：5／6 PASS、第 6 項附缺口；應修 3 項（間歇性測試、scan.platform_arg／rootfs 沒人讀、文件兩處）都已修，建議 6、9、10 已修，其餘寫進 `docs/JETSON.md` 第 7 節已知限制
  - 第二輪（be36327）：8／9 PASS、1 項 FAIL（小）；應修 2 項（-bsp 指向自己、沒有 scan 區塊時沒檢查 platform_arg）與建議 3–8 都在 61d7c6f 修了；draft 沒驗到（run 當時沒跑完）
- 凍結例外（D-036 之後吸收進 M2 的契約修改，PR 說明 `mid.md` 有表）：scan.tools；kernel-cve 鏡像 cache 與退回；kernel-versions.json schema /2 與 Release 附件；platform_params.kernel_upstream_version；release-meta 的 report_status／release_gate／reports／kernel_versions（result 改名 pipeline_result）；scan_plan 用 0x1F 分隔與 collect 同後綴取後面那次；
  分層報告的核心不適用（`--kernel-in-other-report`，只給 -os）與核心不在發行版序列上的防護（kernelcheck 四條 OR 規則、`tools/pilot/lib/data/distro-kernel-sources.json`、`platform_params.kernel_not_distro`／platform.yml `scan.kernel_not_distro`；D-044）；沒宣告自有軟體 → B-own-software GAP（`sbom.own_software_none_reason`；scan.json `own_software`）；scan.json p1_rows 依 layer_todo；scan.platform_arg 傳到工具（`DUMPLING_SCAN_PLATFORM_ARG`）；
  orin-nano-demo 的 config.json 只留必填、vex-rules.json 只留 K1／K2／U1（C0 決定）
- M7 待辦（M2 合併後；判斷邏輯一起驗證）：D-035 排除依據類型；D-036 逐顆核心判定與合併；D-038 出貨的 /boot/config-* 優先（C4 缺口 23）；D-039 核心可利用性三層判斷（從 sca-center 同步，PROVENANCE 更新來源 commit）與精靈以掃描版本覆寫 version／identification；
  D-044 真正的修法：上游版本對核心 CNA、cra_report `kernel_cna_rows` 補 Grype 沒有的 CVE、「核心覆蓋 OK」的判斷條件（C4 缺口 22）；new-project.sh 不帶範本值（config.json、vex-rules.json；同 D-033 的文件骨架）；C4 缺口 7（OMV 原始碼相依依 dumpling:origin=source 歸層）、20（x86 映像的分割區訊息）；sbx-stubs 測試殘留
- M2 範圍已凍結（D-036）：之後的缺口沒擋住 C4 就排到 M7
- 對外約定（給 C4，已通知）：分層重跑只對 -os 給 `--kernel-in-other-report <專案>-bsp`（-bsp 給了 sca-scan 以 exit 64 拒絕）；scan 腳本用 `DUMPLING_SCAN_PLATFORM_ARG`；platform_arg 只能是 jetson／raspberrypi／rockchip／generic，scan.rootfs 只能是 rootfs；
  標準答案的 Jetson 驗收項目（build_record_status、kernel_boot、upstream_source.modified）只對 platform: jetson 的專案要求（6a87c15）
- 工作習慣（對話記憶不跨機器）：推上去的 commit 永久公開，內部原值連暫時都不能進 commit；推送前 `ci/public-check.sh --rev HEAD --private ~/.config/dumpling/forbidden.txt`；完整測試 `source ~/.config/dumpling/local.env && flock "$HEAVY_LOCK" env PYTHON=python3.12 tests/run.sh`（venv 不要放進 PATH）；
  tools/ 的 pytest 要從 repo 根目錄給資料夾（`python -m pytest tools/cra -k …`，`tools/cra/tests/conftest.py` 設路徑；給單一檔案路徑會 import 失敗）；tests/ 底下的 unittest 用 `python3.10 tests/<檔>.py`；改 `tools/` 的檔要在 PROVENANCE 那一列補 M2 的說明（`ci/provenance-check.sh`）；
  STATUS 用 `ci/status-update.sh C1 <檔>`（timeout 給 280 秒，150 秒曾逾時）；代理：Sonnet，medium 或 high（不可信的解析與判斷用 high），寫程式與驗證分開，最多 2 個寫程式＋1 個驗證
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

> **交接狀態（2026-11-13，D-045 搬到第二台 WSL2）**：這台的 C2 工作已停在下面描述的位置。沒有代理在跑，沒有本機背景工作，也沒有進行中的 GitHub Actions。三條分支都已 commit＋push（沒有 force-push）。這台的 worktree 在使用者確認前不要刪。

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
1. **D-042 AMD**：C0 已決定（**D-047**，在 wp0/docs-batch-4），照這兩點修（派一個寫程式的代理），改完和 ebac3e9 的改動一起複驗：
   - (a) **歧義規則改窄，但要有校驗佐證**：同一位置被兩種基底讀到時，只有一種讀法的目錄通過自身的結構與校驗（目錄 checksum、條目範圍都在映像內等），就採用那一種的條目；另一種只列出來，並附上它沒通過的證據。兩種都通過而且內容衝突，或兩種都不通過 → 維持 GAP。（我的補充：子目錄要沿用被採用那一讀法的基底；測試要涵蓋「一邊 checksum 壞」「兩邊都過且內容不同」「兩邊都壞」，以及處理順序反過來結果相同；真樣本 B550M、B650M 重跑，報 SBOM 元件數的變化。）
   - (b) **拿掉 `sys._getframe`**（amd_psp.py:746、:860 附近）：原始位元組裡只要有 AGESA 標記不在走訪範圍內，就標「搜尋不完整」（complete=False）。需要精確結果的話，M7 再請 C1 提供正式回呼介面，現在不跟 C1 談
   - 之後派驗證代理複驗 → 通過後：
   - 把 `origin/wp3/csme-new` 併進 `wp3/amd-psp`。會衝突的有 `docs/PROVENANCE.md`、`tests/run.d/c2-x86-firmware.sh`（兩邊都改了最後的測試清單），x86_firmware.py 兩邊改的是不同段落
   - 併 origin/main（D-021：有衝突才併，開 PR 前確認只剩自己的改動）
   - 重跑 CI
   - **先通知 C0（sca-center 端要用私有檔在本機驗證）**，再開一個 PR，標題「[WP3] 擴充 AMD 平台／新世代 Intel CSME 的解析範圍」，PR 說明照公開資料規定寫
   - 驗證由 C0 派，C0 合併
2. **supplier-normalize**：等 C1 的 M2 合併進 main → 併 origin/main（確定只剩自己的改動）→ 重跑 CI → 開一個 PR → 驗證（C0 派）→ C0 合併。現況：沒有任何真樣本能到 OK（保守、符合原則，不放寬）
3. **D-043**（排在 D-042 之後）：韌體 SBOM 的公告比對，只用公開資料。順序是 (1) → (2)，每段完成通知 C0
   - (1) 自動比對：
     - NVIDIA vBIOS：用每日鏡像的 NVIDIA product-security CSAF 填 `tools/pilot/lib/nvidia-bulletins-gpu-firmware.json`，依 vBIOS 版本＋裝置 ID 判定受影響／已修補／NOT_ASSESSED
     - Intel 微碼：用 intel/Intel-Linux-Processor-Microcode-Data-Files 的 release notes（固定 tag／commit＋sha256）。SBOM 的 CPUID＋rev 比較舊時，列出中間的 INTEL-SA；讀不到 → GAP
     - Intel CSME：加 NVD CPE（converged_security_and_management_engine_firmware），並註明 NVD 資料不完整
   - (2) 規則表：比照 D-039，一個公告一筆（INTEL-SA、AMI-SA、AMD-SB），條件＝元件＋版本範圍，記出處、確認者（角色）、日期；結果只給建議，排除照 D-035 記 vendor-statement
   - (3) vendor-watch 由 C3 改，C2 不動
   - 產出：每份韌體 SBOM 都要有比對結果（受影響／不受影響／NOT_ASSESSED＋依據）並寫進報告；比不到的寫「資料庫沒有資料，以廠商公告為準」，不可以顯示成沒有漏洞
4. 代理規則：同時最多 3 個（寫程式最多 2 個、驗證 1 個，兩者分開）；Sonnet 5.5，effort 用 high（解析不可信資料、判定邏輯）。開代理前看 uptime，負載超過 6 不開新代理（D-005）。PR 的驗證由 C0 派，C2 只派 PR 前的預驗

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
  - `wp2/watch-m2` f204260（已併 main 26a6377；worktree `$AGENT_TMP/dumpling-wt-c3-m2`，從 #32 head 開）：F1 大小警告算 ATTENTION、7 天一次；F2 修剪過的群組再出現用 open_if_closed（`dumpling.pruned_keys`）；F3 Grype DB 過期與 L4T 對應 GAP／FAIL 擋第一次基準；F4 有 Release 卻沒有基準 → 只開「還沒有基準」提醒 Issue（plan.state=null，不寫狀態、不算監控 Issue）；F5 演練三輪都可建基準；F6／concurrency：group 依 ref、compute 用 actions: read 查上一次排程 run（cancelled／失敗／超過 36 小時 → 降級）、keepalive 印最近 3 次排程。PR 未開（等 M2 的 mirrors.sh）
  - `wp5/gitlab` b0079fc（worktree `$AGENT_TMP/dumpling-wt-c3-gitlab`）
- M8 B1（第 14 條通報，C0 交辦：等 M2 期間先做不需要 M7 欄位的部分）：分支 `wp2/art14`（worktree `$AGENT_TMP/dumpling-wt-c3-art14`，從 main 26a6377），只推分支、M8 才開 PR。條文已核對：EUR-Lex CELEX:32024R2847（OJ L 2024/2847, 20.11.2024）第 14(1)–(4) 條、第 71 條（第 14 條自 2026-09-11 適用）；期間的法定計算規則未核對 → 工具算保守值、交法務。銷售市場欄位等 C1 的 M7 → GAP
- 代理（上限 D-041：4 個，寫程式 3、驗證 1）：
  - 寫程式 B1 art14（Sonnet high）：完成。`wp2/art14` e66f499（177 個測試）。**已在 GitHub 實跑 action=drill 六步兩次全綠**（run 43369037768、43369266378；暫時的分支 push 觸發已拿掉）；實跑發現依標籤列 Issue 有索引延遲 → 演練步驟重試、countdown 跳過已關閉的。ART14.md 已加 1182/71 參考（未核對、採較早保守值）與 Bot 例外理由。目前沒有代理在跑
- CI：wp2/watch-m2 b1b236e：演練 43365208989 綠、tests 43365156856 綠（132 個 c3-watch 測試）、real＋dry_run 43366085628 綠（GAP）。main：real＋dry_run 43362385127 綠
- 防 60 天停用：**下次人工檢查日期：2026-12-13**（`gh workflow view watch.yml`）
- 下一步：
  - M2 合併 → `wp2/watch-m2` 併 origin/main → 每日監控改用 `pipeline/lib/mirrors.sh`（kernel-cve 沿用舊鏡像時，報告與 Issue 寫出那行 ATTENTION）＋release-meta 的 `report_status`（報告整體狀態）與 `release_gate`（發行閘門）寫進 Issue 內文與報告，欄位不存在填 NOT_RUN（名稱 C1 已定案：report_status、release_gate、pipeline_result；已做在 7caa0f2；**M2 合併後依 C1 實際格式收斂成只剩一種讀法**（2026-11-13 查 origin/wp1/m2、m2-jetson 還沒有這些欄位）：report_status 只留實際的形狀、拿掉舊名 `result` 與沒用到的格式，其他形狀一律 NOT_RUN）→ 演練／real dry_run → 開 PR → 驗證 → 合併
  - 之後：手動 `mode=real`＋`baseline=true` 建第一次真實基準 → 排程 dry_run 跑一天 → 回報「打開會開哪些 Issue」→ C0 設 WATCH_REAL_ISSUES=on
  - M5：M2 合併後核對 gitlab/.gitlab-ci.yml 的指令（T-01）→ 重跑 CI → 驗證 → 開 PR
- B1 art14 的待辦（M8）：等 M7 的銷售市場欄位再一起開 M8 PR；銷售市場接 M7 的 project.yml 欄位；GitLab 版（私密 Issue、email、SRP）只列在 docs/ART14.md 第 10 節，M5／M8 再做。已實測：github-actions[bot] 開的 Issue 是 author_association=NONE（#21），所以程式接受 Bot 作者是必要的
- 卡住／等決定：等 M2 合併
<!-- END C3 -->

<!-- BEGIN C4 -->
## C4 其他平台（WP7）

- 目前在做：M6。rock-5b-demo 標準答案定案（72 項，8c44f9e）；rpi-lite-demo 標準答案草稿 43 項（17349bb；核心比對先不釘：-os 退回 CNA 多 2700 列、epoch 讓 Grype 漏報約 2400 個核心 CVE，已回報 C0／C1；kernel_upstream_version 6.18.50 已加，34529cf）；ai-nas 標準答案草稿 60 項（894debd，依 dev run 43386797521；deb 322 個與 Debian 官方清單逐一相同）、驗證代理核對中；已把 Radxa 核心 deb 名稱與版本（6.1.84-8，沒有 epoch；原始碼套件 linux-upstream／linux-rk2410）寄給 C1（D-044）
- 分支／PR／commit：`wp7/adapters`（最後 commit 見 git log；已併入 origin/wp1/m2 a957f90 與 origin/wp1/m2-jetson）；`wp7/platform-samples`（868f064）；`wp7/cra-survey`（122042c，已併進 PR #15，PR #15 合併後刪除）；PR 都尚未開（M6 完成才開，D-020）
- 代理：驗證代理 1 個執行中（ai-nas 標準答案，只讀，Sonnet）；rock 三輪已完成
- CI：rock 定案依 43378104334；rpi 依 43380656858；ai-nas 43386797521 OK（scan 步驟 GAP：當時沒有標準答案）
- 已完成：`docs/platforms-research.md`；`platform-samples/` 四份清單；`docs/references/cra-github-survey.md`、`cra-plan-proposal.md`；三個 platform.yml（arch、AI NAS 用 generic）；三個示範專案（sources.yml 含 metadata 清單檔）；sbom_augment（原始磁區元件、D-034 U-Boot CPE、OMV 原始碼併入）；支援期資料表追加 11 筆（D-033）；63 項單元測試
- 下一步：看三個平台的結果；C1 的 D-036（--kernel-version）進來後再跑一次；標準答案逐項核對（官方 SBOM／manifest／.info）後由驗證代理獨立核對，PR 附核對紀錄；不擋路的缺口記在 docs/references/adapter-gaps.md；M6 完成開 PR
- 卡住／等決定：等 C1 的 D-044（--kernel-in-other-report、非發行版核心的 C-kernel-coverage、平台設定宣告欄位名稱）；缺口 20（x86 也叫 B-rockchip、EEPROM 訊息）、21（示範專案 CRA config 是範本虛構值，含 C1 的 orin-nano-demo）已回報 C0
<!-- END C4 -->
