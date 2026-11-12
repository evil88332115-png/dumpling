# STATUS

每個對話一節，**每做完一步就更新並推送**（`ci/status-update.sh`，見 main 的 `docs/HANDOFF.md`）。只改自己那節，`<!-- BEGIN/END -->` 標記不要動。

最後更新：2026-11-12 08:23 -0500（C0）

<!-- BEGIN C0 -->
## C0 協調（WP0）

- 目前在做：看 PR、合併、驗收，回覆 C1–C4
- 分支／PR／commit：main a8509af（#11 文件批次 D-019～D-021 已合併；C2 的 #7、#8；WP0 的 #1–#5、#10）；沒有未推送的累積改動
- 代理：目前沒有 C0 代理在跑
- 代理總數（全部對話）：C1 寫程式 1（A）、C2 寫程式 2，約 3／上限 8
- CI：無進行中
- 下一步：等 C1 把 #9 轉成正式 M1 PR（附逐檔對照表與資料來源）→ C0 派獨立驗證代理 → 合併；等 C2 做到 M3 開一個 PR
- 設定：main 分支保護不再要求分支最新（D-021，使用者同意）；auto-merge 因帳號沒有驗證過的信箱而無法使用，改由 C0 背景等 CI 後合併
- 卡住／等決定：無
<!-- END C0 -->

<!-- BEGIN C1 -->
## C1 流程核心（WP1＋WP6）

- 目前在做：M1（PLAN「里程碑」M1）——工具複製＋PROVENANCE、臨時 DT＋上傳測試 SBOM；依 D-020（做完里程碑才開 PR）M1 完成後一個 PR
- 分支／PR／commit：
  - `wp1/m1-tools`：工具複製＋PROVENANCE＋`tests/run.d/c1-tools.sh`；PR #9（draft，M1 完成後轉正式）；代理 A 進行中，會把 `wp1/m1-dt` 併進來
  - `wp1/m1-dt`：臨時 DT（`pipeline/dt-ephemeral.sh`、`dt-compose.yaml`、`dt-verify.py`）＋測試 SBOM＋`dt-smoke.yml`；5df9d3b（ENISA 改選用、deb 下限 1）；PR #6 已關（D-020）
  - 來源：sca-center 25fa89a
- 代理：
  - 寫程式 A：工具清理複製（`wp1/m1-tools`），Sonnet 5.5／high，進行中；追加：併入 m1-dt、準備逐檔對照表與資料來源表、剔除從內部資料產生的測試資料
  - 寫程式 B：臨時 DT（`wp1/m1-dt`），Sonnet 5.5／medium，完成（dt-smoke run 43223829151 綠燈）
  - 驗證：尚未開（A 完成、sca-scan --sbom 實跑後開）
- CI：dt-smoke 重跑中（`gh run list --branch wp1/m1-dt --workflow dt-smoke.yml`）；之後一律 `gh workflow run <wf> --ref <分支>` 手動觸發
- 下一步：A 完成 → `gh workflow run dt-smoke.yml --ref wp1/m1-tools`（用 sca-scan --sbom 上傳）＋tests → 開驗證代理 → #9 轉正式 PR（附逐檔對照、資料來源表）→ 通知 C0
- 卡住／等決定：無（PR #8 已合併、D-018 規則已修）
<!-- END C1 -->

<!-- BEGIN C2 -->
## C2 韌體（WP3＋WP4）

- 目前在做：M3（BIOS、vBIOS 各至少一個樣本產出 SBOM 並進 DT）。依 D-020，做到 M3 才開**一個** PR；過程只推分支，CI 用 `gh workflow run` 手動觸發
- 已合併：PR #7（樣本清單＋下載核對）、PR #8（x86_firmware → CycloneDX），main 4700739
- 分支（最後整合成 `wp3/m3` 開一個 PR）：
  - `wp3/coreboot-cbfs`：CBFS（FMAP、LZMA／LZ4）、coreboot 版本／config、FSP、VBT、SELF payload 身分（worktree `$AGENT_TMP/dumpling-wt-c2-cbfs`）
  - `wp3/ami-pfat`：AMI PFAT 解封裝（NUC BIOS 讀 ME／微碼）＋ #7、#8 驗證建議（fetch 測試補強、run.d venv 快取）（worktree `$AGENT_TMP/dumpling-wt-c2-pfat`）
- M3 剩下要做的（等 C1 M1 合併）：
  - BIOS 成品端 UEFI 解開：用 `tools/cra/uefi_image.py`（D-016）
  - vBIOS：Intel GOP（要 uefi_image）／VBT／legacy VBIOS；獨立 vBIOS 用合成 option ROM；NVIDIA gpu-firmware 公告比對用 C1 的 `tools/pilot/lib/nvidia_bulletins.py`，沒對到標 NOT_ASSESSED
  - 上傳臨時 DT＋Grype（C1 的 DT 工具）；firmware workflow 對真實樣本的 expected 做 CI 驗收；供應商 SBOM 匯入
- 代理：
  - 代理 C（寫程式，Sonnet 5.5 high）：`wp3/coreboot-cbfs`，狀態：進行中
  - 代理 D（寫程式，Sonnet 5.5 high）：`wp3/ami-pfat`，狀態：進行中
  - （已完成：代理 A／B、PR #7 驗證代理；PR #8 由 C0 驗證）
- CI：無進行中
- 下一步：等代理 C、D 完成 → 我檢查並整合到 `wp3/m3`；C1 M1 合併後做 UEFI／GOP／DT 上傳；M3 完成開一個 PR、派驗證代理、通知 C0
- 卡住／等決定：UEFI 解開、GOP、DT 上傳、NVIDIA 公告比對都等 C1 M1（PR #9）。規則：不用 `gh pr update-branch`，一律 `git merge origin/main`；ASSESS_NOTES 維持英文（C0 同意）；D-021：合併前不必是最新分支，只有 PR 顯示衝突才 merge main
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

- 目前在做：尚未開始（開始條件：C1 的 M2，平台介面與開案範本完成）
- 分支／PR／commit：—
- 代理：無
- CI：無
- 下一步：等 M2
- 卡住／等決定：無
<!-- END C4 -->
