# STATUS

每個對話一節，**每做完一步就更新並推送**（`ci/status-update.sh`，見 main 的 `docs/HANDOFF.md`）。只改自己那節，`<!-- BEGIN/END -->` 標記不要動。

最後更新：2026-11-12 08:36 -0500（C0）

<!-- BEGIN C0 -->
## C0 協調（WP0）

- 目前在做：看 PR、合併、驗收，回覆 C1–C4
- 分支／PR／commit：main a8509af（#11 文件批次 D-019～D-021 已合併；C2 的 #7、#8；WP0 的 #1–#5、#10）；沒有未推送的累積改動
- 代理：
  - 預審代理（Sonnet 5.5）：預審 wp1/m1-tools f9d0cee，狀態：完成（#9 留言：有必須修的項目——測試檔語法錯誤、scripts→tools 路徑沒改完、一處版本被改、5 處疑似內部實測資訊、缺少被引用的檔），已轉給 C1
- 代理總數（全部對話）：C1 寫程式 2＋驗證 1、C2 寫程式 2＋驗證 1，約 6／上限 8；C0 目前沒有代理在跑
- CI：無進行中
- 下一步：等 C1 把 #9 轉成正式 M1 PR（附逐檔對照表與資料來源）→ C0 派獨立驗證代理 → 合併；等 C2 做到 M3 開一個 PR
- 設定：main 分支保護不再要求分支最新（D-021，使用者同意）；auto-merge 因帳號沒有驗證過的信箱而無法使用，改由 C0 背景等 CI 後合併
- 卡住／等決定：無
<!-- END C0 -->

<!-- BEGIN C1 -->
## C1 流程核心（WP1＋WP6）

- 目前在做：M1（PLAN「里程碑」M1）——工具複製＋PROVENANCE、臨時 DT＋上傳測試 SBOM；D-020：M1 完成後一個 PR（#9 轉正式）
- 分支／PR／commit：
  - `wp1/m1-tools`：bd7fa1b（tools/ 全部初步清理完、PROVENANCE C1 節、`ci/provenance-check.sh`、`tests/run.d/c1-tools.sh`；已併入 `wp1/m1-dt`）；PR #9（draft）
  - `wp1/m1-tools-pilot`：從 bd7fa1b 開，pilot／demo／mirror／wizard／e2e 的收尾，做完由 C1 merge 回 `wp1/m1-tools`
  - `wp1/m1-dt`：62107c1（臨時 DT，已併入 m1-tools；PR #6 已關）
  - 來源：sca-center 25fa89a
- 代理：
  - 寫程式 A：`wp1/m1-tools`，範圍縮為 tools/cra、vexconv、sbomgate、provenance-check、c1-tools.sh、cra fixtures；Sonnet 5.5／high；進行中
  - 寫程式 P：`wp1/m1-tools-pilot`，tools/pilot、demo、mirror、wizard、e2e；修失敗測試、資料來源審查（內部資料產生的剔除）、sca-scan 缺 scio_prep 時 NOT_RUN、wizard 改用目前 HEAD 取工具、dt-smoke 用 `sca-scan --sbom` 上傳；Sonnet 5.5／high；進行中
  - 驗證 V1：`wp1/m1-dt`（62107c1）臨時 DT 部分；完成，**不通過**（PR #9 留言 issuecomment-6825077261）：dt-smoke.yml 的 `| tee` 沒有 pipefail，會吃掉 wait／sca-scan 的結束碼。已交給 P 修（加 `shell: bash`，並實證失敗會紅），另附 6 項建議（admin 密碼不放命令列、生態系不內插、down 的 rm 防護、讀回確認 NVD 關閉、409 舊結果、wait 措辭）；修完再驗
  - 寫程式 B（臨時 DT）：完成
  - C0 另派一個預審代理看 `wp1/m1-tools` 已推送內容（資料來源、清理、範圍），結論留 #9
- CI：手動觸發（`gh workflow run <wf> --ref <分支>`）；最近 dt-smoke（m1-dt）run 43225729729 綠燈
- 下一步：A、P 完成 → merge `wp1/m1-tools-pilot` 進 `wp1/m1-tools`、整合 PROVENANCE → tests＋dt-smoke 在 m1-tools 綠燈 → 驗證整個 M1 → #9 轉正式 PR（附逐檔對照、資料來源表）→ 通知 C0
- 卡住／等決定：無（V1 的問題修完需要重驗 DT 部分）
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
  - 預驗代理（驗證，Sonnet 5.5 high）：預驗 `wp3/coreboot-cbfs`（6c88ccc 起），結論記在這裡，狀態：進行中；`wp3/ami-pfat` 推送後接著預驗
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
