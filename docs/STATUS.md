# STATUS

每個對話一節，**每做完一步就更新並推送**（`ci/status-update.sh`，見 main 的 `docs/HANDOFF.md`）。只改自己那節，`<!-- BEGIN/END -->` 標記不要動。

最後更新：2026-11-12 08:17 -0500（C1）

<!-- BEGIN C0 -->
## C0 協調（WP0）

- 目前在做：看 PR、合併、驗收，回覆 C1–C4
- 分支／PR／commit：main 4700739（C2 的 PR #7 樣本清單、#8 BIOS／vBIOS→CycloneDX 已合併；WP0 的 #1–#5、#10 已合併）；本機累積分支 `wp0/docs-batch-1`（D-019＋HANDOFF 修正，還沒推，等累積成批再開 PR）
- 代理：PR #8 驗證代理已完成（通過，留言在 PR #8）；目前沒有 C0 代理在跑
- 代理總數（全部對話）：C1 寫程式 2、C2 寫程式約 2，約 4／上限 8
- CI：無進行中
- 下一步：等 C1 的 M1（A merge main 取得 D-017 共用檔 → 正式 PR）→ C0 派獨立驗證代理 → 合併 → M1；C2 接著做 PR 2b／vBIOS
- 規則提醒：更新 PR 分支用本機 `git merge origin/main`，不用 `gh pr update-branch`（已通知 C1、C2，D-019 待合併）
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

- 目前在做：B 段。已合併：PR #7（樣本清單＋下載核對）、PR #8（x86_firmware → CycloneDX），main 4700739。進行中：PR 2c（coreboot CBFS／FSP／VBT）、PR 3a（AMI PFAT 解封裝）
- 分支／PR／commit：
  - `wp3/coreboot-cbfs`（PR 2c，worktree `$AGENT_TMP/dumpling-wt-c2-cbfs`，PR 尚未開）
  - `wp3/ami-pfat`（PR 3a，從 main 4700739 開出，worktree `$AGENT_TMP/dumpling-wt-c2-pfat`，PR 尚未開）
- 預定 PR（D-014）：
  - ✅ #7 樣本清單＋下載核對；✅ #8 x86_firmware → CycloneDX（NOT_ASSESSED、GAP、CSME CPE）
  - 2c. `wp3/coreboot-cbfs`：CBFS（FMAP、LZMA／LZ4）、coreboot 版本／config、FSP、VBT、SELF payload 身分 → SBOM
  - 3a. `wp3/ami-pfat`：AMI PFAT 解封裝（Intel NUC BIOS 能讀 ME／微碼）；併入 #7、#8 驗證建議（fetch 測試補強、run.d venv 快取）
  - 2b. BIOS 成品端 UEFI 解開（D-016：等 C1 M1 合併後用 `tools/cra/uefi_image.py`）
  - 3b. `wp4/vbios`：Intel GOP（要 uefi_image）／VBT／legacy VBIOS、獨立 vBIOS（合成 option ROM）、NVIDIA gpu-firmware 公告比對 NOT_ASSESSED
  - 4. `wp3/firmware-dt`：firmware workflow 上傳臨時 DT＋Grype、真實樣本對 expected 的 CI 驗收、供應商 SBOM 匯入（等 C1 M1）
- 代理：
  - 代理 A（寫程式）：PR #7，完成；代理 B（寫程式）：PR #8，完成；PR #7 驗證代理：完成（通過）；PR #8 由 C0 驗證：通過
  - 代理 C（寫程式，Sonnet 5.5 high）：PR 2c，分支 `wp3/coreboot-cbfs`，狀態：進行中
  - 代理 D（寫程式，Sonnet 5.5 high）：PR 3a，分支 `wp3/ami-pfat`，狀態：進行中
- CI：無進行中
- 下一步：2c、3a 開 PR、綠燈後派驗證代理（一次一個）→ 通知 C0；C1 M1 合併後做 2b、3b
- 卡住／等決定：2b、3b 的 GOP 部分等 C1 M1（uefi_image.py）。規則提醒：不用 `gh pr update-branch`，一律 `git merge origin/main`
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
