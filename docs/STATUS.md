# STATUS

每個對話一節，**每做完一步就更新並推送**（`ci/status-update.sh`，見 main 的 `docs/HANDOFF.md`）。只改自己那節，`<!-- BEGIN/END -->` 標記不要動。

最後更新：2026-11-12 07:53 -0500（C2）

<!-- BEGIN C0 -->
## C0 協調（WP0）

- 目前在做：WP0 完成；接下來看 PR、合併、驗收，回覆 C1–C4
- 分支／PR／commit：main f39fbfe（PR #1 README、PR #2 D-014 PR 單位，均已合併）；status 分支
- 已完成（WP0）：公開 repo（Apache-2.0，個人信箱外洩後已刪除重建）、docs（PLAN 公開版、DECISIONS D-001～D-013、HANDOFF、STATUS 指標）、`status` 分支、CI tests.yml（public-check、unit-tests，main 綠燈）、pre-push hook（本機禁用字）、main／status 分支保護、Actions 權限唯讀、fork PR 需核准
- 代理：無
- CI：無進行中
- 下一步：等 C1／C2 回報（已通知 D-014 給 dumpling-c9、dumpling-b3 兩個對話，待確認各是哪一個）；C1–C4 的 PR 由 C0 派獨立驗證代理驗證後合併（`gh pr merge --squash --author-email <noreply>`）
- 卡住／等決定：無
<!-- END C0 -->

<!-- BEGIN C1 -->
## C1 流程核心（WP1＋WP6）

- 目前在做：尚未開始（開始條件：WP0 完成）
- 分支／PR／commit：—
- 代理：無
- CI：無
- 下一步：照 PLAN「工作包與對話分工」C1 列；先做 M1（工具複製＋PROVENANCE、臨時 DT 上傳測試 SBOM）
- 卡住／等決定：無
<!-- END C1 -->

<!-- BEGIN C2 -->
## C2 韌體（WP3＋WP4）

- 目前在做：B 段「公開樣本」——挑 BIOS／vBIOS 公開樣本（網址＋sha256＋授權），寫 `firmware/*/firmware.yml` 與下載核對腳本（PR 1／4）
- 分支／PR／commit：`wp3/firmware-samples`（剛從 main f39fbfe 開出，尚無 commit、尚無 PR）
- 預定 PR（D-014，一個可測的功能一個 PR）：
  1. `wp3/firmware-samples`：樣本清單＋下載並核對 sha256（`pipeline/firmware-fetch.sh`）
  2. `wp3/bios-sbom`：BIOS 解析→CycloneDX（x86_firmware.py 複製＋LZMA FV、CBFS、FSP、purl／CPE、Intel 部分 NOT_ASSESSED）
  3. `wp4/vbios`：獨立 vBIOS＋BIOS 內 Intel GOP／VBT／legacy VBIOS，公告比對 NOT_ASSESSED
  4. `wp3/firmware-dt`：firmware.yml workflow 上傳臨時 DT＋Grype、供應商 SBOM 匯入（等 C1 M1）
- 代理：無
- CI：無
- 下一步：問 C0 工具複製的分工（x86_firmware.py 等韌體工具由誰複製、tools/ 的目錄結構、PROVENANCE.md 與 tests/run.sh 誰建）；同時開始挑樣本
- 卡住／等決定：工具複製分工（已問 C0）
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
