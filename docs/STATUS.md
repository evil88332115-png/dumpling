# STATUS

每個對話一節，**每做完一步就更新並推送**（`ci/status-update.sh`，見 main 的 `docs/HANDOFF.md`）。只改自己那節，`<!-- BEGIN/END -->` 標記不要動。

最後更新：（尚未）

<!-- BEGIN C0 -->
## C0 協調（WP0）

- 目前在做：WP0 收尾（repo 已重建）
- 分支／PR／commit：main 6528412（重建後的第一個 commit）；status 分支
- 代理：無
- CI：確認 main 的 tests.yml
- 下一步：套 repo 設定與分支保護、確認 CI 綠燈、通知使用者開 C1
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

- 目前在做：尚未開始（開始條件：WP0 完成；上傳 DT 要等 C1 的 M1）
- 分支／PR／commit：—
- 代理：無
- CI：無
- 下一步：挑公開 BIOS／vBIOS 樣本（網址＋sha256＋授權），解析部分可先做
- 卡住／等決定：無
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
