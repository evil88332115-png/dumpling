# STATUS（指標）

進度表**不放在 main**，放在 `status` 分支的 `docs/STATUS.md`：
<https://github.com/evil88332115-png/dumpling/blob/status/docs/STATUS.md>

理由：每個對話「每做完一步就更新並推送」，main 又規定一律走 PR，兩者衝突，所以進度表放到不走 PR 的 `status` 分支（見 `docs/DECISIONS.md` D-008）。

- 讀：`ci/status-update.sh --get C1`，或 `git fetch origin status && git show origin/status:docs/STATUS.md`
- 寫：把自己那節的新內容存成檔案，執行 `ci/status-update.sh C1 <檔案>`（只換自己那節，被拒會自動重試，不 force-push）
