# M2 PR 說明的草稿（不合併）

這個分支只放 C1 開 M2 PR 用的草稿，**不要合併**；開完 PR 後刪掉這個分支。

- `head.md`：PR 標題與「內容」
- `mid.md`：M2 期間吸收的契約修改（凍結例外）與 M7 待辦
- `datasrc.md`：M2 新增的資料檔與測試資料的來源
- `m2table.py`：D-020 的逐檔對照表（相對 origin/main；tools/ 依 PROVENANCE 比對 sca-center 25fa89a）。
  用法：`python3 -I pr-draft/m2table.py <wp1/m2 的 worktree> "$SCA_CENTER" > table.md`（先 `git fetch`，並在併最新 main 之後再產生）

PR 說明的順序：head.md → 驗收 run 與驗證（跑完後補）→ mid.md → 給 C0 的決定事項 → datasrc.md → table.md → 最後一行 `🤖 Generated with [Claude Code](https://claude.com/claude-code)`。
