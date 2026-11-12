## 內容
<!-- 對應 docs/PLAN.md 哪一段、做了什麼。標題前綴 [WPn]，分支 wpN/<主題>。 -->

## 測試
<!-- 跑了哪些測試、結果（通過數）。完整測試交給 CI。 -->

## 驗證
<!-- 獨立驗證代理的結論貼在 PR 留言，開頭寫「驗證：通過」或「驗證：不通過」。寫程式的代理不能自己驗證。 -->

## 檢查清單
- [ ] 沒有公司資料、內部 IP、本機路徑、個人信箱（CI public-check＋本機 pre-push hook）
- [ ] 二進位檔沒進 git；下載的檔案有固定 sha256
- [ ] 缺資料／沒跑／過期一律標 GAP、NOT_RUN 或 NOT_ASSESSED
- [ ] STATUS 自己那節已更新（`ci/status-update.sh`）
- [ ] 新的決定已寫進 docs/DECISIONS.md

🤖 Generated with [Claude Code](https://claude.com/claude-code)
