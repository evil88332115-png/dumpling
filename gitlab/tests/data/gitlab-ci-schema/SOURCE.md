# gitlab-ci-schema：來源紀錄

| 項目 | 內容 |
|---|---|
| 檔案 | `ci.json`（GitLab 官方 CI 設定檔的 JSON schema，draft-07），原檔一個位元組都沒改 |
| 來源專案 | gitlab-org/gitlab |
| 來源路徑 | `app/assets/javascripts/editor/schema/ci.json`（不在 `ee/`、`jh/`、`doc/` 底下） |
| commit | `28aa2bf90771a11ecc2f86525bc8a70a49c4d810`（2026-10-18，"Allow empty tags array in CI schema"） |
| 取檔網址 | https://gitlab.com/gitlab-org/gitlab/-/raw/28aa2bf90771a11ecc2f86525bc8a70a49c4d810/app/assets/javascripts/editor/schema/ci.json |
| sha256 | `1c6eeb7d3a34c39996afbfe1ade220480eb05bbeae674e86d3c745dfeeded7fd`（下載後核對過才放進 repo） |
| 取檔日期 | 2026-11-13 |
| 授權 | 兩種並存：MIT Expat（GitLab Inc.，上游根目錄 LICENSE）與 Apache-2.0（Mads Kristensen，同資料夾的上游 NOTICE）。條款原文與連結見 `LICENSE.md`、`NOTICE` |
| 來源推測 | 推測源自 SchemaStore 的 gitlab-ci schema（**未證實**；上游 NOTICE 沒有指名檔案） |

`NOTICE` 是同一 commit、同一上游資料夾（`app/assets/javascripts/editor/schema/NOTICE`）的原文副本。

## 更新方式

只由人手動更新：`bash gitlab/fetch-ci-schema.sh [<新 commit>]` 下載到暫存資料夾並印出新舊 sha256，**不會覆蓋 repo 裡的檔**；
確認後手動換 `ci.json`、`NOTICE`，重新核對 `LICENSE.md` 的授權內容，同步改這個檔、`docs/PROVENANCE.md` 的「C3 GitLab 範本」一節、
`gitlab/fetch-ci-schema.sh` 與 `tests/run.d/c3-gitlab-schema.sh` 裡固定的 commit 與 sha256。

## 這份 schema 驗證的意義與限制

官方 schema 驗證通過，只代表 `.gitlab-ci.yml` 的**語法與欄位型別**符合這份 schema，**不保證範本在 GitLab 上一定跑得起來**
（schema 不管 runner 標籤、變數是否存在、`rules` 的邏輯、內部 GitLab 版本是否支援該語法等）。搬到 GitLab 後，要用該 GitLab 實例的 CI Lint 再檢查一次。
