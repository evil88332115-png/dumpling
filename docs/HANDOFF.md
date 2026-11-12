# HANDOFF：中斷後重開的接手步驟

原則：**所有狀態都放在 repo 裡，不放在對話裡**。任何對話被中斷、或換一個新對話接手，只要照這份做就能接著做。

## 對話分工

| 對話 | 工作包 | 負責 |
|---|---|---|
| C0 協調 | WP0 | repo、docs、CI 骨架、分支保護；看 PR、派驗證代理、合併、驗收；統一問使用者要決定的事 |
| C1 流程核心 | WP1＋WP6 | 工具清理複製（PROVENANCE）、臨時 DT、Jetson 編譯＋掃描＋Release、依層分開、平台介面與開案範本、標準答案測試 |
| C2 韌體 | WP3＋WP4 | mini PC BIOS（含 GOP／VBT）、vBIOS |
| C3 監控＋GitLab | WP2＋WP5 | 每日監控、Issue 通知、廠商層級提醒；GitLab 搬移文件與範本 |
| C4 其他平台 | WP7 | Raspberry Pi、Rockchip、x86 NAS 轉接器與示範專案（M2 之後開始） |

## 重開時的固定步驟（每個對話都照做）

0. 載入本機路徑：`source ~/.config/dumpling/local.env`（提供 `$REPO_MAIN`、`$AGENT_TMP`、`$PUBLIC_IMAGES`、`$SCA_CENTER`、`$HEAVY_LOCK`；這份檔案不進 repo）。
1. 讀 `docs/PLAN.md` 自己負責的工作包。
2. 讀 `docs/DECISIONS.md`。
3. 讀 STATUS 自己那一節：`ci/status-update.sh --get C1`（換成自己的節名）。
4. 看 PR 和 CI 的現況：`gh pr list --state all --search "[WP1] in:title"`、`gh run list --limit 20`。
5. 檢查自己的 worktree（`git status`、`git log origin/main..`）；沒推送的東西先推送。
6. 從 STATUS 的「下一步」接著做。

## STATUS 怎麼寫

- STATUS 放在 `status` 分支（D-008），**每做完一步就更新並推送**，不是等里程碑才寫。
- 做法：`ci/status-update.sh --get C1 > "$AGENT_TMP/dumpling-tmp-c1/status.md"`，改完後 `ci/status-update.sh C1 "$AGENT_TMP/dumpling-tmp-c1/status.md"`。只換自己那節；別人同時推送時會自動重試；不 force-push。
- 每節固定欄位：
  - 目前在做哪一步（對應 PLAN 的哪一段）
  - 分支、PR 編號、最後一個 commit
  - 開出去的代理：每個代理一行（任務、分支、狀態：進行中／完成／中斷）
  - 正在跑的 CI（run 連結）或本機背景工作（指令、紀錄檔路徑）
  - 下一步
  - 卡住的地方、等誰決定

## 工作規則

### 位置
- 主 checkout `$REPO_MAIN` 只給 C0 用，固定在 `main`，其他對話不要在那裡切分支。
- 每個對話用自己的 worktree：`git -C "$REPO_MAIN" fetch origin && git -C "$REPO_MAIN" worktree add "$AGENT_TMP/dumpling-wt-c1-<主題>" -b wp1/<主題> origin/main`。
- 暫存放 `$AGENT_TMP/dumpling-tmp-<對話>-<主題>/`，**不放 `/tmp`**（系統碟很小）。跑任何工具或 pytest 前先：
  `export TMPDIR="$AGENT_TMP/dumpling-tmp-c1/tmp"; mkdir -p "$TMPDIR"`，pytest 加 `--basetemp="$AGENT_TMP/dumpling-tmp-c1/pytest"`。用完刪掉。
- 本機重工作（完整測試、Docker、大檔解壓）一律 `flock "$HEAVY_LOCK" <指令>` 排隊，一次只跑一個。代理平常只跑跟自己改動有關的測試，完整測試交給 GitHub CI。

### Git 與 PR
- 分支 `wpN/<主題>`，PR 標題前綴 `[WPn]`。推送一律開分支、發 PR；不 force-push；版本固定。
- commit 信箱已設成 GitHub noreply（D-011，repo config，worktree 共用）。不要改。
- commit 訊息結尾加 `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`；PR 說明結尾加 `🤖 Generated with [Claude Code](https://claude.com/claude-code)`。
- **pre-push hook**：`$REPO_MAIN/.git/hooks/pre-push`（worktree 共用）會在推送前跑 `ci/public-check.sh`，並加上本機禁用字清單 `~/.config/dumpling/forbidden.txt`。被擋就改內容，**不要用 `--no-verify`**。hook 不見了就重裝：`cp ci/pre-push.hook "$REPO_MAIN/.git/hooks/pre-push"`。
- 合併條件（D-010）：CI 的 `public-check`、`unit-tests` 綠燈＋分支是最新（`gh pr update-branch <PR>`）＋獨立驗證代理在 PR 留言「驗證：通過」。合併由 C0 做（squash），**一定要指定作者信箱**：`gh pr merge <PR> --squash --author-email 287638252+evil88332115-png@users.noreply.github.com`。不要在網頁按合併：網頁合併會把帳號主信箱寫成 commit 作者（D-013）。

### 公開資料
- 只用公開 BSP、公開 BIOS／vBIOS 檔；不放任何公司資料、內部 IP、主機名、本機路徑、個人信箱。
- 二進位檔不進 git；CI 從官方網址下載並核對固定 sha256。
- 下載的檔案一律當不可信資料：只解開、不執行，Python 用 `-I`，拒絕 symlink／裝置檔。
- 缺資料、沒跑、過期一律標 GAP、NOT_RUN、NOT_ASSESSED；不寫「安全」、不顯示整體 PASS；不猜版本。

### 代理
- 每個對話（C0–C4）可以自己開 Sonnet 5.5 代理，同時最多 3 個：最多 2 個寫程式（做彼此不相關的部分）、1 個驗證；寫程式和驗證的代理一律分開。全部對話合計最多 8 個。代理本身不再開代理。
- 開代理前看 `uptime`：負載超過 6 先不開。開了就寫進 STATUS 自己那節。
- 代理的工作不能只存在代理裡：一開始就開分支、儘早推 WIP commit、開 draft PR。代理中斷了，新的代理從分支和 STATUS 接手。
- 驗證代理的結論寫在 PR 留言（開頭「驗證：通過」或「驗證：不通過」）。

### 長時間工作
- 交給 GitHub Actions：對話中斷不影響已經在跑的 workflow，重開後用 `gh run list` 看結果。
- 本機背景工作要把指令和紀錄檔路徑寫進 STATUS。

### 溝通
- 要交接、里程碑完成、需要決定時，用跨對話訊息通知 C0（`ListAgents` 找到 C0，再 `SendMessage`）。
- 需要使用者決定的事，一律由 C0 統一問；決定一律寫進 `docs/DECISIONS.md`（日期、誰決定、內容、理由）。
- 所有回覆用繁體中文。

## 完成定義

每個工作包的完成定義在 `docs/PLAN.md` 的「驗證（驗收方式）」與「里程碑」，不靠對話記得做到哪。
