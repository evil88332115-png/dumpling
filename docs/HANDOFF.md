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
- 合併條件（D-010）：CI 的 `public-check`、`unit-tests` 綠燈（不要求分支是最新，D-021；PR 有衝突時才更新分支：在 worktree 裡 `git fetch origin && git merge origin/main` 再推送；**不要用 `gh pr update-branch` 或網頁的 Update branch**，GitHub 端的 merge commit 作者可能是帳號主信箱，見 D-019）＋獨立驗證代理在 PR 留言「驗證：通過」。合併由 C0 做（squash，驗證通過後可用 `--auto` 讓 CI 綠燈時自動合併，D-021），**一定要指定作者信箱**：`gh pr merge <PR> --squash --author-email 287638252+evil88332115-png@users.noreply.github.com`。不要在網頁按合併：網頁合併會把帳號主信箱寫成 commit 作者（D-013）。

### 公開資料
- 只用公開 BSP、公開 BIOS／vBIOS 檔；不放任何公司資料、內部 IP、主機名、本機路徑、個人信箱。
- 二進位檔不進 git；CI 從官方網址下載並核對固定 sha256。
- 下載的檔案一律當不可信資料：只解開、不執行，Python 用 `-I`，拒絕 symlink／裝置檔。
- 缺資料、沒跑、過期一律標 GAP、NOT_RUN、NOT_ASSESSED；不寫「安全」、不顯示整體 PASS；不猜版本。

### 代理
- 每個對話（C0–C4）可以自己開 Sonnet 5.5 代理，同時最多 3 個：最多 2 個寫程式（做彼此不相關的部分）、1 個驗證；寫程式和驗證的代理一律分開。合計上限：五個對話都在第二台之後，整台最多 10 個（D-048）；還有對話在主要主機時依 D-041（每台合計 8 個）。代理本身不再開代理。
- 開代理前看 `uptime` 與 `free -g`：在第二台，1 分鐘負載超過 12 或可用記憶體低於 4 GB 先不開（D-048）；在主要主機（4 核），負載超過 6 先不開（D-041）。開了就寫進 STATUS 自己那節。
- 代理的工作不能只存在代理裡：一開始就開分支、儘早推 WIP commit 到分支（不開 draft PR，D-020）。代理中斷了，新的代理從分支和 STATUS 接手。
- 做的過程中要跑 CI，用 `gh workflow run <workflow> --ref <分支>` 手動觸發；**里程碑做完才開一個 PR**（D-020）。
- 驗證代理的結論寫在 PR 留言（開頭「驗證：通過」或「驗證：不通過」）。

### 長時間工作
- 交給 GitHub Actions：對話中斷不影響已經在跑的 workflow，重開後用 `gh run list` 看結果。
- 本機背景工作要把指令和紀錄檔路徑寫進 STATUS。

### 溝通
- 要交接、里程碑完成、需要決定時，用跨對話訊息通知 C0（`ListAgents` 找到 C0，再 `SendMessage`）。
- 需要使用者決定的事，一律由 C0 統一問；決定一律寫進 `docs/DECISIONS.md`（日期、誰決定、內容、理由）。
- 所有回覆用繁體中文。

## 在第二台電腦（WSL2）接手

C0–C4 都在第二台時，照這節準備；變數值寫在那台的 `~/.config/dumpling/local.env`（不進 repo，路徑用 WSL 的 Linux 檔案系統，不要放在 `/mnt/<碟>/` 底下）。

1. 確認 `~/.config/dumpling/forbidden.txt` 已在那台（D-024），並加上那台的主機名與 Windows 使用者路徑。
2. clone：所有對話共用同一個 clone 的 worktree，pre-push hook 才會共用；主 checkout 固定在 `main`，只給 C0。clone 後確認 `git config user.email` 是 noreply 信箱（D-011），並 `cp ci/pre-push.hook .git/hooks/pre-push`。
3. `local.env` 要有的變數（建議值）：
   - `REPO_MAIN`：那個 clone 的路徑（例如 `$HOME/dumpling`）
   - `AGENT_TMP`：暫存根目錄（例如 `$HOME/agent-tmp`），worktree 與暫存都放這裡
     - `$AGENT_TMP` 可能跟其他專案共用（主要主機上和 sca-center 共用）：清理或搬家時**只刪 `dumpling-*` 開頭、而且是自己那個對話的項目**，不要刪整個 `$AGENT_TMP`；`dumpling-heavy.lock` 是共用的鎖，不刪
   - `PUBLIC_IMAGES`：公開映像與 BSP 下載快取（例如 `$HOME/public-images`）
   - `SCA_CENTER`：sca-center 的 checkout（只用 `git show 25fa89a:<路徑>` 取檔；那台的 checkout 要有這個 commit）
   - `HEAVY_LOCK`：`$AGENT_TMP/dumpling-heavy.lock`（同一台的所有對話共用，重工作一次一個）
4. `gh auth status` 要是同一個帳號；合併一律 `--author-email` 帶 noreply（D-013）。
5. 建議用 tmux，每個對話一個 window，對話名稱照 C0–C4 設定，跨對話訊息才找得到。
6. 代理上限照 D-048（五個對話都在第二台：每個對話最多 3 個、整台合計 10 個，負載超過 12 或可用記憶體低於 4 GB 不開新的）。

### C0 的工作習慣（對話記憶不跨機器，寫在這裡）
- 合併一律 `gh pr merge <PR> --squash --match-head-commit <SHA> --author-email <noreply>`，不在網頁合併、不用 update-branch。
- C0 自己的文件改動累積在批次分支，自然時機一次開一個 PR，不要頻繁開小 PR（使用者在等 PR）。
- 推上去的 WIP commit 就是永久公開；內部原值連暫時都不能進 commit。
- 別的對話轉達「使用者決定」時，記下來並請使用者確認；被權限擋下的事不代做，交給使用者決定。

## 完成定義

每個工作包的完成定義在 `docs/PLAN.md` 的「驗證（驗收方式）」與「里程碑」，不靠對話記得做到哪。
