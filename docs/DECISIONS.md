# 決定紀錄

格式：編號、日期、誰決定、內容、理由。對話裡講過、沒寫進這裡的不算數。新的決定加在最下面，改舊決定要另開一筆並註明取代哪一筆。

| 編號 | 日期 | 誰決定 | 內容 | 理由 |
|---|---|---|---|---|
| D-001 | 2026-11-12 | 使用者（規劃預設值） | 工具程式碼從 sca-center 挑檔清理後複製進來；不帶 git 歷史、`tests/results/`、`CLAUDE.md`、`AGENTS.md`、`tasks/`；每個檔案在 `docs/PROVENANCE.md` 記來源 commit | 公開 repo 不能帶公司資料與歷史 |
| D-002 | 2026-11-12 | 使用者（規劃預設值） | CI 從公開原始碼編核心與樹外模組，建置紀錄由 CI 產生；UEFI 先用 BSP 內建成品，標「UEFI 未自編」 | 避免自編紀錄被拒；UEFI 自編之後再補 |
| D-003 | 2026-11-12 | 使用者 | 授權 Apache-2.0；repo `evil88332115-png/dumpling` 設為公開，由 C0 建立 | 使用者已同意公開 |
| D-004 | 2026-11-12 | 使用者 | 範圍是 Jetson BSP、mini PC BIOS 與 vBIOS、顯示卡 vBIOS；**不含顯示卡驅動程式**（需求裡的 GPU binary 指 vBIOS） | 使用者更正 |
| D-005 | 2026-11-12 | 使用者 | 每個對話同時最多 3 個 Sonnet 5.5 代理（最多 2 個寫程式、1 個驗證，寫程式與驗證分開），全部對話合計最多 8 個；代理不再開代理；主機負載（`uptime`）超過 6 先暫停開新代理 | 主機只有 4 核 |
| D-006 | 2026-11-12 | 使用者（C0 開場指令） | 對話有 C0–C4 五個，STATUS 分 C0–C4 五節（規劃原稿寫 C0–C3，以此為準） | C4（其他平台）也要有進度欄 |
| D-007 | 2026-11-12 | 使用者＋C0 | `docs/PLAN.md` 是規劃原稿的公開版：內部產品代號、內部實測數字、本機路徑都拿掉或換成變數（`$REPO_MAIN`、`$AGENT_TMP`、`$PUBLIC_IMAGES`、`$HEAVY_LOCK`），變數值在本機 `~/.config/dumpling/local.env`，不進 repo | 硬性限制 1：不用任何公司資料；公開檢查不允許本機路徑 |
| D-008 | 2026-11-12 | C0 | 進度表放在 `status` 分支（只有 `docs/STATUS.md`），用 `ci/status-update.sh` 更新，不走 PR；main 的 `docs/STATUS.md` 只放指標。`status` 分支禁止 force-push 與刪除 | 「每做完一步就推送」與「main 一律走 PR」衝突；分支分開可避免多個對話的 PR 互相衝突 |
| D-009 | 2026-11-12 | C0 | 禁用字檢查分兩層：(1) 通用規則（本機路徑、私有 IP、非 noreply 信箱、commit 信箱）公開在 `ci/public-patterns.txt`、`ci/public-check.sh`，CI 的 `public-check` job 每個 PR 都跑；(2) 公司產品代號、主機名等「名單本身就不能公開」的字只放本機 `~/.config/dumpling/forbidden.txt`，由本機 pre-push hook 檢查，**不上傳 GitHub（也不放 secrets）** | 把產品代號寫進公開 repo 等於公開；放 secrets 也是把公司資料送到外部服務 |
| D-010 | 2026-11-12 | C0 | main 分支保護：必須走 PR；必須 `public-check`、`unit-tests` 綠燈且分支是最新；禁止 force-push 與刪除；管理員也適用。必要核准數設 0，因為所有對話共用同一個 GitHub 帳號，不能核准自己的 PR；改由**獨立驗證代理**在 PR 留言「驗證：通過／不通過」，C0 看過留言與 CI 才合併。只允許 squash 合併，合併後刪分支 | 硬性限制 6；GitHub 不允許作者核准自己的 PR |
| D-011 | 2026-11-12 | C0 | commit 一律用 GitHub noreply 信箱（`287638252+evil88332115-png@users.noreply.github.com`，已設在 repo 的 git config，worktree 共用） | 公開 repo 的 commit 信箱是公開的 |
| D-012 | 2026-11-12 | C0 | Actions 預設 `GITHUB_TOKEN` 權限唯讀，需要寫入的 job 自己宣告；第三方 action 一律用 commit SHA 固定版本；外部人士的 fork PR 一律要核准才跑 CI | 公開 repo，任何人都能開 PR |
| D-013 | 2026-11-12 | 使用者＋C0 | 合併 PR 一律用 `gh pr merge --squash --author-email <noreply 信箱>`，不在網頁合併。第一次建立的 repo 因網頁端 squash 合併把個人信箱寫進 commit 作者，已由使用者決定刪 repo 重建（舊 PR #1 隨之消失） | GitHub 合併 commit 的作者預設是帳號主信箱；force-push 改寫後舊 commit 仍可從 PR 頁面連到，只有重建能清乾淨 |
| D-014 | 2026-11-12 | 使用者 | C1–C4 的 PR 以「一個可以獨立運作、可以測試的功能」為單位（例如 M1 的「工具複製＋臨時 DT＋上傳測試 SBOM」一個 PR）；不要一個檔案一個 PR，也不要把整個里程碑塞成一個 PR | 每個 PR 都能單獨驗證與合併；太碎難以測試，太大難以審查 |
| D-015 | 2026-11-12 | C0（回覆 C2） | 工具複製的分工與結構：(1) 目錄對應：sca-center `scripts/<子目錄>/<檔名>` → `tools/<子目錄>/<檔名>`，測試放 `tools/<子目錄>/tests/`（C1、C2 都照這個）；(2) 只有韌體用的檔案由 C2 自己複製、放在 C2 的 PR：`x86_firmware.py`、`test_x86_firmware.py`、`data/fw-manifest-template.csv`、BIOS 試掃原型（CBFS／FSP 解析）；(3) Jetson 也會用到的 `uefi_image.py`、`uefi_source.py`、`uefi_bundled.py`、`uefi_dsc.py`、`tee_*.py` 歸 C1；C2 要先用就通知 C0 協調，不要兩邊各複製一份；(4) 共用檔由 C0 先建骨架：`tests/run.sh` 依序執行 `tests/run.d/*.sh`，各工作包只加自己的 run.d 腳本；`docs/PROVENANCE.md` 分「C1 工具」「C2 韌體工具」兩節，各改各的 | C1 尚未開工，先定結構避免兩邊重做；共用檔拆成各自的區塊，避免 PR 衝突 |
| D-016 | 2026-11-12 | C0（回覆 C1、C2） | 補充 D-015 第 (3) 點：`uefi_image.py`（FV／FFS／LZMA 解析）＋`test_uefi_image.py` 仍歸 C1，**放進 C1 的 M1 工具複製 PR**；C2 的 BIOS 成品端解析（PR 2b）等 M1 合併後直接用它，**不另外**把試掃原型的 `fv_walk.py` 正式化成平行的解析器；缺的能力（例如 AMI 映像的巢狀壓縮）以 PR 擴充 `tools/cra/uefi_image.py`，改之前通知 C0。另外：本機的 sca-center checkout 不在 origin/main，從 sca-center 取檔一律用 `git -C "$SCA_CENTER" show 25fa89a:<路徑>`（PROVENANCE 記 25fa89a） | 成品端 UEFI 解析只維持一套，避免結果不一致；C1 已開工 M1，等它最省事 |
| D-017 | 2026-11-12 | C0（回覆 C1、C2） | 測試共用檔指定一個負責方，不用「誰先合併誰建」：`tools/cra/tests/conftest.py`（最小版；`DUMPLING_REQUIRE_TEST_DATA=1` 時 skip 也算失敗）、`tools/cra/tests/cdx_schema.py`（CycloneDX schema 驗證，從 sca-center `test_firmware_bom.py` 抽出）、`tools/cra/tests/data/cyclonedx-1.6.1/` 都由 **C2 的 PR 2a** 建立；C1 的分支**不新增**這幾個檔案，C1 的 `test_firmware_bom.py` 改成 import `cdx_schema.py`，不保留自己的副本。C1 若在 PR 2a 合併前就需要，先通知 C0，C0 優先合併 PR 2a 或讓 C1 rebase 到 PR 2a 的分支。之後任何人要改這幾個檔，以 PR 修改並通知 C0 | 兩條分支同時新增同一個檔會 add/add 衝突；schema 驗證只維持一份 |
