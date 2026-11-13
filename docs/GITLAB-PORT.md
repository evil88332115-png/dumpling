# GITLAB-PORT：GitHub → 內部 GitLab 搬移對照與檢查清單（M5 第一版）

範圍：PLAN「F. 搬到 GitLab」。這份文件加上 `gitlab/`（`.gitlab-ci.yml` 範本、`README.md`、`fetch-ci-schema.sh`、測試、schema 資料）就是搬移的全部依據。
**公開 repo 規則**：內部主機名、IP、路徑、產品代號一律用變數或佔位字（`<內部 GitLab 網址>`、`gitlab.example.com`、`$INTERNAL_DT_URL`），不寫真值。

## 0. 怎麼讀這份文件

- 每一節的格式：**GitHub 現況 → GitLab 做法 → 要換的東西 → 驗收方式 → 官方依據**。
- 官方依據都是 docs.gitlab.com，查詢日期 **2026-11-13**（當天的線上版本；內部 GitLab 的版本可能較舊，搬移前要用內部版本的文件再核對一次，見 0.2）。
- 官方文件沒寫的行為，一律標 **「官方文件沒寫，待內部環境驗證」**，不猜。彙整表在第 13 節。
- 範本只通過語法檢查與規則測試，**尚未在內部 GitLab 實際執行**；範本裡標 `T-xx` 的是待辦（第 12 節）。

### 0.1 GitLab 版本與授權層級

| 項目 | 需要 | 備註 |
|---|---|---|
| Planner 角色能看 confidential Issue | GitLab 17.7 起（之前是 Reporter 以上） | 官方：Minimum role to see confidential issues changed from Reporter to Planner in GitLab 17.7 |
| Issues API 的 `assignee_ids`（多人指派） | Premium／Ultimate | 官方 Issues API 頁；Free 層級能否用單一指派欄位，官方這頁沒寫，**待內部環境驗證** |
| Project access token | Self-Managed 任何授權都可用 | 官方：Self-Managed 與 Dedicated「with any license」 |
| 自架 Sigstore 簽章 | Free／Premium／Ultimate（Self-Managed） | 見第 9 節 |

### 0.2 搬移前先核對內部版本

把 `gitlab/README.md` 的「內部版本核對表」跑一遍（`id_tokens`、`rules:changes`、`needs:parallel:matrix`、Generic Package、Releases API、`resource_group`、`artifacts:expire_in` 在內部版本都能用）。官方文件的線上版本一直在更新，語法檢查用的 schema 是固定 commit（第 11 節），內部版本比 schema 舊時，用它驗過的語法不保證內部能跑。

---

## 1. workflow → `.gitlab-ci.yml`

**GitHub 現況**：`.github/workflows/` 有 `release.yml`（tag `*/v*`）、`dev.yml`（`dev/**` push＋每日排程）、`pipeline.yml`（reusable，build＋scan）、`firmware.yml`（`firmware/**` 等路徑有 PR 變動）、`watch.yml`／`watch-round.yml`（每日監控）、`tests.yml`（單元測試與公開檢查）、`dt-smoke.yml`。

**GitLab 做法**（範本 `gitlab/.gitlab-ci.yml`）：

| GitHub | GitLab | 範本裡的 job |
|---|---|---|
| `release.yml`：`on.push.tags` | `workflow:rules` 與 job `rules` 用 `$CI_COMMIT_TAG =~ /^[a-z0-9][a-z0-9-]*\/v[0-9][A-Za-z0-9._+-]*$/`（tag 格式 `<專案>/v<數字>…`，同 GitHub 的 `*/v*` 與 `project_config.VERSION_RE`；`proj/1.0` 不建 release pipeline） | `release:build`、`release:scan`、`release:publish`、`release:sign`（選用） |
| `dev.yml`：`dev/**` push、cron | `rules`：`$CI_PIPELINE_SOURCE == "push"` 且分支 `^dev/`；排程 `$CI_PIPELINE_SOURCE == "schedule"` 且排程變數 `DUMPLING_JOB=dev` | `dev:build`、`dev:scan`、`dev:publish`（T-03，目前 NOT_RUN） |
| `pipeline.yml`（reusable） | 隱藏 job 片段 `.build`、`.scan`、`.build-steps`、`.scan-steps`，用 `extends` 與 `!reference` 組合；release 與 dev 共用 | — |
| `firmware.yml` 的路徑觸發 | `rules:changes`（只在 push、merge request 用） | `firmware:fetch`、`firmware:dt`（T-04，目前 NOT_RUN） |
| `watch.yml`／`watch-round.yml` | 排程 `DUMPLING_JOB=watch`；compute 與 notify 兩個 job | `watch:compute`、`watch:notify`（T-05，`when: manual`） |
| `tests.yml` 的 unit-tests | `validate:unit-tests` | `bash tests/run.sh` |
| `tests.yml` 的 public-check | **內部不需要**（那是公開 repo 專用的外洩檢查）；若內部要擋密碼／token，用 GitLab 的 Secret detection，另行決定 | — |
| `permissions:` 與 D-012 | 沒有一對一；見第 7 節 | — |
| `concurrency:` | `resource_group:`（同一個 tag、同一個通知同時只跑一個） | `release:publish`、`watch:notify` |
| `strategy.matrix` | `parallel:matrix`（`needs:parallel:matrix` 對應）；動態清單要改用 child pipeline（T-02） | `dev:*` |
| `actions/upload-artifact` retention-days | `artifacts:expire_in` | 每個 artifacts 都明寫 |
| `needs:` | `needs:`（可跨 stage；`optional: true`） | — |
| `workflow_dispatch` | `$CI_PIPELINE_SOURCE == "web"`（網頁「Run pipeline」）或 `"api"`；手動 job 用 `when: manual`。各 workflow 的**輸入**逐項見下表 | — |
| `dt-smoke.yml`（`pipeline/**` 等路徑的 PR、手動；輸入 `wait_min`）：臨時 DT 冒煙測試 | **不搬（T-15）**。原因：GitLab 版的 scan 在 T-14 之前也開臨時 DT，`release:scan`／`dev:scan` 每次都會跑同一套 `dt-ephemeral.sh up/wait/env/down` 與 `dt-verify.py`，獨立的冒煙測試重複；T-14 改連常駐 DT 之後，改成「常駐 DT 連線與權限的冒煙測試」 | — |
| `watch.yml` 的 `drill-1-baseline`／`drill-2-new-kev`／`drill-3-repeat`／`drill-close`（手動 `mode=drill`） | **不搬（T-16，阻塞於 T-05）**。原因：演練要 `issues.py` 的 GitLab 後端（開／關 Issue、狀態 Issue），T-05 之前跑不起來；`.rules-watch` 因此也只有排程、沒有 web／api 入口（不假裝能跑）。T-05 完成時一起加：web／api 入口＋pipeline 變數 `DUMPLING_WATCH_MODE=drill`，三輪與關閉照 watch.yml | — |
| `firmware.yml` 的觸發（PR 的路徑變動、手動） | 範本是**超集**：分支 push 與 merge request 都依 `rules:changes` 跑（內部沒有「外人開 PR」的顧慮，push 就先跑）；tag pipeline 不跑 | `firmware:fetch` |
| `pipeline.yml` scan 的診斷 artifact（`diag/wizard-out`，只在 artifact、不進 Release） | **不搬**：純除錯用；內部要除錯時把 `$DUMPLING_OUT/wizard-out` 的小檔加進 `.scan` 的 artifacts 即可 | — |
| `pipeline.yml` 的 `setup-go`（`scan.tools: full` 的 govulncheck 需要 Go） | **待辦 T-18**：目前專案都是 `sbom-only`，範本沒裝 Go；有專案改用 `full` 前，映像要含固定版本的 Go（或範本補安裝） | — |

**`workflow_dispatch` 的輸入逐項**（GitHub 手動觸發時可以填的值）：

| workflow：輸入 | 用途 | GitLab 對應 |
|---|---|---|
| `release.yml`：`tag`（手動只建 **draft** Release，不建 git tag） | 正式 tag 之前先試整條 release 流程 | **改成試跑（T-17）**：官方 Releases API 頁沒有 draft 狀態（只有 `released_at` 設在未來的 Upcoming Release，官方沒說它不公開），不能照搬「草稿」。改用網頁或 API 帶 `DUMPLING_RELEASE_DRY_RUN=1`、`DUMPLING_RELEASE_TAG=<專案>/<版本>`：跑 build＋scan，publish 只驗證，不上傳、不建 Release |
| `release.yml`：`stop_after`（build｜all）、`reuse_build_run`、`reuse_scan_run` | 開發 GitHub workflow 本身時省時間（只編譯、沿用別的 run 的 artifact） | **不搬**：開發捷徑，不是發行流程的一部分；GitLab 可以直接重試單一 job（上游 job 的 artifacts 在 `expire_in` 之內還在）。需要時再加 |
| `dev.yml`：`project`（只跑一個專案） | 手動只跑某個專案 | 範本用 `parallel:matrix` 的固定清單（T-02）；手動觸發是 `when: manual`（`.rules-dev`），在 pipeline 頁按要跑的那一格。GitHub 的 dispatch 是直接執行，GitLab 這裡要再按一次（避免 web pipeline 一次跑全部專案的編譯） |
| `dev.yml`：`stop_after`、`reuse_build_run` | 同 release 的開發捷徑 | **不搬**（同上） |
| `watch.yml`：`mode`（drill｜real）、`dry_run`、`baseline` | 演練、試跑不開 Issue、第一次明確建立基準 | **T-05 一起做**：pipeline 變數 `DUMPLING_WATCH_MODE`、`DUMPLING_WATCH_DRY_RUN`、`DUMPLING_WATCH_BASELINE`（對應 `--mode`、`--dry-run`、`--allow-baseline`）。`baseline` 一定要有：第一次建立基準要人明確指定（WATCH.md 3.2），否則 GitLab 版永遠不會建基準 |
| `dt-smoke.yml`：`wait_min` | 驗證 wait 逾時會失敗 | 不搬（同 dt-smoke，T-15） |

**tag pipeline 的細節**：
- tag 名稱 `<專案>/<版本>` 含斜線。tag 作為 Generic Package 的「版本」不適合（斜線），範本拆成套件名稱＝專案、套件版本＝版本。
- 排程、tag 與手動 pipeline 沒有 push 事件，`rules:changes` 對它們的行為不同（官方：沒有 push 事件的新分支 pipeline 永遠為 true；tag、排程、手動要用 `compare_to`）。tag 的 push 也是 push（官方 job_rules：push 事件含分支與 tag），所以範本的 `firmware:fetch`、`validate:unit-tests`、`firmware:dt` 的條件都是 `($CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH)` 或 merge request：只在**分支** push 與 merge request 套用 `changes`，tag pipeline 不跑（不擋 release）。
- `workflow:rules` 沒有任何規則成立時，不建立 pipeline（官方）。範本的五條規則：tag、排程（watch／dev）、`dev/**` 與預設分支 push、merge request、web／api。

**要換的東西**：`DUMPLING_IMAGE`（編譯／掃描映像）、`tags:`（`dumpling`、`dumpling-build`、`dumpling-scan` 三種 runner 標籤，換成內部實際標籤）、`DUMPLING_APT`（映像已含就清空）、`parallel:matrix` 裡的專案清單。

**驗收**：
- [ ] `tests/run.d/c3-gitlab.sh`（規則測試）與 `tests/run.d/c3-gitlab-schema.sh`（官方 schema 驗證＋反向測試）全綠。
- [ ] 內部 GitLab 的 CI Lint 通過。**CI Lint 的操作步驟我沒有查官方文件，待內部環境確認。**
- [ ] 打一個測試 tag（`<專案>/<版本>`）得到 release 流程；推一個 `dev/test` 分支得到 dev 流程；推一般分支沒有 pipeline（除非有 merge request）。

**官方依據**（查詢日期 2026-11-13）：
- `workflow:rules`、`needs`、`rules:changes`、`resource_group`、`artifacts:expire_in`、`image`：https://docs.gitlab.com/ci/yaml/
- 流程來源 `CI_PIPELINE_SOURCE`（push／schedule／web／api／trigger／pipeline／parent_pipeline）與 tag 規則 `if: $CI_COMMIT_TAG`：https://docs.gitlab.com/ci/jobs/job_rules/
- 預先定義變數（`CI_COMMIT_TAG`、`CI_API_V4_URL`、`CI_JOB_TOKEN`…）：https://docs.gitlab.com/ci/variables/predefined_variables/
- child pipeline 可有自己的 `rules`／`workflow`，`CI_PIPELINE_SOURCE` 為 `parent_pipeline`：https://docs.gitlab.com/ci/pipelines/downstream_pipelines/

**官方文件沒寫，待內部環境驗證**：protected tag 的萬用字元 `*/v*` 是否跨斜線比對（官方範例 `*gitlab*` 比對 `gitlab/v1`，暗示可以，但沒有明說）；tag 名稱含斜線時 Release 與 `CI_COMMIT_TAG` 的行為（Releases 文件沒提斜線）。

---

## 2. Release 附件 → GitLab Release ＋ Generic Package Registry（保存 10 年）

**GitHub 現況**：D-029：附件名稱固定（`sbom-<專案>-<版本>.cdx.json`、`release-meta.json`…），GitHub Release 為準；開發版放滾動 pre-release `dev/<專案>`。Actions artifact 只保存 7 天以內。PLAN 註明「10 年保存是內部 GitLab 階段的事」。

**GitLab 做法**：
1. 附件（報告 zip、SBOM、VEX、xlsx、`release-meta.json`…）用 `curl --upload-file` 上傳到 **Generic Package Registry**：`PUT /projects/:id/packages/generic/:package_name/:package_version/:file_name`，用 `JOB-TOKEN: $CI_JOB_TOKEN` 認證（範本 `release:publish`）。套件名稱＝專案、版本＝版本。
2. 用 **Releases API**（`POST /projects/:id/releases`，`JOB-TOKEN` 可用）建立 Release，`assets.links` 指向第 1 步的 Package 檔案（`gitlab/release-payload.py` 產生 JSON；`link_type: package`）。
3. **為什麼不把附件放 job artifacts**：artifacts 有到期時間（`expire_in`，未寫時用 instance 的預設，官方說預設 30 天），不適合 10 年；範本所有 artifacts 都明寫 `expire_in`（1 天～14 天，只做 job 之間傳遞與除錯），**長期保存靠 Package Registry 加 Release**。測試 `test_artifacts_have_expire_in` 保證不會漏寫，也禁止 `never`。
4. 官方：每個 ref 最新的 pipeline 與最近一次成功 pipeline 的 artifacts 不受 `expire_in` 影響（instance 的「Keep the latest artifacts」開啟時，優先於專案設定）。這不是長期保存的依據，只是額外的保險。

**10 年保存要內部決定、不是 CI 範本能做的**（記進搬移檢查清單）：
- Package Registry 與 Release 資料落在哪個儲存（物件儲存或本機磁碟）、備份週期、還原演練。
- 不要啟用 package 自動清理／保留政策去刪 Release 附件的版本（官方建議設 retention policy；這裡要排除或不設）。
- 禁止刪除 tag（官方：刪 tag 會連帶刪掉 Release；刪 Release 不刪 tag）。用 **protected tag** 限制誰能建立與刪除（官方：刪除需 Maintainer／Owner，且在 Allowed to create 名單）。範本建議保護 `*/v*`。
- 專案不要被封存後刪除；專案刪除時的行為（所有 Release 與 Package）官方這幾頁沒寫，**待內部環境驗證**。
- 附件的完整性：建議 `release-meta.json` 內寫入各附件 sha256（M2 的 `release-meta.py` 是否已有，M2 合併後核對），簽章見第 9 節。

**要換的東西**：Package 與 Release 所在專案（產品 repo 或專用發行專案）、儲存與備份設定、protected tag 規則。

**驗收**：
- [ ] 打測試 tag：Release 頁出現 `assets.links`，點進每個連結都能下載，sha256 與 `release-meta.json` 一致。
- [ ] 同一個 tag 再跑一次 `release:publish`：失敗，不覆蓋既有 Release。
- [ ] 刪除測試 tag 的演練只在測試專案做，確認 Release 一併消失（證明要用 protected tag 擋）。
- [ ] 把 `expire_in` 到期後的 job artifacts 清掉，Release 附件仍可下載。

**官方依據**（2026-11-13）：
- Generic Package Registry（PUT 路徑、`JOB-TOKEN`、檔名字元、重複上傳預設「新增檔案到同名同版本套件」）：https://docs.gitlab.com/user/packages/generic_packages/
- Package Registry 概要與儲存（清理與保存期限這頁沒寫）：https://docs.gitlab.com/user/packages/package_registry/
- Release（刪 tag 連帶刪 Release、protected tag）：https://docs.gitlab.com/user/project/releases/
- Releases API（`tag_name`、`assets.links`、`link_type`、Developer 權限、`JOB-TOKEN` 可用）：https://docs.gitlab.com/api/releases/
- Job artifacts（`expire_in`、keep latest）：https://docs.gitlab.com/ci/jobs/job_artifacts/
- Instance 設定（預設到期 30 天、Keep latest）：https://docs.gitlab.com/administration/settings/continuous_integration/
- Protected tags：https://docs.gitlab.com/user/project/protected_tags/

**官方文件沒寫，待內部環境驗證**：Generic Package 同名同版本上傳「同名檔案」是覆蓋還是新增（官方只說同名同版本會新增檔案，沒說同檔名）——影響 `dev:publish` 滾動覆蓋（T-03）；套件名稱與版本的字元規則（官方只寫了檔名規則）；Release／Package 的預設保存期限與專案刪除時的行為；instance 是否能強制 `expire_in` 上限、`expire_in: never` 是否被 instance 設定覆蓋（官方 instance 設定頁沒寫）。

---

## 3. Issue → GitLab Issue（confidential）

**GitHub 現況**：每日監控（`pipeline/watch/issues.py`）用 GitHub API 開 Issue（標籤 `dumpling-watch`、`kev`、`shipped`／`development`…）與一個狀態 Issue（標籤 `watch-state`，內文是 gzip＋base64 的狀態 JSON，含專案版本與命中資料）；公開 repo 只做示範與 `art14-drill`。

**GitLab 做法（規則）**：
1. **已被利用的真實案件（KEV 命中、第 14 條通報案件）一律用 confidential Issue。**
2. **每日監控的狀態 Issue 與命中 Issue 一律 confidential**（含產品版本、元件與 CVE 命中）。
3. 用 API 建 Issue 時帶 `confidential=true`（官方 Issues API：`confidential` boolean，預設 `false`——不帶就是公開給專案成員）。`pipeline/watch/issues.py` 的 GitLab 後端要把它寫死成 true，沒有「關掉」的選項（T-05）。範本 `watch:notify` 有 `--confidential`，測試 `test_issue_creation_is_confidential_and_token_hygiene` 檢查：直接用 curl 呼叫 `/issues` 的行都必須帶 `confidential=true`。
4. **誰看得到**（官方）：專案角色 Planner、Reporter、Developer、Maintainer、Owner（Planner 自 GitLab 17.7 起；之前是 Reporter 以上）。Guest／Minimal 看不到，除非是被指派者，或 Guest 看自己建立的。**搬移前確認專案成員名單**：把不該看的人（例如外部承包商）設為 Guest 或移出專案；真實案件所在專案不要設成 Public。
5. **通知**：GitHub 版用 Issue 指派代表「交給誰」；GitLab 版改成 **Issue 指派＋email**。
   - 指派：Issues API 的 `assignee_ids` 僅 Premium／Ultimate；Free 層級用法**待內部環境驗證**。
   - email：GitLab 的通知設定（專案層級優先於群組層級；被指派者會收到 "Reassigned" 類通知；"New issue" 在 Watch／Participate／On mention 等級會寄出）。官方通知頁**沒寫** confidential Issue 的通知是否只寄給有權限者——**待內部環境驗證**（用測試帳號建 confidential Issue，確認沒有權限的人收不到）。
   - 需要自訂寄信（例如寄給 PM 信箱群組、含倒數）時，從 sca-center 帶回 `scripts/cra/alert_mail.py`（與 `scripts/cra/tests/test_alert_mail.py`），照 D-015 的目錄對應放 `tools/cra/`，在 `docs/PROVENANCE.md` 記來源 commit。**T-08：待辦，這次不帶。**
6. **token 衛生**：`WATCH_GITLAB_TOKEN` 只給 `watch:notify`；不得印出；不得 `set -x`（測試檢查）。
7. 公開 repo 的 `publiccheck.py`（寫入前檢查內文沒有本機路徑、信箱）是公開版的保護；內部版建議保留（避免把內部路徑寫進 Issue 給所有成員），規則內容換成內部版（待決定）。

**要換的東西**：Issue 所在專案（建議專用的、成員受控的專案）、標籤集、`WATCH_GITLAB_TOKEN`、email 通知對象。

**驗收**：
- [ ] 用範本建出的每一個 Issue，在 UI 看都有 confidential 標示；API `GET /projects/:id/issues?confidential=true` 列得出來，`false` 列不出來。
- [ ] 沒有權限的帳號（Guest、非成員）打開 Issue 連結看不到，搜尋不到。
- [ ] 被指派者與預期的 email 收件者有收到通知，沒權限的人沒收到。
- [ ] 狀態 Issue 的重複建立、樂觀鎖（`state_base`）在 GitLab 後端行為與 GitHub 版測試一致。

**官方依據**（2026-11-13）：
- Confidential issue（可見角色、17.7 變更、Guest 限制、無法建立 confidential MR）：https://docs.gitlab.com/user/project/issues/confidential_issues/
- Issues API（`POST /projects/:id/issues`：`confidential`、`labels`、`assignee_ids`（Premium／Ultimate）、`description` 上限 1,048,576 字元；`GET` 的 `confidential` 篩選；預設分頁 20 筆）：https://docs.gitlab.com/api/issues/
- 通知（等級、Reassigned、New issue、專案層級覆蓋群組層級）：https://docs.gitlab.com/user/profile/notifications/

**官方文件沒寫，待內部環境驗證**：Issues API 需要的 token scope 沒有逐端點列出（只知道寫入需要 `api` scope，見第 7 節）；confidential Issue 的 email 通知收件範圍；Free 層級的單一指派參數。

---

## 4. 臨時 DT → 內部常駐 DT

**GitHub 現況**：每個 job 用 `pipeline/dt-ephemeral.sh up/wait/env/down` 開臨時 Dependency-Track（DT），UUID 每天不同；`dt-smoke.yml` 做煙霧測試。每日監控刻意不開 DT（WATCH.md 第 1 節）。

**GitLab 做法**：
- **現況（範本照這個寫）**：`pipeline/platforms/*/scan.sh` 一定用 `pipeline/dt-ephemeral.sh` 開臨時 DT（要 docker），把連線資訊寫進 `PILOT_ENV` 這個**路徑**、自己從公開網址抓 NVIDIA 公告／核心 CVE／EUVD／OSV 鏡像，並設 `MIRROR_REFRESH_STATUS=""`。所以範本的 scan 跟 GitHub 版一樣開臨時 DT：`PILOT_ENV` 是 `$DUMPLING_OUT_BASE/pilot-env/pilot.env`（單獨一個資料夾），掃描 runner 要有 docker（第 5 節），還不能斷外網。
- **目標（待辦 T-14）**：掃描改連**內部常駐 DT**（已有完整鏡像：OSV、KEV、NVD 等）。需要 `scan.sh`／`dt-ephemeral.sh` 新增常駐 DT 模式（C1 的檔案，經 C0 協調）：連線設定 `PILOT_ENV` 改成 File 類型 CI/CD 變數、protected，內容是 `pilot.env`（含 `$INTERNAL_DT_URL` 與服務帳號 API key，格式**待內部驗證**）；`MIRROR_REFRESH_STATUS` **不設為空**，讓鏡像新鮮度檢查生效，過期標 GAP。T-14 完成後範本的 scan 再改。
- DT 專案分層：GitHub 版是 `<名稱>-bsp`／`<名稱>-os` 兩個平行專案（D-030(4)）。**T-07：parent／child 專案在常駐 DT 再評估**（會影響每日監控的專案鍵 `dumpling:<專案>/<版本>#<層>` 與 DT 內的呈現；評估時一併決定舊的平行專案是否遷移）。
- 持續性：常駐 DT 的 UUID 穩定，每日監控理論上可以改走 DT 路線（`exploited_watch.py` 以 DT 專案 UUID 為鍵）。要不要改是另一個決定，不在這次範圍；範本維持與 GitHub 相同的 Grype＋KEV＋EUVD 路線。

**要換的東西**（T-14 之後）：`PILOT_ENV` 變數、`$INTERNAL_DT_URL`、DT API key（見第 7 節）、`firmware:dt` 的呼叫方式（T-04）。

**驗收**：
- [ ] （現況）`release:scan` 在測試 tag 上以臨時 DT 完成，`pipeline/dt-verify.py` 通過。
- [ ] （T-14 之後）`release:scan` 連常駐 DT 完成，常駐 DT 內出現對應專案，`pipeline/dt-verify.py` 通過。
- [ ] （T-14 之後）鏡像過期時（故意讓狀態檔過期）scan 標 GAP，不是 OK。
- [ ] DT API key 沒有出現在 job log、artifacts（`result/`）。

**官方依據**：這一節大部分是內部系統，沒有 GitLab 官方文件；File 類型變數與 protected 見第 7 節的 https://docs.gitlab.com/ci/variables/ 。**常駐 DT 的 pilot.env 格式與權限模型：官方文件不適用，待內部環境驗證。**

---

## 5. 內建 runner → 內部 shell／docker runner

**GitHub 現況**：全部 `ubuntu-24.04`（x64）與 `ubuntu-24.04-arm`（Jetson 編譯）內建 runner；公開 repo 不接自架 runner（任何人開 PR 都能在機器上跑程式）；開頭刪預裝工具騰磁碟；build 與 scan 分 job；每個 job 最長 6 小時。

**GitLab 做法**：
- 三種標籤（範本）：`dumpling`（輕量：測試、打包、通知）、`dumpling-build`（核心／樹外模組編譯，要 arm64 時另標）、`dumpling-scan`（掃描，需要 bubblewrap／user namespace、docker（臨時 DT，T-14 之前）、能連鏡像）。實際標籤換成內部的。
- **跟 GitHub 代管 runner 相同的前提**（範本與被呼叫的腳本都假設；GitHub 版在 runner 上都有）：
  - 非 root 執行時要有**免密碼 sudo**：`pipeline/install-scan-tools.sh` 用 `sudo install`，`tools/e2e/install-tools.sh` 用 `sudo apt-get install bubblewrap` 與 `sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`。範本 `.setup` 依 `id -u` 設 `$SUDO`（root 時為空）；docker executor 以 root 跑時，`DUMPLING_APT` 預設含 `sudo`，讓腳本裡的 `sudo` 可以執行。
  - 套件：`DUMPLING_APT` 不是空的時，範本照 GitHub 版安裝 platform.yml 的 `build.apt`（build）與 `bubblewrap python3-yaml`＋`scan.apt`（scan）。內部映像把 `DUMPLING_APT` 清空時，**映像必須自己含這些套件**（例如 Jetson 編譯要 build-essential、bc、bison、flex、libssl-dev、libelf-dev…，掃描要 zstd、lbzip2；以各專案 platform.yml 為準）。
  - 掃描 runner 要能跑 docker（臨時 DT）：shell executor 裝 docker，或 docker executor 給 docker 存取（做法內部決定；docker-in-docker 要 privileged，安全取捨要內部評估）。T-14 完成、改連常駐 DT 後才不需要。
- executor：shell 或 docker 都可。docker executor 用 `DUMPLING_IMAGE`（RD 的編譯映像，固定 digest 或固定版本，不可用 `latest`，測試檢查）。shell executor 的沙箱需求（user namespace 設定）是整台機器的設定，要在 runner 安裝腳本處理（參考 sca-center 的 `deploy/gitlab-runner/` 的做法，**不複製內部細節**）。
- `concurrent`／清理：編譯需要大量磁碟；範本在 `after_script` 刪除 `$DUMPLING_OUT_BASE`（輸出放在專案資料夾外，避免被掃到自己）；runner 本身需要週期清理工作資料夾與 Docker 資源（做法內部決定）。`concurrent` 的值依磁碟與 CPU 決定，**建議從 1 開始**（掃描與編譯同時跑會互搶磁碟）。**掃描 runner 在 T-14 之前必須是 1**：臨時 DT 綁固定的 `127.0.0.1:${DT_PORT:-8080}`，同一台同時兩個 scan 會搶埠（compose 專案名與狀態資料夾範本已依 `$CI_JOB_ID` 分開，`after_script` 會 `dt-ephemeral.sh down`，job 被取消也不殘留容器）。
- 不開 `interruptible`：build／scan／release 的 job 設 `interruptible: false`，避免新的 push 取消一個已跑一小時的編譯（`default` 設 true 是給測試類 job）。
- 逾時：job 預設 `timeout` 範本已個別設定（編譯 2 小時、掃描 4 小時，沿用 GitHub 版的 120／240 分鐘）。官方：runner 的最大逾時只有比專案設定短時才生效，最小值 600 秒。
- **「公開 repo 不接自架 runner」的理由在內部不適用**（內部 repo 只有受信任的成員能推 code），但仍要做：
  - 掃描與發行用的 runner 設為**只跑 protected branch／protected tag**（官方：runner 可設定只跑保護分支或保護 tag，避免洩漏敏感資訊）。
  - 對應地，`WATCH_GITLAB_TOKEN`（與 T-14 之後的 `PILOT_ENV`）這類變數設 protected（第 7 節），只有保護 ref 的 pipeline 拿得到。
  - merge request pipeline 不拿 protected 變數（官方：MR pipeline 預設拿不到 protected 變數，可選擇開放；**不要開**）。

**要換的東西**：runner 標籤、executor、`DUMPLING_IMAGE`、arm64 編譯機（Jetson 核心編譯需要 arm64 原生；GitHub 版約 36 分鐘）、磁碟空間規劃。

**驗收**：
- [ ] 三種標籤的 runner 都在線；掃描 runner 設為只跑 protected ref，在未保護分支觸發 scan job 會 stuck（預期）。
- [ ] 一次完整 Jetson 編譯在規劃磁碟內完成，結束後 `$DUMPLING_OUT_BASE` 已清掉。
- [ ] 編譯映像的 digest 或版本寫在 `DUMPLING_IMAGE`，沒有 `latest`。

**官方依據**（2026-11-13）：
- Runner 設定（只跑 protected branch／tag、最大逾時、`RUNNER_GENERATE_ARTIFACTS_METADATA`）：https://docs.gitlab.com/ci/runners/configure_runners/
- `image` 的 digest 寫法 `<image-name>@<digest>`、`pull_policy`：https://docs.gitlab.com/ci/yaml/

**官方文件沒寫，待內部環境驗證**：官方 `configure_runners` 頁沒有名為 "Protect a runner" 的段落，保護旗標在各層級 runner 設定頁的實際操作步驟待內部確認；`concurrent`、清理與 executor 的選擇不是官方文件能決定的，是內部決定。

---

## 6. 資料來源：公開 BSP → 公司產品 repo；公開 feed → 內部鏡像

| 項目 | GitHub 版 | GitLab 版 |
|---|---|---|
| BSP／原始碼 | `projects/<專案>/sources.yml` 的公開網址＋sha256（`fetch` 步驟下載並核對） | 公司產品 repo 與內部檔案庫；`sources.yml` 的網址換成內部網址，**sha256 照樣核對**（硬性限制 3 的精神：二進位檔不進 git、下載後核對）。網址放變數，不寫死 |
| CISA KEV、EUVD、核心 CNA、Grype DB | `pipeline/watch/feeds.sh` 每天從公開網址下載 | 改讀**內部鏡像**（sca-center 既有的鏡像同步腳本、`deploy/gitlab-runner/` 的做法）；`feeds.sh` 需要加內部鏡像來源的選項，範本變數 `INTERNAL_MIRROR_URL`（T-06） |
| NVIDIA 公告、OSV | 臨時 DT 開機時下載 | 常駐 DT 已有 |
| 編譯環境 | runner 上 `apt-get` 安裝（`build.apt`） | RD 的 Docker 映像（`DUMPLING_IMAGE`），`DUMPLING_APT` 清空 |

**驗收**：
- [ ] （T-06、T-14 之後）斷開外網的 runner 上，`release:scan` 與 `watch:compute` 的資料源步驟都能完成（全部來自內部鏡像）。現況 scan.sh 與 feeds.sh 都直接從公開網址下載，**還不能斷網**。
- [ ] 鏡像過期時狀態是 GAP；沒有任何步驟靜默回退到公開網址。

**官方依據**：內部系統，不適用 GitLab 官方文件。

---

## 7. 機密設定：GitHub secrets → GitLab CI/CD variables

**GitHub 現況**：`GITHUB_TOKEN` 預設唯讀，需要寫入的 job 自己宣告（D-012）；第三方 action 用 commit SHA 固定；外部人士 fork PR 要核准。本專案沒有存 DT API key（臨時 DT 的 key 每個 job 產生一次）。

**GitLab 做法**：

| 機密／設定 | 放哪裡 | 設定 |
|---|---|---|
| DT API key／`PILOT_ENV`（T-14 之後；現況由臨時 DT 寫入路徑） | 專案（或群組）CI/CD variable，**File** 類型 | **protected**；是 File 類型，內容含 key，**masked 不適用於多行或有空白的值**（官方：masked 值必須單行、不含空白、至少 8 字元），所以靠 protected＋runner 只跑保護 ref 來保護，並確保 job log 不印出；內容格式待內部驗證 |
| `WATCH_GITLAB_TOKEN`（通知用的 project access token） | CI/CD variable，**Variable** 類型 | **protected＋masked**；只有 `watch:notify` 讀（測試檢查） |
| `WATCH_GITLAB_READ_TOKEN`（每日監控讀取用的 project access token） | CI/CD variable，**Variable** 類型 | **protected＋masked**（建議 Masked and hidden）；只有 `watch:compute` 讀。scope `read_api`（官方：唯讀 API）、角色 Planner（官方：confidential Issue 要 Planner 以上才看得到，17.7 起；之前是 Reporter）。狀態 Issue 與監控 Issue 都是 confidential，私有專案的 Release 也要權限，所以 compute 不能沒有 token |
| `COSIGN` 金鑰（若選金鑰對方案，見第 9 節） | KMS 優先；其次 protected＋masked variable | 待內部決定 |
| 排程變數 `DUMPLING_JOB` | Pipeline schedule 的變數 | 不是機密 |

- **GitLab 的 Visible／Masked／Masked and hidden**（官方）：Masked 在 job log 以 `[MASKED]` 取代；Masked and hidden 建立後 UI 看不到值。`WATCH_GITLAB_TOKEN` 建議用 **Masked and hidden**。
- **protected 旗標**：只在保護分支與保護 tag 的 pipeline 可用（官方）。
- **`CI_JOB_TOKEN`（對應 `GITHUB_TOKEN`）**：D-012 的精神是「預設最小權限」。GitLab 對應：
  - job token 的權限是「觸發 pipeline 的使用者」的權限，但可用的 API 端點有限制（官方列表）：Releases API 全部端點、Packages API 全部端點可用；Jobs API 只有 `GET /job`；Repositories、Files、Tags、Commits 等只有少數讀取端點；**Issues API 不在列表裡**，GraphQL 不能用 job token。所以範本用 job token 上傳 Package 與建立 Release，**不用它開 Issue**（測試檢查）。
  - job token 預設只能存取自己的專案（allowlist 預設只含自己）；不要把其他專案或群組加進 allowlist，除非有跨專案需求。
  - job token 只在 job 執行期間有效（官方）。
  - 建立 Release 需要 Developer 以上（官方 Releases API），這是觸發使用者的權限，**tag 保護（protected tag）才是真正限制誰能發 Release 的地方**。
- **Project access token（最小 scope）**：
  - 建立需要 Maintainer／Owner；token 有自己的 bot 使用者，權限來自選的角色與 scope；**只能存取自己的專案**；到期預設 365 天，上限 365 天（管理員在 17.6 起可調）；到期當日 UTC 午夜失效。
  - scope：官方只列 `api`（完整讀寫）、`read_api`（唯讀）、`read_repository`、`write_repository` 等；寫入 Issue 需要 `api`，**沒有更細的 Issue 專用 scope**。因此用「最小角色＋只給一個專案＋專用專案」降低風險。最小角色（能建 Issue 的最低角色）官方這幾頁沒寫，**待內部環境驗證**。
  - 輪替：到期前換新並更新 CI/CD variable；把「token 到期日」放進搬移檢查清單，排程 owner 接手 SOP（第 8 節）一併檢查。官方：預設在最後一個 token 失效或過期 30 天後刪除 bot。
- 第三方 action 的 SHA 固定在 GitLab 對應為：`image` 固定 digest／版本（第 5 節）；`include:` 若引用外部範本要用 `ref:` 固定 commit SHA 或 tag（範本本身目前沒有 `include`）。

**驗收**：
- [ ] `WATCH_GITLAB_TOKEN`（與 T-14 之後的 `PILOT_ENV`）的 protected 旗標已開；在非保護分支 pipeline 印環境變數看不到它們。
- [ ] 在 merge request pipeline 看不到它們。
- [ ] `watch:notify` 以外的 job 看不到 `WATCH_GITLAB_TOKEN` 的使用、`watch:compute` 以外看不到 `WATCH_GITLAB_READ_TOKEN`（測試）；log 與 artifacts 掃不到 token 字串。
- [ ] token 到期日已記入行事曆／排程提醒。

**官方依據**（2026-11-13）：
- CI/CD variables（Visible／Masked／Masked and hidden、protected、遮罩條件、File 類型）：https://docs.gitlab.com/ci/variables/
- Job token（可用 API 列表、allowlist 預設、有效期間）：https://docs.gitlab.com/ci/jobs/ci_job_token/
- Project access token（角色、到期、bot、Self-Managed 任何授權）：https://docs.gitlab.com/user/project/settings/project_access_tokens/
- Token scopes（`api`、`read_api` 適用於 project token）：https://docs.gitlab.com/security/tokens/access_token_scopes/

---

## 8. 排程：GitHub 的 60 天停用 → GitLab pipeline schedules

**GitHub 現況**：公開 repo 60 天沒有活動，排程會被關掉；`watch.yml` 有 `keepalive` job（`gh api -X PUT .../enable`）防停用。

**GitLab 做法**：
- 每日監控與 dev 版用 **Pipeline schedules**（專案 Build > Pipeline schedules），變數 `DUMPLING_JOB=watch`（或 `dev`）。範本的規則用這個變數區分，避免排程同時觸發兩套。
- **不需要 `keepalive` job**：官方排程頁沒有提到閒置自動停用（只說專案或群組標記刪除時排程停止）。**這是「官方文件沒寫」，不是「官方保證沒有」，待內部環境驗證**（建議上線後觀察一個月以上，並設監控：每日監控沒有在預期時間產生結果就告警）。
- **排程擁有者的風險**（官方）：
  - 排程用**擁有者的權限**執行。
  - 擁有者被封鎖或移出專案時，排程狀態會變 `Inactive`。官方文件沒寫擁有者「自行離開」的情形。
  - 取得擁有權：需要 Maintainer 或 Owner，在排程列表按 **Take ownership**。
  - 排程變數只在排程 pipeline 可用。
  - 排程頻率不能快過 instance 設定的最小間隔；每專案排程數量有上限（官方連到 limits 頁，數字沒在這頁）。
- **排程擁有者離職時的接手程序**（寫成 SOP，放進交接清單）：
  1. 離職前：由 Maintainer 在 Pipeline schedules 對所有排程按 **Take ownership**，換成團隊的服務帳號（或負責人的接手者）。**建議用不會離職的服務帳號當擁有者**，帳號角色至少要能存取受保護的變數所需的保護 ref。
  2. 離職日當天：確認排程狀態仍是 Active、`watch:compute` 昨天有產生 artifact；確認 `WATCH_GITLAB_TOKEN`（project access token）不是離職者個人建立的 token（project token 屬於 bot，不隨個人離職失效，但建立者離職要確認 token 到期日仍有人追蹤）。
  3. 離職後一天：看 Pipeline schedules 是否出現 Inactive；有就立刻接手。
  4. 每月：核對排程清單、擁有者與最近一次執行時間（可寫成日常檢查腳本；`GET /projects/:id/pipeline_schedules` 是否有 `active` 欄位，官方 API 頁我沒有讀，**待內部環境驗證**）。
- 每日監控的「沒結果就告警」（死人開關）：GitHub 版的 keepalive 目的是防排程停用；GitLab 版改成外部監看——最簡單的做法是狀態 Issue 的最後更新時間超過 36 小時就寄信。**T-12：寫進 watch 的 GitLab 後端時一併做**，範本目前沒有。

**驗收**：
- [ ] 建立排程：`DUMPLING_JOB=watch`，每日一次，時間避開備份與鏡像更新時段。
- [ ] 把擁有者帳號暫時移出專案（測試專案）→ 排程變 Inactive；用 Take ownership 恢復。
- [ ] 排程一個月以上沒有人手動動過，仍持續執行。

**官方依據**（2026-11-13）：
- Pipeline schedules（擁有者權限、被封鎖或移出時 Inactive、Take ownership、需要 Maintainer／Owner、變數、最小頻率）：https://docs.gitlab.com/ci/pipelines/schedules/

**官方文件沒寫，待內部環境驗證**：閒置多久後排程會自動停用（文件沒提）；擁有者主動退出專案的行為；`cron_timezone` 的設定介面（排程頁只在疑難排解的 SQL 提到欄位名）；排程列表 API 的狀態欄位。

---

## 9. 簽章與來源證明（D-032／D-033 的 A2 GitLab 方案）

**GitHub 現況**：`release.yml` 在 M7 用 `actions/attest-build-provenance` 為每個附件產生來源證明，`actions/attest-sbom` 把 SBOM 綁到對象；證明寫進 Sigstore **公開**透明紀錄，永久公開；驗證用 `gh attestation verify`。權限只在該 job 開 `id-token: write`、`attestations: write`。**內部階段不能沿用公開的透明紀錄**（提案 A2）。

### 9.1 GitLab 官方有的東西

1. **Sigstore cosign keyless 簽章**（`id_tokens`）：
   - job 宣告 `id_tokens: SIGSTORE_ID_TOKEN: {aud: sigstore}`；cosign **2.0.1 以上**；簽署 build artifact 用 `cosign sign-blob <檔> --bundle cosign.bundle`，驗證 `cosign verify-blob <檔> --bundle cosign.bundle --certificate-identity "<identity>" --certificate-oidc-issuer "<GitLab 網址>"`。
   - certificate identity 格式：實例網址、專案路徑、**雙斜線**、CI 設定檔路徑、`@`、ref（官方：單斜線會造成 identity 不符）。
   - **限制**：頁面寫「You must be using GitLab.com」——公用 Sigstore 只信任 GitLab.com 的 pipeline，**不信任 Self-Managed**。`id_tokens` 要寫在被簽署的專案本身；**include 進來的 CI 檔與 child pipeline 不支援**；AutoDevOps 不支援。
   - **Self-Managed 要自架 Sigstore**（另一頁）：要自己跑 Fulcio、Rekor 與 CT log（CT log 必要，cosign 驗證時檢查簽署憑證時間戳）；runner 上放信任材料（Fulcio root、Rekor 公鑰、CT log 公鑰）；Fulcio 設定 `oidc-issuers`（`type: ci-provider`、`ci-provider: gitlab-pipeline`，GitLab issuer URL 要完全比對）；Rekor 要用持久簽署金鑰（例如 Vault transit）與固定 tree ID，否則重啟後信任失效；cosign v3 用 signing config 與 trusted root，v2 用旗標與環境變數；憑證 identity 格式 `https://<CI_SERVER_HOST>/<專案路徑>//.gitlab-ci.yml@<完整 ref>`。檔案式簽署金鑰「只該用於測試」。
2. **Runner 的產物來源證明中繼資料**：job 設 `RUNNER_GENERATE_ARTIFACTS_METADATA=true`，runner 為 artifact 產生 `{ARTIFACT_NAME}-metadata.json`（沒有 artifact 名稱時是 `artifacts-metadata.json`），格式是 **in-toto v0.1 Statement**，predicate 是 **SLSA 1.0 provenance**（`predicateType: https://slsa.dev/provenance/v1`）；環境變數的值一律以空字串表示，保護機密。**官方文件沒說這個檔案有簽章**，也沒寫最低 runner 版本。它和 artifact 一起存成純文字 `.json`，所以它是「描述」不是「證明」：能被改，除非另外簽。
3. cosign 還能做 `cosign attest`（把 SLSA provenance 或 SBOM 當 in-toto predicate 簽成 attestation）。這部分**不是 GitLab 官方文件的內容，我沒有查 cosign 的官方文件，M7 實作前要查**。

### 9.2 內部 Self-Managed 的選項比較

| 選項 | 做法 | 前提 | 限制／風險 | 收件人怎麼驗證 | 金鑰誰管 | 待內部決定 |
|---|---|---|---|---|---|---|
| **A. 自架 Sigstore keyless** | 官方 `id_tokens`＋`cosign sign-blob --bundle`，Fulcio／Rekor／CT log 自架 | 內部要維運 Fulcio、Rekor、CT log 三個服務；Rekor 持久簽署金鑰（如 Vault）；runner 與驗證端都要信任內部 CA 與 trust root；cosign 2.0.1+（官方）；`id_tokens` 寫在被簽署的專案本身，不能用 include 或 child pipeline | 維運成本最高；官方整頁幾乎都是設定細節；Rekor／Fulcio 重建會使舊簽章不可驗；對**外部收件人**（客戶、市場監督機關）驗證，需要把 trust root（公開材料）一併交付，且對方得能用 cosign 驗；是否能對外公開驗證取決於內部決定 | `cosign verify-blob --bundle … --certificate-identity … --certificate-oidc-issuer <內部 GitLab 網址> --trusted-root`（v3）；對外需交付 trust root | 無長期私鑰（金鑰在 Fulcio 短期憑證）；要保管的是 Fulcio／Rekor 的 CA／簽署金鑰與 OIDC 設定 | ☐ 要不要自架；誰維運；對外交付 trust root 的方式 |
| **B. cosign 金鑰對** | 金鑰放 KMS／HSM 或 protected＋masked variable；`cosign sign-blob --key …`；若要帶 SLSA provenance 用 `cosign attest`，關閉公開透明紀錄上傳（提案 A2） | 金鑰管理服務（KMS）或至少 protected 變數；cosign 固定版本進 `tools.lock`（T-09）；公開金鑰的對外發布位置 | 長期私鑰洩漏風險（用 KMS 降低）；輪替需換公鑰並公告；簽章時間沒有透明紀錄佐證（可自行加時間戳，待決定） | `cosign verify-blob --key <公鑰> …`（旗標細節待查 cosign 文件） | 內部資安／平台團隊（KMS）；輪替週期內部決定；protected 變數放私鑰只能當退路 | ☐ KMS 或 protected 變數；輪替週期；公鑰發布位置 |
| **C. 只用 runner 產生的 metadata** | `RUNNER_GENERATE_ARTIFACTS_METADATA=true`，把 `*-metadata.json` 當附件一起放 Release | 只需 runner 版本支援（最低版本官方沒寫，待驗證） | **沒有簽章**，只能證明「runner 宣稱怎麼建的」，任何能改 artifact 的人都能改它；不滿足「可驗證完整性」 | 無（只能比對 sha256 與 metadata 內容，沒有信任根） | 不需要金鑰 | ☐ 是否只當 B 或 A 的輸入 |
| **D（組合，建議評估）** | 先用 C 產生 SLSA provenance，再用 A 或 B 對 provenance 與附件簽章 | 同 A 或 B | 同 A 或 B；多一份附件 | 同 A 或 B | 同 A 或 B | ☐ |

**範本裡的位置**：`release:sign` 是**選用、手動、`allow_failure`**，只實作官方有文件的 keyless 路徑（`id_tokens`＋`sign-blob --bundle`），變數 `DUMPLING_SIGN_MODE` 預設 `none`（不簽）。`cosign` 執行檔需固定版本＋sha256 進 `pipeline/lib/tools.lock`（T-09，M7 的 A2 GitHub 部分一併處理）。範本**沒有**實作選項 B 與 D，因為前提（KMS、公鑰發布）未決定。

**建議**（供內部決定）：
1. 先確認「簽章的需求來自誰、要證明給誰」：只是內部稽核（內部信任根就夠）還是要給外部（客戶、監督機關）驗證。這決定選 A 還是 B。
2. 若沒有人能維運三個 Sigstore 服務，B（KMS 金鑰）比 A 實際；如果內部已有 Sigstore 或願意維運，A 沒有長期私鑰，較佳。
3. 不管選哪個，加上 C 的 provenance 作為被簽署內容之一，簽章要涵蓋所有附件與 `release-meta.json`（內含各附件 sha256）。
4. **不沿用 GitHub 公開透明紀錄**：內部簽章不要上傳到公開的 Rekor。

**驗收**（選定方案後）：
- [ ] 正向：用文件寫的驗證指令，對 Release 附件驗證通過。
- [ ] 負向：把附件改一個位元組再驗證，必須失敗（提案 A2 的負面測試，CI 裡實際跑）。
- [ ] 範本通過語法檢查（`release:sign` 的 `id_tokens` 在被簽署專案本身；測試 `test_signing_job` 檢查）。

**官方依據**（2026-11-13）：
- https://docs.gitlab.com/ci/yaml/signing_examples/ （GitLab.com 的 keyless、cosign ≥ 2.0.1、`--bundle`、identity 格式、include／child pipeline 限制）
- https://docs.gitlab.com/ci/yaml/signing_self_hosted/ （Self-Managed 自架 Sigstore 的需求與限制）
- https://docs.gitlab.com/ci/runners/configure_runners/ 的 Artifact provenance metadata（`RUNNER_GENERATE_ARTIFACTS_METADATA`、in-toto v0.1、SLSA 1.0、空字串規則）
- https://docs.gitlab.com/ci/yaml/ 的 `id_tokens`（`aud` 可為字串、陣列或變數）

**官方文件沒寫，待內部環境驗證**：runner 產生 metadata 的最低 runner 版本與簽章（沒有說明）；metadata 檔案如何與 Release 綁定；`cosign attest`／`attest-blob` 與 `--key`／KMS 的用法（不是 GitLab 官方文件，要查 cosign 文件）；`id_tokens` 在內部版本的可用性（0.2 節的版本核對）。

---

## 10. 第 14 條通報（M8；倒數的 GitLab 版已實作，見 T-10；email 提醒還沒做）

| 項目 | GitHub 公開 repo | GitLab 內部 |
|---|---|---|
| 真實案件 | **不做**。公開 Issue 等於公開揭露 | **confidential Issue**（標籤 `art14`＋階段標籤 `art14-24h`／`art14-72h`／`art14-final`） |
| 演練 | `art14-drill`，Issue 第一行「演練，不是真實通報」，合成資料 | 可保留，同樣標明演練 |
| 倒數更新 | 有開著的 `art14`／`art14-drill` 時，排程每小時更新倒數留言（D-033(3)）；沒有就立刻結束 | pipeline schedule 每小時觸發（`DUMPLING_JOB=art14`），沒有開著的案件立刻結束；排程擁有者規則同第 8 節 |
| 通知 | — | Issue 指派＋email（第 3 節）——**email 與指派尚未實作（T-10 待辦，需內部郵件設定／T-08）** |
| SRP 送出 | 人工步驟 | 人工步驟（工具不自動送） |
| 起算點 | 「知悉時間」由負責人決定；KEV 的 `first_detected` 只是候選 | 同左 |

驗收（M8 時）：真實案件 Issue 全為 confidential；倒數只更新有開著案件；演練與真實的標籤、第一行字樣不可混用；程式在 GitLab 後端寫入前確認 `confidential=true`。
**官方依據**：第 3 節的 confidential Issue 與 Issues API；第 8 節的 pipeline schedules。
**T-10 實作對應**（細節與內部驗證清單見 T-10 列）：`art14.py --backend gitlab`、`art14:countdown`（`DUMPLING_JOB=art14`）；真實案件用 `open-real`；作者／留言者要是成員且等級 ≥ Developer（30）；非 confidential 的 art14 Issue → FAIL、不寫入。上面的驗收項目已有對應的假 API 測試（`pipeline/watch/tests/test_art14_gitlab.py`、`gitlab/tests/test_gitlab_ci.py`），尚未對真實 GitLab 驗證。

---

## 11. 語法檢查（M5 驗收）

- **官方 CI JSON schema** 直接放在 repo：`gitlab/tests/data/gitlab-ci-schema/ci.json`（原檔，一個位元組都沒改），來源 gitlab-org/gitlab 的 `app/assets/javascripts/editor/schema/ci.json`，commit `28aa2bf90771a11ecc2f86525bc8a70a49c4d810`（2026-10-18），sha256 `1c6eeb7d3a34c39996afbfe1ade220480eb05bbeae674e86d3c745dfeeded7fd`（下載後核對過才放）。同資料夾有 `SOURCE.md`（來源與取檔日期）、`NOTICE`（上游原文）、`LICENSE.md`（兩種授權）。
- **授權核對（照實）**：該 commit 的根目錄 LICENSE 寫明 `ee/`、`jh/`、`doc/` 以外的內容與 client-side JavaScript 是 MIT Expat（GitLab Inc.），`ci.json` 不在那些目錄底下；但同一上游資料夾另有 `NOTICE`：Copyright Mads Kristensen、Apache License 2.0，沒有指名檔案。**推測** `ci.json` 源自 SchemaStore 的 gitlab-ci schema（未證實），所以兩種授權都保留（`LICENSE.md`）。dumpling 本身是 Apache-2.0，相容。記錄也在 `docs/PROVENANCE.md` 的「C3 GitLab 範本」。
- **驗證**：`tests/run.d/c3-gitlab-schema.sh` 每次都跑、執行時不連網。做法照 `tests/run.d/c2-x86-firmware.sh`：在 venv 裡裝 `tools/cra/tests/requirements.txt` 固定的 jsonschema（不另選版本；建不起 venv 或裝不起套件就 FAIL，與 c2 一致），用 `gitlab/tests/validate_schema.py`（Draft7Validator，與 `tools/cra/tests/cdx_schema.py` 相同做法）驗證；YAML 由系統 python3 的 PyYAML 轉成 JSON（測試輸出會印出 PyYAML 與 jsonschema 版本）；另跑一個故意弄壞的檔案，必須被擋下。
- **重要限制**：官方 schema 驗證通過，**只代表語法與欄位型別符合 schema，不保證範本在 GitLab 上一定跑得起來**（runner 標籤、變數是否存在、`rules` 邏輯、內部 GitLab 版本是否支援該語法，schema 都不管）。搬到 GitLab 後，**要用該 GitLab 實例的 CI Lint 再檢查一次**（已列入第 14 節檢查清單）。
- **更新 schema**：只由人手動做。`bash gitlab/fetch-ci-schema.sh [<commit>]` 下載到暫存資料夾、核對 sha256、印出新舊 sha256，**不覆蓋 repo 裡的檔**；步驟見 `SOURCE.md`。
- **不連網的規則測試**（`gitlab/tests/test_gitlab_ci.py`）：YAML 可解析；每個 job 有合法 stage 與 script／trigger；`extends`／`needs`／`!reference` 的目標都存在；無 `latest`、映像固定 digest 或固定版本；自訂變數名稱用 `DUMPLING_`／`WATCH_`／`INTERNAL_`／`PILOT_`／`MIRROR_`／`DT_` 開頭；所有 artifacts 明寫 `expire_in` 且不是 `never`；tag 規則在各處一致並通過正反例；watch 的 job 在 GitLab 後端完成前必為 `when: manual` 且要印 NOT_RUN；建 Issue 一定 confidential、不用 job token、不印 token、不 `set -x`；只有簽章 job 有 `id_tokens`；沒有 token／私有 IP 字面值。
- **CI**：`tests/run.sh` 會執行 `c3-gitlab.sh` 與 `c3-gitlab-schema.sh`，不需要改 `.github/workflows/tests.yml`；schema 的 jsonschema 版本與 c2 共用 `tools/cra/tests/requirements.txt`。T-13 改為：確認 CI 的 unit-tests 環境有 `python3-venv` 與 PyYAML（缺 PyYAML 時規則測試印 NOT_RUN，除非 `DUMPLING_REQUIRE_TEST_DATA=1`）。
- 內部 GitLab 還要用該版本的 CI Lint 再驗一次（0.2 節）。

---

## 12. 待辦清單（T-xx）

| 編號 | 內容 | 阻塞於 |
|---|---|---|
| T-01 | **已完成（2026-11-13，main cc7d101）**：核對 `gitlab/.gitlab-ci.yml` 呼叫的指令與 M2 合併後的版本。`project-info.py`、`run-step.sh`、`install-scan-tools.sh`、`install-tool.sh`、`firmware-*.sh` 的參數一致。獨立驗證另外找到並已修：scan 照現行 scan.sh 開臨時 DT（見 T-14）、sudo 與 platform.yml 的 apt、tag pipeline 不跑 validate 類 job（官方 job_rules：tag 的 push 也是 push）、firmware 補 sbomqs 品質檢查、watch 的 grype PATH 與結束碼。修了兩處：(1) `release-meta.py` 少了 `--scan-summary`（沒有它 report_status／release_gate 會是 NOT_RUN），已補；(2) M2 的 scan 會用 `KCVE_CACHE_DIR`（上一份核心 CVE 鏡像，`pipeline/lib/mirrors.sh`）→ 範本加 `.kcve-cache`（GitLab `cache:`，scan 與 watch:compute 共用，只存新抓的；scan 在 after_script 存、`cache:when: always`，失敗也存；watch:compute 要 `wp2/watch-m2` 合併後的 feeds.sh 才會讀 `KCVE_CACHE_DIR`）。官方（docs.gitlab.com/ci/caching）：cache 路徑要在專案資料夾內、預設存在 runner 那台機器（多台 runner 要設分散式 cache 才共用）、保護與非保護分支預設不共用。M7a（#58）之後補了 `--notes result/notes.md`（2026-11-14）：release.yml 用它重寫 notes.md 的 pipeline_result，跟 release-meta.json 一致（adapter-gaps #26），範本的 release-payload.py 拿同一份 notes.md 當 Release 說明。`gitlab/tests/test_gitlab_ci.py` 的 `test_t01_release_meta_same_flags_as_github` 從兩邊的指令抓參數名稱比對（不寫死清單），release.yml 加參數而範本沒跟上就失敗 | — |
| T-02 | dev 版專案清單改動態產生（child pipeline），取代範本的固定 `parallel:matrix` | 內部 GitLab 版本核對 |
| T-03 | `dev:publish`：滾動開發版 SBOM 在 GitLab 的存放（Generic Package 覆蓋行為待驗證）；每日監控 collect 讀取方式 | 內部環境驗證 |
| T-04 | `firmware:dt`：韌體 SBOM 上傳常駐 DT 的呼叫方式（`firmware-dt.sh` 的 pilot.env 與工作目錄） | 內部環境驗證 |
| T-05 | **已實作（2026-11-14，分支 wp5/gitlab-t05；沒有對真實 GitLab 驗證——只有假 API 的單元測試）**：Issue 一律 confidential：建立時寫死 `confidential: true`；修改既有 Issue（例如狀態 Issue）時也送 `confidential: true`（官方 PUT 的 `confidential`：Updates an issue to be confidential）；建立與修改的回應不是 confidential 就 FAIL。quick action：標題、內文或留言有「行首（可縮排）是 `/指令`」的行就**在任何寫入之前** FAIL（dry-run 也檢查；API 層另有第二道檢查）。行首從嚴：`\n` 以外，`\r`、`\v`、`\f`、NEL、U+2028／U+2029 之後也算，縮排可以是空白、tab、NBSP、全形空白（寧可誤擋）；**零寬字元、全形 ／ 開頭會不會被執行，待真實 GitLab 驗證**；狀態 Issue 的 base64 區塊在 GitLab 用 URL-safe 字母表（沒有 `/`，標準 base64 的行可能以 `/` 開頭被當成 quick action），`decode_state` 兩種都讀，GitHub 的格式不變。`--gitlab-url` 格式不合（非 https、帶帳密、`?`、`#`、不是 `/api/v4` 結尾）是用法錯誤（64），兩支工具規則相同。collect.py 對 GitLab 送 `Accept: application/json`（不送 GitHub 的 `vnd.github+json`）；token 標頭每次依網址核對，只送給 API 主機。`pipeline/watch/collect.py` 與 `issues.py` 有 `--backend github｜gitlab`（預設 github，行為不變、既有測試原封不動）。GitLab：`--gitlab-url`（`CI_API_V4_URL`，https，測試才允許本機 http；要以 `/api/v4` 結尾）、`--project`（數字 ID）、token 只從環境變數 `GITLAB_TOKEN` 讀（`PRIVATE-TOKEN` 標頭）。讀取用 `WATCH_GITLAB_READ_TOKEN`（`watch:compute`；scope `read_api`、角色 Planner），寫入用 `WATCH_GITLAB_TOKEN`（`watch:notify`；scope `api`）。**Issue 一律 `confidential: true`（程式寫死，`--confidential` 關不掉；測試檢查每一次建立）**；樂觀鎖（狀態 Issue 的 `updated_at`＋內容 sha256）、標籤自動建立、分頁、rate limit 重試、不跟隨轉址、token 不進輸出都沿用 GitHub 版。**尚未做**：`DUMPLING_WATCH_MODE`／`DRY_RUN`／`BASELINE` 手動輸入與 web／api 入口（T-16）；`watch:*` 仍 `when: manual`（等對真實 GitLab 驗證完再放開）。**依據的官方文件**：Issues API（docs.gitlab.com/api/issues/）：列表 `GET /projects/:id/issues?labels=<逗號字串>&state=opened｜closed｜all&per_page=100`、回傳 `iid`／`description`／`state`／`labels`（字串陣列）／`updated_at`；新增 `POST …/issues`（`title`、`description`、`labels` 逗號字串、`confidential` 預設 false）；修改 `PUT …/issues/:issue_iid`（`description`、`state_event=close｜reopen`、`labels`＝整組取代）。Notes API（/api/notes/）：`POST …/issues/:issue_iid/notes`（`body`）。Labels API（/api/labels/）：`GET`／`POST /projects/:id/labels`（`name`＋`color`，顏色要 `#` 開頭）。Releases API（/api/releases/）：`GET /projects/:id/releases`、`tag_name`／`released_at`／`assets.links[]`、`upcoming_release`。Releases 連結（/api/releases/links/）。Generic Packages（docs.gitlab.com/user/packages/generic_packages/）：`GET /projects/:id/packages/generic/:package_name/:package_version/:file_name`、`PRIVATE-TOKEN`。分頁（/api/rest/）：`per_page` 最大 100、`Link` rel=next、`x-next-page`。限流（docs.gitlab.com/administration/settings/user_and_ip_rate_limits/）：429、`Retry-After`、`RateLimit-Reset`（epoch 秒）。設計取捨：`labels` 在建立時是逗號字串（標籤名稱含逗號就拒絕）；`state_event` 只在目前狀態不同時才送（文件沒寫對已開著的 Issue 送 `reopen` 會怎樣）；沒有 draft Release → `upcoming_release: true` 當 draft（列在 `drafts`、不監控）；沒有 prerelease → `dev/<專案>` 滾動 Release 進 `skipped`（T-03 未決定，不先發明）；附件只收「本專案 Generic Package、同一個 API 主機」的連結，檔名取自網址，其他連結記 problem、不下載；內文或留言有以 `/` 開頭的行（可能被當 quick action 執行）→ 不送。**內部 GitLab 要驗證**：(1) 範本 `watch:*` 的 token 權限（`read_api`＋Planner 讀得到 confidential Issue；`api` 寫得進去）；(2) 建出來的 Issue 真的是 confidential、狀態 Issue 的 description 經 GitLab 存回後 `decode_state` 還解得開、`updated_at` 在讀取與寫入之間穩定（樂觀鎖）；(3) 文件沒寫的行為：標籤已存在時 `POST /labels` 的錯誤碼、對已開著的 Issue 送 `state_event=reopen`、quick action 在程式碼區塊內與縮排行會不會執行；(4) Generic Package 下載是否轉址到物件儲存（開了 direct download 時文件說會轉址；本程式不跟隨轉址，轉址就變成該附件的 problem）、`Link`／`x-next-page` 在反向代理後是否仍是同一個主機；(5) Release 連結是否都指向 Generic Package 網址（發行流程建的連結要符合 `…/projects/<ID>/packages/generic/<套件>/<版本>/<檔名>`，用數字 ID 不用路徑）；(6) 內部 GitLab 版本有沒有這些欄位（`upcoming_release`、`state_event`） | C2 的 WP2 後續（T-16、T-12 接著做；T-03 決定 dev 版收法） |
| T-06 | `feeds.sh` 加內部鏡像來源（`INTERNAL_MIRROR_URL`），資料來源改讀 sca-center 的鏡像 | 內部決定 |
| T-07 | DT parent／child 專案在常駐 DT 再評估（D-030(4)） | 常駐 DT 環境 |
| T-08 | 從 sca-center 帶回 `scripts/cra/alert_mail.py`（與測試），放 `tools/cra/`，在 `docs/PROVENANCE.md` 記來源 commit（D-015） | 需要自訂寄信時 |
| T-09 | cosign 執行檔固定版本＋sha256 進 `pipeline/lib/tools.lock`（`pipeline/install-tool.sh cosign`） | M7（A2） |
| T-10 | **倒數與 GitLab 後端已實作（2026-11-14，分支 wp5/gitlab-t10；沒有對真實 GitLab 驗證——只有假 API 的單元測試）；email 提醒還沒做。** `pipeline/watch/art14.py` 的 GitHub 呼叫全部改走 `issues.py` 的後端層（`Api`／`GitLabApi`），同一套指令邏輯跑在兩個後端；GitHub 行為不變（既有 `test_art14.py` 原封不動）。GitLab 用法：`--backend gitlab --gitlab-url <CI_API_V4_URL> --gitlab-project <數字 ID>`（注意：art14 的 `--project` 本來就是「專案資料夾」，所以 GitLab 專案 ID 用 `--gitlab-project`，和 `issues.py` 的 `--project` 不同）；token 只從環境變數 `GITLAB_TOKEN` 讀。**模式**：演練（`countdown --drill`、`open-drill`）＝標籤 `art14-drill`，演練與示範專案字樣照 GitHub 版，Issue 一律 confidential（後端寫死）；**真實**（`countdown` 不加 `--drill`）＝處理標籤 `art14` 的 Issue（第一行標記 `mode=real`）；新指令 `open-real --match … [--project projects/<專案>]` 開真實案件（私密、標籤 `art14`＋`art14-24h`、沒有演練與示範字樣、說明寫 GitLab 與私密）；**GitHub 上 `open-real` 一律拒絕（沒有任何 API 呼叫），GitHub 上不加 `--drill` 的 `countdown` 仍然是「找到 art14 Issue 就 FAIL」**。**信任**（取代 `author_association`＋`github-actions[bot]`）：Issue 作者、倒數留言的作者要是專案成員且 `access_level` ≥ 30（Developer），用 `GET /projects/:id/members/all/:user_id` 查（含繼承與受邀成員；要 `state == active`；同一個使用者一輪只查一次）；token 自己的使用者（project access token 的 bot 使用者）也是成員，所以工具寫的留言算在內；`system: true` 的留言一律不算倒數留言；偽造倒數標記的低權限留言不算（測試涵蓋 Reporter、Guest、blocked、非成員）。**外洩防線**：有 `art14`／`art14-drill` 標籤、卻不是 `confidential` 的 Issue → 整個 job FAIL、不寫入那個 Issue（不留言、不改標籤、不關閉；可能已經外洩，要人立刻處理），其他案件照常處理；工具建立或修改 Issue 時回應不是 confidential 也 FAIL（T-05 的規則）。**寫入前檢查**：所有要寫的文字（標題、內文、倒數留言、填知悉時間後的整份內文、關閉留言）先過 quick action 檢查（T-05 的 `QUICK_ACTION_RE`，行首 `/指令` 就整批不寫）；演練另外照舊要有「演練」字樣與公開檢查；GitLab 真實案件（內部儲存）不跑公開檢查、不要求「演練」字樣，但沒淨化的 Markdown（@提及、連結、圖片、HTML 實體）檢查照做。**範本**：`art14:countdown`（stage `watch`，排程 `DUMPLING_JOB=art14`，每小時；workflow 規則加上 art14）仍是 `when: manual`＋`allow_failure: true`（同 `watch:*`，驗證完再放開）；token 變數 `ART14_GITLAB_TOKEN`（project access token，scope `api`，角色 Developer 以上，protected＋masked；**和 watch 的 token 分開**，只有這個 job 用）；pipeline 變數 `DUMPLING_ART14_MODE=drill` 切成演練（預設真實）；結束碼 0 OK、1 FAIL；artifact `art14-out/result.json`。排程設定：每小時（例如 `7 * * * *`）、變數 `DUMPLING_JOB=art14`，擁有者規則同第 8 節。**依據的官方文件**（2026-11-14 逐頁讀過）：Notes API（docs.gitlab.com/api/notes/）：`GET /projects/:id/issues/:issue_iid/notes`（參數 `activity_filter`、`sort`、`order_by`；一次 20 筆，分頁看 /api/rest/）、`PUT …/issues/:issue_iid/notes/:note_id`（`body`）、`POST …/notes`（`body`）；回應有 `id`、`body`、`author{id,username,state}`、`system`、`internal`——**該頁沒有說明 `system` 欄位的語意**（只出現在範例回應，推定是 GitLab 自動產生的留言），這點待內部驗證；Project members API（docs.gitlab.com/api/project_members/）：`GET /projects/:id/members/all/:user_id`，回應 `id`、`username`、`state`、`access_level`；存取等級表（同頁）：Guest 10、Planner 15、Reporter 20、Security Manager 25、Developer 30、Maintainer 40、Owner 50（docs.gitlab.com/api/members/ 是 Group members 頁，同樣的等級表，Minimal access 是 5，只限頂層群組）；Issues API（docs.gitlab.com/api/issues/）：列表與單筆回應有 `confidential`（boolean）、`iid`、`state`、`labels`、`author{id,username,state}`（同頁另有 `author_id`、`confidential` 篩選參數，本程式沒用）。**內部 GitLab 要驗證**：(1) 不是成員時 `members/all/:user_id` 的回應（文件沒寫；程式把 HTTP 404 當「不是成員」，其他錯誤整個 FAIL）；blocked 使用者的 `state`；(2) `system` 留言的實際樣子（例如改標籤、改描述的活動紀錄），以及使用者手動留言一定是 `system: false`；(3) Notes 列表加 `per_page=100` 是否生效（notes 頁沒列 per_page；`x-next-page` 分頁照 /api/rest/）；(4) `ART14_GITLAB_TOKEN` 的角色與 scope 能讀 confidential Issue、查成員、寫留言與改 Issue；(5) confidential Issue 上留言的可見度（`internal` 欄位對 Issue 留言的語意；本程式不送 `internal`／`confidential`）；(6) 排程變數 `DUMPLING_ART14_MODE`、`DUMPLING_JOB` 在排程上的傳遞；(7) 依標籤列 Issue 剛建立或關閉後有沒有 GitHub 那種索引延遲（GitHub 實測有，見 ART14.md 第 9 節；GitLab 版沒有重試）；(8) 真實案件的 `open-real` 用 `projects/<專案>` 的 `project.yml`，內部儲存可放較多細節，但仍不放金鑰與個資。**還沒做（記為待辦）**：**email 期限前提醒**（ART14.md 第 10 節：期限前提醒負責人與備援人）——要內部的郵件設定（收件人放內部設定，不進公開 repo）與 T-08 的通知設定；Issue 指派（第 3 節）也還沒接。 | M4、M7 |
| T-11 | 簽章方案決定（第 9.2 節最後一欄） | 內部決定 |
| T-12 | 每日監控的「沒結果就告警」與排程巡檢（第 8 節） | T-05 |
| T-13 | 確認 CI 的 unit-tests 環境有 `python3-venv` 與 PyYAML（`tests.yml` 由 C0 負責，本工作包不改）；若需要改動先回報 | C0 |
| T-14 | **scan 的常駐 DT 模式**：`pipeline/platforms/*/scan.sh` 與 `pipeline/dt-ephemeral.sh` 目前一定開臨時 DT（要 docker）、覆寫 `PILOT_ENV`、自己抓公開鏡像、設 `MIRROR_REFRESH_STATUS=""`。要新增「連既有常駐 DT、讀 File 變數 PILOT_ENV、讀內部鏡像、檢查鏡像新鮮度」的模式；完成後範本的 `.scan-steps` 改連常駐 DT（第 4 節）。這些是 C1 的檔案。**C0 決定（2026-11-13）**：排給 C1、放在 M7 之後；做法是 scan.sh 多一個選項，改連既有的 DT（URL＋金鑰從環境變數讀），不傳這個選項時照舊開臨時 DT | C1，M7 之後 |
| T-15 | `dt-smoke.yml` 的 GitLab 版：T-14 之後改成「常駐 DT 連線與權限」的冒煙測試（T-14 之前 scan 本身就跑臨時 DT，不另搬） | T-14 |
| T-16 | 每日監控的演練（drill 三輪＋關閉）與 web／api 入口 | T-05 |
| T-17 | **已完成（2026-11-14，C0 決定）**：手動試跑 release＝網頁或 API 建 pipeline 時帶 `DUMPLING_RELEASE_DRY_RUN=1` 與 `DUMPLING_RELEASE_TAG=<專案>/<版本>`：跑 `release:build`、`release:scan`，`release:publish` 只驗證（`gitlab/release-publish.sh`），**不上傳 Package、不建 Release、不開 Issue**；`release:sign` 只在真的 tag push、而且不是試跑時跑（規則排除，腳本也檢查；簽章會寫進透明紀錄）。正式 release 的規則要 `$CI_PIPELINE_SOURCE == "push"`：在 tag ref 上從網頁或 API 手動建的 pipeline 也有 `CI_COMMIT_TAG`，沒帶 DRY_RUN 也不會發 Release。代替 GitHub 的「只建 draft Release」。測試：`test_t17_dry_run_pipeline_writes_nothing`（依 rules 求值，試跑 pipeline 自動跑的 job 沒有寫入）、`ReleasePublish.test_dry_run_writes_nothing`（假 curl：一次都沒呼叫）。沒有對真實 GitLab 驗證 | — |
| T-18 | `scan.tools: full` 需要 Go（GitHub 版 `setup-go`，govulncheck 用）：映像含固定版本的 Go，或範本補安裝 | 有專案改用 full 時 |
| T-19 | **已完成（2026-11-14）**：`validate:unit-tests`、`firmware:fetch` 在分支有開著的 MR 時，branch pipeline 不跑（`$CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH && $CI_OPEN_MERGE_REQUESTS` → never；官方 workflow 頁「避免重複 pipeline」的寫法）。放在 job 層級、不放 `workflow:rules`：dev/** 的 build／scan 只在 branch pipeline 跑，整條 branch pipeline 不能關。實際行為待內部驗證 | 內部驗證 |
| T-20 | **已完成（2026-11-14）**：NOT_RUN 一律結束碼 3。`dev:publish` 用 `allow_failure: {exit_codes: [3]}`（官方：列出的結束碼才算允許失敗，其他照常失敗）；`release:sign` 也一樣（沒開簽章或試跑是 NOT_RUN＝3，真的簽章失敗才是失敗）。`firmware:dt`、`watch:*`、網頁觸發的 `dev:*` 是**規則裡的 `when: manual`**：保留規則層級的 `allow_failure: true`，結束碼也改成 3。原因：官方 job_control 頁寫「rules 裡的 `when: manual` 預設 `allow_failure: false`，也就是 blocking manual job，pipeline 會停在那個 stage」，但沒寫 job 層級的 `allow_failure: {exit_codes: [3]}` 會讓手動 job 算 optional 還是 blocking；改了可能讓沒人按的手動 job 卡住整條 pipeline。**內部 GitLab 要驗證**：手動 job 加 `exit_codes` 後是否仍是 optional；是的話再改成只放過 3 | 內部驗證 |
| T-21 | **已完成（2026-11-14）**：`release:publish` 改呼叫 `gitlab/release-publish.sh`：先用 `release-payload.py --files-dir` 驗完全部附件（檔名安全、存在、是一般檔案、不重複），**驗不過一個檔都不上傳**，驗過才上傳 Generic Package、再建 Release。`release-payload.py` 只接受 `https://` 的 API 網址（內部也用 https）。上傳清單只用 release-payload.py 驗過後寫出的 `release-files.txt`（bash 不再自己解析 manifest：最後一行沒有換行、孤立的 `\r` 兩邊切行不同；manifest 有 `\r` 一律拒絕），上傳數要等於 Release 的連結數才建 Release。測試：`ReleasePublish`（假 curl：任何一個附件有問題時呼叫次數是 0；最後一行沒換行時照樣全部上傳；上傳回 HTTP 錯誤時不建 Release）。**TOCTOU（風險低，記一筆）**：驗證與上傳之間附件理論上可能被換掉；result/ 是同一個 job 從 artifact 解出來的暫存資料夾，只有這個 job 寫得到 | — |
| T-22 | 預設映像 `DUMPLING_IMAGE: ubuntu:24.04` 是版本標籤、不是 digest，apt 套件也沒固定版本：內部換成 RD 映像時固定 digest（第 5 節、第 14 節） | 搬移時 |
| T-23 | M8 B2 的支援期限檢查（`pipeline/watch/support.py`，WATCH.md 第 7 節）：範本的 `watch:compute` 在比對前加同一步（`--inventory`、`--out`；不加 `--demo`），`watch:notify` 用 `issues.py` 的 GitLab 版套用 stateless plan（私密 Issue）；FAIL 不擋每日監控的 Issue，另外讓 pipeline 變紅 | 跟 T-10 一起 |

---

## 13. 「官方文件沒寫，待內部環境驗證」彙整

1. protected tag 萬用字元是否跨斜線；tag 含斜線時 Release 的行為（第 1 節）。
2. Generic Package 同名同版本的同檔名上傳是覆蓋還是新增；套件名稱與版本的字元規則（第 2 節）。
3. Release／Package 的預設保存期限、專案刪除時的行為；instance 是否能強制 `expire_in` 上限、`expire_in: never` 是否被覆蓋（第 2 節）。
4. Issues API 各端點需要的 token scope（只知寫入要 `api`）；能建 Issue 的最低 token 角色；Free 層級單一指派參數（第 3、7 節）。
5. confidential Issue 的 email 通知是否只寄給有權限者（第 3 節）。
6. 排程閒置多久自動停用（文件沒提）；擁有者主動退出專案的行為；排程時區設定介面；排程 API 的狀態欄位（第 8 節）。
7. runner 產生的來源證明 metadata：最低 runner 版本、是否簽章（第 9 節）。
8. `cosign attest`／金鑰／KMS 的用法（非 GitLab 官方文件，要查 cosign 文件）（第 9 節）。
9. runner「只跑保護 ref」旗標在各層級的操作步驟（第 5 節）。
10. 常駐 DT 的 `pilot.env` 格式與權限模型（內部系統）（第 4 節）。
11. CI Lint 的操作與內部版本的語法支援（第 1、0.2 節）。

---

## 14. 搬移檢查清單

勾選前要有驗收證據（log、截圖或指令輸出，貼在搬移的 Issue）。

**環境與權限**
- [ ] 內部 GitLab 版本 ≥ 17.7，且 0.2 節的核對表全過。驗收：版本號與核對表結果。
- [ ] 建立專用專案（產品 repo 或發行專案），成員名單已審；真實案件所在專案可見度不是 Public。驗收：成員清單與可見度截圖。
- [ ] 保護 tag `*/v*`，只有 Maintainer 以上能建立；確認萬用字元行為（第 13 節 1）。驗收：非授權帳號推 tag 被拒。
- [ ] 保護分支（預設分支、`dev/*`）。驗收：直接推送被拒或符合團隊規則。

**runner 與映像**
- [ ] 三種標籤的 runner 上線，掃描／發行 runner 設為只跑保護 ref。驗收：未保護分支的 scan job 為 stuck。
- [ ] runner 符合第 5 節「跟 GitHub 代管 runner 相同的前提」：非 root 有免密碼 sudo、掃描 runner 有 docker（T-14 之前）、映像含 platform.yml 的 apt 套件（`DUMPLING_APT` 清空時）。驗收：一次 release:scan 的 log。
- [ ] `DUMPLING_IMAGE` 換成 RD 映像，固定 digest 或版本。驗收：`tests/run.d/c3-gitlab.sh` 通過、job log 的映像為預期版本。
- [ ] 編譯機磁碟與清理規劃完成，一次完整編譯後磁碟回復。驗收：job 前後 `df`。

**變數與機密**
- [ ] `WATCH_GITLAB_TOKEN`（scope api，只給 watch:notify）與 `WATCH_GITLAB_READ_TOKEN`（scope read_api、角色 Planner，只給 watch:compute）都是 Masked and hidden＋protected；T-14 之後再加 `PILOT_ENV`（File，protected）。驗收：非保護分支與 MR pipeline 看不到。
- [ ] project access token 的最小角色與 scope 確認，到期日已排提醒。驗收：記錄於交接文件。
- [ ] 外部資料來源改內部鏡像（第 6 節，T-06、T-14 之後）。驗收：外網斷線下 release:scan 成功。

**流程**
- [ ] 語法：官方 schema 驗證 OK（`c3-gitlab-schema.sh`）。驗收：腳本輸出。
- [ ] **搬到 GitLab 後，用該 GitLab 實例的 CI Lint 再檢查一次**（官方 schema 驗證通過不保證範本在 GitLab 上跑得起來）。驗收：CI Lint 結果截圖或輸出。
- [ ] 測試 tag 的完整 release：Package 檔案、Release 連結、sha256。驗收：第 2 節驗收項。
- [ ] 10 年保存方案：儲存、備份、還原演練、禁止刪除 tag／Release、不設自動清理。驗收：備份與還原紀錄、設定截圖。
- [ ] dev 分支與排程 dev。驗收：`dev/test` 分支與手動排程各跑一次。
- [ ] 韌體路徑改動觸發 `firmware:fetch`。驗收：改 `firmware/` 底下一個檔的 MR 出現該 job，改文件的 MR 沒有。

**監控與通知（T-05 完成後）**
- [ ] watch 的 GitLab 後端完成，`watch:*` 拿掉 `when: manual`。驗收：演練一輪（基準→新增→不重複→關閉）。
- [ ] 所有 Issue 為 confidential。驗收：第 3 節驗收項。
- [ ] 指派與 email 通知。驗收：被指派者收到信，無權限者沒收到。
- [ ] 排程 owner 已換成服務帳號，接手程序已文件化並演練。驗收：第 8 節驗收項。
- [ ] 每日無結果告警（T-12）。驗收：停掉排程一天，告警信寄出。

**簽章（T-11 決定後）**
- [ ] 方案決定並記入 DECISIONS。驗收：D-xxx。
- [ ] 正向與負向驗證在 CI 實跑。驗收：第 9 節驗收項。

**其他**
- [ ] DT parent／child 評估結論（T-07）。
- [ ] alert_mail.py 帶回與 PROVENANCE 紀錄（T-08，需要時）。
- [ ] 第 14 條通報的 GitLab 版（T-10，M8；倒數與後端已實作但未對真實 GitLab 驗證，email 提醒還沒做）。
- [x] 範本通過 M2 合併後的核對（T-01，2026-11-13）。
