# DASHBOARD：GitHub Pages 靜態儀表板（D-062，設計）

> 狀態：**設計已經 C0 同意（2026-11-15），還沒寫程式**（D-062 第 6 點：先交設計給 C0）。負責：C3（WP2）。
> 範圍：公開示範階段。DT 上線後的內部網頁另議（GitLab 搬移與公司 IT），本檔 §8 只寫「搬到 GitLab Pages 要改哪裡」。

## 1. 目的與不做的事

- 目的：不用 127.0.0.1、從任何裝置用瀏覽器看「每個專案、每個版本現在的狀態」與「每日監控開了哪些 Issue」，並直接下載報告包。
- 唯讀、靜態：頁面是 CI 產生的 HTML，**沒有伺服器、沒有 API、沒有登入、不架公開 DT**。
- 不是紀錄：頁面只是把已公開的資料（Release 附件、監控 Issue）整理成一頁；**權威來源仍是 Release 附件與 Issue**（§6）。頁面上看不到的東西不代表不存在，頁尾寫明。
- 硬性限制 5：只顯示 OK／GAP／ATTENTION／NOT_RUN／NOT_ASSESSED 原值，**不出現「安全」、整體 PASS、綠色勾勾這類總結**。沒有命中時寫「這次比對沒有新的已遭利用命中」，不寫「沒有風險」。

## 2. 資料來源（只用已公開的資料）

產生器 `pipeline/dashboard/build.py`（之後寫；Python `-I`），在 CI 裡讀下列資料，輸出 `site/`：

| 資料 | 從哪裡來 | 怎麼取 | 用在 |
|---|---|---|---|
| 專案清單 | repo 的 `projects/*/project.yml` | checkout | 產品名、`status`（development／shipped）、`support_until` |
| Release 清單 | Releases API（`GET /repos/{repo}/releases`） | `GITHUB_TOKEN`（contents: read） | **只取已發布的**（`draft == false`）：tag、`published_at`、`prerelease`、附件清單與下載網址 |
| 版本狀態 | 每個 Release 的 `release-meta.json` | 下載附件 | `report_status`、`release_gate`、`reports[]`（full／bsp／os 各自的狀態）、`pipeline_result`、`commit`、`built_at`、`workflow_run` |
| 掃描摘要 | `scan-summary-<專案>-<版本>.json` | 下載附件 | `vulnerabilities.<報告>.tiers`（p1／p2／p3／accepted／nvidia_bulletin）、`cves_total`、`components`、`runs.*.stages` 裡非 OK 的階段（GAP／NOT_RUN 清單）、`upstream_source`、`build_record_status` |
| VEX 判定統計 | `vex-<專案>-<版本>[-bsp|-os].cdx.json` | 下載附件（每份數 MB） | 依 `analysis.state`＋`justification` 計數（例：not_affected／code_not_present、in_triage） |
| 報告包下載連結 | Release 附件 | 只用 API 回的 `browser_download_url` | `report-*.zip`、`vuln-list-*.xlsx`、`p1-table-*.xlsx`、`sbom-*.cdx.json`、`vex-*.cdx.json`、`release-meta.json`、`scan-summary-*.json`、`build-record-*.json` |
| 監控狀態 | 狀態 Issue（標籤 `watch-state`，目前 #114） | Issues API（issues: read）＋ `issues.py` 的 `decode_state` | 基準時間、比對數、最後更新時間 |
| 最近一輪監控 | 最近一次 `watch.yml` 成功 run 的 artifact `watch-plan-real-1/result.json`、`watch-support-real-1/result.json` | Actions API（actions: read） | 每份 SBOM 的狀態、資料來源狀態、「每日沒有涵蓋的項目」（NOT_RUN）、支援期限各列 |
| 監控 Issue | 標籤 `dumpling-watch`（KEV、廠商層級）、`support-period`、`watch-health` | Issues API | 標題、編號、開／關、建立時間、標籤 |

不讀、不顯示：
- draft Release（還沒發布；公開頁不能早於 Release 公開）。
- 演練（`drill`、`*-drill-done`、`art14-drill`）。
- SBOM 內容本身（幾十 MB），只給下載連結，不複製到 Pages。

**每一筆來源都要有「抓不到」的處理**：附件缺、JSON 壞、schema 不認得 → 那一格寫 `GAP（原因）`，整頁照常產生。來源全部抓不到才讓 job 失敗，不部署空頁蓋掉舊頁。

## 3. 頁面欄位

只有一頁 `index.html`，另附 `data.json`（同一份資料的機器可讀版，方便之後別的工具讀；不含任何金鑰）。

**頁首**
- 產生時間（UTC）、產生用的 commit。
- 監控資料的時間：最近一輪 watch run 的編號與時間、狀態 Issue 編號。
- 狀態圖例：OK／GAP／ATTENTION／NOT_RUN／NOT_ASSESSED 各一句說明。
- 一句固定說明：「狀態只說明有沒有跑、資料齊不齊，不是對產品的保證」。

**A. 專案**（每個專案一列）

| 欄位 | 來源 |
|---|---|
| 產品名、專案鍵 | project.yml |
| 專案狀態（development／shipped） | project.yml |
| 支援期限、剩幾天 | project.yml、support result |
| 支援期限檢查結果 | support result |
| 最新正式版 | Releases |
| 開發版 | Releases |
| 開著的監控 Issue 數 | Issues |

**B. 版本**（每個已發布 Release 一區，新的在上面）
- 基本資料：tag、發布時間、正式版還是開發版（`prerelease`）、release-meta 的 `status`、commit。建置 run 連到 Actions。
- 狀態：full／bsp／os 三份報告各自的 `report_status`、`release_gate`，以及 `pipeline_result`。scan-summary 裡**不是 OK 的階段**逐一列出原值（例：`C-sbomgate GAP`、`C-mirror-freshness NOT_RUN`）。
- 漏洞統計：每份報告的 p1／p2／p3／accepted／NVIDIA 公告 計數、CVE 總數。數字照原樣，不加「通過」或「安全」。
- VEX 判定統計：state × justification 計數表。
- 下載：報告包與各附件的連結，附檔案大小。

**C. 每日監控**
- 最近一輪：時間、結果，連到 run。資料來源 CISA KEV、EUVD、核心 CVE、Grype DB 的狀態與時間。
- 每份 SBOM 的監控狀態，以及「每日沒有涵蓋的項目」（NOT_RUN 原文）。
- 監控 Issue 分三組列：KEV／廠商層級、支援期限、監控健康。每列有編號（連到 Issue）、標題、開／關、建立時間。預設只列開著的，已關閉的另外摺起來。
- 監控資料超過 48 小時沒更新：頁首加 `GAP：監控資料超過 48 小時沒更新`。這段由產生器判斷；頁面沒有 JS，所以也寫明產生時間，讓人自己看。

**頁尾**
- 權威來源是 Release 附件與 Issue。
- 本頁只列已發布的 Release。
- 本頁不保存歷史（§6）。

## 4. 安全設計

威脅：外來文字被當成 HTML 或連結；惡意 Release 附件或 Issue 內容讓頁面跑程式或導去別的網站；部署流程被 PR 拿去用；金鑰外洩到頁面。

- **全部用 HTML 跳脫**：所有字串都先經 `html.escape(s, quote=True)` 再輸出，包括：
  - 外來文字：CVE 說明、公告標題、套件名、元件名、Issue 標題。
  - 我們自己產生的檔案裡的字串，一律當外來文字處理。

  樣板不用會自動解讀 HTML 的引擎，只用 Python 字串組裝，加一個集中的 `esc()`。不輸出任何使用者可控的屬性名或標籤名。
- **連結白名單**：`href` 只允許三種：
  - `https://github.com/<本 repo>/releases/download/…`（附件）
  - `https://github.com/<本 repo>/issues/<數字>`、`…/actions/runs/<數字>`，用編號自己組，不用 API 回的任意網址
  - 本站內的相對路徑

  其他一律不出連結，只顯示文字。外部連結加 `rel="noopener noreferrer"`。
- **格式驗證**：CVE 編號用 `^CVE-\d{4}-\d{4,}$` 驗證，不合格就不當識別字、照文字跳脫顯示。狀態值只接受固定清單（OK／GAP／ATTENTION／NOT_RUN／NOT_ASSESSED／FAIL），其他值顯示成「不明（<跳脫後原值>）」，並列入頁首警告。
- **沒有 JS**：第一版不放任何 JavaScript，篩選、排序都不做，避免 XSS 的整個面。

  Content-Security-Policy 用 `<meta http-equiv>` 設定，因為 GitHub Pages 不能自訂 HTTP 標頭：

  ```
  default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'
  ```

  另外：
  - CSS 只用同站的 `style.css`，不用 inline style，所以不需要 `'unsafe-inline'`。
  - 不載入外部 CDN、字型、圖片。
  - `frame-ancestors` 在 meta 裡無效，GitHub Pages 也沒有標頭可設；頁面沒有可操作的東西，被嵌入的風險可以接受，所以記下來就好，不另做。
- **公開檢查**：部署前對 `site/` 跑和 pre-push 同一套 public-check，命中就不部署。另外對 HTML 檢查三件事：
  - 不能出現 `<script`、`on…=`、`javascript:`。
  - 不能出現「安全」、`PASS` 這類總結字樣。
  - CSP meta 必須存在。
- **權限（D-012）**：產生和部署拆成兩個 job。
  - build：`contents: read`、`issues: read`、`actions: read`。
  - deploy：只有 `pages: write`、`id-token: write`，`environment: github-pages`。

  其他規則：
  - 第三方 action 一律固定 commit SHA（D-012；見 §10 第 4 點），用 `actions/upload-pages-artifact`、`actions/deploy-pages`。
  - **只從 main 部署**，不接 `pull_request` 觸發，fork PR 碰不到部署。
- **不放金鑰**：只用 `GITHUB_TOKEN`，而且只在 build job 的環境變數裡，產生器不把環境變數寫進輸出。`data.json` 只放白名單欄位，不放整份 API 回應。

## 5. 多久更新一次

`.github/workflows/pages.yml`（之後寫）的觸發方式：

| 觸發 | 時機 | 備註 |
|---|---|---|
| `workflow_run`：`watch` 完成 | 每日監控之後，排程每天 01:17Z，實際可能晚好幾小時 | 演練（mode=drill）也會觸發，頁面內容不變（演練 Issue 不列） |
| `workflow_run`：`dev` 完成 | 開發版發布後 | |
| `workflow_run`：`release` 完成 | 正式 Release 發布後（tag push） | 手動建 draft 的 run（workflow_dispatch）不更新；draft 本來就不列 |
| `workflow_dispatch` | 手動 | 只能在 main 上跑（`github.ref == refs/heads/main`） |

**`workflow_run` 要依來源各自判斷**（C0 指出，2026-11-15）。tag 觸發的 release run，`workflow_run.head_branch` 是 tag 名稱，不是 `main`；如果只收 `main`，正式 Release 就不會更新頁面。

| 來源 | `workflow_run.event` | `workflow_run.head_branch` |
|---|---|---|
| watch、dev | `schedule`、`workflow_dispatch` 或 `push` | 必須是 `main` |
| release | 必須是 `push` | 必須符合 `<專案>/<版本>` 的 tag 格式，而且不是 `dev/…`。驗證用 `pipeline/watch/collect.py` 的 `PROJECT_RE`、`VERSION_RE`（`classify` 回 `release` 的那種），與 release.yml 的 `*/v*` 觸發條件一致；不在 workflow 裡另寫一份 regex |

三種來源還有兩條共同規定：
- 一律要求 `workflow_run.head_repository.full_name == github.repository`，也就是 run 必須出自本 repo，不能來自 fork。
- 一律要求 `workflow_run.conclusion` 不是 `cancelled`。`failure` 照樣更新，因為頁面要能顯示失敗。

不符合任何一條就跳過，不更新頁面。來源 repo、event、conclusion、watch／dev 的 `main` 這幾條寫在 build job 的 `if:`，不符就 skipped。release 的 tag 格式由 build 的第一步呼叫 collect.py 判斷；不符就輸出 `go=false`，不產生 artifact。deploy 依賴 build，而且要求 `go == 'true'`。另外，觸發只是「該更新了」的訊號：頁面資料一律重新從 API 讀，不用 `workflow_run` 帶進來的任何欄位（分支名、標題）產生內容。

- 實際約一天一次，加上每次發布。同一時間只跑一個（`concurrency: pages`，不取消進行中的）。
- 不另外設排程，避免多一個要防 60 天停用的 workflow。watch 每天都跑，產生時間就會每天更新。watch 如果停了，頁面時間也停住，看頁首就知道。

## 6. 歷史要留多久、和 CRA 10 年保存的關係

- GitHub Pages 只保留最新一次部署，**頁面本身沒有歷史**，這是刻意的。頁面每次都從權威來源全部重算，不會累積出另一份「第二套紀錄」，也不會和來源不一致。
- 版本歷史：頁面列出所有**還在的已發布 Release**。Release 不會過期，所以舊版本會一直列著。
- 監控歷史：Issue 永久保留（含已關閉的），頁面列出編號與連結。狀態 Issue 的編輯歷程留在 GitHub。
- 每日監控的 artifact 只保留 14 天，`result.json` 不是長期紀錄。頁面只用它顯示「最近一輪」，**不**把它當歷史保存。
- CRA 10 年保存：PLAN 寫明「長期紀錄靠 Release；10 年保存是內部 GitLab 階段的事」，地點是 GitLab Release 或內部檔案庫。**儀表板不承擔保存責任**：
  - 公開階段的紀錄是 Release 附件與 Issue。
  - 內部階段的紀錄是內部檔案庫。
  - 頁面只是看那些紀錄的窗口。
- 如果之後要「某一天的儀表板長什麼樣」，做法是每次 Release 時把當下的 `data.json` 當附件一起上傳，隨 Release 保存。這要改 release.yml，屬於 C1 的範圍，第一版不做，列為待決定。

## 7. 開啟 Pages 需要的 repo 設定（由使用者設定）

1. Settings → Pages → Build and deployment → Source 選 **GitHub Actions**。不選「Deploy from a branch」，所以不需要 `gh-pages` 分支，也不會有東西被推進 repo。
2. Settings → Environments → `github-pages`（第一次部署時自動建立，也可以先建）：
   - Deployment branches 設成 **Selected branches：`main`**。
   - 不加任何 environment secret。
3. 不設自訂網域。網址是 `https://<帳號>.github.io/dumpling/`，HTTPS 預設強制。
4. repo 是公開的，Pages 也是公開的。內容只有已公開的資料，不另外加存取控制，公開 repo 也沒有這個選項。

設定完成前 pages.yml 的 deploy job 會失敗，但不影響其他 workflow。build job 照樣可以產生 artifact，供人預覽。

## 8. 搬到 GitLab Pages 要改哪裡

| 項目 | GitHub | GitLab |
|---|---|---|
| 觸發 | `workflow_run` | 監控與 release pipeline 的最後一個 stage 加 `pages` job，或用 `trigger:` 觸發下游 pipeline；`rules` 只在預設分支 |
| 部署 | `upload-pages-artifact`＋`deploy-pages` | `pages` job，`artifacts: paths: [public]`；產生器輸出目錄改成 `public/` |
| Release 資料 | Releases API、`browser_download_url` | `GET /projects/:id/releases`，附件走 release links 或 generic package registry；連結白名單改成內部 GitLab 的網址前綴 |
| Issue 資料 | Issues API、標籤 | Issues API（`issues.py` 已有 GitLab 後端，見 GITLAB-PORT T-05）；**confidential Issue（art14 真實案件）一律不列，只列筆數**，或整頁開存取控制 |
| token | `GITHUB_TOKEN` | `CI_JOB_TOKEN` 讀不到 Issues API，要用 project access token（`read_api`、masked＋protected 變數）；只在 build job 用 |
| 存取控制 | 公開 | **開 GitLab Pages access control**（只限專案成員），內部頁面不能公開 |
| CSP | `<meta http-equiv>` | 一樣用 meta。GitLab Pages 能不能自訂標頭，要在內部環境確認（列入 GITLAB-PORT 待辦） |
| 監控 artifact | Actions API | Jobs artifacts API |

產生器從一開始就分兩層：
- 資料來源介面：`--backend github|gitlab`，比照 `issues.py`。
- HTML 輸出：與平台無關。

搬移時只換資料來源那一層。

## 9. 測試與驗收（寫程式時要做到）

- 單元測試：
  - 惡意字串（`<script>`、`"><img onerror=…>`、`javascript:`、`@提及`、超長字串、控制字元）出現在元件名、Issue 標題、狀態值時，輸出都被跳脫或擋下。
  - 不在白名單的網址不會出現在 `href` 裡。
  - 不認得的狀態值會顯示成「不明」。
  - 輸出裡沒有「安全」或 PASS 字樣。
  - CSP meta 存在。
- 觸發條件：把 §5 的 `if:` 抽成一個可以測試的函式，或用 `gitlab/tests/gitlabci.py` 那種表達式求值器來測。每一種情況都要有測試：
  - watch、dev 在 `main` 上，事件是 schedule、workflow_dispatch、push → 更新。
  - watch、dev 在其他分支 → 跳過。
  - release 由 `orin-nano-demo/v39.2.1-demo1` 的 tag push 觸發 → 更新。
  - release 是 workflow_dispatch（draft） → 跳過。
  - release 的 `head_branch` 不符合 tag 格式，例如 `main` 或 `feature/x` → 跳過。
  - `head_repository.full_name` 是 fork → 三種來源一律跳過。
  - `conclusion: cancelled` → 跳過。
- 用現在的公開資料試產生一次：
  - 3 個 Release（v39.2.0、v39.2.1、dev）、6 份 SBOM、狀態 Issue #114、4 個支援期限 Issue 都要出現。
  - draft 與演練 Issue 不能出現。
- 驗證代理照 D-048 另外派，effort 用 high（安全相關）。

## 10. 已決定（C0，2026-11-15）

1. **第一版不放 JS**：沒有篩選和排序，只靠瀏覽器的頁內搜尋。之後如果要加，只放同站的 `script.js`，CSP 加 `script-src 'self'`。
2. **`data.json` 當 Release 附件保存**（§6）：列入第二階段，現在不做。
3. **已關閉的監控 Issue**：全部列出，預設摺起來。摺起來用 HTML 的 `<details>`，不需要 JS。
4. **固定 action SHA**：依據是 D-012。D-062 第 5 點寫成 D-027，C0 會在下一批 DECISIONS 更正。
5. **`workflow_run` 依來源各自判斷**（§5），測試寫在 §9。
