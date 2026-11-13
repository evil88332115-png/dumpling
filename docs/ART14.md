# ART14：CRA 第 14 條通報工作流程（WP2，M8 的 B1；GitHub 演練版）

來源：`docs/references/cra-plan-proposal.md` 的 B1、`docs/DECISIONS.md` D-033 第 (3) 點。程式：`pipeline/watch/art14.py`；排程：`.github/workflows/art14.yml`；測試：`pipeline/watch/tests/test_art14.py`。
**公開 repo 只做演練**（合成資料、標籤 `art14-drill`）。真實案件只開在 GitLab 的私密 Issue（見第 8 節）。

## 1. 流程

1. **偵測**（M4 每日監控，已完成）：KEV／EUVD 命中會開監控 Issue，`first_detected` 只是**候選**，不是知悉時間。
2. **開 art14 Issue**：負責人判斷「產品受影響而且漏洞被積極利用」後開（GitHub 只開演練版 `art14-drill`；嚴重事件不會由監控自動偵測，只提供人工開 Issue 的範本）。
3. **填知悉時間（UTC）**：只有負責人能決定。倒數**只從這個欄位**算。沒填時顯示「時鐘未起算（待確認）」與從 `first_detected` 起已經過幾小時。
4. **三階段通報**：每一階段在 SRP（ENISA 單一通報平台）**人工**提交，再把提交編號、提交人、提交時間（UTC）填回 Issue。SRP 沒有 API，工具不做任何自動提交。
5. **倒數留言**：排程每小時更新同一則留言與階段標籤；有「提交時間」的階段標完成。
6. **結束**：全部階段完成後階段標籤全部拿掉，Issue 由人關閉。

倒數只是輔助，GitHub 排程可能延遲，期限由負責人自己掌握。不在公開 Issue 放任何機密。

## 2. 法規出處與核對（2026-11-13，C3 從 EUR-Lex CELEX:32024R2847 讀到，OJ L 2024/2847, 20.11.2024）

| 條款 | 內容（摘要） |
|---|---|
| 第 14(1) 條 | 製造商知悉（becomes aware of）其產品中被積極利用的漏洞時，同時通知協調 CSIRT 與 ENISA（經第 16 條的單一通報平台） |
| 第 14(2) 條 | (a) 早期預警：without undue delay and in any event within 24 hours of the manufacturer becoming aware of it（寫明已知產品在哪些會員國販售，where applicable）；(b) 漏洞通報：within 72 hours of becoming aware；(c) 最終報告：no later than 14 days after a corrective or mitigating measure is available |
| 第 14(3) 條 | 嚴重事件（severe incident having an impact on the security of the product）同樣同時通知協調 CSIRT 與 ENISA |
| 第 14(4) 條 | (a) 早期預警 24 小時內（寫明是否疑似非法或惡意行為造成）；(b) 事件通報 72 小時內；(c) 最終報告：within one month after the submission of the incident notification under point (b) |
| 第 71 條 | Article 14 shall apply from 11 September 2026（本規則一般自 2027-12-11 適用） |

## 3. 期限規則：工具算保守值，精確解釋交給法務

**沒有核對、不宣稱**：期間的法定計算規則（是否適用期間計算的一般規則、小時與日的起算細節）。工具一律算**保守值**，`deadlines()` 的規則：

| 階段 | 起算點 | 期限（UTC） |
|---|---|---|
| 漏洞 1 早期預警 14(2)(a) | 知悉時間 | + 24 小時（整點秒數） |
| 漏洞 2 漏洞通報 14(2)(b) | 知悉時間 | + 72 小時 |
| 漏洞 3 最終報告 14(2)(c) | 修正或緩解措施可用時間 | + 14 × 24 小時 |
| 事件 1 早期預警 14(4)(a) | 知悉時間 | + 24 小時 |
| 事件 2 事件通報 14(4)(b) | 知悉時間 | + 72 小時 |
| 事件 3 最終報告 14(4)(c) | 事件通報（階段 2）送出時間 | 下個月同一日同一時刻；那一天不存在就取該月最後一天同一時刻 |

- 例：2028-01-31 → 2028-02-29（閏年）；2027-01-31 → 2027-02-28；12 月跨年 2026-12-15 → 2027-01-15。
- 全部 UTC。程式內的時間一定要帶時區（沒時區的拒絕，不猜），Issue 欄位只接受 `YYYY-MM-DDTHH:MM:SSZ`。
- 沒有起算點的階段期限是空的，並寫原因（「知悉時間未填」「修正或緩解措施可用時間未填」「事件通報送出時間未填」）。
- **措施可用時間（或事件通報送出時間）早於知悉時間**：不算期限，倒數留言寫「早於知悉時間，請確認」並把最終報告標成未起算；`deadlines()` 對這種輸入丟 `DeadlineError`。理由：多半是打錯，而措施在知悉前就已可用時，14 天怎麼算是法律判斷，交給法務。
- 工具不判斷「是否已知悉」、不判斷監管機關是否認定更早的知悉時間、不判斷嚴重事件是否成立。
- **交給法務的參考（未核對）**：歐盟法規的期間一般適用 Regulation (EEC, Euratom) No 1182/71（期間、日期與期限的規則）。依那份規則，
  以小時計的期間，事件發生的那一個小時通常不計入，所以法定期限可能比「知悉時間＋24h」晚一點；以日、月計的期間也有自己的起訖規則。
  1182/71 實際怎麼適用在 CRA 第 14 條，C3 與 C0 都**沒有核對原文**。**工具採較早的保守值**（上表），寧可提早，不會晚於法定期限的任何合理解釋。

## 4. Issue 內文與欄位（程式解析的契約）

- 第一行：`<!-- dumpling-art14 key=<64 hex> kind=vulnerability|incident mode=drill -->`。key ＝ sha256(`dumpling-art14/1|mode|kind|產品|版本|層|CVE`)（嚴重事件用事件代號），同一個命中只開一個。
- 演練的**第二行固定**是 `演練，不是真實通報`，標題有 `[演練]`；寫入前檢查沒有「演練」字樣就不寫。
- 公開 repo 的演練照 D-040 (3) 寫明示範專案（C0 決定）：標題 `[演練] [示範專案（公開 BSP）] …`，內文第二行之後與倒數留言有一行「示範專案（公開 BSP）」說明，標籤加 `demo`（關閉後保留）。
- 預填（工具帶入，人核對）：產品名稱與版本、層（bsp／os／product）、CVE 與說明、被利用的依據（KEV／EUVD／廠商公告）、受影響版本、`first_detected`（候選）、嚴重度（沒有來源寫「待填」，不猜）、銷售市場與公司角色（見第 7 節）。
- 要人填的欄位（解析器只認這些行的開頭）：
  - `- 知悉時間（UTC）：`
  - 漏洞：`- 修正或緩解措施可用時間（UTC）：`；嚴重事件：`- 事件通報送出時間（UTC）：`、`- 是否疑似非法或惡意行為造成：`
  - 每個階段（`## 階段 N：…` 底下）：`- SRP 提交編號：`、`- 提交人：`、`- 提交時間（UTC）：`
  - 說明文字欄（措施說明、要通知用戶的內容）：不解析，不要放機密。
- 值只能是 `YYYY-MM-DDTHH:MM:SSZ` 或 `未填`。**解析器嚴格**：格式不對、欄位被刪、欄位重複都當成「未填」，倒數留言寫「格式不對」。階段的**提交時間有填就標完成**（晚於期限會註明「晚於期限」）。
- 內文有 SRP 人工檢查清單（登入 SRP、選協調 CSIRT＝主要營業地所在會員國、貼上預填欄位、把編號與時間填回）與法規出處／核對日期。

### 4.1 GitLab：要人填的欄位用「art14 紀錄」留言記錄（內文的時間不算數）

GitLab 的權限設計是：Planner（15）與 Reporter（20）也能改別人 Issue 的內文，但別人的留言只有 Maintainer／Owner 能改。
如果照 GitHub 版從內文讀時間，權限低的人可以把知悉時間與三個提交時間寫進內文，偽造「已通報」，或改知悉時間延後期限（#85 驗證應修 1）。
所以在 GitLab 上，**倒數的依據只取自 Developer（30）以上成員的「art14 紀錄」留言**；內文的「要人填的欄位」一節只當說明，工具只從內文讀它自己預填的 `first_detected`。

格式（第一行固定是 `art14 紀錄`；之後以 `- ` 開頭的行是欄位，其他行是說明、不解析）：

```
art14 紀錄
- 知悉時間（UTC）：2026-11-13T00:00:00Z
- 修正或緩解措施可用時間（UTC）：未填
- 階段 1 SRP 提交編號：<SRP 給的編號>
- 階段 1 提交人：<名字>
- 階段 1 提交時間（UTC）：2026-11-13T20:00:00Z
負責人確認後記錄（這一行是說明，不解析）
```

- 認得的欄位：漏洞是 `知悉時間（UTC）`、`修正或緩解措施可用時間（UTC）`；嚴重事件是 `知悉時間（UTC）`、`事件通報送出時間（UTC）`；各階段是 `階段 N SRP 提交編號`、`階段 N 提交人`、`階段 N 提交時間（UTC）`（N 是 1–3）。
- 可以分好幾則留言記；同一個欄位**以最新的留言為準**，寫 `未填` 就清掉。時間格式同上（`YYYY-MM-DDTHH:MM:SSZ`）。
- 不可信的人（不是 Developer 以上的成員）寫的紀錄留言不算數；看不懂的欄位行、格式不對的時間，倒數留言會寫明，**真實案件整個 job FAIL**（請人修正）。
- 演練（`fill-drill-aware`）在 GitLab 上也是新增一則紀錄留言，不改內文。
- **近似但不合格式的紀錄不會靜默**：可信成員寫的留言，如果第一行有多餘空白或大小寫不同（`ART14 紀錄`）、整則包在 ``` 或 ~~~ 程式碼區塊或引用裡、或欄位行縮排，工具**不解析**，並報問題「疑似紀錄、沒有解析」（寫在倒數留言與 result 的 `problems`）。程式碼區塊裡的行永遠不當欄位。真實案件的紀錄問題一律 FAIL（同上），演練只顯示、不 FAIL。`system` 留言（GitLab 自動產生）永遠不當紀錄、也不當倒數留言。
- **kind／mode 的來源**：取自 Issue 內文第一行標記；標記不合法、mode 不符的 Issue 在真實模式會 FAIL（不是靜默略過）。GitLab 真實案件有登錄（4.2）後，kind 以登錄為準，內文標記和登錄不符一樣 FAIL。
- GitHub（公開 repo，只有演練）維持從內文讀：GitHub 上能改別人 Issue 內文的人要有 write 權限，本來就是可信作者（OWNER／MEMBER／COLLABORATOR）。

### 4.2 GitLab：真實案件的登錄（registry）——標籤被拿掉也不會停

Reporter／Planner 能拿掉 `art14` 標籤、改內文標記（官方 permissions 頁：編輯 Issue 含標籤與 confidential，所有角色都可）；Planner 還能刪任何 Issue。只靠標籤或內文標記找案件，法定倒數會靜默停掉。
所以真實案件另外**登錄**在一個固定編號的 confidential「登錄 Issue」（人工建立，編號放 CI/CD 變數 `ART14_REGISTRY_ISSUE`，或 `--registry-issue`；只有 Maintainer 能改變數）。登錄只看它的**留言**：作者 Developer 以上、非 system、第一行剛好 `art14 登錄`、每行 `- 案件 #<iid> key=<64 hex> kind=vulnerability|incident`；只追加，內文、標籤、狀態都不看。
Reporter／Planner 改不了別人的留言（推定，待內部驗證），也寫不出可信的留言。

- `open-real` 開案後登錄；沒設登錄 Issue 就不開。同一個命中已登錄就不重開（標籤被拿掉也一樣；Issue 不見了就 FAIL）。
- `countdown`（真實）每輪讀登錄，用 iid 直接取案件。**FAIL**：案件不見了（404）、不是 confidential、作者不可信、沒有 `art14` 標籤、標記和登錄不符、登錄沒設或讀不到。拿掉標籤或改壞標記的案件仍照登錄的 kind 繼續倒數。標籤找到、可信、標記正確、還沒登錄的案件由 countdown 補登錄。
- 已關閉的真實案件（標籤找到或已登錄）還有未提交的階段 → FAIL（列在 result 的 `closed`）；逐案隔離。
- result.json 的 `registry` 是登錄快照（登錄 Issue 被刪時人工補回用）。
- 殘留風險：Planner／Owner 能刪登錄 Issue 本身、Maintainer 能刪留言——登錄不見了每輪 FAIL，不會變成「沒有案件」；Developer 以上本來就是可信成員。

## 5. 倒數與標籤

- `countdown --repo R --drill [--now UTC]`：列出開著的 `art14-drill` Issue → 解析 → 更新倒數留言與階段標籤。**沒有可處理的案件就印一行、立刻結束（OK）**。
- **只處理作者是 OWNER／MEMBER／COLLABORATOR 的 Issue**（`author_association`）；另外接受 `github-actions[bot]`（type=Bot）——工作流程用 `GITHUB_TOKEN` 開的 Issue 實測是 `author_association=NONE`，見第 9 節。其他作者的 Issue 略過並列出。
- 倒數留言只維護一則：第一行是 `<!-- dumpling-art14-countdown -->`，用它找（留言者也要可信，偽造的標記留言不算），找到就編輯、內容沒變就不寫，找不到才新增。
- 階段標籤 `art14-24h`／`art14-72h`／`art14-final`：跟著「下一個未完成的階段」，只留一個、其他拿掉；全部完成就全拿掉；其他標籤不動。
- 沒有 `--drill` 的 `countdown`：在 GitHub 上找到開著的 `art14` Issue 就 **FAIL**（公開 repo 不該有真實案件），不修改它。沒有 `art14` Issue 就 OK。
- 排程：`7 * * * *`（每小時，避開整點）。多用的 Actions 時間：沒有案件時一個 job 很短（估計約半分鐘，未實測；D-033 第 3 點）。

## 6. 指令

```
python3 -I pipeline/watch/art14.py open-drill       --repo O/R --match tests/fixtures/watch/art14-drill-match.json [--result r.json]
python3 -I pipeline/watch/art14.py countdown        --repo O/R [--drill] [--now UTC] [--result r.json]
python3 -I pipeline/watch/art14.py fill-drill-aware --repo O/R --at UTC [--result r.json]    # 只改 art14-drill Issue 的知悉時間
python3 -I pipeline/watch/art14.py close-drill      --repo O/R [--result r.json]             # art14-drill → art14-drill-done，關閉
python3 -I pipeline/watch/art14.py check            --result r.json --expect 路徑=值 …       # 驗收用，路徑以點分隔，數字是陣列索引
```
stdout 最後一行 `ART14<TAB>OK|FAIL<TAB>說明`；結束碼 OK 0、FAIL 1、用法 64。GitHub API 一律用 `issues.Api`（token 只放標頭、不跟隨轉址、http 只限本機、rate limit 重試）；寫進 Issue 的文字先過 `publiccheck.check_text()`，命中就不寫。

合成命中格式（`schema: dumpling-art14-drill-match/1`）：`kind`（vulnerability｜incident）、`product`、`version`、`first_detected`；漏洞另有 `layer`、`cve`、`description`、`affected_versions`、`exploited_evidence[{source: KEV|EUVD|vendor, note, ref}]`；嚴重事件另有 `incident_id`、`summary`；選填 `severity`＋`severity_source`（沒有就寫「待填」）。範例：`tests/fixtures/watch/art14-drill-match.json`（CVE-2018-18074、requests 2.19.0、drill-demo v1.0.0、bsp）。

## 7. 專案資訊：銷售市場、產品名稱、公司角色（D-055，M7a 的 `project.yml`）

`open-drill --project projects/<專案>` 用 `pipeline/lib/project_config.load_project` 讀 `project.yml`（含和 `CRA/Config/config.json` 的一致性檢查；不合格就 FAIL、不開 Issue）。欄位定義見 `docs/PLATFORM-INTERFACE.md` 3.1–3.2。

- **銷售市場（會員國）**，第 14(2)(a) 條早期預警要寫明（適用時）：
  | `markets` | Issue 寫的 | result 的 `markets` |
  |---|---|---|
  | 會員國代碼（ISO 3166-1 alpha-2，希臘 GR） | `DE、FR（ISO 3166-1 alpha-2；來源 project.yml）` | `codes` |
  | `EU-ALL`（舊值 `EU` 由 load_project 遷移成它） | `全歐盟（EU-ALL，不逐一列出會員國；來源 project.yml）`，**不展開成 27 國** | `eu-all` |
  | `UNKNOWN`（明確不知道） | **GAP**：銷售市場不明，早期預警不能依會員國通知；請人工確認後填寫 | `unknown` |
  | `TO BE COMPLETED`（還沒填） | **GAP**：markets 還沒填；請人工填寫已知販售的會員國 | `todo` |
  | 沒給 `--project` | **GAP**：沒有指定專案，讀不到 markets；請人工填寫 | `no-project` |
- **產品名稱以 `project.yml` 的 `product_name` 為準**；版本照命中（＝Release tag 的版本，D-055 (3)）。Issue 的 key 不含名稱，改名不會讓同一個命中重開。
- **公司角色**：`company_role` 寫進預填欄位；`supplier` 時加一句「第 14 條是製造商的義務，供應商的角色怎麼適用交給法務判斷」。
- `load_project` 的警告（例如舊值 `EU` 已遷移）只印到日誌（`WARN`），不寫進 Issue。
- 演練（`art14.yml`）用 `projects/orin-nano-demo`（`EU-ALL`），驗收 `markets=eu-all`。

## 8. 演練步驟（`art14.yml`，`action=drill`）

1. `open-drill`（知悉時間未填）→ 驗收：`result=opened`
2. `countdown --now 2026-11-13T06:00:00Z` → 驗收：時鐘未起算、first_detected 起 6 小時、新增一則留言、標籤 `art14-24h`
3. `fill-drill-aware --at 2026-11-13T00:00:00Z`
4. `countdown` → 驗收：24h 期限 `2026-11-14T00:00:00Z`、72h `2026-11-16T00:00:00Z`、最終報告期限空（措施未填）、留言是編輯不是新增
5. 再跑 `open-drill` → 驗收：`result=skipped`（不重複開）
6. `close-drill` → 驗收：關閉 1 個；再 `countdown` 沒有案件。任何一步失敗，job 失敗，並收掉演練 Issue。

每一步以 `--result` 輸出 JSON，下一步用 `check` 比對。**新 workflow 不在預設分支時 `gh workflow run` 會 404**：合併前無法在分支上觸發，CI 驗證靠單元測試；合併後再手動跑 `action=drill`（M8 合併後的待辦）。

## 9. 在 GitHub 上實跑的結果與還沒驗證的地方

- 2026-11-13：合併前用暫時的分支 push 觸發（只限 wp2/art14，跑完已拿掉）在 GitHub 上實跑 `action=drill` 六步：run 43369037768（40f3fb5）、
  43369266378（fa42238）都綠。演練 Issue #37、#38：開 → 時鐘未起算 → 填合成知悉時間 → 24h／72h 期限正確、同一則倒數留言被編輯 → 不重複開 → 關閉並換成 `art14-drill-done`。
- 實跑才發現的：依標籤列 Issue 剛建立／剛關閉後有索引延遲（第一次 run 43368765916 在步驟 2 列不到剛開的 #36 而失敗、失敗時的清理也列不到）。
  演練步驟改成重試（每 10 秒、最多 2 分鐘），countdown 跳過列表裡已關閉的 Issue。每小時的排程不受影響（Issue 早就開好了）。

- 用 `GITHUB_TOKEN` 建立的 Issue：**實測 `author_association` 是 `NONE`**（2026-11-13，每日監控演練開的 Issue #21 與它的留言：`user.login=github-actions[bot]`、`type=Bot`、`author_association=NONE`）。
  所以只看 OWNER／MEMBER／COLLABORATOR 會把自己的演練 Issue 略過；程式另外接受 `user.login == github-actions[bot]` 且 `type == Bot`（必要，不能拿掉）。
  能以 github-actions[bot] 身分寫 Issue 的只有本 repo 的 workflow（有 `issues: write` 的 job）；外部人士的 fork PR 拿到的是唯讀 token，repo 也沒有 `pull_request_target`。
- 公開 repo 的 `art14-drill` 標籤只有有 triage 以上權限的人能加，這是額外的一層，但不是唯一一層（作者檢查）。

## 10. GitLab 階段：GitHub → GitLab 對應（倒數已實作，T-10；email 還沒做）

實作狀態（2026-11-14，分支 wp5/gitlab-t10）：`art14.py` 的 GitLab 後端與 `art14:countdown` job 已寫好，**只用假 API 測過，沒有對真實 GitLab 驗證**（範本的 job 仍是 `when: manual`）。詳細做法、官方文件頁面與內部驗證清單見 `docs/GITLAB-PORT.md` 的 T-10。

| GitHub 演練版 | GitLab 階段（狀態） |
|---|---|
| 公開 Issue，標籤 `art14-drill`，內文第二行「演練，不是真實通報」 | 真實案件開**私密（confidential）Issue**，標籤 `art14`（`open-real --backend gitlab`，GitHub 上拒絕）；演練同樣用私密 Issue（後端寫死 confidential），標籤、第二行字樣不變。**已實作** |
| `GITHUB_TOKEN`、`author_association` 過濾 | 作者與倒數留言的作者要是專案成員、`access_level` ≥ 30（Developer）（`GET /projects/:id/members/all/:user_id`）；`system` 留言不算；有 `art14` 標籤卻不是 confidential 的 Issue → FAIL、不寫入。**已實作** |
| 公開檢查 `publiccheck`（防洩漏到公開） | 內部儲存：真實案件不跑公開檢查、不要求「演練」字樣；仍擋 quick action（`/指令` 行首）與沒淨化的 Markdown；演練照舊。**已實作** |
| 排程每小時倒數留言 | GitLab pipeline schedule 每小時（`DUMPLING_JOB=art14`，job `art14:countdown`，token `ART14_GITLAB_TOKEN`）；留言與標籤邏輯重用 `evaluate`／`render_comment`。**已實作（`when: manual`，待內部驗證後放開）** |
| 作者或標記不可信的案件只是略過 | GitLab 的真實案件被略過就 **FAIL**（法定倒數不能靜默停掉）；演練照舊只略過 |
| 倒數只在 Issue 上看 | 加 **email 通知**（期限前提醒負責人與備援人；email 地址放內部設定，不進公開 repo）。**還沒做**（需要內部郵件設定／GITLAB-PORT T-08） |
| SRP 人工提交、把編號與時間填回 Issue | 不變：SRP 沒有 API，不寫任何自動提交 |
| 銷售市場（第 7 節，讀 `project.yml`） | 不變；`open-real`／`open-drill` 一樣傳 `--project projects/<專案>`（注意 GitLab 專案 ID 用 `--gitlab-project`） |

GitLab 用法：`art14.py <指令> --backend gitlab --gitlab-url "$CI_API_V4_URL" --gitlab-project "$CI_PROJECT_ID"`，token 從環境變數 `GITLAB_TOKEN` 讀。
**`--project` 與 `--gitlab-project` 不一樣**（C0 決定，2026-11-14）：art14.py 的 `--project` 是專案資料夾（`projects/<專案>`，讀 `project.yml`），GitLab 的專案 ID 用 `--gitlab-project`；`issues.py`、`collect.py` 的 `--project` 則是 GitLab 專案 ID。`art14.py --help` 也寫明這點。
GitLab 上的演練 Issue 不是 confidential 時同樣當成外洩處理並 FAIL（C0 決定：內部演練的內容同樣可能有產品資訊）。
GitLab 的 `countdown` 不加 `--drill` ＝ 真實案件（標籤 `art14`）、加 `--drill` ＝ 演練（標籤 `art14-drill`）；GitHub 上不加 `--drill` 仍然是「有 `art14` Issue 就 FAIL」。
