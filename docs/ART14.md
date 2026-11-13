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

## 4. Issue 內文與欄位（程式解析的契約）

- 第一行：`<!-- dumpling-art14 key=<64 hex> kind=vulnerability|incident mode=drill -->`。key ＝ sha256(`dumpling-art14/1|mode|kind|產品|版本|層|CVE`)（嚴重事件用事件代號），同一個命中只開一個。
- 演練的**第二行固定**是 `演練，不是真實通報`，標題有 `[演練]`；寫入前檢查沒有「演練」字樣就不寫。
- 預填（工具帶入，人核對）：產品名稱與版本、層（bsp／os／product）、CVE 與說明、被利用的依據（KEV／EUVD／廠商公告）、受影響版本、`first_detected`（候選）、嚴重度（沒有來源寫「待填」，不猜）、銷售市場（見第 7 節）。
- 要人填的欄位（解析器只認這些行的開頭）：
  - `- 知悉時間（UTC）：`
  - 漏洞：`- 修正或緩解措施可用時間（UTC）：`；嚴重事件：`- 事件通報送出時間（UTC）：`、`- 是否疑似非法或惡意行為造成：`
  - 每個階段（`## 階段 N：…` 底下）：`- SRP 提交編號：`、`- 提交人：`、`- 提交時間（UTC）：`
  - 說明文字欄（措施說明、要通知用戶的內容）：不解析，不要放機密。
- 值只能是 `YYYY-MM-DDTHH:MM:SSZ` 或 `未填`。**解析器嚴格**：格式不對、欄位被刪、欄位重複都當成「未填」，倒數留言寫「格式不對」。階段的**提交時間有填就標完成**（晚於期限會註明「晚於期限」）。
- 內文有 SRP 人工檢查清單（登入 SRP、選協調 CSIRT＝主要營業地所在會員國、貼上預填欄位、把編號與時間填回）與法規出處／核對日期。

## 5. 倒數與標籤

- `countdown --repo R --drill [--now UTC]`：列出開著的 `art14-drill` Issue → 解析 → 更新倒數留言與階段標籤。**沒有可處理的案件就印一行、立刻結束（OK）**。
- **只處理作者是 OWNER／MEMBER／COLLABORATOR 的 Issue**（`author_association`）；另外接受 `github-actions[bot]`（type=Bot）——工作流程用 `GITHUB_TOKEN` 開的演練 Issue 不一定是 OWNER，見第 9 節。其他作者的 Issue 略過並列出。
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

## 7. 銷售市場（會員國）：GAP

規格要求預填「有在哪些會員國販售」（第 14(2)(a) 條）。這個欄位取自 `project.yml`，**由 C1 在 M7 提供**；M7 提供前讀不到，範本一律寫「GAP，project.yml 的欄位由 C1 在 M7 提供，M7 提供前讀不到；請人工填寫」。**不自己訂欄位名、不讀 `project.yml` 的任何猜測欄位**。M7 完成後，M8 才把它接進 `load_match`／範本，並補測試。

## 8. 演練步驟（`art14.yml`，`action=drill`）

1. `open-drill`（知悉時間未填）→ 驗收：`result=opened`
2. `countdown --now 2026-11-13T06:00:00Z` → 驗收：時鐘未起算、first_detected 起 6 小時、新增一則留言、標籤 `art14-24h`
3. `fill-drill-aware --at 2026-11-13T00:00:00Z`
4. `countdown` → 驗收：24h 期限 `2026-11-14T00:00:00Z`、72h `2026-11-16T00:00:00Z`、最終報告期限空（措施未填）、留言是編輯不是新增
5. 再跑 `open-drill` → 驗收：`result=skipped`（不重複開）
6. `close-drill` → 驗收：關閉 1 個；再 `countdown` 沒有案件。任何一步失敗，job 失敗，並收掉演練 Issue。

每一步以 `--result` 輸出 JSON，下一步用 `check` 比對。**新 workflow 不在預設分支時 `gh workflow run` 會 404**：合併前無法在分支上觸發，CI 驗證靠單元測試；合併後再手動跑 `action=drill`（M8 合併後的待辦）。

## 9. 還沒驗證的地方

- 用 `GITHUB_TOKEN` 建立的 Issue，`author_association` 是什麼，沒有在真實 GitHub 上驗證過（單元測試用假 GitHub）。程式因此額外接受 `user.login == github-actions[bot]` 且 `type == Bot`。合併後第一次 `action=drill` 會直接驗證；若真實值是 OWNER／MEMBER 以外且不是這個 Bot，演練會在步驟 2 失敗。
- 公開 repo 的 `art14-drill` 標籤只有有 triage 以上權限的人能加，這是額外的一層，但不是唯一一層（作者檢查）。

## 10. GitLab 階段要改的地方（只列對應；實作在 M5／M8 的 GitLab 部分）

| GitHub 演練版 | GitLab 階段 |
|---|---|
| 公開 Issue，標籤 `art14-drill`，內文第二行「演練，不是真實通報」 | 真實案件開**私密（confidential）Issue**，標籤 `art14`；演練也建議用私密 Issue |
| `GITHUB_TOKEN`、`author_association` 過濾 | 私密 Issue 只有專案成員看得到；改用 GitLab 的 member access level 過濾作者 |
| 公開檢查 `publiccheck`（防洩漏到公開） | 內部儲存可放較多細節，但仍不放機密到 Issue；公開檢查改成「不得出現在對外文件」 |
| 排程每小時倒數留言 | GitLab pipeline schedule 每小時；留言與標籤邏輯可重用（`evaluate`／`render_comment` 是純函式） |
| 倒數只在 Issue 上看 | 加 **email 通知**（期限前提醒負責人與備援人；email 地址放內部設定，不進公開 repo） |
| SRP 人工提交、把編號與時間填回 Issue | 不變：SRP 沒有 API，不寫任何自動提交 |
| 銷售市場 GAP | M7 的 `project.yml` 欄位就緒後預填 |
