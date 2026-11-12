# PLAN 修改提案：CRA 調查採用項目（D-032）

- 來源：`docs/references/cra-github-survey.md`（C4 調查）；採用範圍是 D-032（使用者決定，經 C0 轉達）。
- 寫的人：C4。這份是**提案**，PLAN 怎麼改由 C0 決定、合併。
- 範圍：只寫 D-032 採用的項目，**不加進 M2**，排在之後的里程碑。附件 III／IV 分類、CVD 政策內容、單一聯絡窗口交給法務，dumpling 不決定、不填。
- 法規條號凡標「核對」的，都要回 EUR-Lex 原文確認（調查只看過二手來源）。

## 先講結論：很多東西 sca-center 帶過來的工具已經有了

寫提案前讀了 M1 複製進來的工具，下面這些**已經存在**，提案大多是「接起來、補缺口」，不是從零做：

| 已有的 | 在哪裡 | 跟 D-032 的關係 |
|---|---|---|
| sbomqs 固定版本與安裝 | `pipeline/lib/tools.lock`（v2.1.3，sha256 固定）、`pipeline/install-tool.sh`、`pipeline/check-tool-version.sh` | C2 已用在供應商 BIOS SBOM（`pipeline/lib/firmware_sbom_check.py`），**分數只當參考、不影響狀態**；還沒用 BSI 設定檔 |
| 風險評估、技術文件（附件 VII）、用戶資訊（附件 II）草稿 | `tools/cra/cra_report.py`＋`tools/cra/templates/` | 從 `CRA/Config/config.json` 產生，沒填的欄位寫 `TO BE COMPLETED` 與負責人 |
| 附件 I 第一部分（2）(a)–(m) 的表 | `cra_report.py` 的 `annex_i_table()` | 照人填的 `risk_assessment.annex_i_applicability` 顯示 Applies／Does not apply／TBC；**沒有「dumpling 沒檢查」這一欄** |
| CycloneDX ↔ OpenVEX 轉換 | `tools/vexconv/vexconv.py`、`tools/cra/vex_export.py` | `in_triage` ↔ `under_investigation` 已對應；**但沒有判定的列在轉 OpenVEX 時直接跳過**（`to_openvex()` 裡 `state is None` → `continue`） |
| 支援期檢查 | `tools/cra/support_check.py`＋`tools/cra/data/support-lifecycle.json` | 離線資料表（Ubuntu、Jetson Linux、kernel；每筆有來源網址與查核日期）；`config.schema.json` 已有 `support.end_date`（YYYY-MM）與 `support_period_rationale`；**沒有 Debian、Raspberry Pi OS、Radxa、OMV，也沒有每日檢查與到期提醒** |
| KEV 第一次偵測時間 | `tools/cra/exploited_watch.py`（`first_detected` 寫入後不改） | 可當第 14 條「知悉時間」的**候選**，但不能直接當起算點（見 B1） |
| EU 符合性聲明 | `cra_report.py` 只有指向欄位：聲明副本的位置（`technical_documentation.eu_declaration_of_conformity_copy`，附件 VII 第 7 項）與聲明網址（`eu_declaration_of_conformity_url`，附件 II 第 6 項） | **沒有聲明本身的空殼**（附件 V，核對） |

## 總覽

| 項目 | 改 PLAN 哪一段 | 對話／工作包 | 里程碑 |
|---|---|---|---|
| A1 SBOM 品質閘門（sbomqs＋BSI TR-03183-2） | 「BSP 掃描範圍 › 工具要補的」、「B. mini PC BIOS › 第二條路」、「A. Jetson」第 3 步、「驗證」 | C1（WP1）做共用步驟；C2（WP3／WP4）接韌體 SBOM；C4（WP7）的平台走共用掃描，自動套用 | M7 |
| A2 Release 附件簽章與來源證明 | 「A. Jetson」第 4 步、「F. 搬到 GitLab」、「驗證」 | C1（WP1）做 GitHub；C3（WP5）寫 GitLab 替代方案 | M7（GitLab 部分跟 M5 文件一起補） |
| A3 附件 I 第一部分一律 NOT_ASSESSED | 「BSP 掃描範圍 › 工具要補的」、「驗證」 | C1（WP1） | M7 |
| A4 VEX 的 under_investigation 對應 | 「A. Jetson」第 3 步、「驗證」 | C1（WP1） | M7 |
| B1 第 14 條通報工作流程 | 「E. 監控與通知」、「F. 搬到 GitLab」、「驗證」 | C3（WP2；GitLab 版 WP5） | M8 |
| B2 支援期限與 EOL 管理 | 「開案範本與平台介面 › 1」、「E. 監控與通知」、「驗證」 | C1（WP6）欄位；C3（WP2）每日檢查；C4（WP7）補平台的 OS EOL 資料 | M8（C4 的資料可以隨 M6 先交） |
| C1 CRA 文件骨架 | 「開案範本與平台介面 › 1」、「驗證」 | C1（WP6） | M7 |

**建議新增的里程碑**（加在「工作包與對話分工 › 里程碑」）：
- **M7**：報告與發行的 CRA 補強：A1、A2（GitHub 部分）、A3、A4、C1。條件：M2 完成（Release 與開案範本已經存在）。
- **M8**：通報與支援期限：B1、B2。條件：M4（每日監控開 Issue）完成，加上 M7 的 `project.yml` 欄位。

**分工跟 C0 初步想法的差異**（其他照 C0 的想法）：
1. B2 的平台 OS EOL 資料（Debian 13、Raspberry Pi OS、Radxa rsdk、OMV）由 **C4** 補進 `support-lifecycle.json`。每一筆都要有來源與查核日期，跟 WP7 的樣本研究是同一批資料。
2. A4 會影響判定（VEX 狀態），照 PLAN「代理」規則用 `effort: high`，並派獨立的驗證代理。
3. B1 的通報範本要用到 `project.yml` 的「銷售市場」欄位，這個欄位由 C1 在 WP6 提供。

---

## A1 SBOM 品質閘門（sbomqs＋BSI TR-03183-2）

**1. 改 PLAN 哪一段**
- 「BSP 掃描範圍 › 工具要補的」加第 4 點：每一份 SBOM 都用 sbomqs 的 BSI TR-03183-2 設定檔檢查，包括 dumpling 自己產的、供應商給的和韌體的。
- 「B. mini PC BIOS › 第二條路」：品質檢查改成引用共用步驟，不再只針對供應商 SBOM。
- 「A. Jetson」第 3 步：產出 SBOM 之後加一步「SBOM 品質檢查」，結果進 `status.tsv`。

**做法**
- 共用一個步驟（名稱建議 `pipeline/sbom-quality.sh`，由 C1 決定），輸入一份 SBOM，輸出一行狀態和一份 JSON：
  - BSI 設定檔要求的欄位都齊 → `OK`，說明寫「只表示欄位齊全，不代表內容正確」。
  - 缺必要欄位 → `GAP`，列出缺哪些欄位、各缺幾個元件。版本未知的元件依「不猜版本」的規則本來就是 GAP，這裡照實列出。
  - sbomqs 沒裝、跑失敗或輸出讀不懂 → `NOT_RUN`，Release 摘要把它算成未完成，不當 OK。
  - sbomqs 的分數照 C2 現有的做法只寫在說明裡當參考，不決定狀態，門檻是政策問題。
- 要跑的位置：`sca-scan` 產的 SBOM、`cra_report.py` 產的產品 SBOM（`sbom.cdx.json`）、C2 的韌體 SBOM、供應商 SBOM。
- **待決定（給 C0／使用者）**：BSI 檢查結果是 GAP 時要不要擋 Release。建議**不擋**：照常發布，但 Release 說明與報告摘要明確標 GAP。理由是示範資料裡一定有版本未知的元件，擋下來就永遠發不出去。

**2. 對話／工作包**：C1（WP1）做共用步驟並接進 Jetson 流程；C2（WP3／WP4）把 `firmware_sbom_check.py` 改成呼叫共用步驟或並列 BSI 結果；C4 的平台轉接器走共用的 `scan`，不用另外接。

**3. 里程碑**：M7。

**4. 驗收**
- 單元測試，用合成的 SBOM：欄位齊全 → OK；缺供應商或雜湊 → GAP 並列出欄位；sbomqs 執行檔不存在 → NOT_RUN。
- `check-tool-version.sh sbomqs` 確認版本跟 `tools.lock` 一致，不一致就是 FAIL。
- Jetson 的 Release run：每一份 SBOM 在 `status.tsv` 都有一列品質檢查；報告摘要顯示結果。
- 用 repo 裡現有的 `tests/fixtures/jetson-r39.2.1-base.cdx.json.xz` 跑一次，把結果記在 PR（只記錄，不當標準答案）。

**5. 外部工具與版本固定**
- sbomqs：沿用 `pipeline/lib/tools.lock` 的 v2.1.3（GitHub Release 的 linux amd64 壓縮檔，sha256 固定）。換版本時照 tools.lock 的規則：三個欄位一起改，發布日期至少兩週前。
- BSI 設定檔用的子指令與旗標**未核對**，實作時以 v2.1.3 的 `--help` 為準。設定檔實際對應 TR-03183-2 的哪一版（2.0 或 2.1），要寫進輸出的 JSON。
- BSI TR-03183-2 本身：記錄採用的版本號與發布日期。調查只看到二手來源寫 2.1.0，日期未確認。

## A2 Release 附件簽章與來源證明

**1. 改 PLAN 哪一段**
- 「A. Jetson」第 4 步：發 Release 時，每個附件都產生來源證明，SBOM 另外綁定簽章證明。
- 「F. 搬到 GitLab」：加一項「簽章與來源證明」的替代方案。
- 「驗證 › Jetson」加一條：Release 附件的證明可以驗證。

**做法（GitHub）**
- `release.yml` 在上傳附件前：
  - 用 `actions/attest-build-provenance` 替每個附件產生來源證明，附件包括報告 zip、SBOM、VEX、兩個 xlsx。
  - 用 `actions/attest-sbom` 把產品 SBOM 綁到它描述的對象（報告 zip 或組好的產品映像，由 C1 決定）。
- workflow 權限只在這個 job 開 `id-token: write`、`attestations: write`，其他 job 不給。
- 公開 repo 的證明會寫進 Sigstore 的公開透明紀錄，而且永久公開。示範資料本來就公開，沒有問題，但**這點要寫進 GITLAB-PORT**：內部階段不能沿用公開的透明紀錄。
- 發布後加一個驗證 job：下載附件，跑 `gh attestation verify <檔案> --repo <owner>/<repo>`。

**做法（GitLab，寫進 `docs/GITLAB-PORT.md`）**
- 選項 1：cosign，金鑰放在內部的金鑰管理服務，關掉公開透明紀錄上傳，對外提供公鑰讓收件人驗證。
- 選項 2：GitLab Runner 產生產物的來源證明中繼資料（`RUNNER_GENERATE_ARTIFACTS_METADATA`）。**未核對**，需要 C3 查 GitLab 官方文件，確認支援的版本與格式。
- 兩個選項都要寫：金鑰由誰保管、怎麼輪替、收件人怎麼驗證。

**2. 對話／工作包**：C1（WP1，`release.yml`）；C3（WP5，GITLAB-PORT 的替代方案）。

**3. 里程碑**：GitHub 部分是 M7；GitLab 文件可以在 M5 之後補，最晚跟 M7 一起。

**4. 驗收**
- Release run 綠燈；每個附件都查得到證明，`gh attestation verify` 通過。
- 負面測試：把附件改一個位元組再驗證，必須失敗。這要在 CI 裡實際跑。
- GITLAB-PORT 有「簽章與來源證明」一節，列出選項、金鑰保管、驗證方式；`.gitlab-ci.yml` 範本照 M5 的語法檢查。

**5. 外部工具與版本固定**
- `actions/attest-build-provenance`、`actions/attest-sbom`：一律用**完整 commit SHA** 固定，旁邊註解版本號。版本在實作時查，選發布至少兩週前的；這份提案不寫版本號，因為沒有核對過。
- `gh` CLI：用 runner 內建的版本，在 log 裡印出版本。
- cosign（GitLab 選項 1）：用 GitHub Release 的執行檔，進 `tools.lock` 固定 sha256。

## A3 報告對附件 I 第一部分一律標 NOT_ASSESSED

**1. 改 PLAN 哪一段**
- 「BSP 掃描範圍 › 工具要補的」加一點：報告的附件 I 表加「dumpling 檢查」欄，第一部分全部標 NOT_ASSESSED。
- 「驗證」加一條（見下）。

**做法**
- `cra_report.py` 的 `annex_i_table()` 多一欄「dumpling 檢查」：
  - 第一部分（1）和（2）(b)–(m)：**一律 `NOT_ASSESSED`**，就算人在 config 裡填了 Applies＋措施也一樣。人填的是聲明，dumpling 沒有驗證。人填的那欄保留。
  - (2)(a)「沒有已知可被利用的漏洞」：指向漏洞清單一節，寫出這次弱點分析的資料狀態（COMPLETE／PARTIAL／GAP…）。不寫 OK，也不寫「符合」。
- `status.tsv` 加一列（名稱建議 `D-annex-i-part1`），固定是 `NOT_ASSESSED`。`summary.json` 和 `report.html` 的開頭寫一句：「本報告不評估附件 I 第一部分的產品設計要求（例如安全預設值、預設密碼、資料最小化）。」
- 第二部分（漏洞處理）dumpling 有做一部分，這次不改，之後另外提。

**2. 對話／工作包**：C1（WP1，`cra_report.py`）。

**3. 里程碑**：M7。

**4. 驗收**
- 單元測試：config 的 (b)–(m) 全部填 Applies＋措施 → 「dumpling 檢查」欄仍然全部是 NOT_ASSESSED。
- 報告和 `summary.json` 裡，附件 I 第一部分沒有任何 OK、PASS、符合或安全字樣。測試直接搜尋輸出檔。
- `status.tsv` 有 `D-annex-i-part1	NOT_ASSESSED`。

**5. 外部工具**：無。

## A4 VEX 的 under_investigation 對應

**1. 改 PLAN 哪一段**
- 「A. Jetson」第 3 步的 VEX 產出加一句：沒有判定的列在 VEX 裡寫成「調查中」，不省略。
- PLAN 加一張 VEX 狀態對照表（放在「BSP 掃描範圍」後面或附錄）。

**問題**：現在 `vexconv.py to-openvex` 遇到沒有判定的列直接跳過，所以 `vex.openvex.json` 裡看不到沒評估的漏洞。只讀 OpenVEX 的下游分不出「沒評估」和「不在清單上」，可能把沒評估當成沒問題。

**對照表（建議）**

| dumpling 內部（`vex_export.py` 的分類） | CycloneDX VEX | OpenVEX |
|---|---|---|
| resolved | `resolved`／`resolved_with_pedigree` | `fixed` |
| not_affected（含 false_positive） | `not_affected`／`false_positive`＋理由 | `not_affected`＋justification |
| exploitable | `exploitable`＋處理方式 | `affected`＋action_statement |
| in_triage | `in_triage` | `under_investigation` |
| **untriaged（沒有任何判定）** | **`in_triage`＋屬性 `dumpling:assessment=NOT_ASSESSED`** | **`under_investigation`＋status_notes「dumpling: not assessed」** |

- 內部的發行閘門繼續分開計算 untriaged 和 in_triage，靠那個屬性區分，**閘門的數字不能變**。
- 版本未知、沒有比對到任何 CVE 的元件（`sbomgate` 的 excluded_matches）沒辦法用逐筆 CVE 的 VEX 表達。這些改寫在 VEX 文件層級的說明裡，並在報告列出，不在 VEX 裡編 CVE。

**2. 對話／工作包**：C1（WP1，`vex_export.py`、`vexconv.py`）。會影響判定，用 `effort: high`，驗證代理另外派。

**3. 里程碑**：M7。

**4. 驗收**
- 單元測試：CycloneDX 裡有 N 列沒有判定 → OpenVEX 有 N 筆 `under_investigation`，說明欄寫 not assessed。
- 雙向轉換（to-openvex → to-cdx）後，NOT_ASSESSED 的標記還在。
- 發行閘門的五個分類數字跟改之前一樣，用現有測試的標準答案比對。
- OpenVEX 輸出通過規格驗證，可以用 vexctl 或現有測試的 schema 檢查。

**5. 外部工具與版本固定**：不需要新的工具，OpenVEX 沿用現有的 v0.2.0 context。如果驗收要用 vexctl，用 GitHub Release 的執行檔，進 `tools.lock` 固定 sha256；不用就不裝。

## B1 第 14 條通報工作流程

**1. 改 PLAN 哪一段**
- 「E. 監控與通知」加第 5 點「第 14 條通報」（內容見下）。原本第 4 點的「已出貨的照內部 SOP」後面接這個流程。
- 「F. 搬到 GitLab」：真實案件只能開在內部的私密 Issue。
- 「驗證 › 監控」加演練的驗收。

**做法**
- **起算點**：
  - 法規的時鐘從「知悉」起算（核對）。「知悉」是人的判斷，要確認產品受影響而且漏洞被積極利用，工具不能自己決定。
  - 工具記錄 `first_detected`（`exploited_watch.py` 已有，UTC，寫入後不改），只當**候選**。
  - Issue 上有「知悉時間（UTC）」欄位，由負責人確認後填寫。倒數**只從這個欄位**算。
  - 沒填時，Issue 顯示「時鐘未起算（待確認）」，同時顯示從 first_detected 起已經過了幾小時，提醒盡快確認。監管機關會不會認定知悉時間更早，交給法務判斷。
- **三階段範本**（Issue 範本，各一節，條號核對）：
  - 漏洞：
    1. 早期預警：知悉後 24 小時內。
    2. 漏洞通報：知悉後 72 小時內。
    3. 最終報告：修正或緩解措施可用後 14 天內。
  - 嚴重事件：
    1. 早期預警：24 小時內。
    2. 事件通報：72 小時內。
    3. 最終報告：72 小時的通報送出後 1 個月內。
  - 欄位能預先填的就自動帶入：
    - 產品名稱與版本：取自 `project.yml`。
    - 有在哪些會員國販售：取自 `project.yml` 的銷售市場。
    - CVE 與說明。
    - 被利用的依據（KEV、EUVD、廠商公告）。
    - 嚴重度、受影響版本。
  - 要人填的欄位：修正或緩解措施、要通知用戶的內容、SRP 提交編號、提交人、提交時間。
- **Issue 倒數**：
  - 標籤 `art14`，加上階段標籤 `art14-24h`／`art14-72h`／`art14-final`。
  - 有開著的 `art14` Issue 時，排程每小時更新一次倒數留言（建議值）；平常每天跑一次就好。
  - GitHub 排程可能延遲，所以倒數只是輔助，期限要由負責人自己掌握。這句話寫進 Issue 範本。
- **SRP 送出是人工步驟**：
  - ENISA 的通報平台（SRP）查不到 API。
  - Issue 範本附一份檢查清單：登入 SRP、選協調 CSIRT（主要營業地所在國）、貼上預填的欄位、把 SRP 編號和提交時間填回 Issue。
  - 不在公開 Issue 附上任何機密內容。
- **公開 repo 只做演練**：
  - 用合成資料，標籤 `art14-drill`，Issue 第一行寫「演練，不是真實通報」。
  - 真實案件只開在內部 GitLab 的私密 Issue；公開 Issue 等於公開揭露（調查的缺口 15）。
- 嚴重事件不是漏洞，不會由監控自動偵測，只提供人工開 Issue 的範本。

**2. 對話／工作包**：C3（WP2 是 GitHub 演練版；WP5 是 GitLab 版，改成私密 Issue 加 email）。`project.yml` 的銷售市場欄位由 C1（WP6）提供。

**3. 里程碑**：M8（要先有 M4 的每日監控開 Issue）。

**4. 驗收**
- 期限計算的單元測試：
  - 輸入知悉時間 → 24h、72h 期限正確。
  - 輸入措施可用時間 → 14 天期限正確；嚴重事件則是 72h 通報後 1 個月。
  - 全部用 UTC；跨月、閏年要有測試案例。
- 用合成的 KEV 命中做演練：
  - 開出的 `art14-drill` Issue 有三階段範本，預填欄位正確，同一筆不重複開。
  - 沒填知悉時間時，顯示「時鐘未起算」。
  - 在合成資料裡填了知悉時間後，倒數留言正確。
- 公開 repo 裡只有 `art14-drill` Issue。測試或公開檢查要確認範本產生的內容都帶「演練」字樣。
- GITLAB-PORT 有一節對照：私密 Issue、email 通知、SRP 人工步驟。

**5. 外部工具**：不需要新的工具，用 runner 內建的 `gh` CLI 和 GitHub Issue 表單（YAML）。SRP 沒有 API，也不寫任何自動提交。

## B2 支援期限與 EOL 管理

**1. 改 PLAN 哪一段**
- 「開案範本與平台介面 › 1」：`project.yml` 的「支援期限」展開成具體欄位（見下）。
- 「E. 監控與通知」加一點：每日的支援期限與 EOL 檢查。
- 「驗證 › 監控」加支援期限的驗收。

**做法**
- **`project.yml` 欄位**，對應現有的 `config.schema.json`，讓 `cra_report.py` 和 `support_check.py` 讀同一份資料：
  - `support.end_date`：YYYY-MM。狀態是 shipped 時必填；development 可以空著，空著時檢查結果是 NOT_ASSESSED。
  - `support.type`。
  - `support_period_rationale`：決定支援期限的依據。法規要求至少 5 年，除非產品預期使用期更短（核對）。
  - OS 是我們的平台（AI NAS）另加 `os.distro`、`os.release`；其他平台照 SBOM 裡的 operating-system 元件。
- **資料表**：`tools/cra/data/support-lifecycle.json` 加入 Debian 12／13、Raspberry Pi OS、Radxa rsdk、OMV 8（TrueNAS 只研究，可以不加）：
  - 每一筆都要有來源網址和查核日期。沒有公開資料就寫 `null`，結果是 ATTENTION；**不推估日期**。
  - Debian 的一般安全支援和 LTS 分開列成不同階段（LTS 是另一個專案負責）。
  - Raspberry Pi OS 有沒有自己公布的 EOL，查不到就寫 null，並註明「跟隨 Debian」是推論。
- **每日檢查**（加在 `watch.yml`），對 `projects/` 裡每個 shipped／development 專案：
  - 用 `support_check.py` 加上當天日期檢查：元件比產品先停止維護 → ATTENTION，開一次 Issue（不重複開）。
  - 產品支援期限前 180、90、30 天各開一次提醒 Issue（天數是建議值）。已過期 → 狀態 EOL，報告的支援期一節標 GAP「支援期已結束」。
  - 資料表的查核日期超過 `max_age_days`（現在是 180 天）→ 開 Issue 提醒重新查核。
- 執行時不連網，只讀資料表，跟 GitLab 內網的情況一致。endoflife.date 這類網站只在人工更新資料表時當參考，不當執行時的依賴。

**2. 對話／工作包**：C1（WP6，`project.yml` 欄位與範本）；C3（WP2，每日檢查與 Issue）；C4（WP7，平台的 OS EOL 資料，跟 M6 的示範專案一起）。

**3. 里程碑**：M8。C4 的資料可以隨 M6 先交。

**4. 驗收**
- 單元測試，用固定的 `--today`：
  - 支援期限前 181／180／90／30 天、到期當月、過期各一個案例，結果正確。
  - 沒有 `support.end_date` → NOT_ASSESSED，不是 OK。
  - 合成專案的支援期限比 Debian 12 的維護期晚 → ATTENTION，而且列出 Debian 12。
- 資料表檢查：每一筆都有 `source` 和 `checked`，沒有公開日期的是 null。
- 每日 job 對同一個狀況不重複開 Issue。

**5. 外部工具**：無。資料表人工維護，有來源與查核日期。

## C1 CRA 文件骨架（開案範本）

**1. 改 PLAN 哪一段**
- 「開案範本與平台介面 › 1」產生的檔案加：完整的 `CRA/Config/config.json` 骨架，以及 EU 符合性聲明的空殼範本。
- 「驗證」加一條：新專案的文件骨架。

**做法**
- **沿用 `cra_report.py`**：
  - 它已經從 config 產生風險評估、技術文件（附件 VII）和用戶資訊（附件 II），沒填的地方寫 `TO BE COMPLETED` 與負責人。
  - 開案範本要做的，是讓 `new-project.sh` 產生**每個鍵都在、值都空**的 config.json，產出的文件才會把每一項都列成待完成，不會整段消失。
- **新增**：EU 符合性聲明的空殼範本，項目照附件 V（核對），內容全部 GAP。現在只有「聲明副本」的指向欄位。
- **狀態一律 GAP**：
  - 文件裡沿用 `TO BE COMPLETED` 的寫法，不改 `cra_report.py` 大量字串。
  - `summary.json` 和 `status.tsv` 把每份文件「還有幾項待完成」記成 GAP（例如「技術文件 12 項 GAP」）。
- **交給法務的欄位**：
  - 附件 III／IV 分類、CVD 政策內容與網址、單一聯絡窗口（`vulnerability_contact`）。
  - 範本只放「由法務提供（GAP）」的標記，dumpling 不填、不推、不給預設值。
  - 注意：`config.example.json` 裡的 example.com 範例值**不能**帶進新專案，否則看起來像已經填了。
- **CE 標示與合格評定路徑**：不在範圍內，寫明由法務決定。

**2. 對話／工作包**：C1（WP6）。

**3. 里程碑**：M7。

**4. 驗收**
- `new-project.sh demo --platform <任一平台>` 後直接跑 `cra_report.py`：產生風險評估、技術文件、用戶資訊、符合性聲明空殼四份，每個非自動欄位都是 TO BE COMPLETED；`summary.json` 列出缺的欄位，狀態 GAP。
- 新專案的 config.json 裡沒有 example.com 或任何範例值（測試直接搜尋）。
- 法務欄位在文件裡顯示「由法務提供」，不是空白，也不是範例值。

**5. 外部工具**：無。

---

## 給 C0 的待決定事項

1. A1：BSI 檢查結果是 GAP 時要不要擋 Release。建議不擋，但標示出來。
2. B1：有開著的 `art14` Issue 時，倒數每小時更新可以嗎？會多用 Actions 時間，但只在有案件或演練時跑。
3. C1：文件裡沿用 `TO BE COMPLETED`、狀態檔寫 GAP，這樣分開可以嗎？還是要把文件字樣也統一改成 GAP（`cra_report.py` 要改很多字串）？
4. 里程碑：新增 M7、M8，還是併進現有的里程碑？

## 沒有核對的部分

- sbomqs v2.1.3 的 BSI 子指令與旗標、BSI 設定檔對應的 TR-03183-2 版本。
- `actions/attest-build-provenance`、`actions/attest-sbom` 目前的版本，以及兩者跟 `actions/attest` 的關係。
- GitLab Runner 的產物來源證明中繼資料（名稱、支援版本、格式）。
- 第 13、14 條和附件 I、II、V、VII 的條號與期限細節（標「核對」的地方）。
- Debian、Raspberry Pi OS、Radxa、OMV 的 EOL 日期：還沒查，實作時逐筆附來源。
