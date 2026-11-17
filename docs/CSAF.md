# CSAF 草稿（修補公告與被利用漏洞的使用者通知）

`tools/cra/csaf_advisory.py` 產生兩種 CSAF 2.0（`csaf_security_advisory`）文件。**兩種都只是草稿**：`document.tracking.status` 固定是 `draft`、版本 `0`，工具沒有任何參數能改成 `final`，也不會發布或自動放進客戶資料包；`advisory.md` 與 PM 資料夾的 `README.md` 第一行都寫「草稿：工具不發布，也不會自動放進客戶資料包」。要不要發、怎麼發由負責人決定。

來源：同步 sca-center edac554（D-066 的 S4），移植與清理內容見 `docs/PROVENANCE.md` 的「C3 CSAF 草稿」節。

| | A：版本間的修補公告 | B：被利用漏洞的使用者通知 |
|---|---|---|
| 對應 | CRA Annex I Part II(4)：修補**可用之後**公開已修補漏洞的資訊 | CRA 第 14 條第 8 項：已被積極利用、**修補還沒有**時通知受影響的使用者 |
| 指令 | `csaf_advisory.py --old <前一版 Reports> --new <這一版 Reports> --config <config.json> --out <資料夾>` | `csaf_advisory.py exploited --report <Reports> --cve CVE-… [--cve …] [--config <config.json>] --out <資料夾>` |
| 輸出 | `csaf.json`、`advisory.md`、`csaf-summary.json` | `csaf-exploited-draft.json`、`csaf-exploited-summary.json` |
| 狀態行 | `CSAF<TAB>OK｜ATTENTION｜FAIL<TAB>說明` | `CSAF-EXPLOITED<TAB>OK｜ATTENTION｜GAP｜FAIL<TAB>說明` |

同一個 CVE 通常先有 B（還沒修補），修補釋出後才有 A。官網的公告文字仍是對外的主要管道，CSAF JSON 是它的機器可讀版本；向主管機關的通報（第 14 條的單一通報平台、24／72 小時）是另一件事，不用這兩份檔案。

## 共同規則

- **發布者欄位**（`config.json` 的 `csaf` 區塊，見 `tools/cra/config.schema.json`）：`publisher_name`、`publisher_namespace`、`tracking_id_prefix`、`contact`、`advisory_url_base`、`tlp`。沒填時退回 `manufacturer.*`（聯絡方式另外退回 `vulnerability_contact.contact`），再沒有就寫 `TO BE COMPLETED`（網址佔位 `https://to-be-completed.invalid`；聯絡方式不寫，列在缺的欄位），狀態 ATTENTION。`tlp` 要寫大寫。**工具沒有內建任何預設的網域或聯絡人**；範例值（example.com 等）也當成沒填。
- **驗證**：每份輸出都跑兩層檢查，不符就 FAIL、不產生（並刪掉上一次的輸出）。
  - 完整的 OASIS CSAF 2.0 JSON schema（`tools/cra/data/csaf-2.0/`，官方原檔，來源與授權見同資料夾 `NOTICE.md`），需要 `jsonschema` 與 `referencing`。沒有這兩個套件時，summary 的 `schema_validation.status` 是 `NOT_RUN`，notes 寫明「這不是通過」，狀態 ATTENTION。
  - 內建檢查（不依賴套件，一定會跑）：document 必要欄位與列舉值、security_advisory 設定檔的必要欄位、產品 ID 都有定義、同一產品不同時在互斥的狀態裡。結果寫在 summary 的 `builtin_checks`。
- **輸入是不可信資料**：不跟隨符號連結、單一檔案有大小上限、巢狀太深的 JSON 當成讀不到；A、B 兩條路徑讀進來的字串都去掉控制字元與 Unicode 格式字元並截斷。
- 工具只帶入判定（VEX）的狀態與元件；漏洞描述、嚴重度說明、修補方式的文字要人補。

## A：版本間的修補公告

比對兩版的 `vex.cdx.json`（只有「有判定」的列），每一筆歸成一類：

- `fixed`：舊版受影響，這一版判定已修補，或元件已經不在這一版的 SBOM。只有這一類會寫 `vendor_fix`。
- `new`：這一版才受影響。`still`：兩版都受影響或還在評估。`changed`：其他狀態改變。
- `reassessed`：重新評估成 not_affected。**這不是修補**，不寫 `vendor_fix`。
- `not_stated`：舊版受影響、這一版沒有判定而元件還在，或新版本已修但舊版本還在。**不當成已修**，要先判定。

接進報告：`tools/cra/report_package.py --csaf-previous <前一版的 CRA/Reports、專案資料夾或精靈輸出資料夾>`。

- 草稿放 `交給PM/CSAF/csaf-fix-advisory-<名稱>-<版本>.json`，旁邊的 `README.md` 寫明這是草稿、各分類的意思、發布前要補的欄位。完整輸出放 `內部存檔/csaf-fix-advisory/`。兩者都進 `SHA256SUMS.txt`。
- **不放進客戶資料包**（有測試檢查客戶資料包裡沒有 CSAF 檔案或內容）。
- 沒給 `--csaf-previous`：訊息寫 NOT_RUN（沒有前一版可比較），不算 GAP。給了但產生不了（找不到前一版、前後版是同一份、版本順序反了、驗證失敗等）：原因寫進 `交給PM/未產生的項目.md`（GAP）。
- 發 Release 時自動找同一專案的前一個正式 Release 來比較：已接上，詳見下面「pipeline 接線」一節。只有正式 Release 的 tag push 才會找。前一版依版本排序來選（semver，加上 dumpling 的自然排序延伸：demo2 小於 demo10），不看建立時間。
  - 產生草稿：找到前一版，至少一層的報告 zip 下載、檢查、組好，而且沒有任何一層是 GAP。草稿放 `交給PM/CSAF/`。
  - 記 NOT_RUN（說明以「僅供參考」開頭，不算 GAP，不降低整體狀態）：不是正式 Release 的 tag push；第一個正式 Release；前一版沒有報告 zip；前一版的 zip 裡沒有 VEX；前一版沒有這一層。後兩種舊格式的情況可能只出現在部分層：那幾層記 NOT_RUN，其他層照常產生。
  - 記 GAP（照實記，不擋 Release）：zip 壞掉或不合規則、大小和 Release 記的不同、下載不完整或逾時、VEX 格式不對、版本排不出先後、API 錯誤。

## B：被利用漏洞的使用者通知

- 輸入：報告的 `vulnerability-rows.json`（必要），`vex.cdx.json`／`sbom.cdx.json` 用來取產品名稱與版本。
- **關卡**：要通知的 CVE 在報告裡沒有任何被利用的證據（KEV、EUVD、Grype 的 knownExploited、人工證據）時不產生，狀態 GAP。**這不代表這個 CVE 沒有被利用**，是否需要第 14(8) 條的通知由人判斷。有報告以外的證據時加 `--assume-exploited "<證據說明>"`，說明會寫進草稿。
- 產品狀態依這一版目前的判定：沒有判定或 in_triage → `under_investigation`；exploitable → `known_affected`；not_affected／false_positive → `known_not_affected`；這一版判定 resolved → `fixed`。上游或發行版有修補版本**不算**這個產品已修補。判定是 not_affected 或已修補時會警告「可能不需要通知」。
- 緩解措施預設是 `TO BE COMPLETED by RD`；受影響的元件底下不放 `vendor_fix`。

`tools/cra/exploited_watch.py`（以 Dependency-Track 為來源的監控）在有新的比對時，可以替 `--shipped` 清單裡帶 `cra_project` 的已出貨版本寫草稿到 `<輸出資料夾>/csaf-drafts/<UTC 時間>/`（`--csaf-draft`／`--no-csaf-draft`、`EW_CSAF_DRAFT`；不覆寫既有的草稿；失敗只記在報告的 `csaf_drafts`，不改變監控狀態）。dumpling 在 GitHub 上的每日監控（`pipeline/watch/`）另外接上：新的 KEV 群組落在 shipped 的正式版時，用同一個 Release 的報告 zip 產生草稿，以 workflow artifact 上傳，見 `docs/WATCH.md` 第 8 節。

## pipeline 接線：正式 Release 自動比較前一個正式 Release（S4，C1）

來源：同步 sca-center edac554 的精靈 `--previous-report`，加上 dumpling 自己的 pipeline 部分（`pipeline/lib/previous_release.py`、`pipeline.yml` 的一個步驟）。**只是接上 A 路徑（版本間的修補公告草稿）**；草稿的內容、狀態與不發布的規則照上面。

流程（`pipeline.yml` 的 scan job，在 scan 之前）：

1. `previous_release.py prepare` 判斷這次是不是正式 Release：**只有 tag push**（`GITHUB_EVENT_NAME=push`、`GITHUB_REF_TYPE=tag`、`GITHUB_REF` 就是這次的 `<專案>/<版本>`）。dev 分支的 push、每日排程、手動觸發（包括手動輸入 tag 建草稿）一律 `NOT_RUN`，**不呼叫 GitHub API**，workflow 也不給這一步 token。
2. 用 GitHub API（`GITHUB_TOKEN` 唯讀即可）列出同一個 repo 的 Release，選「前一個正式 Release」（規則見下）。
3. 下載前一版每一層的 `report-<專案>-<版本><後綴>.zip`，只取兩個成員：`報告/交給PM/VEX/vex.cdx.json`、`報告/內部存檔/summary.json`（`csaf_advisory.py` 只讀舊版的這兩個檔；舊版 SBOM 不用）。
4. 依層組成資料夾 `$DUMPLING_OUT/previous-release/`：`previous-release.json`（狀態、前一版 tag、每一層的狀態與說明）與 `<名稱>/vex.cdx.json`、`<名稱>/summary.json`。`<名稱>` 是精靈的 `--name`：`<專案>`（完整）、`<專案>-bsp`、`<專案>-os`。
5. workflow 把資料夾路徑放進環境變數 `DUMPLING_PREVIOUS_REPORTS`（寫進 `GITHUB_ENV`）。`run-step.sh scan` → 各平台的 `scan.sh` → 精靈會繼承它，**各平台的 `scan.sh` 不用改**；完整、`-bsp`、`-os` 三次呼叫精靈時 `--name` 不同，各自拿到對應層的資料夾。
6. 精靈（`tools/wizard/cra-scan.py`）取前一版的順序：`--previous-report` ＞ `DUMPLING_PREVIOUS_REPORTS` ＞ 互動模式列出同名稱的較早輸出（`--yes` 不會自己挑）。拿到資料就給 `report_package.py --csaf-previous`，草稿放 `報告/交給PM/CSAF/`，**只對製造商專案做**。

### 前一個正式 Release 怎麼選

- 同一個專案的 tag `<專案>/v…`；**不是草稿、不是 prerelease、不是這次的 tag**（同名 tag 被重打、這個版本已經有 Release 時，不拿自己比）。`dev/<專案>`（滾動的開發版，prerelease）與其他專案的 tag 不在候選裡。
- **只看版本，不看建立時間**：版本比這次小的之中取最大的。補丁版在舊版本線上才發（例如 v1.1.0 之後才發 v1.0.1）時，前一版是 v1.0.0，不是時間上最近的 v1.1.0。
- 版本字串拆成主版本（`-` 之前）與後綴（`-` 之後）。主版本的數字段比大小（v1.10.0 大於 v1.9.0）；多出來的段落算較大（v1.0 小於 v1.0.1）。主版本相同時：**沒有後綴的比有後綴的大**（v39.2.1-demo1 小於 v39.2.1、v1.0-rc1 小於 v1.0，所以 v39.2.1 的前一版是 v39.2.1-demo1）；兩邊都有後綴時用 `.` 分段逐段比，規則如下表。
- **這是 dumpling 的延伸規則，不是純 semver**：semver 把 `demo10` 當成字母比（demo10 小於 demo2），這裡「字母加數字」的段落用自然排序（demo2 小於 demo10、rc9 小於 rc10）。理由：選錯前一版，公告上「這版修了什麼」就會整份算錯，而 dumpling 的 tag 本來就是 `-demo1` 這種寫法。其餘照 semver。

  | 後綴的段落 | 怎麼比 | 例 |
  |---|---|---|
  | 純數字 | 比數值；排在含字母的段落前面 | `rc.2` 小於 `rc.10`；`1` 小於 `alpha` |
  | 純字母 | 照 ASCII | `alpha` 小於 `beta` |
  | 字母加數字 | 先比字母部分（ASCII），字母相同再比後面的數字（沒有數字的排前面） | `demo2` 小於 `demo10`；`demo3` 小於 `rc1`；`rc` 小於 `rc1` |
  | 前面的段落都相同 | 段落少的排前面 | `rc` 小於 `rc.1` |
  | 其他形式（`1a`、`a1b`） | **排不出先後，記 GAP**（保守，不照 ASCII 猜） | |

- **排不出先後就不猜，記 GAP**：寫法不同的同一版（v1.0 與 v1.00、`rc1` 與 `RC1`、`+` 之後的建置資訊不同）、後綴的段落是上表的「其他形式」、版本不是 `<數字>(.<數字>)*(-<後綴>)?` 的形式（例如 `v1.0rc1`）、同一個 tag 有多個正式 Release。只有比到那一段才會排不出：主版本不同就已經分得出先後。
- 列 Release 的 `draft`／`prerelease` 旗標不是布林值的項目，不當成正式 Release（統計在說明裡）。

### 三種狀態

| 狀態 | 什麼時候 | 結果 |
|---|---|---|
| `NOT_RUN`（僅供參考） | 不是正式 Release 的 tag push；或第一個正式 Release（沒有符合條件的前一版）；或前一版沒有任何報告 zip（報告格式導入前的舊版，說明「僅供參考：前一版 <tag> 沒有報告 zip（舊格式），無法產生版本間公告」）；或前一版每一層的 zip 裡都沒有 VEX 成員（同樣是舊格式）；或前一版沒有這一層的報告（例如這一版新增了 `-os` 分層）；或某一層的 zip 裡沒有 VEX（那一層記 NOT_RUN，其他層照常） | **不算 GAP**。`pipeline-steps.tsv` 記一列 `pipeline-previous-release`（recorded、說明以「僅供參考」開頭，不降低整體狀態）；報告的 `inputs-check.json` 記 informational 的 `csaf-fix-advisory` 步驟，報告訊息寫 `CSAF 修補公告：未產生（NOT_RUN…）` |
| `OK` | 找到前一個正式 Release，這一層的報告 zip 下載、檢查、組好。整體：至少一層 OK、而且沒有任何一層是 GAP（有些層缺 VEX 時整體仍是 OK，說明裡列出缺的層，manifest 裡那幾層是 NOT_RUN） | 精靈給 `--csaf-previous`，`交給PM/CSAF/` 產生草稿 |
| `GAP` | 找到了前一版，但列出／下載／檢查／組裝失敗：API 錯誤、列出 Release 超過整體時間上限（`DUMPLING_PREV_LIST_DEADLINE`，預設 300 秒）、Release 的附件欄位格式不對、附件還沒上傳完或太大、大小與 Release 記的不同、zip 壞掉或不合規則、VEX 不是 CycloneDX、`summary.json` 不是 JSON、版本排不出先後、資料夾缺或 manifest 讀不到。**只要有任何一層是 GAP，整體就是 GAP；沒有任何一層是 GAP，整體就不會是 GAP**；精靈對每一層各看各的：GAP 的層記 GAP，前一版沒有的層（不在 manifest 的 `layers` 裡）與缺 VEX 的層記 NOT_RUN | **照實記，不當成沒有前一版**。`pipeline-steps.tsv` 記 GAP（整體狀態降成 GAP，不擋 Release）；精靈在 `inputs-check.json` 記一般步驟 `gap`，報告的 `交給PM/未產生的項目.md` 列出原因。產生了但 `csaf_advisory.py` 判 FAIL（兩版不是同一個產品、版本相同或順序反了、輸入格式不對）時，由 `report_package.py` 記 GAP |

這個步驟本身不會讓 pipeline 失敗：資料問題、意外的例外都記成 GAP，build 與 scan 照跑。

### 下載的內容是不可信資料

- 單一報告 zip、所有層加起來、API 回應、zip 裡每個成員都有大小上限（見 `previous_release.py` 的 `LIMITS`）；下載超過上限就停止並刪掉檔案，Release 記的大小和實際下載的不同也當成失敗。
- zip 有路徑穿越、絕對路徑、反斜線、符號連結、特殊檔案、重複名稱、加密的成員、成員太多、宣告的解開後大小太大，**整個 zip 不用**（GAP）。只讀名稱精確相同的兩個成員，讀進記憶體後寫成固定檔名（0600），不依 zip 內的路徑解開。
- 下載網址用 `GITHUB_REPOSITORY` 與附件 id 自己組，不用 API 回應裡的網址；轉址（GitHub 轉到簽名網址）不帶 `Authorization`，也只接受 https。`GITHUB_API_URL` 只接受 https（測試用：127.0.0.1／localhost 的 http）。
- `previous-release.json` 與資料夾由精靈再檢查一次：不是一般檔案、太大、格式不對、資料夾是符號連結、manifest 說這一層 OK 但層資料夾裡找不到 `vex.cdx.json`（或它是符號連結），都記 GAP。層名稱（精靈的 `--name` 把 `[A-Za-z0-9._-]` 以外的字元換成 `_` 後）是空白、`.`、`..` 時**不去找資料夾**：manifest 狀態是 OK 時，manifest 不會有這個名稱的層，當成「前一版沒有這一層」記 NOT_RUN（僅供參考，不是 GAP，也不會採用任何資料）；manifest 狀態不是 OK 時照 manifest 的狀態（NOT_RUN 記 NOT_RUN，其他記 GAP）。

### GitLab 版怎麼接（給之後的 T-03 或 C3）

`previous_release.py` 目前只有 GitHub 的 API 用戶端（`GitHub` 類別）。GitLab 的做法：在 CI 範本的 scan 之前，用 Releases API（`GET /projects/:id/releases`）與 `CI_JOB_TOKEN`（或唯讀 token）換一個新的用戶端實作，提供同樣的 `list_releases()`（回傳含 `tag_name`、`draft`、`prerelease` 與附件清單；GitLab 的 Release 沒有草稿，`upcoming_release` 當成 prerelease）與 `download()`，其餘（選版本的規則、zip 檢查、依層組資料夾、manifest）可重用。判斷正式 Release 要改看 `CI_COMMIT_TAG` 與 `CI_PIPELINE_SOURCE`。把資料夾路徑放進 `DUMPLING_PREVIOUS_REPORTS` 就會被精靈讀到。
