# EUVD 標註（`euvd.py`，階段 `C-euvd`）

鏡像腳本（`tools/mirror/euvd.sh`）、標註工具（`euvd.py annotate`，sca-scan 的 `C-euvd`）、DT 的 ENISA KEV 來源檔（`euvd.py dt-enisa`，
`tools/mirror/dt-feeds.sh` 的 `euvdkev` 部分）；報告與每日監控的讀取端見〈讀取端〉。每日更新：`deploy/pilot/euvd-mirror.sh`。

## EUVD 是什麼

ENISA（歐盟網路安全局）依 NIS2 指令第 12 條建的歐盟弱點資料庫，2025 年 5 月上線（https://euvd.enisa.europa.eu）。
每個弱點有自己的編號 `EUVD-YYYY-NNNNN`，同時記 CVE、GHSA 等別名，加上 CVSS、EPSS、廠商與產品、各國 CSIRT 與廠商的公告連結，
以及「已遭利用」標記。ENISA 也是 CVE 編號機構（CNA），歐盟 CSIRT 協調揭露的弱點會先有 EUVD 編號。

CRA 報告裡對歐盟主管機關寫上 EUVD 編號與 ENISA 的已遭利用狀態，讀者不用自己再查一次。

## 取得方式（2026-11-02 實際連線核對）

API 根網址：`https://euvdservices.enisa.europa.eu/api`。端點清單與說明取自 https://euvd.enisa.europa.eu/apidoc
（網頁是 JavaScript 程式，說明文字在 `static/js/main.*.js` 裡）。

| 端點 | 內容 | 核對 |
|---|---|---|
| `/dump/cve-euvd-mapping` | CSV，欄位 `euvd_id,cve_id`。文件：只含已發布 CVE 的紀錄，每日 07:00 UTC 更新 | 已下載：398,838 列、12 MB、5 秒；一個 CVE 只對到一個 EUVD 編號，反過來也是 |
| `/kev/dump` | JSON 陣列，`cveId`、`euvdId`、`dateAdded`（各 KEV 來源中最早的加入日期）、`sources`（`cisa_kev`、`eukev_kev`）。文件：合併 CISA KEV 與 ENISA EU KEV，每日 07:00 UTC 更新 | 已下載：1,783 筆（只在 CISA 1,701、兩邊都有 66、只在 EU KEV 16），260 KB |
| `/search?…` | 篩選查詢，`exploited=true`、分數、日期、廠商、產品等；`size` 最多 100，回 `{items, total}` | 已查：`exploited=true` 共 1,782 筆，18 頁 |
| `/enisaid?id=<EUVD 或 CVE>` | 單筆完整紀錄：`references`、`enisaIdAdvisory`（公告）、`enisaIdProduct`、`exploitedSince`、`epss` 等；找不到回 404 `{"error":"EUVD not found"}` | 已查 CVE-2024-1086 → EUVD-2024-16861，含 RHSA 等公告；CVE-2099-0001 → 404 |
| `/advisory?id=`、`/lastvulnerabilities`、`/exploitedvulnerabilities`、`/criticalvulnerabilities` | 單一公告；首頁用的最新 8 筆 | 已查（回應正常） |

- **EUVD 的「已遭利用」就是 KEV**（已核對）：`search?exploited=true` 的 1,782 個 EUVD 編號與 `kev/dump` 的 `euvdId` 完全相同；
  `kev/dump` 另有 1 筆只有 CVE、還沒有 EUVD 編號。所以這個標記等於 CISA KEV 與 ENISA EU KEV 的聯集，不是另外的情資來源。
  DT 5.2 本來就讀這兩份 KEV（`D-dt-kev-sources`）。網頁上另有「Exploited vulnerabilities - Anomalies (Shadowserver)」的字樣，
  看起來只用在網頁的資訊欄，沒有出現在 API 欄位裡（未核對）。
- **速率限制**：文件沒寫；回應標頭沒有 rate-limit 欄位（已看）。鏡像只下載 2 個大檔，失敗時退避重試。
- **使用條件**：ENISA 網站的法律聲明（https://www.enisa.europa.eu/about-enisa/legal-notice/legal-notice）寫「註明出處即可轉載」；
  是否同樣適用於 euvd 子網域是推論（未核對）。報告上要註明資料來自 ENISA EUVD。
- 不另寫逐筆查詢的增量鏡像：大檔已經包含標註要的全部欄位，一次 Jetson 掃描約 9000 個 CVE，逐筆查詢要好幾小時。

## 鏡像與索引

```
tools/mirror/euvd.sh <鏡像資料夾（必須全新）> <manifest>
tools/mirror/euvd.sh --check <鏡像資料夾>
```

- 內容：`raw/cve-euvd-mapping.csv`、`raw/kev-dump.json`（原檔），以及 `index.tsv`（每個 CVE 一行：EUVD 編號、是否在 KEV、KEV 加入日期、來源）。
  manifest 記來源網址、下載時間、逐檔 sha256。
- 實測（2026-11-02，本機）：26 MB，下載加建索引 15 秒；索引 398,839 個 CVE。
- `--check`：表頭與筆數（`EUVD_MIN_MAPPING_ROWS` 預設 300000、`EUVD_MIN_KEV_ENTRIES` 預設 1000）、格式不符的列、
  由原檔重建索引必須和 `index.tsv` 完全相同、新舊（下載時間 ≤ `EUVD_MAX_AGE_DAYS`，預設 3 天；KEV 最新 dateAdded ≤ `EUVD_KEV_MAX_AGE_DAYS`，預設 14 天）。
  兩份檔案都沒有發布日期，只能用下載時間判斷；KEV 的日期是唯一來自內容的新舊依據。
- 原始資料是外部資料：每個值先用正規式驗證，不合格的列只計數、不寫進索引。

## 標註（`euvd.py annotate`）

```
python3 -I tools/pilot/lib/euvd.py annotate --index <鏡像資料夾> --cves dt/findings.json --cves scan/grype.json --out scan/euvd.json
```

輸入可以是 DT findings、Grype JSON、CVE 文字檔或 JSON 字串陣列（可 .xz）；`UBUNTU-CVE-…`、`DEBIAN-CVE-…` 對到 CVE。
每個 CVE 寫：`euvd_ids`、`in_euvd`、`exploited`、`exploited_text`、`kev_date_added`、`kev_sources`、`links`（EUVD 網頁）。

`exploited` 只有三種值，**不會寫「沒有被利用」**：

| 值 | 意思 | 報告上的文字（第二階段） |
|---|---|---|
| `yes` | EUVD 標示已遭利用（在 CISA KEV 或 EU KEV） | `EUVD-2024-16861 (exploited)` |
| `not_flagged` | EUVD 有這個 CVE，但沒有已遭利用標記 | `EUVD-2025-11377` |
| `unknown` | EUVD 沒有這個 CVE，或沒有可用的索引 | `not in EUVD` 或 `unknown (EUVD index …)` |

status 一行 `C-euvd`：沒有設定鏡像（`--index ""`）、索引不存在、壞掉、被截斷 → GAP，**輸出沒有 `cves`**（讀取端不看 status 時也不可能
把它當成「0 個已被利用」）；索引過期 → GAP（仍標註，說明裡寫過期）；輸入沒有 CVE 而索引可用 → OK（`cves` 是空的）；其他 → OK。
輸入檔讀不到、格式不對、參數錯 → FAIL 一行、退出碼 3。sca-scan 在 DT 與 Grype 都沒有可用的 CVE 清單時記 `C-euvd NOT_RUN`、不寫檔。

抽樣（2026-11-02 的索引；20 個自選的 CVE：Jetson 核心與 Ubuntu 24.04 套件常見的弱點，不是從某一次掃描結果抽出）：20 個都有 EUVD 編號，7 個標示已遭利用（都只在 CISA KEV）。

| CVE | EUVD | 已遭利用 |
|---|---|---|
| CVE-2025-22022（核心） | EUVD-2025-11377 | not_flagged |
| CVE-2025-21756（核心） | EUVD-2025-5169 | not_flagged |
| CVE-2024-1086（核心） | EUVD-2024-16861 | yes（CISA，2024-05-30） |
| CVE-2023-0386、CVE-2024-36971、CVE-2024-50302、CVE-2024-53104、CVE-2025-38352（核心） | 各有 | yes（CISA） |
| CVE-2023-4911（glibc） | EUVD-2023-54750 | yes（CISA） |
| CVE-2024-26581、CVE-2023-52447（核心）；CVE-2024-6387、CVE-2024-3094、CVE-2023-38545、CVE-2024-2961、CVE-2024-45490、CVE-2016-2781、CVE-2017-13716、CVE-2022-27943、CVE-2025-4802（使用者空間） | 各有 | not_flagged |

對照表有 398,838 個 CVE（同期 DT 的 NVD 約 41 萬筆，含已撤銷的），看起來涵蓋幾乎所有已發布的 CVE（推論，未逐一核對）；
「不在 EUVD」多半是剛發布、還沒進當天的檔案，或已撤銷的 CVE。

## 和 DT 的 KEV 比對（2026-11-05 06:49 UTC 同一天的資料，另一個帳號實測；13:51 UTC 本機重新下載，數字相同）

- DT 5.2 的 ENISA KEV 來源預設讀 `raw.githubusercontent.com/enisaeu/CNW/main/advisories/eukev/eukev.json`（`EnisaKevDataSourceFactory`）。
  這份檔**最後一次 commit 是 2026-08-13**，39 個 CVE，最新 dateReported 2026/08/11。DT 的 ENISA mirror 照樣 COMPLETED。
- EUVD 的「已被利用」＝`kev/dump`：1,785 筆（只在 CISA 1,703、兩邊都有 66、只在 EU KEV 16）；`/search?exploited=true` 全部翻頁的集合相同。
- DT 的 CISA（1,768）∪ eukev.json（39）＝1,773，是 EUVD 的嚴格子集：EUVD 多 **12 個 CVE**（11 個只在 EU KEV，9–10 月加入；1 個 EUVD 標
  cisa_kev 但當天的 CISA 檔沒有——CVE-2026-69836，可能被 CISA 移除，未核對）；DT 有而 EUVD 沒有的 0 個。
- 所以「ENISA KEV 與 EUVD 的已遭利用清單是否相同」的答案是**不同**：我們這層（`cra_report.py`、`exploited_watch.py`）讀 EUVD，
  DT 的 ENISA KEV 也改讀 EUVD 產生的檔（下一節）。

## DT 的 ENISA KEV 來源檔（`euvd.py dt-enisa`）

`tools/mirror/dt-feeds.sh` 的 `euvdkev` 部分（或 `DT_KEV_EUVD_FROM=<euvd.sh 的鏡像>` 沿用同一份 kev/dump）產生 `kev/euvd/eukev.json`，
內網 DT 的 enisa `feedUrl` 指向它（pilot：`http://dt-nvd-mirror/kev/euvd/eukev.json`，`deploy/pilot/install.sh` 在 `PILOT_NVD_MIRROR=1` 且
EUVD 鏡像通過檢查時設定）。

- **DT 怎麼讀**（DependencyTrack/dependency-track tag 5.2.0、commit d67a6a3a 的原始碼，2026-11-05 核對；檔名與行為在 `euvd.py` 的註解）：
  頂層要是陣列（否則靜默讀成 0 筆）；每筆轉成 `EnisaKevEntry`（`@JsonIgnoreProperties(ignoreUnknown = true)`）：`cveID`（可 null，null 就略過）、
  `euvdID`（沒用到）、`dateReported`（`LocalDate`，`yyyy/MM/dd`；沒有 null 檢查，缺少會 NullPointerException、整次 mirror 失敗）、
  `shortDescription`（→ description，可缺）、`exploitationType`（`ransomware` → knownRansomware=true，其他 → null，可缺）。
  斷言的 vulnSource 固定 NVD、vulnId 是 cveID；mirror 完刪掉這次沒看到的 enisa 斷言。**沒有在 DT 上實測**（部署後以 KEV 筆數驗證）；
  不合法日期（例如 2026/02/30）在 Jackson 的 SMART 模式下怎麼處理未核對（產生的檔只寫合法日期）。
- **選哪些**：kev/dump 裡 sources 含 `eukev_kev` 的條目（2026-11-05：82 筆）。DT 的來源叫「ENISA EU KEV」，CISA 的條目由 DT 的 CISA 來源讀；
  全部放進來會讓 enisa 的 asserter 也替 CISA 的條目背書，DT 裡的來源就分不清。結果：DT 的 ENISA KEV 從 39 筆變 82 筆，DT 的 isKev 多 11 個 CVE；
  剩下的 1 個（EUVD 標 cisa_kev、CISA 檔沒有）DT 仍不會標，由我們這層的 EUVD 標註抓到（P1、顯示來源、由人判斷）。
- **欄位**：kev/dump 沒有 `shortDescription`、`exploitationType`。上游 eukev.json 有同一個 CVE 時沿用它的欄位（含 ransomware；2026-11-05 有 39 筆），
  其他的不寫（DT 記 null＝未知）。`dateReported` 優先用上游的，否則用 kev/dump 的 `dateAdded`（各 KEV 來源最早的加入日期：也在 CISA 的條目可能是 CISA 的
  日期）。另加 `euvdSources`、`euvdDateAdded`、`dataOrigin`（DT 不讀，存在 RAW 方便追溯）。上游有而 EUVD 的 EU KEV 沒有的 CVE **照上游寫進**（日期與欄位用上游的，
  `dataOrigin` 標「只在上游」；DT 每次 mirror 會刪掉這次沒看到的 enisa 斷言，不寫的話 DT 會默默少掉它們），計數 `upstream_only_entries`。
- **和 CISA KEV 比對**：另抓 CISA KEV（`www.cisa.gov`，DT 的 CISA 來源讀的同一份檔），`SOURCE.json` 的 `euvd_not_in_dt` 列出 EUVD 標已遭利用、
  但 CISA KEV ∪ 這份檔都沒有的 CVE（DT 的 isKev 不會標；2026-11-05 是 CVE-2026-69836，EUVD 標 cisa_kev、當天的 CISA 檔沒有）。
  `D-dt-kev-sources` 的狀態不因此改變（來源之間的不一致，不是缺資料），只在說明以 NOTE 列出（過期時 GAP 的說明也列出）；
  風險評估把它們逐筆放進 P1。`skipped_no_date` 的條目則記 ATTENTION（DT 的檔真的少了它們）。
  - CISA KEV 沒有下載或無法解析時 `euvd_not_in_dt` 是 `null`、`cisa_problem` 寫原因：比對被跳過，`D-dt-kev-sources` 記 **ATTENTION**（不是 OK），
    說明寫出 `cisa_problem`；下一次 `euvd-mirror.sh update` 抓到 CISA KEV 後恢復。
  - 比對用的是 `euvd-mirror.sh update`（`dt-feeds.sh` 的 euvdkev 部分）另抓的 `cisa-kev.json`，**不是 DT 的 CISA 來源實際讀的那一份**
    （DT 在自己的排程，每天 02:00 UTC，直接讀 www.cisa.gov）。兩份通常差不到一天，每日更新連續失敗時最多可差 `EUVD_MAX_AGE_DAYS`（預設 3）天：這段期間 CISA 新增的 CVE 可能漏列（我們的檔有、DT 還沒讀到），
    移除的可能多列（我們的檔沒有、DT 還留著）。會出現在：`SOURCE.json` 的 `euvd_not_in_dt`；`dt-feeds.sh --check`（`euvd-mirror.sh check`）的 NOTE 行；
    sca-scan 的 `D-dt-kev-sources` 說明（`data-sources.json` 的 `enisa_feed.source.euvd_not_in_dt`）。後兩處的文字都註明這一點。
    報告端的 P1 讀 EUVD 本身（`scan/euvd.json`；`exploited_watch.py` 讀鏡像的索引），不讀這份清單，所以不受這個時間差影響。
  - 同一個 CVE 只列一次：已在 `skipped_no_date`（這裡沒寫進 DT 的檔，ATTENTION）的 CVE 不再列入 `euvd_not_in_dt`（來源不一致，NOTE）。
- **連線**：`euvd.sh` 對 euvdservices.enisa.europa.eu 2 個請求；`euvdkev` 部分另抓上游 eukev.json（raw.githubusercontent.com）與 CISA KEV（www.cisa.gov）
  各 1 次（`DT_KEV_EUVD_FROM` 時不再抓 kev/dump；kev 部分已下載時複製），後兩個失敗時只 WARN、照樣產生。
- **檢查**：`dt-feeds.sh --check`（`euvd.py dt-enisa-check`）由原始檔重建比對、檢查 DT 的格式與筆數、kev/dump 下載時間與最新 dateAdded 的新舊；
  上游落後時只印 NOTE。sca-scan 的 `D-dt-kev-sources`（`dtsources.py --enisa-config`）讀 DT 實際的 feedUrl：必須**完全等於**這份檔的網址
  （`EUVD_DT_FEED_URL`，預設 `http://dt-nvd-mirror/kev/euvd/eukev.json`；其他部署，例如 dt-offline 的檔案伺服器，要設這個環境變數），
  不是、或這份檔過期 → GAP，DT 顯示 COMPLETED 也一樣；有 EU KEV 條目因為沒有可用的日期沒寫進檔（`skipped_no_date`）→ ATTENTION 並點名 CVE（不補日期）。
- **已知限制**：
  - kev/dump 的 `sources` 只認小寫（`eukev_kev`、`cisa_kev`；`SRC_RE`）：大小寫不同的值不收，那個條目不會進 DT 的檔（2026-11-05 的實際資料都是小寫）。
  - DT 的 ENISA 設定 `enabled` 要是 JSON 的 `true`；字串 `"true"` 算沒有啟用（GAP）。
  - 新舊以掃描端（或 GitLab runner 的複本）的 EUVD 鏡像判斷，不是 DT 實際讀到的那一份；兩者每日由同一份 `current` 同步，但 DT 讀檔的時間點未核對。
  - 上游 eukev.json 同一個 CVE 出現多次時，取第一筆有合法 `dateReported` 的（都沒有時取第一筆）。

## 部署

步驟與驗證在 `deploy/pilot/README.md` 的〈常駐環境部署〉：實際在跑的 DT 是 runner 的常駐環境 `sca-persist`，
要經 `sca-persistent` workflow 重新部署，再從 `<常駐環境>/current` 跑 `deploy/gitlab-runner/install.sh`；不要在 repo 裡直接跑 deploy/pilot 的腳本
（會另起一套 `sca-pilot`）。DT 的 `KEV_ASSERTION` 裡 enisa 的筆數應從 39 變成 `SOURCE.json` 的 `entries`（2026-11-05：82）。

## 讀取端

- `cra_report.py`（C 線② PR-2）：EUVD 標示已遭利用的 CVE 是另一種被利用證據（不設 kev，記在 `exploited_sources`），**兩種分級方式都進 P1**，
  包括 DT 沒有標 isKev 的（例如上面的 CVE-2026-69836，逐筆成為 P1 的列）；KEV 欄寫 `EUVD (CISA KEV)`、`EUVD (ENISA EU KEV)` 等；
  status 不是 OK、讀不到 → 當作沒有資料、風險評估文件 GAP（理由只在一個地方產生）。`vex_export.py` 的批次規則與發行閘門也算它。
  細節在 `tools/cra/README.md` 的「EUVD」。`C-euvd` 不進 RISK_STAGES（不然 GAP 的理由會寫兩次）。
- `exploited_watch.py`：以 `exploited_index()` 讀 EUVD 鏡像的 `index.tsv`（basis `euvd`，來源寫出 CISA KEV／ENISA EU KEV；
  沒有或過期 → ATTENTION；狀態鍵不變），警示信寫出每個新 CVE 的來源。

## 使用者決定（2026-11-05）

1. DT 的 ENISA KEV 也要改（「我們部署的有問題就改」）：讀 EUVD 產生的檔（上面）。
2. EUVD 過期或沒有 → 風險評估 GAP。
3. **先不對外通報** ENISA CNW 或 DT（GitHub 上的 eukev.json 已經不是最新）。
4. CISA 已移除、EUVD 仍列的 CVE 照樣 P1，顯示來源，由人判斷，不自動降級。

## 還沒做

- 公告與緩解連結：大檔沒有這些欄位，要逐筆查 `/api/enisaid`（離線要在鏡像端查約 1,800 次），先只放 EUVD 網頁連結。
- 報告的 EUVD 編號目前只在 KEV 欄（已遭利用的列）；沒有被利用的列的 EUVD 編號只在 `scan/euvd.json`。
