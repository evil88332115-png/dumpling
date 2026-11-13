# WATCH：每日監控（WP2，PLAN「E. 監控與通知」）

契約文件：`pipeline/watch/` 各支程式的輸入輸出。改契約要同時改這份文件和兩邊的測試。

## 1. 架構（為什麼不開 DT）

- `tools/cra/exploited_watch.py` 以 **DT 專案 UUID** 當比對鍵；GitHub 上每天只能開臨時 DT，UUID 每天不同，會每天全部算新的。
  所以每日監控不開 DT，改成：Grype 重新比對（設定與 Release 相同，`exploited_grype.prepare`）＋CISA KEV＋EUVD＋核心 CNA＋廠商層級。
- **重用、不改**既有工具：`exploited_grype.prepare`／`extract`／`cisa_kev`／`db_status`、`exploited_watch.update_state`／`euvd_text`、
  `euvd.exploited_index`、`exploited_vendor.run_vendor_watch`／`load_config`、`tools/pilot/lib/kernel_cna_version.py`（以指令呼叫）。
- 穩定的專案鍵：`project_uuid` 欄位放 `dumpling:<專案>/<版本>#<層>`（不是 DT 的 UUID）。開發版（滾動 pre-release `dev/<專案>`）的版本固定寫 `dev`，
  每次開發版重建不會變成新的比對。

## 2. 覆蓋範圍（跟 Release 掃描比，每天哪些有、哪些沒有）

| 項目 | Release 掃描 | 每日監控 | 每日沒跑時 |
|---|---|---|---|
| Grype（含 L4T 核心對應、SBOM 的 CPE，例如 D-034 的 U-Boot 上游 CPE） | 有 | 有（同設定） | — |
| CISA KEV、EUVD（CISA KEV ∪ ENISA EU KEV） | DT＋EUVD | 有（每天下載） | 讀不到或過期 → GAP |
| 核心 CNA（kernel_cna_version.py） | 有 | 有，但 `.config` 判定不跑：affected＋unknown 都當候選，Issue 寫「.config 未判定」 | Release 沒有附核心上游版本 → GAP |
| DT（OSV）那條路 | 有 | **NOT_RUN**（報告依層列出） | — |
| NVIDIA 公告 | 有 | **NOT_RUN**（報告列出；廠商層級的 nvidia 仍有） | — |
| 廠商層級（exploited_vendor） | — | 有 | — |

## 3. 程式與資料流

```
watch.yml（每天）
  compute（contents: read、issues: read）
    feeds.sh            → $W/feeds/（CISA KEV、EUVD 鏡像、核心 CNA 鏡像、Grype DB）
    collect.py          → $W/inventory.json＋$W/releases/<n>/…（Release 附件）
    issues.py read-state→ $W/state.json＋$W/state-base.json（狀態 Issue 的內容與樂觀鎖資訊）
    match.py            → $W/plan.json（要開的 Issue、要留言的 Issue、新的狀態）＋$W/report.md
    （plan.json 以 artifact 交給下一個 job）
  notify（issues: write）
    issues.py apply     ← plan.json（再核對一次標記與樂觀鎖；冪等）
  keepalive（actions: write）
    讀 watch.yml 的 state、記錄、呼叫 enable
```

### 3.1 `pipeline/watch/collect.py`（4a）

```
python3 -I pipeline/watch/collect.py (--repo <owner/repo> | --from-dir <資料夾>) --out <工作資料夾> [--max-asset-mb 200]
```
- `--repo`：用 GitHub REST API（`GH_TOKEN`／`GITHUB_TOKEN`，只讀）列出 Release。**跳過 draft**。
  - 正式版：tag `<專案>/<版本>`、不是 prerelease → `kind: release`
  - 開發版：tag `dev/<專案>`、prerelease → `kind: dev`
  - 其他 tag → 列進 `skipped`（附原因）
- `--from-dir`：讀 `<資料夾>/*/release-meta.json`（合成 Release，演練與測試用）；同一個資料夾裡的附件檔名規則和真的一樣。
- 每個 Release 下載：`release-meta.json`（必要）、`sbom-<專案>-<版本>-bsp.cdx.json`、`-os.cdx.json`、整份 `sbom-<專案>-<版本>.cdx.json`、
  `layers.json`、`kernel-versions-<專案>-<版本>.json`（選填，C1 在 M2 提供；只接受 schema `sca-center-kernel-versions/2`，其他版本 → 核心 CNA 標 GAP、寫明 schema 不符：shipped 每顆核心有 `upstream_version`（對不上是 null）、`upstream_basis`、`upstream_note`；null 或沒有附件 → 核心 CNA 標 GAP，Issue／報告寫 upstream_note）、`scan-summary-<專案>-<版本>.json`（選填）。
  - 有分層 SBOM 就用 bsp＋os；沒有分層 SBOM 只有整份 → 層記 `product`。
  - 附件是不可信資料：檔名照規則組出，不用 API 回的檔名當路徑；大小上限；不跟隨連結；JSON 解析失敗算該 Release 的問題（不讓整次失敗）。
  - release-meta 的 `project`、`version` 要跟 tag 一致（dev 版 tag 是 `dev/<專案>`），`status` 只能是 `shipped`／`development`，不一致 → 該 Release 記 problem、不比對。
- 輸出 `<out>/inventory.json`：

```json
{"schema": "dumpling-watch-inventory/1", "generated_at": "2026-11-13T00:00:00Z", "source": "github:owner/repo | dir",
 "status": "OK|GAP|FAIL", "detail": "…",
 "releases": [{"tag": "p/v1", "kind": "release|dev", "project": "p", "version": "v1", "watch_version": "v1｜dev",
               "status": "shipped|development", "platform": "jetson", "os_responsibility": "customer", "commit": "40hex",
               "published_at": "…", "html_url": "…",
               "sboms": {"bsp": {"file": "releases/0/sbom-p-v1-bsp.cdx.json", "sha256": "…", "size": 1}, "os": {…}},
               "kernel_versions": "releases/0/kernel-versions-p-v1.json｜null", "scan_summary": "releases/0/…｜null",
               "problems": []}],
 "skipped": [{"tag": "…", "why": "…"}]}
```
  - 路徑都是相對 `<out>` 的相對路徑（不寫絕對路徑，狀態 Issue 是公開的）。
  - status：API 失敗 → FAIL；有 Release 有 problem → GAP；否則 OK。stdout 一行 `WATCH-COLLECT<TAB>狀態<TAB>說明`；結束碼 OK 0、FAIL 1、GAP 3、用法 64。

### 3.2 `pipeline/watch/match.py`（4b、4c，C3 自己寫）

讀 inventory、feeds、state.json → 呼叫既有工具 → 產生 `plan.json`。規則：
- **第一次（state.json 不存在且 `state-base.json` 說沒有任何監控 Issue）只建基準**：所有比對記 `baseline: true`，不開 Issue。
- 狀態 Issue 不存在、但已有監控 Issue → FAIL（不能重新建基準，會吞掉新的命中）。
- 已有基準之後：新的（含新加入的 Release 本來就有的 KEV）→ 開 Issue；再出現 → 在原 Issue 留言（原 Issue 已關閉時開新 Issue）；
  消失 → 在原 Issue 留言（不自動關閉，關閉由人決定）。一次最多開 `--max-new-issues`（預設 20）個，其餘併成一個彙總 Issue。
- Issue 粒度：比對 (專案, 監控版本, 層, CVE) 一個 Issue（同一個 CVE 的多個元件列在同一個 Issue）；廠商層級 (專案, 監控版本, CVE, 廠商) 一個。

### 3.3 `plan.json`（match.py → issues.py 的契約）

```json
{"schema": "dumpling-watch-plan/1", "mode": "real|drill", "generated_at": "…", "run_url": "…",
 "state_base": {"issue": 12, "updated_at": "…", "body_sha256": "…"} ,
 "state": {…新的狀態，見 3.5…},
 "actions": [
   {"op": "open", "key": "<64 hex>", "title": "…", "body": "…", "labels": ["dumpling-watch", "kev", "shipped", "layer-bsp"]},
   {"op": "comment", "key": "<64 hex>", "body": "…", "reopen_if_closed": false},
   {"op": "open_if_closed", "key": "<64 hex>", "title": "…", "body": "…", "labels": […]}
 ],
 "status": "OK|ATTENTION|FAIL", "detail": "…"}
```
- `state_base`：compute 讀到的狀態 Issue（第一次是 `null`）。apply 時狀態 Issue 的 `updated_at` 或內容 sha256 不同 → FAIL，不寫（有別的執行改過）。
- `key`＝`sha256("dumpling-watch/1|" + mode + "|" + 比對鍵)` 的十六進位。

### 3.4 `pipeline/watch/issues.py`（4d）

```
python3 -I pipeline/watch/issues.py read-state --repo <owner/repo> --mode real|drill --out <資料夾>
python3 -I pipeline/watch/issues.py apply      --repo <owner/repo> --plan <plan.json> [--dry-run]
python3 -I pipeline/watch/issues.py close-drill --repo <owner/repo>      # 演練結束：關閉所有 drill Issue
```
- Token：`GH_TOKEN`／`GITHUB_TOKEN`，只放 HTTP 標頭；不跟隨轉址到別的主機；只連 `api.github.com`（`GITHUB_API_URL` 可改，給 GHES／測試用）。
- 監控 Issue 的內文第一行是標記：`<!-- dumpling-watch key=<64 hex> mode=<real|drill> -->`。
  去重：列出標籤 `dumpling-watch` 的所有 Issue（open＋closed，分頁），本地解析標記；**不用 search API**（索引有延遲）。
- 狀態 Issue：標籤 `watch-state`（drill 是 `watch-state-drill`），內文第一行 `<!-- dumpling-watch-state mode=<mode> schema=1 -->`，
  接著一個程式碼區塊：狀態 JSON 經 gzip＋base64。超過 60000 字元 → FAIL（不截斷）。同時有兩個狀態 Issue → FAIL。
  - `read-state` 輸出 `<out>/state.json`（沒有狀態 Issue 時不產生）與 `<out>/state-base.json`：
    `{"issue": 12｜null, "updated_at": "…", "body_sha256": "…", "watch_issues": <該 mode 的監控 Issue 數>}`。
- `apply`：
  - 先確認 `state_base` 跟現在的狀態 Issue 一致（樂觀鎖），不一致 → FAIL、什麼都不改。
  - 依序執行 actions：`open` 前再列一次標記，已存在就跳過（冪等）；`comment` 找不到原 Issue → 記 problem（不 FAIL）。
  - 缺的標籤自動建立（顏色固定）。
  - 全部做完才寫狀態 Issue（建立或更新內文）；mode=drill 的 Issue 一律加標籤 `drill`。
  - 寫入前，title、body、狀態 JSON 都要過公開檢查的通用規則（`ci/public-patterns.txt`＋`ci/public-allow.txt`，用 `pipeline/watch/publiccheck.py`），
    命中 → FAIL、不寫。
- stdout 一行 `WATCH-ISSUES<TAB>狀態<TAB>說明`；結束碼 OK 0、FAIL 1、用法 64。

### 3.5 狀態（state.json，放在狀態 Issue 裡）

- 結構沿用 `exploited_watch` 的狀態檔（schema 1）：`matches`（鍵＝json [project_uuid, CVE, 元件]）、`vendor_matches`、`vendor_watch`、`runs`，
  另加 `dumpling`: `{"baseline_at": "…", "mode": "real|drill", "issues": {"<key>": {"kind": "kev|vendor", "first_detected": "…"}}}`。
- 只放公開資料：CVE、purl、版本、時間、Release tag、SBOM sha256。**不放路徑、主機資訊**（match.py 寫入前只保留白名單欄位）。
- `runs` 只留最近 30 次。
- GitLab 階段：狀態 Issue 一定設成 confidential（寫在 GITLAB-PORT）。

## 4. 防止排程被停用（60 天）

官方文件（2026-11-13 查）只寫「公開 repo 60 天沒有 repository activity，排程 workflow 會自動停用」，**沒有定義什麼算 activity**；
`PUT /repos/{owner}/{repo}/actions/workflows/{id}/enable` 說明是「sets the state of the workflow to active」，沒寫會不會重新計算 60 天；
通知寄給「最後修改 cron 語法的使用者」。做法：keepalive job（只有 `actions: write`）每天先讀 workflow 的 state 並寫進 job 摘要，再呼叫 enable；
STATUS 的 C3 節記「下次人工檢查日期」，每月人工看一次 `gh workflow view watch.yml`。

## 5. 公開 repo 的 real 模式（D-040）

- 排程的 real **預設只算不寫**（dry_run）：repo 變數 `WATCH_REAL_ISSUES` 是 `on` 才開 Issue。M2 合併、第一次真實基準（手動 `mode=real`，只寫狀態 Issue、不開監控 Issue）之後，
  C3 回報「打開的話會開哪些 Issue」，C0 看過再打開。手動觸發 `mode=real` 照輸入的 dry_run。
- 只開兩種 Issue：已遭利用（KEV／EUVD）、廠商層級。一般 CVE 候選（核心 CNA 的上千筆、D-034 的 U-Boot 候選）不開。
  一次新增超過 20 個群組 → 全部併成一個彙總 Issue（ATTENTION）。
- 標題與內文寫明「示範專案（公開 BSP）」、加 `demo` 標籤（`match.py --demo`）；release-meta 的 shipped／development 照用。
- 第 14 條通報在公開 repo 只做演練（`art14-drill`）；real 命中不開 art14 Issue（M8）。

## 6. 演練（drill，公開 repo 只做演練）

- `watch.yml` 手動觸發 `mode=drill`：inventory 用 `tests/fixtures/watch/drill/`（合成 Release：合成的 SBOM，元件是公開套件的真實版本），
  KEV 用合成的 KEV 檔（`--kev-overlay`：把指定 CVE 加進 CISA KEV 清單），狀態用 `watch-state-drill`，跟真實狀態完全分開。
- 驗收步驟：(1) 沒有 overlay → 建立基準、0 個 Issue；(2) overlay 加一個 CVE → 開 1 個 Issue；(3) 再跑一次 → 0 個新 Issue；(4) `close-drill`。
