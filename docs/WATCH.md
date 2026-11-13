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
| DT（OSV）那條路 | 有 | **NOT_RUN**（每份報告與每個 KEV Issue 都列在「每日沒有涵蓋」，不分層） | — |
| NVIDIA 公告 | 有 | **NOT_RUN**（報告列出；廠商層級的 nvidia 仍有） | — |
| 廠商層級（exploited_vendor） | — | 有 | — |

## 3. 程式與資料流

```
watch.yml（每天）
  compute（contents: read、issues: read、actions: read：查上一次排程 run 的結果）
    feeds.sh            → $W/feeds/（CISA KEV、EUVD 鏡像、核心 CNA 鏡像、Grype DB）
    collect.py          → $W/inventory.json＋$W/releases/<n>/…（Release 附件）
    issues.py read-state→ $W/state.json＋$W/state-base.json（狀態 Issue 的內容與樂觀鎖資訊）
    match.py            → $W/plan.json（要開的 Issue、要留言的 Issue、新的狀態）＋$W/report.md
    （plan.json 以 artifact 交給下一個 job）
  notify（issues: write）
    issues.py apply     ← plan.json（再核對一次標記與樂觀鎖；冪等）
  keepalive（actions: write）
    讀 watch.yml 的 state、記錄、呼叫 enable
  drill-close（issues: write，只在 drill）
    issues.py close-drill：關閉演練 Issue、換成 *-done 標籤
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
  `layers.json`、`kernel-versions-<專案>-<版本>.json`（C1 在 M2 提供，見下；只接受 schema `sca-center-kernel-versions/2`，其他版本 → 核心 CNA 標 GAP、寫明 schema 不符：shipped 每顆核心有 `upstream_version`（對不上是 null）、`upstream_basis`、`upstream_note`；null 或沒有附件 → 核心 CNA 標 GAP，Issue／報告寫 upstream_note）、`scan-summary-<專案>-<版本>.json`（選填）。
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
  - 每個 Release 另有 release-meta 的結論欄位（C1 wp1/m2 9f1d2f0 的實際格式；`status` 是生命週期 development／shipped，**不是掃描結論**）：
    `report_status`（字串：最差那一份報告）、`release_gate`（字串：vex.gate）、`pipeline_result`（字串：流程步驟的結果，不是產品結論）、
    `reports`（`[{report, report_status, release_gate}]`，每份報告一筆，report 是 full／bsp／os…）、`attention`（字串清單：用了舊資料頂替的說明，有才有）。
    值的範圍 OK｜ATTENTION｜NOT_RUN｜GAP｜NOT_ASSESSED｜FAIL，**照原值顯示、不轉換**；缺少或其他形狀一律 `NOT_RUN`。沒有其他讀法（舊名 `result` 已拿掉）。
    每個 KEV／廠商層級 Issue 列「Release 的結論」一行（含每份報告的狀態與 attention），報告的各 SBOM 表也列。
  - `kernel-versions-<專案>-<版本>.json`：照 release-meta 的 `kernel_versions` 欄位（附件檔名或 null）。null → 不讀（核心 CNA 標 GAP）；
    不是規則檔名 → problem、不讀；列了但 Release 沒有這個附件 → problem。開發版 `dev/<專案>` 也有這個附件。
  - status：API 失敗 → FAIL；有 Release 有 problem → GAP；否則 OK。stdout 一行 `WATCH-COLLECT<TAB>狀態<TAB>說明`；結束碼 OK 0、FAIL 1、GAP 3、用法 64。

### 3.2 `pipeline/watch/match.py`（4b、4c，C3 自己寫）

讀 inventory、feeds、state.json → 呼叫既有工具 → 產生 `plan.json`。規則：
- **第一次（state.json 不存在且 `state-base.json` 說沒有任何監控 Issue）只建基準**：所有比對記 `baseline: true`，不開 Issue。
  - 要人明確指定：`--allow-baseline`（watch.yml 手動觸發 `mode=real`＋`baseline=true`；drill 一律給）。沒有指定 → GAP、不產生 plan。
    狀態 Issue 與監控 Issue 都不見時（例如誤刪）不會悄悄重建基準。
  - 有可監控的 Release 卻沒有基準（real）：plan 的 `state` 是 `null`，只開一個固定的「還沒有基準」提醒 Issue（標籤 `watch-health`，op `open`：
    已經有就不重複），issues.py 不寫狀態。這個提醒 Issue 不算「監控 Issue」（不會讓下一次變成「沒有狀態卻有監控 Issue」的 FAIL）；
    建立基準那一輪會在它底下留言。排程綠燈但 GAP 時，看這個 Issue 或 Step Summary。
  - 條件：全部 SBOM 的 Grype 都跑完、Grype DB 是 OK（過期的 DB 建出的基準，DB 更新後既有命中會被當成新的）、
    L4T 核心對應不是 GAP／FAIL（擋下的理由：對應失敗時核心元件沒有比對，基準會漏掉核心的 KEV，之後對應修好時那些既有命中會一次變成新的）、
    CISA KEV 是 OK、EUVD 是 OK（real）、Release 沒有 problem、核心 CNA 沒有 NOT_RUN、廠商層級有跑；
    任何一項不成立 → FAIL、不寫狀態（基準不完整會讓下一次把既有的命中當成新的）。核心 CNA 因為 Release 沒有附件而 GAP 不擋（那是資料不存在，不是沒跑）。
- **還沒有狀態、也沒有任何可監控的 SBOM**（例如 M2 之前只有 draft 或舊格式 Release）→ GAP（結束碼 3），不建空的基準、不產生 plan.json；
  workflow 的 compute 輸出 `has_plan=false`，notify 跳過。M2 之前排程每天是 GAP，不是 FAIL（不亮紅燈）。演練一定要有 plan，沒有就失敗。
- 狀態 Issue 不存在、但已有監控 Issue → FAIL（不能重新建基準，會吞掉新的命中）。
- 已有基準之後：新的群組（含新加入的 Release 本來就有的 KEV）→ 開 Issue；
  已有 Issue 的群組出現新元件（同一個 CVE 的新 purl：SBOM 重發、開發版元件版本變了、Grype DB 多比對到一個元件）或再出現 → `open_if_closed`
  （原 Issue 開著就留言，關閉了就開新的）；基準裡的比對消失後又出現、群組從來沒有 Issue → 不再算基準，開 Issue；
  群組全部消失 → 在原 Issue 留言（不自動關閉，關閉由人決定）。
- 廠商層級的手動清單（`pipeline/watch/vendor-watch.json`，對所有專案生效）：BIOS／vBIOS 韌體的 **Intel、AMD、AMI、NVIDIA**（D-043 第 3 點）
  只要 KEV／EUVD 出現新的條目，就開廠商層級 Issue（沒有元件比對也提醒；已有元件比對的走 KEV Issue）。比對 KEV 的 `vendorProject`，
  經 `exploited_vendor` 的正規化與別名（`American Megatrends`→ami、`Advanced Micro Devices`→amd、`NVIDIA Corporation`→nvidia）。
  拼法查核（2026-11-13）：CISA KEV catalogVersion 2026.11.10（1779 筆）實際有 `Intel`（2 筆）、`AMI`（1 筆，CVE-2024-54085 MegaRAC SPx）；
  **AMD、NVIDIA 在 CISA KEV 與 EUVD 的 KEV dump（1796 筆）都還沒有條目，拼法無法從資料確認**——待辦：第一筆出現時核對 `vendorProject` 的實際拼法，
  不在別名裡就補進 `vendor-watch.json` 的 `aliases`（在那之前，`AMD`／`Advanced Micro Devices`／`NVIDIA`／`NVIDIA Corporation` 已涵蓋）。
  C2 的韌體 SBOM 公告比對會用到這裡的廠商層級結果。
- 廠商層級：只對新的命中開 Issue；再出現與消失**不留言**（廠商層級是較粗的提示，`exploited_vendor` 的再出現本來就不算新的）。
- 降級（只在 real；核心 CNA 缺附件、schema 不符、upstream_version 為 null 也算）：Grype NOT_RUN、CISA KEV／EUVD／Grype DB 不能用或過期、L4T 核心對應 GAP／FAIL、核心 CNA NOT_RUN、已遭利用但元件版本未知
  、Release 附件問題（SBOM 下載失敗、release-meta 不符）、已有狀態卻沒有任何可監控的 Release、
  **上一次排程 run 被取消／失敗／逾時或超過 36 小時沒有排程**（compute 用 `actions: read` 查 watch.yml 的排程 run；keepalive 也印出最近 3 次）
  → 連續 2 次就在固定的健康 Issue（標籤 `watch-health`）開／留言，沒恢復時每 7 天提醒一次；連續 2 次正常才留言「恢復」。報告與 Step Summary 每次都列。
- 已有 Issue 的群組的事件（新增元件、再出現）一次超過 `--max-new-issues` 個 → 併成一個彙總 Issue，不逐一開。
- 已知窗口：降級要連續 2 次才開健康 Issue，第一天只在 Step Summary（結束碼 2 視為成功）；排程 dry_run 期間狀態不寫入，連續次數不會累積。
  C0 打開 `WATCH_REAL_ISSUES` 前要知道這一點。
- 待 M2 之後確認：D-034 的 U-Boot 上游 CPE 實際被 Grype 比對到（目前沒有含 CPE 的測試資料）。
- 每個 KEV Issue 列出靜態的「每日沒有涵蓋」三項，加上這個 Release 這次的 GAP（例如核心 CNA 缺附件時的 upstream_note、L4T 核心對應失敗）。
- 正式版的版本字串是 `dev` → 不比對（會跟開發版的專案鍵相同），記成 Release 問題。一次最多開 `--max-new-issues`（預設 20）個，其餘併成一個彙總 Issue。
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
  - plan 的交叉核對：`--mode`（workflow 一律給）要等於 plan.mode、state.schema 是 1、state.dumpling.mode 相同；actions 最多 200 個；
    標籤只能是白名單（dumpling-watch、kev、vendor-level、shipped、development、layer-*、demo、summary、drill、watch-health）。不合 → FAIL、什麼都不做。
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
  （Step Summary 與 artifact 裡的報告會有 runner 的暫存路徑，例如 Grype NOT_RUN 的原因；那不寫進 Issue。）
- 修剪：消失超過 180 天的比對（`matches`、`vendor_matches`）與沒有剩下任何比對、開出超過 180 天的群組紀錄，從狀態移除；被修剪的比對之後再出現算新的（開新 Issue，偏保守）。
  10 年保存是 GitLab 階段的內部儲存，不靠公開 Issue。
- 修剪過的群組之後再出現：用 `open_if_closed`（舊 Issue 已關閉就開新的、開著就留言），不會被「已有 Issue」跳過；群組鍵記在 `dumpling.pruned_keys`。
- 大小：編碼後超過約 45000 字元 → 整輪 ATTENTION，並在健康 Issue 留言「接近上限」（7 天一次，不每天留言）。超過 60000 字元 → `apply` 照樣執行 Issue 動作（新的 KEV、彙總 Issue 開得出來），
  **狀態不寫**，最後明確 FAIL（下一輪從舊狀態重算：open 因標記跳過，不重複開；留言可能重複）。分段存放是之後的待辦。
- `runs` 只留最近 30 次。
- GitLab 階段：狀態 Issue 一定設成 confidential（寫在 GITLAB-PORT）。

## 4. 防止排程被停用（60 天）

官方文件（2026-11-13 查）只寫「公開 repo 60 天沒有 repository activity，排程 workflow 會自動停用」，**沒有定義什麼算 activity**；
`PUT /repos/{owner}/{repo}/actions/workflows/{id}/enable` 說明是「sets the state of the workflow to active」，沒寫會不會重新計算 60 天；
通知寄給「最後修改 cron 語法的使用者」。做法：keepalive job（只有 `actions: write`）每天先讀 workflow 的 state 並寫進 job 摘要，再呼叫 enable；
`status` 分支上 `docs/STATUS.md` 的 C3 節（D-008，不在 main）記「下次人工檢查日期」，每月人工看一次 `gh workflow view watch.yml`。
workflow 一旦被停用，keepalive 本身也不會跑，只有人工檢查擋得住。

## 5. 公開 repo 的 real 模式（D-040）

- 排程的 real **預設只算不寫**（dry_run）：repo 變數 `WATCH_REAL_ISSUES` 是 `on` 才開 Issue。M2 合併、第一次真實基準（手動 `mode=real`，只寫狀態 Issue、不開監控 Issue）之後，
  C3 回報「打開的話會開哪些 Issue」，C0 看過再打開。手動觸發 `mode=real` 照輸入的 dry_run。
- 只開兩種 Issue：已遭利用（KEV／EUVD）、廠商層級。一般 CVE 候選（核心 CNA 的上千筆、D-034 的 U-Boot 候選）不開。
  一次新增超過 20 個群組 → 全部併成一個彙總 Issue（ATTENTION）。
- 標題與內文寫明「示範專案（公開 BSP）」、加 `demo` 標籤（`match.py --demo`）；release-meta 的 shipped／development 照用。
- 第 14 條通報在公開 repo 只做演練（`art14-drill`）；real 命中不開 art14 Issue（M8）。

## 6. 演練（drill，公開 repo 只做演練）

- concurrency 依 ref 分組（`watch-<ref>`）：分支上的手動演練不會取消 main 的排程。同一個 ref 上同時觸發兩次時，排隊中的那個會被新的取消（GitHub 的規則）；
  排程那一輪如果被取消，下一輪會在報告與健康 Issue 記下來。
- 三輪都給 `--allow-baseline`（drill 的狀態與 real 完全分開）：dry_run 時每一輪都從頭建基準、不寫狀態，只驗證「算得出 plan」。

- `watch.yml` 手動觸發 `mode=drill`：inventory 用 `tests/fixtures/watch/drill/`（合成 Release：合成的 SBOM，元件是公開套件的真實版本），
  KEV 用合成的 KEV 檔（`--kev-overlay`：把指定 CVE 加進 CISA KEV 清單），狀態用 `watch-state-drill`，跟真實狀態完全分開。
- 驗收步驟：(1) 沒有 overlay → 建立基準、0 個 Issue；(2) overlay 加一個 CVE（requests 2.19.0 的 CVE-2018-18074，正式版 bsp 層與開發版各有一份）→ 開 2 個 Issue（每個 Release 一個）；(3) 再跑一次 → 0 個新 Issue；(4) `close-drill`。
