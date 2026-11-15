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
| 韌體（`firmware-demo/<版本>` Release 上每個樣本的 SBOM 與 inventory；`docs/FIRMWARE-WATCH.md`） | 有（firmware.yml 自己的比對與 DT） | **Grype＋KEV／EUVD**：比 Release 附件 `fw-<slug>.cdx.json`，設定同板子；沒有 purl／CPE 的樣本 Grype 是 `NOT_ASSESSED（可比對元件 0：沒有 purl／CPE）`（不是 OK，Grype 空的不代表沒有漏洞，以廠商公告為準）；有可比對元件時照常比對，NVD 的 CSME 資料不完整。**公告重跑**：每天用 repo 當下的三張表（規則表、Intel 微碼、NVIDIA vBIOS）對 Release 附的 inventory 重跑（`pipeline/firmware-rematch.sh`，離線），結果有變化列在報告。**廠商層級**照舊（`vendor-watch.json`）。核心對應、核心 CNA：沒有這一項（韌體 SBOM 沒有 Linux 核心，不算 GAP、不降級）。**限制**：只監控最新的一個韌體 Release；重跑只反映表的更新，不重新解析映像（解析器改進要重新打 Release）；inventory 缺欄位是 GAP，不猜預設值；樣本是公開測試資料（status development），不是出貨品；供應商 SBOM（kind sbom）沒有 inventory，公告比對寫 `NOT_ASSESSED（沒有 inventory，不重跑公告比對）`；ME、微碼、AGESA、PSP、AMI 核心、vBIOS 靠規則表或對照表，比不到就 NOT_ASSESSED（以廠商公告為準） | 公告重跑沒執行（腳本不存在、失敗、不在總表）→ 該樣本 NOT_RUN、整輪降級；檔案不合格 → GAP；表過期或 GAP → 需注意＋降級 |

## 3. 程式與資料流

```
watch.yml（每天）
  compute（contents: read、issues: read、actions: read：查上一次排程 run 的結果）
    （real）actions/cache 還原上一份核心 CVE 鏡像（跟 pipeline.yml 同一個 key 前綴 kernel-cve-mirror- 與路徑）
    feeds.sh            → $W/feeds/（CISA KEV、EUVD 鏡像、核心 CNA 鏡像、Grype DB；鏡像經過 pipeline/lib/mirrors.sh）
    （real）這次新抓的核心 CVE 鏡像存回 cache（頂替用的舊資料不存）
    collect.py          → $W/inventory.json＋$W/releases/<n>/…（Release 附件）
    issues.py read-state→ $W/state.json＋$W/state-base.json（狀態 Issue 的內容與樂觀鎖資訊）
    （real，collect 收到韌體 Release 才有）firmware-rematch.sh → $W/fw-rematch/（continue-on-error；沒有輸出時韌體公告標 NOT_RUN、整輪降級）
    match.py            → $W/plan.json（要開的 Issue、要留言的 Issue、新的狀態）＋$W/report.md
    （plan.json 以 artifact 交給下一個 job）
  notify（issues: write）
    issues.py apply     ← plan.json（再核對一次標記與樂觀鎖；冪等）
  keepalive（actions: write）
    讀 watch.yml 的 state、記錄、呼叫 enable
  drill-close（issues: write，只在 drill）
    issues.py close-drill：關閉演練 Issue、換成 *-done 標籤
```

### 3.0 `pipeline/watch/feeds.sh`（資料源）

- CISA KEV：官方 feed，檢查是陣列、至少 1000 筆。Grype DB：`grype db update`。
- EUVD、核心 CVE：**經過 `pipeline/lib/mirrors.sh`**（跟 Release 掃描同一份規則，不另寫）：EUVD 最多試 3 次；核心 CVE 只讓 mirror 試 1 次（`WATCH_KCVE_MIRROR_TRIES` 可改），因為 kernel-cve.sh 自己會重試 clone 3 次、每次最多 900 秒，兩層疊起來會超過 compute job 的上限（150 分鐘）；失敗刪掉不完整的資料夾 → feeds.tsv 記 GAP，match.py 看不到資料夾 → EUVD GAP／核心 CNA NOT_RUN。
- 核心 CVE 用 `mirror_kernel_cve`：有 `KCVE_CACHE_DIR`（actions/cache 還原的上一份）時，上游沒變就沿用；git.kernel.org 連不上就用 48 小時內的上一份頂替，鏡像腳本最後一行是 ATTENTION、SOURCE 寫 `fallback=yes`。
- **用了舊資料頂替時**：feeds.tsv 記 ATTENTION、`::warning::`；match.py 讀 `<名>.result`／SOURCE，把「核心 CVE 鏡像（Linux 核心 CNA）用了舊資料頂替：…：這段時間新增的核心 CVE 不在清單裡」列進報告的「需注意」（整輪 ATTENTION），並附在這次每個要開的 Issue 與留言最後。訊息裡的絕對路徑換成 `<路徑>`（runner 的暫存路徑不進公開 Issue）。不擋第一次基準（資料最多 48 小時舊；超過就 FAIL → 核心 CNA NOT_RUN，照降級規則處理）。
- 演練不下載 EUVD 與核心 CVE（`--no-euvd --no-kernel-cve`），也不碰 cache。
- watch-round.yml 的資料源步驟有自己的 `timeout-minutes: 100`＋`continue-on-error`：卡住時這一步失敗、job 繼續比對並留下報告；沒有 `.result` 的鏡像（沒做完）先刪掉，缺的資料源在報告標 GAP／NOT_RUN（CISA KEV 與 EUVD 都沒有就 FAIL），也不存 cache。

### 3.1 `pipeline/watch/collect.py`（4a）

```
python3 -I pipeline/watch/collect.py (--repo <owner/repo> | --from-dir <資料夾>) --out <工作資料夾> [--max-asset-mb 200]
```
- `--repo`：用 GitHub REST API（`GH_TOKEN`／`GITHUB_TOKEN`，只讀）列出 Release。**跳過 draft**。
  - 正式版：tag `<專案>/<版本>`、不是 prerelease → `kind: release`
  - 開發版：tag `dev/<專案>`、prerelease → `kind: dev`
  - 其他 tag → 列進 `skipped`（附原因）；draft 的 tag 列進 `drafts`（最多 50 個）
  - **match.py 怎麼看**：`skipped`（資料格式壞掉、tag 不合規則、tag 重複）每一筆都算 Release 問題 → 降級（ATTENTION、連續兩次開健康 Issue）、擋第一次基準，報告寫出是哪個 tag、為什麼；`drafts`（還沒發布）只列在報告的「說明」，不降級。
    （GitHub 的 `GITHUB_TOKEN` 只有 `contents: read` 時列不到 draft，所以排程的報告通常看不到 draft。）
- `--backend gitlab --gitlab-url <…/api/v4> --project <數字 ID>`（GITLAB-PORT T-05，只有假 API 測試、未對真實 GitLab 驗證）：token 讀環境變數 `GITLAB_TOKEN`（`PRIVATE-TOKEN` 標頭），
  用 `GET /projects/:id/releases` 列 Release。GitLab 沒有 draft、也沒有 prerelease：`upcoming_release: true` 當 draft（列進 `drafts`、不監控）；`prerelease` 一律 false，
  所以 `dev/<專案>` 的滾動 Release 目前會進 `skipped`（開發版 SBOM 在 GitLab 怎麼存、怎麼收是 GITLAB-PORT T-03，這裡沒有先發明）。
  附件只讀 `assets.links[]` 裡「本專案 Generic Package、同一個 API 主機」的檔案（`…/projects/<ID>/packages/generic/<套件>/<版本>/<檔名>`），檔名取自網址、過一樣的規則；
  其他連結不下載、記成該 Release 的 problem；下載不跟隨轉址。
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

- **韌體 Release**（`docs/FIRMWARE-WATCH.md`）：tag `firmware-demo/<版本>`（不是 prerelease）分類成 `firmware`，**不進 `releases`**（不要求 release-meta），放在 inventory 的 `firmware`；只收最新的一個（`published_at`），其他列在 `firmware_older`（第一階段示範的限制）。
  讀 `firmware-meta.json`（schema `dumpling-firmware-meta/1`、tag 要一致；壞掉 → 整個韌體 Release 的 problem、inventory GAP），依它下載每個樣本的 `fw-<slug>.cdx.json` 與（bios）`fw-inventory-<slug>.json`，**每個附件都核對 meta 列的 sha256**；單一樣本的問題只讓那一份 GAP。
  監控鍵的版本部分 `watch_version`：`<slug>@<firmware_version>`；版本讀不到或是佔位字串（空、`xx.xx`、`0.0`、`unknown`、`TO BE COMPLETED`…）→ `<slug>@sha256-<映像雜湊前 16 碼>` 並標 GAP；兩者都沒有 → 不監控、列進 `not_watched`。meta 的 `tables` 只留三張表的字串欄位。match.py 讀 `firmware`（見 3.2 的「韌體」），support.py 跳過韌體（不是產品，沒有支援期限）。

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
  - **給 RD：新 Release 帶進來的既有 KEV 也會開 Issue**。基準只涵蓋「建立基準那一刻」已有的 Release；之後才加入的 Release（新 tag、第一次發布的開發版）裡已經有的 KEV 命中都算新的，就算同一個 CVE 在舊 Release 因為在基準裡而沒有 Issue。所以新版本一發布，可能一次開好幾個 Issue，而且舊版本沒有對應的 Issue——這是規則本來的設計（舊 Release 的既有命中不通知，新 Release 是新的出貨，要有人看過）。2026-11-15 第一次真實基準之後新增 `dev/orin-nano-demo`，dry_run 會開 16 個 dev 的 KEV Issue、正式版 0 個；使用者決定重建基準，把 dev 一起納入（見 §5）。
- 廠商層級的手動清單（`pipeline/watch/vendor-watch.json`，對所有專案生效）：BIOS／vBIOS 韌體的 **Intel、AMD、AMI、NVIDIA**（D-043 第 3 點）
  只要 KEV／EUVD 出現新的條目，就開廠商層級 Issue（沒有元件比對也提醒；已有元件比對的走 KEV Issue）。比對 KEV 的 `vendorProject`，
  經 `exploited_vendor` 的正規化與別名（`American Megatrends`→ami、`Advanced Micro Devices`→amd、`NVIDIA Corporation`→nvidia）。
  拼法查核（2026-11-13）：CISA KEV catalogVersion 2026.11.10（1779 筆）實際有 `Intel`（2 筆）、`AMI`（1 筆，CVE-2024-54085 MegaRAC SPx）；
  **AMD、NVIDIA 在 CISA KEV 與 EUVD 的 KEV dump（1796 筆）都還沒有條目，拼法無法從資料確認**——待辦：第一筆出現時核對 `vendorProject` 的實際拼法，
  不在別名裡就補進 `vendor-watch.json` 的 `aliases`（在那之前，`AMD`／`Advanced Micro Devices`／`NVIDIA`／`NVIDIA Corporation` 已涵蓋）。
  C2 的韌體 SBOM 公告比對會用到這裡的廠商層級結果。
- 廠商層級：只對新的命中開 Issue；再出現與消失**不留言**（廠商層級是較粗的提示，`exploited_vendor` 的再出現本來就不算新的）。
  **一個廠商 × CVE 只開一個 Issue**（D-064 B，C0 決定 2026-11-15）：群組鍵是 `issue_key(mode, "vendor", CVE, 廠商)`，不含專案 UUID；內文的表格列出這次命中的每份 SBOM（專案、版本、分層、狀態、Release、監看來源），標籤取各版本狀態與分層的聯集。之後新的版本也命中（KEV 加入不到 `BASELINE_DAYS`＝7 天的條目，新版本第一次監看時不算基準）→ 在原 Issue 留言、只列新的版本（`open_if_closed`：原 Issue 已關閉就開新的）。狀態格式不變：`vendor_matches` 的鍵仍是 `[專案 UUID, CVE, 廠商]`，每份 SBOM 一筆。
  升級前如果已經有「每份 SBOM 一個」的廠商層級 Issue（舊的群組鍵含專案 UUID），升級後新的命中用新的鍵，會另開一個 Issue，不會對到舊的；舊鍵的群組紀錄在 PRUNE_DAYS 後修剪。合併這個改動時（2026-11-15）還沒有任何廠商層級 Issue，所以不會發生。
- 降級（只在 real；核心 CNA 缺附件、schema 不符、upstream_version 為 null 也算）：Grype NOT_RUN、CISA KEV／EUVD／Grype DB 不能用或過期、L4T 核心對應 GAP／FAIL、核心 CNA NOT_RUN、已遭利用但元件版本未知
  、Release 附件問題（SBOM 下載失敗、release-meta 不符）、已有狀態卻沒有任何可監控的 Release、
  **上一次排程 run 被取消／失敗／逾時或超過 36 小時沒有排程**（compute 用 `actions: read` 查 watch.yml 的排程 run；keepalive 也印出最近 3 次）
  → 連續 2 次就在固定的健康 Issue（標籤 `watch-health`）開／留言，沒恢復時每 7 天提醒一次；連續 2 次正常才留言「恢復」。報告與 Step Summary 每次都列。
- 已有 Issue 的群組的事件（新增元件、再出現）一次超過 `--max-new-issues` 個 → 併成一個彙總 Issue，不逐一開。
- 已知窗口：降級要連續 2 次才開健康 Issue，第一天只在 Step Summary（結束碼 2 視為成功）；排程 dry_run 期間狀態不寫入，連續次數不會累積。
  C0 打開 `WATCH_REAL_ISSUES` 前要知道這一點。
- **韌體**（依據 `docs/FIRMWARE-WATCH.md` §2、§4、§5、§7；C0 決定 2026-11-15）：
  - **監控單位**：inventory `firmware.samples` 裡 `watch_version` 與 SBOM 都有的樣本，每份一個：`dumpling:firmware-demo/<slug>@<版本>#firmware`（名稱 `firmware-demo`、層 `firmware`、status `development`：公開的示範樣本，不是出貨品）。
    樣本的 GAP（`problems`）與 `not_watched` 裡 `source: collect` 的列進 Release 問題（降級、擋第一次基準）；`source: meta`（合成 vBIOS 等）只列在「說明」。
  - **Grype**：和板子同一套。SBOM 沒有任何帶 purl、CPE（含 `syft:cpe23` 屬性）的元件 → 不跑 Grype，per_sbom 的 grype 寫 `NOT_ASSESSED（可比對元件 0：沒有 purl／CPE）`：不是 OK，也不算「Grype 沒跑完」（不降級、不擋第一次基準）。
    核心對應、核心 CNA 寫「沒有這一項」，不算 GAP、不降級。
  - **公告重跑**（`match.py --firmware-rematch <資料夾>`，選填）：讀 `rematch-summary.json` 與 `rematch-<slug>.json`，**當不可信資料**：大小上限、不跟隨連結、schema 不符就是 GAP；
    `slug`、`release_tag`、`inventory_sha256` 要和 inventory 一致，不一致就 GAP；`key` 當不透明字串，只檢查字元集 `A-Za-z0-9._=+-:/#`（1～300 字元）；字串一律經過 md_text／md_code／md_title。
    介面照 C2 的 rematch 入口（`pipeline/firmware-rematch.sh`）：結束碼 0＝全部 OK、2＝有 ATTENTION 或 GAP（輸出照寫），只有這兩種而且有 `rematch-summary.json`（最後才寫）才交給 match；1、64 是失敗，watch-round 這一步失敗、不傳 `--firmware-rematch`（韌體標 NOT_RUN、整輪降級），步驟上限 20 分鐘（C2 的入口整次上限 900 秒、單份 300 秒，超過的那份 GAP）。總表的 `rejected`（rematch 丟掉的 firmware-meta 條目：索引＋原因代碼，不帶輸入字串）不是空的 → GAP、整輪降級（meta 是 firmware.yml 產生的，有 rejected 就是產生端有問題）；原因代碼只收 C2 定的幾種，其他寫「格式不對」。總表 `meta_status: GAP`（讀不了 firmware-meta）→ 全部 bios 樣本 GAP，原因照錄；表讀不到時識別是 null、另有 `gap`（原因）；`changed[].before.result` 是 null＝Release 當時沒有這個元件的結果，只有 `review` 變了也算 changed。每個樣本的 affected 最多 100 筆（狀態 Issue 有大小上限），超過整份 GAP；`reasons` 最多 20 筆。讀入的舊狀態先 sanitize（型別不對的紀錄丟掉，不讓 match 當掉）。
    每份 SBOM 多一欄 `advisory`：OK／ATTENTION／GAP／NOT_RUN（不在總表、沒有輸出的 bios 樣本是 NOT_RUN，不拿 Release 當時的結果頂替）；供應商 SBOM 是 `NOT_ASSESSED（沒有 inventory，不重跑公告比對）`（設計上不重跑，不是 NOT_RUN）。
    NOT_RUN／GAP、表過期或 GAP → 整輪降級；結果和 Release 當時不同（`changed`）→ 需注意。報告的「韌體」一節列 `changed`、三張表的識別、status、stale。
  - **公告 Issue**（標籤 `firmware-advisory`、`development`、`layer-firmware`；`mark_demo` 照舊；超過 `--max-new-issues` 併成彙總 Issue）：
    - 規則表、NVIDIA vBIOS（result `affected`）：**一則公告一個 Issue**（群組鍵 `issue_key(mode, "fwadv", <公告 ID>)`），內文列出受影響的樣本（樣本、版本、元件、key、映像 sha256）。
      用語：`review: preliminary` 寫「建議受影響（初步規則，待人審）」，`confirmed` 寫「建議受影響（規則已確認，待負責單位確認）」，vBIOS 照實寫依據（對照表的列、裝置 ID、vBIOS 版本、表的識別）；不能寫成確定受影響。
    - Intel 微碼（`affected-candidate`）：**一個 rematch key 一個 Issue**（`issue_key(mode, "fwadv-ucode", <key>)`），內文列出全部候選 SA 與樣本；用語「版本比較的候選，待人審」。
    - 之後又有樣本變成 affected → 在原 Issue 留言（`open_if_closed`，只列新的樣本）；樣本變成 not-affected／NOT_ASSESSED／不在結果裡、微碼的候選清單變了 → 留言，**不自動關閉**。
    - 表過期（`stale`）或 GAP：不開公告 Issue，進「需注意」，降級（連續兩次開健康 Issue）；表的識別與 status／stale 在報告、`state.firmware.tables`、狀態 Issue 的摘要行。
    - **基準**：第一次基準那一輪的公告結果記成基準（狀態裡 `baseline: true`），不開 Issue（比照 KEV）；基準要求公告重跑沒有 NOT_RUN／GAP、表沒有過期。基準之後才加入的韌體，它既有的 affected 會開 Issue（上面 #112 的規則）。
  - **同 slug、同版本，`image_sha256` 不同**：不開新鍵；進「需注意」、報告列兩個 sha256；這個監控鍵每個開著的 KEV、廠商層級、公告群組 Issue 各留言一次（列兩個 sha256）。
    狀態記每個鍵最近一次的 `image_sha256` 與 `image_sha256_history`（每次變化追加 `{at, old, new}`）；隔天同一個新 sha256 不再留言；`image_sha256` 是 null 不比。
  - **狀態**：`firmware: {"tables": {表: 識別、status、stale}, "samples": {監控鍵: {image_sha256, image_sha256_history, advisory: {key: {kind, result, bulletins, component, review, baseline}}}}}`；
    只存 affected／affected-candidate 的 key。舊的狀態沒有 `firmware` 也能讀；沒重跑（NOT_RUN／GAP）的樣本沿用上一次的紀錄，不當成「不再受影響」；韌體 Release 沒收到或有 problem 時整份沿用。`prune_state` 不修剪還有 affected 的公告群組。
  - **watch-round.yml**：match 之前多一步「韌體公告重跑」（只在 real；collect 收到韌體 Release、`pipeline/firmware-rematch.sh` 存在且可執行才跑；`continue-on-error`；輸出在 `$RUNNER_TEMP/w/fw-rematch`，另存 artifact `watch-fw-rematch-*`）。腳本不存在或失敗時 match 照跑，不傳 `--firmware-rematch`。
  - 限制見 FIRMWARE-WATCH.md §7：重跑只反映表的更新、不重新解析映像；舊的韌體 Release 不比對（只監控最新的一個）。
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
# GitLab 後端（GITLAB-PORT T-05）：--repo 換成 --backend gitlab --gitlab-url <…/api/v4> --project <數字 ID> [--confidential]；token 讀 GITLAB_TOKEN
```
- 後端：預設 `--backend github`（`--repo` 必填，行為不變）。`--backend gitlab` 走 Issues／Notes／Labels API（欄位對照：內文＝`description`、編號＝`iid`、狀態 `opened`／`closed`、標籤是字串），
  **建出來的 Issue 一律 `confidential: true`（寫死，`--confidential` 只是範本相容旗標、關不掉）**；token 放 `PRIVATE-TOKEN` 標頭，只連 `--gitlab-url` 那台（https，測試才允許本機 http），不跟隨轉址，429 照 `Retry-After`／`RateLimit-Reset` 重試。
  只有假 API 測試、未對真實 GitLab 驗證；清單見 GITLAB-PORT T-05。內文或留言有以 `/` 開頭的行（GitLab quick action 可能被執行）→ 不送、FAIL。
- Token：`GH_TOKEN`／`GITHUB_TOKEN`，只放 HTTP 標頭；不跟隨轉址到別的主機；只連 `api.github.com`（`GITHUB_API_URL` 可改，給 GHES／測試用）。
- 監控 Issue 的內文第一行是標記：`<!-- dumpling-watch key=<64 hex> mode=<real|drill> -->`。
- stateless plan（不寫狀態、不做樂觀鎖）有兩種 `stateless_kind`：`support`（預設；支援期限，標記 `dumpling-support`、標籤 `support-period`，只能 `open`）與 `deadman`（死人開關，標記 `dumpling-deadman`、標籤 `watch-deadman`；除了 `open` 還可以對 deadman Issue `comment`，不重開）。兩種都不算進 `read-state` 的 `watch_keys`。
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
  實際的影響是**留言可能重複，不是重複開 Issue**（`open` 有 Issue 標記，下一輪會跳過；`open_if_closed` 的留言與「新增元件」等事件留言會再送一次）。#28 刻意這樣做：漏掉 KEV 通知比重複留言嚴重（C0 確認，2026-11-15）。
  **韌體另有一道**（C0 裁定，2026-11-15）：韌體的資料是外來的（rematch 結果），不能讓它撐爆狀態而擋到 KEV。match 在寫入韌體這一輪的結果後先估算整份狀態的大小；超過 60000 字元 → **只有韌體停下來**：這一輪的韌體結果不寫進狀態（沿用上一輪的韌體狀態）、不產生公告 Issue 的動作、每份韌體樣本的公告比對標 GAP、整輪降級；`state.firmware.size_stopped_at` 記停止的時間，狀態 Issue 的摘要寫「韌體因狀態大小上限停止（時間）」，健康 Issue 當輪就開或留言（7 天一次）。板子的 KEV 照常處理。大小恢復後停止標記清掉、韌體照常。另外每筆公告結果的公告 ID 最多 20 個、每個樣本的 affected 最多 100 筆，超過就那份樣本 GAP（不截斷）。
- `runs` 只留最近 30 次。
- GitLab 階段：狀態 Issue 一定設成 confidential（寫在 GITLAB-PORT）。

## 4. 防止排程被停用（60 天）

官方文件（2026-11-13 查）只寫「公開 repo 60 天沒有 repository activity，排程 workflow 會自動停用」，**沒有定義什麼算 activity**；
`PUT /repos/{owner}/{repo}/actions/workflows/{id}/enable` 說明是「sets the state of the workflow to active」，沒寫會不會重新計算 60 天；
通知寄給「最後修改 cron 語法的使用者」。做法：keepalive job（只有 `actions: write`）每天先讀 workflow 的 state 並寫進 job 摘要，再呼叫 enable；
`status` 分支上 `docs/STATUS.md` 的 C3 節（D-008，不在 main）記「下次人工檢查日期」，每月人工看一次 `gh workflow view watch.yml`。
workflow 一旦被停用，keepalive 本身也不會跑，只有人工檢查擋得住。

### 4.1 死人開關（`pipeline/watch/deadman.py`，GitLab 用；GITLAB-PORT T-12）

「每日監控沒有結果」本身要有人發現：`deadman.py` 讀狀態 Issue，最後更新時間（state 的 `runs` 最後一筆的 `at`）超過 36 小時（`--max-age-hours`，和儀表板的 `STALE_HOURS` 一致）
就開一個 Issue（標籤 `watch-health`、`watch-deadman`；同一次停擺只開一個，恢復後在原 Issue 留言「已恢復」，不自動關閉）。GitLab 上加 `--schedules` 還會巡檢 pipeline schedules
（`DUMPLING_JOB=watch` 的排程不見、被停用、擁有者不是 active、`next_run_at` 過期超過 2 小時〔獨立的常數，不跟狀態的 36 小時走〕；看不到 variables 算 GAP 也是警告）。
輸出 `result.json`，有警告（或要留恢復／提醒留言）時另寫 stateless 的 `plan.json`（`stateless_kind: deadman`）交給 `issues.py apply`；結束碼 OK 0、ALERT 2、FAIL 1。查舊 Issue／留言失敗時，已確定的警告仍然送出，但結果是 FAIL（1），不是 ALERT。範本在 rc＝2 時還會確認 `result.json` 的 `status` 是 `ALERT`（Python 找不到檔案的結束碼也是 2）。
狀態的 `runs` 不是非空列表（缺少、空的、壞掉）也是警告，不退回 Issue 的 `updated_at`。
**停擺次數 n**：同一種停擺的 key 含「第幾次」（`<base>|<n>`）：同一次停擺持續好幾天只開一個 Issue；恢復（deadman 在原 Issue 留言「已恢復」）、人關閉之後再發生，開新的 Issue（標題加「（第 n 次）」）。
deadman 只認作者可信的 Issue 與留言（GitLab：專案成員且等級 ≥ Developer，或 token 自己；GitHub：OWNER／MEMBER／COLLABORATOR 或 github-actions[bot]）；偽造的同 key Issue 不能吞掉警告，也收不到恢復留言（細節與威脅模型見 GITLAB-PORT T-12）。
同一次停擺持續時，每 7 天在原 Issue 留一則「仍在停擺（自 …）」（可信作者的機器標記加時間判斷，7 天內不重複；已關閉的不提醒），直到 T-08 的寄信做好。已關閉的可信 Issue 在恢復時也會收到「已恢復」留言（不重開）。
**只偵測與開 Issue，email 還沒做（T-08）。**範本現在是 `when: manual`：沒人點就不會跑，死人開關要等驗證完放開 manual 才真的有作用。範本 `gitlab/.gitlab-ci.yml` 的 `watch:deadman` 用獨立的排程（`DUMPLING_JOB=deadman`）、獨立的擁有者與 token（`DEADMAN_GITLAB_TOKEN`）。
**GitHub 端目前沒有 deadman**：公開 repo 靠上面的 keepalive 加每月人工檢查（`docs/STATUS.md` 的「下次人工檢查日期」）；第一階段只做 GitLab 範本，GitHub 後端只用在測試與演練。

## 5. 公開 repo 的 real 模式（D-040）

- 排程的 real **預設只算不寫**（dry_run）：repo 變數 `WATCH_REAL_ISSUES` 是 `on` 才開 Issue。M2 合併、第一次真實基準（手動 `mode=real`，只寫狀態 Issue、不開監控 Issue）之後，
  C3 回報「打開的話會開哪些 Issue」，C0 看過再打開。手動觸發 `mode=real` 照輸入的 dry_run。
- 只開兩種 Issue：已遭利用（KEV／EUVD）、廠商層級。一般 CVE 候選（核心 CNA 的上千筆、D-034 的 U-Boot 候選）不開。
  一次新增超過 20 個群組 → 全部併成一個彙總 Issue：標題 `[KEV][ATTENTION] 彙總：…`、加 `attention` 標籤，內文也寫 ATTENTION（已有 Issue 的群組事件太多時的彙總也一樣）。
- **外部字串不能變成通知或連結**：元件名、purl、KEV 的廠商／產品、release-meta 的 attention、kernel-versions 的說明、鏡像訊息都是外部資料。
  識別字（元件、purl、依據、來源、廠商、Release 的 tag 與網址）放進行內程式碼（`match.md_code`：原樣可複製，裡面的 `@`、連結、圖片都不解讀；反引號用更長的分隔符號）；
  其他文字用 `match.md_text`，**和 C2 的 `pipeline/lib/firmware_mdsafe.py` 的 `md_safe` 是同一套規則**（C0 決定，2026-11-14；細節見該檔檔頭）：去控制與格式字元（含單獨的代理字元、零寬字元、雙向覆寫）、`&` 先換成 `&amp;`（`&commat;`、`&lbrack;` 這類 HTML 實體不會渲染成 `@`、`[`）、跳脫 `\ [ ] ( ) < > ! * _ # ~ | ` $`、提及形式的 `@` 插零寬空白（不會通知 `@types` 這類組織）；**md_safe 之後再補一道 Issue 參照**：`#`／`＃` 後面接數字、`GH-` 接數字時插零寬空白（`\#123` 只在 Markdown 那一層有效，GitHub 在渲染後的文字比對 Issue 參照——2026-11-14 用 `POST /markdown` 實測 `\#1`、`owner/repo\#1`、`GH-1` 都會連結，插零寬空白就不會；連結還會在被參照的 Issue 時間軸留下一筆 cross-reference）、會被 cmark-gfm／markdown-it 自動連結的 email、`scheme://`、`www.` 都斷開；`pkg:generic/zlib@1.2.11` 這類 purl 原樣保留；
  標題用 `match.md_title`（`@`、`#`、`&` 後面插零寬空白；標題照字面顯示，不換成 `&amp;`）。產生 plan 前最後再檢查一次（`unsafe_markdown`）：行內程式碼以外還有沒淨化的 `@提及`、`](` 連結、`![` 圖片或 HTML 實體（`&名稱;`、`&#`；`&amp;` 除外）就 FAIL、不產生 plan。
- 第一次建立基準前，先看那次 dry_run 的報告有沒有 ATTENTION（例如核心 CVE 用了 48 小時內的舊資料頂替）：基準不會擋它，但之後補進的那段時間的命中會被當成新的。
- 標題與內文寫明「示範專案（公開 BSP）」、加 `demo` 標籤（`match.py --demo`）；release-meta 的 shipped／development 照用。
- 第 14 條通報在公開 repo 只做演練（`art14-drill`）；real 命中不開 art14 Issue（M8，見 `docs/ART14.md`）。
- 狀態 Issue（`watch-state`）不是通知：標題與內文格式不變，但公開 repo（`--demo`）建立時也加 `demo` 標籤（C0 決定，2026-11-14；第一次真實基準的 #99 是手動補的）。read-state 靠 `watch-state` 標籤與第一行標記找，多了標籤不影響。
- **重建基準**（例如基準建立後才加入、還沒開 Issue 前就要納入的 Release）：只有在「找不到狀態 Issue、也還沒有任何監控 Issue」時才能重建（§3.2）。做法：在舊的狀態 Issue 留言寫明原因與決定者，移除 `watch-state` 標籤並關閉（**不刪除**，保留紀錄；read-state 只靠標籤找）；再手動 `mode=real`＋`baseline=true`，先 dry_run 看報告、同意後實跑；最後看一輪一般的 dry_run，確認 KEV Issue 是 0 個。已經有監控 Issue 時不能這樣做（會吞掉新的命中，FAIL）。2026-11-15：#99 依此關閉（原因：基準建立後新增 dev Release，使用者決定），改由新的狀態 Issue 接手。

## 6. 演練（drill，公開 repo 只做演練）

- concurrency 依 ref 分組（`watch-<ref>`）：分支上的手動演練不會取消 main 的排程。同一個 ref 上同時觸發兩次時，排隊中的那個會被新的取消（GitHub 的規則）；
  排程那一輪如果被取消，下一輪會在報告與健康 Issue 記下來。
- 三輪都給 `--allow-baseline`（drill 的狀態與 real 完全分開）：dry_run 時每一輪都從頭建基準、不寫狀態，只驗證「算得出 plan」。

- `watch.yml` 手動觸發 `mode=drill`：inventory 用 `tests/fixtures/watch/drill/`（合成 Release：合成的 SBOM，元件是公開套件的真實版本），
  KEV 用合成的 KEV 檔（`--kev-overlay`：把指定 CVE 加進 CISA KEV 清單），狀態用 `watch-state-drill`，跟真實狀態完全分開。
- 驗收步驟：(1) 沒有 overlay → 建立基準、0 個 Issue；(2) overlay 加一個 CVE（requests 2.19.0 的 CVE-2018-18074，正式版 bsp 層與開發版各有一份）→ 開 2 個 Issue（每個 Release 一個）；(3) 再跑一次 → 0 個新 Issue；(4) `close-drill`。

## 7. 支援期限與 EOL（M8 B2，`pipeline/watch/support.py`）

每日監控的 real 那一輪在 compute 多跑一步（`watch-round.yml` 的「支援期限與 EOL（real）」），不連網，只讀 `projects/*/project.yml`、collect 收集到的 Release SBOM 與 `tools/cra/data/support-lifecycle.json`。演練不跑。

- **產品支援期限以 `project.yml` 的 `support_until` 為準**（D-055；`config.json` 的 `support.end_date` 由它產生，`load_project` 比對月份，不一致就 FAIL）。
  - 期限前 180／90／30 天各開一次提醒 Issue。只開當下最近的那一級：第一次跑時如果已經剩 20 天，就不補開 180、90 天那兩次。期限當天還算在支援期內。
  - 過了期限：狀態 EOL，開一次 Issue，報告寫 GAP「支援期已結束」。
  - 還沒填（只有 development 可能）：NOT_ASSESSED，不是 OK。
- **元件的維護期**：每個 Release 把各層 SBOM 合併後，用 `tools/cra/support_check.py` 比對資料表。
  - 比對用的設定是複本：`support.end_date` 由 `support_until` 產生，`support.subscriptions` 照 `config.json`。
  - 元件比產品先停止維護、維護期沒有公開、或需要的訂閱沒有設定：ATTENTION。同一個專案的同一個元件問題只開一個 Issue，列出受影響的 Release；之後的新版本有同樣問題不重開。
  - 元件版本不在資料表：NOT_ASSESSED，只寫進報告。
- **我們自己的 OS**（`os_responsibility: ours`）：把 `os.distro`／`os.release` 當成 operating-system 元件比對。資料表沒有這個版本：ATTENTION，開一次 Issue，不推估日期。
- **資料表的查核日期**超過 `max_age_days`（或在未來）：這些項目併成一個提醒 Issue。
- **不重複開**：每個 Issue 的 key 由專案、門檻或元件、日期組成，同一個 key 已經有 Issue（含已關閉）就不再開。支援期限改了，key 就會變，會重新提醒。
  - plan 是 `stateless`：`issues.py apply` 不碰監控的狀態 Issue，也不做樂觀鎖，而且只能有 `open`。
  - Issue 用自己的標記 `<!-- dumpling-support key=… -->` 和標籤 `support-period`，**不是監控 Issue**：`read-state` 不會把它算進 `watch_keys`，所以不會擋住第一次基準。ATTENTION 類另加 `attention`；公開 repo 另加 `demo`。
  - 寫進 Issue 的 `project.yml` 與資料表的值一律經過 `md_text`、`md_code`、`md_title`，寫入前再跑 publiccheck 與 `unsafe_actions`。
  - 一個專案檢查時出錯，只有那個專案記 FAIL（它的 Issue 這次不送出），其他專案照做。`support_until` 沒加引號（YAML 讀成日期）也照常處理。
- **跟每日監控的關係**：失敗不擋每日監控的 Issue（`continue-on-error`）。
  - FAIL（`project.yml` 不合格、資料表壞掉、PyYAML 不在）由 `support-fail` job 讓這一輪變紅。
  - 放在比對前面，報告一定會留在 summary。比對 FAIL 時 compute 失敗、notify 不跑，支援期限的 Issue 延到下一輪（key 不變，晚一天而已）。
  - notify 裡，每日監控的 apply 失敗（例如樂觀鎖），支援期限的 apply 照樣跑（`!cancelled()`）。
  - **C0 放行（`WATCH_REAL_ISSUES=on`）之前一律只算不寫，手動跑、`dry_run=false` 也一樣**（C0 決定，2026-11-14；D-040 的精神：支援期限的 Issue 和監控 Issue 一起由 C0 放行）。放行之後照 `dry_run`。
- 輸出在 artifact `watch-support-<round>-<attempt>`（`report.md`、`result.json`、`plan.json`），報告也寫進 job summary。
- 資料表只有人工維護的項目。Debian、Raspberry Pi OS、Radxa、OMV 由 C4 補（提案 B2）；在那之前，這些平台的 OS 是 NOT_ASSESSED（SBOM 裡的元件），或 ATTENTION（`ours` 的 OS）。
