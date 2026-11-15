# FIRMWARE-WATCH：韌體進每日監控（D-063 第 5 點，設計）

> 狀態：**設計稿，還沒寫程式**。C3（WP2）與 C2（韌體）合寫，C2 已審過（2026-11-15）；C2 的部分（§4 的 rematch 入口、§3 的 Release 產出）照 C2 的回覆收錄。
> C0 已決定（2026-11-15）：(1) 走**獨立的韌體示範專案**（不掛在任何產品下）；(2) 第一階段就做「從 Release 上的 `fw-inventory.json` 每天重跑公告比對」。

## 1. 現況與目標

- 現況（WATCH.md §2）：`collect.py` 只收 GitHub Release；韌體 SBOM 只在 `firmware.yml` 的 Actions artifact（`firmware-sbom`，會過期）。
  所以每日的 Grype／KEV／EUVD 不含韌體元件，只有廠商層級提醒，而且掛在板子的 SBOM 上。
- 目標：
  - 韌體 SBOM 有固定的公開位置（Release 附件，長期保存）。
  - 每天跟板子一樣跑 Grype＋KEV／EUVD＋廠商層級。
  - 每天用 repo 當下的對照表與規則表重跑 D-043 的公告比對（Intel 微碼、NVIDIA vBIOS 表、規則表），結果有變化就讓人看到。
- 不做：
  - 每天重新下載映像。會每天打廠商伺服器，ASUS 條款採保守解讀（D-059）。
    映像只在打 tag 建 Release 時，由 firmware.yml 從廠商官方網址下載一次（和 PR CI 一樣），不是每天下載。
  - 把韌體綁到某個產品。BIOS 樣本是互相獨立的公開測試資料；ai-nas-demo 是 Debian 雲端映像，沒有指定主機板，硬綁等於捏造關聯。

## 2. 專案與版本

| 項目 | 值 | 理由 |
|---|---|---|
| 專案 | `firmware-demo`（不在 `projects/` 裡；不是產品，沒有支援期限） | 獨立的韌體示範專案（C0 決定） |
| Release tag | `firmware-demo/<YYYY.MM.DD>`（同一天第二次加 `.2`、`.3`） | **避開 `*/v*`**，不會觸發 release.yml（板子的建置）。查過 main 上所有 workflow：只有 release.yml 用 tag 觸發。符合 collect 的 `PROJECT_RE`／`VERSION_RE` |
| Release 種類 | 正式 Release（不是 prerelease、不是 draft），只由 tag push 產生 | 每一版都留著，是韌體 SBOM 的長期紀錄（PLAN：長期紀錄靠 Release） |
| 監控的單位 | 每個樣本一份 SBOM | 版本只在同一個樣本底下有意義，樣本 slug 才是識別（C2） |
| 監控鍵（UUID） | `dumpling:firmware-demo/<slug>@<firmware_version>#firmware` | **不含 Release 的日期**。同一個樣本同一版，在新的韌體 Release 重發時鍵不變，不會每次都把既有命中當成新的。樣本換版本，或新加樣本，才是新的鍵；它本來就有的 KEV 依 #112 的規則開 Issue |
| `firmware_version` | 照 firmware.yml 原樣，不改寫：`3404`、`v1.2.0`、`0059`、`v0.9.2`、`v1.0.1`、`2024.02-2ubuntu0.10`、`v1.6.0` | 全部符合 `VERSION_RE`（C2 核對） |

- **只監控最新的一個 `firmware-demo` Release**（依 `published_at`）。舊的韌體 Release 留著當紀錄，collect 列在「說明」，不比對。
  理由：每個 Release 都包含全部樣本，監控鍵又不含日期，同時收多個 Release 會出現重複的鍵。
- 進監控的：
  - `firmware/bios/*` 裡 `status: ok` 的樣本（目前 6 份）。
  - 供應商 SBOM（`firmware/sbom/dasharo-novacustom-ns5x-tgl-v1.6.0`）：正規化後給 Grype 比對；採信規則照 #54／#60，`advisory-match` 不採信。
    它走 firmware-sbom-check，不經過 x86_firmware 解析，**沒有 fw-inventory.json，不重跑公告比對**。
    公告比對那欄寫 `NOT_ASSESSED（供應商 SBOM：不重跑；advisory-match 不採信）`。這是設計上就不做，不是 NOT_RUN。
- 不進監控，只在報告列出：
  - 合成 vBIOS。
  - `vbios/nvidia-displayport-fw-updater-1.1`：沒有 vBIOS 元件。
  - `vbios/standalone-nvidia-option-rom`：GAP，沒有 `firmware_version`。

## 3. Release 附件（C2：firmware.yml 打 tag 時上傳）

- `firmware.yml` 加 `push: tags: ['firmware-demo/*']` 觸發，照現在的流程下載、核對、解析，最後一個 job 建 Release。
  - 只有這個 job 有 `contents: write`（D-012）；手動觸發不建 Release。
- 每個 BIOS 樣本上傳兩個附件：`fw-<slug>.cdx.json`（CycloneDX 1.6，就是現在 artifact 裡的 `fw.cdx.json`）與 `fw-inventory-<slug>.json`（schema `sca-center-fw-inventory/1`）。
  - inventory 沒有絕對路徑，檔名都是「壓縮檔!內部檔名」的形式（C2 核對過現有 artifact），可以公開。
- 供應商 SBOM 只上傳 `fw-<slug>.cdx.json`，內容是正規化後的上傳副本，沒有 inventory。
- 另外上傳 `firmware-meta.json`，供 collect 讀，名稱固定：

  ```json
  {"schema": "dumpling-firmware-meta/1", "tag": "firmware-demo/2026.11.20", "commit": "<40 碼>", "built_at": "…Z", "workflow_run": "…",
   "samples": [{"slug": "intel-nuc11-patgl357-0059", "kind": "bios", "firmware_version": "0059",
                "sbom": "fw-intel-nuc11-patgl357-0059.cdx.json", "sbom_sha256": "…",
                "inventory": "fw-inventory-intel-nuc11-patgl357-0059.json", "inventory_sha256": "…",
                "status": "OK|ATTENTION|GAP", "expect": "OK|MISMATCH|MISSING|ERROR|NOT_RUN|NONE"},
               {"slug": "dasharo-novacustom-ns5x-tgl-v1.6.0", "kind": "sbom", "firmware_version": "v1.6.0",
                "sbom": "fw-dasharo-novacustom-ns5x-tgl-v1.6.0.cdx.json", "sbom_sha256": "…", "normalized": true,
                "inventory": null, "inventory_sha256": null, "status": "…", "expect": "NONE"}],
   "not_watched": [{"slug": "standalone-nvidia-option-rom", "why": "GAP：沒有合法可下載的檔案"}],
   "tables": {"fw_advisory_rules": {"sha256": "…", "table_updated": "…"}, "intel_microcode": {"source_commit": "…"},
              "nvidia_vbios": {"sha256": "…", "mirror_commit": "…", "reviewed_until": "…"}}}
  ```

  `slug` 要符合 `^[a-z0-9][a-z0-9.-]{0,62}$`，附件名照 `fw-<slug>…` 規則；不合就該樣本 GAP。
  `expect` 是 firmware-expect.py 實際的輸出；`NONE`＝firmware.yml 沒寫 expected。`tables` 和 rematch.json 用同一個結構。
  firmware-meta.json 的範例檔由 C2 的 PR 提供（`pipeline/watch/tests/data/`），以範例檔為準。
- 不放二進位映像。Release 只有 JSON；上傳前跑 public-check。

## 4. 每天重跑公告比對（C2：`pipeline/firmware-rematch.sh`）

- 入口：`pipeline/firmware-rematch.sh --meta firmware-meta.json --dir <附件目錄> --now <UTC> --out <目錄>`，內部是 `python3 -I tools/cra/x86_firmware.py --rematch`。
  - 依 meta 的 `samples[]` 找 inventory，自己再核對一次 sha256（collect 之後的第二道防線），不收沒列在 meta 裡的檔案。`kind: sbom` 的樣本跳過。
  - **完全離線**：只讀 repo 當下的三張表，不下載、不連網：
    - `tools/cra/data/fw-advisory-rules.json`
    - Intel 微碼發佈資料表
    - `tools/pilot/lib/nvidia-bulletins-gpu-firmware.json`
  - x86_firmware.py 的 `advisory_section(inv)`、`vbios_advisory_section(inv, now=)`、`rules_section(inv)`、`status_of`、`bom()`、`markdown` 都只吃 inventory，不碰映像（C2 確認）。
- 輸入當不可信資料：
  - 先核對 `firmware-meta.json` 列的 sha256（collect 與 rematch 入口各核對一次）；有大小上限。
  - 不是 JSON、schema 不對、必要的鍵缺了或型別不對，一律 GAP（`rematch-input-invalid`），不丟例外。
- 每個樣本的輸出：
  - 一行 `FIRMWARE-REMATCH <OK|ATTENTION|GAP>`。
  - `rematch.json`（schema 由 C2 的 PR 定，範例檔為準）：

    ```
    {"schema": "dumpling-firmware-rematch/1", "slug", "firmware_version", "release_tag", "inventory_sha256",
     "now": "…Z", "status": "OK|ATTENTION|GAP", "reasons": [..],
     "tables": {同 meta 的 tables，每張表另加 "status": "OK|GAP" 與 "stale": bool},
     "results": [{"key", "kind": "rule|intel-microcode|nvidia-vbios", "component", "result", "bulletins": [..], "reason", "review": "preliminary|confirmed|null"}],
     "changed": [{"key", "kind", "before": {"result", "bulletins"}, "after": {"result", "bulletins"}}]}
    ```

    - `key` 是穩定字串，只由 inventory 的內容組成。例如 `rule:<規則 ID>:<元件種類>:<映像 sha256 前 16 碼>`、`ucode:<cpuid>/<platform>:<rev>`、`vbios:<vendor>:<device>:<rom sha256 前 16 碼>`。確切格式以 C2 的範例檔為準。
    - `result` 照現有比對的原值：
      - 規則表：affected／not-affected／NOT_ASSESSED。
      - 微碼：affected-candidate／older-no-sa／up-to-date／NOT_ASSESSED。
      - vBIOS：affected／fixed／NOT_ASSESSED。
  - 重新產生的 `fw.cdx.json`：`dumpling:advisory-*` 換成今天的結果，`dumpling:vuln-assessment` 仍是 NOT_ASSESSED。
- 狀態規則（沿用現有規則，不另訂）：
  - 表讀不到或驗證不過：那一類元件 NOT_ASSESSED，整份 GAP，寫原因。
  - vBIOS 表鏡像超過 90 天：fixed 降成 NOT_ASSESSED，ATTENTION「對照表過期」。
  - 規則表有 affected 建議：ATTENTION、待人審。Intel 微碼有 affected-candidate：照現有規則。
  - **結果和 Release 當時不同：列出差異，至少 ATTENTION。**
  - **沒重跑就是 NOT_RUN**：Release 沒附 inventory、入口沒執行、執行前就失敗，都算。不能拿 Release 當時的結果當今天的。
    **NOT_RUN 由 watch-round 標**，因為 rematch 沒跑或沒有輸出。rematch 自己只輸出 OK、ATTENTION、GAP。
- C2 的測試：
  - 合成 inventory，涵蓋：輸入壞掉、表過期、表壞掉、結果有變化、NOT_RUN。
  - 真樣本：在 Release 當下重跑，結果要和原本逐位元組相同，只排除 CycloneDX 的 `serialNumber` 與 `metadata.timestamp`。rematch.json 和 inventory 裡的比對結果，要和 Release 當時完全相同。

## 5. 每日監控要改的地方（C3）

**collect.py**
- `classify`：`firmware-demo/<版本>` 而且不是 prerelease → 新的種類 `firmware`。不再當成板子的 `release`，所以不要求 release-meta。
- 只收最新的一個 `firmware-demo` Release，其他列在「說明」。
- 讀 `firmware-meta.json`，依它下載每個樣本的 `fw-<slug>.cdx.json` 與 `fw-inventory-<slug>.json`。
  - 核對 sha256 與大小上限，附件名必須在清單裡。
  - 有問題的樣本只有那一份 GAP，其他照常；`firmware-meta.json` 本身壞掉則整個韌體 Release GAP。
- inventory 多一種條目：`{"kind": "firmware", "project": "firmware-demo", "tag", "samples": [{slug, kind, firmware_version, sbom, inventory, sha256…}]}`。供應商 SBOM 的 `inventory` 是 null。
- GitLab 後端（T-05）照同樣的規則讀 Generic Package 的附件。

**watch-round.yml（compute）**
- match 之前多一步「韌體公告重跑」：`pipeline/firmware-rematch.sh --meta <collect 收到的 firmware-meta.json> --dir <附件目錄> --now <這次執行的 UTC> --out <目錄>`，輸出給 match 讀。
- 這一步失敗不擋其他比對：韌體標 NOT_RUN，整輪降級。

**match.py**
- 每個樣本是一個監控單位：`name = firmware-demo`、`version = <slug>@<firmware_version>`、`layer = firmware`；UUID 見 §2。
- **Grype＋KEV／EUVD**：比 Release 上的 `fw-<slug>.cdx.json`，和板子同一套設定。
  - 目前比得到的只有 Dasharo 樣本的 edk2 purl，與 CSME 的 CPE（14.0.47、18.1.18、18.0.10）。
  - 沒有 purl／CPE 的樣本（B550M、NUC11、OVMF）不能寫成 OK：per_sbom 的 Grype 寫 `NOT_ASSESSED（可比對元件 0：沒有 purl／CPE）`，報告寫「Grype 空的不代表沒有漏洞，以廠商公告為準」。
  - 有可比對元件時照常 OK／GAP，並附「NVD 的 CSME 資料不完整」。
- 核心對應、核心 CNA：**沒有這一項**（韌體 SBOM 沒有 Linux 核心元件），報告的這兩欄寫「沒有這一項」。
- **公告重跑的結果**（`rematch.json`）：
  - 每份 SBOM 多一欄「公告比對」，值是 OK／ATTENTION／GAP／NOT_RUN，原文照錄。供應商 SBOM 寫 `NOT_ASSESSED（供應商 SBOM：不重跑；advisory-match 不採信）`。報告列出 `changed` 與三張表的識別。
  - **開 Issue 的條件**（內文一律寫明：是建議、待負責單位確認、比對依據與表的識別）：
    - **規則表**：結果是 `affected`，而且這則公告在這個樣本還沒開過 Issue → 開「[韌體公告] <公告> 可能影響 <樣本> <版本>（<元件>）」。一則公告一個 Issue。
      - 群組鍵：`issue_key(mode, "fwadv", <slug>@<firmware_version>, <rematch 的 key>)`。
      - 結果從 affected 變回 not-affected，或變成 NOT_ASSESSED：在原 Issue 留言，不自動關閉。
    - **Intel 微碼**：`affected-candidate` 是 release 層級的候選。SBOM 的 revision 比某個微碼 release 舊，就把那個 release 列的 INTEL-SA 都列成候選，所以一份微碼常常帶好幾個 SA（C2）。
      - 因此是**一份微碼一個 Issue**：「[韌體公告] Intel 微碼 <cpuid>/<platform> rev <rev> 有 n 個候選公告（<樣本> <版本>）」，內文列出全部候選 SA。
      - 群組鍵：`issue_key(mode, "fwadv-ucode", <slug>@<firmware_version>, <cpuid>/<platform>)`。
      - 候選清單變了，或結果變成 up-to-date／older-no-sa／NOT_ASSESSED：在原 Issue 留言。
    - **NVIDIA vBIOS 表**：結果是 `affected` 時，比照規則表，一則公告一個 Issue。目前沒有進監控的 vBIOS 樣本。
  - 第一輪就會有既有的 affected（C2 列出的）：
    - AMI 兩則公告會出現在 4 份 AMI 樣本，其中有 firmware.yml 的是 B550M、NUC11。
    - B550M 的 0x8012 對到 AMD-SB-7014／7033。
    - V540TU 的 ME 對到 INTEL-SA-01315。

    所以 §6 第 3、4 步「先看 would_open，再決定照開或重建基準」不能省。
  - 對照表過期（vBIOS 超過 90 天）不開公告 Issue。它是資料健康問題，跟其他資料源一樣進「需注意」，連續兩次就開健康 Issue。
  - 狀態只存有開 Issue 的組合，以及最近一次的表識別，控制狀態 Issue 的大小。
- **廠商層級**：`vendor-watch.json` 的 `projects` 加 `firmware-demo`：intel、amd、ami、nvidia、insyde、phoenix。這就是 D-043 第 3 點 Intel、AMD、AMI、NVIDIA 的落點（D-064）。
  - #121 合併後，同一個廠商 × CVE 只開一個 Issue，內文列出受影響的樣本。
  - `VendorWatchConfig` 測試允許 `firmware-demo` 這個不在 `projects/` 的鍵：測試裡另列「非產品專案」清單，只有 `firmware-demo`。
- **支援期限（support.py）**：韌體 Release 不比支援期限（不是產品）。support.py 跳過 `kind: firmware`，不列「有 Release 但 projects/ 裡沒有這個專案」。
- **第 14 條**：韌體的 real 命中與板子一樣，在公開 repo 不開 art14 Issue。

**儀表板（D-062）**
- 版本區加「韌體示範」，每個樣本一列：版本、Grype 狀態（含 NOT_ASSESSED 的原因）、公告比對狀態、表的識別、下載連結。

## 6. 第一次進監控的順序

1. C2 的 rematch 入口＋測試、firmware.yml 打 tag／上傳 Release 合併。C3 的 collect／match／watch-round 合併。兩邊各自可測：C3 用合成的 firmware-meta 與 inventory。
2. 打第一個 `firmware-demo/<日期>` tag（使用者或 C0）→ 確認 Release 附件與 firmware-meta。
3. 每日監控一般 dry_run，回報 would_open：KEV、廠商層級、韌體公告分開列。新加入的韌體 SBOM 本來就有的 KEV 會算新的（#112 規則）。
4. C0 決定照開，還是先重建基準把韌體納入（WATCH.md §5 的做法），之後才打開 `WATCH_REAL_ISSUES`。

## 7. 限制（照實寫進 WATCH.md 與報告）

- 重跑只反映**表的更新**，不重新解析映像。解析器改進要重新跑 firmware.yml、打新的 Release 才會反映。
- inventory 是 Release 當時那一版程式產生的。日後欄位變了、舊 inventory 缺鍵，就是 GAP（要重新打 Release），不猜預設值。
- ME、微碼、AGESA、PSP、AMI 核心、vBIOS 照舊靠規則表或對照表，比不到就 NOT_ASSESSED（資料庫沒有資料，以廠商公告為準）。
- 樣本是公開測試資料，不是出貨產品。Issue 照 D-040 標「示範專案」，並加 `demo` 標籤。

## 8. 分工與工作量

| 誰 | 做什麼 | 檔案 |
|---|---|---|
| C2 | PR 1：rematch 入口＋測試（約 150＋150 行），以及 rematch.json、firmware-meta.json 的 schema 與範例檔 | `pipeline/firmware-rematch.sh`、`tools/cra/x86_firmware.py --rematch`、`pipeline/watch/tests/data/` |
| C2 | PR 2：firmware.yml 的 tag 觸發、Release 上傳、產生 `firmware-meta.json` | `.github/workflows/firmware.yml`、`pipeline/firmware-ci.sh` |
| C3 | collect 的 `firmware` 種類（GitHub＋GitLab） | `pipeline/watch/collect.py` |
| C3 | watch-round 的重跑步驟、match 的韌體單位與公告 Issue、vendor-watch 的 `firmware-demo`、support 跳過 | `pipeline/watch/*`、`.github/workflows/watch-round.yml` |
| C3 | WATCH.md §2 涵蓋表改成實際的涵蓋、儀表板的韌體區 | `docs/WATCH.md`、儀表板 |

介面只有兩個：`firmware-meta.json`（§3）與 `rematch.json`（§4）。兩邊先合併這兩個 schema 的範例檔（`pipeline/watch/tests/data/`），各自照範例寫測試。

## 9. 待決定（給 C0）

1. 監控鍵不含 Release 日期，而且只監控最新的韌體 Release（§2）。同意嗎？
2. 公告 Issue 的開法（§5）：同意嗎？
   - 規則表、vBIOS：affected 時，一則公告一個 Issue。
   - Intel 微碼：一份微碼一個 Issue，內文列出全部候選 SA。
   - 表過期：只進需注意，不開 Issue。
3. 供應商 SBOM（ns5x）進監控（§2）：只跑 Grype，公告比對寫 NOT_ASSESSED。同意嗎？
4. 第一個 `firmware-demo` tag 由誰打：使用者還是 C0。
