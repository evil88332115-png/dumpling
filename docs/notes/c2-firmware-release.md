# C2：示範用韌體 Release（`firmware.yml` 的 tag 觸發與附件）

只用公開樣本與公開資料。Release 是示範用的公開韌體樣本分析結果，不是產品；附件只有 JSON，沒有任何韌體映像或其他二進位檔。
比對結果是候選與建議，漏洞判定仍是 `NOT_ASSESSED`；`NOT_ASSESSED` 是資料庫沒有資料，以廠商公告為準。
設計見 `docs/FIRMWARE-WATCH.md` 的第 2、3 節（專案、tag、Release 附件、`firmware-meta.json`）；第 5 節是每日監控讀這些附件的一方（`pipeline/watch/collect.py`）。
決定：D-012（Actions 權限、第三方 action 固定 commit SHA）、FIRMWARE-WATCH 第 9 節（C0 的決定）。

## tag

| 項目 | 規則 |
|---|---|
| 格式 | `firmware-demo/<YYYY.MM.DD>`；同一天第二次起加 `.2`、`.3`…`.99`（`.1` 不用） |
| 驗證 | 正規式 fullmatch `firmware-demo/[0-9]{4}\.[0-9]{2}\.[0-9]{2}(\.[2-9]\|\.[1-9][0-9])?`，日期要是有效日期（`2026.02.30`、`2026.13.01`、`0000.00.00` 都不合）。不合就讓 job 失敗，不建 Release |
| 觸發 | `on.push.tags: ['firmware-demo/*']`。`*` 不跨 `/`，所以只有 `firmware-demo/<一段>` 會觸發 |
| 不觸發板子的建置 | `release.yml` 的 tag 是 `*/v*`（第二段以 `v` 開頭）；`firmware-demo/` 後面是數字，不會符合。`tests/test_firmware_meta.py` 用同樣的 glob 規則核對 |
| 誰可以打 tag | **第一個 tag 由 C2 在 C0 同意後打**（FIRMWARE-WATCH 第 6、9 節：設計與實作的 PR 都合併、每日監控 dry_run 的 would_open 給 C0 看過）。之後由 C0 指定的人，在已合併進 main 的 commit 上打。能建 tag 的人就能觸發 workflow（workflow 檔取自 tag 指到的 commit），所以要限制誰能建 `firmware-demo/*` tag（repo 的 tag 保護或 ruleset，是 repo 設定，不在程式裡） |
| 同一天重發 | 同一個 tag 已經有 Release 就不建（不覆蓋）；要重發用 `.2`。已發布的 Release 是長期紀錄，不改寫 |

測試 tag：PR 與 `workflow_dispatch` 沒有真的 tag，端到端自我檢查用 `firmware-demo/0000.00.00`。
它只在 `firmware_meta.py` 加 `--allow-test-tag` 時被接受；因為日期不是有效日期，真的 tag 不會和它相同，加了旗標也不會放行其他不合規的 tag。
它符合 collect 的 tag 檢查（`check_fw_meta` 只比對 meta 的 tag 與 Release 的 tag 相同；`classify` 會把它分成 `firmware`）與 `firmware-rematch.sh` 的 tag 格式，所以同一套自我檢查在三種觸發下都能跑。

## workflow（`.github/workflows/firmware.yml`）

| job | 權限 | 什麼時候跑 | 做什麼 |
|---|---|---|---|
| `firmware-fetch` | `contents: read` | PR、dispatch、tag | 原有的下載、解析、expected 比對、供應商 SBOM 品質檢查；tag 觸發時第一步先驗 tag 格式 |
| `firmware-dt` | `contents: read` | PR、dispatch、tag | 原有的臨時 Dependency-Track |
| `firmware-release-check` | `contents: read` | PR、dispatch、tag | 產生 `firmware-meta.json` 與附件資料夾，做三項自我檢查，上傳 artifact `firmware-release` |
| `firmware-release` | **`contents: write`** | **只有 tag push**，而且前三個 job 都成功 | 下載 artifact、再核對一次、建 Release |

只有最後一個 job 有 `contents: write`（D-012），而且它不下載樣本、不解析任何下載檔，只上傳前一個 job 產生並檢查過的 JSON。PR 與 `workflow_dispatch` 不會到這個 job（`if` 條件要求 push、tag、`firmware-demo/` 開頭）。

建 Release 的順序：

1. 附件再核對一次：`firmware_meta.py collect-check`（meta、附件檔名、sha256），資料夾裡不能有非 JSON 的檔案。
2. 已經有同 tag 的 Release 就失敗。
3. `gh release create … --draft --verify-tag --latest=false`：先建草稿，附件全部上傳；用 API 核對每個附件的名稱、大小、狀態（`uploaded`）和本機一致。
4. 發布成正式版（`draft=false`、`prerelease=false`）。不是 prerelease、不是 draft；`--latest=false` 只是不讓它成為 repo 的「最新 Release」（板子的 Release 才是）。
5. 發布後用 `gh release download` 下載，再跑一次 `collect-check`，並確認 Release 狀態。這一步失敗時 Release 已經存在：刪掉它，用下一個序號（`.2`）重發。

Release 說明文字（`firmware_meta.py release-notes` 產生）：示範用的公開韌體樣本、不是產品、附件只有 JSON、進每日監控的樣本清單與不進的樣本和原因。

## 附件

| 檔案 | 內容 |
|---|---|
| `fw-<slug>.cdx.json`（每個進監控的樣本） | BIOS 樣本：`firmware-ci.sh` 的 `fw.cdx.json`（CycloneDX 1.6）。供應商 SBOM（`kind: sbom`）：`firmware_dt.py prep` 的正規化上傳副本（原檔不動；正規化的規則見 `docs/notes/c2-supplier-sbom.md`） |
| `fw-inventory-<slug>.json`（BIOS 樣本） | `fw-inventory.json`（schema `sca-center-fw-inventory/1`）。檔名都是「壓縮檔!內部檔名」的形式，沒有絕對路徑。供應商 SBOM 沒有 inventory |
| `firmware-meta.json` | 見下節，名稱固定 |

不放映像或任何二進位檔。要上傳的整個資料夾（加上 Release 說明文字）上傳前跑 `ci/public-check.sh`：資料夾不是 git repo，所以做法同 `pages.yml`：複製到暫存資料夾，`git init`、`git add -A`、`git write-tree`，對 tree 跑 `--rev`。不過就不建 Release。

## `firmware-meta.json`（schema `dumpling-firmware-meta/1`）

產生器：`pipeline/lib/firmware_meta.py build`，輸入是各個 `firmware.yml`（`firmware/*/*/firmware.yml`）、`firmware-ci.sh` 的產出、供應商 SBOM 的 prep 結果與 `firmware-sbom-check.sh` 的狀態行。鍵與順序和範例檔 `pipeline/watch/tests/data/firmware-meta.example.json` 相同（範例檔多一個說明用的 `_note`）。

| 欄位 | 說明 |
|---|---|
| `tag`、`commit`、`built_at`、`workflow_run` | tag（見上）、40 位小寫十六進位 commit、UTC 建置時間、工作流程執行的網址 |
| `samples[]` | 每個進監控的樣本一筆，依 slug 排序 |
| `samples[].slug` | 樣本資料夾名稱；fullmatch `^[a-z0-9][a-z0-9.-]{0,62}$`（也不能是 `summary`，那是 rematch 總表的檔名），不合就失敗，不產生 meta |
| `samples[].kind` | `bios` 或 `sbom` |
| `samples[].firmware_version` | `firmware.yml` 的 `firmware_version`，原樣（YAML 數字要加引號，否則失敗） |
| `samples[].image_sha256` | inventory 裡**只有一個** BIOS 映像時填它的 sha256；其他情況與供應商 SBOM 都是 `null` |
| `samples[].sbom`、`sbom_sha256` | `fw-<slug>.cdx.json` 與它的 sha256 |
| `samples[].inventory`、`inventory_sha256` | BIOS 樣本：`fw-inventory-<slug>.json` 與 sha256；供應商 SBOM：`null` |
| `samples[].normalized` | 只有 `kind: sbom` 有，一律 `true`（附的是正規化後的上傳副本） |
| `samples[].status` | BIOS 樣本：inventory 的 `status`（`OK｜ATTENTION｜GAP`，`firmware-bios.sh` 的狀態行就是它；產生時和 `firmware-ci.sh` 的摘要核對，不一致就失敗）。供應商 SBOM：`firmware-sbom-check.sh` 的狀態（FAIL 的不進 Release） |
| `samples[].expect` | `firmware-expect.py` 的結果：多項時取最差的（`ERROR`＞`MISMATCH`＞`MISSING`＞`NOT_RUN`），全部符合是 `OK`；`firmware.yml` 沒寫 `expected` 是 `NONE`；有 `expected` 卻沒有結果記錄是 `NOT_RUN` |
| `not_watched[]` | 不進每日監控的樣本：`{slug, why}`，`why` 一定是非空字串（見下節） |
| `tables` | 三張表的識別：`fw_advisory_rules`（`sha256`、`table_updated`）、`intel_microcode`（`source_commit`、`source_tag`、`table_sha256`）、`nvidia_vbios`（`sha256`、`mirror_commit`、`reviewed_until`）。從每份 BIOS inventory 的 `rules_advisory`、`advisory`、`vbios_advisory` 讀出；任何一份的區段不是 OK、欄位缺漏、或各樣本的識別不一致，產生器就失敗（同一次建置用的是同一份表，不挑一份） |

## 不進監控的樣本：`firmware.yml` 的 `watch` 欄位

要不要監控由 `firmware.yml` **明確宣告**，產生器不從輸出推測：

```yaml
watch:
  monitored: false
  why: "沒有 vBIOS 元件（內嵌的是 GOP 驅動範本，版本是佔位字串）"
```

- 選用欄位。鍵只有 `monitored`（布林）與 `why`；`monitored: false` 時 `why` 必須是單行、非空、最多 300 字的字串。格式在 `pipeline/lib/firmware_watch.py`；`firmware_fetch.py`、`firmware_plan.py`、`firmware_dt.py` 與產生器都會驗證，打錯字或空的 `why` 在第一個讀到的步驟就失敗。
- 目前宣告不監控的：`vbios/nvidia-displayport-fw-updater-1.1`（沒有 vBIOS 元件）與 `vbios/standalone-nvidia-option-rom`（GAP：沒有合法可下載的檔案；CI 只用合成 option ROM 測流程）。合成 vBIOS 沒有自己的 `firmware.yml`，用的是後者。
- `kind: vbios` 的樣本沒有每日監控的流程：`status: ok` 卻沒有宣告 `watch.monitored: false`，產生器失敗。
- `status` 不是 `ok` 的樣本（沒有檔案可下載）一律列進 `not_watched`，`why` 是「狀態：原因」（`notes` 的第一行；有宣告 `why` 時用宣告的，並補上狀態）；`notes` 沒有可當原因的文字就失敗。
- `status: ok` 的 BIOS 或供應商 SBOM 樣本在輸出裡找不到結果（沒有 inventory、沒有 prep 副本）也失敗，不會悄悄略過。

## 端到端自我檢查（`firmware-release-check`，PR、dispatch、tag 都跑）

1. **產生**：`firmware_meta.py build`。不合規的 slug、`why` 空、三張表不一致、狀態與摘要不一致、缺輸出都在這裡失敗。
2. **collect-check**：用檔案路徑載入 `pipeline/watch/collect.py`（不改它），對剛產生的 meta 跑 `check_fw_meta(meta, tag)` 與每個樣本的 `_fw_sample_fields`，另外確認 collect 的監控鍵可用（版本不是佔位字串）、附件內容通過 collect 的 JSON／CycloneDX 檢查；再逐一核對附件：資料夾裡的檔名等於 meta 列的檔名（不多不少）、sha256 完全一致。任何一項不符就失敗（collect 的檢查比較嚴，meta 只要有一處不合格，整個韌體 Release 就是 GAP）。
3. **rematch**：`pipeline/firmware-rematch.sh --meta … --dir … --now <現在> --out …`，然後 `firmware_meta.py rematch-check`：每個 BIOS 樣本的 `rematch-<slug>.json` 的 `changed` 必須是空的（同一份 inventory、同一份表，重跑結果必須和建置時相同）；狀態必須和 meta 一致；三張表的識別與狀態（OK）必須和 meta 一致；`rematch-summary.json` 的 `meta_status` 是 OK、`rejected` 是空的、沒有缺少或多出的樣本。這也證明 meta 能被每日重跑接受。
4. **public-check**：對要上傳的整個資料夾跑 `ci/public-check.sh`。

本機端到端：`tests/test_firmware_meta.py` 用 repo 內的真樣本（OVMF）走完 build → collect-check → rematch → rematch-check；`DUMPLING_REMATCH_ART` 指到 `firmware-sbom` artifact（每個樣本一個子資料夾）時，6 份真樣本都跑。

## 限制

- tag 觸發的 `firmware-release` 只有在 tag push 時才會跑，PR 上無法實測；降低風險的做法：附件的產生與檢查（`firmware-release-check`）三種觸發都跑，建 Release 的 job 只做上傳；上傳用草稿、核對附件、再發布；發布後下載核對。`gh` 與 GitHub API 的呼叫（建草稿、查附件、發布）只有真的 tag 才會執行，第一個 tag 的 `firmware-release` log 要逐步確認。
- 建 Release 的 job 要等 `firmware-dt` 完成（臨時 DT 最長 90 分鐘），DT 因為外部資料源失敗時不建 Release，重新執行 workflow 或用下一個序號重發。
- `tables` 記的是建置當下 repo 的三張表；每日監控讀 repo 當下的表，表更新後 `changed` 才會有內容，這是預期的行為。
- 狀態是解析與離線比對的結果；每個元件的漏洞比對是 `NOT_ASSESSED`；供應商 SBOM 不跑公告重跑（沒有 inventory）。
- 重跑只反映表的更新，不重新解析映像：解析器改進要重新打 tag。
- 本機的 `--private` 禁用字檢查對 inventory 的十六進位值可能有誤報（`0x…` 值剛好含禁用字串）；CI 沒有那份清單，只跑通用規則。
