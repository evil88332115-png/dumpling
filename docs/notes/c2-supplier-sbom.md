# C2：供應商 BIOS SBOM 匯入的品質檢查（分支 wp3/supplier-sbom）

PLAN B 段「第二條路」的前半：下載公開供應商 SBOM → 基本檢查＋sbomqs 評分。上傳 DT 與漏洞比對要等 C1 的臨時 DT 工具，這次不做。
這份是工作紀錄，不是驗證結論。數字是 2026-11-12 量測。

## 檔案

| 檔案 | 內容 |
|---|---|
| `firmware/sbom/dasharo-novacustom-ns5x-tgl-v1.6.0/firmware.yml` | 新樣本（`kind: sbom`、`role: sbom`）；網址仍可下載，sha256／大小與 README 相同 |
| `pipeline/lib/firmware_fetch.py` | 接受 `kind: sbom`；`role: sbom` 與 `kind: sbom` 互相綁定（其他規則不變） |
| `pipeline/lib/tools.lock`、`pipeline/install-tool.sh` | 固定工具的版本、網址、sha256 只寫在 tools.lock；安裝腳本下載後先核對 sha256 才解開，只取一個成員 |
| `pipeline/firmware-sbom-check.sh`、`pipeline/lib/firmware_sbom_check.py` | 品質檢查 |
| `pipeline/lib/firmware_sbom_normalize.py` | 上傳 DT 前的最小格式正規化（見下一節）；由 `firmware_dt.py prep` 對 `kind: sbom` 呼叫 |
| `tests/test_firmware_sbom_normalize.py`、`tools/cra/tests/test_supplier_sbom_schema.py` | 正規化的單元測試（unittest）；正規化後用 CycloneDX 1.4 官方 schema 驗證（pytest，`tools/cra/tests/data/cyclonedx-1.4/`） |
| `pipeline/lib/firmware_mdsafe.py` | 不可信文字進 markdown／步驟摘要前的共用清理（`md_safe`）；SBOM 檢查、`firmware-ci.sh` 的摘要表、`firmware_dt.py` 的報告都用它 |
| `pipeline/check-tool-version.sh` | 安裝後核對執行檔回報的版本等於 `tools.lock` 的 `<工具>_version`（目前只認得 sbomqs） |
| `tests/test_firmware_sbom_check.py`、`tests/test_firmware_mdsafe.py`、`tests/test_firmware_fetch.py` | 單元測試（sbomqs 用假執行檔，不連網） |
| `.github/workflows/firmware.yml` | 安裝 sbomqs、核對版本、跑檢查、摘要表、upload-artifact `firmware-sbom-check` |

## sbomqs

v2.1.3，2026-10-14 發布，linux amd64 tarball，sha256 `c96f07a6a27314c1c268af141af04f1c1b49e61400d7058f6419ca4f7f3bdd6b`（與 GitHub release 的 digest 一致）。
呼叫 `sbomqs score --json -- <檔>`；環境變數只傳 PATH／HOME／LANG／LC_ALL／TMPDIR（不帶 Interlynk token，也不啟用 `--enable-component-analysis`，所以不連外）。
注意：sbomqs 的 JSON 類別陣列鍵名拼成 `comprehenssive`，程式兩種拼法都收。

## 樣本結果

    FIRMWARE-SBOM  ATTENTION  novacustom_ns5x_tgl_v1.6.0.sbom.json
      CycloneDX 1.4，10 個元件；1 個元件缺版本（iPXE）；5 個缺 cpe（Intel Firmware Support Package、Intel Flash Descriptor、Embedded Controller Firmware、iPXE、vboot）；
      sbomqs v2.1.3 分數 4.3（F，僅供參考）；漏洞比對：NOT_RUN

sbomqs 類別：Identification 9.65、Provenance 2.50、Integrity 0、Completeness 5.40、Licensing 0、Vulnerability 10、Structural 8、Component Quality 0（總分 4.33）。

## 設計選擇

- 狀態只由基本檢查決定，分數不設門檻（政策未定）；輸出沒有整體 PASS／安全字樣。
- sbomqs 失敗或找不到：基本檢查結果照出，說明寫 `sbomqs：NOT_RUN（原因）`，不當成 FAIL（CI 另有安裝步驟，安裝失敗會讓 job 紅）。
- 檔名、元件名稱、版本、規格版本、sbomqs 輸出的文字都當不可信文字，寫進 stdout 狀態行、`sbom-check.md`、`$GITHUB_STEP_SUMMARY` 之前一律經 `firmware_mdsafe.md_safe`：
  1. 用 `unicodedata.category` 把所有 C 類（Cc 含 C1 控制字元、Cf 如 U+202E 與零寬字元、Cs 單獨代理、Co、Cn）與 Zl／Zp（U+2028／U+2029）換成空白，連續空白壓成一個；
  2. 先截短（元件名 80、檔名 120 個字元，超過加「…」），再跳脫，不會切在跳脫序列中間；
  3. Markdown 特殊字元 `\ [ ] ( ) < > ! * _ # ~ | ` & $` 一律加反斜線跳脫（選跳脫、不換全形：純文字檢視時還讀得出原字元；代價是 stdout 與 log 裡的 `_`、`(` 也會有反斜線）；
  4. 裸網址開頭 `scheme://`、`www.` 在 `:`／`.` 前加反斜線，GitHub 才不會自動變成連結。沒處理 email 自動連結（只會變成 mailto 連結）。
  跳脫只做一次：`md_cell` 只處理換行；workflow 摘要表的 awk 用 `\\?\|` 規則，已跳脫的 `\|` 不會被再跳脫成 `\\|`。
  `firmware-ci.sh` 的摘要表儲存格（狀態行、expected 說明）與 `firmware_dt.py` 報告裡的檢查名、階段名、錯誤訊息也走同一個函式。
  沒改：`x86_firmware.py` 的 `fw-inventory.md` 有自己的 `md_esc`（HTML 實體＋反斜線），而且只當 artifact、不進步驟摘要。
- 元件缺版本不猜；全部缺版本或沒有元件＝GAP。CycloneDX 計入巢狀元件（不遞迴，最多 50 層；頂層元件是第 1 層）；SPDX 以 `packages` 為元件，purl／cpe 取 `externalRefs`。
- 超過 50 層的元件不檢查，但不會悄悄略過：說明寫「巢狀過深，第 51 層以下沒有檢查（至少 N 個元件未計入）」，狀態至少 ATTENTION（本來是 GAP 的仍是 GAP，說明同樣有這句）。
- 「缺」的定義（版本、purl、cpe 都一樣）：欄位不是字串，或去頭尾空白（含零寬字元）後不分大小寫等於空字串或下列佔位值之一：
  `NOASSERTION`、`NONE`、`N/A`、`UNKNOWN`、`NULL`、`-`。SPDX 的 `versionInfo: NOASSERTION` 因此算缺版本。名稱含這些字的真值（例如 `v1-none`、`pkg:generic/unknown@1`）不算佔位。
- 大小與記憶體：檔案上限 16 MiB（韌體 SBOM 通常只有幾十 KiB；超過就 FAIL，說明寫上限）。解析前先數位元組裡的 `{` 與 `[`，超過 200 萬個就 FAIL「結構太多」、不解析（40 MiB 的 `[{},{},…]` 解析後曾用掉約 4.7 GB）。數的是文字，字串裡的括號也算，所以是估計；正常 SBOM 差兩個數量級以上。
- 讀檔：`os.open(O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY)` 後對同一個 fd `fstat` 檢查是一般檔案、再讀；符號連結、目錄、FIFO、裝置都拒絕（O_NONBLOCK 讓沒有寫入端的 FIFO 不會卡住）。
- sbomqs 版本：安裝後 `pipeline/check-tool-version.sh sbomqs "$exe"` 比對 `version` 輸出的 `GitVersion` 與 `tools.lock` 的 `sbomqs_version`（完全相等才過），不符就讓 job 紅燈。
- CI 的 SBOM 樣本清單用 `shopt -s nullglob`；沒有 `kind: sbom` 的樣本時印 `FIRMWARE-SBOM<TAB>NOT_RUN` 並以 0 結束（不是 FAIL，也不會把字面的萬用字元當檔名）。
- `firmware_plan.py`／`firmware-ci.sh` 只處理 `kind: bios`，sbom 樣本不會送進 x86_firmware（測試涵蓋 plan）。

## 結束碼

| 工具 | 0 | 1 | 2 | 64 |
|---|---|---|---|---|
| `firmware-sbom-check.sh` | 沒有 FAIL（OK、ATTENTION、GAP 都是 0） | 至少一個 SBOM 是 FAIL，或建不起輸出資料夾 | 不使用 | 用法錯誤（沒給 SBOM、沒給 `--out`、未知參數）；同時印一行 `FIRMWARE-SBOM<TAB>FAIL<TAB>-<TAB>用法錯誤…` |
| `firmware-bios.sh` | OK | FAIL | ATTENTION 或 GAP | 參數錯誤 |
| `check-tool-version.sh` | 版本相符 | 不符、讀不到版本、lock 沒有該工具 | 不使用 | 用法錯誤 |

注意兩個「檢查」腳本不同：SBOM 檢查的 ATTENTION／GAP 是 0（CI 只在 FAIL 時紅燈，狀態看狀態行），`firmware-bios.sh` 的 ATTENTION／GAP 是 2。argparse 預設的用法錯誤是 2，會和後者的 ATTENTION 混淆，所以 `firmware_sbom_check.py` 覆寫成 64（和 `firmware-bios.sh`、`x86_firmware.py`、`install-tool.sh` 一致）。

## 上傳 DT 前的最小格式正規化（`firmware_sbom_normalize.py`）

DT 5.2.0 把這份供應商 SBOM 拒收（http=400，`Schema validation failed`）。用 CycloneDX 1.4 官方 schema 驗證原檔，錯誤剛好兩個：根物件多出 `platform`、`firmware_version`
（1.4 起根物件 `additionalProperties: false`），以及 `components[0].licenses[18].license` 只有 `url`（`license` 物件要有 `id` 或 `name`）。
C0 同意的處理：**只改上傳用的副本、原檔不動；不刪資料、不補猜的值、每一筆留紀錄；只處理這兩種已知違規。**

| 規則 | 條件 | 做法 |
|---|---|---|
| `top-level-extra-field` | 根物件的鍵不在該 specVersion 的 schema `properties` 裡（表：1.4、1.5、1.6，取自 CycloneDX/specification 各 tag 的 `bom-<版本>.schema.json`） | 搬到 `metadata.properties`，名稱 `dumpling:supplier-extra:<原欄位名>`，值＝字串原值；其他型別是標準 JSON 字串（`sort_keys`、分隔符 `,` `:`、`ensure_ascii=False`） |
| `license-without-id-or-name` | `components[]`（含巢狀）的 `licenses[]` 項目恰好只有 `license` 一個鍵、`license` 是物件、**沒有 `id` 鍵也沒有 `name` 鍵** | 從 `licenses` 移除該項，元件 `properties` 加 `dumpling:supplier-license-url`（url 為字串時）。license 物件除了 `url` 還有別的欄位（`text` 等）或 `url` 不是字串：整個 license 物件以 JSON 字串存進 `dumpling:supplier-license-entry`（url 為字串時仍另寫 `-url`）。**不把 url 填成 name** |

不處理（照原樣上傳，DT 拒收就照實 FAIL）：其他任何 schema 違規；`id`／`name` 鍵存在但值不合格（`""`、不是 SPDX id）；項目多一個鍵；`licenses` 不是陣列；
`services`、`metadata.component` 的 licenses；`specVersion` 不是 1.4／1.5／1.6（1.2、1.3 的根物件允許額外欄位；1.7 沒有查證）；`metadata`／`metadata.properties`／元件 `properties` 型別不對（沒有地方放紀錄）。
**已知違規但無法搬移**（值超過上限、欄位名稱不合格、元件 `properties` 不是陣列…）記在 `unnormalized[]`，欄位原樣留著；report 說「另有 N 處已知違規無法正規化」。

上限（`MAX_*`）：單一值 8 KiB（位元組）、搬移的值合計 256 KiB、變更 2000 筆、元件巢狀 100 層、欄位名稱 100 字元（不含控制字元與單獨代理字元）、`unnormalized` 最多列 200 筆。
先完整規劃、通過才套用；規劃中出任何例外都整份不處理，文件不動（測試涵蓋超深巢狀、超大欄位、`licenses`／`properties` 型別錯誤等）。

紀錄 `<prep>/normalize.json`（`kind: sbom` 一律寫，沒有變更時 `applied: false`、`changes: []`）：

    {"schema": "firmware-sbom-normalize/1", "input_sha256": "<原檔位元組的 SHA-256>", "spec_version": "1.4",
     "supported": true, "applied": true,
     "changes": [{"rule": "top-level-extra-field", "from": "/platform", "to": ["/metadata/properties/1"],
                  "property": ["dumpling:supplier-extra:platform"], "value_sha256": "<原值標準 JSON 的 SHA-256>"},
                 {"rule": "license-without-id-or-name", "from": "/components/0/licenses/18", "to": ["/components/0/properties/0"],
                  "property": ["dumpling:supplier-license-url"], "value_sha256": "…"}],
     "unnormalized": [{"rule": "…", "at": "<JSON Pointer>", "reason": "…"}], "notes": []}

`from` 是原檔的 JSON Pointer（索引是原檔的，不是移除後的）；`to` 是副本裡新 property 的位置。副本另在 `metadata.properties` 加
`dumpling:normalized-from-sha256`（原檔 SHA-256，與 `dt-project.json` 的 `input_sbom_sha256` 相同）與 `dumpling:normalized-changes`（筆數，不含這兩個標記本身）。
沒有變更時不加標記、文件不動。`dt-project.json` 的 `normalize` 欄位記 `{file, applied, changes, unnormalized}`；`firmware-dt.sh` 把 normalize.json 複製到 `<結果>/<專案名>/`，workflow 的小型 artifact 會帶走。

此樣本實際結果（2026-11-12）：3 筆——`/platform`、`/firmware_version`、`/components/0/licenses/18`；元件數不變（10）；原檔 SHA-256 不變（`5c42344d…6a44ae`）。
副本用官方 1.4 schema 驗證：0 個錯誤（原檔 2 個）。

驗證：`tools/cra/tests/data/cyclonedx-1.4/`（bom、spdx、jsf，CycloneDX/specification tag `1.4`，來源與 SHA-256 見該目錄 README.md）；測試 `tools/cra/tests/test_supplier_sbom_schema.py`
（`tests/run.d/c2-x86-firmware.sh` 跑）用自組的測資確認：原檔無效、正規化後有效、不認得的違規仍無效、已合格的文件不動；
真的檔案不進 repo，是手動用同一個驗證器驗過（見上方結果）。**pipeline 執行時不驗證 schema**：DT 上傳本身就會驗證，結果由 report 照實呈現；
runner 沒有 jsonschema，也不應讓 pipeline 因此失敗。

取捨與限制：
- 副本和原檔不同，DT 裡的 SBOM 不是供應商發布的原樣；差異全部可由 normalize.json 還原（`dumpling:supplier-extra:*` 與 `dumpling:supplier-license-*` 在副本裡）。
- DT 的授權欄位少了那筆 url-only 的項目；它本來就不是 DT 能辨識的授權（沒有 id 與 name）。
- `firmware-sbom-check` 檢查的是原檔，仍會提示「DT 可能拒收（schema 不符）」；那是對原檔的陳述，不因副本被正規化而改變。
- 供應商修好原檔後，副本不會有變更（`changes: []`）；仍被 DT 拒收（別種違規）就是一般 FAIL。

## 還沒做

- 上傳 DT、Grype 漏洞比對：已由 `firmware-dt`（`docs/notes/c2-firmware-dt.md`）做完；這份檢查本身仍是 `漏洞比對：NOT_RUN`。
- sbomqs 的 sigstore 簽章驗證（目前只固定 sha256）。
- 其他 `--profile`（ntia、bsi…）未跑；要不要納入是政策問題。
- email 自動連結沒有中和（只會變成 mailto 連結）；`firmware_mdsafe` 沒有用真正的 markdown 轉換器驗證，測試是字串層級。
- 授權：3mdeb 未聲明，只在 CI 讀取、不散布；是否需向 3mdeb 確認仍待決定。
