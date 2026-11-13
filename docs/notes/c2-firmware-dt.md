# C2：韌體 SBOM 上傳臨時 DT（M3 的「進 DT」）

狀態：`pipeline/lib/firmware_dt.py`（prep／expected／report）、`pipeline/firmware-dt.sh`（每個樣本 prep → scan → verify → report 的迴圈）已做完並有測試；
**已接進 `.github/workflows/firmware.yml` 的 `firmware-dt` job**，並在本機用真的臨時 DT 跑過一次端到端（結果見最後一節）。**job 還沒在 GitHub Actions 上跑過。**
依據的 C1 版本：`wp1/m1-tools`（bd95a8c，M1 已合併進 main 0e706cb）。

## 流程

    firmware-fetch → firmware-ci.sh（firmware-bios.sh → fw.cdx.json，每個樣本）
        │
        ▼  firmware_dt.py prep --sbom fw.cdx.json --sample firmware.yml --out prep/<slug>
        │     → prep/<slug>/sbom.cdx.json、dt-project.json
        │     （kind: sbom 的供應商 SBOM 另做最小格式正規化 → normalize.json；見 c2-supplier-sbom.md）
        ▼  firmware_dt.py expected --prep prep/<slug>
        │     → expected.json（C1 格式）、firmware-dt-expected.json（我們的）
        ▼  dt-ephemeral.sh up → wait → env <自己的子資料夾>/pilot.env
        ▼  每個樣本：tools/pilot/sca-scan --sbom prep/<slug>/sbom.cdx.json --name <專案名> --version <專案版本> --out dt/<專案名>/scan --no-license
        │     （內含 Grype 比對 C-grype、上傳 DT D-dt-*）
        ▼  每個樣本：dt-verify.py verify prep/<slug>/expected.json dt/<專案名>
        ▼  firmware_dt.py report --prep prep/* --dt-result dt --out report   → firmware-dt.md
        ▼  dt-ephemeral.sh down（always）

report 讀的結果資料夾（`--dt-result`）：

    dt/dt-wait.rc                          選用：dt-ephemeral wait 的結束碼（只認 0；3 或其他值＝GAP，所有樣本標 GAP，不會是 OK）
    dt/<專案名>/normalize.json             供應商 SBOM 的正規化紀錄（firmware-dt.sh 從 prep 複製過來；report 不讀它，只讀 prep 的 dt-project.json）
    dt/<專案名>/summary.json               dt-verify 的輸出（components、findings_total、checks）
    dt/<專案名>/scan/status.tsv            sca-scan 的 status.tsv
    dt/<專案名>/scan/scan/grype.json       sca-scan --out 底下的 scan/grype.json

## 重點語意

- **漏洞比對以 Grype 為主，DT 只收件與留存。** 臨時 DT 只開 OSV、KEV（NVD 關閉）：`pkg:github/...` 與只有 CPE 的元件在 DT 完全比對不到。
  Grype 對有 CPE 的元件（例如 CSME）會用 NVD 資料比對。沒有 purl 也沒有 CPE 的元件兩邊都查不到，**但 C-grype 仍顯示 OK**（「N matches（比對完成；不代表不存在其他弱點）」），
  所以 0 筆不是「沒有漏洞」；`dumpling:vuln-assessment` 是 NOT_ASSESSED 的元件（Intel ME、微碼、FSP、GOP／VBT；NVIDIA vBIOS）要靠公告對照。報告固定寫明這點。
- 報告狀態（原則：**資料不完整、有疑點、讀不到，一律不是 OK**；OK 也不代表安全，報告沒有整體 PASS）：
  - FAIL：上傳階段 FAIL、sca-scan **任何**階段 FAIL（不只上傳那三個；`expected_dt` 放行的 `D-dt-upload` 那一列除外）、C-grype FAIL（含 `matches` 不是陣列）、dt-verify 有 FAIL 檢查（同名檢查有多個時任一個 FAIL 就算）、輸出檔讀不到。
  - MISMATCH：樣本宣告 `expected_dt` 卻上傳成功。
  - GAP：`wait` 結束碼不是 0（3＝資料不完整，其他值看不懂）、sca-scan 的必要階段（`REQUIRED_STAGES`，11 個，和 `firmware-dt.sh` 的 `need` 相同）缺任何一列（說明寫「缺少階段 X」；宣告 `expected_dt` 並真的被拒收的樣本只核對上傳之前的階段）、上傳或 Grype 階段 GAP（含 C-grype NOT_RUN，例如 Grype 資料庫不可用）、結果不齊全，或 **dt-verify 的資料不全**——`checks` 不是非空陣列／項目格式不對、
    出現 `OK／FAIL／NOT_RUN` 以外的狀態、有檢查 NOT_RUN、必要檢查（`專案存在`、`弱點分析完成`、`元件數`、`漏洞總數`，名稱取自 C1 的 `dt-verify.py`）缺漏、DT 回報的 `components` 不是 >= 1 的整數。
    理由：驗證沒有完整做完，語意同 `wait` 結束碼 3（資料不完整），不是「有問題」也不是「通過」。GAP 不讓 job 失敗。
  - NOT_RUN：沒有 DT 結果（上傳那三個階段都沒跑）。
  - ATTENTION：上傳與驗證完成，但有任何需要人看的原因（逐項寫在說明裡，見下）。實際樣本都是這個。
  - OK：完成，而且 `attention_reasons()` 沒有任何原因。目前**沒有真樣本能到 OK**（韌體的 `C-sbomgate` 一定是 NOT_ASSESSED，被列為 sca-scan 其他階段不是 OK；`dumpling:vuln-assessment` 也沒有工具會寫 `NONE`）。
- `attention_reasons()` 的項目：
  - **DT 漏洞數與 Grype 比對數**：只有 `type(v) is int and v >= 0` 算讀到（`-3`、null、字串 `-`、bool、浮點數、NaN 都是「讀不到」→ ATTENTION，不當成 0）；> 0 要人審。
  - **`dumpling:vuln-assessment`**：只有**完全等於** `NONE`（已評估、沒有已知漏洞）才放行；沒標、`NOT_ASSESSED`、`not_assessed`、前後有空白、`garbage`、`OK`、非字串，一律要人看。同一元件有多個同名標記時，只要任一個不是 `NONE` 就算。
    **目前沒有任何 dumpling 工具會寫 `NONE`**：`tools/cra/x86_firmware.py` 的 `assessed()` 只寫 `NOT_ASSESSED`（加 `-note` 與 `version-status`）。`NONE` 是預留給「真的做過漏洞評估」的工具；在那之前所有 dumpling 產的 SBOM 都是 ATTENTION。
  - **`dumpling:version-status`**：只認完全相同的 `OK`、`GAP`（`GAP` 列入版本 GAP；其他值，例如 `gap`、` GAP`，列為「不是 OK／GAP」）。**沒有 version 又沒有 `GAP` 標記**的元件另列一條（版本缺漏沒有被記錄）。
  - **供應商 SBOM（`kind: sbom`）自帶的 `dumpling:` 標記不採信**（`vuln-assessment`、`version-status`、`advisory-match` 都一樣；`advisory-match` 不計入「公告比對」那一行）：供應商可以自己塞，一律當作沒標（vuln-assessment 都是「(未標)」、不算版本 GAP），另列「供應商 SBOM 自帶 dumpling: 標記的元件 N 個」。
  - **purl**：先 strip，`^pkg:/*<type>/`（不分大小寫，容許 `pkg://generic/`）才算有 purl；`x`、`generic/x`、`pkg:generic`、空白都算沒有（有填但格式不合的另註明個數）。`PKG:GENERIC/x`、` pkg:generic/x`、`pkg://generic/x` 都算 `pkg:generic`（DT／OSV 沒有 generic 的漏洞資料）。
  - **sca-scan 其他階段**：任何非 OK 的階段（GAP、NOT_ASSESSED、ATTENTION、NOT_RUN、空的或不認得的狀態；例如 `D-dt-data-sources GAP`、`C-sbomgate NOT_ASSESSED`、`C-mirror-freshness NOT_RUN`）都列進一條說明。
    上傳三階段與 C-grype 另有專屬判斷，不重複列。**預期的 NOT_RUN 不列**：`E-*`（`firmware-dt.sh` 固定 `--no-license`，授權與版權整段 NOT_RUN）、`C-kernel-config`、`C-kernel-module-map`（沒給 `--kernel-build`，韌體沒有產品核心的 `.config`）。
    其餘 NOT_RUN（沒檢查鏡像新鮮度、DT 資料源、EUVD…）代表該做的檢查沒做，要列。`scan-status-check.py` 只擋「必要階段」與 FAIL；report 也要求必要階段的每一列都存在（缺列＝GAP），並且列出其他非 OK 階段，所以比它嚴：它回答「必要的有沒有做到」，report 回答「能不能顯示 OK」。
    同一階段在 `status.tsv` 出現多列時留最嚴重的一列（前面的 FAIL 不會被後面的 OK 蓋掉）。
  - **`status.tsv` 有重複列或空名稱列**：各階段的狀態不變（重複的取最嚴重的一列；名稱是空的當成一個不認得的階段「(空的階段名稱)」照常判定），但**只要有這兩種，OK 就降成 ATTENTION**，說明寫「status.tsv 有重複列：階段 X N 列」與「有 N 列的階段名稱是空的」；
    階段名稱只有空白（含 NBSP、全形空白）也算空名稱。FAIL／GAP 等其他狀態也加同一則說明，不靜默。理由：`sca-scan` 每個階段只寫一列、每列都有名稱，出現這兩種代表檔案被改過或寫檔有 bug；取最嚴重的一列只保證「不會往好的方向誤判」，不代表檔案可信，所以選保守的 ATTENTION 而不是只記 note。
    `scan-status-check.py` 是 C1 的檔案、這裡不改；它對重複列是後值蓋前值，與 report 取最嚴重不一致（前面是 FAIL、後面是 OK 時它看到 OK）。
  - **輸入 SBOM 有重複鍵**：見下一節。
  - **供應商 SBOM 自帶 `dumpling:` 開頭的 property**（`kind: sbom`）：prep 把它們就地改名成 `supplier:dumpling:…`（值不動、`normalize.json` 逐筆記原名與位置；規則見 `docs/notes/c2-supplier-sbom.md`），
    讓副本裡的 `dumpling:` property 都是我們寫的。report 寫「供應商 SBOM 自帶名稱以 dumpling: 開頭的 property N 個」，狀態至少 ATTENTION（FAIL／GAP 等其他狀態也加同一則說明）；report 讀 `dt-project.json`，不讀 SBOM 裡的 property，偽造的 `dumpling:normalized-*` 不會進報告。
- **`dumpling:advisory-match`**（本工具產的 SBOM）：只認 `affected-candidate`／`older-no-sa`／`up-to-date`／`NOT_ASSESSED` 四個值計數；其他值（含非字串、同一元件多個不同值）記成「不認得的值」「多個值」，不原樣進報告；報告裡的標籤一律經 `_cell`。這一行只是計數，不影響 OK／ATTENTION。
- **結果檔的讀取**：`status.tsv` 以 `QUOTE_NONE` 解析（欄位開頭的 `"` 是普通字元，不會吞掉後面的列）；`grype.json`、`summary.json` 有重複鍵時不採信（後值會蓋掉前值）→ FAIL；`status.tsv`／`summary.json`／`dt-wait.rc` 路徑存在但不是一般檔案（資料夾、斷掉的符號連結、FIFO）→ FAIL，不當成「沒有」；`dt-wait.rc` 只認 `^[0-9]+$`（前後的 ASCII 空白與換行可以有）。
- 元件欄位型別：`group`、`name`、`version`、`purl`、`cpe` 必須是字串（或沒有／null），`properties` 必須是陣列（或沒有／null）；不符合 → prep 失敗（`FIRMWARE-DT-PREP FAIL`，訊息寫明第幾個元件、哪個欄位），這個樣本不上傳。
  理由：不符合 CycloneDX（DT 也會拒收），後面的計數與 DT 元件身分比對都假設是字串；不猜、不轉型。
- **重複鍵**：讀輸入 SBOM 時用 `object_pairs_hook` 偵測同一個物件裡的重複鍵（標準庫預設後值悄悄蓋掉前值，上傳的副本只剩後值）。
  `dt-project.json` 的 `duplicate_keys`（筆數與前 50 筆：物件完成解析的序號 `object_index`、`pointer`（走訪時邊走邊截斷在 300 字元，鍵名再長處理時間也不隨鍵長增加）、鍵、丟掉的前值的標準 JSON sha256）、`summary.duplicate_keys`；`kind: sbom` 另在 `normalize.json` 的 `notes` 逐筆寫出。
  report 與 prep 狀態行都會提到；狀態至少 ATTENTION，**不直接 FAIL**：DT 不會因此拒收，上傳的內容就是我們解析到的內容，差別只是供應商原檔有被丟掉的值，要人知道並判斷。
- **單獨代理字元**（例如 `\ud800`）：prep 先把 `sbom.cdx.json`、`normalize.json`、`dt-project.json` 都序列化並確認能編成 UTF-8，全部成功才寫檔；失敗是 `FIRMWARE-DT-PREP FAIL … 單獨代理字元…`，不留任何檔案（寫檔中途失敗也會清掉已寫的）。
  `main()` 對非預期的例外也印 FAIL 行（不印 traceback），錯誤訊息經 `md_safe` 才輸出。
- sca-scan 的 `C-sbomgate` 對韌體會是 `NOT_ASSESSED`（sbomgate 只把 library／framework 算成套件，firmware 列為忽略類型）。這是預期，不是失敗。
- `expected.json`：`components` 用「不同身分的元件數」（group、name、version、purl、cpe、sha256 都相同的元件 DT 會合併；實際 DT 合併規則尚未用真 DT 確認，若 verify 的元件數不符先看這點）。
  `min_findings_total: 0`、`min_findings_by_purl_type: {}`；`informational_purl_types` 放 SBOM 裡出現的 purl 類型（只記錄，verify 不拿它當條件）。
  理由：韌體元件大多沒有 purl，DT 查不到；重點是專案存在與元件數。`DT_OSV_ECOSYSTEMS` 不用加（韌體 purl 多為 `pkg:github/...`，OSV 的生態系鏡像不涵蓋，加了只會拉長鏡像時間）。
- `firmware-dt-expected.json`（介面無關）：專案名稱、版本、元件數（總數與不同身分數）、`no_data_components`（沒有 purl 的元件；`reason` 區分「只有 CPE」與「兩者都沒有」）、NOT_ASSESSED 數、版本 GAP 數。
  語意：DT 漏洞數為 0 時，這些元件是「DT 沒有資料」，不是「沒有漏洞」。

## 實際 workflow（`firmware.yml` 的 `firmware-dt`）

獨立 job、**不** `needs: firmware-fetch`，理由：這個 job 的上限是 90 分鐘（OSV、KEV 鏡像）；repo 沒有用過 `download-artifact`（沒有可沿用的固定 SHA），
所以 job 自己下載 BIOS／供應商 SBOM 樣本（`firmware-fetch.sh`，同樣核對 sha256）並跑 `firmware-ci.sh` 取得 SBOM（本機實測約 4 秒，網路時間另計）。
觸發：`workflow_dispatch` 與 `pull_request`（`paths` 加 `pipeline/dt-*`、`pipeline/scan-status-check.py`、`tools/pilot/**`、`tools/e2e/**`）。
注意：`firmware/**` 的 PR 也會觸發這個 job（整個 workflow 共用 `paths`）；DT 鏡像本機約 6 分鐘，Actions 上可能更久。權限 `contents: read`，actions 用固定 SHA。

步驟：checkout → 路徑（`PILOT_ENV` 在自己的子資料夾）→ 下載（bios＋sbom 樣本）→ `firmware-ci.sh` → `install-tools.sh --sbom-only`（Syft／Grype 放 `/usr/local/bin`）→
`dt-ephemeral.sh up` → `wait`（結束碼寫進 `dt-wait.rc`；0、3 繼續，其他非 0 失敗）→ `env` → `firmware-dt.sh`（BIOS 樣本、供應商 SBOM、`--synthetic-vbios`）→
NVIDIA 公告步驟 → 小型 artifact（不含 pilot.env）→ `down`（`if: always()`）。摘要寫進 `$GITHUB_STEP_SUMMARY`。

必要階段（`scan-status-check.py`）：用 C1 預設的 11 個（A-source、B-sandbox、B-sandbox-secrets、B-sbom-provided、C-grype、C-upload-sbom、D-dt-project、D-dt-upload、
D-dt-bom-processing、D-dt-vuln-analysis、F-secret-scan），**一個都沒拿掉**，在 `firmware-dt.sh` 明列。韌體的 `C-sbomgate` 是 NOT_ASSESSED（sbomgate 只把 library／framework 當套件），
不在必要清單內，也不能要求。本機實測四個上傳成功的樣本，11 個必要階段全部 OK。

供應商 SBOM 被 DT 拒收（`expected_dt`）：**目前沒有樣本使用**——Dasharo NS5x 的 SBOM 原檔不符 CycloneDX 1.4 schema，改在 prep 做最小格式正規化後上傳（正規化規則與紀錄見 `docs/notes/c2-supplier-sbom.md`），
它的 `firmware.yml` 不宣告 `expected_dt`。機制保留給「正規化也修不了」的供應商 SBOM（不認得的違規類型）。機制如下：樣本的 `firmware.yml` 可宣告 `expected_dt: {upload: rejected, reason: …}`（鍵見 `firmware/README.md`）。
report 的判斷：宣告 rejected 且 `D-dt-upload` 是 DT 的「BOM 不符 schema」回應（`BOM_INVALID_RE`：說明開頭必須是 `http=400 {"status":400,"title":"The uploaded BOM is invalid","detail":"Schema validation failed"`，DT 5.2.0 實測）→ 狀態照實標 FAIL，說明寫「與 firmware.yml 宣告的 expected_dt 一致」，不讓 job 失敗；
同時 dt-verify 的「弱點分析完成」「元件數」FAIL 是同一個原因，合併成一則說明、不另外計算。**只放行「上傳被拒」這一種**：上傳之前的必要階段（A-source、B-sandbox、B-sandbox-secrets、
B-sbom-provided、C-grype、C-upload-sbom、D-dt-project、F-secret-scan）不是 OK、sca-scan 有別的 FAIL 階段、Grype FAIL、dt-verify 有別項 FAIL，都照常 FAIL 並註明「不放行」。
宣告了卻上傳成功＝MISMATCH（job 失敗，供應商可能修好了）；沒宣告卻被拒收＝一般 FAIL；宣告了但失敗不是這種拒收＝一般 FAIL，**其他 400 也是**（例如 `projectName must not be blank`，那是 dumpling 自己的參數錯誤；PR #14 驗證時發現只看 http=400 會被放行，已改成比對回應開頭）。宣告了卻沒有上傳結果（NOT_RUN／GAP，例如沒有 PILOT_ENV）＝狀態照實，但 report 以 1 結束，與沒宣告的樣本一致。DT 改了訊息時會比對不到，被拒收的樣本變成一般 FAIL（安全的方向），屆時依新回應更新 `BOM_INVALID_RE`。
`firmware-dt.sh` 對有宣告的樣本，sca-scan 結束碼 1、必要階段不是 OK、dt-verify 失敗三步只記 `FIRMWARE-DT-STEP EXPECTED`，是否放行交給 report。
`firmware-sbom-check` 另會提示「DT 可能拒收（schema 不符）」：license 物件沒有 id 也沒有 name、頂層有 CycloneDX 沒有的欄位（寫死的欄位聯集清單，不是 schema 檔，沒提示不代表合格）。

正規化與 report：`dt-project.json` 的 `normalize`（`applied`、`changes`、`unnormalized`）有值時，report 的該樣本說明加「已正規化 N 處（見 normalize.json；上傳的是正規化副本，原檔不變）」，
無法正規化的另加「另有 M 處已知違規無法正規化」。正規化只影響上傳的副本：元件數與 `expected.json` 不變（正規化不增減元件）。

NVIDIA vBIOS 公告：report 的 vBIOS 樣本行與摘要寫「NVIDIA 公告對照：NOT_ASSESSED（…）」，文字用路徑載入 `tools/pilot/lib/nvidia_bulletins.py` 的 `VBIOS_NOT_ASSESSED`（不複製）；
載入失敗寫 GAP 加原因。workflow 另有一步：對照表用 gpu-firmware 專用的空表 `tools/pilot/lib/nvidia-bulletins-gpu-firmware.json`（C1 M2 提供，不借 Jetson 的表）。
檔案存在 → 抓公告鏡像（`tools/mirror/nvidia-bulletins.sh`）→ `nvidia_bulletins.py candidates --group gpu-firmware`，把那一行印進摘要；表是空的，鏡像裡的 gpu-firmware 公告全部列為待審（ATTENTION 是誠實的結果）。
檔案不存在（M2 合併前）→ 不跑 candidates，印 `C-nvidia-bulletins-db GAP 沒有 gpu-firmware 對照表…`。鏡像或工具失敗一樣只記 GAP，不讓 job 失敗。
本機實測（這一步的 run 區塊原樣執行）：沒有表 → GAP 那一行；從 `origin/wp1/m2` 暫時取出表 → `ATTENTION　有 1 個 GPU 韌體（vBIOS）公告待人工審核（5674）…`（暫時檔已刪、沒有 commit）；鏡像抓不到 → GAP 那一行。

## 依賴 C1 介面的地方（C1 改了要跟著改）

| 項目 | 依賴內容 | 在哪裡用 |
|---|---|---|
| `dt-verify.py verify` 的 expected 格式 | 欄位 `project_name`、`project_version`、`components`、`min_findings_total`、`min_findings_by_purl_type`、`informational_purl_types` | `firmware_dt.expected()` |
| `dt-verify.py` 輸出 | `<out>/summary.json` 的 `components`、`findings_total`、`checks[].name／status`；檢查名 `專案存在`、`弱點分析完成`、`元件數`、`漏洞總數`（必要，`REQUIRED_VERIFY_CHECKS`）、`依生態系的漏洞數`；狀態只有 `OK／FAIL／NOT_RUN` | `sample_result()` |
| `sca-scan` 輸出位置 | `<out>/status.tsv`（欄 stage／status／detail；狀態 OK／ATTENTION／GAP／NOT_ASSESSED／FAIL／NOT_RUN）、`<out>/scan/grype.json`（matches 陣列） | `sample_result()` |
| 階段名稱 | `D-dt-project`、`D-dt-upload`、`D-dt-bom-processing`、`C-grype`；預期 NOT_RUN 的 `E-*`、`C-kernel-config`、`C-kernel-module-map` | `UPLOAD_STAGES`、`EXPECTED_NOT_RUN_*`、`sample_result()` |
| `--name`／`--version` 的過濾 | 名稱換掉 `[A-Za-z0-9._-]` 以外字元；版本 `^[A-Za-z0-9][A-Za-z0-9 ._+~()-]{0,99}$` | `project_name()`、`safe_version()` |
| `dt-ephemeral.sh wait` 結束碼 | 0＝完成；3＝GAP（資料不完整）；其他值一律 GAP（看不懂不當成完成） | `dt-wait.rc` |
| 專案查詢 | dt-verify 用 `name`＋`version` 查，所以 expected 的名稱版本必須和 sca-scan 傳的完全相同 | `dt-project.json` |

## 本機端到端結果（2026-11-12，DT 5.2.0、Syft 1.55.0／Grype 0.121.0）

環境：Docker 臨時 DT（OSV: PyPI,npm,Ubuntu；KEV；NVD 關閉）。Syft／Grype 用主機上同版本的 `/opt/sca-tools`（沒有 sudo，沒跑 `install-tools.sh`）。
`RUNNER_TEMP` 要放在家目錄底下：sca-scan 的沙箱探測會在 `RUNNER_TEMP` 放假憑證檔並要求它被遮蔽，放在其他位置會得到 `B-sandbox=FAIL`（本機環境問題，runner 上的 `_temp` 在家目錄內）。
時間：`up` 約 20 秒、`wait` 363～378 秒（四次）、四個樣本的 sca-scan＋verify 合計約 670 秒（含 Grype 資料庫更新與比對；整個端到端約 1068 秒）。

| 樣本 | 元件（不同身分） | DT 元件數 | 上傳 | Grype | verify | report |
|---|---|---|---|---|---|---|
| Protectli VP46xx（BIOS） | 16（14） | 14 | OK | OK（0） | 通過（修正身分後；修正前預期 16 實際 14 → FAIL） | ATTENTION |
| NUC11 PATGL357（BIOS，合併 wp3/m3 後的新 SBOM） | 8（6） | 6 | OK | OK（0） | 通過（合併前 3 個元件、3＝3） | ATTENTION |
| Ubuntu OVMF（BIOS） | 1 | 1 | OK | OK（0） | 通過 | ATTENTION |
| 合成 NVIDIA vBIOS | 1 | 1 | OK | OK（0） | 通過 | ATTENTION（NVIDIA 公告對照：NOT_ASSESSED） |
| Dasharo NS5x 供應商 SBOM（原檔直接上傳，沒有正規化；對照用，正規化副本見後一節） | 10 | 0 | **FAIL（DT 回 http=400）** | OK（36 筆） | FAIL | FAIL |

發現：
- **DT 的元件合併規則不含雜湊**：Protectli 有兩組只有 sha256 不同、其他欄位相同的 FSP-M 映像，DT 合併成一個（16 → 14）。原本 `expected` 的身分含 sha256，預期 16，verify 因此 FAIL；已改成 group／name／version／purl／cpe（含測試）。
  代價：DT 看不到同版本不同映像的第二份，SBOM 原檔仍保留兩份。
- **DT 拒收 3mdeb 的供應商 SBOM（CycloneDX 1.4）**（C2 決定：不改檔、不蓋成 GAP，由樣本宣告 `expected_dt: rejected`，見上方；宣告後 report 仍標 FAIL 但不讓 job 失敗）：`Schema validation failed`——`/components/0/licenses/18/license` 只有 `url`、沒有 `id`／`name`；以及 metadata／properties 有 schema 不允許的欄位（`platform`、`firmware_version`）。
  這是上游檔案不符合 CycloneDX schema；prep 對 `kind: sbom` 的樣本上傳的是最小格式正規化的副本（見 `docs/notes/c2-supplier-sbom.md`），所以現行流程上傳成功；上面這一列是原檔直接上傳的對照。
- `firmware-dt.sh` 遇到 `--result` 已有舊結果會標 FAIL（sca-scan 不接受非空輸出資料夾，舊的 status.tsv 也不能混進 report）；第三次本機執行重用資料夾時差點被舊結果騙成「OK」，所以加了這個檢查。
- 0 筆漏洞的 BIOS 樣本 Grype 也是 0 筆：沒有 purl／CPE 的元件兩邊都比對不到，C-grype 仍顯示 OK，所以不是「沒有漏洞」（報告已固定寫明）。

## 供應商 SBOM 正規化副本的本機端到端（2026-11-12，DT 5.2.0、Grype 0.121.0）

`firmware-fetch` → `firmware-ci.sh`（只跑 Ubuntu OVMF）→ `dt-ephemeral.sh up／wait／env` → `firmware-dt.sh`（OVMF＋Dasharo NS5x 供應商 SBOM）→ `down`（trap）。`wait` 363 秒，兩個樣本的 sca-scan＋verify 共 29 秒（Grype 資料庫是快取的）。

| 樣本 | 元件 | DT 元件數 | 上傳 | Grype | verify | report |
|---|---|---|---|---|---|---|
| Ubuntu OVMF（BIOS） | 1 | 1 | OK | OK（0） | 通過 | ATTENTION |
| Dasharo NS5x 供應商 SBOM（正規化副本） | 10 | **10** | **OK（DT 收下）** | OK（36 筆） | 通過（5 項檢查全 OK；11 個必要階段全 OK） | **ATTENTION**（原因見下） |

- 正規化 3 處：`/platform`、`/firmware_version`、`/components/0/licenses/18`；`normalize.json` 在 `<結果>/firmware-sbom-…/normalize.json`。原檔 SHA-256 不變（`5c42344d…6a44ae`）。
- 樣本沒有 `expected_dt`；原檔直接上傳的結果見上一節的表（http=400、FAIL）。
- report 狀態依現行規則是 ATTENTION，不是 OK。同一份正規化副本（元件 10、purl 10、cpe 5）配全部 OK、Grype 0 筆的假 DT 結果，report 實際列出的原因是：
  沒有 `dumpling:vuln-assessment` 標記的元件 10 個（供應商自帶的 `dumpling:` 標記也不採信）、purl 是 `pkg:generic` 的元件 10 個（DT 的 OSV 沒有 generic 的漏洞資料）、
  沒有 version 也沒有 version-status GAP 標記的元件 1 個，另寫「已正規化 3 處」。真實那次另有 Grype 36 筆比對結果（需要人審）、sca-scan 其他階段不是 OK（例如 `C-sbomgate` NOT_ASSESSED）。
  DT 漏洞數 0 不代表沒有漏洞，漏洞比對的依據是 Grype（36 筆）。

## Actions 實測（run 43266687645，commit bcfef21，workflow_dispatch；Dasharo NS5x 以原檔上傳並宣告 `expected_dt`，沒有正規化）

兩個 job 都 success（firmware-fetch、firmware-dt）。firmware-dt 各步驟：下載 64 秒、解析 4 秒、安裝工具 7 秒、`up` 32 秒、`wait` 257 秒（結束碼 0）、`env` 0 秒、
上傳各樣本並驗證 11 分 44 秒、NVIDIA 步驟 0 秒（沒有 gpu-firmware 表 → GAP 那一行）、down 2 秒；整個 job 約 17 分 53 秒。
五個樣本的 report 行與本機相同（Protectli／NUC／OVMF／合成 vBIOS 為 ATTENTION，Dasharo NS5x 為 FAIL 並註明與宣告一致），`firmware-dt.sh` 退出碼 0。

## 限制

- 宣告 `expected_dt: rejected` 的樣本同時有 status.tsv 重複列或空名稱列時，「與宣告一致」（`accepted`）的判斷不看這兩種；說明裡仍會列出，狀態是 FAIL。
- 重複列與空名稱列的檢查只涵蓋 report 讀的 `scan/status.tsv`；`scan-status-check.py` 的行為見上。
- report 的 OK 不看 NVIDIA 公告對照（公告步驟獨立於 report）；目前沒有工具會寫 `dumpling:vuln-assessment=NONE`，所以 vbios 樣本實際上不會是 OK。
- `summary.json` 內部的一致性不檢查（`components`、`findings_total` 與 `checks[]` 互相矛盾時不擋）：這些值由 `dt-verify.py` 自己寫，report 只檢查型別、必要檢查是否存在與狀態。

## 仍未驗證

- 正規化後的 Actions 實測（上面的本機端到端不是 Actions）；workflow「小型結果」步驟的 `cp` 迴圈用本機結果資料夾原樣跑過，normalize.json 有進 `out/<專案名>/`，但沒有在 Actions 上跑過。
- NVIDIA 公告步驟「有表」那條路只在本機實測（Actions 上目前走「沒有表」→ GAP）。
- `wait` 結束碼 3（GAP）路徑只有單元測試，沒有在真的 DT 上製造。
- `expected_dt` 加入後，含宣告樣本的完整端到端沒有重跑（report／腳本的判斷用假工具的單元測試覆蓋，並用第四次真 DT 的結果資料夾重跑 report 核對過：宣告的樣本 rc=0、狀態 FAIL 加「與宣告一致」）。
