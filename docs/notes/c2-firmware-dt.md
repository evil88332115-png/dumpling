# C2：韌體 SBOM 上傳臨時 DT（M3 的「進 DT」）

狀態：`pipeline/lib/firmware_dt.py`（prep／expected／report）、`pipeline/firmware-dt.sh`（每個樣本 prep → scan → verify → report 的迴圈）已做完並有測試；
**已接進 `.github/workflows/firmware.yml` 的 `firmware-dt` job**，並在本機用真的臨時 DT 跑過一次端到端（結果見最後一節）。**job 還沒在 GitHub Actions 上跑過。**
依據的 C1 版本：`wp1/m1-tools`（bd95a8c，M1 已合併進 main 0e706cb）。

## 流程

    firmware-fetch → firmware-ci.sh（firmware-bios.sh → fw.cdx.json，每個樣本）
        │
        ▼  firmware_dt.py prep --sbom fw.cdx.json --sample firmware.yml --out prep/<slug>
        │     → prep/<slug>/sbom.cdx.json、dt-project.json
        ▼  firmware_dt.py expected --prep prep/<slug>
        │     → expected.json（C1 格式）、firmware-dt-expected.json（我們的）
        ▼  dt-ephemeral.sh up → wait → env <自己的子資料夾>/pilot.env
        ▼  每個樣本：tools/pilot/sca-scan --sbom prep/<slug>/sbom.cdx.json --name <專案名> --version <專案版本> --out dt/<專案名>/scan --no-license
        │     （內含 Grype 比對 C-grype、上傳 DT D-dt-*）
        ▼  每個樣本：dt-verify.py verify prep/<slug>/expected.json dt/<專案名>
        ▼  firmware_dt.py report --prep prep/* --dt-result dt --out report   → firmware-dt.md
        ▼  dt-ephemeral.sh down（always）

report 讀的結果資料夾（`--dt-result`）：

    dt/dt-wait.rc                          選用：dt-ephemeral wait 的結束碼（3＝GAP，所有樣本標 GAP）
    dt/<專案名>/summary.json               dt-verify 的輸出（components、findings_total、checks）
    dt/<專案名>/scan/status.tsv            sca-scan 的 status.tsv
    dt/<專案名>/scan/scan/grype.json       sca-scan --out 底下的 scan/grype.json

## 重點語意

- **漏洞比對以 Grype 為主，DT 只收件與留存。** 臨時 DT 只開 OSV、KEV（NVD 關閉）：`pkg:github/...` 與只有 CPE 的元件在 DT 完全比對不到。
  Grype 對有 CPE 的元件（例如 CSME）會用 NVD 資料比對。沒有 purl 也沒有 CPE 的元件兩邊都查不到，**但 C-grype 仍顯示 OK**（「N matches（比對完成；不代表不存在其他弱點）」），
  所以 0 筆不是「沒有漏洞」；`dumpling:vuln-assessment` 是 NOT_ASSESSED 的元件（Intel ME、微碼、FSP、GOP／VBT；NVIDIA vBIOS）要靠公告對照。報告固定寫明這點。
- 報告狀態：
  - FAIL：上傳階段 FAIL、sca-scan 的 C-grype FAIL、dt-verify 有 FAIL 檢查、輸出檔讀不到。
  - GAP：`wait` 結束碼 3、上傳或 Grype 階段 GAP（含 C-grype NOT_RUN，例如 Grype 資料庫不可用）、或結果不齊全。
  - NOT_RUN：沒有 DT 結果（上傳那三個階段都沒跑）。
  - ATTENTION：上傳與驗證完成，但仍有元件版本 GAP、沒有 purl、或 NOT_ASSESSED（實際樣本幾乎都是這個）。
  - OK：完成且每個元件都有 purl、沒有版本 GAP、沒有 NOT_ASSESSED。**OK 不代表安全**，報告沒有整體 PASS。
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

供應商 SBOM 被 DT 拒收（`expected_dt`）：樣本的 `firmware.yml` 可宣告 `expected_dt: {upload: rejected, reason: …}`（鍵見 `firmware/README.md`）。
report 的判斷：宣告 rejected 且 `D-dt-upload` 是 `http=400` → 狀態照實標 FAIL，說明寫「與 firmware.yml 宣告的 expected_dt 一致」，不讓 job 失敗；
同時 dt-verify 的「弱點分析完成」「元件數」FAIL 是同一個原因，合併成一則說明、不另外計算。**只放行「上傳被拒」這一種**：上傳之前的必要階段（A-source、B-sandbox、B-sandbox-secrets、
B-sbom-provided、C-grype、C-upload-sbom、D-dt-project、F-secret-scan）不是 OK、sca-scan 有別的 FAIL 階段、Grype FAIL、dt-verify 有別項 FAIL，都照常 FAIL 並註明「不放行」。
宣告了卻上傳成功＝MISMATCH（job 失敗，供應商可能修好了）；沒宣告卻被拒收＝一般 FAIL；宣告了但失敗不是 http=400＝一般 FAIL。
`firmware-dt.sh` 對有宣告的樣本，sca-scan 結束碼 1、必要階段不是 OK、dt-verify 失敗三步只記 `FIRMWARE-DT-STEP EXPECTED`，是否放行交給 report。
`firmware-sbom-check` 另會提示「DT 可能拒收（schema 不符）」：license 物件沒有 id 也沒有 name、頂層有 CycloneDX 沒有的欄位（寫死的欄位聯集清單，不是 schema 檔，沒提示不代表合格）。

NVIDIA vBIOS 公告：report 的 vBIOS 樣本行與摘要寫「NVIDIA 公告對照：NOT_ASSESSED（…）」，文字用路徑載入 `tools/pilot/lib/nvidia_bulletins.py` 的 `VBIOS_NOT_ASSESSED`（不複製）；
載入失敗寫 GAP 加原因。workflow 另有一步：對照表用 gpu-firmware 專用的空表 `tools/pilot/lib/nvidia-bulletins-gpu-firmware.json`（C1 M2 提供，不借 Jetson 的表）。
檔案存在 → 抓公告鏡像（`tools/mirror/nvidia-bulletins.sh`）→ `nvidia_bulletins.py candidates --group gpu-firmware`，把那一行印進摘要；表是空的，鏡像裡的 gpu-firmware 公告全部列為待審（ATTENTION 是誠實的結果）。
檔案不存在（M2 合併前）→ 不跑 candidates，印 `C-nvidia-bulletins-db GAP 沒有 gpu-firmware 對照表…`。鏡像或工具失敗一樣只記 GAP，不讓 job 失敗。
本機實測（這一步的 run 區塊原樣執行）：沒有表 → GAP 那一行；從 `origin/wp1/m2` 暫時取出表 → `ATTENTION　有 1 個 GPU 韌體（vBIOS）公告待人工審核（5674）…`（暫時檔已刪、沒有 commit）；鏡像抓不到 → GAP 那一行。

## 依賴 C1 介面的地方（C1 改了要跟著改）

| 項目 | 依賴內容 | 在哪裡用 |
|---|---|---|
| `dt-verify.py verify` 的 expected 格式 | 欄位 `project_name`、`project_version`、`components`、`min_findings_total`、`min_findings_by_purl_type`、`informational_purl_types` | `firmware_dt.expected()` |
| `dt-verify.py` 輸出 | `<out>/summary.json` 的 `components`、`findings_total`、`checks[].name／status` | `sample_result()` |
| `sca-scan` 輸出位置 | `<out>/status.tsv`（欄 stage／status／detail）、`<out>/scan/grype.json`（matches 陣列） | `sample_result()` |
| 階段名稱 | `D-dt-project`、`D-dt-upload`、`D-dt-bom-processing`、`C-grype` | `UPLOAD_STAGES`、`sample_result()` |
| `--name`／`--version` 的過濾 | 名稱換掉 `[A-Za-z0-9._-]` 以外字元；版本 `^[A-Za-z0-9][A-Za-z0-9 ._+~()-]{0,99}$` | `project_name()`、`safe_version()` |
| `dt-ephemeral.sh wait` 結束碼 3 | GAP（資料不完整） | `dt-wait.rc` |
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
| Dasharo NS5x 供應商 SBOM | 10 | 0 | **FAIL（DT 回 http=400）** | OK（36 筆） | FAIL | FAIL |

發現：
- **DT 的元件合併規則不含雜湊**：Protectli 有兩組只有 sha256 不同、其他欄位相同的 FSP-M 映像，DT 合併成一個（16 → 14）。原本 `expected` 的身分含 sha256，預期 16，verify 因此 FAIL；已改成 group／name／version／purl／cpe（含測試）。
  代價：DT 看不到同版本不同映像的第二份，SBOM 原檔仍保留兩份。
- **DT 拒收 3mdeb 的供應商 SBOM（CycloneDX 1.4）**（C2 決定：不改檔、不蓋成 GAP，由樣本宣告 `expected_dt: rejected`，見上方；宣告後 report 仍標 FAIL 但不讓 job 失敗）：`Schema validation failed`——`/components/0/licenses/18/license` 只有 `url`、沒有 `id`／`name`；以及 metadata／properties 有 schema 不允許的欄位（`platform`、`firmware_version`）。
  這是上游檔案不符合 CycloneDX schema，我們不改元件內容，所以這個樣本在 DT 裡是 FAIL（Grype 仍比對了 36 筆，DT 完全沒有資料）。處理方式待 C2 決定（見回報）。
- `firmware-dt.sh` 遇到 `--result` 已有舊結果會標 FAIL（sca-scan 不接受非空輸出資料夾，舊的 status.tsv 也不能混進 report）；第三次本機執行重用資料夾時差點被舊結果騙成「OK」，所以加了這個檢查。
- 0 筆漏洞的 BIOS 樣本 Grype 也是 0 筆：沒有 purl／CPE 的元件兩邊都比對不到，C-grype 仍顯示 OK，所以不是「沒有漏洞」（報告已固定寫明）。

## Actions 實測（run 43266687645，commit bcfef21，workflow_dispatch）

兩個 job 都 success（firmware-fetch、firmware-dt）。firmware-dt 各步驟：下載 64 秒、解析 4 秒、安裝工具 7 秒、`up` 32 秒、`wait` 257 秒（結束碼 0）、`env` 0 秒、
上傳各樣本並驗證 11 分 44 秒、NVIDIA 步驟 0 秒（沒有 gpu-firmware 表 → GAP 那一行）、down 2 秒；整個 job 約 17 分 53 秒。
五個樣本的 report 行與本機相同（Protectli／NUC／OVMF／合成 vBIOS 為 ATTENTION，Dasharo NS5x 為 FAIL 並註明與宣告一致），`firmware-dt.sh` 退出碼 0。
前一個 run（43263224765，commit e4cadcf，還沒有 `expected_dt`）因 Dasharo NS5x 的 FAIL 而失敗，符合預期。

## 仍未驗證

- NVIDIA 公告步驟「有表」那條路只在本機實測（Actions 上目前走「沒有表」→ GAP）。
- `wait` 結束碼 3（GAP）路徑只有單元測試，沒有在真的 DT 上製造。
- `expected_dt` 加入後，含宣告樣本的完整端到端沒有重跑（report／腳本的判斷用假工具的單元測試覆蓋，並用第四次真 DT 的結果資料夾重跑 report 核對過：宣告的樣本 rc=0、狀態 FAIL 加「與宣告一致」）。
