# C2：韌體 SBOM 上傳臨時 DT（M3 的「進 DT」）

狀態：`pipeline/lib/firmware_dt.py`（prep／expected／report）已做完並有測試；**尚未接進 `.github/workflows/firmware.yml`**，等 C1 的臨時 DT 工具合併進 main 後才接。
依據的 C1 版本：`origin/wp1/m1-tools-pilot`（45bb4de）。

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

## workflow 草稿（之後加進 firmware.yml，現在不要加）

新的 job `firmware-dt`，`needs: firmware-fetch`（需要 `firmware-out` 的 SBOM，所以 SBOM 解析要先做；或同一個 job 接在解析步驟之後）。權限 `contents: read`。步驟：

1. checkout（固定 SHA，`persist-credentials: false`）；取得 `firmware-out`（artifact 或同 job 的 `$RUNNER_TEMP/firmware-out`）。
2. 安裝工具：`bash tools/e2e/install-tools.sh`（Grype、Syft 等固定版本；工具要放 `/usr/local/bin`，因為沙箱會遮蔽家目錄）。
3. 每個 BIOS／vBIOS 樣本：`firmware_dt.py prep`、`expected`（vBIOS 合成樣本：先用 `synthetic_vbios.py` 產 ROM，再 `firmware-bios.sh`，`--sample` 指向 GAP 的 `firmware.yml`）。
4. `bash pipeline/dt-ephemeral.sh up`；`wait`（`rc=$?`，把 `$rc` 寫進 `$RESULT/dt-wait.rc`；結束碼 3 是 GAP，不中止後面的步驟，報告會標 GAP；其他非 0 才讓 job 失敗）。
5. `bash pipeline/dt-ephemeral.sh env "$RUNNER_TEMP/pilot/pilot.env"`：**pilot.env 放在自己的子資料夾**，不能直接放在 `$RUNNER_TEMP`（沙箱會遮蔽 PILOT_ENV 所在的整個資料夾）；`export PILOT_ENV=...`。
6. 每個樣本：`tools/pilot/sca-scan --sbom prep/<slug>/sbom.cdx.json --name <project_name> --version <project_version> --out "$RESULT/<project_name>/scan" --no-license`（結束碼 0 或 2 都正常），
   接著 `python3 -I pipeline/scan-status-check.py "$RESULT/<project_name>/scan/status.tsv"`（預設必要階段）。
7. 每個樣本：`python3 -I pipeline/dt-verify.py verify prep/<slug>/expected.json "$RESULT/<project_name>"`（FAIL 不要中止其他樣本，最後統一判斷）。
8. `python3 -I pipeline/lib/firmware_dt.py report --prep prep/* --dt-result "$RESULT" --out report`，把 `firmware-dt.md` 附到 `$GITHUB_STEP_SUMMARY`；report 退出碼 1 讓 job 失敗。
9. `dt-ephemeral.sh down`（`if: always()`）；上傳 artifact（`firmware-dt.md`、各樣本 `summary.json`、`status.tsv`、`grype.json`；不放 pilot.env）。
10. `firmware.yml` 的 `paths` 要加 `pipeline/dt-*`、`pipeline/scan-status-check.py`、`tools/pilot/**`（PR 觸發範圍）。DT 鏡像要花幾十分鐘，建議這個 job 只在 `workflow_dispatch` 與里程碑 PR 跑，timeout 90 分鐘（比照 dt-smoke）。

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

## 試接結果（只在暫存，2026-11-12）

- 用 `git archive origin/wp1/m1-tools-pilot` 取出 C1 的 `tools/`、`pipeline/` 到暫存；用合成 ROM 的 SBOM（prep 後）跑
  `PILOT_ENV=<不存在的檔> tools/pilot/sca-scan --sbom … --no-license`（沒有 DT）：
  - 主機有 Grype（`/opt/sca-tools`，A-tools 會說明），A、B、C 階段都跑得動：`A-source OK`、`B-sbom-provided OK（1 components）`、`C-grype-db OK`、
    `C-grype OK（0 matches（比對完成；不代表不存在其他弱點））`、`C-upload-sbom OK（沒有版本未知的元件）`、`F-secret-scan OK`。
  - `C-sbomgate NOT_ASSESSED（SBOM：EMPTY（套件元件 0）… 弱點分析：NOT_ASSESSED）`，如 C1 所說。
  - `D-dt-*` 全是 `NOT_RUN（沒有 <PILOT_ENV>）`，退出碼 2。
  - 把這個輸出放進 report 的 `--dt-result` 結構：Grype 欄讀得到「OK（0 筆）」，上傳 NOT_RUN，狀態 NOT_RUN。
- `dt-verify.py verify`（PILOT_ENV 指向連不上的 DT）讀得懂我們產的 `expected.json`：`專案存在: FAIL（lookup http=錯誤 URLError）`，其餘 NOT_RUN，退出碼 1；格式沒有被拒絕。
- 沒有在本機起 DT，所以 DT 的元件合併規則、`wait` 的實際行為、`verify` 在真 DT 上的結果都還沒驗證。
