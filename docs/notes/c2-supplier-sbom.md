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
| `tests/test_firmware_sbom_check.py`、`tests/test_firmware_fetch.py` | 單元測試（sbomqs 用假執行檔，不連網） |
| `.github/workflows/firmware.yml` | 安裝 sbomqs、跑檢查、摘要表、upload-artifact `firmware-sbom-check` |

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
- 檔名、元件名稱當不可信文字：去控制字元、`|`、反引號並截短後才印。
- 元件缺版本不猜；全部缺版本或沒有元件＝GAP。CycloneDX 遞迴計入巢狀元件；SPDX 以 `packages` 為元件，purl／cpe 取 `externalRefs`。
- `firmware_plan.py`／`firmware-ci.sh` 只處理 `kind: bios`，sbom 樣本不會送進 x86_firmware（測試涵蓋 plan）。

## 還沒做

- 上傳 DT、Grype 漏洞比對（待臨時 DT 工具）。
- sbomqs 的 sigstore 簽章驗證（目前只固定 sha256）。
- 其他 `--profile`（ntia、bsi…）未跑；要不要納入是政策問題。
- 授權：3mdeb 未聲明，只在 CI 讀取、不散布；是否需向 3mdeb 確認仍待決定。
