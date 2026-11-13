# C2：真實樣本的 CI 驗收（分支 wp3/firmware-expect）

PLAN「驗證」BIOS 那條：ME 與微碼版本要跟試掃結果一致。這次把它做成 CI 步驟。不是整體通過的結論：只比 `firmware.yml` 的 `expected` 寫了的項目。

## 檔案

| 檔案 | 內容 |
|---|---|
| `pipeline/firmware-expect.py` | `expected` 對 `fw-inventory.json`／`fw.cdx.json` 逐項比對；規則與鍵見 `firmware/README.md` |
| `pipeline/firmware-ci.sh` | CI 用：每個 `kind: bios`、`status: ok` 樣本跑 `firmware-bios.sh`（退出碼 2 不算失敗）與 expect（`--strict`，NOT_RUN 也算失敗），寫摘要表 |
| `pipeline/lib/firmware_plan.py` | 決定每個樣本的輸入檔；`analyze` 指定的 deb 成員用 `dpkg-deb --fsys-tarfile` 搭配 `tar` 只取出該成員（拒絕 `..`、絕對路徑、symlink），不執行 |
| `.github/workflows/firmware.yml` | firmware-fetch job 後面接解析與比對步驟、`upload-artifact`（commit SHA 固定，14 天）、`$GITHUB_STEP_SUMMARY` 表；觸發條件加 `tools/cra/**`、`pipeline/firmware-*.sh`、`pipeline/firmware-expect.py`、`pipeline/lib/firmware_*.py` |
| `tests/test_firmware_expect.py` | 假 inventory／SBOM：OK、MISMATCH、MISSING、NOT_RUN、expected 空、格式錯誤、plan 與 member 檢查 |

退出碼：`firmware-expect.py` 有 MISMATCH 或 MISSING 為 1、格式錯誤為 64；`firmware-ci.sh` 任何樣本 FAIL／MISMATCH／MISSING／沒有輸入都為 1。

## expected 的變更（沒有改任何既有的值）

Dasharo（`dasharo-protectli-vp46xx-v1.2.0`）新增四項，依據都是「2026-11-11 公開範例試掃」記錄的 CBFS `revision`／`build_info`：

- `coreboot_version: protectli_vault_jsl_v0.9.2`
- `dasharo_version: v1.2.0`
- `coreboot_build_date: "2024-03-13"`
- （`coreboot_revision: add9d7206e30` 原本就有，只加註解）

VBT 版本（`1.00`、BDB 2.28）試掃報告沒有記錄，沒有加。NUC 維持一份微碼；OVMF 沒有 expected。OVMF 新增 `analyze` 欄位指定要取出 `usr/share/OVMF/OVMF_CODE_4M.fd`。

## 顯示韌體鍵（intel_gop、intel_legacy_vbios）

- 只比 SBOM 同名元件的 `version`（`Intel GOP driver`、`Intel legacy VBIOS (option ROM)`）。同名元件有多個時，跟 `fsp` 一樣任一個相符就 OK、其餘不比；沒有元件或元件沒讀到版本（GAP）＝MISSING，值不同＝MISMATCH，沒有輸出＝NOT_RUN。
- GOP 的 version 只有 build 編號（`1070`），不是 release notes 的 `17.0.1070`，expected 要寫 build 編號。
- 不加 `intel_vbt`：VBT 元件的 version 是 `$VBT` 表頭的格式版本（x100，NUC 樣本三份都是 `1.00`），不是發行版本，比對沒意義。
- NUC 樣本：寫了 `intel_gop: "1070"`（映像讀到 build 1070，release notes 17.0.1070 佐證）。legacy VBIOS 映像讀到 `1003 PC 14.34`，但 release notes 沒有 VBIOS／1003／14.34 字樣（pdftotext 全文查過），沒有獨立佐證，所以沒寫進 expected。

## AMD 鍵（amd_agesa、amd_microcode）

- `amd_agesa` 只比 SBOM 的 `AMD AGESA` 元件 version 的最後一個符記（PI 版本號）或整串；廠商 release notes 寫 `ComboV2PI 1.2.0.B`、映像字串是 `ComboAM4v2PI 1.2.0.B`，名稱部分不比。
- `amd_microcode` 比 `AMD CPU microcode` 元件的 equivalence id 與 patch level（version）；沒有 `amd_psp_*`：PSP 韌體條目的標頭版本沒有找到可對照的公開來源，不寫 expected。
- 樣本 `asus-prime-b550m-a-3404` 寫了 `amd_agesa: "1.2.0.B"`（ASUS 下載頁 release notes）與兩份微碼（與 linux-firmware 位元組相同），出處寫在該檔註解與 `docs/notes/c2-amd-psp.md`。

## CI 結果（2026-11-12）

- 綠燈：https://github.com/evil88332115-png/dumpling/actions/runs/43231626732
- 紅燈證明（暫時分支故意把 ME 版本改成 14.0.47.1559，已刪除分支，錯的值沒進本分支）：https://github.com/evil88332115-png/dumpling/actions/runs/43231826497 ，job 失敗，輸出 `MISMATCH … Intel ME 版本：預期 14.0.47.1559、實際 14.0.47.1558`

| 樣本 | firmware-bios 狀態行 | expected 比對 |
|---|---|---|
| dasharo-protectli-vp46xx-v1.2.0 | ATTENTION：BIOS 映像 1 個；沒有版本清單（無法核對） | 11 項、0 項不符（ME、微碼 3、FSP 2、coreboot 版本／修訂、Dasharo 版本、建置日期、edk2 修訂） |
| intel-nuc11-patgl357-0059 | ATTENTION：解開 PFAT 的 CAP 沒有 flash descriptor、42 個壓縮 UEFI section 沒有解析（GAP）；沒有版本清單 | 1 項、0 項不符（微碼 000806C1／0x80／0xBE） |
| ubuntu-ovmf-2024.02 | ATTENTION：OVMF_CODE_4M.fd 沒有 flash descriptor、1 個壓縮 section 沒有解析；沒有版本清單 | 沒有 expected（0 項） |

三個樣本都是 ATTENTION（解析範圍有限，原因在狀態行），不是 OK。

## 還沒做或不確定

- 比對只涵蓋 `expected` 寫了的值；微碼是「有一筆相符就 OK」，映像裡另有不同 revision 的同 cpuid／platform 微碼不會被抓到。
- `fsp` 是包含檢查，映像多出來的 FSP 版本不比。
- NUC 的 ME（release notes 15.0.56.2834）映像裡找不到，OVMF 沒有可佐證的版本值，所以這兩個沒有 ME／版本類 expected。
- vBIOS 樣本（NVIDIA 更新工具、GAP）沒有進這一步。
- 還沒做上傳 DT（等 C1 的 M1）；`firmware-sbom` 產出物（`fw.cdx.json`、`fw-inventory.json`、`fw-inventory.md`、`expect.log`）保存 14 天，供之後上傳用。
- `$GITHUB_STEP_SUMMARY` 的表格只能在 Actions 頁面看，這邊沒有截圖。
