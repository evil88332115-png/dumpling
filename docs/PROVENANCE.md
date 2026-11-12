# PROVENANCE：從 sca-center 複製的檔案

每個從 sca-center 複製進來的檔案記一列：dumpling 路徑、sca-center 原路徑、來源 commit、清理了什麼。
目錄對應規則（D-015）：sca-center 的 `scripts/<子目錄>/<檔名>` → dumpling 的 `tools/<子目錄>/<檔名>`；測試 `scripts/<子目錄>/tests/` → `tools/<子目錄>/tests/`。
各節只由負責的對話修改，避免衝突。

## C1 工具（WP1）

| dumpling 路徑 | sca-center 原路徑 | 來源 commit | 清理內容 |
|---|---|---|---|

## C2 韌體工具（WP3＋WP4）

| dumpling 路徑 | sca-center 原路徑 | 來源 commit | 清理內容 |
|---|---|---|---|
| `tools/cra/x86_firmware.py` | `scripts/cra/x86_firmware.py` | 25fa89a | 拿掉內部計畫編號與 issue／PR 參照、`CLAUDE.md` 參照、「main 也一樣」這類內部分支說明；範本路徑改成 `tools/cra/data/…`；「內部給的映像」改成「廠商或團隊提供的映像」；SBOM 的 tools 名稱 `sca-center x86_firmware.py` 改成 `dumpling x86_firmware.py`。**解析邏輯沒改。** 新增（dumpling 的功能）：`dumpling:vuln-assessment`／`dumpling:vuln-assessment-note`／`dumpling:version-status` property、Intel CSME 的 `cpe`（family 確定是 CSME 才填；NVD 查證寫在程式註解）。SBOM property 命名空間 `sca-center:` 與 inventory 的 schema 名稱 `sca-center-fw-inventory/1` **維持不變**（C1 複製的報告工具可能依賴） |
| `tools/cra/tests/test_x86_firmware.py` | `scripts/cra/tests/test_x86_firmware.py` | 25fa89a | 拿掉審查輪次與 issue 編號的註解；`cdx_validator` 改從 `cdx_schema.py` import（原本從 `test_firmware_bom`，那個檔案歸 C1）。測試內容沒改 |
| `tools/cra/data/fw-manifest-template.csv` | `scripts/cra/data/fw-manifest-template.csv` | 25fa89a | 無需清理（全是假資料範例），原樣複製 |
| `tools/cra/tests/data/cyclonedx-1.6.1/`（README.md、bom-1.6.schema.json、jsf-0.82.schema.json、spdx.schema.json） | `scripts/cra/tests/data/cyclonedx-1.6.1/` | 25fa89a | 三個 schema 是 CycloneDX 官方檔案，bom 與 spdx 原樣複製；jsf-0.82.schema.json 只改了 `$comment` 裡作者的個人信箱（公開檢查不允許個人信箱；不影響驗證，SHA-256 與原檔的差異見該目錄 README.md）；README 只改了「用來驗證」那句的檔名參照。C1 之後的 cra 測試共用這個位置 |
| `tools/cra/tests/cdx_schema.py` | `scripts/cra/tests/test_firmware_bom.py` 約第 422–434 行（`SCHEMA_DIR`、`cdx_validator`） | 25fa89a | 只抽出這兩段，其餘 `test_firmware_bom.py` 歸 C1，不複製 |
| `tools/cra/tests/conftest.py` | `scripts/cra/tests/conftest.py` 與 `integration/conftest.py`（概念） | 25fa89a | 不複製 `integration/`。改寫成等效的最小版：環境變數 `DUMPLING_REQUIRE_TEST_DATA=1` 時任何 skip 都視為失敗（原本是 `SCA_REQUIRE_TEST_DATA`） |
| `tools/cra/coreboot_cbfs.py`、`tools/cra/tests/test_coreboot_cbfs.py` | BIOS 試掃原型（未進 sca-center git）：CBFS 列表／讀取、SELF payload 展開、FSP header 讀取四支評估用腳本 | 無（原型不在 git） | **依原型重寫，不是複製。** 沿用的做法：CBFS 檔頭（`LARCHIVE`、big endian 欄位、壓縮屬性 tag 0x42435a4c）、LZMA（alone 格式）、SELF segment 表（`>4sIIQII`）、`FSPH` header 欄位位置。新增：FMAP 定位、區域分開記、邊界與上限檢查、LZ4 解碼器、`revision`／`build_info`／`config`／`vbt.bin` 解析、SBOM 元件。測試資料全部是測試自己組的假資料 |

以下是 dumpling 自己寫的（不是複製）：`pipeline/firmware-bios.sh`、`tools/cra/tests/test_x86_firmware_sbom.py`、`tools/cra/tests/requirements.txt`、`tests/run.d/c2-x86-firmware.sh`、`tools/cra/ami_pfat.py`、`tools/cra/tests/test_ami_pfat.py`、`docs/notes/c2-ami-pfat.md`（`ami_pfat.py` 的格式欄位核對自 platomav/BIOSUtilities 的 AMI PFAT 解開工具，只讀原始碼、沒有複製程式碼，出處與授權寫在該檔檔頭）。
