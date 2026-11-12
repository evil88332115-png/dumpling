# C2：coreboot CBFS、FSP、VBT 加進韌體 SBOM（分支 wp3/coreboot-cbfs）

「coreboot 類 BIOS 映像（例如 Dasharo）裡的 CBFS 內容 → 版本與元件加進 `x86_firmware.py` 的 CycloneDX」。
只讀、不執行、不寫磁碟；輸入視為不可信。不是驗證結論：驗證代理與 CI 的結果另記。

## 檔案

| 檔案 | 內容 |
|---|---|
| `tools/cra/coreboot_cbfs.py` | 新模組（只用標準函式庫）：FMAP、CBFS、LZMA／LZ4、revision／build_info／config／FSP／VBT／SELF payload |
| `tools/cra/x86_firmware.py` | `bios_image()` 呼叫 `coreboot_cbfs.analyze()`；`components()` 產 SBOM 元件；markdown 加 CBFS 一節；沒有動 `inputs()` |
| `tools/cra/tests/test_coreboot_cbfs.py` | 假資料測試（FMAP＋CBFS＋LZMA／LZ4＋假 FSPH／VBT／revision／config），不含任何真實映像 |
| `tests/run.d/c2-x86-firmware.sh` | pytest 清單加入新測試 |
| `docs/PROVENANCE.md` | C2 節加一列「依原型重寫」 |

## 模組介面

`analyze(data, lo=0, hi=None, budget=None, max_total=None, max_file=None, max_text=None)`：在 `data[lo:hi]`（BIOS 區域）找 CBFS，
沒有 CBFS 回傳 `None`（OVMF 這類映像什麼都不加）。offset 都是 `data` 的絕對位置。回傳的 dict：

- `method`：`fmap` 或 `scan`；`fmap`：`{offset, version, name, size, areas, flash_start}`。
- `regions[]`：每個 CBFS 區域（`name` 是 FMAP 區域名、`role` 是 RO／RW_A／RW_B／RW_LEGACY 或原名）、`offset`、`size`、`entries`、`empty`、
  `files[]`（名稱、type、offset、長度、壓縮、宣告的解壓後大小、儲存內容的 SHA-256）。
- `coreboot[]`、`payloads[]`、`fsp[]`、`vbt[]`：每項有 `locations[]`（區域、檔名、資料 offset、長度），**相同內容只記一次、列出所有位置**。
- `microcode_files[]`：`cpu_microcode_blob.bin`、`intel_fit` 的位置（x86_firmware 用它給既有的 microcode 元件加 `found-in`，不另產元件）。
- `incomplete[]`：結構壞掉、壓縮解不開、超過上限等（x86_firmware 會變 ATTENTION，前綴 `CBFS:`）；`gaps[]`；`limits`。

低階函式（測試直接用）：`lz4_block()`、`lz4_frame()`、`lzma_alone()`、`decompress()`、`parse_fmap()`、`walk()`、`parse_fsph()`、`parse_vbt()`、`parse_self()`。

## 找 CBFS

1. **FMAP**：掃 `__FMAP__`（最多 64 個候選；coreboot 程式碼本身也有這個字串常數，所以每個候選都驗證版本 1、區域數、名稱可列印）。
   flash 起點：有名叫 `FMAP` 的區域就用「FMAP 位置 − 該區域 offset」（有 Intel descriptor 時 flash 是整個檔案，不只 BIOS 區域）；
   否則依宣告大小在整個檔案和 BIOS 區域之間選。FMAP 區域開頭是 `LARCHIVE` 才當 CBFS（已知名稱優先，區域重疊就只走一次並記 incomplete；
   已知名稱的區域沒有 CBFS 檔頭、或超出 flash 也記 incomplete）。
2. **沒有 FMAP**（或 FMAP 沒有 CBFS 區域、flash 對不上檔案）：掃 `LARCHIVE`：16 bytes 對齊、檔頭驗證通過、至少連續 2 個有效檔案，才算一個 CBFS。
3. 走檔案：下一個檔案在「資料結尾對齊 64 bytes」；位置不是檔頭時往後找下一個對齊的 `LARCHIVE`，跳過的 bytes 不全是 0xFF 就記 incomplete。
   每個檔頭都對區域結尾檢查（長度、資料 offset ≤ 0x10000、檔名要 NUL 結尾且可列印）。全部是迴圈，沒有遞迴；每步一定前進。

## 解壓縮與上限

LZMA 用標準庫（alone 格式，輸出必須恰好等於屬性宣告的大小、串流要正常結束）。LZ4 自己寫：block 解碼器（offset 0、offset 超過已輸出長度、
長度延伸溢位、輸入截斷、輸出超過上限一律 raise）、frame 解碼器（照 coreboot `ulz4fn`：單一 frame、獨立區塊、保留位元 0；
**xxh32 檢查碼不驗證**，同 coreboot）。

| 上限 | 值 |
|---|---|
| 單檔解壓後（FSP、payload 標頭） | `MAX_FILE_OUT` = 16 MiB |
| 文字類與 VBT（revision、build_info、config、vbt） | `MAX_TEXT_OUT` = 1 MiB |
| 整個映像解壓後合計 | `MAX_TOTAL_OUT` = 64 MiB（相同內容只解一次、只計一次） |
| FMAP 候選／區域數／CBFS 區域數 | 64／256／32 |
| 每區域檔案數／整個映像 | 8192／32768 |
| `LARCHIVE` 候選與重新同步 | 4096（掃描模式）／65536（字串數） |
| SELF segment 數、單一 property 清單 | 64、64 |

屬性宣告的解壓後大小超過上限就不解（incomplete）；實際輸出超過宣告也停。只解要讀的檔案，其他檔案只記屬性與儲存內容的雜湊。時間上限沿用 `Budget`。

## SBOM 元件（CycloneDX 1.6，`dumpling:vuln-assessment`＝NOT_ASSESSED、`dumpling:version-status` 沿用既有規則）

全部掛在 BIOS 映像元件的 `dependencies` 底下；`bom-ref` 用內容雜湊（coreboot 另加序號）。位置用 `sca-center:found-in`
（例如 `CBFS RO [COREBOOT]: fspm.bin @0xc07000`）。

| 元件 | name／version | 重點 property | purl | NOT_ASSESSED 原因 |
|---|---|---|---|---|
| coreboot | `coreboot`／`COREBOOT_VERSION` 原字串 | git 修訂、Dasharo 版本、建置字串與 UTC 時間、主機板、config 的雜湊與關鍵欄位（`CONFIG_EDK2_*`、`CONFIG_VBOOT`、`CONFIG_LOCALVERSION`、`CONFIG_MAINBOARD_*`、`CONFIG_SOC_*=y` 清單） | 有 `DASHARO_VERSION` **且** git 修訂是完整 40 碼才填 `pkg:github/dasharo/coreboot@<commit>`；其他情況不填，原因寫在 `sca-center:note` | NVD 對 coreboot（含 Dasharo fork）幾乎沒有資料 |
| edk2 payload（或 `coreboot payload (<名稱>)`） | version 不填（GAP） | SELF segment 表、entry、`CONFIG_EDK2_TAG_OR_REV`、repository | `CONFIG_EDK2_REPOSITORY` 是 `https://github.com/Dasharo/edk2` 且 `CONFIG_EDK2_TAG_OR_REV` 是完整 40 碼才填 `pkg:github/dasharo/edk2@<commit>`；否則不填 | edk2 版本不知道，無法依版本比對（其他 payload：沿用「這一層沒有漏洞比對」） |
| Intel FSP-M／FSP-S | `Intel FSP-M ($CMLFSP$)`／ImageRevision `a.b.c.d` | spec 版本、header revision、ImageId、ImageBase、ComponentAttribute、build／release type | 無 | Intel 公告無法機器比對（與 ME／微碼同一句） |
| Intel VBT | `Intel VBT (Video BIOS Table)`／`$VBT` 標頭版本（÷100，100＝1.00） | 簽章字串、BDB 版本（228＝2.28）、大小 | 無 | Intel 公告無法機器比對，且是顯示設定資料表、不是可執行程式 |

內容不同就是不同元件（雜湊去重）。FSP-M 在 RO、RW_A 各被 `cbfstool` 重新定位到不同位址（ImageBase 不同），所以同版本的 FSP-M 會有兩個元件，
`sca-center:fsp-image-base` 可以看出差別；沒有把它們合併成一個，因為雜湊不同。

## 狀態

CBFS 結構壞掉、壓縮解不開、超過上限、payload segment 範圍超出、FSP／VBT 檔案內容不合法 → `incomplete`，BIOS 映像 ATTENTION（原因進狀態行與
`sca-center:incomplete` property）；其他部分照常。找不到 `revision`／`build_info` → coreboot version 是 GAP。payload 內容（例如 edk2 的 firmware volume）
不展開，記一個 gap（那是 PR 2b 用 `uefi_image.py` 做的）。不出現整體 PASS 或「安全」。

## 本機真實樣本驗證（只寫檔名；結果是這次執行的紀錄，不是驗證結論）

- `protectli_vp46xx_v1.2.0.rom`（`pipeline/firmware-bios.sh`）：狀態 ATTENTION、原因只有「沒有版本清單（無法核對）」（跟加這個功能前相同），SBOM 16 個元件（以前 7 個），
  通過 CycloneDX 1.6.1 schema，全部 NOT_ASSESSED。
  - FMAP 找到（`FLASH` 版本 1.1、25 個區域，flash 起點 0）；CBFS 區域 RO（`COREBOOT`）、RW_A（`FW_MAIN_A`）、另有 `BOOTSPLASH`（只有一個空檔案）。
  - coreboot：`protectli_vault_jsl_v0.9.2`、git `add9d7206e30`（12 碼，所以沒有 purl）、Dasharo `v1.2.0`、建置 2024-03-13T15:18:26Z、主機板 Protectli VP46XX；RO、RW_A 的 `revision` 相同，一個元件、兩個位置。
  - `CONFIG_EDK2_TAG_OR_REV` = `2a15268b36cc732aa9d0a34a33965de6b0fca122`（完整 40 碼）、repository `https://github.com/Dasharo/edk2` → edk2 payload 有 purl `pkg:github/dasharo/edk2@2a15268b36cc…`，version GAP。payload 是 SELF、一個 CODE segment（LZMA）、entry 0x800860。
  - FSP（`$CMLFSP$`、spec 2.1）：`fspm.bin`／`fsps.bin` 是 **9.0.123.32**，`fspm_2.bin`／`fsps_2.bin` 是 **9.2.123.32**；M、S 分開；FSP-S 在 RO、RW_A 內容相同（一個元件兩個位置），FSP-M 兩區域各自重新定位所以各一個元件，共 6 個。
  - VBT：簽章 `$VBT SKYLAKE`、標頭版本 1.00（原始值 100）、BDB 版本 2.28（原始值 228）。
  - 既有部分不變：ME 14.0.47.1558；3 份微碼（000806EC／000A0660／000A0661，revision 0xF8）的元件內容沒變，只多了 `cpu_microcode_blob.bin` 的 `found-in`。
- OVMF（`ovmf_2024.02-2ubuntu0.10_all.deb` 解開的 `OVMF_CODE_4M.fd`）：沒有 CBFS（`cbfs` 為 null），SBOM 與狀態行跟加這個功能前逐位元相同（1 個元件、ATTENTION）。

## 還沒做或不確定

- **LZ4 沒有真實樣本**：Dasharo 的 CBFS 全是 LZMA。LZ4 解碼器只用測試自組的 frame 驗證（含惡意輸入與隨機輸入），尚未對真實 coreboot LZ4 CBFS 核對。
- FSP 的 `ExtendedImageRevision`（+0x4C，header 長度 ≥ 0x50 才有；+0x44／+0x48 是 SiliconInit／MultiPhaseSiInit 入口偏移，依 coreboot `info_header.h`）：非 0 時只記原始值與 note（版本可能偏低），不猜怎麼合併；版本仍只用 `ImageRevision`。Dasharo 的 FSP header 長度是 0x48，沒有這個欄位；ComponentAttribute 的 bit 0／1（build／release type）依 EAS 的描述，未在多個樣本上核對。
- VBT 版本寫成 header 版本 ÷ 100（`100` → `1.00`），依 Linux i915／coreboot 的結構註解（「decimal」）與 i915 的用法；原始值另記在 property。
- edk2 `CONFIG_EDK2_TAG_OR_REV` 是上游 tag（如 `edk2-stable202402`）時，目前仍不填 version（GAP），只記 property。
- 沒有 `config` 時 payload 的身分（edk2 或其他）不知道，只記 `sca-center:note`。
- 沒有展開 payload（SELF → LZMA → edk2 FV）；等 PR 2b。
- 非 Dasharo 的 coreboot 一律不填 purl（上游無法由映像確定）。
