# C2：程式碼完整性的結構證據（Intel FIT）

分支 `wp3/fw-integrity-fit`。設計依據是調查筆記 `docs/notes/c2-code-integrity-survey.md`（D-060 M7f (c)）第 5 節的 PR-2：CI-01（Intel Boot Guard 結構）與 CI-07 的 Intel 部分（FIT 的除錯政策項目）。
這份是實作說明：資料結構、狀態規則、限制、依據、樣本結果。

## 1. 做了什麼、沒做什麼

映像能回答的只有「結構有沒有出現」。平台有沒有照這些結構執行（Boot Guard 的啟用、金鑰雜湊、除錯鎖）在熔絲與晶片組狀態，映像讀不到。所以產生物固定寫成
**structure observed; enforcement not assessed**：

- 做：`x86_firmware.py` 的 `fit_table()` 記錄 FIT 的每一個項目；`integrity_section()` 從項目產生 `bios[].integrity`（`fw-inventory.json`）；BIOS 映像元件加 `dumpling:integrity-*` property；`firmware-expect.py` 加 `expected.integrity`。
- 沒做（PR-8）：`fw-inventory.md` 的新段落、`firmware-ci.sh` 的摘要欄。`status_of()` 沒有讀 `integrity`：GAP 與 NOT_ASSESSED 不會讓報告變 ATTENTION，`fw-inventory.md` 與狀態行的內容與沒有這個欄位時相同（測試鎖住）。
- 沒做：KM／BPM 的內容解讀（政策旗標、金鑰雜湊）、簽章驗證、AMD（沒有 FIT，PSP 目錄是 PR-3）、vBIOS、Jetson。

## 2. 資料

### 2.1 `fw-inventory.json` 的 `bios[].integrity`

```
integrity: {
  scope, statement ("structure observed; enforcement not assessed"),
  fit: {status, offset, complete, issues[], declared_entries, read_entries, header_version, checksum, entries[]},
  items: [{id, state, evidence, basis, reason}, …]
}
```

- `fit.entries[]`：FIT 的每一個項目（type 0x7F 也列）：`entry`（第幾項）、`type`（`0x0b`）、`name`、`address`、`size_field`（單位 16 bytes）、`version`、`checksum_valid_bit`、`offset`（對到映像的檔案位置，落在映像外是 null）、
  `in_image`（位址連同大小欄位都在映像內；type 0x7F 是 null）、KM／BPM 另有 `id_string`（位址開頭 8 bytes，不可印的位元組換成 `.`）。
- `fit.complete`：整張表讀完而且沒有任何問題。`fit.issues`：不完整的原因（見 3.2）。`fit.checksum`：`valid`（C_V 位元有設、整張表加總為 0）、`invalid`（C_V 有設但加總不是 0）、`not-set`（C_V 沒設，規格不要求 checksum）、`not-checked`（表沒完整讀進來）。
- 既有的 `fit` 物件（`status`、`offset`、`entries`、`microcode`、`note`）和微碼的 `in_fit`、`incomplete` 沒有改；新資料只在 `integrity`。AMD 平台的 `integrity.items` 是空的（沒有 FIT），`note` 寫明。

項目 id：

| id | 內容 | 狀態怎麼來 |
|---|---|---|
| `CI-01` | Boot Guard 結構（匯總） | KM 或 BPM 有一個 observed → observed；兩個都 not-found → not-found；其餘 GAP |
| `CI-01.km` | Key Manifest（FIT type 0x0B） | 3.1 |
| `CI-01.bpm` | Boot Policy Manifest（FIT type 0x0C） | 3.1 |
| `CI-01.acm` | startup ACM（FIT type 0x02） | 3.1；不併入 `CI-01`（startup ACM 也用在 Boot Guard 以外的功能） |
| `CI-02` | Boot Guard 是否生效 | 固定 `NOT_ASSESSED`，`ci-needs-fuse-state` |
| `CI-07` | 除錯政策項目（FIT type 0x2F，Intel 名稱 JMP $ Debug Policy） | 3.1 |
| `CI-07.lock` | 除錯是否鎖住 | 固定 `NOT_ASSESSED`，`ci-needs-fuse-state` |

`reason` 用調查筆記第 6 節的代碼：observed 是 `ci-structure-observed-enforcement-unknown`、not-found 是 `ci-not-found-parse-complete`、GAP 是 `ci-not-found-parse-incomplete`（FIT 沒讀到或沒讀完、位址在映像外）或 `ci-container-unsupported`（容器不是完整 SPI 映像）。
`basis`：除了兩個 NOT_ASSESSED 項目，固定寫「映像自述（項目類型依 Intel FIT 規格與 coreboot `fit.h`）、沒有簽章驗證、假設映像沒被改過」；NOT_ASSESSED 項目寫答案在熔絲與晶片組狀態、映像不含，需要上機依據。

### 2.2 SBOM

BIOS 映像元件（不是 ME、微碼等子元件）加：

- `dumpling:integrity-ci-01`、`-ci-01-km`、`-ci-01-bpm`、`-ci-01-acm`、`-ci-02`、`-ci-07`、`-ci-07-lock`：值是該項目的 state。
- `dumpling:integrity-basis`：`structure observed; enforcement not assessed; self-declared by the image: …; no signature was verified; assumes the image was not modified`。

命名空間是 `dumpling:`，不放進 `sca-center:`（C1 的報告工具可能依賴舊名稱，見 `docs/PROVENANCE.md`）。AMD 平台沒有這些 property。

## 3. 狀態規則

### 3.1 一種項目類型（KM、BPM、startup ACM、0x2F）

| 條件 | state | reason |
|---|---|---|
| 有這個類型的項目，至少一個的位址落在映像內 | observed | `ci-structure-observed-enforcement-unknown` |
| 有這個類型的項目，位址都在映像外（或大小欄位從位址起算超出映像末端） | GAP | `ci-not-found-parse-incomplete` |
| 沒有這個類型的項目，而且整張 FIT 完整讀完 | not-found | `ci-not-found-parse-complete` |
| 沒有這個類型的項目，但 FIT 沒讀完 | GAP | `ci-not-found-parse-incomplete` |

KM、BPM 位址開頭的 `__KEYM__`、`__ACBP__` 只是觀察值：證據寫「有看到」或「沒看到」，不影響 state（測試鎖住：字串不在、項目在 → 仍然 observed；字串在、項目不在 → 不會變 observed）。

### 3.2 FIT 沒讀完的原因（`fit.issues`，任何一個都讓 `complete` 是 false）

- 表頭的長度欄位是 0；項目數超過 `MAX_FIT_ENTRIES`（只讀前面的）；項目超出 BIOS 區域末端；
- 表頭版本不是 0x0100；
- 表頭 C_V 位元有設、但整張表的 bytes 加總不是 0；
- 映像被截短（flash descriptor 宣告的區域超出檔案）。

讀到的項目照樣記錄、照樣可以是 observed；只有「沒看到」不能寫成 not-found。

### 3.3 整份映像都是 GAP 的情況（不讀項目）

| 情況 | reason |
|---|---|
| 單獨的 ME 更新檔（沒有 BIOS 區域） | `ci-container-unsupported` |
| 映像是 AMI PFAT 等封裝組回來的（位移不是 SPI 位址，FIT 指標的位置沒有意義；裡面剛好有合法的 FIT 也不採用） | `ci-container-unsupported` |
| 檔尾 −0x40 沒有 FIT 指標、而且沒有 flash descriptor（capsule、只有 BIOS 區域的檔案、其他不是完整 SPI 映像的檔案） | `ci-container-unsupported` |
| 檔尾 −0x40 沒有 FIT 指標、有 flash descriptor 與 BIOS 區域 | `ci-not-found-parse-incomplete`（映像讀不到 FIT，和「平台沒有 FIT」分不出來） |
| FIT 指標對到映像外，或指到的位置不是 `_FIT_` 表頭 | `ci-not-found-parse-incomplete` |

AMD 平台（認出 AMD 標記的映像）不產生項目。

## 4. FIT 的讀法與限制

- 位置：指標在 4 GB−0x40（高 32 bits 為 0、低 32 bits 在 4 GB 以下 16 MB 內），對到映像的方式照既有的 `fit_table()`：完整 SPI 映像是 BIOS 區域，結尾對到 4 GB；沒有 descriptor 的檔案是整個檔案。
- 項目 16 bytes：位址 8、大小 3（單位 16 bytes）＋保留 1、版本 2、類型 1（最高位元是 C_V）、checksum 1。
- 項目名稱依 Intel FIT BIOS Specification rev 1.6 的 Table 4-2；未列的類型記為 `platform manufacturer use`（0x30–0x70）或 `reserved or unknown`。
- 項目位址的意義依類型而不同（有的是指向元件的位址、有的是值）。`in_image` 只是算術：位址對到 4 GB 以下後，從位址起算「大小欄位 × 16 bytes（至少 8 bytes）」是否都在映像內。
  狀態只用在 KM、BPM、startup ACM、0x2F 四種；其他類型只記錄，不產生狀態。0x2F 的位址意義規格沒有寫，規則同其他三種（位址在映像外一律 GAP，不假設它是值）。
- 只讀一張 FIT。top swap 的第二張表、`MAX_FIT_ENTRIES`（512）以後的項目不讀。
- 所有值是映像自述。FIT 的 checksum 與 C_V 只證明表自洽，不證明沒被竄改；沒有做任何簽章驗證；信任根（金鑰雜湊）在熔絲，不在映像。
- 「observed」只代表映像的 FIT 有這個項目。不寫、也不能推論「驗證開機已啟用」「映像已簽章」。
- 檔名（例如 `btg_prod`）不是依據。

## 5. 依據與核對（調查筆記第 7 節第 2 項）

| 項目 | 依據 | 狀態 |
|---|---|---|
| FIT 位置、項目格式、C_V 與 checksum、Size 單位、表頭版本 | Intel Firmware Interface Table BIOS Specification rev 1.6（文件 599500，2025 年 3 月）第 3、4 節；公開、不需登入，`https://cdrdv2-public.intel.com/599500/599500_FW_Interface_Table_BIOS_Spec_Rev1p6.pdf`，529828 bytes，sha256 `f5b368609c03daa521996142c02d33eb2923d76f02b8d6b7f6da1534440e5295`（2026-11-15 取得；放在暫存的新資料夾、只讀文字、沒有執行） | 已核對 |
| 項目類型編號 0x02、0x0B、0x0C、0x10、0x2F 與名稱 | 同一份規格的 Table 4-2（0x02 Startup AC Module、0x0B Key Manifest Record、0x0C Boot Policy Manifest、0x10 CSE Secure Boot、0x2F JMP $ Debug Policy）；coreboot `util/cbfstool/fit.h` 的 `fit_type` 列舉編號相同（0x2D 的名稱兩邊不同，這裡用 Intel 的 Feature Policy Delivery Record） | 已核對 |
| 規格對 KM、BPM 項目的規則 | 規格 4.13、4.14：C_V 位元與 checksum 欄位應為 0、Size 不小於結構大小、BPM 在 KM 之後；樣本的 KM、BPM 項目符合（C_V＝0、checksum＝0） | 已核對（沒有拿來當判斷條件） |
| KM、BPM 結構開頭的 `__KEYM__`、`__ACBP__` | Intel 的 FIT 規格 rev 1.6 **沒有**這兩個字串（規格只講 FIT 項目，不講 KM／BPM 的內容）。公開原始碼依據：Slim Bootloader（BSD-2-Clause-Patent；commit `d79ed7659a1fcea1f82a8d62e7728e37167fb079`）的 `Silicon/CommonSocPkg/Library/BootGuardLibCBnT/BootGuardTpmEventLogLib.c`：`KEY_MANIFEST_STRUCTURE_ID` 是 `"__KEYM__"`、`BOOT_POLICY_MANIFEST_HEADER_STRUCTURE_ID` 是 `"__ACBP__"`，各是結構的第一個欄位 `StructureId[8]`。coreboot 的原始碼封存（`add9d7206e30`）沒有這兩個字串 | 已核對（來源是公開原始碼，不是 Intel 規格文件）；只當觀察值 |
| KM、BPM 的政策旗標、金鑰雜湊欄位的意義 | 沒有讀；沒有公開的 Intel 規格文件（不使用外洩或非公開資料，D-058） | 還沒核對，不解讀 |
| `.CAP` 檔的容器格式（AMI PFAT 以外的 capsule） | 沒有格式文件 | 還沒核對，GAP |

取得過程：Intel 公開網址 `https://www.intel.com/content/dam/www/public/us/en/documents/guides/fit-bios-specification.pdf`（coreboot 文件 `Documentation/soc/intel/fit.md` 引用的位置）經轉址回 200 的 PDF；
`cdrdv2-public.intel.com/599500/FIT_BIOS_Specification.pdf`（猜的檔名）回 403，沒有再試其他方式。Slim Bootloader 的檔案從 GitHub 公開頁面取得，只讀字串與結構定義，沒有複製程式碼。

## 6. 樣本結果

下表是 `firmware-ci.sh` 對本機公開樣本的輸出（`fw-inventory.json` 的 `integrity.items` 與 SBOM property）。`expected.integrity` 的值是另寫的獨立腳本直接從原始位元組讀出來的（只用 `struct`，不引用專案程式）：
FIT 指標與表頭、每個項目的類型與位址、位址開頭的 8 bytes；規則與 3.1、3.2 相同。

| 樣本 | FIT | CI-01／km／bpm／acm | CI-07（0x2F） | CI-02、CI-07.lock | `expected.integrity` |
|---|---|---|---|---|---|
| `novacustom-v540tu-mtl-v1.0.1` | found，4 項：0x01、0x02、0x0B、0x0C，表完整、checksum valid；KM 位址開頭 `__KEYM__`、BPM 位址開頭 `__ACBP__` | observed／observed／observed／observed | not-found | NOT_ASSESSED | 寫了（6 項） |
| `dasharo-protectli-vp46xx-v1.2.0` | found，3 項，都是 0x01，表完整、checksum valid | not-found（四項都是） | not-found | NOT_ASSESSED | 寫了（6 項） |
| `novacustom-nuc-box-arl-v0.9.2` | found，1 項：0x01，表完整、checksum valid | not-found（四項都是） | not-found | NOT_ASSESSED | 寫了（6 項） |
| `intel-nuc11-patgl357-0059` | zip 內四個 `.CAP`（內容相同）是 AMI PFAT 封裝，組回映像；FIT 指標在檔尾 −0x40 讀不到 | GAP（四項都是，`ci-container-unsupported`） | GAP | NOT_ASSESSED | 寫了：全部 GAP（6 項） |
| `ubuntu-ovmf-2024.02` | 沒有 descriptor、檔尾 −0x40 沒有 FIT 指標 | GAP（`ci-container-unsupported`） | GAP | NOT_ASSESSED | 沒寫（沒有可對照的獨立佐證） |
| `asus-prime-b550m-a-3404` | AMD 平台，沒有 FIT | 沒有項目（`integrity.note` 說明） | 沒有項目 | 沒有項目 | 沒寫 |

和 `origin/main` 比較（同一批本機樣本，各跑一次 `firmware-ci.sh`）：`fw-inventory.json` 去掉 `bios[].integrity` 後逐項相同、SBOM 去掉 `dumpling:integrity-*` property 後逐項相同（序號與時間除外）、`fw-inventory.md` 完全相同；
`expected` 比對除了新增的 `integrity` 項目，其餘每一項的結果與數值不變。SBOM 每個有 FIT 結構的 BIOS 映像元件多 8 個 property（7 個項目＋basis）。

NUC 11 的 GAP 不代表這個平台沒有 Boot Guard 結構：檔案是 capsule，不是完整 SPI 映像（調查筆記第 3.4 節）。

## 7. 測試與變異檢查

`tools/cra/tests/test_fw_integrity.py`（合成映像，不含產品映像）涵蓋：每個 FIT 項目的記錄；有 KM、BPM、ACM；只有微碼；只有一個 manifest；type 0x2F；未知與保留類型；
FIT 指標在映像外或指到非 FIT；沒有 FIT 指標（有或沒有 descriptor）；capsule 檔；PFAT 組回的映像；單獨的 ME 更新檔；AMD 平台；項目位址在映像外（含大小欄位超出末端）；
項目數超過上限；checksum、長度、版本不合；映像被截短；SBOM property 的名稱與值；報告與 SBOM 不出現啟用、簽章類的結論；`status_of()` 與 `fw-inventory.md` 不受 `integrity` 影響；`fit` 物件與微碼輸出不變。
`tests/test_firmware_expect.py` 涵蓋 `expected.integrity` 的比對與格式錯誤。

變異檢查：把 `x86_firmware.py` 的判斷逐項拿掉或改掉，確認測試會失敗（25 個變異，全部被抓到）：無效指標不當 GAP、not-found 不要求整張表讀完、容器不當 GAP、有無 descriptor 不分、單獨 ME 更新檔不當 GAP、
位址在映像外也算 observed、checksum／項目數上限／表長度／版本／長度欄位為 0／映像截短不算問題、CI-01 要求 KM 與 BPM 都有、CI-02 與 CI-07.lock 改成非 NOT_ASSESSED、AMD 平台照樣產生項目、
大小欄位不納入 `in_image`、位址在映像外的類型掉到 not-found、沒有 FIT 指標不當 GAP、KM／BPM 字串決定狀態、SBOM 不輸出 property、`fit` 物件多出新鍵、`status_of()` 讀 `integrity`。

## 8. 還沒做

- PR-8：`fw-inventory.md` 的「Code integrity (structure evidence)」一節、`firmware-ci.sh` 的摘要欄（各項 state 的計數）、`status_of()` 語意由使用者或 C0 決定（建議維持不讀 `integrity`）。
- PR-3：AMD PSP 目錄的金鑰、除錯、解鎖項目（CI-05、CI-07 的 AMD 部分）。
- KM、BPM 的內容欄位、`.CAP` 檔內的 FIT（封裝內容的位址對應沒有公開依據）、top swap 的第二張 FIT。
- ETSI 條款對照（調查筆記 PR-0）。
