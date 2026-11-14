# C2：AMI Aptio V 核心版本（Firmware ID 紀錄 `$FID`）與規則表比對（決定 D-058，分支 wp3/ami-core）

只用公開映像與公開資料。這份是工作紀錄，不是驗證結論，也不是漏洞判定：讀不到、有多個互相矛盾的值、結構不認得一律是 GAP／NOT_ASSESSED，不猜。
`$FID` 的結構**沒有 AMI 的公開文件**，欄位位置只從四份公開映像反推；沒有複製任何程式碼，沒有使用任何非公開或外洩的 AMI 資料。

## 檔案

| 檔案 | 內容 |
|---|---|
| `tools/cra/ami_core.py` | 純函式（只用標準函式庫、不碰檔案）：`$FID` 結構檢查（`parse_record`）、前導檢查（`find_fid`）、結果狀態與摘要（`summarize`） |
| `tools/cra/uefi_gfx.py` | 同一次 UEFI 走訪（C1 的 `uefi_image.parse_fvs`）裡收 `$FID` 候選：每塊內容只多一個 `b"$FID" in body` 的檢查，沿用同一份去重（重複內容記新位置）與上限；結果在 `scan()["ami_core"]` |
| `tools/cra/x86_firmware.py` | SBOM 元件與 property、`fw-inventory.md` 的「AMI 核心版本」一節、狀態、規則表的比對輸入、版本清單 `ibv-core` 核對 |
| `tools/cra/fw_advisory_rules.py` | `cond_ami`（規則表 `ami_core` 條件的比較）、`fixed_in` 格式驗證；規則表內容與 `TABLE_SHA256` 沒有因為這項功能而改 |
| `tools/cra/tests/test_ami_core.py` | 測試：全部用測試當場組的合成 FV 與 `$FID` 紀錄，**沒有任何真實映像的位元組** |

用到的 C1 公開介面與 `docs/notes/c2-vbios.md` 相同（`Scan`、`Scan.scan_bytes`、`parse_fvs`、`Stop`、上限常數、`undecoded`／`notes`／`parse_errors`），契約測試 `test_uefi_image_contract.py` 沒有改。

## `$FID` 紀錄的結構（從公開映像反推，不是規格）

偏移從 `$FID` 的 `$` 起算：

| 偏移 | 長度 | 內容 | 檢查 |
|---|---|---|---|
| +0 | 4 | `$FID` | |
| +4 | 1 | 結構版本 | 必須是 `04`（四份樣本都是；只見過這一個值） |
| +5 | 2 | u16 小端，標準部分的長度 | 必須是 120（FIDT 表長 156 ＝ 36 ＋ 120，FFS section 長度 136 ＝ 16 ＋ 120，所以這個解讀對得上） |
| +7 | 9 | BIOS tag | 1～8 個可列印 ASCII，後面補 NUL 到 9 位元組 |
| +16 | 16 | 用途不明 | 不使用 |
| +32 | 3 | Core Major：兩位 ASCII 數字加 NUL（`30 35 00` ＝ "05"） | 位元組比對（`[0-9]{2}\x00`，`fullmatch`），不用 `str.isdigit`（全角數字會被它收下） |
| +35 | 3 | Core Minor | 同上 |
| +38 | 3 | Project Major | 同上 |
| +41 | 3 | Project Minor | 同上 |
| +44 | 7 | 建置時間：u16 年、月、日、時、分、秒 | 值合理才報告日期，否則不報（不影響紀錄是否有效） |

Project 欄位等於廠商公布的 BIOS 版本（3.40、34.04、18.07、0.59），所以欄位順序與意義在四份樣本都對得上。「Core 欄位 ＝ AMI 公告寫的 `AptioV_5.0xx`」是**推論**（見 A1）。

紀錄前面一定有下列兩種前導之一，沒有前導的 `$FID`（例如程式碼模組裡當比對常數用的位元組）不算：

1. **FFS 形式**：前 16 位元組是 FREEFORM_SUBTYPE_GUID section 的子類型 GUID `2EBE0275-6458-4AF9-91ED-D3F4EDB100AA`。這個檔案在開機區塊的 FV（沒壓縮）。
2. **FIDT 形式**：前 36 位元組是 ACPI 表頭，簽章 `FIDT`、表長（u32 小端，+4）在 156～4096；表長不在範圍內就是結構不合的候選（`layout-unknown`）。這份表在 LZMA 壓縮的 FV 裡。

兩種形式內容相同。FIDT 為什麼存在、執行時是否交給 OS，沒有公開文件可查，只是樣本的觀察，實作不依賴它。

## 結果狀態與處理

| status | 條件 | SBOM | 規則表（`ami_core`） |
|---|---|---|---|
| `read` | 至少一份通過結構檢查的紀錄，所有紀錄的 Core 相同 | 有元件，有版本 | 比較（見下） |
| `not-found` | 沒有任何帶前導的 `$FID` | 沒有元件 | NOT_ASSESSED（`no-ami-core-version`）；走訪不完整時寫「沒找到不代表不存在」 |
| `conflict` | 通過檢查的紀錄之間 Core 不同 | **不選一個**，沒有元件、沒有版本；候選（各自的位置、tag、專案版本）列在 `fw-inventory.json` | NOT_ASSESSED（`ami-core-conflict`），狀態 ATTENTION |
| `layout-unknown` | 有帶前導的 `$FID`，但沒有任何一份通過結構檢查 | 沒有元件；`sca-center:gap` 附原始位元組的前 64 個（十六進位） | NOT_ASSESSED（`ami-fid-layout-unknown`），狀態 ATTENTION |
| `not-searched` | 沒有走訪 UEFI 內容（沒有未壓縮的 FV、`uefi_image` 載入不了） | 沒有元件 | NOT_ASSESSED（`no-ami-core-version`） |

- 同一映像內多份 `$FID`（備份 FV、A／B 兩區、FIDT 副本）Core 相同是正常現象，不算矛盾；tag 不同也不算矛盾，只記錄。
- `read` 但另有帶前導卻不合結構的候選：照 `read`，候選數與原因寫在 `sca-center:note`（忽略它們）。
- `complete`：`uefi_image` 的 `undecoded`、`notes`、`parse_errors`、`Stop`、時間上限、去重後內容總量上限、FID 候選數上限都沒有觸發才是完整。不完整時元件加 `sca-center:incomplete`（其他沒解開的地方可能有核心不同的紀錄）。有 coreboot CBFS 的映像一律不完整（CBFS 檔案沒有解開）。
- Core Major 不是 5：有版本、元件名稱是 `AMI firmware core`、沒有 product（`sca-center:note` 寫明）；規則表 NOT_ASSESSED（`ami-product-unknown`）。
- 非 AMI 的映像（沒有 AMI 的線索：`ibv_hint` 沒有 AMI、也不是 PFAT 封裝）沒有核心版本是正常的：只在 BIOS 映像元件的 `sca-center:ami-core-search` 記 `not-found`，不加 `sca-center:gap`、不影響狀態。有 AMI 的線索卻讀不到時才加 gap 與 ATTENTION。

## SBOM

BIOS 映像元件加 `sca-center:ami-core-search`（`read`／`not-found`／`conflict`／`layout-unknown`／`not-searched` 加一句說明）。`read` 時多一個元件，掛在 BIOS 映像底下：

- `type` firmware、`name` `AMI Aptio V core`（Core Major 不是 5 時 `AMI firmware core`）、`version` 映像讀到的原值（`5.17`，主次兩個整數）、`manufacturer` `American Megatrends`；沒有 `hashes`（核心版本不是獨立的二進位）。
- `sca-center:version-basis`：寫明「值是映像自述、沒有簽章驗證」（同 D-050 的 PSP 條目版本）、「結構是從公開映像反推，不是 AMI 文件」。
- `sca-center:ami-core-fid`（`05.17`）、`sca-center:ami-core-product`、`sca-center:ami-core-product-basis`、`sca-center:ami-core-advisory-form`（`AptioV_5.017`）加 `…-basis`（寫明是推導、A1）、`sca-center:ami-fid-bios-tag`、`sca-center:ami-fid-project-version`、`sca-center:build-date`、`sca-center:count`、`sca-center:found-in`（`<module GUID> <形式> +0x<內容內偏移>`）、`sca-center:evidence-sha256`（各份紀錄 120 位元組的 SHA-256）。
- 命名空間：元件事實用 `sca-center:*`，評估用 `dumpling:*`。`dumpling:vuln-assessment` 維持 `NOT_ASSESSED`；規則表建議在 `dumpling:advisory-rule-*`。
- 位置只有 module 與「section 內容裡的偏移」：C1 的介面不給 FV 偏移，PFAT 組回映像的偏移也不是 SPI 位址。

## 規則表比對（`cond_ami`，決定 D-058）

規則 `{component: ami_core, product: "Aptio V", fixed_in: "AptioV_5.044"}`。`fixed_in` 驗證改成 `fullmatch` `AptioV_[0-9]\.[0-9]{3}`（現有兩筆都是 `AptioV_5.044`，規則表內容與 `TABLE_SHA256` 沒有變）。依序判斷：

1. status 不是 `read` → NOT_ASSESSED（`no-ami-core-version`／`ami-core-conflict`／`ami-fid-layout-unknown`）。
2. 沒有 product（Core Major 不是 5）→ NOT_ASSESSED（`ami-product-unknown`）。
3. product 正規化（去空白、轉小寫）後不同 → `out-of-scope`。
4. 規則沒有 `fixed_in` → NOT_ASSESSED（`rule-has-no-fixed-in`）。
5. 核心的 major 與 `fixed_in` 的 major 不同 → NOT_ASSESSED（`ami-core-line-differs`，跨 major 不比）。
6. 核心**低於** `fixed_in`（整數 `(5, 17)` 對 `(5, 44)`）→ **affected 建議**（preliminary 照規則狀態，整份狀態 ATTENTION，待人審）。
7. 核心**不低於** `fixed_in` → 一律 NOT_ASSESSED（`ami-core-mapping-unverified`），不論 `complete`。**第一版不輸出 not-affected**，等 A1 有公開依據（AMI 文件或板廠確認）再另立決策開放。

affected 建議的 detail、`dumpling:advisory-rule-basis` 與報告固定寫明三件事：核心是 AMI 的基底版本，板廠回補的修正在映像裡看不出來；核心版本寫法的對應（A1）尚未經 AMI 或板廠確認；這是請負責單位對照板廠公告的線索，不是漏洞判定。

有 `ami_core` 元件時，`bios_image` 不再比 `ami_core` 規則（同一條規則只出一個建議）；沒有元件時維持原狀（列「可能相關的 AMI 公告」，status 不是 `read` 的原因代碼會出現在 BIOS 映像的建議裡）。

## 版本清單的 `ibv-core` 核對

版本清單的 `ibv-core` 列（例如 `Aptio V 5.27`）和映像讀到的核心比對：用 `(?:Aptio\s*V?[ _]*)?([0-9])\.([0-9]{2,3})`（`fullmatch`）取主、次整數，一致 `match`、不一致 `mismatch`（ATTENTION，待確認）；清單的寫法讀不懂 → `declared-only`、`verifiable` 為 false；清單有、映像讀不到 → `declared-only`、可核對；只有映像 → `extracted-only`。清單**不改變**規則表使用的值（規則表只看映像讀到的）。映像的 Core 互相矛盾或讀不到時沒有映像的值可比。

## 兩個沒有明文的假設

- **A1**：FID 的兩位數 Core Minor（`17`）＝ 公告 `AptioV_5.0NN` 的 NN（`AptioV_5.017`）。公告是三位數、FID 是兩位數；十進位且 NN 小於 99，數字上可以直接對，但沒有 AMI 或板廠的文件寫這個對應，樣本也沒有廠商同時公布 AMI 核心版本與 FID 的例子。
- **A2**：同一個 major 內次版號隨發行遞增。AMI 公告用「up to 5.039」這類說法，與此相容，但沒有明文保證。

兩者都寫在 SBOM property（`sca-center:ami-core-advisory-form-basis`）與報告，並且是第一版不輸出 not-affected 的原因。

## 依據（公開網址；我實際讀過的）

- Setup 畫面 Core Version 的意義：Welotec 文件「Core Version: AMI Kernel version, CRB code base, X64」https://rsaec.docs.welotec.com/latest/BIOS.html ；範例值 5.32 https://alderamin-pico-mk5.docs.welotec.com/latest/BIOS.html 。
- Oracle x9-2 文件：「Core version number … Format is XX.YY（XX - Core major release，YY - Core minor release），Example: 5.20」https://docs.oracle.com/en/servers/x86/x9-2/exa-database/main-menu.html 。
- AMI 公告 PDF：「If the fix version includes "Aptio," AMI's UEFI product, AptioV, was affected.」；`Fix Version` 欄寫 `AptioV_5.044`，例 https://go.ami.com/hubfs/Security%20Advisories/2026/AMI-SA-2026001.pdf （2026002 同格式）。公告沒有寫怎麼從映像或 Setup 找出自己的核心版本。
- GUID 的名稱：`3FD1D3A2-99F7-420B-BC69-8BB1D492A332` 在公開工具的 GUID 清單裡叫 `Fid`；`2EBE0275-…` 在 fwupd 的 `libfwupdplugin/fu-efi-section.c` 叫 `SignOn`（名稱不同，意義不確定）。只有名稱，沒有結構。
- FID 是可以被改的標籤：Win-RAID 討論串寫 FID（俗稱 BIOS Tag）「can be changed」https://winraid.level1techs.com/t/problem-adjust-bios-version-hp-pavilion-500-549ng-ami-aptio4/33124 。所以它和 PSP 標頭版本一樣是映像自述的值。
- 間接佐證（只讀到搜尋結果摘要，原頁面直接抓取回 403，沒有逐字核對）：Aptio V 的 AM4 主機板在 dmidecode 有 `BIOS Revision: 5.17` 的公開傾印（openbenchmarking.org 的 dmidecode 結果頁）；NVD 的 CPE `ami:aptio_v:5.0` 與 VulDB 的「AMI AptioV up to 5.039」顯示公告的 `5.0xx` 是 Aptio V 的核心版本線。
- 沒有用：AMI 的 AFU 使用手冊（多數標 NDA）與任何非公開授權的 AMI 資料。公開的 AFU「PUB」手冊有查，沒有寫 FID 或核心版本；UEFITool、BIOSUtilities、coreboot 沒有查到解析 `$FID` 的程式或文件。

### 看過、不是核心版本或不能用的候選

| 候選 | 為什麼不用 |
|---|---|
| `$IBIOSI$`、`$BVDT`、`AMIBIOS` 加數字、`Aptio` 版本字串 | 四份樣本（含 PFAT 組回映像）都沒有 |
| `AMIBIOS(C)2023 American Megatrends, Inc.` | 只是版權年份 |
| `AMIBIOS 080010`、`AMIBIOS(C)2010 …`（CSM16 的 RAW 區段） | 舊的 legacy 相容層字串 |
| `AMI AptioV v1.0`（PE32 模組的 UTF-16 靜態字串） | 靜態的 HII 字串，與核心版本無關 |
| Setup 的 `Core Version`、`Compliancy`、`Project Version`（值是 `N/A` 佔位字串） | 值在執行時才填，映像裡只有標籤；標籤把 Core Version 寫成 `XX.YY`，語意與 FID 的 Core 欄位吻合 |
| AMITSE 的 `Version %x.%02x.%04x. Copyright …` | TSE（Setup 引擎）的版本格式字串，不是核心版本 |
| SMBIOS Type 0 靜態範本的 System BIOS Major／Minor Release | OEM 可以選：ASUS B650M 的範本是專案版本 18.07，不是 FID 的 5.26；互相矛盾的候選，不採用 |

## 限制

1. 結構只用四份公開映像（每份 3～5 份紀錄）反推；結構版本只見過 `04`。沒有 Aptio IV（核心 4.6.x）、較舊或較新的 Aptio V 樣本，那些映像的 `$FID` 可能不存在或格式不同 → `layout-unknown`／`not-found`（GAP）。
2. A1、A2 沒有明文；Core 是基底版本，板廠回補的修正看不出來；`$FID` 是自述值，可以被改，沒有簽章驗證。
3. 沒有核心版本的映像（Aptio 以外的 IBV、AMI 但沒有 `$FID`、`$FID` 在 `uefi_image` 解不開的地方）沒有元件；沒找到不代表不存在。四份樣本的 `uefi_image` 都有沒解開的部分（EFI 標準壓縮 section 等），完整旗標（`complete`）在這四份都是 false。
4. 規則表只涵蓋收錄的 AMI-SA（2026001、2026002，`Fix Version` 皆為 `AptioV_5.044`；2026002 另有 `AptioV_5.043`，取最高）。
5. 時間戳、tag、專案版本只記錄，不比對；專案版本與板廠版本的對照靠人看。

## 公開樣本結果（核心版本、規則表建議）

四份 AMI 樣本與五份非 AMI 樣本的實測結果（`pipeline/firmware-ci.sh` 與 `pipeline/firmware-bios.sh`；沒有 `firmware.yml` 的樣本結果只寫在這裡）。「紀錄數」是走訪遇到的 `$FID` 紀錄份數（備份 FV、FFS 與 FIDT 兩種形式各算），`complete` 是 `uefi_image` 有沒有全部解開。

| 樣本 | status | 核心 | product | BIOS tag | 專案版本 | 建置時間 | 紀錄數（FFS＋FIDT） | complete | 規則表建議 |
|---|---|---|---|---|---|---|---|---|---|
| ASUS PRIME B550M-A BIOS 3404（`firmware.yml` 有 expected） | read | 5.17 | Aptio V | A5090 | 34.04 | 2023-10-07T18:55:47 | 4（2＋2） | false | affected：AMI-SA-2026001、AMI-SA-2026002（preliminary） |
| Intel NUC 11 PATGL357.0059（PFAT 組回映像；`firmware.yml` 有 expected） | read | 5.19 | Aptio V | PATGL357 | 0.59 | 2026-08-19T10:45:12 | 5（4＋1） | false | affected：同上 |
| ASRock B550 Phantom Gaming 4 3.40（沒有 `firmware.yml`） | read | 5.17 | Aptio V | 1AWQG340、1AWQH340 | 3.40 | 2024-01-18T20:01:11 | 4（2＋2） | false | affected：同上 |
| ASUS PRIME B650M-A BIOS 1807（沒有 `firmware.yml`） | read | 5.26 | Aptio V | A5344 | 18.07 | 2023-09-26T22:56:15 | 3（2＋1） | false | affected：同上 |
| Dasharo Protectli VP46xx v1.2.0 | not-found | — | — | — | — | — | 0 | false（coreboot CBFS 沒有解開） | 沒有 ami_core 元件 |
| NovaCustom NUC box ARL v0.9.2 | not-found | — | — | — | — | — | 0 | false（同上） | 沒有 ami_core 元件 |
| NovaCustom V540TU MTL v1.0.1 | not-found | — | — | — | — | — | 0 | false（同上） | 沒有 ami_core 元件 |
| Ubuntu OVMF 2024.02 | not-found | — | — | — | — | — | 0 | true | 沒有 ami_core 元件 |

- 四份 AMI 樣本的核心版本在同一映像內一致，tag 不同（ASRock 的 `…H340`／`…G340`）不算矛盾；專案版本都等於廠商公布的 BIOS 版本（3.40、34.04、18.07、0.59），NUC 的建置時間與 release notes 的 `PATGL357.0059.2026.0819.1045` 一致。核心版本本身沒有廠商公布的獨立佐證。
- 四份的 `complete` 都是 false：有 `uefi_image` 沒解開的部分（GUID-defined section `CE3233F5-…`、EFI 標準壓縮、結構警告），但 `$FID` 在沒壓縮的開機區塊 FV 與 LZMA 內仍然讀得到。
- NUC 的 5 份紀錄中有一份來自 `uefi_image` 對錯位資料的後備掃描（module 名稱不是真正的 GUID）；同一映像裡 Core 一致，不影響結果。所以位置只能當線索，不能用 module 名稱過濾。
- 規則表建議是比對的結果，不是漏洞判定：核心是基底版本，板廠回補的修正看不出來，A1 尚未確認。四份的 `affected` 都會讓報告狀態是 ATTENTION、待人審；AMI 核心的建議沒有 not-affected。
- 非 AMI 樣本沒有核心版本是正常的，`sca-center:ami-core-search` 記 `not-found`，不加缺口。coreboot 映像的 `complete` 是 false（CBFS 裡的檔案沒有解開），所以 `not-found` 不代表那些檔案裡沒有。
