# C2：AMD 平台的 PSP／BIOS 目錄、微碼與 AGESA（分支 wp3/amd-psp）

擴充 `x86_firmware.py` 對 AMD 平台 BIOS 映像的解析範圍。以前只認得 AMD 平台並記 GAP「AMD microcode 不支援」，SBOM 裡幾乎只有映像本身；
現在解析 Embedded Firmware Structure（EFS）→ PSP／BIOS 目錄 → 條目，讀 AMD 微碼與 AGESA 版本字串。**不是漏洞比對**：所有新元件仍是
`dumpling:vuln-assessment=NOT_ASSESSED`（note：AMD 安全公告無法機器比對，需公告對照）。

## 檔案

| 檔案 | 內容 |
|---|---|
| `tools/cra/amd_psp.py` | 解析本體（只依賴標準函式庫與 C1 的 `uefi_image.py`）；`analyze(data, budget, soft)` 永遠回傳 dict，不丟例外 |
| `tools/cra/x86_firmware.py` | 最小接線：`bios_image()` 在辨識出 AMD 平台時呼叫 `amd_psp.analyze`，結果放 `bios[].amd`；`amd_components()` 產 SBOM 元件；`status_of()`、`markdown()` 各一小段；`ASSESS_NOTES["amd"]` |
| `tools/cra/tests/test_amd_psp.py` | 映像全部當場合成（D-028）；包含不丟例外、壓縮與 size 0、歧義、AGESA 邊界、EFS 位置表、位元位置等針對變異測試補的案例 |
| `firmware/bios/asus-prime-b550m-a-3404/firmware.yml` | 公開樣本與 expected（見下） |
| `pipeline/firmware-expect.py` | 新鍵 `amd_agesa`、`amd_microcode`（說明見 `firmware/README.md`） |

## 解析流程

1. **EFS**：位置表照 coreboot `amdfwread.c` 依 ROM 大小分的三張（視窗 ≤ 4 MiB、≤ 8 MiB、其餘），每個 16 MiB 視窗各查一次簽章 `0x55AA55AA`。更新包有標頭（例如 4 KiB）而讓 EFS 不在固定位置時，
   掃全檔的簽章候選（上限 `MAX_SIG_HITS`），位移是 4 KiB 的整數倍、不超過 `MAX_SHIFT`，而且指標之一真的指到目錄 cookie 才採用。
2. **目錄**：EFS 的 `psp_directory`（+0x10）、`new_psp_directory`（+0x14）、`psp_bak_directory`（+0x2C）、`bios0`–`bios3` 指標；cookie `$PSP`、`$PL2`、`$BHD`、`$BL2`、combo `2PSP`／`2BHD`。
   標頭 checksum 是 coreboot `amdfwtool.c` 的 `fletcher32`（初值 0xFFFF、16 位元小端字、每 359 個字與最後各折疊一次），涵蓋 +8 到最後一個項目結尾。
   三個公開 BIOS 的所有目錄（42 個）checksum 都相符，所以算法與涵蓋範圍是實測確認的（用 coreboot 的算法重跑；先前用「模 65535」的等價寫法也相符，但在某一半剛好是 0 或 0xFFFF 時兩種寫法會不同，所以改成跟 coreboot 一樣）。
3. **往下走**：combo 項目（lvl2 位址）、PSP 的 0x40（L2）、BIOS 的 0x70（L2）、其他解出位置開頭是目錄 cookie 的項目、A/B 復原的 Image Slot Header
   （PSP 的 0x48／0x4A，項目 size 為 0 或 0x100（coreboot 寫 `BLOB_ALIGNMENT`），指到 0x20 bytes 的 slot header；header 的 checksum 是同一個 `fletcher32`，涵蓋 +4 到 +0x20，
   對了才採用裡面的 `pl2_location`（L2 目錄），不對記 `ish-checksum`）。其他 size 的 0x48／0x4A 不解讀（`ish-size`）。深度、目錄數、項目總數有上限，路徑上的目錄不重複走（循環）。
4. **位址**：目錄標頭的 address mode（0 實體、1 相對視窗）優先，只有目錄是 2（相對目錄）或 3（相對 slot）才看項目自己的 mode（PSPTool 的做法）；
   mode 3 的 slot 起點未知，不解。值在 `2^32−W` 以上是映射在 4 GB 頂端的位置（W＝視窗大小，最大 16 MiB，所以大於 16 MiB 的映像相當於遮成 24 bits），其餘是視窗內偏移。
5. **兩種解讀都成立時（歧義）**：EFS 有位移時，指標值可以讀成「視窗座標」（加視窗開頭）或「整個檔案的偏移」（加 0）。**兩種讀法都在目標位置看到目錄 cookie 時，工具不判斷哪一個是硬體實際使用的**：
   兩邊都解析、都列在 inventory（各自的 checksum、項目、版本），記 `pointer-ambiguous`（ATTENTION）；只經由這種指標（以及它們底下的子目錄）才到得了的目錄標成 `ambiguous`（`dir-ambiguous`），
   它們的條目、版本、微碼只列在 `amd.ambiguous` 與 markdown，**不進 SBOM**，也不和確定目錄裡的同一份內容去重（兩邊各自照實列出）。同一個目錄若也從別的不歧義的指標到得了（例如另一個 EFS 單一解讀的指標），就是確定的，不算歧義。
   **同一個位置用不同的視窗基底到達時**（例如一條路徑用基底 0x1000、另一條用基底 0）也是歧義：目錄紀錄以（位置，基底）為單位，每種讀法各自解析（條目位址依基底會讀到不同的位置），每一個都標歧義、不進 SBOM。
   結果只取決於走訪到的紀錄與邊，和 EFS、指標的處理順序無關（有測試把順序反過來比對）。視窗大小只由基底決定。
   combo 項目和 EFS 指標一樣試兩種讀法；L2 指標、slot header、條目位址只用該目錄自己的基底。
6. **條目**：type 對照（coreboot `psp_directory.h`／`bios_directory.h`，名稱沿用上游識別字）、subprogram、instance、rom id、writable、位置、大小。
   `size=0xFFFFFFFF`（例如 soft fuse chain）的位址欄位是值，不是位置。BIOS 目錄 `compressed` 旗標的條目：size 不一定是儲存範圍（可能是解壓後大小），所以只檢查起點在檔案內
   （不在 → `entry-range`），內容**不解壓、不解析**（包括 type 0x66，不會把壓縮內容剛好像明文的東西列成微碼），一律記 `entry-compressed`。
   size 0 的條目：BIOS 的 APOB（type 0x61）有 destination 時是「只有 destination」——coreboot `amdfwtool.c` 要求 APOB 一定要有 destination（"APOB destination not provided"），source／size 可以是 0——
   不算缺口（destination 必須不是 0 也不是全 1，coreboot 的條件是 `!dest`；只對 type 0x61、只在 size 0 時放行）；其他 size 0 的條目一律記 `entry-empty`（意義不明）。
7. **版本**：PSP 韌體條目有 `amd_fw_header`（0x100 bytes）時，`fw_type`（+0x7C）要等於目錄 type、`size_total`（+0x6C）要在 0x100 到項目大小之間，
   通過才讀 +0x60 的 4 bytes，顯示成 byte 反序的十六進位 `aa.bb.cc.dd`（amdfwtool、PSPTool 的顯示方式）；欄位全 0 或全 1 當作沒有。這是**標頭裡的版本欄位原值**，
   不是 AMD 公告用的版本名稱（例如 SMU 版本的十進位寫法），沒有轉換、不猜。
8. **微碼**：BIOS 目錄 type 0x66。項目開頭是 `DMA\0` container（Linux 核心 `amd.c` 的格式）就讀等價表（CPUID ↔ equivalence id）與 patch 區段；
   否則當成單一 patch 標頭：BCD 日期（mmddyyyy，年 2000–2099）、`patch_id`（patch level）、`processor_rev_id`（equivalence id）都要合理。**單獨的 patch 沒有等價表，
   只列 equivalence id，不猜 CPUID**（記 GAP `ucode-cpuid`）。
9. **AGESA**：走訪 firmware volume（`uefi_image.parse_fvs`，LZMA 等解開，FV 以外的非空白位元組它也送進來），在每塊內容找 `AGESA!V` 標記：`V` 加 1–4 個英數字當 tag，
   後面一定要接一個 NUL 或空白當分隔，再讀最多 64 個可列印字元。**沒有分隔符（tag 和字串黏在一起，切不出來）、分隔後是空的、字串超過 64 字元被截斷**都不當成版本：
   記 GAP，截斷的值在 SBOM 的 `AMD AGESA` 元件不寫 `version`（`dumpling:version-status=GAP`，原值前綴放在 `sca-center:note`）。
   另外找整個映像原始位元組裡的標記，**用位置**檢查走訪有沒有涵蓋：走訪搜尋的內容若是原始位元組直接切出來的（不是 LZMA 解壓縮來的；用 uefi_image 呼叫端的 `where` 判斷，判斷不出來就當成不是），
   就在原始位元組裡找這塊內容的位置，標記的位置＝內容的位置＋標記在內容裡的位置；同一塊內容被搜尋 k 次就只算前 k 個出現位置有被搜尋。涵蓋不到的原始標記（例如在 UI section、空白區、被刪除的檔案裡）
   也列出來（位置標 `image (raw bytes)`），並把搜尋標為不完整；所以解壓縮出來的同樣內容或另一個沒被搜尋的複本不會替別的位置抵銷。
   不同的完整值全部列出，超過一個就 ATTENTION。`uefi_image` 載入不了或走訪失敗時只有原始位元組的結果（不完整）。走訪沒有完整（有沒解開的部分、結構警告、沒有 FV、上限）→ 搜尋不完整，
   GAP「沒找到不代表不存在」。同一句問題訊息只記一次。

## GAP 規則（一律列出、不猜；SBOM 不能比實際完整）

`amd.problems`（逐筆，每種最多列 `MAX_PROBLEMS_SHOWN` 筆，其餘只計數）與 `bios[].gaps`（彙整成每種一行：件數與前幾個例子）：

| code | 意思 | 狀態 |
|---|---|---|
| `no-directory` | 沒有任何可解析的目錄 | GAP |
| `efs-no-pointer`、`pointer-unresolved` | EFS／combo／項目的指標沒有指到目錄 cookie | GAP |
| `dir-checksum` | checksum 不符：條目照列但**不用於**版本、雜湊、微碼 | ATTENTION |
| `dir-too-many-entries`、`dir-truncated`、`dir-limit` | 項目數超過上限、項目表超出檔案、目錄數／深度／項目總數超過上限：該目錄的條目不解析 | GAP（`dir-limit` ATTENTION） |
| `dir-loop` | 目錄指標回到走訪路徑上的目錄：不再走 | ATTENTION |
| `type-unknown` | type 不在公開清單：照列位置與大小，不解讀 | GAP |
| `entry-address`、`entry-range`、`entry-size` | 位址解不出（mode 3、大於 2^32）、範圍超出檔案、大小超過 `MAX_BLOB`：不讀、不雜湊 | GAP（`entry-range` ATTENTION） |
| `entry-overlap` | 同一目錄內條目範圍部分重疊、目錄表與任何條目重疊、目錄表互相重疊（不同目錄指到完全相同的範圍是共用，不算；L1 保留較大區間而 L2 條目在裡面也不算） | ATTENTION |
| `version-unverified` | PSP 條目沒有可驗證的標頭版本（彙整一行，列 type 與數量） | GAP |
| `ucode-unrecognised`、`ucode-cpuid`、`ucode-limit` | 微碼條目看不懂、只有 equivalence id、超過上限 | GAP |
| `efs-pointer-unparsed` | EFS 的 imc／gec／xhci／Promontory 指標有值但沒有解析 | GAP |
| `ish-checksum`、`ish-size` | Image Slot Header 的 checksum 不符（不採用它的 `pl2_location`）；0x48／0x4A 項目的 size 不是 0 或 0x100（不解讀） | ATTENTION（`ish-checksum`）／GAP |
| `pointer-ambiguous`、`dir-ambiguous` | 指標在兩種座標解讀下都指到目錄：兩邊都列、都不進 SBOM（工具不判斷哪個是硬體實際使用的）；只經由這種指標到得了的目錄標 ambiguous | ATTENTION |
| `entry-compressed` | BIOS 目錄壓縮旗標的條目：不解壓、不解析（含 type 0x66），只檢查起點在檔案內 | GAP |
| `entry-empty` | size 0 的條目（有 destination 的 APOB 除外，依據見上面第 6 點） | GAP |
| `entry-error`、`internal-error` | 單一條目／整個階段的解析出錯（不該發生）：只影響那個條目／階段，其餘結果照給 | ATTENTION |
| `hash-limit`、`efs-limit` | 雜湊總量／EFS 數超過上限 | GAP |
| AGESA 問題 | 標記後沒有分隔符或字串、字串被截斷、值太多、走訪不完整或有標記走訪沒涵蓋到 | GAP；多個不同的完整值＝ATTENTION |

另外：沒有讀到任何微碼時固定記一行「不是沒有微碼」；`amd_psp` 載入失敗時 `bios[].amd` 是 `None`，gaps 寫「parser did not run」。

## 上限

| 常數 | 值 | 用途 |
|---|---|---|
| `MAX_EFS`、`MAX_SIG_HITS`、`MAX_SHIFT` | 8、4096、0x10000 | EFS 數、全檔簽章候選數、標頭位移 |
| `MAX_DIRS`、`MAX_DEPTH`、`MAX_DIR_ENTRIES`、`MAX_ENTRIES_TOTAL` | 64、4、256、4096 | 目錄數、巢狀深度、單一目錄項目數、全部目錄項目總數（跨巢狀累計） |
| `MAX_BLOB`、`MAX_HASH_TOTAL` | 64 MiB、256 MiB | 單一條目大小；雜湊總量（同一段 offset＋size 只算一次，所以多個目錄共用的條目不會放大） |
| `MAX_UCODE`、`MAX_EQUIV`、`MAX_PATCHES` | 64、256、16 | 微碼數、container 等價表項目數、container 的 patch 數 |
| `MAX_AGESA_MARKERS`、`MAX_AGESA_VALUES`、`MAX_AGESA_INSPECT`、`AGESA_VALUE_LEN` | 4096、16、1 GiB、64 | AGESA 標記總數、不同值數、解開後內容總量（同內容只搜一次）、字串長度 |

沒有用 regex 找 AGESA（`bytes.find` 固定字面值）；目錄 checksum 的計算量上限是 256 項 × 24 bytes。

## 公開樣本：`asus-prime-b550m-a-3404`

ASUS PRIME B550M-A BIOS 3404（2023/10/31，AMI），16.7 MB zip，裡面一個 33558528 位元組的 CAP（4 KiB 標頭＋兩個 16 MiB 視窗）。選它的技術理由：
EFS 因標頭位移不在固定位置（0x21000、0x1021000）；EFS 指向 combo 目錄（`2PSP`／`2BHD`），再指到多個 L1；新世代的 L1 有 0x40／0x70 指標到 L2（`$PL2`、`$BL2`）；
AGESA 字串在壓縮的 firmware volume 裡；release notes 有 AGESA 版本可當出處。

2026-11-13 的解析結果（`python3 -I x86_firmware.py inventory --in PRIME-B550M-A-ASUS-3404.zip`，約 2.5 秒）：

- 2 個 EFS（視窗位移 0x1000）→ 17 個目錄（2 個 combo PSP、1 個 combo BIOS、5 個 L1 PSP、2 個 L2 PSP、5 個 L1 BIOS、2 個 L2 BIOS），244 個目錄項目，checksum 全部相符。
- **歧義**：第二個 EFS 的 `new_psp_directory`（0x131000）讀成視窗座標是 0x1132000（combo），讀成檔案偏移是 0x131000（第一個視窗的 combo），兩邊都有目錄 cookie，工具不判斷。
  讀成檔案偏移時 0x131000 是用基底 0 讀的，而第一個 EFS 用視窗開頭 0x1000 讀同一個位置：**同一個位置用兩種基底讀，條目位址會讀到不同的地方**，所以兩種讀法都標成歧義
  （規則見流程第 5 點），它底下的目錄（L1／L2 PSP、同一個 `psp_bak`／combo 子樹）也是。結果：19 個目錄紀錄（17 個位置，其中 0x131000 與 0x15a000 各有兩種基底的讀法）中 11 個標歧義。
  PSP 這一側（確定可用的）因此沒有任何條目；BIOS 這一側的目錄只經由不歧義的指標到達，所以不受影響（19 份微碼仍是確定的，AGESA 不受影響）。
- 只在歧義目錄裡讀到的 PSP 版本：78 個（列在 `amd.ambiguous`，不進 SBOM）；63 個條目沒有可驗證的標頭版本（公鑰、NVRAM、SECURED_DEBUG、IKEK、token 等）。
- 19 份 AMD 微碼（BIOS 目錄 type 0x66，全是單獨的 patch，全部來自確定的目錄）：patch level、日期、equivalence id，例如 `0x0800820d`／2019-04-16／`0x8082`。
- AGESA：`AGESA!V9` + `ComboAM4v2PI 1.2.0.B`（6 處，只有這一個值）。
- GAP：2 個 Promontory 指標沒解析、5 個壓縮的 BIOS 條目（type 0x62）不解析、3 個未知 type（BIOS 0x67、PSP 0x43、0x4E）、2 個歧義指標與 11 個歧義目錄（讀錯基底的那一側還會冒出
  `pointer-unresolved`、`entry-overlap` 之類的雜訊問題，它們是「用那種基底讀」的後果，不代表映像壞了）、63 個條目沒有版本、微碼只有 equivalence id、
  AGESA 搜尋不完整（2 個 GUID-defined section `CE3233F5-…` 需要處理但不支援，另有一個 FFS 檔的 section 串不乾淨）。狀態 ATTENTION。
- SBOM 元件：99（第一版）→ 55（歧義不選邊）→ **21**（同位置不同基底也算歧義：映像 1、微碼 19、AGESA 1，沒有 PSP 韌體元件）。

與先前版本的差異：第一版（41353d3）把這些目錄全部當成確定的，78 個 PSP 版本都進 SBOM；上一版（f41f5eb）只把 6 個目錄標歧義（34 個 PSP 版本確定）。上一版有一個錯誤：同一個位置第二次被到達時
直接沿用第一次的紀錄，確定的目錄可能用到歧義路徑的基底；現在紀錄以（位置，基底）為單位，結果只取決於走訪到的紀錄與邊，不依賴處理順序。這是保守的選擇：
歧義的指標會連帶讓同一個位置的另一種基底的讀法也不可用，代價是這個樣本的 PSP 版本全部只列在 inventory。如果之後要放寬（例如只讓「不歧義的路徑讀出的紀錄」確定），要由決策者決定。

### expected（只寫有公開出處的值）

| 鍵 | 值 | 出處 |
|---|---|---|
| `amd_agesa` | `1.2.0.B` | ASUS 官方下載頁 BIOS 3404 的 release notes：「Update AGESA version to ComboV2PI 1.2.0.B」（2026-11-13 查）。映像字串的名稱寫法不同（`ComboAM4v2PI`），所以只比 PI 版本號 |
| `amd_microcode` | `0x8082`／`0x0800820d`、`0x8012`／`0x08001250` | 映像裡這兩份 patch 與 linux-firmware（AMD 提供，`LICENSE.amd-ucode` 允許散布）commit `c4586ffaac0c`（2019-12-18）的 `amd-ucode/microcode_amd_fam17h.bin` **位元組相同**（patch 區段 SHA-256 `c00b6b19fd5c…`、`689883cd220d…`）。該檔的等價表把 `0x8012` 對到 CPUID `00800F12`、`0x8082` 對到 `00800F82` |

用 linux-firmware 的真實 container 也順便驗證了 `parse_ucode` 的 container 路徑（10 個歷史版本的檔案都解得開、等價表對得出 CPUID）；CI 的樣本只有單獨 patch，container 路徑靠合成測試。

### 已讀出但沒有佐證（不寫進 expected）

- PSP 韌體條目的標頭版本（bootloader、SMU、ABL…）：沒有找到可對照的公開來源；顯示的是欄位原值，不是公告用的名稱。
- 其他 17 份微碼 patch（不在上述 linux-firmware 版本裡）。
- equivalence id 對應的 CPUID：映像裡的微碼沒有等價表。
- 目錄結構（17 個目錄、244 項）：這是解析結果，不是別人公布的值。

## 另外做過的只讀驗證（不在樣本清單、不在 CI）

可用公開網址重現（下載物當不可信資料，只讀）：

- ASRock B550 Phantom Gaming 4 BIOS 3.40：`https://download.asrock.com/BIOS/AM4/B550%20Phantom%20Gaming%204(3.40)ROM.zip`，15513528 位元組，SHA-256 `7128bf8417924b93b509915cfdfaedecba470f4885d7fb802c906a0ebee5e985`；
  zip 內一個 33554432 位元組的 `B550PG43.40`（SHA-256 `19cd0d852086227e4e85e7f184baa5c23eed93abe1718462dd1079e14a6db692`）。結果：2 個 EFS（0x20000、0x1020000）、17 個目錄、246 項，沒有歧義指標；
  AGESA 同樣是 `ComboAM4v2PI 1.2.0.B`；19 份微碼，其中同兩份與 linux-firmware 位元組相同。ASRock 的下載頁要 JavaScript 驗證，抓不到 release notes，也無法確認授權頁網址，所以沒有列為樣本。
- ASUS PRIME B650M-A BIOS 1807（AM5）：`https://dlcdnets.asus.com/pub/ASUS/mb/BIOS/PRIME-B650M-A-ASUS-1807.zip`，11601928 位元組，SHA-256 `8f9202f9c88ca6124b45951b2745f9eabaa8af87d1a290ffd908a39394985cbc`。
  結果：`psp_bak_directory` 的指標有兩種讀法（視窗座標 0x83000、檔案偏移 0x82000）；0x82000 也從 `new_psp_directory` 用視窗開頭 0x1000 讀過，所以這個位置有兩種基底的讀法，
  整個 PSP／BIOS L2 子樹（9 個目錄紀錄）都標歧義，21 個 PSP 版本與 2 份微碼只列在 inventory，SBOM 只有 AGESA（`ComboAM5PI 1.0.8.0`）。在用基底 0 讀的那一側，A/B slot header 的 checksum 不符
  （位址讀錯了）。另有 2 份微碼條目的格式不同（開頭是 `$PS1` 簽署標頭），記 GAP。
  這個驗證抓到並修正了「size 0 的 0x48／0x4A 項目被當成沒有資料」的錯誤。
- linux-firmware 的 `amd-ucode/microcode_amd_fam17h.bin`：`https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain/amd-ucode/microcode_amd_fam17h.bin?id=<commit>`，
  commit 取 `git log` 該檔的前 10 筆（含 `c4586ffaac0ca0d7045e06140b6426f2e79e96e6`）；10 個版本的 container 都解得開。

## 限制與不確定

- 只認得 coreboot 公開標頭列出的 type；沒有列的（例如 BIOS 0x67、PSP 0x43、0x4E、0x93）只記位置與大小，名稱和意義不猜。
- PSP 版本是標頭欄位原值的十六進位顯示，不同 type 的欄位意義可能不同（ABL 的欄位看起來像日期，沒有佐證所以不解讀）。
- 位址視窗假設是 16 MiB（或更小的映像整體）。映像大小不是 2 的次方又小於 16 MiB、或截斷的檔案，頂端映射的位置會算錯，結果是 `pointer-unresolved` GAP，不會誤讀。
- **兩種座標讀法都成立時，工具不判斷哪一個是硬體實際使用的**（見流程第 5 點）：兩邊都列，都不進 SBOM；這會讓 SBOM 比「選一邊」少，但不會放進可能是錯的那一邊。
  沒有做自動消歧，也沒有「同一個 EFS 的其他指標只在某種座標說得通」這類推論。
- 沒有簽章驗證（Image Slot Header 只驗 checksum）；Promontory 晶片組韌體、IMC／GEC／XHCI 沒有解析；壓縮的 BIOS 目錄條目（type 0x62）不解開。
- AGESA 搜尋依賴 `uefi_image` 能解開的部分；EFI 標準壓縮與需要處理的 GUID-defined section 解不開（會讓搜尋不完整，沒找到不代表不存在）。
- 微碼的 `patch_size` 是目錄項目的大小（單獨 patch 時等於 patch 區段大小）；patch 內部的 checksum、簽章沒驗證。
